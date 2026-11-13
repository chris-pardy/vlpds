//! The space host's calls out (reference `space-policy/manager.ts`,
//! `api/com/atproto/space/util.ts` and `authorizeSpaceSync.ts`): resolving
//! a service identifier, asking a managing app what an account may read
//! and write, confirming a syncer's new registration, and sending a
//! registered syncer a sequenced writer-set update. Every call goes through
//! the SSRF-guarded client (an endpoint is chosen by whoever registered or
//! published it), with a 10 s timeout and a small response cap; a managing
//! app gets service auth from the authority (`aud` = the service identifier
//! as published), a syncer the registration's token in the body instead.

use super::rows::RegistrationRow;
use crate::state::{self, RegId, SpaceId};
use crate::xrpc::App;
use serde_json::{json, Value as J};
use std::time::Duration;
use vlatproto::tid::Tid;

pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 64 << 10;
/// Endpoints are kept in `sG` rows (u16-length strings).
pub const MAX_ENDPOINT: usize = 2048;
/// A registration's token (the lexicon's `maxLength`).
pub const MAX_TOKEN: usize = 512;

/// Reference `resolveServiceEndpoint`: `did#fragment` names that service
/// entry; a bare DID its PDS.
pub async fn resolve_service_endpoint(app: &App, service: &str) -> Option<String> {
    let (did, fragment) = match service.split_once('#') {
        Some((d, f)) => (d, Some(f)),
        None => (service, None),
    };
    if !vlatproto::syntax::valid_did(did) {
        return None;
    }
    let doc = match app.did_resolver.resolve(did).await {
        Ok(d) => d,
        Err(e) => {
            tracing::info!(service, "could not resolve service did: {e:?}");
            return None;
        }
    };
    let ep = match fragment {
        Some(f) => vlatproto::did_resolver::service_endpoint(&doc, f),
        None => vlatproto::did_resolver::service_endpoint(&doc, "atproto_pds"),
    };
    ep.filter(|e| e.len() <= MAX_ENDPOINT)
}

/// A send's error for the logs, without its URL: a query names the space
/// and its members, which the logs must not (privacy.md).
pub(crate) fn http_error(what: &str, e: reqwest::Error) -> String {
    format!("{what}: {}", e.without_url())
}

/// A call to `service` at `endpoint` as `iss` (an account hosted here):
/// Ok(status, JSON body) once it answered.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn call(
    app: &App,
    client: vlatproto::http::Guarded,
    iss: &str,
    service: &str,
    endpoint: &str,
    lxm: &str,
    method: reqwest::Method,
    query: &[(&str, &str)],
    body: Option<&J>,
) -> Result<(u16, J), String> {
    let (key, _) = crate::xrpc::proxy::account_key_status(app, iss).await.map_err(|e| e.message)?;
    let jwt = crate::auth::service_auth_jwt(&key, iss, service, Some(lxm), 60).map_err(|e| e.to_string())?;
    let url = format!("{}/xrpc/{lxm}", endpoint.trim_end_matches('/'));
    let mut rb = client.request(method, &url)?.bearer_auth(jwt).timeout(CALL_TIMEOUT);
    if !query.is_empty() {
        rb = rb.query(query);
    }
    if let Some(b) = body {
        rb = rb.json(b);
    }
    answer(&url, rb).await
}

/// A procedure call to a syncer's registered endpoint: no auth header (the
/// body carries the registration's token).
pub(crate) async fn post_endpoint(
    client: vlatproto::http::Guarded,
    endpoint: &str,
    lxm: &str,
    body: &J,
) -> Result<(u16, J), String> {
    let url = format!("{}/xrpc/{lxm}", endpoint.trim_end_matches('/'));
    answer(&url, client.request(reqwest::Method::POST, &url)?.timeout(CALL_TIMEOUT).json(body)).await
}

async fn answer(url: &str, rb: reqwest::RequestBuilder) -> Result<(u16, J), String> {
    let mut r = rb.send().await.map_err(|e| http_error(url, e))?;
    let status = r.status().as_u16();
    let mut buf = Vec::new();
    while let Some(c) = r.chunk().await.map_err(|e| http_error(url, e))? {
        if buf.len() + c.len() > MAX_RESPONSE {
            return Err(format!("{url}: response too large"));
        }
        buf.extend_from_slice(&c);
    }
    Ok((status, serde_json::from_slice(&buf).unwrap_or(J::Null)))
}

/// A managing app's answer, as the reference's `checkAccess` asks it:
/// `repo` absent for a read with no delegation token, `clientId` only on
/// reads (a write notify doesn't say which app wrote). An app that can't
/// be had (unresolvable, unreachable, an error, a malformed answer) is
/// None, not a denial (reference c60bff387): failing open would hand out
/// credentials for the spaces that asked for the strictest gate, and a
/// denial would read as a loss of access (a syncer's registration dropped,
/// a writer's notify not retried).
pub async fn check_access(
    app: &App,
    space: &str,
    authority: &str,
    managing_app: &str,
    repo: Option<&str>,
    client_id: Option<&str>,
) -> Option<Access> {
    let lxm = "com.atproto.managedspace.checkAccess";
    let log_id = crate::state::space_log_id(space);
    let Some(endpoint) = resolve_service_endpoint(app, managing_app).await else {
        tracing::info!(space = %log_id, managing_app, "could not resolve managing app");
        return None;
    };
    let mut q = vec![("space", space)];
    if let Some(r) = repo {
        q.push(("repo", r));
    }
    if let Some(c) = client_id {
        q.push(("clientId", c));
    }
    let client = vlatproto::http::guarded(app.config.dev_mode);
    match call(app, client, authority, managing_app, &endpoint, lxm, reqwest::Method::GET, &q, None).await {
        Ok((200, body)) => match (body["read"].as_bool(), body["write"].as_bool()) {
            (Some(read), Some(write)) => Some(Access { read, write }),
            _ => {
                tracing::info!(space = %log_id, managing_app, "managing app check answered without read and write");
                None
            }
        },
        Ok((status, _)) => {
            tracing::info!(space = %log_id, managing_app, status, "managing app check failed");
            None
        }
        Err(e) => {
            tracing::info!(space = %log_id, managing_app, "managing app check failed: {e}");
            None
        }
    }
}

/// A managing app's verdict on one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    pub read: bool,
    pub write: bool,
}

/// Notify registrations a space may hold, lapsed ones included: past it a
/// new one takes the place of the lapsed registration that expired
/// longest ago, and is refused when none has lapsed.
pub const MAX_REGISTRATIONS: usize = 256;

/// Live notify registrations across one authority's spaces: each space's
/// cap alone would let one account's spaces register without end.
pub const MAX_REGISTRATIONS_PER_AUTHORITY: usize = 1024;

pub const CONFIRM_REGISTRATION: &str = "com.atproto.space.confirmRegistration";
pub const NOTIFY_SPACE_UPDATE: &str = "com.atproto.space.notifySpaceUpdate";

/// Live registrations across `authority`'s spaces, counted up to `stop_at`.
pub async fn authority_registrations(app: &App, authority: &str, stop_at: usize) -> anyhow::Result<usize> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let prefix = state::space_did_prefix(state::SPACE_REGISTRATION_FAMILY, authority);
    let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?;
    let now = vlatproto::tid::now_micros();
    let mut n = 0;
    while let Some(kv) = it.next().await? {
        if !RegistrationRow::decode(&kv.value)?.lapsed(now) {
            n += 1;
            if n >= stop_at {
                break;
            }
        }
    }
    Ok(n)
}

/// A space's registrations (`sG`) from the authority's shard, lapsed ones
/// included.
pub async fn registrations(app: &App, authority: &str, sid: &SpaceId) -> anyhow::Result<Vec<RegistrationRow>> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let prefix = state::space_prefix(state::SPACE_REGISTRATION_FAMILY, authority, sid);
    let opts = slatedb::config::ScanOptions::default();
    let mut it = p.db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &opts).await?;
    let mut out = Vec::new();
    while let Some(kv) = it.next().await? {
        out.push(RegistrationRow::decode(&kv.value)?);
    }
    Ok(out)
}

/// Reference `confirmRegistration`: before a new registration, the
/// endpoint must take the token as one it issued for the space and echo
/// back a random challenge. Ok(false): it didn't (anything else, an error
/// included, answers RegistrationNotConfirmed).
pub async fn confirm_registration(app: &App, space: &str, endpoint: &str, token: &str) -> bool {
    use base64::Engine;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
    let body = json!({"space": space, "token": token, "challenge": challenge});
    let client = vlatproto::http::guarded(app.config.dev_mode);
    let log_id = state::space_log_id(space);
    match post_endpoint(client, endpoint, CONFIRM_REGISTRATION, &body).await {
        Ok((200, b)) if b["challenge"].as_str() == Some(challenge.as_str()) => true,
        Ok((status, _)) => {
            tracing::info!(space = %log_id, status, "registration not confirmed");
            false
        }
        Err(e) => {
            tracing::info!(space = %log_id, "registration not confirmed: {e}");
            false
        }
    }
}

/// A sequenced change to a writer's place in the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterUpdate {
    /// `defs#repoWrite`: the repo at a new rev.
    Write { repo_rev: Tid, hash: [u8; 32] },
    /// `defs#repoRemoved`: out of the writer set.
    Removed,
}

impl WriterUpdate {
    /// What a writer's `sW` row reports.
    pub fn of(w: &super::rows::WriterRow) -> WriterUpdate {
        match w.removed {
            true => WriterUpdate::Removed,
            false => WriterUpdate::Write { repo_rev: w.repo_rev, hash: w.hash },
        }
    }

    /// As listWriters and notifySpaceUpdate carry it.
    pub fn to_json(&self, writer: &str, space_rev: Tid, prev: Option<Tid>) -> J {
        let mut u = match self {
            WriterUpdate::Write { repo_rev, hash } => json!({
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": writer,
                "repoRev": repo_rev.to_string(),
                "data": b64(hash),
                "spaceRev": space_rev.to_string(),
            }),
            WriterUpdate::Removed => json!({
                "$type": "com.atproto.space.defs#repoRemoved",
                "repo": writer,
                "spaceRev": space_rev.to_string(),
            }),
        };
        if let Some(p) = prev {
            u["prevSpaceRev"] = json!(p.to_string());
        }
        u
    }
}

/// One forward of a sequenced writer-set update to a registration.
pub struct Forward {
    pub authority: std::sync::Arc<str>,
    pub uri: std::sync::Arc<str>,
    pub reg: RegId,
    pub endpoint: String,
    pub token: String,
    pub writer: String,
    pub update: WriterUpdate,
    pub space_rev: Tid,
    pub prev_space_rev: Option<Tid>,
    /// The registration's expiry (unix µs).
    pub expires: u64,
}

fn b64(b: &[u8]) -> J {
    use base64::Engine;
    json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)})
}

/// notifySpaceUpdate to a registration, naming `prev` as the spaceRev
/// before it: "ok", "refused" (a status not worth retrying) or "error". A
/// refused update leaves the registration as it is (reference "keeps an
/// active registration through a rejected update").
pub async fn forward(app: &App, f: &Forward, prev: Option<Tid>) -> &'static str {
    let body = json!({
        "space": &*f.uri,
        "token": f.token,
        "update": f.update.to_json(&f.writer, f.space_rev, prev),
    });
    let client = vlatproto::http::guarded_fanout(app.config.dev_mode);
    let log_id = crate::state::space_log_id(&f.uri);
    let reg = hex::encode(f.reg);
    match post_endpoint(client, &f.endpoint, NOTIFY_SPACE_UPDATE, &body).await {
        Ok((s, _)) if (200..300).contains(&s) => "ok",
        Ok((s, _)) if crate::xrpc::space::retryable_status(s) => {
            tracing::info!(space = %log_id, reg, status = s, "space notify forward failed");
            "error"
        }
        Ok((s, _)) => {
            tracing::info!(space = %log_id, reg, status = s, "space notify forward refused");
            "refused"
        }
        Err(e) => {
            tracing::info!(space = %log_id, reg, "space notify forward failed: {e}");
            "error"
        }
    }
}

/// How long the authority waits on a writer's host to confirm a same-rev
/// hash: well inside the writer's own 10 s notify timeout.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Ok when `writer`'s host serves `hash` at `rev` in `space` now: its
/// getLatestCommit, read as a syncer reads it with a credential `authority`
/// issues itself, its MAC keyed against `writer`'s `#atproto_kem` key. A
/// commit's hash is the author's claim only when it comes from the author's
/// host, MACed for this request, which is what this asks for.
pub async fn check_served_hash(
    app: &App,
    space: &str,
    authority: &str,
    writer: &str,
    rev: Tid,
    hash: &[u8; 32],
) -> Result<(), String> {
    let doc = app.did_resolver.resolve(writer).await.map_err(|e| format!("could not resolve the writer: {e:?}"))?;
    match served_commit(app, &doc, space, authority, writer).await {
        Err(e) if e == MAC_MISMATCH => {
            // the KEM key may have rotated since the document was cached
            if !app.did_resolver.refresh(writer) {
                return Err(e);
            }
            let doc =
                app.did_resolver.resolve(writer).await.map_err(|e| format!("could not resolve the writer: {e:?}"))?;
            check_commit(served_commit(app, &doc, space, authority, writer).await?, rev, hash)
        }
        r => check_commit(r?, rev, hash),
    }
}

const MAC_MISMATCH: &str = "the commit's MAC doesn't verify against the writer's KEM key";

fn check_commit(c: super::commit::Commit, rev: Tid, hash: &[u8; 32]) -> Result<(), String> {
    if c.rev != rev.to_string() {
        return Err(format!("the writer's host is at {}", c.rev));
    }
    if c.data != *hash {
        return Err("the writer's host serves another hash".into());
    }
    Ok(())
}

/// The writer's getLatestCommit, its MAC verified.
async fn served_commit(
    app: &App,
    doc: &J,
    space: &str,
    authority: &str,
    writer: &str,
) -> Result<super::commit::Commit, String> {
    use p256::ecdsa::signature::Signer;
    let endpoint = vlatproto::did_resolver::service_endpoint(doc, "atproto_pds").ok_or("the writer names no PDS")?;
    let kem = super::mac::kem_key_of(doc).ok_or("the writer publishes no KEM key")?;
    let (share, secret) = super::mac::encapsulate(&kem).map_err(|e| e.0.to_string())?;
    let (key, _) = crate::xrpc::proxy::account_key_status(app, authority).await.map_err(|e| e.message)?;
    let holder = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let mut mk = vec![0x80, 0x24];
    mk.extend_from_slice(holder.verifying_key().to_sec1_point(true).as_bytes());
    let holder_did = format!("did:key:z{}", bs58::encode(mk).into_string());
    let mint = super::token::Mint {
        iss: authority,
        sub: space,
        key_id: Some(&holder_did),
        expires_in_secs: Some(60),
        ..Default::default()
    };
    let now = vlatproto::tid::now_micros() as i64 / 1_000_000;
    let jti = super::token::new_jti();
    let cred = super::token::encode(super::token::TokenType::Credential, &mint, "ES256K", now, &jti, |b| {
        Ok::<_, std::convert::Infallible>(key.sign(b))
    })
    .map_err(|e| format!("credential: {e:?}"))?;
    let signed = super::httpsig::headers(&cred, writer, |b| {
        let sig: p256::ecdsa::Signature = holder.sign(b);
        sig.to_bytes().into()
    });
    let url = format!("{}/xrpc/com.atproto.space.getLatestCommit", endpoint.trim_end_matches('/'));
    let mut req = vlatproto::http::guarded(app.config.dev_mode)
        .request(reqwest::Method::GET, &url)?
        .query(&[("space", space), ("repo", writer)])
        .header(super::mac::ACCEPT_SIGNATURE, super::mac::format_request(super::mac::Profile::Commit, &share));
    for (k, v) in signed {
        req = req.header(k, v);
    }
    let mut r = req.timeout(CHECK_TIMEOUT).send().await.map_err(|e| http_error("getLatestCommit", e))?;
    if !r.status().is_success() {
        return Err(format!("getLatestCommit: {}", r.status()));
    }
    let headers = r.headers().clone();
    let mut buf = Vec::new();
    while let Some(c) = r.chunk().await.map_err(|e| http_error("getLatestCommit", e))? {
        if buf.len() + c.len() > MAX_RESPONSE {
            return Err("getLatestCommit: response too large".into());
        }
        buf.extend_from_slice(&c);
    }
    let body: J = serde_json::from_slice(&buf).map_err(|_| "getLatestCommit: not JSON")?;
    let commit = super::commit::Commit::from_json(&body["commit"]).ok_or("getLatestCommit: malformed commit")?;
    super::commit::verify(&commit, space, writer, &share, &secret, &headers).map_err(|_| MAC_MISMATCH.to_string())?;
    Ok(commit)
}

#[cfg(test)]
mod tests {
    /// An unreachable endpoint's error names neither the space nor the
    /// member its query carried.
    #[tokio::test]
    async fn send_errors_leave_the_url_out() {
        let space = "at://did:plc:secretauthority0000000000/space/com.example.group/skey";
        let e = reqwest::Client::new()
            .get("http://127.0.0.1:1/xrpc/com.atproto.space.getLatestCommit")
            .query(&[("space", space), ("repo", "did:plc:secretmember")])
            .send()
            .await
            .unwrap_err();
        assert!(e.to_string().contains("secret"), "reqwest names the URL: {e}");
        let logged = super::http_error("getLatestCommit", e);
        assert!(!logged.contains("secret") && !logged.contains("did:plc"), "{logged}");
    }
}
