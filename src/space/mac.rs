//! Space repos authenticate commits and records with a MAC rather than a
//! signature, so a leaked response proves nothing to a third party
//! (@atproto/space `kem.ts`, `mac.ts`).
//!
//! The key is a per-request shared secret from HPKE's secret export
//! (RFC 9180 §6.2): DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and the
//! Export-only AEAD, `info` "atproto-mac", an empty exporter context. The
//! syncer's ephemeral key (HPKE's `enc`, fresh for every request) meets the
//! author's `#atproto_kem` key.
//!
//! The MAC is an RFC 9421 HTTP message signature, `hmac-sha256`. The
//! syncer asks for one with `Accept-Signature`, its key share as the
//! `keyid` and the profile as the `tag`; the host answers with a header
//! describing the commit or record and a signature over it under the
//! requested label:
//!
//! ```text
//! Accept-Signature: mac=("atproto-space-commit";sf);keyid="did:key:zDna…";tag="atproto-space-commit"
//! Atproto-Space-Commit: ver=1, repo="did:…", space="at://…", rev="3m…", data=:<base64>:
//! Signature-Input: mac=("atproto-space-commit";sf);keyid="did:key:zDna…";tag="atproto-space-commit"
//! Signature: mac=:<base64>:
//! ```

use super::httpsig::{self, Required};
use super::sfv::{self, Bare, Member};
use axum::http::HeaderMap;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::Sha256;
use std::borrow::Cow;

pub const ACCEPT_SIGNATURE: &str = "accept-signature";
pub const ALG: &str = "hmac-sha256";
/// The label this syncer requests its MAC under. A host answers under the
/// label requested; a syncer finds the MAC by its tag.
pub const LABEL: &str = "mac";
/// The parameters a host fulfills. A key share is fresh for each request,
/// so `created`, `expires` and `nonce` would add nothing.
const REQUEST_PARAMS: [&str; 3] = ["keyid", "tag", "alg"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// getLatestCommit, getRepo, listRepoOps: the commit.
    Commit,
    /// getRecord: the record's URI and CID.
    Record,
}

impl Profile {
    /// The profile's tag, and the header its MAC covers.
    pub fn name(self) -> &'static str {
        match self {
            Profile::Commit => "atproto-space-commit",
            Profile::Record => "atproto-space-record",
        }
    }

    /// The one component its MAC covers: the header, as a structured field.
    fn component(self) -> &'static str {
        match self {
            Profile::Commit => "\"atproto-space-commit\";sf",
            Profile::Record => "\"atproto-space-record\";sf",
        }
    }
}

/// The reference's `SpaceMacError` (and `SpaceKemError`, which a host
/// answers alike); its XRPC error is `InvalidSpaceMac`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacError(pub Cow<'static, str>);

impl MacError {
    pub const CODE: &str = "InvalidSpaceMac";
}

impl std::fmt::Display for MacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(m: impl Into<Cow<'static, str>>) -> Result<T, MacError> {
    Err(MacError(m.into()))
}

/// A covered header far over what it holds (a space URI is at most ~8 KiB
/// with a did:web authority; a commit header is that plus ~150 bytes).
const MAX_HEADER: usize = 16 << 10;

/// The uncompressed point (0x04 ‖ x ‖ y) of a P-256 did:key.
fn p256_point(did_key: &str) -> Result<p256::PublicKey, MacError> {
    match super::did_key_alg(did_key) {
        Some("ES256") => {}
        Some(_) => return err("KEM key must be a P-256 did:key"),
        None => return err("invalid KEM key"),
    }
    let raw = bs58::decode(&did_key["did:key:z".len()..]).into_vec().map_err(|_| MacError("invalid KEM key".into()))?;
    p256::PublicKey::from_sec1_bytes(&raw[2..]).map_err(|_| MacError("invalid KEM key".into()))
}

fn uncompressed(k: &p256::PublicKey) -> Vec<u8> {
    k.to_sec1_point(false).as_bytes().to_vec()
}

pub fn did_key(k: &p256::PublicKey) -> String {
    let mut mk = vec![0x80, 0x24];
    mk.extend_from_slice(k.to_sec1_point(true).as_bytes());
    format!("did:key:z{}", bs58::encode(mk).into_string())
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

// HPKE labels every HKDF input with a version and the algorithm IDs:
// 0x0010 DHKEM(P-256, HKDF-SHA256), 0x0001 HKDF-SHA256, 0xffff Export-only.
const KEM_ID: &[u8] = b"KEM\x00\x10";
const SUITE_ID: &[u8] = b"HPKE\x00\x10\x00\x01\xff\xff";
const INFO: &[u8] = b"atproto-mac";

/// HKDF-Extract (an empty salt is HMAC's all-zero key).
fn labeled_extract(id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac(salt, &[b"HPKE-v1", id, label, ikm])
}

/// HKDF-Expand to 32 bytes, one block.
fn labeled_expand(id: &[u8], prk: &[u8], label: &[u8], info: &[u8]) -> [u8; 32] {
    hmac(prk, &[&32u16.to_be_bytes(), b"HPKE-v1", id, label, info, &[1]])
}

/// HPKE's SetupBaseS (or SetupBaseR) then an export with an empty exporter
/// context, from the ECDH result.
fn shared_secret(dh: &[u8], enc: &p256::PublicKey, author: &p256::PublicKey) -> [u8; 32] {
    let eae_prk = labeled_extract(KEM_ID, &[], b"eae_prk", dh);
    let kem_secret =
        labeled_expand(KEM_ID, &eae_prk, b"shared_secret", &[uncompressed(enc), uncompressed(author)].concat());
    let psk_id_hash = labeled_extract(SUITE_ID, &[], b"psk_id_hash", &[]);
    let info_hash = labeled_extract(SUITE_ID, &[], b"info_hash", INFO);
    let context = [&[0u8][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(SUITE_ID, &kem_secret, b"secret", &[]);
    let exporter = labeled_expand(SUITE_ID, &secret, b"exp", &context);
    labeled_expand(SUITE_ID, &exporter, b"sec", &[])
}

/// Repo host side: the shared secret for the syncer's `key_share`, from the
/// author's KEM key.
pub fn decapsulate(author: &p256::SecretKey, key_share: &str) -> Result<[u8; 32], MacError> {
    let syncer = p256_point(key_share)?;
    let dh = p256::ecdh::diffie_hellman(author.to_nonzero_scalar(), syncer.as_affine());
    Ok(shared_secret(dh.raw_secret_bytes(), &syncer, &author.public_key()))
}

/// Syncer side: a fresh ephemeral key against the author's `#atproto_kem`
/// key. (key_share, shared secret); use one per request.
pub fn encapsulate(author_kem_key: &str) -> Result<(String, [u8; 32]), MacError> {
    let author = p256_point(author_kem_key)?;
    let eph = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
    let dh = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), author.as_affine());
    let syncer = eph.public_key();
    Ok((did_key(&syncer), shared_secret(dh.raw_secret_bytes(), &syncer, &author)))
}

/// The did:key of a DID document's `#atproto_kem` verification method.
pub fn kem_key_of(doc: &serde_json::Value) -> Option<String> {
    let did = doc.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let full = format!("{did}#atproto_kem");
    doc.get("verificationMethod")?.as_array()?.iter().find_map(|m| {
        let id = m.get("id")?.as_str()?;
        (id == "#atproto_kem" || id == full)
            .then(|| m.get("publicKeyMultibase")?.as_str().map(|k| format!("did:key:{k}")))?
    })
}

fn string(s: &str) -> Member {
    Member::Item(Bare::String(s.into()), vec![])
}

// ---- Requests ----

/// The syncer's `Accept-Signature`, asking for a MAC keyed by the shared
/// secret for `key_share`.
pub fn format_request(p: Profile, key_share: &str) -> String {
    let params = vec![("keyid".into(), Bare::String(key_share.into())), ("tag".into(), Bare::String(p.name().into()))];
    let inner = Member::InnerList(vec![(Bare::String(p.name().into()), vec![("sf".into(), Bare::Bool(true))])], params);
    sfv::serialize_dictionary(&vec![(LABEL.into(), inner)])
}

/// A MAC request, as the host reads it from `Accept-Signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacRequest {
    pub label: String,
    pub key_share: String,
    /// The requested signature parameters, re-serialized; the MAC uses
    /// them as given.
    pub signature_params: String,
}

/// The MAC requested for `p` in an `Accept-Signature` field, checked to be
/// one the host can fulfill. Requests with other tags are ignored, so this
/// is None when none is for `p`.
pub fn parse_request(value: Option<&str>, p: Profile) -> Result<Option<MacRequest>, MacError> {
    let Some(value) = value else { return Ok(None) };
    if value.len() > httpsig::MAX_FIELD {
        return err("malformed Accept-Signature header");
    }
    let requests = sfv::parse_dictionary(value).map_err(|_| MacError("malformed Accept-Signature header".into()))?;
    let tagged = httpsig::members_with_tag(&requests, p.name());
    let (label, items, params) = match tagged[..] {
        [] => return Ok(None),
        [one] => one,
        _ => return err(format!("more than one MAC requested with tag \"{}\"", p.name())),
    };
    if !httpsig::covers_exactly(items, &[p.component()]) {
        return err(format!("MAC must cover exactly ({})", p.component()));
    }
    if let Some((k, _)) = params.iter().find(|(k, _)| !REQUEST_PARAMS.contains(&k.as_str())) {
        return err(format!("unsupported MAC parameter: {k}"));
    }
    if sfv::get(params, "alg").is_some_and(|a| *a != Bare::String(ALG.into())) {
        return err("MAC algorithm must be hmac-sha256");
    }
    let key_share = match sfv::get(params, "keyid") {
        Some(Bare::String(k)) if vlatproto::syntax::valid_did(k) => k.clone(),
        _ => return err("missing or malformed keyid"),
    };
    Ok(Some(MacRequest {
        label: label.to_string(),
        key_share,
        signature_params: sfv::serialize_inner_list(items, params),
    }))
}

// ---- Responses ----

/// The `Atproto-Space-Commit` header: the commit's fields.
pub fn commit_header(c: &super::commit::Commit) -> String {
    let data = base64::engine::general_purpose::STANDARD.encode(c.data);
    sfv::serialize_dictionary(&vec![
        ("ver".into(), Member::Item(Bare::Number(c.ver as f64), vec![])),
        ("repo".into(), string(&c.repo)),
        ("space".into(), string(&c.space)),
        ("rev".into(), string(&c.rev)),
        ("data".into(), Member::Item(Bare::Bytes(data), vec![])),
    ])
}

/// The `Atproto-Space-Record` header: the record's uri and cid.
pub fn record_header(uri: &str, cid: &str) -> String {
    sfv::serialize_dictionary(&vec![("uri".into(), string(uri)), ("cid".into(), string(cid))])
}

/// The covered header, and the `Signature-Input` and `Signature` of a MAC
/// over it, keyed by the request's `secret`.
pub fn response_headers(
    p: Profile,
    covered: String,
    req: &MacRequest,
    secret: &[u8; 32],
) -> [(&'static str, String); 3] {
    let base = httpsig::base(&[p.component()], &[&covered], &req.signature_params);
    let mac = hmac(secret, &[&base]);
    let label = &req.label;
    [
        (p.name(), covered),
        ("signature-input", format!("{label}={}", req.signature_params)),
        ("signature", format!("{label}=:{}:", base64::engine::general_purpose::STANDARD.encode(mac))),
    ]
}

// ---- Verification ----

/// A syncer's check of a response's MAC, requested with `key_share` (whose
/// shared secret is `secret`): the fields of the header it covers.
fn verify(p: Profile, key_share: &str, secret: &[u8; 32], headers: &HeaderMap) -> Result<sfv::Dictionary, MacError> {
    let (input, sig) = (httpsig::joined(headers, "signature-input"), httpsig::joined(headers, "signature"));
    if input.as_ref().is_some_and(|f| f.len() > httpsig::MAX_FIELD)
        || sig.as_ref().is_some_and(|f| f.len() > httpsig::MAX_FIELD)
    {
        return err("missing or malformed signature headers");
    }
    let req = Required { tag: p.name(), components: &[p.component()], alg: ALG, key_id: key_share };
    let (params, mac) = httpsig::find_signature(input.as_deref(), sig.as_deref(), &req).map_err(MacError)?;
    let header = match httpsig::joined(headers, p.name()) {
        Some(h) if h.len() <= MAX_HEADER => h,
        _ => return err(format!("missing or malformed {} header", p.name())),
    };
    let fields =
        sfv::parse_dictionary(&header).map_err(|_| MacError(format!("malformed {} header", p.name()).into()))?;
    // `sf`: the header as re-serialized from its parsed form
    let base = httpsig::base(&[p.component()], &[&sfv::serialize_dictionary(&fields)], &params);
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    m.update(&base);
    m.verify_slice(&mac).map_err(|_| MacError("MAC does not match".into()))?;
    Ok(fields)
}

/// A member's bare value, ignoring any parameters.
fn bare<'a>(fields: &'a sfv::Dictionary, key: &str) -> Option<&'a Bare> {
    match sfv::get(fields, key)? {
        Member::Item(b, _) => Some(b),
        Member::InnerList(..) => None,
    }
}

/// The reference's `verifyCommitMac`: the response's MAC verifies, and the
/// `Atproto-Space-Commit` header it covers describes `c`.
pub fn verify_commit(
    c: &super::commit::Commit,
    key_share: &str,
    secret: &[u8; 32],
    headers: &HeaderMap,
) -> Result<(), MacError> {
    let f = verify(Profile::Commit, key_share, secret, headers)?;
    let s = |k| match bare(&f, k) {
        Some(Bare::String(v)) => Some(v.as_str()),
        _ => None,
    };
    let data = match bare(&f, "data") {
        Some(Bare::Bytes(b)) => httpsig::B64.decode(b).ok(),
        _ => None,
    };
    let matches = bare(&f, "ver") == Some(&Bare::Number(c.ver as f64))
        && s("repo") == Some(&c.repo)
        && s("space") == Some(&c.space)
        && s("rev") == Some(&c.rev)
        && data.as_deref() == Some(&c.data[..]);
    if !matches {
        return err("commit does not match its MAC");
    }
    Ok(())
}

/// The reference's `verifyRecordMac`: the response's MAC verifies, and the
/// `Atproto-Space-Record` header it covers names `uri` and `cid`.
pub fn verify_record(
    uri: &str,
    cid: &str,
    key_share: &str,
    secret: &[u8; 32],
    headers: &HeaderMap,
) -> Result<(), MacError> {
    let f = verify(Profile::Record, key_share, secret, headers)?;
    if bare(&f, "uri") != Some(&Bare::String(uri.into())) || bare(&f, "cid") != Some(&Bare::String(cid.into())) {
        return err("record does not match its MAC");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::space::commit::Commit;
    use crate::space::vectors::VECTORS;

    fn secret(hex_key: &str) -> p256::SecretKey {
        p256::SecretKey::from_slice(&hex::decode(hex_key).unwrap()).unwrap()
    }

    fn header_map(pairs: &[(&str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    fn json_headers(v: &serde_json::Value) -> Vec<(String, String)> {
        v.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect()
    }

    fn as_map(h: &[(String, String)]) -> HeaderMap {
        header_map(&h.iter().map(|(k, v)| (k.as_str(), v.clone())).collect::<Vec<_>>())
    }

    /// A vector's `headers` object.
    pub(crate) fn json_map(v: &serde_json::Value) -> HeaderMap {
        as_map(&json_headers(v))
    }

    /// testdata/spaces-alpha/vectors.json `kem`, `macRequests`, and the
    /// response headers of `commits` and `recordMacs`.
    #[test]
    fn generated_vectors() {
        for k in VECTORS["kem"].as_array().unwrap() {
            let author = secret(k["authorPrivate"].as_str().unwrap());
            assert_eq!(did_key(&author.public_key()), k["authorKey"].as_str().unwrap());
            let syncer = secret(k["syncerPrivate"].as_str().unwrap());
            let share = k["keyShare"].as_str().unwrap();
            assert_eq!(did_key(&syncer.public_key()), share);
            let want = k["sharedSecret"].as_str().unwrap();
            assert_eq!(hex::encode(decapsulate(&author, share).unwrap()), want);
            // the syncer's side, from its private key
            let dh = p256::ecdh::diffie_hellman(syncer.to_nonzero_scalar(), author.public_key().as_affine());
            let theirs = shared_secret(dh.raw_secret_bytes(), &syncer.public_key(), &author.public_key());
            assert_eq!(hex::encode(theirs), want);
        }
        let profile =
            |v: &serde_json::Value| if v == "atproto-space-commit" { Profile::Commit } else { Profile::Record };
        for r in VECTORS["macRequests"].as_array().unwrap() {
            let p = profile(&r["profile"]);
            let share = r["keyShare"].as_str().unwrap();
            assert_eq!(format_request(p, share), r["header"].as_str().unwrap());
            assert_eq!(parse_request(r["header"].as_str(), p).unwrap().unwrap().key_share, share);
        }
        for (cases, p) in [("commits", Profile::Commit), ("recordMacs", Profile::Record)] {
            for c in VECTORS[cases].as_array().unwrap() {
                let s: [u8; 32] = hex::decode(c["sharedSecret"].as_str().unwrap()).unwrap().try_into().unwrap();
                let req = parse_request(c["request"].as_str(), p).unwrap().unwrap();
                let covered = match p {
                    Profile::Commit => commit_header(&Commit::from_json(&c["commit"]).unwrap()),
                    Profile::Record => record_header(c["uri"].as_str().unwrap(), c["cid"].as_str().unwrap()),
                };
                let mut want = json_headers(&c["headers"]);
                want.sort();
                let mut got: Vec<(String, String)> =
                    response_headers(p, covered, &req, &s).iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
                got.sort();
                assert_eq!(got, want);
                let h = as_map(&want);
                match p {
                    Profile::Commit => {
                        verify_commit(&Commit::from_json(&c["commit"]).unwrap(), &req.key_share, &s, &h).unwrap()
                    }
                    Profile::Record => {
                        verify_record(c["uri"].as_str().unwrap(), c["cid"].as_str().unwrap(), &req.key_share, &s, &h)
                            .unwrap()
                    }
                }
            }
        }
    }

    // The cases below are the reference's tests/kem.test.ts.

    #[test]
    fn round_trips() {
        let author = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        let (share, a) = encapsulate(&did_key(&author.public_key())).unwrap();
        assert_eq!(decapsulate(&author, &share).unwrap(), a);
        // a fresh key share every time
        let (share2, b) = encapsulate(&did_key(&author.public_key())).unwrap();
        assert_ne!(share, share2);
        assert_ne!(a, b);
        // another author's key derives another secret
        let other = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        assert_ne!(decapsulate(&other, &share).unwrap(), a);
    }

    #[test]
    fn keys_must_be_p256() {
        let k256 = vlatproto::crypto::Keypair::generate().did_key();
        assert_eq!(encapsulate(&k256), err("KEM key must be a P-256 did:key"));
        assert_eq!(encapsulate("did:key:znope"), err("invalid KEM key"));
        let author = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        assert!(decapsulate(&author, &k256).is_err());
        assert!(decapsulate(&author, "did:key:nope").is_err());
    }

    /// The export-only DHKEM(P-256, HKDF-SHA256) keys of the HPKE test
    /// vectors (`enc`, `skRm`); the secret is Go crypto/hpke's for `info`
    /// "atproto-mac" and an empty exporter context.
    #[test]
    fn hpke_secret_export() {
        let enc = p256::PublicKey::from_sec1_bytes(&hex::decode("04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d").unwrap()).unwrap();
        let author = secret("62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346");
        assert_eq!(
            hex::encode(decapsulate(&author, &did_key(&enc)).unwrap()),
            "2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d"
        );
    }

    // The cases below are the reference's tests/mac.test.ts.

    const KEY_SHARE: &str = "did:key:zDnaExample";
    const SPACE: &str = "at://did:example:space/space/app.bsky.group/test";
    const CID_A: &str = "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244";
    const CID_B: &str = "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a";

    fn uri() -> String {
        format!("{SPACE}/did:example:alice/app.bsky.feed.post/1")
    }

    fn commit() -> Commit {
        Commit {
            ver: 1,
            space: SPACE.into(),
            repo: "did:example:alice".into(),
            rev: "3kbcq3p7ad400".into(),
            data: [1; 32],
        }
    }

    /// What a syncer verifies with after a host MACs under `host` (the
    /// syncer expects `secret`).
    fn commit_mac(c: &Commit, host: &[u8; 32]) -> Vec<(String, String)> {
        let req = parse_request(Some(&format_request(Profile::Commit, KEY_SHARE)), Profile::Commit).unwrap().unwrap();
        response_headers(Profile::Commit, commit_header(c), &req, host)
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn record_mac(uri: &str, cid: &str, host: &[u8; 32]) -> Vec<(String, String)> {
        let req = parse_request(Some(&format_request(Profile::Record, KEY_SHARE)), Profile::Record).unwrap().unwrap();
        response_headers(Profile::Record, record_header(uri, cid), &req, host)
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn get(h: &[(String, String)], name: &str) -> String {
        h.iter().find(|(k, _)| k == name).unwrap().1.clone()
    }

    fn set(h: &mut [(String, String)], name: &str, v: String) {
        h.iter_mut().find(|(k, _)| k == name).unwrap().1 = v;
    }

    fn parse(h: &str) -> Result<Option<MacRequest>, MacError> {
        parse_request(Some(h), Profile::Commit)
    }

    #[test]
    fn formats_accept_signature() {
        assert_eq!(
            format_request(Profile::Commit, KEY_SHARE),
            "mac=(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaExample\";tag=\"atproto-space-commit\""
        );
        assert_eq!(
            format_request(Profile::Record, KEY_SHARE),
            "mac=(\"atproto-space-record\";sf);keyid=\"did:key:zDnaExample\";tag=\"atproto-space-record\""
        );
    }

    #[test]
    fn request_round_trips() {
        let h = format_request(Profile::Commit, KEY_SHARE);
        assert_eq!(
            parse(&h).unwrap(),
            Some(MacRequest {
                label: "mac".into(),
                key_share: KEY_SHARE.into(),
                signature_params: h["mac=".len()..].into()
            })
        );
    }

    #[test]
    fn request_found_by_tag_under_any_label() {
        let h = format!("other=(\"content-digest\");tag=\"other\", m=(\"atproto-space-commit\";sf);keyid=\"{KEY_SHARE}\";tag=\"atproto-space-commit\"");
        let r = parse(&h).unwrap().unwrap();
        assert_eq!((r.label.as_str(), r.key_share.as_str()), ("m", KEY_SHARE));
    }

    #[test]
    fn request_alg() {
        let h = format_request(Profile::Commit, KEY_SHARE);
        assert!(parse(&format!("{h};alg=\"hmac-sha256\"")).is_ok());
        assert!(parse(&format!("{h};alg=\"ecdsa-p256-sha256\"")).unwrap_err().0.contains("algorithm"));
    }

    #[test]
    fn no_request_with_the_tag() {
        assert_eq!(parse_request(None, Profile::Commit), Ok(None));
        // other tags are ignored, another profile's included
        let h = format!("other=(\"content-digest\");tag=\"other\", {}", format_request(Profile::Record, KEY_SHARE));
        assert_eq!(parse(&h), Ok(None));
    }

    #[test]
    fn malformed_requests() {
        assert!(parse("???").is_err());
        let one = format!("(\"atproto-space-commit\";sf);keyid=\"{KEY_SHARE}\";tag=\"atproto-space-commit\"");
        assert!(parse(&format!("a={one}, b={one}")).unwrap_err().0.contains("more than one MAC requested"));
        let h = format_request(Profile::Commit, KEY_SHARE);
        for param in ["created", "expires", "nonce=\"abc\""] {
            assert!(parse(&format!("{h};{param}")).unwrap_err().0.contains("unsupported MAC parameter"), "{param}");
        }
        for components in [
            "(\"atproto-space-record\";sf)",
            "(\"atproto-space-commit\")",
            "(\"atproto-space-commit\";sf \"authorization\")",
        ] {
            let h = format!("mac={components};keyid=\"{KEY_SHARE}\";tag=\"atproto-space-commit\"");
            assert!(parse(&h).unwrap_err().0.contains("must cover exactly"), "{components}");
        }
        for keyid in ["", ";keyid=\"not-a-did\"", ";keyid=did"] {
            let h = format!("mac=(\"atproto-space-commit\";sf){keyid};tag=\"atproto-space-commit\"");
            assert!(parse(&h).unwrap_err().0.contains("keyid"), "{keyid}");
        }
        // oversized, before parsing
        let pad: String = (0..2000).map(|i| format!("k{i}=1, ")).collect();
        assert!(parse(&format!("{pad}{h}")).is_err());
    }

    #[test]
    fn commit_header_and_mac() {
        let s: [u8; 32] = rand::random();
        let req =
            parse(&format!("sig1=(\"atproto-space-commit\";sf);keyid=\"{KEY_SHARE}\";tag=\"atproto-space-commit\""))
                .unwrap()
                .unwrap();
        let h = response_headers(Profile::Commit, commit_header(&commit()), &req, &s);
        let covered = format!("ver=1, repo=\"did:example:alice\", space=\"{SPACE}\", rev=\"3kbcq3p7ad400\", data=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:");
        let params = format!("(\"atproto-space-commit\";sf);keyid=\"{KEY_SHARE}\";tag=\"atproto-space-commit\"");
        assert_eq!(h[0], ("atproto-space-commit", covered.clone()));
        assert_eq!(h[1], ("signature-input", format!("sig1={params}")));
        // an RFC 9421 hmac-sha256 signature over the covered header
        let base = format!("\"atproto-space-commit\";sf: {covered}\n\"@signature-params\": {params}");
        let mac = base64::engine::general_purpose::STANDARD.encode(hmac(&s, &[base.as_bytes()]));
        assert_eq!(h[2], ("signature", format!("sig1=:{mac}:")));
    }

    #[test]
    fn commit_macs_verify() {
        let s: [u8; 32] = rand::random();
        let c = commit();
        assert_eq!(verify_commit(&c, KEY_SHARE, &s, &as_map(&commit_mac(&c, &s))), Ok(()));
        let other = as_map(&commit_mac(&c, &rand::random()));
        assert!(verify_commit(&c, KEY_SHARE, &s, &other).unwrap_err().0.contains("MAC does not match"));
        for changed in [
            Commit { ver: 2, ..commit() },
            Commit { repo: "did:example:bob".into(), ..commit() },
            Commit { space: format!("{SPACE}2"), ..commit() },
            Commit { rev: "3kbcq3p7ad401".into(), ..commit() },
            Commit { data: [2; 32], ..commit() },
        ] {
            let e = verify_commit(&changed, KEY_SHARE, &s, &as_map(&commit_mac(&c, &s))).unwrap_err();
            assert!(e.0.contains("commit does not match its MAC"), "{changed:?}");
        }
        // a tampered header
        let mut h = commit_mac(&c, &s);
        let v = get(&h, "atproto-space-commit").replace("3kbcq3p7ad400", "3kbcq3p7ad401");
        set(&mut h, "atproto-space-commit", v);
        let e = verify_commit(&Commit { rev: "3kbcq3p7ad401".into(), ..commit() }, KEY_SHARE, &s, &as_map(&h));
        assert!(e.unwrap_err().0.contains("MAC does not match"));
        // the header is covered as a structured field: whitespace isn't
        let mut h = commit_mac(&c, &s);
        let v = get(&h, "atproto-space-commit").replace(", ", ",   ");
        set(&mut h, "atproto-space-commit", v);
        assert_eq!(verify_commit(&c, KEY_SHARE, &s, &as_map(&h)), Ok(()));
        // found by its tag, under any label
        let mut h = commit_mac(&c, &s);
        for name in ["signature-input", "signature"] {
            let v = get(&h, name).replacen("mac=", "other=", 1);
            set(&mut h, name, v);
        }
        assert_eq!(verify_commit(&c, KEY_SHARE, &s, &as_map(&h)), Ok(()));
        // more than one with the tag
        let mut h = commit_mac(&c, &s);
        for name in ["signature-input", "signature"] {
            let v = get(&h, name);
            set(&mut h, name, format!("{v}, {}", v.replacen("mac=", "other=", 1)));
        }
        assert!(verify_commit(&c, KEY_SHARE, &s, &as_map(&h)).unwrap_err().0.contains("more than one"));
        for name in ["atproto-space-commit", "signature-input", "signature"] {
            let mut m = as_map(&commit_mac(&c, &s));
            m.remove(name);
            assert!(verify_commit(&c, KEY_SHARE, &s, &m).is_err(), "{name}");
        }
    }

    /// A MAC under other signature parameters, as a host other than this
    /// one might answer.
    #[test]
    fn mac_parameters() {
        let s: [u8; 32] = rand::random();
        let c = commit();
        let with = |params: &str| {
            let mut h = commit_mac(&c, &s);
            let covered = get(&h, "atproto-space-commit");
            let base = format!("\"atproto-space-commit\";sf: {covered}\n\"@signature-params\": {params}");
            let mac = base64::engine::general_purpose::STANDARD.encode(hmac(&s, &[base.as_bytes()]));
            set(&mut h, "signature-input", format!("mac={params}"));
            set(&mut h, "signature", format!("mac=:{mac}:"));
            verify_commit(&c, KEY_SHARE, &s, &as_map(&h))
        };
        for ok in [
            format!(
                "(\"atproto-space-commit\";sf);tag=\"atproto-space-commit\";created=1700000000;keyid=\"{KEY_SHARE}\""
            ),
            "(\"atproto-space-commit\";sf);tag=\"atproto-space-commit\"".into(),
            format!(
                "(\"atproto-space-commit\";sf);keyid=\"{KEY_SHARE}\";tag=\"atproto-space-commit\";alg=\"hmac-sha256\""
            ),
        ] {
            assert_eq!(with(&ok), Ok(()), "{ok}");
        }
        for (bad, e) in [
            ("(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaOther\";tag=\"atproto-space-commit\"".into(), "keyid does not match"),
            (format!("(\"atproto-space-commit\";sf);keyid=\"{KEY_SHARE}\";tag=\"atproto-space-commit\";alg=\"hmac-sha512\""), "algorithm"),
            (format!("(\"atproto-space-commit\";sf);keyid=\"{KEY_SHARE}\";tag=\"other\""), "missing or malformed signature with tag"),
            (format!("(\"atproto-space-commit\");keyid=\"{KEY_SHARE}\";tag=\"atproto-space-commit\""), "must cover exactly"),
        ] {
            assert!(with(&bad).unwrap_err().0.contains(e), "{bad}");
        }
    }

    #[test]
    fn record_macs() {
        let s: [u8; 32] = rand::random();
        let (uri, c) = (uri(), commit());
        let h = record_mac(&uri, CID_A, &s);
        assert_eq!(get(&h, "atproto-space-record"), format!("uri=\"{uri}\", cid=\"{CID_A}\""));
        assert_eq!(verify_record(&uri, CID_A, KEY_SHARE, &s, &as_map(&h)), Ok(()));
        let other = as_map(&record_mac(&uri, CID_A, &rand::random()));
        assert!(verify_record(&uri, CID_A, KEY_SHARE, &s, &other).unwrap_err().0.contains("MAC does not match"));
        for (u, cid) in [(format!("{uri}2"), CID_A), (uri.clone(), CID_B)] {
            let e = verify_record(&u, cid, KEY_SHARE, &s, &as_map(&h)).unwrap_err();
            assert!(e.0.contains("record does not match its MAC"));
        }
        // never accepted as a commit MAC
        let e = verify_commit(&c, KEY_SHARE, &s, &as_map(&h)).unwrap_err();
        assert!(e.0.contains("missing or malformed signature with tag \"atproto-space-commit\""), "{e}");
    }
}
