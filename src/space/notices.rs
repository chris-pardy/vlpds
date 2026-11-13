//! Notices to registered syncers, delivered reliably (reference
//! `SpaceNotifications.notifySyncers`): `spaceDeleted` to each registration
//! of a space when it's deleted (lapsed ones too), and `registrationExpired`
//! to a lapsed one in place of the first update after it lapsed. Each is
//! sent at once, to many registrations in parallel; a send that fails for
//! a reason worth retrying leaves an `sY` row in the authority's shard,
//! which the shard's owner retries after 1 min, 10 min, 1 h, 6 h, then
//! every 12 h (50-100% of each), until a retry fails after the 72 h window.
//! One row per registration: a deletion notice replaces a pending expiry
//! notice, never the reverse, so a deletion notice is never lost.
//!
//! A syncer that rejects its expiry notice (a status not worth retrying),
//! or can't be reached within the window, is unregistered, unless it
//! renewed meanwhile. A notice that no longer applies is dropped unsent: an
//! expiry once the registration was renewed or is gone, a deletion once
//! the space is live again. A retry waits while the authority is inactive,
//! and is dropped once its account is gone (its deletion sweeps `sY` too).
//! A retry clears or replaces its row only while it's still the one it
//! read, so an older delivery finishing never drops a newer notice.
//!
//! The Nov 5 alpha's rows, `sN` registrations and `sD` notifySpaceDeleted
//! retries, name a service and no token: they can't be sent
//! notifySpaceUpdate, and a syncer registers again the next time it
//! authorizes. The same pass deletes them.

use super::rows::RegistrationRow;
use crate::state::{self, RegId, SpaceId};
use crate::xrpc::App;
use futures::StreamExt;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use vlatproto::tid::Tid;

const EVERY: Duration = Duration::from_secs(30);
/// A retry's pause after each failed attempt in turn, the last repeating.
const DELAYS: [Duration; 5] = [
    Duration::from_secs(60),
    Duration::from_secs(600),
    Duration::from_secs(3600),
    Duration::from_secs(6 * 3600),
    Duration::from_secs(12 * 3600),
];
/// Retried for at least this long: the retry that fails past it is the last.
pub const WINDOW: Duration = Duration::from_secs(72 * 3600);
/// Registrations one notice goes to at once (reference
/// `SYNCER_NOTIFY_CONCURRENCY`).
const CONCURRENCY: usize = 50;
/// Legacy rows deleted per entry.
const LEGACY_BATCH: usize = 500;

const SPACE_DELETED: &str = "com.atproto.space.notifySpaceUpdate#spaceDeleted";
const REGISTRATION_EXPIRED: &str = "com.atproto.space.notifySpaceUpdate#registrationExpired";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    Deleted,
    /// In place of the update at `space_rev`.
    Expired {
        space_rev: Tid,
    },
}

impl Notice {
    fn update(&self) -> serde_json::Value {
        match self {
            Notice::Deleted => json!({"$type": SPACE_DELETED}),
            Notice::Expired { space_rev } => json!({"$type": REGISTRATION_EXPIRED, "spaceRev": space_rev.to_string()}),
        }
    }
}

/// `sY`: a notice owed to one registration (JSON).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeRow {
    pub uri: String,
    pub endpoint: String,
    pub token: String,
    /// `spaceDeleted` or `registrationExpired`.
    pub notice: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_rev: Option<String>,
    pub attempts: u32,
    /// Unix µs.
    pub retry_at: u64,
    /// The end of the retry window (unix µs).
    pub expires_at: u64,
}

impl NoticeRow {
    fn notice(&self) -> Option<Notice> {
        match self.notice.as_str() {
            "spaceDeleted" => Some(Notice::Deleted),
            "registrationExpired" => {
                Some(Notice::Expired { space_rev: self.space_rev.as_deref().and_then(Tid::parse)? })
            }
            _ => None,
        }
    }

    fn id(&self) -> RegId {
        state::reg_id(&self.endpoint, &self.token)
    }
}

fn next_retry(attempts: u32, now: u64) -> u64 {
    let d = DELAYS[(attempts.max(1) as usize).min(DELAYS.len()) - 1];
    now + d.mul_f64(0.5 + rand::random::<f64>() / 2.0).as_micros() as u64
}

enum Sent {
    Delivered,
    Refused(String),
    Retry(String),
}

async fn send(app: &App, uri: &str, endpoint: &str, token: &str, notice: Notice) -> Sent {
    let body = json!({"space": uri, "token": token, "update": notice.update()});
    let client = vlatproto::http::guarded_fanout(app.config.dev_mode);
    match super::host::post_endpoint(client, endpoint, super::host::NOTIFY_SPACE_UPDATE, &body).await {
        Ok((s, _)) if (200..300).contains(&s) => Sent::Delivered,
        Ok((s, _)) if crate::xrpc::space::retryable_status(s) => Sent::Retry(format!("status {s}")),
        Ok((s, _)) => Sent::Refused(format!("status {s}")),
        Err(e) => Sent::Retry(e),
    }
}

fn label(n: Notice) -> &'static str {
    match n {
        Notice::Deleted => "spaceDeleted",
        Notice::Expired { .. } => "registrationExpired",
    }
}

/// Sends `notice` about `space` to each of `regs`, leaving an `sY` row for
/// each send worth retrying; a rejected expiry notice unregisters.
pub async fn notify(
    app: &Arc<App>,
    authority: &str,
    space: &str,
    sid: SpaceId,
    regs: Vec<RegistrationRow>,
    notice: Notice,
) {
    let log_id = state::space_log_id(space);
    futures::stream::iter(regs)
        .for_each_concurrent(CONCURRENCY, |reg| {
            let log_id = &log_id;
            async move {
                let id = hex::encode(reg.id());
                match send(app, space, &reg.endpoint, &reg.token, notice).await {
                    Sent::Delivered => crate::metrics::space_notify("notice", "ok"),
                    Sent::Refused(e) => {
                        crate::metrics::space_notify("notice", "refused");
                        tracing::info!(space = %log_id, reg = id, "{} refused, not retried: {e}", label(notice));
                        abandon(app, space, &reg.endpoint, &reg.token, notice).await;
                    }
                    Sent::Retry(e) => {
                        crate::metrics::space_notify("notice", "error");
                        tracing::info!(space = %log_id, reg = id, "{} queued for retry: {e}", label(notice));
                        if let Err(e) = queue(app, authority, space, sid, &reg, notice).await {
                            tracing::warn!(space = %log_id, reg = id, "{} retry not stored: {e:#}", label(notice));
                        }
                    }
                }
            }
        })
        .await;
}

/// The row for a failed send: a deletion notice replaces whatever is
/// pending; an expiry notice never replaces a pending one.
async fn queue(
    app: &App,
    authority: &str,
    space: &str,
    sid: SpaceId,
    reg: &RegistrationRow,
    notice: Notice,
) -> anyhow::Result<()> {
    let sp = crate::xrpc::space::spaces(app).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let _lock = sp.registering(&sid).await;
    let id = reg.id();
    if matches!(notice, Notice::Expired { .. }) && current(app, authority, &sid, &id).await?.is_some() {
        return Ok(());
    }
    let now = vlatproto::tid::now_micros();
    let row = NoticeRow {
        uri: space.to_string(),
        endpoint: reg.endpoint.clone(),
        token: reg.token.clone(),
        notice: label(notice).to_string(),
        space_rev: match notice {
            Notice::Expired { space_rev } => Some(space_rev.to_string()),
            Notice::Deleted => None,
        },
        attempts: 1,
        retry_at: next_retry(1, now),
        expires_at: now + WINDOW.as_micros() as u64,
    };
    put(app, authority, &sid, &id, Some(&row)).await
}

/// Gives up on a notice: a lapsed registration that rejected its expiry
/// notice, or couldn't be reached, is unregistered, unless it renewed
/// meanwhile. A deleted space's registrations went with it.
async fn abandon(app: &App, space: &str, endpoint: &str, token: &str, notice: Notice) {
    if notice == Notice::Deleted {
        return;
    }
    let id = state::reg_id(endpoint, token);
    if let Err(e) = crate::xrpc::space::unregister_lapsed(app, space, &id, vlatproto::tid::now_micros()).await {
        tracing::info!(space = %state::space_log_id(space), reg = hex::encode(id), "lapsed registration not dropped: {e:#}");
    }
}

async fn put(app: &App, authority: &str, sid: &SpaceId, id: &RegId, row: Option<&NoticeRow>) -> anyhow::Result<()> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let key = state::space_notice_key(authority, sid, id);
    let val = row.map(|r| bytes::Bytes::from(serde_json::to_vec(r).expect("serializes")));
    crate::xrpc::write_private_local(&p, vec![vlsync_store::segment::Mutation { key: key.into(), val }])
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.message))
}

/// Starts the retries of the shards this node owns (with `--spaces`).
pub fn start(app: &Arc<App>) {
    if app.spaces.is_none() {
        return;
    }
    let weak = Arc::downgrade(app);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(EVERY.mul_f64(0.8 + 0.4 * rand::random::<f64>())).await;
            let Some(app) = weak.upgrade() else { return };
            if let Err(e) = retry_due(&app, vlatproto::tid::now_micros()).await {
                tracing::warn!("space syncer notice retries failed: {e:#}");
            }
        }
    });
}

/// One pass over the owned shards at `now` (unix µs): the Nov 5 rows go,
/// and the `sY` rows due are retried. Returns how many `sY` rows it settled
/// (delivered, given up on or dropped).
pub async fn retry_due(app: &Arc<App>, now: u64) -> anyhow::Result<usize> {
    let mut settled = 0;
    for p in app.partitions.owned() {
        drop_legacy(&p).await?;
        let opts = slatedb::config::ScanOptions::default();
        let mut scan = state::FamilyScan::new(&*p.db, state::SPACE_NOTICE_FAMILY, None, &opts).await?;
        let mut due = Vec::new();
        while let Some(kv) = scan.next().await? {
            let Some((authority, sid)) = super::rows::did_sid_head(&kv.key) else { continue };
            let row: NoticeRow = match serde_json::from_slice(&kv.value) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("undecodable syncer notice row skipped: {e}");
                    continue;
                }
            };
            if row.retry_at <= now {
                due.push((authority.to_string(), sid, row));
            }
        }
        drop(scan);
        for (authority, sid, row) in due {
            settled += retry_one(app, &authority, sid, row, now).await? as usize;
        }
    }
    Ok(settled)
}

/// Deletes the shard's `sN` and `sD` rows (the Nov 5 alpha's).
async fn drop_legacy(p: &crate::partition::Partition) -> anyhow::Result<()> {
    for fam in [state::SPACE_NOTIFY_FAMILY, state::SPACE_DELETED_FAMILY] {
        loop {
            let opts = slatedb::config::ScanOptions::default();
            let mut scan = state::FamilyScan::new(&*p.db, fam, None, &opts).await?;
            let mut muts = Vec::new();
            while muts.len() < LEGACY_BATCH {
                let Some(kv) = scan.next().await? else { break };
                muts.push(vlsync_store::segment::Mutation { key: kv.key, val: None });
            }
            drop(scan);
            if muts.is_empty() {
                break;
            }
            let n = muts.len();
            crate::xrpc::write_private_local(p, muts).await.map_err(|e| anyhow::anyhow!("{}", e.message))?;
            tracing::info!(
                family = %String::from_utf8_lossy(fam),
                rows = n,
                "Nov 5 space notify rows dropped (registerNotify registrations name no token)"
            );
            if n < LEGACY_BATCH {
                break;
            }
        }
    }
    Ok(())
}

/// Ok(true) when the row is settled and cleared.
async fn retry_one(app: &Arc<App>, authority: &str, sid: SpaceId, row: NoticeRow, now: u64) -> anyhow::Result<bool> {
    let log_id = state::space_log_id(&row.uri);
    let id = row.id();
    let reg = hex::encode(id);
    let clear = |why: &str| tracing::info!(space = %log_id, reg, "{} retry dropped: {why}", row.notice);
    let Some(notice) = row.notice() else {
        clear("not a notice this host sends");
        return clear_if_same(app, authority, &sid, &row).await;
    };
    let account = match app.account(authority).await {
        Ok(a) if a.status.as_deref() != Some("deleted") => a,
        Ok(_) => {
            clear("the authority's account is gone");
            return clear_if_same(app, authority, &sid, &row).await;
        }
        Err(e) if e.error == "AccountNotFound" => {
            clear("the authority's account is gone");
            return clear_if_same(app, authority, &sid, &row).await;
        }
        Err(e) => anyhow::bail!("{}", e.message),
    };
    if account.status.is_some() {
        return reschedule(app, authority, &sid, &row, notice, now).await;
    }
    if !owed(app, authority, &sid, &id, notice, now).await? {
        clear("it no longer applies");
        return clear_if_same(app, authority, &sid, &row).await;
    }
    match send(app, &row.uri, &row.endpoint, &row.token, notice).await {
        Sent::Delivered => clear_if_same(app, authority, &sid, &row).await,
        Sent::Refused(e) => {
            clear(&e);
            let cleared = clear_if_same(app, authority, &sid, &row).await?;
            abandon(app, &row.uri, &row.endpoint, &row.token, notice).await;
            Ok(cleared)
        }
        Sent::Retry(e) => {
            tracing::info!(space = %log_id, reg, attempts = row.attempts, "{} retry failed: {e}", row.notice);
            reschedule(app, authority, &sid, &row, notice, now).await
        }
    }
}

/// Whether the notice still applies: an expiry while the registration is
/// there and lapsed, a deletion while the space is a tombstone.
async fn owed(app: &App, authority: &str, sid: &SpaceId, id: &RegId, notice: Notice, now: u64) -> anyhow::Result<bool> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    Ok(match notice {
        Notice::Expired { .. } => match p.db.get(state::space_registration_key(authority, sid, id)).await? {
            Some(v) => RegistrationRow::decode(&v)?.lapsed(now),
            None => false,
        },
        Notice::Deleted => match p.db.get(state::space_key(authority, sid)).await? {
            Some(v) => !super::rows::SpaceRow::decode(&v)?.live(),
            None => false,
        },
    })
}

/// Another attempt later, or, past the window, the notice given up on.
async fn reschedule(
    app: &Arc<App>,
    authority: &str,
    sid: &SpaceId,
    row: &NoticeRow,
    notice: Notice,
    now: u64,
) -> anyhow::Result<bool> {
    if row.expires_at <= now {
        tracing::info!(space = %state::space_log_id(&row.uri), reg = hex::encode(row.id()), "{} given up after 72 hours", row.notice);
        let cleared = clear_if_same(app, authority, sid, row).await?;
        abandon(app, &row.uri, &row.endpoint, &row.token, notice).await;
        return Ok(cleared);
    }
    let next = NoticeRow { attempts: row.attempts + 1, retry_at: next_retry(row.attempts + 1, now), ..row.clone() };
    if current(app, authority, sid, &row.id()).await?.as_ref() == Some(row) {
        put(app, authority, sid, &row.id(), Some(&next)).await?;
    }
    Ok(false)
}

async fn current(app: &App, authority: &str, sid: &SpaceId, id: &RegId) -> anyhow::Result<Option<NoticeRow>> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    match p.db.get(state::space_notice_key(authority, sid, id)).await? {
        Some(v) => Ok(Some(serde_json::from_slice(&v)?)),
        None => Ok(None),
    }
}

async fn clear_if_same(app: &App, authority: &str, sid: &SpaceId, read: &NoticeRow) -> anyhow::Result<bool> {
    let id = read.id();
    if current(app, authority, sid, &id).await?.as_ref() != Some(read) {
        return Ok(false);
    }
    put(app, authority, sid, &id, None).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_runs_from_a_minute_to_twelve_hours() {
        let now = 1_000_000_000;
        let d = |a| Duration::from_micros(next_retry(a, now) - now);
        for (a, full) in [(1, 60), (2, 600), (3, 3600), (4, 6 * 3600), (5, 12 * 3600), (9, 12 * 3600)] {
            let full = Duration::from_secs(full);
            assert!(d(a) >= full / 2 && d(a) <= full, "{a}: {:?}", d(a));
        }
    }

    #[test]
    fn rows_round_trip() {
        let r = NoticeRow {
            uri: "at://did:plc:a/space/t.t/k".into(),
            endpoint: "https://s".into(),
            token: "t".into(),
            notice: "registrationExpired".into(),
            space_rev: Some(Tid(1 << 40).to_string()),
            attempts: 2,
            retry_at: 5,
            expires_at: 9,
        };
        let back: NoticeRow = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.notice(), Some(Notice::Expired { space_rev: Tid(1 << 40) }));
        let d = NoticeRow { notice: "spaceDeleted".into(), space_rev: None, ..r };
        assert_eq!(d.notice(), Some(Notice::Deleted));
        assert!(!String::from_utf8(serde_json::to_vec(&d).unwrap()).unwrap().contains("spaceRev"));
    }

    #[test]
    fn notices_are_typed_as_the_lexicon_names_them() {
        assert_eq!(Notice::Deleted.update(), json!({"$type": "com.atproto.space.notifySpaceUpdate#spaceDeleted"}));
        let t = Tid(1 << 40);
        assert_eq!(
            Notice::Expired { space_rev: t }.update(),
            json!({"$type": "com.atproto.space.notifySpaceUpdate#registrationExpired", "spaceRev": t.to_string()})
        );
    }
}
