//! The reference's tests/space/notifications.test.ts "syncer notices": a
//! deletion or expiry notice whose send fails is kept (`sY`) and retried
//! by the authority's shard owner. Retries run here through
//! `vlpds::space::notices::retry_due` with a clock ahead of the backoff.

use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::time::Duration;

const DELETED: &str = "com.atproto.space.notifySpaceUpdate#spaceDeleted";
const EXPIRED: &str = "com.atproto.space.notifySpaceUpdate#registrationExpired";
const HOUR: Duration = Duration::from_secs(3600);

async fn registered(net: &Net, owner: &SpaceClient, reader: &SpaceClient, skey: &str) -> (String, MockService) {
    let syncer = MockService::syncer().await;
    let space = net.create_space(owner, SpaceOpts { skey: Some(skey), members: &[reader], ..Default::default() }).await;
    net.register(reader, &space, syncer.notify()).await.ok();
    (space, syncer)
}

async fn delete(owner: &SpaceClient, space: &str) {
    owner.post("com.atproto.space.deleteSpace", json!({"space": space})).await.ok();
}

fn types(syncer: &MockService) -> Vec<J> {
    syncer.updates().into_iter().map(|u| u["$type"].clone()).collect()
}

/// The registration lapsed and a write after it, so its expiry notice was
/// sent (once).
async fn lapsed_and_told(net: &Net, owner: &SpaceClient, space: &str, syncer: &MockService) {
    net.lapse(space, syncer, &syncer.token, Duration::from_secs(1)).await;
    write(owner, space, W::new()).await.ok();
    syncer.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("the expiry notice");
    tokio::time::sleep(Duration::from_millis(300)).await;
}

/// "sends immediately without queueing a successful notification", "retries
/// a transient failure until delivered" and "does not retry a permanent
/// failure".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deliveries_and_retries() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);

    let (space, ok) = registered(&net, &alice, &bob, "sent").await;
    delete(&alice, &space).await;
    ok.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("told at once");
    assert_eq!(net.retry_notices(&space, HOUR).await, 0, "nothing queued");
    assert_eq!(types(&ok), [json!(DELETED)]);

    let (space, flaky) = registered(&net, &alice, &bob, "flaky").await;
    flaky.respond(503, json!({"error": "Unavailable"}));
    delete(&alice, &space).await;
    flaky.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("the first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(net.pending_notices(&space).await.len(), 1);
    assert_eq!(net.retry_notices(&space, Duration::ZERO).await, 0, "not due yet");
    flaky.respond(200, json!({}));
    assert_eq!(net.retry_notices(&space, HOUR).await, 1, "delivered on retry");
    assert_eq!(types(&flaky), [json!(DELETED), json!(DELETED)]);
    assert_eq!(net.retry_notices(&space, 4 * HOUR).await, 0, "and cleared");

    let (space, gone) = registered(&net, &alice, &bob, "gone").await;
    gone.respond(400, json!({"error": "InvalidRequest"}));
    delete(&alice, &space).await;
    gone.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("the first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(net.retry_notices(&space, 2 * HOUR).await, 0, "a permanent failure isn't kept");
    assert_eq!(gone.calls_to(NOTIFY_SPACE_UPDATE).len(), 1);
}

/// "backs off from a minute to twelve hours" (the schedule itself is
/// `space::notices`' unit test) and "stops retrying after a final retry
/// past 72 hours".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_back_off_and_end_past_72_hours() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let (space, down) = registered(&net, &alice, &bob, "down").await;
    down.respond(503, json!({}));
    delete(&alice, &space).await;
    down.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("the first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let first = net.pending_notices(&space).await;
    assert_eq!(first[0]["attempts"], json!(1));
    assert_eq!(net.retry_notices(&space, Duration::from_secs(20)).await, 0, "not before half a minute");
    assert_eq!(net.retry_notices(&space, Duration::from_secs(61)).await, 0, "retried, still failing");
    let second = net.pending_notices(&space).await;
    assert_eq!(second[0]["attempts"], json!(2));
    let wait = second[0]["retryAt"].as_u64().unwrap() - first[0]["retryAt"].as_u64().unwrap();
    assert!(wait >= 4 * 60 * 1_000_000, "the second pause is longer: {wait} µs");
    assert_eq!(down.calls_to(NOTIFY_SPACE_UPDATE).len(), 2);
    // within the window it's kept; the retry that fails after it is the last
    assert_eq!(net.retry_notices(&space, 71 * HOUR).await, 0);
    assert_eq!(net.pending_notices(&space).await.len(), 1);
    assert_eq!(net.retry_notices(&space, 73 * HOUR).await, 1, "given up");
    assert!(net.pending_notices(&space).await.is_empty());
}

/// "defers retries while the authority is inactive" (vlpds: no send while
/// it's deactivated; resumed once it's active again).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_wait_while_the_authority_is_inactive() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let (space, down) = registered(&net, &alice, &bob, "inactive").await;
    down.respond(503, json!({}));
    delete(&alice, &space).await;
    down.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("the first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    down.respond(200, json!({}));
    let s = &net.pds[0];
    let session = Auth::Bearer(alice.session_jwt.clone());
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &session).await.ok();
    assert_eq!(net.retry_notices(&space, HOUR).await, 0);
    assert_eq!(down.calls_to(NOTIFY_SPACE_UPDATE).len(), 1, "sent while inactive");
    assert_eq!(net.pending_notices(&space).await.len(), 1, "kept");
    let session = s.create_session(&alice.did, crate::oauth::PASSWORD).await.ok();
    let session = Auth::Bearer(session["accessJwt"].as_str().unwrap().into());
    s.xrpc.post("com.atproto.server.activateAccount", &json!({}), &session).await.ok();
    assert_eq!(net.retry_notices(&space, 2 * HOUR).await, 1, "resumed");
    assert_eq!(types(&down), [json!(DELETED), json!(DELETED)]);
}

/// "drops a deletion notice once the space is recreated".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deletion_notice_goes_with_a_new_space() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let (space, again) = registered(&net, &alice, &bob, "again").await;
    again.respond(503, json!({}));
    delete(&alice, &space).await;
    again.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("the first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    net.create_space(&alice, SpaceOpts { skey: Some("again"), ..Default::default() }).await;
    again.respond(200, json!({}));
    assert_eq!(net.retry_notices(&space, 2 * HOUR).await, 1, "dropped for the new space");
    assert_eq!(again.calls_to(NOTIFY_SPACE_UPDATE).len(), 1, "the new space's syncer isn't told");
}

/// "drops a lapsed registration once its expiry notice stops being
/// retried" and "drops an expiry notice once the registration is renewed".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_notices_end_with_the_registration() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);

    let (space, down) = registered(&net, &alice, &bob, "unreachable").await;
    down.respond(503, json!({}));
    lapsed_and_told(&net, &alice, &space, &down).await;
    assert_eq!(net.pending_notices(&space).await[0]["notice"], json!("registrationExpired"));
    assert_eq!(net.retry_notices(&space, 73 * HOUR).await, 1, "given up");
    assert!(until(Duration::from_secs(10), async || net.registrations(&space).await.is_empty()).await, "unregistered");

    let (space, renews) = registered(&net, &alice, &bob, "renews").await;
    renews.respond(503, json!({}));
    lapsed_and_told(&net, &alice, &space, &renews).await;
    assert_eq!(net.pending_notices(&space).await.len(), 1);
    net.register(&bob, &space, renews.notify()).await.ok();
    renews.respond(200, json!({}));
    // due, but within the renewal's 10 min
    assert_eq!(net.retry_notices(&space, Duration::from_secs(120)).await, 1, "dropped");
    assert_eq!(types(&renews), [json!(EXPIRED)], "not sent again");
    assert_eq!(net.registrations(&space).await.len(), 1, "the renewal stays");
}

/// "lets a deletion notice supersede a pending expiry notice" (its other
/// half, an expiry notice never replacing a pending one, is
/// `space::notices::queue`'s, which nothing over XRPC reaches: an expiry
/// needs a live space).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deletion_notice_supersedes_a_pending_expiry_notice() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let (space, down) = registered(&net, &alice, &bob, "supersede").await;
    down.respond(503, json!({}));
    lapsed_and_told(&net, &alice, &space, &down).await;
    delete(&alice, &space).await;
    down.await_calls(NOTIFY_SPACE_UPDATE, 2, Duration::from_secs(10)).await.expect("the deletion's first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let pending = net.pending_notices(&space).await;
    assert_eq!(pending.len(), 1, "one per registration");
    assert_eq!(pending[0]["notice"], json!("spaceDeleted"));
    down.respond(200, json!({}));
    assert_eq!(net.retry_notices(&space, HOUR).await, 1);
    assert_eq!(types(&down), [json!(EXPIRED), json!(DELETED), json!(DELETED)]);
}

/// Rows the Nov 5 alpha stored, a registerNotify registration (`sN`) and a
/// notifySpaceDeleted retry (`sD`), name no token: the retry pass deletes
/// them, and nothing is sent to them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nov_5_rows_are_dropped() {
    use vlpds::state;
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let sid = state::space_id(&space);
    let p = net.pds[0].app.partitions.for_key(&alice.did).unwrap();
    let service = syncer.service_ref();
    let row = vlpds::space::rows::NotifyRow { endpoint: syncer.url.clone(), expires: u64::MAX };
    let deleted = json!({"uri": space, "endpoint": syncer.url, "expires": u64::MAX, "attempts": 1, "retryAt": 0});
    let keys =
        [state::space_notify_key(&alice.did, &sid, &service), state::space_deleted_key(&alice.did, &sid, &service)];
    p.db.put(keys[0].clone(), row.encode().to_vec()).await.unwrap();
    p.db.put(keys[1].clone(), serde_json::to_vec(&deleted).unwrap()).await.unwrap();
    write(&alice, &space, W::new()).await.ok();
    assert_eq!(net.retry_notices(&space, HOUR).await, 0);
    for k in keys {
        assert!(p.db.get(&k).await.unwrap().is_none());
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(syncer.calls().is_empty(), "{:?}", syncer.calls());
}
