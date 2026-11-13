//! Ported from the reference's `tests/space/policy.test.ts` (98ef3a6b; its
//! renames and new member, listSpaces and managing-app cases from d4def6e9f):
//! the `com.atproto.space` lifecycle methods and the baseline policies
//! (`personalspace`, `memberspace`, `managedspace`), with the records a
//! policy publishes. Each test names its reference case. The
//! client-attestation cases of "credential mint gates" live in
//! `ref_client_attestation` with the verifier's own cases.
//!
//! Adaptations: the reference's `writerDids` and storage reads become the
//! authority's `sW` rows and the owner's own reads, and a registration's
//! expiry (no endpoint expires one) goes through a test hook.

use super::ref_net::*;
use crate::common::spaces::{put_members, remove_members, SpaceClient};
use crate::common::*;
use std::time::Duration;

const POLICY: &str = "com.atproto.space.policy";
const MEMBER: &str = "com.atproto.memberspace.member";
const FORUM: &str = "did:web:example.com#forum";
const APP: &str = "https://app.example.com/client-metadata.json";

async fn get_space(owner: &SpaceClient, space: &str) -> Resp {
    owner.get("com.atproto.space.getSpace", &[("space", space)]).await
}

async fn update_space(owner: &SpaceClient, space: &str, policy: J) -> Resp {
    owner.post("com.atproto.space.updateSpace", json!({"space": space, "policy": policy})).await
}

async fn list_members(owner: &SpaceClient, space: &str) -> Resp {
    owner.get("com.atproto.memberspace.listMembers", &[("space", space)]).await
}

fn uris(listed: &J) -> Vec<String> {
    listed["spaces"].as_array().unwrap().iter().filter_map(|s| s["space"].as_str().map(String::from)).collect()
}

fn create_body(skey: &str) -> J {
    json!({"spaceType": TEST_SPACE_TYPE, "skey": skey, "policy": memberspace(json!({}))})
}

fn with_policy(policy: J) -> SpaceOpts<'static> {
    SpaceOpts { policy: Some(policy), ..Default::default() }
}

fn member_dids(listed: &J) -> Vec<String> {
    listed["members"].as_array().unwrap().iter().map(|m| m["did"].as_str().unwrap().to_string()).collect()
}

/// A memberspace as stored, every default filled in, with `config` over it.
fn stored_memberspace(config: J) -> J {
    let mut p = memberspace(
        json!({"publicRead": false, "publicWrite": false, "publishPolicy": false, "publishMembers": false}),
    );
    p.as_object_mut().unwrap().extend(config.as_object().unwrap().clone());
    p
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

/// lifecycle: "creates a space anchored on the caller own DID"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creates_a_space_anchored_on_the_caller() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    assert!(space.starts_with(&format!("at://{}/space/", alice.did)));
    let listed = alice.get("com.atproto.space.listSpaces", &[]).await.ok();
    assert!(uris(&listed).contains(&space), "{listed}");
}

/// lifecycle: "lists the state of the caller's repo in each space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lists_the_state_of_the_callers_repo() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let empty = net.create_space(&alice, SpaceOpts { skey: Some("list-state-empty"), ..Default::default() }).await;
    write(&alice, &space, W::new()).await.ok();
    write(&bob, &space, W::new()).await.ok();
    net.await_writer(&alice, &space, &bob.did).await;
    async fn view(actor: &SpaceClient, authority: &str, target: &str) -> Option<J> {
        let listed = actor.get("com.atproto.space.listSpaces", &[("spaceDid", authority)]).await.ok();
        listed["spaces"].as_array().unwrap().iter().find(|s| s["space"] == json!(target)).cloned()
    }
    let view_of = |actor, target| view(actor, &alice.did, target);
    for actor in [&alice, &bob] {
        let (rev, data) = repo_state(actor, &space).await.expect("a repo");
        let v = view_of(actor, &space).await.expect("listed");
        assert_eq!((&v["repoRev"], &v["data"]), (&json!(rev), &json_bytes(&data)), "{v}");
    }
    // only the authority sequences the space, so only it has a spaceRev
    let cred = net.credential_for(&alice, &space).await;
    let writers = cred.get(&net.pds[0].url, "com.atproto.space.listWriters", &[("space", &space)]).await.ok();
    assert_eq!(view_of(&alice, &space).await.unwrap()["spaceRev"], writers["cursor"]);
    assert!(view_of(&bob, &space).await.unwrap().get("spaceRev").is_none());
    // a space nothing was written to has no repo state to report
    assert_eq!(view_of(&alice, &empty).await, Some(json!({"space": empty})));
}

/// lifecycle: "refuses a duplicate space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_duplicate_space() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    alice.post("com.atproto.space.createSpace", create_body(last_segment(&space))).await.err(400, "SpaceAlreadyExists");
}

/// lifecycle: "refuses a space key that is not a valid record key"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_space_key_that_is_not_a_record_key() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let r = alice.post("com.atproto.space.createSpace", create_body("not a valid rkey")).await;
    refused_mentioning(&r, &["record key"]);
}

/// lifecycle: "filters spaces by spaceType"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filters_spaces_by_space_type() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let other = net.create_space(&alice, SpaceOpts { space_type: Some(OTHER_SPACE_TYPE), ..Default::default() }).await;
    let listed = uris(&alice.get("com.atproto.space.listSpaces", &[("spaceType", TEST_SPACE_TYPE)]).await.ok());
    assert!(listed.contains(&space) && !listed.contains(&other), "{listed:?}");
    let listed = uris(&alice.get("com.atproto.space.listSpaces", &[("spaceType", OTHER_SPACE_TYPE)]).await.ok());
    assert_eq!(listed, [other]);
}

/// lifecycle: "refuses an authority write until createSpace"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_owner_write_until_create_space() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/lazy", alice.did);
    write(&alice, &space, W::new().text("too early")).await.err(400, "SpaceNotFound");
    net.create_space(&alice, SpaceOpts { skey: Some("lazy"), ..Default::default() }).await;
    write(&alice, &space, W::new().text("lazy space")).await.ok();
    assert_eq!(all_records(&alice, &space).await.len(), 1);
}

// ---------------------------------------------------------------------------
// memberspace members
// ---------------------------------------------------------------------------

/// memberspace members: "adds and removes members, and the authority is
/// not one of them"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adds_and_removes_members() {
    let net = Net::new(1).await;
    let (alice, dan, bob) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    put_member(&alice, &space, &bob, true, false).await.ok();
    let members = list_members(&alice, &space).await.ok();
    let dids = member_dids(&members);
    assert!(!dids.contains(&alice.did), "the authority isn't on the member list");
    assert!(dids.contains(&dan.did) && dids.contains(&bob.did), "{members}");
    let b = members["members"].as_array().unwrap().iter().find(|m| m["did"] == json!(bob.did)).unwrap().clone();
    assert_eq!((&b["read"], &b["write"]), (&json!(true), &json!(false)));

    remove_member(&alice, &space, &bob).await.ok();
    assert!(!member_dids(&list_members(&alice, &space).await.ok()).contains(&bob.did));
}

/// memberspace members: "refuses membership changes from a member other
/// than the authority"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_membership_changes_from_a_non_owner() {
    let net = Net::new(2).await;
    let (alice, dan, carol) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    put_member(&dan, &space, &carol, true, true).await.err(400, "NotAuthorized");
    remove_member(&dan, &space, &dan).await.err(400, "NotAuthorized");
}

/// memberspace members: "refuses listMembers to a space credential and to
/// a member other than the authority"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_list_members_to_a_credential_and_a_non_owner() {
    let net = Net::new(2).await;
    let (alice, dan, carol) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol, &dan], ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    cred.get(&net.pds[0].url, "com.atproto.memberspace.listMembers", &[("space", &space)]).await.client_err();
    list_members(&dan, &space).await.err(400, "NotAuthorized");
}

/// memberspace members: "putMembers replaces both access values"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_member_replaces_both_access_values() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    put_member(&alice, &space, &bob, true, false).await.ok();
    put_member(&alice, &space, &bob, false, true).await.ok();
    let members = list_members(&alice, &space).await.ok();
    assert_eq!(members["members"], json!([{"did": bob.did, "read": false, "write": true}]));
}

/// memberspace members: "refuses member methods on a space under another
/// policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_member_methods_under_another_policy() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, with_policy(personalspace())).await;
    put_member(&alice, &space, &bob, true, true).await.err(400, "PolicyMismatch");
    remove_member(&alice, &space, &bob).await.err(400, "PolicyMismatch");
    list_members(&alice, &space).await.err(400, "PolicyMismatch");
}

/// memberspace members: "removeMembers drops the member from the writer set"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_member_drops_the_writer() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    write(&dan, &space, W::new().text("from a member")).await.ok();
    assert_eq!(net.await_writer(&alice, &space, &dan.did).await, vec![dan.did.clone()]);
    remove_member(&alice, &space, &dan).await.ok();
    assert!(net.writer_dids(&alice, &space).await.is_empty());
}

/// memberspace members: "putMembers drops the member from the writer set
/// when it revokes write"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_member_without_write_drops_the_writer() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    write(&dan, &space, W::new().text("from a member")).await.ok();
    net.await_writer(&alice, &space, &dan.did).await;
    put_member(&alice, &space, &dan, true, true).await.ok();
    assert_eq!(net.writer_dids(&alice, &space).await, vec![dan.did.clone()]);
    put_member(&alice, &space, &dan, true, false).await.ok();
    assert!(net.writer_dids(&alice, &space).await.is_empty());
}

/// memberspace members: "tells registered syncers of the writers a member
/// change removes"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn member_changes_tell_syncers_of_removed_writers() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let dan = net.actor("dan", 0).await;
    let syncer = MockService::syncer().await;
    // published members: each change is also the authority's write, sequenced
    // after the removal it makes
    let policy = Some(memberspace(json!({"publishMembers": true})));
    let space =
        net.create_space(&alice, SpaceOpts { members: &[&dan, &bob, &carol], policy, ..Default::default() }).await;
    net.register(&carol, &space, syncer.notify()).await.ok();
    for w in [&dan, &bob] {
        write(w, &space, W::new().text("from a member")).await.ok();
        net.await_writer(&alice, &space, &w.did).await;
    }
    put_member(&alice, &space, &dan, true, false).await.ok();
    remove_member(&alice, &space, &bob).await.ok();
    let removed = || {
        let mut r: Vec<String> = syncer
            .updates()
            .into_iter()
            .filter(|u| u["$type"] == json!("com.atproto.space.defs#repoRemoved"))
            .map(|u| u["repo"].as_str().unwrap().to_string())
            .collect();
        r.sort();
        r
    };
    let mut want = vec![dan.did.clone(), bob.did.clone()];
    want.sort();
    assert!(until(Duration::from_secs(10), async || removed() == want).await, "{:?}", removed());
}

/// memberspace members: "applies a batch of member changes in a single
/// commit"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn applies_a_batch_of_member_changes_in_one_commit() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, with_policy(memberspace(json!({"publishMembers": true})))).await;
    let member_ops = || async {
        let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
        let r = alice.get("com.atproto.space.listRepoOps", &q).await.ok();
        r["ops"].as_array().unwrap().iter().filter(|o| o["collection"] == json!(MEMBER)).cloned().collect::<Vec<_>>()
    };
    let members =
        json!([{"did": bob.did, "read": true, "write": true}, {"did": carol.did, "read": true, "write": false}]);
    alice.post("com.atproto.memberspace.putMembers", json!({"space": space, "members": members})).await.ok();
    let added = member_ops().await;
    assert_eq!(added.len(), 2, "{added:?}");
    assert_eq!(added[0]["rev"], added[1]["rev"]);
    alice
        .post("com.atproto.memberspace.removeMembers", json!({"space": space, "dids": [bob.did, carol.did]}))
        .await
        .ok();
    let removed: Vec<J> = member_ops().await.into_iter().filter(|o| o.get("cid").is_none_or(J::is_null)).collect();
    assert_eq!(removed.len(), 2, "{removed:?}");
    assert_eq!(removed[0]["rev"], removed[1]["rev"]);
    assert!(member_dids(&list_members(&alice, &space).await.ok()).is_empty());
    // at most 100 at once
    let many: Vec<J> = (0..101).map(|i| json!(format!("did:plc:{:0>24}", i))).collect();
    alice
        .post("com.atproto.memberspace.removeMembers", json!({"space": space, "dids": many}))
        .await
        .err(400, "InvalidRequest");
}

/// memberspace members: "takes the last entry for a member listed twice"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn takes_the_last_entry_for_a_member_listed_twice() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, with_policy(memberspace(json!({"publishMembers": true})))).await;
    let members =
        json!([{"did": bob.did, "read": true, "write": true}, {"did": bob.did, "read": true, "write": false}]);
    alice.post("com.atproto.memberspace.putMembers", json!({"space": space, "members": members})).await.ok();
    assert_eq!(
        list_members(&alice, &space).await.ok()["members"],
        json!([{"did": bob.did, "read": true, "write": false}])
    );
}

/// memberspace members: "ignores a DID that is not a member, leaving it in
/// the writer set"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_non_member_leaves_its_writer_state() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, with_policy(memberspace(json!({"publicWrite": true})))).await;
    write(&dan, &space, W::new().text("from a non-member")).await.ok();
    assert_eq!(net.await_writer(&alice, &space, &dan.did).await, vec![dan.did.clone()]);
    remove_member(&alice, &space, &dan).await.ok();
    assert_eq!(net.writer_dids(&alice, &space).await, vec![dan.did.clone()]);
}

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------

/// policy: "persists what createSpace was given"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persists_what_create_space_was_given() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, with_policy(managedspace(FORUM))).await;
    let got = get_space(&alice, &space).await.ok();
    assert_eq!(got["space"], json!(space));
    assert_eq!(got["policy"], json!({"$type": MANAGEDSPACE, "managingApp": FORUM, "publishPolicy": false}));
}

/// policy: "fills in the defaults of an omitted configuration"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fills_in_the_defaults() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, with_policy(memberspace(json!({})))).await;
    assert_eq!(get_space(&alice, &space).await.ok()["policy"], stored_memberspace(json!({})));
}

/// policy: "replaces the policy wholesale on update"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaces_the_policy_wholesale() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let first = memberspace(json!({"publicRead": true, "allowedApps": ["app:x"], "publishMembers": true}));
    let space = net.create_space(&alice, with_policy(first)).await;
    update_space(&alice, &space, memberspace(json!({"publicWrite": true}))).await.ok();
    assert_eq!(get_space(&alice, &space).await.ok()["policy"], stored_memberspace(json!({"publicWrite": true})));
}

/// policy: "keeps the member list across a configuration change"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_the_member_list_across_a_configuration_change() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    update_space(&alice, &space, memberspace(json!({"publicRead": true}))).await.ok();
    assert_eq!(member_dids(&list_members(&alice, &space).await.ok()), vec![bob.did.clone()]);
}

/// policy: "refuses an update from an account other than the authority" (bob's token, presented to
/// the authority's PDS and to his own)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_update_from_a_non_owner() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let body = json!({"space": space, "policy": memberspace(json!({"publicRead": true}))});
    post_at(&bob, &net.pds[0].url, "com.atproto.space.updateSpace", body.clone()).await.client_err();
    bob.post("com.atproto.space.updateSpace", body).await.client_err();
    assert_eq!(get_space(&alice, &space).await.ok()["policy"], stored_memberspace(json!({})));
}

/// policy: "refuses an unrecognized policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_unrecognized_policy() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    update_space(&alice, &space, json!({"$type": "com.example.whatever"})).await.err(400, "UnsupportedPolicy");
}

/// policy: "refuses a managingApp that does not name a service (%s)"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_managing_app_that_does_not_name_a_service() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    for app in ["not-a-did-at-all", "did:web:example.com"] {
        let r = update_space(&alice, &space, managedspace(app)).await;
        refused_mentioning(&r, &["must be a did#serviceId reference"]);
    }
}

/// policy: "refuses the policy to a member with a space credential"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_the_policy_to_a_member_credential() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    cred.get(&net.pds[0].url, "com.atproto.space.getSpace", &[("space", &space)]).await.client_err();
}

/// policy: "refuses the policy to another account on an account credential"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_the_policy_to_another_account() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    get_space(&dan, &space).await.err(400, "NotAuthorized");
}

/// policy: "refuses to answer for a space this host does not govern"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_to_answer_for_a_space_this_host_does_not_govern() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let cred = net.credential_for(&bob, &space).await;
    cred.get(&net.pds[1].url, "com.atproto.space.listWriters", &[("space", &space)]).await.err(400, "SpaceNotFound");
    get_space(&bob, &space).await.client_err();
}

// ---------------------------------------------------------------------------
// policy migration
// ---------------------------------------------------------------------------

/// policy migration: "discards the member list, and migrating back does
/// not restore it"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_discards_the_member_list() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    update_space(&alice, &space, personalspace()).await.ok();
    update_space(&alice, &space, memberspace(json!({}))).await.ok();
    assert_eq!(list_members(&alice, &space).await.ok()["members"], json!([]));
    let token = delegation_token(&bob, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

// ---------------------------------------------------------------------------
// publishing to readers
// ---------------------------------------------------------------------------

async fn published(owner: &SpaceClient, space: &str, collection: &str) -> Vec<J> {
    let q = [("space", space), ("repo", owner.did.as_str()), ("collection", collection)];
    owner.get("com.atproto.space.listRecords", &q).await.ok()["records"].as_array().unwrap().clone()
}

/// (rkey, value) of each published member record, by rkey.
async fn published_members(owner: &SpaceClient, space: &str) -> Vec<(String, J)> {
    let mut out: Vec<(String, J)> = published(owner, space, MEMBER)
        .await
        .into_iter()
        .map(|r| (r["rkey"].as_str().unwrap().to_string(), r["value"].clone()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// publishing to readers: "publishes the policy to readers"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_the_policy_to_readers() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let opts = SpaceOpts {
        members: &[&carol],
        policy: Some(memberspace(json!({"publishPolicy": true}))),
        ..Default::default()
    };
    let space = net.create_space(&alice, opts).await;
    let policy = get_space(&alice, &space).await.ok()["policy"].clone();
    let cred = net.credential_for(&carol, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str()), ("collection", POLICY)];
    let res = cred.get(&net.pds[0].url, "com.atproto.space.listRecords", &q).await.ok();
    let records = res["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{res}");
    assert_eq!(records[0]["rkey"], json!("self"), "{res}");
    assert_eq!(records[0]["value"], json!({"$type": POLICY, "policy": policy}));
}

/// publishing to readers: "keeps the published policy in sync, and
/// withdraws it when unpublished"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_the_published_policy_in_sync() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let managed = json!({"$type": MANAGEDSPACE, "managingApp": FORUM, "publishPolicy": true});
    let space = net.create_space(&alice, with_policy(managed)).await;
    update_space(&alice, &space, memberspace(json!({"publicRead": true, "publishPolicy": true}))).await.ok();
    let records = published(&alice, &space, POLICY).await;
    let policy = get_space(&alice, &space).await.ok()["policy"].clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["value"], json!({"$type": POLICY, "policy": policy}));
    update_space(&alice, &space, memberspace(json!({}))).await.ok();
    assert!(published(&alice, &space, POLICY).await.is_empty());
    expect_set_hash_matches_store(&alice, &space).await;
}

/// publishing to readers: "publishes the member list, keyed by member DID"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_the_member_list() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, with_policy(memberspace(json!({"publishMembers": true})))).await;
    put_member(&alice, &space, &bob, true, true).await.ok();
    put_member(&alice, &space, &carol, true, true).await.ok();
    put_member(&alice, &space, &carol, true, false).await.ok();
    remove_member(&alice, &space, &bob).await.ok();
    assert_eq!(
        published_members(&alice, &space).await,
        [(carol.did.clone(), json!({"$type": MEMBER, "read": true, "write": false}))]
    );
    expect_set_hash_matches_store(&alice, &space).await;
}

/// publishing to readers: "leaves the port of a localhost did:web
/// unencoded in its record key"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaves_a_did_web_port_unencoded_in_its_record_key() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, with_policy(memberspace(json!({"publishMembers": true})))).await;
    let did = "did:web:localhost%3A2583";
    let member = json!({"space": space, "did": did, "read": true, "write": true});
    alice.post("com.atproto.memberspace.putMembers", put_members(member)).await.ok();
    let got = published_members(&alice, &space).await;
    assert_eq!(got.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["did:web:localhost:2583"]);
    alice.post("com.atproto.memberspace.removeMembers", remove_members(json!({"space": space, "did": did}))).await.ok();
    assert!(published_members(&alice, &space).await.is_empty());
}

/// publishing to readers: "publishes or withdraws the whole member list
/// when publishMembers changes"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_or_withdraws_the_whole_member_list() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    assert!(published_members(&alice, &space).await.is_empty());
    update_space(&alice, &space, memberspace(json!({"publishMembers": true}))).await.ok();
    let mut want = vec![bob.did.clone(), carol.did.clone()];
    want.sort();
    let got: Vec<String> = published_members(&alice, &space).await.into_iter().map(|(k, _)| k).collect();
    assert_eq!(got, want);
    update_space(&alice, &space, memberspace(json!({}))).await.ok();
    assert!(published_members(&alice, &space).await.is_empty());
    expect_set_hash_matches_store(&alice, &space).await;
}

/// publishing to readers: "withdraws the published member list on
/// migration"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withdraws_the_published_member_list_on_migration() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let opts = SpaceOpts {
        members: &[&bob],
        policy: Some(memberspace(json!({"publishMembers": true}))),
        ..Default::default()
    };
    let space = net.create_space(&alice, opts).await;
    assert_eq!(published_members(&alice, &space).await.len(), 1);
    update_space(&alice, &space, personalspace()).await.ok();
    assert!(published_members(&alice, &space).await.is_empty());
}

/// publishing to readers: "keeps the published records when the authority
/// clears its repo"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_the_published_records_when_the_authority_clears() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let policy = memberspace(json!({"publishPolicy": true, "publishMembers": true}));
    let space =
        net.create_space(&alice, SpaceOpts { members: &[&bob], policy: Some(policy), ..Default::default() }).await;
    write(&alice, &space, W::new().rkey("own")).await.ok();
    clear(&alice, &space).await.ok();
    let mut colls: Vec<String> =
        all_records(&alice, &space).await.iter().map(|r| r["collection"].as_str().unwrap().to_string()).collect();
    colls.sort();
    assert_eq!(colls, [MEMBER, POLICY]);
    expect_set_hash_matches_store(&alice, &space).await;
    // with only the published records left, there is nothing more to clear
    let cleared = repo_state(&alice, &space).await;
    clear(&alice, &space).await.ok();
    assert_eq!(repo_state(&alice, &space).await, cleared);
}

/// publishing to readers: "notifies the space of what it publishes"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notifies_the_space_of_what_it_publishes() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, with_policy(memberspace(json!({"publishPolicy": true})))).await;
    assert_eq!(net.await_writer(&alice, &space, &alice.did).await, vec![alice.did.clone()]);
}

/// publishing to readers: "refuses direct writes of published records"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_direct_writes_of_published_records() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let opts =
        SpaceOpts { members: &[&bob], policy: Some(memberspace(json!({"publishPolicy": true}))), ..Default::default() };
    let space = net.create_space(&alice, opts).await;
    let record = json!({"$type": POLICY, "policy": {"$type": PERSONALSPACE}});
    let refused = ["cannot be written directly"];
    // in any repo, not only the authority's
    let r = put(&alice, &space, W::new().collection(POLICY).rkey("self").record(record.clone())).await;
    assert_eq!(r.status, 400, "{r:?}");
    refused_mentioning(&r, &refused);
    let member = json!({"$type": MEMBER, "read": true, "write": true});
    let r = write(&bob, &space, W::new().collection(MEMBER).rkey(&carol.did).record(member)).await;
    refused_mentioning(&r, &refused);
    let op =
        json!({"$type": "com.atproto.space.applyWrites#create", "collection": POLICY, "rkey": "self", "value": record});
    let r = bob.post("com.atproto.space.applyWrites", json!({"space": space, "repo": bob.did, "writes": [op]})).await;
    refused_mentioning(&r, &refused);
    // turning validation off doesn't open a way around it
    let r = put(&alice, &space, W::new().collection(POLICY).rkey("self").record(record).validate(false)).await;
    refused_mentioning(&r, &refused);
    // nor can the published policy be withdrawn other than by the policy
    refused_mentioning(&del(&alice, &space, Some(POLICY), "self").await, &refused);
    assert_eq!(published(&alice, &space, POLICY).await.len(), 1);
}

// ---------------------------------------------------------------------------
// personalspace policy
// ---------------------------------------------------------------------------

/// personalspace policy: "authorizes only the authority to read"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn personalspace_authorizes_only_the_authority() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, with_policy(personalspace())).await;
    assert!(!net.credential_for(&alice, &space).await.credential.is_empty());
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// personalspace policy: "tracks no writer but the authority"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn personalspace_tracks_no_writer_but_the_authority() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, with_policy(personalspace())).await;
    write(&alice, &space, W::new().text("my bookmark")).await.ok();
    write(&bob, &space, W::new().text("not tracked")).await.ok();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(net.writer_dids(&alice, &space).await, vec![alice.did.clone()]);
}

// ---------------------------------------------------------------------------
// credential mint gates
// ---------------------------------------------------------------------------

/// credential mint gates: "mints for a non-member when read access is
/// public"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mints_for_a_non_member_when_read_is_public() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, with_policy(memberspace(json!({"publicRead": true})))).await;
    assert!(!net.credential_for(&carol, &space).await.credential.is_empty());
}

/// credential mint gates: "mints without a delegation token when read
/// access is public"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mints_without_a_delegation_token_when_read_is_public() {
    let net = Net::new(1).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, with_policy(memberspace(json!({"publicRead": true})))).await;
    write(&alice, &space, W::new().text("for anyone")).await.ok();
    let (r, holder) = net.public_credential(&space, None).await;
    let credential = r.ok()["credential"].as_str().unwrap().to_string();
    let cred = Cred { credential, holder, http: alice.srv.http.clone() };
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let res = cred.get(&net.pds[0].url, "com.atproto.space.listRecords", &q).await.ok();
    assert_eq!(res["records"].as_array().unwrap().len(), 1, "{res}");
}

/// credential mint gates: "hides a $name space from a request without a
/// delegation token" (memberspace, personalspace; since the Nov 12 alpha a
/// managed space asks its app instead: `managing_app_is_asked_without_a_delegation_token`)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_a_space_from_a_request_without_a_delegation_token() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    for policy in [memberspace(json!({})), personalspace()] {
        let space = net.create_space(&alice, with_policy(policy.clone())).await;
        let r = net.public_credential(&space, None).await.0;
        assert_eq!(r.error_name(), Some("SpaceNotFound"), "{policy}: {r:?}");
    }
}

/// credential mint gates: "hides a space from a request without a
/// delegation token before checking the app"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_a_space_without_a_token_before_checking_the_app() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, with_policy(memberspace(json!({"allowedApps": [APP]})))).await;
    net.public_credential(&space, None).await.0.err(400, "SpaceNotFound");
}

/// credential mint gates: "refuses a request without a delegation token or
/// attestation when apps are restricted"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_tokenless_request_without_an_attestation_when_apps_are_restricted() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space =
        net.create_space(&alice, with_policy(memberspace(json!({"publicRead": true, "allowedApps": [APP]})))).await;
    net.public_credential(&space, None).await.0.err(400, "AppNotAuthorized");
}

/// credential mint gates: "hides the space from a non-member when read
/// access is not public"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_the_space_from_a_non_member() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// credential mint gates: "hides the space from a non-member before
/// checking the app"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_the_space_from_a_non_member_before_checking_the_app() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, with_policy(memberspace(json!({"allowedApps": [APP]})))).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// credential mint gates: "hides the space from a member without read
/// access"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_the_space_from_a_member_without_read_access() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    put_member(&alice, &space, &carol, false, true).await.ok();
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// credential mint gates: "always admits the authority, whatever the
/// policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn always_admits_the_authority() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, with_policy(managedspace("did:web:unreachable.invalid#forum"))).await;
    assert!(!net.credential_for(&alice, &space).await.credential.is_empty());
}

/// credential mint gates: "refuses when apps are restricted and no
/// attestation is presented"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_restricted_apps_without_an_attestation() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space =
        net.create_space(&alice, with_policy(memberspace(json!({"publicRead": true, "allowedApps": [APP]})))).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "AppNotAuthorized");
}

// ---------------------------------------------------------------------------
// managedspace policy
// ---------------------------------------------------------------------------

const CHECK_ACCESS: &str = "com.atproto.managedspace.checkAccess";

async fn forum(authorized: Option<bool>) -> MockService {
    match authorized {
        Some(a) => forum_answering(a, a).await,
        None => {
            let app = MockService::spawn(&[("atproto_forum", "AtprotoForum")]).await;
            app.respond(500, json!({"error": "InternalError"}));
            app
        }
    }
}

/// checkAccess answers read and write together.
async fn forum_answering(read: bool, write: bool) -> MockService {
    let app = MockService::spawn(&[("atproto_forum", "AtprotoForum")]).await;
    app.respond(200, json!({"read": read, "write": write}));
    app
}

/// managedspace policy: "admits a user the managing app authorizes"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_admits_a_user_it_authorizes() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(Some(true)).await;
    let space = net.create_space(&alice, with_policy(managedspace(&app.service_ref()))).await;
    assert!(!net.credential_for(&carol, &space).await.credential.is_empty());
    let asked = app.calls_to(CHECK_ACCESS);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].body, json!({"space": space, "repo": carol.did}));
    // service auth from the authority, so the app can tell who asks
    let auth = asked[0].auth.as_deref().unwrap_or("");
    assert!(auth.starts_with("Bearer "), "{auth}");
    let claims = jwt_claims(auth.trim_start_matches("Bearer "));
    assert_eq!((&claims["iss"], &claims["lxm"]), (&json!(alice.did), &json!(CHECK_ACCESS)));
}

/// managedspace policy: "asks the managing app about a request with no
/// delegation token"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_is_asked_without_a_delegation_token() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let app = forum(Some(true)).await;
    let space = net.create_space(&alice, with_policy(managedspace(&app.service_ref()))).await;
    net.public_credential(&space, None).await.0.ok();
    assert_eq!(app.calls_to(CHECK_ACCESS)[0].body, json!({"space": space}));
    app.respond(200, json!({"read": false, "write": false}));
    net.public_credential(&space, None).await.0.err(400, "SpaceNotFound");
}

/// managedspace policy: "refuses a user the managing app declines"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_refuses_a_user_it_declines() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(Some(false)).await;
    let space = net.create_space(&alice, with_policy(managedspace(&app.service_ref()))).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// managedspace policy: "fails without a credential when the managing app
/// errors"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_outage_fails_without_a_credential() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(None).await;
    let space = net.create_space(&alice, with_policy(managedspace(&app.service_ref()))).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(502, "UpstreamFailure");
}

/// managedspace policy: "fails without a credential when the managing app
/// cannot be resolved"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_unresolvable_fails_without_a_credential() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, with_policy(managedspace("did:web:nonexistent.invalid#forum"))).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(502, "UpstreamFailure");
}

/// managedspace policy: "keeps a registration through a managing app
/// outage, and withdraws it on refusal"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_managing_app_outage_keeps_the_registration() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(Some(true)).await;
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, with_policy(managedspace(&app.service_ref()))).await;
    net.register(&carol, &space, syncer.notify()).await.ok();
    assert_eq!(net.registrations(&space).await.len(), 1);
    app.respond(500, json!({"error": "InternalError"}));
    net.register(&carol, &space, syncer.notify()).await.err(502, "UpstreamFailure");
    assert_eq!(net.registrations(&space).await.len(), 1);
    app.respond(200, json!({"read": false, "write": false}));
    net.register(&carol, &space, syncer.notify()).await.err(400, "SpaceNotFound");
    assert!(net.registrations(&space).await.is_empty());
}

/// managedspace policy: "records a writer the managing app admits, even one
/// it does not let read"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_admits_a_writer_it_does_not_let_read() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let app = forum_answering(false, true).await;
    let space = net.create_space(&alice, with_policy(managedspace(&app.service_ref()))).await;
    write(&bob, &space, W::new().text("admitted by the managing app")).await.ok();
    let dids = net.await_writer(&alice, &space, &bob.did).await;
    assert!(dids.contains(&bob.did), "{dids:?}");
    // a write notify names no app
    assert_eq!(app.calls_to(CHECK_ACCESS)[0].body, json!({"space": space, "repo": bob.did}));
    let token = delegation_token(&bob, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// managedspace policy: "retries a write notification through a managing
/// app outage"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_outage_retries_a_write_notification() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    for p in &net.pds {
        p.app.spaces.as_ref().unwrap().outbox.set_retry_base(Duration::from_millis(200));
    }
    let app = forum(None).await;
    let space = net.create_space(&alice, with_policy(managedspace(&app.service_ref()))).await;
    write(&bob, &space, W::new().text("held through the outage")).await.ok();
    app.await_calls(CHECK_ACCESS, 1, Duration::from_secs(10)).await.expect("asked");
    assert!(net.writer_dids(&alice, &space).await.is_empty());
    app.respond(200, json!({"read": true, "write": true}));
    assert!(net.await_writer(&alice, &space, &bob.did).await.contains(&bob.did));
}

// ---------------------------------------------------------------------------
// notify registration
// ---------------------------------------------------------------------------

const REPO_WRITE: &str = "com.atproto.space.defs#repoWrite";
const REGISTRATION_EXPIRED: &str = "com.atproto.space.notifySpaceUpdate#registrationExpired";
const SPACE_DELETED: &str = "com.atproto.space.notifySpaceUpdate#spaceDeleted";

/// `writeAndForward`: bob writes, and the update reaches `n` calls to the
/// syncer (the reference drains its background queue instead).
async fn write_and_forward(bob: &SpaceClient, space: &str, syncer: &MockService, n: usize) -> Vec<J> {
    write(bob, space, W::new()).await.ok();
    syncer.await_calls(NOTIFY_SPACE_UPDATE, n, Duration::from_secs(10)).await.expect("forwarded");
    syncer.updates()
}

/// A write that's sequenced (in the writer set) and then some time to show
/// that nothing more arrives.
async fn write_and_settle(net: &Net, alice: &SpaceClient, bob: &SpaceClient, space: &str) {
    let before = repo_state(bob, space).await;
    write(bob, space, W::new()).await.ok();
    let rev = repo_state(bob, space).await;
    assert_ne!(before, rev);
    net.await_writer(alice, space, &bob.did).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// notify registration: "confirms a new registration, and forwards writes
/// with its token"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirms_a_new_registration_and_forwards_with_its_token() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    net.register(&carol, &space, syncer.notify_with("first-token")).await.ok();
    let confirmations = syncer.calls_to(CONFIRM_REGISTRATION);
    assert_eq!(confirmations.len(), 1);
    assert_eq!(
        (&confirmations[0].body["space"], &confirmations[0].body["token"]),
        (&json!(space), &json!("first-token"))
    );
    assert!(confirmations[0].auth.is_none(), "the token is the registration's credential");

    write_and_forward(&bob, &space, &syncer, 1).await;
    let delivered = syncer.calls_to(NOTIFY_SPACE_UPDATE);
    assert_eq!(delivered.len(), 1);
    let body = &delivered[0].body;
    assert_eq!((&body["space"], &body["token"]), (&json!(space), &json!("first-token")));
    assert_eq!((&body["update"]["$type"], &body["update"]["repo"]), (&json!(REPO_WRITE), &json!(bob.did)));
    assert!(delivered[0].auth.is_none());

    // renewing with the same token keeps one registration, unconfirmed
    net.register(&carol, &space, syncer.notify_with("first-token")).await.ok();
    assert_eq!(net.registrations(&space).await.len(), 1);
    assert_eq!(syncer.calls_to(CONFIRM_REGISTRATION).len(), 1);
}

/// notify registration: "treats a different token as a separate
/// registration"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_token_is_a_separate_registration() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    for token in ["first-token", "second-token"] {
        net.register(&carol, &space, syncer.notify_with(token)).await.ok();
    }
    write_and_forward(&bob, &space, &syncer, 2).await;
    let mut tokens: Vec<J> =
        syncer.calls_to(NOTIFY_SPACE_UPDATE).into_iter().map(|c| c.body["token"].clone()).collect();
    tokens.sort_by_key(|t| t.to_string());
    assert_eq!(tokens, [json!("first-token"), json!("second-token")]);
}

/// notify registration: "refuses an authorization whose registration is
/// not confirmed"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_unconfirmed_registration() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    syncer.confirm_registrations(false);
    syncer.respond(200, json!({"challenge": "not-the-one"}));
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    net.register(&carol, &space, syncer.notify()).await.err(400, "RegistrationNotConfirmed");
    assert!(net.registrations(&space).await.is_empty());
    // nor one that can't be reached
    let gone = json!({"endpoint": "http://127.0.0.1:1", "token": "t"});
    net.register(&carol, &space, gone).await.err(400, "RegistrationNotConfirmed");
    assert!(net.registrations(&space).await.is_empty());
}

/// notify registration: "sends a lapsed registration an expiry notice in
/// place of the next update, then nothing more"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lapsed_registration_gets_an_expiry_notice_then_nothing() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    net.register(&carol, &space, syncer.notify()).await.ok();
    // however long ago it lapsed
    net.lapse(&space, &syncer, &syncer.token, Duration::from_secs(86_400 + 60)).await;

    let updates = write_and_forward(&bob, &space, &syncer, 1).await;
    let cred = net.credential_for(&alice, &space).await;
    let listed = cred.get(&net.pds[0].url, "com.atproto.space.listWriters", &[("space", &space)]).await.ok();
    assert_eq!(updates, [json!({"$type": REGISTRATION_EXPIRED, "spaceRev": listed["cursor"]})]);

    // kept, for a deletion notice, but sent no updates
    write_and_settle(&net, &alice, &bob, &space).await;
    assert_eq!(syncer.updates().len(), 1);
    assert_eq!(net.registrations(&space).await.len(), 1);

    // reauthorizing renews it
    net.register(&carol, &space, syncer.notify()).await.ok();
    let updates = write_and_forward(&bob, &space, &syncer, 2).await;
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[1]["$type"], json!(REPO_WRITE));
}

/// notify registration: "unregisters a syncer that rejects its expiry
/// notice"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejecting_the_expiry_notice_unregisters() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    syncer.respond(400, json!({"error": "InvalidToken"}));
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    net.register(&carol, &space, syncer.notify()).await.ok();
    net.lapse(&space, &syncer, &syncer.token, Duration::from_secs(1)).await;

    assert_eq!(write_and_forward(&bob, &space, &syncer, 1).await.len(), 1);
    assert!(until(Duration::from_secs(10), async || net.registrations(&space).await.is_empty()).await);
    // registering again is a new registration, confirmed again
    net.register(&carol, &space, syncer.notify()).await.ok();
    assert_eq!(syncer.calls_to(CONFIRM_REGISTRATION).len(), 2);
}

/// notify registration: "retries an expiry notice through a transient
/// failure"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expiry_notice_is_retried_through_a_transient_failure() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    syncer.respond(503, json!({}));
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    net.register(&carol, &space, syncer.notify()).await.ok();
    net.lapse(&space, &syncer, &syncer.token, Duration::from_secs(1)).await;

    write_and_forward(&bob, &space, &syncer, 1).await;
    assert!(until(Duration::from_secs(10), async || net.pending_notices(&space).await.len() == 1).await);
    syncer.respond(200, json!({}));
    assert_eq!(net.retry_notices(&space, Duration::from_secs(3600)).await, 1);
    assert!(net.pending_notices(&space).await.is_empty());
    let types: Vec<J> = syncer.updates().into_iter().map(|u| u["$type"].clone()).collect();
    assert_eq!(types, [json!(REGISTRATION_EXPIRED), json!(REGISTRATION_EXPIRED)]);
    assert_eq!(net.registrations(&space).await.len(), 1);
}

/// notify registration: "keeps an active registration through a rejected
/// update". Updates are best effort; a syncer unregisters only by
/// rejecting its expiry notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_update_keeps_the_registration() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    syncer.respond(401, json!({"error": "InvalidToken"}));
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    net.register(&carol, &space, syncer.notify()).await.ok();
    write_and_forward(&bob, &space, &syncer, 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(net.registrations(&space).await.len(), 1);
    syncer.respond(200, json!({}));
    assert_eq!(write_and_forward(&bob, &space, &syncer, 2).await.len(), 2);
}

/// notify registration: "withdraws the registration carried by a refused
/// authorization"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_authorization_withdraws_its_registration() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    net.register(&carol, &space, syncer.notify_with("syncer-token")).await.ok();
    remove_member(&alice, &space, &carol).await.ok();
    // another token names another registration: the endpoint alone
    // withdraws nothing
    net.register(&carol, &space, syncer.notify_with("guessed-token")).await.err(400, "SpaceNotFound");
    assert_eq!(net.registrations(&space).await.len(), 1);
    net.register(&carol, &space, syncer.notify_with("syncer-token")).await.err(400, "SpaceNotFound");
    assert!(net.registrations(&space).await.is_empty());
    write_and_settle(&net, &alice, &bob, &space).await;
    assert!(syncer.updates().is_empty());
}

/// notify registration: "delivers to each registration without waiting on
/// a slow one". vlpds sends each registration its own lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_registration_holds_up_no_other() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let (slow, fast) = (MockService::syncer().await, MockService::syncer().await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    for s in [&slow, &fast] {
        net.register(&carol, &space, s.notify()).await.ok();
    }
    let held = slow.gate.lock().await;
    write(&bob, &space, W::new()).await.ok();
    fast.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(2)).await.expect("not held up by the slow one");
    drop(held);
    slow.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("the slow one too");
}

// ---------------------------------------------------------------------------
// deletion
// ---------------------------------------------------------------------------

async fn delete_space(owner: &SpaceClient, space: &str) -> Resp {
    owner.post("com.atproto.space.deleteSpace", json!({"space": space})).await
}

/// deletion: "purges the authority own repo and keeps a tombstone" (the
/// blob is gone once space.getBlob no longer serves it)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_purges_the_authority_repo_and_keeps_a_tombstone() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let blob = upload_blob(&alice, b"space blob for deletion").await;
    let cid = blob_cid(&blob);
    let rec = json!({"$type": TEST_COLLECTION, "text": "owner record", "image": blob});
    write(&alice, &space, W::new().rkey("doomed").record(rec)).await.ok();
    let cred = net.credential_for(&alice, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str()), ("cid", cid.as_str())];
    assert_eq!(cred.get(&net.pds[0].url, "com.atproto.space.getBlob", &q).await.status, 200);

    delete_space(&alice, &space).await.ok();
    get_space(&alice, &space).await.err(400, "SpaceNotFound");
    assert!(all_records(&alice, &space).await.is_empty(), "the authority's own records are gone");
    assert_eq!(repo_state(&alice, &space).await, None);
    list_members(&alice, &space).await.client_err();
    alice.get("com.atproto.space.getBlob", &q).await.client_err();
    // the tombstone keeps answering SpaceDeleted
    let token = delegation_token(&bob, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceDeleted");
    delete_space(&alice, &space).await.ok();
}

/// deletion: "answers SpaceDeleted on reauthorization"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_space_deleted_on_credential_renewal() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let token = delegation_token(&carol, &space).await;
    delete_space(&alice, &space).await.ok();
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceDeleted");
}

/// deletion: "answers SpaceDeleted regardless of the request authorization"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_space_deleted_regardless_of_the_authorization() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    delete_space(&alice, &space).await.ok();
    net.mint_credential(&space, "not-a-delegation-token", None).await.0.err(400, "SpaceDeleted");
}

/// deletion: "answers SpaceDeleted to a request without a delegation token"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_space_deleted_without_a_delegation_token() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, with_policy(memberspace(json!({"publicRead": true})))).await;
    delete_space(&alice, &space).await.ok();
    net.public_credential(&space, None).await.0.err(400, "SpaceDeleted");
}

/// deletion: "notifies registered syncers, including lapsed registrations"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_notifies_registered_syncers() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let (syncer, lapsed) = (MockService::syncer().await, MockService::syncer().await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    for s in [&syncer, &lapsed] {
        net.register(&carol, &space, s.notify()).await.ok();
    }
    net.lapse(&space, &lapsed, &lapsed.token, Duration::from_secs(1)).await;
    // a lapsed registration that had its expiry notice still hears of the
    // deletion
    write(&alice, &space, W::new()).await.ok();
    lapsed.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("the expiry notice");
    syncer.await_calls(NOTIFY_SPACE_UPDATE, 1, Duration::from_secs(10)).await.expect("the write");

    delete_space(&alice, &space).await.ok();
    for s in [&syncer, &lapsed] {
        let got = s.await_calls(NOTIFY_SPACE_UPDATE, 2, Duration::from_secs(10)).await.expect("spaceDeleted");
        let want = json!({"space": space, "token": s.token, "update": {"$type": SPACE_DELETED}});
        assert_eq!(got.last().unwrap().body, want);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let types: Vec<J> = lapsed.updates().into_iter().map(|u| u["$type"].clone()).collect();
    assert_eq!(types, [json!(REGISTRATION_EXPIRED), json!(SPACE_DELETED)]);
    assert_eq!(syncer.updates().len(), 2);
    // a registration can't outlive its space (`space::repo::register`
    // refuses a tombstone: "refuses a registration made as the space is
    // deleted")
    net.register(&carol, &space, syncer.notify()).await.err(400, "SpaceDeleted");
}

/// deletion: "leaves a member repo untouched"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_leaves_a_member_repo_untouched() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    write(&bob, &space, W::new().text("member write")).await.ok();
    delete_space(&alice, &space).await.ok();
    assert_eq!(all_records(&bob, &space).await.len(), 1);
    let listed = bob.get("com.atproto.space.listSpaces", &[]).await.ok();
    assert!(uris(&listed).contains(&space), "{listed}");
}

/// deletion: "allows re-creating a deleted space, with a fresh policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allows_re_creating_a_deleted_space_with_a_fresh_policy() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let opts = |p: bool| SpaceOpts {
        skey: Some("recreate"),
        policy: p.then(|| memberspace(json!({"publicRead": true, "publicWrite": true}))),
        ..Default::default()
    };
    let space = net.create_space(&alice, opts(true)).await;
    delete_space(&alice, &space).await.ok();
    assert_eq!(net.create_space(&alice, opts(false)).await, space);
    let got = get_space(&alice, &space).await.ok();
    assert_eq!((&got["policy"]["publicRead"], &got["policy"]["publicWrite"]), (&json!(false), &json!(false)));
    write(&alice, &space, W::new().text("after recreation")).await.ok();
}
