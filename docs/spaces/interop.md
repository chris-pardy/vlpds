---
title: Interop and divergences
section: Spaces
order: 206
status: draft
summary: "Which upstream vlpds tracks, how each upstream change maps onto vlpds, where it deliberately differs from the reference PDS, and the gaps in the spec it works around."
---

```hero
diagram:
  caption: "vlpds speaks the reference's wire in every role, and the interop harness runs it both ways: ref-ref, vlpds-authority, ref-authority and vlpds-only, plus a three-node vlpds cluster on MinIO."
  nodes:
    - { id: v, label: vlpds, sub: "repo host · space host", at: [0, 3], size: [12, 3], tone: accent }
    - { id: r, label: Reference PDS, sub: "atproto `d4def6e9`", at: [26, 3], size: [12, 3], tone: muted }
    - { id: s, label: Syncer, sub: "`@atproto/space` consumer", at: [13, 10], size: [12, 3], tone: blue }
  edges:
    - "v <-> r: notifyRepoUpdate · credential reads"
    - { from: s.t25, to: v.b, label: "listRepoOps · MAC", tone: blue }
    - { from: s.t75, to: r.b, label: "listRepoOps · MAC", tone: blue }
facts:
  - { value: "d4def6e9", label: reference pin, note: "bluesky-social/atproto, the Nov 12 alpha" }
  - { value: MAC, label: per response, note: "RFC 9421 hmac-sha256, HPKE secret export to the author's #atproto_kem key; no commit signatures", tone: accent }
  - { value: STAR, label: getRepo and importRepo, note: "one pass, bytewise path order, control bytes", tone: violet }
  - { value: OAuth, label: only, note: "the biggest divergence", tone: rust }
```

vlpds tracks the reference implementation, since the proposal leaves a lot of the wire to it.
Where the spec is silent, vlpds matches the reference's behaviour. Where vlpds differs, it's on
purpose, and `tests/REFERENCE_COVERAGE.md` lists each case.

## The pin

The pin is bluesky-social/atproto `d4def6e9f`, the Nov 12 alpha
(`0.0.0-spaces-alpha-20261112204144` on npm). The published `permissioned-data-alpha` branch is
`b27a037c7`, the same commit merged with main. The lexicons are vendored unmodified in
`lexicons/spaces-alpha` and the test vectors in `testdata/spaces-alpha`, both regenerated from the
pin by running the reference. The interop harness builds the reference image from the pin's own
root `Dockerfile` (target `pds`).

The previous pin was `98ef3a6b`, the Nov 5 alpha. The table below has a row for each change of
both.

## What the alpha changed, and where it lands

| Upstream | vlpds | Breaking | Stored data |
|---|---|---|---|
| Nov 5: the credential request takes `space`, a key for the credential, and an optional `delegationToken` and `clientAttestation` in its body; a bad token is `InvalidDelegationToken` (proposals #120) | `xrpc/space.rs`, `xrpc/authn.rs` | yes | none |
| Nov 5: `Atproto-Space-Credential` scheme and a `tag="atproto-space-credential"` signature; the old scheme is `InvalidToken` | `space/httpsig.rs` | yes | none |
| Nov 5: no `#atproto_space` key or `#atproto_space_host` entry: tokens are addressed to `<authority>#atproto_pds` and their `kid` is exactly `#atproto` (#123) | `space/token.rs`, `space/host.rs` | yes | none |
| Nov 5: commits are `{ver, repo, space, rev, data}` with no signature, and the repo host MACs each response for one syncer against the author's `#atproto_kem` key; `hash` is `data` (#122) | `space/commit.rs`, `space/mac.rs`, the four read handlers | yes | none: vlpds never stored commit signatures, and the digests are unchanged |
| Nov 5: a `#atproto_kem` key per account: in the genesis op, backfilled once for existing accounts, in getRecommendedDidCredentials, checked by submitPlcOperation | `kem_backfill.rs`, `secrets.rs`, identity endpoints | yes | a wrapped key per account, and one PLC operation per account the backfill can publish for |
| Nov 5: getRepo serves a STAR archive, with control bytes and limits (#114, #131) | `space/star.rs` | yes | none |
| Nov 5: space policies replace simplespace: `com.atproto.space.{create,update,get,delete}Space`, `personalspace`, `memberspace`, `managedspace`, published policy and member records (#119) | the space host methods | yes | Oct 1 configurations convert to policies when read |
| Nov 5: `removeWriter` and `clearRecords` (#128, #127) | the space host and repo methods | no | none |
| Nov 5: account migration: `com.atproto.space.importRepo`, `exportSpaceMeta`, `importSpaceMeta` (#129) | `xrpc/space_import.rs`, `space/meta.rs` | yes (`vlpds.space.importRepo` is gone) | none |
| Nov 5: a taken-down or deactivated authority suspends its spaces: `RepoTakendown` / `RepoDeactivated` on the credential request and the writer listing (#134) | `xrpc/space.rs` | no | none |
| Nov 5: an authority's own repo needs its live space (`SpaceNotFound`) | `space/repo.rs` | no | none |
| The MAC secret is HPKE secret export (RFC 9180 §6.2): DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, Export-only, info `atproto-mac`, empty exporter context. The syncer's ephemeral key is HPKE's `enc` | `space/mac.rs` | yes | none |
| MACs are RFC 9421 `hmac-sha256` signatures. The syncer asks with `Accept-Signature` (its ephemeral key as `keyid`, the profile `atproto-space-commit` or `atproto-space-record` as `tag`), and the host answers with `Atproto-Space-Commit` or `Atproto-Space-Record` and a `Signature-Input` and `Signature` under the requested label. Other tags are ignored; two requests with the profile's tag, or parameters other than `keyid`, `tag` and `alg`, are refused. `Vary: Accept-Signature`, and the three headers exposed to browsers. Replaces `Atproto-Space-Want-Mac` / `Atproto-Space-Mac`; `BadSpaceMac` is `InvalidSpaceMac` | `space/mac.rs`, `space/httpsig.rs`, the read handlers, `space/host.rs` (the syncer side) | yes | none |
| Space credential signatures are made under the label `sig`. A verifier finds exactly one signature by its tag, under any label | `space/httpsig.rs` | yes | none |
| `listRepoOps` carries the current commit (and its MAC) on every page, answers `RepoNotFound` for a repo never written, has a cursor whenever a page is full, and answers `InvalidCursor` for a bad one. A commit's `rev` must be a TID | `xrpc/space.rs`, `space/commit.rs` | yes | none |
| `getSpaceCredential` is `authorizeSpaceSync`: `credentialKey` in place of `credentialKid`, the space's `spaceRev` in the answer, and `SpaceDeleted` before anything about the request is checked | `xrpc/space.rs` | yes | none |
| Notify registrations come with authorization: `authorizeSpaceSync` takes `notify` `{endpoint, token}`, the pair is the registration, and each authorization carrying it renews it until the credential's `exp`. A new one is confirmed with `confirmRegistration` (the challenge echoed, else `RegistrationNotConfirmed`). A refused authorization withdraws its registration. `registerNotify` and `unregisterNotify` are gone | `xrpc/space.rs`, `space/host.rs`, `space/repo.rs` | yes | `sG` rows (registrations) are new. The Nov 5 `sN` rows name no token, and the notices pass deletes them: a syncer registers again the next time it authorizes |
| Syncers get `notifySpaceUpdate` `{space, token, update}`, the update a `repoWrite`, `repoRemoved`, `spaceDeleted` or `registrationExpired`. A lapsed registration's next update is replaced by `registrationExpired`, then it gets nothing but a deletion notice. Deletion and expiry notices are retried for 72 h (1 min, 10 min, 1 h, 6 h, then every 12 h); a syncer that rejects its expiry notice or can't be reached is unregistered. Replaces `notifySpaceDeleted` | `space/fanout.rs`, `space/notices.rs` (`space::deleted` is gone) | yes | `sY` rows for notices still owed. The Nov 5 `sD` rows (notifySpaceDeleted retries) are deleted by the notices pass |
| Removed writers: `removeWriter`, `removeMembers` and a `putMembers` that revokes write sequence the removal at a new spaceRev and forward `repoRemoved`. `listWriters` entries are `repoWrite` or `repoRemoved`, and a removed repo stays listed as removed until it writes again. `exportSpaceMeta` leaves removed writers out | `space/repo.rs`, `space/rows.rs`, `space/meta.rs`, `xrpc/space.rs` | yes | a removed writer's `sW` row is kept and marked (49 bytes); older rows read as not removed |
| Renames: `listRepos` to `listWriters` (`repo` in each entry), `notifyWrite` to `notifyRepoUpdate`, `notifyCredentialRevoked` to `notifyCredentialsRevoked`, `putMember` / `removeMember` to `putMembers` / `removeMembers` (up to 100, one commit, the last entry for a DID wins, non-members ignored), `checkUserAccess` to `checkAccess` (optional `repo`, `read` and `write` answered together), `createSpace` / `getSpace` / `listSpaces` return `space`, `removeWriter` takes `repo`, `listSpaces` filters by `spaceDid`, `NotSpaceOwner` to `NotAuthorized` | `xrpc/space.rs`, `xrpc/space_ops.rs`, `xrpc/space_policy.rs` | yes | none |
| `listSpaces` adds the caller's `repoRev` and `data`, and `spaceRev` for an authority. `listBlobs` drops `since`, `listRecords` drops `reverse`, and `listRecords`, `listSpaces` and `listMembers` answer `InvalidCursor` | `xrpc/space.rs` | yes | none |
| A managed space asks its managing app with no `repo` when there's no delegation token, and `managingApp` must be a `did#serviceId` reference | `space/host.rs`, `xrpc/space_policy.rs` | yes | a stored bare-DID `managingApp` is still read |
| `getRepo`, `exportSpaceMeta`, `importRepo` and `importSpaceMeta` are `application/vnd.dasl.star`. `importRepo` answers `InvalidRepoFile` and `RepoMismatch`, `importSpaceMeta` `InvalidSpaceMeta` | `xrpc/space.rs`, `xrpc/space_meta.rs`, `xrpc/space_import.rs` | yes | none |
| A space meta archive's writer entries hold `repoRev` in place of `rev` | `space/meta.rs` | yes | old archives with `rev` are still read |
| `space:` scopes name the type with `spaceType` in place of `type`. A space type declaration has an optional `title` in place of a required `name` | `oauth/scopes.rs`, `oauth/lexicon.rs`, `oauth/ui.rs` | yes | a stored scope with `type=` and a declaration's `name` are still read |
| Under a `memberspace` with `publicWrite`, a member without write isn't tracked as a writer | `space/repo.rs` | no | none |

Where the spec is silent and vlpds copies the reference: `updateSpace` leaves the writer set as it is
(only `removeWriter`, `removeMembers` and a `putMembers` without write take a writer out),
`listRepoOps` leaves out values for superseded ops, and `listSpaces` treats its
filters as the scope target, so an unfiltered listing needs a wildcard grant.

## Where vlpds differs

| | Reference PDS | vlpds |
|---|---|---|
| Auth | legacy app passwords and password sessions can read and write the account's own space records | OAuth only (final). App passwords (scoped or not) and password sessions get no space reads, writes or delegation tokens, `getServiceAuth` tokens for space methods go only to OAuth apps whose `space:` grant covers the action (the reference checks only `rpc:`), and `importRepo` is OAuth too |
| Admin token on space reads | accepted on the space read methods, a taken-down repo's included | not accepted. Operators read through the audited `vlpds.admin` space methods ([Operating](operating.md)) |
| Exports by a taken-down account | its `allowTakendown` password session may export its spaces | none: space data is OAuth-only, and OAuth signs no taken-down account in |
| Fan-out to syncers | each update goes to a space's registrations in parallel as it's sequenced, unordered | one lane per (space, registration), in spaceRev order, so a slow syncer holds up only itself, and a writer's waiting update is replaced by its newer one |
| notifyRepoUpdate delivery | a retry row written only after a send fails, so an acked write's notify can be lost in a crash | the `sP` row is in the write's own log entry |
| Delegation tokens and client attestations | any lifetime (it mints 60 s) | refused past 300 s, since their `jti`s are held until `exp` |
| Request signatures | no size cap, and header values decoded as latin1 | `Signature-Input` and `Signature` over 8 KiB refused, and header values must be visible ASCII |
| did:keys | refuses hybrid (0x06/0x07) points | the same, checked explicitly, since libsecp256k1 alone would parse them |
| Token claims | `iss` and `sub` need only be truthy | they must be non-empty strings |
| Credential keys | resolves the authority's key on every request | caches a verified credential until `exp`, so a key rotation shows up within the hour |
| Account takedown | the app's session works again after a reversal (what the harness expects) | revokes the account's OAuth sessions, and they stay revoked after a reversal. The app has to sign in again |
| Credentials for taken-down members | issued | refused |
| Record takedown | none for space records: `updateSubjectStatus` refuses a space record | hidden from every space read, and every commit and MAC is over the set without it (a vlpds extension, see [Takedowns](privacy.md#takedowns)) |
| Space takedown | none | a vlpds extension: `authorizeSpaceSync` refuses it (`NotAuthorized`, which withdraws its registration), `listWriters` and credential reads answer `SpaceNotFound`, notifies are dropped and nothing is forwarded |
| Oplog | keeps every op | keeps 7 days. A `since` past that gets the window's start, and the syncer falls back to `getRepo` |
| Revocations | stored for any audience the host has, unbounded, one row each | stored only when the audience account holds a repo in the space or its authority is here (else 200, dropped), capped per authority, space and account, and one past a cap blocks the space's credentials ([Revocation](reading.md#revocation)) |
| Space repo size | no cap | 100k records (`--space-repo-max-records`) |
| Space record size | 1 MiB | 1,000,000 bytes on a write, as for public records; an import takes up to STAR's 1 MiB |
| importRepo | no notify | the authority is told of the imported repo's new rev, as after any write |
| Backlinks | a like of a space URI is recorded as a backlink | public URIs only |
| `sync.getBlob` with Spaces on | serves only publicly referenced blobs | the same. Without `--spaces`, vlpds still serves an upload before any record names it |
| Writes during `clearRecords` or `importRepo` | wait for its transaction | refused with `InvalidRequest` (retry) while the clear or import holds the repo |
| `managingApp` | a `did#serviceId` reference | the same, and the part before `#` must be a valid DID. A bare DID stored before the Nov 12 alpha is still read |
| Nov 5 method names | gone | inbound `notifyWrite` and `notifyCredentialRevoked` are still taken under their Nov 5 names, for peers not yet past them. vlpds sends only the new names |
| Import content types | `application/vnd.dasl.star` | `importRepo` and `importSpaceMeta` take any content type, and read the body as STAR |
| Notify registrations | no caps | at most 256 a space, lapsed ones included (a new one takes the place of the one that lapsed longest ago), 1024 active per authority across its spaces, and 60 new ones an hour per space and endpoint host (`space-register`) |
| The `confirmRegistration` challenge | 16 random base32 characters | 16 random bytes, base64url without padding. A syncer echoes it either way |

## Upstream gaps

```steps
- title: HTTP signatures cover two headers
  body: "A request signature covers only `authorization` and `atproto-space-audience`, with no method or URL. So a captured request can be replayed against any read of the same repo while its credential lives. vlpds requires the audience to be a DID and the target repo, checks the credential's space against the request, and checks revocation on every request. The MAC adds nothing here: it authenticates the response to the syncer, not the request to the host."
- title: Takedowns and the LtHash (Q11)
  body: "The spec has no record takedown for space data, and a hidden record still counts in the repo's hash. vlpds serves a takedown-adjusted view: every read MACs a commit over the set without the hidden records. It keeps every view verifiable, so upstream could adopt it as is."
- title: KEM keys need a PLC operation
  body: "A syncer can't read an account's repos until its `#atproto_kem` key is in its DID document. For an account whose rotation key vlpds doesn't hold (a did:web, or a did:plc that removed it), the key is stored and the owner has to publish it, and until then credential reads of its repos fail."
```
