// The space credential chain, as an app runs it with the reference library:
// a delegation token from the user's own PDS, exchanged at the authority's PDS
// with authorizeSpaceSync for a credential bound to a fresh P-256 key (and, for
// a syncer, a notify registration), then reads anywhere with
// `Authorization: Atproto-Space-Credential`, an audience and an RFC 9421
// signature (@atproto/space createSpaceSigHeaders), plus an Accept-Signature
// MAC request on the reads a syncer trusts.
// (Through the Nov 5 alpha this came from the boards app's Spaces client; that
// app isn't in this repo, so the chain lives here now.)
import { P256Keypair } from '@atproto/crypto'
import { COMMIT_MAC_PROFILE, RECORD_MAC_PROFILE, createSpaceSigHeaders, encapsulate, formatMacRequest, verifyCommit } from '@atproto/space'
import { SPACE_TYPE } from './env.mjs'
import { makeClient } from './http.mjs'
import { kemKey, pdsEndpoint } from './identity.mjs'
import { decodeJwt } from './xrpc.mjs'

export { decodeJwt }

export const spaceUri = (authorityDid, skey, type = SPACE_TYPE) => `at://${authorityDid}/space/${type}/${skey}`
export const spaceDidOf = (uri) => uri.split('/')[2]
export const CRED_SCHEME = 'Atproto-Space-Credential'

export const POLICY = {
  members: (opts = {}) => ({ $type: 'com.atproto.memberspace.policy', ...opts }),
  public: { $type: 'com.atproto.memberspace.policy', publicRead: true },
  managed: (managingApp) => ({ $type: 'com.atproto.managedspace.policy', managingApp }),
  personal: { $type: 'com.atproto.personalspace.policy' },
}

const endpoints = new Map()
/** A repo's host (its #atproto_pds), cached: the harness never moves accounts. */
export async function repoHost(did) {
  if (!endpoints.has(did)) endpoints.set(did, await pdsEndpoint(did))
  return endpoints.get(did)
}

export async function createSpace(authority, skey, opts = {}) {
  const res = await authority.client.com.atproto.space.createSpace({
    spaceType: opts.spaceType ?? SPACE_TYPE,
    skey,
    policy: opts.policy ?? POLICY.members(),
  })
  return res.data.space
}

export async function putMember(authority, space, member, read = true, write = true) {
  await authority.client.com.atproto.memberspace.putMembers({ space, members: [{ did: member.did ?? member, read, write }] })
}

export async function removeMember(authority, space, member) {
  await authority.client.com.atproto.memberspace.removeMembers({ space, dids: [member.did ?? member] })
}

/** The delegation token: minted by the user's own PDS for the space. */
export async function delegationToken(actor, space) {
  return (await actor.client.com.atproto.space.getDelegationToken({ space })).data.token
}

/**
 * authorizeSpaceSync at the authority's PDS with a delegation token (undefined:
 * ask without one). `notify` ({endpoint, token}) registers for notifySpaceUpdate;
 * `credentialKey` overrides the key's did (to send a wrong one).
 */
export async function exchange(space, token, { key, credentialKey, clientAttestation, notify } = {}) {
  key ??= await P256Keypair.create()
  const host = makeClient(await repoHost(spaceDidOf(space)))
  const r = await host.com.atproto.space.authorizeSpaceSync({ space, credentialKey: credentialKey ?? key.did(), delegationToken: token, clientAttestation, notify })
  const cred = new SpaceCred(space, r.data.credential, key)
  cred.spaceRev = r.data.spaceRev
  return cred
}

/** A fresh credential for `actor` (delegation on their PDS, authorizeSpaceSync at the authority). */
export async function credentialFor(actor, space, opts = {}) {
  return exchange(space, await delegationToken(actor, space), opts)
}

const MAC_PROFILES = {
  'com.atproto.space.getLatestCommit': COMMIT_MAC_PROFILE,
  'com.atproto.space.getRepo': COMMIT_MAC_PROFILE,
  'com.atproto.space.listRepoOps': COMMIT_MAC_PROFILE,
  'com.atproto.space.getRecord': RECORD_MAC_PROFILE,
}

/** A MAC request for `did`'s #atproto_kem key: the Accept-Signature value and the encapsulation. */
export async function macRequest(did, profile) {
  const enc = await encapsulate(await kemKey(did))
  return { ...enc, value: formatMacRequest(profile, enc.keyShare) }
}

/** Whether a response's commit MAC verifies (the reference's verifyCommit throws). */
export function commitOk(commit, { space, repo, keyShare, sharedSecret, headers }) {
  try {
    verifyCommit(commit, { space, repo, keyShare, sharedSecret, headers: headers instanceof Headers ? headers : new Headers(headers) })
    return true
  } catch {
    return false
  }
}

export class SpaceCred {
  constructor(space, credential, key) {
    this.space = space
    this.credential = credential
    this.key = key
    this.claims = decodeJwt(credential)
    this.sigs = new Map() // audience -> headers; a signature is reusable per (credential, audience)
  }

  get jti() {
    return this.claims.payload.jti
  }

  expiresInMs() {
    return this.claims.payload.exp * 1000 - Date.now()
  }

  async headersFor(audience) {
    let h = this.sigs.get(audience)
    if (!h) {
      h = (await createSpaceSigHeaders({ authorization: `${CRED_SCHEME} ${this.credential}`, audience, keypair: this.key })).headers
      this.sigs.set(audience, h)
    }
    return h
  }

  /**
   * The auth layer for {@link makeClient}: the audience is the request's
   * `repo` (a repo-host method) or else the space's authority (a host method).
   */
  signer(overrides = {}) {
    return async ({ url, headers, body }) => {
      let params = Object.fromEntries(new URL(url).searchParams)
      if (body && typeof body === 'string') {
        try {
          params = { ...params, ...JSON.parse(body) }
        } catch {}
      }
      const audience = overrides.audience ?? params.repo ?? spaceDidOf(params.space ?? this.space)
      for (const [k, v] of Object.entries(await this.headersFor(audience))) headers.set(k, v)
      for (const [k, v] of Object.entries(overrides.headers ?? {})) headers.set(k, v)
    }
  }

  client(base, overrides) {
    return makeClient(base, this.signer(overrides))
  }

  /** A client for `did`'s repo host. */
  async repoClient(did) {
    return this.client(await repoHost(did))
  }

  /** A client for the space host (the authority's PDS). */
  async hostClient() {
    return this.client(await repoHost(spaceDidOf(this.space)))
  }

  /**
   * One read of `did`'s repo host asking for a MAC under `profile`, with a key
   * share encapsulated afresh: `fn(client, opts)` makes the call. Answers the
   * response, the encapsulation and the response headers to verify with
   * (`mac`: whether a signature came back at all).
   */
  async macRead(did, profile, fn) {
    const req = await macRequest(did, profile)
    const res = await fn(await this.repoClient(did), { headers: { 'accept-signature': req.value } })
    const headers = new Headers(res.headers)
    return { res, keyShare: req.keyShare, sharedSecret: req.sharedSecret, headers, mac: headers.has('signature') }
  }

  /**
   * A client for `did`'s repo host that asks for a MAC, with a fresh key share,
   * on every method that needs one, and checks none: for callers that want the
   * answer, not its authentication (the cost run, sim bookkeeping).
   */
  async macClient(did) {
    const kem = await kemKey(did)
    const sign = this.signer()
    return makeClient(await repoHost(did), async (req) => {
      await sign(req)
      const profile = MAC_PROFILES[new URL(req.url).pathname.replace(/^\/xrpc\//, '')]
      if (profile) req.headers.set('accept-signature', formatMacRequest(profile, (await encapsulate(kem)).keyShare))
    })
  }
}

/** getLatestCommit of `did` with a MAC, verified (throws when it doesn't verify). */
export async function headOf(cred, space, did) {
  const m = await cred.macRead(did, COMMIT_MAC_PROFILE, (cl, opts) => cl.com.atproto.space.getLatestCommit({ space, repo: did }, opts))
  const commit = m.res.data.commit
  if (!commitOk(commit, { space, repo: did, ...m })) throw new Error(`getLatestCommit of ${did}: the commit's MAC did not verify`)
  return commit
}
