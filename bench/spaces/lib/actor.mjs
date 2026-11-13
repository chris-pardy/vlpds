// Accounts on a host and how the driver acts as them. On a reference PDS that
// is a password session (as the reference's own tests do; it accepts one for
// space methods). On vlpds, space access is OAuth-only, so each account also
// authorizes a loopback client headlessly (lib/oauth.mjs) for the scope below;
// the password session is kept for account chores and the refusal tests.
// Passwords are random per run, and every account lives on this stack only.
import { randomBytes } from 'node:crypto'
import { HOSTS, SPACE_TYPE } from './env.mjs'
import { makeClient, rawXrpc } from './http.mjs'
import { oauthLogin } from './oauth.mjs'

export const RUN = process.env.RUN_ID ?? randomBytes(3).toString('hex')

// What an app asks of vlpds: every space action on the harness's space type
// at any authority, managing spaces, blobs, public writes (the leak check's
// control) and the service-auth minting the revocation scenario needs.
export const APP_SCOPE = [
  'atproto',
  `space:${SPACE_TYPE}?authority=*&collection=*&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete`,
  'blob:*/*',
  'repo:*',
  'rpc:com.atproto.space.notifyCredentialsRevoked?aud=*',
  'rpc:com.atproto.space.notifyRepoUpdate?aud=*',
].join(' ')

let seq = 0

function sessionSigner(state) {
  const s = ({ headers }) => headers.set('authorization', `Bearer ${state.accessJwt}`)
  s.retry = async (res) => {
    if (res.status !== 400 && res.status !== 401) return false
    const j = await res.clone().json().catch(() => ({}))
    if (j.error !== 'ExpiredToken') return false
    const r = await rawXrpc(state.base, 'com.atproto.server.refreshSession', {
      method: 'POST',
      headers: { authorization: `Bearer ${state.refreshJwt}` },
    })
    if (!r.ok) return false
    state.accessJwt = r.json.accessJwt
    state.refreshJwt = r.json.refreshJwt
    return true
  }
  return s
}

export class Actor {
  constructor(fields) {
    Object.assign(this, fields)
  }

  get kind() {
    return HOSTS[this.host].kind
  }

  toString() {
    return `${this.name}@${this.host}`
  }

  /**
   * A new account on `hostKey` ('ref-a' | 'ref-b' | 'vlpds'). With
   * `oauth: false` a vlpds account skips the OAuth grant.
   */
  static async create(hostKey, name, { oauth = true, scope = APP_SCOPE } = {}) {
    const host = HOSTS[hostKey]
    const short = `${name}${RUN}${(seq++).toString(36)}`.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 30)
    const handle = `${short}.${host.handleDomain}`
    const password = randomBytes(18).toString('base64url')
    let r
    for (let i = 0; i < 60; i++) {
      r = await rawXrpc(host.url, 'com.atproto.server.createAccount', {
        method: 'POST',
        body: { handle, password, email: `${short}@example.com` },
      })
      if (r.status !== 503) break // a cluster still placing shards answers 503 for a moment
      await new Promise((ok) => setTimeout(ok, 500))
    }
    if (!r.ok) throw new Error(`createAccount ${handle} on ${hostKey}: ${r.status} ${r.error} ${r.message}`)
    const state = { base: host.url, accessJwt: r.json.accessJwt, refreshJwt: r.json.refreshJwt }
    const sessionClient = makeClient(host.url, sessionSigner(state))
    const actor = new Actor({
      name,
      host: hostKey,
      base: host.url,
      did: r.json.did,
      handle,
      password,
      session: state,
      sessionClient,
      client: sessionClient,
      oauth: null,
    })
    if (host.kind === 'vlpds' && oauth) await actor.authorize(scope)
    return actor
  }

  /** (vlpds) Authorize the app for `scope`; space calls then go out with the DPoP token. */
  async authorize(scope = APP_SCOPE) {
    this.oauth = await oauthLogin(this.base, { handle: this.handle, did: this.did, password: this.password, scope })
    this.client = makeClient(this.base, this.oauth.signer())
    return this.oauth
  }

  /** A client acting as this account with another auth layer (an app password session, say). */
  clientWith(signer) {
    return makeClient(this.base, signer)
  }

  bearer(token) {
    return makeClient(this.base, ({ headers }) => headers.set('authorization', `Bearer ${token}`))
  }

  async createAppPassword(name = `app-${seq++}`, privileged = false) {
    const r = await rawXrpc(this.base, 'com.atproto.server.createAppPassword', {
      method: 'POST',
      body: { name, privileged },
      headers: { authorization: `Bearer ${this.session.accessJwt}` },
    })
    if (!r.ok) throw new Error(`createAppPassword: ${r.status} ${r.error} ${r.message}`)
    const s = await rawXrpc(this.base, 'com.atproto.server.createSession', {
      method: 'POST',
      body: { identifier: this.handle, password: r.json.password },
    })
    if (!s.ok) throw new Error(`createSession (app password): ${s.status} ${s.error} ${s.message}`)
    return s.json.accessJwt
  }
}
