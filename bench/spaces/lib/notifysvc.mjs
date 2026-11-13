// A syncing service's inbound side: the endpoint a syncer registers with
// authorizeSpaceSync's `notify` (this server, or a fault proxy in front of it),
// with a token per space. It answers confirmRegistration (echoing the challenge
// for a token it issued for that space), takes notifySpaceUpdate (no service
// auth: the token in the body is the registration's), records every call and
// hands updates to listeners. It also has a real did:plc, so it can answer
// managedspace.checkAccess as a managing app (`<did>#atproto_space_syncer`);
// that call's service auth (iss = the space's authority, aud = this service,
// lxm) is checked against the authority's key from the PLC.
import { randomBytes } from 'node:crypto'
import http from 'node:http'
import { verifySignature } from '@atproto/crypto'
import { createServiceDid, signingKey } from './identity.mjs'
import { decodeJwt, spaceDidOf } from './space.mjs'

export class NotifyService {
  constructor(port, { publicPort } = {}) {
    this.port = port
    this.publicPort = publicPort ?? port
    this.calls = []
    this.listeners = new Set()
    this.authFailures = []
    this.access = () => false // checkAccess policy: (space, repo, clientId) => bool | {read, write}
    this.tokens = new Map() // token -> space
    this.confirm = () => true // confirmRegistration: false answers a wrong challenge
    this.accept = () => true // notifySpaceUpdate: false refuses it (400), as a syncer unregistering does
  }

  get endpoint() {
    return `http://localhost:${this.publicPort}`
  }

  /** The `notify` a syncer of `space` registers with (one token per space, kept across authorizations). */
  register(space) {
    let token = [...this.tokens].find(([, s]) => s === space)?.[0]
    if (!token) this.tokens.set((token = randomBytes(16).toString('hex')), space)
    return { endpoint: this.endpoint, token }
  }

  async start() {
    this.server = http.createServer((req, res) => this.handle(req, res))
    await new Promise((r) => this.server.listen(this.port, '127.0.0.1', r))
    const id = await createServiceDid('atproto_space_syncer', `http://localhost:${this.publicPort}`)
    this.did = id.did
    this.serviceRef = id.serviceRef
    return this
  }

  async stop() {
    this.server?.closeAllConnections?.()
    await new Promise((r) => this.server?.close(r) ?? r())
  }

  on(fn) {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }

  callsTo(lxm, space) {
    return this.calls.filter((c) => c.lxm === lxm && (!space || c.body?.space === space))
  }

  /** notifySpaceUpdate calls for `space` whose update is `type` (repoWrite, repoRemoved, spaceDeleted, registrationExpired). */
  updates(space, type) {
    return this.callsTo('com.atproto.space.notifySpaceUpdate', space).filter((c) => !type || c.body.update?.$type?.endsWith(`#${type}`))
  }

  async verifyAuth(auth, lxm, space) {
    if (!auth?.startsWith('Bearer ')) return 'no bearer service auth'
    const jwt = auth.slice(7)
    let claims
    try {
      claims = decodeJwt(jwt)
    } catch {
      return 'malformed jwt'
    }
    const { payload } = claims
    const authority = space ? spaceDidOf(space) : undefined
    if (authority && payload.iss !== authority) return `iss ${payload.iss} is not the authority ${authority}`
    if (payload.aud !== this.serviceRef && payload.aud !== this.did) return `aud ${payload.aud} is not ${this.serviceRef}`
    if (payload.lxm !== lxm) return `lxm ${payload.lxm} is not ${lxm}`
    if (!(payload.exp * 1000 > Date.now() - 5000)) return 'expired'
    const [h, p, s] = jwt.split('.')
    try {
      const key = await signingKey(payload.iss)
      const ok = await verifySignature(key, new TextEncoder().encode(`${h}.${p}`), Buffer.from(s, 'base64url'))
      if (!ok) return 'bad signature'
    } catch (e) {
      return `signature check failed: ${e.message}`
    }
    return null
  }

  async handle(req, res) {
    const chunks = []
    for await (const c of req) chunks.push(c)
    const raw = Buffer.concat(chunks).toString('utf8')
    const url = new URL(req.url, 'http://localhost')
    const lxm = url.pathname.replace(/^\/xrpc\//, '')
    let body
    try {
      body = raw ? JSON.parse(raw) : Object.fromEntries(url.searchParams)
    } catch {
      body = raw
    }
    const at = performance.now()
    // the registration's token authenticates what a space host sends a syncer
    const tokenAuthed = lxm === 'com.atproto.space.confirmRegistration' || lxm === 'com.atproto.space.notifySpaceUpdate'
    const authErr = tokenAuthed
      ? this.tokens.get(body?.token) === body?.space
        ? null
        : `token ${String(body?.token).slice(0, 8)} was not issued for ${body?.space}`
      : await this.verifyAuth(req.headers.authorization, lxm, body?.space)
    const call = { lxm, body, at, wall: Date.now(), authErr, auth: req.headers.authorization }
    this.calls.push(call)
    const reply = (status, obj) => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(obj ?? {}))
    }
    if (authErr) {
      this.authFailures.push(call)
      return reply(tokenAuthed ? 400 : 401, { error: tokenAuthed ? 'InvalidRequest' : 'AuthRequired', message: authErr })
    }
    if (lxm === 'com.atproto.space.confirmRegistration') {
      return reply(200, { challenge: this.confirm(body) ? body.challenge : `${body.challenge}x` })
    }
    if (lxm === 'com.atproto.managedspace.checkAccess') {
      const a = this.access(body.space, body.repo, body.clientId)
      return reply(200, typeof a === 'object' ? a : { read: !!a, write: !!a })
    }
    if (lxm === 'com.atproto.space.notifySpaceUpdate' && !this.accept(body)) {
      return reply(400, { error: 'InvalidRequest', message: 'not registered' })
    }
    for (const fn of this.listeners) {
      try {
        fn(call)
      } catch (e) {
        console.error('notify listener', e)
      }
    }
    reply(200, {})
  }
}
