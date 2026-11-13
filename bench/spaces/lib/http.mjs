// HTTP plumbing: host-side fetch, the reference XRPC client over a pluggable
// auth layer, and the errors scenarios classify on.
import { AtpBaseClient } from '@atproto/api'
import { PORTS } from './env.mjs'
import { attachSpaceMethods } from './xrpc.mjs'

/** A method the server answered 501 for (or doesn't route): a scenario using it is "not implemented". */
export class NotImplemented extends Error {
  constructor(nsid, detail = '') {
    super(`${nsid} not implemented ${detail}`.trim())
    this.nsid = nsid
  }
}

/** The NotImplemented behind an error, if any (the XRPC client wraps what the fetch handler throws). */
export function notImplemented(e) {
  for (let x = e, i = 0; x && i < 5; x = x.cause, i++) if (x instanceof NotImplemented) return x
  const m = /(\S+) not implemented \((\d+)\)/.exec(e?.message ?? '')
  return m ? new NotImplemented(m[1], `(${m[2]})`) : null
}

// "localhost" can resolve to ::1 first, where nothing listens on the host
export const hostUrl = (u) => String(u).replace('//localhost:', '//127.0.0.1:')

// Client-side timings of the driver's XRPC calls, keyed by scope (the e2e
// config, the sim, the cost step), host, method and outcome, so one host's
// numbers never blend into another's and refusals stay apart from durable
// writes. A call that retried (DPoP nonce, expired token) is timed on its
// final attempt only, and counted under `retried`.
const timings = new Map()
let scope = ''
export function setTimingScope(s) {
  scope = s
}

const PORT_LABELS = new Map([
  [PORTS.refA, 'ref-a'],
  [PORTS.refB, 'ref-b'],
  [PORTS.vlpds, 'vlpds'],
  ...PORTS.vlpdsNodes.map((p, i) => [p, `vlpds-n${i}`]),
  ...Object.entries(PORTS.hostProxy).map(([h, p]) => [p, `${h}~proxy`]),
])
export function hostLabel(url) {
  const u = new URL(String(url))
  return PORT_LABELS.get(Number(u.port)) ?? u.host
}

function outcomeOf(status) {
  if (status >= 200 && status < 300) return 'ok'
  if (status === 501) return 'ni'
  if (status >= 400 && status < 500) return 'refused'
  return 'error'
}

function recordTiming(url, nsid, ms, status, retried = false) {
  const key = [scope, hostLabel(url), nsid, status == null ? 'error' : outcomeOf(status)].join('\t')
  let t = timings.get(key)
  if (!t) timings.set(key, (t = { ms: [], retried: 0 }))
  t.ms.push(ms)
  if (retried) t.retried++
}

const SPACE_METHOD = /^com\.atproto\.(simple)?space\./

/** Flat timing rows (`summarize` each) for the methods `match` takes. */
export function timingRows(summarize, match = SPACE_METHOD) {
  const rows = []
  for (const [k, t] of timings) {
    const [config, host, method, outcome] = k.split('\t')
    if (!match.test(method)) continue
    rows.push({ config, host, method, outcome, ...summarize(t.ms), retried: t.retried })
  }
  const ord = (r) => [r.config, r.host, r.method, r.outcome].join('\t')
  return rows.sort((a, b) => (ord(a) < ord(b) ? -1 : 1))
}

/** Successful calls per host and method across every scope (samples pooled). */
export function timingByHost(summarize, match = SPACE_METHOD) {
  const pooled = new Map()
  for (const [k, t] of timings) {
    const [, host, method, outcome] = k.split('\t')
    if (outcome !== 'ok' || !match.test(method)) continue
    const key = `${host}\t${method}`
    pooled.set(key, [...(pooled.get(key) ?? []), ...t.ms])
  }
  return [...pooled]
    .map(([k, ms]) => {
      const [host, method] = k.split('\t')
      return { host, method, ...summarize(ms) }
    })
    .sort((a, b) => (a.method === b.method ? (a.host < b.host ? -1 : 1) : a.method < b.method ? -1 : 1))
}

export async function hfetch(url, init = {}) {
  return fetch(hostUrl(url), { ...init, redirect: 'manual' })
}

// a 404 naming an unrouted method counts as 501 (not implemented)
const notImplementedStatus = (status, body) => (status === 404 && /MethodNotImplemented|XRPCNotSupported|Method Not Implemented/i.test(body) ? 501 : status)

function nsidOf(path) {
  return /\/xrpc\/([^?]+)/.exec(path)?.[1] ?? path
}

/**
 * The reference XRPC client (@atproto/api at the alpha, plus the space
 * methods from lib/xrpc.mjs) against `base`, with
 * `sign(request)` adding auth headers to each request (and retrying it when it
 * returns a new Request, for DPoP nonces). 501 becomes {@link NotImplemented}.
 */
export function makeClient(base, sign = null) {
  const handler = async (path, init) => {
    const url = new URL(path, base).toString()
    const nsid = nsidOf(path)
    let headers = new Headers(init.headers)
    let res
    for (let attempt = 0; attempt < 3; attempt++) {
      const h = new Headers(headers)
      if (sign) await sign({ method: (init.method ?? 'GET').toUpperCase(), url, headers: h, body: init.body, attempt })
      const t0 = performance.now()
      try {
        res = await hfetch(url, { ...init, headers: h })
      } catch (e) {
        recordTiming(url, nsid, performance.now() - t0, null, attempt > 0)
        throw e
      }
      const ms = performance.now() - t0
      const again = sign?.retry && (await sign.retry(res, { method: (init.method ?? 'GET').toUpperCase(), url }))
      if (again && attempt < 2) continue
      recordTiming(url, nsid, ms, notImplementedStatus(res.status, res.status === 404 ? await res.clone().text() : ''), attempt > 0)
      break
    }
    if (res.status === 501) throw new NotImplemented(nsid, `(${res.status})`)
    if (res.status === 404 && notImplementedStatus(404, await res.clone().text()) === 501) throw new NotImplemented(nsid, '(404)')
    return res
  }
  return attachSpaceMethods(new AtpBaseClient(handler), handler)
}

/** Call and return `{ok, status, error, message, data}` instead of throwing XRPC errors. */
export async function attempt(fn) {
  try {
    const r = await fn()
    return { ok: true, status: 200, data: r.data, headers: r.headers }
  } catch (e) {
    const ni = notImplemented(e)
    if (ni) throw ni
    if (e && typeof e.status === 'number') return { ok: false, status: e.status, error: e.error, message: e.message }
    throw e
  }
}

/** Raw XRPC request (for wire tests the typed client can't express). */
export async function rawXrpc(base, nsid, { method = 'GET', params, body, headers = {}, contentType } = {}) {
  const u = new URL(`/xrpc/${nsid}`, base)
  for (const [k, v] of Object.entries(params ?? {})) {
    if (Array.isArray(v)) v.forEach((x) => u.searchParams.append(k, x))
    else if (v !== undefined) u.searchParams.set(k, String(v))
  }
  const init = { method, headers: { ...headers } }
  if (body !== undefined) {
    if (body instanceof Uint8Array) {
      init.body = body
      init.headers['content-type'] = contentType ?? 'application/octet-stream'
    } else {
      init.body = JSON.stringify(body)
      init.headers['content-type'] = 'application/json'
    }
  }
  const t0 = performance.now()
  let res
  try {
    res = await hfetch(u, init)
  } catch (e) {
    recordTiming(u, nsid, performance.now() - t0, null)
    throw e
  }
  const ms = performance.now() - t0
  const buf = new Uint8Array(await res.arrayBuffer())
  let json
  try {
    json = JSON.parse(new TextDecoder().decode(buf))
  } catch {}
  recordTiming(u, nsid, ms, res.status === 404 && /MethodNotImplemented|XRPCNotSupported/.test(json?.error ?? '') ? 501 : res.status)
  if (res.status === 501) throw new NotImplemented(nsid, '(501)')
  if (res.status === 404 && /MethodNotImplemented|XRPCNotSupported/.test(json?.error ?? '')) throw new NotImplemented(nsid, '(404)')
  return { status: res.status, ok: res.ok, headers: res.headers, bytes: buf, json, error: json?.error, message: json?.message }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export async function waitFor(what, fn, { timeoutMs = 15000, intervalMs = 100 } = {}) {
  const t0 = Date.now()
  let last
  while (Date.now() - t0 < timeoutMs) {
    try {
      last = await fn()
      if (last) return last
    } catch (e) {
      const ni = notImplemented(e)
      if (ni) throw ni
      last = e
    }
    await sleep(intervalMs)
  }
  throw new Error(`timed out waiting for ${what}${last instanceof Error ? `: ${last.message}` : ''}`)
}
