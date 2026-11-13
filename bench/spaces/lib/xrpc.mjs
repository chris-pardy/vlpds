// The space-family methods (com.atproto.space, memberspace, managedspace) as
// `client.com.atproto.space.<method>(paramsOrInput, opts)`. @atproto/api left
// them out at the Nov 12 alpha (they went to @atproto/lex-space, a higher-level
// client that hides the wire this harness checks), so they're driven here from
// the vendored lexicons (lexicons/spaces-alpha, the same files vlpds serves),
// and every request's params and every JSON answer is validated against them,
// as @atproto/api did. Answers and errors keep @atproto/api's shape: `{ data,
// headers }` with lower-cased header names, and an Error with `status`,
// `error` and `message`.
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { Lexicons, jsonToLex } from '@atproto/lexicon'

const ROOT = new URL('../../../lexicons/spaces-alpha/', import.meta.url).pathname
const NAMESPACES = ['com.atproto.space', 'com.atproto.memberspace', 'com.atproto.managedspace', 'com.atproto.personalspace']

function* lexiconFiles(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) yield* lexiconFiles(join(dir, e.name))
    else if (e.name.endsWith('.json')) yield JSON.parse(readFileSync(join(dir, e.name), 'utf8'))
  }
}

const docs = [...lexiconFiles(ROOT)]
export const lexicons = new Lexicons(docs)
const methods = new Map(docs.filter((d) => ['query', 'procedure'].includes(d.defs.main?.type)).map((d) => [d.id, d.defs.main]))

export class XrpcError extends Error {
  constructor(status, error, message, headers) {
    super(message || error || `HTTP ${status}`)
    this.status = status
    this.error = error
    this.headers = headers
  }
}

export function decodeJwt(jwt) {
  const [h, p] = jwt.split('.')
  return {
    header: JSON.parse(Buffer.from(h, 'base64url').toString()),
    payload: JSON.parse(Buffer.from(p, 'base64url').toString()),
  }
}

// cid-link and blob refs (e.g. a blob from repo.uploadBlob) have toJSON
const encodeBody = (input) => JSON.stringify(input, (_, v) => (v instanceof Uint8Array ? { $bytes: Buffer.from(v).toString('base64').replace(/=+$/, '') } : v))

/**
 * Call `nsid` through `handler(path, init)` (makeClient's fetch handler, which
 * signs, times and retries). Queries take params; procedures take their input
 * (a JSON object, or bytes with `opts.encoding`) and optional `opts.params`.
 */
export async function call(handler, nsid, arg, opts = {}) {
  const def = methods.get(nsid)
  if (!def) throw new Error(`no lexicon for ${nsid}`)
  const params = def.type === 'query' ? arg : opts.params
  if (params) lexicons.assertValidXrpcParams(nsid, params)
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params ?? {})) {
    if (Array.isArray(v)) v.forEach((x) => qs.append(k, String(x)))
    else if (v !== undefined) qs.set(k, String(v))
  }
  const headers = { ...(opts.headers ?? {}) }
  const init = { method: def.type === 'query' ? 'GET' : 'POST', headers }
  if (def.type === 'procedure' && arg !== undefined) {
    if (arg instanceof Uint8Array) {
      init.body = arg
      headers['content-type'] = opts.encoding ?? def.input?.encoding ?? 'application/octet-stream'
    } else {
      init.body = encodeBody(arg)
      headers['content-type'] = 'application/json'
    }
  }
  const res = await handler(`/xrpc/${nsid}${qs.size ? `?${qs}` : ''}`, init)
  const hdrs = Object.fromEntries([...res.headers].map(([k, v]) => [k.toLowerCase(), v]))
  const buf = new Uint8Array(await res.arrayBuffer())
  const isJson = /^application\/json/i.test(hdrs['content-type'] ?? '')
  let json
  if (isJson && buf.length) {
    try {
      json = JSON.parse(Buffer.from(buf).toString('utf8'))
    } catch {}
  }
  if (!res.ok) throw new XrpcError(res.status, json?.error, json?.message, hdrs)
  let data
  if (def.output?.encoding === 'application/json') {
    if (!isJson) throw new XrpcError(200, 'InvalidResponse', `${nsid}: expected application/json, got ${hdrs['content-type']}`, hdrs)
    data = jsonToLex(json)
    try {
      lexicons.assertValidXrpcOutput(nsid, data)
    } catch (e) {
      throw new XrpcError(200, 'InvalidResponse', `${nsid}: the answer does not match the lexicon: ${e.message}`, hdrs)
    }
  } else if (def.output) {
    data = buf
  }
  return { success: true, data, headers: hdrs }
}

/** `client.com.atproto.<ns>.<method>` for the space family, on `handler`. */
export function attachSpaceMethods(client, handler) {
  for (const ns of NAMESPACES) {
    const name = ns.split('.').pop()
    client.com.atproto[name] = new Proxy(
      {},
      {
        get: (_, method) => (typeof method === 'string' ? (arg, opts) => call(handler, `${ns}.${method}`, arg, opts) : undefined),
      },
    )
  }
  return client
}
