// A space syncer built on the reference library (@atproto/space): it catches
// up through the space host's listWriters from a spaceRev checkpoint, pulls
// each repo from its own host with listRepoOps (inline values; every page
// carries the current commit and its MAC, checked once the last page is
// applied), keeps a running LtHash per repo and compares it to the verified
// commit, falling back to a full getRepo (a STAR archive, verified with
// verifyRepoStarFull) on a mismatch or when it has nothing yet. notifySpaceUpdate
// drives it between catch-ups: a repoWrite pulls, a repoRemoved drops the repo,
// a prevSpaceRev it hasn't processed means a gap (back to listWriters), and
// registrationExpired re-authorizes. Every read asks for a MAC with a key share
// encapsulated afresh to the author's #atproto_kem key, and counts only once it
// verifies.
import { COMMIT_MAC_PROFILE, LtHash, verifyRepoStarFull } from '@atproto/space'
import { attempt } from './http.mjs'
import { commitOk, credentialFor } from './space.mjs'

const REPO_WRITE = 'com.atproto.space.defs#repoWrite'
const REPO_REMOVED = 'com.atproto.space.defs#repoRemoved'
const cidStr = (c) => (c == null ? null : typeof c === 'string' ? c : c.toString())

export class Syncer {
  /**
   * `member`: the account whose delegation the syncer's credentials come from
   * (a reader). `notify()`, when given, answers the {endpoint, token} each
   * authorization registers (and so renews).
   */
  constructor(name, space, member, { snapshot, notify } = {}) {
    this.name = name
    this.space = space
    this.member = member
    this.register = notify
    this.cred = null
    this.checkpoint = undefined // the last spaceRev whose repos are fully processed
    this.repos = new Map() // did -> { rev, hash: LtHash, records: Map(path -> { cid, value }) }
    this.violations = []
    this.stats = { listWriters: 0, opsPulls: 0, fullPulls: 0, mismatchFallbacks: 0, macRetries: 0, gaps: 0, notifies: 0, dupNotifies: 0, removed: 0, expired: 0, credentials: 0 }
    this.lastSpaceRev = undefined // highest spaceRev seen (listWriters or notify)
    this.chains = new Map() // did -> promise, to serialize per-repo pulls
    this.lastError = null
    this.deleted = false
    this.queue = Promise.resolve()
    if (snapshot) this.restore(snapshot)
  }

  /** Notifies and catch-ups run one at a time, in arrival order. */
  enqueue(fn) {
    const p = this.queue.then(fn)
    this.queue = p.catch((e) => {
      this.lastError = e
    })
    return p
  }

  sync() {
    return this.enqueue(() => this.catchUp())
  }

  /** A notifySpaceUpdate body ({space, token, update}). */
  notify(body) {
    return this.enqueue(() => this.onNotify(body))
  }

  idle() {
    return this.queue
  }

  violation(what) {
    this.violations.push(`${new Date().toISOString()} ${this.name}: ${what}`)
  }

  async credential(force = false) {
    if (force || !this.cred || this.cred.expiresInMs() < 60_000) {
      this.cred = await credentialFor(this.member, this.space, { notify: this.register?.() })
      this.stats.credentials++
    }
    return this.cred
  }

  /** Repeat a read with a fresh credential once when the host says it expired or was revoked. */
  async withCred(fn) {
    let cred = await this.credential()
    try {
      return await fn(cred)
    } catch (e) {
      if (e?.status === 401 || /Expired|Revoked/i.test(e?.error ?? '')) {
        cred = await this.credential(true)
        return fn(cred)
      }
      throw e
    }
  }

  /** listWriters from the checkpoint to an empty page; pulls repos whose repoRev moved. */
  async catchUp() {
    let cursor = this.checkpoint
    for (;;) {
      this.stats.listWriters++
      const page = await this.withCred(async (cred) => (await cred.hostClient()).com.atproto.space.listWriters({ space: this.space, cursor, limit: 100 }))
      const repos = page.data.repos
      if (!repos.length) {
        if (page.data.cursor !== undefined) this.violation(`empty listWriters page carries cursor ${page.data.cursor}`)
        break
      }
      let prev = cursor
      for (const r of repos) {
        if (prev !== undefined && !(r.spaceRev > prev)) this.violation(`listWriters spaceRev not ascending: ${r.spaceRev} after ${prev}`)
        if (r.prevSpaceRev !== undefined) this.violation(`listWriters entry carries prevSpaceRev ${r.prevSpaceRev}`)
        prev = r.spaceRev
        if (r.$type === REPO_REMOVED) {
          this.repos.delete(r.repo)
        } else if (r.$type === REPO_WRITE) {
          const local = this.repos.get(r.repo)
          if (!local || local.rev < r.repoRev || !hashEq(local.hash.digest(), r.data)) await this.pull(r.repo)
        } else {
          this.violation(`listWriters entry of unknown $type ${r.$type}`)
        }
        this.seeSpaceRev(r.spaceRev)
      }
      if (page.data.cursor !== undefined && page.data.cursor !== repos.at(-1).spaceRev) this.violation(`listWriters cursor ${page.data.cursor} != last spaceRev ${repos.at(-1).spaceRev}`)
      if (page.data.cursor === undefined) {
        this.checkpoint = repos.at(-1).spaceRev
        break
      }
      cursor = page.data.cursor
      this.checkpoint = cursor
    }
  }

  seeSpaceRev(rev) {
    if (this.lastSpaceRev === undefined || rev > this.lastSpaceRev) this.lastSpaceRev = rev
  }

  async onNotify(body) {
    if (body.space !== this.space) return
    const u = body.update ?? {}
    this.stats.notifies++
    if (u.$type === 'com.atproto.space.notifySpaceUpdate#spaceDeleted') {
      this.deleted = true
      return
    }
    if (u.$type === 'com.atproto.space.notifySpaceUpdate#registrationExpired') {
      // re-authorize (renewing the registration), then catch up from where we were
      this.stats.expired++
      await this.credential(true)
      await this.catchUp()
      return
    }
    if (this.lastSpaceRev !== undefined && u.spaceRev <= this.lastSpaceRev) {
      this.stats.dupNotifies++ // duplicate or out of order: never move the checkpoint back
      // only a repo still held: one not held was removed since (or is new, which
      // the in-order update or listWriters brings)
      const local = this.repos.get(u.repo)
      if (u.$type === REPO_WRITE && local && local.rev < u.repoRev) await this.pull(u.repo)
      return
    }
    if (u.prevSpaceRev !== this.checkpoint) {
      this.stats.gaps++
      await this.catchUp()
      return
    }
    if (u.$type === REPO_REMOVED) {
      this.stats.removed++
      this.repos.delete(u.repo)
    } else {
      await this.pull(u.repo)
    }
    this.seeSpaceRev(u.spaceRev)
    this.checkpoint = u.spaceRev
  }

  pull(did) {
    const prev = this.chains.get(did) ?? Promise.resolve()
    const next = prev.catch(() => {}).then(() => this.pullNow(did))
    this.chains.set(did, next)
    return next
  }

  async pullNow(did) {
    const local = this.repos.get(did)
    if (!local) return this.full(did)
    this.stats.opsPulls++
    const work = { rev: local.rev, hash: new LtHash(local.hash.state()), records: new Map(local.records) }
    let cursor
    let last
    for (;;) {
      const m = await this.withCred((cred) =>
        cred.macRead(did, COMMIT_MAC_PROFILE, (c, opts) => c.com.atproto.space.listRepoOps({ space: this.space, repo: did, since: local.rev || undefined, cursor, limit: 100 }, opts)),
      )
      const page = m.res.data
      if (!page.commit) this.violation(`listRepoOps page for ${did} without a commit`)
      for (const op of page.ops) {
        const path = `${op.collection}/${op.rkey}`
        const prevCid = cidStr(op.prev)
        const cid = cidStr(op.cid)
        if (prevCid) work.hash.remove(`${path}/${prevCid}`)
        if (cid) work.hash.add(`${path}/${cid}`)
        if (cid) work.records.set(path, { cid, value: op.value })
        else work.records.delete(path)
      }
      last = m
      if (!page.cursor) break
      cursor = page.cursor
    }
    const commit = last.res.data.commit
    if (!commit || !commitOk(commit, { space: this.space, repo: did, ...last })) {
      this.stats.macRetries++
      this.violation(`listRepoOps commit for ${did} failed verification`)
      return this.full(did)
    }
    if (!hashEq(work.hash.digest(), commit.data)) {
      this.stats.mismatchFallbacks++
      return this.full(did)
    }
    if (local.rev && commit.rev < local.rev) this.violation(`repo ${did} rev went back: ${commit.rev} < ${local.rev}`)
    work.rev = commit.rev
    this.repos.set(did, work)
  }

  async full(did) {
    this.stats.fullPulls++
    let m
    const res = await this.withCred(async (cred) =>
      attempt(async () => {
        m = await cred.macRead(did, COMMIT_MAC_PROFILE, (c, opts) => c.com.atproto.space.getRepo({ space: this.space, repo: did }, opts))
        return m.res
      }),
    )
    if (!res.ok) {
      if (res.error === 'RepoNotFound') {
        this.repos.set(did, { rev: '', hash: new LtHash(), records: new Map() })
        return
      }
      throw new Error(`getRepo ${did}: ${res.status} ${res.error} ${res.message}`)
    }
    const verified = await verifyRepoStarFull([res.data], { space: this.space, repo: did, keyShare: m.keyShare, sharedSecret: m.sharedSecret, headers: m.headers })
    const records = new Map()
    const hash = new LtHash()
    for (const r of verified.records) {
      const path = `${r.collection}/${r.rkey}`
      records.set(path, { cid: r.cid.toString(), value: r.record })
      hash.add(`${path}/${r.cid.toString()}`)
    }
    const prev = this.repos.get(did)
    if (prev?.rev && verified.commit.rev < prev.rev) this.violation(`repo ${did} rev went back on getRepo: ${verified.commit.rev} < ${prev.rev}`)
    this.repos.set(did, { rev: verified.commit.rev, hash, records })
  }

  /** Paths and CIDs of a repo, for comparing against ground truth. */
  view(did) {
    const r = this.repos.get(did)
    if (!r) return null
    return new Map([...r.records].map(([p, v]) => [p, v.cid]))
  }

  snapshot() {
    return {
      checkpoint: this.checkpoint,
      lastSpaceRev: this.lastSpaceRev,
      repos: [...this.repos].map(([did, r]) => [did, { rev: r.rev, state: Buffer.from(r.hash.state()).toString('base64'), records: [...r.records] }]),
    }
  }

  restore(s) {
    this.checkpoint = s.checkpoint
    this.lastSpaceRev = s.lastSpaceRev
    this.repos = new Map(s.repos.map(([did, r]) => [did, { rev: r.rev, hash: new LtHash(Buffer.from(r.state, 'base64')), records: new Map(r.records) }]))
  }
}

export function hashEq(a, b) {
  if (!a || !b || a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
