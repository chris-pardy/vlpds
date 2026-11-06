//! STAR archives (<https://dasl.ing/star.html>, @atproto/star) and the
//! `atproto-space-repo` profile getRepo serves: a header, then key/value
//! pairs each preceded by a `0x01` control byte, then a `0x00` to end it.
//!
//! ```text
//! [ magic | len | meta ] [ 1 | len | path | len | record ] ... [ 0 ]
//! ```
//!
//! The magic is `2a 6c 01 00`, each `len` an unsigned varint in its
//! shortest form. The metadata is the repo's commit plus `"$type":
//! "atproto-space-repo"`, as canonical DRISL; each pair is a record path
//! (`{collection}/{rkey}`) and the record's DRISL bytes, in strict bytewise
//! order of the paths. The profile caps the metadata at 64 KiB, a path at
//! 4 KiB and a record at 1 MiB (the reference's `REPO_STAR_LIMITS`). The
//! MAC is in the response's `Atproto-Space-Mac` header, not the archive.

use super::commit::Commit;
use super::lthash::LtHash;

pub const MAGIC: [u8; 4] = [0x2a, 0x6c, 0x01, 0x00];
/// Before each pair.
pub const CONTROL_PAIR: u8 = 0x01;
/// After the last pair: the archive is complete.
pub const CONTROL_END: u8 = 0x00;
pub const REPO_STAR_TYPE: &str = "atproto-space-repo";
/// The largest record a space repo holds (the reference's `MAX_RECORD_SIZE`).
pub const MAX_RECORD_SIZE: usize = 1 << 20;
/// Both Spaces profiles' metadata and key limits (`REPO_STAR_LIMITS`,
/// `SPACE_META_STAR_LIMITS`); STAR itself sets none.
pub const MAX_META_LENGTH: u64 = 64 << 10;
pub const MAX_KEY_LENGTH: u64 = 4 << 10;
/// A varint longer than this is refused (as @atproto/star).
pub const MAX_VARINT_BYTES: usize = 9;

/// The reference's `StarParseError`, and the profile's checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarError(pub String);

impl std::fmt::Display for StarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail(m: impl Into<String>) -> StarError {
    StarError(m.into())
}

pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    vlatproto::car::write_varint(out, n)
}

/// The archive's start: the magic and the commit as its metadata.
pub fn write_header(out: &mut Vec<u8>, commit: &Commit) {
    out.extend_from_slice(&MAGIC);
    let meta = commit.to_cbor(Some(REPO_STAR_TYPE));
    write_varint(out, meta.len() as u64);
    out.extend_from_slice(&meta);
}

/// One record's pair, after its control byte.
pub fn write_pair(out: &mut Vec<u8>, path: &[u8], record: &[u8]) {
    out.push(CONTROL_PAIR);
    write_varint(out, path.len() as u64);
    out.extend_from_slice(path);
    write_varint(out, record.len() as u64);
    out.extend_from_slice(record);
}

/// The end of the archive, after the last pair.
pub fn write_end(out: &mut Vec<u8>) {
    out.push(CONTROL_END);
}

/// A varint at the front of `b`: Ok(None) when `b` ends before it does.
/// Non-minimal encodings (a final zero byte after the first) and ones past
/// [`MAX_VARINT_BYTES`] are refused.
pub fn read_varint(b: &[u8]) -> Result<Option<(u64, usize)>, StarError> {
    let mut n = 0u64;
    for i in 0..MAX_VARINT_BYTES {
        let Some(&byte) = b.get(i) else { return Ok(None) };
        n |= ((byte & 0x7f) as u64) << (7 * i);
        if byte < 0x80 {
            if byte == 0 && i > 0 {
                return Err(fail("non-canonical varint"));
            }
            return Ok(Some((n, i + 1)));
        }
    }
    Err(fail("varint too long"))
}

/// The metadata as the commit it carries: a canonical DRISL map whose
/// `$type` is this profile's.
pub fn parse_meta(b: &[u8]) -> Result<Commit, StarError> {
    use vlatproto::cbor::ValueRef;
    let v = vlatproto::cbor::Value::decode(b).map_err(|e| fail(format!("invalid metadata: {e}")))?;
    if v.to_cbor() != b {
        return Err(fail("metadata is not canonical DRISL"));
    }
    let v = ValueRef::decode(b).map_err(|e| fail(format!("invalid metadata: {e}")))?;
    if !matches!(v, ValueRef::Map(_)) || !matches!(v.get("$type"), Some(ValueRef::Text(_))) {
        return Err(fail("metadata must be a map with a $type"));
    }
    if v.get("$type").and_then(|t| t.as_str()) != Some(REPO_STAR_TYPE) {
        return Err(fail(format!("invalid repo metadata: $type must be {REPO_STAR_TYPE}")));
    }
    let text = |k: &str| match v.get(k) {
        Some(ValueRef::Text(t)) => Ok(t.to_string()),
        _ => Err(fail(format!("invalid repo metadata: {k} must be a string"))),
    };
    let ver = match v.get("ver") {
        Some(ValueRef::Int(n)) => *n,
        _ => return Err(fail("invalid repo metadata: ver must be an integer")),
    };
    let data = match v.get("data") {
        Some(ValueRef::Bytes(b)) => b.to_vec(),
        _ => return Err(fail("invalid repo metadata: data must be bytes")),
    };
    let (repo, space) = (text("repo")?, text("space")?);
    if !vlatproto::syntax::valid_did(&repo) {
        return Err(fail("invalid repo metadata: repo must be a DID"));
    }
    if vlatproto::syntax::parse_space_uri(&space).is_none_or(|u| u.record.is_some()) {
        return Err(fail("invalid repo metadata: space must be a space URI"));
    }
    Ok(Commit { ver, repo, space, rev: text("rev")?, data })
}

/// What a whole archive in memory holds: its commit and its records as
/// (path, record bytes), checked as [`Archive::push`] checks them.
#[derive(Debug)]
pub struct Parsed {
    pub commit: Commit,
    pub records: Vec<(String, Vec<u8>)>,
}

/// A repo archive checked as it's read (the reference's `verifyRepoStar`
/// past the MAC): paths in strict order, each a record path, records
/// within [`MAX_RECORD_SIZE`] and DRISL maps, folded into a set hash that
/// must equal the commit's `data` at the end.
pub struct Archive {
    pub commit: Commit,
    pub set: LtHash,
    prev: Option<Vec<u8>>,
    pub records: u64,
}

impl Archive {
    pub fn new(commit: Commit) -> Archive {
        Archive { commit, set: LtHash::default(), prev: None, records: 0 }
    }

    /// The pair's path (`{collection}/{rkey}`, split) and record CID.
    pub fn push(&mut self, key: &[u8], value: &[u8]) -> Result<(String, vlatproto::cid::Cid), StarError> {
        let path = std::str::from_utf8(key).map_err(|_| fail("a record path isn't UTF-8"))?;
        if self.prev.as_deref().is_some_and(|p| key <= p) {
            return Err(fail(format!("records out of order at {path}")));
        }
        self.prev = Some(key.to_vec());
        let (collection, rkey) = path
            .split_once('/')
            .filter(|(c, r)| vlatproto::syntax::valid_nsid(c) && vlatproto::syntax::valid_rkey(r))
            .ok_or_else(|| fail(format!("invalid record path {path}")))?;
        if value.len() > MAX_RECORD_SIZE {
            return Err(fail(format!("record at {path} is over {MAX_RECORD_SIZE} bytes")));
        }
        match vlatproto::cbor::ValueRef::decode(value) {
            Ok(vlatproto::cbor::ValueRef::Map(_)) => {}
            Ok(_) => return Err(fail(format!("invalid record at {path}"))),
            Err(_) => return Err(fail(format!("invalid record cbor at {path}"))),
        }
        let cid = vlatproto::cid::Cid::dag_cbor(value);
        self.set.add(&super::commit::element(collection, rkey, &cid.to_string()));
        self.records += 1;
        Ok((path.to_string(), cid))
    }

    /// At EOF: the records are the repo the commit describes.
    pub fn finish(&self) -> Result<(), StarError> {
        match super::commit::matches(&self.set, &self.commit) {
            true => Ok(()),
            false => Err(fail("records do not match the commit data")),
        }
    }
}

/// Frame limits for [`read`], as @atproto/star's `ReadStarOptions`.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub meta: u64,
    pub key: u64,
    pub value: u64,
}

/// The repo profile's limits (`REPO_STAR_LIMITS`).
pub const REPO_LIMITS: Limits = Limits { meta: MAX_META_LENGTH, key: MAX_KEY_LENGTH, value: MAX_RECORD_SIZE as u64 };

/// A whole STAR archive in memory, framing only (@atproto/star `readStar`):
/// the metadata bytes and the pairs. Refuses EOF before the end byte, a
/// control byte other than `0x00`/`0x01`, bytes after the end, and a frame
/// over its limit (from its length, before it's read).
pub fn read(b: &[u8], limits: Limits) -> Result<(&[u8], Vec<(&[u8], &[u8])>), StarError> {
    fn frame<'a>(rest: &'a [u8], pos: &mut usize, max: u64) -> Result<&'a [u8], StarError> {
        let (len, n) = read_varint(&rest[*pos..])?.ok_or_else(|| fail("unexpected end of archive"))?;
        if len > max {
            return Err(fail(format!("length {len} exceeds limit of {max}")));
        }
        let start = *pos + n;
        let end = usize::try_from(len)
            .ok()
            .and_then(|l| start.checked_add(l))
            .filter(|e| *e <= rest.len())
            .ok_or_else(|| fail("unexpected end of archive"))?;
        *pos = end;
        Ok(&rest[start..end])
    }
    let rest = b.strip_prefix(&MAGIC[..]).ok_or_else(|| fail("invalid magic bytes"))?;
    let mut pos = 0;
    let meta = frame(rest, &mut pos, limits.meta)?;
    let mut pairs = Vec::new();
    loop {
        let control = *rest.get(pos).ok_or_else(|| fail("unexpected end of archive"))?;
        pos += 1;
        match control {
            CONTROL_END => break,
            CONTROL_PAIR => {
                let key = frame(rest, &mut pos, limits.key)?;
                let value = frame(rest, &mut pos, limits.value)?;
                pairs.push((key, value));
            }
            c => return Err(fail(format!("invalid control byte: {c}"))),
        }
    }
    if pos != rest.len() {
        return Err(fail("unexpected bytes after end of archive"));
    }
    Ok((meta, pairs))
}

/// A whole repo archive: the header, the pairs, the digest. Its commit's
/// MAC (and repo and space) are the caller's to check.
pub fn parse(b: &[u8]) -> Result<Parsed, StarError> {
    let (meta, pairs) = read(b, REPO_LIMITS)?;
    let mut a = Archive::new(parse_meta(meta)?);
    let mut records = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let (path, _) = a.push(key, value)?;
        records.push((path, value.to_vec()));
    }
    a.finish()?;
    Ok(Parsed { commit: a.commit, records })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;

    fn rec(text: &str) -> Vec<u8> {
        vlatproto::cbor::Value::from_json(&serde_json::json!({"$type": "a.b.c", "text": text})).unwrap().to_cbor()
    }

    fn archive(commit: &Commit, records: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        write_header(&mut out, commit);
        for (p, r) in records {
            write_pair(&mut out, p.as_bytes(), r);
        }
        write_end(&mut out);
        out
    }

    fn commit_over(records: &[(&str, Vec<u8>)]) -> Commit {
        let mut set = LtHash::default();
        for (p, r) in records {
            let (c, k) = p.split_once('/').unwrap();
            set.add(&crate::space::commit::element(c, k, &vlatproto::cid::Cid::dag_cbor(r).to_string()));
        }
        Commit::of(&set, "at://did:example:space/space/a.b.c/k", "did:example:alice", "3kbcq3p7ad400")
    }

    /// testdata/spaces-alpha/vectors.json `star`: archives the reference's
    /// `serializeRepo` wrote, byte for byte what this writes.
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["star"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            let bytes = hex::decode(c["archive"].as_str().unwrap()).unwrap();
            let p = parse(&bytes).unwrap();
            assert_eq!(p.commit, Commit::from_json(&c["commit"]).unwrap());
            let mut out = Vec::new();
            write_header(&mut out, &p.commit);
            for (path, r) in &p.records {
                write_pair(&mut out, path.as_bytes(), r);
            }
            write_end(&mut out);
            assert_eq!(out, bytes);
            assert_eq!(p.records.len() as u64, c["records"].as_u64().unwrap());
        }
    }

    #[test]
    fn round_trip_and_refusals() {
        let records = vec![("a.b.c/1", rec("one")), ("a.b.c/2", rec("two")), ("a.b.d/1", rec("three"))];
        let commit = commit_over(&records);
        let b = archive(&commit, &records);
        let p = parse(&b).unwrap();
        assert_eq!(p.commit, commit);
        assert_eq!(p.records.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(), ["a.b.c/1", "a.b.c/2", "a.b.d/1"]);

        // an empty repo has no pairs: the header, then the end byte
        let empty = commit_over(&[]);
        let e = archive(&empty, &[]);
        assert_eq!(e.last(), Some(&CONTROL_END));
        assert!(parse(&e).unwrap().records.is_empty());

        // out of order, a duplicate
        let mut swapped = records.clone();
        swapped.swap(0, 1);
        assert!(parse(&archive(&commit, &swapped)).unwrap_err().0.contains("out of order"));
        let dup = vec![records[0].clone(), records[0].clone()];
        assert!(parse(&archive(&commit_over(&dup[..1]), &dup)).unwrap_err().0.contains("out of order"));
        // a record missing, or one too many
        assert!(parse(&archive(&commit, &records[..2])).unwrap_err().0.contains("commit data"));
        // truncated anywhere past the header
        for cut in 1..8 {
            assert!(parse(&b[..b.len() - cut]).is_err(), "{cut}");
        }
        // oversized
        let big = vlatproto::cbor::Value::from_json(&serde_json::json!({"t": "x".repeat(MAX_RECORD_SIZE)}))
            .unwrap()
            .to_cbor();
        let e = parse(&archive(&commit_over(&[("a.b.c/1", big.clone())]), &[("a.b.c/1", big)])).unwrap_err();
        assert!(e.0.contains("exceeds limit"), "{e}");
        // bad magic, a bad path, a record that isn't a map
        assert!(parse(&b[1..]).is_err());
        assert!(parse(&archive(&commit, &[("no-slash", rec("x"))])).unwrap_err().0.contains("record path"));
        let five = vlatproto::cbor::Value::Int(5).to_cbor();
        assert!(parse(&archive(&commit, &[("a.b.c/1", five)])).unwrap_err().0.contains("invalid record"));
        // the metadata's $type
        let mut other = Vec::new();
        other.extend_from_slice(&MAGIC);
        let meta = commit.to_cbor(Some("other"));
        write_varint(&mut other, meta.len() as u64);
        other.extend_from_slice(&meta);
        write_end(&mut other);
        assert!(parse(&other).unwrap_err().0.contains("$type"));
        let mut none = Vec::new();
        none.extend_from_slice(&MAGIC);
        let meta = commit.to_cbor(None);
        write_varint(&mut none, meta.len() as u64);
        none.extend_from_slice(&meta);
        write_end(&mut none);
        assert!(parse(&none).is_err());
    }

    /// The November 5 framing: `0x01` before each pair, `0x00` to end, and
    /// nothing else (@atproto/star's messages).
    #[test]
    fn control_bytes() {
        let records = vec![("a.b.c/1", rec("one"))];
        let commit = commit_over(&records);
        let b = archive(&commit, &records);
        let mut header = Vec::new();
        write_header(&mut header, &commit);
        assert_eq!(b[header.len()], CONTROL_PAIR);
        assert_eq!(b.last(), Some(&CONTROL_END));
        let err = |b: &[u8]| parse(b).unwrap_err().0;
        // no end byte: truncated, not complete
        assert_eq!(err(&b[..b.len() - 1]), "unexpected end of archive");
        assert_eq!(err(&header), "unexpected end of archive");
        // the October 29 framing (no control bytes) reads as a bad one
        let mut old = header.clone();
        write_varint(&mut old, 7);
        old.extend_from_slice(b"a.b.c/1");
        assert!(err(&old).starts_with("invalid control byte"), "{}", err(&old));
        let mut two = b.clone();
        two[header.len()] = 2;
        assert_eq!(err(&two), "invalid control byte: 2");
        let mut trailing = b.clone();
        trailing.push(0);
        assert_eq!(err(&trailing), "unexpected bytes after end of archive");
    }

    /// The profile's limits: 64 KiB of metadata, 4 KiB keys, 1 MiB values.
    #[test]
    fn limits() {
        let commit = commit_over(&[]);
        let mut long_key = Vec::new();
        write_header(&mut long_key, &commit);
        write_pair(&mut long_key, &vec![b'a'; 4097], &rec("x"));
        write_end(&mut long_key);
        assert_eq!(parse(&long_key).unwrap_err().0, "length 4097 exceeds limit of 4096");
        let mut big_meta = MAGIC.to_vec();
        write_varint(&mut big_meta, (64 << 10) + 1);
        assert_eq!(parse(&big_meta).unwrap_err().0, "length 65537 exceeds limit of 65536");
        // generic STAR sets none
        let unlimited = Limits { meta: u64::MAX, key: u64::MAX, value: u64::MAX };
        assert_eq!(read(&long_key, unlimited).unwrap().1.len(), 1);
    }

    #[test]
    fn varints() {
        assert_eq!(read_varint(&[0]), Ok(Some((0, 1))));
        assert_eq!(read_varint(&[0x80, 0x01]), Ok(Some((128, 2))));
        assert_eq!(read_varint(&[0x80]), Ok(None));
        assert!(read_varint(&[0x81, 0x00]).is_err(), "a padding zero");
        assert_eq!(read_varint(&[0xff; 8]), Ok(None));
        assert!(read_varint(&[0xff; 10]).is_err());
        let mut b = Vec::new();
        write_varint(&mut b, MAX_RECORD_SIZE as u64);
        assert_eq!(read_varint(&b), Ok(Some((MAX_RECORD_SIZE as u64, b.len()))));
    }
}
