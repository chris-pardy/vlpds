//! RFC 8941 structured fields, as the `structured-headers` 1.0.1 package
//! the reference verifies with parses and re-serializes them. The signature
//! base re-serializes the parsed `Signature-Input` member, so its quirks
//! are part of the wire: integers and decimals are one JS number (`1.0`
//! comes back as `1`), byte sequences keep their base64 text, a parameter
//! true is written bare, and a repeated key keeps its first position with
//! its last value.

#[derive(Debug, Clone, PartialEq)]
pub enum Bare {
    Number(f64),
    String(String),
    Token(String),
    /// The base64 text as written.
    Bytes(String),
    Bool(bool),
}

pub type Params = Vec<(String, Bare)>;

#[derive(Debug, Clone, PartialEq)]
pub enum Member {
    Item(Bare, Params),
    InnerList(Vec<(Bare, Params)>, Params),
}

pub type Dictionary = Vec<(String, Member)>;

pub fn get<'a, T>(map: &'a [(String, T)], key: &str) -> Option<&'a T> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn set<T>(map: &mut Vec<(String, T)>, key: String, v: T) {
    match map.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = v,
        None => map.push((key, v)),
    }
}

pub fn parse_dictionary(input: &str) -> Result<Dictionary, &'static str> {
    let mut p = Parser { s: input.as_bytes(), pos: 0 };
    p.skip_ws();
    let mut dict = Vec::new();
    while !p.eof() {
        let key = p.key()?;
        let member = if p.look() == Some(b'=') {
            p.pos += 1;
            p.item_or_inner_list()?
        } else {
            Member::Item(Bare::Bool(true), p.params()?)
        };
        set(&mut dict, key, member);
        p.skip_ows();
        if p.eof() {
            break;
        }
        p.expect(b',')?;
        p.skip_ows();
        if p.eof() {
            return Err("trailing comma");
        }
    }
    Ok(dict)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn eof(&self) -> bool {
        self.pos >= self.s.len()
    }

    fn look(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.look();
        self.pos += 1;
        c
    }

    fn expect(&mut self, c: u8) -> Result<(), &'static str> {
        if self.look() != Some(c) {
            return Err("unexpected character");
        }
        self.pos += 1;
        Ok(())
    }

    fn skip_ws(&mut self) {
        while self.look() == Some(b' ') {
            self.pos += 1;
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.look(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn item_or_inner_list(&mut self) -> Result<Member, &'static str> {
        if self.look() != Some(b'(') {
            let (b, p) = self.item()?;
            return Ok(Member::Item(b, p));
        }
        self.pos += 1;
        let mut items = Vec::new();
        while !self.eof() {
            self.skip_ws();
            if self.look() == Some(b')') {
                self.pos += 1;
                return Ok(Member::InnerList(items, self.params()?));
            }
            items.push(self.item()?);
            if !matches!(self.look(), Some(b' ' | b')')) {
                return Err("expected a space or ) after an inner list item");
            }
        }
        Err("unterminated inner list")
    }

    fn item(&mut self) -> Result<(Bare, Params), &'static str> {
        Ok((self.bare()?, self.params()?))
    }

    fn params(&mut self) -> Result<Params, &'static str> {
        let mut params = Vec::new();
        while self.look() == Some(b';') {
            self.pos += 1;
            self.skip_ws();
            let key = self.key()?;
            let value = if self.look() == Some(b'=') {
                self.pos += 1;
                self.bare()?
            } else {
                Bare::Bool(true)
            };
            set(&mut params, key, value);
        }
        Ok(params)
    }

    fn key(&mut self) -> Result<String, &'static str> {
        if !matches!(self.look(), Some(b'a'..=b'z' | b'*')) {
            return Err("a key must start with a-z or *");
        }
        let start = self.pos;
        while matches!(self.look(), Some(b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')) {
            self.pos += 1;
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.pos]).into_owned())
    }

    fn bare(&mut self) -> Result<Bare, &'static str> {
        match self.look().ok_or("unexpected end of input")? {
            b'-' | b'0'..=b'9' => self.number(),
            b'"' => self.string(),
            b'A'..=b'Z' | b'a'..=b'z' | b'*' => Ok(self.token()),
            b':' => self.bytes(),
            b'?' => {
                self.pos += 1;
                match self.next() {
                    Some(b'1') => Ok(Bare::Bool(true)),
                    Some(b'0') => Ok(Bare::Bool(false)),
                    _ => Err("bad boolean"),
                }
            }
            _ => Err("unexpected input"),
        }
    }

    fn number(&mut self) -> Result<Bare, &'static str> {
        let negative = self.look() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        if !matches!(self.look(), Some(b'0'..=b'9')) {
            return Err("expected a digit");
        }
        let mut n = String::new();
        let mut decimal = false;
        while let Some(c) = self.look() {
            match c {
                b'0'..=b'9' => n.push(c as char),
                b'.' if !decimal => {
                    if n.len() > 12 {
                        return Err("decimal too long");
                    }
                    n.push('.');
                    decimal = true;
                }
                _ => break,
            }
            self.pos += 1;
            if (!decimal && n.len() > 15) || (decimal && n.len() > 16) {
                return Err("number too long");
            }
        }
        if decimal && (n.ends_with('.') || n.split('.').nth(1).is_some_and(|f| f.len() > 3)) {
            return Err("bad decimal");
        }
        let v: f64 = n.parse().map_err(|_| "bad number")?;
        Ok(Bare::Number(if negative { -v } else { v }))
    }

    fn string(&mut self) -> Result<Bare, &'static str> {
        self.pos += 1;
        let mut out = String::new();
        while let Some(c) = self.next() {
            match c {
                b'\\' => match self.next() {
                    Some(e @ (b'\\' | b'"')) => out.push(e as char),
                    _ => return Err("bad escape"),
                },
                b'"' => return Ok(Bare::String(out)),
                0x20..=0x7e => out.push(c as char),
                _ => return Err("strings must be printable ASCII"),
            }
        }
        Err("unterminated string")
    }

    fn token(&mut self) -> Bare {
        let start = self.pos;
        while self.look().is_some_and(|c| c.is_ascii_alphanumeric() || b":/!#$%&'*+-.^_`|~".contains(&c)) {
            self.pos += 1;
        }
        Bare::Token(String::from_utf8_lossy(&self.s[start..self.pos]).into_owned())
    }

    fn bytes(&mut self) -> Result<Bare, &'static str> {
        self.pos += 1;
        let len = self.s[self.pos..].iter().position(|&c| c == b':').ok_or("unterminated byte sequence")?;
        let b64 = &self.s[self.pos..self.pos + len];
        self.pos += len + 1;
        if !b64.iter().all(|&c| c.is_ascii_alphanumeric() || b"+/=".contains(&c)) {
            return Err("bad byte sequence");
        }
        Ok(Bare::Bytes(String::from_utf8_lossy(b64).into_owned()))
    }
}

pub fn serialize_inner_list(items: &[(Bare, Params)], params: &Params) -> String {
    let items: Vec<String> = items.iter().map(|(b, p)| serialize_item(b, p)).collect();
    format!("({}){}", items.join(" "), serialize_params(params))
}

/// A bare `true` member is written as its key alone, as structured-headers
/// does.
pub fn serialize_dictionary(d: &Dictionary) -> String {
    let members: Vec<String> = d
        .iter()
        .map(|(k, m)| match m {
            Member::Item(Bare::Bool(true), p) => format!("{k}{}", serialize_params(p)),
            Member::Item(b, p) => format!("{k}={}", serialize_item(b, p)),
            Member::InnerList(i, p) => format!("{k}={}", serialize_inner_list(i, p)),
        })
        .collect();
    members.join(", ")
}

pub fn serialize_item(b: &Bare, p: &Params) -> String {
    serialize_bare(b) + &serialize_params(p)
}

fn serialize_params(p: &Params) -> String {
    p.iter()
        .map(|(k, v)| match v {
            Bare::Bool(true) => format!(";{k}"),
            v => format!(";{k}={}", serialize_bare(v)),
        })
        .collect()
}

fn serialize_bare(b: &Bare) -> String {
    match b {
        // parsed numbers have at most 15 digits, so an integral one is exact
        Bare::Number(n) if n.fract() == 0.0 => format!("{}", *n as i64),
        Bare::Number(n) => {
            let s = format!("{n:.3}");
            s.trim_end_matches('0').to_string()
        }
        Bare::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Bare::Token(t) => t.clone(),
        Bare::Bytes(b) => format!(":{b}:"),
        Bare::Bool(true) => "?1".into(),
        Bare::Bool(false) => "?0".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner(s: &str) -> String {
        match parse_dictionary(&format!("a={s}")).unwrap().remove(0).1 {
            Member::InnerList(i, p) => serialize_inner_list(&i, &p),
            m => panic!("{m:?}"),
        }
    }

    #[test]
    fn reserializes_like_structured_headers() {
        assert_eq!(
            inner(r#"("authorization" "atproto-space-audience")"#),
            r#"("authorization" "atproto-space-audience")"#
        );
        assert_eq!(inner(r#"(  "a"   "b" );keyid="k";alg="x""#), r#"("a" "b");keyid="k";alg="x""#);
        assert_eq!(inner(r#"("a");x=1.0;y=1.50;z=-0;w=007;v=-1.025"#), r#"("a");x=1;y=1.5;z=0;w=7;v=-1.025"#);
        assert_eq!(inner(r#"("a");f=?1;g=?0;t=tok/en;b=:YWJj:"#), r#"("a");f;g=?0;t=tok/en;b=:YWJj:"#);
        assert_eq!(inner(r#"("a");k="1";j=2;k="3""#), r#"("a");k="3";j=2"#);
        assert_eq!(inner(r#"("a\"b\\c";p);q"#), r#"("a\"b\\c";p);q"#);
        assert_eq!(inner("()"), "()");
        assert_eq!(inner("(); keyid=\"k\""), "();keyid=\"k\"");
    }

    #[test]
    fn dictionaries() {
        let d = parse_dictionary(r#"other=("authorization");keyid="other",	atproto-space=:YWJj:, flag;p=1"#).unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(get(&d, "atproto-space"), Some(&Member::Item(Bare::Bytes("YWJj".into()), vec![])));
        assert_eq!(get(&d, "flag"), Some(&Member::Item(Bare::Bool(true), vec![("p".into(), Bare::Number(1.0))])));
        // a repeated key keeps its first position and its last value
        let d = parse_dictionary("a=1, b=2, a=3").unwrap();
        assert_eq!(
            d,
            vec![
                ("a".into(), Member::Item(Bare::Number(3.0), vec![])),
                ("b".into(), Member::Item(Bare::Number(2.0), vec![]))
            ]
        );
        assert_eq!(parse_dictionary("").unwrap(), vec![]);
        let d = parse_dictionary("a=1,   b=\"x\";p, c, d=(1 2);q=?0, e=:YWJj:, f=?1, g=?0").unwrap();
        assert_eq!(serialize_dictionary(&d), "a=1, b=\"x\";p, c, d=(1 2);q=?0, e=:YWJj:, f, g=?0");
        for bad in [
            "a=1,",
            "A=1",
            "a=(\"x\"",
            "a=(\"x\"\"y\")",
            "a=\"unterminated",
            "a=\"bad\\escape\"",
            "a=:abc",
            "a=:a b:",
            "a=?2",
            "a=1.",
            "a=1.2345",
            "a=1234567890123456",
            "a=1234567890123.1",
            "a=-",
            "a=1 b=2",
            "a=@",
            "a=1;",
        ] {
            assert!(parse_dictionary(bad).is_err(), "{bad}");
        }
        assert!(parse_dictionary("a=123456789012345").is_ok());
        assert!(parse_dictionary("a=123456789012.123").is_ok());
    }
}
