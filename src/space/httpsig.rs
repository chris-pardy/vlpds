//! The RFC 9421 HTTP Message Signatures subset Spaces uses
//! (@atproto/space `http-signature.ts`), for space credential requests and,
//! through the shared helpers below, for MACs ([`super::mac`]).
//!
//! A request with a space credential carries one signature tagged
//! `atproto-space-credential` (the reference signs under the label `sig`;
//! a verifier finds it by its tag, under any label) by the P-256 did:key
//! the credential is bound to (its `cnf.kid`), covering exactly
//! `("authorization" "atproto-space-audience")`.
//!
//! No method, target or time is covered, so a signature may be replayed
//! with the same headers: the credential's expiry bounds that, and the
//! audience header pins it to one repo. The optional `alg` must be
//! `ecdsa-p256-sha256` and an optional `keyid` must be `cnf.kid`; other
//! parameters (`created`, say) are covered but not interpreted.
//! Signatures are raw r‖s (64 bytes); high-S is accepted, DER is not.

use super::sfv::{self, Bare, Member, Params};
use axum::http::HeaderMap;
use base64::Engine;
use std::borrow::Cow;

pub const LABEL: &str = "sig";
pub const TAG: &str = "atproto-space-credential";
pub const ALG: &str = "ecdsa-p256-sha256";
pub const AUDIENCE_HEADER: &str = "atproto-space-audience";

const COMPONENTS: &[&str] = &["\"authorization\"", "\"atproto-space-audience\""];

/// The reference's `SpaceSignatureError`; its XRPC error is
/// `BadSpaceSignature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigError(pub Cow<'static, str>);

impl SigError {
    pub const CODE: &str = "BadSpaceSignature";
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Far over what this subset needs (a did:key is ~57 bytes). The parser's
/// duplicate-key handling is a linear scan per key.
pub const MAX_FIELD: usize = 8 << 10;

const INVALID: SigError = SigError(Cow::Borrowed("invalid HTTP message signature"));

/// The signature base (RFC 9421 §2.5) over `components` (serialized, e.g.
/// `"authorization"`), whose values are given in order, under the
/// serialized `signature_params`.
pub fn base(components: &[&str], values: &[&str], signature_params: &str) -> Vec<u8> {
    let mut lines: Vec<String> = components.iter().zip(values).map(|(c, v)| format!("{c}: {}", v.trim())).collect();
    lines.push(format!("\"@signature-params\": {signature_params}"));
    lines.join("\n").into_bytes()
}

/// What a request's signature covers, joined into lines.
pub fn signature_base(authorization: &str, signature_params: &str, audience: &str) -> Vec<u8> {
    base(COMPONENTS, &[authorization, audience], signature_params)
}

/// The `Signature-Input` member the reference's client writes.
pub fn signature_input() -> String {
    format!("(\"authorization\" \"{AUDIENCE_HEADER}\");tag=\"{TAG}\"")
}

/// The four headers of a request with a space credential, signed by
/// `sign` (the credential's bound P-256 key, raw r‖s).
pub fn headers(credential: &str, audience: &str, sign: impl FnOnce(&[u8]) -> [u8; 64]) -> [(&'static str, String); 4] {
    let authorization = format!("Atproto-Space-Credential {credential}");
    let input = signature_input();
    let sig = sign(&signature_base(&authorization, &input, audience));
    [
        ("authorization", authorization),
        (AUDIENCE_HEADER, audience.to_string()),
        ("signature-input", format!("{LABEL}={input}")),
        ("signature", format!("{LABEL}=:{}:", base64::engine::general_purpose::STANDARD.encode(sig))),
    ]
}

/// Verifies a request's `atproto-space-credential` signature by
/// `credential_key`, the credential's `cnf.kid`.
pub fn verify(headers: &HeaderMap, credential_key: &str) -> Result<(), SigError> {
    let authorization = single(headers, "authorization")
        .filter(|a| !a.is_empty())
        .ok_or(SigError("missing or malformed \"authorization\" field".into()))?;
    let audience = single(headers, AUDIENCE_HEADER)
        .filter(|a| !a.is_empty())
        .ok_or(SigError("missing or malformed \"atproto-space-audience\" field".into()))?;
    let (input, sig) = (joined(headers, "signature-input"), joined(headers, "signature"));
    if input.as_ref().is_some_and(|f| f.len() > MAX_FIELD) || sig.as_ref().is_some_and(|f| f.len() > MAX_FIELD) {
        return Err(INVALID);
    }
    let req = Required { tag: TAG, components: COMPONENTS, alg: ALG, key_id: credential_key };
    let (params, sig) = find_signature(input.as_deref(), sig.as_deref(), &req).map_err(SigError)?;
    if super::did_key_alg(credential_key) != Some("ES256") {
        return Err(SigError("signature key must be a P-256 did:key".into()));
    }
    let base = signature_base(authorization, &params, audience);
    if sig.len() != 64 {
        return Err(INVALID);
    }
    match super::verify_did_key(credential_key, &base, &sig, true) {
        Ok(true) => Ok(()),
        _ => Err(INVALID),
    }
}

// ---- RFC 9421 helpers, shared with MACs ----

/// What an application requires of the signature it verifies (RFC 9421
/// §3.2.1).
pub struct Required<'a> {
    /// Identifies the signature among any others on the message.
    pub tag: &'a str,
    /// Exactly the components it must cover, in order, serialized.
    pub components: &'a [&'a str],
    /// What its `alg` and `keyid` must be, if it names them.
    pub alg: &'a str,
    pub key_id: &'a str,
}

/// The members of a `Signature-Input` or `Accept-Signature` dictionary
/// tagged `tag` (a string, not a token): (label, components, parameters).
pub fn members_with_tag<'a>(
    members: &'a sfv::Dictionary,
    tag: &str,
) -> Vec<(&'a str, &'a [(Bare, Params)], &'a Params)> {
    members
        .iter()
        .filter_map(|(label, m)| match m {
            Member::InnerList(items, params) if sfv::get(params, "tag") == Some(&Bare::String(tag.into())) => {
                Some((label.as_str(), &items[..], params))
            }
            _ => None,
        })
        .collect()
}

/// Whether `items` are exactly `expected`, each with its parameters.
pub fn covers_exactly(items: &[(Bare, Params)], expected: &[&str]) -> bool {
    items.len() == expected.len() && items.iter().zip(expected).all(|((b, p), e)| sfv::serialize_item(b, p) == *e)
}

/// The reference's `findSignature`: the one signature tagged `req.tag` in a
/// message's `Signature-Input` and `Signature` fields, checked against
/// `req`. Labels carry no meaning (RFC 9421 §7.2.5). Returns its serialized
/// parameters and its bytes.
pub fn find_signature(
    input: Option<&str>,
    signature: Option<&str>,
    req: &Required,
) -> Result<(String, Vec<u8>), Cow<'static, str>> {
    const MALFORMED: &str = "missing or malformed signature headers";
    let (Some(input), Some(signature)) = (input, signature) else { return Err(MALFORMED.into()) };
    let inputs = sfv::parse_dictionary(input).map_err(|_| MALFORMED)?;
    let sigs = sfv::parse_dictionary(signature).map_err(|_| MALFORMED)?;
    let tag = req.tag;
    let tagged = members_with_tag(&inputs, tag);
    if tagged.len() > 1 {
        return Err(format!("more than one signature with tag \"{tag}\"").into());
    }
    let found = tagged.first().and_then(|(label, items, params)| match sfv::get(&sigs, label) {
        Some(Member::Item(Bare::Bytes(b), p)) if p.is_empty() => B64.decode(b).ok().map(|s| (*items, *params, s)),
        _ => None,
    });
    let Some((items, params, sig)) = found else {
        return Err(format!("missing or malformed signature with tag \"{tag}\"").into());
    };
    if !covers_exactly(items, req.components) {
        return Err(format!("signature must cover exactly ({}), in order", req.components.join(" ")).into());
    }
    if sfv::get(params, "alg").is_some_and(|a| *a != Bare::String(req.alg.into())) {
        return Err(format!("signature algorithm must be {}", req.alg).into());
    }
    if sfv::get(params, "keyid").is_some_and(|k| *k != Bare::String(req.key_id.into())) {
        return Err("signature keyid does not match the expected key".into());
    }
    Ok((sfv::serialize_inner_list(items, params), sig))
}

/// Standard base64, `=` padding optional and unused bits ignored, as the
/// reference decodes a byte sequence (`Uint8Array.fromBase64`, "loose").
pub const B64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Exactly one field line, as text.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut v = headers.get_all(name).iter();
    let first = v.next()?.to_str().ok()?;
    v.next().is_none().then_some(first)
}

/// Every field line, combined with ", " (RFC 9110 §5.3, as Node joins a
/// repeated header). None when absent or not visible ASCII.
pub fn joined(headers: &HeaderMap, name: &str) -> Option<String> {
    let lines: Vec<&str> = headers.get_all(name).iter().map(|v| v.to_str().ok()).collect::<Option<_>>()?;
    (!lines.is_empty()).then(|| lines.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;
    use p256::ecdsa::signature::Signer;

    const AUTHORIZATION: &str = "Atproto-Space-Credential credential";
    const AUDIENCE: &str = "did:example:repo";
    const INPUT: &str = "(\"authorization\" \"atproto-space-audience\");tag=\"atproto-space-credential\"";

    fn key() -> (p256::ecdsa::SigningKey, String) {
        let sk = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
        let mut mk = vec![0x80, 0x24];
        mk.extend_from_slice(sk.verifying_key().to_sec1_point(true).as_bytes());
        (sk, format!("did:key:z{}", bs58::encode(mk).into_string()))
    }

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    fn sign(sk: &p256::ecdsa::SigningKey, base: &[u8]) -> String {
        let sig: p256::ecdsa::Signature = sk.sign(base);
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    }

    /// The reference client's headers (`createSpaceSigHeaders`).
    fn signed(sk: &p256::ecdsa::SigningKey) -> Vec<(String, String)> {
        let sig = sign(sk, &signature_base(AUTHORIZATION, INPUT, AUDIENCE));
        vec![
            ("authorization".into(), AUTHORIZATION.into()),
            (AUDIENCE_HEADER.into(), AUDIENCE.into()),
            ("signature-input".into(), format!("{LABEL}={INPUT}")),
            ("signature".into(), format!("{LABEL}=:{sig}:")),
        ]
    }

    fn to_map(h: &[(String, String)]) -> HeaderMap {
        hm(&h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>())
    }

    fn set(h: &mut [(String, String)], name: &str, value: String) {
        h.iter_mut().find(|(k, _)| k == name).unwrap().1 = value;
    }

    fn get(h: &[(String, String)], name: &str) -> String {
        h.iter().find(|(k, _)| k == name).unwrap().1.clone()
    }

    /// testdata/spaces-alpha/vectors.json `httpsig`: headers the reference
    /// signed.
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["httpsig"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            let pairs: Vec<(String, String)> = c["headers"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect();
            let key = c["keyDid"].as_str().unwrap();
            assert_eq!(verify(&to_map(&pairs), key), Ok(()), "{c}");
            let (_, other) = self::key();
            assert!(verify(&to_map(&pairs), &other).is_err());
        }
    }

    #[test]
    fn helper_headers_verify() {
        let (sk, did) = key();
        let h = headers("tok", AUDIENCE, |b| {
            let sig: p256::ecdsa::Signature = sk.sign(b);
            sig.to_bytes().into()
        });
        let pairs: Vec<(String, String)> = h.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        assert_eq!(get(&pairs, "authorization"), "Atproto-Space-Credential tok");
        assert_eq!(verify(&to_map(&pairs), &did), Ok(()));
    }

    // The cases below are the reference's src/http-signature.test.ts.

    #[test]
    fn signs_and_verifies() {
        let (sk, did) = key();
        let h = signed(&sk);
        assert_eq!(signature_input(), INPUT);
        let base = format!(
            "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {INPUT}"
        );
        assert_eq!(signature_base(AUTHORIZATION, INPUT, AUDIENCE), base.as_bytes());
        assert_eq!(verify(&to_map(&h), &did), Ok(()));
    }

    #[test]
    fn tag_required() {
        let (sk, did) = key();
        for tag in ["", ";tag=\"other\"", ";tag=atproto-space-credential"] {
            let mut h = signed(&sk);
            set(
                &mut h,
                "signature-input",
                format!("{LABEL}={}", INPUT.replace(";tag=\"atproto-space-credential\"", tag)),
            );
            let e = verify(&to_map(&h), &did).unwrap_err().0;
            assert!(e.contains("missing or malformed signature with tag \"atproto-space-credential\""), "{tag}: {e}");
        }
    }

    #[test]
    fn signs_under_the_sig_label() {
        let (sk, _) = key();
        let h = headers("tok", AUDIENCE, |b| {
            let sig: p256::ecdsa::Signature = sk.sign(b);
            sig.to_bytes().into()
        });
        assert!(h[2].1.starts_with("sig=") && h[3].1.starts_with("sig="), "{h:?}");
    }

    /// The Nov 5 alpha's label, or any other: the tag finds it.
    #[test]
    fn any_label() {
        let (sk, did) = key();
        let mut h = signed(&sk);
        set(&mut h, "signature-input", format!("atproto-space-credential={INPUT}"));
        let sig = get(&h, "signature").replacen(LABEL, "atproto-space-credential", 1);
        set(&mut h, "signature", sig);
        assert_eq!(verify(&to_map(&h), &did), Ok(()));
    }

    #[test]
    fn more_than_one_with_the_tag() {
        let (sk, did) = key();
        let mut h = signed(&sk);
        for name in ["signature-input", "signature"] {
            let v = get(&h, name);
            set(&mut h, name, format!("{v}, {}", v.replacen("sig=", "other=", 1)));
        }
        let e = verify(&to_map(&h), &did).unwrap_err().0;
        assert!(e.contains("more than one signature with tag \"atproto-space-credential\""), "{e}");
    }

    #[test]
    fn high_s_accepted_der_refused() {
        let (sk, did) = key();
        let mut h = signed(&sk);
        let prefix = format!("{LABEL}=:");
        let b64 = get(&h, "signature").trim_start_matches(&prefix).trim_end_matches(':').to_string();
        let sig = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
        let n = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
        let mut high = sig[..32].to_vec();
        high.extend(crate::space::commit::tests::sub_be(&n, &sig[32..]));
        let enc = base64::engine::general_purpose::STANDARD.encode(&high);
        set(&mut h, "signature", format!("{LABEL}=:{enc}:"));
        assert_eq!(verify(&to_map(&h), &did), Ok(()));

        let der = p256::ecdsa::Signature::from_slice(&sig).unwrap().to_der();
        set(
            &mut h,
            "signature",
            format!("{LABEL}=:{}:", base64::engine::general_purpose::STANDARD.encode(der.as_bytes())),
        );
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));

        // unpadded base64
        set(&mut h, "signature", format!("{LABEL}=:{}:", b64.trim_end_matches('=')));
        assert_eq!(verify(&to_map(&h), &did), Ok(()));
    }

    #[test]
    fn found_by_tag_under_any_label_with_optional_parameters() {
        let (sk, did) = key();
        let input = format!(
            "(\"authorization\" \"atproto-space-audience\");alg=\"ecdsa-p256-sha256\";created=1618884473;keyid=\"{did}\";tag=\"atproto-space-credential\""
        );
        let base = format!("\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {input}");
        let sig = sign(&sk, base.as_bytes());
        let h = hm(&[
            ("authorization", AUTHORIZATION),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", &format!("other=(\"authorization\");keyid=\"other\", custom={input}")),
            ("signature", &format!("other=:YWJj:, custom=:{sig}:")),
        ]);
        assert_eq!(verify(&h, &did), Ok(()));
        // the same members split over two field lines
        let h = hm(&[
            ("authorization", AUTHORIZATION),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", "other=(\"authorization\");keyid=\"other\""),
            ("signature-input", &format!("{LABEL}={input}")),
            ("signature", "other=:YWJj:"),
            ("signature", &format!("{LABEL}=:{sig}:")),
        ]);
        assert_eq!(verify(&h, &did), Ok(()));
    }

    #[test]
    fn covered_fields_are_bound() {
        let (sk, did) = key();
        for name in ["authorization", AUDIENCE_HEADER] {
            let mut h = signed(&sk);
            let v = get(&h, name);
            set(&mut h, name, format!("{v}-changed"));
            assert_eq!(verify(&to_map(&h), &did), Err(INVALID), "{name}");

            let mut m = to_map(&signed(&sk));
            m.append(axum::http::HeaderName::from_static(name), v.parse().unwrap());
            assert!(verify(&m, &did).unwrap_err().0.contains("malformed"), "{name}");
        }
        for name in ["authorization", AUDIENCE_HEADER, "signature-input", "signature"] {
            let mut m = to_map(&signed(&sk));
            m.remove(name);
            assert!(verify(&m, &did).is_err(), "{name}");
        }
        // whitespace around a covered value is not part of the base
        let mut m = to_map(&signed(&sk));
        m.insert("authorization", format!("{AUTHORIZATION} ").parse().unwrap());
        assert_eq!(verify(&m, &did), Ok(()));
        // an audience the signature doesn't cover
        let input = "(\"authorization\");tag=\"atproto-space-credential\"";
        let sig = sign(&sk, format!("\"authorization\": {AUTHORIZATION}\n\"@signature-params\": {input}").as_bytes());
        let h = hm(&[
            ("authorization", AUTHORIZATION),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", &format!("{LABEL}={input}")),
            ("signature", &format!("{LABEL}=:{sig}:")),
        ]);
        assert!(verify(&h, &did).unwrap_err().0.contains("must cover"));
    }

    #[test]
    fn keys() {
        let (sk, did) = key();
        let (other_sk, other) = key();
        assert_eq!(verify(&to_map(&signed(&other_sk)), &did), Err(INVALID));

        let mut h = signed(&sk);
        let v = get(&h, "signature-input");
        set(&mut h, "signature-input", format!("{v};keyid=\"{other}\""));
        assert!(verify(&to_map(&h), &did).unwrap_err().0.contains("keyid does not match"));

        let k256 = vlatproto::crypto::Keypair::generate().did_key();
        assert!(verify(&to_map(&signed(&sk)), &k256).unwrap_err().0.contains("P-256"));
    }

    #[test]
    fn components_and_params() {
        let (sk, did) = key();
        for components in [
            "(\"atproto-space-audience\")",
            "(\"atproto-space-audience\" \"authorization\")",
            "(\"authorization\" \"atproto-space-audience\" \"content-type\")",
            "(\"authorization\" \"authorization\" \"atproto-space-audience\")",
            "(\"authorization\";sf \"atproto-space-audience\")",
            "(authorization atproto-space-audience)",
        ] {
            let mut h = signed(&sk);
            set(&mut h, "signature-input", format!("{LABEL}={components};tag=\"atproto-space-credential\""));
            let e = verify(&to_map(&h), &did).unwrap_err().0;
            assert!(e.contains("must cover exactly"), "{components}: {e}");
        }
        let mut h = signed(&sk);
        set(&mut h, "signature-input", format!("{LABEL}=not-a-list"));
        assert!(verify(&to_map(&h), &did).unwrap_err().0.contains("missing or malformed"));
        // parameters are signed
        let mut h = signed(&sk);
        let v = get(&h, "signature-input");
        set(&mut h, "signature-input", format!("{v};alg=\"ecdsa-p256-sha256\""));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
        for alg in [";alg=\"ecdsa-p384-sha384\"", ";alg=ecdsa-p256-sha256", ";alg"] {
            let mut h = signed(&sk);
            set(&mut h, "signature-input", format!("{v}{alg}"));
            let e = verify(&to_map(&h), &did).unwrap_err().0;
            assert!(e.contains("algorithm"), "{alg}: {e}");
        }
    }

    #[test]
    fn signature_values() {
        let (sk, did) = key();
        for signature in ["not-a-byte-sequence", ":YWJj:", ":!!!:", "(:YWJj:)"] {
            let mut h = signed(&sk);
            set(&mut h, "signature", format!("{LABEL}={signature}"));
            assert!(verify(&to_map(&h), &did).is_err(), "{signature}");
        }
        let mut h = signed(&sk);
        let v = get(&h, "signature");
        set(&mut h, "signature", format!("{v};x=1"));
        assert!(verify(&to_map(&h), &did).unwrap_err().0.contains("missing or malformed signature with tag"));
        // oversized fields are refused before parsing
        let mut h = signed(&sk);
        let input = get(&h, "signature-input");
        let pad: String = (0..2000).map(|i| format!("k{i}=1, ")).collect();
        set(&mut h, "signature-input", format!("{pad}{input}"));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
        // a later member with the same label replaces the first
        let mut h = signed(&sk);
        set(&mut h, "signature", format!("{v}, {LABEL}=:YWJj:"));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
    }
}
