//! JWT-SVID validation (SPEC 12.3a; the SPIFFE JWT-SVID standard).
//!
//! Tokens are verified with `ring` directly rather than through a JOSE library: the algorithm is
//! checked against a fixed list before any key is looked up, and the token header cannot steer
//! which verification runs. Every rejection gives the client the same error; the reason goes to
//! the server log. Tokens are never logged.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, UnparsedPublicKey};
use scion_core::{ErrorCode, Principal, Result, ScionError};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Tolerated clock skew when checking `exp`.
const EXP_LEEWAY_SECS: f64 = 30.0;

fn rejected(reason: &'static str) -> ScionError {
    tracing::info!(reason, "JWT-SVID rejected");
    ScionError::unauthenticated("invalid JWT-SVID")
}

fn bundle_error(m: &str) -> ScionError {
    ScionError::new(ErrorCode::InvalidArgument, format!("SPIFFE bundle: {m}"))
}

/// The `alg` values accepted, checked before anything else in the token is used. The JWT-SVID
/// standard also lists ES512, which `ring` cannot verify and SPIRE never issues.
const ALGORITHMS: [&str; 8] = [
    "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
];

/// A public key usable for one family of algorithms.
enum PublicKey {
    P256(Vec<u8>),
    P384(Vec<u8>),
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

struct BundleKey {
    kid: String,
    key: PublicKey,
}

#[derive(Deserialize)]
struct RawBundle {
    keys: Vec<RawKey>,
}

#[derive(Deserialize)]
struct RawKey {
    #[serde(rename = "use")]
    usage: Option<String>,
    kty: String,
    kid: Option<String>,
    crv: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

fn decode_field(field: &Option<String>, name: &str) -> Result<Vec<u8>> {
    let text = field
        .as_deref()
        .ok_or_else(|| bundle_error(&format!("key lacks {name}")))?;
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| bundle_error(&format!("key has an invalid {name}")))
}

impl RawKey {
    /// The uncompressed point `ring` expects: 0x04, then x and y.
    fn ec_point(&self) -> Result<Vec<u8>> {
        let mut point = vec![4];
        point.extend(decode_field(&self.x, "x")?);
        point.extend(decode_field(&self.y, "y")?);
        Ok(point)
    }

    /// The key, or `None` for a type Scion cannot use: one unknown entry must not invalidate a
    /// bundle whose other keys work.
    fn public_key(&self) -> Result<Option<PublicKey>> {
        match (self.kty.as_str(), self.crv.as_deref()) {
            ("EC", Some("P-256")) => Ok(Some(PublicKey::P256(self.ec_point()?))),
            ("EC", Some("P-384")) => Ok(Some(PublicKey::P384(self.ec_point()?))),
            ("RSA", _) => Ok(Some(PublicKey::Rsa {
                n: decode_field(&self.n, "n")?,
                e: decode_field(&self.e, "e")?,
            })),
            _ => Ok(None),
        }
    }
}

/// The JWT-SVID signing keys of a trust domain.
pub struct SvidBundle {
    keys: Vec<BundleKey>,
}

impl SvidBundle {
    /// Parse a SPIFFE bundle (a JWK set).
    pub fn parse(json: &[u8]) -> Result<Self> {
        let raw: RawBundle =
            serde_json::from_slice(json).map_err(|_| bundle_error("invalid JSON"))?;
        let mut keys = Vec::new();
        for key in raw.keys {
            if key.usage.as_deref() != Some("jwt-svid") {
                continue;
            }
            let kid = key
                .kid
                .clone()
                .ok_or_else(|| bundle_error("key lacks kid"))?;
            if let Some(public) = key.public_key()? {
                keys.push(BundleKey { kid, key: public });
            }
        }
        Ok(SvidBundle { keys })
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    typ: Option<String>,
    /// RFC 7515: a verifier must reject extensions it does not understand; Scion knows none.
    crit: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Payload {
    sub: String,
    aud: Audience,
    exp: f64,
}

/// RFC 7519 allows `aud` as a single string or as a list.
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    /// A token with a second audience could be replayed by that audience, so this accepts
    /// exactly one value.
    fn is_only(&self, audience: &str) -> bool {
        match self {
            Audience::One(a) => a == audience,
            Audience::Many(list) => matches!(&list[..], [a] if a == audience),
        }
    }
}

fn verify(alg: &str, key: &PublicKey, input: &[u8], sig: &[u8]) -> bool {
    let rsa = match alg {
        "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
        "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
        "RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
        "PS256" => &signature::RSA_PSS_2048_8192_SHA256,
        "PS384" => &signature::RSA_PSS_2048_8192_SHA384,
        "PS512" => &signature::RSA_PSS_2048_8192_SHA512,
        _ => {
            return match (alg, key) {
                ("ES256", PublicKey::P256(point)) => {
                    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                        .verify(input, sig)
                        .is_ok()
                }
                ("ES384", PublicKey::P384(point)) => {
                    UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, point)
                        .verify(input, sig)
                        .is_ok()
                }
                _ => false,
            };
        }
    };
    match key {
        PublicKey::Rsa { n, e } => signature::RsaPublicKeyComponents { n, e }
            .verify(rsa, input, sig)
            .is_ok(),
        _ => false,
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(part: &str, reason: &'static str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| rejected(reason))?;
    serde_json::from_slice(&bytes).map_err(|_| rejected(reason))
}

/// Validates JWT-SVIDs for one trust domain and audience.
pub struct SvidValidator {
    /// `spiffe://<trust domain>/`, the prefix of every accepted SPIFFE ID.
    id_prefix: String,
    audience: String,
}

impl SvidValidator {
    /// A validator accepting `audience` from `trust_domain`.
    pub fn new(trust_domain: &str, audience: &str) -> Self {
        SvidValidator {
            id_prefix: format!("spiffe://{trust_domain}/"),
            audience: audience.to_owned(),
        }
    }

    /// Validate `token` against `bundle` at time `now`; the principal is its SPIFFE ID.
    pub fn validate(&self, token: &str, bundle: &SvidBundle, now: SystemTime) -> Result<Principal> {
        let parts: Vec<&str> = token.split('.').collect();
        let [header_part, payload_part, sig_part] = parts[..] else {
            return Err(rejected("not JWS Compact Serialization"));
        };
        let header: Header = decode_json(header_part, "malformed header")?;
        if !ALGORITHMS.contains(&header.alg.as_str()) {
            return Err(rejected("algorithm not allowed"));
        }
        if header
            .typ
            .as_deref()
            .is_some_and(|t| t != "JWT" && t != "JOSE")
        {
            return Err(rejected("typ not allowed"));
        }
        if header.crit.is_some() {
            return Err(rejected("critical header extension"));
        }
        let sig = URL_SAFE_NO_PAD
            .decode(sig_part)
            .map_err(|_| rejected("malformed signature"))?;
        let input = format!("{header_part}.{payload_part}");
        let mut candidates = bundle
            .keys
            .iter()
            .filter(|k| header.kid.as_deref().is_none_or(|kid| kid == k.kid));
        if !candidates.any(|k| verify(&header.alg, &k.key, input.as_bytes(), &sig)) {
            return Err(rejected("signature does not verify"));
        }
        let payload: Payload = decode_json(payload_part, "malformed payload")?;
        let now_secs = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| rejected("clock before the epoch"))?
            .as_secs_f64();
        if now_secs >= payload.exp + EXP_LEEWAY_SECS {
            return Err(rejected("expired"));
        }
        if !payload.aud.is_only(&self.audience) {
            return Err(rejected("wrong audience"));
        }
        match Principal::parse(&payload.sub) {
            Ok(p @ Principal::Spiffe(_)) if payload.sub.starts_with(&self.id_prefix) => Ok(p),
            _ => Err(rejected("subject outside the trust domain")),
        }
    }
}
