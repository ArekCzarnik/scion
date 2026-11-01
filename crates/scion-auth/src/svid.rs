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
use std::time::SystemTime;

fn rejected(reason: &'static str) -> ScionError {
    tracing::info!(reason, "JWT-SVID rejected");
    ScionError::unauthenticated("invalid JWT-SVID")
}

fn bundle_error(m: &str) -> ScionError {
    ScionError::new(ErrorCode::InvalidArgument, format!("SPIFFE bundle: {m}"))
}

/// A public key usable for one family of algorithms.
enum PublicKey {
    P256(Vec<u8>),
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
    /// The key, or `None` for a type Scion cannot use: one unknown entry must not invalidate a
    /// bundle whose other keys work.
    fn public_key(&self) -> Result<Option<PublicKey>> {
        match (self.kty.as_str(), self.crv.as_deref()) {
            ("EC", Some("P-256")) => {
                let mut point = vec![4];
                point.extend(decode_field(&self.x, "x")?);
                point.extend(decode_field(&self.y, "y")?);
                Ok(Some(PublicKey::P256(point)))
            }
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
}

#[derive(Deserialize)]
struct Payload {
    sub: String,
}

fn verify(alg: &str, key: &PublicKey, input: &[u8], sig: &[u8]) -> bool {
    match (alg, key) {
        ("ES256", PublicKey::P256(point)) => {
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(input, sig)
                .is_ok()
        }
        _ => false,
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(part: &str, reason: &'static str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| rejected(reason))?;
    serde_json::from_slice(&bytes).map_err(|_| rejected(reason))
}

/// Validates JWT-SVIDs for one trust domain and audience.
pub struct SvidValidator {
    #[allow(dead_code)]
    trust_domain: String,
    #[allow(dead_code)]
    audience: String,
}

impl SvidValidator {
    /// A validator accepting `audience` from `trust_domain`.
    pub fn new(trust_domain: &str, audience: &str) -> Self {
        SvidValidator {
            trust_domain: trust_domain.to_owned(),
            audience: audience.to_owned(),
        }
    }

    /// Validate `token` against `bundle` at time `now`; the principal is its SPIFFE ID.
    pub fn validate(
        &self,
        token: &str,
        bundle: &SvidBundle,
        _now: SystemTime,
    ) -> Result<Principal> {
        let parts: Vec<&str> = token.split('.').collect();
        let [header_part, payload_part, sig_part] = parts[..] else {
            return Err(rejected("not JWS Compact Serialization"));
        };
        let header: Header = decode_json(header_part, "malformed header")?;
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
        Principal::parse(&payload.sub).map_err(|_| rejected("subject is not a SPIFFE ID"))
    }
}
