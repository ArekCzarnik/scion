//! Fake SPIFFE issuer for JWT-SVID tests. It holds one key per algorithm family and signs any
//! header and payload, so tests can build valid tokens and deliberately malformed ones.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test infrastructure

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use ring::rand::SystemRandom;
use ring::rsa::PublicKeyComponents;
use ring::signature::{self, EcdsaKeyPair, KeyPair, RsaKeyPair};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::task::AbortHandle;

/// Key id of the P-256 key.
const KID_P256: &str = "fake-p256";
/// Key id of the P-384 key.
const KID_P384: &str = "fake-p384";
/// Key id of the RSA key.
const KID_RSA: &str = "fake-rsa";

/// A throwaway RSA-2048 PKCS#8 key: `ring` cannot generate RSA keys, and it protects nothing.
const RSA_PKCS8_BASE64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZHe46tjwTzNZtRgxa9jdSxCx8UsejE2/QIaMGQ1eNAaMLDvvlMTi9r39e7q9dG7Zg7U0gNZlh4pOmejoUaSzH9zwpPvRu500CchirH8ku5bzclmt0VQ0bUFd9V9Lb87ZWU8AFJQjBIV1x/Vv1OA2ELcY8Fck8dEq6wJgZ6YvlRfsVueZK96mqZ//zLb3KT+g6QBwcSZgEPa832+VcdBWS2eG/M4msj/VGGVWZTKWk7Mf22FwljrIhoMWh6ktrSn8dDP8L/cHWR5Jyv14vpKlo9tx3HLagL70l+PBMGirgRv0AE68SKQDo3gtIo5yBvhaRRrJoPGxc8JHKdw3jITtfAgMBAAECggEAIOiZ+tkzWvbxy2dSKRlnwkpMyd1MOCoSiRQIH0Nmyk8ktODlClS/GnU2059PAkhYiPF+/rJRGNacdZ/SHNTiPj75pfDOYN77O7MqjQmI12xoB3FfQSdBENJJKIz+v2r9yLDyCnWWEZvqi4QRA6am2dGMWgAdW+Xui8b0Zv0QwMPmsviJDax5faXlURyDm2BazgOElB83g5e5QYuwOMbKL3xXzMcBm+ku8gndPG+sCIOvnjqrvmz5nAmZy/5bOqkbV6v5CqyFh5PotSsjNhAgVNJTHinDWlPdwq6b73UmXzCuDDzykDIGSIXNhsAVO1IhTl42P9Iz6jbC1xJTWHpPUQKBgQDwRBBo6mz4e/OBdDP/d0VLHw1yDd1cMbQUM9W+04faD7N93EVmpwonjJYWnP7uixrxzwo6mX9TootdWlzROMUdiVrYZgKLMt7faASziPxgQOXgPfu6Dq19AG1CvYVn2OKEAytE2czEkmNhQ3OqdLy4g/lQUsth2XvvEzWRCHNYkQKBgQDnVckwG/AIqMTZpjDqEvmMYk5DV0VXVpjJ7PJ65fuhwM6oNAmp31kEQ5nDXYqWiK64OWZMgWkrKNWTbmYoSFc5e30LJYJkV19Ce8DoCIP2txfupFdCvdR1gUuK+FTuNoOcdt782wo0uJ1GGm7XTXaPOUsmoNpjbUmlxikIZf7M7wKBgBC3q6yhIxPnC/pl63hLBDdF4dmdvVk83BrLwIOWlE1H6mVHfky2Mq6tyYOpSNOwOh+5GC0boRBgrvG/59Vm7dAwTnHgJy0oTPmeczVKwsSvv07rASjg/JFGBlQue6nOHXSyA8C2ptjGlsOdvd6OYNM125MLL7uPNmBcJc4BmIUBAoGBAIxKOfgy+R5HOxnC72cEmtHHzC6KfkK5AW9zgpmFX1R42NqotDOQfytW06jm0WT4/vw50xASavUBjoQaL1m+hScW/H4GAU1YryxiYFpWz7CO2LSgdUrEVFPuVSGx989+v9HjRNeS/l16l+YroYxwLbYtyKVkZwxk+oTN55RwRlWBAoGAUU+IYla0AYIOnxmC+91Fbcm40bXbtTPQs0rtqKDn3vNCaR/2c0JOpnx7NAnHpWx2dSU/hvs/ZXBIxxYu8UNQU5uvx/8uczPstkdq15PVc4uXd7zk204opoyYPrcgSuhej8bc9cqA8qXaGog4sY6hWsd1tyj4nFTJhlk3OhcccTs=";

/// Signs JWT-SVIDs with fresh P-256 and P-384 keys and a fixed RSA test key.
pub struct SvidIssuer {
    rng: SystemRandom,
    p256: EcdsaKeyPair,
    p384: EcdsaKeyPair,
    rsa: RsaKeyPair,
}

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn ec_key(alg: &'static signature::EcdsaSigningAlgorithm, rng: &SystemRandom) -> EcdsaKeyPair {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, rng).unwrap();
    EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), rng).unwrap()
}

fn ec_jwk(key: &EcdsaKeyPair, crv: &str, kid: &str) -> Value {
    // The public key is the uncompressed point: 0x04, then x and y of equal length.
    let point = &key.public_key().as_ref()[1..];
    let (x, y) = point.split_at(point.len() / 2);
    json!({"use": "jwt-svid", "kty": "EC", "kid": kid, "crv": crv, "x": b64(x), "y": b64(y)})
}

impl Default for SvidIssuer {
    fn default() -> Self {
        Self::new()
    }
}

impl SvidIssuer {
    /// An issuer with fresh elliptic-curve keys.
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let der = STANDARD.decode(RSA_PKCS8_BASE64).unwrap();
        SvidIssuer {
            p256: ec_key(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng),
            p384: ec_key(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, &rng),
            rsa: RsaKeyPair::from_pkcs8(&der).unwrap(),
            rng,
        }
    }

    /// The SPIFFE bundle (a JWK set) holding every public key.
    pub fn bundle_json(&self) -> Vec<u8> {
        let rsa = PublicKeyComponents::<Vec<u8>>::from(self.rsa.public());
        let keys = json!({
            "spiffe_refresh_hint": 300,
            "keys": [
                ec_jwk(&self.p256, "P-256", KID_P256),
                ec_jwk(&self.p384, "P-384", KID_P384),
                {"use": "jwt-svid", "kty": "RSA", "kid": KID_RSA,
                 "n": b64(&rsa.n), "e": b64(&rsa.e)},
            ],
        });
        serde_json::to_vec(&keys).unwrap()
    }

    /// One bundle holding the keys of every issuer, as during a key rotation.
    pub fn merged_bundle(issuers: &[&SvidIssuer]) -> Vec<u8> {
        let mut keys = Vec::new();
        for issuer in issuers {
            let bundle: Value = serde_json::from_slice(&issuer.bundle_json()).unwrap();
            keys.extend(bundle["keys"].as_array().unwrap().iter().cloned());
        }
        serde_json::to_vec(&json!({"keys": keys})).unwrap()
    }

    /// A JWT-SVID signed with ES256, carrying `sub`, `aud` and `exp`.
    pub fn svid(&self, sub: &str, aud: &str, exp_unix: i64) -> String {
        self.sign(
            &json!({"alg": "ES256", "kid": KID_P256}),
            &json!({"sub": sub, "aud": [aud], "exp": exp_unix}),
        )
    }

    /// A token with exactly these parts, so that tests can forge any signature.
    pub fn raw(&self, header: &Value, payload: &Value, sig: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            b64(&serde_json::to_vec(header).unwrap()),
            b64(&serde_json::to_vec(payload).unwrap()),
            b64(sig)
        )
    }

    /// `header` and `payload` signed with the key matching `header.alg`.
    pub fn sign(&self, header: &Value, payload: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(header).unwrap()),
            b64(&serde_json::to_vec(payload).unwrap())
        );
        let alg = header["alg"].as_str().unwrap();
        let sig = self.signature(alg, input.as_bytes());
        format!("{input}.{}", b64(&sig))
    }

    fn signature(&self, alg: &str, input: &[u8]) -> Vec<u8> {
        let rsa_padding: &dyn signature::RsaEncoding = match alg {
            "ES256" => return self.p256.sign(&self.rng, input).unwrap().as_ref().to_vec(),
            "ES384" => return self.p384.sign(&self.rng, input).unwrap().as_ref().to_vec(),
            "RS256" => &signature::RSA_PKCS1_SHA256,
            "RS384" => &signature::RSA_PKCS1_SHA384,
            "RS512" => &signature::RSA_PKCS1_SHA512,
            "PS256" => &signature::RSA_PSS_SHA256,
            "PS384" => &signature::RSA_PSS_SHA384,
            "PS512" => &signature::RSA_PSS_SHA512,
            other => panic!("SvidIssuer cannot sign {other}"),
        };
        let mut sig = vec![0; self.rsa.public().modulus_len()];
        self.rsa
            .sign(rsa_padding, &self.rng, input, &mut sig)
            .unwrap();
        sig
    }
}

#[derive(Default)]
struct BundleState {
    body: Vec<u8>,
    down: bool,
    stalled: bool,
}

/// A SPIFFE bundle endpoint on `127.0.0.1:0`, with switches for outages.
pub struct FakeSpiffe {
    url: String,
    state: Arc<Mutex<BundleState>>,
    server: AbortHandle,
}

async fn serve_bundle(State(state): State<Arc<Mutex<BundleState>>>) -> Response {
    let (body, down, stalled) = {
        let s = state.lock();
        (s.body.clone(), s.down, s.stalled)
    };
    if stalled {
        std::future::pending::<()>().await;
    }
    if down {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    body.into_response()
}

impl FakeSpiffe {
    /// Start serving `bundle`.
    pub async fn start(bundle: Vec<u8>) -> Self {
        let state = Arc::new(Mutex::new(BundleState {
            body: bundle,
            ..BundleState::default()
        }));
        let app = Router::new()
            .route("/keys", get(serve_bundle))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        })
        .abort_handle();
        FakeSpiffe {
            url: format!("http://{addr}/keys"),
            state,
            server,
        }
    }

    /// The bundle URL.
    pub fn bundle_url(&self) -> String {
        self.url.clone()
    }

    /// Replace the served bundle.
    pub fn set_bundle(&self, bundle: Vec<u8>) {
        self.state.lock().body = bundle;
    }

    /// While on, requests fail with 503.
    pub fn set_down(&self, down: bool) {
        self.state.lock().down = down;
    }

    /// While on, requests never answer.
    pub fn set_stalled(&self, stalled: bool) {
        self.state.lock().stalled = stalled;
    }
}

impl Drop for FakeSpiffe {
    fn drop(&mut self) {
        self.server.abort();
    }
}
