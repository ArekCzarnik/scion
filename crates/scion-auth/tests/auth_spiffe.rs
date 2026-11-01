//! JWT-SVID login validation (docs/features/spiffe-workload-identity.md; SPEC 12.3a).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test-only helpers outside #[test] fns

use scion_auth::{SvidBundle, SvidValidator};
use scion_core::{ErrorCode, Principal, Result};
use scion_testkit::SvidIssuer;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AUDIENCE: &str = "scion://monorepo";
const SUB: &str = "spiffe://example.org/ns/agents/sa/reviewer";
const NOW: u64 = 1_800_000_000;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW)
}

fn exp_in(secs: i64) -> i64 {
    NOW as i64 + secs
}

fn validate(issuer: &SvidIssuer, token: &str) -> Result<Principal> {
    let bundle = SvidBundle::parse(&issuer.bundle_json()).unwrap();
    SvidValidator::new("example.org", AUDIENCE).validate(token, &bundle, now())
}

fn assert_rejected(result: Result<Principal>) {
    let err = result.expect_err("the token must be rejected");
    assert_eq!(err.code, ErrorCode::Unauthenticated);
    assert_eq!(err.message, "invalid JWT-SVID");
}

#[test]
fn valid_svid_gives_the_subject_as_principal() {
    let issuer = SvidIssuer::new();
    let token = issuer.svid(SUB, AUDIENCE, exp_in(300));
    assert_eq!(
        validate(&issuer, &token).unwrap(),
        Principal::Spiffe(SUB.into())
    );
}

#[test]
fn every_supported_algorithm_is_accepted() {
    let issuer = SvidIssuer::new();
    for alg in [
        "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
    ] {
        let token = issuer.sign(
            &json!({"alg": alg}),
            &json!({"sub": SUB, "aud": [AUDIENCE], "exp": exp_in(300)}),
        );
        assert_eq!(
            validate(&issuer, &token).unwrap(),
            Principal::Spiffe(SUB.into()),
            "{alg}"
        );
    }
}

#[test]
fn unlisted_algorithms_are_rejected() {
    let issuer = SvidIssuer::new();
    let claims = json!({"sub": SUB, "aud": [AUDIENCE], "exp": exp_in(300)});
    for alg in [
        "none", "None", "HS256", "HS384", "HS512", "ES512", "EdDSA", "",
    ] {
        let token = issuer.raw(&json!({"alg": alg}), &claims, b"forged");
        assert_rejected(validate(&issuer, &token));
    }
    let token = issuer.raw(&json!({"alg": "none"}), &claims, b"");
    assert_rejected(validate(&issuer, &token));
}

#[test]
fn a_key_only_verifies_its_own_algorithm_family() {
    let issuer = SvidIssuer::new();
    let claims = json!({"sub": SUB, "aud": [AUDIENCE], "exp": exp_in(300)});
    let es256 = issuer.sign(&json!({"alg": "ES256"}), &claims);
    let sig = es256.rsplit('.').next().unwrap();
    let swapped = format!(
        "{}.{}",
        issuer
            .sign(&json!({"alg": "RS256"}), &claims)
            .rsplit_once('.')
            .unwrap()
            .0,
        sig
    );
    assert_rejected(validate(&issuer, &swapped));
}

#[test]
fn expiry_is_enforced_with_30_seconds_of_leeway() {
    let issuer = SvidIssuer::new();
    let at = |secs| issuer.svid(SUB, AUDIENCE, exp_in(secs));
    assert!(validate(&issuer, &at(-29)).is_ok());
    assert_rejected(validate(&issuer, &at(-30)));
    assert_rejected(validate(&issuer, &at(-3600)));
    let no_exp = issuer.sign(
        &json!({"alg": "ES256"}),
        &json!({"sub": SUB, "aud": [AUDIENCE]}),
    );
    assert_rejected(validate(&issuer, &no_exp));
    let bad_exp = issuer.sign(
        &json!({"alg": "ES256"}),
        &json!({"sub": SUB, "aud": [AUDIENCE], "exp": "tomorrow"}),
    );
    assert_rejected(validate(&issuer, &bad_exp));
}
