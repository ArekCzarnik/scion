//! JWT-SVID login validation (docs/features/spiffe-workload-identity.md; SPEC 12.3a).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test-only helpers outside #[test] fns

use scion_auth::{SvidBundle, SvidValidator};
use scion_core::{ErrorCode, Principal, Result};
use scion_testkit::SvidIssuer;
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

#[allow(dead_code)]
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
