//! SPIFFE IDs as ACL members (docs/features/spiffe-workload-identity.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scion_core::Principal;
use scion_object::RefName;
use scion_policy::{AdminPerm, Policy};

const REVIEWER: &str = "spiffe://example.org/ns/agents/sa/reviewer";
const RUNNER: &str = "spiffe://example.org/ns/ci/sa/runner";

fn acl() -> String {
    format!(
        r#"
version = 1

[groups]
readers = ["group:writers", "{RUNNER}"]
writers = ["{REVIEWER}"]

[[paths]]
prefix = "/"
read = ["group:readers"]
write = ["group:writers"]

[refs."main"]
update = ["group:writers"]
force = []

[admin]
redact = []
purge = []
refs = ["{RUNNER}"]
"#
    )
}

fn spiffe(id: &str) -> Principal {
    Principal::Spiffe(id.into())
}

#[test]
fn a_spiffe_member_receives_its_grants() {
    let p = Policy::parse(&acl()).unwrap();
    let main = RefName::parse("main").unwrap();
    assert!(p.can_read_bytes(&spiffe(REVIEWER), b"a"));
    assert!(p.can_write_bytes(&spiffe(REVIEWER), b"a"));
    assert!(p.can_update_ref(&spiffe(REVIEWER), &main));
    assert!(!p.can_admin(&spiffe(REVIEWER), AdminPerm::Refs));
    assert!(p.can_read_bytes(&spiffe(RUNNER), b"a"));
    assert!(!p.can_write_bytes(&spiffe(RUNNER), b"a"));
    assert!(p.can_admin(&spiffe(RUNNER), AdminPerm::Refs));
}

#[test]
fn groups_resolve_through_nesting() {
    let p = Policy::parse(&acl()).unwrap();
    assert_eq!(p.groups_of(&spiffe(REVIEWER)), vec!["readers", "writers"]);
    assert_eq!(p.groups_of(&spiffe(RUNNER)), vec!["readers"]);
}

#[test]
fn matching_is_exact() {
    let p = Policy::parse(&acl()).unwrap();
    for other in [
        "spiffe://example.org/ns/agents/sa/Reviewer",
        "spiffe://example.org/ns/agents/sa/reviewer/pod/1",
        "spiffe://example.org/ns/agents/sa",
        "spiffe://other.org/ns/agents/sa/reviewer",
    ] {
        assert!(!p.can_read_bytes(&spiffe(other), b"a"), "{other}");
    }
    assert!(!p.can_read_bytes(&Principal::Service("reviewer".into()), b"a"));
}

#[test]
fn malformed_members_are_rejected() {
    for bad in [
        "spiffe://example.org",
        "spiffe://example.org/ns/agents/*",
        "spiffe://Example.org/a",
        "spiffe://example.org/a?b",
    ] {
        let toml = acl().replace(REVIEWER, bad);
        assert!(Policy::parse(&toml).is_err(), "{bad}");
    }
}
