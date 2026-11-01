//! `[auth.spiffe]` (docs/features/spiffe-workload-identity.md): optional, strict, and with its
//! own token lifetime.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test-only helpers outside #[test] fns

use scion_config::{ConfigError, MapEnv, ServerConfig, parse_server};
use std::path::PathBuf;
use std::time::Duration;

const BASE: &str = r#"
[server]
listen = "127.0.0.1:7443"
tls_cert = "/c"
tls_key = "/k"
repo = "r"

[metadata]
url = "postgresql://db"

[objects]
endpoint = "https://s3"
bucket = "b"

[auth]
github_client_id = "id"
signing_keys = ["/key"]

[policy]
path = "/acl.toml"
"#;

const SECTION: &str = r#"
[auth.spiffe]
trust_domain = "example.org"
audience = "scion://monorepo"
bundle_url = "https://spire.example.org/keys"
"#;

fn parse(extra: &str) -> Result<ServerConfig, ConfigError> {
    parse_server(&format!("{BASE}{extra}"), &MapEnv::default())
}

fn invalid_key(extra: &str) -> String {
    match parse(extra) {
        Err(ConfigError::Invalid { key, .. }) => key,
        other => panic!("expected an invalid key, got {other:?}"),
    }
}

#[test]
fn the_section_is_optional() {
    assert!(parse("").unwrap().auth.spiffe.is_none());
}

#[test]
fn defaults_are_short_lived() {
    let cfg = parse(SECTION).unwrap();
    let s = cfg.auth.spiffe.unwrap();
    assert_eq!(s.trust_domain, "example.org");
    assert_eq!(s.audience, "scion://monorepo");
    assert_eq!(s.token_ttl, Duration::from_secs(3600));
    assert_eq!(s.bundle_refresh, Duration::from_secs(300));
    assert_eq!(
        s.bundle_url.as_deref(),
        Some("https://spire.example.org/keys")
    );
    assert_eq!(s.bundle_file, None);
}

#[test]
fn a_file_can_replace_the_url() {
    let section = SECTION.replace(
        "bundle_url = \"https://spire.example.org/keys\"",
        "bundle_file = \"/run/spire/jwks.json\"\ntoken_ttl = \"15m\"\nbundle_refresh = \"1m\"",
    );
    let s = parse(&section).unwrap().auth.spiffe.unwrap();
    assert_eq!(s.bundle_file, Some(PathBuf::from("/run/spire/jwks.json")));
    assert_eq!(s.token_ttl, Duration::from_secs(900));
    assert_eq!(s.bundle_refresh, Duration::from_secs(60));
}

#[test]
fn exactly_one_bundle_source_is_required() {
    let neither = SECTION.replace("bundle_url = \"https://spire.example.org/keys\"\n", "");
    assert_eq!(invalid_key(&neither), "auth.spiffe.bundle_url");
    let both = format!("{SECTION}bundle_file = \"/x\"\n");
    assert_eq!(invalid_key(&both), "auth.spiffe.bundle_url");
}

#[test]
fn bundle_url_must_use_https_outside_loopback() {
    let with_url = |url: &str| SECTION.replace("https://spire.example.org/keys", url);
    assert_eq!(
        invalid_key(&with_url("http://spire.example.org/keys")),
        "auth.spiffe.bundle_url"
    );
    assert_eq!(
        invalid_key(&with_url("ftp://x/keys")),
        "auth.spiffe.bundle_url"
    );
    assert!(parse(&with_url("http://127.0.0.1:9/keys")).is_ok());
}

#[test]
fn invalid_values_name_their_key() {
    let bad_domain = SECTION.replace("example.org\"\naud", "Example Org\"\naud");
    assert_eq!(invalid_key(&bad_domain), "auth.spiffe.trust_domain");
    let no_audience = SECTION.replace("scion://monorepo", "");
    assert_eq!(invalid_key(&no_audience), "auth.spiffe.audience");
    let zero_ttl = format!("{SECTION}token_ttl = \"0s\"\n");
    assert_eq!(invalid_key(&zero_ttl), "auth.spiffe.token_ttl");
    let zero_refresh = format!("{SECTION}bundle_refresh = \"0s\"\n");
    assert_eq!(invalid_key(&zero_refresh), "auth.spiffe.bundle_refresh");
}

#[test]
fn unknown_keys_are_rejected() {
    let unknown = format!("{SECTION}trust_domains = [\"x\"]\n");
    assert!(
        matches!(parse(&unknown), Err(ConfigError::UnknownKey { .. })),
        "{:?}",
        parse(&unknown)
    );
}
