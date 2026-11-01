//! The real `scion` binary through `assert_cmd`: help, usage errors and auth exit codes.
//!
//! This suite stays apart from `cli_smoke`, which runs the CLI in-process on parallel test
//! threads. A child spawned here would share the open file descriptions of that process between
//! fork and exec, among them another test's `.scion/lock`, and its flock would outlive the
//! test's unlock: the next command in that test would then fail with UNAVAILABLE.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod cli_support;

use assert_cmd::Command;
use cli_support::Harness;
use scion_conformance::TestCluster;

#[tokio::test(flavor = "multi_thread")]
async fn binary_help_usage_and_whoami() {
    let h = Harness::start(false).await;
    let token = h.cluster.token_for(&TestCluster::gh("bob"));
    let home = h.home.path().to_path_buf();
    let endpoint = h.endpoint.clone();
    let ca = h.ca_file.clone();
    tokio::task::spawn_blocking(move || {
        let help = Command::cargo_bin("scion")
            .unwrap()
            .arg("--help")
            .output()
            .unwrap();
        assert_eq!(help.status.code(), Some(0));
        let text = String::from_utf8_lossy(&help.stdout);
        assert!(text.contains("Exit codes:"), "{text}");
        assert!(text.contains("3  conflicts"), "{text}");

        let bad = Command::cargo_bin("scion")
            .unwrap()
            .arg("nope")
            .output()
            .unwrap();
        assert_eq!(bad.status.code(), Some(2));

        let who = Command::cargo_bin("scion")
            .unwrap()
            .env_clear()
            .env("HOME", &home)
            .env("SCION_ENDPOINT", &endpoint)
            .env("SCION_CA_FILE", &ca)
            .env("SCION_TOKEN", &token)
            .args(["--json", "whoami"])
            .output()
            .unwrap();
        assert_eq!(
            who.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&who.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&who.stdout).unwrap();
        assert_eq!(v["schema"], "scion.cli.whoami.v1");
        assert_eq!(v["data"]["principal"], "github:bob");
        cli_support::validate(&v);

        let unauth = Command::cargo_bin("scion")
            .unwrap()
            .env_clear()
            .env("HOME", &home)
            .env("SCION_ENDPOINT", &endpoint)
            .env("SCION_CA_FILE", &ca)
            .env("SCION_TOKEN", "v4.public.garbage")
            .arg("whoami")
            .output()
            .unwrap();
        assert_eq!(unauth.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&unauth.stderr).contains("UNAUTHENTICATED"));
    })
    .await
    .unwrap();
}
