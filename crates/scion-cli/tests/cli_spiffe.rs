//! `scion login --spiffe` and silent re-exchange through the Workload API
//! (docs/features/spiffe-workload-identity.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod cli_support;

use cli_support::{Harness, Out, scion};
use scion_config::{MapEnv, SpiffeSection};
use scion_conformance::{ClusterOpts, TestCluster};
use scion_proto::workload::fetch_jwt_svid;
use scion_testkit::{FakeSpiffe, FakeWorkloadApi, SvidIssuer};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AUDIENCE: &str = "scion://monorepo";
const SUB: &str = "spiffe://example.org/ns/agents/sa/reviewer";

/// A cluster accepting JWT-SVIDs from `issuer`, with [`SUB`] in group `eng`.
struct Spiffe {
    h: Harness,
    issuer: SvidIssuer,
    workload: FakeWorkloadApi,
    _bundle: FakeSpiffe,
}

fn svid(issuer: &SvidIssuer) -> String {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 300;
    issuer.svid(SUB, AUDIENCE, exp)
}

impl Spiffe {
    async fn start(daemon: bool) -> Self {
        let issuer = SvidIssuer::new();
        let bundle = FakeSpiffe::start(issuer.bundle_json()).await;
        let section = SpiffeSection {
            trust_domain: "example.org".into(),
            audience: AUDIENCE.into(),
            token_ttl: Duration::from_secs(900),
            bundle_url: Some(bundle.bundle_url()),
            bundle_file: None,
            bundle_refresh: Duration::from_secs(3600),
        };
        let mut opts = ClusterOpts::default().with_daemon(daemon);
        let acl = TestCluster::DEFAULT_ACL.replace("eng = [", &format!("eng = [\"{SUB}\", "));
        opts = opts.with_acl(&acl);
        let base = opts.server.tweak.clone();
        opts.server.tweak = Some(Arc::new(move |c| {
            if let Some(base) = &base {
                base(c);
            }
            c.auth.spiffe = Some(section.clone());
        }));
        let workload = FakeWorkloadApi::start(svid(&issuer)).await;
        Spiffe {
            h: Harness::start_with(opts).await,
            issuer,
            workload,
            _bundle: bundle,
        }
    }

    fn env(&self) -> MapEnv {
        let mut env = self.h.env_anon();
        env.0
            .insert("SPIFFE_ENDPOINT_SOCKET".into(), self.workload.socket());
        env
    }
}

fn creds_path(h: &Harness) -> PathBuf {
    h.home.path().join(".config/scion/credentials")
}

async fn login(env: &MapEnv) -> Out {
    scion(env, &["--json", "login", "--spiffe"]).await
}

#[tokio::test(flavor = "multi_thread")]
async fn login_stores_a_token_for_the_workload() {
    let s = Spiffe::start(false).await;
    let out = login(&s.env()).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    let v = out.json();
    cli_support::validate(&v);
    assert_eq!(v["data"]["principal"], SUB);
    assert_eq!(v["data"]["method"], "spiffe");
    assert_eq!(v["data"]["github_token_stored"], false);
    assert_eq!(s.workload.audiences(), vec![AUDIENCE]);

    let path = creds_path(&s.h);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let creds = scion_wc::credentials::read(&path).unwrap();
    assert_eq!(creds.github_token, None);
    let claims = s.h.cluster.servers[0]
        .ctx()
        .verifier
        .verify(&creds.token, SystemTime::now());
    assert_eq!(claims.unwrap().sub.id_string(), SUB);

    let out = scion(&s.env(), &["--json", "whoami"]).await;
    assert_eq!(out.json()["data"]["principal"], SUB);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_waits_for_the_identity() {
    let s = Spiffe::start(false).await;
    s.workload.deny_next(2);
    let out = login(&s.env()).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(s.workload.calls(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_identity_fails_after_the_limit() {
    let issuer = SvidIssuer::new();
    let workload = FakeWorkloadApi::start(svid(&issuer)).await;
    workload.deny_next(u32::MAX);
    let err = fetch_jwt_svid(&workload.socket(), AUDIENCE, Duration::from_millis(250))
        .await
        .unwrap_err();
    assert!(err.message.contains("no identity issued"), "{err:?}");
    assert!(workload.calls() >= 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_workload_api_is_a_clear_error() {
    let s = Spiffe::start(false).await;
    let out = scion(&s.h.env_anon(), &["login", "--spiffe"]).await;
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains("SPIFFE_ENDPOINT_SOCKET"),
        "{}",
        out.stderr
    );

    let mut env = s.h.env_anon();
    env.0.insert(
        "SPIFFE_ENDPOINT_SOCKET".into(),
        "unix:///nonexistent/api.sock".into(),
    );
    let out = scion(&env, &["login", "--spiffe"]).await;
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("Workload API"), "{}", out.stderr);

    env.0
        .insert("SPIFFE_ENDPOINT_SOCKET".into(), "tcp://127.0.0.1:1".into());
    let out = scion(&env, &["login", "--spiffe"]).await;
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("unix:"), "{}", out.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_without_spiffe_is_a_clear_error() {
    let h = Harness::start(false).await;
    let issuer = SvidIssuer::new();
    let workload = FakeWorkloadApi::start(svid(&issuer)).await;
    let mut env = h.env_anon();
    env.0
        .insert("SPIFFE_ENDPOINT_SOCKET".into(), workload.socket());
    let out = scion(&env, &["login", "--spiffe"]).await;
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains("does not accept JWT-SVID"),
        "{}",
        out.stderr
    );
    assert_eq!(workload.calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn service_and_spiffe_exclude_each_other() {
    let s = Spiffe::start(false).await;
    let out = scion(&s.env(), &["login", "--spiffe", "--service", "ci"]).await;
    assert_ne!(out.code, 0);
    assert_eq!(s.workload.calls(), 0);
}

fn expired_token(s: &Spiffe) -> String {
    let who = scion_core::Principal::Spiffe(SUB.into());
    let now = SystemTime::now();
    let ctx = s.h.cluster.servers[0].ctx();
    ctx.keyring
        .issue(
            &who,
            Duration::from_secs(60),
            now - Duration::from_secs(3600),
        )
        .unwrap()
        .0
}

fn store_token(s: &Spiffe, token: String) {
    let creds = scion_wc::credentials::Credentials {
        token,
        github_token: None,
    };
    scion_wc::credentials::write(&creds_path(&s.h), &creds).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_token_is_replaced_silently() {
    let s = Spiffe::start(false).await;
    let expired = expired_token(&s);
    store_token(&s, expired.clone());
    let out = scion(&s.env(), &["--json", "whoami"]).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.json()["data"]["principal"], SUB);
    assert_eq!(s.workload.calls(), 1);
    let fresh = scion_wc::credentials::read(&creds_path(&s.h)).unwrap();
    assert_ne!(fresh.token, expired);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_prior_login_is_needed() {
    let s = Spiffe::start(false).await;
    let out = scion(&s.env(), &["--json", "whoami"]).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.json()["data"]["principal"], SUB);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_exchange_is_reported_once() {
    let s = Spiffe::start(false).await;
    store_token(&s, expired_token(&s));
    s.workload.set_svid(svid(&SvidIssuer::new()));
    let out = scion(&s.env(), &["whoami"]).await;
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("UNAUTHENTICATED"), "{}", out.stderr);
    assert_eq!(s.workload.calls(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_explicit_token_is_never_replaced() {
    let s = Spiffe::start(false).await;
    let mut env = s.env();
    env.0.insert("SCION_TOKEN".into(), expired_token(&s));
    let out = scion(&env, &["whoami"]).await;
    assert_ne!(out.code, 0);
    assert_eq!(s.workload.calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_github_login_keeps_its_stored_token_without_a_workload_api() {
    let s = Spiffe::start(false).await;
    store_token(&s, expired_token(&s));
    let out = scion(&s.h.env_anon(), &["whoami"]).await;
    assert_ne!(out.code, 0);
    assert_eq!(s.workload.calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_works_through_the_daemon() {
    let s = Spiffe::start(true).await;
    let mut env = s.env();
    env.0.insert("SCION_ENDPOINT".into(), s.h.daemon_endpoint());
    let out = login(&env).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.json()["data"]["principal"], SUB);
    let out = scion(&env, &["--json", "whoami"]).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.json()["data"]["principal"], SUB);
}
