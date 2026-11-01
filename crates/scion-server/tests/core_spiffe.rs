//! JWT-SVID login end to end through the in-process server (docs/features/
//! spiffe-workload-identity.md): identity, per-agent rights, attribution, bundle outages.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test-only helpers outside #[test] fns

mod core_support;
mod write_support;

use core_support::{eventually, http_get};
use scion_config::{ServerConfig, SpiffeSection};
use scion_core::{Clock, ErrorCode, ManualClock, ObjectId};
use scion_proto::{ScionClient, v1};
use scion_server::testing::{InProcessServer, ServerTestOpts};
use scion_testkit::{FakeSpiffe, SvidIssuer};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use write_support::{create_req, expect_err, put_entry, root};

const AUDIENCE: &str = "scion://monorepo";
const REVIEWER: &str = "spiffe://example.org/ns/agents/sa/reviewer";
const RUNNER: &str = "spiffe://example.org/ns/ci/sa/runner";

fn acl() -> String {
    format!(
        r#"
version = 1

[groups]
agents = ["{REVIEWER}", "{RUNNER}"]

[[paths]]
prefix = "/"
read = ["group:agents"]
write = []

[[paths]]
prefix = "/reviews"
write = ["{REVIEWER}"]

[[paths]]
prefix = "/builds"
write = ["{RUNNER}"]

[refs."main"]
update = ["group:agents"]
force = []

[admin]
redact = []
purge = []
refs = []
"#
    )
}

fn section(fake: &FakeSpiffe) -> SpiffeSection {
    SpiffeSection {
        trust_domain: "example.org".into(),
        audience: AUDIENCE.into(),
        token_ttl: Duration::from_secs(900),
        bundle_url: Some(fake.bundle_url()),
        bundle_file: None,
        bundle_refresh: Duration::from_secs(3600),
    }
}

fn opts_with(
    section: SpiffeSection,
    tweak: impl Fn(&mut ServerConfig) + Send + Sync + 'static,
) -> ServerTestOpts {
    ServerTestOpts {
        acl_toml: acl(),
        service_principals: vec![("ci".into(), "ci-secret".into())],
        tweak: Some(Arc::new(move |c| {
            c.auth.spiffe = Some(section.clone());
            c.rate_limit.per_principal_rps = 1_000_000;
            c.rate_limit.burst = 1_000_000;
            tweak(c);
        })),
        ..ServerTestOpts::default()
    }
}

async fn start(fake: &FakeSpiffe) -> InProcessServer {
    InProcessServer::start(opts_with(section(fake), |_| {})).await
}

fn svid(issuer: &SvidIssuer, sub: &str) -> String {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 300;
    issuer.svid(sub, AUDIENCE, exp)
}

async fn login(srv: &InProcessServer, token: &str) -> Result<v1::LoginResponse, tonic::Status> {
    let request = v1::LoginRequest {
        credential: Some(v1::login_request::Credential::JwtSvid(token.to_owned())),
    };
    srv.client(None)
        .await
        .auth()
        .login(request)
        .await
        .map(|r| r.into_inner())
}

async fn agent(srv: &InProcessServer, issuer: &SvidIssuer, sub: &str) -> ScionClient {
    let token = login(srv, &svid(issuer, sub)).await.unwrap().token;
    srv.client(None).await.with_token(Some(token))
}

#[tokio::test(flavor = "multi_thread")]
async fn login_gives_a_token_for_the_spiffe_id() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let srv = start(&fake).await;
    let response = login(&srv, &svid(&issuer, REVIEWER)).await.unwrap();
    assert_eq!(response.principal, REVIEWER);
    let client = srv.client(None).await.with_token(Some(response.token));
    let me = client
        .auth()
        .who_am_i(v1::WhoAmIRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(me.principal, REVIEWER);
    assert_eq!(me.groups, vec!["agents"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_token_uses_the_spiffe_lifetime() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let start_at = SystemTime::now();
    let clock = ManualClock::new(start_at);
    let srv = InProcessServer::start(ServerTestOpts {
        clock: Some(clock.clone()),
        ..opts_with(section(&fake), |_| {})
    })
    .await;
    let spiffe = login(&srv, &svid(&issuer, REVIEWER)).await.unwrap();
    let want = start_at.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 + 900;
    assert!(
        (spiffe.expires_at_unix - want).abs() <= 1,
        "{}",
        spiffe.expires_at_unix
    );

    let request = v1::LoginRequest {
        credential: Some(v1::login_request::Credential::Service(
            v1::ServiceCredential {
                service_name: "ci".into(),
                service_secret: "ci-secret".into(),
            },
        )),
    };
    let service = srv
        .client(None)
        .await
        .auth()
        .login(request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(service.principal, "service:ci");
    assert!(
        service.expires_at_unix > want + 3600,
        "the service TTL must stay unchanged"
    );
}
