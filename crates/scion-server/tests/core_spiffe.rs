//! JWT-SVID login end to end through the in-process server (docs/features/
//! spiffe-workload-identity.md): identity, per-agent rights, attribution, bundle outages.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test-only helpers outside #[test] fns

mod core_support;
mod write_support;

use core_support::{eventually, http_get};
use scion_config::{ServerConfig, SpiffeSection};
use scion_core::{ErrorCode, ManualClock, ObjectId};
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

async fn server_info(srv: &InProcessServer) -> v1::ServerInfo {
    let request = v1::GetServerInfoRequest {};
    srv.client(None)
        .await
        .objects()
        .get_server_info(request)
        .await
        .unwrap()
        .into_inner()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_audience_is_advertised() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    assert_eq!(
        server_info(&start(&fake).await).await.spiffe_audience,
        AUDIENCE
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_section_svids_are_rejected_and_no_audience_is_advertised() {
    let issuer = SvidIssuer::new();
    let srv = InProcessServer::start(ServerTestOpts {
        acl_toml: acl(),
        ..ServerTestOpts::default()
    })
    .await;
    assert_eq!(server_info(&srv).await.spiffe_audience, "");
    let status = login(&srv, &svid(&issuer, REVIEWER)).await.unwrap_err();
    expect_err(&status, ErrorCode::Unauthenticated, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_svid_is_a_missing_field() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let status = login(&start(&fake).await, "").await.unwrap_err();
    expect_err(&status, ErrorCode::InvalidArgument, None);
}

/// Store a blob and record it as uploaded by the client's own principal (SPEC 12.5).
async fn upload(srv: &InProcessServer, c: &ScionClient, content: &[u8]) -> (ObjectId, u64) {
    let (id, _) = srv
        .ctx()
        .objects
        .put_blob(content.to_vec().into())
        .await
        .unwrap();
    let who = c
        .auth()
        .who_am_i(v1::WhoAmIRequest {})
        .await
        .unwrap()
        .into_inner()
        .principal;
    let meta = &srv.ctx().storage.meta;
    meta.record_upload(&id, &who, SystemTime::now())
        .await
        .unwrap();
    (id, content.len() as u64)
}

async fn put(
    srv: &InProcessServer,
    c: &ScionClient,
    path: &str,
    change: u32,
) -> Result<ObjectId, tonic::Status> {
    let parent = root(srv).await;
    let (id, size) = upload(srv, c, path.as_bytes()).await;
    let delta = vec![put_entry(path, &id, size)];
    let created = c
        .write()
        .create_changeset(create_req(&[parent], delta, change))
        .await?;
    Ok(ObjectId::from_bytes(&created.into_inner().changeset_id).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn each_agent_is_limited_to_its_own_acl_rights() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let srv = start(&fake).await;
    let reviewer = agent(&srv, &issuer, REVIEWER).await;
    let runner = agent(&srv, &issuer, RUNNER).await;
    put(&srv, &reviewer, "reviews/a.txt", 1).await.unwrap();
    put(&srv, &runner, "builds/a.txt", 2).await.unwrap();
    let denied = put(&srv, &reviewer, "builds/b.txt", 3).await.unwrap_err();
    expect_err(&denied, ErrorCode::PermissionDenied, None);
    let denied = put(&srv, &runner, "reviews/b.txt", 4).await.unwrap_err();
    expect_err(&denied, ErrorCode::PermissionDenied, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unlisted_workload_has_no_access() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let srv = start(&fake).await;
    let stranger = agent(&srv, &issuer, "spiffe://example.org/ns/agents/sa/stranger").await;
    let denied = put(&srv, &stranger, "reviews/a.txt", 1).await.unwrap_err();
    expect_err(&denied, ErrorCode::PermissionDenied, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn replicas_share_rights_and_attribution() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let srv = start(&fake).await;
    let one = agent(&srv, &issuer, REVIEWER).await;
    let two = agent(&srv, &issuer, REVIEWER).await;
    for (client, path, change) in [(&one, "reviews/1.txt", 1), (&two, "reviews/2.txt", 2)] {
        let id = put(&srv, client, path, change).await.unwrap();
        let cs = srv.ctx().history.changeset(&id).await.unwrap();
        assert_eq!(cs.created_by, REVIEWER);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn history_names_the_agent() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let srv = start(&fake).await;
    let reviewer = agent(&srv, &issuer, REVIEWER).await;
    let id = put(&srv, &reviewer, "reviews/a.txt", 1).await.unwrap();
    let meta_id = srv
        .ctx()
        .history
        .changeset(&id)
        .await
        .unwrap()
        .changeset
        .meta;
    let meta = srv.ctx().objects.get_meta(&meta_id).await.unwrap();
    assert_eq!(meta.creator, REVIEWER.as_bytes());

    let land = v1::LandRequest {
        r#ref: "main".into(),
        head: id.as_bytes().to_vec(),
        allow_empty: false,
    };
    reviewer.write().land(land).await.unwrap();
    let log = v1::GetRefLogRequest {
        name: "main".into(),
        from_version: 0,
        limit: 0,
    };
    let entries = reviewer
        .refs()
        .get_ref_log(log)
        .await
        .unwrap()
        .into_inner()
        .entries;
    assert_eq!(entries.last().unwrap().principal, REVIEWER);
}

#[tokio::test(flavor = "multi_thread")]
async fn rotated_keys_are_picked_up_without_a_restart() {
    let old = SvidIssuer::new();
    let new = SvidIssuer::new();
    let fake = Arc::new(FakeSpiffe::start(old.bundle_json()).await);
    let mut quick = section(&fake);
    quick.bundle_refresh = Duration::from_millis(20);
    let srv = InProcessServer::start(opts_with(quick, |_| {})).await;
    assert!(login(&srv, &svid(&new, REVIEWER)).await.is_err());
    fake.set_bundle(new.bundle_json());
    let bundles = srv.ctx().spiffe.as_ref().unwrap().bundles.clone();
    let token = svid(&new, REVIEWER);
    let validator = SvidValidatorProbe::new();
    eventually("the new keys are loaded", || {
        validator.accepts(&token, &bundles)
    })
    .await;
    login(&srv, &token).await.unwrap();
}

struct SvidValidatorProbe(scion_auth::SvidValidator);

impl SvidValidatorProbe {
    fn new() -> Self {
        Self(scion_auth::SvidValidator::new("example.org", AUDIENCE))
    }

    fn accepts(&self, token: &str, bundles: &scion_auth::BundleCache) -> bool {
        self.0
            .validate(token, &bundles.current(), SystemTime::now())
            .is_ok()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bundle_outage_keeps_the_server_working() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let clock = ManualClock::new(SystemTime::now());
    let mut quick = section(&fake);
    quick.bundle_refresh = Duration::from_millis(20);
    let srv = InProcessServer::start(ServerTestOpts {
        clock: Some(clock.clone()),
        ..opts_with(quick, |_| {})
    })
    .await;
    let holder = agent(&srv, &issuer, REVIEWER).await;

    fake.set_down(true);
    clock.advance(Duration::from_secs(120));
    let metrics = srv.ctx().metrics.clone();
    eventually("the age metric grows", || {
        metrics.spiffe_bundle_age() >= 120
    })
    .await;

    holder.auth().who_am_i(v1::WhoAmIRequest {}).await.unwrap();
    login(&srv, &svid(&issuer, RUNNER)).await.unwrap();
    assert_eq!(http_get(srv.admin_addr().unwrap(), "/readyz").await.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "SPIFFE bundle")]
async fn an_unreachable_bundle_fails_startup() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    fake.set_down(true);
    start(&fake).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_svid_is_rejected_with_the_uniform_error() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let srv = start(&fake).await;
    let status = login(&srv, &issuer.svid(REVIEWER, AUDIENCE, 1))
        .await
        .unwrap_err();
    let err = expect_err(&status, ErrorCode::Unauthenticated, None);
    assert_eq!(err.message, "invalid JWT-SVID");
}

#[tokio::test(flavor = "multi_thread")]
async fn svids_never_reach_the_logs() {
    let capture = scion_obs::capture::LogCapture::install();
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let srv = start(&fake).await;
    let good = svid(&issuer, REVIEWER);
    let bad = format!("{}x", svid(&issuer, RUNNER));
    let token = login(&srv, &good).await.unwrap().token;
    login(&srv, &bad).await.unwrap_err();
    let needles = [good.as_bytes(), bad.as_bytes(), token.as_bytes()];
    assert!(capture.find_needles(&needles).is_empty());
    // The capture must have seen the rejection, or the check above proves nothing.
    assert!(capture.raw().contains("JWT-SVID rejected"));
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_failed_logins_are_rate_limited() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let srv = InProcessServer::start(opts_with(section(&fake), |c| {
        c.rate_limit.per_principal_rps = 1;
        c.rate_limit.burst = 3;
    }))
    .await;
    let client = srv.client(None).await;
    let mut limited = false;
    for _ in 0..20 {
        let request = v1::LoginRequest {
            credential: Some(v1::login_request::Credential::JwtSvid("forged".into())),
        };
        let status = client.auth().login(request).await.unwrap_err();
        limited |= status.code() == tonic::Code::ResourceExhausted;
    }
    assert!(limited);
}
