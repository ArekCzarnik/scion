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
