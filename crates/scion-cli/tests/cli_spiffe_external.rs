//! The whole JWT-SVID path against a real SPIRE agent; `scripts/test-spire.sh` sets the gates.
//! Fakes can share a misunderstanding with the validator, so this is the interoperability proof.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod cli_support;

use cli_support::{Harness, scion};
use scion_config::SpiffeSection;
use scion_conformance::{ClusterOpts, TestCluster};
use scion_proto::v1;
use scion_proto::workload::fetch_jwt_svid;
use std::sync::Arc;
use std::time::{Duration, Instant};

const AUDIENCE: &str = "scion://spire-e2e";

struct Gates {
    socket: String,
    bundle: String,
    id: String,
    trust_domain: String,
    rotate: String,
}

fn gates() -> Option<Gates> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    Some(Gates {
        socket: var("SCION_TEST_SPIRE_SOCKET")?,
        bundle: var("SCION_TEST_SPIRE_BUNDLE")?,
        id: var("SCION_TEST_SPIRE_ID")?,
        trust_domain: var("SCION_TEST_SPIRE_TRUST_DOMAIN")?,
        rotate: var("SCION_TEST_SPIRE_ROTATE")?,
    })
}

async fn harness(g: &Gates) -> Harness {
    let section = SpiffeSection {
        trust_domain: g.trust_domain.clone(),
        audience: AUDIENCE.into(),
        token_ttl: Duration::from_secs(900),
        bundle_url: None,
        bundle_file: Some(g.bundle.clone().into()),
        bundle_refresh: Duration::from_millis(100),
    };
    let acl = TestCluster::DEFAULT_ACL.replace("eng = [", &format!("eng = [\"{}\", ", g.id));
    let mut opts = ClusterOpts::default().with_daemon(false).with_acl(&acl);
    let base = opts.server.tweak.clone();
    opts.server.tweak = Some(Arc::new(move |c| {
        if let Some(base) = &base {
            base(c);
        }
        c.auth.spiffe = Some(section.clone());
    }));
    Harness::start_with(opts).await
}

async fn login_with(h: &Harness, svid: String) -> Result<v1::LoginResponse, tonic::Status> {
    let client = h.cluster.servers[0].client(None).await;
    let request = v1::LoginRequest {
        credential: Some(v1::login_request::Credential::JwtSvid(svid)),
    };
    client.auth().login(request).await.map(|r| r.into_inner())
}

#[tokio::test(flavor = "multi_thread")]
async fn external_spiffe_against_a_real_spire_agent() {
    let Some(g) = gates() else {
        println!("SKIP: SCION_TEST_SPIRE_SOCKET is not set; run scripts/test-spire.sh");
        return;
    };
    let h = harness(&g).await;
    let mut env = h.env_anon();
    env.0
        .insert("SPIFFE_ENDPOINT_SOCKET".into(), g.socket.clone());

    // A real SVID logs in, and the whole write path carries the identity.
    let out = scion(&env, &["--json", "login", "--spiffe"]).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.json()["data"]["principal"], g.id.as_str());

    let work = h.path("wc");
    let wc = work.to_str().unwrap();
    assert_eq!(scion(&env, &["checkout", "main", wc]).await.code, 0);
    std::fs::write(work.join("spire.txt"), "hello\n").unwrap();
    let out = scion(&env, &["-C", wc, "commit", "-m", "from SPIRE"]).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = scion(&env, &["-C", wc, "land", "--ref", "main"]).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = scion(&env, &["--json", "show", "main"]).await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.json()["data"]["meta"]["creator"], g.id.as_str());

    // An SVID minted for another audience does not log in here.
    let wrong = fetch_jwt_svid(&g.socket, "scion://elsewhere", Duration::ZERO)
        .await
        .unwrap();
    let status = login_with(&h, wrong).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    // After a key rotation, new SVIDs verify without restarting Scion.
    let before = fetch_jwt_svid(&g.socket, "scion://kid-probe-1", Duration::ZERO)
        .await
        .unwrap();
    let status = std::process::Command::new(&g.rotate).status().unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut attempt = 0;
    loop {
        attempt += 1;
        let audience = format!("{AUDIENCE}/rotated-{attempt}");
        let probe = fetch_jwt_svid(&g.socket, &audience, Duration::ZERO)
            .await
            .unwrap();
        if probe.split('.').next() != before.split('.').next() {
            break;
        }
        assert!(Instant::now() < deadline, "SPIRE never used the new key");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let svid = fetch_jwt_svid(&g.socket, AUDIENCE, Duration::ZERO)
            .await
            .unwrap();
        if login_with(&h, svid).await.is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the rotated key was never accepted"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
