//! The cached SPIFFE bundle (docs/features/spiffe-workload-identity.md): the last good keys stay
//! in use whatever a refresh does.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scion_auth::{BundleCache, BundleSource, SvidValidator};
use scion_testkit::{FakeSpiffe, SvidIssuer};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

const AUDIENCE: &str = "scion://monorepo";
const SUB: &str = "spiffe://example.org/ns/agents/sa/reviewer";

fn t(secs: u64) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000 + secs)
}

fn accepts(cache: &BundleCache, issuer: &SvidIssuer) -> bool {
    let token = issuer.svid(SUB, AUDIENCE, 1_800_000_000 + 3600);
    SvidValidator::new("example.org", AUDIENCE)
        .validate(&token, &cache.current(), t(0))
        .is_ok()
}

async fn cache_for(fake: &FakeSpiffe) -> BundleCache {
    BundleCache::load(BundleSource::Url(fake.bundle_url()), t(0))
        .await
        .unwrap()
}

#[tokio::test]
async fn loads_from_a_url() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    assert!(accepts(&cache_for(&fake).await, &issuer));
}

#[tokio::test]
async fn loads_from_a_file() {
    let issuer = SvidIssuer::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jwks.json");
    std::fs::write(&path, issuer.bundle_json()).unwrap();
    let cache = BundleCache::load(BundleSource::File(path), t(0))
        .await
        .unwrap();
    assert!(accepts(&cache, &issuer));
}

#[tokio::test]
async fn the_first_load_must_succeed() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    fake.set_down(true);
    assert!(
        BundleCache::load(BundleSource::Url(fake.bundle_url()), t(0))
            .await
            .is_err()
    );
    fake.set_down(false);
    fake.set_bundle(b"not json".to_vec());
    assert!(
        BundleCache::load(BundleSource::Url(fake.bundle_url()), t(0))
            .await
            .is_err()
    );
    fake.set_bundle(br#"{"keys": []}"#.to_vec());
    assert!(
        BundleCache::load(BundleSource::Url(fake.bundle_url()), t(0))
            .await
            .is_err()
    );
    let missing = BundleSource::File("/nonexistent/jwks.json".into());
    assert!(BundleCache::load(missing, t(0)).await.is_err());
}

#[tokio::test]
async fn rotation_needs_only_a_refresh() {
    let old = SvidIssuer::new();
    let new = SvidIssuer::new();
    let fake = FakeSpiffe::start(old.bundle_json()).await;
    let cache = cache_for(&fake).await;
    assert!(!accepts(&cache, &new));

    fake.set_bundle(SvidIssuer::merged_bundle(&[&old, &new]));
    cache.refresh(t(10)).await.unwrap();
    assert!(accepts(&cache, &old));
    assert!(accepts(&cache, &new));

    fake.set_bundle(new.bundle_json());
    cache.refresh(t(20)).await.unwrap();
    assert!(!accepts(&cache, &old));
    assert!(accepts(&cache, &new));
}

#[tokio::test]
async fn a_failed_refresh_keeps_the_last_good_keys() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let cache = cache_for(&fake).await;

    fake.set_down(true);
    assert!(cache.refresh(t(10)).await.is_err());
    assert!(accepts(&cache, &issuer));

    fake.set_down(false);
    for bad in [b"not json".to_vec(), br#"{"keys": []}"#.to_vec()] {
        fake.set_bundle(bad);
        assert!(cache.refresh(t(20)).await.is_err());
        assert!(accepts(&cache, &issuer));
    }
}

#[tokio::test]
async fn age_counts_from_the_last_success() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let cache = cache_for(&fake).await;
    assert_eq!(cache.age(t(30)), Duration::from_secs(30));
    cache.refresh(t(40)).await.unwrap();
    assert_eq!(cache.age(t(50)), Duration::from_secs(10));
    fake.set_down(true);
    assert!(cache.refresh(t(60)).await.is_err());
    assert_eq!(cache.age(t(70)), Duration::from_secs(30));
}

#[tokio::test]
async fn a_stalled_refresh_does_not_block_readers() {
    let issuer = SvidIssuer::new();
    let fake = FakeSpiffe::start(issuer.bundle_json()).await;
    let cache = Arc::new(cache_for(&fake).await);
    fake.set_stalled(true);
    let background = cache.clone();
    let refresh = tokio::spawn(async move { background.refresh(t(10)).await });
    tokio::task::yield_now().await;
    let read = tokio::time::timeout(Duration::from_secs(1), async { accepts(&cache, &issuer) });
    assert!(read.await.unwrap());
    refresh.abort();
}
