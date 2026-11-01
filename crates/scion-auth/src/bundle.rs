//! The cached JWT-SVID keys of a trust domain (SPEC 12.3a).
//!
//! `Login` reads only the cache, so a slow or failing bundle source cannot delay it. The first
//! load must succeed; after that a failed refresh keeps the last good keys and logs an error, as
//! an invalid policy reload does (SPEC 6.2).

use crate::SvidBundle;
use parking_lot::Mutex;
use scion_core::{ErrorCode, Result, ScionError};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Bound on one bundle fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

fn unavailable(m: String) -> ScionError {
    ScionError::new(ErrorCode::Unavailable, format!("SPIFFE bundle: {m}"))
}

/// Where the bundle comes from.
#[derive(Clone, Debug)]
pub enum BundleSource {
    /// A SPIFFE bundle endpoint.
    Url(String),
    /// A file, for example one written by `spiffe-helper`.
    File(PathBuf),
}

struct Loaded {
    bundle: Arc<SvidBundle>,
    at: SystemTime,
}

/// The last good bundle and when it was fetched.
pub struct BundleCache {
    source: BundleSource,
    http: reqwest::Client,
    loaded: Mutex<Loaded>,
}

async fn fetch(source: &BundleSource, http: &reqwest::Client) -> Result<SvidBundle> {
    let bytes = match source {
        BundleSource::Url(url) => {
            let response = http
                .get(url)
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|e| unavailable(format!("fetch failed: {}", e.without_url())))?;
            let body = response.bytes().await;
            body.map_err(|e| unavailable(format!("read failed: {}", e.without_url())))?
                .to_vec()
        }
        BundleSource::File(path) => tokio::fs::read(path)
            .await
            .map_err(|e| unavailable(format!("cannot read the file: {}", e.kind())))?,
    };
    let bundle = SvidBundle::parse(&bytes)?;
    if bundle.is_empty() {
        return Err(unavailable("no usable jwt-svid key".to_owned()));
    }
    Ok(bundle)
}

impl BundleCache {
    /// Load the bundle for the first time at `now`.
    pub async fn load(source: BundleSource, now: SystemTime) -> Result<Self> {
        // Redirects stay off: the URL is the configured source of trust.
        let http = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| unavailable(format!("HTTP client: {e}")))?;
        let bundle = fetch(&source, &http).await?;
        Ok(BundleCache {
            source,
            http,
            loaded: Mutex::new(Loaded {
                bundle: Arc::new(bundle),
                at: now,
            }),
        })
    }

    /// Fetch again at `now`. On failure the last good keys stay in use.
    pub async fn refresh(&self, now: SystemTime) -> Result<()> {
        match fetch(&self.source, &self.http).await {
            Ok(bundle) => {
                *self.loaded.lock() = Loaded {
                    bundle: Arc::new(bundle),
                    at: now,
                };
                Ok(())
            }
            Err(e) => {
                tracing::error!(error = %e, "SPIFFE bundle refresh failed; keeping the last good keys");
                Err(e)
            }
        }
    }

    /// The keys to validate with.
    pub fn current(&self) -> Arc<SvidBundle> {
        self.loaded.lock().bundle.clone()
    }

    /// Time since the last successful fetch.
    pub fn age(&self, now: SystemTime) -> Duration {
        now.duration_since(self.loaded.lock().at)
            .unwrap_or_default()
    }
}
