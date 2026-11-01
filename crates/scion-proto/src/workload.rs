//! The client side of the SPIFFE Workload API, as far as JWT-SVID login needs it.

use crate::client::unix_connector;
use crate::spiffe::JwtsvidRequest;
use crate::spiffe::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use scion_core::{ErrorCode, Result, ScionError};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tonic::metadata::MetadataValue;

/// The environment variable naming the Workload API socket.
pub const ENV_SOCKET: &str = "SPIFFE_ENDPOINT_SOCKET";

/// How long a client waits for its identity by default. A new pod can start before its
/// registration entry reaches the SPIRE agent on that node.
pub const IDENTITY_WAIT: Duration = Duration::from_secs(60);

const FIRST_RETRY: Duration = Duration::from_millis(100);
const LONGEST_RETRY: Duration = Duration::from_secs(5);

fn unavailable(m: String) -> ScionError {
    ScionError::new(ErrorCode::Unavailable, format!("SPIFFE Workload API: {m}"))
}

/// `unix:///path` or `unix:/path`, the two forms the SPIFFE standard allows for a local socket.
fn socket_path(socket: &str) -> Result<PathBuf> {
    socket
        .strip_prefix("unix://")
        .or_else(|| socket.strip_prefix("unix:"))
        .filter(|path| path.starts_with('/'))
        .map(PathBuf::from)
        .ok_or_else(|| unavailable(format!("{ENV_SOCKET} is not a unix: address")))
}

/// Fetch a JWT-SVID for `audience` from the Workload API at `socket`. While the API answers
/// `PermissionDenied`, which it does until the workload has an identity, this retries for up to
/// `wait`.
pub async fn fetch_jwt_svid(socket: &str, audience: &str, wait: Duration) -> Result<String> {
    let path = socket_path(socket)?;
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(unix_connector(path))
        .await
        .map_err(|e| unavailable(format!("cannot connect to {socket}: {e}")))?;
    let mut client = SpiffeWorkloadApiClient::new(channel);
    let deadline = Instant::now() + wait;
    let mut delay = FIRST_RETRY;
    loop {
        let mut request = tonic::Request::new(JwtsvidRequest {
            audience: vec![audience.to_owned()],
            spiffe_id: String::new(),
        });
        // Required by the standard, which rejects requests lacking it.
        request
            .metadata_mut()
            .insert("workload.spiffe.io", MetadataValue::from_static("true"));
        match client.fetch_jwtsvid(request).await {
            Ok(response) => {
                return response
                    .into_inner()
                    .svids
                    .into_iter()
                    .next()
                    .map(|s| s.svid)
                    .ok_or_else(|| unavailable("the response holds no JWT-SVID".to_owned()));
            }
            Err(status)
                if status.code() == tonic::Code::PermissionDenied
                    && Instant::now() + delay < deadline =>
            {
                tracing::debug!("no SPIFFE identity yet; retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(LONGEST_RETRY);
            }
            Err(status) => {
                return Err(unavailable(format!("no JWT-SVID: {}", status.message())));
            }
        }
    }
}
