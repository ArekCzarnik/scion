//! Authentication (SPEC 12; PLAN 2.10, 6.1): PASETO v4.public Ed25519 tokens, keyrings with
//! rotation, the constant-time comparison primitive, service principals, JWT-SVID validation,
//! the GitHub API client and the GitHub device flow.
#![warn(missing_docs)]

pub mod device_flow;

mod bundle;
mod github;
mod secret;
mod service;
mod svid;
mod token;

pub use bundle::{BundleCache, BundleSource};
pub use github::{GitHubClient, GitHubUser};
#[cfg(feature = "test-hooks")]
pub use secret::ct_eq_calls;
pub use secret::{Secret, ct_eq};
pub use service::ServicePrincipals;
pub use svid::{SvidBundle, SvidValidator};
pub use token::{Claims, Keyring, PublicKeyInfo, Verifier};
