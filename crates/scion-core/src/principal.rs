//! Principals and tiers (SPEC 4.3.8, 7.1).

use crate::error::{ErrorCode, Result, ScionError};
use std::fmt;

/// An authenticated identity (SPEC 4.3.8). `group:` principals exist only in policy and
/// never authenticate, so they are not representable here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Principal {
    /// A human logged in through GitHub; `id` is the stable numeric GitHub id carried in the
    /// token (not part of the id string).
    GitHub {
        /// GitHub login.
        login: String,
        /// Stable numeric GitHub user id, when known.
        id: Option<u64>,
    },
    /// An agent, CI job or importer authenticated with a configured secret.
    Service(String),
    /// A workload authenticated with a JWT-SVID; holds the full SPIFFE ID, unchanged.
    Spiffe(String),
}

/// Longest SPIFFE ID that implementations must support.
const MAX_SPIFFE_ID_BYTES: usize = 2048;
/// Longest SPIFFE trust domain name.
const MAX_TRUST_DOMAIN_BYTES: usize = 255;

/// Whether `s` is a SPIFFE ID with a non-empty path (a workload rather than a trust domain).
fn valid_spiffe_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("spiffe://") else {
        return false;
    };
    let Some((domain, path)) = rest.split_once('/') else {
        return false;
    };
    s.len() <= MAX_SPIFFE_ID_BYTES
        && !domain.is_empty()
        && domain.len() <= MAX_TRUST_DOMAIN_BYTES
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && path.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && b != b':' && b != b'/')
}

impl Principal {
    /// Parse `github:<login>`, `service:<name>` or a `spiffe://` ID (INVALID_ARGUMENT
    /// otherwise).
    pub fn parse(s: &str) -> Result<Self> {
        let invalid = || {
            ScionError::new(
                ErrorCode::InvalidArgument,
                format!("invalid principal {s:?}"),
            )
        };
        if let Some(login) = s.strip_prefix("github:")
            && valid_name(login)
        {
            return Ok(Principal::GitHub {
                login: login.to_owned(),
                id: None,
            });
        }
        if let Some(name) = s.strip_prefix("service:")
            && valid_name(name)
        {
            return Ok(Principal::Service(name.to_owned()));
        }
        if valid_spiffe_id(s) {
            return Ok(Principal::Spiffe(s.to_owned()));
        }
        Err(invalid())
    }

    /// The principal id string: `github:<login>`, `service:<name>` or the SPIFFE ID.
    pub fn id_string(&self) -> String {
        match self {
            Principal::GitHub { login, .. } => format!("github:{login}"),
            Principal::Service(name) => format!("service:{name}"),
            Principal::Spiffe(id) => id.clone(),
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id_string())
    }
}

/// The serving tier reported in the `scion-tier` trailer (SPEC 7.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tier {
    /// The authoritative server.
    Server,
    /// A caching daemon.
    Daemon,
}

impl Tier {
    /// `"server"` or `"daemon"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Server => "server",
            Tier::Daemon => "daemon",
        }
    }

    /// Inverse of [`Tier::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "server" => Some(Tier::Server),
            "daemon" => Some(Tier::Daemon),
            _ => None,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spiffe_ids_round_trip_unchanged() {
        let id = "spiffe://example.org/ns/agents/sa/reviewer";
        let p = Principal::parse(id).unwrap();
        assert_eq!(p, Principal::Spiffe(id.into()));
        assert_eq!(p.id_string(), id);
        assert_eq!(Principal::parse(&p.id_string()).unwrap(), p);
    }

    #[test]
    fn spiffe_ids_keep_their_exact_case() {
        let upper = Principal::parse("spiffe://example.org/ns/Agents").unwrap();
        let lower = Principal::parse("spiffe://example.org/ns/agents").unwrap();
        assert_ne!(upper, lower);
    }

    #[test]
    fn spiffe_id_length_limit_is_2048_bytes() {
        let prefix = "spiffe://example.org/";
        let at_limit = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
        assert!(Principal::parse(&at_limit).is_ok());
        let over = format!("{at_limit}a");
        assert!(Principal::parse(&over).is_err());
    }

    #[test]
    fn invalid_spiffe_ids_are_rejected() {
        for bad in [
            "spiffe://",
            "spiffe://example.org",
            "spiffe://example.org/",
            "spiffe://Example.org/a",
            "spiffe://exa mple.org/a",
            "spiffe://example.org:443/a",
            "spiffe://user@example.org/a",
            "spiffe:///a",
            "spiffe://example.org//a",
            "spiffe://example.org/a/",
            "spiffe://example.org/./a",
            "spiffe://example.org/a/../b",
            "spiffe://example.org/a?b=c",
            "spiffe://example.org/a#b",
            "spiffe://example.org/a%20b",
            "spiffe://example.org/*",
            "SPIFFE://example.org/a",
        ] {
            assert!(Principal::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parse_and_display() {
        let p = Principal::parse("github:alice").unwrap();
        assert_eq!(
            p,
            Principal::GitHub {
                login: "alice".into(),
                id: None
            }
        );
        assert_eq!(p.to_string(), "github:alice");
        assert_eq!(p.id_string(), "github:alice");
        let with_id = Principal::GitHub {
            login: "alice".into(),
            id: Some(42),
        };
        assert_eq!(with_id.to_string(), "github:alice");
        let s = Principal::parse("service:ci").unwrap();
        assert_eq!(s, Principal::Service("ci".into()));
        assert_eq!(s.to_string(), "service:ci");
        assert_eq!(Principal::parse(&s.id_string()).unwrap(), s);
        for bad in [
            "",
            "alice",
            "github:",
            "service:",
            "group:eng",
            "github:a b",
            "github-id:12",
            "service:a:b",
        ] {
            assert_eq!(
                Principal::parse(bad).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{bad}"
            );
        }
    }

    #[test]
    fn tiers() {
        assert_eq!(Tier::Server.as_str(), "server");
        assert_eq!(Tier::Daemon.to_string(), "daemon");
        assert_eq!(Tier::parse("daemon"), Some(Tier::Daemon));
        assert_eq!(Tier::parse("x"), None);
    }
}
