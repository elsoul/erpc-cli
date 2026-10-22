// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The single source of truth for every host `erpc` is allowed to contact.
//!
//! Two controls share this list:
//!
//! 1. Before a commit, `scripts/check-endpoints.sh` extracts these literals and
//!    refuses any other URL in a tracked text file, so a new destination cannot
//!    enter the repository without a reviewer seeing this file change.
//! 2. At runtime, [`ensure_service_url`] is the helper that callers use to
//!    check a destination before contacting it. **It has no callers yet**:
//!    this version of `erpc` performs no network requests at all. When the
//!    HTTP client lands, every outbound call path must go through it.
//!
//! What this does and does not buy. Because ERPC's own endpoints are
//! compile-time constants and are never read from configuration or environment
//! variables, a tampered config file cannot redirect ERPC traffic. It does
//! **not** stop a malicious dependency, which can open its own socket without
//! consulting this module; there is no egress sandbox here.
//!
//! **Not covered:** node endpoints the operator names themselves, such as
//! `erpc check rpc --url`. Those are the user's own targets, validated by
//! [`ensure_user_supplied_url`] for shape and scheme only.

use std::fmt;

/// ERPC service hosts. These receive credentials, so the list is deliberately short.
pub const SERVICE_HOSTS: &[&str] = &[
    "auth-api.erpc.global",
    "user-api.erpc.global",
    "mcp-user-api.erpc.global",
    "x402.erpc.global",
    "edge.erpc.global",
];

/// Hosts opened in the operator's browser. No credential is ever sent by `erpc`.
pub const BROWSER_HOSTS: &[&str] = &["dashboard.erpc.global", "erpc.global"];

/// Release distribution and update checks. No credential is sent.
pub const DISTRIBUTION_HOSTS: &[&str] = &[
    "install.erpc.global",
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

/// Build and CI tooling. Contacted by cargo, npm and workflows, never by the binary.
pub const TOOLING_HOSTS: &[&str] = &[
    "crates.io",
    "index.crates.io",
    "static.crates.io",
    "sh.rustup.rs",
    "registry.npmjs.org",
];

/// Host prefixes allowed with any suffix label, for the snapshot mirror pool.
/// An entry `("solana-snapshot-", ".erpc.global")` matches
/// `solana-snapshot-ams.erpc.global` but not `evil-solana-snapshot-x.other`.
pub const HOST_PATTERNS: &[(&str, &str)] = &[("solana-snapshot-", ".erpc.global")];

/// Hosts that may be *linked from documentation* and from nowhere else.
///
/// `erpc` never contacts these; they exist so that the egress gate can apply
/// one rule to the whole repository ("every URL names a declared host")
/// instead of trying to tell a prose link from an instruction, which is a
/// judgement a text matcher makes badly. Adding a reference means adding it
/// here, which is cheap and visible.
///
/// Not usable by [`ensure_service_url`]: these are not ERPC destinations.
/// Keep this list to hosts something actually links today. A grant held "in
/// case" is a standing permission nobody is reviewing.
pub const DOCUMENTATION_HOSTS: &[&str] = &[
    "www.contributor-covenant.org",
    "keepachangelog.com",
    "semver.org",
    "elsoul.nl",
];

/// Loopback hosts, where plaintext `http`/`ws` is allowed: the OAuth redirect
/// listener and `erpc mcp serve --http`.
///
/// An IPv6 literal must be bracketed in a URL, so `[::1]` is the form that
/// reaches this list; a bare `::1` is rejected as malformed before the list is
/// consulted.
pub const LOOPBACK_HOSTS: &[&str] = &["127.0.0.1", "localhost", "[::1]"];

/// Why a URL was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointError {
    /// The string did not parse as an absolute URL.
    Malformed,
    /// The scheme is not permitted for this host.
    Scheme(String),
    /// The URL carries a username or password.
    Userinfo,
    /// The host is not in the allowlist in this module.
    HostNotAllowed(String),
    /// A non-loopback URL named an explicit port.
    Port(u16),
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "not an absolute URL"),
            Self::Scheme(s) => write!(f, "scheme `{s}` is not allowed; use https or wss"),
            Self::Userinfo => write!(f, "URL must not carry a username or password"),
            Self::HostNotAllowed(h) => write!(
                f,
                "host `{h}` is not in the endpoint allowlist (crates/erpc-core/src/endpoints.rs)"
            ),
            Self::Port(p) => write!(f, "explicit port `{p}` is not allowed for a service host"),
        }
    }
}

impl std::error::Error for EndpointError {}

/// Hosts `erpc` may contact, for the pre-commit gate and diagnostics.
///
/// Excludes [`DOCUMENTATION_HOSTS`], which are link targets, not destinations.
#[must_use]
pub fn all_hosts() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = SERVICE_HOSTS
        .iter()
        .chain(BROWSER_HOSTS)
        .chain(DISTRIBUTION_HOSTS)
        .chain(TOOLING_HOSTS)
        .chain(LOOPBACK_HOSTS)
        .copied()
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// True when `host` is loopback.
#[must_use]
pub fn is_loopback(host: &str) -> bool {
    LOOPBACK_HOSTS.contains(&host)
}

/// True when `host` is allowed, either exactly or through a pattern.
#[must_use]
pub fn is_allowed_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if all_hosts().contains(&host) {
        return true;
    }
    HOST_PATTERNS.iter().any(|(prefix, suffix)| {
        host.len() > prefix.len() + suffix.len()
            && host.starts_with(prefix)
            && host.ends_with(suffix)
            // the wildcard label must not itself contain a dot
            && !host[prefix.len()..host.len() - suffix.len()].contains('.')
    })
}

/// Refuse any URL that `erpc` must not contact on its own initiative.
///
/// Accepts `https`/`wss` to an allowlisted host with no explicit port and no
/// userinfo, or `http`/`ws`/`https`/`wss` to loopback with any port.
///
/// No caller exists in this version; see the module documentation.
///
/// # Errors
///
/// Returns the specific [`EndpointError`] so the caller can report why.
pub fn ensure_service_url(raw: &str) -> Result<(), EndpointError> {
    let parsed = Parsed::parse(raw)?;
    if parsed.userinfo {
        return Err(EndpointError::Userinfo);
    }
    if !is_allowed_host(&parsed.host) {
        return Err(EndpointError::HostNotAllowed(parsed.host));
    }
    if is_loopback(parsed.host.trim_end_matches('.')) {
        return match parsed.scheme.as_str() {
            "http" | "https" | "ws" | "wss" => Ok(()),
            other => Err(EndpointError::Scheme(other.to_owned())),
        };
    }
    match parsed.scheme.as_str() {
        "https" | "wss" => {}
        other => return Err(EndpointError::Scheme(other.to_owned())),
    }
    if let Some(p) = parsed.port {
        return Err(EndpointError::Port(p));
    }
    Ok(())
}

/// Validate a URL the operator supplied themselves, such as a node RPC endpoint.
///
/// The host is their choice, so only the shape is checked: an absolute URL,
/// a transport-secure scheme unless it is loopback, and no userinfo.
///
/// # Errors
///
/// Returns the specific [`EndpointError`] so the caller can report why.
pub fn ensure_user_supplied_url(raw: &str) -> Result<(), EndpointError> {
    let parsed = Parsed::parse(raw)?;
    if parsed.userinfo {
        return Err(EndpointError::Userinfo);
    }
    match parsed.scheme.as_str() {
        "https" | "wss" => Ok(()),
        "http" | "ws" if is_loopback(&parsed.host) => Ok(()),
        other => Err(EndpointError::Scheme(other.to_owned())),
    }
}

/// The few URL parts these checks need, parsed without a dependency.
///
/// Deliberately strict: anything that does not look like
/// `scheme://host[:port][/...]` is [`EndpointError::Malformed`] rather than
/// being guessed at.
struct Parsed {
    scheme: String,
    host: String,
    port: Option<u16>,
    userinfo: bool,
}

impl Parsed {
    fn parse(raw: &str) -> Result<Self, EndpointError> {
        if raw.trim() != raw || raw.is_empty() {
            return Err(EndpointError::Malformed);
        }
        let (scheme, rest) = raw.split_once("://").ok_or(EndpointError::Malformed)?;
        if scheme.is_empty()
            || !scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return Err(EndpointError::Malformed);
        }
        // Authority ends at the first '/', '?' or '#'.
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() {
            return Err(EndpointError::Malformed);
        }
        // Userinfo is everything before the last '@'.
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((_, hp)) => (true, hp),
            None => (false, authority),
        };
        if hostport.is_empty() {
            return Err(EndpointError::Malformed);
        }
        // IPv6 literals are bracketed; a port follows the closing bracket.
        let (host, port_str) = if let Some(close) = hostport.find(']') {
            if !hostport.starts_with('[') {
                return Err(EndpointError::Malformed);
            }
            let h = &hostport[..=close];
            let r = &hostport[close + 1..];
            match r.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None if r.is_empty() => (h, None),
                None => return Err(EndpointError::Malformed),
            }
        } else {
            match hostport.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (hostport, None),
            }
        };
        if host.is_empty() || host.contains(['/', '\\', '@', ' ']) {
            return Err(EndpointError::Malformed);
        }
        let port = match port_str {
            Some(p) => Some(p.parse::<u16>().map_err(|_| EndpointError::Malformed)?),
            None => None,
        };
        Ok(Self {
            scheme: scheme.to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            port,
            userinfo,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EndpointError, all_hosts, ensure_service_url, ensure_user_supplied_url, is_allowed_host,
    };

    #[test]
    fn service_urls_are_accepted() {
        for u in [
            "https://auth-api.erpc.global/oauth/token",
            "https://user-api.erpc.global/v3/user/get",
            "https://x402.erpc.global/v1/credits/topup",
            "wss://edge.erpc.global/",
            "https://solana-snapshot-ams.erpc.global/snapshot.tar.zst",
            "https://github.com/elsoul/erpc-cli/releases/latest",
            "http://127.0.0.1:53123/callback",
            "ws://localhost:20026/v1/session/ws",
        ] {
            assert_eq!(ensure_service_url(u), Ok(()), "should be allowed: {u}");
        }
    }

    #[test]
    fn unlisted_hosts_are_refused() {
        for u in [
            "https://evil.example.com/v3/user/get",
            "https://user-api.erpc.global.evil.com/",
            "https://admin-internal.erpc.global/",
            // the wildcard label must not span a dot
            "https://solana-snapshot-a.b.erpc.global/",
        ] {
            assert!(
                matches!(ensure_service_url(u), Err(EndpointError::HostNotAllowed(_))),
                "should be refused: {u}"
            );
        }
    }

    #[test]
    fn insecure_and_odd_urls_are_refused() {
        assert!(matches!(
            ensure_service_url("http://user-api.erpc.global/"),
            Err(EndpointError::Scheme(_))
        ));
        assert!(matches!(
            ensure_service_url("https://user:pw@user-api.erpc.global/"),
            Err(EndpointError::Userinfo)
        ));
        assert!(matches!(
            ensure_service_url("https://user-api.erpc.global:8443/"),
            Err(EndpointError::Port(8443))
        ));
        for u in [
            "",
            " https://github.com",
            "github.com",
            "file:///etc/passwd",
        ] {
            assert!(ensure_service_url(u).is_err(), "should be refused: {u}");
        }
    }

    #[test]
    fn trailing_dot_cannot_escape_the_allowlist() {
        assert!(is_allowed_host("user-api.erpc.global."));
        assert!(!is_allowed_host("user-api.erpc.global.evil.com"));
    }

    #[test]
    fn user_supplied_urls_allow_any_secure_host() {
        assert_eq!(
            ensure_user_supplied_url("https://my-own-node.example.net:8899/"),
            Ok(())
        );
        assert_eq!(ensure_user_supplied_url("http://127.0.0.1:8899/"), Ok(()));
        assert!(matches!(
            ensure_user_supplied_url("http://my-own-node.example.net/"),
            Err(EndpointError::Scheme(_))
        ));
    }

    #[test]
    fn allowlist_is_sorted_deduped_and_non_empty() {
        let hosts = all_hosts();
        assert!(hosts.len() > 10);
        let mut sorted = hosts.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(hosts, sorted);
    }

    /// `docs/public-hosts.md` explains this list to readers. The gates read the
    /// code, so the page can drift silently unless something checks it.
    #[test]
    fn every_host_is_documented() {
        let doc = include_str!("../../../docs/public-hosts.md");
        // Documentation hosts are a standing grant to link from prose, so the
        // page that explains the lists must show them too; `all_hosts()`
        // deliberately excludes them, which once left them invisible.
        // Match the table cell, not any substring: `github.com` is contained
        // in `api.github.com`, so a plain `contains` lets rows be deleted.
        let mut missing: Vec<&str> = all_hosts()
            .into_iter()
            .chain(super::DOCUMENTATION_HOSTS.iter().copied())
            .filter(|h| !doc.contains(&format!("`{h}`")))
            .collect();
        for (prefix, suffix) in super::HOST_PATTERNS {
            if !doc.contains(&format!("{prefix}*{suffix}")) {
                missing.push(prefix);
            }
        }
        assert!(
            missing.is_empty(),
            "not described in docs/public-hosts.md: {missing:?}"
        );
    }

    /// Documentation hosts are link targets only. Letting one through
    /// [`ensure_service_url`] would make the page's "never contacted"
    /// statement false.
    #[test]
    fn documentation_hosts_are_not_service_destinations() {
        for h in super::DOCUMENTATION_HOSTS {
            assert!(
                !all_hosts().contains(h),
                "{h} is both a documentation host and a service host"
            );
            assert!(
                matches!(
                    ensure_service_url(&format!("https://{h}/")),
                    Err(EndpointError::HostNotAllowed(_))
                ),
                "ensure_service_url must refuse the documentation host {h}"
            );
        }
    }

    /// The page must point at the script for the exception list rather than
    /// restate it, because a restated list drifts from the script silently.
    #[test]
    fn the_page_defers_to_the_script_for_its_exception_list() {
        let doc = include_str!("../../../docs/public-hosts.md");
        assert!(
            doc.contains("--print-exceptions"),
            "docs/public-hosts.md must point readers at \
             `scripts/check-endpoints.sh --print-exceptions`"
        );
        assert!(
            !doc.contains("is the one exception") && !doc.contains("are the exception"),
            "docs/public-hosts.md must not claim a single exception; the gate has several"
        );
    }
}
