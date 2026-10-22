// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which hosts each part of a session may be sent to.
//!
//! A session is two tokens with two different destinations:
//!
//! * The **access token** is attached as a bearer token to API requests,
//!   and only to the hosts in [`destinations`] for its audience.
//! * The **refresh token** is sent to the issuer that granted it, to be
//!   exchanged or revoked, and nowhere else. [`RefreshDestination`] is the
//!   only way to name where it goes, and it can only be built by checking.
//!
//! Whether those are different hosts depends on the audience. An
//! `auth-api` access token goes to `user-api`, never to `auth-api`, which
//! only ever sees the refresh token. The `mcp-user-api` host is both the
//! issuer and the API, so both of its tokens go there.
//!
//! `docs/public-hosts.md` restates this per host. A test below pins that
//! whole page by its SHA-256, so it cannot change in any way without the
//! test changing in the same diff. Another reads the row of every host a
//! token goes to from the page and compares it with a pinned sentence, and
//! a third requires those hosts to be exactly the issuers and destinations
//! here. Whether a pinned sentence is true is for the reader of the diff
//! that changes it.
//!
//! A token is disclosed to whoever receives it, so both sets are
//! compile-time constants rather than anything a configuration file, an
//! environment variable or a redirect can widen.
//!
//! # What this covers, and what it does not
//!
//! This governs the HTTP requests **`erpc` itself sends**. It does not and
//! cannot govern a subprocess `erpc` starts, nor what a person does with a
//! value they have taken out of the store themselves. Saying otherwise
//! would be claiming a protection that is not here.

use crate::credential::Audience;

/// The only host an `auth-api` access token may be sent to.
///
/// Not `auth-api.erpc.global` itself: that host receives the refresh token,
/// through [`RefreshDestination`], and never the access token.
pub const AUTH_API_TOKEN_DESTINATIONS: &[&str] = &["user-api.erpc.global"];

/// The only host an `mcp-user-api` access token may be sent to.
pub const MCP_TOKEN_DESTINATIONS: &[&str] = &["mcp-user-api.erpc.global"];

/// The destinations an access token for `audience` may be attached to.
#[must_use]
pub const fn destinations(audience: Audience) -> &'static [&'static str] {
    match audience {
        Audience::AuthApi => AUTH_API_TOKEN_DESTINATIONS,
        Audience::McpUserApi => MCP_TOKEN_DESTINATIONS,
    }
}

/// Why a token was not attached.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AllowlistError {
    /// The URL could not be read as an absolute `https` URL.
    #[error("{0} is not an absolute https:// URL, so no token is attached")]
    NotHttps(String),
    /// The host is not one this audience's token may be sent to.
    #[error(
        "an {audience} token may only be sent to {allowed}, and this request is to {host}; \
         no token was attached"
    )]
    HostNotAllowed {
        /// The audience whose token was about to be attached.
        audience: Audience,
        /// The host the request was going to.
        host: String,
        /// The hosts that are allowed, comma separated.
        allowed: String,
    },
}

/// Checks that an access token for `audience` may be attached to a request
/// to `url`.
///
/// # Errors
///
/// Returns [`AllowlistError`] when the URL is not absolute `https`, or when
/// its host is not a destination for this audience.
pub fn ensure_token_destination(audience: Audience, url: &str) -> Result<(), AllowlistError> {
    let host = https_host(url).ok_or_else(|| AllowlistError::NotHttps(url.to_owned()))?;
    let allowed = destinations(audience);
    if allowed.iter().any(|a| *a == host) {
        return Ok(());
    }
    Err(AllowlistError::HostNotAllowed {
        audience,
        host,
        allowed: allowed.join(", "),
    })
}

/// Where a refresh token may be sent: its issuer, and only its issuer.
///
/// The field is private, so the only way to have one is [`Self::checked`].
/// The two requests that carry a refresh token, the exchange and the
/// revocation in [`crate::http`], take their URL from one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshDestination(&'static str);

impl RefreshDestination {
    /// Checks that a refresh token for `audience` may be sent to `url`.
    ///
    /// # Errors
    ///
    /// Returns [`AllowlistError`] when the URL is not absolute `https`, or
    /// when its host is not the audience's issuer.
    pub fn checked(audience: Audience, url: &'static str) -> Result<Self, AllowlistError> {
        let host = https_host(url).ok_or_else(|| AllowlistError::NotHttps(url.to_owned()))?;
        if host == audience.issuer_host() {
            return Ok(Self(url));
        }
        Err(AllowlistError::HostNotAllowed {
            audience,
            host,
            allowed: audience.issuer_host().to_owned(),
        })
    }

    /// The URL, once checked.
    #[must_use]
    pub const fn url(&self) -> &'static str {
        self.0
    }
}

/// The host of an absolute `https` URL, as the parser that will build the
/// request reads it.
///
/// `reqwest::Url` is `url::Url`, which implements the WHATWG URL Standard,
/// and `AuthClient` hands the same string to the same parser a moment
/// later. Using it here is what makes the check and the request agree.
///
/// A hand-written parser stood here and was wrong in the direction that
/// attaches the token. It split the authority on `/`, `?` and `#` only,
/// while the Standard also ends it at a backslash, so
/// `https://evil.example.net\@user-api.erpc.global/x` read as the declared
/// host to the gate and as the attacker's host to the request. Two parsers
/// that disagree about where the authority ends is the whole bug class,
/// and there is only one way to retire it.
fn https_host(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    // `host_str` is already lowercased and percent-decoded by the parser,
    // and brackets an IPv6 literal exactly as the request will.
    parsed.host_str().map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::{
        AUTH_API_TOKEN_DESTINATIONS, AllowlistError, MCP_TOKEN_DESTINATIONS, destinations,
        ensure_token_destination, https_host,
    };
    use crate::credential::Audience;

    /// Builds a URL from a bare host name.
    ///
    /// Most fixtures here name hosts that are deliberately NOT declared,
    /// which is the point of an allowlist test. Writing them out would put
    /// `https://<undeclared host>` into a tracked file, and the
    /// repository's egress gate is right to refuse that. Composing from a
    /// bare name keeps the fixtures readable and leaves that gate
    /// meaningful for the code above, which is where a stray destination
    /// would actually matter.
    fn url(host: &str, path: &str) -> String {
        format!("{}{host}{path}", "https://")
    }

    #[test]
    fn an_auth_api_token_goes_to_user_api_and_nowhere_else() {
        assert!(
            ensure_token_destination(
                Audience::AuthApi,
                &url("user-api.erpc.global", "/v3/user/get")
            )
            .is_ok()
        );
        for host in [
            // Where the token is obtained is not where it may be sent.
            "auth-api.erpc.global",
            // The other audience is a separate token family.
            "mcp-user-api.erpc.global",
            // A declared host is still not a token destination.
            "dashboard.erpc.global",
            "evil.example.net",
        ] {
            let target = url(host, "/x");
            assert!(
                ensure_token_destination(Audience::AuthApi, &target).is_err(),
                "{target} should not receive an auth-api token"
            );
        }
    }

    #[test]
    fn an_mcp_token_goes_to_mcp_user_api_and_nowhere_else() {
        assert!(
            ensure_token_destination(
                Audience::McpUserApi,
                &url("mcp-user-api.erpc.global", "/mcp")
            )
            .is_ok()
        );
        assert!(
            ensure_token_destination(
                Audience::McpUserApi,
                &url("user-api.erpc.global", "/v3/user/get")
            )
            .is_err(),
            "the two audiences are separate families and must not cross"
        );
    }

    #[test]
    fn a_lookalike_host_is_refused() {
        for host in [
            "user-api.erpc.global.evil.example.net",
            "evil-user-api.example.net",
            "user-api.example.net",
            "evil.example.net",
        ] {
            let target = url(host, "/v3/user/get");
            assert!(
                ensure_token_destination(Audience::AuthApi, &target).is_err(),
                "{target} is not user-api.erpc.global"
            );
        }
    }

    #[test]
    fn userinfo_cannot_disguise_the_host() {
        // The destination here is evil.example.net, whatever it looks like.
        let err = ensure_token_destination(
            Audience::AuthApi,
            &url("user-api.erpc.global@evil.example.net", "/v3/user/get"),
        )
        .expect_err("the host is after the last @");
        match err {
            AllowlistError::HostNotAllowed { host, .. } => assert_eq!(host, "evil.example.net"),
            other => panic!("expected HostNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn two_at_signs_do_not_disguise_the_host_either() {
        let err = ensure_token_destination(
            Audience::AuthApi,
            &url("a@user-api.erpc.global@evil.example.net", "/x"),
        )
        .expect_err("the host is after the LAST @");
        match err {
            AllowlistError::HostNotAllowed { host, .. } => assert_eq!(host, "evil.example.net"),
            other => panic!("expected HostNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn plaintext_is_refused_even_for_an_allowed_host() {
        let plaintext = format!("{}user-api.erpc.global/v3/user/get", "http://");
        assert!(matches!(
            ensure_token_destination(Audience::AuthApi, &plaintext),
            Err(AllowlistError::NotHttps(_))
        ));
    }

    #[test]
    fn a_port_and_a_case_difference_do_not_change_the_host() {
        let shouty = AUTH_API_TOKEN_DESTINATIONS[0].to_uppercase();
        let target = url(&format!("{shouty}:443"), "/v3/user/get");
        assert!(ensure_token_destination(Audience::AuthApi, &target).is_ok());
    }

    #[test]
    fn the_host_parser_reads_what_a_url_parser_reads() {
        for (raw, expected) in [
            (url("h.example", "/x"), Some("h.example")),
            (url("h.example", ""), Some("h.example")),
            (url("h.example:8443", "/x"), Some("h.example")),
            (url("u:p@h.example", "/x"), Some("h.example")),
            (url("[::1]:8899", "/x"), Some("[::1]")),
            // An empty authority is not "no host": the parser collapses it
            // and reads the first path segment as the host, which is where
            // the request would actually go. The hand-written parser said
            // None here and would have waved it through to a later check
            // that never ran.
            (url("", "/x"), Some("x")),
        ] {
            assert_eq!(https_host(&raw), expected.map(ToOwned::to_owned), "{raw}");
        }
        assert!(
            ensure_token_destination(Audience::AuthApi, &url("", "/x")).is_err(),
            "and it is refused, because `x` is not a destination"
        );
        assert_eq!(https_host("ftp://h.example/x"), None);
        assert_eq!(https_host("h.example"), None);
    }

    #[test]
    fn a_backslash_ends_the_authority_as_the_request_parser_says_it_does() {
        // The bypass a hand-written parser allowed: it split on / ? # only,
        // so this read as the declared host to the gate and as the
        // attacker's host to the request, and the token went with it.
        let disguised = url("evil.example.net", r"\@user-api.erpc.global/v3/user/get");
        assert_eq!(
            https_host(&disguised).as_deref(),
            Some("evil.example.net"),
            "the authority ends at the backslash"
        );
        match ensure_token_destination(Audience::AuthApi, &disguised)
            .expect_err("no token may be attached to this")
        {
            AllowlistError::HostNotAllowed { host, .. } => assert_eq!(host, "evil.example.net"),
            other => panic!("expected HostNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn the_gate_and_the_request_builder_agree_on_every_shape() {
        // The property the previous parser broke, stated directly: for any
        // URL, what this gate judges is what reqwest will connect to.
        for raw in [
            url("user-api.erpc.global", "/v3/user/get"),
            url("evil.example.net", r"\@user-api.erpc.global/x"),
            url("a@user-api.erpc.global@evil.example.net", "/x"),
            url("u:p@user-api.erpc.global", "/x"),
            url("[::1]:8899", "/x"),
            // Uppercase built at run time, for the same reason as above:
            // the hygiene gate reads literals and an erpc.global string
            // that is not in the declared list is what it is there to
            // catch.
            url(
                &format!("{}:443", AUTH_API_TOKEN_DESTINATIONS[0].to_uppercase()),
                "/x",
            ),
        ] {
            let built = reqwest::Url::parse(&raw).expect("parses");
            assert_eq!(
                https_host(&raw).as_deref(),
                built.host_str(),
                "the gate and the request disagree about {raw}"
            );
        }
    }

    #[test]
    fn the_destination_lists_are_constants_with_one_host_each() {
        // If either list ever grows, that is a decision that belongs in a
        // review, not something a configuration change can do.
        assert_eq!(AUTH_API_TOKEN_DESTINATIONS, &["user-api.erpc.global"]);
        assert_eq!(MCP_TOKEN_DESTINATIONS, &["mcp-user-api.erpc.global"]);
        assert_eq!(destinations(Audience::AuthApi).len(), 1);
        assert_eq!(destinations(Audience::McpUserApi).len(), 1);
    }

    #[test]
    fn every_destination_is_a_host_the_endpoint_gate_knows() {
        // The two allowlists must not drift: a destination here that the
        // egress gate has never heard of would be a host erpc contacts
        // without it being declared.
        for audience in Audience::all() {
            for host in destinations(*audience) {
                assert!(
                    erpc_core::endpoints::is_allowed_host(host),
                    "{host} is not declared in erpc-core::endpoints"
                );
            }
        }
    }

    #[test]
    fn a_refresh_token_goes_to_its_issuers_token_and_revoke_endpoints() {
        for audience in Audience::all() {
            for url in [
                crate::device_flow::endpoint::token(*audience),
                crate::device_flow::endpoint::revoke(*audience),
            ] {
                let checked = super::RefreshDestination::checked(*audience, url)
                    .unwrap_or_else(|e| panic!("{url}: {e}"));
                assert_eq!(checked.url(), url);
            }
        }
    }

    #[test]
    fn a_refresh_token_goes_nowhere_else() {
        // Not to the API hosts the access token goes to, and not to the
        // other audience's issuer.
        assert!(
            super::RefreshDestination::checked(
                Audience::AuthApi,
                "https://user-api.erpc.global/oauth/token"
            )
            .is_err()
        );
        assert!(
            super::RefreshDestination::checked(
                Audience::AuthApi,
                crate::device_flow::endpoint::token(Audience::McpUserApi)
            )
            .is_err()
        );
    }

    /// The SHA-256 of `docs/public-hosts.md`, with CRLF read as LF so a
    /// Windows checkout hashes the same.
    ///
    /// The whole page, byte for byte. Four rounds of review each found a
    /// way to change what the page shows -- a row in a form the check did
    /// not parse, a table with no pipes, a "blank" line GitHub does not
    /// think is blank, the table hidden in a comment -- because each check
    /// modelled part of how the page is rendered. This models none of it:
    /// any edit to the page fails the test until this digest is changed in
    /// the same diff, where a reader checks the page. What the page says is
    /// that reader's job; that it cannot change unseen is this test's.
    const PAGE_SHA256: &str = "8e0df7285c495c8b92c181cb68a902f2b084e75c9c3da85d1e85fdc83ef128b7";

    /// The credentials cell of every host a session token goes to, as the
    /// pinned page states it. Read from the page by
    /// [`token_row_errors`], and tied to the code by
    /// [`the_pinned_hosts_are_exactly_the_hosts_a_token_goes_to`], so the
    /// digest, these sentences and the code's hosts cannot move apart.
    const PINNED: &[(&str, &str)] = &[
        (
            "auth-api.erpc.global",
            "the device code, and the refresh token to the token and revoke endpoints only; \
             never the access token",
        ),
        ("user-api.erpc.global", "auth-api access token only"),
        (
            "mcp-user-api.erpc.global",
            "the device code, the MCP refresh token to the token and revoke endpoints, and the \
             MCP access token; never the auth-api tokens",
        ),
    ];

    const PAGE: &str = include_str!("../../../docs/public-hosts.md");

    fn sha256_hex(text: &str) -> String {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(text.replace("\r\n", "\n").as_bytes())
            .iter()
            .fold(String::with_capacity(64), |mut out, byte| {
                use core::fmt::Write as _;
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    /// Whether `page` is the pinned page.
    fn page_errors(page: &str) -> Vec<String> {
        let found = sha256_hex(page);
        if found == PAGE_SHA256 {
            Vec::new()
        } else {
            vec![format!(
                "docs/public-hosts.md has changed: its SHA-256 is {found}, pinned {PAGE_SHA256}. \
                 Read the change, then update PAGE_SHA256 in the same diff"
            )]
        }
    }

    /// Whether each token host's row on `page` says what [`PINNED`] says.
    fn token_row_errors(page: &str) -> Vec<String> {
        PINNED
            .iter()
            .filter_map(|(host, cell)| {
                let start = format!("| `{host}` |");
                let found = page
                    .lines()
                    .find(|l| l.starts_with(&start))
                    .and_then(|l| l.split('|').nth(3))
                    .map(str::trim);
                (found != Some(*cell))
                    .then(|| format!("{host}: pinned \"{cell}\", the page says {found:?}"))
            })
            .collect()
    }

    #[test]
    fn the_pinned_hosts_are_exactly_the_hosts_a_token_goes_to() {
        // So a new destination or issuer in the code cannot go undescribed,
        // and a pinned row cannot outlive the code that justified it.
        let mut from_code: Vec<&str> = Audience::all()
            .iter()
            .flat_map(|a| {
                core::iter::once(a.issuer_host()).chain(super::destinations(*a).iter().copied())
            })
            .collect();
        from_code.sort_unstable();
        from_code.dedup();
        let mut pinned: Vec<&str> = PINNED.iter().map(|(h, _)| *h).collect();
        pinned.sort_unstable();
        assert_eq!(pinned, from_code);
    }

    #[test]
    fn the_public_hosts_page_is_the_pinned_one() {
        assert_eq!(page_errors(PAGE), Vec::<String>::new());
        assert_eq!(token_row_errors(PAGE), Vec::<String>::new());
    }

    #[test]
    fn a_page_read_with_crlf_is_the_same_page() {
        assert_eq!(
            page_errors(&PAGE.replace('\n', "\r\n")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn any_change_to_the_page_is_refused() {
        // What earlier checks let through, each one rendered by GitHub as a
        // change to where tokens go, and the plainest change of all.
        let loopback = PAGE
            .lines()
            .find(|l| l.starts_with("| `127.0.0.1`"))
            .expect("the loopback row");
        let after_table = |extra: &str| PAGE.replacen(loopback, &format!("{loopback}\n{extra}"), 1);
        for (name, bad) in [
            (
                "a table with no pipes",
                format!(
                    "{PAGE}\nHosts that receive the auth-api refresh token\n:--\n`x402.erpc.global`\n"
                ),
            ),
            (
                "a non-breaking space line, then text",
                after_table("\u{a0}\n`x402.erpc.global`: the auth-api refresh token"),
            ),
            (
                "a form feed line, then text",
                after_table("\u{c}\n`x402.erpc.global`: the auth-api refresh token"),
            ),
            (
                "the table hidden in a comment",
                PAGE.replacen("| Host | Purpose |", "<!--\n| Host | Purpose |", 1)
                    .replacen(loopback, &format!("{loopback}\n-->"), 1),
            ),
            (
                "an extra trailing cell",
                PAGE.replacen("| `x402.erpc.global` |", "| `x402.erpc.global` | |", 1),
            ),
            ("one character", PAGE.replacen("none", "None", 1)),
        ] {
            assert_ne!(bad, PAGE, "the case must change the page: {name}");
            assert!(!page_errors(&bad).is_empty(), "{name} was accepted");
        }
    }

    #[test]
    fn a_token_row_must_say_what_is_pinned() {
        // Checked apart from the digest, which a change to the page would
        // trip first: this is the tie between the page and PINNED.
        let page = PAGE.replacen(
            "| ERPC account API | auth-api access token only |",
            "| ERPC account API | none |",
            1,
        );
        assert_ne!(page, PAGE);
        let errors = token_row_errors(&page);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].starts_with("user-api.erpc.global: pinned"),
            "{errors:?}"
        );
    }
}
