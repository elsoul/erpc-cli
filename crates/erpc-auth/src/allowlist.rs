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
//! `docs/public-hosts.md` restates this per host. Tests below pin the
//! credentials cell of every issuer and access-token destination word for
//! word, require that set of hosts to be exactly the one these lists and
//! the issuer hosts produce, and reject the words "access", "refresh" and
//! "device", in any case, in every other row's credentials. Whether a
//! pinned sentence is true is for the reader of the diff that changes it.
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

    /// What `docs/public-hosts.md` says each issuer and access-token
    /// destination receives, word for word.
    ///
    /// Pinned rather than matched. Two rounds of matching words in the
    /// prose were each beaten by a sentence that used the words and said
    /// the opposite. A pinned cell cannot drift: changing the table, or
    /// the set of hosts the code sends a token to, fails a test until this
    /// list is changed in the same diff, where a reader checks the text.
    /// What the text means is that reader's job, not this test's.
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

    /// Words that name a session credential. No row outside [`PINNED`] may
    /// use any of them, in any case and in any position.
    const SESSION_WORDS: &[&str] = &["access", "refresh", "device"];

    /// Every way the public hosts table disagrees with [`PINNED`].
    ///
    /// Reads every row in the file with three cells and a host in the
    /// first, in any table, so a second table cannot hide a row: a pinned
    /// host repeated there is held to its pin, and any other host to the
    /// word rule, wherever the row is.
    fn table_errors(table: &str) -> Vec<String> {
        let mut errors = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for line in table.lines().filter(|l| l.starts_with("| `")) {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            // `| a | b | c |` splits into five pieces; the documentation
            // table has two columns and four pieces.
            if cells.len() != 5 {
                continue;
            }
            let credentials = cells[3];
            for host in cells[1].split('`').skip(1).step_by(2) {
                seen.push(host.to_owned());
                match PINNED.iter().find(|(h, _)| *h == host) {
                    Some((_, pinned)) if credentials != *pinned => {
                        errors.push(format!(
                            "{host}: says \"{credentials}\", pinned \"{pinned}\""
                        ));
                    }
                    Some(_) => {}
                    None => {
                        let lower = credentials.to_ascii_lowercase();
                        for word in SESSION_WORDS {
                            if lower.contains(word) {
                                errors.push(format!(
                                    "{host}: receives no session credential, and says \"{word}\": \
                                     {credentials}"
                                ));
                            }
                        }
                    }
                }
            }
        }
        for (host, _) in PINNED {
            if !seen.iter().any(|s| s == host) {
                errors.push(format!("{host}: no row"));
            }
        }
        errors
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

    const TABLE: &str = include_str!("../../../docs/public-hosts.md");

    /// The table with one row's credentials cell replaced.
    fn with_cell(host: &str, cell: &str) -> String {
        let start = format!("| `{host}` |");
        TABLE
            .lines()
            .map(|line| {
                if line.starts_with(&start) {
                    let cells: Vec<&str> = line.split('|').collect();
                    format!("|{}|{}| {cell} |", cells[1], cells[2])
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_public_hosts_table_says_where_each_token_goes() {
        assert_eq!(table_errors(TABLE), Vec::<String>::new());
    }

    #[test]
    fn the_table_check_rejects_the_contradictions_it_exists_for() {
        // Every one of these was accepted by an earlier version of the
        // check, which matched words in the prose.
        for (host, cell) in [
            (
                "mcp-user-api.erpc.global",
                "the device code, and the MCP refresh token to the token and revoke endpoints \
                 only; never the access token",
            ),
            (
                "user-api.erpc.global",
                "auth-api access token, the device code and the auth-api refresh token",
            ),
            ("x402.erpc.global", "the MCP access token"),
            ("x402.erpc.global", "Access token for the MCP server"),
            (
                "x402.erpc.global",
                "the MCP Access Token and payment headers",
            ),
            ("dashboard.erpc.global", "the auth-api Refresh Token"),
            ("edge.erpc.global", "the access-token"),
            ("dl.erpc.global", "never a device code"),
            (
                "auth-api.erpc.global",
                "the device code and the refresh token, never to anything but the token and \
                 revoke endpoints; also the access token",
            ),
            (
                "auth-api.erpc.global",
                "the device code, and the refresh token to the token and revoke endpoints only",
            ),
            (
                "user-api.erpc.global",
                "auth-api access token only; never the device code, but the refresh token as well",
            ),
            ("user-api.erpc.global", "no access token"),
            ("user-api.erpc.global", "the MCP access token only"),
            ("user-api.erpc.global", "none"),
            (
                "mcp-user-api.erpc.global",
                "the device code, the MCP refresh token to the token and revoke endpoints, the \
                 auth-api refresh token and the auth-api access token",
            ),
        ] {
            let bad = with_cell(host, cell);
            assert_ne!(bad, TABLE, "the case must change the table: {host}");
            assert!(
                !table_errors(&bad).is_empty(),
                "{host} with \"{cell}\" was accepted"
            );
        }
    }

    #[test]
    fn a_row_cannot_be_hidden_or_dropped() {
        // A second table with the same header, repeating a pinned host with
        // a different cell. Read like the first, so held to the pin.
        let second = format!(
            "{TABLE}\n\n| Host | Purpose | Credentials that may be sent |\n|---|---|---|\n\
             | `user-api.erpc.global` | ERPC account API | auth-api refresh token |\n"
        );
        assert!(
            !table_errors(&second).is_empty(),
            "a second table was not read"
        );
        // A pinned host with no row at all.
        let dropped: String = TABLE
            .lines()
            .filter(|l| !l.starts_with("| `user-api.erpc.global` |"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_ne!(dropped, TABLE);
        assert!(
            table_errors(&dropped).iter().any(|e| e.ends_with("no row")),
            "a missing row was not noticed"
        );
    }
}
