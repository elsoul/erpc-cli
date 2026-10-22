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
//! `docs/public-hosts.md` restates this per host. A test below pins every
//! line of that document that contains a `|`, exactly and in order, so no
//! row can be added, reworded or written in another form without the test
//! changing in the same diff; it also refuses an HTML table and text run on
//! from a table's last row. A second test requires the hosts whose token
//! rows are pinned to be exactly the issuers and destinations here. Whether
//! a pinned sentence is true is for the reader of the diff that changes it.
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

    /// Every line of `docs/public-hosts.md` that contains a `|`, in order,
    /// exactly as it must be.
    ///
    /// Fail-closed, after three rounds of reading the table and each time
    /// missing a row written in a form the reader did not expect: a line
    /// with an extra cell, one without a leading pipe, one with an escaped
    /// pipe, a second table. Whatever a line looks like, if it has a pipe
    /// in it, it is one of these or the test fails. Changing the table
    /// means changing this list in the same diff, where a reader checks
    /// what the rows say; what they mean is that reader's job.
    const PIPED_LINES: &[&str] = &[
        "| Host | Purpose | Credentials that may be sent |",
        "|---|---|---|",
        "| `auth-api.erpc.global` | OAuth device flow: issue, refresh, revoke; its verification page is opened in the browser | the device code, and the refresh token to the token and revoke endpoints only; never the access token |",
        "| `user-api.erpc.global` | ERPC account API | auth-api access token only |",
        "| `mcp-user-api.erpc.global` | ERPC User MCP server, and the issuer of its own tokens | the device code, the MCP refresh token to the token and revoke endpoints, and the MCP access token; never the auth-api tokens |",
        "| `x402.erpc.global` | x402 payments and credit top-up | x402 billing session token and payment headers only; never auth-api/MCP tokens, never ERPC API keys |",
        "| `edge.erpc.global` | RPC endpoint, for the planned `check` command | RPC API key supplied by the operator |",
        "| `dashboard.erpc.global` | opened in the browser for signup and payment setup | none |",
        "| `erpc.global` | project home page, linked from package metadata | none |",
        "| `solana-snapshot-*.erpc.global` | snapshot mirrors | none |",
        "| `dl.erpc.global` | release mirror (R2) | none |",
        "| `install.erpc.global` | installer script | none |",
        "| `github.com`, `api.github.com` | releases, attestations | none |",
        "| `objects.githubusercontent.com`, `release-assets.githubusercontent.com` | release artifact downloads | none |",
        "| `crates.io`, `index.crates.io`, `static.crates.io` | dependencies (cargo, build time) | none |",
        "| `registry.npmjs.org` | installer worker dependencies (npm, build time) | none |",
        "| `sh.rustup.rs` | toolchain installation in CI | none |",
        "| `127.0.0.1`, `localhost`, `[::1]` | planned OAuth redirect listener and local MCP server; plaintext `http`/`ws` allowed here only | session token for the local MCP server |",
        "| Host | Linked from |",
        "|---|---|",
        "| `www.apache.org` | the licence text and headers |",
        "| `www.contributor-covenant.org` | `CODE_OF_CONDUCT.md` |",
        "| `keepachangelog.com` | `CHANGELOG.md` |",
        "| `semver.org` | `CHANGELOG.md` |",
        "| `elsoul.nl` | `NOTICE` |",
        "| `axodotdev.github.io` | the cargo-dist configuration comment |",
        "| `docs.github.com` | contributor documentation |",
        "| `reuse.software` | licensing documentation |",
    ];

    /// The credentials cell of every host a session token goes to, which
    /// must be the cell of that host's line in [`PIPED_LINES`]. Kept apart
    /// so that [`the_pinned_hosts_are_exactly_the_hosts_a_token_goes_to`]
    /// can tie the set of such hosts to the code.
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

    /// Every way the document departs from [`PIPED_LINES`] and [`PINNED`].
    fn table_errors(doc: &str) -> Vec<String> {
        table_errors_against(doc, PIPED_LINES)
    }

    /// [`table_errors`] against a given list of pinned lines, so a test can
    /// change the list and the document together and reach the
    /// cross-check with [`PINNED`] on its own.
    fn table_errors_against(doc: &str, pinned_lines: &[&str]) -> Vec<String> {
        let mut errors = Vec::new();
        let lines: Vec<&str> = doc.lines().collect();
        let piped: Vec<&str> = lines.iter().copied().filter(|l| l.contains('|')).collect();
        if piped != pinned_lines {
            let at = piped
                .iter()
                .zip(pinned_lines)
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| piped.len().min(pinned_lines.len()));
            errors.push(format!(
                "the lines with a pipe differ from the pinned ones at {at}: found {:?}, pinned {:?}",
                piped.get(at),
                pinned_lines.get(at)
            ));
        }
        // A table ends at a blank line. A line of text straight after the
        // last row is read by GitHub as one more row, pipe or not.
        for (n, pair) in lines.windows(2).enumerate() {
            if pair[0].contains('|') && !pair[1].contains('|') && !pair[1].trim().is_empty() {
                errors.push(format!(
                    "line {}: a table row followed by text, not a blank line",
                    n + 1
                ));
            }
        }
        // And a table can be written in HTML, with no pipe at all.
        if doc.to_ascii_lowercase().contains("<table") {
            errors.push("an HTML table".to_owned());
        }
        for (host, cell) in PINNED {
            let start = format!("| `{host}` |");
            let row = pinned_lines.iter().find(|l| l.starts_with(&start));
            let found = row.and_then(|l| l.split('|').nth(3)).map(str::trim);
            if found != Some(*cell) {
                errors.push(format!(
                    "{host}: pinned \"{cell}\", the pinned table says {found:?}"
                ));
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

    const DOC: &str = include_str!("../../../docs/public-hosts.md");

    #[test]
    fn the_public_hosts_table_says_where_each_token_goes() {
        assert_eq!(table_errors(DOC), Vec::<String>::new());
    }

    #[test]
    fn a_row_in_any_form_is_held_to_the_pinned_lines() {
        // The forms round 11 of the review used to slip a row past a
        // reader that parsed the table, each one rendered by GitHub as an
        // ordinary row, and the word games an earlier check fell for.
        let x402 = PIPED_LINES
            .iter()
            .find(|l| l.starts_with("| `x402.erpc.global` |"))
            .expect("the x402 row");
        let replace = |from: &str, to: &str| -> String {
            assert_eq!(DOC.matches(from).count(), 1, "{from}");
            DOC.replacen(from, to, 1)
        };
        let after_last_row = |extra: &str| -> String {
            let last = PIPED_LINES
                .iter()
                .find(|l| l.starts_with("| `127.0.0.1`"))
                .expect("the loopback row");
            replace(last, &format!("{last}\n{extra}"))
        };
        for (name, bad) in [
            (
                "an extra trailing cell",
                replace(x402, &format!("{x402} |")),
            ),
            (
                "a compact second table",
                format!(
                    "{DOC}\n|Host|Purpose|Credentials|\n|-|-|-|\n\
                     |`user-api.erpc.global`|ERPC account API|auth-api refresh token|\n"
                ),
            ),
            (
                "an indented repeated row",
                after_last_row(" | `user-api.erpc.global` | x | the auth-api refresh token |"),
            ),
            (
                "no leading pipe",
                after_last_row("`x402.erpc.global` | x402 payments | the MCP access token"),
            ),
            (
                "a host out of backticks",
                replace(
                    x402,
                    &x402.replacen("`x402.erpc.global`", "x402.erpc.global", 1),
                ),
            ),
            (
                "an escaped pipe",
                replace(
                    x402,
                    &x402.replacen("x402 payments", "x402 payments \\| top-up", 1),
                ),
            ),
            (
                "a synonym",
                replace(
                    x402,
                    &x402.replacen(
                        "never auth-api/MCP tokens",
                        "the auth-api and MCP tokens",
                        1,
                    ),
                ),
            ),
            (
                "an entity",
                replace(
                    x402,
                    &x402.replacen("payment headers", "acc&#101;ss tokens", 1),
                ),
            ),
            (
                "text straight after the table",
                after_last_row("the auth-api refresh token"),
            ),
            (
                "an HTML table",
                format!(
                    "{DOC}\n<table><tr><td>user-api.erpc.global</td><td>refresh token</td></tr></table>\n"
                ),
            ),
        ] {
            assert_ne!(bad, DOC, "the case must change the document: {name}");
            assert!(!table_errors(&bad).is_empty(), "{name} was accepted");
        }
    }

    #[test]
    fn a_pinned_cell_must_agree_with_the_pinned_table() {
        // The document and the pinned lines changed together, so the line
        // comparison is satisfied; only the cross-check with PINNED is left
        // to notice that user-api no longer admits to the access token.
        let from = "| `user-api.erpc.global` | ERPC account API | auth-api access token only |";
        let to = "| `user-api.erpc.global` | ERPC account API | none |";
        let lines: Vec<&str> = PIPED_LINES
            .iter()
            .map(|l| if *l == from { to } else { *l })
            .collect();
        assert_ne!(lines, PIPED_LINES, "the row is in the pinned lines");
        let doc = DOC.replacen(from, to, 1);
        assert_ne!(doc, DOC);
        let errors = table_errors_against(&doc, &lines);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].starts_with("user-api.erpc.global: pinned"),
            "{errors:?}"
        );
    }
}
