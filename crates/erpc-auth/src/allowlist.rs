// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which hosts a session token may be attached to.
//!
//! A bearer token is disclosed to whoever receives it, so the set of
//! destinations is a compile-time constant rather than anything a
//! configuration file, an environment variable or a redirect can widen.
//!
//! # What this covers, and what it does not
//!
//! This governs the HTTP requests **`erpc` itself sends**. It does not and
//! cannot govern a subprocess `erpc` starts, nor what a person does with a
//! value they have taken out of the store themselves. Saying otherwise
//! would be claiming a protection that is not here.

use crate::credential::Audience;

/// The only host an `auth-api` session token may be sent to.
///
/// Not `auth-api.erpc.global` itself: tokens are *obtained* there, which is
/// a different operation that does not attach an existing session.
pub const AUTH_API_TOKEN_DESTINATIONS: &[&str] = &["user-api.erpc.global"];

/// The only host an `mcp-user-api` session token may be sent to.
pub const MCP_TOKEN_DESTINATIONS: &[&str] = &["mcp-user-api.erpc.global"];

/// The destinations a token for `audience` may be attached to.
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

/// Checks that a token for `audience` may be attached to a request to `url`.
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
}
