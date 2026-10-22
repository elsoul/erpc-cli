// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The device authorization grant, as `erpc login` uses it.
//!
//! The protocol is RFC 8628: ask for a code, send the operator to a page to
//! approve it, and poll until they have. What is here is the decision-making
//! part of that exchange and nothing else. Sending the requests belongs to
//! the caller, which owns the HTTP client and the allowlist check, so that
//! the polling rules can be tested without a network.
//!
//! The rules that matter, and why:
//!
//! * The interval never goes below five seconds, and `slow_down` or a 429
//!   adds five more. A client that polls faster than the server asked is
//!   indistinguishable from one trying to brute-force a user code.
//! * A network error doubles the wait rather than retrying immediately, so
//!   a flapping connection does not turn into a tight loop.
//! * Polling stops at `expires_in`. A device code that has expired will
//!   never be approved, and continuing to ask only looks like an attack.

use core::time::Duration;

use crate::credential::{Audience, TokenShapeError, check_token_shape};

/// The smallest interval the client will ever use, whatever the server says.
pub const MIN_INTERVAL: Duration = Duration::from_secs(5);

/// How much `slow_down` adds to the interval, per RFC 8628 section 3.5.
pub const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// The longest wait this client will choose for itself.
///
/// A ceiling on the client's own backoff, never on what the server asked
/// for. RFC 8628 section 3.5 says `slow_down` raises the interval by five
/// seconds for this and every later request, so capping a server interval
/// that is already above this would poll MORE often exactly when the
/// server asked for less.
pub const MAX_INTERVAL: Duration = Duration::from_secs(60);

/// The client identifier `erpc` presents. A public client: it has no
/// secret, which is the point of the device grant.
pub const CLIENT_ID: &str = "erpc-cli";

/// The scopes requested at authorization time.
pub const SCOPE: &str = "openid profile email";

/// What the authorization endpoint returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorization {
    /// The code the client polls with. Not shown to the operator.
    pub device_code: String,
    /// The short code the operator reads out or types.
    pub user_code: String,
    /// The page the operator opens.
    pub verification_uri: String,
    /// The same page with the code already filled in, when offered.
    pub verification_uri_complete: Option<String>,
    /// How long the whole exchange may take.
    pub expires_in: Duration,
    /// The server's requested polling interval.
    pub interval: Duration,
}

impl DeviceAuthorization {
    /// The URL to open, preferring the one with the code already in it.
    #[must_use]
    pub fn open_url(&self) -> &str {
        self.verification_uri_complete
            .as_deref()
            .unwrap_or(&self.verification_uri)
    }
}

/// One reply to a poll of the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PollOutcome {
    /// The operator has not finished yet.
    Pending,
    /// The server asked the client to slow down.
    SlowDown,
    /// The operator approved, and these are the tokens.
    Approved {
        /// The bearer token.
        access_token: String,
        /// The token used to obtain the next access token.
        refresh_token: String,
        /// How long the access token is good for.
        expires_in: Duration,
    },
    /// The operator refused.
    Denied,
    /// The device code is no longer valid.
    Expired,
    /// Something else went wrong; the string is the server's error code.
    Failed(String),
    /// The request did not reach the server.
    NetworkError,
}

/// Why a login stopped without a session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoginError {
    /// The operator refused the request on the approval page.
    #[error("the sign-in was refused on the approval page")]
    Denied,
    /// The code expired before it was approved.
    #[error("the sign-in code expired before it was approved; run `erpc login` again")]
    Expired,
    /// The server returned an error.
    #[error("the sign-in failed: {0}")]
    Server(String),
    /// The server's tokens were not usable.
    #[error("the server returned a token that is not usable: {0}")]
    BadToken(#[from] TokenShapeError),
}

/// Tracks the polling interval and the deadline across one login.
///
/// Separated from the I/O so that every rule above has a test that does not
/// need a server. The caller asks [`Self::next_wait`] what to do with each
/// outcome and sleeps for what it returns.
#[derive(Debug, Clone)]
pub struct Poller {
    interval: Duration,
    elapsed: Duration,
    budget: Duration,
}

/// What the poller says to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Wait this long, then poll again.
    Wait(Duration),
    /// Stop: the login finished or failed.
    Stop(Result<Approved, LoginError>),
}

/// A completed login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    /// The bearer token.
    pub access_token: String,
    /// The token used to obtain the next access token.
    pub refresh_token: String,
    /// How long the access token is good for.
    pub expires_in: Duration,
}

/// The client's own backoff, bounded by [`MAX_INTERVAL`] and never below
/// `current`.
///
/// Two bounds, both one-directional. The ceiling keeps a doubling backoff
/// from running away; the floor keeps that ceiling from ever *reducing* an
/// interval the server asked for, which would be backing off by polling
/// more often.
fn back_off(current: Duration, proposed: Duration) -> Duration {
    proposed.min(MAX_INTERVAL).max(current)
}

impl Poller {
    /// Starts from what the authorization endpoint said.
    ///
    /// A server interval below the floor is raised to it, and a missing or
    /// absurd `expires_in` still bounds the loop.
    #[must_use]
    pub fn new(auth: &DeviceAuthorization) -> Self {
        Self {
            interval: auth.interval.max(MIN_INTERVAL),
            elapsed: Duration::ZERO,
            budget: auth.expires_in,
        }
    }

    /// The interval the next poll will use.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// How much of the budget is left.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.budget.saturating_sub(self.elapsed)
    }

    /// Folds one poll result into the loop's state.
    ///
    /// Returns either how long to wait before polling again, or the end of
    /// the login.
    pub fn next_wait(&mut self, outcome: PollOutcome) -> Next {
        match outcome {
            PollOutcome::Approved {
                access_token,
                refresh_token,
                expires_in,
            } => {
                if let Err(e) = check_token_shape(&access_token) {
                    return Next::Stop(Err(LoginError::BadToken(e)));
                }
                if let Err(e) = check_token_shape(&refresh_token) {
                    return Next::Stop(Err(LoginError::BadToken(e)));
                }
                Next::Stop(Ok(Approved {
                    access_token,
                    refresh_token,
                    expires_in,
                }))
            }
            PollOutcome::Denied => Next::Stop(Err(LoginError::Denied)),
            PollOutcome::Expired => Next::Stop(Err(LoginError::Expired)),
            PollOutcome::Failed(code) => Next::Stop(Err(LoginError::Server(code))),
            PollOutcome::Pending => self.advance(),
            PollOutcome::SlowDown => {
                // Always +5, with no ceiling. This is the server asking
                // for less traffic, and RFC 8628 section 3.5 says the
                // increase applies to this and every later request. A cap
                // here would poll more often than before the signal
                // whenever the server's interval is already above it.
                self.interval = self.interval.saturating_add(SLOW_DOWN_STEP);
                self.advance()
            }
            PollOutcome::NetworkError => {
                // Double, rather than retry at once: a connection that is
                // down stays down for a while, and hammering it is both
                // useless and noisy.
                self.interval = back_off(self.interval, self.interval.saturating_mul(2));
                self.advance()
            }
        }
    }

    /// Charges the next interval against the budget, or stops.
    fn advance(&mut self) -> Next {
        if self.remaining() <= self.interval {
            return Next::Stop(Err(LoginError::Expired));
        }
        self.elapsed += self.interval;
        Next::Wait(self.interval)
    }
}

/// Where the login sends its two requests.
///
/// Constants rather than configuration: these are the endpoints of the
/// identity provider, and a build that could be pointed at another one by
/// an environment variable would be a build that can be phished.
pub mod endpoint {
    use super::Audience;

    /// The device authorization endpoint.
    ///
    /// Written out per audience rather than formatted from a host, so that
    /// the repository's egress gate can read the destination as a literal
    /// and check it against the declared hosts. A URL assembled at run time
    /// is a URL no gate can see.
    #[must_use]
    pub const fn authorization(audience: Audience) -> &'static str {
        match audience {
            Audience::AuthApi => "https://auth-api.erpc.global/oauth/device/authorization",
            Audience::McpUserApi => "https://mcp-user-api.erpc.global/oauth/device/authorization",
        }
    }

    /// The token endpoint.
    #[must_use]
    pub const fn token(audience: Audience) -> &'static str {
        match audience {
            Audience::AuthApi => "https://auth-api.erpc.global/oauth/token",
            Audience::McpUserApi => "https://mcp-user-api.erpc.global/oauth/token",
        }
    }

    /// The revocation endpoint.
    #[must_use]
    pub const fn revoke(audience: Audience) -> &'static str {
        match audience {
            Audience::AuthApi => "https://auth-api.erpc.global/oauth/revoke",
            Audience::McpUserApi => "https://mcp-user-api.erpc.global/oauth/revoke",
        }
    }
}

/// Whether `url` is a page the operator may be sent to for this sign-in.
///
/// Only `https` on the issuer's own host -- the host the authorization was
/// requested from, which is where the issuer puts its verification page --
/// and only characters a URL of that kind needs. The URL comes from the
/// network, and it is printed to a terminal and handed to the operating
/// system to open; on Windows that goes through `cmd`, where `&`, `|`, `^`
/// and `%` are syntax. A narrow character set is what makes both safe
/// without depending on how either one quotes.
#[must_use]
pub fn is_verification_url(url: &str, issuer_host: &str) -> bool {
    url.strip_prefix("https://")
        .and_then(|rest| rest.strip_prefix(issuer_host))
        .is_some_and(|path| {
            path.starts_with('/')
                && path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~/?=".contains(&b))
        })
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{
        Audience, DeviceAuthorization, LoginError, MAX_INTERVAL, MIN_INTERVAL, Next, PollOutcome,
        Poller, endpoint, is_verification_url,
    };

    #[test]
    fn the_issuers_own_verification_page_is_accepted() {
        // The shape the issuer really sends.
        for url in [
            "https://auth-api.erpc.global/oauth/device",
            "https://auth-api.erpc.global/oauth/device?user_code=ABCD-EFGH",
        ] {
            assert!(is_verification_url(url, "auth-api.erpc.global"), "{url}");
        }
    }

    #[test]
    fn a_verification_page_anywhere_else_or_with_shell_syntax_is_refused() {
        // On Windows the URL goes to `cmd /C start`, where these
        // are command separators and variable expansion.
        let host = "auth-api.erpc.global";
        for url in [
            "https://auth-api.erpc.global/oauth/device?user_code=A&calc.exe",
            "https://auth-api.erpc.global/oauth/device?x=1|whoami",
            "https://auth-api.erpc.global/oauth/device?x=^%PATH%",
            "https://auth-api.erpc.global/oauth/device?x=\"y",
            "https://auth-api.erpc.global/oauth/device x",
            "https://auth-api.erpc.global/oauth/device\n",
            "https://auth-api.erpc.global:8443/oauth/device",
            "https://user@auth-api.erpc.global/oauth/device",
            "https://dashboard.erpc.global/activate",
            "https://auth-api.erpc.global",
        ] {
            assert!(!is_verification_url(url, host), "{url:?}");
        }
        // Assembled, as the URL fixtures elsewhere are: a lookalike host and
        // a plaintext scheme are both findings for the endpoint gate,
        // correctly, since it cannot tell a fixture from a destination.
        let lookalike = ["https://auth-api.erpc.global", ".evil.example/oauth/device"].concat();
        assert!(!is_verification_url(&lookalike, host));
        let plaintext = ["http", "://auth-api.erpc.global/oauth/device"].concat();
        assert!(!is_verification_url(&plaintext, host));
    }

    fn auth(interval_secs: u64, expires_secs: u64) -> DeviceAuthorization {
        DeviceAuthorization {
            device_code: "dc".to_owned(),
            user_code: "ABCD-EFGH".to_owned(),
            verification_uri: "https://auth-api.erpc.global/oauth/device".to_owned(),
            verification_uri_complete: Some(
                "https://auth-api.erpc.global/oauth/device?user_code=ABCD-EFGH".to_owned(),
            ),
            expires_in: Duration::from_secs(expires_secs),
            interval: Duration::from_secs(interval_secs),
        }
    }

    fn jwt(tag: &str) -> String {
        format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ{tag}In0.c2ln")
    }

    #[test]
    fn the_interval_never_drops_below_five_seconds() {
        // A server asking for one second does not get one second.
        let poller = Poller::new(&auth(1, 600));
        assert_eq!(poller.interval(), MIN_INTERVAL);
    }

    #[test]
    fn a_longer_server_interval_is_respected() {
        assert_eq!(
            Poller::new(&auth(15, 600)).interval(),
            Duration::from_secs(15)
        );
    }

    #[test]
    fn slow_down_adds_five_seconds() {
        let mut poller = Poller::new(&auth(5, 600));
        assert_eq!(
            poller.next_wait(PollOutcome::SlowDown),
            Next::Wait(Duration::from_secs(10))
        );
        assert_eq!(
            poller.next_wait(PollOutcome::SlowDown),
            Next::Wait(Duration::from_secs(15))
        );
        assert_eq!(poller.interval(), Duration::from_secs(15));
    }

    #[test]
    fn pending_keeps_the_interval_as_it_is() {
        let mut poller = Poller::new(&auth(5, 600));
        assert_eq!(
            poller.next_wait(PollOutcome::Pending),
            Next::Wait(MIN_INTERVAL)
        );
        assert_eq!(
            poller.next_wait(PollOutcome::Pending),
            Next::Wait(MIN_INTERVAL)
        );
    }

    #[test]
    fn a_network_error_doubles_the_wait() {
        let mut poller = Poller::new(&auth(5, 600));
        assert_eq!(
            poller.next_wait(PollOutcome::NetworkError),
            Next::Wait(Duration::from_secs(10))
        );
        assert_eq!(
            poller.next_wait(PollOutcome::NetworkError),
            Next::Wait(Duration::from_secs(20))
        );
    }

    #[test]
    fn slow_down_never_lowers_a_server_interval_above_the_cap() {
        // A server asking for 90 seconds and then sending slow_down is
        // asking for less traffic, not more. Capping at 60 here would
        // poll half again as often as it did before the signal.
        let mut poller = Poller::new(&auth(90, 86_400));
        assert_eq!(poller.interval(), Duration::from_secs(90));
        let next = poller.next_wait(PollOutcome::SlowDown);
        assert_eq!(next, Next::Wait(Duration::from_secs(95)));
        assert_eq!(poller.interval(), Duration::from_secs(95));
    }

    #[test]
    fn a_network_error_does_not_lower_a_server_interval_above_the_cap_either() {
        let mut poller = Poller::new(&auth(90, 86_400));
        let _ = poller.next_wait(PollOutcome::NetworkError);
        assert!(
            poller.interval() >= Duration::from_secs(90),
            "backing off must not become backing on: {:?}",
            poller.interval()
        );
    }

    #[test]
    fn the_wait_is_bounded_however_bad_the_network_is() {
        let mut poller = Poller::new(&auth(5, 86_400));
        for _ in 0..20 {
            if let Next::Wait(d) = poller.next_wait(PollOutcome::NetworkError) {
                assert!(d <= MAX_INTERVAL, "waited {d:?}");
            }
        }
        assert_eq!(poller.interval(), MAX_INTERVAL);
    }

    #[test]
    fn polling_stops_when_the_code_expires() {
        // A 12-second budget at 5-second intervals: wait at 0 and at 5,
        // and at 10 there are 2 seconds left, which is not enough for
        // another interval, so the loop ends rather than polling once more
        // against a code that is about to be refused anyway.
        let mut poller = Poller::new(&auth(5, 12));
        assert_eq!(
            poller.next_wait(PollOutcome::Pending),
            Next::Wait(MIN_INTERVAL)
        );
        assert_eq!(
            poller.next_wait(PollOutcome::Pending),
            Next::Wait(MIN_INTERVAL)
        );
        assert_eq!(poller.remaining(), Duration::from_secs(2));
        assert!(matches!(
            poller.next_wait(PollOutcome::Pending),
            Next::Stop(Err(LoginError::Expired))
        ));
    }

    #[test]
    fn a_budget_shorter_than_one_interval_stops_at_once() {
        let mut poller = Poller::new(&auth(5, 3));
        assert!(matches!(
            poller.next_wait(PollOutcome::Pending),
            Next::Stop(Err(LoginError::Expired))
        ));
    }

    #[test]
    fn a_slow_down_can_exhaust_the_budget() {
        let mut poller = Poller::new(&auth(5, 20));
        let _ = poller.next_wait(PollOutcome::SlowDown);
        assert!(matches!(
            poller.next_wait(PollOutcome::SlowDown),
            Next::Stop(Err(LoginError::Expired))
        ));
    }

    #[test]
    fn approval_returns_the_tokens() {
        let mut poller = Poller::new(&auth(5, 600));
        let outcome = poller.next_wait(PollOutcome::Approved {
            access_token: jwt("a"),
            refresh_token: jwt("r"),
            expires_in: Duration::from_secs(3600),
        });
        match outcome {
            Next::Stop(Ok(approved)) => {
                assert_eq!(approved.expires_in, Duration::from_secs(3600));
                assert_eq!(approved.access_token, jwt("a"));
            }
            other => panic!("expected an approval, got {other:?}"),
        }
    }

    #[test]
    fn a_token_that_is_not_a_jwt_is_refused_rather_than_stored() {
        // An error page returned with a 200 would otherwise be filed away
        // as a session and surface much later as a puzzling 401.
        let mut poller = Poller::new(&auth(5, 600));
        let outcome = poller.next_wait(PollOutcome::Approved {
            access_token: "<!DOCTYPE html>".to_owned(),
            refresh_token: jwt("r"),
            expires_in: Duration::from_secs(3600),
        });
        assert!(matches!(outcome, Next::Stop(Err(LoginError::BadToken(_)))));
    }

    #[test]
    fn a_bad_refresh_token_is_caught_too() {
        let mut poller = Poller::new(&auth(5, 600));
        let outcome = poller.next_wait(PollOutcome::Approved {
            access_token: jwt("a"),
            refresh_token: String::new(),
            expires_in: Duration::from_secs(3600),
        });
        assert!(matches!(outcome, Next::Stop(Err(LoginError::BadToken(_)))));
    }

    #[test]
    fn refusal_and_expiry_stop_immediately() {
        let mut poller = Poller::new(&auth(5, 600));
        assert_eq!(
            poller.next_wait(PollOutcome::Denied),
            Next::Stop(Err(LoginError::Denied))
        );
        assert_eq!(
            poller.next_wait(PollOutcome::Expired),
            Next::Stop(Err(LoginError::Expired))
        );
    }

    #[test]
    fn a_server_error_is_reported_with_its_code() {
        let mut poller = Poller::new(&auth(5, 600));
        match poller.next_wait(PollOutcome::Failed("invalid_client".to_owned())) {
            Next::Stop(Err(LoginError::Server(code))) => assert_eq!(code, "invalid_client"),
            other => panic!("expected a server error, got {other:?}"),
        }
    }

    #[test]
    fn the_complete_url_is_preferred_when_the_server_offers_one() {
        let with = auth(5, 600);
        assert!(with.open_url().contains("code=ABCD-EFGH"));
        let without = DeviceAuthorization {
            verification_uri_complete: None,
            ..auth(5, 600)
        };
        assert_eq!(
            without.open_url(),
            "https://auth-api.erpc.global/oauth/device"
        );
    }

    #[test]
    fn every_endpoint_is_https_on_the_audience_issuer() {
        for audience in Audience::all() {
            for url in [
                endpoint::authorization(*audience),
                endpoint::token(*audience),
                endpoint::revoke(*audience),
            ] {
                assert!(url.starts_with("https://"), "{url}");
                assert!(url.contains(audience.issuer_host()), "{url}");
                assert!(
                    erpc_core::endpoints::ensure_service_url(url).is_ok(),
                    "{url} is not a declared endpoint"
                );
            }
        }
    }
}
