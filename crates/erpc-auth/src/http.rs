// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The requests `erpc-auth` sends, and the one client that sends them.
//!
//! The decision-making lives in [`crate::device_flow`]; this module is the
//! part that touches the network. Keeping them apart is what lets the
//! polling rules be tested without a server, and it means every rule this
//! module has to honour is stated somewhere that has its own tests.
//!
//! Two properties are enforced here and nowhere else:
//!
//! * A session token is attached only to a destination
//!   [`crate::allowlist`] permits, checked immediately before the request
//!   is built, not when the URL was chosen.
//! * The identity endpoints are the constants in [`crate::device_flow`].
//!   Nothing reads a base URL from configuration or the environment,
//!   because a build that can be pointed at another identity provider is a
//!   build that can be phished.

use core::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use crate::allowlist::{self, AllowlistError};
use crate::credential::{Audience, Credential};
use crate::device_flow::{CLIENT_ID, DeviceAuthorization, PollOutcome, SCOPE, endpoint};

/// How long any single request may take.
///
/// The poll loop has its own schedule, so a request that hangs must not be
/// allowed to stall it past the device code's lifetime.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What went wrong talking to the identity provider.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpError {
    /// The client could not be built.
    #[error("could not start an HTTPS client: {0}")]
    Client(String),
    /// The request did not reach the server, or the reply was unreadable.
    #[error("could not reach {host}: {reason}")]
    Transport {
        /// The host that was being contacted.
        host: &'static str,
        /// What went wrong.
        reason: String,
    },
    /// The server answered with something this client cannot read.
    #[error("{host} returned a reply this version cannot read: {reason}")]
    Malformed {
        /// The host that answered.
        host: &'static str,
        /// What was wrong with it.
        reason: String,
    },
    /// The server refused.
    #[error("{host} refused the request with {status}")]
    Status {
        /// The host that answered.
        host: &'static str,
        /// The HTTP status.
        status: u16,
    },
    /// A token was about to be sent somewhere it may not go.
    #[error(transparent)]
    Allowlist(#[from] AllowlistError),
}

/// An HTTPS client for the ERPC identity and account APIs.
#[derive(Debug, Clone)]
pub struct AuthClient {
    inner: reqwest::Client,
}

impl AuthClient {
    /// Builds a client.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Client`] when the TLS stack cannot start.
    pub fn new() -> Result<Self, HttpError> {
        let inner = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .https_only(true)
            .user_agent(concat!("erpc/", env!("CARGO_PKG_VERSION")))
            // A redirect is how a request to an allowed host ends up at
            // one that is not. The allowlist is checked before the
            // request; following a redirect would move the destination
            // afterwards, where nothing checks it again.
            //
            // NOT covered by a test, and worth saying so rather than
            // implying otherwise: observing it needs a TLS server on
            // loopback, and this client validates certificates against
            // the system roots, so a self-signed one would be refused
            // before the redirect could be seen. What is tested is the
            // setting beside it -- plaintext is refused outright, so a
            // redirect to an `http://` URL cannot be followed either --
            // and the allowlist check this backs up.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| HttpError::Client(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Starts a device authorization.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError`] when the request fails or the reply is not a
    /// device authorization.
    pub async fn authorize(&self, audience: Audience) -> Result<DeviceAuthorization, HttpError> {
        let host = audience.issuer_host();
        let response = self
            .inner
            .post(endpoint::authorization(audience))
            .form(&[("client_id", CLIENT_ID), ("scope", SCOPE)])
            .send()
            .await
            .map_err(|e| HttpError::Transport {
                host,
                reason: e.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(HttpError::Status {
                host,
                status: status.as_u16(),
            });
        }
        let body: AuthorizationBody = response.json().await.map_err(|e| HttpError::Malformed {
            host,
            reason: e.to_string(),
        })?;
        body.into_authorization(host)
    }

    /// Polls the token endpoint once.
    ///
    /// Network failures are returned as [`PollOutcome::NetworkError`]
    /// rather than as an error, because the poll loop treats them as a
    /// reason to wait longer rather than to give up.
    pub async fn poll_token(&self, audience: Audience, device_code: &str) -> PollOutcome {
        let request = self.inner.post(endpoint::token(audience)).form(&[
            ("client_id", CLIENT_ID),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
        ]);
        let Ok(response) = request.send().await else {
            return PollOutcome::NetworkError;
        };
        let status = response.status();
        // 429 is the other way a server says slow down.
        if status.as_u16() == 429 {
            return PollOutcome::SlowDown;
        }
        let Ok(body) = response.json::<TokenBody>().await else {
            return PollOutcome::NetworkError;
        };
        body.into_outcome(status.is_success())
    }

    /// Asks the issuer to invalidate a refresh token.
    ///
    /// Failure is reported, not raised: revocation is cleanup, and a
    /// caller in the middle of recovering from an earlier failure should
    /// not be derailed by it.
    pub async fn revoke(&self, audience: Audience, refresh_token: &SecretString) -> bool {
        self.inner
            .post(endpoint::revoke(audience))
            .form(&[
                ("client_id", CLIENT_ID),
                ("token", refresh_token.expose_secret()),
                ("token_type_hint", "refresh_token"),
            ])
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
    }

    /// Exchanges a refresh token for a new session.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError`] when the exchange fails. A `400` from the
    /// issuer means the refresh token is spent or the family was revoked,
    /// and the caller must sign in again.
    pub async fn refresh(
        &self,
        audience: Audience,
        refresh_token: &SecretString,
        now: i64,
    ) -> Result<Credential, HttpError> {
        let host = audience.issuer_host();
        let response = self
            .inner
            .post(endpoint::token(audience))
            .form(&[
                ("client_id", CLIENT_ID),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.expose_secret()),
            ])
            .send()
            .await
            .map_err(|e| HttpError::Transport {
                host,
                reason: e.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(HttpError::Status {
                host,
                status: status.as_u16(),
            });
        }
        let body: TokenBody = response.json().await.map_err(|e| HttpError::Malformed {
            host,
            reason: e.to_string(),
        })?;
        body.into_credential(host, now)
    }

    /// Sends a GET with no token and returns only the status.
    ///
    /// Exists so a test can observe what the client does with a redirect
    /// without going through the allowlist, which would refuse a loopback
    /// address before the client was reached. Carries no credential, so
    /// it cannot disclose one.
    #[cfg(test)]
    pub(crate) async fn probe_for_test(&self, url: &str) -> Result<u16, HttpError> {
        let response = self
            .inner
            .get(url)
            .send()
            .await
            .map_err(|e| HttpError::Transport {
                host: "probe",
                reason: e.to_string(),
            })?;
        Ok(response.status().as_u16())
    }

    /// Sends an authenticated GET and returns the status and body.
    ///
    /// The allowlist is checked here, against the URL this call will
    /// actually use.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Allowlist`] when `url` is not a destination
    /// this audience's token may go to, and [`HttpError::Transport`] when
    /// the request fails.
    pub async fn get_with_token(
        &self,
        audience: Audience,
        url: &str,
        access_token: &SecretString,
    ) -> Result<(u16, String), HttpError> {
        allowlist::ensure_token_destination(audience, url)?;
        let host = audience.issuer_host();
        let response = self
            .inner
            .get(url)
            .bearer_auth(access_token.expose_secret())
            .send()
            .await
            .map_err(|e| HttpError::Transport {
                host,
                reason: e.to_string(),
            })?;
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        Ok((status, text))
    }
}

/// The device authorization reply, as RFC 8628 defines it.
#[derive(Debug, Deserialize)]
struct AuthorizationBody {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

impl AuthorizationBody {
    fn into_authorization(self, host: &'static str) -> Result<DeviceAuthorization, HttpError> {
        if self.device_code.is_empty() || self.user_code.is_empty() {
            return Err(HttpError::Malformed {
                host,
                reason: "the authorization reply has no device or user code".to_owned(),
            });
        }
        if self.expires_in == 0 {
            return Err(HttpError::Malformed {
                host,
                reason: "the authorization reply expires immediately".to_owned(),
            });
        }
        Ok(DeviceAuthorization {
            device_code: self.device_code,
            user_code: self.user_code,
            verification_uri: self.verification_uri,
            verification_uri_complete: self.verification_uri_complete,
            expires_in: Duration::from_secs(self.expires_in),
            // RFC 8628 says five seconds when the server does not say.
            interval: Duration::from_secs(self.interval.unwrap_or(5)),
        })
    }
}

/// The token endpoint's reply, success or error.
#[derive(Debug, Deserialize)]
struct TokenBody {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

impl TokenBody {
    /// Reads one poll reply.
    fn into_outcome(self, success: bool) -> PollOutcome {
        if let Some(error) = self.error {
            return match error.as_str() {
                "authorization_pending" => PollOutcome::Pending,
                "slow_down" => PollOutcome::SlowDown,
                "access_denied" => PollOutcome::Denied,
                "expired_token" => PollOutcome::Expired,
                other => PollOutcome::Failed(other.to_owned()),
            };
        }
        if !success {
            return PollOutcome::Failed("the server refused without saying why".to_owned());
        }
        let (Some(access_token), Some(refresh_token)) = (self.access_token, self.refresh_token)
        else {
            return PollOutcome::Failed("the reply has no tokens in it".to_owned());
        };
        PollOutcome::Approved {
            access_token,
            refresh_token,
            expires_in: Duration::from_secs(self.expires_in.unwrap_or(0)),
        }
    }

    /// Reads a refresh reply.
    fn into_credential(self, host: &'static str, now: i64) -> Result<Credential, HttpError> {
        let (Some(access_token), Some(refresh_token), Some(expires_in)) =
            (self.access_token, self.refresh_token, self.expires_in)
        else {
            return Err(HttpError::Malformed {
                host,
                reason: "the refresh reply is missing a token or its lifetime".to_owned(),
            });
        };
        for token in [&access_token, &refresh_token] {
            crate::credential::check_token_shape(token).map_err(|e| HttpError::Malformed {
                host,
                reason: e.to_string(),
            })?;
        }
        let lifetime = i64::try_from(expires_in).unwrap_or(i64::MAX);
        Ok(Credential {
            access_token: SecretString::from(access_token),
            refresh_token: SecretString::from(refresh_token),
            expires_at: now.saturating_add(lifetime),
        })
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{AuthorizationBody, HttpError, TokenBody};
    use crate::device_flow::PollOutcome;

    const HOST: &str = "auth-api.erpc.global";

    fn jwt(tag: &str) -> String {
        format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ{tag}In0.c2ln")
    }

    #[test]
    fn an_authorization_reply_is_read() {
        let body: AuthorizationBody = serde_json::from_str(
            r#"{"device_code":"dc","user_code":"ABCD","verification_uri":"https://dashboard.erpc.global/activate","expires_in":600,"interval":5}"#,
        )
        .expect("parses");
        let auth = body.into_authorization(HOST).expect("valid");
        assert_eq!(auth.expires_in, Duration::from_secs(600));
        assert_eq!(auth.interval, Duration::from_secs(5));
        assert_eq!(auth.verification_uri_complete, None);
    }

    #[test]
    fn a_missing_interval_defaults_to_five_seconds() {
        // RFC 8628 section 3.2: five seconds when the server is silent.
        let body: AuthorizationBody = serde_json::from_str(
            r#"{"device_code":"dc","user_code":"ABCD","verification_uri":"https://dashboard.erpc.global/activate","expires_in":600}"#,
        )
        .expect("parses");
        let auth = body.into_authorization(HOST).expect("valid");
        assert_eq!(auth.interval, Duration::from_secs(5));
    }

    #[test]
    fn an_authorization_reply_without_codes_is_refused() {
        let body: AuthorizationBody = serde_json::from_str(
            r#"{"device_code":"","user_code":"","verification_uri":"https://dashboard.erpc.global/x","expires_in":600}"#,
        )
        .expect("parses");
        assert!(matches!(
            body.into_authorization(HOST),
            Err(HttpError::Malformed { .. })
        ));
    }

    #[test]
    fn an_authorization_that_expires_at_once_is_refused() {
        let body: AuthorizationBody = serde_json::from_str(
            r#"{"device_code":"dc","user_code":"ABCD","verification_uri":"https://dashboard.erpc.global/x","expires_in":0}"#,
        )
        .expect("parses");
        assert!(matches!(
            body.into_authorization(HOST),
            Err(HttpError::Malformed { .. })
        ));
    }

    #[test]
    fn each_oauth_error_maps_to_its_outcome() {
        for (error, expected) in [
            ("authorization_pending", PollOutcome::Pending),
            ("slow_down", PollOutcome::SlowDown),
            ("access_denied", PollOutcome::Denied),
            ("expired_token", PollOutcome::Expired),
        ] {
            let body: TokenBody =
                serde_json::from_str(&format!(r#"{{"error":"{error}"}}"#)).expect("parses");
            assert_eq!(body.into_outcome(false), expected, "{error}");
        }
    }

    #[test]
    fn an_unknown_oauth_error_carries_its_code() {
        let body: TokenBody =
            serde_json::from_str(r#"{"error":"invalid_client"}"#).expect("parses");
        assert_eq!(
            body.into_outcome(false),
            PollOutcome::Failed("invalid_client".to_owned())
        );
    }

    #[test]
    fn an_approval_carries_both_tokens() {
        let raw = format!(
            r#"{{"access_token":"{}","refresh_token":"{}","expires_in":3600}}"#,
            jwt("a"),
            jwt("r")
        );
        let body: TokenBody = serde_json::from_str(&raw).expect("parses");
        match body.into_outcome(true) {
            PollOutcome::Approved { expires_in, .. } => {
                assert_eq!(expires_in, Duration::from_secs(3600));
            }
            other => panic!("expected an approval, got {other:?}"),
        }
    }

    #[test]
    fn a_success_with_no_tokens_is_a_failure_not_an_approval() {
        let body: TokenBody = serde_json::from_str("{}").expect("parses");
        assert!(matches!(body.into_outcome(true), PollOutcome::Failed(_)));
    }

    #[test]
    fn a_refresh_reply_becomes_a_credential_with_an_absolute_expiry() {
        let raw = format!(
            r#"{{"access_token":"{}","refresh_token":"{}","expires_in":3600}}"#,
            jwt("a"),
            jwt("r")
        );
        let body: TokenBody = serde_json::from_str(&raw).expect("parses");
        let cred = body.into_credential(HOST, 1_000).expect("valid");
        assert_eq!(cred.expires_at, 4_600);
    }

    #[test]
    fn a_refresh_reply_with_a_token_that_is_not_a_jwt_is_refused() {
        let raw = format!(
            r#"{{"access_token":"<!DOCTYPE html>","refresh_token":"{}","expires_in":3600}}"#,
            jwt("r")
        );
        let body: TokenBody = serde_json::from_str(&raw).expect("parses");
        assert!(matches!(
            body.into_credential(HOST, 1_000),
            Err(HttpError::Malformed { .. })
        ));
    }

    #[test]
    fn a_refresh_reply_missing_a_lifetime_is_refused() {
        let raw = format!(
            r#"{{"access_token":"{}","refresh_token":"{}"}}"#,
            jwt("a"),
            jwt("r")
        );
        let body: TokenBody = serde_json::from_str(&raw).expect("parses");
        assert!(matches!(
            body.into_credential(HOST, 1_000),
            Err(HttpError::Malformed { .. })
        ));
    }
}

/// Tests that need a server. Each one removes the doubt that a client
/// setting is only a comment: every control here fails the test when the
/// builder line is deleted.
#[cfg(test)]
mod client_tests {
    use super::{AuthClient, HttpError};
    use crate::credential::Audience;
    use secrecy::SecretString;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    /// Serves one request with the given response, and returns its port.
    async fn serve_once(response: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0_u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        });
        port
    }

    #[tokio::test]
    async fn the_client_refuses_plaintext_even_to_a_server_that_answers() {
        // `.https_only(true)`. The server here really does answer, so a
        // client without that setting returns 200 and this test fails;
        // with it, the request is refused before a byte leaves. That is
        // what makes this a test of the setting and not of the network.
        let port = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").await;
        let client = AuthClient::new().expect("a client");
        let url = format!("{}127.0.0.1:{port}/", "http://");
        assert!(
            client.probe_for_test(&url).await.is_err(),
            "plaintext must not be sent at all"
        );
    }

    #[tokio::test]
    async fn an_allowed_host_over_plaintext_still_carries_no_token() {
        let client = AuthClient::new().expect("a client");
        let url = format!("{}user-api.erpc.global/v3/user/get", "http://");
        assert!(matches!(
            client
                .get_with_token(
                    Audience::AuthApi,
                    &url,
                    &SecretString::from("a.b.c".to_owned()),
                )
                .await,
            Err(HttpError::Allowlist(_))
        ));
    }
}
