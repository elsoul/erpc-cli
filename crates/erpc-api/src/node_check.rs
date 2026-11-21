// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The fixed local node check's wire protocol.

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::ApiError;

/// The node check endpoint.
pub const NODE_CHECK_URL: &str = "https://user-api.erpc.global/v3/ai/node-check";

/// The only check recognized by this client.
pub const SOLANA_RPC_BIND: &str = "solana_rpc_bind";

/// A classification of the local namespace's TCP 8899 listeners.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    /// A wildcard or non-loopback binding was found.
    NonLoopback,
    /// All observed bindings were loopback.
    LoopbackOnly,
    /// No listener was observed.
    NotListening,
    /// The listener tables could not be inspected completely.
    Unknown,
}

/// The service's finding for the provided observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    /// Review the wildcard or non-loopback binding.
    ReviewBinding,
    /// Only loopback bindings were observed.
    LoopbackBinding,
    /// No listener was observed.
    NoListener,
    /// The check could not classify the bindings.
    Inconclusive,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    finding: Finding,
}

fn body(observation: Observation) -> serde_json::Value {
    json!({ "check": SOLANA_RPC_BIND, "observation": observation })
}

fn reply(status: u16, body: &str, observation: Observation) -> Result<Finding, ApiError> {
    let invalid = || ApiError::Malformed("invalid node check response".to_owned());
    let expected = match observation {
        Observation::NonLoopback => Finding::ReviewBinding,
        Observation::LoopbackOnly => Finding::LoopbackBinding,
        Observation::NotListening => Finding::NoListener,
        Observation::Unknown => Finding::Inconclusive,
    };
    match status {
        200 if body.trim_start().starts_with('{') => {
            let finding = serde_json::from_str::<Reply>(body)
                .map_err(|_| invalid())?
                .finding;
            if finding != expected {
                return Err(invalid());
            }
            Ok(finding)
        }
        200 => Err(invalid()),
        401 => Err(ApiError::Unauthorized),
        other => Err(ApiError::Status(other)),
    }
}

/// Submits a classification to the fixed endpoint with the account's token.
///
/// # Errors
/// Returns an API error when the request fails or the response is invalid.
pub async fn check(
    client: &AuthClient,
    access_token: &SecretString,
    observation: Observation,
) -> Result<Finding, ApiError> {
    let (status, response) = client
        .post_with_token(
            Audience::AuthApi,
            NODE_CHECK_URL,
            access_token,
            body(observation).to_string().into_bytes(),
            None,
        )
        .await?;
    reply(status, &response, observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_allowed_for_the_account_token() {
        assert!(erpc_core::endpoints::ensure_service_url(NODE_CHECK_URL).is_ok());
        assert!(
            erpc_auth::allowlist::ensure_token_destination(Audience::AuthApi, NODE_CHECK_URL)
                .is_ok()
        );
    }

    #[test]
    fn request_contains_only_the_fixed_check_and_observation() {
        for (observation, value) in [
            (Observation::NonLoopback, "non_loopback"),
            (Observation::LoopbackOnly, "loopback_only"),
            (Observation::NotListening, "not_listening"),
            (Observation::Unknown, "unknown"),
        ] {
            assert_eq!(
                body(observation),
                json!({"check": "solana_rpc_bind", "observation": value})
            );
        }
    }

    #[test]
    fn response_accepts_only_the_four_findings() {
        for (value, observation, finding) in [
            (
                "review_binding",
                Observation::NonLoopback,
                Finding::ReviewBinding,
            ),
            (
                "loopback_binding",
                Observation::LoopbackOnly,
                Finding::LoopbackBinding,
            ),
            (
                "no_listener",
                Observation::NotListening,
                Finding::NoListener,
            ),
            ("inconclusive", Observation::Unknown, Finding::Inconclusive),
        ] {
            let response = json!({"finding": value}).to_string();
            assert!(matches!(reply(200, &response, observation), Ok(actual) if actual == finding));
        }
        for invalid in [
            r#"{"finding":"arbitrary text"}"#,
            r#"{"finding":"no_listener","extra":"arbitrary text"}"#,
            r#"{"finding":"no_listener","finding":"inconclusive"}"#,
            r#"{"finding":null}"#,
            r#"{"finding":"review_binding"}"#,
            "{}",
            r#"["no_listener"]"#,
        ] {
            assert!(
                matches!(reply(200, invalid, Observation::NotListening), Err(ApiError::Malformed(message)) if message == "invalid node check response")
            );
        }
        assert!(matches!(
            reply(401, "arbitrary text", Observation::Unknown),
            Err(ApiError::Unauthorized)
        ));
        assert!(matches!(
            reply(503, "arbitrary text", Observation::Unknown),
            Err(ApiError::Status(503))
        ));
    }
}
