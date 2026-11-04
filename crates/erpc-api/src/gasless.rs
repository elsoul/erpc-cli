// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Buying ERPC Credit with EURC on Base, gas paid by ERPC: user-api's
//! gasless sessions.
//!
//! A session is prepared for an amount and a paying wallet (user-api quotes
//! it, VAT included, and returns the EIP-3009 transfer to sign), then the
//! signature is submitted and user-api relays it; the session's state says
//! when the credit is granted. A prepared session that will not be signed
//! is cancelled.

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::ApiError;

const SESSIONS_URL: &str = "https://user-api.erpc.global/v3/user/credit-gasless-sessions";

/// What user-api answered: the status and the session as it is now.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// The session, or user-api's failure body; `null` when not JSON.
    pub body: Value,
}

/// A session id: a UUID, checked before it goes into a path.
fn session_url(id: &str, tail: &str) -> Result<String, ApiError> {
    let ok = id.len() == 36
        && id.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    if ok {
        Ok(format!("{SESSIONS_URL}/{id}{tail}"))
    } else {
        Err(ApiError::Malformed(format!("{id:?} is not a session id")))
    }
}

fn reply(status: u16, text: &str) -> Result<Reply, ApiError> {
    if status == 401 {
        return Err(ApiError::Unauthorized);
    }
    Ok(Reply {
        status,
        body: serde_json::from_str(text).unwrap_or(Value::Null),
    })
}

async fn post(
    client: &AuthClient,
    token: &SecretString,
    url: &str,
    body: &Value,
) -> Result<Reply, ApiError> {
    let bytes = serde_json::to_vec(body).map_err(|e| ApiError::Malformed(e.to_string()))?;
    let (status, text) = client
        .post_with_token(Audience::AuthApi, url, token, bytes, None)
        .await?;
    reply(status, &text)
}

/// Prepares a session: `amount_credits` (1 to 10,000, 1 Credit = €0.01)
/// paid from `payer`. `client_request_id` (a UUID) makes a retry the same
/// session, not a second one.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] or the transport's error; a refusal is a
/// [`Reply`] with its status.
pub async fn prepare(
    client: &AuthClient,
    token: &SecretString,
    client_request_id: &str,
    amount_credits: u32,
    payer: &str,
) -> Result<Reply, ApiError> {
    let body = json!({
        "clientRequestId": client_request_id,
        "amountCredits": amount_credits,
        "payer": payer,
    });
    post(client, token, SESSIONS_URL, &body).await
}

/// Submits the signature (`0x` and 130 hex digits) for session `id`.
///
/// # Errors
///
/// As [`prepare`], and [`ApiError::Malformed`] for an id that is not one.
pub async fn submit(
    client: &AuthClient,
    token: &SecretString,
    id: &str,
    signature: &str,
) -> Result<Reply, ApiError> {
    let url = session_url(id, "/submit")?;
    post(client, token, &url, &json!({ "signature": signature })).await
}

/// Cancels session `id`, which will not be signed.
///
/// # Errors
///
/// As [`submit`].
pub async fn cancel(
    client: &AuthClient,
    token: &SecretString,
    id: &str,
) -> Result<Reply, ApiError> {
    let url = session_url(id, "/cancel")?;
    post(client, token, &url, &json!({})).await
}

/// Session `id` as it is now.
///
/// # Errors
///
/// As [`submit`].
pub async fn status(
    client: &AuthClient,
    token: &SecretString,
    id: &str,
) -> Result<Reply, ApiError> {
    let url = session_url(id, "")?;
    let (status, text) = client
        .get_with_token(Audience::AuthApi, &url, token)
        .await?;
    reply(status, &text)
}

#[cfg(test)]
mod tests {
    use super::session_url;

    #[test]
    fn only_a_uuid_goes_into_the_path() {
        assert_eq!(
            session_url("123e4567-e89b-42d3-a456-426614174000", "/submit").expect("url"),
            "https://user-api.erpc.global/v3/user/credit-gasless-sessions/123e4567-e89b-42d3-a456-426614174000/submit"
        );
        for bad in [
            "",
            "../../v3/user/get",
            "123e4567-e89b-42d3-a456-42661417400?",
            "123e4567e89b42d3a456426614174000aaaa",
        ] {
            assert!(session_url(bad, "").is_err(), "{bad}");
        }
    }
}
