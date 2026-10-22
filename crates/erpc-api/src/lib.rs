// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-api`: the typed client for the ERPC account API.
//!
//! Only the calls `erpc` itself makes, and only through
//! [`erpc_auth::AuthClient`], so that the destination allowlist is applied
//! to every one of them in the same place rather than remembered at each
//! call site.

#![forbid(unsafe_code)]

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde::Deserialize;

/// The account endpoint. A constant for the same reason the identity
/// endpoints are: a destination that configuration can move is one that
/// can be moved by whoever edits the configuration.
pub const USER_GET_URL: &str = "https://user-api.erpc.global/v3/user/get";

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-api";

/// Why an account lookup did not return an account.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApiError {
    /// The request failed.
    #[error(transparent)]
    Http(#[from] erpc_auth::HttpError),
    /// The session is not accepted.
    #[error("the session was refused; run `erpc login`")]
    Unauthorized,
    /// The session is valid but there is no ERPC account behind it.
    #[error("this sign-in has no ERPC account yet; run `erpc signup`")]
    NoAccount,
    /// The server answered with something unreadable.
    #[error("user-api returned a reply this version cannot read: {0}")]
    Malformed(String),
    /// The server refused for another reason.
    #[error("user-api refused the request with {0}")]
    Status(u16),
}

/// The parts of an account this version uses.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct User {
    /// The account's stable identifier.
    #[serde(default)]
    pub uid: String,
    /// The display name, when the account has one.
    #[serde(default)]
    pub username: Option<String>,
    /// The e-mail address, when the account has one.
    #[serde(default)]
    pub email: Option<String>,
}

impl User {
    /// The best single label for this account.
    #[must_use]
    pub fn label(&self) -> &str {
        self.username
            .as_deref()
            .or(self.email.as_deref())
            .unwrap_or(&self.uid)
    }

    /// [`Self::label`] for a terminal: control characters and the
    /// characters that reorder text replaced.
    ///
    /// The value comes from the server. A control character in it could be
    /// an escape sequence by the time it is printed, and a bidirectional
    /// override can make it read as something else. JSON output uses
    /// [`Self::label`] unchanged: it is data for a program, and the encoder
    /// escapes only the C0 control characters in it.
    #[must_use]
    pub fn label_for_display(&self) -> String {
        self.label()
            .chars()
            .map(|c| {
                let reorders = matches!(
                    c,
                    '\u{061C}'
                        | '\u{200E}'
                        | '\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                );
                if c.is_control() || reorders { '?' } else { c }
            })
            .collect()
    }
}

/// Fetches the account behind a session.
///
/// A 401 means the session is not accepted and a 404 means there is no
/// account yet. They are separated because the operator's next step
/// differs: sign in again, or sign up.
///
/// # Errors
///
/// Returns [`ApiError`] when the request fails or the account cannot be
/// read.
pub async fn get_user(client: &AuthClient, access_token: &SecretString) -> Result<User, ApiError> {
    let (status, body) = client
        .get_with_token(Audience::AuthApi, USER_GET_URL, access_token)
        .await?;
    match status {
        200 => parse_user(&body),
        401 | 403 => Err(ApiError::Unauthorized),
        404 => Err(ApiError::NoAccount),
        other => Err(ApiError::Status(other)),
    }
}

/// Reads the account out of a reply body.
///
/// Accepts the object directly or wrapped in `data`, because the account
/// API uses both shapes and a client that only knows one of them turns a
/// working session into a puzzling error.
fn parse_user(body: &str) -> Result<User, ApiError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| ApiError::Malformed(e.to_string()))?;
    let object = value.get("data").unwrap_or(&value);
    serde_json::from_value(object.clone()).map_err(|e| ApiError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{CRATE_NAME, USER_GET_URL, parse_user};

    #[test]
    fn crate_name_matches_package() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn the_account_endpoint_is_a_declared_host() {
        assert!(
            erpc_core::endpoints::ensure_service_url(USER_GET_URL).is_ok(),
            "{USER_GET_URL} is not declared in erpc-core::endpoints"
        );
    }

    #[test]
    fn the_account_endpoint_is_a_destination_the_allowlist_permits() {
        // Otherwise every call would be refused before it was sent, and
        // the first person to find out would be an operator mid-login.
        assert!(
            erpc_auth::allowlist::ensure_token_destination(
                erpc_auth::credential::Audience::AuthApi,
                USER_GET_URL
            )
            .is_ok()
        );
    }

    #[test]
    fn a_bare_account_object_is_read() {
        let user = parse_user(r#"{"uid":"u1","username":"alice","email":"a@example.net"}"#)
            .expect("parses");
        assert_eq!(user.uid, "u1");
        assert_eq!(user.label(), "alice");
    }

    #[test]
    fn an_account_wrapped_in_data_is_read_too() {
        let user = parse_user(r#"{"data":{"uid":"u2","email":"b@example.net"}}"#).expect("parses");
        assert_eq!(user.uid, "u2");
        assert_eq!(user.label(), "b@example.net");
    }

    #[test]
    fn an_account_with_only_an_id_still_has_a_label() {
        let user = parse_user(r#"{"uid":"u3"}"#).expect("parses");
        assert_eq!(user.label(), "u3");
    }

    #[test]
    fn a_label_is_printed_without_control_characters() {
        let user: super::User =
            serde_json::from_str(r#"{"uid":"u4","username":"al\u001b[2Jice"}"#).expect("parses");
        let shown = user.label_for_display();
        assert!(!shown.contains('\u{1b}'), "{shown}");
        assert!(shown.starts_with("al"), "{shown}");
        let user: super::User =
            serde_json::from_str(r#"{"uid":"u5","username":"alice\u202eroot"}"#).expect("parses");
        assert!(!user.label_for_display().contains('\u{202e}'));
        let user: super::User =
            serde_json::from_str(r#"{"uid":"u6","username":"a\u061cb"}"#).expect("parses");
        assert!(!user.label_for_display().contains('\u{061c}'));
    }

    #[test]
    fn an_html_error_page_is_not_an_account() {
        assert!(parse_user("<!DOCTYPE html>").is_err());
    }
}
