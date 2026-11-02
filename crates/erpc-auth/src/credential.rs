// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What a stored session is, and what it is stored under.

use core::fmt;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Which API a session belongs to.
///
/// A session is never valid for more than one audience. The two ERPC APIs
/// issue tokens from separate families, and sending one API's token to the
/// other would both fail and disclose it, so the audience is part of the
/// key a session is stored under and part of the check made before a token
/// is attached to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Audience {
    /// `auth-api.erpc.global`: the account session.
    AuthApi,
    /// `mcp-user-api.erpc.global`: the MCP session.
    McpUserApi,
}

impl Audience {
    /// The short, stable name used in storage keys and file names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthApi => "auth-api",
            Self::McpUserApi => "mcp-user-api",
        }
    }

    /// The host that issues tokens for this audience.
    #[must_use]
    pub const fn issuer_host(self) -> &'static str {
        match self {
            Self::AuthApi => "auth-api.erpc.global",
            Self::McpUserApi => "mcp-user-api.erpc.global",
        }
    }

    /// Every audience, for iteration in `logout` and in diagnostics.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::AuthApi, Self::McpUserApi]
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a session is filed under.
///
/// The account name is part of the key so that two accounts on one machine
/// do not overwrite each other, and so that a 1Password item title can name
/// the account and the host it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredKey {
    audience: Audience,
    account: String,
}

impl CredKey {
    /// Builds a key for an audience and an account name.
    #[must_use]
    pub fn new(audience: Audience, account: impl Into<String>) -> Self {
        Self {
            audience,
            account: account.into(),
        }
    }

    /// The audience this session belongs to.
    #[must_use]
    pub fn audience(&self) -> Audience {
        self.audience
    }

    /// The account name.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The identifier used by the OS keychain, as `<audience>:<account>`.
    #[must_use]
    pub fn keychain_account(&self) -> String {
        format!("{}:{}", self.audience.as_str(), self.account)
    }
}

impl fmt::Display for CredKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.audience, self.account)
    }
}

/// A session: the two tokens and when the access token stops being usable.
///
/// `expires_at` is seconds since the Unix epoch. It is stored rather than
/// derived at read time because a store may be read long after it was
/// written, and because the refresh path has to decide whether to rotate
/// before it can know anything else.
///
/// The tokens are [`SecretString`], which do not print themselves, and
/// `Debug` is implemented by hand below so that the rendering names the
/// fields and shows only the expiry.
/// `Credential` is deliberately not serialisable. What goes into a store is
/// [`StoredCredential`], which carries a version; a type that could be
/// written directly would be written without one.
#[derive(Clone)]
pub struct Credential {
    /// The bearer token for the audience's API.
    pub access_token: SecretString,
    /// The token used to obtain the next access token.
    pub refresh_token: SecretString,
    /// Unix timestamp, in seconds, after which the access token is stale.
    pub expires_at: i64,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Named fields, no values. A session that leaks through a log line
        // is the same incident as one that leaks any other way.
        f.debug_struct("Credential")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credential {
    /// How long before expiry a session is treated as needing a refresh.
    ///
    /// A token that expires while a request is in flight fails the request,
    /// so the refresh happens a minute early.
    pub const REFRESH_MARGIN_SECS: i64 = 60;

    /// Whether this session should be refreshed before being used at `now`.
    #[must_use]
    pub fn needs_refresh(&self, now: i64) -> bool {
        now >= self.expires_at.saturating_sub(Self::REFRESH_MARGIN_SECS)
    }

    /// Whether the access token is already unusable at `now`.
    #[must_use]
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }
}

/// The shape a token must have to be stored.
///
/// `erpc` does not decode a token or trust anything inside it. It checks
/// only that what the server returned looks like a JWT, so that an error
/// page or an empty body is not filed away as a session and surfaced much
/// later as a puzzling 401.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenShapeError {
    /// The token is empty.
    #[error("the server returned an empty token")]
    Empty,
    /// The token does not have three dot-separated parts.
    #[error("the server returned a token that is not in three parts, so it is not a JWT")]
    NotThreeParts,
    /// One of the parts is empty or is not base64url.
    #[error("the server returned a token whose parts are not base64url")]
    NotBase64Url,
}

/// Checks that `token` has the shape of a JWT, without decoding it.
///
/// # Errors
///
/// Returns [`TokenShapeError`] when the value is empty, is not in three
/// parts, or holds a character base64url does not use.
pub fn check_token_shape(token: &str) -> Result<(), TokenShapeError> {
    if token.is_empty() {
        return Err(TokenShapeError::Empty);
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TokenShapeError::NotThreeParts);
    };
    // The signature of an unsecured JWT is empty; the other two never are.
    for part in [header, payload] {
        if part.is_empty() || !is_base64url(part) {
            return Err(TokenShapeError::NotBase64Url);
        }
    }
    if !is_base64url(signature) {
        return Err(TokenShapeError::NotBase64Url);
    }
    Ok(())
}

/// Whether every byte is one base64url uses.
fn is_base64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
}

/// A session as it sits in a file or a 1Password item.
///
/// Separate from [`Credential`] because what is written down has a version
/// on it. A reader that meets a version it does not know refuses the record
/// rather than guessing at its fields.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct StoredCredential {
    /// The format version of this record.
    pub store_version: u32,
    /// The access token.
    pub access_token: String,
    /// The refresh token.
    pub refresh_token: String,
    /// Unix timestamp, in seconds, after which the access token is stale.
    #[zeroize(skip)]
    pub expires_at: i64,
}

/// The only record version this build writes and accepts.
pub const STORE_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::{
        Audience, CredKey, Credential, STORE_VERSION, StoredCredential, TokenShapeError,
        check_token_shape,
    };
    use secrecy::SecretString;

    fn sample() -> Credential {
        Credential {
            access_token: SecretString::from("a.b.c"),
            refresh_token: SecretString::from("d.e.f"),
            expires_at: 1_000,
        }
    }

    #[test]
    fn debug_does_not_print_either_token() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains("a.b.c"), "{rendered}");
        assert!(!rendered.contains("d.e.f"), "{rendered}");
        assert!(rendered.contains("expires_at"));
    }

    #[test]
    fn a_session_is_refreshed_a_minute_early() {
        let cred = sample();
        assert!(!cred.needs_refresh(1_000 - Credential::REFRESH_MARGIN_SECS - 1));
        assert!(cred.needs_refresh(1_000 - Credential::REFRESH_MARGIN_SECS));
        assert!(!cred.is_expired(999));
        assert!(cred.is_expired(1_000));
    }

    #[test]
    fn an_audience_names_its_own_issuer() {
        assert_eq!(Audience::AuthApi.issuer_host(), "auth-api.erpc.global");
        assert_eq!(
            Audience::McpUserApi.issuer_host(),
            "mcp-user-api.erpc.global"
        );
        assert_eq!(Audience::all().len(), 2);
    }

    #[test]
    fn a_key_separates_accounts_and_audiences() {
        let a = CredKey::new(Audience::AuthApi, "alice");
        let b = CredKey::new(Audience::AuthApi, "bob");
        let c = CredKey::new(Audience::McpUserApi, "alice");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.keychain_account(), "auth-api:alice");
        assert_eq!(c.keychain_account(), "mcp-user-api:alice");
    }

    #[test]
    fn a_jwt_shaped_token_is_accepted() {
        assert!(check_token_shape("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln").is_ok());
    }

    #[test]
    fn an_error_page_is_not_a_token() {
        assert_eq!(
            check_token_shape("<!DOCTYPE html>").expect_err("html is not a token"),
            TokenShapeError::NotThreeParts
        );
    }

    #[test]
    fn an_empty_token_is_refused() {
        assert_eq!(
            check_token_shape("").expect_err("an empty token is refused"),
            TokenShapeError::Empty
        );
    }

    #[test]
    fn a_token_with_an_empty_header_is_refused() {
        assert_eq!(
            check_token_shape(".payload.sig").expect_err("the header is required"),
            TokenShapeError::NotBase64Url
        );
    }

    #[test]
    fn a_token_with_a_space_is_refused() {
        assert_eq!(
            check_token_shape("aa.bb b.cc").expect_err("base64url has no spaces"),
            TokenShapeError::NotBase64Url
        );
    }

    #[test]
    fn a_stored_record_carries_its_version() {
        let stored = StoredCredential {
            store_version: STORE_VERSION,
            access_token: "a.b.c".to_owned(),
            refresh_token: "d.e.f".to_owned(),
            expires_at: 1,
        };
        assert_eq!(stored.store_version, 1);
    }
}
