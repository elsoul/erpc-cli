// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The operating system's own keychain, for machines without `op`.
//!
//! macOS Keychain, the Secret Service on Linux, and the Windows Credential
//! Manager, all through the `keyring` crate under the service name `erpc`
//! and the account `<audience>:<user>`.
//!
//! The record stored is the same versioned document the file store writes,
//! serialised as JSON, so that a session written by one store can be read
//! by a reader that knows the format and nothing else.

use secrecy::{ExposeSecret as _, SecretString};

use super::{CredentialStore, StoreError, StoreKind};
use crate::credential::{CredKey, Credential, STORE_VERSION, StoredCredential};

/// The service name every erpc entry is filed under.
pub const SERVICE: &str = "erpc";

/// A session store backed by the operating system's keychain.
#[derive(Debug, Clone, Default)]
pub struct OsKeychain {
    service: String,
}

impl OsKeychain {
    /// Uses the standard `erpc` service name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            service: SERVICE.to_owned(),
        }
    }

    /// Uses a service name of your own, so that a test does not write into
    /// the operator's real keychain.
    #[must_use]
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &CredKey) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(&self.service, &key.keychain_account()).map_err(|e| {
            StoreError::Backend {
                kind: StoreKind::OsKeychain,
                operation: "address the keychain entry",
                reason: e.to_string(),
            }
        })
    }
}

/// Reads a keychain entry's text back into a session.
///
/// Apart from the keychain call so that it can be tested on a machine
/// with no keychain, including that a malformed entry is reported without
/// quoting it.
fn parse_entry(raw: &str) -> Result<Credential, StoreError> {
    let stored: StoredCredential =
        serde_json::from_str(raw).map_err(|e| super::unparsable_json("the keychain entry", &e))?;
    if stored.store_version != STORE_VERSION {
        return Err(StoreError::UnknownVersion {
            found: stored.store_version,
            expected: STORE_VERSION,
        });
    }
    Ok(Credential {
        access_token: SecretString::from(stored.access_token.clone()),
        refresh_token: SecretString::from(stored.refresh_token.clone()),
        expires_at: stored.expires_at,
    })
}

impl CredentialStore for OsKeychain {
    fn load(&self, key: &CredKey) -> Result<Option<Credential>, StoreError> {
        let entry = self.entry(key)?;
        let raw = match entry.get_password() {
            Ok(raw) => raw,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(e) => {
                return Err(StoreError::Backend {
                    kind: StoreKind::OsKeychain,
                    operation: "read from the keychain",
                    reason: e.to_string(),
                });
            }
        };
        parse_entry(&raw).map(Some)
    }

    fn save(&self, key: &CredKey, cred: &Credential) -> Result<(), StoreError> {
        let stored = StoredCredential {
            store_version: STORE_VERSION,
            access_token: cred.access_token.expose_secret().to_owned(),
            refresh_token: cred.refresh_token.expose_secret().to_owned(),
            expires_at: cred.expires_at,
        };
        let raw = serde_json::to_string(&stored).map_err(|e| StoreError::Backend {
            kind: StoreKind::OsKeychain,
            operation: "serialise the session",
            reason: e.to_string(),
        })?;
        // `set_password` replaces an existing entry in one call on every
        // supported platform, so there is no window where the entry is
        // missing.
        self.entry(key)?
            .set_password(&raw)
            .map_err(|e| StoreError::Backend {
                kind: StoreKind::OsKeychain,
                operation: "write to the keychain",
                reason: e.to_string(),
            })
    }

    fn delete(&self, key: &CredKey) -> Result<(), StoreError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(StoreError::Backend {
                kind: StoreKind::OsKeychain,
                operation: "remove from the keychain",
                reason: e.to_string(),
            }),
        }
    }

    fn kind(&self) -> StoreKind {
        StoreKind::OsKeychain
    }
}

#[cfg(test)]
mod tests {
    use super::{OsKeychain, SERVICE, parse_entry};
    use crate::credential::{Audience, CredKey};
    use crate::store::{CredentialStore as _, StoreKind};

    #[test]
    fn a_malformed_entry_is_reported_without_quoting_it() {
        let token = crate::lock::tests::token_fixture();
        let raw = format!(
            r#"{{"store_version":1,"access_token":"a","refresh_token":"b","expires_at":"{token}"}}"#
        );
        let Err(err) = parse_entry(&raw) else {
            panic!("the entry is malformed");
        };
        let shown = err.to_string();
        assert!(!shown.contains("U0VDUkVUUEFZTE9BRA"), "{shown}");
    }

    #[test]
    fn the_default_service_is_erpc() {
        assert_eq!(SERVICE, "erpc");
        assert_eq!(OsKeychain::new().kind(), StoreKind::OsKeychain);
        assert!(!OsKeychain::new().kind().writes_secrets_to_disk());
    }

    #[test]
    fn an_entry_is_addressed_by_audience_and_account() {
        // The address is what keeps two accounts, and the two APIs, apart
        // inside one keychain. Checked here rather than against a live
        // keychain, which a CI runner does not have.
        let key = CredKey::new(Audience::McpUserApi, "alice");
        assert_eq!(key.keychain_account(), "mcp-user-api:alice");
    }
}
