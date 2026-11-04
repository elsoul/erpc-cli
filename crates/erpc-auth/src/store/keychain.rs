// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The operating system's own keychain, for machines without `op`.
//!
//! macOS Keychain, the Secret Service on Linux, and the Windows Credential
//! Manager, under the service name `erpc` and the account
//! `<audience>:<user>`. On macOS through Apple's `security` tool (see
//! `security_cli` for why); elsewhere through the `keyring` crate.
//!
//! A Linux machine without a Secret Service -- a server reached over SSH,
//! with no desktop to run one -- uses the kernel's keyring instead: the
//! user's persistent keyring, which outlives the login session but not a
//! reboot, nor a few days unused (`/proc/sys/kernel/keys/
//! persistent_keyring_expiry`). Nothing reaches the disk either way; when
//! the kernel has dropped the session, `erpc login` is asked for again.
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

    #[cfg(not(target_os = "macos"))]
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

/// Whether a Secret Service answers on the session bus, asked once.
///
/// Answered by opening a session with it, which is what every read and
/// write starts with: a bus with nothing behind the name, or no bus this
/// user can reach, is a no.
#[cfg(target_os = "linux")]
#[must_use]
pub fn secret_service_answers() -> bool {
    static ANSWERS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ANSWERS.get_or_init(|| {
        dbus_secret_service::SecretService::connect(dbus_secret_service::EncryptionType::Plain)
            .is_ok()
    })
}

/// What holds the session on this machine, as a person would say it in
/// `lang`.
#[must_use]
pub fn describe(lang: erpc_core::i18n::Lang) -> &'static str {
    use erpc_core::i18n::Lang::{En, Ja, Ru, Zh};
    #[cfg(target_os = "macos")]
    let name = match lang {
        En => "macOS Keychain",
        Ja => "macOS キーチェーン",
        Zh => "macOS 钥匙串",
        Ru => "связка ключей macOS",
    };
    #[cfg(target_os = "windows")]
    let name = match lang {
        En => "Windows Credential Manager",
        Ja => "Windows 資格情報マネージャー",
        Zh => "Windows 凭据管理器",
        Ru => "диспетчер учётных данных Windows",
    };
    #[cfg(target_os = "linux")]
    let name = match (secret_service_answers(), lang) {
        (true, En) => "the Secret Service keyring",
        (true, Ja) => "Secret Service のキーリング",
        (true, Zh) => "Secret Service 密钥环",
        (true, Ru) => "связка ключей Secret Service",
        (false, En) => "the kernel keyring (kept until a reboot)",
        (false, Ja) => "カーネルのキーリング（再起動まで保持）",
        (false, Zh) => "内核密钥环（保留到重启）",
        (false, Ru) => "связка ключей ядра (хранится до перезагрузки)",
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let name = match lang {
        En => "the system keyring",
        Ja => "OS のキーリング",
        Zh => "系统密钥环",
        Ru => "системная связка ключей",
    };
    name
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
    super::non_empty(&stored.access_token, &stored.refresh_token)?;
    Ok(Credential {
        access_token: SecretString::from(stored.access_token.clone()),
        refresh_token: SecretString::from(stored.refresh_token.clone()),
        expires_at: stored.expires_at,
    })
}

/// Turns a `security` or kernel keyring failure into the store's error.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn backend(operation: &'static str) -> impl Fn(String) -> StoreError {
    move |reason| StoreError::Backend {
        kind: StoreKind::OsKeychain,
        operation,
        reason,
    }
}

#[cfg(target_os = "macos")]
impl CredentialStore for OsKeychain {
    fn load(&self, key: &CredKey) -> Result<Option<Credential>, StoreError> {
        super::security_cli::read(&self.service, &key.keychain_account())
            .map_err(backend("read from the keychain"))?
            .map(|raw| parse_entry(&raw))
            .transpose()
    }

    fn save(&self, key: &CredKey, cred: &Credential) -> Result<(), StoreError> {
        super::security_cli::write(&self.service, &key.keychain_account(), &serialise(cred)?)
            .map_err(backend("write to the keychain"))
    }

    fn delete(&self, key: &CredKey) -> Result<(), StoreError> {
        super::security_cli::delete(&self.service, &key.keychain_account())
            .map_err(backend("remove from the keychain"))
    }

    fn kind(&self) -> StoreKind {
        StoreKind::OsKeychain
    }
}

/// The user's persistent keyring in the Linux kernel.
///
/// It outlives the login session, for a few days unused. It is reached
/// from the user keyring rather than from a session keyring, so a process
/// started outside a PAM login -- cron, a systemd unit -- finds it too.
///
/// The kernel lets the user write and search it only through a keyring the
/// process holds, which a login provides. A process whose session keyring
/// is revoked or another user's -- after `su` without `-`, or `sudo -E` --
/// holds none, and is refused: told so, rather than given a session that
/// could not be read back.
#[cfg(target_os = "linux")]
mod kernel {
    use linux_keyutils::{KeyError, KeyRing, KeyRingIdentifier};

    /// What a refusal means here, and what to do about it.
    const NOT_HELD: &str = "this process holds none of your kernel keyrings, which happens \
        when it was started without a login of its own (`su` without `-`, `sudo -E`); \
        start it from a login as yourself, or choose another store with \
        `erpc login --store`";

    /// The keyring, attached to the user keyring.
    fn ring() -> Result<KeyRing, String> {
        KeyRing::get_persistent(KeyRingIdentifier::User).map_err(explain)
    }

    /// A kernel error as a sentence.
    fn explain(e: KeyError) -> String {
        match e {
            KeyError::AccessDenied | KeyError::PermissionDenied => NOT_HELD.to_owned(),
            other => other.to_string(),
        }
    }

    /// The key's description: the service and the account.
    fn description(service: &str, account: &str) -> String {
        format!("{service}:{account}")
    }

    /// A miss: no such key, or one the kernel has let go.
    const fn missing(e: KeyError) -> bool {
        matches!(
            e,
            KeyError::KeyDoesNotExist | KeyError::KeyExpired | KeyError::KeyRevoked
        )
    }

    /// The entry's text, or none when there is no entry.
    pub(super) fn read(service: &str, account: &str) -> Result<Option<String>, String> {
        let bytes = match ring()?
            .search(&description(service, account))
            .and_then(|key| key.read_to_vec())
        {
            Ok(bytes) => bytes,
            Err(e) if missing(e) => return Ok(None),
            Err(e) => return Err(explain(e)),
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "the entry is not text".to_owned())
    }

    /// Writes the entry. A key with the same description is updated in
    /// place, in one call: a reader sees the old text or the new.
    pub(super) fn write(service: &str, account: &str, text: &str) -> Result<(), String> {
        ring()?
            .add_key(&description(service, account), text)
            .map(|_| ())
            .map_err(explain)
    }

    /// Removes the entry; one that is not there is removed already.
    pub(super) fn delete(service: &str, account: &str) -> Result<(), String> {
        match ring()?
            .search(&description(service, account))
            .and_then(|key| key.invalidate())
        {
            Ok(()) => Ok(()),
            Err(e) if missing(e) => Ok(()),
            Err(e) => Err(explain(e)),
        }
    }
}

/// The session as the versioned document every store writes.
fn serialise(cred: &Credential) -> Result<String, StoreError> {
    let stored = StoredCredential {
        store_version: STORE_VERSION,
        access_token: cred.access_token.expose_secret().to_owned(),
        refresh_token: cred.refresh_token.expose_secret().to_owned(),
        expires_at: cred.expires_at,
    };
    serde_json::to_string(&stored).map_err(|e| StoreError::Backend {
        kind: StoreKind::OsKeychain,
        operation: "serialise the session",
        reason: e.to_string(),
    })
}

#[cfg(not(target_os = "macos"))]
impl CredentialStore for OsKeychain {
    fn load(&self, key: &CredKey) -> Result<Option<Credential>, StoreError> {
        #[cfg(target_os = "linux")]
        if !secret_service_answers() {
            return kernel::read(&self.service, &key.keychain_account())
                .map_err(backend("read from the kernel keyring"))?
                .map(|raw| parse_entry(&raw))
                .transpose();
        }
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
        let raw = serialise(cred)?;
        #[cfg(target_os = "linux")]
        if !secret_service_answers() {
            return kernel::write(&self.service, &key.keychain_account(), &raw)
                .map_err(backend("write to the kernel keyring"));
        }
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
        #[cfg(target_os = "linux")]
        if !secret_service_answers() {
            return kernel::delete(&self.service, &key.keychain_account())
                .map_err(backend("remove from the kernel keyring"));
        }
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

/// Secrets other than the session, kept in the same keychain the session
/// is: by `service` and `account`, as text, never on a command line.
///
/// For keys that must outlive a reboot, so on Linux only the Secret
/// Service is used; the kernel keyring, which the session falls back to,
/// forgets what it holds.
pub mod item {
    use zeroize::Zeroizing;

    #[cfg(target_os = "linux")]
    fn durable() -> Result<(), String> {
        if super::secret_service_answers() {
            Ok(())
        } else {
            Err(
                "no Secret Service answers here, and the kernel keyring forgets what it holds \
                 at a reboot; keep this secret in 1Password instead"
                    .to_owned(),
            )
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn entry(service: &str, account: &str) -> Result<keyring::Entry, String> {
        #[cfg(target_os = "linux")]
        durable()?;
        keyring::Entry::new(service, account).map_err(|e| e.to_string())
    }

    /// The secret under `service` and `account`, or `None` when there is none.
    ///
    /// # Errors
    ///
    /// A message when the keychain cannot be read.
    pub fn read(service: &str, account: &str) -> Result<Option<Zeroizing<String>>, String> {
        #[cfg(target_os = "macos")]
        return super::super::security_cli::read(service, account).map(|s| s.map(Zeroizing::new));
        #[cfg(not(target_os = "macos"))]
        match entry(service, account)?.get_password() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Keeps `secret` under `service` and `account`, replacing what was there.
    ///
    /// # Errors
    ///
    /// A message when the keychain cannot be written.
    pub fn write(service: &str, account: &str, secret: &str) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        return super::super::security_cli::write(service, account, secret);
        #[cfg(not(target_os = "macos"))]
        entry(service, account)?
            .set_password(secret)
            .map_err(|e| e.to_string())
    }

    /// Removes what is under `service` and `account`; nothing there is not
    /// an error.
    ///
    /// # Errors
    ///
    /// A message when the keychain cannot be written.
    pub fn delete(service: &str, account: &str) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        return super::super::security_cli::delete(service, account);
        #[cfg(not(target_os = "macos"))]
        match entry(service, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OsKeychain, SERVICE, parse_entry};
    use crate::credential::{Audience, CredKey};
    use crate::store::{CredentialStore as _, StoreKind};

    #[test]
    fn an_entry_with_an_empty_token_is_not_a_session() {
        let raw = r#"{"store_version":1,"access_token":"a.b.c","refresh_token":"","expires_at":1}"#;
        assert!(matches!(
            parse_entry(raw),
            Err(crate::store::StoreError::Corrupt(_))
        ));
    }

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

    /// A session saved, read back and removed, in this machine's keychain:
    /// on a Linux server, the kernel's keyring.
    #[test]
    #[ignore = "touches this machine's keychain"]
    fn a_session_round_trips_through_the_keychain() {
        use secrecy::{ExposeSecret as _, SecretString};
        let store = OsKeychain::with_service("erpc-test-round-trip");
        let key = CredKey::new(Audience::AuthApi, "round-trip");
        let cred = crate::credential::Credential {
            access_token: SecretString::from("a.b.c"),
            refresh_token: SecretString::from("refresh"),
            expires_at: 1,
        };
        store.save(&key, &cred).expect("saved");
        let back = store.load(&key).expect("read").expect("there");
        assert_eq!(back.refresh_token.expose_secret(), "refresh");
        store.delete(&key).expect("removed");
        assert!(store.load(&key).expect("read").is_none());
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
