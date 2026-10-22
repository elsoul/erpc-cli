// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Where a session is kept, and how the right place is chosen.
//!
//! Four implementations, in the order they are preferred:
//!
//! 1. [`one_password::Desktop`] — the default on a person's machine. The
//!    1Password app holds the item and asks for biometrics.
//! 2. [`one_password::ServiceAccount`] — CI, headless servers and resident
//!    agents, selected by the presence of a service account token.
//! 3. [`keychain::OsKeychain`] — machines without `op`.
//! 4. [`file::FileStore`] — the last resort, and the only one that writes a
//!    secret to disk. It warns, and `erpc doctor` reports it.
//!
//! Validator keys and wallet keys do not come through here. This trait is
//! for session tokens only; key material goes through `erpc-secret` and
//! 1Password, which is a different path with a different gate.

pub mod file;
pub mod keychain;
pub mod one_password;
pub mod select;

use crate::credential::{CredKey, Credential};

/// Which implementation a store is, for diagnostics and for the warning
/// that the file store has to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreKind {
    /// 1Password through the desktop application.
    OnePasswordDesktop,
    /// 1Password through a service account token.
    OnePasswordServiceAccount,
    /// The operating system's keychain.
    OsKeychain,
    /// A file under the erpc state directory.
    File,
}

impl StoreKind {
    /// The name used in configuration, in `--store` and in `erpc doctor`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnePasswordDesktop => "1password-desktop",
            Self::OnePasswordServiceAccount => "1password-service-account",
            Self::OsKeychain => "keychain",
            Self::File => "file",
        }
    }

    /// Whether this store writes a secret to the local disk.
    ///
    /// The requirement is that nothing is left on the machine, and this is
    /// the predicate that finds the exceptions to it.
    #[must_use]
    pub const fn writes_secrets_to_disk(self) -> bool {
        matches!(self, Self::File)
    }

    /// Parses a name from configuration or `--store`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "1password-desktop" => Some(Self::OnePasswordDesktop),
            "1password-service-account" => Some(Self::OnePasswordServiceAccount),
            "keychain" => Some(Self::OsKeychain),
            "file" => Some(Self::File),
            _ => None,
        }
    }
}

impl core::fmt::Display for StoreKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What went wrong reading or writing a session.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The backing store is not usable on this machine.
    #[error("{kind} is not available here: {reason}")]
    Unavailable {
        /// Which store was tried.
        kind: StoreKind,
        /// Why it could not be used.
        reason: String,
    },
    /// The stored record is in a format this build does not know.
    #[error(
        "the stored session is version {found}, and this build of erpc writes version {expected}; \
         run `erpc login` again"
    )]
    UnknownVersion {
        /// The version found in the record.
        found: u32,
        /// The version this build writes.
        expected: u32,
    },
    /// The record could not be parsed.
    #[error("the stored session could not be read: {0}")]
    Corrupt(String),
    /// The underlying operation failed.
    #[error("{operation} failed for {kind}: {reason}")]
    Backend {
        /// Which store failed.
        kind: StoreKind,
        /// What was being attempted.
        operation: &'static str,
        /// The underlying message, already stripped of secrets.
        reason: String,
    },
}

/// Reads and writes one session.
///
/// `save` replaces atomically: a reader either sees the session that was
/// there before or the one being written, never a half-written record. The
/// refresh path depends on that, because it rotates a token that another
/// process may be reading at the same moment.
pub trait CredentialStore {
    /// Loads the session filed under `key`, if there is one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store is unreachable or the record
    /// is unreadable. A missing session is `Ok(None)`, not an error.
    fn load(&self, key: &CredKey) -> Result<Option<Credential>, StoreError>;

    /// Writes `cred` under `key`, replacing any session already there.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the write does not complete.
    fn save(&self, key: &CredKey, cred: &Credential) -> Result<(), StoreError>;

    /// Removes the session filed under `key`.
    ///
    /// Removing a session that is not there succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store is reachable but the removal
    /// fails.
    fn delete(&self, key: &CredKey) -> Result<(), StoreError>;

    /// Which implementation this is.
    fn kind(&self) -> StoreKind;
}

#[cfg(test)]
mod tests {
    use super::StoreKind;

    #[test]
    fn every_kind_round_trips_through_its_name() {
        for kind in [
            StoreKind::OnePasswordDesktop,
            StoreKind::OnePasswordServiceAccount,
            StoreKind::OsKeychain,
            StoreKind::File,
        ] {
            assert_eq!(StoreKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(StoreKind::parse("something-else"), None);
    }

    #[test]
    fn only_the_file_store_writes_secrets_to_disk() {
        assert!(StoreKind::File.writes_secrets_to_disk());
        for kind in [
            StoreKind::OnePasswordDesktop,
            StoreKind::OnePasswordServiceAccount,
            StoreKind::OsKeychain,
        ] {
            assert!(!kind.writes_secrets_to_disk(), "{kind}");
        }
    }
}
