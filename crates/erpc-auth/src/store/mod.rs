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
//! 4. [`file::FileStore`] — the last resort, and the only store that writes
//!    a secret to disk. It warns, and `erpc doctor` reports it. The one other
//!    case of a session on disk is not a store: a rotation the store refused
//!    is parked in a file by [`crate::lock`], and `erpc doctor` reports that
//!    too.
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
    /// The name used in `--store` and in `erpc doctor`.
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

    /// Parses a name from `--store`.
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

/// A record that would not parse, described by where and never by what.
///
/// The parsers' own messages quote the text they choke on -- `toml` prints
/// the offending line, `serde_json` can quote a value -- and in these
/// records that text is a session token. A message that reaches `error:`
/// on the operator's terminal is not a place a token may go, so the
/// position is all that is kept.
pub(crate) fn unparsable_toml(what: &str, text: &str, error: &toml::de::Error) -> StoreError {
    let line = error
        .span()
        .map(|span| text[..span.start.min(text.len())].matches('\n').count() + 1);
    StoreError::Corrupt(match line {
        Some(line) => format!("{what} is not valid TOML at line {line}"),
        None => format!("{what} is not valid TOML"),
    })
}

/// The JSON counterpart of [`unparsable_toml`].
pub(crate) fn unparsable_json(what: &str, error: &serde_json::Error) -> StoreError {
    StoreError::Corrupt(format!(
        "{what} is not the expected JSON at line {}, column {}",
        error.line(),
        error.column()
    ))
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

#[cfg(test)]
mod unparsable_tests {
    use super::{unparsable_json, unparsable_toml};
    use crate::credential::StoredCredential;

    #[test]
    fn neither_parser_message_is_passed_on() {
        // serde_json quotes a value it could not convert, and toml quotes
        // the line it stopped on; in these records both are tokens.
        let token = crate::lock::tests::token_fixture();
        let json = format!(
            r#"{{"store_version":1,"access_token":"a","refresh_token":"b","expires_at":"{token}"}}"#
        );
        let err = serde_json::from_str::<StoredCredential>(&json).expect_err("a type error");
        assert!(
            err.to_string().contains("U0VDUkVUUEFZTE9BRA"),
            "the premise: {err}"
        );
        let shown = unparsable_json("the keychain entry", &err).to_string();
        assert!(!shown.contains("U0VDUkVUUEFZTE9BRA"), "{shown}");

        let text = format!("store_version = 1\nexpires_at = \"{token}\"\n");
        let err = toml::from_str::<StoredCredential>(&text).expect_err("a type error");
        let shown = unparsable_toml("the credentials file", &text, &err).to_string();
        assert!(!shown.contains("U0VDUkVUUEFZTE9BRA"), "{shown}");
    }
}
