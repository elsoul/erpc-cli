// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which store is used, and why.
//!
//! The operator's choice wins where there is one -- `--store`, or what they
//! picked at `erpc login` -- and otherwise the choice is made from facts.
//! The reason is carried alongside it so that `erpc doctor` can print a
//! sentence the operator can act on. An operator who cannot tell why their
//! session went to a file instead of 1Password cannot fix it.

use super::StoreKind;

/// The facts the choice is made from.
///
/// Only facts that hold without asking anyone. Whether the 1Password
/// desktop app answers is not one of them: asking `op` can raise a
/// biometric prompt, so the desktop store is chosen by the operator, at
/// `erpc login` or with `--store`, never by detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    /// A 1Password service account token is in the environment.
    pub service_account_token: bool,
    /// An OS keychain is available on this machine.
    pub keychain_available: bool,
}

impl Environment {
    /// Nothing available: the starting point for a test.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            service_account_token: false,
            keychain_available: false,
        }
    }
}

/// Why a store was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// The operator asked for it, through `--store`.
    Requested,
    /// The operator chose it at `erpc login`, and it is kept in the
    /// configuration.
    Configured,
    /// A service account token is present, so this is a headless context.
    ServiceAccountToken,
    /// Nothing was chosen, and the machine has a keychain.
    KeychainDefault,
    /// Nothing was chosen, and there is no keychain either.
    NothingElseAvailable,
}

impl core::fmt::Display for Reason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Requested => "you asked for it with --store",
            Self::Configured => "you chose it at `erpc login`; it is kept in config.toml",
            Self::ServiceAccountToken => {
                "OP_SERVICE_ACCOUNT_TOKEN is set, so this is treated as a headless context"
            }
            Self::KeychainDefault => {
                "the default on a machine with an OS keychain; `erpc login` offers 1Password too"
            }
            Self::NothingElseAvailable => {
                "no OS keychain is available, so the session goes to a file on disk"
            }
        };
        f.write_str(text)
    }
}

/// A chosen store, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// The store to use.
    pub kind: StoreKind,
    /// Why this one.
    pub reason: Reason,
}

impl Selection {
    /// Whether this choice leaves a secret on the local disk.
    #[must_use]
    pub const fn warns(self) -> bool {
        self.kind.writes_secrets_to_disk()
    }
}

/// Chooses a store.
///
/// In order: `requested`, from `--store`, which always wins, because an
/// operator who names a store has a reason; then `configured`, the choice
/// kept from `erpc login`; then a service account token, which means nobody
/// is at the keyboard; then the keychain; then a file.
#[must_use]
pub fn choose(
    env: &Environment,
    requested: Option<StoreKind>,
    configured: Option<StoreKind>,
) -> Selection {
    if let Some(kind) = requested {
        return Selection {
            kind,
            reason: Reason::Requested,
        };
    }
    if let Some(kind) = configured {
        return Selection {
            kind,
            reason: Reason::Configured,
        };
    }
    if env.service_account_token {
        return Selection {
            kind: StoreKind::OnePasswordServiceAccount,
            reason: Reason::ServiceAccountToken,
        };
    }
    if env.keychain_available {
        return Selection {
            kind: StoreKind::OsKeychain,
            reason: Reason::KeychainDefault,
        };
    }
    Selection {
        kind: StoreKind::File,
        reason: Reason::NothingElseAvailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{Environment, Reason, StoreKind, choose};

    fn operator_machine() -> Environment {
        Environment {
            keychain_available: true,
            service_account_token: false,
        }
    }

    #[test]
    fn an_operator_machine_uses_the_keychain_by_default() {
        let chosen = choose(&operator_machine(), None, None);
        assert_eq!(chosen.kind, StoreKind::OsKeychain);
        assert_eq!(chosen.reason, Reason::KeychainDefault);
        assert!(!chosen.warns());
    }

    #[test]
    fn a_configured_store_is_used_without_asking_again() {
        let chosen = choose(
            &operator_machine(),
            None,
            Some(StoreKind::OnePasswordDesktop),
        );
        assert_eq!(chosen.kind, StoreKind::OnePasswordDesktop);
        assert_eq!(chosen.reason, Reason::Configured);
    }

    #[test]
    fn a_service_account_token_wins_over_the_keychain() {
        // The token means there is no one to answer a prompt.
        let env = Environment {
            service_account_token: true,
            ..operator_machine()
        };
        let chosen = choose(&env, None, None);
        assert_eq!(chosen.kind, StoreKind::OnePasswordServiceAccount);
        assert_eq!(chosen.reason, Reason::ServiceAccountToken);
    }

    #[test]
    fn a_bare_machine_falls_through_to_a_file_and_says_so() {
        let chosen = choose(&Environment::none(), None, None);
        assert_eq!(chosen.kind, StoreKind::File);
        assert_eq!(chosen.reason, Reason::NothingElseAvailable);
        assert!(
            chosen.warns(),
            "the file store is the one case the operator must be told about"
        );
    }

    #[test]
    fn an_explicit_choice_wins_over_the_configuration_and_every_fact() {
        for requested in [
            StoreKind::File,
            StoreKind::OsKeychain,
            StoreKind::OnePasswordDesktop,
            StoreKind::OnePasswordServiceAccount,
        ] {
            let chosen = choose(&operator_machine(), Some(requested), Some(StoreKind::File));
            assert_eq!(chosen.kind, requested);
            assert_eq!(chosen.reason, Reason::Requested);
        }
    }

    #[test]
    fn every_reason_prints_something_actionable() {
        for reason in [
            Reason::Requested,
            Reason::Configured,
            Reason::ServiceAccountToken,
            Reason::KeychainDefault,
            Reason::NothingElseAvailable,
        ] {
            let text = reason.to_string();
            assert!(text.len() > 20, "{reason:?} prints `{text}`");
        }
    }
}
