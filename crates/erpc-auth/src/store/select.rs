// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which store is used, and why.
//!
//! The choice is made from facts, not preferences, and the reason is
//! carried alongside it so that `erpc doctor` can print a sentence the
//! operator can act on. An operator who cannot tell why their session went
//! to a file instead of 1Password cannot fix it.

use super::StoreKind;

/// The facts the choice is made from.
///
/// One field per condition, kept as separate booleans so that this type can
/// be read beside the selection rules below and checked off.
#[allow(
    clippy::struct_excessive_bools,
    reason = "one field per condition in the selection rules, kept legible on purpose"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    /// A 1Password service account token is in the environment.
    pub service_account_token: bool,
    /// `op` was found at an absolute path.
    pub op_present: bool,
    /// `op account list` succeeded, so the desktop app really answered.
    ///
    /// Only ever set by running that command. A caller that has not run it
    /// leaves this false, and the choice then falls through to the
    /// keychain rather than sending a session to an app that may be signed
    /// out, have integration switched off, or not be running at all.
    pub op_account_usable: bool,
    /// An OS keychain is available on this machine.
    pub keychain_available: bool,
}

impl Environment {
    /// Nothing available: the starting point for a test.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            service_account_token: false,
            op_present: false,
            op_account_usable: false,
            keychain_available: false,
        }
    }
}

/// Why a store was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// The operator asked for it, through `--store` or configuration.
    Requested,
    /// A service account token is present, so this is a headless context.
    ServiceAccountToken,
    /// `op` is installed and its desktop account is reachable.
    OnePasswordDesktopReachable,
    /// `op` is not usable, and the machine has a keychain.
    NoOpSoKeychain,
    /// Nothing else is available.
    NothingElseAvailable,
}

impl core::fmt::Display for Reason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Requested => "you asked for it with --store or in config.toml",
            Self::ServiceAccountToken => {
                "OP_SERVICE_ACCOUNT_TOKEN is set, so this is treated as a headless context"
            }
            Self::OnePasswordDesktopReachable => {
                "op is installed and `op account list` answered, so the desktop app holds the \
                 session"
            }
            Self::NoOpSoKeychain => {
                "the 1Password desktop app did not answer, so the OS keychain holds the session"
            }
            Self::NothingElseAvailable => {
                "neither op nor an OS keychain is available, so the session goes to a file on disk"
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
/// `requested` is an explicit choice from `--store` or configuration, which
/// always wins: an operator who names a store has a reason, and silently
/// using another one would be worse than failing later if it is not there.
#[must_use]
pub fn choose(env: &Environment, requested: Option<StoreKind>) -> Selection {
    if let Some(kind) = requested {
        return Selection {
            kind,
            reason: Reason::Requested,
        };
    }
    // A service account token is checked before the desktop app: its
    // presence means nobody is at the keyboard to answer a biometric
    // prompt, whatever else is installed.
    if env.service_account_token {
        return Selection {
            kind: StoreKind::OnePasswordServiceAccount,
            reason: Reason::ServiceAccountToken,
        };
    }
    if env.op_present && env.op_account_usable {
        return Selection {
            kind: StoreKind::OnePasswordDesktop,
            reason: Reason::OnePasswordDesktopReachable,
        };
    }
    if env.keychain_available {
        return Selection {
            kind: StoreKind::OsKeychain,
            reason: Reason::NoOpSoKeychain,
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
            op_present: true,
            op_account_usable: true,
            keychain_available: true,
            service_account_token: false,
        }
    }

    #[test]
    fn an_operator_machine_uses_the_desktop_app() {
        let chosen = choose(&operator_machine(), None);
        assert_eq!(chosen.kind, StoreKind::OnePasswordDesktop);
        assert_eq!(chosen.reason, Reason::OnePasswordDesktopReachable);
        assert!(!chosen.warns());
    }

    #[test]
    fn a_service_account_token_wins_over_the_desktop_app() {
        // Even on a machine with the app installed: the token means there
        // is no one to answer a prompt.
        let env = Environment {
            service_account_token: true,
            ..operator_machine()
        };
        let chosen = choose(&env, None);
        assert_eq!(chosen.kind, StoreKind::OnePasswordServiceAccount);
        assert_eq!(chosen.reason, Reason::ServiceAccountToken);
    }

    #[test]
    fn op_installed_but_unreachable_falls_through_to_the_keychain() {
        let env = Environment {
            op_account_usable: false,
            ..operator_machine()
        };
        let chosen = choose(&env, None);
        assert_eq!(chosen.kind, StoreKind::OsKeychain);
        assert_eq!(chosen.reason, Reason::NoOpSoKeychain);
    }

    #[test]
    fn a_bare_machine_falls_through_to_a_file_and_says_so() {
        let chosen = choose(&Environment::none(), None);
        assert_eq!(chosen.kind, StoreKind::File);
        assert_eq!(chosen.reason, Reason::NothingElseAvailable);
        assert!(
            chosen.warns(),
            "the file store is the one case the operator must be told about"
        );
    }

    #[test]
    fn an_explicit_choice_wins_over_every_fact() {
        for requested in [
            StoreKind::File,
            StoreKind::OsKeychain,
            StoreKind::OnePasswordDesktop,
            StoreKind::OnePasswordServiceAccount,
        ] {
            let chosen = choose(&operator_machine(), Some(requested));
            assert_eq!(chosen.kind, requested);
            assert_eq!(chosen.reason, Reason::Requested);
        }
    }

    #[test]
    fn every_reason_prints_something_actionable() {
        for reason in [
            Reason::Requested,
            Reason::ServiceAccountToken,
            Reason::OnePasswordDesktopReachable,
            Reason::NoOpSoKeychain,
            Reason::NothingElseAvailable,
        ] {
            let text = reason.to_string();
            assert!(text.len() > 20, "{reason:?} prints `{text}`");
        }
    }
}
