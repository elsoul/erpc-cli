// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc login`, `erpc logout` and `erpc whoami`.
//!
//! What is wired here is the part that does not need the network: which
//! store a session goes to, what the operator is told, and what each exit
//! code means. The HTTP side of the device grant is the next piece of this
//! phase; until it lands, `login` reports what it would do and stops rather
//! than pretending to have signed anyone in.

use std::io::IsTerminal as _;

use erpc_auth::credential::Audience;
use erpc_auth::store::select::{Environment, Selection, choose};
use erpc_auth::store::{StoreKind, one_password::OpCli};

/// What a session command decided, in a form both renderers can print.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoreReport {
    /// The store that would hold the session.
    pub store: String,
    /// Why that store was chosen.
    pub reason: String,
    /// Whether this choice leaves a secret on the local disk.
    pub writes_to_disk: bool,
}

impl From<Selection> for StoreReport {
    fn from(selection: Selection) -> Self {
        Self {
            store: selection.kind.to_string(),
            reason: selection.reason.to_string(),
            writes_to_disk: selection.warns(),
        }
    }
}

/// Reads the facts the store choice is made from.
///
/// `op account list` is not run here: starting a subprocess to answer a
/// question nobody asked would make `erpc --help` slower and could pop a
/// biometric prompt. Presence of the binary is what this checks, and the
/// first real use is what discovers whether the app answers.
#[must_use]
pub fn detect_environment() -> Environment {
    let op_present = OpCli::discover().is_some();
    Environment {
        service_account_token: std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN")
            .is_some_and(|v| !v.is_empty()),
        op_present,
        op_account_usable: op_present,
        keychain_available: cfg!(any(target_os = "macos", target_os = "windows"))
            || std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some(),
    }
}

/// Chooses the store for this machine, honouring an explicit request.
#[must_use]
pub fn plan_store(requested: Option<StoreKind>) -> Selection {
    choose(&detect_environment(), requested)
}

/// Whether a person can be prompted right now.
#[must_use]
pub fn has_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// The audience `erpc login` signs in to.
pub const LOGIN_AUDIENCE: Audience = Audience::AuthApi;

/// The one-line warning shown when a session will be written to disk.
///
/// States the consequence and not the cause: the cause is printed on its
/// own line beside it, and the two readings of it (no store was available,
/// or the operator asked for this one) are different sentences.
pub const DISK_WARNING: &str = "the session will be written to a file on this machine, which is \
     the one case where erpc leaves a secret on disk; `erpc doctor` reports it for as long as it \
     is there";

#[cfg(test)]
mod tests {
    use super::{DISK_WARNING, LOGIN_AUDIENCE, StoreReport, plan_store};
    use erpc_auth::credential::Audience;
    use erpc_auth::store::StoreKind;
    use erpc_auth::store::select::{Environment, Selection, choose};

    #[test]
    fn an_explicit_store_is_honoured_whatever_the_machine_has() {
        let selection = plan_store(Some(StoreKind::File));
        assert_eq!(selection.kind, StoreKind::File);
    }

    #[test]
    fn the_report_carries_the_warning_flag_for_the_file_store() {
        let report: StoreReport = choose(&Environment::none(), None).into();
        assert_eq!(report.store, "file");
        assert!(report.writes_to_disk);
        assert!(!report.reason.is_empty());
    }

    #[test]
    fn the_report_does_not_warn_for_a_store_that_keeps_nothing_on_disk() {
        let selection = Selection {
            kind: StoreKind::OnePasswordDesktop,
            reason: erpc_auth::store::select::Reason::OnePasswordDesktopReachable,
        };
        let report: StoreReport = selection.into();
        assert!(!report.writes_to_disk);
    }

    #[test]
    fn login_signs_in_to_the_account_api() {
        assert_eq!(LOGIN_AUDIENCE, Audience::AuthApi);
    }

    #[test]
    fn the_disk_warning_names_the_tool_that_keeps_reporting_it() {
        assert!(DISK_WARNING.contains("doctor"));
    }
}
