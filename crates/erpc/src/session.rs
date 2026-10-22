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
use std::path::PathBuf;

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
/// `probe_desktop` says whether to run `op account list`. It is false for
/// anything that only wants to report, because starting a subprocess to
/// answer a question nobody asked would slow every command down and could
/// raise a biometric prompt; it is true when a session is about to be
/// written and the answer decides where.
///
/// Without the probe `op_account_usable` stays false, so an installed `op`
/// alone never selects the desktop store. The binary being on disk says
/// nothing about whether the app is running, signed in, or has CLI
/// integration switched on.
#[must_use]
pub fn detect_environment(probe_desktop: bool) -> Environment {
    let op_present = OpCli::discover().is_some();
    Environment {
        service_account_token: std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN")
            .is_some_and(|v| !v.is_empty()),
        op_present,
        op_account_usable: op_present && probe_desktop && desktop_app_answers(),
        keychain_available: cfg!(any(target_os = "macos", target_os = "windows"))
            || std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some(),
    }
}

/// Runs `op account list` and reports whether it succeeded.
///
/// The only thing that can establish that the desktop app is reachable.
/// Any failure -- not installed, signed out, integration off, prompt
/// dismissed -- is a no, and the caller falls through to the keychain.
fn desktop_app_answers() -> bool {
    let Some(path) = OpCli::discover() else {
        return false;
    };
    std::process::Command::new(path)
        .args(["account", "list", "--format", "json"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Chooses the store for this machine, honouring an explicit request.
///
/// `probe_desktop` is passed through to [`detect_environment`]. An explicit
/// request skips the probe entirely: the operator has already decided, and
/// a subprocess would only delay them.
#[must_use]
pub fn plan_store(requested: Option<StoreKind>) -> Selection {
    let probe_desktop = requested.is_none();
    choose(&detect_environment(probe_desktop), requested)
}

/// Whether a person can be prompted right now.
#[must_use]
pub fn has_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// The erpc state directory, `~/.erpc/state`.
///
/// `ERPC_HOME` overrides the root, which is what makes a test, and a CI
/// job, able to run without touching the operator's own files.
#[must_use]
pub fn state_dir() -> PathBuf {
    state_dir_from(|name| std::env::var_os(name))
}

/// The state directory, reading the environment through `var`.
///
/// Split out so a test can describe a machine instead of mutating the
/// process environment, which this workspace forbids anyway: changing a
/// variable is `unsafe` in this edition because another thread may be
/// reading it.
#[must_use]
pub fn state_dir_from<F>(var: F) -> PathBuf
where
    F: Fn(&str) -> Option<std::ffi::OsString>,
{
    let root = var("ERPC_HOME").map_or_else(
        || {
            var("HOME")
                .map_or_else(|| PathBuf::from("."), PathBuf::from)
                .join(".erpc")
        },
        PathBuf::from,
    );
    root.join("state")
}

/// The account name a session is filed under.
///
/// The operating-system user, which is what distinguishes two accounts on
/// one machine before anyone has signed in and there is a better name.
#[must_use]
pub fn local_account() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "default".to_owned())
}

/// This machine's name, for the 1Password item title.
#[must_use]
pub fn host_label() -> String {
    std::env::var("ERPC_HOST_LABEL")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_owned())
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
    fn an_installed_op_alone_does_not_select_the_desktop_store() {
        // The binary being on disk says nothing about whether the app is
        // running, signed in, or has CLI integration on. Without the probe
        // the fact stays false and the choice falls through.
        let env = Environment {
            op_present: true,
            op_account_usable: false,
            keychain_available: true,
            service_account_token: false,
        };
        let chosen = choose(&env, None);
        assert_eq!(chosen.kind, StoreKind::OsKeychain);
    }

    #[test]
    fn the_reason_for_falling_through_does_not_claim_the_app_answered() {
        let env = Environment {
            op_present: true,
            op_account_usable: false,
            keychain_available: true,
            service_account_token: false,
        };
        let report: StoreReport = choose(&env, None).into();
        assert!(
            !report.reason.contains("answered") || report.reason.contains("did not answer"),
            "a fall-through must not read as success: {}",
            report.reason
        );
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
    fn erpc_home_moves_the_state_directory() {
        let moved = super::state_dir_from(|n| match n {
            "ERPC_HOME" => Some(std::ffi::OsString::from("/srv/erpc")),
            _ => None,
        });
        assert_eq!(moved, std::path::Path::new("/srv/erpc/state"));
    }

    #[test]
    fn without_erpc_home_the_state_directory_is_under_the_home_directory() {
        let home = super::state_dir_from(|n| match n {
            "HOME" => Some(std::ffi::OsString::from("/home/alice")),
            _ => None,
        });
        assert_eq!(home, std::path::Path::new("/home/alice/.erpc/state"));
    }

    #[test]
    fn an_account_name_is_always_available() {
        assert!(!super::local_account().is_empty());
        assert!(!super::host_label().is_empty());
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
