// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc login`, `erpc logout` and `erpc whoami`.
//!
//! What is wired here is the machine's own facts: which store a session
//! goes to, where the state directory is, and what this host and account
//! are called. The library does not go looking for those; a CLI is the
//! right place to know them.

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
/// `probe_desktop` says whether to run `op account list`. [`plan_store`]
/// sets it whenever no store was named, for every command, because then
/// the answer decides which store the command reads or writes. With
/// `--store` the choice is made and the probe is skipped: it would only
/// cost a subprocess and possibly a biometric prompt.
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
///
/// # Errors
///
/// Returns a message when neither `ERPC_HOME` nor the home directory gives
/// an absolute path; see [`state_dir_from`].
pub fn state_dir() -> Result<PathBuf, String> {
    state_dir_from(std::env::var_os("ERPC_HOME"), std::env::home_dir())
}

/// The state directory, from `ERPC_HOME` and the home directory.
///
/// Split out so a test can describe a machine instead of mutating the
/// process environment, which this workspace forbids anyway: changing a
/// variable is `unsafe` in this edition because another thread may be
/// reading it.
///
/// The home directory comes from the platform's own lookup, which on
/// Windows is the profile directory: `HOME` is not set there by default,
/// and reading it alone sent every Windows user to the fallback.
///
/// # Errors
///
/// Refuses rather than falling back to a relative path. The fallback used
/// to be `.`, which put the credentials file and any parked session in
/// whatever directory `erpc` ran in -- possibly a git working tree -- where
/// `erpc doctor`, run from anywhere else, could not see them. It also made
/// the refresh lock one per directory instead of one per machine, so two
/// refreshes from two directories could both rotate the token and revoke
/// the family, which is what the lock exists to prevent.
pub fn state_dir_from(
    erpc_home: Option<std::ffi::OsString>,
    home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    let root = match (erpc_home.filter(|v| !v.is_empty()), home) {
        (Some(explicit), _) => PathBuf::from(explicit),
        (None, Some(home)) => home.join(".erpc"),
        (None, None) => {
            return Err(
                "cannot find a home directory for erpc's state; set ERPC_HOME to an absolute path"
                    .to_owned(),
            );
        }
    };
    if !root.is_absolute() {
        return Err(format!(
            "erpc's state directory must be an absolute path, got {}; set ERPC_HOME to one",
            root.display()
        ));
    }
    Ok(root.join("state"))
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
     the one store that leaves a secret on disk; `erpc doctor` reports it for as long as it is \
     there";

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

    /// An absolute path on whichever platform runs the test. `/srv/erpc`
    /// is relative on Windows, which has no root without a drive.
    fn somewhere_absolute() -> std::path::PathBuf {
        std::env::temp_dir().join("erpc-test-root")
    }

    #[test]
    fn erpc_home_moves_the_state_directory() {
        let root = somewhere_absolute();
        let moved = super::state_dir_from(Some(root.clone().into_os_string()), None)
            .expect("an absolute ERPC_HOME is used as it is");
        assert_eq!(moved, root.join("state"));
    }

    #[test]
    fn without_erpc_home_the_state_directory_is_under_the_home_directory() {
        let home = somewhere_absolute();
        let dir = super::state_dir_from(None, Some(home.clone())).expect("a home directory");
        assert_eq!(dir, home.join(".erpc").join("state"));
    }

    #[test]
    fn the_state_directory_is_never_relative() {
        // Round 6: with no home directory it fell back to `.`, which put
        // secrets in the working directory and split the refresh lock.
        assert!(super::state_dir_from(None, None).is_err());
        assert!(super::state_dir_from(Some(".".into()), None).is_err());
        assert!(super::state_dir_from(Some("relative/erpc".into()), None).is_err());
        assert!(super::state_dir_from(None, Some(".".into())).is_err());
        assert!(super::state_dir_from(Some("".into()), Some(".".into())).is_err());
        // An empty ERPC_HOME is unset, not "here".
        let home = somewhere_absolute();
        assert_eq!(
            super::state_dir_from(Some("".into()), Some(home.clone())).expect("falls through"),
            home.join(".erpc").join("state")
        );
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
