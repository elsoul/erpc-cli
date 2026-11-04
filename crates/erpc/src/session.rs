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
use erpc_auth::store::StoreKind;
use erpc_auth::store::one_password::{Mode, OpCli, OpRunner as _};
use erpc_auth::store::select::{Environment, Selection, choose};

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
/// Nothing here starts a process. Whether the 1Password desktop app answers
/// is asked only by `erpc login`, when it offers the choice, because asking
/// can raise a biometric prompt.
#[must_use]
pub fn detect_environment() -> Environment {
    Environment {
        service_account_token: std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN")
            .is_some_and(|v| !v.is_empty()),
        // Linux always has one: the Secret Service where it answers, and
        // the kernel's keyring where it does not.
        keychain_available: cfg!(any(
            target_os = "macos",
            target_os = "windows",
            target_os = "linux"
        )) || std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some(),
    }
}

/// Asks `op` whether 1Password answers as the operator, and reports
/// whether it did.
///
/// The only thing that can establish it. With the desktop app, `op account
/// list`; with a session from `op signin`, `op whoami`, because without the
/// app `op account list` succeeds signed in or not. Any failure -- not
/// installed, signed out, integration off, prompt dismissed, the session
/// expired -- is a no, and `erpc login` does not offer 1Password.
///
/// Through the same runner the store uses, so the probe gets the same small
/// environment as every other `op` this binary starts, not all of this
/// process's.
pub fn desktop_app_answers() -> bool {
    let args: &[&str] = if signin_session() {
        &["whoami", "--format", "json"]
    } else {
        &["account", "list", "--format", "json"]
    };
    OpCli::from_env(Mode::Desktop, |name| std::env::var_os(name))
        .and_then(|cli| cli.run(args, None))
        .is_ok_and(|out| out.success)
}

/// Whether this shell holds a session from `op signin`, which 1Password
/// is reached through where there is no desktop app.
#[must_use]
pub fn signin_session() -> bool {
    std::env::vars_os().any(|(name, value)| {
        !value.is_empty()
            && name
                .to_str()
                .is_some_and(erpc_auth::store::one_password::is_signin_session)
    })
}

/// A 1Password vault, as `op vault list` names it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Vault {
    /// The vault id, which is what erpc records.
    pub id: String,
    /// The name the operator knows it by.
    pub name: String,
}

/// The vaults the signed-in 1Password account can see.
///
/// # Errors
///
/// Returns a message when `op` cannot be run or does not answer.
pub fn list_vaults() -> Result<Vec<Vault>, String> {
    let cli =
        OpCli::from_env(Mode::Desktop, |name| std::env::var_os(name)).map_err(|e| e.to_string())?;
    let out = cli
        .run(&["vault", "list", "--format", "json"], None)
        .map_err(|e| e.to_string())?;
    if !out.success {
        return Err(
            "`op vault list` failed; check that the 1Password app is running and unlocked, \
             or, without the app, that the `op signin` session has not expired"
                .to_owned(),
        );
    }
    serde_json::from_str(&out.stdout).map_err(|e| {
        format!(
            "could not read `op vault list`'s output at line {}, column {}",
            e.line(),
            e.column()
        )
    })
}

/// The vault offered first: the account's own vault, which only its
/// owner can see, when there is one with a name 1Password gives it.
///
/// Never a shared vault by default. A session put in a vault other people
/// can read is a session other people can use.
#[must_use]
pub fn personal_vault(vaults: &[Vault]) -> Option<usize> {
    ["Employee", "Private", "Personal"]
        .iter()
        .find_map(|name| vaults.iter().position(|v| v.name == *name))
}

/// Chooses the store for this machine: `--store` first, then the store
/// `erpc login` recorded in the configuration, then the default.
#[must_use]
pub fn plan_store(requested: Option<StoreKind>, configured: Option<StoreKind>) -> Selection {
    choose(&detect_environment(), requested, configured)
}

/// Where the configuration lives: `config.toml` beside the state directory.
///
/// # Errors
///
/// Returns a message when there is no absolute place for erpc's files; see
/// [`state_dir`].
pub fn config_path() -> Result<PathBuf, String> {
    let state = state_dir()?;
    Ok(state.parent().map_or_else(
        || state.join("config.toml"),
        |root| root.join("config.toml"),
    ))
}

/// `name` in the directory `config.toml` is in, where erpc keeps its
/// other files.
///
/// # Errors
///
/// Returns a message when there is no home directory.
pub fn beside_config(name: &str) -> Result<PathBuf, String> {
    let config = config_path()?;
    Ok(config
        .parent()
        .map_or_else(|| PathBuf::from(name), |p| p.join(name)))
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
///
/// `ERPC_HOST_LABEL` when set, and otherwise the name the operating system
/// gives the machine. Not `$HOSTNAME`: shells set it without exporting it,
/// so erpc never saw it, and every machine was `unknown-host` -- one item
/// title for all of them, which is the sharing the host in the title is
/// there to prevent.
#[must_use]
pub fn host_label() -> String {
    std::env::var("ERPC_HOST_LABEL")
        .ok()
        .and_then(|label| tidy_host(&label))
        .or_else(system_host_name)
        .unwrap_or_else(|| "unknown-host".to_owned())
}

/// The operating system's name for this machine.
fn system_host_name() -> Option<String> {
    #[cfg(target_os = "linux")]
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname").ok();
    #[cfg(target_os = "macos")]
    let name = std::process::Command::new("/usr/sbin/scutil")
        .args(["--get", "LocalHostName"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok());
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let name = std::env::var("COMPUTERNAME").ok();
    name.as_deref().and_then(tidy_host)
}

/// A host name as it goes into a title: trimmed, and none when empty.
fn tidy_host(name: &str) -> Option<String> {
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_owned())
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
        let selection = plan_store(Some(StoreKind::File), Some(StoreKind::OsKeychain));
        assert_eq!(selection.kind, StoreKind::File);
    }

    #[test]
    fn the_personal_vault_is_offered_first_and_a_shared_one_never() {
        let vault = |name: &str| super::Vault {
            id: format!("id-{name}"),
            name: name.to_owned(),
        };
        let business = [vault("Shared"), vault("Employee"), vault("Accounting")];
        assert_eq!(super::personal_vault(&business), Some(1));
        let shared_only = [vault("Shared"), vault("Automation")];
        assert_eq!(super::personal_vault(&shared_only), None);
    }

    #[test]
    fn the_recorded_store_is_used_when_none_is_named() {
        let selection = plan_store(None, Some(StoreKind::OnePasswordDesktop));
        assert_eq!(selection.kind, StoreKind::OnePasswordDesktop);
    }

    #[test]
    fn the_report_carries_the_warning_flag_for_the_file_store() {
        let report: StoreReport = choose(&Environment::none(), None, None).into();
        assert_eq!(report.store, "file");
        assert!(report.writes_to_disk);
        assert!(!report.reason.is_empty());
    }

    #[test]
    fn the_report_does_not_warn_for_a_store_that_keeps_nothing_on_disk() {
        let selection = Selection {
            kind: StoreKind::OnePasswordDesktop,
            reason: erpc_auth::store::select::Reason::Configured,
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
    fn the_real_lookup_gives_an_absolute_directory_here() {
        // The other tests hand `state_dir_from` the paths. This one asks the
        // platform, which is the part Windows does differently: no `HOME`,
        // a profile directory instead. CI runs it on all three.
        let dir = super::state_dir().expect("a home directory on this machine");
        assert!(dir.is_absolute(), "{}", dir.display());
    }

    #[test]
    fn the_state_directory_is_never_relative() {
        // With no home directory it used to fall back to `.`, which put
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
    fn the_host_is_the_machine_s_own_name() {
        // Wherever the platform can tell, which is every one CI runs on.
        let name = super::system_host_name().expect("the machine has a name");
        assert!(!name.is_empty() && name.trim() == name, "{name:?}");
        assert_eq!(super::tidy_host("  box-1\n").as_deref(), Some("box-1"));
        assert_eq!(super::tidy_host(" \n"), None);
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
