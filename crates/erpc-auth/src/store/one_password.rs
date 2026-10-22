// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Sessions kept in 1Password, through the `op` command line.
//!
//! Two modes share everything but how they authenticate:
//!
//! * [`Desktop`] talks to the 1Password application, which asks the
//!   operator for biometrics. This is the default on a person's machine.
//! * [`ServiceAccount`] uses a token from the environment. This is how CI,
//!   a headless server or a resident agent reaches a session.
//!
//! Both drive `op` as a subprocess with a deliberately small environment.
//! `op` is resolved from an absolute path rather than by searching `PATH`,
//! because a gate that can be redirected by a `PATH` entry is not a gate.
//!
//! The item is an API Credential titled `ERPC CLI session <account>@<host>`.
//! The host is in the title because one item must not be shared between
//! machines: two machines refreshing the same session would each invalidate
//! the other's token family and log both out.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use super::{CredentialStore, StoreError, StoreKind};
use crate::credential::{CredKey, Credential, STORE_VERSION};

/// The 1Password item category sessions are stored under.
pub const ITEM_CATEGORY: &str = "API Credential";

/// The field names inside the item.
mod field {
    /// The bearer token.
    pub const ACCESS: &str = "access_token";
    /// The token used to obtain the next access token.
    pub const REFRESH: &str = "refresh_token";
    /// The access token's expiry, as a Unix timestamp in seconds.
    pub const EXPIRES_AT: &str = "expires_at";
    /// The record format version.
    pub const STORE_VERSION: &str = "store_version";
}

/// Where `op` is looked for when the configuration does not say.
///
/// Absolute paths only. `PATH` is not searched: an `op` picked up from the
/// environment could be anything, and this process hands it secrets.
const KNOWN_OP_PATHS: &[&str] = &[
    "/usr/local/bin/op",
    "/opt/homebrew/bin/op",
    "/usr/bin/op",
    "/home/linuxbrew/.linuxbrew/bin/op",
    "C:\\Program Files\\1Password CLI\\op.exe",
];

/// What `op` printed.
#[derive(Debug, Clone)]
pub struct OpOutput {
    /// Whether `op` exited successfully.
    pub success: bool,
    /// Standard output.
    pub stdout: String,
    /// Standard error, already shortened for display.
    pub stderr: String,
}

/// Runs `op`. Injectable so that the command this store builds can be
/// tested without 1Password being installed.
pub trait OpRunner {
    /// Runs `op` with `args`, optionally feeding `stdin`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the process cannot be started.
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError>;
}

/// The real `op` binary.
#[derive(Debug, Clone)]
pub struct OpCli {
    path: PathBuf,
    env: BTreeMap<String, OsString>,
}

impl OpCli {
    /// Builds a runner for an `op` at an absolute path.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] when the path is not absolute.
    pub fn at(
        path: impl Into<PathBuf>,
        extra_env: BTreeMap<String, OsString>,
    ) -> Result<Self, StoreError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(StoreError::Unavailable {
                kind: StoreKind::OnePasswordDesktop,
                reason: format!(
                    "`op` must be given as an absolute path, got {}",
                    path.display()
                ),
            });
        }
        Ok(Self {
            path,
            env: extra_env,
        })
    }

    /// Looks for `op` at the known absolute locations.
    #[must_use]
    pub fn discover() -> Option<PathBuf> {
        KNOWN_OP_PATHS
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .map(Path::to_path_buf)
    }

    /// Builds a runner for the given mode, reading the small set of
    /// variables `op` is allowed to see from `var`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] when `op` cannot be found at any
    /// of the known absolute locations, or when `mode` is
    /// [`Mode::ServiceAccount`] and no token is in the environment.
    pub fn from_env(
        mode: Mode,
        var: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Self, StoreError> {
        let path = Self::discover().ok_or_else(|| StoreError::Unavailable {
            kind: mode.kind(),
            reason: "the 1Password CLI (op) was not found at any known absolute path".to_owned(),
        })?;
        let mut env = Self::base_env(&var);
        match mode {
            Mode::Desktop => {
                // Desktop integration is what makes the app prompt for
                // biometrics instead of failing in the background.
                env.insert(
                    "OP_BIOMETRIC_UNLOCK_ENABLED".to_owned(),
                    OsString::from("true"),
                );
            }
            Mode::ServiceAccount => {
                let token = var("OP_SERVICE_ACCOUNT_TOKEN")
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| StoreError::Unavailable {
                        kind: mode.kind(),
                        reason: "OP_SERVICE_ACCOUNT_TOKEN is not set".to_owned(),
                    })?;
                // Passed through to the child, never written anywhere.
                env.insert("OP_SERVICE_ACCOUNT_TOKEN".to_owned(), token);
            }
        }
        Self::at(path, env)
    }

    /// The variables `op` is allowed to see, beyond the mode's own.
    ///
    /// Everything else is removed. A smaller environment means fewer ways
    /// for a surprise variable to change which account `op` talks to.
    fn base_env(var: impl Fn(&str) -> Option<OsString>) -> BTreeMap<String, OsString> {
        let mut env = BTreeMap::new();
        for name in ["HOME", "PATH", "USER", "LANG", "TMPDIR", "OP_ACCOUNT"] {
            if let Some(value) = var(name) {
                env.insert(name.to_owned(), value);
            }
        }
        env.insert("OP_CACHE".to_owned(), OsString::from("false"));
        env
    }
}

impl OpRunner for OpCli {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
        use std::io::Write as _;
        use std::process::Stdio;

        let mut command = Command::new(&self.path);
        command.args(args).env_clear().envs(&self.env);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });

        let mut child = command.spawn().map_err(|e| StoreError::Unavailable {
            kind: StoreKind::OnePasswordDesktop,
            reason: format!("could not run {}: {e}", self.path.display()),
        })?;
        if let Some(input) = stdin {
            let mut handle = child.stdin.take().ok_or_else(|| StoreError::Backend {
                kind: StoreKind::OnePasswordDesktop,
                operation: "open a pipe to op",
                reason: "the child had no stdin".to_owned(),
            })?;
            handle
                .write_all(input.as_bytes())
                .map_err(|e| StoreError::Backend {
                    kind: StoreKind::OnePasswordDesktop,
                    operation: "write to op",
                    reason: e.to_string(),
                })?;
        }
        let output = child.wait_with_output().map_err(|e| StoreError::Backend {
            kind: StoreKind::OnePasswordDesktop,
            operation: "wait for op",
            reason: e.to_string(),
        })?;
        Ok(OpOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: first_line(&String::from_utf8_lossy(&output.stderr)),
        })
    }
}

/// Keeps the first line of `op`'s diagnostics and drops the rest.
///
/// `op` can be chatty, and a long message is both unhelpful in an error and
/// more surface for something sensitive to appear in.
fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or_default().trim();
    if line.len() > 200 {
        let mut cut = 200;
        while !line.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &line[..cut])
    } else {
        line.to_owned()
    }
}

/// How a 1Password store authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Through the desktop application, with biometrics.
    Desktop,
    /// With a service account token from the environment.
    ServiceAccount,
}

impl Mode {
    /// The store kind this mode reports.
    #[must_use]
    pub const fn kind(self) -> StoreKind {
        match self {
            Self::Desktop => StoreKind::OnePasswordDesktop,
            Self::ServiceAccount => StoreKind::OnePasswordServiceAccount,
        }
    }
}

/// A session store backed by a 1Password vault.
pub struct OnePassword<R: OpRunner> {
    runner: R,
    mode: Mode,
    vault: String,
    host: String,
}

/// The desktop-backed store.
pub type Desktop<R> = OnePassword<R>;
/// The service-account-backed store.
pub type ServiceAccount<R> = OnePassword<R>;

impl<R: OpRunner> OnePassword<R> {
    /// Builds a store for one vault, on one host.
    ///
    /// `vault` is a 1Password vault identifier and `host` is this machine's
    /// name, which goes into the item title.
    pub fn new(runner: R, mode: Mode, vault: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            runner,
            mode,
            vault: vault.into(),
            host: host.into(),
        }
    }

    /// The item title a session is filed under.
    #[must_use]
    pub fn item_title(&self, key: &CredKey) -> String {
        format!(
            "ERPC CLI session {}@{} ({})",
            key.account(),
            self.host,
            key.audience()
        )
    }

    fn backend(&self, operation: &'static str, reason: String) -> StoreError {
        StoreError::Backend {
            kind: self.mode.kind(),
            operation,
            reason,
        }
    }
}

/// The parts of `op item get --format json` this store reads.
#[derive(Debug, Deserialize)]
struct OpItem {
    #[serde(default)]
    fields: Vec<OpField>,
}

/// One field of an item.
#[derive(Debug, Deserialize)]
struct OpField {
    #[serde(default)]
    label: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    value: String,
}

impl OpItem {
    /// The value of the field with this label or id.
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.label == name || f.id == name)
            .map(|f| f.value.as_str())
    }
}

impl<R: OpRunner> CredentialStore for OnePassword<R> {
    fn load(&self, key: &CredKey) -> Result<Option<Credential>, StoreError> {
        let title = self.item_title(key);
        let out = self.runner.run(
            &[
                "item",
                "get",
                &title,
                "--vault",
                &self.vault,
                "--format",
                "json",
            ],
            None,
        )?;
        if !out.success {
            // `op` says "isn't an item" for a miss. Anything else is a
            // failure the operator needs to see rather than a missing
            // session, which would silently start a fresh login.
            if out.stderr.contains("isn't an item") || out.stderr.contains("not found") {
                return Ok(None);
            }
            return Err(self.backend("read the item", out.stderr));
        }

        let item: OpItem =
            serde_json::from_str(&out.stdout).map_err(|e| StoreError::Corrupt(e.to_string()))?;

        let version = item
            .field(field::STORE_VERSION)
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        if version != STORE_VERSION {
            return Err(StoreError::UnknownVersion {
                found: version,
                expected: STORE_VERSION,
            });
        }
        let (Some(access), Some(refresh), Some(expires)) = (
            item.field(field::ACCESS),
            item.field(field::REFRESH),
            item.field(field::EXPIRES_AT),
        ) else {
            return Err(StoreError::Corrupt(
                "the item does not have the expected fields".to_owned(),
            ));
        };
        let expires_at = expires
            .parse::<i64>()
            .map_err(|e| StoreError::Corrupt(format!("expires_at is not a timestamp: {e}")))?;

        Ok(Some(Credential {
            access_token: SecretString::from(access.to_owned()),
            refresh_token: SecretString::from(refresh.to_owned()),
            expires_at,
        }))
    }

    fn save(&self, key: &CredKey, cred: &Credential) -> Result<(), StoreError> {
        let title = self.item_title(key);
        let access = format!("{}={}", field::ACCESS, cred.access_token.expose_secret());
        let refresh = format!("{}={}", field::REFRESH, cred.refresh_token.expose_secret());
        let expires = format!("{}={}", field::EXPIRES_AT, cred.expires_at);
        let version = format!("{}={}", field::STORE_VERSION, STORE_VERSION);

        // Edit first. `op item edit` replaces the fields in one call, which
        // is the atomic replacement the trait promises; create would leave
        // a second item with the same title.
        let edit = self.runner.run(
            &[
                "item",
                "edit",
                &title,
                "--vault",
                &self.vault,
                &access,
                &refresh,
                &expires,
                &version,
            ],
            None,
        )?;
        if edit.success {
            return Ok(());
        }
        if !(edit.stderr.contains("isn't an item") || edit.stderr.contains("not found")) {
            return Err(self.backend("update the item", edit.stderr));
        }

        let create = self.runner.run(
            &[
                "item",
                "create",
                "--category",
                ITEM_CATEGORY,
                "--title",
                &title,
                "--vault",
                &self.vault,
                &access,
                &refresh,
                &expires,
                &version,
            ],
            None,
        )?;
        if create.success {
            Ok(())
        } else {
            Err(self.backend("create the item", create.stderr))
        }
    }

    fn delete(&self, key: &CredKey) -> Result<(), StoreError> {
        let title = self.item_title(key);
        let out = self
            .runner
            .run(&["item", "delete", &title, "--vault", &self.vault], None)?;
        if out.success || out.stderr.contains("isn't an item") || out.stderr.contains("not found") {
            Ok(())
        } else {
            Err(self.backend("remove the item", out.stderr))
        }
    }

    fn kind(&self) -> StoreKind {
        self.mode.kind()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::ffi::OsString;

    use secrecy::{ExposeSecret as _, SecretString};

    use super::{Mode, OnePassword, OpCli, OpOutput, OpRunner, first_line};
    use crate::credential::{Audience, CredKey, Credential};
    use crate::store::{CredentialStore as _, StoreError, StoreKind};

    /// Records the commands it is given and replies from a script.
    struct FakeOp {
        calls: RefCell<Vec<Vec<String>>>,
        replies: RefCell<Vec<OpOutput>>,
    }

    impl FakeOp {
        fn new(replies: Vec<OpOutput>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                replies: RefCell::new(replies),
            }
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.borrow().clone()
        }
    }

    impl OpRunner for &FakeOp {
        fn run(&self, args: &[&str], _stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).to_owned()).collect());
            let mut replies = self.replies.borrow_mut();
            if replies.is_empty() {
                Ok(OpOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "no reply scripted".to_owned(),
                })
            } else {
                Ok(replies.remove(0))
            }
        }
    }

    fn ok(stdout: &str) -> OpOutput {
        OpOutput {
            success: true,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    fn missing() -> OpOutput {
        OpOutput {
            success: false,
            stdout: String::new(),
            stderr: "\"x\" isn't an item. Specify the item with its UUID, name, or domain."
                .to_owned(),
        }
    }

    fn key() -> CredKey {
        CredKey::new(Audience::AuthApi, "alice")
    }

    const VAULT: &str = "4xq7zj2mn8d5r3vb6kwth9pcyf";

    #[test]
    fn the_item_title_names_the_account_the_host_and_the_audience() {
        let fake = FakeOp::new(vec![]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        assert_eq!(
            store.item_title(&key()),
            "ERPC CLI session alice@mac-001 (auth-api)"
        );
        // Two machines must not share one item: a refresh on either would
        // invalidate the other's token family.
        let other = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-002");
        assert_ne!(store.item_title(&key()), other.item_title(&key()));
    }

    #[test]
    fn a_missing_item_reads_as_no_session() {
        let fake = FakeOp::new(vec![missing()]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        assert!(
            store
                .load(&key())
                .expect("a miss is not an error")
                .is_none()
        );
    }

    #[test]
    fn a_failure_that_is_not_a_miss_is_an_error() {
        let fake = FakeOp::new(vec![OpOutput {
            success: false,
            stdout: String::new(),
            stderr: "authorization prompt dismissed".to_owned(),
        }]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        // Reporting this as "no session" would silently start a new login
        // and leave the old one in the vault.
        assert!(store.load(&key()).is_err());
    }

    #[test]
    fn a_stored_item_is_read_back() {
        let json = r#"{"fields":[
            {"id":"a","label":"access_token","value":"a.b.c"},
            {"id":"b","label":"refresh_token","value":"d.e.f"},
            {"id":"c","label":"expires_at","value":"1700000000"},
            {"id":"d","label":"store_version","value":"1"}
        ]}"#;
        let fake = FakeOp::new(vec![ok(json)]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        let got = store.load(&key()).expect("load").expect("present");
        assert_eq!(got.access_token.expose_secret(), "a.b.c");
        assert_eq!(got.expires_at, 1_700_000_000);

        let call = &store_calls(&fake)[0];
        assert_eq!(call[0], "item");
        assert_eq!(call[1], "get");
        assert!(call.contains(&"--vault".to_owned()));
        assert!(call.contains(&VAULT.to_owned()));
    }

    #[test]
    fn an_item_from_another_version_is_refused() {
        let json = r#"{"fields":[
            {"id":"a","label":"access_token","value":"a.b.c"},
            {"id":"b","label":"refresh_token","value":"d.e.f"},
            {"id":"c","label":"expires_at","value":"1700000000"},
            {"id":"d","label":"store_version","value":"7"}
        ]}"#;
        let fake = FakeOp::new(vec![ok(json)]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        assert!(matches!(
            store.load(&key()),
            Err(StoreError::UnknownVersion {
                found: 7,
                expected: 1
            })
        ));
    }

    #[test]
    fn an_item_missing_a_field_is_corrupt_not_absent() {
        let json = r#"{"fields":[{"id":"d","label":"store_version","value":"1"}]}"#;
        let fake = FakeOp::new(vec![ok(json)]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        assert!(matches!(store.load(&key()), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn saving_edits_an_existing_item_in_one_call() {
        let fake = FakeOp::new(vec![ok("")]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        store
            .save(
                &key(),
                &Credential {
                    access_token: SecretString::from("a.b.c"),
                    refresh_token: SecretString::from("d.e.f"),
                    expires_at: 7,
                },
            )
            .expect("save");

        let calls = store_calls(&fake);
        assert_eq!(calls.len(), 1, "an edit should not be followed by a create");
        assert_eq!(calls[0][1], "edit");
        assert!(calls[0].iter().any(|a| a == "access_token=a.b.c"));
        assert!(calls[0].iter().any(|a| a == "store_version=1"));
    }

    #[test]
    fn saving_creates_the_item_when_there_is_none() {
        let fake = FakeOp::new(vec![missing(), ok("")]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        store
            .save(
                &key(),
                &Credential {
                    access_token: SecretString::from("a.b.c"),
                    refresh_token: SecretString::from("d.e.f"),
                    expires_at: 7,
                },
            )
            .expect("save");

        let calls = store_calls(&fake);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][1], "create");
        assert!(calls[1].iter().any(|a| a == "API Credential"));
    }

    #[test]
    fn deleting_an_item_that_is_not_there_succeeds() {
        let fake = FakeOp::new(vec![missing()]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        store.delete(&key()).expect("deleting nothing is fine");
    }

    #[test]
    fn the_two_modes_report_different_kinds() {
        let fake = FakeOp::new(vec![]);
        assert_eq!(
            OnePassword::new(&fake, Mode::Desktop, VAULT, "h").kind(),
            StoreKind::OnePasswordDesktop
        );
        assert_eq!(
            OnePassword::new(&fake, Mode::ServiceAccount, VAULT, "h").kind(),
            StoreKind::OnePasswordServiceAccount
        );
    }

    #[test]
    fn op_must_be_an_absolute_path() {
        // A relative `op` would be resolved against the working directory,
        // which is how a gate gets pointed at something else.
        assert!(OpCli::at("op", BTreeMap::new()).is_err());
        assert!(OpCli::at("./op", BTreeMap::new()).is_err());
    }

    #[test]
    fn the_environment_passed_to_op_is_small_and_disables_the_cache() {
        let env = OpCli::base_env(|name| match name {
            "HOME" => Some(OsString::from("/home/alice")),
            "PATH" => Some(OsString::from("/usr/bin")),
            "SECRET_SAUCE" => Some(OsString::from("leak me")),
            _ => None,
        });
        assert_eq!(env.get("HOME"), Some(&OsString::from("/home/alice")));
        assert_eq!(env.get("OP_CACHE"), Some(&OsString::from("false")));
        assert!(
            !env.contains_key("SECRET_SAUCE"),
            "only the named variables are passed through"
        );
    }

    #[test]
    fn a_service_account_runner_needs_its_token() {
        let err = OpCli::from_env(Mode::ServiceAccount, |_| None)
            .expect_err("without a token there is nothing to authenticate with");
        assert!(matches!(err, StoreError::Unavailable { .. }));
    }

    #[test]
    fn diagnostics_are_cut_to_one_line() {
        assert_eq!(first_line("one\ntwo\nthree"), "one");
        let long = "x".repeat(400);
        let cut = first_line(&long);
        assert!(cut.chars().count() <= 201, "{}", cut.chars().count());
    }

    fn store_calls(fake: &FakeOp) -> Vec<Vec<String>> {
        fake.calls()
    }
}
