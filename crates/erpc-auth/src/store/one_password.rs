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
pub const ITEM_CATEGORY: &str = "API_CREDENTIAL";

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

    /// The JSON document `op` is given on stdin.
    ///
    /// Built here rather than formatted into arguments so that no token
    /// ever appears in a process listing.
    fn template(title: &str, cred: &Credential) -> Result<String, StoreError> {
        let doc = serde_json::json!({
            "title": title,
            "category": "API_CREDENTIAL",
            "fields": [
                {
                    "id": field::ACCESS,
                    "label": field::ACCESS,
                    "type": "CONCEALED",
                    "value": cred.access_token.expose_secret(),
                },
                {
                    "id": field::REFRESH,
                    "label": field::REFRESH,
                    "type": "CONCEALED",
                    "value": cred.refresh_token.expose_secret(),
                },
                {
                    "id": field::EXPIRES_AT,
                    "label": field::EXPIRES_AT,
                    "type": "STRING",
                    "value": cred.expires_at.to_string(),
                },
                {
                    "id": field::STORE_VERSION,
                    "label": field::STORE_VERSION,
                    "type": "STRING",
                    "value": STORE_VERSION.to_string(),
                },
            ],
        });
        serde_json::to_string(&doc).map_err(|e| StoreError::Backend {
            kind: StoreKind::OnePasswordDesktop,
            operation: "build the item template",
            reason: e.to_string(),
        })
    }

    /// Whether an item with this title exists in the vault.
    ///
    /// Asked with `op item list`, whose success or failure means something,
    /// rather than by reading the words in a failed `op item edit`. Matching
    /// `op`'s prose was wrong in exactly the way that is hard to notice: the
    /// real message for a missing item is "could not find item to edit", the
    /// code looked for "isn't an item" and "not found", so the first sign-in
    /// on a machine reported a failure instead of creating the item. A
    /// message is not an interface; an exit status over a listing is.
    ///
    /// A failure here is returned, not swallowed. "The vault does not exist"
    /// and "the item does not exist" are different problems with different
    /// fixes, and the operator needs to be told which one they have.
    fn item_exists(&self, title: &str) -> Result<bool, StoreError> {
        let out = self.runner.run(
            &["item", "list", "--vault", &self.vault, "--format", "json"],
            None,
        )?;
        if !out.success {
            return Err(self.backend("list the vault", out.stderr));
        }
        let items: Vec<OpListEntry> =
            serde_json::from_str(&out.stdout).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Ok(items.iter().any(|i| i.title == title))
    }

    fn backend(&self, operation: &'static str, reason: String) -> StoreError {
        StoreError::Backend {
            kind: self.mode.kind(),
            operation,
            reason,
        }
    }
}

/// One row of `op item list --format json`.
#[derive(Debug, Deserialize)]
struct OpListEntry {
    #[serde(default)]
    title: String,
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
            // A miss and a failure look alike in `op`'s output, and
            // treating a failure as a miss would silently start a fresh
            // login and strand the session already in the vault. Ask
            // instead of guessing.
            if self.item_exists(&title)? {
                return Err(self.backend("read the item", out.stderr));
            }
            return Ok(None);
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
        let template = Self::template(&title, cred)?;

        // The template goes in on stdin, never in argv. `op` says so
        // itself -- "Command arguments can be visible to other processes
        // on your machine. For sensitive values, use a template instead" --
        // and a refresh token sitting in a process listing is outside the
        // vault boundary this store exists to keep it inside.
        //
        // Ask whether the item is there, then do the one right thing.
        // Editing an item that does not exist and creating one that does
        // are both failures, and the two commands report them in prose
        // that differs between `op` versions.
        if self.item_exists(&title)? {
            // Edit replaces the fields in one call, which is the atomic
            // replacement the trait promises. Create would leave a second
            // item with the same title.
            let edit = self.runner.run(
                &["item", "edit", &title, "--vault", &self.vault],
                Some(&template),
            )?;
            return if edit.success {
                Ok(())
            } else {
                Err(self.backend("update the item", edit.stderr))
            };
        }

        let create = self.runner.run(
            &["item", "create", "-", "--vault", &self.vault],
            Some(&template),
        )?;
        if create.success {
            Ok(())
        } else {
            Err(self.backend("create the item", create.stderr))
        }
    }

    fn delete(&self, key: &CredKey) -> Result<(), StoreError> {
        let title = self.item_title(key);
        if !self.item_exists(&title)? {
            return Ok(());
        }
        let out = self
            .runner
            .run(&["item", "delete", &title, "--vault", &self.vault], None)?;
        if out.success {
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
        stdins: RefCell<Vec<Option<String>>>,
        replies: RefCell<Vec<OpOutput>>,
    }

    impl FakeOp {
        fn new(replies: Vec<OpOutput>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                stdins: RefCell::new(Vec::new()),
                replies: RefCell::new(replies),
            }
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.borrow().clone()
        }
        fn stdins(&self) -> Vec<Option<String>> {
            self.stdins.borrow().clone()
        }
    }

    impl OpRunner for &FakeOp {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).to_owned()).collect());
            self.stdins.borrow_mut().push(stdin.map(ToOwned::to_owned));
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

    /// The message `op` 2.40 really prints when an item is not there.
    ///
    /// Measured, not guessed. The previous code looked for "isn't an item"
    /// and "not found", neither of which appears in it, so a first sign-in
    /// on a new machine reported a failure instead of creating the item.
    const REAL_EDIT_MISS: &str = "[ERROR] 2026/10/22 17:37:43 unable to process line 1: \
                                  could not find item to edit";

    fn failed(stderr: &str) -> OpOutput {
        OpOutput {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_owned(),
        }
    }

    /// A successful `op item list` holding these titles.
    fn list_of(titles: &[&str]) -> OpOutput {
        let rows: Vec<String> = titles
            .iter()
            .map(|t| format!(r#"{{"id":"x","title":"{t}"}}"#))
            .collect();
        ok(&format!("[{}]", rows.join(",")))
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
        // get fails, and the listing says the item is not there.
        let fake = FakeOp::new(vec![failed(REAL_EDIT_MISS), list_of(&[])]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        assert!(
            store
                .load(&key())
                .expect("a miss is not an error")
                .is_none()
        );
    }

    #[test]
    fn a_vault_that_does_not_exist_is_an_error_not_an_empty_session() {
        // The operator's problem here is the vault, not the session, and
        // reporting "not signed in" would send them to fix the wrong one.
        let fake = FakeOp::new(vec![
            failed("x"),
            failed("[ERROR] \"v\" isn't a vault in this account."),
        ]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        match store.load(&key()) {
            Err(StoreError::Backend { operation, .. }) => {
                assert_eq!(operation, "list the vault");
            }
            other => panic!("expected a vault error, got {other:?}"),
        }
    }

    #[test]
    fn a_failure_that_is_not_a_miss_is_an_error() {
        // The item is there; the read failed for another reason. Calling
        // that "no session" would start a new login and strand the one in
        // the vault.
        let title = "ERPC CLI session alice@mac-001 (auth-api)";
        let fake = FakeOp::new(vec![
            failed("authorization prompt dismissed"),
            list_of(&[title]),
        ]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
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

    const ACCESS: &str = "access.token.secret";
    const REFRESH: &str = "refresh.token.secret";

    fn session() -> Credential {
        Credential {
            access_token: SecretString::from(ACCESS),
            refresh_token: SecretString::from(REFRESH),
            expires_at: 1_700_000_000,
        }
    }

    /// Fails if either token appears anywhere in any argument vector.
    fn assert_no_token_in_argv(fake: &FakeOp) {
        for call in fake.calls() {
            for arg in &call {
                assert!(
                    !arg.contains(ACCESS) && !arg.contains(REFRESH),
                    "a token reached op's argv, where a process listing can read it: {arg}"
                );
            }
        }
    }

    #[test]
    fn saving_edits_an_existing_item_in_one_call() {
        let fake = FakeOp::new(vec![
            list_of(&["ERPC CLI session alice@mac-001 (auth-api)"]),
            ok(""),
        ]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        store.save(&key(), &session()).expect("save");

        let calls = store_calls(&fake);
        assert_eq!(calls.len(), 2, "one listing, then one edit, and no create");
        assert_eq!(calls[0][1], "list");
        assert_eq!(calls[1][1], "edit");
        assert_no_token_in_argv(&fake);

        // Index 1: the listing comes first and carries no stdin.
        let body = fake.stdins()[1]
            .clone()
            .expect("the template goes in on stdin");
        assert!(body.contains(ACCESS), "the template carries the session");
        assert!(body.contains("CONCEALED"), "the token fields are concealed");
        assert!(body.contains("store_version"));
    }

    #[test]
    fn saving_creates_the_item_when_there_is_none() {
        // The listing is empty, so the item is created. This is the path
        // that was broken: `op item edit` on a missing item says "could
        // not find item to edit", which the old prose match missed, so
        // the first sign-in on a machine failed instead of creating.
        let fake = FakeOp::new(vec![list_of(&[]), ok("")]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        store.save(&key(), &session()).expect("save");

        let calls = store_calls(&fake);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1], "list");
        assert_eq!(calls[1][1], "create");
        assert!(
            calls[1].iter().any(|a| a == "-"),
            "create reads the template from stdin"
        );
        assert_no_token_in_argv(&fake);
        assert!(
            fake.stdins()[1]
                .as_deref()
                .is_some_and(|b| b.contains(REFRESH)),
            "the create call carries the session on stdin"
        );
    }

    #[test]
    fn neither_token_ever_reaches_a_process_listing() {
        // `op` warns about this itself: "Command arguments can be visible
        // to other processes on your machine. For sensitive values, use a
        // template instead." A refresh token in argv is outside the vault
        // boundary this store exists to keep it inside.
        for replies in [
            vec![
                list_of(&["ERPC CLI session alice@mac-001 (auth-api)"]),
                ok(""),
            ],
            vec![list_of(&[]), ok("")],
        ] {
            let fake = FakeOp::new(replies);
            let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
            store.save(&key(), &session()).expect("save");
            assert_no_token_in_argv(&fake);
        }
    }

    #[test]
    fn deleting_an_item_that_is_not_there_succeeds() {
        let fake = FakeOp::new(vec![list_of(&[])]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        store.delete(&key()).expect("deleting nothing is fine");
        assert_eq!(
            store_calls(&fake).len(),
            1,
            "nothing to delete means no delete call"
        );
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

    /// Runs `/usr/bin/env` through the real `OpCli` and returns what the
    /// child saw.
    ///
    /// The only way to test `env_clear`: the map this store builds is one
    /// thing, and what the child actually inherits is another. A test of
    /// the map stays green with `env_clear()` deleted, which is exactly
    /// how that control could be removed without anyone noticing.
    #[cfg(unix)]
    fn child_environment() -> Vec<String> {
        use std::collections::BTreeMap;

        let mut env = BTreeMap::new();
        env.insert("HOME".to_owned(), OsString::from("/home/alice"));
        env.insert("OP_CACHE".to_owned(), OsString::from("false"));
        let cli = OpCli::at("/usr/bin/env", env).expect("an absolute path");
        let out = cli.run(&[], None).expect("env runs");
        out.stdout.lines().map(ToOwned::to_owned).collect()
    }

    #[cfg(unix)]
    #[test]
    fn op_does_not_inherit_this_process_environment() {
        // This process has plenty of variables; the child must see only
        // the two it was given.
        assert!(
            std::env::vars_os().count() > 3,
            "the test is meaningless if the parent environment is empty"
        );
        let seen = child_environment();
        let names: Vec<&str> = seen
            .iter()
            .filter_map(|l| l.split('=').next())
            .filter(|n| !n.is_empty())
            .collect();
        assert!(names.contains(&"HOME"), "{names:?}");
        assert!(names.contains(&"OP_CACHE"), "{names:?}");
        assert_eq!(
            names.len(),
            2,
            "op must see only what it was given, saw {names:?}"
        );
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
