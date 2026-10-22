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

/// Where `op` is looked for.
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
///
/// Both streams can hold a token -- `item get` prints the item, and a
/// failed write may echo the template -- so `Debug` reports their lengths
/// and not their contents.
#[derive(Clone)]
pub struct OpOutput {
    /// Whether `op` exited successfully.
    pub success: bool,
    /// Standard output.
    pub stdout: String,
    /// Standard error, as `op` printed it.
    ///
    /// Not shortened or redacted here: the store does both when it turns
    /// this into an error, after it has replaced the exact token values it
    /// knows. Cutting it first could leave half a token, which neither the
    /// exact match nor the shape check recognises.
    pub stderr: String,
}

impl core::fmt::Debug for OpOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpOutput")
            .field("success", &self.success)
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .finish()
    }
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
///
/// `Debug` names the variables it passes and not their values: in service
/// account mode one of them is the service account token.
#[derive(Clone)]
pub struct OpCli {
    path: PathBuf,
    env: BTreeMap<String, OsString>,
}

impl core::fmt::Debug for OpCli {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpCli")
            .field("path", &self.path)
            .field("env", &self.env.keys().collect::<Vec<_>>())
            .finish()
    }
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
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Keeps the first line of `op`'s diagnostics, redacted and shortened.
///
/// `op` is fed a template containing both tokens on stdin. If it ever
/// echoes part of that back in a parse error, the message travels into a
/// `StoreError` and from there to the operator's terminal and logs. Any
/// run that looks like a JWT is replaced before that can happen.
fn first_line(text: &str) -> String {
    let redacted = redact_tokens(text);
    let line = redacted.lines().next().unwrap_or_default().trim();
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

/// Replaces anything shaped like a JWT with a marker.
///
/// Deliberately crude and deliberately wide: three dot-separated runs of
/// base64url with a long first run. A false positive costs a less helpful
/// error message; a false negative puts a session token in a log.
///
/// What counts as that shape is [`crate::credential::check_token_shape`]'s
/// answer, not a second opinion. Two pieces of code holding different
/// views of one shape, with the difference in the leaking direction, is
/// how a token got through before: this required three non-empty parts
/// while the shape check accepts an empty signature, so a token erpc was
/// willing to store was one its own redaction did not recognise.
///
/// It is not the whole of that answer, and is not claimed to be: the
/// first run has to be at least eight characters or ordinary prose with
/// two dots in it would be eaten, while the shape check has no such
/// floor. Real tokens clear it -- a JWT header is twenty characters
/// before it is anything -- but a short-headed one the shape check
/// accepts would pass through here. That gap is why the save path matches
/// the two values it holds exactly, in [`without_the_tokens`], rather
/// than relying on this.
fn redact_tokens(text: &str) -> String {
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=';
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let token_len = rest
            .split(|c: char| !(is_b64(c) || c == '.'))
            .next()
            .map_or(0, str::len);
        let candidate = &rest[..token_len];
        // A token in the last position of a sentence drags the full stop
        // into the run. Counting that as a fourth, empty part made the
        // run stop looking like a JWT and printed the whole of it --
        // which is the commonest position of all for a token to be in.
        let core = candidate.trim_end_matches('.');
        let parts: Vec<&str> = core.split('.').collect();
        // Three parts, or two and a separator: the signature is the only
        // part `check_token_shape` lets be empty, so it is the only one
        // allowed to be missing here.
        let unsecured = parts.len() == 2 && core.len() < candidate.len();
        let looks_like_a_jwt = (parts.len() == 3 || unsecured)
            && parts[0].len() >= 8
            && parts.iter().all(|p| !p.is_empty() && p.chars().all(is_b64));
        if looks_like_a_jwt {
            out.push_str("<redacted>");
            // The empty signature's separator belongs to the token; any
            // further dots are the sentence's and stay in the message.
            rest = &rest[core.len() + usize::from(unsecured)..];
        } else {
            let step = rest.chars().next().map_or(1, char::len_utf8);
            out.push_str(&rest[..step]);
            rest = &rest[step..];
        }
    }
    out
}

/// Replaces the exact token values with a marker.
///
/// [`redact_tokens`] guesses at a shape because it runs where the values
/// are not known. Here they are: the only reason `op` can echo a token
/// back at all is that this process just handed it one on stdin, so the
/// values can be matched exactly and the shape left as the insurance it
/// is. A token `op` mangles, wraps or quotes in a way the heuristic does
/// not recognise is still caught, as long as the value itself survives in
/// the message.
fn without_the_tokens(reason: String, cred: &Credential) -> String {
    let mut out = reason;
    for value in [
        cred.access_token.expose_secret(),
        cred.refresh_token.expose_secret(),
    ] {
        if !value.is_empty() {
            out = out.replace(value, "<redacted>");
        }
    }
    out
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
            return Err(self.backend("list the vault", &out.stderr));
        }
        let items: Vec<OpListEntry> = serde_json::from_str(&out.stdout)
            .map_err(|e| self.unparsable_output("the vault listing", &e))?;
        Ok(items.iter().any(|i| i.title == title))
    }

    /// Output from `op` that does not parse.
    ///
    /// A failure of the tool, not of the record: `op` changing its output
    /// format says nothing about the session in the vault, which may well
    /// be live. So it is a backend error, which stops a sign-in rather
    /// than letting it write over that session unrevoked, as a record
    /// that does not parse would. Reported by position, as everywhere.
    /// Output that parses but lacks the version field is treated the same
    /// way, in `load`; one that parses with every field present is a
    /// record, and judged as one.
    fn unparsable_output(&self, what: &str, error: &serde_json::Error) -> StoreError {
        StoreError::Backend {
            kind: self.mode.kind(),
            operation: "read op's output",
            reason: super::unparsable_json(what, error).to_string(),
        }
    }

    /// Every one of `op`'s diagnostics becomes an error here, and only
    /// here, so this is where it is redacted by shape and cut to a line.
    /// Callers that know the token values replace them first.
    fn backend(&self, operation: &'static str, reason: &str) -> StoreError {
        StoreError::Backend {
            kind: self.mode.kind(),
            operation,
            reason: first_line(reason),
        }
    }
}

/// One row of `op item list --format json`.
#[derive(Deserialize)]
struct OpListEntry {
    #[serde(default)]
    title: String,
}

/// The parts of `op item get --format json` this store reads.
#[derive(Deserialize)]
struct OpItem {
    #[serde(default)]
    fields: Vec<OpField>,
}

/// One field of an item.
#[derive(Deserialize)]
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
                return Err(self.backend("read the item", &out.stderr));
            }
            return Ok(None);
        }

        let item: OpItem = serde_json::from_str(&out.stdout)
            .map_err(|e| self.unparsable_output("the 1Password item", &e))?;

        // No version field at all is `op` speaking a shape this build does
        // not read, not a record from another build: every item erpc has
        // written has one. Everything in the parsed types defaults, so a
        // renamed `fields` or `label` still parses -- into an item with no
        // fields -- and calling that an unreadable record would let a
        // sign-in write over a session that may be live, unrevoked.
        let Some(raw_version) = item.field(field::STORE_VERSION) else {
            return Err(self.backend(
                "read op's output",
                "the item has no store_version field, so op's output is not in a shape this \
                 build reads",
            ));
        };
        // And a version that is empty or not a number is the same thing: a
        // renamed `value` leaves the field found by its label with nothing
        // in it. Only a well-formed number other than this build's is a
        // record from another build.
        let Ok(version) = raw_version.parse::<u32>() else {
            return Err(self.backend(
                "read op's output",
                "the item's store_version is not a number, so op's output is not in a shape \
                 this build reads",
            ));
        };
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
        super::non_empty(access, refresh)?;
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
                Err(self.backend("update the item", &without_the_tokens(edit.stderr, cred)))
            };
        }

        let create = self.runner.run(
            &["item", "create", "-", "--vault", &self.vault],
            Some(&template),
        )?;
        if create.success {
            Ok(())
        } else {
            Err(self.backend("create the item", &without_the_tokens(create.stderr, cred)))
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
            Err(self.backend("remove the item", &out.stderr))
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

    use super::{Mode, OnePassword, OpCli, OpOutput, OpRunner, first_line, redact_tokens};
    use crate::credential::{Audience, CredKey, Credential, check_token_shape};
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
    fn a_token_echoed_by_op_never_reaches_an_error_message() {
        // `op` is handed both tokens on stdin. If it quotes any of the
        // template back in a parse error, that message becomes a
        // StoreError and reaches the terminal and the logs.
        // Assembled rather than written out. A test for redacting
        // token-shaped strings has to contain one, and a literal would be
        // a finding for gitleaks -- correctly, since it cannot tell a
        // fixture from the real thing. Same accommodation as the URL
        // fixtures, for the same reason.
        let token = [
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiJhbGljZSJ9",
            "c2lnbmF0dXJl",
        ]
        .join(".");
        let noisy = format!("[ERROR] unable to process line 1: near \"{token}\"");
        let cleaned = first_line(&noisy);
        assert!(!cleaned.contains(&token), "{cleaned}");
        assert!(cleaned.contains("<redacted>"), "{cleaned}");
        assert!(
            cleaned.contains("unable to process"),
            "the message survives"
        );
    }

    /// A JWT-shaped value, assembled rather than written out.
    ///
    /// Same accommodation as the fixture above and the URL fixtures: a
    /// test for redacting token-shaped strings has to contain one, and a
    /// literal would be a finding for `gitleaks`, correctly, since it
    /// cannot tell a fixture from the real thing.
    fn token_shaped(signature: &str) -> String {
        let mut parts = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJhbGljZSJ9"].join(".");
        parts.push('.');
        parts.push_str(signature);
        parts
    }

    #[test]
    fn a_token_in_the_last_position_of_a_sentence_is_redacted() {
        // The commonest position of all, and the one that leaked: the full
        // stop joined the run, made a fourth and empty part, and the whole
        // run was printed as it stood.
        let token = token_shaped("c2lnbmF0dXJl");
        let noisy = format!("[ERROR] unable to process line 1: near {token}.");
        let cleaned = first_line(&noisy);
        assert!(!cleaned.contains(&token), "{cleaned}");
        assert!(cleaned.contains("<redacted>"), "{cleaned}");
        assert!(
            cleaned.ends_with('.'),
            "the sentence keeps its stop: {cleaned}"
        );
    }

    #[test]
    fn a_token_with_an_empty_signature_is_redacted_as_the_shape_check_accepts_it() {
        // An unsecured JWT is a token erpc stores, so it is one the
        // redaction has to recognise. Where the two differed -- the shape
        // check accepts an empty signature, the redaction required three
        // non-empty parts -- erpc would store a token its own redaction
        // printed in the clear.
        for signature in ["c2lnbmF0dXJl", ""] {
            let token = token_shaped(signature);
            assert!(
                check_token_shape(&token).is_ok(),
                "erpc would store this: {token}"
            );
            let cleaned = redact_tokens(&token);
            assert!(!cleaned.contains(&token), "and prints it: {cleaned}");
            assert_eq!(cleaned, "<redacted>", "{cleaned}");
        }
    }

    #[test]
    fn a_token_op_echoes_back_is_matched_by_value_not_only_by_shape() {
        // The heuristic is insurance. The caller knows both values -- it
        // handed them over on stdin a moment ago -- and these two are not
        // of a shape the heuristic recognises, so only an exact match
        // keeps them out of the message.
        assert_eq!(
            redact_tokens(ACCESS),
            ACCESS,
            "the fixture has to be one the shape check misses, or this proves nothing"
        );
        let fake = FakeOp::new(vec![
            list_of(&["ERPC CLI session alice@mac-001 (auth-api)"]),
            failed(&format!(
                "[ERROR] unable to process line 1: near \"{ACCESS}\""
            )),
        ]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        let err = store
            .save(&key(), &session())
            .expect_err("op refused the edit");
        let rendered = err.to_string();
        assert!(!rendered.contains(ACCESS), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("unable to process"),
            "the message survives: {rendered}"
        );
    }

    #[test]
    fn a_token_op_echoes_back_from_a_create_is_matched_too() {
        // The create path carries the same template as the edit path.
        let fake = FakeOp::new(vec![
            list_of(&[]),
            failed(&format!("[ERROR] could not create item: {REFRESH}")),
        ]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        let rendered = store
            .save(&key(), &session())
            .expect_err("op refused the create")
            .to_string();
        assert!(!rendered.contains(REFRESH), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn a_token_is_replaced_whole_before_the_message_is_cut() {
        // Cutting to 200 bytes first left the front half of a token that
        // straddled the cut, which the exact match no longer recognised
        // and the shape check never would: the fixture is one it misses.
        // Placed so the value starts five bytes before the cut. The
        // padding is not base64url: padding that is joins the token into
        // one long run, which the shape check then catches by accident and
        // the test proves nothing -- which is what it did at first.
        let noisy = format!("{}{ACCESS} and the rest of the line", "~".repeat(195));
        assert_eq!(redact_tokens(&noisy), noisy, "the shape check must miss it");
        let fake = FakeOp::new(vec![
            list_of(&["ERPC CLI session alice@mac-001 (auth-api)"]),
            failed(&noisy),
        ]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        let rendered = store
            .save(&key(), &session())
            .expect_err("op refused the edit")
            .to_string();
        assert!(!rendered.contains(&ACCESS[..5]), "{rendered}");
        assert!(rendered.contains("<reda"), "{rendered}");
    }

    /// Saves through the real [`OpCli`], with `op` replaced by a script
    /// that lists the item and then fails the edit printing `stderr`.
    ///
    /// The `FakeOp` tests cannot see where the runner cuts the message,
    /// because they never go through [`OpCli::run`]; that is where a review
    /// found the previous cut, and a `FakeOp` test of it stayed green with
    /// the old code restored.
    #[cfg(unix)]
    fn save_through_a_scripted_op(stderr: &str) -> String {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let script = dir.path().join("op");
        let title = "ERPC CLI session alice@mac-001 (auth-api)";
        let body = format!(
            "#!/bin/sh\n/bin/cat >/dev/null\nif [ \"$2\" = list ]; then\n  \
             printf '%s' '[{{\"id\":\"x\",\"title\":\"{title}\"}}]'\n  exit 0\nfi\n\
             printf '%s\\n' '{stderr}' >&2\nexit 1\n"
        );
        std::fs::write(&script, body).expect("write the script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("make it executable");
        let store = OnePassword::new(
            OpCli::at(&script, BTreeMap::new()).expect("an absolute path"),
            Mode::Desktop,
            VAULT,
            "mac-001",
        );
        // A script written moments ago can be briefly "busy" to exec on
        // Linux while another test thread forks; that is a spawn failure,
        // not a result, so it is retried.
        for _ in 0..5 {
            match store.save(&key(), &session()) {
                Err(StoreError::Unavailable { .. }) => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return e.to_string(),
                Ok(()) => panic!("the script fails the edit"),
            }
        }
        panic!("the script could not be started");
    }

    #[cfg(unix)]
    #[test]
    fn a_token_straddling_the_cut_is_replaced_whole_through_the_real_runner() {
        let noisy = format!("{}{ACCESS} and the rest of the line", "~".repeat(195));
        assert_eq!(redact_tokens(&noisy), noisy, "the shape check must miss it");
        let rendered = save_through_a_scripted_op(&noisy);
        assert!(rendered.contains("update the item"), "{rendered}");
        assert!(!rendered.contains(&ACCESS[..5]), "{rendered}");
    }

    #[test]
    fn a_malformed_item_is_reported_without_quoting_it() {
        // serde_json quotes a value it could not convert; in an item that
        // value is a token.
        let token = crate::lock::tests::token_fixture();
        let fake = FakeOp::new(vec![ok(&format!(r#"{{"fields":"{token}"}}"#))]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        let err = store.load(&key()).expect_err("the item is malformed");
        // The tool's output, not the record: a sign-in must stop here, not
        // write over a session that may be live.
        assert!(matches!(err, StoreError::Backend { .. }), "{err:?}");
        let shown = err.to_string();
        assert!(!shown.contains("U0VDUkVUUEFZTE9BRA"), "{shown}");
    }

    #[test]
    fn a_malformed_listing_is_reported_without_quoting_it() {
        let token = crate::lock::tests::token_fixture();
        let fake = FakeOp::new(vec![
            failed("x"),
            // A string where a row belongs, which serde_json quotes.
            ok(&format!(r#"["{token}"]"#)),
        ]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        let err = store.load(&key()).expect_err("the listing is malformed");
        // This runs when `item get` has failed, which is when a live item
        // may be there; a corrupt-record error would let a sign-in write
        // over it.
        assert!(matches!(err, StoreError::Backend { .. }), "{err:?}");
        let shown = err.to_string();
        assert!(!shown.contains("U0VDUkVUUEFZTE9BRA"), "{shown}");
    }

    #[test]
    fn an_item_whose_values_moved_stops_a_sign_in_too() {
        // `value` renamed: every field is still found by its label, and
        // every value is empty.
        let json = r#"{"fields":[
            {"id":"a","label":"access_token","val":"x"},
            {"id":"b","label":"refresh_token","val":"y"},
            {"id":"c","label":"expires_at","val":"1700000000"},
            {"id":"d","label":"store_version","val":"1"}
        ]}"#;
        let fake = FakeOp::new(vec![ok(json)]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        let err = store
            .load(&key())
            .expect_err("not an item this build reads");
        assert!(matches!(err, StoreError::Backend { .. }), "{err:?}");
    }

    #[test]
    fn an_item_with_an_empty_token_is_not_a_session() {
        let json = r#"{"fields":[
            {"id":"a","label":"access_token","value":""},
            {"id":"b","label":"refresh_token","value":"d.e.f"},
            {"id":"c","label":"expires_at","value":"1700000000"},
            {"id":"d","label":"store_version","value":"1"}
        ]}"#;
        let fake = FakeOp::new(vec![ok(json)]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        assert!(matches!(store.load(&key()), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn a_version_from_another_build_is_still_a_record() {
        let json = r#"{"fields":[{"id":"d","label":"store_version","value":"9"}]}"#;
        let fake = FakeOp::new(vec![ok(json)]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        assert!(matches!(
            store.load(&key()),
            Err(StoreError::UnknownVersion { found: 9, .. })
        ));
    }

    #[test]
    fn an_item_in_a_shape_this_build_does_not_read_stops_a_sign_in() {
        // Parses -- every field defaults -- but carries no version, which
        // every item erpc writes has. That is `op` changing its format,
        // not a record from another build.
        let fake = FakeOp::new(vec![ok(r#"{"sections":[],"fieldsV2":[]}"#)]);
        let store = OnePassword::new(&fake, Mode::Desktop, VAULT, "mac-001");
        let err = store
            .load(&key())
            .expect_err("not an item this build reads");
        assert!(matches!(err, StoreError::Backend { .. }), "{err:?}");
    }

    #[test]
    fn the_runner_does_not_print_the_values_it_passes() {
        let token = crate::lock::tests::token_fixture();
        let cli = OpCli::from_env(Mode::ServiceAccount, |name| {
            (name == "OP_SERVICE_ACCOUNT_TOKEN").then(|| OsString::from(token.clone()))
        });
        // Without `op` installed there is no runner to print; the property
        // is then checked on one built directly.
        let cli = cli.unwrap_or_else(|_| {
            let mut env = BTreeMap::new();
            env.insert(
                "OP_SERVICE_ACCOUNT_TOKEN".to_owned(),
                OsString::from(token.clone()),
            );
            OpCli::at(std::env::temp_dir().join("op"), env).expect("an absolute path")
        });
        let shown = format!("{cli:?}");
        assert!(!shown.contains("U0VDUkVUUEFZTE9BRA"), "{shown}");
        assert!(shown.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{shown}");
    }

    #[test]
    fn op_output_does_not_print_what_op_printed() {
        // `item get` prints the item, tokens included, and a failed write
        // may echo the template.
        let out = OpOutput {
            success: false,
            stdout: ACCESS.to_owned(),
            stderr: REFRESH.to_owned(),
        };
        let shown = format!("{out:?}");
        assert!(
            !shown.contains(ACCESS) && !shown.contains(REFRESH),
            "{shown}"
        );
        assert!(shown.contains("stderr_len"), "{shown}");
    }

    #[test]
    fn ordinary_diagnostics_are_left_readable() {
        // The redaction is wide on purpose, but it must not eat the
        // messages an operator needs.
        for message in [
            "[ERROR] \"v\" isn't a vault in this account.",
            "[ERROR] unable to process line 1: could not find item to edit",
            "authorization prompt dismissed",
        ] {
            assert_eq!(first_line(message), message, "{message}");
        }
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
