// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! How every command says it failed: one code, one exit status, one shape.
//!
//! A failure is a [`CliError`]: a [`Code`] a script can branch on, a
//! message a person can read, and, when there is one, a hint naming what to
//! do next. [`crate::finish`] is the only place they are printed, so every
//! command looks the same:
//!
//! ```text
//! error: nothing was changed: you said no
//! hint: run it again and answer yes, or pass --yes
//! ```
//!
//! and with `--json`, on standard output:
//!
//! ```json
//! {"error":{"code":"declined","exit":6,"message":"…","hint":"…"}}
//! ```
//!
//! The codes, their exit statuses and the rules for writing a message are
//! in `docs/errors.md`. A code, once published, keeps its name and status.

use core::fmt;

/// What kind of failure it was. Each has its own exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// The command could not do what was asked.
    Failed,
    /// The command line was not usable as given.
    Usage,
    /// A person has to answer and no one is at a terminal.
    NeedsTerminal,
    /// There is no usable ERPC session.
    NotSignedIn,
    /// A check ran and found problems; its report says which.
    ProblemsFound,
    /// A person was asked and said no; nothing was changed.
    Declined,
    /// ERPC, or another service, could not be reached.
    Network,
}

impl Code {
    /// Every code, in exit-status order.
    #[cfg(test)]
    pub const ALL: [Self; 7] = [
        Self::Failed,
        Self::Usage,
        Self::NeedsTerminal,
        Self::NotSignedIn,
        Self::ProblemsFound,
        Self::Declined,
        Self::Network,
    ];

    /// The name a script reads, in `--json` output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Usage => "usage",
            Self::NeedsTerminal => "needs_terminal",
            Self::NotSignedIn => "not_signed_in",
            Self::ProblemsFound => "problems_found",
            Self::Declined => "declined",
            Self::Network => "network",
        }
    }

    /// The exit status. 0 is success; a stop by Ctrl-C ends erpc by the
    /// signal itself, as a shell expects.
    #[must_use]
    pub const fn exit(self) -> u8 {
        match self {
            Self::Failed => 1,
            Self::Usage => 2,
            Self::NeedsTerminal => 3,
            Self::NotSignedIn => 4,
            Self::ProblemsFound => 5,
            Self::Declined => 6,
            Self::Network => 7,
        }
    }

    /// The mark a failure of this code has at a terminal: a plain failure
    /// is ❌; one that only needs something done first is gentler.
    #[must_use]
    pub const fn mark(self) -> &'static str {
        match self {
            Self::Failed => "❌",
            Self::Usage => "🤔",
            Self::NeedsTerminal => "⌨️ ",
            Self::NotSignedIn => "🔐",
            Self::ProblemsFound => "🩺",
            Self::Declined => "👋",
            Self::Network => "🌐",
        }
    }

    /// What to do next, when the failure itself says nothing more, and
    /// the words that show a message has said it already.
    const fn default_hint(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Usage => Some(("add --help to the command to see what it takes", "--help")),
            Self::NeedsTerminal => Some((
                "run it in a terminal, or pass --yes where it takes one",
                "--yes",
            )),
            Self::NotSignedIn => Some(("run `erpc login`", "erpc login")),
            Self::Network => Some((
                "check the connection and try again; `erpc doctor` checks this machine",
                "erpc doctor",
            )),
            Self::Failed | Self::ProblemsFound | Self::Declined => None,
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failure, as it is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    /// What kind it was.
    pub code: Code,
    /// What went wrong, and why when that is known. Empty when the command
    /// has printed its own report already.
    pub message: String,
    /// What to do next.
    pub hint: Option<String>,
    /// What a script needs besides the message: what the command did
    /// before it failed. Only in the JSON.
    pub details: Option<serde_json::Value>,
    /// The mark shown at a terminal in place of the code's: 🔑 for "set
    /// already", say, which needs a flag rather than a fix.
    pub mark: Option<&'static str>,
}

impl CliError {
    /// A failure of `code` saying `message`.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
            details: None,
            mark: None,
        }
    }

    /// Shows `mark` at a terminal in place of the code's.
    #[must_use]
    pub fn mark(mut self, mark: &'static str) -> Self {
        self.mark = Some(mark);
        self
    }

    /// The same, with what the command did before it failed, for scripts.
    #[must_use]
    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// The same, with a hint of what to do next.
    #[must_use]
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// The hint shown: the one given, else the code's own unless the
    /// message already names it.
    #[must_use]
    pub fn shown_hint(&self) -> Option<String> {
        self.hint.clone().or_else(|| {
            self.code
                .default_hint()
                // "run `erpc login`" is not said twice.
                .filter(|(_, said)| !self.message.contains(said))
                .map(|(hint, _)| hint.to_owned())
        })
    }

    /// The lines a person reads, on standard error.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = format!("error: {}", self.message);
        if let Some(hint) = self.shown_hint() {
            out.push_str("\nhint: ");
            out.push_str(&hint);
        }
        out
    }

    /// The lines a person reads at a terminal: the code's mark, the
    /// message, and the hint under it, without `error:` and `hint:`.
    #[must_use]
    pub fn drawn(&self) -> String {
        let mut lines = self.message.lines();
        let first = lines.next().unwrap_or_default();
        let mut out = format!(
            "{} {}",
            self.mark.unwrap_or(self.code.mark()),
            console::style(first).for_stderr().bold()
        );
        for line in lines {
            out.push_str("\n   ");
            out.push_str(line);
        }
        if let Some(hint) = self.shown_hint() {
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!("\n   💡 {}", console::style(hint).for_stderr().dim()),
            );
        }
        out
    }

    /// The object a script reads, on standard output.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        let mut error = serde_json::json!({
            "code": self.code.as_str(),
            "exit": self.code.exit(),
            "message": self.message,
        });
        if let Some(hint) = self.shown_hint() {
            error["hint"] = serde_json::json!(hint);
        }
        if let Some(details) = &self.details {
            error["details"] = details.clone();
        }
        serde_json::json!({ "error": error })
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// A message on its own is a plain failure: the `?` in code that says
/// why with a `String` keeps working.
impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self::new(Code::Failed, message)
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        Self::new(Code::Failed, message)
    }
}

/// `error`, with [`Code::Network`] when somewhere in its chain a request
/// never reached the server.
pub fn classify(error: &(dyn std::error::Error + 'static)) -> CliError {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(e) = cause {
        if matches!(
            e.downcast_ref::<erpc_auth::HttpError>(),
            Some(erpc_auth::HttpError::Transport { .. })
        ) {
            return CliError::new(Code::Network, error.to_string());
        }
        cause = e.source();
    }
    CliError::new(Code::Failed, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{CliError, Code};

    #[test]
    fn every_code_has_its_own_name_and_exit_status() {
        let mut names: Vec<&str> = Code::ALL.iter().map(|c| c.as_str()).collect();
        let mut exits: Vec<u8> = Code::ALL.iter().map(|c| c.exit()).collect();
        names.sort_unstable();
        names.dedup();
        exits.sort_unstable();
        exits.dedup();
        assert_eq!(names.len(), Code::ALL.len());
        assert_eq!(exits.len(), Code::ALL.len());
        assert!(!exits.contains(&0), "0 is success");
        // Published: scripts depend on these.
        assert_eq!(
            Code::ALL.map(Code::exit),
            [1, 2, 3, 4, 5, 6, 7],
            "exit statuses never move"
        );
    }

    #[test]
    fn details_are_for_scripts_only() {
        let e = CliError::new(Code::Failed, "partly done")
            .hint("run it again")
            .details(serde_json::json!({ "removal": "failed" }));
        assert_eq!(e.json()["error"]["details"]["removal"], "failed");
        assert!(!e.text().contains("removal"), "{}", e.text());
        assert!(
            CliError::new(Code::Failed, "x").json()["error"]
                .get("details")
                .is_none()
        );
    }

    #[test]
    fn the_documented_table_is_the_one_in_the_code() {
        let doc = include_str!("../../../docs/errors.md");
        for code in Code::ALL {
            let row = format!("| `{}` | {} |", code.as_str(), code.exit());
            assert!(doc.contains(&row), "docs/errors.md lacks {row}");
        }
    }

    #[test]
    fn a_failure_reads_the_same_way_as_text_and_as_json() {
        let e = CliError::new(Code::Declined, "nothing was changed").hint("pass --yes");
        assert_eq!(e.text(), "error: nothing was changed\nhint: pass --yes");
        assert_eq!(
            e.json(),
            serde_json::json!({ "error": {
                "code": "declined", "exit": 6, "message": "nothing was changed", "hint": "pass --yes"
            }})
        );
    }

    #[test]
    fn a_default_hint_is_not_said_twice() {
        let e = CliError::new(Code::NotSignedIn, "the session expired");
        assert_eq!(e.shown_hint().as_deref(), Some("run `erpc login`"));
        let e = CliError::new(Code::NotSignedIn, "the session expired; run `erpc login`");
        assert_eq!(e.shown_hint(), None);
        assert_eq!(CliError::from("x".to_owned()).shown_hint(), None);
        let e = CliError::new(Code::Usage, "`erpc v --help` lists the verbs");
        assert_eq!(e.shown_hint(), None);
    }

    #[test]
    fn a_request_that_never_arrived_is_a_network_failure() {
        let unreachable = erpc_auth::HttpError::Transport {
            host: "the issuer",
            reason: "timed out".to_owned(),
        };
        assert_eq!(super::classify(&unreachable).code, Code::Network);
        let refused = erpc_auth::HttpError::Status {
            host: "the issuer",
            status: 500,
        };
        assert_eq!(super::classify(&refused).code, Code::Failed);
    }
}
