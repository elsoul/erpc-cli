// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc doctor`: what this machine is doing with your session.
//!
//! The requirement is that `erpc` leaves no secret on this machine, with
//! two stated exceptions. A rule with exceptions needs something that
//! finds them, and that is what this command is for: the file store, a
//! session parked after a rotation the store refused, and the temporary
//! file either can leave if a write is interrupted. Several places in the
//! code promise that this command will report those, so it has to exist
//! and it has to actually look.

use std::path::{Path, PathBuf};

use erpc_auth::credential::Audience;
use erpc_auth::session::parked_path;
use erpc_auth::store::select::Selection;

/// How long a parked session may sit before it stops being a note and
/// becomes a finding.
pub const PARKED_STALE_AFTER: std::time::Duration = std::time::Duration::from_hours(24);

/// How serious one observation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Nothing to do.
    Ok,
    /// Worth knowing about.
    Note,
    /// Should be dealt with.
    Warn,
}

/// One thing `doctor` found.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    /// How serious it is.
    pub level: Level,
    /// What was looked at.
    pub subject: String,
    /// What was found.
    pub detail: String,
}

impl Finding {
    /// A finding that needs nothing done.
    #[must_use]
    pub fn ok(subject: &str, detail: String) -> Self {
        Self {
            level: Level::Ok,
            subject: subject.to_owned(),
            detail,
        }
    }

    /// A finding the operator should act on.
    #[must_use]
    pub fn warn(subject: &str, detail: String) -> Self {
        Self {
            level: Level::Warn,
            subject: subject.to_owned(),
            detail,
        }
    }
}

/// A secret left on this machine, and how long it has been there.
#[derive(Debug, Clone)]
pub struct OnDisk {
    /// Where it is.
    pub path: PathBuf,
    /// How long since it was last written, when that can be read.
    pub age: Option<std::time::Duration>,
}

/// Finds the files that hold a secret on this machine.
///
/// Both exceptions, in one place: the file store's own file, and a parked
/// session for any audience. Takes the paths rather than computing them so
/// a test can point it at a directory of its own.
#[must_use]
pub fn secrets_on_disk(state_dir: &Path) -> Vec<OnDisk> {
    let mut found = Vec::new();
    let mut consider = |path: PathBuf| {
        let Ok(meta) = std::fs::metadata(&path) else {
            return;
        };
        if !meta.is_file() {
            return;
        }
        let age = meta
            .modified()
            .ok()
            .and_then(|t| std::time::SystemTime::now().duration_since(t).ok());
        found.push(OnDisk { path, age });
    };
    consider(state_dir.join("credentials.toml"));
    for audience in Audience::all() {
        consider(parked_path(state_dir, *audience));
    }
    // Both are written to a temporary file beside them and renamed into
    // place. A crash between the two leaves the temporary file, holding
    // the same secret, under a name nothing else looks for.
    if let Ok(entries) = std::fs::read_dir(state_dir) {
        let mut temporary: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| is_interrupted_write(path))
            .collect();
        temporary.sort();
        for path in temporary {
            consider(path);
        }
    }
    found
}

/// Whether `path` is the temporary file of a secret write that did not
/// finish: `.credentials-*.tmp` from the file store, `.pending-*.tmp` from
/// a parked session.
fn is_interrupted_write(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "tmp")
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(".credentials-") || n.starts_with(".pending-"))
}

/// Turns the store choice and what is on disk into findings.
#[must_use]
pub fn findings(selection: Selection, on_disk: &[OnDisk]) -> Vec<Finding> {
    let mut out = vec![Finding {
        level: if selection.kind.writes_secrets_to_disk() {
            Level::Warn
        } else {
            Level::Ok
        },
        subject: "credential store".to_owned(),
        detail: format!("{} — {}", selection.kind, selection.reason),
    }];

    if on_disk.is_empty() {
        out.push(Finding {
            level: Level::Ok,
            subject: "secrets on this machine".to_owned(),
            detail: "none".to_owned(),
        });
        return out;
    }

    for item in on_disk {
        let parked = item
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("pending-credentials."));
        let stale = item.age.is_some_and(|age| age > PARKED_STALE_AFTER);
        let level = if (parked && stale) || is_interrupted_write(&item.path) {
            Level::Warn
        } else {
            Level::Note
        };
        let detail = if is_interrupted_write(&item.path) {
            format!(
                "{} — left by a write that did not finish, and it may hold a session in \
                 cleartext. erpc does not use it; delete it.",
                item.path.display()
            )
        } else if parked {
            if stale {
                // Either the store has refused it ever since, and it is a
                // live token in cleartext, or a sign-in or sign-out revoked
                // it and could not unlink it. This command cannot tell
                // which without the store, so it says both, and the one
                // instruction that is right for both.
                format!(
                    "{} — a session parked more than a day ago. It may be a live refresh token \
                     in cleartext. Run `erpc login`, which tries to revoke it, says whether it \
                     could, and replaces the session; if the file is still here afterwards, \
                     erpc could not delete it, so check the permissions on its directory and \
                     delete it yourself.",
                    item.path.display()
                )
            } else {
                format!(
                    "{} — a session parked when a store write failed. If the store still holds \
                     the session it replaced, the next `erpc whoami` files it away and deletes \
                     it. If you have signed in since, erpc ignores it, and `erpc login` said \
                     then whether its token could be revoked; it is here only because it could \
                     not be deleted, so check the permissions on its directory and delete it \
                     yourself.",
                    item.path.display()
                )
            }
        } else {
            format!(
                "{} — the file store, which is the one case erpc keeps a secret here",
                item.path.display()
            )
        };
        out.push(Finding {
            level,
            subject: "secret on this machine".to_owned(),
            detail,
        });
    }
    out
}

/// The exit status a set of findings deserves.
#[must_use]
pub fn worst(findings: &[Finding]) -> Level {
    if findings.iter().any(|f| f.level == Level::Warn) {
        Level::Warn
    } else if findings.iter().any(|f| f.level == Level::Note) {
        Level::Note
    } else {
        Level::Ok
    }
}

/// The marker shown beside each finding.
#[must_use]
pub const fn marker(level: Level) -> &'static str {
    match level {
        Level::Ok => "ok  ",
        Level::Note => "note",
        Level::Warn => "warn",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Level, OnDisk, PARKED_STALE_AFTER, findings, secrets_on_disk, worst};
    use erpc_auth::store::StoreKind;
    use erpc_auth::store::select::{Reason, Selection};

    fn selection(kind: StoreKind) -> Selection {
        Selection {
            kind,
            reason: Reason::Requested,
        }
    }

    #[test]
    fn a_clean_machine_has_nothing_to_report() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let on_disk = secrets_on_disk(dir.path());
        assert!(on_disk.is_empty());
        let f = findings(selection(StoreKind::OsKeychain), &on_disk);
        assert_eq!(worst(&f), Level::Ok);
    }

    #[test]
    fn the_file_store_is_reported_because_it_is_the_stated_exception() {
        let f = findings(selection(StoreKind::File), &[]);
        assert_eq!(worst(&f), Level::Warn);
        assert!(f[0].detail.contains("file"));
    }

    #[test]
    fn a_credentials_file_is_found() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(dir.path().join("credentials.toml"), "x").expect("write");
        let on_disk = secrets_on_disk(dir.path());
        assert_eq!(on_disk.len(), 1);
        assert!(
            findings(selection(StoreKind::File), &on_disk)
                .iter()
                .any(|f| f.detail.contains("credentials.toml"))
        );
    }

    #[test]
    fn a_parked_session_is_found_for_each_audience() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(dir.path().join("pending-credentials.auth-api"), "x").expect("write");
        std::fs::write(dir.path().join("pending-credentials.mcp-user-api"), "x").expect("write");
        assert_eq!(secrets_on_disk(dir.path()).len(), 2);
    }

    #[test]
    fn a_fresh_parked_session_is_a_note_and_an_old_one_is_a_warning() {
        let fresh = OnDisk {
            path: "/s/pending-credentials.auth-api".into(),
            age: Some(Duration::from_secs(60)),
        };
        let old = OnDisk {
            path: "/s/pending-credentials.auth-api".into(),
            age: Some(PARKED_STALE_AFTER + Duration::from_secs(1)),
        };
        assert_eq!(
            worst(&findings(selection(StoreKind::OsKeychain), &[fresh])),
            Level::Note
        );
        assert_eq!(
            worst(&findings(selection(StoreKind::OsKeychain), &[old])),
            Level::Warn
        );
    }

    #[test]
    fn a_fresh_parked_session_says_what_will_clear_it() {
        let fresh = OnDisk {
            path: "/s/pending-credentials.auth-api".into(),
            age: Some(Duration::from_secs(60)),
        };
        let f = findings(selection(StoreKind::OsKeychain), &[fresh]);
        let detail = &f[1].detail;
        // The message tells the operator a command will clean this up, so
        // that command has to be the one that really does it.
        assert!(detail.contains("whoami"), "{detail}");
    }

    #[test]
    fn a_write_that_did_not_finish_is_found_and_warned_about() {
        // The temporary file a crash leaves holds the same secret
        // as the file it was going to replace, and nothing reported it.
        let dir = tempfile::tempdir().expect("a temporary directory");
        // Assembled: `credentials-` followed by a random-looking suffix is
        // the shape gitleaks reads as a key assignment, correctly, since it
        // cannot tell a temporary file's name from a credential. Same
        // accommodation as the token fixtures, for the same reason.
        for prefix in [".credentials-", ".pending-"] {
            let name = format!("{prefix}{}.tmp", "a1b2");
            std::fs::write(dir.path().join(name), "x").expect("write");
        }
        // Not ours, so not reported.
        std::fs::write(dir.path().join(".other-e5f6.tmp"), "x").expect("write");
        let found = secrets_on_disk(dir.path());
        assert_eq!(
            found.len(),
            2,
            "{:?}",
            found.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        assert_eq!(
            worst(&findings(selection(StoreKind::OsKeychain), &found)),
            Level::Warn
        );
    }

    #[test]
    fn a_directory_in_the_way_is_not_reported_as_a_secret() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir(dir.path().join("credentials.toml")).expect("mkdir");
        assert!(secrets_on_disk(dir.path()).is_empty());
    }
}
