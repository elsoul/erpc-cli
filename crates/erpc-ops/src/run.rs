// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A run on a node: send the bundle, start it, follow it to its result.
//!
//! The node runs the play itself, under a transient systemd unit, so a
//! dropped connection does not stop it; following again reattaches to it.

use erpc_ssh::{
    RESULT_MARKER, RemoteCommand, RemotePath, RunId, RunPrepare, RunStart, Session, SshError,
    Stream,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::bundle::Built;

/// The runner the node executes, sent with every run.
pub const NODE_RUN_SH: &str = include_str!("../node/node-run.sh");
/// Isolated preparation and result publication, with no user-site imports.
pub const RUN_FILES: &str = include_str!("../node/run-files.py");

/// What went wrong with a run.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// SSH failed.
    #[error(transparent)]
    Ssh(#[from] SshError),
    /// What arrived on the node is not what was sent.
    #[error(
        "the bundle arrived damaged on the node (expected {expected}, got {got}); nothing was run"
    )]
    Damaged {
        /// The digest erpc computed.
        expected: String,
        /// The digest the node computed.
        got: String,
    },
    /// The run ended without a readable result.
    #[error("the run ended without a result; see its log on the node in {0}")]
    NoResult(String),
    /// A value could not be made into a command.
    #[error("{0}")]
    Invalid(String),
}

/// How a run ended, from the node's `result.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RunResult {
    /// `ok` or `failed`.
    pub status: String,
    /// `ansible-playbook`'s exit code, or the runner's own.
    pub exit_code: i32,
    /// When the runner started, UTC.
    pub started_at: String,
    /// When it finished, UTC.
    pub finished_at: String,
    /// The play.
    pub play: String,
    /// Why it failed, when the runner knows.
    #[serde(default)]
    pub message: String,
}

impl RunResult {
    /// Whether the play succeeded.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.status == "ok" && self.exit_code == 0
    }
}

/// A new run id: `r-`, the UTC time to the second, and six random hex digits.
///
/// # Errors
///
/// Returns [`RunError::Invalid`] only if the clock gives a date with more than
/// four digits of year.
pub fn new_run_id() -> Result<RunId, RunError> {
    use std::hash::{BuildHasher as _, Hasher as _};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(now.as_nanos());
    let (y, mo, d, h, mi, s) = civil(now.as_secs());
    let id = format!(
        "r-{y:04}{mo:02}{d:02}t{h:02}{mi:02}{s:02}-{:06x}",
        hasher.finish() & 0xff_ffff
    );
    RunId::new(&id).map_err(|e| RunError::Invalid(e.to_string()))
}

/// Now, UTC, as RFC 3339 to the second: `2026-10-23T11:17:43Z`.
#[must_use]
pub fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Seconds since the epoch as a UTC date and time.
fn civil(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Howard Hinnant's days-to-civil, for the proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day, rem / 3600, rem % 3600 / 60, rem % 60)
}

fn path(text: &str) -> Result<RemotePath, RunError> {
    RemotePath::new(text).map_err(|e| RunError::Invalid(e.to_string()))
}

/// Sends `bundle` and the runner to a new run directory, checks the bundle
/// arrived whole, and starts `play` from it.
///
/// # Errors
///
/// Returns [`RunError`] when a step fails; nothing is started unless the
/// node's digest of the bundle matches.
pub fn start(session: &Session, bundle: &Built, play: &str) -> Result<RunId, RunError> {
    let run = new_run_id()?;
    let dir = run.dir();
    session.run(
        &RemoteCommand::WriteFile(path(&format!("{dir}/node-run.sh"))?),
        Some(NODE_RUN_SH.as_bytes()),
    )?;
    session.run(
        &RemoteCommand::WriteFile(path(&format!("{dir}/run-files.py"))?),
        Some(RUN_FILES.as_bytes()),
    )?;
    let archive = path(&format!("{dir}/bundle.tar.gz"))?;
    session.run(
        &RemoteCommand::WriteFile(archive.clone()),
        Some(&bundle.bytes),
    )?;
    let out = session.run(&RemoteCommand::Sha256(archive), None)?;
    let got = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if got != bundle.sha256 {
        return Err(RunError::Damaged {
            expected: bundle.sha256.clone(),
            got,
        });
    }
    let start = RunStart::new(run.clone(), &bundle.sha256, play)
        .map_err(|e| RunError::Invalid(e.to_string()))?;
    let prepared = RunPrepare::new(
        &start,
        &format!("{:x}", Sha256::digest(NODE_RUN_SH)),
        &format!("{:x}", Sha256::digest(RUN_FILES)),
    )
    .map_err(|e| RunError::Invalid(e.to_string()))?;
    session.run(
        &RemoteCommand::PrepareRun(prepared),
        Some(RUN_FILES.as_bytes()),
    )?;
    session.run(&RemoteCommand::StartRun(start), None)?;
    Ok(run)
}

/// Follows `run` until it ends, handing each log line to `on_line`, and
/// returns its result. Reattaches to a run already going, or replays one
/// that ended.
///
/// # Errors
///
/// Returns [`RunError`] when SSH fails or the run left no result.
pub fn follow(
    session: &Session,
    run: &RunId,
    on_line: &mut dyn FnMut(&str),
) -> Result<RunResult, RunError> {
    let mut after_marker = false;
    let mut result = String::new();
    session.stream(
        &RemoteCommand::FollowRun(run.clone()),
        &mut |stream, line| {
            if stream == Stream::Stderr {
                return;
            }
            if after_marker {
                result.push_str(line);
            } else if line == RESULT_MARKER {
                after_marker = true;
            } else {
                on_line(line);
            }
        },
    )?;
    serde_json::from_str(&result).map_err(|_| RunError::NoResult(run.dir()))
}

#[cfg(test)]
mod tests {
    use super::{RunResult, civil, new_run_id};

    #[test]
    fn a_run_id_has_its_form_and_differs_each_time() {
        let a = new_run_id().expect("id");
        let b = new_run_id().expect("id");
        assert!(a.as_str().starts_with("r-20"), "{}", a.as_str());
        assert_ne!(a, b);
    }

    #[test]
    fn dates_come_out_right() {
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(civil(1_792_756_800), (2026, 10, 23, 12, 0, 0));
    }

    #[test]
    fn a_result_reads_from_the_runners_json() {
        let result: RunResult = serde_json::from_str(
            r#"{"status":"ok","exit_code":0,"started_at":"2026-10-23T12:00:00Z","finished_at":"2026-10-23T12:01:00Z","play":"p.yml","message":""}"#,
        )
        .expect("parses");
        assert!(result.ok());
    }

    #[test]
    fn the_runner_checks_the_digest_and_takes_the_lock_before_anything_else() {
        let script = super::NODE_RUN_SH;
        let lock = script.find("flock -n 9").expect("lock");
        assert!(
            script.contains("exec 9</opt/erpc\n"),
            "the lock needs no write access"
        );
        let digest = script.find("sha256sum bundle.tar.gz").expect("digest");
        let play = script.find("-I -m ansible.cli.playbook -i").expect("play");
        assert!(lock < digest && digest < play);
        assert!(script.contains("--require-hashes"));
    }
}
