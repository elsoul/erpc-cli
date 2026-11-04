// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker run`: build the app for this machine and run it here, the
//! way a server will run it.
//!
//! The app gets a clean environment: `[vars]`, the `[secrets]` read from
//! their stores, and the few variables a program needs to run at all, and
//! nothing else of erpc's -- no 1Password token, no SSH agent. The trading
//! key goes in on the app's standard input, a pipe erpc writes the 64
//! bytes to and closes; `ERPC_WORKER_KEY_FD=0` tells the app to read it
//! there. (A descriptor of its own would need code erpc does not allow
//! itself, and a pipe on standard input is the same pipe.) The key is
//! never in a file, an argument or the environment.
//!
//! `--check` starts the app, waits until it is healthy, stops it, and says
//! how it went: the check `deploy` makes before it ships a release.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use erpc_core::i18n::Lang;
use erpc_worker::manifest::Manifest;
use erpc_worker::server::probe;
use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::node_common::Say;
use crate::worker::{Dir, load};
use crate::worker_deploy::said_in;
use crate::worker_secrets;

/// What the app's environment keeps of erpc's own, so that it runs and
/// prints as it would from a shell.
const PASSED: [&str; 7] = ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "TZ", "TMPDIR"];

/// How long a start without a health URL must stay up to count as healthy.
const SETTLE: Duration = Duration::from_secs(5);

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

/// `erpc worker run` and `erpc worker run --check`.
pub(crate) fn run(json: bool, dir: &Dir, check: bool) -> Outcome {
    match start_and_watch(json, dir, check) {
        Ok(outcome) => outcome,
        Err(e) => e.into(),
    }
}

fn start_and_watch(json: bool, dir: &Dir, check: bool) -> Result<Outcome, CliError> {
    let say = Say { quiet: json };
    let (path, m) = load(dir)?;
    let root = path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_owned);
    let missing = m.missing();
    if !missing.is_empty() {
        let (scope, first, settings) = (dir.scope(), &missing[0], missing.join(", "));
        let hint = t!("worker_run.missing_hint", first, dir_scope = scope);
        return Err(failed(t!("worker_run.missing", name = m.name, settings)).hint(hint));
    }
    if m.wallet.is_some() {
        worker_secrets::may_read_key().map_err(failed)?;
    }
    let bin = build(&m, &root, &say)?;
    let mut command = Command::new(&bin);
    command
        .args(&m.run.args)
        .current_dir(&root)
        .env_clear()
        .envs(
            PASSED
                .iter()
                .filter_map(|n| std::env::var_os(n).map(|v| (n, v))),
        )
        .envs(&m.vars);
    for (name, reference) in &m.secrets {
        let value = worker_secrets::read(reference).map_err(failed)?;
        command.env(name, value.as_str());
    }
    let key = if let Some(wallet) = &m.wallet {
        let keypair =
            worker_secrets::read_key(&wallet.source, wallet.pubkey.as_deref()).map_err(failed)?;
        command.env("ERPC_WORKER_KEY_FD", "0");
        if let Some(pubkey) = &wallet.pubkey {
            command.env("ERPC_WORKER_PUBKEY", pubkey);
        }
        let mut bytes = Zeroizing::new([0_u8; 64]);
        bytes.copy_from_slice(keypair.bytes());
        Some(bytes)
    } else {
        let dir_scope = dir.scope();
        say.line(&t!("worker_run.watch_only", dir_scope));
        None
    };
    command.stdin(if key.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    if json {
        // stdout is erpc's result; the app's output goes beside erpc's progress.
        command.stdout(Stdio::from(std::io::stderr()));
    }
    let mut child = command.spawn().map_err(|e| {
        let bin = bin.display();
        failed(t!("worker_run.could_not_start", bin, error = e))
    })?;
    if let Some(key) = key {
        let handed = child
            .stdin
            .take()
            .ok_or_else(|| failed(t!("worker_run.no_stdin")))
            .and_then(|mut pipe| {
                pipe.write_all(&key[..])
                    .map_err(|e| failed(t!("worker_run.key_not_handed", error = e)))
            });
        drop(key);
        if let Err(e) = handed {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    }
    say.line(&t!("worker_run.started", name = m.name, pid = child.id()));
    if check {
        return Ok(check_and_stop(json, &m, child));
    }
    watch(&m, child, &say)
}

/// Builds the app for this machine and returns its binary.
fn build(m: &Manifest, root: &Path, say: &Say) -> Result<PathBuf, CliError> {
    let (program, args) = m
        .build
        .command
        .split_first()
        .ok_or_else(|| failed(t!("worker_run.build.empty")))?;
    let command = m.build.command.join(" ");
    say.line(&t!("worker_run.build.building", command));
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::io::stderr()))
        .status()
        .map_err(|e| failed(t!("worker_run.build.could_not_run", program, error = e)))?;
    if !status.success() {
        return Err(failed(t!("worker_run.build.failed", status)));
    }
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || root.join("target"),
        |d| {
            let d = PathBuf::from(d);
            if d.is_absolute() { d } else { root.join(d) }
        },
    );
    let bin = target.join("release").join(m.bin());
    if bin.is_file() {
        Ok(bin)
    } else {
        Err(
            failed(t!("worker_run.build.no_binary", bin = bin.display()))
                .hint(t!("worker_run.build.no_binary_hint")),
        )
    }
}

/// Runs until the app ends; says once when it is healthy.
fn watch(m: &Manifest, mut child: Child, say: &Say) -> Result<Outcome, CliError> {
    let health = m.run.health.as_ref().and_then(|h| h.http.clone());
    let mut healthy = health.is_none();
    if healthy {
        say.line(&t!("worker_run.running"));
    }
    loop {
        if let Some(status) = child.try_wait().map_err(|e| failed(e.to_string()))? {
            return if status.success() {
                let stopped = t!("worker_run.stopped", name = m.name);
                Ok(Outcome::Done(
                    crate::ui::Report::new()
                        .marked("👋", stopped.clone())
                        .or_plain(stopped),
                ))
            } else {
                Err(failed(t!("worker_run.ended", name = m.name, status)))
            };
        }
        if !healthy && health.as_deref().is_some_and(probe) {
            healthy = true;
            say.line(&t!("worker_run.healthy"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Starts, waits for health or the timeout, stops, and reports.
fn check_and_stop(json: bool, m: &Manifest, mut child: Child) -> Outcome {
    // The reason is English in `--json` output, which scripts read.
    let lang = if json { Lang::En } else { crate::i18n::lang() };
    let started = Instant::now();
    let health = m.run.health.as_ref();
    let timeout = Duration::from_secs(u64::from(health.map_or(30, |h| h.timeout_secs)));
    let url = health.and_then(|h| h.http.as_deref());
    let verdict = loop {
        if let Ok(Some(status)) = child.try_wait() {
            break Err(said_in!(lang, t!("worker_run.check.ended", status)));
        }
        let up = match url {
            Some(url) => probe(url),
            None => started.elapsed() >= SETTLE,
        };
        if up {
            break Ok(());
        }
        if started.elapsed() >= timeout {
            break Err(said_in!(
                lang,
                t!("worker_run.check.timeout", secs = timeout.as_secs())
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    let _ = child.kill();
    let _ = child.wait();
    let after = started.elapsed();
    if json {
        crate::print_json(&json!({
            "name": m.name,
            "healthy": verdict.is_ok(),
            "after_ms": u64::try_from(after.as_millis()).unwrap_or(u64::MAX),
            "reason": verdict.as_ref().err(),
        }));
    }
    match verdict {
        Ok(()) if json => Outcome::Done(String::new()),
        Ok(()) => {
            let secs = format!("{:.1}", after.as_secs_f64());
            let text = t!("worker_run.check.healthy", name = m.name, secs);
            Outcome::Done(crate::ui::Report::new().done(text.clone()).or_plain(text))
        }
        Err(why) if json => {
            let _ = why;
            Outcome::Problems(String::new())
        }
        Err(why) => {
            let text = t!("worker_run.check.failed", name = m.name, why);
            Outcome::Problems(
                crate::ui::Report::new()
                    .marked("🩺", text.clone())
                    .or_plain(text),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use erpc_core::i18n::Lang;

    use crate::i18n::speaking;

    #[test]
    fn what_run_says_is_said_in_the_language_of_the_run() {
        let english = t!("worker_run.started", name = "bot", pid = 42);
        assert_eq!(english, "bot started (pid 42)");
        for lang in [Lang::Ja, Lang::Ru] {
            let said = speaking(lang, || t!("worker_run.started", name = "bot", pid = 42));
            assert_ne!(said, english);
            assert!(!said.contains('{'), "{said}");
            assert!(said.contains("bot") && said.contains("42"), "{said}");
        }
    }
}
