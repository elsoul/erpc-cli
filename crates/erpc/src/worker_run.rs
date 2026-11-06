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
//!
//! `--grpc` and `--shreds` give the app data lines that let in this
//! machine's address (`--ip`), as `GRPC_ENDPOINT` and `SHREDS_ENDPOINT`: an
//! active line of the account's that lets it in already is taken up, else a
//! new hourly one is started, after the person's yes to its price. The
//! lines are not written to erpc.toml. When the run ends, Ctrl-C included,
//! the hourly ones are ended, after the person's yes; `--keep-lines` keeps
//! them for the next run. Ctrl-C is taken for that from before the first
//! line is asked for until the last is ended ([`Hold`]): one that comes
//! while a line is being bought waits for the purchase to be on record,
//! and the line is then ended with the rest.

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use erpc_core::i18n::Lang;
use erpc_worker::manifest::{Line, LineKind, Manifest};
use erpc_worker::server::probe;
use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::interrupt::Hold;
use crate::node_common::Say;
use crate::worker::{Dir, load};
use crate::worker_deploy::said_in;
use crate::worker_secrets;
use crate::worker_vps::{self, Api};

/// What the app's environment keeps of erpc's own, so that it runs and
/// prints as it would from a shell.
const PASSED: [&str; 7] = ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "TZ", "TMPDIR"];

/// How long a start without a health URL must stay up to count as healthy.
const SETTLE: Duration = Duration::from_secs(5);

/// How long the app is given to stop on its own after Ctrl-C, before it is
/// killed.
const STOP_GRACE: Duration = Duration::from_secs(10);

/// The data lines a run was asked for.
pub(crate) struct Lines {
    /// Each kind, with the plan asked for a new one.
    pub(crate) kinds: Vec<(LineKind, Option<String>)>,
    /// The address they let in.
    pub(crate) ip: Option<Ipv4Addr>,
    /// Whether they outlive the run.
    pub(crate) keep: bool,
}

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

/// `erpc worker run` and `erpc worker run --check`.
pub(crate) async fn run(json: bool, dir: &Dir, check: bool, lines: &Lines) -> Outcome {
    match start_and_watch(json, dir, check, lines).await {
        Ok(outcome) => outcome,
        Err(e) => e.into(),
    }
}

async fn start_and_watch(
    json: bool,
    dir: &Dir,
    check: bool,
    lines: &Lines,
) -> Result<Outcome, CliError> {
    let say = Say { quiet: json };
    let (path, m) = load(dir)?;
    let root = path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_owned);
    let given: Vec<&str> = lines.kinds.iter().map(|(k, _)| k.setting()).collect();
    let missing = m.missing_besides(&given);
    if !missing.is_empty() {
        let (scope, first) = (dir.scope(), missing[0].first());
        let settings = missing
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        // A line's setting comes from the line's flag, not from a secret.
        let hint = match LineKind::ALL.into_iter().find(|k| k.setting() == first) {
            Some(kind) if kind != LineKind::Unlimited => {
                t!(
                    "worker_run.missing_line_hint",
                    first,
                    flag = kind.flag(),
                    dir_scope = scope
                )
            }
            _ => t!("worker_run.missing_hint", first, dir_scope = scope),
        };
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
    let Some(ip) = lines.ip.filter(|_| !lines.kinds.is_empty()) else {
        let child = spawn(json, &m, &bin, command, key, &say)?;
        if check {
            return Ok(check_and_stop(json, &m, child, None).await);
        }
        return watch(&m, child, &say, None, &dir.scope()).await;
    };
    let api = Api::open().await?;
    // From here until the lines are let go, Ctrl-C stops the run and not
    // erpc, whatever erpc is in the middle of.
    let mut interrupt = Hold::new();
    let mut held = Vec::new();
    let ran = match take_lines(&api, lines, ip, &mut held, &say, &mut interrupt).await {
        Ok(()) => {
            for line in &held {
                command.env(line.kind.setting(), &line.endpoint);
            }
            match spawn(json, &m, &bin, command, key, &say) {
                Ok(child) if check => {
                    Ok(check_and_stop(json, &m, child, Some(&mut interrupt)).await)
                }
                Ok(child) => watch(&m, child, &say, Some(&mut interrupt), &dir.scope()).await,
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    };
    let_go(&api, &held, lines.keep, ip, &dir.scope(), &say).await;
    ran
}

/// Takes up or starts each line asked for, and waits until it is active
/// and lets in `ip`. Each goes into `held` as soon as the account has it,
/// so that it is ended however this ends, Ctrl-C included.
async fn take_lines(
    api: &Api,
    lines: &Lines,
    ip: Ipv4Addr,
    held: &mut Vec<Line>,
    say: &Say,
    interrupt: &mut Hold,
) -> Result<(), CliError> {
    let charged = worker_vps::charged(api).await?;
    for (kind, plan) in &lines.kinds {
        let kind = *kind;
        let label = kind.label();
        let line = take_line(
            kind,
            held,
            interrupt,
            async || {
                let Some(id) = worker_vps::line_letting_in(api, kind, ip).await? else {
                    return Ok(None);
                };
                let mut line = Line {
                    kind,
                    id,
                    endpoint: String::new(),
                    hourly: true,
                };
                line.hourly = worker_vps::is_charged(&charged, &line);
                say.line(&t!(
                    "worker_run.line.taking_up",
                    kind = label,
                    id = line.id,
                    ip
                ));
                Ok(Some((line.id, line.hourly)))
            },
            async |named| {
                worker_vps::start_line(api, kind, ip, None, plan.as_deref(), "", say, named).await
            },
            async |id, hourly| worker_vps::wait_line(api, kind, id, ip, hourly, say).await,
        )
        .await?;
        say.line(&t!(
            "worker_run.line.active",
            kind = label,
            id = line.id,
            setting = kind.setting(),
            endpoint = line.endpoint
        ));
    }
    Ok(())
}

/// What a line's start is given to name the line with, as soon as the
/// account has it.
type Named<'a> = &'a mut dyn FnMut(&str) -> Result<(), CliError>;

/// One line's way into `held`: the one `find` knows, else the one `start`
/// buys, then `wait` until it is active.
///
/// Ctrl-C is answered between these and during the wait, and never by
/// dropping a request half-way: a purchase that was sent is let finish, so
/// that the line it made is in `held`, and with it among the lines the run
/// ends, before the run stops. No line is asked for after a Ctrl-C.
async fn take_line(
    kind: LineKind,
    held: &mut Vec<Line>,
    interrupt: &mut Hold,
    find: impl AsyncFnOnce() -> Result<Option<(String, bool)>, CliError>,
    start: impl AsyncFnOnce(Named<'_>) -> Result<String, CliError>,
    wait: impl AsyncFnOnce(&str, bool) -> Result<Line, CliError>,
) -> Result<Line, CliError> {
    let interrupted = || failed(t!("worker_run.check.interrupted"));
    if interrupt.came() {
        return Err(interrupted());
    }
    let found = find().await?;
    let (id, hourly) = if let Some(found) = found {
        found
    } else {
        if interrupt.came() {
            return Err(interrupted());
        }
        let mut named = None;
        let started = start(&mut |id: &str| {
            named = Some(id.to_owned());
            Ok(())
        })
        .await;
        let started = match (started, named) {
            (started, Some(id)) => {
                // Ended with the rest when this run ends, which the
                // hint for a deploy's line does not say.
                let started = started.map_err(|e| e.hint(t!("worker_run.line.made_anyway")));
                held.push(Line {
                    kind,
                    id,
                    endpoint: String::new(),
                    hourly: true,
                });
                started
            }
            (started, None) => started,
        };
        (started?, true)
    };
    if !held.iter().any(|l| l.kind == kind) {
        held.push(Line {
            kind,
            id: id.clone(),
            endpoint: String::new(),
            hourly,
        });
    }
    // Ctrl-C, now or while the line was found or bought, stops the run,
    // and the line is ended with the rest rather than left charged.
    let line = tokio::select! {
        biased;
        () = interrupt.wait() => return Err(interrupted()),
        line = wait(&id, hourly) => line?,
    };
    if let Some(on) = held.iter_mut().find(|l| l.kind == kind) {
        *on = line.clone();
    }
    Ok(line)
}

/// Ends the hourly lines in `held`, after the person's yes, unless they
/// are kept. One that is not ended is said, with what it costs.
async fn let_go(api: &Api, held: &[Line], keep: bool, ip: Ipv4Addr, dir_scope: &str, say: &Say) {
    for line in held {
        let (kind, id) = (line.kind.label(), &line.id);
        let flag = match line.kind {
            LineKind::Shreds => "shreds",
            _ => "grpc",
        };
        if !line.hourly {
            say.line(&t!("worker_run.line.not_hourly", kind, id));
        } else if keep {
            crate::interrupt::say(&t!("worker_run.line.kept", kind, id, dir_scope, flag, ip));
        } else {
            match worker_vps::end_line(api, line, say).await {
                Ok(_) => say.line(&t!("worker_run.line.ended", kind, id)),
                Err(e) => crate::interrupt::say(&t!(
                    "worker_run.line.not_ended",
                    kind,
                    id,
                    message = e.message,
                    dir_scope,
                    flag,
                    ip
                )),
            }
        }
    }
}

/// Starts the app and hands it its key.
fn spawn(
    json: bool,
    m: &Manifest,
    bin: &Path,
    mut command: Command,
    key: Option<Zeroizing<[u8; 64]>>,
    say: &Say,
) -> Result<Child, CliError> {
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
    Ok(child)
}

/// Resolves on Ctrl-C when lines are held (erpc then stays to end them;
/// the app, in the same process group, has the signal too), at once when
/// it came before the app was started. Without lines, never: Ctrl-C then
/// ends erpc with the app, as it always has.
async fn stopped_by_ctrl_c(interrupt: Option<&mut Hold>) {
    match interrupt {
        Some(interrupt) => interrupt.wait().await,
        None => core::future::pending::<()>().await,
    }
}

/// Gives the app [`STOP_GRACE`] to end on its own, then kills it.
async fn stop(child: &mut Child) {
    let started = Instant::now();
    while started.elapsed() < STOP_GRACE {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
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

/// Runs until the app ends, or Ctrl-C when lines are held; says once
/// when it is healthy.
async fn watch(
    m: &Manifest,
    mut child: Child,
    say: &Say,
    interrupt: Option<&mut Hold>,
    dir_scope: &str,
) -> Result<Outcome, CliError> {
    let health = m.run.health.as_ref().and_then(|h| h.http.clone());
    let mut healthy = health.is_none();
    if healthy {
        say.line(&t!("worker_run.running"));
    }
    let mut ctrl_c = std::pin::pin!(stopped_by_ctrl_c(interrupt));
    loop {
        if let Some(status) = child.try_wait().map_err(|e| failed(e.to_string()))? {
            return if status.success() {
                Ok(stopped(m, dir_scope))
            } else {
                Err(failed(t!("worker_run.ended", name = m.name, status)))
            };
        }
        if !healthy && health.as_deref().is_some_and(probe) {
            healthy = true;
            say.line(&t!("worker_run.healthy"));
        }
        tokio::select! {
            () = &mut ctrl_c => {
                stop(&mut child).await;
                return Ok(stopped(m, dir_scope));
            }
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
}

fn stopped(m: &Manifest, dir_scope: &str) -> Outcome {
    let stopped = t!("worker_run.stopped", name = m.name);
    let mut report = crate::ui::Report::new().marked("👋", stopped.clone());
    let mut plain = stopped;
    // An app that trades with a key may have held positions when it stopped.
    if m.wallet.is_some() {
        let kept = t!("worker_run.positions_kept", dir_scope);
        report = report.detail(kept.clone());
        plain.push('\n');
        plain.push_str(&kept);
    }
    Outcome::Done(report.or_plain(plain))
}

/// Starts, waits for health or the timeout (or Ctrl-C, when lines are
/// `taken`), stops, and reports.
async fn check_and_stop(
    json: bool,
    m: &Manifest,
    mut child: Child,
    interrupt: Option<&mut Hold>,
) -> Outcome {
    // The reason is English in `--json` output, which scripts read.
    let lang = if json { Lang::En } else { crate::i18n::lang() };
    let started = Instant::now();
    let health = m.run.health.as_ref();
    let timeout = Duration::from_secs(u64::from(health.map_or(30, |h| h.timeout_secs)));
    let url = health.and_then(|h| h.http.as_deref());
    let mut ctrl_c = std::pin::pin!(stopped_by_ctrl_c(interrupt));
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
        tokio::select! {
            () = &mut ctrl_c => break Err(said_in!(lang, t!("worker_run.check.interrupted"))),
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
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
    use clap::{CommandFactory as _, Parser};
    use erpc_core::i18n::Lang;
    use erpc_worker::manifest::{Line, LineKind};

    use super::{failed, take_line};
    use crate::i18n::speaking;
    use crate::interrupt::Hold;
    use crate::worker::Action;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        action: Action,
    }

    #[test]
    fn a_line_for_a_run_needs_the_address_it_lets_in() {
        let parse = |args: &[&str]| {
            Cli::command()
                .try_get_matches_from(["worker", "run"].iter().chain(args))
                .is_ok()
        };
        assert!(!parse(&["--grpc"]));
        assert!(!parse(&["--shreds"]));
        assert!(!parse(&["--grpc", "--ip", "2001:db8::1"]));
        assert!(!parse(&["--shreds-plan", "p", "--ip", "203.0.113.7"]));
        assert!(parse(&["--grpc", "--shreds", "--ip", "203.0.113.7"]));
        assert!(parse(&[
            "--shreds",
            "--shreds-plan",
            "p",
            "--ip",
            "203.0.113.7",
            "--keep-lines"
        ]));
    }

    fn line(kind: LineKind, id: &str) -> Line {
        Line {
            kind,
            id: id.to_owned(),
            endpoint: format!("line-{id}.example"),
            hourly: true,
        }
    }

    /// A hold a test presses Ctrl-C on by sending to the returned sender.
    fn hold() -> (tokio::sync::oneshot::Sender<()>, Hold) {
        let (press, pressed) = tokio::sync::oneshot::channel::<()>();
        let interrupt = Hold::of(async move {
            let _ = pressed.await;
        });
        (press, interrupt)
    }

    /// What left a line charged with nothing said: Ctrl-C while the line
    /// was being bought. The purchase is let finish, the line it made is
    /// held, to be ended with the rest, and the run stops before waiting.
    #[tokio::test]
    async fn ctrl_c_while_a_line_is_bought_keeps_the_line_to_end_it() {
        let (press, mut interrupt) = hold();
        let mut held = vec![line(LineKind::Grpc, "41")];
        let waited = std::cell::Cell::new(false);
        let taken = take_line(
            LineKind::Shreds,
            &mut held,
            &mut interrupt,
            async || Ok(None),
            async |named| {
                named("77")?;
                // Ctrl-C, with the request still under way.
                press.send(()).expect("the hold listens");
                tokio::task::yield_now().await;
                Ok("77".to_owned())
            },
            async |_, _| {
                waited.set(true);
                Ok(line(LineKind::Shreds, "77"))
            },
        )
        .await;
        assert_eq!(
            taken.expect_err("the run stops").message,
            t!("worker_run.check.interrupted")
        );
        assert!(!waited.get(), "the line was waited for after Ctrl-C");
        let ids: Vec<&str> = held.iter().map(|l| l.id.as_str()).collect();
        assert_eq!(ids, ["41", "77"], "both lines are there to be ended");
    }

    /// A purchase that fails after the account made the line all the same:
    /// the line is held too.
    #[tokio::test]
    async fn a_line_made_by_a_start_that_failed_is_held() {
        let (_press, mut interrupt) = hold();
        let mut held = Vec::new();
        let taken = take_line(
            LineKind::Grpc,
            &mut held,
            &mut interrupt,
            async || Ok(None),
            async |named| {
                named("12")?;
                Err(failed("it never became active"))
            },
            async |_, _| unreachable!("a start that failed is not waited for"),
        )
        .await;
        assert!(taken.is_err());
        assert_eq!(
            held,
            [Line {
                endpoint: String::new(),
                ..line(LineKind::Grpc, "12")
            }]
        );
    }

    /// After a Ctrl-C nothing more is asked of the account: no line is
    /// looked for and none is bought.
    #[tokio::test]
    async fn no_line_is_asked_for_after_ctrl_c() {
        let (press, mut interrupt) = hold();
        press.send(()).expect("the hold listens");
        let mut held = Vec::new();
        let taken = take_line(
            LineKind::Grpc,
            &mut held,
            &mut interrupt,
            async || unreachable!("looked for a line after Ctrl-C"),
            async |_| unreachable!("bought a line after Ctrl-C"),
            async |_, _| unreachable!("waited for a line after Ctrl-C"),
        )
        .await;
        assert!(taken.is_err());
        assert!(held.is_empty());

        // Between finding that there is none and buying one, too.
        let (press, mut interrupt) = hold();
        let taken = take_line(
            LineKind::Grpc,
            &mut held,
            &mut interrupt,
            async || {
                press.send(()).expect("the hold listens");
                Ok(None)
            },
            async |_| unreachable!("bought a line after Ctrl-C"),
            async |_, _| unreachable!("waited for a line after Ctrl-C"),
        )
        .await;
        assert!(taken.is_err());
        assert!(held.is_empty());
    }

    /// Ctrl-C while a line becomes active stops the wait, with the line
    /// held; without one the line is taken as it became.
    #[tokio::test]
    async fn a_line_is_held_through_its_wait_and_taken_as_it_became() {
        let (press, mut interrupt) = hold();
        let mut held = Vec::new();
        let taken = take_line(
            LineKind::Grpc,
            &mut held,
            &mut interrupt,
            async || Ok(Some(("9".to_owned(), true))),
            async |_| unreachable!("a line found is not bought"),
            async |_, _| {
                press.send(()).expect("the hold listens");
                core::future::pending().await
            },
        )
        .await;
        assert!(taken.is_err());
        assert_eq!(held.len(), 1);

        let (_press, mut interrupt) = hold();
        let mut held = Vec::new();
        let taken = take_line(
            LineKind::Grpc,
            &mut held,
            &mut interrupt,
            async || Ok(Some(("9".to_owned(), true))),
            async |_| unreachable!("a line found is not bought"),
            async |id, _| Ok(line(LineKind::Grpc, id)),
        )
        .await
        .expect("the line");
        assert_eq!(taken.endpoint, "line-9.example");
        assert_eq!(held, [taken]);
    }

    #[test]
    fn a_line_left_charged_is_said_with_how_to_take_it_up() {
        for lang in [Lang::En, Lang::Ja, Lang::Zh, Lang::Ru] {
            let said = speaking(lang, || {
                t!(
                    "worker_run.line.not_ended",
                    kind = "Shreds",
                    id = 77,
                    message = "no",
                    dir_scope = " --dir bot",
                    flag = "shreds",
                    ip = "203.0.113.7"
                )
            });
            assert!(!said.contains('{'), "{said}");
            assert!(
                said.contains("erpc worker run --dir bot --shreds --ip 203.0.113.7"),
                "{said}"
            );
        }
    }

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
