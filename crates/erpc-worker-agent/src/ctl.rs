// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-worker-agent ctl`: what erpc runs as root over SSH.
//!
//! It owns the worker's directory: it checks a release against the
//! digests its `release.json` states before the release may run, moves
//! `current` and `previous` with a rename each (so a reader sees one
//! release or the other, never neither), and holds `.lock` while it does,
//! so two deploys cannot interleave. Activation is: check, point `current`
//! at the release, have the agent restart the app, and wait for it to be
//! healthy; when it is not, point `current` back and restart again. The
//! releases past `keep_releases` are then removed, never `current` or
//! `previous`.
//!
//! Everything it prints is one JSON object on standard output, for erpc to
//! read, whose `ok` says whether it did what was asked.

use std::fs::File;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use erpc_worker::release::{self, Release};
use erpc_worker::server::{self, Launch, Reply, Status};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::Verb;
use crate::wafctl;

/// The biggest unlock read from standard input.
const MAX_UNLOCK: u64 = 256 * 1024;
/// What the health wait adds to the release's own timeout, for the app's
/// own start.
const SLACK: Duration = Duration::from_secs(5);

/// The most that is read of a worker's `wanted` file: its agent writes
/// `1` or `0` and a newline.
const MAX_WANTED: u64 = 8;

/// Where erpc stages a release's files before `install` moves them in.
const UPLOADS: &str = "/opt/erpc/uploads";

/// Runs one verb and prints its JSON answer.
pub(crate) fn run(id: &str, dir: &Path, socket: &Path, verb: &Verb) -> ExitCode {
    let answer = match verb {
        Verb::Setup {
            restart_agent,
            keep_agent,
        } => setup(
            id,
            dir,
            socket,
            Asked::from_flags(*restart_agent, *keep_agent),
            &Host::real(),
        ),
        Verb::Install { release } => locked(dir, || {
            install(id, dir, Path::new(UPLOADS), release, wanted_running)
        }),
        Verb::Remove => remove(id, dir),
        Verb::FirewallApply => crate::firewall::apply(id),
        Verb::FirewallConfirm => crate::firewall::confirm(),
        Verb::FirewallShow => crate::firewall::show().map(|mut shown| {
            shown["waf"] = wafctl::status(&wafctl::Host::server(), id);
            shown
        }),
        Verb::WafApply => locked(dir, || {
            wafctl::apply(&wafctl::Host::server(), id, &wafctl::config_on_stdin()?)
        }),
        Verb::WafRemove => locked(dir, || wafctl::remove(&wafctl::Host::server(), id)),
        Verb::Status => status(id, dir, socket),
        Verb::Unlock => unlock(socket),
        Verb::Lock => forward(socket, r#"{"op":"lock"}"#),
        Verb::Start => forward(socket, r#"{"op":"start"}"#),
        Verb::Stop => forward(socket, r#"{"op":"stop"}"#),
        Verb::Restart => forward(socket, r#"{"op":"restart"}"#),
        Verb::Activate { release } => {
            locked(dir, || activate(dir, socket, release, wanted_running))
        }
        Verb::Rollback { to } => {
            locked(dir, || rollback(dir, socket, to.as_deref(), wanted_running))
        }
        Verb::Releases => releases(dir).map(|r| json!({ "ok": true, "releases": r })),
        Verb::BenchRpc => crate::bench::run(),
        Verb::BackupSetup { at } => crate::backup::setup(id, at),
        Verb::BackupRemove => crate::backup::remove(id),
        Verb::BackupStatus => Ok(crate::backup::status(id)),
        Verb::BackupNow => crate::backup::now(id),
        Verb::Services { redis, postgres } => crate::services::ensure(id, *redis, *postgres),
    };
    let body = answer.unwrap_or_else(|e| json!({ "ok": false, "error": e }));
    println!("{body}");
    // The answer is the JSON, `ok` included; exiting 0 whenever there is one
    // lets erpc read why a verb failed (ssh drops what a failed command
    // printed). A crash still exits otherwise.
    ExitCode::SUCCESS
}

/// Holds the worker's lock around `change`.
fn locked(dir: &Path, change: impl FnOnce() -> Result<Value, String>) -> Result<Value, String> {
    std::fs::create_dir_all(dir.join("releases"))
        .map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    let lock = File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join(".lock"))
        .map_err(|e| format!("could not open the lock: {e}"))?;
    lock.try_lock().map_err(|_| {
        "another erpc is changing this worker; try again when it is done".to_owned()
    })?;
    let result = change();
    let _ = lock.unlock();
    result
}

/// Sends one request line and reads the answer.
fn ask(socket: &Path, line: &[u8]) -> Result<Reply, String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|e| format!("the agent is not answering on {}: {e}", socket.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(90)))
        .map_err(|e| e.to_string())?;
    stream.write_all(line).map_err(|e| e.to_string())?;
    if !line.ends_with(b"\n") {
        stream.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    let mut answer = String::new();
    BufReader::new(stream)
        .read_line(&mut answer)
        .map_err(|e| format!("could not read the agent's answer: {e}"))?;
    serde_json::from_str(&answer).map_err(|e| format!("the agent's answer is not JSON: {e}"))
}

fn forward(socket: &Path, line: &str) -> Result<Value, String> {
    let reply = ask(socket, line.as_bytes())?;
    serde_json::to_value(&reply).map_err(|e| e.to_string())
}

fn agent_status(socket: &Path) -> Result<Status, String> {
    ask(socket, br#"{"op":"status"}"#)?
        .status
        .ok_or_else(|| "the agent gave no status".to_owned())
}

/// The unlock request is read from standard input and passed on as it is:
/// it carries the key, so it is not parsed or copied here more than once,
/// and the buffer is wiped.
fn unlock(socket: &Path) -> Result<Value, String> {
    #[allow(clippy::cast_possible_truncation, reason = "256 KiB")]
    let line = crate::wiped::read(&mut std::io::stdin().lock(), MAX_UNLOCK as usize, false)
        .map_err(|e| format!("could not read standard input: {e}"))?
        .ok_or("the unlock on standard input is too long")?;
    let body = line.trim_ascii();
    if !body.starts_with(br#"{"op":"unlock""#) || body.contains(&b'\n') {
        return Err("standard input is not one unlock request".to_owned());
    }
    let reply = ask(socket, body)?;
    serde_json::to_value(&reply).map_err(|e| e.to_string())
}

/// The release a link points at, by id.
fn pointed(dir: &Path, link: &str) -> Option<String> {
    let target = std::fs::read_link(dir.join(link)).ok()?;
    let id = target.file_name()?.to_str()?.to_owned();
    release::is_id(&id).then_some(id)
}

/// Points `link` at `releases/<id>` in one rename.
fn point(dir: &Path, link: &str, id: &str) -> Result<(), String> {
    let tmp = dir.join(format!(".{link}.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(format!("releases/{id}"), &tmp)
        .and_then(|()| std::fs::rename(&tmp, dir.join(link)))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("could not point {link} at {id}: {e}")
        })
}

fn sha256(path: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use core::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        }))
}

/// A release on disk, checked: its records parse, its binary and files
/// have the digests `release.json` states, and its launch file names the
/// same binary.
fn checked(dir: &Path, id: &str) -> Result<(PathBuf, Release, Launch), String> {
    if !release::is_id(id) {
        return Err(format!("`{id}` is not a release id"));
    }
    let release_dir = dir.join("releases").join(id);
    let read = |name: &str| {
        std::fs::read_to_string(release_dir.join(name))
            .map_err(|e| format!("release {id} has no readable {name}: {e}"))
    };
    let release = Release::parse(&read(release::FILE_NAME)?)?;
    let launch = Launch::parse(&read(server::LAUNCH_FILE)?)?;
    if release.id != id {
        return Err(format!(
            "release {id}'s release.json says it is {}",
            release.id
        ));
    }
    if launch.bin != release.bin {
        return Err(format!(
            "release {id} launches {}, and was built as {}",
            launch.bin, release.bin
        ));
    }
    if sha256(&release_dir.join(&release.bin))? != release.sha256 {
        return Err(format!(
            "release {id}'s binary is not the one that was built; it is not used"
        ));
    }
    for file in &release.files {
        if sha256(&release_dir.join(&file.path))? != file.sha256 {
            return Err(format!(
                "release {id}'s {} is not the one that was shipped",
                file.path
            ));
        }
    }
    Ok((release_dir, release, launch))
}

/// Waits until the agent runs `id` healthy, or says why it did not.
fn healthy(socket: &Path, id: &str, timeout: Duration) -> Result<Status, String> {
    let started = Instant::now();
    let mut last = None;
    while started.elapsed() < timeout {
        let status = agent_status(socket)?;
        if status.release.as_deref() == Some(id) && status.healthy {
            return Ok(status);
        }
        if status.state == "locked" {
            return Err(status
                .reason
                .unwrap_or_else(|| "the worker is locked".to_owned()));
        }
        // A start the agent refused (the port is taken, the binary would
        // not run) does not come good by waiting: the agent tries again
        // only when something changes.
        if status.state == "waiting"
            && status.release.is_none()
            && let Some(refused) = &status.reason
        {
            return Err(refused.clone());
        }
        last = Some(status);
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(match last {
        Some(s) => format!(
            "release {id} was not healthy within {}s (state {}, last exit {})",
            timeout.as_secs(),
            s.state,
            s.last_exit.unwrap_or_else(|| "none".to_owned())
        ),
        None => format!("release {id} was not healthy within {}s", timeout.as_secs()),
    })
}

/// Whether a worker's agent is asked to keep its app running, as the
/// `wanted` file in its state says ([`kept_running`]).
fn wanted_running(worker: &str) -> bool {
    kept_running(&server::wanted_file(&server::state_dir(worker)))
}

/// What a worker's `wanted` file says of its app: kept running, unless the
/// file says it is not.
///
/// This is read as root, and the file is in the worker's state directory,
/// which its app can write to. So it is opened without following a link
/// and without waiting (a FIFO would hold `ctl` here, with its own
/// worker's lock held), only a regular file is read, and no more of it
/// than [`MAX_WANTED`].
///
/// - No file: the agent was never asked to run the app. Not kept running.
/// - `0`: stopped. Not kept running.
/// - `1`: kept running.
/// - Anything else (a link, a FIFO, a directory, more than the agent
///   writes, other words): not what the agent writes, so nothing is known.
///   It counts as kept running. That errs towards refusing a release on
///   the worker's port, which costs a deploy on another port. The other
///   way, two apps could be given one port, and whichever starts first
///   would keep the other from starting.
pub(crate) fn kept_running(wanted: &Path) -> bool {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = match rustix::fs::open(wanted, flags, Mode::empty()) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return false,
        Err(_) => return true,
    };
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        return true;
    }
    let mut said = Vec::new();
    match file.take(MAX_WANTED + 1).read_to_end(&mut said) {
        Ok(read) if read as u64 <= MAX_WANTED => said.trim_ascii() != b"0",
        _ => true,
    }
}

/// The refusal for a release whose health port is another worker's on
/// this server: one that is kept running (`runs`, by its name) and whose
/// release in use is probed on the same port. Two apps cannot listen on
/// one port, and the probe would take the other's answer for this app's.
/// Only health ports are compared: a release without a health URL, or
/// beside a neighbour without one, is not refused here.
fn port_clash(dir: &Path, launch: &Launch, runs: impl Fn(&str) -> bool) -> Option<String> {
    let port_of = |launch: &Launch| {
        let url = launch.health.http.as_deref()?;
        server::health_address(url).map(|address| address.port())
    };
    let ours = port_of(launch)?;
    let this = dir.file_name()?;
    let mut others: Vec<_> = std::fs::read_dir(dir.parent()?)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_name() != this)
        .collect();
    others.sort_by_key(std::fs::DirEntry::file_name);
    others.into_iter().find_map(|entry| {
        let name = entry.file_name().to_str()?.to_owned();
        let text =
            std::fs::read_to_string(entry.path().join("current").join(server::LAUNCH_FILE)).ok()?;
        let theirs = Launch::parse(&text).ok()?;
        (port_of(&theirs) == Some(ours) && runs(&name))
            .then(|| server::port_taken(ours, Some(&name)))
    })
}

fn restart(socket: &Path) -> Result<(), String> {
    let reply = ask(socket, br#"{"op":"restart"}"#)?;
    // A restart that cannot start says so in the status; the health wait
    // reports it.
    if reply.ok || reply.status.is_some() {
        Ok(())
    } else {
        Err(reply
            .error
            .unwrap_or_else(|| "the agent refused".to_owned()))
    }
}

/// `activate`: `id` made current and waited for, and the release before
/// put back when it does not come up healthy. `runs` says whether another
/// worker on the server is kept running ([`port_clash`]).
fn activate(
    dir: &Path,
    socket: &Path,
    id: &str,
    runs: impl Fn(&str) -> bool,
) -> Result<Value, String> {
    let (_, _, launch) = checked(dir, id)?;
    let before = pointed(dir, "current");
    let before_previous = pointed(dir, "previous");
    if before.as_deref() == Some(id) {
        return Ok(json!({ "ok": true, "release": id, "changed": false }));
    }
    if let Some(taken) = port_clash(dir, &launch, runs) {
        // Said before anything is switched: the release in use stays.
        return Ok(json!({ "ok": false, "release": id, "error": taken, "unchanged": true }));
    }
    point(dir, "current", id)?;
    if let Some(old) = &before {
        point(dir, "previous", old)?;
    }
    restart(socket)?;
    let timeout = Duration::from_secs(u64::from(launch.health.timeout_secs)) + SLACK;
    match healthy(socket, id, timeout) {
        Ok(status) => {
            let removed = prune(dir, launch.keep_releases)?;
            Ok(json!({
                "ok": true,
                "release": id,
                "previous": before,
                "changed": true,
                "status": status,
                "removed": removed,
            }))
        }
        Err(why) => {
            let Some(old) = before else {
                // A first release with nothing to go back to: leave it
                // stopped rather than failing over and over.
                let _ = ask(socket, br#"{"op":"stop"}"#);
                return Ok(
                    json!({ "ok": false, "release": id, "error": why, "rolled_back": false }),
                );
            };
            point(dir, "current", &old)?;
            if let Some(p) = &before_previous {
                point(dir, "previous", p)?;
            }
            restart(socket)?;
            let back = healthy(socket, &old, timeout);
            Ok(json!({
                "ok": false,
                "release": id,
                "error": why,
                "rolled_back": true,
                "running": old,
                "running_healthy": back.is_ok(),
            }))
        }
    }
}

/// `rollback`: the previous release, or `to`, made current and waited
/// for. `runs` is as for [`activate`]: the release gone back to may be
/// probed on a port a neighbour was given since.
fn rollback(
    dir: &Path,
    socket: &Path,
    to: Option<&str>,
    runs: impl Fn(&str) -> bool,
) -> Result<Value, String> {
    let current = pointed(dir, "current");
    let target = match to {
        Some(id) => id.to_owned(),
        None => pointed(dir, "previous").ok_or("there is no previous release to go back to")?,
    };
    if current.as_deref() == Some(target.as_str()) {
        return Ok(json!({ "ok": true, "release": target, "changed": false }));
    }
    let (_, _, launch) = checked(dir, &target)?;
    if let Some(taken) = port_clash(dir, &launch, runs) {
        // Said before anything is switched: the release in use stays.
        return Ok(json!({ "ok": false, "release": target, "error": taken, "unchanged": true }));
    }
    point(dir, "current", &target)?;
    if let Some(old) = &current {
        point(dir, "previous", old)?;
    }
    restart(socket)?;
    let timeout = Duration::from_secs(u64::from(launch.health.timeout_secs)) + SLACK;
    let result = healthy(socket, &target, timeout);
    Ok(json!({
        "ok": result.is_ok(),
        "release": target,
        "previous": current,
        "changed": true,
        "error": result.err(),
    }))
}

/// Every release kept, newest first, with what its record says.
fn releases(dir: &Path) -> Result<Vec<Value>, String> {
    let current = pointed(dir, "current");
    let previous = pointed(dir, "previous");
    let mut ids = release_ids(dir)?;
    ids.reverse();
    Ok(ids
        .into_iter()
        .map(|id| {
            let record =
                std::fs::read_to_string(dir.join("releases").join(&id).join(release::FILE_NAME))
                    .ok()
                    .and_then(|t| Release::parse(&t).ok());
            json!({
                "id": id,
                "current": current.as_deref() == Some(id.as_str()),
                "previous": previous.as_deref() == Some(id.as_str()),
                "built_at": record.as_ref().map(|r| r.built_at.clone()),
                "sha256": record.as_ref().map(|r| r.sha256.clone()),
                "commit": record.as_ref().and_then(|r| r.source.as_ref().map(|s| s.commit.clone())),
                "dirty": record.as_ref().and_then(|r| r.source.as_ref().map(|s| s.dirty)),
            })
        })
        .collect())
}

/// The release directories, oldest first (the ids sort by time).
fn release_ids(dir: &Path) -> Result<Vec<String>, String> {
    let entries = match std::fs::read_dir(dir.join("releases")) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("could not list the releases: {e}")),
    };
    let mut ids: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| release::is_id(n))
        .collect();
    ids.sort();
    Ok(ids)
}

/// Removes the oldest releases past `keep`, never `current` or `previous`.
fn prune(dir: &Path, keep: u8) -> Result<Vec<String>, String> {
    let keep = usize::from(keep.max(1));
    let held = [pointed(dir, "current"), pointed(dir, "previous")];
    let ids = release_ids(dir)?;
    let mut removed = Vec::new();
    let excess = ids.len().saturating_sub(keep);
    for id in ids.into_iter().take(excess) {
        if held.iter().any(|h| h.as_deref() == Some(id.as_str())) {
            continue;
        }
        std::fs::remove_dir_all(dir.join("releases").join(&id))
            .map_err(|e| format!("could not remove release {id}: {e}"))?;
        removed.push(id);
    }
    Ok(removed)
}

/// Runs `systemctl` with `args`.
pub(crate) fn systemctl(args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new("systemctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("could not run systemctl: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// What `setup` was asked to do about an agent that runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// Neither flag: restart it only when what it runs from changed.
    IfChanged,
    /// `--restart-agent`: its binary was just replaced.
    Restart,
    /// `--keep-agent`: leave it running, whatever changed.
    Keep,
}

impl Asked {
    /// From the flags. They are not given together; were they, keeping
    /// comes first: a restarted agent has neither the key nor the secrets,
    /// and `--keep-agent` says nothing follows that hands them back.
    const fn from_flags(restart_agent: bool, keep_agent: bool) -> Self {
        match (keep_agent, restart_agent) {
            (true, _) => Self::Keep,
            (false, true) => Self::Restart,
            (false, false) => Self::IfChanged,
        }
    }
}

/// What `setup` does about the worker's agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentNext {
    /// It does not run: it is started. It comes up locked, and there is
    /// nothing to lose.
    Start,
    /// It runs, and is restarted: it comes back locked.
    Restart,
    /// It runs what is installed: left as it is.
    Leave,
    /// It runs and was asked to be kept: left as it is, whatever changed.
    Keep,
}

impl AgentNext {
    /// From whether the unit is active, what was asked, and whether what
    /// the agent runs from changed: its unit's text, or the agent
    /// installed since it started.
    const fn of(active: bool, asked: Asked, changed: bool) -> Self {
        match (active, asked, changed) {
            (false, ..) => Self::Start,
            (true, Asked::Keep, _) => Self::Keep,
            (true, Asked::Restart, _) | (true, Asked::IfChanged, true) => Self::Restart,
            (true, Asked::IfChanged, false) => Self::Leave,
        }
    }

    /// As the answer names it.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "started",
            Self::Restart => "restarted",
            Self::Leave => "running",
            Self::Keep => "kept",
        }
    }
}

/// Whether `a` and `b` are two files rather than one; `None` when either
/// cannot be read.
fn differ(a: &Path, b: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let (a, b) = (std::fs::metadata(a).ok()?, std::fs::metadata(b).ok()?);
    Some((a.dev(), a.ino()) != (b.dev(), b.ino()))
}

/// How `setup` asks systemd: [`systemctl`], or a test's.
type Systemctl<'a> = &'a dyn Fn(&[&str]) -> Result<String, String>;

/// What `setup` changes outside the worker's directory: where it writes,
/// and how it asks systemd. The server's own ([`Host::real`]), or a
/// test's.
struct Host<'a> {
    /// Where systemd reads the worker's unit from.
    units: &'a Path,
    /// What keeps needrestart from the workers.
    needrestart: &'a Path,
    systemctl: Systemctl<'a>,
}

impl Host<'static> {
    /// The server `ctl` runs on.
    fn real() -> Self {
        Self {
            units: Path::new("/etc/systemd/system"),
            needrestart: Path::new(server::NEEDRESTART_CONF),
            systemctl: &systemctl,
        }
    }
}

/// The agent installed, as a file: the one this `ctl` runs from.
pub(crate) const INSTALLED: &str = "/proc/self/exe";

/// Whether process `pid`, as `proc` (the server's `/proc`) has it, runs
/// the file `installed`; `None` when that cannot be told (no such process,
/// or a file that cannot be read). The files themselves are compared, by
/// device and inode, not their paths: a binary replaced while it ran
/// keeps running from a file that has no name any more.
///
/// The one way a unit's main process is told from the agent installed:
/// a worker's agent here ([`runs_another_agent`]), and its WAF's proxy
/// ([`crate::wafctl`]).
pub(crate) fn runs_installed(proc: &Path, pid: u32, installed: &Path) -> Option<bool> {
    differ(&proc.join(pid.to_string()).join("exe"), installed).map(|other| !other)
}

/// Whether the agent that runs as `unit` is not the one installed, which
/// is the one this `ctl` runs from: an agent replaced while it ran, and
/// kept then (`--keep-agent`) or never restarted since. `false` when that
/// cannot be told.
fn runs_another_agent(unit: &str, systemctl: Systemctl<'_>) -> bool {
    let Ok(pid) = systemctl(&["show", "--property=MainPID", "--value", unit]) else {
        return false;
    };
    let Ok(pid) = pid.trim().parse() else {
        return false;
    };
    runs_installed(Path::new("/proc"), pid, Path::new(INSTALLED)) == Some(false)
}

/// `setup`: the worker's directory and unit, written when they differ, and
/// its agent running. An agent that runs is restarted when `asked` says
/// its binary was just replaced, when its unit changed, or when it is not
/// the agent installed; it comes back locked. Asked to keep it, it is left
/// running whatever changed, and the answer says whether something newer
/// waits for its next restart: the unit is written all the same, so that
/// restart uses it.
///
/// needrestart is told to leave the workers alone first, before the unit
/// is written or its agent started; when that cannot be written the answer
/// says why (`needrestart_error`), and the setup goes on.
fn setup(
    id: &str,
    dir: &Path,
    socket: &Path,
    asked: Asked,
    host: &Host<'_>,
) -> Result<Value, String> {
    use std::os::unix::fs::PermissionsExt as _;
    let systemctl = host.systemctl;
    std::fs::create_dir_all(dir.join("releases"))
        .map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    for d in [dir.to_owned(), dir.join("releases")] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("could not set {}'s mode: {e}", d.display()))?;
    }
    // Before anything installs a package on this server: needrestart would
    // restart the workers after it, and a restarted agent has no key.
    let needrestart = keep_from_needrestart(host.needrestart).err();
    let unit_path = host.units.join(server::unit_name(id));
    let wanted = server::unit(id);
    let written = std::fs::read_to_string(&unit_path).ok().as_deref() != Some(wanted.as_str());
    if written {
        std::fs::write(&unit_path, &wanted)
            .and_then(|()| {
                std::fs::set_permissions(&unit_path, std::fs::Permissions::from_mode(0o644))
            })
            .map_err(|e| format!("could not write {}: {e}", unit_path.display()))?;
        systemctl(&["daemon-reload"])?;
    }
    let unit = server::unit_name(id);
    systemctl(&["enable", "--quiet", &unit])?;
    let active = systemctl(&["is-active", &unit]).is_ok();
    // An agent kept while a newer one was installed is not the one
    // installed: the next setup that may restart it does.
    let changed = written || (active && runs_another_agent(&unit, systemctl));
    let next = AgentNext::of(active, asked, changed);
    match next {
        AgentNext::Start => {
            systemctl(&["start", &unit])?;
        }
        AgentNext::Restart => {
            systemctl(&["restart", &unit])?;
        }
        AgentNext::Leave | AgentNext::Keep => {}
    }
    // The agent answers once its socket is there.
    let since = Instant::now();
    while agent_status(socket).is_err() {
        if since.elapsed() > Duration::from_secs(15) {
            return Err(format!(
                "the agent did not come up: see journalctl -u {unit}"
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(json!({
        "ok": true,
        "unit": if written { "written" } else { "unchanged" },
        "agent": next.as_str(),
        "newer_waits": next == AgentNext::Keep && changed,
        "needrestart_error": needrestart,
    }))
}

/// Writes what keeps needrestart from restarting a worker
/// ([`server::needrestart_conf`]) to `path`, when it is not there as it
/// should be. On a server without needrestart the file waits for it. The
/// file is 0644 and a directory made for it 0755, whatever the umask, as
/// the rest of needrestart's configuration is.
fn keep_from_needrestart(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    let wanted = server::needrestart_conf();
    if std::fs::read_to_string(path).ok().as_deref() == Some(wanted.as_str()) {
        return Ok(());
    }
    let failed = |e: std::io::Error| format!("could not write {}: {e}", path.display());
    if let Some(dir) = path.parent() {
        make_dirs(dir).map_err(failed)?;
    }
    std::fs::write(path, wanted).map_err(failed)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).map_err(failed)
}

/// Makes `dir`, and the directories above it that are not there, 0755
/// whatever the umask. One that is there is left as it is.
fn make_dirs(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    if let Some(above) = dir.parent() {
        make_dirs(above)?;
    }
    std::fs::create_dir(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
}

/// Copies `from` into `to`: directories 0755, files 0644, `bin` 0755, all
/// root's.
fn copy_tree(from: &Path, to: &Path, bin: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(to).map_err(|e| format!("could not make {}: {e}", to.display()))?;
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    for entry in
        std::fs::read_dir(from).map_err(|e| format!("could not list {}: {e}", from.display()))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target, "")?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target)
                .map_err(|e| format!("could not copy {}: {e}", entry.path().display()))?;
            let mode = if entry.file_name() == bin {
                0o755
            } else {
                0o644
            };
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))
                .map_err(|e| e.to_string())?;
        }
        // Links and anything else in an upload are left behind.
    }
    Ok(())
}

/// `install`: the staged upload of `id`'s release, moved into its releases
/// and checked against its digests; nothing is kept when a digest differs,
/// or when the release is probed on the health port of another worker
/// that `runs` says is kept running ([`port_clash`]).
fn install(
    id: &str,
    dir: &Path,
    uploads: &Path,
    release_id: &str,
    runs: impl Fn(&str) -> bool,
) -> Result<Value, String> {
    if !release::is_id(release_id) {
        return Err(format!("`{release_id}` is not a release id"));
    }
    let staged = uploads.join(id).join(release_id);
    let target = dir.join("releases").join(release_id);
    if target.exists() {
        // Installed by an earlier deploy that went no further.
        let (_, _, launch) = checked(dir, release_id)?;
        let _ = std::fs::remove_dir_all(&staged);
        if let Some(taken) = port_clash(dir, &launch, &runs) {
            return Err(taken);
        }
        return Ok(json!({ "ok": true, "release": release_id, "installed": false }));
    }
    let record = std::fs::read_to_string(staged.join(release::FILE_NAME))
        .map_err(|e| format!("nothing staged for {release_id}: {e}"))?;
    let bin = Release::parse(&record)?.bin;
    let tmp = dir
        .join("releases")
        .join(format!(".{release_id}.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    copy_tree(&staged, &tmp, &bin)?;
    std::fs::rename(&tmp, &target).map_err(|e| {
        let _ = std::fs::remove_dir_all(&tmp);
        format!("could not move release {release_id} into place: {e}")
    })?;
    // Refused here, before the key or a secret is asked for: a release
    // that cannot have its health port is not kept.
    let refused = match checked(dir, release_id) {
        Ok((_, _, launch)) => port_clash(dir, &launch, &runs),
        Err(e) => Some(e),
    };
    if let Some(why) = refused {
        let _ = std::fs::remove_dir_all(&target);
        return Err(why);
    }
    let _ = std::fs::remove_dir_all(&staged);
    // The worker's upload directory too, once nothing else is staged in it.
    let _ = std::fs::remove_dir(uploads.join(id));
    Ok(json!({ "ok": true, "release": release_id, "installed": true }))
}

/// `remove`: the worker stopped and gone: its unit, its releases, its
/// state, its WAF, and anything staged for it.
fn remove(id: &str, dir: &Path) -> Result<Value, String> {
    // Asked first, so that a firewall change another worker has waiting
    // refuses the removal with the worker still as it was.
    let held = crate::firewall::hold()?;
    let unit = server::unit_name(id);
    let unit_path = PathBuf::from("/etc/systemd/system").join(&unit);
    if unit_path.exists() {
        let _ = systemctl(&["disable", "--now", "--quiet", &unit]);
        // The dynamic user's state directory goes with the unit.
        let _ = systemctl(&["clean", "--what=state", "--what=runtime", &unit]);
        std::fs::remove_file(&unit_path)
            .map_err(|e| format!("could not remove {}: {e}", unit_path.display()))?;
        systemctl(&["daemon-reload"])?;
    }
    if dir.exists() {
        std::fs::remove_dir_all(dir)
            .map_err(|e| format!("could not remove {}: {e}", dir.display()))?;
    }
    let _ = std::fs::remove_dir_all(PathBuf::from(UPLOADS).join(id));
    // Its WAF goes too, which would only answer 502 from now on. A failure
    // is said, and does not keep the port open: that is closed below.
    let waf = wafctl::remove(&wafctl::Host::server(), id).err();
    // Its backup timer goes too, which would only fail from now on; the
    // snapshots in the repository stay. A failure here is said, and does
    // not keep the port open.
    let backup = crate::backup::remove(id).err();
    // Its opening goes too; closing a port cannot lock anyone out, so the
    // table is replaced at once.
    let firewall = crate::firewall::close(id, &held)?;
    Ok(json!({
        "ok": true,
        "removed": id,
        "firewall": firewall,
        "backup_error": backup,
        "waf_error": waf,
    }))
}

/// `status`: the agent's, with the releases on disk, and the worker's WAF
/// (null when it has none).
fn status(id: &str, dir: &Path, socket: &Path) -> Result<Value, String> {
    let agent = agent_status(socket);
    Ok(json!({
        "ok": agent.is_ok(),
        "agent": agent.as_ref().ok(),
        "error": agent.as_ref().err(),
        "current": pointed(dir, "current"),
        "previous": pointed(dir, "previous"),
        "releases": release_ids(dir)?.len(),
        "waf": wafctl::status(&wafctl::Host::server(), id),
    }))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use erpc_worker::release::{FILE_NAME, Release, Shipped};
    use erpc_worker::server::{self, Health, LAUNCH_FILE, Launch, Reply, Status};
    use serde_json::Value;
    use sha2::{Digest as _, Sha256};

    use super::{Asked, Host};

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        Sha256::digest(bytes)
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    /// A launch file whose app is probed on `port`, or not probed.
    fn launch_on(port: Option<u16>) -> Launch {
        Launch {
            format: server::LAUNCH_FORMAT,
            bin: "bot".to_owned(),
            args: Vec::new(),
            vars: std::collections::BTreeMap::new(),
            secrets: Vec::new(),
            pubkey: None,
            health: Health {
                http: port.map(|p| format!("http://127.0.0.1:{p}/healthz")),
                timeout_secs: 1,
            },
            keep_releases: 2,
        }
    }

    /// Another worker under `workers`, whose release in use is probed on
    /// `port`.
    fn neighbour(workers: &Path, name: &str, port: Option<u16>) {
        let dir = workers.join(name).join("current");
        std::fs::create_dir_all(&dir).expect("dir");
        let launch = serde_json::to_vec(&launch_on(port)).expect("json");
        std::fs::write(dir.join(LAUNCH_FILE), launch).expect("launch");
    }

    /// Every neighbour is kept running, or none is: what `wanted_running`
    /// tells `install`, `activate` and `rollback` on a server.
    fn running(_: &str) -> bool {
        true
    }
    fn stopped(_: &str) -> bool {
        false
    }

    /// Stages release `id` in `uploads/<worker>/<id>`, as erpc uploads one.
    fn stage(uploads: &Path, id: &str) {
        stage_on(uploads, id, None);
    }

    /// [`stage`], for a release probed on `port`.
    fn stage_on(uploads: &Path, id: &str, port: Option<u16>) {
        let dir = uploads.join("bot-default").join(id);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("bot"), b"the binary").expect("bin");
        std::fs::write(dir.join("config.jsonc"), b"{}").expect("file");
        let release = Release {
            format: erpc_worker::release::FORMAT,
            id: id.to_owned(),
            app: "bot".to_owned(),
            bin: "bot".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            glibc: None,
            sha256: hex(b"the binary"),
            size: 10,
            built_at: "2026-10-29T12:00:00Z".to_owned(),
            source: None,
            manifest_sha256: hex(b"erpc.toml"),
            files: vec![Shipped {
                path: "config.jsonc".to_owned(),
                sha256: hex(b"{}"),
            }],
            erpc_version: "0.0.1".to_owned(),
        };
        std::fs::write(
            dir.join(FILE_NAME),
            serde_json::to_vec(&release).expect("json"),
        )
        .expect("release");
        std::fs::write(
            dir.join(LAUNCH_FILE),
            serde_json::to_vec(&launch_on(port)).expect("json"),
        )
        .expect("launch");
    }

    #[test]
    fn the_needrestart_rule_is_written_once_and_put_back_when_changed() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("needrestart/conf.d/50-erpc-worker.conf");
        super::keep_from_needrestart(&path).expect("written");
        let wanted = erpc_worker::server::needrestart_conf();
        assert_eq!(std::fs::read_to_string(&path).expect("read"), wanted);
        // Left as it is when it is right, and put back when it is not.
        let before = std::fs::metadata(&path)
            .expect("meta")
            .modified()
            .expect("time");
        super::keep_from_needrestart(&path).expect("kept");
        let after = std::fs::metadata(&path)
            .expect("meta")
            .modified()
            .expect("time");
        assert_eq!(before, after, "not rewritten");
        std::fs::write(&path, "# emptied\n").expect("write");
        super::keep_from_needrestart(&path).expect("restored");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), wanted);
    }

    /// The child's side of the mode test: writes the rule where
    /// `ERPC_TEST_NEEDRESTART` says. Without it, it does nothing, which is
    /// how it runs among the other tests.
    #[test]
    fn needrestart_child() {
        let Some(path) = std::env::var_os("ERPC_TEST_NEEDRESTART") else {
            return;
        };
        super::keep_from_needrestart(Path::new(&path)).expect("written");
    }

    #[test]
    fn the_needrestart_rule_and_its_directory_are_readable_whatever_the_umask() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("needrestart/conf.d/50-erpc-worker.conf");
        // The umask is the whole process's, and the other tests write
        // files meanwhile: the rule is written by this test binary run
        // again, under a umask that leaves a new file or directory to its
        // owner alone.
        let status = std::process::Command::new("sh")
            .args(["-c", "umask 077 && exec \"$@\"", "sh"])
            .arg(std::env::current_exe().expect("this test binary"))
            .args(["--exact", "ctl::tests::needrestart_child", "--nocapture"])
            .env("ERPC_TEST_NEEDRESTART", &path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("the child");
        assert!(status.success(), "the child failed: {status}");
        let mode = |path: &Path| {
            let meta = std::fs::metadata(path).expect("there");
            meta.permissions().mode() & 0o7777
        };
        assert_eq!(mode(&path), 0o644);
        assert_eq!(mode(&tmp.path().join("needrestart/conf.d")), 0o755);
        assert_eq!(mode(&tmp.path().join("needrestart")), 0o755);
    }

    #[test]
    fn setup_tells_needrestart_before_it_touches_the_unit() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("workers/bot-default");
        let units = tmp.path().join("systemd");
        let rule = tmp.path().join("needrestart/conf.d/50-erpc-worker.conf");
        let socket = tmp.path().join("agent.sock");
        agent_saying(&socket, || status("stopped"));
        // What systemd was asked, and whether the rule was there by then.
        // The unit is not active, so it is started.
        let asked = std::cell::RefCell::new(Vec::new());
        let systemctl = |args: &[&str]| {
            asked.borrow_mut().push((args.join(" "), rule.exists()));
            if args.first() == Some(&"is-active") {
                Err("inactive".to_owned())
            } else {
                Ok(String::new())
            }
        };
        let host = Host {
            units: &units,
            needrestart: &rule,
            systemctl: &systemctl,
        };
        let setup =
            |host: &Host<'_>| super::setup("bot-default", &dir, &socket, Asked::IfChanged, host);

        // Nowhere to write the unit: the setup ends there, and the rule
        // is written already.
        let failed = setup(&host).expect_err("no unit");
        assert!(failed.contains("could not write"), "{failed}");
        assert_eq!(
            std::fs::read_to_string(&rule).expect("the rule"),
            server::needrestart_conf()
        );
        assert!(asked.borrow().is_empty(), "{asked:?}");

        // With it, the unit is written and its agent started, the rule
        // there before systemd is asked for anything.
        std::fs::remove_file(&rule).expect("removed");
        std::fs::create_dir(&units).expect("units");
        let answer = setup(&host).expect("set up");
        assert_eq!(answer["agent"], "started", "{answer}");
        assert_eq!(answer["unit"], "written", "{answer}");
        assert_eq!(answer["needrestart_error"], Value::Null, "{answer}");
        let unit = server::unit_name("bot-default");
        assert_eq!(
            std::fs::read_to_string(units.join(&unit)).expect("the unit"),
            server::unit("bot-default")
        );
        assert_eq!(
            *asked.borrow(),
            [
                ("daemon-reload".to_owned(), true),
                (format!("enable --quiet {unit}"), true),
                (format!("is-active {unit}"), true),
                (format!("start {unit}"), true),
            ]
        );

        // A rule that cannot be written is said, and stops nothing.
        let file = tmp.path().join("file");
        std::fs::write(&file, "").expect("a file");
        let under_a_file = file.join("conf.d/50-erpc-worker.conf");
        let answer = setup(&Host {
            needrestart: &under_a_file,
            ..host
        })
        .expect("set up all the same");
        let said = answer["needrestart_error"].as_str().expect("said");
        assert!(said.starts_with("could not write "), "{said}");
        assert_eq!(answer["unit"], "unchanged", "{answer}");
    }

    #[test]
    fn a_wanted_file_that_is_not_the_agents_counts_as_kept_running() {
        use rustix::fs::{CWD, Mode, mkfifoat};
        let tmp = tempfile::tempdir().expect("tmp");
        let wanted = tmp.path().join("wanted");
        // As the agent writes it, and before it was ever asked to run.
        assert!(!super::kept_running(&wanted), "never asked to run");
        std::fs::write(&wanted, "1\n").expect("write");
        assert!(super::kept_running(&wanted));
        std::fs::write(&wanted, "0\n").expect("write");
        assert!(!super::kept_running(&wanted));

        // What the worker's app can put there instead. Each would say
        // "stopped" to a reader that trusted it, or hold it; none is
        // followed, waited for or read past what the agent writes, and
        // each counts as kept running.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, "0\n").expect("write");
        std::fs::remove_file(&wanted).expect("removed");
        std::os::unix::fs::symlink(&elsewhere, &wanted).expect("link");
        assert!(super::kept_running(&wanted), "a link is not followed");

        // A FIFO nobody writes to: an open that waited would not return.
        std::fs::remove_file(&wanted).expect("removed");
        mkfifoat(CWD, &wanted, Mode::RUSR | Mode::WUSR).expect("fifo");
        let (tx, rx) = std::sync::mpsc::channel();
        let fifo = wanted.clone();
        std::thread::spawn(move || tx.send(super::kept_running(&fifo)));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).ok(),
            Some(true),
            "a FIFO is not waited for"
        );

        std::fs::remove_file(&wanted).expect("removed");
        std::fs::write(&wanted, format!("0{}", "\n".repeat(4096))).expect("write");
        assert!(super::kept_running(&wanted), "more than the agent writes");
        std::fs::write(&wanted, "no\n").expect("write");
        assert!(super::kept_running(&wanted), "other words");
        std::fs::remove_file(&wanted).expect("removed");
        std::fs::create_dir(&wanted).expect("dir");
        assert!(super::kept_running(&wanted), "a directory");
    }

    #[test]
    fn a_release_on_a_running_neighbours_port_is_refused_by_name() {
        let tmp = tempfile::tempdir().expect("tmp");
        // A worker's release in use, as `current` points at it.
        let put = |worker: &str, port: Option<u16>| neighbour(tmp.path(), worker, port);
        put("api-default", Some(3000));
        put("quiet-default", None);
        // This worker's own earlier release is no neighbour.
        put("bot-default", Some(3005));
        let ours = tmp.path().join("bot-default");
        let clash = |port, runs: bool| super::port_clash(&ours, &launch_on(port), |_| runs);

        let refused = clash(Some(3000), true).expect("refused");
        assert_eq!(erpc_worker::server::taken_port(&refused), Some(3000));
        assert!(refused.contains("api-default"), "{refused}");
        // A neighbour that was stopped does not hold its port.
        assert_eq!(clash(Some(3000), false), None);
        assert_eq!(clash(Some(3001), true), None);
        assert_eq!(clash(Some(3005), true), None);
        // Without a health URL there is no port to compare.
        assert_eq!(clash(None, true), None);
    }

    const ONE: &str = "20261029T120000Z-1a2b3c4d";
    const TWO: &str = "20261029T130000Z-1a2b3c4d";
    const THREE: &str = "20261029T140000Z-1a2b3c4d";

    #[test]
    fn an_agent_that_runs_is_kept_when_asked_and_restarted_only_when_due() {
        use super::AgentNext::{self, Keep, Leave, Restart, Start};
        use super::Asked;
        // (active, restart asked, changed, keep asked): every row. Changed
        // is the unit's text, or the agent installed since this one
        // started.
        let rows = [
            // Not running: started, whatever else. It comes up locked, and
            // there is nothing to lose.
            (false, false, false, false, Start),
            (false, false, false, true, Start),
            (false, false, true, false, Start),
            (false, false, true, true, Start),
            (false, true, false, false, Start),
            (false, true, false, true, Start),
            (false, true, true, false, Start),
            (false, true, true, true, Start),
            // Running, and not asked to be kept: restarted when asked or
            // when what it runs from changed, else left.
            (true, false, false, false, Leave),
            (true, false, true, false, Restart),
            (true, true, false, false, Restart),
            (true, true, true, false, Restart),
            // Running, and asked to be kept: kept, whatever changed. The
            // two flags are not given together; keeping would win.
            (true, false, false, true, Keep),
            (true, false, true, true, Keep),
            (true, true, false, true, Keep),
            (true, true, true, true, Keep),
        ];
        for (active, restart, changed, keep, next) in rows {
            assert_eq!(
                AgentNext::of(active, Asked::from_flags(restart, keep), changed),
                next,
                "active {active}, restart {restart}, changed {changed}, keep {keep}"
            );
        }
        assert_eq!(
            [Start, Restart, Leave, Keep].map(AgentNext::as_str),
            ["started", "restarted", "running", "kept"]
        );
    }

    #[test]
    fn a_replaced_binary_is_another_file_than_the_one_that_runs() {
        let tmp = tempfile::tempdir().expect("tmp");
        let installed = tmp.path().join("agent");
        std::fs::write(&installed, b"the agent").expect("write");
        // What runs is what is installed, by this name or another.
        let running = tmp.path().join("running");
        std::fs::hard_link(&installed, &running).expect("link");
        assert_eq!(super::differ(&running, &installed), Some(false));
        // Installed again, as `install` does: a new file under the name,
        // and the one that runs is the old one.
        std::fs::remove_file(&installed).expect("remove");
        std::fs::write(&installed, b"the agent").expect("write");
        assert_eq!(super::differ(&running, &installed), Some(true));
        // What cannot be read says nothing, and restarts nothing.
        assert_eq!(super::differ(&tmp.path().join("gone"), &installed), None);
        assert_eq!(
            super::differ(Path::new("/proc/self/exe"), Path::new("/proc/self/exe")),
            Some(false)
        );

        // A unit's main process, as /proc has it: the file it runs,
        // against the one installed.
        let proc = tmp.path().join("proc");
        std::fs::create_dir_all(proc.join("4242")).expect("proc");
        std::fs::hard_link(&running, proc.join("4242/exe")).expect("link");
        assert_eq!(
            super::runs_installed(&proc, 4242, &installed),
            Some(false),
            "it runs the file from before"
        );
        assert_eq!(super::runs_installed(&proc, 4242, &running), Some(true));
        // No such process, and no main process at all.
        assert_eq!(super::runs_installed(&proc, 4243, &installed), None);
        assert_eq!(super::runs_installed(&proc, 0, &installed), None);
        // This process runs the file it runs from.
        assert_eq!(
            super::runs_installed(
                Path::new("/proc"),
                std::process::id(),
                Path::new(super::INSTALLED)
            ),
            Some(true)
        );
    }

    #[test]
    fn an_agent_is_another_only_where_its_unit_is_seen_to_run_another_file() {
        use std::cell::RefCell;
        // What systemd says the unit's main process is.
        let asked = RefCell::new(Vec::new());
        let another = |pid: Result<String, String>| {
            super::runs_another_agent("erpc-worker-bot-default.service", &|args: &[&str]| {
                asked.borrow_mut().push(args.join(" "));
                pid.clone()
            })
        };
        // This process: the file `ctl` runs from is the one it runs.
        assert!(!another(Ok(format!("{}\n", std::process::id()))));
        assert_eq!(
            asked.borrow().as_slice(),
            ["show --property=MainPID --value erpc-worker-bot-default.service"]
        );
        // A process of another program: another file than the agent.
        let mut other = std::process::Command::new("sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("another program");
        let pid = other.id().to_string();
        assert!(another(Ok(pid.clone())), "it runs another file");
        other.kill().expect("ended");
        other.wait().expect("gone");
        // What cannot be told is not "another": a process that is gone,
        // no main process, a systemd that does not answer or says
        // something that is no process.
        for untold in [
            Ok(pid),
            Ok("0".to_owned()),
            Ok(String::new()),
            Ok("n/a".to_owned()),
            Err("Failed to connect to bus".to_owned()),
        ] {
            assert!(!another(untold.clone()), "{untold:?}");
        }
    }

    #[test]
    fn a_release_whose_digests_match_is_installed_and_a_tampered_one_is_not_kept() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (dir, uploads) = (tmp.path().join("worker"), tmp.path().join("uploads"));
        stage(&uploads, ONE);
        let answer = super::install("bot-default", &dir, &uploads, ONE, running).expect("installs");
        assert_eq!(answer["installed"], true);
        assert!(dir.join("releases").join(ONE).join("bot").is_file());
        assert!(
            !uploads.join("bot-default").exists(),
            "the upload is cleared"
        );

        // The binary changed on the way: refused, and nothing is kept.
        stage(&uploads, TWO);
        std::fs::write(
            uploads.join("bot-default").join(TWO).join("bot"),
            b"another",
        )
        .expect("tamper");
        let refused =
            super::install("bot-default", &dir, &uploads, TWO, running).expect_err("refused");
        assert!(refused.contains("not the one that was built"), "{refused}");
        assert!(!dir.join("releases").join(TWO).exists());

        // A shipped file changed: refused the same way.
        stage(&uploads, THREE);
        std::fs::write(
            uploads.join("bot-default").join(THREE).join("config.jsonc"),
            b"{\"x\":1}",
        )
        .expect("tamper");
        let refused =
            super::install("bot-default", &dir, &uploads, THREE, running).expect_err("refused");
        assert!(refused.contains("config.jsonc"), "{refused}");
        assert!(!dir.join("releases").join(THREE).exists());
    }

    #[test]
    fn a_release_changed_after_it_was_installed_is_not_activated() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (dir, uploads) = (tmp.path().join("worker"), tmp.path().join("uploads"));
        stage(&uploads, ONE);
        super::install("bot-default", &dir, &uploads, ONE, running).expect("installs");
        std::fs::write(dir.join("releases").join(ONE).join("bot"), b"changed").expect("tamper");
        assert!(super::checked(&dir, ONE).is_err());
        assert!(
            super::checked(&dir, "../../etc").is_err(),
            "not a release id"
        );
    }

    #[test]
    fn pruning_never_removes_current_or_previous() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path();
        for id in [ONE, TWO, THREE] {
            std::fs::create_dir_all(dir.join("releases").join(id)).expect("dir");
        }
        // The two oldest are the live ones: neither goes, though only one
        // release is to be kept.
        super::point(dir, "current", ONE).expect("current");
        super::point(dir, "previous", TWO).expect("previous");
        let removed = super::prune(dir, 1).expect("prunes");
        assert!(removed.is_empty(), "{removed:?}");
        super::point(dir, "current", THREE).expect("current");
        let removed = super::prune(dir, 1).expect("prunes");
        assert_eq!(removed, [ONE]);
        assert_eq!(super::release_ids(dir).expect("ids"), [TWO, THREE]);
    }

    /// A status in `state`, with no app running.
    fn status(state: &str) -> Status {
        Status {
            state: state.to_owned(),
            healthy: false,
            wanted: true,
            key_held: true,
            secrets_held: Vec::new(),
            release: None,
            pid: None,
            up_secs: None,
            restarts: 0,
            last_exit: None,
            reason: None,
        }
    }

    /// A stand-in agent on `socket`: every request is answered with the
    /// status `status` gives then.
    fn agent_saying(socket: &Path, status: impl Fn() -> Status + Send + 'static) {
        let listener = UnixListener::bind(socket).expect("bind");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_err() {
                    continue;
                }
                let reply = Reply {
                    ok: true,
                    error: None,
                    status: Some(status()),
                };
                let _ = writeln!(stream, "{}", serde_json::to_string(&reply).expect("json"));
            }
        });
    }

    /// An agent on `socket` whose app never comes up healthy on `bad`, and
    /// is healthy on any other release `current` points at.
    fn fake_agent(socket: &Path, dir: &Path, bad: &'static str) {
        let dir = dir.to_owned();
        agent_saying(socket, move || {
            let release = super::pointed(&dir, "current");
            Status {
                healthy: release.as_deref() != Some(bad),
                release,
                pid: Some(1),
                up_secs: Some(1),
                ..status("running")
            }
        });
    }

    #[test]
    fn a_start_the_agent_refused_ends_the_health_wait_at_once() {
        let tmp = tempfile::tempdir().expect("tmp");
        let socket = tmp.path().join("agent.sock");
        let refused = server::port_taken(3000, None);
        let reason = std::sync::Arc::new(std::sync::Mutex::new(Some(refused.clone())));
        let said = std::sync::Arc::clone(&reason);
        agent_saying(&socket, move || Status {
            reason: said.lock().expect("reason").clone(),
            ..status("waiting")
        });
        // The agent's own words, long before the timeout: it tries again
        // only every minute, and the port is no freer then.
        let asked = Instant::now();
        let why = super::healthy(&socket, ONE, Duration::from_secs(10)).expect_err("refused");
        assert_eq!(why, refused);
        assert!(asked.elapsed() < Duration::from_secs(5), "not at once");
        // An app that ended and waits to be started again gives no reason:
        // that one is waited for.
        *reason.lock().expect("reason") = None;
        let why = super::healthy(&socket, ONE, Duration::from_secs(1)).expect_err("not healthy");
        assert!(why.contains("was not healthy within 1s"), "{why}");
    }

    /// A worker under `tmp` with `ONE` (probed on 3000) as `previous`,
    /// `TWO` (on 3001) as `current`, and `THREE` (on 3000) installed, all
    /// while its neighbour `api-default`, on 3000, was stopped.
    fn beside_a_neighbour_on_3000(tmp: &Path) -> std::path::PathBuf {
        let workers = tmp.join("workers");
        let (dir, uploads) = (workers.join("bot-default"), tmp.join("uploads"));
        neighbour(&workers, "api-default", Some(3000));
        for (id, port) in [(ONE, 3000), (TWO, 3001), (THREE, 3000)] {
            stage_on(&uploads, id, Some(port));
            super::install("bot-default", &dir, &uploads, id, stopped).expect("installs");
        }
        super::point(&dir, "current", TWO).expect("current");
        super::point(&dir, "previous", ONE).expect("previous");
        dir
    }

    #[test]
    fn a_release_on_a_running_neighbours_health_port_is_not_installed() {
        let tmp = tempfile::tempdir().expect("tmp");
        let workers = tmp.path().join("workers");
        let (dir, uploads) = (workers.join("bot-default"), tmp.path().join("uploads"));
        let installed = dir.join("releases").join(ONE);
        neighbour(&workers, "api-default", Some(3000));
        stage_on(&uploads, ONE, Some(3000));
        let taken = server::port_taken(3000, Some("api-default"));

        // Refused by the neighbour's name, and the release is not kept.
        let refused =
            super::install("bot-default", &dir, &uploads, ONE, running).expect_err("refused");
        assert_eq!(refused, taken);
        assert!(!installed.exists(), "the release is not kept");

        // A neighbour that was stopped holds no port: installed.
        let answer = super::install("bot-default", &dir, &uploads, ONE, stopped).expect("installs");
        assert_eq!(answer["installed"], true);
        assert!(installed.join("bot").is_file());

        // Installed by a deploy that went no further, and the neighbour
        // runs again since: the next deploy is refused the same way.
        let refused =
            super::install("bot-default", &dir, &uploads, ONE, running).expect_err("refused");
        assert_eq!(refused, taken);
        let answer = super::install("bot-default", &dir, &uploads, ONE, stopped).expect("there");
        assert_eq!(answer["installed"], false);

        // An app without a health URL has no port to compare.
        stage_on(&uploads, TWO, None);
        super::install("bot-default", &dir, &uploads, TWO, running).expect("installs");
    }

    #[test]
    fn a_release_on_a_running_neighbours_health_port_is_not_activated() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = beside_a_neighbour_on_3000(tmp.path());
        // Nothing listens here yet: an agent asked to restart would fail
        // the call, so the refusal comes before anything is asked of it.
        let socket = tmp.path().join("agent.sock");
        let links = || {
            (
                super::pointed(&dir, "current"),
                super::pointed(&dir, "previous"),
            )
        };
        let as_it_was = (Some(TWO.to_owned()), Some(ONE.to_owned()));

        let answer = super::activate(&dir, &socket, THREE, running).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");
        assert_eq!(answer["unchanged"], true, "{answer}");
        assert_eq!(
            answer["error"],
            server::port_taken(3000, Some("api-default")),
            "{answer}"
        );
        assert_eq!(links(), as_it_was);

        // A neighbour that was stopped refuses nothing.
        fake_agent(&socket, &dir, ONE);
        let answer = super::activate(&dir, &socket, THREE, stopped).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(links(), (Some(THREE.to_owned()), Some(TWO.to_owned())));
    }

    #[test]
    fn a_rollback_onto_a_running_neighbours_health_port_is_refused() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = beside_a_neighbour_on_3000(tmp.path());
        let socket = tmp.path().join("agent.sock");
        let links = || {
            (
                super::pointed(&dir, "current"),
                super::pointed(&dir, "previous"),
            )
        };
        let as_it_was = (Some(TWO.to_owned()), Some(ONE.to_owned()));

        // To the previous release, and to one named: the neighbour was
        // given the port they are probed on since they ran.
        for to in [None, Some(THREE)] {
            let answer = super::rollback(&dir, &socket, to, running).expect("answers");
            assert_eq!(answer["ok"], false, "{answer}");
            assert_eq!(answer["unchanged"], true, "{answer}");
            assert_eq!(
                answer["error"],
                server::port_taken(3000, Some("api-default")),
                "{answer}"
            );
            assert_eq!(links(), as_it_was);
        }

        // A neighbour that was stopped refuses nothing.
        fake_agent(&socket, &dir, THREE);
        let answer = super::rollback(&dir, &socket, None, stopped).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(links(), (Some(ONE.to_owned()), Some(TWO.to_owned())));
    }

    #[test]
    fn an_unhealthy_release_puts_both_links_back() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (dir, uploads) = (tmp.path().join("worker"), tmp.path().join("uploads"));
        for id in [ONE, TWO, THREE] {
            stage(&uploads, id);
            super::install("bot-default", &dir, &uploads, id, running).expect("installs");
        }
        super::point(&dir, "current", TWO).expect("current");
        super::point(&dir, "previous", ONE).expect("previous");
        let socket = tmp.path().join("agent.sock");
        fake_agent(&socket, &dir, THREE);
        let answer = super::activate(&dir, &socket, THREE, running).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");
        assert_eq!(answer["rolled_back"], true, "{answer}");
        assert_eq!(answer["running"], TWO, "{answer}");
        assert_eq!(super::pointed(&dir, "current").as_deref(), Some(TWO));
        assert_eq!(super::pointed(&dir, "previous").as_deref(), Some(ONE));
    }

    #[test]
    fn a_healthy_release_becomes_current_and_the_old_one_previous() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (dir, uploads) = (tmp.path().join("worker"), tmp.path().join("uploads"));
        for id in [ONE, TWO] {
            stage(&uploads, id);
            super::install("bot-default", &dir, &uploads, id, running).expect("installs");
        }
        super::point(&dir, "current", ONE).expect("current");
        let socket = tmp.path().join("agent.sock");
        fake_agent(&socket, &dir, THREE);
        let answer = super::activate(&dir, &socket, TWO, running).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(super::pointed(&dir, "current").as_deref(), Some(TWO));
        assert_eq!(super::pointed(&dir, "previous").as_deref(), Some(ONE));
    }
}
