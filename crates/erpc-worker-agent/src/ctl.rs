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
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use erpc_worker::release::{self, Release};
use erpc_worker::server::{self, Launch, Reply, Status};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::Verb;

/// The biggest unlock read from standard input.
const MAX_UNLOCK: u64 = 256 * 1024;
/// What the health wait adds to the release's own timeout, for the app's
/// own start.
const SLACK: Duration = Duration::from_secs(5);

/// Where erpc stages a release's files before `install` moves them in.
const UPLOADS: &str = "/opt/erpc/uploads";

/// Runs one verb and prints its JSON answer.
pub(crate) fn run(id: &str, dir: &Path, socket: &Path, verb: &Verb) -> ExitCode {
    let answer = match verb {
        Verb::Setup { restart_agent } => setup(id, dir, socket, *restart_agent),
        Verb::Install { release } => locked(dir, || install(id, dir, Path::new(UPLOADS), release)),
        Verb::Remove => remove(id, dir),
        Verb::FirewallApply => crate::firewall::apply(id),
        Verb::FirewallConfirm => crate::firewall::confirm(),
        Verb::FirewallShow => crate::firewall::show(),
        Verb::Status => status(dir, socket),
        Verb::Unlock => unlock(socket),
        Verb::Lock => forward(socket, r#"{"op":"lock"}"#),
        Verb::Start => forward(socket, r#"{"op":"start"}"#),
        Verb::Stop => forward(socket, r#"{"op":"stop"}"#),
        Verb::Restart => forward(socket, r#"{"op":"restart"}"#),
        Verb::Activate { release } => locked(dir, || activate(dir, socket, release)),
        Verb::Rollback { to } => locked(dir, || rollback(dir, socket, to.as_deref())),
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

fn activate(dir: &Path, socket: &Path, id: &str) -> Result<Value, String> {
    let (_, _, launch) = checked(dir, id)?;
    let before = pointed(dir, "current");
    let before_previous = pointed(dir, "previous");
    if before.as_deref() == Some(id) {
        return Ok(json!({ "ok": true, "release": id, "changed": false }));
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

fn rollback(dir: &Path, socket: &Path, to: Option<&str>) -> Result<Value, String> {
    let current = pointed(dir, "current");
    let target = match to {
        Some(id) => id.to_owned(),
        None => pointed(dir, "previous").ok_or("there is no previous release to go back to")?,
    };
    if current.as_deref() == Some(target.as_str()) {
        return Ok(json!({ "ok": true, "release": target, "changed": false }));
    }
    let (_, _, launch) = checked(dir, &target)?;
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

/// `setup`: the worker's directory and unit, written when they differ, and
/// its agent running. `restart_agent` restarts a running agent, whose
/// binary was just replaced; it comes back locked.
fn setup(id: &str, dir: &Path, socket: &Path, restart_agent: bool) -> Result<Value, String> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir.join("releases"))
        .map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    for d in [dir.to_owned(), dir.join("releases")] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("could not set {}'s mode: {e}", d.display()))?;
    }
    let unit_path = PathBuf::from("/etc/systemd/system").join(server::unit_name(id));
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
    let agent = if !active {
        systemctl(&["start", &unit])?;
        "started"
    } else if restart_agent || written {
        systemctl(&["restart", &unit])?;
        "restarted"
    } else {
        "running"
    };
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
    Ok(json!({ "ok": true, "unit": if written { "written" } else { "unchanged" }, "agent": agent }))
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
/// and checked against its digests; nothing is kept when a digest differs.
fn install(id: &str, dir: &Path, uploads: &Path, release_id: &str) -> Result<Value, String> {
    if !release::is_id(release_id) {
        return Err(format!("`{release_id}` is not a release id"));
    }
    let staged = uploads.join(id).join(release_id);
    let target = dir.join("releases").join(release_id);
    if target.exists() {
        // Installed by an earlier deploy that went no further.
        checked(dir, release_id)?;
        let _ = std::fs::remove_dir_all(&staged);
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
    if let Err(e) = checked(dir, release_id) {
        let _ = std::fs::remove_dir_all(&target);
        return Err(e);
    }
    let _ = std::fs::remove_dir_all(&staged);
    // The worker's upload directory too, once nothing else is staged in it.
    let _ = std::fs::remove_dir(uploads.join(id));
    Ok(json!({ "ok": true, "release": release_id, "installed": true }))
}

/// `remove`: the worker stopped and gone: its unit, its releases, its
/// state, and anything staged for it.
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
    // Its backup timer goes too, which would only fail from now on; the
    // snapshots in the repository stay. A failure here is said, and does
    // not keep the port open.
    let backup = crate::backup::remove(id).err();
    // Its opening goes too; closing a port cannot lock anyone out, so the
    // table is replaced at once.
    let firewall = crate::firewall::close(id, &held)?;
    Ok(json!({ "ok": true, "removed": id, "firewall": firewall, "backup_error": backup }))
}

/// `status`: the agent's, with the releases on disk.
fn status(dir: &Path, socket: &Path) -> Result<Value, String> {
    let agent = agent_status(socket);
    Ok(json!({
        "ok": agent.is_ok(),
        "agent": agent.as_ref().ok(),
        "error": agent.as_ref().err(),
        "current": pointed(dir, "current"),
        "previous": pointed(dir, "previous"),
        "releases": release_ids(dir)?.len(),
    }))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use erpc_worker::release::{FILE_NAME, Release, Shipped};
    use erpc_worker::server::{Health, LAUNCH_FILE, Launch, Reply, Status};
    use sha2::{Digest as _, Sha256};

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        Sha256::digest(bytes)
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    /// Stages release `id` in `uploads/<worker>/<id>`, as erpc uploads one.
    fn stage(uploads: &Path, id: &str) {
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
        let launch = Launch {
            format: erpc_worker::server::LAUNCH_FORMAT,
            bin: "bot".to_owned(),
            args: Vec::new(),
            vars: std::collections::BTreeMap::new(),
            secrets: Vec::new(),
            pubkey: None,
            health: Health {
                http: None,
                timeout_secs: 1,
            },
            keep_releases: 2,
        };
        std::fs::write(
            dir.join(LAUNCH_FILE),
            serde_json::to_vec(&launch).expect("json"),
        )
        .expect("launch");
    }

    const ONE: &str = "20261029T120000Z-1a2b3c4d";
    const TWO: &str = "20261029T130000Z-1a2b3c4d";
    const THREE: &str = "20261029T140000Z-1a2b3c4d";

    #[test]
    fn a_release_whose_digests_match_is_installed_and_a_tampered_one_is_not_kept() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (dir, uploads) = (tmp.path().join("worker"), tmp.path().join("uploads"));
        stage(&uploads, ONE);
        let answer = super::install("bot-default", &dir, &uploads, ONE).expect("installs");
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
        let refused = super::install("bot-default", &dir, &uploads, TWO).expect_err("refused");
        assert!(refused.contains("not the one that was built"), "{refused}");
        assert!(!dir.join("releases").join(TWO).exists());

        // A shipped file changed: refused the same way.
        stage(&uploads, THREE);
        std::fs::write(
            uploads.join("bot-default").join(THREE).join("config.jsonc"),
            b"{\"x\":1}",
        )
        .expect("tamper");
        let refused = super::install("bot-default", &dir, &uploads, THREE).expect_err("refused");
        assert!(refused.contains("config.jsonc"), "{refused}");
        assert!(!dir.join("releases").join(THREE).exists());
    }

    #[test]
    fn a_release_changed_after_it_was_installed_is_not_activated() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (dir, uploads) = (tmp.path().join("worker"), tmp.path().join("uploads"));
        stage(&uploads, ONE);
        super::install("bot-default", &dir, &uploads, ONE).expect("installs");
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

    /// An agent on `socket` whose app never comes up healthy on `bad`, and
    /// is healthy on any other release `current` points at.
    fn fake_agent(socket: &Path, dir: &Path, bad: &'static str) {
        let listener = UnixListener::bind(socket).expect("bind");
        let dir = dir.to_owned();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_err() {
                    continue;
                }
                let release = super::pointed(&dir, "current");
                let status = Status {
                    state: "running".to_owned(),
                    healthy: release.as_deref() != Some(bad),
                    wanted: true,
                    key_held: true,
                    secrets_held: Vec::new(),
                    release,
                    pid: Some(1),
                    up_secs: Some(1),
                    restarts: 0,
                    last_exit: None,
                    reason: None,
                };
                let reply = Reply {
                    ok: true,
                    error: None,
                    status: Some(status),
                };
                let _ = writeln!(stream, "{}", serde_json::to_string(&reply).expect("json"));
            }
        });
    }

    #[test]
    fn an_unhealthy_release_puts_both_links_back() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (dir, uploads) = (tmp.path().join("worker"), tmp.path().join("uploads"));
        for id in [ONE, TWO, THREE] {
            stage(&uploads, id);
            super::install("bot-default", &dir, &uploads, id).expect("installs");
        }
        super::point(&dir, "current", TWO).expect("current");
        super::point(&dir, "previous", ONE).expect("previous");
        let socket = tmp.path().join("agent.sock");
        fake_agent(&socket, &dir, THREE);
        let answer = super::activate(&dir, &socket, THREE).expect("answers");
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
            super::install("bot-default", &dir, &uploads, id).expect("installs");
        }
        super::point(&dir, "current", ONE).expect("current");
        let socket = tmp.path().join("agent.sock");
        fake_agent(&socket, &dir, THREE);
        let answer = super::activate(&dir, &socket, TWO).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(super::pointed(&dir, "current").as_deref(), Some(TWO));
        assert_eq!(super::pointed(&dir, "previous").as_deref(), Some(ONE));
    }
}
