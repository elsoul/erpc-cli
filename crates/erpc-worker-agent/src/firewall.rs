// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The server's worker firewall, as `ctl` changes it (run as root).
//!
//! One table for the server, `inet erpc_worker`, dropping every inbound
//! connection it does not name ([`erpc_worker::server::firewall_table`]).
//! It is made from one opening per worker, kept in
//! `/etc/erpc/worker-firewall/workers/<id>.json`, so the workers on a
//! server share it and each changes only its own part.
//!
//! A change that may lock erpc out goes in two steps, as the SSH allow list
//! does. `firewall-apply` loads the new table after keeping the one in
//! force, and arms a timer that loads the kept one again after
//! [`erpc_worker::server::FIREWALL_ROLLBACK_SECONDS`]. Only
//! `firewall-confirm`, run over a fresh connection -- which proves the new
//! table lets erpc in -- disarms it, keeps the new opening, and loads the
//! table at boot. A worker's removal only closes its port, so it is applied
//! at once.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use erpc_worker::server::{
    FIREWALL_DIR, FIREWALL_ROLLBACK_SECONDS, FirewallRequest, Opening, firewall_table,
};
use serde_json::{Value, json};

const ROLLBACK_UNIT: &str = "erpc-worker-firewall-rollback";
const BOOT_UNIT: &str = "erpc-worker-firewall.service";

/// Where `confirm` moves the pending change it takes.
const CONFIRMING: &str = "confirming.json";
/// Where the rollback moves the pending change it takes.
const ROLLED_BACK: &str = "rolled-back.json";

fn dir() -> PathBuf {
    PathBuf::from(FIREWALL_DIR)
}

/// What the rollback timer runs: take the pending change, and only then
/// put the previous table back.
fn rollback_command(d: &Path) -> String {
    let quoted = |name: &str| format!("'{}'", d.join(name).display());
    format!(
        "mv {} {} && /usr/sbin/nft -f {}",
        quoted("pending.json"),
        quoted(ROLLED_BACK),
        quoted("previous.nft")
    )
}

/// Holds the server's firewall lock while a firewall verb runs: two
/// workers deploying at once take turns.
fn lock(d: &Path) -> Result<std::fs::File, String> {
    std::fs::create_dir_all(d).map_err(|e| format!("could not make {}: {e}", d.display()))?;
    let file = std::fs::File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(d.join(".lock"))
        .map_err(|e| format!("could not open the firewall lock: {e}"))?;
    file.lock()
        .map_err(|e| format!("could not take the firewall lock: {e}"))?;
    Ok(file)
}

/// Whether the rollback timer of a change not yet confirmed is waiting.
/// It is gone once it has fired, and after a restart: either way the
/// change it guards is no longer in force.
fn armed() -> Result<bool, String> {
    let out = Command::new("systemctl")
        .args(["is-active", &format!("{ROLLBACK_UNIT}.timer")])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run systemctl: {e}"))?;
    timer_state(&String::from_utf8_lossy(&out.stdout))
}

/// What `systemctl is-active` printed, as armed or not. Anything else
/// (systemd not answering) is an error, never "not armed": taken for one,
/// it would let a change be kept or dropped while its timer still runs.
fn timer_state(stdout: &str) -> Result<bool, String> {
    match stdout.lines().next().map(str::trim) {
        Some("active" | "activating" | "reloading") => Ok(true),
        Some("inactive" | "failed" | "dead") => Ok(false),
        other => Err(format!(
            "could not tell whether the firewall's rollback timer is waiting (systemctl said {})",
            other.filter(|o| !o.is_empty()).unwrap_or("nothing")
        )),
    }
}

/// Moves a change that is no longer in force out of the way, as the
/// rollback itself does, rather than deleting it.
fn set_aside(d: &Path) {
    let _ = std::fs::rename(d.join("pending.json"), d.join(ROLLED_BACK));
}

/// Refuses while another change waits to be confirmed: its table and the
/// one it would go back to were made from the openings as they were.
fn refuse_while_waiting(
    d: &Path,
    armed: impl FnOnce() -> Result<bool, String>,
) -> Result<(), String> {
    if !d.join("pending.json").exists() {
        return Ok(());
    }
    if armed()? {
        return Err(format!(
            "another firewall change on this server is waiting to be confirmed; try again in \
             {FIREWALL_ROLLBACK_SECONDS} seconds"
        ));
    }
    set_aside(d);
    Ok(())
}

/// The pending change, taken for `confirm` by one rename, or `None` when
/// there is none to take: the rollback took it, or nothing was applied.
fn claim(d: &Path) -> Option<String> {
    std::fs::rename(d.join("pending.json"), d.join(CONFIRMING)).ok()?;
    std::fs::read_to_string(d.join(CONFIRMING)).ok()
}

fn rolled_back() -> Value {
    json!({ "ok": false, "firewall": "rolled_back",
        "error": "the change is not in force: the rollback put the previous firewall back, or \
                  the server restarted before it was confirmed" })
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, text)
        .and_then(|()| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)))
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("could not write {}: {e}", path.display())
        })
}

/// The openings kept, by worker; `candidate` in place of its worker's.
fn openings(
    candidate: Option<(&str, Option<&Opening>)>,
) -> Result<BTreeMap<String, Opening>, String> {
    let mut all = BTreeMap::new();
    let workers = dir().join("workers");
    if let Ok(entries) = std::fs::read_dir(&workers) {
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if !erpc_worker::server::is_unit_id(id) {
                continue;
            }
            let text = std::fs::read_to_string(entry.path())
                .map_err(|e| format!("could not read {name}: {e}"))?;
            let opening: Opening = serde_json::from_str(&text)
                .map_err(|e| format!("{name} is not an opening: {e}"))?;
            all.insert(id.to_owned(), opening);
        }
    }
    if let Some((id, opening)) = candidate {
        match opening {
            Some(o) => {
                all.insert(id.to_owned(), o.clone());
            }
            None => {
                all.remove(id);
            }
        }
    }
    Ok(all)
}

/// Checks `table` with `nft -c`, then loads it.
fn load(table: &str, path: &Path) -> Result<(), String> {
    write(path, table)?;
    let path = path.to_string_lossy();
    run("nft", &["-c", "-f", &path])?;
    run("nft", &["-f", &path]).map(|_| ())
}

/// `firewall-apply`: this worker's opening (stdin) applied to the table,
/// under the rollback timer.
pub(crate) fn apply(id: &str) -> Result<Value, String> {
    let mut input = String::new();
    std::io::stdin()
        .lock()
        .take(64 * 1024)
        .read_to_string(&mut input)
        .map_err(|e| format!("could not read standard input: {e}"))?;
    let request: FirewallRequest =
        serde_json::from_str(input.trim()).map_err(|e| format!("not a firewall request: {e}"))?;
    if request.ssh_port == 0 {
        return Err("0 is not the SSH port".to_owned());
    }
    if let Some(o) = &request.opening
        && (o.port == 0 || o.port == request.ssh_port || o.allow.is_empty() || o.allow.len() > 64)
    {
        return Err("an opening is a port other than SSH's, for 1 to 64 addresses".to_owned());
    }
    let d = dir();
    let _lock = lock(&d)?;
    std::fs::create_dir_all(d.join("workers"))
        .map_err(|e| format!("could not make {}: {e}", d.display()))?;
    // Another worker's change, not yet confirmed, has its own timer:
    // stopping it would keep a table nobody proved lets erpc in.
    refuse_while_waiting(&d, armed)?;
    let all = openings(Some((id, request.opening.as_ref())))?;
    let table = firewall_table(request.ssh_port, &all);
    let _ = run("systemctl", &["stop", &format!("{ROLLBACK_UNIT}.timer")]);
    // What is in force now is what the timer goes back to.
    let previous = std::fs::read_to_string(d.join("applied.nft"))
        .unwrap_or_else(|_| "table inet erpc_worker\ndelete table inet erpc_worker\n".to_owned());
    write(&d.join("previous.nft"), &previous)?;
    let pending = serde_json::to_string(&json!({
        "id": id,
        "ssh_port": request.ssh_port,
        "opening": request.opening,
    }))
    .map_err(|e| e.to_string())?;
    write(&d.join("pending.json"), &pending)?;
    let _ = std::fs::remove_file(d.join(ROLLED_BACK));
    let _ = std::fs::remove_file(d.join(CONFIRMING));
    // The timer puts the previous table back only if it takes the pending
    // change first, by a rename `confirm` races for: one of them wins.
    let rollback = rollback_command(&d);
    run(
        "systemd-run",
        &[
            "--quiet",
            "--collect",
            &format!("--unit={ROLLBACK_UNIT}"),
            &format!("--on-active={FIREWALL_ROLLBACK_SECONDS}"),
            "/bin/sh",
            "-c",
            &rollback,
        ],
    )?;
    if let Err(e) = load(&table, &d.join("pending.nft")) {
        let _ = run("systemctl", &["stop", &format!("{ROLLBACK_UNIT}.timer")]);
        return Err(e);
    }
    Ok(json!({ "ok": true, "firewall": "applied", "rollback_seconds": FIREWALL_ROLLBACK_SECONDS }))
}

/// `firewall-confirm`: keeps what `firewall-apply` loaded, when its timer
/// has not run out.
pub(crate) fn confirm() -> Result<Value, String> {
    let d = dir();
    let _lock = lock(&d)?;
    // No timer means the change is not in force: the rollback ran, or the
    // server restarted and loaded the table kept before it. Checked before
    // the change is taken, so a timer that fires in between takes it
    // first, and confirm reports that.
    if !armed()? {
        set_aside(&d);
        return Ok(rolled_back());
    }
    let Some(pending) = claim(&d) else {
        return Ok(rolled_back());
    };
    // The change is this command's now: the timer, if it fires, finds
    // nothing to take and leaves the table alone.
    let _ = run("systemctl", &["stop", &format!("{ROLLBACK_UNIT}.timer")]);
    let pending: Value = serde_json::from_str(&pending).map_err(|e| e.to_string())?;
    let id = pending["id"].as_str().unwrap_or_default();
    if !erpc_worker::server::is_unit_id(id) {
        return Err("the pending change names no worker".to_owned());
    }
    let opening_path = d.join("workers").join(format!("{id}.json"));
    match pending.get("opening").filter(|o| !o.is_null()) {
        Some(opening) => write(&opening_path, &opening.to_string())?,
        None => {
            let _ = std::fs::remove_file(&opening_path);
        }
    }
    std::fs::rename(d.join("pending.nft"), d.join("applied.nft"))
        .map_err(|e| format!("could not keep the table: {e}"))?;
    let _ = std::fs::remove_file(d.join(CONFIRMING));
    boot_unit()?;
    Ok(json!({ "ok": true, "firewall": "confirmed" }))
}

/// Loads the kept table at boot, after nftables' own rules.
fn boot_unit() -> Result<(), String> {
    let unit = format!(
        "# Written by erpc worker. Loads the worker firewall at boot.\n\
         [Unit]\n\
         Description=erpc worker firewall\n\
         DefaultDependencies=no\n\
         After=nftables.service\n\
         Wants=network-pre.target\n\
         Before=network-pre.target shutdown.target\n\
         Conflicts=shutdown.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         ExecStart=/usr/sbin/nft -f {FIREWALL_DIR}/applied.nft\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    let path = PathBuf::from("/etc/systemd/system").join(BOOT_UNIT);
    if std::fs::read_to_string(&path).ok().as_deref() != Some(unit.as_str()) {
        write(&path, &unit)?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        run("systemctl", &["daemon-reload"])?;
    }
    run("systemctl", &["enable", "--quiet", BOOT_UNIT]).map(|_| ())
}

/// The firewall held for closing a worker's port: taken by `remove` before
/// it takes the worker down and kept until the port is closed, so no other
/// change can come in between, and a refusal leaves the worker as it was.
pub(crate) struct Held {
    // Held, not read: the lock lasts as long as this does.
    _lock: std::fs::File,
}

/// Takes the firewall for [`close`], refused while another worker's change
/// waits to be confirmed: that change has this worker's opening in both
/// its tables, so either its confirm or its rollback would open the port
/// again.
pub(crate) fn hold() -> Result<Held, String> {
    let d = dir();
    let file = lock(&d)?;
    refuse_while_waiting(&d, armed)?;
    Ok(Held { _lock: file })
}

/// Closes `id`'s port at once (it cannot lock anyone out), with the
/// firewall held. Nothing to do when the server has no worker firewall.
pub(crate) fn close(id: &str, _held: &Held) -> Result<Value, String> {
    let d = dir();
    let opening_path = d.join("workers").join(format!("{id}.json"));
    if !d.join("applied.nft").exists() {
        let _ = std::fs::remove_file(&opening_path);
        return Ok(json!("none"));
    }
    let ssh_port = std::fs::read_to_string(d.join("applied.nft"))
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("tcp dport ")
                    .and_then(|r| r.strip_suffix(" accept"))
                    .and_then(|p| p.parse::<u16>().ok())
            })
        })
        .unwrap_or(22);
    let all = openings(Some((id, None)))?;
    load(&firewall_table(ssh_port, &all), &d.join("next.nft"))?;
    std::fs::rename(d.join("next.nft"), d.join("applied.nft"))
        .map_err(|e| format!("could not keep the table: {e}"))?;
    let _ = std::fs::remove_file(&opening_path);
    Ok(json!("closed"))
}

/// `firewall-show`: the table in force, and the openings.
pub(crate) fn show() -> Result<Value, String> {
    let table = run("nft", &["list", "table", "inet", "erpc_worker"]).ok();
    Ok(json!({
        "ok": true,
        "table": table,
        "openings": openings(None)?,
        "pending": dir().join("pending.json").exists(),
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn confirm_and_the_rollback_cannot_both_take_the_change() {
        let tmp = tempfile::tempdir().expect("tmp");
        let d = tmp.path();
        std::fs::write(d.join("pending.json"), r#"{"id":"bot-default"}"#).expect("pending");
        assert!(super::claim(d).is_some(), "confirm takes it");
        assert!(super::claim(d).is_none(), "once");

        // The timer fired first: its command moved the change away, and
        // confirm reports the rollback.
        std::fs::write(d.join("pending.json"), r#"{"id":"bot-default"}"#).expect("pending");
        std::fs::remove_file(d.join(super::CONFIRMING)).expect("clear");
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(super::rollback_command(d).replace("&& /usr/sbin/nft -f", "&& test -n"))
            .status()
            .expect("sh");
        assert!(status.success());
        assert!(super::claim(d).is_none());
        assert_eq!(super::rolled_back()["firewall"], "rolled_back");
    }

    #[test]
    fn only_a_timer_systemd_calls_inactive_is_not_armed() {
        assert_eq!(super::timer_state("active\n"), Ok(true));
        assert_eq!(super::timer_state("inactive\n"), Ok(false));
        assert_eq!(super::timer_state("failed\n"), Ok(false));
        assert!(super::timer_state("").is_err());
        assert!(super::timer_state("Failed to connect to bus\n").is_err());
    }

    #[test]
    fn a_change_no_longer_in_force_is_set_aside_not_deleted() {
        let tmp = tempfile::tempdir().expect("tmp");
        std::fs::write(tmp.path().join("pending.json"), "{}").expect("pending");
        super::set_aside(tmp.path());
        assert!(!tmp.path().join("pending.json").exists());
        assert!(tmp.path().join(super::ROLLED_BACK).exists());
    }

    #[test]
    fn a_change_waiting_its_timer_refuses_another_and_a_stale_one_is_set_aside() {
        let tmp = tempfile::tempdir().expect("tmp");
        let d = tmp.path();
        assert!(
            super::refuse_while_waiting(d, || Ok(true)).is_ok(),
            "nothing waiting"
        );
        std::fs::write(d.join("pending.json"), "{}").expect("pending");
        let refused = super::refuse_while_waiting(d, || Ok(true)).expect_err("refused");
        assert!(refused.contains("waiting to be confirmed"), "{refused}");
        assert!(d.join("pending.json").exists(), "left as it was");
        // systemd not answering: an error, and nothing is touched.
        assert!(super::refuse_while_waiting(d, || Err("no bus".to_owned())).is_err());
        assert!(d.join("pending.json").exists());
        // Its timer gone: no longer in force, set aside.
        assert!(super::refuse_while_waiting(d, || Ok(false)).is_ok());
        assert!(!d.join("pending.json").exists());
        assert!(d.join(super::ROLLED_BACK).exists());
    }

    #[test]
    fn the_firewall_lock_is_taken_in_turn() {
        let tmp = tempfile::tempdir().expect("tmp");
        let first = super::lock(tmp.path()).expect("first");
        assert!(
            std::fs::File::open(tmp.path().join(".lock"))
                .expect("open")
                .try_lock()
                .is_err(),
            "held"
        );
        drop(first);
        assert!(super::lock(tmp.path()).is_ok(), "free again");
    }

    #[test]
    fn the_rollback_does_nothing_once_confirm_has_the_change() {
        let tmp = tempfile::tempdir().expect("tmp");
        let d = tmp.path();
        std::fs::write(d.join("pending.json"), "{}").expect("pending");
        assert!(super::claim(d).is_some());
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(super::rollback_command(d).replace("/usr/sbin/nft -f", "touch"))
            .status()
            .expect("sh");
        assert!(!status.success(), "mv finds nothing to take");
        assert!(
            !d.join("previous.nft").exists(),
            "and the table is not put back"
        );
    }
}
