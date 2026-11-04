// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The worker's backup, as root: its credentials, its service and timer
//! ([`erpc_worker::server::backup_service`]), and what the last run did.
//!
//! The credentials arrive on standard input and are written root-only;
//! they are never on a command line. They are checked to be the five
//! variables restic needs and nothing else
//! ([`erpc_worker::server::backup_env_ok`]), because they become the
//! environment of a program that runs as root.

use std::io::{Read, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use erpc_worker::server;
use serde_json::{Value, json};

use crate::ctl::systemctl;

/// The largest credentials read from standard input.
const MAX_ENV: u64 = 4096;

fn units() -> PathBuf {
    PathBuf::from("/etc/systemd/system")
}

/// Writes `text` to `path` with `mode` through a temporary file beside it,
/// made with that mode before anything is written, then renamed. Says
/// whether the file changed.
fn put(path: &Path, text: &str, mode: u32) -> Result<bool, String> {
    if std::fs::read_to_string(path).ok().as_deref() == Some(text) {
        return Ok(false);
    }
    let temp = path.with_extension("erpc-new");
    let _ = std::fs::remove_file(&temp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)
        .map_err(|e| format!("could not write {}: {e}", temp.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("could not write {}: {e}", temp.display()))?;
    std::fs::rename(&temp, path).map_err(|e| format!("could not keep {}: {e}", path.display()))?;
    Ok(true)
}

/// The credentials in `input`, checked to be what erpc sends for worker
/// `id`. Read into room made first, so no copy is left behind unwiped.
fn credentials(id: &str, input: impl Read) -> Result<zeroize::Zeroizing<String>, String> {
    let room = usize::try_from(MAX_ENV).unwrap_or(4096) + 64;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(room));
    input
        .take(MAX_ENV + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read the credentials: {e}"))?;
    let refused = || "the backup credentials are not what erpc sends".to_owned();
    if bytes.len() as u64 > MAX_ENV {
        return Err(refused());
    }
    let text = zeroize::Zeroizing::new(
        String::from_utf8(core::mem::take(&mut *bytes)).map_err(|_| refused())?,
    );
    if !server::backup_env_ok(id, &text) {
        return Err(refused());
    }
    Ok(text)
}

/// Whether `path` is root's and only root can change it.
fn root_only(path: &Path) -> Result<(), String> {
    let meta = std::fs::metadata(path).map_err(|_| format!("{} is not there", path.display()))?;
    if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} can be changed by others than root",
            path.display()
        ));
    }
    Ok(())
}

/// `backup-setup`: the credentials from standard input, the service and the
/// timer at `at`, and the timer running.
pub(crate) fn setup(id: &str, at: &str) -> Result<Value, String> {
    let time = server::time_of_day(at).ok_or_else(|| format!("{at:?} is not a time of day"))?;
    let env = credentials(id, std::io::stdin())?;
    // The program root runs, and where it lives.
    let restic = Path::new(server::RESTIC_PATH);
    root_only(restic)?;
    if let Some(parent) = restic.parent() {
        root_only(parent)?;
    }
    let dir = Path::new(server::BACKUP_DIR);
    std::fs::create_dir_all(dir).map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("could not set {}'s mode: {e}", dir.display()))?;
    // The credentials before, put back when the rest fails, so a setup that
    // fails leaves the backup as it was.
    let env_path = server::backup_env_path(id);
    let before = std::fs::read_to_string(&env_path)
        .ok()
        .map(zeroize::Zeroizing::new);
    put(&env_path, &env, 0o600)?;
    let units_written = (|| -> Result<bool, String> {
        let service = put(
            &units().join(server::backup_service_name(id)),
            &server::backup_service(id),
            0o644,
        )?;
        let timer = put(
            &units().join(server::backup_timer_name(id)),
            &server::backup_timer(id, time),
            0o644,
        )?;
        if service || timer {
            systemctl(&["daemon-reload"])?;
        }
        systemctl(&["enable", "--now", "--quiet", &server::backup_timer_name(id)])?;
        Ok(service || timer)
    })();
    let written = match units_written {
        Ok(written) => written,
        Err(e) => {
            let _ = match &before {
                Some(text) => put(&env_path, text, 0o600).map(|_| ()),
                None => std::fs::remove_file(&env_path).map_err(|e| e.to_string()),
            };
            return Err(e);
        }
    };
    Ok(json!({
        "ok": true,
        "timer": server::backup_timer_name(id),
        "units": if written { "written" } else { "unchanged" },
    }))
}

/// `backup-remove`: the timer stopped, and the units, the credentials and
/// the cache gone. What is in the repository stays.
///
/// # Errors
///
/// When a unit or the credentials cannot be removed.
pub(crate) fn remove(id: &str) -> Result<Value, String> {
    let timer = server::backup_timer_name(id);
    let service = server::backup_service_name(id);
    let mut removed = false;
    for unit in [&timer, &service] {
        let path = units().join(unit);
        if path.exists() {
            let _ = systemctl(&["disable", "--now", "--quiet", unit]);
            if unit == &service {
                let _ = systemctl(&["clean", "--what=cache", unit]);
            }
            std::fs::remove_file(&path)
                .map_err(|e| format!("could not remove {}: {e}", path.display()))?;
            removed = true;
        }
    }
    let env = server::backup_env_path(id);
    if env.exists() {
        std::fs::remove_file(&env)
            .map_err(|e| format!("could not remove {}: {e}", env.display()))?;
        removed = true;
    }
    if removed {
        systemctl(&["daemon-reload"])?;
    }
    Ok(json!({ "ok": true, "removed": removed }))
}

/// One property of a unit, as `systemctl show` gives it.
fn property(unit: &str, name: &str) -> String {
    systemctl(&["show", unit, "--property", name, "--value"]).unwrap_or_default()
}

/// `backup-status`: whether the timer is on, when it runs next, and what
/// the last run did.
pub(crate) fn status(id: &str) -> Value {
    let timer = server::backup_timer_name(id);
    let service = server::backup_service_name(id);
    if !units().join(&timer).exists() {
        return json!({ "ok": true, "on": false });
    }
    let last_exit = property(&service, "ExecMainStatus");
    json!({
        "ok": true,
        "on": true,
        "active": property(&timer, "ActiveState"),
        "next": property(&timer, "NextElapseUSecRealtime"),
        "running": property(&service, "ActiveState") == "activating",
        "last": {
            "result": property(&service, "Result"),
            "exit": last_exit.parse::<i64>().ok(),
            "at": property(&service, "ExecMainExitTimestamp"),
        },
    })
}

/// `backup-now`: one run, waited for, then its status.
pub(crate) fn now(id: &str) -> Result<Value, String> {
    let service = server::backup_service_name(id);
    if !units().join(&service).exists() {
        return Err("backups are not on for this worker".to_owned());
    }
    // A oneshot's start returns when the run has ended; a failed run is
    // reported in the status, not as an error of this verb.
    let started = systemctl(&["start", &service]);
    let mut answer = status(id);
    if let Err(e) = started {
        answer["error"] = json!(e);
        answer["ok"] = json!(false);
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    const GOOD: &str = "RESTIC_REPOSITORY=rest:https://user-api.erpc.global/v3/storage/restic\n\
                        RESTIC_REST_USERNAME=erpcsk_TESTONLY\nRESTIC_REST_PASSWORD=abc\n\
                        RESTIC_PASSWORD=0123abcd\nRESTIC_HOST=erpc-worker-bot-default-0a1b2c3d\n";

    #[test]
    fn the_credentials_are_taken_only_as_erpc_sends_them() {
        let got = super::credentials("bot-default", GOOD.as_bytes()).expect("taken");
        assert_eq!(got.as_str(), GOOD);
        // Another worker's, too long, not UTF-8, or with more in them.
        assert!(super::credentials("bot-prod", GOOD.as_bytes()).is_err());
        let long = format!("{GOOD}{}", "x".repeat(5000));
        assert!(super::credentials("bot-default", long.as_bytes()).is_err());
        assert!(super::credentials("bot-default", &[0xff, 0xfe][..]).is_err());
        let more = format!("{GOOD}LD_PRELOAD=/tmp/x\n");
        assert!(super::credentials("bot-default", more.as_bytes()).is_err());
    }

    #[test]
    fn a_file_is_written_with_its_mode_and_left_when_unchanged() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("bot.env");
        assert!(super::put(&path, "A=1\n", 0o600).expect("written"));
        let mode = std::fs::metadata(&path)
            .expect("there")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!super::put(&path, "A=1\n", 0o600).expect("unchanged"));
        assert!(super::put(&path, "A=2\n", 0o600).expect("replaced"));
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "A=2\n");
        assert!(!path.with_extension("erpc-new").exists());
    }

    #[test]
    fn a_program_others_can_change_is_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("restic");
        std::fs::write(&path, b"x").expect("written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("mode");
        // Not root's, unless the test runs as root.
        let mine = super::root_only(&path);
        if rustix::process::geteuid().is_root() {
            assert!(mine.is_ok());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775)).expect("mode");
            assert!(super::root_only(&path).is_err());
        } else {
            assert!(mine.is_err());
        }
        assert!(super::root_only(&dir.path().join("none")).is_err());
    }
}
