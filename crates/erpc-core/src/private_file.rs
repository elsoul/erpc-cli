// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Files for the owner alone, written whole and read back whole: a file is
//! made 0600 from the start, written under a name of its own, synced and
//! renamed over the old one, so a reader sees the old file or the new one,
//! never part of either. [`locked`] keeps two erpc processes that read,
//! change and write the same file from losing each other's change.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

fn private(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
}

/// Writes `bytes` to `path`, replacing what was there; makes its directory
/// when missing.
///
/// # Errors
///
/// A message naming the file that could not be written.
pub fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    // Its own name, so two writers never share one half-written file.
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = dir.join(tmp_name);
    let written = private(OpenOptions::new().write(true).create(true).truncate(true))
        .open(&tmp)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .and_then(|()| std::fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("could not write {}: {e}", path.display())
    })
}

/// Runs `change` holding the lock beside `path` (`<path>.lock`), waiting
/// for another process that holds it.
///
/// # Errors
///
/// The lock cannot be had, or what `change` returns.
pub fn locked<T>(path: &Path, change: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    let lock_path = dir.join(name);
    let lock = private(OpenOptions::new().write(true).create(true).truncate(false))
        .open(&lock_path)
        .map_err(|e| format!("could not open {}: {e}", lock_path.display()))?;
    lock.lock()
        .map_err(|e| format!("could not lock {}: {e}", lock_path.display()))?;
    let result = change();
    let _ = lock.unlock();
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_file_is_replaced_whole_and_private() {
        let dir = std::env::temp_dir().join(format!("erpc-core-pf-{}", std::process::id()));
        let path = dir.join("a").join("state.json");
        super::write(&path, b"one").expect("first");
        super::locked(&path, || super::write(&path, b"two")).expect("second");
        assert_eq!(std::fs::read(&path).expect("read"), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let left: Vec<_> = std::fs::read_dir(path.parent().expect("dir"))
            .expect("list")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "tmp"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
