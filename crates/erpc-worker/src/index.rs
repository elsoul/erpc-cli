// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `~/.erpc/workers.toml`: the app directories on this machine, so that
//! `erpc worker list` can show every worker without being run from inside
//! each one.
//!
//! It is a list of directories and nothing else; what each app is and
//! where it runs stays in its own `erpc.toml`. `init` and `deploy` add the
//! app they ran in; an entry whose directory is gone is shown as such and
//! dropped by `forget`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The index file's name, beside erpc's `config.toml`.
pub const FILE_NAME: &str = "workers.toml";

/// One app directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The app's name when it was added. The manifest's own name wins
    /// when they differ.
    pub name: String,
    /// The app's root, where its `erpc.toml` is. Absolute.
    pub dir: PathBuf,
}

/// The whole index.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    /// Every app, in the order they were added.
    #[serde(default, rename = "worker")]
    pub workers: Vec<Entry>,
}

impl Index {
    /// Reads the index at `path`; no file is an empty index.
    ///
    /// # Errors
    ///
    /// A message when the file is there and cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .map_err(|e| format!("{} is not valid: {}", path.display(), e.message())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("could not read {}: {e}", path.display())),
        }
    }

    /// Adds `dir` under `name`, or renames it when it is there already.
    /// Returns whether anything changed.
    ///
    /// # Errors
    ///
    /// A message when `dir` is not absolute: a relative one would mean a
    /// different app from every other directory.
    pub fn remember(&mut self, name: &str, dir: &Path) -> Result<bool, String> {
        if !dir.is_absolute() {
            return Err(format!("{} is not an absolute path", dir.display()));
        }
        if let Some(entry) = self.workers.iter_mut().find(|e| e.dir == dir) {
            if entry.name == name {
                return Ok(false);
            }
            name.clone_into(&mut entry.name);
            return Ok(true);
        }
        self.workers.push(Entry {
            name: name.to_owned(),
            dir: dir.to_owned(),
        });
        Ok(true)
    }

    /// Removes `dir`. Returns whether it was there.
    pub fn forget(&mut self, dir: &Path) -> bool {
        let before = self.workers.len();
        self.workers.retain(|e| e.dir != dir);
        self.workers.len() != before
    }
}

/// Reads the index at `path`, lets `change` edit it, and writes it back
/// when `change` says it changed, holding the file's lock throughout so
/// that two erpc processes do not lose each other's entry.
///
/// # Errors
///
/// A message when the index cannot be read, locked or written, or what
/// `change` returns.
pub fn update<T>(
    path: &Path,
    change: impl FnOnce(&mut Index) -> Result<(T, bool), String>,
) -> Result<T, String> {
    erpc_core::private_file::locked(path, || {
        let mut index = Index::load(path)?;
        let (out, changed) = change(&mut index)?;
        if changed {
            let text = toml::to_string(&index).map_err(|e| e.to_string())?;
            let header = "# The erpc worker apps on this machine. erpc keeps this file; each \
                          app's own erpc.toml says what it is.\n";
            erpc_core::private_file::write(path, format!("{header}{text}").as_bytes())?;
        }
        Ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::{Index, update};

    #[test]
    fn an_app_is_remembered_once_and_renamed_in_place() {
        let mut index = Index::default();
        let dir = std::env::temp_dir().join("bot");
        assert!(index.remember("bot", &dir).expect("absolute"));
        assert!(!index.remember("bot", &dir).expect("absolute"));
        assert!(index.remember("bot2", &dir).expect("absolute"));
        assert_eq!(index.workers.len(), 1);
        assert_eq!(index.workers[0].name, "bot2");
        assert!(index.remember("x", std::path::Path::new("rel")).is_err());
        assert!(index.forget(&dir));
        assert!(!index.forget(&dir));
    }

    #[test]
    fn the_file_is_written_only_when_it_changes() {
        let root = std::env::temp_dir().join(format!("erpc-worker-index-{}", std::process::id()));
        let path = root.join(super::FILE_NAME);
        let dir = root.join("apps").join("bot");
        assert!(!path.exists());
        update(&path, |i| Ok(((), i.remember("bot", &dir)?))).expect("add");
        let loaded = Index::load(&path).expect("load");
        assert_eq!(loaded.workers.len(), 1);
        assert_eq!(loaded.workers[0].dir, dir);
        let before = std::fs::metadata(&path)
            .expect("meta")
            .modified()
            .expect("mtime");
        update(&path, |i| Ok(((), i.remember("bot", &dir)?))).expect("same");
        let after = std::fs::metadata(&path)
            .expect("meta")
            .modified()
            .expect("mtime");
        assert_eq!(before, after);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_file_is_an_empty_index() {
        let path = std::env::temp_dir().join("erpc-worker-no-such-index.toml");
        assert_eq!(Index::load(&path).expect("empty"), Index::default());
    }
}
