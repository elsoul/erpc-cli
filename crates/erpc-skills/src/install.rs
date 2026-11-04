// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Writing the skills to a directory on the machine, so they are there to
//! read -- by the operator, and by an agent that reads `SKILL.md` files.
//!
//! Each skill becomes `<dir>/<name>/SKILL.md`. What erpc wrote is recorded,
//! with each file's SHA-256, in a ledger kept apart from the directory; a
//! later install only replaces or removes a file that still holds what erpc
//! wrote. A file someone has changed, or a skill of the same name that erpc
//! did not write, is left as it is and reported.

use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest as _, Sha256};

/// What became of each skill.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// Written for the first time, or replaced with a newer text.
    pub written: Vec<String>,
    /// Already the current text.
    pub unchanged: Vec<String>,
    /// Not erpc's, or changed since erpc wrote it: left as it is.
    pub kept: Vec<String>,
    /// erpc's, and no longer a skill: removed.
    pub removed: Vec<String>,
}

/// Writes every skill under `dir`, recording what it wrote in `ledger`.
///
/// # Errors
///
/// Returns a message when a directory or file cannot be written or the
/// ledger cannot be read.
pub fn install(dir: &Path, ledger: &Path) -> Result<Report, String> {
    let skills: BTreeMap<&str, &str> = crate::FILES.iter().copied().collect();
    install_these(dir, ledger, &skills)
}

/// The skills a place `ledger` records would get from an install now: new
/// ones, ones whose text changed, and ones that are gone. `None` when erpc
/// never installed skills there.
///
/// # Errors
///
/// Returns a message when the ledger cannot be read.
pub fn stale(ledger: &Path) -> Result<Option<Vec<String>>, String> {
    if !ledger.exists() {
        return Ok(None);
    }
    let skills: BTreeMap<&str, &str> = crate::FILES.iter().copied().collect();
    Ok(Some(stale_these(&read_ledger(ledger)?, &skills)))
}

fn stale_these(wrote: &BTreeMap<String, String>, skills: &BTreeMap<&str, &str>) -> Vec<String> {
    let mut out: Vec<String> = skills
        .iter()
        .filter(|(name, text)| wrote.get(**name) != Some(&digest(text.as_bytes())))
        .map(|(name, _)| (*name).to_owned())
        .collect();
    out.extend(
        wrote
            .keys()
            .filter(|name| !skills.contains_key(name.as_str()))
            .cloned(),
    );
    out.sort();
    out
}

/// One digest of every skill this erpc carries: it changes when any of
/// them does, so a notice can be given once per change.
#[must_use]
pub fn fingerprint() -> String {
    let mut all = String::new();
    for (name, text) in crate::FILES {
        all.push_str(name);
        all.push('\0');
        all.push_str(&digest(text.as_bytes()));
        all.push('\n');
    }
    digest(all.as_bytes())
}

fn install_these(
    dir: &Path,
    ledger: &Path,
    skills: &BTreeMap<&str, &str>,
) -> Result<Report, String> {
    let mut wrote = read_ledger(ledger)?;
    let mut report = Report::default();
    for (name, text) in skills {
        let file = dir.join(name).join("SKILL.md");
        let new = digest(text.as_bytes());
        let ours = match std::fs::read(&file) {
            Ok(bytes) => {
                let now = digest(&bytes);
                if now == new {
                    wrote.insert((*name).to_owned(), new);
                    report.unchanged.push((*name).to_owned());
                    continue;
                }
                wrote.get(*name) == Some(&now)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => return Err(format!("cannot read {}: {e}", file.display())),
        };
        if ours {
            write(&file, text.as_bytes())?;
            wrote.insert((*name).to_owned(), new);
            report.written.push((*name).to_owned());
        } else {
            report.kept.push((*name).to_owned());
        }
    }
    let gone: Vec<String> = wrote
        .keys()
        .filter(|name| !skills.contains_key(name.as_str()))
        .cloned()
        .collect();
    for name in gone {
        let file = dir.join(&name).join("SKILL.md");
        let still_ours = std::fs::read(&file).is_ok_and(|b| Some(&digest(&b)) == wrote.get(&name));
        if still_ours {
            std::fs::remove_file(&file)
                .map_err(|e| format!("cannot remove {}: {e}", file.display()))?;
            // The directory goes only if nothing else is in it.
            let _ = std::fs::remove_dir(dir.join(&name));
            report.removed.push(name.clone());
        }
        wrote.remove(&name);
    }
    let body = serde_json::to_string_pretty(&wrote).map_err(|e| e.to_string())?;
    write(ledger, body.as_bytes())?;
    Ok(report)
}

/// The ledger: each skill erpc wrote, and the SHA-256 of what it wrote.
fn read_ledger(ledger: &Path) -> Result<BTreeMap<String, String>, String> {
    match std::fs::read_to_string(ledger) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|e| format!("{} is not erpc's skill ledger: {e}", ledger.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!("cannot read {}: {e}", ledger.display())),
    }
}

/// Writes `bytes` to `path` through a file beside it, so a reader sees the
/// old text or the new one, never half of it.
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    let temporary = path.with_extension("erpc-tmp");
    std::fs::write(&temporary, bytes)
        .and_then(|()| std::fs::rename(&temporary, path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&temporary);
            format!("cannot write {}: {e}", path.display())
        })
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            use core::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::install_these;

    fn skills<'a>(pairs: &[(&'a str, &'a str)]) -> BTreeMap<&'a str, &'a str> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn every_skill_is_written_and_a_second_install_changes_nothing() {
        let dir = tempfile::tempdir().expect("dir");
        let (root, ledger) = (dir.path().join("skills"), dir.path().join("ledger.json"));
        let report = super::install(&root, &ledger).expect("installs");
        assert_eq!(report.written.len(), crate::all().len());
        let text = std::fs::read_to_string(root.join("solana-validator-mainnet/SKILL.md"))
            .expect("written");
        assert!(text.starts_with("---\nname: solana-validator-mainnet\n"));
        let again = super::install(&root, &ledger).expect("installs");
        assert!(again.written.is_empty());
        assert_eq!(again.unchanged.len(), crate::all().len());
        assert_eq!(super::stale(&ledger).expect("reads"), Some(Vec::new()));
        assert_eq!(
            super::stale(&dir.path().join("none.json")).expect("reads"),
            None
        );
    }

    #[test]
    fn a_place_is_stale_when_a_skill_is_new_changed_or_gone() {
        let dir = tempfile::tempdir().expect("dir");
        let (root, ledger) = (dir.path().join("skills"), dir.path().join("ledger.json"));
        install_these(&root, &ledger, &skills(&[("a", "one"), ("b", "two")])).expect("installs");
        let wrote = super::read_ledger(&ledger).expect("ledger");
        let now = skills(&[("a", "one, newer"), ("c", "three")]);
        assert_eq!(super::stale_these(&wrote, &now), ["a", "b", "c"]);
        assert!(super::stale_these(&wrote, &skills(&[("a", "one"), ("b", "two")])).is_empty());
    }

    #[test]
    fn a_newer_text_replaces_only_what_erpc_wrote() {
        let dir = tempfile::tempdir().expect("dir");
        let (root, ledger) = (dir.path().join("skills"), dir.path().join("ledger.json"));
        install_these(&root, &ledger, &skills(&[("a", "one"), ("b", "one")])).expect("first");
        std::fs::write(root.join("b/SKILL.md"), "edited by hand").expect("edit");
        std::fs::create_dir_all(root.join("c")).expect("dir");
        std::fs::write(root.join("c/SKILL.md"), "someone else's").expect("theirs");

        let report = install_these(
            &root,
            &ledger,
            &skills(&[("a", "two"), ("b", "two"), ("c", "two")]),
        )
        .expect("second");
        assert_eq!(report.written, ["a"]);
        assert_eq!(report.kept, ["b", "c"]);
        let read = |n: &str| std::fs::read_to_string(root.join(n).join("SKILL.md")).expect("read");
        assert_eq!(read("a"), "two");
        assert_eq!(read("b"), "edited by hand");
        assert_eq!(read("c"), "someone else's");
    }

    #[test]
    fn a_skill_that_is_gone_is_removed_unless_it_was_changed() {
        let dir = tempfile::tempdir().expect("dir");
        let (root, ledger) = (dir.path().join("skills"), dir.path().join("ledger.json"));
        install_these(
            &root,
            &ledger,
            &skills(&[("a", "x"), ("b", "x"), ("k", "x")]),
        )
        .expect("first");
        std::fs::write(root.join("b/SKILL.md"), "edited").expect("edit");
        let report = install_these(&root, &ledger, &skills(&[("k", "x")])).expect("second");
        assert_eq!(report.removed, ["a"]);
        assert!(!root.join("a").exists());
        assert!(root.join("b/SKILL.md").exists(), "an edited file stays");
    }

    #[test]
    fn a_ledger_that_is_not_erpcs_stops_the_install() {
        let dir = tempfile::tempdir().expect("dir");
        let ledger = dir.path().join("ledger.json");
        std::fs::write(&ledger, "not json").expect("write");
        assert!(super::install(&dir.path().join("skills"), &ledger).is_err());
    }
}
