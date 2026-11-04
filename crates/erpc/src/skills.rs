// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc skills`: the assistant's skills, on this machine.
//!
//! `install` writes them to `~/.erpc/skills/<name>/SKILL.md`, and with
//! `--agent` to that agent's skills directory too. The installer runs it
//! after putting the binary in place; an update runs it again. What erpc
//! wrote is recorded under `~/.erpc/state`, so a file someone has changed
//! is never overwritten (see [`erpc_skills::install`]).
//!
//! The skills ship inside the binary and are checked against its commands
//! (`skill_check`), so a skill never names a flag this erpc lacks. What can
//! fall behind is the copy on disk, after an upgrade: `erpc doctor` warns
//! when a place erpc installed to is behind, and the first command after
//! the skills change says so once, at a terminal. `erpc skills sync` (the
//! same as `install`) brings them up to date.

use std::path::PathBuf;

use crate::commands::Outcome;
use crate::session;

/// An agent whose skills directory erpc can write to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Agent {
    /// Claude Code: `~/.claude/skills`, or `$CLAUDE_CONFIG_DIR/skills`.
    Claude,
}

impl Agent {
    const fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
        }
    }

    fn skills_dir(self) -> Result<PathBuf, String> {
        match self {
            Self::Claude => std::env::var_os("CLAUDE_CONFIG_DIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .or_else(|| std::env::home_dir().map(|home| home.join(".claude")))
                .filter(|dir| dir.is_absolute())
                .map(|dir| dir.join("skills"))
                .ok_or_else(|| "cannot find Claude Code's directory".to_owned()),
        }
    }
}

/// `erpc skills install`.
pub fn install(json: bool, agents: &[Agent]) -> Outcome {
    match install_all(agents) {
        Ok(done) => {
            if json {
                crate::print_json(&serde_json::Value::Array(
                    done.iter()
                        .map(|(place, dir, report)| {
                            serde_json::json!({
                                "place": place,
                                "dir": dir,
                                "written": report.written,
                                "unchanged": report.unchanged,
                                "kept": report.kept,
                                "removed": report.removed,
                            })
                        })
                        .collect(),
                ));
                return Outcome::Done(String::new());
            }
            Outcome::Done(
                done.iter()
                    .map(|(_, dir, report)| describe(dir, report))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
        }
        Err(e) => Outcome::Failed(e),
    }
}

type Installed = (&'static str, PathBuf, erpc_skills::install::Report);

fn install_all(agents: &[Agent]) -> Result<Vec<Installed>, String> {
    let state = session::state_dir()?;
    let root = state
        .parent()
        .ok_or("erpc's state directory has no parent")?
        .to_path_buf();
    let mut places = vec![("erpc", root.join("skills"))];
    for agent in agents {
        places.push((agent.name(), agent.skills_dir()?));
    }
    places
        .into_iter()
        .map(|(place, dir)| {
            let ledger = state.join(format!("skills-{place}.json"));
            erpc_skills::install::install(&dir, &ledger).map(|report| (place, dir, report))
        })
        .collect()
}

fn describe(dir: &std::path::Path, report: &erpc_skills::install::Report) -> String {
    use core::fmt::Write as _;
    let mut out = format!(
        "{}: {} written, {} already current",
        dir.display(),
        report.written.len(),
        report.unchanged.len()
    );
    if !report.removed.is_empty() {
        let _ = write!(out, ", removed {}", report.removed.join(", "));
    }
    if !report.kept.is_empty() {
        let _ = write!(
            out,
            "\n  left as they are (changed since erpc wrote them, or not erpc's): {}",
            report.kept.join(", ")
        );
    }
    out
}

/// Each place erpc installed skills to that an install now would change,
/// by its name (`erpc`, `claude`), with the skills that would change.
fn behind() -> Vec<(String, Vec<String>)> {
    let Ok(state) = session::state_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&state) else {
        return Vec::new();
    };
    let mut out: Vec<(String, Vec<String>)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let place = name
                .strip_prefix("skills-")?
                .strip_suffix(".json")?
                .to_owned();
            let changed = erpc_skills::install::stale(&entry.path()).ok()??;
            (!changed.is_empty()).then_some((place, changed))
        })
        .collect();
    out.sort();
    out
}

/// The command that brings `places` up to date.
fn sync_command(places: &[(String, Vec<String>)]) -> String {
    let mut command = "erpc skills sync".to_owned();
    for (place, _) in places {
        if place != "erpc" {
            command.push_str(" --agent ");
            command.push_str(place);
        }
    }
    command
}

/// What `erpc doctor` says about the skills on this machine.
pub(crate) fn finding() -> Option<crate::doctor::Finding> {
    let behind = behind();
    if behind.is_empty() {
        return None;
    }
    let what: Vec<String> = behind
        .iter()
        .map(|(place, names)| format!("{place} ({})", names.join(", ")))
        .collect();
    Some(crate::doctor::Finding::warn(
        "Skills",
        format!(
            "older than this erpc in {}; run `{}`",
            what.join("; "),
            sync_command(&behind)
        ),
    ))
}

/// Says once, at a terminal, that the skills on disk are behind the ones
/// this erpc carries: once per change of them, recorded beside the ledgers.
pub(crate) fn notice_once() {
    if !session::has_terminal() {
        return;
    }
    let Ok(state) = session::state_dir() else {
        return;
    };
    let marker = state.join("skills-noticed");
    let now = erpc_skills::install::fingerprint();
    if std::fs::read_to_string(&marker).is_ok_and(|seen| seen.trim() == now) {
        return;
    }
    let behind = behind();
    if behind.is_empty() {
        return;
    }
    crate::interrupt::say(&format!(
        "note: the skills on this machine are older than this erpc; `{}` updates them",
        sync_command(&behind)
    ));
    let _ = std::fs::write(&marker, now);
}

/// `erpc skills list`.
pub fn list(json: bool) -> Outcome {
    let skills = erpc_skills::all();
    if json {
        crate::print_json(&serde_json::Value::Array(
            skills
                .iter()
                .map(|s| serde_json::json!({ "name": s.name, "description": s.description }))
                .collect(),
        ));
        return Outcome::Done(String::new());
    }
    Outcome::Done(
        skills
            .iter()
            .map(|s| format!("{}\n  {}", s.name, s.description))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}
