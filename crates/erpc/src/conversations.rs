// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Conversations kept on disk, so `erpc resume` can pick one up.
//!
//! One JSON file per conversation under `~/.erpc/conversations/`, written
//! after every answer, so leaving the console -- or losing the terminal --
//! loses nothing that was answered. The files hold the conversation as the
//! model was sent it, which is what continuing it needs. They are the
//! operator's own words and the answers to them, so they are written for
//! the owner alone.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The format of a saved conversation.
const VERSION: u32 = 1;
/// How long a title is kept, in characters.
const TITLE_CHARS: usize = 60;

/// A conversation as saved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Saved {
    /// The format this was written in.
    pub version: u32,
    /// What `erpc resume` takes.
    pub id: String,
    /// The first question, shortened, to tell conversations apart.
    pub title: String,
    /// When it started and when it was last answered, in Unix seconds.
    pub created: i64,
    pub updated: i64,
    /// Whether it had reached the main model.
    pub settled: bool,
    /// The messages, as the model is sent them.
    pub messages: Vec<Value>,
    /// The messages summarised away to keep the conversation short, oldest
    /// first: kept so nothing said is lost.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archived: Vec<Value>,
}

/// What a list shows of a saved conversation: read without building its
/// messages, which can be long.
#[derive(Debug, Clone, Deserialize)]
pub struct Summary {
    version: u32,
    /// What `erpc resume` takes.
    pub id: String,
    /// The first question, shortened.
    pub title: String,
    /// When it was last answered, in Unix seconds.
    pub updated: i64,
}

/// Where one conversation is saved.
#[derive(Debug, Clone)]
pub struct Record {
    dir: PathBuf,
    id: String,
    created: i64,
    saved: bool,
    /// The first question as a title, fixed once known: after compaction
    /// the first message is the summary.
    title: Option<String>,
}

impl Record {
    /// A new conversation, not written until its first answer.
    ///
    /// # Errors
    ///
    /// Returns a message when there is no home directory to keep it in.
    pub fn new() -> Result<Self, String> {
        Ok(Self::new_in(dir()?))
    }

    fn new_in(dir: PathBuf) -> Self {
        let id = loop {
            let id = fresh_id();
            if !dir.join(format!("{id}.json")).exists() {
                break id;
            }
        };
        Self {
            dir,
            id,
            created: crate::commands::now(),
            saved: false,
            title: None,
        }
    }

    /// The record of a conversation that was saved before.
    ///
    /// # Errors
    ///
    /// Returns a message when there is no home directory.
    pub fn continuing(saved: &Saved) -> Result<Self, String> {
        Ok(Self {
            dir: dir()?,
            id: saved.id.clone(),
            created: saved.created,
            saved: true,
            title: Some(saved.title.clone()),
        })
    }

    /// The id `erpc resume` takes.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether anything has been written, so there is something to resume.
    pub const fn saved(&self) -> bool {
        self.saved
    }

    /// Writes the conversation, replacing what was written before.
    ///
    /// # Errors
    ///
    /// Returns a message when the file cannot be written.
    pub fn save(
        &mut self,
        messages: &[Value],
        archived: &[Value],
        settled: bool,
    ) -> Result<(), String> {
        let title = self
            .title
            .get_or_insert_with(|| {
                title(if archived.is_empty() {
                    messages
                } else {
                    archived
                })
            })
            .clone();
        let saved = Saved {
            version: VERSION,
            id: self.id.clone(),
            title,
            created: self.created,
            updated: crate::commands::now(),
            settled,
            messages: messages.to_vec(),
            archived: archived.to_vec(),
        };
        let text =
            serde_json::to_vec(&saved).map_err(|e| t!("conversations.not_saved", error = e))?;
        write_private(
            &self.dir,
            &self.dir.join(format!("{}.json", self.id)),
            &text,
        )?;
        self.saved = true;
        Ok(())
    }
}

/// Where conversations are kept: `conversations` beside `config.toml`.
///
/// # Errors
///
/// Returns a message when there is no home directory.
pub fn dir() -> Result<PathBuf, String> {
    crate::session::beside_config("conversations")
}

/// Reads one saved conversation.
///
/// # Errors
///
/// Returns a message when the id is not one this writes, or there is no
/// such conversation, or it cannot be read.
pub fn load(id: &str) -> Result<Saved, String> {
    load_in(&dir()?, id)
}

fn load_in(dir: &Path, id: &str) -> Result<Saved, String> {
    // Only the ids this writes, so an id can never name a path elsewhere.
    if id.len() != 8 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(t!("conversations.bad_id", id = format!("{id:?}")));
    }
    let path = dir.join(format!("{}.json", id.to_ascii_lowercase()));
    let text = std::fs::read(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => t!("conversations.no_such", id),
        _ => t!("conversations.unreadable", path = path.display(), error = e),
    })?;
    let saved: Saved = serde_json::from_slice(&text).map_err(|e| {
        t!(
            "conversations.not_a_conversation",
            path = path.display(),
            error = e
        )
    })?;
    if saved.version != VERSION {
        return Err(t!("conversations.other_version", id));
    }
    Ok(saved)
}

/// Every saved conversation, the most recently answered first. Files that
/// cannot be read are left out. Only what a list shows is read; [`load`]
/// reads the one chosen.
///
/// # Errors
///
/// Returns a message when the directory exists but cannot be read.
pub fn list() -> Result<Vec<Summary>, String> {
    list_in(&dir()?)
}

fn list_in(dir: &Path) -> Result<Vec<Summary>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(t!(
                "conversations.unreadable",
                path = dir.display(),
                error = e
            ));
        }
    };
    let mut all: Vec<Summary> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let id = name.to_str()?.strip_suffix(".json")?;
            if id.len() != 8 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            // The messages are skipped over, not built.
            let bytes = std::fs::read(entry.path()).ok()?;
            let summary: Summary = serde_json::from_slice(&bytes).ok()?;
            (summary.version == VERSION && summary.id.eq_ignore_ascii_case(id)).then_some(summary)
        })
        .collect();
    all.sort_by_key(|saved| std::cmp::Reverse(saved.updated));
    Ok(all)
}

/// The first thing asked, on one line and shortened.
fn title(messages: &[Value]) -> String {
    let first = messages
        .iter()
        .find(|m| m.get("role").and_then(Value::as_str) == Some("user"))
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let line: String = first.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > TITLE_CHARS {
        let short: String = line.chars().take(TITLE_CHARS - 1).collect();
        format!("{short}…")
    } else {
        line
    }
}

/// Eight hex digits, different each time: the clock, the process and the
/// standard library's per-process random keys, hashed together.
fn fresh_id() -> String {
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    hasher.write_u128(nanos);
    hasher.write_u32(std::process::id());
    format!("{:08x}", hasher.finish() & 0xFFFF_FFFF)
}

/// Writes `bytes` to `path` for the owner alone: the directory is made
/// private, and the file is written beside its target and renamed over it,
/// so a reader never sees half of it.
fn write_private(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| t!("conversations.not_created", path = dir.display(), error = e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    erpc_core::private_file::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Record, list_in, load_in, title};

    fn turn(question: &str) -> Vec<serde_json::Value> {
        vec![
            json!({"role": "user", "content": question}),
            json!({"role": "assistant", "content": [{"type": "text", "text": "answer"}]}),
        ]
    }

    #[test]
    fn a_saved_conversation_reads_back_and_is_listed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut record = Record::new_in(dir.path().to_path_buf());
        assert!(!record.saved());
        record
            .save(&turn("testnet に立てたい"), &[], true)
            .expect("saved");
        assert!(record.saved());
        let back = load_in(dir.path(), record.id()).expect("read back");
        assert_eq!(back.title, "testnet に立てたい");
        assert!(back.settled);
        assert_eq!(back.messages.len(), 2);
        let listed = list_in(dir.path()).expect("listed");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, record.id());
    }

    #[test]
    fn a_compacted_conversation_keeps_its_title_and_what_was_summarised() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut record = Record::new_in(dir.path().to_path_buf());
        record
            .save(&turn("first question"), &[], false)
            .expect("saved");
        let summary = turn("[erpc: a summary …]");
        record
            .save(&summary, &turn("first question"), false)
            .expect("saved");
        let back = load_in(dir.path(), record.id()).expect("read back");
        assert_eq!(back.title, "first question");
        assert_eq!(back.archived.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_can_read_a_conversation() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut record = Record::new_in(dir.path().join("conversations"));
        record.save(&turn("hi"), &[], false).expect("saved");
        let file = dir
            .path()
            .join("conversations")
            .join(format!("{}.json", record.id()));
        let mode = std::fs::metadata(file).expect("file").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn an_id_cannot_name_a_path_elsewhere() {
        let dir = tempfile::tempdir().expect("tempdir");
        for id in ["../../etc", "abc", "zzzzzzzz", "12345678/"] {
            let err = load_in(dir.path(), id).expect_err("refused");
            assert!(!err.is_empty(), "{id}");
        }
    }

    #[test]
    fn a_long_question_becomes_a_short_title() {
        let long = "word ".repeat(40);
        let t = title(&turn(&long));
        assert!(t.chars().count() <= 60, "{t}");
        assert!(t.ends_with('…'));
        assert_eq!(title(&[]), "");
    }
}
