// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the assistant remembers about the user from one conversation to
//! the next: short facts it saves with `remember` (their hosts, chains,
//! preferences, decisions) and drops with `forget`, kept in one file on
//! the user's machine and read into the system prompt when a conversation
//! starts. The user can list and delete them (`erpc memory`).
//!
//! Nothing that looks like a secret is kept: a fact naming a password or a
//! key, or holding a long run of key-like characters, is refused whatever
//! the model meant.

use core::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The most facts kept; the oldest goes when a new one would pass it.
pub const MAX_FACTS: usize = 40;
/// The longest fact, in characters.
pub const MAX_CHARS: usize = 200;

/// One remembered fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    /// What `forget` takes; never reused.
    pub id: u32,
    /// The fact.
    pub text: String,
    /// When it was saved, in Unix seconds.
    pub saved: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    next: u32,
    facts: Vec<Fact>,
}

/// The facts, kept in a JSON file for the owner alone.
#[derive(Debug, Clone)]
pub struct Memory {
    path: PathBuf,
}

/// Words that say a fact is about a secret.
const SECRET_WORDS: [&str; 18] = [
    "password",
    "passphrase",
    "recovery phrase",
    "recovery words",
    "secret phrase",
    "復元フレーズ",
    "リカバリーフレーズ",
    "private key",
    "secret key",
    "seed phrase",
    "mnemonic",
    "api key",
    "access token",
    "パスワード",
    "秘密鍵",
    "シードフレーズ",
    "ニーモニック",
    "begin openssh",
];

/// Phrases with a secret word in them that name a way of logging in, not a
/// secret: "password logins are off" is worth remembering.
const NOT_SECRETS: [&str; 7] = [
    "1password",
    "password login",
    "password authentication",
    "passwordless",
    "パスワードログイン",
    "パスワード認証",
    "パスワードなし",
];

/// Why `text` may not be kept, if it may not.
fn refused(text: &str) -> Option<&'static str> {
    // "1Password" is where secrets are kept, not one.
    let lower = NOT_SECRETS
        .iter()
        .fold(text.to_lowercase(), |t, phrase| t.replace(phrase, ""));
    if SECRET_WORDS.iter().any(|w| lower.contains(w)) {
        return Some("it names a secret; secrets are never remembered");
    }
    // A way of logging in named next to something shaped like a password
    // ("root password login is Tr0ub4dor&3"): the phrase let through above
    // does not let the password through with it.
    let whole = text.to_lowercase().replace("1password", "");
    if ["password", "パスワード"].iter().any(|w| whole.contains(w))
        && text
            .split_whitespace()
            .any(|w| !w.to_lowercase().contains("1password") && password_shaped(w))
    {
        return Some("it seems to hold a password; secrets are never remembered");
    }
    // A key, a token or a keypair: a long unbroken run of key characters
    // (a public key or an address is shorter), or a byte array.
    let longest_run = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-".contains(c)))
        .map(str::len)
        .max()
        .unwrap_or(0);
    if longest_run >= 60 {
        return Some("it holds something that looks like a key or a token");
    }
    if text.matches(',').count() >= 31 && text.chars().filter(char::is_ascii_digit).count() >= 32 {
        return Some("it holds something that looks like a keypair");
    }
    let words: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || "\"'`()[]{}<>,;".contains(c))
        .filter(|w| !w.is_empty())
        .collect();
    if words.iter().any(|w| token_shaped(w)) {
        return Some("it holds something that looks like a token or an API key");
    }
    // A recovery phrase: twelve or more short lowercase words in a row.
    // Prose has words of one or two letters, capitals or punctuation.
    let mut run = 0;
    for word in text.split_whitespace() {
        let seedy = (3..=8).contains(&word.len()) && word.bytes().all(|b| b.is_ascii_lowercase());
        run = if seedy { run + 1 } else { 0 };
        if run >= 12 {
            return Some("it holds something that looks like a recovery phrase");
        }
    }
    None
}

/// Whether `word` looks like a password: six or more characters with
/// letters and digits, or letters and symbols. A number, a name or a
/// hyphenated word does not.
fn password_shaped(word: &str) -> bool {
    let word = word.trim_matches(|c: char| ".,;:!?\"'()".contains(c));
    let letters = word.chars().any(char::is_alphabetic);
    let digits = word.chars().any(|c| c.is_ascii_digit());
    let symbols = word.chars().any(|c| "!@#$%^&*+=?~|<>".contains(c));
    word.chars().count() >= 6 && letters && (digits || symbols)
}

/// Prefixes that well-known services put on their secret tokens.
const TOKEN_PREFIXES: [&str; 12] = [
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "sk-",
    "sk_live_",
    "rk_live_",
    "xoxb-",
    "xoxp-",
    "AKIA",
];

/// Whether `word` looks like a token: a known secret prefix followed by
/// enough characters, or a UUID (as ERPC API keys are).
fn token_shaped(word: &str) -> bool {
    if TOKEN_PREFIXES
        .iter()
        .any(|p| word.starts_with(p) && word.len() >= p.len() + 16)
    {
        return true;
    }
    let parts: Vec<&str> = word.split('-').collect();
    parts.len() == 5
        && parts.iter().map(|p| p.len()).eq([8, 4, 4, 4, 12])
        && parts
            .iter()
            .all(|p| p.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl Memory {
    /// The memory kept at `path`.
    #[must_use]
    pub const fn at(path: PathBuf) -> Self {
        Self { path }
    }

    /// Where it is kept.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The file; empty when there is none yet. One that cannot be read is
    /// an error, never empty: saving over it would lose every fact.
    fn load(&self) -> Result<File, String> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                format!(
                    "{} is unreadable ({e}); fix it, or start again with `erpc memory clear`",
                    self.path.display()
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
            Err(e) => Err(format!("could not read {}: {e}", self.path.display())),
        }
    }

    fn store(&self, file: &File) -> Result<(), String> {
        let text = serde_json::to_vec_pretty(file).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(&self.path, &text)
    }

    /// Runs `change` holding the memory's lock, so two conversations saving
    /// at once never lose each other's facts.
    fn locked<T>(&self, change: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        erpc_core::private_file::locked(&self.path, change)
    }

    /// Every fact, oldest first.
    ///
    /// # Errors
    ///
    /// The file is there but cannot be read.
    pub fn facts(&self) -> Result<Vec<Fact>, String> {
        self.load().map(|file| file.facts)
    }

    /// Keeps `text`; returns its id. The same fact twice is kept once.
    ///
    /// # Errors
    ///
    /// Empty, too long, secret-looking, or the file cannot be written.
    pub fn remember(&self, text: &str, now: i64) -> Result<u32, String> {
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if text.is_empty() || text.chars().count() > MAX_CHARS {
            return Err(format!("a fact is 1 to {MAX_CHARS} characters"));
        }
        if let Some(why) = refused(&text) {
            return Err(format!("not remembered: {why}"));
        }
        self.locked(|| self.add(text, now))
    }

    fn add(&self, text: String, now: i64) -> Result<u32, String> {
        let mut file = self.load()?;
        if let Some(same) = file.facts.iter().find(|f| f.text == text) {
            return Ok(same.id);
        }
        file.next = file
            .next
            .max(file.facts.iter().map(|f| f.id).max().unwrap_or(0))
            + 1;
        let id = file.next;
        file.facts.push(Fact {
            id,
            text,
            saved: now,
        });
        if file.facts.len() > MAX_FACTS {
            file.facts.remove(0);
        }
        self.store(&file)?;
        Ok(id)
    }

    /// Drops fact `id`; whether there was one.
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub fn forget(&self, id: u32) -> Result<bool, String> {
        self.locked(|| {
            let mut file = self.load()?;
            let before = file.facts.len();
            file.facts.retain(|f| f.id != id);
            if file.facts.len() == before {
                return Ok(false);
            }
            self.store(&file)?;
            Ok(true)
        })
    }

    /// Drops every fact. The count of ids is kept, so an id a conversation
    /// already holds never comes to name a newer fact. A file that cannot
    /// be read is removed: this is the way out of one.
    ///
    /// # Errors
    ///
    /// The file cannot be written or removed.
    pub fn clear(&self) -> Result<(), String> {
        self.locked(|| match self.load() {
            Ok(file) => {
                let next = file
                    .next
                    .max(file.facts.iter().map(|f| f.id).max().unwrap_or(0));
                if next == 0 {
                    return Ok(());
                }
                self.store(&File {
                    next,
                    facts: Vec::new(),
                })
            }
            Err(_) => std::fs::remove_file(&self.path)
                .map_err(|e| format!("could not remove {}: {e}", self.path.display())),
        })
    }

    /// The facts as a system prompt block; `None` when there are none, or
    /// the file cannot be read (`erpc memory list` says why).
    #[must_use]
    pub fn prompt(&self) -> Option<String> {
        let facts = self.facts().ok()?;
        if facts.is_empty() {
            return None;
        }
        let mut text = String::from(
            "# What you remember about this user\n\nFrom earlier conversations, saved with \
             `remember` (the number is what `forget` takes). Use them; they may be out of date, \
             so check with a tool before acting on one.\n\n",
        );
        for fact in facts {
            let _ = writeln!(text, "- [{}] {}", fact.id, fact.text);
        }
        Some(text)
    }
}

/// What `remember` and `forget` take: their properties and the required
/// ones.
pub(crate) fn input_schema(name: &str) -> (Value, Value) {
    if name == "remember" {
        (
            json!({ "fact": { "type": "string", "maxLength": MAX_CHARS, "description": "One short fact, in the user's language, that will help in later conversations." } }),
            json!(["fact"]),
        )
    } else {
        (
            json!({ "id": { "type": "integer", "description": "The fact's number, as the remembered list shows it." } }),
            json!(["id"]),
        )
    }
}

/// `remember`: keeps a fact for later conversations.
pub(crate) fn remember(memory: Option<&Memory>, input: &Value, now: i64) -> Result<Value, String> {
    let memory = memory.ok_or("this erpc keeps no memory")?;
    let text = input
        .get("fact")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let id = memory.remember(text, now)?;
    Ok(json!({ "remembered": true, "id": id }))
}

/// `forget`: drops a remembered fact.
pub(crate) fn forget(memory: Option<&Memory>, input: &Value) -> Result<Value, String> {
    let memory = memory.ok_or("this erpc keeps no memory")?;
    let id = input
        .get("id")
        .and_then(Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
        .ok_or("id is the fact's number")?;
    Ok(json!({ "forgotten": memory.forget(id)? }))
}

#[cfg(test)]
mod tests {
    use super::{MAX_FACTS, Memory, refused};

    fn memory() -> (tempfile::TempDir, Memory) {
        let dir = tempfile::tempdir().expect("dir");
        let memory = Memory::at(dir.path().join("memory.json"));
        (dir, memory)
    }

    #[test]
    fn facts_are_kept_once_listed_and_forgotten() {
        let (_dir, memory) = memory();
        assert!(memory.prompt().is_none());
        let a = memory
            .remember("Runs Arc testnet node arc1", 1)
            .expect("kept");
        let b = memory
            .remember("Prefers answers in  Japanese", 2)
            .expect("kept");
        assert_eq!(memory.remember("Runs Arc testnet node arc1", 3), Ok(a));
        let prompt = memory.prompt().expect("facts");
        assert!(prompt.contains(&format!("- [{b}] Prefers answers in Japanese")));
        assert_eq!(memory.forget(a), Ok(true));
        assert_eq!(memory.forget(a), Ok(false));
        let c = memory.remember("Validator on tokyo", 4).expect("kept");
        assert!(c > b, "ids are not reused");
        memory.clear().expect("cleared");
        assert!(memory.facts().expect("read").is_empty());
        let d = memory.remember("Runs Sui later", 5).expect("kept");
        assert!(d > c, "not after a clear either");
    }

    #[test]
    fn the_oldest_goes_past_the_limit() {
        let (_dir, memory) = memory();
        for i in 0..=MAX_FACTS {
            memory.remember(&format!("fact {i}"), 0).expect("kept");
        }
        let facts = memory.facts().expect("read");
        assert_eq!(facts.len(), MAX_FACTS);
        assert_eq!(facts[0].text, "fact 1");
    }

    #[test]
    fn an_unreadable_file_is_never_written_over() {
        let (_dir, memory) = memory();
        std::fs::write(memory.path(), "[broken").expect("written");
        assert!(memory.facts().is_err());
        assert!(memory.remember("Runs a node", 1).is_err());
        assert!(memory.prompt().is_none());
        assert_eq!(
            std::fs::read_to_string(memory.path()).expect("read"),
            "[broken"
        );
    }

    #[test]
    fn nothing_that_looks_secret_is_kept() {
        for secret in [
            "The VPS password is hunter2",
            "Password logins are off; the password was hunter2",
            "ERPC key 3f2a9c1e-7b4d-4e8a-9f10-2c3d4e5f6a7b",
            "seed: abandon ability able about above absent absorb abstract absurd abuse access accident",
            "復元フレーズは金庫にある",
            "root password login is Tr0ub4dor&3",
            "password login works with hunter22",
            "秘密鍵は1Passwordにある",
            "key 4Nd1mY7Q9vXq2bJz8kL3pR6sT0wE5uH1aC9fG2hJ4kL6mN8pQ0rS2tU4vW6xY8zA0bC2dE4fG",
            "[12,34,56,78,90,12,34,56,78,90,12,34,56,78,90,12,34,56,78,90,12,34,56,78,90,12,34,56,78,90,12,34]",
        ] {
            assert!(refused(secret).is_some(), "{secret}");
        }
        // Put together here, so no scanner takes the test for a real token.
        let github = format!("GitHub token {}_{}", "ghp", "x".repeat(36));
        assert!(refused(&github).is_some(), "{github}");
        for fine in [
            "Validator identity 7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2",
            "EURC wallet 0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42",
            "Uses 1Password vault erpc-ops",
            "VPS 570059 is key-only: password logins are off",
            "VPS 570059 はパスワードログインをオフにした",
            "The user runs a testnet validator in Frankfurt and an Arc RPC node in London",
            "prefers short answers in japanese and wants every paid start confirmed first",
        ] {
            assert!(refused(fine).is_none(), "{fine}");
        }
    }
}
