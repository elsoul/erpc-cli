// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker import`: an app the operator already has, taken into erpc
//! worker as it is.
//!
//! An app made by `init` comes with its `erpc.toml`. One that exists
//! already has a directory, a way to build it and, usually, a `.env` file
//! and a note on how to run it. `import` reads that directory and writes
//! the `erpc.toml` it describes, so that `check`, `run` and `deploy` work
//! on it without a line of its code changed:
//!
//! - **How it is built:** a Cargo package is built as `deploy` builds any
//!   app. Anything else is built the operator's way, and the Linux binary
//!   that comes out is named with `--binary` (`build.prebuilt`): erpc ships
//!   it as it is.
//! - **Its settings:** the names in `.env.example` (and its like) and in
//!   `.env`. Values are copied only from the example files, which are
//!   written to be shared, and only where neither the name nor the value
//!   looks like a secret. Nothing is read out of `.env` but its names, and
//!   one port.
//! - **What needs a person:** a setting that looks like a secret, by its
//!   name or by a credential in its example's value, is named with the
//!   command that keeps it (`erpc worker secret put`), and a key file with
//!   the one that takes it in and wipes it.
//!
//! Nothing but `erpc.toml` is written in the app, and nothing in it is run.
//! The file is made new: when anything is at its path, a link included,
//! `import` refuses rather than write over it or through it.
//!
//! The directory may be anyone's, a repository cloned a minute ago. What
//! is read in it is a regular file inside it, up to [`MAX_TEXT`]: a link
//! that leads out of the directory, a pipe, a device and a file larger
//! than that are left unread, and each is said.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use erpc_worker::index;
use erpc_worker::manifest::{self, Chain, LineKind, Manifest, ManifestError, Services};
use serde_json::json;

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::worker::shell_word;

/// What `erpc worker import` was asked for.
pub(crate) struct Request<'a> {
    pub(crate) dir: Option<&'a Path>,
    pub(crate) name: Option<&'a str>,
    pub(crate) binary: Option<&'a str>,
    pub(crate) bin: Option<&'a str>,
    pub(crate) port: Option<u16>,
    pub(crate) health: Option<&'a str>,
    pub(crate) chain: Chain,
}

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

fn usage(message: impl Into<String>) -> CliError {
    CliError::new(Code::Usage, message)
}

/// How the app's binary comes to be.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Build {
    /// `cargo build --release`, and the binary's name when it is not the
    /// app's.
    Cargo { bin: Option<String> },
    /// A Linux binary built another way: its path inside the app.
    Prebuilt(String),
}

/// What the app's directory says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    name: String,
    build: Build,
    /// Plain settings and their values, from the example files.
    vars: Vec<(String, String)>,
    /// Settings with no value copied, each with the file that names it:
    /// an example with none to copy, or `.env`, whose values are not read.
    unset: Vec<(String, &'static str)>,
    /// Settings that look like secrets, by their name or by a credential
    /// in the example's value.
    secrets: Vec<String>,
    /// Settings a data line provides, with the flag that starts it.
    lines: Vec<(String, &'static str)>,
    /// Settings a service in `services` sets on the server, with the
    /// service: left out of `[vars]`, where one would be used in its place.
    served: Vec<(String, &'static str)>,
    port: Option<u16>,
    /// What gives the port something that is not one, and is not used:
    /// the setting (or `EXPOSE`) and its file.
    bad_ports: Vec<(String, &'static str)>,
    health: Option<String>,
    /// Files that look like a key, by name.
    key_files: Vec<String>,
    /// Files that look like a key and whose names are not printed, each
    /// as [`shown`] shows it.
    odd_keys: Vec<String>,
    /// Local services the app's compose file runs beside it.
    services: Services,
    /// Whether a Dockerfile or a compose file is there.
    docker: bool,
    /// The files that were there and were not read, each with why.
    unread: Vec<(String, Unread)>,
    /// Where a quoted value never closes, by its file: nothing after it
    /// was read there. With the setting's name when what stands before
    /// the `=` is one; text that is no name is not kept.
    unclosed: Vec<(Option<String>, &'static str)>,
    /// The example files read for their names only, being one file with
    /// another name.
    names_only: Vec<String>,
    /// How many lines of each dotenv file have, before their `=`, what no
    /// setting can be named: left out, and said by their number. What
    /// stands there is text of the file, in `.env` text that may be
    /// anything (a URL with its password, a line of a key), and is never
    /// shown.
    skipped: Vec<(&'static str, usize)>,
}

/// The files settings are read from: the ones written to be shared, whose
/// values are copied, then `.env`, whose are not.
const EXAMPLES: [&str; 5] = [
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    "env.example",
];

/// The settings that say which port an app listens on.
const PORT_NAMES: [&str; 6] = [
    "PORT",
    "API_PORT",
    "HTTP_PORT",
    "SERVER_PORT",
    "LISTEN_PORT",
    "APP_PORT",
];

/// The `NAME=value` settings of a dotenv file, with nothing expanded or
/// run: comments and blank lines skipped, a leading `export` taken off. A
/// name that is not one is left out.
///
/// A value that opens with a quote runs to the quote that closes it, over
/// as many lines as that takes: a line inside it is the value's, and is
/// never read as a setting of its own, whatever it is shaped like. A
/// quote that never closes takes the rest of the file, which then names
/// no setting, and its value is given as `None`: where it would have
/// ended is not known, so it is not a value to copy.
///
/// A byte order mark at the start, which editors on Windows write, is not
/// part of the first name.
fn dotenv(text: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut rest = text.strip_prefix('\u{feff}').unwrap_or(text);
    while !rest.is_empty() {
        let end = rest.find('\n').unwrap_or(rest.len());
        let after_line = rest.get(end + 1..).unwrap_or_default();
        let line = rest[..end].trim_start();
        let line = match line.strip_prefix("export") {
            Some(named) if named.starts_with([' ', '\t']) => named.trim_start(),
            _ => line,
        };
        let Some((name, value)) = line.split_once('=').filter(|_| !line.starts_with('#')) else {
            rest = after_line;
            continue;
        };
        // The value where it starts, with all that follows it: it may
        // run past the end of its line.
        let from = &rest[end - value.trim_start().len()..];
        let (value, after) = match from.chars().next() {
            Some(quote @ ('"' | '\'')) => quoted_value(&from[1..], quote),
            _ => unquoted_value(from),
        };
        rest = after;
        let name = name.trim();
        if !name.is_empty() {
            out.push((name.to_owned(), value));
        }
    }
    out
}

/// A quoted value, read from after the quote that opens it, and the text
/// after the line it closes on (what follows the closing quote there is a
/// comment). In double quotes a backslash keeps the character after it,
/// so `\"` does not close the value, and `\n` is a line break; in single
/// quotes nothing is special but the quote. `None` and no text left when
/// the quote never closes.
fn quoted_value(from: &str, quote: char) -> (Option<String>, &str) {
    let mut value = String::new();
    let mut chars = from.char_indices();
    while let Some((at, c)) = chars.next() {
        if c == quote {
            let after = from[at + 1..].split_once('\n').map_or("", |(_, rest)| rest);
            return (Some(value), after);
        }
        if c == '\\' && quote == '"' {
            match chars.next() {
                Some((_, 'n')) => value.push('\n'),
                Some((_, kept @ ('"' | '\\' | '$' | '`'))) => value.push(kept),
                Some((_, other)) => value.extend(['\\', other]),
                None => {}
            }
        } else {
            value.push(c);
        }
    }
    (None, "")
}

/// An unquoted value and the text after it: to the end of its line or to
/// a comment (` #`), and on to the next line when the line ends with a
/// backslash, as a shell joins them.
fn unquoted_value(from: &str) -> (Option<String>, &str) {
    let mut value = String::new();
    let mut rest = from;
    loop {
        let (line, after) = rest.split_once('\n').unwrap_or((rest, ""));
        rest = after;
        let line = line.trim_end();
        if let Some((text, _comment)) = line.split_once(" #") {
            value.push_str(text);
            break;
        }
        match line.strip_suffix('\\') {
            Some(joined) if !rest.is_empty() => value.push_str(joined),
            _ => {
                value.push_str(line);
                break;
            }
        }
    }
    (Some(value.trim_end().to_owned()), rest)
}

/// Whether a setting's name says its value is a secret. Wider than the
/// rule `check` warns by: a name taken for a secret costs one `secret put`,
/// and one missed puts a credential in a file that is committed.
fn secret_name(name: &str) -> bool {
    manifest::looks_secret(name)
        || [
            "KEY",
            "PASS",
            "CREDENTIAL",
            "WEBHOOK",
            "AUTH",
            "DSN",
            "COOKIE",
            "SIGNING",
        ]
        .iter()
        .any(|word| name.contains(word))
}

/// `text` as an app's name: lowercase letters, digits and single hyphens.
fn slug(text: &str) -> Option<String> {
    let mut out = String::new();
    for c in text.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_end_matches('-').to_owned();
    let out = out
        .trim_start_matches(|c: char| c.is_ascii_digit())
        .to_owned();
    manifest::is_slug(&out, 32).then_some(out)
}

/// Whether a terminal acts on `c` rather than shows it, or `c` changes
/// how the text around it is shown: a control character (an escape, a
/// line break), or a Unicode format character that hides or reorders
/// text. A file's name is whatever the repository's author made it.
fn unprintable(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2069}'
                | '\u{feff}'
        )
}

/// `text` as it is printed: each character a terminal would not show as
/// itself is a `?`.
fn shown(text: &str) -> String {
    text.chars()
        .map(|c| if unprintable(c) { '?' } else { c })
        .collect()
}

/// The package a `Cargo.toml` describes and the binary to build: the one
/// `asked` for, the only `[[bin]]`, or the package's own when it has a
/// `src/main.rs`. The names in it are the file's author's: what is said
/// of them is said as [`shown`].
fn cargo_package(
    text: &str,
    has_main: bool,
    asked: Option<&str>,
) -> Result<(String, String), String> {
    let doc: toml::Value = text.parse().map_err(|e: toml::de::Error| {
        t!("worker_import.cargo.unreadable", error = shown(e.message()))
    })?;
    let Some(package) = doc
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(toml::Value::as_str)
    else {
        return Err(if doc.get("workspace").is_some() {
            t!("worker_import.cargo.workspace")
        } else {
            t!("worker_import.cargo.no_package")
        });
    };
    let mut bins: Vec<String> = doc
        .get("bin")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|b| b.get("name").and_then(toml::Value::as_str))
        .map(ToOwned::to_owned)
        .collect();
    if has_main && !bins.iter().any(|b| b == package) {
        bins.push(package.to_owned());
    }
    let bin = match asked {
        Some(asked) if bins.iter().any(|b| b == asked) => asked.to_owned(),
        Some(asked) => {
            return Err(t!(
                "worker_import.cargo.no_such_bin",
                asked,
                bins = shown(&bins.join(", "))
            ));
        }
        None => match bins.as_slice() {
            [] => return Err(t!("worker_import.cargo.no_bin", package = shown(package))),
            [only] => only.clone(),
            _ => {
                return Err(t!(
                    "worker_import.cargo.several_bins",
                    bins = shown(&bins.join(", "))
                ));
            }
        },
    };
    Ok((package.to_owned(), bin))
}

/// The most that is read of a file in the app's directory: 1 MiB, far
/// more than a dotenv file, a Cargo.toml, a Dockerfile or a compose file
/// a person wrote.
const MAX_TEXT: u64 = 1024 * 1024;

/// Why a file in the app's directory was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unread {
    /// A link that leads outside the app's directory, or nowhere.
    Link,
    /// An example file that is a link, wherever it leads.
    LinkedExample,
    /// Not a regular file: a pipe, a device, a directory.
    NotAFile,
    /// Larger than [`MAX_TEXT`].
    TooLarge,
    /// Not UTF-8 text.
    NotText,
    /// The system would not open or read it, and why.
    Failed(String),
}

impl Unread {
    /// The line that says `file` was not read.
    fn said(&self, file: &str) -> String {
        match self {
            Self::Link => t!("worker_import.unread.link", file),
            Self::LinkedExample => t!("worker_import.unread.linked_example", file),
            Self::NotAFile => t!("worker_import.unread.not_a_file", file),
            Self::TooLarge => t!("worker_import.unread.too_large", file),
            Self::NotText => t!("worker_import.unread.not_text", file),
            Self::Failed(error) => t!("worker_import.unread.failed", file, error),
        }
    }

    /// The reason as one word, for a script.
    const fn code(&self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::LinkedExample => "linked_example",
            Self::NotAFile => "not_a_file",
            Self::TooLarge => "too_large",
            Self::NotText => "not_text",
            Self::Failed(_) => "unreadable",
        }
    }
}

/// What is known of a file that was opened, to tell whether it is one
/// file with another name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Opened {
    /// How many names it has (hard links); one where that is not told.
    names: u64,
    /// Its device and inode, where a file has them (Unix).
    id: Option<(u64, u64)>,
}

impl Opened {
    #[cfg(unix)]
    fn of(file: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            names: file.nlink(),
            id: Some((file.dev(), file.ino())),
        }
    }

    #[cfg(not(unix))]
    fn of(_file: &std::fs::Metadata) -> Self {
        Self { names: 1, id: None }
    }
}

/// What is done with a file that is a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Links {
    /// Followed to a file inside the app.
    Inside,
    /// Not followed: the file is read only when it is one itself.
    NotFollowed,
}

/// The text of the file `name` in the app at `root`, which is its real
/// path; `None` when there is no such file.
///
/// A link is followed only to a file inside the app ([`Links::Inside`]):
/// the values of a file elsewhere on the machine are not this app's to
/// copy. An example file is read with [`Links::NotFollowed`]: its values
/// are copied, and a link under its name could lead to a file whose values
/// are not for copying, the app's own `.env` among them. What the name
/// leads to is looked at before it is opened, since opening a pipe waits
/// for a writer and opening a device can do more than read it, and again
/// once open, so that it is the file looked at that is read. No more than
/// [`MAX_TEXT`] is read of it.
///
/// With the text comes what is known of the file that was opened
/// ([`Opened`]), taken from the open file, so that it is said of the file
/// that was read and not of what is under its name a moment later.
fn read_text(root: &Path, name: &str, links: Links) -> Result<Option<(String, Opened)>, Unread> {
    use std::io::Read as _;
    let failed = |e: std::io::Error| Unread::Failed(e.to_string());
    let named = root.join(name);
    let path = match std::fs::symlink_metadata(&named) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(failed(e)),
        Ok(link) if link.file_type().is_symlink() => match links {
            Links::NotFollowed => return Err(Unread::LinkedExample),
            Links::Inside => std::fs::canonicalize(&named)
                .ok()
                .filter(|target| target.starts_with(root))
                .ok_or(Unread::Link)?,
        },
        Ok(_) => named,
    };
    if !std::fs::symlink_metadata(&path).map_err(failed)?.is_file() {
        return Err(Unread::NotAFile);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path).map_err(failed)?;
    let opened = file.metadata().map_err(failed)?;
    if !opened.is_file() {
        return Err(Unread::NotAFile);
    }
    if opened.len() > MAX_TEXT {
        return Err(Unread::TooLarge);
    }
    let which = Opened::of(&opened);
    // One byte more than is allowed, to tell a file that grew since.
    let mut bytes = Vec::new();
    file.take(MAX_TEXT + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if bytes.len() as u64 > MAX_TEXT {
        return Err(Unread::TooLarge);
    }
    String::from_utf8(bytes)
        .map(|text| Some((text, which)))
        .map_err(|_| Unread::NotText)
}

/// The files of the app's directory as `import` reads them, and the ones
/// it would not read.
struct Files {
    /// The app's directory, as its real path: what a link's target is
    /// held against.
    root: PathBuf,
    unread: Vec<(String, Unread)>,
    /// The example files read for their names only.
    names_only: Vec<String>,
}

impl Files {
    fn of(root: &Path) -> Self {
        Self {
            root: std::fs::canonicalize(root).unwrap_or_else(|_| root.to_owned()),
            unread: Vec::new(),
            names_only: Vec::new(),
        }
    }

    /// The text of the file `name`, when it is there and was read; one
    /// that was not read is kept, to be said.
    fn text(&mut self, name: &str) -> Option<String> {
        self.read(name, Links::Inside).map(|(text, _)| text)
    }

    /// The text of the example file `name`, and whether its values are
    /// for copying. It is read only when it is a file itself, never
    /// through a link. Its values are not for copying when it is one file
    /// with another name, since what is under the other name may not have
    /// been written to be shared:
    ///
    /// - the file that was opened has more than one name (a hard link, to
    ///   `.env` or to any other file), which is told on Unix;
    /// - it is a dotenv file of the app that is no example
    ///   ([`Self::is_private`]).
    ///
    /// It is then read as `.env` is, and kept, to be said.
    fn example(&mut self, name: &str) -> Option<(String, bool)> {
        let (text, opened) = self.read(name, Links::NotFollowed)?;
        let shared = opened.names > 1 || self.is_private(name, opened);
        if shared {
            self.names_only.push(name.to_owned());
        }
        Some((text, !shared))
    }

    fn read(&mut self, name: &str, links: Links) -> Option<(String, Opened)> {
        read_text(&self.root, name, links).unwrap_or_else(|why| {
            self.unread.push((name.to_owned(), why));
            None
        })
    }

    /// Whether the example `name`, `opened` as it was read, is also a
    /// dotenv file of the app that is no example (`.env`, or `.env.` and
    /// anything): what is written through that name is then in this file.
    ///
    /// Told two ways. By the file's device and inode, on Unix: the same
    /// file, whatever names lead to it, and also when the example's name
    /// was given to another file while this one was being read. And by
    /// real paths, on every system: the other name is a link that leads
    /// to the example.
    fn is_private(&self, name: &str, opened: Opened) -> bool {
        let real = std::fs::canonicalize(self.root.join(name)).ok();
        let entries = std::fs::read_dir(&self.root)
            .into_iter()
            .flatten()
            .flatten();
        entries.into_iter().any(|entry| {
            let other = entry.file_name();
            let other = other.to_string_lossy();
            if !(other == ".env" || other.starts_with(".env.")) || EXAMPLES.contains(&&*other) {
                return false;
            }
            let path = entry.path();
            let same_file = opened.id.is_some()
                && std::fs::metadata(&path).is_ok_and(|other| Opened::of(&other).id == opened.id);
            let links_here = entry.file_type().is_ok_and(|kind| kind.is_symlink())
                && real.is_some()
                && std::fs::canonicalize(&path).ok() == real;
            same_file || links_here
        })
    }
}

/// Whether a file in the app's directory looks like a key by its name.
fn key_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), "wallet.json" | "id.json" | "keypair.json")
        || lower.ends_with(".keypair.json")
        || lower.ends_with("-keypair.json")
}

/// The files in the app's directory that look like a key: the ones that
/// can be named in a command, and the others, each as [`shown`] shows it.
/// A name with a character that is not printed, or that is not UTF-8, is
/// not put into a command: what is printed would not be the file's name.
fn key_files(root: &Path) -> (Vec<String>, Vec<String>) {
    let (mut named, mut odd) = (Vec::new(), Vec::new());
    for entry in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let lossy = name.to_string_lossy();
        if !key_file(&lossy) {
            continue;
        }
        match name.to_str() {
            Some(name) if !name.chars().any(unprintable) => named.push(name.to_owned()),
            _ => odd.push(shown(&lossy)),
        }
    }
    named.sort();
    odd.sort();
    (named, odd)
}

/// A port an app can listen on, from the text that names it: 1 to 65535.
fn port_of(text: &str) -> Option<u16> {
    text.trim().parse().ok().filter(|port| *port != 0)
}

/// The first port a Dockerfile exposes, and whether an `EXPOSE` names,
/// before it, something that is not one: `0`, a number past 65535, a
/// variable.
fn exposed(dockerfile: &str) -> (Option<u16>, bool) {
    let mut odd = false;
    for line in dockerfile.lines() {
        let mut words = line.split_whitespace();
        if !words
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("EXPOSE"))
        {
            continue;
        }
        for word in words {
            match port_of(word.split('/').next().unwrap_or_default()) {
                Some(port) => return (Some(port), odd),
                None => odd = true,
            }
        }
    }
    (None, odd)
}

/// The names a compose file goes by, in the order compose looks for them.
const COMPOSE: [&str; 4] = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
];

/// The local services a compose file runs beside the app: Redis and
/// PostgreSQL, each told by an entry under the top-level `services:`
/// whose `image:` is one, or which is named as one. The word anywhere
/// else says nothing: in a comment, in a `depends_on`, in a URL another
/// service is given, in a volume's name.
///
/// Read by its indentation, as compose files are written, not as YAML in
/// full: a file in flow style names no service here.
fn composed(text: &str) -> Services {
    let mut found = Services::default();
    let mut note = |name: &str| match name.to_ascii_lowercase().as_str() {
        "redis" | "redis-stack" | "redis-stack-server" => found.redis = true,
        "postgres" | "postgresql" => found.postgres = true,
        _ => {}
    };
    // Whether the line is under `services:`, and how far its entries and
    // each entry's own keys are indented.
    let (mut inside, mut entry, mut key) = (false, None, None);
    for line in text.lines() {
        let line = line.split(" #").next().unwrap_or_default().trim_end();
        let body = line.trim_start();
        let indent = line.len() - body.len();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        if indent == 0 {
            (inside, entry, key) = (body == "services:", None, None);
        } else if inside && indent <= *entry.get_or_insert(indent) {
            // An entry: its name, before the colon.
            key = None;
            let name = body.split(':').next().unwrap_or_default();
            note(name.trim().trim_matches(['"', '\'']));
        } else if inside && indent <= *key.get_or_insert(indent) {
            // One of the entry's keys. An image is `[host/]name[:tag]`
            // or `name@digest`: the name is its last part.
            let image = ["image: ", "image:\t"]
                .iter()
                .find_map(|key| body.strip_prefix(key))
                .map(|image| image.trim().trim_matches(['"', '\'']));
            if let Some(image) = image {
                let image = image.split('@').next().unwrap_or_default();
                let last = image.rsplit('/').next().unwrap_or_default();
                note(last.split(':').next().unwrap_or_default());
            }
        }
    }
    found
}

/// The app's settings, as its dotenv files name them.
#[derive(Default)]
struct Settings {
    vars: Vec<(String, String)>,
    unset: Vec<(String, &'static str)>,
    secrets: Vec<String>,
    lines: Vec<(String, &'static str)>,
    served: Vec<(String, &'static str)>,
    port: Option<u16>,
    bad_ports: Vec<(String, &'static str)>,
    unclosed: Vec<(Option<String>, &'static str)>,
    skipped: Vec<(&'static str, usize)>,
}

/// Reads the settings: values from the example files, names from `.env`.
/// `asked` is the port given on the command line, which wins; `services`
/// are the ones the app's erpc.toml will ask for.
///
/// Whose values are copied is decided by the file that was read, not by
/// the name it was asked for under: an example is read only when it is a
/// file itself, and one that is one file with another name is read as
/// `.env` is ([`Files::example`]).
fn settings(files: &mut Files, asked: Option<u16>, services: Services) -> Settings {
    let mut out = Settings {
        port: asked,
        ..Settings::default()
    };
    // Each setting with the file that names it, the examples first: the
    // first file to name one is where it is from.
    let mut named = Vec::new();
    for file in EXAMPLES.into_iter().chain([".env"]) {
        let (text, from) = if file == ".env" {
            (files.text(file), file)
        } else {
            match files.example(file) {
                Some((text, true)) => (Some(text), file),
                Some((text, false)) => (Some(text), ".env"),
                None => (None, file),
            }
        };
        let mut unnamed = 0;
        for (name, value) in text.iter().flat_map(|text| dotenv(text)) {
            // What stands before a line's first `=` is a setting's name
            // only when it can be one (capital letters, digits and `_`,
            // not one erpc or the server sets itself). Anything else is
            // text of the file: counted, and neither kept nor shown.
            let nameable = manifest::check_setting_name(&name).is_ok();
            if value.is_none() {
                out.unclosed.push((nameable.then(|| name.clone()), file));
            }
            if nameable {
                named.push((from, name, value));
            } else {
                unnamed += 1;
            }
        }
        if unnamed > 0 {
            out.skipped.push((file, unnamed));
        }
    }
    let provided = services.provided();
    let mut seen = BTreeSet::new();
    for (file, setting, value) in named {
        if !seen.insert(setting.clone()) {
            continue;
        }
        // What a port's setting gives: a port, or something that is none.
        let port = value
            .as_deref()
            .filter(|v| !v.is_empty() && PORT_NAMES.contains(&setting.as_str()))
            .map(port_of);
        match port {
            Some(Some(port)) => out.port = out.port.or(Some(port)),
            Some(None) => out.bad_ports.push((setting.clone(), file)),
            None => {}
        }
        // Out of `.env` nothing is taken but a port: a number, not a
        // secret, and the one value read there.
        let value = value.filter(|_| file != ".env" || matches!(port, Some(Some(_))));
        if let Some(kind) = LineKind::ALL.into_iter().find(|k| k.setting() == setting) {
            out.lines.push((setting, kind.flag()));
        } else if let Some((service, _)) = provided.iter().find(|(_, set)| *set == setting) {
            // The service on the server sets it. One written under [vars]
            // is used in its place, and would point the app at the
            // database of the machine the example was written on.
            out.served.push((setting, *service));
        } else if secret_name(&setting)
            || value.as_deref().is_some_and(|value| {
                // Only a value `[vars]` could hold is read for a
                // credential: a longer one is not copied whatever it is,
                // and reading for shapes takes longer than the value is
                // long.
                value.len() <= manifest::MAX_VAR_VALUE && manifest::carries_credential(value)
            })
        {
            // A credential in an example's value says what the setting is
            // for, placeholder or not: it is kept as a secret, not copied.
            out.secrets.push(setting);
        } else {
            // Copied when there is a value and `[vars]` can hold it: one
            // of several lines is named, as an empty one is.
            match value.filter(|v| !v.is_empty() && manifest::check_var_value(v).is_ok()) {
                Some(value) => out.vars.push((setting, value)),
                None => out.unset.push((setting, file)),
            }
        }
    }
    out
}

/// How the app is built and what it is called: the binary `--binary`
/// names, else the Cargo package in its directory.
fn built(root: &Path, req: &Request<'_>, files: &mut Files) -> Result<(String, Build), CliError> {
    let (build, default_name) = if let Some(path) = req.binary {
        let full = root.join(path);
        // A file of the app: one a link under that name leads to elsewhere
        // is refused here as `check` and a deploy refuse it.
        let inside = match (std::fs::canonicalize(root), std::fs::canonicalize(&full)) {
            (Ok(root), Ok(real)) => real.starts_with(root),
            _ => false,
        };
        if Path::new(path).is_absolute() || !full.is_file() || !inside {
            return Err(
                usage(t!("worker_import.no_binary", path, full = full.display()))
                    .hint(t!("worker_import.no_binary_hint")),
            );
        }
        let stem = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        (Build::Prebuilt(path.to_owned()), stem)
    } else if let Some(cargo) = files.text("Cargo.toml") {
        let has_main = root.join("src/main.rs").is_file();
        let (package, bin) = cargo_package(&cargo, has_main, req.bin).map_err(usage)?;
        (Build::Cargo { bin: Some(bin) }, package)
    } else if let Some((file, why)) = files.unread.first() {
        // A Cargo.toml that is there and was not read: said for what it
        // is, not as an app without one.
        return Err(usage(why.said(file)).hint(t!("worker_import.no_cargo_hint")));
    } else {
        return Err(usage(t!("worker_import.no_cargo", dir = root.display()))
            .hint(t!("worker_import.no_cargo_hint")));
    };
    let name = match req.name {
        Some(name) if manifest::is_slug(name, 32) => name.to_owned(),
        Some(name) => return Err(usage(t!("worker.init.bad_name", name))),
        None => slug(&default_name).ok_or_else(|| {
            usage(t!("worker_import.no_name", from = shown(&default_name)))
                .hint(t!("worker_import.no_name_hint"))
        })?,
    };
    // The binary is named only when it is not the app's own name.
    let build = match build {
        Build::Cargo { bin } => Build::Cargo {
            bin: bin.filter(|b| *b != name),
        },
        prebuilt @ Build::Prebuilt(_) => prebuilt,
    };
    Ok((name, build))
}

/// Reads the app's directory.
fn survey(root: &Path, req: &Request<'_>) -> Result<Found, CliError> {
    if req.port == Some(0) {
        return Err(usage(t!("worker_import.bad_port_flag")));
    }
    let mut files = Files::of(root);
    let (name, build) = built(root, req, &mut files)?;
    // What runs it today: the services beside it decide which settings
    // the server gives it.
    let dockerfile = files.text("Dockerfile");
    let compose = COMPOSE.iter().find_map(|file| files.text(file));
    let services = compose.as_deref().map(composed).unwrap_or_default();
    let Settings {
        vars,
        unset,
        secrets,
        lines,
        served,
        port,
        mut bad_ports,
        unclosed,
        skipped,
    } = settings(&mut files, req.port, services);
    // The Dockerfile's port when no setting names one.
    let port = port.or_else(|| {
        let (port, odd) = exposed(dockerfile.as_deref()?);
        bad_ports.extend(odd.then(|| ("EXPOSE".to_owned(), "Dockerfile")));
        port
    });
    let (key_files, odd_keys) = key_files(root);
    let health = match (req.health, port) {
        (Some(path), Some(_)) if path.starts_with('/') => Some(path.to_owned()),
        (Some(path), _) => return Err(usage(t!("worker_import.bad_health", path))),
        (None, _) => None,
    };
    Ok(Found {
        name,
        build,
        vars,
        unset,
        secrets,
        lines,
        served,
        port,
        bad_ports,
        health,
        key_files,
        odd_keys,
        services,
        docker: dockerfile.is_some() || compose.is_some(),
        unread: files.unread,
        unclosed,
        names_only: files.names_only,
        skipped,
    })
}

/// A TOML basic string holding `value`, on one line: a line break in a
/// value is written as `\n`, so that no line of a value is a line of the
/// file, and a control character as its escape.
fn quoted(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The `erpc.toml` `found` describes.
fn manifest_text(found: &Found, chain: Chain) -> String {
    use std::fmt::Write as _;
    let name = &found.name;
    let mut out = format!(
        "# {name}: an erpc worker app, taken in by erpc worker import.\n\
         # Run erpc worker check to see what it describes and what is missing.\n\
         # erpc copied no value into it that it recognised as a secret. The file is\n\
         # meant to be committed, and is yours to read before you commit it: a\n\
         # secret in a shape erpc does not know would be under [vars] as written.\n\n\
         name  = {}\nchain = \"{chain}\"\n",
        quoted(name)
    );
    match &found.build {
        Build::Cargo { bin: Some(bin) } => {
            let _ = write!(
                out,
                "\n# Built with `cargo build --release`; the binary cargo makes is named\n\
                 # after its package, not the app.\n[build]\nbin = {}\n",
                quoted(bin)
            );
        }
        Build::Cargo { bin: None } => {}
        Build::Prebuilt(path) => {
            let _ = write!(
                out,
                "\n# A Linux binary built outside erpc: `build` and `deploy` ship it as it is.\n\
                 # Build it again before a deploy that should carry a change.\n\
                 [build]\nprebuilt = {}\n",
                quoted(path)
            );
        }
    }
    if let Some(port) = found.port {
        out.push_str(
            "\n[run]\n# The port the app listens on, which [env.<name>.firewall] app_allow opens on\n\
             # the server. It stays closed until app_allow lists someone.\n",
        );
        let _ = writeln!(out, "port = {port}");
        if let Some(path) = &found.health {
            // The host and port first, then the path: a loopback address.
            let mut url = format!("http://127.0.0.1:{port}");
            url.push_str(path);
            let _ = writeln!(
                out,
                "# How a fresh start is judged healthy: this answers 2xx once the app is ready.\n\
                 health = {{ http = {}, timeout_secs = 30 }}",
                quoted(&url)
            );
        }
    }
    out.push_str(
        "\n# What else an app can have, each a table of its own:\n#\n\
         # [secrets]    secret settings, as references to where they are kept, never the\n\
         #              values themselves. The secret put verb keeps a value and writes\n\
         #              its reference; the app reads it as an environment variable.\n\
         # [services]   `redis = true` or `postgres = true`: a local Redis or PostgreSQL\n\
         #              on the server, installed and started by deploy (REDIS_URL,\n\
         #              DATABASE_URL).\n\
         # [wallet]     a trading key, taken in by the key import verb and handed to\n\
         #              the app on a pipe when it starts.\n\
         # [env.<name>] where it is deployed; written by a deploy.\n",
    );
    served_text(found, &mut out);
    secrets_text(found, &mut out);
    vars_text(found, &mut out);
    out
}

/// The settings taken for secrets, as comments in the `erpc.toml` `found`
/// describes. What import says is said once; the file is what is read
/// before a deploy, and a setting that is in neither `[vars]` nor
/// `[secrets]` is one the app is deployed without.
fn secrets_text(found: &Found, out: &mut String) {
    use std::fmt::Write as _;
    if found.secrets.is_empty() {
        return;
    }
    out.push_str(
        "\n# Taken for secrets, by their name or by what an example gave them, so no\n\
         # value is in this file. The app is deployed without each until it is kept:\n\
         # the secret put verb keeps a value and writes its reference under [secrets].\n\
         # One that is no secret after all is set under [vars].\n",
    );
    for setting in &found.secrets {
        let _ = writeln!(out, "#   {setting}");
    }
}

/// The `[vars]` table of the `erpc.toml` `found` describes: the values
/// copied, then, as comments, the settings none was copied for, under
/// the reason: the example had none to copy, or only `.env` names it.
fn vars_text(found: &Found, out: &mut String) {
    use std::fmt::Write as _;
    if found.vars.is_empty() && found.unset.is_empty() {
        return;
    }
    out.push_str("\n# Plain settings, given to the app as environment variables.\n[vars]\n");
    for (setting, value) in &found.vars {
        let _ = writeln!(out, "{setting} = {}", quoted(value));
    }
    let (in_env, in_examples): (Vec<_>, Vec<_>) =
        found.unset.iter().partition(|(_, file)| *file == ".env");
    for (settings, why) in [
        (
            in_examples,
            "# In an example file with no value erpc could copy (none, one of several\n\
             # lines, or one longer than 4096 bytes): set each here when it is not a\n\
             # secret, or keep it with the secret put verb when it is.\n",
        ),
        (
            in_env,
            "# Named only where erpc reads no values (.env, or an example file that is\n\
             # one file with another name): set each here when it is not a secret, or\n\
             # keep it with the secret put verb when it is.\n",
        ),
    ] {
        if !settings.is_empty() {
            out.push_str(why);
        }
        for (setting, _) in settings {
            let _ = writeln!(out, "# {setting} = \"\"");
        }
    }
}

/// The `[services]` table of the `erpc.toml` `found` describes, and the
/// settings left out of `[vars]` because the server is given them: by a
/// service there, or by a data line.
fn served_text(found: &Found, out: &mut String) {
    use std::fmt::Write as _;
    if !found.services.is_empty() {
        out.push_str("\n# The compose file runs these beside the app; deploy puts them on the server.\n[services]\n");
        if found.services.redis {
            out.push_str("redis    = true\n");
        }
        if found.services.postgres {
            out.push_str("postgres = true\n");
        }
    }
    if !found.served.is_empty() || !found.lines.is_empty() {
        out.push_str(
            "\n# Not under [vars], where a value would be used in place of the one the\n\
             # server is given:\n",
        );
        for (setting, service) in &found.served {
            let _ = writeln!(
                out,
                "#   {setting}: set by the {service} service above, for the one deploy installs."
            );
        }
        for (setting, flag) in &found.lines {
            let _ = writeln!(
                out,
                "#   {setting}: set by an ERPC data line, which --{flag} on deploy starts."
            );
        }
    }
}

/// The commands to run next, in order, for the app at `root`. `app_scope`
/// names the app after a verb that takes it as its argument; `flag_scope`
/// after one whose own arguments come first (`key import`, `secret put`),
/// which take it by `--dir`.
///
/// A key file is named by its whole path, quoted for the shell: `key
/// import` reads the file from the directory the command is run in, which
/// need not be the app's, and then wipes it. A name is whatever the
/// directory holds, so nothing of it is left for a shell to act on.
fn next_steps(found: &Found, root: &Path, app_scope: &str, flag_scope: &str) -> Vec<String> {
    use std::fmt::Write as _;
    let mut next = Vec::new();
    {
        let dir_scope = flag_scope;
        next.extend(found.key_files.iter().map(|file| {
            let file = shell_word(&root.join(file).to_string_lossy());
            format!("erpc worker key import {file} --wipe{dir_scope}")
        }));
        next.extend(
            found
                .secrets
                .iter()
                .map(|setting| format!("erpc worker secret put {setting}{dir_scope}")),
        );
    }
    let dir_scope = app_scope;
    next.push(format!("erpc worker check{dir_scope}"));
    if matches!(found.build, Build::Cargo { .. }) {
        next.push(format!("erpc worker run{dir_scope}"));
    }
    let flags = found
        .lines
        .iter()
        .fold(String::new(), |mut flags, (_, flag)| {
            let _ = write!(flags, " --{flag}");
            flags
        });
    // A new app has no environment but the default one, which a deploy
    // without `--env` means: its scope is the app's.
    let scope = app_scope;
    next.push(format!("erpc worker deploy{scope}{flags}"));
    next
}

/// How the next steps name the app at `root`: after a verb that takes the
/// app as its argument, and after one that takes it by `--dir`. `listed`
/// is the directory erpc's list has under the app's name, when it has
/// exactly one: by its name when that is this app, else by its directory.
/// Another app of the same name on the list makes the name ambiguous, and
/// a step that used it would fail.
fn scopes(name: &str, root: &Path, listed: Option<&Path>) -> (String, String) {
    if listed == Some(root) {
        crate::worker::name_scopes(name)
    } else {
        let by_dir = crate::worker::Dir::at(root).scope();
        (by_dir.clone(), by_dir)
    }
}

/// `erpc worker import`.
pub(crate) fn import(json: bool, req: &Request<'_>) -> Outcome {
    match imported(json, req) {
        Ok(outcome) => outcome,
        Err(e) => e.into(),
    }
}

fn imported(json: bool, req: &Request<'_>) -> Result<Outcome, CliError> {
    let root = match req.dir {
        Some(dir) => dir.to_owned(),
        None => std::env::current_dir().map_err(|e| failed(t!("worker.find.no_cwd", error = e)))?,
    };
    let root = std::fs::canonicalize(&root)
        .map_err(|e| usage(t!("worker_import.no_dir", dir = root.display(), error = e)))?;
    let (found, path) = written(&root, req)?;
    let indexed = crate::session::beside_config(index::FILE_NAME)
        .and_then(|p| index::update(&p, |i| Ok(((), i.remember(&found.name, &root)?))))
        .err();
    let listed = indexed
        .is_none()
        .then(|| crate::worker::by_name(&found.name).ok())
        .flatten();
    let (app_scope, flag_scope) = scopes(&found.name, &root, listed.as_deref());
    let next = next_steps(&found, &root, &app_scope, &flag_scope);
    if json {
        crate::print_json(&as_json(&found, &root, &path, indexed.is_none(), &next));
        return Ok(Outcome::Done(String::new()));
    }
    Ok(Outcome::Done(
        report(&found, &path, indexed.as_deref(), &next, &flag_scope).text(),
    ))
}

/// What `import` found and wrote, for a script.
fn as_json(
    found: &Found,
    root: &Path,
    path: &Path,
    indexed: bool,
    next: &[String],
) -> serde_json::Value {
    let names = |pairs: &[(String, &'static str)]| -> Vec<String> {
        pairs.iter().map(|(name, _)| name.clone()).collect()
    };
    json!({
        "name": found.name,
        "dir": root,
        "manifest": path,
        "build": match &found.build {
            Build::Cargo { bin } => json!({ "cargo": true, "bin": bin }),
            Build::Prebuilt(binary) => json!({ "prebuilt": binary }),
        },
        "vars": found.vars.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        "unset": names(&found.unset),
        "unset_from": found.unset.iter().cloned().collect::<std::collections::BTreeMap<_, _>>(),
        "secrets": found.secrets,
        "lines": names(&found.lines),
        "services": found.services.provided().iter().map(|(s, _)| s).collect::<Vec<_>>(),
        "served": names(&found.served),
        "port": found.port,
        "ports_skipped": found.bad_ports.iter().map(|(name, file)| {
            json!({ "file": file, "name": name })
        }).collect::<Vec<_>>(),
        "health": found.health,
        "key_files": found.key_files,
        "key_files_unnamed": found.odd_keys,
        "unread": found.unread.iter().map(|(file, why)| {
            json!({ "file": file, "why": why.code() })
        }).collect::<Vec<_>>(),
        "unclosed": found.unclosed.iter().map(|(name, file)| {
            json!({ "file": file, "name": name })
        }).collect::<Vec<_>>(),
        "names_only": found.names_only,
        "names_skipped": found.skipped.iter().map(|(file, count)| {
            json!({ "file": file, "count": count })
        }).collect::<Vec<_>>(),
        "indexed": indexed,
        "next": next,
    })
}

/// Reads the app at `root` and writes the `erpc.toml` it describes, which
/// must not be there yet.
fn written(root: &Path, req: &Request<'_>) -> Result<(Found, PathBuf), CliError> {
    let path = root.join(manifest::FILE_NAME);
    nothing_at(&path)?;
    let found = survey(root, req)?;
    let text = manifest_text(&found, req.chain);
    // What is written is what `check` reads: a file it would refuse is a
    // fault here, said before anything is written.
    Manifest::parse(&text).map_err(|e| {
        let error = match &e {
            ManifestError::Invalid(problems) => problems.join("; "),
            other => other.to_string(),
        };
        failed(t!("worker_import.invalid", error = shown(&error)))
    })?;
    write_new(&path, &text)?;
    Ok((found, path))
}

/// Refuses when anything is at `path`, said before the app is read: an
/// `erpc.toml`, or a link (one that leads nowhere too), a directory or a
/// pipe under its name. `exists` would follow a link and call one that
/// leads nowhere absent.
fn nothing_at(path: &Path) -> Result<(), CliError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(there) if there.is_file() => {
            let dir_scope = crate::worker::manifest_scope(path);
            Err(failed(t!("worker_import.exists", path = path.display()))
                .hint(t!("worker_import.exists_hint", dir_scope)))
        }
        Ok(_) => Err(in_the_way(path)),
        Err(e) => Err(not_written(path, &e)),
    }
}

fn in_the_way(path: &Path) -> CliError {
    failed(t!("worker_import.in_the_way", path = path.display()))
        .hint(t!("worker_import.in_the_way_hint"))
}

fn not_written(path: &Path, error: &std::io::Error) -> CliError {
    failed(t!(
        "worker_import.not_written",
        path = path.display(),
        error
    ))
}

/// Writes `text` to a file made new at `path`. Making it new fails on
/// anything that is there and follows no link, so one planted at the path,
/// or put there since [`nothing_at`] looked, is never written through: a
/// cloned repository cannot aim this file at one outside it.
fn write_new(path: &Path, text: &str) -> Result<(), CliError> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => in_the_way(path),
            _ => not_written(path, &e),
        })?;
    file.write_all(text.as_bytes()).map_err(|e| {
        // The file is this run's own: half an erpc.toml is not left
        // behind to be read as one.
        let _ = std::fs::remove_file(path);
        not_written(path, &e)
    })
}

/// What `import` says it found and wrote.
fn report(
    found: &Found,
    path: &Path,
    unlisted: Option<&str>,
    next: &[String],
    dir_scope: &str,
) -> crate::ui::Report {
    let built = match &found.build {
        Build::Cargo { bin } => t!(
            "worker_import.built.cargo",
            bin = bin.as_deref().unwrap_or(&found.name)
        ),
        Build::Prebuilt(binary) => t!("worker_import.built.prebuilt", binary),
    };
    let mut fields = vec![(t!("worker_import.field.build"), built)];
    if let Some(port) = found.port {
        fields.push((t!("worker_import.field.port"), port.to_string()));
    }
    if !found.vars.is_empty() {
        let names: Vec<&str> = found.vars.iter().map(|(n, _)| n.as_str()).collect();
        fields.push((t!("worker_import.field.vars"), names.join(", ")));
    }
    let mut out = crate::ui::Report::new()
        .done(t!("worker_import.done", name = found.name))
        .detail(crate::ui::tidy(path))
        .fields(fields);
    if !found.secrets.is_empty() {
        out = out.warning(t!(
            "worker_import.secrets",
            names = found.secrets.join(", ")
        ));
    }
    let (in_env, in_examples): (Vec<_>, Vec<_>) =
        found.unset.iter().partition(|(_, file)| *file == ".env");
    let names = |settings: &[&(String, &str)]| -> String {
        let names: Vec<&str> = settings.iter().map(|(name, _)| name.as_str()).collect();
        names.join(", ")
    };
    if !in_examples.is_empty() {
        let files: BTreeSet<&str> = in_examples.iter().map(|(_, file)| *file).collect();
        let files = files.into_iter().collect::<Vec<_>>().join(", ");
        out = out.warning(t!(
            "worker_import.unset_example",
            files,
            names = names(&in_examples)
        ));
    }
    if !in_env.is_empty() {
        out = out.warning(t!("worker_import.unset", names = names(&in_env)));
    }
    for (name, file) in &found.bad_ports {
        out = out.warning(t!("worker_import.bad_port", file, name));
    }
    for (file, why) in &found.unread {
        out = out.warning(why.said(file));
    }
    for (name, file) in &found.unclosed {
        out = out.warning(match name {
            Some(name) => t!("worker_import.unclosed", file, name = shown(name)),
            None => t!("worker_import.unclosed_line", file),
        });
    }
    for file in &found.names_only {
        out = out.warning(t!("worker_import.names_only", file));
    }
    for (file, count) in &found.skipped {
        out = out.warning(tn!("worker_import.skipped", *count, file));
    }
    if !found.key_files.is_empty() {
        out = out.warning(t!(
            "worker_import.key_files",
            files = found.key_files.join(", "),
            dir_scope
        ));
    }
    if !found.odd_keys.is_empty() {
        out = out.warning(t!(
            "worker_import.key_files_odd",
            files = found.odd_keys.join(", "),
            dir_scope
        ));
    }
    if !found.lines.is_empty() {
        let names: Vec<&str> = found.lines.iter().map(|(n, _)| n.as_str()).collect();
        out = out.info(t!("worker_import.lines", names = names.join(", ")));
    }
    if !found.served.is_empty() {
        let names: Vec<String> = found
            .served
            .iter()
            .map(|(setting, service)| format!("{setting} ({service})"))
            .collect();
        out = out.info(t!("worker_import.served", names = names.join(", ")));
    }
    if found.docker {
        out = out.info(t!("worker_import.docker"));
    }
    if matches!(found.build, Build::Prebuilt(_)) {
        out = out.info(t!("worker_import.prebuilt_note"));
    }
    out = out.info(t!("worker_import.state"));
    if let Some(error) = unlisted {
        out = out.warning(t!("worker.init.unlisted", error));
    }
    out.next(next.iter().cloned())
}

#[cfg(test)]
mod tests {
    use super::{
        Build, Found, Links, MAX_TEXT, Request, Unread, cargo_package, dotenv, manifest_text,
        next_steps, slug, survey, written,
    };

    /// A file read as every file but an example is: a link is followed to
    /// a file inside the app.
    fn read_text(root: &std::path::Path, name: &str) -> Result<Option<String>, Unread> {
        super::read_text(root, name, Links::Inside).map(|read| read.map(|(text, _)| text))
    }
    use crate::worker::shell_word;
    use erpc_worker::manifest::{Chain, Manifest, Services};

    fn request<'a>() -> Request<'a> {
        Request {
            dir: None,
            name: None,
            binary: None,
            bin: None,
            port: None,
            health: None,
            chain: Chain::Solana,
        }
    }

    #[test]
    fn a_dotenv_file_gives_its_names_and_values_and_runs_nothing() {
        let read = dotenv(
            "# a comment\n\nPORT=8080\nexport NAME = \"my bot\"\nQUOTED='a b'\n\
             URL=http_like_value # the rest is a comment\nEMPTY=\nNOT A SETTING\n=value\n\
             SUB=$(rm -rf nothing)\n",
        );
        assert_eq!(
            read,
            [
                ("PORT", "8080"),
                ("NAME", "my bot"),
                ("QUOTED", "a b"),
                ("URL", "http_like_value"),
                ("EMPTY", ""),
                ("SUB", "$(rm -rf nothing)"),
            ]
            .map(|(n, v)| (n.to_owned(), Some(v.to_owned())))
        );
    }

    /// The settings `text` gives, with `-` for a value whose quote never
    /// closes.
    fn settings_of(text: &str) -> Vec<(String, String)> {
        dotenv(text)
            .into_iter()
            .map(|(name, value)| (name, value.unwrap_or_else(|| "-".to_owned())))
            .collect()
    }

    fn pairs<const N: usize>(pairs: [(&str, &str); N]) -> Vec<(String, String)> {
        pairs
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .to_vec()
    }

    /// What the review found: a value over several lines, whose later
    /// lines are shaped like settings. They are the value's.
    #[test]
    fn a_quoted_value_runs_to_its_closing_quote_over_any_lines() {
        let seeds = "TOTP_SEEDS=\"FIRSTSEEDLINE====\nSECONDSEEDLINE====\nTHIRD=x\n\"\nAFTER=1\n";
        assert_eq!(
            settings_of(seeds),
            pairs([
                (
                    "TOTP_SEEDS",
                    "FIRSTSEEDLINE====\nSECONDSEEDLINE====\nTHIRD=x\n"
                ),
                ("AFTER", "1"),
            ])
        );
        // Single quotes, where a backslash is a character like any other,
        // and `export` before the name.
        assert_eq!(
            settings_of("export PEM='line one\\\nINNER=2\n# not a comment\n'\nAFTER=1\n"),
            pairs([
                ("PEM", "line one\\\nINNER=2\n# not a comment\n"),
                ("AFTER", "1"),
            ])
        );
        // A quote escaped inside double quotes does not close the value,
        // nor does the other kind of quote.
        assert_eq!(
            settings_of(
                "MOTD=\"she said \\\"hi\\\"\nINNER=\\\"2\\\"\nit's \\\\ fine\" # closed\nAFTER=1\n"
            ),
            pairs([
                ("MOTD", "she said \"hi\"\nINNER=\"2\"\nit's \\ fine"),
                ("AFTER", "1"),
            ])
        );
        // An escaped line break, and an escape that is none.
        assert_eq!(
            settings_of("A=\"one\\ntwo \\d\"\nB=''\nC=\"\"\n"),
            pairs([("A", "one\ntwo \\d"), ("B", ""), ("C", "")])
        );
    }

    #[test]
    fn a_quote_that_never_closes_takes_the_rest_of_the_file() {
        for open in ["\"", "'"] {
            let text = format!("BEFORE=1\nOPEN={open}first\nINNER=2\nexport ALSO=3\n");
            assert_eq!(
                settings_of(&text),
                pairs([("BEFORE", "1"), ("OPEN", "-")]),
                "{text}"
            );
        }
        // An escaped quote at the very end closes nothing either.
        assert_eq!(settings_of("OPEN=\"x\\\"\nINNER=2"), pairs([("OPEN", "-")]));
    }

    #[test]
    fn an_unquoted_value_ends_at_its_line_unless_a_backslash_joins_the_next() {
        assert_eq!(
            settings_of(
                "LIST=one,\\\nTWO=2,\\\n  three # the end\nAFTER=1\r\nNOTE=a # c \\\nLAST=x\\"
            ),
            pairs([
                ("LIST", "one,TWO=2,  three"),
                ("AFTER", "1"),
                ("NOTE", "a"),
                ("LAST", "x\\"),
            ])
        );
        // A quote inside an unquoted value is a character of it.
        assert_eq!(
            settings_of("MOTD=don't panic\nAFTER=1\n"),
            pairs([("MOTD", "don't panic"), ("AFTER", "1")])
        );
    }

    #[test]
    fn no_line_of_a_value_reaches_erpc_toml_as_a_name() {
        let dir = bot();
        let seeds = "TOTP_SEEDS=\"FIRSTSEEDLINE====\nSECONDSEEDLINE====\n\"\nREGION=tokyo\n";
        std::fs::write(dir.path().join(".env"), seeds).expect("a .env");
        std::fs::write(
            dir.path().join(".env.example"),
            "GREETING=\"hello, world\"\nBANNER=\"line one\nFAKE_NAME=inside\n\"\n\
             OPEN='never closed\nLOST=1\n",
        )
        .expect("an example");
        let found = survey(dir.path(), &request()).expect("read");
        assert_eq!(found.vars, pairs([("GREETING", "hello, world")]));
        // Named and not copied: a value of several lines, which [vars]
        // does not hold, the one that never closed, and what only `.env`
        // has.
        assert_eq!(
            found.unset,
            [
                ("BANNER", ".env.example"),
                ("OPEN", ".env.example"),
                ("REGION", ".env")
            ]
            .map(|(name, file)| (name.to_owned(), file))
        );
        assert_eq!(found.secrets, ["TOTP_SEEDS"]);
        let text = manifest_text(&found, Chain::Solana);
        for line in [
            "SECONDSEEDLINE",
            "FIRSTSEEDLINE",
            "FAKE_NAME",
            "LOST",
            "never closed",
        ] {
            assert!(!text.contains(line), "{line} reached erpc.toml:\n{text}");
        }
        let m = Manifest::parse(&text).expect("a manifest check accepts");
        assert_eq!(m.vars.len(), 1, "{:?}", m.vars);
    }

    #[test]
    fn a_value_is_written_on_one_line_and_reads_back_as_it_was() {
        for value in [
            "plain",
            "",
            "two\nlines\r\n",
            "a \"quote\" and a \\ backslash",
            "tab\there",
            "bell \u{7} escape \u{1b}[31m del \u{7f} c1 \u{85}",
            "日本語 and ✓",
        ] {
            let written = super::quoted(value);
            assert!(!written.contains(char::is_control), "{written:?}");
            let read: toml::Table = format!("v = {written}").parse().expect("TOML");
            assert_eq!(read["v"].as_str(), Some(value), "{written}");
        }
    }

    #[test]
    fn a_name_is_made_from_what_the_package_or_binary_is_called() {
        assert_eq!(slug("my_trading_bot").as_deref(), Some("my-trading-bot"));
        assert_eq!(slug("Sniper.v2").as_deref(), Some("sniper-v2"));
        assert_eq!(slug("--bot--").as_deref(), Some("bot"));
        assert_eq!(slug("9lives").as_deref(), Some("lives"));
        assert_eq!(slug("ボット"), None, "nothing a name can be made of");
        assert_eq!(slug(&"x".repeat(40)), None, "too long to be a name");
    }

    #[test]
    fn a_cargo_package_names_the_binary_to_build() {
        let one = "[package]\nname = \"sniper\"\n";
        assert_eq!(
            cargo_package(one, true, None),
            Ok(("sniper".to_owned(), "sniper".to_owned()))
        );
        // No src/main.rs and no [[bin]]: a library, nothing to run.
        assert!(cargo_package(one, false, None).is_err());
        let two =
            "[package]\nname = \"tools\"\n[[bin]]\nname = \"bot\"\n[[bin]]\nname = \"probe\"\n";
        let several = cargo_package(two, false, None).expect_err("which one");
        assert!(several.contains("bot, probe"), "{several}");
        assert_eq!(
            cargo_package(two, false, Some("probe")),
            Ok(("tools".to_owned(), "probe".to_owned()))
        );
        assert!(cargo_package(two, false, Some("nope")).is_err());
        // A workspace root is not an app.
        let workspace = cargo_package("[workspace]\nmembers = [\"a\"]\n", false, None)
            .expect_err("a workspace");
        assert!(workspace.contains("workspace"), "{workspace}");
        assert!(cargo_package("not toml =", false, None).is_err());
        // A name in it is said without what a terminal would act on.
        let odd =
            "[package]\nname = \"tools\"\n[[bin]]\nname = \"a\\u001b[2J\"\n[[bin]]\nname = \"b\"\n";
        let said = cargo_package(odd, false, None).expect_err("which one");
        assert!(said.contains("a?[2J, b"), "{said:?}");
        let said = cargo_package(odd, false, Some("c")).expect_err("no such one");
        assert!(!said.contains('\u{1b}'), "{said:?}");
    }

    /// An existing bot's directory: a Cargo package with a `.env`, an
    /// example of it, a key file and a compose file.
    fn bot() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a directory");
        let write = |name: &str, text: &str| {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
            std::fs::write(path, text).expect("a file");
        };
        write(
            "Cargo.toml",
            "[package]\nname = \"my_bot\"\nversion = \"0.1.0\"\n",
        );
        write("src/main.rs", "fn main() {}\n");
        write(
            ".env.example",
            "PORT=8080\nLOG_LEVEL=info\nRPC_URL=\nAPI_TOKEN=changeme\nGRPC_ENDPOINT=\n\
             FEED=wss_host/?token=abc\nlowercase=skipped\n",
        );
        write(
            ".env",
            "PORT=9090\nLOG_LEVEL=debug\nPRIVATE_KEY=5Jsecretsecretsecret\nREGION=tokyo\n\
             WEBHOOK_URL=hooks_value\n",
        );
        write("wallet.json", "[1,2,3]");
        write(
            "docker-compose.yml",
            "services:\n  cache:\n    image: redis:7\n",
        );
        dir
    }

    #[test]
    fn an_apps_directory_is_read_without_its_secret_values() {
        let dir = bot();
        let found = survey(dir.path(), &request()).expect("read");
        assert_eq!(found.name, "my-bot");
        assert_eq!(
            found.build,
            Build::Cargo {
                bin: Some("my_bot".to_owned())
            }
        );
        // Values come from the example file only; the example's port wins.
        assert_eq!(found.port, Some(8080));
        assert_eq!(
            found.vars,
            [("PORT", "8080"), ("LOG_LEVEL", "info")].map(|(n, v)| (n.to_owned(), v.to_owned()))
        );
        // Named, never valued: an empty example, and what only `.env` has.
        assert_eq!(
            found.unset,
            [("RPC_URL", ".env.example"), ("REGION", ".env")]
                .map(|(name, file)| (name.to_owned(), file))
        );
        // A secret by its name, or by the credential its example carries.
        assert_eq!(
            found.secrets,
            ["API_TOKEN", "FEED", "PRIVATE_KEY", "WEBHOOK_URL"]
        );
        assert_eq!(found.lines, [("GRPC_ENDPOINT".to_owned(), "grpc")]);
        assert_eq!(found.key_files, ["wallet.json"]);
        assert!(found.services.redis && !found.services.postgres && found.docker);

        let text = manifest_text(&found, Chain::Solana);
        for secret in [
            "5Jsecretsecretsecret",
            "hooks_value",
            "changeme",
            "debug",
            "tokyo",
            "abc",
        ] {
            assert!(
                !text.contains(secret),
                "{secret} reached erpc.toml:\n{text}"
            );
        }
        let m = Manifest::parse(&text).expect("a manifest check accepts");
        assert_eq!(m.name, "my-bot");
        assert_eq!(m.bin(), "my_bot");
        assert_eq!(m.run.port, Some(8080));
        assert!(m.services.redis);
        assert_eq!(m.vars.get("LOG_LEVEL").map(String::as_str), Some("info"));
        assert!(m.secrets.is_empty() && m.wallet.is_none());
        assert!(m.warnings().is_empty(), "{:?}", m.warnings());
    }

    /// A credential's shape, joined from parts so that no file holds one
    /// whole: the gates that look for real ones read this file too.
    fn joined(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn a_credential_in_an_examples_value_is_kept_as_a_secret_not_copied() {
        let dir = bot();
        let jwt = joined(&[
            "eyJ",
            "hbGciOiJIUzI1NiJ9",
            ".",
            "eyJ",
            "zdWIiOiIxIn0",
            ".",
            "c2ln",
        ]);
        // Under names that say nothing: only the value tells.
        let hostile = [
            (
                "UPSTREAM",
                joined(&["https", "://user:hunter2", "@", "rpc-host/"]),
            ),
            ("STORE", joined(&["postgres", "://admin:pw", "@", "db/app"])),
            ("HEADER", format!("Bearer {jwt}")),
            ("BILLING", joined(&["sk_", "live_", "abc123"])),
            ("BUCKET_ID", joined(&["AKIA", "ABCDEFGHIJKLMNOP"])),
            ("FORGE", joined(&["ghp", "_", "abc123"])),
            (
                "NOTIFY",
                joined(&["https", "://", "hooks.slack.com", "/services/", "T0/B0/x"]),
            ),
            ("FEED", "rpc-host/?api-key=abc".to_owned()),
        ];
        let example: String = hostile
            .iter()
            .map(|(name, value)| format!("{name}={value}\n"))
            .chain(["LOG_LEVEL=info\nLABELS=key=value\n".to_owned()])
            .collect();
        std::fs::write(dir.path().join(".env.example"), example).expect("an example");
        std::fs::remove_file(dir.path().join(".env")).expect("no .env");
        let found = survey(dir.path(), &request()).expect("read");
        let names: Vec<&str> = hostile.iter().map(|(name, _)| *name).collect();
        assert_eq!(found.secrets, names);
        // What only looks like one is a plain setting still.
        assert_eq!(
            found.vars,
            [("LOG_LEVEL", "info"), ("LABELS", "key=value")]
                .map(|(n, v)| (n.to_owned(), v.to_owned()))
        );
        let text = manifest_text(&found, Chain::Solana);
        for (name, value) in &hostile {
            assert!(!text.contains(value.as_str()), "{name} reached erpc.toml");
        }
        let m = Manifest::parse(&text).expect("a manifest check accepts");
        assert!(m.credentials_in_vars().is_empty());
        // Each is named with the command that keeps it.
        let next = next_steps(&found, dir.path(), " bot", " --dir bot");
        assert!(next.contains(&"erpc worker secret put UPSTREAM --dir bot".to_owned()));
        assert!(text.contains("no value into it that it recognised as a secret"));
    }

    #[test]
    fn a_service_is_told_by_an_entry_of_the_compose_file_not_by_the_word() {
        let (redis, postgres, both, none) = (
            Services {
                redis: true,
                postgres: false,
            },
            Services {
                redis: false,
                postgres: true,
            },
            Services {
                redis: true,
                postgres: true,
            },
            Services::default(),
        );
        // By its image, with a registry, a tag or a digest, quoted or not.
        for (compose, told) in [
            ("services:\n  cache:\n    image: redis:7-alpine\n", redis),
            (
                "services:\n  db:\n    image: \"docker.io/library/postgres:16\"\n",
                postgres,
            ),
            (
                "services:\n  db:\n    restart: always\n    image: bitnami/postgresql@sha256:0a\n",
                postgres,
            ),
            // By its name, built from a Dockerfile of its own.
            ("services:\n  redis:\n    build: ./redis\n", redis),
            (
                "version: \"3\"\nservices:\n    bot:\n        build: .\n    Postgres:\n        build: db\n\
                 \n    redis:\n        image: 'redis'\n",
                both,
            ),
            // The word where it names no service: a comment, a service
            // taken out, what another service depends on and is given,
            // a volume, another tool's image, a key under another table.
            (
                "# redis and postgres ran here once\nservices:\n  bot:\n    build: .\n",
                none,
            ),
            (
                "services:\n  bot:\n    build: .\n#  cache:\n#    image: redis:7\n",
                none,
            ),
            (
                "services:\n  bot:\n    build: .  # talks to redis\n    depends_on:\n      - redis\n\
                 \x20   environment:\n      REDIS_URL: redis-address\n      image: postgres\n",
                none,
            ),
            (
                "services:\n  bot:\n    build: .\nvolumes:\n  redis:\n  postgres:\n",
                none,
            ),
            (
                "services:\n  metrics:\n    image: tools/redis_exporter:1\n  ui:\n    image: pgadmin\n",
                none,
            ),
            ("x-defaults:\n  redis:\n    image: redis\n", none),
            ("", none),
        ] {
            assert_eq!(super::composed(compose), told, "{compose}");
        }
    }

    /// What the review found: PostgreSQL in the compose file and the
    /// address of the developer's own in the example. Written together,
    /// `[vars]` wins on the server, and the app is pointed at a role the
    /// PostgreSQL deploy installs does not have.
    #[test]
    fn a_setting_a_service_provides_is_left_out_of_vars() {
        let dir = bot();
        let local = joined(&["postgres", "://app:devpass", "@", "localhost/app"]);
        std::fs::write(
            dir.path().join(".env.example"),
            format!("DATABASE_URL={local}\nREDIS_URL=redis-at-home\nLOG_LEVEL=info\n"),
        )
        .expect("an example");
        std::fs::write(dir.path().join(".env"), "DATABASE_URL=other\n").expect("a .env");
        std::fs::write(
            dir.path().join("docker-compose.yml"),
            "services:\n  db:\n    image: postgres:16\n",
        )
        .expect("a compose file");
        let found = survey(dir.path(), &request()).expect("read");
        assert!(found.services.postgres && !found.services.redis);
        assert_eq!(found.served, [("DATABASE_URL".to_owned(), "postgres")]);
        // Redis is not asked for: its address is the app's own setting.
        assert_eq!(
            found.vars,
            pairs([("REDIS_URL", "redis-at-home"), ("LOG_LEVEL", "info")])
        );
        assert!(
            found.secrets.is_empty() && found.unset.is_empty(),
            "{found:?}"
        );
        let text = manifest_text(&found, Chain::Solana);
        assert!(!text.contains("devpass"), "{text}");
        assert!(
            text.contains("#   DATABASE_URL: set by the postgres service above"),
            "{text}"
        );
        let m = Manifest::parse(&text).expect("a manifest check accepts");
        assert!(m.services.postgres);
        assert!(!m.vars.contains_key("DATABASE_URL"), "{:?}", m.vars);
        let said = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            super::report(&found, dir.path(), None, &[], "").text()
        });
        assert!(said.contains("DATABASE_URL (postgres)"), "{said}");
        // Without the service the same line is the app's own, and its
        // password keeps it out of [vars] all the same.
        std::fs::remove_file(dir.path().join("docker-compose.yml")).expect("removed");
        let found = survey(dir.path(), &request()).expect("read");
        assert!(found.served.is_empty());
        assert_eq!(found.secrets, ["DATABASE_URL"]);
    }

    #[test]
    fn the_next_steps_take_the_key_and_the_secrets_in_first() {
        let dir = bot();
        let found = survey(dir.path(), &request()).expect("read");
        // The key file by its whole path: `key import` reads it from the
        // directory the step is run in, and that may be any.
        let wallet = shell_word(&dir.path().join("wallet.json").to_string_lossy());
        assert_eq!(
            next_steps(&found, dir.path(), " my-bot", " --dir my-bot"),
            [
                &format!("erpc worker key import {wallet} --wipe --dir my-bot"),
                "erpc worker secret put API_TOKEN --dir my-bot",
                "erpc worker secret put FEED --dir my-bot",
                "erpc worker secret put PRIVATE_KEY --dir my-bot",
                "erpc worker secret put WEBHOOK_URL --dir my-bot",
                "erpc worker check my-bot",
                "erpc worker run my-bot",
                "erpc worker deploy my-bot --grpc",
            ]
        );
    }

    /// The words of `line` as a POSIX shell splits it, and nothing when
    /// the shell would do more than split: an expansion, a second
    /// command, a redirection or a pattern, left outside single quotes.
    fn sh_words(line: &str) -> Option<Vec<String>> {
        let mut words = Vec::new();
        let mut word: Option<String> = None;
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            match c {
                ' ' | '\t' => words.extend(word.take()),
                '\'' => {
                    let word = word.get_or_insert_with(String::new);
                    loop {
                        match chars.next()? {
                            '\'' => break,
                            c => word.push(c),
                        }
                    }
                }
                '\\' => word.get_or_insert_with(String::new).push(chars.next()?),
                c if "\"$`;&|()<>*?[]{}~#!\n\r".contains(c) => return None,
                c => word.get_or_insert_with(String::new).push(c),
            }
        }
        words.extend(word);
        Some(words)
    }

    fn parses(words: &[String]) -> bool {
        <crate::Cli as clap::Parser>::try_parse_from(words).is_ok()
    }

    /// The words `erpc` is run with when `step` is given to `sh` in
    /// `cwd`, with `erpc` a function that writes them out.
    #[cfg(unix)]
    fn words_sh_runs(step: &str, cwd: &std::path::Path) -> Vec<String> {
        let script = format!(
            "erpc() {{ for word in \"$@\"; do printf '%s\\000' \"$word\"; done; }}\n{step}\n"
        );
        let out = std::process::Command::new("sh")
            .args(["-c", &script])
            .current_dir(cwd)
            .output()
            .expect("sh");
        assert!(out.status.success(), "{step}: {out:?}");
        let mut words: Vec<String> = String::from_utf8(out.stdout)
            .expect("UTF-8")
            .split('\0')
            .map(ToOwned::to_owned)
            .collect();
        assert_eq!(words.pop().as_deref(), Some(""), "{step}");
        words
    }

    /// What the review found: a file's name went into the steps as it
    /// was. Given to a shell, `x;touch INJECTED;-keypair.json` ran
    /// `touch`; printed, an escape in a name reached the terminal.
    #[cfg(unix)]
    #[test]
    fn a_key_files_name_is_nothing_a_shell_or_a_terminal_acts_on() {
        let dir = bot();
        let root = std::fs::canonicalize(dir.path()).expect("its real path");
        let hostile = [
            "$(touch INJECTED2)-keypair.json",
            "-keypair.json",
            "`touch INJECTED3`-keypair.json",
            "it's a key && more > out-keypair.json",
            "x;touch INJECTED;-keypair.json",
        ];
        let odd = [
            "\u{1b}[31mred-keypair.json",
            "two\nlines-keypair.json",
            "\u{202e}txt.-keypair.json",
        ];
        for name in hostile.iter().chain(&odd) {
            std::fs::write(root.join(name), "[1,2,3]").expect("a key file");
        }
        let found = survey(&root, &request()).expect("read");
        // Named in a step: every name that can be printed. The others
        // are told apart and shown with the character replaced.
        let mut named: Vec<&str> = hostile.iter().copied().chain(["wallet.json"]).collect();
        named.sort_unstable();
        assert_eq!(found.key_files, named);
        assert_eq!(
            found.odd_keys,
            [
                "?[31mred-keypair.json",
                "?txt.-keypair.json",
                "two?lines-keypair.json"
            ]
        );
        // Each step is one command, to a parser that splits as a shell
        // does and to a shell: the file by its whole path, as one word.
        let next = next_steps(&found, &root, " my-bot", " --dir my-bot");
        let elsewhere = tempfile::tempdir().expect("another directory");
        for (step, name) in next.iter().zip(&found.key_files) {
            let file = root.join(name).to_string_lossy().into_owned();
            let meant = [
                "erpc", "worker", "key", "import", &file, "--wipe", "--dir", "my-bot",
            ];
            let words = sh_words(step).unwrap_or_else(|| panic!("more than words: {step}"));
            assert_eq!(words, meant, "{step}");
            assert_eq!(words_sh_runs(step, elsewhere.path()), meant[1..], "{step}");
        }
        for step in &next {
            let words = sh_words(step).unwrap_or_else(|| panic!("more than words: {step}"));
            assert!(parses(&words), "`{step}` does not parse");
        }
        let made: Vec<_> = std::fs::read_dir(elsewhere.path()).expect("it").collect();
        assert!(made.is_empty(), "a step did more than run erpc: {made:?}");
        // Nothing a terminal acts on is printed, as text or as JSON.
        let said = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            super::report(
                &found,
                &root.join("erpc.toml"),
                None,
                &next,
                " --dir my-bot",
            )
            .text()
        });
        let json = super::as_json(&found, &root, &root.join("erpc.toml"), true, &next).to_string();
        for out in [&said, &json] {
            assert!(
                !out.chars().any(|c| c != '\n' && super::unprintable(c)),
                "{out:?}"
            );
            assert!(!out.contains("u001b") && !out.contains("u202e"), "{out}");
            assert!(out.contains("?[31mred-keypair.json"), "{out}");
        }
        assert!(said.contains("rename each"), "{said}");
    }

    #[test]
    fn an_app_whose_name_another_has_is_named_by_its_directory() {
        use erpc_worker::index::Index;
        let (one, two) = (bot(), bot());
        for dir in [&one, &two] {
            std::fs::write(
                dir.path().join("erpc.toml"),
                "name = \"my-bot\"\nchain = \"solana\"\n",
            )
            .expect("its erpc.toml");
        }
        let by_name = (" my-bot".to_owned(), " --dir my-bot".to_owned());
        let by_dir = |dir: &tempfile::TempDir| {
            let scope = format!(" --dir {}", shell_word(&dir.path().to_string_lossy()));
            (scope.clone(), scope)
        };
        // The only app of its name on the list: named by it.
        let mut index = Index::default();
        index.remember("my-bot", one.path()).expect("absolute");
        let listed = crate::worker::named(&index, "my-bot").ok();
        assert_eq!(listed.as_deref(), Some(one.path()));
        assert_eq!(
            super::scopes("my-bot", one.path(), listed.as_deref()),
            by_name
        );
        // A second one: the name finds neither, and each step would fail
        // as ambiguous. Named by its directory, each parses.
        index.remember("my-bot", two.path()).expect("absolute");
        let listed = crate::worker::named(&index, "my-bot").ok();
        assert_eq!(listed, None);
        let (app, flag) = super::scopes("my-bot", two.path(), listed.as_deref());
        assert_eq!((app.clone(), flag.clone()), by_dir(&two));
        let found = survey(two.path(), &request()).expect("read");
        for step in next_steps(&found, two.path(), &app, &flag) {
            let words = sh_words(&step).unwrap_or_else(|| panic!("more than words: {step}"));
            assert!(parses(&words), "`{step}` does not parse");
            assert!(step.contains(&two.path().display().to_string()), "{step}");
        }
        // A name the list has for another directory is not this app's.
        assert_eq!(
            super::scopes("my-bot", two.path(), Some(one.path())),
            by_dir(&two)
        );
    }

    #[test]
    fn a_binary_built_another_way_is_shipped_as_it_is() {
        let dir = tempfile::tempdir().expect("a directory");
        std::fs::create_dir(dir.path().join("dist")).expect("dist");
        std::fs::write(dir.path().join("dist/Sniper_Go"), b"\x7fELF").expect("a binary");
        let req = Request {
            binary: Some("dist/Sniper_Go"),
            port: Some(8080),
            health: Some("/healthz"),
            ..request()
        };
        let found = survey(dir.path(), &req).expect("read");
        assert_eq!(found.name, "sniper-go");
        assert_eq!(found.build, Build::Prebuilt("dist/Sniper_Go".to_owned()));
        let text = manifest_text(&found, Chain::Solana);
        let m = Manifest::parse(&text).expect("a manifest check accepts");
        assert_eq!(m.build.prebuilt.as_deref(), Some("dist/Sniper_Go"));
        let health = m.run.health.expect("health").http.expect("a url");
        assert!(health.ends_with(":8080/healthz"), "{health}");
        // It cannot be run here by building it: the steps go to the deploy.
        assert!(
            !next_steps(&found, dir.path(), "", "")
                .iter()
                .any(|s| s.contains(" run"))
        );

        // A binary that is not there, a path that is not a path, a
        // directory with nothing to build: each refused, nothing written.
        for bad in [
            Request {
                binary: Some("dist/absent"),
                ..request()
            },
            Request {
                binary: Some("/bin/sh"),
                ..request()
            },
            Request {
                health: Some("healthz"),
                port: Some(1),
                binary: Some("dist/Sniper_Go"),
                ..request()
            },
            request(),
        ] {
            assert!(survey(dir.path(), &bad).is_err());
        }
        assert!(!dir.path().join("erpc.toml").exists());
    }

    #[test]
    fn the_manifest_is_written_new_and_never_over_one_that_is_there() {
        let dir = bot();
        let (found, path) = written(dir.path(), &request()).expect("written");
        assert_eq!(found.name, "my-bot");
        assert_eq!(path, dir.path().join("erpc.toml"));
        let text = std::fs::read_to_string(&path).expect("the file");
        assert_eq!(Manifest::parse(&text).expect("valid").name, "my-bot");
        // A second import is refused with the check to run, and the file
        // is as it was.
        std::fs::write(&path, "name = \"mine\"\nchain = \"solana\"\n").expect("edited");
        let again = written(dir.path(), &request()).expect_err("there already");
        assert!(
            again
                .hint
                .is_some_and(|hint| hint.contains("erpc worker check --dir "))
        );
        let kept = std::fs::read_to_string(&path).expect("the file");
        assert!(kept.contains("mine"), "{kept}");
    }

    /// What the review found: a repository with `erpc.toml` as a link to a
    /// path outside it, which nothing is at yet. `exists` called it absent
    /// and the write went through it.
    #[cfg(unix)]
    #[test]
    fn a_link_at_erpc_toml_is_never_written_through() {
        use std::os::unix::fs::symlink;
        let dir = bot();
        let outside = tempfile::tempdir().expect("another directory");
        let target = outside.path().join("planted-profile");
        let link = dir.path().join("erpc.toml");
        symlink(&target, &link).expect("a link that leads nowhere");
        written(dir.path(), &request()).expect_err("refused");
        assert!(!target.exists(), "the import wrote through the link");
        // The write itself refuses, for a link put there after the look.
        let write_new = super::write_new;
        write_new(&link, "name = \"x\"\n").expect_err("refused");
        assert!(!target.exists(), "the write went through the link");
        // A link to a file that is there: refused, the file untouched.
        std::fs::write(&target, "mine").expect("a file outside");
        written(dir.path(), &request()).expect_err("refused");
        write_new(&link, "name = \"x\"\n").expect_err("refused");
        assert_eq!(std::fs::read_to_string(&target).expect("it"), "mine");
        // The link is still a link, and nothing else was made beside it.
        let still = std::fs::symlink_metadata(&link).expect("the link");
        assert!(still.file_type().is_symlink());
        // A directory under the name is in the way too.
        std::fs::remove_file(&link).expect("unlinked");
        std::fs::create_dir(&link).expect("a directory");
        written(dir.path(), &request()).expect_err("refused");
    }

    #[test]
    fn only_a_bounded_regular_file_is_read() {
        let dir = bot();
        let root = std::fs::canonicalize(dir.path()).expect("its real path");
        assert_eq!(read_text(&root, "absent"), Ok(None));
        let text = read_text(&root, ".env.example").expect("read");
        assert!(text.is_some_and(|text| text.starts_with("PORT=8080")));
        // A directory under a file's name, and text that is not UTF-8.
        assert_eq!(read_text(&root, "src"), Err(Unread::NotAFile));
        std::fs::write(root.join("latin"), b"NAME=caf\xe9\n").expect("a file");
        assert_eq!(read_text(&root, "latin"), Err(Unread::NotText));
        // A file of exactly the most that is read, and one byte more:
        // sparse, so nothing of that size is written.
        let sized = |name: &str, len: u64| {
            let file = std::fs::File::create(root.join(name)).expect("a file");
            file.set_len(len).expect("its length");
        };
        sized("full", MAX_TEXT);
        sized("over", MAX_TEXT + 1);
        assert!(read_text(&root, "full").expect("read").is_some());
        assert_eq!(read_text(&root, "over"), Err(Unread::TooLarge));
        // What the review made: 3 GiB, where a file can be that long and
        // hold nothing.
        #[cfg(unix)]
        {
            sized("huge", 3 << 30);
            assert_eq!(read_text(&root, "huge"), Err(Unread::TooLarge));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_app_a_pipe_and_a_device_are_not_read() {
        use std::os::unix::fs::symlink;
        let dir = bot();
        let root = std::fs::canonicalize(dir.path()).expect("its real path");
        let outside = tempfile::tempdir().expect("another directory");
        let other = outside.path().join("other.env");
        std::fs::write(&other, "ELSEWHERE=not-this-apps\n").expect("a file outside");
        // A link to a file inside the app is the app's own file.
        std::fs::create_dir(root.join("config")).expect("config");
        std::fs::write(root.join("config/shared"), "INSIDE=yes\n").expect("a file inside");
        symlink("config/shared", root.join("inside")).expect("a link inside");
        assert_eq!(
            read_text(&root, "inside"),
            Ok(Some("INSIDE=yes\n".to_owned()))
        );
        // One that leads out, to nothing, or to a device is not followed.
        symlink(&other, root.join("out")).expect("a link out");
        symlink(outside.path().join("nothing"), root.join("nowhere")).expect("a link");
        symlink("/dev/zero", root.join("zero")).expect("a link to a device");
        for name in ["out", "nowhere", "zero"] {
            assert_eq!(read_text(&root, name), Err(Unread::Link), "{name}");
        }
        // A pipe is not opened: opening one waits for a writer.
        let made = std::process::Command::new("mkfifo")
            .arg(root.join("pipe"))
            .status()
            .expect("mkfifo");
        assert!(made.success(), "mkfifo");
        assert_eq!(read_text(&root, "pipe"), Err(Unread::NotAFile));
    }

    /// What the review found, each in the place of a file import reads:
    /// an example that is a link to another app's, a `.env` that is a
    /// pipe, a Dockerfile that is a device, a compose file of 3 GiB.
    #[cfg(unix)]
    #[test]
    fn what_import_does_not_read_is_said_and_nothing_of_it_is_taken() {
        use std::os::unix::fs::symlink;
        let dir = bot();
        let outside = tempfile::tempdir().expect("another directory");
        let other = outside.path().join("other.env");
        std::fs::write(&other, "ELSEWHERE=not-this-apps\nPORT=7777\n").expect("outside");
        for name in [".env.example", ".env", "docker-compose.yml"] {
            std::fs::remove_file(dir.path().join(name)).expect("removed");
        }
        symlink(&other, dir.path().join(".env.example")).expect("a link out");
        let made = std::process::Command::new("mkfifo")
            .arg(dir.path().join(".env"))
            .status()
            .expect("mkfifo");
        assert!(made.success(), "mkfifo");
        symlink("/dev/zero", dir.path().join("Dockerfile")).expect("a device");
        let compose = std::fs::File::create(dir.path().join("compose.yml")).expect("a file");
        compose.set_len(3 << 30).expect("sparse");
        std::fs::write(dir.path().join(".env.sample"), b"\xff\xfeNAME=x\n").expect("a file");

        let found = survey(dir.path(), &request()).expect("read");
        assert_eq!(
            found.unread,
            [
                ("Dockerfile", Unread::Link),
                ("compose.yml", Unread::TooLarge),
                (".env.example", Unread::LinkedExample),
                (".env.sample", Unread::NotText),
                (".env", Unread::NotAFile),
            ]
            .map(|(file, why)| (file.to_owned(), why))
        );
        assert!(found.vars.is_empty() && found.unset.is_empty(), "{found:?}");
        assert_eq!(found.port, None);
        assert!(found.services.is_empty() && !found.docker);
        let text = manifest_text(&found, Chain::Solana);
        assert!(!text.contains("ELSEWHERE"), "{text}");
        // Each is said, by its own name.
        let said = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            super::report(&found, dir.path(), None, &[], "").text()
        });
        for line in [
            ".env.example is a link, and an example file is read only when it is a file itself",
            ".env.sample is not UTF-8 text",
            ".env is not a regular file",
            "compose.yml is larger than 1 MiB",
        ] {
            assert!(said.contains(line), "{line}: {said}");
        }
        // A Cargo.toml that cannot be read stops the import, said as such.
        std::fs::remove_file(dir.path().join("Cargo.toml")).expect("removed");
        symlink(
            outside.path().join("Cargo.toml"),
            dir.path().join("Cargo.toml"),
        )
        .expect("a link");
        let refused = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            survey(dir.path(), &request()).expect_err("refused")
        });
        assert!(
            refused.message.contains("Cargo.toml is a link"),
            "{}",
            refused.message
        );
    }

    /// What the review found: `.env.example` as a link to the app's own
    /// `.env` had `.env`'s values copied, since the names-only rule went by
    /// the name asked for and the link was followed inside the app. An
    /// example is now read only when it is a file itself.
    #[cfg(unix)]
    #[test]
    fn an_example_that_is_a_link_copies_nothing_of_what_it_leads_to() {
        use std::os::unix::fs::symlink;
        let private = "REGION=tokyo\nFEED_HOST=feed.internal\nWORKERS=7\n";
        // One hop to `.env`; two hops, through a directory; and a link to
        // another file inside the app that is no example either.
        let cases: [(&str, &[(&str, &str)]); 3] = [
            (".env.example", &[(".env", ".env.example")]),
            (
                ".env.dist",
                &[("../.env", "cfg/shared"), ("cfg/shared", ".env.dist")],
            ),
            (".env.sample", &[("local/prod.env", ".env.sample")]),
        ];
        for (example, links) in cases {
            let dir = bot();
            let root = dir.path();
            for name in [".env.example", ".env"] {
                std::fs::remove_file(root.join(name)).expect("removed");
            }
            std::fs::write(root.join(".env"), private).expect(".env");
            std::fs::create_dir(root.join("cfg")).expect("cfg");
            std::fs::create_dir(root.join("local")).expect("local");
            std::fs::write(root.join("local/prod.env"), private).expect("a private file");
            for (to, at) in links {
                symlink(to, root.join(at)).expect("a link");
            }

            let found = survey(root, &request()).expect("read");
            assert!(found.vars.is_empty(), "{example}: {:?}", found.vars);
            assert_eq!(
                found.unread,
                [(example.to_owned(), Unread::LinkedExample)],
                "{example}"
            );
            // `.env` still gives its names, and only those.
            assert_eq!(
                found.unset,
                [
                    ("REGION", ".env"),
                    ("FEED_HOST", ".env"),
                    ("WORKERS", ".env")
                ]
                .map(|(name, file)| (name.to_owned(), file)),
                "{example}"
            );
            let text = manifest_text(&found, Chain::Solana);
            for value in ["tokyo", "feed.internal", "= \"7\""] {
                assert!(!text.contains(value), "{example}: {value} in\n{text}");
            }
        }
    }

    /// `.env` under an example's name by a hard link is one file with two
    /// names: read as `.env` is, whichever name is asked for.
    #[cfg(unix)]
    #[test]
    fn an_example_that_is_env_itself_gives_names_only() {
        let dir = bot();
        let root = dir.path();
        std::fs::remove_file(root.join(".env.example")).expect("removed");
        std::fs::write(root.join(".env"), "PORT=9090\nREGION=tokyo\nWORKERS=7\n").expect(".env");
        std::fs::hard_link(root.join(".env"), root.join(".env.example")).expect("a hard link");

        let found = survey(root, &request()).expect("read");
        // The port is the one value `.env` gives.
        assert_eq!(found.port, Some(9090));
        assert_eq!(found.vars, [("PORT".to_owned(), "9090".to_owned())]);
        assert_eq!(
            found.unset,
            [("REGION", ".env"), ("WORKERS", ".env")].map(|(name, file)| (name.to_owned(), file))
        );
        assert!(found.unread.is_empty(), "{:?}", found.unread);
        assert_eq!(found.names_only, [".env.example"]);
        let text = manifest_text(&found, Chain::Solana);
        assert!(
            !text.contains("tokyo") && !text.contains("= \"7\""),
            "{text}"
        );
        // Said, and there for a script.
        let said = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            super::report(&found, root, None, &[], "").text()
        });
        assert!(
            said.contains(".env.example is one file with another name"),
            "{said}"
        );
        let json = super::as_json(&found, root, root, false, &[]);
        assert_eq!(json["names_only"], serde_json::json!([".env.example"]));
        // An example of its own beside `.env` is copied as before.
        std::fs::remove_file(root.join(".env.example")).expect("removed");
        std::fs::write(root.join(".env.example"), "REGION=frankfurt\n").expect("an example");
        let found = survey(root, &request()).expect("read");
        assert!(
            found
                .vars
                .contains(&("REGION".to_owned(), "frankfurt".to_owned())),
            "{:?}",
            found.vars
        );
        assert!(found.names_only.is_empty());
    }

    /// What the third review found: the rule knew `.env` alone, and by
    /// its path. An example is one file with another name when it has a
    /// second name of any kind, or when another dotenv file of the app is
    /// a link to it; what is written under that other name is in it.
    #[cfg(unix)]
    #[test]
    fn an_example_that_is_one_file_with_another_name_gives_names_only() {
        use std::os::unix::fs::symlink;
        let private = "REGION=tokyo\nWORKERS=7\n";
        // How the example comes to be one file with another: a hard link
        // to a private file that is not `.env`, a private file that is a
        // link to it, and `.env` itself as a link to it.
        let cases: [&dyn Fn(&std::path::Path); 3] = [
            &|root| {
                std::fs::write(root.join(".env.local"), private).expect("a private file");
                std::fs::hard_link(root.join(".env.local"), root.join(".env.example"))
                    .expect("a hard link");
            },
            &|root| {
                std::fs::write(root.join(".env.example"), private).expect("an example");
                symlink(".env.example", root.join(".env.local")).expect("a link");
            },
            &|root| {
                std::fs::write(root.join(".env.example"), private).expect("an example");
                symlink(".env.example", root.join(".env")).expect("a link");
            },
        ];
        for (case, make) in cases.iter().enumerate() {
            let dir = bot();
            let root = dir.path();
            for name in [".env.example", ".env"] {
                std::fs::remove_file(root.join(name)).expect("removed");
            }
            make(root);
            let found = survey(root, &request()).expect("read");
            assert!(found.vars.is_empty(), "case {case}: {:?}", found.vars);
            assert_eq!(found.names_only, [".env.example"], "case {case}");
            assert_eq!(
                found.unset,
                [("REGION", ".env"), ("WORKERS", ".env")]
                    .map(|(name, file)| (name.to_owned(), file)),
                "case {case}"
            );
            let text = manifest_text(&found, Chain::Solana);
            assert!(!text.contains("tokyo"), "case {case}:\n{text}");
        }
        // One example as a link to another is no private file's doing:
        // the link is not read, and the file it leads to is copied.
        let dir = bot();
        let root = dir.path();
        std::fs::remove_file(root.join(".env")).expect("removed");
        std::fs::write(root.join(".env.example"), "REGION=frankfurt\n").expect("an example");
        symlink(".env.example", root.join(".env.sample")).expect("a link");
        let found = survey(root, &request()).expect("read");
        assert_eq!(found.vars, [("REGION".to_owned(), "frankfurt".to_owned())]);
        assert!(found.names_only.is_empty());
        assert_eq!(
            found.unread,
            [(".env.sample".to_owned(), Unread::LinkedExample)]
        );
    }

    /// What the fourth review still saw: the example's name given to a
    /// plain file while the hard link to `.env` it had been was being
    /// read. What was read is told by the file that was opened, whatever
    /// its name leads to afterwards.
    #[cfg(unix)]
    #[test]
    fn a_file_that_was_env_when_it_was_opened_is_private_whatever_its_name_leads_to_now() {
        use super::{Files, Opened};
        let dir = bot();
        let files = Files::of(dir.path());
        let opened =
            |name: &str| Opened::of(&std::fs::metadata(files.root.join(name)).expect("there"));
        // The example is a file of its own now, with one name.
        let example = opened(".env.example");
        assert_eq!(example.names, 1);
        assert!(!files.is_private(".env.example", example));
        // But the file that was read under its name was `.env`.
        assert!(files.is_private(".env.example", opened(".env")));
        // Any private dotenv file of the app counts, not `.env` alone.
        std::fs::write(files.root.join(".env.local"), "REGION=tokyo\n").expect("a private file");
        assert!(files.is_private(".env.example", opened(".env.local")));
        // Another example does not: its values are for copying too.
        std::fs::write(files.root.join(".env.sample"), "REGION=tokyo\n").expect("an example");
        assert!(!files.is_private(".env.example", opened(".env.sample")));
    }

    /// Each of the three ways an example is told to be one file with
    /// another name, alone: the fifth review found that the newest of them
    /// answered for the other two in every test.
    #[cfg(unix)]
    #[test]
    fn each_way_an_example_is_told_to_be_another_file_holds_alone() {
        use super::{Files, Opened};
        use std::os::unix::fs::symlink;
        // A second name that is no dotenv file's: only the count of names
        // tells it.
        let dir = bot();
        let root = dir.path();
        std::fs::remove_file(root.join(".env.example")).expect("removed");
        std::fs::write(root.join("notes.txt"), "REGION=tokyo\n").expect("a file");
        std::fs::hard_link(root.join("notes.txt"), root.join(".env.example")).expect("a link");
        let found = survey(root, &request()).expect("read");
        assert_eq!(found.names_only, [".env.example"]);
        assert!(
            !found
                .vars
                .contains(&("REGION".to_owned(), "tokyo".to_owned())),
            "{:?}",
            found.vars
        );
        // Where a file has no device and inode to go by, a private dotenv
        // file that is a link to the example is told by its real path.
        let dir = bot();
        let files = Files::of(dir.path());
        let unnumbered = Opened { names: 1, id: None };
        assert!(!files.is_private(".env.example", unnumbered));
        symlink(".env.example", files.root.join(".env.local")).expect("a link");
        assert!(files.is_private(".env.example", unnumbered));
        // A link from another example, or to another file, is not that.
        std::fs::remove_file(files.root.join(".env.local")).expect("removed");
        symlink(".env.example", files.root.join(".env.sample")).expect("a link");
        symlink("Cargo.toml", files.root.join(".env.local")).expect("a link");
        assert!(!files.is_private(".env.example", unnumbered));
    }

    /// A line whose text before `=` can be no setting's name is left out,
    /// and that is said by number: the app would otherwise be deployed
    /// without a setting and nothing says so. What the text is, is not
    /// said. The sixth review found it printed, and in `.env` it can be
    /// anything: a URL with its password, the last line of a key.
    #[test]
    fn a_line_that_names_no_setting_is_counted_and_never_shown() {
        let dir = bot();
        let root = dir.path();
        std::fs::write(
            root.join(".env.example"),
            "db_url=postgres_like\nMixed_Case=1\nERPC_WORKER_PORT=1\nLD_PRELOAD=x\n1ST=x\nLOG_LEVEL=info\n",
        )
        .expect("an example");
        // `.env` with lines that are no settings, each with a marker
        // before its first `=`.
        std::fs::write(
            root.join(".env"),
            "postgres://app:MARKERONE@db.internal/app?sslmode=require\n\
             SESSION: MARKERTWO==\n\
             MARKERTHREE0a1b2c3d==\n\
             curl -H \"Authorization: Bearer MARKERFOUR\" host/x?a=1\n\
             note MARKERFIVE=\"never closed\nREGION=tokyo\n",
        )
        .expect(".env");
        let found = survey(root, &request()).expect("read");
        assert_eq!(found.skipped, [(".env.example", 5), (".env", 5)]);
        // The quote that never closes is in a line that names no setting:
        // said without its text.
        assert_eq!(found.unclosed, [(None, ".env")]);
        assert!(
            found
                .vars
                .contains(&("LOG_LEVEL".to_owned(), "info".to_owned()))
        );
        let text = manifest_text(&found, Chain::Solana);
        let said = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            super::report(&found, root, None, &[], "").text()
        });
        let json = super::as_json(&found, root, root, false, &[]).to_string();
        for out in [&text, &said, &json] {
            for marker in [
                "MARKERONE",
                "MARKERTWO",
                "MARKERTHREE",
                "MARKERFOUR",
                "MARKERFIVE",
                "db_url",
                "Mixed_Case",
                "sslmode",
            ] {
                assert!(!out.contains(marker), "{marker} in:\n{out}");
            }
        }
        assert!(
            said.contains(".env.example has 5 lines that name no setting")
                && said.contains(".env has 5 lines that name no setting")
                && said.contains("in .env, a quote never closes"),
            "{said}"
        );
        let json = super::as_json(&found, root, root, false, &[]);
        assert_eq!(
            json["names_skipped"],
            serde_json::json!([
                { "file": ".env.example", "count": 5 },
                { "file": ".env", "count": 5 },
            ])
        );
        assert_eq!(
            json["unclosed"],
            serde_json::json!([{ "file": ".env", "name": null }])
        );
        // One line is said as one.
        std::fs::write(root.join(".env.example"), "db_url=x\n").expect("an example");
        std::fs::remove_file(root.join(".env")).expect("removed");
        let found = survey(root, &request()).expect("read");
        let said = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            super::report(&found, root, None, &[], "").text()
        });
        assert!(
            said.contains(".env.example has 1 line that names no setting"),
            "{said}"
        );
    }

    /// The dotenv reader and the whole reading of a directory meet
    /// whatever text a file holds. This runs them over text made from the
    /// pieces they part at, with characters of every width, and asks only
    /// that they answer.
    #[test]
    fn the_dotenv_reader_and_the_import_answer_for_any_text() {
        let pieces: [&str; 40] = [
            "=", "\n", "\r\n", "\"", "'", "\\", "#", " #", "export ", " ", "\t", "\u{a0}",
            "\u{2028}", "\u{3000}", "\u{feff}", "é", "日本", "🔑", "\u{130}", "\u{1e9e}", "\0",
            "\u{202e}", "PORT", "API_PORT", "NAME", "name", "8080", "://", "@", ":", "/", "?", "&",
            ",", ";", "\\n", "\\\"", "$(", "password", "Ab3",
        ];
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move |below: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % 1_000_003).expect("small") % below
        };
        let dir = bot();
        for round in 0..30_000 {
            let mut text = String::new();
            for _ in 0..=next(30) {
                text.push_str(pieces[next(pieces.len())]);
            }
            let _ = dotenv(&text);
            // The whole import now and then: what is found, written, said.
            if round % 100 == 0 {
                std::fs::write(dir.path().join(".env.example"), &text).expect("an example");
                std::fs::write(dir.path().join(".env"), &text).expect(".env");
                if let Ok(found) = survey(dir.path(), &request()) {
                    let _ = Manifest::parse(&manifest_text(&found, Chain::Solana));
                    let _ = super::report(&found, dir.path(), None, &[], "").text();
                    let _ = super::as_json(&found, dir.path(), dir.path(), false, &[]);
                }
            }
        }
    }

    /// `import --binary` takes a file of the app, as `check` and a deploy
    /// do: one a link under that name leads to elsewhere is refused.
    #[cfg(unix)]
    #[test]
    fn a_binary_a_link_leads_to_outside_the_app_is_refused_at_import() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("a directory");
        let outside = tempfile::tempdir().expect("another directory");
        std::fs::write(outside.path().join("service"), b"\x7fELF").expect("a file elsewhere");
        std::fs::create_dir(dir.path().join("dist")).expect("dist");
        symlink(
            outside.path().join("service"),
            dir.path().join("dist/service"),
        )
        .expect("a link");
        let req = Request {
            binary: Some("dist/service"),
            ..request()
        };
        let refused = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            survey(dir.path(), &req).expect_err("refused")
        });
        assert!(
            refused.message.contains("is not a file inside the app"),
            "{}",
            refused.message
        );
        // The same file inside the app, and a link to it there, are taken.
        std::fs::remove_file(dir.path().join("dist/service")).expect("removed");
        std::fs::write(dir.path().join("dist/real"), b"\x7fELF").expect("a file inside");
        symlink("real", dir.path().join("dist/service")).expect("a link inside");
        let found = survey(dir.path(), &req).expect("read");
        assert_eq!(found.build, Build::Prebuilt("dist/service".to_owned()));
    }

    /// What the review measured: 80 KB of `=` as an example's value took
    /// 48 seconds to read for a credential's shape. A value `[vars]` could
    /// not hold is not read for one; it is named, with no value.
    #[test]
    fn a_value_too_long_for_vars_is_named_and_not_read_for_a_credential() {
        let dir = bot();
        let long = "=".repeat(48 * 1024);
        let jwts = "eyJ".repeat(16 * 1024);
        // One byte longer than `[vars]` holds, with a key in a query at
        // its start: what tells, without a clock, that it was not read.
        let keyed = format!("feed-host/?api-key=abc&pad={}", "x".repeat(4097 - 27));
        assert_eq!(keyed.len(), super::manifest::MAX_VAR_VALUE + 1);
        assert!(super::manifest::carries_credential(&keyed));
        std::fs::write(
            dir.path().join(".env.example"),
            format!("PADDING={long}\nHEADERS={jwts}\nFEED_URL={keyed}\nLOG_LEVEL=info\n"),
        )
        .expect("an example");
        let started = std::time::Instant::now();
        let found = survey(dir.path(), &request()).expect("read");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        // The example's plain value, and the port `.env` gives.
        assert_eq!(
            found.vars,
            [("LOG_LEVEL", "info"), ("PORT", "9090")].map(|(n, v)| (n.to_owned(), v.to_owned()))
        );
        // Named with no value, and not as a secret: nothing of them was
        // read for one.
        for name in ["PADDING", "HEADERS", "FEED_URL"] {
            assert!(
                found.unset.contains(&(name.to_owned(), ".env.example")),
                "{name}: {:?}",
                found.unset
            );
            assert!(!found.secrets.contains(&name.to_owned()), "{name}");
        }
        // One byte shorter, and the same value is read and held.
        let fits = format!("feed-host/?api-key=abc&pad={}", "x".repeat(4096 - 27));
        std::fs::write(
            dir.path().join(".env.example"),
            format!("FEED_URL={fits}\n"),
        )
        .expect("an example");
        let found = survey(dir.path(), &request()).expect("read");
        assert!(found.secrets.contains(&"FEED_URL".to_owned()), "{found:?}");
    }

    /// A file saved on Windows can start with a byte order mark: the first
    /// setting is read all the same.
    #[test]
    fn a_byte_order_mark_is_not_part_of_the_first_name() {
        assert_eq!(
            settings_of("\u{feff}LOG_LEVEL=info\nREGION=tokyo\n"),
            pairs([("LOG_LEVEL", "info"), ("REGION", "tokyo")])
        );
        let dir = bot();
        std::fs::write(
            dir.path().join(".env.example"),
            "\u{feff}LOG_LEVEL=info\nREGION=tokyo\n",
        )
        .expect("an example");
        let found = survey(dir.path(), &request()).expect("read");
        // Both of the example's, and the port `.env` gives.
        assert_eq!(
            found.vars,
            [("LOG_LEVEL", "info"), ("REGION", "tokyo"), ("PORT", "9090")]
                .map(|(n, v)| (n.to_owned(), v.to_owned()))
        );
    }

    /// A quote that never closes takes the rest of its file. That is said,
    /// by the setting it opens at, and the settings after it are not
    /// passed over in silence.
    #[test]
    fn a_quote_that_never_closes_is_said() {
        let dir = bot();
        std::fs::write(
            dir.path().join(".env.example"),
            "LOG_LEVEL=info\nGREETING=\"hello\nREGION=tokyo\n",
        )
        .expect("an example");
        let found = survey(dir.path(), &request()).expect("read");
        assert_eq!(
            found.unclosed,
            [(Some("GREETING".to_owned()), ".env.example")]
        );
        assert!(
            found
                .unset
                .contains(&("GREETING".to_owned(), ".env.example"))
        );
        let said = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            super::report(&found, dir.path(), None, &[], "").text()
        });
        assert!(
            said.contains("in .env.example, the quote that opens GREETING's value never closes"),
            "{said}"
        );
        let json = super::as_json(&found, dir.path(), dir.path(), false, &[]);
        assert_eq!(
            json["unclosed"],
            serde_json::json!([{ "file": ".env.example", "name": "GREETING" }])
        );
    }

    /// What import says is said once. `erpc.toml` is what is read before a
    /// deploy: a setting taken for a secret is named there too, since one
    /// that is in neither table is one the app is deployed without.
    #[test]
    fn a_setting_taken_for_a_secret_is_named_in_erpc_toml() {
        let dir = bot();
        let found = survey(dir.path(), &request()).expect("read");
        let text = manifest_text(&found, Chain::Solana);
        for secret in &found.secrets {
            assert!(
                text.contains(&format!("\n#   {secret}\n")),
                "{secret}:\n{text}"
            );
        }
        assert!(text.contains("# Taken for secrets"), "{text}");
        // Comments only: the file reads as it did.
        let m = Manifest::parse(&text).expect("valid");
        assert!(m.secrets.is_empty());
        // And nothing is said of secrets where none was found.
        std::fs::write(dir.path().join(".env.example"), "LOG_LEVEL=info\n").expect("an example");
        std::fs::remove_file(dir.path().join(".env")).expect("removed");
        let found = survey(dir.path(), &request()).expect("read");
        assert!(found.secrets.is_empty());
        assert!(!manifest_text(&found, Chain::Solana).contains("Taken for secrets"));
    }

    /// What the review found: `PORT=0` and `EXPOSE 0` stopped the import
    /// with the manifest's refusal printed as Rust prints a value.
    #[test]
    fn what_is_not_a_port_is_skipped_and_said_plainly() {
        use erpc_core::i18n::Lang;
        assert_eq!(super::port_of("8080"), Some(8080));
        assert_eq!(super::port_of(" 65535 "), Some(65535));
        for none in ["0", "65536", "70000", "-1", "http", "", "80 80"] {
            assert_eq!(super::port_of(none), None, "{none}");
        }
        assert_eq!(
            super::exposed("FROM x\nEXPOSE 8080/tcp 9090\n"),
            (Some(8080), false)
        );
        assert_eq!(
            super::exposed("expose 0\nEXPOSE $PORT 70000 3000/udp\n"),
            (Some(3000), true)
        );
        assert_eq!(super::exposed("# EXPOSE 80\nEXPOSE 0\n"), (None, true));
        assert_eq!(super::exposed("FROM x\n"), (None, false));

        let dir = bot();
        let write = |name: &str, text: &str| {
            std::fs::write(dir.path().join(name), text).expect("a file");
        };
        // The first setting that names a port gives it; the ones that
        // name none are said, and the import goes on.
        write(
            ".env.example",
            "PORT=0\nAPI_PORT=70000\nHTTP_PORT=8081\nLISTEN_PORT=\n",
        );
        write(".env", "SERVER_PORT=not-a-port-at-all\nAPP_PORT=9000\n");
        write("Dockerfile", "FROM scratch\nEXPOSE 0\n");
        let found = survey(dir.path(), &request()).expect("read");
        assert_eq!(found.port, Some(8081));
        assert_eq!(
            found.bad_ports,
            [
                ("PORT", ".env.example"),
                ("API_PORT", ".env.example"),
                ("SERVER_PORT", ".env")
            ]
            .map(|(name, file)| (name.to_owned(), file))
        );
        // Out of `.env` a port is taken and nothing else, said or not.
        assert!(
            found
                .vars
                .contains(&("APP_PORT".to_owned(), "9000".to_owned()))
        );
        let text = manifest_text(&found, Chain::Solana);
        let said = crate::i18n::speaking(Lang::En, || {
            super::report(&found, dir.path(), None, &[], "").text()
        });
        for out in [&text, &said] {
            assert!(!out.contains("not-a-port-at-all"), "{out}");
        }
        assert!(
            said.contains(".env gives SERVER_PORT something that is not a port from 1 to 65535"),
            "{said}"
        );
        assert_eq!(Manifest::parse(&text).expect("valid").run.port, Some(8081));

        // No setting names a port: the Dockerfile's, which names none.
        write(".env.example", "PORT=0\n");
        write(".env", "");
        let found = survey(dir.path(), &request()).expect("read");
        assert_eq!(found.port, None);
        assert_eq!(
            found.bad_ports,
            [("PORT", ".env.example"), ("EXPOSE", "Dockerfile")]
                .map(|(name, file)| (name.to_owned(), file))
        );
        let (_, path) = written(dir.path(), &request()).expect("written all the same");
        let m = Manifest::load(&path).expect("valid");
        assert_eq!(m.run.port, None);

        // --port 0 is refused in words, and so is a manifest check would
        // refuse: never as Rust prints a value.
        std::fs::remove_file(&path).expect("removed");
        let zero = Request {
            port: Some(0),
            ..request()
        };
        let refused = crate::i18n::speaking(Lang::En, || {
            written(dir.path(), &zero).expect_err("no port")
        });
        assert_eq!(refused.message, "--port takes a port from 1 to 65535");
        write(
            "Cargo.toml",
            "[package]\nname = \"my_bot\"\n[[bin]]\nname = \"my.bot\"\npath = \"src/main.rs\"\n",
        );
        let dotted = Request {
            bin: Some("my.bot"),
            ..request()
        };
        let refused = crate::i18n::speaking(Lang::En, || {
            written(dir.path(), &dotted).expect_err("a name check refuses")
        });
        assert!(
            refused.message.contains("build.bin `my.bot` must be"),
            "{}",
            refused.message
        );
        assert!(!refused.message.contains("Invalid("), "{}", refused.message);
        assert!(!path.exists(), "nothing was written");
    }

    #[test]
    fn a_setting_is_reported_from_the_file_that_names_it() {
        let dir = bot();
        std::fs::write(dir.path().join(".env.sample"), "CLUSTER=\nRPC_URL=late\n").expect("a file");
        let found = survey(dir.path(), &request()).expect("read");
        assert_eq!(
            found.unset,
            [
                ("RPC_URL", ".env.example"),
                ("CLUSTER", ".env.sample"),
                ("REGION", ".env")
            ]
            .map(|(name, file)| (name.to_owned(), file))
        );
        let said = crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
            super::report(&found, dir.path(), None, &[], "").text()
        });
        assert!(
            said.contains("in .env.example, .env.sample with no value erpc could copy")
                && said.contains(": RPC_URL, CLUSTER\n"),
            "{said}"
        );
        assert!(
            said.contains("named only where erpc reads no values") && said.contains(": REGION\n"),
            "{said}"
        );
        // In erpc.toml each is a comment under the reason it has no value.
        let text = manifest_text(&found, Chain::Solana);
        let example = text
            .find("# In an example file with no value")
            .expect("said");
        let env = text
            .find("# Named only where erpc reads no values")
            .expect("said");
        let at = |name: &str| text.find(&format!("# {name} = \"\"")).expect("named");
        assert!(
            example < at("RPC_URL") && at("CLUSTER") < env && env < at("REGION"),
            "{text}"
        );
        let json = super::as_json(&found, dir.path(), dir.path(), true, &[]);
        assert_eq!(
            json["unset"],
            serde_json::json!(["RPC_URL", "CLUSTER", "REGION"])
        );
        assert_eq!(json["unset_from"]["REGION"], ".env");
        assert_eq!(json["unset_from"]["CLUSTER"], ".env.sample");
    }

    #[test]
    fn a_manifest_with_nothing_found_is_still_one() {
        let found = Found {
            name: "plain".to_owned(),
            build: Build::Cargo { bin: None },
            vars: Vec::new(),
            unset: Vec::new(),
            secrets: Vec::new(),
            lines: Vec::new(),
            port: None,
            bad_ports: Vec::new(),
            health: None,
            key_files: Vec::new(),
            odd_keys: Vec::new(),
            served: Vec::new(),
            services: Services::default(),
            docker: false,
            unread: Vec::new(),
            unclosed: Vec::new(),
            names_only: Vec::new(),
            skipped: Vec::new(),
        };
        let m = Manifest::parse(&manifest_text(&found, Chain::Solana)).expect("valid");
        assert_eq!((m.name.as_str(), m.bin()), ("plain", "plain"));
    }
}
