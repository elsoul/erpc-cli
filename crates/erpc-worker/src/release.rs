// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A release: one build of an app for its servers, and what it was built
//! from.
//!
//! `erpc worker build` writes it as `release.json` beside the binary.
//! `deploy` carries it to the server with the binary, where it names the
//! release's directory and is what `releases`, `status` and `rollback`
//! show. The binary's digest is checked on the server against it, so what
//! runs is what was built.

use serde::{Deserialize, Serialize};

/// The format of `release.json`. A reader refuses another.
pub const FORMAT: u32 = 1;

/// The file name beside the binary.
pub const FILE_NAME: &str = "release.json";

/// A file shipped with the release (`run.files`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shipped {
    /// Its path inside the app.
    pub path: String,
    /// Its SHA-256, hex.
    pub sha256: String,
}

/// Where the source came from, when it is a git repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// The commit checked out.
    pub commit: String,
    /// Whether there were changes not committed.
    pub dirty: bool,
}

/// One release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    /// [`FORMAT`].
    pub format: u32,
    /// `<UTC time>-<first 8 of the digest>`, such as
    /// `20261029T121314Z-1a2b3c4d`: sorts by time, and names the binary.
    pub id: String,
    /// The app's name.
    pub app: String,
    /// The binary's name.
    pub bin: String,
    /// The Rust target triple it was built for.
    pub target: String,
    /// The oldest glibc it runs on, for a `-gnu` target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glibc: Option<String>,
    /// The binary's SHA-256, hex.
    pub sha256: String,
    /// The binary's size in bytes.
    pub size: u64,
    /// When it was built, RFC 3339 UTC.
    pub built_at: String,
    /// The commit it was built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// The SHA-256 of the `erpc.toml` it was built with.
    pub manifest_sha256: String,
    /// The files shipped with it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<Shipped>,
    /// The erpc that built it.
    pub erpc_version: String,
}

/// The release id for a build at `built_at` (RFC 3339, `…T…Z`) of a
/// binary with digest `sha256`.
#[must_use]
pub fn id(built_at: &str, sha256: &str) -> String {
    let compact: String = built_at
        .chars()
        .filter(|c| !matches!(c, '-' | ':'))
        .collect();
    format!("{compact}-{}", &sha256[..sha256.len().min(8)])
}

/// Whether `path` names a file inside a release: relative, in `/`-separated
/// parts none of which is empty, `.` or `..`, with no backslash or NUL. The
/// agent joins it to the release's directory, so nothing else may reach
/// out of it.
#[must_use]
pub fn is_inside(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', '\0'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Whether `text` is a release id as [`id`] makes them: safe as a
/// directory name on the server and in a command.
#[must_use]
pub fn is_id(text: &str) -> bool {
    let Some((time, digest)) = text.split_once('-') else {
        return false;
    };
    let b = time.as_bytes();
    time.len() == 16
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'T'
        && b[9..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'Z'
        && digest.len() == 8
        && digest
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Release {
    /// Reads `release.json`, refusing another format.
    ///
    /// # Errors
    ///
    /// A message when the text is not a release this erpc reads.
    pub fn parse(text: &str) -> Result<Self, String> {
        let release: Self =
            serde_json::from_str(text).map_err(|e| format!("release.json is not valid: {e}"))?;
        if release.format != FORMAT {
            return Err(format!(
                "release.json is format {}, and this erpc reads {FORMAT}",
                release.format
            ));
        }
        if !is_id(&release.id) {
            return Err(format!(
                "release.json's id `{}` is not a release id",
                release.id
            ));
        }
        if !is_inside(&release.bin) || release.bin.contains('/') {
            return Err(format!(
                "release.json's binary `{}` is not a file name",
                release.bin
            ));
        }
        if let Some(file) = release.files.iter().find(|f| !is_inside(&f.path)) {
            return Err(format!(
                "release.json ships `{}`, which is not a path inside the release",
                file.path
            ));
        }
        Ok(release)
    }
}

#[cfg(test)]
mod tests {
    use super::{FORMAT, Release, id, is_id, is_inside};

    #[test]
    fn only_paths_inside_the_release_are_taken() {
        for good in ["config.jsonc", "conf/app.toml", "a.b/c"] {
            assert!(is_inside(good), "{good}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a//b",
            "./a",
            "a\\b",
            "a/",
        ] {
            assert!(!is_inside(bad), "{bad}");
        }
    }

    #[test]
    fn an_id_sorts_by_time_and_names_the_digest() {
        let made = id("2026-10-29T12:13:14Z", "1a2b3c4d5e6f");
        assert_eq!(made, "20261029T121314Z-1a2b3c4d");
        assert!(is_id(&made));
        for bad in [
            "",
            "20261029T121314Z",
            "20261029T121314Z-1A2B3C4D",
            "20261029T121314Z-1a2b3c4",
            "../../etc-1a2b3c4d",
            "20261029X121314Z-1a2b3c4d",
        ] {
            assert!(!is_id(bad), "{bad}");
        }
    }

    #[test]
    fn a_release_round_trips_and_another_format_is_refused() {
        let release = Release {
            format: FORMAT,
            id: id("2026-10-29T12:13:14Z", "1a2b3c4d5e6f"),
            app: "bot".to_owned(),
            bin: "bot".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            glibc: Some("2.31".to_owned()),
            sha256: "1a2b3c4d5e6f".to_owned(),
            size: 1,
            built_at: "2026-10-29T12:13:14Z".to_owned(),
            source: None,
            manifest_sha256: "00".to_owned(),
            files: Vec::new(),
            erpc_version: "0.0.1".to_owned(),
        };
        let text = serde_json::to_string(&release).expect("json");
        assert_eq!(Release::parse(&text).expect("parse"), release);
        let other = text.replace("\"format\":1", "\"format\":2");
        assert!(Release::parse(&other).is_err());
    }
}
