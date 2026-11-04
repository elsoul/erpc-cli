// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A run's bundle: the plays, what erpc adds for the host, and the node's
//! own files, as one gzipped tar with its SHA-256.
//!
//! The archive is deterministic: entries in path order, every timestamp and
//! owner zero, modes fixed. The same inputs make the same digest, so a run
//! can be compared with the one before it.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

/// The Ansible configuration of every run.
pub const ANSIBLE_CFG: &str = include_str!("../node/ansible.cfg");
/// The hash-pinned Ansible every node installs.
pub const REQUIREMENTS: &str = include_str!("../node/requirements.txt");

/// A bundle being put together.
#[derive(Debug, Clone, Default)]
pub struct Bundle {
    files: BTreeMap<String, Vec<u8>>,
}

/// A finished bundle.
#[derive(Clone)]
pub struct Built {
    /// The gzipped tar.
    pub bytes: Vec<u8>,
    /// Its SHA-256, lowercase hex.
    pub sha256: String,
}

impl core::fmt::Debug for Built {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The bundle carries the solv password hash; its bytes are not
        // something to print.
        f.debug_struct("Built")
            .field("len", &self.bytes.len())
            .field("sha256", &self.sha256)
            .finish()
    }
}

/// Why a file cannot go in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// Not a relative path of plain names.
    #[error("{0:?} cannot be a path in a bundle")]
    Path(String),
    /// Writing the archive failed.
    #[error("the bundle could not be written: {0}")]
    Write(String),
}

impl Bundle {
    /// A bundle with the node's own files: `ansible.cfg` and
    /// `requirements.txt`.
    #[must_use]
    pub fn new() -> Self {
        let mut bundle = Self::default();
        bundle
            .files
            .insert("ansible.cfg".to_owned(), ANSIBLE_CFG.as_bytes().to_vec());
        bundle.files.insert(
            "requirements.txt".to_owned(),
            REQUIREMENTS.as_bytes().to_vec(),
        );
        bundle
    }

    /// Adds or replaces the file at `path`, relative to the bundle's root.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::Path`] for an absolute path, an empty, `.` or
    /// `..` component, or a name outside letters, digits, `.`, `_` and `-`.
    pub fn add(&mut self, path: &str, bytes: impl Into<Vec<u8>>) -> Result<(), BundleError> {
        let plain = |part: &str| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        };
        if !path.split('/').all(plain) {
            return Err(BundleError::Path(path.to_owned()));
        }
        self.files.insert(path.to_owned(), bytes.into());
        Ok(())
    }

    /// The paths in the bundle, sorted.
    #[must_use]
    pub fn paths(&self) -> Vec<&str> {
        self.files.keys().map(String::as_str).collect()
    }

    /// Writes the archive and computes its digest.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::Write`] when the archive cannot be written.
    pub fn finish(&self) -> Result<Built, BundleError> {
        let write = |e: std::io::Error| BundleError::Write(e.to_string());
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gzip);
        tar.mode(tar::HeaderMode::Deterministic);
        for (path, bytes) in &self.files {
            let mut header = tar::Header::new_ustar();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut header, path, bytes.as_slice())
                .map_err(write)?;
        }
        let bytes = tar.into_inner().map_err(write)?.finish().map_err(write)?;
        let sha256 = Sha256::digest(&bytes)
            .iter()
            .fold(String::new(), |mut out, b| {
                use core::fmt::Write as _;
                let _ = write!(out, "{b:02x}");
                out
            });
        Ok(Built { bytes, sha256 })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::{Bundle, BundleError};

    fn entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
        archive
            .entries()
            .expect("entries")
            .map(|e| {
                let mut e = e.expect("entry");
                let path = e.path().expect("path").display().to_string();
                let mut body = Vec::new();
                e.read_to_end(&mut body).expect("read");
                (path, body)
            })
            .collect()
    }

    #[test]
    fn a_bundle_holds_the_node_files_and_what_was_added() {
        let mut bundle = Bundle::new();
        bundle
            .add("ansible/x/site.yml", "- hosts: all\n")
            .expect("add");
        bundle.add("inventory.yml", "{}").expect("add");
        let built = bundle.finish().expect("built");
        let names: Vec<String> = entries(&built.bytes).into_iter().map(|(p, _)| p).collect();
        assert_eq!(
            names,
            [
                "ansible.cfg",
                "ansible/x/site.yml",
                "inventory.yml",
                "requirements.txt"
            ]
        );
    }

    #[test]
    fn the_same_inputs_make_the_same_digest() {
        let make = || {
            let mut bundle = Bundle::new();
            bundle.add("inventory.yml", "{}").expect("add");
            bundle.finish().expect("built").sha256
        };
        assert_eq!(make(), make());
        let mut other = Bundle::new();
        other.add("inventory.yml", "{ }").expect("add");
        assert_ne!(make(), other.finish().expect("built").sha256);
    }

    #[test]
    fn paths_that_could_escape_the_bundle_are_refused() {
        let mut bundle = Bundle::new();
        for bad in ["/etc/passwd", "../x", "a/../b", "a//b", "a b", ""] {
            assert_eq!(
                bundle.add(bad, "x"),
                Err(BundleError::Path(bad.to_owned())),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_pinned_requirements_name_every_hash() {
        // --require-hashes refuses any line without one; check the file
        // carries them before a node finds out.
        let pins: Vec<&str> = super::REQUIREMENTS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.starts_with(' ') && !l.trim().is_empty())
            .collect();
        assert!(pins.iter().any(|l| l.starts_with("ansible==")), "{pins:?}");
        assert!(
            pins.iter().any(|l| l.starts_with("ansible-core==2.18.")),
            "{pins:?}"
        );
        assert!(pins.iter().all(|l| l.contains("==")), "{pins:?}");
        assert!(super::REQUIREMENTS.matches("--hash=sha256:").count() > pins.len());
    }
}
