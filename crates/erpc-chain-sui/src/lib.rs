// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Sui node deployment contracts. No node, key or transaction is created locally.
#![forbid(unsafe_code)]

use include_dir::{Dir, include_dir};

pub mod network;
pub mod status;
pub mod validator;

/// Workspace component name.
pub const CRATE_NAME: &str = "erpc-chain-sui";
/// Embedded, reviewed deployment files.
pub static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// Read an embedded deployment file.
#[must_use]
pub fn file(path: &str) -> Option<&'static [u8]> {
    TEMPLATES.get_file(path).map(include_dir::File::contents)
}

/// Paths of every embedded file, sorted.
#[must_use]
pub fn files() -> Vec<&'static str> {
    fn walk(dir: &'static Dir<'static>, out: &mut Vec<&'static str>) {
        for f in dir.files() {
            if let Some(p) = f.path().to_str() {
                out.push(p);
            }
        }
        for sub in dir.dirs() {
            walk(sub, out);
        }
    }
    let mut out = Vec::new();
    walk(&TEMPLATES, &mut out);
    out.sort_unstable();
    out
}
