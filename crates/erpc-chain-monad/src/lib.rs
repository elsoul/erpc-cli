// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Monad native operations. Financial signing and transaction submission remain external.
#![forbid(unsafe_code)]
pub mod contract;
pub mod registration;
use include_dir::{Dir, include_dir};
/// Reviewed deployment files, including the package and network catalog.
pub static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");
/// Read one embedded deployment file.
#[must_use]
pub fn file(path: &str) -> Option<&'static [u8]> {
    TEMPLATES.get_file(path).map(include_dir::File::contents)
}
/// Sorted paths of all deployment files.
#[must_use]
pub fn files() -> Vec<&'static str> {
    fn walk(dir: &'static Dir<'static>, out: &mut Vec<&'static str>) {
        for file in dir.files() {
            if let Some(path) = file.path().to_str() {
                out.push(path);
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
