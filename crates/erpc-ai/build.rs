// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Rebuilds when a catalog changes: they are embedded by `include_dir`,
//! which rustc does not track.

fn main() {
    println!("cargo:rerun-if-changed=locales");
}
