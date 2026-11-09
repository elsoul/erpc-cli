// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Track every change to this package's embedded template directory.

fn main() {
    // include_dir records existing files; directory tracking also finds new ones.
    println!("cargo::rerun-if-changed=templates");
}
