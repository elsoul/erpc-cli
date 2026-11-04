// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Execute identity custody failure tests using inert fixture data.

#[test]
#[cfg(unix)]
fn identity_custody_failure_paths_execute_without_a_node() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/offline.py");
    let result = std::process::Command::new("python3")
        .arg(script)
        .output()
        .expect("Python 3");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
