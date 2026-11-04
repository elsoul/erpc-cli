// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Execute host failure paths with temporary inert data and mocked service calls.
#[cfg(unix)]
#[test]
fn owned_lifecycle_bootstrap_and_release_failure_paths() {
    let output = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/lifecycle.py"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("Python3 offline harness");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
