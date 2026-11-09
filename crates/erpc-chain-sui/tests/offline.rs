// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Python probe mocks run under cargo test without network, nodes or keys.
#[test]
fn remote_probe_failure_paths() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/probes.py");
    let checked = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg(script)
        .status()
        .expect("Python 3 is required for offline Sui probe tests");
    assert!(checked.success());
}

#[test]
fn validator_identity_and_admission_failure_paths() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/validator_probes.py");
    let checked = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg(script)
        .status()
        .expect("Python 3 is required for offline Sui validator tests");
    assert!(checked.success());
}

#[test]
fn original_runtime_authority_failure_paths() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/authority_test.py");
    let checked = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg(script)
        .status()
        .expect("Python 3 is required for offline Sui authority tests");
    assert!(checked.success());
}

#[cfg(unix)]
#[test]
fn original_source_opening_history_failure_paths() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/release_test.py");
    assert!(
        std::process::Command::new("python3")
            .arg("-B")
            .arg(script)
            .status()
            .expect("Python is required")
            .success()
    );
}
