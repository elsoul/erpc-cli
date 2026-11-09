// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! POSIX host-model regressions; these do not provision a host or run Arc.
#[cfg(unix)]
#[test]
fn original_authority_filesystem_and_release_failure_cases() {
    for script in [
        "authority_primitives.py",
        "authority_release.py",
        "authority_prepare.py",
        "authority_lifecycle.py",
        "authority_migration.py",
        "authority_recovery.py",
        "authority_process.py",
        "authority_observer.py",
        "authority_firewall.py",
        "authority_volume.py",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(script);
        let output = std::process::Command::new("python3")
            .arg("-B")
            .arg(path)
            .output()
            .expect("Python is required for host failure-path verification");
        assert!(
            output.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
