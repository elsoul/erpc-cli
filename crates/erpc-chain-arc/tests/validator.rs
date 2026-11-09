// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Isolated validator host models; no native node, key generation or NSS mutation.
#[cfg(unix)]
#[test]
fn validator_original_authority_failure_cases() {
    for script in [
        "validator_accounts.py",
        "validator_custody.py",
        "validator_admission.py",
        "validator_state.py",
        "validator_units.py",
        "validator_ipc.py",
        "validator_remote.py",
        "validator_process.py",
        "validator_control.py",
        "validator_namespace.py",
        "validator_storage.py",
        "validator_loaded.py",
        "validator_revocation.py",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(script);
        let output = std::process::Command::new("python3")
            .arg("-B")
            .arg(path)
            .output()
            .expect("Python is required for validator authority regressions");
        assert!(
            output.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
