// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Inert publication/ownership tests; native clients are never executed.
#[cfg(unix)]
#[test]
fn artifact_and_state_failure_paths() {
    for script in [
        "artifact_test.py",
        "state_failures.py",
        "gateway_test.py",
        "public_test.py",
        "process_test.py",
        "render_retention_test.py",
        "setup_test.py",
        "accounts_test.py",
        "phases_test.py",
        "entrypoints_test.py",
        "host_test.py",
        "validator_custody.py",
        "validator_volume.py",
        "validator_public.py",
        "validator_modes.py",
        "aqa_artifact.py",
        "aqa_public.py",
        "aqa_custody.py",
        "aqa_runtime.py",
        "aqa_entrypoints.py",
        "aqa_accounts.py",
        "aqa_process.py",
        "aqa_host.py",
    ] {
        let output = std::process::Command::new("python3")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(script),
            )
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("inert Python fixture");
        assert!(
            output.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
