// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Inert controller/ABI fixtures. No device, blockchain client or real key is executed.
#[cfg(unix)]
#[test]
fn native_failure_paths_preserve_ownership_identity_and_cancellation() {
    for name in [
        "device_identity.py",
        "state_failures.py",
        "host_failures.py",
        "registration_observer.py",
        "accounts_test.py",
        "namespace_test.py",
        "entrypoints_test.py",
        "account_authority.py",
        "data_layout.py",
        "incomplete_data_recovery.py",
    ] {
        let result = std::process::Command::new("python3")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(name),
            )
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("offline Python harness");
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
#[test]
fn embedded_runtime_contains_no_generated_bytecode_or_secret_files() {
    for path in erpc_chain_monad::files() {
        let extension = std::path::Path::new(path)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();
        assert!(
            !path.contains("__pycache__")
                && !["pyc", "cred"]
                    .iter()
                    .any(|kind| extension.eq_ignore_ascii_case(kind)),
            "{path}"
        );
    }
}
