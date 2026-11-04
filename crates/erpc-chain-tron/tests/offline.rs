// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Offline native API adapter and custody-boundary regression checks.

#[test]
fn custody_and_native_adapter_failures() {
    for script in ["offline.py", "control_paths.py"] {
        let result = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(script),
            )
            .status()
            .expect("Python 3 and a JDK are required for offline TRON adapter checks");
        assert!(result.success());
    }
}
