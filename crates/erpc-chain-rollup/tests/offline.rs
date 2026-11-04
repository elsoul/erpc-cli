// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the actual carried transport without contacting a provider or node.

#[cfg(unix)]
#[test]
fn upstream_credentials_and_transport_boundaries_fail_closed() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/upstreams_test.py"
        ))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("Python3 offline harness");
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
}
