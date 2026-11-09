// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Offline failure paths and the exact installed helper contract.

#[cfg(unix)]
#[test]
fn bootstrap_and_owned_lifecycle_failures() {
    for script in [
        "bootstrap_test.py",
        "lifecycle_test.py",
        "custody_test.py",
        "corecell_test.py",
        "corecell_lifecycle_test.py",
        "coreaccount_test.py",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(script);
        assert!(
            std::process::Command::new("python3")
                .arg("-B")
                .arg(path)
                .status()
                .expect("Python is required")
                .success()
        );
    }
}

#[test]
fn launchers_share_the_reviewed_isolated_revision_loader_and_carry_no_bytecode() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let canonical = std::fs::read_to_string(root.join("erpc-ssh/src/python-trust.py")).unwrap();
    let release = std::fs::read_to_string(root.join("erpc-ssh/src/python-release.py")).unwrap();
    for name in ["control.py", "launcher.py"] {
        let text = erpc_chain_kaia::TEMPLATES
            .get_file(format!("node/{name}"))
            .unwrap()
            .contents_utf8()
            .unwrap();
        let section = text
            .split("# BEGIN ERPC TRUSTED IMPORTS\n")
            .nth(1)
            .unwrap()
            .split("# END ERPC TRUSTED IMPORTS")
            .next()
            .unwrap();
        assert_eq!(section, canonical);
        assert!(text.starts_with("#!/usr/bin/python3 -I"));
        if name == "launcher.py" {
            assert_eq!(
                text.split("# BEGIN ERPC TRUSTED RELEASE\n")
                    .nth(1)
                    .unwrap()
                    .split("# END ERPC TRUSTED RELEASE")
                    .next()
                    .unwrap(),
                release
            );
        }
    }
    let unit = erpc_chain_kaia::TEMPLATES
        .get_file("node/erpc-kaia.service")
        .unwrap()
        .contents_utf8()
        .unwrap();
    assert!(unit.contains("ExecStop=@ERPC_KAIA_CONTROL@ stop-container"));
    assert!(unit.contains("SendSIGKILL=no"));
    // Native key access is staged by the root controller after original-account
    // validation. PID1 must not deliver secrets to a name before that check.
    assert!(unit.lines().all(|line| !line.starts_with("User=")
        && !line.starts_with("Group=")
        && !line.starts_with("LoadCredential")
        && !line.starts_with("SetCredential")
        && !line.starts_with("ImportCredential")));
    let deploy = erpc_chain_kaia::TEMPLATES
        .get_file("node/deploy.yml")
        .unwrap()
        .contents_utf8()
        .unwrap();
    assert!(deploy.find("firewall-require").unwrap() < deploy.find("begin-install").unwrap());
    check(&erpc_chain_kaia::TEMPLATES);
}

fn check(directory: &include_dir::Dir<'_>) {
    for file in directory.files() {
        assert!(!file.path().to_string_lossy().contains("__pycache__"));
    }
    for child in directory.dirs() {
        check(child);
    }
}
