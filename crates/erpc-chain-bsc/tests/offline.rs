// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Tiny metadata/archive and mocked host failure checks; no node binary is run.

#[cfg(unix)]
#[test]
fn snapshot_and_lifecycle_failures_preserve_ownership_and_existing_data() {
    for script in [
        "bootstrap_test.py",
        "lifecycle_test.py",
        "validator_custody_test.py",
    ] {
        let output = std::process::Command::new("python3")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(script),
            )
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("offline Python harness");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn clean(dir: &include_dir::Dir<'_>) {
    for file in dir.files() {
        assert!(!file.path().to_string_lossy().contains("__pycache__"));
    }
    for sub in dir.dirs() {
        clean(sub);
    }
}

#[test]
fn carried_catalog_is_pinned_and_cannot_include_generated_bytecode() {
    let value: serde_json::Value =
        serde_json::from_slice(erpc_chain_bsc::CATALOG_BYTES).expect("public catalog");
    for network in [
        erpc_chain_bsc::Network::Mainnet,
        erpc_chain_bsc::Network::Chapel,
    ] {
        assert_eq!(value[network.name()]["recommended"], network.recommended());
        let release = network
            .qualify(network.recommended())
            .expect("reviewed release");
        for arch in ["amd64", "arm64"] {
            let artifact = &release["binaries"][arch];
            assert!(
                artifact["url"]
                    .as_str()
                    .expect("URL")
                    .starts_with("https://github.com/bnb-chain/bsc/releases/download/")
            );
            assert_eq!(artifact["sha256"].as_str().expect("digest").len(), 64);
        }
        for mode in ["full", "pruned"] {
            let snapshot = network.catalog()["recommended_snapshots"][mode]
                .as_str()
                .expect("snapshot");
            assert_eq!(network.catalog()["snapshots"][snapshot]["retention"], mode);
        }
    }
    clean(&erpc_chain_bsc::TEMPLATES);
}

#[test]
fn carried_controller_uses_the_reviewed_canonical_sibling_loader() {
    let text = erpc_chain_bsc::TEMPLATES
        .get_file("node/control.py")
        .unwrap()
        .contents_utf8()
        .unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let canonical = std::fs::read_to_string(root.join("erpc-ssh/src/python-trust.py")).unwrap();
    let section = text
        .split("# BEGIN ERPC TRUSTED IMPORTS\n")
        .nth(1)
        .unwrap()
        .split("# END ERPC TRUSTED IMPORTS")
        .next()
        .unwrap();
    assert_eq!(section, canonical);
    assert!(text.starts_with("#!/usr/bin/python3 -I"));
}

#[test]
fn installed_launcher_seals_a_revision_before_loading_the_controller() {
    let source = erpc_chain_bsc::TEMPLATES
        .get_file("node/launcher.py")
        .expect("launcher")
        .contents_utf8()
        .expect("UTF-8");
    let trust = include_str!("../../erpc-ssh/src/python-trust.py");
    let release = include_str!("../../erpc-ssh/src/python-release.py");
    assert_eq!(
        source
            .split("# BEGIN ERPC TRUSTED IMPORTS\n")
            .nth(1)
            .expect("marker")
            .split("# END ERPC TRUSTED IMPORTS")
            .next()
            .expect("body"),
        trust
    );
    assert_eq!(
        source
            .split("# BEGIN ERPC TRUSTED RELEASE\n")
            .nth(1)
            .expect("marker")
            .split("# END ERPC TRUSTED RELEASE")
            .next()
            .expect("body"),
        release
    );
    assert!(source.starts_with("#!/usr/bin/python3 -I\n"));
    for name in ["node/erpc-bsc.service", "node/erpc-bsc-activation.service"] {
        let unit = erpc_chain_bsc::TEMPLATES
            .get_file(name)
            .expect("unit")
            .contents_utf8()
            .expect("UTF-8");
        assert!(unit.contains("@ERPC_BSC_CONTROL@"));
        assert!(!unit.contains("/current/control.py"));
    }
}
