// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public manifest authentication and mocked host lifecycle acceptance.

#[cfg(unix)]
#[test]
fn actual_generated_guard_refuses_untrusted_installed_bytes_before_execution() {
    use std::io::Write as _;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut child = std::process::Command::new("python3")
        .arg(root.join("tests/entrypoints.py"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            serde_json::json!({"unit":erpc_chain_bitcoin::unit(20000,20000).unwrap()})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[cfg(unix)]
#[test]
fn actual_gpg_authenticates_public_release_fixture_and_rejects_tampering() {
    let manifest = include_str!("../releases/SHA256SUMS-31.1");
    let signatures = include_str!("../releases/SHA256SUMS-31.1.asc");
    let status = erpc_chain_bitcoin::download::authenticate(manifest, signatures)
        .expect("both trusted signatures");
    assert!(erpc_chain_bitcoin::release::verify_status(&status).is_ok());
    let tampered = manifest.replace(
        "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e",
        &"a".repeat(64),
    );
    assert!(erpc_chain_bitcoin::download::authenticate(&tampered, signatures).is_err());
    assert!(erpc_chain_bitcoin::download::authenticate(manifest, "not a signature").is_err());
}

#[cfg(unix)]
#[test]
fn mutations_enforce_ownership_and_interrupted_installation_safety() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in [
        "lifecycle.py",
        "cancellation_retry.py",
        "accounts.py",
        "volumes.py",
        "authority.py",
        "sources.py",
        "processes.py",
        "migration.py",
    ] {
        let result = std::process::Command::new("python3")
            .arg(root.join("tests").join(name))
            .arg(root.join("templates/node/control.py"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("Python3 offline harness");
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn readiness_requires_network_index_and_sync_not_just_rpc() {
    use erpc_chain_bitcoin::{network::Network, status::evaluate, storage::Storage};
    let mut sample = serde_json::json!({"phase":"installed","service":"active","rpc_available":true,"stopped":false,"authority_valid":true,"process_owned":true,"source_current":true,"genesis":Network::Signet.genesis(),"blockchain":{"chain":"signet","blocks":100,"headers":100,"verificationprogress":1.0,"initialblockdownload":false,"pruned":false},"indexes":{"txindex":{"synced":true,"best_block_height":100}},"connections":4,"tip_time":100_000});
    assert!(evaluate(Network::Signet, Storage::Full, &sample, 100_001).ready);
    sample["indexes"]["txindex"]["synced"] = serde_json::json!(false);
    assert!(!evaluate(Network::Signet, Storage::Full, &sample, 100_001).ready);
    sample["indexes"]["txindex"]["synced"] = serde_json::json!(true);
    for (field, value) in [
        ("genesis", serde_json::json!(Network::Mainnet.genesis())),
        ("rpc_available", serde_json::json!(false)),
        ("stopped", serde_json::json!(true)),
        ("process_owned", serde_json::json!(false)),
        ("source_current", serde_json::json!(false)),
        ("authority_valid", serde_json::json!(false)),
        ("connections", serde_json::json!(0)),
        ("tip_time", serde_json::json!(1)),
    ] {
        let mut bad = sample.clone();
        bad[field] = value;
        assert!(
            !evaluate(Network::Signet, Storage::Full, &bad, 100_001).ready,
            "{field}"
        );
    }
    assert!(!evaluate(Network::Mainnet, Storage::Full, &sample, 100_001).ready);
    sample["blockchain"]["pruned"] = serde_json::json!(true);
    assert!(!evaluate(Network::Signet, Storage::Full, &sample, 100_001).ready);
    sample["indexes"] = serde_json::json!({});
    assert!(
        evaluate(
            Network::Signet,
            Storage::Pruned { target_mib: 10240 },
            &sample,
            100_001
        )
        .ready
    );
}

#[cfg(unix)]
#[test]
fn node_manifest_verifier_matches_the_controller_and_rejects_wrong_expected_digest() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let verify = |digest: &str| {
        std::process::Command::new("python3")
            .arg(root.join("templates/node/verify.py"))
            .arg(root.join("releases/SHA256SUMS-31.1"))
            .arg(root.join("releases/SHA256SUMS-31.1.asc"))
            .arg(root.join("templates/gpg"))
            .arg("bitcoin-31.1-x86_64-linux-gnu.tar.gz")
            .arg(digest)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("offline verifier")
    };
    let good = verify("b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e");
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert!(!verify(&"a".repeat(64)).status.success());
}
