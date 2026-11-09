// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Offline manifest and host lifecycle qualification, without a node binary.

use erpc_chain_nitro::{
    network::Network,
    release::{INDEX, Platform},
};
use sha2::{Digest, Sha256};

#[test]
fn actual_official_manifest_bytes_match_both_pinned_platforms() {
    let index = include_bytes!("fixtures/image-index.json");
    assert_eq!(format!("sha256:{:x}", Sha256::digest(index)), INDEX);
    let value: serde_json::Value = serde_json::from_slice(index).expect("public OCI fixture");
    for (platform, bytes) in [
        (
            Platform::Amd64,
            include_bytes!("fixtures/amd64-manifest.json").as_slice(),
        ),
        (
            Platform::Arm64,
            include_bytes!("fixtures/arm64-manifest.json").as_slice(),
        ),
    ] {
        assert_eq!(
            format!("sha256:{:x}", Sha256::digest(bytes)),
            platform.digest()
        );
        let descriptor = value["manifests"]
            .as_array()
            .expect("platforms")
            .iter()
            .find(|v| v["platform"]["architecture"] == platform.name())
            .expect("reviewed architecture");
        assert_eq!(descriptor["platform"]["os"], "linux");
        assert_eq!(descriptor["digest"], platform.digest());
    }
}
#[test]
fn every_carried_document_is_pinned_to_a_node_only_host() {
    for network in [
        Network::One,
        Network::Nova,
        Network::Sepolia,
        Network::Robinhood,
        Network::RobinhoodTestnet,
    ] {
        let (url, digest) = network.chain_info().expect("network metadata");
        let host = url
            .strip_prefix("https://")
            .expect("TLS")
            .split('/')
            .next()
            .expect("host");
        assert!(erpc_core::endpoints::NODE_HOSTS.contains(&host));
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|v| v.is_ascii_hexdigit()));
    }
}
#[cfg(unix)]
#[test]
fn carried_controller_enforces_ownership_fences_credentials_and_service_contracts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for script in ["lifecycle.py", "recovery.py"] {
        let output = std::process::Command::new("python3")
            .arg("-B")
            .arg(root.join("tests").join(script))
            .output()
            .expect("offline Python harness");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn assertion_validator_authority_and_public_admission_are_exercised_offline() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in [
        "validator_artifact.py",
        "validator_admission.py",
        "validator_configuration.py",
        "validator_state.py",
        "validator_accounts.py",
        "validator_crypto.py",
        "validator_transactions.py",
        "validator_transport.py",
        "validator_observer.py",
        "validator_host.py",
        "validator_preflight.py",
        "validator_custody.py",
        "validator_wallet_stage.py",
        "validator_provider_stage.py",
        "validator_processes.py",
        "validator_protocol.py",
        "validator_authority.py",
        "validator_container.py",
        "validator_history.py",
        "validator_volumes.py",
        "validator_controller.py",
        "validator_services.py",
        "validator_bounded.py",
        "validator_publication.py",
        "validator_firewall.py",
        "validator_runtime.py",
        "validator_registration.py",
        "validator_tls.py",
        "validator_render.py",
        "validator_credentials.py",
        "validator_public_result.py",
    ] {
        let output = std::process::Command::new("python3")
            .arg(root.join("tests").join(name))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("inert assertion-validator fixture");
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn robinhood_public_admission_is_qualified_without_signing_or_native_effects() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/robinhood_admission.py");
    let result = std::process::Command::new("python3")
        .arg("-B")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[cfg(unix)]
#[test]
fn robinhood_defensive_profiles_refuse_foreign_authority_and_nondefensive_sends() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let result = std::process::Command::new("python3")
        .arg(root.join("tests/robinhood_defensive.py"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("isolated Robinhood public-profile cases");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
