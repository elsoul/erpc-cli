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
    let output = std::process::Command::new("python3")
        .arg(root.join("tests/lifecycle.py"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("offline Python harness");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
