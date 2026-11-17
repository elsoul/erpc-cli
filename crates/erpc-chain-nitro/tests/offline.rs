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

/// One test per Python fixture, named after its file: the fixtures run in
/// parallel, and each one that fails is reported, not only the first. The
/// modules that use it are `cfg(test)`, so their shared `fixture` helper may
/// `expect` as a test does.
#[cfg(unix)]
macro_rules! fixtures {
    ($($fixture:ident),* $(,)?) => {
        $(
            #[test]
            fn $fixture() {
                fixture(concat!(stringify!($fixture), ".py"));
            }
        )*
    };
}

#[cfg(unix)]
#[cfg(test)]
mod carried_controller_enforces_ownership_fences_credentials_and_service_contracts {
    fn fixture(script: &str) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
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

    fixtures! {
        lifecycle,
        recovery,
    }
}

#[cfg(unix)]
#[cfg(test)]
mod assertion_validator_authority_and_public_admission_are_exercised_offline {
    fn fixture(name: &str) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
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

    fixtures! {
        validator_artifact,
        validator_admission,
        validator_configuration,
        validator_state,
        validator_accounts,
        validator_crypto,
        validator_transactions,
        validator_transport,
        validator_observer,
        validator_host,
        validator_preflight,
        validator_custody,
        validator_wallet_stage,
        validator_provider_stage,
        validator_processes,
        validator_protocol,
        validator_authority,
        validator_container,
        validator_history,
        validator_volumes,
        validator_controller,
        validator_services,
        validator_bounded,
        validator_publication,
        validator_firewall,
        validator_runtime,
        validator_registration,
        validator_tls,
        validator_render,
        validator_credentials,
        validator_public_result,
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
