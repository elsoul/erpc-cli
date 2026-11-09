// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Reviewed network-qualified distribution and genesis metadata.
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// One immutable downloadable artifact; digests authenticate content before use.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    /// Fixed source URL, including the genesis object's immutable generation.
    pub url: String,
    /// Expected SHA-256 of the complete bytes.
    pub sha256: String,
    /// Exact byte count, also a download bound.
    pub bytes: u64,
}

/// Debian package and its separately pinned keyless signature material.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    /// Package; extracted only after signature verification, never installed with maintainer scripts.
    pub package: File,
    /// Detached Sigstore signature, not `OpenPGP`.
    pub signature: File,
    /// Base64-encoded PEM Fulcio certificate from the signing workflow.
    pub certificate: File,
}

/// One independently versioned layer of the Polygon stack.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    /// Exact stable release tag.
    pub tag: String,
    /// Resolved source commit.
    pub commit: String,
    /// Official release publication time.
    pub published_at: String,
    /// Exact GitHub Actions workflow and tag identity, checked by Cosign.
    pub certificate_identity: String,
    /// Architecture-qualified packages.
    pub assets: BTreeMap<String, Package>,
}

/// Signature verifier bootstrap, independently SHA-256 pinned.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Verifier {
    /// Resolved source commit of the verifier release.
    pub commit: String,
    /// Official publication time of the verifier release.
    pub published_at: String,
    /// Exact Cosign release tag.
    pub tag: String,
    /// Architecture-qualified binaries.
    pub assets: BTreeMap<String, File>,
}

/// Network identity, dual-client release pair and complete upstream configurations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Mainnet or Amoy.
    pub network: String,
    /// Bor EVM chain ID.
    pub chain_id: u64,
    /// Mainnet Ethereum or Sepolia parent network.
    pub parent: String,
    /// Expected Bor block-zero hash.
    pub bor_genesis_hash: String,
    /// Migrated Heimdall v2 chain ID.
    pub heimdall_chain_id: String,
    /// First height in the migrated v2 chain.
    pub heimdall_initial_height: u64,
    /// Complete migrated genesis, pinned by an observed hash of official bytes.
    pub heimdall_genesis: File,
    /// GCS object generation, independently matched during hashing.
    pub genesis_generation: String,
    /// Date of primary-source verification.
    pub observed_at: String,
    /// Bor and Heimdall pins, upgraded as an explicitly reviewed pair.
    pub releases: BTreeMap<String, Release>,
    /// Full Bor, Heimdall consensus and Heimdall application configurations.
    pub configs: BTreeMap<String, File>,
    /// Exact signature-verifier distribution.
    pub verifier: Verifier,
}

impl Network {
    /// Parse an embedded reviewed profile; runtime URLs never select a profile.
    /// # Errors
    /// Refuses unsupported networks or a malformed embedded catalog.
    pub fn get(network: &str) -> Result<Self, String> {
        let bytes = match network {
            "mainnet" => include_str!("../networks/mainnet.json"),
            "amoy" => include_str!("../networks/amoy.json"),
            _ => return Err("Polygon PoS supports Mainnet and Amoy".into()),
        };
        serde_json::from_str(bytes).map_err(|_| "invalid embedded Polygon profile".into())
    }

    /// Bind the exact complete reviewed profile into a remote deployment intent.
    /// # Errors
    /// Serialization failure prevents constructing a target.
    pub fn digest(&self) -> Result<String, String> {
        fn ordered(value: serde_json::Value) -> serde_json::Value {
            match value {
                serde_json::Value::Object(fields) => {
                    let sorted: BTreeMap<_, _> = fields
                        .into_iter()
                        .map(|(key, value)| (key, ordered(value)))
                        .collect();
                    serde_json::Value::Object(sorted.into_iter().collect())
                }
                serde_json::Value::Array(values) => {
                    serde_json::Value::Array(values.into_iter().map(ordered).collect())
                }
                other => other,
            }
        }
        let value = serde_json::to_value(self).map_err(|_| "cannot encode Polygon profile")?;
        let bytes =
            serde_json::to_vec(&ordered(value)).map_err(|_| "cannot encode Polygon profile")?;
        if !bytes.is_ascii() {
            return Err("reviewed Polygon metadata must be ASCII".into());
        }
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Select a supported host architecture before any download or mutation.
    /// # Errors
    /// Refuses any platform without both client packages and the verifier.
    pub fn platform(&self, architecture: &str) -> Result<(), String> {
        if !["x86_64", "aarch64"].contains(&architecture)
            || !self.verifier.assets.contains_key(architecture)
            || self.releases.len() != 2
            || ["bor", "heimdall"].iter().any(|layer| {
                !self
                    .releases
                    .get(*layer)
                    .is_some_and(|r| r.assets.contains_key(architecture))
            })
        {
            return Err(
                "Polygon requires reviewed Linux x86_64/aarch64 packages for both clients".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_bind_both_layers_and_immutable_migrated_genesis() {
        for (name, chain, parent, height) in [
            ("mainnet", 137, "mainnet", 24_404_501),
            ("amoy", 80_002, "sepolia", 8_788_501),
        ] {
            let profile = Network::get(name).unwrap();
            assert_eq!(
                (
                    profile.chain_id,
                    profile.parent.as_str(),
                    profile.heimdall_initial_height
                ),
                (chain, parent, height)
            );
            assert_eq!(profile.heimdall_chain_id, format!("heimdallv2-{chain}"));
            assert!(
                profile
                    .heimdall_genesis
                    .url
                    .ends_with(&format!("?generation={}", profile.genesis_generation))
            );
            assert_eq!(profile.releases["bor"].tag, "v2.10.3");
            assert_eq!(profile.releases["heimdall"].tag, "v0.13.2");
            assert_ne!(
                profile.releases["bor"].commit,
                profile.releases["heimdall"].commit
            );
            for arch in ["x86_64", "aarch64"] {
                profile.platform(arch).unwrap();
            }
            assert!(profile.platform("riscv64").is_err());
            let mut changed = profile.clone();
            changed.heimdall_genesis.sha256 = "0".repeat(64);
            assert_ne!(profile.digest().unwrap(), changed.digest().unwrap());
        }
        assert!(Network::get("mumbai").is_err());
    }
}
