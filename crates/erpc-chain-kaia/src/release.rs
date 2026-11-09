// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed OCI content and source qualification. Tags never select executable bytes.

/// Latest stable source-qualified release as of 2026-10-26.
pub const VERSION: &str = "2.2.2";
/// Resolved upstream release source revision.
pub const COMMIT: &str = "ac7c81f3a9759704b5ce77b42ae91851ce45a9c3";
/// Exact official Linux AMD64 image manifest.
pub const IMAGE: &str = "docker.io/kaiachain/kaia@sha256:3d7c03285024e393848ffc001309e1cb27b3271b9c84f0d6f1548557e894f5c5";

/// The Docker guide and final-image source qualify only Linux AMD64. A registry
/// ARM64 label alone does not establish a runnable native image.
#[must_use]
pub fn platform(value: &str) -> Option<&'static str> {
    matches!(value, "amd64" | "x86_64").then_some("amd64")
}

/// Refuse unreviewed versions before changing a desired deployment record.
/// # Errors
/// A new release needs an independently reviewed catalog update.
pub fn qualify(version: &str) -> Result<(), &'static str> {
    if version == VERSION {
        Ok(())
    } else {
        Err("Kaia release is not in this CLI's reviewed image catalog")
    }
}

/// Refuse unknown current/wanted releases and database downgrades.
/// # Errors
/// Both endpoints must be source-qualified; the current single-entry catalog
/// permits only an idempotent update.
pub fn update(current: &str, wanted: &str) -> Result<(), &'static str> {
    qualify(current)?;
    qualify(wanted)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tags_and_unqualified_arm_images_cannot_select_executable_content() {
        for version in ["latest", "v2.2.2", "2.2.1", "2.2.3", "2.2.2;id"] {
            assert!(qualify(version).is_err());
        }
        assert!(update(VERSION, VERSION).is_ok());
        assert!(platform("aarch64").is_none());
        assert!(platform("arm64").is_none());
        assert_eq!(platform("x86_64"), Some("amd64"));
        let catalog: serde_json::Value =
            serde_json::from_str(include_str!("../templates/node/catalog.json")).unwrap();
        assert_eq!(catalog["image"], IMAGE);
        assert_eq!(catalog["commit"], COMMIT);
        for network in [
            crate::network::Network::Mainnet,
            crate::network::Network::Kairos,
        ] {
            let value = &catalog["networks"][network.name()];
            assert_eq!(value["chain_id"], network.id());
            assert_eq!(value["genesis"], network.genesis());
            let snapshot = &value["snapshots"][value["recommended_snapshot"].as_str().unwrap()];
            assert!(snapshot["sha256"].is_null());
            assert_eq!(snapshot["md5"].as_str().unwrap().len(), 32);
            assert!(
                snapshot["uncompressed_bytes"].as_u64().unwrap()
                    > snapshot["bytes"].as_u64().unwrap()
            );
        }
    }
}
