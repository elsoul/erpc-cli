// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Reviewed client pairs. A Base release never selects the OP clients.

use erpc_chain_rollup::profile::Family;
use serde::{Deserialize, Serialize};

/// Target host architecture, independent of the controller platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    /// Linux AMD64.
    Amd64,
    /// Linux ARM64.
    Arm64,
}

impl Architecture {
    /// Parse the host's uname architecture without guessing.
    #[must_use]
    pub fn parse(machine: &str) -> Option<Self> {
        match machine {
            "x86_64" => Some(Self::Amd64),
            "aarch64" => Some(Self::Arm64),
            _ => None,
        }
    }
}

/// Artifact trust mechanism; digests are exact per-platform identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Distribution {
    /// Signed Base native release archive with a pinned SHA-256.
    BaseArchive,
    /// Official OP OCI image selected by immutable platform manifest digest.
    OpImage,
}

/// A selected client artifact, not an untrusted URL from inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Client {
    /// Program/image name.
    pub name: &'static str,
    /// Stable upstream release version.
    pub version: &'static str,
    /// Resolved full source commit.
    pub commit: &'static str,
    /// Archive SHA-256 or OCI platform manifest digest, without prefix.
    pub sha256: &'static str,
    /// Artifact authentication and installation strategy.
    pub distribution: Distribution,
}

/// Qualified execution/consensus pair for a specific host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pair {
    /// Linux host architecture.
    pub architecture: Architecture,
    /// Execution client.
    pub execution: Client,
    /// Consensus derivation client.
    pub consensus: Client,
}

/// Base release signing key primary fingerprint.
pub const BASE_SIGNER: &str = "5EFE7BCFCD85682711F9FC30904841FFEBD38BAD";

/// Recommended stable pair, inspected 2026-10-26; not a latest-tag lookup.
#[must_use]
pub const fn recommended(family: Family, architecture: Architecture) -> Pair {
    let base = matches!(family, Family::Base);
    let arm = matches!(architecture, Architecture::Arm64);
    if base {
        Pair {
            architecture,
            execution: Client {
                name: "base-reth-node",
                version: "1.5.1",
                commit: "5476069f1eb74a56bccb56fdefd4b4bb0e3cda42",
                sha256: if arm {
                    "010b2bfc64112152c5dde435ee088f9bb3cc0938234183dcbafd38e3e8109f57"
                } else {
                    "7731fef2e236c0b68a75ad326efdd7f9f7333e4c7c1def21e439ed9ff4850b90"
                },
                distribution: Distribution::BaseArchive,
            },
            consensus: Client {
                name: "base-consensus",
                version: "1.5.1",
                commit: "5476069f1eb74a56bccb56fdefd4b4bb0e3cda42",
                sha256: if arm {
                    "c0972826d5dbad783bdbf616484f0aeb938622159db8e5b51bcdf43e80beaca6"
                } else {
                    "f7457d5fb797a815ba301e4d5d68ff17e21c98fbfe6cebc081ad8e5e300913f4"
                },
                distribution: Distribution::BaseArchive,
            },
        }
    } else {
        Pair {
            architecture,
            execution: Client {
                name: "op-reth",
                version: "2.6.1",
                commit: "e16bffa18420c86dbab693097bc33117f74a5f7d",
                sha256: if arm {
                    "b9c8fc9733c9123a17c9223a480d1f1a05cd1ad64fab2d792f76565cc44bad80"
                } else {
                    "02be1f9c1eef42abadcf7b6440a311ee0d63fe6e7289e784e544d5cb5a4de473"
                },
                distribution: Distribution::OpImage,
            },
            consensus: Client {
                name: "op-node",
                version: "1.19.11",
                commit: "43c071cbff8ad7512581561aa2d43c990544b650",
                sha256: if arm {
                    "86eedf0e54f1ab24f0d243e3cd8b86241036b49d7a52d0fc0b1639f0e00b128b"
                } else {
                    "dc7a525974c88d0c369bcffaea0f735ca268e64a354507e688328f426c0c363a"
                },
                distribution: Distribution::OpImage,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Architecture, Distribution, recommended};
    use erpc_chain_rollup::profile::Family;

    #[test]
    fn base_cannot_silently_receive_an_op_stack_client_or_wrong_architecture() {
        let base = recommended(Family::Base, Architecture::Arm64);
        assert_eq!(base.execution.name, "base-reth-node");
        assert_eq!(base.consensus.name, "base-consensus");
        assert_eq!(base.execution.distribution, Distribution::BaseArchive);
        let op = recommended(Family::Optimism, Architecture::Arm64);
        let soneium = recommended(Family::Soneium, Architecture::Arm64);
        assert_eq!(op, soneium);
        assert_ne!(base, op);
        assert_ne!(
            op.execution.sha256,
            recommended(Family::Optimism, Architecture::Amd64)
                .execution
                .sha256
        );
        assert!(Architecture::parse("riscv64").is_none());
    }
}
