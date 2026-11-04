// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Reviewed OCI content identities. Tags never select executable bytes at deploy.

/// Current source-qualified stable Nitro version.
pub const VERSION: &str = "3.12.1";
/// GitHub release tag's resolved source revision.
pub const COMMIT: &str = "70fa99a6e711f09eedd96a907290c3df0f3bcf7d";
/// Original upstream release image tag, retained for provenance only.
pub const TAG: &str = "v3.12.1-70fa99a";
/// Official OCI index, retrieved and hashed on 2026-10-26.
pub const INDEX: &str = "sha256:62fc024836967fd3a0fe59c346f2d8706cdf5200cbea1e16bfdf07996d3b45fd";

/// Supported Linux image architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux x86-64.
    Amd64,
    /// Linux `AArch64`.
    Arm64,
}
impl Platform {
    /// Parse a host facts architecture.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "x86_64" | "amd64" => Some(Self::Amd64),
            "aarch64" | "arm64" => Some(Self::Arm64),
            _ => None,
        }
    }
    /// OCI architecture identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }
    /// Platform-specific manifest digest; not an executable tag lookup.
    #[must_use]
    pub const fn digest(self) -> &'static str {
        match self {
            Self::Amd64 => {
                "sha256:948cf8c42a6ed85bc055f13866fb9a029c8234dc16c12d7ffa4ed669270aaea8"
            }
            Self::Arm64 => {
                "sha256:b285195fcd048005d0530e87f827e9b0e506e730fd7822a6ee4ac17c93b87b32"
            }
        }
    }
}

/// An approved source/image pair. Retain older entries when adding a release so
/// existing managed records can be inspected and upgraded, never rolled back.
#[derive(Debug, Clone, Copy)]
pub struct Qualified {
    /// Canonical stable version.
    pub version: &'static str,
    /// Resolved upstream source commit.
    pub commit: &'static str,
    images: [&'static str; 2],
}
impl Qualified {
    /// Immutable image selected for a known Linux platform.
    #[must_use]
    pub fn image(self, platform: Platform) -> String {
        let index = match platform {
            Platform::Amd64 => 0,
            Platform::Arm64 => 1,
        };
        format!("docker.io/offchainlabs/nitro-node@{}", self.images[index])
    }
}
const CATALOG: &[Qualified] = &[Qualified {
    version: VERSION,
    commit: COMMIT,
    images: [Platform::Amd64.digest(), Platform::Arm64.digest()],
}];

/// Resolve only reviewed content; tags and unreviewed versions cannot select bytes.
/// # Errors
/// The catalog must be updated in a reviewed erpc release before selecting new bytes.
pub fn get(value: &str) -> Result<&'static Qualified, &'static str> {
    CATALOG
        .iter()
        .find(|release| release.version == value)
        .ok_or("Nitro release is not in this CLI's reviewed image catalog")
}
/// Validate the release without opening a connection.
/// # Errors
/// Rejects versions outside the reviewed catalog.
pub fn qualify(value: &str) -> Result<(), &'static str> {
    get(value).map(|_| ())
}

fn numbered(value: &str) -> Result<Vec<u16>, &'static str> {
    value
        .split('.')
        .map(|part| {
            part.parse()
                .map_err(|_| "invalid version in release catalog")
        })
        .collect()
}
/// Refuse database downgrades before changing desired inventory.
/// # Errors
/// Both versions must be in the reviewed catalog and the new version cannot be older.
pub fn update(current: &str, wanted: &str) -> Result<&'static Qualified, &'static str> {
    let current = get(current)?;
    let wanted = get(wanted)?;
    if numbered(wanted.version)? < numbered(current.version)? {
        return Err("Nitro database downgrades are refused");
    }
    Ok(wanted)
}

#[cfg(test)]
mod tests {
    #[test]
    fn release_selection_cannot_be_redirected_or_downgraded() {
        for value in ["latest", "3.11.4", "3.12.1-rc.1", "4.0.0", "3.12.1;id"] {
            assert!(super::qualify(value).is_err());
        }
        assert!(super::qualify("3.12.1").is_ok());
        assert!(super::Platform::parse("riscv64").is_none());
    }
}
