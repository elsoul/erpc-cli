// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Built-in network identity and explicit immutable retention choices.

/// Public network with a source-pinned genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Kaia mainnet, formerly Cypress.
    Mainnet,
    /// Kairos testnet, formerly Baobab.
    Kairos,
}
impl Network {
    /// Embedded network-specific bootstrap catalog.
    #[must_use]
    pub fn catalog(self) -> &'static serde_json::Value {
        &crate::CATALOG["networks"][self.name()]
    }
    /// Recommended stable executable profile.
    #[must_use]
    pub const fn recommended(self) -> &'static str {
        crate::release::VERSION
    }
    /// Resolve only reviewed source and image content.
    /// # Errors
    /// Unqualified tags cannot select a download.
    pub fn qualify(self, version: &str) -> Result<&'static serde_json::Value, &'static str> {
        crate::release::qualify(version)?;
        Ok(&crate::CATALOG)
    }
    /// Required fresh capacity before subtracting allocated managed data/cache.
    /// # Errors
    /// Rejects unknown original snapshot identities or malformed catalog sizes.
    pub fn initial_capacity(self, storage: &str, snapshot: &str) -> Result<u64, &'static str> {
        let floor = 4001 * 1024_u64.pow(3);
        match storage {
            "full" if snapshot == "genesis" => Ok(floor),
            "pruned" => {
                let selected = &self.catalog()["snapshots"][snapshot];
                let compressed = selected["bytes"]
                    .as_u64()
                    .ok_or("unknown original Kaia snapshot")?;
                let expanded = selected["uncompressed_bytes"]
                    .as_u64()
                    .ok_or("missing Kaia snapshot capacity")?;
                compressed
                    .checked_add(expanded)
                    .and_then(|n| n.checked_add(200_000_000_000))
                    .map(|n| n.max(floor))
                    .ok_or("Kaia capacity overflow")
            }
            _ => Err("unsupported Kaia storage/bootstrap contract"),
        }
    }
    /// Parse canonical CLI names; private network IDs are not supported.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mainnet" => Some(Self::Mainnet),
            "kairos" => Some(Self::Kairos),
            _ => None,
        }
    }
    /// Canonical CLI and client network name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Kairos => "kairos",
        }
    }
    /// Chain identity checked on every health observation.
    #[must_use]
    pub const fn id(self) -> u64 {
        match self {
            Self::Mainnet => 8217,
            Self::Kairos => 1001,
        }
    }
    /// Genesis identity from the qualified client source's params/config.go.
    #[must_use]
    pub const fn genesis(self) -> &'static str {
        match self {
            Self::Mainnet => "0xc72e5293c3c3ba38ed8ae910f780e4caaa9fb95e79784f7ab74c3c262ea7137e",
            Self::Kairos => "0xe33ff05ceec2581ca9496f38a2bf9baad5d4eed629e896ccb33d1dc991bc4b4a",
        }
    }
}

/// Selected at reservation; never converted against an existing database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// Official live-pruned snapshot followed by continuous state pruning.
    Pruned,
    /// Fresh full synchronization from genesis; no qualified full snapshot.
    Full,
}
impl Storage {
    /// Parse an explicit supported database mode.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pruned" => Some(Self::Pruned),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
    /// Stable inventory value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pruned => "pruned",
            Self::Full => "full",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_and_retention_cannot_be_inferred_from_legacy_or_private_names() {
        for name in ["8217", "1001", "cypress", "baobab", "testnet"] {
            assert!(Network::parse(name).is_none());
        }
        assert_ne!(Network::Mainnet.genesis(), Network::Kairos.genesis());
        assert!(Storage::parse("archive").is_none());
        assert_eq!(Storage::parse("pruned"), Some(Storage::Pruned));
    }
}
