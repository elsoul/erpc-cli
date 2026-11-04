// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `AvalancheGo` lifecycle policy and embedded, signature-verified deployment.
#![forbid(unsafe_code)]

use include_dir::{Dir, include_dir};
use serde::{Deserialize, Serialize};

pub mod registration;
pub mod release;
pub mod status;

/// Workspace component name.
pub const CRATE_NAME: &str = "erpc-chain-avax";
/// Templates used by remote Ansible runs.
pub static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// Avalanche network identity. P-Chain network IDs are distinct from C-Chain EVM IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Primary Network mainnet.
    Mainnet,
    /// Fuji testnet.
    Fuji,
}
impl Network {
    /// Parse the canonical CLI name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mainnet" => Some(Self::Mainnet),
            "fuji" => Some(Self::Fuji),
            _ => None,
        }
    }
    /// `AvalancheGo` network selector.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Fuji => "fuji",
        }
    }
    /// Avalanche network ID, used by P/X APIs.
    #[must_use]
    pub const fn id(self) -> u32 {
        match self {
            Self::Mainnet => 1,
            Self::Fuji => 5,
        }
    }
    /// EVM chain ID, used only by the C-Chain.
    #[must_use]
    pub const fn evm_id(self) -> u32 {
        match self {
            Self::Mainnet => 43114,
            Self::Fuji => 43113,
        }
    }
}
/// Files carried in the deployment bundle.
#[must_use]
pub fn files() -> Vec<(&'static str, &'static [u8])> {
    fn collect(dir: &'static Dir<'static>, files: &mut Vec<(&'static str, &'static [u8])>) {
        for file in dir.files() {
            if let Some(path) = file.path().to_str() {
                files.push((path, file.contents()));
            }
        }
        for child in dir.dirs() {
            collect(child, files);
        }
    }
    let mut files = Vec::new();
    collect(&TEMPLATES, &mut files);
    files.sort_unstable_by_key(|(p, _)| *p);
    files
}
