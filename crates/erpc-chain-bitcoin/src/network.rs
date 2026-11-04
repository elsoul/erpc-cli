// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin Core v31.1 chain parameters; see docs/chains/bitcoin.md.

/// An explicitly selected Bitcoin network. Deprecated testnet3 is not offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Production Bitcoin.
    Mainnet,
    /// Public testnet4.
    Testnet4,
    /// Default public signet; custom signet challenges require separate support.
    Signet,
    /// Local regression-test network, never treated as synchronized by peer age.
    Regtest,
}

impl Network {
    /// Accepts CLI canonical names only; `testnet` is deliberately ambiguous.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "mainnet" => Some(Self::Mainnet),
            "testnet4" => Some(Self::Testnet4),
            "signet" => Some(Self::Signet),
            "regtest" => Some(Self::Regtest),
            _ => None,
        }
    }

    /// Network value used in inventory and CLI.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// Bitcoin Core's `chain` configuration/status value.
    #[must_use]
    pub const fn core_name(self) -> &'static str {
        match self {
            Self::Mainnet => "main",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// Core appends this subdirectory to the explicit data directory.
    #[must_use]
    pub const fn data_suffix(self) -> &'static str {
        match self {
            Self::Mainnet => "",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// Default P2P TCP port.
    #[must_use]
    pub const fn p2p_port(self) -> u16 {
        match self {
            Self::Mainnet => 8333,
            Self::Testnet4 => 48333,
            Self::Signet => 38333,
            Self::Regtest => 18444,
        }
    }

    /// Native RPC TCP port; keep this listener on loopback.
    #[must_use]
    pub const fn rpc_port(self) -> u16 {
        match self {
            Self::Mainnet => 8332,
            Self::Testnet4 => 48332,
            Self::Signet => 38332,
            Self::Regtest => 18443,
        }
    }

    /// Genesis identifier that the controller must read from block zero.
    #[must_use]
    pub const fn genesis(self) -> &'static str {
        match self {
            Self::Mainnet => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            Self::Testnet4 => "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            Self::Signet => "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            Self::Regtest => "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        }
    }
}
