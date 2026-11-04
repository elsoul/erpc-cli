// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The kinds of Ethereum RPC node erpc runs.
//!
//! - **full**: pruned the way `reth download --full` leaves it: state in
//!   full, transactions since the Merge, receipts and history for the last
//!   10,064 blocks. Serves `eth`, `net` and `web3`.
//! - **archive**: everything, and `debug` and `trace` besides.

/// What kind of Ethereum RPC node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcType {
    /// Pruned, the usual RPC node.
    Full,
    /// Every block's history and state.
    Archive,
}

impl RpcType {
    /// Every kind, as the flag takes them.
    pub const NAMES: [&'static str; 2] = ["full", "archive"];

    /// The kind `name` names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "full" => Some(Self::Full),
            "archive" => Some(Self::Archive),
            _ => None,
        }
    }

    /// The name the flag and the inventory use; also `reth download`'s
    /// preset (`--full`, `--archive`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Archive => "archive",
        }
    }

    /// The JSON-RPC namespaces served over HTTP and WebSocket.
    #[must_use]
    pub const fn apis(self) -> &'static str {
        match self {
            Self::Full => "eth,net,web3",
            Self::Archive => "eth,net,web3,debug,trace",
        }
    }

    /// The free space the Reth datadir needs before the snapshot, in GB:
    /// what it holds extracted on 2026-10-23, plus the largest archive while
    /// it is extracted, plus room to grow.
    #[must_use]
    pub const fn min_free_gb(self) -> u64 {
        match self {
            Self::Full => 1_500,
            Self::Archive => 3_500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RpcType;

    #[test]
    fn the_kinds_read_back_and_archive_serves_more() {
        for name in RpcType::NAMES {
            assert_eq!(RpcType::parse(name).map(RpcType::as_str), Some(name));
        }
        assert_eq!(RpcType::parse("provider"), None);
        assert!(!RpcType::Full.apis().contains("trace"));
        assert!(RpcType::Archive.apis().contains("debug"));
        assert!(RpcType::Archive.min_free_gb() > RpcType::Full.min_free_gb());
    }
}
