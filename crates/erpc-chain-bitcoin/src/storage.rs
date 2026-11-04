// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! RPC storage choices. Pruning cannot be combined with the full transaction index.

use crate::network::Network;

/// Explicit retention policy. Index/archive conversions require a new sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// Retain blocks and maintain the transaction index for historical RPC.
    Full,
    /// Retain a bounded block-file set; no full transaction index.
    Pruned {
        /// Core's prune target in MiB, excluding chainstate and other overhead.
        target_mib: u64,
    },
}

impl Storage {
    /// Validate configuration without emitting a contradictory `txindex` flag.
    ///
    /// # Errors
    /// Returns an error for a target below Core's 550 MiB minimum or an excessive
    /// value outside the signed integer range consumed by Core.
    pub fn validate(self) -> Result<(), &'static str> {
        if let Self::Pruned { target_mib } = self
            && !(550..=i64::MAX as u64).contains(&target_mib)
        {
            return Err("prune target must be between 550 MiB and the signed 64-bit maximum");
        }
        Ok(())
    }

    /// Render only operator-independent, non-secret settings. Authentication uses
    /// Core's local cookie; wallets, REST and arbitrary admin listeners are disabled.
    ///
    /// # Errors
    /// Returns an error for invalid storage configuration.
    pub fn config(self, network: Network) -> Result<String, &'static str> {
        self.validate()?;
        let (prune, txindex) = match self {
            Self::Full => (0, 1),
            Self::Pruned { target_mib } => (target_mib, 0),
        };
        Ok(format!(
            "chain={}\nserver=1\ndaemon=0\ndisablewallet=1\nrest=0\ndbcache=1024\nprune={prune}\ntxindex={txindex}\n\n[{}]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport={}\nport={}\n",
            network.core_name(),
            network.core_name(),
            network.rpc_port(),
            network.p2p_port(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::Storage;
    use crate::network::Network;

    #[test]
    fn pruning_never_requests_the_incompatible_transaction_index() {
        let full = Storage::Full.config(Network::Mainnet).expect("full");
        let pruned = Storage::Pruned { target_mib: 10_240 }
            .config(Network::Testnet4)
            .expect("pruned");
        assert!(full.contains("prune=0\ntxindex=1\n"));
        assert!(pruned.contains("prune=10240\ntxindex=0\n"));
        assert!(pruned.contains("[testnet4]\nrpcbind=127.0.0.1"));
        assert!(!pruned.contains("rpcpassword"));
        for target_mib in [0, 1, 549, u64::MAX] {
            assert!(
                Storage::Pruned { target_mib }
                    .config(Network::Signet)
                    .is_err()
            );
        }
    }
}
