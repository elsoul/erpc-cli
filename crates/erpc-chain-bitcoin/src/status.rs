// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Typed Core status. A responding process is not sufficient evidence of readiness.

use crate::network::Network;
use serde::Deserialize;

/// Required fields from `getblockchaininfo`; absent fields fail deserialization.
#[derive(Debug, Deserialize)]
pub struct BlockchainInfo {
    /// Core's network name.
    pub chain: String,
    /// Validated block count.
    pub blocks: u64,
    /// Known header count.
    pub headers: u64,
    /// Fraction of chain validation work completed.
    pub verificationprogress: f64,
    /// Core's own initial block download state.
    pub initialblockdownload: bool,
    /// Whether old block files are pruned.
    pub pruned: bool,
}

impl BlockchainInfo {
    /// Check identity and core sync state, not index readiness or peer freshness.
    /// The caller must additionally inspect `getindexinfo` for indexed RPC and
    /// peers/tip progress before admitting remote traffic.
    ///
    /// # Errors
    /// Wrong network/genesis or inconsistent progress produces an error, not an
    /// apparent syncing/success state.
    pub fn synced(&self, network: Network, genesis: &str) -> Result<bool, &'static str> {
        if self.chain != network.core_name() || genesis != network.genesis() {
            return Err("Bitcoin network/genesis mismatch");
        }
        if !self.verificationprogress.is_finite()
            || !(0.0..=1.0).contains(&self.verificationprogress)
            || self.blocks > self.headers
        {
            return Err("invalid Bitcoin synchronization status");
        }
        Ok(!self.initialblockdownload && self.blocks == self.headers)
    }
}

#[cfg(test)]
mod tests {
    use super::BlockchainInfo;
    use crate::network::Network;

    #[test]
    fn readiness_does_not_default_missing_or_wrong_network_data_to_success() {
        assert!(serde_json::from_str::<BlockchainInfo>("{}").is_err());
        let mut info: BlockchainInfo = serde_json::from_str(r#"{"chain":"signet","blocks":100,"headers":101,"verificationprogress":0.99,"initialblockdownload":true,"pruned":false}"#).expect("fixture");
        assert_eq!(
            info.synced(Network::Signet, Network::Signet.genesis()),
            Ok(false)
        );
        info.headers = 100;
        info.initialblockdownload = false;
        assert_eq!(
            info.synced(Network::Signet, Network::Signet.genesis()),
            Ok(true)
        );
        assert!(
            info.synced(Network::Mainnet, Network::Signet.genesis())
                .is_err()
        );
        assert!(
            info.synced(Network::Signet, Network::Regtest.genesis())
                .is_err()
        );
        info.verificationprogress = f64::NAN;
        assert!(
            info.synced(Network::Signet, Network::Signet.genesis())
                .is_err()
        );
    }
}

/// Operational RPC readiness, including requested retention/index semantics.
#[derive(Debug, serde::Serialize)]
pub struct Readiness {
    /// All identity, service, sync and index checks passed.
    pub ready: bool,
    /// Concrete missing readiness evidence; empty only when ready.
    pub problems: Vec<&'static str>,
}

/// Evaluate the bounded inspection response returned by the owned host helper.
/// No missing field is silently treated as healthy.
#[must_use]
pub fn evaluate(
    network: Network,
    storage: crate::storage::Storage,
    response: &serde_json::Value,
    now: u64,
) -> Readiness {
    let mut problems = Vec::new();
    if response["phase"] != "installed" || response["service"] != "active" {
        problems.push("service is not installed and active");
    }
    if response["stopped"] != false
        || response["authority_valid"] != true
        || response["process_owned"] != true
        || response["source_current"] != true
    {
        problems.push("original active process, source or account authority is unproven or fenced");
    }
    if response["rpc_available"] != true {
        problems.push("RPC inspection is unavailable or warming up");
    }
    let info = serde_json::from_value::<BlockchainInfo>(response["blockchain"].clone());
    if let Ok(info) = info {
        match info.synced(network, response["genesis"].as_str().unwrap_or_default()) {
            Ok(true) => {}
            Ok(false) => {
                problems.push("initial block download or header synchronization is incomplete");
            }
            Err(_) => problems.push("network/genesis or synchronization metadata is invalid"),
        }
        let pruned = matches!(storage, crate::storage::Storage::Pruned { .. });
        if pruned != info.pruned {
            problems.push("retention differs from the immutable storage contract");
        }
        if !pruned
            && (response["indexes"]["txindex"]["synced"] != true
                || response["indexes"]["txindex"]["best_block_height"]
                    .as_u64()
                    .is_none_or(|height| height < info.blocks))
        {
            problems.push("full transaction index has not reached the validated tip");
        }
    } else {
        problems.push("blockchain inspection fields are missing or malformed");
    }
    if network != Network::Regtest {
        if response["connections"]
            .as_u64()
            .is_none_or(|peers| peers == 0)
        {
            problems.push("no peer connectivity");
        }
        if response["tip_time"]
            .as_u64()
            .is_none_or(|tip| tip > now.saturating_add(7200) || now.saturating_sub(tip) > 86_400)
        {
            problems.push("tip timestamp is stale, unavailable or implausibly future");
        }
    }
    Readiness {
        ready: problems.is_empty(),
        problems,
    }
}
