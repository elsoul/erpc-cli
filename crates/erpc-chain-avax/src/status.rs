// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed interpretation of local P/C/X and validator observations.
use crate::Network;
use serde_json::Value;
/// Readiness requires both correct network IDs and all three bootstraps.
#[must_use]
pub fn ready(s: &Value, network: Network) -> bool {
    s["network"]["result"]["networkID"]
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .or_else(|| {
            s["network"]["result"]["networkID"]
                .as_u64()
                .and_then(|v| v.try_into().ok())
        })
        == Some(network.id())
        && s["chain_id"]["result"]
            .as_str()
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            == Some(network.evm_id())
        && ["P", "X", "C"]
            .iter()
            .all(|c| s["bootstrap"][c]["result"]["isBootstrapped"] == true)
        && s["health"]["result"]["healthy"] == true
}
/// The P-Chain response, never process liveness, establishes admission.
#[must_use]
pub fn validator_state(s: &Value, node_id: &str, term_end: Option<u64>, now: u64) -> &'static str {
    // getPendingValidators was removed after Durango. Acceptance starts validation
    // immediately; an empty current set is not proof that no transaction is pending.
    let Some(nodes) = s["current"]["result"]["validators"].as_array() else {
        return "unknown";
    };
    if nodes.iter().any(|n| n["nodeID"] == node_id) {
        return "active";
    }
    if term_end.is_some_and(|end| now >= end) {
        "term finished (historical registration and reward unverified)"
    } else {
        "not active"
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn unknown_or_wrong_network_is_never_ready() {
        let mut s = json!({"network":{"result":{"networkID":"5"}},"chain_id":{"result":"0xa869"},"bootstrap":{},"health":{"result":{"healthy":true}}});
        assert!(!ready(&s, Network::Fuji));
        for c in ["P", "X", "C"] {
            s["bootstrap"][c] = json!({"result":{"isBootstrapped":true}});
        }
        assert!(ready(&s, Network::Fuji));
        assert!(!ready(&s, Network::Mainnet));
        s["bootstrap"]["P"]["result"]["isBootstrapped"] = json!(false);
        assert!(!ready(&s, Network::Fuji));
    }
    #[test]
    fn registration_is_not_implied_by_health() {
        assert_eq!(validator_state(&json!({}), "node", None, 0), "unknown");
        // v1.15.2 GetCurrentValidatorsReply returns only validators. No legacy
        // pending response is required for a fresh node to prepare registration.
        let s = json!({"jsonrpc":"2.0","id":1,"current":{"result":{"validators":[]}}});
        assert_eq!(validator_state(&s, "node", None, 0), "not active");
        assert_eq!(
            validator_state(
                &json!({"current":{"error":{"code":-32601}}}),
                "node",
                None,
                0
            ),
            "unknown"
        );
        let active = json!({"current":{"result":{"validators":[{"nodeID":"node","startTime":"100","endTime":"200","stakeAmount":"1000000000"}]}}});
        assert_eq!(validator_state(&active, "node", None, 0), "active");
        assert_eq!(
            validator_state(&s, "other", Some(1), 2),
            "term finished (historical registration and reward unverified)"
        );
    }
}
