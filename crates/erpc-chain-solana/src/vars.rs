// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The variables the plays read for a host, made from its inventory items.
//!
//! They are the ones `slv v init` wrote into SLV's inventory for a testnet
//! validator that only syncs, so the carried plays see what they were
//! written for. Connection variables (`ansible_host`, `ansible_user`, the key
//! file) are left out: the node runs the plays itself.

use erpc_chain::inventory::{Host, Validator};
use serde_json::{Map, Value, json};

/// The commission ERPC's testnet validator runs with, in basis points. SLV
/// wrote 1000.
const COMMISSION_BPS: u32 = 0;
/// The RPC port and the dynamic port range SLV opens on a testnet validator.
const PORT_RPC: u16 = 7211;
const DYNAMIC_PORT_RANGE: &str = "8900-8930";

/// The host variables for `host` of `validator`, with the operator's public
/// key for the `solv` user.
///
/// With `voting`, the startup script names the vote account instead of
/// `--no-voting`. The caller decides it, having checked the account on chain
/// (it votes for this identity and has its BLS key): the node still starts
/// with its unstaked identity, and votes only once the identity is put on it.
#[must_use]
pub fn host_vars(
    validator: &Validator,
    host: &Host,
    solv_authorized_key: &str,
    voting: bool,
) -> Map<String, Value> {
    let vars = json!({
        "name": validator.name,
        "identity_account": validator.identity_account,
        "identity_ref": validator.identity_ref,
        // Sync-only: no vote account, voting off. The plays check both.
        "vote_account": if voting { validator.vote_account.as_str() } else { "" },
        "authority_account": "",
        "no_voting": !voting,
        "validator_type": validator.client,
        "region": host.jito.region,
        "relayer_url": host.jito.relayer_url,
        "block_engine_url": host.jito.block_engine_url,
        "shred_receiver_address": host.jito.shred_receiver_address,
        "commission_bps": COMMISSION_BPS,
        "snapshot_url": "",
        "port_rpc": PORT_RPC,
        "dynamic_port_range": DYNAMIC_PORT_RANGE,
        "xdp_enabled": false,
        "solv_authorized_key": solv_authorized_key,
    });
    match vars {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::{Host, Jito, Role, Validator};
    use serde_json::Value;

    use super::host_vars;

    #[test]
    fn the_variables_are_the_ones_slv_writes_for_a_sync_only_testnet_validator() {
        let validator = Validator {
            name: "tv1".to_owned(),
            identity_account: "Ident".to_owned(),
            identity_ref: "op://v/i/keypair".to_owned(),
            client: "agave".to_owned(),
            ..Validator::default()
        };
        let host = Host {
            name: "tv1-a".to_owned(),
            role: Some(Role::Primary),
            jito: Jito {
                region: "ny".to_owned(),
                block_engine_url: "block-engine-ny".to_owned(),
                relayer_url: "relayer-ny".to_owned(),
                shred_receiver_address: "64.130.35.224:1002".to_owned(),
                ..Jito::default()
            },
            ..Host::default()
        };
        let vars = host_vars(&validator, &host, "ssh-ed25519 AAAA op@laptop", false);
        let mut keys: Vec<&str> = vars.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "authority_account",
                "block_engine_url",
                "commission_bps",
                "dynamic_port_range",
                "identity_account",
                "identity_ref",
                "name",
                "no_voting",
                "port_rpc",
                "region",
                "relayer_url",
                "shred_receiver_address",
                "snapshot_url",
                "solv_authorized_key",
                "validator_type",
                "vote_account",
                "xdp_enabled",
            ]
        );
        // The bootstrap check wants a boolean, not the string "true".
        assert_eq!(vars["no_voting"], Value::Bool(true));
        assert_eq!(vars["vote_account"], "");
        let voting = Validator {
            vote_account: "Vote111".to_owned(),
            ..validator.clone()
        };
        let vars = host_vars(&voting, &host, "ssh-ed25519 AAAA op@laptop", true);
        assert_eq!(vars["no_voting"], Value::Bool(false));
        assert_eq!(vars["vote_account"], "Vote111");
        // A vote account the caller has not checked is not used.
        let vars = host_vars(&voting, &host, "ssh-ed25519 AAAA op@laptop", false);
        assert_eq!(vars["vote_account"], "");
        assert_eq!(vars["validator_type"], "agave");
        assert!(!vars.contains_key("ansible_host"));
    }
}
