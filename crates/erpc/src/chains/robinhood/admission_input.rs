// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Validate public registration input before a provider, host or run bundle is used.
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{io::Read as _, path::Path};

pub(crate) fn catalog() -> Result<Value, String> {
    let file = erpc_chain_nitro::TEMPLATES
        .get_file("robinhood-admission/node/catalog.json")
        .ok_or("missing compiled Robinhood admission catalog")?;
    let value: Value = serde_json::from_slice(file.contents())
        .map_err(|_| "invalid compiled admission catalog")?;
    if value["schema"] != 1 {
        return Err("unsupported compiled admission catalog".into());
    }
    Ok(value)
}

pub(crate) fn profile(network: &str) -> Result<Value, String> {
    let qualified = erpc_chain_nitro::network::Network::parse("robinhood", network)
        .ok_or("Robinhood admission requires explicit mainnet or testnet")?;
    let value = catalog()?["profiles"][network].clone();
    if value["child"] != qualified.id()
        || value["parent"] != if network == "mainnet" { 1 } else { 11_155_111 }
        || value["chain_info_sha256"] != qualified.chain_info()?.1
    {
        return Err("admission catalog differs from the qualified network".into());
    }
    for name in ["bridge", "rollup", "stake_asset_address"] {
        address(value[name].as_str().ok_or("missing protocol address")?)?;
    }
    Ok(value)
}

pub(crate) fn address(value: &str) -> Result<String, String> {
    let value = value.to_ascii_lowercase();
    if value.len() != 42
        || !value.starts_with("0x")
        || !erpc_chain_nitro::validator::hex(&value[2..], 40)
        || value[2..].bytes().all(|byte| byte == b'0')
    {
        return Err("pass a nonzero public validator EOA address".into());
    }
    Ok(value)
}

pub(crate) fn calldata(validator: &str) -> Result<String, String> {
    let validator = address(validator)?;
    Ok(format!(
        "0xa3ffb772{:064x}{:064x}{:064x}{:0>64}{:064x}{:064x}",
        64,
        128,
        1,
        &validator[2..],
        1,
        1
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    block: SecretString,
    block_hash: SecretString,
    block_timestamp: u64,
    observed_at: u64,
}
impl Snapshot {
    fn checked(self) -> Result<Value, String> {
        let block = self.block.expose_secret();
        let digits = block.strip_prefix("0x").ok_or("invalid public snapshot")?;
        let number = u64::from_str_radix(digits, 16).map_err(|_| "invalid public snapshot")?;
        let hash = self.block_hash.expose_secret();
        if number == 0
            || block != format!("0x{number:x}")
            || hash.len() != 66
            || !hash.starts_with("0x")
            || !erpc_chain_nitro::validator::hex(&hash[2..], 64)
            || hash[2..].bytes().all(|byte| byte == b'0')
            || self.block_timestamp == 0
            || self.observed_at == 0
        {
            return Err("invalid bounded public snapshot".into());
        }
        Ok(
            json!({"block":block,"block_hash":hash,"block_timestamp":self.block_timestamp,"observed_at":self.observed_at}),
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: SecretString,
    network: SecretString,
    parent_chain_id: u64,
    child_chain_id: u64,
    parent_genesis: SecretString,
    bridge: SecretString,
    rollup: SecretString,
    validator_address: SecretString,
    value: SecretString,
    calldata: SecretString,
    contracts_source_commit: SecretString,
    administrator_selected_externally: bool,
    financial_action_performed: bool,
    snapshot: Snapshot,
    notice: SecretString,
}

fn parse(raw: &[u8], network: &str, validator: &str) -> Result<Value, String> {
    let input: Intent =
        serde_json::from_slice(raw).map_err(|_| "invalid closed public admission intent")?;
    let catalog = catalog()?;
    let profile = profile(network)?;
    let validator = address(validator)?;
    let call = calldata(&validator)?;
    let source = catalog["contracts_source_commit"]
        .as_str()
        .ok_or("missing public ABI source")?;
    let notice = catalog["external_review_notice"]
        .as_str()
        .ok_or("missing public review notice")?;
    if input.schema.expose_secret() != "erpc-robinhood-admission-intent-v1"
        || input.network.expose_secret() != network
        || profile["parent"] != input.parent_chain_id
        || profile["child"] != input.child_chain_id
        || profile["genesis"] != input.parent_genesis.expose_secret()
        || profile["bridge"] != input.bridge.expose_secret()
        || profile["rollup"] != input.rollup.expose_secret()
        || input.validator_address.expose_secret() != validator
        || input.value.expose_secret() != "0x0"
        || input.calldata.expose_secret() != call
        || input.contracts_source_commit.expose_secret() != source
        || input.notice.expose_secret() != notice
        || !input.administrator_selected_externally
        || input.financial_action_performed
    {
        return Err("intent differs from the requested network, public sender or external administrator call".into());
    }
    let snapshot = input.snapshot.checked()?;
    Ok(
        json!({"schema":"erpc-robinhood-admission-intent-v1","network":network,
        "parent_chain_id":profile["parent"],"child_chain_id":profile["child"],
        "parent_genesis":profile["genesis"],"bridge":profile["bridge"],"rollup":profile["rollup"],
        "validator_address":validator,"value":"0x0","calldata":call,"contracts_source_commit":source,
        "administrator_selected_externally":true,"financial_action_performed":false,"snapshot":snapshot,"notice":notice}),
    )
}

pub(crate) fn read(path: &Path, network: &str, validator: &str) -> Result<Value, String> {
    let before =
        std::fs::symlink_metadata(path).map_err(|_| "cannot inspect public admission intent")?;
    if !before.is_file() || before.len() > 16384 {
        return Err("public intent must be a bounded regular file".into());
    }
    let file = std::fs::File::open(path).map_err(|_| "cannot open public admission intent")?;
    let opened = file
        .metadata()
        .map_err(|_| "cannot inspect opened public intent")?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err("public intent changed while opening".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err("public intent identity changed while opening".into());
        }
    }
    let mut raw = zeroize::Zeroizing::new(Vec::new());
    file.take(16385)
        .read_to_end(&mut raw)
        .map_err(|_| "cannot read public intent")?;
    if raw.len() > 16384 {
        return Err("public admission intent exceeds its bound".into());
    }
    parse(&raw, network, validator)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn intent(network: &str, wallet: &str) -> Value {
        let p = profile(network).unwrap();
        let c = catalog().unwrap();
        json!({"schema":"erpc-robinhood-admission-intent-v1","network":network,
            "parent_chain_id":p["parent"],"child_chain_id":p["child"],"parent_genesis":p["genesis"],
            "bridge":p["bridge"],"rollup":p["rollup"],"validator_address":wallet,"value":"0x0",
            "calldata":calldata(wallet).unwrap(),"contracts_source_commit":c["contracts_source_commit"],
            "administrator_selected_externally":true,"financial_action_performed":false,
            "snapshot":{"block":"0x1234","block_hash":format!("0x{}","b".repeat(64)),"block_timestamp":1_999_400,"observed_at":2_000_000},
            "notice":c["external_review_notice"]})
    }
    #[test]
    fn bounded_intents_keep_only_exact_public_network_sender_and_administrator_payload() {
        let wallet = format!("0x{}", "1".repeat(40));
        for network in ["mainnet", "testnet"] {
            let value = intent(network, &wallet);
            assert_eq!(
                parse(value.to_string().as_bytes(), network, &wallet).unwrap(),
                value
            );
            for (key, wrong) in [
                ("schema", json!("INERT_PRIVATE_MARKER")),
                ("notice", json!("INERT_PRIVATE_MARKER")),
                ("network", json!("other")),
                ("parent_chain_id", json!(true)),
                ("value", json!("0x1")),
                ("calldata", json!("0xdeadbeef")),
                ("validator_address", json!(format!("0x{}", "2".repeat(40)))),
                ("administrator_selected_externally", json!(1)),
                ("financial_action_performed", json!(true)),
            ] {
                let mut changed = value.clone();
                changed[key] = wrong;
                let error = parse(changed.to_string().as_bytes(), network, &wallet).unwrap_err();
                assert!(!error.contains("INERT_PRIVATE_MARKER"));
            }
            let mut changed = value.clone();
            changed["snapshot"]["block"] = json!("0x01234");
            assert!(parse(changed.to_string().as_bytes(), network, &wallet).is_err());
            changed = value;
            changed["private_input"] = json!("INERT_PRIVATE_MARKER");
            assert!(
                !parse(changed.to_string().as_bytes(), network, &wallet)
                    .unwrap_err()
                    .contains("INERT_PRIVATE_MARKER")
            );
        }
    }
    #[test]
    fn calldata_is_the_canonical_single_validator_admin_array_call() {
        let address = format!("0x{}", "12".repeat(20));
        let call = calldata(&address).unwrap();
        assert_eq!(call.len(), 2 + 8 + 6 * 64);
        assert!(call.starts_with("0xa3ffb772"));
        assert_eq!(
            &call[10 + 3 * 64..10 + 4 * 64],
            format!("{:0>64}", &address[2..])
        );
        assert_eq!(&call[call.len() - 64..], format!("{:064x}", 1));
        assert!(calldata(&format!("0x{}", "0".repeat(40))).is_err());
    }
}
