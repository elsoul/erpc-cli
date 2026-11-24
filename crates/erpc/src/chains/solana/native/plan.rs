// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Compare approved, pending and requested native configuration without mutation.
use crate::solana_native::{access_values, flag, one};
use clap::ArgMatches;
use erpc_chain::inventory::solana_native::{NativeConfig, NativeHost};
use erpc_chain_solana_native as native;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub(crate) fn render(
    node: &NativeHost,
    stored: &NativeConfig,
    args: &ArgMatches,
    observed: &Value,
) -> Result<Value, String> {
    let mut change = one(args, "change").unwrap_or("deploy");
    let registration = if flag(args, "activate-validator") {
        if change != "deploy" {
            return Err(
                "activation preview requires plan --change deploy --activate-validator".into(),
            );
        }
        change = "activate-validator";
        Some(crate::solana_native_deploy::registration(
            node, stored, args,
        )?)
    } else {
        None
    };
    let mut desired = stored.clone();
    for (key, list) in [
        ("rpc-allow", &mut desired.rpc_allow),
        ("management-allow", &mut desired.management_allow),
    ] {
        if let Some(values) = access_values(args, key) {
            if change != "update-config" {
                return Err("access changes require plan --change update-config".into());
            }
            *list = values;
        }
    }
    desired
        .validate(&node.contract)
        .map_err(|_| "native access or identity configuration is invalid")?;
    let mut result = compare(node, &desired, change, observed)?;
    if let Some(registration) = registration {
        result["registration"] = registration;
    }
    Ok(result)
}

fn compare(
    node: &NativeHost,
    desired: &NativeConfig,
    change: &str,
    observed: &Value,
) -> Result<Value, String> {
    if !matches!(
        change,
        "deploy" | "update" | "update-config" | "activate-validator"
    ) || observed.get("approved").is_none()
        || observed.get("pending").is_none()
        || !observed["cutover"].is_boolean()
        || !observed["retired"].is_boolean()
    {
        return Err("native planning metadata is unavailable or invalid; use this CLI's prepared host helpers".into());
    }
    let catalog = native::catalog()?;
    let source = catalog
        .networks
        .get(&node.contract.network)
        .ok_or("native network is not qualified")?;
    let (mode, identity) = crate::solana_native_deploy::runtime_selection(
        node,
        desired,
        observed,
        change == "activate-validator",
    )?;
    let target = json!({"network":node.contract.network,"mode":mode,"identity":identity,
        "version":source.version,"commit":source.commit,"helper_revision":native::helper_revision()?,
        "catalog_sha256":format!("{:x}",Sha256::digest(native::file("node/catalog.json").ok_or("native catalog missing")?))});
    let access = json!({"rpc":desired.rpc_allow,"management":desired.management_allow});
    let approved = &observed["approved"];
    let pending = &observed["pending"];
    let source_changed = ["network", "version", "commit", "catalog_sha256"]
        .iter()
        .any(|key| approved["target"][key] != target[key]);
    let access_changed = ["rpc", "management"]
        .iter()
        .any(|key| approved["access"][key] != access[key]);
    let mut blockers = Vec::new();
    if let Err(reason) =
        crate::solana_source_upgrade::check_target(source, &observed["opening_authority"])
    {
        blockers.push(reason);
    }
    if observed["recovery"]["phase"] == "prepared" {
        blockers.push("Repeat --recover-cutover with the recorded original recovery intent; partial recovery cannot authorize deployment.");
    }
    if matches!(change, "update-config" | "activate-validator")
        && (approved.is_null() || source_changed)
    {
        blockers.push("Configuration-only updates require the same verified installed client; deploy or update the qualified client first.");
    }
    if !pending.is_null()
        && (pending["current"] != true
            || pending["action"] != change
            || target
                .as_object()
                .ok_or("invalid native target")?
                .iter()
                .any(|(key, value)| pending["target"][key] != *value)
            || (!pending["access"].is_null()
                && ["rpc", "management"]
                    .iter()
                    .any(|key| pending["access"][key] != access[key])))
    {
        blockers.push(if observed["cutover"] == true {
            "Recover the interrupted cutover with --recover-cutover <original intent> before a fresh deployment."
        } else {
            "Resume the original pending target, or explicitly abandon its build before replacing it."
        });
    }
    if observed["cutover"] == true && pending.is_null() {
        blockers.push("The stopped cutover has no resumable deployment request; preserve its original state before recovery.");
    }
    if change == "activate-validator"
        && (node.contract.is_rpc()
            || approved["target"]["mode"] != "sync"
            || approved["authorized"] != true)
    {
        blockers.push("First voting activation requires this validator host's original healthy synchronization deployment.");
    }
    if change != "activate-validator"
        && !approved.is_null()
        && (approved["target"]["mode"] != mode || approved["target"]["identity"] != identity)
    {
        blockers.push("This command cannot replace an approved runtime's role or identity.");
    }
    Ok(
        json!({"name":node.contract.name,"network":node.contract.network,"profile":node.contract.profile,
        "change":change,"approved":approved,"pending":pending,"retired":observed["retired"],"recovery":observed["recovery"],
        "desired":{"target":target,"access":access,"genesis":source.genesis,"volumes":node.contract.volumes},
        "differences":{"client":source_changed,"helpers":approved["target"]["helper_revision"]!=target["helper_revision"],"access":access_changed},
        "execution":{"build":if matches!(change,"update-config"|"activate-validator"){"reuse verified published binary"}else{"resume or build the qualified source"},
            "restarts_runtime":true,"requires_fresh_ingress_confirmation":true,"preserves_data":true},
        "opening_authority":observed["opening_authority"],"blockers":blockers,"read_only":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fresh_observation() -> Value {
        json!({"approved":null,"pending":null,"cutover":false,"retired":false,
            "opening_authority":{"opening_protocol":1,"prepared":true,"highest":null}})
    }
    fn fixture() -> (NativeHost, NativeConfig) {
        let contract = native::contract::Contract {
            schema: 1,
            profile: "agave-native-rpc".into(),
            inventory_id: "a".repeat(26),
            name: "fixture".into(),
            network: "testnet".into(),
            host_binding: "b".repeat(64),
            identity_account: "2".repeat(44),
            vote_account: None,
            authority_account: None,
            volumes: native::contract::Volumes {
                accounts: "10000000-0000-0000-0000-000000000001".into(),
                ledger: "10000000-0000-0000-0000-000000000002".into(),
                snapshots: "10000000-0000-0000-0000-000000000003".into(),
            },
        };
        (
            NativeHost {
                item_version: 1,
                contract,
                address: "192.0.2.2".into(),
                ssh_user: "ubuntu".into(),
                ssh_port: 22,
                host_key: String::new(),
            },
            NativeConfig {
                identity_ref: format!("op://{}/{}/identity", "a".repeat(26), "b".repeat(26)),
                sync_ref: None,
                sync_identity: None,
                rpc_allow: vec!["192.0.2.8/32".into()],
                management_allow: vec![],
                commission: None,
            },
        )
    }
    #[test]
    fn real_target_and_access_comparison_never_includes_private_references() {
        let (node, config) = fixture();
        let mut observed = fresh_observation();
        let fresh = compare(&node, &config, "deploy", &observed).unwrap();
        assert_eq!(fresh["differences"]["client"], true);
        observed["approved"] = json!({"target":fresh["desired"]["target"],"access":fresh["desired"]["access"],"authorized":true});
        let mut changed = config.clone();
        changed.rpc_allow = vec!["198.51.100.3/32".into()];
        let plan = compare(&node, &changed, "update-config", &observed).unwrap();
        assert_eq!(
            plan["differences"],
            json!({"client":false,"helpers":false,"access":true})
        );
        assert_eq!(plan["blockers"], json!([]));
        assert!(!plan.to_string().contains("op://"));
        observed["approved"]["target"]["commit"] = json!("c".repeat(40));
        assert!(
            !compare(&node, &changed, "update-config", &observed).unwrap()["blockers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn cancelled_or_different_pending_targets_are_reported_as_blockers() {
        let (node, config) = fixture();
        let mut observed = fresh_observation();
        let fresh = compare(&node, &config, "deploy", &observed).unwrap();
        observed["pending"] = json!({"current":false,"action":"deploy","target":fresh["desired"]["target"],"access":null});
        assert_eq!(
            compare(&node, &config, "deploy", &observed).unwrap()["blockers"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        observed["pending"]["current"] = json!(true);
        assert_eq!(
            compare(&node, &config, "deploy", &observed).unwrap()["blockers"],
            json!([])
        );
    }
    #[test]
    fn activation_preview_has_public_binding_and_later_updates_keep_voting_identity() {
        use erpc_core::chain::{Chain, Role};
        let (mut node, mut config) = fixture();
        node.contract.profile = "agave-native".into();
        node.contract.vote_account = Some("3".repeat(44));
        node.contract.authority_account = Some("4".repeat(44));
        config.sync_identity = Some("5".repeat(44));
        config.sync_ref = Some(format!("op://{}/{}/sync", "a".repeat(26), "b".repeat(26)));
        config.commission = Some(5);
        config.rpc_allow.clear();
        let mut observed = fresh_observation();
        let sync = compare(&node, &config, "deploy", &observed).unwrap();
        observed["approved"] = json!({"target":sync["desired"]["target"],"access":sync["desired"]["access"],"authorized":true});
        let parsed = crate::tree::command(Role::Validator, Chain::Solana)
            .try_get_matches_from([
                "validator",
                "plan",
                "--activate-validator",
                "--exclusive-identity",
                "--bls-public",
                "Sdc8ifFBHUBsC2Vi8MNMfZoWHzywb15tngCzNVGB44AYkmChggZPBcPhGwGD5LiNF",
            ])
            .unwrap();
        let result = render(&node, &config, parsed.subcommand().unwrap().1, &observed).unwrap();
        assert_eq!(result["desired"]["target"]["mode"], "validator");
        assert_eq!(
            result["desired"]["target"]["identity"],
            node.contract.identity_account
        );
        assert_eq!(result["registration"]["commission"], 5);
        assert_eq!(result["blockers"], json!([]));
        assert!(!result.to_string().contains("op://"));
        observed["approved"]["target"] = result["desired"]["target"].clone();
        let update = compare(&node, &config, "update-config", &observed).unwrap();
        assert_eq!(update["desired"]["target"]["mode"], "validator");
        assert_eq!(update["blockers"], json!([]));
        assert_eq!(
            update["desired"]["target"]["identity"],
            node.contract.identity_account
        );
        let (rpc, config) = fixture();
        assert!(render(&rpc, &config, parsed.subcommand().unwrap().1, &observed).is_err());
    }
    #[test]
    fn plan_surfaces_missing_history_and_a_higher_original_opening_floor() {
        let (node, config) = fixture();
        let mut observed = fresh_observation();
        observed
            .as_object_mut()
            .unwrap()
            .remove("opening_authority");
        let plan = compare(&node, &config, "deploy", &observed).unwrap();
        assert!(
            plan["blockers"][0]
                .as_str()
                .unwrap()
                .contains("upgrade-source-authority")
        );
        observed = fresh_observation();
        observed["opening_authority"]["highest"] =
            json!({"version":"99.0.0","commit":"a".repeat(40)});
        let plan = compare(&node, &config, "update", &observed).unwrap();
        assert!(plan["blockers"][0].as_str().unwrap().contains("below"));
        assert_eq!(plan["opening_authority"], observed["opening_authority"]);
        assert_eq!(plan["read_only"], true);
    }
}
