// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated Ethereum signer ownership, deployment and lifecycle.

use crate::{
    commands::Outcome,
    eth_rpc::{Facts, Login},
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{EthRpc, Store, eth_validator::EthValidator};
use erpc_chain_eth::{
    releases::{self, Client},
    validator,
};
use erpc_ssh::{RemoteCommand, Session};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::path::Path;

fn one<'a>(sub: &'a ArgMatches, name: &str) -> Option<&'a str> {
    sub.try_get_one::<String>(name)
        .ok()
        .flatten()
        .map(String::as_str)
}
fn flag(sub: &ArgMatches, name: &str) -> bool {
    sub.try_get_one::<bool>(name)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
fn login(sub: &ArgMatches) -> Login {
    Login {
        ssh_key: sub
            .try_get_one::<std::path::PathBuf>("ssh-key")
            .ok()
            .flatten()
            .cloned(),
        ssh_agent: sub
            .try_get_one::<std::path::PathBuf>("ssh-agent")
            .ok()
            .flatten()
            .cloned(),
    }
}
fn owner(node: &EthValidator) -> Result<&str, String> {
    node.node
        .id
        .as_deref()
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .ok_or_else(|| "invalid validator inventory owner".into())
}
fn find(nodes: &[EthValidator], name: &str) -> Result<EthValidator, String> {
    nodes
        .iter()
        .find(|node| node.node.name == name)
        .cloned()
        .ok_or_else(|| "validator is not initialized in this network".into())
}
fn open(network: &str, sub: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        network,
        one(sub, "vault"),
        "erpc v --chain eth init --network <network> --vault <vault>",
    )?;
    let runner = node_common::op_runner()?;
    Ok((node_common::store(&runner, &vault, "eth", network)?, vault))
}
fn send(session: &Session, request: &Value) -> Result<Value, String> {
    let encoded = SecretString::from(request.to_string());
    send_secret(session, &encoded)
}
fn send_secret(session: &Session, encoded: &SecretString) -> Result<Value, String> {
    let output = session
        .run(
            &RemoteCommand::EthValidatorControl,
            Some(encoded.expose_secret().as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "validator returned an invalid public response".into())
}
fn connect(node: &EthValidator, sub: &ArgMatches) -> Result<(erpc_ssh::Target, Session), String> {
    let target = crate::eth_rpc::target(&node.node, &login(sub))?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    Ok((target, session))
}
fn print(value: &Value, json_out: bool) -> Outcome {
    if json_out {
        crate::print_json(value);
        Outcome::Done(String::new())
    } else {
        Outcome::Done(serde_json::to_string_pretty(value).unwrap_or_default())
    }
}

/// Read bounded private material without exposing it in errors or Debug.
fn input_file(path: &Path, private: bool) -> Result<SecretString, String> {
    use std::io::Read as _;
    #[cfg(not(unix))]
    let _ = private;
    let meta = std::fs::symlink_metadata(path).map_err(|_| "cannot read input file metadata")?;
    if !meta.is_file() || meta.len() > 16 * 1024 * 1024 {
        return Err("input must be a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if private && meta.permissions().mode() & 0o077 != 0 {
            return Err("custody input files must be private (chmod 600)".into());
        }
    }
    let mut text = zeroize::Zeroizing::new(String::new());
    let file = std::fs::File::open(path).map_err(|_| "cannot open private input")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let opened = file
            .metadata()
            .map_err(|_| "cannot inspect private input")?;
        if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
            return Err("private input changed while opening it".into());
        }
    }
    file.take(16 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| "cannot read private input")?;
    if text.len() > 16 * 1024 * 1024 {
        return Err("input too large".into());
    }
    Ok(SecretString::from(text.as_str()))
}
fn path<'a>(sub: &'a ArgMatches, name: &str) -> Result<&'a Path, String> {
    sub.try_get_one::<std::path::PathBuf>(name)
        .ok()
        .flatten()
        .map(std::path::PathBuf::as_path)
        .ok_or_else(|| "required input file missing".into())
}

async fn pin(
    client: Client,
    wanted: Option<&str>,
    facts: &Facts,
    previous: Option<&str>,
) -> Result<(String, String, String), String> {
    let platform = facts.platform()?;
    let github = releases::Github::new().map_err(|e| e.to_string())?;
    // Deliberately no carried-list fallback for validator deployment or upgrade.
    let listing = github.releases(client).await.map_err(|e| e.to_string())?;
    let selected =
        releases::choose(client, &listing, wanted, platform).map_err(|e| e.to_string())?;
    validator::release(client, &selected.tag, previous)?;
    let commit = github
        .commit(client, &selected.tag)
        .await
        .map_err(|e| e.to_string())?;
    Ok((
        selected.tag.clone(),
        commit,
        selected
            .digest(platform)
            .ok_or("release has no checksum")?
            .to_owned(),
    ))
}

fn play(
    node: &EthValidator,
    network: validator::Network,
    phase: &str,
    session: &Session,
    target: &erpc_ssh::Target,
    say: &Say,
) -> Result<String, String> {
    let facts = crate::eth_rpc::facts(session)?;
    let refuse = facts.refusals();
    if !refuse.is_empty() {
        return Err(refuse.join("; "));
    }
    validator::release(Client::Reth, &node.node.reth_version, None)?;
    validator::release(Client::Lighthouse, &node.node.lighthouse_version, None)?;
    validator::address(&node.fee_recipient)?;
    let net = erpc_chain_eth::network::Network {
        name: network.name,
        client_name: network.name,
        chain_id: network.chain_id,
    };
    let extra = json!({"ev_network":network.name,"ev_owner":owner(node)?,"ev_fee_recipient":node.fee_recipient,"ev_phase":phase}).as_object().ok_or("invalid variables")?.clone();
    let vars = crate::eth_rpc::RunVars {
        node: &node.node,
        network: &net,
        facts: &facts,
        extra,
    };
    crate::eth_rpc::run_play(
        session,
        target,
        &vars,
        "validator/deploy.yml",
        "Repeat the same validator command to recover",
        say,
    )
}

async fn init(
    sub: &ArgMatches,
    network: validator::Network,
    store: &Store<OpCli>,
    vault: &str,
    say: &Say,
) -> Result<Value, String> {
    let name = one(sub, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let existing = store
        .eth_validators()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|v| v.node.name == name);
    let mut node = if let Some(node) = existing {
        if node.state != "prepared" {
            return Err(
                "init cannot reinitialize validator custody; use deploy or update-config".into(),
            );
        }
        if one(sub, "host").is_some_and(|host| host != node.node.address)
            || one(sub, "fee-recipient").is_some_and(|value| value != node.fee_recipient)
        {
            return Err(
                "init cannot change host ownership or fee recipient; use update-config or migrate"
                    .into(),
            );
        }
        node
    } else {
        let host = one(sub, "host").ok_or("new validator requires --host")?;
        let fee = validator::address(
            one(sub, "fee-recipient").ok_or("new validator requires --fee-recipient")?,
        )?;
        let port = sub.get_one::<u16>("port").copied().unwrap_or(22);
        let host_key = node_common::host_key(host, port, None, one(sub, "fingerprint"), say)?;
        EthValidator {
            node: EthRpc {
                name: name.to_owned(),
                address: host.to_owned(),
                ssh_user: one(sub, "user").unwrap_or("ubuntu").to_owned(),
                ssh_port: port,
                host_key: host_key.to_openssh(),
                rpc_type: "full".into(),
                ..EthRpc::default()
            },
            fee_recipient: fee,
            state: "prepared".into(),
            ..EthValidator::default()
        }
    };
    let (target, session) = connect(&node, sub)?;
    let facts = crate::eth_rpc::facts(&session)?;
    let refuse = facts.refusals();
    if !refuse.is_empty() {
        return Err(refuse.join("; "));
    }
    if node.node.id.is_none() {
        let (version, commit, digest) =
            pin(Client::Reth, one(sub, "reth-version"), &facts, None).await?;
        node.node.reth_version = version;
        node.node.reth_commit = commit;
        node.node.reth_sha256 = digest;
        let (version, commit, digest) = pin(
            Client::Lighthouse,
            one(sub, "lighthouse-version"),
            &facts,
            None,
        )
        .await?;
        node.node.lighthouse_version = version;
        node.node.lighthouse_commit = commit;
        node.node.lighthouse_sha256 = digest;
    }
    node_common::go_ahead(flag(sub, "yes"), "no validator changes made")
        .map_err(|e| e.to_string())?;
    if node.node.id.is_none() {
        node = store.add_eth_validator(&node).map_err(|e| e.to_string())?;
    }
    node_common::save_vault(network.name, vault)?;
    let run = play(&node, network, "init", &session, &target, say)?;
    node.node.last_run = run;
    node.node.last_result = "init ok".into();
    store
        .update_eth_validator(&node)
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"name":name,"network":network.name,"state":"prepared","keys_imported":false,"deposit_submitted":false}),
    )
}

fn import(
    node: &mut EthValidator,
    sub: &ArgMatches,
    network: validator::Network,
    session: &Session,
    store: &Store<OpCli>,
) -> Result<Value, String> {
    let key = input_file(path(sub, "keystore")?, true)?;
    let password = input_file(path(sub, "password-file")?, true)?;
    let history = input_file(path(sub, "slashing-history")?, true)?;
    let key_doc: Value =
        serde_json::from_str(key.expose_secret()).map_err(|_| "invalid encrypted keystore JSON")?;
    let pubkey = validator::keystore(&key_doc)?;
    let history_doc: Value =
        serde_json::from_str(history.expose_secret()).map_err(|_| "invalid history JSON")?;
    validator::history(&history_doc, network, &pubkey, true)?;
    if store
        .eth_validators()
        .map_err(|e| e.to_string())?
        .iter()
        .any(|v| v.node.id != node.node.id && v.pubkey == pubkey)
    {
        return Err("this key already belongs to a managed validator; use migrate".into());
    }
    node_common::go_ahead(flag(sub, "yes"), "no key imported").map_err(|e| e.to_string())?;
    // JSON encoding only; password is never placed in argv, env, inventory or a run bundle.
    let pass = SecretString::from(
        serde_json::to_string(password.expose_secret().trim_end_matches(['\r', '\n']))
            .map_err(|_| "cannot encode password")?,
    );
    let request = SecretString::from(format!(
        "{{\"owner\":\"{}\",\"action\":\"import\",\"new_key\":true,\"material\":{{\"keystore\":{},\"password\":{},\"history\":{}}}}}",
        owner(node)?,
        key.expose_secret(),
        pass.expose_secret(),
        history.expose_secret()
    ));
    transact_import(
        node,
        &pubkey,
        |candidate| {
            store
                .update_eth_validator(candidate)
                .map_err(|e| e.to_string())
        },
        || send_secret(session, &request),
    )
}

/// Reserve only an empty owner. Existing custody is never rewritten before the
/// remote host accepts the exact retry; a rejected import leaves it unchanged.
fn transact_import(
    node: &mut EthValidator,
    pubkey: &str,
    mut persist: impl FnMut(&EthValidator) -> Result<EthValidator, String>,
    remote: impl FnOnce() -> Result<Value, String>,
) -> Result<Value, String> {
    if (!node.pubkey.is_empty() && node.pubkey != pubkey)
        || !matches!(node.state.as_str(), "prepared" | "importing" | "imported")
    {
        return Err("this validator owner cannot import a different or fenced key".into());
    }
    if node.pubkey.is_empty() {
        let mut reserved = node.clone();
        pubkey.clone_into(&mut reserved.pubkey);
        reserved.state = "importing".into();
        *node = persist(&reserved)?;
    }
    let result = remote()?;
    let mut complete = node.clone();
    complete.state = "imported".into();
    *node = persist(&complete)?;
    Ok(result)
}

fn migrate(
    node: &mut EthValidator,
    sub: &ArgMatches,
    session: &Session,
    store: &Store<OpCli>,
) -> Result<Value, String> {
    let destination = one(sub, "to").ok_or("migrate requires --to")?;
    let mut to = find(
        &store.eth_validators().map_err(|e| e.to_string())?,
        destination,
    )?;
    if owner(node)? == owner(&to)? {
        return Err("migration needs a different owned host".into());
    }
    let (_, target_session) = connect(&to, sub)?;
    let target_state = send(
        &target_session,
        &json!({"owner":owner(&to)?,"action":"status"}),
    )?;
    if !["prepared", "importing", "imported"]
        .contains(&target_state["state"].as_str().unwrap_or_default())
    {
        return Err("destination cannot accept a migration".into());
    }
    if target_state["pubkey"]
        .as_str()
        .is_some_and(|key| !key.is_empty() && key != node.pubkey)
    {
        return Err("destination already owns another validator key".into());
    }
    node_common::go_ahead(flag(sub, "yes"), "no signer moved").map_err(|e| e.to_string())?;
    let request = SecretString::from(
        json!({"owner":owner(node)?,"action":"fence-export","destination":owner(&to)?}).to_string(),
    );
    let exported = session
        .run(
            &RemoteCommand::EthValidatorControl,
            Some(request.expose_secret().as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    let bytes = zeroize::Zeroizing::new(exported.stdout);
    let material = std::str::from_utf8(&bytes).map_err(|_| "invalid migration response")?;
    // Source is already persistently fenced and shutdown was confirmed before any target import.
    node.state = "fenced".into();
    *node = store
        .update_eth_validator(node)
        .map_err(|e| e.to_string())?;
    let request = SecretString::from(format!(
        "{{\"owner\":\"{}\",\"action\":\"import\",\"source_owner\":\"{}\",\"material\":{}}}",
        owner(&to)?,
        owner(node)?,
        material
    ));
    let result = transact_import(
        &mut to,
        &node.pubkey,
        |candidate| {
            store
                .update_eth_validator(candidate)
                .map_err(|e| e.to_string())
        },
        || send_secret(&target_session, &request),
    )?;

    Ok(
        json!({"source_fenced":true,"destination":destination,"import":result,"signing_started":false}),
    )
}

fn deposit_review(
    sub: &ArgMatches,
    network: validator::Network,
    node: &EthValidator,
    session: &Session,
) -> Result<Value, String> {
    let raw = input_file(path(sub, "deposit-data")?, false)?;
    let data: Value =
        serde_json::from_str(raw.expose_secret()).map_err(|_| "invalid deposit JSON")?;
    let review = erpc_chain_eth::deposit::review(
        &data,
        network,
        &node.pubkey,
        one(sub, "withdrawal-address").ok_or("missing withdrawal address")?,
    )?;
    let status = send(session, &json!({"owner":owner(node)?,"action":"status"}))?;
    if status["ready"] != true
        || status["activation"] != "not_in_beacon_state"
        || status["pubkey"] != review.pubkey
    {
        return Err("deposit review requires a synced matching key absent from beacon state; pending deposits outside state must be checked in the official launchpad".into());
    }
    Ok(
        json!({"network":network.name,"pubkey":review.pubkey,"withdrawal_address":review.withdrawal_address,"amount_gwei":review.amount_gwei,"chain_id":network.chain_id,"deposit_data_root":data[0]["deposit_data_root"],"ssz_and_bls_valid":true,"transaction_submitted":false,"next":"Review pending deposit transactions and submit through the official network staking launchpad; do not repeat a pending deposit"}),
    )
}

async fn update_pins(
    node: &mut EthValidator,
    sub: &ArgMatches,
    facts: &Facts,
) -> Result<(), String> {
    let (version, commit, digest) = pin(
        Client::Reth,
        one(sub, "reth-version"),
        facts,
        Some(&node.node.reth_version),
    )
    .await?;
    node.node.reth_version = version;
    node.node.reth_commit = commit;
    node.node.reth_sha256 = digest;
    let (version, commit, digest) = pin(
        Client::Lighthouse,
        one(sub, "lighthouse-version"),
        facts,
        Some(&node.node.lighthouse_version),
    )
    .await?;
    node.node.lighthouse_version = version;
    node.node.lighthouse_commit = commit;
    node.node.lighthouse_sha256 = digest;
    Ok(())
}

async fn operation(
    verb: &str,
    sub: &ArgMatches,
    network: validator::Network,
    say: &Say,
) -> Result<Value, String> {
    let (store, vault) = open(network.name, sub)?;
    if verb == "init" {
        return init(sub, network, &store, &vault, say).await;
    }
    let nodes = store.eth_validators().map_err(|e| e.to_string())?;
    if verb == "list" {
        return Ok(json!(nodes.iter().map(|v|json!({"name":v.node.name,"state":v.state,"pubkey":v.pubkey,"network":network.name})).collect::<Vec<_>>()));
    }
    let mut node = find(
        &nodes,
        one(sub, "name").ok_or("validator command requires --name")?,
    )?;
    if verb == "plan" {
        return Ok(
            json!({"name":node.node.name,"network":network.name,"reth":node.node.reth_version,"lighthouse":node.node.lighthouse_version,"fee_recipient":node.fee_recipient,"owned_stack":true,"signing_requires_explicit_start":true,"deploy_submits_deposit":false,"destroy_preserves_custody":true,"live_acceptance":"deferred"}),
        );
    }
    let (target, session) = connect(&node, sub)?;
    match verb {
        "keys-import" => import(&mut node, sub, network, &session, &store),
        "migrate" => migrate(&mut node, sub, &session, &store),
        "deposit-review" => deposit_review(sub, network, &node, &session),
        "status" => send(&session, &json!({"owner":owner(&node)?,"action":"status"})),
        "logs" => {
            let log_output = Say { quiet: false };
            session
                .stream(
                    &RemoteCommand::EthValidatorLogs {
                        lines: sub.get_one::<u32>("lines").copied().unwrap_or(100),
                        follow: flag(sub, "follow"),
                    },
                    &mut |_, line| log_output.line(line),
                )
                .map_err(|e| e.to_string())?;
            Ok(json!({"logs":"complete"}))
        }
        "start" | "stop" | "restart" | "destroy" => {
            if ["start", "restart"].contains(&verb) {
                let owners = store.eth_validators().map_err(|e| e.to_string())?;
                if node.pubkey.is_empty()
                    || node.state != "imported"
                    || owners
                        .iter()
                        .filter(|v| v.pubkey == node.pubkey && v.state != "fenced")
                        .count()
                        != 1
                {
                    return Err("signing requires one completed, unique managed owner; recover the import or migration first".into());
                }
            }
            node_common::go_ahead(flag(sub, "yes"), "no validator service changed")
                .map_err(|e| e.to_string())?;
            let result = send(&session, &json!({"owner":owner(&node)?,"action":verb}))?;
            if verb == "destroy" {
                node.state = "fenced".into();
                store
                    .update_eth_validator(&node)
                    .map_err(|e| e.to_string())?;
            }
            Ok(result)
        }
        "deploy" | "update" | "update-config" => {
            let state = send(&session, &json!({"owner":owner(&node)?,"action":"status"}))?;
            if state["state"] == "maintenance" && verb != "deploy" {
                return Err("resume deploy with the stored desired pair before requesting another configuration or release".into());
            }
            if verb == "update" {
                update_pins(&mut node, sub, &crate::eth_rpc::facts(&session)?).await?;
            }
            if let Some(fee) = one(sub, "fee-recipient") {
                node.fee_recipient = validator::address(fee)?;
            }
            node_common::go_ahead(flag(sub, "yes"), "no configuration changed")
                .map_err(|e| e.to_string())?;
            node = store
                .update_eth_validator(&node)
                .map_err(|e| e.to_string())?;
            let run = play(
                &node,
                network,
                if verb == "deploy" { "deploy" } else { "update" },
                &session,
                &target,
                say,
            )?;
            node.node.last_run = run;
            node.node.last_result = format!("{verb} ok; signer stopped");
            store
                .update_eth_validator(&node)
                .map_err(|e| e.to_string())?;
            Ok(
                json!({"name":node.node.name,"supporting_clients":"started","signer":"stopped","deposit_submitted":false}),
            )
        }
        _ => Err("unsupported Ethereum validator operation".into()),
    }
}

pub(crate) async fn run(verb: &str, sub: &ArgMatches, network: &str, json_out: bool) -> Outcome {
    let Some(network) = validator::network(network) else {
        return Outcome::Usage("unsupported validator network".into());
    };
    let say = Say { quiet: json_out };
    match operation(verb, sub, network, &say).await {
        Ok(value) => print(&value, json_out),
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn custody_reads_reject_shared_and_symlinked_files() {
        use secrecy::ExposeSecret as _;
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let dir = tempfile::tempdir().expect("temporary directory");
        let file = dir.path().join("input");
        std::fs::write(&file, "fixture-only").expect("fixture");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
            .expect("permissions");
        assert!(super::input_file(&file, true).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
            .expect("permissions");
        assert_eq!(
            super::input_file(&file, true)
                .expect("private")
                .expose_secret(),
            "fixture-only"
        );
        let link = dir.path().join("link");
        symlink(&file, &link).expect("symlink");
        assert!(super::input_file(&link, true).is_err());
    }
    #[test]
    fn rejected_import_preserves_existing_owner_without_any_store_write() {
        use super::transact_import;
        use erpc_chain::inventory::eth_validator::EthValidator;
        use std::cell::Cell;
        for state in ["importing", "imported"] {
            let original = EthValidator {
                pubkey: "key-a".into(),
                state: state.into(),
                ..EthValidator::default()
            };
            let mut node = original.clone();
            let writes = Cell::new(0);
            let remote = Cell::new(false);
            assert!(
                transact_import(
                    &mut node,
                    "key-b",
                    |v| {
                        writes.set(writes.get() + 1);
                        Ok(v.clone())
                    },
                    || {
                        remote.set(true);
                        Ok(serde_json::json!({}))
                    }
                )
                .is_err()
            );
            assert_eq!(writes.get(), 0);
            assert!(!remote.get());
            assert_eq!(node, original);
            // A remote rejection of the SAME key is also not permission to downgrade its ownership state.
            assert!(
                transact_import(
                    &mut node,
                    "key-a",
                    |v| {
                        writes.set(writes.get() + 1);
                        Ok(v.clone())
                    },
                    || Err("remote rejected material".into())
                )
                .is_err()
            );
            assert_eq!(writes.get(), 0);
            assert_eq!(node, original);
        }
    }

    #[test]
    fn failed_new_import_keeps_reservation_and_failed_completion_does_not_clear_it() {
        use super::transact_import;
        use erpc_chain::inventory::eth_validator::EthValidator;
        let mut node = EthValidator {
            state: "prepared".into(),
            ..EthValidator::default()
        };
        let writes = std::cell::Cell::new(0);
        assert!(
            transact_import(
                &mut node,
                "key-a",
                |v| {
                    writes.set(writes.get() + 1);
                    Ok(v.clone())
                },
                || Err("lost SSH reply".into())
            )
            .is_err()
        );
        assert_eq!(writes.get(), 1);
        assert_eq!(node.pubkey, "key-a");
        assert_eq!(node.state, "importing");
        let reserved = node.clone();
        assert!(
            transact_import(
                &mut node,
                "key-a",
                |_| Err("store completion failed".into()),
                || Ok(serde_json::json!({}))
            )
            .is_err()
        );
        assert_eq!(node, reserved);
    }
}
