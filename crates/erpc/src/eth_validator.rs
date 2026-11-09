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
fn contract(
    node: &EthValidator,
    network: &str,
) -> Result<erpc_chain_eth::authority::Contract, String> {
    let host = &node.node;
    let value = erpc_chain_eth::authority::Contract {
        schema: 1,
        role: "validator".into(),
        owner: owner(node)?.into(),
        network: network.into(),
        kind: "validator".into(),
        host_binding: erpc_chain_eth::authority::host_binding(
            &host.address,
            &host.ssh_user,
            host.ssh_port,
            &host.host_key,
        ),
    };
    value.validate().map_err(str::to_owned)?;
    Ok(value)
}
fn envelope(
    node: &EthValidator,
    network: &str,
    request: &SecretString,
) -> Result<SecretString, String> {
    if request.expose_secret().len() > 16 * 1024 * 1024 {
        return Err("validator private request exceeds its bound".into());
    }
    let identity = serde_json::to_string(&contract(node, network)?)
        .map_err(|_| "cannot encode original validator identity")?;
    // Only the public contract is serialized as an ordinary String. The private
    // request remains SecretString; no password is parsed into a debug Value.
    Ok(SecretString::from(format!(
        "{{\"contract\":{identity},\"request\":{}}}",
        request.expose_secret()
    )))
}

fn send(
    session: &Session,
    node: &EthValidator,
    network: &str,
    request: &Value,
) -> Result<Value, String> {
    let encoded = envelope(node, network, &SecretString::from(request.to_string()))?;
    send_secret(session, &encoded)
}
fn send_secret(session: &Session, encoded: &SecretString) -> Result<Value, String> {
    let output = session
        .run(
            &RemoteCommand::EthValidatorControl,
            Some(encoded.expose_secret().as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    if output.stdout.len() > 1024 * 1024 {
        return Err("validator public response exceeds its bound".into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "validator returned an invalid public response".into())
}
fn connect(node: &EthValidator, sub: &ArgMatches) -> Result<(erpc_ssh::Target, Session), String> {
    let target = crate::eth_rpc::target(&node.node, &login(sub))?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    Ok((target, session))
}
fn print(value: &Value, json_out: bool, problems: bool) -> Outcome {
    let message = if json_out {
        crate::print_json(value);
        String::new()
    } else {
        serde_json::to_string_pretty(value).unwrap_or_default()
    };
    if problems {
        Outcome::Problems(message)
    } else {
        Outcome::Done(message)
    }
}

fn emit_journal(
    json_out: bool,
    line: &str,
    mut stdout: impl FnMut(&str),
    mut stderr: impl FnMut(&str),
) {
    if json_out {
        stdout(&json!({"journal":line}).to_string());
    } else {
        stderr(line);
    }
}

fn journal_line(json_out: bool, line: &str, say: &Say) {
    emit_journal(json_out, line, crate::print_line, |value| say.line(value));
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

fn checked_facts(session: &Session) -> Result<Facts, String> {
    let facts = crate::eth_rpc::facts(session)?;
    let failures = facts.refusals();
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }
    Ok(facts)
}

fn play(
    node: &EthValidator,
    network: validator::Network,
    phase: &str,
    session: &Session,
    target: &erpc_ssh::Target,
    say: &Say,
    renew_transport: bool,
) -> Result<String, String> {
    let facts = checked_facts(session)?;
    validator::release(Client::Reth, &node.node.reth_version, None)?;
    validator::release(Client::Lighthouse, &node.node.lighthouse_version, None)?;
    validator::address(&node.fee_recipient)?;
    let net = erpc_chain_eth::network::Network {
        name: network.name,
        client_name: network.name,
        chain_id: network.chain_id,
    };
    let mut vars = play_vars(node, &net, &facts, phase)?;
    if phase != "init" {
        let source = deployment_source(node, renew_transport);
        let observed = send(
            session,
            node,
            network.name,
            &json!({"owner":owner(node)?,"action":"deployment"}),
        )?;
        let intent = crate::eth_authority::deployment_intent(&observed, &source, phase)?;
        let request = json!({"owner":owner(node)?,"action":"reserve-deploy","intent":intent,
            "target":source,"operation":phase});
        let authorized = send(session, node, network.name, &request)?;
        if authorized["authorized"] != true || authorized["intent"] != intent {
            return Err("original validator deployment was not authorized".into());
        }
        deployment_variables(&mut vars, &request)?;
    }
    crate::eth_rpc::run_play(
        session,
        target,
        &vars,
        "validator/deploy.yml",
        "Repeat the same validator command to recover",
        say,
    )
}

fn deployment_variables(
    vars: &mut crate::eth_rpc::RunVars<'_>,
    request: &Value,
) -> Result<(), String> {
    let intent = request["intent"]
        .as_str()
        .ok_or("missing original validator deployment intent")?;
    if intent.len() != 32
        || !intent
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || request["action"] != "reserve-deploy"
        || request["owner"] != vars.extra["ev_owner"]
    {
        return Err("validator deployment variables do not match original authority".into());
    }
    let envelope = vars
        .extra
        .get_mut("ev_request")
        .ok_or("missing original validator contract")?;
    envelope["request"] = request.clone();
    vars.extra.insert("ev_intent".into(), json!(intent));
    Ok(())
}

fn deployment_source(node: &EthValidator, renew_transport: bool) -> Value {
    json!({"pair":format!("reth-{}--lighthouse-{}",node.node.reth_version,node.node.lighthouse_version),
        "reth_commit":node.node.reth_commit,"lighthouse_commit":node.node.lighthouse_commit,
        "reth_archive":node.node.reth_sha256,"lighthouse_archive":node.node.lighthouse_sha256,
        "fee_recipient":node.fee_recipient,"renew_transport":renew_transport})
}

fn play_vars<'a>(
    node: &'a EthValidator,
    network: &'a erpc_chain_eth::network::Network,
    facts: &'a Facts,
    phase: &str,
) -> Result<crate::eth_rpc::RunVars<'a>, String> {
    let extra=json!({"ev_network":network.name,"ev_owner":owner(node)?,"ev_fee_recipient":node.fee_recipient,
        "ev_phase":phase,"ev_loader":erpc_chain_eth::authority::carried_loader(),
        "ev_request":{"contract":contract(node,network.name)?,"request":{"owner":owner(node)?,"action":"prepare"}}})
        .as_object().ok_or("invalid validator variables")?.clone();
    Ok(crate::eth_rpc::RunVars {
        role: erpc_core::chain::Role::Validator,
        node: &node.node,
        network,
        facts,
        extra,
    })
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
    let migrating = flag(sub, "migrate-authority");
    if migrating && existing.is_none() {
        return Err(
            "legacy authority migration requires the original existing validator inventory".into(),
        );
    }
    let mut node = if let Some(node) = existing {
        if node.state != "prepared" && !migrating {
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
    let facts = checked_facts(&session)?;
    if migrating {
        return migrate_authority(
            &mut node,
            sub,
            network,
            (&session, &target),
            &facts,
            store,
            say,
        )
        .await;
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
    let run = play(&node, network, "init", &session, &target, say, false)?;
    node.node.last_run = run;
    node.node.last_result = "init ok".into();
    store
        .update_eth_validator(&node)
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"name":name,"network":network.name,"state":"prepared","keys_imported":false,"deposit_submitted":false}),
    )
}

async fn migrate_authority(
    node: &mut EthValidator,
    sub: &ArgMatches,
    network: validator::Network,
    connection: (&Session, &erpc_ssh::Target),
    facts: &Facts,
    store: &Store<OpCli>,
    say: &Say,
) -> Result<Value, String> {
    let original = contract(node, network.name)?;
    let proof = crate::eth_authority_evidence::validator(
        &original,
        &node.pubkey,
        path(sub, "original-passwd")?,
        path(sub, "original-group")?,
        path(sub, "original-machine-id")?,
        path(sub, "original-client-record")?,
    )?;
    update_pins(node, sub, facts).await?;
    for (client, name, tag, commit) in [
        (
            Client::Reth,
            "reth",
            &node.node.reth_version,
            &node.node.reth_commit,
        ),
        (
            Client::Lighthouse,
            "lighthouse",
            &node.node.lighthouse_version,
            &node.node.lighthouse_commit,
        ),
    ] {
        let previous = proof["opened_sources"][name]["version"]
            .as_str()
            .ok_or("missing highest original client version")?;
        validator::release(client, tag, Some(previous))?;
        if tag == previous
            && proof["opened_sources"][name]["commit"].as_str() != Some(commit.as_str())
        {
            return Err(
                "qualified client differs at the highest original data-opening version".into(),
            );
        }
    }
    node_common::go_ahead(flag(sub, "yes"), "no legacy authority converted")
        .map_err(|e| e.to_string())?;
    let net = erpc_chain_eth::network::Network {
        name: network.name,
        client_name: network.name,
        chain_id: network.chain_id,
    };
    let mut vars = play_vars(node, &net, facts, "migration")?;
    vars.extra.insert("ev_request".into(),json!({"contract":original,"request":{"owner":owner(node)?,"action":"migrate-authority","proof":proof}}));
    let run = crate::eth_rpc::run_play(
        connection.0,
        connection.1,
        &vars,
        "validator/migrate.yml",
        "Preserve the original backup evidence and repeat this explicit migration; no signer is started",
        say,
    )?;
    let observed = send(
        connection.0,
        node,
        network.name,
        &json!({"owner":owner(node)?,"action":"deployment"}),
    )?;
    if observed["migration"]["records"] != proof["records"] {
        return Err("original validator migration has not completed".into());
    }
    node.fee_recipient = validator::address(
        observed["migration"]["fee_recipient"]
            .as_str()
            .ok_or("original fee recipient unavailable")?,
    )?;
    node.node.last_run = run;
    node.node.last_result = "original authority converted; signer stopped".into();
    *node = store
        .update_eth_validator(node)
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"migrated":true,"name":node.node.name,"network":network.name,"signing_started":false,
        "native_history_preserved":true,"next":"deploy the qualified supporting clients, then review readiness before explicit start"}),
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
    // Public scope/readiness proof precedes any private bytes sent to the host.
    // A failed cross-network initialization must not receive the signer secret.
    let authority = send(
        session,
        node,
        network.name,
        &json!({"owner":owner(node)?,"action":"key-authority","pubkey":pubkey,"new_key":true}),
    )?;
    if authority["authorized"] != true || authority["pubkey"] != pubkey {
        return Err(
            "original validator host did not authorize this exact public key import".into(),
        );
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
    let request = envelope(node, network.name, &request)?;
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
    network: &str,
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
        &to,
        network,
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
    let authority = send(
        &target_session,
        &to,
        network,
        &json!({"owner":owner(&to)?,"action":"key-authority","pubkey":node.pubkey,"source_owner":owner(node)?}),
    )?;
    if authority["authorized"] != true || authority["pubkey"] != node.pubkey {
        return Err(
            "original destination did not authorize this exact managed signer transfer".into(),
        );
    }
    node_common::go_ahead(flag(sub, "yes"), "no signer moved").map_err(|e| e.to_string())?;
    let request = SecretString::from(
        json!({"owner":owner(node)?,"action":"fence-export","destination":owner(&to)?}).to_string(),
    );
    let request = envelope(node, network, &request)?;
    let exported = session
        .run(
            &RemoteCommand::EthValidatorControl,
            Some(request.expose_secret().as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    let bytes = zeroize::Zeroizing::new(exported.stdout);
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("private validator migration response exceeds its bound".into());
    }
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
    let request = envelope(&to, network, &request)?;
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

fn write_backup(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(
        |_| "backup output must be a new file in an existing operator-controlled directory",
    )?;
    file.write_all(bytes).and_then(|()|file.sync_all()).map_err(|_|"encrypted backup write is incomplete; preserve it and retry with a new output name")?;
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent).and_then(|file|file.sync_all()).map_err(|_|"encrypted backup directory persistence failed; preserve the output and verify storage")?;
    }
    Ok(())
}

fn backup(
    node: &EthValidator,
    network: &str,
    sub: &ArgMatches,
    session: &Session,
) -> Result<Value, String> {
    node_common::go_ahead(flag(sub, "yes"), "no encrypted backup written")
        .map_err(|e| e.to_string())?;
    let request = envelope(
        node,
        network,
        &SecretString::from(json!({"owner":owner(node)?,"action":"custody-backup"}).to_string()),
    )?;
    let output = session
        .run(
            &RemoteCommand::EthValidatorControl,
            Some(request.expose_secret().as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    let bytes = zeroize::Zeroizing::new(output.stdout);
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err("original encrypted backup exceeds its bound".into());
    }
    let metadata: Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid original encrypted backup response")?;
    if metadata.as_object().is_none_or(|v| v.len() != 4)
        || metadata["schema"] != 1
        || metadata["contract"] != json!(contract(node, network)?)
        || metadata["pubkey"] != node.pubkey
        || metadata["ciphertext"].as_str().is_none_or(|value| {
            value.is_empty()
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        })
    {
        return Err("encrypted backup does not match the original managed signer".into());
    }
    write_backup(path(sub, "output")?, &bytes)?;
    Ok(
        json!({"encrypted_backup_saved":true,"plaintext_exported":false,"slashing_history_included":false,
        "recovery":"Requires this same original host authority and its existing systemd host encryption key; no signing-history reset"}),
    )
}

fn restore_backup(
    node: &EthValidator,
    network: &str,
    sub: &ArgMatches,
    session: &Session,
) -> Result<Value, String> {
    let raw = input_file(path(sub, "backup")?, true)?;
    if raw.expose_secret().len() > 1024 * 1024 {
        return Err("encrypted backup exceeds its bound".into());
    }
    node_common::go_ahead(flag(sub, "yes"), "no original custody restored")
        .map_err(|e| e.to_string())?;
    let request = SecretString::from(format!(
        "{{\"owner\":\"{}\",\"action\":\"custody-restore\",\"backup\":{}}}",
        owner(node)?,
        raw.expose_secret()
    ));
    send_secret(session, &envelope(node, network, &request)?)
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
    let status = send(
        session,
        node,
        network.name,
        &json!({"owner":owner(node)?,"action":"status"}),
    )?;
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

fn service(
    verb: &str,
    node: &mut EthValidator,
    sub: &ArgMatches,
    network: validator::Network,
    session: &Session,
    store: &Store<OpCli>,
) -> Result<Value, String> {
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
    let result = send(
        session,
        node,
        network.name,
        &json!({"owner":owner(node)?,"action":verb}),
    )?;
    if verb == "destroy" {
        node.state = "fenced".into();
        store
            .update_eth_validator(node)
            .map_err(|e| e.to_string())?;
    }
    Ok(result)
}

fn logs(session: &Session, sub: &ArgMatches, json_out: bool) -> Result<Value, String> {
    let log_output = Say { quiet: false };
    session
        .stream(
            &RemoteCommand::EthValidatorLogs {
                lines: sub.get_one::<u32>("lines").copied().unwrap_or(100),
                follow: flag(sub, "follow"),
            },
            &mut |_, line| journal_line(json_out, line, &log_output),
        )
        .map_err(|e| e.to_string())?;
    Ok(json!({"logs":"complete"}))
}

fn recover(
    node: &EthValidator,
    network: &str,
    sub: &ArgMatches,
    session: &Session,
) -> Result<Option<Value>, String> {
    let Some(intent) = one(sub, "recover-cutover") else {
        return Ok(None);
    };
    if intent.len() != 32
        || !intent
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(
            "recovery requires the original 32-character lowercase hexadecimal intent from plan"
                .into(),
        );
    }
    node_common::go_ahead(flag(sub, "yes"), "no original deployment recovered")
        .map_err(|e| e.to_string())?;
    send(
        session,
        node,
        network,
        &json!({"owner":owner(node)?,"action":"recover","intent":intent}),
    )
    .map(Some)
}

fn deployment_retry(
    node: &EthValidator,
    sub: &ArgMatches,
    verb: &str,
    observed: &Value,
) -> Result<bool, String> {
    let pending = &observed["pending"];
    if pending.is_null() {
        return Ok(false);
    }
    if observed["pending_current"] != true
        || pending["action"] != verb
        || pending["target"] != deployment_source(node, flag(sub, "renew-transport"))
        || one(sub, "fee-recipient").is_some_and(|value| {
            validator::address(value).ok().as_deref() != Some(node.fee_recipient.as_str())
        })
        || one(sub, "reth-version").is_some_and(|value| value != node.node.reth_version)
        || one(sub, "lighthouse-version").is_some_and(|value| value != node.node.lighthouse_version)
    {
        return Err("resume the exact original validator operation and configuration, or explicitly recover its recorded intent first".into());
    }
    Ok(true)
}

async fn operation(
    verb: &str,
    sub: &ArgMatches,
    network: validator::Network,
    say: &Say,
    json_out: bool,
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
    let (target, session) = connect(&node, sub)?;
    if verb == "plan" {
        let observed = send(
            &session,
            &node,
            network.name,
            &json!({"owner":owner(&node)?,"action":"deployment"}),
        )?;
        return Ok(
            json!({"name":node.node.name,"network":network.name,"desired":deployment_source(&node,false),
            "observed":observed,"signing_requires_explicit_start":true,"deploy_submits_deposit":false,
            "destroy_preserves_custody":true,"read_only":true}),
        );
    }
    match verb {
        "keys-import" => import(&mut node, sub, network, &session, &store),
        "keys-backup" => backup(&node, network.name, sub, &session),
        "keys-restore" => restore_backup(&node, network.name, sub, &session),
        "migrate" => migrate(&mut node, network.name, sub, &session, &store),
        "deposit-review" => deposit_review(sub, network, &node, &session),
        "status" => send(
            &session,
            &node,
            network.name,
            &json!({"owner":owner(&node)?,"action":"status"}),
        ),
        "logs" => {
            let scope = send(
                &session,
                &node,
                network.name,
                &json!({"owner":owner(&node)?,"action":"log-authority"}),
            )?;
            if scope["original_journal_authorized"] != true {
                return Err("original validator journal scope was not verified".into());
            }
            logs(&session, sub, json_out)
        }
        "start" | "stop" | "restart" | "destroy" => {
            service(verb, &mut node, sub, network, &session, &store)
        }
        "deploy" | "update" | "update-config" => {
            if let Some(result) = recover(&node, network.name, sub, &session)? {
                return Ok(result);
            }
            let state = send(
                &session,
                &node,
                network.name,
                &json!({"owner":owner(&node)?,"action":"deployment"}),
            )?;
            let retry = deployment_retry(&node, sub, verb, &state)?;
            if verb == "update" && !retry {
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
                verb,
                &session,
                &target,
                say,
                flag(sub, "renew-transport"),
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

fn observation_problem(verb: &str, value: &Value) -> bool {
    value["pending"] == true
        || (matches!(verb, "status" | "start" | "restart") && value["ready"] != true)
}

pub(crate) async fn run(verb: &str, sub: &ArgMatches, network: &str, json_out: bool) -> Outcome {
    let Some(network) = validator::network(network) else {
        return Outcome::Usage("unsupported validator network".into());
    };
    let say = Say { quiet: json_out };
    match operation(verb, sub, network, &say, json_out).await {
        Ok(value) => {
            let problems = observation_problem(verb, &value);
            print(&value, json_out, problems)
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn actual_validator_play_variables_keep_mainnet_and_hoodi_out_of_rpc_authority() {
        use super::{EthRpc, EthValidator, Facts};
        let node = EthValidator {
            node: EthRpc {
                id: Some("inertvalidatorowner".into()),
                name: "fixture".into(),
                ssh_user: "ubuntu".into(),
                ssh_port: 22,
                rpc_type: "full".into(),
                reth_version: "v2.8.1".into(),
                reth_commit: "a".repeat(40),
                reth_sha256: "b".repeat(64),
                lighthouse_version: "v8.3.2".into(),
                lighthouse_commit: "c".repeat(40),
                lighthouse_sha256: "d".repeat(64),
                ..EthRpc::default()
            },
            fee_recipient: format!("0x{}", "1".repeat(40)),
            ..EthValidator::default()
        };
        let facts = Facts::parse(
            "os=ubuntu 24.04\nmachine=x86_64\nmem_kb=131000000\ncpus=32\nx86_64_v3=4\nroot_free_kb=400000000\ndata_free_kb=3800000000\ncontroller=203.0.113.7\nssh_port=22\nsudo=yes\n",
        );
        for name in ["mainnet", "hoodi"] {
            let profile = super::validator::network(name).unwrap();
            let net = erpc_chain_eth::network::Network {
                name: profile.name,
                client_name: profile.name,
                chain_id: profile.chain_id,
            };
            for phase in ["init", "deploy", "update", "update-config"] {
                let mut vars = super::play_vars(&node, &net, &facts, phase).unwrap();
                if phase != "init" {
                    let request = serde_json::json!({"owner":"inertvalidatorowner","action":"reserve-deploy","intent":"e".repeat(32),
                        "operation":phase,"target":super::deployment_source(&node,false)});
                    super::deployment_variables(&mut vars, &request).unwrap();
                }
                let encoded = vars
                    .inventory_json()
                    .expect("actual validator inventory builder");
                render_inventory_if_requested(&encoded);
                let inventory: serde_json::Value = serde_json::from_str(&encoded).unwrap();
                let host = &inventory["all"]["hosts"]["fixture"];
                assert_eq!(host["eth_chain_id"], profile.chain_id);
                assert_eq!(host["ev_network"], name);
                assert_eq!(host["ev_phase"], phase);
                assert_eq!(host["ev_owner"], "inertvalidatorowner");
                assert_eq!(host["ev_request"]["contract"]["role"], "validator");
                assert_eq!(host["ev_request"]["contract"]["network"], name);
                if phase != "init" {
                    assert_eq!(host["ev_intent"], "e".repeat(32));
                    assert_eq!(host["ev_request"]["request"]["operation"], phase);
                    assert_eq!(
                        host["ev_request"]["request"]["target"],
                        super::deployment_source(&node, false)
                    );
                }
                assert!(host.get("eth_authority_request").is_none());
                assert!(host.get("eth_authority_loader").is_none());
                assert!(host["eth_reth_url"].as_str().unwrap().contains("v2.8.1"));
                assert!(
                    host["eth_lighthouse_url"]
                        .as_str()
                        .unwrap()
                        .contains("v8.3.2")
                );
            }
        }
    }

    fn render_inventory_if_requested(inventory: &str) {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let Some(python) = std::env::var_os("ERPC_TEST_ANSIBLE_PYTHON") else {
            return;
        };
        let mut child = Command::new(python)
            .args(["-I", "-B"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../erpc-chain-eth/tests/authority_validator_play.py"
            ))
            .arg("--inventory")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("explicitly selected inert Ansible renderer");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(inventory.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn actual_update_retry_keeps_the_original_target_instead_of_fetching_another_release() {
        let node = super::EthValidator {
            node: super::EthRpc {
                reth_version: "v2.8.1".into(),
                lighthouse_version: "v8.3.2".into(),
                ..Default::default()
            },
            fee_recipient: format!("0x{}", "1".repeat(40)),
            ..Default::default()
        };
        let command = crate::tree::command(
            erpc_core::chain::Role::Validator,
            erpc_core::chain::Chain::Eth,
        );
        let args = command
            .clone()
            .try_get_matches_from(["validator", "update", "--renew-transport"])
            .unwrap();
        let sub = args.subcommand().unwrap().1;
        let mut observed = serde_json::json!({"pending_current":true,"pending":{"action":"update","target":super::deployment_source(&node,true)}});
        assert!(super::deployment_retry(&node, sub, "update", &observed).unwrap());
        observed["pending_current"] = serde_json::json!(false);
        assert!(super::deployment_retry(&node, sub, "update", &observed).is_err());
        observed["pending_current"] = serde_json::json!(true);
        let changed = command
            .try_get_matches_from([
                "validator",
                "update",
                "--renew-transport",
                "--reth-version",
                "v2.8.2",
            ])
            .unwrap();
        assert!(
            super::deployment_retry(&node, changed.subcommand().unwrap().1, "update", &observed)
                .is_err()
        );
        assert!(super::deployment_retry(&node, sub, "deploy", &observed).is_err());
    }

    #[test]
    fn json_journal_uses_stdout_one_record_per_line_and_pending_start_is_not_success() {
        for json in [false, true] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let input = "inert quote \" and CR\rLF\n marker";
            super::emit_journal(
                json,
                input,
                |value| stdout.push(value.to_owned()),
                |value| stderr.push(value.to_owned()),
            );
            if json {
                assert!(stderr.is_empty());
                assert_eq!(stdout.len(), 1);
                assert!(!stdout[0].contains(['\r', '\n']));
                let event: serde_json::Value = serde_json::from_str(&stdout[0]).unwrap();
                assert_eq!(event["journal"], input);
            } else {
                assert!(stdout.is_empty());
                assert_eq!(stderr, vec![input]);
            }
        }
        assert!(matches!(
            super::print(&serde_json::json!({"pending":true}), false, true),
            super::Outcome::Problems(_)
        ));
        for verb in ["status", "start", "restart"] {
            assert!(super::observation_problem(
                verb,
                &serde_json::json!({"started":true,"ready":false,"pending":false})
            ));
            assert!(!super::observation_problem(
                verb,
                &serde_json::json!({"ready":true,"pending":false})
            ));
        }
    }

    #[test]
    fn encrypted_backup_never_overwrites_an_existing_original_or_alias() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("encrypted.backup");
        super::write_backup(&path, b"inert encrypted capsule").unwrap();
        assert!(super::write_backup(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"inert encrypted capsule");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let alias = root.path().join("alias");
            std::os::unix::fs::symlink(&path, &alias).unwrap();
            assert!(super::write_backup(&alias, b"replacement").is_err());
        }
    }

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
