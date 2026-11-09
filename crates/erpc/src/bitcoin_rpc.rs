// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin RPC lifecycle over pinned SSH and scoped 1Password metadata.

use crate::{
    commands::Outcome,
    eth_rpc::Facts,
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, bitcoin::BitcoinRpc};
use erpc_chain_bitcoin::{
    download::{self, Authenticated},
    network::Network,
    release::{self, Platform, Version},
    storage::Storage,
};
use erpc_ops::bundle::Bundle;
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use serde_json::{Value, json};

fn one<'a>(args: &'a ArgMatches, name: &str) -> Option<&'a str> {
    args.try_get_one::<String>(name)
        .ok()
        .flatten()
        .map(String::as_str)
}
fn yes(args: &ArgMatches) -> bool {
    args.try_get_one::<bool>("yes")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
fn owner(node: &BitcoinRpc) -> Result<&str, String> {
    node.id
        .as_deref()
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .ok_or_else(|| "invalid Bitcoin inventory owner".into())
}
fn storage(node: &BitcoinRpc) -> Result<Storage, String> {
    let value = match node.storage.as_str() {
        "full" if node.prune_mib == 0 => Storage::Full,
        "pruned" => Storage::Pruned {
            target_mib: node.prune_mib,
        },
        _ => return Err("invalid stored Bitcoin retention contract".into()),
    };
    value.validate().map_err(str::to_owned)?;
    Ok(value)
}
fn target(node: &BitcoinRpc, args: &ArgMatches) -> Result<Target, String> {
    let key = args
        .try_get_one::<std::path::PathBuf>("ssh-key")
        .ok()
        .flatten()
        .ok_or("pass --ssh-key with the operator public key file")?;
    Ok(Target {
        host: node.address.clone(),
        port: node.ssh_port,
        user: node.ssh_user.clone(),
        host_key: HostKey::parse(&node.host_key).map_err(|e| e.to_string())?,
        identity: Identity::Agent {
            socket: node_common::agent_socket(
                args.try_get_one::<std::path::PathBuf>("ssh-agent")
                    .ok()
                    .flatten()
                    .map(std::path::PathBuf::as_path),
            )?,
            public_key: key.clone(),
        },
    })
}
fn host_check(facts: &Facts) -> Result<Platform, String> {
    let ubuntu = facts
        .os
        .strip_prefix("ubuntu ")
        .and_then(|v| v.split_once('.'))
        .and_then(|(major, minor)| Some((major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?)))
        .is_some_and(|v| v >= (24, 4));
    if !ubuntu || !facts.sudo || facts.mem_kb < 3_500_000 || facts.cpus < 2 {
        return Err(
            "Bitcoin hosts require Ubuntu 24.04+, passwordless sudo, 4 GB RAM and two CPU cores"
                .into(),
        );
    }
    Platform::parse(&facts.machine)
        .ok_or_else(|| "Bitcoin release platform must be Linux x86_64 or aarch64".into())
}
fn request(node: &BitcoinRpc, network: Network, action: &str) -> Result<Value, String> {
    use sha2::{Digest as _, Sha256};
    storage(node)?;
    let version = Version::parse(&node.version).map_err(|e| e.to_string())?;
    let platform = Platform::parse(&node.platform).ok_or("invalid stored platform")?;
    if node.commit.len() != 40
        || !node.commit.bytes().all(|v| v.is_ascii_hexdigit())
        || node.sha256.len() != 64
        || !node.sha256.bytes().all(|v| v.is_ascii_hexdigit())
    {
        return Err("invalid stored release pin".into());
    }
    let binding = serde_json::to_vec(&json!([
        "erpc-bitcoin-original-host-v1",
        node.address,
        node.ssh_user,
        node.ssh_port,
        node.host_key
    ]))
    .map_err(|_| "cannot encode original Bitcoin host binding")?;
    Ok(
        json!({"owner":owner(node)?,"network":network.name(),"storage":node.storage,"prune_mib":node.prune_mib,
        "action":action,"host_binding":format!("{:x}",Sha256::digest(binding)),
        "pin":{"version":version.as_str(),"commit":node.commit,"sha256":node.sha256,"platform":platform.target()}}),
    )
}
fn control(
    session: &Session,
    node: &BitcoinRpc,
    network: Network,
    action: &str,
) -> Result<Value, String> {
    control_request(session, &request(node, network, action)?)
}
fn control_request(session: &Session, request: &Value) -> Result<Value, String> {
    let body = erpc_ssh::bitcoin::input(
        erpc_chain_bitcoin::CONTROLLER,
        request.to_string().as_bytes(),
    )
    .map_err(str::to_owned)?;
    let output = session
        .run(
            &RemoteCommand::BitcoinControl {
                program: erpc_chain_bitcoin::CONTROLLER,
            },
            Some(&body),
        )
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid Bitcoin controller response".into())
}

fn migration_request(
    node: &BitcoinRpc,
    network: Network,
    path: &std::path::Path,
) -> Result<Value, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|_| "cannot open original Bitcoin public runtime record")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect original runtime record")?
        .is_file()
    {
        return Err("original runtime record must be a regular public JSON file".into());
    }
    let mut bytes = Vec::new();
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read original Bitcoin public runtime record")?;
    if bytes.len() > 65_536 {
        return Err("original runtime record exceeds its bound".into());
    }
    let original: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "original runtime record is not valid public JSON")?;
    let mut value = request(node, network, "migrate-original")?;
    let fields = [
        "schema",
        "contract",
        "machine_sha256",
        "layout",
        "account",
        "highest_source",
        "daemon_sha256",
        "client_sha256",
    ];
    if original.as_object().is_none_or(|map| {
        map.len() != fields.len() || fields.iter().any(|name| !map.contains_key(*name))
    }) || original["schema"] != "erpc-bitcoin-original-v1"
    {
        return Err("original runtime record does not use the closed public history schema".into());
    }
    value["original"] = original;
    Ok(value)
}

fn migration_action(
    verb: &str,
    args: &ArgMatches,
    node: &BitcoinRpc,
    network: Network,
    mut send: impl FnMut(&Value) -> Result<Value, String>,
) -> Result<Option<Value>, String> {
    if verb != "deploy" {
        return Ok(None);
    }
    let Some(path) = args
        .try_get_one::<std::path::PathBuf>("original-runtime-record")
        .ok()
        .flatten()
    else {
        return Ok(None);
    };
    let request = migration_request(node, network, path)?;
    node_common::go_ahead(yes(args), "no legacy Bitcoin authority migrated")
        .map_err(|e| e.to_string())?;
    send(&request).map(Some)
}

fn deployment_request(
    node: &BitcoinRpc,
    network: Network,
    before: &Value,
) -> Result<Value, String> {
    use sha2::Digest as _;
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "cannot create Bitcoin deployment intent")?;
    let mut value = request(node, network, "authorize")?;
    value["intent"] = json!(format!("{:032x}", u128::from_be_bytes(bytes)));
    value["controller_sha256"] = json!(format!(
        "{:x}",
        sha2::Sha256::digest(erpc_chain_bitcoin::CONTROLLER.as_bytes())
    ));
    let account = |field: &str| {
        before[field]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| "original Bitcoin numeric account is unavailable".to_owned())
    };
    if before["authority_valid"] != true {
        return Err("Bitcoin original authority is unproven; use explicit legacy migration".into());
    }
    value["unit"] = json!(erpc_chain_bitcoin::unit(
        account("service_uid")?,
        account("service_gid")?
    )?);
    value["generation"] = json!(
        before["generation"]
            .as_u64()
            .filter(|value| *value < i64::MAX as u64)
            .ok_or("missing original Bitcoin operation generation")?
    );
    Ok(value)
}
fn open(network: Network, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        network.name(),
        one(args, "vault"),
        "erpc r --chain bitcoin init --network <network> --vault <vault>",
    )?;
    Ok((
        node_common::store(
            &node_common::op_runner()?,
            &vault,
            "bitcoin",
            network.name(),
        )?,
        vault,
    ))
}
fn find(store: &Store<OpCli>, args: &ArgMatches) -> Result<BitcoinRpc, String> {
    let name = one(args, "name").ok_or("Bitcoin operation requires --name")?;
    store
        .bitcoin_rpcs()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name)
        .ok_or_else(|| "Bitcoin node is not initialized in this network".into())
}
fn pin_node(node: &mut BitcoinRpc, release: &Authenticated) {
    node.version = release.pin.version.to_string();
    node.commit.clone_from(&release.pin.commit);
    node.sha256.clone_from(&release.pin.sha256);
    node.platform = match release.pin.platform {
        Platform::X86_64 => "x86_64",
        Platform::Aarch64 => "aarch64",
    }
    .into();
}
fn add_templates(dir: &include_dir::Dir<'_>, bundle: &mut Bundle) -> Result<(), String> {
    for file in dir.files() {
        let path = file.path().to_str().ok_or("invalid carried path")?;
        let content = if path == "node/control.py" {
            erpc_chain_bitcoin::CONTROLLER.as_bytes()
        } else {
            file.contents()
        };
        bundle
            .add(path, content.to_vec())
            .map_err(|e| e.to_string())?;
    }
    for child in dir.dirs() {
        add_templates(child, bundle)?;
    }
    Ok(())
}
fn play(
    node: &BitcoinRpc,
    network: Network,
    phase: &str,
    release: &Authenticated,
    session: &Session,
    target: &Target,
    say: &Say,
) -> Result<String, String> {
    let retention = storage(node)?;
    let version = &release.pin.version;
    let platform = release.pin.platform;
    let request = if phase == "init" {
        request(node, network, "prepare")?
    } else {
        let before = control(session, node, network, "status")?;
        let request = deployment_request(node, network, &before)?;
        control_request(session, &request)?;
        request
    };
    let variables = json!({"ansible_connection":"local","btc_version":version.as_str(),"btc_platform":platform.target(),"btc_archive":platform.archive(version),"btc_archive_url":release::archive_url(version,platform),"btc_sha256":release.pin.sha256,"btc_request":request,"btc_config":retention.config(network).map_err(str::to_owned)?,"btc_phase":phase});
    let mut bundle = Bundle::new();
    add_templates(&erpc_chain_bitcoin::TEMPLATES, &mut bundle)?;
    bundle
        .add(
            "inventory.yml",
            json!({"all":{"hosts":{node.name.clone():variables}}})
                .to_string()
                .into_bytes(),
        )
        .map_err(|e| e.to_string())?;
    bundle
        .add("node/SHA256SUMS", release.manifest.as_bytes().to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add(
            "node/SHA256SUMS.asc",
            release.signatures.as_bytes().to_vec(),
        )
        .map_err(|e| e.to_string())?;
    let built = bundle.finish().map_err(|e| e.to_string())?;
    let run =
        erpc_ops::run::start(session, &built, "node/deploy.yml").map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Repeat init or deploy using the stored desired release",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "Bitcoin {phase} failed; data is preserved. Resume the same target with init/deploy (run {})",
            run.as_str()
        ));
    }
    Ok(run.as_str().into())
}

async fn authenticated(node: &BitcoinRpc, wanted: Option<&str>) -> Result<Authenticated, String> {
    let version = Version::parse(wanted.unwrap_or(&node.version)).map_err(|e| e.to_string())?;
    if !version.at_least(&Version::parse(&node.version).map_err(|e| e.to_string())?) {
        return Err("Bitcoin database downgrade is not a valid plan".into());
    }
    let platform = Platform::parse(&node.platform).ok_or("invalid Bitcoin platform")?;
    let fetched = download::fetch(version, platform).await?;
    if wanted.is_none() && (fetched.pin.commit != node.commit || fetched.pin.sha256 != node.sha256)
    {
        return Err(
            "upstream tag or manifest differs from the stored release; refusing silent re-pin"
                .into(),
        );
    }
    Ok(fetched)
}

async fn init(network: Network, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let (store, vault) = open(network, args)?;
    let name = one(args, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let existing = store
        .bitcoin_rpcs()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name);
    let mut node = if let Some(node) = existing {
        if one(args, "host").is_some_and(|host| host != node.address)
            || one(args, "type").is_some_and(|kind| kind != node.storage)
            || args
                .try_get_one::<u64>("prune-mib")
                .ok()
                .flatten()
                .is_some_and(|size| *size != node.prune_mib)
            || one(args, "version")
                .is_some_and(|v| Version::parse(v).map_or(true, |v| v.as_str() != node.version))
        {
            return Err("init cannot change an owned host, retention or release; use update for a new release".into());
        }
        node
    } else {
        let address = one(args, "host").ok_or("new node requires --host")?;
        let port = args.get_one::<u16>("port").copied().unwrap_or(22);
        let key = node_common::host_key(address, port, None, one(args, "fingerprint"), say)?;
        let kind = one(args, "type").unwrap_or("full");
        let prune = args.try_get_one::<u64>("prune-mib").ok().flatten().copied();
        if kind == "full" && prune.is_some() {
            return Err("full transaction indexing cannot be combined with pruning".into());
        }
        BitcoinRpc {
            name: name.into(),
            address: address.into(),
            ssh_user: one(args, "user").unwrap_or("ubuntu").into(),
            ssh_port: port,
            host_key: key.to_openssh(),
            version: one(args, "version").unwrap_or(release::RECOMMENDED).into(),
            storage: kind.into(),
            prune_mib: if kind == "pruned" {
                prune.unwrap_or(10_240)
            } else {
                0
            },
            ..BitcoinRpc::default()
        }
    };
    storage(&node)?;
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = crate::eth_rpc::facts(&session)?;
    let platform = host_check(&facts)?;
    let verified = if node.id.is_none() {
        download::fetch(
            Version::parse(&node.version).map_err(|e| e.to_string())?,
            platform,
        )
        .await?
    } else {
        authenticated(&node, None).await?
    };
    if verified.pin.platform != platform {
        return Err("host architecture differs from its stored release platform".into());
    }
    pin_node(&mut node, &verified);
    node_common::go_ahead(yes(args), "no Bitcoin host changed").map_err(|e| e.to_string())?;
    if node.id.is_none() {
        node = store.add_bitcoin_rpc(&node).map_err(|e| e.to_string())?;
    }
    node_common::save_vault(network.name(), &vault)?;
    node.last_run = play(&node, network, "init", &verified, &session, &target, say)?;
    node.last_result = "init ok".into();
    store.update_bitcoin_rpc(&node).map_err(|e| e.to_string())?;
    Ok(json!({"name":node.name,"network":network.name(),"state":"prepared","wallet_enabled":false}))
}

fn readiness(network: Network, node: &BitcoinRpc, mut response: Value) -> Result<Value, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "invalid controller clock")?
        .as_secs();
    let health = erpc_chain_bitcoin::status::evaluate(network, storage(node)?, &response, now);
    response["readiness"] = serde_json::to_value(health).map_err(|_| "cannot encode readiness")?;
    Ok(response)
}

async fn change(
    verb: &str,
    network: Network,
    args: &ArgMatches,
    node: &mut BitcoinRpc,
    store: &Store<OpCli>,
    say: &Say,
) -> Result<Value, String> {
    let target = target(node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if let Some(result) = migration_action(verb, args, node, network, |request| {
        control_request(&session, request)
    })? {
        // Migration terminates the command without entering deployment.
        return Ok(result);
    }
    // Emergency cancellation is authenticated by the carried original-host
    // controller. It must not depend on RPC health, deployment capacity or a
    // successful status/facts call before attempting owned shutdown.
    if matches!(verb, "stop" | "destroy") {
        node_common::go_ahead(yes(args), "no Bitcoin service changed")
            .map_err(|e| e.to_string())?;
        let response = control(&session, node, network, verb)?;
        node.last_result = format!("{verb} ok; data retained");
        *node = store.update_bitcoin_rpc(node).map_err(|e| e.to_string())?;
        return Ok(response);
    }
    let platform = host_check(&crate::eth_rpc::facts(&session)?)?;
    if Platform::parse(&node.platform) != Some(platform) {
        return Err("host architecture differs from the stored release".into());
    }
    // Verify remote ownership BEFORE updating any desired inventory pin.
    let before = control(&session, node, network, "status")?;
    if before["phase"] == "installing" && !["deploy", "stop", "destroy"].contains(&verb) {
        return Err("resume deploy at the stored target before another operation".into());
    }
    match verb {
        "deploy" | "update" | "update-config" => {
            let verified = authenticated(
                node,
                if verb == "update" {
                    one(args, "version")
                } else {
                    None
                },
            )
            .await?;
            let stored_version = Version::parse(&node.version).map_err(|e| e.to_string())?;
            if !verified.pin.version.at_least(&stored_version) {
                return Err(
                    "Bitcoin database downgrades are refused before changing inventory".into(),
                );
            }
            if let Some(installed) = before["installed"]["version"].as_str()
                && !verified
                    .pin
                    .version
                    .at_least(&Version::parse(installed).map_err(|e| e.to_string())?)
            {
                return Err(
                    "requested release is older than the host's installed database owner".into(),
                );
            }
            node_common::go_ahead(yes(args), "no Bitcoin configuration changed")
                .map_err(|e| e.to_string())?;
            let mut wanted = node.clone();
            pin_node(&mut wanted, &verified);
            *node = store
                .update_bitcoin_rpc(&wanted)
                .map_err(|e| e.to_string())?;
            node.last_run = play(node, network, verb, &verified, &session, &target, say)?;
            node.last_result = format!("{verb} ok");
            *node = store.update_bitcoin_rpc(node).map_err(|e| e.to_string())?;
            readiness(network, node, control(&session, node, network, "status")?)
        }
        "start" | "restart" => {
            node_common::go_ahead(yes(args), "no Bitcoin service changed")
                .map_err(|e| e.to_string())?;
            let mut desired = request(node, network, verb)?;
            if matches!(verb, "start" | "restart") {
                desired["generation"] = before["generation"].clone();
            }
            let response = control_request(&session, &desired)?;
            node.last_result = format!("{verb} ok; data retained");
            *node = store.update_bitcoin_rpc(node).map_err(|e| e.to_string())?;
            Ok(response)
        }
        _ => Err("unsupported Bitcoin mutation".into()),
    }
}

fn emit_log(
    json_out: bool,
    line: &str,
    mut stdout: impl FnMut(&str),
    mut stderr: impl FnMut(&str),
) {
    if json_out {
        stdout(&json!({"type":"log","chain":"bitcoin","line":line}).to_string());
    } else {
        stderr(line);
    }
}

async fn operation(
    verb: &str,
    network: Network,
    args: &ArgMatches,
    say: &Say,
) -> Result<Value, String> {
    if verb == "init" {
        return init(network, args, say).await;
    }
    let (store, _) = open(network, args)?;
    if verb == "list" {
        return Ok(json!({"nodes":store.bitcoin_rpcs().map_err(|e|e.to_string())?}));
    }
    let mut node = find(&store, args)?;
    if verb == "plan" {
        let change = one(args, "change").unwrap_or("deploy");
        let candidate = if change == "update" {
            Some(
                authenticated(
                    &node,
                    Some(one(args, "version").ok_or("plan --change update requires --version")?),
                )
                .await?,
            )
        } else {
            None
        };
        return Ok(
            json!({"name":node.name,"network":network.name(),"change":change,"version":candidate.as_ref().map_or(node.version.as_str(),|r|r.pin.version.as_str()),"storage":node.storage,"prune_mib":node.prune_mib,"rpc":"loopback with local cookie; wallet disabled","automatic_database_rollback":false,"destroy_preserves_data":true}),
        );
    }
    if ["status", "logs"].contains(&verb) {
        let target = target(&node, args)?;
        let session = Session::open(&target).map_err(|e| e.to_string())?;
        let response = control(&session, &node, network, "status")?;
        if verb == "logs" {
            let logs = Say { quiet: false };
            session
                .stream(
                    &RemoteCommand::BitcoinLogs {
                        lines: args.get_one::<u32>("lines").copied().unwrap_or(100),
                        follow: args.get_flag("follow"),
                    },
                    &mut |_, line| {
                        emit_log(say.quiet, line, crate::print_line, |text| logs.line(text));
                    },
                )
                .map_err(|e| e.to_string())?;
            return Ok(json!({"logs":"complete"}));
        }
        return readiness(network, &node, response);
    }
    change(verb, network, args, &mut node, &store, say).await
}

pub(crate) fn report_status(
    result: Result<Value, String>,
    json_out: bool,
    output: &mut dyn FnMut(&str),
) -> Outcome {
    crate::node_report::status(result, "/readiness/ready", json_out, output)
}

pub(crate) async fn run(
    verb: &str,
    args: &ArgMatches,
    network: Option<&str>,
    json_out: bool,
) -> Outcome {
    let Some(network) = network.and_then(Network::parse) else {
        return Outcome::Usage(
            "Bitcoin operations require --network mainnet, testnet4, signet or regtest".into(),
        );
    };
    let say = Say { quiet: json_out };
    let result = operation(verb, network, args, &say).await;
    if verb == "status" {
        return report_status(result, json_out, &mut crate::print_line);
    }
    match result {
        Ok(value) => {
            if json_out {
                crate::print_json(&value);
            } else {
                say.line(&serde_json::to_string_pretty(&value).unwrap_or_default());
            }
            Outcome::Done(String::new())
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn actual_rust_bundle_and_generated_unit_reach_pinned_ansible_controller() {
        use std::io::Write as _;
        let python = std::env::var("ERPC_TEST_ANSIBLE_PYTHON").unwrap_or_else(|_| "python3".into());
        let id = |flag| {
            let out = std::process::Command::new("id").arg(flag).output().unwrap();
            assert!(out.status.success());
            String::from_utf8(out.stdout)
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap()
        };
        let mut bundle = Bundle::new();
        add_templates(&erpc_chain_bitcoin::TEMPLATES, &mut bundle).unwrap();
        let finished = bundle.finish().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("public-bundle.tar.gz");
        std::fs::write(&archive, finished.bytes).unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-bitcoin/tests/play.py");
        let mut child = std::process::Command::new(python)
            .arg(script)
            .arg(archive)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                json!({"unit":erpc_chain_bitcoin::unit(id("-u"),id("-g")).unwrap()})
                    .to_string()
                    .as_bytes(),
            )
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if std::env::var_os("ERPC_TEST_ANSIBLE_PYTHON").is_some() {
            assert!(!String::from_utf8_lossy(&result.stdout).contains("SKIP"));
        }
    }

    #[test]
    fn parsed_legacy_migration_uses_the_public_request_and_returns_without_deploying() {
        use erpc_core::chain::{Chain, Role};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.json");
        let record = json!({"schema":"erpc-bitcoin-original-v1","contract":{},"machine_sha256":"public",
            "layout":{},"account":{},"highest_source":{},"daemon_sha256":"public","client_sha256":"public"});
        std::fs::write(&path, record.to_string()).unwrap();
        let matches = crate::tree::command(Role::Rpc, Chain::Bitcoin)
            .try_get_matches_from([
                "rpc",
                "deploy",
                "--network",
                "signet",
                "--original-runtime-record",
                path.to_str().unwrap(),
                "--yes",
            ])
            .unwrap();
        let args = matches.subcommand_matches("deploy").unwrap();
        let node = BitcoinRpc {
            id: Some("publicowner".into()),
            version: "31.1".into(),
            platform: "x86_64".into(),
            commit: "a".repeat(40),
            sha256: "b".repeat(64),
            storage: "full".into(),
            ..BitcoinRpc::default()
        };
        let mut sent = Vec::new();
        let result = migration_action("deploy", args, &node, Network::Signet, |request| {
            sent.push(request.clone());
            Ok(json!({"migrated":true,"service":"stopped"}))
        })
        .unwrap();
        assert_eq!(result.unwrap()["service"], "stopped");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["action"], "migrate-original");
        assert_eq!(sent[0]["original"], record);
        assert!(sent[0].get("intent").is_none());
        std::fs::write(&path, "{\"unexpected\":\"private-format\"}").unwrap();
        assert!(
            migration_action("deploy", args, &node, Network::Signet, |_| panic!(
                "invalid file must not reach SSH"
            ))
            .is_err()
        );
        let ordinary = crate::tree::command(Role::Rpc, Chain::Bitcoin)
            .try_get_matches_from(["rpc", "deploy", "--network", "signet"])
            .unwrap();
        assert!(
            migration_action(
                "deploy",
                ordinary.subcommand_matches("deploy").unwrap(),
                &node,
                Network::Signet,
                |_| panic!("ordinary deploy does not send a migration request")
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn logs_route_compact_json_to_stdout_and_human_lines_to_stderr() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        emit_log(
            true,
            "public journal\nentry",
            |s| out.push(s.to_owned()),
            |s| err.push(s.to_owned()),
        );
        assert!(err.is_empty());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&out[0]).unwrap()["line"],
            "public journal\nentry"
        );
        out.clear();
        emit_log(
            false,
            "public journal",
            |s| out.push(s.to_owned()),
            |s| err.push(s.to_owned()),
        );
        assert!(out.is_empty());
        assert_eq!(err, vec!["public journal"]);
    }

    #[test]
    fn actual_carried_controller_fits_windows_ssh_with_quoted_argument_margin() {
        let command = RemoteCommand::BitcoinControl {
            program: erpc_chain_bitcoin::CONTROLLER,
        }
        .line();
        assert!(command.starts_with("sudo -n /usr/bin/python3 -I -c 'import sys,hashlib;"));
        // The generated command is ASCII with no backslashes. Account for the
        // outer Windows quotes and escapes of every contained double quote.
        let quoted = command.encode_utf16().count() + command.matches('"').count() + 2;
        assert!(quoted + 8192 < 32_767, "encoded controller: {quoted}");
        assert!(
            erpc_chain_bitcoin::unit(20000, 20000)
                .unwrap()
                .contains("ExecStartPre=+/usr/bin/python3 -I -c")
        );
        assert!(
            !erpc_chain_bitcoin::unit(20000, 20000)
                .unwrap()
                .contains("@BITCOIN_GUARD@")
        );
    }
}
