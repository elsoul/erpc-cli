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
    Ok(
        json!({"owner":owner(node)?,"network":network.name(),"storage":node.storage,"prune_mib":node.prune_mib,"action":action,"pin":{"version":version.as_str(),"commit":node.commit,"sha256":node.sha256,"platform":platform.target()}}),
    )
}
fn control(
    session: &Session,
    node: &BitcoinRpc,
    network: Network,
    action: &str,
) -> Result<Value, String> {
    let body = request(node, network, action)?.to_string();
    let output = session
        .run(&RemoteCommand::BitcoinControl, Some(body.as_bytes()))
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid Bitcoin controller response".into())
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
        bundle
            .add(
                file.path().to_str().ok_or("invalid carried path")?,
                file.contents().to_vec(),
            )
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
    let variables = json!({"ansible_connection":"local","btc_version":version.as_str(),"btc_platform":platform.target(),"btc_archive":platform.archive(version),"btc_archive_url":release::archive_url(version,platform),"btc_sha256":release.pin.sha256,"btc_request":request(node,network,"prepare")?,"btc_config":retention.config(network).map_err(str::to_owned)?,"btc_phase":phase});
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
    let platform = host_check(&crate::eth_rpc::facts(&session)?)?;
    if Platform::parse(&node.platform) != Some(platform) {
        return Err("host architecture differs from the stored release".into());
    }
    // Verify remote ownership BEFORE updating any desired inventory pin.
    let before = control(&session, node, network, "status")?;
    if before["phase"] == "installing" && verb != "deploy" {
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
        "start" | "stop" | "restart" | "destroy" => {
            node_common::go_ahead(yes(args), "no Bitcoin service changed")
                .map_err(|e| e.to_string())?;
            let response = control(&session, node, network, verb)?;
            node.last_result = format!("{verb} ok; data retained");
            *node = store.update_bitcoin_rpc(node).map_err(|e| e.to_string())?;
            Ok(response)
        }
        _ => Err("unsupported Bitcoin mutation".into()),
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
                    &mut |_, line| logs.line(line),
                )
                .map_err(|e| e.to_string())?;
            return Ok(json!({"logs":"complete"}));
        }
        return readiness(network, &node, response);
    }
    change(verb, network, args, &mut node, &store, say).await
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
    match operation(verb, network, args, &say).await {
        Ok(value) => {
            let unhealthy = verb == "status" && value["readiness"]["ready"] != true;
            if json_out {
                crate::print_json(&value);
            } else {
                say.line(&serde_json::to_string_pretty(&value).unwrap_or_default());
            }
            if unhealthy {
                Outcome::Failed("Bitcoin RPC is not ready; see readiness problems".into())
            } else {
                Outcome::Done(String::new())
            }
        }
        Err(error) => Outcome::Failed(error),
    }
}
