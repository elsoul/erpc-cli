// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the `erpc r --chain eth` verbs share: the network's vault and RPC
//! nodes, reaching a node, its facts, the variables and bundle of a run,
//! running a play to its end, and the firewall confirmation. The allow-list
//! check is Arc's ([`crate::arc_rpc::allow_list`]).

use std::net::IpAddr;
use std::path::PathBuf;

use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{EthRpc, Store};
use erpc_chain_eth::kind::RpcType;
use erpc_chain_eth::network::Network;
use erpc_chain_eth::releases::{self, Client, Platform};
use erpc_ops::bundle::{Built, Bundle};
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use serde_json::{Map, Value, json};

use crate::node_common::{Say, agent_socket, op_runner, store, vault_for};

/// The chain, as the inventory names it.
pub(crate) const CHAIN: &str = "eth";
/// Memory below which a node is refused: a Reth and Lighthouse node wants
/// 32 GB, and a 32 GB machine reports a little less.
pub(crate) const MIN_MEMORY_KB: u64 = 30_000_000;

/// How to log in: the operator's key in its agent.
#[derive(Debug, Clone, Default)]
pub(crate) struct Login {
    /// The `.pub` file of the key that logs in.
    pub(crate) ssh_key: Option<PathBuf>,
    /// The agent's socket.
    pub(crate) ssh_agent: Option<PathBuf>,
}

/// The network's vault, its store, and the RPC nodes in it.
pub(crate) struct Opened {
    pub(crate) vault: String,
    pub(crate) store: Store<OpCli>,
    pub(crate) nodes: Vec<EthRpc>,
    pub(crate) network: Network,
}

/// Opens the network's vault and reads its RPC nodes.
pub(crate) fn open(network: &str, vault_flag: Option<&str>, say: &Say) -> Result<Opened, String> {
    let net = erpc_chain_eth::network::get(network)
        .ok_or_else(|| format!("erpc runs Ethereum RPC nodes on mainnet so far, not {network}"))?;
    let vault = vault_for(
        network,
        vault_flag,
        &format!("erpc r --chain eth init -n {network} --vault <vault id>"),
    )?;
    let runner = op_runner()?;
    let store = store(&runner, &vault, CHAIN, network)?;
    say.line("1Password  reading the inventory…");
    let nodes = store.eth_rpcs().map_err(|e| e.to_string())?;
    Ok(Opened {
        vault,
        store,
        nodes,
        network: net,
    })
}

/// The stored node called `name`.
pub(crate) fn find<'a>(
    nodes: &'a [EthRpc],
    name: &str,
    network: &str,
) -> Result<&'a EthRpc, String> {
    nodes.iter().find(|n| n.name == name).ok_or_else(|| {
        format!(
            "there is no Ethereum RPC node {name} on {network}; `erpc r --chain eth list -n {network}` shows them"
        )
    })
}

/// The target that logs in to a stored node with its pinned host key.
pub(crate) fn target(node: &EthRpc, login: &Login) -> Result<Target, String> {
    let ssh_key = login
        .ssh_key
        .clone()
        .ok_or("pass --ssh-key <path to the .pub of the key that logs in>")?;
    Ok(Target {
        host: node.address.clone(),
        port: node.ssh_port,
        user: node.ssh_user.clone(),
        host_key: HostKey::parse(&node.host_key).map_err(|e| e.to_string())?,
        identity: Identity::Agent {
            socket: agent_socket(login.ssh_agent.as_deref())?,
            public_key: ssh_key,
        },
    })
}

/// A host's facts, from [`RemoteCommand::EthFacts`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) os: String,
    pub(crate) machine: String,
    pub(crate) mem_kb: u64,
    pub(crate) cpus: u32,
    /// How many of AVX2, BMI2, FMA and MOVBE the processor has.
    pub(crate) x86_64_v3: u32,
    pub(crate) root_free_kb: u64,
    pub(crate) data_free_kb: Option<u64>,
    pub(crate) controller: String,
    pub(crate) ssh_port: u16,
    pub(crate) sudo: bool,
}

impl Facts {
    pub(crate) fn parse(text: &str) -> Self {
        let mut f = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key {
                "os" => value.clone_into(&mut f.os),
                "machine" => value.clone_into(&mut f.machine),
                "mem_kb" => f.mem_kb = value.parse().unwrap_or(0),
                "cpus" => f.cpus = value.parse().unwrap_or(0),
                "x86_64_v3" => f.x86_64_v3 = value.parse().unwrap_or(0),
                "root_free_kb" => f.root_free_kb = value.parse().unwrap_or(0),
                "data_free_kb" => f.data_free_kb = value.parse().ok(),
                "controller" => value.clone_into(&mut f.controller),
                "ssh_port" => f.ssh_port = value.parse().unwrap_or(0),
                "sudo" => f.sudo = value == "yes",
                _ => {}
            }
        }
        f
    }

    /// The release platform, from the machine.
    pub(crate) fn platform(&self) -> Result<Platform, String> {
        Platform::from_uname(&self.machine).ok_or_else(|| {
            format!(
                "the server is {}; Reth and Lighthouse are released for x86_64 and aarch64",
                self.machine
            )
        })
    }

    /// Ubuntu at or above 24.04, which Reth's glibc 2.38 needs.
    fn ubuntu_ok(&self) -> bool {
        let Some(version) = self.os.strip_prefix("ubuntu ") else {
            return false;
        };
        let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
        let (major, minor) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
        (major, minor) >= (24, 4)
    }

    /// What stops an Ethereum node here, if anything.
    pub(crate) fn refusals(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.sudo {
            out.push("the login user cannot run sudo without a password".to_owned());
        }
        if !self.ubuntu_ok() {
            out.push(format!(
                "the server runs {:?}; Reth's release needs glibc 2.38, which Ubuntu has from 24.04",
                self.os
            ));
        }
        if self.mem_kb < MIN_MEMORY_KB {
            out.push(format!(
                "{} GB of memory; a Reth and Lighthouse node wants 32 GB",
                self.mem_kb / 1_000_000
            ));
        }
        if self.machine == "x86_64" && self.x86_64_v3 < 4 {
            out.push(
                "the processor lacks AVX2, BMI2, FMA or MOVBE; Reth's x86_64 release is built for x86-64-v3"
                    .to_owned(),
            );
        }
        if let Err(e) = self.platform() {
            out.push(e);
        }
        out
    }

    /// The controller's address, as the node sees erpc's connection.
    pub(crate) fn controller_ip(&self) -> Result<IpAddr, String> {
        self.controller.parse().map_err(|_| {
            format!(
                "could not read the address erpc connects from ({:?}); the firewall needs it",
                self.controller
            )
        })
    }
}

/// Reads the host's facts.
pub(crate) fn facts(session: &Session) -> Result<Facts, String> {
    let out = session
        .run(&RemoteCommand::EthFacts, None)
        .map_err(|e| e.to_string())?;
    Ok(Facts::parse(&String::from_utf8_lossy(&out.stdout)))
}

/// The type a node is given: `--type`, else what is stored, else `full`;
/// fixed once stored, since it decides what history the data holds.
pub(crate) fn rpc_type(node: &EthRpc, stored: bool, flag: Option<&str>) -> Result<RpcType, String> {
    let wanted = match (flag, stored) {
        (Some(t), _) => t,
        (None, true) => node.rpc_type.as_str(),
        (None, false) => "full",
    };
    let kind = RpcType::parse(wanted).ok_or_else(|| {
        format!(
            "--type {wanted} is not one of {}",
            RpcType::NAMES.join(", ")
        )
    })?;
    if stored && wanted != node.rpc_type {
        return Err(format!(
            "{} is a {} node; its type decides the history its data holds, so it cannot \
             become {wanted}. Destroy it with --purge-data --forget and init it again",
            node.name, node.rpc_type
        ));
    }
    Ok(kind)
}

/// The management sets: the stored list plus the address erpc connects
/// from, so a firewall erpc applies always admits erpc.
pub(crate) fn management(node: &EthRpc, controller: IpAddr) -> (Vec<String>, Vec<String>) {
    let mut v4 = node.management_allow.clone();
    let mut v6 = Vec::new();
    match controller {
        IpAddr::V4(ip) => {
            let ip = ip.to_string();
            if !v4.contains(&ip) {
                v4.push(ip);
            }
        }
        IpAddr::V6(ip) => v6.push(ip.to_string()),
    }
    (v4, v6)
}

/// A warning when SSH would be admitted from erpc's present address alone.
pub(crate) fn lockout_warning(management: &[String], facts: &Facts) -> Option<String> {
    management.is_empty().then(|| {
        format!(
            "warning    SSH will be admitted only from {}, the address erpc connects from now. \
             If it changes, only the provider's console reaches the node: add a stable range \
             with --management-allow",
            facts.controller
        )
    })
}

/// What a run on the node is told about it: the inventory's host variables.
pub(crate) struct RunVars<'a> {
    pub(crate) role: erpc_core::chain::Role,
    pub(crate) node: &'a EthRpc,
    pub(crate) network: &'a Network,
    pub(crate) facts: &'a Facts,
    pub(crate) extra: Map<String, Value>,
}

impl RunVars<'_> {
    /// The host variables.
    pub(crate) fn host_vars(&self) -> Result<Map<String, Value>, String> {
        let platform = self.facts.platform()?;
        let controller = self.facts.controller_ip()?;
        if self.facts.ssh_port == 0 {
            return Err("the server-observed SSH destination port is missing; refuse an unconfirmed ingress policy".into());
        }
        let kind = RpcType::parse(&self.node.rpc_type)
            .ok_or_else(|| format!("{} has no type erpc runs", self.node.name))?;
        let (v4, v6) = management(self.node, controller);
        let mut vars = Map::new();
        let mut set = |k: &str, v: Value| {
            vars.insert(k.to_owned(), v);
        };
        set("ansible_connection", json!("local"));
        set("eth_chain_id", json!(self.network.chain_id));
        set("eth_rpc_type", json!(kind.as_str()));
        set("eth_min_free_gb", json!(kind.min_free_gb()));
        for (client, version, commit, sha256) in [
            (
                Client::Reth,
                &self.node.reth_version,
                &self.node.reth_commit,
                &self.node.reth_sha256,
            ),
            (
                Client::Lighthouse,
                &self.node.lighthouse_version,
                &self.node.lighthouse_commit,
                &self.node.lighthouse_sha256,
            ),
        ] {
            let name = client.name();
            set(&format!("eth_{name}_version"), json!(version));
            set(&format!("eth_{name}_commit"), json!(commit));
            set(&format!("eth_{name}_sha256"), json!(sha256));
            set(
                &format!("eth_{name}_url"),
                json!(releases::archive_url(client, version, platform)),
            );
            set(
                &format!("eth_{name}_fingerprint"),
                json!(client.fingerprint()),
            );
        }
        set("eth_rpc_allow", json!(self.node.rpc_allow));
        set("eth_monitoring_allow", json!(self.node.monitoring_allow));
        set("eth_fw_management_v4", json!(v4));
        set("eth_fw_management_v6", json!(v6));
        set("eth_ssh_port", json!(self.facts.ssh_port));
        match self.role {
            erpc_core::chain::Role::Rpc => {
                set(
                    "eth_authority_loader",
                    json!(erpc_chain_eth::authority::carried_loader()),
                );
                set(
                    "eth_authority_request",
                    crate::eth_authority::request(
                        self.node,
                        self.network.name,
                        "prepare",
                        json!({}),
                    )?,
                );
            }
            erpc_core::chain::Role::Validator => {}
            erpc_core::chain::Role::Node => {
                return Err(
                    "Ethereum run variables require an explicit RPC or validator role".into(),
                );
            }
        }
        vars.extend(self.extra.clone());
        Ok(vars)
    }

    /// The inventory a run reads: this node, run locally. Its address stays
    /// out of it.
    pub(crate) fn inventory_json(&self) -> Result<String, String> {
        Ok(
            json!({ "all": { "hosts": { self.node.name.clone(): self.host_vars()? } } })
                .to_string(),
        )
    }
}

/// A run's bundle: every carried Ethereum template, the inventory, and the
/// free-disk rule the init play checks again before it wipes a disk.
pub(crate) fn bundle(inventory_json: &str) -> Result<Built, String> {
    let mut bundle = Bundle::new();
    for path in erpc_chain_eth::files() {
        let bytes = erpc_chain_eth::file(path).ok_or_else(|| format!("{path} is not carried"))?;
        bundle
            .add(path, bytes.to_vec())
            .map_err(|e| e.to_string())?;
    }
    bundle
        .add("inventory.yml", inventory_json.as_bytes().to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add(
            erpc_chain_eth::bundle::FREE_DISKS,
            erpc_ssh::FREE_DISKS_SCRIPT.as_bytes().to_vec(),
        )
        .map_err(|e| e.to_string())?;
    bundle
        .add("rpc-firewall.py", erpc_ops::RPC_FIREWALL.to_vec())
        .map_err(|e| e.to_string())?;
    bundle.finish().map_err(|e| e.to_string())
}

/// Runs `play` on the node and follows it to its end. `again` is the
/// command that shows a lost run's end.
pub(crate) fn run_play(
    session: &Session,
    target: &Target,
    vars: &RunVars<'_>,
    play: &str,
    again: &str,
    say: &Say,
) -> Result<String, String> {
    let mut inventory = vars.inventory_json()?;
    if [erpc_chain_eth::plays::DEPLOY, erpc_chain_eth::plays::UPDATE].contains(&play) {
        let source = crate::eth_authority::source(vars.node)?;
        let observed = crate::eth_authority::invoke(
            session,
            vars.node,
            vars.network.name,
            "deployment",
            json!({}),
        )?;
        let operation = if play == erpc_chain_eth::plays::UPDATE {
            "update"
        } else if vars.extra.get("eth_phase").and_then(Value::as_str) == Some("config") {
            "update-config"
        } else {
            "deploy"
        };
        let intent = crate::eth_authority::deployment_intent(&observed, &source, operation)?;
        crate::eth_authority::invoke(
            session,
            vars.node,
            vars.network.name,
            "reserve-deploy",
            json!({"intent":intent,"target":source,"operation":operation}),
        )?;
        let mut document: Value = serde_json::from_str(&inventory).map_err(|e| e.to_string())?;
        let host = document["all"]["hosts"][&vars.node.name]
            .as_object_mut()
            .ok_or("missing generated Ethereum host")?;
        host.insert("eth_authority_intent".into(), json!(intent));
        host.insert("eth_authority_source".into(), source);
        inventory = document.to_string();
        let preparation = bundle(&inventory)?;
        let prepared = erpc_ops::run::start(session, &preparation, erpc_chain_eth::plays::FIREWALL)
            .map_err(|e| e.to_string())?;
        let result = crate::node_common::follow(
            target,
            &prepared,
            "Retry deployment to prepare the firewall again",
            say,
        )?;
        if !result.ok() {
            return Err("firewall preparation failed; deployment was not started".into());
        }
        let fresh = Session::open(target).map_err(|e| e.to_string())?;
        crate::eth_authority::invoke(
            &fresh,
            vars.node,
            vars.network.name,
            "firewall-confirm",
            json!({"intent":intent,"firewall":{"run":prepared.as_str(),"bundle":preparation.sha256}}),
        )?;
        say.line("firewall   confirmed from a fresh authenticated connection");
        inventory = erpc_ops::firewall_inventory(&inventory, &prepared, &preparation.sha256)?;
    }
    let built = bundle(&inventory)?;
    let run = erpc_ops::run::start(session, &built, play).map_err(|e| e.to_string())?;
    say.line(&format!(
        "run        {} on {}",
        run.as_str(),
        vars.node.name
    ));
    let result = crate::node_common::follow(target, &run, again, say)?;
    if result.ok() {
        Ok(run.as_str().to_owned())
    } else {
        Err(format!(
            "{play} failed on {} (run {}, exit {}){}. Fix it and run the same command again",
            vars.node.name,
            run.as_str(),
            result.exit_code,
            if result.message.is_empty() {
                String::new()
            } else {
                format!(": {}", result.message)
            }
        ))
    }
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::EthRpc;
    use serde_json::Value;

    use erpc_chain_eth::kind::RpcType;

    use super::{Facts, RunVars, rpc_type};

    pub(crate) fn facts() -> Facts {
        Facts::parse(
            "os=ubuntu 24.04\nmachine=x86_64\nmem_kb=131000000\ncpus=32\nx86_64_v3=4\n\
             root_free_kb=400000000\ndata_free_kb=3800000000\ncontroller=203.0.113.7\n\
             ssh_port=22\nsudo=yes\n",
        )
    }

    pub(crate) fn node() -> EthRpc {
        EthRpc {
            id: Some("inertoriginalinventory".into()),
            name: "eth1".to_owned(),
            address: "192.0.2.10".to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 22,
            rpc_type: "full".to_owned(),
            reth_version: "v2.8.1".to_owned(),
            reth_commit: "d763342fa185e4e90ee79dc65f6a5706168b0bcb".to_owned(),
            reth_sha256: "a".repeat(64),
            lighthouse_version: "v8.3.2".to_owned(),
            lighthouse_commit: "a376defa".repeat(5),
            lighthouse_sha256: "b".repeat(64),
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            ..EthRpc::default()
        }
    }

    #[test]
    fn ingress_uses_the_server_observed_port_and_never_the_external_forwarded_target() {
        let mut node = node();
        node.ssh_port = 2200;
        let mut observed = facts();
        observed.ssh_port = 2222;
        let network = erpc_chain_eth::network::get("mainnet").unwrap();
        let build = |facts: &Facts| {
            RunVars {
                role: erpc_core::chain::Role::Rpc,
                node: &node,
                network: &network,
                facts,
                extra: serde_json::Map::new(),
            }
            .host_vars()
        };
        assert_eq!(build(&observed).unwrap()["eth_ssh_port"], 2222);
        observed.ssh_port = 0;
        assert!(build(&observed).is_err());
    }

    #[test]
    fn the_facts_read_and_an_unfit_host_is_refused() {
        let f = facts();
        assert!(f.refusals().is_empty(), "{:?}", f.refusals());
        let jammy = Facts {
            os: "ubuntu 22.04".to_owned(),
            ..f.clone()
        };
        assert_eq!(jammy.refusals().len(), 1);
        let old_cpu = Facts {
            x86_64_v3: 2,
            mem_kb: 16_000_000,
            sudo: false,
            ..f.clone()
        };
        assert_eq!(old_cpu.refusals().len(), 3);
        let arm = Facts {
            machine: "aarch64".to_owned(),
            x86_64_v3: 0,
            ..f
        };
        assert!(arm.refusals().is_empty());
    }

    #[test]
    fn a_type_defaults_to_full_and_is_fixed_once_stored() {
        let n = node();
        assert_eq!(rpc_type(&n, false, None).map(RpcType::as_str), Ok("full"));
        assert_eq!(
            rpc_type(&n, false, Some("archive")).map(RpcType::as_str),
            Ok("archive")
        );
        assert!(rpc_type(&n, true, Some("archive")).is_err());
        assert_eq!(rpc_type(&n, true, None).map(RpcType::as_str), Ok("full"));
        assert!(rpc_type(&n, false, Some("provider")).is_err());
    }

    #[test]
    fn the_run_inventory_has_both_pins_and_not_the_address() {
        let network = erpc_chain_eth::network::get("mainnet").expect("mainnet");
        let n = node();
        let f = facts();
        let vars = RunVars {
            role: erpc_core::chain::Role::Rpc,
            node: &n,
            network: &network,
            facts: &f,
            extra: serde_json::Map::new(),
        };
        let text = vars.inventory_json().expect("inventory");
        assert!(!text.contains("192.0.2.10"), "{text}");
        let doc: Value = serde_json::from_str(&text).expect("JSON");
        let host = &doc["all"]["hosts"]["eth1"];
        assert_eq!(host["eth_chain_id"], 1);
        assert_eq!(host["eth_authority_request"]["contract"]["role"], "rpc");
        assert_eq!(
            host["eth_authority_request"]["contract"]["network"],
            "mainnet"
        );
        assert_eq!(host["eth_rpc_type"], "full");
        assert_eq!(host["eth_min_free_gb"], 1500);
        assert_eq!(host["eth_fw_management_v4"][0], "203.0.113.7");
        assert_eq!(
            host["eth_reth_fingerprint"],
            "50FB7CC55B2E8AFA59FE03B7AA5ED56A7FBF253E"
        );
        assert!(
            host["eth_lighthouse_url"]
                .as_str()
                .expect("url")
                .ends_with("lighthouse-v8.3.2-x86_64-unknown-linux-gnu.tar.gz")
        );
        let built = super::bundle(&text).expect("bundle");
        assert_eq!(built.sha256.len(), 64);
    }
}
