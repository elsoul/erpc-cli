// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the `erpc r --chain solana` verbs share: the network's vault and RPC
//! nodes, reaching a node, the variables and bundle of a run, running a play
//! to its end, the firewall confirmation, and the node's state.

use std::fmt::Write as _;
use std::net::IpAddr;

use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{SolanaRpc, Store};
use erpc_chain_solana::rpc;
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use serde_json::{Map, Value, json};

use crate::arc_rpc::{Facts, Login};
use crate::node_common::{Say, agent_socket, op_runner, store, vault_for};

/// The chain, as the inventory names it.
pub(crate) const CHAIN: &str = "solana";
/// Memory below which erpc warns: SLV's servers for a `SendTx` or gRPC node
/// have 256 GB at the least, and an Index node 512 GB.
const WANT_MEMORY_KB: u64 = 250_000_000;
const WANT_INDEX_MEMORY_KB: u64 = 500_000_000;

/// The network's vault, its store, and the Solana RPC nodes in it.
pub(crate) struct Opened {
    pub(crate) vault: String,
    pub(crate) store: Store<OpCli>,
    pub(crate) nodes: Vec<SolanaRpc>,
}

/// Opens the network's vault and reads its RPC nodes.
pub(crate) fn open(network: &str, vault_flag: Option<&str>, say: &Say) -> Result<Opened, String> {
    if !rpc::NETWORKS.contains(&network) {
        return Err(format!(
            "erpc sets up Solana RPC nodes on {} so far, not {network}",
            rpc::NETWORKS.join(", ")
        ));
    }
    let vault = vault_for(
        network,
        vault_flag,
        &format!("erpc r --chain solana init -n {network} --vault <vault id>"),
    )?;
    let runner = op_runner()?;
    let store = store(&runner, &vault, CHAIN, network)?;
    say.line("1Password  reading the inventory…");
    let nodes = store.solana_rpcs().map_err(|e| e.to_string())?;
    Ok(Opened {
        vault,
        store,
        nodes,
    })
}

/// The stored node called `name`.
pub(crate) fn find<'a>(
    nodes: &'a [SolanaRpc],
    name: &str,
    network: &str,
) -> Result<&'a SolanaRpc, String> {
    nodes.iter().find(|n| n.name == name).ok_or_else(|| {
        format!(
            "there is no Solana RPC node {name} on {network}; `erpc r --chain solana list -n {network}` shows them"
        )
    })
}

/// The stored node, refused until init has made `solv` on it.
pub(crate) fn find_ready<'a>(
    nodes: &'a [SolanaRpc],
    name: &str,
    network: &str,
) -> Result<&'a SolanaRpc, String> {
    let node = find(nodes, name, network)?;
    if node.ssh_user != "solv" {
        return Err(format!(
            "{name} has no solv user yet: run `erpc r --chain solana init -n {network} --name {name}` again to finish it"
        ));
    }
    Ok(node)
}

/// The target that logs in to a stored node with its pinned host key.
pub(crate) fn target(node: &SolanaRpc, login: &Login) -> Result<Target, String> {
    target_as(node, &node.ssh_user, login)
}

/// As [`target`], logging in as `user`.
pub(crate) fn target_as(node: &SolanaRpc, user: &str, login: &Login) -> Result<Target, String> {
    let ssh_key = login
        .ssh_key
        .clone()
        .ok_or("pass --ssh-key <path to the .pub of the key that logs in>")?;
    Ok(Target {
        host: node.address.clone(),
        port: node.ssh_port,
        user: user.to_owned(),
        host_key: HostKey::parse(&node.host_key).map_err(|e| e.to_string())?,
        identity: Identity::Agent {
            socket: agent_socket(login.ssh_agent.as_deref())?,
            public_key: ssh_key,
        },
    })
}

/// What stops a Solana RPC node on this host, if anything.
pub(crate) fn refusals(facts: &Facts) -> Vec<String> {
    let mut out = Vec::new();
    if !facts.sudo {
        out.push("the login user cannot run sudo without a password".to_owned());
    }
    if facts.machine != "x86_64" {
        out.push(format!(
            "the server is {}; the clients are built for x86_64",
            facts.machine
        ));
    }
    out
}

/// A warning when the host has less memory than the node's type wants.
pub(crate) fn memory_warning(facts: &Facts, rpc_type: &str) -> Option<String> {
    let index = rpc::RpcType::parse(rpc_type).is_some_and(rpc::RpcType::faithful);
    let want = if index {
        WANT_INDEX_MEMORY_KB
    } else {
        WANT_MEMORY_KB
    };
    (facts.mem_kb < want).then(|| {
        format!(
            "warning    {} GB of memory; a mainnet {rpc_type} node wants {} GB or more",
            facts.mem_kb / 1_000_000,
            if index { 512 } else { 256 }
        )
    })
}

/// A warning when SSH would be admitted from erpc's present address alone.
pub(crate) fn lockout_warning(node: &SolanaRpc, facts: &Facts) -> Option<String> {
    crate::arc_rpc::lockout_warning(&node.management_allow, facts)
}

/// What a run on the node is told about it.
pub(crate) struct RunVars<'a> {
    pub(crate) network: &'a str,
    pub(crate) node: &'a SolanaRpc,
    pub(crate) facts: &'a Facts,
    /// The operator's public key line, for `create_user`.
    pub(crate) authorized: &'a str,
    pub(crate) extra: Map<String, Value>,
}

impl RunVars<'_> {
    /// The host variables: SLV's, the pins, and the firewall's lists with
    /// the address erpc connects from in the management set.
    pub(crate) fn host_vars(&self) -> Result<Map<String, Value>, String> {
        let mut vars =
            rpc::host_vars(self.network, self.node, self.authorized).map_err(|e| e.to_string())?;
        let controller = self.facts.controller_ip()?;
        let (v4, v6) = management_lists(self.node, controller);
        let (low, high) = rpc::CLUSTER_PORTS;
        for (k, v) in [
            ("ansible_connection", json!("local")),
            ("erpc_fw_management_v4", json!(v4)),
            ("erpc_fw_management_v6", json!(v6)),
            ("erpc_fw_rpc_v4", json!(self.node.rpc_allow)),
            ("erpc_fw_monitoring_v4", json!(self.node.monitoring_allow)),
            ("erpc_fw_client_ports", json!(rpc::CLIENT_PORTS)),
            ("erpc_fw_metrics_ports", json!(rpc::METRICS_PORTS)),
            ("erpc_fw_cluster_ports", json!(format!("{low}-{high}"))),
            ("erpc_ssh_port", json!(self.node.ssh_port)),
        ] {
            vars.insert(k.to_owned(), v);
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

/// The management sets: the stored list plus erpc's own address, so a
/// firewall erpc applies always admits erpc.
fn management_lists(node: &SolanaRpc, controller: IpAddr) -> (Vec<String>, Vec<String>) {
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

/// Runs `play` on the node with the node's pins and `vars_files`, and
/// follows it to its end. Returns the run's id.
pub(crate) fn run_play(
    session: &Session,
    target: &Target,
    vars: &RunVars<'_>,
    play: &str,
    vars_files: &[(&str, String)],
    again: &str,
    say: &Say,
) -> Result<String, String> {
    let pinned = rpc::versions_yml(vars.network, vars.node).map_err(|e| e.to_string())?;
    let mut files: Vec<(&str, String)> = vec![("vars/versions.yml", pinned)];
    files.extend(vars_files.iter().cloned());
    let mut inventory = vars.inventory_json()?;
    if [
        erpc_chain_solana::plays::MAINNET_RPC_DEPLOY,
        erpc_chain_solana::plays::MAINNET_RPC_CONFIG,
        erpc_chain_solana::plays::MAINNET_RPC_UPDATE,
    ]
    .contains(&play)
    {
        let preparation = crate::validator_init::bundle(&inventory, &files)?;
        let prepared = erpc_ops::run::start(
            session,
            &preparation,
            erpc_chain_solana::plays::MAINNET_RPC_FIREWALL,
        )
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
        confirm_firewall(
            target,
            erpc_ssh::firewall::FirewallToken::new(prepared.clone(), &preparation.sha256)?,
            say,
        )?;
        inventory = erpc_ops::firewall_inventory(&inventory, &prepared, &preparation.sha256)?;
    }
    let built = crate::validator_init::bundle(&inventory, &files)?;
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
            "{play} failed on {} (run {}, exit {}){}. Fix it and run the same command again; \
             what is done is not redone",
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

/// After a play that may have changed the firewall: connects afresh and
/// confirms the table, which proves the new table admits erpc. If erpc
/// cannot get in, the node puts the previous table back by itself.
fn confirm_firewall(
    target: &Target,
    token: erpc_ssh::firewall::FirewallToken,
    say: &Say,
) -> Result<(), String> {
    let fresh = Session::open(target).map_err(|e| e.to_string())?;
    match fresh.run(&RemoteCommand::SolanaRpcFirewallConfirm { token }, None) {
        Ok(out) => {
            if String::from_utf8_lossy(&out.stdout).contains("firewall=confirmed") {
                say.line("firewall   confirmed from a fresh connection");
            }
            Ok(())
        }
        Err(e) => Err(format!(
            "could not reach the node again after the firewall changed ({e}); it restores the \
             previous table after its rollback timer and active operation finish. If no policy can be restored, node services are stopped and disabled. Check --management-allow and run the same command again"
        )),
    }
}

/// Records how a run ended in the node's item; a 1Password prompt that has
/// timed out after a long run is a warning, not a failure.
pub(crate) fn record(
    store: &Store<OpCli>,
    node: SolanaRpc,
    run: &str,
    result: &str,
    say: &Say,
) -> SolanaRpc {
    let next = SolanaRpc {
        last_run: run.to_owned(),
        last_result: result.to_owned(),
        ..node
    };
    match store.update_solana_rpc(&next) {
        Ok(stored) => stored,
        Err(e) => {
            say.line(&format!(
                "warning    the run is not recorded in 1Password: {e}"
            ));
            next
        }
    }
}

/// A Solana RPC node's state, from [`RemoteCommand::SolanaRpcStatus`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent observed service/filter facts, not control state.
pub(crate) struct Status {
    pub(crate) validator: String,
    pub(crate) faithful: String,
    pub(crate) of1_sync: String,
    pub(crate) firewall_unit: String,
    pub(crate) identity_link: String,
    pub(crate) identity: String,
    pub(crate) health: String,
    pub(crate) slot: Option<u64>,
    pub(crate) version: String,
    pub(crate) faithful_version: String,
    pub(crate) grpc_listen: bool,
    pub(crate) geyser_version: String,
    pub(crate) restarts: String,
    pub(crate) since: String,
    pub(crate) ledger_used_kb: Option<u64>,
    pub(crate) ledger_free_kb: Option<u64>,
    pub(crate) accounts_free_kb: Option<u64>,
    pub(crate) firewall_table: bool,
    pub(crate) firewall_armed: bool,
    pub(crate) firewall_revoked: bool,
}

/// The `result` of a JSON-RPC answer, its error's message, or what came
/// back when it is neither.
fn rpc_answer(text: &str) -> Result<Value, String> {
    if text.is_empty() {
        return Err("no answer".to_owned());
    }
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Err(text.chars().take(120).collect());
    };
    if let Some(r) = v.get("result") {
        return Ok(r.clone());
    }
    Err(v["error"]["message"]
        .as_str()
        .map_or_else(|| text.chars().take(120).collect(), str::to_owned))
}

impl Status {
    pub(crate) fn parse(text: &str) -> Self {
        let mut s = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            let number = || value.parse::<u64>().ok();
            match key {
                "unit_solv" => value.clone_into(&mut s.validator),
                "unit_faithful" => value.clone_into(&mut s.faithful),
                "unit_of1-index-sync" => value.clone_into(&mut s.of1_sync),
                "unit_erpc-solana-rpc-firewall" => value.clone_into(&mut s.firewall_unit),
                "identity_link" => value.clone_into(&mut s.identity_link),
                "identity" => value.clone_into(&mut s.identity),
                "health" => {
                    s.health = match rpc_answer(value) {
                        Ok(v) => v.as_str().map_or_else(|| v.to_string(), str::to_owned),
                        Err(e) => e,
                    };
                }
                "slot" => s.slot = rpc_answer(value).ok().and_then(|v| v.as_u64()),
                "version" => {
                    s.version = rpc_answer(value)
                        .ok()
                        .and_then(|v| v["solana-core"].as_str().map(str::to_owned))
                        .unwrap_or_default();
                }
                "faithful" => {
                    s.faithful_version = match rpc_answer(value) {
                        Ok(v) => v
                            .get("solana-core")
                            .and_then(Value::as_str)
                            .map_or_else(|| "answers".to_owned(), str::to_owned),
                        Err(e) => e,
                    };
                }
                "grpc_listen" => s.grpc_listen = value == "yes",
                "geyser_version" => value.clone_into(&mut s.geyser_version),
                "restarts" => value.clone_into(&mut s.restarts),
                "since" => value.clone_into(&mut s.since),
                "ledger_used_kb" => s.ledger_used_kb = number(),
                "ledger_free_kb" => s.ledger_free_kb = number(),
                "accounts_free_kb" => s.accounts_free_kb = number(),
                "firewall_table" => s.firewall_table = value == "yes",
                "firewall_armed" => s.firewall_armed = value == "yes",
                "firewall_revoked" => s.firewall_revoked = value == "yes",
                _ => {}
            }
        }
        s
    }

    /// The validator answers and is caught up.
    pub(crate) fn healthy(&self) -> bool {
        self.health == "ok"
    }

    /// What is wrong with a deployed node, if anything. A node that is
    /// still catching up is not a problem: it says so in its health.
    pub(crate) fn problems(&self, node: &SolanaRpc) -> Vec<String> {
        let mut out = Vec::new();
        if self.validator != "active" {
            out.push(format!(
                "the validator service is {:?}, not active",
                self.validator
            ));
        }
        if self.identity_link != "/home/solv/rpc-identity.json" {
            out.push(format!(
                "identity.json leads to {:?}, not the node's RPC identity",
                self.identity_link
            ));
        }
        if !node.identity_account.is_empty()
            && !self.identity.is_empty()
            && self.identity != node.identity_account
        {
            out.push(format!(
                "the node runs as {}, not {}, the identity in 1Password",
                self.identity, node.identity_account
            ));
        }
        if rpc::RpcType::parse(&node.rpc_type).is_some_and(rpc::RpcType::faithful)
            && self.faithful != "active"
        {
            out.push(format!("Old Faithful is {:?}, not active", self.faithful));
        }
        // The validator loads the plugin once it has a snapshot, and serves
        // RPC only after that: RPC that answers without gRPC is a plugin
        // that did not load, where a validator still fetching its snapshot
        // has neither.
        if rpc::RpcType::parse(&node.rpc_type).is_some_and(rpc::RpcType::geyser)
            && self.slot.is_some()
            && !self.grpc_listen
        {
            out.push(
                "nothing listens on gRPC port 10000: the Yellowstone plugin did not load (`logs --source validator`)"
                    .to_owned(),
            );
        }
        if !self.firewall_table {
            out.push("the firewall table is not loaded".to_owned());
        }
        if self.firewall_revoked {
            out.push("firewall rollback revoked startup; retry deployment after correcting access ranges".to_owned());
        }
        if self.firewall_armed {
            out.push(
                "a firewall change is waiting for confirmation; run update-config again".to_owned(),
            );
        }
        out
    }
}

/// Reads the node's state.
pub(crate) fn read_status(session: &Session) -> Result<Status, String> {
    let out = session
        .run(&RemoteCommand::SolanaRpcStatus, None)
        .map_err(|e| e.to_string())?;
    Ok(Status::parse(&String::from_utf8_lossy(&out.stdout)))
}

/// A list, or `nobody`.
pub(crate) fn list_or_nobody(list: &[String]) -> String {
    if list.is_empty() {
        "nobody".to_owned()
    } else {
        list.join(",")
    }
}

/// The node's pins, one per line, for a plan or a report.
pub(crate) fn pins(node: &SolanaRpc) -> String {
    let mut out = String::new();
    let short = |c: &str| c[..c.len().min(12)].to_owned();
    let _ = write!(
        out,
        "{} {} @ {}",
        node.client,
        node.version,
        short(&node.commit)
    );
    if !node.geyser_version.is_empty() {
        let _ = write!(
            out,
            ", yellowstone {} @ {}",
            node.geyser_version,
            short(&node.geyser_commit)
        );
    }
    if !node.of1_version.is_empty() {
        let _ = write!(out, ", old faithful {}", node.of1_version);
    }
    out
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::SolanaRpc;
    use serde_json::Value;

    use super::{RunVars, Status, memory_warning, pins, refusals};
    use crate::arc_rpc::Facts;

    fn facts() -> Facts {
        Facts::parse(
            "machine=x86_64\nmem_kb=528000000\ncpus=64\ncpu_max_mhz=4000\nroot_free_kb=400000000\n\
             data_free_kb=\nsystemd=255\ntpm=no\ncontroller=203.0.113.7\nssh_port=22\nsudo=yes\n",
        )
    }

    fn node() -> SolanaRpc {
        SolanaRpc {
            name: "rpc1".to_owned(),
            address: "192.0.2.10".to_owned(),
            ssh_user: "solv".to_owned(),
            ssh_port: 22,
            client: "jito".to_owned(),
            rpc_type: "index".to_owned(),
            version: "v4.3.2-jito".to_owned(),
            commit: "a".repeat(40),
            of1_version: "v0.7.31".to_owned(),
            of1_sha256: "c".repeat(64),
            region: "frankfurt".to_owned(),
            identity_account: "Ident111".to_owned(),
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            management_allow: vec!["192.0.2.50".to_owned()],
            ..SolanaRpc::default()
        }
    }

    #[test]
    fn the_run_inventory_has_the_firewall_lists_with_erpc_and_not_the_address() {
        let n = node();
        let f = facts();
        let vars = RunVars {
            network: "mainnet",
            node: &n,
            facts: &f,
            authorized: "ssh-ed25519 AAAA op",
            extra: serde_json::Map::new(),
        };
        let text = vars.inventory_json().expect("inventory");
        assert!(!text.contains("192.0.2.10"), "{text}");
        let doc: Value = serde_json::from_str(&text).expect("JSON");
        let host = &doc["all"]["hosts"]["rpc1"];
        assert_eq!(host["ansible_connection"], "local");
        assert_eq!(host["erpc_fw_management_v4"][1], "203.0.113.7");
        assert_eq!(host["erpc_fw_rpc_v4"][0], "198.51.100.0/24");
        assert_eq!(host["erpc_fw_client_ports"][0], 7211);
        assert_eq!(host["erpc_fw_cluster_ports"], "8000-8030");
        assert_eq!(host["rpc_type"], "Index RPC");
        let pinned = erpc_chain_solana::rpc::versions_yml("mainnet", &n).expect("pins");
        let built =
            crate::validator_init::bundle(&text, &[("vars/versions.yml", pinned)]).expect("bundle");
        assert_eq!(built.sha256.len(), 64);
    }

    #[test]
    fn a_host_without_sudo_or_x86_is_refused_and_a_small_one_warned_about() {
        assert!(refusals(&facts()).is_empty());
        let arm = Facts {
            machine: "aarch64".to_owned(),
            sudo: false,
            ..facts()
        };
        assert_eq!(refusals(&arm).len(), 2);
        assert!(memory_warning(&facts(), "index").is_none());
        let small = Facts {
            mem_kb: 264_000_000,
            ..facts()
        };
        assert!(memory_warning(&small, "send-tx").is_none());
        assert!(memory_warning(&small, "index-grpc").is_some());
    }

    const SAMPLE: &str = "unit_solv=active\nunit_faithful=active\nunit_of1-index-sync=active\n\
        unit_erpc-solana-rpc-firewall=active\nidentity_link=/home/solv/rpc-identity.json\n\
        identity=Ident111\nhealth={\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":1}\n\
        slot={\"jsonrpc\":\"2.0\",\"result\":460514749,\"id\":1}\n\
        version={\"jsonrpc\":\"2.0\",\"result\":{\"feature-set\":1,\"solana-core\":\"4.3.2\"},\"id\":1}\n\
        faithful={\"jsonrpc\":\"2.0\",\"result\":{\"faithful\":\"v0.7.31\"},\"id\":1}\n\
        restarts=0\nsince=Fri 2026-10-23 10:00:00 UTC\nledger_used_kb=1\nledger_free_kb=2\n\
        accounts_free_kb=3\nfirewall_table=yes\nfirewall_armed=no\ngrpc_listen=no\ngeyser_version=\n";

    #[test]
    fn the_status_reads_and_a_healthy_node_has_no_problems() {
        let s = Status::parse(SAMPLE);
        assert!(s.healthy());
        assert_eq!(s.slot, Some(460_514_749));
        assert_eq!(s.version, "4.3.2");
        assert_eq!(s.faithful_version, "answers");
        assert!(s.problems(&node()).is_empty(), "{:?}", s.problems(&node()));
        let behind = SAMPLE.replace(
            "{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":1}",
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32005,\"message\":\"Node is behind by 120 slots\"},\"id\":1}",
        );
        let s = Status::parse(&behind);
        assert_eq!(s.health, "Node is behind by 120 slots");
        assert!(s.problems(&node()).is_empty());
        let wrong = SAMPLE
            .replace("unit_faithful=active", "unit_faithful=failed")
            .replace("rpc-identity.json", "validator-keypair.json")
            .replace("firewall_table=yes", "firewall_table=no");
        assert_eq!(Status::parse(&wrong).problems(&node()).len(), 3);
        // A gRPC node whose plugin did not load says so; one that serves
        // gRPC reads its plugin's version.
        let grpc = SolanaRpc {
            rpc_type: "grpc".to_owned(),
            ..node()
        };
        let s = Status::parse(SAMPLE);
        assert_eq!(s.problems(&grpc).len(), 1, "{:?}", s.problems(&grpc));
        let fetching = SAMPLE.replace(
            "slot={\"jsonrpc\":\"2.0\",\"result\":460514749,\"id\":1}",
            "slot=",
        );
        let s = Status::parse(&fetching);
        assert!(s.problems(&grpc).is_empty(), "{:?}", s.problems(&grpc));
        let serving = SAMPLE
            .replace("grpc_listen=no", "grpc_listen=yes")
            .replace("geyser_version=\n", "geyser_version=16.1.5+solana.4.3.2\n");
        let s = Status::parse(&serving);
        assert!(s.problems(&grpc).is_empty(), "{:?}", s.problems(&grpc));
        assert_eq!(s.geyser_version, "16.1.5+solana.4.3.2");
    }

    #[test]
    fn the_pins_read_for_each_client() {
        assert!(pins(&node()).starts_with("jito v4.3.2-jito @ aaaaaaaaaaaa, old faithful v0.7.31"));
    }
}
