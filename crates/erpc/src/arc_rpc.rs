// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the `erpc r --chain arc` verbs share: the network's vault and RPC
//! nodes, reaching a node, its facts, the allow lists, the variables and
//! bundle of a run, and running a play to its end.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{RpcNode, Store};
use erpc_chain_arc::kind;
use erpc_chain_arc::network::Network;
use erpc_chain_arc::releases::{self, Platform};
use erpc_ops::bundle::{Built, Bundle};
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use serde_json::{Map, Value, json};

use crate::node_common::{Say, agent_socket, op_runner, store, vault_for};

/// The chain, as the inventory names it.
pub(crate) const CHAIN: &str = "arc";
/// Memory below which a node is refused: Arc asks for 64 GB, and a 64 GB
/// machine reports a little less.
pub(crate) const MIN_MEMORY_KB: u64 = 60_000_000;
/// The source-qualified credential-recipient ordering used by this profile.
pub(crate) const SUPPORTED_SYSTEMD: u32 = 255;

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
    pub(crate) runner: OpCli,
    pub(crate) store: Store<OpCli>,
    pub(crate) nodes: Vec<RpcNode>,
    pub(crate) network: Network,
}

/// Opens the network's vault and reads its RPC nodes.
pub(crate) fn open(network: &str, vault_flag: Option<&str>, say: &Say) -> Result<Opened, String> {
    let net = erpc_chain_arc::network::get(network)
        .ok_or_else(|| format!("Arc has no network {network}"))?;
    let vault = vault_for(
        network,
        vault_flag,
        &format!("erpc r --chain arc init -n {network} --vault <vault id>"),
    )?;
    let runner = op_runner()?;
    let store = store(&runner, &vault, CHAIN, network)?;
    say.line("1Password  reading the inventory…");
    let nodes = store.rpc_nodes().map_err(|e| e.to_string())?;
    Ok(Opened {
        vault,
        runner,
        store,
        nodes,
        network: net,
    })
}

/// The stored node called `name`.
pub(crate) fn find<'a>(
    nodes: &'a [RpcNode],
    name: &str,
    network: &str,
) -> Result<&'a RpcNode, String> {
    nodes.iter().find(|n| n.name == name).ok_or_else(|| {
        format!("there is no Arc RPC node {name} on {network}; `erpc r --chain arc list -n {network}` shows them")
    })
}

/// The target that logs in to a stored node with its pinned host key.
pub(crate) fn target(node: &RpcNode, login: &Login) -> Result<Target, String> {
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

/// A host's facts, from [`RemoteCommand::NodeFacts`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) machine: String,
    pub(crate) mem_kb: u64,
    pub(crate) cpus: u32,
    pub(crate) cpu_max_mhz: u32,
    pub(crate) root_free_kb: u64,
    pub(crate) data_free_kb: Option<u64>,
    /// What is mounted at /var/lib/arc, when something is: a disk an
    /// earlier init gave the data.
    pub(crate) data_mount: String,
    pub(crate) systemd: u32,
    pub(crate) tpm: bool,
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
                "machine" => value.clone_into(&mut f.machine),
                "mem_kb" => f.mem_kb = value.parse().unwrap_or(0),
                "cpus" => f.cpus = value.parse().unwrap_or(0),
                "cpu_max_mhz" => f.cpu_max_mhz = value.parse().unwrap_or(0),
                "root_free_kb" => f.root_free_kb = value.parse().unwrap_or(0),
                "data_free_kb" => f.data_free_kb = value.parse().ok(),
                "data_mount" => value.clone_into(&mut f.data_mount),
                "systemd" => f.systemd = value.parse().unwrap_or(0),
                "tpm" => f.tpm = value == "yes",
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
                "the server is {}; arc-node is released for x86_64 and aarch64",
                self.machine
            )
        })
    }

    /// What stops an Arc node here, if anything.
    pub(crate) fn refusals(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.sudo {
            out.push("the login user cannot run sudo without a password".to_owned());
        }
        if self.systemd != SUPPORTED_SYSTEMD {
            out.push(format!(
                "systemd {} is outside the qualified original Arc profile (Ubuntu 24.04 / systemd {SUPPORTED_SYSTEMD})",
                self.systemd
            ));
        }
        if self.mem_kb < MIN_MEMORY_KB {
            out.push(format!(
                "{} GB of memory; Arc asks for 64 GB",
                self.mem_kb / 1_000_000
            ));
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
        .run(&RemoteCommand::NodeFacts, None)
        .map_err(|e| e.to_string())?;
    Ok(Facts::parse(&String::from_utf8_lossy(&out.stdout)))
}

/// Checks an allow list: IPv4 addresses or CIDRs, without duplicates.
/// `open_ok` allows `0.0.0.0/0`, everyone.
pub(crate) fn allow_list(
    what: &str,
    items: &[String],
    open_ok: bool,
) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (addr, prefix) = match item.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (item, None),
        };
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|_| format!("{what}: {item:?} is not an IPv4 address or CIDR"))?;
        let canonical = match prefix {
            None => ip.to_string(),
            Some(p) => {
                let bits: u8 = p
                    .parse()
                    .ok()
                    .filter(|b| *b <= 32)
                    .ok_or_else(|| format!("{what}: {item:?} has no prefix length 0–32"))?;
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                if u32::from(ip) & !mask != 0 {
                    return Err(format!(
                        "{what}: {item} has host bits set; the network is {}/{bits}",
                        Ipv4Addr::from(u32::from(ip) & mask)
                    ));
                }
                if bits == 0 && !open_ok {
                    return Err(format!("{what}: 0.0.0.0/0 would admit everyone"));
                }
                if bits == 32 {
                    ip.to_string()
                } else {
                    format!("{ip}/{bits}")
                }
            }
        };
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    Ok(out)
}

/// The type flags: `None` keeps what is stored.
#[derive(Debug, Clone, Default)]
pub(crate) struct KindFlags {
    /// `--type`.
    pub(crate) rpc_type: Option<String>,
    /// `--debug-api`.
    pub(crate) debug_api: Option<bool>,
    /// `--trusted-peers`.
    pub(crate) trusted_peers: Option<Vec<String>>,
    /// `--sentry-peers`.
    pub(crate) sentry_peers: Option<Vec<String>>,
}

/// `node` with the type the flags give, checked: the type is fixed once
/// stored (it decides what history the data holds), `debug` and `trace`
/// never go on a provider node, and only a provider node has peers, which
/// it must have.
pub(crate) fn with_kind(
    node: &RpcNode,
    stored: bool,
    flags: &KindFlags,
) -> Result<RpcNode, String> {
    let mut next = node.clone();
    let wanted = match (&flags.rpc_type, stored) {
        (Some(t), _) => t.clone(),
        (None, true) => node.rpc_type.clone(),
        (None, false) => "full".to_owned(),
    };
    let rpc_type = kind::RpcType::parse(&wanted).ok_or_else(|| {
        format!(
            "--type {wanted} is not one of {}",
            kind::RpcType::NAMES.join(", ")
        )
    })?;
    if stored && wanted != node.rpc_type {
        return Err(format!(
            "{} is a {} node; its type decides the history its data holds, so it cannot \
             become {wanted}. Destroy it with --purge-data and init it again, or init another node",
            node.name, node.rpc_type
        ));
    }
    next.rpc_type = wanted;
    if let Some(on) = flags.debug_api {
        next.debug_api = on;
    }
    if next.debug_api && !rpc_type.allows_debug_api() {
        return Err(
            "--debug-api is refused on a provider node: Arc's onboarding forbids debug and trace"
                .to_owned(),
        );
    }
    let peers = |flag: &Option<Vec<String>>, kept: &[String]| -> Vec<String> {
        let mut list: Vec<String> = flag.as_ref().map_or_else(
            || kept.to_vec(),
            |items| {
                items
                    .iter()
                    .map(|i| i.trim().to_owned())
                    .filter(|i| !i.is_empty())
                    .collect()
            },
        );
        let mut seen = std::collections::HashSet::new();
        list.retain(|i| seen.insert(i.clone()));
        list
    };
    next.trusted_peers = peers(&flags.trusted_peers, &node.trusted_peers);
    next.sentry_peers = peers(&flags.sentry_peers, &node.sentry_peers);
    if rpc_type == kind::RpcType::Provider {
        if next.trusted_peers.is_empty() || next.sentry_peers.is_empty() {
            return Err(
                "a provider node needs --trusted-peers <enode URLs> and --sentry-peers \
                 <multiaddrs>, both from Arc's onboarding"
                    .to_owned(),
            );
        }
        for enode in &next.trusted_peers {
            kind::check_enode(enode)?;
        }
        for sentry in &next.sentry_peers {
            kind::sentry_address(sentry)?;
        }
    } else if !next.trusted_peers.is_empty() || !next.sentry_peers.is_empty() {
        return Err(format!(
            "--trusted-peers and --sentry-peers are for provider nodes; a {} node follows the public relays",
            next.rpc_type
        ));
    }
    Ok(next)
}

/// The management sets: the stored list plus the address erpc connects
/// from, so a firewall erpc applies always admits erpc.
pub(crate) fn management(node: &RpcNode, controller: IpAddr) -> (Vec<String>, Vec<String>) {
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

/// A warning when SSH would be admitted from erpc's present address alone:
/// if that address changes, nothing can reach the node but its console.
pub(crate) fn lockout_warning(node_management: &[String], facts: &Facts) -> Option<String> {
    node_management.is_empty().then(|| {
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
    pub(crate) node: &'a RpcNode,
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
            return Err("the server-observed SSH destination port is missing".into());
        }
        let (v4, v6) = management(self.node, controller);
        let mut vars = Map::new();
        let mut set = |k: &str, v: Value| {
            vars.insert(k.to_owned(), v);
        };
        set("ansible_connection", json!("local"));
        set("arc_chain", json!(self.network.chain));
        set("arc_chain_id", json!(self.network.chain_id));
        set("arc_version", json!(self.node.version));
        set("arc_commit", json!(self.node.commit));
        set(
            "arc_archive_url",
            json!(releases::archive_url(&self.node.version, platform)),
        );
        set("arc_archive_sha256", json!(self.node.archive_sha256));
        set(
            "arc_follow",
            json!(
                self.network
                    .follow
                    .iter()
                    .map(erpc_chain_arc::network::Follow::flag)
                    .collect::<Vec<_>>()
            ),
        );
        set(
            "arc_relays",
            json!(
                self.network
                    .follow
                    .iter()
                    .map(|f| f.http.clone())
                    .collect::<Vec<_>>()
            ),
        );
        set("arc_rpc_type", json!(self.node.rpc_type));
        set("arc_debug_api", json!(self.node.debug_api));
        set("arc_trusted_peers", json!(self.node.trusted_peers));
        set("arc_sentry_peers", json!(self.node.sentry_peers));
        set(
            "arc_sentry_addresses",
            json!(
                self.node
                    .sentry_peers
                    .iter()
                    .map(|p| kind::sentry_address(p).map(|ip| ip.to_string()))
                    .collect::<Result<Vec<_>, _>>()?
            ),
        );
        set("arc_rpc_allow", json!(self.node.rpc_allow));
        set("arc_monitoring_allow", json!(self.node.monitoring_allow));
        set("arc_fw_management_v4", json!(v4));
        set("arc_fw_management_v6", json!(v6));
        set("arc_ssh_port", json!(self.facts.ssh_port));
        set(
            "arc_authority_loader",
            json!(erpc_chain_arc::authority::carried_loader()?),
        );
        set(
            "arc_authority_contract",
            crate::arc_authority::contract(self.node, self.network)?,
        );
        set(
            "arc_authority_helpers",
            json!(erpc_chain_arc::authority::helper_hash()?),
        );
        set(
            "arc_authority_request",
            crate::arc_authority::prepare(self.node, self.network)?,
        );
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

/// A sealed run carries the complete helper profile, templates and public inventory.
pub(crate) fn bundle(inventory_json: &str) -> Result<Built, String> {
    let mut bundle = Bundle::new();
    for path in erpc_chain_arc::files() {
        let bytes = erpc_chain_arc::file(path).ok_or_else(|| format!("{path} is not carried"))?;
        bundle
            .add(path, bytes.to_vec())
            .map_err(|e| e.to_string())?;
    }
    bundle
        .add("inventory.yml", inventory_json.as_bytes().to_vec())
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
    erpc_chain_arc::authority::qualify_source(
        &vars.node.version,
        &vars.node.commit,
        &vars.node.archive_sha256,
        vars.facts.platform()?,
    )?;
    let mut inventory = vars.inventory_json()?;
    if [erpc_chain_arc::plays::DEPLOY, erpc_chain_arc::plays::UPDATE].contains(&play) {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "could not reserve an Arc deployment intent")?;
        let intent = nonce
            .iter()
            .fold(String::with_capacity(32), |mut value, byte| {
                use std::fmt::Write as _;
                let _ = write!(value, "{byte:02x}");
                value
            });
        crate::arc_authority::invoke(
            session,
            vars.node,
            vars.network,
            "reserve",
            json!({
                "intent":intent,"target":crate::arc_authority::source(vars.node,vars.facts)?,
                "policy":crate::arc_authority::policy(vars.node,vars.facts)?
            }),
        )?;
        let mut document: Value =
            serde_json::from_str(&inventory).map_err(|_| "invalid Arc inventory")?;
        let host = document["all"]["hosts"][&vars.node.name]
            .as_object_mut()
            .ok_or("missing original Arc host")?;
        host.insert("arc_authority_intent".into(), json!(intent));
        host.insert(
            "arc_authority_contract".into(),
            crate::arc_authority::contract(vars.node, vars.network)?,
        );
        host.insert(
            "arc_authority_helpers".into(),
            json!(erpc_chain_arc::authority::helper_hash()?),
        );
        inventory = document.to_string();
        let preparation = bundle(&inventory)?;
        let prepared = erpc_ops::run::start(session, &preparation, erpc_chain_arc::plays::FIREWALL)
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
        crate::arc_authority::invoke(
            &fresh,
            vars.node,
            vars.network,
            "firewall-confirm",
            json!({
                "intent":intent,"operation":prepared.as_str(),"bundle":preparation.sha256
            }),
        )?;
        say.line("firewall   original operation confirmed over fresh SSH");
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

/// Short form of a byte count in kilobytes.
pub(crate) fn gb(kb: u64) -> String {
    format!("{} GB", kb / 1_000_000)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use erpc_chain::inventory::RpcNode;
    use serde_json::Value;

    use super::{Facts, KindFlags, RunVars, allow_list, management, with_kind};

    #[cfg(unix)]
    #[test]
    fn actual_original_entrypoints_reject_unsafe_bytes_before_interpretation() {
        use std::io::Write as _;
        let command = erpc_ssh::RemoteCommand::ArcControl(
            erpc_ssh::arc::Control::new(&erpc_chain_arc::authority::profile()).unwrap(),
        )
        .line();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-arc/tests/authority_entrypoints.py");
        let mut child = std::process::Command::new("python3")
            .args(["-B"])
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::json!({"ssh":command}).to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn a_type_is_checked_and_fixed_once_stored() {
        let new = RpcNode {
            name: "arc1".to_owned(),
            ..RpcNode::default()
        };
        let full = with_kind(&new, false, &KindFlags::default()).expect("full by default");
        assert_eq!((full.rpc_type.as_str(), full.debug_api), ("full", false));
        let archive = with_kind(
            &new,
            false,
            &KindFlags {
                rpc_type: Some("archive".to_owned()),
                debug_api: Some(true),
                ..KindFlags::default()
            },
        )
        .expect("archive with debug");
        assert!(archive.debug_api);
        let kept = with_kind(&archive, true, &KindFlags::default()).expect("kept");
        assert_eq!((kept.rpc_type.as_str(), kept.debug_api), ("archive", true));
        let moved = with_kind(
            &archive,
            true,
            &KindFlags {
                rpc_type: Some("full".to_owned()),
                ..KindFlags::default()
            },
        );
        assert!(moved.expect_err("fixed").contains("cannot"));
        assert!(
            with_kind(
                &new,
                false,
                &KindFlags {
                    rpc_type: Some("Archive".to_owned()),
                    ..KindFlags::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn a_provider_needs_its_peers_and_no_debug_api() {
        let new = RpcNode::default();
        let flags = |debug: bool, peers: bool| KindFlags {
            rpc_type: Some("provider".to_owned()),
            debug_api: Some(debug),
            trusted_peers: peers.then(|| {
                vec![
                    format!("enode://{}@192.0.2.7:30303", "ab".repeat(64)),
                    format!("enode://{}@192.0.2.7:30303", "ab".repeat(64)),
                ]
            }),
            sentry_peers: peers
                .then(|| vec!["/ip4/192.0.2.8/tcp/27000/p2p/12D3KooWabc".to_owned()]),
        };
        let provider = with_kind(&new, false, &flags(false, true)).expect("provider");
        assert_eq!(provider.trusted_peers.len(), 1, "duplicates go");
        assert!(with_kind(&new, false, &flags(true, true)).is_err());
        assert!(with_kind(&new, false, &flags(false, false)).is_err());
        let peers_on_full = KindFlags {
            rpc_type: None,
            ..flags(false, true)
        };
        assert!(with_kind(&new, false, &peers_on_full).is_err());
    }

    fn facts() -> Facts {
        Facts::parse(
            "machine=x86_64\nmem_kb=65800000\ncpus=16\ncpu_max_mhz=5000\nroot_free_kb=400000000\n\
             data_free_kb=\nsystemd=255\ntpm=no\ncontroller=203.0.113.7\nssh_port=22\nsudo=yes\n",
        )
    }

    fn node() -> RpcNode {
        RpcNode {
            id: Some("iiiiiiiiiiiiiiiiiiiiiiiiii".into()),
            host_key: "inert-original-host-key".into(),
            consensus_public_key: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into(),
            rpc_type: "full".into(),
            name: "arc1".to_owned(),
            address: "192.0.2.10".to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 22,
            version: "v0.8.1".to_owned(),
            commit: "ab09dbfd9".to_owned(),
            archive_sha256: "a".repeat(64),
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            management_allow: vec!["192.0.2.50".to_owned()],
            ..RpcNode::default()
        }
    }

    #[test]
    fn the_facts_read_and_a_small_or_old_host_is_refused() {
        let f = facts();
        assert_eq!(f.systemd, 255);
        assert_eq!(f.data_free_kb, None);
        assert_eq!(f.data_mount, "");
        assert_eq!(
            Facts::parse("data_mount=/dev/nvme0n1\n").data_mount,
            "/dev/nvme0n1"
        );
        assert!(f.refusals().is_empty(), "{:?}", f.refusals());
        let old = Facts {
            systemd: 249,
            mem_kb: 32_000_000,
            sudo: false,
            machine: "riscv64".to_owned(),
            ..f
        };
        assert_eq!(old.refusals().len(), 4);
    }

    #[test]
    fn allow_lists_are_canonical_and_refuse_what_is_not_a_network() {
        let items: Vec<String> = ["198.51.100.0/24", "203.0.113.5", "203.0.113.5/32", " "]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            allow_list("rpc", &items, false).expect("ok"),
            ["198.51.100.0/24", "203.0.113.5"]
        );
        for bad in ["198.51.100.1/24", "300.1.1.1", "10.0.0.0/33", "::1", "x"] {
            assert!(allow_list("rpc", &[bad.to_owned()], true).is_err(), "{bad}");
        }
        assert!(allow_list("ssh", &["0.0.0.0/0".to_owned()], false).is_err());
        assert_eq!(
            allow_list("rpc", &["0.0.0.0/0".to_owned()], true).expect("open"),
            ["0.0.0.0/0"]
        );
    }

    #[test]
    fn the_firewall_always_admits_the_controller() {
        let v4: IpAddr = "203.0.113.7".parse().expect("ip");
        assert_eq!(management(&node(), v4).0, ["192.0.2.50", "203.0.113.7"]);
        let v6: IpAddr = "2001:db8::7".parse().expect("ip");
        let (four, six) = management(&node(), v6);
        assert_eq!(four, ["192.0.2.50"]);
        assert_eq!(six, ["2001:db8::7"]);
    }

    #[cfg(unix)]
    #[test]
    fn actual_ansible_request_and_register_fields_match_the_original_controller() {
        use std::io::Write as _;
        let network = erpc_chain_arc::network::get("testnet").unwrap();
        let node = node();
        let facts = facts();
        let variables = RunVars {
            node: &node,
            network: &network,
            facts: &facts,
            extra: serde_json::Map::new(),
        }
        .host_vars()
        .unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-arc/tests/authority_play.py");
        let mut child = std::process::Command::new("python3")
            .arg("-B")
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::to_string(&variables).unwrap().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(path) = std::env::var_os("ERPC_ARC_PUBLIC_TEST_VARS") {
            std::fs::write(path, serde_json::to_vec(&variables).unwrap()).unwrap();
        }
    }

    #[test]
    fn the_run_inventory_has_the_node_run_locally_and_not_its_address() {
        let network = erpc_chain_arc::network::get("testnet").expect("testnet");
        let n = node();
        let f = facts();
        let vars = RunVars {
            node: &n,
            network: &network,
            facts: &f,
            extra: serde_json::Map::new(),
        };
        let text = vars.inventory_json().expect("inventory");
        assert!(!text.contains("192.0.2.10"), "{text}");
        let doc: Value = serde_json::from_str(&text).expect("JSON");
        let host = &doc["all"]["hosts"]["arc1"];
        assert_eq!(host["ansible_connection"], "local");
        assert_eq!(host["arc_chain"], "arc-testnet");
        assert_eq!(host["arc_chain_id"], 5_042_002);
        assert_eq!(host["arc_follow"].as_array().expect("follow").len(), 3);
        assert_eq!(host["arc_fw_management_v4"][1], "203.0.113.7");
        assert!(
            host["arc_archive_url"]
                .as_str()
                .expect("url")
                .ends_with("arc-node-v0.8.1-x86_64-unknown-linux-gnu.tar.gz")
        );
        let built = super::bundle(&text).expect("bundle");
        assert_eq!(built.sha256.len(), 64);
    }
}
