// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain eth init`: an Ethereum RPC node, from a fresh Ubuntu
//! server to a host ready for `deploy`.
//!
//! Everything is checked before anything is written: the vault opens, the
//! server's host key is the one the operator confirms, the server is Ubuntu
//! 24.04 or later with the processor, memory and sudo the clients need, a
//! free disk is found for the data, and the Reth and Lighthouse releases are
//! pinned with their commits and archive digests. Then the node's item is
//! stored and `init.yml` runs on the node. No secret is made: the engine's
//! JWT is made on the node by `deploy` and never leaves it.
//!
//! The same command again picks up a run that stopped part way: what was
//! stored is found and reused, never made twice.

use std::fmt::Write as _;

use erpc_chain::inventory::EthRpc;
use erpc_chain_eth::kind::RpcType;
use erpc_chain_eth::plays;
use erpc_chain_eth::releases::{self, Client};
use erpc_ssh::{Identity, Session, Target};
use serde_json::json;

use crate::arc_rpc::{allow_list, gb};
use crate::commands::Outcome;
use crate::error::CliError;
use crate::eth_rpc::{Facts, Login, RunVars, facts, open, rpc_type, run_play};
use crate::node_common::{
    FreeDisk, Say, agent_socket, check_ubuntu, free_disks, go_ahead, host_key, save_vault,
};

/// What `erpc r --chain eth init` was asked to do.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// The network.
    pub network: String,
    /// The node's name.
    pub name: String,
    /// The server's address; needed for a new node.
    pub host: Option<String>,
    /// The sudo user erpc logs in as.
    pub user: String,
    /// The SSH port.
    pub port: u16,
    /// The host key fingerprint the operator expects, `SHA256:…`.
    pub fingerprint: Option<String>,
    /// The vault, when `keyless.toml` has none for the network.
    pub vault: Option<String>,
    /// `full` or `archive`; `full` for a new node when not given.
    pub rpc_type: Option<String>,
    /// The Reth release to pin; the newest at or above the floor when not given.
    pub reth_version: Option<String>,
    /// The Lighthouse release to pin, likewise.
    pub lighthouse_version: Option<String>,
    /// Who may reach RPC; `None` keeps what is stored.
    pub rpc_allow: Option<Vec<String>>,
    /// Who may reach SSH besides erpc; `None` keeps what is stored.
    pub management_allow: Option<Vec<String>>,
    /// Who may scrape metrics; `None` keeps what is stored.
    pub monitoring_allow: Option<Vec<String>>,
    /// How to log in.
    pub login: Login,
    /// Do not ask before writing.
    pub yes: bool,
}

/// What a finished init reports.
struct Done {
    network: String,
    node: EthRpc,
    run: String,
}

impl Done {
    fn json(&self) -> serde_json::Value {
        json!({
            "status": "ok",
            "chain": "eth",
            "network": self.network,
            "node": {
                "name": self.node.name,
                "type": self.node.rpc_type,
                "reth_version": self.node.reth_version,
                "reth_commit": self.node.reth_commit,
                "lighthouse_version": self.node.lighthouse_version,
                "lighthouse_commit": self.node.lighthouse_commit,
                "rpc_allow": self.node.rpc_allow,
                "management_allow": self.node.management_allow,
                "monitoring_allow": self.node.monitoring_allow,
            },
            "run": self.run,
        })
    }

    fn text(&self) -> String {
        let short = |c: &str| c[..c.len().min(12)].to_owned();
        let list = |l: &[String]| {
            if l.is_empty() {
                "nobody".to_owned()
            } else {
                l.join(", ")
            }
        };
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Ethereum RPC node {} ({}) is ready for deploy.",
            self.node.name, self.node.rpc_type
        );
        let _ = writeln!(
            out,
            "  reth        {} @ {}",
            self.node.reth_version,
            short(&self.node.reth_commit)
        );
        let _ = writeln!(
            out,
            "  lighthouse  {} @ {}",
            self.node.lighthouse_version,
            short(&self.node.lighthouse_commit)
        );
        let _ = writeln!(out, "  rpc         {}", list(&self.node.rpc_allow));
        let _ = writeln!(out, "  metrics     {}", list(&self.node.monitoring_allow));
        let _ = write!(
            out,
            "Next: erpc r --chain eth deploy -n {} --name {}",
            self.network, self.node.name
        );
        out
    }
}

/// Runs `erpc r --chain eth init`.
pub async fn run(args: Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    match init(&args, &say).await {
        Ok(done) => {
            if json_out {
                crate::print_json(&done.json());
                Outcome::Done(String::new())
            } else {
                Outcome::Done(done.text())
            }
        }
        Err(e) => Outcome::from(e),
    }
}

/// Where the server is and how it is reached, for a new node or a stored
/// one.
fn server(
    existing: Option<&EthRpc>,
    others: &[EthRpc],
    args: &Args,
) -> Result<(String, u16, String, Option<String>), String> {
    if let Some(node) = existing {
        if let Some(host) = &args.host
            && host != &node.address
        {
            return Err(format!(
                "{} is stored at {}, not {host}; pick another --name for another server",
                node.name, node.address
            ));
        }
        return Ok((
            node.address.clone(),
            node.ssh_port,
            node.ssh_user.clone(),
            Some(node.host_key.clone()),
        ));
    }
    let host = args
        .host
        .clone()
        .ok_or("pass --host <address> for the new node's server")?;
    if let Some(other) = others.iter().find(|n| n.address == host) {
        return Err(format!(
            "{host} is already the Ethereum RPC node {}",
            other.name
        ));
    }
    Ok((host, args.port, args.user.clone(), None))
}

/// RPC, management and monitoring allow lists, in that order.
type AllowLists = (Vec<String>, Vec<String>, Vec<String>);

/// The allow lists the node will have: the flags where given, else what is
/// stored.
fn allow_lists(existing: Option<&EthRpc>, args: &Args) -> Result<AllowLists, String> {
    let stored = existing.cloned().unwrap_or_default();
    let pick = |flag: &Option<Vec<String>>, what: &str, open_ok: bool, kept: Vec<String>| {
        flag.as_ref()
            .map_or(Ok(kept), |items| allow_list(what, items, open_ok))
    };
    Ok((
        pick(&args.rpc_allow, "--rpc-allow", true, stored.rpc_allow)?,
        pick(
            &args.management_allow,
            "--management-allow",
            false,
            stored.management_allow,
        )?,
        pick(
            &args.monitoring_allow,
            "--monitoring-allow",
            false,
            stored.monitoring_allow,
        )?,
    ))
}

/// A pin: tag, commit and archive digest.
pub(crate) type Pin = (String, String, String);

/// `client`'s release for a node on `facts`' platform, with its commit and
/// digest.
pub(crate) async fn pin(
    client: Client,
    wanted: Option<&str>,
    facts: &Facts,
    say: &Say,
) -> Result<Pin, String> {
    let platform = facts.platform()?;
    let github = releases::Github::new().map_err(|e| e.to_string())?;
    let (release, source) = releases::pin(&github, client, wanted, platform)
        .await
        .map_err(|e| e.to_string())?;
    let digest = release
        .digest(platform)
        .ok_or("the release has no digest for this platform")?
        .to_owned();
    if let releases::Source::Snapshot(why) = source {
        say.line(&format!(
            "release    GitHub could not be read ({why}); using the carried list of {}",
            releases::snapshot().read
        ));
    }
    say.line(&format!(
        "release    {} {} @ {} ({})",
        client.name(),
        release.tag,
        &release.commit[..12],
        platform.target()
    ));
    Ok((release.tag, release.commit, digest))
}

/// The disk the data goes on, if the server has a free one.
fn disk(disks: &[FreeDisk], facts: &Facts, kind: RpcType, say: &Say) -> Option<FreeDisk> {
    let want_kb = kind.min_free_gb() * 1_000_000;
    if let Some(first) = disks.first() {
        say.line(&format!(
            "disk       /dev/{} ({}) becomes /var/lib/ethereum{}{}",
            first.name,
            gb(first.bytes / 1000),
            if first.wipe {
                format!(
                    ", after removing its empty partitions ({})",
                    first.partitions
                )
            } else {
                String::new()
            },
            if first.bytes / 1000 < want_kb {
                format!(
                    " — too small for a {} node, which needs {}",
                    kind.as_str(),
                    gb(want_kb)
                )
            } else {
                String::new()
            }
        ));
        return Some(first.clone());
    }
    let free = facts.data_free_kb.unwrap_or(facts.root_free_kb);
    say.line(&format!(
        "disk       no free disk; the data goes on the root disk ({} free){}",
        gb(free),
        if free < want_kb {
            format!(
                " — a {} node needs {}; deploy stops before the snapshot",
                kind.as_str(),
                gb(want_kb)
            )
        } else {
            String::new()
        }
    ));
    None
}

#[allow(clippy::too_many_lines)]
async fn init(args: &Args, say: &Say) -> Result<Done, CliError> {
    erpc_chain::inventory::check_name(&args.name).map_err(|e| e.to_string())?;
    let opened = open(&args.network, args.vault.as_deref(), say)?;
    let existing = opened.nodes.iter().find(|n| n.name == args.name).cloned();
    let others: Vec<EthRpc> = opened
        .nodes
        .iter()
        .filter(|n| n.name != args.name)
        .cloned()
        .collect();
    let (address, port, user, pinned) = server(existing.as_ref(), &others, args)?;
    let (rpc, management, monitoring) = allow_lists(existing.as_ref(), args)?;
    let kind = rpc_type(
        existing.as_ref().unwrap_or(&EthRpc::default()),
        existing.is_some(),
        args.rpc_type.as_deref(),
    )?;

    erpc_ssh::config::check_host(&address).map_err(|e| e.to_string())?;
    let key_seen = host_key(
        &address,
        port,
        pinned.as_deref(),
        args.fingerprint.as_deref(),
        say,
    )?;
    let ssh_key = args
        .login
        .ssh_key
        .clone()
        .ok_or("pass --ssh-key <path to the .pub of the key that logs in>")?;
    let target = Target {
        host: address.clone(),
        port,
        user: user.clone(),
        host_key: key_seen.clone(),
        identity: Identity::Agent {
            socket: agent_socket(args.login.ssh_agent.as_deref())?,
            public_key: ssh_key,
        },
    };
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let os = check_ubuntu(&session)?;
    let facts = facts(&session)?;
    say.line(&format!(
        "server     {address} as {user}: {os}, {} cpus, {} memory",
        facts.cpus,
        gb(facts.mem_kb)
    ));
    let refusals = facts.refusals();
    if !refusals.is_empty() {
        return Err(format!(
            "this server cannot run an Ethereum node: {}. Nothing was changed",
            refusals.join("; ")
        )
        .into());
    }
    if rpc.iter().any(|r| r == "0.0.0.0/0") {
        say.line("rpc        open to everyone (0.0.0.0/0)");
    }

    let data_disk = disk(&free_disks(&session)?, &facts, kind, say);
    let ((reth_version, reth_commit, reth_sha256), (lh_version, lh_commit, lh_sha256)) =
        match &existing {
            Some(node) => (
                (
                    node.reth_version.clone(),
                    node.reth_commit.clone(),
                    node.reth_sha256.clone(),
                ),
                (
                    node.lighthouse_version.clone(),
                    node.lighthouse_commit.clone(),
                    node.lighthouse_sha256.clone(),
                ),
            ),
            None => (
                pin(Client::Reth, args.reth_version.as_deref(), &facts, say).await?,
                pin(
                    Client::Lighthouse,
                    args.lighthouse_version.as_deref(),
                    &facts,
                    say,
                )
                .await?,
            ),
        };

    say.line(&format!(
        "plan       {} {} ({}) on {}: the node item into 1Password, then the host setup",
        if existing.is_some() {
            "resume"
        } else {
            "new node"
        },
        args.name,
        kind.as_str(),
        args.network,
    ));
    if kind == RpcType::Archive {
        say.line(
            "type       archive keeps every block and serves debug and trace: about 3 TB on disk \
             today, growing; keep --rpc-allow to your own proxies",
        );
    }
    if let Some(warning) = crate::eth_rpc::lockout_warning(&management, &facts) {
        say.line(&warning);
    }
    go_ahead(args.yes, "nothing was written")?;

    let wanted = EthRpc {
        name: args.name.clone(),
        address: address.clone(),
        ssh_user: user.clone(),
        ssh_port: port,
        host_key: key_seen.to_openssh(),
        rpc_type: kind.as_str().to_owned(),
        reth_version,
        reth_commit,
        reth_sha256,
        lighthouse_version: lh_version,
        lighthouse_commit: lh_commit,
        lighthouse_sha256: lh_sha256,
        rpc_allow: rpc,
        management_allow: management,
        monitoring_allow: monitoring,
        ..EthRpc::default()
    };
    let node = match &existing {
        None => opened
            .store
            .add_eth_rpc(&wanted)
            .map_err(|e| e.to_string())?,
        Some(stored) => {
            let merged = EthRpc {
                id: stored.id.clone(),
                item_version: stored.item_version,
                last_run: stored.last_run.clone(),
                last_result: stored.last_result.clone(),
                ..wanted
            };
            if &merged == stored {
                merged
            } else {
                opened
                    .store
                    .update_eth_rpc(&merged)
                    .map_err(|e| e.to_string())?
            }
        }
    };
    say.line(&format!("inventory  {} stored", node.name));
    save_vault(&args.network, &opened.vault)?;

    let mut extra = serde_json::Map::new();
    extra.insert(
        "eth_disk".to_owned(),
        data_disk.map_or(
            serde_json::Value::Null,
            |d| json!({ "name": d.name, "wipe": d.wipe }),
        ),
    );
    let vars = RunVars {
        node: &node,
        network: &opened.network,
        facts: &facts,
        extra,
    };
    say.line("host       preparing the server…");
    let run = run_play(
        &session,
        &target,
        &vars,
        plays::INIT,
        "Run the same init again to see how it ended",
        say,
    )?;
    drop(session);
    let node = opened
        .store
        .update_eth_rpc(&EthRpc {
            last_run: run.clone(),
            last_result: "init ok".to_owned(),
            ..node
        })
        .map_err(|e| e.to_string())?;
    Ok(Done {
        network: args.network.clone(),
        node,
        run,
    })
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::EthRpc;

    use super::{Args, allow_lists, server};

    fn stored() -> EthRpc {
        EthRpc {
            name: "eth1".to_owned(),
            address: "192.0.2.10".to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 2222,
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            ..EthRpc::default()
        }
    }

    fn args() -> Args {
        Args {
            network: "mainnet".to_owned(),
            name: "eth1".to_owned(),
            user: "ubuntu".to_owned(),
            port: 22,
            ..Args::default()
        }
    }

    #[test]
    fn a_stored_node_is_resumed_where_it_is_and_a_new_one_needs_an_address() {
        let node = stored();
        let (address, port, _, _) = server(Some(&node), &[], &args()).expect("resume");
        assert_eq!((address.as_str(), port), ("192.0.2.10", 2222));
        let elsewhere = Args {
            host: Some("192.0.2.99".to_owned()),
            ..args()
        };
        assert!(server(Some(&node), &[], &elsewhere).is_err());
        assert!(server(None, &[], &args()).is_err());
        let taken = Args {
            name: "eth2".to_owned(),
            host: Some("192.0.2.10".to_owned()),
            ..args()
        };
        assert!(server(None, &[node], &taken).is_err());
    }

    #[test]
    fn a_flag_replaces_a_stored_list_and_no_flag_keeps_it() {
        let node = stored();
        let (rpc, mgmt, _) = allow_lists(Some(&node), &args()).expect("kept");
        assert_eq!(rpc, ["198.51.100.0/24"]);
        assert!(mgmt.is_empty());
        let open_ssh = Args {
            management_allow: Some(vec!["0.0.0.0/0".to_owned()]),
            ..args()
        };
        assert!(allow_lists(Some(&node), &open_ssh).is_err());
    }
}
