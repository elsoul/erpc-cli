// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain arc init`: an Arc RPC node, from a fresh Ubuntu server
//! to a host ready for `deploy`.
//!
//! Everything is checked before anything is written: the vault opens, the
//! server's host key is the one the operator confirms, the server is Ubuntu
//! with the memory, systemd and sudo an Arc node needs, original pre-mounted
//! storage is qualified, and the carried release is pinned by commit and digest.
//! Then the public host and consensus identity are reserved, their original
//! key is stored and verified, and `init.yml` runs on the node.
//!
//! The same command again picks up a run that stopped part way: what was
//! stored is found and reused, never made twice.

use std::fmt::Write as _;

use erpc_chain::inventory::RpcNode;
use erpc_chain_arc::{key, plays, releases};
use erpc_ssh::{Identity, Session, Target};
use serde_json::json;

use crate::arc_rpc::{
    Facts, KindFlags, Login, RunVars, allow_list, facts, gb, open, run_play, with_kind,
};
use crate::commands::Outcome;
use crate::error::CliError;
use crate::node_common::{Say, agent_socket, check_ubuntu, go_ahead, host_key, save_vault};

/// What `erpc r --chain arc init` was asked to do.
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
    /// The release to pin; the newest at or above the floor when not given.
    pub version: Option<String>,
    /// Who may reach RPC; `None` keeps what is stored.
    pub rpc_allow: Option<Vec<String>>,
    /// Who may reach SSH besides erpc; `None` keeps what is stored.
    pub management_allow: Option<Vec<String>>,
    /// Who may scrape metrics; `None` keeps what is stored.
    pub monitoring_allow: Option<Vec<String>>,
    /// The type, `debug` and `trace`, and a provider's peers.
    pub kind: KindFlags,
    /// How to log in.
    pub login: Login,
    /// Do not ask before writing.
    pub yes: bool,
    /// Explicit historical original-account adoption; never inferred from live NSS.
    pub migration: crate::arc_migration::Inputs,
}

/// What a finished init reports.
struct Done {
    network: String,
    node: RpcNode,
    run: String,
}

impl Done {
    fn json(&self) -> serde_json::Value {
        json!({
            "status": "ok",
            "chain": "arc",
            "network": self.network,
            "node": {
                "name": self.node.name,
                "type": self.node.rpc_type,
                "debug_api": self.node.debug_api,
                "version": self.node.version,
                "commit": self.node.commit,
                "consensus_public_key": self.node.consensus_public_key,
                "rpc_allow": self.node.rpc_allow,
                "management_allow": self.node.management_allow,
                "monitoring_allow": self.node.monitoring_allow,
            },
            "run": self.run,
        })
    }

    fn text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Arc RPC node {} ({}{}) is ready for deploy.",
            self.node.name,
            self.node.rpc_type,
            if self.node.debug_api {
                ", with debug and trace"
            } else {
                ""
            }
        );
        let _ = writeln!(
            out,
            "  release   {} @ {}",
            self.node.version,
            &self.node.commit[..self.node.commit.len().min(12)]
        );
        let _ = writeln!(
            out,
            "  key       {} (in 1Password; the node gets it encrypted)",
            self.node.consensus_public_key
        );
        let list = |l: &[String]| {
            if l.is_empty() {
                "nobody".to_owned()
            } else {
                l.join(", ")
            }
        };
        let _ = writeln!(out, "  rpc       {}", list(&self.node.rpc_allow));
        let _ = writeln!(out, "  metrics   {}", list(&self.node.monitoring_allow));
        let _ = write!(
            out,
            "Next: erpc r --chain arc deploy -n {} --name {}",
            self.network, self.node.name
        );
        out
    }
}

/// Runs `erpc r --chain arc init`.
pub async fn run(args: Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    if args.migration.enabled {
        return migrate(&args, json_out, &say);
    }
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
    existing: Option<&RpcNode>,
    others: &[RpcNode],
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
        return Err(format!("{host} is already the Arc RPC node {}", other.name));
    }
    Ok((host, args.port, args.user.clone(), None))
}

/// RPC, management and monitoring allow lists, in that order.
type AllowLists = (Vec<String>, Vec<String>, Vec<String>);

/// The allow lists the node will have: the flags where given, else what is
/// stored.
fn allow_lists(existing: Option<&RpcNode>, args: &Args) -> Result<AllowLists, String> {
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

/// The release a new node is pinned to, with its commit and digest.
async fn pin(
    wanted: Option<&str>,
    facts: &Facts,
    say: &Say,
) -> Result<(String, String, String), String> {
    let platform = facts.platform()?;
    let github = releases::Github::new().map_err(|e| e.to_string())?;
    let (release, source) = releases::pin(
        &github,
        Some(wanted.unwrap_or(erpc_chain_arc::authority::VERSION)),
        platform,
    )
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
    erpc_chain_arc::authority::qualify_source(&release.tag, &release.commit, &digest, platform)?;
    say.line(&format!(
        "release    arc-node {} @ {} ({})",
        release.tag,
        &release.commit[..12],
        platform.target()
    ));
    Ok((release.tag, release.commit, digest))
}

#[allow(clippy::too_many_lines)]
async fn init(args: &Args, say: &Say) -> Result<Done, CliError> {
    // Checked before anything is written, the consensus key above all.
    erpc_chain::inventory::check_name(&args.name).map_err(|e| e.to_string())?;
    let opened = open(&args.network, args.vault.as_deref(), say)?;
    let existing = opened.nodes.iter().find(|n| n.name == args.name).cloned();
    let others: Vec<RpcNode> = opened
        .nodes
        .iter()
        .filter(|n| n.name != args.name)
        .cloned()
        .collect();
    let (address, port, user, pinned) = server(existing.as_ref(), &others, args)?;
    let (rpc, management, monitoring) = allow_lists(existing.as_ref(), args)?;
    let kind = with_kind(
        existing.as_ref().unwrap_or(&RpcNode::default()),
        existing.is_some(),
        &args.kind,
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
        "server     {address} as {user}: {os}, {} cpus{}, {} memory, systemd {}{}",
        facts.cpus,
        if facts.cpu_max_mhz > 0 {
            format!(" up to {} MHz", facts.cpu_max_mhz)
        } else {
            String::new()
        },
        gb(facts.mem_kb),
        facts.systemd,
        if facts.tpm { ", TPM" } else { "" }
    ));
    let refusals = facts.refusals();
    if !refusals.is_empty() {
        return Err(format!(
            "this server cannot run an Arc node: {}. Nothing was changed",
            refusals.join("; ")
        )
        .into());
    }
    if rpc.iter().any(|r| r == "0.0.0.0/0") {
        say.line("rpc        open to everyone (0.0.0.0/0)");
    }

    say.line(
        "storage    using the original pre-mounted /var/lib/arc filesystem; no disk is formatted",
    );
    let (version, commit, digest) = match &existing {
        Some(node) => (
            node.version.clone(),
            node.commit.clone(),
            node.archive_sha256.clone(),
        ),
        None => pin(args.version.as_deref(), &facts, say).await?,
    };

    say.line(&format!(
        "plan       {} {} ({}) on {}: {}",
        if existing.is_some() {
            "resume"
        } else {
            "new node"
        },
        args.name,
        kind.rpc_type,
        args.network,
        if existing.is_some() {
            "the host setup"
        } else {
            "consensus key and node item into 1Password, then the host setup"
        }
    ));
    match kind.rpc_type.as_str() {
        "archive" => say.line(
            "type       archive keeps every block, so the data only grows (both layers were \
             about 250 GB when Arc last measured); watch the disk with `status`",
        ),
        "provider" => say.line(&format!(
            "type       provider: peers with {} execution and {} consensus peers from onboarding; \
             30303 opens to all, 27000 to the sentries",
            kind.trusted_peers.len(),
            kind.sentry_peers.len()
        )),
        _ => {}
    }
    if kind.debug_api {
        say.line("rpc        debug and trace too: keep --rpc-allow to your own proxies");
    }
    if let Some(warning) = crate::arc_rpc::lockout_warning(&management, &facts) {
        say.line(&warning);
    }
    go_ahead(args.yes, "nothing was written")?;

    crate::arc_authority::preflight(&session, &target, existing.as_ref(), &opened.network, say)?;
    let wanted = RpcNode {
        name: args.name.clone(),
        address: address.clone(),
        ssh_user: user.clone(),
        ssh_port: port,
        host_key: key_seen.to_openssh(),
        version,
        commit,
        archive_sha256: digest,
        consensus_public_key: existing
            .as_ref()
            .map_or_else(String::new, |v| v.consensus_public_key.clone()),
        rpc_type: kind.rpc_type,
        debug_api: kind.debug_api,
        trusted_peers: kind.trusted_peers,
        sentry_peers: kind.sentry_peers,
        rpc_allow: rpc,
        management_allow: management,
        monitoring_allow: monitoring,
        ..RpcNode::default()
    };
    erpc_chain_arc::authority::qualify_source(
        &wanted.version,
        &wanted.commit,
        &wanted.archive_sha256,
        facts.platform()?,
    )?;
    let node = crate::arc_custody::provision(
        &opened.store,
        &opened.runner,
        &opened.vault,
        &args.network,
        wanted,
        existing.as_ref(),
        key::ConsensusKey::generate,
    )?;
    say.line(&format!("inventory  {} stored", node.name));
    save_vault(&args.network, &opened.vault)?;

    let extra = serde_json::Map::new();
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
        .update_rpc_node(&RpcNode {
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

fn migrate(args: &Args, json_out: bool, say: &Say) -> Outcome {
    let result = (|| -> Result<_, CliError> {
        if args.host.is_some()
            || args.version.is_some()
            || args.kind.rpc_type.is_some()
            || args.rpc_allow.is_some()
            || args.management_allow.is_some()
            || args.monitoring_allow.is_some()
            || args.kind.debug_api.is_some()
            || args.kind.trusted_peers.is_some()
            || args.kind.sentry_peers.is_some()
        {
            return Err("Arc authority migration retains the original inventory host, source, policy and history profile".into());
        }
        let proof = crate::arc_migration::evidence(&args.migration)?;
        let opened = open(&args.network, args.vault.as_deref(), say)?;
        let node = crate::arc_rpc::find(&opened.nodes, &args.name, &args.network)?.clone();
        let target = crate::arc_rpc::target(&node, &args.login)?;
        let session = Session::open(&target).map_err(|e| e.to_string())?;
        check_ubuntu(&session)?;
        let facts = facts(&session)?;
        if !facts.refusals().is_empty() {
            return Err("original Arc host does not meet its supported operating baseline".into());
        }
        say.line("migration  qualify original account/source evidence, preserve keys and data, and leave supported legacy services retired");
        go_ahead(args.yes, "nothing was changed")?;
        let mut extra = serde_json::Map::new();
        extra.insert("arc_migration_request".into(), crate::arc_authority::request(&node,&opened.network,"migration-check",json!({
            "target":crate::arc_authority::source(&node,&facts)?,"policy":crate::arc_authority::policy(&node,&facts)?,
            "evidence":proof,"helpers":erpc_chain_arc::authority::helper_hash()?
        }))?);
        let run = run_play(
            &session,
            &target,
            &RunVars {
                node: &node,
                network: &opened.network,
                facts: &facts,
                extra,
            },
            "ansible/arc-rpc/migrate.yml",
            "Repeat the same explicit migration with its original records",
            say,
        )?;
        Ok((node, run))
    })();
    match result {
        Err(error) => Outcome::from(error),
        Ok((node, run)) => {
            if json_out {
                crate::print_json(
                    &json!({"migration":"recorded","name":node.name,"run":run,"runtime_started":false}),
                );
                Outcome::Done(String::new())
            } else {
                Outcome::Done("Original Arc authority is recorded. First migration leaves services retired; repeating a completed migration leaves runtime unchanged.".into())
            }
        }
    }
}

#[cfg(test)]
fn sample_key() -> erpc_ssh::HostKey {
    erpc_ssh::HostKey::parse(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/",
    )
    .expect("key")
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::RpcNode;

    use super::{Args, allow_lists, sample_key, server};

    fn stored() -> RpcNode {
        RpcNode {
            name: "arc1".to_owned(),
            address: "192.0.2.10".to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 2222,
            host_key: sample_key().to_openssh(),
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            ..RpcNode::default()
        }
    }

    fn args() -> Args {
        Args {
            network: "testnet".to_owned(),
            name: "arc1".to_owned(),
            user: "ubuntu".to_owned(),
            port: 22,
            ..Args::default()
        }
    }

    #[test]
    fn a_stored_node_is_resumed_where_it_is_and_a_new_one_needs_an_address() {
        let node = stored();
        let (address, port, _, pinned) = server(Some(&node), &[], &args()).expect("resume");
        assert_eq!((address.as_str(), port), ("192.0.2.10", 2222));
        assert!(pinned.is_some());
        let elsewhere = Args {
            host: Some("192.0.2.99".to_owned()),
            ..args()
        };
        assert!(server(Some(&node), &[], &elsewhere).is_err());
        assert!(server(None, &[], &args()).is_err());
        let taken = Args {
            name: "arc2".to_owned(),
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
        let replaced = Args {
            rpc_allow: Some(vec!["203.0.113.0/24".to_owned()]),
            management_allow: Some(vec!["0.0.0.0/0".to_owned()]),
            ..args()
        };
        assert!(allow_lists(Some(&node), &replaced).is_err());
        let replaced = Args {
            management_allow: None,
            ..replaced
        };
        assert_eq!(
            allow_lists(Some(&node), &replaced).expect("replaced").0,
            ["203.0.113.0/24"]
        );
    }
}
