// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain solana init`: a Solana mainnet RPC node, from a fresh
//! Ubuntu server to a host ready for `deploy`. The port of `slv rpc init`.
//!
//! Everything is checked before anything is written: the client and type go
//! together, the vault opens, the server's host key is the one the operator
//! confirms, the server is Ubuntu on `x86_64` with sudo, Jito's regions are
//! measured from it, and every release the node will build or download is
//! pinned (the client's tag and commit; the Yellowstone
//! plugin built for that agave; Old Faithful and its binary's digest).
//! Then the node's item is stored with a new `solv` password, and
//! `create_user.yml` runs on the node. The item then logs in as `solv`.
//!
//! The same command again picks up a run that stopped part way: what was
//! stored is found and reused, never made twice.

use std::fmt::Write as _;

use erpc_chain::inventory::SolanaRpc;
use erpc_chain_solana::github::{self, Github};
use erpc_chain_solana::rpc::{self, Client, RpcType};
use erpc_chain_solana::{crypt, plays, regions, versions};
use erpc_ssh::{Identity, RemoteCommand, Session, Target};
use serde_json::json;

use crate::arc_rpc::{Login, allow_list, facts, gb};
use crate::commands::Outcome;
use crate::error::CliError;
use crate::node_common::{
    Say, agent_socket, check_ubuntu, go_ahead, host_key, public_key_line, save_vault,
};
use crate::solana_rpc::{RunVars, memory_warning, open, refusals, run_play};

/// What `erpc r --chain solana init` was asked to do.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// The network.
    pub network: String,
    /// The node's name.
    pub name: String,
    /// The server's address; needed for a new node.
    pub host: Option<String>,
    /// The user that logs in before `solv` exists.
    pub user: String,
    /// The SSH port.
    pub port: u16,
    /// The host key fingerprint the operator expects, `SHA256:…`.
    pub fingerprint: Option<String>,
    /// The vault, when `keyless.toml` has none for the network.
    pub vault: Option<String>,
    /// `agave` or `jito`; `jito` for a new node when not given.
    pub client: Option<String>,
    /// `send-tx`, `index`, `grpc` or `index-grpc`.
    pub rpc_type: Option<String>,
    /// The client release to pin; the recommended one when not given.
    pub version: Option<String>,
    /// The Yellowstone release to pin; the one built for the client when
    /// not given.
    pub geyser_version: Option<String>,
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
    node: SolanaRpc,
    run: String,
}

impl Done {
    fn json(&self) -> serde_json::Value {
        json!({
            "status": "ok",
            "chain": "solana",
            "network": self.network,
            "node": {
                "name": self.node.name,
                "client": self.node.client,
                "type": self.node.rpc_type,
                "version": self.node.version,
                "commit": self.node.commit,
                "geyser_version": self.node.geyser_version,
                "of1_version": self.node.of1_version,
                "region": self.node.region,
                "rpc_allow": self.node.rpc_allow,
                "management_allow": self.node.management_allow,
                "monitoring_allow": self.node.monitoring_allow,
            },
            "run": self.run,
        })
    }

    fn text(&self) -> String {
        let mut out = String::new();
        let n = &self.node;
        let _ = writeln!(
            out,
            "Solana RPC node {} ({} {}) is ready for deploy.",
            n.name, n.client, n.rpc_type
        );
        let _ = writeln!(out, "  pins      {}", crate::solana_rpc::pins(n));
        let _ = writeln!(out, "  region    {}", n.region);
        let _ = writeln!(
            out,
            "  rpc       {}",
            crate::solana_rpc::list_or_nobody(&n.rpc_allow)
        );
        let _ = writeln!(
            out,
            "  metrics   {}",
            crate::solana_rpc::list_or_nobody(&n.monitoring_allow)
        );
        let _ = write!(
            out,
            "Next: erpc r --chain solana deploy -n {} --name {} --ssh-key <pub>",
            self.network, n.name
        );
        out
    }
}

/// Runs `erpc r --chain solana init`.
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
/// one: address, port, the user that logs in now, and the pinned host key.
fn server(
    existing: Option<&SolanaRpc>,
    others: &[SolanaRpc],
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
            "{host} is already the Solana RPC node {}",
            other.name
        ));
    }
    Ok((host, args.port, args.user.clone(), None))
}

/// RPC, management and monitoring allow lists, in that order.
type AllowLists = (Vec<String>, Vec<String>, Vec<String>);

/// The allow lists the node will have: the flags where given, else what is
/// stored.
fn allow_lists(existing: Option<&SolanaRpc>, args: &Args) -> Result<AllowLists, String> {
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

/// The releases a node of `client` and `rpc_type` is pinned to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Pins {
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) geyser_version: String,
    pub(crate) geyser_commit: String,
    pub(crate) of1_version: String,
    pub(crate) of1_sha256: String,
}

impl Pins {
    /// The node with these pins.
    pub(crate) fn apply(&self, node: &SolanaRpc) -> SolanaRpc {
        SolanaRpc {
            version: self.version.clone(),
            commit: self.commit.clone(),
            geyser_version: self.geyser_version.clone(),
            geyser_commit: self.geyser_commit.clone(),
            of1_version: self.of1_version.clone(),
            of1_sha256: self.of1_sha256.clone(),
            ..node.clone()
        }
    }

    /// A stored node's pins.
    pub(crate) fn of(node: &SolanaRpc) -> Self {
        Self {
            version: node.version.clone(),
            commit: node.commit.clone(),
            geyser_version: node.geyser_version.clone(),
            geyser_commit: node.geyser_commit.clone(),
            of1_version: node.of1_version.clone(),
            of1_sha256: node.of1_sha256.clone(),
        }
    }
}

/// What to pin.
pub(crate) struct Wanted<'a> {
    pub(crate) network: &'a str,
    pub(crate) client: Client,
    pub(crate) rpc_type: RpcType,
    /// The client's tag, when asked for.
    pub(crate) version: Option<&'a str>,
    /// The Yellowstone tag, when asked for.
    pub(crate) geyser_version: Option<&'a str>,
    /// The Old Faithful pin to keep, when there is one; a new one otherwise.
    pub(crate) of1: Option<(String, String)>,
}

/// Pins every release the node builds or downloads, from GitHub. Nothing
/// is pinned from a carried copy: a pin needs the commit, which only GitHub
/// has.
pub(crate) async fn pin(wanted: &Wanted<'_>, say: &Say) -> Result<Pins, String> {
    let gh = Github::new().map_err(|e| e.to_string())?;
    let mut pins = Pins::default();
    let name = wanted.client.as_str();
    let tag = if let Some(tag) = wanted.version {
        versions::check_floor(wanted.network, tag).map_err(|e| e.to_string())?;
        tag.to_owned()
    } else {
        let (tag, _, why) = github::recommended(&gh, name, wanted.network)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(why) = why {
            return Err(format!(
                "could not read the releases from GitHub ({why}); pinning needs the \
                 commit, which only GitHub has. Try again later"
            ));
        }
        tag
    };
    let commit = gh.commit(name, &tag).await.map_err(|e| e.to_string())?;
    say.line(&format!("client     {name} {tag} @ {}", &commit[..12]));
    pins.version = tag;
    pins.commit = commit;
    if wanted.rpc_type.geyser() {
        let published = gh
            .published(rpc::YELLOWSTONE_REPO)
            .await
            .map_err(|e| e.to_string())?;
        let release = rpc::choose_geyser(&published, &pins.version, wanted.geyser_version)
            .map_err(|e| e.to_string())?;
        let commit = gh
            .commit_in(rpc::YELLOWSTONE_REPO, &release.tag)
            .await
            .map_err(|e| e.to_string())?;
        say.line(&format!(
            "geyser     yellowstone {} @ {}",
            release.tag,
            &commit[..12]
        ));
        pins.geyser_version = release.tag.clone();
        pins.geyser_commit = commit;
    }
    if wanted.rpc_type.faithful() {
        let (tag, sha) = if let Some(kept) = &wanted.of1 {
            kept.clone()
        } else {
            let published = gh
                .published(rpc::FAITHFUL_REPO)
                .await
                .map_err(|e| e.to_string())?;
            rpc::choose_faithful(&published, None).map_err(|e| e.to_string())?
        };
        say.line(&format!(
            "history    old faithful {tag} (sha256 {})",
            &sha[..12]
        ));
        pins.of1_version = tag;
        pins.of1_sha256 = sha;
    }
    Ok(pins)
}

/// The nearest Jito region, measured from the server.
fn measure_region(session: &Session, network: &str, say: &Say) -> Result<String, String> {
    say.line("region     measuring Jito's regions from the server…");
    let latencies = regions::measure(session, network).map_err(|e| e.to_string())?;
    for l in &latencies {
        say.line(&format!(
            "           {:<10} {}",
            l.key,
            l.ms.map_or_else(|| "no reply".to_owned(), |ms| format!("{ms:.1} ms"))
        ));
    }
    let best = regions::nearest(&latencies).ok_or("no Jito region answered from the server")?;
    Ok(best.key.clone())
}

#[allow(clippy::too_many_lines)]
async fn init(args: &Args, say: &Say) -> Result<Done, CliError> {
    let opened = open(&args.network, args.vault.as_deref(), say)?;
    let existing = opened.nodes.iter().find(|n| n.name == args.name).cloned();
    let others: Vec<SolanaRpc> = opened
        .nodes
        .iter()
        .filter(|n| n.name != args.name)
        .cloned()
        .collect();
    // A stored node keeps its client and type; a new one needs --type.
    let (client_name, type_name) = match &existing {
        Some(n) => {
            for (flag, given, stored) in [
                ("--client", args.client.as_deref(), n.client.as_str()),
                ("--type", args.rpc_type.as_deref(), n.rpc_type.as_str()),
            ] {
                if let Some(given) = given
                    && given != stored
                {
                    return Err(format!(
                        "{} is stored as {stored}; {flag} {given} needs a new node (another --name), or destroy it first",
                        n.name
                    ).into());
                }
            }
            (n.client.clone(), n.rpc_type.clone())
        }
        None => (
            args.client.clone().unwrap_or_else(|| "jito".to_owned()),
            args.rpc_type
                .clone()
                .ok_or("pass --type send-tx, index, grpc or index-grpc for the new node")?,
        ),
    };
    let (client, rpc_type) =
        rpc::check_choice(&args.network, &client_name, &type_name).map_err(|e| e.to_string())?;
    let (address, port, user, pinned) = server(existing.as_ref(), &others, args)?;
    let (rpc_allow, management, monitoring) = allow_lists(existing.as_ref(), args)?;

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
    let authorized = public_key_line(&ssh_key)?;
    let socket = agent_socket(args.login.ssh_agent.as_deref())?;
    let target_for = |login_user: &str| Target {
        host: address.clone(),
        port,
        user: login_user.to_owned(),
        host_key: key_seen.clone(),
        identity: Identity::Agent {
            socket: socket.clone(),
            public_key: ssh_key.clone(),
        },
    };
    let session = Session::open(&target_for(&user)).map_err(|e| e.to_string())?;
    let os = check_ubuntu(&session)?;
    let facts = facts(&session)?;
    say.line(&format!(
        "server     {address} as {user}: {os}, {} cpus{}, {} memory",
        facts.cpus,
        if facts.cpu_max_mhz > 0 {
            format!(" up to {} MHz", facts.cpu_max_mhz)
        } else {
            String::new()
        },
        gb(facts.mem_kb),
    ));
    let refused = refusals(&facts);
    if !refused.is_empty() {
        return Err(format!(
            "this server cannot run a Solana RPC node: {}. Nothing was changed",
            refused.join("; ")
        )
        .into());
    }
    if let Some(warning) = memory_warning(&facts, rpc_type.as_str()) {
        say.line(&warning);
    }
    if rpc_allow.iter().any(|r| r == "0.0.0.0/0") {
        say.line("rpc        open to everyone (0.0.0.0/0)");
    }

    // A node that logs in as solv has finished init: only its allow lists
    // can change here.
    if let Some(node) = existing.as_ref().filter(|n| n.ssh_user == "solv") {
        let next = SolanaRpc {
            rpc_allow,
            management_allow: management,
            monitoring_allow: monitoring,
            ..node.clone()
        };
        let node = if &next == node {
            say.line(&format!(
                "solv       {} is set up already; nothing to do",
                node.name
            ));
            next
        } else {
            go_ahead(args.yes, "nothing was written")?;
            say.line("inventory  allow lists stored; `update-config` applies them to the node");
            opened
                .store
                .update_solana_rpc(&next)
                .map_err(|e| e.to_string())?
        };
        return Ok(Done {
            network: args.network.clone(),
            run: node.last_run.clone(),
            node,
        });
    }

    let region = match &existing {
        Some(n) if !n.region.is_empty() => n.region.clone(),
        _ => measure_region(&session, &args.network, say)?,
    };
    let pins = match &existing {
        Some(n) => Pins::of(n),
        None => {
            pin(
                &Wanted {
                    network: &args.network,
                    client,
                    rpc_type,
                    version: args.version.as_deref(),
                    geyser_version: args.geyser_version.as_deref(),
                    of1: None,
                },
                say,
            )
            .await?
        }
    };

    say.line(&format!(
        "plan       {} {} on {}: {}",
        if existing.is_some() {
            "resume"
        } else {
            "new node"
        },
        args.name,
        args.network,
        if existing.is_some() {
            "stored already; the solv user"
        } else {
            "the node's item into 1Password, then the solv user"
        }
    ));
    let probe = SolanaRpc {
        management_allow: management.clone(),
        ..SolanaRpc::default()
    };
    if let Some(warning) = crate::solana_rpc::lockout_warning(&probe, &facts) {
        say.line(&warning);
    }
    go_ahead(args.yes, "nothing was written")?;

    let (node, password) = if let Some(stored) = existing {
        let password = opened
            .store
            .rpc_solv_password(&stored)
            .map_err(|e| e.to_string())?;
        let next = SolanaRpc {
            rpc_allow,
            management_allow: management,
            monitoring_allow: monitoring,
            ..stored.clone()
        };
        let stored = if next == stored {
            stored
        } else {
            opened
                .store
                .update_solana_rpc(&next)
                .map_err(|e| e.to_string())?
        };
        (stored, password)
    } else {
        let password = crypt::new_password().map_err(|e| e.to_string())?;
        let wanted = pins.apply(&SolanaRpc {
            name: args.name.clone(),
            address: address.clone(),
            ssh_user: user.clone(),
            ssh_port: port,
            host_key: key_seen.to_openssh(),
            client: client.as_str().to_owned(),
            rpc_type: rpc_type.as_str().to_owned(),
            region,
            rpc_allow,
            management_allow: management,
            monitoring_allow: monitoring,
            ..SolanaRpc::default()
        });
        let stored = opened
            .store
            .add_solana_rpc(&wanted, &password)
            .map_err(|e| e.to_string())?;
        (stored, password)
    };
    say.line(&format!("inventory  {} stored", node.name));
    save_vault(&args.network, &opened.vault)?;

    let hash = crypt::hash_password(&password).map_err(|e| e.to_string())?;
    let pwd = json!({ "encrypted_password": hash }).to_string();
    let vars = RunVars {
        network: &args.network,
        node: &node,
        facts: &facts,
        authorized: &authorized,
        extra: serde_json::Map::new(),
    };
    say.line("solv       creating the user on the server…");
    let run = run_play(
        &session,
        &target_for(&user),
        &vars,
        plays::CREATE_USER,
        &[("vars/config.pwd.yml", pwd)],
        "Run the same init again to see how it ended",
        say,
    )?;
    drop(session);

    // The server answers as solv with the operator's key: from now on the
    // node logs in as solv.
    let solv = Session::open(&target_for("solv")).map_err(|e| e.to_string())?;
    solv.run(&RemoteCommand::Uname, None)
        .map_err(|e| format!("solv was made but does not log in: {e}"))?;
    let node = opened
        .store
        .update_solana_rpc(&SolanaRpc {
            ssh_user: "solv".to_owned(),
            last_run: run.clone(),
            last_result: "init ok".to_owned(),
            ..node
        })
        .map_err(|e| e.to_string())?;
    say.line(&format!("solv       logs in to {}", node.name));
    Ok(Done {
        network: args.network.clone(),
        node,
        run,
    })
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::SolanaRpc;

    use super::{Args, Pins, allow_lists, server};

    fn stored() -> SolanaRpc {
        SolanaRpc {
            name: "rpc1".to_owned(),
            address: "192.0.2.10".to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 2222,
            host_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/"
                    .to_owned(),
            client: "jito".to_owned(),
            rpc_type: "index".to_owned(),
            version: "v4.3.2-jito".to_owned(),
            commit: "a".repeat(40),
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            ..SolanaRpc::default()
        }
    }

    fn args() -> Args {
        Args {
            network: "mainnet".to_owned(),
            name: "rpc1".to_owned(),
            user: "ubuntu".to_owned(),
            port: 22,
            ..Args::default()
        }
    }

    #[test]
    fn a_stored_node_is_resumed_where_it_is_and_a_new_one_needs_an_address() {
        let node = stored();
        let (address, port, user, pinned) = server(Some(&node), &[], &args()).expect("resume");
        assert_eq!(
            (address.as_str(), port, user.as_str()),
            ("192.0.2.10", 2222, "ubuntu")
        );
        assert!(pinned.is_some());
        let elsewhere = Args {
            host: Some("192.0.2.99".to_owned()),
            ..args()
        };
        assert!(server(Some(&node), &[], &elsewhere).is_err());
        assert!(server(None, &[], &args()).is_err());
        let taken = Args {
            name: "rpc2".to_owned(),
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
    }

    #[test]
    fn pins_round_trip_through_a_node() {
        let node = stored();
        let pins = Pins::of(&node);
        assert_eq!(pins.apply(&SolanaRpc::default()).version, "v4.3.2-jito");
        assert_eq!(pins.apply(&node), node);
    }
}
