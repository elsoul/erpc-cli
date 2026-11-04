// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc v init`: a validator and its first host, or a spare host for one.
//!
//! Everything is checked before anything is written: the vault opens, the
//! server's host key is the one the operator confirms, the server is
//! Ubuntu, Jito's regions are measured from it, and a client release is
//! chosen and its commit read. Then the identity (a new validator only),
//! the validator item and the host item are stored, and the server gets
//! its `solv` user through the carried `create_user.yml`, run on the node.
//! The host item then logs in as `solv`.
//!
//! A run that stops part way is picked up by running the same command
//! again: what was stored is found and reused, never made twice.

use std::fmt::Write as _;
use std::path::PathBuf;

use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Host, Inventory, Role, Store, Validator};
use erpc_chain_solana::{crypt, github, identity, plays, regions, vars, versions};
use erpc_ops::bundle::{Built, Bundle};
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use secrecy::SecretString;
use serde_json::json;

use crate::commands::Outcome;
use crate::error::CliError;
use crate::node_common::{
    Say, agent_socket, check_ubuntu, host_key, op_runner, public_key_line, save_vault, store,
    vault_for,
};

/// What `erpc v init` was asked to do.
#[derive(Debug, Clone)]
pub struct Args {
    /// The network.
    pub network: String,
    /// The validator's name.
    pub name: String,
    /// The server's address; needed for a new host.
    pub host: Option<String>,
    /// The user that logs in before `solv` exists.
    pub user: String,
    /// The SSH port.
    pub port: u16,
    /// Add a spare host to an existing validator.
    pub spare: bool,
    /// The `.pub` file of the operator's key, authorized for `solv` too.
    pub ssh_key: Option<PathBuf>,
    /// The SSH agent holding that key.
    pub ssh_agent: Option<PathBuf>,
    /// The host key fingerprint the operator expects, `SHA256:…`.
    pub fingerprint: Option<String>,
    /// The vault, when `keyless.toml` has none for the network.
    pub vault: Option<String>,
    /// `agave` or `jito`.
    pub client: String,
    /// Do not ask before writing.
    pub yes: bool,
    /// Where the identity comes from; made new when not given.
    pub identity: Option<String>,
    /// Where the vote account's key comes from; made new when not given.
    pub vote_account: Option<String>,
    /// Where the withdraw authority comes from; made new when not given.
    pub authority: Option<String>,
    /// The host key fingerprint of a machine a key is read from.
    pub source_fingerprint: Option<String>,
}

/// The networks `erpc v init` sets validators up on.
const NETWORKS: [&str; 2] = ["testnet", "mainnet"];
/// The clients it pins.
const CLIENTS: [&str; 4] = versions::CLIENTS;

/// Runs `erpc v init`.
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

/// What a finished init reports.
struct Done {
    network: String,
    validator: Validator,
    host: Host,
    run: String,
}

impl Done {
    fn json(&self) -> serde_json::Value {
        json!({
            "status": "ok",
            "network": self.network,
            "validator": {
                "name": self.validator.name,
                "identity": self.validator.identity_account,
                "client": self.validator.client,
                "version": self.validator.version,
                "commit": self.validator.commit,
            },
            "host": {
                "name": self.host.name,
                "role": self.host.role.map(Role::as_str),
                "ssh_user": self.host.ssh_user,
                "region": self.host.jito.region,
                "latency_ms": self.host.jito.latency_ms,
            },
            "run": self.run,
        })
    }

    fn text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} {} ({}) is ready for deploy.",
            self.host.role.map_or("host", Role::as_str),
            self.host.name,
            self.validator.name
        );
        let _ = writeln!(
            out,
            "  identity {}  (unstaked on the node; the key stays in 1Password)",
            self.validator.identity_account
        );
        let _ = writeln!(
            out,
            "  client   {} {} @ {}",
            self.validator.client,
            self.validator.version,
            &self.validator.commit[..self.validator.commit.len().min(12)]
        );
        let _ = writeln!(
            out,
            "  jito     {} ({} ms)",
            self.host.jito.region, self.host.jito.latency_ms
        );
        let _ = write!(
            out,
            "Next: erpc v deploy -n {} --name {}",
            self.network, self.validator.name
        );
        out
    }
}

/// Where the validator and the host stand in the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
// One value per run: boxing the items would buy nothing.
#[allow(clippy::large_enum_variant)]
enum Plan {
    /// A new validator and its primary host.
    New { host_name: String },
    /// A new spare host for an existing validator.
    Spare {
        validator: Validator,
        host_name: String,
    },
    /// Both are stored; what is left is the server.
    Resume { validator: Validator, host: Host },
}

/// Works out what to do from the inventory, refusing what does not fit.
fn plan(
    inventory: &Inventory,
    name: &str,
    address: Option<&str>,
    spare: bool,
) -> Result<Plan, String> {
    let validator = inventory.validators.iter().find(|v| v.name == name);
    let hosts = inventory.hosts_of(name);
    // A host given by address that is already this validator's: resume it.
    if let Some(address) = address
        && let Some(host) = hosts.iter().find(|h| h.address == address)
    {
        let validator =
            validator.ok_or("the inventory has a host for a validator it does not have")?;
        return Ok(Plan::Resume {
            validator: validator.clone(),
            host: (*host).clone(),
        });
    }
    if let Some(other) = address.and_then(|a| inventory.hosts.iter().find(|h| h.address == a)) {
        return Err(format!(
            "{} is already {}, a host of {}",
            other.address, other.name, other.validator
        ));
    }
    // No address: the one host that has not got `solv` yet, else the
    // validator's only host.
    if address.is_none() {
        let pending: Vec<&Host> = hosts
            .iter()
            .copied()
            .filter(|h| h.ssh_user != "solv")
            .collect();
        let one: Option<&Host> = match (pending.as_slice(), hosts.as_slice()) {
            ([host], _) | ([], [host]) => Some(host),
            _ => None,
        };
        return match (validator, one) {
            (Some(v), Some(host)) => Ok(Plan::Resume {
                validator: v.clone(),
                host: host.clone(),
            }),
            _ => Err("pass --host <address> for the server".to_owned()),
        };
    }
    let host_name = next_host_name(inventory, name);
    match (validator, spare) {
        (None, false) => Ok(Plan::New { host_name }),
        (None, true) => Err(format!(
            "there is no validator {name} to add a spare to; run `erpc v init` without --spare first"
        )),
        (Some(v), true) => Ok(Plan::Spare {
            validator: v.clone(),
            host_name,
        }),
        (Some(_), false) => Err(format!(
            "validator {name} exists; add another server to it with --spare"
        )),
    }
}

/// `<name>-1`, `<name>-2`, …: the first one the inventory does not have.
fn next_host_name(inventory: &Inventory, name: &str) -> String {
    (1..=999)
        .map(|n| format!("{name}-{n}"))
        .find(|candidate| !inventory.hosts.iter().any(|h| &h.name == candidate))
        .unwrap_or_else(|| format!("{name}-x"))
}

/// A run's bundle: every carried template, the host's inventory and the
/// vars files.
pub(crate) fn bundle(inventory_json: &str, vars_files: &[(&str, String)]) -> Result<Built, String> {
    let mut bundle = Bundle::new();
    for path in erpc_chain_solana::files() {
        let bytes =
            erpc_chain_solana::file(path).ok_or_else(|| format!("{path} is not carried"))?;
        bundle
            .add(path, bytes.to_vec())
            .map_err(|e| e.to_string())?;
    }
    bundle
        .add("inventory.yml", inventory_json.as_bytes().to_vec())
        .map_err(|e| e.to_string())?;
    // The disk rule the deploy play checks again before it wipes anything:
    // the same script erpc ran before asking the operator.
    bundle
        .add(
            "files/free-disks.sh",
            erpc_ssh::FREE_DISKS_SCRIPT.as_bytes().to_vec(),
        )
        .map_err(|e| e.to_string())?;
    for (path, text) in vars_files {
        bundle
            .add(path, text.as_bytes().to_vec())
            .map_err(|e| e.to_string())?;
    }
    bundle
        .add("rpc-firewall.py", erpc_ops::RPC_FIREWALL.to_vec())
        .map_err(|e| e.to_string())?;
    bundle.finish().map_err(|e| e.to_string())
}

/// The inventory a run on the node reads: this host, run locally.
pub(crate) fn inventory_json(
    validator: &Validator,
    host: &Host,
    solv_authorized_key: &str,
    voting: bool,
    extra: serde_json::Map<String, serde_json::Value>,
) -> String {
    let mut host_vars = vars::host_vars(validator, host, solv_authorized_key, voting);
    host_vars.insert("ansible_connection".to_owned(), json!("local"));
    host_vars.extend(extra);
    json!({ "all": { "hosts": { host.name.clone(): host_vars } } }).to_string()
}

/// The vault for the network, the store on it, and what it holds.
pub(crate) fn open_vault(
    network: &str,
    flag: Option<&str>,
    say: &Say,
) -> Result<(String, OpCli, Store<OpCli>, Inventory), String> {
    let vault = vault_for(network, flag, &format!("erpc v init -n {network}"))?;
    let runner = op_runner()?;
    let store = store(&runner, &vault, "solana", network)?;
    say.line("1Password  reading the inventory…");
    let inventory = store.load().map_err(|e| e.to_string())?;
    Ok((vault, runner, store, inventory))
}

/// Jito's regions measured from the server, and the nearest one's fields.
fn measure_jito(
    session: &Session,
    network: &str,
    say: &Say,
) -> Result<erpc_chain::inventory::Jito, String> {
    say.line("jito       measuring the regions from the server…");
    let latencies = regions::measure(session, network).map_err(|e| e.to_string())?;
    for l in &latencies {
        say.line(&format!(
            "           {:<10} {}",
            l.key,
            l.ms.map_or_else(|| "no reply".to_owned(), |ms| format!("{ms:.1} ms"))
        ));
    }
    let best = regions::nearest(&latencies).ok_or("no Jito region answered from the server")?;
    regions::jito_for(network, &best.key, best.ms, &erpc_ops::run::utc_now())
        .ok_or_else(|| "the nearest region is not in the table".to_owned())
}

/// The recommended release and the commit its tag points at, from GitHub.
async fn pin_release(client: &str, network: &str, say: &Say) -> Result<(String, String), String> {
    let gh = github::Github::new().map_err(|e| e.to_string())?;
    let (tag, _, why) = github::recommended(&gh, client, network)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(why) = why {
        return Err(format!(
            "could not read the releases from GitHub ({why}); the carried copy recommends \
             {tag}, but pinning needs its commit, which only GitHub has. Try again later"
        ));
    }
    let commit = gh.commit(client, &tag).await.map_err(|e| e.to_string())?;
    say.line(&format!("client     {client} {tag} @ {}", &commit[..12]));
    Ok((tag, commit))
}

/// The identity of a new validator: the one an earlier run stored, or a new one.
fn identity_for(
    runner: &OpCli,
    vault: &str,
    args: &Args,
    say: &Say,
) -> Result<identity::StoredIdentity, String> {
    if let Some(found) =
        identity::find(runner, vault, &args.network, &args.name).map_err(|e| e.to_string())?
    {
        say.line(&format!(
            "identity   {} (stored by an earlier run)",
            found.pubkey
        ));
        return Ok(found);
    }
    let made =
        identity::store_new(runner, vault, &args.network, &args.name).map_err(|e| e.to_string())?;
    say.line(&format!("identity   {} stored in 1Password", made.pubkey));
    Ok(made)
}

/// The server a new host item records.
struct Server {
    address: String,
    key: HostKey,
}

/// Stores what the plan needs and returns the validator, the host and the
/// host's `solv` password.
#[allow(clippy::too_many_arguments)]
fn store_items(
    plan: Plan,
    store: &Store<OpCli>,
    runner: &OpCli,
    vault: &str,
    args: &Args,
    server: &Server,
    jito: erpc_chain::inventory::Jito,
    pin: Option<(String, String)>,
    inventory: &Inventory,
    say: &Say,
) -> Result<(Validator, Host, SecretString), String> {
    let (validator, host_name, role) = match plan {
        Plan::Resume { validator, host } => {
            let password = store.solv_password(&host).map_err(|e| e.to_string())?;
            return Ok((validator, host, password));
        }
        Plan::Spare {
            validator,
            host_name,
        } => (validator, host_name, Role::Spare),
        Plan::New { host_name } => {
            let parse = |s: &Option<String>| {
                s.as_deref()
                    .map(crate::validator_keys::parse_source)
                    .transpose()
            };
            let (identity_src, vote_src, authority_src) = (
                parse(&args.identity)?,
                parse(&args.vote_account)?,
                parse(&args.authority)?,
            );
            let reach = crate::validator_keys::Reach {
                ssh_key: args.ssh_key.as_deref(),
                ssh_agent: args.ssh_agent.as_deref(),
                source_fingerprint: args.source_fingerprint.as_deref(),
                inventory,
            };
            let keys = crate::validator_keys::KeyVault {
                runner,
                vault,
                network: &args.network,
                name: &args.name,
            };
            let stored = match &identity_src {
                None | Some(crate::validator_keys::Source::New) => {
                    let s = identity_for(runner, vault, args, say)?;
                    crate::validator_keys::Obtained {
                        pubkey: s.pubkey,
                        reference: s.reference,
                    }
                }
                Some(source) => crate::validator_keys::obtain(
                    source,
                    identity::KeyRole::Identity,
                    &keys,
                    &reach,
                    say,
                )?,
            };
            let (version, commit) = pin.ok_or("no release was pinned")?;
            let validator = crate::validator_keys::fill(
                Validator {
                    name: args.name.clone(),
                    identity_account: stored.pubkey,
                    identity_ref: stored.reference,
                    client: args.client.clone(),
                    version,
                    commit,
                    region: jito.region.clone(),
                    ..Validator::default()
                },
                vote_src.as_ref(),
                authority_src.as_ref(),
                &keys,
                &reach,
                say,
            )?;
            let validator = store.add_validator(&validator).map_err(|e| e.to_string())?;
            (validator, host_name, Role::Primary)
        }
    };
    let password = crypt::new_password().map_err(|e| e.to_string())?;
    let host = store
        .add_host(
            &Host {
                name: host_name,
                validator: args.name.clone(),
                role: Some(role),
                address: server.address.clone(),
                ssh_user: args.user.clone(),
                ssh_port: args.port,
                host_key: server.key.to_openssh(),
                jito,
                ..Host::default()
            },
            &password,
        )
        .map_err(|e| e.to_string())?;
    Ok((validator, host, password))
}

/// Says what will be written and asks, unless `--yes`.
fn go_ahead(plan: &Plan, args: &Args, say: &Say) -> Result<(), CliError> {
    let (role, host_name, what) = match plan {
        Plan::New { host_name } => (
            Role::Primary,
            host_name.as_str(),
            "new identity, validator and host items, then the solv user",
        ),
        Plan::Spare { host_name, .. } => (
            Role::Spare,
            host_name.as_str(),
            "new host item, then the solv user",
        ),
        Plan::Resume { host, .. } => (
            host.role.unwrap_or(Role::Spare),
            host.name.as_str(),
            "stored already; the solv user",
        ),
    };
    say.line(&format!(
        "plan       {} {host_name} of {} on {}: {what}",
        role.as_str(),
        args.name,
        args.network,
    ));
    crate::node_common::go_ahead(args.yes, "nothing was written")
}

/// How to reach the server: the confirmed host key, the operator's key in
/// its agent, and the user that logs in now.
struct Link {
    address: String,
    port: u16,
    login_user: String,
    key: HostKey,
    socket: PathBuf,
    ssh_key: PathBuf,
    /// The operator's public key line, authorized for `solv`.
    authorized: String,
}

impl Link {
    fn target(&self, user: &str) -> Target {
        Target {
            host: self.address.clone(),
            port: self.port,
            user: user.to_owned(),
            host_key: self.key.clone(),
            identity: Identity::Agent {
                socket: self.socket.clone(),
                public_key: self.ssh_key.clone(),
            },
        }
    }
}

/// Works out how to reach the server, and confirms its host key.
fn connect(plan: &Plan, args: &Args, say: &Say) -> Result<Link, String> {
    let ssh_key = args
        .ssh_key
        .clone()
        .ok_or("pass --ssh-key <path to the .pub of the key that logs in>")?;
    let authorized = public_key_line(&ssh_key)?;
    let socket = agent_socket(args.ssh_agent.as_deref())?;
    // A stored host logs in as the user it has now: `solv` once init is done.
    let (address, port, login_user, pinned) = match plan {
        Plan::Resume { host, .. } => (
            host.address.clone(),
            host.ssh_port,
            host.ssh_user.clone(),
            Some(host.host_key.clone()),
        ),
        _ => (
            args.host.clone().ok_or("pass --host <address>")?,
            args.port,
            args.user.clone(),
            None,
        ),
    };
    erpc_ssh::config::check_host(&address).map_err(|e| e.to_string())?;
    let key = host_key(
        &address,
        port,
        pinned.as_deref(),
        args.fingerprint.as_deref(),
        say,
    )?;
    Ok(Link {
        address,
        port,
        login_user,
        key,
        socket,
        ssh_key,
        authorized,
    })
}

/// Refuses a network or client `init` does not set up.
fn check_args(args: &Args) -> Result<(), String> {
    if !NETWORKS.contains(&args.network.as_str()) {
        return Err(format!(
            "`erpc v init` sets up {} validators so far, not {}",
            NETWORKS.join(", "),
            args.network
        ));
    }
    if !CLIENTS.contains(&args.client.as_str()) {
        return Err(format!("--client is one of {}", CLIENTS.join(", ")));
    }
    Ok(())
}

async fn init(args: &Args, say: &Say) -> Result<Done, CliError> {
    check_args(args)?;
    let (vault, runner, store, inventory) = open_vault(&args.network, args.vault.as_deref(), say)?;
    let plan = plan(&inventory, &args.name, args.host.as_deref(), args.spare)?;

    let link = connect(&plan, args, say)?;
    let session = Session::open(&link.target(&link.login_user)).map_err(|e| e.to_string())?;
    let os = check_ubuntu(&session)?;
    say.line(&format!(
        "server     {} as {}: {os}",
        link.address, link.login_user
    ));

    // A host that logs in as `solv` has finished init: the login above was
    // the check, and nothing is written again.
    if let Plan::Resume { validator, host } = &plan
        && host.ssh_user == "solv"
    {
        say.line(&format!(
            "solv       {} is set up already; nothing to do",
            host.name
        ));
        return Ok(Done {
            network: args.network.clone(),
            validator: validator.clone(),
            host: host.clone(),
            run: host.last_run.clone(),
        });
    }

    let jito = match &plan {
        Plan::Resume { host, .. } if !host.jito.region.is_empty() => host.jito.clone(),
        _ => measure_jito(&session, &args.network, say)?,
    };
    let pin = if let Plan::New { .. } = plan {
        Some(pin_release(&args.client, &args.network, say).await?)
    } else {
        None
    };

    go_ahead(&plan, args, say)?;

    let server = Server {
        address: link.address.clone(),
        key: link.key.clone(),
    };
    let (validator, host, password) = store_items(
        plan, &store, &runner, &vault, args, &server, jito, pin, &inventory, say,
    )?;
    say.line(&format!(
        "inventory  {} and {} stored",
        validator.name, host.name
    ));

    save_vault(&args.network, &vault)?;

    let run = create_user(
        &session,
        &args.network,
        &validator,
        &host,
        &password,
        &link.authorized,
        say,
    )?;
    drop(session);

    // The server answers as `solv` with the operator's key: from now on the
    // host logs in as `solv`.
    let solv = Session::open(&link.target("solv")).map_err(|e| e.to_string())?;
    solv.run(&RemoteCommand::Uname, None)
        .map_err(|e| format!("solv was made but does not log in: {e}"))?;
    let host = store
        .update_host(&Host {
            ssh_user: "solv".to_owned(),
            last_run: run.clone(),
            last_result: "init ok".to_owned(),
            ..host
        })
        .map_err(|e| e.to_string())?;
    say.line(&format!("solv       logs in to {}", host.name));
    Ok(Done {
        network: args.network.clone(),
        validator,
        host,
        run,
    })
}

/// Runs the carried `create_user.yml` on the node, with the `solv`
/// password's hash, and returns the run's id.
fn create_user(
    session: &Session,
    network: &str,
    validator: &Validator,
    host: &Host,
    password: &SecretString,
    authorized: &str,
    say: &Say,
) -> Result<String, String> {
    let hash = crypt::hash_password(password).map_err(|e| e.to_string())?;
    let pwd = json!({ "encrypted_password": hash }).to_string();
    let pinned = versions::versions_yml(
        network,
        &validator.client,
        &validator.version,
        &validator.commit,
    )
    .map_err(|e| e.to_string())?;
    let built = bundle(
        &inventory_json(validator, host, authorized, false, serde_json::Map::new()),
        &[("vars/config.pwd.yml", pwd), ("vars/versions.yml", pinned)],
    )?;
    say.line("solv       creating the user on the server…");
    let run =
        erpc_ops::run::start(session, &built, plays::CREATE_USER).map_err(|e| e.to_string())?;
    let result = erpc_ops::run::follow(session, &run, &mut |line| say.line(&format!("  | {line}")))
        .map_err(|e| e.to_string())?;
    if !result.ok() {
        return Err(format!(
            "create_user failed on {} (run {}, exit {}): {}. Fix it and run the same command again",
            host.name,
            run.as_str(),
            result.exit_code,
            result.message
        ));
    }
    Ok(run.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::{Host, Inventory, Role, Validator};
    use serde_json::Value;

    use super::{Plan, bundle, inventory_json, next_host_name, plan};

    fn validator(name: &str) -> Validator {
        Validator {
            name: name.to_owned(),
            identity_account: "Ident".to_owned(),
            client: "agave".to_owned(),
            ..Validator::default()
        }
    }

    fn host(name: &str, of: &str, address: &str, user: &str) -> Host {
        Host {
            name: name.to_owned(),
            validator: of.to_owned(),
            role: Some(Role::Primary),
            address: address.to_owned(),
            ssh_user: user.to_owned(),
            ssh_port: 22,
            ..Host::default()
        }
    }

    #[test]
    fn a_new_name_makes_a_validator_and_its_first_host() {
        let empty = Inventory::default();
        assert_eq!(
            plan(&empty, "tv1", Some("192.0.2.10"), false),
            Ok(Plan::New {
                host_name: "tv1-1".to_owned()
            })
        );
        assert!(plan(&empty, "tv1", Some("192.0.2.10"), true).is_err());
        assert!(plan(&empty, "tv1", None, false).is_err());
    }

    #[test]
    fn an_existing_validator_takes_a_spare_and_refuses_a_second_primary() {
        let inv = Inventory {
            validators: vec![validator("tv1")],
            hosts: vec![host("tv1-1", "tv1", "192.0.2.10", "solv")],
        };
        assert_eq!(
            plan(&inv, "tv1", Some("192.0.2.11"), true),
            Ok(Plan::Spare {
                validator: validator("tv1"),
                host_name: "tv1-2".to_owned()
            })
        );
        assert!(plan(&inv, "tv1", Some("192.0.2.11"), false).is_err());
        // Another validator's server is refused.
        assert!(plan(&inv, "tv2", Some("192.0.2.10"), false).is_err());
        assert_eq!(next_host_name(&inv, "tv2"), "tv2-1");
    }

    #[test]
    fn a_stored_host_is_resumed_by_address_or_alone() {
        let pending = host("tv1-1", "tv1", "192.0.2.10", "ubuntu");
        let inv = Inventory {
            validators: vec![validator("tv1")],
            hosts: vec![pending.clone()],
        };
        let resumed = Plan::Resume {
            validator: validator("tv1"),
            host: pending,
        };
        assert_eq!(
            plan(&inv, "tv1", Some("192.0.2.10"), false),
            Ok(resumed.clone())
        );
        assert_eq!(plan(&inv, "tv1", None, false), Ok(resumed));
        // With two finished hosts, which one is not a guess.
        let two = Inventory {
            validators: vec![validator("tv1")],
            hosts: vec![
                host("tv1-1", "tv1", "192.0.2.10", "solv"),
                host("tv1-2", "tv1", "192.0.2.11", "solv"),
            ],
        };
        assert!(plan(&two, "tv1", None, false).is_err());
    }

    #[test]
    fn the_run_inventory_is_the_host_run_locally_with_the_key_to_authorize() {
        let text = inventory_json(
            &validator("tv1"),
            &host("tv1-1", "tv1", "192.0.2.10", "ubuntu"),
            "ssh-ed25519 AAAA op",
            false,
            serde_json::Map::new(),
        );
        let doc: Value = serde_json::from_str(&text).expect("JSON");
        let vars = &doc["all"]["hosts"]["tv1-1"];
        assert_eq!(vars["ansible_connection"], "local");
        assert_eq!(vars["solv_authorized_key"], "ssh-ed25519 AAAA op");
        assert_eq!(vars["no_voting"], true);
        // Where the node is and how to reach it stays out of the bundle.
        assert!(!text.contains("192.0.2.10"));
    }

    #[test]
    fn the_bundle_carries_the_templates_the_inventory_and_the_vars() {
        let built = bundle("{}", &[("vars/config.pwd.yml", "{}".to_owned())]).expect("bundle");
        assert_eq!(built.sha256.len(), 64);
        assert!(built.bytes.len() > 10_000);
    }
}
