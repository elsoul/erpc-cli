// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A validator's keys: the identity, the vote account and its withdraw
//! authority, each kept in 1Password.
//!
//! A key comes from one of these, named on the command line:
//!
//! - `new`: made in memory and stored;
//! - `op://<vault>/<item>/keypair`: an item the operator already has, used
//!   where it is once its public key checks out;
//! - a file, such as SLV's `~/.slv/keys/<pubkey>.json`: read once and stored;
//!   the file is left where it is, for the operator to delete;
//! - `node:<host>:<path>`: a file on a host of the inventory, read over its
//!   pinned SSH connection, as `solv`;
//! - `ssh:<user>@<address>:<path>`: a file on another machine, read once its
//!   host key matches `--source-fingerprint`;
//! - a public key alone, for a vote account or an authority made and kept
//!   elsewhere.

use std::path::{Path, PathBuf};

use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Inventory, Store, Validator};
use erpc_chain_solana::identity::{self, KeyRole, Keypair, StoredIdentity};
use erpc_ssh::{HostKey, Identity, KeyFilePath, RemoteCommand, Session, Target};
use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::Outcome;
use crate::node_common::{Say, agent_socket, confirm};
use crate::validator_init::open_vault;

/// Where a key comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Made now.
    New,
    /// An existing 1Password item.
    Op(String),
    /// A file on this machine.
    File(PathBuf),
    /// A file on a host of the inventory.
    Node {
        /// The host's inventory name.
        host: String,
        /// The file.
        path: KeyFilePath,
    },
    /// A file on another machine.
    Remote {
        /// The login user.
        user: String,
        /// The machine.
        address: String,
        /// The file.
        path: KeyFilePath,
    },
    /// A public key only: the key is kept elsewhere.
    Pubkey(String),
}

/// Whether `text` has the shape of a base58 public key.
fn is_pubkey(text: &str) -> bool {
    (32..=44).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
}

/// Reads a source as the command line gives it.
///
/// # Errors
///
/// Returns a message naming the forms erpc takes.
pub fn parse_source(text: &str) -> Result<Source, String> {
    let text = text.trim();
    let path = |p: &str| KeyFilePath::new(p).map_err(|e| e.to_string());
    if text == "new" {
        return Ok(Source::New);
    }
    if text.starts_with("op://") {
        return Ok(Source::Op(text.to_owned()));
    }
    if let Some(rest) = text.strip_prefix("node:") {
        let (host, file) = rest
            .split_once(':')
            .ok_or("node: takes node:<host>:<path>")?;
        return Ok(Source::Node {
            host: host.to_owned(),
            path: path(file)?,
        });
    }
    if let Some(rest) = text.strip_prefix("ssh:") {
        let (login, file) = rest
            .split_once(':')
            .ok_or("ssh: takes ssh:<user>@<address>:<path>")?;
        let (user, address) = login
            .split_once('@')
            .ok_or("ssh: takes ssh:<user>@<address>:<path>")?;
        erpc_ssh::config::check_host(address).map_err(|e| e.to_string())?;
        return Ok(Source::Remote {
            user: user.to_owned(),
            address: address.to_owned(),
            path: path(file)?,
        });
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return expand_home(rest, std::env::home_dir()).map(Source::File);
    }
    if text.starts_with('/') || text.starts_with("./") {
        return Ok(Source::File(PathBuf::from(text)));
    }
    if is_pubkey(text) {
        return Ok(Source::Pubkey(text.to_owned()));
    }
    Err(format!(
        "{text:?} is not a key source: use new, op://<vault>/<item>/keypair, a file path, \
         node:<host>:<path>, ssh:<user>@<address>:<path>, or a public key"
    ))
}

/// Use the platform profile lookup (USERPROFILE on Windows), never a relative
/// fallback into the current directory when the user's home is unavailable.
fn expand_home(rest: &str, home: Option<PathBuf>) -> Result<PathBuf, String> {
    let home = home
        .filter(|p| p.is_absolute())
        .ok_or("cannot find an absolute home directory for the key file")?;
    Ok(home.join(rest))
}

/// What reading a remote key needs: the operator's key and agent, and the
/// fingerprint of a machine outside the inventory.
pub struct Reach<'a> {
    /// The `.pub` of the key that logs in.
    pub ssh_key: Option<&'a Path>,
    /// The agent socket.
    pub ssh_agent: Option<&'a Path>,
    /// The host key fingerprint of a machine outside the inventory.
    pub source_fingerprint: Option<&'a str>,
    /// The inventory, for `node:`.
    pub inventory: &'a Inventory,
}

/// Where a validator's keys are kept: the vault, and whose keys they are.
pub struct KeyVault<'a> {
    /// `op`.
    pub runner: &'a OpCli,
    /// The vault id.
    pub vault: &'a str,
    /// The network.
    pub network: &'a str,
    /// The validator.
    pub name: &'a str,
}

/// A key once it is where erpc keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obtained {
    /// The public key.
    pub pubkey: String,
    /// The `op://` reference; empty for a public key alone.
    pub reference: String,
}

impl From<StoredIdentity> for Obtained {
    fn from(s: StoredIdentity) -> Self {
        Self {
            pubkey: s.pubkey,
            reference: s.reference,
        }
    }
}

/// Puts the key `source` names where erpc keeps it: in 1Password as
/// validator `name`'s `role` key, or referenced where it already is.
///
/// # Errors
///
/// Returns a message when the source cannot be read, its key is not a
/// keypair, or 1Password refuses.
pub fn obtain(
    source: &Source,
    role: KeyRole,
    keys: &KeyVault<'_>,
    reach: &Reach<'_>,
    say: &Say,
) -> Result<Obtained, String> {
    let KeyVault {
        runner,
        vault,
        network,
        name,
    } = *keys;
    let store = |keypair: Keypair| -> Result<Obtained, String> {
        identity::store_key(runner, vault, network, name, role, &keypair)
            .map(Obtained::from)
            .map_err(|e| e.to_string())
    };
    match source {
        Source::New => {
            if let Some(found) =
                identity::find_key(runner, vault, network, name, role).map_err(|e| e.to_string())?
            {
                say.line(&format!(
                    "{:<10} {} (stored by an earlier run)",
                    role.as_str(),
                    found.pubkey
                ));
                return Ok(found.into());
            }
            let made = identity::store_new_key(runner, vault, network, name, role)
                .map_err(|e| e.to_string())?;
            say.line(&format!(
                "{:<10} {} made and stored in 1Password",
                role.as_str(),
                made.pubkey
            ));
            Ok(made.into())
        }
        Source::Op(reference) => {
            let keypair = identity::read_keypair(runner, reference).map_err(|e| e.to_string())?;
            say.line(&format!(
                "{:<10} {} (the 1Password item given)",
                role.as_str(),
                keypair.pubkey()
            ));
            Ok(Obtained {
                pubkey: keypair.pubkey(),
                reference: reference.clone(),
            })
        }
        Source::File(path) => {
            let text = Zeroizing::new(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("could not read {}: {e}", path.display()))?,
            );
            let keypair = Keypair::parse_json(&text).map_err(|e| e.to_string())?;
            let stored = store(keypair)?;
            say.line(&format!(
                "{:<10} {} read from {} and stored in 1Password; the file is still there: \
                 delete it once you have checked the item",
                role.as_str(),
                stored.pubkey,
                path.display()
            ));
            Ok(stored)
        }
        Source::Node { host, path } => {
            let keypair = read_inventory_host(host, path, reach)?;
            let stored = store(keypair)?;
            say.line(&format!(
                "{:<10} {} read from {host}:{} and stored in 1Password",
                role.as_str(),
                stored.pubkey,
                path.as_str()
            ));
            Ok(stored)
        }
        Source::Remote {
            user,
            address,
            path,
        } => {
            let keypair = read_other_machine(user, address, path, reach)?;
            let stored = store(keypair)?;
            say.line(&format!(
                "{:<10} {} read from {address}:{} and stored in 1Password",
                role.as_str(),
                stored.pubkey,
                path.as_str()
            ));
            Ok(stored)
        }
        Source::Pubkey(pubkey) => {
            if role == KeyRole::Identity {
                return Err(
                    "the identity must be a keypair erpc can reach, not a public key".to_owned(),
                );
            }
            say.line(&format!("{:<10} {pubkey} (kept elsewhere)", role.as_str()));
            Ok(Obtained {
                pubkey: pubkey.clone(),
                reference: String::new(),
            })
        }
    }
}

/// Reads a key file on a host of the inventory, over its pinned connection.
fn read_inventory_host(
    host: &str,
    path: &KeyFilePath,
    reach: &Reach<'_>,
) -> Result<Keypair, String> {
    let h = reach
        .inventory
        .hosts
        .iter()
        .find(|h| h.name == host)
        .ok_or_else(|| format!("the inventory has no host {host}"))?;
    let key = HostKey::parse(&h.host_key).map_err(|e| e.to_string())?;
    read_remote(&h.address, h.ssh_port, &h.ssh_user, key, path, reach)
}

/// Reads a key file on a machine outside the inventory, once its host key
/// matches `--source-fingerprint`.
fn read_other_machine(
    user: &str,
    address: &str,
    path: &KeyFilePath,
    reach: &Reach<'_>,
) -> Result<Keypair, String> {
    let offered = erpc_ssh::keyscan(address, 22).map_err(|e| e.to_string())?;
    let expected = reach.source_fingerprint.ok_or_else(|| {
        format!(
            "{address} offers host key {}; check it on that machine and pass \
             --source-fingerprint {}",
            offered.fingerprint(),
            offered.fingerprint()
        )
    })?;
    if expected.trim() != offered.fingerprint() {
        return Err(format!(
            "{address} offers {}, not the {expected} given; nothing was read",
            offered.fingerprint()
        ));
    }
    read_remote(address, 22, user, offered, path, reach)
}

fn read_remote(
    address: &str,
    port: u16,
    user: &str,
    host_key: HostKey,
    path: &KeyFilePath,
    reach: &Reach<'_>,
) -> Result<Keypair, String> {
    let ssh_key = reach
        .ssh_key
        .ok_or("pass --ssh-key <path to the .pub of the key that logs in>")?;
    let session = Session::open(&Target {
        host: address.to_owned(),
        port,
        user: user.to_owned(),
        host_key,
        identity: Identity::Agent {
            socket: agent_socket(reach.ssh_agent)?,
            public_key: ssh_key.to_owned(),
        },
    })
    .map_err(|e| e.to_string())?;
    let out = session
        .run(&RemoteCommand::ReadKeyFile(path.clone()), None)
        .map_err(|e| format!("could not read {}: {e}", path.as_str()))?;
    let bytes = Zeroizing::new(out.stdout);
    let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
    Keypair::parse_json(&text).map_err(|e| e.to_string())
}

/// What `erpc v keys` was asked to do.
#[derive(Debug, Clone)]
pub struct Args {
    /// The network.
    pub network: String,
    /// The validator.
    pub name: String,
    /// Where the vote account's key comes from; `new` when it has none.
    pub vote: Option<String>,
    /// Where the withdraw authority comes from; `new` when it has none.
    pub authority: Option<String>,
    /// The `.pub` of the key that logs in, for `node:` and `ssh:`.
    pub ssh_key: Option<PathBuf>,
    /// The agent.
    pub ssh_agent: Option<PathBuf>,
    /// For `ssh:`.
    pub source_fingerprint: Option<String>,
    /// Do not ask.
    pub yes: bool,
}

/// Fills in the vote and authority keys of `validator` from the sources
/// given, making new ones where it has none and nothing is given, and
/// refuses an authority that is the identity.
///
/// # Errors
///
/// Returns a message when a key cannot be obtained or the keys clash.
#[allow(clippy::too_many_arguments)]
pub fn fill(
    mut validator: Validator,
    vote: Option<&Source>,
    authority: Option<&Source>,
    keys: &KeyVault<'_>,
    reach: &Reach<'_>,
    say: &Say,
) -> Result<Validator, String> {
    let new = Source::New;
    if let Some(source) = vote.or(validator.vote_account.is_empty().then_some(&new)) {
        let got = obtain(source, KeyRole::Vote, keys, reach, say)?;
        validator.vote_account = got.pubkey;
        validator.vote_ref = got.reference;
    }
    if let Some(source) = authority.or(validator.authority_account.is_empty().then_some(&new)) {
        let got = obtain(source, KeyRole::Authority, keys, reach, say)?;
        validator.authority_account = got.pubkey;
        validator.authority_ref = got.reference;
    }
    check_distinct(&validator)?;
    Ok(validator)
}

/// The identity, the vote account and the authority are three keys.
fn check_distinct(v: &Validator) -> Result<(), String> {
    let keys = [
        ("identity", &v.identity_account),
        ("vote account", &v.vote_account),
        ("authority", &v.authority_account),
    ];
    for (i, (a, ka)) in keys.iter().enumerate() {
        for (b, kb) in &keys[i + 1..] {
            if !ka.is_empty() && ka == kb {
                return Err(format!(
                    "the {a} and the {b} are the same key, {ka}; they must differ"
                ));
            }
        }
    }
    Ok(())
}

/// Runs `erpc v keys`: shows the validator's keys and fills in the vote and
/// authority keys.
pub fn run(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    match keys(args, &say) {
        Ok(v) => {
            if json_out {
                crate::print_json(&json!({
                    "validator": v.name,
                    "identity": v.identity_account,
                    "vote_account": v.vote_account,
                    "authority": v.authority_account,
                    "vote_in_1password": !v.vote_ref.is_empty(),
                    "authority_in_1password": !v.authority_ref.is_empty(),
                }));
                return Outcome::Done(String::new());
            }
            Outcome::Done(format!(
                "{}\n  identity  {}\n  vote      {}\n  authority {}{}",
                v.name,
                v.identity_account,
                v.vote_account,
                v.authority_account,
                if v.authority_ref.is_empty() {
                    " (kept elsewhere)"
                } else {
                    ""
                }
            ))
        }
        Err(e) => Outcome::Failed(e),
    }
}

fn keys(args: &Args, say: &Say) -> Result<Validator, String> {
    let vote = args.vote.as_deref().map(parse_source).transpose()?;
    let authority = args.authority.as_deref().map(parse_source).transpose()?;
    let (vault, runner, store, inventory) = open_vault(&args.network, None, say)?;
    let validator = inventory
        .validators
        .iter()
        .find(|v| v.name == args.name)
        .cloned()
        .ok_or_else(|| {
            format!(
                "there is no validator {}; `erpc v init` makes one",
                args.name
            )
        })?;
    let missing = validator.vote_account.is_empty() || validator.authority_account.is_empty();
    if vote.is_none() && authority.is_none() && !missing {
        return Ok(validator);
    }
    if !validator.vote_account.is_empty() && vote.is_some() {
        return Err(format!(
            "{} has the vote account {} already; nothing was changed",
            validator.name, validator.vote_account
        ));
    }
    say.line(&format!(
        "plan       {}: vote {}, authority {}",
        validator.name,
        describe(vote.as_ref(), &validator.vote_account),
        describe(authority.as_ref(), &validator.authority_account)
    ));
    if !args.yes {
        if !crate::session::has_terminal() {
            return Err(
                "nothing was written: pass --yes to go ahead without a terminal".to_owned(),
            );
        }
        if !confirm("Go ahead?")? {
            return Err("nothing was written".to_owned());
        }
    }
    let reach = Reach {
        ssh_key: args.ssh_key.as_deref(),
        ssh_agent: args.ssh_agent.as_deref(),
        source_fingerprint: args.source_fingerprint.as_deref(),
        inventory: &inventory,
    };
    let name = validator.name.clone();
    let keys = KeyVault {
        runner: &runner,
        vault: &vault,
        network: &args.network,
        name: &name,
    };
    let filled = fill(
        validator,
        vote.as_ref(),
        authority.as_ref(),
        &keys,
        &reach,
        say,
    )?;
    write(&store, &filled)
}

fn describe(source: Option<&Source>, current: &str) -> String {
    match source {
        Some(Source::New) => "new".to_owned(),
        Some(Source::Op(r)) => format!("from {r}"),
        Some(Source::File(p)) => format!("from {}", p.display()),
        Some(Source::Node { host, path }) => format!("from {host}:{}", path.as_str()),
        Some(Source::Remote { address, path, .. }) => format!("from {address}:{}", path.as_str()),
        Some(Source::Pubkey(p)) => format!("{p}, kept elsewhere"),
        None if current.is_empty() => "new".to_owned(),
        None => format!("{current} (kept)"),
    }
}

fn write(store: &Store<OpCli>, v: &Validator) -> Result<Validator, String> {
    store.update_validator(v).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::Validator;

    use super::{Source, check_distinct, parse_source};

    #[test]
    fn home_expansion_uses_an_absolute_platform_profile() {
        let home = std::env::temp_dir().join("erpc-key-home-fixture");
        assert_eq!(
            super::expand_home(".slv/keys/K.json", Some(home.clone())).expect("profile"),
            home.join(".slv/keys/K.json")
        );
        assert!(super::expand_home("key.json", None).is_err());
        assert!(super::expand_home("key.json", Some("relative".into())).is_err());
    }

    #[test]
    fn each_source_form_is_read() {
        assert_eq!(parse_source("new"), Ok(Source::New));
        assert_eq!(
            parse_source("op://v/i/keypair"),
            Ok(Source::Op("op://v/i/keypair".to_owned()))
        );
        assert!(matches!(
            parse_source("/home/op/.slv/keys/K.json"),
            Ok(Source::File(_))
        ));
        assert!(
            matches!(parse_source("~/.slv/keys/K.json"), Ok(Source::File(p)) if p.ends_with(".slv/keys/K.json"))
        );
        assert!(matches!(
            parse_source("node:tv1-1:/home/solv/testnet-validator-keypair.json"),
            Ok(Source::Node { host, .. }) if host == "tv1-1"
        ));
        assert!(matches!(
            parse_source("ssh:solv@192.0.2.7:/home/solv/vote-account-keypair.json"),
            Ok(Source::Remote { user, address, .. }) if user == "solv" && address == "192.0.2.7"
        ));
        assert_eq!(
            parse_source("6XdQ6szHJjm1t3XbgahSS6WVEhsrs5fniZbLgfkN1QWn"),
            Ok(Source::Pubkey(
                "6XdQ6szHJjm1t3XbgahSS6WVEhsrs5fniZbLgfkN1QWn".to_owned()
            ))
        );
        for bad in [
            "",
            "node:tv1-1",
            "node:tv1-1:/etc/shadow",
            "ssh:host:/k.json",
            "key.json",
        ] {
            assert!(parse_source(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_three_keys_must_differ() {
        let v = Validator {
            identity_account: "A".to_owned(),
            vote_account: "B".to_owned(),
            authority_account: "A".to_owned(),
            ..Validator::default()
        };
        assert!(
            check_distinct(&v)
                .unwrap_err()
                .contains("identity and the authority")
        );
        let ok = Validator {
            authority_account: "C".to_owned(),
            ..v
        };
        assert!(check_distinct(&ok).is_ok());
    }
}
