// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The node inventory, kept in 1Password.
//!
//! A stolen laptop or a leaked dotfile should not hand over the network map:
//! which IPs run validators, which is the primary and which the spare. So the
//! inventory is not a file. Each logical validator is an item, each machine
//! running it is another, and they live in the network's vault next to the
//! identity they use. A command reads them into memory and keeps nothing on
//! disk.
//!
//! - **Validator item:** name, identity, vote account, client and pinned
//!   version, region, and which host is active.
//! - **Host item:** its validator, its role (primary or spare), its address,
//!   SSH user and pinned host key, the Jito endpoints measured from it, and
//!   its last run. It also holds the `solv` password as a concealed field,
//!   which is read only when a run needs it.
//! - **RPC node item** (Arc): one machine serving RPC, with its address, SSH
//!   user and pinned host key, the pinned release and its archive digest,
//!   where its consensus key is kept, who may reach it, and its last run.
//! - **Solana RPC node item**: the same kind of item in a Solana scope, with
//!   the client and RPC type, every release the node builds or downloads
//!   pinned, the node's identity once it has one, who may reach it, and the
//!   `solv` password as a concealed field, as a validator host has it.
//!
//! Items are found by tag, `erpc` and `erpc/<chain>/<network>/<kind>`, in two
//! `op` calls for the whole inventory: one listing, piped into one `item get`.
//! A write rereads the item, refuses if it changed since it was read, edits
//! it, and reads it back. 1Password has no compare-and-swap, so this narrows
//! a race between two writers rather than closing it; a local lock keeps one
//! erpc from racing itself.

#[path = "avax_inventory.rs"]
pub mod avax;
/// OP-family follower ownership records.
pub mod rollup;
pub mod sui;
pub mod tron;

use std::collections::BTreeMap;
use std::path::PathBuf;

use erpc_auth::store::one_password::OpRunner;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};

/// The format of the items. A reader refuses an item of another version
/// rather than guessing at its fields.
pub const FORMAT: &str = "1";

/// Bitcoin host ownership records.
pub mod bitcoin;
/// Ethereum validator ownership inventory.
pub mod eth_validator;
pub mod nitro;
/// The tag every inventory item carries.
pub const TAG: &str = "erpc";

/// What kind of item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A logical validator.
    Validator,
    /// A machine running one.
    Host,
    /// A machine serving RPC, on a chain whose RPC nodes stand alone.
    Rpc,
}

impl Kind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::Host => "host",
            Self::Rpc => "rpc",
        }
    }
}

/// The chain and network an inventory is for: `solana` and `testnet`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The chain, as `erpc-core` names it.
    pub chain: String,
    /// The network.
    pub network: String,
}

impl Scope {
    /// The tag of the items of `kind` in this scope.
    #[must_use]
    pub fn tag(&self, kind: Kind) -> String {
        format!("{TAG}/{}/{}/{}", self.chain, self.network, kind.as_str())
    }
}

/// A host's part in its validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Runs the identity when the validator votes.
    Primary,
    /// Kept in sync, ready to take the identity over.
    Spare,
}

impl Role {
    /// As stored.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Spare => "spare",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "primary" => Some(Self::Primary),
            "spare" => Some(Self::Spare),
            _ => None,
        }
    }
}

/// A logical validator.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Validator {
    /// The 1Password item id, once stored.
    pub id: Option<String>,
    /// The item's version when it was read, to refuse an update over a
    /// newer one.
    pub item_version: u64,
    /// Unique within its network; the inventory hostname's prefix.
    pub name: String,
    /// The identity's public key.
    pub identity_account: String,
    /// The `op://` reference of the identity keypair.
    pub identity_ref: String,
    /// Empty while the validator only syncs.
    pub vote_account: String,
    /// The `op://` reference of the vote account's keypair, when erpc holds
    /// it; empty for a vote account made elsewhere.
    pub vote_ref: String,
    /// The vote account's withdraw authority.
    pub authority_account: String,
    /// The `op://` reference of its keypair; empty when it is kept elsewhere.
    pub authority_ref: String,
    /// `agave`, `jito` or `allnodes-jito`.
    pub client: String,
    /// The pinned release tag.
    pub version: String,
    /// The commit that tag pointed at when it was pinned.
    pub commit: String,
    /// The Jito region.
    pub region: String,
    /// The name of the host that runs the identity, if any.
    pub active_host: String,
}

/// A machine running a validator.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Host {
    /// The 1Password item id, once stored.
    pub id: Option<String>,
    /// The item's version when it was read, to refuse an update over a
    /// newer one.
    pub item_version: u64,
    /// The inventory hostname, unique within the network.
    pub name: String,
    /// The validator it runs.
    pub validator: String,
    /// `primary` or `spare`.
    pub role: Option<Role>,
    /// An IP address or DNS name.
    pub address: String,
    /// The SSH user: `ubuntu` until `solv` exists, `solv` after.
    pub ssh_user: String,
    /// The SSH port.
    pub ssh_port: u16,
    /// The pinned `ssh-ed25519` host key.
    pub host_key: String,
    /// The Jito endpoints measured from this host.
    pub jito: Jito,
    /// The last run's id and result.
    pub last_run: String,
    /// The last run's result.
    pub last_result: String,
}

/// The Jito endpoints a host uses, and when they were measured.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Jito {
    /// The region's key, `ny` or `dallas`.
    pub region: String,
    /// The block engine the client sends bundles through.
    pub block_engine_url: String,
    /// The relayer the client takes transactions from.
    pub relayer_url: String,
    /// Where the client forwards shreds, `ip:port`.
    pub shred_receiver_address: String,
    /// The round trip to the region, in milliseconds, when measured.
    pub latency_ms: String,
    /// When it was measured, RFC 3339.
    pub measured_at: String,
    /// The date of the region table the measurement used.
    pub table_date: String,
}

/// A machine serving RPC (Arc).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RpcNode {
    /// The 1Password item id, once stored.
    pub id: Option<String>,
    /// The item's version when it was read, to refuse an update over a
    /// newer one.
    pub item_version: u64,
    /// Unique within its network.
    pub name: String,
    /// An IP address or DNS name.
    pub address: String,
    /// The sudo user erpc logs in as.
    pub ssh_user: String,
    /// The SSH port.
    pub ssh_port: u16,
    /// The pinned `ssh-ed25519` host key.
    pub host_key: String,
    /// The pinned release tag.
    pub version: String,
    /// The commit that tag pointed at when it was pinned.
    pub commit: String,
    /// The SHA-256 of the release archive for the node's platform.
    pub archive_sha256: String,
    /// The `op://` reference of the consensus key.
    pub consensus_key_ref: String,
    /// The consensus key's public half, to check what the node runs with.
    pub consensus_public_key: String,
    /// What kind of RPC node: `full`, `archive` or `provider`. An item
    /// without one is `full`, the only kind there was before.
    pub rpc_type: String,
    /// Whether JSON-RPC also serves `debug` and `trace`.
    pub debug_api: bool,
    /// A provider node's execution-layer peers, enode URLs from onboarding.
    pub trusted_peers: Vec<String>,
    /// A provider node's consensus-layer peers, multiaddrs from onboarding.
    pub sentry_peers: Vec<String>,
    /// Who may reach JSON-RPC and WebSocket: IPv4 addresses or CIDRs.
    pub rpc_allow: Vec<String>,
    /// Who may reach SSH, besides the machine erpc runs on.
    pub management_allow: Vec<String>,
    /// Who may scrape the metrics ports.
    pub monitoring_allow: Vec<String>,
    /// The last run's id.
    pub last_run: String,
    /// The last run's result.
    pub last_result: String,
}

/// A machine serving Solana RPC: no validator behind it, so the client, the
/// pins and the host's own fields are one item.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SolanaRpc {
    /// The 1Password item id, once stored.
    pub id: Option<String>,
    /// The item's version when it was read, to refuse an update over a
    /// newer one.
    pub item_version: u64,
    /// Unique within its network; the inventory hostname.
    pub name: String,
    /// An IP address or DNS name.
    pub address: String,
    /// The SSH user: the first login user until `solv` exists, `solv` after.
    pub ssh_user: String,
    /// The SSH port.
    pub ssh_port: u16,
    /// The pinned `ssh-ed25519` host key.
    pub host_key: String,
    /// `agave` or `jito`.
    pub client: String,
    /// `send-tx`, `index`, `grpc` or `index-grpc`.
    pub rpc_type: String,
    /// The agave or jito release tag.
    pub version: String,
    /// The commit `version` pointed at when it was pinned.
    pub commit: String,
    /// The Yellowstone gRPC plugin's tag, for the gRPC types.
    pub geyser_version: String,
    /// The commit it pointed at when it was pinned.
    pub geyser_commit: String,
    /// The Old Faithful release tag, for the Index types.
    pub of1_version: String,
    /// The SHA-256 of its Linux binary.
    pub of1_sha256: String,
    /// The nearest Jito region, measured from the host.
    pub region: String,
    /// The node's identity, made on the node; empty until deploy reads it.
    pub identity_account: String,
    /// Who may reach RPC, WebSocket, gRPC and Old Faithful.
    pub rpc_allow: Vec<String>,
    /// Who may reach SSH, besides the machine erpc runs on.
    pub management_allow: Vec<String>,
    /// Who may scrape the metrics ports.
    pub monitoring_allow: Vec<String>,
    /// The last run's id.
    pub last_run: String,
    /// The last run's result.
    pub last_result: String,
}

/// A machine serving Ethereum RPC: Reth and Lighthouse on one host, each
/// pinned by tag, commit and the SHA-256 of its release archive.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EthRpc {
    /// The 1Password item id, once stored.
    pub id: Option<String>,
    /// The item's version when it was read, to refuse an update over a
    /// newer one.
    pub item_version: u64,
    /// Unique within its network.
    pub name: String,
    /// An IP address or DNS name.
    pub address: String,
    /// The sudo user erpc logs in as.
    pub ssh_user: String,
    /// The SSH port.
    pub ssh_port: u16,
    /// The pinned `ssh-ed25519` host key.
    pub host_key: String,
    /// `full` or `archive`.
    pub rpc_type: String,
    /// The Reth release tag.
    pub reth_version: String,
    /// The commit it pointed at when it was pinned.
    pub reth_commit: String,
    /// The SHA-256 of its release archive.
    pub reth_sha256: String,
    /// The Lighthouse release tag.
    pub lighthouse_version: String,
    /// The commit it pointed at when it was pinned.
    pub lighthouse_commit: String,
    /// The SHA-256 of its release archive.
    pub lighthouse_sha256: String,
    /// Who may reach JSON-RPC and WebSocket.
    pub rpc_allow: Vec<String>,
    /// Who may reach SSH, besides the machine erpc runs on.
    pub management_allow: Vec<String>,
    /// Who may scrape the metrics ports.
    pub monitoring_allow: Vec<String>,
    /// The last run's id.
    pub last_run: String,
    /// The last run's result.
    pub last_result: String,
}

/// Everything in one scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// The validators.
    pub validators: Vec<Validator>,
    /// The hosts that run them.
    pub hosts: Vec<Host>,
}

impl Inventory {
    /// The hosts of `validator`, primary first.
    #[must_use]
    pub fn hosts_of(&self, validator: &str) -> Vec<&Host> {
        let mut hosts: Vec<&Host> = self
            .hosts
            .iter()
            .filter(|h| h.validator == validator)
            .collect();
        hosts.sort_by_key(|h| (h.role != Some(Role::Primary), h.name.clone()));
        hosts
    }
}

/// What went wrong with the inventory.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// `op` failed.
    #[error("1Password could not {operation}: {reason}")]
    Op {
        /// What was being done.
        operation: &'static str,
        /// `op`'s first line of complaint.
        reason: String,
    },
    /// `op` printed something that is not what this version reads.
    #[error("1Password's reply to {0} could not be read")]
    Unreadable(&'static str),
    /// An item is not in the format this version reads.
    #[error("the inventory item {title:?} is not one this version of erpc reads ({reason})")]
    Item {
        /// The item's title.
        title: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The name is taken, or the value cannot be stored.
    #[error("{0}")]
    Refused(String),
    /// The item changed between reading it and writing it.
    #[error(
        "the inventory item {0:?} changed while erpc was updating it; nothing was written. Run the command again"
    )]
    Changed(String),
    /// The local lock could not be taken.
    #[error("could not take the inventory lock: {0}")]
    Lock(String),
}

fn op_error(operation: &'static str, stderr: &str) -> InventoryError {
    let line = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no reason given");
    InventoryError::Op {
        operation,
        reason: line.chars().filter(|c| !c.is_control()).take(300).collect(),
    }
}

/// The inventory of one scope, in one vault.
pub struct Store<R: OpRunner> {
    runner: R,
    vault: String,
    scope: Scope,
    lock: PathBuf,
}

/// One item of `op item get --format json`.
#[derive(Deserialize)]
struct OpItem {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    version: u64,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    fields: Vec<OpField>,
}

#[derive(Deserialize)]
struct OpField {
    #[serde(default)]
    label: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    value: Option<String>,
}

impl OpItem {
    /// The plain fields. Concealed ones are left out: a listing has no use for
    /// a password, so it is not kept.
    fn plain(&self) -> BTreeMap<&str, &str> {
        self.fields
            .iter()
            .filter(|f| f.kind != "CONCEALED")
            .filter_map(|f| Some((f.label.as_str(), f.value.as_deref()?)))
            .collect()
    }
}

/// The fields of a validator, in a fixed order.
fn validator_fields(v: &Validator) -> Vec<(&'static str, String)> {
    vec![
        ("erpc_format", FORMAT.to_owned()),
        ("name", v.name.clone()),
        ("identity_account", v.identity_account.clone()),
        ("identity_ref", v.identity_ref.clone()),
        ("vote_account", v.vote_account.clone()),
        ("vote_ref", v.vote_ref.clone()),
        ("authority_account", v.authority_account.clone()),
        ("authority_ref", v.authority_ref.clone()),
        ("client", v.client.clone()),
        ("version", v.version.clone()),
        ("commit", v.commit.clone()),
        ("region", v.region.clone()),
        ("active_host", v.active_host.clone()),
    ]
}

fn host_fields(h: &Host) -> Vec<(&'static str, String)> {
    vec![
        ("erpc_format", FORMAT.to_owned()),
        ("name", h.name.clone()),
        ("validator", h.validator.clone()),
        (
            "role",
            h.role.map_or(String::new(), |r| r.as_str().to_owned()),
        ),
        ("address", h.address.clone()),
        ("ssh_user", h.ssh_user.clone()),
        ("ssh_port", h.ssh_port.to_string()),
        ("host_key", h.host_key.clone()),
        ("jito_region", h.jito.region.clone()),
        ("block_engine_url", h.jito.block_engine_url.clone()),
        ("relayer_url", h.jito.relayer_url.clone()),
        (
            "shred_receiver_address",
            h.jito.shred_receiver_address.clone(),
        ),
        ("jito_latency_ms", h.jito.latency_ms.clone()),
        ("jito_measured_at", h.jito.measured_at.clone()),
        ("jito_table_date", h.jito.table_date.clone()),
        ("last_run", h.last_run.clone()),
        ("last_result", h.last_result.clone()),
    ]
}

fn rpc_node_fields(n: &RpcNode) -> Vec<(&'static str, String)> {
    vec![
        ("erpc_format", FORMAT.to_owned()),
        ("name", n.name.clone()),
        ("address", n.address.clone()),
        ("ssh_user", n.ssh_user.clone()),
        ("ssh_port", n.ssh_port.to_string()),
        ("host_key", n.host_key.clone()),
        ("version", n.version.clone()),
        ("commit", n.commit.clone()),
        ("archive_sha256", n.archive_sha256.clone()),
        ("consensus_key_ref", n.consensus_key_ref.clone()),
        ("consensus_public_key", n.consensus_public_key.clone()),
        ("rpc_type", n.rpc_type.clone()),
        ("debug_api", n.debug_api.to_string()),
        ("trusted_peers", n.trusted_peers.join(",")),
        ("sentry_peers", n.sentry_peers.join(",")),
        ("rpc_allow", n.rpc_allow.join(",")),
        ("management_allow", n.management_allow.join(",")),
        ("monitoring_allow", n.monitoring_allow.join(",")),
        ("last_run", n.last_run.clone()),
        ("last_result", n.last_result.clone()),
    ]
}

fn solana_rpc_fields(n: &SolanaRpc) -> Vec<(&'static str, String)> {
    vec![
        ("erpc_format", FORMAT.to_owned()),
        ("name", n.name.clone()),
        ("address", n.address.clone()),
        ("ssh_user", n.ssh_user.clone()),
        ("ssh_port", n.ssh_port.to_string()),
        ("host_key", n.host_key.clone()),
        ("client", n.client.clone()),
        ("rpc_type", n.rpc_type.clone()),
        ("version", n.version.clone()),
        ("commit", n.commit.clone()),
        ("geyser_version", n.geyser_version.clone()),
        ("geyser_commit", n.geyser_commit.clone()),
        ("of1_version", n.of1_version.clone()),
        ("of1_sha256", n.of1_sha256.clone()),
        ("region", n.region.clone()),
        ("identity_account", n.identity_account.clone()),
        ("rpc_allow", n.rpc_allow.join(",")),
        ("management_allow", n.management_allow.join(",")),
        ("monitoring_allow", n.monitoring_allow.join(",")),
        ("last_run", n.last_run.clone()),
        ("last_result", n.last_result.clone()),
    ]
}

fn eth_rpc_fields(n: &EthRpc) -> Vec<(&'static str, String)> {
    vec![
        ("erpc_format", FORMAT.to_owned()),
        ("name", n.name.clone()),
        ("address", n.address.clone()),
        ("ssh_user", n.ssh_user.clone()),
        ("ssh_port", n.ssh_port.to_string()),
        ("host_key", n.host_key.clone()),
        ("rpc_type", n.rpc_type.clone()),
        ("reth_version", n.reth_version.clone()),
        ("reth_commit", n.reth_commit.clone()),
        ("reth_sha256", n.reth_sha256.clone()),
        ("lighthouse_version", n.lighthouse_version.clone()),
        ("lighthouse_commit", n.lighthouse_commit.clone()),
        ("lighthouse_sha256", n.lighthouse_sha256.clone()),
        ("rpc_allow", n.rpc_allow.join(",")),
        ("management_allow", n.management_allow.join(",")),
        ("monitoring_allow", n.monitoring_allow.join(",")),
        ("last_run", n.last_run.clone()),
        ("last_result", n.last_result.clone()),
    ]
}

/// A name the inventory accepts: letters, digits, `.`, `_` and `-`, starting
/// with a letter or digit. It becomes the inventory hostname and part of item
/// titles.
///
/// # Errors
/// The name is refused, and why.
pub fn check_name(name: &str) -> Result<(), InventoryError> {
    let ok = name.len() <= 63
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if ok {
        Ok(())
    } else {
        Err(InventoryError::Refused(format!(
            "{name:?} is not a name the inventory accepts: use letters, digits, `.`, `_` and `-`, starting with a letter or digit"
        )))
    }
}

impl<R: OpRunner> Store<R> {
    /// The inventory of `scope` in `vault`, with its local lock at `lock`.
    pub fn new(runner: R, vault: impl Into<String>, scope: Scope, lock: PathBuf) -> Self {
        Self {
            runner,
            vault: vault.into(),
            scope,
            lock,
        }
    }

    fn title(&self, kind: Kind, name: &str) -> String {
        match kind {
            Kind::Validator => format!("erpc {} {name} validator", self.scope.network),
            Kind::Host => format!("erpc {} {name} host", self.scope.network),
            Kind::Rpc => format!(
                "erpc {} {name} {}-rpc",
                self.scope.network, self.scope.chain
            ),
        }
    }

    /// Every item of `kind`: a listing by tag, piped into one `item get`.
    fn items(&self, kind: Kind) -> Result<Vec<OpItem>, InventoryError> {
        let tag = self.scope.tag(kind);
        let list = self
            .runner
            .run(
                &[
                    "item",
                    "list",
                    "--vault",
                    &self.vault,
                    "--tags",
                    &tag,
                    "--format",
                    "json",
                ],
                None,
            )
            .map_err(|e| InventoryError::Op {
                operation: "list the inventory",
                reason: e.to_string(),
            })?;
        if !list.success {
            return Err(op_error("list the inventory", &list.stderr));
        }
        let listed: Vec<Value> = serde_json::from_str(&list.stdout)
            .map_err(|_| InventoryError::Unreadable("the listing"))?;
        if listed.is_empty() {
            return Ok(Vec::new());
        }
        // The listing names each item's vault; `op item get -` reads it.
        let got = self
            .runner
            .run(
                &["item", "get", "-", "--format", "json"],
                Some(&list.stdout),
            )
            .map_err(|e| InventoryError::Op {
                operation: "read the inventory",
                reason: e.to_string(),
            })?;
        if !got.success {
            return Err(op_error("read the inventory", &got.stderr));
        }
        let items: Result<Vec<OpItem>, _> = serde_json::Deserializer::from_str(&got.stdout)
            .into_iter::<OpItem>()
            .collect();
        let items = items.map_err(|_| InventoryError::Unreadable("the items"))?;
        // A listing by tag also matches a tag's prefix in some `op`
        // versions; keep exactly the items that carry this tag.
        Ok(items
            .into_iter()
            .filter(|i| i.tags.contains(&tag))
            .collect())
    }

    /// The whole inventory of the scope.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError`] when `op` fails or an item is not in this
    /// version's format.
    pub fn load(&self) -> Result<Inventory, InventoryError> {
        let validators = self
            .items(Kind::Validator)?
            .iter()
            .map(read_validator)
            .collect::<Result<_, _>>()?;
        let hosts = self
            .items(Kind::Host)?
            .iter()
            .map(read_host)
            .collect::<Result<_, _>>()?;
        Ok(Inventory { validators, hosts })
    }

    /// The RPC nodes of the scope, in two `op` calls.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError`] when `op` fails or an item is not in this
    /// version's format.
    pub fn rpc_nodes(&self) -> Result<Vec<RpcNode>, InventoryError> {
        self.items(Kind::Rpc)?.iter().map(read_rpc_node).collect()
    }

    /// Stores a new RPC node.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Refused`] when the name or the address is
    /// taken or the name is not acceptable, and other errors when `op` fails.
    pub fn add_rpc_node(&self, node: &RpcNode) -> Result<RpcNode, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if let Some(other) = self
            .rpc_nodes()?
            .into_iter()
            .find(|n| n.name == node.name || n.address == node.address)
        {
            return Err(InventoryError::Refused(format!(
                "RPC node {:?} at {} is already in the inventory",
                other.name, other.address
            )));
        }
        let item = self.create(Kind::Rpc, &node.name, &rpc_node_fields(node), None)?;
        read_rpc_node(&item)
    }

    /// Writes the fields of a stored RPC node, as [`Store::update_host`] does.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Changed`] when the item changed meanwhile.
    pub fn update_rpc_node(&self, node: &RpcNode) -> Result<RpcNode, InventoryError> {
        let _lock = self.lock()?;
        let item = self.update(
            Kind::Rpc,
            (node.id.as_deref(), node.item_version),
            &node.name,
            &rpc_node_fields(node),
            None,
        )?;
        read_rpc_node(&item)
    }

    /// The Solana RPC nodes of the scope, in two `op` calls.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError`] when `op` fails or an item is not in this
    /// version's format.
    pub fn solana_rpcs(&self) -> Result<Vec<SolanaRpc>, InventoryError> {
        self.items(Kind::Rpc)?.iter().map(read_solana_rpc).collect()
    }

    /// Stores a new Solana RPC node, with its `solv` password.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Refused`] when the name or the address is
    /// taken or the name is not acceptable, and other errors when `op` fails.
    pub fn add_solana_rpc(
        &self,
        node: &SolanaRpc,
        solv_password: &SecretString,
    ) -> Result<SolanaRpc, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if let Some(other) = self
            .solana_rpcs()?
            .into_iter()
            .find(|n| n.name == node.name || n.address == node.address)
        {
            return Err(InventoryError::Refused(format!(
                "RPC node {:?} at {} is already in the inventory",
                other.name, other.address
            )));
        }
        let item = self.create(
            Kind::Rpc,
            &node.name,
            &solana_rpc_fields(node),
            Some(solv_password),
        )?;
        read_solana_rpc(&item)
    }

    /// Writes the fields of a stored Solana RPC node, as
    /// [`Store::update_host`] does, keeping its `solv` password.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Changed`] when the item changed meanwhile.
    pub fn update_solana_rpc(&self, node: &SolanaRpc) -> Result<SolanaRpc, InventoryError> {
        let _lock = self.lock()?;
        let password = self.rpc_solv_password(node)?;
        let item = self.update(
            Kind::Rpc,
            (node.id.as_deref(), node.item_version),
            &node.name,
            &solana_rpc_fields(node),
            Some(&password),
        )?;
        read_solana_rpc(&item)
    }

    /// The Ethereum RPC nodes of the scope, in two `op` calls.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError`] when `op` fails or an item is not in this
    /// version's format.
    pub fn eth_rpcs(&self) -> Result<Vec<EthRpc>, InventoryError> {
        self.items(Kind::Rpc)?.iter().map(read_eth_rpc).collect()
    }

    /// Stores a new Ethereum RPC node.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Refused`] when the name or the address is
    /// taken or the name is not acceptable, and other errors when `op` fails.
    pub fn add_eth_rpc(&self, node: &EthRpc) -> Result<EthRpc, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if let Some(other) = self
            .eth_rpcs()?
            .into_iter()
            .find(|n| n.name == node.name || n.address == node.address)
        {
            return Err(InventoryError::Refused(format!(
                "RPC node {:?} at {} is already in the inventory",
                other.name, other.address
            )));
        }
        let item = self.create(Kind::Rpc, &node.name, &eth_rpc_fields(node), None)?;
        read_eth_rpc(&item)
    }

    /// Writes the fields of a stored Ethereum RPC node.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Changed`] when the item changed meanwhile.
    pub fn update_eth_rpc(&self, node: &EthRpc) -> Result<EthRpc, InventoryError> {
        let _lock = self.lock()?;
        let item = self.update(
            Kind::Rpc,
            (node.id.as_deref(), node.item_version),
            &node.name,
            &eth_rpc_fields(node),
            None,
        )?;
        read_eth_rpc(&item)
    }

    /// The `solv` password of a Solana RPC node, read on its own when a run
    /// needs it.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError`] when `op` fails or the field is empty.
    pub fn rpc_solv_password(&self, node: &SolanaRpc) -> Result<SecretString, InventoryError> {
        self.read_solv_password(node.id.as_deref(), Kind::Rpc, &node.name)
    }

    /// The `solv` password of a host, read on its own when a run needs it.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError`] when `op` fails or the field is empty.
    pub fn solv_password(&self, host: &Host) -> Result<SecretString, InventoryError> {
        self.read_solv_password(host.id.as_deref(), Kind::Host, &host.name)
    }

    fn read_solv_password(
        &self,
        id: Option<&str>,
        kind: Kind,
        name: &str,
    ) -> Result<SecretString, InventoryError> {
        let id = id.ok_or_else(|| InventoryError::Refused(format!("{name} is not stored yet")))?;
        let reference = format!("op://{}/{id}/solv_password", self.vault);
        let out = self
            .runner
            .run(&["read", "--no-newline", &reference], None)
            .map_err(|e| InventoryError::Op {
                operation: "read the solv password",
                reason: e.to_string(),
            })?;
        if !out.success {
            return Err(op_error("read the solv password", &out.stderr));
        }
        if out.stdout.is_empty() {
            return Err(InventoryError::Item {
                title: self.title(kind, name),
                reason: "it has no solv password".to_owned(),
            });
        }
        Ok(SecretString::from(out.stdout))
    }

    /// Stores a new validator.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Refused`] when the name is taken or not
    /// acceptable, and other errors when `op` fails.
    pub fn add_validator(&self, validator: &Validator) -> Result<Validator, InventoryError> {
        check_name(&validator.name)?;
        let _lock = self.lock()?;
        if self
            .load()?
            .validators
            .iter()
            .any(|v| v.name == validator.name)
        {
            return Err(InventoryError::Refused(format!(
                "a {} validator named {:?} already exists",
                self.scope.network, validator.name
            )));
        }
        let item = self.create(
            Kind::Validator,
            &validator.name,
            &validator_fields(validator),
            None,
        )?;
        read_validator(&item)
    }

    /// Stores a new host, with its `solv` password.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Refused`] when the name or address is taken,
    /// its validator does not exist, or a primary already exists for it.
    pub fn add_host(
        &self,
        host: &Host,
        solv_password: &SecretString,
    ) -> Result<Host, InventoryError> {
        check_name(&host.name)?;
        let _lock = self.lock()?;
        let inventory = self.load()?;
        if !inventory
            .validators
            .iter()
            .any(|v| v.name == host.validator)
        {
            return Err(InventoryError::Refused(format!(
                "there is no validator named {:?}",
                host.validator
            )));
        }
        if let Some(other) = inventory
            .hosts
            .iter()
            .find(|h| h.name == host.name || h.address == host.address)
        {
            return Err(InventoryError::Refused(format!(
                "host {:?} at {} is already in the inventory",
                other.name, other.address
            )));
        }
        if host.role == Some(Role::Primary)
            && inventory
                .hosts_of(&host.validator)
                .iter()
                .any(|h| h.role == Some(Role::Primary))
        {
            return Err(InventoryError::Refused(format!(
                "validator {:?} already has a primary; add this host as a spare",
                host.validator
            )));
        }
        let item = self.create(
            Kind::Host,
            &host.name,
            &host_fields(host),
            Some(solv_password),
        )?;
        read_host(&item)
    }

    /// Writes the fields of a stored host, checking first that nobody else
    /// changed it since it was read, and reading it back after.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Changed`] when the item changed meanwhile.
    pub fn update_host(&self, host: &Host) -> Result<Host, InventoryError> {
        let _lock = self.lock()?;
        // An edit replaces every field, so the password goes back in with
        // the rest, on stdin like everything else.
        let password = self.solv_password(host)?;
        let item = self.update(
            Kind::Host,
            (host.id.as_deref(), host.item_version),
            &host.name,
            &host_fields(host),
            Some(&password),
        )?;
        read_host(&item)
    }

    /// As [`Store::update_host`], for a validator.
    ///
    /// # Errors
    ///
    /// As [`Store::update_host`].
    pub fn update_validator(&self, validator: &Validator) -> Result<Validator, InventoryError> {
        let _lock = self.lock()?;
        let item = self.update(
            Kind::Validator,
            (validator.id.as_deref(), validator.item_version),
            &validator.name,
            &validator_fields(validator),
            None,
        )?;
        read_validator(&item)
    }

    /// Removes a stored item, a validator's or a host's, by its id.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError`] when `op` fails.
    pub fn remove(&self, id: &str) -> Result<(), InventoryError> {
        let _lock = self.lock()?;
        let out = self
            .runner
            .run(&["item", "delete", id, "--vault", &self.vault], None)
            .map_err(|e| InventoryError::Op {
                operation: "remove the item",
                reason: e.to_string(),
            })?;
        if out.success {
            Ok(())
        } else {
            Err(op_error("remove the item", &out.stderr))
        }
    }

    fn lock(&self) -> Result<erpc_auth::lock::ExclusiveLock, InventoryError> {
        erpc_auth::lock::ExclusiveLock::acquire(&self.lock)
            .map_err(|e| InventoryError::Lock(e.to_string()))
    }

    /// The item document `op` is given on stdin.
    fn template(
        &self,
        kind: Kind,
        name: &str,
        fields: &[(&str, String)],
        password: Option<&SecretString>,
    ) -> String {
        use secrecy::ExposeSecret as _;
        let mut list: Vec<Value> = fields
            .iter()
            .map(|(label, value)| json!({ "id": label, "label": label, "type": "STRING", "value": value }))
            .collect();
        if let Some(password) = password {
            list.push(json!({
                "id": "solv_password", "label": "solv_password", "type": "CONCEALED",
                "value": password.expose_secret(),
            }));
        }
        json!({
            "title": self.title(kind, name),
            "category": "SECURE_NOTE",
            "tags": [TAG, self.scope.tag(kind)],
            "fields": list,
        })
        .to_string()
    }

    fn create(
        &self,
        kind: Kind,
        name: &str,
        fields: &[(&str, String)],
        password: Option<&SecretString>,
    ) -> Result<OpItem, InventoryError> {
        let template = self.template(kind, name, fields, password);
        let out = self
            .runner
            .run(
                &[
                    "item",
                    "create",
                    "-",
                    "--vault",
                    &self.vault,
                    "--format",
                    "json",
                ],
                Some(&template),
            )
            .map_err(|e| InventoryError::Op {
                operation: "create the item",
                reason: e.to_string(),
            })?;
        if !out.success {
            return Err(op_error("create the item", &out.stderr));
        }
        let created: OpItem = serde_json::from_str(&out.stdout)
            .map_err(|_| InventoryError::Unreadable("the new item"))?;
        // Read back and compare, as every write is.
        let back = self.get(&created.id)?;
        verify(&back, fields, &self.title(kind, name))?;
        Ok(back)
    }

    fn get(&self, id: &str) -> Result<OpItem, InventoryError> {
        let out = self
            .runner
            .run(
                &[
                    "item",
                    "get",
                    id,
                    "--vault",
                    &self.vault,
                    "--format",
                    "json",
                ],
                None,
            )
            .map_err(|e| InventoryError::Op {
                operation: "read the item",
                reason: e.to_string(),
            })?;
        if !out.success {
            return Err(op_error("read the item", &out.stderr));
        }
        serde_json::from_str(&out.stdout).map_err(|_| InventoryError::Unreadable("the item"))
    }

    /// Replaces the fields of a stored item. `read` is the item's id and the
    /// version it had when the caller read it: a newer version means someone
    /// else wrote it since, and nothing is written over that.
    fn update(
        &self,
        kind: Kind,
        read: (Option<&str>, u64),
        name: &str,
        fields: &[(&str, String)],
        password: Option<&SecretString>,
    ) -> Result<OpItem, InventoryError> {
        let title = self.title(kind, name);
        let (id, version) = read;
        let id =
            id.ok_or_else(|| InventoryError::Refused(format!("{title:?} is not stored yet")))?;
        if self.get(id)?.version != version {
            return Err(InventoryError::Changed(title));
        }
        // Everything, the address and the host key included, goes in on
        // stdin: an argument shows in a process listing.
        let template = self.template(kind, name, fields, password);
        let out = self
            .runner
            .run(
                &["item", "edit", id, "--vault", &self.vault],
                Some(&template),
            )
            .map_err(|e| InventoryError::Op {
                operation: "update the item",
                reason: e.to_string(),
            })?;
        if !out.success {
            return Err(op_error("update the item", &out.stderr));
        }
        let back = self.get(id)?;
        verify(&back, fields, &title)?;
        Ok(back)
    }
}

/// Every field reads back as written.
fn verify(item: &OpItem, fields: &[(&str, String)], title: &str) -> Result<(), InventoryError> {
    let plain = item.plain();
    for (label, value) in fields {
        if plain.get(label).copied().unwrap_or_default() != value {
            return Err(InventoryError::Item {
                title: title.to_owned(),
                reason: format!("{label} did not read back as written"),
            });
        }
    }
    Ok(())
}

fn field(plain: &BTreeMap<&str, &str>, name: &str) -> String {
    plain.get(name).copied().unwrap_or_default().to_owned()
}

fn checked(item: &OpItem) -> Result<BTreeMap<&str, &str>, InventoryError> {
    let plain = item.plain();
    match plain.get("erpc_format").copied() {
        Some(FORMAT) => Ok(plain),
        found => Err(InventoryError::Item {
            title: item.title.clone(),
            reason: format!("format {:?}, not {FORMAT}", found.unwrap_or("missing")),
        }),
    }
}

fn read_validator(item: &OpItem) -> Result<Validator, InventoryError> {
    let f = checked(item)?;
    Ok(Validator {
        id: Some(item.id.clone()),
        item_version: item.version,
        name: field(&f, "name"),
        identity_account: field(&f, "identity_account"),
        identity_ref: field(&f, "identity_ref"),
        vote_account: field(&f, "vote_account"),
        vote_ref: field(&f, "vote_ref"),
        authority_account: field(&f, "authority_account"),
        authority_ref: field(&f, "authority_ref"),
        client: field(&f, "client"),
        version: field(&f, "version"),
        commit: field(&f, "commit"),
        region: field(&f, "region"),
        active_host: field(&f, "active_host"),
    })
}

fn read_host(item: &OpItem) -> Result<Host, InventoryError> {
    let f = checked(item)?;
    let port = field(&f, "ssh_port");
    Ok(Host {
        id: Some(item.id.clone()),
        item_version: item.version,
        name: field(&f, "name"),
        validator: field(&f, "validator"),
        role: Role::parse(&field(&f, "role")),
        address: field(&f, "address"),
        ssh_user: field(&f, "ssh_user"),
        ssh_port: port.parse().map_err(|_| InventoryError::Item {
            title: item.title.clone(),
            reason: format!("ssh_port {port:?} is not a port"),
        })?,
        host_key: field(&f, "host_key"),
        jito: Jito {
            region: field(&f, "jito_region"),
            block_engine_url: field(&f, "block_engine_url"),
            relayer_url: field(&f, "relayer_url"),
            shred_receiver_address: field(&f, "shred_receiver_address"),
            latency_ms: field(&f, "jito_latency_ms"),
            measured_at: field(&f, "jito_measured_at"),
            table_date: field(&f, "jito_table_date"),
        },
        last_run: field(&f, "last_run"),
        last_result: field(&f, "last_result"),
    })
}

fn read_rpc_node(item: &OpItem) -> Result<RpcNode, InventoryError> {
    let f = checked(item)?;
    let port = field(&f, "ssh_port");
    let list = |name: &str| -> Vec<String> {
        field(&f, name)
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    };
    Ok(RpcNode {
        id: Some(item.id.clone()),
        item_version: item.version,
        name: field(&f, "name"),
        address: field(&f, "address"),
        ssh_user: field(&f, "ssh_user"),
        ssh_port: port.parse().map_err(|_| InventoryError::Item {
            title: item.title.clone(),
            reason: format!("ssh_port {port:?} is not a port"),
        })?,
        host_key: field(&f, "host_key"),
        version: field(&f, "version"),
        commit: field(&f, "commit"),
        archive_sha256: field(&f, "archive_sha256"),
        consensus_key_ref: field(&f, "consensus_key_ref"),
        consensus_public_key: field(&f, "consensus_public_key"),
        rpc_type: match field(&f, "rpc_type") {
            t if t.is_empty() => "full".to_owned(),
            t => t,
        },
        debug_api: field(&f, "debug_api") == "true",
        trusted_peers: list("trusted_peers"),
        sentry_peers: list("sentry_peers"),
        rpc_allow: list("rpc_allow"),
        management_allow: list("management_allow"),
        monitoring_allow: list("monitoring_allow"),
        last_run: field(&f, "last_run"),
        last_result: field(&f, "last_result"),
    })
}

fn read_eth_rpc(item: &OpItem) -> Result<EthRpc, InventoryError> {
    let f = checked(item)?;
    let port = field(&f, "ssh_port");
    let list = |name: &str| -> Vec<String> {
        field(&f, name)
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    };
    Ok(EthRpc {
        id: Some(item.id.clone()),
        item_version: item.version,
        name: field(&f, "name"),
        address: field(&f, "address"),
        ssh_user: field(&f, "ssh_user"),
        ssh_port: port.parse().map_err(|_| InventoryError::Item {
            title: item.title.clone(),
            reason: format!("ssh_port {port:?} is not a port"),
        })?,
        host_key: field(&f, "host_key"),
        rpc_type: field(&f, "rpc_type"),
        reth_version: field(&f, "reth_version"),
        reth_commit: field(&f, "reth_commit"),
        reth_sha256: field(&f, "reth_sha256"),
        lighthouse_version: field(&f, "lighthouse_version"),
        lighthouse_commit: field(&f, "lighthouse_commit"),
        lighthouse_sha256: field(&f, "lighthouse_sha256"),
        rpc_allow: list("rpc_allow"),
        management_allow: list("management_allow"),
        monitoring_allow: list("monitoring_allow"),
        last_run: field(&f, "last_run"),
        last_result: field(&f, "last_result"),
    })
}

fn read_solana_rpc(item: &OpItem) -> Result<SolanaRpc, InventoryError> {
    let f = checked(item)?;
    let port = field(&f, "ssh_port");
    let list = |name: &str| -> Vec<String> {
        field(&f, name)
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    };
    Ok(SolanaRpc {
        id: Some(item.id.clone()),
        item_version: item.version,
        name: field(&f, "name"),
        address: field(&f, "address"),
        ssh_user: field(&f, "ssh_user"),
        ssh_port: port.parse().map_err(|_| InventoryError::Item {
            title: item.title.clone(),
            reason: format!("ssh_port {port:?} is not a port"),
        })?,
        host_key: field(&f, "host_key"),
        client: field(&f, "client"),
        rpc_type: field(&f, "rpc_type"),
        version: field(&f, "version"),
        commit: field(&f, "commit"),
        geyser_version: field(&f, "geyser_version"),
        geyser_commit: field(&f, "geyser_commit"),
        of1_version: field(&f, "of1_version"),
        of1_sha256: field(&f, "of1_sha256"),
        region: field(&f, "region"),
        identity_account: field(&f, "identity_account"),
        rpc_allow: list("rpc_allow"),
        management_allow: list("management_allow"),
        monitoring_allow: list("monitoring_allow"),
        last_run: field(&f, "last_run"),
        last_result: field(&f, "last_result"),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use erpc_auth::store::StoreError;
    use erpc_auth::store::one_password::{OpOutput, OpRunner};
    use secrecy::{ExposeSecret as _, SecretString};
    use serde_json::{Value, json};

    use super::{
        EthRpc, Host, InventoryError, Jito, Role, RpcNode, Scope, SolanaRpc, Store, Validator,
    };

    /// `op`, in memory: enough of `item list/get/create/edit` and `read` to
    /// exercise the store, and a record of every argv it was given.
    #[derive(Default)]
    struct FakeOp {
        items: RefCell<Vec<Value>>,
        calls: RefCell<Vec<Vec<String>>>,
    }

    fn reply(stdout: String) -> OpOutput {
        OpOutput {
            success: true,
            stdout,
            stderr: String::new(),
        }
    }

    impl OpRunner for &FakeOp {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).to_owned()).collect());
            let mut items = self.items.borrow_mut();
            match args {
                [
                    "item",
                    "list",
                    "--vault",
                    _,
                    "--tags",
                    tag,
                    "--format",
                    "json",
                ] => {
                    let listed: Vec<Value> = items
                        .iter()
                        .filter(|i| {
                            i["tags"]
                                .as_array()
                                .is_some_and(|t| t.iter().any(|x| x == tag))
                        })
                        .map(|i| json!({ "id": i["id"], "title": i["title"] }))
                        .collect();
                    Ok(reply(Value::Array(listed).to_string()))
                }
                ["item", "get", "-", "--format", "json"] => {
                    let wanted: Vec<Value> =
                        serde_json::from_str(stdin.unwrap_or("[]")).expect("listing");
                    let out: Vec<String> = wanted
                        .iter()
                        .filter_map(|w| items.iter().find(|i| i["id"] == w["id"]))
                        .map(Value::to_string)
                        .collect();
                    Ok(reply(out.join("\n")))
                }
                ["item", "get", id, "--vault", _, "--format", "json"] => {
                    let item = items.iter().find(|i| i["id"] == *id).expect("exists");
                    Ok(reply(item.to_string()))
                }
                ["item", "create", "-", "--vault", _, "--format", "json"] => {
                    let mut item: Value =
                        serde_json::from_str(stdin.expect("template")).expect("json");
                    item["id"] = json!(format!("item{}", items.len() + 1));
                    item["version"] = json!(1);
                    items.push(item.clone());
                    Ok(reply(item.to_string()))
                }
                ["item", "edit", id, "--vault", _] => {
                    let template: Value =
                        serde_json::from_str(stdin.expect("template")).expect("json");
                    let item = items.iter_mut().find(|i| i["id"] == *id).expect("exists");
                    item["fields"] = template["fields"].clone();
                    item["version"] = json!(item["version"].as_u64().unwrap_or(0) + 1);
                    Ok(reply(item.to_string()))
                }
                ["read", "--no-newline", reference] => {
                    let id = reference.split('/').nth(3).expect("id");
                    let item = items.iter().find(|i| i["id"] == id).expect("exists");
                    let value = item["fields"]
                        .as_array()
                        .and_then(|f| f.iter().find(|f| f["label"] == "solv_password"))
                        .and_then(|f| f["value"].as_str())
                        .unwrap_or_default();
                    Ok(reply(value.to_owned()))
                }
                other => panic!("unexpected op call: {other:?}"),
            }
        }
    }

    impl FakeOp {
        /// Bumps an item's version, as a write from another machine would.
        fn bump(&self, id: &str) {
            let mut items = self.items.borrow_mut();
            let item = items.iter_mut().find(|i| i["id"] == id).expect("exists");
            item["version"] = json!(item["version"].as_u64().unwrap_or(0) + 1);
        }
    }

    fn store(op: &FakeOp) -> Store<&FakeOp> {
        let dir = std::env::temp_dir().join(format!("erpc-inventory-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        Store::new(
            op,
            "vaultid",
            Scope {
                chain: "solana".to_owned(),
                network: "testnet".to_owned(),
            },
            dir.join("inventory.lock"),
        )
    }

    fn validator() -> Validator {
        Validator {
            name: "tv1".to_owned(),
            identity_account: "Ident1111111111111111111111111111111111111".to_owned(),
            identity_ref: "op://vaultid/identityitem/keypair".to_owned(),
            client: "agave".to_owned(),
            version: "v4.4.0-beta.1".to_owned(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            region: "ny".to_owned(),
            ..Validator::default()
        }
    }

    fn host(name: &str, address: &str, role: Role) -> Host {
        Host {
            name: name.to_owned(),
            validator: "tv1".to_owned(),
            role: Some(role),
            address: address.to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 22,
            host_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/"
                    .to_owned(),
            jito: Jito {
                region: "ny".to_owned(),
                block_engine_url: "block-engine-ny".to_owned(),
                ..Jito::default()
            },
            ..Host::default()
        }
    }

    fn password() -> SecretString {
        SecretString::from("correct horse battery staple".to_owned())
    }

    #[test]
    fn a_validator_and_its_hosts_round_trip() {
        let op = FakeOp::default();
        let s = store(&op);
        s.add_validator(&validator()).expect("validator");
        s.add_host(&host("tv1-a", "203.0.113.5", Role::Primary), &password())
            .expect("primary");
        s.add_host(&host("tv1-b", "203.0.113.6", Role::Spare), &password())
            .expect("spare");
        let inventory = s.load().expect("loads");
        assert_eq!(inventory.validators.len(), 1);
        assert_eq!(inventory.validators[0].version, "v4.4.0-beta.1");
        let hosts = inventory.hosts_of("tv1");
        assert_eq!(
            hosts.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(),
            ["tv1-a", "tv1-b"]
        );
        assert_eq!(hosts[0].role, Some(Role::Primary));
        assert_eq!(hosts[1].address, "203.0.113.6");
        assert_eq!(hosts[0].jito.block_engine_url, "block-engine-ny");
    }

    #[test]
    fn the_whole_inventory_is_read_in_two_calls_per_kind() {
        let op = FakeOp::default();
        let s = store(&op);
        s.add_validator(&validator()).expect("validator");
        s.add_host(&host("tv1-a", "203.0.113.5", Role::Primary), &password())
            .expect("host");
        op.calls.borrow_mut().clear();
        s.load().expect("loads");
        assert_eq!(op.calls.borrow().len(), 4, "{:#?}", op.calls.borrow());
    }

    #[test]
    fn names_addresses_and_a_second_primary_are_refused() {
        let op = FakeOp::default();
        let s = store(&op);
        s.add_validator(&validator()).expect("validator");
        assert!(matches!(
            s.add_validator(&validator()),
            Err(InventoryError::Refused(_))
        ));
        s.add_host(&host("tv1-a", "203.0.113.5", Role::Primary), &password())
            .expect("primary");
        for refused in [
            host("tv1-a", "203.0.113.9", Role::Spare),
            host("tv1-c", "203.0.113.5", Role::Spare),
            host("tv1-d", "203.0.113.7", Role::Primary),
            Host {
                validator: "nope".to_owned(),
                ..host("tv1-e", "203.0.113.8", Role::Spare)
            },
            host("bad name", "203.0.113.10", Role::Spare),
        ] {
            assert!(
                matches!(
                    s.add_host(&refused, &password()),
                    Err(InventoryError::Refused(_))
                ),
                "{}",
                refused.name
            );
        }
    }

    #[test]
    fn an_update_over_someone_elses_write_is_refused() {
        let op = FakeOp::default();
        let s = store(&op);
        s.add_validator(&validator()).expect("validator");
        let stored = s
            .add_host(&host("tv1-a", "203.0.113.5", Role::Primary), &password())
            .expect("host");
        op.bump(stored.id.as_deref().expect("id"));
        let mut changed = stored.clone();
        changed.ssh_user = "solv".to_owned();
        assert!(matches!(
            s.update_host(&changed),
            Err(InventoryError::Changed(_))
        ));
    }

    #[test]
    fn an_update_keeps_the_password_and_reads_back() {
        let op = FakeOp::default();
        let s = store(&op);
        s.add_validator(&validator()).expect("validator");
        let stored = s
            .add_host(&host("tv1-a", "203.0.113.5", Role::Primary), &password())
            .expect("host");
        let mut changed = stored.clone();
        changed.ssh_user = "solv".to_owned();
        let updated = s.update_host(&changed).expect("updated");
        assert_eq!(updated.ssh_user, "solv");
        assert_eq!(
            s.solv_password(&updated).expect("password").expose_secret(),
            password().expose_secret()
        );
    }

    #[test]
    fn no_password_address_or_host_key_reaches_ops_arguments() {
        let op = FakeOp::default();
        let s = store(&op);
        s.add_validator(&validator()).expect("validator");
        let stored = s
            .add_host(&host("tv1-a", "203.0.113.5", Role::Primary), &password())
            .expect("host");
        let mut changed = stored.clone();
        changed.ssh_user = "solv".to_owned();
        s.update_host(&changed).expect("updated");
        for call in op.calls.borrow().iter() {
            let line = call.join(" ");
            for secret in ["correct horse", "203.0.113.5", "AAAAC3NzaC1lZDI1NTE5"] {
                assert!(!line.contains(secret), "{secret} in argv: {line}");
            }
        }
    }

    #[test]
    fn a_listing_does_not_keep_the_password() {
        let op = FakeOp::default();
        let s = store(&op);
        s.add_validator(&validator()).expect("validator");
        s.add_host(&host("tv1-a", "203.0.113.5", Role::Primary), &password())
            .expect("host");
        let shown = format!("{:?}", s.load().expect("loads"));
        assert!(!shown.contains("correct horse"), "{shown}");
    }

    #[test]
    fn an_item_of_another_format_is_refused() {
        let op = FakeOp::default();
        let s = store(&op);
        s.add_validator(&validator()).expect("validator");
        for item in op.items.borrow_mut().iter_mut() {
            for field in item["fields"].as_array_mut().expect("fields") {
                if field["label"] == "erpc_format" {
                    field["value"] = json!("99");
                }
            }
        }
        assert!(matches!(s.load(), Err(InventoryError::Item { .. })));
    }

    fn arc_store(op: &FakeOp) -> Store<&FakeOp> {
        let dir = std::env::temp_dir().join(format!("erpc-inventory-arc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        Store::new(
            op,
            "vaultid",
            Scope {
                chain: "arc".to_owned(),
                network: "testnet".to_owned(),
            },
            dir.join("inventory.lock"),
        )
    }

    fn rpc_node(name: &str, address: &str) -> RpcNode {
        RpcNode {
            name: name.to_owned(),
            address: address.to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 22,
            host_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/"
                    .to_owned(),
            version: "v0.8.1".to_owned(),
            commit: "ab09dbf0123456789abcdef0123456789abcdef0".to_owned(),
            archive_sha256: "a".repeat(64),
            consensus_key_ref: "op://vaultid/keyitem/private_key".to_owned(),
            consensus_public_key: "pubkey".to_owned(),
            rpc_type: "full".to_owned(),
            rpc_allow: vec!["198.51.100.0/24".to_owned(), "203.0.113.9".to_owned()],
            management_allow: Vec::new(),
            monitoring_allow: vec!["192.0.2.50".to_owned()],
            ..RpcNode::default()
        }
    }

    #[test]
    fn an_rpc_node_round_trips_with_its_allow_lists() {
        let op = FakeOp::default();
        let s = arc_store(&op);
        let stored = s
            .add_rpc_node(&rpc_node("arc1", "203.0.113.5"))
            .expect("stored");
        assert_eq!(stored.rpc_allow, ["198.51.100.0/24", "203.0.113.9"]);
        assert!(stored.management_allow.is_empty());
        {
            let items = op.items.borrow();
            assert_eq!(items[0]["title"], "erpc testnet arc1 arc-rpc");
            assert!(
                items[0]["tags"]
                    .as_array()
                    .expect("tags")
                    .contains(&json!("erpc/arc/testnet/rpc"))
            );
        }
        op.calls.borrow_mut().clear();
        assert_eq!(s.rpc_nodes().expect("loads"), std::slice::from_ref(&stored));
        assert_eq!(op.calls.borrow().len(), 2);
        let updated = s
            .update_rpc_node(&RpcNode {
                last_result: "deploy ok".to_owned(),
                ..stored
            })
            .expect("updated");
        assert_eq!(updated.last_result, "deploy ok");
    }

    #[test]
    fn a_provider_node_keeps_its_peers_and_an_old_item_is_full() {
        let op = FakeOp::default();
        let s = arc_store(&op);
        let stored = s
            .add_rpc_node(&RpcNode {
                rpc_type: "provider".to_owned(),
                debug_api: false,
                trusted_peers: vec![format!("enode://{}@192.0.2.7:30303", "ab".repeat(64))],
                sentry_peers: vec!["/ip4/192.0.2.8/tcp/27000/p2p/12D3KooWabc".to_owned()],
                ..rpc_node("arc1", "203.0.113.5")
            })
            .expect("stored");
        assert_eq!(stored.rpc_type, "provider");
        assert_eq!(stored.trusted_peers.len(), 1);
        assert_eq!(
            stored.sentry_peers,
            ["/ip4/192.0.2.8/tcp/27000/p2p/12D3KooWabc"]
        );
        let old = s
            .add_rpc_node(&RpcNode {
                rpc_type: String::new(),
                ..rpc_node("arc2", "203.0.113.6")
            })
            .expect("stored");
        assert_eq!(old.rpc_type, "full");
        assert!(!old.debug_api);
    }

    #[test]
    fn an_rpc_node_name_or_address_twice_is_refused_and_nothing_leaks_to_argv() {
        let op = FakeOp::default();
        let s = arc_store(&op);
        s.add_rpc_node(&rpc_node("arc1", "203.0.113.5"))
            .expect("stored");
        for twice in [
            rpc_node("arc1", "203.0.113.6"),
            rpc_node("arc2", "203.0.113.5"),
        ] {
            assert!(matches!(
                s.add_rpc_node(&twice),
                Err(InventoryError::Refused(_))
            ));
        }
        for call in op.calls.borrow().iter() {
            let line = call.join(" ");
            for secret in ["203.0.113.5", "AAAAC3NzaC1lZDI1NTE5", "198.51.100.0"] {
                assert!(!line.contains(secret), "{secret} in argv: {line}");
            }
        }
    }

    fn mainnet_store(op: &FakeOp) -> Store<&FakeOp> {
        let dir =
            std::env::temp_dir().join(format!("erpc-inventory-solana-rpc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        Store::new(
            op,
            "vaultid",
            Scope {
                chain: "solana".to_owned(),
                network: "mainnet".to_owned(),
            },
            dir.join("inventory.lock"),
        )
    }

    #[test]
    fn an_ethereum_rpc_node_round_trips_with_both_pins() {
        let op = FakeOp::default();
        let dir = std::env::temp_dir().join(format!("erpc-inventory-eth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let s = Store::new(
            &op,
            "v123",
            Scope {
                chain: "eth".to_owned(),
                network: "mainnet".to_owned(),
            },
            dir.join("inventory.lock"),
        );
        let node = EthRpc {
            name: "eth1".to_owned(),
            address: "203.0.113.9".to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 22,
            host_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/"
                    .to_owned(),
            rpc_type: "archive".to_owned(),
            reth_version: "v2.8.1".to_owned(),
            reth_commit: "a".repeat(40),
            reth_sha256: "b".repeat(64),
            lighthouse_version: "v8.3.2".to_owned(),
            lighthouse_commit: "c".repeat(40),
            lighthouse_sha256: "d".repeat(64),
            rpc_allow: vec!["198.51.100.0/24".to_owned(), "203.0.113.7".to_owned()],
            ..EthRpc::default()
        };
        let stored = s.add_eth_rpc(&node).expect("stored");
        assert_eq!(stored.lighthouse_sha256, "d".repeat(64));
        assert_eq!(stored.rpc_allow.len(), 2);
        assert_eq!(op.items.borrow()[0]["title"], "erpc mainnet eth1 eth-rpc");
        assert_eq!(s.eth_rpcs().expect("loads"), std::slice::from_ref(&stored));
        let updated = s
            .update_eth_rpc(&EthRpc {
                last_result: "deploy ok".to_owned(),
                ..stored.clone()
            })
            .expect("updated");
        assert_eq!(updated.last_result, "deploy ok");
        assert!(matches!(
            s.update_eth_rpc(&stored),
            Err(InventoryError::Changed(_))
        ));
        assert!(matches!(
            s.add_eth_rpc(&EthRpc {
                name: "eth2".to_owned(),
                ..node
            }),
            Err(InventoryError::Refused(_))
        ));
    }

    #[test]
    fn avalanche_identity_and_backup_are_immutable_and_not_in_argv() {
        use super::avax::AvaxNode;
        let op = FakeOp::default();
        let dir = tempfile_dir();
        let s = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "avax".into(),
                network: "fuji".into(),
            },
            dir.join("avax.lock"),
        );
        let node = AvaxNode {
            name: "av1".into(),
            address: "192.0.2.10".into(),
            network: "fuji".into(),
            rpc_type: "full".into(),
            validator: true,
            ..AvaxNode::default()
        };
        let stored = s.add_avax_node(&node).expect("create");
        assert!(s.add_avax_node(&node).is_err());
        let pinned = s
            .update_avax_node(&AvaxNode {
                node_id: "public-node-id".into(),
                identity_hashes: json!({"public":"digest"}),
                node_pop: json!({"public":"proof"}),
                ..stored.clone()
            })
            .expect("pin");
        assert!(s.update_avax_node(&stored).is_err());
        let secret = SecretString::from("inert encrypted-backup fixture");
        let backed = s.backup_avax_identity(&pinned, &secret).expect("backup");
        assert_eq!(
            s.avax_identity_backup(&backed)
                .expect("read")
                .expose_secret(),
            secret.expose_secret()
        );
        for altered in [
            AvaxNode {
                address: "192.0.2.11".into(),
                ..backed.clone()
            },
            AvaxNode {
                node_id: "different".into(),
                ..backed.clone()
            },
            AvaxNode {
                rpc_type: "archive".into(),
                ..backed.clone()
            },
            AvaxNode {
                validator: false,
                ..backed.clone()
            },
        ] {
            assert!(s.update_avax_node(&altered).is_err());
        }
        let updated = s
            .update_avax_node(&AvaxNode {
                last_result: "ok".into(),
                ..backed
            })
            .expect("update");
        assert_eq!(
            s.avax_identity_backup(&updated)
                .expect("retained")
                .expose_secret(),
            secret.expose_secret()
        );
        assert!(
            !format!("{:?}", s.avax_nodes().expect("listing")).contains(secret.expose_secret())
        );
        for call in op.calls.borrow().iter() {
            assert!(!call.join(" ").contains(secret.expose_secret()));
        }
    }

    fn solana_rpc(name: &str, address: &str) -> SolanaRpc {
        SolanaRpc {
            name: name.to_owned(),
            address: address.to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 22,
            host_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/"
                    .to_owned(),
            client: "jito".to_owned(),
            rpc_type: "index-grpc".to_owned(),
            version: "v4.3.2-jito".to_owned(),
            commit: "a".repeat(40),
            geyser_version: "v16.1.5+solana.4.3.2".to_owned(),
            geyser_commit: "b".repeat(40),
            of1_version: "v0.7.31".to_owned(),
            of1_sha256: "c".repeat(64),
            region: "frankfurt".to_owned(),
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            monitoring_allow: vec!["192.0.2.50".to_owned()],
            ..SolanaRpc::default()
        }
    }

    #[test]
    fn a_solana_rpc_node_round_trips_and_keeps_its_password() {
        let op = FakeOp::default();
        let s = mainnet_store(&op);
        let stored = s
            .add_solana_rpc(&solana_rpc("rpc1", "203.0.113.5"), &password())
            .expect("stored");
        assert_eq!(stored.geyser_version, "v16.1.5+solana.4.3.2");
        assert_eq!(stored.rpc_allow, ["198.51.100.0/24"]);
        {
            let items = op.items.borrow();
            assert_eq!(items[0]["title"], "erpc mainnet rpc1 solana-rpc");
            assert!(
                items[0]["tags"]
                    .as_array()
                    .expect("tags")
                    .contains(&json!("erpc/solana/mainnet/rpc"))
            );
        }
        assert_eq!(
            s.solana_rpcs().expect("loads"),
            std::slice::from_ref(&stored)
        );
        let updated = s
            .update_solana_rpc(&SolanaRpc {
                ssh_user: "solv".to_owned(),
                identity_account: "Ident111".to_owned(),
                ..stored.clone()
            })
            .expect("updated");
        assert_eq!(updated.ssh_user, "solv");
        assert_eq!(
            s.rpc_solv_password(&updated)
                .expect("password")
                .expose_secret(),
            password().expose_secret()
        );
        // Another writer in between is refused.
        assert!(matches!(
            s.update_solana_rpc(&stored),
            Err(InventoryError::Changed(_))
        ));
        assert!(matches!(
            s.add_solana_rpc(&solana_rpc("rpc2", "203.0.113.5"), &password()),
            Err(InventoryError::Refused(_))
        ));
        for call in op.calls.borrow().iter() {
            let line = call.join(" ");
            for secret in [
                "203.0.113.5",
                "AAAAC3NzaC1lZDI1NTE5",
                password().expose_secret(),
            ] {
                assert!(!line.contains(secret), "{secret} in argv: {line}");
            }
        }
    }

    #[test]
    fn sui_nodes_reject_duplicate_hosts_roles_and_stale_writes() {
        use super::sui::SuiNode;
        let op = FakeOp::default();
        let dir = tempfile_dir();
        let s = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "sui".to_owned(),
                network: "testnet".to_owned(),
            },
            dir.join("sui.lock"),
        );
        let node = SuiNode {
            name: "sui1".to_owned(),
            address: "192.0.2.4".to_owned(),
            role: "fullnode".to_owned(),
            ..SuiNode::default()
        };
        let stored = s.add_sui_node(&node).expect("reserve");
        assert_eq!(s.sui_nodes("fullnode").expect("list"), vec![stored.clone()]);
        assert!(
            s.add_sui_node(&SuiNode {
                name: "validator1".to_owned(),
                role: "validator".to_owned(),
                ..node
            })
            .is_err()
        );
        let updated = s
            .update_sui_node(&SuiNode {
                last_result: "init ok".to_owned(),
                ..stored.clone()
            })
            .expect("update");
        assert!(s.update_sui_node(&stored).is_err());
        assert!(
            s.update_sui_node(&SuiNode {
                address: "192.0.2.5".to_owned(),
                ..updated
            })
            .is_err()
        );
        for call in op.calls.borrow().iter() {
            assert!(!call.join(" ").contains("192.0.2.4"));
        }
    }

    #[test]
    fn sui_inventory_refuses_owner_or_any_key_reuse_and_metadata_changes() {
        use super::sui::SuiNode;
        let op = FakeOp::default();
        let dir = tempfile_dir();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "sui".to_owned(),
                network: "testnet".to_owned(),
            },
            dir.join("sui.lock"),
        );
        let fields = [
            "account-address",
            "protocol-key",
            "network-key",
            "worker-key",
        ];
        let info = fields
            .iter()
            .map(|f| ((*f).to_owned(), serde_json::json!(format!("original-{f}"))))
            .collect::<serde_json::Map<_, _>>();
        let original = SuiNode {
            name: "one".to_owned(),
            address: "192.0.2.1".to_owned(),
            role: "validator".to_owned(),
            validator_metadata: Some(serde_json::json!({"info":info})),
            ..SuiNode::default()
        };
        let saved = store.add_sui_node(&original).expect("reserve");
        for field in fields {
            let mut other = original.clone();
            other.name = "two".to_owned();
            other.address = "192.0.2.2".to_owned();
            let mut info = fields
                .iter()
                .map(|f| ((*f).to_owned(), serde_json::json!(format!("different-{f}"))))
                .collect::<serde_json::Map<_, _>>();
            info[field] = serde_json::json!(format!("original-{field}"));
            other.validator_metadata = Some(serde_json::json!({"info":info}));
            assert!(store.add_sui_node(&other).is_err(), "{field}");
        }
        let mut changed = saved;
        changed.validator_metadata = Some(serde_json::json!({"info":{}}));
        assert!(store.update_sui_node(&changed).is_err());
    }

    #[test]
    fn tron_inventory_refuses_duplicate_signers_hosts_and_credential_reference_changes() {
        use super::tron::TronNode;
        let op = FakeOp::default();
        let dir = tempfile_dir();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "tron".into(),
                network: "nile".into(),
            },
            dir.join("tron.lock"),
        );
        let original = TronNode {
            name: "one".into(),
            address: "192.0.2.1".into(),
            role: "validator".into(),
            owner: "public-owner-fixture".into(),
            signer: "public-signer-fixture".into(),
            ..TronNode::default()
        };
        let saved = store.add_tron_node(&original).expect("reserve");
        for kind in ["host", "owner", "signer"] {
            let mut other = TronNode {
                name: "two".into(),
                address: "192.0.2.2".into(),
                role: "validator".into(),
                owner: "different-owner".into(),
                signer: "different-signer".into(),
                ..TronNode::default()
            };
            match kind {
                "host" => other.address.clone_from(&original.address),
                "owner" => other.owner.clone_from(&original.owner),
                _ => other.signer.clone_from(&original.signer),
            }
            assert!(store.add_tron_node(&other).is_err(), "{kind}");
        }
        let mut changed = saved.clone();
        changed.credential_references[0] = "different-reference".into();
        assert!(store.update_tron_node(&changed).is_err());
        let mut changed = saved.clone();
        changed.owner = "another-owner".into();
        assert!(store.update_tron_node(&changed).is_err());
        store
            .update_tron_node(&saved)
            .expect("same original metadata");
        assert!(
            store.update_tron_node(&saved).is_err(),
            "stale inventory version"
        );
    }

    /// One real round trip through 1Password: create a validator and a host,
    /// read them back, update the host, then remove both. Run by hand with
    /// `ERPC_TEST_VAULT=<vault id>`; it asks 1Password for approval.
    #[test]
    #[ignore = "writes to a real 1Password vault"]
    fn a_real_round_trip_through_1password() {
        use erpc_auth::store::one_password::{Mode, OpCli};
        let vault = std::env::var("ERPC_TEST_VAULT").expect("ERPC_TEST_VAULT");
        let runner = OpCli::from_env(Mode::Desktop, |n| std::env::var_os(n)).expect("op");
        let dir = tempfile_dir();
        let s = Store::new(
            runner,
            vault,
            Scope {
                chain: "solana".to_owned(),
                network: "roundtrip".to_owned(),
            },
            dir.join("inventory.lock"),
        );
        let name = format!("rt{}", std::process::id());
        let v = s
            .add_validator(&Validator {
                name: name.clone(),
                ..validator()
            })
            .expect("validator");
        let h = s
            .add_host(
                &Host {
                    name: format!("{name}-a"),
                    validator: name.clone(),
                    ..host("x", "198.51.100.7", Role::Primary)
                },
                &password(),
            )
            .expect("host");
        let result = (|| {
            let inventory = s.load()?;
            assert_eq!(inventory.hosts_of(&name).len(), 1);
            let mut changed = h.clone();
            changed.ssh_user = "solv".to_owned();
            let updated = s.update_host(&changed)?;
            assert_eq!(updated.ssh_user, "solv");
            assert_eq!(
                s.solv_password(&updated)?.expose_secret(),
                password().expose_secret()
            );
            Ok::<(), InventoryError>(())
        })();
        s.remove(h.id.as_deref().expect("id"))
            .expect("host removed");
        s.remove(v.id.as_deref().expect("id"))
            .expect("validator removed");
        result.expect("round trip");
    }

    #[test]
    fn ethereum_validator_ownership_is_separate_and_duplicate_keys_are_refused() {
        use super::eth_validator::EthValidator;
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "eth".to_owned(),
                network: "hoodi".to_owned(),
            },
            tempfile_dir().join("eth-validator.lock"),
        );
        let new = |name: &str, address: &str| EthValidator {
            node: EthRpc {
                name: name.to_owned(),
                address: address.to_owned(),
                ssh_port: 22,
                rpc_type: "full".to_owned(),
                ..EthRpc::default()
            },
            fee_recipient: "reviewed-address".to_owned(),
            state: "prepared".to_owned(),
            ..EthValidator::default()
        };
        let mut first = store
            .add_eth_validator(&new("signer1", "192.0.2.1"))
            .expect("first");
        assert!(store.eth_rpcs().expect("RPC listing").is_empty());
        assert!(
            store
                .add_eth_validator(&new("signer2", "192.0.2.1"))
                .is_err()
        );
        let mut second = store
            .add_eth_validator(&new("signer2", "192.0.2.2"))
            .expect("second");
        first.pubkey = "public-fixture".to_owned();
        first.state = "importing".to_owned();
        first = store.update_eth_validator(&first).expect("reservation");
        second.pubkey.clone_from(&first.pubkey);
        second.state = "importing".to_owned();
        assert!(store.update_eth_validator(&second).is_err());
        for replacement in ["different-key", ""] {
            let mut changed = first.clone();
            changed.pubkey = replacement.to_owned();
            assert!(store.update_eth_validator(&changed).is_err());
            assert_eq!(
                store
                    .eth_validators()
                    .expect("unchanged ownership")
                    .iter()
                    .find(|v| v.node.id == first.node.id)
                    .expect("first"),
                &first
            );
        }
        first.state = "imported".to_owned();
        first = store
            .update_eth_validator(&first)
            .expect("completed import");
        let mut downgrade = first.clone();
        downgrade.state = "importing".to_owned();
        assert!(store.update_eth_validator(&downgrade).is_err());
        let old = first.clone();
        first.state = "fenced".to_owned();
        store.update_eth_validator(&first).expect("fenced source");
        assert!(store.update_eth_validator(&old).is_err());
        assert!(store.update_eth_validator(&second).is_ok());
        for argv in op.calls.borrow().iter() {
            assert!(!argv.join(" ").contains("192.0.2."));
        }
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("erpc-inventory-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }
    #[test]
    fn bitcoin_scope_roundtrips_but_cannot_retarget_a_host_or_retention() {
        use super::bitcoin::BitcoinRpc;
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "bitcoin".into(),
                network: "signet".into(),
            },
            tempfile_dir().join("bitcoin.lock"),
        );
        let node = BitcoinRpc {
            name: "btc1".into(),
            address: "192.0.2.42".into(),
            ssh_port: 22,
            storage: "full".into(),
            ..BitcoinRpc::default()
        };
        let mut stored = store.add_bitcoin_rpc(&node).expect("reserved");
        assert_eq!(store.bitcoin_rpcs().expect("read"), [stored.clone()]);
        let mut different = stored.clone();
        different.storage = "pruned".into();
        different.prune_mib = 10240;
        assert!(store.update_bitcoin_rpc(&different).is_err());
        different = stored.clone();
        different.address = "192.0.2.43".into();
        assert!(store.update_bitcoin_rpc(&different).is_err());
        let old = stored.clone();
        stored.last_result = "deploy ok".into();
        store.update_bitcoin_rpc(&stored).expect("recorded");
        assert!(store.update_bitcoin_rpc(&old).is_err());
        assert!(store.add_bitcoin_rpc(&node).is_err());
        for args in op.calls.borrow().iter() {
            assert!(!args.join(" ").contains("192.0.2."));
        }
    }
    #[test]
    fn nitro_public_records_require_op_references_and_keep_host_ownership() {
        use super::nitro::NitroRpc;
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "arbitrum".into(),
                network: "sepolia".into(),
            },
            tempfile_dir().join("nitro.lock"),
        );
        let mut node = NitroRpc {
            name: "nitro1".into(),
            address: "192.0.2.44".into(),
            ssh_port: 22,
            version: "3.12.1".into(),
            commit: "a".repeat(40),
            platform: "amd64".into(),
            upstreams_ref: "https://github.com/provider-value".into(),
            ..NitroRpc::default()
        };
        assert!(store.add_nitro_rpc(&node).is_err());
        node.upstreams_ref = format!("op://{}/{}/l1", "a".repeat(26), "b".repeat(26));
        let stored = store.add_nitro_rpc(&node).expect("owner");
        assert_eq!(
            store.nitro_rpcs().expect("list").as_slice(),
            std::slice::from_ref(&stored)
        );
        let mut changed = stored.clone();
        changed.address = "192.0.2.45".into();
        assert!(store.update_nitro_rpc(&changed).is_err());
        changed = stored.clone();
        changed.platform = "arm64".into();
        assert!(store.update_nitro_rpc(&changed).is_err());
        changed = stored.clone();
        changed.upstreams_ref = "https://github.com/provider-value".into();
        assert!(store.update_nitro_rpc(&changed).is_err());
        changed = stored.clone();
        changed.last_result = "prepared".into();
        store.update_nitro_rpc(&changed).expect("update");
        assert!(store.update_nitro_rpc(&stored).is_err());
        let mut corrupted = serde_json::to_value(&stored).expect("record");
        corrupted["upstreams_ref"] = json!("https://github.com/provider-value");
        {
            let mut items = op.items.borrow_mut();
            let fields = items[0]["fields"].as_array_mut().expect("fields");
            fields
                .iter_mut()
                .find(|field| field["label"] == "nitro_record")
                .expect("record field")["value"] = json!(corrupted.to_string());
        }
        let error = store
            .nitro_rpcs()
            .expect_err("reject public provider value");
        assert!(!error.to_string().contains("provider-value"));
        for args in op.calls.borrow().iter() {
            assert!(!args.join(" ").contains("192.0.2."));
            assert!(!args.join(" ").contains("provider-value"));
        }
    }
    #[test]
    fn rollup_inventory_scope_secrets_retention_and_revision_are_enforced() {
        use super::rollup::RollupRpc;
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "base".into(),
                network: "sepolia".into(),
            },
            tempfile_dir().join("rollup.lock"),
        );
        let mut node = RollupRpc {
            name: "base1".into(),
            address: "192.0.2.44".into(),
            ssh_port: 22,
            family: "base".into(),
            network: "sepolia".into(),
            history: "full".into(),
            upstream_ref: "https://github.com/provider-value".into(),
            ..RollupRpc::default()
        };
        assert!(store.add_rollup_rpc(&node).is_err());
        node.upstream_ref = format!("op://{}/{}/l1", "a".repeat(26), "b".repeat(26));
        let stored = store.add_rollup_rpc(&node).expect("owned record");
        assert_eq!(store.rollup_rpcs().expect("list"), vec![stored.clone()]);
        assert!(store.add_rollup_rpc(&node).is_err());
        for field in [
            "address", "history", "family", "network", "host_key", "ssh_user",
        ] {
            let mut changed = serde_json::to_value(&stored).expect("record");
            changed[field] = json!("different");
            let mut changed: RollupRpc = serde_json::from_value(changed).expect("record");
            changed.id.clone_from(&stored.id);
            changed.item_version = stored.item_version;
            assert!(store.update_rollup_rpc(&changed).is_err(), "{field}");
        }
        let mut changed = stored.clone();
        changed.last_result = "prepared".into();
        store
            .update_rollup_rpc(&changed)
            .expect("allowed mutable field");
        assert!(store.update_rollup_rpc(&stored).is_err());
        let mut corrupted = serde_json::to_value(&stored).expect("record");
        corrupted["upstream_ref"] = json!("https://github.com/provider-value");
        {
            let mut items = op.items.borrow_mut();
            items[0]["fields"]
                .as_array_mut()
                .expect("fields")
                .iter_mut()
                .find(|field| field["label"] == "rollup_record")
                .expect("record field")["value"] = json!(corrupted.to_string());
        }
        let error = store
            .rollup_rpcs()
            .expect_err("refuse public credential value");
        assert!(!error.to_string().contains("provider-value"));
        assert!(
            op.calls
                .borrow()
                .iter()
                .all(|args| !args.join(" ").contains("provider-value"))
        );
    }
}
