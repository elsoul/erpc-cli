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
//! Legacy item readers use a tag listing piped into one `item get`. Arc uses
//! selected public fields instead: listings never request key references or
//! concealed values. Its explicit writes use typed snapshots and readback.
//! A write rereads the item, refuses if it changed since it was read, edits
//! it, and reads it back. 1Password has no compare-and-swap, so this narrows
//! a race between two writers rather than closing it; a local lock keeps one
//! erpc from racing itself.

#[path = "arc_inventory.rs"]
mod arc_inventory;
/// Dedicated Arc validator inventory, isolated from RPC metadata and key references.
#[path = "arc_validator_inventory.rs"]
pub mod arc_validator;

#[path = "avax_inventory.rs"]
pub mod avax;
pub mod monad;
pub mod polygon;

/// Public ownership for Hyperliquid non-validator hosts.
pub mod hyperliquid;
/// Separate original AQA agent publisher host metadata.
pub mod hyperliquid_aqa;
/// Dedicated Hyperliquid consensus-hot ownership, separate from RPC records.
pub mod hyperliquid_validator;
/// OP-family follower ownership records.
pub mod rollup;
pub mod solana_listing;
pub mod solana_migration;
mod solana_migration_item;
pub mod solana_migration_pending;
pub mod solana_migration_reference;
/// Separate native Solana host ownership.
pub mod solana_native;
pub mod solana_public;
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

/// Original Arbitrum assertion-validator public ownership records.
pub mod arbitrum_validator;
/// Bitcoin host ownership records.
pub mod bitcoin;
/// BSC host ownership and bootstrap records.
pub mod bsc;
/// BSC validator ownership, separate from RPC inventory.
pub mod bsc_validator;
/// Ethereum validator ownership inventory.
pub mod eth_validator;
pub mod kaia;
pub mod kaia_corecell;
/// Dedicated NEAR RPC ownership.
pub mod near;
pub mod nitro;
pub mod robinhood_validator;
/// The tag every inventory item carries.
pub const TAG: &str = "erpc";

/// What kind of item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A logical validator.
    Validator,
    /// A dedicated native Solana host, separate from legacy Solv credentials.
    NativeHost,
    /// Original public intent while an explicit Solv copy migration is pending.
    NativeMigration,
    /// A machine running one.
    Host,
    /// A machine serving RPC, on a chain whose RPC nodes stand alone.
    Rpc,
    /// A separately owned validator-side publisher with dedicated agent custody.
    Publisher,
}

impl Kind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::NativeHost => "native-host",
            Self::NativeMigration => "native-migration",
            Self::Host => "host",
            Self::Rpc => "rpc",
            Self::Publisher => "publisher",
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
    /// Legacy stored `op://` reference, left empty by public projection.
    /// Explicit custody operations use [`Store::arc_key_reference`].
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

/// The selected `fields` in the shape `op item get --fields … --format json`
/// prints them, for the test doubles: `op` leaves `value` out of a field whose
/// value is empty, and prints one object, not an array, when exactly one
/// field is selected.
#[cfg(test)]
fn fields_as_op_prints(mut fields: Vec<Value>) -> Value {
    for field in &mut fields {
        if let Some(field) = field.as_object_mut()
            && field.get("value").and_then(Value::as_str) == Some("")
        {
            field.remove("value");
        }
    }
    if fields.len() == 1 {
        fields.remove(0)
    } else {
        Value::Array(fields)
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
            Kind::NativeHost => format!("erpc {} {name} native-host", self.scope.network),
            Kind::NativeMigration => format!("erpc {} {name} native-migration", self.scope.network),
            Kind::Host => format!("erpc {} {name} host", self.scope.network),
            Kind::Publisher => format!(
                "erpc {} {name} {}-publisher",
                self.scope.network, self.scope.chain
            ),
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

    use super::solana_native::{NativeConfig, NativeHost};
    use super::{EthRpc, Host, InventoryError, Jito, Role, Scope, SolanaRpc, Store, Validator};

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

    #[test]
    fn polygon_original_signer_binding_is_monotonic_and_sentry_policy_remains_mutable() {
        use super::polygon::{PolygonNode, PolygonSentry, PolygonValidator};
        let op = FakeOp::default();
        let dir = tempfile_dir();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "polygon".into(),
                network: "amoy".into(),
            },
            dir.join("polygon-key.lock"),
        );
        let original = PolygonNode {
            name: "validator-one".into(),
            address: "192.0.2.1".into(),
            ssh_user: "ubuntu".into(),
            ssh_port: 22,
            host_key: "fixture-pinned-host".into(),
            network: "amoy".into(),
            role: "validator".into(),
            architecture: "x86_64".into(),
            advertise_ip: "192.0.2.2".into(),
            upstream_ref: format!("op://{}/{}/l1", "a".repeat(26), "b".repeat(26)),
            profile: serde_json::json!({"network":"amoy"}),
            validator: Some(PolygonValidator {
                phase: "observing".into(),
                stake_owner: format!("0x{}", "cd".repeat(20)),
                signer: format!("0x{}", "ab".repeat(20)),
                creation: "c".repeat(32),
                original_ref: String::new(),
                original_ready: false,
                sentries: vec![PolygonSentry {
                    address: "192.0.2.3".into(),
                    bor_node_id: "ab".repeat(64),
                    heimdall_node_id: "cd".repeat(20),
                }],
            }),
            ..PolygonNode::default()
        };
        let saved = store
            .add_polygon_node(&original)
            .expect("public creation binding");
        let mut ready = saved.clone();
        let authority = ready.validator.as_mut().expect("authority");
        authority.original_ref =
            format!("op://{}/{}/signer_secret", "a".repeat(26), "b".repeat(26));
        authority.original_ready = true;
        let ready = store
            .update_polygon_node(&ready)
            .expect("one-way read-back transition");
        for field in ["owner", "signer", "creation", "reference", "readiness"] {
            let mut changed = ready.clone();
            let authority = changed.validator.as_mut().expect("authority");
            match field {
                "owner" => authority.stake_owner = format!("0x{}", "ef".repeat(20)),
                "signer" => authority.signer = format!("0x{}", "ef".repeat(20)),
                "creation" => authority.creation = "d".repeat(32),
                "reference" => {
                    authority.original_ref =
                        format!("op://{}/{}/signer_secret", "a".repeat(26), "c".repeat(26));
                }
                _ => {
                    authority.original_ref.clear();
                    authority.original_ready = false;
                }
            }
            assert!(store.update_polygon_node(&changed).is_err(), "{field}");
        }
        let mut changed = ready.clone();
        changed.validator.as_mut().expect("authority").sentries[0].address = "192.0.2.4".into();
        assert!(store.update_polygon_node(&changed).is_ok());
        let mut shared_owner = original.clone();
        shared_owner.name = "invalid-owner".into();
        shared_owner.address = "192.0.2.5".into();
        let authority = shared_owner.validator.as_mut().expect("authority");
        authority.stake_owner.clone_from(&authority.signer);
        assert!(store.add_polygon_node(&shared_owner).is_err());
    }

    #[test]
    fn polygon_inventory_preserves_owner_and_separates_roles_and_networks() {
        use super::polygon::PolygonNode;
        let op = FakeOp::default();
        let dir = tempfile_dir();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "polygon".into(),
                network: "amoy".into(),
            },
            dir.join("polygon.lock"),
        );
        let original = PolygonNode {
            name: "one".into(),
            address: "192.0.2.1".into(),
            ssh_user: "ubuntu".into(),
            ssh_port: 22,
            host_key: "fixture-pinned-host".into(),
            network: "amoy".into(),
            role: "fullnode".into(),
            architecture: "x86_64".into(),
            advertise_ip: "192.0.2.2".into(),
            upstream_ref: format!("op://{}/{}/l1", "a".repeat(26), "b".repeat(26)),
            profile: serde_json::json!({"network":"amoy"}),
            ..PolygonNode::default()
        };
        let saved = store
            .add_polygon_node(&original)
            .expect("stable reservation");
        assert!(saved.id.is_some());
        let mut duplicate = original.clone();
        duplicate.role = "validator".into();
        duplicate.name = "two".into();
        assert!(store.add_polygon_node(&duplicate).is_err());
        for field in [
            "network",
            "role",
            "architecture",
            "address",
            "name",
            "host_key",
        ] {
            let mut changed = saved.clone();
            match field {
                "network" => changed.network = "mainnet".into(),
                "role" => changed.role = "validator".into(),
                "architecture" => changed.architecture = "aarch64".into(),
                "address" => changed.address = "192.0.2.3".into(),
                "name" => changed.name = "renamed".into(),
                _ => changed.host_key = "changed".into(),
            }
            assert!(store.update_polygon_node(&changed).is_err(), "{field}");
        }
        let mut rotation = saved.clone();
        rotation.upstream_ref = format!("op://{}/{}/l1", "a".repeat(26), "c".repeat(26));
        let rotated = store
            .update_polygon_node(&rotation)
            .expect("explicit parent rotation");
        assert_eq!(rotated.id, saved.id);
        assert!(
            store.update_polygon_node(&saved).is_err(),
            "stale version cannot undo rotation"
        );
    }

    #[test]
    fn the_doubles_print_selected_fields_as_op_does() {
        let field = |label: &str, value: &str| -> Value {
            json!({"id":label,"label":label,"type":"STRING","value":value})
        };
        // An empty value has no key at all.
        assert_eq!(
            super::fields_as_op_prints(vec![field("name", "tv1"), field("region", "")]),
            json!([field("name", "tv1"), {"id":"region","label":"region","type":"STRING"}])
        );
        // One selected field is an object, not an array of one.
        assert_eq!(
            super::fields_as_op_prints(vec![field("region", "")]),
            json!({"id":"region","label":"region","type":"STRING"})
        );
        assert_eq!(
            super::fields_as_op_prints(vec![field("name", "tv1")]),
            field("name", "tv1")
        );
    }

    #[test]
    fn op_errors_keep_the_first_line_without_control_characters_and_at_most_300_long() {
        // What op wrote to standard error goes to a terminal and into --json:
        // no escape sequence, bell, carriage return or other control
        // character of it, and no more than 300 characters.
        let stderr = format!(
            "\n  [ERROR] a\u{1b}[31mb\u{7}c\rd\u{9b}e\u{0}f {}\nan inert second line\n",
            "x".repeat(400)
        );
        let InventoryError::Op { operation, reason } =
            super::op_error("list the inventory", &stderr)
        else {
            panic!("op's failure is an op failure");
        };
        assert_eq!(operation, "list the inventory");
        let shown = format!("[ERROR] a[31mbcdef {}", "x".repeat(400));
        assert_eq!(reason, shown.chars().take(300).collect::<String>());
        assert_eq!(reason.chars().count(), 300);
        assert!(!reason.chars().any(char::is_control), "{reason:?}");
        // Blank standard error says so.
        assert_eq!(
            super::op_error("read the item", " \n\t\n").to_string(),
            "1Password could not read the item: no reason given"
        );
    }

    /// One real round trip through 1Password: create a validator and a host,
    /// read them back, update the host, then remove both. Then what a first
    /// native `erpc v init` stores for a new validator, and the listing
    /// `erpc v list` reads of it. Run by hand with
    /// `ERPC_TEST_VAULT=<vault id>`; it asks 1Password for approval. The
    /// first half removes its validator and host when each of its steps
    /// passes; one that fails can leave them in the vault, under the
    /// `roundtrip` network tag. The native half looks for the items it made,
    /// whatever happened, and removes them or names any it could not. The
    /// native items can only be made in the vault's Solana testnet scope, so
    /// that half refuses a vault that holds such an inventory: name a vault
    /// without one.
    #[test]
    #[ignore = "writes to a real 1Password vault"]
    fn a_real_round_trip_through_1password() {
        use erpc_auth::store::one_password::{Mode, OpCli};
        let vault = std::env::var("ERPC_TEST_VAULT").expect("ERPC_TEST_VAULT");
        let runner = OpCli::from_env(Mode::Desktop, |n| std::env::var_os(n)).expect("op");
        let dir = tempfile_dir();
        let s = Store::new(
            runner.clone(),
            vault.clone(),
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
        let native = real_native_registration(&runner, &vault, &name);
        result.expect("round trip");
        assert!(native.is_empty(), "{}", native.join("\n"));
    }

    /// What a first native `erpc v init` stores for a new validator: its
    /// registration, which leaves four of its fields empty, its host and that
    /// host's settings.
    fn native_registration(name: &str) -> (Validator, NativeHost, NativeConfig) {
        use erpc_chain_solana_native::contract::{Contract, Volumes, host_binding};
        let reference = |item: &str| format!("op://{}/{}/keypair", "v".repeat(26), item.repeat(26));
        let source = erpc_chain_solana_native::catalog()
            .expect("catalog")
            .networks
            .remove("testnet")
            .expect("a testnet release");
        let key = host("x", "198.51.100.8", Role::Primary).host_key;
        let validator = Validator {
            name: name.to_owned(),
            identity_account: "2".repeat(44),
            identity_ref: reference("k"),
            vote_account: "3".repeat(44),
            authority_account: "4".repeat(44),
            client: "agave".to_owned(),
            version: source.version,
            commit: source.commit,
            ..Validator::default()
        };
        let node = NativeHost {
            item_version: 0,
            address: "198.51.100.8".to_owned(),
            ssh_user: "ubuntu".to_owned(),
            ssh_port: 22,
            contract: Contract {
                schema: 1,
                profile: "agave-native".to_owned(),
                inventory_id: String::new(),
                name: name.to_owned(),
                network: "testnet".to_owned(),
                host_binding: host_binding("198.51.100.8", "ubuntu", 22, &key),
                identity_account: validator.identity_account.clone(),
                vote_account: Some(validator.vote_account.clone()),
                authority_account: Some(validator.authority_account.clone()),
                volumes: Volumes {
                    accounts: "10000000-0000-0000-0000-000000000001".to_owned(),
                    ledger: "10000000-0000-0000-0000-000000000002".to_owned(),
                    snapshots: "10000000-0000-0000-0000-000000000003".to_owned(),
                },
            },
            host_key: key,
        };
        let settings = NativeConfig {
            identity_ref: reference("k"),
            sync_ref: Some(reference("s")),
            sync_identity: Some("5".repeat(44)),
            rpc_allow: Vec::new(),
            management_allow: Vec::new(),
            commission: Some(5),
        };
        (validator, node, settings)
    }

    /// The native half of the real round trip, and what went wrong in it:
    /// this is where the way 1Password keeps and prints an empty field shows.
    /// Whatever happened, the items are found again by their titles and
    /// removed.
    fn real_native_registration(
        runner: &erpc_auth::store::one_password::OpCli,
        vault: &str,
        name: &str,
    ) -> Vec<String> {
        use super::Kind;
        let s = Store::new(
            runner.clone(),
            vault,
            Scope {
                chain: "solana".to_owned(),
                network: "testnet".to_owned(),
            },
            tempfile_dir().join("inventory.lock"),
        );
        // A test item must never sit beside a real one, or be listed with it.
        for kind in [
            Kind::Validator,
            Kind::Host,
            Kind::Rpc,
            Kind::NativeHost,
            Kind::NativeMigration,
        ] {
            match s.items(kind) {
                Ok(items) if items.is_empty() => {}
                Ok(_) => {
                    return vec![
                        "the vault holds a Solana testnet inventory, so the native half wrote \
                         nothing; name a vault without one"
                            .to_owned(),
                    ];
                }
                Err(e) => return vec![format!("the vault could not be looked through: {e}")],
            }
        }
        let (validator, node, settings) = native_registration(name);
        let outcome = (|| {
            let stored = s
                .add_native_solana_validator(&validator, &node)
                .map_err(|e| format!("the registration was not stored: {e}"))?;
            s.add_configured_solana_native_host(&node, &settings)
                .map_err(|e| format!("the native host was not stored: {e}"))?;
            let rows = s
                .solana_node_summaries(false)
                .map_err(|e| format!("the validators were not listed: {e}"))?;
            let row = rows
                .iter()
                .find(|row| row["name"] == name)
                .ok_or("the registration is not in the listing")?;
            if row["backend"] != "native" || row["region"] != "" {
                return Err(format!("the registration is listed as {row}"));
            }
            let id = stored.id.as_deref().ok_or("the registration has no id")?;
            an_empty_field_alone(runner, vault, id)
        })();
        let mut problems: Vec<String> = outcome.err().into_iter().collect();
        for kind in [Kind::NativeHost, Kind::Validator] {
            let title = s.title(kind, name);
            match s.items(kind) {
                Ok(items) => {
                    for item in items.iter().filter(|item| item.title == title) {
                        if let Err(e) = s.remove(&item.id) {
                            problems.push(format!("{title:?} is still in the vault: {e}"));
                        }
                    }
                }
                Err(e) => problems.push(format!("{title:?} may still be in the vault: {e}")),
            }
        }
        problems
    }

    /// Selects the registration's empty region alone, says how 1Password
    /// printed it, and reads it as the inventory does.
    fn an_empty_field_alone(
        runner: &erpc_auth::store::one_password::OpCli,
        vault: &str,
        id: &str,
    ) -> Result<(), String> {
        let selector = [
            "item",
            "get",
            id,
            "--vault",
            vault,
            "--fields",
            "label=region",
            "--format",
            "json",
        ];
        let reply = runner.run(&selector, None).map_err(|e| e.to_string())?;
        if !reply.success {
            return Err(super::op_error("read the item", &reply.stderr).to_string());
        }
        let with = |key: &str| {
            if reply.stdout.contains(key) {
                "with"
            } else {
                "without"
            }
        };
        println!(
            "1Password printed one selected field as an {}, {} a value key and {} a section key",
            if reply.stdout.trim_start().starts_with('{') {
                "object"
            } else {
                "array"
            },
            with("\"value\""),
            with("\"section\""),
        );
        let raw = SecretString::from(reply.stdout);
        let field = super::solana_public::selected_fields(&raw, &["region"])
            .map_err(|e| format!("an empty field selected alone was not read: {e}"))?;
        if field["region"].expose_secret().is_empty() {
            Ok(())
        } else {
            Err("the empty region did not read back empty".to_owned())
        }
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
    fn hyperliquid_rpc_records_cannot_change_original_network_or_accept_wallet_fields() {
        use super::hyperliquid::HyperliquidNode;
        use erpc_chain_hyperliquid::{Network, contract::Contract};
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "hyperliquid".into(),
                network: "testnet".into(),
            },
            tempfile_dir().join("hyperliquid.lock"),
        );
        let node = HyperliquidNode {
            id: None,
            item_version: 0,
            name: "hyper1".into(),
            address: "192.0.2.44".into(),
            ssh_user: "ubuntu".into(),
            ssh_port: 22,
            host_key: "inert-host-key".into(),
            contract: Contract {
                owner: "a".repeat(32),
                network: Network::Testnet,
                role: "rpc".into(),
                public_ip: "8.8.8.8".into(),
                validator: None,
            },
            supervisor_sha256: "b".repeat(64),
            signed_at: 1_788_863_627,
            rpc_allow: vec![],
            management_allow: vec![],
            last_run: String::new(),
            last_result: String::new(),
        };
        let saved = store
            .add_hyperliquid_node(&node)
            .expect("new public ownership");
        assert!(store.add_hyperliquid_node(&node).is_err());
        for kind in 0..4 {
            let mut changed = saved.clone();
            match kind {
                0 => changed.contract.network = Network::Mainnet,
                1 => changed.contract.public_ip = "1.1.1.1".into(),
                2 => changed.ssh_port = 2222,
                _ => changed.contract.role = "validator".into(),
            }
            assert!(store.update_hyperliquid_node(&changed).is_err());
        }
        let mut updated = saved.clone();
        updated.last_result = "prepared".into();
        store
            .update_hyperliquid_node(&updated)
            .expect("same owner result");
        assert!(store.update_hyperliquid_node(&saved).is_err());
        let mut corrupted = serde_json::to_value(saved).expect("public record");
        corrupted["wallet_material"] = json!("inert unexpected authority");
        {
            let mut items = op.items.borrow_mut();
            let fields = items[0]["fields"].as_array_mut().unwrap();
            fields
                .iter_mut()
                .find(|field| field["label"] == "hyperliquid_record")
                .unwrap()["value"] = json!(corrupted.to_string());
        }
        assert!(store.hyperliquid_nodes().is_err());
        assert!(
            op.calls
                .borrow()
                .iter()
                .all(|args| !args.join(" ").contains("192.0.2.44"))
        );
    }

    #[test]
    fn hyperliquid_validator_preserves_original_hot_authority_and_excludes_rpc_hosts() {
        use super::hyperliquid::HyperliquidNode;
        use super::hyperliquid_validator::{Mode, ValidatorNode};
        use erpc_chain_hyperliquid::{Network, contract::Contract, validator::HotMaterial};
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "hyperliquid".into(),
                network: "testnet".into(),
            },
            tempfile_dir().join("hl-validator.lock"),
        );
        let key =
            HotMaterial::parse(format!("{{\"key\":\"{}\"}}", "01".repeat(32)).into()).unwrap();
        let node = ValidatorNode {
            host: HyperliquidNode {
                id: None,
                item_version: 0,
                name: "val1".into(),
                address: "192.0.2.45".into(),
                ssh_user: "ubuntu".into(),
                ssh_port: 22,
                host_key: "inert-host-key".into(),
                contract: Contract {
                    owner: "a".repeat(32),
                    network: Network::Testnet,
                    role: "validator".into(),
                    public_ip: "8.8.8.8".into(),
                    validator: Some(
                        key.identity(&format!("0x{}", "ab".repeat(20)), "0.01")
                            .unwrap(),
                    ),
                },
                supervisor_sha256: "b".repeat(64),
                signed_at: 1_788_863_627,
                rpc_allow: vec![],
                management_allow: vec![],
                last_run: String::new(),
                last_result: String::new(),
            },
            hot_key_ref: format!("op://{}/{}/consensus", "a".repeat(26), "b".repeat(26)),
            mode: Mode::Follower,
        };
        assert!(!format!("{node:?}").contains(&node.hot_key_ref));
        let saved = store.add_hyperliquid_validator(&node).unwrap();
        assert!(store.add_hyperliquid_validator(&node).is_err());
        let mut rpc = node.host.clone();
        rpc.contract.role = "rpc".into();
        rpc.contract.validator = None;
        assert!(store.add_hyperliquid_node(&rpc).is_err());
        for change in 0..7 {
            let mut wrong = saved.clone();
            match change {
                0 => wrong.host.contract.network = Network::Mainnet,
                1 => wrong.hot_key_ref = "https://github.com".into(),
                2 => wrong.host.contract.validator.as_mut().unwrap().max_hot_usdc = "1".into(),
                3 => wrong.host.contract.public_ip = "1.1.1.1".into(),
                4 => wrong.host.rpc_allow = vec!["192.0.2.20".into()],
                5 => wrong.host.ssh_port = 2222,
                _ => {
                    wrong.hot_key_ref = format!("op://{}/{}/other", "a".repeat(26), "b".repeat(26));
                }
            }
            assert!(store.update_hyperliquid_validator(&wrong).is_err());
        }
        let mut active = saved.clone();
        active.mode = Mode::Validator;
        let active = store.update_hyperliquid_validator(&active).unwrap();
        let mut downgrade = active.clone();
        downgrade.mode = Mode::Follower;
        assert!(store.update_hyperliquid_validator(&downgrade).is_err());
        assert!(store.update_hyperliquid_validator(&saved).is_err());
        assert_eq!(store.hyperliquid_validators().unwrap()[0], active);
        assert!(
            op.calls
                .borrow()
                .iter()
                .all(|args| !args.join(" ").contains(&node.hot_key_ref))
        );
        // Reverse reservation order is refused as well.
        let other_op = FakeOp::default();
        let other = Store::new(
            &other_op,
            "vaultid",
            Scope {
                chain: "hyperliquid".into(),
                network: "testnet".into(),
            },
            tempfile_dir().join("hl-reverse.lock"),
        );
        other.add_hyperliquid_node(&rpc).unwrap();
        assert!(other.add_hyperliquid_validator(&node).is_err());
    }

    fn aqa_fixture() -> super::hyperliquid_aqa::Publisher {
        use erpc_chain_hyperliquid::{Network, aqa};
        let material =
            aqa::AgentMaterial::parse(format!("{{\"key\":\"{}\"}}", "02".repeat(32)).into())
                .unwrap();
        super::hyperliquid_aqa::Publisher {
            id: None,
            item_version: 0,
            name: "publisher1".into(),
            address: "192.0.2.46".into(),
            ssh_user: "ubuntu".into(),
            ssh_port: 2222,
            host_key: "inert-aqa-host-key".into(),
            contract: aqa::Contract {
                schema: 1,
                profile: "hyperliquid-aqa".into(),
                owner: "c".repeat(32),
                network: Network::Testnet,
                host_binding: aqa::host_binding("192.0.2.46", "ubuntu", 2222, "inert-aqa-host-key"),
                identity: material
                    .identity(
                        &format!("0x{}", "ab".repeat(20)),
                        &format!("0x{}", "cd".repeat(20)),
                        &format!("0x{}", "ef".repeat(20)),
                        "original-agent",
                    )
                    .unwrap(),
            },
            agent_key_ref: format!("op://{}/{}/agent", "a".repeat(26), "b".repeat(26)),
            version: "1.2.0".into(),
            archive_sha256: "e".repeat(64),
            signed_at: 1_774_922_628,
            management_allow: vec![],
            last_run: String::new(),
            last_result: String::new(),
        }
    }

    #[test]
    fn aqa_inventory_keeps_original_separate_host_agent_and_concealed_identifier() {
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "hyperliquid".into(),
                network: "testnet".into(),
            },
            tempfile_dir().join("aqa.lock"),
        );
        let node = aqa_fixture();
        assert!(!format!("{node:?}").contains(&node.agent_key_ref));
        let saved = store.add_hyperliquid_publisher(&node).unwrap();
        for change in 0..7 {
            let mut duplicate = node.clone();
            duplicate.name = "publisher2".into();
            duplicate.address = "192.0.2.47".into();
            duplicate.host_key = "inert-second-host-key".into();
            duplicate.contract.owner = "d".repeat(32);
            duplicate.agent_key_ref =
                format!("op://{}/{}/second-agent", "a".repeat(26), "b".repeat(26));
            let key = erpc_chain_hyperliquid::aqa::AgentMaterial::parse(
                format!("{{\"key\":\"{}\"}}", "03".repeat(32)).into(),
            )
            .unwrap();
            duplicate.contract.identity = key
                .identity(
                    &node.contract.identity.validator,
                    &node.contract.identity.consensus_signer,
                    &node.contract.identity.agent_master,
                    "second-agent",
                )
                .unwrap();
            match change {
                0 => duplicate.name = node.name.clone(),
                1 => duplicate.address = node.address.clone(),
                2 => duplicate.host_key = node.host_key.clone(),
                3 => duplicate.contract.owner = node.contract.owner.clone(),
                4 => duplicate.contract.identity = node.contract.identity.clone(),
                5 => duplicate.agent_key_ref = node.agent_key_ref.clone(),
                _ => duplicate.agent_key_ref = "https://github.com/inert-private-value".into(),
            }
            duplicate.contract.host_binding = erpc_chain_hyperliquid::aqa::host_binding(
                &duplicate.address,
                &duplicate.ssh_user,
                duplicate.ssh_port,
                &duplicate.host_key,
            );
            assert!(store.add_hyperliquid_publisher(&duplicate).is_err());
        }
        for change in 0..6 {
            let mut wrong = saved.clone();
            match change {
                0 => wrong.ssh_port = 22,
                1 => wrong.contract.identity.agent_name = "replacement".into(),
                2 => {
                    wrong.agent_key_ref =
                        format!("op://{}/{}/replacement", "a".repeat(26), "b".repeat(26));
                }
                3 => wrong.contract.network = erpc_chain_hyperliquid::Network::Mainnet,
                4 => wrong.signed_at -= 1,
                _ => wrong.management_allow = vec!["0.0.0.0/0".into()],
            }
            assert!(store.update_hyperliquid_publisher(&wrong).is_err());
        }
        let mut update = saved.clone();
        update.last_result = "stopped; ciphertext retained".into();
        let update = store.update_hyperliquid_publisher(&update).unwrap();
        assert!(store.update_hyperliquid_publisher(&saved).is_err());
        assert_eq!(store.hyperliquid_publishers().unwrap(), vec![update]);
        assert!(
            op.calls
                .borrow()
                .iter()
                .all(|args| !args.join(" ").contains(&node.agent_key_ref))
        );
        let mut items = op.items.borrow_mut();
        let fields = items[0]["fields"].as_array_mut().unwrap();
        let record = fields
            .iter_mut()
            .find(|field| field["label"] == "hyperliquid_aqa_record")
            .unwrap();
        let mut corrupt: serde_json::Value =
            serde_json::from_str(record["value"].as_str().unwrap()).unwrap();
        corrupt["private_key"] = json!("inert unexpected authority");
        record["value"] = json!(corrupt.to_string());
        drop(items);
        assert!(store.hyperliquid_publishers().is_err());
    }

    #[test]
    fn publisher_and_rpc_cannot_share_a_host_in_either_reservation_order() {
        use super::hyperliquid::HyperliquidNode;
        use erpc_chain_hyperliquid::{Network, contract::Contract};
        let aqa = aqa_fixture();
        let rpc = HyperliquidNode {
            id: None,
            item_version: 0,
            name: "rpc1".into(),
            address: aqa.address.clone(),
            ssh_user: "ubuntu".into(),
            ssh_port: 22,
            host_key: "inert-rpc-host-key".into(),
            contract: Contract {
                owner: "f".repeat(32),
                network: Network::Testnet,
                role: "rpc".into(),
                public_ip: "8.8.8.8".into(),
                validator: None,
            },
            supervisor_sha256: "a".repeat(64),
            signed_at: 1_788_863_627,
            rpc_allow: vec![],
            management_allow: vec![],
            last_run: String::new(),
            last_result: String::new(),
        };
        for publisher_first in [true, false] {
            let op = FakeOp::default();
            let store = Store::new(
                &op,
                "vaultid",
                Scope {
                    chain: "hyperliquid".into(),
                    network: "testnet".into(),
                },
                tempfile_dir().join("aqa-separate.lock"),
            );
            if publisher_first {
                store.add_hyperliquid_publisher(&aqa).unwrap();
                assert!(store.add_hyperliquid_node(&rpc).is_err());
            } else {
                store.add_hyperliquid_node(&rpc).unwrap();
                assert!(store.add_hyperliquid_publisher(&aqa).is_err());
            }
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
    #[test]
    fn near_inventory_preserves_owned_host_and_rejects_stale_writers() {
        use super::near::NearRpc;
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "near".into(),
                network: "testnet".into(),
            },
            tempfile_dir().join("near.lock"),
        );
        let node = NearRpc {
            name: "near1".into(),
            address: "192.0.2.55".into(),
            platform: "x86_64".into(),
            version: "2.14.0-rc.6".into(),
            commit: "a".repeat(40),
            ..NearRpc::default()
        };
        let stored = store.add_near_rpc(&node).expect("reserve owner");
        assert!(store.add_near_rpc(&node).is_err());
        let mut changed = stored.clone();
        changed.address = "192.0.2.56".into();
        assert!(store.update_near_rpc(&changed).is_err());
        changed = stored.clone();
        changed.platform = "aarch64".into();
        assert!(store.update_near_rpc(&changed).is_err());
        changed = stored.clone();
        changed.rpc_allow = vec!["192.0.2.0/24".into()];
        let updated = store
            .update_near_rpc(&changed)
            .expect("change desired policy");
        assert_eq!(updated.rpc_allow, changed.rpc_allow);
        assert!(store.update_near_rpc(&stored).is_err());
        assert_eq!(store.near_rpcs().expect("list"), vec![updated]);
        assert!(
            op.calls
                .borrow()
                .iter()
                .all(|args| !args.join(" ").contains("192.0.2."))
        );
    }

    #[test]
    fn near_validator_inventory_is_role_scoped_and_cannot_replace_consensus_identity() {
        use super::near::{NearRpc, Validator};
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "near".into(),
                network: "testnet".into(),
            },
            tempfile_dir().join("near-validator.lock"),
        );
        let node = NearRpc {
            name: "validator".into(),
            address: "192.0.2.55".into(),
            platform: "x86_64".into(),
            version: "2.14.0-rc.6".into(),
            commit: "a".repeat(40),
            validator: Some(Validator {
                account_id: "fixture.pool.f863973.m0".into(),
                owner_account: "owner.testnet".into(),
                public_key: "ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z".into(),
                key_ref: format!("op://{}/{}/validator", "a".repeat(26), "b".repeat(26)),
                commission_basis_points: 500,
            }),
            ..NearRpc::default()
        };
        let stored = store.add_near_rpc(&node).expect("validator reservation");
        assert!(store.near_rpcs().expect("RPC scope").is_empty());
        assert_eq!(
            store.near_nodes(true).expect("validator scope"),
            vec![stored.clone()]
        );
        let mut rpc = node.clone();
        rpc.validator = None;
        rpc.name = "rpc".into();
        assert!(
            store.add_near_rpc(&rpc).is_err(),
            "same host cannot be reserved under another role"
        );
        rpc.address = "192.0.2.56".into();
        store.add_near_rpc(&rpc).expect("separate RPC host");
        let mut duplicate = node.clone();
        duplicate.name = "other-validator".into();
        duplicate.address = "192.0.2.57".into();
        assert!(
            store.add_near_rpc(&duplicate).is_err(),
            "dedicated consensus identity cannot be reserved twice"
        );
        for change in 0..5 {
            let mut changed = stored.clone();
            let validator = changed.validator.as_mut().expect("validator");
            match change {
                0 => validator.account_id = "other.pool.f863973.m0".into(),
                1 => validator.owner_account = "another.testnet".into(),
                2 => validator.public_key = "different".into(),
                3 => validator.commission_basis_points = 1000,
                _ => {
                    validator.key_ref =
                        format!("op://{}/{}/validator", "c".repeat(26), "d".repeat(26));
                }
            }
            assert!(store.update_near_rpc(&changed).is_err());
        }
        let mut changed = stored.clone();
        changed.validator = None;
        assert!(store.update_near_rpc(&changed).is_err());
        changed = stored;
        changed.rpc_allow = vec!["192.0.2.0/24".into()];
        assert!(
            store.update_near_rpc(&changed).is_err(),
            "validator RPC remains local"
        );
    }

    #[test]
    fn bsc_inventory_freezes_host_retention_snapshot_and_refuses_stale_writes() {
        use super::bsc::BscRpc;
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "bsc".into(),
                network: "chapel".into(),
            },
            tempfile_dir().join("bsc.lock"),
        );
        let node = BscRpc {
            name: "bsc1".into(),
            address: "192.0.2.42".into(),
            ssh_port: 22,
            version: "1.8.1".into(),
            commit: "a".repeat(40),
            platform: "amd64".into(),
            storage: "full".into(),
            snapshot: "testnet-fixture".into(),
            ..BscRpc::default()
        };
        let stored = store.add_bsc_rpc(&node).expect("reserved");
        assert_eq!(store.bsc_rpcs().expect("list"), vec![stored.clone()]);
        for field in ["address", "host_key", "platform", "storage", "snapshot"] {
            let mut changed = serde_json::to_value(&stored).expect("record");
            changed[field] = json!("different");
            let mut changed: BscRpc = serde_json::from_value(changed).expect("record");
            changed.id.clone_from(&stored.id);
            changed.item_version = stored.item_version;
            assert!(store.update_bsc_rpc(&changed).is_err(), "{field}");
        }
        let mut changed = stored.clone();
        changed.last_result = "prepared".into();
        store.update_bsc_rpc(&changed).expect("result update");
        assert!(store.update_bsc_rpc(&stored).is_err());
        assert!(store.add_bsc_rpc(&node).is_err());
        assert!(
            op.calls
                .borrow()
                .iter()
                .all(|args| !args.join(" ").contains("192.0.2."))
        );
    }
    #[test]
    fn bsc_signer_reservation_survives_rejected_replacement_and_retirement() {
        use super::{bsc::BscRpc, bsc_validator::BscValidator};
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "bsc".into(),
                network: "chapel".into(),
            },
            tempfile_dir().join("bsc-validator.lock"),
        );
        let new = |name: &str, address: &str| BscValidator {
            node: BscRpc {
                name: name.into(),
                address: address.into(),
                ssh_port: 22,
                version: "1.8.1".into(),
                commit: "a".repeat(40),
                platform: "amd64".into(),
                storage: "full".into(),
                snapshot: "testnet-fixture".into(),
                ..BscRpc::default()
            },
            operator: format!("0x{}", "2".repeat(40)),
            custody: "unprovisioned".into(),
            ..BscValidator::default()
        };
        let mut first = store
            .add_bsc_validator(&new("first", "192.0.2.42"))
            .expect("fresh reservation");
        assert!(store.add_bsc_rpc(&first.node).is_err());
        let mut second = store
            .add_bsc_validator(&new("second", "192.0.2.43"))
            .expect("second host");
        first.consensus = format!("0x{}", "3".repeat(40));
        first.vote = "4".repeat(96);
        first.proof = format!("0x{}", "5".repeat(192));
        first.custody = "owned".into();
        first = store
            .update_bsc_validator(&first)
            .expect("host public receipt reserved");
        for (field, replacement) in [
            ("operator", String::new()),
            ("consensus", String::new()),
            ("vote", String::new()),
            ("proof", String::new()),
            ("custody", String::new()),
            ("operator", format!("0x{}", "9".repeat(40))),
            ("consensus", format!("0x{}", "6".repeat(40))),
            ("vote", "7".repeat(96)),
            ("proof", format!("0x{}", "8".repeat(192))),
        ] {
            let mut altered = serde_json::to_value(&first).expect("public record");
            altered[field] = json!(replacement);
            let mut altered: BscValidator = serde_json::from_value(altered).expect("public record");
            altered.node.id.clone_from(&first.node.id);
            altered.node.item_version = first.node.item_version;
            assert!(store.update_bsc_validator(&altered).is_err());
            assert_eq!(
                store
                    .bsc_validators()
                    .expect("unchanged reservation")
                    .into_iter()
                    .find(|n| n.node.id == first.node.id)
                    .expect("first"),
                first
            );
        }
        second.consensus.clone_from(&first.consensus);
        second.vote.clone_from(&first.vote);
        second.proof.clone_from(&first.proof);
        second.custody = "owned".into();
        assert!(store.update_bsc_validator(&second).is_err());
        first.node.last_result = "destroy complete; keys retained".into();
        store
            .update_bsc_validator(&first)
            .expect("retirement result");
        assert!(store.update_bsc_validator(&second).is_err());
    }

    #[test]
    fn monad_reservations_preserve_physical_device_keys_and_financial_authorities() {
        use super::monad::MonadNode;
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "monad".into(),
                network: "testnet".into(),
            },
            tempfile_dir().join("monad.lock"),
        );
        let c = erpc_chain_monad::contract::Contract {
            owner: "ab".repeat(16),
            network: "testnet".into(),
            role: "validator".into(),
            partuuid: "abcdefab-abcd-abcd-abcd-abcdefabcdef".into(),
            public_ip: "8.8.8.8".into(),
            name_record_sequence: 1,
            // Public SEC1 generator, no private material or native key generation.
            secp: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            bls: "ab".repeat(48),
            beneficiary: format!("0x{}", "cd".repeat(20)),
            auth_address: format!("0x{}", "ef".repeat(20)),
        };
        let n = MonadNode {
            id: None,
            item_version: 0,
            name: "node".into(),
            address: "192.0.2.60".into(),
            ssh_user: "ubuntu".into(),
            ssh_port: 22,
            host_key: String::new(),
            contract: c,
            keys_ref: format!("op://{}/{}/keys", "a".repeat(26), "b".repeat(26)),
            version: "0.16.5".into(),
            consensus_commit: "a".repeat(40),
            execution_commit: "b".repeat(40),
            rpc_allow: vec![],
            management_allow: vec![],
            monitoring_allow: vec![],
            last_run: String::new(),
            last_result: String::new(),
        };
        let saved = store.add_monad_node(&n).expect("new ownership");
        assert!(store.monad_nodes("rpc").unwrap().is_empty());
        for change in 0..6 {
            let mut altered = saved.clone();
            match change {
                0 => altered.contract.partuuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into(),
                1 => altered.contract.owner = "bc".repeat(16),
                2 => altered.contract.beneficiary = format!("0x{}", "ba".repeat(20)),
                3 => altered.contract.auth_address = format!("0x{}", "dc".repeat(20)),
                4 => altered.keys_ref = format!("op://{}/{}/keys", "c".repeat(26), "d".repeat(26)),
                _ => altered.contract.name_record_sequence = 2,
            }
            assert!(store.update_monad_node(&altered).is_err());
        }
        let mut different = n.clone();
        different.contract.network = "mainnet".into();
        different.address = "192.0.2.61".into();
        different.name = "different".into();
        assert!(store.add_monad_node(&different).is_err());
        different.contract.network = "testnet".into();
        assert!(
            store.add_monad_node(&different).is_err(),
            "duplicate consensus identity"
        );
        different.keys_ref = "not-a-secret-reference".into();
        assert!(store.add_monad_node(&different).is_err());
        let mut updated = saved;
        updated.last_result = "stopped".into();
        store.update_monad_node(&updated).expect("result update");
    }

    #[test]
    fn kaia_inventory_preserves_network_genesis_and_original_bootstrap() {
        use super::kaia::KaiaRpc;
        let op = FakeOp::default();
        let directory = tempfile_dir();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "kaia".into(),
                network: "kairos".into(),
            },
            directory.join("kaia.lock"),
        );
        let original = KaiaRpc {
            name: "endpoint".into(),
            network: "kairos".into(),
            genesis: format!("0x{}", "a".repeat(64)),
            address: "192.0.2.1".into(),
            ssh_user: "ubuntu".into(),
            ssh_port: 22,
            host_key: "fixture".into(),
            version: "2.2.2".into(),
            commit: "b".repeat(40),
            image: format!("docker.io/kaiachain/kaia@sha256:{}", "c".repeat(64)),
            platform: "amd64".into(),
            storage: "full".into(),
            snapshot: "genesis".into(),
            ..KaiaRpc::default()
        };
        let saved = store.add_kaia_rpc(&original).unwrap();
        let mut duplicate = original.clone();
        duplicate.name = "other".into();
        assert!(store.add_kaia_rpc(&duplicate).is_err());
        for change in 0..7 {
            let mut changed = saved.clone();
            match change {
                0 => changed.network = "mainnet".into(),
                1 => changed.genesis = format!("0x{}", "d".repeat(64)),
                2 => changed.address = "192.0.2.2".into(),
                3 => changed.host_key = "different".into(),
                4 => changed.ssh_port = 2222,
                5 => changed.ssh_user = "another-user".into(),
                _ => {
                    changed.storage = "pruned".into();
                    changed.snapshot =
                        "kaia-kairos-pruning-chaindata-20261026010014.tar.zst".into();
                }
            }
            assert!(store.update_kaia_rpc(&changed).is_err());
        }
        let mut policy = saved.clone();
        policy.management_allow.push("198.51.100.1".into());
        store.update_kaia_rpc(&policy).unwrap();
        assert!(store.update_kaia_rpc(&saved).is_err());
    }

    /// One real round trip through 1Password: create a validator and a host,
    /// read them back, update the host, then remove both. Run by hand with
    /// `ERPC_TEST_VAULT=<vault id>`; it asks 1Password for approval.

    #[test]
    fn kaia_corecell_reservations_preserve_host_role_and_established_custody() {
        use super::{kaia::KaiaRpc, kaia_corecell::KaiaCoreCell};
        let op = FakeOp::default();
        let store = Store::new(
            &op,
            "vaultid",
            Scope {
                chain: "kaia".into(),
                network: "kairos".into(),
            },
            tempfile_dir().join("kaia-cell.lock"),
        );
        let fresh = KaiaCoreCell {
            node: KaiaRpc {
                name: "core1".into(),
                network: "kairos".into(),
                genesis: format!("0x{}", "a".repeat(64)),
                address: "192.0.2.10".into(),
                ssh_user: "ubuntu".into(),
                ssh_port: 22,
                host_key: "inert-host-key".into(),
                version: "2.2.2".into(),
                commit: "a".repeat(40),
                image: format!("docker.io/kaiachain/kaia@sha256:{}", "b".repeat(64)),
                platform: "amd64".into(),
                storage: "full".into(),
                snapshot: "genesis".into(),
                ..KaiaRpc::default()
            },
            node_kind: "cn".into(),
            advertise: "192.0.2.10".into(),
            peers: vec![
                "kni://public-fixture-cn".into(),
                "kni://public-fixture-pn".into(),
            ],
            reward_address: format!("0x{}", "a".repeat(40)),
            manager_address: format!("0x{}", "b".repeat(40)),
            gc_id: "17".into(),
            ..KaiaCoreCell::default()
        };
        let reserved = store.add_kaia_corecell(&fresh).unwrap();
        assert!(store.add_kaia_rpc(&fresh.node).is_err());
        let mut established = reserved.clone();
        established.node_address = format!("0x{}", "c".repeat(40));
        established.peer_key = "d".repeat(128);
        established.bls_key = "e".repeat(96);
        established.bls_pop = "f".repeat(192);
        let established = store.update_kaia_corecell(&established).unwrap();
        for change in 0..6 {
            let mut value = established.clone();
            match change {
                0 => value.node.address = "192.0.2.11".into(),
                1 => value.node_kind = "pn".into(),
                2 => value.node_address = format!("0x{}", "d".repeat(40)),
                3 => value.bls_key = "a".repeat(96),
                4 => {
                    value.node_address.clear();
                    value.peer_key.clear();
                    value.bls_key.clear();
                    value.bls_pop.clear();
                }
                _ => value.node.network = "mainnet".into(),
            }
            assert!(store.update_kaia_corecell(&value).is_err());
        }
        assert!(store.update_kaia_corecell(&reserved).is_err());
        assert_eq!(store.kaia_corecells().unwrap(), vec![established.clone()]);
        let mut other = fresh;
        other.node.name = "core2".into();
        other.node.address = "192.0.2.20".into();
        other.advertise = "192.0.2.20".into();
        let mut other = store.add_kaia_corecell(&other).unwrap();
        other.node_address = established.node_address;
        other.peer_key = established.peer_key;
        other.bls_key = established.bls_key;
        other.bls_pop = established.bls_pop;
        assert!(store.update_kaia_corecell(&other).is_err());
        assert!(
            store
                .kaia_corecells()
                .unwrap()
                .iter()
                .any(|value| value.node.name == "core2" && value.node_address.is_empty())
        );
    }
}
