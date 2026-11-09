// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public, durable reservations for explicitly selected Solv copy migrations.
//! A reservation never creates native runtime authority or copies a private key.
use super::solana_migration_item::MigrationItem;
use super::solana_migration_reference::RegisteredIdentity;
use super::{
    FORMAT, InventoryError, Kind, OpRunner, Store,
    solana_migration::{LegacySource, PublicRecord},
    solana_native::{NativeConfig, NativeHost},
    solana_public::selected_fields,
};
use erpc_chain_solana_native::migration_request::{Action, Original, Request};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

const LABELS: &[&str] = &["erpc_format", "name", "native_migration"];
const SELECTOR: &str = "label=erpc_format,label=name,label=native_migration";
fn invalid() -> InventoryError {
    InventoryError::Unreadable("public Solana migration reservation")
}

fn canonical_address(value: &str) -> Result<String, InventoryError> {
    erpc_ssh::config::check_host(value).map_err(|_| invalid())?;
    Ok(value.parse::<std::net::IpAddr>().map_or_else(
        |_| value.trim_end_matches('.').to_ascii_lowercase(),
        |address| address.to_string(),
    ))
}

// Unlike public plans, the durable inventory snapshot retains original item IDs.
// It is never returned as CLI output or used as an authority without rereading.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedRecord {
    id: String,
    version: u64,
    fields: BTreeMap<String, String>,
}
impl From<&PublicRecord> for SavedRecord {
    fn from(value: &PublicRecord) -> Self {
        Self {
            id: value.item_id.clone(),
            version: value.item_version,
            fields: value.fields.clone(),
        }
    }
}
impl SavedRecord {
    fn public(&self) -> PublicRecord {
        PublicRecord {
            item_id: self.id.clone(),
            item_version: self.version,
            fields: self.fields.clone(),
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSource {
    network: String,
    rpc: bool,
    selected_host: String,
    node: SavedRecord,
    hosts: Vec<SavedRecord>,
}
impl From<&LegacySource> for SavedSource {
    fn from(value: &LegacySource) -> Self {
        Self {
            network: value.network.clone(),
            rpc: value.rpc,
            selected_host: value.selected_host.clone(),
            node: SavedRecord::from(&value.node),
            hosts: value.hosts.iter().map(SavedRecord::from).collect(),
        }
    }
}
impl SavedSource {
    fn public(&self) -> LegacySource {
        LegacySource {
            network: self.network.clone(),
            rpc: self.rpc,
            selected_host: self.selected_host.clone(),
            node: self.node.public(),
            hosts: self.hosts.iter().map(SavedRecord::public).collect(),
        }
    }
}

/// One immutable migration intent and its original public inventory snapshot.
/// This retains identifier-only original key references, never private values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    schema: u8,
    /// Stable intent, retained on retry rather than regenerated after ambiguity.
    pub intent: String,
    source: SavedSource,
    /// Historical host evidence qualified before any service retirement.
    pub original: Original,
    /// Future native ownership; this item's assigned identity is retained at cutover.
    pub node: NativeHost,
    /// Existing registered identity, absent for non-voting RPC migration.
    pub registered_identity: Option<RegisteredIdentity>,
}
impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingSolanaMigration")
            .finish_non_exhaustive()
    }
}

/// Match the existing public inspection's source binding, including item versions.
/// # Errors
/// Returns an error if the public evidence cannot be represented canonically.
pub fn source_binding(
    source: &LegacySource,
    original: &Original,
) -> Result<String, InventoryError> {
    let identifiers = std::iter::once(&source.node)
        .chain(source.hosts.iter())
        .map(|record| (&record.item_id, record.item_version))
        .collect::<Vec<_>>();
    let history = serde_json::to_value(&original.source_history).map_err(|_| invalid())?;
    let raw = serde_json::to_vec(&(source, identifiers, &original.historical, Some(history)))
        .map_err(|_| invalid())?;
    Ok(format!("{:x}", Sha256::digest(raw)))
}
fn original_networks(raw: &str) -> Result<Vec<String>, InventoryError> {
    let mut networks = std::collections::BTreeSet::new();
    for value in raw.split(',').filter(|value| !value.is_empty()) {
        let (address, prefix) = value
            .split_once('/')
            .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
        let address: std::net::IpAddr = address.parse().map_err(|_| invalid())?;
        let width = if address.is_ipv4() { 32_u8 } else { 128_u8 };
        let prefix = prefix.map_or(Ok(width), |value| {
            value.parse::<u8>().map_err(|_| invalid())
        })?;
        if prefix > width {
            return Err(invalid());
        }
        let bits = match address {
            std::net::IpAddr::V4(v) => u128::from(u32::from(v)),
            std::net::IpAddr::V6(v) => u128::from(v),
        };
        let host_mask = if prefix == 0 {
            u128::MAX
        } else {
            (1_u128 << (width - prefix)) - 1
        };
        let canonical = bits & !host_mask;
        let address = if width == 32 {
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                u32::try_from(canonical).map_err(|_| invalid())?,
            ))
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(canonical))
        };
        networks.insert(format!("{address}/{prefix}"));
    }
    if networks.len() > 64 {
        return Err(invalid());
    }
    Ok(networks.into_iter().collect())
}

impl Pending {
    /// Build a provisional record before the provider assigns its immutable ID.
    /// # Errors
    /// Rejects inconsistent original source, host, network, roles or target volumes.
    pub fn new(
        source: &LegacySource,
        original: Original,
        node: NativeHost,
        intent: String,
        registered_identity: Option<RegisteredIdentity>,
    ) -> Result<Self, InventoryError> {
        if !node.contract.inventory_id.is_empty() || node.item_version != 0 {
            return Err(invalid());
        }
        let record = Self {
            schema: 1,
            intent,
            source: SavedSource::from(source),
            original,
            node,
            registered_identity,
        };
        record.validate()?;
        Ok(record)
    }
    /// Validate a closed protocol before reading credentials or contacting a host.
    /// # Errors
    /// Rejects a different original registration, management target or history.
    pub fn validate(&self) -> Result<(), InventoryError> {
        let mut node = self.node.clone();
        if node.contract.inventory_id.is_empty() {
            node.contract.inventory_id = "a".repeat(26);
        }
        node.validate()?;
        if node.contract.is_rpc() {
            if self.registered_identity.is_some() {
                return Err(invalid());
            }
        } else {
            let reference = self.registered_identity.as_ref().ok_or_else(invalid)?;
            reference.validate()?;
            if reference.public != node.contract.identity_account {
                return Err(invalid());
            }
        }

        let source = self.source.public();
        let fields = &source.node.fields;
        let host = source
            .hosts
            .iter()
            .find(|host| host.fields.get("name") == Some(&source.selected_host))
            .ok_or_else(invalid)?;
        if self.schema != 1
            || source.hosts.len() != 1
            || source.network != node.contract.network
            || source.rpc != node.contract.is_rpc()
            || fields.get("name") != Some(&node.contract.name)
            || fields.get("identity_account") != Some(&node.contract.identity_account)
            || fields.get("client").map(String::as_str) != Some("agave")
            || host.fields.get("address") != Some(&node.address)
            || host.fields.get("host_key") != Some(&node.host_key)
            || host
                .fields
                .get("ssh_port")
                .and_then(|v| v.parse::<u16>().ok())
                != Some(node.ssh_port)
            || self.original.management_user != node.ssh_user
            || self.original.source_sha256 != source_binding(&source, &self.original)?
        {
            return Err(invalid());
        }
        if source.rpc {
            if fields.get("rpc_type").map(String::as_str) != Some("send-tx")
                || [
                    "geyser_version",
                    "geyser_commit",
                    "of1_version",
                    "of1_sha256",
                ]
                .iter()
                .any(|name| fields.get(*name).is_none_or(|value| !value.is_empty()))
            {
                return Err(invalid());
            }
        } else if fields.get("vote_account") != node.contract.vote_account.as_ref()
            || fields.get("authority_account") != node.contract.authority_account.as_ref()
        {
            return Err(invalid());
        }
        for record in std::iter::once(&self.source.node).chain(self.source.hosts.iter()) {
            if record.id.len() != 26
                || !record
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                || record.version == 0
                || record.fields.len() > 32
                || record.fields.iter().any(|(key, value)| {
                    key.len() > 64
                        || value.len() > 4096
                        || value.chars().any(char::is_control)
                        || value.contains("op://")
                })
            {
                return Err(invalid());
            }
        }
        self.request_with_node(Action::MigrationReserve, &node)
            .validate()
            .map_err(|_| invalid())?;
        self.configuration(&format!(
            "op://{}/{}/migration_identity",
            "a".repeat(26),
            "b".repeat(26)
        ))?;
        Ok(())
    }
    fn request_with_node(&self, action: Action, node: &NativeHost) -> Request {
        Request {
            action,
            intent: self.intent.clone(),
            legacy: self.original.clone(),
            contract: node.contract.clone(),
            ssh_port: node.ssh_port,
        }
    }
    /// Preserve the original key targets and network scopes in native metadata.
    /// A bare legacy address becomes its exact host CIDR; no scope is widened.
    /// # Errors
    /// Refuses unsupported access ranges or incomplete original key authority.
    pub fn configuration(&self, backup_reference: &str) -> Result<NativeConfig, InventoryError> {
        let rpc = self.node.contract.is_rpc();
        let configuration = NativeConfig {
            identity_ref: if rpc {
                backup_reference.into()
            } else {
                self.registered_identity
                    .as_ref()
                    .ok_or_else(invalid)?
                    .reference
                    .clone()
            },
            sync_ref: if rpc {
                None
            } else {
                Some(backup_reference.into())
            },
            sync_identity: if rpc {
                None
            } else {
                Some(self.original.host_identity.public.clone())
            },
            rpc_allow: if rpc {
                original_networks(
                    self.source
                        .node
                        .fields
                        .get("rpc_allow")
                        .ok_or_else(invalid)?,
                )?
            } else {
                Vec::new()
            },
            management_allow: if rpc {
                original_networks(
                    self.source
                        .node
                        .fields
                        .get("management_allow")
                        .ok_or_else(invalid)?,
                )?
            } else {
                Vec::new()
            },
            commission: self.original.commission,
        };
        configuration
            .validate(&self.node.contract)
            .map_err(|_| invalid())?;
        Ok(configuration)
    }

    /// Produce a typed request only after durable reservation and readback.
    /// # Errors
    /// Rejects provisional/unconfirmed identity or invalid public scope.
    pub fn request(&self, action: Action) -> Result<Request, InventoryError> {
        self.validate()?;
        if self.node.item_version == 0 || self.node.contract.inventory_id.is_empty() {
            return Err(invalid());
        }
        Ok(self.request_with_node(action, &self.node))
    }
    /// Return only progress-independent public selection metadata.
    #[must_use]
    pub fn summary(&self) -> Value {
        json!({"network":self.node.contract.network,"name":self.node.contract.name,
            "host_name":self.source.selected_host,"backend":"migration","address":self.node.address,
            "identity":self.node.contract.identity_account,"migration_complete":false,"ready":null,
            "runtime_inspected":false})
    }
}

/// Verified stored bytes; the caller additionally derives and compares the
/// public identity before acknowledging native custody. Debug hides references.
pub struct MigrationBackup {
    /// Refreshed item version from the same owned provider item.
    pub pending: Pending,
    /// Identifier-only reference to the same item's original concealed field.
    pub reference: String,
    /// Actual provider readback, never a value copied from the write request.
    pub key: SecretString,
    /// Canonical original plaintext digest for the host custody acknowledgment.
    pub sha256: String,
}
impl std::fmt::Debug for MigrationBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MigrationBackup([REDACTED])")
    }
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BackupReceipt {
    schema: u8,
    intent: String,
    public: String,
    sha256: String,
    field: String,
}
fn backup_digest(key: &SecretString) -> Result<String, InventoryError> {
    if key.expose_secret().is_empty() || key.expose_secret().len() > 4096 {
        return Err(invalid());
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(key.expose_secret().as_bytes())
    ))
}

impl<R: OpRunner> Store<R> {
    /// Resolve the exact original identity pointer using public metadata only.
    /// Friendly legacy vault names become canonical IDs; the target does not change.
    /// # Errors
    /// Refuses changed source records, ambiguous references or another public key.
    pub fn resolve_solana_migration_identity(
        &self,
        source: &LegacySource,
    ) -> Result<Option<RegisteredIdentity>, InventoryError> {
        if self.solana_migration_source(
            &source.node.fields["name"],
            source.rpc,
            &source.selected_host,
        )? != *source
        {
            return Err(invalid());
        }
        let resolved = self.source_registered_identity(source)?;
        if self.solana_migration_source(
            &source.node.fields["name"],
            source.rpc,
            &source.selected_host,
        )? != *source
        {
            return Err(invalid());
        }
        Ok(resolved)
    }

    fn source_registered_identity(
        &self,
        source: &LegacySource,
    ) -> Result<Option<RegisteredIdentity>, InventoryError> {
        if source.rpc {
            return Ok(None);
        }
        let (id, version, reference) = self.public_projection(
            Kind::Validator,
            &source.node.fields["name"],
            "label=erpc_format,label=name,label=identity_ref",
            |raw| {
                let fields = selected_fields(raw, &["erpc_format", "name", "identity_ref"])?;
                if fields["erpc_format"].expose_secret() != FORMAT
                    || fields["name"].expose_secret() != source.node.fields["name"]
                {
                    return Err(invalid());
                }
                Ok(fields["identity_ref"].expose_secret().to_owned())
            },
        )?;
        if id != source.node.item_id || version != source.node.item_version {
            return Err(invalid());
        }
        let resolved = RegisteredIdentity::resolve(
            &self.runner,
            &reference,
            &source.node.fields["identity_account"],
        )?;
        Ok(Some(resolved))
    }

    fn original_migration_item(
        &self,
        record: &Pending,
    ) -> Result<(MigrationItem, String), InventoryError> {
        self.verify_solana_original_migration(record)?;
        let node = &record.node;
        let kind = self.original_migration_kind(&node.contract.name)?;
        let vault = self.public_item_vault(
            kind,
            &node.contract.name,
            &node.contract.inventory_id,
            node.item_version,
        )?;
        let output = self
            .runner
            .run(
                &[
                    "item",
                    "get",
                    &node.contract.inventory_id,
                    "--vault",
                    &vault,
                    "--format",
                    "json",
                    "--reveal",
                ],
                None,
            )
            .map_err(|_| invalid())?;
        let _stderr = SecretString::from(output.stderr);
        let raw = SecretString::from(output.stdout);
        if !output.success {
            return Err(invalid());
        }
        let item = MigrationItem::parse(
            &raw,
            &node.contract.inventory_id,
            node.item_version,
            &vault,
            &self.title(kind, &node.contract.name),
        )
        .map_err(|_| invalid())?;
        if item.field("erpc_format", "STRING").map_err(|_| invalid())? != FORMAT
            || item.field("name", "STRING").map_err(|_| invalid())? != node.contract.name
        {
            return Err(invalid());
        }
        let saved: Pending = serde_json::from_str(
            item.field("native_migration", "STRING")
                .map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let mut expected = record.clone();
        expected.node.contract.inventory_id.clear();
        expected.node.item_version = 0;
        if saved != expected {
            return Err(invalid());
        }
        self.verify_solana_original_migration(record)?;
        Ok((item, vault))
    }
    fn recorded_migration_backup(
        record: &Pending,
        item: &MigrationItem,
        vault: &str,
    ) -> Result<Option<MigrationBackup>, InventoryError> {
        let receipt = item
            .optional_field("migration_custody", "STRING")
            .map_err(|_| invalid())?;
        let key = item
            .optional_field("migration_identity", "CONCEALED")
            .map_err(|_| invalid())?;
        let (Some(receipt), Some(key)) = (receipt, key) else {
            if receipt.is_some() || key.is_some() {
                return Err(invalid());
            }
            return Ok(None);
        };
        let receipt: BackupReceipt = serde_json::from_str(receipt).map_err(|_| invalid())?;
        let key: SecretString = key.to_owned().into();
        let sha256 = backup_digest(&key)?;
        if receipt.schema != 1
            || receipt.intent != record.intent
            || receipt.public != record.original.host_identity.public
            || receipt.sha256 != sha256
            || receipt.field != "migration_identity"
        {
            return Err(invalid());
        }
        let reference = format!(
            "op://{vault}/{}/migration_identity",
            record.node.contract.inventory_id
        );
        erpc_secret::OpRef::parse(&reference).map_err(|_| invalid())?;
        Ok(Some(MigrationBackup {
            pending: record.clone(),
            reference,
            key,
            sha256,
        }))
    }
    /// Read only the owned migration note; preserve unrelated fields and keys.
    /// The caller must cryptographically validate returned key bytes against the
    /// original public identity before acknowledging the host.
    /// # Errors
    /// Refuses changed scope, partial/foreign custody or ambiguous provider data.
    pub fn solana_migration_backup(
        &self,
        record: &Pending,
    ) -> Result<Option<MigrationBackup>, InventoryError> {
        let (item, vault) = self.original_migration_item(record)?;
        Self::recorded_migration_backup(record, &item, &vault)
    }
    /// Store caller-verified original canonical key bytes in the same reserved
    /// item, then return actual provider readback and its refreshed version.
    /// No key is generated, no separate item is created, and an ambiguous edit
    /// is resolved only by exact same-item readback. Local locking is not CAS.
    /// # Errors
    /// Refuses concurrent edits, existing different custody, unknown-field loss,
    /// incomplete readback or a different original legacy source.
    pub fn backup_solana_migration_identity(
        &self,
        record: &Pending,
        key: &SecretString,
    ) -> Result<MigrationBackup, InventoryError> {
        let _lock = self.lock()?;
        let (mut item, vault) = self.original_migration_item(record)?;
        if let Some(existing) = Self::recorded_migration_backup(record, &item, &vault)? {
            if existing.key.expose_secret() != key.expose_secret() {
                return Err(invalid());
            }
            return Ok(existing);
        }
        let receipt = BackupReceipt {
            schema: 1,
            intent: record.intent.clone(),
            public: record.original.host_identity.public.clone(),
            sha256: backup_digest(key)?,
            field: "migration_identity".into(),
        };
        item.set_field(
            "migration_identity",
            "CONCEALED",
            key.expose_secret().to_owned().into(),
        )
        .map_err(|_| invalid())?;
        item.set_field(
            "migration_custody",
            "STRING",
            serde_json::to_string(&receipt)
                .map_err(|_| invalid())?
                .into(),
        )
        .map_err(|_| invalid())?;
        let body = item.serialize().map_err(|_| invalid())?;
        self.verify_solana_pending_migration(record)?;
        // A lost/nonzero reply is not proof that the edit did not happen.
        if let Ok(output) = self.runner.run(
            &[
                "item",
                "edit",
                &record.node.contract.inventory_id,
                "--vault",
                &vault,
                "--format",
                "json",
            ],
            Some(body.expose_secret()),
        ) {
            let _stdout = SecretString::from(output.stdout);
            let _stderr = SecretString::from(output.stderr);
        }
        let refreshed = self.solana_pending_migration(&record.node.contract.name)?;
        let mut expected = record.clone();
        expected.node.item_version = refreshed.node.item_version;
        if expected != refreshed
            || refreshed.node.item_version
                != record
                    .node
                    .item_version
                    .checked_add(1)
                    .ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        let (after, after_vault) = self.original_migration_item(&refreshed)?;
        if after_vault != vault
            || !item
                .preserves(&after, &["migration_identity", "migration_custody"])
                .map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        let result =
            Self::recorded_migration_backup(&refreshed, &after, &vault)?.ok_or_else(invalid)?;
        if result.key.expose_secret() != key.expose_secret() {
            return Err(invalid());
        }
        Ok(result)
    }

    /// Read one pending migration using exact-scope public field projections only.
    /// # Errors
    /// Refuses malformed, ambiguous, foreign or concurrently changed records.
    pub fn solana_pending_migration(&self, name: &str) -> Result<Pending, InventoryError> {
        let (id, version, mut record) =
            self.public_projection(Kind::NativeMigration, name, SELECTOR, |raw| {
                let fields = selected_fields(raw, LABELS)?;
                if fields["erpc_format"].expose_secret() != FORMAT
                    || fields["name"].expose_secret() != name
                    || fields["native_migration"].expose_secret().len() > 131_072
                {
                    return Err(invalid());
                }
                let record: Pending =
                    serde_json::from_str(fields["native_migration"].expose_secret())
                        .map_err(|_| invalid())?;
                if !record.node.contract.inventory_id.is_empty()
                    || record.node.item_version != 0
                    || record.node.contract.name != name
                {
                    return Err(invalid());
                }
                record.validate()?;
                Ok(record)
            })?;
        record.node.contract.inventory_id = id;
        record.node.item_version = version;
        record.validate()?;
        if record.node.contract.network != self.scope.network {
            return Err(invalid());
        }
        Ok(record)
    }
    /// List public pending reservations; this is not a runtime health check.
    /// # Errors
    /// Refuses any ambiguous or malformed reservation instead of hiding it.
    pub fn solana_pending_migrations(&self) -> Result<Vec<Pending>, InventoryError> {
        self.public_names(Kind::NativeMigration)?
            .iter()
            .map(|name| self.solana_pending_migration(name))
            .collect()
    }
    fn pending_physical_host(&self, record: &Pending) -> Result<(), InventoryError> {
        let address = canonical_address(&record.node.address)?;
        for kind in [Kind::Host, Kind::Rpc] {
            for name in self.public_names(kind)? {
                let candidate = self.migration_record(kind, &name, &["address", "host_key"])?;
                if record
                    .source
                    .hosts
                    .iter()
                    .any(|original| original.id == candidate.item_id)
                {
                    continue;
                }
                let key = erpc_ssh::HostKey::parse(&candidate.fields["host_key"])
                    .map_err(|_| invalid())?;
                if canonical_address(&candidate.fields["address"])? == address
                    || key.to_openssh() == record.node.host_key
                {
                    return Err(InventoryError::Refused(
                        "another legacy record reserves the original physical host".into(),
                    ));
                }
            }
        }
        Ok(())
    }
    fn pending_registration(&self, record: &Pending) -> Result<(), InventoryError> {
        let node = &record.node;
        self.reject_other_validator_identity(&node.contract.name, &node.contract.identity_account)?;
        // A host-only filename is not authority evidence. Never back up an
        // identity recorded as any logical validator's signer, vote account or
        // withdrawal authority in this original network inventory scope.
        for name in self.public_names(Kind::Validator)? {
            let other = self.migration_record(
                Kind::Validator,
                &name,
                &["identity_account", "vote_account", "authority_account"],
            )?;
            if ["identity_account", "vote_account", "authority_account"]
                .iter()
                .any(|field| {
                    other.fields.get(*field) == Some(&record.original.host_identity.public)
                })
            {
                return Err(InventoryError::Refused(
                    "host-only identity is a recorded validator authority".into(),
                ));
            }
        }
        if node.contract.is_rpc()
            && self
                .public_names(Kind::Validator)?
                .contains(&node.contract.name)
        {
            return Err(InventoryError::Refused(
                "RPC migration name belongs to a logical validator".into(),
            ));
        }
        Ok(())
    }
    /// Reread original legacy source and exact reservation before a host mutation.
    /// # Errors
    /// Refuses changed item identity/version, legacy scope or a native collision.
    pub fn verify_solana_pending_migration(&self, record: &Pending) -> Result<(), InventoryError> {
        record.validate()?;
        if self.resolve_solana_migration_identity(&record.source.public())?
            != record.registered_identity
        {
            return Err(invalid());
        }
        self.pending_registration(record)?;
        self.pending_physical_host(record)?;
        if self.solana_pending_migration(&record.node.contract.name)? != *record
            || self.solana_migration_source(
                &record.node.contract.name,
                record.source.rpc,
                &record.source.selected_host,
            )? != record.source.public()
        {
            return Err(InventoryError::Changed(record.node.contract.name.clone()));
        }
        Ok(())
    }
    /// Reserve migration before any legacy service is stopped. An ambiguous create
    /// is recovered by reading the same named reservation; never create another one.
    /// Provider operations have local locking and readback, not distributed CAS.
    /// # Errors
    /// Refuses changed original sources, another reservation or native ownership.
    pub fn reserve_solana_migration(&self, proposed: &Pending) -> Result<Pending, InventoryError> {
        proposed.validate()?;
        if self.resolve_solana_migration_identity(&proposed.source.public())?
            != proposed.registered_identity
        {
            return Err(invalid());
        }
        if !proposed.node.contract.inventory_id.is_empty()
            || proposed.node.item_version != 0
            || proposed.node.contract.network != self.scope.network
        {
            return Err(invalid());
        }
        let _lock = self.lock()?;
        self.pending_registration(proposed)?;
        self.pending_physical_host(proposed)?;
        for old in self.solana_pending_migrations()? {
            if old.node.contract.name == proposed.node.contract.name {
                let mut expected = proposed.clone();
                expected.intent.clone_from(&old.intent);
                expected
                    .node
                    .contract
                    .inventory_id
                    .clone_from(&old.node.contract.inventory_id);
                expected.node.item_version = old.node.item_version;
                if expected != old {
                    return Err(invalid());
                }
                self.verify_solana_pending_migration(&old)?;
                return Ok(old);
            }
            if old.node.address == proposed.node.address
                || old.node.host_key == proposed.node.host_key
                || old.node.contract.identity_account == proposed.node.contract.identity_account
            {
                return Err(InventoryError::Refused(
                    "another migration reserves the original host or identity".into(),
                ));
            }
        }
        if self.solana_migration_source(
            &proposed.node.contract.name,
            proposed.source.rpc,
            &proposed.source.selected_host,
        )? != proposed.source.public()
        {
            return Err(invalid());
        }
        if self.solana_native_hosts()?.iter().any(|old| {
            old.contract.name == proposed.node.contract.name
                || old.address == proposed.node.address
                || old.host_key == proposed.node.host_key
                || old.contract.identity_account == proposed.node.contract.identity_account
        }) {
            return Err(invalid());
        }
        let raw = serde_json::to_string(proposed).map_err(|_| invalid())?;
        if raw.len() > 131_072 {
            return Err(invalid());
        }
        self.create_projected_note(
            Kind::NativeMigration,
            &proposed.node.contract.name,
            &[
                ("erpc_format", FORMAT.into()),
                ("name", proposed.node.contract.name.clone()),
                ("native_migration", raw),
            ],
        )?;
        let readback = self.solana_pending_migration(&proposed.node.contract.name)?;
        let mut expected = proposed.clone();
        expected
            .node
            .contract
            .inventory_id
            .clone_from(&readback.node.contract.inventory_id);
        expected.node.item_version = readback.node.item_version;
        if expected != readback {
            return Err(invalid());
        }
        self.verify_solana_pending_migration(&readback)?;
        Ok(readback)
    }
}

#[path = "solana_migration_promotion.rs"]
mod promotion;
pub use promotion::{CutoverReceipt, NativePromotion};

#[cfg(test)]
#[path = "solana_migration_pending_tests.rs"]
mod tests;
