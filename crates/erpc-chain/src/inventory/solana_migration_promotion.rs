// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Same-item promotion; no legacy record or original concealed value is deleted.
use super::*;

/// Public hashes linking the original host, retained key and provider transition.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverReceipt {
    /// Closed acknowledgment schema.
    pub schema: u8,
    /// Original immutable migration intent.
    pub intent: String,
    /// The same provider item allocated before the original service stopped.
    pub inventory_id: String,
    /// Provider version whose original custody was read back before promotion.
    pub reserved_version: u64,
    /// Exact original public legacy snapshot binding.
    pub source_sha256: String,
    /// Canonical immutable native owner hash.
    pub contract_sha256: String,
    /// Canonical native configuration hash (references, not private key values).
    pub config_sha256: String,
    /// Original canonical plaintext hash, also verified against host encryption.
    pub custody_sha256: String,
}
impl std::fmt::Debug for CutoverReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CutoverReceipt([PUBLIC BINDINGS])")
    }
}
/// Verified provider state, still requiring the original host's final acknowledgment.
pub struct NativePromotion {
    /// The same original scope with the newly observed provider version.
    pub pending: Pending,
    /// Original references and preserved access policy.
    pub configuration: NativeConfig,
    /// Immutable cutover prepared before the provider tag changed.
    pub receipt: CutoverReceipt,
}
impl std::fmt::Debug for NativePromotion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativePromotion([REDACTED])")
    }
}
fn digest(value: &impl Serialize) -> Result<String, InventoryError> {
    let normalized = serde_json::to_value(value).map_err(|_| invalid())?;
    let bytes = serde_json::to_vec(&normalized).map_err(|_| invalid())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
impl CutoverReceipt {
    fn new(
        record: &Pending,
        configuration: &NativeConfig,
        sha256: String,
    ) -> Result<Self, InventoryError> {
        Ok(Self {
            schema: 1,
            intent: record.intent.clone(),
            inventory_id: record.node.contract.inventory_id.clone(),
            reserved_version: record.node.item_version,
            source_sha256: record.original.source_sha256.clone(),
            contract_sha256: digest(&record.node.contract)?,
            config_sha256: digest(configuration)?,
            custody_sha256: sha256,
        })
    }
}
impl<R: OpRunner> Store<R> {
    pub(super) fn original_migration_kind(&self, name: &str) -> Result<Kind, InventoryError> {
        let pending = self
            .public_names(Kind::NativeMigration)?
            .iter()
            .any(|value| value == name);
        let native = self
            .public_names(Kind::NativeHost)?
            .iter()
            .any(|value| value == name);
        match (pending, native) {
            (true, false) => Ok(Kind::NativeMigration),
            (false, true) => Ok(Kind::NativeHost),
            _ => Err(invalid()),
        }
    }
    /// Read a reservation even after its same item acquired the native-host tag.
    /// This never treats a generic native host as a migration or adopts another ID.
    /// # Errors
    /// Refuses missing provenance, conflicting kinds or a changed owner.
    pub fn solana_original_migration(&self, name: &str) -> Result<Pending, InventoryError> {
        if self.original_migration_kind(name)? == Kind::NativeMigration {
            return self.solana_pending_migration(name);
        }
        let host = self.solana_native_host(name)?;
        let (id, version, mut record) =
            self.public_projection(Kind::NativeHost, name, SELECTOR, |raw| {
                let fields = selected_fields(raw, LABELS)?;
                if fields["erpc_format"].expose_secret() != FORMAT
                    || fields["name"].expose_secret() != name
                {
                    return Err(invalid());
                }
                let value: Pending =
                    serde_json::from_str(fields["native_migration"].expose_secret())
                        .map_err(|_| invalid())?;
                if !value.node.contract.inventory_id.is_empty() || value.node.item_version != 0 {
                    return Err(invalid());
                }
                value.validate()?;
                Ok(value)
            })?;
        record.node.contract.inventory_id = id;
        record.node.item_version = version;
        record.validate()?;
        if record.node != host {
            return Err(invalid());
        }
        Ok(record)
    }
    /// Reconcile only the exact saved legacy snapshot behind this owned native item.
    /// Fresh initialization continues to reject every legacy/native collision.
    /// # Errors
    /// Refuses edited originals, an added companion host, reference changes or aliases.
    pub fn verify_solana_original_migration(&self, record: &Pending) -> Result<(), InventoryError> {
        record.validate()?;
        if self.original_migration_kind(&record.node.contract.name)? == Kind::NativeMigration {
            return self.verify_solana_pending_migration(record);
        }
        if self.solana_original_migration(&record.node.contract.name)? != *record {
            return Err(invalid());
        }
        self.pending_registration(record)?;
        self.pending_physical_host(record)?;
        let original = record.source.public();
        let before = self.migration_source_original(
            &record.node.contract.name,
            record.source.rpc,
            &record.source.selected_host,
        )?;
        if before != original
            || self.source_registered_identity(&original)? != record.registered_identity
        {
            return Err(invalid());
        }
        let after = self.migration_source_original(
            &record.node.contract.name,
            record.source.rpc,
            &record.source.selected_host,
        )?;
        if before != after {
            return Err(invalid());
        }
        for other in self.solana_native_hosts()? {
            if other.contract.inventory_id != record.node.contract.inventory_id
                && (other.address == record.node.address
                    || other.host_key == record.node.host_key
                    || other.contract.identity_account == record.node.contract.identity_account)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    /// Read the immutable public acknowledgment retained after native promotion.
    /// Later access-policy edits do not rewrite this historical transition.
    /// # Errors
    /// Refuses a different original item, contract, source or provider generation.
    pub fn solana_migration_cutover(
        &self,
        record: &Pending,
    ) -> Result<Option<CutoverReceipt>, InventoryError> {
        self.verify_solana_original_migration(record)?;
        if self.original_migration_kind(&record.node.contract.name)? == Kind::NativeMigration {
            return Ok(None);
        }
        let (id, version, receipt) = self.public_projection(
            Kind::NativeHost,
            &record.node.contract.name,
            "label=migration_cutover",
            |raw| {
                let fields = selected_fields(raw, &["migration_cutover"])?;
                serde_json::from_str::<CutoverReceipt>(fields["migration_cutover"].expose_secret())
                    .map_err(|_| invalid())
            },
        )?;
        let hex = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if id != record.node.contract.inventory_id
            || version != record.node.item_version
            || receipt.schema != 1
            || receipt.intent != record.intent
            || receipt.inventory_id != id
            || receipt.source_sha256 != record.original.source_sha256
            || receipt.contract_sha256 != digest(&record.node.contract)?
            || receipt.reserved_version == 0
            || receipt.reserved_version >= version
            || !hex(&receipt.config_sha256)
            || !hex(&receipt.custody_sha256)
        {
            return Err(invalid());
        }
        Ok(Some(receipt))
    }
    /// Prepare public cutover hashes after actual same-item secret readback.
    /// The caller validates its private key/public association before using this.
    /// # Errors
    /// Refuses lost custody or an already-promoted item with different configuration.
    pub fn prepare_solana_migration_promotion(
        &self,
        record: &Pending,
    ) -> Result<NativePromotion, InventoryError> {
        self.verify_solana_original_migration(record)?;
        let backup = self.solana_migration_backup(record)?.ok_or_else(invalid)?;
        let configuration = record.configuration(&backup.reference)?;
        let mut receipt = CutoverReceipt::new(record, &configuration, backup.sha256)?;
        if self.original_migration_kind(&record.node.contract.name)? == Kind::NativeHost {
            let (item, _) = self.original_migration_item(record)?;
            let previous: CutoverReceipt = serde_json::from_str(
                item.field("migration_cutover", "STRING")
                    .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?;
            receipt.reserved_version = previous.reserved_version;
            if previous != receipt
                || receipt.reserved_version >= record.node.item_version
                || self.solana_native_config(&record.node)? != configuration
            {
                return Err(invalid());
            }
        }
        Ok(NativePromotion {
            pending: record.clone(),
            configuration,
            receipt,
        })
    }
    /// Change only this original item's title/tag and add native fields. All key
    /// bytes, user notes, tags and retained legacy evidence survive the edit.
    /// A failed reply is resolved by exact readback; no replacement item is created.
    /// # Errors
    /// Refuses changed intent, originals, custody/configuration or unknown-field loss.
    pub fn promote_solana_migration(
        &self,
        prepared: &NativePromotion,
    ) -> Result<NativePromotion, InventoryError> {
        let _lock = self.lock()?;
        let record = &prepared.pending;
        let current = self.prepare_solana_migration_promotion(record)?;
        if current.receipt != prepared.receipt || current.configuration != prepared.configuration {
            return Err(invalid());
        }
        if self.original_migration_kind(&record.node.contract.name)? == Kind::NativeHost {
            return Ok(current);
        }
        let (mut item, vault) = self.original_migration_item(record)?;
        let mut native = record.node.clone();
        native.contract.inventory_id.clear();
        native.item_version = 0;
        for (label, value) in [
            (
                "native_host",
                serde_json::to_string(&native).map_err(|_| invalid())?,
            ),
            (
                "native_config",
                serde_json::to_string(&prepared.configuration).map_err(|_| invalid())?,
            ),
            (
                "migration_cutover",
                serde_json::to_string(&prepared.receipt).map_err(|_| invalid())?,
            ),
        ] {
            item.set_field(label, "STRING", value.into())
                .map_err(|_| invalid())?;
        }
        item.promote_title_and_tag(
            &self.title(Kind::NativeHost, &record.node.contract.name),
            &self.scope.tag(Kind::NativeMigration),
            &self.scope.tag(Kind::NativeHost),
        )
        .map_err(|_| invalid())?;
        let body = item.serialize().map_err(|_| invalid())?;
        self.verify_solana_pending_migration(record)?;
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
        let refreshed = self.solana_original_migration(&record.node.contract.name)?;
        let mut expected = record.clone();
        expected.node.item_version = refreshed.node.item_version;
        if refreshed != expected
            || refreshed.node.item_version
                != record
                    .node
                    .item_version
                    .checked_add(1)
                    .ok_or_else(invalid)?
            || self.original_migration_kind(&record.node.contract.name)? != Kind::NativeHost
        {
            return Err(invalid());
        }
        let (after, after_vault) = self.original_migration_item(&refreshed)?;
        if vault != after_vault
            || !item
                .preserves(
                    &after,
                    &["native_host", "native_config", "migration_cutover"],
                )
                .map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        self.prepare_solana_migration_promotion(&refreshed)
    }
}
