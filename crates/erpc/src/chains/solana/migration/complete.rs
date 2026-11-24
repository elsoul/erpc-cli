// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Original custody readback, same-item promotion and durable host acknowledgment.
use super::*;
use erpc_chain_solana::identity::Keypair;
use secrecy::{ExposeSecret as _, SecretString};

fn original_key(raw: &str, public: &str) -> Result<SecretString, String> {
    if raw.len() > 4096 {
        return Err("original key exceeds its bounded format".into());
    }
    let key = Keypair::parse_json(raw).map_err(|_| "original key material is invalid")?;
    if key.pubkey() != public {
        return Err("original private identity does not match the approved public source".into());
    }
    Ok(key.to_json().to_string().into())
}
impl Live<'_> {
    fn original_registered_identity(&self) -> Result<(), String> {
        self.original()?;
        if let Some(identity) = &self.pending.registered_identity {
            let op = node_common::op_runner()?;
            identity
                .verify(&op)
                .map_err(|_| "original registered identity reference changed")?;
            let reference = erpc_secret::OpRef::parse(&identity.reference)
                .map_err(|_| "invalid original registered identity reference")?;
            let raw = crate::rollup_credentials::read_concealed(&op, &reference)?;
            let _verified = original_key(raw.expose_secret(), &identity.public)?;
            identity
                .verify(&op)
                .map_err(|_| "original registered identity changed during readback")?;
        }
        self.original()
    }
    fn backup_original(&mut self) -> Result<(), String> {
        self.original()?;
        let existing = self
            .store
            .solana_migration_backup(&self.pending)
            .map_err(|_| "original migration custody cannot be read back")?;
        let backup = if let Some(backup) = existing {
            backup
        } else {
            let request = self
                .pending
                .request(Action::MigrationExport)
                .map_err(|e| e.to_string())?;
            let input = serde_json::to_vec(&request)
                .map_err(|_| "cannot encode original private request")?;
            self.original()?;
            let output = self.session.run_private(
                &erpc_ssh::RemoteCommand::SolanaNative(Remote::MigrationExport(Revision::new(
                    &native::helper_revision()?,
                )?)),
                &input,
                4096,
            )?;
            self.original()?;
            let text = std::str::from_utf8(output.expose())
                .map_err(|_| "invalid original private response")?;
            let key = original_key(text, &self.pending.original.host_identity.public)?;
            // The remote cipher receipt hashes the canonical file, so transport
            // cannot normalize a different or extended payload into authority.
            if text != key.expose_secret() {
                return Err("original private response is not canonical".into());
            }
            self.store.backup_solana_migration_identity(&self.pending, &key)
                .map_err(|_| "original custody write/readback is incomplete; resume this same inventory item")?
        };
        let canonical = original_key(
            backup.key.expose_secret(),
            &self.pending.original.host_identity.public,
        )?;
        if canonical.expose_secret() != backup.key.expose_secret()
            || format!("{:x}", Sha256::digest(canonical.expose_secret().as_bytes()))
                != backup.sha256
        {
            return Err("original stored custody digest differs".into());
        }
        // A successful edit advances the provider generation. Never carry v1
        // into the next host operation after the exact same item became v2.
        self.pending = backup.pending;
        self.original()
    }
    fn cutover_stage(
        &mut self,
        action: Action,
        receipt: &CutoverReceipt,
        version: Option<u64>,
    ) -> Result<(), String> {
        if !matches!(
            action,
            Action::MigrationPrepareCutover | Action::MigrationFinalize
        ) {
            return Err("unsupported original cutover stage".into());
        }
        let mut value =
            serde_json::to_value(self.pending.request(action).map_err(|e| e.to_string())?)
                .map_err(|_| "cannot encode original cutover")?;
        value["cutover"] = json!({"receipt":receipt,"provider_version":version});
        self.sealed(&value)
    }
    fn finish_ack(&mut self, receipt: &CutoverReceipt, version: u64) -> Result<Progress, String> {
        if self.pending.node.item_version != version {
            return Err("original provider acknowledgment generation changed".into());
        }
        self.cutover_stage(Action::MigrationFinalize, receipt, Some(version))?;
        let result = self.progress()?;
        if !result.migration_complete
            || !result.cutover.as_ref().is_some_and(|ack| {
                ack.phase == "complete"
                    && ack.receipt == *receipt
                    && ack.provider_version.is_some_and(|v| v <= version)
            })
        {
            return Err(
                "original native completion acknowledgment is missing; resume the same migration"
                    .into(),
            );
        }
        Ok(result)
    }
    pub(super) fn complete(&mut self) -> Result<Progress, String> {
        let status = self.progress()?;
        let promoted = self
            .store
            .solana_migration_cutover(&self.pending)
            .map_err(|_| "original provider cutover cannot be reconciled")?;
        if let Some(ack) = &status.cutover
            && ack.phase == "complete"
        {
            let receipt =
                promoted.ok_or("host completion has no matching original native inventory")?;
            if ack.receipt != receipt
                || ack
                    .provider_version
                    .is_none_or(|v| v > self.pending.node.item_version)
            {
                return Err("host and provider completion bindings differ".into());
            }
            if status.migration_complete {
                return Ok(status);
            }
            // Only repair final durable acknowledgment; never replay original
            // copy, source floor, custody or configuration over newer history.
            return self.finish_ack(&receipt, self.pending.node.item_version);
        }
        if status
            .helper_revision
            .as_ref()
            .is_some_and(|value| native::helper_revision().as_ref() != Ok(value))
        {
            return Err(
                "original migration helper differs; an explicit compatible upgrade is required"
                    .into(),
            );
        }
        if let Some(receipt) = promoted {
            if !status
                .cutover
                .as_ref()
                .is_some_and(|ack| ack.phase == "prepared" && ack.receipt == receipt)
            {
                return Err("promoted inventory has no matching original host preparation".into());
            }
            // A historical receipt alone cannot acknowledge a still-pending
            // handoff. Recheck the current configuration/custody at one exact
            // provider generation before using that same pair in finalize.
            let verified = self
                .store
                .prepare_solana_migration_promotion(&self.pending)
                .map_err(
                    |_| "original promoted configuration or custody changed before completion",
                )?;
            if verified.receipt != receipt || verified.pending != self.pending {
                return Err("prepared host and current provider snapshot differ".into());
            }
            self.original_registered_identity()?;
            self.backup_original()?;
            if self.pending != verified.pending {
                return Err("original provider snapshot changed during custody readback".into());
            }
            return self.finish_ack(&verified.receipt, verified.pending.node.item_version);
        }
        self.original_registered_identity()?;
        continue_copy(self)?;
        self.stage(Action::MigrationCustody)?;
        self.backup_original()?;
        self.original_registered_identity()?;
        let prepared = self
            .store
            .prepare_solana_migration_promotion(&self.pending)
            .map_err(|_| "original provider promotion cannot be prepared")?;
        self.cutover_stage(Action::MigrationPrepareCutover, &prepared.receipt, None)?;
        let promoted = self
            .store
            .promote_solana_migration(&prepared)
            .map_err(|_| "original provider promotion is not confirmed; resume the same item")?;
        let version = promoted.pending.node.item_version;
        self.pending = promoted.pending;
        self.original()?;
        self.finish_ack(&promoted.receipt, version)
    }
}
