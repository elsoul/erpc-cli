// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public BSC signer reservations; remote custody receipts remain authoritative.

use super::{
    InventoryError, Kind, OpItem, OpRunner, Store,
    bsc::{self, BscRpc},
    check_name, checked,
};
use serde::{Deserialize, Serialize};

/// One dedicated host, external financial operator, and immutable hot identities.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BscValidator {
    /// Common host/network-qualified client metadata, tagged as a validator.
    pub node: BscRpc,
    /// Financial operator address only; its secret never enters this record/host.
    pub operator: String,
    /// Consensus public address, empty until the owned host publishes its key.
    pub consensus: String,
    /// Compressed public BLS vote key, empty before provisioning.
    pub vote: String,
    /// Public network/operator-bound BLS proof of possession.
    pub proof: String,
    /// Unprovisioned or owned; retirement does not release the identity reservation.
    pub custody: String,
    /// Reference to the verified concealed same-owner custody backup.
    pub backup_ref: String,
}
fn encoded(value: &str, length: usize, prefix: bool) -> bool {
    let value = if prefix {
        value.strip_prefix("0x").unwrap_or("")
    } else {
        value
    };
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && value.bytes().any(|c| c != b'0')
}
fn validate(v: &BscValidator) -> Result<(), InventoryError> {
    if !v.backup_ref.is_empty() && erpc_secret::OpRef::parse(&v.backup_ref).is_err() {
        return Err(InventoryError::Unreadable("BSC custody backup reference"));
    }
    let empty = v.consensus.is_empty() && v.vote.is_empty() && v.proof.is_empty();
    let full = encoded(&v.consensus, 40, true)
        && encoded(&v.vote, 96, false)
        && encoded(&v.proof, 192, true)
        && v.consensus != v.operator;
    if !encoded(&v.operator, 40, true)
        || !["unprovisioned", "owned"].contains(&v.custody.as_str())
        || (v.custody == "unprovisioned" && !empty)
        || (v.custody == "owned" && !full)
        || (!empty && !full)
    {
        return Err(InventoryError::Unreadable("BSC validator identities"));
    }
    Ok(())
}
fn fields(v: &BscValidator) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(v)?;
    let mut fields = bsc::fields(&v.node)?;
    fields.extend([
        ("bsc_validator_operator", v.operator.clone()),
        ("bsc_validator_consensus", v.consensus.clone()),
        ("bsc_validator_vote", v.vote.clone()),
        ("bsc_validator_proof", v.proof.clone()),
        ("bsc_validator_custody", v.custody.clone()),
        ("bsc_validator_backup", v.backup_ref.clone()),
    ]);
    Ok(fields)
}
fn read(item: &OpItem) -> Result<BscValidator, InventoryError> {
    let f = checked(item)?;
    let field = |name| {
        f.get(name)
            .map(|v| (*v).to_owned())
            .ok_or(InventoryError::Unreadable("BSC validator record"))
    };
    let v = BscValidator {
        node: bsc::read(item)?,
        operator: field("bsc_validator_operator")?,
        consensus: field("bsc_validator_consensus")?,
        vote: field("bsc_validator_vote")?,
        proof: field("bsc_validator_proof")?,
        custody: field("bsc_validator_custody")?,
        backup_ref: field("bsc_validator_backup")?,
    };
    validate(&v)?;
    Ok(v)
}
impl<R: OpRunner> Store<R> {
    /// Read only BSC validators in this network scope.
    /// # Errors
    /// Refuses another chain or malformed public metadata.
    pub fn bsc_validators(&self) -> Result<Vec<BscValidator>, InventoryError> {
        if self.scope.chain != "bsc" {
            return Err(InventoryError::Refused("expected BSC scope".into()));
        }
        self.items(Kind::Validator)?.iter().map(read).collect()
    }
    /// Reserve a fresh host before its signing keys exist.
    /// # Errors
    /// Refuses an established key, duplicate name, or RPC/validator host collision.
    pub fn add_bsc_validator(&self, v: &BscValidator) -> Result<BscValidator, InventoryError> {
        check_name(&v.node.name)?;
        validate(v)?;
        if v.custody != "unprovisioned" {
            return Err(InventoryError::Refused(
                "new BSC validators must begin without keys".into(),
            ));
        }
        let _lock = self.lock()?;
        if self
            .bsc_validators()?
            .iter()
            .any(|old| old.node.name == v.node.name || old.node.address == v.node.address)
            || self
                .bsc_rpcs()?
                .iter()
                .any(|old| old.address == v.node.address)
        {
            return Err(InventoryError::Refused(
                "BSC host is already reserved".into(),
            ));
        }
        read(&self.create(Kind::Validator, &v.node.name, &fields(v)?, None)?)
    }
    /// Update operation results without replacing established ownership/identities.
    /// # Errors
    /// Refuses stale writes, changed immutable fields, key erasure/replacement,
    /// duplicate reservations, and reversal to an unprovisioned identity.
    pub fn update_bsc_validator(&self, v: &BscValidator) -> Result<BscValidator, InventoryError> {
        validate(v)?;
        let _lock = self.lock()?;
        let id = v
            .node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("BSC validator owner"))?;
        let old = read(&self.get(id)?)?;
        if (
            &old.node.address,
            &old.node.host_key,
            &old.node.platform,
            &old.node.storage,
            &old.node.snapshot,
            &old.operator,
        ) != (
            &v.node.address,
            &v.node.host_key,
            &v.node.platform,
            &v.node.storage,
            &v.node.snapshot,
            &v.operator,
        ) || (!old.consensus.is_empty()
            && (&old.consensus, &old.vote, &old.proof) != (&v.consensus, &v.vote, &v.proof))
            || (!old.backup_ref.is_empty() && old.backup_ref != v.backup_ref)
            || (old.custody == "owned" && v.custody == "unprovisioned")
        {
            return Err(InventoryError::Refused(
                "BSC validator ownership and reserved identities are immutable".into(),
            ));
        }
        if v.custody == "owned"
            && self.bsc_validators()?.iter().any(|other| {
                other.node.id != v.node.id
                    && (other.consensus == v.consensus || other.vote == v.vote)
            })
        {
            return Err(InventoryError::Refused(
                "BSC signing identity already has an owner".into(),
            ));
        }
        read(&self.update(
            Kind::Validator,
            (Some(id), v.node.item_version),
            &v.node.name,
            &fields(v)?,
            None,
        )?)
    }
}
