// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Ethereum validator inventory: separate from RPC and Solana identities.

use super::{
    EthRpc, InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked, eth_rpc_fields,
    read_eth_rpc,
};

/// A dedicated execution/beacon/validator host. No signing secrets are stored in
/// this metadata; keystores/passwords remain on the operator and signer hosts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EthValidator {
    /// Host and verified binary pins, stored under a validator tag, never an RPC tag.
    pub node: EthRpc,
    /// Nonzero execution fee recipient, not withdrawal credentials.
    pub fee_recipient: String,
    /// Public key after import. One key per owner record.
    pub pubkey: String,
    /// Lifecycle state: prepared, imported, or fenced. Remote state is authoritative.
    pub state: String,
}

fn fields(v: &EthValidator) -> Vec<(&'static str, String)> {
    let mut fields = eth_rpc_fields(&v.node);
    fields.extend([
        ("eth_validator_format", "1".into()),
        ("fee_recipient", v.fee_recipient.clone()),
        ("pubkey", v.pubkey.clone()),
        ("validator_state", v.state.clone()),
    ]);
    fields
}

fn read(item: &OpItem) -> Result<EthValidator, InventoryError> {
    let f = checked(item)?;
    if f.get("eth_validator_format") != Some(&"1") {
        return Err(InventoryError::Unreadable("the Ethereum validator format"));
    }
    Ok(EthValidator {
        node: read_eth_rpc(item)?,
        fee_recipient: f.get("fee_recipient").unwrap_or(&"").to_string(),
        pubkey: f.get("pubkey").unwrap_or(&"").to_string(),
        state: f.get("validator_state").unwrap_or(&"").to_string(),
    })
}

impl<R: OpRunner> Store<R> {
    /// Read validator metadata in this network's vault.
    /// # Errors
    /// Refuses non-Ethereum scopes and malformed or unreadable items.
    pub fn eth_validators(&self) -> Result<Vec<EthValidator>, InventoryError> {
        if self.scope.chain != "eth" {
            return Err(InventoryError::Refused("expected Ethereum scope".into()));
        }
        self.items(Kind::Validator)?.iter().map(read).collect()
    }

    /// Reserve a dedicated host, without importing keys or creating a deposit.
    /// # Errors
    /// Duplicate names/addresses and RPC host collisions are refused under the local inventory lock.
    pub fn add_eth_validator(&self, v: &EthValidator) -> Result<EthValidator, InventoryError> {
        check_name(&v.node.name)?;
        if !v.pubkey.is_empty() || v.state != "prepared" {
            return Err(InventoryError::Refused(
                "new validator records must begin without a key".into(),
            ));
        }
        let _lock = self.lock()?;
        if self
            .eth_validators()?
            .iter()
            .any(|old| old.node.name == v.node.name || old.node.address == v.node.address)
            || self
                .eth_rpcs()?
                .iter()
                .any(|old| old.address == v.node.address)
        {
            return Err(InventoryError::Refused(
                "Ethereum host is already reserved".into(),
            ));
        }
        read(&self.create(Kind::Validator, &v.node.name, &fields(v), None)?)
    }

    /// Persist metadata without changing the immutable host owner or losing pins.
    /// # Errors
    /// A concurrently changed item or duplicate active public key is refused.
    pub fn update_eth_validator(&self, v: &EthValidator) -> Result<EthValidator, InventoryError> {
        let _lock = self.lock()?;
        let id = v
            .node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("validator id"))?;
        let old = read(&self.get(id)?)?;
        if old.node.address != v.node.address || old.node.host_key != v.node.host_key {
            return Err(InventoryError::Refused(
                "validator ownership cannot move through an inventory edit".into(),
            ));
        }
        if !old.pubkey.is_empty() && old.pubkey != v.pubkey {
            return Err(InventoryError::Refused(
                "a reserved validator public key is immutable".into(),
            ));
        }
        let transition_ok = matches!(
            (old.state.as_str(), v.state.as_str()),
            ("prepared", "prepared" | "importing" | "fenced")
                | ("importing", "importing" | "imported" | "fenced")
                | ("imported", "imported" | "fenced")
                | ("fenced", "fenced")
        );
        if !transition_ok
            || (v.state == "prepared" && !v.pubkey.is_empty())
            || (matches!(v.state.as_str(), "importing" | "imported") && v.pubkey.is_empty())
        {
            return Err(InventoryError::Refused(
                "invalid validator ownership transition".into(),
            ));
        }
        if !v.pubkey.is_empty()
            && v.state != "fenced"
            && self.eth_validators()?.iter().any(|other| {
                other.node.id != v.node.id && other.pubkey == v.pubkey && other.state != "fenced"
            })
        {
            return Err(InventoryError::Refused(
                "validator public key already has an owner".into(),
            ));
        }
        read(&self.update(
            Kind::Validator,
            (Some(id), v.node.item_version),
            &v.node.name,
            &fields(v),
            None,
        )?)
    }
}
