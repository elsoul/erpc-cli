// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated validator metadata holds an identifier-only reference, never key bytes.
use super::{
    InventoryError, Kind, OpItem, OpRunner, Store, checked,
    hyperliquid::{HyperliquidNode, validate_for},
};
use erpc_secret::OpRef;
use serde::{Deserialize, Serialize};

/// Explicit bootstrap versus activated native consensus operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Synchronize as the officially required non-validating follower first.
    Follower,
    /// Original key mounted to the explicitly activated validator service.
    Validator,
}
impl Mode {
    /// Native target marker, included in the authorized operation receipt.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Follower => "follower",
            Self::Validator => "validator",
        }
    }
}

/// Public validator authority plus one concealed original-key reference.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorNode {
    /// Public host metadata; its contract is explicitly validator-scoped.
    pub host: HyperliquidNode,
    /// Identifier-only 1Password field holding the original native key object.
    pub hot_key_ref: String,
    /// Last applied native mode; activation is independently verified on host.
    pub mode: Mode,
}
impl std::fmt::Debug for ValidatorNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HyperliquidValidator")
            .field("name", &self.host.name)
            .field("contract", &self.host.contract)
            .field("mode", &self.mode)
            .field("hot_key_ref", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
fn invalid() -> InventoryError {
    InventoryError::Unreadable("Hyperliquid validator ownership")
}
fn validate(node: &ValidatorNode) -> Result<(), InventoryError> {
    validate_for(&node.host, "validator")?;
    OpRef::parse(&node.hot_key_ref).map_err(|_| invalid())?;
    if !node.host.rpc_allow.is_empty() {
        return Err(invalid());
    }
    Ok(())
}
fn read(item: &OpItem) -> Result<ValidatorNode, InventoryError> {
    let fields = checked(item)?;
    let mut node: ValidatorNode = serde_json::from_str(
        fields
            .get("hyperliquid_validator_record")
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    validate(&node)?;
    node.host.id = Some(item.id.clone());
    node.host.item_version = item.version;
    Ok(node)
}
fn fields(node: &ValidatorNode) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(node)?;
    Ok(vec![
        ("erpc_format", super::FORMAT.into()),
        (
            "hyperliquid_validator_record",
            serde_json::to_string(node).map_err(|_| invalid())?,
        ),
    ])
}
fn same_host(a: &HyperliquidNode, b: &HyperliquidNode) -> bool {
    a.name == b.name
        || a.address == b.address
        || a.host_key == b.host_key
        || a.contract.owner == b.contract.owner
        || a.contract.public_ip == b.contract.public_ip
}
impl<R: OpRunner> Store<R> {
    /// Read only the selected network's typed validator metadata.
    /// # Errors
    /// Refuses wrong scope, unsafe references or inconsistent public ownership.
    pub fn hyperliquid_validators(&self) -> Result<Vec<ValidatorNode>, InventoryError> {
        if self.scope.chain != "hyperliquid" {
            return Err(invalid());
        }
        let result = self
            .items(Kind::Validator)?
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        if result
            .iter()
            .any(|node| node.host.contract.network.name() != self.scope.network)
        {
            return Err(invalid());
        }
        Ok(result)
    }
    /// Reserve a distinct original validator and cold/hot identity pairing.
    /// # Errors
    /// Refuses existing RPC/validator hosts, signer reuse or implicit activation.
    pub fn add_hyperliquid_validator(
        &self,
        node: &ValidatorNode,
    ) -> Result<ValidatorNode, InventoryError> {
        validate(node)?;
        if self.scope.chain != "hyperliquid"
            || node.host.contract.network.name() != self.scope.network
            || node.mode != Mode::Follower
            || node.host.id.is_some()
            || node.host.item_version != 0
        {
            return Err(invalid());
        }
        let _lock = self.lock()?;
        let identity = node.host.contract.validator.as_ref().ok_or_else(invalid)?;
        if self
            .hyperliquid_nodes()?
            .iter()
            .any(|other| same_host(other, &node.host))
            || self.hyperliquid_validators()?.iter().any(|other| {
                same_host(&other.host, &node.host)
                    || other.host.contract.validator.as_ref().is_some_and(|value| {
                        value.signer == identity.signer || value.validator == identity.validator
                    })
            })
            || self.hyperliquid_publishers()?.iter().any(|other| {
                other.name == node.host.name
                    || other.address == node.host.address
                    || other.host_key == node.host.host_key
                    || other.contract.owner == node.host.contract.owner
                    || other.agent_key_ref == node.hot_key_ref
                    || [identity.signer.as_str(), identity.validator.as_str()]
                        .contains(&other.contract.identity.agent.as_str())
            })
        {
            return Err(InventoryError::Refused(
                "Hyperliquid host or original validator/signer is already reserved".into(),
            ));
        }
        read(&self.create(Kind::Validator, &node.host.name, &fields(node)?, None)?)
    }
    /// Preserve original host, concealed reference and dedicated funding policy.
    /// # Errors
    /// Refuses stale writes, ownership changes or a silent consensus downgrade.
    pub fn update_hyperliquid_validator(
        &self,
        node: &ValidatorNode,
    ) -> Result<ValidatorNode, InventoryError> {
        validate(node)?;
        if self.scope.chain != "hyperliquid"
            || node.host.contract.network.name() != self.scope.network
        {
            return Err(invalid());
        }
        let _lock = self.lock()?;
        let id = node.host.id.as_deref().ok_or_else(invalid)?;
        let previous = read(&self.get(id)?)?;
        if previous.host.name != node.host.name
            || previous.host.address != node.host.address
            || previous.host.ssh_user != node.host.ssh_user
            || previous.host.ssh_port != node.host.ssh_port
            || previous.host.host_key != node.host.host_key
            || previous.host.contract != node.host.contract
            || previous.hot_key_ref != node.hot_key_ref
            || (previous.mode == Mode::Validator && node.mode != Mode::Validator)
        {
            return Err(InventoryError::Refused(
                "original Hyperliquid validator host, key and funding boundary are immutable"
                    .into(),
            ));
        }
        read(&self.update(
            Kind::Validator,
            (Some(id), node.host.item_version),
            &node.host.name,
            &fields(node)?,
            None,
        )?)
    }
}
