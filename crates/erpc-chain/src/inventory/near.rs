// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Near RPC ownership and immutable platform metadata.

use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use serde::{Deserialize, Serialize};

/// Public staking-pool and dedicated signing-key reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    /// Full pool account used by nearcore's validator signer.
    pub account_id: String,
    /// External pool-owner transaction account.
    pub owner_account: String,
    /// Dedicated Ed25519 consensus public key.
    pub public_key: String,
    /// Original native key-file field in 1Password, never its value.
    pub key_ref: String,
    /// Explicit operator-selected initial pool commission.
    pub commission_basis_points: u16,
}

/// Dedicated Near follower host, stored as an RPC item in its network vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearRpc {
    /// Item identity, assigned by the secret store.
    #[serde(skip)]
    pub id: Option<String>,
    /// Optimistic concurrency version.
    #[serde(skip)]
    pub item_version: u64,
    /// Inventory name.
    pub name: String,
    /// SSH address.
    pub address: String,
    /// SSH login user.
    pub ssh_user: String,
    /// SSH port.
    pub ssh_port: u16,
    /// Pinned OpenSSH host key.
    pub host_key: String,
    /// Canonical stable version.
    pub version: String,
    /// Resolved source commit.
    pub commit: String,
    /// Linux OCI architecture.
    pub platform: String,
    /// Trusted RPC IPv4 ranges; empty means loopback only.
    pub rpc_allow: Vec<String>,
    /// Trusted metrics IPv4 ranges; empty means loopback only.
    pub metrics_allow: Vec<String>,
    /// Additional canonical management IPv4 ranges.
    pub management_allow: Vec<String>,
    /// Present only for a separately owned validator role; old RPC records omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<Validator>,
    /// Last remote run identifier.
    pub last_run: String,
    /// Last completed controller operation.
    pub last_result: String,
}

fn validate(node: &NearRpc) -> Result<(), InventoryError> {
    if let Some(validator) = &node.validator {
        erpc_secret::OpRef::parse(&validator.key_ref)
            .map_err(|_| InventoryError::Unreadable("NEAR validator key reference"))?;
        if validator.commission_basis_points > 10000 || !node.rpc_allow.is_empty() {
            return Err(InventoryError::Unreadable(
                "NEAR validator role configuration",
            ));
        }
    }
    if node.platform != "x86_64"
        || node.commit.len() != 40
        || !node
            .commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || node.version.is_empty()
        || node.version.len() > 32
        || !node
            .version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return Err(InventoryError::Unreadable("Near release metadata"));
    }
    Ok(())
}

fn fields(node: &NearRpc) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(node)?;
    let record =
        serde_json::to_string(node).map_err(|_| InventoryError::Unreadable("Near record"))?;
    Ok(vec![
        ("erpc_format", super::FORMAT.to_owned()),
        ("near_record", record),
    ])
}
fn read(item: &OpItem) -> Result<NearRpc, InventoryError> {
    let fields = checked(item)?;
    let mut node: NearRpc = serde_json::from_str(
        fields
            .get("near_record")
            .ok_or(InventoryError::Unreadable("Near record"))?,
    )
    .map_err(|_| InventoryError::Unreadable("Near record"))?;
    validate(&node)?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
impl<R: OpRunner> Store<R> {
    /// List Near RPC items in this exact scope.
    /// # Errors
    /// Wrong chain or malformed records are refused.
    pub fn near_rpcs(&self) -> Result<Vec<NearRpc>, InventoryError> {
        self.near_nodes(false)
    }
    /// List only the exact requested NEAR role.
    /// # Errors
    /// Rejects another chain scope, malformed records or inconsistent role tags.
    pub fn near_nodes(&self, validator: bool) -> Result<Vec<NearRpc>, InventoryError> {
        if self.scope.chain != "near" {
            return Err(InventoryError::Refused("expected Near scope".into()));
        }
        let nodes: Vec<NearRpc> = self
            .items(if validator {
                Kind::Validator
            } else {
                Kind::Rpc
            })?
            .iter()
            .map(read)
            .collect::<Result<_, _>>()?;
        if nodes
            .iter()
            .any(|node| node.validator.is_some() != validator)
        {
            return Err(InventoryError::Unreadable("NEAR role tag"));
        }
        Ok(nodes)
    }
    /// Reserve a host without changing its remote data.
    /// # Errors
    /// Duplicate name/address or a store failure prevents reservation.
    pub fn add_near_rpc(&self, node: &NearRpc) -> Result<NearRpc, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        for role in [false, true] {
            if self.near_nodes(role)?.iter().any(|old| {
                old.name == node.name
                    || old.address == node.address
                    || old
                        .validator
                        .as_ref()
                        .zip(node.validator.as_ref())
                        .is_some_and(|(a, b)| {
                            a.account_id == b.account_id || a.public_key == b.public_key
                        })
            }) {
                return Err(InventoryError::Refused(
                    "NEAR host or consensus identity is already reserved".into(),
                ));
            }
        }
        read(&self.create(
            if node.validator.is_some() {
                Kind::Validator
            } else {
                Kind::Rpc
            },
            &node.name,
            &fields(node)?,
            None,
        )?)
    }
    /// Update pins/run results while preserving host and platform ownership.
    /// # Errors
    /// Ownership changes and stale writes are refused.
    pub fn update_near_rpc(&self, node: &NearRpc) -> Result<NearRpc, InventoryError> {
        let _lock = self.lock()?;
        let id = node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("Near owner"))?;
        let old = read(&self.get(id)?)?;
        if old.validator != node.validator
            || (old.address, old.host_key, old.platform)
                != (
                    node.address.clone(),
                    node.host_key.clone(),
                    node.platform.clone(),
                )
        {
            return Err(InventoryError::Refused(
                "Near host and platform contract are immutable".into(),
            ));
        }
        read(&self.update(
            if node.validator.is_some() {
                Kind::Validator
            } else {
                Kind::Rpc
            },
            (Some(id), node.item_version),
            &node.name,
            &fields(node)?,
            None,
        )?)
    }
}
