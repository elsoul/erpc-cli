// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Original separate AQA host and identifier-only concealed agent reference.
use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use erpc_chain_hyperliquid::aqa::{Contract, host_binding};
use erpc_secret::OpRef;
use serde::{Deserialize, Serialize};

/// Public AQA lifecycle metadata. Original keys remain in concealed custody.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publisher {
    /// Inventory identifier, excluded from the serialized public record.
    #[serde(skip)]
    pub id: Option<String>,
    /// Optimistic concurrency version.
    #[serde(skip)]
    pub item_version: u64,
    /// Original operator inventory name.
    pub name: String,
    /// Original SSH destination.
    pub address: String,
    /// Original administrative SSH login.
    pub ssh_user: String,
    /// Original SSH port.
    pub ssh_port: u16,
    /// Original pinned public SSH host key.
    pub host_key: String,
    /// Immutable separate-host and public agent relationship.
    pub contract: Contract,
    /// Identifier-only field reference; never an arbitrary URL or private value.
    pub agent_key_ref: String,
    /// Qualified native publisher version.
    pub version: String,
    /// Qualified signed archive digest.
    pub archive_sha256: String,
    /// Original qualified signature timestamp; update rollback is refused.
    pub signed_at: u64,
    /// Additional management-only ingress ranges.
    pub management_allow: Vec<String>,
    /// Last remote operation identifier.
    pub last_run: String,
    /// Last completed operation result.
    pub last_result: String,
}
impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AqaPublisher")
            .field("name", &self.name)
            .field("contract", &self.contract)
            .field("agent_key_ref", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
fn invalid() -> InventoryError {
    InventoryError::Unreadable("AQA publisher ownership")
}
fn validate(node: &Publisher) -> Result<(), InventoryError> {
    check_name(&node.name)?;
    node.contract.validate().map_err(|_| invalid())?;
    OpRef::parse(&node.agent_key_ref).map_err(|_| invalid())?;
    if node.address.is_empty()
        || node.address.len() > 253
        || node
            .address
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || node.ssh_user.is_empty()
        || node.ssh_user.len() > 32
        || !node
            .ssh_user
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        || ["erpc-hl-aqa", "erpc-hyperliquid", "erpc-hyperliquid-rpc"]
            .contains(&node.ssh_user.as_str())
        || node.ssh_port == 0
        || node.host_key.len() > 2048
        || host_binding(&node.address, &node.ssh_user, node.ssh_port, &node.host_key)
            != node.contract.host_binding
        || node.archive_sha256.len() != 64
        || !(1..4_102_444_800).contains(&node.signed_at)
        || !node
            .archive_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || node.version.split('.').count() != 3
        || node.version.len() > 24
        || node
            .version
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(invalid());
    }
    if erpc_chain_hyperliquid::aqa::management(&node.management_allow).map_err(|_| invalid())?
        != node.management_allow
    {
        return Err(invalid());
    }
    Ok(())
}
fn read(item: &OpItem) -> Result<Publisher, InventoryError> {
    let fields = checked(item)?;
    let mut node: Publisher =
        serde_json::from_str(fields.get("hyperliquid_aqa_record").ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    validate(&node)?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
fn fields(node: &Publisher) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(node)?;
    Ok(vec![
        ("erpc_format", super::FORMAT.into()),
        (
            "hyperliquid_aqa_record",
            serde_json::to_string(node).map_err(|_| invalid())?,
        ),
    ])
}
impl<R: OpRunner> Store<R> {
    /// Read the selected network's separate AQA publisher records.
    /// # Errors
    /// Refuses malformed records or another chain/network scope.
    pub fn hyperliquid_publishers(&self) -> Result<Vec<Publisher>, InventoryError> {
        if self.scope.chain != "hyperliquid" {
            return Err(invalid());
        }
        let nodes = self
            .items(Kind::Publisher)?
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        if nodes
            .iter()
            .any(|node| node.contract.network.name() != self.scope.network)
        {
            return Err(invalid());
        }
        Ok(nodes)
    }
    /// Reserve a new separate host and dedicated key, without reading secret fields.
    /// # Errors
    /// Refuses duplicate names, hosts, keys/references and consensus-key reuse.
    pub fn add_hyperliquid_publisher(&self, node: &Publisher) -> Result<Publisher, InventoryError> {
        validate(node)?;
        if self.scope.chain != "hyperliquid"
            || node.contract.network.name() != self.scope.network
            || node.id.is_some()
            || node.item_version != 0
        {
            return Err(invalid());
        }
        let _lock = self.lock()?;
        let duplicate = self.hyperliquid_publishers()?.iter().any(|old| {
            old.name == node.name
                || old.address == node.address
                || old.host_key == node.host_key
                || old.contract.owner == node.contract.owner
                || old.contract.identity.agent == node.contract.identity.agent
                || old.agent_key_ref == node.agent_key_ref
        });
        let native = self.hyperliquid_nodes()?.iter().any(|old| {
            old.name == node.name
                || old.address == node.address
                || old.host_key == node.host_key
                || old.contract.owner == node.contract.owner
        });
        let consensus = self.hyperliquid_validators()?.iter().any(|old| {
            old.host.name == node.name
                || old.host.address == node.address
                || old.host.host_key == node.host_key
                || old.host.contract.owner == node.contract.owner
                || old.hot_key_ref == node.agent_key_ref
                || old
                    .host
                    .contract
                    .validator
                    .as_ref()
                    .is_some_and(|identity| {
                        identity.signer == node.contract.identity.agent
                            || identity.validator == node.contract.identity.agent
                    })
        });
        if duplicate || native || consensus {
            return Err(InventoryError::Refused(
                "AQA host or agent already belongs to another original profile".into(),
            ));
        }
        read(&self.create(Kind::Publisher, &node.name, &fields(node)?, None)?)
    }
    /// Update operational observations/policy while retaining the original host and key.
    /// # Errors
    /// Refuses stale updates or changes to immutable custody/connection fields.
    pub fn update_hyperliquid_publisher(
        &self,
        node: &Publisher,
    ) -> Result<Publisher, InventoryError> {
        validate(node)?;
        if self.scope.chain != "hyperliquid" || node.contract.network.name() != self.scope.network {
            return Err(invalid());
        }
        let _lock = self.lock()?;
        let id = node.id.as_deref().ok_or_else(invalid)?;
        let previous = read(&self.get(id)?)?;
        if previous.name != node.name
            || previous.address != node.address
            || previous.ssh_user != node.ssh_user
            || previous.ssh_port != node.ssh_port
            || previous.host_key != node.host_key
            || previous.contract != node.contract
            || previous.agent_key_ref != node.agent_key_ref
            || node.signed_at < previous.signed_at
        {
            return Err(InventoryError::Refused(
                "AQA original host, agent and approval scope are immutable".into(),
            ));
        }
        read(&self.update(
            Kind::Publisher,
            (Some(id), node.item_version),
            &node.name,
            &fields(node)?,
            None,
        )?)
    }
}
