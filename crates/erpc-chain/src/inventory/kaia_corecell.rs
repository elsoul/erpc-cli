// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Immutable Kaia core-cell host and consensus identity reservations.

use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked, kaia::KaiaRpc};
use serde::{Deserialize, Serialize};

/// One dedicated CN or PN host. All financial authorities are public addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KaiaCoreCell {
    /// Common immutable host/network/bootstrap contract and mutable release pin.
    #[serde(flatten)]
    pub node: KaiaRpc,
    /// Immutable native CN or PN role.
    pub node_kind: String,
    /// Explicit externally reachable numeric IPv4 address.
    pub advertise: String,
    /// Approved static KNI peer records, supplied by the operator.
    pub peers: Vec<String>,
    /// External reward recipient; no private wallet is read by the backend.
    pub reward_address: String,
    /// External manager account, normally a Safe wallet.
    pub manager_address: String,
    /// Externally deployed staking contract, empty before registration.
    pub staking_address: String,
    /// Administratively assigned uint256 GC ID, canonical decimal; zero if unassigned.
    pub gc_id: String,
    /// Established dedicated consensus/peer address; immutable after reservation.
    pub node_address: String,
    /// Original uncompressed secp256k1 public identity.
    pub peer_key: String,
    /// Original compressed BLS public key.
    pub bls_key: String,
    /// Original BLS proof of possession.
    pub bls_pop: String,
    /// Concealed same-owner backup reference, never the backup contents.
    pub backup_ref: String,
}

fn public_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn address(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|v| public_hex(v, 40) && v.bytes().any(|v| v != b'0'))
}
fn gc_id(value: &str) -> bool {
    const MAX: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    !value.is_empty()
        && value.bytes().all(|v| v.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && (value.len() < MAX.len() || (value.len() == MAX.len() && value <= MAX))
}
fn validate(node: &KaiaCoreCell) -> Result<(), InventoryError> {
    super::kaia::validate(&node.node)?;
    let identities = [
        &node.node_address,
        &node.peer_key,
        &node.bls_key,
        &node.bls_pop,
    ];
    let empty = identities.iter().all(|v| v.is_empty());
    if !matches!(node.node_kind.as_str(), "cn" | "pn")
        || (node.node_kind == "cn" && node.node.storage != "full")
        || node.advertise.parse::<std::net::Ipv4Addr>().is_err()
        || (!node.peers.is_empty() && !(2..=64).contains(&node.peers.len()))
        || node
            .peers
            .iter()
            .any(|v| v.len() > 256 || !v.starts_with("kni://"))
        || (node.node_kind == "cn"
            && (!address(&node.reward_address) || !address(&node.manager_address)))
        || !gc_id(&node.gc_id)
        || (node.node_kind == "pn"
            && (!node.reward_address.is_empty()
                || !node.manager_address.is_empty()
                || !node.staking_address.is_empty()
                || node.gc_id != "0"))
        || (!node.staking_address.is_empty() && !address(&node.staking_address))
        || (!empty
            && (!address(&node.node_address)
                || !public_hex(&node.peer_key, 128)
                || !public_hex(&node.bls_key, 96)
                || !public_hex(&node.bls_pop, 192)))
        || (!node.node_address.is_empty()
            && (node.node_address == node.reward_address
                || node.node_address == node.manager_address))
        || (!node.backup_ref.is_empty()
            && (empty || erpc_secret::OpRef::parse(&node.backup_ref).is_err()))
    {
        return Err(InventoryError::Unreadable("Kaia core-cell ownership"));
    }
    Ok(())
}
fn fields(node: &KaiaCoreCell) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(node)?;
    Ok(vec![
        ("erpc_format", super::FORMAT.into()),
        (
            "kaia_corecell",
            serde_json::to_string(node)
                .map_err(|_| InventoryError::Unreadable("Kaia core-cell record"))?,
        ),
    ])
}
fn read(item: &OpItem) -> Result<KaiaCoreCell, InventoryError> {
    let fields = checked(item)?;
    let mut node: KaiaCoreCell = serde_json::from_str(
        fields
            .get("kaia_corecell")
            .ok_or(InventoryError::Unreadable("Kaia core-cell record"))?,
    )
    .map_err(|_| InventoryError::Unreadable("Kaia core-cell record"))?;
    validate(&node)?;
    node.node.id = Some(item.id.clone());
    node.node.item_version = item.version;
    Ok(node)
}
fn same_host(old: &KaiaRpc, new: &KaiaRpc) -> bool {
    old.name == new.name
        && old.network == new.network
        && old.genesis == new.genesis
        && old.address == new.address
        && old.ssh_user == new.ssh_user
        && old.ssh_port == new.ssh_port
        && old.host_key == new.host_key
        && old.platform == new.platform
        && old.storage == new.storage
        && old.snapshot == new.snapshot
}
impl<R: OpRunner> Store<R> {
    /// List core cells in this exact Kaia network scope.
    /// # Errors
    /// Refuses malformed or cross-network records.
    pub fn kaia_corecells(&self) -> Result<Vec<KaiaCoreCell>, InventoryError> {
        if self.scope.chain != "kaia" {
            return Err(InventoryError::Refused("expected Kaia scope".into()));
        }
        let values = self
            .items(Kind::Validator)?
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        if values.iter().any(|v| v.node.network != self.scope.network) {
            return Err(InventoryError::Unreadable("Kaia core-cell network scope"));
        }
        Ok(values)
    }
    /// Reserve a fresh CN/PN host before creating operational custody.
    /// # Errors
    /// Duplicate hosts/names and malformed metadata are refused.
    pub fn add_kaia_corecell(&self, node: &KaiaCoreCell) -> Result<KaiaCoreCell, InventoryError> {
        check_name(&node.node.name)?;
        validate(node)?;
        if self.scope.chain != "kaia" || node.node.network != self.scope.network {
            return Err(InventoryError::Unreadable("Kaia core-cell network scope"));
        }
        let _lock = self.lock()?;
        let conflicts = self
            .kaia_corecells()?
            .iter()
            .any(|v| v.node.name == node.node.name || v.node.address == node.node.address)
            || self
                .kaia_rpcs()?
                .iter()
                .any(|v| v.name == node.node.name || v.address == node.node.address);
        if conflicts {
            return Err(InventoryError::Refused(
                "Kaia host is already reserved".into(),
            ));
        }
        if !node.node_address.is_empty() || !node.backup_ref.is_empty() {
            return Err(InventoryError::Refused(
                "Kaia consensus custody must originate on its newly reserved host".into(),
            ));
        }
        read(&self.create(Kind::Validator, &node.node.name, &fields(node)?, None)?)
    }
    /// Update public configuration and results without replacing a reserved key.
    /// # Errors
    /// Rejects host/role/key/backup changes and stale store writes.
    pub fn update_kaia_corecell(
        &self,
        node: &KaiaCoreCell,
    ) -> Result<KaiaCoreCell, InventoryError> {
        validate(node)?;
        if self.scope.chain != "kaia" || node.node.network != self.scope.network {
            return Err(InventoryError::Unreadable("Kaia core-cell network scope"));
        }
        let _lock = self.lock()?;
        let id = node
            .node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("Kaia core-cell owner"))?;
        let old = read(&self.get(id)?)?;
        if !same_host(&old.node, &node.node)
            || old.node_kind != node.node_kind
            || old.advertise != node.advertise
            || (!old.node_address.is_empty()
                && (&old.node_address, &old.peer_key, &old.bls_key, &old.bls_pop)
                    != (
                        &node.node_address,
                        &node.peer_key,
                        &node.bls_key,
                        &node.bls_pop,
                    ))
            || (!old.backup_ref.is_empty() && old.backup_ref != node.backup_ref)
        {
            return Err(InventoryError::Refused(
                "Kaia host, kind and reserved consensus identities are immutable".into(),
            ));
        }
        if !node.node_address.is_empty()
            && self.kaia_corecells()?.iter().any(|other| {
                other.node.id != node.node.id
                    && (other.node_address == node.node_address
                        || other.peer_key == node.peer_key
                        || other.bls_key == node.bls_key)
            })
        {
            return Err(InventoryError::Refused(
                "Kaia identity is reserved by another managed owner".into(),
            ));
        }
        read(&self.update(
            Kind::Validator,
            (Some(id), node.node.item_version),
            &node.node.name,
            &fields(node)?,
            None,
        )?)
    }
}
