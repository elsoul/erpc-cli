// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public native ownership uses field projections, never concealed keys or legacy passwords.
use super::{
    FORMAT, InventoryError, Kind, OpRunner, Store, Validator, solana_public::selected_fields,
    validator_fields,
};
use erpc_chain_solana_native::contract::{Contract, host_binding};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const LABELS: [&str; 3] = ["erpc_format", "name", "native_host"];
const SELECTOR: &str = "label=erpc_format,label=name,label=native_host";

/// Public SSH and immutable native node ownership; no credential references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHost {
    /// Public metadata item version observed before a subsequent mutation.
    #[serde(skip)]
    pub item_version: u64,
    /// Original host, public accounts and provisioned filesystems.
    pub contract: Contract,
    /// SSH address, never a shell fragment.
    pub address: String,
    /// Management login; distinct from both runtime and builder accounts.
    pub ssh_user: String,
    /// Pinned SSH port.
    pub ssh_port: u16,
    /// Canonical OpenSSH Ed25519 host key.
    pub host_key: String,
}

/// Deployment settings read separately from public host listings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConfig {
    /// Identifier-only concealed node identity field; never the private value.
    pub identity_ref: String,
    /// Separate non-voting synchronization identity for a validator profile.
    pub sync_ref: Option<String>,
    /// Public synchronization identity; not the registered signing identity.
    pub sync_identity: Option<String>,
    /// Explicit client/TLS-gateway networks allowed to use RPC.
    pub rpc_allow: Vec<String>,
    /// Additional SSH management networks; the current connection is added at deployment.
    pub management_allow: Vec<String>,
    /// External vote-account commission policy, absent for RPC-only hosts.
    pub commission: Option<u8>,
}
impl std::fmt::Debug for NativeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeConfig").finish_non_exhaustive()
    }
}
impl NativeConfig {
    /// Validate role separation and canonical bounded access lists before tools run.
    /// # Errors
    /// Refuses non-identifier references, financial/RPC role confusion or unsafe ACLs,
    /// each with the rule it breaks ([`InventoryError::Refused`]).
    pub fn validate(&self, contract: &Contract) -> Result<(), InventoryError> {
        let refused = |reason: &str| InventoryError::Refused(reason.to_owned());
        erpc_secret::OpRef::parse(&self.identity_ref).map_err(|e| {
            InventoryError::Refused(format!("the identity reference is not usable: {e}"))
        })?;
        if contract.is_rpc() {
            if self.sync_ref.is_some() || self.sync_identity.is_some() || self.commission.is_some()
            {
                return Err(refused(
                    "an RPC host takes no synchronization identity and no commission",
                ));
            }
        } else {
            let reference = self
                .sync_ref
                .as_deref()
                .ok_or_else(|| refused("a validator needs a synchronization identity reference"))?;
            erpc_secret::OpRef::parse(reference).map_err(|e| {
                InventoryError::Refused(format!(
                    "the synchronization identity reference is not usable: {e}"
                ))
            })?;
            let identity = self.sync_identity.as_deref().ok_or_else(|| {
                refused("a validator needs its synchronization identity's public key")
            })?;
            if reference == self.identity_ref {
                return Err(refused(
                    "the synchronization identity reference must differ from the identity reference",
                ));
            }
            if identity == contract.identity_account {
                return Err(refused(
                    "the synchronization identity must differ from the validator identity",
                ));
            }
            let mut trial = contract.clone();
            identity.clone_into(&mut trial.identity_account);
            if trial.inventory_id.is_empty() {
                trial.inventory_id = "a".repeat(26);
            }
            trial.validate().map_err(|_| {
                refused(
                    "the synchronization identity must be a canonical public key, \
                     distinct from the vote account and the withdrawal authority",
                )
            })?;
            if !self.rpc_allow.is_empty() {
                return Err(refused("a validator takes no RPC allow list"));
            }
            if self.commission.is_none_or(|value| value > 100) {
                return Err(refused("a validator needs a commission from 0 to 100"));
            }
        }
        for (list, values) in [
            ("RPC allow list", &self.rpc_allow),
            ("management allow list", &self.management_allow),
        ] {
            if values.len() > 64 {
                return Err(InventoryError::Refused(format!(
                    "the {list} holds more than 64 networks"
                )));
            }
            let mut seen = std::collections::BTreeSet::new();
            for value in values {
                if !seen.insert(value) {
                    return Err(InventoryError::Refused(format!(
                        "the {list} names {value:?} twice"
                    )));
                }
                check_network(value).map_err(|rule| {
                    InventoryError::Refused(format!("{value:?} in the {list} {rule}"))
                })?;
            }
        }
        Ok(())
    }
}

/// An access-list entry: a network written as its first address and its
/// prefix, the one way erpc prints it. The error is the rule it breaks.
fn check_network(value: &str) -> Result<(), String> {
    let (address, width) = value
        .split_once('/')
        .and_then(|(address, prefix)| {
            Some((address.parse::<IpAddr>().ok()?, prefix.parse::<u8>().ok()?))
        })
        .ok_or("is not a network such as 198.51.100.0/24")?;
    let (minimum, maximum) = if address.is_ipv4() {
        (8, 32)
    } else {
        (32, 128)
    };
    if !(minimum..=maximum).contains(&width) {
        return Err(format!("needs a prefix from /{minimum} to /{maximum}"));
    }
    let bits = match address {
        IpAddr::V4(value) => u128::from(u32::from(value)),
        IpAddr::V6(value) => u128::from(value),
    };
    let host_mask = (1_u128 << (maximum - width)) - 1;
    if bits & host_mask != 0 {
        return Err(format!("is not the first address of a /{width} network"));
    }
    if address.is_unspecified()
        || address.is_multicast()
        || matches!(address, IpAddr::V6(value) if value.to_ipv4_mapped().is_some())
    {
        return Err("is an unspecified, multicast or IPv4-mapped network".into());
    }
    if format!("{address}/{width}") != value {
        return Err(format!("must be written {address}/{width}"));
    }
    Ok(())
}
fn invalid() -> InventoryError {
    InventoryError::Unreadable("native Solana host metadata")
}
impl NativeHost {
    /// Check public connection coordinates against immutable host ownership.
    /// # Errors
    /// Refuses malformed accounts, keys, names, filesystems or a changed host binding.
    pub fn validate(&self) -> Result<(), InventoryError> {
        self.contract.validate().map_err(|_| invalid())?;
        erpc_ssh::config::check_host(&self.address).map_err(|_| invalid())?;
        let key = erpc_ssh::HostKey::parse(&self.host_key).map_err(|_| invalid())?;
        if key.to_openssh() != self.host_key
            || self.ssh_port == 0
            || self.ssh_user.is_empty()
            || self.ssh_user.len() > 32
            || !self.ssh_user.as_bytes()[0].is_ascii_lowercase()
            || !self
                .ssh_user
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
            || [
                "solv",
                "erpc-solana",
                "erpc-solana-build",
                "erpc-solana-proof",
                "erpc-solana-gateway",
            ]
            .contains(&self.ssh_user.as_str())
            || host_binding(&self.address, &self.ssh_user, self.ssh_port, &self.host_key)
                != self.contract.host_binding
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn fields(&self) -> Result<Vec<(&'static str, String)>, InventoryError> {
        let mut record = self.clone();
        // The store assigns identity; do not accept an identity from JSON data.
        record.contract.inventory_id.clear();
        let record = serde_json::to_string(&record).map_err(|_| invalid())?;
        Ok(vec![
            ("erpc_format", FORMAT.into()),
            ("name", self.contract.name.clone()),
            ("native_host", record),
        ])
    }
}

fn decode(raw: &SecretString, name: &str) -> Result<NativeHost, InventoryError> {
    let selected = selected_fields(raw, &LABELS)?;
    let get = |label: &str| {
        selected
            .get(label)
            .map(SecretString::expose_secret)
            .ok_or_else(invalid)
    };
    if get("erpc_format")? != FORMAT || get("name")? != name {
        return Err(invalid());
    }
    let node: NativeHost = serde_json::from_str(get("native_host")?).map_err(|_| invalid())?;
    if node.contract.name != name || !node.contract.inventory_id.is_empty() {
        return Err(invalid());
    }
    Ok(node)
}

#[derive(Deserialize)]
struct Created {
    id: String,
}

impl<R: OpRunner> Store<R> {
    pub(super) fn reject_other_validator_identity(
        &self,
        name: &str,
        identity: &str,
    ) -> Result<(), InventoryError> {
        for other in self.public_names(Kind::Validator)? {
            if other == name {
                continue;
            }
            let (_, _, same) = self.public_projection(
                Kind::Validator,
                &other,
                "label=erpc_format,label=name,label=identity_account",
                |raw| {
                    let selected =
                        selected_fields(raw, &["erpc_format", "name", "identity_account"])?;
                    if selected["erpc_format"].expose_secret() != FORMAT
                        || selected["name"].expose_secret() != other
                    {
                        return Err(invalid());
                    }
                    Ok(selected["identity_account"].expose_secret() == identity)
                },
            )?;
            if same {
                return Err(InventoryError::Refused(
                    "another validator already reserves this signing identity".into(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn create_projected_note(
        &self,
        kind: Kind,
        name: &str,
        fields: &[(&str, String)],
    ) -> Result<(String, u64), InventoryError> {
        let template = self.template(kind, name, fields, None);
        let output = self
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
            .map_err(|_| invalid())?;
        let _stderr = SecretString::from(output.stderr);
        let raw = SecretString::from(output.stdout);
        if !output.success || raw.expose_secret().len() > 1_048_576 {
            return Err(invalid());
        }
        let created: Created = serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?;
        let labels: Vec<_> = fields.iter().map(|(label, _)| *label).collect();
        let selector = labels
            .iter()
            .map(|label| format!("label={label}"))
            .collect::<Vec<_>>()
            .join(",");
        let (id, version, ()) = self.public_projection(kind, name, &selector, |raw| {
            let selected = selected_fields(raw, &labels)?;
            if fields
                .iter()
                .any(|(label, expected)| selected[*label].expose_secret() != expected)
            {
                return Err(invalid());
            }
            Ok(())
        })?;
        if id != created.id {
            return Err(invalid());
        }
        Ok((id, version))
    }

    /// Reserve public logical-validator metadata after its identity key was stored.
    /// This does not create/import a withdrawal or vote-account private key.
    /// # Errors
    /// Refuses existing names, different public accounts, nonqualified client pins
    /// and financial key references; all read-back uses explicit public fields.
    pub fn add_native_solana_validator(
        &self,
        validator: &Validator,
        node: &NativeHost,
    ) -> Result<Validator, InventoryError> {
        if node.contract.is_rpc()
            || !node.contract.inventory_id.is_empty()
            || node.item_version != 0
        {
            return Err(invalid());
        }
        let mut provisional = node.clone();
        provisional.contract.inventory_id = "a".repeat(26);
        provisional.validate()?;
        let catalog = erpc_chain_solana_native::catalog().map_err(|_| invalid())?;
        let source = catalog
            .networks
            .get(&self.scope.network)
            .ok_or_else(invalid)?;
        let reference: Vec<_> = validator
            .identity_ref
            .strip_prefix("op://")
            .ok_or_else(invalid)?
            .split('/')
            .collect();
        let id = |value: &str| {
            value.len() == 26
                && value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        };
        if reference.len() != 3
            || !id(reference[0])
            || !id(reference[1])
            || reference[2] != "keypair"
            || validator.id.is_some()
            || validator.item_version != 0
            || validator.name != node.contract.name
            || node.contract.network != self.scope.network
            || validator.identity_account != node.contract.identity_account
            || Some(validator.vote_account.as_str()) != node.contract.vote_account.as_deref()
            || Some(validator.authority_account.as_str())
                != node.contract.authority_account.as_deref()
            || !validator.vote_ref.is_empty()
            || !validator.authority_ref.is_empty()
            || !validator.active_host.is_empty()
            || !validator.region.is_empty()
            || validator.client != "agave"
            || validator.version != source.version
            || validator.commit != source.commit
        {
            return Err(invalid());
        }
        let _lock = self.lock()?;
        if self
            .public_names(Kind::Validator)?
            .iter()
            .any(|name| name == &validator.name)
            || self.solana_native_hosts()?.iter().any(|host| {
                host.contract.name == validator.name
                    || host.contract.identity_account == validator.identity_account
            })
        {
            return Err(InventoryError::Refused(
                "validator name is already reserved; resume its original identity".into(),
            ));
        }
        self.reject_other_validator_identity(&validator.name, &validator.identity_account)?;
        let (id, version) = self.create_projected_note(
            Kind::Validator,
            &validator.name,
            &validator_fields(validator),
        )?;
        let mut stored = validator.clone();
        stored.id = Some(id);
        stored.item_version = version;
        Ok(stored)
    }

    /// Read precisely the three public native-host fields from one item.
    /// # Errors
    /// Refuses concurrent edits, secret fields, wrong scope or malformed ownership.
    pub fn solana_native_host(&self, name: &str) -> Result<NativeHost, InventoryError> {
        let (id, version, mut node) =
            self.public_projection(Kind::NativeHost, name, SELECTOR, |raw| decode(raw, name))?;
        node.contract.inventory_id = id;
        node.item_version = version;
        node.validate()?;
        if node.contract.network != self.scope.network {
            return Err(invalid());
        }
        Ok(node)
    }

    /// List dedicated native hosts without reading legacy passwords or keys.
    /// # Errors
    /// Ambiguous or changed public items are refused.
    pub fn solana_native_hosts(&self) -> Result<Vec<NativeHost>, InventoryError> {
        self.public_names(Kind::NativeHost)?
            .iter()
            .map(|name| self.solana_native_host(name))
            .collect()
    }

    fn reject_legacy_native_collision(&self, node: &NativeHost) -> Result<(), InventoryError> {
        // Query only public connection/validator fields of older nodes. Whole
        // Host gets would also request solv_password, which is unnecessary here.
        for kind in [Kind::Host, Kind::Rpc] {
            let labels: &[&str] = if kind == Kind::Host {
                &["erpc_format", "name", "address", "host_key", "validator"]
            } else {
                &["erpc_format", "name", "address", "host_key"]
            };
            let selector = labels
                .iter()
                .map(|label| format!("label={label}"))
                .collect::<Vec<_>>()
                .join(",");
            for name in self.public_names(kind)? {
                let (_, _, (old_name, address, host_key, validator)) =
                    self.public_projection(kind, &name, &selector, |raw| {
                        let selected = selected_fields(raw, labels)?;
                        if selected["erpc_format"].expose_secret() != FORMAT {
                            return Err(invalid());
                        }
                        Ok((
                            selected["name"].expose_secret().to_owned(),
                            selected["address"].expose_secret().to_owned(),
                            selected["host_key"].expose_secret().to_owned(),
                            selected
                                .get("validator")
                                .map_or("", SecretString::expose_secret)
                                .to_owned(),
                        ))
                    })?;
                if old_name != name {
                    return Err(invalid());
                }
                let key = erpc_ssh::HostKey::parse(&host_key).map_err(|_| invalid())?;
                if address == node.address
                    || key.to_openssh() == node.host_key
                    || (kind == Kind::Host && validator == node.contract.name)
                {
                    return Err(InventoryError::Refused(
                        "legacy host requires explicit migration before native reservation".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Reserve one native validator host or a dedicated non-voting RPC host.
    /// # Errors
    /// Refuses legacy migration, duplicate host/identity, and registration mismatch.
    /// Validator hosts require matching logical public registration; RPC hosts
    /// have no financial account and cannot adopt a logical validator's name.
    pub fn add_solana_native_host(&self, node: &NativeHost) -> Result<NativeHost, InventoryError> {
        self.reserve_solana_native_host(node, None)
    }

    /// Reserve ownership and immutable key references together before host mutation.
    /// # Errors
    /// Refuses invalid settings, duplicates, existing legacy hosts or mismatched registration.
    pub fn add_configured_solana_native_host(
        &self,
        node: &NativeHost,
        configuration: &NativeConfig,
    ) -> Result<NativeHost, InventoryError> {
        configuration.validate(&node.contract)?;
        self.reserve_solana_native_host(node, Some(configuration))
    }

    fn reserve_solana_native_host(
        &self,
        node: &NativeHost,
        configuration: Option<&NativeConfig>,
    ) -> Result<NativeHost, InventoryError> {
        if !node.contract.inventory_id.is_empty() || node.item_version != 0 {
            return Err(invalid());
        }
        let mut provisional = node.clone();
        provisional.contract.inventory_id = "a".repeat(26);
        provisional.validate()?;
        if node.contract.network != self.scope.network {
            return Err(invalid());
        }
        let _lock = self.lock()?;
        if self.solana_pending_migrations()?.iter().any(|pending| {
            pending.node.contract.name == node.contract.name
                || pending.node.address == node.address
                || pending.node.host_key == node.host_key
                || pending.node.contract.identity_account == node.contract.identity_account
        }) {
            return Err(InventoryError::Refused(
                "pending Solv migration cannot be replaced by native initialization".into(),
            ));
        }
        self.reject_other_validator_identity(&node.contract.name, &node.contract.identity_account)?;
        if node.contract.is_rpc() {
            if self
                .public_names(Kind::Validator)?
                .contains(&node.contract.name)
            {
                return Err(InventoryError::Refused(
                    "RPC name belongs to a validator".into(),
                ));
            }
        } else {
            let validator = self.public_solana_validator(&node.contract.name)?;
            if validator.identity_account != node.contract.identity_account
                || Some(validator.vote_account.as_str()) != node.contract.vote_account.as_deref()
                || Some(validator.authority_account.as_str())
                    != node.contract.authority_account.as_deref()
            {
                return Err(InventoryError::Refused(
                    "native public registration differs".into(),
                ));
            }
        }
        if self.solana_native_hosts()?.iter().any(|old| {
            old.contract.name == node.contract.name
                || old.address == node.address
                || old.host_key == node.host_key
                || old.contract.identity_account == node.contract.identity_account
        }) {
            return Err(InventoryError::Refused(
                "native host or identity is already reserved, or public registration differs"
                    .into(),
            ));
        }
        self.reject_legacy_native_collision(node)?;
        let mut fields = node.fields()?;
        if let Some(configuration) = configuration {
            fields.push((
                "native_config",
                serde_json::to_string(configuration).map_err(|_| invalid())?,
            ));
        }
        let (created, _) =
            self.create_projected_note(Kind::NativeHost, &node.contract.name, &fields)?;
        let back = self.solana_native_host(&node.contract.name)?;
        let mut expected = node.clone();
        expected.contract.inventory_id.clone_from(&created);
        expected.item_version = back.item_version;
        if back != expected {
            return Err(invalid());
        }
        Ok(back)
    }

    /// Read only original native public accounts, without legacy passwords or key references.
    /// # Errors
    /// Refuses a non-validator host or a changed logical registration.
    pub fn public_native_solana_keys(
        &self,
        name: &str,
    ) -> Result<super::solana_public::PublicValidator, InventoryError> {
        let node = self.solana_native_host(name)?;
        let keys = self.public_solana_validator(name)?;
        if node.contract.is_rpc()
            || node.contract.identity_account != keys.identity_account
            || node.contract.vote_account.as_deref() != Some(keys.vote_account.as_str())
            || node.contract.authority_account.as_deref() != Some(keys.authority_account.as_str())
            || self.solana_native_host(name)? != node
        {
            return Err(invalid());
        }
        Ok(keys)
    }

    /// Read deployment settings without requesting the concealed node key values.
    /// # Errors
    /// Refuses a changed item/owner, wrong field type or malformed role settings.
    pub fn solana_native_config(&self, node: &NativeHost) -> Result<NativeConfig, InventoryError> {
        node.validate()?;
        let (id, version, value) = self.public_projection(
            Kind::NativeHost,
            &node.contract.name,
            "label=erpc_format,label=name,label=native_config",
            |raw| {
                let fields = selected_fields(raw, &["erpc_format", "name", "native_config"])?;
                if fields["erpc_format"].expose_secret() != FORMAT
                    || fields["name"].expose_secret() != node.contract.name
                {
                    return Err(invalid());
                }
                serde_json::from_str::<NativeConfig>(fields["native_config"].expose_secret())
                    .map_err(|_| invalid())
            },
        )?;
        if id != node.contract.inventory_id || version != node.item_version {
            return Err(InventoryError::Changed(node.contract.name.clone()));
        }
        // What was stored was checked when it was written; a rule it breaks
        // now is a reply this version cannot read, not a setting to fix.
        value.validate(&node.contract).map_err(|_| invalid())?;
        Ok(value)
    }

    fn verify_protected_native_config(
        &self,
        template: &super::solana_migration_item::MigrationItem,
        node: &NativeHost,
        original: &NativeConfig,
    ) -> Result<(), InventoryError> {
        if template
            .field("erpc_format", "STRING")
            .map_err(|_| invalid())?
            != FORMAT
            || template.field("name", "STRING").map_err(|_| invalid())? != node.contract.name
        {
            return Err(invalid());
        }
        let mut original_host: NativeHost = serde_json::from_str(
            template
                .field("native_host", "STRING")
                .map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        if !original_host.contract.inventory_id.is_empty() {
            return Err(invalid());
        }
        original_host
            .contract
            .inventory_id
            .clone_from(&node.contract.inventory_id);
        original_host.item_version = node.item_version;
        let original_config: NativeConfig = serde_json::from_str(
            template
                .field("native_config", "STRING")
                .map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        if original_host != *node
            || original_config != *original
            || self.solana_native_host(&node.contract.name)? != *node
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Save access policy after rechecking the original public item version.
    /// Key references, synchronization identity and commission cannot change.
    /// # Errors
    /// Refuses stale scope, identity changes, provider failure or differing readback.
    pub fn update_solana_native_config(
        &self,
        node: &NativeHost,
        configuration: &NativeConfig,
    ) -> Result<NativeHost, InventoryError> {
        configuration.validate(&node.contract)?;
        let _lock = self.lock()?;
        if self.solana_native_host(&node.contract.name)? != *node {
            return Err(InventoryError::Changed(node.contract.name.clone()));
        }
        let original = self.solana_native_config(node)?;
        if original.identity_ref != configuration.identity_ref
            || original.sync_ref != configuration.sync_ref
            || original.sync_identity != configuration.sync_identity
            || original.commission != configuration.commission
        {
            return Err(InventoryError::Refused(
                "native signing ownership is immutable".into(),
            ));
        }
        let (mut template, vault) = self.protected_native_note(
            Kind::NativeHost,
            &node.contract.name,
            &node.contract.inventory_id,
            node.item_version,
        )?;
        self.verify_protected_native_config(&template, node, &original)?;
        template
            .set_field(
                "native_config",
                "STRING",
                serde_json::to_string(configuration)
                    .map_err(|_| invalid())?
                    .into(),
            )
            .map_err(|_| invalid())?;
        let body = template.serialize().map_err(|_| invalid())?;
        let output = self
            .runner
            .run(
                &[
                    "item",
                    "edit",
                    &node.contract.inventory_id,
                    "--vault",
                    &vault,
                    "--format",
                    "json",
                ],
                Some(body.expose_secret()),
            )
            .map_err(|_| invalid())?;
        let _stdout = SecretString::from(output.stdout);
        let _stderr = SecretString::from(output.stderr);
        if !output.success {
            return Err(invalid());
        }
        let back = self.solana_native_host(&node.contract.name)?;
        let mut expected = node.clone();
        expected.item_version = back.item_version;
        if back != expected || self.solana_native_config(&back)? != *configuration {
            return Err(invalid());
        }
        let (after, after_vault) = self.protected_native_note(
            Kind::NativeHost,
            &back.contract.name,
            &back.contract.inventory_id,
            back.item_version,
        )?;
        if after_vault != vault
            || !template
                .preserves(&after, &["native_config"])
                .map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        Ok(back)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{Host, Role, Scope, SolanaRpc, host_fields, solana_rpc_fields};
    use erpc_auth::store::{StoreError, one_password::OpOutput};
    use erpc_chain_solana_native::contract::Volumes;
    use serde_json::{Value, json};
    use std::cell::RefCell;

    fn host() -> NativeHost {
        // Inert public SSH key already used by the SSH parser fixtures.
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/";
        NativeHost {
            item_version: 0,
            address: "192.0.2.10".into(),
            ssh_user: "operator".into(),
            ssh_port: 22,
            host_key: key.into(),
            contract: Contract {
                schema: 1,
                profile: "agave-native".into(),
                inventory_id: String::new(),
                name: "fixture".into(),
                network: "testnet".into(),
                host_binding: host_binding("192.0.2.10", "operator", 22, key),
                identity_account: "2".repeat(44),
                vote_account: Some("3".repeat(44)),
                authority_account: Some("4".repeat(44)),
                volumes: Volumes {
                    accounts: "10000000-0000-0000-0000-000000000001".into(),
                    ledger: "10000000-0000-0000-0000-000000000002".into(),
                    snapshots: "10000000-0000-0000-0000-000000000003".into(),
                },
            },
        }
    }
    fn rpc_config() -> NativeConfig {
        NativeConfig {
            identity_ref: format!("op://{}/{}/identity", "a".repeat(26), "b".repeat(26)),
            sync_ref: None,
            sync_identity: None,
            rpc_allow: vec!["192.0.2.0/24".into()],
            management_allow: vec![],
            commission: None,
        }
    }

    #[test]
    fn public_backend_and_mixed_summaries_do_not_request_private_fields_or_infer_deployment() {
        use crate::inventory::solana_listing::Backend;
        let mock = fixture();
        for (label, value) in [
            ("client", "agave"),
            ("version", "v4.4.0-beta.1"),
            ("region", ""),
        ] {
            mock.items.borrow_mut()[0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":label,"label":label,"type":"STRING","value":value}));
        }
        assert_eq!(
            store(&mock).solana_backend("fixture", false).unwrap(),
            Backend::New
        );
        assert_eq!(
            store(&mock).solana_backend("new-node", false).unwrap(),
            Backend::New
        );
        store(&mock).add_solana_native_host(&host()).unwrap();
        mock.calls.borrow_mut().clear();
        assert_eq!(
            store(&mock).solana_backend("fixture", false).unwrap(),
            Backend::Native
        );
        assert!(store(&mock).solana_backend("fixture", true).is_err());
        let rows = store(&mock).solana_node_summaries(false).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["backend"], "native");
        assert!(rows[0]["version"].is_null());
        assert!(rows[0]["hosts"][0]["last_result"].is_null());
        for call in mock.calls.borrow().iter().filter(|call| call[1] == "get") {
            assert_eq!(call[5], "--fields");
            assert!(
                !["solv_password", "identity_ref", "native_config", "keypair"]
                    .iter()
                    .any(|label| call[6].contains(label))
            );
        }
        assert!(!rows[0].to_string().contains("op://"));
        let fields = [
            ("erpc_format", "1"),
            ("name", "legacy-primary"),
            ("validator", "fixture"),
        ];
        let raw = store(&mock).template(
            Kind::Host,
            "legacy-primary",
            &fields
                .iter()
                .map(|(k, v)| (*k, (*v).to_owned()))
                .collect::<Vec<_>>(),
            None,
        );
        let mut legacy: Value = serde_json::from_str(&raw).unwrap();
        legacy["id"] = "h".repeat(26).into();
        legacy["version"] = 1.into();
        legacy["fields"].as_array_mut().unwrap().push(json!({"id":"solv_password","label":"solv_password","type":"CONCEALED","value":"inert password decoy"}));
        mock.items.borrow_mut().push(legacy);
        assert!(store(&mock).solana_backend("fixture", false).is_err());
        mock.items
            .borrow_mut()
            .retain(|item| !item["title"].as_str().unwrap().ends_with(" native-host"));
        assert_eq!(
            store(&mock).solana_backend("fixture", false).unwrap(),
            Backend::Solv
        );
    }

    #[test]
    fn mixed_rpc_listing_preserves_legacy_rows_and_rejects_concealed_substitution() {
        use crate::inventory::solana_listing::Backend;
        let mut mock = fixture();
        mock.items.borrow_mut().clear();
        let mut node = host();
        node.contract.profile = "agave-native-rpc".into();
        node.contract.vote_account = None;
        node.contract.authority_account = None;
        store(&mock).add_solana_native_host(&node).unwrap();
        let fields = [
            ("erpc_format", "1"),
            ("name", "legacy"),
            ("address", "192.0.2.12"),
            ("client", "jito"),
            ("rpc_type", "grpc"),
            ("version", "v4.3.2-jito"),
            ("identity_account", "inert-public-identity"),
            ("rpc_allow", "192.0.2.0/24,198.51.100.3/32"),
            ("last_result", "deployed"),
        ];
        let mut record = store(&mock).template(
            Kind::Rpc,
            "legacy",
            &fields
                .iter()
                .map(|(k, v)| (*k, (*v).to_owned()))
                .collect::<Vec<_>>(),
            None,
        );
        let mut item: Value = serde_json::from_str(&record).unwrap();
        record.clear();
        item["id"] = "r".repeat(26).into();
        item["version"] = 1.into();
        item["fields"].as_array_mut().unwrap().push(json!({"id":"solv_password","label":"solv_password","type":"CONCEALED","value":"inert password decoy"}));
        mock.items.borrow_mut().push(item);
        mock.calls.borrow_mut().clear();
        assert_eq!(
            store(&mock).solana_backend("legacy", true).unwrap(),
            Backend::Solv
        );
        let rows = store(&mock).solana_node_summaries(true).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["backend"], "native");
        assert!(rows[0]["version"].is_null());
        assert_eq!(rows[1]["backend"], "solv");
        assert_eq!(rows[1]["type"], "grpc");
        assert_eq!(
            rows[1]["rpc_allow"],
            json!(["192.0.2.0/24", "198.51.100.3/32"])
        );
        assert!(!serde_json::to_string(&rows).unwrap().contains("decoy"));
        assert!(
            mock.calls
                .borrow()
                .iter()
                .filter(|c| c[1] == "get")
                .all(|c| c[5] == "--fields" && !c[6].contains("solv_password"))
        );
        mock.inject_concealed = true;
        assert!(store(&mock).solana_node_summaries(true).is_err());
    }

    #[test]
    fn native_configuration_keeps_references_out_of_public_host_reads() {
        let mock = fixture();
        mock.items.borrow_mut().clear();
        let mut node = host();
        node.contract.profile = "agave-native-rpc".into();
        node.contract.vote_account = None;
        node.contract.authority_account = None;
        let config = rpc_config();
        let stored = store(&mock)
            .add_configured_solana_native_host(&node, &config)
            .unwrap();
        mock.items.borrow_mut()[0]["fields"].as_array_mut().unwrap().push(json!({"id":"migration_identity","label":"migration_identity","type":"CONCEALED","value":"inert original migration key"}));
        mock.items.borrow_mut()[0]["fields"].as_array_mut().unwrap().push(json!({"id":"native_migration","label":"native_migration","type":"STRING","value":"retained original migration evidence"}));
        mock.calls.borrow_mut().clear();
        assert_eq!(
            store(&mock).solana_native_hosts().unwrap(),
            std::slice::from_ref(&stored)
        );
        assert!(
            mock.calls
                .borrow()
                .iter()
                .flatten()
                .all(|argument| !argument.contains("native_config"))
        );
        assert!(!serde_json::to_string(&stored).unwrap().contains("op://"));
        assert!(!format!("{config:?}").contains("op://"));
        assert_eq!(store(&mock).solana_native_config(&stored).unwrap(), config);
        let mut changed = config.clone();
        changed.management_allow = vec!["198.51.100.9/32".into()];
        let updated = store(&mock)
            .update_solana_native_config(&stored, &changed)
            .unwrap();
        assert!(updated.item_version > stored.item_version);
        for (label, value) in [
            ("migration_identity", "inert original migration key"),
            ("native_migration", "retained original migration evidence"),
        ] {
            assert_eq!(
                mock.items.borrow()[0]["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|field| field["label"] == label)
                    .unwrap()["value"],
                value
            );
        }
        assert!(
            store(&mock)
                .update_solana_native_config(&stored, &config)
                .is_err()
        );
        changed.identity_ref = format!("op://{}/{}/identity", "a".repeat(26), "c".repeat(26));
        let writes = mock
            .calls
            .borrow()
            .iter()
            .filter(|call| call.get(1).is_some_and(|v| v == "edit"))
            .count();
        assert!(
            store(&mock)
                .update_solana_native_config(&updated, &changed)
                .is_err()
        );
        assert_eq!(
            writes,
            mock.calls
                .borrow()
                .iter()
                .filter(|call| call.get(1).is_some_and(|v| v == "edit"))
                .count()
        );
        let mut stale = updated;
        stale.item_version += 1;
        assert!(store(&mock).solana_native_config(&stale).is_err());
    }

    #[test]
    fn an_access_list_entry_is_refused_with_the_rule_it_breaks() {
        let refused = |config: &NativeConfig, contract: &Contract| {
            config.validate(contract).unwrap_err().to_string()
        };
        let mut node = host();
        node.contract.profile = "agave-native-rpc".into();
        node.contract.vote_account = None;
        node.contract.authority_account = None;
        let original = rpc_config();
        original.validate(&node.contract).unwrap();
        for (value, rule) in [
            ("0.0.0.0/0", "needs a prefix from /8 to /32"),
            ("10.0.0.0/7", "needs a prefix from /8 to /32"),
            ("192.0.2.0/33", "needs a prefix from /8 to /32"),
            ("2001:db8::/129", "needs a prefix from /32 to /128"),
            ("::/0", "needs a prefix from /32 to /128"),
            ("192.0.2.1/24", "is not the first address of a /24 network"),
            (
                "0.0.0.0/8",
                "is an unspecified, multicast or IPv4-mapped network",
            ),
            (
                "224.0.0.0/8",
                "is an unspecified, multicast or IPv4-mapped network",
            ),
            (
                "::ffff:192.0.2.0/120",
                "is an unspecified, multicast or IPv4-mapped network",
            ),
            ("2001:DB8::/32", "must be written 2001:db8::/32"),
            ("192.0.2.0/024", "must be written 192.0.2.0/24"),
            (
                "192.0.2.1;id/32",
                "is not a network such as 198.51.100.0/24",
            ),
            ("192.0.2.1", "is not a network such as 198.51.100.0/24"),
            ("example.com/24", "is not a network such as 198.51.100.0/24"),
        ] {
            let mut config = original.clone();
            config.rpc_allow = vec![value.into()];
            assert_eq!(
                refused(&config, &node.contract),
                format!("{value:?} in the RPC allow list {rule}")
            );
            config.rpc_allow.clear();
            config.management_allow = vec![value.into()];
            assert_eq!(
                refused(&config, &node.contract),
                format!("{value:?} in the management allow list {rule}")
            );
        }
        let mut config = original.clone();
        config.management_allow = vec!["198.51.100.0/24".into(), "198.51.100.0/24".into()];
        assert_eq!(
            refused(&config, &node.contract),
            r#"the management allow list names "198.51.100.0/24" twice"#
        );
        config.rpc_allow = (0..64).map(|i| format!("10.0.{i}.0/24")).collect();
        config.management_allow.clear();
        config.validate(&node.contract).unwrap();
        config.rpc_allow.push("10.0.64.0/24".into());
        assert_eq!(
            refused(&config, &node.contract),
            "the RPC allow list holds more than 64 networks"
        );
    }

    #[test]
    fn config_refuses_role_confusion_unknown_key_refs_and_noncanonical_access() {
        let refused = |config: &NativeConfig, contract: &Contract| {
            config.validate(contract).unwrap_err().to_string()
        };
        let mut node = host();
        node.contract.profile = "agave-native-rpc".into();
        node.contract.vote_account = None;
        node.contract.authority_account = None;
        let original = rpc_config();
        original.validate(&node.contract).unwrap();
        let mut bad = original.clone();
        bad.identity_ref = "op://vault-name/key/identity".into();
        assert_eq!(
            refused(&bad, &node.contract),
            "the identity reference is not usable: the vault must be a 26-character \
             1Password id, not a name: a name can be reassigned and so does not pin what is read"
        );
        for change in [
            (|c: &mut NativeConfig| c.commission = Some(5)) as fn(&mut NativeConfig),
            |c| c.sync_identity = Some("5".repeat(44)),
            |c| c.sync_ref = Some(format!("op://{}/{}/sync", "a".repeat(26), "c".repeat(26))),
        ] {
            let mut bad = original.clone();
            change(&mut bad);
            assert_eq!(
                refused(&bad, &node.contract),
                "an RPC host takes no synchronization identity and no commission"
            );
        }
        let validator = host();
        let mut config = original;
        config.rpc_allow.clear();
        config.sync_ref = Some(format!("op://{}/{}/sync", "a".repeat(26), "c".repeat(26)));
        config.sync_identity = Some("5".repeat(44));
        config.commission = Some(5);
        config.validate(&validator.contract).unwrap();
        for commission in [0, 100] {
            let mut edge = config.clone();
            edge.commission = Some(commission);
            edge.validate(&validator.contract).unwrap();
        }
        let identity = validator.contract.identity_account.clone();
        let vote = validator.contract.vote_account.clone();
        let identity_ref = config.identity_ref.clone();
        for (change, rule) in [
            (
                Box::new(|c: &mut NativeConfig| c.sync_ref = None)
                    as Box<dyn Fn(&mut NativeConfig)>,
                "a validator needs a synchronization identity reference",
            ),
            (
                Box::new(|c| c.sync_ref = Some("op://Private/My Item/keypair".into())),
                "the synchronization identity reference is not usable: the vault must be a \
                 26-character 1Password id, not a name: a name can be reassigned and so does \
                 not pin what is read",
            ),
            (
                Box::new(|c| c.sync_identity = None),
                "a validator needs its synchronization identity's public key",
            ),
            (
                Box::new(move |c| c.sync_ref = Some(identity_ref.clone())),
                "the synchronization identity reference must differ from the identity reference",
            ),
            (
                Box::new(move |c| c.sync_identity = Some(identity.clone())),
                "the synchronization identity must differ from the validator identity",
            ),
            (
                Box::new(move |c| c.sync_identity = vote.clone()),
                "the synchronization identity must be a canonical public key, distinct from \
                 the vote account and the withdrawal authority",
            ),
            (
                Box::new(|c| c.sync_identity = Some("z".repeat(44))),
                "the synchronization identity must be a canonical public key, distinct from \
                 the vote account and the withdrawal authority",
            ),
            (
                Box::new(|c| c.rpc_allow = vec!["198.51.100.20/32".into()]),
                "a validator takes no RPC allow list",
            ),
            (
                Box::new(|c| c.commission = None),
                "a validator needs a commission from 0 to 100",
            ),
            (
                Box::new(|c| c.commission = Some(101)),
                "a validator needs a commission from 0 to 100",
            ),
        ] {
            let mut bad = config.clone();
            change(&mut bad);
            assert_eq!(refused(&bad, &validator.contract), rule);
        }
    }

    #[test]
    fn a_stored_configuration_that_breaks_a_rule_is_a_reply_this_version_cannot_read() {
        let mock = fixture();
        mock.items.borrow_mut().clear();
        let mut node = host();
        node.contract.profile = "agave-native-rpc".into();
        node.contract.vote_account = None;
        node.contract.authority_account = None;
        let stored = store(&mock)
            .add_configured_solana_native_host(&node, &rpc_config())
            .unwrap();
        for item in mock.items.borrow_mut().iter_mut() {
            for field in item["fields"].as_array_mut().unwrap() {
                if field["label"] == "native_config" {
                    let mut config: Value =
                        serde_json::from_str(field["value"].as_str().unwrap()).unwrap();
                    config["rpc_allow"] = json!(["192.0.2.1/24"]);
                    field["value"] = config.to_string().into();
                }
            }
        }
        assert_eq!(
            store(&mock)
                .solana_native_config(&stored)
                .unwrap_err()
                .to_string(),
            "1Password's reply to native Solana host metadata could not be read"
        );
    }

    struct Mock {
        items: RefCell<Vec<Value>>,
        calls: RefCell<Vec<Vec<String>>>,
        inject_concealed: bool,
    }
    impl Mock {
        fn whole_note(&self, id: &str) -> String {
            assert_eq!(id, "n".repeat(26));
            let mut item = self
                .items
                .borrow()
                .iter()
                .find(|item| item["id"] == id)
                .unwrap()
                .clone();
            item["vault"] = json!({"id":"v".repeat(26)});
            item.to_string()
        }
    }
    impl OpRunner for &Mock {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).into()).collect());
            let stdout = match args {
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
                    let listed: Vec<_> = self.items.borrow().iter().filter(|item| item["tags"].as_array().unwrap().iter().any(|t| t==tag))
                        .map(|item| json!({"id":item["id"],"title":item["title"],"version":item["version"],
                            "vault":{"id":"v".repeat(26)},"category":"SECURE_NOTE","tags":item["tags"]})).collect();
                    serde_json::to_string(&listed).unwrap()
                }
                [
                    "item",
                    "get",
                    id,
                    "--vault",
                    _,
                    "--fields",
                    selector,
                    "--format",
                    "json",
                ] => {
                    assert!(
                        !selector.contains("solv_password") && !selector.contains("label=keypair")
                    );
                    let items = self.items.borrow();
                    let item = items.iter().find(|item| item["id"] == *id).unwrap();
                    let labels: Vec<_> = selector
                        .split(',')
                        .map(|s| s.strip_prefix("label=").unwrap())
                        .collect();
                    let mut fields: Vec<_> = item["fields"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|f| labels.contains(&f["label"].as_str().unwrap()))
                        .cloned()
                        .collect();
                    if self.inject_concealed {
                        fields[0]["type"] = "CONCEALED".into();
                        fields[0]["value"] = "inert secret decoy".into();
                    }
                    crate::inventory::fields_as_op_prints(fields).to_string()
                }
                ["item", "create", "-", "--vault", _, "--format", "json"] => {
                    let mut item: Value = serde_json::from_str(stdin.unwrap()).unwrap();
                    item["id"] = if item["title"].as_str().unwrap().ends_with(" validator") {
                        "i".repeat(26)
                    } else {
                        "n".repeat(26)
                    }
                    .into();
                    item["version"] = 1.into();
                    self.items.borrow_mut().push(item.clone());
                    item.to_string()
                }
                [
                    "item",
                    "get",
                    id,
                    "--vault",
                    _,
                    "--format",
                    "json",
                    "--reveal",
                ] => self.whole_note(id),
                ["item", "edit", id, "--vault", _, "--format", "json"] => {
                    let mut items = self.items.borrow_mut();
                    let item = items.iter_mut().find(|item| item["id"] == *id).unwrap();
                    let mut next: Value = serde_json::from_str(stdin.unwrap()).unwrap();
                    assert_eq!(next["id"], item["id"]);
                    assert_eq!(next["version"], item["version"]);
                    next["version"] = (item["version"].as_u64().unwrap() + 1).into();
                    *item = next;
                    item.to_string()
                }
                _ => panic!("unexpected whole-item or secret read: {args:?}"),
            };
            Ok(OpOutput {
                success: true,
                stdout,
                stderr: String::new(),
            })
        }
    }
    fn fixture() -> Mock {
        let node = host();
        let fields = vec![
            ("erpc_format", FORMAT.to_owned()),
            ("name", node.contract.name),
            ("identity_account", node.contract.identity_account),
            ("vote_account", node.contract.vote_account.unwrap()),
            (
                "authority_account",
                node.contract.authority_account.unwrap(),
            ),
        ];
        let fields: Vec<_> = fields
            .into_iter()
            .map(|(name, value)| json!({"id":name,"label":name,"type":"STRING","value":value}))
            .collect();
        Mock {
            items: RefCell::new(vec![
                json!({"id":"i".repeat(26),"version":1,"title":"erpc testnet fixture validator",
            "tags":["erpc","erpc/solana/testnet/validator"],"fields":fields}),
            ]),
            calls: RefCell::new(vec![]),
            inject_concealed: false,
        }
    }
    fn store(mock: &Mock) -> Store<&Mock> {
        Store::new(
            mock,
            "network-vault",
            Scope {
                chain: "solana".into(),
                network: "testnet".into(),
            },
            std::env::temp_dir().join(format!(
                "erpc-native-inventory-{}-{:p}.lock",
                std::process::id(),
                mock
            )),
        )
    }
    fn registration(node: &NativeHost) -> Validator {
        let source = erpc_chain_solana_native::catalog()
            .unwrap()
            .networks
            .remove("testnet")
            .unwrap();
        Validator {
            name: node.contract.name.clone(),
            identity_account: node.contract.identity_account.clone(),
            vote_account: node.contract.vote_account.clone().unwrap(),
            authority_account: node.contract.authority_account.clone().unwrap(),
            identity_ref: format!("op://{}/{}/keypair", "v".repeat(26), "k".repeat(26)),
            client: "agave".into(),
            version: source.version,
            commit: source.commit,
            ..Validator::default()
        }
    }
    #[test]
    fn native_logical_reservation_round_trips_without_loading_legacy_hosts_or_financial_keys() {
        let mock = fixture();
        mock.items.borrow_mut().clear();
        let store = store(&mock);
        let node = host();
        let validator = registration(&node);
        let mut financial = validator.clone();
        financial.authority_ref = "inert forbidden withdrawer reference".into();
        assert!(
            store
                .add_native_solana_validator(&financial, &node)
                .is_err()
        );
        assert!(mock.calls.borrow().is_empty());
        let stored = store
            .add_native_solana_validator(&validator, &node)
            .unwrap();
        assert_eq!(stored.id, Some("i".repeat(26)));
        let mut alias_node = node.clone();
        alias_node.contract.name = "alias".into();
        let mut alias_validator = validator.clone();
        alias_validator.name = "alias".into();
        assert!(
            store
                .add_native_solana_validator(&alias_validator, &alias_node)
                .is_err()
        );
        store.add_solana_native_host(&node).unwrap();
        assert!(
            store
                .add_native_solana_validator(&validator, &node)
                .is_err()
        );
        assert!(
            !mock
                .calls
                .borrow()
                .iter()
                .any(|args| args.get(1).map(String::as_str) == Some("read"))
        );
    }

    #[test]
    fn a_first_registration_is_stored_and_listed_with_the_fields_it_leaves_empty() {
        use crate::inventory::solana_listing::Backend;
        let mock = fixture();
        mock.items.borrow_mut().clear();
        let store = store(&mock);
        let node = host();
        // What a first `erpc v init` writes. A registration must leave vote_ref,
        // authority_ref, region and active_host empty, and `op` prints an empty
        // field without a value.
        let stored = store
            .add_native_solana_validator(&registration(&node), &node)
            .unwrap();
        assert_eq!(stored.id, Some("i".repeat(26)));
        // Stored alone, as by an init that stopped before its host: neither
        // backend's node yet, and init resumes it.
        let rows = store.solana_node_summaries(false).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0]["backend"].is_null(), "{}", rows[0]);
        assert_eq!(rows[0]["hosts"], json!([]));
        assert_eq!(rows[0]["identity"], node.contract.identity_account);
        assert_eq!(
            store.solana_backend("fixture", false).unwrap(),
            Backend::New
        );
        let reserved = store.add_solana_native_host(&node).unwrap();
        let rows = store.solana_node_summaries(false).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "fixture");
        assert_eq!(rows[0]["backend"], "native");
        assert_eq!(rows[0]["identity"], node.contract.identity_account);
        assert_eq!(rows[0]["region"], "");
        assert_eq!(rows[0]["hosts"][0]["address"], reserved.address);
        assert_eq!(
            store.solana_backend("fixture", false).unwrap(),
            Backend::Native
        );
        assert_eq!(
            store.public_native_solana_keys("fixture").unwrap().name,
            "fixture"
        );
    }

    #[test]
    fn nodes_the_released_version_left_unfinished_are_listed_with_their_empty_fields() {
        let mock = fixture();
        mock.items.borrow_mut().clear();
        let key = host().host_key;
        let password = SecretString::from("inert password decoy");
        let legacy = |kind: Kind, name: &str, id: char, fields: &[(&str, String)]| {
            let password = (kind != Kind::Validator).then_some(&password);
            let raw = store(&mock).template(kind, name, fields, password);
            let mut item: Value = serde_json::from_str(&raw).unwrap();
            item["id"] = id.to_string().repeat(26).into();
            item["version"] = 1.into();
            mock.items.borrow_mut().push(item);
        };
        // A validator whose init the released version did not finish: its host
        // was stored before the first run, so it has no last result yet.
        legacy(
            Kind::Validator,
            "tv1",
            'i',
            &validator_fields(&Validator {
                name: "tv1".into(),
                identity_account: "2".repeat(44),
                identity_ref: format!("op://{}/{}/keypair", "v".repeat(26), "k".repeat(26)),
                client: "agave".into(),
                version: "v4.4.0-beta.1".into(),
                commit: "a".repeat(40),
                region: "ny".into(),
                ..Validator::default()
            }),
        );
        legacy(
            Kind::Host,
            "tv1-a",
            'h',
            &host_fields(&Host {
                name: "tv1-a".into(),
                validator: "tv1".into(),
                role: Some(Role::Primary),
                address: "203.0.113.5".into(),
                ssh_user: "ubuntu".into(),
                ssh_port: 22,
                host_key: key.clone(),
                ..Host::default()
            }),
        );
        // An RPC node before its first deploy, with the default allow list:
        // no identity, nobody allowed and no last result.
        legacy(
            Kind::Rpc,
            "rpc1",
            'r',
            &solana_rpc_fields(&SolanaRpc {
                name: "rpc1".into(),
                address: "203.0.113.6".into(),
                ssh_user: "ubuntu".into(),
                ssh_port: 22,
                host_key: key,
                client: "agave".into(),
                rpc_type: "send-tx".into(),
                version: "v4.4.0-beta.1".into(),
                commit: "a".repeat(40),
                region: "ny".into(),
                ..SolanaRpc::default()
            }),
        );
        // And one whose host it never stored: not a solv node, and the next
        // init, a native one, takes it over.
        legacy(
            Kind::Validator,
            "tv2",
            'j',
            &validator_fields(&Validator {
                name: "tv2".into(),
                identity_account: "6".repeat(44),
                identity_ref: format!("op://{}/{}/keypair", "v".repeat(26), "m".repeat(26)),
                client: "agave".into(),
                version: "v4.4.0-beta.1".into(),
                commit: "a".repeat(40),
                region: "ny".into(),
                ..Validator::default()
            }),
        );
        let validators = store(&mock).solana_node_summaries(false).unwrap();
        assert_eq!(validators.len(), 2);
        assert_eq!(validators[0]["name"], "tv1");
        assert_eq!(validators[0]["backend"], "solv");
        assert_eq!(
            validators[0]["hosts"],
            json!([{"name":"tv1-a","role":"primary","address":"203.0.113.5","last_result":""}])
        );
        assert_eq!(validators[1]["name"], "tv2");
        assert!(validators[1]["backend"].is_null(), "{}", validators[1]);
        assert_eq!(validators[1]["hosts"], json!([]));
        assert_eq!(validators[1]["version"], "v4.4.0-beta.1");
        assert_eq!(
            store(&mock).solana_backend("tv2", false).unwrap(),
            crate::inventory::solana_listing::Backend::New
        );
        let nodes = store(&mock).solana_node_summaries(true).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["name"], "rpc1");
        assert_eq!(nodes[0]["backend"], "solv");
        assert_eq!(nodes[0]["identity"], "");
        assert_eq!(nodes[0]["rpc_allow"], json!([]));
        assert_eq!(nodes[0]["last_result"], "");
        assert!(!format!("{validators:?}{nodes:?}").contains("decoy"));
    }

    #[test]
    fn native_key_view_uses_only_public_original_accounts_and_refuses_registration_drift() {
        let mock = fixture();
        let store = store(&mock);
        store.add_solana_native_host(&host()).unwrap();
        let keys = store.public_native_solana_keys("fixture").unwrap();
        assert_eq!(keys.identity_account, host().contract.identity_account);
        let mut items = mock.items.borrow_mut();
        let account = items[0]["fields"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|field| field["label"] == "authority_account")
            .unwrap();
        account["value"] = json!("5".repeat(44));
        drop(items);
        assert!(store.public_native_solana_keys("fixture").is_err());
        assert!(!mock.calls.borrow().iter().any(|call| {
            call.iter()
                .any(|argument| argument.contains("_ref") || argument.contains("password"))
        }));
    }

    #[test]
    fn reservation_round_trips_with_field_projections_and_refuses_duplicate_identity() {
        let mock = fixture();
        let store = store(&mock);
        let created = store.add_solana_native_host(&host()).unwrap();
        assert_eq!(created.contract.inventory_id, "n".repeat(26));
        assert_eq!(store.solana_native_host("fixture").unwrap(), created);
        assert_eq!(store.solana_native_hosts().unwrap(), vec![created]);
        assert!(store.add_solana_native_host(&host()).is_err());
        assert_eq!(
            mock.calls
                .borrow()
                .iter()
                .filter(|args| args.get(1).map(String::as_str) == Some("create"))
                .count(),
            1
        );
    }
    #[test]
    fn rpc_reservation_needs_no_logical_validator_or_financial_key() {
        let mock = fixture();
        mock.items.borrow_mut().clear();
        let mut node = host();
        node.contract.profile = "agave-native-rpc".into();
        node.contract.vote_account = None;
        node.contract.authority_account = None;
        let created = store(&mock).add_solana_native_host(&node).unwrap();
        assert!(created.contract.is_rpc());
        assert_eq!(store(&mock).solana_native_host("fixture").unwrap(), created);
        assert_eq!(mock.items.borrow().len(), 1);
        assert!(mock.calls.borrow().iter().all(|args| args[0] != "read"));
        assert!(
            store(&mock)
                .add_native_solana_validator(&Validator::default(), &node)
                .is_err()
        );
    }

    #[test]
    fn rpc_cannot_adopt_a_validator_name_or_financial_accounts() {
        let mock = fixture();
        let mut node = host();
        node.contract.profile = "agave-native-rpc".into();
        assert!(store(&mock).add_solana_native_host(&node).is_err());
        node.contract.vote_account = None;
        node.contract.authority_account = None;
        assert!(store(&mock).add_solana_native_host(&node).is_err());
        assert!(!mock.calls.borrow().iter().any(|args| args[1] == "create"));
        node.contract.inventory_id = "a".repeat(26);
        node.ssh_user = "erpc-solana-proof".into();
        node.contract.host_binding =
            host_binding(&node.address, &node.ssh_user, node.ssh_port, &node.host_key);
        assert!(node.validate().is_err());
    }
    #[test]
    fn concealed_projection_and_public_registration_mismatch_prevent_creation() {
        let mut mock = fixture();
        mock.inject_concealed = true;
        let error = store(&mock)
            .add_solana_native_host(&host())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("decoy"));
        assert!(!mock.calls.borrow().iter().any(|args| args[1] == "create"));
        let mock = fixture();
        let mut wrong = host();
        wrong.contract.vote_account = Some("5".repeat(44));
        assert!(store(&mock).add_solana_native_host(&wrong).is_err());
        assert!(!mock.calls.borrow().iter().any(|args| args[1] == "create"));
    }
    #[test]
    fn stored_connection_changes_cannot_rebind_the_original_host() {
        let mock = fixture();
        let store = store(&mock);
        store.add_solana_native_host(&host()).unwrap();
        {
            let mut items = mock.items.borrow_mut();
            let native = items
                .iter_mut()
                .find(|item| item["id"] == "n".repeat(26))
                .unwrap();
            let record = native["fields"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|f| f["label"] == "native_host")
                .unwrap();
            let mut value: Value = serde_json::from_str(record["value"].as_str().unwrap()).unwrap();
            value["address"] = "192.0.2.11".into();
            record["value"] = value.to_string().into();
        }
        assert!(store.solana_native_host("fixture").is_err());
    }

    #[test]
    fn legacy_primary_on_a_different_host_is_not_implicitly_migrated_or_read_in_full() {
        let mock = fixture();
        let node = host();
        let fields = vec![
            ("erpc_format", FORMAT.to_owned()),
            ("name", "fixture-primary".into()),
            ("address", "192.0.2.99".into()),
            (
                "host_key",
                format!("{}A", node.host_key.trim_end_matches('/')),
            ),
            ("validator", "fixture".into()),
        ];
        let mut fields: Vec<_> = fields
            .into_iter()
            .map(|(name, value)| json!({"id":name,"label":name,"type":"STRING","value":value}))
            .collect();
        fields.push(json!({"id":"solv_password","label":"solv_password","type":"CONCEALED","value":"inert legacy secret"}));
        mock.items.borrow_mut().push(
            json!({"id":"h".repeat(26),"version":1,"title":"erpc testnet fixture-primary host",
            "tags":["erpc","erpc/solana/testnet/host"],"fields":fields}),
        );
        let error = store(&mock)
            .add_solana_native_host(&host())
            .unwrap_err()
            .to_string();
        assert!(error.contains("explicit migration"));
        assert!(!mock.calls.borrow().iter().any(|args| args[1] == "create"));
    }
}
