// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated Arc validator public projection and original-key binding.
//! Selected-field/typed-write mechanics derive from reviewed Arc RPC inventory.
use super::{InventoryError, Kind, OpField, OpItem, Store, check_name};
use erpc_auth::store::one_password::OpRunner;
use erpc_secret::OpRef;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeSet;

/// One dedicated validator host; it cannot reuse an RPC inventory item or key scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArcValidatorNode {
    /// Common pinned host/native release metadata; RPC exposure remains disabled.
    pub host: super::RpcNode,
    /// Original externally held governance controller address.
    pub controller: String,
    /// Approved external reward recipient.
    pub fee_recipient: String,
    /// `observer` before explicit activation, then `validator`.
    pub participation: String,
    /// Operator confirms institutional permission; live membership is checked remotely.
    pub admission_approved: bool,
    /// Dedicated external consensus signer; the common host key field is only P2P.
    pub signing_public_key: String,
    /// Closed public endpoint/CA hash/artifact/PCR input JSON, validated by the Arc client.
    pub remote_signer: String,
}
impl std::ops::Deref for ArcValidatorNode {
    type Target = super::RpcNode;
    fn deref(&self) -> &Self::Target {
        &self.host
    }
}
impl std::ops::DerefMut for ArcValidatorNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.host
    }
}
fn validator_node_fields(node: &ArcValidatorNode) -> Vec<(&'static str, String)> {
    let mut values = super::rpc_node_fields(&node.host);
    values.extend([
        ("arc_validator_format", "1".into()),
        ("controller", node.controller.clone()),
        ("fee_recipient", node.fee_recipient.clone()),
        ("participation", node.participation.clone()),
        ("admission_approved", node.admission_approved.to_string()),
        ("signing_public_key", node.signing_public_key.clone()),
        ("remote_signer", node.remote_signer.clone()),
    ]);
    values
}
fn read_validator_node(item: &OpItem) -> Result<ArcValidatorNode, InventoryError> {
    let fields = super::checked(item)?;
    if fields.get("arc_validator_format") != Some(&"1") {
        return Err(invalid());
    }
    let approved = match fields.get("admission_approved") {
        Some(&"true") => true,
        Some(&"false") => false,
        _ => return Err(invalid()),
    };
    let controller = super::field(&fields, "controller");
    let fee_recipient = super::field(&fields, "fee_recipient");
    let address = |s: &str| {
        s.len() == 42
            && s.starts_with("0x")
            && s.as_bytes()[2..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            && s.as_bytes()[2..].iter().any(|b| *b != b'0')
    };
    let participation = super::field(&fields, "participation");
    let signing_public_key = super::field(&fields, "signing_public_key");
    let remote_signer = super::field(&fields, "remote_signer");
    let profile: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&remote_signer).map_err(|_| invalid())?;
    let expected = [
        "endpoint",
        "server_ca_sha256",
        "image_sha256",
        "pcr0",
        "pcr1",
        "pcr2",
        "pcr4",
    ];
    if !address(&controller)
        || !address(&fee_recipient)
        || !matches!(participation.as_str(), "observer" | "validator")
        || signing_public_key.len() != 44
        || signing_public_key == super::field(&fields, "consensus_public_key")
        || profile.len() != expected.len()
        || expected.iter().any(|field| !profile.contains_key(*field))
        || profile
            .values()
            .any(|value| value.is_empty() || value.len() > 512)
    {
        return Err(invalid());
    }
    Ok(ArcValidatorNode {
        host: super::read_rpc_node(item)?,
        controller,
        fee_recipient,
        participation,
        admission_approved: approved,
        signing_public_key,
        remote_signer,
    })
}

const PUBLIC: &str = "label=erpc_format,label=name,label=address,label=ssh_user,label=ssh_port,label=host_key,label=version,label=commit,label=archive_sha256,label=consensus_public_key,label=rpc_type,label=debug_api,label=trusted_peers,label=sentry_peers,label=rpc_allow,label=management_allow,label=monitoring_allow,label=last_run,label=last_result,label=arc_validator_format,label=controller,label=fee_recipient,label=participation,label=admission_approved,label=signing_public_key,label=remote_signer";
const PENDING: &str = "erpc-arc-validator-key-pending-v1";
const REQUIRED: &[&str] = &[
    "erpc_format",
    "name",
    "address",
    "ssh_user",
    "ssh_port",
    "host_key",
    "version",
    "commit",
    "archive_sha256",
    "consensus_public_key",
    "arc_validator_format",
    "controller",
    "fee_recipient",
    "participation",
    "admission_approved",
    "signing_public_key",
    "remote_signer",
];
fn invalid() -> InventoryError {
    InventoryError::Unreadable("Arc inventory qualification")
}
fn identifier(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
struct Vault {
    id: String,
}
#[derive(Deserialize, PartialEq, Eq)]
struct Metadata {
    id: String,
    title: String,
    category: String,
    vault: Vault,
    version: u64,
    tags: Vec<String>,
}
#[derive(Deserialize)]
struct Field {
    id: String,
    label: String,
    #[serde(rename = "type")]
    kind: String,
    value: Option<SecretString>,
    purpose: Option<String>,
    section: Option<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
struct Item {
    id: String,
    title: String,
    category: String,
    vault: Vault,
    version: u64,
    tags: Vec<String>,
    fields: Vec<Field>,
    sections: Option<Vec<serde::de::IgnoredAny>>,
    files: Option<Vec<serde::de::IgnoredAny>>,
    urls: Option<Vec<serde::de::IgnoredAny>>,
}
struct Snapshot {
    metadata: Metadata,
    fields: Vec<Field>,
    node: ArcValidatorNode,
}
impl Snapshot {
    fn field(&self, label: &str) -> Option<&Field> {
        self.fields.iter().find(|v| v.label == label)
    }
    fn reference(&self) -> Result<&SecretString, InventoryError> {
        let value = self
            .field("consensus_key_ref")
            .and_then(|v| v.value.as_ref())
            .ok_or_else(invalid)?;
        if value.expose_secret() != PENDING
            && OpRef::parse(value.expose_secret())
                .map_err(|_| invalid())?
                .field()
                != "private_key"
        {
            return Err(invalid());
        }
        Ok(value)
    }
    fn note(&self) -> Option<&str> {
        self.field("notesPlain")
            .and_then(|v| v.value.as_ref())
            .map(ExposeSecret::expose_secret)
            .filter(|v| !v.is_empty())
    }
}
struct SecretValue<'a>(&'a SecretString);
impl Serialize for SecretValue<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.expose_secret())
    }
}
#[derive(Serialize)]
struct OutputField<'a> {
    id: &'a str,
    label: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<SecretValue<'a>>,
}
#[derive(Serialize)]
struct Template<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault: Option<&'a Vault>,
    title: &'a str,
    category: &'static str,
    tags: &'a [String],
    fields: Vec<OutputField<'a>>,
}

impl<R: OpRunner> Store<R> {
    fn arc_validator_output(
        &self,
        args: &[&str],
        input: Option<&str>,
    ) -> Result<SecretString, InventoryError> {
        let output = self.runner.run(args, input).map_err(|_| invalid())?;
        let _stderr = SecretString::from(output.stderr);
        let raw = SecretString::from(output.stdout);
        if !output.success || raw.expose_secret().len() > 1_048_576 {
            return Err(invalid());
        }
        Ok(raw)
    }
    fn arc_validator_listing(&self) -> Result<Vec<Metadata>, InventoryError> {
        if !identifier(&self.vault)
            || self.scope.chain != "arc"
            || !["mainnet", "testnet"].contains(&self.scope.network.as_str())
        {
            return Err(invalid());
        }
        let tag = self.scope.tag(Kind::Validator);
        let raw = self.arc_validator_output(
            &[
                "item",
                "list",
                "--vault",
                &self.vault,
                "--tags",
                &tag,
                "--format",
                "json",
            ],
            None,
        )?;
        let list: Vec<Metadata> =
            serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?;
        let mut found = Vec::new();
        let mut ids = BTreeSet::new();
        let mut titles = BTreeSet::new();
        for mut item in list {
            if !identifier(&item.id) || !identifier(&item.vault.id) || !ids.insert(item.id.clone())
            {
                return Err(invalid());
            }
            if !item.tags.contains(&tag) {
                continue;
            }
            if item.category != "SECURE_NOTE"
                || item.version == 0
                || !item.tags.iter().any(|v| v == super::TAG)
                || item
                    .tags
                    .iter()
                    .any(|v| v.starts_with("erpc/") && v != &tag)
                || item.tags.iter().collect::<BTreeSet<_>>().len() != item.tags.len()
                || !titles.insert(item.title.clone())
                || (identifier(&self.vault) && self.vault != item.vault.id)
            {
                return Err(invalid());
            }
            item.tags.sort();
            found.push(item);
        }
        found.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(found)
    }
    fn arc_validator_fields(
        &self,
        item: &Metadata,
        selector: &str,
    ) -> Result<Vec<Field>, InventoryError> {
        let raw = self.arc_validator_output(
            &[
                "item",
                "get",
                &item.id,
                "--vault",
                &item.vault.id,
                "--fields",
                selector,
                "--format",
                "json",
            ],
            None,
        )?;
        match raw.expose_secret().trim_start().as_bytes().first() {
            Some(b'[') => serde_json::from_str(raw.expose_secret()).map_err(|_| invalid()),
            Some(b'{') => serde_json::from_str(raw.expose_secret())
                .map(|v| vec![v])
                .map_err(|_| invalid()),
            _ => Err(invalid()),
        }
    }
    fn arc_validator_decode(
        &self,
        item: &Metadata,
        fields: &[&Field],
    ) -> Result<ArcValidatorNode, InventoryError> {
        let known = validator_node_fields(&ArcValidatorNode::default());
        let mut public = Vec::new();
        let mut labels = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for field in fields {
            if field.id.is_empty()
                || !ids.insert(&field.id)
                || !labels.insert(&field.label)
                || field.kind != "STRING"
                || field.purpose.is_some()
                || field.section.is_some()
                || field.label == "consensus_key_ref"
                || !known.iter().any(|(key, _)| *key == field.label)
            {
                return Err(invalid());
            }
            let value = field.value.as_ref().map_or("", ExposeSecret::expose_secret);
            if REQUIRED.contains(&field.label.as_str()) && value.is_empty() {
                return Err(invalid());
            }
            public.push(OpField {
                label: field.label.clone(),
                kind: "STRING".into(),
                value: Some(value.to_owned()),
            });
        }
        if REQUIRED
            .iter()
            .any(|name| !labels.iter().any(|label| label.as_str() == *name))
        {
            return Err(invalid());
        }
        let node = read_validator_node(&OpItem {
            id: item.id.clone(),
            title: item.title.clone(),
            version: item.version,
            tags: item.tags.clone(),
            fields: public,
        })
        .map_err(|_| invalid())?;
        check_name(&node.name).map_err(|_| invalid())?;
        if node.ssh_port == 0
            || item.title != self.title(Kind::Validator, &node.name)
            || node.consensus_public_key.is_empty()
            || node.rpc_type != "validator-minimal"
            || node.debug_api
            || !node.rpc_allow.is_empty()
        {
            return Err(invalid());
        }
        Ok(node)
    }
    fn arc_validator_public(&self, item: &Metadata) -> Result<ArcValidatorNode, InventoryError> {
        self.arc_validator_decode(
            item,
            &self
                .arc_validator_fields(item, PUBLIC)?
                .iter()
                .collect::<Vec<_>>(),
        )
    }
    fn arc_validator_selected(&self, node: &ArcValidatorNode) -> Result<Metadata, InventoryError> {
        let id = node
            .id
            .as_deref()
            .filter(|v| identifier(v))
            .ok_or_else(invalid)?;
        let item = self
            .arc_validator_listing()?
            .into_iter()
            .find(|v| v.id == id)
            .ok_or_else(invalid)?;
        if item.version != node.item_version {
            return Err(InventoryError::Changed(node.name.clone()));
        }
        if item.title != self.title(Kind::Validator, &node.name) {
            return Err(invalid());
        }
        Ok(item)
    }
    /// Public node fields only; consensus references and private values are not requested.
    /// # Errors
    /// Refuses ambiguous, concealed, malformed or changing projections.
    pub fn arc_validators(&self) -> Result<Vec<ArcValidatorNode>, InventoryError> {
        let before = self.arc_validator_listing()?;
        let nodes = before
            .iter()
            .map(|v| self.arc_validator_public(v))
            .collect::<Result<Vec<_>, _>>()?;
        if before != self.arc_validator_listing()? {
            return Err(invalid());
        }
        Ok(nodes)
    }
    /// Read only this original node's key reference for an explicit custody operation.
    /// # Errors
    /// Refuses a stale node, wrong field type or non-identifier reference.
    pub fn arc_validator_key_reference(
        &self,
        node: &ArcValidatorNode,
    ) -> Result<Option<OpRef>, InventoryError> {
        let item = self.arc_validator_selected(node)?;
        if self.arc_validator_public(&item)? != *node {
            return Err(invalid());
        }
        let fields = self.arc_validator_fields(&item, "label=consensus_key_ref")?;
        if fields.len() != 1 {
            return Err(invalid());
        }
        let field = &fields[0];
        if field.id.is_empty()
            || field.label != "consensus_key_ref"
            || field.kind != "STRING"
            || field.section.is_some()
            || field.purpose.is_some()
        {
            return Err(invalid());
        }
        let value = field.value.as_ref().ok_or_else(invalid)?.expose_secret();
        let reference = if value == PENDING {
            None
        } else {
            Some(OpRef::parse(value).map_err(|_| invalid())?)
        };
        if reference
            .as_ref()
            .is_some_and(|v| v.field() != "private_key" || v.vault() != self.vault)
            || self.arc_validator_selected(node)? != item
        {
            return Err(invalid());
        }
        Ok(reference)
    }
    fn arc_validator_snapshot(&self, metadata: Metadata) -> Result<Snapshot, InventoryError> {
        let raw = self.arc_validator_output(
            &[
                "item",
                "get",
                &metadata.id,
                "--vault",
                &metadata.vault.id,
                "--format",
                "json",
                "--reveal",
            ],
            None,
        )?;
        let mut item: Item = serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?;
        item.tags.sort();
        let found = Metadata {
            id: item.id,
            title: item.title,
            category: item.category,
            vault: item.vault,
            version: item.version,
            tags: item.tags,
        };
        if found != metadata
            || item.sections.as_ref().is_some_and(|v| !v.is_empty())
            || item.files.as_ref().is_some_and(|v| !v.is_empty())
            || item.urls.as_ref().is_some_and(|v| !v.is_empty())
        {
            return Err(invalid());
        }
        let known = validator_node_fields(&ArcValidatorNode::default());
        let mut ids = BTreeSet::new();
        let mut labels = BTreeSet::new();
        for field in &item.fields {
            if field.id.is_empty()
                || !ids.insert(&field.id)
                || !labels.insert(&field.label)
                || field.kind != "STRING"
                || field.section.is_some()
            {
                return Err(invalid());
            }
            if field.label == "notesPlain" {
                if field.purpose.as_deref() != Some("NOTES") {
                    return Err(invalid());
                }
            } else if field.purpose.is_some()
                || !known.iter().any(|(label, _)| *label == field.label)
            {
                return Err(invalid());
            }
        }
        let public = item
            .fields
            .iter()
            .filter(|v| v.label != "notesPlain" && v.label != "consensus_key_ref")
            .collect::<Vec<_>>();
        let node = self.arc_validator_decode(&metadata, &public)?;
        if self.arc_validator_selected(&node)? != metadata {
            return Err(invalid());
        }
        let snapshot = Snapshot {
            metadata,
            fields: item.fields,
            node,
        };
        let value = snapshot.reference()?.expose_secret();
        if value != PENDING && OpRef::parse(value).map_err(|_| invalid())?.vault() != self.vault {
            return Err(invalid());
        }
        Ok(snapshot)
    }
    fn arc_validator_document(
        &self,
        node: &ArcValidatorNode,
        previous: Option<&Snapshot>,
        reference: &str,
    ) -> Result<SecretString, InventoryError> {
        let title = self.title(Kind::Validator, &node.name);
        let tags = previous.map_or_else(
            || vec![super::TAG.into(), self.scope.tag(Kind::Validator)],
            |v| v.metadata.tags.clone(),
        );
        let mut canonical = validator_node_fields(node);
        canonical
            .iter_mut()
            .find(|(k, _)| *k == "consensus_key_ref")
            .ok_or_else(invalid)?
            .1 = reference.into();
        let canonical = canonical
            .into_iter()
            .map(|(k, v)| (k, SecretString::from(v)))
            .collect::<Vec<_>>();
        let mut fields = Vec::new();
        for (label, value) in &canonical {
            fields.push(OutputField {
                id: previous
                    .and_then(|v| v.field(label))
                    .map_or(label, |v| v.id.as_str()),
                label,
                kind: "STRING",
                purpose: None,
                value: Some(SecretValue(value)),
            });
        }
        if let Some(note) = previous.and_then(|v| v.field("notesPlain")) {
            fields.push(OutputField {
                id: &note.id,
                label: &note.label,
                kind: &note.kind,
                purpose: note.purpose.as_deref(),
                value: note.value.as_ref().map(SecretValue),
            });
        }
        serde_json::to_string(&Template {
            id: previous.map(|v| v.metadata.id.as_str()),
            version: previous.map(|v| v.metadata.version),
            vault: previous.map(|v| &v.metadata.vault),
            title: &title,
            category: "SECURE_NOTE",
            tags: &tags,
            fields,
        })
        .map(SecretString::from)
        .map_err(|_| invalid())
    }
    fn arc_validator_write(
        &self,
        node: &ArcValidatorNode,
        previous: &Snapshot,
        reference: &str,
    ) -> Result<ArcValidatorNode, InventoryError> {
        let document = self.arc_validator_document(node, Some(previous), reference)?;
        if self.arc_validator_selected(&previous.node)? != previous.metadata {
            return Err(invalid());
        }
        let _response = self.arc_validator_output(
            &[
                "item",
                "edit",
                &previous.metadata.id,
                "--vault",
                &previous.metadata.vault.id,
                "--format",
                "json",
            ],
            Some(document.expose_secret()),
        )?;
        let found = self
            .arc_validator_listing()?
            .into_iter()
            .find(|v| v.id == previous.metadata.id)
            .ok_or_else(invalid)?;
        if found.version < previous.metadata.version {
            return Err(invalid());
        }
        let back = self.arc_validator_snapshot(found)?;
        let mut wanted = node.clone();
        wanted.item_version = back.node.item_version;
        if wanted != back.node
            || previous.metadata.tags != back.metadata.tags
            || previous.note() != back.note()
            || back.reference()?.expose_secret() != reference
        {
            return Err(invalid());
        }
        Ok(back.node)
    }
    /// Reserve the original public host and identity before any private key item is made.
    /// # Errors
    /// Refuses collisions, references on fresh reservations and ambiguous storage results.
    pub fn add_arc_validator(
        &self,
        node: &ArcValidatorNode,
    ) -> Result<ArcValidatorNode, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if node.rpc_type != "validator-minimal"
            || node.debug_api
            || !node.rpc_allow.is_empty()
            || node.ssh_port == 0
            || node.id.is_some()
            || node.item_version != 0
            || !node.consensus_key_ref.is_empty()
            || node.consensus_public_key.is_empty()
            || self
                .rpc_nodes()?
                .iter()
                .any(|old| old.address == node.address)
            || self
                .arc_validators()?
                .iter()
                .any(|v| v.name == node.name || v.address == node.address)
        {
            return Err(invalid());
        }
        let document = self.arc_validator_document(node, None, PENDING)?;
        let _response = self.arc_validator_output(
            &[
                "item",
                "create",
                "-",
                "--vault",
                &self.vault,
                "--format",
                "json",
            ],
            Some(document.expose_secret()),
        )?;
        let back = self
            .arc_validators()?
            .into_iter()
            .find(|v| v.name == node.name)
            .ok_or_else(invalid)?;
        let mut wanted = node.clone();
        wanted.id.clone_from(&back.id);
        wanted.item_version = back.item_version;
        if wanted != back {
            return Err(invalid());
        }
        Ok(back)
    }
    /// Update mutable operation fields without fetching secrets for public readers.
    /// # Errors
    /// Refuses original host/identity/history changes and unsupported private item fields.
    pub fn update_arc_validator(
        &self,
        node: &ArcValidatorNode,
    ) -> Result<ArcValidatorNode, InventoryError> {
        let _lock = self.lock()?;
        let metadata = self.arc_validator_selected(node)?;
        let old = self.arc_validator_public(&metadata)?;
        if !node.consensus_key_ref.is_empty()
            || old.name != node.name
            || old.address != node.address
            || old.host_key != node.host_key
            || old.consensus_public_key != node.consensus_public_key
            || old.rpc_type != node.rpc_type
            || old.controller != node.controller
            || old.signing_public_key != node.signing_public_key
            || old.remote_signer != node.remote_signer
        {
            return Err(invalid());
        }
        let snapshot = self.arc_validator_snapshot(metadata)?;
        if old != snapshot.node {
            return Err(invalid());
        }
        self.arc_validator_write(node, &snapshot, snapshot.reference()?.expose_secret())
    }
    /// Bind the verified original key item's exact identifier reference once.
    /// # Errors
    /// A completed binding cannot be replaced, even after a failed write acknowledgement.
    pub fn bind_arc_validator_key(
        &self,
        node: &ArcValidatorNode,
        reference: &OpRef,
    ) -> Result<ArcValidatorNode, InventoryError> {
        let _lock = self.lock()?;
        let metadata = self.arc_validator_selected(node)?;
        if reference.field() != "private_key"
            || reference.vault() != self.vault
            || self.arc_validator_public(&metadata)? != *node
        {
            return Err(invalid());
        }
        let snapshot = self.arc_validator_snapshot(metadata)?;
        let old = snapshot.reference()?.expose_secret();
        let value = reference.to_string();
        if snapshot.node != *node || (old != PENDING && old != value) {
            return Err(invalid());
        }
        self.arc_validator_write(node, &snapshot, &value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_auth::store::{StoreError, one_password::OpOutput};
    use serde_json::{Value, json};
    use std::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        item: RefCell<Option<Value>>,
        calls: RefCell<Vec<Vec<String>>>,
    }
    impl OpRunner for Fake {
        fn run(&self, args: &[&str], input: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|v| (*v).into()).collect());
            let field = |name: &str| args.iter().position(|v| *v == name).map(|i| args[i + 1]);
            let value = match args[1] {
                "list" => {
                    let item = self.item.borrow();
                    let rows: Vec<Value> = item.as_ref().into_iter()
                        .filter(|item| item["tags"].as_array().unwrap().iter().any(|v| Some(v.as_str().unwrap()) == field("--tags")))
                        .map(|item| json!({"id":item["id"],"title":item["title"],"category":item["category"],
                                          "vault":item["vault"],"version":item["version"],"tags":item["tags"]}))
                        .collect();
                    json!(rows)
                }
                "create" | "edit" => {
                    let mut item: Value = serde_json::from_str(input.unwrap()).unwrap();
                    let version = self
                        .item
                        .borrow()
                        .as_ref()
                        .map_or(1, |old| old["version"].as_u64().unwrap() + 1);
                    item["id"] = json!("i".repeat(26));
                    item["vault"] = json!({"id":"a".repeat(26)});
                    item["version"] = json!(version);
                    *self.item.borrow_mut() = Some(item.clone());
                    item
                }
                "get" => {
                    let item = self.item.borrow();
                    let item = item.as_ref().unwrap();
                    assert_eq!(args[2], item["id"].as_str().unwrap());
                    if let Some(selected) = field("--fields") {
                        let names: Vec<_> = selected
                            .split(',')
                            .map(|v| v.strip_prefix("label=").unwrap())
                            .collect();
                        super::super::fields_as_op_prints(
                            item["fields"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .filter(|v| names.contains(&v["label"].as_str().unwrap()))
                                .cloned()
                                .collect(),
                        )
                    } else {
                        item.clone()
                    }
                }
                other => panic!("unexpected inert op operation {other}"),
            };
            Ok(OpOutput {
                success: true,
                stdout: value.to_string(),
                stderr: String::new(),
            })
        }
    }
    fn node() -> ArcValidatorNode {
        ArcValidatorNode {
            host: super::super::RpcNode {
                name: "inert-validator".into(),
                address: "192.0.2.3".into(),
                ssh_user: "ubuntu".into(),
                ssh_port: 22,
                host_key: "inert pinned host metadata".into(),
                version: "v0.8.1".into(),
                commit: "b".repeat(40),
                archive_sha256: "c".repeat(64),
                consensus_public_key: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into(),
                rpc_type: "validator-minimal".into(),
                ..super::super::RpcNode::default()
            },
            controller: format!("0x{}", "d".repeat(40)),
            fee_recipient: format!("0x{}", "e".repeat(40)),
            participation: "observer".into(),
            admission_approved: false,
            signing_public_key: "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=".into(),
            remote_signer:
                json!({"endpoint":"https://127.0.0.1:10340/", "server_ca_sha256":"a".repeat(64),
                "image_sha256":"b".repeat(64), "pcr0":"c".repeat(96), "pcr1":"d".repeat(96),
                "pcr2":"e".repeat(96), "pcr4":"f".repeat(96)})
                .to_string(),
        }
    }
    fn store(root: &std::path::Path) -> Store<Fake> {
        Store::new(
            Fake::default(),
            "a".repeat(26),
            super::super::Scope {
                chain: "arc".into(),
                network: "testnet".into(),
            },
            root.join("inventory.lock"),
        )
    }
    #[test]
    fn malformed_initial_runtime_role_refuses_before_creating_a_public_or_private_item() {
        for scenario in 0..4 {
            let root = tempfile::tempdir().unwrap();
            let store = store(root.path());
            let mut value = node();
            match scenario {
                0 => value.host.rpc_type = "full".into(),
                1 => value.host.debug_api = true,
                2 => value.host.rpc_allow = vec!["0.0.0.0/0".into()],
                _ => value.host.ssh_port = 0,
            }
            assert!(store.add_arc_validator(&value).is_err());
            assert!(store.runner.item.borrow().is_none());
            assert!(store.runner.calls.borrow().is_empty());
        }
    }

    #[test]
    fn public_validator_listing_never_requests_the_key_reference_or_full_item() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        let original = store.add_arc_validator(&node()).unwrap();
        store.runner.calls.borrow_mut().clear();
        assert_eq!(store.arc_validators().unwrap(), vec![original]);
        for call in store
            .runner
            .calls
            .borrow()
            .iter()
            .filter(|call| call[1] == "get")
        {
            let index = call.iter().position(|v| v == "--fields").unwrap();
            assert!(!call[index + 1].contains("consensus_key_ref"));
            assert!(!call.iter().any(|v| v == "--reveal"));
        }
        assert!(store.rpc_nodes().unwrap().is_empty());
    }
    #[test]
    fn public_reservation_and_explicit_reference_binding_preserve_original_controller() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        let original = store.add_arc_validator(&node()).unwrap();
        assert!(
            store
                .arc_validator_key_reference(&original)
                .unwrap()
                .is_none()
        );
        let reference = OpRef::parse(&format!(
            "op://{}/{}/private_key",
            "a".repeat(26),
            "k".repeat(26)
        ))
        .unwrap();
        let bound = store.bind_arc_validator_key(&original, &reference).unwrap();
        assert_eq!(
            store.arc_validator_key_reference(&bound).unwrap().unwrap(),
            reference
        );
        let mut changed = bound.clone();
        changed.controller = format!("0x{}", "f".repeat(40));
        assert!(store.update_arc_validator(&changed).is_err());
        assert!(store.update_arc_validator(&original).is_err());
        changed = bound;
        changed.participation = "validator".into();
        changed.admission_approved = true;
        let saved = store.update_arc_validator(&changed).unwrap();
        assert_eq!(saved.participation, "validator");
        assert!(saved.admission_approved);
        assert_eq!(
            store.arc_validator_key_reference(&saved).unwrap().unwrap(),
            reference
        );
    }
    #[test]
    fn duplicate_or_concealed_public_fields_and_foreign_scope_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store.add_arc_validator(&node()).unwrap();
        let original = store.runner.item.borrow().clone().unwrap();
        let mut changed = original.clone();
        let field = changed["fields"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|v| v["label"] == "controller")
            .unwrap();
        field["type"] = json!("CONCEALED");
        *store.runner.item.borrow_mut() = Some(changed);
        assert!(store.arc_validators().is_err());
        let mut changed = original.clone();
        let duplicated = changed["fields"][0].clone();
        changed["fields"].as_array_mut().unwrap().push(duplicated);
        *store.runner.item.borrow_mut() = Some(changed);
        assert!(store.arc_validators().is_err());
        let mut changed = original;
        changed["tags"]
            .as_array_mut()
            .unwrap()
            .push(json!("erpc/arc/mainnet/validator"));
        *store.runner.item.borrow_mut() = Some(changed);
        assert!(store.arc_validators().is_err());
    }
}
