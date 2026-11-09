// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Arc public projection and original consensus-key reference binding.
use super::{
    InventoryError, Kind, OpField, OpItem, RpcNode, Store, check_name, read_rpc_node,
    rpc_node_fields,
};
use erpc_auth::store::one_password::OpRunner;
use erpc_secret::OpRef;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeSet;

const PUBLIC: &str = "label=erpc_format,label=name,label=address,label=ssh_user,label=ssh_port,label=host_key,label=version,label=commit,label=archive_sha256,label=consensus_public_key,label=rpc_type,label=debug_api,label=trusted_peers,label=sentry_peers,label=rpc_allow,label=management_allow,label=monitoring_allow,label=last_run,label=last_result";
const PENDING: &str = "erpc-arc-key-pending-v1";
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
    node: RpcNode,
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
    fn arc_output(
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
    fn arc_listing(&self) -> Result<Vec<Metadata>, InventoryError> {
        if !identifier(&self.vault)
            || self.scope.chain != "arc"
            || !["mainnet", "testnet"].contains(&self.scope.network.as_str())
        {
            return Err(invalid());
        }
        let tag = self.scope.tag(Kind::Rpc);
        let raw = self.arc_output(
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
    fn arc_fields(&self, item: &Metadata, selector: &str) -> Result<Vec<Field>, InventoryError> {
        let raw = self.arc_output(
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
    fn arc_decode(&self, item: &Metadata, fields: &[&Field]) -> Result<RpcNode, InventoryError> {
        let known = rpc_node_fields(&RpcNode::default());
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
        let node = read_rpc_node(&OpItem {
            id: item.id.clone(),
            title: item.title.clone(),
            version: item.version,
            tags: item.tags.clone(),
            fields: public,
        })
        .map_err(|_| invalid())?;
        check_name(&node.name).map_err(|_| invalid())?;
        if node.ssh_port == 0
            || item.title != self.title(Kind::Rpc, &node.name)
            || node.consensus_public_key.is_empty()
            || !["full", "archive", "provider"].contains(&node.rpc_type.as_str())
        {
            return Err(invalid());
        }
        Ok(node)
    }
    fn arc_public(&self, item: &Metadata) -> Result<RpcNode, InventoryError> {
        self.arc_decode(
            item,
            &self.arc_fields(item, PUBLIC)?.iter().collect::<Vec<_>>(),
        )
    }
    fn arc_selected(&self, node: &RpcNode) -> Result<Metadata, InventoryError> {
        let id = node
            .id
            .as_deref()
            .filter(|v| identifier(v))
            .ok_or_else(invalid)?;
        let item = self
            .arc_listing()?
            .into_iter()
            .find(|v| v.id == id)
            .ok_or_else(invalid)?;
        if item.version != node.item_version {
            return Err(InventoryError::Changed(node.name.clone()));
        }
        if item.title != self.title(Kind::Rpc, &node.name) {
            return Err(invalid());
        }
        Ok(item)
    }
    /// Public node fields only; consensus references and private values are not requested.
    /// # Errors
    /// Refuses ambiguous, concealed, malformed or changing projections.
    pub fn rpc_nodes(&self) -> Result<Vec<RpcNode>, InventoryError> {
        let before = self.arc_listing()?;
        let nodes = before
            .iter()
            .map(|v| self.arc_public(v))
            .collect::<Result<Vec<_>, _>>()?;
        if before != self.arc_listing()? {
            return Err(invalid());
        }
        Ok(nodes)
    }
    /// Read only this original node's key reference for an explicit custody operation.
    /// # Errors
    /// Refuses a stale node, wrong field type or non-identifier reference.
    pub fn arc_key_reference(&self, node: &RpcNode) -> Result<Option<OpRef>, InventoryError> {
        let item = self.arc_selected(node)?;
        if self.arc_public(&item)? != *node {
            return Err(invalid());
        }
        let fields = self.arc_fields(&item, "label=consensus_key_ref")?;
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
            || self.arc_selected(node)? != item
        {
            return Err(invalid());
        }
        Ok(reference)
    }
    fn arc_snapshot(&self, metadata: Metadata) -> Result<Snapshot, InventoryError> {
        let raw = self.arc_output(
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
        let known = rpc_node_fields(&RpcNode::default());
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
        let node = self.arc_decode(&metadata, &public)?;
        if self.arc_selected(&node)? != metadata {
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
    fn arc_document(
        &self,
        node: &RpcNode,
        previous: Option<&Snapshot>,
        reference: &str,
    ) -> Result<SecretString, InventoryError> {
        let title = self.title(Kind::Rpc, &node.name);
        let tags = previous.map_or_else(
            || vec![super::TAG.into(), self.scope.tag(Kind::Rpc)],
            |v| v.metadata.tags.clone(),
        );
        let mut canonical = rpc_node_fields(node);
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
    fn arc_write(
        &self,
        node: &RpcNode,
        previous: &Snapshot,
        reference: &str,
    ) -> Result<RpcNode, InventoryError> {
        let document = self.arc_document(node, Some(previous), reference)?;
        if self.arc_selected(&previous.node)? != previous.metadata {
            return Err(invalid());
        }
        let _response = self.arc_output(
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
            .arc_listing()?
            .into_iter()
            .find(|v| v.id == previous.metadata.id)
            .ok_or_else(invalid)?;
        if found.version < previous.metadata.version {
            return Err(invalid());
        }
        let back = self.arc_snapshot(found)?;
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
    pub fn add_rpc_node(&self, node: &RpcNode) -> Result<RpcNode, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if node.id.is_some()
            || node.item_version != 0
            || !node.consensus_key_ref.is_empty()
            || node.consensus_public_key.is_empty()
            || self
                .rpc_nodes()?
                .iter()
                .any(|v| v.name == node.name || v.address == node.address)
        {
            return Err(invalid());
        }
        let document = self.arc_document(node, None, PENDING)?;
        let _response = self.arc_output(
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
            .rpc_nodes()?
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
    pub fn update_rpc_node(&self, node: &RpcNode) -> Result<RpcNode, InventoryError> {
        let _lock = self.lock()?;
        let metadata = self.arc_selected(node)?;
        let old = self.arc_public(&metadata)?;
        if !node.consensus_key_ref.is_empty()
            || old.name != node.name
            || old.address != node.address
            || old.host_key != node.host_key
            || old.consensus_public_key != node.consensus_public_key
            || old.rpc_type != node.rpc_type
        {
            return Err(invalid());
        }
        let snapshot = self.arc_snapshot(metadata)?;
        if old != snapshot.node {
            return Err(invalid());
        }
        self.arc_write(node, &snapshot, snapshot.reference()?.expose_secret())
    }
    /// Bind the verified original key item's exact identifier reference once.
    /// # Errors
    /// A completed binding cannot be replaced, even after a failed write acknowledgement.
    pub fn bind_arc_key(
        &self,
        node: &RpcNode,
        reference: &OpRef,
    ) -> Result<RpcNode, InventoryError> {
        let _lock = self.lock()?;
        let metadata = self.arc_selected(node)?;
        if reference.field() != "private_key"
            || reference.vault() != self.vault
            || self.arc_public(&metadata)? != *node
        {
            return Err(invalid());
        }
        let snapshot = self.arc_snapshot(metadata)?;
        let old = snapshot.reference()?.expose_secret();
        let value = reference.to_string();
        if snapshot.node != *node || (old != PENDING && old != value) {
            return Err(invalid());
        }
        self.arc_write(node, &snapshot, &value)
    }
}
