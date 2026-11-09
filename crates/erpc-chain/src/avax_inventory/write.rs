// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Explicit item edits retain the original optional backup in zeroizing fields.
//! No secret value enters a generic JSON Value or the legacy `OpItem` model.
use super::projection::{self, Field, Listed};
use super::{AvaxNode, FORMAT, InventoryError, Kind, OpRunner, SecretString, Store};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeSet;

#[derive(Deserialize)]
struct Item {
    id: String,
    title: String,
    version: u64,
    vault: projection::Vault,
    category: String,
    tags: Vec<String>,
    fields: Vec<Field>,
    #[serde(default)]
    sections: Option<Vec<serde::de::IgnoredAny>>,
    #[serde(default)]
    files: Option<Vec<serde::de::IgnoredAny>>,
    #[serde(default)]
    urls: Option<Vec<serde::de::IgnoredAny>>,
}
pub(super) struct Snapshot {
    pub metadata: Listed,
    pub node: AvaxNode,
    fields: Vec<Field>,
}
impl Snapshot {
    fn note(&self) -> Option<&SecretString> {
        self.fields
            .iter()
            .find(|f| f.label == "notesPlain")
            .and_then(|f| f.value.as_ref())
            .filter(|v| !v.expose_secret().is_empty())
    }
    fn backup(&self) -> Option<&SecretString> {
        self.fields
            .iter()
            .find(|f| f.label == "staking_backup")
            .and_then(|f| f.value.as_ref())
            .filter(|v| !v.expose_secret().is_empty())
    }
}
struct SecretValue<'a>(&'a SecretString);
impl Serialize for SecretValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.expose_secret())
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
struct VaultRef<'a> {
    id: &'a str,
}
#[derive(Serialize)]
struct Template<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault: Option<VaultRef<'a>>,
    title: &'a str,
    category: &'static str,
    tags: &'a [String],
    fields: Vec<OutputField<'a>>,
}

impl<R: OpRunner> Store<R> {
    pub(super) fn avax_snapshot(&self, metadata: Listed) -> Result<Snapshot, InventoryError> {
        // An explicit write needs the existing optional backup to construct a
        // replacement template. The API does not document partial-template
        // retention. This read is never used by list/status or public projection.
        let raw = self.avax_output(
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
        let mut item: Item =
            serde_json::from_str(raw.expose_secret()).map_err(|_| projection::invalid())?;
        item.tags.sort();
        let observed = Listed {
            id: item.id,
            title: item.title,
            version: item.version,
            vault: item.vault,
            category: item.category,
            tags: item.tags,
        };
        if observed != metadata
            || item.sections.as_ref().is_some_and(|v| !v.is_empty())
            || item.files.as_ref().is_some_and(|v| !v.is_empty())
            || item.urls.as_ref().is_some_and(|v| !v.is_empty())
        {
            return Err(projection::invalid());
        }
        let mut ids = BTreeSet::new();
        let mut labels = BTreeSet::new();
        for field in &item.fields {
            if field.id.is_empty()
                || !ids.insert(&field.id)
                || !labels.insert(field.label.as_str())
                || field.section.is_some()
            {
                return Err(projection::invalid());
            }
            match field.label.as_str() {
                "erpc_format" | "avax_node"
                    if field.kind == "STRING" && field.purpose.is_none() => {}
                "staking_backup" if field.kind == "CONCEALED" && field.purpose.is_none() => {}
                "notesPlain"
                    if field.kind == "STRING" && field.purpose.as_deref() == Some("NOTES") => {}
                _ => return Err(projection::invalid()),
            }
        }
        let public = item
            .fields
            .iter()
            .filter(|f| ["erpc_format", "avax_node"].contains(&f.label.as_str()))
            .collect::<Vec<_>>();
        let node = self.avax_public_fields(&metadata, &public)?;
        if self.avax_selected(&node)? != metadata {
            return Err(projection::invalid());
        }
        Ok(Snapshot {
            metadata,
            node,
            fields: item.fields,
        })
    }
    fn avax_document(
        &self,
        node: &AvaxNode,
        snapshot: Option<&Snapshot>,
        backup: Option<&SecretString>,
    ) -> Result<SecretString, InventoryError> {
        let title = self.title(Kind::Rpc, &node.name);
        let tags = snapshot.map_or_else(
            || vec![super::super::TAG.into(), self.scope.tag(Kind::Rpc)],
            |v| v.metadata.tags.clone(),
        );
        let format = SecretString::from(FORMAT);
        let record =
            SecretString::from(serde_json::to_string(node).map_err(|_| projection::invalid())?);
        let mut fields = Vec::new();
        if let Some(previous) = snapshot {
            for field in &previous.fields {
                let value = match field.label.as_str() {
                    "erpc_format" => Some(&format),
                    "avax_node" => Some(&record),
                    "staking_backup" => backup.or(field.value.as_ref()),
                    _ => field.value.as_ref(),
                };
                fields.push(OutputField {
                    id: &field.id,
                    label: &field.label,
                    kind: &field.kind,
                    purpose: field.purpose.as_deref(),
                    value: value.map(SecretValue),
                });
            }
        } else {
            for (label, value) in [("erpc_format", &format), ("avax_node", &record)] {
                fields.push(OutputField {
                    id: label,
                    label,
                    kind: "STRING",
                    purpose: None,
                    value: Some(SecretValue(value)),
                });
            }
        }
        if let Some(value) = backup
            && !fields.iter().any(|field| field.label == "staking_backup")
        {
            fields.push(OutputField {
                id: "staking_backup",
                label: "staking_backup",
                kind: "CONCEALED",
                purpose: None,
                value: Some(SecretValue(value)),
            });
        }
        serde_json::to_string(&Template {
            id: snapshot.map(|v| v.metadata.id.as_str()),
            version: snapshot.map(|v| v.metadata.version),
            vault: snapshot.map(|v| VaultRef {
                id: &v.metadata.vault.id,
            }),
            title: &title,
            category: "SECURE_NOTE",
            tags: &tags,
            fields,
        })
        .map(SecretString::from)
        .map_err(|_| projection::invalid())
    }
    pub(super) fn avax_create(&self, node: &AvaxNode) -> Result<AvaxNode, InventoryError> {
        let document = self.avax_document(node, None, None)?;
        let _response = self.avax_output(
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
        // Discover and project the original public reservation, rather than
        // trusting or parsing a potentially secret-bearing create response.
        let back = self
            .avax_nodes()?
            .into_iter()
            .find(|v| v.name == node.name)
            .ok_or_else(projection::invalid)?;
        let mut expected = node.clone();
        expected.id.clone_from(&back.id);
        expected.item_version = back.item_version;
        if back != expected {
            return Err(projection::invalid());
        }
        Ok(back)
    }
    pub(super) fn avax_write(
        &self,
        node: &AvaxNode,
        previous: &Snapshot,
        backup: Option<&SecretString>,
    ) -> Result<AvaxNode, InventoryError> {
        if backup.is_some_and(|v| v.expose_secret().is_empty()) {
            return Err(projection::invalid());
        }
        let document = self.avax_document(node, Some(previous), backup)?;
        if self.avax_selected(&previous.node)? != previous.metadata {
            return Err(projection::invalid());
        }
        let _response = self.avax_output(
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
        let metadata = self
            .avax_listing()?
            .into_iter()
            .find(|v| v.id == previous.metadata.id)
            .ok_or_else(projection::invalid)?;
        if metadata.version < previous.metadata.version {
            return Err(projection::invalid());
        }
        let back = self.avax_snapshot(metadata)?;
        let mut wanted = node.clone();
        wanted.item_version = back.node.item_version;
        if back.node != wanted
            || back.metadata.tags != previous.metadata.tags
            || back.note().map(ExposeSecret::expose_secret)
                != previous.note().map(ExposeSecret::expose_secret)
            || back.backup().map(ExposeSecret::expose_secret)
                != backup
                    .or_else(|| previous.backup())
                    .map(ExposeSecret::expose_secret)
        {
            return Err(InventoryError::Unreadable("Avalanche write readback"));
        }
        Ok(back.node)
    }
}
