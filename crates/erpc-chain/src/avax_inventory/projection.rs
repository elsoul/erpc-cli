// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public field projection and a zeroizing boundary for provider output.
use super::{AvaxNode, FORMAT, InventoryError, Kind, OpRunner, SecretString, Store, check_name};
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const PUBLIC_FIELDS: &str = "label=erpc_format,label=avax_node";
pub(super) const LIMIT: usize = 1_048_576;
pub(super) fn invalid() -> InventoryError {
    InventoryError::Unreadable("Avalanche inventory projection")
}
pub(super) fn identifier(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
#[derive(Deserialize, PartialEq, Eq)]
pub(super) struct Vault {
    pub id: String,
}
#[derive(Deserialize, PartialEq, Eq)]
pub(super) struct Listed {
    pub id: String,
    pub title: String,
    pub version: u64,
    pub vault: Vault,
    pub category: String,
    pub tags: Vec<String>,
}
#[derive(Deserialize)]
pub(super) struct Field {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: Option<SecretString>,
    pub purpose: Option<String>,
    pub section: Option<serde::de::IgnoredAny>,
}
impl<R: OpRunner> Store<R> {
    pub(super) fn avax_output(
        &self,
        args: &[&str],
        input: Option<&str>,
    ) -> Result<SecretString, InventoryError> {
        let output = self.runner.run(args, input).map_err(|_| invalid())?;
        let _stderr = SecretString::from(output.stderr);
        let raw = SecretString::from(output.stdout);
        if !output.success || raw.expose_secret().len() > LIMIT {
            return Err(invalid());
        }
        Ok(raw)
    }
    pub(super) fn avax_listing(&self) -> Result<Vec<Listed>, InventoryError> {
        self.avax_scope()?;
        let scope = self.scope.tag(Kind::Rpc);
        let raw = self.avax_output(
            &[
                "item",
                "list",
                "--vault",
                &self.vault,
                "--tags",
                &scope,
                "--format",
                "json",
            ],
            None,
        )?;
        let list: Vec<Listed> = serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?;
        let mut ids = BTreeSet::new();
        let mut titles = BTreeSet::new();
        let mut found = Vec::new();
        for mut item in list {
            if !identifier(&item.id) || !identifier(&item.vault.id) || !ids.insert(item.id.clone())
            {
                return Err(invalid());
            }
            if !item.tags.contains(&scope) {
                continue;
            }
            if item.version == 0
                || item.category != "SECURE_NOTE"
                || !item.tags.iter().any(|v| v == super::super::TAG)
                || item
                    .tags
                    .iter()
                    .any(|v| v.starts_with("erpc/") && v != &scope)
                || item.tags.iter().collect::<BTreeSet<_>>().len() != item.tags.len()
                || !titles.insert(item.title.clone())
                || (identifier(&self.vault) && item.vault.id != self.vault)
            {
                return Err(invalid());
            }
            item.tags.sort();
            found.push(item);
        }
        found.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(found)
    }
    pub(super) fn avax_fields(
        &self,
        item: &Listed,
        selector: &str,
        reveal: bool,
    ) -> Result<Vec<Field>, InventoryError> {
        let mut args = vec![
            "item",
            "get",
            &item.id,
            "--vault",
            &item.vault.id,
            "--fields",
            selector,
            "--format",
            "json",
        ];
        if reveal {
            args.push("--reveal");
        }
        let raw = self.avax_output(&args, None)?;
        match raw.expose_secret().trim_start().as_bytes().first() {
            Some(b'[') => serde_json::from_str(raw.expose_secret()).map_err(|_| invalid()),
            Some(b'{') => serde_json::from_str(raw.expose_secret())
                .map(|field| vec![field])
                .map_err(|_| invalid()),
            _ => Err(invalid()),
        }
    }
    pub(super) fn avax_public(&self, item: &Listed) -> Result<AvaxNode, InventoryError> {
        let fields = self.avax_fields(item, PUBLIC_FIELDS, false)?;
        self.avax_public_fields(item, &fields.iter().collect::<Vec<_>>())
    }
    pub(super) fn avax_public_fields(
        &self,
        item: &Listed,
        fields: &[&Field],
    ) -> Result<AvaxNode, InventoryError> {
        let mut values = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for field in fields {
            if !["erpc_format", "avax_node"].contains(&field.label.as_str()) {
                return Err(invalid());
            }
            if field.kind != "STRING"
                || field.id.is_empty()
                || !ids.insert(&field.id)
                || values
                    .insert(
                        field.label.as_str(),
                        field.value.as_ref().ok_or_else(invalid)?,
                    )
                    .is_some()
            {
                return Err(invalid());
            }
        }
        if values.len() != 2
            || values
                .get("erpc_format")
                .ok_or_else(invalid)?
                .expose_secret()
                != FORMAT
        {
            return Err(invalid());
        }
        let mut node: AvaxNode =
            serde_json::from_str(values.get("avax_node").ok_or_else(invalid)?.expose_secret())
                .map_err(|_| invalid())?;
        check_name(&node.name).map_err(|_| invalid())?;
        if node.network != self.scope.network || item.title != self.title(Kind::Rpc, &node.name) {
            return Err(invalid());
        }
        node.id = Some(item.id.clone());
        node.item_version = item.version;
        Ok(node)
    }
    pub(super) fn avax_selected(&self, node: &AvaxNode) -> Result<Listed, InventoryError> {
        let id = node
            .id
            .as_deref()
            .filter(|v| identifier(v))
            .ok_or_else(invalid)?;
        let selected = self
            .avax_listing()?
            .into_iter()
            .find(|v| v.id == id)
            .ok_or_else(invalid)?;
        if selected.version != node.item_version {
            return Err(InventoryError::Changed(node.name.clone()));
        }
        if selected.title != self.title(Kind::Rpc, &node.name) {
            return Err(invalid());
        }
        Ok(selected)
    }
}
