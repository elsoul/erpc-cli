// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Exact public-key qualification before selected concealed-field access.
use super::{ConsensusKey, KeyError, STANDARD, StoredKey, title};
use base64::Engine as _;
use erpc_auth::store::one_password::OpRunner;
use erpc_secret::OpRef;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// The durable public host reservation which owns this node key.
pub struct Owner<'a> {
    /// Identifier of the original 1Password vault, never its mutable name.
    pub vault: &'a str,
    /// Qualified Arc network.
    pub network: &'a str,
    /// Original inventory node name.
    pub name: &'a str,
    /// Identifier of the original public RPC inventory item.
    pub item: &'a str,
}
fn invalid() -> KeyError {
    KeyError::Mismatch("original key scope, type or version")
}
fn identifier(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
impl Owner<'_> {
    fn validate(&self) -> Result<(), KeyError> {
        if !identifier(self.vault)
            || !identifier(self.item)
            || super::super::network::get(self.network).is_none()
            || self.name.is_empty()
            || self.name.len() > 63
            || !self.name.as_bytes()[0].is_ascii_alphanumeric()
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn tag(&self) -> String {
        format!("erpc/arc/{}/key", self.network)
    }
    fn origin(&self) -> String {
        format!("erpc/arc/origin/{}", self.item)
    }
}
#[derive(Deserialize, PartialEq, Eq)]
struct Vault {
    id: String,
}
#[derive(Deserialize, PartialEq, Eq)]
struct Item {
    id: String,
    title: String,
    category: String,
    version: u64,
    vault: Vault,
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
fn run<R: OpRunner>(
    runner: &R,
    args: &[&str],
    input: Option<&str>,
) -> Result<SecretString, KeyError> {
    let output = runner.run(args, input).map_err(|_| invalid())?;
    let _stderr = SecretString::from(output.stderr);
    let raw = SecretString::from(output.stdout);
    if !output.success || raw.expose_secret().len() > 1_048_576 {
        return Err(invalid());
    }
    Ok(raw)
}
fn selected<R: OpRunner>(runner: &R, owner: &Owner<'_>) -> Result<Option<Item>, KeyError> {
    owner.validate()?;
    let raw = run(
        runner,
        &["item", "list", "--vault", owner.vault, "--format", "json"],
        None,
    )?;
    let items: Vec<Item> = serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?;
    let wanted = title(owner.network, owner.name);
    let tag = owner.tag();
    let origin = owner.origin();
    let mut ids = BTreeSet::new();
    let mut found = None;
    for mut item in items {
        if !identifier(&item.id) || !identifier(&item.vault.id) || !ids.insert(item.id.clone()) {
            return Err(invalid());
        }
        if item.title != wanted {
            continue;
        }
        if found.is_some()
            || item.vault.id != owner.vault
            || item.category != "API_CREDENTIAL"
            || item.version == 0
            || !item.tags.iter().any(|v| v == "erpc")
            || !item.tags.contains(&tag)
            || item
                .tags
                .iter()
                .any(|v| v.starts_with("erpc/") && v != &tag && v != &origin)
            || item.tags.iter().collect::<BTreeSet<_>>().len() != item.tags.len()
        {
            return Err(invalid());
        }
        item.tags.sort();
        found = Some(item);
    }
    Ok(found)
}
fn field<R: OpRunner>(
    runner: &R,
    item: &Item,
    label: &str,
    kind: &str,
) -> Result<SecretString, KeyError> {
    let selector = format!("label={label}");
    let mut args = vec![
        "item",
        "get",
        &item.id,
        "--vault",
        &item.vault.id,
        "--fields",
        &selector,
        "--format",
        "json",
    ];
    if kind == "CONCEALED" {
        args.push("--reveal");
    }
    let raw = run(runner, &args, None)?;
    let mut fields: Vec<Field> = match raw.expose_secret().trim_start().as_bytes().first() {
        Some(b'[') => serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?,
        Some(b'{') => vec![serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?],
        _ => return Err(invalid()),
    };
    if fields.len() != 1 {
        return Err(invalid());
    }
    let value = fields.pop().ok_or_else(invalid)?;
    if value.id.is_empty()
        || value.label != label
        || value.kind != kind
        || value.purpose.is_some()
        || value.section.is_some()
    {
        return Err(invalid());
    }
    value.value.ok_or_else(invalid)
}
fn public<R: OpRunner>(runner: &R, item: &Item) -> Result<SecretString, KeyError> {
    let raw = field(runner, item, "public_key", "STRING")?;
    let text = raw.expose_secret();
    let mut decoded = Zeroizing::new([0_u8; 32]);
    let size = STANDARD
        .decode_slice(text, decoded.as_mut_slice())
        .map_err(|_| invalid())?;
    if size != 32 || text.len() != 44 {
        return Err(invalid());
    }
    Ok(raw)
}
fn qualified<R: OpRunner>(
    runner: &R,
    owner: &Owner<'_>,
    stored: &StoredKey,
) -> Result<Item, KeyError> {
    let reference = OpRef::parse(&stored.reference).map_err(|_| invalid())?;
    let item = selected(runner, owner)?.ok_or_else(invalid)?;
    if reference.vault() != owner.vault
        || reference.item() != item.id
        || reference.field() != "private_key"
        || public(runner, &item)?.expose_secret() != stored.public_key
        || selected(runner, owner)?.as_ref() != Some(&item)
    {
        return Err(invalid());
    }
    Ok(item)
}
/// Verify a pinned reference using only original-scope metadata and public fields.
/// Legacy unbound key items are accepted only through this explicit original reference.
/// # Errors
/// Refuses a changed item, wrong scope/type or public-key mismatch.
pub fn verify<R: OpRunner>(
    runner: &R,
    owner: &Owner<'_>,
    stored: &StoredKey,
) -> Result<(), KeyError> {
    qualified(runner, owner, stored).map(|_| ())
}

/// Recover a newly created key only when its original public reservation tag matches.
/// This function never reads a private field or creates a replacement identity.
/// # Errors
/// Refuses legacy unbound adoption, ambiguity and mismatching public material.
pub fn find_original<R: OpRunner>(
    runner: &R,
    owner: &Owner<'_>,
    expected: &str,
) -> Result<Option<StoredKey>, KeyError> {
    let Some(item) = selected(runner, owner)? else {
        return Ok(None);
    };
    if !item.tags.contains(&owner.origin())
        || public(runner, &item)?.expose_secret() != expected
        || selected(runner, owner)?.as_ref() != Some(&item)
    {
        return Err(invalid());
    }
    Ok(Some(StoredKey {
        public_key: expected.into(),
        reference: format!("op://{}/{}/private_key", owner.vault, item.id),
    }))
}
/// Create the original in-memory key after its public host reservation is durable.
/// Never call this to regenerate material for an existing incomplete reservation.
/// # Errors
/// An existing item, ambiguous response or failed readback is an error, not absence.
pub fn store_reserved<R: OpRunner>(
    runner: &R,
    owner: &Owner<'_>,
    key: &ConsensusKey,
) -> Result<StoredKey, KeyError> {
    if selected(runner, owner)?.is_some() {
        return Err(KeyError::Exists(title(owner.network, owner.name)));
    }
    let public_key = key.public_key();
    let secret = key.seed_base64();
    let head=json!({"title":title(owner.network,owner.name),"category":"API_CREDENTIAL","tags":["erpc",owner.tag(),owner.origin()]}).to_string();
    let mut template = Zeroizing::new(head.trim_end_matches('}').to_owned());
    template.push_str(",\"fields\":[{\"id\":\"private_key\",\"label\":\"private_key\",\"type\":\"CONCEALED\",\"value\":\"");
    template.push_str(&secret);
    template.push_str("\"},");
    template.push_str(
        &json!({"id":"public_key","label":"public_key","type":"STRING","value":public_key})
            .to_string(),
    );
    template.push_str("]}");
    let _response = run(
        runner,
        &[
            "item",
            "create",
            "-",
            "--vault",
            owner.vault,
            "--format",
            "json",
        ],
        Some(&template),
    )?;
    let stored = find_original(runner, owner, &public_key)?.ok_or_else(invalid)?;
    let back = read(runner, owner, &stored)?;
    if back.seed_base64().as_str() != secret.as_str() {
        return Err(invalid());
    }
    Ok(stored)
}
/// Read exactly one concealed seed only after qualification of the original public binding.
/// # Errors
/// Rejects malformed references, non-concealed/multiple fields and metadata drift.
pub fn read<R: OpRunner>(
    runner: &R,
    owner: &Owner<'_>,
    stored: &StoredKey,
) -> Result<ConsensusKey, KeyError> {
    let item = qualified(runner, owner, stored)?;
    let value = field(runner, &item, "private_key", "CONCEALED")?;
    let key = ConsensusKey::parse_seed(value.expose_secret())?;
    if key.public_key() != stored.public_key || selected(runner, owner)?.as_ref() != Some(&item) {
        return Err(invalid());
    }
    Ok(key)
}
