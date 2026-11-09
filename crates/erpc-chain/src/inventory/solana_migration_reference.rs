// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Resolve only an existing registered identity reference. No voter key export.
use super::{InventoryError, OpRunner};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

fn invalid() -> InventoryError {
    InventoryError::Unreadable("original registered identity reference")
}
fn id(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
/// Exact metadata of the already-recorded registered identity; never key bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredIdentity {
    /// Canonical provider IDs, resolved from the original pointer before stopping.
    pub reference: String,
    /// Original key-item version; annotations/rotations must not be silently adopted.
    pub version: u64,
    /// Original registered node public identity.
    pub public: String,
}
impl std::fmt::Debug for RegisteredIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegisteredIdentity([REDACTED])")
    }
}
#[derive(Deserialize, PartialEq, Eq)]
struct Vault {
    id: String,
}
#[derive(Deserialize, PartialEq, Eq)]
struct Item {
    id: String,
    version: u64,
    category: String,
    vault: Vault,
}
#[derive(Deserialize)]
struct Field {
    id: String,
    label: String,
    #[serde(rename = "type")]
    kind: String,
    value: SecretString,
}
fn metadata(op: &impl OpRunner, vault: &str, item: &str) -> Result<Item, InventoryError> {
    let output = op
        .run(
            &["item", "list", "--vault", vault, "--format", "json"],
            None,
        )
        .map_err(|_| invalid())?;
    let _stderr = SecretString::from(output.stderr);
    let raw = SecretString::from(output.stdout);
    if !output.success || raw.expose_secret().len() > 16_777_216 {
        return Err(invalid());
    }
    let items: Vec<Item> = serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?;
    if items.len() > 32768 {
        return Err(invalid());
    }
    let mut ids = BTreeSet::new();
    let mut selected = None;
    for entry in items {
        if !id(&entry.id)
            || !id(&entry.vault.id)
            || entry.version == 0
            || !ids.insert(entry.id.clone())
        {
            return Err(invalid());
        }
        if entry.id == item {
            if !matches!(entry.category.as_str(), "API_CREDENTIAL" | "SECURE_NOTE") {
                return Err(invalid());
            }
            selected = Some(entry);
        }
    }
    selected.ok_or_else(invalid)
}
fn public(op: &impl OpRunner, item: &Item, expected: &str) -> Result<(), InventoryError> {
    let output = op
        .run(
            &[
                "item",
                "get",
                &item.id,
                "--vault",
                &item.vault.id,
                "--fields",
                "label=pubkey",
                "--format",
                "json",
            ],
            None,
        )
        .map_err(|_| invalid())?;
    let _stderr = SecretString::from(output.stderr);
    let raw = SecretString::from(output.stdout);
    if !output.success || raw.expose_secret().len() > 16384 {
        return Err(invalid());
    }
    let fields: Vec<Field> = if raw.expose_secret().trim_start().starts_with('[') {
        serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?
    } else {
        vec![serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?]
    };
    if fields.len() != 1
        || fields[0].id.is_empty()
        || fields[0].label != "pubkey"
        || fields[0].kind != "STRING"
        || fields[0].value.expose_secret() != expected
    {
        return Err(invalid());
    }
    Ok(())
}
impl RegisteredIdentity {
    pub(super) fn validate(&self) -> Result<(), InventoryError> {
        let reference = erpc_secret::OpRef::parse(&self.reference).map_err(|_| invalid())?;
        if reference.field() != "keypair"
            || self.version == 0
            || !(32..=44).contains(&self.public.len())
            || !self
                .public
                .bytes()
                .all(|b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b))
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn resolve(
        op: &impl OpRunner,
        raw: &str,
        expected: &str,
    ) -> Result<Self, InventoryError> {
        let fields = raw
            .strip_prefix("op://")
            .ok_or_else(invalid)?
            .split('/')
            .collect::<Vec<_>>();
        if fields.len() != 3
            || fields[0].is_empty()
            || fields[0].len() > 256
            || fields[0].starts_with('-')
            || fields[0].chars().any(char::is_control)
            || !id(fields[1])
            || fields[2] != "keypair"
        {
            return Err(invalid());
        }
        let before = metadata(op, fields[0], fields[1])?;
        public(op, &before, expected)?;
        if metadata(op, &before.vault.id, &before.id)? != before {
            return Err(invalid());
        }
        let record = Self {
            reference: format!("op://{}/{}/keypair", before.vault.id, before.id),
            version: before.version,
            public: expected.into(),
        };
        record.validate()?;
        Ok(record)
    }
    /// Validate metadata/public identity immediately before and after the caller's
    /// explicitly selected concealed-field read. No whole key item is fetched.
    /// # Errors
    /// Refuses item movement, rotation, wrong public fields or changed metadata.
    pub fn verify(&self, op: &impl OpRunner) -> Result<(), InventoryError> {
        self.validate()?;
        let reference = erpc_secret::OpRef::parse(&self.reference).map_err(|_| invalid())?;
        let before = metadata(op, reference.vault(), reference.item())?;
        if before.version != self.version || before.vault.id != reference.vault() {
            return Err(invalid());
        }
        public(op, &before, &self.public)?;
        if metadata(op, reference.vault(), reference.item())? != before {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_auth::store::{StoreError, one_password::OpOutput};
    use serde_json::json;
    use std::cell::{Cell, RefCell};
    struct Provider {
        calls: RefCell<Vec<Vec<String>>>,
        lists: Cell<u64>,
        wrong_type: bool,
        changed: bool,
    }
    impl OpRunner for Provider {
        fn run(&self, args: &[&str], input: Option<&str>) -> Result<OpOutput, StoreError> {
            assert!(input.is_none());
            self.calls
                .borrow_mut()
                .push(args.iter().map(|v| (*v).into()).collect());
            let value = match args {
                ["item", "list", "--vault", vault, "--format", "json"] => {
                    assert!(*vault == "Original Vault" || *vault == "v".repeat(26));
                    self.lists.set(self.lists.get() + 1);
                    json!([{"id":"k".repeat(26),"version":if self.changed&&self.lists.get()>1 {2}else{1},
                        "vault":{"id":"v".repeat(26)},"category":"API_CREDENTIAL"}])
                }
                [
                    "item",
                    "get",
                    item,
                    "--vault",
                    vault,
                    "--fields",
                    "label=pubkey",
                    "--format",
                    "json",
                ] => {
                    assert_eq!(*item, "k".repeat(26));
                    assert_eq!(*vault, "v".repeat(26));
                    json!({"id":"pubkey","label":"pubkey","type":if self.wrong_type{"CONCEALED"}else{"STRING"},"value":"2".repeat(44)})
                }
                _ => panic!("unexpected credential or whole-item read"),
            };
            Ok(OpOutput {
                success: true,
                stdout: value.to_string(),
                stderr: "INERT_PRIVATE_DIAGNOSTIC".into(),
            })
        }
    }
    #[test]
    fn friendly_original_vault_is_resolved_by_exact_item_identity_without_reading_any_key() {
        let op = Provider {
            calls: RefCell::default(),
            lists: Cell::new(0),
            wrong_type: false,
            changed: false,
        };
        let record = RegisteredIdentity::resolve(
            &op,
            &format!("op://Original Vault/{}/keypair", "k".repeat(26)),
            &"2".repeat(44),
        )
        .unwrap();
        assert_eq!(
            record.reference,
            format!("op://{}/{}/keypair", "v".repeat(26), "k".repeat(26))
        );
        record.verify(&op).unwrap();
        assert!(!format!("{record:?}").contains("op://"));
        assert!(
            op.calls
                .borrow()
                .iter()
                .flatten()
                .all(|arg| arg != "--reveal")
        );
    }
    #[test]
    fn changed_metadata_or_concealed_public_field_refuses_before_secret_lookup() {
        for (wrong_type, changed) in [(true, false), (false, true)] {
            let op = Provider {
                calls: RefCell::default(),
                lists: Cell::new(0),
                wrong_type,
                changed,
            };
            let error = RegisteredIdentity::resolve(
                &op,
                &format!("op://Original Vault/{}/keypair", "k".repeat(26)),
                &"2".repeat(44),
            )
            .unwrap_err();
            assert!(!error.to_string().contains("INERT"));
        }
    }
}
