// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public validator projection without requesting Host items or key references.
use super::{FORMAT, InventoryError, Kind, OpRunner, Store, TAG, check_name, op_error};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const FIELDS: [&str; 5] = [
    "erpc_format",
    "name",
    "identity_account",
    "vote_account",
    "authority_account",
];
const SELECTOR: &str = "label=erpc_format,label=name,label=identity_account,label=vote_account,label=authority_account";

/// Only the public accounts required by a registration observer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicValidator {
    /// Immutable inventory name selected by the caller.
    pub name: String,
    /// Node identity public key.
    pub identity_account: String,
    /// Vote-account public address.
    pub vote_account: String,
    /// External withdrawal authority public key.
    pub authority_account: String,
}

#[derive(Deserialize, PartialEq, Eq)]
struct Vault {
    id: String,
}
#[derive(Deserialize, PartialEq, Eq)]
struct Listed {
    id: String,
    title: String,
    version: u64,
    vault: Vault,
    category: String,
    tags: Vec<String>,
}
#[derive(Deserialize)]
struct Field {
    id: String,
    label: String,
    #[serde(rename = "type")]
    kind: String,
    // Even a wrong-type selected field remains protected until rejected.
    // `op` leaves the key out when the value is empty.
    #[serde(default)]
    value: SecretString,
}
fn invalid() -> InventoryError {
    InventoryError::Unreadable("public Solana validator projection")
}
fn identifier(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
fn select(text: &str, scope: &str, title: &str) -> Result<Listed, InventoryError> {
    if text.len() > 1_048_576 {
        return Err(invalid());
    }
    let listed: Vec<Listed> = serde_json::from_str(text).map_err(|_| invalid())?;
    let mut ids = BTreeSet::new();
    let mut matches = Vec::new();
    for item in listed {
        if !identifier(&item.id) || !identifier(&item.vault.id) || !ids.insert(item.id.clone()) {
            return Err(invalid());
        }
        if item.title != title || !item.tags.iter().any(|tag| tag == scope) {
            continue;
        }
        if item.category != "SECURE_NOTE"
            || item.version == 0
            || !item.tags.iter().any(|tag| tag == TAG)
            || item
                .tags
                .iter()
                .filter(|tag| tag.starts_with("erpc/"))
                .any(|tag| tag != scope)
            || item.tags.iter().collect::<BTreeSet<_>>().len() != item.tags.len()
        {
            return Err(invalid());
        }
        matches.push(item);
    }
    if matches.len() != 1 {
        return Err(invalid());
    }
    matches.pop().ok_or_else(invalid)
}
pub(super) fn selected_fields(
    raw: &SecretString,
    labels: &[&str],
) -> Result<BTreeMap<String, SecretString>, InventoryError> {
    if raw.expose_secret().len() > 16_384 {
        return Err(invalid());
    }
    // `op` prints one object, not an array, when exactly one field is selected.
    let fields: Vec<Field> = match raw.expose_secret().trim_start().as_bytes().first() {
        Some(b'[') => serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?,
        Some(b'{') => vec![serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?],
        _ => return Err(invalid()),
    };
    if fields.len() != labels.len() {
        return Err(invalid());
    }
    let mut ids = BTreeSet::new();
    let mut selected = BTreeMap::new();
    for field in fields {
        if field.kind != "STRING"
            || field.id.is_empty()
            || !ids.insert(field.id)
            || !labels.contains(&field.label.as_str())
            || selected.insert(field.label, field.value).is_some()
        {
            return Err(invalid());
        }
    }
    Ok(selected)
}
fn projection(raw: &SecretString, name: &str) -> Result<PublicValidator, InventoryError> {
    let selected = selected_fields(raw, &FIELDS)?;
    let get = |label: &str| {
        selected
            .get(label)
            .map(SecretString::expose_secret)
            .ok_or_else(invalid)
    };
    if get("erpc_format")? != FORMAT || get("name")? != name {
        return Err(invalid());
    }
    // Full canonical Base58 decoding is the caller's chain-profile validation.
    for label in ["identity_account", "vote_account", "authority_account"] {
        let public = get(label)?;
        if !(32..=44).contains(&public.len())
            || !public
                .bytes()
                .all(|b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b))
        {
            return Err(invalid());
        }
    }
    Ok(PublicValidator {
        name: name.into(),
        identity_account: get("identity_account")?.into(),
        vote_account: get("vote_account")?.into(),
        authority_account: get("authority_account")?.into(),
    })
}
impl<R: OpRunner> Store<R> {
    pub(super) fn public_names(&self, kind: Kind) -> Result<Vec<String>, InventoryError> {
        if self.scope.chain != "solana"
            || !["mainnet", "testnet"].contains(&self.scope.network.as_str())
        {
            return Err(invalid());
        }
        let tag = self.scope.tag(kind);
        let output = self
            .runner
            .run(
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
            )
            .map_err(|e| InventoryError::Op {
                operation: "list the inventory",
                reason: e.to_string(),
            })?;
        let stderr = SecretString::from(output.stderr);
        let raw = SecretString::from(output.stdout);
        if !output.success {
            return Err(op_error("list the inventory", stderr.expose_secret()));
        }
        if raw.expose_secret().len() > 1_048_576 {
            return Err(invalid());
        }
        let items: Vec<Listed> =
            serde_json::from_str(raw.expose_secret()).map_err(|_| invalid())?;
        let pattern = self.title(kind, "__name__");
        let (prefix, suffix) = pattern.split_once("__name__").ok_or_else(invalid)?;
        let mut names = BTreeSet::new();
        for item in items.iter().filter(|item| item.tags.contains(&tag)) {
            let name = item
                .title
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
                .ok_or_else(invalid)?;
            check_name(name)?;
            select(raw.expose_secret(), &tag, &item.title)?;
            if !names.insert(name.to_owned()) {
                return Err(invalid());
            }
        }
        Ok(names.into_iter().collect())
    }

    fn public_item_listing(&self, kind: Kind, name: &str) -> Result<Listed, InventoryError> {
        let tag = self.scope.tag(kind);
        let output = self
            .runner
            .run(
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
            )
            .map_err(|e| InventoryError::Op {
                operation: "list the inventory",
                reason: e.to_string(),
            })?;
        let stderr = SecretString::from(output.stderr);
        let raw = SecretString::from(output.stdout);
        if !output.success {
            return Err(op_error("list the inventory", stderr.expose_secret()));
        }
        select(raw.expose_secret(), &tag, &self.title(kind, name))
    }
    /// Request only five public fields from one exact-scope validator item.
    /// No Host item, signer reference, concealed field or whole-item get is requested.
    /// A second metadata listing detects item edits/retags during projection.
    /// # Errors
    /// Refuses ambiguous identities/scopes/fields, wrong types or concurrent changes.
    pub fn public_solana_validator(&self, name: &str) -> Result<PublicValidator, InventoryError> {
        self.public_projection(Kind::Validator, name, SELECTOR, |raw| projection(raw, name))
            .map(|(_, _, public)| public)
    }

    /// List public logical registrations without reading keys or legacy hosts.
    /// # Errors
    /// Refuses ambiguous, malformed or concurrently changed metadata.
    pub fn public_solana_validators(&self) -> Result<Vec<PublicValidator>, InventoryError> {
        self.public_names(Kind::Validator)?
            .iter()
            .map(|name| self.public_solana_validator(name))
            .collect()
    }

    pub(super) fn public_item_vault(
        &self,
        kind: Kind,
        name: &str,
        id: &str,
        version: u64,
    ) -> Result<String, InventoryError> {
        let listed = self.public_item_listing(kind, name)?;
        if listed.id != id || listed.version != version {
            return Err(invalid());
        }
        Ok(listed.vault.id)
    }

    pub(super) fn public_projection<T>(
        &self,
        kind: Kind,
        name: &str,
        selector: &str,
        parse: impl FnOnce(&SecretString) -> Result<T, InventoryError>,
    ) -> Result<(String, u64, T), InventoryError> {
        check_name(name)?;
        if self.scope.chain != "solana"
            || !["mainnet", "testnet"].contains(&self.scope.network.as_str())
        {
            return Err(invalid());
        }
        let before = self.public_item_listing(kind, name)?;
        let output = self
            .runner
            .run(
                &[
                    "item",
                    "get",
                    &before.id,
                    "--vault",
                    &before.vault.id,
                    "--fields",
                    selector,
                    "--format",
                    "json",
                ],
                None,
            )
            .map_err(|e| InventoryError::Op {
                operation: "read the item",
                reason: e.to_string(),
            })?;
        let stderr = SecretString::from(output.stderr);
        let raw = SecretString::from(output.stdout);
        if !output.success {
            return Err(op_error("read the item", stderr.expose_secret()));
        }
        let public = parse(&raw)?;
        let after = self.public_item_listing(kind, name)?;
        if before != after {
            return Err(invalid());
        }
        Ok((before.id, before.version, public))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_auth::store::{StoreError, one_password::OpOutput};
    use serde_json::{Value, json};
    use std::cell::RefCell;
    struct Mock {
        lists: RefCell<Vec<String>>,
        fields: String,
        calls: RefCell<Vec<Vec<String>>>,
    }
    impl OpRunner for &Mock {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            assert!(stdin.is_none());
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).into()).collect());
            let stdout = match args {
                [
                    "item",
                    "list",
                    "--vault",
                    "network-vault",
                    "--tags",
                    "erpc/solana/testnet/validator",
                    "--format",
                    "json",
                ] => self.lists.borrow_mut().remove(0),
                [
                    "item",
                    "get",
                    id,
                    "--vault",
                    vault,
                    "--fields",
                    selector,
                    "--format",
                    "json",
                ] if *id == "a".repeat(26) && *vault == "v".repeat(26) && *selector == SELECTOR => {
                    self.fields.clone()
                }
                _ => panic!("unexpected request for unprojected or unrelated inventory"),
            };
            Ok(OpOutput {
                success: true,
                stdout,
                stderr: String::new(),
            })
        }
    }
    fn listing() -> Value {
        json!([{"id":"a".repeat(26),"title":"erpc testnet node validator","version":1,
            "vault":{"id":"v".repeat(26)},"category":"SECURE_NOTE","tags":["erpc","erpc/solana/testnet/validator"]},
            {"id":"b".repeat(26),"title":"erpc testnet node host","version":1,"vault":{"id":"v".repeat(26)},"category":"SECURE_NOTE","tags":["erpc","erpc/solana/testnet/host"]},
            {"id":"c".repeat(26),"title":"erpc testnet other validator","version":1,"vault":{"id":"v".repeat(26)},"category":"SECURE_NOTE","tags":["erpc","erpc/solana/testnet/validator"]}])
    }
    fn fields() -> Value {
        Value::Array(FIELDS.iter().map(|name|json!({"id":name,"label":name,"type":"STRING","value":match *name {"erpc_format"=>"1","name"=>"node",_=>"77777777777777777777777777777777777777777777"}})).collect())
    }
    fn fixture() -> Mock {
        let text = listing().to_string();
        Mock {
            lists: RefCell::new(vec![text.clone(), text]),
            fields: fields().to_string(),
            calls: RefCell::new(Vec::new()),
        }
    }
    fn read(mock: &Mock) -> Result<PublicValidator, InventoryError> {
        Store::new(
            mock,
            "network-vault",
            super::super::Scope {
                chain: "solana".into(),
                network: "testnet".into(),
            },
            std::path::PathBuf::new(),
        )
        .public_solana_validator("node")
    }
    #[test]
    fn only_selected_public_fields_are_requested_despite_unrelated_host_and_validator_items() {
        let mock = fixture();
        assert_eq!(read(&mock).unwrap().name, "node");
        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls.iter().filter(|c| c[1] == "get").count(), 1);
        assert_eq!(calls[1][6], SELECTOR);
        for secret in [
            "solv_password",
            "identity_ref",
            "vote_ref",
            "authority_ref",
            "--reveal",
        ] {
            assert!(!calls.iter().flatten().any(|v| v.contains(secret)));
        }
    }
    #[test]
    fn ambiguous_or_foreign_metadata_never_triggers_any_item_get() {
        for mutation in 0..6 {
            let mut list = listing();
            match mutation {
                0 => {
                    let same = list[0].clone();
                    list.as_array_mut().unwrap().push(same);
                }
                1 => list[0]["tags"] = json!(["erpc", "erpc/solana/testnet/validator/child"]),
                2 => {
                    list[0]["tags"] = json!([
                        "erpc",
                        "erpc/solana/testnet/validator",
                        "erpc/solana/mainnet/validator"
                    ]);
                }
                3 => list[0]["category"] = json!("LOGIN"),
                4 => list[0]["id"] = json!("--reveal"),
                _ => {
                    let mut same = list[0].clone();
                    same["id"] = json!("d".repeat(26));
                    list.as_array_mut().unwrap().push(same);
                }
            }
            let mock = fixture();
            mock.lists.borrow_mut()[0] = list.to_string();
            assert!(read(&mock).is_err());
            assert_eq!(mock.calls.borrow().len(), 1);
        }
    }
    #[test]
    fn concealed_extra_duplicate_or_wrong_type_fields_are_not_exposed() {
        for mutation in 0..6 {
            let mut selected = fields();
            match mutation {
                0=>{selected[2]["type"]=json!("CONCEALED");selected[2]["value"]=json!("inert secret decoy");},
                1=>selected.as_array_mut().unwrap().push(json!({"id":"solv_password","label":"solv_password","type":"CONCEALED","value":"inert secret decoy"})),
                2=>selected[2]["label"]=json!("name"),
                3=>selected[2]["id"]=selected[1]["id"].clone(),
                4=>selected[0]["value"]=json!("2"),
                _=>selected[1]["value"]=json!("other"),
            }
            let mut mock = fixture();
            mock.fields = selected.to_string();
            let error = read(&mock).unwrap_err().to_string();
            assert!(!error.contains("decoy"));
            assert_eq!(mock.calls.borrow().len(), 2);
        }
        let mut mock = fixture();
        mock.fields = mock.fields.replace(
            "\"type\":\"STRING\"",
            "\"type\":\"STRING\",\"type\":\"CONCEALED\"",
        );
        assert!(read(&mock).is_err());
    }
    fn select(
        reply: &Value,
        labels: &[&str],
    ) -> Result<BTreeMap<String, SecretString>, InventoryError> {
        selected_fields(&SecretString::from(reply.to_string()), labels)
    }
    #[test]
    fn an_empty_value_and_a_field_selected_alone_are_read_as_op_prints_them() {
        // `op` leaves the key out of an empty value, and prints one selected
        // field as an object, not as an array of one.
        let name = json!({"id":"name","label":"name","type":"STRING","value":"node"});
        let region = json!({"id":"region","label":"region","type":"STRING"});
        let both = select(&json!([name, region]), &["name", "region"]).unwrap();
        assert_eq!(both["name"].expose_secret(), "node");
        assert_eq!(both["region"].expose_secret(), "");
        let alone = select(&region, &["region"]).unwrap();
        assert_eq!(alone.len(), 1);
        assert_eq!(alone["region"].expose_secret(), "");
        assert_eq!(
            select(&name, &["name"]).unwrap()["name"].expose_secret(),
            "node"
        );
    }
    #[test]
    fn a_field_selected_alone_is_held_to_every_check_a_list_is() {
        let region = json!({"id":"region","label":"region","type":"STRING"});
        let decoy = "inert secret decoy";
        for (reply, labels) in [
            // One field where two were asked for.
            (region.clone(), &["name", "region"][..]),
            // A field that was not asked for.
            (
                json!({"id":"other","label":"other","type":"STRING"}),
                &["region"],
            ),
            // A concealed field, with a value and without one.
            (
                json!({"id":"region","label":"region","type":"CONCEALED","value":decoy}),
                &["region"],
            ),
            (
                json!({"id":"region","label":"region","type":"CONCEALED"}),
                &["region"],
            ),
            // No id, no type, and a value that is not text.
            (
                json!({"id":"","label":"region","type":"STRING"}),
                &["region"],
            ),
            (json!({"id":"region","label":"region"}), &["region"]),
            (
                json!({"id":"region","label":"region","type":"STRING","value":null}),
                &["region"],
            ),
            // Neither an object nor an array.
            (json!("region"), &["region"]),
            // Over the size this reader takes.
            (
                json!({"id":"region","label":"region","type":"STRING","value":"x".repeat(16_384)}),
                &["region"],
            ),
            // And a list that has as many fields as were asked for, but one
            // label twice under two ids and the other not at all.
            (
                json!([
                    {"id":"name","label":"name","type":"STRING","value":"node"},
                    {"id":"other","label":"name","type":"STRING","value":decoy},
                ]),
                &["name", "region"],
            ),
        ] {
            let Err(error) = select(&reply, labels) else {
                panic!("{reply} was read for {labels:?}");
            };
            assert!(!error.to_string().contains(decoy));
        }
    }
    #[test]
    fn a_registration_without_one_of_its_public_values_is_refused() {
        // None of the five may be empty, however `op` prints an empty one.
        for (index, label) in FIELDS.iter().enumerate() {
            let mut selected = fields();
            selected[index].as_object_mut().unwrap().remove("value");
            let mut mock = fixture();
            mock.fields = selected.to_string();
            assert!(read(&mock).is_err(), "{label}");
            assert_eq!(mock.calls.borrow().len(), 2);
        }
    }
    #[test]
    fn concurrent_retag_or_edit_refuses_the_projection() {
        for key in ["version", "tags", "vault"] {
            let mock = fixture();
            let mut changed = listing();
            changed[0][key] = match key {
                "version" => json!(2),
                "tags" => json!(["erpc", "erpc/solana/mainnet/validator"]),
                _ => json!({"id":"z".repeat(26)}),
            };
            mock.lists.borrow_mut()[1] = changed.to_string();
            assert!(read(&mock).is_err());
            assert_eq!(mock.calls.borrow().len(), 3);
        }
    }

    const COMPLAINT: &str =
        "[ERROR] 2026/11/05 00:00:00 authorization prompt dismissed, please try again";
    /// `op` failing: refusing as it does when it is locked or its prompt is
    /// dismissed, or unable to start at all. The listings may still answer.
    struct Failing {
        starts: bool,
        lists: bool,
    }
    impl Failing {
        fn unable() -> StoreError {
            StoreError::Unavailable {
                kind: erpc_auth::store::StoreKind::OnePasswordDesktop,
                reason: "could not run op: inert permission failure".into(),
            }
        }
    }
    impl OpRunner for &Failing {
        fn run(&self, args: &[&str], _: Option<&str>) -> Result<OpOutput, StoreError> {
            if self.lists && args[1] == "list" {
                return Ok(OpOutput {
                    success: true,
                    stdout: listing().to_string(),
                    stderr: String::new(),
                });
            }
            if !self.starts {
                return Err(Failing::unable());
            }
            Ok(OpOutput {
                success: false,
                stdout: "inert secret decoy".into(),
                stderr: format!("\n  {COMPLAINT}\nan inert second line\n"),
            })
        }
    }
    fn failing(op: &Failing) -> Store<&Failing> {
        Store::new(
            op,
            "network-vault",
            super::super::Scope {
                chain: "solana".into(),
                network: "testnet".into(),
            },
            std::path::PathBuf::new(),
        )
    }
    #[test]
    fn a_failing_op_is_reported_in_its_own_first_line() {
        // The first call of every Solana command is one of these listings.
        for (starts, reason) in [
            (true, COMPLAINT.to_owned()),
            (false, Failing::unable().to_string()),
        ] {
            let op = Failing {
                starts,
                lists: false,
            };
            let store = failing(&op);
            for error in [
                store.solana_backend("node", false).unwrap_err(),
                store.solana_backend("node", true).unwrap_err(),
                store.solana_node_summaries(false).unwrap_err(),
                store.solana_node_summaries(true).unwrap_err(),
                store.public_solana_validators().unwrap_err(),
                store.public_solana_validator("node").unwrap_err(),
            ] {
                assert_eq!(
                    error.to_string(),
                    format!("1Password could not list the inventory: {reason}")
                );
            }
            let op = Failing {
                starts,
                lists: true,
            };
            assert_eq!(
                failing(&op)
                    .public_solana_validator("node")
                    .unwrap_err()
                    .to_string(),
                format!("1Password could not read the item: {reason}")
            );
        }
    }
    #[test]
    fn a_listing_op_printed_but_too_large_to_read_is_still_unreadable() {
        let mock = fixture();
        // No item in it, so only the size can refuse it.
        mock.lists.borrow_mut()[0] = format!("[]{}", " ".repeat(1_048_576));
        let store = Store::new(
            &mock,
            "network-vault",
            super::super::Scope {
                chain: "solana".into(),
                network: "testnet".into(),
            },
            std::path::PathBuf::new(),
        );
        assert_eq!(
            store.public_solana_validators().unwrap_err().to_string(),
            invalid().to_string()
        );
        assert_eq!(mock.calls.borrow().len(), 1);
    }
}
