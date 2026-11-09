// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public source snapshots for explicit migration planning; never key retrieval.
use super::{FORMAT, InventoryError, Kind, OpRunner, Store, solana_public::selected_fields};
use secrecy::ExposeSecret as _;
use serde::Serialize;
use std::collections::BTreeMap;

const VALIDATOR: &[&str] = &[
    "identity_account",
    "vote_account",
    "authority_account",
    "client",
    "version",
    "commit",
    "region",
    "active_host",
];
const HOST: &[&str] = &[
    "validator",
    "role",
    "address",
    "ssh_user",
    "ssh_port",
    "host_key",
];
const RPC: &[&str] = &[
    "address",
    "ssh_user",
    "ssh_port",
    "host_key",
    "client",
    "rpc_type",
    "version",
    "commit",
    "geyser_version",
    "geyser_commit",
    "of1_version",
    "of1_sha256",
    "region",
    "identity_account",
    "rpc_allow",
    "management_allow",
    "monitoring_allow",
];

/// Exact item metadata and selected nonconcealed fields, not host observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicRecord {
    /// Original provider identifier; retained internally for binding, not displayed.
    #[serde(skip_serializing)]
    pub item_id: String,
    /// Provider version observed before and after the field projection.
    pub item_version: u64,
    /// Only explicitly selected STRING fields; never credential references.
    pub fields: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::super::{
        Host, Role, Scope, SolanaRpc, Validator, fields_as_op_prints, host_fields,
        solana_rpc_fields, validator_fields,
    };
    use super::*;
    use erpc_auth::store::{StoreError, one_password::OpOutput};
    use serde_json::{Value, json};
    use std::cell::{Cell, RefCell};

    struct Inventory {
        items: RefCell<Vec<Value>>,
        calls: RefCell<Vec<Vec<String>>>,
        reads: Cell<usize>,
        change_node_on_read: Option<usize>,
    }
    impl OpRunner for &Inventory {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            assert!(stdin.is_none(), "planning must never write inventory");
            self.calls
                .borrow_mut()
                .push(args.iter().map(|arg| (*arg).into()).collect());
            let stdout = match args {
                [
                    "item",
                    "list",
                    "--vault",
                    "inventory",
                    "--tags",
                    _,
                    "--format",
                    "json",
                ] => self
                    .items
                    .borrow()
                    .iter()
                    .map(|item| {
                        let mut item = item.clone();
                        item.as_object_mut().unwrap().remove("fields");
                        item
                    })
                    .collect::<Value>(),
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
                ] if *vault == "v".repeat(26) => {
                    let labels = selector
                        .split(',')
                        .map(|label| label.strip_prefix("label=").unwrap())
                        .collect::<Vec<_>>();
                    assert!(
                        !labels
                            .iter()
                            .any(|label| label.ends_with("_ref") || label.contains("password"))
                    );
                    let count = self.reads.get() + 1;
                    self.reads.set(count);
                    if self.change_node_on_read == Some(count) {
                        self.items.borrow_mut()[0]["version"] = json!(2);
                    }
                    let items = self.items.borrow();
                    let item = items.iter().find(|item| item["id"] == *id).unwrap();
                    fields_as_op_prints(
                        labels
                            .iter()
                            .filter_map(|label| {
                                item["fields"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .find(|field| field["label"] == *label)
                                    .cloned()
                            })
                            .collect(),
                    )
                }
                _ => panic!("unprojected or mutating operation in migration planning"),
            };
            Ok(OpOutput {
                success: true,
                stdout: serde_json::to_string(&stdout).unwrap(),
                stderr: String::new(),
            })
        }
    }
    fn item(id: char, kind: &str, name: &str, fields: Vec<(&str, String)>) -> Value {
        let mut fields = fields
            .into_iter()
            .map(|(label, value)| json!({"id":label,"label":label,"type":"STRING","value":value}))
            .collect::<Vec<_>>();
        fields.push(json!({"id":"solv_password","label":"solv_password","type":"CONCEALED","value":"inert concealed decoy"}));
        let suffix = if kind == "rpc" { "solana-rpc" } else { kind };
        json!({"id":id.to_string().repeat(26),"version":1,"title":format!("erpc testnet {name} {suffix}"),"category":"SECURE_NOTE","vault":{"id":"v".repeat(26)},"tags":["erpc",format!("erpc/solana/testnet/{kind}")],"fields":fields})
    }
    fn fixture(rpc: bool) -> Inventory {
        let items = if rpc {
            vec![item(
                'a',
                "rpc",
                "node",
                solana_rpc_fields(&SolanaRpc {
                    name: "node".into(),
                    client: "jito".into(),
                    rpc_type: "index-grpc".into(),
                    identity_account: "2".repeat(44),
                    geyser_version: "v1".into(),
                    ..SolanaRpc::default()
                }),
            )]
        } else {
            vec![
                item(
                    'a',
                    "validator",
                    "node",
                    validator_fields(&Validator {
                        name: "node".into(),
                        client: "jito".into(),
                        active_host: "primary".into(),
                        identity_account: "2".repeat(44),
                        ..Validator::default()
                    }),
                ),
                item(
                    'b',
                    "host",
                    "primary",
                    host_fields(&Host {
                        name: "primary".into(),
                        validator: "node".into(),
                        role: Some(Role::Primary),
                        ..Host::default()
                    }),
                ),
                item(
                    'c',
                    "host",
                    "spare",
                    host_fields(&Host {
                        name: "spare".into(),
                        validator: "node".into(),
                        role: Some(Role::Spare),
                        ..Host::default()
                    }),
                ),
            ]
        };
        Inventory {
            items: RefCell::new(items),
            calls: RefCell::new(Vec::new()),
            reads: Cell::new(0),
            change_node_on_read: None,
        }
    }
    fn read(inventory: &Inventory, rpc: bool, host: &str) -> Result<LegacySource, InventoryError> {
        Store::new(
            inventory,
            "inventory",
            Scope {
                chain: "solana".into(),
                network: "testnet".into(),
            },
            std::path::PathBuf::new(),
        )
        .solana_migration_source("node", rpc, host)
    }
    #[test]
    fn real_field_projection_keeps_all_hosts_and_features_without_private_reads() {
        let inventory = fixture(false);
        let source = read(&inventory, false, "spare").unwrap();
        assert_eq!(source.hosts.len(), 2);
        assert_eq!(source.selected_host, "spare");
        assert_eq!(source.node.fields["active_host"], "primary");
        let text = serde_json::to_string(&source).unwrap();
        for absent in ["decoy", "identity_ref", "solv_password", &"a".repeat(26)] {
            assert!(!text.contains(absent));
        }
        let inventory = fixture(true);
        let source = read(&inventory, true, "node").unwrap();
        assert_eq!(source.node.fields["rpc_type"], "index-grpc");
        assert_eq!(source.node.fields["geyser_version"], "v1");
    }
    #[test]
    fn a_source_is_read_with_the_fields_the_released_version_left_empty() {
        let clear = |inventory: &Inventory, label: &str| {
            inventory.items.borrow_mut()[0]["fields"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|field| field["label"] == label)
                .unwrap()["value"] = json!("");
        };
        // The released version never wrote active_host.
        let inventory = fixture(false);
        clear(&inventory, "active_host");
        let source = read(&inventory, false, "primary").unwrap();
        assert_eq!(source.node.fields["active_host"], "");
        assert_eq!(source.node.fields["identity_account"], "2".repeat(44));
        assert_eq!(source.hosts.len(), 2);
        // A node with no plugin, no archive and nobody allowed in yet.
        let inventory = fixture(true);
        clear(&inventory, "geyser_version");
        let source = read(&inventory, true, "node").unwrap();
        for label in [
            "geyser_version",
            "geyser_commit",
            "of1_version",
            "of1_sha256",
            "rpc_allow",
            "management_allow",
            "monitoring_allow",
        ] {
            assert_eq!(source.node.fields[label], "", "{label}");
        }
        assert_eq!(source.node.fields["rpc_type"], "index-grpc");
    }
    #[test]
    fn explicit_host_cannot_select_another_registration_or_omit_a_companion() {
        for rpc in [false, true] {
            assert!(read(&fixture(rpc), rpc, "unrelated").is_err());
        }
        let inventory = fixture(false);
        inventory.items.borrow_mut()[2]["fields"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|field| field["label"] == "validator")
            .unwrap()["value"] = json!("other-registration");
        assert!(read(&inventory, false, "spare").is_err());
    }
    #[test]
    fn concealed_or_reference_fields_never_reach_output_and_concurrent_edits_are_refused() {
        for mutation in ["concealed", "reference", "control"] {
            let inventory = fixture(false);
            let mut items = inventory.items.borrow_mut();
            let field = items[0]["fields"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|field| field["label"] == "client")
                .unwrap();
            match mutation {
                "concealed" => {
                    field["type"] = json!("CONCEALED");
                    field["value"] = json!("inert concealed decoy");
                }
                "reference" => field["value"] = json!("op://inert/decoy/field"),
                _ => field["value"] = json!("inert\ndecoy"),
            }
            drop(items);
            let error = read(&inventory, false, "primary").unwrap_err().to_string();
            assert!(!error.contains("decoy"));
        }
        for count in [1, 3, 6] {
            let mut inventory = fixture(false);
            inventory.change_node_on_read = Some(count);
            assert!(read(&inventory, false, "primary").is_err());
        }
    }
}

/// Source registration and all associated physical hosts, without changing backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LegacySource {
    /// Selected network.
    pub network: String,
    /// Standalone RPC versus logical validator.
    pub rpc: bool,
    /// Exact selected physical host. Other hosts remain represented below.
    pub selected_host: String,
    /// Logical validator or standalone RPC record.
    pub node: PublicRecord,
    /// All validator hosts, or the standalone RPC host.
    pub hosts: Vec<PublicRecord>,
}

fn invalid() -> InventoryError {
    InventoryError::Unreadable("public Solana migration source")
}

impl<R: OpRunner> Store<R> {
    pub(super) fn migration_record(
        &self,
        kind: Kind,
        name: &str,
        extra: &[&str],
    ) -> Result<PublicRecord, InventoryError> {
        let labels: Vec<_> = ["erpc_format", "name"]
            .into_iter()
            .chain(extra.iter().copied())
            .collect();
        let selector = labels
            .iter()
            .map(|label| format!("label={label}"))
            .collect::<Vec<_>>()
            .join(",");
        let (item_id, item_version, fields) =
            self.public_projection(kind, name, &selector, |raw| {
                let selected = selected_fields(raw, &labels)?;
                if selected["erpc_format"].expose_secret() != FORMAT
                    || selected["name"].expose_secret() != name
                {
                    return Err(invalid());
                }
                // Even public projections may be malformed. Never reflect unexpected
                // fields, concealed types, controls or credential references in a plan.
                let mut fields = BTreeMap::new();
                for (label, value) in selected {
                    let text = value.expose_secret();
                    if text.len() > 4096
                        || text.chars().any(char::is_control)
                        || text.contains("op://")
                    {
                        return Err(invalid());
                    }
                    fields.insert(label, text.to_owned());
                }
                Ok(fields)
            })?;
        Ok(PublicRecord {
            item_id,
            item_version,
            fields,
        })
    }

    /// Read the explicit legacy source without concealed fields or mutations.
    /// Each projection checks provider metadata before/after; the complete source
    /// is reread to reject observed intervening edits. This is not an atomic
    /// provider transaction and cannot authorize a later host mutation.
    /// # Errors
    /// Refuses native reservations, absent/foreign hosts, ambiguous records,
    /// concealed fields and observed concurrent edits.
    pub fn solana_migration_source(
        &self,
        name: &str,
        rpc: bool,
        selected_host: &str,
    ) -> Result<LegacySource, InventoryError> {
        super::check_name(name)?;
        super::check_name(selected_host)?;
        let before = self.migration_source_once(name, rpc, selected_host)?;
        let after = self.migration_source_once(name, rpc, selected_host)?;
        if before != after {
            return Err(invalid());
        }
        Ok(before)
    }

    fn migration_source_once(
        &self,
        name: &str,
        rpc: bool,
        selected_host: &str,
    ) -> Result<LegacySource, InventoryError> {
        let native_names = self.public_names(Kind::NativeHost)?;
        if native_names
            .iter()
            .any(|value| value == name || value == selected_host)
        {
            return Err(InventoryError::Refused(
                "migration source already has a native reservation".into(),
            ));
        }
        self.migration_source_original(name, rpc, selected_host)
    }

    // Only migration reconciliation may use this after authenticating its own
    // native inventory item. Fresh initialization keeps the native-name guard.
    pub(super) fn migration_source_original(
        &self,
        name: &str,
        rpc: bool,
        selected_host: &str,
    ) -> Result<LegacySource, InventoryError> {
        if rpc {
            if selected_host != name {
                return Err(invalid());
            }
            let node = self.migration_record(Kind::Rpc, name, RPC)?;
            return Ok(LegacySource {
                network: self.scope.network.clone(),
                rpc,
                selected_host: selected_host.into(),
                hosts: vec![node.clone()],
                node,
            });
        }
        let node = self.migration_record(Kind::Validator, name, VALIDATOR)?;
        let mut hosts = Vec::new();
        for host in self.public_names(Kind::Host)? {
            let association = self.migration_record(Kind::Host, &host, &["validator"])?;
            if association.fields["validator"] != name {
                continue;
            }
            let record = self.migration_record(Kind::Host, &host, HOST)?;
            if record.item_id != association.item_id
                || record.item_version != association.item_version
                || record.fields["validator"] != name
                || !matches!(record.fields["role"].as_str(), "primary" | "spare")
            {
                return Err(invalid());
            }
            hosts.push(record);
        }
        if !hosts
            .iter()
            .any(|host| host.fields["name"] == selected_host)
            || (!node.fields["active_host"].is_empty()
                && !hosts
                    .iter()
                    .any(|host| host.fields["name"] == node.fields["active_host"]))
        {
            return Err(invalid());
        }
        Ok(LegacySource {
            network: self.scope.network.clone(),
            rpc,
            selected_host: selected_host.into(),
            node,
            hosts,
        })
    }
}
