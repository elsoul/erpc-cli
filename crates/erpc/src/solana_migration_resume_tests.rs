// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Execute the production completion implementation directly with real Store
//! operations. Only provider I/O and host transport are inert; no SSH/1P runs.
use super::{Action, Cutover, CutoverReceipt, Pending, Progress, Remote, Revision, native};
use crate::node_common;
use erpc_auth::store::{
    StoreError,
    one_password::{OpOutput, OpRunner},
};
use erpc_chain::inventory::{
    FORMAT, Kind, Scope, Store,
    solana_migration::{LegacySource, PublicRecord},
    solana_migration_pending::source_binding,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
};

// Compile the actual route a second time against a transport-only test host.
// This prevents a mock from implementing the resume decision being tested.
#[allow(
    clippy::duplicate_mod,
    reason = "Compile the production route against inert transport without reimplementing its decisions"
)]
#[path = "solana_migration_complete.rs"]
mod actual_completion;

struct Provider {
    items: RefCell<Vec<Value>>,
    mix_configuration_read: Cell<bool>,
    reveals: Cell<usize>,
}
impl Provider {
    fn replace_field(&self, label: &str, value: Value) {
        let mut items = self.items.borrow_mut();
        let item = items
            .iter_mut()
            .find(|item| item["id"] == "b".repeat(26))
            .unwrap();
        item["fields"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|field| field["label"] == label)
            .unwrap()["value"] = value;
        item["version"] = json!(item["version"].as_u64().unwrap() + 1);
    }
    fn edit_policy(&self) {
        let item = self
            .items
            .borrow()
            .iter()
            .find(|item| item["id"] == "b".repeat(26))
            .unwrap()
            .clone();
        let text = item["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == "native_config")
            .unwrap()["value"]
            .as_str()
            .unwrap();
        let mut config: Value = serde_json::from_str(text).unwrap();
        config["management_allow"] = json!(["198.51.100.9/32"]);
        self.replace_field("native_config", json!(config.to_string()));
    }
    fn fields(&self, id: &str, selector: &str) -> Value {
        let labels = selector
            .split(',')
            .map(|v| v.strip_prefix("label=").unwrap())
            .collect::<Vec<_>>();
        assert!(!labels.iter().any(|v| v.contains("password")));
        if labels.contains(&"native_config") && self.mix_configuration_read.replace(false) {
            // Two external revisions: edit then restore the policy. A matching
            // final value must not disguise a different provider generation.
            let mut items = self.items.borrow_mut();
            let item = items.iter_mut().find(|item| item["id"] == id).unwrap();
            item["version"] = json!(item["version"].as_u64().unwrap() + 2);
        }
        let items = self.items.borrow();
        let item = items.iter().find(|item| item["id"] == id).unwrap();
        // What `op` prints: an empty value has no key, and one selected field
        // is an object, not an array.
        let mut selected = item["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| labels.contains(&f["label"].as_str().unwrap()))
            .cloned()
            .collect::<Vec<_>>();
        for field in &mut selected {
            if field["value"] == "" {
                field.as_object_mut().unwrap().remove("value");
            }
        }
        if selected.len() == 1 {
            selected.remove(0)
        } else {
            Value::Array(selected)
        }
    }
}
impl OpRunner for &Provider {
    fn run(&self, args: &[&str], input: Option<&str>) -> Result<OpOutput, StoreError> {
        let value = match args {
            [
                "item",
                "list",
                "--vault",
                "inventory",
                "--tags",
                tag,
                "--format",
                "json",
            ] => {
                json!(
                    self.items
                        .borrow()
                        .iter()
                        .filter(|item| item["tags"].as_array().unwrap().contains(&json!(tag)))
                        .map(|item| {
                            let mut metadata = item.clone();
                            metadata.as_object_mut().unwrap().remove("fields");
                            metadata
                        })
                        .collect::<Vec<_>>()
                )
            }
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
            ] => {
                assert_eq!(*vault, "v".repeat(26));
                assert!(input.is_none());
                self.fields(id, selector)
            }
            [
                "item",
                "create",
                "-",
                "--vault",
                "inventory",
                "--format",
                "json",
            ] => {
                let mut item: Value = serde_json::from_str(input.unwrap()).unwrap();
                assert_eq!(item["title"], "erpc mainnet fixture native-migration");
                assert_eq!(self.items.borrow().len(), 1);
                item["id"] = json!("b".repeat(26));
                item["version"] = json!(1);
                item["vault"] = json!({"id":"v".repeat(26)});
                self.items.borrow_mut().push(item.clone());
                item
            }
            ["item", "edit", id, "--vault", vault, "--format", "json"] => {
                assert_eq!(*id, "b".repeat(26));
                assert_eq!(*vault, "v".repeat(26));
                let mut next: Value = serde_json::from_str(input.unwrap()).unwrap();
                let mut items = self.items.borrow_mut();
                let item = items.iter_mut().find(|item| item["id"] == *id).unwrap();
                assert_eq!(next["version"], item["version"]);
                next["version"] = json!(item["version"].as_u64().unwrap() + 1);
                *item = next.clone();
                next
            }
            [
                "item",
                "get",
                id,
                "--vault",
                vault,
                "--format",
                "json",
                "--reveal",
            ] => {
                assert_eq!(*id, "b".repeat(26), "never reveal the legacy item");
                assert_eq!(*vault, "v".repeat(26));
                self.reveals.set(self.reveals.get() + 1);
                self.items
                    .borrow()
                    .iter()
                    .find(|item| item["id"] == *id)
                    .unwrap()
                    .clone()
            }
            _ => panic!("unexpected provider operation"),
        };
        Ok(OpOutput {
            success: true,
            stdout: value.to_string(),
            stderr: String::new(),
        })
    }
}

fn public_vector() -> SecretString {
    // RFC8032 section7.1 TEST1, shared with native custody tests. Public test
    // material only; no key generator or operational credential is used.
    let vector = concat!(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let bytes = (0..vector.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&vector[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    serde_json::to_string(&bytes).unwrap().into()
}
fn fixture() -> (Pending, Provider) {
    let (mut node, request) = super::bundle_tests::fixture(true, "mainnet").unwrap();
    node.contract.inventory_id.clear();
    node.item_version = 0;
    let mut fields = BTreeMap::new();
    for (name, value) in [
        ("erpc_format", FORMAT),
        ("name", "fixture"),
        ("address", node.address.as_str()),
        ("ssh_user", "solv"),
        ("ssh_port", "2222"),
        ("host_key", node.host_key.as_str()),
        ("client", "agave"),
        ("rpc_type", "send-tx"),
        (
            "version",
            request.legacy.artifact_evidence.source["version"].as_str(),
        ),
        (
            "commit",
            request.legacy.artifact_evidence.source["commit"].as_str(),
        ),
        ("identity_account", node.contract.identity_account.as_str()),
        ("geyser_version", ""),
        ("geyser_commit", ""),
        ("of1_version", ""),
        ("of1_sha256", ""),
        ("region", ""),
        ("rpc_allow", ""),
        ("management_allow", ""),
        ("monitoring_allow", ""),
    ] {
        fields.insert(name.to_owned(), value.to_owned());
    }
    let record = PublicRecord {
        item_id: "a".repeat(26),
        item_version: 1,
        fields,
    };
    let source = LegacySource {
        network: "mainnet".into(),
        rpc: true,
        selected_host: "fixture".into(),
        node: record.clone(),
        hosts: vec![record.clone()],
    };
    let mut original = request.legacy;
    original.source_sha256 = source_binding(&source, &original).unwrap();
    let pending = Pending::new(&source, original, node, request.intent, None).unwrap();
    let fields = record
        .fields
        .iter()
        .map(|(label, value)| json!({"id":label,"label":label,"type":"STRING","value":value}))
        .collect::<Vec<_>>();
    let scope = Scope {
        chain: "solana".into(),
        network: "mainnet".into(),
    };
    let item = json!({"id":record.item_id,"version":1,"category":"SECURE_NOTE","title":"erpc mainnet fixture solana-rpc",
        "vault":{"id":"v".repeat(26)},"tags":["erpc",scope.tag(Kind::Rpc)],"fields":fields});
    (
        pending,
        Provider {
            items: RefCell::new(vec![item]),
            mix_configuration_read: Cell::new(false),
            reveals: Cell::new(0),
        },
    )
}

#[derive(Default)]
struct NoPrivateExport {
    calls: Cell<usize>,
}
impl NoPrivateExport {
    fn run_private(
        &self,
        _: &erpc_ssh::RemoteCommand,
        _: &[u8],
        _: usize,
    ) -> Result<erpc_ssh::PrivateOutput, &'static str> {
        self.calls.set(self.calls.get() + 1);
        panic!("resumed handoff must use retained custody, not export another key")
    }
}
struct Live<'a> {
    store: &'a Store<&'a Provider>,
    pending: Pending,
    session: NoPrivateExport,
    status: Progress,
    sent: Vec<Value>,
}
impl Live<'_> {
    fn original(&self) -> Result<(), String> {
        self.store
            .verify_solana_original_migration(&self.pending)
            .map_err(|_| "original scope differs".into())
    }
    fn progress(&mut self) -> Result<Progress, String> {
        self.original()?;
        Progress::checked(
            serde_json::to_value(&self.status).unwrap(),
            &self.pending.intent,
        )
    }
    fn stage(&mut self, action: Action) -> Result<(), String> {
        self.sent.push(json!({"unexpected_stage": action}));
        panic!("resume cannot replay original custody or copying")
    }
    fn sealed(&mut self, value: &Value) -> Result<(), String> {
        self.original()?;
        assert_eq!(value["action"], "migration-finalize");
        let receipt: CutoverReceipt =
            serde_json::from_value(value["cutover"]["receipt"].clone()).unwrap();
        let previous = self.status.cutover.as_ref().unwrap();
        assert_eq!(previous.receipt, receipt);
        let version = if previous.phase == "complete" {
            previous.provider_version.unwrap()
        } else {
            value["cutover"]["provider_version"].as_u64().unwrap()
        };
        self.sent.push(value.clone());
        self.status.recorded_phase = "complete".into();
        self.status.migration_complete = true;
        self.status.cutover = Some(Cutover {
            phase: "complete".into(),
            receipt,
            provider_version: Some(version),
        });
        self.original()
    }
}
fn continue_copy(_: &mut Live<'_>) -> Result<Progress, String> {
    panic!("resumed handoff cannot recopy history")
}
fn host_status(
    pending: &Pending,
    receipt: CutoverReceipt,
    complete_ack: bool,
    marker: bool,
) -> Progress {
    Progress {
        intent: pending.intent.clone(),
        migration_reserved: true,
        recorded_phase: if marker {
            "complete"
        } else if complete_ack {
            "finalizing"
        } else {
            "promoting"
        }
        .into(),
        helper_revision: Some(native::helper_revision().unwrap()),
        copy_recorded_complete: true,
        data_recorded_promoted: true,
        migration_complete: marker,
        runtime_inspected: false,
        ready: None,
        cutover: Some(Cutover {
            phase: if complete_ack { "complete" } else { "prepared" }.into(),
            receipt,
            provider_version: complete_ack.then_some(3),
        }),
    }
}
fn with_promoted(test: impl FnOnce(&Store<&Provider>, &Provider, Pending, CutoverReceipt)) {
    let (candidate, provider) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(
        &provider,
        "inventory",
        Scope {
            chain: "solana".into(),
            network: "mainnet".into(),
        },
        directory.path().join("inventory.lock"),
    );
    let reserved = store.reserve_solana_migration(&candidate).unwrap();
    let backup = store
        .backup_solana_migration_identity(&reserved, &public_vector())
        .unwrap();
    let prepared = store
        .prepare_solana_migration_promotion(&backup.pending)
        .unwrap();
    let promoted = store.promote_solana_migration(&prepared).unwrap();
    assert_eq!(promoted.pending.node.item_version, 3);
    test(&store, &provider, promoted.pending, promoted.receipt);
}

#[test]
fn prepared_ack_rechecks_actual_provider_configuration_before_any_host_effect() {
    for changed in [false, true] {
        with_promoted(|store, provider, pending, receipt| {
            if changed {
                provider.edit_policy();
            }
            let current = store.solana_original_migration("fixture").unwrap();
            let before = provider.items.borrow().clone();
            let mut live = Live {
                store,
                pending: current,
                session: NoPrivateExport::default(),
                status: host_status(&pending, receipt.clone(), false, false),
                sent: vec![],
            };
            let result = live.complete();
            if changed {
                assert!(result.unwrap_err().contains("promoted configuration"));
                assert!(live.sent.is_empty());
            } else {
                assert!(result.unwrap().migration_complete);
                assert_eq!(live.sent.len(), 1);
                assert_eq!(live.sent[0]["cutover"]["provider_version"], 3);
                assert_eq!(
                    live.sent[0]["cutover"]["receipt"],
                    serde_json::to_value(receipt).unwrap()
                );
            }
            assert_eq!(
                *provider.items.borrow(),
                before,
                "resumption changed original provider fields"
            );
        });
    }
}
#[test]
fn prepared_ack_refuses_a_changed_generation_even_when_the_policy_value_is_restored() {
    with_promoted(|store, provider, pending, receipt| {
        provider.mix_configuration_read.set(true);
        let mut live = Live {
            store,
            status: host_status(&pending, receipt, false, false),
            pending,
            session: NoPrivateExport::default(),
            sent: vec![],
        };
        assert!(live.complete().is_err());
        assert!(live.sent.is_empty());
        assert!(!provider.mix_configuration_read.get());
        assert_eq!(
            store
                .solana_original_migration("fixture")
                .unwrap()
                .node
                .item_version,
            5
        );
    });
}
#[test]
fn completed_ack_keeps_later_policy_and_only_repairs_its_original_marker() {
    for marker in [false, true] {
        with_promoted(|store, provider, pending, receipt| {
            provider.edit_policy();
            let current = store.solana_original_migration("fixture").unwrap();
            let before = provider.items.borrow().clone();
            let reveals = provider.reveals.get();
            let mut live = Live {
                store,
                pending: current,
                session: NoPrivateExport::default(),
                status: host_status(&pending, receipt.clone(), true, marker),
                sent: vec![],
            };
            let result = live.complete().unwrap();
            assert!(result.migration_complete);
            assert_eq!(result.cutover.unwrap().provider_version, Some(3));
            assert_eq!(live.sent.len(), usize::from(!marker));
            if !marker {
                assert_eq!(live.sent[0]["cutover"]["provider_version"], 4);
            }
            assert_eq!(*provider.items.borrow(), before);
            assert_eq!(provider.reveals.get(), reveals);
        });
    }
}
#[test]
fn unknown_original_custody_contract_or_host_stage_never_finalizes() {
    for changed in ["source", "custody", "contract", "stage"] {
        with_promoted(|store, provider, pending, receipt| {
            let mut current = pending.clone();
            let mut status = host_status(&pending, receipt, false, false);
            match changed {
                "source" => provider.items.borrow_mut()[0]["version"] = json!(2),
                "custody" => {
                    provider.replace_field("migration_identity", json!("INERT_INVALID_KEY"));
                }
                "contract" => current.node.contract.name = "other".into(),
                "stage" => status.recorded_phase = "unknown".into(),
                _ => unreachable!(),
            }
            if changed == "custody" {
                current = store.solana_original_migration("fixture").unwrap();
            }
            let mut live = Live {
                store,
                pending: current,
                session: NoPrivateExport::default(),
                status,
                sent: vec![],
            };
            assert!(live.complete().is_err());
            assert!(live.sent.is_empty());
        });
    }
}
