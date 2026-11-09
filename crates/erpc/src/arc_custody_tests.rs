// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Real init/store/key orchestration over inert 1Password transcripts.
use super::*;
use erpc_auth::store::{
    StoreError,
    one_password::{OpOutput, OpRunner},
};
use erpc_chain::inventory::Scope;
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};

const VAULT: &str = "vvvvvvvvvvvvvvvvvvvvvvvvvv";
// RFC8032 test 1, never operational key material.
const SEED: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
const PUBLIC: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

#[derive(Default)]
struct Op {
    items: RefCell<Vec<Value>>,
    calls: RefCell<Vec<Vec<String>>>,
    events: RefCell<Vec<String>>,
    fault: RefCell<Option<&'static str>>,
    reads: Cell<u32>,
    error_text: Cell<bool>,
    unfiltered: Cell<bool>,
}
impl Op {
    fn create(&self, stdin: &str) -> OpOutput {
        let mut item: Value = serde_json::from_str(stdin).unwrap();
        let key = item["category"] == "API_CREDENTIAL";
        self.events
            .borrow_mut()
            .push(if key { "key-create" } else { "public-reserve" }.into());
        if key && self.fail("before-key-create") {
            return failed();
        }
        item["id"] = json!(format!("{:026}", self.items.borrow().len() + 1));
        item["version"] = json!(1);
        item["vault"] = json!({"id":VAULT});
        self.items.borrow_mut().push(item.clone());
        if self.fail(if key {
            "after-key-create"
        } else {
            "after-public-create"
        }) {
            return failed();
        }
        output(item.to_string())
    }

    fn listing(&self, tag: Option<&str>) -> OpOutput {
        let items = self
            .items
            .borrow()
            .iter()
            .filter(|v| {
                self.unfiltered.get()
                    || tag.is_none_or(|tag| v["tags"].as_array().unwrap().contains(&json!(tag)))
            })
            .map(|item| {
                let mut v = item.clone();
                v.as_object_mut().unwrap().remove("fields");
                v
            })
            .collect::<Vec<_>>();
        output(json!(items).to_string())
    }

    fn fail(&self, name: &str) -> bool {
        if self.fault.borrow().as_deref() == Some(name) {
            self.fault.take();
            true
        } else {
            false
        }
    }
    fn item(&self, category: &str) -> Value {
        self.items
            .borrow()
            .iter()
            .find(|v| v["category"] == category)
            .unwrap()
            .clone()
    }
    fn mutate(&self, category: &str, change: impl FnOnce(&mut Value)) {
        change(
            self.items
                .borrow_mut()
                .iter_mut()
                .find(|v| v["category"] == category)
                .unwrap(),
        );
    }
    fn field(&self, label: &str, value: Value) {
        self.mutate("API_CREDENTIAL", |item| {
            let field = item["fields"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| v["label"] == label)
                .unwrap();
            *field = value;
        });
    }
}
fn output(stdout: String) -> OpOutput {
    OpOutput {
        success: true,
        stdout,
        stderr: String::new(),
    }
}
fn failed() -> OpOutput {
    OpOutput {
        success: false,
        stdout: SEED.into(),
        stderr: format!("inert provider diagnostic {SEED}"),
    }
}
impl OpRunner for &Op {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
        self.calls
            .borrow_mut()
            .push(args.iter().map(|v| (*v).into()).collect());
        if self.error_text.get() {
            return Ok(failed());
        }
        if self.fail("transport") {
            return Err(StoreError::Unavailable {
                kind: erpc_auth::store::StoreKind::OnePasswordDesktop,
                reason: SEED.into(),
            });
        }
        let value = |flag: &str| args.iter().position(|v| *v == flag).map(|i| args[i + 1]);
        if args[..2] == ["item", "list"] {
            return Ok(self.listing(value("--tags")));
        }
        if args[..2] == ["item", "create"] {
            return Ok(self.create(stdin.unwrap()));
        }
        if args[..2] == ["item", "edit"] {
            self.events.borrow_mut().push("public-edit".into());
            if self.fail("before-bind") {
                return Ok(failed());
            }
            let mut items = self.items.borrow_mut();
            let item = items.iter_mut().find(|v| v["id"] == args[2]).unwrap();
            let mut next: Value = serde_json::from_str(stdin.unwrap()).unwrap();
            next["id"] = item["id"].clone();
            next["vault"] = item["vault"].clone();
            next["version"] = json!(item["version"].as_u64().unwrap() + 1);
            *item = next.clone();
            if self.fail("after-bind") {
                return Ok(failed());
            }
            return Ok(output(next.to_string()));
        }
        assert_eq!(&args[..2], ["item", "get"]);
        assert_ne!(
            args[2], "-",
            "public operations must never traverse whole items"
        );
        let mut items = self.items.borrow_mut();
        let item = items.iter_mut().find(|v| v["id"] == args[2]).unwrap();
        assert_eq!(value("--vault"), Some(VAULT));
        let Some(selector) = value("--fields") else {
            assert_eq!(
                item["category"], "SECURE_NOTE",
                "private item must only be projected"
            );
            assert!(args.contains(&"--reveal"));
            if self.fail("snapshot") {
                return Ok(failed());
            }
            return Ok(output(item.to_string()));
        };
        if self.fail("selected-field") {
            return Ok(failed());
        }
        if self.fail("full-response") {
            return Ok(output(item.to_string()));
        }
        if selector == "label=private_key" {
            self.reads.set(self.reads.get() + 1);
            assert!(args.contains(&"--reveal"));
            if self.fail("private-readback") {
                return Ok(failed());
            }
        } else {
            assert!(!args.contains(&"--reveal"));
        }
        let labels = selector
            .split(',')
            .map(|v| v.strip_prefix("label=").unwrap())
            .collect::<Vec<_>>();
        let fields = item["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| labels.contains(&v["label"].as_str().unwrap()))
            .cloned()
            .collect::<Vec<_>>();
        if self.fail("version-after-field") {
            item["version"] = json!(item["version"].as_u64().unwrap() + 1);
        }
        Ok(output(json!(fields).to_string()))
    }
}
struct Host {
    op: Op,
    directory: tempfile::TempDir,
}
impl Host {
    fn new() -> Self {
        Self {
            op: Op::default(),
            directory: tempfile::tempdir().unwrap(),
        }
    }
    fn store(&self) -> Store<&Op> {
        Store::new(
            &self.op,
            VAULT,
            Scope {
                chain: "arc".into(),
                network: "testnet".into(),
            },
            self.directory.path().join("lock"),
        )
    }
    fn wanted() -> RpcNode {
        RpcNode {
            name: "arc-one".into(),
            address: "192.0.2.20".into(),
            ssh_user: "ubuntu".into(),
            ssh_port: 22,
            host_key: "public-host-fixture".into(),
            version: "v0.8.1".into(),
            commit: "a".repeat(40),
            archive_sha256: "b".repeat(64),
            rpc_type: "full".into(),
            ..RpcNode::default()
        }
    }
    fn fresh(&self) -> Result<RpcNode, String> {
        provision(
            &self.store(),
            &&self.op,
            VAULT,
            "testnet",
            Self::wanted(),
            None,
            || ConsensusKey::parse_seed(SEED),
        )
    }
    fn retry(&self) -> Result<RpcNode, String> {
        let node = self
            .store()
            .rpc_nodes()
            .map_err(|e| e.to_string())?
            .pop()
            .unwrap();
        provision(
            &self.store(),
            &&self.op,
            VAULT,
            "testnet",
            node.clone(),
            Some(&node),
            || panic!("retry cannot generate a key"),
        )
    }
    fn stored(&self, node: &RpcNode) -> key::StoredKey {
        key::StoredKey {
            public_key: node.consensus_public_key.clone(),
            reference: self
                .store()
                .arc_key_reference(node)
                .unwrap()
                .unwrap()
                .to_string(),
        }
    }
    fn owner(node: &RpcNode) -> key::Owner<'_> {
        key::Owner {
            vault: VAULT,
            network: "testnet",
            name: &node.name,
            item: node.id.as_deref().unwrap(),
        }
    }
}

#[test]
fn actual_init_reserves_before_original_key_and_public_reads_never_request_it() {
    let host = Host::new();
    let node = host.fresh().unwrap();
    assert_eq!(node.consensus_public_key, PUBLIC);
    assert!(node.consensus_key_ref.is_empty());
    assert_eq!(
        &host.op.events.borrow()[..3],
        ["public-reserve", "key-create", "public-edit"]
    );
    let key = host.op.item("API_CREDENTIAL");
    assert!(key["tags"].as_array().unwrap().contains(&json!(format!(
        "erpc/arc/origin/{}",
        node.id.as_deref().unwrap()
    ))));
    host.op.calls.borrow_mut().clear();
    assert_eq!(host.store().rpc_nodes().unwrap(), [node]);
    for args in host.op.calls.borrow().iter() {
        assert!(!args.iter().any(|s| s.contains("private_key")
            || s.contains("consensus_key_ref")
            || s == "--reveal"));
        if args[1] == "get" {
            assert!(args.contains(&"--fields".into()));
        }
    }
}

#[test]
fn ambiguous_create_or_bind_recovers_one_original_key_without_regeneration() {
    for failure in [
        "after-key-create",
        "private-readback",
        "before-bind",
        "after-bind",
    ] {
        let host = Host::new();
        *host.op.fault.borrow_mut() = Some(failure);
        let error = host.fresh().unwrap_err();
        assert!(!error.contains(SEED));
        let original = host.op.item("API_CREDENTIAL");
        let node = host.retry().unwrap();
        assert_eq!(node.consensus_public_key, PUBLIC);
        assert_eq!(host.op.item("API_CREDENTIAL"), original);
        assert_eq!(host.op.items.borrow().len(), 2);
        assert_eq!(
            host.op
                .events
                .borrow()
                .iter()
                .filter(|v| v.as_str() == "key-create")
                .count(),
            1
        );
    }
}

#[test]
fn public_reservation_or_uncommitted_key_failure_never_becomes_permission_to_regenerate() {
    for failure in ["after-public-create", "before-key-create"] {
        let host = Host::new();
        *host.op.fault.borrow_mut() = Some(failure);
        assert!(host.fresh().is_err());
        let original = host.op.items.borrow().clone();
        let error = host.retry().unwrap_err();
        assert!(error.contains("do not regenerate"));
        assert_eq!(*host.op.items.borrow(), original);
        assert_eq!(original.len(), 1);
    }
}

#[test]
fn provider_failures_and_wrong_secret_field_types_never_echo_private_material() {
    let host = Host::new();
    let node = host.fresh().unwrap();
    let stored = host.stored(&node);
    host.op.error_text.set(true);
    assert!(
        !key::read(&&host.op, &Host::owner(&node), &stored)
            .unwrap_err()
            .to_string()
            .contains(SEED)
    );
    host.op.error_text.set(false);
    host.op.field(
        "private_key",
        json!({"id":"private_key","label":"private_key","type":"STRING","value":SEED}),
    );
    assert!(key::read(&&host.op, &Host::owner(&node), &stored).is_err());
    host.op.field(
        "public_key",
        json!({"id":"public_key","label":"public_key","type":"CONCEALED","value":SEED}),
    );
    let reads = host.op.reads.get();
    let error = key::read(&&host.op, &Host::owner(&node), &stored).unwrap_err();
    assert!(!error.to_string().contains(SEED));
    assert_eq!(reads, host.op.reads.get());
}

#[test]
fn public_projection_type_duplicates_and_version_drift_fail_closed() {
    for failure in ["type", "duplicate", "version"] {
        let host = Host::new();
        host.fresh().unwrap();
        host.op.calls.borrow_mut().clear();
        if failure == "version" {
            *host.op.fault.borrow_mut() = Some("version-after-field");
        } else {
            host.op.mutate("SECURE_NOTE", |item| {
                let list = item["fields"].as_array_mut().unwrap();
                if failure == "type" {
                    list[0]["type"] = json!("CONCEALED");
                    list[0]["value"] = json!(SEED);
                } else {
                    list.push(list[0].clone());
                }
            });
        }
        assert!(host.store().rpc_nodes().is_err());
        assert!(
            !host
                .op
                .calls
                .borrow()
                .iter()
                .any(|v| v.contains(&"--reveal".into()))
        );
    }
}

#[test]
fn original_public_identity_host_history_and_completed_reference_are_immutable() {
    let host = Host::new();
    let node = host.fresh().unwrap();
    let original_reference = host.stored(&node).reference;
    for change in ["address", "host_key", "consensus_public_key", "rpc_type"] {
        let mut changed = node.clone();
        match change {
            "address" => changed.address = "192.0.2.21".into(),
            "host_key" => changed.host_key = "other".into(),
            "consensus_public_key" => changed.consensus_public_key = "other".into(),
            _ => changed.rpc_type = "archive".into(),
        }
        assert!(host.store().update_rpc_node(&changed).is_err());
    }
    let replacement =
        OpRef::parse(&format!("op://{VAULT}/{}/private_key", "x".repeat(26))).unwrap();
    assert!(host.store().bind_arc_key(&node, &replacement).is_err());
    let changed = host
        .store()
        .update_rpc_node(&RpcNode {
            last_result: "deployment pending".into(),
            ..node.clone()
        })
        .unwrap();
    assert_eq!(
        original_reference,
        host.store()
            .arc_key_reference(&changed)
            .unwrap()
            .unwrap()
            .to_string()
    );
    assert!(host.store().update_rpc_node(&node).is_err());
}

#[test]
fn original_legacy_reference_is_verifiable_but_unbound_pending_key_cannot_be_adopted() {
    let host = Host::new();
    let node = host.fresh().unwrap();
    let stored = host.stored(&node);
    host.op.mutate("API_CREDENTIAL", |item| {
        item["tags"]
            .as_array_mut()
            .unwrap()
            .retain(|v| !v.as_str().unwrap().starts_with("erpc/arc/origin/"));
    });
    key::verify(&&host.op, &Host::owner(&node), &stored).unwrap();
    assert_eq!(
        key::read(&&host.op, &Host::owner(&node), &stored)
            .unwrap()
            .public_key(),
        PUBLIC
    );
    assert!(key::find_original(&&host.op, &Host::owner(&node), PUBLIC).is_err());
}

#[test]
fn named_references_foreign_scope_and_duplicate_key_metadata_refuse_before_private_reads() {
    let host = Host::new();
    let node = host.fresh().unwrap();
    let stored = host.stored(&node);
    let reads = host.op.reads.get();
    for reference in [
        "op://vault/item/private_key",
        &format!("op://{VAULT}/{}/other", "x".repeat(26)),
    ] {
        assert!(
            key::read(
                &&host.op,
                &Host::owner(&node),
                &key::StoredKey {
                    reference: reference.into(),
                    ..stored.clone()
                }
            )
            .is_err()
        );
    }
    let mut owner = Host::owner(&node);
    owner.network = "mainnet";
    assert!(key::read(&&host.op, &owner, &stored).is_err());
    let mut duplicate = host.op.item("API_CREDENTIAL");
    duplicate["id"] = json!("z".repeat(26));
    host.op.items.borrow_mut().push(duplicate);
    assert!(key::read(&&host.op, &Host::owner(&node), &stored).is_err());
    assert_eq!(reads, host.op.reads.get());
}

#[test]
fn full_archive_provider_and_legacy_optional_fields_round_trip_publicly() {
    for kind in ["full", "archive", "provider"] {
        let host = Host::new();
        let mut wanted = Host::wanted();
        wanted.rpc_type = kind.into();
        if kind == "provider" {
            wanted.trusted_peers = vec![format!("enode://{}@192.0.2.7:30303", "ab".repeat(64))];
            wanted.sentry_peers = vec!["/ip4/192.0.2.8/tcp/27000/p2p/12D3KooWabc".into()];
        }
        let node = provision(
            &host.store(),
            &&host.op,
            VAULT,
            "testnet",
            wanted.clone(),
            None,
            || ConsensusKey::parse_seed(SEED),
        )
        .unwrap();
        assert_eq!(node.rpc_type, kind);
        assert_eq!(node.trusted_peers, wanted.trusted_peers);
        assert_eq!(node.sentry_peers, wanted.sentry_peers);
        assert_eq!(host.retry().unwrap(), node);
        if kind == "full" {
            host.op.mutate("SECURE_NOTE", |item| {
                item["fields"].as_array_mut().unwrap().retain(|v| {
                    !matches!(
                        v["label"].as_str(),
                        Some("rpc_type" | "debug_api" | "trusted_peers" | "sentry_peers")
                    )
                });
            });
            assert_eq!(host.store().rpc_nodes().unwrap()[0].rpc_type, "full");
        }
    }
}

#[test]
fn explicit_public_updates_preserve_original_reference_notes_tags_and_field_ids() {
    let host = Host::new();
    host.fresh().unwrap();
    host.op.mutate("SECURE_NOTE",|item|{
        item["tags"].as_array_mut().unwrap().push(json!("operator-note-tag"));
        let fields=item["fields"].as_array_mut().unwrap();
        for field in fields.iter_mut() {field["id"]=json!(format!("custom-{}",field["label"].as_str().unwrap()));}
        fields.push(json!({"id":"notesPlain","label":"notesPlain","type":"STRING","purpose":"NOTES","value":SEED}));
    });
    let previous = host.op.item("SECURE_NOTE");
    let node = host.store().rpc_nodes().unwrap().pop().unwrap();
    let reference = host.stored(&node).reference;
    let changed = host
        .store()
        .update_rpc_node(&RpcNode {
            last_result: "changed public operation".into(),
            ..node
        })
        .unwrap();
    assert_eq!(host.stored(&changed).reference, reference);
    let after = host.op.item("SECURE_NOTE");
    assert_eq!(previous["tags"], after["tags"]);
    for old in previous["fields"].as_array().unwrap() {
        let next = after["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["label"] == old["label"])
            .unwrap();
        assert_eq!(next["id"], old["id"]);
        if matches!(
            old["label"].as_str(),
            Some("notesPlain" | "consensus_key_ref")
        ) {
            assert_eq!(next, old);
        }
    }
    for argv in host.op.calls.borrow().iter() {
        assert!(!argv.join(" ").contains(SEED));
    }
}

#[test]
fn unknown_snapshot_material_and_failed_projection_are_never_erased_or_treated_as_absence() {
    for kind in [
        "concealed",
        "section",
        "file",
        "url",
        "reference-type",
        "duplicate",
    ] {
        let host = Host::new();
        host.fresh().unwrap();
        let node = host.store().rpc_nodes().unwrap().pop().unwrap();
        host.op.mutate("SECURE_NOTE", |item| match kind {
            "concealed" => item["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":"unknown","label":"unknown","type":"CONCEALED","value":SEED})),
            "section" => item["sections"] = json!([{"id":"unknown"}]),
            "file" => item["files"] = json!([{"id":"unknown"}]),
            "url" => item["urls"] = json!([{"href":"unknown"}]),
            "reference-type" => {
                let field = item["fields"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|v| v["label"] == "consensus_key_ref")
                    .unwrap();
                field["type"] = json!("CONCEALED");
                field["value"] = json!(SEED);
            }
            _ => {
                let fields = item["fields"].as_array_mut().unwrap();
                fields.push(fields[0].clone());
            }
        });
        let original = host.op.items.borrow().clone();
        let events = host.op.events.borrow().len();
        assert!(
            host.store()
                .update_rpc_node(&RpcNode {
                    last_result: "update".into(),
                    ..node
                })
                .is_err()
        );
        assert_eq!(*host.op.items.borrow(), original);
        assert_eq!(host.op.events.borrow().len(), events);
    }
    let host = Host::new();
    let node = host.fresh().unwrap();
    let original = host.op.items.borrow().clone();
    for failure in ["selected-field", "transport"] {
        *host.op.fault.borrow_mut() = Some(failure);
        let error = host
            .store()
            .arc_key_reference(&node)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(SEED));
        assert_eq!(*host.op.items.borrow(), original);
    }
}

#[test]
fn unrelated_host_items_are_not_fetched_even_if_listing_returns_extra_metadata() {
    let host = Host::new();
    let node = host.fresh().unwrap();
    host.op.items.borrow_mut().push(json!({"id":"h".repeat(26),"title":"unrelated host","category":"SECURE_NOTE","version":1,"vault":{"id":VAULT},"tags":["erpc","erpc/solana/testnet/host"],"fields":[{"id":"password","label":"password","type":"CONCEALED","value":SEED}]}));
    host.op.unfiltered.set(true);
    host.op.calls.borrow_mut().clear();
    assert_eq!(
        host.store().rpc_nodes().unwrap(),
        std::slice::from_ref(&node)
    );
    let stored = host.stored(&node);
    key::verify(&&host.op, &Host::owner(&node), &stored).unwrap();
    assert!(
        !host
            .op
            .calls
            .borrow()
            .iter()
            .any(|argv| argv[1] == "get" && argv[2] == "h".repeat(26))
    );
}

#[test]
fn typed_key_projection_refuses_whole_item_fallback_and_duplicate_private_fields() {
    let host = Host::new();
    let node = host.fresh().unwrap();
    let stored = host.stored(&node);
    *host.op.fault.borrow_mut() = Some("full-response");
    let reads = host.op.reads.get();
    assert!(key::read(&&host.op, &Host::owner(&node), &stored).is_err());
    assert_eq!(host.op.reads.get(), reads);
    host.op.mutate("API_CREDENTIAL", |item| {
        let fields = item["fields"].as_array_mut().unwrap();
        let secret = fields
            .iter()
            .find(|v| v["label"] == "private_key")
            .unwrap()
            .clone();
        fields.push(secret);
    });
    assert!(key::read(&&host.op, &Host::owner(&node), &stored).is_err());
}

#[test]
fn empty_optional_public_values_do_not_make_a_missing_reference_into_creation_authority() {
    let host = Host::new();
    host.fresh().unwrap();
    host.op.mutate("SECURE_NOTE", |item| {
        for field in item["fields"].as_array_mut().unwrap() {
            if field["value"] == "" {
                field.as_object_mut().unwrap().remove("value");
            }
        }
    });
    let node = host.store().rpc_nodes().unwrap().pop().unwrap();
    assert!(node.rpc_allow.is_empty());
    assert!(node.management_allow.is_empty());
    host.op.mutate("SECURE_NOTE", |item| {
        let field = item["fields"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|v| v["label"] == "consensus_key_ref")
            .unwrap();
        field.as_object_mut().unwrap().remove("value");
    });
    assert!(host.store().arc_key_reference(&node).is_err());
    assert!(host.retry().is_err());
    assert_eq!(
        host.op
            .events
            .borrow()
            .iter()
            .filter(|v| v.as_str() == "key-create")
            .count(),
        1
    );
}

fn deliver_original(host: &Host, node: &RpcNode) -> Result<(), String> {
    let reference = host
        .store()
        .arc_key_reference(node)
        .map_err(|e| e.to_string())?
        .ok_or("missing original reference")?;
    let stored = key::StoredKey {
        public_key: node.consensus_public_key.clone(),
        reference: reference.to_string(),
    };
    let key = key::read(&&host.op, &Host::owner(node), &stored).map_err(|e| e.to_string())?;
    assert_eq!(key.public_key(), PUBLIC);
    Ok(())
}

#[test]
fn actual_configuration_orchestrator_delivers_and_renders_the_saved_public_version() {
    let host = Host::new();
    let original = host.fresh().unwrap();
    let key = host.op.item("API_CREDENTIAL");
    let next = RpcNode {
        rpc_allow: vec!["198.51.100.0/24".into()],
        ..original.clone()
    };
    let observed = RefCell::new(Vec::new());
    let (saved, result) = configure(
        &host.store(),
        &original,
        &next,
        |node| {
            assert!(node.item_version > original.item_version);
            assert!(host.store().arc_key_reference(&original).is_err());
            deliver_original(&host, node)?;
            observed.borrow_mut().push(node.item_version);
            Ok(())
        },
        |node| {
            assert_eq!(observed.borrow().as_slice(), [node.item_version]);
            let network = erpc_chain_arc::network::get("testnet").unwrap();
            let facts = crate::arc_rpc::Facts {
                machine: "x86_64".into(),
                controller: "192.0.2.1".into(),
                ssh_port: 22,
                ..crate::arc_rpc::Facts::default()
            };
            let vars = crate::arc_rpc::RunVars {
                node,
                network: &network,
                facts: &facts,
                extra: serde_json::Map::new(),
            };
            let document: Value = serde_json::from_str(&vars.inventory_json()?).unwrap();
            assert_eq!(
                document["all"]["hosts"][&node.name]["arc_rpc_allow"],
                json!(["198.51.100.0/24"])
            );
            observed.borrow_mut().push(node.item_version);
            Ok("host configuration applied")
        },
    )
    .unwrap();
    assert_eq!(result, "host configuration applied");
    assert_eq!(
        observed.borrow().as_slice(),
        [saved.item_version, saved.item_version]
    );
    assert_eq!(host.op.item("API_CREDENTIAL"), key);
}

#[test]
fn concurrent_change_after_save_still_refuses_custody_and_never_applies_stale_configuration() {
    let host = Host::new();
    let original = host.fresh().unwrap();
    let key = host.op.item("API_CREDENTIAL");
    let next = RpcNode {
        debug_api: true,
        ..original.clone()
    };
    let applied = Cell::new(false);
    let error = configure(
        &host.store(),
        &original,
        &next,
        |node| {
            host.op.mutate("SECURE_NOTE", |item| {
                item["version"] = json!(item["version"].as_u64().unwrap() + 1);
            });
            deliver_original(&host, node)
        },
        |_| {
            applied.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(!applied.get());
    assert!(error.contains("configuration may already be saved"));
    assert!(!error.contains("nothing was written"));
    assert_eq!(host.op.item("API_CREDENTIAL"), key);
    let latest = host.store().rpc_nodes().unwrap().pop().unwrap();
    assert!(latest.debug_api);
    configure(
        &host.store(),
        &latest,
        &latest,
        |node| deliver_original(&host, node),
        |_| {
            applied.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(applied.get());
    assert_eq!(host.op.item("API_CREDENTIAL"), key);
}

#[test]
fn failed_public_update_never_reads_private_custody_or_runs_configuration() {
    let host = Host::new();
    let original = host.fresh().unwrap();
    let reads = host.op.reads.get();
    let next = RpcNode {
        debug_api: true,
        ..original.clone()
    };
    *host.op.fault.borrow_mut() = Some("before-bind");
    assert!(
        configure(
            &host.store(),
            &original,
            &next,
            |_| panic!("failed save cannot read custody"),
            |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(host.op.reads.get(), reads);
    assert!(!host.store().rpc_nodes().unwrap()[0].debug_api);
}
