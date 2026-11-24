// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated peer reservation regressions adapted from reviewed Arc70 transcripts.
//! Only the public RFC8032 test vector is parsed; no operational key is generated.
use super::*;
use erpc_auth::store::{
    StoreError,
    one_password::{OpOutput, OpRunner},
};
use erpc_chain::inventory::{RpcNode, Scope};
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
    fn wanted() -> ArcValidatorNode {
        ArcValidatorNode { host:RpcNode {
            name: "arc-one".into(),
            address: "192.0.2.20".into(),
            ssh_user: "ubuntu".into(),
            ssh_port: 22,
            host_key: "public-host-fixture".into(),
            version: "v0.8.1".into(),
            commit: "a".repeat(40),
            archive_sha256: "b".repeat(64),
            rpc_type: "validator-minimal".into(),
            ..RpcNode::default()
        }, controller:format!("0x{}","a".repeat(40)),fee_recipient:format!("0x{}","b".repeat(40)),
        participation:"observer".into(),admission_approved:false,
        signing_public_key:"PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=".into(),
        remote_signer:json!({"endpoint":"https://127.0.0.1:10340/","server_ca_sha256":"c".repeat(64),
          "image_sha256":"d".repeat(64),"pcr0":"e".repeat(96),"pcr1":"e".repeat(96),"pcr2":"e".repeat(96),"pcr4":"e".repeat(96)}).to_string() }
    }
    fn fresh(&self) -> Result<ArcValidatorNode, String> {
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
    fn retry(&self) -> Result<ArcValidatorNode, String> {
        let node = self
            .store()
            .arc_validators()
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
    fn stored(&self, node: &ArcValidatorNode) -> key::StoredKey {
        key::StoredKey {
            public_key: node.consensus_public_key.clone(),
            reference: self
                .store()
                .arc_validator_key_reference(node)
                .unwrap()
                .unwrap()
                .to_string(),
        }
    }
    fn owner(node: &ArcValidatorNode) -> key::validator::Owner<'_> {
        key::validator::Owner {
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
        "erpc/arc/validator-origin/{}",
        node.id.as_deref().unwrap()
    ))));
    host.op.calls.borrow_mut().clear();
    assert_eq!(host.store().arc_validators().unwrap(), [node]);
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
        !key::validator::read(&&host.op, &Host::owner(&node), &stored)
            .unwrap_err()
            .to_string()
            .contains(SEED)
    );
    host.op.error_text.set(false);
    host.op.field(
        "private_key",
        json!({"id":"private_key","label":"private_key","type":"STRING","value":SEED}),
    );
    assert!(key::validator::read(&&host.op, &Host::owner(&node), &stored).is_err());
    host.op.field(
        "public_key",
        json!({"id":"public_key","label":"public_key","type":"CONCEALED","value":SEED}),
    );
    let reads = host.op.reads.get();
    let error = key::validator::read(&&host.op, &Host::owner(&node), &stored).unwrap_err();
    assert!(!error.to_string().contains(SEED));
    assert_eq!(reads, host.op.reads.get());
}

#[test]
fn external_consensus_identity_is_never_generated_or_adopted_as_local_peer_custody() {
    let host = Host::new();
    let mut wanted = Host::wanted();
    wanted.signing_public_key = PUBLIC.into();
    let result = provision(
        &host.store(),
        &&host.op,
        VAULT,
        "testnet",
        wanted,
        None,
        || ConsensusKey::parse_seed(SEED),
    );
    assert!(result.is_err());
    assert!(host.op.events.borrow().is_empty());
}

#[test]
fn missing_or_foreign_original_tag_refuses_before_any_concealed_read() {
    for foreign in [false, true] {
        let host = Host::new();
        let node = host.fresh().unwrap();
        let stored = host.stored(&node);
        host.op.mutate("API_CREDENTIAL", |item| {
            item["tags"].as_array_mut().unwrap().retain(|tag| {
                !tag.as_str()
                    .unwrap()
                    .starts_with("erpc/arc/validator-origin/")
            });
            if foreign {
                item["tags"].as_array_mut().unwrap().push(json!(
                    "erpc/arc/validator-origin/zzzzzzzzzzzzzzzzzzzzzzzzzz"
                ));
            }
        });
        let before = host.op.reads.get();
        assert!(key::validator::read(&&host.op, &Host::owner(&node), &stored).is_err());
        assert_eq!(host.op.reads.get(), before);
    }
}
