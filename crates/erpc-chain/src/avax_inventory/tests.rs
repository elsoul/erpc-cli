// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use erpc_auth::store::{StoreError, one_password::OpOutput};
use serde_json::Value;
use std::cell::{Cell, RefCell};

const SECRET: &str = "inert-original-backup-that-must-not-leak";
fn node() -> AvaxNode {
    AvaxNode {
        name: "av1".into(),
        address: "192.0.2.10".into(),
        network: "fuji".into(),
        rpc_type: "full".into(),
        validator: true,
        ..Default::default()
    }
}
fn metadata() -> Value {
    json!({"id":"i".repeat(26),"title":"erpc fuji av1 avax-rpc","version":1,"vault":{"id":"v".repeat(26)},"category":"SECURE_NOTE","tags":["erpc","erpc/avax/fuji/rpc"]})
}
fn public_fields() -> Value {
    json!([{"id":"format-id","label":"erpc_format","type":"STRING","value":FORMAT},{"id":"record-id","label":"avax_node","type":"STRING","value":serde_json::to_string(&node()).unwrap()}])
}
struct Fake {
    listed: RefCell<Vec<Value>>,
    fields: RefCell<Value>,
    calls: RefCell<Vec<Vec<String>>>,
    drift: Cell<bool>,
}
impl Fake {
    fn new() -> Self {
        Self {
            listed: RefCell::new(vec![metadata()]),
            fields: RefCell::new(public_fields()),
            calls: RefCell::new(Vec::new()),
            drift: Cell::new(false),
        }
    }
}
impl OpRunner for &Fake {
    fn run(&self, args: &[&str], input: Option<&str>) -> Result<OpOutput, StoreError> {
        self.calls
            .borrow_mut()
            .push(args.iter().map(|v| (*v).into()).collect());
        assert!(input.is_none());
        let value = match args {
            [
                "item",
                "list",
                "--vault",
                _,
                "--tags",
                "erpc/avax/fuji/rpc",
                "--format",
                "json",
            ] => json!(*self.listed.borrow()),
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
                assert_eq!(*id, "i".repeat(26));
                assert_eq!(*vault, "v".repeat(26));
                assert_eq!(*selector, projection::PUBLIC_FIELDS);
                if self.drift.get() {
                    self.listed.borrow_mut()[0]["version"] = json!(2);
                }
                self.fields.borrow().clone()
            }
            _ => panic!("unexpected whole-item, concealed or mutation request: {args:?}"),
        };
        Ok(OpOutput {
            success: true,
            stdout: value.to_string(),
            stderr: String::new(),
        })
    }
}
fn store(fake: &Fake) -> Store<&Fake> {
    Store::new(
        fake,
        "v".repeat(26),
        super::super::Scope {
            chain: "avax".into(),
            network: "fuji".into(),
        },
        std::env::temp_dir().join("unused-read-only-avax-projection.lock"),
    )
}
#[test]
fn listing_only_requests_exact_public_fields_and_never_decoy_host_secrets() {
    let fake = Fake::new();
    let mut decoy = metadata();
    decoy["id"] = json!("h".repeat(26));
    decoy["title"] = json!("decoy host");
    decoy["tags"] = json!(["erpc", "erpc/avax/fuji/host"]);
    fake.listed.borrow_mut().push(decoy);
    let found = store(&fake).avax_nodes().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, Some("i".repeat(26)));
    assert!(!format!("{found:?}").contains(SECRET));
    assert_eq!(
        fake.calls.borrow().iter().filter(|c| c[1] == "get").count(),
        1
    );
    assert!(fake.calls.borrow().iter().all(|c| {
        !c.iter()
            .any(|v| v == "--reveal" || v.contains("staking_backup"))
    }));
}
#[test]
fn wrong_public_types_duplicate_fields_and_metadata_changes_fail_without_echo() {
    for case in [
        "concealed",
        "duplicate",
        "drift",
        "retag",
        "vault",
        "category",
        "title",
        "network",
    ] {
        let fake = Fake::new();
        match case {
            "concealed" => {
                fake.fields.borrow_mut()[1]["type"] = json!("CONCEALED");
                fake.fields.borrow_mut()[1]["value"] = json!(SECRET);
            }
            "duplicate" => {
                let field = fake.fields.borrow()[0].clone();
                fake.fields.borrow_mut()[1] = field;
            }
            "drift" => fake.drift.set(true),
            "retag" => {
                fake.listed.borrow_mut()[0]["tags"] =
                    json!(["erpc", "erpc/avax/fuji/rpc", "erpc/avax/mainnet/rpc"]);
            }
            "vault" => fake.listed.borrow_mut()[0]["vault"]["id"] = json!("w".repeat(26)),
            "category" => fake.listed.borrow_mut()[0]["category"] = json!("LOGIN"),
            "title" => fake.listed.borrow_mut()[0]["title"] = json!("different"),
            _ => {
                let mut foreign = node();
                foreign.network = "mainnet".into();
                fake.fields.borrow_mut()[1]["value"] =
                    json!(serde_json::to_string(&foreign).unwrap());
            }
        }
        let error = store(&fake).avax_nodes().unwrap_err();
        assert!(!error.to_string().contains(SECRET), "{case}");
        assert!(
            fake.calls
                .borrow()
                .iter()
                .all(|c| !c.iter().any(|v| v == "--reveal"))
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    None,
    BeforeWrite,
    AfterWrite,
    Readback,
    CorruptBackup,
    SnapshotUnavailable,
}
struct Writable {
    item: RefCell<Option<Value>>,
    calls: RefCell<Vec<Vec<String>>>,
    failure: Cell<Failure>,
    edited: Cell<bool>,
    same_version: Cell<bool>,
    drift: Cell<bool>,
}
impl Writable {
    fn new() -> Self {
        Self {
            item: RefCell::new(None),
            calls: RefCell::new(Vec::new()),
            failure: Cell::new(Failure::None),
            edited: Cell::new(false),
            same_version: Cell::new(false),
            drift: Cell::new(false),
        }
    }
    fn list(&self) -> Value {
        self.item.borrow().as_ref().map_or_else(
            || json!([]),
            |item| {
                let mut value = item.clone();
                value.as_object_mut().unwrap().remove("fields");
                json!([value])
            },
        )
    }
    fn stored_backup(&self) -> Option<String> {
        self.item
            .borrow()
            .as_ref()?
            .get("fields")?
            .as_array()?
            .iter()
            .find(|f| f["label"] == "staking_backup")?
            .get("value")?
            .as_str()
            .map(str::to_owned)
    }
    fn writes(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|a| ["create", "edit"].contains(&a[1].as_str()))
            .count()
    }
    fn snapshots(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|a| a[1] == "get" && !a.iter().any(|v| v == "--fields"))
            .count()
    }
    fn mutate(&self, args: &[&str], input: &str) -> OpOutput {
        if self.failure.get() == Failure::BeforeWrite {
            return failed();
        }
        let version = self
            .item
            .borrow()
            .as_ref()
            .and_then(|v| v["version"].as_u64())
            .unwrap_or(0);
        let mut item: Value = serde_json::from_str(input).unwrap();
        if args[1] == "edit" {
            assert_eq!(item["id"], "i".repeat(26));
            assert_eq!(item["version"], version);
            assert_eq!(item["vault"]["id"], "v".repeat(26));
        }
        item["id"] = json!("i".repeat(26));
        item["vault"] = json!({"id":"v".repeat(26)});
        item["version"] = json!(if self.same_version.get() {
            version
        } else {
            version + 1
        });
        if self.failure.get() == Failure::CorruptBackup {
            for field in item["fields"].as_array_mut().unwrap() {
                if field["label"] == "staking_backup" {
                    field["value"] = json!("different inert readback");
                }
            }
        }
        *self.item.borrow_mut() = Some(item);
        self.edited.set(args[1] == "edit");
        if self.failure.get() == Failure::AfterWrite {
            return failed();
        }
        // Command responses can echo secrets even when they are not useful JSON.
        OpOutput {
            success: true,
            stdout: SECRET.into(),
            stderr: SECRET.into(),
        }
    }
}
fn failed() -> OpOutput {
    OpOutput {
        success: false,
        stdout: SECRET.into(),
        stderr: SECRET.into(),
    }
}
impl OpRunner for &Writable {
    fn run(&self, args: &[&str], input: Option<&str>) -> Result<OpOutput, StoreError> {
        self.calls
            .borrow_mut()
            .push(args.iter().map(|v| (*v).into()).collect());
        if ["create", "edit"].contains(&args[1]) {
            return Ok(self.mutate(args, input.unwrap()));
        }
        assert!(input.is_none());
        let value = match args {
            [
                "item",
                "list",
                "--vault",
                _,
                "--tags",
                "erpc/avax/fuji/rpc",
                "--format",
                "json",
            ] => self.list(),
            [
                "item",
                "get",
                _,
                "--vault",
                _,
                "--fields",
                selector,
                "--format",
                "json",
                tail @ ..,
            ] => {
                let item = self.item.borrow();
                let fields = item.as_ref().unwrap()["fields"].as_array().unwrap();
                match *selector {
                    projection::PUBLIC_FIELDS => {
                        assert!(tail.is_empty());
                        json!(
                            fields
                                .iter()
                                .filter(|f| ["erpc_format", "avax_node"]
                                    .contains(&f["label"].as_str().unwrap()))
                                .collect::<Vec<_>>()
                        )
                    }
                    "label=staking_backup" => {
                        assert_eq!(tail, ["--reveal"]);
                        let Some(field) = fields.iter().find(|f| f["label"] == "staking_backup")
                        else {
                            return Ok(failed());
                        };
                        field.clone()
                    }
                    _ => panic!("unexpected selector"),
                }
            }
            [
                "item",
                "get",
                _,
                "--vault",
                _,
                "--format",
                "json",
                "--reveal",
            ] => {
                if (self.edited.get() && self.failure.get() == Failure::Readback)
                    || self.failure.get() == Failure::SnapshotUnavailable
                {
                    return Ok(failed());
                }
                if self.drift.get() {
                    let mut item = self.item.borrow_mut();
                    let item = item.as_mut().unwrap();
                    item["version"] = json!(item["version"].as_u64().unwrap() + 1);
                }
                self.item.borrow().as_ref().unwrap().clone()
            }
            _ => panic!("unexpected command {args:?}"),
        };
        Ok(OpOutput {
            success: true,
            stdout: value.to_string(),
            stderr: String::new(),
        })
    }
}
struct Fixture {
    op: Writable,
    path: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "erpc-avax-projection-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self {
            op: Writable::new(),
            path,
        }
    }
    fn store(&self) -> Store<&Writable> {
        Store::new(
            &self.op,
            "v".repeat(26),
            super::super::Scope {
                chain: "avax".into(),
                network: "fuji".into(),
            },
            self.path.join("inventory.lock"),
        )
    }
    fn pinned(&self) -> AvaxNode {
        let store = self.store();
        let mut node = store.add_avax_node(&node()).unwrap();
        node.node_id = "public-node-id".into();
        node.identity_hashes = json!({"public":"digest"});
        node.node_pop = json!({"public":"proof"});
        store.update_avax_node(&node).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn original_backup_survives_public_update_and_explicit_restore_uses_one_field() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let pinned = fixture.pinned();
    let secret = SecretString::from(SECRET);
    let backed = store.backup_avax_identity(&pinned, &secret).unwrap();
    {
        let mut item = fixture.op.item.borrow_mut();
        let item = item.as_mut().unwrap();
        item["tags"]
            .as_array_mut()
            .unwrap()
            .push(json!("operator-note"));
        item["fields"].as_array_mut().unwrap().push(json!({"id":"notesPlain","label":"notesPlain","type":"STRING","purpose":"NOTES","value":"retained operator note"}));
    }
    let mut wanted = backed;
    wanted.last_result = "configured".into();
    let updated = store.update_avax_node(&wanted).unwrap();
    assert_eq!(fixture.op.stored_backup().as_deref(), Some(SECRET));
    assert!(
        fixture.op.item.borrow().as_ref().unwrap()["tags"]
            .as_array()
            .unwrap()
            .contains(&json!("operator-note"))
    );
    let snapshots = fixture.op.snapshots();
    assert_eq!(
        store
            .avax_identity_backup(&updated)
            .unwrap()
            .expose_secret(),
        SECRET
    );
    assert_eq!(fixture.op.snapshots(), snapshots);
    let snapshots = fixture.op.snapshots();
    assert!(!format!("{:?}", store.avax_nodes().unwrap()).contains(SECRET));
    assert_eq!(fixture.op.snapshots(), snapshots);
    for call in fixture.op.calls.borrow().iter() {
        assert!(!call.join(" ").contains(SECRET));
    }
}
#[test]
fn absent_legacy_backup_and_noop_versions_are_preserved_without_guessing_read_errors() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let pinned = fixture.pinned();
    assert!(fixture.op.stored_backup().is_none());
    fixture.op.same_version.set(true);
    let updated = store.update_avax_node(&pinned).unwrap();
    assert_eq!(updated.item_version, pinned.item_version);
    assert!(fixture.op.stored_backup().is_none());
    let writes = fixture.op.writes();
    assert!(store.avax_identity_backup(&updated).is_err());
    assert_eq!(fixture.op.writes(), writes);
}
#[test]
fn immutable_scope_and_stale_versions_fail_before_requesting_private_snapshots() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let pinned = fixture.pinned();
    let backed = store
        .backup_avax_identity(&pinned, &SecretString::from(SECRET))
        .unwrap();
    for field in [
        "address", "node_id", "history", "role", "version", "network",
    ] {
        let mut altered = backed.clone();
        match field {
            "address" => altered.address = "192.0.2.11".into(),
            "node_id" => altered.node_id = "different".into(),
            "history" => altered.rpc_type = "archive".into(),
            "role" => altered.validator = false,
            "version" => altered.item_version -= 1,
            _ => altered.network = "mainnet".into(),
        }
        let snapshots = fixture.op.snapshots();
        let writes = fixture.op.writes();
        assert!(store.update_avax_node(&altered).is_err());
        assert_eq!(fixture.op.snapshots(), snapshots);
        assert_eq!(fixture.op.writes(), writes);
    }
}
#[test]
fn failed_or_ambiguous_writes_never_echo_secrets_or_attempt_rollback() {
    for failure in [
        Failure::BeforeWrite,
        Failure::AfterWrite,
        Failure::Readback,
        Failure::CorruptBackup,
    ] {
        let fixture = Fixture::new();
        let store = fixture.store();
        let pinned = fixture.pinned();
        let backed = store
            .backup_avax_identity(&pinned, &SecretString::from(SECRET))
            .unwrap();
        fixture.op.edited.set(false);
        fixture.op.failure.set(failure);
        let writes = fixture.op.writes();
        let error = store
            .backup_avax_identity(
                &backed,
                &SecretString::from("inert refreshed original bundle"),
            )
            .unwrap_err();
        assert!(!error.to_string().contains(SECRET));
        assert_eq!(fixture.op.writes(), writes + 1);
        if failure == Failure::BeforeWrite {
            assert_eq!(fixture.op.stored_backup().as_deref(), Some(SECRET));
        }
        fixture.op.failure.set(Failure::None);
        let fresh = store.avax_nodes().unwrap().pop().unwrap();
        assert!(
            store
                .backup_avax_identity(&fresh, &SecretString::from(SECRET))
                .is_ok()
        );
        assert_eq!(fixture.op.stored_backup().as_deref(), Some(SECRET));
    }
}
#[test]
fn malformed_or_changed_private_snapshot_refuses_before_edit() {
    for case in [
        "type",
        "duplicate",
        "extra",
        "section",
        "attachment",
        "race",
    ] {
        let fixture = Fixture::new();
        let store = fixture.store();
        let pinned = fixture.pinned();
        let backed = store
            .backup_avax_identity(&pinned, &SecretString::from(SECRET))
            .unwrap();
        match case {
            "type" => {
                let mut item = fixture.op.item.borrow_mut();
                item.as_mut().unwrap()["fields"][2]["type"] = json!("STRING");
            }
            "duplicate" => {
                let mut item = fixture.op.item.borrow_mut();
                let fields = item.as_mut().unwrap()["fields"].as_array_mut().unwrap();
                fields.push(fields[2].clone());
            }
            "extra" => fixture.op.item.borrow_mut().as_mut().unwrap()["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":"other","label":"other","type":"CONCEALED","value":SECRET})),
            "section" => {
                fixture.op.item.borrow_mut().as_mut().unwrap()["sections"] =
                    json!([{"id":"unknown"}]);
            }
            "attachment" => {
                fixture.op.item.borrow_mut().as_mut().unwrap()["files"] =
                    json!([{"name":"unknown"}]);
            }
            _ => fixture.op.drift.set(true),
        }
        let writes = fixture.op.writes();
        let error = store.update_avax_node(&backed).unwrap_err();
        assert!(!error.to_string().contains(SECRET));
        assert_eq!(fixture.op.writes(), writes);
    }
}
#[test]
fn ambiguous_creation_is_discovered_publicly_and_never_duplicated() {
    let fixture = Fixture::new();
    let store = fixture.store();
    fixture.op.failure.set(Failure::AfterWrite);
    assert!(store.add_avax_node(&node()).is_err());
    fixture.op.failure.set(Failure::None);
    assert_eq!(store.avax_nodes().unwrap().len(), 1);
    let writes = fixture.op.writes();
    assert!(store.add_avax_node(&node()).is_err());
    assert_eq!(fixture.op.writes(), writes);
    assert_eq!(fixture.op.snapshots(), 0);
}

#[test]
fn unavailable_snapshot_is_never_treated_as_an_absent_backup() {
    for with_backup in [false, true] {
        let fixture = Fixture::new();
        let store = fixture.store();
        let mut pinned = fixture.pinned();
        if with_backup {
            pinned = store
                .backup_avax_identity(&pinned, &SecretString::from(SECRET))
                .unwrap();
        }
        fixture.op.failure.set(Failure::SnapshotUnavailable);
        let writes = fixture.op.writes();
        assert!(store.update_avax_node(&pinned).is_err());
        assert_eq!(fixture.op.writes(), writes);
        assert_eq!(
            fixture.op.stored_backup().as_deref(),
            if with_backup { Some(SECRET) } else { None }
        );
    }
}
#[test]
fn null_optional_metadata_is_not_an_unknown_attachment_or_section() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let node = fixture.pinned();
    {
        let mut item = fixture.op.item.borrow_mut();
        let item = item.as_mut().unwrap();
        for name in ["sections", "files", "urls"] {
            item[name] = Value::Null;
        }
    }
    assert!(store.update_avax_node(&node).is_ok());
}
