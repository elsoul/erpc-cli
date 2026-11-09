// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::inventory::{Scope, fields_as_op_prints, solana_listing::Backend};
use erpc_auth::store::{StoreError, one_password::OpOutput};
use erpc_chain_solana_native::{
    contract::{Contract, Volumes, host_binding},
    migration::{OriginalAccount, OriginalBuild},
    migration_request::{Highest, History, Role},
};
use std::cell::{Cell, RefCell};

struct Provider {
    items: RefCell<Vec<Value>>,
    calls: RefCell<Vec<Vec<String>>>,
    ambiguous_create: Cell<bool>,
    creates: Cell<usize>,
    edits: Cell<usize>,
    ambiguous_edit: Cell<bool>,
    corrupt_edit: Cell<bool>,
}
impl Provider {
    fn project(&self, id: &str, vault: &str, selector: &str) -> Value {
        assert_eq!(vault, "v".repeat(26));
        let labels = selector
            .split(',')
            .map(|label| label.strip_prefix("label=").unwrap())
            .collect::<Vec<_>>();
        assert!(
            labels
                .iter()
                .all(|label| !label.ends_with("_ref") && !label.contains("password"))
        );
        let items = self.items.borrow();
        let item = items.iter().find(|item| item["id"] == id).unwrap();
        fields_as_op_prints(
            item["fields"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|field| labels.contains(&field["label"].as_str().unwrap()))
                .cloned()
                .collect(),
        )
    }

    fn create(&self, input: &str) -> (Value, bool) {
        let mut item: Value = serde_json::from_str(input).unwrap();
        assert_eq!(item["title"], "erpc mainnet fixture native-migration");
        assert!(
            item["fields"]
                .as_array()
                .unwrap()
                .iter()
                .all(|field| field["type"] == "STRING")
        );
        item["id"] = json!("b".repeat(26));
        item["version"] = json!(1);
        item["vault"] = json!({"id":"v".repeat(26)});
        self.items.borrow_mut().push(item.clone());
        self.creates.set(self.creates.get() + 1);
        if self.ambiguous_create.replace(false) {
            (json!({"private":"INERT_PRIVATE_MARKER"}), false)
        } else {
            (item, true)
        }
    }

    fn edit(&self, id: &str, vault: &str, input: &str) -> (Value, bool) {
        assert_eq!(id, "b".repeat(26));
        assert_eq!(vault, "v".repeat(26));
        let mut edited: Value = serde_json::from_str(input).unwrap();
        let mut items = self.items.borrow_mut();
        let item = items.iter_mut().find(|item| item["id"] == id).unwrap();
        assert_eq!(edited["version"], item["version"]);
        edited["version"] = json!(item["version"].as_u64().unwrap() + 1);
        if self.corrupt_edit.replace(false) {
            edited["fields"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|field| field["label"] == "migration_identity")
                .unwrap()["value"] = json!("INERT_CHANGED_PRIVATE");
        }
        *item = edited.clone();
        self.edits.set(self.edits.get() + 1);
        if self.ambiguous_edit.replace(false) {
            (json!({"private":"INERT_PRIVATE_MARKER"}), false)
        } else {
            (edited, true)
        }
    }
}
impl OpRunner for &Provider {
    fn run(&self, args: &[&str], input: Option<&str>) -> Result<OpOutput, StoreError> {
        self.calls
            .borrow_mut()
            .push(args.iter().map(|v| (*v).into()).collect());
        let mut success = true;
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
                assert!(input.is_none());
                Value::Array(
                    self.items
                        .borrow()
                        .iter()
                        .filter(|item| item["tags"].as_array().unwrap().contains(&json!(tag)))
                        .map(|item| {
                            let mut value = item.clone();
                            value.as_object_mut().unwrap().remove("fields");
                            value
                        })
                        .collect(),
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
                assert!(input.is_none());
                self.project(id, vault, selector)
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
                let (item, ok) = self.create(input.unwrap());
                success = ok;
                item
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
                assert!(input.is_none());
                assert_eq!(*id, "b".repeat(26));
                assert_eq!(*vault, "v".repeat(26));
                self.items
                    .borrow()
                    .iter()
                    .find(|item| item["id"] == *id)
                    .unwrap()
                    .clone()
            }
            ["item", "edit", id, "--vault", vault, "--format", "json"] => {
                let (edited, ok) = self.edit(id, vault, input.unwrap());
                success = ok;
                edited
            }
            _ => panic!("unprojected or unexpected mutation in pending migration fixture"),
        };
        Ok(OpOutput {
            success,
            stdout: value.to_string(),
            stderr: "INERT_PRIVATE_MARKER".into(),
        })
    }
}
fn host_identity(identity: &str) -> erpc_chain_solana_native::migration_request::HostIdentity {
    erpc_chain_solana_native::migration_request::HostIdentity {
        role: "rpc".into(),
        path: "/home/solv/rpc-identity.json".into(),
        uid: 1001,
        gid: 1001,
        inode: 123,
        bytes: 240,
        mtime_ns: 1,
        public: identity.into(),
        bls_public: "2".repeat(66),
    }
}

fn candidate() -> (Pending, Provider) {
    let identity = "2".repeat(44);
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/";
    let origins: Value = serde_json::from_slice(
        erpc_chain_solana_native::file("node/migration-sources.json").unwrap(),
    )
    .unwrap();
    let profile: BTreeMap<String, String> =
        serde_json::from_value(origins["sources"]["mainnet"][0].clone()).unwrap();
    let mut fields = BTreeMap::new();
    for (name, value) in [
        ("erpc_format", FORMAT),
        ("name", "fixture"),
        ("address", "192.0.2.10"),
        ("ssh_user", "solv"),
        ("ssh_port", "22"),
        ("host_key", key),
        ("client", "agave"),
        ("rpc_type", "send-tx"),
        ("version", profile["version"].as_str()),
        ("commit", profile["commit"].as_str()),
        ("identity_account", identity.as_str()),
        ("geyser_version", ""),
        ("geyser_commit", ""),
        ("of1_version", ""),
        ("of1_sha256", ""),
        ("region", ""),
        ("rpc_allow", ""),
        ("management_allow", ""),
        ("monitoring_allow", ""),
    ] {
        fields.insert(name.into(), value.into());
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
    let historical = OriginalAccount::from_sources(
        b"root:x:0:0::/root:/bin/bash\nsolv:x:1001:1001::/home/solv:/bin/bash\n",
        b"root:x:0:\nsolv:x:1001:\n",
        b"11111111111111111111111111111111\n",
    )
    .unwrap();
    let build=OriginalBuild::from_record(json!({"schema":1,"client":"agave","network":"mainnet","source":profile,"executable_sha256":"c".repeat(64),"executable_bytes":1234}).to_string().as_bytes(),"mainnet").unwrap();
    let volumes = Volumes {
        accounts: "10000000-0000-0000-0000-000000000001".into(),
        ledger: "10000000-0000-0000-0000-000000000002".into(),
        snapshots: "10000000-0000-0000-0000-000000000003".into(),
    };
    let mut original = Original {
        network: "mainnet".into(),
        role: Role::Rpc,
        identity_account: identity.clone(),
        vote_account: None,
        historical,
        management_user: "operator".into(),
        host_identity: host_identity(&identity),
        commission: None,
        source_sha256: String::new(),
        settings_sha256: "db8624b041fc51d22e4bf5e144bcc1e21d46ea5e1a4efbe739306cff9dc7f743".into(),
        source_history: History {
            document_sha256: "d".repeat(64),
            highest: Highest {
                version: profile["version"].clone(),
                commit: profile["commit"].clone(),
            },
        },
        keygen_evidence: build.clone(),
        artifact_evidence: build,
        target_volumes: volumes.clone(),
    };
    original.source_sha256 = source_binding(&source, &original).unwrap();
    let node = NativeHost {
        item_version: 0,
        address: "192.0.2.10".into(),
        ssh_user: "operator".into(),
        ssh_port: 22,
        host_key: key.into(),
        contract: Contract {
            schema: 1,
            profile: "agave-native-rpc".into(),
            inventory_id: String::new(),
            name: "fixture".into(),
            network: "mainnet".into(),
            host_binding: host_binding("192.0.2.10", "operator", 22, key),
            identity_account: identity,
            vote_account: None,
            authority_account: None,
            volumes,
        },
    };
    let pending = Pending::new(&source, original, node, "e".repeat(32), None).unwrap();
    (pending, provider(&record))
}
fn provider(record: &PublicRecord) -> Provider {
    let mut fields = record
        .fields
        .iter()
        .map(|(label, value)| json!({"id":label,"label":label,"type":"STRING","value":value}))
        .collect::<Vec<_>>();
    fields.push(json!({"id":"solv_password","label":"solv_password","type":"CONCEALED","value":"INERT_PRIVATE_MARKER"}));
    let item = json!({"id":record.item_id,"version":1,"title":"erpc mainnet fixture solana-rpc","category":"SECURE_NOTE","vault":{"id":"v".repeat(26)},"tags":["erpc","erpc/solana/mainnet/rpc"],"fields":fields});
    Provider {
        items: RefCell::new(vec![item]),
        calls: RefCell::new(Vec::new()),
        ambiguous_create: Cell::new(false),
        creates: Cell::new(0),
        edits: Cell::new(0),
        ambiguous_edit: Cell::new(false),
        corrupt_edit: Cell::new(false),
    }
}
fn store<'a>(provider: &'a Provider, directory: &std::path::Path) -> Store<&'a Provider> {
    Store::new(
        provider,
        "inventory",
        Scope {
            chain: "solana".into(),
            network: "mainnet".into(),
        },
        directory.join("inventory.lock"),
    )
}
#[test]
fn reservation_retains_original_metadata_and_fences_both_backends_without_private_reads() {
    let (candidate, provider) = candidate();
    let temporary = tempfile::tempdir().unwrap();
    let store = store(&provider, temporary.path());
    let original = provider.items.borrow()[0].clone();
    assert_eq!(
        store.solana_backend("fixture", true).unwrap(),
        Backend::Solv
    );
    assert!(candidate.request(Action::MigrationRetire).is_err());
    let reserved = store.reserve_solana_migration(&candidate).unwrap();
    assert_eq!(reserved.node.contract.inventory_id, "b".repeat(26));
    assert_eq!(
        reserved.request(Action::MigrationRetire).unwrap().contract,
        reserved.node.contract
    );
    assert_eq!(
        store.solana_backend("fixture", true).unwrap(),
        Backend::Migration
    );
    assert!(store.solana_backend("fixture", false).is_err());
    assert!(store.solana_native_hosts().unwrap().is_empty());
    assert!(store.add_solana_native_host(&candidate.node).is_err());
    let rows = store.solana_node_summaries(true).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["backend"], "migration");
    assert_eq!(rows[0]["ready"], Value::Null);
    assert_eq!(rows[0]["migration_complete"], false);
    assert!(!rows[0].to_string().contains("INERT_PRIVATE_MARKER"));
    assert_eq!(provider.items.borrow()[0], original);
    store.verify_solana_pending_migration(&reserved).unwrap();
}
#[test]
fn ambiguous_create_reuses_the_original_item_and_intent_without_a_second_write() {
    let (mut candidate, provider) = candidate();
    let temporary = tempfile::tempdir().unwrap();
    let store = store(&provider, temporary.path());
    provider.ambiguous_create.set(true);
    assert!(
        !store
            .reserve_solana_migration(&candidate)
            .unwrap_err()
            .to_string()
            .contains("INERT_PRIVATE_MARKER")
    );
    let original_intent = candidate.intent.clone();
    candidate.intent = "f".repeat(32);
    let resumed = store.reserve_solana_migration(&candidate).unwrap();
    assert_eq!(resumed.intent, original_intent);
    assert_eq!(provider.creates.get(), 1);
    assert_eq!(resumed.node.contract.inventory_id, "b".repeat(26));
}
#[test]
fn original_edits_and_concealed_or_changed_reservations_refuse_before_host_requests() {
    let (candidate, provider) = candidate();
    let temporary = tempfile::tempdir().unwrap();
    let store = store(&provider, temporary.path());
    let reserved = store.reserve_solana_migration(&candidate).unwrap();
    provider.items.borrow_mut()[0]["version"] = json!(2);
    assert!(store.verify_solana_pending_migration(&reserved).is_err());
    provider.items.borrow_mut()[0]["version"] = json!(1);
    let mut items = provider.items.borrow_mut();
    let field = items[1]["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|v| v["label"] == "native_migration")
        .unwrap();
    field["type"] = json!("CONCEALED");
    field["value"] = json!("INERT_PRIVATE_MARKER");
    drop(items);
    assert!(
        !store
            .solana_pending_migration("fixture")
            .unwrap_err()
            .to_string()
            .contains("INERT_PRIVATE_MARKER")
    );
    assert!(store.solana_backend("fixture", true).is_err());
}

#[test]
fn public_logical_registration_collisions_refuse_before_creating_or_resuming_migration() {
    for logical_name in ["fixture", "other"] {
        let (candidate, provider) = candidate();
        let temporary = tempfile::tempdir().unwrap();
        let store = store(&provider, temporary.path());
        let logical = json!({"id":"z".repeat(26),"version":1,"title":format!("erpc mainnet {logical_name} validator"),
            "category":"SECURE_NOTE","vault":{"id":"v".repeat(26)},"tags":["erpc","erpc/solana/mainnet/validator"],
            "fields":[{"id":"erpc_format","label":"erpc_format","type":"STRING","value":FORMAT},
                {"id":"name","label":"name","type":"STRING","value":logical_name},
                {"id":"identity_account","label":"identity_account","type":"STRING","value":candidate.node.contract.identity_account}]});
        provider.items.borrow_mut().push(logical.clone());
        assert!(store.reserve_solana_migration(&candidate).is_err());
        assert_eq!(provider.creates.get(), 0);
        provider.items.borrow_mut().pop();
        let reserved = store.reserve_solana_migration(&candidate).unwrap();
        provider.items.borrow_mut().push(logical);
        assert!(store.verify_solana_pending_migration(&reserved).is_err());
    }
}

#[test]
fn a_host_key_recorded_as_another_vote_or_withdrawal_authority_never_reaches_export() {
    for label in ["vote_account", "authority_account"] {
        let (candidate, provider) = candidate();
        let temporary = tempfile::tempdir().unwrap();
        let store = store(&provider, temporary.path());
        let mut fields = vec![
            json!({"id":"erpc_format","label":"erpc_format","type":"STRING","value":FORMAT}),
            json!({"id":"name","label":"name","type":"STRING","value":"other"}),
        ];
        for field in ["identity_account", "vote_account", "authority_account"] {
            fields.push(json!({"id":field,"label":field,"type":"STRING","value":if field==label {candidate.original.host_identity.public.clone()}else{"8".repeat(44)}}));
        }
        let record = json!({"id":"z".repeat(26),"version":1,"title":"erpc mainnet other validator",
            "category":"SECURE_NOTE","vault":{"id":"v".repeat(26)},"tags":["erpc","erpc/solana/mainnet/validator"],"fields":fields});
        provider.items.borrow_mut().push(record.clone());
        assert!(store.reserve_solana_migration(&candidate).is_err());
        assert_eq!(provider.creates.get(), 0);
        provider.items.borrow_mut().pop();
        let reserved = store.reserve_solana_migration(&candidate).unwrap();
        provider.items.borrow_mut().push(record);
        assert!(store.verify_solana_pending_migration(&reserved).is_err());
        assert_eq!(provider.creates.get(), 1);
    }
}

#[test]
fn another_legacy_host_or_rpc_cannot_share_the_selected_physical_server() {
    for kind in ["host", "rpc"] {
        for same_address in [false, true] {
            let (candidate, provider) = candidate();
            let temporary = tempfile::tempdir().unwrap();
            let store = store(&provider, temporary.path());
            let suffix = if kind == "rpc" { "solana-rpc" } else { "host" };
            let key = if same_address {
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
            } else {
                candidate.node.host_key.as_str()
            };
            assert!(erpc_ssh::HostKey::parse(key).is_ok());
            let duplicate = json!({"id":"z".repeat(26),"version":1,"title":format!("erpc mainnet alias {suffix}"),
                "category":"SECURE_NOTE","vault":{"id":"v".repeat(26)},"tags":["erpc",format!("erpc/solana/mainnet/{kind}")],
                "fields":[{"id":"erpc_format","label":"erpc_format","type":"STRING","value":FORMAT},
                    {"id":"name","label":"name","type":"STRING","value":"alias"},
                    {"id":"address","label":"address","type":"STRING","value":if same_address{"192.0.2.10"}else{"192.0.2.11"}},
                    {"id":"host_key","label":"host_key","type":"STRING","value":key},
                    {"id":"solv_password","label":"solv_password","type":"CONCEALED","value":"INERT_PRIVATE_MARKER"}]});
            provider.items.borrow_mut().push(duplicate.clone());
            assert!(store.reserve_solana_migration(&candidate).is_err());
            assert_eq!(provider.creates.get(), 0);
            provider.items.borrow_mut().pop();
            let reserved = store.reserve_solana_migration(&candidate).unwrap();
            provider.items.borrow_mut().push(duplicate);
            assert!(store.verify_solana_pending_migration(&reserved).is_err());
        }
    }
}

#[test]
fn same_item_original_backup_preserves_unknown_fields_and_refreshes_version() {
    for ambiguous in [false, true] {
        let (candidate, provider) = candidate();
        let temporary = tempfile::tempdir().unwrap();
        let store = store(&provider, temporary.path());
        store.reserve_solana_migration(&candidate).unwrap();
        let legacy = provider.items.borrow()[0].clone();
        {
            let mut items = provider.items.borrow_mut();
            let item = &mut items[1];
            item["version"] = json!(2);
            item["tags"]
                .as_array_mut()
                .unwrap()
                .push(json!("user-kept-tag"));
            item["fields"].as_array_mut().unwrap().push(json!({"id":"notesPlain","label":"notesPlain","type":"STRING","purpose":"NOTES","value":"INERT_UNKNOWN_NOTES"}));
            item["fields"].as_array_mut().unwrap().push(json!({"id":"other","label":"other","type":"CONCEALED","value":"INERT_UNKNOWN_PRIVATE","entropy":118.283_493_041_992_19}));
            item["favorite"] = json!(true);
        }
        let record = store.solana_pending_migration("fixture").unwrap();
        provider.ambiguous_edit.set(ambiguous);
        let key: SecretString = "INERT_CANONICAL_PRIVATE".into();
        let stored = store
            .backup_solana_migration_identity(&record, &key)
            .unwrap();
        assert_eq!(stored.key.expose_secret(), key.expose_secret());
        assert_eq!(stored.pending.node.item_version, 3);
        assert_eq!(
            stored.pending.node.contract.inventory_id,
            record.node.contract.inventory_id
        );
        assert_eq!(
            stored.reference,
            format!(
                "op://{}/{}/migration_identity",
                "v".repeat(26),
                "b".repeat(26)
            )
        );
        assert!(!format!("{stored:?}").contains("INERT"));
        assert!(store.verify_solana_pending_migration(&record).is_err());
        store
            .verify_solana_pending_migration(&stored.pending)
            .unwrap();
        let again = store
            .backup_solana_migration_identity(&stored.pending, &key)
            .unwrap();
        assert_eq!(again.pending, stored.pending);
        assert_eq!(provider.edits.get(), 1);
        assert_eq!(provider.creates.get(), 1);
        let items = provider.items.borrow();
        assert_eq!(items[0], legacy);
        let item = &items[1];
        assert!(
            item["tags"]
                .as_array()
                .unwrap()
                .contains(&json!("user-kept-tag"))
        );
        assert_eq!(item["favorite"], true);
        for (label, value) in [
            ("notesPlain", "INERT_UNKNOWN_NOTES"),
            ("other", "INERT_UNKNOWN_PRIVATE"),
        ] {
            assert_eq!(
                item["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|field| field["label"] == label)
                    .unwrap()["value"],
                value
            );
        }
        assert!(
            provider
                .calls
                .borrow()
                .iter()
                .flatten()
                .all(|argument| !argument.contains("INERT"))
        );
    }
}

#[test]
fn malformed_or_changed_private_readback_is_not_overwritten_or_reported_as_success() {
    let (candidate, provider) = candidate();
    let temporary = tempfile::tempdir().unwrap();
    let store = store(&provider, temporary.path());
    let record = store.reserve_solana_migration(&candidate).unwrap();
    let key: SecretString = "INERT_CANONICAL_PRIVATE".into();
    provider.corrupt_edit.set(true);
    let error = store
        .backup_solana_migration_identity(&record, &key)
        .unwrap_err();
    assert!(!error.to_string().contains("INERT"));
    assert_eq!(provider.edits.get(), 1);
    let refreshed = store.solana_pending_migration("fixture").unwrap();
    assert!(
        store
            .backup_solana_migration_identity(&refreshed, &key)
            .is_err()
    );
    assert_eq!(provider.edits.get(), 1);
    assert!(store.solana_migration_backup(&refreshed).is_err());
}

#[test]
fn native_promotion_keeps_the_same_key_item_and_reconciles_only_exact_originals() {
    for ambiguous in [false, true] {
        let (candidate, provider) = candidate();
        let temporary = tempfile::tempdir().unwrap();
        let store = store(&provider, temporary.path());
        let reserved = store.reserve_solana_migration(&candidate).unwrap();
        let original = provider.items.borrow()[0].clone();
        let key: SecretString = "INERT_CANONICAL_PRIVATE".into();
        let backup = store
            .backup_solana_migration_identity(&reserved, &key)
            .unwrap();
        let prepared = store
            .prepare_solana_migration_promotion(&backup.pending)
            .unwrap();
        assert_eq!(prepared.receipt.reserved_version, 2);
        provider.ambiguous_edit.set(ambiguous);
        let promoted = store.promote_solana_migration(&prepared).unwrap();
        assert_eq!(
            promoted.pending.node.contract.inventory_id,
            reserved.node.contract.inventory_id
        );
        assert_eq!(promoted.pending.node.item_version, 3);
        assert_eq!(
            store.solana_backend("fixture", true).unwrap(),
            super::super::solana_listing::Backend::Native
        );
        let rows = store.solana_node_summaries(true).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["backend"], "native");
        assert_eq!(provider.items.borrow()[0], original);
        assert!(store.solana_pending_migrations().unwrap().is_empty());
        assert_eq!(
            store.solana_original_migration("fixture").unwrap(),
            promoted.pending
        );
        assert!(
            store
                .solana_migration_source("fixture", true, "fixture")
                .is_err()
        );
        store
            .verify_solana_original_migration(&promoted.pending)
            .unwrap();
        assert_eq!(
            store
                .solana_migration_backup(&promoted.pending)
                .unwrap()
                .unwrap()
                .key
                .expose_secret(),
            key.expose_secret()
        );
        let repeated = store.promote_solana_migration(&promoted).unwrap();
        assert_eq!(repeated.receipt, prepared.receipt);
        assert_eq!(provider.edits.get(), 2);
        assert_eq!(provider.creates.get(), 1);
        let mut config = promoted.configuration.clone();
        config.management_allow = vec!["198.51.100.7/32".into()];
        let updated = store
            .update_solana_native_config(&promoted.pending.node, &config)
            .unwrap();
        let record = store.solana_original_migration("fixture").unwrap();
        assert_eq!(record.node, updated);
        assert_eq!(
            store
                .solana_migration_backup(&record)
                .unwrap()
                .unwrap()
                .key
                .expose_secret(),
            key.expose_secret()
        );
        assert_eq!(
            store.solana_migration_cutover(&record).unwrap(),
            Some(prepared.receipt)
        );
        assert!(
            store.prepare_solana_migration_promotion(&record).is_err(),
            "completion must not roll back a later access policy"
        );
        provider.items.borrow_mut()[0]["version"] = json!(2);
        assert!(store.verify_solana_original_migration(&record).is_err());
        assert!(store.solana_backend("fixture", true).is_err());
        assert!(store.solana_node_summaries(true).is_err());
    }
}

#[test]
fn original_network_scopes_are_canonicalized_without_widening_or_public_access_bypass() {
    assert_eq!(
        original_networks("203.0.113.7,198.51.100.7/24,203.0.113.7").unwrap(),
        ["198.51.100.0/24", "203.0.113.7/32"]
    );
    let (mut candidate, _) = candidate();
    candidate
        .source
        .node
        .fields
        .insert("rpc_allow".into(), "0.0.0.0/0".into());
    // What the reservation holds came from 1Password, so a value the native
    // rules refuse is reported as that reply, like every other check of it.
    assert_eq!(
        candidate
            .configuration(&format!(
                "op://{}/{}/migration_identity",
                "v".repeat(26),
                "b".repeat(26)
            ))
            .unwrap_err()
            .to_string(),
        "1Password's reply to public Solana migration reservation could not be read"
    );
}
