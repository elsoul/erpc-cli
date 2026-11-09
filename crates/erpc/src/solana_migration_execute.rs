// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Explicit public Solv retirement/copy orchestration with a durable original intent.
use crate::{
    commands::Outcome,
    error::CliError,
    node_common::{self, Say},
    solana_migration as planning,
    solana_native::{self, one},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{
    Store,
    solana_migration_pending::{CutoverReceipt, Pending},
    solana_native::NativeHost,
};
use erpc_chain_solana_native::{
    self as native,
    contract::{Contract, host_binding},
    migration_request::{Action, Original},
};
use erpc_ssh::{
    Session, Target,
    solana_native::{Command as Remote, Revision},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const PLAY: &str = "ansible/solana-native/migration.yml";
// Exact host wire record; independent observations are validated together below.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    intent: String,
    migration_reserved: bool,
    recorded_phase: String,
    helper_revision: Option<String>,
    copy_recorded_complete: bool,
    data_recorded_promoted: bool,
    migration_complete: bool,
    runtime_inspected: bool,
    ready: Option<bool>,
    cutover: Option<Cutover>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cutover {
    phase: String,
    receipt: CutoverReceipt,
    provider_version: Option<u64>,
}
impl Progress {
    fn checked(raw: Value, expected_intent: &str) -> Result<Self, String> {
        if raw
            .as_object()
            .is_none_or(|object| object.len() != 10 || !object.contains_key("ready"))
        {
            return Err("closed original migration progress required".into());
        }
        let value: Self =
            serde_json::from_value(raw).map_err(|_| "invalid original migration progress")?;
        let phase = value.recorded_phase.as_str();
        let copied = matches!(phase, "copied" | "promoting" | "finalizing" | "complete");
        let final_ack = value
            .cutover
            .as_ref()
            .is_some_and(|c| c.phase == "complete");
        if value.intent != expected_intent
            || value.runtime_inspected
            || value.ready.is_some()
            || ![
                "unreserved",
                "reserved",
                "masked",
                "retired",
                "copied",
                "promoting",
                "finalizing",
                "complete",
            ]
            .contains(&phase)
            || value.migration_reserved == (phase == "unreserved")
            || value.migration_complete != (phase == "complete")
            || value.copy_recorded_complete != copied
            || value.data_recorded_promoted && !copied
            || matches!(phase, "finalizing" | "complete")
                && (!value.data_recorded_promoted || !final_ack)
            || phase == "unreserved" && (value.helper_revision.is_some() || value.cutover.is_some())
            || value.helper_revision.as_ref().is_some_and(|v| {
                v.len() != 64
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || value.cutover.as_ref().is_some_and(|c| {
                !matches!(c.phase.as_str(), "prepared" | "complete")
                    || c.receipt.intent != expected_intent
                    || c.receipt.schema != 1
                    || c.receipt.reserved_version == 0
                    || !value.data_recorded_promoted
                    || (c.phase == "complete") != c.provider_version.is_some()
                    || c.provider_version
                        .is_some_and(|v| v <= c.receipt.reserved_version)
            })
        {
            return Err(
                "migration progress differs from the original intent; no runtime health is implied"
                    .into(),
            );
        }
        Ok(value)
    }
}
trait Operations {
    fn stage(&mut self, action: Action) -> Result<(), String>;
    fn confirm_manager(&mut self) -> Result<(), String>;
    fn progress(&mut self) -> Result<Progress, String>;
}
// Every resume reauthenticates the original reservation. A visible data receipt
// is not a complete source-floor handoff, so promotion is always reverified.
fn continue_copy(operations: &mut impl Operations) -> Result<Progress, String> {
    operations.stage(Action::MigrationReserve)?;
    let status = operations.progress()?;
    if !status.copy_recorded_complete {
        operations.stage(Action::MigrationRetire)?;
        operations.confirm_manager()?;
        operations.stage(Action::MigrationCopy)?;
    }
    operations.stage(Action::MigrationPromoteData)?;
    let status = operations.progress()?;
    if !status.copy_recorded_complete
        || !status.data_recorded_promoted
        || status.recorded_phase != "promoting"
    {
        return Err("original data promotion is incomplete; resume the same migration".into());
    }
    Ok(status)
}
struct Live<'a> {
    store: &'a Store<OpCli>,
    pending: Pending,
    target: Target,
    session: Session,
    say: Say,
}
impl Live<'_> {
    fn original(&self) -> Result<(), String> {
        self.store
            .verify_solana_original_migration(&self.pending)
            .map_err(|_| {
                "original migration inventory changed; retain its existing host state".into()
            })
    }
    fn sealed(&mut self, value: &Value) -> Result<(), String> {
        self.original()?;
        let built = solana_native::request_bundle(&self.pending.node, value)?;
        let run = erpc_ops::run::start(&self.session, &built, PLAY).map_err(|e| e.to_string())?;
        let result = node_common::follow(
            &self.target,
            &run,
            "Use migration status or resume for this original intent; retain original data and keys",
            &self.say,
        )?;
        self.original()?;
        if !result.ok() || result.play != PLAY {
            return Err("original migration stage did not finish; use status/resume without changing the intent".into());
        }
        Ok(())
    }
    fn direct(&self, action: Action) -> Result<Value, String> {
        self.original()?;
        let request = self.pending.request(action).map_err(|e| e.to_string())?;
        let value = solana_native::request(
            &self.session,
            if action == Action::MigrationStatus {
                Remote::MigrationStatus
            } else {
                Remote::Control(Revision::new(&native::helper_revision()?)?)
            },
            &serde_json::to_value(request)
                .map_err(|_| "cannot encode original migration request")?,
        )?;
        self.original()?;
        Ok(value)
    }
}
impl Operations for Live<'_> {
    fn stage(&mut self, action: Action) -> Result<(), String> {
        self.original()?;
        let request = self.pending.request(action).map_err(|e| e.to_string())?;
        if !request.requires_sealed_run() {
            return Err("migration stage requires its dedicated transport".into());
        }
        let value =
            serde_json::to_value(request).map_err(|_| "cannot encode original migration stage")?;
        self.sealed(&value)
    }
    fn confirm_manager(&mut self) -> Result<(), String> {
        // Reopen using the retained distinct management login after retirement.
        // The native direct controller verifies the actual SSH caller and UID.
        self.session = Session::open(&self.target).map_err(
            |_| "separate management login must work after original privilege retirement",
        )?;
        let value = self.direct(Action::MigrationConfirmManager)?;
        if value
            != json!({"manager_reauthenticated":true,"legacy_retired":true,"copy_authorized":false,"runtime_started":false})
        {
            return Err("original separate manager was not confirmed".into());
        }
        Ok(())
    }
    fn progress(&mut self) -> Result<Progress, String> {
        Progress::checked(self.direct(Action::MigrationStatus)?, &self.pending.intent)
    }
}
fn open(args: &ArgMatches) -> Result<Store<OpCli>, String> {
    let network = one(args, "network").ok_or("migration requires --network")?;
    if !matches!(network, "mainnet" | "testnet") {
        return Err("migration requires mainnet or testnet".into());
    }
    let vault = node_common::vault_for(
        network,
        one(args, "vault"),
        "pass the original network inventory vault",
    )?;
    node_common::store(&node_common::op_runner()?, &vault, "solana", network)
}
fn candidate(
    args: &ArgMatches,
    rpc: bool,
    store: &Store<OpCli>,
    settings: &crate::solana_migration_settings::Approved,
    host_identity: &Value,
    commission: &Value,
) -> Result<Pending, String> {
    let (source, historical, history) = planning::inputs(args, rpc)?;
    if source.hosts.len() != 1 {
        return Err("this copy migration requires one qualified original physical host; retain other Solv configurations".into());
    }
    let history = history.ok_or("original client history is required")?;
    let build = planning::original_build(args, &source.network, Some(&history))?
        .ok_or("independent original build evidence is required")?;
    let manager = one(args, "management-user").ok_or("a separate management login is required")?;
    let mut original = planning::inspection_request(&source, &historical, &history, manager)?;
    original["settings_sha256"] = json!(settings.digest);
    original["host_identity"] = host_identity.clone();
    original["commission"] = commission.clone();
    original["keygen_evidence"] =
        serde_json::to_value(planning::original_keygen(args, &source.network, &build)?)
            .map_err(|_| "cannot encode original keygen evidence")?;
    original["artifact_evidence"] =
        serde_json::to_value(build).map_err(|_| "cannot encode original build")?;
    original["target_volumes"] = serde_json::to_value(
        planning::copy_targets(args)?.ok_or("three separate target volumes are required")?,
    )
    .map_err(|_| "cannot encode original target volumes")?;
    let original: Original = serde_json::from_value(original)
        .map_err(|_| "invalid complete public migration evidence")?;
    let host = &source.hosts[0].fields;
    let address = host
        .get("address")
        .ok_or("original host address missing")?
        .clone();
    let key = host
        .get("host_key")
        .ok_or("original pinned host key missing")?
        .clone();
    let port = host
        .get("ssh_port")
        .and_then(|v| v.parse::<u16>().ok())
        .ok_or("original SSH port missing")?;
    let node = NativeHost {
        item_version: 0,
        address: address.clone(),
        ssh_user: manager.into(),
        ssh_port: port,
        host_key: key.clone(),
        contract: Contract {
            schema: 1,
            profile: if rpc {
                "agave-native-rpc"
            } else {
                "agave-native"
            }
            .into(),
            inventory_id: String::new(),
            name: one(args, "name").ok_or("migration requires --name")?.into(),
            network: source.network.clone(),
            host_binding: host_binding(&address, manager, port, &key),
            identity_account: original.identity_account.clone(),
            vote_account: original.vote_account.clone(),
            authority_account: if rpc {
                None
            } else {
                source.node.fields.get("authority_account").cloned()
            },
            volumes: original.target_volumes.clone(),
        },
    };
    // A public operation ID; no signer key or operational credential is generated.
    let nonce = erpc_ops::run::new_run_id().map_err(|e| e.to_string())?;
    let intent = format!("{:x}", Sha256::digest(nonce.as_str().as_bytes()))[..32].to_owned();
    let reference = store
        .resolve_solana_migration_identity(&source)
        .map_err(|e| e.to_string())?;
    Pending::new(&source, original, node, intent, reference).map_err(|e| e.to_string())
}
fn execute(action: &str, args: &ArgMatches, rpc: bool, json_out: bool) -> Result<Value, CliError> {
    let name = one(args, "name").ok_or("migration requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|_| "invalid migration name")?;
    let say = Say { quiet: json_out };
    let store = open(args)?;
    let pending = if action == "execute" {
        if store
            .solana_pending_migrations()
            .map_err(|e| e.to_string())?
            .iter()
            .any(|p| p.node.contract.name == name)
        {
            return Err("an original migration is already reserved; use migration resume with its saved scope".into());
        }
        let observed = planning::inspect_custody(args, rpc)?;
        let settings = crate::solana_migration_settings::inspect(
            &observed,
            rpc,
            one(args, "network").ok_or("migration requires --network")?,
        )?;
        let pending = candidate(
            args,
            rpc,
            &store,
            &settings,
            &observed["custody_source"],
            &observed["authority_observation"]["commission"],
        )?;
        if observed["source_sha256"] != pending.original.source_sha256
            || observed["inspection"]["original_build_evidence"]
                != serde_json::to_value(&pending.original.artifact_evidence)
                    .map_err(|_| "invalid original build scope")?
            || observed["inspection"]["original_keygen_evidence"]
                != serde_json::to_value(&pending.original.keygen_evidence)
                    .map_err(|_| "invalid original keygen scope")?
        {
            return Err("original source changed during inspection".into());
        }
        if !json_out || !solana_native::flag(args, "yes") {
            eprintln!(
                "Original migration settings and changes:\n{}",
                serde_json::to_string_pretty(&json!({"settings":settings.public,"host_only_identity":observed["custody_source"],"authority_observation":observed["authority_observation"]}))
                    .map_err(|_| "cannot display inspected settings")?
            );
        }
        solana_native::confirm(
            args,
            "migration retirement, retained-source copy and original host-only key backup were not confirmed",
        )?;
        store.reserve_solana_migration(&pending).map_err(|_| "migration reservation was not confirmed; inspect status before retrying or creating anything")?
    } else {
        let pending = store
            .solana_original_migration(name)
            .map_err(|e| e.to_string())?;
        if pending.node.contract.is_rpc() != rpc {
            return Err("migration role differs from its original reservation".into());
        }
        if action == "resume" {
            solana_native::confirm(args, "original migration resume was not confirmed")?;
        }
        pending
    };
    store
        .verify_solana_original_migration(&pending)
        .map_err(|e| e.to_string())?;
    let target = solana_native::target(&pending.node, args)?;
    let session = Session::open(&target)
        .map_err(|_| "original separate management session is unavailable")?;
    let mut operation = Live {
        store: &store,
        pending,
        target,
        session,
        say,
    };
    let progress = if action == "status" {
        operation.progress()?
    } else {
        operation.complete()?
    };
    let mut selection = operation.pending.summary();
    selection["migration_complete"] = json!(progress.migration_complete);
    if progress.migration_complete {
        selection["backend"] = json!("native");
    }
    Ok(
        json!({"selection":selection,"migration_complete":progress.migration_complete,"progress":progress,
        "runtime_started":false,"next_step":if progress.migration_complete {"explicit native deployment and observation; voting activation remains separate"} else {"resume the same original migration"}}),
    )
}
pub(crate) fn run(action: &str, args: &ArgMatches, rpc: bool, json_out: bool) -> Outcome {
    // As a native verb's: a refused confirmation keeps its code.
    solana_native::outcome(execute(action, args, rpc, json_out), json_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Model {
        calls: Vec<String>,
        copied: bool,
        promoted: bool,
        fail: Option<Action>,
    }
    impl Operations for Model {
        fn stage(&mut self, action: Action) -> Result<(), String> {
            self.calls.push(
                serde_json::to_value(action)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .into(),
            );
            if self.fail == Some(action) {
                return Err("interrupted original stage".into());
            }
            if action == Action::MigrationCopy {
                self.copied = true;
            }
            if action == Action::MigrationPromoteData {
                self.promoted = true;
            }
            Ok(())
        }
        fn confirm_manager(&mut self) -> Result<(), String> {
            self.calls.push("fresh-manager".into());
            Ok(())
        }
        fn progress(&mut self) -> Result<Progress, String> {
            self.calls.push("status".into());
            Ok(Progress {
                intent: "a".repeat(32),
                migration_reserved: true,
                recorded_phase: if self.promoted {
                    "promoting"
                } else if self.copied {
                    "copied"
                } else {
                    "reserved"
                }
                .into(),
                helper_revision: Some("b".repeat(64)),
                copy_recorded_complete: self.copied,
                data_recorded_promoted: self.promoted,
                migration_complete: false,
                runtime_inspected: false,
                ready: None,
                cutover: None,
            })
        }
    }
    #[test]
    fn progress_is_bound_to_the_original_intent_and_never_substitutes_runtime_health() {
        let original = json!({"intent":"a".repeat(32),"migration_reserved":true,"recorded_phase":"reserved",
            "helper_revision":native::helper_revision().unwrap(),"copy_recorded_complete":false,"data_recorded_promoted":false,
            "migration_complete":false,"runtime_inspected":false,"ready":null,"cutover":null});
        assert!(Progress::checked(original.clone(), &"a".repeat(32)).is_ok());
        for (field, value) in [
            ("intent", json!("b".repeat(32))),
            ("helper_revision", json!("invalid")),
            ("migration_complete", json!(true)),
            ("runtime_inspected", json!(true)),
            ("ready", json!(true)),
            ("data_recorded_promoted", json!(true)),
            ("recorded_phase", json!("complete")),
            ("migration_reserved", json!(1)),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(
                Progress::checked(changed, &"a".repeat(32)).is_err(),
                "{field}"
            );
        }
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove("ready");
        assert!(Progress::checked(missing, &"a".repeat(32)).is_err());
        let mut private = original;
        private["private_key"] = json!("INERT_PRIVATE_MARKER");
        assert!(
            !Progress::checked(private, &"a".repeat(32))
                .unwrap_err()
                .contains("INERT_PRIVATE_MARKER")
        );
    }
    #[test]
    fn interrupted_stage_does_not_advance_and_copy_receipt_never_skips_promotion_verification() {
        for failed in [
            Action::MigrationReserve,
            Action::MigrationRetire,
            Action::MigrationCopy,
            Action::MigrationPromoteData,
        ] {
            let mut model = Model {
                calls: vec![],
                copied: false,
                promoted: false,
                fail: Some(failed),
            };
            assert!(continue_copy(&mut model).is_err());
            assert_eq!(
                model.calls.last().unwrap(),
                serde_json::to_value(failed).unwrap().as_str().unwrap()
            );
            model.fail = None;
            model.calls.clear();
            let result = continue_copy(&mut model).unwrap();
            assert!(result.data_recorded_promoted);
            assert!(!result.migration_complete);
            assert!(model.calls.contains(&"migration-promote-data".into()));
        }
        for promoted in [false, true] {
            let mut model = Model {
                calls: vec![],
                copied: true,
                promoted,
                fail: None,
            };
            continue_copy(&mut model).unwrap();
            assert_eq!(
                model.calls,
                [
                    "migration-reserve",
                    "status",
                    "migration-promote-data",
                    "status"
                ]
            );
        }
        let mut model = Model {
            calls: vec![],
            copied: false,
            promoted: false,
            fail: None,
        };
        continue_copy(&mut model).unwrap();
        assert_eq!(
            model.calls,
            [
                "migration-reserve",
                "status",
                "migration-retire",
                "fresh-manager",
                "migration-copy",
                "migration-promote-data",
                "status"
            ]
        );
    }
    #[test]
    fn migration_execution_requires_original_evidence_but_resume_keeps_the_stored_scope() {
        let command = planning::command();
        for action in ["execute", "resume", "status"] {
            assert!(
                command
                    .clone()
                    .try_get_matches_from(["migration", action])
                    .is_err()
            );
        }
        for action in ["resume", "status"] {
            command
                .clone()
                .try_get_matches_from(["migration", action, "--ssh-key", "operator.pub"])
                .unwrap();
            assert!(
                command
                    .clone()
                    .try_get_matches_from([
                        "migration",
                        action,
                        "--ssh-key",
                        "operator.pub",
                        "--management-user",
                        "other"
                    ])
                    .is_err()
            );
        }
    }
}

#[cfg(all(test, unix))]
#[path = "solana_migration_bundle_tests.rs"]
mod bundle_tests;

#[path = "solana_migration_complete.rs"]
mod completion;

#[cfg(test)]
#[cfg(unix)]
#[path = "solana_migration_resume_tests.rs"]
mod resume_tests;
