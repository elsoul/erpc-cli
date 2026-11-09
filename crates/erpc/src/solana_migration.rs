// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Explicit legacy inspection and migration commands; no automatic backend replacement.
use crate::{commands::Outcome, node_common, solana_native::one};
use clap::{Arg, ArgMatches, Command};
use erpc_chain::inventory::solana_migration::LegacySource;
use erpc_chain_solana_native::{
    self as native,
    migration::{OriginalAccount, OriginalBuild},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
};

pub(crate) fn command() -> Command {
    let mut plan = Command::new("plan")
        .about("Inspect public legacy inventory and historical ownership evidence without contacting or modifying a node")
        .arg(Arg::new("host-name").long("host-name").help("Exact physical validator host; required for validators, including single-host registrations"))
        .arg(Arg::new("vault").long("vault").help("Original network inventory vault identifier"));
    for (id, help) in [
        (
            "original-passwd",
            "Independent public passwd backup from the original host",
        ),
        (
            "original-group",
            "Independent public group backup from the original host",
        ),
        (
            "original-machine-id",
            "Independent original machine-id backup; not the live observer's identity",
        ),
    ] {
        plan = plan.arg(
            Arg::new(id)
                .long(id)
                .required(true)
                .value_parser(clap::value_parser!(PathBuf))
                .help(help),
        );
    }
    plan = plan.arg(Arg::new("original-client-record").long("original-client-record")
        .value_parser(clap::value_parser!(PathBuf))
        .help("Independent public highest-used Agave version/commit history; required for host inspection"));
    plan=plan.arg(Arg::new("original-build-record").long("original-build-record")
        .value_parser(clap::value_parser!(PathBuf)).requires("original-client-record")
        .help("Independent original Agave build/artifact record; matches qualified source/compiler and exact executable bytes, never inferred from a live hash"));
    plan=plan.arg(Arg::new("original-keygen-record").long("original-keygen-record")
        .value_parser(clap::value_parser!(PathBuf)).requires("original-build-record")
        .help("Independent same-source solana-keygen artifact SHA/size record for original BLS authority exclusion"));
    let mut inspect = plan.clone().name("inspect")
        .mut_arg("original-client-record", |arg| arg.required(true))
        .about("Read public ownership and startup configuration through a separate management login; leave the existing service running")
        .arg(Arg::new("management-user").long("management-user").required(true))
        .arg(Arg::new("ssh-key").long("ssh-key").required(true).value_parser(clap::value_parser!(PathBuf)))
        .arg(Arg::new("ssh-agent").long("ssh-agent").value_parser(clap::value_parser!(PathBuf)));
    for id in [
        "target-accounts-uuid",
        "target-ledger-uuid",
        "target-snapshots-uuid",
    ] {
        inspect = inspect.arg(Arg::new(id).long(id)
            .requires_all(["target-accounts-uuid", "target-ledger-uuid", "target-snapshots-uuid"].into_iter().filter(|other| *other != id))
            .help("Optional copy preflight: UUID of an empty, separately provisioned native data volume; supply all three"));
    }
    let execute = inspect
        .clone()
        .name("execute")
        .about("Reserve and run verified original service retirement and copy to separate volumes")
        .mut_arg("original-build-record", |arg| arg.required(true))
        .mut_arg("original-keygen-record", |arg| arg.required(true))
        .mut_arg("target-accounts-uuid", |arg| arg.required(true))
        .mut_arg("target-ledger-uuid", |arg| arg.required(true))
        .mut_arg("target-snapshots-uuid", |arg| arg.required(true))
        .arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(clap::ArgAction::SetTrue),
        );
    let status = Command::new("status")
        .about("Read original pending migration records without asserting runtime health")
        .arg(Arg::new("vault").long("vault"))
        .arg(
            Arg::new("ssh-key")
                .long("ssh-key")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("ssh-agent")
                .long("ssh-agent")
                .value_parser(clap::value_parser!(PathBuf)),
        );
    let resume = status
        .clone()
        .name("resume")
        .about("Resume the same original migration intent; never create another owner or key")
        .arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(clap::ArgAction::SetTrue),
        );
    Command::new("migration")
        .about("Inspect and explicitly migrate original Solv hosts")
        .subcommand_required(true)
        .subcommand(plan)
        .subcommand(inspect)
        .subcommand(execute)
        .subcommand(resume)
        .subcommand(status)
}

fn guard(args: &ArgMatches, source: erpc_core::chain::Source) -> Result<(), String> {
    let operation = erpc_core::chain::Verb {
        name: "migration",
        about: "Explicit original Solv migration",
        read_only: !matches!(args.subcommand_name(), Some("execute" | "resume")),
    };
    erpc_core::chain::guard_mainnet(
        &operation,
        erpc_core::chain::Chain::Solana,
        source,
        args.get_one::<String>("network").map(String::as_str),
    )
}

fn original_file(path: &Path, maximum: u64) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let original =
        std::fs::symlink_metadata(path).map_err(|_| "historical input metadata is unavailable")?;
    if !original.is_file() || original.len() == 0 || original.len() > maximum {
        return Err(
            "historical input must be a bounded nonempty regular file, not a symlink".into(),
        );
    }
    let file = std::fs::File::open(path).map_err(|_| "historical input cannot be opened")?;
    let opened = file
        .metadata()
        .map_err(|_| "historical input cannot be inspected")?;
    if !opened.is_file()
        || opened.len() != original.len()
        || opened.modified().ok() != original.modified().ok()
    {
        return Err("historical input changed while opening".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if original.dev() != opened.dev() || original.ino() != opened.ino() {
            return Err("historical input changed while opening".into());
        }
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "historical input cannot be read")?;
    let after = file
        .metadata()
        .map_err(|_| "historical input cannot be reinspected")?;
    if bytes.len() as u64 != opened.len()
        || after.len() != opened.len()
        || after.modified().ok() != opened.modified().ok()
    {
        return Err("historical input changed while reading or exceeds its bound".into());
    }
    Ok(bytes)
}

fn evidence(args: &ArgMatches) -> Result<OriginalAccount, String> {
    let read = |id, maximum| {
        original_file(
            args.get_one::<PathBuf>(id)
                .ok_or("historical input is required")?,
            maximum,
        )
    };
    OriginalAccount::from_sources(
        &read("original-passwd", 1_048_576)?,
        &read("original-group", 1_048_576)?,
        &read("original-machine-id", 34)?,
    )
}

fn render(
    source: &LegacySource,
    original: &OriginalAccount,
    history: Option<&Value>,
) -> Result<Value, String> {
    let catalog = native::catalog()?;
    let profile = catalog
        .networks
        .get(&source.network)
        .ok_or("migration network has no native profile")?;
    let fields = &source.node.fields;
    let mut blockers = vec![
        "Historical backups are operator-supplied evidence; their provenance and current-host ownership have not been verified.",
        "Read-only host inspection must qualify units, startup arguments, original identity, voting history, storage and a separate management login before any cutover.",
    ];
    let mut differences = Vec::new();
    if let Some(history) = history {
        let observed = json!({"opening_protocol":1,"prepared":true,"highest":history["highest"]});
        if let Err(reason) = crate::solana_source_upgrade::check_target(profile, &observed) {
            blockers.push(reason);
        }
    } else {
        blockers.push("Independent highest-used Agave source history is required before inspecting or migrating original data.");
    }
    if fields["client"] != "agave" {
        differences.push("The selected native profile changes the recorded client to Agave; client-specific behavior requires an explicitly qualified migration.");
    }
    if source.rpc {
        if fields["rpc_type"] != "send-tx"
            || !fields["geyser_version"].is_empty()
            || !fields["geyser_commit"].is_empty()
            || !fields["of1_version"].is_empty()
            || !fields["of1_sha256"].is_empty()
        {
            differences.push("The source declares RPC indexing, Geyser or Old Faithful features; the native profile cannot be assumed to preserve them.");
        }
        // Even send-tx requires live argument comparison: the inventory alone
        // does not describe all TPU, subscription and peer settings.
        blockers.push("RPC behavior must be compared against the actual startup configuration; an inventory type is not a compatibility certificate.");
    }
    if source.hosts.len() > 1 {
        blockers.push("Other hosts share this logical validator; migration must retain their identity/history and reconcile each host explicitly.");
    }
    // A requested client replacement is not approval to drop its functionality.
    // Inventory can establish incompatibility, but cannot establish host safety.
    let compatibility = if differences.is_empty() {
        "requires-host-inspection"
    } else {
        blockers.push("This source has no qualified feature-preserving migration to the selected native profile; keep operating it through the existing Solv backend.");
        "unsupported"
    };
    let ids = std::iter::once(&source.node)
        .chain(source.hosts.iter())
        .map(|record| (&record.item_id, record.item_version))
        .collect::<Vec<_>>();
    let binding = serde_json::to_vec(&(source, ids, original, history))
        .map_err(|_| "migration source cannot be bound")?;
    Ok(json!({
        "schema":1,"read_only":true,"host_contacted":false,"execution_authorized":false,
        "source":source,"historical_ownership":original,
        "original_source_history":history,
        "source_sha256":format!("{:x}",Sha256::digest(binding)),
        "candidate":{"backend":"native","client":"agave","version":profile.version,"commit":profile.commit,
            "profile":if source.rpc {"agave-native-rpc"} else {"agave-native"}},
        "differences":differences,"blockers":blockers,
        "compatibility":{"status":compatibility,"existing_backend":"solv","policy":"qualified-configurations-only"},
        "backend_changed":false
    }))
}

fn read_history(path: &Path, network: &str) -> Result<Value, String> {
    let raw = crate::solana_source_upgrade::read(path, network)?;
    let record: Value =
        serde_json::from_str(&raw).map_err(|_| "invalid original client history")?;
    Ok(
        json!({"document_sha256":format!("{:x}",Sha256::digest(raw.as_bytes())),
        "highest":{"version":record["version"].as_str().ok_or("invalid original source version")?.trim_start_matches('v'),
                   "commit":record["commit"]}}),
    )
}

pub(crate) fn inputs(
    args: &ArgMatches,
    rpc: bool,
) -> Result<(LegacySource, OriginalAccount, Option<Value>), String> {
    let network = one(args, "network").ok_or("migration plan requires --network")?;
    if !matches!(network, "mainnet" | "testnet") {
        return Err("migration requires mainnet or testnet".into());
    }
    let name = one(args, "name").ok_or("migration plan requires --name")?;
    let host = one(args, "host-name")
        .or(if rpc { Some(name) } else { None })
        .ok_or("validator migration requires an explicit --host-name")?;
    let original = evidence(args)?;
    let history = args
        .get_one::<PathBuf>("original-client-record")
        .map(|path| read_history(path, network))
        .transpose()?;
    let vault = node_common::vault_for(
        network,
        one(args, "vault"),
        "pass the original network inventory vault",
    )?;
    let runner = node_common::op_runner()?;
    let store = node_common::store(&runner, &vault, "solana", network)?;
    let source = store.solana_migration_source(name, rpc, host).map_err(
        |_| "legacy migration source is absent, ambiguous, changed or not a public projection",
    )?;
    Ok((source, original, history))
}

pub(crate) fn original_build(
    args: &ArgMatches,
    network: &str,
    history: Option<&Value>,
) -> Result<Option<OriginalBuild>, String> {
    let Some(path) = args.get_one::<PathBuf>("original-build-record") else {
        return Ok(None);
    };
    let record = OriginalBuild::from_record(&original_file(path, 16384)?, network)?;
    let highest =
        history.ok_or("original highest-used source history is required with build evidence")?;
    if highest["highest"]["version"].as_str() != Some(record.source["version"].as_str())
        || highest["highest"]["commit"].as_str() != Some(record.source["commit"].as_str())
    {
        return Err("original highest-used history and qualified current build association differ; preserve Solv operation".into());
    }
    Ok(Some(record))
}
pub(crate) fn original_keygen(
    args: &ArgMatches,
    network: &str,
    build: &OriginalBuild,
) -> Result<OriginalBuild, String> {
    let path = args
        .get_one::<PathBuf>("original-keygen-record")
        .ok_or("independent original keygen artifact evidence is required")?;
    let record = OriginalBuild::keygen_from_record(&original_file(path, 16384)?, network)?;
    if record.source != build.source {
        return Err("original validator and keygen source/compiler differ".into());
    }
    Ok(record)
}
fn plan(args: &ArgMatches, rpc: bool) -> Result<Value, String> {
    let (source, original, history) = inputs(args, rpc)?;
    let build = original_build(args, &source.network, history.as_ref())?;
    let mut value = render(&source, &original, history.as_ref())?;
    value["original_build_evidence"] =
        serde_json::to_value(build).map_err(|_| "cannot encode public build evidence")?;
    Ok(value)
}

pub(crate) fn inspection_request(
    source: &LegacySource,
    original: &OriginalAccount,
    history: &Value,
    manager: &str,
) -> Result<Value, String> {
    if manager.is_empty()
        || manager.len() > 32
        || !manager.as_bytes()[0].is_ascii_lowercase()
        || !manager
            .bytes()
            .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || b"_-".contains(&v))
        || matches!(manager, "solv" | "root")
    {
        return Err("migration inspection requires a separate nonroot management login".into());
    }
    let plan = render(source, original, Some(history))?;
    if plan["compatibility"]["status"] == "unsupported" {
        return Err(
            "this source has no qualified migration profile; keep using its existing Solv backend"
                .into(),
        );
    }
    let catalog = native::catalog()?;
    let profile = catalog
        .networks
        .get(&source.network)
        .ok_or("unqualified migration network")?;
    crate::solana_source_upgrade::check_target(
        profile,
        &json!({"opening_protocol":1,"prepared":true,"highest":history["highest"]}),
    )?;
    let identity = source
        .node
        .fields
        .get("identity_account")
        .ok_or("legacy public identity is unavailable")?;
    erpc_chain_solana::validator_profile::public_bytes(identity, 32)?;
    let vote = if source.rpc {
        None
    } else {
        source
            .node
            .fields
            .get("vote_account")
            .filter(|value| !value.is_empty())
    };
    if let Some(vote) = vote {
        erpc_chain_solana::validator_profile::public_bytes(vote, 32)?;
    }
    Ok(
        json!({"network":source.network,"role":if source.rpc {"rpc"} else {"validator"},
        "identity_account":identity,"vote_account":vote,"historical":original,
        "source_history":history,
        "management_user":manager,"source_sha256":plan["source_sha256"]}),
    )
}

fn inspection_target(
    source: &LegacySource,
    args: &ArgMatches,
    manager: &str,
) -> Result<erpc_ssh::Target, String> {
    use erpc_ssh::{HostKey, Identity, Target};
    let host = source
        .hosts
        .iter()
        .find(|host| host.fields["name"] == source.selected_host)
        .ok_or("selected legacy host is unavailable")?;
    Ok(Target {
        host: host.fields["address"].clone(),
        port: host.fields["ssh_port"]
            .parse::<u16>()
            .ok()
            .filter(|v| *v != 0)
            .ok_or("invalid original SSH port")?,
        user: manager.into(),
        host_key: HostKey::parse(&host.fields["host_key"])
            .map_err(|_| "invalid original host key")?,
        identity: Identity::Agent {
            socket: node_common::agent_socket(
                args.get_one::<PathBuf>("ssh-agent").map(PathBuf::as_path),
            )?,
            public_key: args
                .get_one::<PathBuf>("ssh-key")
                .cloned()
                .ok_or("management public key is required")?,
        },
    })
}

pub(crate) fn inspect(args: &ArgMatches, rpc: bool) -> Result<Value, String> {
    inspect_original(args, rpc, false)
}
pub(crate) fn inspect_custody(args: &ArgMatches, rpc: bool) -> Result<Value, String> {
    inspect_original(args, rpc, true)
}
fn inspect_original(args: &ArgMatches, rpc: bool, custody: bool) -> Result<Value, String> {
    use erpc_ssh::{RemoteCommand, Session};
    let targets = copy_targets(args)?;
    let (source, original, history) = inputs(args, rpc)?;
    let manager = one(args, "management-user").ok_or("a separate management login is required")?;
    let history = history.ok_or("original source history is required before host inspection")?;
    let mut request = inspection_request(&source, &original, &history, manager)?;
    let build = original_build(args, &source.network, Some(&history))?;
    if let Some(build) = &build {
        request["artifact_evidence"] =
            serde_json::to_value(build).map_err(|_| "cannot encode original artifact evidence")?;
    }
    if custody || args.get_one::<PathBuf>("original-keygen-record").is_some() {
        request["keygen_evidence"] = serde_json::to_value(original_keygen(
            args,
            &source.network,
            build.as_ref().ok_or("original build evidence required")?,
        )?)
        .map_err(|_| "cannot encode original keygen evidence")?;
    }
    if let Some(targets) = &targets {
        request["target_volumes"] =
            serde_json::to_value(targets).map_err(|_| "invalid migration target volumes")?;
    }
    let target = inspection_target(&source, args, manager)?;
    let session = Session::open(&target)
        .map_err(|_| "cannot reach original host through the separate management login")?;
    let (remote, input) = if custody {
        let withdrawer = source
            .node
            .fields
            .get("authority_account")
            .filter(|v| !v.is_empty());
        let packet = serde_json::to_vec(&json!({"legacy":request,"withdrawer":withdrawer}))
            .map_err(|_| "cannot encode original custody inspection")?;
        (
            erpc_ssh::solana_native::Command::LegacyKeyInspect,
            erpc_ssh::solana_native::key_inspection_input(&packet)?,
        )
    } else {
        (
            erpc_ssh::solana_native::Command::LegacyInspect,
            request.to_string().into_bytes(),
        )
    };
    let output = session
        .run(&RemoteCommand::SolanaNative(remote), Some(&input))
        .map_err(|_| "legacy public inspection failed; preserve the existing configuration")?;
    let raw = zeroize::Zeroizing::new(output.stdout);
    let _diagnostics = zeroize::Zeroizing::new(output.stderr);
    if raw.len() > 65536 {
        return Err("legacy inspection response exceeds its bound".into());
    }
    let envelope: Value =
        serde_json::from_slice(&raw).map_err(|_| "invalid legacy inspection response")?;
    let observed = if custody {
        envelope
            .get("inspection")
            .cloned()
            .ok_or("original custody inspection is missing")?
    } else {
        envelope.clone()
    };
    if observed["schema"] != 1
        || observed["source_sha256"] != request["source_sha256"]
        || observed["read_only"] != true
        || observed["execution_authorized"] != false
        || observed["historical_account_matches"] != true
        || observed["original_source_history"] != request["source_history"]
    {
        return Err("legacy inspection does not match the original request".into());
    }
    if build.is_some()
        && (observed["original_build_evidence"] != request["artifact_evidence"]
            || observed["service"]["process"]["artifact_evidence_matches"] != true)
    {
        return Err("current process does not match the independent original build artifact; preserve Solv operation".into());
    }
    if targets.is_some()
        && (observed["copy_preflight"]["requested_volumes"] != request["target_volumes"]
            || observed["copy_preflight"]["requires_stopped_recheck"] != true
            || observed["copy_preflight"]["source_retained"] != true
            || observed["copy_preflight"]["copy_authorized"] != false)
    {
        return Err("copy preflight does not match the requested separate volumes".into());
    }
    let mut result = render(&source, &original, Some(&history))?;
    result["host_contacted"] = json!(true);
    result["inspection"] = observed;
    if custody {
        if envelope.as_object().is_none_or(|v| v.len() != 3) {
            return Err("unexpected original custody observation fields".into());
        }
        result["custody_source"] = envelope["custody_source"].clone();
        result["authority_observation"] = envelope["authority_observation"].clone();
    }
    result["blockers"][0] = json!(
        "Current account and machine identity match the supplied historical evidence; its provenance remains the operator's responsibility."
    );
    Ok(result)
}

pub(crate) fn copy_targets(
    args: &ArgMatches,
) -> Result<Option<std::collections::BTreeMap<String, String>>, String> {
    let mut targets = std::collections::BTreeMap::new();
    for kind in ["accounts", "ledger", "snapshots"] {
        if let Some(value) = one(args, &format!("target-{kind}-uuid")) {
            let canonical = value.len() == 36
                && value.bytes().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    }
                });
            if !canonical {
                return Err("migration target must be a canonical filesystem UUID".into());
            }
            targets.insert(kind.to_owned(), value.to_owned());
        }
    }
    if targets.is_empty() {
        return Ok(None);
    }
    if targets.len() != 3
        || targets
            .values()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 3
    {
        return Err("copy migration requires three distinct target filesystem UUIDs".into());
    }
    Ok(Some(targets))
}

pub(crate) fn run(
    args: &ArgMatches,
    rpc: bool,
    json_out: bool,
    source: erpc_core::chain::Source,
) -> Outcome {
    if let Err(error) = guard(args, source) {
        return Outcome::Usage(error);
    }
    let Some((action, args)) = args.subcommand() else {
        return Outcome::Usage(
            "migration requires plan, inspect, execute, resume or status".into(),
        );
    };
    // A migration names its network and node, as every Solana verb does.
    for (key, flag) in [("network", "--network"), ("name", "--name")] {
        if one(args, key).is_none() {
            return Outcome::Usage(format!("migration requires {flag}"));
        }
    }
    if matches!(action, "execute" | "resume" | "status") {
        return crate::solana_migration_execute::run(action, args, rpc, json_out);
    }
    let result = match action {
        "plan" => plan(args, rpc),
        "inspect" => inspect(args, rpc),
        _ => {
            return Outcome::Usage(
                "migration requires plan, inspect, execute, resume or status".into(),
            );
        }
    };
    match result {
        Ok(value) if json_out => {
            crate::print_json(&value);
            Outcome::Done(String::new())
        }
        Ok(value) => Outcome::Done(serde_json::to_string_pretty(&value).unwrap_or_default()),
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_chain::inventory::solana_migration::PublicRecord;
    use erpc_core::chain::{Chain, Role};
    use std::collections::BTreeMap;

    #[test]
    fn copy_preflight_cli_requires_three_distinct_canonical_volume_ids() {
        let base = [
            "migration",
            "inspect",
            "--original-passwd",
            "public-passwd",
            "--original-group",
            "public-group",
            "--original-machine-id",
            "public-machine",
            "--original-client-record",
            "public-client",
            "--management-user",
            "operator",
            "--ssh-key",
            "manager.pub",
        ];
        let ids = [
            "10000000-0000-0000-0000-000000000001",
            "10000000-0000-0000-0000-000000000002",
            "10000000-0000-0000-0000-000000000003",
        ];
        let none = command().try_get_matches_from(base).unwrap();
        assert_eq!(copy_targets(none.subcommand().unwrap().1).unwrap(), None);
        let partial = base.into_iter().chain(["--target-accounts-uuid", ids[0]]);
        assert!(command().try_get_matches_from(partial).is_err());
        for (first, valid) in [
            (ids[0], true),
            (ids[1], false),
            ("not-a-uuid", false),
            ("10000000-0000-0000-0000-00000000000A", false),
        ] {
            let matches = command()
                .try_get_matches_from(base.into_iter().chain([
                    "--target-accounts-uuid",
                    first,
                    "--target-ledger-uuid",
                    ids[1],
                    "--target-snapshots-uuid",
                    ids[2],
                ]))
                .unwrap();
            let result = copy_targets(matches.subcommand().unwrap().1);
            assert_eq!(result.is_ok(), valid);
            if valid {
                assert_eq!(result.unwrap().unwrap().len(), 3);
            }
        }
    }

    fn history() -> Value {
        let catalog = native::catalog().unwrap();
        let profile = &catalog.networks["testnet"];
        json!({"document_sha256":"d".repeat(64),"highest":{"version":profile.version,"commit":profile.commit}})
    }

    #[test]
    fn independent_history_is_bounded_network_bound_and_cannot_authorize_a_downgrade() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original-client.json");
        let record = history();
        let raw = json!({"schema":1,"client":"agave","network":"testnet",
            "version":record["highest"]["version"],"commit":record["highest"]["commit"]})
        .to_string();
        std::fs::write(&path, &raw).unwrap();
        let original = read_history(&path, "testnet").unwrap();
        assert_eq!(original["highest"], record["highest"]);
        assert_eq!(
            original["document_sha256"],
            format!("{:x}", Sha256::digest(raw.as_bytes()))
        );
        assert!(read_history(&path, "mainnet").is_err());
        let mut source = source(false);
        source.node.fields.insert("client".into(), "agave".into());
        let without = render(&source, &self::original(), None).unwrap();
        let with = render(&source, &self::original(), Some(&original)).unwrap();
        assert_ne!(without["source_sha256"], with["source_sha256"]);
        assert!(
            without["blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap().contains("highest-used"))
        );
        let mut higher = original.clone();
        higher["highest"]["version"] = json!("99.0.0");
        assert!(
            inspection_request(&source, &self::original(), &higher, "operator")
                .unwrap_err()
                .contains("below")
        );
        let mut substituted = original;
        substituted["highest"]["commit"] = json!("f".repeat(40));
        assert!(
            inspection_request(&source, &self::original(), &substituted, "operator")
                .unwrap_err()
                .contains("differs")
        );
    }

    fn original() -> OriginalAccount {
        OriginalAccount::from_sources(
            b"solv:x:1001:1002::/home/solv:/bin/bash\n",
            b"solv:x:1002:\n",
            b"11111111111111111111111111111111\n",
        )
        .unwrap()
    }
    fn source(rpc: bool) -> LegacySource {
        let fields = BTreeMap::from([
            ("name".into(), "node".into()),
            ("client".into(), "jito".into()),
            ("rpc_type".into(), "index-grpc".into()),
            ("geyser_version".into(), "v1".into()),
            ("geyser_commit".into(), "c".repeat(40)),
            ("of1_version".into(), "v1".into()),
            ("of1_sha256".into(), "d".repeat(64)),
        ]);
        let node = PublicRecord {
            item_id: "a".repeat(26),
            item_version: 1,
            fields,
        };
        let mut spare = node.clone();
        spare.item_id = "b".repeat(26);
        spare.fields.insert("name".into(), "spare".into());
        LegacySource {
            network: "testnet".into(),
            rpc,
            selected_host: "node".into(),
            hosts: if rpc {
                vec![node.clone()]
            } else {
                vec![node.clone(), spare]
            },
            node,
        }
    }
    #[test]
    fn actual_command_tree_requires_historical_inputs_and_an_explicit_validator_host() {
        for role in [Role::Validator, Role::Rpc] {
            let command = crate::tree::command(role, Chain::Solana);
            command.clone().debug_assert();
            assert!(
                command
                    .clone()
                    .try_get_matches_from([role.as_str(), "migration", "plan"])
                    .is_err()
            );
            let parsed = command
                .try_get_matches_from([
                    role.as_str(),
                    "-n",
                    "testnet",
                    "--name",
                    "node",
                    "migration",
                    "plan",
                    "--original-passwd",
                    "public-passwd",
                    "--original-group",
                    "public-group",
                    "--original-machine-id",
                    "public-machine",
                ])
                .unwrap();
            let args = parsed.subcommand().unwrap().1.subcommand().unwrap().1;
            assert_eq!(one(args, "network"), Some("testnet"));
            assert_eq!(one(args, "name"), Some("node"));
            if role == Role::Validator {
                assert_eq!(
                    plan(args, false).unwrap_err(),
                    "validator migration requires an explicit --host-name"
                );
            }
        }
    }
    #[test]
    fn plan_reports_features_and_companions_without_authorizing_any_host_operation() {
        for rpc in [false, true] {
            let source = source(rpc);
            let plan = render(&source, &original(), None).unwrap();
            assert_eq!(plan["read_only"], true);
            assert_eq!(plan["host_contacted"], false);
            assert_eq!(plan["execution_authorized"], false);
            assert_eq!(plan["backend_changed"], false);
            assert_eq!(
                plan["source"]["hosts"].as_array().unwrap().len(),
                if rpc { 1 } else { 2 }
            );
            assert_eq!(
                plan["differences"].as_array().unwrap().len(),
                if rpc { 2 } else { 1 }
            );
            let mut recreated = source.clone();
            recreated.node.item_id = "c".repeat(26);
            assert_ne!(
                plan["source_sha256"],
                render(&recreated, &original(), None).unwrap()["source_sha256"]
            );
            let text = serde_json::to_string(&plan).unwrap();
            for absent in [
                "/home/solv",
                "11111111111111111111111111111111",
                &"a".repeat(26),
            ] {
                assert!(!text.contains(absent));
            }
        }
    }
    #[test]
    fn bounded_real_files_keep_bytes_and_reject_links_directories_and_oversized_sources() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public-passwd");
        let bytes = b"solv:x:1001:1002::/home/solv:/bin/bash\n";
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(original_file(&path, 1024).unwrap().as_slice(), bytes);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(original_file(&path, 4).is_err());
        assert!(original_file(dir.path(), 1024).is_err());
        std::fs::write(&path, b"").unwrap();
        assert!(original_file(&path, 1024).is_err());
        #[cfg(unix)]
        {
            let link = dir.path().join("public-link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(original_file(&link, 1024).is_err());
        }
    }

    #[test]
    fn unqualified_clients_and_features_remain_legacy_and_never_become_approved_by_planning() {
        for rpc in [false, true] {
            let mut candidate = source(rpc);
            candidate
                .node
                .fields
                .insert("client".into(), "agave".into());
            candidate
                .node
                .fields
                .insert("rpc_type".into(), "send-tx".into());
            for field in [
                "geyser_version",
                "geyser_commit",
                "of1_version",
                "of1_sha256",
            ] {
                candidate.node.fields.insert(field.into(), String::new());
            }
            let inspected_later = render(&candidate, &original(), None).unwrap();
            assert_eq!(
                inspected_later["compatibility"]["status"],
                "requires-host-inspection"
            );
            assert_eq!(inspected_later["execution_authorized"], false);
            for client in ["jito", "allnodes-jito", "firedancer", "unknown", ""] {
                let mut custom = candidate.clone();
                custom.node.fields.insert("client".into(), client.into());
                let plan = render(&custom, &original(), None).unwrap();
                assert_eq!(plan["compatibility"]["status"], "unsupported");
                assert_eq!(plan["compatibility"]["existing_backend"], "solv");
                assert_eq!(plan["backend_changed"], false);
                assert_eq!(plan["execution_authorized"], false);
            }
            if rpc {
                for (field, value) in [
                    ("rpc_type", "index"),
                    ("rpc_type", "grpc"),
                    ("rpc_type", "index-grpc"),
                    ("geyser_version", "v1"),
                    ("geyser_commit", "commit-only"),
                    ("of1_version", "v1"),
                    ("of1_sha256", "digest-only"),
                ] {
                    let mut custom = candidate.clone();
                    custom.node.fields.insert(field.into(), value.into());
                    let plan = render(&custom, &original(), None).unwrap();
                    assert_eq!(plan["compatibility"]["status"], "unsupported", "{field}");
                    assert_eq!(plan["execution_authorized"], false);
                }
            }
        }
    }

    #[test]
    fn remote_inspection_requires_a_distinct_management_user_and_a_qualified_public_source() {
        let mut source = source(false);
        for user in ["solv", "root", "", "operator;id", "-user", "user\nname"] {
            assert!(inspection_request(&source, &original(), &history(), user).is_err());
        }
        assert!(
            inspection_request(&source, &original(), &history(), "operator")
                .unwrap_err()
                .contains("existing Solv")
        );
        source.node.fields.insert("client".into(), "agave".into());
        source
            .node
            .fields
            .insert("identity_account".into(), "2".repeat(44));
        source
            .node
            .fields
            .insert("vote_account".into(), "3".repeat(44));
        let request = inspection_request(&source, &original(), &history(), "operator").unwrap();
        assert_eq!(request["management_user"], "operator");
        assert_eq!(request["role"], "validator");
        assert_eq!(request["historical"]["uid"], 1001);
        assert_eq!(
            request["source_sha256"],
            render(&source, &original(), Some(&history())).unwrap()["source_sha256"]
        );
        assert!(!request.to_string().contains("op://"));
        for role in [Role::Rpc, Role::Validator] {
            let command = crate::tree::command(role, Chain::Solana);
            assert!(
                command
                    .clone()
                    .try_get_matches_from([
                        role.as_str(),
                        "migration",
                        "inspect",
                        "--original-passwd",
                        "public-passwd",
                        "--original-group",
                        "public-group",
                        "--original-machine-id",
                        "public-machine"
                    ])
                    .is_err()
            );
            command
                .try_get_matches_from([
                    role.as_str(),
                    "migration",
                    "inspect",
                    "--original-passwd",
                    "public-passwd",
                    "--original-group",
                    "public-group",
                    "--original-machine-id",
                    "public-machine",
                    "--original-client-record",
                    "public-client",
                    "--management-user",
                    "operator",
                    "--ssh-key",
                    "management.pub",
                ])
                .unwrap();
        }
    }
}
