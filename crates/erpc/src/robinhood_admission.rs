// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public admission preparation on an existing owned Robinhood RPC host.
use crate::{commands::Outcome, node_common, robinhood_admission_input as input};
use clap::{Arg, ArgMatches, Command, value_parser};
use erpc_core::chain::Verb;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::PathBuf};

pub(crate) const REGISTRATION: Verb = Verb {
    name: "registration",
    about: "Observe public Robinhood admission or prepare/validate external administrator calldata",
    read_only: true,
};
const PLAY: &str = "robinhood-admission/control.yml";
const PREFIX: &str = "robinhood-admission/node";
const PROFILE: [&str; 7] = [
    "catalog.json",
    "control.py",
    "entry.py",
    "follower.py",
    "observation.py",
    "storage.py",
    "upstreams.py",
];

pub(crate) fn args(command: Command) -> Command {
    command
        .about(REGISTRATION.about)
        .arg(
            Arg::new("action")
                .long("action")
                .default_value("status")
                .value_parser(["status", "prepare", "validate"]),
        )
        .arg(
            Arg::new("validator-address")
                .long("validator-address")
                .required(true)
                .help("Public dedicated EOA address; no signing key is read"),
        )
        .arg(
            Arg::new("file")
                .long("file")
                .value_parser(value_parser!(PathBuf))
                .help(
                    "Public intent returned by --action prepare; only valid with --action validate",
                ),
        )
        .arg(
            Arg::new("vault").long("vault").help(
                "Inventory vault containing the existing Robinhood RPC node selected by --name",
            ),
        )
        .arg(
            Arg::new("ssh-key")
                .long("ssh-key")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("ssh-agent")
                .long("ssh-agent")
                .value_parser(value_parser!(PathBuf)),
        )
}

fn one<'a>(args: &'a ArgMatches, name: &str) -> Option<&'a str> {
    args.try_get_one::<String>(name)
        .ok()
        .flatten()
        .map(String::as_str)
}

fn public_input(args: &ArgMatches, network: &str) -> Result<(String, String, Value), String> {
    input::profile(network)?;
    let validator =
        input::address(one(args, "validator-address").ok_or("public validator address required")?)?;
    let action = one(args, "action").ok_or("public admission action required")?;
    let file = args.get_one::<PathBuf>("file");
    let intent = match (action, file) {
        ("validate", Some(path)) => input::read(path, network, &validator)?,
        ("validate", None) => {
            return Err("validation requires --file with the public admission intent".into());
        }
        ("status" | "prepare", None) => Value::Null,
        _ => return Err("only validation accepts an intent file".into()),
    };
    let name =
        one(args, "name").ok_or("pass --name for the original Robinhood RPC inventory host")?;
    erpc_chain::inventory::check_name(name).map_err(|_| "invalid original RPC inventory name")?;
    Ok((action.into(), validator, intent))
}

fn sources() -> Result<BTreeMap<String, Vec<u8>>, String> {
    let source = erpc_chain_nitro::TEMPLATES
        .get_dir(PREFIX)
        .ok_or("missing admission source")?;
    if source.dirs().next().is_some() {
        return Err("nested admission helper source is unsupported".into());
    }
    let mut files = BTreeMap::new();
    for file in source.files() {
        let name = file
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid admission source name")?;
        files.insert(name.to_owned(), file.contents().to_vec());
    }
    for (name, path) in [
        ("follower.py", "node/control.py"),
        ("storage.py", "validator/node/storage.py"),
    ] {
        let source = erpc_chain_nitro::TEMPLATES
            .get_file(path)
            .ok_or("missing reviewed admission dependency")?;
        if files
            .insert(name.into(), source.contents().to_vec())
            .is_some()
        {
            return Err("duplicate admission source dependency".into());
        }
    }
    if files
        .insert(
            "upstreams.py".into(),
            erpc_chain_rollup::UPSTREAM_PROXY.as_bytes().to_vec(),
        )
        .is_some()
        || files.len() != PROFILE.len()
        || PROFILE.iter().any(|name| !files.contains_key(*name))
    {
        return Err("admission source profile differs from the closed compiled set".into());
    }
    Ok(files)
}

fn helpers(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut digest = Sha256::new();
    for (name, bytes) in files {
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(Sha256::digest(bytes));
    }
    format!("{:x}", digest.finalize())
}

fn bundle(name: &str, request: &Value) -> Result<(erpc_ops::bundle::Built, String), String> {
    let files = sources()?;
    let fingerprint = helpers(&files);
    let mut bundle = erpc_ops::bundle::Bundle::new();
    for (name, bytes) in files {
        bundle
            .add(&format!("{PREFIX}/{name}"), bytes)
            .map_err(|e| e.to_string())?;
    }
    bundle
        .add(
            PLAY,
            erpc_chain_nitro::TEMPLATES
                .get_file(PLAY)
                .ok_or("missing admission play")?
                .contents()
                .to_vec(),
        )
        .map_err(|e| e.to_string())?;
    let inventory =
        json!({"all":{"hosts":{name:{"ansible_connection":"local","admission_request":request}}}});
    bundle
        .add("inventory.yml", inventory.to_string().into_bytes())
        .map_err(|e| e.to_string())?;
    Ok((bundle.finish().map_err(|e| e.to_string())?, fingerprint))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicResult {
    schema: String,
    run: String,
    bundle_sha256: String,
    helpers_sha256: String,
    request_sha256: String,
    result: Value,
}
fn public_result(
    raw: &[u8],
    run: &str,
    bundle: &str,
    helpers: &str,
    request: &Value,
) -> Result<Value, String> {
    if raw.len() > 65536 {
        return Err("admission result exceeds its public bound".into());
    }
    let value: PublicResult =
        serde_json::from_slice(raw).map_err(|_| "invalid public admission result")?;
    if value.schema != "erpc-robinhood-admission-public-result-v1"
        || value.run != run
        || value.bundle_sha256 != bundle
        || value.helpers_sha256 != helpers
        || value.request_sha256 != erpc_chain_nitro::validator::request_digest(request)?
        || !value.result.is_object()
    {
        return Err("admission result is not bound to this exact compiled request and run".into());
    }
    Ok(value.result)
}

fn observe(args: &ArgMatches, network: &str, json_out: bool) -> Result<Value, String> {
    let (action, validator, intent) = public_input(args, network)?;
    let qualified = erpc_chain_nitro::network::Network::parse("robinhood", network)
        .ok_or("unsupported Robinhood network")?;
    let (node, target, session, scope) = crate::nitro_rpc::admission_session(qualified, args)?;
    let request = json!({"schema":1,"action":action,"rpc_node":scope,"validator_address":validator,"intent":intent});
    let (built, helpers) = bundle(&node.name, &request)?;
    let say = node_common::Say { quiet: json_out };
    let run = erpc_ops::run::start(&session, &built, PLAY).map_err(|e| e.to_string())?;
    let result = node_common::follow(
        &target,
        &run,
        "Repeat the read-only admission request; no node or signing authority was changed",
        &say,
    )?;
    if !result.ok() {
        return Err(
            "public admission observation failed; no registration or activation was performed"
                .into(),
        );
    }
    let output = session
        .run(
            &erpc_ssh::RemoteCommand::RobinhoodAdmissionResult(run.clone()),
            None,
        )
        .map_err(|_| "completed admission result could not be authenticated")?;
    public_result(
        &output.stdout,
        run.as_str(),
        &built.sha256,
        &helpers,
        &request,
    )
}

pub(crate) fn run(args: &ArgMatches, network: Option<&str>, json_out: bool) -> Outcome {
    let Some(network) = network else {
        return Outcome::Usage("Robinhood admission requires --network mainnet or testnet".into());
    };
    match observe(args, network, json_out) {
        Ok(value) => {
            let problems = one(args, "action") == Some("status")
                && (value["admitted"] != true || value["rollup_paused"] != false);
            let text = if json_out {
                crate::print_json(&value);
                String::new()
            } else {
                serde_json::to_string_pretty(&value).unwrap_or_default()
            };
            if problems {
                Outcome::Problems(text)
            } else {
                Outcome::Done(text)
            }
        }
        Err(message) => Outcome::Failed(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Write as _;
    #[cfg(unix)]
    use std::process::{Command, Stdio};
    fn request(network: &str, action: &str, intent: &Value) -> Value {
        let release = erpc_chain_nitro::release::get("3.12.1").unwrap();
        json!({"schema":1,"action":action,"validator_address":format!("0x{}", "1".repeat(40)),"intent":intent,
            "rpc_node":{"owner":"a".repeat(26),"family":"robinhood","network":network,"platform":"amd64",
            "version":"3.12.1","commit":release.commit,"config_id":"d".repeat(64),"action":"admission-observe"}})
    }
    #[cfg(unix)]
    fn execute(request: &Value, scenario: &str) -> Value {
        let (built, helpers) = bundle("fixture", request).unwrap();
        let python =
            std::env::var_os("ERPC_TEST_ADMISSION_PYTHON").unwrap_or_else(|| "python3".into());
        let mut process = Command::new(python)
            .args(["-I", "-B"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/robinhood_admission_play.py"
            ))
            .arg(scenario)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        process
            .stdin
            .take()
            .unwrap()
            .write_all(&built.bytes)
            .unwrap();
        let output = process.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{scenario}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if scenario == "safe" {
            public_result(
                &output.stdout,
                "r-robinhood-admission-fixture",
                &built.sha256,
                &helpers,
                request,
            )
            .unwrap()
        } else {
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                value,
                json!({"refused":true,"originals_preserved":true,"public_result_written":false})
            );
            value
        }
    }
    #[cfg(unix)]
    #[test]
    fn actual_compiled_admission_bundle_preserves_rpc_custody_and_roundtrips_public_intents() {
        for network in ["mainnet", "testnet"] {
            let status = execute(&request(network, "status", &Value::Null), "safe");
            assert_eq!(status["admitted"], false);
            assert_eq!(status["financial_action_performed"], false);
            let intent = execute(&request(network, "prepare", &Value::Null), "safe");
            let directory = tempfile::tempdir().unwrap();
            let file = directory.path().join("public-intent.json");
            std::fs::write(&file, intent.to_string()).unwrap();
            let checked = input::read(&file, network, &format!("0x{}", "1".repeat(40))).unwrap();
            assert_eq!(checked, intent);
            let validated = execute(&request(network, "validate", &checked), "safe");
            assert_eq!(validated["intent_matches_current_observation"], true);
            assert_eq!(validated["activation_authorized"], false);
            let mut forged = checked.clone();
            forged["snapshot"]["block_hash"] = json!(format!("0x{}", "c".repeat(64)));
            execute(&request(network, "validate", &forged), "forged-snapshot");
            for scenario in [
                "foreign-owner",
                "plaintext",
                "private-provider",
                "decrypt-failed",
                "provider-error",
                "changed-owner",
                "changed-cipher",
                "reorg",
                "stale",
            ] {
                execute(&request(network, "prepare", &Value::Null), scenario);
            }
        }
    }
    #[test]
    fn public_result_cannot_be_reused_for_another_source_bundle_run_or_request() {
        let query = request("testnet", "status", &Value::Null);
        let record = json!({"schema":"erpc-robinhood-admission-public-result-v1","run":"r-public-fixture",
            "bundle_sha256":"a".repeat(64),"helpers_sha256":"b".repeat(64),
            "request_sha256":erpc_chain_nitro::validator::request_digest(&query).unwrap(),"result":{"admitted":false}});
        let raw = record.to_string();
        assert!(
            public_result(
                raw.as_bytes(),
                "r-public-fixture",
                &"a".repeat(64),
                &"b".repeat(64),
                &query
            )
            .is_ok()
        );
        for (field, replacement) in [
            ("schema", "erpc-arbitrum-public-result-v1"),
            ("run", "r-other-fixture"),
            ("bundle_sha256", "wrong"),
            ("helpers_sha256", "wrong"),
            ("request_sha256", "wrong"),
        ] {
            let mut wrong = record.clone();
            wrong[field] = json!(replacement);
            assert!(
                public_result(
                    wrong.to_string().as_bytes(),
                    "r-public-fixture",
                    &"a".repeat(64),
                    &"b".repeat(64),
                    &query
                )
                .is_err()
            );
        }
    }
}
