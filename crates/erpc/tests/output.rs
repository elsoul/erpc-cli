// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A command whose output cannot be written fails, rather than reporting
//! success with nothing written.

use std::process::{Command, Stdio};

#[test]
fn robinhood_defensive_requires_explicit_vault_before_any_provider_access() {
    let home = tempfile::tempdir().unwrap();
    for network in ["mainnet", "testnet"] {
        for verb in erpc_core::chain::COMMON_VERBS {
            let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
            command
                .env_clear()
                .env("ERPC_HOME", home.path())
                .env("PATH", home.path());
            if let Some(root) = std::env::var_os("SYSTEMROOT") {
                command.env("SYSTEMROOT", root);
            }
            command.args([
                "--json",
                "v",
                "--chain",
                "robinhood",
                "--network",
                network,
                "--name",
                "fixture",
                verb.name,
            ]);
            if verb.name == "update" {
                command.args(["--version", "3.12.2"]);
            }
            let output = command.stdin(Stdio::null()).output().unwrap();
            assert!(!output.status.success());
            assert!(output.stderr.is_empty());
            let text = String::from_utf8(output.stdout).unwrap();
            assert_eq!(text.lines().count(), 1);
            let _: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(text.contains("--vault"), "{network} {}: {text}", verb.name);
            assert!(!text.contains("N/A"));
            assert!(!text.contains("not implemented"));
        }
    }
}

#[test]
fn all_eighteen_rpc_backends_route_without_fabricating_a_deployment() {
    let home = tempfile::tempdir().expect("empty isolated configuration");
    for (chain, network) in [
        ("solana", "testnet"),
        ("ethereum", "mainnet"),
        ("avalanche", "fuji"),
        ("bitcoin", "signet"),
        ("base", "sepolia"),
        ("arbitrum", "sepolia"),
        ("polygon", "amoy"),
        ("bsc", "chapel"),
        ("optimism", "sepolia"),
        ("kaia", "kairos"),
        ("soneium", "minato"),
        ("monad", "testnet"),
        ("hyperliquid", "testnet"),
        ("arc", "testnet"),
        ("robinhood", "testnet"),
        ("near", "testnet"),
        ("tron", "nile"),
        ("sui", "testnet"),
    ] {
        for verb in [
            "init",
            "deploy",
            "list",
            "status",
            "logs",
            "start",
            "stop",
            "restart",
            "update",
            "update-config",
            "plan",
            "destroy",
        ] {
            // No name, vault, SSH identity or inherited provider environment.
            // List/plan may return a local empty inventory or carried profile;
            // every actual host operation must refuse its missing prerequisites.
            let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
            command
                .env_clear()
                .env("ERPC_HOME", home.path())
                .env("PATH", home.path());
            if let Some(root) = std::env::var_os("SYSTEMROOT") {
                command.env("SYSTEMROOT", root);
            }
            let output = command
                .args([
                    "--json",
                    "rpc",
                    "--chain",
                    chain,
                    "--network",
                    network,
                    verb,
                ])
                .stdin(Stdio::null())
                .output()
                .expect("isolated command route");
            assert!(
                output.stderr.is_empty(),
                "{chain} {verb}: stderr is not JSON stdout"
            );
            let text = String::from_utf8(output.stdout).expect("UTF-8 command output");
            assert_eq!(text.lines().count(), 1, "{chain} {verb}: {text}");
            let _: serde_json::Value =
                serde_json::from_str(&text).expect("one complete JSON record");
            assert!(!text.contains("not implemented"), "{chain} {verb}: {text}");
            if !matches!(verb, "list" | "plan") {
                assert!(
                    !output.status.success(),
                    "{chain} {verb} succeeded without an original host"
                );
            }
        }
    }
}

#[test]
fn arc_original_inventory_cannot_be_forgotten_before_any_provider_or_host_access() {
    let home = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_erpc"))
        .args([
            "--json",
            "rpc",
            "--chain",
            "arc",
            "--network",
            "testnet",
            "destroy",
            "--name",
            "original",
            "--purge-data",
            "--forget",
        ])
        .env("ERPC_HOME", home.path())
        .env("PATH", home.path())
        .env_remove("ERPC_CHAIN")
        .env_remove("ERPC_NETWORK")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stderr.is_empty());
    let text = String::from_utf8(result.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    let _: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert!(text.contains("original inventory, key and data history"));
    assert!(!text.contains("1Password CLI"));
}

#[test]
fn output_that_cannot_be_written_fails_the_command() {
    let home = tempfile::tempdir().expect("a temporary directory");
    for args in [
        &["config", "path"][..],
        &["version"],
        &["--json", "version"],
    ] {
        // Its stdout is a pipe nobody reads any more.
        let (reader, writer) = std::io::pipe().expect("a pipe");
        drop(reader);
        let status = Command::new(env!("CARGO_BIN_EXE_erpc"))
            .args(args)
            .env("ERPC_HOME", home.path())
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(Stdio::null())
            .status()
            .expect("erpc runs");
        assert_eq!(status.code(), Some(1), "erpc {}: {status}", args.join(" "));
    }
}

#[test]
fn arc_rpc_and_preparation_routes_keep_actual_guards_and_signing_unavailable() {
    let home = tempfile::tempdir().expect("isolated configuration");
    for verb in erpc_core::chain::COMMON_VERBS {
        let rpc = Command::new(env!("CARGO_BIN_EXE_erpc"))
            .args([
                "--json",
                "rpc",
                "--chain",
                "arc",
                "--network",
                "testnet",
                verb.name,
            ])
            .env("ERPC_HOME", home.path())
            .env_remove("ERPC_CHAIN")
            .env_remove("ERPC_NETWORK")
            .env("PATH", home.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            rpc.stderr.is_empty(),
            "{}: {}",
            verb.name,
            String::from_utf8_lossy(&rpc.stderr)
        );
        let text = String::from_utf8(rpc.stdout).unwrap();
        let records: Vec<_> = text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect();
        assert_eq!(records.len(), 1);
        assert!(!text.contains("not implemented"), "{}", verb.name);
        if verb.name == "list" {
            assert!(rpc.status.success());
            assert_eq!(records[0]["nodes"], serde_json::json!([]));
        } else {
            assert!(!rpc.status.success());
            assert!(text.contains("--name"), "{}: {text}", verb.name);
        }
        for network in ["mainnet", "testnet"] {
            let validator = Command::new(env!("CARGO_BIN_EXE_erpc"))
                .args([
                    "--json",
                    "v",
                    "--chain",
                    "arc",
                    "--network",
                    network,
                    verb.name,
                ])
                .env("ERPC_HOME", home.path())
                .env_remove("ERPC_CHAIN")
                .env_remove("ERPC_NETWORK")
                .env("PATH", home.path())
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert_eq!(validator.status.success(), verb.name == "list");
            assert!(validator.stderr.is_empty());
            let text = String::from_utf8(validator.stdout).unwrap();
            assert_eq!(text.lines().count(), 1);
            let record: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
            assert!(!text.contains("N/A"));
            if verb.name == "plan" {
                assert_eq!(record["production_activation_available"], false);
                assert_eq!(record["validator_ready"], false);
                assert_eq!(record["preparation_available"], true);
            } else if verb.name == "list" {
                assert_eq!(record["nodes"], serde_json::json!([]));
            } else {
                assert!(text.contains("--name"), "{}: {text}", verb.name);
            }
        }
    }
}

#[test]
fn polygon_failure_is_one_json_record_before_credentials_or_ssh() {
    let home = tempfile::tempdir().expect("isolated configuration");
    let output = Command::new(env!("CARGO_BIN_EXE_erpc"))
        .args(["--json", "rpc", "--chain", "polygon", "status"])
        .env("ERPC_HOME", home.path())
        .env_remove("ERPC_CHAIN")
        .env_remove("ERPC_NETWORK")
        .stdin(Stdio::null())
        .output()
        .expect("offline CLI failure");
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 1, "global failure remains one JSON line");
    let value: serde_json::Value = serde_json::from_str(lines[0]).expect("complete failure record");
    assert!(value.to_string().contains("explicit --network"));
}

#[test]
fn nitro_log_failure_is_one_json_record_before_credentials_or_ssh() {
    let home = tempfile::tempdir().expect("isolated configuration");
    for chain in ["arbitrum", "robinhood"] {
        let output = Command::new(env!("CARGO_BIN_EXE_erpc"))
            .args(["--json", "rpc", "--chain", chain, "logs"])
            .env("ERPC_HOME", home.path())
            .env_remove("ERPC_CHAIN")
            .env_remove("ERPC_NETWORK")
            .stdin(Stdio::null())
            .output()
            .expect("offline logs command");
        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).expect("UTF-8 JSON");
        let records: Vec<_> = text.lines().collect();
        assert_eq!(records.len(), 1, "global error remains one stdout record");
        let error: serde_json::Value =
            serde_json::from_str(records[0]).expect("complete JSON error");
        assert!(error.to_string().contains("explicit supported network"));
    }
}

#[test]
fn arbitrum_validator_wrong_network_is_one_json_error_before_custody() {
    let home = tempfile::tempdir().expect("isolated configuration");
    let output = Command::new(env!("CARGO_BIN_EXE_erpc"))
        .args([
            "--json",
            "validator",
            "--chain",
            "arbitrum",
            "status",
            "--network",
            "nova",
            "--name",
            "fixture",
        ])
        .env("ERPC_HOME", home.path())
        .env_remove("ERPC_CHAIN")
        .env_remove("ERPC_NETWORK")
        .stdin(Stdio::null())
        .output()
        .expect("offline namespace failure");
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    assert_eq!(text.lines().count(), 1);
    let error: serde_json::Value = serde_json::from_str(&text).expect("compact complete error");
    assert!(error.to_string().contains("Arbitrum One mainnet only"));
}

#[test]
fn arbitrum_validator_missing_name_is_refused_before_inventory_access() {
    let home = tempfile::tempdir().expect("isolated configuration");
    let output = Command::new(env!("CARGO_BIN_EXE_erpc"))
        .args([
            "--json",
            "validator",
            "--chain",
            "arbitrum",
            "status",
            "--network",
            "mainnet",
        ])
        .env("ERPC_HOME", home.path())
        .env("PATH", home.path())
        .env_remove("ERPC_CHAIN")
        .env_remove("ERPC_NETWORK")
        .stdin(Stdio::null())
        .output()
        .expect("offline argument failure");
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    assert_eq!(text.lines().count(), 1);
    let error: serde_json::Value = serde_json::from_str(&text).expect("complete JSON error");
    assert!(error.to_string().contains("before inventory access"));
}

#[test]
fn polygon_validator_routes_fail_before_credentials_and_never_offer_submission() {
    let home = tempfile::tempdir().expect("isolated configuration");
    for verb in [
        "init",
        "deploy",
        "list",
        "status",
        "logs",
        "start",
        "stop",
        "restart",
        "update",
        "update-config",
        "plan",
        "destroy",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_erpc"))
            .args(["--json", "v", "--chain", "polygon", verb])
            .env("ERPC_HOME", home.path())
            .env_remove("ERPC_CHAIN")
            .env_remove("ERPC_NETWORK")
            .stdin(Stdio::null())
            .output()
            .expect("offline validator route");
        assert!(!output.status.success(), "{verb}");
        assert!(output.stderr.is_empty(), "{verb}");
        let text = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 1, "{verb}: {text}");
        let value: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert!(value.to_string().contains("--network"), "{verb}: {value}");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_erpc"))
        .args([
            "--json",
            "v",
            "--chain",
            "polygon",
            "registration",
            "--network",
            "amoy",
            "--action",
            "submit",
        ])
        .env("ERPC_HOME", home.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    let error: serde_json::Value = serde_json::from_str(&text).unwrap();
    let usage = error.to_string();
    assert!(usage.contains("invalid value 'submit'"));
    assert!(usage.contains("prepare, validate, status"));
}

#[test]
fn original_volume_upgrade_uses_the_parsed_recovery_path_before_any_provider_or_key_access() {
    let home = tempfile::tempdir().unwrap();
    let evidence = home.path().join("original-root.json");
    std::fs::write(&evidence, br#"{"schema":"INERT_WRONG_PUBLIC_RECORD"}"#).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_erpc"))
        .args([
            "--json",
            "v",
            "--chain",
            "arbitrum",
            "--network",
            "mainnet",
            "init",
            "--name",
            "original",
            "--upgrade-volume-authority",
            "--original-root-volume-record",
        ])
        .arg(&evidence)
        .env("ERPC_HOME", home.path())
        .env("PATH", home.path())
        .env_remove("ERPC_CHAIN")
        .env_remove("ERPC_NETWORK")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stderr.is_empty());
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(stdout.contains("historical ROOT volume record"));
    assert!(!stdout.contains("INERT_WRONG_PUBLIC_RECORD") && !stdout.contains("1Password"));
}

#[test]
fn arc_preparation_extras_keep_signing_held_and_reject_bad_public_intents_before_tools() {
    let home = tempfile::tempdir().unwrap();
    let sender = format!("0x{}", "a".repeat(40));
    let cases = arc_public_guard_cases(&sender);
    for network in ["mainnet", "testnet"] {
        for (arguments, code, reason) in &cases {
            let output = Command::new(env!("CARGO_BIN_EXE_erpc"))
                .args([
                    "--json",
                    "v",
                    "--chain",
                    "arc",
                    "--network",
                    network,
                    "--name",
                    "original",
                ])
                .args(arguments)
                .env("ERPC_HOME", home.path())
                .env("PATH", home.path())
                .env_remove("ERPC_CHAIN")
                .env_remove("ERPC_NETWORK")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(*code),
                "{arguments:?}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(output.stderr.is_empty());
            let text = String::from_utf8(output.stdout).unwrap();
            assert_eq!(text.lines().count(), 1);
            let _: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(text.contains(reason), "{arguments:?}: {text}");
            assert!(!text.contains("1Password"));
        }
    }
}

fn arc_public_guard_cases(sender: &str) -> Vec<(Vec<&str>, i32, &str)> {
    vec![
        (
            vec!["activate"],
            1,
            "Production Arc activation remains unavailable",
        ),
        (vec!["prepare-registration"], 2, "--step"),
        (
            vec![
                "prepare-registration",
                "--step",
                "register",
                "--from",
                "invalid",
            ],
            2,
            "--from",
        ),
        (
            vec![
                "prepare-registration",
                "--step",
                "configure-controller",
                "--from",
                sender,
                "--registration-id",
                "0",
                "--voting-power-limit",
                "10",
            ],
            2,
            "positive integer",
        ),
        (
            vec![
                "prepare-registration",
                "--step",
                "remove",
                "--from",
                sender,
                "--voting-power",
                "10",
            ],
            2,
            "does not apply",
        ),
        (
            vec![
                "validate-registration",
                "--step",
                "register",
                "--from",
                sender,
            ],
            2,
            "--registration-file",
        ),
        (
            vec!["reset-bootstrap", "--original-intent", "invalid"],
            2,
            "128-bit",
        ),
        (vec!["init"], 2, "--signer-ca"),
    ]
}

#[test]
fn a_solana_list_for_a_person_is_the_result_on_standard_output() {
    // No keyless.toml: nothing is asked of 1Password, and the list is empty.
    let home = tempfile::tempdir().expect("empty isolated configuration");
    for (role, hint, record) in [
        (
            "v",
            "no validators yet: `erpc v --chain solana init --help`",
            r#"{"validators":[]}"#,
        ),
        (
            "rpc",
            "no Solana RPC nodes yet: `erpc rpc --chain solana init --help`",
            r#"{"nodes":[]}"#,
        ),
    ] {
        for json in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
            command
                .env_clear()
                .env("ERPC_HOME", home.path())
                .env("PATH", home.path());
            if let Some(root) = std::env::var_os("SYSTEMROOT") {
                command.env("SYSTEMROOT", root);
            }
            if json {
                command.arg("--json");
            }
            let output = command
                .args([role, "--chain", "solana", "list"])
                .stdin(Stdio::null())
                .output()
                .expect("isolated command route");
            assert_eq!(output.status.code(), Some(0), "{role} json={json}");
            assert!(
                output.stderr.is_empty(),
                "{role} json={json}: the list is not a progress line: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).expect("UTF-8 command output");
            if json {
                assert_eq!(text, format!("{record}\n"), "{role}");
            } else {
                assert!(text.starts_with(hint), "{role}: {text}");
                assert_eq!(text.lines().count(), 1, "{role}: {text}");
            }
        }
    }
}

#[test]
fn a_solana_verb_without_its_network_or_name_is_a_usage_error() {
    // Refused before any vault, 1Password or SSH access.
    let home = tempfile::tempdir().expect("isolated configuration");
    let node = |missing: &str| format!("Solana node operations require {missing}");
    let migration = |missing: &str| format!("migration requires {missing}");
    let plan = [
        "--original-passwd",
        "passwd",
        "--original-group",
        "group",
        "--original-machine-id",
        "machine-id",
    ];
    let migrate = |role: &'static str, action: &'static str, rest: &[&'static str]| {
        let mut line = vec![role, "--chain", "solana", "migration", action];
        line.extend(rest);
        line
    };
    for (arguments, message) in [
        (
            vec!["v", "--chain", "solana", "deploy", "-n", "testnet"],
            node("--name"),
        ),
        (
            vec!["v", "--chain", "solana", "init", "-n", "testnet"],
            node("--name"),
        ),
        (vec!["v", "--chain", "solana", "status"], node("--network")),
        (
            vec!["v", "--chain", "solana", "status", "--name", "tv1"],
            node("--network"),
        ),
        (
            vec!["rpc", "--chain", "solana", "status", "-n", "testnet"],
            node("--name"),
        ),
        (vec!["rpc", "--chain", "solana", "plan"], node("--network")),
        (
            vec!["rpc", "--chain", "solana", "deploy", "-n", "testnet"],
            node("--name"),
        ),
        // `migration`, which is dispatched on its own.
        (
            migrate("v", "status", &["--ssh-key", "k.pub"]),
            migration("--network"),
        ),
        (
            migrate("v", "status", &["--ssh-key", "k.pub", "-n", "testnet"]),
            migration("--name"),
        ),
        (
            migrate("rpc", "resume", &["--ssh-key", "k.pub", "--name", "rpc1"]),
            migration("--network"),
        ),
        (migrate("v", "plan", &plan), migration("--network")),
        (
            migrate("rpc", "plan", &[&plan[..], &["-n", "mainnet"]].concat()),
            migration("--name"),
        ),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
        command
            .env_clear()
            .env("ERPC_HOME", home.path())
            .env("PATH", home.path());
        if let Some(root) = std::env::var_os("SYSTEMROOT") {
            command.env("SYSTEMROOT", root);
        }
        let output = command
            .arg("--json")
            .args(&arguments)
            .stdin(Stdio::null())
            .output()
            .expect("isolated command route");
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stderr.is_empty(), "{arguments:?}");
        let text = String::from_utf8(output.stdout).expect("UTF-8 JSON");
        assert_eq!(text.lines().count(), 1, "{arguments:?}: {text}");
        let record: serde_json::Value = serde_json::from_str(&text).expect("one JSON record");
        let error = &record["error"];
        assert_eq!(error["code"], "usage", "{arguments:?}: {text}");
        assert_eq!(error["exit"], 2, "{arguments:?}: {text}");
        assert_eq!(error["message"], message, "{arguments:?}");
        assert_eq!(
            error["hint"], "add --help to the command to see what it takes",
            "{arguments:?}"
        );
    }
}

/// erpc, isolated: no configuration, no PATH, nothing on standard input.
fn isolated(home: &std::path::Path, arguments: &[&str]) -> std::io::Result<std::process::Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
    command.env_clear().env("ERPC_HOME", home).env("PATH", home);
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", root);
    }
    command.args(arguments).stdin(Stdio::null()).output()
}

#[test]
fn a_solana_node_without_a_saved_vault_is_told_a_command_that_saves_one() {
    // No keyless.toml: refused before 1Password is asked anything.
    let home = tempfile::tempdir().expect("isolated configuration");
    let takes_vault = |role: &str| {
        format!(
            "pass --vault <vault id> (`op vault list` prints them); a new node's init saves it \
             on this machine, see `erpc {role} --chain solana init --help`"
        )
    };
    // `keys` and `vote-account` take no --vault.
    let saved = "a validator's init saves it on this machine with --vault <vault id>; \
                 `erpc v --chain solana init --help` lists what init takes"
        .to_owned();
    for (arguments, network, hint) in [
        (
            &[
                "v", "--chain", "solana", "status", "-n", "testnet", "--name", "tv1",
            ][..],
            "testnet",
            takes_vault("v"),
        ),
        (
            &[
                "rpc", "--chain", "solana", "status", "-n", "mainnet", "--name", "tv1",
            ],
            "mainnet",
            takes_vault("rpc"),
        ),
        (
            &[
                "v", "--chain", "solana", "keys", "-n", "testnet", "--name", "tv1",
            ],
            "testnet",
            saved.clone(),
        ),
        (
            &[
                "v",
                "--chain",
                "solana",
                "vote-account",
                "-n",
                "testnet",
                "--name",
                "tv1",
            ],
            "testnet",
            saved.clone(),
        ),
    ] {
        let mut line = vec!["--json"];
        line.extend(arguments);
        let output = isolated(home.path(), &line).expect("isolated command route");
        assert_eq!(output.status.code(), Some(1), "{arguments:?}");
        assert!(output.stderr.is_empty(), "{arguments:?}");
        let text = String::from_utf8(output.stdout).expect("UTF-8 JSON");
        assert_eq!(text.lines().count(), 1, "{arguments:?}: {text}");
        let record: serde_json::Value = serde_json::from_str(&text).expect("one JSON record");
        assert_eq!(
            record["error"]["message"],
            format!("no vault is set for {network}"),
            "{arguments:?}"
        );
        assert_eq!(record["error"]["hint"], hint, "{arguments:?}");
    }
}

#[test]
fn a_node_command_line_clap_refuses_is_one_json_line_with_clap_words() {
    let home = tempfile::tempdir().expect("isolated configuration");
    for (arguments, message) in [
        (
            &["v", "--chain", "solana", "deploy", "--bogus"][..],
            "unexpected argument '--bogus' found",
        ),
        (
            &[
                "v",
                "--chain",
                "solana",
                "registration",
                "-n",
                "testnet",
                "--name",
                "tv1",
            ],
            "the following required arguments were not provided: \
             --action <action> --bls <bls> --commission <commission>",
        ),
        (
            &[
                "v",
                "--chain",
                "solana",
                "deploy",
                "-n",
                "testnet",
                "--backend",
                "bogus",
            ],
            "invalid value 'bogus' for '--backend <backend>' [possible values: native, solv]",
        ),
    ] {
        let mut line = vec!["--json"];
        line.extend(arguments);
        let output = isolated(home.path(), &line).expect("isolated command route");
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stderr.is_empty(), "{arguments:?}");
        let text = String::from_utf8(output.stdout).expect("UTF-8 JSON");
        assert_eq!(text.lines().count(), 1, "{arguments:?}: {text}");
        let record: serde_json::Value = serde_json::from_str(&text).expect("one JSON record");
        assert_eq!(record["error"]["code"], "usage", "{arguments:?}");
        assert_eq!(record["error"]["message"], message, "{arguments:?}");
        assert_eq!(
            record["error"]["hint"], "add --help to the command to see what it takes",
            "{arguments:?}"
        );
    }
    // Help is the output, whole, not its first line.
    let output = isolated(
        home.path(),
        &["--json", "v", "--chain", "solana", "deploy", "--help"],
    )
    .expect("isolated command route");
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(help.lines().count() > 3, "{help}");
    assert!(help.contains("Usage: erpc validator deploy"), "{help}");
}

/// `erpc worker firewall allow` and `deny` with nothing to change: text
/// for a person, and under `--json` one JSON record, not that text. The
/// answer needs neither the server nor an SSH key: none is here.
#[test]
fn a_firewall_change_with_nothing_to_change_is_text_or_under_json_one_record() {
    let home = tempfile::tempdir().expect("isolated configuration");
    let app = home.path().join("bot");
    std::fs::create_dir_all(&app).expect("the app's directory");
    let manifest = "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n\
                    [env.default]\nhost = \"203.0.113.10\"\n\
                    [env.default.firewall]\nssh_allow = [\"198.51.100.7\"]\n\
                    app_allow = [\"198.51.100.7\"]\n";
    std::fs::write(app.join("erpc.toml"), manifest).expect("erpc.toml");
    let dir = app.to_str().expect("a UTF-8 path");
    let run = |json: bool, verb: &str, address: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
        command
            .env_clear()
            .env("ERPC_HOME", home.path().join("erpc"))
            .env("HOME", home.path())
            .env("PATH", home.path());
        if let Some(root) = std::env::var_os("SYSTEMROOT") {
            command.env("SYSTEMROOT", root);
        }
        if json {
            command.arg("--json");
        }
        let output = command
            .args(["worker", "firewall", verb, "--to", "app", address])
            .args(["--dir", dir])
            .stdin(Stdio::null())
            .output()
            .expect("isolated command route");
        let said = String::from_utf8(output.stdout).expect("UTF-8 output");
        assert!(output.stderr.is_empty(), "{verb} json={json}");
        assert_eq!(said.lines().count(), 1, "{verb} json={json}: {said}");
        (output.status.code(), said)
    };
    for (verb, address, already) in [
        ("allow", "198.51.100.7", "is allowed already"),
        ("deny", "203.0.113.9", "is not allowed already"),
    ] {
        let (code, text) = run(false, verb, address);
        assert_eq!(code, Some(0), "{verb}: {text}");
        let start = format!(
            "nothing to change: {address} {already}; `erpc worker firewall sync --env default --dir "
        );
        assert!(text.starts_with(&start), "{verb}: {text}");
        assert!(
            text.ends_with("` applies erpc.toml again\n"),
            "{verb}: {text}"
        );
        let (code, said) = run(true, verb, address);
        assert_eq!(code, Some(0), "{verb}: {said}");
        let record: serde_json::Value = serde_json::from_str(&said).expect("one JSON record");
        assert_eq!(
            record,
            serde_json::json!({
                "worker": "bot-default",
                "changed": false,
                "erpc_toml": {
                    "ssh_allow": ["198.51.100.7/32"],
                    "app_allow": ["198.51.100.7/32"],
                },
            }),
            "{verb}"
        );
        // What is not an address is refused as that, before the server's
        // address, its host key or an SSH key is looked for.
        let (code, said) = run(true, verb, "nonsense");
        assert_eq!(code, Some(2), "{verb}: {said}");
        let record: serde_json::Value = serde_json::from_str(&said).expect("one JSON record");
        assert_eq!(record["error"]["code"], "usage", "{verb}: {said}");
    }
    // Nothing was written: erpc.toml is as it was.
    assert_eq!(
        std::fs::read_to_string(app.join("erpc.toml")).expect("erpc.toml"),
        manifest
    );
}
