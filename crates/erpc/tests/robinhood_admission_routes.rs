// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Real CLI guards run before providers, SSH, private input or financial actions.
use std::process::{Command, Stdio};

#[test]
fn admission_actions_use_the_specific_public_route_without_provider_access() {
    let home = tempfile::tempdir().unwrap();
    let wallet = format!("0x{}", "1".repeat(40));
    for network in ["mainnet", "testnet"] {
        for action in ["status", "prepare", "validate"] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
            command
                .env_clear()
                .env("ERPC_HOME", home.path())
                .env("PATH", home.path());
            if let Some(root) = std::env::var_os("SYSTEMROOT") {
                command.env("SYSTEMROOT", root);
            }
            let result = command
                .args([
                    "--json",
                    "v",
                    "--chain",
                    "robinhood",
                    "registration",
                    "--network",
                    network,
                    "--action",
                    action,
                    "--validator-address",
                    &wallet,
                ])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(1));
            assert!(result.stderr.is_empty());
            let text = String::from_utf8(result.stdout).unwrap();
            assert_eq!(text.lines().count(), 1);
            let _: serde_json::Value = serde_json::from_str(&text).unwrap();
            let expected = if action == "validate" {
                "validation requires --file"
            } else {
                "original Robinhood RPC inventory host"
            };
            assert!(text.contains(expected), "{action}: {text}");
            assert!(!text.contains("1Password") && !text.contains("not implemented"));
        }
    }
}

#[test]
fn malformed_public_intent_is_redacted_before_inventory_or_provider_access() {
    let home = tempfile::tempdir().unwrap();
    let input = home.path().join("invalid-public-intent.json");
    std::fs::write(&input, br#"{"private_input":"INERT_PRIVATE_MARKER"}"#).unwrap();
    let wallet = format!("0x{}", "1".repeat(40));
    let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
    command
        .env_clear()
        .env("ERPC_HOME", home.path())
        .env("PATH", home.path());
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", root);
    }
    let result = command
        .args([
            "--json",
            "v",
            "--chain",
            "robinhood",
            "registration",
            "--network",
            "testnet",
            "--action",
            "validate",
            "--validator-address",
            &wallet,
            "--file",
        ])
        .arg(input)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stderr.is_empty());
    let text = String::from_utf8(result.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains("invalid closed public admission intent"));
    assert!(!text.contains("INERT_PRIVATE_MARKER") && !text.contains("1Password"));
}
