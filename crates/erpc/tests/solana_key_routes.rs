// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The Solana key verbs refuse an implicit chain on mainnet before any provider.
use std::process::{Command, Stdio};

#[test]
fn solana_key_verbs_cannot_use_an_implicit_mainnet_chain() {
    let home = tempfile::tempdir().unwrap();
    for verb in ["keys", "vote-account"] {
        for network in ["mainnet", "testnet"] {
            for explicit in [false, true] {
                let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
                command
                    .env_clear()
                    .env("ERPC_HOME", home.path())
                    .env("HOME", home.path())
                    .env("USERPROFILE", home.path())
                    .env("PATH", home.path())
                    .env("ERPC_CHAIN", "solana");
                if let Some(root) = std::env::var_os("SYSTEMROOT") {
                    command.env("SYSTEMROOT", root);
                }
                command.args(["--json", "v"]);
                if explicit {
                    command.args(["--chain", "solana"]);
                }
                let output = command
                    .args([verb, "--network", network, "--name", "fixture", "--yes"])
                    .stdin(Stdio::null())
                    .output()
                    .unwrap();
                let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                let text = result.to_string();
                let case = format!("{verb} {network} explicit={explicit}: {text}");
                if network == "mainnet" && !explicit {
                    assert_eq!(output.status.code(), Some(2), "{case}");
                    assert!(text.contains("--chain solana"), "{case}");
                    assert!(text.contains("ERPC_CHAIN"), "{case}");
                } else {
                    // Past the guard: there is no vault on this machine.
                    assert_ne!(output.status.code(), Some(2), "{case}");
                    assert!(!text.contains("has to be on the command line"), "{case}");
                }
            }
        }
    }
}
