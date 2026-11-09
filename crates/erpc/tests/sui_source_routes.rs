// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Compiled Sui source-history input guards, without a provider, host or native key.

use std::process::{Command, Stdio};

#[test]
fn original_history_guards_run_before_provider_or_host_access() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("history.json");
    for role in ["rpc", "v"] {
        for network in ["mainnet", "testnet"] {
            for present in [false, true] {
                if present {
                    std::fs::write(&path, b"not a public original history record").unwrap();
                } else if path.exists() {
                    std::fs::remove_file(&path).unwrap();
                }
                let output = Command::new(env!("CARGO_BIN_EXE_erpc"))
                    .args([
                        "--json",
                        role,
                        "--chain",
                        "sui",
                        "--network",
                        network,
                        "update",
                        "--name",
                        "fixture",
                        "--migrate-source-history",
                    ])
                    .arg(&path)
                    .arg("--yes")
                    .env("ERPC_HOME", home.path())
                    .env("PATH", home.path())
                    .env_remove("ERPC_CHAIN")
                    .env_remove("ERPC_NETWORK")
                    .stdin(Stdio::null())
                    .output()
                    .unwrap();
                assert!(!output.status.success());
                let result = String::from_utf8(output.stdout).unwrap();
                assert!(result.contains("history"), "{result}");
                assert!(
                    !result.contains("1Password CLI"),
                    "history must fail before provider access: {result}"
                );
                assert!(!result.contains("not a public original history record"));
                assert!(output.stderr.is_empty());
            }
        }
    }
}
