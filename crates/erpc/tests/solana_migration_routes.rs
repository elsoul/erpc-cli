// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Mutating migration routes must enforce the mainnet selector before providers.
use std::process::{Command, Stdio};
#[test]
fn original_migration_cannot_use_an_implicit_mainnet_chain() {
    let home = tempfile::tempdir().unwrap();
    for role in ["rpc", "v"] {
        for action in ["resume", "execute"] {
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
                command.args(["--json", role]);
                if explicit {
                    command.args(["--chain", "solana"]);
                }
                command.args(["migration", action]);
                if action == "execute" {
                    command.args([
                        "--original-passwd",
                        "public-passwd",
                        "--original-group",
                        "public-group",
                        "--original-machine-id",
                        "public-machine",
                        "--original-client-record",
                        "public-history",
                        "--original-build-record",
                        "public-build",
                        "--original-keygen-record",
                        "public-keygen",
                        "--management-user",
                        "operator",
                        "--target-accounts-uuid",
                        "10000000-0000-0000-0000-000000000001",
                        "--target-ledger-uuid",
                        "10000000-0000-0000-0000-000000000002",
                        "--target-snapshots-uuid",
                        "10000000-0000-0000-0000-000000000003",
                    ]);
                }
                let output = command
                    .args([
                        "--network",
                        "mainnet",
                        "--name",
                        "fixture",
                        "--ssh-key",
                        "operator.pub",
                        "--yes",
                    ])
                    .stdin(Stdio::null())
                    .output()
                    .unwrap();
                let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert!(output.stderr.is_empty());
                let text = result.to_string();
                if explicit {
                    assert_ne!(output.status.code(), Some(2), "{text}");
                    assert!(!text.contains("write --chain"), "{text}");
                } else {
                    assert_eq!(output.status.code(), Some(2), "{text}");
                    assert!(text.contains("--chain solana"), "{text}");
                }
            }
        }
    }
}
