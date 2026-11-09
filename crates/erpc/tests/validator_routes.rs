// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Run the integrated validator command surfaces with no provider configuration,
//! tools or host selection. These are routing/refusal checks, not node acceptance.
use std::process::{Command, Stdio};

fn isolated(
    args: &[&str],
    home: &std::path::Path,
) -> Result<(std::process::ExitStatus, String), Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
    command.env_clear().env("ERPC_HOME", home).env("PATH", home);
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", root);
    }
    let result = command.args(args).stdin(Stdio::null()).output()?;
    assert!(result.stderr.is_empty(), "{args:?}");
    let text = String::from_utf8(result.stdout)?;
    assert_eq!(text.lines().count(), 1, "{args:?}: {text}");
    let _: serde_json::Value = serde_json::from_str(&text)?;
    Ok((result.status, text))
}

#[test]
fn connected_validator_lifecycles_reject_missing_host_authority_without_generic_fallback() {
    let home = tempfile::tempdir().unwrap();
    for (chain, network) in [
        ("solana", "testnet"),
        ("ethereum", "hoodi"),
        ("avalanche", "fuji"),
        ("arbitrum", "mainnet"),
        ("robinhood", "testnet"),
        ("arc", "testnet"),
        ("polygon", "amoy"),
        ("bsc", "chapel"),
        ("kaia", "kairos"),
        ("monad", "testnet"),
        ("hyperliquid", "testnet"),
        ("near", "testnet"),
        ("tron", "nile"),
        ("sui", "testnet"),
    ] {
        for verb in erpc_core::chain::COMMON_VERBS {
            let (status, text) = isolated(
                &[
                    "--json",
                    "v",
                    "--chain",
                    chain,
                    "--network",
                    network,
                    verb.name,
                ],
                home.path(),
            )
            .expect("isolated JSON validator route");
            assert!(
                !text.contains("not implemented"),
                "{chain} {}: {text}",
                verb.name
            );
            assert!(
                !text.contains("validator N/A"),
                "{chain} {}: {text}",
                verb.name
            );
            if !matches!(verb.name, "list" | "plan") {
                assert!(
                    !status.success(),
                    "{chain} {} succeeded without original authority",
                    verb.name
                );
            }
        }
    }
}

#[test]
fn protocols_without_an_independent_validator_role_do_not_fabricate_lifecycle_success() {
    let home = tempfile::tempdir().unwrap();
    for chain in ["bitcoin", "base", "optimism", "soneium"] {
        for verb in erpc_core::chain::COMMON_VERBS {
            let (status, text) = isolated(
                &[
                    "--json",
                    "v",
                    "--chain",
                    chain,
                    "--network",
                    "mainnet",
                    verb.name,
                ],
                home.path(),
            )
            .expect("isolated JSON validator route");
            assert_eq!(status.code(), Some(2), "{chain} {}: {text}", verb.name);
            assert!(
                text.contains("validator N/A"),
                "{chain} {}: {text}",
                verb.name
            );
        }
    }
}
