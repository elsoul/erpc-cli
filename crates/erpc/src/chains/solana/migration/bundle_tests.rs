// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Production `request_bundle` and carried/direct entry composition with inert host facts.
use super::*;
use erpc_chain_solana_native::migration::{OriginalAccount, OriginalBuild};
use erpc_chain_solana_native::migration_request::Request;
use std::io::Write as _;
use std::process::{Command, Stdio};

pub(super) fn fixture(
    rpc: bool,
    network: &str,
) -> Result<(NativeHost, Request), Box<dyn std::error::Error>> {
    // A future deployment catalog must not silently replace the historical
    // executable/compiler evidence used by the original-copy fixture.
    let origins: Value = serde_json::from_slice(
        native::file("node/migration-sources.json").ok_or("original fixture catalog missing")?,
    )?;
    let profile = &origins["sources"][network][0];
    let artifact = OriginalBuild::from_record(
        &serde_json::to_vec(&json!({"schema":1,"client":"agave","network":network,
            "source":profile,
            "executable_sha256":"f".repeat(64),"executable_bytes":8192}))?,
        network,
    )?;
    // Public RFC8032 section 7.1 TEST1; never operational material.
    let original_public = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/";
    let contract: Contract = serde_json::from_value(
        json!({"schema":1,"profile":if rpc{"agave-native-rpc"}else{"agave-native"},
        "inventory_id":"a".repeat(26),"name":"fixture","network":network,
        "host_binding":host_binding("192.0.2.10","operator",2222,key),"identity_account":if rpc{original_public.to_owned()}else{"2".repeat(44)},
        "vote_account":if rpc{Value::Null}else{json!("3".repeat(44))},
        "authority_account":if rpc{Value::Null}else{json!("4".repeat(44))},
        "volumes":{"accounts":"10000000-0000-0000-0000-000000000001","ledger":"10000000-0000-0000-0000-000000000002","snapshots":"10000000-0000-0000-0000-000000000003"}}),
    )?;
    let historical = OriginalAccount::from_sources(
        b"root:x:0:0::/root:/bin/bash\nsolv:x:1001:1101::/home/solv:/bin/bash\n",
        b"root:x:0:\nsolv:x:1101:\n",
        b"11111111111111111111111111111111\n",
    )?;
    let request: Request = serde_json::from_value(
        json!({"action":"migration-reserve","intent":"a".repeat(32),"ssh_port":2222,
        "contract":contract,"legacy":{"network":network,"role":if rpc{"rpc"}else{"validator"},
            "identity_account":contract.identity_account,"vote_account":contract.vote_account,
            "historical":historical,"commission":if rpc{None}else{Some(5)},
            "host_identity":{"role":if rpc{"rpc"}else{"sync"},"path":if rpc{"/home/solv/rpc-identity.json"}else{"/home/solv/unstaked-identity.json"},
                "uid":1001,"gid":1101,"inode":123,"bytes":225,"mtime_ns":1,
                "public":original_public,"bls_public":"2".repeat(66)},
            "management_user":"operator","source_sha256":"a".repeat(64),
            "settings_sha256":"db8624b041fc51d22e4bf5e144bcc1e21d46ea5e1a4efbe739306cff9dc7f743",
            "source_history":{"document_sha256":"b".repeat(64),"highest":{"version":profile["version"],"commit":profile["commit"]}},
            "artifact_evidence":artifact,"keygen_evidence":artifact,"target_volumes":contract.volumes}}),
    )?;
    let node = NativeHost {
        item_version: 1,
        contract,
        address: "192.0.2.10".into(),
        ssh_user: "operator".into(),
        ssh_port: 2222,
        host_key: key.into(),
    };
    node.validate()?;
    request.validate()?;
    Ok((node, request))
}

#[test]
fn compiled_original_migration_bundles_reach_real_carried_and_direct_controllers() {
    for network in ["mainnet", "testnet"] {
        for rpc in [false, true] {
            let (node, mut request) = fixture(rpc, network).unwrap();
            let mut bundles = Vec::new();
            for action in [
                Action::MigrationReserve,
                Action::MigrationRetire,
                Action::MigrationCopy,
                Action::MigrationPromoteData,
                Action::MigrationCustody,
                Action::MigrationPrepareCutover,
                Action::MigrationFinalize,
            ] {
                request.action = action;
                request.validate().unwrap();
                let mut value = serde_json::to_value(&request).unwrap();
                if matches!(
                    action,
                    Action::MigrationPrepareCutover | Action::MigrationFinalize
                ) {
                    let contract = serde_json::to_value(&request.contract).unwrap();
                    value["cutover"] = json!({"receipt":{"schema":1,"intent":request.intent,
                        "inventory_id":request.contract.inventory_id,"reserved_version":2,
                        "source_sha256":request.legacy.source_sha256,
                        "contract_sha256":format!("{:x}",Sha256::digest(serde_json::to_vec(&contract).unwrap())),
                        "config_sha256":"b".repeat(64),
                        "custody_sha256":"3d1f13179711d5f24425c90e5fd23bcd7042c461f6d7f57cca5a32e04d6faf02"},
                        "provider_version":if action==Action::MigrationFinalize{Some(3)}else{None}});
                }
                let built = solana_native::request_bundle(&node, &value).unwrap();
                bundles.push(json!({"action":action,"sha256":built.sha256,"bytes":built.bytes}));
            }
            let control = erpc_ssh::RemoteCommand::SolanaNative(Remote::Control(
                Revision::new(&native::helper_revision().unwrap()).unwrap(),
            ))
            .line();
            let export = erpc_ssh::RemoteCommand::SolanaNative(Remote::MigrationExport(
                Revision::new(&native::helper_revision().unwrap()).unwrap(),
            ))
            .line();
            let packet = json!({"bundles":bundles,"control":control,"export":export});
            let python =
                std::env::var_os("ERPC_TEST_MIGRATION_PYTHON").unwrap_or_else(|| "python3".into());
            let mut child = Command::new(python)
                .args(["-I", "-B"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../erpc-chain-solana-native/tests/migration_bundle.py"
                ))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&serde_json::to_vec(&packet).unwrap())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{network} rpc={rpc}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["actual_carried_stages"], 7);
            assert_eq!(report["rejected_scope_cases"], 3);
            assert_eq!(report["manager_reauthenticated"], true);
            assert_eq!(report["original_data_retained"], true);
            assert_eq!(report["data_recorded_promoted"], true);
            assert_eq!(report["migration_complete"], true);
            assert_eq!(report["runtime_started"], false);
        }
    }
}
