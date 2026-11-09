// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Explicit public source history for a previously managed native data owner.
use crate::{node_common, solana_native};
use erpc_chain::inventory::solana_native::NativeHost;
use erpc_chain_solana_native as native;
use erpc_ssh::{Session, Target};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{io::Read as _, path::Path};

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Pre {
    Number(u64),
    Word(String),
}
fn precedence(value: &str) -> Result<(Vec<u64>, bool, Vec<Pre>), &'static str> {
    if value.is_empty() || value.len() > 128 {
        return Err("invalid original client version");
    }
    let value = value.strip_prefix('v').unwrap_or(value);
    let (core, suffix) = value
        .split_once('-')
        .map_or((value, None), |(core, pre)| (core, Some(pre)));
    let number = |part: &str| {
        if part.is_empty()
            || !part.bytes().all(|v| v.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return Err("invalid original client version");
        }
        part.parse::<u64>()
            .map_err(|_| "original version exceeds its numeric bound")
    };
    let core = core.split('.').map(number).collect::<Result<Vec<_>, _>>()?;
    if core.len() != 3 {
        return Err("original client version requires major.minor.patch");
    }
    let mut labels = Vec::new();
    if let Some(pre) = suffix {
        for label in pre.split('.') {
            if label.is_empty()
                || !label
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || v == b'-')
            {
                return Err("invalid original prerelease version");
            }
            labels.push(if label.bytes().all(|v| v.is_ascii_digit()) {
                Pre::Number(number(label)?)
            } else {
                Pre::Word(label.into())
            });
        }
    }
    Ok((core, suffix.is_none(), labels))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u8,
    client: String,
    network: String,
    version: String,
    commit: String,
}
fn validate(raw: &[u8], network: &str) -> Result<(), String> {
    if raw.is_empty() || raw.len() > 16384 {
        return Err("original client record exceeds its bound".into());
    }
    let record: Record =
        serde_json::from_slice(raw).map_err(|_| "invalid original public client record")?;
    if record.schema != 1
        || record.client != "agave"
        || record.network != network
        || record.commit.len() != 40
        || !record
            .commit
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err("original client record has another schema, client, network or commit".into());
    }
    precedence(&record.version)?;
    Ok(())
}
pub(crate) fn read(path: &Path, network: &str) -> Result<String, String> {
    let before =
        std::fs::symlink_metadata(path).map_err(|_| "original client record is unavailable")?;
    if !before.is_file() || before.len() == 0 || before.len() > 16384 {
        return Err("original client record must be a bounded regular file, not a symlink".into());
    }
    let file = std::fs::File::open(path).map_err(|_| "original client record cannot be opened")?;
    let opened = file
        .metadata()
        .map_err(|_| "original client record cannot be inspected")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("original client record changed while opening".into());
        }
    }
    if !opened.is_file()
        || opened.len() != before.len()
        || opened.modified().ok() != before.modified().ok()
    {
        return Err("original client record changed while opening".into());
    }
    let mut raw = zeroize::Zeroizing::new(Vec::new());
    (&file)
        .take(16385)
        .read_to_end(&mut raw)
        .map_err(|_| "original client record cannot be read")?;
    let after = file
        .metadata()
        .map_err(|_| "original client record cannot be reinspected")?;
    if after.len() != opened.len()
        || after.modified().ok() != opened.modified().ok()
        || raw.len() as u64 != opened.len()
    {
        return Err("original client record changed while reading".into());
    }
    validate(&raw, network)?;
    String::from_utf8(raw.to_vec()).map_err(|_| "original client record is not UTF-8".into())
}

pub(crate) fn check_target(
    profile: &native::Profile,
    observed: &Value,
) -> Result<(), &'static str> {
    if observed["opening_protocol"] != 1 {
        return Err(
            "upgrade this existing native host with init --upgrade-source-authority --original-client-record before deployment",
        );
    }
    if observed["prepared"] != true {
        return Err("complete the original source-authority preparation before deployment");
    }
    let highest = &observed["highest"];
    if highest.is_null() {
        return Ok(());
    }
    let version = highest["version"]
        .as_str()
        .ok_or("native source history is unavailable")?;
    let desired = precedence(&profile.version)?;
    let previous = precedence(version)?;
    if desired < previous {
        return Err("desired native version is below the original data-opening floor");
    }
    if desired == previous {
        for (key, target) in [
            ("commit", &profile.commit),
            ("cargo_lock_sha256", &profile.cargo_lock_sha256),
            ("rust", &profile.rust),
            ("rust_manifest_sha256", &profile.rust_manifest_sha256),
        ] {
            if (key == "commit" || highest.get(key).is_some())
                && highest[key].as_str() != Some(target.as_str())
            {
                return Err(
                    "desired native source or compiler differs at the original data-opening version",
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn apply(
    node: &NativeHost,
    session: &Session,
    target: &Target,
    document: &str,
    say: &node_common::Say,
) -> Result<Value, String> {
    let request = json!({"action":"upgrade-source-authority","contract":node.contract,"original_client_record":document});
    let bundle = solana_native::request_bundle(node, &request)?;
    let run = erpc_ops::run::start(
        session,
        &bundle,
        "ansible/solana-native/upgrade-source-authority.yml",
    )
    .map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Resume the explicit upgrade with the same original source-history record",
        say,
    )?;
    if !result.ok() {
        return Err("original source-authority upgrade is incomplete; preserve its records and resume with the same history".into());
    }
    let after = solana_native::probe(session, node)?;
    if after["helper_revision"].as_str() != Some(native::helper_revision()?.as_str()) {
        return Err("source-authority upgrade did not publish the current verified helpers".into());
    }
    let observed = solana_native::control(session, node, "opening-authority")?;
    Ok(
        json!({"name":node.contract.name,"network":node.contract.network,"source_authority_upgraded":true,
        "runtime_started":false,"opening_authority":observed,"next_operation":"deploy with the qualified client"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_core::chain::{Chain, Role};

    fn record() -> Value {
        json!({"schema":1,"client":"agave","network":"mainnet","version":"4.3.2","commit":"c".repeat(40)})
    }
    #[test]
    fn only_explicit_original_public_history_is_read_and_input_errors_do_not_echo_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public-history.json");
        let bytes = serde_json::to_vec(&record()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(read(&path, "mainnet").unwrap().as_bytes(), bytes);
        assert!(read(&path, "testnet").is_err());
        for (key, value) in [
            ("schema", json!(true)),
            ("client", json!("jito")),
            ("version", json!("4.3")),
            ("commit", json!("inert-private-marker")),
            ("unknown", json!("inert-private-marker")),
        ] {
            let mut wrong = record();
            wrong[key] = value;
            std::fs::write(&path, wrong.to_string()).unwrap();
            let error = read(&path, "mainnet").unwrap_err();
            assert!(!error.contains("inert-private-marker"));
        }
        assert!(read(dir.path(), "mainnet").is_err());
        std::fs::write(&path, vec![b' '; 16385]).unwrap();
        assert!(read(&path, "mainnet").is_err());
        #[cfg(unix)]
        {
            std::fs::write(&path, &bytes).unwrap();
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read(&link, "mainnet").is_err());
        }
    }
    #[test]
    fn actual_native_flags_require_both_history_and_explicit_upgrade_and_refuse_legacy_workflow() {
        for role in [Role::Rpc, Role::Validator] {
            let command = crate::tree::command(role, Chain::Solana);
            command.clone().debug_assert();
            for tail in [
                vec!["--upgrade-source-authority"],
                vec!["--original-client-record", "history.json"],
            ] {
                let mut args = vec![role.as_str(), "init"];
                args.extend(tail);
                assert!(command.clone().try_get_matches_from(args).is_err());
            }
            let parsed = command
                .try_get_matches_from([
                    role.as_str(),
                    "init",
                    "--upgrade-source-authority",
                    "--original-client-record",
                    "history.json",
                ])
                .unwrap();
            let args = parsed.subcommand().unwrap().1;
            assert!(solana_native::flag(args, "upgrade-source-authority"));
            assert!(crate::solana_backend::legacy_options(args).is_err());
        }
    }
    #[test]
    fn public_plan_uses_semver_order_and_preserves_same_version_source_binding() {
        let order = [
            "4.4.0-alpha",
            "4.4.0-alpha.1",
            "4.4.0-alpha.beta",
            "4.4.0-beta",
            "4.4.0-beta.2",
            "4.4.0-beta.10",
            "4.4.0-rc.1",
            "4.4.0",
            "4.4.1",
        ];
        assert!(
            order
                .windows(2)
                .all(|pair| precedence(pair[0]).unwrap() < precedence(pair[1]).unwrap())
        );
        for bad in ["4.3", "04.3.2", "4.3.2-beta.01", "4.3.2+unknown", "4.3.2\n"] {
            assert!(precedence(bad).is_err());
        }
        let catalog = native::catalog().unwrap();
        let profile = &catalog.networks["mainnet"];
        let mut observation = json!({"opening_protocol":1,"prepared":true,"highest":{
            "version":profile.version,"commit":profile.commit}});
        check_target(profile, &observation).unwrap();
        observation["highest"]["commit"] = json!("f".repeat(40));
        assert!(check_target(profile, &observation).is_err());
        observation["highest"] = json!({"version":"99.0.0","commit":"f".repeat(40)});
        assert!(check_target(profile, &observation).is_err());
        assert!(check_target(profile, &Value::Null).is_err());
    }
}

#[cfg(all(test, unix))]
#[test]
fn emitted_upgrade_bundle_reaches_the_actual_controller_with_the_original_public_record() {
    use native::contract::{Contract, Volumes};
    let node = NativeHost {
        item_version: 1,
        contract: Contract {
            schema: 1,
            profile: "agave-native".into(),
            inventory_id: "a".repeat(26),
            name: "fixture".into(),
            network: "mainnet".into(),
            host_binding: "b".repeat(64),
            identity_account: "2".repeat(44),
            vote_account: Some("3".repeat(44)),
            authority_account: Some("4".repeat(44)),
            volumes: Volumes {
                accounts: "10000000-0000-0000-0000-000000000001".into(),
                ledger: "10000000-0000-0000-0000-000000000002".into(),
                snapshots: "10000000-0000-0000-0000-000000000003".into(),
            },
        },
        address: "192.0.2.20".into(),
        ssh_user: "operator".into(),
        ssh_port: 22,
        host_key: "public test fixture".into(),
    };
    let catalog = native::catalog().unwrap();
    let profile = &catalog.networks["mainnet"];
    let document = json!({"schema":1,"client":"agave","network":"mainnet","version":profile.version,"commit":profile.commit}).to_string();
    validate(document.as_bytes(), "mainnet").unwrap();
    let request = json!({"action":"upgrade-source-authority","contract":node.contract,"original_client_record":document});
    let bundle = solana_native::request_bundle(&node, &request).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sealed-fixture.tar.gz");
    std::fs::write(&path, bundle.bytes).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../erpc-chain-solana-native/tests/source_upgrade.py");
    let result = std::process::Command::new("python3")
        .arg("-B")
        .arg(script)
        .arg("--bundle")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
