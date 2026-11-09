// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Read independently retained original system-account records, never current NSS.
use erpc_chain::inventory::EthRpc;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{io::Read as _, path::Path};
use zeroize::Zeroizing;

fn input(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let before =
        std::fs::symlink_metadata(path).map_err(|_| "cannot inspect the original backup record")?;
    if !before.is_file() || before.len() > 1024 * 1024 {
        return Err("original backup must be a bounded ordinary file".into());
    }
    let file = std::fs::File::open(path).map_err(|_| "cannot open the original backup record")?;
    let opened = file
        .metadata()
        .map_err(|_| "cannot inspect the opened backup record")?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err("original backup changed while opening it".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (opened.dev(), opened.ino()) != (before.dev(), before.ino()) {
            return Err("original backup identity changed".into());
        }
    }
    let mut raw = Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "cannot read the original backup record")?;
    if raw.len() > 1024 * 1024 {
        return Err("original backup exceeds its bound".into());
    }
    Ok(raw)
}

fn parse(passwd: &[u8], group: &[u8], machine: &[u8]) -> Result<Value, String> {
    let passwd_text =
        std::str::from_utf8(passwd).map_err(|_| "original passwd record is not UTF-8")?;
    let group_text =
        std::str::from_utf8(group).map_err(|_| "original group record is not UTF-8")?;
    let host = std::str::from_utf8(machine)
        .map_err(|_| "original machine identity is not UTF-8")?
        .trim();
    if host.len() != 32
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "original machine-id must be the retained 32-character hexadecimal identity".into(),
        );
    }
    let users: Vec<Vec<&str>> = passwd_text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.split(':').collect())
        .collect();
    let groups: Vec<Vec<&str>> = group_text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.split(':').collect())
        .collect();
    if users.iter().any(|row| row.len() != 7) || groups.iter().any(|row| row.len() != 4) {
        return Err("invalid original account record format".into());
    }
    let matches: Vec<_> = groups.iter().filter(|row| row[0] == "ethereum").collect();
    if matches.len() != 1 {
        return Err("original ethereum group is missing or ambiguous".into());
    }
    let original = matches[0];
    let gid = original[2]
        .parse::<u32>()
        .map_err(|_| "invalid original group identity")?;
    if !(100..=999).contains(&gid)
        || !matches!(original[1], "x" | "*" | "!")
        || original[3]
            .split(',')
            .any(|member| !matches!(member, "" | "reth" | "lighthouse"))
        || groups
            .iter()
            .filter(|row| row[2].parse::<u32>().ok() == Some(gid))
            .count()
            != 1
    {
        return Err("original shared group has unknown authority or aliases".into());
    }
    let mut result = serde_json::Map::new();
    let mut ids = std::collections::BTreeSet::new();
    for name in ["reth", "lighthouse"] {
        let matches: Vec<_> = users.iter().filter(|row| row[0] == name).collect();
        if matches.len() != 1 {
            return Err("original native account is missing or ambiguous".into());
        }
        let row = matches[0];
        let uid = row[2]
            .parse::<u32>()
            .map_err(|_| "invalid original numeric user")?;
        if !(100..=999).contains(&uid)
            || !ids.insert(uid)
            || row[3].parse::<u32>().ok() != Some(gid)
            || row[5] != format!("/var/lib/ethereum/{name}")
            || row[6] != "/usr/sbin/nologin"
            || !matches!(row[1], "x" | "*" | "!")
            || users
                .iter()
                .filter(|entry| entry[2].parse::<u32>().ok() == Some(uid))
                .count()
                != 1
        {
            return Err("original native account profile or numeric isolation differs".into());
        }
        result.insert(name.into(), json!({"uid":uid,"gid":gid}));
    }
    if users.iter().any(|row| {
        row[3].parse::<u32>().ok() == Some(gid) && !matches!(row[0], "reth" | "lighthouse")
    }) {
        return Err("original Ethereum primary group was shared with another account".into());
    }
    Ok(
        json!({"schema":1,"machine":format!("{:x}",Sha256::digest(host.as_bytes())),
        "accounts":{"schema":1,"role":"rpc","groups":{"ethereum":gid},"users":result},
        "records":{"passwd":format!("{:x}",Sha256::digest(passwd)),"group":format!("{:x}",Sha256::digest(group)),"machine":format!("{:x}",Sha256::digest(machine))}}),
    )
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct OpenedSource {
    version: String,
    commit: String,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct OpenedSources {
    reth: OpenedSource,
    lighthouse: OpenedSource,
}
fn opened_sources(raw: &[u8]) -> Result<Value, String> {
    let value: OpenedSources = serde_json::from_slice(raw)
        .map_err(|_| "original highest-opened client records must be closed version/commit JSON")?;
    for source in [&value.reth, &value.lighthouse] {
        let version = source
            .version
            .strip_prefix('v')
            .ok_or("original client version must be canonical stable vMAJOR.MINOR.PATCH")?;
        let fields: Vec<_> = version.split('.').collect();
        if fields.len() != 3
            || fields.iter().any(|part| {
                part.is_empty()
                    || part.len() > 6
                    || !part.bytes().all(|b| b.is_ascii_digit())
                    || (part.len() > 1 && part.starts_with('0'))
            })
            || source.commit.len() != 40
            || !source
                .commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(
                "original highest-opened native version or source commit is invalid".into(),
            );
        }
    }
    serde_json::to_value(value).map_err(|_| "invalid original source records".into())
}

pub(crate) fn read(
    node: &EthRpc,
    network: &str,
    passwd: &Path,
    group: &Path,
    machine: &Path,
    clients: &Path,
) -> Result<Value, String> {
    let mut value = parse(&input(passwd)?, &input(group)?, &input(machine)?)?;
    let raw = input(clients)?;
    value["opened_sources"] = opened_sources(&raw)?;
    value["records"]["opened_sources"] = json!(format!("{:x}", Sha256::digest(&raw)));
    value["contract"] = json!(crate::eth_authority::contract(node, network)?);
    Ok(value)
}

#[cfg(test)]
mod tests {
    const PASSWD: &str = "reth:x:991:990::/var/lib/ethereum/reth:/usr/sbin/nologin\nlighthouse:x:992:990::/var/lib/ethereum/lighthouse:/usr/sbin/nologin\n";
    const GROUP: &str = "ethereum:x:990:\n";
    #[test]
    fn historical_native_source_records_are_explicit_closed_and_stable() {
        let value = serde_json::json!({"reth":{"version":"v2.8.1","commit":"a".repeat(40)},"lighthouse":{"version":"v8.3.2","commit":"b".repeat(40)}});
        assert_eq!(
            super::opened_sources(value.to_string().as_bytes()).unwrap(),
            value
        );
        for tag in [
            "2.8.1",
            "v02.8.1",
            "v2.8.1-beta.1",
            "v2.8",
            "v2.8.1+build",
            "v2.9999999.1",
        ] {
            let mut wrong = value.clone();
            wrong["reth"]["version"] = serde_json::json!(tag);
            assert!(super::opened_sources(wrong.to_string().as_bytes()).is_err());
        }
        let mut wrong = value.clone();
        wrong["reth"]["extra"] = serde_json::json!("inert");
        assert!(super::opened_sources(wrong.to_string().as_bytes()).is_err());
        assert!(super::opened_sources(b"{}").is_err());
    }
    #[test]
    fn original_records_supply_numbers_without_any_live_nss_lookup() {
        let value = super::parse(
            PASSWD.as_bytes(),
            GROUP.as_bytes(),
            "a".repeat(32).as_bytes(),
        )
        .unwrap();
        assert_eq!(value["accounts"]["users"]["reth"]["uid"], 991);
        assert_eq!(value["accounts"]["users"]["lighthouse"]["gid"], 990);
        assert!(!value.to_string().contains("/usr/sbin/nologin"));
        for wrong in [
            format!("{PASSWD}alias:x:991:991::/inert:/bin/sh\n"),
            PASSWD.replace("/usr/sbin/nologin", "/bin/sh"),
            PASSWD.replace("992:990", "991:990"),
        ] {
            assert!(
                super::parse(
                    wrong.as_bytes(),
                    GROUP.as_bytes(),
                    "a".repeat(32).as_bytes()
                )
                .is_err()
            );
        }
        assert!(
            super::parse(
                PASSWD.as_bytes(),
                b"ethereum:x:990:unknown\n",
                "a".repeat(32).as_bytes()
            )
            .is_err()
        );
    }
}

fn backup_rows(raw: &[u8], fields: usize) -> Result<Vec<Vec<&str>>, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "original account backup is not UTF-8")?;
    let rows: Vec<Vec<&str>> = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.split(':').collect())
        .collect();
    if rows.len() > 100_000 || rows.iter().any(|row| row.len() != fields) {
        return Err("invalid original system account backup".into());
    }
    Ok(rows)
}
fn original_number(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|v| (100..=999).contains(v))
        .ok_or_else(|| "original account is not a bounded system identity".into())
}
fn validator_original_accounts(passwd: &[u8], group: &[u8]) -> Result<Value, String> {
    const USERS: [&str; 3] = ["ev-reth", "ev-beacon", "ev-validator"];
    let users = backup_rows(passwd, 7)?;
    let groups = backup_rows(group, 4)?;
    let mut original_groups = serde_json::Map::new();
    let mut gids = std::collections::BTreeSet::new();
    for name in ["ev-engine", "ev-reth", "ev-beacon", "ev-validator"] {
        let rows: Vec<_> = groups.iter().filter(|row| row[0] == name).collect();
        if rows.len() != 1 {
            return Err("original validator group is missing or ambiguous".into());
        }
        let row = rows[0];
        let gid = original_number(row[2])?;
        let allowed: &[&str] = if name == "ev-engine" {
            &["ev-reth", "ev-beacon"]
        } else {
            std::slice::from_ref(&name)
        };
        if !gids.insert(gid)
            || !matches!(row[1], "x" | "*" | "!")
            || row[3]
                .split(',')
                .any(|member| !member.is_empty() && !allowed.contains(&member))
            || groups
                .iter()
                .filter(|value| value[2].parse::<u32>().ok() == Some(gid))
                .count()
                != 1
        {
            return Err("original validator group has aliases or unrelated members".into());
        }
        original_groups.insert(name.into(), json!(gid));
    }
    let mut original_users = serde_json::Map::new();
    let mut uids = std::collections::BTreeSet::new();
    for name in USERS {
        let rows: Vec<_> = users.iter().filter(|row| row[0] == name).collect();
        if rows.len() != 1 {
            return Err("original validator account is missing or ambiguous".into());
        }
        let row = rows[0];
        let uid = original_number(row[2])?;
        let gid = original_number(row[3])?;
        if !uids.insert(uid)
            || original_groups[name] != gid
            || !matches!(row[1], "x" | "*" | "!")
            || (row[5] != "/nonexistent" && row[5] != format!("/home/{name}"))
            || row[6] != "/usr/sbin/nologin"
            || users
                .iter()
                .filter(|value| value[2].parse::<u32>().ok() == Some(uid))
                .count()
                != 1
            || users
                .iter()
                .any(|value| value[0] != name && value[3].parse::<u32>().ok() == Some(gid))
            || groups.iter().any(|value| {
                value[3].split(',').any(|member| member == name)
                    && value[0] != name
                    && !(value[0] == "ev-engine" && name != "ev-validator")
            })
        {
            return Err("original validator account profile or numeric isolation differs".into());
        }
        original_users.insert(
            name.into(),
            json!({"uid":uid,"gid":gid,"home":row[5],"shell":row[6]}),
        );
    }
    let engine = original_groups["ev-engine"]
        .as_u64()
        .ok_or("missing original engine group")?;
    if users
        .iter()
        .any(|row| row[3].parse::<u64>().ok() == Some(engine))
    {
        return Err("original engine-only group was a primary login group".into());
    }
    Ok(json!({"users":original_users,"groups":original_groups}))
}

/// Explicit original validator accounts, without adopting current remote NSS.
pub(crate) fn validator(
    expected: &erpc_chain_eth::authority::Contract,
    signer_pubkey: &str,
    passwd: &Path,
    group: &Path,
    machine: &Path,
    clients: &Path,
) -> Result<Value, String> {
    expected.validate().map_err(str::to_owned)?;
    if expected.role != "validator" {
        return Err("original validator contract required".into());
    }
    if !signer_pubkey.is_empty()
        && (signer_pubkey.len() != 98
            || !signer_pubkey.starts_with("0x")
            || !signer_pubkey[2..]
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)))
    {
        return Err("original inventory signer public key is invalid".into());
    }
    let passwd = input(passwd)?;
    let group = input(group)?;
    let machine = input(machine)?;
    let clients = input(clients)?;
    let original = validator_original_accounts(&passwd, &group)?;
    let host = std::str::from_utf8(&machine)
        .map_err(|_| "invalid original machine identity")?
        .trim();
    if host.len() != 32
        || !host
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err("original machine identity must be retained lowercase hexadecimal".into());
    }
    Ok(
        json!({"schema":1,"contract":expected,"machine":format!("{:x}",Sha256::digest(host.as_bytes())),
        "legacy_accounts":original,"signer_pubkey":signer_pubkey,"opened_sources":opened_sources(&clients)?,
        "records":{"passwd":format!("{:x}",Sha256::digest(&passwd)),"group":format!("{:x}",Sha256::digest(&group)),
        "machine":format!("{:x}",Sha256::digest(&machine)),"opened_sources":format!("{:x}",Sha256::digest(&clients))}}),
    )
}

#[cfg(test)]
mod validator_tests {
    fn original() -> (String, String) {
        ("ev-reth:x:991:991::/home/ev-reth:/usr/sbin/nologin\nev-beacon:x:992:992::/home/ev-beacon:/usr/sbin/nologin\nev-validator:x:993:993::/home/ev-validator:/usr/sbin/nologin\n".into(),
         "ev-engine:x:990:ev-reth,ev-beacon\nev-reth:x:991:\nev-beacon:x:992:\nev-validator:x:993:\n".into())
    }
    #[test]
    fn only_original_three_validator_users_and_isolated_group_authority_are_accepted() {
        let (users, groups) = original();
        let parsed =
            super::validator_original_accounts(users.as_bytes(), groups.as_bytes()).unwrap();
        assert_eq!(parsed["users"]["ev-validator"]["uid"], 993);
        assert_eq!(
            parsed["users"]["ev-validator"]["home"],
            "/home/ev-validator"
        );
        assert!(parsed["users"].get("ev-transport").is_none());
        for changed in [
            users.replace(":993:993:", ":991:993:"),
            users.replace("/home/ev-validator", "/custom/validator"),
            users.replace("ev-validator:x:", "ev-validator:actual-inert-password:"),
            users.clone() + "foreign:x:1993:993::/home/foreign:/bin/sh\n",
            users.clone() + "alias:x:991:1991::/home/alias:/bin/sh\n",
        ] {
            assert!(
                super::validator_original_accounts(changed.as_bytes(), groups.as_bytes()).is_err()
            );
        }
        for changed in [
            groups.replace("ev-reth,ev-beacon", "ev-reth,ev-beacon,foreign"),
            groups.replace("ev-engine:x:990:", "ev-engine:x:991:"),
            groups.clone() + "other:x:800:ev-validator\n",
        ] {
            assert!(
                super::validator_original_accounts(users.as_bytes(), changed.as_bytes()).is_err()
            );
        }
    }
    #[test]
    fn actual_validator_backup_files_produce_only_selected_public_authority_and_source_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let (users, groups) = original();
        let passwd = directory.path().join("passwd");
        let group = directory.path().join("group");
        let machine = directory.path().join("machine");
        let sources = directory.path().join("sources");
        std::fs::write(&passwd, users).unwrap();
        std::fs::write(&group, groups).unwrap();
        std::fs::write(&machine, "b".repeat(32)).unwrap();
        let pins = serde_json::json!({"reth":{"version":"v2.8.1","commit":"c".repeat(40)},"lighthouse":{"version":"v8.3.2","commit":"d".repeat(40)}});
        std::fs::write(&sources, pins.to_string()).unwrap();
        for network in ["mainnet", "hoodi"] {
            let expected = erpc_chain_eth::authority::Contract {
                schema: 1,
                role: "validator".into(),
                owner: "originalfixture".into(),
                network: network.into(),
                kind: "validator".into(),
                host_binding: "a".repeat(64),
            };
            let result =
                super::validator(&expected, "", &passwd, &group, &machine, &sources).unwrap();
            assert_eq!(result["contract"], serde_json::json!(expected));
            assert_eq!(result["opened_sources"], pins);
            assert_eq!(result["records"].as_object().unwrap().len(), 4);
            assert_ne!(result["machine"], "b".repeat(32));
        }
    }
}
