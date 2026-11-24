// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bounded public original-history input; never a signing key or an inferred receipt.
use serde_json::Value;
use std::{io::Read as _, path::Path};

pub(crate) fn read(path: &Path) -> Result<Value, String> {
    let named =
        std::fs::symlink_metadata(path).map_err(|_| "cannot inspect original Sui history path")?;
    if !named.is_file() {
        return Err("original Sui history must be a regular non-symlink file".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "cannot open original Sui source history")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect original Sui history")?;
    if !metadata.is_file() || metadata.len() > 16_384 {
        return Err("original Sui history must be a regular file of at most 16 KiB".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
            || (metadata.dev(), metadata.ino()) != (named.dev(), named.ino())
        {
            return Err(
                "original Sui history must not change or be writable by other users".into(),
            );
        }
    }
    let mut bytes = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read original Sui history")?;
    if bytes.len() > 16_384 {
        return Err("original Sui history exceeds 16 KiB".into());
    }
    parse(&bytes)
}

fn parse(bytes: &[u8]) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "invalid public Sui source history JSON")?;
    let object = value
        .as_object()
        .ok_or("Sui source history must be an object")?;
    if object.len() != 6
        || ![
            "format",
            "contract",
            "service_uid",
            "service_gid",
            "highest_opened",
            "database_state",
        ]
        .iter()
        .all(|key| object.contains_key(*key))
        || value["format"] != 1
    {
        return Err("unsupported Sui source history fields or format".into());
    }
    for name in ["service_uid", "service_gid"] {
        if !value[name]
            .as_u64()
            .is_some_and(|number| (100..=999).contains(&number))
        {
            return Err("Sui history requires its original numeric account receipt".into());
        }
    }
    let contract = value["contract"]
        .as_object()
        .ok_or("Sui history needs its original contract")?;
    if contract.len() != 3
        || !matches!(
            value["contract"]["role"].as_str(),
            Some("fullnode" | "validator")
        )
    {
        return Err("invalid original Sui history contract".into());
    }
    let network = value["contract"]["network"]
        .as_str()
        .and_then(erpc_chain_sui::network::get)
        .ok_or("invalid Sui history network")?;
    if value["contract"]["genesis"] != network.genesis_sha256 {
        return Err("Sui history genesis differs from the selected network".into());
    }
    if !matches!(
        value["database_state"].as_str(),
        Some("never-opened" | "bootstrap-only" | "bootstrap-complete" | "native-opened")
    ) || value["highest_opened"].is_null() != (value["database_state"] == "never-opened")
    {
        return Err("Sui history requires consistent independent database-use evidence".into());
    }
    if !value["highest_opened"].is_null() {
        let source = value["highest_opened"]
            .as_object()
            .ok_or("highest-opened Sui source must be an object")?;
        if source.len() != 4
            || !["version", "commit", "architecture", "archive_sha256"]
                .iter()
                .all(|key| source.get(*key).is_some_and(Value::is_string))
        {
            return Err("invalid highest-opened Sui source fields".into());
        }
        let version = source["version"]
            .as_str()
            .ok_or("missing Sui source version")?;
        let selected = erpc_chain_sui::network::historical(network.name, version)
            .ok_or("Sui original source is not qualified; do not infer or replace its history")?;
        selected.validate_pin(
            version,
            source["commit"].as_str().unwrap_or_default(),
            source["archive_sha256"].as_str().unwrap_or_default(),
            source["architecture"].as_str().unwrap_or_default(),
        )?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn original() -> Value {
        let source = erpc_chain_sui::network::historical("testnet", "testnet-v1.82.2").unwrap();
        json!({"format":1,"database_state":"native-opened","contract":{"network":"testnet","role":"validator","genesis":source.genesis_sha256},
            "service_uid":995,"service_gid":995,"highest_opened":{"version":source.version,"commit":source.commit,
            "architecture":"x86_64","archive_sha256":source.amd64_sha256}})
    }

    #[test]
    fn independent_original_history_refuses_other_network_and_unknown_sources() {
        let value = original();
        assert_eq!(parse(&serde_json::to_vec(&value).unwrap()).unwrap(), value);
        for field in ["version", "commit", "archive_sha256", "architecture"] {
            let mut changed = value.clone();
            changed["highest_opened"][field] = json!("unqualified");
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut changed = value.clone();
        changed["contract"]["network"] = json!("mainnet");
        assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        changed = value;
        changed["highest_opened"] = Value::Null;
        changed["database_state"] = json!("never-opened");
        assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_ok());
        changed["private_key"] = json!("unexpected field must not enter a run bundle");
        assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
    }

    #[test]
    fn original_file_is_bounded_and_regular_before_reading() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.json");
        std::fs::write(&path, serde_json::to_vec(&original()).unwrap()).unwrap();
        assert!(read(&path).is_ok());
        assert!(read(directory.path()).is_err());
        std::fs::write(&path, vec![b'x'; 16_385]).unwrap();
        assert!(read(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn linked_or_mutable_history_is_refused() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.json");
        std::fs::write(&path, serde_json::to_vec(&original()).unwrap()).unwrap();
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read(&path).is_err());
    }
}
