// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Independent original ROOT volume record; never reconstruct history from today's mount.
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::path::Path;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalRoot {
    schema: SecretString,
    uuid: SecretString,
    fstype: SecretString,
    inode: u64,
}
fn uuid(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(part, size)| erpc_chain_nitro::validator::hex(part, size))
        && value.bytes().any(|byte| byte != b'0' && byte != b'-')
}
fn parse(raw: &[u8]) -> Result<Value, String> {
    let value: HistoricalRoot =
        serde_json::from_slice(raw).map_err(|_| "invalid historical ROOT volume record")?;
    if value.schema.expose_secret() != "erpc-nitro-original-root-volume-v1"
        || !uuid(value.uuid.expose_secret())
        || !matches!(value.fstype.expose_secret(), "ext4" | "xfs")
        || value.inode == 0
    {
        return Err(
            "historical ROOT record must identify its original UUID, filesystem type and inode"
                .into(),
        );
    }
    Ok(
        json!({"uuid":value.uuid.expose_secret(),"fstype":value.fstype.expose_secret(),
              "inode":value.inode,"record_sha256":format!("{:x}",Sha256::digest(raw))}),
    )
}
pub(crate) fn read(path: Option<&Path>) -> Result<Value, String> {
    let Some(path) = path else {
        return Ok(Value::Null);
    };
    let before =
        std::fs::symlink_metadata(path).map_err(|_| "cannot inspect historical ROOT record")?;
    if !before.is_file() || before.len() > 16384 {
        return Err("historical ROOT record must be a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.nlink() != 1 || before.mode() & 0o022 != 0 {
            return Err(
                "historical ROOT record must not be linked or writable by other users".into(),
            );
        }
    }
    let file = std::fs::File::open(path).map_err(|_| "cannot open historical ROOT record")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let opened = file
            .metadata()
            .map_err(|_| "cannot inspect opened historical ROOT record")?;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err("historical ROOT record changed while opening".into());
        }
    }
    let mut raw = zeroize::Zeroizing::new(Vec::new());
    file.take(16385)
        .read_to_end(&mut raw)
        .map_err(|_| "cannot read historical ROOT record")?;
    if raw.len() > 16384 {
        return Err("historical ROOT record exceeds its bound".into());
    }
    parse(&raw)
}
pub(crate) fn request(
    contract: &erpc_chain_nitro::validator::Contract,
    original: &Value,
) -> Result<Value, String> {
    contract.validate()?;
    Ok(json!({"action":"upgrade-volume-authority","contract":contract,"original_root":original}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Vec<u8> {
        json!({"schema":"erpc-nitro-original-root-volume-v1","uuid":"00000000-0000-0000-0000-000000000001","fstype":"ext4","inode":12345}).to_string().into_bytes()
    }

    #[cfg(unix)]
    #[test]
    fn actual_compiled_upgrade_reaches_carried_play_and_returns_the_bound_stopped_result() {
        use std::io::Write as _;
        let contract = erpc_chain_nitro::validator::Contract {
            owner: "a".repeat(26),
            family: "arbitrum".into(),
            network: "mainnet".into(),
            platform: "amd64".into(),
            role: "assertion-validator".into(),
            wallet: format!("0x{}", "1".repeat(40)),
            creation: "b".repeat(32),
            host_binding: "c".repeat(64),
            data_uuid: "00000000-0000-0000-0000-000000000001".into(),
        };
        let request = request(&contract, &Value::Null).unwrap();
        let inventory = crate::arbitrum_bundle::control_inventory("fixture", &request).unwrap();
        let bundle = crate::arbitrum_bundle::build(&inventory).unwrap();
        let mut child = std::process::Command::new("python3")
            .arg("-B")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/arbitrum_volume_play.py"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&bundle.bytes)
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result = erpc_chain_nitro::validator::public_result(
            &output.stdout,
            "r-original-volume-upgrade",
            &bundle.sha256,
            &crate::arbitrum_bundle::helpers().unwrap(),
            &request,
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"volume_authority":"original","stopped":true,"runtime_started":false})
        );
    }

    #[test]
    fn only_exact_historical_public_fields_enter_the_bound_request() {
        let raw = record();
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed["inode"], 12345);
        assert_eq!(
            parsed["record_sha256"],
            format!("{:x}", Sha256::digest(&raw))
        );
        assert!(read(None).unwrap().is_null());
        for change in [
            json!({"schema":"inert","uuid":"00000000-0000-0000-0000-000000000001","fstype":"ext4","inode":12345}),
            json!({"schema":"erpc-nitro-original-root-volume-v1","uuid":"INERT_PRIVATE_MARKER","fstype":"ext4","inode":12345}),
            json!({"schema":"erpc-nitro-original-root-volume-v1","uuid":"00000000-0000-0000-0000-000000000001","fstype":"ext4","inode":0}),
        ] {
            let error = parse(change.to_string().as_bytes()).unwrap_err();
            assert!(!error.contains("INERT_PRIVATE_MARKER"));
        }
    }

    #[test]
    fn closed_upgrade_request_keeps_original_owner_without_activation_or_key_fields() {
        let contract = erpc_chain_nitro::validator::Contract {
            owner: "a".repeat(26),
            family: "arbitrum".into(),
            network: "mainnet".into(),
            platform: "amd64".into(),
            role: "assertion-validator".into(),
            wallet: format!("0x{}", "1".repeat(40)),
            creation: "b".repeat(32),
            host_binding: "c".repeat(64),
            data_uuid: "00000000-0000-0000-0000-000000000001".into(),
        };
        let value = request(&contract, &parse(&record()).unwrap()).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["action"], "upgrade-volume-authority");
        assert_eq!(value["contract"], serde_json::to_value(&contract).unwrap());
        assert!(value.get("secret").is_none() && value.get("activate").is_none());
        let mut wrong = contract;
        wrong.family = "robinhood".into();
        assert!(request(&wrong, &Value::Null).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_evidence_never_accepts_aliases_or_other_user_writes() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("original-root.json");
        std::fs::write(&path, record()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read(Some(&path)).is_ok());
        let alias = root.path().join("alias.json");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(read(Some(&path)).is_err());
        std::fs::remove_file(&alias).unwrap();
        symlink(&path, &alias).unwrap();
        assert!(read(Some(&alias)).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read(Some(&path)).is_err());
    }
}
