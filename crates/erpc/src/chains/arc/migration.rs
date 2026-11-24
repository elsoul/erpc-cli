// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Explicit historical Arc records; project only the original fixed account and source.
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub(crate) struct Inputs {
    pub enabled: bool,
    pub passwd: Option<PathBuf>,
    pub group: Option<PathBuf>,
    pub machine: Option<PathBuf>,
    pub source: Option<PathBuf>,
}

fn read(path: Option<&Path>) -> Result<zeroize::Zeroizing<String>, String> {
    let path =
        path.ok_or("explicit Arc migration requires all four independent historical records")?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "cannot inspect Arc historical input")?;
    if !metadata.is_file() || metadata.len() > 131_072 {
        return Err("Arc historical input must be a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return Err(
                "Arc historical input must not be linked or writable by other users".into(),
            );
        }
    }
    let file = std::fs::File::open(path).map_err(|_| "cannot open Arc historical input")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let opened = file
            .metadata()
            .map_err(|_| "cannot inspect opened Arc historical input")?;
        if (metadata.dev(), metadata.ino()) != (opened.dev(), opened.ino()) {
            return Err("Arc historical input changed while opening".into());
        }
    }
    let mut value = zeroize::Zeroizing::new(String::new());
    file.take(131_073)
        .read_to_string(&mut value)
        .map_err(|_| "cannot read Arc historical input")?;
    if value.len() > 131_072 {
        return Err("Arc historical input is too large".into());
    }
    Ok(value)
}

fn id(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|v| (100..=2_147_483_647).contains(v) && *v != 65_534)
        .ok_or_else(|| "invalid original Arc numeric identity".into())
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Highest {
    version: String,
    commit: String,
}

pub(crate) fn evidence(inputs: &Inputs) -> Result<Value, String> {
    if !inputs.enabled {
        return Err("historical adoption requires --migrate-authority".into());
    }
    let passwd = read(inputs.passwd.as_deref())?;
    let group = read(inputs.group.as_deref())?;
    let machine = read(inputs.machine.as_deref())?;
    let source = read(inputs.source.as_deref())?;
    let users: Vec<Vec<&str>> = passwd
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split(':').collect())
        .collect();
    let groups: Vec<Vec<&str>> = group
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split(':').collect())
        .collect();
    if users.iter().any(|row| row.len() != 7) || groups.iter().any(|row| row.len() != 4) {
        return Err("unsupported historical Arc passwd/group record format".into());
    }
    let named: Vec<_> = users.iter().filter(|row| row[0] == "arc").collect();
    let named_groups: Vec<_> = groups.iter().filter(|row| row[0] == "arc").collect();
    if named.len() != 1 || named_groups.len() != 1 {
        return Err("historical Arc account is missing or ambiguous".into());
    }
    let user = named[0];
    let g = named_groups[0];
    let uid = id(user[2])?;
    let gid = id(user[3])?;
    if id(g[2])? != gid
        || user[5] != "/var/lib/arc"
        || user[6] != "/usr/sbin/nologin"
        || !g[3]
            .split(',')
            .all(|member| member.is_empty() || member == "arc")
        || users.iter().any(|row| {
            row[0] != "arc"
                && (row[2].parse::<u32>().ok() == Some(uid)
                    || row[3].parse::<u32>().ok() == Some(gid))
        })
        || groups.iter().any(|row| {
            row[0] != "arc"
                && (row[2].parse::<u32>().ok() == Some(gid)
                    || row[3].split(',').any(|member| member == "arc"))
        })
    {
        return Err(
            "historical Arc identity is shared or differs from the supported dedicated profile"
                .into(),
        );
    }
    let machine_text = machine.trim();
    if machine_text.len() != 32
        || !machine_text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid historical Arc machine-id".into());
    }
    let highest: Highest = serde_json::from_str(&source)
        .map_err(|_| "invalid original highest-used Arc source record")?;
    let version = erpc_chain_arc::releases::read(&highest.version)
        .ok_or("invalid historical Arc source version")?;
    if version.pre.is_some()
        || highest.commit.len() != 40
        || !highest
            .commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("historical Arc source must be a stable full commit".into());
    }
    let hash = |raw: &str| format!("{:x}", Sha256::digest(raw.as_bytes()));
    Ok(
        json!({"uid":uid,"gid":gid,"machine":hash(machine_text),"highest":highest,
        "proofs":{"passwd":hash(&passwd),"group":hash(&group),"machine":hash(&machine),"source":hash(&source)}}),
    )
}

#[cfg(test)]
mod tests {
    use super::{Inputs, evidence};
    use std::io::Write as _;

    fn fixture() -> (tempfile::TempDir, Inputs) {
        let root = tempfile::tempdir().unwrap();
        let write = |name: &str, content: &str| {
            let path = root.path().join(name);
            std::fs::write(&path, content).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            Some(path)
        };
        let value = Inputs {
            enabled: true,
            passwd: write(
                "passwd",
                "arc:x:999:999::/var/lib/arc:/usr/sbin/nologin\npublic-decoy:x:1001:1001::/nonselected:/bin/false\n",
            ),
            group: write("group", "arc:x:999:\npublic-decoy:x:1001:\n"),
            machine: write("machine", &"0".repeat(32)),
            source: write(
                "source",
                &serde_json::json!({"version":"v0.8.1","commit":"a".repeat(40)}).to_string(),
            ),
        };
        (root, value)
    }

    #[test]
    fn historical_records_project_only_original_public_identity_and_hashes() {
        let (_root, inputs) = fixture();
        let value = evidence(&inputs).unwrap();
        assert_eq!(value["uid"], 999);
        assert_eq!(value["gid"], 999);
        assert_eq!(value["proofs"].as_object().unwrap().len(), 4);
        assert!(!value.to_string().contains("public-decoy"));
        assert!(!value.to_string().contains("/nonselected"));
        assert!(
            evidence(&Inputs {
                enabled: false,
                ..inputs
            })
            .is_err()
        );
    }

    #[test]
    fn ambiguous_originals_shared_primary_groups_and_unqualified_history_are_refused() {
        for extra in [
            "arc:x:998:998::/var/lib/arc:/usr/sbin/nologin\n",
            "other:x:1001:999::/other:/bin/false\n",
        ] {
            let (_root, inputs) = fixture();
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(inputs.passwd.as_ref().unwrap())
                .unwrap();
            file.write_all(extra.as_bytes()).unwrap();
            assert!(evidence(&inputs).is_err());
        }
        let (_root, inputs) = fixture();
        std::fs::write(
            inputs.source.as_ref().unwrap(),
            r#"{"version":"v0.8.1","commit":"short","unknown":"inert"}"#,
        )
        .unwrap();
        let error = evidence(&inputs).unwrap_err();
        assert!(!error.contains("inert"));
    }

    #[cfg(unix)]
    #[test]
    fn linked_or_writable_historical_files_cannot_become_authority() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        for kind in ["symlink", "hardlink", "mode"] {
            let (root, inputs) = fixture();
            let path = inputs.passwd.as_ref().unwrap();
            match kind {
                "symlink" => {
                    let old = root.path().join("old");
                    std::fs::rename(path, &old).unwrap();
                    symlink(old, path).unwrap();
                }
                "hardlink" => std::fs::hard_link(path, root.path().join("alias")).unwrap(),
                _ => {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
                }
            }
            assert!(evidence(&inputs).is_err(), "{kind}");
        }
    }
}
