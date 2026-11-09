// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public historical account evidence for an explicitly selected Solv migration.
//! This parses operator-provided original backups. It does not prove their
//! provenance, infer ownership from current NSS, or authorize a host mutation.
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Digests of the exact independently supplied original files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDigests {
    /// Original passwd file; never a shadow file.
    pub passwd: String,
    /// Original group file.
    pub group: String,
    /// Original machine-id file, including its original line ending.
    pub machine_id: String,
}

/// The original Solv identity to compare against current host observations.
/// Raw account files, password fields and machine-id are not serialized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalAccount {
    /// Historical service/login UID, not a newly resolved name.
    pub uid: u32,
    /// Historical private primary GID.
    pub gid: u32,
    /// SHA256 of the canonical 32-byte original machine-id text.
    pub machine_id_sha256: String,
    /// Exact source file hashes for the retained migration record.
    pub source: SourceDigests,
}

fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn text(raw: &[u8]) -> Result<&str, String> {
    if raw.is_empty() || raw.len() > 1_048_576 {
        return Err("historical account file is empty or exceeds its bound".into());
    }
    std::str::from_utf8(raw).map_err(|_| "historical account file is not UTF-8".into())
}

fn rows(raw: &[u8], count: usize) -> Result<Vec<Vec<&str>>, String> {
    let mut result = Vec::new();
    for line in text(raw)?.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > 4096 || line.chars().any(char::is_control) || result.len() >= 10_000 {
            return Err("historical account record exceeds its format or size bound".into());
        }
        let values: Vec<_> = line.split(':').collect();
        if values.len() != count || values[0].is_empty() || !matches!(values[1], "x" | "*" | "!") {
            return Err(
                "historical account format is unsupported; use public passwd/group backups".into(),
            );
        }
        result.push(values);
    }
    Ok(result)
}

fn number(value: &str) -> Result<u32, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("historical UID/GID is not numeric".into());
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|v| *v < 2_u32.pow(31))
        .ok_or_else(|| "historical UID/GID exceeds its supported range".into())
}

impl OriginalAccount {
    /// Compare a separately observed current account against the historical one.
    /// Other account-file changes do not replace the original numeric authority.
    /// # Errors
    /// Refuses a different machine, UID or primary GID; no correction is performed.
    pub fn verify_observed(&self, current: &Self) -> Result<(), String> {
        if self.uid != current.uid
            || self.gid != current.gid
            || self.machine_id_sha256 != current.machine_id_sha256
        {
            return Err(
                "current host or Solv numeric identity differs from historical evidence".into(),
            );
        }
        Ok(())
    }

    /// Parse the original local Solv account from independent pre-migration backups.
    /// Current-host NSS must be checked separately against this returned evidence.
    /// # Errors
    /// Refuses aliases, shared original groups, root, changed layout, shadow input,
    /// malformed machine identity and ambiguous or oversized historical records.
    pub fn from_sources(passwd: &[u8], group: &[u8], machine_id: &[u8]) -> Result<Self, String> {
        let users = rows(passwd, 7)?;
        let groups = rows(group, 4)?;
        let selected: Vec<_> = users.iter().filter(|row| row[0] == "solv").collect();
        if selected.len() != 1 {
            return Err("historical Solv account is absent or ambiguous".into());
        }
        let user = selected[0];
        let uid = number(user[2])?;
        let gid = number(user[3])?;
        if uid == 0 || gid == 0 || user[5] != "/home/solv" || user[6] != "/bin/bash" {
            return Err("historical Solv account is not the managed nonroot layout".into());
        }
        let mut matches = 0;
        for row in &users {
            let other_uid = number(row[2])?;
            let primary_group = number(row[3])?;
            if other_uid == uid {
                matches += 1;
            }
            if row[0] != "solv" && primary_group == gid {
                return Err("historical Solv primary group was shared".into());
            }
        }
        if matches != 1 {
            return Err("historical Solv UID has another account alias".into());
        }
        let mut matches = 0;
        for row in &groups {
            let observed = number(row[2])?;
            if row[0] == "solv" || observed == gid {
                if row[0] != "solv" || observed != gid || !matches!(row[3], "" | "solv") {
                    return Err("historical Solv group has another name, ID or member".into());
                }
                matches += 1;
            }
        }
        if matches != 1 {
            return Err("historical Solv group is absent or ambiguous".into());
        }
        if machine_id.len() > 34 {
            return Err("historical machine identity exceeds its bound".into());
        }
        let machine = text(machine_id)?.trim_end_matches(['\r', '\n']);
        if machine.len() != 32
            || !machine
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || machine.bytes().all(|b| b == b'0')
        {
            return Err("historical machine identity is invalid".into());
        }
        Ok(Self {
            uid,
            gid,
            machine_id_sha256: digest(machine.as_bytes()),
            source: SourceDigests {
                passwd: digest(passwd),
                group: digest(group),
                machine_id: digest(machine_id),
            },
        })
    }
}

/// Independently retained original build association, never synthesized from a live host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalBuild {
    /// Digest of the exact public evidence file supplied before host inspection.
    pub document_sha256: String,
    /// Network whose reviewed source/compiler this original build identifies.
    pub network: String,
    /// Exact reviewed source/compiler fields; their provenance remains operator evidence.
    pub source: std::collections::BTreeMap<String, String>,
    /// Original executable digest from the independent artifact record.
    pub executable_sha256: String,
    /// Exact original executable size, bounded before observing a process image.
    pub executable_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRecord {
    schema: u8,
    client: String,
    network: String,
    source: std::collections::BTreeMap<String, String>,
    executable_sha256: String,
    executable_bytes: u64,
}
/// Preserve reviewed original build identities independently of future targets.
fn qualified_original_source(
    network: &str,
    want: &std::collections::BTreeMap<String, String>,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Originals {
        schema: u8,
        git_sources: std::collections::BTreeMap<String, Vec<String>>,
        sources:
            std::collections::BTreeMap<String, Vec<std::collections::BTreeMap<String, String>>>,
    }
    let bytes =
        crate::file("node/migration-sources.json").ok_or("original source catalog missing")?;
    let values: Originals =
        serde_json::from_slice(bytes).map_err(|_| "invalid original source catalog")?;
    if values.schema != 1
        || want
            .get("commit")
            .and_then(|commit| values.git_sources.get(commit))
            .is_none_or(Vec::is_empty)
    {
        return Err("invalid original source catalog schema".into());
    }
    values
        .sources
        .get(network)
        .and_then(|items| items.iter().find(|item| *item == want))
        .cloned()
        .ok_or_else(|| "original source/compiler is outside the reviewed migration origins".into())
}
impl OriginalBuild {
    /// Qualify a separately retained original artifact record against this CLI's source profile.
    /// This compares evidence; it does not authenticate who produced the original record or
    /// claim that a local executable hash alone proves reproducible source provenance.
    /// # Errors
    /// Refuses missing/extra fields, another network/source/compiler, or invalid artifact bounds.
    pub fn from_record(raw: &[u8], network: &str) -> Result<Self, String> {
        Self::from_client_record(raw, network, "agave", 4 * 1024 * 1024 * 1024)
    }
    /// Qualify the independently retained same-source public keygen artifact.
    /// Version output alone never grants permission to execute a legacy binary.
    /// # Errors
    /// Refuses another client, source/compiler, network or oversized artifact.
    pub fn keygen_from_record(raw: &[u8], network: &str) -> Result<Self, String> {
        Self::from_client_record(raw, network, "solana-keygen", 128 * 1024 * 1024)
    }
    fn from_client_record(
        raw: &[u8],
        network: &str,
        client: &str,
        maximum: u64,
    ) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > 16384 {
            return Err("original build record exceeds its bound".into());
        }
        let record: BuildRecord =
            serde_json::from_slice(raw).map_err(|_| "invalid independent original build record")?;
        let source = qualified_original_source(network, &record.source)?;
        if record.schema != 1
            || record.client != client
            || record.network != network
            || record.source != source
            || record.executable_sha256.len() != 64
            || !record
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || record.executable_sha256.bytes().all(|byte| byte == b'0')
            || record.executable_bytes == 0
            || (client == "solana-keygen" && record.executable_bytes < 64)
            || record.executable_bytes > maximum
        {
            return Err("original artifact lacks the qualified source/compiler or bounded executable identity; preserve Solv operation".into());
        }
        Ok(Self {
            document_sha256: digest(raw),
            network: network.into(),
            source,
            executable_sha256: record.executable_sha256,
            executable_bytes: record.executable_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const USERS: &str = "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:manager:/home/ubuntu:/bin/bash\nsolv:x:1001:1101:runtime:/home/solv:/bin/bash\n";
    const GROUPS: &str = "root:x:0:\nsudo:x:27:ubuntu,solv\nubuntu:x:1000:\nsolv:x:1101:\n";
    const MACHINE: &str = "11111111111111111111111111111111\n";

    fn original_profile(network: &str) -> serde_json::Value {
        let origins: serde_json::Value =
            serde_json::from_slice(crate::file("node/migration-sources.json").unwrap()).unwrap();
        origins["sources"][network][0].clone()
    }

    #[test]
    fn public_keygen_record_requires_its_own_client_kind_and_same_reviewed_original_source() {
        let profile = original_profile("mainnet");
        let mut value = serde_json::json!({"schema":1,"client":"solana-keygen","network":"mainnet","source":profile,"executable_sha256":"a".repeat(64),"executable_bytes":640});
        let raw = serde_json::to_vec(&value).unwrap();
        assert!(OriginalBuild::keygen_from_record(&raw, "mainnet").is_ok());
        assert!(OriginalBuild::from_record(&raw, "mainnet").is_err());
        value["client"] = serde_json::json!("agave");
        assert!(
            OriginalBuild::keygen_from_record(&serde_json::to_vec(&value).unwrap(), "mainnet")
                .is_err()
        );
        value["client"] = serde_json::json!("solana-keygen");
        value["executable_bytes"] = serde_json::json!(128 * 1024 * 1024 + 1);
        assert!(
            OriginalBuild::keygen_from_record(&serde_json::to_vec(&value).unwrap(), "mainnet")
                .is_err()
        );
    }

    #[test]
    fn original_build_record_is_independent_bounded_and_qualified_before_host_observation() {
        let profile = original_profile("mainnet");
        let value = serde_json::json!({"schema":1,"client":"agave","network":"mainnet",
            "source":profile,
            "executable_sha256":"a".repeat(64),"executable_bytes":123_456});
        let raw = serde_json::to_vec(&value).unwrap();
        let record = OriginalBuild::from_record(&raw, "mainnet").unwrap();
        assert_eq!(record.document_sha256, digest(&raw));
        assert_eq!(record.executable_bytes, 123_456);
        assert!(OriginalBuild::from_record(&raw, "testnet").is_err());
        for field in [
            "version",
            "commit",
            "cargo_lock_sha256",
            "rust",
            "rust_manifest_sha256",
        ] {
            let mut wrong = value.clone();
            wrong["source"][field] = serde_json::json!("unqualified");
            assert!(
                OriginalBuild::from_record(&serde_json::to_vec(&wrong).unwrap(), "mainnet")
                    .is_err()
            );
        }
        for size in [0, 4 * 1024 * 1024 * 1024_u64 + 1] {
            let mut wrong = value.clone();
            wrong["executable_bytes"] = serde_json::json!(size);
            assert!(
                OriginalBuild::from_record(&serde_json::to_vec(&wrong).unwrap(), "mainnet")
                    .is_err()
            );
        }
        let mut private = value;
        private["private_key"] = serde_json::json!("inert-private-marker");
        let error = OriginalBuild::from_record(&serde_json::to_vec(&private).unwrap(), "mainnet")
            .unwrap_err();
        assert!(!error.contains("inert-private-marker"));
    }
    #[test]
    fn newer_deployment_targets_do_not_expand_original_migration_qualification() {
        for network in ["mainnet", "testnet"] {
            let original = original_profile(network);
            let mut record = serde_json::json!({"schema":1,"client":"agave","network":network,
                "source":original,"executable_sha256":"a".repeat(64),"executable_bytes":123_456});
            assert!(
                OriginalBuild::from_record(&serde_json::to_vec(&record).unwrap(), network).is_ok()
            );
            // This forward deployment target is not one of the separately
            // reviewed original Solv sources. Test data never changes that list.
            record["source"]["version"] = serde_json::json!("4.4.0");
            record["source"]["commit"] =
                serde_json::json!("9ef63128134af559561f6a91a641ec01e665c70d");
            assert!(
                OriginalBuild::from_record(&serde_json::to_vec(&record).unwrap(), network).is_err()
            );
            record["client"] = serde_json::json!("solana-keygen");
            assert!(
                OriginalBuild::keygen_from_record(&serde_json::to_vec(&record).unwrap(), network)
                    .is_err()
            );
        }
    }

    #[test]
    fn historical_numeric_evidence_does_not_infer_current_names_or_export_raw_files() {
        let evidence =
            OriginalAccount::from_sources(USERS.as_bytes(), GROUPS.as_bytes(), MACHINE.as_bytes())
                .unwrap();
        assert_eq!((evidence.uid, evidence.gid), (1001, 1101));
        let json = serde_json::to_string(&evidence).unwrap();
        assert!(!json.contains("manager"));
        assert!(!json.contains("/home/solv"));
        assert!(!json.contains(MACHINE.trim()));
        let changed = OriginalAccount::from_sources(
            USERS.as_bytes(),
            GROUPS.as_bytes(),
            MACHINE.trim().as_bytes(),
        )
        .unwrap();
        assert_eq!(evidence.machine_id_sha256, changed.machine_id_sha256);
        assert_ne!(evidence.source.machine_id, changed.source.machine_id);
    }

    #[test]
    fn aliases_shared_group_root_and_foreign_layout_are_refused() {
        for users in [
            USERS.replace("solv:x:1001:1101", "solv:x:0:0"),
            USERS.replace("/home/solv", "/srv/other"),
            USERS.replace("solv:x:", "foreign:x:"),
            format!("{USERS}alias:x:1001:1200::/home/alias:/bin/bash\n"),
            format!("{USERS}other:x:1200:1101::/home/other:/bin/bash\n"),
            format!("{USERS}solv:x:1002:1200::/home/solv:/bin/bash\n"),
        ] {
            assert!(
                OriginalAccount::from_sources(
                    users.as_bytes(),
                    GROUPS.as_bytes(),
                    MACHINE.as_bytes()
                )
                .is_err()
            );
        }
        for groups in [
            GROUPS.replace("solv:x:1101:", "solv:x:1101:ubuntu"),
            format!("{GROUPS}alias:x:1101:\n"),
            format!("{GROUPS}solv:x:1200:\n"),
        ] {
            assert!(
                OriginalAccount::from_sources(
                    USERS.as_bytes(),
                    groups.as_bytes(),
                    MACHINE.as_bytes()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn current_observation_cannot_replace_original_numeric_or_machine_identity() {
        let original =
            OriginalAccount::from_sources(USERS.as_bytes(), GROUPS.as_bytes(), MACHINE.as_bytes())
                .unwrap();
        let mut current = original.clone();
        current.uid += 1;
        assert!(original.verify_observed(&current).is_err());
        current = original.clone();
        current.gid += 1;
        assert!(original.verify_observed(&current).is_err());
        current = original.clone();
        current.machine_id_sha256 = "f".repeat(64);
        assert!(original.verify_observed(&current).is_err());
        let unrelated =
            format!("{USERS}new-package:x:2000:2000:package:/nonexistent:/usr/sbin/nologin\n");
        let current = OriginalAccount::from_sources(
            unrelated.as_bytes(),
            GROUPS.as_bytes(),
            MACHINE.as_bytes(),
        )
        .unwrap();
        assert_ne!(original.source.passwd, current.source.passwd);
        original.verify_observed(&current).unwrap();
    }

    #[test]
    fn malformed_private_or_oversized_source_is_not_reflected_in_diagnostics() {
        let marker = "inert-private-field-marker";
        let input = USERS.replace("solv:x:", &format!("solv:{marker}:"));
        let error =
            OriginalAccount::from_sources(input.as_bytes(), GROUPS.as_bytes(), MACHINE.as_bytes())
                .unwrap_err();
        assert!(!error.contains(marker));
        for machine in [
            "",
            "0".repeat(32).as_str(),
            "inert-private-field-marker",
            "11111111111111111111111111111111 ",
        ] {
            assert!(
                OriginalAccount::from_sources(
                    USERS.as_bytes(),
                    GROUPS.as_bytes(),
                    machine.as_bytes()
                )
                .is_err()
            );
        }
        assert!(
            OriginalAccount::from_sources(
                &vec![b'x'; 1_048_577],
                GROUPS.as_bytes(),
                MACHINE.as_bytes()
            )
            .is_err()
        );
        assert!(
            OriginalAccount::from_sources(&[255], GROUPS.as_bytes(), MACHINE.as_bytes()).is_err()
        );
    }
}
