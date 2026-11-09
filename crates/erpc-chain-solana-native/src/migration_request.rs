// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Closed public protocol for original Solv retirement/copy, never key payloads.
use crate::{
    contract::{Contract, Volumes},
    migration::{OriginalAccount, OriginalBuild},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Only existing, independently qualified source-built Agave layouts are eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Dedicated non-voting RPC identity.
    Rpc,
    /// Original logical validator; migration never automatically activates voting.
    Validator,
}
/// One public, independently retained highest-used source identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Highest {
    /// Canonical source version without a leading v.
    pub version: String,
    /// Full original Git commit.
    pub commit: String,
}
/// History evidence is separate from the artifact's exact original build record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    /// SHA256 of the independently supplied original history document.
    pub document_sha256: String,
    /// Highest source ever admitted to the original data.
    pub highest: Highest,
}
/// Public descriptor-bound original host-only identity. No key bytes or references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentity {
    /// Non-voting synchronization or RPC custody role.
    pub role: String,
    /// One fixed original file, never an operator-selected path.
    pub path: String,
    /// Original numeric owner.
    pub uid: u32,
    /// Original numeric group.
    pub gid: u32,
    /// Original file inode; device numbers are observation-only.
    pub inode: u64,
    /// Bounded original file length.
    pub bytes: u64,
    /// Original modification timestamp, compared before private capture.
    pub mtime_ns: u64,
    /// Public key derived and classified before reservation.
    pub public: String,
    /// Same-source native BLS public derivation, excluded from all current vote accounts.
    pub bls_public: String,
}
/// Exact original public inspection input retained throughout migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Original {
    /// Original network.
    pub network: String,
    /// Original runtime role.
    pub role: Role,
    /// Existing recorded public identity; never a regenerated key.
    pub identity_account: String,
    /// Existing public vote account, absent for RPC.
    pub vote_account: Option<String>,
    /// Original public account-file evidence.
    pub historical: OriginalAccount,
    /// Separate management login, not solv or root.
    pub management_user: String,
    /// Original inventory/ownership/history binding, including original item versions.
    pub source_sha256: String,
    /// Canonical public settings digest approved after original read-only inspection.
    pub settings_sha256: String,
    /// Original host-only identity qualified before any service retirement.
    pub host_identity: HostIdentity,
    /// Original observed integer commission; absent for non-voting RPC profiles.
    pub commission: Option<u8>,
    /// Independently recorded highest-used native source.
    pub source_history: History,
    /// Independently recorded original executable/source/compiler evidence.
    pub artifact_evidence: OriginalBuild,
    /// Independent same-source keygen artifact, never inferred from live version output.
    pub keygen_evidence: OriginalBuild,
    /// Three operator-provisioned distinct target filesystems.
    pub target_volumes: Volumes,
}
/// Public stages that never generate, export or import a private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Reserve exact original host evidence before retirement.
    MigrationReserve,
    /// Persistently mask the original unit and retire its original login privileges.
    MigrationRetire,
    /// Confirm that the separate original management login still works.
    MigrationConfirmManager,
    /// Read recorded progress, not current native health.
    MigrationStatus,
    /// Copy retained originals into protected staging.
    MigrationCopy,
    /// Hand off the actual copied inodes while leaving native startup fenced.
    MigrationPromoteData,
    /// Retain only the classified original host-only key in host-bound encryption.
    MigrationCustody,
    /// Export that same retained original only through private-output transport.
    MigrationExport,
    /// Prepare exact provider hashes while native startup remains closed.
    MigrationPrepareCutover,
    /// Acknowledge the same promoted item and durably open native ownership.
    MigrationFinalize,
}
/// Exact public JSON sent over stdin or in the sealed operation bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Explicit stage.
    pub action: Action,
    /// Stable original migration intent.
    pub intent: String,
    /// Qualified original scope.
    pub legacy: Original,
    /// New original native owner, with its durable inventory item ID.
    pub contract: Contract,
    /// Observed SSH port that must remain reachable through retirement.
    pub ssh_port: u16,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
impl Request {
    /// Validate the complete original scope before contacting a host or inventory.
    /// This checks evidence consistency, not the provenance of operator backups.
    /// # Errors
    /// Refuses incomplete history, changed network/role/account/volume, old source
    /// substitution, a runtime management login, and malformed public identifiers.
    pub fn validate(&self) -> Result<(), String> {
        self.contract.validate()?;
        let original = &self.legacy;
        let account = &original.historical;
        let manager = &original.management_user;
        if !hex(&self.intent, 32)
            || self.ssh_port == 0
            || original.network != self.contract.network
            || (original.role == Role::Rpc) != self.contract.is_rpc()
            || original.identity_account != self.contract.identity_account
            || original.vote_account != self.contract.vote_account
            || original.target_volumes != self.contract.volumes
            || (self.contract.is_rpc() && original.commission.is_some())
            || (!self.contract.is_rpc() && original.commission.is_none_or(|v| v > 100))
            || account.uid == 0
            || account.gid == 0
            || account.uid >= 1 << 31
            || account.gid >= 1 << 31
            || manager.is_empty()
            || manager.len() > 32
            || !manager.as_bytes()[0].is_ascii_lowercase()
            || !manager
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
            || [
                "root",
                "solv",
                "erpc-solana",
                "erpc-solana-build",
                "erpc-solana-proof",
                "erpc-solana-gateway",
            ]
            .contains(&manager.as_str())
            || [
                &original.source_sha256,
                &original.settings_sha256,
                &original.source_history.document_sha256,
                &original.artifact_evidence.document_sha256,
                &original.keygen_evidence.document_sha256,
                &account.machine_id_sha256,
                &account.source.passwd,
                &account.source.group,
                &account.source.machine_id,
            ]
            .into_iter()
            .any(|value| !hex(value, 64))
        {
            return Err("original migration ownership or historical evidence differs".into());
        }
        let key = &original.host_identity;
        let rpc = self.contract.is_rpc();
        let expected_role = if rpc { "rpc" } else { "sync" };
        let expected_path = if rpc {
            "/home/solv/rpc-identity.json"
        } else {
            "/home/solv/unstaked-identity.json"
        };
        let mut trial = self.contract.clone();
        trial.identity_account.clone_from(&key.public);
        trial.validate()?;
        if key.role != expected_role
            || key.path != expected_path
            || key.uid != account.uid
            || key.gid != account.gid
            || key.inode == 0
            || key.bytes == 0
            || key.bytes > 4096
            || key.mtime_ns == 0
            || key.bls_public.len() > 66
            || !crate::contract::encoded_key::<48>(&key.bls_public)
            || (rpc && key.public != self.contract.identity_account)
            || (!rpc && key.public == self.contract.identity_account)
        {
            return Err("original host-only identity authority differs".into());
        }
        let build = &original.artifact_evidence;
        let document = serde_json::to_vec(&json!({"schema":1,"client":"agave","network":build.network,
            "source":build.source,"executable_sha256":build.executable_sha256,"executable_bytes":build.executable_bytes}))
            .map_err(|_| "original build evidence cannot be represented")?;
        OriginalBuild::from_record(&document, &original.network)?;
        let keygen = &original.keygen_evidence;
        let record=serde_json::to_vec(&json!({"schema":1,"client":"solana-keygen","network":keygen.network,
            "source":keygen.source,"executable_sha256":keygen.executable_sha256,"executable_bytes":keygen.executable_bytes}))
            .map_err(|_|"original keygen record cannot be represented")?;
        OriginalBuild::keygen_from_record(&record, &original.network)?;
        if keygen.source != build.source {
            return Err("original validator and keygen sources differ".into());
        }

        if build.source.get("version") != Some(&original.source_history.highest.version)
            || build.source.get("commit") != Some(&original.source_history.highest.commit)
        {
            return Err("original executable and highest-used history differ".into());
        }
        Ok(())
    }

    /// Whether this public stage must use a root-sealed operation bundle.
    #[must_use]
    pub const fn requires_sealed_run(&self) -> bool {
        !matches!(
            self.action,
            Action::MigrationConfirmManager | Action::MigrationStatus | Action::MigrationExport
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::SourceDigests;
    fn request() -> Request {
        let origins: serde_json::Value =
            serde_json::from_slice(crate::file("node/migration-sources.json").unwrap()).unwrap();
        let source = origins["sources"]["mainnet"][0].clone();
        let artifact = OriginalBuild::from_record(
            &serde_json::to_vec(
                &json!({"schema":1,"client":"agave","network":"mainnet","source":source,
                "executable_sha256":"f".repeat(64),"executable_bytes":8192}),
            )
            .unwrap(),
            "mainnet",
        )
        .unwrap();
        let contract: Contract=serde_json::from_value(json!({"schema":1,"profile":"agave-native",
            "inventory_id":"a".repeat(26),"name":"fixture","network":"mainnet","host_binding":"b".repeat(64),
            "identity_account":"2".repeat(44),"vote_account":"3".repeat(44),"authority_account":"4".repeat(44),
            "volumes":{"accounts":"10000000-0000-0000-0000-000000000001","ledger":"10000000-0000-0000-0000-000000000002","snapshots":"10000000-0000-0000-0000-000000000003"}})).unwrap();
        Request {
            action: Action::MigrationReserve,
            intent: "a".repeat(32),
            legacy: Original {
                network: contract.network.clone(),
                role: Role::Validator,
                identity_account: contract.identity_account.clone(),
                vote_account: contract.vote_account.clone(),
                historical: OriginalAccount {
                    uid: 1001,
                    gid: 1101,
                    machine_id_sha256: "c".repeat(64),
                    source: SourceDigests {
                        passwd: "d".repeat(64),
                        group: "e".repeat(64),
                        machine_id: "f".repeat(64),
                    },
                },
                management_user: "operator".into(),
                source_sha256: "a".repeat(64),
                settings_sha256: "b".repeat(64),
                host_identity: HostIdentity {
                    role: "sync".into(),
                    path: "/home/solv/unstaked-identity.json".into(),
                    uid: 1001,
                    gid: 1101,
                    inode: 123,
                    bytes: 240,
                    mtime_ns: 1,
                    public: "7".repeat(44),
                    bls_public: "2".repeat(66),
                },
                commission: Some(5),
                source_history: History {
                    document_sha256: "b".repeat(64),
                    highest: Highest {
                        version: artifact.source["version"].clone(),
                        commit: artifact.source["commit"].clone(),
                    },
                },
                keygen_evidence: artifact.clone(),
                artifact_evidence: artifact,
                target_volumes: contract.volumes.clone(),
            },
            contract,
            ssh_port: 2222,
        }
    }
    #[test]
    fn original_public_scope_roundtrips_and_never_contains_key_payload_fields() {
        let original = request();
        original.validate().unwrap();
        let raw = serde_json::to_vec(&original).unwrap();
        assert_eq!(serde_json::from_slice::<Request>(&raw).unwrap(), original);
        for field in ["key_file", "password", "private_key", "withdraw_ref"] {
            let mut value = serde_json::to_value(&original).unwrap();
            value[field] = json!("inert concealed decoy");
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
    }
    #[test]
    fn changed_original_role_history_volume_manager_or_owner_refuses_before_tools() {
        let original = request();
        let mut cases = Vec::new();
        let mut case = original.clone();
        case.legacy.role = Role::Rpc;
        cases.push(case);
        let mut case = original.clone();
        case.legacy.historical.uid = 0;
        cases.push(case);
        let mut case = original.clone();
        case.legacy.management_user = "solv".into();
        cases.push(case);
        let mut case = original.clone();
        case.legacy.source_history.highest.commit = "c".repeat(40);
        cases.push(case);
        let mut case = original.clone();
        case.legacy
            .artifact_evidence
            .source
            .insert("rust".into(), "1.0.0".into());
        cases.push(case);
        let mut case = original.clone();
        case.legacy.target_volumes.accounts = case.legacy.target_volumes.ledger.clone();
        cases.push(case);
        let mut case = original.clone();
        case.ssh_port = 0;
        cases.push(case);
        for case in cases {
            assert!(case.validate().is_err());
        }
    }
    #[test]
    fn private_export_is_never_a_sealed_logged_stage() {
        for action in [
            Action::MigrationReserve,
            Action::MigrationRetire,
            Action::MigrationCopy,
            Action::MigrationPromoteData,
            Action::MigrationCustody,
            Action::MigrationExport,
            Action::MigrationConfirmManager,
            Action::MigrationStatus,
        ] {
            let mut value = request();
            value.action = action;
            assert_eq!(
                value.requires_sealed_run(),
                !matches!(
                    action,
                    Action::MigrationConfirmManager
                        | Action::MigrationStatus
                        | Action::MigrationExport
                )
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn actual_python_controller_accepts_the_compiled_public_request_shape() {
        use std::io::Write as _;
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/node");
        let mut child = std::process::Command::new("python3")
            .args(["-I", "-B", "-c", "import os,sys,json; sys.path.insert(0,sys.argv[1]); import native_migration_retire as m; m.ROOT_UID=os.getuid(); value=m.scope(json.load(sys.stdin)); print(value['intent'])"])
            .arg(source).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&request()).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            "a".repeat(32)
        );
    }
}
