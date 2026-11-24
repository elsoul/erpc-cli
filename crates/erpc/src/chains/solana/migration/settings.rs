// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Closed public settings shown before original migration approval.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const CHANGES: [&str; 6] = [
    "original data paths move to independently reserved copied volumes",
    "native service uses isolated original numeric accounts and encrypted credentials",
    "RPC binds loopback behind the authenticated native gateway",
    "gossip and dynamic ports use the fixed native ingress profile",
    "bootstrap identities and entrypoints use the fixed native network catalog",
    "voting remains disabled until separate original registration and history validation",
];
const LEADER: &str =
    "remove no-wait-for-vote-to-start-leader; retain native rooted-vote leader safety";
const FLAGS: [&str; 7] = [
    "--wal-recovery-mode",
    "--use-snapshot-archives-at-startup",
    "--limit-ledger-size",
    "--limit-blockstore-size",
    "--expected-shred-version",
    "--no-port-check",
    "--no-skip-initial-accounts-db-clean",
];
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Overrides {
    path: String,
    sha256: String,
    canonical_text: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    schema: u8,
    arguments: Vec<String>,
    overrides: Option<Overrides>,
    changes: Vec<String>,
}
pub(crate) struct Approved {
    pub digest: String,
    pub public: Value,
}
fn invalid() -> String {
    "original public migration settings are not qualified".into()
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
impl Overrides {
    fn validate(&self, rpc: bool, network: &str) -> Result<(), String> {
        if rpc
            || network != "mainnet"
            || self.path != "/home/solv/overrides.yml"
            || !hash(&self.sha256)
            || !self.canonical_text.is_ascii()
            || self.canonical_text.len() > 16384
        {
            return Err(invalid());
        }
        let body = self
            .canonical_text
            .strip_prefix("staked_map_id:\n")
            .and_then(|v| v.strip_suffix('\n'))
            .ok_or_else(invalid)?;
        let mut previous = "";
        let mut count = 0;
        for line in body.split('\n') {
            let (key, amount) = line
                .strip_prefix("  ")
                .and_then(|v| v.split_once(": "))
                .ok_or_else(invalid)?;
            erpc_chain_solana::validator_profile::public_bytes(key, 32).map_err(|_| invalid())?;
            let number = amount.parse::<u64>().map_err(|_| invalid())?;
            if key <= previous || amount != number.to_string() {
                return Err(invalid());
            }
            previous = key;
            count += 1;
        }
        if !(1..=64).contains(&count) {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Settings {
    fn validate(&self, rpc: bool, network: &str) -> Result<(), String> {
        let permitted = CHANGES
            .iter()
            .copied()
            .chain((rpc && self.changes.len() == 7).then_some(LEADER));
        if self.schema != 1
            || self.arguments.len() > 16
            || !self.changes.iter().map(String::as_str).eq(permitted)
        {
            return Err(invalid());
        }
        let mut index = 0;
        let mut last = None;
        let mut retention = false;
        while index < self.arguments.len() {
            let flag = &self.arguments[index];
            index += 1;
            let position = FLAGS.iter().position(|v| v == flag).ok_or_else(invalid)?;
            if last.is_some_and(|old| position <= old) {
                return Err(invalid());
            }
            last = Some(position);
            if position >= 5 {
                continue;
            }
            let value = self.arguments.get(index).ok_or_else(invalid)?;
            index += 1;
            let valid = match position {
                0 => value == "skip_any_corrupted_record",
                1 => matches!(value.as_str(), "when-newest" | "always" | "never"),
                _ => {
                    !value.is_empty()
                        && value.len() <= 12
                        && value.bytes().all(|v| v.is_ascii_digit())
                }
            };
            if !valid {
                return Err(invalid());
            }
            if matches!(position, 2 | 3) {
                if retention {
                    return Err(invalid());
                }
                retention = true;
            }
            if position == 4 && value.parse::<u16>().is_err() {
                return Err(invalid());
            }
        }
        if let Some(value) = &self.overrides {
            value.validate(rpc, network)?;
        }
        Ok(())
    }
}
pub(crate) fn inspect(observation: &Value, rpc: bool, network: &str) -> Result<Approved, String> {
    let value = &observation["inspection"];
    if !matches!(network, "mainnet" | "testnet")
        || value["settings"].as_object().is_none_or(|object| {
            object.len() != 4
                || !["schema", "arguments", "overrides", "changes"]
                    .iter()
                    .all(|key| object.contains_key(*key))
        })
    {
        return Err(invalid());
    }

    let settings: Settings =
        serde_json::from_value(value["settings"].clone()).map_err(|_| invalid())?;
    settings.validate(rpc, network)?;
    let public = serde_json::to_value(settings).map_err(|_| invalid())?;
    let bytes = serde_json::to_vec(&public).map_err(|_| invalid())?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    if value["settings_sha256"].as_str() != Some(digest.as_str()) {
        return Err("original migration settings digest differs from the inspected plan".into());
    }
    Ok(Approved { digest, public })
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn observed(settings: &Value) -> Value {
        let sha = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(settings).unwrap())
        );
        json!({"inspection":{"settings":settings,"settings_sha256":sha}})
    }
    #[test]
    fn canonical_empty_policy_matches_the_actual_native_protocol() {
        let value =
            observed(&json!({"schema":1,"arguments":[],"overrides":null,"changes":CHANGES}));
        assert_eq!(
            inspect(&value, true, "mainnet").unwrap().digest,
            "db8624b041fc51d22e4bf5e144bcc1e21d46ea5e1a4efbe739306cff9dc7f743"
        );
        let mut changed = value;
        changed["inspection"]["settings"]["arguments"] = json!(["--no-port-check"]);
        assert!(inspect(&changed, true, "mainnet").is_err());
    }
    #[test]
    fn unsafe_arguments_private_fields_and_unapproved_changes_never_reach_preview() {
        let original = json!({"schema":1,"arguments":[],"overrides":null,"changes":CHANGES});
        for arguments in [
            json!(["--identity", "INERT_PRIVATE_MARKER"]),
            json!(["--no-wait-for-vote-to-start-leader"]),
            json!(["--limit-ledger-size", "1", "--limit-blockstore-size", "1"]),
            json!(["--expected-shred-version", "65536"]),
        ] {
            let mut value = original.clone();
            value["arguments"] = arguments;
            assert!(inspect(&observed(&value), true, "mainnet").is_err());
        }
        let mut extra = original;
        extra["private_key"] = json!("INERT_PRIVATE_MARKER");
        assert!(inspect(&observed(&extra), true, "mainnet").is_err());
    }
    #[test]
    fn required_nullable_fields_and_leader_guard_changes_remain_explicit() {
        let mut settings = json!({"schema":1,"arguments":[],"overrides":null,"changes":CHANGES});
        let mut missing = settings.clone();
        missing.as_object_mut().unwrap().remove("overrides");
        assert!(inspect(&observed(&missing), true, "mainnet").is_err());
        settings["changes"]
            .as_array_mut()
            .unwrap()
            .push(json!(LEADER));
        assert!(inspect(&observed(&settings), true, "mainnet").is_ok());
        assert!(inspect(&observed(&settings), false, "mainnet").is_err());
        assert!(inspect(&observed(&settings), true, "unqualified").is_err());
    }
    #[test]
    fn override_projection_is_canonical_public_data_and_role_bound() {
        let key = "2".repeat(44);
        let mut value = json!({"schema":1,"arguments":[],"overrides":{"path":"/home/solv/overrides.yml","sha256":"a".repeat(64),
            "canonical_text":format!("staked_map_id:\n  {key}: 1\n")},"changes":CHANGES});
        assert!(inspect(&observed(&value), false, "mainnet").is_ok());
        assert!(inspect(&observed(&value), true, "mainnet").is_err());
        assert!(inspect(&observed(&value), false, "testnet").is_err());
        value["overrides"]["canonical_text"] = json!(format!(
            "staked_map_id:\n  {key}: 1\n# INERT_PRIVATE_MARKER\n"
        ));
        assert!(inspect(&observed(&value), false, "mainnet").is_err());
    }
}
