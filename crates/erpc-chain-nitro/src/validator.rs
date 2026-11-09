// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Exact Arbitrum One assertion-validator contract, separate from follower scope.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Qualified native version; changes require a jointly reviewed host catalog.
pub const VERSION: &str = "3.12.2";
/// Resolved upstream source revision.
pub const COMMIT: &str = "5f02f3f03076343061f167e81b8e82ec5518064b";
/// Exact Linux amd64 OCI manifest.
pub const IMAGE: &str = "docker.io/offchainlabs/nitro-node@sha256:c908f324a08b7332d1fa031b83b071cfa2d9edd8a364c4344d7c34b665bf08e9";
/// Expected local immutable OCI configuration identity.
pub const IMAGE_ID: &str =
    "sha256:10de676fe40c8ff6046d9ad113db2e587877442c77df013559a342ea3a81757a";

/// Public original host, account and dedicated wallet binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Original public inventory item ID.
    pub owner: String,
    /// Arbitrum only.
    pub family: String,
    /// One mainnet only; no admission claim for other Nitro chains.
    pub network: String,
    /// Reviewed native platform.
    pub platform: String,
    /// Immutable assertion-validator role.
    pub role: String,
    /// Original dedicated lowercase public EVM address.
    pub wallet: String,
    /// Original wallet creation intent, retained on ambiguous creation.
    pub creation: String,
    /// Canonical SSH address, login, port and pinned key binding.
    pub host_binding: String,
    /// Original filesystem UUID observed before reservation.
    pub data_uuid: String,
}

/// Desired runtime mode; observing never implies validator readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Local validation without granting the native signing key.
    Observing,
    /// Explicit native assertion/challenge operation with original history.
    Active,
}

/// Reviewed native and complete carried source target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    /// Explicit desired mode.
    pub phase: Phase,
    /// Qualified native version.
    pub version: String,
    /// Resolved source commit.
    pub commit: String,
    /// Exact manifest reference.
    pub image: String,
    /// Exact OCI configuration digest.
    pub image_id: String,
    /// Digest of every carried Python sibling.
    pub helpers_sha256: String,
    /// Digest of public credential references and firewall configuration.
    pub config_id: String,
}

/// Lowercase fixed-size hexadecimal, without prefixes.
#[must_use]
pub fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Canonical identifier used by the inventory service.
#[must_use]
pub fn identifier(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
impl Contract {
    /// Refuse foreign scope and malformed original ownership metadata.
    /// # Errors
    /// Returns a static error without reflecting inventory values.
    pub fn validate(&self) -> Result<(), String> {
        let uuid = self.data_uuid.split('-').collect::<Vec<_>>();
        if !identifier(&self.owner)
            || self.family != "arbitrum"
            || self.network != "mainnet"
            || self.platform != "amd64"
            || self.role != "assertion-validator"
            || !self
                .wallet
                .strip_prefix("0x")
                .is_some_and(|v| hex(v, 40) && v.bytes().any(|b| b != b'0'))
            || !hex(&self.creation, 32)
            || !hex(&self.host_binding, 64)
            || uuid.len() != 5
            || !uuid
                .iter()
                .zip([8, 4, 4, 4, 12])
                .all(|(part, size)| hex(part, size))
            || !self.data_uuid.bytes().any(|b| b != b'0' && b != b'-')
        {
            return Err("invalid original Arbitrum One validator contract".into());
        }
        Ok(())
    }
}
impl Deployment {
    /// Construct an exact catalog target from the complete helper/config digests.
    /// # Errors
    /// Invalid public digests are refused.
    pub fn new(phase: Phase, helpers_sha256: String, config_id: String) -> Result<Self, String> {
        if !hex(&helpers_sha256, 64) || !hex(&config_id, 64) {
            return Err("invalid Arbitrum validator deployment identity".into());
        }
        Ok(Self {
            phase,
            version: VERSION.into(),
            commit: COMMIT.into(),
            image: IMAGE.into(),
            image_id: IMAGE_ID.into(),
            helpers_sha256,
            config_id,
        })
    }
}

/// Domain-separated SSH authority binding. Inputs must first pass the SSH target
/// parser; their exact canonical values are retained in public inventory.
/// # Errors
/// Invalid port or empty/control-containing fields are refused.
pub fn host_binding(
    address: &str,
    user: &str,
    port: u16,
    host_key: &str,
) -> Result<String, String> {
    if port == 0
        || [address, user, host_key]
            .iter()
            .any(|v| v.is_empty() || v.chars().any(char::is_control))
    {
        return Err("invalid original SSH authority".into());
    }
    let encoded = serde_json::to_vec(&(
        "erpc/arbitrum-validator/ssh/v1",
        address,
        user,
        port,
        host_key,
    ))
    .map_err(|_| "cannot encode original SSH authority")?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicResult {
    schema: String,
    run: String,
    bundle_sha256: String,
    helpers_sha256: String,
    request_sha256: String,
    result: serde_json::Value,
}

/// Canonical sorted compact public JSON digest, shared with the carried publisher.
/// # Errors
/// Encoding failure is reported without reflecting the request.
pub fn request_digest(request: &serde_json::Value) -> Result<String, String> {
    let bytes =
        serde_json::to_vec(request).map_err(|_| "cannot encode public validator request")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Bind the externally authenticated completed result to this exact invocation.
/// # Errors
/// Extra fields, oversized output, stale source/request or foreign run are refused.
pub fn public_result(
    raw: &[u8],
    run: &str,
    bundle: &str,
    helpers: &str,
    request: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    if raw.len() > 262_144 {
        return Err("validator public result exceeds limit".into());
    }
    let value: PublicResult =
        serde_json::from_slice(raw).map_err(|_| "invalid validator public result")?;
    if value.schema != "erpc-arbitrum-public-result-v1"
        || value.run != run
        || value.bundle_sha256 != bundle
        || value.helpers_sha256 != helpers
        || value.request_sha256 != request_digest(request)?
        || !value.result.is_object()
        || !hex(bundle, 64)
        || !hex(helpers, 64)
    {
        return Err("validator public result is not bound to this exact invocation".into());
    }
    Ok(value.result)
}

/// Collect every carried sibling and the reviewed shared upstream proxy.
/// # Errors
/// Missing source, nested paths or an already present proxy are refused.
pub fn helper_files(upstreams: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let source = crate::TEMPLATES
        .get_dir("validator/node")
        .ok_or("missing validator helper sources")?;
    if source.dirs().next().is_some() {
        return Err("nested validator helper source profile".into());
    }
    let mut files = BTreeMap::new();
    for file in source.files() {
        let name = file
            .path()
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or("invalid helper basename")?;
        if files
            .insert(name.into(), file.contents().to_vec())
            .is_some()
        {
            return Err("duplicate helper basename".into());
        }
    }
    if files
        .insert("upstreams.py".into(), upstreams.to_vec())
        .is_some()
    {
        return Err("shared proxy is duplicated in validator source profile".into());
    }
    helpers_digest(&files)?;
    Ok(files)
}

/// Hash the closed sibling profile exactly as the host publication verifier:
/// sorted UTF-8 basename, NUL, then binary SHA256 of its bytes.
/// # Errors
/// Empty, nested, non-Python or duplicate caller names are refused by the map API.
pub fn helpers_digest(files: &BTreeMap<String, Vec<u8>>) -> Result<String, String> {
    if files.is_empty()
        || files.keys().any(|name| {
            std::path::Path::new(name).extension() != Some(std::ffi::OsStr::new("py"))
                || name.contains('/')
                || name.contains('\\')
                || name
                    .bytes()
                    .any(|b| !(b.is_ascii_alphanumeric() || b"_.-".contains(&b)))
        })
    {
        return Err("invalid complete Arbitrum helper profile".into());
    }
    let mut digest = Sha256::new();
    for (name, bytes) in files {
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(Sha256::digest(bytes));
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_scope_and_ssh_authority_cannot_drift() {
        let mut c = Contract {
            owner: "a".repeat(26),
            family: "arbitrum".into(),
            network: "mainnet".into(),
            platform: "amd64".into(),
            role: "assertion-validator".into(),
            wallet: format!("0x{}", "1".repeat(40)),
            creation: "2".repeat(32),
            host_binding: host_binding("192.0.2.1", "ubuntu", 22, "fixture-key").unwrap(),
            data_uuid: "00000000-0000-0000-0000-000000000001".into(),
        };
        assert!(c.validate().is_ok());
        for network in ["nova", "sepolia", "testnet"] {
            c.network = network.into();
            assert!(c.validate().is_err());
        }
        assert_ne!(
            host_binding("192.0.2.1", "ubuntu", 22, "fixture-key").unwrap(),
            host_binding("192.0.2.1", "ubuntu", 2222, "fixture-key").unwrap()
        );
        assert!(host_binding("192.0.2.1", "ubuntu", 0, "fixture-key").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn serialized_catalog_is_accepted_by_the_actual_host_protocol() {
        use std::io::Write;
        let target = Deployment::new(Phase::Observing, "a".repeat(64), "b".repeat(64)).unwrap();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/validator/node");
        let code = "import json,sys;sys.dont_write_bytecode=True;sys.path.insert(0,sys.argv[1]);import protocol,storage,hashlib;value=json.load(sys.stdin);protocol.target(value['target']);assert value['target']['phase']=='observing';assert hashlib.sha256(storage.encode(value['request'])).hexdigest()==value['request_sha256']";
        let mut child = std::process::Command::new("python3")
            .args(["-I", "-B", "-c", code])
            .arg(dir)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&serde_json::json!({"target":target,"request":{"action":"preflight"},"request_sha256":request_digest(&serde_json::json!({"action":"preflight"})).unwrap()})).unwrap())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn public_preflight_results_require_exact_source_request_and_run() {
        let request = serde_json::json!({"action":"preflight"});
        let mut output = serde_json::json!({"schema":"erpc-arbitrum-public-result-v1","run":"r-public-fixture","bundle_sha256":"a".repeat(64),"helpers_sha256":"b".repeat(64),"request_sha256":request_digest(&request).unwrap(),"result":{"data_uuid":"00000000-0000-0000-0000-000000000001"}});
        let check = |value: &serde_json::Value| {
            public_result(
                &serde_json::to_vec(value).unwrap(),
                "r-public-fixture",
                &"a".repeat(64),
                &"b".repeat(64),
                &request,
            )
        };
        assert!(check(&output).is_ok());
        for field in ["run", "bundle_sha256", "helpers_sha256", "request_sha256"] {
            let mut changed = output.clone();
            changed[field] = serde_json::json!("wrong");
            assert!(check(&changed).is_err());
        }
        output["unexpected"] = serde_json::json!(true);
        assert!(check(&output).is_err());
    }

    #[test]
    fn helper_digest_includes_names_and_all_bytes() {
        let files = BTreeMap::from([
            ("a.py".into(), b"one".to_vec()),
            ("b.py".into(), b"two".to_vec()),
        ]);
        let original = helpers_digest(&files).unwrap();
        let mut changed = files.clone();
        changed.insert("b.py".into(), b"three".to_vec());
        assert_ne!(original, helpers_digest(&changed).unwrap());
        let mut renamed = files;
        let bytes = renamed.remove("a.py").unwrap();
        renamed.insert("c.py".into(), bytes);
        assert_ne!(original, helpers_digest(&renamed).unwrap());
        renamed.insert("../unsafe.py".into(), Vec::new());
        assert!(helpers_digest(&renamed).is_err());
    }
}
