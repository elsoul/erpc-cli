// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Exact Robinhood admitted Defensive validator contract, separate from follower scope.
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

/// Closed Robinhood networks; each has an independently sealed namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Child4663 on Ethereum mainnet.
    Mainnet,
    /// Child46630 on Ethereum Sepolia.
    Testnet,
}
impl Network {
    /// Parse only the two qualified network names.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mainnet" => Some(Self::Mainnet),
            "testnet" => Some(Self::Testnet),
            _ => None,
        }
    }
    /// Canonical public inventory name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
    /// Fixed installed source namespace, distinct from One and the other network.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::Mainnet => "robinhood-mainnet-validator",
            Self::Testnet => "robinhood-testnet-validator",
        }
    }
}

/// Public original host, account and dedicated wallet binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Original public inventory item ID.
    pub owner: String,
    /// Robinhood only; never accepts the One inventory or custody namespace.
    pub family: String,
    /// Mainnet or testnet, bound to a separately sealed profile.
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
    /// Explicit native Defensive rival assertion/stake operation with original history.
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
            || self.family != "robinhood"
            || Network::parse(&self.network).is_none()
            || self.platform != "amd64"
            || self.role != "defensive-validator"
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
            return Err("invalid original Robinhood Defensive validator contract".into());
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
            return Err("invalid Robinhood validator deployment identity".into());
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
        "erpc/robinhood-defensive/ssh/v1",
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
    if value.schema != "erpc-robinhood-defensive-result-v1"
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
pub fn helper_files(
    network: Network,
    upstreams: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut files = crate::validator::helper_files(upstreams)?;
    let selected = format!("robinhood-validator/scopes/{}.py", network.name());
    let scope = crate::TEMPLATES
        .get_file(&selected)
        .ok_or("missing sealed Robinhood scope")?;
    files.insert("scope.py".into(), scope.contents().to_vec());
    let overrides = crate::TEMPLATES
        .get_dir("robinhood-validator/node")
        .ok_or("missing Defensive financial policy")?;
    let expected = ["admission.py", "registration.py", "transactions.py"];
    if overrides.dirs().next().is_some() || overrides.files().count() != expected.len() {
        return Err("unqualified Robinhood helper override set".into());
    }
    for source in overrides.files() {
        let name = source
            .path()
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or("invalid Defensive helper path")?;
        if !expected.contains(&name) || !files.contains_key(name) {
            return Err("unqualified Defensive helper override".into());
        }
        files.insert(name.into(), source.contents().to_vec());
    }
    helpers_digest(&files)?;
    Ok(files)
}

/// Hash the closed sibling profile exactly as the host publication verifier:
/// sorted UTF-8 basename, NUL, then binary SHA256 of its bytes.
/// # Errors
/// Empty, nested, non-Python or duplicate caller names are refused by the map API.
pub fn helpers_digest(files: &BTreeMap<String, Vec<u8>>) -> Result<String, String> {
    crate::validator::helpers_digest(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_networks_have_distinct_closed_original_contracts() {
        let mut value = Contract {
            owner: "a".repeat(26),
            family: "robinhood".into(),
            network: "mainnet".into(),
            platform: "amd64".into(),
            role: "defensive-validator".into(),
            wallet: format!("0x{}", "1".repeat(40)),
            creation: "2".repeat(32),
            host_binding: host_binding("192.0.2.1", "ubuntu", 22, "fixture").unwrap(),
            data_uuid: "10000000-0000-0000-0000-000000000001".into(),
        };
        assert!(value.validate().is_ok());
        value.network = "testnet".into();
        assert!(value.validate().is_ok());
        for network in ["sepolia", "nova", "arbitrum"] {
            value.network = network.into();
            assert!(value.validate().is_err());
        }
        value.network = "mainnet".into();
        value.family = "arbitrum".into();
        assert!(value.validate().is_err());
        value.family = "robinhood".into();
        value.role = "assertion-validator".into();
        assert!(value.validate().is_err());
        assert_ne!(
            host_binding("192.0.2.1", "ubuntu", 22, "fixture").unwrap(),
            crate::validator::host_binding("192.0.2.1", "ubuntu", 22, "fixture").unwrap()
        );
    }
    #[test]
    fn complete_profiles_differ_from_one_and_cannot_share_wallet_or_storage_scope() {
        let one = crate::validator::helper_files(b"# inert shared proxy").unwrap();
        let main = helper_files(Network::Mainnet, b"# inert shared proxy").unwrap();
        let test = helper_files(Network::Testnet, b"# inert shared proxy").unwrap();
        assert_ne!(
            helpers_digest(&one).unwrap(),
            helpers_digest(&main).unwrap()
        );
        assert_ne!(
            helpers_digest(&main).unwrap(),
            helpers_digest(&test).unwrap()
        );
        for (network, files) in [(Network::Mainnet, main), (Network::Testnet, test)] {
            let scope = String::from_utf8(files["scope.py"].clone()).unwrap();
            assert!(scope.contains(network.namespace()));
            assert!(scope.contains("STRATEGY = 'Defensive'"));
            assert_eq!(files["state.py"], one["state.py"]);
            assert_eq!(files["crypto.py"], one["crypto.py"]);
            assert_ne!(files["transactions.py"], one["transactions.py"]);
        }
    }
}
