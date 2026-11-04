// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Small first-party bootstrap metadata, pinned before any large node download.

use erpc_chain_rollup::profile::{Family, Profile};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

const MAX_METADATA: usize = 16 * 1024 * 1024;
const OP_ROOT: &str = "https://datadirs.optimism.io/";
const FULL_HISTORY_BLOCKS: u64 = 13_392_000;
const BASE_COMPONENTS: [&str; 8] = [
    "state",
    "headers",
    "transactions",
    "transaction_senders",
    "receipts",
    "account_changesets",
    "storage_changesets",
    "rocksdb_indices",
];
const BASE_API: &str = "https://chain.base.org/api/snapshots";

/// Immutable public bootstrap pin. The large manifest itself stays outside inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// `genesis`, `op-archive` or `base-manifest`.
    pub kind: String,
    /// Official HTTPS archive or manifest URL, absent for genesis sync.
    pub url: String,
    /// SHA-256 of the exact archive/manifest bytes.
    pub sha256: String,
    /// Initial provisioning policy, reduced only by allocated partial bootstrap data.
    pub required_free_bytes: u64,
    /// L2 network identifier.
    pub chain_id: u64,
}

/// A pin and optional bounded manifest bytes ready to carry in a deployment bundle.
#[derive(Debug)]
pub struct Prepared {
    /// Safe public record for the node inventory.
    pub pin: Pin,
    /// Base's immutable local manifest; never provider credentials.
    pub manifest: Option<Vec<u8>>,
}

fn capacity(profile: Profile, archive: bool) -> u64 {
    let gb = match (profile.family, profile.network == "mainnet", archive) {
        (Family::Base, true, true) => 18_000,
        (Family::Base, true, false) | (Family::Optimism, true, true) => 4_000,
        (Family::Base, false, true) => 6_000,
        (Family::Base, false, false) | (_, true, _) | (_, false, true) => 2_000,
        (_, false, false) => 1_000,
    };
    gb * 1_000_000_000
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("erpc-rollup-bootstrap")
        .build()
        .map_err(|_| "cannot create bootstrap metadata client".into())
}

async fn get(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    erpc_core::endpoints::ensure_service_url(url)
        .map_err(|_| "bootstrap host is not registered")?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "bootstrap metadata request failed")?;
    if !response.status().is_success() {
        return Err("bootstrap metadata is unavailable".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "bootstrap metadata transfer failed")?
    {
        if bytes.len() + chunk.len() > MAX_METADATA {
            return Err("bootstrap metadata exceeds limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|v| v.is_ascii_hexdigit())
}
fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || b"-_.".contains(&v))
        })
}
fn base_host(profile: Profile) -> &'static str {
    if profile.network == "mainnet" {
        "mainnet-v2-snapshots.base.org"
    } else {
        "sepolia-v2-snapshots.base.org"
    }
}
fn base_url(profile: Profile, raw: &str, manifest: bool) -> bool {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    if url.scheme() != "https"
        || url.host_str() != Some(base_host(profile))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    if !manifest {
        return url.path() == "/";
    }
    let parts: Vec<_> = url.path().split('/').collect();
    parts.len() == 3
        && parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[1].bytes().all(|b| b.is_ascii_digit())
        && parts[2] == "manifest.json"
}

fn outputs(files: &Value) -> Result<u64, String> {
    let files = files
        .as_array()
        .filter(|v| !v.is_empty())
        .ok_or("snapshot has no output integrity records")?;
    let mut total = 0u64;
    for file in files {
        if !file["path"].as_str().is_some_and(safe_relative)
            || !file["blake3"].as_str().is_some_and(hash)
        {
            return Err("unsafe snapshot output path or integrity record".into());
        }
        total = total
            .checked_add(file["size"].as_u64().ok_or("invalid output size")?)
            .ok_or("snapshot output size overflow")?;
    }
    Ok(total)
}

fn component_shape(component: &Value, block: u64) -> Result<(), String> {
    if let Some(file) = component["file"].as_str() {
        if !safe_relative(file) || component["size"].as_u64().is_none() {
            return Err("unsafe snapshot archive".into());
        }
        let size = outputs(&component["output_files"])?;
        if component["decompressed_size"].as_u64() != Some(size) {
            return Err("inconsistent snapshot output size".into());
        }
        return Ok(());
    }
    let files = component["chunk_files"]
        .as_array()
        .ok_or("snapshot chunk paths are missing")?;
    let integrity = component["chunk_output_files"]
        .as_array()
        .ok_or("snapshot chunk integrity is missing")?;
    let sizes = component["chunk_sizes"]
        .as_array()
        .ok_or("snapshot chunk sizes missing")?;
    let plain = component["chunk_decompressed_sizes"]
        .as_array()
        .ok_or("snapshot expanded sizes missing")?;
    let span = component["blocks_per_file"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("invalid snapshot chunk span")?;
    if component["total_blocks"].as_u64() != Some(block)
        || files.len() as u64 != block.div_ceil(span)
        || [integrity.len(), sizes.len(), plain.len()]
            .iter()
            .any(|n| *n != files.len())
    {
        return Err("inconsistent snapshot chunks".into());
    }
    for (index, file) in files.iter().enumerate() {
        if !file.as_str().is_some_and(safe_relative)
            || sizes[index].as_u64().is_none()
            || plain[index].as_u64() != Some(outputs(&integrity[index])?)
        {
            return Err("unsafe or inconsistent snapshot chunk".into());
        }
    }
    Ok(())
}

fn base_manifest(profile: Profile, bytes: &[u8]) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "invalid Base snapshot manifest")?;
    if value["chain_id"].as_u64() != Some(profile.chain_id)
        || value["storage_version"] != 2
        || !value["base_url"]
            .as_str()
            .is_some_and(|url| base_url(profile, url, false))
    {
        return Err("Base snapshot network/storage/source mismatch".into());
    }
    let block = value["block"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("snapshot block is missing")?;
    let components = value["components"]
        .as_object()
        .filter(|c| BASE_COMPONENTS.iter().all(|name| c.contains_key(*name)))
        .ok_or("required snapshot components are missing")?;
    for (name, component) in components {
        if !BASE_COMPONENTS.contains(&name.as_str()) && name != "proofs" {
            return Err("unknown snapshot component".into());
        }
        component_shape(component, block)?;
    }
    Ok(value)
}

/// Validate all paths and integrity records before the official downloader reads them.
/// # Errors
/// Wrong chain/storage, alternate hosts, traversal and missing integrity data fail closed.
pub fn validate_base_manifest(profile: Profile, bytes: &[u8]) -> Result<(), String> {
    base_manifest(profile, bytes).map(|_| ())
}

/// Apply Base's `(2 × database + compressed snapshot) × 1.2` provisioning formula
/// to exactly the components selected by the pinned v1.5.1 downloader. Its full
/// preset retains 13,392,000 blocks, so catalog `fullSize` is not authoritative.
/// # Errors
/// Incomplete or inconsistent manifests and integer overflow fail closed.
pub fn base_capacity(profile: Profile, archive: bool, bytes: &[u8]) -> Result<u64, String> {
    let value = base_manifest(profile, bytes)?;
    let components = value["components"]
        .as_object()
        .ok_or("missing components")?;
    let mut disk = 0u64;
    for (name, component) in components {
        if name == "proofs"
            || (!archive && matches!(name.as_str(), "transaction_senders" | "rocksdb_indices"))
        {
            continue;
        }
        let selected = if component["file"].is_string() {
            vec![(
                component["size"].as_u64(),
                component["decompressed_size"].as_u64(),
            )]
        } else {
            let total = component["total_blocks"]
                .as_u64()
                .ok_or("missing block count")?;
            let span = component["blocks_per_file"]
                .as_u64()
                .ok_or("missing chunk span")?;
            let first = if archive || name == "headers" {
                0
            } else {
                total.saturating_sub(FULL_HISTORY_BLOCKS) / span
            };
            component["chunk_sizes"]
                .as_array()
                .ok_or("missing chunk sizes")?
                .iter()
                .zip(
                    component["chunk_decompressed_sizes"]
                        .as_array()
                        .ok_or("missing output sizes")?,
                )
                .skip(usize::try_from(first).map_err(|_| "chunk index overflow")?)
                .map(|(compressed, plain)| (compressed.as_u64(), plain.as_u64()))
                .collect()
        };
        for (compressed, plain) in selected {
            let estimate = plain
                .ok_or("missing output size")?
                .checked_mul(2)
                .and_then(|n| n.checked_add(compressed?))
                .ok_or("snapshot capacity overflow")?;
            disk = disk
                .checked_add(estimate)
                .ok_or("snapshot capacity overflow")?;
        }
    }
    let required = disk
        .checked_mul(6)
        .ok_or("snapshot capacity overflow")?
        .div_ceil(5)
        .max(capacity(profile, archive));
    if required > 100_000_000_000_000 {
        return Err("snapshot capacity exceeds the reviewed provisioning range".into());
    }
    Ok(required)
}

fn op_filename(name: &str, archive: bool) -> bool {
    let prefix = if archive {
        "mainnet-op-mainnet-reth-archive-storage-v2-"
    } else {
        "mainnet-op-mainnet-reth-full-storage-v2-"
    };
    let Some(date) = name
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(".tar.zst"))
    else {
        return false;
    };
    let parts: Vec<_> = date.split('-').collect();
    parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|v| v.bytes().all(|c| c.is_ascii_digit()))
        && parts[1].parse::<u8>().is_ok_and(|m| (1..=12).contains(&m))
        && parts[2].parse::<u8>().is_ok_and(|d| (1..=31).contains(&d))
}

async fn op_snapshot(
    client: &reqwest::Client,
    profile: Profile,
    archive: bool,
) -> Result<Prepared, String> {
    let index = String::from_utf8(get(client, OP_ROOT).await?)
        .map_err(|_| "invalid official snapshot index")?;
    // Match only exact closed filename grammar, never an arbitrary href destination.
    let name = index
        .split(['"', '\'', '<', '>', ' ', '\n', '\r'])
        .map(|s| s.trim_start_matches('/'))
        .filter(|name| op_filename(name, archive))
        .max()
        .ok_or("official OP Mainnet storage-v2 snapshot unavailable")?;
    let url = format!("{OP_ROOT}{name}");
    let manifest = String::from_utf8(get(client, &format!("{url}.sha256sum")).await?)
        .map_err(|_| "invalid OP snapshot checksum")?;
    let fields: Vec<_> = manifest.split_whitespace().collect();
    if fields.len() != 2 || !hash(fields[0]) || fields[1] != name {
        return Err("OP snapshot checksum does not identify the selected file".into());
    }
    Ok(Prepared {
        pin: Pin {
            kind: "op-archive".into(),
            url,
            sha256: fields[0].to_ascii_lowercase(),
            required_free_bytes: capacity(profile, archive),
            chain_id: profile.chain_id,
        },
        manifest: None,
    })
}

/// Select fresh first-party metadata for a new, not-yet-started bootstrap.
/// # Errors
/// Transport, chain, source or integrity metadata errors prevent provisioning.
pub async fn prepare(profile: Profile, archive: bool) -> Result<Prepared, String> {
    if erpc_chain_rollup::profile::get(profile.family, profile.network) != Some(profile) {
        return Err("unsupported follower profile".into());
    }
    if profile.family == Family::Base {
        let client = client()?;
        let list: Vec<Value> = serde_json::from_slice(&get(&client, BASE_API).await?)
            .map_err(|_| "invalid Base snapshot listing")?;
        let wanted = profile.chain_id.to_string();
        let selected = list
            .iter()
            .filter(|row| row["chainId"].as_str() == Some(wanted.as_str()))
            .filter(|row| {
                row["metadataUrl"]
                    .as_str()
                    .is_some_and(|url| base_url(profile, url, true))
            })
            .max_by_key(|row| row["block"].as_u64())
            .ok_or("official Base snapshot is missing")?;
        let url = selected["metadataUrl"]
            .as_str()
            .ok_or("snapshot URL missing")?
            .to_owned();
        let manifest = get(&client, &url).await?;
        let required_free_bytes = base_capacity(profile, archive, &manifest)?;
        return Ok(Prepared {
            pin: Pin {
                kind: "base-manifest".into(),
                url,
                sha256: sha256(&manifest),
                required_free_bytes,
                chain_id: profile.chain_id,
            },
            manifest: Some(manifest),
        });
    }
    if profile.pre_bedrock {
        return op_snapshot(&client()?, profile, archive).await;
    }
    Ok(Prepared {
        pin: Pin {
            kind: "genesis".into(),
            url: String::new(),
            sha256: String::new(),
            required_free_bytes: capacity(profile, archive),
            chain_id: profile.chain_id,
        },
        manifest: None,
    })
}

/// Retrieve the same immutable manifest for an interrupted installation, never re-pin.
/// # Errors
/// Missing/changed metadata or a mismatched stored source fails closed.
pub async fn resume(profile: Profile, archive: bool, pin: Pin) -> Result<Prepared, String> {
    if erpc_chain_rollup::profile::get(profile.family, profile.network) != Some(profile) {
        return Err("unsupported follower profile".into());
    }
    if pin.chain_id != profile.chain_id
        || (profile.family != Family::Base && pin.required_free_bytes != capacity(profile, archive))
    {
        return Err("stored bootstrap network/capacity policy differs".into());
    }
    let manifest = match pin.kind.as_str() {
        "base-manifest"
            if profile.family == Family::Base
                && base_url(profile, &pin.url, true)
                && hash(&pin.sha256) =>
        {
            let bytes = get(&client()?, &pin.url).await?;
            if sha256(&bytes) != pin.sha256 {
                return Err("stored Base snapshot manifest changed".into());
            }
            if pin.required_free_bytes != base_capacity(profile, archive, &bytes)? {
                return Err("stored Base capacity differs from its immutable manifest".into());
            }
            Some(bytes)
        }
        "op-archive"
            if profile.pre_bedrock
                && pin
                    .url
                    .strip_prefix(OP_ROOT)
                    .is_some_and(|name| op_filename(name, archive))
                && hash(&pin.sha256) =>
        {
            None
        }
        "genesis"
            if !profile.pre_bedrock
                && profile.family != Family::Base
                && pin.url.is_empty()
                && pin.sha256.is_empty() =>
        {
            None
        }
        _ => return Err("unsupported stored bootstrap source".into()),
    };
    Ok(Prepared { pin, manifest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (Profile, Value) {
        let profile = erpc_chain_rollup::profile::get(Family::Base, "mainnet").expect("profile");
        let output =
            json!([{"path":"db/data", "size":100_000_000_000u64, "blake3":"a".repeat(64)}]);
        let mut components = serde_json::Map::new();
        for name in BASE_COMPONENTS {
            let value = if ["state", "rocksdb_indices"].contains(&name) {
                json!({"file":format!("123/{name}.tar.zst"), "size":50_000_000_000u64,
                    "decompressed_size":100_000_000_000u64, "output_files":output})
            } else {
                json!({"blocks_per_file":1_000_000, "total_blocks":20_000_000,
                    "chunk_files":(0..20).map(|i|format!("123/{name}-{i}.tar.zst")).collect::<Vec<_>>(),
                    "chunk_sizes":vec![50_000_000_000u64;20],
                    "chunk_decompressed_sizes":vec![100_000_000_000u64;20],
                    "chunk_output_files":vec![output.clone();20]})
            };
            components.insert(name.into(), value);
        }
        (
            profile,
            json!({"block":20_000_000,"chain_id":8453,"storage_version":2,
            "base_url":"https://mainnet-v2-snapshots.base.org", "components":components}),
        )
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("fixture JSON")
    }

    #[test]
    fn capacity_matches_pinned_full_selection_and_archive_history() {
        let (profile, manifest) = fixture();
        // Full: state + 20 header chunks + 14 chunks from each of four tails.
        // Archive additionally retains senders, indices, and every history chunk.
        assert_eq!(
            base_capacity(profile, false, &bytes(&manifest)),
            Ok(77 * 300_000_000_000)
        );
        assert_eq!(
            base_capacity(profile, true, &bytes(&manifest)),
            Ok(122 * 300_000_000_000)
        );
        let mut small = manifest.clone();
        small["components"]["state"]["size"] = json!(50_000_000_001u64);
        assert_eq!(
            base_capacity(profile, false, &bytes(&small)),
            Ok(77 * 300_000_000_000 + 2)
        );
    }

    #[test]
    fn incomplete_history_wrong_network_and_unsafe_integrity_are_refused() {
        let (profile, manifest) = fixture();
        let mutations = [
            ("/chain_id", json!(84532)),
            ("/base_url", json!("https://github.com")),
            ("/components/headers/blocks_per_file", json!(0)),
            ("/components/headers/total_blocks", json!(19_000_000)),
            (
                "/components/headers/chunk_files/0",
                json!("../outside.tar.zst"),
            ),
            (
                "/components/headers/chunk_output_files/0/0/path",
                json!("/etc/cron.d/job"),
            ),
            (
                "/components/headers/chunk_output_files/0/0/blake3",
                json!("missing"),
            ),
            ("/components/headers/chunk_decompressed_sizes/0", json!(0)),
            ("/components/state/size", json!(u64::MAX)),
        ];
        for (pointer, value) in mutations {
            let mut bad = manifest.clone();
            *bad.pointer_mut(pointer).expect("fixture path") = value;
            assert!(
                base_capacity(profile, true, &bytes(&bad)).is_err(),
                "{pointer}"
            );
        }
        for name in BASE_COMPONENTS {
            let mut bad = manifest.clone();
            bad["components"]
                .as_object_mut()
                .expect("components")
                .remove(name);
            assert!(
                base_capacity(profile, true, &bytes(&bad)).is_err(),
                "missing {name}"
            );
        }
    }
}
