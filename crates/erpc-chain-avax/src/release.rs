// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Release policy: only reviewed 1.15 patch updates; no automatic DB downgrade.
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Reviewed signing key, embedded in the deployment bundle.
pub const FINGERPRINT: &str = "5395BDA1129CAC3E74699D07D93080B0C0D5FE8B";
/// Default network-qualified release. Updates require an explicit tag.
pub const RECOMMENDED: &str = "v1.15.2";
const API: &str = "https://api.github.com/repos/ava-labs/avalanchego";
const DOWNLOAD: &str = "https://github.com/ava-labs/avalanchego/releases/download";

/// Complete immutable archive identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    /// Release tag.
    pub version: String,
    /// Resolved source commit.
    pub commit: String,
    /// Linux architecture.
    pub arch: String,
    /// SHA-256 of archive.
    pub sha256: String,
}
/// Parse only the reviewed patch line, excluding prereleases and URL/path injection.
#[must_use]
pub fn patch(tag: &str) -> Option<u32> {
    let p = tag.strip_prefix("v1.15.")?;
    if p.is_empty()
        || p.len() > 5
        || (p.starts_with('0') && p.len() > 1)
        || !p.bytes().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    p.parse().ok().filter(|p| *p >= 2)
}
/// Fixed upstream archive URL; validates every path component.
/// # Errors
/// Rejects unsupported releases and architectures.
pub fn archive_url(tag: &str, arch: &str) -> Result<String, String> {
    if patch(tag).is_none() || !["amd64", "arm64"].contains(&arch) {
        return Err("unsupported Avalanche release/platform".into());
    }
    Ok(format!(
        "{DOWNLOAD}/{tag}/avalanchego-linux-{arch}-{tag}.tar.gz"
    ))
}
/// Validate a stored pin before using it in shell paths or templates.
/// # Errors
/// Rejects missing/invalid digests, commits or release identifiers.
pub fn validate(pin: &Pin) -> Result<(), String> {
    archive_url(&pin.version, &pin.arch)?;
    for (s, size) in [(&pin.commit, 40), (&pin.sha256, 64)] {
        if s.len() != size || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid Avalanche release pin".into());
        }
    }
    Ok(())
}
/// Reject rollback and architecture changes.
/// # Errors
/// Refuses unreviewed or decreasing versions.
pub fn update_allowed(old: &Pin, next: &Pin) -> Result<(), String> {
    validate(old)?;
    validate(next)?;
    if old.arch != next.arch
        || patch(&next.version) < patch(&old.version)
        || (old.version == next.version && old != next)
    {
        return Err("Avalanche downgrade, architecture change or mutated release refused".into());
    }
    Ok(())
}
async fn get(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    erpc_core::endpoints::ensure_service_url(url).map_err(|e| e.to_string())?;
    client
        .get(url)
        .send()
        .await
        .map_err(|_| "cannot read Avalanche release metadata")?
        .error_for_status()
        .map_err(|_| "Avalanche release metadata unavailable")?
        .json()
        .await
        .map_err(|_| "invalid Avalanche release metadata".into())
}
/// Pin a stable release's GitHub digest and source commit; no stale fallback.
/// # Errors
/// Refuses prereleases, absent signatures, missing SHA-256 or unavailable metadata.
pub async fn resolve(tag: &str, arch: &str) -> Result<Pin, String> {
    let expected = archive_url(tag, arch)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("erpc")
        .build()
        .map_err(|e| e.to_string())?;
    let release = get(&client, &format!("{API}/releases/tags/{tag}")).await?;
    let commit = get(&client, &format!("{API}/commits/{tag}")).await?;
    parse(tag, arch, &expected, &release, &commit)
}
fn parse(
    tag: &str,
    arch: &str,
    expected: &str,
    release: &Value,
    commit: &Value,
) -> Result<Pin, String> {
    if release["tag_name"] != tag || release["prerelease"] != false || release["draft"] != false {
        return Err("not the requested stable release".into());
    }
    let assets = release["assets"]
        .as_array()
        .ok_or("release has no assets")?;
    let archive = assets
        .iter()
        .find(|a| a["browser_download_url"] == expected)
        .ok_or("release archive absent")?;
    if !assets
        .iter()
        .any(|a| a["browser_download_url"] == format!("{expected}.sig"))
    {
        return Err("release signature absent".into());
    }
    let pin = Pin {
        version: tag.into(),
        arch: arch.into(),
        commit: commit["sha"].as_str().ok_or("commit absent")?.into(),
        sha256: archive["digest"]
            .as_str()
            .and_then(|s| s.strip_prefix("sha256:"))
            .ok_or("SHA-256 absent")?
            .into(),
    };
    validate(&pin)?;
    Ok(pin)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn metadata_cannot_substitute_a_prerelease_or_different_asset() {
        let url = archive_url("v1.15.2", "amd64").unwrap();
        let mut r = json!({"tag_name":"v1.15.2","prerelease":false,"draft":false,"assets":[{"browser_download_url":url,"digest":format!("sha256:{}","a".repeat(64))},{"browser_download_url":format!("{url}.sig")}]});
        let c = json!({"sha":"b".repeat(40)});
        assert!(parse("v1.15.2", "amd64", &url, &r, &c).is_ok());
        r["prerelease"] = json!(true);
        assert!(parse("v1.15.2", "amd64", &url, &r, &c).is_err());
        r["prerelease"] = json!(false);
        r["assets"][0]["digest"] = json!(null);
        assert!(parse("v1.15.2", "amd64", &url, &r, &c).is_err());
        for tag in ["v1.15.1", "v1.16.0", "v1.15.2-rc.1", "v1.15.2/../../x"] {
            assert!(archive_url(tag, "amd64").is_err());
        }
    }
    #[test]
    fn production_urls_are_declared() {
        for url in [
            format!("{API}/commits/v1.15.2"),
            archive_url("v1.15.2", "arm64").unwrap(),
        ] {
            assert!(erpc_core::endpoints::ensure_service_url(&url).is_ok());
        }
    }
}
