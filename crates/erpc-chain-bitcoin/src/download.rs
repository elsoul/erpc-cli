// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Read small release metadata and authenticate it using an isolated GPG keyring.

use crate::release::{self, Pin, Platform, Version};
use std::time::Duration;

/// Authenticated release metadata, carried to the host for independent verification.
#[derive(Debug)]
pub struct Authenticated {
    /// Version/source/platform/archive digest.
    pub pin: Pin,
    /// Signed manifest bytes.
    pub manifest: String,
    /// Detached signature bundle.
    pub signatures: String,
}

fn restricted(program: &std::path::Path) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    command.env_clear().stdin(std::process::Stdio::null());
    for name in ["SystemRoot", "WINDIR", "TMPDIR", "TMP", "TEMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("LC_ALL", "C");
    command
}

fn tool(name: &str) -> Result<std::process::Command, String> {
    let paths: &[&str] = if cfg!(windows) {
        &[
            "C:/Program Files/GnuPG/bin",
            "C:/Program Files (x86)/GnuPG/bin",
            "C:/Program Files/Git/usr/bin",
        ]
    } else {
        &["/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"]
    };
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let path = paths
        .iter()
        .map(|dir| std::path::Path::new(dir).join(&file))
        .find(|p| p.is_file())
        .ok_or("install GnuPG (gpg and gpgv) in a standard system location")?;
    Ok(restricted(&path))
}

async fn get(client: &reqwest::Client, url: &str) -> Result<String, String> {
    erpc_core::endpoints::ensure_service_url(url).map_err(|e| e.to_string())?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "release metadata request failed")?;
    if !response.status().is_success() {
        return Err("release metadata server refused the request".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "release metadata transfer failed")?
    {
        if body.len() + chunk.len() > 1024 * 1024 {
            return Err("release metadata exceeds 1 MiB".into());
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| "release metadata is not UTF-8".into())
}

/// Verify GPG status using only the two carried public keys. No private keys are used.
/// # Errors
/// Missing GPG, corrupted manifests or missing quorum fail closed.
pub fn authenticate(manifest: &str, signatures: &str) -> Result<String, String> {
    let dir = tempfile::tempdir().map_err(|_| "cannot create verification directory")?;
    let home = dir.path().join("keyring");
    std::fs::create_dir(&home).map_err(|_| "cannot create isolated keyring")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot restrict keyring")?;
    }
    let keys = dir.path().join("keys.asc");
    let sums = dir.path().join("SHA256SUMS");
    let sig = dir.path().join("SHA256SUMS.asc");
    for (path, contents) in [
        (
            &keys,
            format!("{}\n{}", release::FANQUAKE_KEY, release::ACHOW_KEY),
        ),
        (&sums, manifest.to_owned()),
        (&sig, signatures.to_owned()),
    ] {
        std::fs::write(path, contents).map_err(|_| "cannot write public verification material")?;
    }
    let imported = tool("gpg")?
        .args(["--batch", "--no-options", "--homedir"])
        .arg(&home)
        .arg("--import")
        .arg(&keys)
        .output()
        .map_err(|_| "GPG is required to authenticate Bitcoin releases")?;
    if !imported.status.success() {
        return Err("could not import the pinned Bitcoin verification keys".into());
    }
    let exported = tool("gpg")?
        .args(["--batch", "--no-options", "--homedir"])
        .arg(&home)
        .arg("--export")
        .output()
        .map_err(|_| "could not export public verification keyring")?;
    if !exported.status.success() {
        return Err("could not export public verification keyring".into());
    }
    let keyring = dir.path().join("trustedkeys.gpg");
    std::fs::write(&keyring, exported.stdout)
        .map_err(|_| "cannot write public verification keyring")?;
    let result = tool("gpgv")?
        .arg("--homedir")
        .arg(&home)
        .arg("--keyring")
        .arg(&keyring)
        .args(["--status-fd", "1"])
        .arg(&sig)
        .arg(&sums)
        .output()
        .map_err(|_| "could not run manifest verification")?;
    let status = String::from_utf8(result.stdout).map_err(|_| "invalid GPG status")?;
    release::verify_status(&status).map_err(|e| e.to_string())?;
    Ok(status)
}

/// Pin a live version without trusting download TLS or a checksum by itself.
/// # Errors
/// Transport, source-tag, signature and platform failures are refused.
pub async fn fetch(version: Version, platform: Platform) -> Result<Authenticated, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("erpc-bitcoin-release")
        .build()
        .map_err(|_| "cannot construct metadata client")?;
    let (sums, sig) = release::manifest_urls(&version);
    let manifest = get(&client, &sums).await?;
    let signatures = get(&client, &sig).await?;
    let status = authenticate(&manifest, &signatures)?;
    let commit_url = format!(
        "https://api.github.com/repos/bitcoin/bitcoin/commits/{}",
        version.tag()
    );
    let source: serde_json::Value = serde_json::from_str(&get(&client, &commit_url).await?)
        .map_err(|_| "invalid source-tag response")?;
    let commit = source["sha"].as_str().ok_or("source tag has no commit")?;
    let pin = Pin::from_verified_manifest(version, commit, platform, &manifest, &status)
        .map_err(|e| e.to_string())?;
    Ok(Authenticated {
        pin,
        manifest,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn verification_process_does_not_inherit_controller_credentials() {
        const MARKER: &str = "ERPC_BITCOIN_ENV_PROBE";
        if std::env::var_os(MARKER).is_some() {
            let output = super::restricted(std::path::Path::new("/usr/bin/env"))
                .output()
                .expect("env");
            let text = String::from_utf8(output.stdout).expect("environment");
            assert!(!text.contains("OP_SERVICE_ACCOUNT_TOKEN"));
            assert!(!text.contains(MARKER));
        } else {
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "download::tests::verification_process_does_not_inherit_controller_credentials",
                ])
                .env(MARKER, "1")
                .env("OP_SERVICE_ACCOUNT_TOKEN", "fixture-only")
                .status()
                .expect("probe child");
            assert!(status.success());
        }
    }
}
