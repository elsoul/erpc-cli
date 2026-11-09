// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Release paths and strict parsing of manifests authenticated by GPG.
//!
//! Callers must check the actual artifact hash after selecting its authenticated
//! manifest entry. A hash or TLS download alone is not a signature check.

use std::collections::BTreeSet;
use std::fmt;

/// Lowest release supported by this backend, with the 31.1 operational fixes.
pub const FLOOR: &str = "31.1";
/// Default and currently source-qualified executable release.
pub const RECOMMENDED: &str = "31.1";
/// Source commit of the default release.
pub const RECOMMENDED_COMMIT: &str = "9be056a8a72b624dae9623b2f7bded92c2a21c91";
/// Primary public key fingerprints independently authenticated during research.
pub const SIGNERS: [&str; 2] = [
    "E777299FC265DD04793070EB944D35F9AC3DB76A",
    "152812300785C96444D3334D17565732E08E5E41",
];
/// Michael Ford's public release key from the pinned Guix signatures repository.
pub const FANQUAKE_KEY: &str = include_str!("../templates/gpg/fanquake.asc");
/// Ava Chow's public release key from the same pinned repository.
pub const ACHOW_KEY: &str = include_str!("../templates/gpg/achow101.asc");

/// Error in an untrusted release input. No arbitrary input is echoed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Signed releases still need qualified runtime/API behavior before execution.
    #[error(
        "native release is not in this CLI's source-qualified catalog; update erpc before selecting it"
    )]
    Catalog,
    /// Only stable, canonical, numeric release versions are accepted.
    #[error("expected a supported stable Bitcoin Core version, such as 31.1")]
    Version,
    /// The manifest does not uniquely identify the requested artifact.
    #[error("Bitcoin checksum manifest is malformed, ambiguous or missing the artifact")]
    Manifest,
    /// Two distinct trusted primary keys did not authenticate the manifest.
    #[error("Bitcoin manifest needs valid signatures from both pinned release signers")]
    Signature,
    /// The stored source identifier is not a complete commit hash.
    #[error("Bitcoin release source pin must be a complete commit hash")]
    Commit,
}

/// A validated canonical stable version, safe to use as one URL/path component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version(String);

impl Version {
    /// Parse a stable tag/version with two or three numeric components.
    ///
    /// # Errors
    /// Rejects prereleases, leading zeros, path/shell characters and releases
    /// older than the supported floor.
    pub fn parse(value: &str) -> Result<Self, Error> {
        let value = value.strip_prefix('v').unwrap_or(value);
        let parts: Vec<_> = value.split('.').collect();
        if !(2..=3).contains(&parts.len()) {
            return Err(Error::Version);
        }
        let mut numbers = [0u16; 3];
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return Err(Error::Version);
            }
            numbers[i] = part.parse().map_err(|_| Error::Version)?;
        }
        if numbers < [31, 1, 0] {
            return Err(Error::Version);
        }
        Ok(Self(value.to_owned()))
    }

    /// Canonical version without the optional `v` prefix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this version is at least the already installed version.
    #[must_use]
    pub fn at_least(&self, previous: &Self) -> bool {
        let numbers = |text: &str| {
            let mut result = [0u16; 3];
            for (index, part) in text.split('.').enumerate() {
                result[index] = part.parse().unwrap_or_default();
            }
            result
        };
        numbers(&self.0) >= numbers(&previous.0)
    }

    /// Official upstream tag.
    #[must_use]
    pub fn tag(&self) -> String {
        format!("v{}", self.0)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Supported production host platforms, not the controller's platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux x86-64.
    X86_64,
    /// Linux ARM64.
    Aarch64,
}

impl Platform {
    /// An OS machine name read from the target's preflight.
    #[must_use]
    pub fn parse(machine: &str) -> Option<Self> {
        match machine {
            "x86_64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// Release archive target name.
    #[must_use]
    pub const fn target(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-linux-gnu",
            Self::Aarch64 => "aarch64-linux-gnu",
        }
    }

    /// The exact filename that a checksum manifest must contain.
    #[must_use]
    pub fn archive(self, version: &Version) -> String {
        format!("bitcoin-{version}-{}.tar.gz", self.target())
    }
}

/// Construct an official release URL without accepting an arbitrary host/path.
#[must_use]
pub fn archive_url(version: &Version, platform: Platform) -> String {
    format!(
        "https://bitcoincore.org/bin/bitcoin-core-{version}/{}",
        platform.archive(version)
    )
}

/// Official checksum manifest and its detached signature bundle.
#[must_use]
pub fn manifest_urls(version: &Version) -> (String, String) {
    let base = format!("https://bitcoincore.org/bin/bitcoin-core-{version}/SHA256SUMS");
    (base.clone(), format!("{base}.asc"))
}

/// Check the output of GPG's dedicated `--status-fd`, not its human stderr.
///
/// Use a fresh keyring containing only the two carried keys. The full upstream
/// signature bundle can contain signatures from keys not in this trust set, so
/// GPG's aggregate exit code alone cannot establish the required quorum. A
/// successful parse requires valid signatures by both primary keys; repetition
/// of one signer or a subkey does not count as another independent signature.
///
/// # Errors
/// Rejects invalid/expired/revoked signatures, failure statuses or absence of
/// both trusted primary signatures. This does not itself invoke GPG.
pub fn verify_status(status: &str) -> Result<(), Error> {
    let mut verified = BTreeSet::new();
    for line in status.lines() {
        let Some(line) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.first().copied() {
            Some("BADSIG" | "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG" | "FAILURE" | "NODATA") => {
                return Err(Error::Signature);
            }
            Some("VALIDSIG") => {
                // VALIDSIG fields: signing fingerprint, date, timestamp, expiry,
                // version, reserved, key algorithm, hash algorithm, class,
                // optional primary fingerprint (always emitted by modern GPG).
                if !(10..=11).contains(&fields.len()) {
                    return Err(Error::Signature);
                }
                // SHA-256/384/512 only; reject weak digest signatures.
                if !matches!(fields[8], "8" | "9" | "10") || fields[9] != "00" {
                    return Err(Error::Signature);
                }
                let primary = fields.get(10).copied().unwrap_or(fields[1]);
                if SIGNERS.contains(&primary) {
                    verified.insert(primary);
                }
            }
            _ => {}
        }
    }
    if verified.len() == SIGNERS.len() {
        Ok(())
    } else {
        Err(Error::Signature)
    }
}

/// Select a unique checksum from an already authenticated SHA256SUMS manifest.
///
/// # Errors
/// Rejects malformed entries, non-ASCII/path-bearing names, duplicate names and
/// missing platform entries. No filename from the manifest is executed.
pub fn checksum(manifest: &str, version: &Version, platform: Platform) -> Result<String, Error> {
    let wanted = platform.archive(version);
    let mut seen = BTreeSet::new();
    let mut selected = None;
    for line in manifest.lines().filter(|l| !l.is_empty()) {
        let (hash, name) = line.split_once("  ").ok_or(Error::Manifest)?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Manifest);
        }
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || name.starts_with('.')
            || !seen.insert(name)
        {
            return Err(Error::Manifest);
        }
        if name == wanted {
            selected = Some(hash.to_ascii_lowercase());
        }
    }
    selected.ok_or(Error::Manifest)
}

/// Public inventory pin; no URL or installation command is taken from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// Stable version.
    pub version: Version,
    /// Source commit of the corresponding upstream tag.
    pub commit: String,
    /// Selected artifact hash from the authenticated manifest.
    pub sha256: String,
    /// Target architecture.
    pub platform: Platform,
}

impl Pin {
    /// Refuse source/tag or archive replacement and unqualified future runtimes.
    /// # Errors
    /// The current executable catalog contains the exact reviewed 31.1 artifacts.
    pub fn qualified(&self) -> Result<(), Error> {
        let digest = match self.platform {
            Platform::X86_64 => "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e",
            Platform::Aarch64 => "dcf1873f2208ba4f962f3398d47e154c39c0084be8f4553e05c940d0ace3d004",
        };
        if self.version.as_str() != RECOMMENDED
            || self.commit != RECOMMENDED_COMMIT
            || self.sha256 != digest
        {
            return Err(Error::Catalog);
        }
        Ok(())
    }

    /// Combine authenticated manifest evidence with a validated source pin.
    ///
    /// # Errors
    /// Invalid source, signature or checksum data is refused before a pin exists.
    pub fn from_verified_manifest(
        version: Version,
        commit: &str,
        platform: Platform,
        manifest: &str,
        gpg_status: &str,
    ) -> Result<Self, Error> {
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Commit);
        }
        verify_status(gpg_status)?;
        let sha256 = checksum(manifest, &version, platform)?;
        Ok(Self {
            version,
            commit: commit.to_ascii_lowercase(),
            sha256,
            platform,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Platform, SIGNERS, Version, checksum, verify_status};

    fn signature(primary: &str, signing: &str) -> String {
        format!("[GNUPG:] VALIDSIG {signing} 2026-07-07 1783382997 0 4 0 1 8 00 {primary}\n")
    }

    #[test]
    fn official_manifest_selects_each_platforms_recorded_digest() {
        let manifest = include_str!("../releases/SHA256SUMS-31.1");
        let version = Version::parse("31.1").expect("version");
        assert_eq!(
            checksum(manifest, &version, Platform::X86_64).expect("x86"),
            "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e"
        );
        assert_eq!(
            checksum(manifest, &version, Platform::Aarch64).expect("arm"),
            "dcf1873f2208ba4f962f3398d47e154c39c0084be8f4553e05c940d0ace3d004"
        );
    }

    #[test]
    fn executable_catalog_does_not_admit_arbitrary_higher_history_or_substituted_sources() {
        let manifest = include_str!("../releases/SHA256SUMS-31.1");
        for platform in [Platform::X86_64, Platform::Aarch64] {
            let version = Version::parse("31.1").unwrap();
            let mut pin = super::Pin {
                sha256: checksum(manifest, &version, platform).unwrap(),
                version,
                commit: super::RECOMMENDED_COMMIT.into(),
                platform,
            };
            assert!(pin.qualified().is_ok());
            let original = pin.clone();
            pin.commit = "a".repeat(40);
            assert_eq!(pin.qualified(), Err(Error::Catalog));
            pin = original.clone();
            pin.sha256 = "b".repeat(64);
            assert_eq!(pin.qualified(), Err(Error::Catalog));
            pin = original;
            pin.version = Version::parse("32.0").unwrap();
            assert_eq!(pin.qualified(), Err(Error::Catalog));
        }
    }

    #[test]
    fn version_cannot_escape_download_path_or_select_an_unsupported_release() {
        for bad in [
            "",
            "31",
            "31.0",
            "30.2",
            "31.01",
            "31.1-rc1",
            "31.1/../../tmp",
            "31.1\n",
            "31.1;id",
            "31.1.0.1",
            "65536.1",
        ] {
            assert_eq!(Version::parse(bad), Err(Error::Version), "{bad:?}");
        }
        assert_eq!(Version::parse("v31.1").expect("version").as_str(), "31.1");
    }

    #[test]
    fn distinct_trusted_primary_signers_are_required_not_repeated_subkeys() {
        let first = signature(SIGNERS[0], "CFB16E21C950F67FA95E558F2EEB9F5CC09526C1");
        let second = signature(SIGNERS[1], SIGNERS[1]);
        assert!(verify_status(&(first.clone() + &first)).is_err());
        assert!(
            verify_status(&(first.clone() + &signature(&"A".repeat(40), &"A".repeat(40)))).is_err()
        );
        let good = first + &second;
        assert_eq!(verify_status(&good), Ok(()));
        assert!(verify_status(&(good.clone() + "[GNUPG:] EXPKEYSIG example\n")).is_err());
        assert!(verify_status(&good.replace(" 8 00 ", " 2 00 ")).is_err());
        assert!(verify_status("gpg: Good signature from anyone").is_err());
    }

    #[test]
    fn wrong_platform_duplicate_and_path_bearing_manifest_entries_are_refused() {
        let version = Version::parse("31.1").expect("version");
        let line = format!("{}  bitcoin-31.1-x86_64-linux-gnu.tar.gz\n", "a".repeat(64));
        assert_eq!(
            checksum(&line, &version, Platform::X86_64),
            Ok("a".repeat(64))
        );
        assert_eq!(
            checksum(&line, &version, Platform::Aarch64),
            Err(Error::Manifest)
        );
        assert_eq!(
            checksum(&(line.clone() + &line), &version, Platform::X86_64),
            Err(Error::Manifest)
        );
        assert!(
            checksum(
                &line.replace("bitcoin-31.1", "../bitcoin-31.1"),
                &version,
                Platform::X86_64
            )
            .is_err()
        );
        assert!(checksum(&line.replace("aa", "gg"), &version, Platform::X86_64).is_err());
    }
}
