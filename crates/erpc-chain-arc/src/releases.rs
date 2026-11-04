// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which arc-node release a node runs, and how erpc knows it is that one.
//!
//! - **Floor.** Nothing below [`FLOOR`] is installed: the testnet and mainnet
//!   hard forks it carries have activated, and older releases stop syncing.
//! - **Recommendation.** The newest release that is not a pre-release, at or
//!   above the floor, with an archive for the node's platform.
//! - **Pin.** `init` records the tag, the commit it points at, and the
//!   SHA-256 GitHub states for the archive. The node checks the archive it
//!   downloads against that digest before installing it, so a release asset
//!   replaced after the pin is refused rather than run.
//! - **Migrations.** Moving across a release that changes the data layout
//!   needs a step `update` does not take on its own; [`migrations_between`]
//!   names them, and the move is refused until it is done.
//!
//! GitHub is read live; `releases/releases.json`, carried in the binary, is
//! the fallback and says when it was read.

use core::cmp::Ordering;
use core::time::Duration;
use std::collections::BTreeMap;

use serde::Deserialize;

/// The lowest release erpc installs.
pub const FLOOR: &str = "v0.8.0";
/// The repository the releases come from.
pub const REPOSITORY: &str = "circlefin/arc-node";
/// GitHub's listing of the releases, with each asset's digest.
pub const RELEASES_URL: &str =
    "https://api.github.com/repos/circlefin/arc-node/releases?per_page=100";
const API: &str = "https://api.github.com/repos/circlefin/arc-node";
const TIMEOUT: Duration = Duration::from_secs(20);

/// The carried snapshot of the releases.
const SNAPSHOT: &str = include_str!("../releases/releases.json");

/// What went wrong choosing or reading a release.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    /// The text is not a release tag erpc reads.
    #[error("{0:?} is not an arc-node release tag (vX.Y.Z)")]
    Tag(String),
    /// Below the floor.
    #[error("{0} is below {FLOOR}, the lowest release that still syncs")]
    BelowFloor(String),
    /// No such release, or none that fits.
    #[error("{0}")]
    Missing(String),
    /// The HTTPS client could not start.
    #[error("could not start an HTTPS client: {0}")]
    Client(String),
    /// The URL is not one erpc may contact.
    #[error("{0}")]
    Endpoint(String),
    /// GitHub could not be reached.
    #[error("could not reach GitHub: {0}")]
    Transport(String),
    /// GitHub answered with an error.
    #[error("GitHub answered {status} for {url}")]
    Status {
        /// The HTTP status.
        status: u16,
        /// What was asked.
        url: String,
    },
    /// GitHub's answer was not what it should be.
    #[error("GitHub's answer could not be read: {0}")]
    Malformed(String),
}

/// A release version: `v0.8.1`, or `v1.0.0-rc.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// X.
    pub major: u64,
    /// Y.
    pub minor: u64,
    /// Z.
    pub patch: u64,
    /// What follows `-`, if anything.
    pub pre: Option<String>,
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                // A pre-release comes before its release.
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(a), Some(b)) => a.cmp(b),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Reads a tag; `None` for anything that is not `vX.Y.Z[-pre]` with a plain
/// pre-release part, so a tag can go into a URL and a path unquoted.
#[must_use]
pub fn read(tag: &str) -> Option<Version> {
    let rest = tag.strip_prefix('v')?;
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let mut parts = core.split('.');
    let mut number = || -> Option<u64> {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let (major, minor, patch) = (number()?, number()?, number()?);
    if parts.next().is_some() {
        return None;
    }
    if let Some(pre) = pre
        && (pre.is_empty()
            || pre.len() > 32
            || !pre.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'))
    {
        return None;
    }
    Some(Version {
        major,
        minor,
        patch,
        pre: pre.map(str::to_owned),
    })
}

fn floor() -> Version {
    // FLOOR is a constant a test reads.
    read(FLOOR).unwrap_or(Version {
        major: u64::MAX,
        minor: 0,
        patch: 0,
        pre: None,
    })
}

/// The node's processor, as the release archives name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// `x86_64`.
    X86_64,
    /// `aarch64`.
    Aarch64,
}

impl Platform {
    /// From `uname -m`.
    #[must_use]
    pub fn from_uname(machine: &str) -> Option<Self> {
        match machine.trim() {
            "x86_64" | "amd64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// The target triple in the archive's name.
    #[must_use]
    pub const fn target(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-unknown-linux-gnu",
            Self::Aarch64 => "aarch64-unknown-linux-gnu",
        }
    }
}

/// The archive of `tag` for `platform`.
#[must_use]
pub fn archive_name(tag: &str, platform: Platform) -> String {
    format!("arc-node-{tag}-{}.tar.gz", platform.target())
}

/// Where the node downloads that archive.
#[must_use]
pub fn archive_url(tag: &str, platform: Platform) -> String {
    format!(
        "https://github.com/{REPOSITORY}/releases/download/{tag}/{}",
        archive_name(tag, platform)
    )
}

/// One release.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Release {
    /// Its tag.
    pub tag: String,
    /// Whether GitHub marks it a pre-release.
    #[serde(default)]
    pub prerelease: bool,
    /// The commit the tag points at; empty until read.
    #[serde(default)]
    pub commit: String,
    /// The archive's SHA-256 per target triple.
    #[serde(default)]
    pub sha256: BTreeMap<String, String>,
}

impl Release {
    /// The archive digest for `platform`, if the release has that archive.
    #[must_use]
    pub fn digest(&self, platform: Platform) -> Option<&str> {
        self.sha256
            .get(platform.target())
            .map(String::as_str)
            .filter(|d| is_sha256(d))
    }
}

/// The carried snapshot.
#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    /// The URL it was read from.
    pub source: String,
    /// When.
    pub read: String,
    /// The releases, newest first as GitHub lists them.
    pub releases: Vec<Release>,
}

/// The snapshot carried in the binary.
#[must_use]
pub fn snapshot() -> Snapshot {
    // Fixed at build time and read by a test.
    serde_json::from_str(SNAPSHOT).unwrap_or(Snapshot {
        source: String::new(),
        read: String::new(),
        releases: Vec::new(),
    })
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A commit id: 40 lowercase hex digits.
#[must_use]
pub fn is_commit(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The release to install: `wanted` when given (it must exist, be at or
/// above the floor, and have an archive for `platform`), else the newest
/// that is not a pre-release.
///
/// # Errors
///
/// Returns [`ReleaseError`] naming what does not fit.
pub fn choose<'a>(
    releases: &'a [Release],
    wanted: Option<&str>,
    platform: Platform,
) -> Result<&'a Release, ReleaseError> {
    let floor = floor();
    if let Some(tag) = wanted {
        let version = read(tag).ok_or_else(|| ReleaseError::Tag(tag.to_owned()))?;
        if version < floor {
            return Err(ReleaseError::BelowFloor(tag.to_owned()));
        }
        let release = releases
            .iter()
            .find(|r| r.tag == tag)
            .ok_or_else(|| ReleaseError::Missing(format!("arc-node has no release {tag}")))?;
        if release.digest(platform).is_none() {
            return Err(ReleaseError::Missing(format!(
                "{tag} has no {} archive with a digest",
                platform.target()
            )));
        }
        return Ok(release);
    }
    releases
        .iter()
        .filter(|r| !r.prerelease && r.digest(platform).is_some())
        .filter_map(|r| read(&r.tag).filter(|v| *v >= floor).map(|v| (v, r)))
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, r)| r)
        .ok_or_else(|| {
            ReleaseError::Missing(format!(
                "no arc-node release at or above {FLOOR} has a {} archive",
                platform.target()
            ))
        })
}

/// A release that changes what is on disk, and the step it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// The first release that needs the step.
    pub at: &'static str,
    /// What the step is.
    pub step: &'static str,
}

/// Every release that needs a step of its own when a node moves across it.
pub const MIGRATIONS: &[Migration] = &[Migration {
    at: "v0.8.0",
    step: "the execution layer's storage moves to V2: stop both layers, run \
           `arc-node-execution db --datadir <datadir> --chain <chain> migrate-v2`, \
           start the execution layer alone until eth_syncing is false, then the consensus layer",
}];

/// The migrations a move from `from` to `to` crosses, in either direction.
/// A tag erpc cannot read crosses nothing it knows of.
#[must_use]
pub fn migrations_between(from: &str, to: &str) -> Vec<Migration> {
    let (Some(a), Some(b)) = (read(from), read(to)) else {
        return Vec::new();
    };
    let (low, high) = if a <= b { (a, b) } else { (b, a) };
    MIGRATIONS
        .iter()
        .filter(|m| read(m.at).is_some_and(|at| low < at && at <= high))
        .copied()
        .collect()
}

/// Reads GitHub, anonymously, through the endpoint allowlist, following no
/// redirects.
#[derive(Debug, Clone)]
pub struct Github {
    inner: reqwest::Client,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    #[serde(default)]
    digest: Option<String>,
}

impl Github {
    /// A client.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::Client`] when TLS cannot be set up.
    pub fn new() -> Result<Self, ReleaseError> {
        let inner = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("erpc/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ReleaseError::Client(e.to_string()))?;
        Ok(Self { inner })
    }

    async fn get(&self, url: &str, accept: &str) -> Result<String, ReleaseError> {
        erpc_core::endpoints::ensure_service_url(url)
            .map_err(|e| ReleaseError::Endpoint(e.to_string()))?;
        let response = self
            .inner
            .get(url)
            .header(reqwest::header::ACCEPT, accept)
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| ReleaseError::Transport(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(ReleaseError::Status {
                status: status.as_u16(),
                url: url.to_owned(),
            });
        }
        response
            .text()
            .await
            .map_err(|e| ReleaseError::Transport(e.to_string()))
    }

    /// The releases, with each Linux archive's digest; commits are not read.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError`] when GitHub cannot be read.
    pub async fn releases(&self) -> Result<Vec<Release>, ReleaseError> {
        let text = self
            .get(RELEASES_URL, "application/vnd.github+json")
            .await?;
        let listed: Vec<ApiRelease> =
            serde_json::from_str(&text).map_err(|e| ReleaseError::Malformed(e.to_string()))?;
        Ok(listed
            .into_iter()
            .filter(|r| !r.draft)
            .map(from_api)
            .collect())
    }

    /// The commit `tag` points at, through an annotated tag too.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError`] for a tag erpc does not read, or when GitHub
    /// cannot be read or answers with something that is not a commit.
    pub async fn commit(&self, tag: &str) -> Result<String, ReleaseError> {
        if read(tag).is_none() {
            return Err(ReleaseError::Tag(tag.to_owned()));
        }
        let sha = self
            .get(
                &format!("{API}/commits/{tag}"),
                "application/vnd.github.sha",
            )
            .await?;
        let sha = sha.trim().to_owned();
        if is_commit(&sha) {
            Ok(sha)
        } else {
            Err(ReleaseError::Malformed(format!(
                "{tag} did not resolve to a commit"
            )))
        }
    }
}

fn from_api(r: ApiRelease) -> Release {
    let mut sha256 = BTreeMap::new();
    for platform in [Platform::X86_64, Platform::Aarch64] {
        let name = archive_name(&r.tag_name, platform);
        if let Some(digest) = r
            .assets
            .iter()
            .find(|a| a.name == name)
            .and_then(|a| a.digest.as_deref())
            .and_then(|d| d.strip_prefix("sha256:"))
            .filter(|d| is_sha256(d))
        {
            sha256.insert(platform.target().to_owned(), digest.to_owned());
        }
    }
    Release {
        tag: r.tag_name,
        prerelease: r.prerelease,
        commit: String::new(),
        sha256,
    }
}

/// Where a pin came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// GitHub, read now.
    Live,
    /// The carried snapshot, because GitHub could not be read (the reason).
    Snapshot(String),
}

/// The release to pin, with its commit: chosen from GitHub, or from the
/// carried snapshot when GitHub cannot be read.
///
/// # Errors
///
/// Returns [`ReleaseError`] when no release fits, or the snapshot's entry
/// has no commit.
pub async fn pin(
    github: &Github,
    wanted: Option<&str>,
    platform: Platform,
) -> Result<(Release, Source), ReleaseError> {
    let live = async {
        let releases = github.releases().await?;
        let mut release = choose(&releases, wanted, platform)?.clone();
        release.commit = github.commit(&release.tag).await?;
        Ok::<_, ReleaseError>(release)
    };
    match live.await {
        Ok(release) => Ok((release, Source::Live)),
        // A release that does not fit is the answer, not a reason to fall back.
        Err(
            e @ (ReleaseError::Tag(_) | ReleaseError::BelowFloor(_) | ReleaseError::Missing(_)),
        ) => Err(e),
        Err(e) => {
            let s = snapshot();
            let release = choose(&s.releases, wanted, platform)?.clone();
            if !is_commit(&release.commit) {
                return Err(ReleaseError::Missing(format!(
                    "the carried copy has no commit for {}",
                    release.tag
                )));
            }
            Ok((release, Source::Snapshot(e.to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FLOOR, Platform, RELEASES_URL, Release, ReleaseError, archive_url, choose,
        migrations_between, read, snapshot,
    };

    fn release(tag: &str, pre: bool, digest: bool) -> Release {
        let mut sha256 = std::collections::BTreeMap::new();
        if digest {
            sha256.insert("x86_64-unknown-linux-gnu".to_owned(), "a".repeat(64));
        }
        Release {
            tag: tag.to_owned(),
            prerelease: pre,
            commit: String::new(),
            sha256,
        }
    }

    #[test]
    fn tags_are_read_strictly_and_ordered_with_pre_releases_first() {
        assert!(read("v0.8.1") > read("v0.8.0"));
        assert!(read("v0.10.0") > read("v0.9.9"));
        assert!(read("v1.0.0-rc.1") < read("v1.0.0"));
        for bad in [
            "0.8.1",
            "v0.8",
            "v0.8.1.2",
            "v0.8.1-",
            "v0.8.1-rc/1",
            "v0.8.x",
            "main",
            "v0.8.1 ",
        ] {
            assert!(read(bad).is_none(), "{bad}");
        }
        assert!(read(FLOOR).is_some());
    }

    #[test]
    fn the_newest_release_at_or_above_the_floor_with_an_archive_is_chosen() {
        let releases = [
            release("v0.9.0-rc.1", true, true),
            release("v0.8.2", false, false),
            release("v0.8.1", false, true),
            release("v0.7.3", false, true),
        ];
        let x86 = Platform::X86_64;
        assert_eq!(choose(&releases, None, x86).expect("one").tag, "v0.8.1");
        assert_eq!(
            choose(&releases, Some("v0.9.0-rc.1"), x86)
                .expect("asked")
                .tag,
            "v0.9.0-rc.1"
        );
        assert!(matches!(
            choose(&releases, Some("v0.7.3"), x86),
            Err(ReleaseError::BelowFloor(_))
        ));
        assert!(matches!(
            choose(&releases, Some("v0.8.2"), x86),
            Err(ReleaseError::Missing(_))
        ));
        assert!(choose(&releases, None, Platform::Aarch64).is_err());
    }

    #[test]
    fn the_carried_snapshot_recommends_a_pinnable_release() {
        let s = snapshot();
        assert_eq!(s.read, "2026-10-23");
        let chosen = choose(&s.releases, None, Platform::X86_64).expect("chosen");
        assert_eq!(chosen.tag, "v0.8.1");
        assert!(super::is_commit(&chosen.commit));
        assert_eq!(
            chosen.digest(Platform::X86_64),
            Some("04127c5bb9488de743755b5089f4434c335cf349386d5d01347abfbc402d932a")
        );
    }

    #[test]
    fn moving_across_v0_8_0_needs_the_storage_migration() {
        assert_eq!(migrations_between("v0.7.3", "v0.8.1").len(), 1);
        assert_eq!(migrations_between("v0.8.1", "v0.7.3").len(), 1);
        assert!(migrations_between("v0.8.0", "v0.8.1").is_empty());
        assert!(migrations_between("v0.8.1", "v0.8.1").is_empty());
    }

    #[test]
    fn every_url_is_an_allowed_destination() {
        assert!(erpc_core::endpoints::ensure_service_url(RELEASES_URL).is_ok());
        assert!(
            erpc_core::endpoints::ensure_service_url(
                "https://api.github.com/repos/circlefin/arc-node/commits/v0.8.1"
            )
            .is_ok()
        );
        assert_eq!(
            archive_url("v0.8.1", Platform::X86_64),
            "https://github.com/circlefin/arc-node/releases/download/v0.8.1/arc-node-v0.8.1-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[tokio::test]
    #[ignore = "reads GitHub"]
    async fn the_live_pin_has_a_commit_and_a_digest() {
        let github = super::Github::new().expect("client");
        let (release, source) = super::pin(&github, None, Platform::X86_64)
            .await
            .expect("pinned");
        assert_eq!(source, super::Source::Live);
        assert!(super::is_commit(&release.commit));
        assert!(release.digest(Platform::X86_64).is_some());
    }
}
