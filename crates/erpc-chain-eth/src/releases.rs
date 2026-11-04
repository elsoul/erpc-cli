// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which Reth and Lighthouse releases a node runs, and how erpc knows they
//! are those.
//!
//! - **Floor.** Nothing below a client's floor is installed: older releases
//!   do not follow mainnet past its latest hard fork.
//! - **Recommendation.** The newest release that is not a pre-release, at or
//!   above the floor, with an archive for the node's platform.
//! - **Pin.** `init` records each client's tag, the commit it points at, and
//!   the SHA-256 GitHub states for the archive. The node checks the archive
//!   against that digest and against the release's GPG signature, made with
//!   the key whose fingerprint erpc carries ([`Client::fingerprint`]), before
//!   installing it.
//!
//! GitHub is read live; `releases/releases.json`, carried in the binary, is
//! the fallback and says when it was read.

use core::cmp::Ordering;
use core::time::Duration;
use std::collections::BTreeMap;

use serde::Deserialize;

const TIMEOUT: Duration = Duration::from_secs(20);

/// The carried snapshot of the releases.
const SNAPSHOT: &str = include_str!("../releases/releases.json");

/// One of the two clients a node runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    /// The execution layer, which serves JSON-RPC.
    Reth,
    /// The consensus layer.
    Lighthouse,
}

impl Client {
    /// Both, in the order they start.
    pub const ALL: [Self; 2] = [Self::Reth, Self::Lighthouse];

    /// Its name, as the archives and the binaries have it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reth => "reth",
            Self::Lighthouse => "lighthouse",
        }
    }

    /// The GitHub repository its releases come from.
    #[must_use]
    pub const fn repository(self) -> &'static str {
        match self {
            Self::Reth => "paradigmxyz/reth",
            Self::Lighthouse => "sigp/lighthouse",
        }
    }

    /// GitHub's listing of its releases, with each asset's digest.
    #[must_use]
    pub const fn releases_url(self) -> &'static str {
        match self {
            Self::Reth => "https://api.github.com/repos/paradigmxyz/reth/releases?per_page=100",
            Self::Lighthouse => {
                "https://api.github.com/repos/sigp/lighthouse/releases?per_page=100"
            }
        }
    }

    const fn api(self) -> &'static str {
        match self {
            Self::Reth => "https://api.github.com/repos/paradigmxyz/reth",
            Self::Lighthouse => "https://api.github.com/repos/sigp/lighthouse",
        }
    }

    /// The lowest release erpc installs.
    #[must_use]
    pub const fn floor(self) -> &'static str {
        match self {
            Self::Reth => "v2.8.0",
            Self::Lighthouse => "v8.3.0",
        }
    }

    /// The fingerprint of the key that signs its release archives; the
    /// key itself is carried as `templates/gpg/<name>.asc`.
    #[must_use]
    pub const fn fingerprint(self) -> &'static str {
        match self {
            Self::Reth => "50FB7CC55B2E8AFA59FE03B7AA5ED56A7FBF253E",
            Self::Lighthouse => "15E66D941F697E28F49381F426416DC3F30674B0",
        }
    }
}

/// What went wrong choosing or reading a release.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    /// The text is not a release tag erpc reads.
    #[error("{0:?} is not a release tag (vX.Y.Z)")]
    Tag(String),
    /// Below the floor.
    #[error("{tag} is below {floor}, the lowest {client} release erpc installs")]
    BelowFloor {
        /// The client.
        client: &'static str,
        /// The tag asked for.
        tag: String,
        /// The floor.
        floor: &'static str,
    },
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

/// A release version: `v2.8.1`, or `v8.4.0-rc.0`.
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

fn floor(client: Client) -> Version {
    // The floors are constants a test reads.
    read(client.floor()).unwrap_or(Version {
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

/// The archive of `client`'s `tag` for `platform`; its signature is the
/// same name with `.asc`.
#[must_use]
pub fn archive_name(client: Client, tag: &str, platform: Platform) -> String {
    format!("{}-{tag}-{}.tar.gz", client.name(), platform.target())
}

/// Where the node downloads that archive.
#[must_use]
pub fn archive_url(client: Client, tag: &str, platform: Platform) -> String {
    format!(
        "https://github.com/{}/releases/download/{tag}/{}",
        client.repository(),
        archive_name(client, tag, platform)
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
    /// When it was read from GitHub.
    pub read: String,
    /// Reth's releases, newest first as GitHub lists them.
    pub reth: Vec<Release>,
    /// Lighthouse's releases, likewise.
    pub lighthouse: Vec<Release>,
}

impl Snapshot {
    /// `client`'s releases.
    #[must_use]
    pub fn of(&self, client: Client) -> &[Release] {
        match client {
            Client::Reth => &self.reth,
            Client::Lighthouse => &self.lighthouse,
        }
    }
}

/// The snapshot carried in the binary.
#[must_use]
pub fn snapshot() -> Snapshot {
    // Fixed at build time and read by a test.
    serde_json::from_str(SNAPSHOT).unwrap_or(Snapshot {
        read: String::new(),
        reth: Vec::new(),
        lighthouse: Vec::new(),
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

/// The release of `client` to install: `wanted` when given (it must exist,
/// be at or above the floor, and have an archive for `platform`), else the
/// newest that is not a pre-release.
///
/// # Errors
///
/// Returns [`ReleaseError`] naming what does not fit.
pub fn choose<'a>(
    client: Client,
    releases: &'a [Release],
    wanted: Option<&str>,
    platform: Platform,
) -> Result<&'a Release, ReleaseError> {
    let floor = floor(client);
    if let Some(tag) = wanted {
        let version = read(tag).ok_or_else(|| ReleaseError::Tag(tag.to_owned()))?;
        if version < floor {
            return Err(ReleaseError::BelowFloor {
                client: client.name(),
                tag: tag.to_owned(),
                floor: client.floor(),
            });
        }
        let release = releases.iter().find(|r| r.tag == tag).ok_or_else(|| {
            ReleaseError::Missing(format!("{} has no release {tag}", client.name()))
        })?;
        if release.digest(platform).is_none() {
            return Err(ReleaseError::Missing(format!(
                "{} {tag} has no {} archive with a digest",
                client.name(),
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
                "no {} release at or above {} has a {} archive",
                client.name(),
                client.floor(),
                platform.target()
            ))
        })
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

    /// `client`'s releases, with each Linux archive's digest; commits are
    /// not read.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError`] when GitHub cannot be read.
    pub async fn releases(&self, client: Client) -> Result<Vec<Release>, ReleaseError> {
        let text = self
            .get(client.releases_url(), "application/vnd.github+json")
            .await?;
        let listed: Vec<ApiRelease> =
            serde_json::from_str(&text).map_err(|e| ReleaseError::Malformed(e.to_string()))?;
        Ok(listed
            .into_iter()
            .filter(|r| !r.draft)
            .map(|r| from_api(client, r))
            .collect())
    }

    /// The commit `client`'s `tag` points at, through an annotated tag too.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError`] for a tag erpc does not read, or when GitHub
    /// cannot be read or answers with something that is not a commit.
    pub async fn commit(&self, client: Client, tag: &str) -> Result<String, ReleaseError> {
        if read(tag).is_none() {
            return Err(ReleaseError::Tag(tag.to_owned()));
        }
        let sha = self
            .get(
                &format!("{}/commits/{tag}", client.api()),
                "application/vnd.github.sha",
            )
            .await?;
        let sha = sha.trim().to_owned();
        if is_commit(&sha) {
            Ok(sha)
        } else {
            Err(ReleaseError::Malformed(format!(
                "{} {tag} did not resolve to a commit",
                client.name()
            )))
        }
    }
}

fn from_api(client: Client, r: ApiRelease) -> Release {
    let mut sha256 = BTreeMap::new();
    for platform in [Platform::X86_64, Platform::Aarch64] {
        let name = archive_name(client, &r.tag_name, platform);
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

/// `client`'s release to pin, with its commit: chosen from GitHub, or from
/// the carried snapshot when GitHub cannot be read.
///
/// # Errors
///
/// Returns [`ReleaseError`] when no release fits, or the snapshot's entry
/// has no commit.
pub async fn pin(
    github: &Github,
    client: Client,
    wanted: Option<&str>,
    platform: Platform,
) -> Result<(Release, Source), ReleaseError> {
    let live = async {
        let releases = github.releases(client).await?;
        let mut release = choose(client, &releases, wanted, platform)?.clone();
        release.commit = github.commit(client, &release.tag).await?;
        Ok::<_, ReleaseError>(release)
    };
    match live.await {
        Ok(release) => Ok((release, Source::Live)),
        // A release that does not fit is the answer, not a reason to fall back.
        Err(
            e @ (ReleaseError::Tag(_) | ReleaseError::BelowFloor { .. } | ReleaseError::Missing(_)),
        ) => Err(e),
        Err(e) => {
            let s = snapshot();
            let release = choose(client, s.of(client), wanted, platform)?.clone();
            if !is_commit(&release.commit) {
                return Err(ReleaseError::Missing(format!(
                    "the carried copy has no commit for {} {}",
                    client.name(),
                    release.tag
                )));
            }
            Ok((release, Source::Snapshot(e.to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, Platform, Release, ReleaseError, archive_url, choose, read, snapshot};

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
    fn tags_are_read_strictly_and_the_floors_are_tags() {
        assert!(read("v2.8.1") > read("v2.8.0"));
        assert!(read("v8.4.0-rc.0") < read("v8.4.0"));
        for bad in ["2.8.1", "v2.8", "v2.8.1.2", "v2.8.1-", "v2.8.x", "main"] {
            assert!(read(bad).is_none(), "{bad}");
        }
        for client in Client::ALL {
            assert!(read(client.floor()).is_some(), "{client:?}");
            assert_eq!(client.fingerprint().len(), 40);
        }
    }

    #[test]
    fn the_newest_release_at_or_above_the_floor_with_an_archive_is_chosen() {
        let releases = [
            release("v8.4.0-rc.0", true, true),
            release("v8.3.3", false, false),
            release("v8.3.2", false, true),
            release("v8.2.2", false, true),
        ];
        let x86 = Platform::X86_64;
        let pick = |wanted| choose(Client::Lighthouse, &releases, wanted, x86);
        assert_eq!(pick(None).expect("one").tag, "v8.3.2");
        assert_eq!(pick(Some("v8.4.0-rc.0")).expect("asked").tag, "v8.4.0-rc.0");
        assert!(matches!(
            pick(Some("v8.2.2")),
            Err(ReleaseError::BelowFloor { .. })
        ));
        assert!(matches!(
            pick(Some("v8.3.3")),
            Err(ReleaseError::Missing(_))
        ));
    }

    #[test]
    fn the_carried_snapshot_pins_both_clients() {
        let s = snapshot();
        assert_eq!(s.read, "2026-10-24");
        for (client, tag, digest) in [
            (
                Client::Reth,
                "v2.8.1",
                "466b3fe5a221ccfd40916c8fca1b3a35d986364617fbe3c7469983fd496f697f",
            ),
            (
                Client::Lighthouse,
                "v8.3.2",
                "ea914e932462d6a93ad78c21377d70f995e05ac224248be0b58c2f4d6740439a",
            ),
        ] {
            let chosen = choose(client, s.of(client), None, Platform::X86_64).expect("chosen");
            assert_eq!(chosen.tag, tag);
            assert!(super::is_commit(&chosen.commit));
            assert_eq!(chosen.digest(Platform::X86_64), Some(digest));
        }
    }

    #[test]
    fn every_url_is_an_allowed_destination() {
        for client in Client::ALL {
            assert!(erpc_core::endpoints::ensure_service_url(client.releases_url()).is_ok());
        }
        assert_eq!(
            archive_url(Client::Reth, "v2.8.1", Platform::X86_64),
            "https://github.com/paradigmxyz/reth/releases/download/v2.8.1/reth-v2.8.1-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[tokio::test]
    #[ignore = "reads GitHub"]
    async fn the_live_pins_have_a_commit_and_a_digest() {
        let github = super::Github::new().expect("client");
        for client in Client::ALL {
            let (release, source) = super::pin(&github, client, None, Platform::X86_64)
                .await
                .expect("pinned");
            assert_eq!(source, super::Source::Live);
            assert!(super::is_commit(&release.commit));
            assert!(release.digest(Platform::X86_64).is_some());
        }
    }
}
