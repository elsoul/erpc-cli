// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The release notes and tag commits [`crate::versions`] works from, read
//! from GitHub's public API.
//!
//! No token is sent: the requests are anonymous, which GitHub allows 60 an
//! hour from one address, and a pin takes three. Every URL is on
//! `api.github.com`, checked against erpc's allowlist before it is sent;
//! redirects are not followed and plaintext is refused.

use core::time::Duration;

use serde::Deserialize;

use crate::versions::{self, Note, VersionError};

/// Agave's releases, newest first.
pub const AGAVE_RELEASES_URL: &str =
    "https://api.github.com/repos/anza-xyz/agave/releases?per_page=100";
/// Jito's releases, newest first.
pub const JITO_RELEASES_URL: &str =
    "https://api.github.com/repos/jito-foundation/jito-solana/releases?per_page=100";
/// Allnodes' Jito releases.
pub const ALLNODES_RELEASES_URL: &str =
    "https://api.github.com/repos/allnodes/solana-jito/releases?per_page=100";
/// Firedancer's releases.
pub const FIREDANCER_RELEASES_URL: &str =
    "https://api.github.com/repos/firedancer-io/firedancer/releases?per_page=100";
/// The API's base, for the commit of a tag.
const API: &str = "https://api.github.com/repos";

/// How long a request may take.
const TIMEOUT: Duration = Duration::from_secs(20);

/// Why GitHub could not answer.
#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    /// The HTTPS client could not start.
    #[error("could not start an HTTPS client: {0}")]
    Client(String),
    /// The URL is not one erpc may contact.
    #[error("{0}")]
    Endpoint(String),
    /// The request did not complete.
    #[error("could not reach GitHub: {0}")]
    Transport(String),
    /// GitHub refused, for example over its rate limit.
    #[error("GitHub answered {status} for {url}")]
    Status {
        /// The HTTP status.
        status: u16,
        /// What was asked.
        url: String,
    },
    /// The answer was not what the API documents.
    #[error("GitHub's answer could not be read: {0}")]
    Malformed(String),
    /// The tag or commit is not acceptable.
    #[error(transparent)]
    Version(#[from] VersionError),
}

/// A client for the few requests this module makes.
#[derive(Debug, Clone)]
pub struct Github {
    inner: reqwest::Client,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    #[serde(default)]
    digest: Option<String>,
}

/// A release of one of the components an RPC node runs beside its client,
/// reduced to what [`crate::rpc`] chooses by.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Published {
    /// The tag.
    pub tag: String,
    /// GitHub marks it a pre-release.
    pub prerelease: bool,
    /// The first line of its note.
    pub first_line: String,
    /// Each asset's name and SHA-256, from GitHub's `sha256:` digest.
    pub assets: Vec<(String, String)>,
}

impl Github {
    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Returns [`GithubError::Client`] when the TLS stack cannot start.
    pub fn new() -> Result<Self, GithubError> {
        let inner = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            // GitHub refuses requests without one.
            .user_agent(concat!("erpc/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| GithubError::Client(e.to_string()))?;
        Ok(Self { inner })
    }

    async fn get(&self, url: &str, accept: &str) -> Result<String, GithubError> {
        erpc_core::endpoints::ensure_service_url(url)
            .map_err(|e| GithubError::Endpoint(e.to_string()))?;
        let response = self
            .inner
            .get(url)
            .header(reqwest::header::ACCEPT, accept)
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| GithubError::Transport(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(GithubError::Status {
                status: status.as_u16(),
                url: url.to_owned(),
            });
        }
        response
            .text()
            .await
            .map_err(|e| GithubError::Transport(e.to_string()))
    }

    async fn releases(&self, url: &str) -> Result<Vec<Release>, GithubError> {
        let text = self.get(url, "application/vnd.github+json").await?;
        let releases: Vec<Release> =
            serde_json::from_str(&text).map_err(|e| GithubError::Malformed(e.to_string()))?;
        Ok(releases.into_iter().filter(|r| !r.draft).collect())
    }

    /// Agave's release notes, reduced to their first lines.
    ///
    /// # Errors
    ///
    /// Returns [`GithubError`] when GitHub cannot be read.
    pub async fn agave_notes(&self) -> Result<Vec<Note>, GithubError> {
        Ok(self
            .releases(AGAVE_RELEASES_URL)
            .await?
            .into_iter()
            .map(|r| Note {
                first_line: versions::first_line(r.body.as_deref().unwrap_or("")).to_owned(),
                tag: r.tag_name,
            })
            .collect())
    }

    /// Jito's release tags.
    ///
    /// # Errors
    ///
    /// Returns [`GithubError`] when GitHub cannot be read.
    pub async fn jito_tags(&self) -> Result<Vec<String>, GithubError> {
        Ok(self
            .releases(JITO_RELEASES_URL)
            .await?
            .into_iter()
            .map(|r| r.tag_name)
            .collect())
    }

    /// Allnodes' Jito release tags.
    ///
    /// # Errors
    ///
    /// Returns [`GithubError`] when GitHub cannot be read.
    pub async fn allnodes_tags(&self) -> Result<Vec<String>, GithubError> {
        Ok(self
            .releases(ALLNODES_RELEASES_URL)
            .await?
            .into_iter()
            .map(|r| r.tag_name)
            .collect())
    }

    /// Firedancer's release notes, reduced to their first lines.
    ///
    /// # Errors
    ///
    /// Returns [`GithubError`] when GitHub cannot be read.
    pub async fn firedancer_notes(&self) -> Result<Vec<Note>, GithubError> {
        Ok(self
            .releases(FIREDANCER_RELEASES_URL)
            .await?
            .into_iter()
            .map(|r| Note {
                first_line: versions::first_line(r.body.as_deref().unwrap_or("")).to_owned(),
                tag: r.tag_name,
            })
            .collect())
    }

    /// The newest releases of `repo`, one of [`crate::rpc::REPOSITORIES`],
    /// drafts left out.
    ///
    /// # Errors
    ///
    /// Returns [`GithubError`] when GitHub cannot be read, or `repo` is not
    /// one erpc reads.
    pub async fn published(&self, repo: &str) -> Result<Vec<Published>, GithubError> {
        if !crate::rpc::REPOSITORIES.contains(&repo) {
            return Err(GithubError::Version(VersionError::Client(repo.to_owned())));
        }
        Ok(self
            .releases(&format!("{API}/{repo}/releases?per_page=100"))
            .await?
            .into_iter()
            .map(|r| Published {
                first_line: versions::first_line(r.body.as_deref().unwrap_or("")).to_owned(),
                prerelease: r.prerelease,
                assets: r
                    .assets
                    .into_iter()
                    .filter_map(|a| {
                        let sha = a.digest?.strip_prefix("sha256:")?.to_owned();
                        Some((a.name, sha))
                    })
                    .collect(),
                tag: r.tag_name,
            })
            .collect())
    }

    /// The commit `tag` of `client`'s repository points at, the tag object
    /// followed through.
    ///
    /// # Errors
    ///
    /// Returns [`GithubError`] for a tag that is not a release version, a
    /// client erpc does not pin, or an answer that is not a commit SHA.
    pub async fn commit(&self, client: &str, tag: &str) -> Result<String, GithubError> {
        self.commit_in(versions::repository(client)?, tag).await
    }

    /// The commit `tag` of `repo` points at: a client's repository or one of
    /// [`crate::rpc::REPOSITORIES`].
    ///
    /// # Errors
    ///
    /// As [`Github::commit`].
    pub async fn commit_in(&self, repo: &str, tag: &str) -> Result<String, GithubError> {
        let known = crate::rpc::REPOSITORIES.contains(&repo)
            || versions::CLIENTS
                .iter()
                .any(|c| versions::repository(c).is_ok_and(|r| r == repo));
        if !known {
            return Err(GithubError::Version(VersionError::Client(repo.to_owned())));
        }
        check_tag(tag)?;
        // Yellowstone's tags carry the agave they are built for after a `+`,
        // which a path keeps only escaped.
        let path_tag = tag.replace('+', "%2B");
        let sha = self
            .get(
                &format!("{API}/{repo}/commits/{path_tag}"),
                "application/vnd.github.sha",
            )
            .await?;
        let sha = sha.trim().to_owned();
        versions::check_commit(&sha)?;
        Ok(sha)
    }
}

/// A tag goes into a URL path, so only the characters release tags use.
fn check_tag(tag: &str) -> Result<(), VersionError> {
    let plain = !tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));
    if plain && versions::read(tag).is_some() {
        Ok(())
    } else {
        Err(VersionError::Unreadable(tag.to_owned()))
    }
}

/// Where a recommendation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// GitHub, just now.
    Live,
    /// The copy erpc carries, because GitHub could not be read.
    Snapshot,
}

/// The tag `client` would run on `network`: from GitHub, or from the carried
/// copy when GitHub cannot be read, with the reason it could not.
///
/// # Errors
///
/// Returns [`VersionError`] when no release fits, from either source.
pub async fn recommended(
    github: &Github,
    client: &str,
    network: &str,
) -> Result<(String, Source, Option<GithubError>), VersionError> {
    // Only what the client's rule reads.
    let live = async {
        let (mut agave, mut jito, mut allnodes, mut firedancer) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        match client {
            "firedancer" => firedancer = github.firedancer_notes().await?,
            _ => agave = github.agave_notes().await?,
        }
        match client {
            "jito" => jito = github.jito_tags().await?,
            "allnodes-jito" => allnodes = github.allnodes_tags().await?,
            _ => {}
        }
        Ok::<_, GithubError>((agave, jito, allnodes, firedancer))
    };
    match live.await {
        Ok((agave, jito, allnodes, firedancer)) => {
            let releases = versions::Releases {
                agave: &agave,
                jito: &jito,
                allnodes: &allnodes,
                firedancer: &firedancer,
            };
            Ok((
                versions::recommended_tag(client, network, releases)?,
                Source::Live,
                None,
            ))
        }
        Err(e) => Ok((
            versions::recommended_tag(client, network, versions::snapshot().releases())?,
            Source::Snapshot,
            Some(e),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AGAVE_RELEASES_URL, ALLNODES_RELEASES_URL, API, FIREDANCER_RELEASES_URL, JITO_RELEASES_URL,
        check_tag,
    };

    #[test]
    fn every_url_is_an_allowed_destination() {
        for url in [
            AGAVE_RELEASES_URL,
            JITO_RELEASES_URL,
            ALLNODES_RELEASES_URL,
            FIREDANCER_RELEASES_URL,
            &format!("{API}/anza-xyz/agave/commits/v4.4.0-beta.1"),
            &format!("{API}/rpcpool/yellowstone-grpc/commits/v16.1.5%2Bsolana.4.3.2"),
            &format!("{API}/firedancer-io/firedancer/releases?per_page=100"),
        ] {
            assert!(
                erpc_core::endpoints::ensure_service_url(url).is_ok(),
                "{url}"
            );
        }
    }

    #[test]
    fn only_a_plain_release_tag_goes_into_a_url() {
        assert!(check_tag("v4.4.0-beta.1").is_ok());
        assert!(check_tag("v4.3.0-jito.1").is_ok());
        assert!(check_tag("v16.1.5+solana.4.3.2").is_ok());
        for bad in [
            "",
            "main",
            "v4.4.0/../x",
            "v4.4.0?x=1",
            "v4.4.0#",
            "v4.4.0 x",
        ] {
            assert!(check_tag(bad).is_err(), "{bad}");
        }
    }

    /// Reads GitHub for real; `cargo test -- --ignored` to run it.
    #[tokio::test]
    #[ignore = "reads GitHub"]
    async fn the_live_recommendation_has_a_commit() {
        let github = super::Github::new().expect("client");
        let (tag, source, _) = super::recommended(&github, "agave", "testnet")
            .await
            .expect("recommended");
        assert_eq!(source, super::Source::Live);
        let sha = github.commit("agave", &tag).await.expect("commit");
        assert_eq!(sha.len(), 40);
    }
}
