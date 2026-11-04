// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which client release a validator runs, and how that choice is held still.
//!
//! - **Floor.** The oldest release Alpenglow runs on, per network, as SLV
//!   has it. Nothing below it is pinned or built; the carried
//!   `check_alpenglow_floor.yml` stops a run below it as well.
//! - **Recommendation.** Agave says on the first line of each release note
//!   which clusters the release is for. The recommended release for a
//!   network is the newest one whose first line names that network, at or
//!   above the floor. A Jito build is the `-jito` tag of that release, an
//!   Allnodes build its `-allnodes` tag.
//! - **Firedancer** has its own releases and words: the full Firedancer
//!   (`v26.x`) says "mainnet ready release" or "Testnet Release", and its
//!   floor is the first release that runs Alpenglow ([`FIREDANCER_FLOOR`]).
//!   Frankendancer's `v0.x` tags are never a validator's.
//! - **Pin.** The chosen tag and the commit it pointed at are kept in the
//!   validator item. The build checks out the tag and stops if it is no
//!   longer that commit, so nothing changes under a validator silently.
//!
//! The release notes are read from GitHub when erpc can reach it
//! ([`crate::github`]); `versions/releases.json` is the copy used when it
//! cannot.

use core::cmp::Ordering;
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::{Map, Value, json};

/// The oldest release Alpenglow runs on, per network.
pub const FLOORS: [(&str, &str); 3] = [
    ("mainnet", "4.3.0"),
    ("testnet", "4.4.0-beta.0"),
    ("devnet", "4.4.0-beta.0"),
];

/// The oldest full Firedancer release a validator runs, on any network:
/// the first that runs Alpenglow and is mainnet ready.
pub const FIREDANCER_FLOOR: &str = "26.10.2";

/// The clients erpc pins for a validator.
pub const CLIENTS: [&str; 4] = ["agave", "jito", "allnodes-jito", "firedancer"];

/// The floor of `network`.
#[must_use]
pub fn floor(network: &str) -> Option<&'static str> {
    FLOORS.iter().find(|(n, _)| *n == network).map(|(_, f)| *f)
}

/// A release as SLV compares them: X.Y.Z, then alpha, beta, rc or release,
/// then the pre-release number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Release {
    /// Major, minor, patch.
    pub numbers: [u64; 3],
    /// 0 alpha, 1 beta, 2 rc, 3 release.
    pub rank: u8,
    /// The pre-release number; 0 for a release.
    pub number: u64,
}

/// The rank of a release that is not a pre-release.
const RELEASE_RANK: u8 = 3;

/// Reads a version the way SLV does: an optional `v`; X.Y with an optional
/// .Z; further numeric components ignored; an optional `-alpha`, `-beta` or
/// `-rc` with an optional dot and number; anything after that ignored, so
/// `4.3.0-beta.3-jito` is 4.3.0-beta.3. `None` when there is no X.Y.
#[must_use]
pub fn read(version: &str) -> Option<Release> {
    let rest = version.trim();
    let rest = rest.strip_prefix('v').unwrap_or(rest);
    let (major, rest) = digits(rest)?;
    let (minor, mut rest) = digits(rest.strip_prefix('.')?)?;
    let mut patch = 0;
    if let Some((p, after)) = rest.strip_prefix('.').and_then(digits) {
        patch = p;
        rest = after;
        while let Some((_, after)) = rest.strip_prefix('.').and_then(digits) {
            rest = after;
        }
    }
    let (mut rank, mut number) = (RELEASE_RANK, 0);
    if let Some(pre) = rest.strip_prefix('-') {
        for (name, r) in [("alpha", 0), ("beta", 1), ("rc", 2)] {
            if let Some(after) = pre.strip_prefix(name) {
                rank = r;
                let after = after.strip_prefix('.').unwrap_or(after);
                number = digits(after).map_or(0, |(n, _)| n);
                break;
            }
        }
    }
    Some(Release {
        numbers: [major, minor, patch],
        rank,
        number,
    })
}

/// The leading digits of `s` as a number, and what follows them.
fn digits(s: &str) -> Option<(u64, &str)> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    Some((s[..end].parse().ok()?, &s[end..]))
}

/// Why a version was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionError {
    /// erpc carries no floor for this network.
    #[error("erpc has no client floor for the {0} network")]
    Network(String),
    /// Not a version erpc can compare.
    #[error("{0:?} is not a release version (expected X.Y.Z, as in v4.4.0-beta.1)")]
    Unreadable(String),
    /// Older than the network runs on.
    #[error("{version} is older than {floor}, the oldest release {network} runs on")]
    BelowFloor {
        /// The version asked for.
        version: String,
        /// The network.
        network: String,
        /// Its floor.
        floor: &'static str,
    },
    /// The client has no releases erpc knows how to pick.
    #[error("erpc does not pin {0} releases")]
    Client(String),
    /// No release fits.
    #[error("no {client} release for {network} at or above {floor}")]
    NoRelease {
        /// The client.
        client: String,
        /// The network.
        network: String,
        /// Its floor.
        floor: &'static str,
    },
    /// Not a full commit SHA.
    #[error("{0:?} is not a 40-character commit SHA")]
    Commit(String),
}

/// Refuses `version` when it is below the floor of `network`, or cannot be
/// compared with it. SLV only warns about the second outside mainnet; erpc
/// pins release tags, so it has no reason to accept one.
///
/// # Errors
///
/// Returns [`VersionError`] for an unknown network, an unreadable version, or
/// one below the floor.
pub fn check_floor(network: &str, version: &str) -> Result<(), VersionError> {
    let floor = floor(network).ok_or_else(|| VersionError::Network(network.to_owned()))?;
    let read = read(version).ok_or_else(|| VersionError::Unreadable(version.to_owned()))?;
    if read < read_floor(floor) {
        return Err(VersionError::BelowFloor {
            version: version.to_owned(),
            network: network.to_owned(),
            floor,
        });
    }
    Ok(())
}

/// [`check_floor`] for `client`: a full Firedancer release at or above
/// [`FIREDANCER_FLOOR`], any other client against the network's floor.
///
/// # Errors
///
/// As [`check_floor`], and for a Firedancer tag that is not a full
/// Firedancer release.
pub fn check_client_floor(network: &str, client: &str, version: &str) -> Result<(), VersionError> {
    if client != "firedancer" {
        return check_floor(network, version);
    }
    floor(network).ok_or_else(|| VersionError::Network(network.to_owned()))?;
    let read = read(version).ok_or_else(|| VersionError::Unreadable(version.to_owned()))?;
    if !is_full_firedancer(version) || read < read_floor(FIREDANCER_FLOOR) {
        return Err(VersionError::BelowFloor {
            version: version.to_owned(),
            network: network.to_owned(),
            floor: FIREDANCER_FLOOR,
        });
    }
    Ok(())
}

/// A full Firedancer tag: `v<YY>.<MM>.<N>`, never Frankendancer's `v0.x`.
#[must_use]
pub fn is_full_firedancer(tag: &str) -> bool {
    read(tag).is_some_and(|r| r.numbers[0] >= 26 && r.rank == RELEASE_RANK)
}

fn read_floor(floor: &str) -> Release {
    read(floor).unwrap_or(Release {
        numbers: [u64::MAX; 3],
        rank: RELEASE_RANK,
        number: 0,
    })
}

/// The clusters a release note's first line names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Suitable {
    /// For mainnet: a stable release.
    pub mainnet: bool,
    /// For testnet: a testnet release, or one also recommended for it.
    pub testnet: bool,
    /// For devnet, likewise.
    pub devnet: bool,
}

impl Suitable {
    /// Whether `network` is named.
    #[must_use]
    pub fn names(self, network: &str) -> bool {
        match network {
            "mainnet" => self.mainnet,
            "testnet" => self.testnet,
            "devnet" => self.devnet,
            _ => false,
        }
    }
}

/// What the first line of an Agave release note says the release is for.
///
/// The lines Agave writes, and what each is read as:
///
/// - "This a stable release suitable for Testnet, Devnet and Mainnet Beta."
///   is all three.
/// - "This a stable release." is mainnet: a patch of the line mainnet runs.
/// - "This is a testnet release." is testnet, and devnet too when it adds
///   "It is also recommended for Devnet."
/// - "This is Mainnet-beta Upgrade Candidate release …" is a candidate for a
///   share of mainnet, so not a recommendation for it; it names testnet or
///   devnet only when it says it is also recommended for them.
/// - "This is a pre-release for testing only …" is nothing.
///
/// Any other line, such as a bare "## What's Changed", is nothing: a release
/// whose note does not say what it is for is not recommended.
#[must_use]
pub fn suitable(first_line: &str) -> Suitable {
    let line = first_line.to_ascii_lowercase();
    if line.contains("for testing only") || line.contains("do not deploy") {
        return Suitable::default();
    }
    let stable = line.contains("stable release");
    let suitable_for_all = stable && line.contains("suitable for");
    let testnet_release = line.contains("testnet release");
    let also = |net: &str| {
        line.split("also recommended for")
            .nth(1)
            .is_some_and(|rest| rest.contains(net))
    };
    Suitable {
        mainnet: stable && (!line.contains("suitable for") || line.contains("mainnet")),
        testnet: testnet_release
            || (suitable_for_all && line.contains("testnet"))
            || also("testnet"),
        devnet: (suitable_for_all && line.contains("devnet")) || also("devnet"),
    }
}

/// What the first line of a full Firedancer release note says it is for:
/// "This is a mainnet ready release." is mainnet and testnet; "This is a
/// Testnet Release. It is not suggested for Mainnet Beta use." is testnet.
#[must_use]
pub fn firedancer_suitable(first_line: &str) -> Suitable {
    let line = first_line.to_ascii_lowercase();
    let mainnet = line.contains("mainnet ready");
    let testnet = mainnet || line.contains("testnet release");
    Suitable {
        mainnet,
        testnet,
        devnet: testnet,
    }
}

/// The newest full Firedancer release for `network`, at or above
/// [`FIREDANCER_FLOOR`].
///
/// # Errors
///
/// Returns [`VersionError::NoRelease`] when none fits.
pub fn recommend_firedancer<'a>(
    network: &str,
    notes: &'a [Note],
) -> Result<&'a Note, VersionError> {
    floor(network).ok_or_else(|| VersionError::Network(network.to_owned()))?;
    let bar = read_floor(FIREDANCER_FLOOR);
    notes
        .iter()
        .filter(|n| is_full_firedancer(&n.tag))
        .filter(|n| firedancer_suitable(&n.first_line).names(network))
        .filter_map(|n| Some((read(&n.tag)?, n)))
        .filter(|(r, _)| *r >= bar)
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, n)| n)
        .ok_or(VersionError::NoRelease {
            client: "firedancer".to_owned(),
            network: network.to_owned(),
            floor: FIREDANCER_FLOOR,
        })
}

/// The first line of a release note that has text on it.
#[must_use]
pub fn first_line(body: &str) -> &str {
    body.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
}

/// A release note, reduced to what the rule reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Note {
    /// The tag, `v4.4.0-beta.1`.
    pub tag: String,
    /// The first line of its note.
    pub first_line: String,
}

/// The copy of the release notes erpc carries.
#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    /// Where it was read from.
    pub source: String,
    /// When, `YYYY-MM-DD`.
    pub read: String,
    /// Agave's releases, newest first, drafts left out.
    pub agave: Vec<Note>,
    /// Jito's release tags.
    pub jito: Vec<String>,
    /// Allnodes' Jito release tags.
    #[serde(default)]
    pub allnodes: Vec<String>,
    /// Firedancer's releases, newest first, drafts left out.
    #[serde(default)]
    pub firedancer: Vec<Note>,
}

const SNAPSHOT_JSON: &str = include_str!("../versions/releases.json");

/// The carried copy.
///
/// # Panics
///
/// Only if `versions/releases.json` does not parse, which a test rules out.
#[must_use]
pub fn snapshot() -> &'static Snapshot {
    static SNAPSHOT: OnceLock<Snapshot> = OnceLock::new();
    #[allow(clippy::expect_used)]
    SNAPSHOT
        .get_or_init(|| serde_json::from_str(SNAPSHOT_JSON).expect("versions/releases.json parses"))
}

/// The newest Agave release for `network`, at or above its floor.
///
/// # Errors
///
/// Returns [`VersionError`] for a network erpc has no floor for, or when no
/// release fits.
pub fn recommend<'a>(network: &str, notes: &'a [Note]) -> Result<&'a Note, VersionError> {
    let floor = floor(network).ok_or_else(|| VersionError::Network(network.to_owned()))?;
    let bar = read_floor(floor);
    notes
        .iter()
        .filter(|n| suitable(&n.first_line).names(network))
        .filter_map(|n| Some((read(&n.tag)?, n)))
        .filter(|(r, _)| *r >= bar)
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, n)| n)
        .ok_or(VersionError::NoRelease {
            client: "agave".to_owned(),
            network: network.to_owned(),
            floor,
        })
}

/// The Jito build of Agave release `agave_tag`: `<tag>-jito`, or the latest
/// `<tag>-jito.N` that supersedes it.
#[must_use]
pub fn jito_tag<'a>(agave_tag: &str, jito_tags: &'a [String]) -> Option<&'a str> {
    suffixed_tag(agave_tag, "jito", jito_tags)
}

/// The Allnodes build of Agave release `agave_tag`: `<tag>-allnodes`, or the
/// latest `<tag>-allnodes.N`.
#[must_use]
pub fn allnodes_tag<'a>(agave_tag: &str, tags: &'a [String]) -> Option<&'a str> {
    suffixed_tag(agave_tag, "allnodes", tags)
}

/// `<agave_tag>-<suffix>` or the latest `<agave_tag>-<suffix>.N`.
fn suffixed_tag<'a>(agave_tag: &str, suffix: &str, tags: &'a [String]) -> Option<&'a str> {
    let base = format!("{agave_tag}-{suffix}");
    tags.iter()
        .filter_map(|t| {
            let rest = t.strip_prefix(&base)?;
            let n = if rest.is_empty() {
                Some(0)
            } else {
                rest.strip_prefix('.')?.parse::<u64>().ok().map(|n| n + 1)
            };
            Some((n?, t.as_str()))
        })
        .max_by_key(|(n, _)| *n)
        .map(|(_, t)| t)
}

/// The GitHub repository of a client's releases.
///
/// # Errors
///
/// Returns [`VersionError::Client`] for a client erpc does not pin.
pub fn repository(client: &str) -> Result<&'static str, VersionError> {
    match client {
        "agave" => Ok("anza-xyz/agave"),
        "jito" => Ok("jito-foundation/jito-solana"),
        "allnodes-jito" => Ok("allnodes/solana-jito"),
        "firedancer" => Ok("firedancer-io/firedancer"),
        other => Err(VersionError::Client(other.to_owned())),
    }
}

/// The releases a recommendation reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct Releases<'a> {
    /// Agave's release notes.
    pub agave: &'a [Note],
    /// Jito's tags.
    pub jito: &'a [String],
    /// Allnodes' tags.
    pub allnodes: &'a [String],
    /// Firedancer's release notes.
    pub firedancer: &'a [Note],
}

/// The tag `client` would run on `network`, from the releases given.
///
/// # Errors
///
/// Returns [`VersionError`] when no release fits.
pub fn recommended_tag(
    client: &str,
    network: &str,
    releases: Releases<'_>,
) -> Result<String, VersionError> {
    if client == "firedancer" {
        return recommend_firedancer(network, releases.firedancer).map(|n| n.tag.clone());
    }
    let release = recommend(network, releases.agave)?;
    let none = || VersionError::NoRelease {
        client: client.to_owned(),
        network: network.to_owned(),
        floor: floor(network).unwrap_or_default(),
    };
    match client {
        "agave" => Ok(release.tag.clone()),
        "jito" => jito_tag(&release.tag, releases.jito)
            .map(str::to_owned)
            .ok_or_else(none),
        "allnodes-jito" => allnodes_tag(&release.tag, releases.allnodes)
            .map(str::to_owned)
            .ok_or_else(none),
        other => Err(VersionError::Client(other.to_owned())),
    }
}

impl Snapshot {
    /// The carried copy as [`Releases`].
    #[must_use]
    pub fn releases(&self) -> Releases<'_> {
        Releases {
            agave: &self.agave,
            jito: &self.jito,
            allnodes: &self.allnodes,
            firedancer: &self.firedancer,
        }
    }
}

/// Refuses anything but a full, lowercase commit SHA.
///
/// # Errors
///
/// Returns [`VersionError::Commit`] otherwise.
pub fn check_commit(sha: &str) -> Result<(), VersionError> {
    if sha.len() == 40 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(VersionError::Commit(sha.to_owned()))
    }
}

/// The bundle's `vars/versions.yml` for a validator on `network`: the
/// pinned version of its client, without the `v` the build plays add, and
/// the commit the build must check out. JSON, which YAML reads as it is.
///
/// # Errors
///
/// Returns [`VersionError`] when the pin is below the floor, unreadable, for
/// a client erpc does not pin, or its commit is not a full SHA.
pub fn versions_yml(
    network: &str,
    client: &str,
    tag: &str,
    commit: &str,
) -> Result<String, VersionError> {
    repository(client)?;
    check_client_floor(network, client, tag)?;
    check_commit(commit)?;
    let version = tag.strip_prefix('v').unwrap_or(tag);
    let key = client.replace('-', "_");
    let mut section = Map::new();
    section.insert(format!("version_{key}"), Value::from(version));
    section.insert(format!("commit_{key}"), Value::from(commit));
    let doc = json!({ format!("{network}_validators"): section });
    Ok(format!("{doc:#}\n"))
}

/// Orders two versions; `None` when either cannot be read.
#[must_use]
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    Some(read(a)?.cmp(&read(b)?))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        Note, Release, VersionError, allnodes_tag, check_client_floor, check_floor, first_line,
        jito_tag, read, recommend, recommend_firedancer, recommended_tag, snapshot, suitable,
        versions_yml,
    };

    /// SLV's cases for its floor (`tests/alpenglow_floor_vectors.json` of the
    /// template erpc carries), which its play and its CLI both answer.
    const VECTORS: &str = include_str!("../versions/testdata/alpenglow_floor_vectors.json");

    #[test]
    fn versions_read_and_compare_as_slv_reads_them() {
        let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
        let floors = vectors["floors"].as_object().expect("floors");
        for (network, floor) in floors {
            assert_eq!(super::floor(network), floor.as_str(), "{network}");
        }
        let cases = vectors["client_versions"].as_array().expect("cases");
        assert!(cases.len() > 50);
        for case in cases {
            let value = match &case["value"] {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let expected = case["reads"].as_array().map(|r| {
                let n = |i: usize| r[i].as_u64().expect("number");
                Release {
                    numbers: [n(0), n(1), n(2)],
                    rank: u8::try_from(n(3)).expect("rank"),
                    number: n(4),
                }
            });
            assert_eq!(read(&value), expected, "{value}: {}", case["why"]);
            for (network, below) in case["below"].as_object().expect("below") {
                let refused = matches!(
                    check_floor(network, &value),
                    Err(VersionError::BelowFloor { .. })
                );
                assert_eq!(
                    refused,
                    below.as_bool().expect("bool"),
                    "{value} on {network}"
                );
            }
        }
    }

    #[test]
    fn an_unreadable_version_is_refused_everywhere() {
        for network in ["mainnet", "testnet"] {
            assert!(matches!(
                check_floor(network, "main"),
                Err(VersionError::Unreadable(_))
            ));
        }
        assert!(matches!(
            check_floor("localnet", "4.4.0"),
            Err(VersionError::Network(_))
        ));
    }

    #[test]
    fn each_first_line_agave_writes_is_read_for_its_clusters() {
        let cases = [
            (
                "This a stable release suitable for Testnet, Devnet and Mainnet Beta.",
                (true, true, true),
            ),
            ("This a stable release.", (true, false, false)),
            ("This is a testnet release.", (false, true, false)),
            (
                "This is a testnet release. It is also recommended for Devnet.",
                (false, true, true),
            ),
            (
                "This is a testnet release.  It is also recommended for Devnet.",
                (false, true, true),
            ),
            (
                "This is Mainnet-beta Upgrade Candidate release recommended for 10% adoption.",
                (false, false, false),
            ),
            (
                "This is Mainnet-beta Upgrade Candidate release. It is also recommended for Testnet and Devnet.",
                (false, true, true),
            ),
            (
                "This is a pre-release for testing only. Do not deploy to mainnet, testnet, or any production host.",
                (false, false, false),
            ),
            ("## What's Changed", (false, false, false)),
            ("> [!WARNING]", (false, false, false)),
        ];
        for (line, (mainnet, testnet, devnet)) in cases {
            let s = suitable(line);
            assert_eq!(
                (s.mainnet, s.testnet, s.devnet),
                (mainnet, testnet, devnet),
                "{line}"
            );
        }
        assert_eq!(
            first_line("\n\n  This is a testnet release.\nmore"),
            "This is a testnet release."
        );
    }

    #[test]
    fn every_first_line_in_the_snapshot_is_one_the_rule_knows() {
        let known = [
            "stable release",
            "testnet release",
            "upgrade candidate",
            "for testing only",
            "what's changed",
            "[!warning]",
        ];
        for note in &snapshot().agave {
            let line = note.first_line.to_ascii_lowercase();
            assert!(
                known.iter().any(|k| line.contains(k)),
                "{}: {line}",
                note.tag
            );
        }
    }

    #[test]
    fn the_snapshot_recommends_the_newest_release_for_each_network() {
        let s = snapshot();
        assert_eq!(s.read, "2026-10-24");
        assert_eq!(
            recommend("testnet", &s.agave).map(|n| n.tag.as_str()),
            Ok("v4.4.0-beta.1")
        );
        assert_eq!(
            recommend("mainnet", &s.agave).map(|n| n.tag.as_str()),
            Ok("v4.3.2")
        );
        assert_eq!(
            recommended_tag("jito", "testnet", s.releases()).as_deref(),
            Ok("v4.4.0-beta.1-jito")
        );
        assert_eq!(
            recommended_tag("jito", "mainnet", s.releases()).as_deref(),
            Ok("v4.3.2-jito")
        );
        assert_eq!(
            recommended_tag("allnodes-jito", "mainnet", s.releases()).as_deref(),
            Ok("v4.3.2-allnodes")
        );
        assert_eq!(
            recommended_tag("allnodes-jito", "testnet", s.releases()).as_deref(),
            Ok("v4.4.0-beta.1-allnodes")
        );
        for network in ["mainnet", "testnet"] {
            assert_eq!(
                recommended_tag("firedancer", network, s.releases()).as_deref(),
                Ok("v26.10.4")
            );
        }
    }

    #[test]
    fn firedancer_is_the_full_client_at_or_above_its_alpenglow_floor() {
        let note = |tag: &str, line: &str| Note {
            tag: tag.to_owned(),
            first_line: line.to_owned(),
        };
        let mainnet_ready = "This is a mainnet ready release.";
        let testnet = "This is a Testnet Release. It is not suggested for Mainnet Beta use.";
        let notes = [
            note("v26.10.1", testnet),
            note("v26.10.3", mainnet_ready),
            note("v26.11.0", testnet),
            note("v26.09.6", mainnet_ready),
            note("v0.1204.40300", mainnet_ready),
        ];
        let tag = |n: &str| recommend_firedancer(n, &notes).map(|n| n.tag.clone());
        assert_eq!(tag("mainnet").as_deref(), Ok("v26.10.3"));
        assert_eq!(tag("testnet").as_deref(), Ok("v26.11.0"));
        assert!(recommend_firedancer("mainnet", &notes[..1]).is_err());
        assert!(check_client_floor("mainnet", "firedancer", "v26.10.2").is_ok());
        assert!(check_client_floor("mainnet", "firedancer", "v26.09.6").is_err());
        assert!(check_client_floor("mainnet", "firedancer", "v0.1204.40300").is_err());
        assert!(check_client_floor("mainnet", "agave", "v4.3.2").is_ok());
    }

    #[test]
    fn allnodes_builds_follow_the_agave_tag() {
        let tags: Vec<String> = ["v4.3.0-allnodes", "v4.3.0-allnodes.1", "v4.3.2-allnodes"]
            .map(str::to_owned)
            .to_vec();
        assert_eq!(allnodes_tag("v4.3.0", &tags), Some("v4.3.0-allnodes.1"));
        assert_eq!(allnodes_tag("v4.3.1", &tags), None);
    }

    #[test]
    fn a_release_suitable_for_testnet_but_below_its_floor_is_not_recommended() {
        let note = |tag: &str, line: &str| Note {
            tag: tag.to_owned(),
            first_line: line.to_owned(),
        };
        let notes = [
            note(
                "v4.3.2",
                "This a stable release suitable for Testnet, Devnet and Mainnet Beta.",
            ),
            note("v4.5.0-alpha.2", "This is a pre-release for testing only."),
        ];
        assert!(matches!(
            recommend("testnet", &notes),
            Err(VersionError::NoRelease { .. })
        ));
        // Newest by version, not by the order the notes come in.
        let notes = [
            note("v4.4.0-beta.0", "This is a testnet release."),
            note("v4.4.0-beta.2", "This is a testnet release."),
            note("v4.4.0-beta.1", "This is a testnet release."),
        ];
        assert_eq!(
            recommend("testnet", &notes).map(|n| n.tag.as_str()),
            Ok("v4.4.0-beta.2")
        );
    }

    #[test]
    fn a_superseding_jito_build_wins() {
        let tags: Vec<String> = [
            "v4.3.0-jito",
            "v4.3.0-jito.1",
            "v4.3.0-jito.0",
            "v4.3.0-rc.1-jito",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(jito_tag("v4.3.0", &tags), Some("v4.3.0-jito.1"));
        assert_eq!(jito_tag("v4.3.1", &tags), None);
    }

    #[test]
    fn the_versions_file_pins_the_tag_and_its_commit() {
        let sha = "3ad9da2c390eb7ad2630ed15afcd463e72e007a8";
        let text = versions_yml("testnet", "agave", "v4.4.0-beta.1", sha).expect("pinned");
        let doc: Value = serde_json::from_str(&text).expect("JSON, which YAML reads");
        assert_eq!(doc["testnet_validators"]["version_agave"], "4.4.0-beta.1");
        assert_eq!(doc["testnet_validators"]["commit_agave"], sha);
        assert!(matches!(
            versions_yml("testnet", "agave", "v4.3.2", sha),
            Err(VersionError::BelowFloor { .. })
        ));
        assert!(matches!(
            versions_yml("testnet", "agave", "v4.4.0-beta.1", "3ad9da2"),
            Err(VersionError::Commit(_))
        ));
        assert!(matches!(
            versions_yml("testnet", "firedancer", "v4.4.0-beta.1", sha),
            Err(VersionError::BelowFloor { .. })
        ));
        assert!(matches!(
            versions_yml("testnet", "solana", "v4.4.0-beta.1", sha),
            Err(VersionError::Client(_))
        ));
        let doc: Value = serde_json::from_str(
            &versions_yml("mainnet", "allnodes-jito", "v4.3.2-allnodes", sha).expect("pinned"),
        )
        .expect("JSON");
        assert_eq!(
            doc["mainnet_validators"]["version_allnodes_jito"],
            "4.3.2-allnodes"
        );
        assert_eq!(doc["mainnet_validators"]["commit_allnodes_jito"], sha);
        let doc: Value = serde_json::from_str(
            &versions_yml("mainnet", "firedancer", "v26.10.4", sha).expect("pinned"),
        )
        .expect("JSON");
        assert_eq!(doc["mainnet_validators"]["version_firedancer"], "26.10.4");
    }
}
