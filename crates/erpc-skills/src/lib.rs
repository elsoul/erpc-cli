// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-skills`: the assistant's skills, one per subject, compiled into
//! the binary so they match the version the user runs.
//!
//! A skill is a directory under `skills/` holding a `SKILL.md` in the Agent
//! Skills form: frontmatter with `name` and `description`, then Markdown.
//! The name says what it is about, most specific last:
//!
//! - `erpc-<subject>` for ERPC itself (`erpc-account`, `erpc-services`);
//! - `<chain>-<role>-<network>` for a node, when the networks differ in
//!   practice (`solana-validator-mainnet`, `solana-validator-testnet`);
//! - `<chain>-<role>` when they do not (`arc-rpc`, `sui-node`).
//!
//! The assistant is given every name and description, and reads a skill's
//! text when a question needs it.

#![forbid(unsafe_code)]

pub mod install;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-skills";

/// One skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skill {
    /// Its name, the directory it is in.
    pub name: &'static str,
    /// When it applies, for choosing it.
    pub description: &'static str,
    /// The text after the frontmatter.
    pub body: &'static str,
}

/// Each skill's directory and file, in the order they are listed.
const FILES: &[(&str, &str)] = &[
    (
        "erpc-account",
        include_str!("../skills/erpc-account/SKILL.md"),
    ),
    (
        "erpc-services",
        include_str!("../skills/erpc-services/SKILL.md"),
    ),
    (
        "erpc-storage",
        include_str!("../skills/erpc-storage/SKILL.md"),
    ),
    ("erpc-nodes", include_str!("../skills/erpc-nodes/SKILL.md")),
    (
        "erpc-rpc-bench",
        include_str!("../skills/erpc-rpc-bench/SKILL.md"),
    ),
    (
        "erpc-worker",
        include_str!("../skills/erpc-worker/SKILL.md"),
    ),
    (
        "solana-validator-mainnet",
        include_str!("../skills/solana-validator-mainnet/SKILL.md"),
    ),
    (
        "solana-validator-testnet",
        include_str!("../skills/solana-validator-testnet/SKILL.md"),
    ),
    (
        "solana-rpc-mainnet",
        include_str!("../skills/solana-rpc-mainnet/SKILL.md"),
    ),
    (
        "op-follower-node",
        include_str!("../skills/op-follower-node/SKILL.md"),
    ),
    ("nitro-node", include_str!("../skills/nitro-node/SKILL.md")),
    ("arc-rpc", include_str!("../skills/arc-rpc/SKILL.md")),
    (
        "ethereum-node",
        include_str!("../skills/ethereum-node/SKILL.md"),
    ),
    (
        "avalanche-node",
        include_str!("../skills/avalanche-node/SKILL.md"),
    ),
    ("sui-node", include_str!("../skills/sui-node/SKILL.md")),
    (
        "bitcoin-node",
        include_str!("../skills/bitcoin-node/SKILL.md"),
    ),
];

/// Every skill, in a fixed order.
///
/// # Panics
///
/// Never in a build whose tests pass: every file is checked to parse.
#[must_use]
pub fn all() -> Vec<Skill> {
    FILES
        .iter()
        .map(|(dir, text)| parse(text).unwrap_or_else(|e| panic!("skills/{dir}/SKILL.md: {e}")))
        .collect()
}

/// The skill named `name`.
#[must_use]
pub fn get(name: &str) -> Option<Skill> {
    all().into_iter().find(|skill| skill.name == name)
}

/// The names and descriptions, one line each, for the assistant to choose
/// from.
#[must_use]
pub fn index() -> String {
    all()
        .iter()
        .map(|skill| format!("- `{}`: {}", skill.name, skill.description))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A `SKILL.md`: the frontmatter's `name` and `description`, and the rest.
fn parse(text: &'static str) -> Result<Skill, String> {
    let rest = text
        .strip_prefix("---\n")
        .ok_or("does not start with frontmatter")?;
    let (front, body) = rest
        .split_once("\n---\n")
        .ok_or("the frontmatter is not closed")?;
    let field = |key: &str| {
        front
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(format!("no {key} in the frontmatter"))
    };
    Ok(Skill {
        name: field("name")?,
        description: field("description")?,
        body: body.trim_start(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn embedded_skill_bytes_do_not_depend_on_checkout_platform() {
        for (name, text) in super::FILES {
            assert!(
                !text.contains('\r'),
                "{name}: checkout must preserve LF for embedded files"
            );
        }
    }

    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn every_chain_skill_points_to_its_official_sources() {
        // What a skill says about releases and flags ages; the project's own
        // repository and documentation do not, so every chain skill names them.
        for skill in super::all().iter().filter(|s| !s.name.starts_with("erpc-")) {
            let (_, sources) = skill
                .body
                .split_once("\n## Official sources\n")
                .unwrap_or_else(|| panic!("{} has no Official sources section", skill.name));
            assert!(
                sources.contains("https://github.com/"),
                "{} names no repository",
                skill.name
            );
            assert!(
                sources
                    .lines()
                    .filter(|l| l.starts_with("- https://"))
                    .count()
                    >= 2,
                "{} names fewer than two sources",
                skill.name
            );
        }
    }

    #[test]
    fn every_skill_is_named_after_its_directory_once() {
        let skills = super::all();
        assert_eq!(skills.len(), super::FILES.len());
        for (skill, (dir, _)) in skills.iter().zip(super::FILES) {
            assert_eq!(skill.name, *dir);
            assert!(
                skill
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{}",
                skill.name
            );
            assert!(skill.body.starts_with("# "), "{} has a title", skill.name);
            assert!(
                skill.description.len() <= 400,
                "{}'s description is short",
                skill.name
            );
        }
        let mut names: Vec<_> = skills.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), skills.len());
    }

    #[test]
    fn every_skill_directory_is_listed() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/skills");
        let mut found: Vec<String> = std::fs::read_dir(dir)
            .expect("skills directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        found.sort();
        let mut listed: Vec<&str> = super::FILES.iter().map(|(dir, _)| *dir).collect();
        listed.sort_unstable();
        assert_eq!(found, listed);
    }

    #[test]
    fn a_skill_a_skill_names_exists() {
        let names: Vec<_> = super::all().iter().map(|s| s.name).collect();
        for skill in super::all() {
            for word in skill.body.split('`').skip(1).step_by(2) {
                let looks_like_one = (word.starts_with("erpc-")
                    || word.starts_with("solana-")
                    || word.ends_with("-node"))
                    && !word.contains(' ');
                if looks_like_one {
                    assert!(names.contains(&word), "{} names {word}", skill.name);
                }
            }
        }
    }

    #[test]
    fn frontmatter_that_is_missing_or_open_is_refused() {
        assert!(super::parse("# no frontmatter").is_err());
        assert!(super::parse("---\nname: a\ndescription: b\n").is_err());
        assert!(super::parse("---\nname: a\n---\n# A").is_err());
        let skill = super::parse("---\nname: a\ndescription: b c\n---\n\n# A\n").expect("parses");
        assert_eq!(
            (skill.name, skill.description, skill.body),
            ("a", "b c", "# A\n")
        );
        assert!(super::get("solana-validator-mainnet").is_some());
        assert!(super::get("nodes").is_none());
    }
}
