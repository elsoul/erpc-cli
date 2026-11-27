// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The collector's plain-text key search: what it found, counted by kind,
//! role, class of place and who can read it, with the places themselves.
//!
//! None of this is sent anywhere: the billing facts and the report request
//! leave the section out, `--json` carries its counts and classes without
//! the places, and the places are printed only on the operator's screen,
//! escaped so that a file's name cannot drive the terminal.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

/// How many places of one group the collector lists.
pub(super) const PLACES_SHOWN: usize = 10;
/// The longest place, in characters of its encoding.
pub(super) const PLACE_LIMIT: usize = 1024;
/// All places together, each counted with 3 more for its quotes and comma.
pub(super) const PLACES_BUDGET: usize = 6144;
/// The largest count of a group.
pub(super) const MAX_COUNT: u32 = 100_000;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    SolanaKeypair,
    EvmPrivateKey,
    Mnemonic,
    UnencryptedKeystore,
    EnvSecret,
    ProcessEnvSecret,
    HistorySecret,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum Role {
    ValidatorIdentity,
    Unknown,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum Location {
    Home,
    RootHome,
    Etc,
    Opt,
    Srv,
    Var,
    Tmp,
    Docker,
    ProcessEnv,
    ShellHistory,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum Access {
    OwnerOnly,
    Group,
    World,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Coverage {
    Complete,
    Partial,
    Unreadable,
}

/// A local finding the key groups raise, in the order the report lists
/// them. Each kind raises its own; a keypair that is the validator's
/// identity raises one only when others than its owner can read it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Finding {
    PlaintextWalletKey,
    ValidatorIdentityPermissions,
    MnemonicOnDisk,
    UnencryptedKeystore,
    SecretInEnvFile,
    SecretInProcessEnv,
    SecretInShellHistory,
}

impl Finding {
    const ALL: [Self; 7] = [
        Self::PlaintextWalletKey,
        Self::ValidatorIdentityPermissions,
        Self::MnemonicOnDisk,
        Self::UnencryptedKeystore,
        Self::SecretInEnvFile,
        Self::SecretInProcessEnv,
        Self::SecretInShellHistory,
    ];

    const fn id(self) -> &'static str {
        match self {
            Self::PlaintextWalletKey => "plaintext_wallet_key",
            Self::ValidatorIdentityPermissions => "validator_identity_permissions",
            Self::MnemonicOnDisk => "mnemonic_on_disk",
            Self::UnencryptedKeystore => "unencrypted_keystore",
            Self::SecretInEnvFile => "secret_in_env_file",
            Self::SecretInProcessEnv => "secret_in_process_env",
            Self::SecretInShellHistory => "secret_in_shell_history",
        }
    }

    fn text(self) -> String {
        let (finding, fix) = match self {
            Self::PlaintextWalletKey => (
                t!("node_check.finding_plaintext_wallet_key"),
                t!("node_check.fix_plaintext_wallet_key"),
            ),
            Self::ValidatorIdentityPermissions => (
                t!("node_check.finding_validator_identity_permissions"),
                t!("node_check.fix_validator_identity_permissions"),
            ),
            Self::MnemonicOnDisk => (
                t!("node_check.finding_mnemonic_on_disk"),
                t!("node_check.fix_mnemonic_on_disk"),
            ),
            Self::UnencryptedKeystore => (
                t!("node_check.finding_unencrypted_keystore"),
                t!("node_check.fix_unencrypted_keystore"),
            ),
            Self::SecretInEnvFile => (
                t!("node_check.finding_secret_in_env_file"),
                t!("node_check.fix_secret_in_env_file"),
            ),
            Self::SecretInProcessEnv => (
                t!("node_check.finding_secret_in_process_env"),
                t!("node_check.fix_secret_in_process_env"),
            ),
            Self::SecretInShellHistory => (
                t!("node_check.finding_secret_in_shell_history"),
                t!("node_check.fix_secret_in_shell_history"),
            ),
        };
        t!("node_check.key_finding", finding = finding, fix = fix)
    }
}

/// The finding that every account can read a key, raised beside a group's
/// own.
const WORLD_READABLE: &str = "key_world_readable";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    kind: Kind,
    role: Role,
    location: Location,
    access: Access,
    count: u32,
    /// Where, as the collector encoded the paths: never serialized again.
    #[serde(skip_serializing)]
    places: Vec<String>,
    /// How many more places there are than `places` lists.
    #[serde(skip_serializing)]
    more: u32,
}

impl Group {
    const fn key(&self) -> (Kind, Role, Location, Access) {
        (self.kind, self.role, self.location, self.access)
    }

    /// Whether the kind, role, place and access can go together, as the
    /// collector makes them.
    const fn consistent(&self) -> bool {
        let identity = matches!(self.role, Role::ValidatorIdentity);
        let files = !matches!(self.location, Location::ProcessEnv | Location::ShellHistory);
        match self.kind {
            Kind::SolanaKeypair => files,
            Kind::ProcessEnvSecret => {
                !identity
                    && matches!(self.location, Location::ProcessEnv)
                    && matches!(self.access, Access::OwnerOnly)
            }
            Kind::HistorySecret => !identity && matches!(self.location, Location::ShellHistory),
            Kind::EvmPrivateKey | Kind::Mnemonic | Kind::UnencryptedKeystore | Kind::EnvSecret => {
                !identity && files
            }
        }
    }

    fn valid(&self) -> bool {
        self.consistent()
            && (1..=MAX_COUNT).contains(&self.count)
            && self.places.len() <= PLACES_SHOWN
            && u64::try_from(self.places.len()).unwrap_or(u64::MAX) + u64::from(self.more)
                <= u64::from(self.count)
            && self.places.iter().all(|place| decode(place).is_some())
    }

    fn finding(&self) -> Option<Finding> {
        Some(match (self.kind, self.role) {
            (Kind::SolanaKeypair, Role::ValidatorIdentity) => {
                if self.access == Access::OwnerOnly {
                    return None;
                }
                Finding::ValidatorIdentityPermissions
            }
            (Kind::SolanaKeypair | Kind::EvmPrivateKey, _) => Finding::PlaintextWalletKey,
            (Kind::Mnemonic, _) => Finding::MnemonicOnDisk,
            (Kind::UnencryptedKeystore, _) => Finding::UnencryptedKeystore,
            (Kind::EnvSecret, _) => Finding::SecretInEnvFile,
            (Kind::ProcessEnvSecret, _) => Finding::SecretInProcessEnv,
            (Kind::HistorySecret, _) => Finding::SecretInShellHistory,
        })
    }

    fn detail(&self) -> String {
        t!(
            "node_check.key",
            kind = wire(self.kind),
            role = wire(self.role),
            location = wire(self.location),
            access = wire(self.access),
            count = self.count
        )
    }

    fn describe(&self, text: &mut String, places: bool) {
        let _ = writeln!(text, "  - {}", self.detail());
        if !places {
            return;
        }
        for place in &self.places {
            let _ = writeln!(text, "      {}", shown(place));
        }
        if self.more > 0 {
            let _ = writeln!(
                text,
                "      {}",
                t!("node_check.key_more", count = self.more)
            );
        }
    }
}

/// A class as the collector names it.
fn wire(value: impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => String::new(),
    }
}

/// The plain-text key search's section of the collector's report.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Keys {
    coverage: Coverage,
    groups: Vec<Group>,
}

impl Keys {
    /// Whether the section keeps to the collector's bounds: groups of
    /// consistent classes, each once and in order, counts in range, at most
    /// [`PLACES_SHOWN`] places a group, each a well-formed encoding of at
    /// most [`PLACE_LIMIT`] characters, all within [`PLACES_BUDGET`].
    pub(super) fn valid(&self) -> bool {
        let spent: usize = self
            .groups
            .iter()
            .flat_map(|group| &group.places)
            .map(|place| place.len() + 3)
            .sum();
        (self.coverage != Coverage::Unreadable || self.groups.is_empty())
            && self
                .groups
                .windows(2)
                .all(|pair| pair[0].key() < pair[1].key())
            && self.groups.iter().all(Group::valid)
            && spent <= PLACES_BUDGET
    }

    /// The local findings the groups raise, by id, for `localFindings`.
    pub(super) fn findings(&self) -> Vec<&'static str> {
        let mut ids: Vec<&'static str> = Finding::ALL
            .into_iter()
            .filter(|finding| self.groups.iter().any(|g| g.finding() == Some(*finding)))
            .map(Finding::id)
            .collect();
        if self
            .groups
            .iter()
            .any(|group| group.access == Access::World)
        {
            ids.push(WORLD_READABLE);
        }
        ids
    }

    pub(super) fn describe(&self, text: &mut String) {
        let heading = match self.coverage {
            Coverage::Complete => t!("node_check.key_search_complete"),
            Coverage::Partial => t!("node_check.key_search_partial"),
            Coverage::Unreadable => t!("node_check.key_search_unreadable"),
        };
        let _ = writeln!(text, "{heading}");
        if self.groups.is_empty() {
            if self.coverage != Coverage::Unreadable {
                let _ = writeln!(text, "{}", t!("node_check.key_none"));
            }
            return;
        }
        for finding in Finding::ALL {
            let mut groups = self
                .groups
                .iter()
                .filter(|group| group.finding() == Some(finding))
                .peekable();
            if groups.peek().is_some() {
                let _ = writeln!(text, "{}", finding.text());
                groups.for_each(|group| group.describe(text, true));
            }
        }
        let mut kept = self
            .groups
            .iter()
            .filter(|group| group.finding().is_none())
            .peekable();
        if kept.peek().is_some() {
            let _ = writeln!(text, "{}", t!("node_check.key_identity_kept"));
            kept.for_each(|group| group.describe(text, true));
        }
        let mut open = self
            .groups
            .iter()
            .filter(|group| group.access == Access::World)
            .peekable();
        if open.peek().is_some() {
            let _ = writeln!(
                text,
                "{}",
                t!(
                    "node_check.key_finding",
                    finding = t!("node_check.finding_key_world_readable"),
                    fix = t!("node_check.fix_key_world_readable")
                )
            );
            // The places are listed above, under the group's own finding.
            open.for_each(|group| group.describe(text, false));
        }
    }
}

/// Whether the collector writes `byte` as itself: printable ASCII other
/// than `%`, `"` and `\`, so that JSON leaves it as it is.
const fn plain(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e) && !matches!(byte, b'"' | b'%' | b'\\')
}

/// The bytes of a path as the collector encodes it: an absolute path of at
/// most [`PLACE_LIMIT`] characters, each byte either itself (see [`plain`])
/// or `%` and two upper-case hexadecimal digits, and only a byte that is not
/// written as itself, never NUL. `None` for anything else.
fn decode(place: &str) -> Option<Vec<u8>> {
    let encoded = place.as_bytes();
    if encoded.len() > PLACE_LIMIT || encoded.first() != Some(&b'/') {
        return None;
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut at = 0;
    while let Some(&byte) = encoded.get(at) {
        if byte == b'%' {
            let high = digit(*encoded.get(at + 1)?)?;
            let low = digit(*encoded.get(at + 2)?)?;
            let value = (high << 4) | low;
            if value == 0 || plain(value) {
                return None;
            }
            bytes.push(value);
            at += 3;
        } else if plain(byte) {
            bytes.push(byte);
            at += 1;
        } else {
            return None;
        }
    }
    Some(bytes)
}

/// A place as the operator reads it: its characters, with `\` doubled,
/// control, bidirectional and invisible formatting characters escaped as
/// `\u{…}`, and each byte that is not UTF-8 as `\xHH`. So a file's name
/// cannot rewrite the terminal or hide part of itself. Characters that
/// merely look alike (a Cyrillic `а` for a Latin `a`) are shown as they are.
fn shown(place: &str) -> String {
    let hidden = |c: char| {
        matches!(
            c,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
        )
    };
    let mut text = String::new();
    for chunk in decode(place).unwrap_or_default().utf8_chunks() {
        for c in chunk.valid().chars() {
            if c == '\\' {
                text.push_str("\\\\");
            } else if c.is_control() || hidden(c) {
                let _ = write!(text, "{}", c.escape_unicode());
            } else {
                text.push(c);
            }
        }
        for byte in chunk.invalid() {
            let _ = write!(text, "\\x{byte:02x}");
        }
    }
    text
}

#[cfg(test)]
pub(super) mod tests {
    use serde_json::{Value, json};

    use super::{Keys, MAX_COUNT, PLACE_LIMIT, PLACES_BUDGET, decode, shown};

    /// Every group the collector can make, in its order, as
    /// `(kind, role, location, access)`.
    pub(in crate::node) fn every_group() -> Vec<[&'static str; 4]> {
        let files = [
            "home",
            "root_home",
            "etc",
            "opt",
            "srv",
            "var",
            "tmp",
            "docker",
        ];
        let access = ["owner_only", "group", "world"];
        let mut groups = Vec::new();
        for (kind, roles) in [
            ("solana_keypair", &["validator_identity", "unknown"][..]),
            ("evm_private_key", &["unknown"]),
            ("mnemonic", &["unknown"]),
            ("unencrypted_keystore", &["unknown"]),
            ("env_secret", &["unknown"]),
            ("process_env_secret", &["unknown"]),
            ("history_secret", &["unknown"]),
        ] {
            let (locations, reach): (&[&str], &[&str]) = match kind {
                "process_env_secret" => (&["process_env"], &["owner_only"]),
                "history_secret" => (&["shell_history"], &access),
                _ => (&files, &access),
            };
            for role in roles {
                for location in locations {
                    for access in reach {
                        groups.push([kind, role, location, access]);
                    }
                }
            }
        }
        groups
    }

    fn group(kind: &str, role: &str, location: &str, access: &str) -> Value {
        json!({"kind": kind, "role": role, "location": location, "access": access,
            "count": 1, "places": [], "more": 0})
    }

    fn keys(value: &Value) -> Option<Keys> {
        serde_json::from_value::<Keys>(value.clone())
            .ok()
            .filter(Keys::valid)
    }

    #[test]
    fn every_group_the_collector_makes_is_accepted_once_and_in_order() {
        let all: Vec<Value> = every_group()
            .iter()
            .map(|[k, r, l, a]| group(k, r, l, a))
            .collect();
        assert_eq!(all.len(), 148);
        assert!(keys(&json!({"coverage": "partial", "groups": all})).is_some());
        let mut swapped = all.clone();
        swapped.swap(0, 1);
        assert!(keys(&json!({"coverage": "partial", "groups": swapped})).is_none());
        let twice = vec![all[0].clone(), all[0].clone()];
        assert!(keys(&json!({"coverage": "partial", "groups": twice})).is_none());
    }

    #[test]
    fn the_parser_refuses_what_the_collector_never_makes() {
        let ok = group("mnemonic", "unknown", "opt", "world");
        assert!(keys(&json!({"coverage": "complete", "groups": [ok]})).is_some());
        for bad in [
            group("mnemonic", "validator_identity", "opt", "world"),
            group("mnemonic", "unknown", "process_env", "owner_only"),
            group("process_env_secret", "unknown", "process_env", "world"),
            group("process_env_secret", "unknown", "home", "owner_only"),
            group("history_secret", "unknown", "home", "owner_only"),
            group("solana_keypair", "unknown", "shell_history", "owner_only"),
            group("mnemonic", "unknown", "mnt", "world"),
        ] {
            assert!(
                keys(&json!({"coverage": "complete", "groups": [bad]})).is_none(),
                "{bad}"
            );
        }
        let with = |field: &str, value: Value| {
            let mut changed = ok.clone();
            changed[field] = value;
            json!({"coverage": "complete", "groups": [changed]})
        };
        for (field, value) in [
            ("count", json!(0)),
            ("count", json!(MAX_COUNT + 1)),
            ("count", json!(-1)),
            ("more", json!(2)),
            ("places", json!(["/a", "/b"])),
            ("places", json!(vec!["/a"; 11])),
            ("path", json!("/a")),
        ] {
            assert!(
                keys(&with(field, value.clone())).is_none(),
                "{field} {value}"
            );
        }
        let mut many = ok.clone();
        many["count"] = json!(12);
        many["places"] = json!(vec!["/a"; 10]);
        many["more"] = json!(2);
        assert!(keys(&json!({"coverage": "complete", "groups": [many]})).is_some());
        assert!(keys(&json!({"coverage": "unreadable", "groups": [ok]})).is_none());
        assert!(keys(&json!({"coverage": "unreadable", "groups": []})).is_some());
        assert!(keys(&json!({"coverage": "absent", "groups": []})).is_none());
        assert!(keys(&json!({"coverage": "complete", "groups": [], "extra": 1})).is_none());
    }

    #[test]
    fn places_are_bounded_and_strictly_encoded() {
        let long = format!("/{}", "a".repeat(PLACE_LIMIT - 1));
        assert_eq!(decode(&long).map(|b| b.len()), Some(PLACE_LIMIT));
        assert!(decode(&format!("{long}a")).is_none());
        assert_eq!(
            decode("/home/a%25b%22c%5Cd%FF%E3%81%82").as_deref(),
            Some(&b"/home/a%b\"c\\d\xff\xe3\x81\x82"[..])
        );
        for bad in [
            "home/x", "", "/a%", "/a%4", "/a%ff", "/a%41", "/a%00", "/a%2G", "/a%+F", "/a\"b",
            "/a\\b", "/a\tb", "/a\u{e9}",
        ] {
            assert!(decode(bad).is_none(), "{bad:?}");
        }
        // The places of all groups together stay within their budget: as
        // many of the longest as fit, and not one more.
        let place = format!("/{}", "b".repeat(PLACE_LIMIT - 1));
        let fit = PLACES_BUDGET / (PLACE_LIMIT + 3);
        let mut group = json!({"kind": "mnemonic", "role": "unknown", "location": "opt",
            "access": "world", "count": 10, "places": vec![place.clone(); fit], "more": 0});
        assert!(keys(&json!({"coverage": "complete", "groups": [group.clone()]})).is_some());
        group["places"] = json!(vec![place; fit + 1]);
        assert!(keys(&json!({"coverage": "complete", "groups": [group]})).is_none());
    }

    /// The collector bounds what it sends by the numbers this parser
    /// holds it to: should they drift, every report with keys would be
    /// refused whole.
    #[test]
    fn the_collector_keeps_to_the_bounds_the_parser_holds_it_to() {
        use super::PLACES_SHOWN;

        let script = erpc_ssh::command::NODE_SECURITY_POSTURE_SCRIPT;
        for (name, value) in [
            ("PLACES_SHOWN", PLACES_SHOWN),
            ("PLACE_LIMIT", PLACE_LIMIT),
            ("PLACES_BUDGET", PLACES_BUDGET),
            (
                "MAX_COUNT",
                usize::try_from(MAX_COUNT).unwrap_or(usize::MAX),
            ),
        ] {
            let line = format!("{name} = {value}");
            assert_eq!(script.lines().filter(|l| *l == line).count(), 1, "{line}");
        }
    }

    #[test]
    fn places_cannot_drive_the_terminal_or_pass_for_each_other() {
        assert_eq!(
            shown("/tmp/%1B[2Jkey%E2%80%AEtxt.json%0A"),
            "/tmp/\\u{1b}[2Jkey\\u{202e}txt.json\\u{a}"
        );
        assert_eq!(
            shown("/a%D8%9Cb%E2%80%A8c%E2%81%A6d"),
            "/a\\u{61c}b\\u{2028}c\\u{2066}d"
        );
        // A byte that is not UTF-8, and a name that spells one out.
        assert_eq!(shown("/k%FF"), "/k\\xff");
        assert_eq!(shown("/k%5Cxff"), "/k\\\\xff");
        assert_eq!(shown("/home/sol/%E9%8D%B5.json"), "/home/sol/\u{9375}.json");
        // Invisible characters are shown; look-alike letters are left as they are.
        assert_eq!(
            shown("/k%E2%80%8Bey%EF%BB%BF%C2%AD%E2%81%A0"),
            "/k\\u{200b}ey\\u{feff}\\u{ad}\\u{2060}"
        );
        assert_eq!(shown("/%D0%B0.json"), "/\u{430}.json");
    }
}
