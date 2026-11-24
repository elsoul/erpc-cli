// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Whether a file's contents, a line of a shell history or a process's
//! environment hold a private key or a secret. Every check reads the bytes
//! where they lie and returns a kind or a count: nothing here copies them,
//! puts them in an error or prints them.

use std::sync::OnceLock;

use erpc_api::security_check::KeyKind;
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};

/// Parts of a variable's name that say it holds a private key or a secret.
const SECRET_NAMES: &[&[u8]] = &[
    b"PRIVATE_KEY",
    b"SECRET_KEY",
    b"MNEMONIC",
    b"SEED_PHRASE",
    b"KEYPAIR",
    b"WALLET_KEY",
];

/// Starts of a value that points to a secret kept elsewhere rather than
/// holding it: a password manager, a keychain, a keystore, a shell
/// expansion such as `${…}`, or a file's path.
const REFERENCES: &[&[u8]] = &[
    b"op://",
    b"keychain:",
    b"keystore:",
    b"$",
    b"/",
    b"~/",
    b"./",
    b"../",
];

/// Ends of a variable's name that say it holds where a secret is, not the
/// secret, such as `KEYPAIR_PATH`.
const LOCATION_NAMES: &[&[u8]] = &[b"_PATH", b"_FILE", b"_DIR"];

/// What a file holds.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Hit {
    pub(super) kind: KeyKind,
    /// How many: one for a key file, the lines for an environment file.
    pub(super) count: usize,
    /// A Solana keypair's public key, base58, when its halves agree.
    pub(super) pubkey: Option<String>,
}

impl Hit {
    const fn one(kind: KeyKind) -> Self {
        Self {
            kind,
            count: 1,
            pubkey: None,
        }
    }
}

/// What the file `name` holds, from its whole `contents`.
pub(super) fn classify(name: &[u8], contents: &[u8]) -> Option<Hit> {
    if is_env_file(name) {
        let count = env_secret_lines(contents);
        return (count > 0).then_some(Hit {
            kind: KeyKind::EnvSecret,
            count,
            pubkey: None,
        });
    }
    match contents.trim_ascii_start().first() {
        Some(b'[') if is_solana_keypair(contents) => Some(Hit {
            pubkey: solana_pubkey(contents),
            ..Hit::one(KeyKind::SolanaKeypair)
        }),
        Some(b'{') if is_unencrypted_keystore(contents) => {
            Some(Hit::one(KeyKind::UnencryptedKeystore))
        }
        _ if is_key_file_name(name) && is_hex_key(contents) => {
            Some(Hit::one(KeyKind::EvmPrivateKey))
        }
        _ if is_mnemonic(contents) => Some(Hit::one(KeyKind::Mnemonic)),
        _ => None,
    }
}

/// Whether `contents` is a Solana CLI keypair: a JSON array of exactly 64
/// integers from 0 to 255, and nothing else.
pub(super) fn is_solana_keypair(contents: &[u8]) -> bool {
    let Some(inner) = contents
        .trim_ascii()
        .strip_prefix(b"[")
        .and_then(|rest| rest.strip_suffix(b"]"))
    else {
        return false;
    };
    let mut count = 0;
    for part in inner.split(|&b| b == b',') {
        let part = part.trim_ascii();
        if part.is_empty() || part.len() > 3 || !part.iter().all(u8::is_ascii_digit) {
            return false;
        }
        let value = part
            .iter()
            .fold(0_u16, |value, &digit| value * 10 + u16::from(digit - b'0'));
        count += 1;
        if value > 255 || count > 64 {
            return false;
        }
    }
    count == 64
}

/// The public key of the keypair in `contents`, when its public half is
/// the one its secret half makes. The keypair is wiped when this returns.
pub(super) fn solana_pubkey(contents: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(contents).ok()?;
    erpc_chain_solana::identity::Keypair::parse_json(text)
        .ok()
        .map(|keypair| keypair.pubkey())
}

/// Whether `contents` is 64 hexadecimal digits and nothing else, with or
/// without `0x`.
fn is_hex_key(contents: &[u8]) -> bool {
    let text = contents.trim_ascii();
    let digits = text
        .strip_prefix(b"0x")
        .or_else(|| text.strip_prefix(b"0X"))
        .unwrap_or(text);
    digits.len() == 64 && digits.iter().all(u8::is_ascii_hexdigit)
}

/// Whether a file's name says it holds a key: it has `key`, `private` or
/// `wallet` in it, in any case, and is not a `.pem` file.
fn is_key_file_name(name: &[u8]) -> bool {
    let pem = name.len() >= 4 && name[name.len() - 4..].eq_ignore_ascii_case(b".pem");
    !pem && [&b"key"[..], b"private", b"wallet"]
        .iter()
        .any(|word| contains_ignore_case(name, word))
}

/// The BIP-39 English word list, sorted.
fn word_list() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    // bip39-english.txt is the BIP-39 English word list, unchanged, under
    // this notice:
    //
    // Copyright (c) 2013 Marek Palatinus, Pavol Rusnak, Aaron Voisine, Sean Bowe
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to
    // permit persons to whom the Software is furnished to do so, subject to
    // the following conditions:
    //
    // The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    // IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    // CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    // TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    // SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    WORDS.get_or_init(|| include_str!("bip39-english.txt").lines().collect())
}

/// Whether `contents` is a BIP-39 seed phrase: 12, 15, 18, 21 or 24 words of
/// the English list, in lower case, and nothing else.
fn is_mnemonic(contents: &[u8]) -> bool {
    let list = word_list();
    let mut count = 0;
    for word in contents
        .split(u8::is_ascii_whitespace)
        .filter(|w| !w.is_empty())
    {
        count += 1;
        let known = std::str::from_utf8(word).is_ok_and(|w| list.binary_search(&w).is_ok());
        if !known || count > 24 {
            return false;
        }
    }
    matches!(count, 12 | 15 | 18 | 21 | 24)
}

/// Whether `contents` is a JSON object with a private key field and no
/// `crypto` object, which an encrypted keystore has.
fn is_unencrypted_keystore(contents: &[u8]) -> bool {
    serde_json::from_slice::<Shape>(contents).is_ok_and(|shape| shape.private_key && !shape.crypto)
}

/// The fields of a JSON object that matter here. The values are skipped
/// unread, so no part of a key is copied.
#[derive(Default)]
struct Shape {
    private_key: bool,
    crypto: bool,
}

impl<'de> Deserialize<'de> for Shape {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Shape;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Shape, A::Error> {
                let mut shape = Shape::default();
                while let Some(field) = map.next_key::<Field>()? {
                    map.next_value::<IgnoredAny>()?;
                    match field {
                        Field::PrivateKey => shape.private_key = true,
                        Field::Crypto => shape.crypto = true,
                        Field::Other => {}
                    }
                }
                Ok(shape)
            }
        }
        deserializer.deserialize_map(Fields)
    }
}

enum Field {
    PrivateKey,
    Crypto,
    Other,
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Name;
        impl Visitor<'_> for Name {
            type Value = Field;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a field name")
            }
            fn visit_str<E>(self, name: &str) -> Result<Field, E> {
                Ok(if folds_to(name, b"crypto") {
                    Field::Crypto
                } else if [&b"privatekey"[..], b"privkey", b"secretkey"]
                    .iter()
                    .any(|word| folds_to(name, word))
                {
                    Field::PrivateKey
                } else {
                    Field::Other
                })
            }
        }
        deserializer.deserialize_identifier(Name)
    }
}

/// Whether `name` is `word` once lowered and without `_` or `-`, so that
/// `privateKey`, `private_key` and `Private-Key` are one name.
fn folds_to(name: &str, word: &[u8]) -> bool {
    name.bytes()
        .filter(|b| !matches!(b, b'_' | b'-'))
        .map(|b| b.to_ascii_lowercase())
        .eq(word.iter().copied())
}

/// Whether a file's name makes it an environment file: `.env`, a name
/// ending in `.env`, or `environment`.
fn is_env_file(name: &[u8]) -> bool {
    name.ends_with(b".env") || name == b"environment"
}

/// How many lines of an environment file set a secret's variable to a
/// value written out in it.
fn env_secret_lines(contents: &[u8]) -> usize {
    contents
        .split(|&b| b == b'\n')
        .filter(|line| {
            let line = line.trim_ascii();
            let line = line
                .strip_prefix(b"export ")
                .map_or(line, <[u8]>::trim_ascii_start);
            line.iter().position(|&b| b == b'=').is_some_and(|eq| {
                let name = line[..eq].trim_ascii_end();
                is_name(name) && is_secret_name(name) && is_written_out(&line[eq + 1..])
            })
        })
        .count()
}

/// How many variables of a process's environment, as `/proc/<pid>/environ`
/// lists them, are secrets' variables set to a value written out.
pub(super) fn environ_secrets(environ: &[u8]) -> usize {
    environ
        .split(|&b| b == 0)
        .filter(|entry| {
            entry.iter().position(|&b| b == b'=').is_some_and(|eq| {
                let name = &entry[..eq];
                is_name(name) && is_secret_name(name) && is_written_out(&entry[eq + 1..])
            })
        })
        .count()
}

/// How many lines of a shell history hold what looks like a key: 64
/// hexadecimal digits in a row, 87 or 88 base58 characters in a row (a
/// Solana secret key's length), or a secret's variable set to a value
/// written out.
pub(super) fn history_secret_lines(history: &[u8]) -> usize {
    history
        .split(|&b| b == b'\n')
        .filter(|line| {
            line.split(|b| !b.is_ascii_hexdigit())
                .any(|run| run.len() == 64)
                || line
                    .split(|&b| !is_base58(b))
                    .any(|run| matches!(run.len(), 87 | 88))
                || assigns_secret(line)
        })
        .count()
}

fn is_base58(b: u8) -> bool {
    b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l')
}

/// Whether a command line sets a secret's variable, such as
/// `export PRIVATE_KEY=…`, to a value written out.
fn assigns_secret(line: &[u8]) -> bool {
    line.iter().enumerate().any(|(eq, &b)| {
        if b != b'=' {
            return false;
        }
        let start = line[..eq]
            .iter()
            .rposition(|&b| !is_name_byte(b))
            .map_or(0, |i| i + 1);
        let name = &line[start..eq];
        let value = &line[eq + 1..];
        let end = value
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(value.len());
        !name.is_empty() && is_secret_name(name) && is_written_out(&value[..end])
    })
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_name(name: &[u8]) -> bool {
    name.first()
        .is_some_and(|&b| b.is_ascii_alphabetic() || b == b'_')
        && name.iter().all(|&b| is_name_byte(b))
}

fn is_secret_name(name: &[u8]) -> bool {
    let location = LOCATION_NAMES.iter().any(|end| {
        name.len() >= end.len() && name[name.len() - end.len()..].eq_ignore_ascii_case(end)
    });
    !location
        && SECRET_NAMES
            .iter()
            .any(|secret| contains_ignore_case(name, secret))
}

/// Whether a variable's value is the secret itself: not empty, and not a
/// reference to where it is kept.
fn is_written_out(value: &[u8]) -> bool {
    let value = value.trim_ascii();
    let value = value
        .strip_prefix(b"\"")
        .or_else(|| value.strip_prefix(b"'"))
        .unwrap_or(value);
    let value = value
        .strip_suffix(b"\"")
        .or_else(|| value.strip_suffix(b"'"))
        .unwrap_or(value);
    !value.is_empty() && !REFERENCES.iter().any(|r| value.starts_with(r))
}

fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
pub(super) mod tests {
    use std::fmt::Write as _;

    use erpc_api::security_check::KeyKind;
    use erpc_chain_solana::identity::Keypair;

    use super::{
        classify, environ_secrets, history_secret_lines, is_mnemonic, is_solana_keypair, word_list,
    };

    /// 64 hexadecimal digits made when the test runs.
    pub(in crate::node::security) fn hex_key() -> String {
        (0..32_u8).fold(String::new(), |mut hex, i| {
            let _ = write!(hex, "{:02x}", i * 7 + 3);
            hex
        })
    }

    /// A seed phrase of `n` words from the list, made when the test runs.
    pub(in crate::node::security) fn phrase(n: usize) -> String {
        let list = word_list();
        (0..n)
            .map(|i| list[(i * 167 + 41) % list.len()])
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A keypair's JSON array with `value` in place of its first number.
    pub(in crate::node::security) fn array_with(value: u16) -> String {
        let numbers: Vec<String> = std::iter::once(value)
            .chain((1..64).map(|i| i * 3 % 256))
            .map(|n| n.to_string())
            .collect();
        format!("[{}]", numbers.join(", "))
    }

    fn kind(name: &str, contents: &str) -> Option<KeyKind> {
        classify(name.as_bytes(), contents.as_bytes()).map(|hit| hit.kind)
    }

    #[test]
    fn the_word_list_is_the_sorted_english_list() {
        let list = word_list();
        assert_eq!(list.len(), 2048);
        assert!(list.windows(2).all(|w| w[0] < w[1]));
        assert!(
            list.iter()
                .all(|w| (3..=8).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase()))
        );
    }

    #[test]
    fn solana_keypairs_are_exactly_64_bytes() {
        let keypair = Keypair::generate().unwrap_or_else(|e| panic!("{e}"));
        let json = keypair.to_json();
        let hit = classify(b"id.json", json.as_bytes()).unwrap_or_else(|| panic!("no hit"));
        assert_eq!(hit.kind, KeyKind::SolanaKeypair);
        assert_eq!(hit.pubkey, Some(keypair.pubkey()));

        assert!(is_solana_keypair(array_with(255).as_bytes()));
        assert!(!is_solana_keypair(array_with(256).as_bytes()));
        let short = array_with(1).replacen("1, ", "", 1);
        assert!(!is_solana_keypair(short.as_bytes()));
        let long = array_with(1).replacen('[', "[1, ", 1);
        assert!(!is_solana_keypair(long.as_bytes()));
        assert!(!is_solana_keypair(
            array_with(1).replacen('1', "-1", 1).as_bytes()
        ));
        assert!(!is_solana_keypair(b"[]"));
        // An array whose halves do not agree is still a keypair's shape; its
        // public key is not known.
        let mismatched =
            classify(b"x.json", array_with(9).as_bytes()).unwrap_or_else(|| panic!("no hit"));
        assert_eq!(mismatched.pubkey, None);
    }

    #[test]
    fn hex_keys_need_a_key_name_and_64_digits() {
        let key = hex_key();
        assert_eq!(kind("wallet.txt", &key), Some(KeyKind::EvmPrivateKey));
        assert_eq!(
            kind("deployer.KEY", &format!("0x{key}\n")),
            Some(KeyKind::EvmPrivateKey)
        );
        assert_eq!(kind("private", &key), Some(KeyKind::EvmPrivateKey));
        assert_eq!(kind("notes.txt", &key), None);
        assert_eq!(kind("server.pem", &key), None);
        assert_eq!(kind("wallet.key", &key[1..]), None);
        assert_eq!(kind("wallet.key", &format!("{key} {key}")), None);
    }

    #[test]
    fn seed_phrases_are_whole_files_of_list_words() {
        for n in [12, 15, 18, 21, 24] {
            assert_eq!(kind("seed.txt", &phrase(n)), Some(KeyKind::Mnemonic), "{n}");
        }
        assert!(is_mnemonic(phrase(12).replace(' ', "\n").as_bytes()));
        for n in [11, 13, 25] {
            assert!(!is_mnemonic(phrase(n).as_bytes()), "{n}");
        }
        assert!(!is_mnemonic(phrase(12).to_uppercase().as_bytes()));
        let mut words: Vec<String> = phrase(12).split(' ').map(str::to_owned).collect();
        words[3] = "erpc".to_owned();
        assert!(!is_mnemonic(words.join(" ").as_bytes()));
    }

    #[test]
    fn only_keystores_without_encryption_are_found() {
        let key = hex_key();
        assert_eq!(
            kind(
                "UTC--wallet",
                &format!(r#"{{"address": "ab", "privateKey": "{key}"}}"#)
            ),
            Some(KeyKind::UnencryptedKeystore)
        );
        assert_eq!(
            kind("k.json", &format!(r#"{{"secret_key": "ed25519:{key}"}}"#)),
            Some(KeyKind::UnencryptedKeystore)
        );
        // An encrypted Ethereum keystore, either spelling of `crypto`.
        for crypto in ["crypto", "Crypto"] {
            let v3 = format!(
                r#"{{"version": 3, "id": "x", "address": "ab", "{crypto}": {{"ciphertext": "{key}", "cipher": "aes-128-ctr"}}}}"#
            );
            assert_eq!(kind("UTC--2024", &v3), None);
        }
        // erpc's own keystore: its master key and an entry, both sealed.
        let master = format!(
            r#"{{"format": "erpc-keystore-master", "version": 1, "key_id": "00", "kdf": "pbkdf2-hmac-sha256", "iterations": 600000, "salt": "{key}", "cipher": "chacha20-poly1305", "nonce": "00", "wrapped": "{key}"}}"#
        );
        let entry = format!(
            r#"{{"format": "erpc-keystore-entry", "version": 1, "key_id": "00", "name": "worker/bot", "kind": "key", "kdf": "hkdf-sha256", "salt": "{key}", "cipher": "chacha20-poly1305", "nonce": "00", "sealed": "{key}"}}"#
        );
        assert_eq!(kind("master.json", &master), None);
        assert_eq!(kind("bot.json", &entry), None);
        assert_eq!(kind("x.json", "{not json"), None);
        assert_eq!(kind("x.json", r#"["privateKey"]"#), None);
    }

    #[test]
    fn env_files_count_secrets_written_out() {
        let key = hex_key();
        let file = format!(
            "# PRIVATE_KEY={key}\nexport PRIVATE_KEY={key}\nBOT_MNEMONIC=\"{words}\"\nSOLANA_KEYPAIR='{key}'\n\
             SECRET_KEY=op://vault/item/field\nWALLET_KEY=${{WALLET_KEY_FILE}}\nSEED_PHRASE=keychain:seed\n\
             KEYPAIR_PATH=keystore:bot\nEMPTY_PRIVATE_KEY=\nQUOTED_PRIVATE_KEY=\"\"\nLOG_LEVEL=info\n\
             SOLANA_KEYPAIR=~/.config/solana/id.json\nVALIDATOR_KEYPAIR=/home/sol/id.json\n\
             PRIVATE_KEY=./deployer.key\nKEYPAIR_FILE=id.json\nwallet_key_dir={key}\n",
            words = phrase(12)
        );
        for name in [".env", "bot.env", "environment"] {
            let hit = classify(name.as_bytes(), file.as_bytes())
                .unwrap_or_else(|| panic!("no hit in {name}"));
            assert_eq!((hit.kind, hit.count), (KeyKind::EnvSecret, 3), "{name}");
        }
        assert_eq!(kind(".env.example", &file), None);
        assert_eq!(kind(".env", "LOG_LEVEL=info\n"), None);
    }

    #[test]
    fn process_environments_count_secrets_written_out() {
        let key = hex_key();
        let environ = format!(
            "PATH=/usr/bin\0PRIVATE_KEY={key}\0SEED_PHRASE=op://v/i/f\0HOME=/root\0KEYPAIR=/run/keys/id.json\0"
        );
        assert_eq!(environ_secrets(environ.as_bytes()), 1);
        assert_eq!(environ_secrets(b"PATH=/usr/bin\0WALLET_KEY=\0"), 0);
    }

    #[test]
    fn history_lines_with_keys_are_counted() {
        let key = hex_key();
        let keypair = Keypair::generate().unwrap_or_else(|e| panic!("{e}"));
        let secret = erpc_chain_solana::identity::base58(keypair.bytes());
        let history = format!(
            "ls -la\ncast send --private-key 0x{key} 0xab\nimport-key {secret}\n\
             export PRIVATE_KEY=abc\nexport PRIVATE_KEY=\"$(op read op://v/i/f)\"\n\
             echo {short}\nunset PRIVATE_KEY\n: 1700000000:0;WALLET_KEY=xyz ./bot\n\
             export SOLANA_KEYPAIR=~/.config/solana/id.json\nKEYPAIR_PATH=id.json ./bot\n",
            short = &key[1..]
        );
        assert_eq!(history_secret_lines(history.as_bytes()), 4);
        assert_eq!(history_secret_lines(b"git log --oneline\n"), 0);
    }
}
