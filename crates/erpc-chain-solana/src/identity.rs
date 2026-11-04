// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A validator identity, made in memory and kept in 1Password.
//!
//! The keypair is generated from the operating system's random source and
//! goes from memory into 1Password on `op`'s standard input. It is never
//! written to a file and never put on a command line, and every buffer that
//! held it is wiped when dropped. It is then read back and checked to be the
//! key it was meant to be.
//!
//! The item has the layout SLV uses, so either tool reads the other's: an
//! `API_CREDENTIAL` with `keypair` (concealed, the 64-byte array as
//! `solana-keygen` writes it) and `pubkey`. The reference to it is
//! `op://<vault>/<item>/keypair`.

use ed25519_dalek::SigningKey;
use erpc_auth::store::one_password::OpRunner;
use serde_json::{Value, json};
use zeroize::{Zeroize as _, Zeroizing};

/// What went wrong making or storing an identity.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The operating system's random source failed.
    #[error("no randomness for a new key: {0}")]
    Random(String),
    /// `op` failed.
    #[error("1Password could not {operation}: {reason}")]
    Op {
        /// What was being done.
        operation: &'static str,
        /// `op`'s first line.
        reason: String,
    },
    /// The text is not a keypair.
    #[error("not a Solana keypair: {0}")]
    Keypair(&'static str),
    /// An item with that title is already in the vault.
    #[error("{0:?} is already in the vault; nothing was made. Use that identity, or another name")]
    Exists(String),
    /// What 1Password returned is not the key that was stored.
    #[error(
        "the identity in 1Password did not read back as it was made ({0}); it has not been used"
    )]
    Mismatch(&'static str),
}

/// A Solana keypair: the 32-byte secret seed and the 32-byte public key,
/// in the order `solana-keygen` writes them.
pub struct Keypair {
    bytes: Zeroizing<[u8; 64]>,
}

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("pubkey", &self.pubkey())
            .finish()
    }
}

impl Keypair {
    /// A new keypair from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Random`] when there is no randomness.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut_slice()).map_err(|e| IdentityError::Random(e.to_string()))?;
        Ok(Self::from_seed(&seed))
    }

    fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let mut bytes = Zeroizing::new([0_u8; 64]);
        bytes[..32].copy_from_slice(seed);
        bytes[32..].copy_from_slice(&signing.verifying_key().to_bytes());
        Self { bytes }
    }

    /// The public key, base58, as Solana prints it.
    #[must_use]
    pub fn pubkey(&self) -> String {
        base58(&self.bytes[32..])
    }

    /// The 64 bytes themselves, secret seed first, for handing the key to a
    /// process over a pipe. Copy them only into a buffer that is wiped.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// The keypair as `solana-keygen` writes it: a JSON array of 64 numbers.
    #[must_use]
    pub fn to_json(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::with_capacity(64 * 4 + 2));
        text.push('[');
        for (i, b) in self.bytes.iter().enumerate() {
            if i > 0 {
                text.push(',');
            }
            text.push_str(&b.to_string());
        }
        text.push(']');
        text
    }

    /// Reads the `solana-keygen` form, and checks that the public half is the
    /// one the secret half makes.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Keypair`] for anything else.
    pub fn parse_json(text: &str) -> Result<Self, IdentityError> {
        let inner = text
            .trim()
            .strip_prefix('[')
            .and_then(|t| t.strip_suffix(']'))
            .ok_or(IdentityError::Keypair("not a JSON array"))?;
        let mut bytes = Zeroizing::new([0_u8; 64]);
        let mut count = 0;
        for part in inner.split(',') {
            let byte: u8 = part
                .trim()
                .parse()
                .map_err(|_| IdentityError::Keypair("not bytes"))?;
            *bytes
                .get_mut(count)
                .ok_or(IdentityError::Keypair("more than 64 bytes"))? = byte;
            count += 1;
        }
        if count != 64 {
            return Err(IdentityError::Keypair("not 64 bytes"));
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        seed.copy_from_slice(&bytes[..32]);
        let made = Self::from_seed(&seed);
        if made.bytes[32..] != bytes[32..] {
            return Err(IdentityError::Keypair(
                "the public key is not the secret key's",
            ));
        }
        Ok(made)
    }
}

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Bitcoin-alphabet base58, as Solana writes keys.
#[must_use]
pub fn base58(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    // Big-endian base-256 to base-58, digit by digit.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
    for &byte in &bytes[zeros..] {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = u8::try_from(carry % 58).unwrap_or(0);
            carry /= 58;
        }
        while carry > 0 {
            digits.push(u8::try_from(carry % 58).unwrap_or(0));
            carry /= 58;
        }
    }
    let mut out = "1".repeat(zeros);
    out.extend(
        digits
            .iter()
            .rev()
            .map(|&d| char::from(ALPHABET[usize::from(d)])),
    );
    out
}

/// An identity once stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdentity {
    /// The public key.
    pub pubkey: String,
    /// `op://<vault>/<item>/keypair`.
    pub reference: String,
}

/// Which of a validator's keys an item holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// The node identity: signs votes and gossip, pays the vote fees.
    Identity,
    /// The vote account's own key, needed only to create the account.
    Vote,
    /// The vote account's withdraw authority. It never goes to a node.
    Authority,
}

impl KeyRole {
    /// As it appears in titles and tags.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Vote => "vote",
            Self::Authority => "authority",
        }
    }
}

/// The title of a network's identity item for validator `name`.
#[must_use]
pub fn title(network: &str, name: &str) -> String {
    title_for(network, name, KeyRole::Identity)
}

/// The title of the item holding validator `name`'s `role` key.
#[must_use]
pub fn title_for(network: &str, name: &str, role: KeyRole) -> String {
    format!("erpc {network} {name} {}", role.as_str())
}

/// Reads the keypair at `reference` (`op://…/keypair`) into memory, and
/// checks it against the item's `pubkey` field when the item has one.
///
/// # Errors
///
/// Returns [`IdentityError`] when `op` fails, the text is not a keypair, or
/// its public key is not the one the item states.
pub fn read_keypair<R: OpRunner>(runner: &R, reference: &str) -> Result<Keypair, IdentityError> {
    if !reference.starts_with("op://") || reference.chars().any(char::is_whitespace) {
        return Err(IdentityError::Keypair("not an op:// reference"));
    }
    let read = |r: &str| -> Result<Option<String>, IdentityError> {
        let out = runner
            .run(&["read", "--no-newline", r], None)
            .map_err(|e| IdentityError::Op {
                operation: "read the key",
                reason: e.to_string(),
            })?;
        Ok(out.success.then_some(out.stdout))
    };
    let mut text = read(reference)?.ok_or(IdentityError::Op {
        operation: "read the key",
        reason: format!("{reference} could not be read"),
    })?;
    let keypair = Keypair::parse_json(&text);
    text.zeroize();
    let keypair = keypair?;
    if let Some(item) = reference.strip_suffix("/keypair")
        && let Some(stated) = read(&format!("{item}/pubkey"))?
        && !stated.trim().is_empty()
        && stated.trim() != keypair.pubkey()
    {
        return Err(IdentityError::Mismatch("pubkey"));
    }
    Ok(keypair)
}

fn op_error(operation: &'static str, stderr: &str) -> IdentityError {
    let line = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no reason given");
    IdentityError::Op {
        operation,
        reason: line.chars().filter(|c| !c.is_control()).take(300).collect(),
    }
}

/// Deletes the item `reference` (`op://<vault>/<item>/<field>`) points at:
/// a key that is no longer needed, such as a vote account's once the account
/// exists, whose public key is all that is kept.
///
/// # Errors
///
/// Returns [`IdentityError`] for a reference that is not `op://` or when `op`
/// refuses.
pub fn delete_item<R: OpRunner>(runner: &R, reference: &str) -> Result<(), IdentityError> {
    let mut parts = reference
        .strip_prefix("op://")
        .ok_or(IdentityError::Keypair("not an op:// reference"))?
        .split('/');
    let (Some(vault), Some(item)) = (parts.next(), parts.next()) else {
        return Err(IdentityError::Keypair("not an op:// item reference"));
    };
    let plain = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric());
    if !plain(vault) || !plain(item) {
        return Err(IdentityError::Keypair("not an op:// item reference by id"));
    }
    let out = runner
        .run(&["item", "delete", item, "--vault", vault], None)
        .map_err(|e| IdentityError::Op {
            operation: "delete the item",
            reason: e.to_string(),
        })?;
    if out.success {
        Ok(())
    } else {
        Err(op_error("delete the item", &out.stderr))
    }
}

/// The identity already stored for validator `name` of `network`, if any:
/// what a run of `erpc v init` that stopped after storing it left.
///
/// # Errors
///
/// Returns [`IdentityError`] when `op` fails, or the item is not one erpc
/// wrote (its tag or public key is missing).
pub fn find<R: OpRunner>(
    runner: &R,
    vault: &str,
    network: &str,
    name: &str,
) -> Result<Option<StoredIdentity>, IdentityError> {
    find_key(runner, vault, network, name, KeyRole::Identity)
}

/// The `role` key already stored for validator `name` of `network`, if any.
///
/// # Errors
///
/// As [`find`].
pub fn find_key<R: OpRunner>(
    runner: &R,
    vault: &str,
    network: &str,
    name: &str,
    role: KeyRole,
) -> Result<Option<StoredIdentity>, IdentityError> {
    let title = title_for(network, name, role);
    let run = |args: &[&str], operation: &'static str| {
        let out = runner.run(args, None).map_err(|e| IdentityError::Op {
            operation,
            reason: e.to_string(),
        })?;
        if out.success {
            Ok(out.stdout)
        } else {
            Err(op_error(operation, &out.stderr))
        }
    };
    let listed = run(
        &["item", "list", "--vault", vault, "--format", "json"],
        "list the vault",
    )?;
    let listed: Vec<Value> =
        serde_json::from_str(&listed).map_err(|_| IdentityError::Mismatch("the vault listing"))?;
    let Some(item) = listed.iter().find(|i| i["title"] == title) else {
        return Ok(None);
    };
    let tag = format!("erpc/solana/{network}/{}", role.as_str());
    let tagged = item["tags"]
        .as_array()
        .is_some_and(|tags| tags.iter().any(|t| t == tag.as_str()));
    let id = item["id"]
        .as_str()
        .filter(|_| tagged)
        .ok_or(IdentityError::Mismatch(
            "an item has the key's title but not its tag",
        ))?;
    let pubkey = run(
        &["read", "--no-newline", &format!("op://{vault}/{id}/pubkey")],
        "read the public key",
    )?;
    if pubkey.is_empty() || bs58_len(&pubkey).is_none() {
        return Err(IdentityError::Mismatch("pubkey"));
    }
    Ok(Some(StoredIdentity {
        pubkey,
        reference: format!("op://{vault}/{id}/keypair"),
    }))
}

/// `Some` when `text` is 32 to 44 base58 characters, the shape of a public
/// key.
fn bs58_len(text: &str) -> Option<usize> {
    let ok = (32..=44).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'));
    ok.then_some(text.len())
}

/// Makes a new identity for validator `name` of `network`, stores it in
/// `vault`, and reads it back.
///
/// # Errors
///
/// Returns [`IdentityError::Exists`] when the vault already has an identity by
/// that title, and other errors when `op` fails or the read-back differs.
pub fn store_new<R: OpRunner>(
    runner: &R,
    vault: &str,
    network: &str,
    name: &str,
) -> Result<StoredIdentity, IdentityError> {
    store_key(
        runner,
        vault,
        network,
        name,
        KeyRole::Identity,
        &Keypair::generate()?,
    )
}

/// Makes a new `role` key for validator `name` and stores it, as
/// [`store_new`] does the identity.
///
/// # Errors
///
/// As [`store_new`].
pub fn store_new_key<R: OpRunner>(
    runner: &R,
    vault: &str,
    network: &str,
    name: &str,
    role: KeyRole,
) -> Result<StoredIdentity, IdentityError> {
    store_key(runner, vault, network, name, role, &Keypair::generate()?)
}

/// Stores `keypair` as validator `name`'s `role` key and reads it back: a
/// new key, or one the operator already had.
///
/// # Errors
///
/// Returns [`IdentityError::Exists`] when the vault already has an item by
/// that title, and other errors when `op` fails or the read-back differs.
pub fn store_key<R: OpRunner>(
    runner: &R,
    vault: &str,
    network: &str,
    name: &str,
    role: KeyRole,
    keypair: &Keypair,
) -> Result<StoredIdentity, IdentityError> {
    let title = title_for(network, name, role);
    let run = |args: &[&str], stdin: Option<&str>, operation: &'static str| {
        let out = runner.run(args, stdin).map_err(|e| IdentityError::Op {
            operation,
            reason: e.to_string(),
        })?;
        if out.success {
            Ok(out.stdout)
        } else {
            Err(op_error(operation, &out.stderr))
        }
    };
    let tag = format!("erpc/solana/{network}/{}", role.as_str());
    let listed = run(
        &["item", "list", "--vault", vault, "--format", "json"],
        None,
        "list the vault",
    )?;
    let listed: Vec<Value> =
        serde_json::from_str(&listed).map_err(|_| IdentityError::Mismatch("the vault listing"))?;
    if listed.iter().any(|i| i["title"] == title) {
        return Err(IdentityError::Exists(title));
    }

    let pubkey = keypair.pubkey();
    let secret = keypair.to_json();
    // Built around the secret rather than through a JSON serializer, so the
    // one copy of the template is the one that is wiped.
    let mut template = Zeroizing::new(String::new());
    let head =
        json!({ "title": title, "category": "API_CREDENTIAL", "tags": ["erpc", tag] }).to_string();
    template.push_str(head.trim_end_matches('}'));
    template.push_str(",\"fields\":[{\"id\":\"keypair\",\"label\":\"keypair\",\"type\":\"CONCEALED\",\"value\":\"");
    template.push_str(&secret);
    template.push_str("\"},");
    template.push_str(
        &json!({ "id": "pubkey", "label": "pubkey", "type": "STRING", "value": pubkey })
            .to_string(),
    );
    template.push_str("]}");
    let created = run(
        &["item", "create", "-", "--vault", vault, "--format", "json"],
        Some(&template),
        "store the identity",
    )?;
    drop(template);
    let created: Value =
        serde_json::from_str(&created).map_err(|_| IdentityError::Mismatch("the new item"))?;
    let id = created["id"]
        .as_str()
        .ok_or(IdentityError::Mismatch("the new item has no id"))?
        .to_owned();

    // Read back both halves: the secret, which must make the same public key,
    // and the public field the inventory shows.
    let reference = format!("op://{vault}/{id}/keypair");
    let mut back = run(
        &["read", "--no-newline", &reference],
        None,
        "read the identity back",
    )?;
    let parsed = Keypair::parse_json(&back);
    back.zeroize();
    if parsed?.pubkey() != pubkey {
        return Err(IdentityError::Mismatch("keypair"));
    }
    let public = run(
        &["read", "--no-newline", &format!("op://{vault}/{id}/pubkey")],
        None,
        "read the public key back",
    )?;
    if public != pubkey {
        return Err(IdentityError::Mismatch("pubkey"));
    }
    Ok(StoredIdentity { pubkey, reference })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use erpc_auth::store::StoreError;
    use erpc_auth::store::one_password::{OpOutput, OpRunner};
    use serde_json::{Value, json};

    use super::{IdentityError, Keypair, base58, find, store_new};

    /// RFC 8032, test 1.
    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn the_public_key_matches_rfc_8032_and_prints_as_solana_does() {
        let seed: [u8; 32] = hex(SEED).try_into().expect("32");
        let keypair = Keypair::from_seed(&seed);
        assert_eq!(keypair.bytes[32..], hex(PUBLIC)[..]);
        // base58 of the RFC public key, worked out independently.
        assert_eq!(
            keypair.pubkey(),
            "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"
        );
        assert_eq!(base58(&[0; 32]), "11111111111111111111111111111111");
    }

    #[test]
    fn the_keygen_form_round_trips_and_a_wrong_public_half_is_refused() {
        let keypair = Keypair::generate().expect("random");
        let text = keypair.to_json();
        assert_eq!(text.matches(',').count(), 63);
        let back = Keypair::parse_json(&text).expect("parses");
        assert_eq!(back.pubkey(), keypair.pubkey());
        let mut tampered: Vec<u8> = text
            .trim_matches(['[', ']'])
            .split(',')
            .map(|b| b.parse().expect("u8"))
            .collect();
        tampered[63] ^= 1;
        let tampered = format!(
            "[{}]",
            tampered
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(Keypair::parse_json(&tampered).is_err());
        assert!(Keypair::parse_json("[1,2,3]").is_err());
        assert!(Keypair::parse_json("not json").is_err());
    }

    #[test]
    fn two_keys_are_never_the_same() {
        let a = Keypair::generate().expect("random");
        let b = Keypair::generate().expect("random");
        assert_ne!(a.pubkey(), b.pubkey());
    }

    #[test]
    fn debug_shows_the_public_key_only() {
        let keypair = Keypair::generate().expect("random");
        let shown = format!("{keypair:?}");
        assert!(shown.contains(&keypair.pubkey()));
        assert!(!shown.contains(&keypair.to_json()[1..10]));
    }

    /// `op`, in memory, for the store.
    #[derive(Default)]
    struct FakeOp {
        items: RefCell<Vec<Value>>,
        argv: RefCell<Vec<String>>,
        corrupt_read: bool,
    }

    fn reply(stdout: String) -> OpOutput {
        OpOutput {
            success: true,
            stdout,
            stderr: String::new(),
        }
    }

    impl OpRunner for &FakeOp {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            self.argv.borrow_mut().push(args.join(" "));
            let mut items = self.items.borrow_mut();
            match args {
                ["item", "list", ..] => Ok(reply(Value::Array(items.clone()).to_string())),
                ["item", "create", ..] => {
                    let mut item: Value =
                        serde_json::from_str(stdin.expect("template")).expect("json");
                    item["id"] = json!("newitem");
                    items.push(item.clone());
                    Ok(reply(item.to_string()))
                }
                ["read", "--no-newline", reference] => {
                    let field = reference.rsplit('/').next().expect("field");
                    let item = &items[0];
                    let mut value = item["fields"]
                        .as_array()
                        .and_then(|f| f.iter().find(|f| f["label"] == field))
                        .and_then(|f| f["value"].as_str())
                        .unwrap_or_default()
                        .to_owned();
                    if self.corrupt_read && field == "pubkey" {
                        value.push('x');
                    }
                    Ok(reply(value))
                }
                other => panic!("unexpected op call: {other:?}"),
            }
        }
    }

    #[test]
    fn a_new_identity_is_stored_read_back_and_never_on_a_command_line() {
        let op = FakeOp::default();
        let stored = store_new(&&op, "vaultid", "testnet", "tv1").expect("stored");
        assert_eq!(stored.reference, "op://vaultid/newitem/keypair");
        let item = op.items.borrow()[0].clone();
        assert_eq!(item["title"], "erpc testnet tv1 identity");
        assert_eq!(item["category"], "API_CREDENTIAL");
        let secret = item["fields"][0]["value"]
            .as_str()
            .expect("keypair")
            .to_owned();
        assert_eq!(
            Keypair::parse_json(&secret).expect("keypair").pubkey(),
            stored.pubkey
        );
        for line in op.argv.borrow().iter() {
            assert!(!line.contains(&secret[1..20]), "secret in argv: {line}");
        }
    }

    #[test]
    fn an_existing_identity_is_not_replaced() {
        let op = FakeOp::default();
        op.items
            .borrow_mut()
            .push(json!({ "id": "old", "title": "erpc testnet tv1 identity" }));
        assert!(matches!(
            store_new(&&op, "vaultid", "testnet", "tv1"),
            Err(IdentityError::Exists(_))
        ));
    }

    #[test]
    fn a_stored_identity_is_found_again_and_a_lookalike_is_refused() {
        let op = FakeOp::default();
        assert_eq!(
            find(&&op, "vaultid", "testnet", "tv1").expect("listed"),
            None
        );
        let stored = store_new(&&op, "vaultid", "testnet", "tv1").expect("stored");
        assert_eq!(
            find(&&op, "vaultid", "testnet", "tv1").expect("found"),
            Some(stored)
        );
        let lookalike = FakeOp::default();
        lookalike
            .items
            .borrow_mut()
            .push(json!({ "id": "x", "title": "erpc testnet tv1 identity", "tags": [] }));
        assert!(matches!(
            find(&&lookalike, "vaultid", "testnet", "tv1"),
            Err(IdentityError::Mismatch(_))
        ));
    }

    #[test]
    fn a_read_back_that_differs_is_refused() {
        let op = FakeOp {
            corrupt_read: true,
            ..FakeOp::default()
        };
        assert!(matches!(
            store_new(&&op, "vaultid", "testnet", "tv1"),
            Err(IdentityError::Mismatch("pubkey"))
        ));
    }

    /// Makes a real identity in a real vault, checks it, and removes it. Run
    /// by hand with `ERPC_TEST_VAULT=<vault id>`; it asks 1Password for
    /// approval.
    #[test]
    #[ignore = "writes to a real 1Password vault"]
    fn a_real_identity_is_made_read_back_and_removed() {
        use erpc_auth::store::one_password::{Mode, OpCli};
        let vault = std::env::var("ERPC_TEST_VAULT").expect("ERPC_TEST_VAULT");
        let runner = OpCli::from_env(Mode::Desktop, |n| std::env::var_os(n)).expect("op");
        let name = format!("rt{}", std::process::id());
        let stored = store_new(&runner, &vault, "roundtrip", &name).expect("stored and read back");
        assert!(stored.pubkey.len() >= 32, "{}", stored.pubkey);
        let id = stored
            .reference
            .split('/')
            .nth(3)
            .expect("item id")
            .to_owned();
        let removed = runner
            .run(&["item", "delete", &id, "--vault", &vault], None)
            .expect("op");
        assert!(
            removed.success,
            "remove the test identity {id} by hand: {}",
            removed.stderr
        );
    }
}
