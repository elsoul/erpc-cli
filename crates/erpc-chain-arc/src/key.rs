// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! An Arc node's consensus key, made in memory and kept in 1Password.
//!
//! The consensus layer reads an Ed25519 key at start: its P2P identity, and
//! on a validator its signing key. An RPC node follows and signs nothing, so
//! the key matters less than a validator's, but it is still a secret. erpc
//! makes it from the operating system's random source and stores only its
//! 32-byte seed, base64, in 1Password, on `op`'s standard input. The node gets
//! it in the form `arc-node-consensus` reads,
//! `{"type":"tendermint/PrivKeyEd25519","value":"<seed, base64>"}`, over SSH
//! standard input into `systemd-creds encrypt`, and never as a file in the
//! clear. Every buffer that held it is wiped when dropped.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use erpc_auth::store::one_password::OpRunner;
use serde_json::{Value, json};
use zeroize::{Zeroize as _, Zeroizing};

/// What went wrong making, storing or reading a key.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
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
    /// The text is not a key.
    #[error("not an Arc consensus key: {0}")]
    Malformed(&'static str),
    /// An item with that title is already in the vault.
    #[error("{0:?} is already in the vault; nothing was made")]
    Exists(String),
    /// What 1Password returned is not the key that was stored.
    #[error("the consensus key in 1Password did not read back as it was made ({0})")]
    Mismatch(&'static str),
}

/// An Ed25519 consensus key.
pub struct ConsensusKey {
    seed: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl core::fmt::Debug for ConsensusKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConsensusKey")
            .field("public_key", &self.public_key())
            .finish()
    }
}

impl ConsensusKey {
    /// A new key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Random`] when there is no randomness.
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut_slice()).map_err(|e| KeyError::Random(e.to_string()))?;
        Ok(Self::from_seed(&seed))
    }

    fn from_seed(seed: &[u8; 32]) -> Self {
        let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        Self {
            seed: Zeroizing::new(*seed),
            public,
        }
    }

    /// The public key, base64, as the key file's public form writes it.
    #[must_use]
    pub fn public_key(&self) -> String {
        STANDARD.encode(self.public)
    }

    /// The seed, base64: what 1Password holds.
    #[must_use]
    pub fn seed_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.seed.as_slice()))
    }

    /// The key file `arc-node-consensus` reads.
    #[must_use]
    pub fn node_json(&self) -> Zeroizing<String> {
        let seed = self.seed_base64();
        let mut text = Zeroizing::new(String::with_capacity(96));
        text.push_str("{\"type\":\"tendermint/PrivKeyEd25519\",\"value\":\"");
        text.push_str(&seed);
        text.push_str("\"}");
        text
    }

    /// Reads a seed in base64.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Malformed`] for anything but 32 bytes in base64.
    pub fn parse_seed(text: &str) -> Result<Self, KeyError> {
        let mut bytes = Zeroizing::new(
            STANDARD
                .decode(text.trim())
                .map_err(|_| KeyError::Malformed("not base64"))?,
        );
        let seed: &[u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::Malformed("not 32 bytes"))?;
        let key = Self::from_seed(seed);
        bytes.zeroize();
        Ok(key)
    }
}

/// A key once stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredKey {
    /// The public key, base64.
    pub public_key: String,
    /// `op://<vault>/<item>/private_key`.
    pub reference: String,
}

/// The title of node `name`'s key item on `network`.
#[must_use]
pub fn title(network: &str, name: &str) -> String {
    format!("erpc {network} {name} arc consensus key")
}

fn tag(network: &str) -> String {
    format!("erpc/arc/{network}/key")
}

fn op_error(operation: &'static str, stderr: &str) -> KeyError {
    let line = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no reason given");
    KeyError::Op {
        operation,
        reason: line.chars().filter(|c| !c.is_control()).take(300).collect(),
    }
}

fn run<R: OpRunner>(
    runner: &R,
    args: &[&str],
    stdin: Option<&str>,
    operation: &'static str,
) -> Result<String, KeyError> {
    let out = runner.run(args, stdin).map_err(|e| KeyError::Op {
        operation,
        reason: e.to_string(),
    })?;
    if out.success {
        Ok(out.stdout)
    } else {
        Err(op_error(operation, &out.stderr))
    }
}

/// The key already stored for node `name` of `network`, if any: what an
/// `init` that stopped after storing it left.
///
/// # Errors
///
/// Returns [`KeyError`] when `op` fails, or an item has the key's title but
/// not its tag.
pub fn find<R: OpRunner>(
    runner: &R,
    vault: &str,
    network: &str,
    name: &str,
) -> Result<Option<StoredKey>, KeyError> {
    let title = title(network, name);
    let listed = run(
        runner,
        &["item", "list", "--vault", vault, "--format", "json"],
        None,
        "list the vault",
    )?;
    let listed: Vec<Value> =
        serde_json::from_str(&listed).map_err(|_| KeyError::Mismatch("the vault listing"))?;
    let Some(item) = listed.iter().find(|i| i["title"] == title) else {
        return Ok(None);
    };
    let tag = tag(network);
    let tagged = item["tags"]
        .as_array()
        .is_some_and(|tags| tags.iter().any(|t| t == tag.as_str()));
    let id = item["id"]
        .as_str()
        .filter(|_| tagged)
        .ok_or(KeyError::Mismatch(
            "an item has the key's title but not its tag",
        ))?;
    let public_key = run(
        runner,
        &[
            "read",
            "--no-newline",
            &format!("op://{vault}/{id}/public_key"),
        ],
        None,
        "read the public key",
    )?;
    if STANDARD.decode(&public_key).map(|b| b.len()) != Ok(32) {
        return Err(KeyError::Mismatch("public_key"));
    }
    Ok(Some(StoredKey {
        public_key,
        reference: format!("op://{vault}/{id}/private_key"),
    }))
}

/// Makes a new key for node `name` of `network`, stores it in `vault`, and
/// reads it back.
///
/// # Errors
///
/// Returns [`KeyError::Exists`] when the vault already has a key by that
/// title, and other errors when `op` fails or the read-back differs.
pub fn store_new<R: OpRunner>(
    runner: &R,
    vault: &str,
    network: &str,
    name: &str,
) -> Result<StoredKey, KeyError> {
    store(runner, vault, network, name, &ConsensusKey::generate()?)
}

fn store<R: OpRunner>(
    runner: &R,
    vault: &str,
    network: &str,
    name: &str,
    key: &ConsensusKey,
) -> Result<StoredKey, KeyError> {
    let title = title(network, name);
    let listed = run(
        runner,
        &["item", "list", "--vault", vault, "--format", "json"],
        None,
        "list the vault",
    )?;
    let listed: Vec<Value> =
        serde_json::from_str(&listed).map_err(|_| KeyError::Mismatch("the vault listing"))?;
    if listed.iter().any(|i| i["title"] == title) {
        return Err(KeyError::Exists(title));
    }
    let public_key = key.public_key();
    let secret = key.seed_base64();
    // Built around the secret rather than through a JSON serializer, so the
    // one copy of the template is the one that is wiped. Base64 needs no
    // escaping inside a JSON string.
    let mut template = Zeroizing::new(String::new());
    let head =
        json!({ "title": title, "category": "API_CREDENTIAL", "tags": ["erpc", tag(network)] })
            .to_string();
    template.push_str(head.trim_end_matches('}'));
    template.push_str(",\"fields\":[{\"id\":\"private_key\",\"label\":\"private_key\",\"type\":\"CONCEALED\",\"value\":\"");
    template.push_str(&secret);
    template.push_str("\"},");
    template.push_str(
        &json!({ "id": "public_key", "label": "public_key", "type": "STRING", "value": public_key })
            .to_string(),
    );
    template.push_str("]}");
    let created = run(
        runner,
        &["item", "create", "-", "--vault", vault, "--format", "json"],
        Some(&template),
        "store the consensus key",
    )?;
    drop(template);
    let created: Value =
        serde_json::from_str(&created).map_err(|_| KeyError::Mismatch("the new item"))?;
    let id = created["id"]
        .as_str()
        .ok_or(KeyError::Mismatch("the new item has no id"))?
        .to_owned();
    let stored = StoredKey {
        public_key,
        reference: format!("op://{vault}/{id}/private_key"),
    };
    // Read back both halves, as a run would.
    let back = read(runner, &stored)?;
    if back.public_key() != stored.public_key {
        return Err(KeyError::Mismatch("private_key"));
    }
    Ok(stored)
}

/// Reads the key `stored` points at into memory, and checks it is the one
/// the item's public key states.
///
/// # Errors
///
/// Returns [`KeyError`] when `op` fails, the text is not a key, or its
/// public key is not the one stated.
pub fn read<R: OpRunner>(runner: &R, stored: &StoredKey) -> Result<ConsensusKey, KeyError> {
    let reference = stored.reference.as_str();
    let Some(item) = reference.strip_suffix("/private_key") else {
        return Err(KeyError::Malformed("not an op://…/private_key reference"));
    };
    if !reference.starts_with("op://") || reference.chars().any(char::is_whitespace) {
        return Err(KeyError::Malformed("not an op:// reference"));
    }
    let mut text = run(
        runner,
        &["read", "--no-newline", reference],
        None,
        "read the consensus key",
    )?;
    let key = ConsensusKey::parse_seed(&text);
    text.zeroize();
    let key = key?;
    let stated = run(
        runner,
        &["read", "--no-newline", &format!("{item}/public_key")],
        None,
        "read the public key",
    )?;
    if stated.trim() != key.public_key() || stored.public_key != key.public_key() {
        return Err(KeyError::Mismatch("public_key"));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use erpc_auth::store::StoreError;
    use erpc_auth::store::one_password::{OpOutput, OpRunner};
    use serde_json::{Value, json};

    use super::{ConsensusKey, KeyError, find, read, store_new};

    /// RFC 8032, test 1, and its two halves in base64 (worked out apart
    /// from this code).
    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const SEED_B64: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
    const PUBLIC_B64: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    #[test]
    fn the_key_file_is_the_form_arc_node_consensus_reads() {
        let key = ConsensusKey::from_seed(&SEED);
        assert_eq!(key.public_key(), PUBLIC_B64);
        assert_eq!(
            key.node_json().as_str(),
            format!("{{\"type\":\"tendermint/PrivKeyEd25519\",\"value\":\"{SEED_B64}\"}}")
        );
        let doc: Value = serde_json::from_str(&key.node_json()).expect("JSON");
        assert_eq!(doc["type"], "tendermint/PrivKeyEd25519");
        assert!(!format!("{key:?}").contains(SEED_B64));
    }

    #[test]
    fn a_seed_round_trips_and_anything_else_is_refused() {
        let key = ConsensusKey::generate().expect("random");
        let back = ConsensusKey::parse_seed(&key.seed_base64()).expect("parses");
        assert_eq!(back.public_key(), key.public_key());
        for bad in ["", "not base64!", "AAAA", PUBLIC_B64.trim_end_matches('=')] {
            assert!(ConsensusKey::parse_seed(bad).is_err(), "{bad}");
        }
    }

    /// `op`, in memory: `item list/create` and `read`, and every argv.
    #[derive(Default)]
    struct FakeOp {
        items: RefCell<Vec<Value>>,
        calls: RefCell<Vec<String>>,
    }

    impl OpRunner for &FakeOp {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            self.calls.borrow_mut().push(args.join(" "));
            let mut items = self.items.borrow_mut();
            let ok = |stdout: String| OpOutput {
                success: true,
                stdout,
                stderr: String::new(),
            };
            match args {
                ["item", "list", "--vault", _, "--format", "json"] => {
                    Ok(ok(Value::Array(items.clone()).to_string()))
                }
                ["item", "create", "-", "--vault", _, "--format", "json"] => {
                    let mut item: Value =
                        serde_json::from_str(stdin.expect("template")).expect("json");
                    item["id"] = json!(format!("key{}", items.len() + 1));
                    items.push(item.clone());
                    Ok(ok(item.to_string()))
                }
                ["read", "--no-newline", reference] => {
                    let mut parts = reference.trim_start_matches("op://").split('/');
                    let (_, id, field) = (parts.next(), parts.next(), parts.next());
                    let item = items
                        .iter()
                        .find(|i| i["id"] == id.expect("id"))
                        .expect("item");
                    let value = item["fields"]
                        .as_array()
                        .and_then(|f| f.iter().find(|f| f["label"] == field.expect("field")))
                        .and_then(|f| f["value"].as_str())
                        .unwrap_or_default();
                    Ok(ok(value.to_owned()))
                }
                other => panic!("unexpected op call: {other:?}"),
            }
        }
    }

    #[test]
    fn a_key_is_stored_found_and_read_back_and_never_reaches_argv() {
        let fake = FakeOp::default();
        let op = &fake;
        let stored = store_new(&op, "vaultid", "testnet", "arc1").expect("stored");
        assert_eq!(
            find(&op, "vaultid", "testnet", "arc1").expect("listed"),
            Some(stored.clone())
        );
        assert!(
            find(&op, "vaultid", "testnet", "arc2")
                .expect("listed")
                .is_none()
        );
        let key = read(&op, &stored).expect("read");
        assert_eq!(key.public_key(), stored.public_key);
        assert!(matches!(
            store_new(&op, "vaultid", "testnet", "arc1"),
            Err(KeyError::Exists(_))
        ));
        let seed = key.seed_base64();
        for call in op.calls.borrow().iter() {
            assert!(!call.contains(seed.as_str()), "secret in argv: {call}");
        }
        let item = &op.items.borrow()[0];
        assert_eq!(item["title"], "erpc testnet arc1 arc consensus key");
        assert_eq!(item["tags"][1], "erpc/arc/testnet/key");
    }
}
