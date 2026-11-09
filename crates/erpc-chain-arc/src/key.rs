// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! An Arc node's consensus key, made in memory and kept in 1Password.
//!
//! The consensus layer reads an Ed25519 key at start: its P2P identity, and
//! on a permissioned validator its signing key. The RPC lifecycle does not
//! imply validator admission. The original node key is a secret. erpc
//! makes it from the operating system's random source and stores only its
//! 32-byte seed, base64, in 1Password, on `op`'s standard input. The node gets
//! it in the form `arc-node-consensus` reads,
//! `{"type":"tendermint/PrivKeyEd25519","value":"<seed, base64>"}`, over SSH
//! standard input into `systemd-creds encrypt`, and never as a file in the
//! clear. Seed/templates are zeroizing and returned provider text is wrapped
//! immediately; generic process-transport allocations are outside this boundary.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
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
        /// A fixed public reason; provider diagnostics are never copied.
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
        let mut bytes = Zeroizing::new([0_u8; 32]);
        let size = STANDARD
            .decode_slice(text.trim(), bytes.as_mut_slice())
            .map_err(|_| KeyError::Malformed("not a 32-byte base64 seed"))?;
        if size != 32 {
            return Err(KeyError::Malformed("not 32 bytes"));
        }
        let key = Self::from_seed(&bytes);
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

#[path = "key_storage.rs"]
mod storage;
pub use storage::{Owner, find_original, read, store_reserved, verify};

/// Dedicated validator key items, separate from the RPC custody scope.
#[path = "key_validator_storage.rs"]
pub mod validator;

#[cfg(test)]
#[path = "key_tests.rs"]
mod tests;
