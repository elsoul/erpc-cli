// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A server's host key, pinned: the one key a connection accepts.
//!
//! Only `ssh-ed25519` is accepted. A pin names one algorithm and one key, and
//! the connection is configured to offer that algorithm alone, so there is
//! nothing to downgrade to.

use sha2::{Digest as _, Sha256};

/// The algorithm every pin uses.
pub const ALGORITHM: &str = "ssh-ed25519";

/// A pinned `ssh-ed25519` host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    /// The key blob as OpenSSH prints it, base64.
    base64: String,
    /// The same blob, decoded.
    blob: Vec<u8>,
}

/// Why a host key was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostKeyError {
    /// Not `ssh-ed25519 <base64>`.
    #[error("a host key must be `ssh-ed25519 <base64>`")]
    Format,
    /// The base64 does not decode.
    #[error("the host key is not valid base64")]
    Base64,
    /// The decoded blob is not an Ed25519 public key.
    #[error("the host key is not an Ed25519 public key")]
    Blob,
}

impl HostKey {
    /// Reads `ssh-ed25519 <base64> [comment]`, the form `ssh-keyscan`, a
    /// `.pub` file and `known_hosts` use (without the host column).
    ///
    /// # Errors
    ///
    /// Returns [`HostKeyError`] for any other algorithm, bad base64, or a blob
    /// that is not a 32-byte Ed25519 key.
    pub fn parse(text: &str) -> Result<Self, HostKeyError> {
        let mut fields = text.split_whitespace();
        if fields.next() != Some(ALGORITHM) {
            return Err(HostKeyError::Format);
        }
        let base64 = fields.next().ok_or(HostKeyError::Format)?;
        let blob = decode_base64(base64).ok_or(HostKeyError::Base64)?;
        // The SSH wire form: string "ssh-ed25519", string <32 bytes>.
        let mut rest = blob.as_slice();
        let algorithm = take_string(&mut rest).ok_or(HostKeyError::Blob)?;
        let key = take_string(&mut rest).ok_or(HostKeyError::Blob)?;
        if algorithm != ALGORITHM.as_bytes() || key.len() != 32 || !rest.is_empty() {
            return Err(HostKeyError::Blob);
        }
        Ok(Self {
            base64: base64.to_owned(),
            blob,
        })
    }

    /// `ssh-ed25519 <base64>`, with no comment.
    #[must_use]
    pub fn to_openssh(&self) -> String {
        format!("{ALGORITHM} {}", self.base64)
    }

    /// The fingerprint as `ssh-keygen -l` prints it: `SHA256:` and the
    /// unpadded base64 of the SHA-256 of the blob.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(&self.blob);
        let mut out = encode_base64(&digest);
        while out.ends_with('=') {
            out.pop();
        }
        format!("SHA256:{out}")
    }
}

/// The `ssh-ed25519` key in `ssh-keyscan` output, which is lines of
/// `<host> <algorithm> <base64>` and `#` comments.
///
/// # Errors
///
/// Returns [`HostKeyError::Format`] when there is no `ssh-ed25519` line, and
/// the error of [`HostKey::parse`] when the line is malformed.
pub fn from_keyscan(output: &str) -> Result<HostKey, HostKeyError> {
    let line = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.split_once(' ').map(|(_, key)| key))
        .filter(|key| key.starts_with(ALGORITHM))
        .ok_or(HostKeyError::Format)?;
    HostKey::parse(line)
}

fn take_string<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, tail) = rest.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    if tail.len() < len {
        return None;
    }
    let (value, tail) = tail.split_at(len);
    *rest = tail;
    Some(value)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64 with padding, as OpenSSH writes keys. `None` for anything
/// else, including stray characters.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| ALPHABET.iter().position(|&a| a == c);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.chunks(4);
    let last = chunks.len() - 1;
    for (index, chunk) in chunks.enumerate() {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && index != last) {
            return None;
        }
        let mut n = 0_u32;
        for &c in &chunk[..4 - pad] {
            n = n << 6 | u32::try_from(value(c)?).ok()?;
        }
        n <<= 6 * pad;
        let decoded = n.to_be_bytes();
        out.extend_from_slice(&decoded[1..4 - pad]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{HostKey, HostKeyError, decode_base64, encode_base64, from_keyscan};

    /// Made with `ssh-keygen -t ed25519`; the fingerprint is what
    /// `ssh-keygen -lf` printed for it.
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/";
    const FINGERPRINT: &str = "SHA256:lPj0B6VyygOzgRWIgXcYc68i80nabNkWWyNANifXm9o";

    #[test]
    fn the_fingerprint_matches_ssh_keygen() {
        let key = HostKey::parse(KEY).expect("parses");
        assert_eq!(key.fingerprint(), FINGERPRINT);
        assert_eq!(key.to_openssh(), KEY);
    }

    #[test]
    fn a_comment_after_the_key_is_ignored() {
        let key = HostKey::parse(&format!("{KEY} root@node")).expect("parses");
        assert_eq!(key.fingerprint(), FINGERPRINT);
    }

    #[test]
    fn other_algorithms_and_broken_keys_are_refused() {
        assert_eq!(
            HostKey::parse("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ=="),
            Err(HostKeyError::Format)
        );
        assert_eq!(
            HostKey::parse("ssh-ed25519 not*base64"),
            Err(HostKeyError::Base64)
        );
        // Valid base64 of something that is not an Ed25519 key blob.
        assert_eq!(
            HostKey::parse("ssh-ed25519 aGVsbG8="),
            Err(HostKeyError::Blob)
        );
        assert_eq!(HostKey::parse(""), Err(HostKeyError::Format));
    }

    #[test]
    fn the_ed25519_line_is_found_in_keyscan_output() {
        let output = format!("# 203.0.113.5:22 SSH-2.0-OpenSSH_9.6\n203.0.113.5 {KEY}\n");
        assert_eq!(
            from_keyscan(&output).expect("found").fingerprint(),
            FINGERPRINT
        );
        assert_eq!(from_keyscan("# nothing\n"), Err(HostKeyError::Format));
    }

    #[test]
    fn base64_round_trips_and_refuses_bad_padding() {
        for sample in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            if sample.is_empty() {
                continue;
            }
            let text = encode_base64(sample);
            assert_eq!(decode_base64(&text).as_deref(), Some(sample), "{text}");
        }
        assert_eq!(decode_base64("Zm9v=Zm9v"), None);
        assert_eq!(decode_base64("Zg="), None);
        assert_eq!(decode_base64("Z==="), None);
    }
}
