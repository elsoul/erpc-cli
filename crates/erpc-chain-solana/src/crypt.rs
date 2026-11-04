// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The `solv` user's password: made here, kept in the host's 1Password
//! item, and sent to the node only as a SHA-512 crypt hash (`$6$`), which
//! is what `useradd -p` and the carried `create_user.yml` take.
//!
//! The hash is Ulrich Drepper's "Unix crypt using SHA-256 and SHA-512"
//! with the default 5000 rounds, the form `openssl passwd -6` and glibc's
//! `crypt(3)` write. The tests are the specification's own vectors.

use core::fmt::Write as _;

use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha512};
use zeroize::Zeroizing;

/// The characters crypt's base64 uses, in its order.
const CRYPT64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// The rounds when the hash does not say.
const DEFAULT_ROUNDS: u32 = 5000;
/// The longest salt the scheme reads.
const SALT_MAX: usize = 16;
/// The length of a generated password: 32 letters and digits, about 190 bits.
const PASSWORD_LEN: usize = 32;

/// The order the digest's bytes are encoded in, three at a time.
const ORDER: [(usize, usize, usize); 21] = [
    (0, 21, 42),
    (22, 43, 1),
    (44, 2, 23),
    (3, 24, 45),
    (25, 46, 4),
    (47, 5, 26),
    (6, 27, 48),
    (28, 49, 7),
    (50, 8, 29),
    (9, 30, 51),
    (31, 52, 10),
    (53, 11, 32),
    (12, 33, 54),
    (34, 55, 13),
    (56, 14, 35),
    (15, 36, 57),
    (37, 58, 16),
    (59, 17, 38),
    (18, 39, 60),
    (40, 61, 19),
    (62, 20, 41),
];

/// Why a password or salt could not be made.
#[derive(Debug, thiserror::Error)]
#[error("the system's random source failed: {0}")]
pub struct RandomError(String);

/// A new password of letters and digits, for one host's `solv` user.
///
/// # Errors
///
/// Returns [`RandomError`] when the system's random source fails.
pub fn new_password() -> Result<SecretString, RandomError> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    // 62 does not divide 256: bytes of 248 and above are drawn again, so
    // every character is equally likely.
    let mut out = Zeroizing::new(String::with_capacity(PASSWORD_LEN));
    let mut buf = Zeroizing::new([0_u8; 64]);
    while out.len() < PASSWORD_LEN {
        getrandom::fill(buf.as_mut_slice()).map_err(|e| RandomError(e.to_string()))?;
        for &b in buf.iter() {
            if b < 248 && out.len() < PASSWORD_LEN {
                out.push(char::from(ALPHABET[usize::from(b % 62)]));
            }
        }
    }
    Ok(SecretString::from(out.as_str()))
}

/// A new 16-character salt.
///
/// # Errors
///
/// Returns [`RandomError`] when the system's random source fails.
pub fn new_salt() -> Result<String, RandomError> {
    let mut buf = [0_u8; SALT_MAX];
    getrandom::fill(&mut buf).map_err(|e| RandomError(e.to_string()))?;
    Ok(buf
        .iter()
        .map(|b| char::from(CRYPT64[usize::from(b & 63)]))
        .collect())
}

/// `$6$<salt>$<hash>` of `password`, with a new salt.
///
/// # Errors
///
/// Returns [`RandomError`] when the system's random source fails.
pub fn hash_password(password: &SecretString) -> Result<String, RandomError> {
    Ok(sha512_crypt(
        password.expose_secret().as_bytes(),
        &new_salt()?,
        None,
    ))
}

/// SHA-512 crypt of `key` with `salt` (cut to 16 bytes) and `rounds`, or
/// the default 5000 when `None`, which the result then does not state.
#[must_use]
// The names are the specification's: A, B, C, DP, DS, P and S.
#[allow(clippy::many_single_char_names)]
pub fn sha512_crypt(key: &[u8], salt: &str, rounds: Option<u32>) -> String {
    let salt = &salt.as_bytes()[..salt.len().min(SALT_MAX)];
    let rounds_n = rounds.unwrap_or(DEFAULT_ROUNDS).clamp(1000, 999_999_999);

    let b = Sha512::new()
        .chain_update(key)
        .chain_update(salt)
        .chain_update(key)
        .finalize();

    let mut a = Sha512::new().chain_update(key).chain_update(salt);
    let mut left = key.len();
    while left > 64 {
        a.update(b);
        left -= 64;
    }
    a.update(&b[..left]);
    let mut n = key.len();
    while n > 0 {
        if n & 1 == 1 {
            a.update(b);
        } else {
            a.update(key);
        }
        n >>= 1;
    }
    let a = a.finalize();

    let mut dp = Sha512::new();
    for _ in 0..key.len() {
        dp.update(key);
    }
    let p = Zeroizing::new(repeat(&dp.finalize(), key.len()));

    let mut ds = Sha512::new();
    for _ in 0..16 + usize::from(a[0]) {
        ds.update(salt);
    }
    let s = repeat(&ds.finalize(), salt.len());

    let mut c = a;
    for i in 0..rounds_n {
        let mut h = Sha512::new();
        if i % 2 == 1 {
            h.update(p.as_slice());
        } else {
            h.update(c);
        }
        if i % 3 != 0 {
            h.update(&s);
        }
        if i % 7 != 0 {
            h.update(p.as_slice());
        }
        if i % 2 == 1 {
            h.update(c);
        } else {
            h.update(p.as_slice());
        }
        c = h.finalize();
    }

    let mut out = String::from("$6$");
    if rounds.is_some() {
        let _ = write!(out, "rounds={rounds_n}$");
    }
    out.push_str(&String::from_utf8_lossy(salt));
    out.push('$');
    for (x, y, z) in ORDER {
        encode(&mut out, c[x], c[y], c[z], 4);
    }
    encode(&mut out, 0, 0, c[63], 2);
    out
}

/// `len` bytes of `digest` repeated.
fn repeat(digest: &[u8], len: usize) -> Vec<u8> {
    digest.iter().copied().cycle().take(len).collect()
}

fn encode(out: &mut String, b2: u8, b1: u8, b0: u8, n: usize) {
    let mut w = u32::from(b2) << 16 | u32::from(b1) << 8 | u32::from(b0);
    for _ in 0..n {
        out.push(char::from(CRYPT64[(w & 0x3f) as usize]));
        w >>= 6;
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::{hash_password, new_password, new_salt, sha512_crypt};

    /// The test vectors of the specification, "Unix crypt using SHA-256 and
    /// SHA-512", for SHA-512.
    #[test]
    fn the_specification_vectors_hash_as_published() {
        let cases: [(&str, &str, Option<u32>, &str); 5] = [
            (
                "saltstring",
                "Hello world!",
                None,
                "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
            ),
            (
                "saltstringsaltstring",
                "Hello world!",
                Some(10000),
                "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
            ),
            (
                "toolongsaltstring",
                "This is just a test",
                Some(5000),
                "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
            ),
            (
                "anotherlongsaltstring",
                "a very much longer text to encrypt.  This one even stretches over morethan one line.",
                Some(1400),
                "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
            ),
            (
                "roundstoolow",
                "the minimum number is still observed",
                Some(10),
                "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
            ),
        ];
        for (salt, key, rounds, expected) in cases {
            assert_eq!(
                sha512_crypt(key.as_bytes(), salt, rounds),
                expected,
                "{key}"
            );
        }
    }

    #[test]
    fn a_new_hash_has_the_form_create_user_accepts() {
        let password = new_password().expect("password");
        assert_eq!(password.expose_secret().len(), 32);
        assert!(
            password
                .expose_secret()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric())
        );
        let hash = hash_password(&password).expect("hash");
        // The pattern create_user.yml asserts.
        let (salt, digest) = hash
            .strip_prefix("$6$")
            .and_then(|r| r.split_once('$'))
            .expect("$6$salt$digest");
        let crypt64 = |s: &str| {
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
        };
        assert!((1..=16).contains(&salt.len()) && crypt64(salt), "{hash}");
        assert!(digest.len() == 86 && crypt64(digest), "{hash}");
        assert_ne!(new_salt().expect("salt"), new_salt().expect("salt"));
    }
}
