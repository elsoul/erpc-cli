// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The encryption `erpc storage put` applies by default, and `get` undoes.
//!
//! The format, version 1, all of it public so that the files can be read
//! without erpc:
//!
//! ```text
//! magic    8 bytes   "ERPCENC1"
//! key id   8 bytes   the first 8 bytes of SHA-256(master key)
//! salt    32 bytes   random, new for every file
//! payload            STREAM: the plaintext in 64 KiB chunks, each sealed
//!                    with ChaCha20-Poly1305 (16-byte tag after it)
//! ```
//!
//! - The file's key is HKDF-SHA256 of the master key, with the salt and the
//!   info string [`INFO`].
//! - Chunk `n` is sealed with the nonce `n` as 11 bytes big-endian followed
//!   by one byte: 1 for the last chunk, 0 for the others. The header (magic,
//!   key id, salt) is the associated data of every chunk.
//! - Every chunk but the last is a full 64 KiB. The last may be shorter, and
//!   is empty only when the whole file is.
//!
//! This is the payload construction age uses. A chunk taken from another
//! file, moved, or dropped from the end fails to open, and so does a header
//! that was changed. The cryptography is aws-lc-rs, which rustls already
//! brings in, so the format costs no new dependency.

use std::io::{self, Read, Write};

use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// What every encrypted file starts with.
pub const MAGIC: &[u8; 8] = b"ERPCENC1";

/// Bytes before the payload.
pub const HEADER_LEN: usize = 8 + 8 + 32;

/// The HKDF info string.
pub const INFO: &[u8] = b"erpc storage v1 payload key";

const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;

/// The account's storage encryption key.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// Wraps 32 key bytes.
    #[cfg(test)]
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A new random key.
    ///
    /// # Errors
    ///
    /// When the system has no randomness to give.
    pub fn generate() -> Result<Self, String> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| "could not make a random key")?;
        Ok(Self(bytes))
    }

    /// The key as 64 hex digits, for a store or for writing down.
    #[must_use]
    pub fn to_hex(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(64));
        for b in self.0.iter() {
            out.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            out.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
        }
        out
    }

    /// Reads 64 hex digits.
    ///
    /// # Errors
    ///
    /// When `text` is not 64 hex digits.
    pub fn from_hex(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("a storage key is 64 hex digits".to_owned());
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        for (i, pair) in text.as_bytes().chunks(2).enumerate() {
            let digit = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => c - b'A' + 10,
            };
            bytes[i] = digit(pair[0]) << 4 | digit(pair[1]);
        }
        Ok(Self(bytes))
    }

    /// The first 8 bytes of SHA-256 of the key: names it without showing it.
    #[must_use]
    pub fn id(&self) -> [u8; 8] {
        let digest = Sha256::digest(self.0.as_slice());
        let mut id = [0u8; 8];
        id.copy_from_slice(&digest[..8]);
        id
    }

    /// [`Self::id`] as hex.
    #[must_use]
    pub fn id_hex(&self) -> String {
        use core::fmt::Write as _;
        self.id()
            .iter()
            .fold(String::with_capacity(16), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            })
    }

    fn file_key(&self, salt: &[u8]) -> io::Result<LessSafeKey> {
        let prk = Salt::new(HKDF_SHA256, salt).extract(self.0.as_slice());
        let okm = prk
            .expand(&[INFO], &CHACHA20_POLY1305)
            .map_err(|_| invalid("could not derive the file's key"))?;
        Ok(LessSafeKey::new(UnboundKey::from(okm)))
    }
}

/// The size of `plain` bytes once encrypted.
#[must_use]
pub fn sealed_len(plain: u64) -> u64 {
    let chunks = plain.div_ceil(CHUNK as u64).max(1);
    HEADER_LEN as u64 + plain + chunks * TAG as u64
}

/// Whether `start` is the beginning of an encrypted file.
#[must_use]
pub fn is_sealed(start: &[u8]) -> bool {
    start.starts_with(MAGIC)
}

fn nonce(counter: u64, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(last);
    Nonce::assume_unique_for_key(n)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

/// Reads until `buf` is full or the source ends; how much was read.
fn read_full<R: Read>(source: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match source.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Encrypts what it reads from `inner`, as a reader of the encrypted file.
pub struct Sealer<R: Read> {
    inner: R,
    key: LessSafeKey,
    header: [u8; HEADER_LEN],
    out: Vec<u8>,
    out_pos: usize,
    carry: Option<u8>,
    counter: u64,
    done: bool,
}

impl<R: Read> Sealer<R> {
    /// Starts encrypting `inner` under `master`, with a new random salt.
    ///
    /// # Errors
    ///
    /// When there is no randomness, or the key cannot be derived.
    pub fn new(inner: R, master: &MasterKey) -> io::Result<Self> {
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).map_err(|_| invalid("could not make a random salt"))?;
        let mut header = [0u8; HEADER_LEN];
        header[..8].copy_from_slice(MAGIC);
        header[8..16].copy_from_slice(&master.id());
        header[16..].copy_from_slice(&salt);
        Ok(Self {
            inner,
            key: master.file_key(&salt)?,
            out: header.to_vec(),
            header,
            out_pos: 0,
            carry: None,
            counter: 0,
            done: false,
        })
    }

    fn next_chunk(&mut self) -> io::Result<()> {
        let mut chunk = Vec::with_capacity(CHUNK + TAG);
        chunk.resize(CHUNK, 0);
        let mut filled = 0;
        if let Some(b) = self.carry.take() {
            chunk[0] = b;
            filled = 1;
        }
        filled += read_full(&mut self.inner, &mut chunk[filled..])?;
        chunk.truncate(filled);
        // The last chunk is sealed as the last, so a byte past it is read
        // now and kept for the next one.
        let mut one = [0u8; 1];
        let last = read_full(&mut self.inner, &mut one)? == 0;
        if !last {
            self.carry = Some(one[0]);
        }
        self.key
            .seal_in_place_append_tag(
                nonce(self.counter, last),
                Aad::from(&self.header[..]),
                &mut chunk,
            )
            .map_err(|_| invalid("could not encrypt"))?;
        self.counter += 1;
        self.done = last;
        self.out = chunk;
        self.out_pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for Sealer<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.out_pos == self.out.len() {
            if self.done {
                return Ok(0);
            }
            self.next_chunk()?;
        }
        let n = buf.len().min(self.out.len() - self.out_pos);
        buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        Ok(n)
    }
}

/// Decrypts what is written to it into `inner`. Nothing is complete until
/// [`Self::finish`] says so: a file cut short is found only there.
pub struct Opener<'k, W: Write> {
    inner: W,
    master: &'k MasterKey,
    key: Option<(LessSafeKey, [u8; HEADER_LEN])>,
    buf: Vec<u8>,
    counter: u64,
}

impl<'k, W: Write> Opener<'k, W> {
    /// Starts decrypting into `inner` with `master`.
    pub fn new(inner: W, master: &'k MasterKey) -> Self {
        Self {
            inner,
            master,
            key: None,
            buf: Vec::with_capacity(CHUNK + TAG),
            counter: 0,
        }
    }

    fn open_chunk(&mut self, len: usize, last: bool) -> io::Result<()> {
        let Some((key, header)) = &self.key else {
            return Err(invalid("the file has no header"));
        };
        let opened = key
            .open_in_place(
                nonce(self.counter, last),
                Aad::from(&header[..]),
                &mut self.buf[..len],
            )
            .map_err(|_| invalid("the file is damaged, cut short, or not from this account"))?;
        self.inner.write_all(opened)?;
        self.buf.drain(..len);
        self.counter += 1;
        Ok(())
    }

    /// Checks that the file ended where it should, and hands back the
    /// writer.
    ///
    /// # Errors
    ///
    /// When the file is cut short, damaged or empty.
    pub fn finish(mut self) -> io::Result<W> {
        if self.key.is_none() {
            return Err(invalid("the file is cut short: it has no complete header"));
        }
        let len = self.buf.len();
        if len < TAG || (len == TAG && self.counter > 0) {
            return Err(invalid("the file is cut short"));
        }
        self.open_chunk(len, true)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for Opener<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.key.is_none() && self.buf.len() >= HEADER_LEN {
            let mut header = [0u8; HEADER_LEN];
            header.copy_from_slice(&self.buf[..HEADER_LEN]);
            if &header[..8] != MAGIC {
                return Err(invalid("this is not an erpc-encrypted file"));
            }
            if header[8..16] != self.master.id() {
                return Err(invalid(
                    "the file was encrypted with another storage key than this machine has",
                ));
            }
            let key = self.master.file_key(&header[16..])?;
            self.key = Some((key, header));
            self.buf.drain(..HEADER_LEN);
        }
        // A full chunk is opened as not the last only once a byte after it
        // has arrived; otherwise it may be the last.
        while self.key.is_some() && self.buf.len() > CHUNK + TAG {
            self.open_chunk(CHUNK + TAG, false)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> MasterKey {
        MasterKey::new([n; 32])
    }

    fn seal(plain: &[u8], k: &MasterKey) -> Vec<u8> {
        let mut out = Vec::new();
        Sealer::new(plain, k)
            .expect("starts")
            .read_to_end(&mut out)
            .expect("seals");
        out
    }

    fn open(sealed: &[u8], k: &MasterKey, piece: usize) -> io::Result<Vec<u8>> {
        let mut opener = Opener::new(Vec::new(), k);
        for part in sealed.chunks(piece.max(1)) {
            opener.write_all(part)?;
        }
        opener.finish()
    }

    #[test]
    fn a_file_that_grew_is_seen_past_its_predicted_length() {
        // What `put` relies on: after reading the sealed length of the size
        // it saw, a Sealer over a file that grew still has bytes to give.
        let key = MasterKey::new([7; 32]);
        for (seen, now) in [(0_usize, 1_usize), (65_536, 65_537), (100, 200_000)] {
            let plain = vec![1u8; now];
            let mut sealer = Sealer::new(&plain[..], &key).expect("sealer");
            let mut first = vec![0u8; usize::try_from(sealed_len(seen as u64)).expect("fits")];
            std::io::Read::read_exact(&mut sealer, &mut first).expect("reads the predicted length");
            let more = std::io::Read::read(&mut sealer, &mut [0u8; 1]).expect("reads");
            assert!(more > 0, "a file of {seen} grown to {now} was not seen");
        }
        let mut same = Sealer::new(&[1u8; 100][..], &key).expect("sealer");
        let mut all = vec![0u8; usize::try_from(sealed_len(100)).expect("fits")];
        std::io::Read::read_exact(&mut same, &mut all).expect("reads");
        assert_eq!(
            std::io::Read::read(&mut same, &mut [0u8; 1]).expect("reads"),
            0
        );
    }

    #[test]
    fn every_size_round_trips_and_has_the_predicted_length() {
        let k = key(7);
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 17] {
            let plain: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 251).unwrap_or(0))
                .collect();
            let sealed = seal(&plain, &k);
            assert_eq!(sealed.len() as u64, sealed_len(len as u64), "len {len}");
            assert!(is_sealed(&sealed));
            for piece in [1, 7, 4096, CHUNK + TAG, 1 << 20] {
                assert_eq!(
                    open(&sealed, &k, piece).expect("opens"),
                    plain,
                    "len {len} piece {piece}"
                );
            }
        }
    }

    #[test]
    fn the_same_file_twice_is_two_different_ciphertexts() {
        let k = key(1);
        assert_ne!(seal(b"same", &k), seal(b"same", &k));
    }

    #[test]
    fn a_changed_byte_anywhere_is_refused() {
        let k = key(2);
        let plain = vec![9u8; 2 * CHUNK + 5];
        let sealed = seal(&plain, &k);
        for at in [
            0,
            9,
            20,
            HEADER_LEN + 3,
            HEADER_LEN + CHUNK + TAG + 1,
            sealed.len() - 1,
        ] {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert!(open(&bad, &k, 1 << 20).is_err(), "byte {at}");
        }
    }

    #[test]
    fn a_file_cut_at_a_chunk_boundary_is_refused() {
        let k = key(3);
        let sealed = seal(&vec![1u8; 2 * CHUNK + 5], &k);
        assert!(open(&sealed[..HEADER_LEN + CHUNK + TAG], &k, 1 << 20).is_err());
        assert!(open(&sealed[..HEADER_LEN + 2 * (CHUNK + TAG)], &k, 1 << 20).is_err());
        assert!(open(&sealed[..HEADER_LEN], &k, 1 << 20).is_err());
        assert!(open(&sealed[..10], &k, 1 << 20).is_err());
    }

    #[test]
    fn another_key_is_named_as_the_problem() {
        let sealed = seal(b"secret", &key(4));
        let err = open(&sealed, &key(5), 1 << 20).expect_err("refused");
        assert!(err.to_string().contains("another storage key"), "{err}");
    }

    #[test]
    fn a_plain_file_is_not_taken_for_an_encrypted_one() {
        assert!(!is_sealed(b"hello world"));
        assert!(open(&[b'x'; 100], &key(6), 1 << 20).is_err());
    }

    #[test]
    fn a_key_survives_hex_and_its_id_is_stable() {
        let k = MasterKey::generate().expect("random");
        let back = MasterKey::from_hex(&k.to_hex()).expect("parses");
        assert_eq!(k.id(), back.id());
        assert_eq!(k.id_hex().len(), 16);
        assert!(MasterKey::from_hex("abc").is_err());
        assert!(MasterKey::from_hex(&"g".repeat(64)).is_err());
        assert_eq!(
            MasterKey::from_hex(&"AB".repeat(32)).expect("upper").id(),
            key(0xab).id()
        );
    }
}
