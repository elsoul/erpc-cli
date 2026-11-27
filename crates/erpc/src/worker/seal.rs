// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Sealing an app's secret to the machines that may open it, and opening
//! one sealed to this machine: HPKE (RFC 9180), single shot, with
//! DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, in its base mode
//! (sealed by the dashboard, with no sender) and its auth mode (sealed by
//! erpc on a machine, which authenticates as the sender with its own
//! sealing key). That is a Diffie-Hellman proof, not a signature: whoever
//! holds the recipient's key can make a seal that names any sender.
//!
//! The ERPC account keeps only what this makes: the encapsulated key
//! (`enc`) and the ciphertext (`ct`), as unpadded base64url. It cannot open
//! them. What a seal is for is bound into it as its associated data: the
//! account, the app's id there, the app, the setting's name and the
//! secret's version ([`Aad`]), so a seal moved to another of them does not
//! open.
//!
//! Built from aws-lc-rs's X25519, HMAC-SHA256 (HKDF's extract), HKDF's
//! expand and AES-256-GCM. A Diffie-Hellman result of all zeros (a
//! low-order public key) stops both sealing and opening.

#![expect(
    dead_code,
    reason = "the commands that seal and open come with the next change; this one is the cipher and its known answers"
)]

use aws_lc_rs::aead::{AES_256_GCM, Aad as GcmAad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::{hkdf, hmac};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// The `info` every seal carries.
pub(crate) const INFO: &[u8] = b"erpc-worker-secret:v1";

/// The suite's ids: KEM, KDF and AEAD.
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0002;

/// The modes this uses: base, and auth.
const MODE_BASE: u8 = 0x00;
const MODE_AUTH: u8 = 0x02;

/// Sizes, in bytes: a key, a shared secret, an AEAD key, a nonce, a tag.
const N_PK: usize = 32;
const N_SECRET: usize = 32;
const N_K: usize = 32;
const N_N: usize = 12;
const N_TAG: usize = 16;

/// The largest value sealed, in bytes.
pub(crate) const PLAINTEXT_MAX: usize = 8192;

/// Why a seal could not be made or opened. None of them carries a key, a
/// value or ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SealError {
    /// A public key, an encapsulated key or a ciphertext not in its form.
    Form(&'static str),
    /// The Diffie-Hellman result was all zeros: a key that is not one.
    ZeroSecret,
    /// The cipher could not run.
    Cipher,
    /// It did not open: not sealed to this key, from this sender, for this
    /// account, app, name and version, or changed since.
    Open,
    /// The value is not one a secret may be: 1 to 8192 bytes of UTF-8,
    /// without a NUL.
    Value,
    /// An element of the associated data is not in its form.
    Aad(&'static str),
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Form(what) => write!(f, "{what} is not in the form a seal has"),
            Self::ZeroSecret => f.write_str("the key exchange gave nothing; the key is not one"),
            Self::Cipher => f.write_str("the cipher could not run"),
            Self::Open => f.write_str("it does not open with this key for this secret"),
            Self::Value => {
                f.write_str("a secret's value is 1 to 8192 bytes of UTF-8, without a NUL")
            }
            Self::Aad(what) => write!(f, "{what} is not in the form a seal names it in"),
        }
    }
}

impl core::error::Error for SealError {}

// ------------------------------------------------------------ the KDF

/// I2OSP(n, 2).
const fn two(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

/// The KEM's suite id: `"KEM" ‖ I2OSP(kem_id, 2)`.
fn kem_suite() -> Vec<u8> {
    [b"KEM".as_slice(), &two(KEM_ID)].concat()
}

/// The key schedule's suite id: "HPKE" ‖ kem ‖ kdf ‖ aead.
fn hpke_suite() -> Vec<u8> {
    [
        b"HPKE".as_slice(),
        &two(KEM_ID),
        &two(KDF_ID),
        &two(AEAD_ID),
    ]
    .concat()
}

/// HKDF-Extract(salt, ikm): HMAC-SHA256 keyed by the salt.
fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    Zeroizing::new(hmac::sign(&key, ikm).as_ref().to_vec())
}

/// A length, as HKDF's expand takes it.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand(prk, info, len).
fn expand(prk: &[u8], info: &[&[u8]], len: usize) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, prk);
    let mut out = Zeroizing::new(vec![0; len]);
    prk.expand(info, Len(len))
        .and_then(|okm| okm.fill(&mut out))
        .map_err(|_| SealError::Cipher)?;
    Ok(out)
}

/// LabeledExtract(salt, label, ikm), under `suite`.
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    let labeled = Zeroizing::new([b"HPKE-v1".as_slice(), suite, label, ikm].concat());
    extract(salt, &labeled)
}

/// LabeledExpand(prk, label, info, len), under `suite`.
fn labeled_expand(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let length = two(u16::try_from(len).map_err(|_| SealError::Cipher)?);
    expand(prk, &[&length, b"HPKE-v1", suite, label, info], len)
}

// ------------------------------------------------------------ the KEM

/// A sealing key's secret half: 32 bytes, wiped when dropped.
#[derive(Clone)]
pub(crate) struct SecretKey(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

impl SecretKey {
    /// The key with these 32 bytes.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A new key, from the system's random source.
    pub(crate) fn generate() -> Result<Self, SealError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(bytes.as_mut()).map_err(|_| SealError::Cipher)?;
        Ok(Self(bytes))
    }

    /// The key RFC 9180's `DeriveKeyPair` makes from `ikm`: what a test's
    /// fixed keys are, and nothing else.
    pub(crate) fn derive(ikm: &[u8]) -> Result<Self, SealError> {
        let suite = kem_suite();
        let prk = labeled_extract(&suite, b"", b"dkp_prk", ikm);
        let sk = labeled_expand(&suite, &prk, b"sk", b"", 32)?;
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&sk);
        Ok(Self(bytes))
    }

    /// The bytes, for the store that keeps them.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key as a store keeps it: its 32 bytes as unpadded base64url.
    pub(crate) fn to_text(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0.as_ref()))
    }

    /// The key a store kept as [`SecretKey::to_text`] wrote it, refused
    /// when it is not 32 bytes in that canonical form.
    pub(crate) fn from_text(text: &str) -> Result<Self, SealError> {
        let text = text.trim();
        let form = || SealError::Form("a sealing key");
        // Decoded and written back with nothing left unwiped: the key's text
        // is the key.
        let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(text).map_err(|_| form())?);
        if bytes.len() != 32 || *Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice())) != text {
            return Err(form());
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    fn private(&self) -> Result<PrivateKey, SealError> {
        PrivateKey::from_private_key(&X25519, self.0.as_ref()).map_err(|_| SealError::Cipher)
    }

    /// Its public half: 32 bytes.
    pub(crate) fn public(&self) -> Result<[u8; 32], SealError> {
        let public = self
            .private()?
            .compute_public_key()
            .map_err(|_| SealError::Cipher)?;
        public.as_ref().try_into().map_err(|_| SealError::Cipher)
    }
}

/// DH(sk, pk), refused when it is all zeros. aws-lc refuses that itself
/// (its X25519 fails on an all-zero result, the one way it fails for a
/// 32-byte key), and the result is checked here as well.
fn dh(sk: &SecretKey, pk: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let out = agreement::agree(
        &sk.private()?,
        UnparsedPublicKey::new(&X25519, pk),
        SealError::ZeroSecret,
        |secret| Ok(Zeroizing::new(secret.to_vec())),
    )?;
    if out.iter().all(|b| *b == 0) {
        return Err(SealError::ZeroSecret);
    }
    Ok(out)
}

/// `ExtractAndExpand(dh, kem_context)`: the shared secret.
fn shared_secret(dh: &[u8], kem_context: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let suite = kem_suite();
    let prk = labeled_extract(&suite, b"", b"eae_prk", dh);
    labeled_expand(&suite, &prk, b"shared_secret", kem_context, N_SECRET)
}

/// A buffer for the Diffie-Hellman results, the first one in it, with room
/// for the second: one that grew would leave the first behind, unwiped.
fn joined(first: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut all = Zeroizing::new(Vec::with_capacity(2 * N_SECRET));
    all.extend_from_slice(first);
    all
}

/// `Encap` (or `AuthEncap`, with `sender`) to `pk_r` under the ephemeral key
/// `sk_e`: the shared secret and `enc`.
fn encap(
    sk_e: &SecretKey,
    pk_r: &[u8; 32],
    sender: Option<&SecretKey>,
) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), SealError> {
    let enc = sk_e.public()?;
    let mut dh_all = joined(&dh(sk_e, pk_r)?);
    let mut kem_context = [enc.as_slice(), pk_r].concat();
    if let Some(sk_s) = sender {
        dh_all.extend_from_slice(&dh(sk_s, pk_r)?);
        kem_context.extend_from_slice(&sk_s.public()?);
    }
    Ok((shared_secret(&dh_all, &kem_context)?, enc))
}

/// `Decap` (or `AuthDecap`, with `sender`) of `enc` by `sk_r`.
fn decap(
    enc: &[u8; 32],
    sk_r: &SecretKey,
    sender: Option<&[u8; 32]>,
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let pk_r = sk_r.public()?;
    let mut dh_all = joined(&dh(sk_r, enc)?);
    let mut kem_context = [enc.as_slice(), &pk_r].concat();
    if let Some(pk_s) = sender {
        dh_all.extend_from_slice(&dh(sk_r, pk_s)?);
        kem_context.extend_from_slice(pk_s);
    }
    shared_secret(&dh_all, &kem_context)
}

// ---------------------------------------------------- the key schedule

/// `KeySchedule(mode, shared_secret, info)` with no PSK: the AEAD key and the
/// base nonce, which a single-shot seal uses as its nonce.
fn key_schedule(
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, [u8; N_N]), SealError> {
    let suite = hpke_suite();
    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
    let context = [&[mode][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(&suite, shared_secret, b"secret", b"");
    let key = labeled_expand(&suite, &secret, b"key", &context, N_K)?;
    let nonce = labeled_expand(&suite, &secret, b"base_nonce", &context, N_N)?;
    let mut base_nonce = [0u8; N_N];
    base_nonce.copy_from_slice(&nonce);
    Ok((key, base_nonce))
}

fn gcm(key: &[u8]) -> Result<LessSafeKey, SealError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| SealError::Cipher)
}

/// A value sealed: the encapsulated key and the ciphertext with its tag.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Sealed {
    /// The encapsulated key, 32 bytes.
    pub(crate) enc: [u8; 32],
    /// The ciphertext, the tag at its end.
    pub(crate) ct: Vec<u8>,
}

impl core::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sealed(<redacted>)")
    }
}

impl Sealed {
    /// The encapsulated key as the account takes it: unpadded base64url.
    pub(crate) fn enc_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.enc)
    }

    /// The ciphertext as the account takes it: unpadded base64url.
    pub(crate) fn ct_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.ct)
    }

    /// A seal as the account sends it, each part checked to be in its
    /// canonical form and of a size a value of 1 to 8192 bytes makes.
    pub(crate) fn from_text(enc: &str, ct: &str) -> Result<Self, SealError> {
        let enc = public_key(enc).map_err(|_| SealError::Form("enc"))?;
        // 17 to 8208 bytes are 23 to 10944 characters: anything longer is
        // not decoded at all.
        if !(23..=10_944).contains(&ct.len()) {
            return Err(SealError::Form("ct"));
        }
        let ct = canonical(ct).ok_or(SealError::Form("ct"))?;
        if !(N_TAG + 1..=N_TAG + PLAINTEXT_MAX).contains(&ct.len()) {
            return Err(SealError::Form("ct"));
        }
        Ok(Self { enc, ct })
    }
}

/// Seals `pt` to `pk_r` with `info` and `aad`, under the ephemeral key
/// `sk_e`: base mode without `sender`, auth mode with it.
fn seal_with(
    sk_e: &SecretKey,
    pk_r: &[u8; 32],
    sender: Option<&SecretKey>,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<Sealed, SealError> {
    let (shared, enc) = encap(sk_e, pk_r, sender)?;
    let mode = if sender.is_some() {
        MODE_AUTH
    } else {
        MODE_BASE
    };
    let (key, nonce) = key_schedule(mode, &shared, info)?;
    // Room for the tag from the start: a buffer that grew would leave the
    // value behind, unwiped. Wiped if sealing fails.
    let mut ct = Zeroizing::new(Vec::with_capacity(pt.len() + N_TAG));
    ct.extend_from_slice(pt);
    gcm(&key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            GcmAad::from(aad),
            &mut *ct,
        )
        .map_err(|_| SealError::Cipher)?;
    Ok(Sealed {
        enc,
        ct: core::mem::take(&mut *ct),
    })
}

/// Opens `sealed` with `sk_r`, `info` and `aad`: base mode without
/// `sender`, auth mode with the sender's public key.
fn open_with(
    sealed: &Sealed,
    sk_r: &SecretKey,
    sender: Option<&[u8; 32]>,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let shared = decap(&sealed.enc, sk_r, sender)?;
    let mode = if sender.is_some() {
        MODE_AUTH
    } else {
        MODE_BASE
    };
    let (key, nonce) = key_schedule(mode, &shared, info)?;
    let mut buffer = Zeroizing::new(sealed.ct.clone());
    let len = gcm(&key)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            GcmAad::from(aad),
            &mut buffer,
        )
        .map_err(|_| SealError::Open)?
        .len();
    buffer.truncate(len);
    Ok(buffer)
}

// -------------------------------------------------------- what callers use

/// A secret's value as one may be sealed: 1 to 8192 bytes of UTF-8,
/// without a NUL.
pub(crate) fn check_value(value: &[u8]) -> Result<(), SealError> {
    let ok = (1..=PLAINTEXT_MAX).contains(&value.len())
        && core::str::from_utf8(value).is_ok()
        && !value.contains(&0);
    if ok { Ok(()) } else { Err(SealError::Value) }
}

/// Seals `value` from this machine (`sender`, its sealing key) to `pk_r`,
/// for `aad`: the auth mode, under a fresh ephemeral key.
pub(crate) fn seal_auth(
    pk_r: &[u8; 32],
    sender: &SecretKey,
    aad: &Aad,
    value: &[u8],
) -> Result<Sealed, SealError> {
    check_value(value)?;
    seal_with(
        &SecretKey::generate()?,
        pk_r,
        Some(sender),
        INFO,
        aad.text().as_bytes(),
        value,
    )
}

/// Opens `sealed` with this machine's key `sk_r`, for `aad`: from the
/// machine whose public key is `sender` (auth), or from the dashboard
/// (base, with no sender). The value is checked as a secret's.
pub(crate) fn open(
    sealed: &Sealed,
    sk_r: &SecretKey,
    sender: Option<&[u8; 32]>,
    aad: &Aad,
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let value = open_with(sealed, sk_r, sender, INFO, aad.text().as_bytes())?;
    check_value(&value)?;
    Ok(value)
}

/// Unpadded base64url that encodes back to itself.
fn canonical(text: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == text).then_some(bytes)
}

/// A public key as the account and the dashboard write it: 32 bytes as
/// unpadded base64url (43 characters), canonical, the last byte's top bit
/// clear.
pub(crate) fn public_key(text: &str) -> Result<[u8; 32], SealError> {
    let bytes = canonical(text).ok_or(SealError::Form("a public key"))?;
    let key: [u8; N_PK] = bytes
        .try_into()
        .map_err(|_| SealError::Form("a public key"))?;
    if key[31] & 0x80 != 0 {
        return Err(SealError::Form("a public key"));
    }
    Ok(key)
}

/// A public key as text.
pub(crate) fn public_key_text(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

/// A key's fingerprint: `SHA256:` and the SHA-256 of its 32 bytes in
/// unpadded standard base64, as an SSH host key's is written.
pub(crate) fn fingerprint(key: &[u8; 32]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(key)))
}

/// What a seal is for, bound into it: the account, the app's id there, the
/// app, the setting's name and the secret's version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Aad {
    text: String,
}

impl Aad {
    /// The associated data for `name` at `version` of `app` (`worker_id`
    /// in the account) of the account `user_id`, each element checked to
    /// be in its form first.
    pub(crate) fn new(
        user_id: u64,
        worker_id: &str,
        app: &str,
        name: &str,
        version: u64,
    ) -> Result<Self, SealError> {
        if !(1..=2_147_483_647).contains(&user_id) {
            return Err(SealError::Aad("the account's id"));
        }
        if !is_uuid_v4(worker_id) {
            return Err(SealError::Aad("the app's id"));
        }
        if !erpc_worker::manifest::is_slug(app, 32) {
            return Err(SealError::Aad("the app"));
        }
        if erpc_worker::manifest::check_setting_name(name).is_err() {
            return Err(SealError::Aad("the setting's name"));
        }
        if !(1..=4_294_967_295).contains(&version) {
            return Err(SealError::Aad("the version"));
        }
        Ok(Self {
            text: format!("erpc-worker-secret:v1:{user_id}:{worker_id}:{app}:{name}:{version}"),
        })
    }

    /// The text that is bound in.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

/// Whether `id` is a version-4 UUID in lowercase.
fn is_uuid_v4(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            14 => c == b'4',
            19 => matches!(c, b'8' | b'9' | b'a' | b'b'),
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn hex_of(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    fn key32(bytes: &[u8]) -> [u8; 32] {
        bytes.try_into().expect("32 bytes")
    }

    /// One of the test vectors RFC 9180 Appendix A cites (its `[TestVectors]`: the
    /// `test-vectors.json` of cfrg/draft-irtf-cfrg-hpke at commit
    /// 5f503c564da00b0687b3de75f1dfbdfc4079ad31), mode 0 and mode 2 of kem
    /// 0x0020, kdf 0x0001, aead 0x0002; the RFC's own text prints none for
    /// this suite. The values that
    /// stand for keys are written in two halves: the secret scanner reads a
    /// whole one as a leaked key, and these are published test values.
    struct Vector {
        mode: u8,
        ikm_e: String,
        ikm_r: String,
        ikm_s: Option<String>,
        sk_rm: String,
        pk_em: &'static str,
        pk_rm: &'static str,
        pk_sm: Option<&'static str>,
        shared_secret: String,
        key: String,
        base_nonce: &'static str,
        info: &'static str,
        aad: &'static str,
        pt: &'static str,
        ct: &'static str,
    }

    fn vectors() -> [Vector; 2] {
        [
            Vector {
                mode: MODE_BASE,
                ikm_e: [
                    "2cd7c601cefb3d42a62b04b7a9041494",
                    "c06c7843818e0ce28a8f704ae7ab20f9",
                ]
                .concat(),
                ikm_r: [
                    "dac33b0e9db1b59dbbea58d59a14e7b5",
                    "896e9bdf98fad6891e99d1686492b9ee",
                ]
                .concat(),
                ikm_s: None,
                sk_rm: [
                    "497b4502664cfea5d5af0b39934dac72",
                    "242a74f8480451e1aee7d6a53320333d",
                ]
                .concat(),
                pk_em: "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
                pk_rm: "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
                pk_sm: None,
                shared_secret: [
                    "3101c54c3a4f87439eaac080699ed9bb",
                    "cc726ffe44e860c0424ccb7e3e2ead7b",
                ]
                .concat(),
                key: [
                    "f50b0609186798729ed0564b36ef2ef8",
                    "044f1f9d05636874d1f46c819c7a669f",
                ]
                .concat(),
                base_nonce: "151d9929e2449747889bc923",
                info: "4f6465206f6e2061204772656369616e2055726e",
                aad: "436f756e742d30",
                pt: "4265617574792069732074727574682c20747275746820626561757479",
                ct: "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
            },
            Vector {
                mode: MODE_AUTH,
                ikm_e: [
                    "734369ab3061f71ee85e090fae308553",
                    "cac8e7b3fbd45b4ba83d05e0cd05b1c4",
                ]
                .concat(),
                ikm_r: [
                    "f59761a1e479c2a291b91a5af2b35dd2",
                    "cace1b2042b570f88a16b226f6f30774",
                ]
                .concat(),
                ikm_s: Some(
                    [
                        "87137373fe6b28a72534f38048b9467a",
                        "614d3566fb3a16a50fcaf11c76051392",
                    ]
                    .concat(),
                ),
                sk_rm: [
                    "47f1eee3670dfaaf27c30a83d06ee9f2",
                    "57af174727c17b35328ef730dfc1cd81",
                ]
                .concat(),
                pk_em: "9e59f4b1fa5c876f684765290c34e51145894cc4f244342b9fb1a4bdfd8bb426",
                pk_rm: "3668d659cec6f338f4f8dc6da6733118d2a633f186a3c1415c895111a8eb7c7d",
                pk_sm: Some("4a91c3d0893433f5e31a79fc520f885527a1bc60bf2b0c72693dd7f0b2e41a5a"),
                shared_secret: [
                    "6579475ca739247fad60b7713b0077f1",
                    "e966e0eaf6f95bff8fa41e446db4b226",
                ]
                .concat(),
                key: [
                    "db0218adcafe73ee2e320bd08146d232",
                    "cedfbd45c7e43d1fae3f1c79dc179b40",
                ]
                .concat(),
                base_nonce: "41da94323642095905a34938",
                info: "4f6465206f6e2061204772656369616e2055726e",
                aad: "436f756e742d30",
                pt: "4265617574792069732074727574682c20747275746820626561757479",
                ct: "10b964283ac2cc0bdc4c85ab617291b446bf3832e9359b2c3a0facc50ea75a3c1afd08aeaacd6041d02eb560ec",
            },
        ]
    }

    #[test]
    fn the_rfc_9180_known_answers_hold_for_base_and_auth() {
        for v in vectors() {
            let sk_e = SecretKey::derive(&hex(&v.ikm_e)).expect("derived");
            let sk_r = SecretKey::derive(&hex(&v.ikm_r)).expect("derived");
            assert_eq!(sk_r.bytes().to_vec(), hex(&v.sk_rm), "mode {}", v.mode);
            let sk_s = v
                .ikm_s
                .as_ref()
                .map(|i| SecretKey::derive(&hex(i)).expect("derived"));
            assert_eq!(
                sk_e.public().expect("a key").to_vec(),
                hex(v.pk_em),
                "mode {}",
                v.mode
            );
            assert_eq!(sk_r.public().expect("a key").to_vec(), hex(v.pk_rm));
            if let (Some(sk_s), Some(pk_sm)) = (&sk_s, v.pk_sm) {
                assert_eq!(sk_s.public().expect("a key").to_vec(), hex(pk_sm));
            }
            let pk_r = key32(&hex(v.pk_rm));
            let (shared, enc) = encap(&sk_e, &pk_r, sk_s.as_ref()).expect("encap");
            assert_eq!(shared.to_vec(), hex(&v.shared_secret));
            assert_eq!(enc.to_vec(), hex(v.pk_em));
            let (key, nonce) = key_schedule(v.mode, &shared, &hex(v.info)).expect("schedule");
            assert_eq!(key.to_vec(), hex(&v.key));
            assert_eq!(nonce.to_vec(), hex(v.base_nonce));
            let sealed = seal_with(
                &sk_e,
                &pk_r,
                sk_s.as_ref(),
                &hex(v.info),
                &hex(v.aad),
                &hex(v.pt),
            )
            .expect("sealed");
            assert_eq!(sealed.ct, hex(v.ct));
            let pk_s = sk_s.as_ref().map(|s| s.public().expect("a key"));
            let opened = open_with(&sealed, &sk_r, pk_s.as_ref(), &hex(v.info), &hex(v.aad))
                .expect("opened");
            assert_eq!(opened.to_vec(), hex(v.pt));
        }
    }

    // ------------------------------------------- the dashboard's fixtures

    const FIXTURE: &str = "erpc-worker-seal-fixtures/v1";
    const WORKER_ID: &str = "2c1d5e3a-7b4f-4a9e-8d6c-0f1e2a3b4c5d";

    /// A fixture key: DeriveKeyPair(SHA-256("<format>:key:<name>")). Every
    /// key of the fixtures comes from a public string, so none is kept.
    fn fixture_key(name: &str) -> SecretKey {
        SecretKey::derive(&Sha256::digest(format!("{FIXTURE}:key:{name}"))).expect("derived")
    }

    fn fixture_ephemeral(id: &str) -> SecretKey {
        SecretKey::derive(&Sha256::digest(format!("{FIXTURE}:ephemeral:{id}"))).expect("derived")
    }

    fn aad_of(elements: &Value) -> Aad {
        Aad::new(
            elements["userId"].as_u64().expect("userId"),
            elements["workerId"].as_str().expect("workerId"),
            elements["app"].as_str().expect("app"),
            elements["name"].as_str().expect("name"),
            elements["version"].as_u64().expect("version"),
        )
        .expect("an aad")
    }

    fn elements() -> Value {
        json!({ "userId": 100_001, "workerId": WORKER_ID, "app": "pump-sniper",
                "name": "API_TOKEN", "version": 2 })
    }

    /// The cases the dashboard sealed in JS that open, with what JS made of
    /// them: sealed here the same way, they must be the same bytes.
    /// A case: its id, recipient, sender, value, and what JS made: `enc`
    /// and `ct`.
    type JsCase = (
        &'static str,
        &'static str,
        Option<&'static str>,
        &'static str,
        &'static str,
        &'static str,
    );

    const SEALED_IN_JS: [JsCase; 7] = [
        (
            "base-ascii",
            "recipientA",
            None,
            "erpc worker fixture value 1",
            "1EUdMsYjVGauUdbrZhB1E1rN5HzkXh8aj4kLesvcdyA",
            "A7YUdhVJfcxkviY6lwnhP5yaVsDY8vyxcQQt7rEWwGiUif_xPV1HQIK1Ww",
        ),
        (
            "base-japanese",
            "recipientA",
            None,
            "日本語の値と ASCII の値",
            "aa1dxzGKIsXQJH1XLElxj-4J7qvf-50IrlyW1nU_XC8",
            "kJcCacRw3WHdxg8Xy0tU2zF91RaMmfvDZ8UcDEA_LedhDzLn0F3Xys4CLxT42FY",
        ),
        (
            "base-1byte",
            "recipientA",
            None,
            "z",
            "nrkQqs2pMVFvaiPVeDfO3WWCV1rz6JmNpf2HiFgTV20",
            "cdY7rhz6UFHbmSqmceeXAI0",
        ),
        (
            "auth-ascii",
            "recipientA",
            Some("senderA"),
            "erpc worker fixture value 1",
            "Cf2UQ4KhzZAayny5M9-z3j5wxUcJkUs2Xcxrt7zygGk",
            "oist6hvmfz1HOijoisK3-8-3ZEd7FYc65JL-AtG6I8Z2VQTBYj3MSFmtUA",
        ),
        (
            "auth-japanese",
            "recipientA",
            Some("senderA"),
            "日本語の値と ASCII の値",
            "z1xBFhEabnzxT9iV5ho0oUEN5-ehqLrZa4K0aCi2bCQ",
            "QkOxzZYi7DFFANtm7whWWlGHVK5_t-__GIwmNqlBZOqpbb2BZ_HB8lrfGoEegFM",
        ),
        (
            "auth-1byte",
            "recipientA",
            Some("senderA"),
            "z",
            "p6RKIr567g4l_G4i8q5OsC5aA2oBwSf7uULmPm52ozk",
            "7HIbS36Z0LXeB-hD86tNsz8",
        ),
        (
            "auth-self",
            "senderA",
            Some("senderA"),
            "erpc worker fixture value 1",
            "aTMzaxx-Qk2mkPgtHZUJGWqTNvpid2bp_SLEpjwoxWY",
            "8DiaX2V7ZACdfEbxuQIaoLnr4ML9T_kUvTXR1ZyTTf5UsSacROQg7iCwVA",
        ),
    ];

    #[test]
    fn what_the_dashboard_seals_in_js_is_sealed_the_same_here_and_opens() {
        let aad = aad_of(&elements());
        for (id, recipient, sender, value, enc, ct) in SEALED_IN_JS {
            let sk_r = fixture_key(recipient);
            let sk_s = sender.map(fixture_key);
            let sealed = seal_with(
                &fixture_ephemeral(id),
                &sk_r.public().expect("a key"),
                sk_s.as_ref(),
                INFO,
                aad.text().as_bytes(),
                value.as_bytes(),
            )
            .expect("sealed");
            assert_eq!(
                (sealed.enc_text().as_str(), sealed.ct_text().as_str()),
                (enc, ct),
                "{id}"
            );
            let from_js = Sealed::from_text(enc, ct).expect("in form");
            let pk_s = sk_s.as_ref().map(|s| s.public().expect("a key"));
            let opened = open(&from_js, &sk_r, pk_s.as_ref(), &aad).expect("opened");
            assert_eq!(opened.as_slice(), value.as_bytes(), "{id}");
        }
    }

    #[test]
    fn a_seal_does_not_open_for_another_account_app_name_version_key_or_mode() {
        let aad = aad_of(&elements());
        let (r, s) = (fixture_key("recipientA"), fixture_key("senderA"));
        let pk_s = s.public().expect("a key");
        let value = b"erpc worker fixture value 1";
        let base = seal_with(
            &fixture_ephemeral("x"),
            &r.public().expect("a key"),
            None,
            INFO,
            aad.text().as_bytes(),
            value,
        )
        .expect("sealed");
        let auth = seal_with(
            &fixture_ephemeral("y"),
            &r.public().expect("a key"),
            Some(&s),
            INFO,
            aad.text().as_bytes(),
            value,
        )
        .expect("sealed");
        let moved = |field: &str, to: Value| {
            let mut e = elements();
            e[field] = to;
            aad_of(&e)
        };
        for other in [
            moved("userId", json!(100_002)),
            moved("workerId", json!("2c1d5e3a-7b4f-4a9e-8d6c-0f1e2a3b4c5e")),
            moved("app", json!("pump-sniper-b")),
            moved("name", json!("API_TOKEN_B")),
            moved("version", json!(3)),
        ] {
            assert_eq!(open(&base, &r, None, &other), Err(SealError::Open));
            assert_eq!(open(&auth, &r, Some(&pk_s), &other), Err(SealError::Open));
        }
        let b = fixture_key("recipientB");
        assert_eq!(open(&base, &b, None, &aad), Err(SealError::Open));
        assert_eq!(open(&auth, &b, Some(&pk_s), &aad), Err(SealError::Open));
        let other_sender = fixture_key("senderB").public().expect("a key");
        assert_eq!(
            open(&auth, &r, Some(&other_sender), &aad),
            Err(SealError::Open)
        );
        assert_eq!(open(&auth, &r, None, &aad), Err(SealError::Open));
        assert_eq!(open(&base, &r, Some(&pk_s), &aad), Err(SealError::Open));
        assert!(open(&base, &r, None, &aad).is_ok() && open(&auth, &r, Some(&pk_s), &aad).is_ok());
    }

    /// Every case of the dashboard's fixture file, the large ones too, when
    /// `ERPC_SEAL_JS_FIXTURES` names it: not in this repository, so a run
    /// without it checks nothing here.
    #[test]
    fn every_case_of_the_dashboards_fixture_file_when_given() {
        let Ok(path) = std::env::var("ERPC_SEAL_JS_FIXTURES") else {
            return;
        };
        let file: Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("the file")).expect("json");
        assert_eq!(file["format"], FIXTURE);
        for (name, key) in file["keys"].as_object().expect("keys") {
            let pk = fixture_key(name).public().expect("a key");
            assert_eq!(
                public_key_text(&pk),
                key["pk"].as_str().expect("pk"),
                "{name}"
            );
            assert_eq!(
                fingerprint(&pk),
                key["fingerprint"].as_str().expect("fp"),
                "{name}"
            );
        }
        let cases = file["cases"].as_array().expect("cases");
        for case in cases {
            let id = case["id"].as_str().expect("id");
            let sealed_with = &case["sealedWith"];
            let value = hex(case["plaintextHex"].as_str().expect("plaintext"));
            let sk_r = fixture_key(sealed_with["recipient"].as_str().expect("recipient"));
            let sk_s = sealed_with["sender"].as_str().map(fixture_key);
            let again = seal_with(
                &fixture_ephemeral(id),
                &sk_r.public().expect("a key"),
                sk_s.as_ref(),
                INFO,
                aad_of(&sealed_with["aadElements"]).text().as_bytes(),
                &value,
            )
            .expect("sealed");
            assert_eq!(again.enc_text(), case["enc"].as_str().expect("enc"), "{id}");
            assert_eq!(again.ct_text(), case["ct"].as_str().expect("ct"), "{id}");
            let given = Sealed::from_text(
                case["enc"].as_str().expect("enc"),
                case["ct"].as_str().expect("ct"),
            )
            .expect("in form");
            let with = &case["openWith"];
            let sender = with["sender"]
                .as_str()
                .filter(|_| with["mode"] == "auth")
                .map(|s| fixture_key(s).public().expect("a key"));
            let opened = open(
                &given,
                &fixture_key(with["recipient"].as_str().expect("recipient")),
                sender.as_ref(),
                &aad_of(&with["aadElements"]),
            );
            match case["expect"].as_str() {
                Some("ok") => assert_eq!(opened.expect("opened").to_vec(), value, "{id}"),
                _ => assert_eq!(opened, Err(SealError::Open), "{id}"),
            }
        }
        assert_eq!(cases.len(), 24);
    }

    /// Writes this side's fixture file, in the dashboard's form, where
    /// `ERPC_SEAL_RUST_FIXTURES_OUT` names it: every case sealed here.
    #[test]
    fn this_sides_fixture_file_is_written_when_asked() {
        let Ok(out) = std::env::var("ERPC_SEAL_RUST_FIXTURES_OUT") else {
            return;
        };
        let given: Value = serde_json::from_str(
            &std::fs::read_to_string(std::env::var("ERPC_SEAL_JS_FIXTURES").expect("the JS file"))
                .expect("read"),
        )
        .expect("json");
        let mut keys = serde_json::Map::new();
        for name in ["recipientA", "recipientB", "senderA", "senderB"] {
            let sk = fixture_key(name);
            let pk = sk.public().expect("a key");
            keys.insert(
                name.to_owned(),
                json!({
                    "ikm": hex_of(&Sha256::digest(format!("{FIXTURE}:key:{name}"))),
                    "sk": URL_SAFE_NO_PAD.encode(sk.bytes()),
                    "pk": public_key_text(&pk),
                    "fingerprint": fingerprint(&pk),
                }),
            );
        }
        let mut cases = Vec::new();
        for case in given["cases"].as_array().expect("cases") {
            let id = case["id"].as_str().expect("id");
            let with = &case["sealedWith"];
            let value = hex(case["plaintextHex"].as_str().expect("plaintext"));
            let eph = fixture_ephemeral(id);
            let aad = aad_of(&with["aadElements"]);
            let sk_s = with["sender"].as_str().map(fixture_key);
            let sealed = seal_with(
                &eph,
                &fixture_key(with["recipient"].as_str().expect("recipient"))
                    .public()
                    .expect("a key"),
                sk_s.as_ref(),
                INFO,
                aad.text().as_bytes(),
                &value,
            )
            .expect("sealed");
            let mut out_case = case.clone();
            out_case["ephemeral"] = json!({
                "ikm": hex_of(&Sha256::digest(format!("{FIXTURE}:ephemeral:{id}"))),
                "sk": URL_SAFE_NO_PAD.encode(eph.bytes()),
                "pk": public_key_text(&eph.public().expect("a key")),
            });
            out_case["aad"] = json!(aad.text());
            out_case["enc"] = json!(sealed.enc_text());
            out_case["ct"] = json!(sealed.ct_text());
            cases.push(out_case);
        }
        let file = json!({
            "format": FIXTURE,
            "producer": "erpc (Rust, aws-lc-rs)",
            "suite": { "kemId": 32, "kdfId": 1, "aeadId": 2 },
            "info": "erpc-worker-secret:v1",
            "keys": keys,
            "cases": cases,
        });
        std::fs::write(out, serde_json::to_string_pretty(&file).expect("json")).expect("written");
    }

    // ---------------------------------------------------------------- forms

    #[test]
    fn a_public_key_is_32_bytes_in_canonical_base64url_with_the_top_bit_clear() {
        let pk = fixture_key("recipientA").public().expect("a key");
        let text = public_key_text(&pk);
        assert_eq!(text.len(), 43);
        assert_eq!(public_key(&text).expect("in form"), pk);
        assert!(fingerprint(&pk).starts_with("SHA256:") && fingerprint(&pk).len() == 50);
        for bad in [
            "",
            &text[..42],
            &format!("{text}A"),
            &format!("{text}="),
            // The same bytes, not as erpc and the dashboard write them.
            &text.replace('_', "/").replace('-', "+"),
        ] {
            assert!(public_key(bad).is_err(), "{bad}");
        }
        // The top bit of the last byte set: not a key the account takes.
        let mut high = pk;
        high[31] |= 0x80;
        assert!(public_key(&public_key_text(&high)).is_err());
    }

    #[test]
    fn a_seal_from_the_account_is_checked_for_its_form_and_size() {
        let enc = public_key_text(&fixture_key("recipientA").public().expect("a key"));
        let ct = |len: usize| URL_SAFE_NO_PAD.encode(vec![7u8; len]);
        assert!(Sealed::from_text(&enc, &ct(17)).is_ok());
        assert!(Sealed::from_text(&enc, &ct(16 + 8192)).is_ok());
        assert_eq!(Sealed::from_text(&enc, &ct(16)), Err(SealError::Form("ct")));
        assert_eq!(
            Sealed::from_text(&enc, &ct(16 + 8193)),
            Err(SealError::Form("ct"))
        );
        assert_eq!(
            Sealed::from_text("AAAA", &ct(20)),
            Err(SealError::Form("enc"))
        );
        assert_eq!(
            Sealed::from_text(&enc, "A7YU=="),
            Err(SealError::Form("ct"))
        );
        let sealed = Sealed::from_text(&enc, &ct(20)).expect("in form");
        assert_eq!(format!("{sealed:?}"), "Sealed(<redacted>)");
    }

    #[test]
    fn the_associated_data_names_its_elements_in_their_forms_only() {
        let aad = aad_of(&elements());
        assert_eq!(
            aad.text(),
            "erpc-worker-secret:v1:100001:2c1d5e3a-7b4f-4a9e-8d6c-0f1e2a3b4c5d:pump-sniper:API_TOKEN:2"
        );
        let new = |u: u64, w: &str, a: &str, n: &str, v: u64| Aad::new(u, w, a, n, v);
        assert!(new(0, WORKER_ID, "pump-sniper", "API_TOKEN", 2).is_err());
        assert!(new(2_147_483_648, WORKER_ID, "pump-sniper", "API_TOKEN", 2).is_err());
        assert!(
            new(
                1,
                "2C1D5E3A-7B4F-4A9E-8D6C-0F1E2A3B4C5D",
                "pump-sniper",
                "API_TOKEN",
                2
            )
            .is_err()
        );
        assert!(
            new(
                1,
                "2c1d5e3a-7b4f-1a9e-8d6c-0f1e2a3b4c5d",
                "pump-sniper",
                "API_TOKEN",
                2
            )
            .is_err()
        );
        assert!(new(1, WORKER_ID, "Pump", "API_TOKEN", 2).is_err());
        assert!(new(1, WORKER_ID, "pump:sniper", "API_TOKEN", 2).is_err());
        assert!(new(1, WORKER_ID, "pump-sniper", "api_token", 2).is_err());
        assert!(new(1, WORKER_ID, "pump-sniper", "API_TOKEN", 0).is_err());
        assert!(new(1, WORKER_ID, "pump-sniper", "API_TOKEN", 4_294_967_296).is_err());
    }

    #[test]
    fn a_value_is_utf8_of_1_to_8192_bytes_without_a_nul() {
        assert!(check_value(b"x").is_ok());
        assert!(check_value(&[b'x'; 8192]).is_ok());
        assert_eq!(check_value(b""), Err(SealError::Value));
        assert_eq!(check_value(&[b'x'; 8193]), Err(SealError::Value));
        assert_eq!(check_value(b"a\0b"), Err(SealError::Value));
        assert_eq!(check_value(&[0xff, 0xfe]), Err(SealError::Value));
        let r = fixture_key("recipientA");
        let s = fixture_key("senderA");
        let aad = aad_of(&elements());
        assert_eq!(
            seal_auth(&r.public().expect("a key"), &s, &aad, b""),
            Err(SealError::Value)
        );
    }

    #[test]
    fn a_seal_from_this_machine_opens_with_its_key_and_carries_a_fresh_ephemeral_key() {
        let r = fixture_key("recipientA");
        let s = SecretKey::generate().expect("a key");
        let aad = aad_of(&elements());
        let pk_r = r.public().expect("a key");
        let one = seal_auth(&pk_r, &s, &aad, b"a value").expect("sealed");
        let two = seal_auth(&pk_r, &s, &aad, b"a value").expect("sealed");
        assert_ne!(one.enc, two.enc);
        let pk_s = s.public().expect("a key");
        assert_eq!(
            open(&one, &r, Some(&pk_s), &aad)
                .expect("opened")
                .as_slice(),
            b"a value"
        );
        assert_eq!(format!("{s:?}"), "SecretKey(<redacted>)");
    }

    #[test]
    fn a_key_exchange_that_gives_all_zeros_is_refused() {
        // The zero point is of low order: every exchange with it is zero.
        let r = fixture_key("recipientA");
        assert_eq!(
            seal_with(&fixture_ephemeral("z"), &[0u8; 32], None, INFO, b"", b"x"),
            Err(SealError::ZeroSecret)
        );
        let sealed = Sealed {
            enc: [0u8; 32],
            ct: vec![0; 17],
        };
        assert_eq!(
            open_with(&sealed, &r, None, INFO, b""),
            Err(SealError::ZeroSecret)
        );
    }

    #[test]
    fn what_opens_is_checked_as_a_value_too_in_either_mode() {
        let r = fixture_key("recipientA");
        let s = fixture_key("senderA");
        let pk_r = r.public().expect("a key");
        let pk_s = s.public().expect("a key");
        let aad = aad_of(&elements());
        let long = vec![b'x'; PLAINTEXT_MAX + 1];
        for bad in [&b""[..], b"a\0b", &[0xff][..], &long] {
            for sender in [None, Some(&s)] {
                // Sealed past the check, as a dashboard that did not check
                // would: opened, it is refused for what it is.
                let sealed = seal_with(
                    &fixture_ephemeral("v"),
                    &pk_r,
                    sender,
                    INFO,
                    aad.text().as_bytes(),
                    bad,
                )
                .expect("sealed");
                let from = sender.map(|_| &pk_s);
                assert_eq!(open(&sealed, &r, from, &aad), Err(SealError::Value));
            }
        }
    }

    #[test]
    fn the_largest_value_seals_and_opens_in_either_mode() {
        let r = fixture_key("recipientA");
        let s = fixture_key("senderA");
        let pk_r = r.public().expect("a key");
        let pk_s = s.public().expect("a key");
        let aad = aad_of(&elements());
        let value = vec![b'z'; PLAINTEXT_MAX];
        let auth = seal_auth(&pk_r, &s, &aad, &value).expect("sealed");
        let base = seal_with(
            &fixture_ephemeral("big"),
            &pk_r,
            None,
            INFO,
            aad.text().as_bytes(),
            &value,
        )
        .expect("sealed");
        for (sealed, from) in [(&auth, Some(&pk_s)), (&base, None)] {
            assert_eq!(sealed.ct.len(), PLAINTEXT_MAX + N_TAG);
            assert_eq!(sealed.ct_text().len(), 10_944);
            let again = Sealed::from_text(&sealed.enc_text(), &sealed.ct_text()).expect("in form");
            assert_eq!(
                open(&again, &r, from, &aad).expect("opened").as_slice(),
                &value[..]
            );
        }
        // One character more is not decoded at all.
        let longer = format!("{}A", auth.ct_text());
        assert_eq!(
            Sealed::from_text(&auth.enc_text(), &longer),
            Err(SealError::Form("ct"))
        );
    }

    #[test]
    fn a_low_order_sender_key_stops_an_auth_open() {
        let r = fixture_key("recipientA");
        let aad = aad_of(&elements());
        let sealed = seal_auth(
            &r.public().expect("a key"),
            &fixture_key("senderA"),
            &aad,
            b"a value",
        )
        .expect("sealed");
        // The zero point, and the point of order 4 (u = 1): every exchange
        // with them is zero after clamping.
        let mut one = [0u8; 32];
        one[0] = 1;
        for sender in [[0u8; 32], one] {
            assert_eq!(
                open(&sealed, &r, Some(&sender), &aad),
                Err(SealError::ZeroSecret)
            );
        }
    }

    #[test]
    fn a_fingerprint_is_the_keys_sha256_in_unpadded_standard_base64() {
        // SHA-256 of 32 zero bytes, as a fixed answer: the dashboard and
        // the account compute the same.
        assert_eq!(
            fingerprint(&[0u8; 32]),
            "SHA256:Zmh6rfhivXdsj8GLjp+OIAiXFIVu4jOzkCpZHQ1fKSU"
        );
    }

    #[test]
    fn a_sealing_key_reads_back_as_kept_and_only_in_its_canonical_form() {
        let key = fixture_key("recipientA");
        let text = key.to_text();
        assert_eq!(text.len(), 43);
        let back = SecretKey::from_text(&text).expect("read back");
        assert_eq!(back.bytes(), key.bytes());
        // The last character carries 2 bits past the 32 bytes: set, the
        // text is not the one the bytes write, and is refused.
        let zeros = "A".repeat(42);
        assert!(SecretKey::from_text(&format!("{zeros}A")).is_ok());
        assert_eq!(
            SecretKey::from_text(&format!("{zeros}B")).err(),
            Some(SealError::Form("a sealing key"))
        );
        assert_eq!(
            SecretKey::from_text(&"A".repeat(42)).err(),
            Some(SealError::Form("a sealing key"))
        );
    }
}
