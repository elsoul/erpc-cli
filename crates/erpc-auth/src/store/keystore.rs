// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! An encrypted keystore: files under the erpc home that hold secrets
//! sealed with a key only a passphrase opens.
//!
//! It is for a machine whose keychain cannot keep a secret past a reboot
//! (Linux with no Secret Service: a server, WSL, an SSH login) and for
//! anyone who asks for it by name. `erpc worker` keeps an app's secret
//! settings and its trading key here when it has neither 1Password nor
//! such a keychain. It is not a session store: `erpc login` does not use it.
//!
//! # The format, version 1
//!
//! All of it is public, so the files can be read without erpc. Bytes are
//! written as lowercase hex.
//!
//! ```text
//! <keystore>/                             directory, mode 0700
//!   master.json                           mode 0600
//!   master.json.lock                      empty; held while master.json is made
//!   entries/<service>/<account>.json      mode 0600, in directories of mode 0700
//! ```
//!
//! `master.json` holds the master key, 32 random bytes, wrapped under a key
//! made from the passphrase:
//!
//! ```json
//! {
//!   "format": "erpc-keystore-master",
//!   "version": 1,
//!   "key_id": "<8 bytes: the start of SHA-256 of the master key>",
//!   "kdf": "pbkdf2-hmac-sha256",
//!   "iterations": 600000,
//!   "salt": "<32 random bytes>",
//!   "cipher": "chacha20-poly1305",
//!   "nonce": "<12 random bytes>",
//!   "wrapped": "<48 bytes: the master key sealed, then the 16-byte tag>"
//! }
//! ```
//!
//! - The wrapping key is 32 bytes of PBKDF2-HMAC-SHA256 over the
//!   passphrase's UTF-8 bytes as they were typed (not normalised), with
//!   `salt` and `iterations`.
//! - The master key is sealed with ChaCha20-Poly1305 under the wrapping key
//!   and `nonce`. The associated data is the text of `format`, `version`,
//!   `key_id`, `kdf`, `iterations`, `salt` and `cipher`, in that order, each
//!   followed by a line feed.
//!
//! An entry holds one value, sealed under a key of its own:
//!
//! ```json
//! {
//!   "format": "erpc-keystore-entry",
//!   "version": 1,
//!   "key_id": "<the id of the master key it is sealed under>",
//!   "name": "<service>/<account>",
//!   "kind": "<key or secret>",
//!   "kdf": "hkdf-sha256",
//!   "salt": "<32 random bytes, new at every write>",
//!   "cipher": "chacha20-poly1305",
//!   "nonce": "<12 random bytes, new at every write>",
//!   "sealed": "<the value sealed, then the 16-byte tag>"
//! }
//! ```
//!
//! - `kind` says what the value is: `key` for a trading key, `secret` for
//!   anything else ([`Kind`]). An entry is read as one or the other, and
//!   opens only as the kind it was written as.
//! - The entry's key is 32 bytes of HKDF-SHA256 over the master key, with
//!   `salt` and the info string [`ENTRY_INFO`].
//! - The value is sealed with ChaCha20-Poly1305 under that key and `nonce`.
//!   The associated data is the text of `format`, `version`, `key_id`,
//!   `name`, `kind`, `kdf`, `salt` and `cipher`, in that order, each
//!   followed by a line feed, where `name` is the `<service>/<account>` the
//!   entry is asked for by and `kind` the kind it is asked for as. So an
//!   entry moved or renamed to another account, sealed under another master
//!   key, or whose `kind` was rewritten, does not open.
//!
//! A service and an account are ASCII letters, digits, `.`, `_` and `-`,
//! and are kept in the case they were given. Two names that differ only in
//! the case of their letters (or in a `.` at the end) are one file on some
//! file systems, so the keystore holds one spelling of a name at most: it
//! reads the directory, and where another spelling is there it does not
//! read, write or remove the entry ([`KeystoreError::OtherSpelling`]).
//!
//! The cryptography is aws-lc-rs, which rustls already brings in, as for
//! `erpc storage`.
//!
//! # What this does and does not protect
//!
//! - Whoever has the files and the passphrase has everything in them.
//! - Without the passphrase, the files are as strong as the passphrase.
//!   PBKDF2 makes each guess cost [`ITERATIONS`] hashes; it does not make a
//!   passphrase that can be guessed into one that cannot.
//! - Names are not hidden: the service and account are the file's path, and
//!   the length of a value shows in the size of its file.
//! - A file that was changed does not open. An entry replaced by an older
//!   copy of itself does: nothing here notices a rollback.
//! - The kind of an entry binds this code, and nothing else: whoever has
//!   the master key can open a `key` entry by the rules above.
//! - Removing an entry removes its file; it does not scrub the disk.
//! - An unlock kept by [`unlock`] is the master key in the Linux kernel's
//!   keyring, in memory. Any process running as the same user can read it
//!   (one whose session does not hold the user's keyring can link it in)
//!   until it is dropped, the machine restarts or the kernel lets the
//!   keyring go.

use core::fmt;
use core::num::NonZeroU32;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::pbkdf2;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// The PBKDF2-HMAC-SHA256 iterations a new keystore is made with.
pub const ITERATIONS: u32 = 600_000;

/// The most iterations a `master.json` may ask for. A file that asks for
/// more is refused rather than obeyed, so a planted one cannot hold erpc
/// for hours.
pub const MAX_ITERATIONS: u32 = 10_000_000;

/// The fewest characters a new passphrase has.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// The longest value an entry holds, in bytes.
pub const MAX_VALUE: usize = 64 * 1024;

/// The HKDF info string of an entry's key.
pub const ENTRY_INFO: &[u8] = b"erpc keystore v1 entry key";

/// The file the wrapped master key is in.
pub const MASTER_FILE: &str = "master.json";

/// The directory the entries are under.
pub const ENTRIES_DIR: &str = "entries";

const VERSION: u32 = 1;
const MASTER_FORMAT: &str = "erpc-keystore-master";
const ENTRY_FORMAT: &str = "erpc-keystore-entry";
const KDF_PASSPHRASE: &str = "pbkdf2-hmac-sha256";
const KDF_ENTRY: &str = "hkdf-sha256";
const CIPHER: &str = "chacha20-poly1305";
const KEY: usize = 32;
const SALT: usize = 32;
const NONCE: usize = 12;
const TAG: usize = 16;
/// How many characters of a file's own text an error shows.
const SHOWN: usize = 64;
/// The largest `master.json` read; a real one is under 500 bytes.
const MAX_MASTER_FILE: u64 = 16 * 1024;
/// The largest entry file read: the longest value in hex, and its fields.
const MAX_ENTRY_FILE: u64 = (MAX_VALUE as u64 + TAG as u64) * 2 + 4096;

/// What an entry holds, written into it and sealed with it: an entry opens
/// only as the kind it was written as.
///
/// It is what lets a caller read a trading key by rules of its own (a
/// person at a terminal) and be sure that no read of a secret hands one
/// over, whatever name the entry is asked for by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A trading key.
    Key,
    /// Anything else: an API token, a URL that carries one.
    Secret,
}

impl Kind {
    /// The word the entry's file says it with.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Secret => "secret",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        match word {
            "key" => Some(Self::Key),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// Why the keystore could not do what was asked. No variant carries a
/// passphrase, a key or a value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeystoreError {
    /// There is no keystore in this directory: no `master.json`.
    Missing,
    /// A keystore is here already, so none was made.
    Exists,
    /// A new passphrase has fewer characters than [`MIN_PASSPHRASE_CHARS`].
    PassphraseTooShort,
    /// The passphrase does not open `master.json`, or the file was changed
    /// since it was written: the two cannot be told apart.
    WrongPassphrase,
    /// A file is not what this format says it is.
    Unreadable {
        /// The file.
        path: String,
        /// What is wrong with it; never its contents.
        why: &'static str,
    },
    /// A file is of a version, or uses a derivation or cipher, this build
    /// does not know.
    Unsupported {
        /// The file.
        path: String,
        /// What it asks for.
        what: String,
    },
    /// The entry was sealed under another keystore's master key.
    OtherMaster {
        /// The entry, as `<service>/<account>`.
        name: String,
    },
    /// The entry does not open: it was changed, or it is another entry's
    /// file under this name.
    Changed {
        /// The entry, as `<service>/<account>`.
        name: String,
    },
    /// The entry was written as the other kind: a trading key asked for
    /// as a secret, or a secret asked for as a trading key.
    OtherKind {
        /// The entry, as `<service>/<account>`.
        name: String,
        /// The kind its file says it was written as.
        kept: Kind,
    },
    /// The keystore holds this name in another spelling: one that differs
    /// in the case of its letters, which some file systems take for the
    /// same file. Nothing was read, written or removed.
    OtherSpelling {
        /// The entry asked for, as `<service>/<account>`.
        name: String,
        /// The file or directory that spells it otherwise.
        found: String,
    },
    /// A service or account that cannot name a file here.
    BadName,
    /// The value is longer than [`MAX_VALUE`].
    TooLong,
    /// A file or directory could not be read or written.
    Io(String),
    /// The system gave no randomness.
    NoRandom,
    /// The cryptography library refused to derive a key or to seal.
    Crypto,
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("there is no keystore here"),
            Self::Exists => f.write_str("a keystore is here already"),
            Self::PassphraseTooShort => write!(
                f,
                "a keystore passphrase is {MIN_PASSPHRASE_CHARS} characters or more"
            ),
            Self::WrongPassphrase => f.write_str(
                "that passphrase does not open the keystore, or its master.json was changed",
            ),
            Self::Unreadable { path, why } => write!(f, "{path} is not a keystore file: {why}"),
            Self::Unsupported { path, what } => {
                write!(f, "{path} asks for {what}, which this erpc does not know")
            }
            Self::OtherMaster { name } => {
                write!(f, "{name} was sealed under another keystore's master key")
            }
            Self::Changed { name } => write!(
                f,
                "{name} does not open: its file was changed, or belongs under another name"
            ),
            Self::OtherKind {
                name,
                kept: Kind::Key,
            } => write!(
                f,
                "{name} is kept as a trading key, and is not read as a secret"
            ),
            Self::OtherKind {
                name,
                kept: Kind::Secret,
            } => write!(
                f,
                "{name} is kept as a secret, and is not read as a trading key"
            ),
            Self::OtherSpelling { name, found } => write!(
                f,
                "{name} is in the keystore under another spelling ({found}); the two are one \
                 file where case is ignored, so nothing was done"
            ),
            Self::BadName => f.write_str(
                "a keystore service and account are letters, digits, `.`, `_` and `-`, and do \
                 not start with `.`",
            ),
            Self::TooLong => write!(f, "a keystore value is at most {MAX_VALUE} bytes"),
            Self::Io(message) => f.write_str(message),
            Self::NoRandom => f.write_str("the system gave no randomness"),
            Self::Crypto => f.write_str("the keystore's cryptography could not be run"),
        }
    }
}

impl core::error::Error for KeystoreError {}

/// A keystore's master key, unwrapped. Wiped when dropped.
#[derive(Clone)]
pub struct Master(Zeroizing<[u8; KEY]>);

impl Master {
    fn generate() -> Result<Self, KeystoreError> {
        let mut bytes = Zeroizing::new([0_u8; KEY]);
        random(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// The first 8 bytes of SHA-256 of the key, as hex: names the key
    /// without showing it.
    #[must_use]
    pub fn id(&self) -> String {
        hex(&Sha256::digest(self.0.as_slice())[..8])
    }

    fn entry_key(&self, salt: &[u8; SALT]) -> Result<LessSafeKey, KeystoreError> {
        let prk = Salt::new(HKDF_SHA256, salt).extract(self.0.as_slice());
        let okm = prk
            .expand(&[ENTRY_INFO], &CHACHA20_POLY1305)
            .map_err(|_| KeystoreError::Crypto)?;
        Ok(LessSafeKey::new(UnboundKey::from(okm)))
    }
}

impl fmt::Debug for Master {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Master({})", self.id())
    }
}

/// `master.json` as it is written.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MasterFile {
    format: String,
    version: u32,
    key_id: String,
    kdf: String,
    iterations: u32,
    salt: String,
    cipher: String,
    nonce: String,
    wrapped: String,
}

/// An entry's file as it is written.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    format: String,
    version: u32,
    key_id: String,
    name: String,
    kind: String,
    kdf: String,
    salt: String,
    cipher: String,
    nonce: String,
    sealed: String,
}

/// What every file of the format starts from, read before the rest so an
/// unknown version is said as that and not as a missing field.
#[derive(Deserialize)]
struct Head {
    format: String,
    version: u32,
}

/// `master.json`, checked and decoded.
struct Wrapped {
    key_id: String,
    iterations: NonZeroU32,
    salt: [u8; SALT],
    nonce: [u8; NONCE],
    sealed: [u8; KEY + TAG],
}

impl Wrapped {
    fn aad(&self) -> String {
        master_aad(&self.key_id, self.iterations.get(), &self.salt)
    }
}

/// The associated data the master key is sealed with.
fn master_aad(key_id: &str, iterations: u32, salt: &[u8; SALT]) -> String {
    format!(
        "{MASTER_FORMAT}\n{VERSION}\n{key_id}\n{KDF_PASSPHRASE}\n{iterations}\n{}\n{CIPHER}\n",
        hex(salt)
    )
}

/// The associated data the entry `name` is sealed with as a `kind`.
fn entry_aad(key_id: &str, name: &str, kind: Kind, salt: &[u8; SALT]) -> String {
    format!(
        "{ENTRY_FORMAT}\n{VERSION}\n{key_id}\n{name}\n{}\n{KDF_ENTRY}\n{}\n{CIPHER}\n",
        kind.as_str(),
        hex(salt)
    )
}

/// The key a passphrase wraps the master key under.
fn wrapping_key(
    passphrase: &str,
    salt: &[u8; SALT],
    iterations: NonZeroU32,
) -> Result<LessSafeKey, KeystoreError> {
    let mut key = Zeroizing::new([0_u8; KEY]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        passphrase.as_bytes(),
        key.as_mut(),
    );
    UnboundKey::new(&CHACHA20_POLY1305, key.as_slice())
        .map(LessSafeKey::new)
        .map_err(|_| KeystoreError::Crypto)
}

fn random(out: &mut [u8]) -> Result<(), KeystoreError> {
    aws_lc_rs::rand::fill(out).map_err(|_| KeystoreError::NoRandom)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

/// The bytes `text` spells in hex, or none when it is not hex.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

fn unhex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    unhex(text)?.try_into().ok()
}

/// Whether `id` is a key id as this format writes one.
fn is_key_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `part` may be a service or an account: what a `keystore:`
/// reference takes, and never `.`, `..` or a hidden file.
fn is_part(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 128
        && !part.starts_with('.')
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether two names are one file where a file system ignores case, or
/// drops a `.` from the end of a name as Windows does. The names here are
/// ASCII ([`is_part`]), so ASCII case is all the case there is.
fn same_file(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// The names in `dir` that are `name` or another spelling of it
/// ([`same_file`]). A directory that is not there holds none.
fn spellings(dir: &Path, name: &str) -> Result<Vec<String>, KeystoreError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io("list", dir, &e)),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| io("list", dir, &e))?;
        // A name that is not UTF-8 is no spelling of an ASCII one.
        if let Some(other) = entry.file_name().to_str()
            && same_file(other, name)
        {
            found.push(other.to_owned());
        }
    }
    Ok(found)
}

/// Text a keystore file supplied, as an error may show it: in quotes, cut
/// to [`SHOWN`] characters, every character that is not printable ASCII
/// written as an escape. A file brought from another machine cannot put a
/// control character or an escape sequence on the terminal through it.
fn shown(text: &str) -> String {
    let mut out = String::from('"');
    for c in text.chars().take(SHOWN) {
        out.extend(c.escape_default());
    }
    out.push('"');
    if text.chars().nth(SHOWN).is_some() {
        out.push_str("...");
    }
    out
}

fn io(what: &str, path: &Path, error: &std::io::Error) -> KeystoreError {
    KeystoreError::Io(format!("could not {what} {}: {error}", path.display()))
}

/// Makes `dir`, and what is above it, for the owner alone; one that is
/// there already is made the owner's alone too.
fn private_dir(dir: &Path) -> Result<(), KeystoreError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| io("make", dir, &e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| io("make private", dir, &e))?;
    }
    Ok(())
}

/// Asks the system to put `dir`'s own record of a rename on disk. Not
/// every file system can, and the file itself was synced before it was
/// renamed, so a refusal is not a failure.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// The whole of `path`, none when there is no such file, an error when it
/// is larger than `max`.
fn read_file(path: &Path, max: u64) -> Result<Option<Vec<u8>>, KeystoreError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io("read", path, &e)),
    };
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io("read", path, &e))?;
    if bytes.len() as u64 > max {
        return Err(unreadable(path, "it is larger than a keystore file is"));
    }
    Ok(Some(bytes))
}

fn unreadable(path: &Path, why: &'static str) -> KeystoreError {
    KeystoreError::Unreadable {
        path: path.display().to_string(),
        why,
    }
}

fn unsupported(path: &Path, what: String) -> KeystoreError {
    KeystoreError::Unsupported {
        path: path.display().to_string(),
        what,
    }
}

/// Checks that `bytes` is a file of `format` in a version this build
/// reads, before the rest of it is looked at.
fn check_head(path: &Path, bytes: &[u8], format: &str) -> Result<(), KeystoreError> {
    let head: Head = serde_json::from_slice(bytes)
        .map_err(|_| unreadable(path, "it is not a JSON document of this format"))?;
    if head.format != format {
        return Err(unreadable(path, "it is another kind of file"));
    }
    if head.version != VERSION {
        return Err(unsupported(path, format!("version {}", head.version)));
    }
    Ok(())
}

/// `master.json` for `master`, wrapped under `passphrase` with this salt
/// and nonce. Apart from the randomness, so that a test pins the format
/// with values of its own.
fn wrap(
    master: &Master,
    passphrase: &str,
    iterations: NonZeroU32,
    salt: &[u8; SALT],
    nonce: [u8; NONCE],
) -> Result<MasterFile, KeystoreError> {
    let key_id = master.id();
    let key = wrapping_key(passphrase, salt, iterations)?;
    // Room for the tag, so sealing does not move the key to a new buffer.
    let mut wrapped = Zeroizing::new(Vec::with_capacity(KEY + TAG));
    wrapped.extend_from_slice(master.0.as_slice());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(master_aad(&key_id, iterations.get(), salt).as_bytes()),
        &mut *wrapped,
    )
    .map_err(|_| KeystoreError::Crypto)?;
    Ok(MasterFile {
        format: MASTER_FORMAT.to_owned(),
        version: VERSION,
        key_id,
        kdf: KDF_PASSPHRASE.to_owned(),
        iterations: iterations.get(),
        salt: hex(salt),
        cipher: CIPHER.to_owned(),
        nonce: hex(&nonce),
        wrapped: hex(&wrapped),
    })
}

/// The file of the entry `name`: `value`, a `kind`, sealed under `master`
/// with this salt and nonce. Apart from the randomness, as [`wrap`] is.
fn seal(
    master: &Master,
    name: &str,
    kind: Kind,
    salt: &[u8; SALT],
    nonce: [u8; NONCE],
    value: &str,
) -> Result<EntryFile, KeystoreError> {
    let key_id = master.id();
    // Room for the tag, so sealing does not move the value to a new
    // buffer and leave the old one unwiped.
    let mut sealed = Zeroizing::new(Vec::with_capacity(value.len() + TAG));
    sealed.extend_from_slice(value.as_bytes());
    master
        .entry_key(salt)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(entry_aad(&key_id, name, kind, salt).as_bytes()),
            &mut *sealed,
        )
        .map_err(|_| KeystoreError::Crypto)?;
    Ok(EntryFile {
        format: ENTRY_FORMAT.to_owned(),
        version: VERSION,
        key_id,
        name: name.to_owned(),
        kind: kind.as_str().to_owned(),
        kdf: KDF_ENTRY.to_owned(),
        salt: hex(salt),
        cipher: CIPHER.to_owned(),
        nonce: hex(&nonce),
        sealed: hex(&sealed),
    })
}

/// A keystore file as it is written to the disk.
fn file_text(file: &impl Serialize) -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(file)?;
    text.push('\n');
    Ok(text)
}

/// A keystore in one directory.
#[derive(Debug, Clone)]
pub struct Keystore {
    dir: PathBuf,
    iterations: NonZeroU32,
}

impl Keystore {
    /// The keystore in `dir`, made with [`ITERATIONS`] when it is made.
    #[must_use]
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            iterations: NonZeroU32::new(ITERATIONS).unwrap_or(NonZeroU32::MIN),
        }
    }

    /// As [`Self::at`], made with `iterations` instead: for tests, which
    /// make many keystores. erpc itself makes one only with [`Self::at`].
    /// Opening reads the count from `master.json` either way.
    #[must_use]
    pub fn with_iterations(dir: impl Into<PathBuf>, iterations: NonZeroU32) -> Self {
        Self {
            dir: dir.into(),
            iterations,
        }
    }

    /// The directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where the wrapped master key is.
    #[must_use]
    pub fn master_path(&self) -> PathBuf {
        self.dir.join(MASTER_FILE)
    }

    /// Where the entry under `service` and `account` is, or would be.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::BadName`] for a service or account that cannot
    /// name a file here.
    pub fn entry_path(&self, service: &str, account: &str) -> Result<PathBuf, KeystoreError> {
        if !is_part(service) || !is_part(account) {
            return Err(KeystoreError::BadName);
        }
        Ok(self
            .dir
            .join(ENTRIES_DIR)
            .join(service)
            .join(format!("{account}.json")))
    }

    /// The file of the entry under `service` and `account` when there is
    /// one, once the keystore is seen to hold the name in this spelling
    /// alone.
    ///
    /// The directories are read, not the file opened. Where a file system
    /// ignores case, `bot.WALLET.json` opens `bot.wallet.json`, and a write
    /// or a removal under the one name would take the other's entry.
    /// Reading the names finds a second spelling on any file system, so a
    /// keystore behaves the same wherever its directory is carried.
    fn spelled(&self, service: &str, account: &str) -> Result<Option<PathBuf>, KeystoreError> {
        let path = self.entry_path(service, account)?;
        let other = |dir: &Path, found: &str| KeystoreError::OtherSpelling {
            name: format!("{service}/{account}"),
            found: dir.join(found).display().to_string(),
        };
        let entries = self.dir.join(ENTRIES_DIR);
        if let Some(found) = spellings(&entries, service)?
            .iter()
            .find(|found| *found != service)
        {
            return Err(other(&entries, found));
        }
        let dir = entries.join(service);
        let file = format!("{account}.json");
        let found = spellings(&dir, &file)?;
        if let Some(found) = found.iter().find(|found| **found != file) {
            return Err(other(&dir, found));
        }
        Ok((!found.is_empty()).then_some(path))
    }

    fn wrapped(&self) -> Result<Option<Wrapped>, KeystoreError> {
        let path = self.master_path();
        let Some(bytes) = read_file(&path, MAX_MASTER_FILE)? else {
            return Ok(None);
        };
        check_head(&path, &bytes, MASTER_FORMAT)?;
        let file: MasterFile = serde_json::from_slice(&bytes)
            .map_err(|_| unreadable(&path, "its fields are not a master key's"))?;
        if file.kdf != KDF_PASSPHRASE {
            return Err(unsupported(
                &path,
                format!("the derivation {}", shown(&file.kdf)),
            ));
        }
        if file.cipher != CIPHER {
            return Err(unsupported(
                &path,
                format!("the cipher {}", shown(&file.cipher)),
            ));
        }
        if file.iterations > MAX_ITERATIONS {
            return Err(unsupported(
                &path,
                format!("{} iterations", file.iterations),
            ));
        }
        let iterations = NonZeroU32::new(file.iterations)
            .ok_or_else(|| unreadable(&path, "its iteration count is zero"))?;
        if !is_key_id(&file.key_id) {
            return Err(unreadable(&path, "its key id is not 16 hex digits"));
        }
        let field = |why| unreadable(&path, why);
        Ok(Some(Wrapped {
            key_id: file.key_id,
            iterations,
            salt: unhex_array(&file.salt)
                .ok_or_else(|| field("its salt is not 32 bytes of hex"))?,
            nonce: unhex_array(&file.nonce)
                .ok_or_else(|| field("its nonce is not 12 bytes of hex"))?,
            sealed: unhex_array(&file.wrapped)
                .ok_or_else(|| field("its wrapped key is not 48 bytes of hex"))?,
        }))
    }

    /// The id of this keystore's master key, or none when there is no
    /// keystore here. Read from `master.json` without opening it.
    ///
    /// # Errors
    ///
    /// When `master.json` is there and is not what the format says.
    pub fn key_id(&self) -> Result<Option<String>, KeystoreError> {
        Ok(self.wrapped()?.map(|w| w.key_id))
    }

    /// Makes the keystore: a new master key, wrapped under `passphrase`,
    /// which is then read back with it before anything is sealed.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::PassphraseTooShort`], [`KeystoreError::Exists`]
    /// when there is one already (two processes making one at once: the
    /// second is told so), or why the file could not be written.
    pub fn create(&self, passphrase: &str) -> Result<Master, KeystoreError> {
        if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(KeystoreError::PassphraseTooShort);
        }
        private_dir(&self.dir)?;
        let path = self.master_path();
        let made =
            erpc_core::private_file::locked(&path, || Ok(self.write_master(&path, passphrase)))
                .map_err(KeystoreError::Io)??;
        // Read back from the disk with the passphrase alone: a master key
        // that cannot be had again must not get anything sealed under it.
        match self.open(passphrase) {
            Ok(back) if back.id() == made.id() => Ok(made),
            other => {
                let _ = std::fs::remove_file(&path);
                Err(other
                    .err()
                    .unwrap_or_else(|| unreadable(&path, "it did not read back as it was written")))
            }
        }
    }

    fn write_master(&self, path: &Path, passphrase: &str) -> Result<Master, KeystoreError> {
        if path.exists() {
            return Err(KeystoreError::Exists);
        }
        let master = Master::generate()?;
        let mut salt = [0_u8; SALT];
        random(&mut salt)?;
        let mut nonce = [0_u8; NONCE];
        random(&mut nonce)?;
        let file = wrap(&master, passphrase, self.iterations, &salt, nonce)?;
        self.put_file(path, &file)?;
        Ok(master)
    }

    /// Writes `file` to `path` as JSON: whole, for the owner alone.
    fn put_file(&self, path: &Path, file: &impl Serialize) -> Result<(), KeystoreError> {
        let text = file_text(file)
            .map_err(|e| KeystoreError::Io(format!("could not write {}: {e}", path.display())))?;
        erpc_core::private_file::write(path, text.as_bytes()).map_err(KeystoreError::Io)?;
        sync_dir(path.parent().unwrap_or(&self.dir));
        Ok(())
    }

    /// Unwraps the master key with `passphrase`.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::Missing`] when there is no keystore,
    /// [`KeystoreError::WrongPassphrase`] when the passphrase does not open
    /// it or `master.json` was changed, or why the file is not readable.
    pub fn open(&self, passphrase: &str) -> Result<Master, KeystoreError> {
        let wrapped = self.wrapped()?.ok_or(KeystoreError::Missing)?;
        let key = wrapping_key(passphrase, &wrapped.salt, wrapped.iterations)?;
        let mut buffer = Zeroizing::new(wrapped.sealed.to_vec());
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(wrapped.nonce),
                Aad::from(wrapped.aad().as_bytes()),
                &mut buffer,
            )
            .map_err(|_| KeystoreError::WrongPassphrase)?;
        let mut bytes = Zeroizing::new([0_u8; KEY]);
        if plain.len() != KEY {
            return Err(unreadable(
                &self.master_path(),
                "its wrapped key is not a key",
            ));
        }
        bytes.copy_from_slice(plain);
        let master = Master(bytes);
        if master.id() != wrapped.key_id {
            return Err(unreadable(
                &self.master_path(),
                "its key id is not its key's",
            ));
        }
        Ok(master)
    }

    /// Whether there is an entry under `service` and `account`. Needs no
    /// passphrase: the names are not hidden.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::BadName`], [`KeystoreError::OtherSpelling`] when
    /// the keystore holds the name spelled otherwise, or why the directory
    /// could not be read.
    pub fn has(&self, service: &str, account: &str) -> Result<bool, KeystoreError> {
        Ok(self.spelled(service, account)?.is_some())
    }

    /// The file of the entry under `service` and `account` and the kind it
    /// says it is, as far as it can be checked with no key; none when
    /// there is no such entry.
    fn entry(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<(PathBuf, EntryFile, Kind)>, KeystoreError> {
        let Some(path) = self.spelled(service, account)? else {
            return Ok(None);
        };
        let Some(bytes) = read_file(&path, MAX_ENTRY_FILE)? else {
            return Ok(None);
        };
        check_head(&path, &bytes, ENTRY_FORMAT)?;
        let file: EntryFile = serde_json::from_slice(&bytes)
            .map_err(|_| unreadable(&path, "its fields are not an entry's"))?;
        if file.kdf != KDF_ENTRY {
            return Err(unsupported(
                &path,
                format!("the derivation {}", shown(&file.kdf)),
            ));
        }
        if file.cipher != CIPHER {
            return Err(unsupported(
                &path,
                format!("the cipher {}", shown(&file.cipher)),
            ));
        }
        if file.name != format!("{service}/{account}") {
            return Err(KeystoreError::Changed {
                name: format!("{service}/{account}"),
            });
        }
        let kept = Kind::parse(&file.kind)
            .ok_or_else(|| unsupported(&path, format!("the kind {}", shown(&file.kind))))?;
        Ok(Some((path, file, kept)))
    }

    /// The kind the entry under `service` and `account` says it was
    /// written as, or none when there is no such entry. Needs no
    /// passphrase, and proves nothing: the seal holds an entry to its kind
    /// when it is read ([`Self::read`]). For a caller that would rather
    /// find the wrong kind before it does anything slow.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::OtherSpelling`] when the keystore holds the name
    /// spelled otherwise, or why its file is not readable.
    pub fn kind(&self, service: &str, account: &str) -> Result<Option<Kind>, KeystoreError> {
        Ok(self.entry(service, account)?.map(|(_, _, kept)| kept))
    }

    /// The value under `service` and `account`, read as a `kind`, or none
    /// when there is no such entry.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::OtherKind`] for an entry written as the other
    /// kind, [`KeystoreError::OtherMaster`] for one another keystore
    /// sealed, [`KeystoreError::Changed`] for one that does not open,
    /// [`KeystoreError::OtherSpelling`] when the keystore holds the name
    /// spelled otherwise, or why its file is not readable.
    pub fn read(
        &self,
        master: &Master,
        service: &str,
        account: &str,
        kind: Kind,
    ) -> Result<Option<Zeroizing<String>>, KeystoreError> {
        let name = format!("{service}/{account}");
        let Some((path, file, kept)) = self.entry(service, account)? else {
            return Ok(None);
        };
        // Refused on what the file says, before anything is opened. A file
        // whose kind was rewritten to get past this is refused by the
        // seal, which was made with the kind it was written as.
        if kept != kind {
            return Err(KeystoreError::OtherKind { name, kept });
        }
        if file.key_id != master.id() {
            return Err(KeystoreError::OtherMaster { name });
        }
        let field = |why| unreadable(&path, why);
        let salt: [u8; SALT] =
            unhex_array(&file.salt).ok_or_else(|| field("its salt is not 32 bytes of hex"))?;
        let nonce: [u8; NONCE] =
            unhex_array(&file.nonce).ok_or_else(|| field("its nonce is not 12 bytes of hex"))?;
        let mut buffer = Zeroizing::new(
            unhex(&file.sealed).ok_or_else(|| field("its sealed value is not hex"))?,
        );
        let plain = master
            .entry_key(&salt)?
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(entry_aad(&file.key_id, &name, kind, &salt).as_bytes()),
                &mut buffer,
            )
            .map_err(|_| KeystoreError::Changed { name })?;
        let text = core::str::from_utf8(plain).map_err(|_| field("its value is not text"))?;
        Ok(Some(Zeroizing::new(text.to_owned())))
    }

    /// Seals `value` under `service` and `account` as a `kind`, replacing
    /// what was there.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::OtherMaster`] when `master` is not this keystore's
    /// (nothing is sealed under a key its `master.json` does not hold),
    /// [`KeystoreError::OtherSpelling`] when the keystore holds the name
    /// spelled otherwise (nothing is written over), [`KeystoreError::Missing`],
    /// [`KeystoreError::TooLong`], or why the file could not be written.
    pub fn write(
        &self,
        master: &Master,
        service: &str,
        account: &str,
        kind: Kind,
        value: &str,
    ) -> Result<(), KeystoreError> {
        let path = self.entry_path(service, account)?;
        let name = format!("{service}/{account}");
        if value.len() > MAX_VALUE {
            return Err(KeystoreError::TooLong);
        }
        let key_id = self.key_id()?.ok_or(KeystoreError::Missing)?;
        if key_id != master.id() {
            return Err(KeystoreError::OtherMaster { name });
        }
        self.spelled(service, account)?;
        let mut salt = [0_u8; SALT];
        random(&mut salt)?;
        let mut nonce = [0_u8; NONCE];
        random(&mut nonce)?;
        let file = seal(master, &name, kind, &salt, nonce, value)?;
        let entries = self.dir.join(ENTRIES_DIR);
        private_dir(&entries)?;
        private_dir(&entries.join(service))?;
        self.put_file(&path, &file)
    }

    /// Removes the entry under `service` and `account`; whether there was
    /// one. Needs no passphrase.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::BadName`], [`KeystoreError::OtherSpelling`] when
    /// the keystore holds the name spelled otherwise (nothing is removed),
    /// or why the file could not be removed.
    pub fn delete(&self, service: &str, account: &str) -> Result<bool, KeystoreError> {
        let Some(path) = self.spelled(service, account)? else {
            return Ok(false);
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {
                sync_dir(path.parent().unwrap_or(&self.dir));
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io("remove", &path, &e)),
        }
    }
}

/// The unlock: a keystore's master key kept in the Linux kernel's
/// persistent keyring for the user, so the passphrase is asked once per
/// reboot or idle period and not by every command.
///
/// It is the keyring `erpc login` falls back to on such a machine: in
/// memory, reached through the user keyring, gone at a reboot and after
/// [`idle_expiry_secs`] unused. Other systems have none; there
/// [`SUPPORTED`] is false, nothing is ever kept, and the passphrase is
/// asked for each time.
pub mod unlock {
    use super::Master;

    /// Whether this system can keep an unlock at all.
    pub const SUPPORTED: bool = cfg!(target_os = "linux");

    /// Why an unlock could not be kept or dropped.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum UnlockError {
        /// This system has no kernel keyring.
        Unsupported,
        /// This process holds none of the user's kernel keyrings, so the
        /// kernel lets it neither write nor search one: it was started
        /// without a login of its own (`su` without `-`, `sudo -E`).
        NotHeld,
        /// The kernel refused, for this reason.
        Kernel(String),
    }

    impl core::fmt::Display for UnlockError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Unsupported => f.write_str("this system has no kernel keyring"),
                Self::NotHeld => f.write_str(
                    "this process holds none of your kernel keyrings (it was started without \
                     a login of its own)",
                ),
                Self::Kernel(reason) => write!(f, "the kernel keyring refused: {reason}"),
            }
        }
    }

    impl core::error::Error for UnlockError {}

    /// What the description of every unlock starts with.
    const PREFIX: &str = "erpc-keystore:master:";

    /// The description the master key `key_id` is kept under.
    #[must_use]
    pub fn description(key_id: &str) -> String {
        format!("{PREFIX}{key_id}")
    }

    /// The key ids of the unlocks in `proc_keys`, the text of `/proc/keys`:
    /// a line for each key this user may see, which ends in the key's
    /// description and, for a key that holds something, `: <length>`.
    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn listed(proc_keys: &str) -> Vec<String> {
        let mut ids: Vec<String> = proc_keys
            .lines()
            .filter_map(|line| {
                let at = line.find(PREFIX)?;
                let rest = &line[at + PREFIX.len()..];
                let id = rest.get(..16)?;
                // The description starts at the prefix and ends with the id.
                let whole = line[..at].ends_with(char::is_whitespace)
                    && rest[16..]
                        .chars()
                        .next()
                        .is_none_or(|c| c == ':' || c.is_whitespace());
                (whole && super::is_key_id(id)).then(|| id.to_owned())
            })
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// How long the kernel keeps the keyring unused, in seconds: what
    /// `/proc/sys/kernel/keys/persistent_keyring_expiry` says. None when
    /// it cannot be read.
    #[must_use]
    pub fn idle_expiry_secs() -> Option<u64> {
        if !SUPPORTED {
            return None;
        }
        std::fs::read_to_string("/proc/sys/kernel/keys/persistent_keyring_expiry")
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    #[cfg(target_os = "linux")]
    mod kernel {
        use linux_keyutils::KeyError;
        use zeroize::Zeroizing;

        use super::super::{KEY, Master};
        use super::{UnlockError, description, listed};
        use crate::store::keychain::kernel::{missing, ring};

        fn explain(e: KeyError) -> UnlockError {
            match e {
                KeyError::AccessDenied | KeyError::PermissionDenied => UnlockError::NotHeld,
                other => UnlockError::Kernel(other.to_string()),
            }
        }

        pub(super) fn kept(key_id: &str) -> Option<Master> {
            let key = ring().ok()?.search(&description(key_id)).ok()?;
            let mut bytes = Zeroizing::new([0_u8; KEY]);
            // The kernel says how long the payload is, whatever the room.
            let len = key.read(&mut *bytes).ok()?;
            let master = Master(bytes);
            // Only the key it is named for: anything else is not an unlock.
            (len == KEY && master.id() == key_id).then_some(master)
        }

        pub(super) fn keep(master: &Master) -> Result<(), UnlockError> {
            ring()
                .and_then(|ring| ring.add_key(&description(&master.id()), master.0.as_slice()))
                .map(|_| ())
                .map_err(explain)
        }

        pub(super) fn forget(key_id: &str) -> Result<bool, UnlockError> {
            match ring()
                .and_then(|ring| ring.search(&description(key_id)))
                .and_then(|key| key.invalidate())
            {
                Ok(()) => Ok(true),
                Err(e) if missing(e) => Ok(false),
                Err(e) => Err(explain(e)),
            }
        }

        /// The kernel has no call that lists a keyring by description, and
        /// the one that lists its key ids trusts the caller for the count.
        /// `/proc/keys` names every key this user may see; each unlock in
        /// it is then looked for in the keyring and dropped by its name,
        /// as [`forget`] does. Where the file cannot be read, `also` is
        /// still dropped.
        pub(super) fn forget_all(also: Option<&str>) -> Result<usize, UnlockError> {
            let mut ids = std::fs::read_to_string("/proc/keys")
                .map(|text| listed(&text))
                .unwrap_or_default();
            if let Some(also) = also
                && !ids.iter().any(|id| id == also)
            {
                ids.push(also.to_owned());
            }
            let mut dropped = 0;
            for id in ids {
                if forget(&id)? {
                    dropped += 1;
                }
            }
            Ok(dropped)
        }
    }

    /// The master key kept for the keystore whose key is `key_id`, when
    /// one is kept and this process can read it. Every failure is a no:
    /// the passphrase opens the keystore all the same.
    #[must_use]
    pub fn kept(key_id: &str) -> Option<Master> {
        #[cfg(target_os = "linux")]
        return kernel::kept(key_id);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = key_id;
            None
        }
    }

    /// Keeps `master`, replacing an unlock of the same keystore.
    ///
    /// # Errors
    ///
    /// Why it was not kept.
    pub fn keep(master: &Master) -> Result<(), UnlockError> {
        #[cfg(target_os = "linux")]
        return kernel::keep(master);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = master;
            Err(UnlockError::Unsupported)
        }
    }

    /// Drops the unlock of the keystore whose key is `key_id`; whether
    /// there was one.
    ///
    /// # Errors
    ///
    /// Why the keyring could not be asked.
    pub fn forget(key_id: &str) -> Result<bool, UnlockError> {
        #[cfg(target_os = "linux")]
        return kernel::forget(key_id);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = key_id;
            Ok(false)
        }
    }

    /// Drops every unlock kept for this user, whichever keystore it opens,
    /// and says how many there were. An unlock of a keystore whose
    /// `master.json` is gone or unreadable, or that is under another erpc
    /// home, has no key id left to be dropped by.
    ///
    /// `also` is the key id of an unlock to drop even where the kernel's
    /// list of keys cannot be read: the keystore the caller is at.
    ///
    /// # Errors
    ///
    /// Why the keyring could not be asked.
    pub fn forget_all(also: Option<&str>) -> Result<usize, UnlockError> {
        #[cfg(target_os = "linux")]
        return kernel::forget_all(also);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = also;
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;
    use std::path::{Path, PathBuf};

    use zeroize::Zeroizing;

    use super::{
        ENTRY_INFO, ITERATIONS, Keystore, KeystoreError, Kind, MAX_VALUE, MIN_PASSPHRASE_CHARS,
        Master, entry_aad, file_text, master_aad, seal, unhex_array, unlock, wrap,
    };

    const PASSPHRASE: &str = "correct horse battery";
    const SERVICE: &str = "erpc-worker";

    /// A keystore in a directory of its own, made with few iterations so
    /// the tests are quick.
    fn fresh() -> (tempfile::TempDir, Keystore) {
        let home = tempfile::tempdir().expect("a directory");
        let store = Keystore::with_iterations(
            home.path().join("keystore"),
            NonZeroU32::new(1_000).expect("not zero"),
        );
        (home, store)
    }

    /// Every file under `dir`.
    fn files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).expect("list").flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(files(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    /// `path` as JSON, changed by `change`, written back.
    fn edit(path: &Path, change: impl FnOnce(&mut serde_json::Value)) {
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("read")).expect("JSON");
        change(&mut value);
        std::fs::write(path, serde_json::to_vec_pretty(&value).expect("JSON")).expect("write");
    }

    /// A change to a keystore file read as JSON.
    type Change = Box<dyn FnOnce(&mut serde_json::Value)>;

    /// The hex string under `field`, its first digit changed.
    fn flip_hex(field: &'static str) -> impl FnOnce(&mut serde_json::Value) {
        move |value| {
            let text = value[field].as_str().expect("hex").to_owned();
            let first = if text.starts_with('0') { "1" } else { "0" };
            value[field] = format!("{first}{}", &text[1..]).into();
        }
    }

    #[test]
    fn a_new_keystore_is_made_with_the_shipped_iteration_count() {
        // The count is what stands between a stolen file and its
        // passphrase: pinned here, and in what the file says.
        assert_eq!(ITERATIONS, 600_000);
        let home = tempfile::tempdir().expect("a directory");
        let store = Keystore::at(home.path().join("keystore"));
        store.create(PASSPHRASE).expect("made");
        let file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(store.master_path()).expect("read"))
                .expect("JSON");
        assert_eq!(file["iterations"], 600_000);
        assert_eq!(file["kdf"], "pbkdf2-hmac-sha256");
        assert_eq!(file["cipher"], "chacha20-poly1305");
        assert_eq!(file["version"], 1);
        store.open(PASSPHRASE).expect("opens");
    }

    #[test]
    fn a_value_round_trips_and_a_missing_one_is_none() {
        let (_home, store) = fresh();
        assert_eq!(store.key_id().expect("no file is not an error"), None);
        assert_eq!(store.open(PASSPHRASE).err(), Some(KeystoreError::Missing));
        let master = store.create(PASSPHRASE).expect("made");
        assert_eq!(store.key_id().expect("reads"), Some(master.id()));
        assert!(!store.has(SERVICE, "bot.API_TOKEN").expect("named"));
        assert!(
            store
                .read(&master, SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .is_none()
        );
        store
            .write(
                &master,
                SERVICE,
                "bot.API_TOKEN",
                Kind::Secret,
                "s3cret-value",
            )
            .expect("kept");
        assert!(store.has(SERVICE, "bot.API_TOKEN").expect("named"));
        // Opened again from the passphrase, as another process would.
        let again = store.open(PASSPHRASE).expect("opens");
        assert_eq!(again.id(), master.id());
        let back = store
            .read(&again, SERVICE, "bot.API_TOKEN", Kind::Secret)
            .expect("reads")
            .expect("there");
        assert_eq!(back.as_str(), "s3cret-value");
        // Replaced in place, with a new salt and nonce.
        let path = store.entry_path(SERVICE, "bot.API_TOKEN").expect("named");
        let first = std::fs::read(&path).expect("read");
        store
            .write(
                &master,
                SERVICE,
                "bot.API_TOKEN",
                Kind::Secret,
                "s3cret-value",
            )
            .expect("kept");
        assert_ne!(std::fs::read(&path).expect("read"), first);
        assert!(store.delete(SERVICE, "bot.API_TOKEN").expect("removed"));
        assert!(
            !store
                .delete(SERVICE, "bot.API_TOKEN")
                .expect("gone already")
        );
        assert!(
            store
                .read(&master, SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .is_none()
        );
    }

    #[test]
    fn a_wrong_passphrase_is_refused() {
        let (_home, store) = fresh();
        store.create(PASSPHRASE).expect("made");
        for wrong in ["correct horse batterY", "", "correct horse battery "] {
            assert_eq!(
                store.open(wrong).err(),
                Some(KeystoreError::WrongPassphrase),
                "{wrong:?}"
            );
        }
    }

    #[test]
    fn a_short_passphrase_makes_no_keystore() {
        let (_home, store) = fresh();
        let short = "a".repeat(MIN_PASSPHRASE_CHARS - 1);
        assert_eq!(
            store.create(&short).err(),
            Some(KeystoreError::PassphraseTooShort)
        );
        assert!(!store.dir().exists(), "nothing was made");
        // Characters are counted, not bytes: eleven of three bytes each.
        assert_eq!(
            store.create(&"鍵".repeat(MIN_PASSPHRASE_CHARS - 1)).err(),
            Some(KeystoreError::PassphraseTooShort)
        );
        store
            .create(&"鍵".repeat(MIN_PASSPHRASE_CHARS))
            .expect("twelve characters");
    }

    #[test]
    fn a_second_keystore_is_not_made_over_the_first() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        store
            .write(&master, SERVICE, "bot.wallet", Kind::Key, "the key")
            .expect("kept");
        assert_eq!(
            store.create("another passphrase").err(),
            Some(KeystoreError::Exists)
        );
        // The first still opens, and still holds what it held.
        let again = store.open(PASSPHRASE).expect("opens");
        assert_eq!(
            store
                .read(&again, SERVICE, "bot.wallet", Kind::Key)
                .expect("reads")
                .expect("there")
                .as_str(),
            "the key"
        );
    }

    #[test]
    fn a_changed_master_file_is_refused() {
        let (_home, store) = fresh();
        store.create(PASSPHRASE).expect("made");
        let path = store.master_path();
        let good = std::fs::read(&path).expect("read");
        let cases: Vec<(&str, Change)> = vec![
            ("salt", Box::new(flip_hex("salt"))),
            ("nonce", Box::new(flip_hex("nonce"))),
            ("wrapped", Box::new(flip_hex("wrapped"))),
            ("key_id", Box::new(flip_hex("key_id"))),
            ("iterations", Box::new(|v| v["iterations"] = 1_001.into())),
            ("no iterations", Box::new(|v| v["iterations"] = 0.into())),
            (
                "too many iterations",
                Box::new(|v| v["iterations"] = u32::MAX.into()),
            ),
            ("version", Box::new(|v| v["version"] = 2.into())),
            ("kdf", Box::new(|v| v["kdf"] = "scrypt".into())),
            ("cipher", Box::new(|v| v["cipher"] = "aes-256-gcm".into())),
            (
                "format",
                Box::new(|v| v["format"] = "erpc-keystore-entry".into()),
            ),
            ("an added field", Box::new(|v| v["extra"] = 1.into())),
            ("a short salt", Box::new(|v| v["salt"] = "00".into())),
        ];
        for (what, change) in cases {
            std::fs::write(&path, &good).expect("restore");
            store.open(PASSPHRASE).expect("the unchanged file opens");
            edit(&path, change);
            assert!(store.open(PASSPHRASE).is_err(), "{what}");
        }
        // Changed parameters fail as a wrong passphrase does: they are part
        // of what the master key is sealed with.
        std::fs::write(&path, &good).expect("restore");
        edit(&path, |v| v["iterations"] = 1_001.into());
        assert_eq!(
            store.open(PASSPHRASE).err(),
            Some(KeystoreError::WrongPassphrase)
        );
        std::fs::write(&path, &good).expect("restore");
        edit(&path, |v| v["version"] = 2.into());
        assert!(matches!(
            store.open(PASSPHRASE),
            Err(KeystoreError::Unsupported { .. })
        ));
    }

    #[test]
    fn no_single_changed_byte_of_either_file_opens() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        store
            .write(
                &master,
                SERVICE,
                "bot.API_TOKEN",
                Kind::Secret,
                "s3cret-value",
            )
            .expect("kept");
        let path = store.master_path();
        let good = std::fs::read(&path).expect("read");
        for at in 0..good.len() {
            let mut bad = good.clone();
            bad[at] ^= 1;
            std::fs::write(&path, &bad).expect("write");
            assert!(store.open(PASSPHRASE).is_err(), "master.json byte {at}");
        }
        std::fs::write(&path, &good).expect("restore");
        let path = store.entry_path(SERVICE, "bot.API_TOKEN").expect("named");
        let good = std::fs::read(&path).expect("read");
        for at in 0..good.len() {
            let mut bad = good.clone();
            bad[at] ^= 1;
            std::fs::write(&path, &bad).expect("write");
            assert!(
                store
                    .read(&master, SERVICE, "bot.API_TOKEN", Kind::Secret)
                    .is_err(),
                "entry byte {at}"
            );
        }
    }

    #[test]
    fn a_changed_entry_is_refused() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        store
            .write(
                &master,
                SERVICE,
                "bot.API_TOKEN",
                Kind::Secret,
                "s3cret-value",
            )
            .expect("kept");
        let path = store.entry_path(SERVICE, "bot.API_TOKEN").expect("named");
        let good = std::fs::read(&path).expect("read");
        let read = || store.read(&master, SERVICE, "bot.API_TOKEN", Kind::Secret);
        let changed = KeystoreError::Changed {
            name: "erpc-worker/bot.API_TOKEN".to_owned(),
        };
        for field in ["salt", "nonce", "sealed"] {
            std::fs::write(&path, &good).expect("restore");
            edit(&path, flip_hex(field));
            assert_eq!(read().err(), Some(changed.clone()), "{field}");
        }
        std::fs::write(&path, &good).expect("restore");
        edit(&path, |v| v["name"] = "erpc-worker/bot.OTHER".into());
        assert_eq!(read().err(), Some(changed));
        std::fs::write(&path, &good).expect("restore");
        edit(&path, flip_hex("key_id"));
        assert!(matches!(read(), Err(KeystoreError::OtherMaster { .. })));
        std::fs::write(&path, &good).expect("restore");
        edit(&path, |v| v["version"] = 2.into());
        assert!(matches!(read(), Err(KeystoreError::Unsupported { .. })));
        std::fs::write(&path, &good).expect("restore");
        edit(&path, |v| v["sealed"] = "zz".into());
        assert!(matches!(read(), Err(KeystoreError::Unreadable { .. })));
        // Cut short, and not a keystore file at all.
        std::fs::write(&path, &good[..good.len() / 2]).expect("write");
        assert!(matches!(read(), Err(KeystoreError::Unreadable { .. })));
        std::fs::write(&path, b"s3cret-value").expect("write");
        assert!(matches!(read(), Err(KeystoreError::Unreadable { .. })));
        std::fs::write(&path, &good).expect("restore");
        assert_eq!(
            read().expect("reads").expect("there").as_str(),
            "s3cret-value"
        );
    }

    #[test]
    fn an_entry_opens_only_as_the_kind_it_was_written_as() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        store
            .write(&master, SERVICE, "bot.wallet", Kind::Key, "the key")
            .expect("kept");
        store
            .write(&master, SERVICE, "bot.API_TOKEN", Kind::Secret, "tok-1")
            .expect("kept");
        let other = |account: &str, kept| KeystoreError::OtherKind {
            name: format!("{SERVICE}/{account}"),
            kept,
        };
        let changed = |account: &str| KeystoreError::Changed {
            name: format!("{SERVICE}/{account}"),
        };
        // What each says it is, asked with no key.
        assert_eq!(store.kind(SERVICE, "bot.wallet"), Ok(Some(Kind::Key)));
        assert_eq!(store.kind(SERVICE, "bot.API_TOKEN"), Ok(Some(Kind::Secret)));
        assert_eq!(store.kind(SERVICE, "bot.OTHER"), Ok(None));
        // A key is not read as a secret, nor a secret as a key.
        assert_eq!(
            store
                .read(&master, SERVICE, "bot.wallet", Kind::Secret)
                .err(),
            Some(other("bot.wallet", Kind::Key))
        );
        assert_eq!(
            store
                .read(&master, SERVICE, "bot.API_TOKEN", Kind::Key)
                .err(),
            Some(other("bot.API_TOKEN", Kind::Secret))
        );
        for (account, written, rewritten, value) in [
            ("bot.wallet", Kind::Key, Kind::Secret, "the key"),
            ("bot.API_TOKEN", Kind::Secret, Kind::Key, "tok-1"),
        ] {
            // Each opens as what it is.
            assert_eq!(
                store
                    .read(&master, SERVICE, account, written)
                    .expect("reads")
                    .expect("there")
                    .as_str(),
                value
            );
            // The kind rewritten in the file: asked for as the new kind,
            // the file lets the read past and the seal refuses it; asked
            // for as the old one, the file no longer says so.
            let path = store.entry_path(SERVICE, account).expect("named");
            let good = std::fs::read(&path).expect("read");
            edit(&path, |v| v["kind"] = rewritten.as_str().into());
            assert_eq!(
                store.read(&master, SERVICE, account, rewritten).err(),
                Some(changed(account)),
                "{account} as {rewritten:?}"
            );
            assert_eq!(
                store.read(&master, SERVICE, account, written).err(),
                Some(other(account, rewritten)),
                "{account} as {written:?}"
            );
            // A kind this build does not know, and no kind at all.
            for kind in [Kind::Key, Kind::Secret] {
                std::fs::write(&path, &good).expect("restore");
                edit(&path, |v| v["kind"] = "wallet".into());
                assert!(matches!(
                    store.read(&master, SERVICE, account, kind),
                    Err(KeystoreError::Unsupported { .. })
                ));
                std::fs::write(&path, &good).expect("restore");
                edit(&path, |v| {
                    v.as_object_mut().expect("an object").remove("kind");
                });
                assert!(matches!(
                    store.read(&master, SERVICE, account, kind),
                    Err(KeystoreError::Unreadable { .. })
                ));
            }
            std::fs::write(&path, &good).expect("restore");
        }
        // What the refusal says.
        assert_eq!(
            other("bot.wallet", Kind::Key).to_string(),
            "erpc-worker/bot.wallet is kept as a trading key, and is not read as a secret"
        );
        assert_eq!(
            other("bot.API_TOKEN", Kind::Secret).to_string(),
            "erpc-worker/bot.API_TOKEN is kept as a secret, and is not read as a trading key"
        );
    }

    /// Whether the file system `dir` is on keeps two names apart that
    /// differ only in case: Linux's do, the defaults of macOS and Windows
    /// do not.
    fn keeps_case_apart(dir: &Path) -> bool {
        std::fs::write(dir.join("probe"), b"").expect("write");
        let apart = !dir.join("PROBE").exists();
        std::fs::remove_file(dir.join("probe")).expect("remove");
        apart
    }

    /// On every file system: where case is ignored, the second spelling
    /// names the first one's file, and where it is not, it would become a
    /// second file that such a file system cannot hold beside the first.
    #[test]
    fn another_spelling_of_a_name_is_not_written_removed_or_read() {
        let (home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        store
            .write(&master, SERVICE, "bot.wallet", Kind::Key, "the key")
            .expect("kept");
        let path = store.entry_path(SERVICE, "bot.wallet").expect("named");
        let before = std::fs::read(&path).expect("read");
        let refused = |result: Option<KeystoreError>, what: &str| {
            assert!(
                matches!(result, Some(KeystoreError::OtherSpelling { .. })),
                "{what}: {result:?}"
            );
        };
        let all_refused = |service: &str, account: &str| {
            let what = format!("{service}/{account}");
            for kind in [Kind::Key, Kind::Secret] {
                refused(
                    store.write(&master, service, account, kind, "x").err(),
                    &what,
                );
                refused(store.read(&master, service, account, kind).err(), &what);
            }
            refused(store.delete(service, account).err(), &what);
            refused(store.has(service, account).err(), &what);
            refused(store.kind(service, account).err(), &what);
        };
        // A setting named WALLET; the service spelled otherwise, with the
        // key's account and with one that is not there; and the `.` that
        // Windows drops from the end of a directory's name.
        for (service, account) in [
            (SERVICE, "bot.WALLET"),
            (SERVICE, "Bot.Wallet"),
            ("ERPC-WORKER", "bot.wallet"),
            ("Erpc-Worker", "bot.OTHER"),
            ("erpc-worker.", "bot.wallet"),
        ] {
            all_refused(service, account);
        }
        // The key's file is as it was, alone, and opens with what it held.
        assert_eq!(std::fs::read(&path).expect("read"), before);
        assert_eq!(
            files(&store.dir().join("entries")),
            std::slice::from_ref(&path)
        );
        assert_eq!(
            store
                .read(&master, SERVICE, "bot.wallet", Kind::Key)
                .expect("reads")
                .expect("there")
                .as_str(),
            "the key"
        );
        // The refusal names the spelling that is there.
        let said = store
            .delete(SERVICE, "bot.WALLET")
            .expect_err("refused")
            .to_string();
        assert!(said.starts_with("erpc-worker/bot.WALLET is in the keystore"));
        assert!(said.contains("bot.wallet.json"), "{said}");
        // A name with no other spelling is written and removed as ever.
        store
            .write(&master, SERVICE, "bot.WALLET_2", Kind::Secret, "x")
            .expect("kept");
        assert!(store.delete(SERVICE, "bot.WALLET_2").expect("removed"));
        // Two spellings side by side, which only a file system that tells
        // them apart can hold: neither is read, written or removed, since
        // carried to one that does not, one of them would be lost.
        if keeps_case_apart(home.path()) {
            let twin = path.with_file_name("bot.WALLET.json");
            std::fs::copy(&path, &twin).expect("copy");
            for account in ["bot.wallet", "bot.WALLET"] {
                all_refused(SERVICE, account);
            }
            assert_eq!(std::fs::read(&path).expect("read"), before);
            assert_eq!(std::fs::read(&twin).expect("read"), before);
        }
    }

    #[test]
    fn text_from_a_file_reaches_an_error_only_in_quotes_and_escaped() {
        type Run<'a> = &'a dyn Fn() -> Result<(), KeystoreError>;
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        store
            .write(&master, SERVICE, "bot.API_TOKEN", Kind::Secret, "tok-1")
            .expect("kept");
        // Clears the screen, rings the bell, and writes over the line.
        let hostile = "x\u{1b}[2J\u{7}\r\u{9b}31m\u{202e}\"";
        let escaped = r#""x\u{1b}[2J\u{7}\r\u{9b}31m\u{202e}\"""#;
        let entry = store.entry_path(SERVICE, "bot.API_TOKEN").expect("named");
        let read = || {
            store
                .read(&master, SERVICE, "bot.API_TOKEN", Kind::Secret)
                .map(|_| ())
        };
        let open = || store.open(PASSPHRASE).map(|_| ());
        let cases: [(&Path, &str, &str, Run); 5] = [
            (&store.master_path(), "kdf", "the derivation", &open),
            (&store.master_path(), "cipher", "the cipher", &open),
            (&entry, "kdf", "the derivation", &read),
            (&entry, "cipher", "the cipher", &read),
            (&entry, "kind", "the kind", &read),
        ];
        for (path, field, what, run) in cases {
            let good = std::fs::read(path).expect("read");
            edit(path, |v| v[field] = hostile.into());
            let said = run().expect_err("refused").to_string();
            assert!(
                said.contains(&format!("asks for {what} {escaped}, which")),
                "{field}: {said:?}"
            );
            assert!(
                said.chars().all(|c| c.is_ascii() && !c.is_ascii_control()),
                "{field}: {said:?}"
            );
            // A long one is cut.
            edit(path, |v| v[field] = "A".repeat(5_000).into());
            let said = run().expect_err("refused").to_string();
            assert!(
                said.contains(&format!("{what} \"{}\"..., which", "A".repeat(64))),
                "{field}: {said:?}"
            );
            std::fs::write(path, good).expect("restore");
            run().expect("the unchanged file opens");
        }
    }

    /// The passphrase of the known answers: not ASCII alone, so that its
    /// bytes are seen to be its UTF-8.
    const KAT_PASSPHRASE: &str = "correct horse battery staple, pinned (v1) é";
    /// `master.json` of the known answers.
    const MASTER_JSON: &str = r#"{
  "format": "erpc-keystore-master",
  "version": 1,
  "key_id": "630dcd2966c43366",
  "kdf": "pbkdf2-hmac-sha256",
  "iterations": 600000,
  "salt": "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
  "cipher": "chacha20-poly1305",
  "nonce": "c0c1c2c3c4c5c6c7c8c9cacb",
  "wrapped": "bb6613c0f47eb2f06b04a85cd4be89883059f1f4176caeee95f7b7f8c3a7b26358389ea709a40f51d2a385b2d5d668fa"
}
"#;
    /// The known answers' trading key, `entries/erpc-worker/bot.wallet.json`.
    const KEY_JSON: &str = r#"{
  "format": "erpc-keystore-entry",
  "version": 1,
  "key_id": "630dcd2966c43366",
  "name": "erpc-worker/bot.wallet",
  "kind": "key",
  "kdf": "hkdf-sha256",
  "salt": "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
  "cipher": "chacha20-poly1305",
  "nonce": "d0d1d2d3d4d5d6d7d8d9dadb",
  "sealed": "6d3b3b54afebe3d23326993bcd2b8e2197b5a286cac52d4c735c885549dd1b4704aa0a48d2cee4bd0d"
}
"#;
    /// The known answers' secret, `entries/erpc-worker/bot.API_TOKEN.json`.
    const SECRET_JSON: &str = r#"{
  "format": "erpc-keystore-entry",
  "version": 1,
  "key_id": "630dcd2966c43366",
  "name": "erpc-worker/bot.API_TOKEN",
  "kind": "secret",
  "kdf": "hkdf-sha256",
  "salt": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  "cipher": "chacha20-poly1305",
  "nonce": "606162636465666768696a6b",
  "sealed": "977aa49168985dd45c912d836f5f954ed3f4ed433cd8821708bbd53ff28cf7fa"
}
"#;
    /// The id of the known answers' master key.
    const KEY_ID: &str = "630dcd2966c43366";

    /// Format version 1, pinned: this passphrase, master key, salts and
    /// nonces give these files byte for byte, and these files open.
    ///
    /// The three files were made, and opened again, by a second
    /// implementation that knows only the format as the module states it:
    /// PBKDF2 from Python's `hashlib`, HKDF written out with its `hmac`,
    /// and ChaCha20-Poly1305 from its `cryptography` package.
    ///
    /// A change to the order of the associated data, to the HKDF info
    /// string, to the iteration count or to how the kind is marked fails
    /// here, rather than in a keystore somebody already has.
    #[test]
    fn format_version_1_is_pinned_by_known_answers() {
        let bytes = |hex: &str| unhex_array(hex).expect("32 bytes of hex");
        let master = Master(Zeroizing::new(bytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )));
        let master_salt = bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        let key_salt = bytes("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let secret_salt = bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        let master_nonce = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
        ];
        let key_nonce = [
            0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
        ];
        let secret_nonce = [
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        ];
        let iterations = NonZeroU32::new(ITERATIONS).expect("not zero");
        // What the seals cover, written out.
        assert_eq!(master.id(), KEY_ID);
        assert_eq!(ENTRY_INFO, b"erpc keystore v1 entry key");
        assert_eq!(
            master_aad(KEY_ID, ITERATIONS, &master_salt),
            format!(
                "erpc-keystore-master\n1\n{KEY_ID}\npbkdf2-hmac-sha256\n600000\n\
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\n\
                 chacha20-poly1305\n"
            )
        );
        assert_eq!(
            entry_aad(KEY_ID, "erpc-worker/bot.wallet", Kind::Key, &key_salt),
            format!(
                "erpc-keystore-entry\n1\n{KEY_ID}\nerpc-worker/bot.wallet\nkey\nhkdf-sha256\n\
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\n\
                 chacha20-poly1305\n"
            )
        );
        // What is written.
        let wrapped = wrap(
            &master,
            KAT_PASSPHRASE,
            iterations,
            &master_salt,
            master_nonce,
        )
        .expect("wrapped");
        assert_eq!(file_text(&wrapped).expect("JSON"), MASTER_JSON);
        let key = seal(
            &master,
            "erpc-worker/bot.wallet",
            Kind::Key,
            &key_salt,
            key_nonce,
            "[11,22,33,44,55,66,77,88]",
        )
        .expect("sealed");
        assert_eq!(file_text(&key).expect("JSON"), KEY_JSON);
        let secret = seal(
            &master,
            "erpc-worker/bot.API_TOKEN",
            Kind::Secret,
            &secret_salt,
            secret_nonce,
            "tok-7f3a9c1e5b2d",
        )
        .expect("sealed");
        assert_eq!(file_text(&secret).expect("JSON"), SECRET_JSON);
        // And what is written opens: the files as they are above, put
        // where a keystore has them.
        let home = tempfile::tempdir().expect("a directory");
        let store = Keystore::at(home.path().join("keystore"));
        let entries = store.dir().join("entries").join(SERVICE);
        std::fs::create_dir_all(&entries).expect("dir");
        std::fs::write(store.master_path(), MASTER_JSON).expect("write");
        std::fs::write(entries.join("bot.wallet.json"), KEY_JSON).expect("write");
        std::fs::write(entries.join("bot.API_TOKEN.json"), SECRET_JSON).expect("write");
        let opened = store.open(KAT_PASSPHRASE).expect("opens");
        assert_eq!(opened.id(), KEY_ID);
        assert_eq!(opened.0.as_slice(), master.0.as_slice());
        assert_eq!(
            store
                .read(&opened, SERVICE, "bot.wallet", Kind::Key)
                .expect("reads")
                .expect("there")
                .as_str(),
            "[11,22,33,44,55,66,77,88]"
        );
        assert_eq!(
            store
                .read(&opened, SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .expect("there")
                .as_str(),
            "tok-7f3a9c1e5b2d"
        );
    }

    /// A limit, stated in the module's words and held here so it is not
    /// forgotten: an older copy of the same entry, put back, opens.
    #[test]
    fn an_older_copy_of_the_same_entry_still_opens() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        let path = store.entry_path(SERVICE, "bot.API_TOKEN").expect("named");
        store
            .write(
                &master,
                SERVICE,
                "bot.API_TOKEN",
                Kind::Secret,
                "the older value",
            )
            .expect("kept");
        let older = std::fs::read(&path).expect("read");
        store
            .write(
                &master,
                SERVICE,
                "bot.API_TOKEN",
                Kind::Secret,
                "the newer value",
            )
            .expect("kept");
        std::fs::write(&path, older).expect("put back");
        assert_eq!(
            store
                .read(&master, SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .expect("there")
                .as_str(),
            "the older value"
        );
    }

    #[test]
    fn an_entry_copied_to_another_account_does_not_open() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        store
            .write(
                &master,
                SERVICE,
                "bot.API_TOKEN",
                Kind::Secret,
                "s3cret-value",
            )
            .expect("kept");
        store
            .write(&master, SERVICE, "other.API_TOKEN", Kind::Secret, "another")
            .expect("kept");
        let from = store.entry_path(SERVICE, "bot.API_TOKEN").expect("named");
        // Over another account's file, and to a name that had none.
        for to in ["other.API_TOKEN", "bot.wallet"] {
            let path = store.entry_path(SERVICE, to).expect("named");
            std::fs::copy(&from, &path).expect("copy");
            assert_eq!(
                store.read(&master, SERVICE, to, Kind::Secret).err(),
                Some(KeystoreError::Changed {
                    name: format!("{SERVICE}/{to}")
                }),
                "{to}"
            );
            // With the name inside rewritten to match, it is the seal that
            // refuses it.
            edit(&path, |v| v["name"] = format!("{SERVICE}/{to}").into());
            assert_eq!(
                store.read(&master, SERVICE, to, Kind::Secret).err(),
                Some(KeystoreError::Changed {
                    name: format!("{SERVICE}/{to}")
                }),
                "{to}, renamed inside"
            );
        }
        // And under another service.
        let path = store
            .entry_path("other-service", "bot.API_TOKEN")
            .expect("named");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::copy(&from, &path).expect("copy");
        edit(&path, |v| v["name"] = "other-service/bot.API_TOKEN".into());
        assert!(matches!(
            store.read(&master, "other-service", "bot.API_TOKEN", Kind::Secret),
            Err(KeystoreError::Changed { .. })
        ));
    }

    #[test]
    fn an_entry_sealed_under_another_master_does_not_open() {
        let (_home, ours) = fresh();
        let (_other_home, theirs) = fresh();
        let our_master = ours.create(PASSPHRASE).expect("made");
        let their_master = theirs.create(PASSPHRASE).expect("made");
        assert_ne!(our_master.id(), their_master.id());
        theirs
            .write(&their_master, SERVICE, "bot.wallet", Kind::Key, "their key")
            .expect("kept");
        let path = ours.entry_path(SERVICE, "bot.wallet").expect("named");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::copy(
            theirs.entry_path(SERVICE, "bot.wallet").expect("named"),
            &path,
        )
        .expect("copy");
        let other = KeystoreError::OtherMaster {
            name: "erpc-worker/bot.wallet".to_owned(),
        };
        assert_eq!(
            ours.read(&our_master, SERVICE, "bot.wallet", Kind::Key)
                .err(),
            Some(other.clone())
        );
        // Passed off as ours by its key id, the seal still refuses it.
        edit(&path, |v| v["key_id"] = our_master.id().into());
        assert!(matches!(
            ours.read(&our_master, SERVICE, "bot.wallet", Kind::Key),
            Err(KeystoreError::Changed { .. })
        ));
        // And nothing is sealed here under a master this keystore does not
        // hold.
        assert_eq!(
            ours.write(&their_master, SERVICE, "bot.wallet", Kind::Key, "x")
                .err(),
            Some(other)
        );
    }

    #[test]
    fn nothing_kept_is_on_the_disk_in_the_clear() {
        let (home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        let setting = "a setting's value, kept sealed";
        let key = "[11,22,33,44,55,66,77,88,99,111,122,133]";
        store
            .write(&master, SERVICE, "bot.API_TOKEN", Kind::Secret, setting)
            .expect("kept");
        store
            .write(&master, SERVICE, "bot.wallet", Kind::Key, key)
            .expect("kept");
        let all = files(home.path());
        assert_eq!(all.len(), 4, "{all:?}");
        let hex = |s: &str| super::hex(s.as_bytes());
        for path in all {
            let bytes = std::fs::read(&path).expect("read");
            let text = String::from_utf8_lossy(&bytes).to_lowercase();
            for secret in [setting, key, PASSPHRASE] {
                assert!(!text.contains(secret), "{} holds {secret}", path.display());
                assert!(
                    !text.contains(&hex(secret)),
                    "{} holds {secret} in hex",
                    path.display()
                );
            }
            assert!(
                !text.contains(&super::hex(master.0.as_slice())),
                "{} holds the master key",
                path.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn files_are_the_owners_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let (home, store) = fresh();
        // A keystore directory that was there already, and open to all.
        std::fs::create_dir_all(store.dir()).expect("dir");
        std::fs::set_permissions(store.dir(), std::fs::Permissions::from_mode(0o777))
            .expect("chmod");
        let master = store.create(PASSPHRASE).expect("made");
        store
            .write(&master, SERVICE, "bot.wallet", Kind::Key, "the key")
            .expect("kept");
        let mode = |path: &Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777
        };
        let entry = store.entry_path(SERVICE, "bot.wallet").expect("named");
        for dir in [
            store.dir(),
            &store.dir().join("entries"),
            entry.parent().expect("parent"),
        ] {
            assert_eq!(mode(dir), 0o700, "{}", dir.display());
        }
        for file in files(home.path()) {
            assert_eq!(mode(&file), 0o600, "{}", file.display());
        }
        // No half-written file is left beside the whole ones.
        assert!(
            files(home.path())
                .iter()
                .all(|p| p.extension().is_none_or(|e| e != "tmp"))
        );
    }

    #[test]
    fn a_name_that_is_not_a_plain_file_name_is_refused() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        for (service, account) in [
            ("..", "x"),
            ("erpc-worker", ".."),
            ("erpc-worker", "."),
            ("erpc-worker", ".hidden"),
            ("erpc-worker", "a/b"),
            ("erpc-worker", ""),
            ("", "x"),
            ("erpc-worker", "a b"),
            ("erpc-worker", "a\\b"),
        ] {
            assert_eq!(
                store
                    .write(&master, service, account, Kind::Secret, "x")
                    .err(),
                Some(KeystoreError::BadName),
                "{service}/{account}"
            );
            assert_eq!(
                store.has(service, account).err(),
                Some(KeystoreError::BadName)
            );
            assert_eq!(
                store.delete(service, account).err(),
                Some(KeystoreError::BadName)
            );
        }
        assert_eq!(
            store
                .write(
                    &master,
                    SERVICE,
                    "bot.BIG",
                    Kind::Secret,
                    &"x".repeat(MAX_VALUE + 1)
                )
                .err(),
            Some(KeystoreError::TooLong)
        );
        store
            .write(
                &master,
                SERVICE,
                "bot.BIG",
                Kind::Secret,
                &"x".repeat(MAX_VALUE),
            )
            .expect("the longest value");
        assert_eq!(
            store
                .read(&master, SERVICE, "bot.BIG", Kind::Secret)
                .expect("reads")
                .expect("there")
                .len(),
            MAX_VALUE
        );
    }

    #[test]
    fn an_error_names_no_secret() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        store
            .write(
                &master,
                SERVICE,
                "bot.API_TOKEN",
                Kind::Secret,
                "s3cret-value",
            )
            .expect("kept");
        let path = store.entry_path(SERVICE, "bot.API_TOKEN").expect("named");
        edit(&path, flip_hex("sealed"));
        let said = [
            store.open("s3cret-wrong-passphrase").expect_err("refused"),
            store
                .read(&master, SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect_err("refused"),
        ]
        .map(|e| format!("{e} {e:?}"))
        .join(" ");
        assert!(!said.contains("s3cret"), "{said}");
        assert!(!format!("{master:?}").contains(&super::hex(master.0.as_slice())));
    }

    #[test]
    fn an_unlock_is_named_for_the_key_it_opens() {
        assert_eq!(
            unlock::description("0123456789abcdef"),
            "erpc-keystore:master:0123456789abcdef"
        );
    }

    #[test]
    fn the_unlocks_in_the_kernels_list_of_keys_are_found_by_their_description() {
        // `/proc/keys`: a keyring, an unlock with two days left, the
        // session of `erpc login`, a second unlock, the first again, and
        // five that are not unlocks: an id in capitals, one too long, one
        // too short, a description that only ends like one, and one with
        // nothing after it that is no id.
        let text = "\
0a2f7ad5 I--Q---     1 perm 1f3f0000  1000 65534 keyring   _uid.1000: empty
1d2ed9c6 I--Q---     2   2d 3f010000  1000  1000 user      erpc-keystore:master:fedcba9876543210: 32
2b3c4d5e I--Q---     1 perm 3f010000  1000  1000 user      erpc:erpc-login.alice: 420
3c4d5e6f I--Q---     1 perm 3f010000  1000  1000 user      erpc-keystore:master:0123456789abcdef: 32
4d5e6f70 I------     1 perm 3f010000  1000  1000 user      erpc-keystore:master:fedcba9876543210
5e6f7081 I--Q---     1 perm 3f010000  1000  1000 user      erpc-keystore:master:0123456789ABCDEF: 32
6f708192 I--Q---     1 perm 3f010000  1000  1000 user      erpc-keystore:master:0123456789abcdef0: 32
70819203 I--Q---     1 perm 3f010000  1000  1000 user      erpc-keystore:master:short: 32
81920314 I--Q---     1 perm 3f010000  1000  1000 user      my-erpc-keystore:master:00000000000000aa: 32
92031425 I--Q---     1 perm 3f010000  1000  1000 user      erpc-keystore:master:
";
        assert_eq!(
            unlock::listed(text),
            ["0123456789abcdef", "fedcba9876543210"]
        );
        assert!(unlock::listed("").is_empty());
        // Each is dropped by the description it is kept under.
        assert!(text.contains(&unlock::description("0123456789abcdef")));
    }

    /// Where there is no kernel keyring, nothing is kept and nothing is
    /// there to drop. (On Linux the keyring is this machine's own, and is
    /// left to the test below.)
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_system_without_a_kernel_keyring_keeps_no_unlock() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        assert!(!unlock::SUPPORTED);
        assert_eq!(unlock::keep(&master), Err(unlock::UnlockError::Unsupported));
        assert!(unlock::kept(&master.id()).is_none());
        assert_eq!(unlock::forget(&master.id()), Ok(false));
        assert_eq!(unlock::forget_all(Some(&master.id())), Ok(0));
        assert_eq!(unlock::idle_expiry_secs(), None);
    }

    /// The unlock kept, read back and dropped, in this machine's kernel
    /// keyring: `keyctl session - sh -c 'keyctl link @u @s; cargo test -p
    /// erpc-auth -- --ignored kernel'` where the shell holds no keyring.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "touches this machine's kernel keyring"]
    fn an_unlock_round_trips_through_the_kernel_keyring() {
        let (_home, store) = fresh();
        let master = store.create(PASSPHRASE).expect("made");
        let id = master.id();
        assert!(unlock::kept(&id).is_none());
        unlock::keep(&master).expect("kept");
        let back = unlock::kept(&id).expect("there");
        assert_eq!(back.id(), id);
        store
            .write(
                &back,
                SERVICE,
                "bot.API_TOKEN",
                Kind::Secret,
                "s3cret-value",
            )
            .expect("the kept key seals");
        assert!(unlock::idle_expiry_secs().is_some());
        assert_eq!(unlock::forget(&id), Ok(true));
        assert!(unlock::kept(&id).is_none());
        assert_eq!(unlock::forget(&id), Ok(false));
    }

    /// Every unlock dropped at once, in a kernel keyring. It drops each
    /// erpc keystore unlock of the user it runs as, so it is for a keyring
    /// that is nobody's, a user namespace of its own: `unshare -U -r
    /// keyctl session - sh -c 'keyctl link @u @s; cargo test -p erpc-auth
    /// -- --ignored every_unlock'`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "drops every erpc keystore unlock in this user's kernel keyring"]
    fn every_unlock_of_this_user_is_dropped_at_once() {
        let (_home, ours) = fresh();
        let (_other_home, theirs) = fresh();
        let (_third_home, third) = fresh();
        let masters = [&ours, &theirs, &third].map(|store| store.create(PASSPHRASE).expect("made"));
        for master in &masters {
            unlock::keep(master).expect("kept");
            assert!(unlock::kept(&master.id()).is_some());
        }
        // Dropped by what the kernel lists, with no key id given: as for a
        // keystore whose `master.json` is gone.
        let dropped = unlock::forget_all(None).expect("dropped");
        assert!(dropped >= 3, "{dropped}");
        for master in &masters {
            assert!(unlock::kept(&master.id()).is_none());
        }
        assert_eq!(unlock::forget_all(Some(&masters[0].id())), Ok(0));
        // One the caller names is dropped among the others, once.
        unlock::keep(&masters[1]).expect("kept");
        assert_eq!(unlock::forget_all(Some(&masters[1].id())), Ok(1));
        assert!(unlock::kept(&masters[1].id()).is_none());
    }
}
