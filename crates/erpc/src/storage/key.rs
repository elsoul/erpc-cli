// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Where the storage encryption key is kept: in the store `erpc login`
//! chose.
//!
//! - 1Password: an item tagged `erpc-storage-key` in the login vault, looked
//!   for there only. It is found again by its tag, on this machine or
//!   another, so every machine signed in to the same vault uses the same key.
//! - The macOS keychain: a generic password, service `erpc-storage-key`.
//! - The file store: `storage-key` beside the config, mode 0600.
//!
//! The key is never kept where it would not last. The Linux keyring erpc
//! uses is the kernel's, gone after a reboot, so there the key goes to
//! 1Password or a file instead. Losing the key loses every file encrypted
//! with it, which is why `erpc storage key export` exists.

use erpc_auth::store::StoreKind;

use crate::account_secret::Slot;
use crate::storage_crypt::MasterKey;

/// Where the key is kept.
pub const SLOT: Slot = Slot {
    tag: "erpc-storage-key",
    title: "ERPC storage encryption key",
    note: "erpc storage encrypts files with this key. Without it they cannot be read.",
    service: "erpc-storage-key",
    file: "storage-key",
    what: "the storage key",
    instead: ", or use --no-encrypt",
};

/// Where the key is, said for a person.
#[must_use]
pub fn place(kind: StoreKind) -> String {
    SLOT.place(kind)
}

/// The key, if one is kept, and the store it is kept in.
///
/// # Errors
///
/// When the store cannot be read, or holds something that is not a key.
pub fn load() -> Result<(Option<MasterKey>, StoreKind), String> {
    let (hex, kind) = SLOT.read()?;
    let key = hex.map(|h| MasterKey::from_hex(&h)).transpose()?;
    Ok((key, kind))
}

/// The key, made and kept if there is none yet. `made` says whether it was
/// made now, so the caller can tell the person to back it up.
///
/// # Errors
///
/// When the store cannot be read or written.
pub fn load_or_create() -> Result<(MasterKey, StoreKind, bool), String> {
    if let (Some(key), kind) = load()? {
        return Ok((key, kind, false));
    }
    let key = MasterKey::generate()?;
    let kind = SLOT.write(&key.to_hex())?;
    Ok((key, kind, true))
}

/// Keeps `key`, refusing to replace a different one: files encrypted with
/// that one would become unreadable.
///
/// # Errors
///
/// When a different key is kept already, or the store cannot be written.
pub fn import(key: &MasterKey) -> Result<StoreKind, String> {
    match load()? {
        (Some(existing), kind) if existing.id() == key.id() => Ok(kind),
        (Some(existing), _) => Err(format!(
            "a different storage key ({}) is kept already; files encrypted with it would become \
             unreadable, so erpc does not replace it",
            existing.id_hex()
        )),
        (None, _) => SLOT.write(&key.to_hex()),
    }
}
