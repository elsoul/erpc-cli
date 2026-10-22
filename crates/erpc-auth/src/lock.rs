// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The exclusive lock a refresh runs under, and the file a rotated session
//! is parked in when the store will not take it.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use fs2::FileExt as _;
use secrecy::ExposeSecret as _;

use crate::credential::{Credential, STORE_VERSION, StoredCredential};
use crate::store::{StoreError, StoreKind};

/// The permission bits on anything this module creates.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// An exclusive lock held for as long as the value lives.
///
/// Dropping it releases the lock; the file itself is left in place,
/// because removing it would let a second process create a fresh one and
/// take a lock that excludes nobody.
#[derive(Debug)]
pub struct ExclusiveLock {
    _file: File,
}

impl ExclusiveLock {
    /// Takes the lock at `path`, creating the file and its directory.
    ///
    /// Blocks until the lock is available.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] when the file cannot be created or
    /// the lock cannot be taken.
    pub fn acquire(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| backend("create the lock directory", &e))?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(FILE_MODE);
        }
        let file = options
            .open(path)
            .map_err(|e| backend("open the lock file", &e))?;
        file.lock_exclusive()
            .map_err(|e| backend("take the lock", &e))?;
        Ok(Self { _file: file })
    }
}

/// Writes a rotated session to a file so it is not lost.
///
/// Only called when the issuer has already rotated and the store has
/// refused the result: at that point the old refresh token is spent and
/// this is the only copy of the new one. Written 0600, and replaced
/// atomically so a concurrent reader sees one version or the other.
///
/// # Errors
///
/// Returns [`StoreError::Backend`] when the file cannot be written.
pub fn park_credential(path: &Path, cred: &Credential) -> Result<(), StoreError> {
    let stored = StoredCredential {
        store_version: STORE_VERSION,
        access_token: cred.access_token.expose_secret().to_owned(),
        refresh_token: cred.refresh_token.expose_secret().to_owned(),
        expires_at: cred.expires_at,
    };
    let text = toml::to_string_pretty(&stored).map_err(|e| backend("serialise the session", &e))?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| backend("create the state directory", &e))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".pending-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|e| backend("create a temporary file", &e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(FILE_MODE))
            .map_err(|e| backend("set permissions", &e))?;
    }
    tmp.as_file_mut()
        .write_all(text.as_bytes())
        .map_err(|e| backend("write the parked session", &e))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| backend("flush the parked session", &e))?;
    tmp.persist(path)
        .map_err(|e| backend("place the parked session", &e.error))?;
    Ok(())
}

/// Reads a parked session, leaving the file in place.
///
/// Reading and removing are separate on purpose. The file exists because
/// a store write failed, and the store may still be failing when it is
/// read: deleting first and then failing to save destroys the only copy
/// of a token whose predecessor is already spent, which is the loss this
/// whole mechanism exists to prevent. The caller clears it with
/// [`clear_parked`] once the session is somewhere durable.
///
/// Returns `Ok(None)` when there is nothing parked.
///
/// # Errors
///
/// Returns [`StoreError`] when the file exists but cannot be read, or is
/// in a format this build does not know.
pub fn read_parked(path: &Path) -> Result<Option<Credential>, StoreError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(backend("read the parked session", &e)),
    };
    let stored: StoredCredential =
        toml::from_str(&text).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    if stored.store_version != STORE_VERSION {
        return Err(StoreError::UnknownVersion {
            found: stored.store_version,
            expected: STORE_VERSION,
        });
    }
    Ok(Some(Credential {
        access_token: secrecy::SecretString::from(stored.access_token.clone()),
        refresh_token: secrecy::SecretString::from(stored.refresh_token.clone()),
        expires_at: stored.expires_at,
    }))
}

/// Removes a parked session.
///
/// Called once the session it held is durable somewhere else, or once it
/// has been revoked. Removing a file that is not there succeeds, so a
/// caller need not check first.
///
/// # Errors
///
/// Returns [`StoreError`] when the file exists and cannot be removed.
pub fn clear_parked(path: &Path) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(backend("remove the parked session", &e)),
    }
}

fn backend(operation: &'static str, error: &dyn core::fmt::Display) -> StoreError {
    StoreError::Backend {
        kind: StoreKind::File,
        operation,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{ExclusiveLock, clear_parked, park_credential, read_parked};
    use crate::credential::Credential;
    use crate::store::StoreError;
    use secrecy::{ExposeSecret as _, SecretString};

    fn cred() -> Credential {
        Credential {
            access_token: SecretString::from("a.b.c"),
            refresh_token: SecretString::from("d.e.f"),
            expires_at: 1_700_000_000,
        }
    }

    #[test]
    fn a_lock_can_be_taken_and_released() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("locks").join("auth-api.lock");
        {
            let _guard = ExclusiveLock::acquire(&path).expect("the lock is taken");
            assert!(path.exists(), "the lock file is created with its directory");
        }
        // Released on drop, so the next acquire succeeds.
        let _again = ExclusiveLock::acquire(&path).expect("the lock is free again");
    }

    #[test]
    fn a_parked_session_round_trips_and_reading_does_not_remove_it() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("pending-credentials.auth-api");
        park_credential(&path, &cred()).expect("parked");

        let taken = read_parked(&path).expect("read").expect("present");
        assert_eq!(taken.access_token.expose_secret(), "a.b.c");
        assert_eq!(taken.expires_at, 1_700_000_000);
        assert!(
            path.exists(),
            "reading must not remove it: the caller may still fail to store it, and this \
             is the only copy"
        );

        clear_parked(&path).expect("cleared");
        assert!(!path.exists());
        clear_parked(&path).expect("clearing nothing is fine");
    }

    #[test]
    fn nothing_parked_is_not_an_error() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        assert!(
            read_parked(&dir.path().join("pending-credentials.auth-api"))
                .expect("reading nothing succeeds")
                .is_none()
        );
    }

    #[test]
    fn an_unreadable_parked_file_stays_where_it_is() {
        // It is still a secret on disk, so it must keep showing up in
        // diagnostics rather than disappearing on the next run.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("pending-credentials.auth-api");
        std::fs::write(&path, "not toml {{{").expect("write the fixture");
        assert!(matches!(read_parked(&path), Err(StoreError::Corrupt(_))));
        assert!(
            path.exists(),
            "a file that could not be read is not deleted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_parked_session_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("pending-credentials.auth-api");
        park_credential(&path, &cred()).expect("parked");
        let mode = std::fs::metadata(&path)
            .expect("exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
    }
}
