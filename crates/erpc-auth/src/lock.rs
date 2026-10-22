// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The exclusive lock a refresh runs under, and the file a rotated session
//! is parked in when the store will not take it.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use fs2::FileExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

use crate::credential::Credential;
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

/// The format version of a parked file.
///
/// Its own number, not the store's: the parked record and the stored one
/// are different shapes, and the parked one changed when it started
/// naming the session it replaced. Reusing the store's version would let
/// a build that ignores unknown fields read a new record as an old one and
/// file it away unconditionally, which is exactly what the new field is
/// there to stop.
pub const PARKED_VERSION: u32 = 2;

/// A parked session as it sits in the file.
///
/// Not a [`crate::credential::StoredCredential`]: a parked session is only
/// newer than the store while the store still holds the session it
/// replaced, so the record has to say which one that was. Without that the
/// file was unconditional authority, and a leftover that a sign-in had
/// already revoked but could not unlink was written back over that sign-in
/// by the next command.
#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct ParkedRecord {
    store_version: u32,
    access_token: String,
    refresh_token: String,
    #[zeroize(skip)]
    expires_at: i64,
    /// [`fingerprint`] of the refresh token the rotation replaced.
    #[zeroize(skip)]
    replaces: String,
}

/// A session read back from the parked file.
pub struct Parked {
    /// The session the rotation produced.
    pub credential: Credential,
    replaces: String,
}

impl Parked {
    /// Whether this should be filed over `held`, what the store has now.
    ///
    /// Only when `held` is exactly the session the rotation replaced. Any
    /// other value means something has written the store since -- a
    /// sign-in, which revoked this parked token, or a different store
    /// altogether, whose session this is not -- and putting the parked
    /// one back would overwrite a newer session with an older or a foreign
    /// one. An empty store is not the replaced session either: the stores
    /// replace a session atomically, so a failed save leaves the old one
    /// in place, and an empty store means it was signed out of.
    #[must_use]
    pub fn supersedes(&self, held: Option<&Credential>) -> bool {
        held.is_some_and(|h| fingerprint(&h.refresh_token) == self.replaces)
    }

    /// Whether the store already holds this very session.
    ///
    /// A store write that reported failure but was applied leaves the same
    /// live token in the store and in this file. Nothing needs filing, but
    /// the cleartext copy should not wait for the next sign-in to go.
    #[must_use]
    pub fn is_held_in(&self, held: Option<&Credential>) -> bool {
        held.is_some_and(|h| {
            fingerprint(&h.refresh_token) == fingerprint(&self.credential.refresh_token)
        })
    }
}

/// Names a refresh token without writing it down.
///
/// SHA-256, hex. The token is a long random value, so the digest cannot be
/// turned back into it, and the file holds no token beyond the one it was
/// always going to hold.
fn fingerprint(token: &SecretString) -> String {
    Sha256::digest(token.expose_secret().as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use core::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Writes a rotated session to a file so it is not lost.
///
/// Only called when the issuer has already rotated and the store has
/// refused the result: at that point the old refresh token is spent and
/// this is the only copy of the new one. Written 0600, and replaced
/// atomically so a concurrent reader sees one version or the other.
///
/// `replaces` is the session the store still holds, which the rotation
/// spent. It is recorded by its SHA-256 only, so that a later reader
/// can tell whether the store has moved on.
///
/// # Errors
///
/// Returns [`StoreError::Backend`] when the file cannot be written.
pub fn park_credential(
    path: &Path,
    cred: &Credential,
    replaces: &Credential,
) -> Result<(), StoreError> {
    let stored = ParkedRecord {
        store_version: PARKED_VERSION,
        access_token: cred.access_token.expose_secret().to_owned(),
        refresh_token: cred.refresh_token.expose_secret().to_owned(),
        expires_at: cred.expires_at,
        replaces: fingerprint(&replaces.refresh_token),
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
/// Returns `Ok(None)` when there is nothing parked. Whether what is parked
/// should be filed away is [`Parked::supersedes`]'s question, not this
/// function's.
///
/// # Errors
///
/// Returns [`StoreError`] when the file exists but cannot be read, or is
/// in a format this build does not know -- including a parked file written
/// before records said what they replace, which cannot be told apart from
/// a stale leftover and so is not trusted.
pub fn read_parked(path: &Path) -> Result<Option<Parked>, StoreError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(backend("read the parked session", &e)),
    };
    let stored: ParkedRecord =
        toml::from_str(&text).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    if stored.store_version != PARKED_VERSION {
        return Err(StoreError::UnknownVersion {
            found: stored.store_version,
            expected: PARKED_VERSION,
        });
    }
    Ok(Some(Parked {
        credential: Credential {
            access_token: SecretString::from(stored.access_token.clone()),
            refresh_token: SecretString::from(stored.refresh_token.clone()),
            expires_at: stored.expires_at,
        },
        replaces: stored.replaces.clone(),
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

    fn spent() -> Credential {
        Credential {
            access_token: SecretString::from("old.access.s"),
            refresh_token: SecretString::from("old.refresh.s"),
            expires_at: 1_600_000_000,
        }
    }

    #[test]
    fn a_parked_session_supersedes_only_the_session_it_replaced() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("pending-credentials.auth-api");
        park_credential(&path, &cred(), &spent()).expect("parked");
        let parked = read_parked(&path).expect("read").expect("present");

        assert!(
            parked.supersedes(Some(&spent())),
            "the store still holds what it replaced"
        );
        // A sign-in since, or another store's session: either way not this
        // rotation's predecessor, and overwriting it would lose a newer one.
        assert!(!parked.supersedes(Some(&cred())));
        assert!(!parked.supersedes(None), "an empty store was signed out of");
    }

    #[test]
    fn the_replaced_token_is_not_written_down() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("pending-credentials.auth-api");
        park_credential(&path, &cred(), &spent()).expect("parked");
        let text = std::fs::read_to_string(&path).expect("read the file");
        assert!(!text.contains("old.refresh.s"), "{text}");
        assert!(!text.contains("old.access.s"), "{text}");
    }

    #[test]
    fn a_parked_file_that_does_not_say_what_it_replaced_is_not_trusted() {
        // The format before this one, which shared the store's version
        // number. It cannot be told apart from a stale leftover, so
        // reading it is an error and nothing files it away.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("pending-credentials.auth-api");
        std::fs::write(
            &path,
            "store_version = 1\naccess_token = \"a\"\nrefresh_token = \"b\"\nexpires_at = 1\n",
        )
        .expect("write the fixture");
        assert!(read_parked(&path).is_err());
    }

    #[test]
    fn a_parked_file_is_versioned_apart_from_the_store() {
        // An earlier build reads `store_version` and compares it with the
        // store's own number. A new record carrying that number would be
        // read as an old one; carrying its own, it is refused.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("pending-credentials.auth-api");
        park_credential(&path, &cred(), &spent()).expect("parked");
        let text = std::fs::read_to_string(&path).expect("read the file");
        assert!(
            text.contains(&format!("store_version = {}", super::PARKED_VERSION)),
            "{text}"
        );
        assert_ne!(super::PARKED_VERSION, crate::credential::STORE_VERSION);
    }

    #[test]
    fn a_parked_session_knows_when_the_store_already_holds_it() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("pending-credentials.auth-api");
        park_credential(&path, &cred(), &spent()).expect("parked");
        let parked = read_parked(&path).expect("read").expect("present");
        assert!(parked.is_held_in(Some(&cred())));
        assert!(!parked.is_held_in(Some(&spent())));
        assert!(!parked.is_held_in(None));
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
        park_credential(&path, &cred(), &spent()).expect("parked");

        let taken = read_parked(&path).expect("read").expect("present");
        assert_eq!(taken.credential.access_token.expose_secret(), "a.b.c");
        assert_eq!(taken.credential.expires_at, 1_700_000_000);
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
        park_credential(&path, &cred(), &spent()).expect("parked");
        let mode = std::fs::metadata(&path)
            .expect("exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
    }
}
