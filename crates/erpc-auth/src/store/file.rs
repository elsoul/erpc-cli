// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The last-resort store: a file under the erpc state directory.
//!
//! This is the one store that writes a session to the local disk, and it is
//! therefore a stated exception to "nothing is left on the machine" rather
//! than a normal option. (The other exception is not a store: a rotation
//! the store refused, parked by [`crate::lock`].) It exists for minimal
//! Linux installs with neither `op` nor a Secret Service. It is used when
//! asked for, or when neither of those is available; `erpc login` warns
//! when it is, and `erpc doctor` reports that it is in use.
//!
//! The file is created 0600, written to a temporary file in the same
//! directory and renamed over the target, under an exclusive `flock` held
//! for the whole read-modify-write. The rename is what makes a replacement
//! atomic for a reader; the lock is what keeps two refreshes from racing.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use fs2::FileExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use super::{CredentialStore, StoreError, StoreKind};
use crate::credential::{CredKey, Credential, STORE_VERSION, StoredCredential};

/// The permission bits the credentials file must have.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// The on-disk document: one table per `<audience>:<account>` key.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Document {
    #[serde(default)]
    sessions: BTreeMap<String, StoredCredential>,
}

/// A session store backed by one TOML file.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// Uses the given file.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file this store reads and writes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The sidecar file the exclusive lock is taken on.
    ///
    /// Separate from the credentials file on purpose. The replacement is a
    /// rename over the target, and Windows refuses to rename over a file
    /// that anyone still has open -- including this process. Locking a
    /// sidecar keeps the mutual exclusion while leaving the target closed.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        self.path.with_file_name(name)
    }

    /// Takes the exclusive lock for a read-modify-write.
    ///
    /// The returned handle must be held for the whole sequence: dropping
    /// it releases the lock.
    fn lock(&self) -> Result<File, StoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Self::backend("create the state directory", &e))?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(FILE_MODE);
        }
        let file = options
            .open(self.lock_path())
            .map_err(|e| Self::backend("open the lock file", &e))?;
        file.lock_exclusive()
            .map_err(|e| Self::backend("take the lock", &e))?;
        Ok(file)
    }

    /// Reads the document. The caller must already hold the lock.
    ///
    /// Opens and closes the file, so that nothing holds a handle on it
    /// when the replacement renames over it.
    fn read_document(&self) -> Result<Document, StoreError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Document::default()),
            Err(e) => return Err(Self::backend("read the credentials file", &e)),
        };
        if text.trim().is_empty() {
            return Ok(Document::default());
        }
        toml::from_str(&text).map_err(|e| super::unparsable_toml("the credentials file", &text, &e))
    }

    /// Writes the document beside the target and renames it over.
    fn write_document(&self, doc: &Document) -> Result<(), StoreError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let text = toml::to_string_pretty(doc)
            .map_err(|e| Self::backend("serialise the credentials file", &e))?;

        let mut tmp = tempfile::Builder::new()
            .prefix(".credentials-")
            .suffix(".tmp")
            .tempfile_in(parent)
            .map_err(|e| Self::backend("create a temporary file", &e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // Set the mode before the content, so the secret is never
            // readable by anyone else even for an instant.
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(FILE_MODE))
                .map_err(|e| Self::backend("set permissions on the temporary file", &e))?;
        }
        tmp.as_file_mut()
            .write_all(text.as_bytes())
            .map_err(|e| Self::backend("write the temporary file", &e))?;
        tmp.as_file_mut()
            .sync_all()
            .map_err(|e| Self::backend("flush the temporary file", &e))?;
        tmp.persist(&self.path)
            .map_err(|e| Self::backend("replace the credentials file", &e.error))?;
        Ok(())
    }

    fn backend(operation: &'static str, error: &dyn core::fmt::Display) -> StoreError {
        StoreError::Backend {
            kind: StoreKind::File,
            operation,
            reason: error.to_string(),
        }
    }
}

impl CredentialStore for FileStore {
    fn load(&self, key: &CredKey) -> Result<Option<Credential>, StoreError> {
        let _lock = self.lock()?;
        let doc = self.read_document()?;
        let Some(stored) = doc.sessions.get(&key.keychain_account()) else {
            return Ok(None);
        };
        if stored.store_version != STORE_VERSION {
            return Err(StoreError::UnknownVersion {
                found: stored.store_version,
                expected: STORE_VERSION,
            });
        }
        Ok(Some(Credential {
            access_token: SecretString::from(stored.access_token.clone()),
            refresh_token: SecretString::from(stored.refresh_token.clone()),
            expires_at: stored.expires_at,
        }))
    }

    fn save(&self, key: &CredKey, cred: &Credential) -> Result<(), StoreError> {
        let _lock = self.lock()?;
        let mut doc = self.read_document()?;
        doc.sessions.insert(
            key.keychain_account(),
            StoredCredential {
                store_version: STORE_VERSION,
                access_token: cred.access_token.expose_secret().to_owned(),
                refresh_token: cred.refresh_token.expose_secret().to_owned(),
                expires_at: cred.expires_at,
            },
        );
        self.write_document(&doc)
    }

    fn delete(&self, key: &CredKey) -> Result<(), StoreError> {
        let _lock = self.lock()?;
        let mut doc = self.read_document()?;
        if doc.sessions.remove(&key.keychain_account()).is_none() {
            return Ok(());
        }
        self.write_document(&doc)
    }

    fn kind(&self) -> StoreKind {
        StoreKind::File
    }
}

#[cfg(test)]
mod tests {
    use super::FileStore;
    use crate::credential::{Audience, CredKey, Credential};
    use crate::store::{CredentialStore as _, StoreError, StoreKind};
    use secrecy::{ExposeSecret as _, SecretString};

    #[test]
    fn a_broken_credentials_file_does_not_quote_its_token() {
        // Round 6: `erpc whoami --store file` printed the token from the
        // line `toml` failed on.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("credentials.toml");
        let token = crate::lock::tests::token_fixture();
        std::fs::write(&path, format!("[sessions]\naccess_token = \"{token}\n")).expect("write");
        let err = FileStore::new(&path)
            .load(&CredKey::new(Audience::AuthApi, "alice"))
            .expect_err("the file is malformed");
        let shown = err.to_string();
        assert!(!shown.contains("U0VDUkVUUEFZTE9BRA"), "{shown}");
        assert!(shown.contains("line 2"), "the position is kept: {shown}");
    }

    fn cred(access: &str) -> Credential {
        Credential {
            access_token: SecretString::from(access.to_owned()),
            refresh_token: SecretString::from("r.r.r".to_owned()),
            expires_at: 1_700_000_000,
        }
    }

    fn key() -> CredKey {
        CredKey::new(Audience::AuthApi, "alice")
    }

    #[test]
    fn a_session_round_trips() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = FileStore::new(dir.path().join("credentials.toml"));
        assert!(store.load(&key()).expect("an empty store reads").is_none());

        store.save(&key(), &cred("a.b.c")).expect("the save lands");
        let loaded = store
            .load(&key())
            .expect("the load succeeds")
            .expect("a session is there");
        assert_eq!(loaded.access_token.expose_secret(), "a.b.c");
        assert_eq!(loaded.expires_at, 1_700_000_000);
    }

    #[test]
    fn two_accounts_do_not_overwrite_each_other() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = FileStore::new(dir.path().join("credentials.toml"));
        let alice = CredKey::new(Audience::AuthApi, "alice");
        let bob = CredKey::new(Audience::AuthApi, "bob");
        let mcp = CredKey::new(Audience::McpUserApi, "alice");

        store.save(&alice, &cred("alice.token.x")).expect("save");
        store.save(&bob, &cred("bob.token.x")).expect("save");
        store.save(&mcp, &cred("mcp.token.x")).expect("save");

        for (k, expected) in [
            (&alice, "alice.token.x"),
            (&bob, "bob.token.x"),
            (&mcp, "mcp.token.x"),
        ] {
            let got = store.load(k).expect("load").expect("present");
            assert_eq!(got.access_token.expose_secret(), expected);
        }
    }

    #[test]
    fn a_replacement_leaves_one_session_not_two() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("credentials.toml");
        let store = FileStore::new(&path);
        store.save(&key(), &cred("first.token.x")).expect("save");
        store.save(&key(), &cred("second.token.x")).expect("save");

        let text = std::fs::read_to_string(&path).expect("the file is readable");
        assert!(!text.contains("first.token.x"), "the old token is gone");
        assert!(text.contains("second.token.x"));
    }

    #[test]
    fn deleting_a_session_that_is_not_there_succeeds() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = FileStore::new(dir.path().join("credentials.toml"));
        store.delete(&key()).expect("deleting nothing is fine");
    }

    #[test]
    fn deleting_removes_only_the_named_session() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = FileStore::new(dir.path().join("credentials.toml"));
        let alice = CredKey::new(Audience::AuthApi, "alice");
        let bob = CredKey::new(Audience::AuthApi, "bob");
        store.save(&alice, &cred("alice.token.x")).expect("save");
        store.save(&bob, &cred("bob.token.x")).expect("save");

        store.delete(&alice).expect("delete");
        assert!(store.load(&alice).expect("load").is_none());
        assert!(store.load(&bob).expect("load").is_some());
    }

    #[test]
    fn a_record_from_a_future_version_is_refused_rather_than_guessed_at() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("credentials.toml");
        std::fs::write(
            &path,
            "[sessions.\"auth-api:alice\"]\n\
             store_version = 99\n\
             access_token = \"a.b.c\"\n\
             refresh_token = \"d.e.f\"\n\
             expires_at = 1\n",
        )
        .expect("write the fixture");
        let store = FileStore::new(&path);
        match store.load(&key()) {
            Err(StoreError::UnknownVersion { found, expected }) => {
                assert_eq!(found, 99);
                assert_eq!(expected, 1);
            }
            other => panic!("expected an UnknownVersion error, got {other:?}"),
        }
    }

    #[test]
    fn a_corrupt_file_is_reported_as_corrupt() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("credentials.toml");
        std::fs::write(&path, "this is not toml {{{").expect("write the fixture");
        let store = FileStore::new(&path);
        assert!(matches!(store.load(&key()), Err(StoreError::Corrupt(_))));
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("credentials.toml");
        let store = FileStore::new(&path);
        store.save(&key(), &cred("a.b.c")).expect("save");

        let mode = std::fs::metadata(&path)
            .expect("the file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
    }

    #[test]
    fn the_lock_is_a_separate_file_from_the_credentials() {
        // Not a detail: the replacement renames over the credentials file,
        // and Windows refuses to rename over a file this process still has
        // open. Locking the credentials file itself made every save fail
        // there with "Access is denied", which only CI could show. Keeping
        // them separate is what makes the save portable.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("credentials.toml");
        let store = FileStore::new(&path);
        assert_ne!(store.lock_path(), path);
        assert_eq!(
            store.lock_path().file_name().and_then(|n| n.to_str()),
            Some("credentials.toml.lock")
        );

        store.save(&key(), &cred("a.b.c")).expect("save");
        assert!(store.lock_path().exists(), "the lock file is created");
        assert!(path.exists(), "and so is the credentials file");
    }

    #[test]
    fn repeated_saves_succeed() {
        // The sequence that failed on Windows: save, then save again over
        // the file the first one created.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = FileStore::new(dir.path().join("credentials.toml"));
        for i in 0..5 {
            store
                .save(&key(), &cred(&format!("token.{i}.x")))
                .unwrap_or_else(|e| panic!("save {i} failed: {e}"));
        }
        let got = store.load(&key()).expect("load").expect("present");
        assert_eq!(got.access_token.expose_secret(), "token.4.x");
    }

    #[test]
    fn the_kind_says_it_writes_to_disk() {
        let store = FileStore::new("/tmp/does-not-matter");
        assert_eq!(store.kind(), StoreKind::File);
        assert!(store.kind().writes_secrets_to_disk());
    }
}
