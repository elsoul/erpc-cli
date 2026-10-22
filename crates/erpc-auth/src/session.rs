// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Signing in, keeping a session current, and signing out.
//!
//! The order of operations here is the part that matters, and most of it
//! exists because of how a refresh-token family behaves: the issuer
//! invalidates the whole family when it sees a token reused, so two
//! processes refreshing at once log the operator out of both. Everything
//! below is arranged so that cannot happen, and so that a failure leaves
//! either the old session or the new one, never neither.

use core::time::Duration;
use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::credential::{Audience, CredKey, Credential};
use crate::device_flow::{Approved, DeviceAuthorization, LoginError, Next, Poller};
use crate::http::{AuthClient, HttpError};
use crate::store::{CredentialStore, StoreError};

/// Why a sign-in or a refresh did not produce a usable session.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The device grant did not complete.
    #[error(transparent)]
    Login(#[from] LoginError),
    /// A request failed.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The session could not be read or written.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// There is no stored session for this account.
    #[error("not signed in; run `erpc login`")]
    NoSession,
    /// The refresh token was refused, so the family is gone.
    #[error("the session has expired or was signed out elsewhere; run `erpc login`")]
    Expired,
    /// The session was obtained but could not be stored.
    ///
    /// Carries the path the tokens were parked at, so the operator is told
    /// where they are rather than left with a secret in an unnamed file.
    #[error(
        "signed in, but the session could not be saved to the {store}: {reason}. \
         The new tokens are at {parked} (0600); the next command files them away and \
         deletes that file, as long as nothing else has written the store first"
    )]
    SavedToFallback {
        /// Which store refused.
        store: String,
        /// Why it refused.
        reason: String,
        /// Where the tokens are.
        parked: PathBuf,
    },
}

/// Asks the issuer to invalidate a refresh token.
///
/// A trait with one method, so that the three locked writers can be
/// tested as sequences rather than only as parts. Their defects were in
/// what they did and did not do around the revocation, which a test
/// cannot see if reaching it needs a network.
pub trait Revoker {
    /// Invalidates `refresh_token`, reporting whether the issuer agreed.
    fn revoke(
        &self,
        audience: Audience,
        refresh_token: &SecretString,
    ) -> impl Future<Output = bool>;
}

impl Revoker for AuthClient {
    fn revoke(
        &self,
        audience: Audience,
        refresh_token: &SecretString,
    ) -> impl Future<Output = bool> {
        Self::revoke(self, audience, refresh_token)
    }
}

/// What a caller must do while the operator approves the sign-in.
pub trait LoginPrompt {
    /// Shows the verification page and code to the operator.
    fn present(&self, authorization: &DeviceAuthorization);
    /// Waits, between polls.
    fn wait(&self, duration: Duration) -> impl Future<Output = ()>;
}

/// Runs the device grant to completion.
///
/// Returns the approved tokens. Storing them, and checking the account
/// exists, are the caller's next steps and are separate so that a failure
/// in either can revoke what this produced.
///
/// # Errors
///
/// Returns [`SessionError`] when the grant is refused, expires, or the
/// issuer cannot be reached.
pub async fn run_device_grant<P: LoginPrompt>(
    client: &AuthClient,
    audience: Audience,
    prompt: &P,
) -> Result<Approved, SessionError> {
    let authorization = client.authorize(audience).await?;
    prompt.present(&authorization);

    let mut poller = Poller::new(&authorization);
    loop {
        let outcome = client
            .poll_token(audience, &authorization.device_code)
            .await;
        match poller.next_wait(outcome) {
            Next::Wait(duration) => prompt.wait(duration).await,
            Next::Stop(Ok(approved)) => return Ok(approved),
            Next::Stop(Err(e)) => return Err(e.into()),
        }
    }
}

/// Where a session is parked when the store refuses it after a rotation.
///
/// A refresh that succeeds at the issuer and then fails to save would
/// otherwise lose the only copy of the new token, and the old one is
/// already spent. This is one of the stated exceptions to "no secrets on
/// this machine", and `erpc doctor` reports the file for as long as it is
/// there.
#[must_use]
pub fn parked_path(state_dir: &Path, audience: Audience) -> PathBuf {
    state_dir.join(format!("pending-credentials.{}", audience.as_str()))
}

/// The lock a refresh is performed under.
///
/// One per audience, in a fixed place, so that every process on this
/// machine serialises on the same file whatever store it is using.
#[must_use]
pub fn refresh_lock_path(state_dir: &Path, audience: Audience) -> PathBuf {
    state_dir
        .join("locks")
        .join(format!("{}.lock", audience.as_str()))
}

/// Returns a session that is usable now, refreshing it if it is about to
/// expire.
///
/// The whole read-check-rotate-write sequence happens under an exclusive
/// lock, and the store is read again inside the lock. Another process may
/// have refreshed while this one was waiting, and rotating a second time
/// would present the issuer with a token it has already seen, which
/// revokes the family and signs the operator out everywhere.
///
/// # Errors
///
/// Returns [`SessionError::NoSession`] when nothing is stored,
/// [`SessionError::Expired`] when the issuer refuses the refresh token,
/// and [`SessionError::SavedToFallback`] when the new session could not be
/// written to the store.
pub async fn current_session(
    client: &AuthClient,
    store: &dyn CredentialStore,
    key: &CredKey,
    state_dir: &Path,
    now: i64,
) -> Result<Credential, SessionError> {
    let lock_path = refresh_lock_path(state_dir, key.audience());
    let _guard = crate::lock::ExclusiveLock::acquire(&lock_path)?;

    // A session parked by an earlier rotation is newer than what the
    // store holds while the store still holds the token that rotation
    // spent. File it away before reading, or the older copy would be
    // refreshed with a spent token and the issuer would revoke the family.
    //
    // Only then. Once anything else has written the store -- a sign-in,
    // which revoked the parked token, or another store's session sharing
    // this path -- the parked file is the older one, and filing it away
    // overwrote a fresh sign-in with a revoked token. That happened
    // whenever a sign-in could not unlink the file, so the decision rests
    // on what the file says it replaced, not on whether it still exists.
    //
    // Read, save, then clear, in that order. Clearing first and then
    // failing to save destroys the only copy -- and the store failing is
    // exactly the condition that created the file.
    let parked_at = parked_path(state_dir, key.audience());
    // A file this build cannot read is a reason to skip the recovery, not
    // to fail the command. Failing wedged every session read behind a
    // file that nothing cleared: the error said to sign in again, and
    // signing in left it exactly where it was. The file stays, and `erpc
    // doctor` reports it.
    if let Ok(Some(parked)) = crate::lock::read_parked(&parked_at) {
        let held = store.load(key)?;
        if parked.supersedes(held.as_ref()) {
            store.save(key, &parked.credential)?;
            // Saved, so the file no longer supersedes anything: the store
            // now holds the rotation's own token, not the one it replaced.
            // An unlink that fails leaves a file nothing will act on, and
            // `erpc doctor` reports it; failing the command over it would
            // only hide a session that is in fact fine.
            let _ = crate::lock::clear_parked(&parked_at);
        } else if parked.is_held_in(held.as_ref()) {
            // The save that parked it had in fact landed. The store has
            // this session already; the cleartext copy has no purpose.
            let _ = crate::lock::clear_parked(&parked_at);
        }
    }

    // Read inside the lock, not before it. A session read before waiting
    // is a session that may already have been replaced.
    let Some(existing) = store.load(key)? else {
        return Err(SessionError::NoSession);
    };
    if !existing.needs_refresh(now) {
        return Ok(existing);
    }

    let rotated = match client
        .refresh(key.audience(), &existing.refresh_token, now)
        .await
    {
        Ok(rotated) => rotated,
        // 400 is what RFC 6749 specifies for invalid_grant, but an
        // issuer that answers 401 or 403 to a spent refresh token means
        // the same thing to the operator: sign in again.
        Err(HttpError::Status {
            status: 400 | 401 | 403,
            ..
        }) => return Err(SessionError::Expired),
        Err(e) => return Err(e.into()),
    };

    if let Err(e) = store.save(key, &rotated) {
        // The issuer has already rotated: the old refresh token is spent
        // and the new one exists only here. Losing it now would mean a
        // forced sign-in, so it is parked where the next run can pick it
        // up, and the operator is told where.
        let parked = parked_path(state_dir, key.audience());
        crate::lock::park_credential(&parked, &rotated, &existing)?;
        return Err(SessionError::SavedToFallback {
            store: store.kind().to_string(),
            reason: e.to_string(),
            parked,
        });
    }
    Ok(rotated)
}

/// Signs out: revokes the refresh token and removes the stored session.
///
/// Revocation is attempted first and its failure does not stop the
/// removal. A token left in a store that the operator believes they have
/// signed out of is worse than one revoked at the issuer but still on
/// disk, and the reverse order risks exactly that.
///
/// Holds the same lock a refresh does, for the whole sequence, and owns
/// the parked file as the other two writers do. Without it, a refresh running concurrently rotates the token
/// this function is about to revoke: sign-out then revokes the spent one,
/// reports success, and leaves the rotated token live at the issuer with
/// nobody holding it -- or writes it back into the store after the delete,
/// so a sign-out that reported success leaves a usable session behind.
///
/// Returns whether the issuer confirmed the revocation.
///
/// # Errors
///
/// Returns [`SessionError::Store`] when the lock cannot be taken, or when
/// either the stored session or the parked file could not be removed --
/// after both removals have been attempted.
pub async fn sign_out<R: Revoker>(
    client: &R,
    store: &dyn CredentialStore,
    key: &CredKey,
    state_dir: &Path,
) -> Result<bool, SessionError> {
    let _guard =
        crate::lock::ExclusiveLock::acquire(&refresh_lock_path(state_dir, key.audience()))?;
    let stored_revoked = match store.load(key)? {
        Some(existing) => Some(client.revoke(key.audience(), &existing.refresh_token).await),
        None => None,
    };

    // A parked session is a live refresh token in cleartext on this
    // machine. Signing out has to revoke it and remove it, or `erpc
    // logout` reports success while leaving a usable session on disk that
    // the next command would reinstate.
    let parked_at = parked_path(state_dir, key.audience());
    let parked_revoked = match crate::lock::read_parked(&parked_at) {
        Ok(Some(parked)) => Some(
            client
                .revoke(key.audience(), &parked.credential.refresh_token)
                .await,
        ),
        Ok(None) => None,
        // There is a file and this build cannot read the token in it, so
        // it cannot be revoked and nothing may say it was. It is removed
        // below all the same.
        Err(_) => Some(false),
    };

    // Both removals are attempted whatever the other one does. Stopping
    // at the first failure meant a parked file that could not be unlinked
    // -- a read-only state directory does it -- also left the session in
    // the store, so `erpc logout` reported a failure having removed
    // nothing. The failure is still returned afterwards: something is
    // left on this machine and the operator has to be told.
    let cleared = crate::lock::clear_parked(&parked_at);
    let deleted = store.delete(key);
    cleared?;
    deleted?;

    // Every revocation this attempted has to have been accepted before
    // the caller may say the session was revoked at the issuer. Reporting
    // the disjunction let a failed revocation of the session the operator
    // was actually using be masked by a successful one of a parked
    // leftover: `erpc logout` said the session was revoked while it
    // stayed valid.
    let attempted: Vec<bool> = [stored_revoked, parked_revoked]
        .into_iter()
        .flatten()
        .collect();
    Ok(!attempted.is_empty() && !attempted.contains(&false))
}

/// Stores a freshly obtained session, revoking whatever it replaces.
///
/// Under the same lock as a refresh and a sign-out, for the same reason:
/// these are the three writers of one key, and a sign-in that overlaps a
/// refresh can otherwise overwrite the rotated token and strand it live at
/// the issuer.
///
/// The previous session is revoked only after the new one is stored. The
/// other order risks leaving the operator with neither.
///
/// Returns what happened to a parked file, when anything about it needs
/// saying, so the caller can tell the operator at once rather than leave
/// it to `erpc doctor`. A file that stays is harmless to this session:
/// it no longer names the session the store holds, so nothing files it
/// away. Whether its token was revoked is reported, not assumed.
///
/// # Errors
///
/// Returns [`SessionError`] when the lock cannot be taken or the session
/// cannot be stored. A failure to read what was there before is reported
/// rather than passed over: it means an old refresh token is still live
/// and is about to become unreachable.
pub async fn store_new_session<R: Revoker>(
    client: &R,
    store: &dyn CredentialStore,
    key: &CredKey,
    state_dir: &Path,
    credential: &Credential,
) -> Result<Option<ParkedReport>, SessionError> {
    let _guard =
        crate::lock::ExclusiveLock::acquire(&refresh_lock_path(state_dir, key.audience()))?;
    let previous = store.load(key)?;
    store.save(key, credential)?;

    // The parked file is only newer than the store, never newer than a
    // fresh sign-in. Leaving it would let the next command overwrite this
    // session with a stale one and strand this one live at the issuer.
    let parked_at = parked_path(state_dir, key.audience());
    let parked_revoked = match crate::lock::read_parked(&parked_at) {
        Ok(Some(parked)) => Some(
            client
                .revoke(key.audience(), &parked.credential.refresh_token)
                .await,
        ),
        Ok(None) => None,
        // A file this build cannot read holds a token it cannot present to
        // the issuer. It is removed all the same, and said so.
        Err(_) => Some(false),
    };
    // The session is durable the moment `store.save` returns, so nothing
    // after that point may turn this into an error. `login` answers an
    // error by revoking the token it just obtained, which would leave the
    // operator told the sign-in failed, a revoked token in the store, and
    // the previous session alive with nobody holding it.
    //
    // A file that cannot be unlinked -- a read-only state directory, or a
    // directory sitting where the file belongs -- is not a threat to this
    // session: it names the session it replaced, which is no longer the
    // one the store holds, so `current_session` leaves it alone. It is
    // handed back so the operator hears about it now.
    let removed = crate::lock::clear_parked(&parked_at).is_ok();

    if let Some(previous) = previous {
        client.revoke(key.audience(), &previous.refresh_token).await;
    }
    Ok(match parked_revoked {
        Some(revoked) if !(revoked && removed) => Some(ParkedReport {
            path: parked_at,
            revoked,
            removed,
        }),
        _ => None,
    })
}

/// What a sign-in did with a parked file it found, when that was not the
/// clean case of revoking its token and removing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkedReport {
    /// Where the file is, or was.
    pub path: PathBuf,
    /// Whether the issuer accepted the revocation of the token in it.
    /// False for a file this build could not read.
    pub revoked: bool,
    /// Whether the file is gone.
    pub removed: bool,
}

/// Turns an approved grant into a credential with an absolute expiry.
#[must_use]
pub fn approved_to_credential(approved: Approved, now: i64) -> Credential {
    let lifetime = i64::try_from(approved.expires_in.as_secs()).unwrap_or(i64::MAX);
    Credential {
        access_token: SecretString::from(approved.access_token),
        refresh_token: SecretString::from(approved.refresh_token),
        expires_at: now.saturating_add(lifetime),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{approved_to_credential, parked_path, refresh_lock_path};
    use crate::credential::Audience;
    use crate::device_flow::Approved;
    use core::time::Duration;
    use secrecy::ExposeSecret as _;

    use std::cell::Cell;

    use super::current_session;
    use crate::credential::{CredKey, Credential};
    use crate::http::AuthClient;
    use crate::lock::{park_credential, read_parked};
    use crate::store::{CredentialStore, StoreError, StoreKind};
    use secrecy::SecretString;

    fn cred(tag: &str) -> Credential {
        Credential {
            access_token: SecretString::from(format!("acc.{tag}.s")),
            refresh_token: SecretString::from(format!("ref.{tag}.s")),
            expires_at: 1_700_000_000,
        }
    }

    fn key() -> CredKey {
        CredKey::new(Audience::AuthApi, "alice")
    }

    /// Parks `cred(tag)` as the rotation of `cred(replaces)`.
    fn park(at: &Path, tag: &str, replaces: &str) {
        park_credential(at, &cred(tag), &cred(replaces)).expect("parked");
    }

    /// A store that can be told to refuse writes, so the condition that
    /// creates a parked file can be reproduced.
    struct FlakyStore {
        held: std::cell::RefCell<Option<Credential>>,
        refuse_saves: Cell<bool>,
    }

    impl FlakyStore {
        fn new() -> Self {
            Self {
                held: std::cell::RefCell::new(None),
                refuse_saves: Cell::new(false),
            }
        }
        fn refresh_token(&self) -> Option<String> {
            self.held
                .borrow()
                .as_ref()
                .map(|c| c.refresh_token.expose_secret().to_owned())
        }
    }

    impl CredentialStore for FlakyStore {
        fn load(&self, _key: &CredKey) -> Result<Option<Credential>, StoreError> {
            Ok(self.held.borrow().clone())
        }
        fn save(&self, _key: &CredKey, cred: &Credential) -> Result<(), StoreError> {
            if self.refuse_saves.get() {
                return Err(StoreError::Backend {
                    kind: StoreKind::OnePasswordDesktop,
                    operation: "write the item",
                    reason: "authorization prompt dismissed".to_owned(),
                });
            }
            *self.held.borrow_mut() = Some(cred.clone());
            Ok(())
        }
        fn delete(&self, _key: &CredKey) -> Result<(), StoreError> {
            *self.held.borrow_mut() = None;
            Ok(())
        }
        fn kind(&self) -> StoreKind {
            StoreKind::OnePasswordDesktop
        }
    }

    /// A time far enough ahead that `needs_refresh` is false, so
    /// `current_session` returns before it would build a request.
    const NOW: i64 = 1_600_000_000;

    #[tokio::test]
    async fn a_recovery_that_cannot_store_keeps_the_parked_file() {
        // The condition that created the file is the store refusing a
        // write, and it is usually still true when the recovery runs.
        // Clearing before the save destroyed the only copy of a token
        // whose predecessor was already spent.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "ROTATED", "SPENT");

        let store = FlakyStore::new();
        store.save(&key(), &cred("SPENT")).expect("save");
        store.refuse_saves.set(true);
        let client = AuthClient::new().expect("a client");

        // The real function. An earlier version of this test wrote the
        // sequence out by hand and stayed green with the fix reverted,
        // which is not evidence of anything.
        let outcome = current_session(&client, &store, &key(), dir.path(), NOW).await;
        assert!(
            outcome.is_err(),
            "the store refused, so this cannot succeed"
        );
        assert!(
            at.exists(),
            "a failed save must leave the only copy where it is"
        );

        assert_eq!(
            store.refresh_token().as_deref(),
            Some("ref.SPENT.s"),
            "the refused save changed nothing"
        );

        // Once the store works, the recovery completes and clears it.
        store.refuse_saves.set(false);
        let recovered = current_session(&client, &store, &key(), dir.path(), NOW)
            .await
            .expect("the recovery completes");
        assert_eq!(recovered.refresh_token.expose_secret(), "ref.ROTATED.s");
        assert!(!at.exists(), "and the file is cleared once it is durable");
        assert_eq!(store.refresh_token().as_deref(), Some("ref.ROTATED.s"));
    }

    #[tokio::test]
    async fn an_unreadable_parked_file_does_not_wedge_a_good_session() {
        // A record from a later build used to fail every session read,
        // with no way out: the error said to sign in again, and signing
        // in did not clear the file.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        std::fs::write(
            &at,
            "store_version = 99\naccess_token = \"a\"\nrefresh_token = \"b\"\nexpires_at = 1\n",
        )
        .expect("write the fixture");
        assert!(read_parked(&at).is_err(), "this build cannot read it");

        let store = FlakyStore::new();
        store.save(&key(), &cred("GOOD")).expect("save");
        let client = AuthClient::new().expect("a client");

        // Three times, because the failure this covers was permanent.
        for attempt in 1..=3 {
            let got = current_session(&client, &store, &key(), dir.path(), NOW)
                .await
                .unwrap_or_else(|e| panic!("attempt {attempt} failed: {e}"));
            assert_eq!(got.refresh_token.expose_secret(), "ref.GOOD.s");
        }
        assert!(at.exists(), "and it is still there for doctor to report");
    }

    /// Records what it was asked to revoke, and agrees to everything.
    #[derive(Default)]
    struct RecordingRevoker {
        seen: std::cell::RefCell<Vec<String>>,
    }

    impl super::Revoker for RecordingRevoker {
        fn revoke(
            &self,
            _audience: Audience,
            refresh_token: &SecretString,
        ) -> impl Future<Output = bool> {
            self.seen
                .borrow_mut()
                .push(refresh_token.expose_secret().to_owned());
            core::future::ready(true)
        }
    }

    #[tokio::test]
    async fn a_sign_in_clears_and_revokes_a_stale_parked_session() {
        // Without this the next command restores the parked session over
        // the one just obtained, and the fresh token is left live at the
        // issuer with nobody holding it.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "OLD-PARKED", "PREVIOUS");

        let store = FlakyStore::new();
        store.save(&key(), &cred("PREVIOUS")).expect("save");
        let revoker = RecordingRevoker::default();

        super::store_new_session(&revoker, &store, &key(), dir.path(), &cred("NEW-LOGIN"))
            .await
            .expect("stored");

        assert_eq!(store.refresh_token().as_deref(), Some("ref.NEW-LOGIN.s"));
        assert!(!at.exists(), "the stale parked session is gone");
        let seen = revoker.seen.borrow().clone();
        assert!(seen.contains(&"ref.OLD-PARKED.s".to_owned()), "{seen:?}");
        assert!(seen.contains(&"ref.PREVIOUS.s".to_owned()), "{seen:?}");
    }

    #[tokio::test]
    async fn signing_out_revokes_and_removes_a_parked_session() {
        // A parked session is a live refresh token in cleartext. A logout
        // that leaves it reports success while the next command signs the
        // operator back in.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "PARKED", "STORED");

        let store = FlakyStore::new();
        store.save(&key(), &cred("STORED")).expect("save");
        let revoker = RecordingRevoker::default();

        let confirmed = super::sign_out(&revoker, &store, &key(), dir.path())
            .await
            .expect("signed out");

        assert!(confirmed);
        assert!(!at.exists(), "no live token may survive a sign-out on disk");
        assert!(store.refresh_token().is_none());
        let seen = revoker.seen.borrow().clone();
        assert!(seen.contains(&"ref.PARKED.s".to_owned()), "{seen:?}");
        assert!(seen.contains(&"ref.STORED.s".to_owned()), "{seen:?}");
    }

    /// Agrees to everything except the tokens it was told to refuse.
    struct ChoosyRevoker {
        refuse: Vec<String>,
    }

    impl super::Revoker for ChoosyRevoker {
        fn revoke(
            &self,
            _audience: Audience,
            refresh_token: &SecretString,
        ) -> impl Future<Output = bool> {
            let token = refresh_token.expose_secret().to_owned();
            core::future::ready(!self.refuse.contains(&token))
        }
    }

    #[tokio::test]
    async fn a_sign_out_claims_a_revocation_only_if_every_attempt_was_accepted() {
        // The operator's session is the one in the store. A parked file is
        // a leftover. Reporting the disjunction meant the leftover's
        // successful revocation spoke for the session that was actually
        // refused, and `erpc logout` printed "revoked at the issuer" over
        // a session that stayed valid.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "PARKED", "STORED");

        let store = FlakyStore::new();
        store.save(&key(), &cred("STORED")).expect("save");
        let revoker = ChoosyRevoker {
            refuse: vec!["ref.STORED.s".to_owned()],
        };

        let confirmed = super::sign_out(&revoker, &store, &key(), dir.path())
            .await
            .expect("signed out");
        assert!(
            !confirmed,
            "the session the operator was using was not revoked, so nothing may say it was"
        );
        // The local removals happen either way.
        assert!(store.refresh_token().is_none());
        assert!(!at.exists());
    }

    #[tokio::test]
    async fn a_parked_file_that_cannot_be_read_cannot_be_claimed_as_revoked() {
        // Its token was never presented to the issuer, so a sign-out that
        // removes it may not say the session was revoked, however the
        // stored one went.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        std::fs::write(&at, "store_version = 99\n").expect("write the fixture");
        assert!(read_parked(&at).is_err(), "this build cannot read it");

        let store = FlakyStore::new();
        store.save(&key(), &cred("STORED")).expect("save");
        let revoker = RecordingRevoker::default();

        let confirmed = super::sign_out(&revoker, &store, &key(), dir.path())
            .await
            .expect("signed out");
        assert!(!confirmed);
        assert!(!at.exists(), "it is still removed");
        assert!(store.refresh_token().is_none());
    }

    #[tokio::test]
    async fn a_sign_out_that_revokes_nothing_at_all_claims_nothing() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = FlakyStore::new();
        let revoker = ChoosyRevoker { refuse: Vec::new() };
        assert!(
            !super::sign_out(&revoker, &store, &key(), dir.path())
                .await
                .expect("signed out"),
            "there was no session, so there is no revocation to report"
        );
    }

    /// Makes `dir` one whose files can be read but not unlinked, which is
    /// what leaves a parked file behind after the attempt to clear it.
    ///
    /// Returns false when the mode is not enforced for this user -- root
    /// ignores it -- because then there is nothing to reproduce.
    #[cfg(unix)]
    fn hold_files_down(dir: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        let probe = dir.join("probe");
        std::fs::write(&probe, "x").expect("write the probe");
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500))
            .expect("make the directory read-only");
        if std::fs::remove_file(&probe).is_ok() {
            release_files(dir);
            return false;
        }
        true
    }

    #[cfg(unix)]
    fn release_files(dir: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_parked_file_that_cannot_be_cleared_does_not_undo_a_sign_in() {
        // The session is durable the moment the store accepts it. Letting
        // the unlink that follows fail the whole call made `login` revoke
        // the token it had just stored: the operator was told the sign-in
        // failed, the store held a dead token, and the previous session
        // was left alive with nobody holding it.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "OLD-PARKED", "PREVIOUS");
        // The lock lives under the state directory and has to be takeable
        // once the directory stops accepting new entries.
        std::fs::create_dir_all(dir.path().join("locks")).expect("the lock directory");

        let store = FlakyStore::new();
        store.save(&key(), &cred("PREVIOUS")).expect("save");
        let revoker = RecordingRevoker::default();

        if !hold_files_down(dir.path()) {
            return;
        }
        let outcome =
            super::store_new_session(&revoker, &store, &key(), dir.path(), &cred("NEW-LOGIN"))
                .await;
        release_files(dir.path());

        outcome.expect("a session the store accepted is a session, whatever the unlink does");
        assert_eq!(
            store.refresh_token().as_deref(),
            Some("ref.NEW-LOGIN.s"),
            "and it is the new one"
        );
        assert!(at.exists(), "the file stays, for doctor to report");
        // The revocations after the unlink still happen: the `?` skipped
        // the previous session's, leaving it live and unreachable.
        let seen = revoker.seen.borrow().clone();
        assert!(seen.contains(&"ref.OLD-PARKED.s".to_owned()), "{seen:?}");
        assert!(seen.contains(&"ref.PREVIOUS.s".to_owned()), "{seen:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_leftover_a_sign_in_could_not_delete_never_comes_back_over_it() {
        // Round 4's blocker. Letting the unlink fail quietly was only half
        // of it: the next command found the file, filed it over the fresh
        // sign-in, and the store held a token the sign-in had just revoked.
        // Both cases the review reproduced: the directory still read-only
        // on the next command, and writable again.
        for stays_read_only in [true, false] {
            let dir = tempfile::tempdir().expect("a temporary directory");
            let at = parked_path(dir.path(), Audience::AuthApi);
            park(&at, "OLD-PARKED", "PREVIOUS");
            std::fs::create_dir_all(dir.path().join("locks")).expect("the lock directory");

            let store = FlakyStore::new();
            store.save(&key(), &cred("PREVIOUS")).expect("save");
            let revoker = RecordingRevoker::default();
            let client = AuthClient::new().expect("a client");

            if !hold_files_down(dir.path()) {
                return;
            }
            let leftover =
                super::store_new_session(&revoker, &store, &key(), dir.path(), &cred("NEW-LOGIN"))
                    .await;
            if !stays_read_only {
                release_files(dir.path());
            }
            let next = current_session(&client, &store, &key(), dir.path(), NOW).await;
            release_files(dir.path());

            assert_eq!(
                leftover.expect("signed in"),
                Some(super::ParkedReport {
                    path: at.clone(),
                    revoked: true,
                    removed: false,
                }),
                "the file that could not be deleted is handed back to be reported"
            );
            let next = next.unwrap_or_else(|e| panic!("read-only {stays_read_only}: {e}"));
            assert_eq!(
                next.refresh_token.expose_secret(),
                "ref.NEW-LOGIN.s",
                "read-only {stays_read_only}: the next command must see the sign-in"
            );
            assert_eq!(store.refresh_token().as_deref(), Some("ref.NEW-LOGIN.s"));
        }
    }

    #[tokio::test]
    async fn a_parked_session_is_filed_only_over_the_session_it_replaced() {
        // Another store's session, or one a sign-in put there: in both the
        // parked file is not newer, and it is not this function's to take.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "PARKED", "SOMEONE-ELSE");

        let store = FlakyStore::new();
        store.save(&key(), &cred("CURRENT")).expect("save");
        let client = AuthClient::new().expect("a client");

        let got = current_session(&client, &store, &key(), dir.path(), NOW)
            .await
            .expect("the stored session is fine");
        assert_eq!(got.refresh_token.expose_secret(), "ref.CURRENT.s");
        assert_eq!(store.refresh_token().as_deref(), Some("ref.CURRENT.s"));
        assert!(
            at.exists(),
            "a parked session that may be another store's live token is not deleted"
        );
    }

    #[tokio::test]
    async fn a_sign_in_says_when_a_parked_token_it_removed_was_never_revoked() {
        // Round 5. A parked file this build cannot read was unlinked
        // without its token reaching the issuer, and nothing was said; with
        // the unlink failing too, `login` called it "revoked just now".
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        std::fs::write(&at, "store_version = 99\n").expect("write the fixture");
        let store = FlakyStore::new();
        let revoker = RecordingRevoker::default();

        let report =
            super::store_new_session(&revoker, &store, &key(), dir.path(), &cred("NEW-LOGIN"))
                .await
                .expect("signed in");
        assert_eq!(
            report,
            Some(super::ParkedReport {
                path: at.clone(),
                revoked: false,
                removed: true,
            })
        );
        assert!(!at.exists());
    }

    #[tokio::test]
    async fn a_sign_in_says_when_the_issuer_refused_the_parked_token() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "OLD-PARKED", "PREVIOUS");
        let store = FlakyStore::new();
        let revoker = ChoosyRevoker {
            refuse: vec!["ref.OLD-PARKED.s".to_owned()],
        };
        let report =
            super::store_new_session(&revoker, &store, &key(), dir.path(), &cred("NEW-LOGIN"))
                .await
                .expect("signed in");
        assert_eq!(report.map(|r| (r.revoked, r.removed)), Some((false, true)));
    }

    #[tokio::test]
    async fn a_parked_copy_of_the_stored_session_is_cleared_not_filed() {
        // A save that reported failure but landed: the same live token is
        // in the store and in cleartext on disk. Only the disk copy goes.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "LANDED", "SPENT");
        let store = FlakyStore::new();
        store.save(&key(), &cred("LANDED")).expect("save");
        let client = AuthClient::new().expect("a client");

        let got = current_session(&client, &store, &key(), dir.path(), NOW)
            .await
            .expect("the stored session is fine");
        assert_eq!(got.refresh_token.expose_secret(), "ref.LANDED.s");
        assert!(!at.exists(), "the cleartext copy is gone");
    }

    #[tokio::test]
    async fn a_sign_in_with_a_working_unlink_reports_nothing_left_over() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "OLD-PARKED", "PREVIOUS");
        let store = FlakyStore::new();
        let revoker = RecordingRevoker::default();
        let leftover =
            super::store_new_session(&revoker, &store, &key(), dir.path(), &cred("NEW-LOGIN"))
                .await
                .expect("signed in");
        assert!(leftover.is_none());
        assert!(!at.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_parked_file_that_cannot_be_cleared_still_removes_the_session() {
        // Stopping at the first failed removal meant the session stayed in
        // the store as well, so `erpc logout` reported a failure having
        // removed nothing at all.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "PARKED", "STORED");
        std::fs::create_dir_all(dir.path().join("locks")).expect("the lock directory");

        let store = FlakyStore::new();
        store.save(&key(), &cred("STORED")).expect("save");
        let revoker = RecordingRevoker::default();

        if !hold_files_down(dir.path()) {
            return;
        }
        let outcome = super::sign_out(&revoker, &store, &key(), dir.path()).await;
        release_files(dir.path());

        assert!(
            outcome.is_err(),
            "a live token left on disk is a failure and has to be reported"
        );
        assert!(
            store.refresh_token().is_none(),
            "the removal that could be done was done"
        );
        let seen = revoker.seen.borrow().clone();
        assert!(seen.contains(&"ref.PARKED.s".to_owned()), "{seen:?}");
        assert!(seen.contains(&"ref.STORED.s".to_owned()), "{seen:?}");
    }

    #[tokio::test]
    async fn signing_out_with_nothing_parked_still_works() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = FlakyStore::new();
        store.save(&key(), &cred("STORED")).expect("save");
        let revoker = RecordingRevoker::default();
        assert!(
            super::sign_out(&revoker, &store, &key(), dir.path())
                .await
                .expect("signed out")
        );
    }

    #[test]
    fn the_lock_is_one_per_audience_in_a_fixed_place() {
        let dir = Path::new("/home/alice/.erpc/state");
        let auth = refresh_lock_path(dir, Audience::AuthApi);
        let mcp = refresh_lock_path(dir, Audience::McpUserApi);
        assert_ne!(auth, mcp);
        assert!(auth.ends_with("locks/auth-api.lock"), "{}", auth.display());
        // Fixed, not derived from the store: two processes using different
        // stores must still serialise against each other.
        assert_eq!(auth, refresh_lock_path(dir, Audience::AuthApi));
    }

    #[test]
    fn the_parked_file_is_named_for_its_audience() {
        let dir = Path::new("/home/alice/.erpc/state");
        assert!(parked_path(dir, Audience::AuthApi).ends_with("pending-credentials.auth-api"));
        assert_ne!(
            parked_path(dir, Audience::AuthApi),
            parked_path(dir, Audience::McpUserApi)
        );
    }

    #[test]
    fn an_approval_becomes_an_absolute_expiry() {
        let cred = approved_to_credential(
            Approved {
                access_token: "a.b.c".to_owned(),
                refresh_token: "d.e.f".to_owned(),
                expires_in: Duration::from_secs(3600),
            },
            1_000,
        );
        assert_eq!(cred.expires_at, 4_600);
        assert_eq!(cred.access_token.expose_secret(), "a.b.c");
    }

    #[test]
    fn an_absurd_lifetime_does_not_wrap_the_clock() {
        let cred = approved_to_credential(
            Approved {
                access_token: "a.b.c".to_owned(),
                refresh_token: "d.e.f".to_owned(),
                expires_in: Duration::from_secs(u64::MAX),
            },
            1_000,
        );
        assert_eq!(cred.expires_at, i64::MAX);
    }
}
