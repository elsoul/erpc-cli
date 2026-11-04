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
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use secrecy::SecretString;
use tokio::sync::watch;

use crate::client::{AuthClient, HttpError};
use crate::credential::{Audience, CredKey, Credential};
use crate::device_flow::{Approved, DeviceAuthorization, LoginError, Next, Poller};
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
    /// The session needed refreshing, and erpc is on its way out, so it
    /// was left for the next command; see [`Leaving`].
    #[error("erpc is leaving, so the session was not refreshed")]
    Leaving,
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

/// Exchanges a refresh token for a new session.
///
/// A trait for the same reason as [`Revoker`]: the rotation in
/// [`current_session`] is where a session is lost if anything goes wrong
/// between spending the old token and saving the new one, and a test
/// cannot reach it if that needs a network.
pub trait Refresher {
    /// Presents `refresh_token` to the issuer for `audience`.
    fn refresh(
        &self,
        audience: Audience,
        refresh_token: &SecretString,
        now: i64,
    ) -> impl Future<Output = Result<Credential, HttpError>> + Send;
}

impl Refresher for AuthClient {
    fn refresh(
        &self,
        audience: Audience,
        refresh_token: &SecretString,
        now: i64,
    ) -> impl Future<Output = Result<Credential, HttpError>> + Send {
        Self::refresh(self, audience, refresh_token, now)
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

/// Where a session is parked when it cannot reach the store after a
/// rotation: when the store refuses it, or when erpc has to end before the
/// store has taken it (see [`Leaving::park`]).
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
/// Taking the lock and every store call run on the blocking pool, so the
/// caller's task keeps running while 1Password or the keychain answers.
///
/// A rotation -- the refresh and the save of what it returns -- runs as a
/// task of its own once it starts. A caller that stops waiting, as Ctrl-C
/// on the console's splash does, cannot cut it off between spending the
/// old refresh token and saving the new one; that would leave the store
/// holding a spent token, and the next refresh would revoke the family.
/// A process leaves through [`Leaving`], which waits for a rotation under
/// way or parks what it has not saved, and starts no new one.
///
/// # Errors
///
/// Returns [`SessionError::NoSession`] when nothing is stored,
/// [`SessionError::Expired`] when the issuer refuses the refresh token,
/// [`SessionError::SavedToFallback`] when the new session could not be
/// written to the store, and [`SessionError::Leaving`] when it needed
/// refreshing after the process had begun to leave.
pub async fn current_session<R, S>(
    client: &R,
    store: &Arc<S>,
    key: &CredKey,
    state_dir: &Path,
    now: i64,
) -> Result<Credential, SessionError>
where
    R: Refresher + Clone + Send + Sync + 'static,
    S: CredentialStore + Send + Sync + ?Sized + 'static,
{
    let (guard, held) = {
        let (key, state_dir) = (key.clone(), state_dir.to_owned());
        off_thread(store, move |store| read_locked(store, &key, &state_dir)).await?
    };
    let Some(existing) = held else {
        return Err(SessionError::NoSession);
    };
    if !existing.needs_refresh(now) {
        return Ok(existing);
    }

    // Counted before it starts, and refused once the process has begun to
    // leave: a process on its way out neither misses one nor sees one
    // start after it has decided.
    let Some(counted) = Rotating::begin() else {
        return Err(SessionError::Leaving);
    };
    let rotation = Rotation {
        client: client.clone(),
        store: Arc::clone(store),
        key: key.clone(),
        state_dir: state_dir.to_owned(),
        existing,
        lock: guard,
        counted,
    };
    match tokio::spawn(rotation.run(now)).await {
        Ok(done) => done,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Only when the runtime shuts down before the rotation finished.
        Err(_) => Err(SessionError::Leaving),
    }
}

/// A rotation under way: what it needs to refresh `existing` and file what
/// comes back.
struct Rotation<R, S: ?Sized> {
    client: R,
    store: Arc<S>,
    key: CredKey,
    state_dir: PathBuf,
    existing: Credential,
    /// The refresh lock, held until the save is done.
    lock: crate::lock::ExclusiveLock,
    /// Counts it as under way, for a process about to leave.
    counted: Rotating,
}

impl<R, S> Rotation<R, S>
where
    R: Refresher,
    S: CredentialStore + Send + Sync + ?Sized + 'static,
{
    /// Refreshes, then saves or parks what comes back.
    async fn run(self, now: i64) -> Result<Credential, SessionError> {
        let Self {
            client,
            store,
            key,
            state_dir,
            existing,
            lock,
            mut counted,
        } = self;
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

        // The old refresh token is spent, and the new session exists only
        // here until the store has it. A process that cannot wait for the
        // store parks it from this record.
        let lock = Arc::new(lock);
        counted.answered(
            &rotated,
            &existing,
            parked_path(&state_dir, key.audience()),
            Arc::clone(&lock),
        );
        let filed = off_thread(&store, move |store| {
            // The lock goes with the write, so it is held until the write
            // is done.
            let _lock = lock;
            file_rotation(store, &key, &state_dir, rotated, &existing)
        })
        .await;
        counted.filed();
        filed
    }
}

/// What the rotations in this process are doing, for a process about to
/// leave.
#[derive(Default)]
struct InFlight {
    /// Rotations under way.
    rotations: usize,
    /// Of those, the ones the issuer has answered whose new session the
    /// store does not have yet, by rotation.
    unsaved: BTreeMap<u64, Unsaved>,
    /// How many [`Leaving`]s there are. While there is one, no rotation
    /// starts.
    leaving: usize,
}

/// A rotated session the store does not have yet, and what parking it
/// takes.
struct Unsaved {
    rotated: Credential,
    replaces: Credential,
    parked_at: PathBuf,
}

static IN_FLIGHT: LazyLock<watch::Sender<InFlight>> =
    LazyLock::new(|| watch::Sender::new(InFlight::default()));

/// One rotation under way, counted in [`IN_FLIGHT`] for as long as it lives.
struct Rotating {
    id: u64,
    /// The refresh lock, shared with the save from the moment the issuer
    /// answers. If this is dropped unfiled, it parks the session before the
    /// lock can go, so no other erpc reads the store in between.
    lock: Option<Arc<crate::lock::ExclusiveLock>>,
}

impl Rotating {
    /// Counts a rotation, unless the process has begun to leave.
    fn begin() -> Option<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut begun = false;
        IN_FLIGHT.send_if_modified(|in_flight| {
            if in_flight.leaving > 0 {
                return false;
            }
            in_flight.rotations += 1;
            begun = true;
            true
        });
        begun.then_some(Self { id, lock: None })
    }

    /// The issuer has answered with `rotated`, which replaces `replaces`.
    /// Until the store has it, a process that has to leave parks it at
    /// `parked_at`.
    fn answered(
        &mut self,
        rotated: &Credential,
        replaces: &Credential,
        parked_at: PathBuf,
        lock: Arc<crate::lock::ExclusiveLock>,
    ) {
        self.lock = Some(lock);
        let unsaved = Unsaved {
            rotated: rotated.clone(),
            replaces: replaces.clone(),
            parked_at,
        };
        IN_FLIGHT.send_modify(|in_flight| {
            in_flight.unsaved.insert(self.id, unsaved);
        });
    }

    /// The store has the new session, or it is parked, or parking it failed
    /// and the caller is told: either way there is nothing left to keep.
    fn filed(&mut self) {
        IN_FLIGHT.send_modify(|in_flight| {
            in_flight.unsaved.remove(&self.id);
        });
        self.lock = None;
    }
}

impl Drop for Rotating {
    /// A rotation dropped before it was filed -- its task cancelled by a
    /// runtime shutting down, or unwound by a panic -- parks what the issuer
    /// handed back, so that settling does not mean losing it.
    fn drop(&mut self) {
        let mut left = None;
        IN_FLIGHT.send_modify(|in_flight| {
            left = in_flight.unsaved.remove(&self.id);
            in_flight.rotations = in_flight.rotations.saturating_sub(1);
        });
        if let Some(left) = left {
            let _ = crate::lock::park_credential(&left.parked_at, &left.rotated, &left.replaces);
        }
        // Only now, after the park, may the lock go.
        self.lock = None;
    }
}

/// A process on its way out. While one exists no rotation starts, and it
/// can wait for the rotations under way or park what they have not saved.
///
/// A rotation spends the old refresh token at the issuer before the store
/// has the new one. A process that ends in between leaves the store
/// holding a spent token; the next refresh presents it, and the issuer
/// revokes the family, signing the operator out everywhere.
/// [`current_session`] runs a rotation as a task of its own, so a caller
/// that stops waiting does not cut it off. A process that leaves without
/// this first does.
#[must_use = "rotations can start again as soon as it is dropped"]
pub struct Leaving {
    _private: (),
}

impl Leaving {
    /// Stops new rotations from starting in this process.
    pub fn start() -> Self {
        IN_FLIGHT.send_modify(|in_flight| in_flight.leaving += 1);
        Self { _private: () }
    }

    /// Whether a rotation is still under way.
    #[must_use]
    pub fn rotating(&self) -> bool {
        IN_FLIGHT.borrow().rotations > 0
    }

    /// Resolves once no rotation is under way.
    pub async fn settled(&self) {
        wait_for(|in_flight| in_flight.rotations == 0).await;
    }

    /// Resolves once no rotation is still waiting for the issuer, which
    /// [`crate::client::REQUEST_TIMEOUT`] bounds.
    pub async fn answered(&self) {
        wait_for(|in_flight| in_flight.rotations == in_flight.unsaved.len()).await;
    }

    /// Parks every rotated session the store does not have yet, where the
    /// next [`current_session`] files it into the store, and says where.
    /// For a process that cannot wait for the store any longer.
    ///
    /// A rotation still waiting for the issuer has nothing to park yet;
    /// wait for [`Self::answered`] first. A save that lands after all leaves
    /// a parked copy of what the store holds, which the next
    /// `current_session` deletes.
    #[must_use]
    pub fn park(&self) -> Vec<Result<PathBuf, StoreError>> {
        let unsaved: Vec<(Credential, Credential, PathBuf)> = IN_FLIGHT
            .borrow()
            .unsaved
            .values()
            .map(|u| (u.rotated.clone(), u.replaces.clone(), u.parked_at.clone()))
            .collect();
        unsaved
            .into_iter()
            .map(|(rotated, replaces, at)| {
                crate::lock::park_credential(&at, &rotated, &replaces).map(|()| at)
            })
            .collect()
    }
}

impl Drop for Leaving {
    fn drop(&mut self) {
        IN_FLIGHT.send_modify(|in_flight| in_flight.leaving = in_flight.leaving.saturating_sub(1));
    }
}

async fn wait_for(done: impl FnMut(&InFlight) -> bool) {
    let mut watching = IN_FLIGHT.subscribe();
    // The sender is a static and is never dropped.
    let _ = watching.wait_for(done).await;
}

/// Runs store work on the blocking pool, and waits for it without
/// holding up the caller's task.
///
/// The stores are synchronous, and the slow ones are processes waited on:
/// `op` takes seconds while the 1Password app asks for approval, and
/// `security` can sit behind a keychain prompt. The refresh lock can wait
/// on another erpc. Waited on in the task, that stopped the task, and on
/// erpc's single-threaded runtime every other task with it: the console's
/// splash drew nothing until 1Password had answered.
///
/// Work that has started runs to the end even if the caller stops
/// waiting, unless the process leaves first; a rotation's save is kept
/// from that by [`Leaving`].
async fn off_thread<S, T>(
    store: &Arc<S>,
    work: impl FnOnce(&S) -> Result<T, SessionError> + Send + 'static,
) -> Result<T, SessionError>
where
    S: CredentialStore + Send + Sync + ?Sized + 'static,
    T: Send + 'static,
{
    let kind = store.kind();
    let store = Arc::clone(store);
    match tokio::task::spawn_blocking(move || work(store.as_ref())).await {
        Ok(done) => done,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Only when the runtime shuts down before the work started.
        Err(_) => Err(SessionError::Store(StoreError::Unavailable {
            kind,
            reason: "erpc was shutting down".to_owned(),
        })),
    }
}

/// Takes the refresh lock, files away a parked session that is newer than
/// the stored one, and reads the store. The first half of
/// [`current_session`], and blocking.
fn read_locked<S: CredentialStore + ?Sized>(
    store: &S,
    key: &CredKey,
    state_dir: &Path,
) -> Result<(crate::lock::ExclusiveLock, Option<Credential>), SessionError> {
    let lock_path = refresh_lock_path(state_dir, key.audience());
    let guard = crate::lock::ExclusiveLock::acquire(&lock_path)?;

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
    let held = store.load(key)?;
    Ok((guard, held))
}

/// Saves a rotated session, or parks it if the store refuses. The last
/// step of [`current_session`], and blocking.
fn file_rotation<S: CredentialStore + ?Sized>(
    store: &S,
    key: &CredKey,
    state_dir: &Path,
    rotated: Credential,
    existing: &Credential,
) -> Result<Credential, SessionError> {
    if let Err(e) = store.save(key, &rotated) {
        // The issuer has already rotated: the old refresh token is spent
        // and the new one exists only here. Losing it now would mean a
        // forced sign-in, so it is parked where the next run can pick it
        // up, and the operator is told where.
        let parked = parked_path(state_dir, key.audience());
        crate::lock::park_credential(&parked, &rotated, existing)?;
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
/// Returns what became of the session at the issuer.
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
) -> Result<Revocation, SessionError> {
    let _guard =
        crate::lock::ExclusiveLock::acquire(&refresh_lock_path(state_dir, key.audience()))?;
    let stored_revoked = match readable(store.load(key))? {
        Readable::Held(existing) => {
            Some(client.revoke(key.audience(), &existing.refresh_token).await)
        }
        Readable::Nothing => None,
        // A record this build cannot read still has to go: refusing to
        // sign out over it left the operator no way out at all, since
        // signing in failed on the same read. Its token cannot be revoked,
        // and nothing may say it was.
        Readable::Unreadable(_) => Some(false),
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
    Ok(if attempted.is_empty() {
        Revocation::NothingToRevoke
    } else if attempted.contains(&false) {
        Revocation::NotConfirmed
    } else {
        Revocation::Confirmed
    })
}

/// What a sign-out did at the issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// Every token it found was revoked, and the issuer said so.
    Confirmed,
    /// At least one token it found was not revoked: the issuer refused, or
    /// the token could not be read to be presented.
    NotConfirmed,
    /// There was no session on this machine to revoke.
    NothingToRevoke,
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
) -> Result<SignInReport, SessionError> {
    let _guard =
        crate::lock::ExclusiveLock::acquire(&refresh_lock_path(state_dir, key.audience()))?;
    let (previous, previous_unreadable) = match readable(store.load(key))? {
        Readable::Held(previous) => (Some(previous), None),
        Readable::Nothing => (None, None),
        // Replaced all the same, and said so: a record this build cannot
        // read is one nobody can use, and refusing the sign-in over it
        // left the operator no way past it.
        Readable::Unreadable(why) => (None, Some(why)),
    };
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
    Ok(SignInReport {
        parked: match parked_revoked {
            Some(revoked) if !(revoked && removed) => Some(ParkedReport {
                path: parked_at,
                revoked,
                removed,
            }),
            _ => None,
        },
        previous_unreadable,
    })
}

/// What a sign-in could not do cleanly, for the caller to tell the
/// operator. The default is the clean case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignInReport {
    /// A parked file that was not both revoked and removed.
    pub parked: Option<ParkedReport>,
    /// The store held a session this build could not read, and why. It was
    /// replaced and could not be revoked. The reason says how much went
    /// with it: for the file store, the whole file.
    pub previous_unreadable: Option<String>,
}

/// A store read, sorted by what a writer can do about it.
enum Readable {
    Held(Credential),
    Nothing,
    Unreadable(String),
}

/// Sorts a store read. A record that will not parse, or is from another
/// build, is something a writer can replace; a store that could not be
/// reached is not, because what it holds may be a live session.
fn readable(read: Result<Option<Credential>, StoreError>) -> Result<Readable, SessionError> {
    match read {
        Ok(Some(held)) => Ok(Readable::Held(held)),
        Ok(None) => Ok(Readable::Nothing),
        Err(e @ (StoreError::Corrupt(_) | StoreError::UnknownVersion { .. })) => {
            Ok(Readable::Unreadable(e.to_string()))
        }
        Err(e) => Err(e.into()),
    }
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::current_session;
    use crate::client::{AuthClient, HttpError};
    use crate::credential::{CredKey, Credential};
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
    ///
    /// `Sync`, because `current_session` calls a store from the blocking
    /// pool.
    struct FlakyStore {
        held: Mutex<Option<Credential>>,
        refuse_saves: AtomicBool,
    }

    impl FlakyStore {
        fn new() -> Self {
            Self {
                held: Mutex::new(None),
                refuse_saves: AtomicBool::new(false),
            }
        }
        fn refuse_saves(&self, refuse: bool) {
            self.refuse_saves.store(refuse, Ordering::SeqCst);
        }
        fn refresh_token(&self) -> Option<String> {
            self.held
                .lock()
                .expect("not poisoned")
                .as_ref()
                .map(|c| c.refresh_token.expose_secret().to_owned())
        }
    }

    impl CredentialStore for FlakyStore {
        fn load(&self, _key: &CredKey) -> Result<Option<Credential>, StoreError> {
            Ok(self.held.lock().expect("not poisoned").clone())
        }
        fn save(&self, _key: &CredKey, cred: &Credential) -> Result<(), StoreError> {
            if self.refuse_saves.load(Ordering::SeqCst) {
                return Err(StoreError::Backend {
                    kind: StoreKind::OnePasswordDesktop,
                    operation: "write the item",
                    reason: "authorization prompt dismissed".to_owned(),
                });
            }
            *self.held.lock().expect("not poisoned") = Some(cred.clone());
            Ok(())
        }
        fn delete(&self, _key: &CredKey) -> Result<(), StoreError> {
            *self.held.lock().expect("not poisoned") = None;
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

        let store = Arc::new(FlakyStore::new());
        store.save(&key(), &cred("SPENT")).expect("save");
        store.refuse_saves(true);
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
        store.refuse_saves(false);
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

        let store = Arc::new(FlakyStore::new());
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

    /// A store that blocks its thread for a while before it answers, the
    /// way `op` does while the 1Password app waits for approval.
    struct SlowStore {
        held: Credential,
        delay: Duration,
    }

    impl CredentialStore for SlowStore {
        fn load(&self, _key: &CredKey) -> Result<Option<Credential>, StoreError> {
            std::thread::sleep(self.delay);
            Ok(Some(self.held.clone()))
        }
        fn save(&self, _key: &CredKey, _cred: &Credential) -> Result<(), StoreError> {
            Ok(())
        }
        fn delete(&self, _key: &CredKey) -> Result<(), StoreError> {
            Ok(())
        }
        fn kind(&self) -> StoreKind {
            StoreKind::OnePasswordDesktop
        }
    }

    #[tokio::test]
    async fn a_slow_store_does_not_stop_the_runtime() {
        // A single-threaded runtime, as erpc's is. The console's splash
        // is a task on it, and a store read that blocked the thread froze
        // the splash for as long as 1Password took: one frame, then nothing.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(SlowStore {
            held: cred("SLOW"),
            delay: Duration::from_millis(300),
        });
        let client = AuthClient::new().expect("a client");

        let mut ticks = 0;
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let key = key();
        let mut read = std::pin::pin!(current_session(&client, &store, &key, dir.path(), NOW));
        let got = loop {
            tokio::select! {
                got = &mut read => break got,
                _ = tick.tick() => ticks += 1,
            }
        };
        assert_eq!(
            got.expect("the stored session is fine")
                .refresh_token
                .expose_secret(),
            "ref.SLOW.s"
        );
        // About 30; at most one if the read held the thread.
        assert!(ticks >= 10, "the runtime ticked {ticks} times in 300 ms");
    }

    /// A time at which `cred(..)` needs refreshing.
    const EXPIRING: i64 = 1_700_000_000;

    /// Taken by every test that rotates or leaves. What rotations are under
    /// way, and whether the process is leaving, is one record per process,
    /// and a test that leaves would otherwise refuse another's rotation.
    static ROTATIONS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Rotates any refresh token into `cred(tag)`, `delay` after it is
    /// asked, and notes which tokens it was given.
    #[derive(Clone)]
    struct FakeIssuer {
        tag: &'static str,
        delay: Duration,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl FakeIssuer {
        fn new(tag: &'static str, delay: Duration) -> Self {
            Self {
                tag,
                delay,
                seen: Arc::default(),
            }
        }
        fn seen(&self) -> Vec<String> {
            self.seen.lock().expect("not poisoned").clone()
        }
    }

    impl super::Refresher for FakeIssuer {
        fn refresh(
            &self,
            _audience: Audience,
            refresh_token: &SecretString,
            _now: i64,
        ) -> impl Future<Output = Result<Credential, HttpError>> + Send {
            self.seen
                .lock()
                .expect("not poisoned")
                .push(refresh_token.expose_secret().to_owned());
            let (rotated, delay) = (cred(self.tag), self.delay);
            async move {
                tokio::time::sleep(delay).await;
                Ok(rotated)
            }
        }
    }

    #[tokio::test]
    async fn an_expiring_session_is_rotated_and_saved() {
        let _rotations = ROTATIONS.lock().await;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(FlakyStore::new());
        store.save(&key(), &cred("OLD")).expect("save");
        let issuer = FakeIssuer::new("ROTATED", Duration::ZERO);

        let got = current_session(&issuer, &store, &key(), dir.path(), EXPIRING)
            .await
            .expect("rotated");
        assert_eq!(got.refresh_token.expose_secret(), "ref.ROTATED.s");
        assert_eq!(store.refresh_token().as_deref(), Some("ref.ROTATED.s"));
        assert_eq!(issuer.seen(), ["ref.OLD.s"]);
        assert!(!parked_path(dir.path(), Audience::AuthApi).exists());
    }

    #[tokio::test]
    async fn a_rotation_the_store_refuses_is_parked() {
        let _rotations = ROTATIONS.lock().await;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(FlakyStore::new());
        store.save(&key(), &cred("OLD")).expect("save");
        store.refuse_saves(true);
        let issuer = FakeIssuer::new("ROTATED", Duration::ZERO);

        let outcome = current_session(&issuer, &store, &key(), dir.path(), EXPIRING).await;
        let Err(super::SessionError::SavedToFallback { parked, .. }) = outcome else {
            panic!("expected the rotation to be parked: {outcome:?}");
        };
        assert_eq!(parked, parked_path(dir.path(), Audience::AuthApi));
        let parked = read_parked(&parked).expect("readable").expect("parked");
        assert_eq!(
            parked.credential.refresh_token.expose_secret(),
            "ref.ROTATED.s"
        );
        assert!(parked.supersedes(Some(&cred("OLD"))));
        assert_eq!(store.refresh_token().as_deref(), Some("ref.OLD.s"));
    }

    #[tokio::test]
    async fn a_rotation_outlives_a_caller_that_stops_waiting() {
        // Ctrl-C on the console's splash drops the future that asked for
        // the session. Dropped while the refresh was out, the issuer spent
        // the old token and the new one went nowhere.
        let _rotations = ROTATIONS.lock().await;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(FlakyStore::new());
        store.save(&key(), &cred("OLD")).expect("save");
        let issuer = FakeIssuer::new("ROTATED", Duration::from_millis(200));
        {
            let key = key();
            let mut asking =
                std::pin::pin!(current_session(&issuer, &store, &key, dir.path(), EXPIRING));
            while issuer.seen().is_empty() {
                tokio::select! {
                    _ = &mut asking => panic!("done before the caller stopped waiting"),
                    () = tokio::time::sleep(Duration::from_millis(5)) => {}
                }
            }
        }
        let leaving = super::Leaving::start();
        assert!(leaving.rotating(), "the rotation is still under way");

        // The lock is still held, and is released only once the rotation
        // is saved.
        let lock = refresh_lock_path(dir.path(), Audience::AuthApi);
        let probe = Arc::clone(&store);
        let held_once_free = tokio::task::spawn_blocking(move || {
            let _lock = crate::lock::ExclusiveLock::acquire(&lock).expect("the lock");
            probe.refresh_token()
        })
        .await
        .expect("the probe");
        assert_eq!(held_once_free.as_deref(), Some("ref.ROTATED.s"));
        leaving.settled().await;
    }

    #[tokio::test]
    async fn a_process_that_is_leaving_starts_no_rotation() {
        // Deciding to leave and a rotation starting a moment later would
        // spend the old token with nobody left to save the new one.
        let _rotations = ROTATIONS.lock().await;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(FlakyStore::new());
        store.save(&key(), &cred("OLD")).expect("save");
        let issuer = FakeIssuer::new("ROTATED", Duration::ZERO);

        let leaving = super::Leaving::start();
        let outcome = current_session(&issuer, &store, &key(), dir.path(), EXPIRING).await;
        assert!(
            matches!(outcome, Err(super::SessionError::Leaving)),
            "{outcome:?}"
        );
        assert!(issuer.seen().is_empty(), "the issuer was never asked");
        assert_eq!(store.refresh_token().as_deref(), Some("ref.OLD.s"));

        drop(leaving);
        let got = current_session(&issuer, &store, &key(), dir.path(), EXPIRING)
            .await
            .expect("rotations start again");
        assert_eq!(got.refresh_token.expose_secret(), "ref.ROTATED.s");
    }

    /// A store whose saves wait until [`GatedStore::open`] is called, the
    /// way a keyring save waits on an unlock prompt.
    struct GatedStore {
        held: Mutex<Credential>,
        saving: AtomicBool,
        open: (Mutex<bool>, std::sync::Condvar),
    }

    impl GatedStore {
        fn holding(cred: Credential) -> Self {
            Self {
                held: Mutex::new(cred),
                saving: AtomicBool::new(false),
                open: (Mutex::new(false), std::sync::Condvar::new()),
            }
        }
        fn open(&self) {
            *self.open.0.lock().expect("not poisoned") = true;
            self.open.1.notify_all();
        }
        fn refresh_token(&self) -> String {
            let held = self.held.lock().expect("not poisoned");
            held.refresh_token.expose_secret().to_owned()
        }
    }

    impl CredentialStore for GatedStore {
        fn load(&self, _key: &CredKey) -> Result<Option<Credential>, StoreError> {
            Ok(Some(self.held.lock().expect("not poisoned").clone()))
        }
        fn save(&self, _key: &CredKey, cred: &Credential) -> Result<(), StoreError> {
            self.saving.store(true, Ordering::SeqCst);
            let mut open = self.open.0.lock().expect("not poisoned");
            while !*open {
                open = self.open.1.wait(open).expect("not poisoned");
            }
            *self.held.lock().expect("not poisoned") = cred.clone();
            Ok(())
        }
        fn delete(&self, _key: &CredKey) -> Result<(), StoreError> {
            Ok(())
        }
        fn kind(&self) -> StoreKind {
            StoreKind::OsKeychain
        }
    }

    #[tokio::test]
    async fn a_process_that_cannot_wait_parks_what_the_store_has_not_taken() {
        // The store is stuck, and erpc has to go: the new session goes where
        // the next command files it, not nowhere.
        let _rotations = ROTATIONS.lock().await;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(GatedStore::holding(cred("OLD")));
        let issuer = FakeIssuer::new("ROTATED", Duration::ZERO);
        let rotation = tokio::spawn({
            let (issuer, store, dir) = (issuer.clone(), Arc::clone(&store), dir.path().to_owned());
            async move { current_session(&issuer, &store, &key(), &dir, EXPIRING).await }
        });
        while !store.saving.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let leaving = super::Leaving::start();
        assert!(leaving.rotating());
        leaving.answered().await;
        let at = parked_path(dir.path(), Audience::AuthApi);
        let parked: Vec<_> = leaving
            .park()
            .into_iter()
            .map(|p| p.expect("parked"))
            .collect();
        assert_eq!(parked, std::slice::from_ref(&at));
        let record = read_parked(&at).expect("readable").expect("there");
        assert_eq!(
            record.credential.refresh_token.expose_secret(),
            "ref.ROTATED.s"
        );
        assert!(
            record.supersedes(Some(&cred("OLD"))),
            "the next command files it over the spent token"
        );

        // The save lands after all: the parked copy is then of what the
        // store holds, and the next read deletes it.
        store.open();
        rotation
            .await
            .expect("the rotation")
            .expect("saved after all");
        leaving.settled().await;
        drop(leaving);
        assert_eq!(store.refresh_token(), "ref.ROTATED.s");
        current_session(&issuer, &store, &key(), dir.path(), NOW)
            .await
            .expect("the stored session");
        assert!(!at.exists(), "the parked copy is gone");
    }

    #[tokio::test]
    async fn parking_waits_for_a_refresh_the_issuer_has_not_answered() {
        // Nothing comes back from the issuer yet, so there is nothing to
        // park. Leaving then would spend the old token with the new one
        // still on its way.
        let _rotations = ROTATIONS.lock().await;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(GatedStore::holding(cred("OLD")));
        let issuer = FakeIssuer::new("ROTATED", Duration::from_millis(300));
        let rotation = tokio::spawn({
            let (issuer, store, dir) = (issuer.clone(), Arc::clone(&store), dir.path().to_owned());
            async move { current_session(&issuer, &store, &key(), &dir, EXPIRING).await }
        });
        while issuer.seen().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let leaving = super::Leaving::start();
        assert!(leaving.park().is_empty(), "the issuer has not answered");
        let asked = std::time::Instant::now();
        leaving.answered().await;
        assert!(
            asked.elapsed() >= Duration::from_millis(200),
            "answered() waited for the issuer: {:?}",
            asked.elapsed()
        );
        let parked = leaving.park();
        assert_eq!(parked.len(), 1);
        assert!(parked[0].is_ok());

        store.open();
        rotation.await.expect("the rotation").expect("saved");
        leaving.settled().await;
    }

    #[test]
    fn a_rotation_cut_off_before_it_is_saved_parks_what_came_back() {
        // A runtime shutting down drops its tasks. A rotation dropped that
        // way used to count as settled, and the new session went with it.
        let _rotations = ROTATIONS.blocking_lock();
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(GatedStore::holding(cred("OLD")));
        let issuer = FakeIssuer::new("ROTATED", Duration::ZERO);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on({
            let (rotating, dir) = (Arc::clone(&store), dir.path().to_owned());
            let store = Arc::clone(&store);
            async move {
                tokio::spawn(async move {
                    let _ = current_session(&issuer, &rotating, &key(), &dir, EXPIRING).await;
                });
                while !store.saving.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        });
        runtime.shutdown_background();

        let at = parked_path(dir.path(), Audience::AuthApi);
        let record = read_parked(&at).expect("readable").expect("parked");
        assert_eq!(
            record.credential.refresh_token.expose_secret(),
            "ref.ROTATED.s"
        );
        assert!(record.supersedes(Some(&cred("OLD"))));
        // The save is still waiting on its own thread; let it go.
        store.open();
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

        assert_eq!(confirmed, super::Revocation::Confirmed);
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
        assert_eq!(
            confirmed,
            super::Revocation::NotConfirmed,
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
        assert_eq!(confirmed, super::Revocation::NotConfirmed);
        assert!(!at.exists(), "it is still removed");
        assert!(store.refresh_token().is_none());
    }

    #[tokio::test]
    async fn a_sign_out_that_revokes_nothing_at_all_claims_nothing() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = FlakyStore::new();
        let revoker = ChoosyRevoker { refuse: Vec::new() };
        assert_eq!(
            super::sign_out(&revoker, &store, &key(), dir.path())
                .await
                .expect("signed out"),
            super::Revocation::NothingToRevoke,
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
        // Letting the unlink fail quietly was only half
        // of it: the next command found the file, filed it over the fresh
        // sign-in, and the store held a token the sign-in had just revoked.
        // Both cases the review reproduced: the directory still read-only
        // on the next command, and writable again.
        for stays_read_only in [true, false] {
            let dir = tempfile::tempdir().expect("a temporary directory");
            let at = parked_path(dir.path(), Audience::AuthApi);
            park(&at, "OLD-PARKED", "PREVIOUS");
            std::fs::create_dir_all(dir.path().join("locks")).expect("the lock directory");

            let store = Arc::new(FlakyStore::new());
            store.save(&key(), &cred("PREVIOUS")).expect("save");
            let revoker = RecordingRevoker::default();
            let client = AuthClient::new().expect("a client");

            if !hold_files_down(dir.path()) {
                return;
            }
            let leftover = super::store_new_session(
                &revoker,
                store.as_ref(),
                &key(),
                dir.path(),
                &cred("NEW-LOGIN"),
            )
            .await;
            if !stays_read_only {
                release_files(dir.path());
            }
            let next = current_session(&client, &store, &key(), dir.path(), NOW).await;
            release_files(dir.path());

            assert_eq!(
                leftover.expect("signed in").parked,
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

        let store = Arc::new(FlakyStore::new());
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
        // A parked file this build cannot read used to be unlinked
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
            report.parked,
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
        assert_eq!(
            report.parked.map(|r| (r.revoked, r.removed)),
            Some((false, true))
        );
    }

    #[tokio::test]
    async fn a_parked_copy_of_the_stored_session_is_cleared_not_filed() {
        // A save that reported failure but landed: the same live token is
        // in the store and in cleartext on disk. Only the disk copy goes.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let at = parked_path(dir.path(), Audience::AuthApi);
        park(&at, "LANDED", "SPENT");
        let store = Arc::new(FlakyStore::new());
        store.save(&key(), &cred("LANDED")).expect("save");
        let client = AuthClient::new().expect("a client");

        let got = current_session(&client, &store, &key(), dir.path(), NOW)
            .await
            .expect("the stored session is fine");
        assert_eq!(got.refresh_token.expose_secret(), "ref.LANDED.s");
        assert!(!at.exists(), "the cleartext copy is gone");
    }

    /// A store whose one record is from a build this one cannot read.
    struct UnreadableStore {
        held: std::cell::RefCell<Option<Credential>>,
        unreadable: Cell<bool>,
    }

    impl CredentialStore for UnreadableStore {
        fn load(&self, _key: &CredKey) -> Result<Option<Credential>, StoreError> {
            if self.unreadable.get() {
                return Err(StoreError::UnknownVersion {
                    found: 9,
                    expected: 1,
                });
            }
            Ok(self.held.borrow().clone())
        }
        fn save(&self, _key: &CredKey, cred: &Credential) -> Result<(), StoreError> {
            self.unreadable.set(false);
            *self.held.borrow_mut() = Some(cred.clone());
            Ok(())
        }
        fn delete(&self, _key: &CredKey) -> Result<(), StoreError> {
            self.unreadable.set(false);
            *self.held.borrow_mut() = None;
            Ok(())
        }
        fn kind(&self) -> StoreKind {
            StoreKind::File
        }
    }

    fn unreadable_store() -> UnreadableStore {
        UnreadableStore {
            held: std::cell::RefCell::new(None),
            unreadable: Cell::new(true),
        }
    }

    #[tokio::test]
    async fn an_unreadable_stored_session_does_not_block_a_sign_in() {
        // The error said to sign in again, and signing in failed
        // on the same read -- after the operator had approved it, so the
        // new session was revoked as well.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = unreadable_store();
        let revoker = RecordingRevoker::default();
        let report =
            super::store_new_session(&revoker, &store, &key(), dir.path(), &cred("NEW-LOGIN"))
                .await
                .expect("signed in");
        assert!(
            report.previous_unreadable.is_some(),
            "and the operator is told"
        );
        assert_eq!(
            store
                .held
                .borrow()
                .as_ref()
                .map(|c| c.refresh_token.expose_secret().to_owned()),
            Some("ref.NEW-LOGIN.s".to_owned())
        );
    }

    #[tokio::test]
    async fn an_unreadable_stored_session_does_not_block_a_sign_out() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = unreadable_store();
        let revoker = RecordingRevoker::default();
        let confirmed = super::sign_out(&revoker, &store, &key(), dir.path())
            .await
            .expect("signed out");
        assert_eq!(
            confirmed,
            super::Revocation::NotConfirmed,
            "a token nobody could read was not revoked"
        );
        assert!(!store.unreadable.get(), "the record was removed");
    }

    /// A real file store whose file does not parse.
    fn broken_file_store(dir: &Path) -> crate::store::file::FileStore {
        let path = dir.join("credentials.toml");
        std::fs::write(&path, "[sessions]\naccess_token = \"abc\n").expect("write");
        crate::store::file::FileStore::new(path)
    }

    #[tokio::test]
    async fn a_file_store_that_does_not_parse_does_not_block_a_sign_in() {
        // A mock that accepts the save proves nothing about the store that
        // refused it: the real one read the whole file first, failed, and
        // the sign-in was approved in the browser and then revoked.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = broken_file_store(dir.path());
        let revoker = RecordingRevoker::default();
        let report =
            super::store_new_session(&revoker, &store, &key(), dir.path(), &cred("NEW-LOGIN"))
                .await
                .expect("signed in");
        let why = report.previous_unreadable.expect("the operator is told");
        assert!(why.contains("whole file"), "and how much went: {why}");
        let held = store.load(&key()).expect("readable now").expect("present");
        assert_eq!(held.refresh_token.expose_secret(), "ref.NEW-LOGIN.s");
    }

    #[tokio::test]
    async fn a_file_store_that_does_not_parse_does_not_block_a_sign_out() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = broken_file_store(dir.path());
        let revoker = RecordingRevoker::default();
        let confirmed = super::sign_out(&revoker, &store, &key(), dir.path())
            .await
            .expect("signed out");
        assert_eq!(confirmed, super::Revocation::NotConfirmed);
        assert!(!dir.path().join("credentials.toml").exists());
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_reached_still_stops_a_sign_in() {
        // Not the same as unreadable: what it holds may be a live session,
        // and writing over it would strand that.
        struct Unreachable;
        impl CredentialStore for Unreachable {
            fn load(&self, _key: &CredKey) -> Result<Option<Credential>, StoreError> {
                Err(StoreError::Backend {
                    kind: StoreKind::OsKeychain,
                    operation: "read from the keychain",
                    reason: "locked".to_owned(),
                })
            }
            fn save(&self, _key: &CredKey, _cred: &Credential) -> Result<(), StoreError> {
                panic!("must not write over what it could not read")
            }
            fn delete(&self, _key: &CredKey) -> Result<(), StoreError> {
                panic!("must not delete what it could not read")
            }
            fn kind(&self) -> StoreKind {
                StoreKind::OsKeychain
            }
        }
        let dir = tempfile::tempdir().expect("a temporary directory");
        let revoker = RecordingRevoker::default();
        assert!(
            super::store_new_session(&revoker, &Unreachable, &key(), dir.path(), &cred("N"))
                .await
                .is_err()
        );
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
        assert_eq!(leftover, super::SignInReport::default());
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
        assert_eq!(
            super::sign_out(&revoker, &store, &key(), dir.path())
                .await
                .expect("signed out"),
            super::Revocation::Confirmed
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
