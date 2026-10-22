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
         The new tokens are at {parked} (0600); erpc will file them away and delete \
         that file on the next run"
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

    // A session parked by an earlier rotation is the newest one there is:
    // the token it replaced is already spent. File it away before reading,
    // or the store's older copy would be used and then refreshed with a
    // token the issuer has already rotated, which revokes the family.
    if let Some(parked) = crate::lock::take_parked(&parked_path(state_dir, key.audience()))? {
        store.save(key, &parked)?;
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
        Err(HttpError::Status { status: 400, .. }) => return Err(SessionError::Expired),
        Err(e) => return Err(e.into()),
    };

    if let Err(e) = store.save(key, &rotated) {
        // The issuer has already rotated: the old refresh token is spent
        // and the new one exists only here. Losing it now would mean a
        // forced sign-in, so it is parked where the next run can pick it
        // up, and the operator is told where.
        let parked = parked_path(state_dir, key.audience());
        crate::lock::park_credential(&parked, &rotated)?;
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
/// Holds the same lock a refresh does, for the whole load-revoke-delete
/// sequence. Without it, a refresh running concurrently rotates the token
/// this function is about to revoke: sign-out then revokes the spent one,
/// reports success, and leaves the rotated token live at the issuer with
/// nobody holding it -- or writes it back into the store after the delete,
/// so a sign-out that reported success leaves a usable session behind.
///
/// Returns whether the issuer confirmed the revocation.
///
/// # Errors
///
/// Returns [`SessionError::Store`] when the lock cannot be taken or the
/// session cannot be removed.
pub async fn sign_out(
    client: &AuthClient,
    store: &dyn CredentialStore,
    key: &CredKey,
    state_dir: &Path,
) -> Result<bool, SessionError> {
    let _guard =
        crate::lock::ExclusiveLock::acquire(&refresh_lock_path(state_dir, key.audience()))?;
    let revoked = match store.load(key)? {
        Some(existing) => client.revoke(key.audience(), &existing.refresh_token).await,
        None => false,
    };
    store.delete(key)?;
    Ok(revoked)
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
/// # Errors
///
/// Returns [`SessionError`] when the lock cannot be taken or the session
/// cannot be stored. A failure to read what was there before is reported
/// rather than passed over: it means an old refresh token is still live
/// and is about to become unreachable.
pub async fn store_new_session(
    client: &AuthClient,
    store: &dyn CredentialStore,
    key: &CredKey,
    state_dir: &Path,
    credential: &Credential,
) -> Result<(), SessionError> {
    let _guard =
        crate::lock::ExclusiveLock::acquire(&refresh_lock_path(state_dir, key.audience()))?;
    let previous = store.load(key)?;
    store.save(key, credential)?;
    if let Some(previous) = previous {
        client.revoke(key.audience(), &previous.refresh_token).await;
    }
    Ok(())
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
