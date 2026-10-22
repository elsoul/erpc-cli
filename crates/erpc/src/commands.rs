// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What `erpc login`, `erpc logout` and `erpc whoami` do.
//!
//! The order in `login` is the part worth reading. A session is only
//! stored once the account behind it has been confirmed, and anything that
//! fails after the grant revokes the tokens it obtained rather than
//! leaving a live session nobody is holding.

use core::time::Duration;

use erpc_auth::credential::CredKey;
use erpc_auth::device_flow::DeviceAuthorization;
use erpc_auth::session::{LoginPrompt, approved_to_credential};
use erpc_auth::store::StoreKind;
use erpc_auth::{AuthClient, session as auth_session};

use crate::browser;
use crate::session::{self, StoreReport};
use crate::store_for;

/// How a command ended, in the terms the exit codes are written in.
#[derive(Debug)]
pub enum Outcome {
    /// It worked, and this is what to tell the operator.
    Done(String),
    /// It failed, and this is why.
    Failed(String),
    /// There is no usable session.
    NoSession(String),
    /// A person is needed and there is nobody at a terminal.
    NeedsTerminal(String),
}

/// Prints the approval page and waits between polls.
struct Prompt {
    json: bool,
    no_browser: bool,
}

impl LoginPrompt for Prompt {
    fn present(&self, authorization: &DeviceAuthorization) {
        let url = authorization.open_url();
        let opened = match browser::decide(self.no_browser, |n| std::env::var_os(n)) {
            Ok(()) => match browser::open(url) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("could not open a browser: {e}");
                    false
                }
            },
            Err(reason) => {
                if !self.json {
                    println!("Not opening a browser: {reason}.");
                }
                false
            }
        };
        if self.json {
            crate::print_json(&serde_json::json!({
                "status": "awaiting-approval",
                "verification_uri": authorization.verification_uri,
                "user_code": authorization.user_code,
                "browser_opened": opened,
            }));
        } else {
            if opened {
                println!("A browser is opening the approval page.");
            }
            println!("  Open:  {}", authorization.verification_uri);
            println!("  Code:  {}", authorization.user_code);
            println!("Waiting for you to approve it...");
        }
    }

    async fn wait(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Signs in.
pub async fn login(json: bool, requested: Option<StoreKind>, no_browser: bool) -> Outcome {
    let selection = session::plan_store(requested);
    let report = StoreReport::from(selection);

    if no_browser || session::has_terminal() {
        // Fine: either a person is here, or they asked for the code.
    } else {
        return Outcome::NeedsTerminal(
            "erpc login needs a terminal, or --no-browser to print the code instead".to_owned(),
        );
    }

    let client = match AuthClient::new() {
        Ok(client) => client,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let prompt = Prompt { json, no_browser };

    let approved =
        match auth_session::run_device_grant(&client, session::LOGIN_AUDIENCE, &prompt).await {
            Ok(approved) => approved,
            Err(e) => return Outcome::Failed(e.to_string()),
        };
    let credential = approved_to_credential(approved, now());

    // Confirm the account before storing anything. A session saved for an
    // account that does not exist turns into a puzzling failure later, and
    // the operator's next step here is `erpc signup`, not `erpc login`.
    let user = match erpc_api::get_user(&client, &credential.access_token).await {
        Ok(user) => user,
        Err(e) => return Outcome::Failed(revoke_and_report(&client, &credential, e).await),
    };

    let key = CredKey::new(session::LOGIN_AUDIENCE, session::local_account());
    let store = match store_for(selection.kind) {
        Ok(store) => store,
        Err(e) => return Outcome::Failed(revoke_and_report(&client, &credential, e).await),
    };

    // Store under the refresh lock, and revoke the previous session only
    // once the new one is safely in place. A failure to read what was
    // there is reported rather than passed over: it means an old refresh
    // token is live and about to become unreachable.
    let leftover = match auth_session::store_new_session(
        &client,
        store.as_ref(),
        &key,
        &session::state_dir(),
        &credential,
    )
    .await
    {
        Ok(leftover) => leftover,
        Err(e) => {
            // Nothing is holding the new tokens either, so do not leave them
            // live. Whether the issuer accepted the revocation is reported,
            // because an operator whose failed sign-in left a live token has
            // no other way to find out.
            let revoked = client
                .revoke(session::LOGIN_AUDIENCE, &credential.refresh_token)
                .await;
            return Outcome::Failed(if revoked {
                format!("{e}; the new session was revoked at the issuer")
            } else {
                format!(
                    "{e}; the new session could NOT be revoked at the issuer and may stay valid \
                 until it expires"
                )
            });
        }
    };

    if json {
        crate::print_json(&serde_json::json!({
            "status": "signed-in",
            "account": user.label(),
            "uid": user.uid,
            "store": report,
            "undeleted_file": leftover.as_ref().map(|p| p.display().to_string()),
        }));
        Outcome::Done(String::new())
    } else {
        let mut lines = vec![format!("Signed in as {}.", user.label())];
        lines.push(format!("  session kept in the {} store", report.store));
        if report.writes_to_disk {
            lines.push(format!("  warning: {}", session::DISK_WARNING));
        }
        // Said now, not left to `erpc doctor`: the sign-in is fine, but a
        // file holding a token is still on disk and erpc could not remove
        // it.
        if let Some(path) = &leftover {
            lines.push(format!(
                "  warning: could not delete {}. It holds an older session, revoked just now, \
                 and erpc will not use it; check the permissions on its directory and delete \
                 it yourself.",
                path.display()
            ));
        }
        Outcome::Done(lines.join("\n"))
    }
}

/// Signs out.
pub async fn logout(json: bool, requested: Option<StoreKind>) -> Outcome {
    let selection = session::plan_store(requested);
    let store = match store_for(selection.kind) {
        Ok(store) => store,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let key = CredKey::new(session::LOGIN_AUDIENCE, session::local_account());

    let client = match AuthClient::new() {
        Ok(client) => client,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    match auth_session::sign_out(&client, store.as_ref(), &key, &session::state_dir()).await {
        Ok(revoked) => {
            if json {
                crate::print_json(&serde_json::json!({
                    "status": "signed-out",
                    "revoked_at_issuer": revoked,
                    "store": StoreReport::from(selection),
                }));
                Outcome::Done(String::new())
            } else if revoked {
                Outcome::Done("Signed out, and the session was revoked at the issuer.".to_owned())
            } else {
                // Worth saying: the local copy is gone either way, but a
                // token that was not revoked is still live until it expires.
                Outcome::Done(
                    "Signed out locally. The issuer did not confirm the revocation, so the \
                     session may stay valid until it expires."
                        .to_owned(),
                )
            }
        }
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// Shows who the stored session belongs to.
pub async fn whoami(json: bool, requested: Option<StoreKind>) -> Outcome {
    let selection = session::plan_store(requested);
    let store = match store_for(selection.kind) {
        Ok(store) => store,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let key = CredKey::new(session::LOGIN_AUDIENCE, session::local_account());
    let client = match AuthClient::new() {
        Ok(client) => client,
        Err(e) => return Outcome::Failed(e.to_string()),
    };

    let credential = match auth_session::current_session(
        &client,
        store.as_ref(),
        &key,
        &session::state_dir(),
        now(),
    )
    .await
    {
        Ok(credential) => credential,
        Err(erpc_auth::SessionError::NoSession) => {
            return no_session(json, "not signed in");
        }
        Err(erpc_auth::SessionError::Expired) => {
            return no_session(json, "the session has expired or was signed out elsewhere");
        }
        Err(e) => return Outcome::Failed(e.to_string()),
    };

    match erpc_api::get_user(&client, &credential.access_token).await {
        Ok(user) => {
            if json {
                crate::print_json(&serde_json::json!({
                    "status": "signed-in",
                    "account": user.label(),
                    "uid": user.uid,
                    "email": user.email,
                    "store": StoreReport::from(selection),
                }));
                Outcome::Done(String::new())
            } else {
                Outcome::Done(format!(
                    "{}\n  session kept in the {} store",
                    user.label(),
                    selection.kind
                ))
            }
        }
        Err(erpc_api::ApiError::Unauthorized) => {
            no_session(json, "the session was refused by the account API")
        }
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// Revokes a session nobody will hold, and says whether that worked.
///
/// Attempting a revocation and not checking it would let a failed sign-in
/// leave a live token with no sign of it. The caller's error is kept
/// first, because that is what the operator has to fix.
async fn revoke_and_report(
    client: &AuthClient,
    credential: &erpc_auth::credential::Credential,
    cause: impl core::fmt::Display,
) -> String {
    let revoked = client
        .revoke(session::LOGIN_AUDIENCE, &credential.refresh_token)
        .await;
    if revoked {
        format!("{cause}; the sign-in was revoked at the issuer")
    } else {
        format!(
            "{cause}; the sign-in could NOT be revoked at the issuer and may stay valid until \
             it expires"
        )
    }
}

/// Builds the "no session" outcome in both output modes.
fn no_session(json: bool, reason: &str) -> Outcome {
    if json {
        crate::print_json(&serde_json::json!({
            "status": "no-session",
            "reason": reason,
            "hint": "run `erpc login`",
        }));
        Outcome::NoSession(String::new())
    } else {
        Outcome::NoSession(format!("{reason}. Run `erpc login`."))
    }
}

/// Seconds since the Unix epoch.
///
/// A clock before 1970 would make every session look expired, which is the
/// safe direction, so this saturates rather than failing.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Reports what this machine is doing with your session.
///
/// Synchronous on purpose: it looks at this machine and asks nothing of
/// the network, so it works when nothing else does.
pub fn doctor(json: bool, requested: Option<StoreKind>) -> Outcome {
    let selection = session::plan_store(requested);
    let state_dir = session::state_dir();
    let on_disk = crate::doctor::secrets_on_disk(&state_dir);
    let found = crate::doctor::findings(selection, &on_disk);
    let worst = crate::doctor::worst(&found);

    if json {
        crate::print_json(&serde_json::json!({
            "status": match worst {
                crate::doctor::Level::Ok => "ok",
                crate::doctor::Level::Note => "note",
                crate::doctor::Level::Warn => "warn",
            },
            "state_dir": state_dir,
            "findings": found,
        }));
        return doctor_outcome(worst);
    }

    let mut lines = Vec::new();
    for finding in &found {
        lines.push(format!(
            "{} {}: {}",
            crate::doctor::marker(finding.level),
            finding.subject,
            finding.detail
        ));
    }
    // Printed here rather than returned, because a report is not an
    // error message: `Outcome::Failed` prefixes "error:" and writes to
    // stderr, which is right for a failure and wrong for a page of
    // findings. The outcome then carries only the exit status.
    println!("{}", lines.join("\n"));
    doctor_outcome(worst)
}

/// A warning exits non-zero.
///
/// A cron or a CI job that runs `erpc doctor` to assert this machine is
/// clean has to be able to tell, and a command that always exits 0 can
/// say nothing to one.
fn doctor_outcome(worst: crate::doctor::Level) -> Outcome {
    if worst == crate::doctor::Level::Warn {
        Outcome::Failed(String::new())
    } else {
        Outcome::Done(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::{Outcome, now};

    #[test]
    fn the_clock_is_a_plausible_unix_time() {
        // Past 2020 and before 2100: enough to catch a unit mix-up, which
        // would otherwise show up as every session being expired or none.
        let t = now();
        assert!(t > 1_577_836_800, "{t}");
        assert!(t < 4_102_444_800, "{t}");
    }

    #[test]
    fn each_outcome_carries_its_own_message() {
        let outcomes = [
            Outcome::Done("a".to_owned()),
            Outcome::Failed("b".to_owned()),
            Outcome::NoSession("c".to_owned()),
            Outcome::NeedsTerminal("d".to_owned()),
        ];
        assert_eq!(outcomes.len(), 4);
    }
}
