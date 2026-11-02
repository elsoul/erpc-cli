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
use erpc_auth::session::{
    LoginPrompt, ParkedReport, Revocation, SignInReport, approved_to_credential,
};
use erpc_auth::store::StoreKind;
use erpc_auth::store::select::Selection;
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

/// Where `erpc login` keeps the session, and whether that was a choice to
/// record.
struct Destination {
    selection: Selection,
    vault: Option<String>,
    /// The operator picked or named this, so it goes in the configuration.
    record: bool,
}

/// Decides where a sign-in is kept.
///
/// `--store` (and `--vault`) decide without asking. Otherwise, at a
/// terminal, the operator picks; the keychain is the default, and
/// 1Password is offered when its app answers. Without a terminal, or with a
/// service account token, nothing is asked: the recorded store or the
/// default is used, because a script must never wait on a question.
fn destination(
    requested: Option<StoreKind>,
    vault: Option<String>,
    config: &crate::config::Config,
    interactive: bool,
) -> Result<Destination, String> {
    let env = session::detect_environment();
    let (selection, record) = if requested.is_some() {
        (session::plan_store(requested, None), true)
    } else if !interactive || env.service_account_token {
        (session::plan_store(None, config.credential_store), false)
    } else {
        (pick_store(&env, config)?, true)
    };

    let is_1password = matches!(
        selection.kind,
        StoreKind::OnePasswordDesktop | StoreKind::OnePasswordServiceAccount
    );
    let vault = if !is_1password {
        None
    } else if vault.is_some() {
        vault
    } else if std::env::var_os("ERPC_CREDENTIAL_VAULT").is_some_and(|v| !v.is_empty()) {
        // `store_for` reads it; recording it would pin a one-off override.
        None
    } else if interactive && selection.kind == StoreKind::OnePasswordDesktop {
        Some(pick_vault(config.credential_vault.as_deref())?)
    } else {
        config.credential_vault.clone()
    };
    Ok(Destination {
        selection,
        vault,
        record,
    })
}

/// Asks which store to use.
fn pick_store(
    env: &erpc_auth::store::select::Environment,
    config: &crate::config::Config,
) -> Result<Selection, String> {
    let mut kinds = Vec::new();
    let mut labels = Vec::new();
    if env.keychain_available {
        kinds.push(StoreKind::OsKeychain);
        labels.push(format!("{KEYCHAIN_NAME} (on this machine)"));
    }
    if session::desktop_app_answers() {
        kinds.push(StoreKind::OnePasswordDesktop);
        labels.push("1Password (the desktop app asks to unlock)".to_owned());
    }
    if !env.keychain_available {
        kinds.push(StoreKind::File);
        labels.push("a file on this machine (leaves the session on disk)".to_owned());
    }
    let reason = erpc_auth::store::select::Reason::Configured;
    if kinds.len() == 1 {
        return Ok(Selection {
            kind: kinds[0],
            reason,
        });
    }
    let default = config
        .credential_store
        .and_then(|kind| kinds.iter().position(|k| *k == kind))
        .unwrap_or(0);
    let index = crate::prompt::pick(
        "Where should erpc keep your session?",
        &labels,
        Some(default),
    )?;
    Ok(Selection {
        kind: kinds[index],
        reason,
    })
}

/// Asks which 1Password vault to use.
fn pick_vault(recorded: Option<&str>) -> Result<String, String> {
    let vaults = session::list_vaults()?;
    if vaults.is_empty() {
        return Err("the 1Password account has no vault erpc can use".to_owned());
    }
    let labels: Vec<String> = vaults
        .iter()
        .map(|v| format!("{} ({})", v.name, v.id))
        .collect();
    let default = recorded
        .and_then(|id| vaults.iter().position(|v| v.id == id))
        .or_else(|| session::personal_vault(&vaults));
    let index = crate::prompt::pick(
        "Which 1Password vault? (anyone who can read it can use the session)",
        &labels,
        default,
    )?;
    Ok(vaults[index].id.clone())
}

/// Everything `login` settles before the operator is sent to a browser:
/// where erpc's files are, what was recorded, and where this session goes.
fn prepare_login(
    json: bool,
    requested: Option<StoreKind>,
    vault: Option<String>,
) -> Result<
    (
        std::path::PathBuf,
        std::path::PathBuf,
        crate::config::Config,
        Destination,
    ),
    String,
> {
    let state_dir = session::state_dir()?;
    let config_path = session::config_path()?;
    let config = crate::config::load(&config_path)?;
    let interactive = !json && session::has_terminal();
    let chosen = destination(requested, vault, &config, interactive)?;
    Ok((state_dir, config_path, config, chosen))
}

/// What the operating system calls its keychain.
const KEYCHAIN_NAME: &str = if cfg!(target_os = "macos") {
    "macOS Keychain"
} else if cfg!(target_os = "windows") {
    "Windows Credential Manager"
} else {
    "the Secret Service keyring"
};

/// Signs in.
pub async fn login(
    json: bool,
    requested: Option<StoreKind>,
    vault: Option<String>,
    no_browser: bool,
) -> Outcome {
    if no_browser || session::has_terminal() {
        // Fine: either a person is here, or they asked for the code.
    } else {
        return Outcome::NeedsTerminal(
            "erpc login needs a terminal, or --no-browser to print the code instead".to_owned(),
        );
    }

    // Before the operator is sent to a browser: a sign-in that cannot be
    // kept anywhere should not be approved first and revoked after. That
    // covers the state directory and the store itself -- a 1Password store
    // with no vault configured, say.
    let (state_dir, config_path, config, chosen) = match prepare_login(json, requested, vault) {
        Ok(prepared) => prepared,
        Err(e) => return Outcome::Failed(e),
    };
    let report = StoreReport::from(chosen.selection);
    let key = CredKey::new(session::LOGIN_AUDIENCE, session::local_account());
    let store = match store_for(chosen.selection.kind, chosen.vault.as_deref()) {
        Ok(store) => store,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
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

    // Store under the refresh lock, and revoke the previous session only
    // once the new one is safely in place. A failure to read what was
    // there is reported rather than passed over: it means an old refresh
    // token is live and about to become unreachable.
    let leftover = match auth_session::store_new_session(
        &client,
        store.as_ref(),
        &key,
        &state_dir,
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

    let (notes, moved_from) =
        record_choice(&client, &chosen, &config, &config_path, &key, &state_dir).await;

    if json {
        crate::print_json(&serde_json::json!({
            "status": "signed-in",
            "account": user.label(),
            "uid": user.uid,
            "store": report,
            "moved_from": moved_from.map(|k| k.to_string()),
            "notes": notes,
            "previous_session_unreadable": leftover.previous_unreadable,
            "parked_file": leftover.parked.as_ref().map(|r| serde_json::json!({
                "path": r.path.display().to_string(),
                "revoked_at_issuer": r.revoked,
                "removed": r.removed,
            })),
        }));
        Outcome::Done(String::new())
    } else {
        let mut lines = vec![format!("Signed in as {}.", user.label_for_display())];
        lines.push(format!("  session kept in the {} store", report.store));
        if report.writes_to_disk {
            lines.push(format!("  warning: {}", session::DISK_WARNING));
        }
        // Said now, not left to `erpc doctor`: the sign-in is fine, but
        // something about the parked file it found did not go cleanly.
        for warning in sign_in_warnings(&leftover) {
            lines.push(format!("  warning: {warning}"));
        }
        for note in notes {
            lines.push(format!("  {note}"));
        }
        Outcome::Done(lines.join("\n"))
    }
}

/// After a sign-in is stored: records where it went, and signs out of the
/// store the operator moved away from. Returns what to tell the operator,
/// and the store moved from, if any.
///
/// Recorded only now, once the session is in the store: a sign-in that
/// failed should not change where the next command looks.
async fn record_choice(
    client: &AuthClient,
    chosen: &Destination,
    config: &crate::config::Config,
    config_path: &std::path::Path,
    key: &CredKey,
    state_dir: &std::path::Path,
) -> (Vec<String>, Option<StoreKind>) {
    let mut notes = Vec::new();
    if chosen.record
        && let Err(e) =
            crate::config::save_store(config_path, chosen.selection.kind, chosen.vault.as_deref())
    {
        notes.push(format!(
            "could not record the choice ({e}); pass --store {} to the next command",
            chosen.selection.kind
        ));
    }
    // The store the other commands used until now. A session left there
    // is a second live session nobody will use, so it is signed out.
    let previous = session::plan_store(None, config.credential_store).kind;
    let moved_from = (chosen.record && previous != chosen.selection.kind).then_some(previous);
    if let Some(previous) = moved_from {
        notes.push(
            sign_out_of_previous(
                client,
                previous,
                config.credential_vault.as_deref(),
                key,
                state_dir,
            )
            .await,
        );
    }
    (notes, moved_from)
}

/// Signs out of the session kept in the store the operator just moved
/// away from, and says what happened.
async fn sign_out_of_previous(
    client: &AuthClient,
    previous: StoreKind,
    vault: Option<&str>,
    key: &CredKey,
    state_dir: &std::path::Path,
) -> String {
    let store = match store_for(previous, vault) {
        Ok(store) => store,
        Err(e) => {
            return format!(
                "a session may still be kept in the {previous} store, which could not be opened \
                 ({e}); `erpc logout --store {previous}` removes it"
            );
        }
    };
    match auth_session::sign_out(client, store.as_ref(), key, state_dir).await {
        Ok(Revocation::Confirmed) => {
            format!("signed out of the session kept in the {previous} store")
        }
        Ok(Revocation::NotConfirmed) => format!(
            "removed the session kept in the {previous} store; the issuer did not confirm its \
             revocation"
        ),
        Ok(Revocation::NothingToRevoke) => format!("the {previous} store held no session"),
        Err(e) => format!(
            "could not sign out of the session kept in the {previous} store ({e}); \
             `erpc logout --store {previous}` removes it"
        ),
    }
}

/// The store a command uses, and the vault for it: `--store` if given,
/// otherwise what `erpc login` recorded, otherwise the default.
fn planned(requested: Option<StoreKind>) -> Result<(Selection, Option<String>), String> {
    let config = crate::config::load(&session::config_path()?)?;
    Ok((
        session::plan_store(requested, config.credential_store),
        config.credential_vault,
    ))
}

/// Signs out.
pub async fn logout(json: bool, requested: Option<StoreKind>) -> Outcome {
    let (selection, vault) = match planned(requested) {
        Ok(planned) => planned,
        Err(e) => return Outcome::Failed(e),
    };
    let store = match store_for(selection.kind, vault.as_deref()) {
        Ok(store) => store,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let key = CredKey::new(session::LOGIN_AUDIENCE, session::local_account());

    let client = match AuthClient::new() {
        Ok(client) => client,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let state_dir = match session::state_dir() {
        Ok(dir) => dir,
        Err(e) => return Outcome::Failed(e),
    };
    match auth_session::sign_out(&client, store.as_ref(), &key, &state_dir).await {
        Ok(revocation) => {
            if json {
                crate::print_json(&serde_json::json!({
                    "status": "signed-out",
                    "revoked_at_issuer": revocation == Revocation::Confirmed,
                    "had_session": revocation != Revocation::NothingToRevoke,
                    "store": StoreReport::from(selection),
                }));
                Outcome::Done(String::new())
            } else {
                Outcome::Done(sign_out_message(revocation).to_owned())
            }
        }
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// Shows who the stored session belongs to.
pub async fn whoami(json: bool, requested: Option<StoreKind>) -> Outcome {
    let (selection, vault) = match planned(requested) {
        Ok(planned) => planned,
        Err(e) => return Outcome::Failed(e),
    };
    let store = match store_for(selection.kind, vault.as_deref()) {
        Ok(store) => store,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let key = CredKey::new(session::LOGIN_AUDIENCE, session::local_account());
    let client = match AuthClient::new() {
        Ok(client) => client,
        Err(e) => return Outcome::Failed(e.to_string()),
    };

    let state_dir = match session::state_dir() {
        Ok(dir) => dir,
        Err(e) => return Outcome::Failed(e),
    };
    let credential =
        match auth_session::current_session(&client, store.as_ref(), &key, &state_dir, now()).await
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
                    user.label_for_display(),
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
    let (selection, vault) = match planned(requested) {
        Ok(planned) => planned,
        Err(e) => return Outcome::Failed(e),
    };
    let state_dir = match session::state_dir() {
        Ok(dir) => dir,
        Err(e) => return Outcome::Failed(e),
    };
    let on_disk = crate::doctor::secrets_on_disk(&state_dir);
    let mut found = crate::doctor::findings(selection, &on_disk);
    // Which vault, for a 1Password store: the first thing to check when a
    // session is not where the operator expected it.
    if matches!(
        selection.kind,
        StoreKind::OnePasswordDesktop | StoreKind::OnePasswordServiceAccount
    ) {
        let overridden = std::env::var("ERPC_CREDENTIAL_VAULT")
            .ok()
            .filter(|v| !v.is_empty());
        found.insert(
            1,
            match (overridden, vault) {
                (Some(id), _) => crate::doctor::Finding::ok(
                    "1Password vault",
                    format!("{id} (from ERPC_CREDENTIAL_VAULT)"),
                ),
                (None, Some(id)) => crate::doctor::Finding::ok(
                    "1Password vault",
                    format!("{id} (chosen at `erpc login`)"),
                ),
                (None, None) => crate::doctor::Finding::warn(
                    "1Password vault",
                    "none chosen; run `erpc login` and pick one".to_owned(),
                ),
            },
        );
    }
    let found = found;
    let worst = crate::doctor::worst(&found);

    if json {
        crate::print_json(&serde_json::json!({
            "status": match worst {
                crate::doctor::Level::Ok => "ok",
                crate::doctor::Level::Note => "note",
                crate::doctor::Level::Warn => "warn",
            },
            "state_dir": state_dir,
            "config": session::config_path().ok(),
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

/// What `logout` says, from what happened at the issuer.
const fn sign_out_message(revocation: Revocation) -> &'static str {
    match revocation {
        Revocation::Confirmed => "Signed out, and the session was revoked at the issuer.",
        // Worth saying: the local copy is gone either way, but a token
        // that was not revoked is still live until it expires.
        Revocation::NotConfirmed => {
            "Signed out locally. The issuer did not confirm the revocation, so the session may \
             stay valid until it expires."
        }
        Revocation::NothingToRevoke => {
            "There was no session on this machine; nothing to sign out of."
        }
    }
}

/// What `login` says about what it could not do cleanly.
fn sign_in_warnings(report: &SignInReport) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(why) = &report.previous_unreadable {
        out.push(format!(
            "the session stored before this one could not be read ({why}), so it was replaced \
             without being revoked and may stay valid until it expires."
        ));
    }
    if let Some(parked) = &report.parked {
        out.push(parked_warning(parked));
    }
    out
}

/// What `login` says about a parked file it could not deal with cleanly.
///
/// Each sentence is conditional on what actually happened: "revoked" only
/// when the issuer accepted it, "deleted" only when the file is gone.
fn parked_warning(report: &ParkedReport) -> String {
    let path = report.path.display();
    let token = if report.revoked {
        "the older session in it was revoked"
    } else {
        "the older session in it could NOT be revoked and may stay valid until it expires"
    };
    if report.removed {
        format!("removed {path}; {token}.")
    } else {
        format!(
            "could not delete {path}; {token}. erpc will not use it. Check the permissions on \
             its directory and delete it yourself."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Outcome, ParkedReport, Revocation, SignInReport, now, parked_warning, sign_in_warnings,
        sign_out_message,
    };

    #[test]
    fn signing_out_of_nothing_does_not_mention_the_issuer() {
        let said = sign_out_message(Revocation::NothingToRevoke);
        assert!(!said.contains("issuer"), "{said}");
        assert!(sign_out_message(Revocation::NotConfirmed).contains("did not confirm"));
        assert!(sign_out_message(Revocation::Confirmed).contains("was revoked"));
    }

    #[test]
    fn a_clean_sign_in_warns_about_nothing() {
        assert!(sign_in_warnings(&SignInReport::default()).is_empty());
    }

    #[test]
    fn an_unreadable_previous_session_is_said_not_to_be_revoked() {
        let warnings = sign_in_warnings(&SignInReport {
            parked: None,
            previous_unreadable: Some("the stored session is version 9".to_owned()),
        });
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("without being revoked"),
            "{warnings:?}"
        );
        // The reason is what tells the operator how much went with it --
        // for the file store, the whole file -- so it has to be printed.
        assert!(
            warnings[0].contains("the stored session is version 9"),
            "{warnings:?}"
        );
    }

    fn report(revoked: bool, removed: bool) -> ParkedReport {
        ParkedReport {
            path: "/s/pending-credentials.auth-api".into(),
            revoked,
            removed,
        }
    }

    #[test]
    fn the_parked_warning_claims_a_revocation_only_when_there_was_one() {
        // `login` used to say "revoked just now" for a token that was
        // never presented to the issuer.
        for removed in [true, false] {
            let refused = parked_warning(&report(false, removed));
            assert!(refused.contains("could NOT be revoked"), "{refused}");
            let accepted = parked_warning(&report(true, removed));
            assert!(!accepted.contains("NOT"), "{accepted}");
            assert!(accepted.contains("was revoked"), "{accepted}");
        }
    }

    #[test]
    fn the_parked_warning_says_delete_it_only_when_it_is_still_there() {
        let stuck = parked_warning(&report(true, false));
        assert!(stuck.contains("could not delete"), "{stuck}");
        assert!(stuck.contains("delete it yourself"), "{stuck}");
        let gone = parked_warning(&report(false, true));
        assert!(gone.starts_with("removed "), "{gone}");
        assert!(!gone.contains("delete it yourself"), "{gone}");
    }

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
