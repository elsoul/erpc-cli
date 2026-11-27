// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker deploy` to an environment kept in the ERPC account: what a
//! deploy refuses there before anything is reached, the server facts the
//! deploy changes written to the account instead of `erpc.toml`, the record
//! that the app runs before the key is handed over, and the deploy put on
//! record once the app runs.
//!
//! So far a deploy there ships a release to the server the account names,
//! and buys nothing and changes no line. Every write replaces the whole
//! environment, so each is built from the record the account last answered
//! with, changing only what this deploy changed, and expects that record's
//! revision: a write another sign-in made in between is refused, not
//! written over. What the account then says of the server is pinned again
//! only when it reaches the server the way this machine wrote it.

use erpc_api::worker::{
    self as account, Deployed, DeployedApp, DeployedSecret, DeployedWaf, EnvDetail, PutEnv,
    SecretSource, Service, WorkerError,
};
use erpc_worker::manifest::{Line, LineKind, Manifest, SecretRef};

use crate::cli::error::{CliError, Code};
use crate::worker::App;
use crate::worker::account::{self as kept, Account, Anchor, Kept};
use crate::worker::deploy::Where;

fn failed(message: String) -> CliError {
    CliError::new(Code::Failed, message)
}

/// The most settings and secrets the account keeps the names of, each.
pub(crate) const NAMES_MAX: usize = 128;

/// The most addresses the account keeps in each firewall list.
const ALLOW_MAX: usize = crate::worker::firewall::ACCOUNT_SSH_MAX;

/// Refuses, before the account or the server is reached, the options a
/// deploy to an environment kept in the account does not take yet: choose
/// or buy a server, add, change or forget a line, or keep the environment
/// elsewhere.
pub(crate) fn refuse_options(at: &Where, app: &App) -> Result<(), CliError> {
    let asked = at.host.is_some()
        || at.user.is_some()
        || at.port.is_some()
        || at.fingerprint.is_some()
        || at.vps.is_some()
        || at.new_vps
        || at.region.is_some()
        || at.plan.is_some()
        || !at.lines.is_empty()
        || at.udp_port.is_some()
        || at.udp_region.is_some()
        || at.udp_any_source
        || at.vault.is_some()
        || at.inline
        || !at.forget_lines.is_empty();
    if asked {
        return Err(
            failed(t!("worker_deploy_account.not_yet", env = app.env.as_str())).hint(t!(
                "worker_deploy_account.not_yet_hint",
                scope = app.scope()
            )),
        );
    }
    Ok(())
}

/// Refuses a record a deploy cannot carry yet: a server coming in or going
/// out. Said as nothing deployed: this is asked before anything is.
pub(crate) fn refuse_record(app: &App, record: &EnvDetail) -> Result<(), CliError> {
    record_carried(app, record).map_err(nothing_deployed)
}

/// What a deploy of the environment `kept` keeps in the account goes on
/// with, or why it does not, before anything is built, bought or changed:
/// a record it can carry ([`refuse_record`]), lists of who may reach SSH
/// and the app that erpc puts on the server as they are (the account
/// holds them to none of erpc.toml's checks where they are written), and
/// the lines in use ([`with_lines`]).
/// [`ready`], and what changed in the account's list of who may reach the
/// app since this machine last put it on the server, said on stderr before
/// the deploy acts, and agreed to (`--yes`, or a yes at a terminal) when
/// anything did: the deploy puts that list on the server.
pub(crate) fn ready_shown(
    app: &App,
    kept: &Kept,
    pins: &std::path::Path,
    yes: bool,
) -> Result<Manifest, CliError> {
    let m = ready(app, kept)?;
    if let Some(line) = crate::worker::firewall::app_changes_of(kept, pins, app) {
        crate::node::common::Say { quiet: false }.line(&line);
        crate::node::common::go_ahead(yes, &t!("worker_deploy_account.nothing_deployed_yet"))?;
    }
    Ok(m)
}

pub(crate) fn ready(app: &App, kept: &Kept) -> Result<Manifest, CliError> {
    refuse_record(app, &kept.record)?;
    let env = crate::worker::env_of(&kept.manifest, app)?;
    crate::worker::firewall::account_lists_usable(
        &kept.manifest,
        env,
        &crate::worker::firewall::Unread::of(&kept.record),
        &app.scope(),
    )
    .map_err(nothing_deployed)?;
    with_lines(app, kept)
}

/// `e`, said as refused before anything was deployed.
fn nothing_deployed(e: CliError) -> CliError {
    let message = t!("worker_deploy_account.nothing_deployed", why = e.message);
    CliError { message, ..e }
}

/// Why a deploy cannot carry `record`, said without what became of the
/// deploy: before anything, or at the hand-over.
fn record_carried(app: &App, record: &EnvDetail) -> Result<(), CliError> {
    if record
        .servers
        .iter()
        .any(|s| s.slot != account::Slot::Active)
    {
        return Err(
            failed(t!("worker_deploy_account.moving", env = app.env.as_str()))
                .hint(t!("worker_deploy_account.moving_hint", scope = app.scope())),
        );
    }
    Ok(())
}

/// Whether a line the account names is ended: gone from it, or cancelled.
fn ended(state: &account::State) -> bool {
    *state == account::State::Gone || state.as_str() == "cancelled"
}

/// `kept`'s manifest, with the lines the account names that are in use, so
/// that the app is handed their endpoints as it is for an environment kept
/// in `erpc.toml`. A line is named by the account's own id: this
/// environment is never saved to `erpc.toml`. An ended line is left out.
/// Refused: a UDP Forwarding line, a line not ready yet or not active (held
/// for maintenance, or ending), a kind this erpc does not know, two lines
/// of one kind, and an endpoint not in its form.
pub(crate) fn with_lines(app: &App, kept: &Kept) -> Result<Manifest, CliError> {
    let mut m = kept.manifest.clone();
    let lines = lines_in_use(app, &kept.record).map_err(nothing_deployed)?;
    if let Some(env) = m.env.get_mut(&app.env) {
        env.lines = lines;
    }
    Ok(m)
}

/// Why a line in `state`, not active, is not handed to the app, with what
/// is known to bring it back. A line is never said to be ended: a state
/// that could come back would be lost for good. Only what the account says
/// a state means is said of it: a line being set up comes up; one under
/// maintenance may be ERPC's maintenance or being ended, which the state
/// does not tell apart; one suspended is stopped, most often for ERPC
/// Credit or a payment, and said the same whatever its `hourly` says (a
/// line in a Bundle follows the Bundle's billing): it may resume once
/// what is due is met, by the hour, by the period or by card, as the
/// account decides; an Unlimited line can be ended if left so, and a gRPC
/// or Shreds line paid by the hour, or part of a bundle paid by the hour,
/// is normally ended at once, so it is said to act now; a line of a kind
/// this erpc does not know is said as any other state. A gRPC or Shreds
/// line available has no address registered yet. Any other state is said
/// as it is.
fn not_active(app: &App, (kind, id): (&str, &str), state: &account::State) -> CliError {
    let env = app.env.as_str();
    let scope = app.scope();
    let state = state.as_str();
    let hint = match state {
        "provisioning" | "applying" => {
            return failed(t!(
                "worker_deploy_account.line_coming_up",
                env,
                kind,
                id,
                state
            ))
            .hint(t!("worker_deploy_account.line_coming_up_hint", scope));
        }
        "maintenance" => t!("worker_deploy_account.line_maintenance_hint", scope),
        // A suspended line is said the same, whatever its `hourly` says:
        // which way brings it back is the account's to decide, and a line
        // in a Bundle follows the Bundle's billing. Every way it may come
        // back is said, none as sure. A gRPC or Shreds line paid by the hour, or
        // part of a bundle paid by the hour, is normally ended at once.
        "suspended" if matches!(kind, "grpc" | "shreds") => {
            t!("worker_deploy_account.line_suspended_now_hint", scope)
        }
        "suspended" if kind == "unlimited" => {
            t!("worker_deploy_account.line_suspended_hint", scope)
        }
        "available" if matches!(kind, "grpc" | "shreds") => {
            t!("worker_deploy_account.line_available_hint", scope)
        }
        _ => t!("worker_deploy_account.line_other_hint", scope),
    };
    failed(t!(
        "worker_deploy_account.line_not_active",
        env,
        kind,
        id,
        state
    ))
    .hint(hint)
}

/// The lines `record` names that are in use, as [`with_lines`] hands them
/// to the app, or why one cannot be.
pub(crate) fn lines_in_use(app: &App, record: &EnvDetail) -> Result<Vec<Line>, CliError> {
    let env = app.env.as_str();
    let mut lines: Vec<Line> = Vec::new();
    for l in record.lines.iter().filter(|l| !ended(&l.state)) {
        if l.kind == account::LineKind::Udp {
            return Err(failed(t!("worker_deploy_account.udp", env))
                .hint(t!("worker_deploy_account.line_hint", scope = app.scope())));
        }
        let kind = l.kind.as_str();
        let hint = || t!("worker_deploy_account.line_hint", scope = app.scope());
        // A line not active is said by what its state is known to mean:
        // erpc never says to end a line whose state could come back.
        if l.state != account::State::Active {
            return Err(not_active(app, (kind, &kept::shown(&l.id)), &l.state));
        }
        let Some(given) = l
            .endpoint
            .clone()
            .filter(|e| !l.pending && !e.trim().is_empty())
        else {
            return Err(
                failed(t!("worker_deploy_account.line_pending", env, kind)).hint(t!(
                    "worker_deploy_account.line_pending_hint",
                    scope = app.scope()
                )),
            );
        };
        let kind = match kind {
            "grpc" => LineKind::Grpc,
            "shreds" => LineKind::Shreds,
            "unlimited" => LineKind::Unlimited,
            other => {
                return Err(
                    failed(t!("worker_deploy_account.line_unknown", env, kind = other))
                        .hint(hint()),
                );
            }
        };
        if lines.iter().any(|have| have.kind == kind) {
            return Err(failed(t!(
                "worker_deploy_account.line_twice",
                env,
                kind = l.kind.as_str()
            ))
            .hint(hint()));
        }
        // The account gives an endpoint as the line's product has it (gRPC
        // and Shreds as `http://<host>`): read as erpc.toml's lines are.
        let Some(endpoint) = crate::worker::vps::line_endpoint(kind, &given) else {
            return Err(failed(t!(
                "worker_deploy_account.line_endpoint",
                env,
                kind = l.kind.as_str()
            ))
            .hint(hint()));
        };
        lines.push(Line {
            kind,
            id: l.id.clone(),
            endpoint,
            hourly: l.hourly,
            sources: Vec::new(),
        });
    }
    Ok(lines)
}

/// Who may reach SSH as the account keeps it: each address with its prefix
/// length, as the firewall step put it in the environment.
pub(crate) fn allow_list(env: &erpc_worker::manifest::Env) -> Vec<String> {
    env.firewall
        .ssh_allow
        .iter()
        .map(crate::worker::firewall::account_text)
        .collect()
}

/// What a deploy of `m` ships, as the account keeps it: the names of its
/// settings and secrets, never their values, and where each secret comes
/// from.
pub(crate) fn deployed_app(m: &Manifest) -> Result<DeployedApp, CliError> {
    if m.vars.len() > NAMES_MAX || m.secrets.len() > NAMES_MAX {
        return Err(failed(t!(
            "worker_deploy_account.too_many",
            max = NAMES_MAX
        )));
    }
    let mut app = DeployedApp::default();
    app.chain = m.chain.to_string();
    app.template.clone_from(&m.template);
    app.run_port = m.run.port;
    app.waf = m.waf.as_ref().map(|waf| DeployedWaf::new(waf.port));
    if m.services.redis {
        app.services.push(Service::Redis);
    }
    if m.services.postgres {
        app.services.push(Service::Postgres);
    }
    app.var_names = m.vars.keys().cloned().collect();
    app.secrets = m
        .secrets
        .iter()
        .map(|(name, source)| {
            let kind = match source {
                SecretRef::OnePassword(_) => SecretSource::OnePassword,
                SecretRef::Keychain { .. } => SecretSource::Keychain,
                SecretRef::Keystore { .. } => SecretSource::Keystore,
            };
            DeployedSecret::new(name.clone(), kind)
        })
        .collect();
    Ok(app)
}

/// Why a write to the account's record did not go as sent, for the caller
/// to say: what a deploy says is [`Unwritten::deploy_said`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unwritten {
    /// The account refused it, and said why: nothing was written.
    Refused(String),
    /// Another sign-in wrote the record since it was read: nothing was
    /// written over.
    Conflict,
    /// The answer was lost on the way, could not be read, or the account
    /// failed on its side: it may have been written.
    Lost(String),
    /// Written, and the account's answer reaches the server another way
    /// than was sent: nothing new was trusted.
    Differs,
    /// A list longer than the account keeps: nothing was sent.
    TooLong,
    /// Not signed in, or the sign-in could not be renewed: nothing was
    /// sent.
    NotSignedIn(String),
}

impl Unwritten {
    /// What a deploy of environment `env` says of it.
    pub(crate) fn deploy_said(&self, env: &str) -> String {
        match self {
            Self::Refused(error) | Self::Lost(error) | Self::NotSignedIn(error) => error.clone(),
            Self::Conflict => t!("worker_deploy_account.changed_meanwhile", env),
            Self::Differs => t!("worker_deploy_account.answer_differs", env),
            Self::TooLong => t!("worker_deploy_account.allow_too_long", max = ALLOW_MAX),
        }
    }

    /// `e`, as what it says of a write.
    pub(crate) fn of(e: &WorkerError) -> Self {
        match e {
            WorkerError::Refused(r) if r.code == Some(account::Code::RevisionConflict) => {
                Self::Conflict
            }
            WorkerError::Refused(r) if r.status >= 500 => Self::Lost(e.to_string()),
            WorkerError::Api(erpc_api::ApiError::Status(status)) if *status >= 500 => {
                Self::Lost(e.to_string())
            }
            WorkerError::Api(erpc_api::ApiError::Http(_) | erpc_api::ApiError::Malformed(_))
            | WorkerError::NewerFormat {
                after_write: true, ..
            } => Self::Lost(e.to_string()),
            WorkerError::Api(erpc_api::ApiError::Unauthorized) | WorkerError::Session(_) => {
                Self::NotSignedIn(e.to_string())
            }
            other => Self::Refused(other.to_string()),
        }
    }
}

/// An environment kept in the account, as a deploy goes through it: the
/// record the account last answered with, what this machine trusts of it,
/// and where this machine's pin is.
pub(crate) struct Deploying<'a, A> {
    /// How to reach the account.
    pub(crate) api: &'a A,
    /// The app's name.
    pub(crate) name: &'a str,
    /// The record the account last answered with.
    pub(crate) record: EnvDetail,
    /// What this machine trusts of the record: as pinned, then as this
    /// deploy wrote it.
    pub(crate) trusted: Anchor,
    /// The app's id in the account.
    pub(crate) app_id: String,
    /// The account's own id.
    pub(crate) uid: String,
    /// This machine's pins.
    pub(crate) pins: std::path::PathBuf,
    /// Whether this deploy recorded that the app runs.
    pub(crate) recorded: bool,
    /// What is said at the end besides: a pin that could not be written.
    pub(crate) warnings: Vec<String>,
}

impl<'a, A: Account> Deploying<'a, A> {
    /// The deploy of an environment `held` keeps, through `api`.
    pub(crate) fn new(api: &'a A, name: &'a str, held: &Kept, pins: std::path::PathBuf) -> Self {
        Self {
            api,
            name,
            record: held.record.clone(),
            trusted: Anchor::of(&held.app_id, &held.record),
            app_id: held.app_id.clone(),
            uid: held.uid.clone(),
            pins,
            recorded: false,
            warnings: Vec::new(),
        }
    }

    /// Writes `body`, built on the last record, and keeps what the account
    /// answers as the record. A write that changes how the server is
    /// reached is trusted, and pinned, only when the answer reaches it the
    /// way this machine wrote it.
    async fn put(&mut self, app: &App, body: PutEnv) -> Result<(), Unwritten> {
        let sent = Anchor::of_facts(&self.app_id, &body.facts, self.trusted.server.clone());
        let answer = put_waiting(self.api, self.name, &app.env, &body)
            .await
            .map_err(|e| Unwritten::of(&e))?;
        let now = Anchor::of(&self.app_id, &answer);
        self.record = answer;
        if now != sent {
            return Err(Unwritten::Differs);
        }
        if now != self.trusted {
            self.trusted = now.clone();
            // The account took the write: a pin that could not follow is
            // said, and asked about next time, not taken for a write lost.
            if let Err(error) = kept::pin(
                &self.pins,
                &kept::pin_key(&self.uid, self.name, &app.env),
                &now,
            ) {
                self.warnings
                    .push(t!("worker_deploy_account.pin_not_updated", error));
            }
        }
        Ok(())
    }

    /// Records the account's list of who may reach the app, as this deploy
    /// put it on the server, as the one this machine last saw: the
    /// firewall commands show what changed since. Said, not failed, when
    /// it cannot be written.
    pub(crate) fn saw_app_list(&mut self, app: &App) {
        let key = kept::pin_key(&self.uid, self.name, &app.env);
        if let Err(error) = kept::see_app(&self.pins, &key, &self.record.facts.firewall.app_allow) {
            self.warnings
                .push(t!("worker_deploy_account.seen_not_updated", error));
        }
    }

    /// Step 5: who may reach SSH, as the firewall now lets them in, each
    /// with its prefix length ([`allow_list`]), written to the account's
    /// record (nothing else the deploy reads changes).
    pub(crate) async fn write_firewall(
        &mut self,
        app: &App,
        ssh_allow: &[String],
    ) -> Result<(), String> {
        // Entries erpc does not read are never dropped from the account
        // without a word: a deploy is stopped before it builds anything
        // ([`ready`]), and this write refused all the same.
        let unread = crate::worker::firewall::Unread::of(&self.record);
        if !unread.ssh.is_empty() {
            return Err(t!(
                "worker_deploy_account.unread_not_written",
                entries = unread
                    .ssh
                    .iter()
                    .map(|e| kept::shown(e))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let now: Vec<erpc_worker::net::Cidr> = ssh_allow
            .iter()
            .filter_map(|e| erpc_worker::net::Cidr::parse_any(e).ok())
            .collect();
        let ssh =
            crate::worker::firewall::written_text(&self.record.facts.firewall.ssh_allow, &now);
        let app_allow = self.record.facts.firewall.app_allow.clone();
        self.write_lists(app, &ssh, &app_allow)
            .await
            .map_err(|u| u.deploy_said(&app.env))?;
        // The app's list is on the server as the account keeps it: the one
        // this machine last put there, for the firewall commands.
        self.saw_app_list(app);
        Ok(())
    }

    /// Who may reach SSH and who may reach the app, each address with its
    /// prefix length, written to the account's record as `erpc worker
    /// firewall` changed them; nothing else changes.
    pub(crate) async fn write_lists(
        &mut self,
        app: &App,
        ssh_allow: &[String],
        app_allow: &[String],
    ) -> Result<(), Unwritten> {
        if ssh_allow.len() > ALLOW_MAX || app_allow.len() > ALLOW_MAX {
            return Err(Unwritten::TooLong);
        }
        let mut facts = self.record.facts.clone();
        facts.firewall = account::Firewall::new(ssh_allow.to_vec(), app_allow.to_vec());
        if facts == self.record.facts {
            return Ok(());
        }
        let body = PutEnv::new(self.record.revision, facts).keeping_deploy(&self.record);
        self.put(app, body).await
    }

    /// Before the key is handed over: the record is read again and must
    /// still be the one trusted, to be reached ([`kept::reachable`]); then
    /// the account records that the app runs, when it names a server in
    /// use, and its answer must still be the one trusted. Anything else, or
    /// a record the account does not take, hands nothing over.
    pub(crate) async fn record_runs(&mut self, app: &App) -> Result<(), CliError> {
        let env = app.env.as_str();
        let changed = || {
            failed(t!("worker_deploy_account.changed_before_hand_over", env)).hint(t!(
                "worker_deploy_account.changed_before_hand_over_hint",
                scope = app.scope()
            ))
        };
        let fresh = self.api.env(self.name, env).await.map_err(|e| {
            let error = e.to_string();
            let said = t!("worker_deploy_account.not_reread", env, error);
            match e {
                WorkerError::Api(erpc_api::ApiError::Unauthorized) | WorkerError::Session(_) => {
                    CliError::new(Code::NotSignedIn, said).hint(t!("worker_vps.login_hint"))
                }
                WorkerError::Api(_) => CliError::new(Code::Network, said),
                _ => failed(said),
            }
        })?;
        // What the deploy began with must still hold: reached, as trusted,
        // and a record it can carry. Said as nothing handed over: the
        // release is on the server already.
        let not_handed = |e: CliError| {
            let message = t!("worker_deploy_account.not_handed_over", why = e.message);
            CliError { message, ..e }
        };
        kept::reachable(app, &fresh, Some(&self.trusted)).map_err(not_handed)?;
        record_carried(app, &fresh).map_err(not_handed)?;
        lines_in_use(app, &fresh).map_err(not_handed)?;
        if Anchor::of(&self.app_id, &fresh) != self.trusted {
            return Err(changed());
        }
        self.record = fresh;
        if !kept::has_server_in_use(&self.record) {
            return Ok(());
        }
        let record = kept::record_running(self.api, app, self.name, true)
            .await
            .map_err(|u| {
                let said = CliError::new(
                    u.error.code,
                    t!(
                        "worker_deploy_account.not_recorded",
                        env,
                        error = u.error.message.as_str()
                    ),
                );
                let maybe = u
                    .unknown
                    .then(|| t!("worker_account.may_say_running", scope = app.scope()));
                match (u.error.hint, maybe) {
                    (Some(hint), Some(maybe)) => {
                        said.hint(format!("{hint}{}{maybe}", t!("worker_account.hint_sep")))
                    }
                    (Some(hint), None) | (None, Some(hint)) => said.hint(hint),
                    (None, None) => said,
                }
            })?;
        self.recorded = true;
        if Anchor::of(&self.app_id, &record) != self.trusted {
            self.record = record;
            return Err(changed());
        }
        self.record = record;
        Ok(())
    }

    /// Once the app runs: the deploy of `release`, and what it shipped,
    /// put on the account's record.
    pub(crate) async fn write_deploy(
        &mut self,
        app: &App,
        release: &str,
        shipped: DeployedApp,
    ) -> Result<(), String> {
        let deployed = Deployed::new(release, erpc_ops::run::utc_now());
        let body = PutEnv::new(self.record.revision, self.record.facts.clone())
            .with_deploy(deployed, shipped);
        self.put(app, body)
            .await
            .map_err(|u| u.deploy_said(&app.env))
    }
}

/// Steps 8 of a deploy, in order: for an environment kept in the account
/// (`account`), and unless the deploy only prepares (`prepares`), the
/// account records that the app runs ([`Deploying::record_runs`]); only
/// then is `hand` run, which hands the key and the secrets over. A record
/// refused or a record changed hands nothing over.
pub(crate) async fn record_then_hand_over<A: Account, T>(
    account: Option<&mut Deploying<'_, A>>,
    app: &App,
    prepares: bool,
    hand: impl FnOnce() -> Result<T, CliError>,
) -> Result<T, CliError> {
    if !prepares && let Some(account) = account {
        account.record_runs(app).await?;
    }
    hand()
}

/// The busy answers a put is sent again after, at most.
const BUSY_TRIES: u32 = 3;

/// [`Account::put_env`], sent again after the wait the account asks for
/// when it answers that it is busy.
async fn put_waiting(
    api: &impl Account,
    name: &str,
    env: &str,
    body: &PutEnv,
) -> Result<EnvDetail, WorkerError> {
    let mut tries = 0;
    loop {
        tries += 1;
        match api.put_env(name, env, body).await {
            Ok(written) => return Ok(written.record),
            Err(WorkerError::Refused(r))
                if r.code == Some(account::Code::RateLimited) && tries < BUSY_TRIES =>
            {
                let wait = r.retry_after().unwrap_or(6).min(30);
                tokio::time::sleep(core::time::Duration::from_secs(wait)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::worker::account::stand_in::{Fake, refused};

    const APP_ID: &str = "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13";
    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    pub(super) fn record() -> EnvDetail {
        // Built, not written out: the endpoint gate reads literals.
        // In the account's form: gRPC and Shreds as `http://<host>`.
        let grpc = ["http", "grpc.example.net/"].join("://");
        let shreds = ["http", "shreds.example.net"].join("://");
        serde_json::from_value(json!({
            "name": "prod", "revision": 7, "factsFormat": 2,
            "facts": { "desiredCores": 4, "host": "203.0.113.10", "sshUser": "ubuntu",
                "sshPort": null, "hostKey": HOST_KEY,
                "firewall": { "sshAllow": ["198.51.100.7/32"], "appAllow": ["0.0.0.0/0"] },
                "starting": {},
                "backup": { "accessKey": 100_001, "resticKey": "restic-key-for-a-test", "host": "198.51.100.30" } },
            "servers": [{ "id": "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60", "slot": "active",
                "cores": 2, "memoryGb": 8, "region": "amsterdam", "hourly": true,
                "appRunning": false, "state": "active" }],
            "desiredCores": 4, "activeCores": 2, "coreOptions": [1, 2, 4, 8],
            "lines": [
                { "id": "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314", "kind": "grpc", "hourly": true,
                  "pending": false, "state": "active", "endpoint": grpc },
                { "id": "9d2b7f31-5e8a-4c61-b0f4-2a7e9c1d6b58", "kind": "shreds", "hourly": true,
                  "pending": false, "state": "gone", "endpoint": shreds }
            ],
            "refStates": { "backup": null }, "deployed": null, "deployedApp": null,
            "updatedAt": "2026-10-29T15:40:37.000Z"
        }))
        .expect("an environment")
    }

    fn manifest() -> Manifest {
        Manifest::parse(
            "name = \"bot\"\nchain = \"solana\"\ntemplate = \"solana/hello@1\"\n\
             [run]\nport = 8080\n[vars]\nRUST_LOG = \"info\"\n\
             [secrets]\nAPI_TOKEN = \"keychain:erpc-worker/bot-api-token\"\n\
             [services]\nredis = true\n[env.prod]\naccount = true\n",
        )
        .expect("a manifest")
    }

    fn kept(record: EnvDetail) -> Kept {
        let mut m = manifest();
        m.env.insert(
            "prod".to_owned(),
            crate::worker::account::facts_env(&record),
        );
        Kept {
            manifest: m,
            record,
            app_id: APP_ID.to_owned(),
            uid: "user-100001".to_owned(),
        }
    }

    fn app() -> App {
        App::at("apps/bot", "prod")
    }

    #[test]
    fn a_suspended_line_is_said_as_the_account_treats_its_kind() {
        use erpc_core::i18n::Lang;
        let hint = |kind: &str| {
            let mut r = record();
            r.lines[0].kind = account::LineKind::from(kind);
            r.lines[0].state = account::State::from("suspended");
            let e = with_lines(&app(), &kept(r)).expect_err("refused");
            e.hint.unwrap_or_default()
        };
        // gRPC and Shreds are normally ended at once, and one still
        // suspended may come back with credit: said both ways, to act now,
        // never that credit cannot bring it back nor that it surely does.
        // (A UDP Forwarding line is refused before.)
        for kind in ["grpc", "shreds"] {
            let said = hint(kind);
            assert!(
                said.contains("ended by the account at once"),
                "{kind}: {said}"
            );
            assert!(
                said.contains("still suspended may come back"),
                "{kind}: {said}"
            );
            assert!(
                said.contains("now") && said.contains("ERPC support"),
                "{kind}: {said}"
            );
            assert!(!said.contains("end it"), "{kind}: {said}");
        }
        // In every language, the resume is said.
        for (lang, comes_back) in [
            (Lang::En, "still suspended may come back"),
            (Lang::Ja, "戻ることがあります"),
            (Lang::Zh, "可能会恢复"),
            (Lang::Ru, "ещё приостановленная может вернуться"),
        ] {
            let said = crate::cli::i18n::speaking(lang, || hint("grpc"));
            assert!(said.contains(comes_back), "{lang:?}: {said}");
        }
        // Unlimited is held: left so, the account may end it, so the person
        // acts soon; it may resume, never surely, and support is given the
        // line's id.
        let said = hint("unlimited");
        assert!(
            said.contains("ERPC Credit") && said.contains("soon"),
            "{said}"
        );
        assert!(
            said.contains("may resume")
                && !said.contains("resumes it by itself")
                && said.contains("line's id"),
            "{said}"
        );
        for (lang, may, sure) in [
            (Lang::En, "may resume", "resumes it by itself"),
            (Lang::Ja, "再開することがあります", "自動で再開します"),
            (Lang::Zh, "可能会恢复", "它会自行恢复"),
            (Lang::Ru, "может возобновиться", "возобновится сама"),
        ] {
            let said = crate::cli::i18n::speaking(lang, || hint("unlimited"));
            assert!(
                said.contains(may) && !said.contains(sure),
                "{lang:?}: {said}"
            );
        }
        // A kind this erpc does not know is said as any other state.
        let said = hint("jito");
        assert!(
            !said.contains("resumes") && said.contains("ERPC support"),
            "{said}"
        );
    }

    #[test]
    fn a_deploy_there_refuses_choosing_buying_and_lines_and_a_record_it_cannot_carry() {
        let ok = kept(record());
        assert!(
            refuse_options(&Where::default(), &app()).is_ok()
                && refuse_record(&app(), &ok.record).is_ok()
        );
        for at in [
            Where {
                host: Some("203.0.113.20".to_owned()),
                ..Where::default()
            },
            Where {
                new_vps: true,
                ..Where::default()
            },
            Where {
                vps: Some(200_002),
                ..Where::default()
            },
            Where {
                lines: vec![(LineKind::Grpc, None)],
                ..Where::default()
            },
            Where {
                forget_lines: vec!["300003".to_owned()],
                ..Where::default()
            },
        ] {
            let e = refuse_options(&at, &app()).expect_err("refused");
            assert!(e.message.contains("does not yet choose"), "{}", e.message);
            // Its way out ends nothing.
            let hint = e.hint.unwrap_or_default();
            assert!(hint.contains("ERPC support"), "{hint}");
            assert!(
                !hint.contains("ended on") && !hint.contains("end it"),
                "{hint}"
            );
        }
        let mut moving = record();
        moving.servers[0].slot = account::Slot::Incoming;
        let e = refuse_record(&app(), &kept(moving).record).expect_err("refused");
        assert!(
            e.message.contains("coming in or going out"),
            "{}",
            e.message
        );
        // A line not active is said by its state: one that could come back
        // is never said to be ended.
        let said = |state: &str| {
            let mut r = record();
            r.lines[0].state = account::State::from(state);
            let e = with_lines(&app(), &kept(r)).expect_err("refused");
            assert!(e.message.contains("nothing was deployed"), "{}", e.message);
            (e.message, e.hint.unwrap_or_default())
        };
        let (message, hint) = said("provisioning");
        assert!(message.contains("still being set up"), "{message}");
        assert!(hint.contains("deploy again"), "{hint}");
        // No state's hint says to end the line, whatever it is.
        for state in [
            "provisioning",
            "applying",
            "maintenance",
            "suspended",
            "available",
            "removing",
            "error",
            "something-new",
        ] {
            let (_, hint) = said(state);
            assert!(
                !hint.contains("end it") && !hint.contains("ended on"),
                "{state}: {hint}"
            );
            assert!(hint.contains("ERPC support"), "{state}: {hint}");
        }
        assert!(said("maintenance").1.contains("deploy again"));
        // A gRPC line available has no address; another kind is not told
        // to register one.
        assert!(said("available").1.contains("address"));
        let mut unlimited = record();
        unlimited.lines[0].kind = account::LineKind::from("unlimited");
        unlimited.lines[0].state = account::State::from("available");
        let e = with_lines(&app(), &kept(unlimited)).expect_err("refused");
        assert!(!e.hint.unwrap_or_default().contains("address"));
        // An empty endpoint is no endpoint.
        let mut empty = record();
        empty.lines[0].endpoint = Some(String::new());
        let e = with_lines(&app(), &kept(empty)).expect_err("refused");
        assert!(e.message.contains("no endpoint yet"), "{}", e.message);
        let mut pending = record();
        pending.lines[0].pending = true;
        pending.lines[0].endpoint = None;
        let e = with_lines(&app(), &kept(pending)).expect_err("refused");
        assert!(e.message.contains("no endpoint yet"), "{}", e.message);
        let mut udp = record();
        udp.lines[0].kind = account::LineKind::Udp;
        let e = with_lines(&app(), &kept(udp)).expect_err("refused");
        assert!(e.message.contains("UDP Forwarding"), "{}", e.message);
    }

    #[test]
    fn the_app_is_handed_the_endpoints_of_the_lines_the_account_names() {
        let m = with_lines(&app(), &kept(record())).expect("lines");
        let env = &m.env["prod"];
        let vars: Vec<(&str, &str)> = env.line_vars().collect();
        // The gone line is left out.
        assert_eq!(
            vars,
            [(
                "GRPC_ENDPOINT",
                ["https", "grpc.example.net"].join("://").as_str()
            )]
        );
        assert!(env.account);
    }

    #[test]
    fn what_a_deploy_ships_is_kept_by_name_never_by_value() {
        let shipped = deployed_app(&manifest()).expect("shipped");
        let sent = serde_json::to_value(
            PutEnv::new(1, record().facts).with_deploy(Deployed::new("r1", "t"), shipped),
        )
        .expect("encodes");
        let app = &sent["deployedApp"];
        assert_eq!(app["chain"], "solana");
        assert_eq!(app["runPort"], 8080);
        assert_eq!(app["services"], json!(["redis"]));
        assert_eq!(app["varNames"], json!(["RUST_LOG"]));
        assert_eq!(
            app["secrets"],
            json!([{ "name": "API_TOKEN", "kind": "keychain" }])
        );
        assert!(!sent.to_string().contains("\"info\""), "a value was sent");
        let mut many = manifest();
        for i in 0..=NAMES_MAX {
            many.vars.insert(format!("V{i}"), "x".to_owned());
        }
        assert!(deployed_app(&many).is_err());
    }

    fn deploying<'a>(fake: &'a Fake, pins: &std::path::Path) -> Deploying<'a, Fake> {
        let held = kept(fake.env.borrow().clone());
        Deploying::new(fake, "bot", &held, pins.to_path_buf())
    }

    fn pinned(pins: &std::path::Path) -> Option<Anchor> {
        crate::worker::account::pinned(
            pins,
            &crate::worker::account::pin_key("user-100001", "bot", "prod"),
        )
        .expect("readable")
    }

    #[tokio::test]
    async fn a_deploy_writes_on_the_record_it_last_read_and_keeps_what_it_did_not_change() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let fake = Fake::new(record());
        let mut d = deploying(&fake, &pins);
        // The firewall as it was: nothing is written.
        d.write_firewall(&app(), &["198.51.100.7/32".to_owned()])
            .await
            .expect("same");
        assert!(fake.log.borrow().is_empty());
        // Another address may reach SSH: written, and pinned from what
        // this machine wrote.
        let allow = ["198.51.100.7/32".to_owned(), "198.51.100.8/32".to_owned()];
        d.write_firewall(&app(), &allow).await.expect("written");
        let now = fake.env.borrow().clone();
        assert_eq!(now.facts.firewall.ssh_allow, allow);
        assert_eq!(now.facts.backup, record().facts.backup);
        assert_eq!(now.facts.desired_cores, record().facts.desired_cores);
        assert_eq!(pinned(&pins), Some(Anchor::of(APP_ID, &now)));
        // The app's state, then the deploy: each write on the revision the
        // one before it answered with.
        d.record_runs(&app()).await.expect("recorded");
        d.write_deploy(&app(), "r1", deployed_app(&manifest()).expect("shipped"))
            .await
            .expect("written");
        assert_eq!(*fake.log.borrow(), ["put_env", "record true", "put_env"]);
        let after = fake.env.borrow().clone();
        assert_eq!(
            after.deployed.as_ref().map(|d| d.release.as_str()),
            Some("r1")
        );
        assert_eq!(after.facts.backup, record().facts.backup);
        assert!(after.servers[0].app_running);
    }

    #[tokio::test]
    async fn the_record_a_first_login_wrote_is_deployed_as_any_other() {
        // What `server start` and the first login leave: an address, a host
        // key and a login name; no list of who may reach SSH or the app, no
        // line, no backup and no deploy on record.
        let mut fresh = record();
        fresh.facts.firewall = account::Firewall::default();
        fresh.facts.backup = None;
        fresh.lines.clear();
        fresh.servers[0].cores = Some(1);
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let fake = Fake::new(fresh.clone());
        // Nothing in it stops the deploy before anything is deployed.
        let m = ready(&app(), &kept(fresh)).expect("goes on");
        assert!(m.env["prod"].firewall.ssh_allow.is_empty());
        // The deploy writes who may reach SSH (the address it runs from),
        // records that the app runs, then the deploy.
        let mut d = deploying(&fake, &pins);
        d.write_firewall(&app(), &["198.51.100.7/32".to_owned()])
            .await
            .expect("written");
        d.record_runs(&app()).await.expect("recorded");
        d.write_deploy(&app(), "r1", deployed_app(&manifest()).expect("shipped"))
            .await
            .expect("written");
        assert_eq!(*fake.log.borrow(), ["put_env", "record true", "put_env"]);
        let after = fake.env.borrow().clone();
        assert_eq!(after.facts.firewall.ssh_allow, ["198.51.100.7/32"]);
        assert_eq!(after.facts.host_key.as_deref(), Some(HOST_KEY));
        assert_eq!(
            after.deployed.as_ref().map(|d| d.release.as_str()),
            Some("r1")
        );
        assert!(after.servers[0].app_running);
        assert_eq!(pinned(&pins), Some(Anchor::of(APP_ID, &after)));
    }

    #[tokio::test]
    async fn a_write_another_sign_in_got_in_before_is_not_written_over_or_trusted() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let fake = Fake::new(record());
        let mut d = deploying(&fake, &pins);
        // Someone else wrote in between: the revision read is not the one
        // the account has.
        fake.env.borrow_mut().revision += 1;
        let e = d
            .write_firewall(&app(), &["198.51.100.9/32".to_owned()])
            .await
            .expect_err("refused");
        assert!(e.contains("another sign-in"), "{e}");
        assert_eq!(pinned(&pins), None);
        // The account took the write, and its answer reaches another host:
        // nothing is trusted.
        let fake = Fake::new(record());
        *fake.meddle.borrow_mut() = Some("198.51.100.66".to_owned());
        let mut d = deploying(&fake, &pins);
        let e = d
            .write_firewall(&app(), &["198.51.100.9/32".to_owned()])
            .await
            .expect_err("refused");
        assert!(e.contains("another way"), "{e}");
        assert_eq!(pinned(&pins), None);
    }

    #[tokio::test]
    async fn a_record_of_running_the_account_refuses_stops_the_deploy_and_an_own_server_has_none() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(409, "app_running_elsewhere", Value::Null));
        let mut d = deploying(&fake, &pins);
        let e = d.record_runs(&app()).await.expect_err("refused");
        assert!(e.message.contains("were not handed over"), "{}", e.message);
        let mut own = record();
        own.servers.clear();
        let fake = Fake::new(own);
        let mut d = deploying(&fake, &pins);
        d.record_runs(&app()).await.expect("nothing to record");
        assert!(fake.log.borrow().is_empty());
    }

    #[test]
    fn what_the_account_says_of_a_server_is_never_saved_to_erpc_toml() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("erpc.toml");
        std::fs::write(
            &path,
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\naccount = true\n",
        )
        .expect("erpc.toml");
        let record = crate::worker::EnvRecord {
            path: &path,
            app: "bot",
            env: "prod",
        };
        // The account's facts, as a command is given them: refused.
        let facts = crate::worker::account::facts_env(&super::tests::record());
        let e = record.save(&facts, None).expect_err("refused");
        assert!(e.contains("not written to erpc.toml"), "{e}");
        // So are they with lines the account names.
        let lines = with_lines(&app(), &kept(super::tests::record())).expect("lines");
        assert!(record.save(&lines.env["prod"], None).is_err());
        // The marker alone is what erpc.toml keeps.
        record
            .save(&crate::worker::EnvRecord::kept_in_account(), None)
            .expect("the marker");
        assert!(
            !std::fs::read_to_string(&path)
                .expect("read")
                .contains("203.0.113.10")
        );
    }

    #[tokio::test]
    async fn who_may_reach_ssh_goes_with_its_prefix_and_unchanged_writes_nothing() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let held = kept(record());
        // As the firewall step leaves the environment: addresses as Cidrs.
        let mut env = held.manifest.env["prod"].clone();
        env.firewall.ssh_allow =
            vec![erpc_worker::net::Cidr::parse("198.51.100.7").expect("an address")];
        let allow = allow_list(&env);
        assert_eq!(allow, ["198.51.100.7/32"]);
        let fake = Fake::new(record());
        let mut d = Deploying::new(&fake, "bot", &held, pins.clone());
        d.write_firewall(&app(), &allow).await.expect("same");
        assert!(fake.log.borrow().is_empty());
        // Another one: written, and the account takes it.
        env.firewall
            .ssh_allow
            .push(erpc_worker::net::Cidr::parse("2001:db8::1").expect("an address"));
        d.write_firewall(&app(), &allow_list(&env))
            .await
            .expect("written");
        assert_eq!(
            fake.env.borrow().facts.firewall.ssh_allow,
            ["198.51.100.7/32", "2001:db8::1/128"]
        );
    }

    #[tokio::test]
    async fn a_record_changed_before_the_hand_over_hands_nothing_over() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let held = kept(record());
        let fake = Fake::new(record());
        let mut d = Deploying::new(&fake, "bot", &held, pins);
        // Another sign-in points the environment elsewhere during the build.
        fake.env.borrow_mut().facts.host = Some("198.51.100.66".to_owned());
        let e = d.record_runs(&app()).await.expect_err("refused");
        assert!(e.message.contains("not the one trusted"), "{}", e.message);
        assert!(!d.recorded);
        assert!(fake.written.borrow().is_empty());
        // Its server in use ended meanwhile: refused as gone.
        let fake = Fake::new(record());
        let mut d = Deploying::new(
            &fake,
            "bot",
            &held,
            std::path::PathBuf::from("/nonexistent/pins"),
        );
        fake.env.borrow_mut().servers.clear();
        let e = d.record_runs(&app()).await.expect_err("refused");
        assert!(e.message.contains("is gone"), "{}", e.message);
    }

    #[test]
    fn only_lines_in_use_are_handed_to_the_app_one_of_each_kind() {
        // A cancelled UDP line is ended: left out, and no refusal.
        let mut cancelled = record();
        cancelled.lines[1].kind = account::LineKind::Udp;
        cancelled.lines[1].state = account::State::from("cancelled");
        assert!(with_lines(&app(), &kept(cancelled)).is_ok());
        // A line held for maintenance (or ending): refused by its state.
        let mut held = record();
        held.lines[0].state = account::State::from("maintenance");
        let e = with_lines(&app(), &kept(held)).expect_err("refused");
        assert!(e.message.contains("in state maintenance"), "{}", e.message);
        // Two gRPC lines: refused, not the last one taken.
        let mut twice = record();
        twice.lines[1] = twice.lines[0].clone();
        let e = with_lines(&app(), &kept(twice)).expect_err("refused");
        assert!(e.message.contains("two grpc lines"), "{}", e.message);
    }

    #[test]
    fn a_line_the_account_gives_as_http_is_dialled_over_tls_as_erpc_toml_lines_are() {
        let m = with_lines(&app(), &kept(record())).expect("lines");
        let vars: Vec<(&str, String)> = m.env["prod"]
            .line_vars()
            .map(|(k, v)| (k, v.to_owned()))
            .collect();
        assert_eq!(
            vars,
            [("GRPC_ENDPOINT", ["https", "grpc.example.net"].join("://"))]
        );
        // An Unlimited line keeps its plain address and port.
        let mut unlimited = record();
        unlimited.lines[1].kind = account::LineKind::Unlimited;
        unlimited.lines[1].state = account::State::Active;
        unlimited.lines[1].endpoint = Some(["http", "198.51.100.40:8899/"].join("://"));
        let m = with_lines(&app(), &kept(unlimited)).expect("lines");
        assert!(
            m.env["prod"]
                .line_vars()
                .any(|(_, v)| v == ["http", "198.51.100.40:8899"].join("://"))
        );
    }

    #[tokio::test]
    async fn the_key_is_handed_over_only_after_the_account_recorded_that_the_app_runs() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let held = kept(record());
        // Recorded first, then handed over.
        let fake = Fake::new(record());
        let mut d = Deploying::new(&fake, "bot", &held, pins.clone());
        record_then_hand_over(Some(&mut d), &app(), false, || {
            fake.log.borrow_mut().push("hand over".to_owned());
            Ok(())
        })
        .await
        .expect("handed over");
        assert_eq!(*fake.log.borrow(), ["record true", "hand over"]);
        // Refused by the account: nothing handed over.
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(409, "app_running_elsewhere", Value::Null));
        let mut d = Deploying::new(&fake, "bot", &held, pins.clone());
        let handed = record_then_hand_over(Some(&mut d), &app(), false, || {
            fake.log.borrow_mut().push("hand over".to_owned());
            Ok(())
        })
        .await;
        assert!(handed.is_err());
        assert!(!fake.log.borrow().contains(&"hand over".to_owned()));
        // Only prepared: nothing recorded.
        let fake = Fake::new(record());
        let mut d = Deploying::new(&fake, "bot", &held, pins);
        record_then_hand_over(Some(&mut d), &app(), true, || Ok(()))
            .await
            .expect("prepared");
        assert!(fake.written.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_firewall_write_keeps_the_last_deploy_and_a_start_under_way() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let mut before = record();
        before.deployed = Some(Deployed::new(
            "20261029T154037Z-6914df5f",
            "2026-10-29T15:40:37Z",
        ));
        let mut shipped = DeployedApp::default();
        shipped.chain = "solana".to_owned();
        before.deployed_app = Some(shipped.clone());
        // A made-up start key, built here so it reads as no credential.
        let made_up = ["01234567", "89abcdef"].concat().repeat(2);
        before.facts.starting = serde_json::from_value(json!({ "grpc": {
            "key": made_up, "family": "grpc", "product": "p",
            "region": null, "ip": null } }))
        .expect("a start");
        let held = kept(before.clone());
        let fake = Fake::new(before.clone());
        let mut d = Deploying::new(&fake, "bot", &held, pins);
        d.write_firewall(&app(), &["198.51.100.9/32".to_owned()])
            .await
            .expect("written");
        let after = fake.env.borrow().clone();
        assert_eq!(after.deployed, before.deployed);
        assert_eq!(after.deployed_app, before.deployed_app);
        assert_eq!(after.facts.starting, before.facts.starting);
    }

    #[tokio::test]
    async fn a_busy_answer_is_sent_again_and_another_409_is_said_as_the_account_said_it() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let held = kept(record());
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(429, "rate_limited", json!({ "retryAfter": 0 })));
        let mut d = Deploying::new(&fake, "bot", &held, pins.clone());
        d.write_firewall(&app(), &["198.51.100.9/32".to_owned()])
            .await
            .expect("written after the wait");
        assert_eq!(*fake.log.borrow(), ["put_env", "put_env"]);
        // A 409 that is no revision conflict is not said as another sign-in.
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(409, "account_closed", Value::Null));
        let mut d = Deploying::new(&fake, "bot", &held, pins);
        let e = d
            .write_firewall(&app(), &["198.51.100.9/32".to_owned()])
            .await
            .expect_err("refused");
        assert!(!e.contains("another sign-in"), "{e}");
    }

    #[tokio::test]
    async fn a_pin_that_cannot_follow_a_write_the_account_took_is_a_warning() {
        let held = kept(record());
        let fake = Fake::new(record());
        // A directory where the pins file would be: it cannot be written.
        let dir = tempfile::tempdir().expect("a directory");
        let mut d = Deploying::new(&fake, "bot", &held, dir.path().to_path_buf());
        d.write_firewall(&app(), &["198.51.100.9/32".to_owned()])
            .await
            .expect("the account took it");
        // The pin's warning, and that of the app's list last put there,
        // each said once.
        assert_eq!(d.warnings.len(), 2, "{:?}", d.warnings);
        assert!(
            d.warnings[0].contains("record of what it trusts"),
            "{:?}",
            d.warnings
        );
        assert!(
            d.warnings[1].contains("list of who may reach the app"),
            "{:?}",
            d.warnings
        );
    }

    #[tokio::test]
    async fn a_server_moving_in_during_the_build_hands_nothing_over() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let held = kept(record());
        let fake = Fake::new(record());
        let mut incoming = fake.env.borrow().servers[0].clone();
        incoming.slot = account::Slot::Incoming;
        fake.env.borrow_mut().servers.push(incoming);
        let mut d = Deploying::new(&fake, "bot", &held, pins);
        let e = d.record_runs(&app()).await.expect_err("refused");
        assert!(e.message.contains("were not handed over"), "{}", e.message);
        assert!(fake.written.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_line_that_stops_being_active_during_the_build_hands_nothing_over() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let held = kept(record());
        let fake = Fake::new(record());
        fake.env.borrow_mut().lines[0].state = account::State::from("maintenance");
        let mut d = Deploying::new(&fake, "bot", &held, pins);
        let e = d.record_runs(&app()).await.expect_err("refused");
        assert!(e.message.contains("were not handed over"), "{}", e.message);
        assert!(!e.message.contains("nothing was deployed"), "{}", e.message);
        assert!(fake.written.borrow().is_empty());
    }

    #[test]
    fn the_json_answer_names_the_place_the_record_was_kept_in() {
        let in_toml =
            crate::worker::deploy::kept_where(json!({ "erpc_toml_updated": true }), false);
        assert_eq!(in_toml, json!({ "erpc_toml_updated": true }));
        let in_account =
            crate::worker::deploy::kept_where(json!({ "erpc_toml_updated": false }), true);
        assert_eq!(in_account, json!({ "account_updated": false }));
    }

    #[test]
    fn a_line_not_active_is_named_by_its_id_shown_clean() {
        let said = |state: &str| {
            let mut r = record();
            r.lines[0].state = account::State::from(state);
            let e = with_lines(&app(), &kept(r)).expect_err("refused");
            (e.message, e.hint.unwrap_or_default())
        };
        let (message, _) = said("provisioning");
        // The line is named by its id, as support is asked with it, and an
        // id holding terminal control is shown cleaned.
        let id = record().lines[0].id.clone();
        assert!(message.contains(&id), "{message}");
        assert!(said("suspended").0.contains(&id));
        let mut odd = record();
        odd.lines[0].id = "c47a1e09\u{1b}[2K".to_owned();
        odd.lines[0].state = account::State::from("suspended");
        let e = with_lines(&app(), &kept(odd)).expect_err("refused");
        assert!(
            !e.message.contains('\u{1b}') && e.message.contains("c47a1e09"),
            "{}",
            e.message
        );
    }

    #[test]
    fn a_suspended_line_is_said_the_same_whatever_its_hourly_says_in_every_language() {
        use erpc_core::i18n::Lang;
        // The hint does not depend on `hourly`. Every way a line may
        // come back is said, none as sure; nothing is said to be ended by
        // the person; a gRPC or Shreds line, which a bundle paid by the
        // hour can hold, says "at once" and "now".
        let hint = |kind: &str, state: &str, hourly: bool, lang: Lang| {
            crate::cli::i18n::speaking(lang, || {
                let mut r = record();
                r.lines[0].kind = account::LineKind::from(kind);
                r.lines[0].state = account::State::from(state);
                r.lines[0].hourly = hourly;
                with_lines(&app(), &kept(r))
                    .expect_err("refused")
                    .hint
                    .unwrap_or_default()
            })
        };
        for (lang, ways, bundle, at_once, now, id, ends) in [
            (
                Lang::En,
                ["hourly charges", "next period's charge", "unpaid invoice"],
                "Bundle",
                "at once",
                "now",
                "line's id",
                ["end it", "cancel it", "resumes by itself"],
            ),
            (
                Lang::Ja,
                ["1 時間分", "次の期間分", "未払いの請求"],
                "Bundle プラン",
                "すぐ終了",
                "今すぐ",
                "回線の id",
                ["終了してください", "解約してください", "自動で戻ります"],
            ),
            (
                Lang::Zh,
                ["一小时的费用", "下一个周期的费用", "未付账单"],
                "Bundle 方案",
                "立即终止",
                "立即",
                "线路的 id",
                ["请终止", "请取消", "会自动恢复"],
            ),
            (
                Lang::Ru,
                [
                    "час всех почасовых",
                    "следующий период",
                    "неоплаченный счёт",
                ],
                "Bundle-тариф",
                "сразу завершается",
                "сейчас",
                "id линии",
                ["завершите", "отмените", "возобновится сама"],
            ),
        ] {
            for kind in ["grpc", "shreds", "unlimited"] {
                let said = hint(kind, "suspended", false, lang);
                assert_eq!(said, hint(kind, "suspended", true, lang), "{kind} {lang:?}");
                for way in ways {
                    assert!(said.contains(way), "{kind} {lang:?} {way}: {said}");
                }
                assert!(said.contains(id), "{kind} {lang:?}: {said}");
                for end in ends {
                    assert!(!said.contains(end), "{kind} {lang:?} {end}: {said}");
                }
                let grpc = kind != "unlimited";
                assert_eq!(said.contains(bundle), grpc, "{kind} {lang:?}: {said}");
                assert_eq!(said.contains(at_once), grpc, "{kind} {lang:?}: {said}");
                if grpc {
                    assert!(said.contains(now), "{kind} {lang:?}: {said}");
                }
            }
            // Every other state of every kind names the line's id and
            // nothing to end.
            for kind in ["grpc", "shreds", "unlimited", "jito"] {
                for state in ["provisioning", "maintenance", "available", "error"] {
                    for hourly in [true, false] {
                        let said = hint(kind, state, hourly, lang);
                        assert!(said.contains(id), "{kind} {state} {lang:?}: {said}");
                        for end in ends {
                            assert!(!said.contains(end), "{kind} {state} {lang:?}: {said}");
                        }
                    }
                }
            }
            // A kind this erpc does not know, suspended: said as any other
            // state, exactly.
            let other = crate::cli::i18n::speaking(lang, || {
                t!(
                    "worker_deploy_account.line_other_hint",
                    scope = app().scope()
                )
            });
            for hourly in [true, false] {
                assert_eq!(hint("jito", "suspended", hourly, lang), other, "{lang:?}");
            }
        }
    }

    #[test]
    fn a_deploy_stops_before_anything_at_lists_erpc_would_not_put_on_the_server() {
        let mut ok = record();
        ok.facts.firewall = account::Firewall::new(vec!["198.51.100.7/32".to_owned()], Vec::new());
        ready(&app(), &kept(ok)).expect("ready");
        for (ssh, app_allow, said) in [
            // Everyone on the app's list, and no WAF in front of it.
            (vec!["198.51.100.7/32"], vec!["0.0.0.0/0"], "everyone"),
            (vec!["198.51.100.0/24"], vec![], "198.51.100.0/24"),
            (vec!["198.51.100.7/32"], vec!["10.0.0.1/24"], "10.0.0.1/24"),
        ] {
            let mut r = record();
            r.facts.firewall = account::Firewall::new(
                ssh.iter().map(|&a| a.to_owned()).collect(),
                app_allow.iter().map(|&a: &&str| a.to_owned()).collect(),
            );
            let e = ready(&app(), &kept(r)).expect_err("refused");
            assert!(e.message.contains("nothing was deployed"), "{}", e.message);
            assert!(e.message.contains(said), "{}", e.message);
            assert!(e.hint.unwrap_or_default().contains("firewall deny"));
        }
    }

    #[tokio::test]
    async fn a_list_longer_than_the_account_keeps_is_not_sent() {
        let dir = tempfile::tempdir().expect("a directory");
        let held = kept(record());
        let fake = Fake::new(record());
        let mut d = Deploying::new(&fake, "bot", &held, dir.path().join("worker_account.json"));
        let long: Vec<String> = (1..=17).map(|n| format!("203.0.113.{n}/32")).collect();
        let ssh = vec!["198.51.100.7/32".to_owned()];
        assert_eq!(
            d.write_lists(&app(), &ssh, &long).await,
            Err(Unwritten::TooLong)
        );
        assert_eq!(
            d.write_lists(&app(), &long, &[]).await,
            Err(Unwritten::TooLong)
        );
        assert!(fake.log.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_deploy_shows_what_changed_in_the_apps_list_and_records_it_only_once_written() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let mut r = record();
        r.facts.firewall = account::Firewall::new(
            vec!["198.51.100.7/32".to_owned()],
            vec!["198.51.100.30/32".to_owned()],
        );
        let held = kept(r.clone());
        // Shown, and asked: with no terminal here, refused without --yes.
        let _ = crate::node::common::heard::take_printed();
        let e = ready_shown(&app(), &held, &pins, false).expect_err("asked");
        assert_eq!(e.code, Code::NeedsTerminal);
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(printed.contains("198.51.100.30/32"), "{printed}");
        ready_shown(&app(), &held, &pins, true).expect("--yes takes it");
        // A write the account refuses records nothing; one it takes does.
        let key = kept::pin_key("user-100001", "bot", "prod");
        let fake = Fake::new(r.clone());
        fake.answers
            .borrow_mut()
            .push(refused(400, "invalid_request", Value::Null));
        let mut d = Deploying::new(&fake, "bot", &held, pins.clone());
        assert!(
            d.write_firewall(&app(), &["198.51.100.9/32".to_owned()])
                .await
                .is_err()
        );
        assert_eq!(kept::app_seen(&pins, &key).expect("read"), None);
        let fake = Fake::new(r);
        let mut d = Deploying::new(&fake, "bot", &held, pins.clone());
        d.write_firewall(&app(), &["198.51.100.9/32".to_owned()])
            .await
            .expect("written");
        assert_eq!(
            kept::app_seen(&pins, &key).expect("read"),
            Some(vec!["198.51.100.30/32".to_owned()])
        );
        // Nothing new since: not asked again.
        ready_shown(&app(), &kept(fake.env.borrow().clone()), &pins, false).expect("nothing new");
        // Unpinned, it is forgotten too.
        kept::unpin(&pins, &key).expect("unpinned");
        assert_eq!(kept::app_seen(&pins, &key).expect("read"), None);
    }

    #[tokio::test]
    async fn a_deploy_never_writes_over_an_ssh_entry_erpc_does_not_read() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut r = record();
        r.facts.firewall = account::Firewall::new(
            vec!["198.51.100.7/32".to_owned(), "10.0.0.1/24".to_owned()],
            Vec::new(),
        );
        let held = kept(r.clone());
        let fake = Fake::new(r);
        let mut d = Deploying::new(&fake, "bot", &held, dir.path().join("worker_account.json"));
        let e = d
            .write_firewall(&app(), &["198.51.100.7/32".to_owned()])
            .await
            .expect_err("refused");
        assert!(e.contains("10.0.0.1/24"), "{e}");
        assert!(fake.log.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_deploy_writes_the_accounts_own_text_and_a_new_mapped_address_in_hex() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut r = record();
        r.facts.firewall = account::Firewall::new(
            vec![
                "2001:DB8::1/128".to_owned(),
                "::FFFF:C633:6404/128".to_owned(),
            ],
            Vec::new(),
        );
        let held = kept(r.clone());
        let fake = Fake::new(r);
        let mut d = Deploying::new(&fake, "bot", &held, dir.path().join("worker_account.json"));
        // As the firewall step leaves the environment: erpc's text, plus a
        // new mapped address.
        let mut env = held.manifest.env["prod"].clone();
        env.firewall
            .ssh_allow
            .push(erpc_worker::net::Cidr::parse_any("::ffff:203.0.113.8").expect("an address"));
        d.write_firewall(&app(), &allow_list(&env))
            .await
            .expect("written");
        assert_eq!(
            fake.env.borrow().facts.firewall.ssh_allow,
            [
                "2001:DB8::1/128",
                "::FFFF:C633:6404/128",
                "::ffff:cb00:7108/128"
            ]
        );
    }
}
