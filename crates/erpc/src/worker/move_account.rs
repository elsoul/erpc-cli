// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker move --to account`: an environment kept in `erpc.toml`
//! moves into the ERPC account. The account takes in its server and its
//! lines by their product ids (which it never gives back), keeps its server
//! facts, and `erpc.toml` keeps only `account = true`.
//!
//! The move is one way, so it is made in the order that can be resumed:
//! what the account has is read and decided on first, then everything is
//! written to the account, each step one the account answers the same way
//! when it is sent again, and `erpc.toml` is changed after the account (then
//! this machine's records of what it trusts), and only when it is still as
//! the move read it. A move stopped half way is run again and
//! goes on where it stopped; the server already in the slot in use is sent
//! again, so that the account says whether it is this one.
//!
//! What this machine then trusts of the environment is its own record: the
//! account's answer must reach the server the same way, or nothing is
//! trusted and `erpc.toml` is left as it was.
//!
//! It refuses what it cannot carry over whole: a start with no outcome yet
//! (whose purchase the account would lose track of), a UDP Forwarding line
//! (whose source addresses the account does not give yet, which the
//! server's firewall needs), an environment a 1Password item keeps (which
//! every checkout reads, and which would have to tell all of them), and an
//! account that does not yet let this sign-in end the servers and lines of
//! an environment kept there (a moved environment could then not be ended).

use erpc_api::worker::{
    self as account, AdoptLine, AdoptServer, AdoptSlot, Code as AccountCode, EnvDetail, Facts,
    PutApp, PutEnv, PutWallet, ServerKind, WalletSource, WorkerError,
};
use erpc_ssh::worker::Verb;
use erpc_worker::manifest::{Env, LineKind, Manifest, ResourceKind, SecretRef};
use serde_json::{Value, json};

use crate::cli::error::{CliError, Code};
use crate::worker::App;
use crate::worker::account::{self as kept, Account, Anchor};

fn failed(message: String) -> CliError {
    CliError::new(Code::Failed, message)
}

/// What a move carries to the account: the app's record and the
/// environment's, and what is to be taken in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The app's name.
    pub(crate) name: String,
    /// The environment's name.
    pub(crate) env: String,
    /// The app's record.
    pub(crate) app: PutApp,
    /// The environment's facts.
    pub(crate) facts: Facts,
    /// The server, by kind and product number.
    pub(crate) server: Option<(ServerKind, u64)>,
    /// The lines, by kind and product number.
    pub(crate) lines: Vec<(account::LineKind, u64)>,
    /// How the app and environment are named on a command line, for hints.
    pub(crate) scope: String,
}

/// The wallet's public side as the account takes it, when the app has a
/// wallet with its public key on record.
fn wallet_of(m: &Manifest) -> Result<Option<PutWallet>, CliError> {
    let Some(wallet) = &m.wallet else {
        return Ok(None);
    };
    let Some(pubkey) = &wallet.pubkey else {
        return Ok(None);
    };
    let source = match &wallet.source {
        SecretRef::OnePassword(_) => WalletSource::OnePassword,
        SecretRef::Keychain { .. } => WalletSource::Keychain,
        SecretRef::Keystore { .. } => WalletSource::Keystore,
    };
    PutWallet::new(pubkey.clone(), source)
        .map(Some)
        .map_err(|e| failed(e.to_string()))
}

const fn server_kind(kind: ResourceKind) -> ServerKind {
    match kind {
        ResourceKind::Vps => ServerKind::Vps,
        ResourceKind::SuperVps => ServerKind::SuperVps,
        ResourceKind::PremiumVps => ServerKind::PremiumVps,
        ResourceKind::BareMetal => ServerKind::BareMetal,
    }
}

/// A product number as the account takes it in.
fn number(id: &str, what: &str) -> Result<u64, CliError> {
    id.parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| failed(t!("worker_move.not_a_number", what, id)))
}

/// What moving environment `env_name` of `m`, its facts `env` as
/// `erpc.toml` has them, takes to the account, or why it cannot be moved.
pub(crate) fn plan(m: &Manifest, env_name: &str, env: &Env) -> Result<Plan, CliError> {
    if !env.starting.is_empty() {
        let what: Vec<&str> = env.starting.keys().map(|s| s.as_str()).collect();
        return Err(failed(t!(
            "worker_move.starting",
            env = env_name,
            what = what.join(", ")
        ))
        .hint(t!("worker_move.starting_hint", env = env_name)));
    }
    if env.lines.iter().any(|l| l.kind == LineKind::Udp) {
        return Err(failed(t!("worker_move.udp", env = env_name)));
    }
    // A backup's keys would go into the account's record, where deleting
    // the environment does not revoke them.
    if env.backup.is_some() {
        return Err(failed(t!("worker_move.backup", env = env_name)));
    }
    let server = env
        .resource
        .as_ref()
        .map(|r| Ok::<_, CliError>((server_kind(r.kind), number(&r.id, r.kind.as_str())?)))
        .transpose()?;
    let lines = env
        .lines
        .iter()
        .map(|l| {
            let kind = match l.kind {
                LineKind::Grpc => account::LineKind::Grpc,
                LineKind::Shreds => account::LineKind::Shreds,
                LineKind::Unlimited => account::LineKind::Unlimited,
                LineKind::Udp => unreachable!("refused above"),
            };
            Ok((kind, number(&l.id, l.kind.label())?))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    // Each entry as the account takes it: an IPv4-mapped IPv6 address in
    // hex, as the firewall commands write it.
    let strings = |list: &[erpc_worker::net::Cidr]| {
        list.iter()
            .map(crate::worker::firewall::account_text)
            .collect()
    };
    let mut facts = Facts::default();
    facts.host.clone_from(&env.host);
    facts.ssh_user.clone_from(&env.ssh_user);
    facts.ssh_port = env.ssh_port;
    facts.host_key.clone_from(&env.host_key);
    facts.firewall = account::Firewall::new(
        strings(&env.firewall.ssh_allow),
        strings(&env.firewall.app_allow),
    );
    // A backup's keys are not carried (refused before this is planned).
    facts.backup = None;
    let app = PutApp::new(0, m.chain.to_string(), m.template.clone(), wallet_of(m)?);
    Ok(Plan {
        name: m.name.clone(),
        env: env_name.to_owned(),
        app,
        facts,
        server,
        lines,
        scope: String::new(),
    })
}

/// Whether the app runs, by the worker's state as its agent says it: one
/// starting or waiting to come up counts as running, so that the record
/// never says it is stopped while it runs.
pub(crate) fn runs(state: Option<&str>) -> bool {
    matches!(state, Some("running" | "starting" | "waiting"))
}

/// The refusal of a move to an account that does not yet let this sign-in
/// end what an environment kept there runs on.
fn not_open() -> CliError {
    failed(t!("worker_move.not_open")).hint(t!("worker_move.not_open_hint"))
}

/// An account's refusal or failure, said, with the exit status it calls
/// for: not signed in, the network, or a refusal.
fn account_failed(e: &WorkerError) -> CliError {
    match e {
        WorkerError::Api(erpc_api::ApiError::Unauthorized) | WorkerError::Session(_) => {
            CliError::new(Code::NotSignedIn, e.to_string()).hint(t!("worker_vps.login_hint"))
        }
        WorkerError::Api(_) => CliError::new(Code::Network, e.to_string()),
        _ => CliError::new(Code::Failed, e.to_string()),
    }
}

/// Whether a server or line on the account's record is not ended: one the
/// account reads as gone, or cancelled, is no longer the environment's.
fn live(state: &account::State) -> bool {
    *state != account::State::Gone && state.as_str() != "cancelled"
}

/// How many servers, in the slot in use and in all, and lines `env` holds
/// that are not ended.
fn holding(env: &EnvDetail) -> (usize, usize, usize) {
    let servers: Vec<_> = env.servers.iter().filter(|s| live(&s.state)).collect();
    let active = servers
        .iter()
        .filter(|s| s.slot == account::Slot::Active)
        .count();
    let lines = env.lines.iter().filter(|l| live(&l.state)).count();
    (active, servers.len(), lines)
}

/// Asks the account whether it lets this sign-in end what environment
/// `plan.env` would run on there: before anything is reached, SSH
/// included.
pub(crate) async fn probe(api: &impl Account, plan: &Plan) -> Result<(), CliError> {
    api.may_manage(&plan.name, &plan.env)
        .await
        .map_err(|e| match &e {
            WorkerError::Refused(r) if r.status == 403 => not_open(),
            _ => not_moved(&plan.env, account_failed(&e)),
        })
}

/// The app's record as `plan` writes it, as JSON: what is compared with the
/// record the account has.
fn planned(plan: &PutApp) -> Value {
    serde_json::to_value(plan).unwrap_or(Value::Null)
}

/// Whether `a`, the app's record in the account, says what `plan` would
/// write of it.
fn app_as_planned(a: &account::App, plan: &PutApp) -> bool {
    let want = planned(plan);
    let source = a
        .wallet
        .as_ref()
        .and_then(|w| w.source_kind.as_ref())
        .and_then(|k| serde_json::to_value(k).ok());
    a.chain == want["chain"].as_str().unwrap_or_default()
        && a.template.as_deref() == want["template"].as_str()
        && a.wallet.as_ref().map(|w| w.pubkey.as_str()) == want["wallet"]["pubkey"].as_str()
        && source.as_ref() == want["wallet"].get("sourceKind")
}

/// Whether `a` is another app than `plan`'s: on another chain, or with
/// another wallet, or with one where erpc.toml has none. Its template and
/// where its key is kept are brought to erpc.toml's.
fn app_is_another(a: &account::App, plan: &PutApp) -> bool {
    let want = planned(plan);
    a.chain != want["chain"].as_str().unwrap_or_default()
        || a.wallet
            .as_ref()
            .is_some_and(|w| Some(w.pubkey.as_str()) != want["wallet"]["pubkey"].as_str())
}

/// Whether `env`, as the account keeps it, can be this move's: what it
/// holds is at most the server in use and the lines the move takes in.
/// With other facts than erpc.toml's, it can be one only when it holds
/// nothing yet, or the server in use, which the account is then asked to
/// say is this one.
fn can_be_ours(env: &EnvDetail, plan: &Plan) -> bool {
    let (active, servers, lines) = holding(env);
    let holds = active == servers
        && active <= usize::from(plan.server.is_some())
        && lines <= plan.lines.len();
    let empty = servers == 0 && lines == 0;
    // A record a deploy was made to is in use from another checkout: its
    // facts are not written over from this erpc.toml.
    let in_use = env.deployed.is_some() && env.facts != plan.facts;
    holds && !in_use && (env.facts == plan.facts || empty || active == 1)
}

/// Whether `env` holds a server the account reads as gone. [`can_be_ours`]
/// counts the others: those, in any slot, the move would not take in. A
/// gone one is read by the commands that work on a moved environment all
/// the same, so it is not moved into.
fn holds_a_gone_server(env: &EnvDetail) -> bool {
    env.servers.iter().any(|s| !live(&s.state))
}

/// What the account has of `plan`'s app and environment, read and decided
/// on before anything is written: refused when it is another app, an
/// environment in an older form, or one that holds what is not this
/// move's.
async fn what_is_there(
    api: &impl Account,
    plan: &Plan,
) -> Result<(Option<account::App>, Option<EnvDetail>), CliError> {
    let app = match api.app(&plan.name).await {
        Ok(app) => Some(app),
        Err(WorkerError::Refused(r)) if r.code == Some(AccountCode::WorkerNotFound) => None,
        Err(e) => return Err(not_moved(&plan.env, account_failed(&e))),
    };
    if app.as_ref().is_some_and(|a| app_is_another(a, &plan.app)) {
        return Err(failed(t!(
            "worker_move.app_differs",
            app = plan.name.as_str()
        )));
    }
    let found = match &app {
        None => None,
        Some(_) => match api.env(&plan.name, &plan.env).await {
            Ok(env) => Some(env),
            Err(WorkerError::Refused(r)) if r.code == Some(AccountCode::EnvNotFound) => None,
            Err(e) => return Err(not_moved(&plan.env, account_failed(&e))),
        },
    };
    if let Some(env) = &found {
        // An older form keeps its server and lines where this erpc does
        // not read them: it would look as if it held none.
        if env.facts_format < account::FACTS_FORMAT {
            return Err(failed(t!(
                "worker_account.older_format",
                env = plan.env.as_str()
            )));
        }
        // Every server the record holds that this move does not take in,
        // in any slot and any state, is refused: the commands that work on
        // a moved environment read them all, gone ones included.
        if holds_a_gone_server(env) || !can_be_ours(env, plan) {
            return Err(
                failed(t!("worker_move.env_differs", env = plan.env.as_str()))
                    .hint(t!("worker_move.env_differs_hint")),
            );
        }
    }
    Ok((app, found))
}

/// Writes `plan` to the account, each step one the account answers the
/// same way when it is sent again, so a move stopped half way goes on.
/// Everything is read and decided before anything is written. `app_running`
/// is whether the app runs on the server now. Returns the app's id and the
/// environment as the account then keeps it.
pub(crate) async fn take_in(
    api: &impl Account,
    plan: &Plan,
    app_running: bool,
) -> Result<(String, EnvDetail), CliError> {
    let (app, found) = what_is_there(api, plan).await?;
    // A server already in the slot in use is sent again first, as the
    // account keeps it, so that the account says whether it is this one
    // (the same answer) or another (a refusal) before anything is written.
    let mut confirmed = None;
    if let (Some(env), Some((kind, id))) = (&found, plan.server)
        && env.servers.iter().any(|s| s.slot == account::Slot::Active)
    {
        confirmed = Some(
            api.adopt_server(
                &plan.name,
                &plan.env,
                &send_server(env, kind, id, app_running),
            )
            .await
            .map_err(|e| not_moved(&plan.env, taken_elsewhere(&e, &plan.env)))?
            .record,
        );
    }
    // From the first write on, whatever stops the move is said, here and
    // only here, as a move that stopped part way.
    written(api, plan, app_running, (app, found, confirmed))
        .await
        .map_err(|e| part_way(&plan.env, e, true))
}

/// The server in the slot in use as a take-in sends it: with whether the
/// app runs as the account records it, else as the agent said.
fn send_server(env: &EnvDetail, kind: ServerKind, id: u64, app_running: bool) -> AdoptServer {
    let running = env
        .servers
        .iter()
        .find(|s| s.slot == account::Slot::Active)
        .map_or(app_running, |s| s.app_running);
    AdoptServer::new(kind, id, AdoptSlot::Active, Some(running))
}

/// [`take_in`] from its first write on. An error is its cause alone:
/// [`take_in`] says what became of the move.
async fn written(
    api: &impl Account,
    plan: &Plan,
    app_running: bool,
    (app, found, confirmed): (Option<account::App>, Option<EnvDetail>, Option<EnvDetail>),
) -> Result<(String, EnvDetail), CliError> {
    let failed_ = |e: WorkerError| account_failed(&e);
    // The app's record: made, or brought to what erpc.toml says.
    let app = match app {
        Some(app) if app_as_planned(&app, &plan.app) => app,
        Some(app) => {
            let mut body = plan.app.clone();
            body.expected_revision = app.revision;
            api.put_app(&plan.name, &body)
                .await
                .map_err(failed_)?
                .record
        }
        None => {
            api.put_app(&plan.name, &plan.app)
                .await
                .map_err(failed_)?
                .record
        }
    };
    let mut env = match (confirmed, found) {
        (Some(env), _) | (None, Some(env)) => env,
        (None, None) => {
            api.put_env(&plan.name, &plan.env, &PutEnv::new(0, plan.facts.clone()))
                .await
                .map_err(failed_)?
                .record
        }
    };
    // The server, into the slot in use, when it is not there yet.
    if let Some((kind, id)) = plan.server
        && !env.servers.iter().any(|s| s.slot == account::Slot::Active)
    {
        env = api
            .adopt_server(
                &plan.name,
                &plan.env,
                &send_server(&env, kind, id, app_running),
            )
            .await
            .map_err(|e| taken_elsewhere(&e, &plan.env))?
            .record;
    }
    // The facts: brought to this machine's record, once what the
    // environment holds is known to be this move's.
    if env.facts != plan.facts {
        let body = PutEnv::new(env.revision, plan.facts.clone()).keeping_deploy(&env);
        env = api
            .put_env(&plan.name, &plan.env, &body)
            .await
            .map_err(failed_)?
            .record;
    }
    // The lines: one sent again is taken in once. The account names them by
    // its own ids only, so they are confirmed as they are sent.
    for (kind, id) in &plan.lines {
        env = api
            .adopt_line(&plan.name, &plan.env, &AdoptLine::new(kind.clone(), *id))
            .await
            .map_err(|e| line_refused(&e, plan, *id))?
            .record;
    }
    // What the environment holds is now this move's, and nothing else.
    let (_, servers, lines) = holding(&env);
    if servers != usize::from(plan.server.is_some()) || lines != plan.lines.len() {
        return Err(
            failed(t!("worker_move.env_differs_why", env = plan.env.as_str()))
                .hint(t!("worker_move.env_differs_hint")),
        );
    }
    // A record taken in again keeps the state it had: brought to whether
    // the app runs now, as the agent said.
    if plan.server.is_some()
        && env
            .servers
            .iter()
            .any(|s| s.slot == account::Slot::Active && s.app_running != app_running)
    {
        env = api
            .set_app_running(&plan.name, &plan.env, &account::Slot::Active, app_running)
            .await
            .map_err(failed_)?;
    }
    Ok((app.id, env))
}

/// Why a take-in was refused: another environment of the account has the
/// server or the line, or this one has another server in use; any other
/// refusal as it came. The cause alone: the caller says what became of the
/// move.
fn taken_elsewhere(e: &WorkerError, env: &str) -> CliError {
    match e {
        WorkerError::Refused(r) if r.code == Some(AccountCode::AlreadyAttached) => {
            failed(t!("worker_move.attached_elsewhere_why"))
                .hint(t!("worker_move.attached_elsewhere_hint"))
        }
        WorkerError::Refused(r) if r.code == Some(AccountCode::SlotOccupied) => {
            failed(t!("worker_move.env_differs_why", env)).hint(t!("worker_move.env_differs_hint"))
        }
        other => account_failed(other),
    }
}

/// A line the account does not take into an environment (a Bundle's part)
/// said so, with its product id; any other refusal as [`taken_elsewhere`]
/// says it.
fn line_refused(e: &WorkerError, plan: &Plan, id: u64) -> CliError {
    let env = plan.env.as_str();
    match e {
        // Not this account's, or no longer: most often ended, as a line run
        // out of credit is. Taken off erpc.toml's record, the rest moves.
        WorkerError::Refused(r) if r.code == Some(AccountCode::ResourceNotFound) => {
            failed(t!("worker_move.line_not_found", env, id)).hint(t!(
                "worker_move.line_not_found_hint",
                id,
                scope = plan.scope.as_str()
            ))
        }
        WorkerError::Refused(r) if r.code == Some(AccountCode::NotAdoptable) => {
            let reason = r.reason().unwrap_or_default();
            let message = if reason == "bundle_part" {
                t!("worker_move.bundle_part", env, id)
            } else if reason.is_empty() {
                t!("worker_move.not_adoptable_unsaid", env, id)
            } else {
                t!(
                    "worker_move.not_adoptable",
                    env,
                    id,
                    reason = crate::storage::clean(&reason)
                )
            };
            failed(message).hint(t!("worker_move.not_adoptable_hint", id))
        }
        other => taken_elsewhere(other, env),
    }
}

/// `erpc worker move --to account`.
pub(crate) async fn run(json: bool, app: &App, yes: bool) -> Result<(Value, String), CliError> {
    let (path, file) = crate::worker::load(&app.dir)?;
    let in_file = crate::worker::env_of(&file, app)?.clone();
    if in_file.account {
        let text = t!("worker_move.already", env = app.env.as_str());
        return Ok((json!({ "moved": false, "already": true }), text));
    }
    // An environment whose facts a 1Password item keeps is read by every
    // checkout that reads the item; moving it would need the item to say so
    // to all of them, which it does not yet.
    if in_file.inventory.is_some() {
        return Err(failed(t!("worker_move.in_item", env = app.env.as_str())));
    }
    // No server at all: deployed first, then moved.
    if in_file.resource.is_none() && in_file.host.is_none() {
        return Err(failed(t!("worker_move.no_server", env = app.env.as_str()))
            .hint(t!("worker_move.not_ready_hint", scope = app.scope())));
    }
    // A server not set up yet (no address or no host key in erpc.toml):
    // once moved, nothing could finish it, since a deploy there takes no
    // address. Deployed first, then moved.
    if (in_file.resource.is_some() || in_file.host.is_some())
        && (in_file.host.is_none() || in_file.host_key.is_none())
    {
        return Err(failed(t!("worker_move.not_ready", env = app.env.as_str()))
            .hint(t!("worker_move.not_ready_hint", scope = app.scope())));
    }
    // More settings or secret settings than the account keeps the names of:
    // once moved, no deploy could go through.
    let max = crate::worker::deploy_account::NAMES_MAX;
    if file.vars.len() > max || file.secrets.len() > max {
        return Err(failed(t!(
            "worker_move.too_many",
            env = app.env.as_str(),
            max
        )));
    }
    // A backup's keys would go into the account's record, and the account's
    // delete would drop them without revoking them: not moved yet.
    if in_file.backup.is_some() {
        return Err(failed(t!("worker_move.backup", env = app.env.as_str()))
            .hint(t!("worker_move.backup_hint", scope = app.scope())));
    }
    let mut plan = plan(&file, &app.env, &in_file)?;
    plan.scope = app.scope();
    ask(app, &plan, yes, json)?;
    let signed = kept::Signed::open().await?;
    let pins = kept::pins_path().map_err(failed)?;
    // Whether the app runs on the server now, from its agent: read once the
    // account is known to let this sign-in end what it will run on.
    let running = || {
        if plan.server.is_some() && in_file.host.is_some() {
            let (_, id, session) = crate::worker::remote::reach(app, None)?;
            let answer = crate::worker::remote::ctl_ok(&session, &id, Verb::Status, None)
                .map_err(|e| failed(t!("worker_move.state_unread", error = e.message)))?;
            Ok(runs(answer["agent"]["state"].as_str()))
        } else {
            Ok(false)
        }
    };
    let file = Read {
        path: &path,
        read: &file,
    };
    run_with(app, &plan, file, (&signed, &pins), running).await
}

/// erpc.toml as the move read it, and where it is.
struct Read<'a> {
    path: &'a std::path::Path,
    read: &'a Manifest,
}

/// The move once agreed to, through the signed-in `api` and this machine's
/// pins at `pins`: the account is asked first whether it lets this sign-in
/// end what the environment will run on, then `running` says whether the
/// app runs on the server, then the account is written, its record checked
/// as the commands after the move read it, erpc.toml changed, and then this
/// machine's own record pinned. A stop after the account was written to is
/// said as a move that stopped part way; a pin that could not be written,
/// on stderr, under `--json` too.
async fn run_with(
    app: &App,
    plan: &Plan,
    file: Read<'_>,
    (api, pins): (&impl Account, &std::path::Path),
    running: impl FnOnce() -> Result<bool, CliError>,
) -> Result<(Value, String), CliError> {
    // Nothing is reached before the account is known to let this sign-in
    // end what the environment will run on there.
    probe(api, plan).await?;
    let app_running = running().map_err(|e| not_moved(&plan.env, e))?;
    let (app_id, detail) = take_in(api, plan, app_running).await?;
    let after = |e: CliError| part_way(&plan.env, e, true);
    // The record is read as the commands that work on a moved environment
    // read it: what they would refuse is not moved into. Their hints are
    // for a moved environment, which this is not.
    works_once_moved(app, &detail).map_err(|e| part_way(&plan.env, e, false))?;
    let own = trusted(&app_id, plan, &detail).map_err(after)?;
    let uid = api.uid().await.map_err(after)?;
    // erpc.toml first, then what this machine trusts: a stop at erpc.toml
    // leaves nothing pinned, and a pin that could not be written leaves
    // nothing trusted unasked: the next command asks, or stops while the
    // record cannot be read.
    finish(file.path, app, file.read).map_err(after)?;
    let key = kept::pin_key(&uid, &plan.name, &app.env);
    // Said on stderr under `--json` too, as the note before the yes is: a
    // script is told that nothing is trusted here yet.
    let say = crate::node::common::Say { quiet: false };
    if let Err(error) = kept::pin(pins, &key, &own) {
        say.line(&format!(
            "warning: {}",
            t!("worker_move.not_pinned", env = app.env.as_str(), error)
        ));
    } else if let Err(error) = kept::see_app(pins, &key, &plan.facts.firewall.app_allow) {
        // The app's list on the server is the one this machine moved, not
        // what the account answered: the next deploy says any change made
        // meanwhile.
        say.line(&format!(
            "warning: {}",
            t!("worker_deploy_account.seen_not_updated", error)
        ));
    }
    let answer = json!({
        "moved": true,
        "env": app.env,
        "server": plan.server.is_some(),
        "lines": plan.lines.len(),
        "appRunning": app_running,
        "account": kept::account_json(&detail),
    });
    let mut text = vec![moved_said(plan)];
    text.extend(kept::account_said(&detail));
    Ok((answer, text.join("\n")))
}

/// Whether the commands that work on a moved environment take `detail` as
/// it is: its server reached, its record carried by a deploy, its lines
/// handed to the app.
fn works_once_moved(app: &App, detail: &EnvDetail) -> Result<(), CliError> {
    crate::worker::account::reachable(app, detail, None)?;
    crate::worker::deploy_account::refuse_record(app, detail)?;
    crate::worker::deploy_account::lines_in_use(app, detail)?;
    Ok(())
}

/// `e`, the cause of a stop after the account was written to, said as a
/// move that stopped part way: erpc.toml is as it was. `keep_hint`: whether
/// `e`'s own hint holds for an environment that is not moved; else the
/// move's own is said.
fn part_way(env: &str, e: CliError, keep_hint: bool) -> CliError {
    let message = t!("worker_move.part_way", env, why = e.message);
    let hint = match e.hint {
        Some(hint) if keep_hint => hint,
        _ => t!("worker_move.part_way_hint"),
    };
    CliError::new(e.code, message).hint(hint)
}

/// `e`, the cause of a stop before anything was written, said as a move
/// that did not happen.
fn not_moved(env: &str, e: CliError) -> CliError {
    let message = t!("worker_move.not_moved", env, why = e.message);
    match e.hint {
        Some(hint) => CliError::new(e.code, message).hint(hint),
        None => CliError::new(e.code, message),
    }
}

/// What this machine trusts of the environment once it is moved: its own
/// record, not what the account answered. The two must reach the server
/// the same way, or nothing is trusted and erpc.toml is left as it was.
fn trusted(app_id: &str, plan: &Plan, detail: &EnvDetail) -> Result<Anchor, CliError> {
    // The server in use is the one this move took in, by the id the
    // account answered with for it.
    let own = Anchor::of_facts(app_id, &plan.facts, Anchor::of(app_id, detail).server);
    if Anchor::of(app_id, detail) == own {
        Ok(own)
    } else {
        Err(failed(t!(
            "worker_move.changed_meanwhile",
            env = plan.env.as_str()
        )))
    }
}

/// What the move took in: its server, if it had one, and its lines.
fn taken_said(plan: &Plan) -> String {
    let lines = plan.lines.len();
    if plan.server.is_some() {
        tn!("worker_move.with_server", lines)
    } else {
        tn!("worker_move.without_server", lines)
    }
}

fn moved_said(plan: &Plan) -> String {
    t!(
        "worker_move.moved",
        env = plan.env.as_str(),
        taken = taken_said(plan)
    )
}

/// The question asked before the move: what it takes in, then what does
/// not work on the environment once moved.
fn question(app: &App, plan: &Plan) -> String {
    format!(
        "{} {}",
        t!(
            "worker_move.question",
            env = app.env.as_str(),
            taken = taken_said(plan)
        ),
        loses()
    )
}

/// What changes once the environment is moved, by part: what the person
/// is told before the one-way yes, at a terminal after the question and
/// under `--yes` on stderr. The first says it is one way; each of the
/// others is one of the groups of docs/worker.md's "What changes once
/// moved", which lists more.
fn loses() -> String {
    loses_parts().map(|(_, text)| text).join(" ")
}

/// The parts of [`loses`], each by its catalog key.
fn loses_parts() -> [(&'static str, String); 8] {
    [
        ("worker_move.loses_oneway", t!("worker_move.loses_oneway")),
        ("worker_move.loses_access", t!("worker_move.loses_access")),
        (
            "worker_move.loses_commands",
            t!("worker_move.loses_commands"),
        ),
        ("worker_move.loses_deploy", t!("worker_move.loses_deploy")),
        ("worker_move.loses_delete", t!("worker_move.loses_delete")),
        ("worker_move.loses_bundle", t!("worker_move.loses_bundle")),
        ("worker_move.loses_others", t!("worker_move.loses_others")),
        ("worker_move.loses_more", t!("worker_move.loses_more")),
    ]
}

/// Asks before the move, which cannot be undone: at a terminal, unless
/// `yes`; with nobody to ask and no `yes`, refused.
fn ask(app: &App, plan: &Plan, yes: bool, json: bool) -> Result<(), CliError> {
    // What stops working once moved is said before the move, under --yes
    // too: on stderr, as the move starts.
    if yes {
        crate::node::common::Say { quiet: false }.line(&format!("note: {}", loses()));
        return Ok(());
    }
    if !crate::account::session::has_terminal() || json {
        return Err(CliError::new(
            Code::NeedsTerminal,
            t!("worker_move.needs_yes", env = app.env.as_str()),
        )
        .hint(t!("worker_move.needs_yes_hint", scope = app.scope())));
    }
    if crate::node::common::confirm(&question(app, plan)).map_err(failed)? {
        Ok(())
    } else {
        Err(CliError::new(Code::Declined, t!("worker_move.declined")))
    }
}

/// The last step: `erpc.toml` keeps only `account = true` for the
/// environment. Read again first: changed in any way since the move read it
/// as `read` (a deploy, a firewall rule, the wallet), it is left as it is,
/// and the move is run again.
fn finish(path: &std::path::Path, app: &App, read: &Manifest) -> Result<(), CliError> {
    let now = Manifest::load(path).map_err(|e| failed(e.to_string()))?;
    if now != *read {
        return Err(failed(t!(
            "worker_move.file_changed",
            env = app.env.as_str()
        )));
    }
    let record = crate::worker::EnvRecord {
        path,
        app: &now.name,
        env: &app.env,
    };
    record
        .save(
            &Env {
                account: true,
                ..Env::default()
            },
            None,
        )
        .map_err(failed)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use erpc_api::worker::{Refusal, Written};
    use serde_json::json;

    use super::*;

    const APP_ID: &str = "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13";
    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    fn manifest(env: &str) -> Manifest {
        Manifest::parse(&format!(
            "name = \"bot\"\nchain = \"solana\"\ntemplate = \"solana/hello@1\"\n[env.prod]\n{env}"
        ))
        .expect("a manifest")
    }

    fn deployed_text() -> String {
        // Built, not written out: the endpoint gate reads literals.
        let endpoint = ["https", "edge.erpc.global"].join("://");
        format!(
            "host = \"203.0.113.10\"\nssh_user = \"ubuntu\"\nhost_key = \"{HOST_KEY}\"\n\
             resource = {{ kind = \"vps\", id = \"200002\", region = \"amsterdam\", hourly = true }}\n\
             lines = [{{ kind = \"grpc\", id = \"300003\", endpoint = \"{endpoint}\", hourly = true }}]\n\
             [env.prod.firewall]\nssh_allow = [\"198.51.100.7/32\"]\n"
        )
    }

    fn deployed() -> Manifest {
        manifest(&deployed_text())
    }

    fn refused(status: u16, code: &str) -> WorkerError {
        WorkerError::Refused(Refusal {
            status,
            code: Some(AccountCode::from(code)),
            message: None,
            data: Value::Null,
        })
    }

    fn other_facts() -> Value {
        json!({ "host": "198.51.100.20", "sshUser": null, "sshPort": null, "hostKey": null,
                "firewall": { "sshAllow": [], "appAllow": [] }, "starting": {}, "backup": null,
                "desiredCores": null })
    }

    /// The account, in memory: an app, an environment, what was taken in,
    /// and a step that fails once. A server is in the slot in use; sent
    /// again, the account answers as it does: the same for the same
    /// server and state, a refusal for any other.
    #[derive(Default)]
    #[allow(
        clippy::struct_excessive_bools,
        reason = "a stand-in's switches, one for each case it plays"
    )]
    struct Fake {
        closed: bool,
        app: RefCell<Option<Value>>,
        env: RefCell<Option<Value>>,
        servers: RefCell<Vec<(String, u64, bool)>>,
        lines: RefCell<Vec<(String, u64)>>,
        fail_line_once: RefCell<bool>,
        elsewhere: Vec<u64>,
        /// Lines the account will not take in: a Bundle's parts.
        bundle_parts: Vec<u64>,
        /// The environment comes back in an older form.
        older: bool,
        /// Another line appears in the environment as one is taken in.
        extra_line: bool,
        /// Server rows the record holds besides those taken in, as the
        /// account answers them.
        held: Vec<Value>,
        /// Lines the account does not have (ended, or not this account's).
        missing: Vec<u64>,
        /// The state the lines taken in come back in.
        line_state: Option<&'static str>,
        /// What the account refuses a line with, `not_adoptable`'s reason.
        not_adoptable: Option<Value>,
        /// The environment's record is refused when written.
        refuse_env: bool,
        /// The one call that fails, by its name in `calls`, as `cut_as`.
        cut_off: Option<&'static str>,
        /// How the call `cut_off` names fails.
        cut_as: Cut,
        /// Line rows the record holds besides those taken in.
        held_lines: Vec<Value>,
        /// Another sign-in changes the app's list as the move writes.
        app_list_changed: bool,
        /// Another sign-in writes the environment's facts as the lines are
        /// taken in.
        meddles: bool,
        calls: RefCell<Vec<&'static str>>,
    }

    /// How a call cut off fails: with no answer, its sign-in's session
    /// lost, or the sign-in refused by the account.
    #[derive(Default, Clone, Copy, Debug)]
    enum Cut {
        #[default]
        NoAnswer,
        SessionLost,
        Unauthorized,
    }

    /// Each way a call is cut off, with the exit status it calls for.
    const KINDS: [(Cut, Code); 3] = [
        (Cut::NoAnswer, Code::Network),
        (Cut::SessionLost, Code::NotSignedIn),
        (Cut::Unauthorized, Code::NotSignedIn),
    ];

    /// Whether `e`'s hint is the one to sign in again.
    fn signed_out_hint(e: &CliError) -> bool {
        e.hint.as_deref().is_some_and(|h| h.contains("erpc login"))
    }

    impl Fake {
        /// The failure of the call cut off.
        fn cut(&self) -> WorkerError {
            match self.cut_as {
                Cut::NoAnswer => {
                    WorkerError::Api(erpc_api::ApiError::Malformed("cut off".to_owned()))
                }
                Cut::SessionLost => WorkerError::Session("expired".to_owned()),
                Cut::Unauthorized => WorkerError::Api(erpc_api::ApiError::Unauthorized),
            }
        }

        fn env_value(&self) -> Value {
            let env = self.env.borrow().clone().expect("an environment");
            // In the account's form; built, not written out: the endpoint
            // gate reads literals.
            let endpoint = ["http", "grpc.example.net/"].join("://");
            let servers: Vec<Value> = self
                .servers
                .borrow()
                .iter()
                .map(|(_, _, running)| {
                    json!({ "id": "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60", "slot": "active",
                            "cores": 2, "memoryGb": 8, "region": "amsterdam", "hourly": true,
                            "appRunning": running, "state": "active" })
                })
                .chain(self.held.iter().cloned())
                .collect();
            let lines: Vec<Value> = self
                .lines
                .borrow()
                .iter()
                .map(|(kind, _)| {
                    json!({ "id": "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314", "kind": kind,
                            "hourly": true, "pending": false,
                            "state": self.line_state.unwrap_or("active"),
                            "endpoint": endpoint })
                })
                .chain(self.held_lines.iter().cloned())
                .collect();
            let mut facts = env["facts"].clone();
            if self.app_list_changed && facts.is_object() {
                facts["firewall"]["appAllow"] = json!(["198.51.100.99/32"]);
            }
            json!({
                "name": "prod", "revision": env["revision"],
                "factsFormat": if self.older { 1 } else { 2 },
                "facts": facts, "servers": servers, "desiredCores": null,
                "activeCores": null, "coreOptions": [], "lines": lines,
                "refStates": { "backup": null }, "deployed": null, "deployedApp": null,
                "updatedAt": "2026-10-29T15:40:37.000Z"
            })
        }

        fn detail(&self) -> EnvDetail {
            serde_json::from_value(self.env_value()).expect("an environment")
        }

        fn bump(&self) {
            if let Some(env) = self.env.borrow_mut().as_mut() {
                env["revision"] = json!(env["revision"].as_u64().unwrap_or(0) + 1);
            }
        }

        fn with_env(facts: &Value) -> Self {
            let fake = Self::default();
            *fake.app.borrow_mut() = Some(json!({ "id": APP_ID, "name": "bot", "chain": "solana",
                "template": "solana/hello@1", "wallet": null, "revision": 1 }));
            *fake.env.borrow_mut() = Some(json!({ "revision": 3, "facts": facts }));
            fake
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the stand-in answers at once; the account it stands in for is awaited"
    )]
    impl Account for Fake {
        async fn uid(&self) -> Result<String, CliError> {
            if self.cut_off == Some("uid") {
                // As the account's id read says each kind of failure.
                return Err(account_failed(&self.cut()));
            }
            Ok("user-100001".to_owned())
        }

        async fn may_manage(&self, _: &str, _: &str) -> Result<(), WorkerError> {
            self.calls.borrow_mut().push("probe");
            if self.cut_off == Some("probe") {
                return Err(self.cut());
            }
            if self.closed {
                return Err(WorkerError::Refused(Refusal {
                    status: 403,
                    code: None,
                    message: None,
                    data: Value::Null,
                }));
            }
            Ok(())
        }

        async fn app(&self, _: &str) -> Result<account::App, WorkerError> {
            if self.cut_off == Some("app") {
                return Err(self.cut());
            }
            match self.app.borrow().clone() {
                Some(app) => Ok(serde_json::from_value(app).expect("an app")),
                None => Err(refused(404, "worker_not_found")),
            }
        }

        async fn put_app(
            &self,
            name: &str,
            body: &PutApp,
        ) -> Result<Written<account::App>, WorkerError> {
            self.calls.borrow_mut().push("put_app");
            if self.cut_off == Some("put_app") {
                return Err(self.cut());
            }
            let sent = serde_json::to_value(body).expect("encodes");
            let app = json!({ "id": APP_ID, "name": name, "chain": sent["chain"],
                              "template": sent["template"], "wallet": sent["wallet"],
                              "revision": sent["expectedRevision"].as_u64().unwrap_or(0) + 1 });
            *self.app.borrow_mut() = Some(app.clone());
            Ok(Written::new(
                true,
                serde_json::from_value(app).expect("an app"),
            ))
        }

        async fn env(&self, _: &str, _: &str) -> Result<EnvDetail, WorkerError> {
            if self.cut_off == Some("env") {
                return Err(self.cut());
            }
            if self.env.borrow().is_none() {
                return Err(refused(404, "env_not_found"));
            }
            Ok(self.detail())
        }

        async fn put_env(
            &self,
            _: &str,
            _: &str,
            body: &PutEnv,
        ) -> Result<Written<EnvDetail>, WorkerError> {
            self.calls.borrow_mut().push("put_env");
            if self.cut_off == Some("put_env") {
                return Err(self.cut());
            }
            if self.refuse_env {
                return Err(refused(400, "invalid_request"));
            }
            let sent = serde_json::to_value(body).expect("encodes");
            let revision = self
                .env
                .borrow()
                .as_ref()
                .map_or(0, |e| e["revision"].as_u64().unwrap_or(0));
            if sent["expectedRevision"] != json!(revision) {
                return Err(refused(409, "revision_conflict"));
            }
            *self.env.borrow_mut() =
                Some(json!({ "revision": revision + 1, "facts": sent["facts"] }));
            Ok(written(self.detail()))
        }

        async fn adopt_server(
            &self,
            _: &str,
            _: &str,
            body: &AdoptServer,
        ) -> Result<Written<EnvDetail>, WorkerError> {
            self.calls.borrow_mut().push("adopt_server");
            if self.cut_off == Some("adopt_server") {
                return Err(self.cut());
            }
            let sent = serde_json::to_value(body).expect("encodes");
            let kind = sent["kind"].as_str().unwrap_or_default().to_owned();
            let id = sent["id"].as_u64().unwrap_or_default();
            let running = sent["appRunning"].as_bool().unwrap_or(false);
            if self.elsewhere.contains(&id) {
                return Err(refused(409, "already_attached"));
            }
            let there = self.servers.borrow().first().cloned();
            match there {
                Some(s) if s.0 == kind && s.1 == id && s.2 == running => {
                    return Ok(written(self.detail()));
                }
                Some(_) => return Err(refused(409, "slot_occupied")),
                None => self.servers.borrow_mut().push((kind, id, running)),
            }
            self.bump();
            Ok(written(self.detail()))
        }

        async fn delete_env_ending(
            &self,
            _: &str,
            _: &str,
            _: u64,
        ) -> Result<account::money::Deleting, WorkerError> {
            unreachable!("not asked of this stand-in")
        }

        async fn set_app_running(
            &self,
            _: &str,
            _: &str,
            _: &account::Slot,
            running: bool,
        ) -> Result<EnvDetail, WorkerError> {
            self.calls.borrow_mut().push("set_app_running");
            if self.cut_off == Some("set_app_running") {
                return Err(self.cut());
            }
            for server in self.servers.borrow_mut().iter_mut() {
                server.2 = running;
            }
            self.bump();
            Ok(self.detail())
        }

        async fn end_server(
            &self,
            _: &str,
            _: &str,
            _: &account::Slot,
            _: &str,
        ) -> Result<account::money::Ended, WorkerError> {
            unreachable!("a move ends nothing")
        }

        async fn open_starts(&self, _: &str, _: &str) -> Result<usize, WorkerError> {
            unreachable!("a move reads no starts this way")
        }

        async fn adopt_line(
            &self,
            _: &str,
            _: &str,
            body: &AdoptLine,
        ) -> Result<Written<EnvDetail>, WorkerError> {
            self.calls.borrow_mut().push("adopt_line");
            if self.cut_off == Some("adopt_line") {
                return Err(self.cut());
            }
            if self.fail_line_once.replace(false) {
                return Err(WorkerError::Api(erpc_api::ApiError::Malformed(
                    "cut off".to_owned(),
                )));
            }
            let sent = serde_json::to_value(body).expect("encodes");
            let id = sent["id"].as_u64().unwrap_or_default();
            if self.elsewhere.contains(&id) {
                return Err(refused(409, "already_attached"));
            }
            if self.missing.contains(&id) {
                return Err(refused(404, "resource_not_found"));
            }
            if let Some(data) = &self.not_adoptable {
                return Err(WorkerError::Refused(Refusal {
                    status: 409,
                    code: Some(AccountCode::from("not_adoptable")),
                    message: None,
                    data: data.clone(),
                }));
            }
            if self.bundle_parts.contains(&id) {
                return Err(WorkerError::Refused(Refusal {
                    status: 409,
                    code: Some(AccountCode::from("not_adoptable")),
                    message: None,
                    data: json!({ "reason": "bundle_part" }),
                }));
            }
            let kind = sent["kind"].as_str().unwrap_or_default().to_owned();
            // Sent again: taken in once.
            if !self.lines.borrow().iter().any(|(_, l)| *l == id) {
                self.lines.borrow_mut().push((kind, id));
                if self.extra_line {
                    self.lines.borrow_mut().push(("shreds".to_owned(), 300_009));
                }
                self.bump();
            }
            if self.meddles
                && let Some(env) = self.env.borrow_mut().as_mut()
            {
                env["facts"]["host"] = json!("198.51.100.20");
            }
            Ok(written(self.detail()))
        }
    }

    fn written<T>(record: T) -> Written<T> {
        Written::new(false, record)
    }

    fn plan_of(m: &Manifest) -> Plan {
        plan(m, "prod", &m.env["prod"]).expect("a plan")
    }

    #[test]
    fn a_plan_carries_the_facts_the_server_and_the_lines_by_number() {
        let plan = plan_of(&deployed());
        assert_eq!(plan.server, Some((ServerKind::Vps, 200_002)));
        assert_eq!(plan.lines, [(account::LineKind::Grpc, 300_003)]);
        assert_eq!(plan.facts.host.as_deref(), Some("203.0.113.10"));
        assert_eq!(plan.facts.firewall.ssh_allow, ["198.51.100.7/32"]);
        assert!(plan.facts.starting.is_empty());
        let app = serde_json::to_value(&plan.app).expect("encodes");
        assert_eq!(app["chain"], "solana");
        assert_eq!(app["template"], "solana/hello@1");
        assert_eq!(app["wallet"], Value::Null);
        assert_eq!(app["expectedRevision"], 0);
        // Every fact, each from its own setting.
        let m = manifest(&format!(
            "host = \"203.0.113.10\"\nssh_user = \"deploy\"\nssh_port = 2222\n\
             host_key = \"{HOST_KEY}\"\n\
             resource = {{ kind = \"vps\", id = \"200002\", region = \"amsterdam\", hourly = true }}\n\
             [env.prod.firewall]\nssh_allow = [\"198.51.100.7/32\"]\napp_allow = [\"203.0.113.0/24\"]\n\
             [run]\nport = 8080\n"
        ));
        let facts = plan_of(&m).facts;
        assert_eq!(facts.host.as_deref(), Some("203.0.113.10"));
        assert_eq!(facts.ssh_user.as_deref(), Some("deploy"));
        assert_eq!(facts.ssh_port, Some(2222));
        assert_eq!(facts.host_key.as_deref(), Some(HOST_KEY));
        assert_eq!(facts.firewall.ssh_allow, ["198.51.100.7/32"]);
        assert_eq!(facts.firewall.app_allow, ["203.0.113.0/24"]);
        assert!(facts.backup.is_none());
    }

    #[test]
    fn what_cannot_be_carried_over_whole_is_not_moved() {
        // A start with no outcome yet.
        let starting = manifest(
            "host = \"203.0.113.10\"\n[env.prod.starting]\n\
             server = { key = \"0123456789abcdef0123456789abcdef\", family = \"vps\", product = \"p\" }\n",
        );
        let e = plan(&starting, "prod", &starting.env["prod"]).expect_err("refused");
        assert!(e.message.contains("no outcome yet"), "{}", e.message);
        // A UDP Forwarding line.
        let udp = manifest(
            "host = \"203.0.113.10\"\n\
             lines = [{ kind = \"udp\", id = \"300003\", endpoint = \"0.0.0.0:10001\", hourly = true }]\n",
        );
        let e = plan(&udp, "prod", &udp.env["prod"]).expect_err("refused");
        assert!(e.message.contains("UDP Forwarding"), "{}", e.message);
    }

    #[test]
    fn the_app_runs_when_its_agent_says_it_runs_or_is_coming_up() {
        for state in ["running", "starting", "waiting"] {
            assert!(runs(Some(state)), "{state}");
        }
        for state in [Some("locked"), Some("stopped"), Some("other"), None] {
            assert!(!runs(state), "{state:?}");
        }
    }

    #[tokio::test]
    async fn a_move_writes_the_app_and_the_environment_then_takes_in_what_it_runs_on() {
        let fake = Fake::default();
        let plan = plan_of(&deployed());
        let (app_id, env) = take_in(&fake, &plan, true).await.expect("moved");
        assert_eq!(app_id, APP_ID);
        assert_eq!(
            *fake.calls.borrow(),
            ["put_app", "put_env", "adopt_server", "adopt_line"]
        );
        assert_eq!(*fake.servers.borrow(), [("vps".to_owned(), 200_002, true)]);
        assert_eq!(*fake.lines.borrow(), [("grpc".to_owned(), 300_003)]);
        assert_eq!(env.servers.len(), 1);
        assert_eq!(env.facts, plan.facts);
        assert_eq!(
            trusted(&app_id, &plan, &env).expect("trusted"),
            Anchor::of_facts(APP_ID, &plan.facts, Anchor::of(APP_ID, &env).server)
        );
        // What the move pins is what the account's record then reads as:
        // `status` and the commands find it the same, and ask nothing.
        assert_eq!(
            trusted(&app_id, &plan, &env).expect("trusted"),
            Anchor::of(APP_ID, &env)
        );
    }

    #[tokio::test]
    async fn a_move_stopped_half_way_goes_on_and_the_account_confirms_the_server() {
        let fake = Fake {
            fail_line_once: RefCell::new(true),
            ..Fake::default()
        };
        let plan = plan_of(&deployed());
        assert!(take_in(&fake, &plan, true).await.is_err());
        // Run again, the app now stopped: the server already in the slot is
        // sent again as the account keeps it, which the account answers the
        // same way for this one server, and only the line is new; then the
        // record is brought to whether the app runs now.
        fake.calls.borrow_mut().clear();
        take_in(&fake, &plan, false).await.expect("moved");
        assert_eq!(
            *fake.calls.borrow(),
            ["adopt_server", "adopt_line", "set_app_running"]
        );
        assert_eq!(*fake.servers.borrow(), [("vps".to_owned(), 200_002, false)]);
        assert_eq!(fake.lines.borrow().len(), 1);
        // And again, once all is there: nothing is taken in twice, and the
        // state, as it is, is not written again.
        fake.calls.borrow_mut().clear();
        take_in(&fake, &plan, false).await.expect("moved");
        assert_eq!(fake.lines.borrow().len(), 1);
        assert!(!fake.calls.borrow().contains(&"set_app_running"));
    }

    #[tokio::test]
    async fn a_resumed_move_does_not_take_another_server_in_the_slot_for_its_own() {
        // The slot in use has another server than erpc.toml's: the account
        // refuses the one sent, and the facts are not written over.
        let fake =
            Fake::with_env(&serde_json::to_value(plan_of(&deployed()).facts).expect("facts"));
        fake.servers
            .borrow_mut()
            .push(("vps".to_owned(), 200_099, true));
        let e = take_in(&fake, &plan_of(&deployed()), true)
            .await
            .expect_err("refused");
        assert!(e.message.contains("another server"), "{}", e.message);
        assert!(e.message.contains("was not moved"), "{}", e.message);
        assert_eq!(*fake.calls.borrow(), ["adopt_server"]);
        // With other facts too, and an app record that would be brought to
        // erpc.toml's: still refused, and nothing written before.
        let fake = Fake::with_env(&other_facts());
        if let Some(app) = fake.app.borrow_mut().as_mut() {
            app["template"] = Value::Null;
        }
        fake.servers
            .borrow_mut()
            .push(("vps".to_owned(), 200_099, true));
        assert!(take_in(&fake, &plan_of(&deployed()), true).await.is_err());
        assert_eq!(*fake.calls.borrow(), ["adopt_server"]);
        assert_eq!(
            fake.env.borrow().as_ref().expect("env")["facts"],
            other_facts()
        );
    }

    #[tokio::test]
    async fn an_empty_environment_record_with_other_facts_is_brought_to_erpc_toml() {
        // A move that stopped before it took anything in, then a firewall
        // rule added here: the record holds nothing, and is written over.
        let fake = Fake::with_env(&other_facts());
        let plan = plan_of(&deployed());
        let (_, env) = take_in(&fake, &plan, true).await.expect("moved");
        assert_eq!(env.facts, plan.facts);
        assert_eq!(
            *fake.calls.borrow(),
            ["adopt_server", "put_env", "adopt_line"]
        );
        // That write cut off: said as a move that stopped part way, with
        // the exit status of how it failed.
        for (cut_as, code) in KINDS {
            let fake = Fake {
                cut_off: Some("put_env"),
                cut_as,
                ..Fake::with_env(&other_facts())
            };
            let e = take_in(&fake, &plan, true).await.expect_err("stopped");
            assert!(e.message.contains("stopped part way"), "{}", e.message);
            assert_eq!(e.code, code, "{cut_as:?}");
            assert_eq!(signed_out_hint(&e), code == Code::NotSignedIn, "{cut_as:?}");
            assert_eq!(*fake.calls.borrow(), ["adopt_server", "put_env"]);
        }
    }

    #[tokio::test]
    async fn an_account_that_cannot_end_a_moved_environment_takes_nothing_in() {
        let fake = Fake {
            closed: true,
            ..Fake::default()
        };
        let e = probe(&fake, &plan_of(&deployed()))
            .await
            .expect_err("refused");
        assert!(e.message.contains("does not yet let"), "{}", e.message);
        assert_eq!(*fake.calls.borrow(), ["probe"]);
        assert!(fake.app.borrow().is_none() && fake.env.borrow().is_none());
    }

    #[tokio::test]
    async fn what_the_account_keeps_otherwise_is_refused_before_anything_is_written() {
        // An app of that name on another chain.
        let fake = Fake::default();
        *fake.app.borrow_mut() = Some(json!({ "id": APP_ID, "name": "bot", "chain": "ethereum",
            "template": null, "wallet": null, "revision": 4 }));
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("another chain"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
        // An environment holding more lines than erpc.toml names.
        let fake = Fake::with_env(&other_facts());
        fake.lines
            .borrow_mut()
            .extend([("grpc".to_owned(), 300_004), ("shreds".to_owned(), 300_005)]);
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("other lines"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
        // A line another environment has.
        let fake = Fake {
            elsewhere: vec![300_003],
            ..Fake::default()
        };
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("another environment"), "{}", e.message);
        // A line the account does not take in, a Bundle's part: said so,
        // by its id, and nothing after it is sent.
        let fake = Fake {
            bundle_parts: vec![300_003],
            ..Fake::default()
        };
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("line 300003"), "{}", e.message);
        assert!(e.message.contains("part of a Bundle"), "{}", e.message);
        assert!(
            e.message.contains("the move did not change erpc.toml"),
            "{}",
            e.message
        );
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("ERPC support") && hint.contains("300003"),
            "{hint}"
        );
        assert_eq!(fake.calls.borrow().last(), Some(&"adopt_line"));
        assert!(fake.lines.borrow().is_empty());
    }

    #[tokio::test]
    async fn what_is_trusted_is_this_machines_record_not_the_accounts_last_answer() {
        // Another sign-in writes the environment while it is moved: the
        // account's answer reaches another host, and nothing is trusted.
        let fake = Fake {
            meddles: true,
            ..Fake::default()
        };
        let plan = plan_of(&deployed());
        let (app_id, env) = take_in(&fake, &plan, true).await.expect("taken in");
        assert_eq!(env.facts.host.as_deref(), Some("198.51.100.20"));
        let e = trusted(&app_id, &plan, &env).expect_err("not trusted");
        assert!(
            e.message.contains("changed while it was moved"),
            "{}",
            e.message
        );
    }

    fn checkout(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("erpc.toml");
        std::fs::write(&path, text).expect("erpc.toml");
        (dir, path)
    }

    #[tokio::test]
    async fn an_environment_a_1password_item_keeps_is_not_moved_and_nothing_is_reached() {
        // Joined here, so the hygiene check does not read it as a vault.
        let vault = concat!("abcdefghijklm", "nopqrstuvwxyz");
        let (dir, _) = checkout(&format!(
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\n\
             inventory = {{ vault = \"{vault}\" }}\n"
        ));
        let e = run(true, &App::at(dir.path(), "prod"), true)
            .await
            .expect_err("refused");
        assert!(e.message.contains("1Password item"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_backed_up_environment_is_not_moved_and_nothing_is_reached() {
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\n{}\
             [env.prod.backup]\naccess_key = 100001\nrestic_key = \"3f1c2b9e\"\nhost = \"bot-prod\"\n",
            deployed_text()
        );
        let (dir, path) = checkout(&text);
        let e = run(true, &App::at(dir.path(), "prod"), true)
            .await
            .expect_err("refused");
        assert!(e.message.contains("backed up"), "{}", e.message);
        assert!(e.hint.unwrap_or_default().contains("backup off"));
        assert_eq!(std::fs::read_to_string(&path).expect("read"), text);
    }

    #[tokio::test]
    async fn a_server_not_set_up_yet_is_not_moved_and_nothing_is_reached() {
        // A server bought, with no host key yet.
        let text = "name = \"bot\"\nchain = \"solana\"\n[env.prod]\nhost = \"203.0.113.10\"\n";
        let (dir, path) = checkout(text);
        let e = run(true, &App::at(dir.path(), "prod"), true)
            .await
            .expect_err("refused");
        assert!(
            e.message.contains("no address or no host key"),
            "{}",
            e.message
        );
        assert!(e.hint.unwrap_or_default().contains("erpc worker deploy"));
        assert_eq!(std::fs::read_to_string(&path).expect("read"), text);
    }

    #[test]
    fn what_the_account_reads_as_gone_is_not_counted_and_a_record_in_use_is_not_written_over() {
        let plan = plan_of(&deployed());
        let fake = Fake::default();
        *fake.env.borrow_mut() = Some(
            json!({ "revision": 3, "facts": serde_json::to_value(&plan.facts).expect("facts") }),
        );
        fake.servers
            .borrow_mut()
            .push(("vps".to_owned(), 200_002, true));
        fake.lines.borrow_mut().push(("grpc".to_owned(), 300_003));
        let mut env = fake.detail();
        // A line the account reads as gone is not the environment's.
        let mut gone = env.lines[0].clone();
        gone.id = "9d2b7f31-5e8a-4c61-b0f4-2a7e9c1d6b58".to_owned();
        gone.state = account::State::Gone;
        env.lines.push(gone);
        assert!(can_be_ours(&env, &plan));
        // A record a deploy was made to, with other facts: not written over.
        env.deployed = Some(
            serde_json::from_value(json!({
                "release": "r1", "at": "2026-11-20T00:00:00Z"
            }))
            .expect("a deploy"),
        );
        env.facts.host = Some("198.51.100.9".to_owned());
        assert!(!can_be_ours(&env, &plan));
    }

    #[tokio::test]
    async fn a_session_lost_or_a_sign_in_refused_at_each_call_is_said_as_not_signed_in() {
        let (dir, path, m) = own_server_checkout();
        let before = std::fs::read_to_string(&path).expect("erpc.toml");
        let pins = dir.path().join("worker_account.json");
        let app = App::at(dir.path(), "prod");
        let plan = plan(&m, "prod", &m.env["prod"]).expect("a plan");
        let deployed_plan = plan_of(&deployed());
        let signed_out = |e: &CliError, said: &str, call: &str| {
            assert!(e.message.contains(said), "{call}: {}", e.message);
            assert_eq!(e.code, Code::NotSignedIn, "{call}");
            assert!(
                e.hint.as_deref().unwrap_or_default().contains("erpc login"),
                "{call}: {:?}",
                e.hint
            );
        };
        for cut_as in [Cut::SessionLost, Cut::Unauthorized] {
            // The whole move: before the first write, and after it.
            for (call, said) in [
                ("probe", "was not moved"),
                ("app", "was not moved"),
                ("put_app", "stopped part way"),
                ("put_env", "stopped part way"),
                ("uid", "stopped part way"),
            ] {
                let fake = Fake {
                    cut_off: Some(call),
                    cut_as,
                    ..Fake::default()
                };
                let read = Read {
                    path: &path,
                    read: &m,
                };
                let e = run_with(&app, &plan, read, (&fake, &pins), || Ok(false))
                    .await
                    .expect_err("stopped");
                signed_out(&e, said, call);
                assert!(!pins.exists(), "{call}");
                let now = std::fs::read_to_string(&path).expect("erpc.toml");
                assert_eq!(now, before, "{call}");
            }
            // The environment's record, read before anything is written.
            let fake = Fake {
                cut_off: Some("env"),
                cut_as,
                ..Fake::with_env(&other_facts())
            };
            let e = take_in(&fake, &plan, false).await.expect_err("stopped");
            signed_out(&e, "was not moved", "env");
            // The server and a line of a deployed environment, taken in.
            for call in ["adopt_server", "adopt_line"] {
                let fake = Fake {
                    cut_off: Some(call),
                    cut_as,
                    ..Fake::default()
                };
                let e = take_in(&fake, &deployed_plan, true)
                    .await
                    .expect_err("stopped");
                signed_out(&e, "stopped part way", call);
                assert_eq!(fake.calls.borrow().last(), Some(&call));
            }
            // A move run again: the resend that confirms the server in use,
            // before anything is written.
            let first = Fake {
                fail_line_once: RefCell::new(true),
                ..Fake::default()
            };
            assert!(take_in(&first, &deployed_plan, true).await.is_err());
            let fake = Fake {
                cut_off: Some("adopt_server"),
                cut_as,
                ..first
            };
            fake.calls.borrow_mut().clear();
            let e = take_in(&fake, &deployed_plan, false)
                .await
                .expect_err("stopped");
            signed_out(&e, "was not moved", "adopt_server sent again");
            assert_eq!(*fake.calls.borrow(), ["adopt_server"]);
            // And the app's state, brought to the record last.
            let fake = Fake {
                fail_line_once: RefCell::new(true),
                cut_off: Some("set_app_running"),
                cut_as,
                ..Fake::default()
            };
            assert!(take_in(&fake, &deployed_plan, true).await.is_err());
            let e = take_in(&fake, &deployed_plan, false)
                .await
                .expect_err("stopped");
            signed_out(&e, "stopped part way", "set_app_running");
            assert_eq!(fake.calls.borrow().last(), Some(&"set_app_running"));
        }
    }

    #[tokio::test]
    async fn nobody_to_say_yes_stops_the_move_before_the_account_or_the_server_is_reached() {
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\n{}",
            deployed_text()
        );
        let (dir, path) = checkout(&text);
        // With `--json` and no `--yes`: refused as needing a terminal, before
        // any sign-in is opened, and erpc.toml is as it was.
        let e = run(true, &App::at(dir.path(), "prod"), false)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), text);
    }

    #[test]
    fn the_last_step_leaves_only_the_marker_and_not_over_a_change() {
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\n{}\n[env.staging]\nhost = \"203.0.113.11\"\n",
            deployed_text()
        );
        let (dir, path) = checkout(&text);
        let app = App::at(dir.path(), "prod");
        let read = Manifest::load(&path).expect("read");
        // Changed since the move read it: left as it is.
        std::fs::write(
            &path,
            text.replace(
                "\"198.51.100.7/32\"",
                "\"198.51.100.7/32\", \"198.51.100.8/32\"",
            ),
        )
        .expect("changed");
        let e = finish(&path, &app, &read).expect_err("refused");
        assert!(e.message.contains("erpc.toml changed"), "{}", e.message);
        assert!(!Manifest::load(&path).expect("read").env["prod"].account);
        // As read: only the marker is left, and the other environment is
        // as it was.
        std::fs::write(&path, &text).expect("back");
        finish(&path, &app, &read).expect("written");
        let after = Manifest::load(&path).expect("read back");
        assert!(after.env["prod"].account);
        assert_eq!(after.env["prod"].host, None);
        assert_eq!(after.env["staging"].host.as_deref(), Some("203.0.113.11"));
    }

    #[test]
    fn what_the_move_takes_in_is_said_with_its_server_or_without_and_by_count() {
        let plan = plan_of(&deployed());
        assert!(
            moved_said(&plan).contains("with its server and 1 line;"),
            "{}",
            moved_said(&plan)
        );
        let bare = plan_of(&manifest("host = \"203.0.113.10\"\n"));
        assert!(
            moved_said(&bare).contains("with no server and 0 lines"),
            "{}",
            moved_said(&bare)
        );
    }

    #[test]
    fn mapped_entries_go_into_the_account_in_hex() {
        let mut m = deployed();
        let env = m.env.get_mut("prod").expect("prod");
        env.firewall.ssh_allow =
            vec![erpc_worker::net::Cidr::parse_any("::ffff:198.51.100.7").expect("an address")];
        let plan = plan(&m, "prod", &m.env["prod"]).expect("a plan");
        assert_eq!(plan.facts.firewall.ssh_allow, ["::ffff:c633:6407/128"]);
    }

    /// The words of `text` that look like flags, whole: `--udp` is not
    /// found inside `--udp-port`.
    fn flags_in(text: &str) -> std::collections::BTreeSet<String> {
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .filter(|w| w.starts_with("--"))
            .map(ToOwned::to_owned)
            .collect()
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one list of every refused option, held to the note in four languages"
    )]
    fn what_a_moved_environment_cannot_do_is_said_before_the_yes_for_every_refused_option() {
        use crate::worker::deploy::Where;
        use erpc_core::i18n::Lang;
        type Set = fn(&mut Where);
        // Every field of a deploy's options, named: one added here fails to
        // build until it is decided whether a moved environment takes it,
        // and, if not, the note says so.
        let Where {
            host: _,
            user: _,
            port: _,
            fingerprint: _,
            vps: _,
            new_vps: _,
            region: _,
            plan: _,
            lines: _,
            udp_port: _,
            udp_region: _,
            udp_any_source: _,
            vault: _,
            inline: _,
            forget_lines: _,
            starts: _,
            upto: _,
            kept: _,
        } = Where::default();
        let app = App::at("apps/bot", "prod");
        let refused: [(&str, Set); 20] = [
            ("--host", |w| w.host = Some("203.0.113.10".to_owned())),
            ("--user", |w| w.user = Some("ubuntu".to_owned())),
            ("--port", |w| w.port = Some(2222)),
            ("--fingerprint", |w| {
                w.fingerprint = Some("SHA256:x".to_owned());
            }),
            ("--server", |w| w.vps = Some(200_002)),
            ("--new-server", |w| w.new_vps = true),
            ("--region", |w| w.region = Some("amsterdam".to_owned())),
            ("--plan", |w| w.plan = Some("prod_x".to_owned())),
            ("--grpc", |w| {
                w.lines.push((LineKind::Grpc, None));
            }),
            ("--shreds", |w| {
                w.lines.push((LineKind::Shreds, None));
            }),
            ("--unlimited", |w| {
                w.lines.push((LineKind::Unlimited, None));
            }),
            ("--udp", |w| {
                w.lines.push((LineKind::Udp, None));
            }),
            ("--udp-port", |w| w.udp_port = Some(9000)),
            ("--udp-region", |w| {
                w.udp_region = Some("frankfurt".to_owned());
            }),
            ("--udp-any-source", |w| w.udp_any_source = true),
            ("--vault", |w| w.vault = Some("Private".to_owned())),
            ("--inline", |w| w.inline = true),
            ("--forget-line", |w| {
                w.forget_lines.push("300003".to_owned());
            }),
            // Taken: --yes, and preparing, choose and buy nothing here.
            ("", |w| {
                w.starts = crate::worker::deploy::Starts::from_yes(true);
            }),
            ("", |w| {
                w.upto = crate::worker::deploy::Upto::from_prepare(true);
            }),
        ];
        for lang in [Lang::En, Lang::Ja, Lang::Zh, Lang::Ru] {
            let loses = crate::cli::i18n::speaking(lang, loses);
            let parts = crate::cli::i18n::speaking(lang, loses_parts);
            let part = |key: &str| {
                parts
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, text)| text.clone())
                    .unwrap_or_default()
            };
            let said = flags_in(&loses);
            // The clauses each part is held to, in each language's own
            // words: that the move is one way, who trusts the server without
            // a question, what --yes does not give, what is not reached,
            // what stays charged and until when, what stays written, and
            // where more is listed.
            let meant: [(&str, &[&str]); 8] = match lang {
                Lang::En => [
                    (
                        "worker_move.loses_oneway",
                        &[
                            "The move cannot be undone",
                            "erpc.toml then keeps only account = true, and the account does not give the product ids back",
                        ],
                    ),
                    (
                        "worker_move.loses_access",
                        &[
                            "Every command on it then needs your ERPC sign-in and the account reachable",
                            "this machine trusts its server as moved",
                            "another machine signed in to the same ERPC account trusts it once with a yes at a terminal",
                            "another ERPC account does not see it",
                            "--yes and --json do not give it",
                            "when what the account says of the server changes, it is asked again at a terminal",
                            "an ERPC server the account does not show as active is not reached, not even to stop the app",
                        ],
                    ),
                    (
                        "worker_move.loses_commands",
                        &[
                            "rollback, backup, api, trades and bench do not work on it yet",
                            "firewall does, on the account's lists",
                            "at most 16 addresses each, erpc's own counted in the SSH list",
                            "status no longer says what it costs by the hour or how long the credit lasts",
                        ],
                    ),
                    (
                        "worker_move.loses_deploy",
                        &[
                            "deploy no longer takes --host",
                            "its server cannot be chosen or bought, no line can be added or taken off the record",
                            "a deploy cannot bring it back into erpc.toml or 1Password",
                            "a deploy is refused while a line on the account's record that has not ended is not active",
                        ],
                    ),
                    (
                        "worker_move.loses_delete",
                        &[
                            "delete --release-server does not reach the server or remove the worker",
                            "it asks the account to end everything the environment runs on",
                            "the account ends nothing while anything on it but a line bought as part of a Bundle (which it takes off the environment without ending it, whatever its state) is not paid by the hour, cannot be ended in the state it is in, or is a start with no outcome",
                            "its hourly server and lines then stay charged, and are ended only when that is settled and the delete is run again",
                            "On a server of your own it is asked at a terminal only, --yes not being enough, and the worker keeps running there",
                            "A plain delete, delete --forget and delete --forget-line are refused",
                        ],
                    ),
                    (
                        "worker_move.loses_bundle",
                        &[
                            "A line bought as part of a Bundle is not taken in: the account refuses it, and the move stops there, what was already written to the account staying there",
                            "until its Bundle is on the account's record it may be taken in",
                            "erpc takes it off the record only by deleting the environment, which does not end it, and cannot end it apart from its Bundle",
                        ],
                    ),
                    (
                        "worker_move.loses_others",
                        &[
                            "While an environment of this machine is kept in the account",
                            "a delete --release-server --yes of this machine's other environments that would end a server is refused",
                            "and of this one too once another is kept there",
                            "without --yes, it is asked at a terminal",
                        ],
                    ),
                    (
                        "worker_move.loses_more",
                        &["More differences are listed in docs/worker.md"],
                    ),
                ],
                Lang::Ja => [
                    (
                        "worker_move.loses_oneway",
                        &[
                            "移すと元に戻せません",
                            "erpc.toml には account = true だけが残り、アカウントは商品 ID を返しません",
                        ],
                    ),
                    (
                        "worker_move.loses_access",
                        &[
                            "この環境のすべてのコマンドで ERPC へのサインインとアカウントへの接続が要ります",
                            "このマシンは、移したとおりにサーバーを信頼します",
                            "同じ ERPC アカウントにサインインしたほかのマシンでは、一度、端末で yes と答えてサーバーを信頼する必要があります",
                            "ほかの ERPC アカウントからは見えません",
                            "--yes や --json では答えられません",
                            "アカウントが示すサーバーの内容が変わると、端末でもう一度尋ねます",
                            "アカウントが active と示さない ERPC のサーバーには接続せず、アプリを止めることもできません",
                        ],
                    ),
                    (
                        "worker_move.loses_commands",
                        &[
                            "rollback・backup・api・trades・bench はまだ使えません",
                            "firewall は、アカウントの一覧に対して使えます",
                            "一覧はそれぞれ 16 件までで、SSH の一覧には erpc 自身のアドレスも数えます",
                            "status は、時間あたりの料金やクレジットがいつまでもつかを示さなくなります",
                        ],
                    ),
                    (
                        "worker_move.loses_deploy",
                        &[
                            "を受けなくなります",
                            "サーバーを選ぶことや買うことも、回線を足すことや記録から外すこともできず",
                            "deploy で erpc.toml や 1Password に戻すこともできません",
                            "アカウントの記録に、終了しておらず active でもない回線がある間は、deploy は断られます",
                        ],
                    ),
                    (
                        "worker_move.loses_delete",
                        &[
                            "delete --release-server はサーバーに接続せず、ワーカーも消しません",
                            "環境が使っているものすべての終了をアカウントに頼み",
                            "アカウントは、Bundle の一部として買った回線（状態にかかわらず、終了せずに環境から外します）のほかに、時間課金でないものが 1 つでもあるか、今の状態では終了できないものがあるか、結果の分からない開始がある間は、何も終了しません",
                            "そのとき、時間課金のサーバーや回線は課金されたままで、それが片付いてから delete をもう一度実行して、はじめて終了します",
                            "自分のサーバーでは端末でだけ尋ね、--yes では進まず、そこのワーカーは動き続けます",
                            "delete だけ、delete --forget、delete --forget-line は断られます",
                        ],
                    ),
                    (
                        "worker_move.loses_bundle",
                        &[
                            "Bundle の一部として買った回線は取り込まれません。アカウントが断り、移動はそこで止まり、アカウントにすでに書いたものはそこに残ります",
                            "その Bundle がアカウントに記録されるまでは取り込まれることがあり",
                            "erpc がその回線を記録から外せるのは環境を削除するときだけで、そのときも回線は終了せず、Bundle と別に終了することもできません",
                        ],
                    ),
                    (
                        "worker_move.loses_others",
                        &[
                            "このマシンの環境がアカウントに保管されている間は",
                            "このマシンのほかの環境の delete --release-server --yes は、サーバーを終了するものなら断られます",
                            "ほかの環境もアカウントに保管されれば、この環境のものも同じです",
                            "--yes を付けなければ、端末で尋ねます",
                        ],
                    ),
                    (
                        "worker_move.loses_more",
                        &[
                            "ほかの違いは、docs/worker.md の「What changes once moved」に挙げています",
                        ],
                    ),
                ],
                Lang::Zh => [
                    (
                        "worker_move.loses_oneway",
                        &[
                            "移动后无法撤回",
                            "erpc.toml 只保留 account = true，账户不会交还产品 ID",
                        ],
                    ),
                    (
                        "worker_move.loses_access",
                        &[
                            "对它的每个命令都需要你的 ERPC 登录以及能连接到账户",
                            "本机按移动时的内容信任其服务器",
                            "登录同一 ERPC 账户的其他机器则要在终端上回答一次 yes 来信任它",
                            "其他 ERPC 账户则看不到它",
                            "--yes 和 --json 无法代替",
                            "账户所说的服务器信息一旦变化，就会在终端上再次询问",
                            "账户未显示为 active 的 ERPC 服务器不会被连接，连停止应用也不行",
                        ],
                    ),
                    (
                        "worker_move.loses_commands",
                        &[
                            "rollback、backup、api、trades 和 bench 暂时还不能用于它",
                            "firewall 可以，作用于账户中的列表",
                            "每个列表最多 16 个地址，SSH 列表中 erpc 自身的地址也计入",
                            "status 不再显示每小时的费用以及积分还能用多久",
                        ],
                    ),
                    (
                        "worker_move.loses_deploy",
                        &[
                            "deploy 不再接受 --host",
                            "无法选择或购买其服务器，无法添加线路或将线路从记录中移除",
                            "deploy 也无法再把它改回由 erpc.toml 或 1Password 保管",
                            "账户记录中有尚未终止且不处于 active 的线路时，deploy 会被拒绝",
                        ],
                    ),
                    (
                        "worker_move.loses_delete",
                        &[
                            "delete --release-server 不会连接服务器，也不会删除 worker",
                            "它请账户终止该环境使用的一切",
                            "而只要其中除作为 Bundle 一部分购买的线路（无论其状态如何，账户都会将其从环境中移除而不终止）以外，有任何非按小时计费的内容、在当前状态下无法终止的内容，或有结果未知的开通，账户就什么都不终止",
                            "此时按小时计费的服务器和线路会继续计费，要等那项内容处理完毕后再次运行 delete，才会被终止",
                            "如果是你自己的服务器，只会在终端上询问，仅有 --yes 不会继续，其上的 worker 会继续运行",
                            "单独的 delete、delete --forget 和 delete --forget-line 会被拒绝",
                        ],
                    ),
                    (
                        "worker_move.loses_bundle",
                        &[
                            "作为 Bundle 一部分购买的线路不会被纳入：账户会拒绝它，移动在此停止，已写入账户的内容会留在账户中",
                            "在其 Bundle 记入账户之前，它可能会被纳入",
                            "erpc 只有在删除该环境时才能将其从记录中移除，且这不会终止它；erpc 也无法脱离其 Bundle 单独终止它",
                        ],
                    ),
                    (
                        "worker_move.loses_others",
                        &[
                            "只要本机有环境保管在账户中",
                            "本机其他环境中会终止服务器的 delete --release-server --yes 就会被拒绝",
                            "一旦另有环境保管在账户中，此环境的也一样",
                            "不加 --yes 时，会在终端上询问",
                        ],
                    ),
                    (
                        "worker_move.loses_more",
                        &["更多差异列在 docs/worker.md 的“What changes once moved”中"],
                    ),
                ],
                Lang::Ru => [
                    (
                        "worker_move.loses_oneway",
                        &[
                            "Перенос нельзя отменить",
                            "в erpc.toml останется только account = true, а аккаунт не возвращает ID продуктов",
                        ],
                    ),
                    (
                        "worker_move.loses_access",
                        &[
                            "каждая команда для него требует входа в ERPC и доступного аккаунта",
                            "эта машина доверяет его серверу таким, каким его перенесли",
                            "другая машина, вошедшая в тот же аккаунт ERPC, доверяет ему один раз, ответив yes в терминале",
                            "другой же аккаунт ERPC его не видит",
                            "--yes и --json этого не дают",
                            "когда то, что аккаунт говорит о сервере, меняется, это снова спрашивается в терминале",
                            "к серверу ERPC, который аккаунт не показывает активным, не подключаются — даже чтобы остановить приложение",
                        ],
                    ),
                    (
                        "worker_move.loses_commands",
                        &[
                            "rollback, backup, api, trades и bench с ним пока не работают",
                            "firewall работает — со списками аккаунта",
                            "в каждом не больше 16 адресов, в списке SSH считается и адрес самого erpc",
                            "status больше не показывает почасовую стоимость и на сколько хватит кредитов",
                        ],
                    ),
                    (
                        "worker_move.loses_deploy",
                        &[
                            "deploy больше не принимает --host",
                            "сервер нельзя выбрать или купить, линию нельзя добавить или убрать из записей",
                            "а deploy не может вернуть окружение в erpc.toml или 1Password",
                            "deploy отклоняется, пока в записи аккаунта есть незавершённая линия не в состоянии active",
                        ],
                    ),
                    (
                        "worker_move.loses_delete",
                        &[
                            "delete --release-server не подключается к серверу и не удаляет воркер",
                            "он просит аккаунт завершить всё, на чём работает окружение",
                            "а аккаунт ничего не завершает, пока на нём, кроме линии, купленной как часть Bundle (её аккаунт снимает с окружения, не завершая, в любом состоянии), есть что-то оплачиваемое не почасово, что-то, что нельзя завершить в его нынешнем состоянии, или запуск без известного исхода",
                            "почасовые сервер и линии тогда остаются оплачиваемыми и завершаются, только когда это разрешится и delete запустят снова",
                            "Для собственного сервера это спрашивается только в терминале, --yes недостаточно, и воркер на нём продолжает работать",
                            "Простой delete, delete --forget и delete --forget-line отклоняются",
                        ],
                    ),
                    (
                        "worker_move.loses_bundle",
                        &[
                            "Линия, купленная как часть Bundle, не принимается: аккаунт её отклоняет, и перенос на ней останавливается, а уже записанное в аккаунт остаётся там",
                            "пока её Bundle не записан в аккаунте, её могут принять",
                            "erpc сможет убрать её из записей, только удалив окружение, и это её не завершит, а завершить её отдельно от её Bundle не сможет",
                        ],
                    ),
                    (
                        "worker_move.loses_others",
                        &[
                            "Пока окружение этой машины хранится в аккаунте",
                            "delete --release-server --yes для других окружений этой машины, который завершил бы сервер, отклоняется",
                            "а для этого окружения — когда в аккаунте хранится и другое",
                            "без --yes это спрашивается в терминале",
                        ],
                    ),
                    (
                        "worker_move.loses_more",
                        &["Другие различия перечислены в docs/worker.md"],
                    ),
                ],
            };
            for (flag, set) in &refused {
                let mut at = Where::default();
                set(&mut at);
                let is_refused = crate::worker::deploy_account::refuse_options(&at, &app).is_err();
                assert_eq!(is_refused, !flag.is_empty(), "{flag}");
                if !flag.is_empty() {
                    assert!(said.contains(*flag), "{lang:?}: {flag} not said: {loses}");
                }
            }
            // delete's own refusals, said as delete's, each whole; and
            // --forget-line said for deploy too, not only for delete.
            for words in ["delete --forget", "delete --forget-line"] {
                let whole = loses.match_indices(words).any(|(at, _)| {
                    !loses[at + words.len()..]
                        .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '-')
                });
                assert!(whole, "{lang:?}: {words} not said: {loses}");
            }
            assert!(
                loses.matches("--forget-line").count() >= 2,
                "{lang:?}: deploy's --forget-line not said: {loses}"
            );
            // The account's limits, a Bundle's line, and what a delete with
            // --yes of this machine's environments becomes.
            for said in ["16", "Bundle", "delete --release-server --yes"] {
                assert!(loses.contains(said), "{lang:?}: {said} not said: {loses}");
            }
            // The commands that do not work on it yet, by name.
            for command in ["rollback", "backup", "api", "trades", "bench", "firewall"] {
                let words: Vec<&str> = loses
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                    .collect();
                assert!(
                    words.contains(&command),
                    "{lang:?}: {command} not said: {loses}"
                );
            }
            // The deploy part names every option refused there.
            let deploy = flags_in(&part("worker_move.loses_deploy"));
            for (flag, _) in refused.iter().filter(|(f, _)| !f.is_empty()) {
                assert!(
                    deploy.contains(*flag),
                    "{lang:?}: {flag} not in the deploy part"
                );
            }
            for (key, words) in [
                ("worker_move.loses_access", &["--yes", "--json"][..]),
                ("worker_move.loses_commands", &["16", "firewall"][..]),
                (
                    "worker_move.loses_delete",
                    &["delete --release-server", "delete --forget", "--yes"][..],
                ),
                ("worker_move.loses_bundle", &["Bundle"][..]),
                (
                    "worker_move.loses_others",
                    &["delete --release-server --yes"][..],
                ),
                (
                    "worker_move.loses_more",
                    &["docs/worker.md", "What changes once moved"][..],
                ),
            ] {
                let text = part(key);
                assert!(loses.contains(&text), "{lang:?}: {key} not in the note");
                for word in words {
                    assert!(text.contains(word), "{lang:?}: {key} lacks {word}: {text}");
                }
            }
            for (key, phrases) in meant {
                let text = part(key);
                for phrase in phrases {
                    assert!(
                        text.contains(phrase),
                        "{lang:?}: {key} lacks {phrase}: {text}"
                    );
                }
            }
            // And nothing said that is not a flag erpc has.
            let known: std::collections::BTreeSet<String> = refused
                .iter()
                .filter(|(f, _)| !f.is_empty())
                .map(|(f, _)| (*f).to_owned())
                .chain(["--release-server", "--forget", "--yes", "--json"].map(ToOwned::to_owned))
                .collect();
            assert!(said.is_subset(&known), "{lang:?}: {said:?}");
        }
        // The list the note points to is where it says.
        let docs =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/worker.md"))
                .expect("docs/worker.md");
        assert!(docs.contains("What changes once moved"));
        assert!(crate::worker::deploy_account::refuse_options(&Where::default(), &app).is_ok());
        // Asked at a terminal: the question carries it.
        let loses = loses();
        let plan = plan_of(&deployed());
        assert!(question(&app, &plan).ends_with(&loses));
        // Under --yes: said on stderr as the move starts.
        let _ = crate::node::common::heard::take_printed();
        ask(&app, &plan, true, true).expect("--yes goes ahead");
        let printed = crate::node::common::heard::take_printed();
        assert_eq!(printed, [format!("note: {loses}")]);
    }

    #[tokio::test]
    async fn an_older_form_and_an_app_with_another_wallet_are_refused_before_anything_is_written() {
        // The environment in an older form: its server and lines are not
        // read, so it would look as if it held none.
        let fake = Fake::with_env(&other_facts());
        let fake = Fake {
            older: true,
            ..fake
        };
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("older form"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
        // An app of that name with a wallet where erpc.toml has none.
        let fake = Fake::default();
        *fake.app.borrow_mut() = Some(json!({ "id": APP_ID, "name": "bot", "chain": "solana",
            "template": "solana/hello@1",
            "wallet": { "pubkey": "11111111111111111111111111111111" }, "revision": 4 }));
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("another wallet"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
    }

    #[tokio::test]
    async fn an_app_record_with_another_template_or_key_place_is_brought_to_erpc_toml() {
        // The same chain and no wallet, from another template.
        let fake = Fake::default();
        *fake.app.borrow_mut() = Some(json!({ "id": APP_ID, "name": "bot", "chain": "solana",
            "template": "solana/pumpfun@1", "wallet": null, "revision": 4 }));
        take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect("moved");
        assert_eq!(fake.calls.borrow().first(), Some(&"put_app"));
        let app = fake.app.borrow().clone().expect("an app");
        assert_eq!(app["template"], "solana/hello@1");
        // The same wallet, its key kept somewhere other than erpc.toml says.
        let pubkey = "11111111111111111111111111111111";
        let m = Manifest::parse(&format!(
            "name = \"bot\"\nchain = \"solana\"\ntemplate = \"solana/hello@1\"\n\
             [wallet]\nsource = \"keychain:erpc-worker/bot\"\npubkey = \"{pubkey}\"\n\
             [env.prod]\n{}",
            deployed_text()
        ))
        .expect("a manifest");
        let fake = Fake::default();
        *fake.app.borrow_mut() = Some(json!({ "id": APP_ID, "name": "bot", "chain": "solana",
            "template": "solana/hello@1",
            "wallet": { "pubkey": pubkey, "sourceKind": "1password" }, "revision": 4 }));
        take_in(&fake, &plan_of(&m), false).await.expect("moved");
        assert_eq!(fake.calls.borrow().first(), Some(&"put_app"));
        let app = fake.app.borrow().clone().expect("an app");
        assert_eq!(app["wallet"]["pubkey"], pubkey);
        assert_eq!(app["wallet"]["sourceKind"], "keychain");
        // That write cut off: said as a move that stopped part way, with
        // the exit status of how it failed.
        for (cut_as, code) in KINDS {
            let fake = Fake {
                cut_off: Some("put_app"),
                cut_as,
                ..Fake::default()
            };
            *fake.app.borrow_mut() = Some(json!({ "id": APP_ID, "name": "bot",
                "chain": "solana", "template": "solana/pumpfun@1", "wallet": null,
                "revision": 4 }));
            let e = take_in(&fake, &plan_of(&deployed()), false)
                .await
                .expect_err("stopped");
            assert!(e.message.contains("stopped part way"), "{}", e.message);
            assert_eq!(e.code, code, "{cut_as:?}");
            assert_eq!(signed_out_hint(&e), code == Code::NotSignedIn, "{cut_as:?}");
            assert_eq!(*fake.calls.borrow(), ["put_app"]);
        }
    }

    #[tokio::test]
    async fn an_environment_that_ends_up_holding_more_than_planned_is_not_counted_as_moved() {
        // Another line appears as this move's are taken in: the end check
        // refuses it.
        let fake = Fake {
            extra_line: true,
            ..Fake::default()
        };
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("stopped part way"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_line_on_another_environment_after_writes_says_the_move_stopped_part_way() {
        // The line, and the server: each refused after the app's and the
        // environment's records were written.
        for elsewhere in [300_003, 200_002] {
            let fake = Fake {
                elsewhere: vec![elsewhere],
                ..Fake::default()
            };
            let e = take_in(&fake, &plan_of(&deployed()), false)
                .await
                .expect_err("refused");
            assert!(
                e.message.contains("stopped part way"),
                "{elsewhere}: {}",
                e.message
            );
            assert!(e.hint.is_some());
            assert!(fake.app.borrow().is_some(), "{elsewhere}");
        }
    }

    /// An environment on a server of the person's own: a host, no product.
    fn on_own_server() -> Manifest {
        manifest(&format!(
            "host = \"203.0.113.10\"\nssh_user = \"ubuntu\"\nhost_key = \"{HOST_KEY}\"\n"
        ))
    }

    #[tokio::test]
    async fn a_server_the_move_does_not_take_in_is_refused_before_anything_is_written() {
        let gone = |slot: &str| {
            json!({ "id": "5d2f8a61-7c4e-4b93-9e0a-1f6b3c8d2e47", "slot": slot,
                    "cores": 2, "memoryGb": 8, "region": "amsterdam", "hourly": true,
                    "appRunning": false, "state": "gone" })
        };
        // A gone server in the slot in use, and a move of an environment on
        // the person's own server: once moved, nothing could reach it.
        let fake = Fake {
            held: vec![gone("active")],
            ..Fake::with_env(&other_facts())
        };
        let e = take_in(&fake, &plan_of(&on_own_server()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("was not moved"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
        // A gone server in another slot, with the move's own server: a
        // deploy there would refuse the record.
        let fake = Fake {
            held: vec![gone("incoming")],
            ..Fake::with_env(&other_facts())
        };
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("was not moved"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
        // A gone server in the slot in use, with the move's own server: an
        // ended server is not moved into.
        let fake = Fake {
            held: vec![gone("active")],
            ..Fake::with_env(&other_facts())
        };
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("was not moved"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
        // A server in use, and a move of an environment on the person's
        // own server: the record would name another server than it runs on.
        let mut live = gone("active");
        live["state"] = json!("active");
        let fake = Fake {
            held: vec![live],
            ..Fake::with_env(&other_facts())
        };
        let e = take_in(&fake, &plan_of(&on_own_server()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("was not moved"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_record_the_commands_would_refuse_is_not_moved_into() {
        // Lines that come back not active: a deploy would not hand them to
        // the app, so erpc.toml is not changed.
        let fake = Fake {
            line_state: Some("provisioning"),
            ..Fake::default()
        };
        let (_, detail) = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect("taken in");
        let app = App::at("apps/bot", "prod");
        let e = works_once_moved(&app, &detail).expect_err("refused");
        let e = part_way("prod", e, false);
        assert!(e.message.contains("stopped part way"), "{}", e.message);
        // The hint is the move's, not one for a moved environment.
        assert_eq!(e.hint, Some(t!("worker_move.part_way_hint")));
        // As taken in: active, it is.
        let fake = Fake::default();
        let (_, detail) = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect("taken in");
        works_once_moved(&app, &detail).expect("works");
    }

    #[tokio::test]
    async fn refusals_after_the_account_was_written_say_the_move_stopped_part_way() {
        // The environment's record refused after the app's was written.
        let fake = Fake {
            refuse_env: true,
            ..Fake::default()
        };
        let e = take_in(&fake, &plan_of(&deployed()), false)
            .await
            .expect_err("refused");
        assert!(e.message.contains("stopped part way"), "{}", e.message);
        assert!(e.hint.is_some());
        // A line the account no longer has: said by its id, with the way
        // to take it off erpc.toml's record.
        let fake = Fake {
            missing: vec![300_003],
            ..Fake::default()
        };
        let mut plan = plan_of(&deployed());
        plan.scope = " --env prod".to_owned();
        let e = take_in(&fake, &plan, false).await.expect_err("refused");
        assert!(e.message.contains("line 300003"), "{}", e.message);
        assert!(e.message.contains("stopped part way"), "{}", e.message);
        assert!(
            e.hint
                .unwrap_or_default()
                .contains("`erpc worker deploy --forget-line 300003 --env prod`")
        );
        // Refused for another reason than a Bundle's, or for none.
        for (data, said) in [
            (json!({ "reason": "kept_elsewhere" }), "(kept_elsewhere)"),
            (Value::Null, "into an environment;"),
        ] {
            let fake = Fake {
                not_adoptable: Some(data),
                ..Fake::default()
            };
            let e = take_in(&fake, &plan_of(&deployed()), false)
                .await
                .expect_err("refused");
            assert!(e.message.contains(said), "{}", e.message);
            assert!(!e.message.contains("Bundle") && !e.message.contains("()"));
        }
    }

    #[tokio::test]
    async fn an_environment_on_no_server_is_not_moved_and_nothing_is_reached() {
        let (dir, _) = checkout("name = \"bot\"\nchain = \"solana\"\n[env.prod]\n");
        let e = run(true, &App::at(dir.path(), "prod"), true)
            .await
            .expect_err("refused");
        assert!(e.message.contains("runs on no server yet"), "{}", e.message);
        assert!(e.hint.unwrap_or_default().contains("erpc worker deploy"));
    }

    /// An own-server environment's erpc.toml, written to a checkout, and
    /// the move's view of it.
    fn own_server_checkout() -> (tempfile::TempDir, std::path::PathBuf, Manifest) {
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\ntemplate = \"solana/hello@1\"\n[env.prod]\n\
             host = \"203.0.113.10\"\nssh_user = \"ubuntu\"\nhost_key = \"{HOST_KEY}\"\n"
        );
        let (dir, path) = checkout(&text);
        let m = Manifest::parse(&text).expect("a manifest");
        (dir, path, m)
    }

    #[tokio::test]
    async fn a_move_asks_the_account_first_changes_erpc_toml_then_pins_this_machines_record() {
        let (dir, path, m) = own_server_checkout();
        let pins = dir.path().join("worker_account.json");
        let app = App::at(dir.path(), "prod");
        let plan = plan(&m, "prod", &m.env["prod"]).expect("a plan");
        let fake = Fake::default();
        let read = Read {
            path: &path,
            read: &m,
        };
        let (answer, _) = run_with(&app, &plan, read, (&fake, &pins), || Ok(false))
            .await
            .expect("moved");
        assert_eq!(answer["moved"], json!(true));
        // The sign-in check before any write; nothing more than the plan.
        assert_eq!(*fake.calls.borrow(), ["probe", "put_app", "put_env"]);
        // This machine's own record pinned, not the account's answer.
        let key = kept::pin_key("user-100001", "bot", "prod");
        let pinned = kept::pinned(&pins, &key).expect("read").expect("pinned");
        assert_eq!(pinned, Anchor::of_facts(APP_ID, &plan.facts, None));
        // The app's list moved is recorded as the one on the server.
        assert_eq!(
            kept::app_seen(&pins, &key).expect("read"),
            Some(plan.facts.firewall.app_allow.clone())
        );
        // erpc.toml keeps only the marker.
        let now = std::fs::read_to_string(&path).expect("erpc.toml");
        assert!(
            now.contains("account = true") && !now.contains("203.0.113.10"),
            "{now}"
        );
        // Another sign-in changes the app's list meanwhile: this machine's
        // list is recorded, so the next deploy says the change.
        let (dir, path, m) = own_server_checkout();
        let pins = dir.path().join("worker_account.json");
        let app = App::at(dir.path(), "prod");
        let fake = Fake {
            app_list_changed: true,
            ..Fake::default()
        };
        let read = Read {
            path: &path,
            read: &m,
        };
        run_with(&app, &plan, read, (&fake, &pins), || Ok(false))
            .await
            .expect("moved");
        assert_eq!(
            kept::app_seen(&pins, &key).expect("read"),
            Some(plan.facts.firewall.app_allow.clone())
        );
        // Another sign-in changes how the server is reached meanwhile:
        // nothing is pinned, and erpc.toml is as it was.
        let (dir, path, m) = own_server_checkout();
        let before = std::fs::read_to_string(&path).expect("erpc.toml");
        let pins = dir.path().join("worker_account.json");
        let app = App::at(dir.path(), "prod");
        let mut moving_m = m.clone();
        let env = moving_m.env.get_mut("prod").expect("prod");
        env.resource = deployed().env["prod"].resource.clone();
        env.lines = deployed().env["prod"].lines.clone();
        let moving = super::plan(&moving_m, "prod", &moving_m.env["prod"]).expect("a plan");
        let fake = Fake {
            meddles: true,
            ..Fake::default()
        };
        let read = Read {
            path: &path,
            read: &m,
        };
        let e = run_with(&app, &moving, read, (&fake, &pins), || Ok(false))
            .await
            .expect_err("not trusted");
        assert!(e.message.contains("stopped part way"), "{}", e.message);
        assert!(!pins.exists());
        assert_eq!(std::fs::read_to_string(&path).expect("erpc.toml"), before);
    }

    #[tokio::test]
    async fn a_move_that_stops_leaves_erpc_toml_and_the_pins_as_they_were() {
        let (dir, path, m) = own_server_checkout();
        let before = std::fs::read_to_string(&path).expect("erpc.toml");
        let pins = dir.path().join("worker_account.json");
        let app = App::at(dir.path(), "prod");
        let plan = plan(&m, "prod", &m.env["prod"]).expect("a plan");
        // An account that does not let this sign-in end what it would run
        // on: nothing is written, and the agent is not asked.
        let fake = Fake {
            closed: true,
            ..Fake::default()
        };
        let read = Read {
            path: &path,
            read: &m,
        };
        let e = run_with(&app, &plan, read, (&fake, &pins), || {
            panic!("the agent is not asked")
        })
        .await
        .expect_err("refused");
        assert!(!e.message.contains("part way"), "{}", e.message);
        assert_eq!(*fake.calls.borrow(), ["probe"]);
        // Each account call after the first write, cut off: said as a move
        // that stopped part way, erpc.toml and the pins as they were.
        for call in ["put_app", "put_env", "uid"] {
            let fake = Fake {
                cut_off: Some(call),
                ..Fake::default()
            };
            let read = Read {
                path: &path,
                read: &m,
            };
            let e = run_with(&app, &plan, read, (&fake, &pins), || Ok(false))
                .await
                .expect_err("stopped");
            assert!(
                e.message.contains("stopped part way"),
                "{call}: {}",
                e.message
            );
            assert!(e.hint.is_some(), "{call}");
            // No answer is a network failure, after the first write too.
            assert_eq!(e.code, Code::Network, "{call}");
        }
        // Lines and the server of a deployed environment: the same.
        for call in ["adopt_server", "adopt_line"] {
            let fake = Fake {
                cut_off: Some(call),
                ..Fake::default()
            };
            let e = take_in(&fake, &plan_of(&deployed()), true)
                .await
                .expect_err("stopped");
            assert!(
                e.message.contains("stopped part way"),
                "{call}: {}",
                e.message
            );
            assert_eq!(e.code, Code::Network, "{call}");
            assert_eq!(fake.calls.borrow().last(), Some(&call));
        }
        // A move run again, the app now stopped: the record is brought to
        // it last, and that write cut off is said the same.
        let fake = Fake {
            fail_line_once: RefCell::new(true),
            cut_off: Some("set_app_running"),
            ..Fake::default()
        };
        let deployed_plan = plan_of(&deployed());
        assert!(take_in(&fake, &deployed_plan, true).await.is_err());
        let e = take_in(&fake, &deployed_plan, false)
            .await
            .expect_err("stopped");
        assert!(e.message.contains("stopped part way"), "{}", e.message);
        assert_eq!(e.code, Code::Network);
        assert_eq!(fake.calls.borrow().last(), Some(&"set_app_running"));
        // The last check refuses: the same, with the move's own hint.
        let fake = Fake {
            line_state: Some("provisioning"),
            ..Fake::default()
        };
        let mut m2 = m.clone();
        let env = m2.env.get_mut("prod").expect("prod");
        env.resource = deployed().env["prod"].resource.clone();
        env.lines = deployed().env["prod"].lines.clone();
        let plan2 = super::plan(&m2, "prod", &m2.env["prod"]).expect("a plan");
        let read = Read {
            path: &path,
            read: &m,
        };
        let e = run_with(&app, &plan2, read, (&fake, &pins), || Ok(false))
            .await
            .expect_err("stopped");
        assert!(e.message.contains("stopped part way"), "{}", e.message);
        assert_eq!(e.hint, Some(t!("worker_move.part_way_hint")));
        assert_eq!(std::fs::read_to_string(&path).expect("erpc.toml"), before);
        assert!(!pins.exists());
    }

    #[tokio::test]
    async fn a_live_server_in_another_slot_is_refused_before_anything_is_written() {
        // The record has the move's own facts: only the server it holds in
        // another slot keeps it from being this move's.
        let plan = plan_of(&deployed());
        let facts = serde_json::to_value(&plan.facts).expect("facts");
        let fake = Fake {
            held: vec![
                json!({ "id": "5d2f8a61-7c4e-4b93-9e0a-1f6b3c8d2e47", "slot": "incoming",
                "cores": 2, "memoryGb": 8, "region": "amsterdam", "hourly": true,
                "appRunning": false, "state": "active" }),
            ],
            ..Fake::with_env(&facts)
        };
        let e = take_in(&fake, &plan, false).await.expect_err("refused");
        assert!(e.message.contains("not moved"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn the_record_is_read_as_the_commands_after_the_move_read_it() {
        let app = App::at("apps/bot", "prod");
        let fake = Fake::default();
        let facts = serde_json::to_value(&plan_of(&deployed()).facts).expect("facts");
        *fake.env.borrow_mut() = Some(json!({ "revision": 3, "facts": facts }));
        fake.servers
            .borrow_mut()
            .push(("vps".to_owned(), 200_002, true));
        works_once_moved(&app, &fake.detail()).expect("works");
        // A server in use that is suspended: not reached.
        let mut detail = fake.detail();
        detail.servers[0].state = account::State::from("suspended");
        assert!(works_once_moved(&app, &detail).is_err());
        // A server coming in besides the one in use: a deploy does not carry
        // the record.
        let mut detail = fake.detail();
        let mut incoming = detail.servers[0].clone();
        incoming.slot = account::Slot::Incoming;
        detail.servers.push(incoming);
        assert!(works_once_moved(&app, &detail).is_err());
    }

    #[tokio::test]
    async fn a_cancelled_line_in_the_record_does_not_count_against_the_move() {
        // A UDP line the account keeps as cancelled is not one the move has
        // to take in, nor one the commands after it hand to the app.
        let (_, path, m) = own_server_checkout();
        let plan = plan(&m, "prod", &m.env["prod"]).expect("a plan");
        let facts = serde_json::to_value(&plan.facts).expect("facts");
        let fake = Fake {
            held_lines: vec![
                json!({ "id": "8e3b1d27-6a4f-4c95-b0e2-7d9a1c5f3e68", "kind": "udp",
                "hourly": true, "pending": false, "state": "cancelled", "endpoint": null }),
            ],
            ..Fake::with_env(&facts)
        };
        let (_, detail) = take_in(&fake, &plan, false).await.expect("taken in");
        works_once_moved(&App::at(path.parent().expect("a dir"), "prod"), &detail).expect("works");
    }

    #[tokio::test]
    async fn erpc_toml_changed_during_the_move_leaves_nothing_pinned() {
        let (dir, path, m) = own_server_checkout();
        let pins = dir.path().join("worker_account.json");
        let app = App::at(dir.path(), "prod");
        let plan = plan(&m, "prod", &m.env["prod"]).expect("a plan");
        // Another command writes erpc.toml while the account is written.
        let mut changed = std::fs::read_to_string(&path).expect("erpc.toml");
        changed.push_str("[env.staging]\n");
        std::fs::write(&path, &changed).expect("written");
        let fake = Fake::default();
        let read = Read {
            path: &path,
            read: &m,
        };
        let e = run_with(&app, &plan, read, (&fake, &pins), || Ok(false))
            .await
            .expect_err("stopped");
        assert!(e.message.contains("stopped part way"), "{}", e.message);
        assert!(!pins.exists());
        assert_eq!(std::fs::read_to_string(&path).expect("erpc.toml"), changed);
    }

    #[tokio::test]
    async fn an_app_with_more_names_than_the_account_keeps_is_not_moved() {
        let vars = (0..=128).fold(String::new(), |mut text, n| {
            use std::fmt::Write as _;
            let _ = writeln!(text, "V{n} = \"x\"");
            text
        });
        let (dir, _) = checkout(&format!(
            "name = \"bot\"\nchain = \"solana\"\n[vars]\n{vars}[env.prod]\n\
             host = \"203.0.113.10\"\nssh_user = \"ubuntu\"\nhost_key = \"{HOST_KEY}\"\n"
        ));
        let e = run(true, &App::at(dir.path(), "prod"), true)
            .await
            .expect_err("refused");
        assert!(e.message.contains("128"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_stop_before_anything_was_written_says_it_was_not_moved() {
        let (dir, path, m) = own_server_checkout();
        let pins = dir.path().join("worker_account.json");
        let app = App::at(dir.path(), "prod");
        let plan = plan(&m, "prod", &m.env["prod"]).expect("a plan");
        // The app's state could not be read.
        let fake = Fake::default();
        let read = Read {
            path: &path,
            read: &m,
        };
        let e = run_with(&app, &plan, read, (&fake, &pins), || {
            Err(failed("ssh: connection refused".to_owned()))
        })
        .await
        .expect_err("stopped");
        assert!(e.message.contains("was not moved"), "{}", e.message);
        assert_eq!(*fake.calls.borrow(), ["probe"]);
        // The account could not be read: its app, its environment, or
        // whether it lets this sign-in end what the move would run on.
        for call in ["app", "env"] {
            let fake = Fake {
                cut_off: Some(call),
                ..Fake::with_env(&other_facts())
            };
            let e = take_in(&fake, &plan, false).await.expect_err("stopped");
            assert!(e.message.contains("was not moved"), "{call}: {}", e.message);
            assert_eq!(e.code, Code::Network, "{call}");
        }
        // A move run again with its server already in the slot in use: the
        // resend that asks the account whether it is this one, cut off.
        let first = Fake {
            fail_line_once: RefCell::new(true),
            ..Fake::default()
        };
        let again = plan_of(&deployed());
        assert!(take_in(&first, &again, true).await.is_err());
        let fake = Fake {
            cut_off: Some("adopt_server"),
            ..first
        };
        fake.calls.borrow_mut().clear();
        let e = take_in(&fake, &again, false).await.expect_err("stopped");
        assert!(e.message.contains("was not moved"), "{}", e.message);
        assert_eq!(e.code, Code::Network);
        assert_eq!(*fake.calls.borrow(), ["adopt_server"]);
        let fake = Fake {
            cut_off: Some("probe"),
            ..Fake::default()
        };
        let read = Read {
            path: &path,
            read: &m,
        };
        let e = run_with(&app, &plan, read, (&fake, &pins), || Ok(false))
            .await
            .expect_err("stopped");
        assert!(e.message.contains("was not moved"), "{}", e.message);
        assert_eq!(e.code, Code::Network);
    }

    #[test]
    fn with_json_and_no_yes_the_move_is_refused_before_anything() {
        let app = App::at("apps/bot", "prod");
        let plan = plan_of(&deployed());
        let e = ask(&app, &plan, false, true).expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
    }

    #[tokio::test]
    async fn a_record_with_the_moves_facts_and_more_lines_is_refused_before_anything() {
        let plan = plan_of(&deployed());
        let facts = serde_json::to_value(&plan.facts).expect("facts");
        let fake = Fake::with_env(&facts);
        fake.lines
            .borrow_mut()
            .extend([("grpc".to_owned(), 300_004), ("shreds".to_owned(), 300_005)]);
        let e = take_in(&fake, &plan, false).await.expect_err("refused");
        assert!(e.message.contains("not moved"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
    }

    #[tokio::test]
    async fn an_app_with_as_many_names_as_the_account_keeps_moves_on_and_secrets_count_too() {
        // 128 settings: not refused here; the move goes on to its question,
        // which with --json and no --yes is refused before any sign-in.
        let names = |n: usize, table: &str| {
            (0..n).fold(format!("[{table}]\n"), |mut text, i| {
                use std::fmt::Write as _;
                let _ = writeln!(text, "V{i} = \"x\"");
                text
            })
        };
        let server = format!(
            "[env.prod]\nhost = \"203.0.113.10\"\nssh_user = \"ubuntu\"\nhost_key = \"{HOST_KEY}\"\n"
        );
        let (dir, _) = checkout(&format!(
            "name = \"bot\"\nchain = \"solana\"\n{}{server}",
            names(128, "vars")
        ));
        let e = run(true, &App::at(dir.path(), "prod"), false)
            .await
            .expect_err("asked");
        assert_eq!(e.code, Code::NeedsTerminal, "{}", e.message);
        // 129 secret settings: refused before anything.
        let secrets = (0..=128).fold(String::from("[secrets]\n"), |mut text, i| {
            use std::fmt::Write as _;
            let _ = writeln!(text, "S{i} = \"keychain:bot/S{i}\"");
            text
        });
        let (dir, _) = checkout(&format!(
            "name = \"bot\"\nchain = \"solana\"\n{secrets}{server}"
        ));
        let e = run(true, &App::at(dir.path(), "prod"), true)
            .await
            .expect_err("refused");
        assert!(e.message.contains("128"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_pin_that_cannot_be_written_after_the_move_is_printed_on_stderr() {
        let (dir, path, m) = own_server_checkout();
        // The pins' place is a directory: the pin cannot be written.
        let pins = dir.path().join("pins");
        std::fs::create_dir_all(&pins).expect("a directory");
        let app = App::at(dir.path(), "prod");
        let plan = plan(&m, "prod", &m.env["prod"]).expect("a plan");
        let fake = Fake::default();
        let read = Read {
            path: &path,
            read: &m,
        };
        // Printed, not only handed to be said: the move prints it whether
        // or not `--json` is given.
        let _ = crate::node::common::heard::take_printed();
        run_with(&app, &plan, read, (&fake, &pins), || Ok(false))
            .await
            .expect("moved");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("what it trusts of it could not be written"),
            "{printed}"
        );
        let now = std::fs::read_to_string(&path).expect("erpc.toml");
        assert!(now.contains("account = true"), "{now}");
        // The record cannot be read either: the next command stops, as the
        // warning says, and trusts nothing.
        assert!(printed.contains("stops until it is fixed"), "{printed}");
        let after = Manifest::load(&path).expect("a manifest");
        let next =
            crate::worker::account::status_plan(&fake, &app, &after, &pins, true, |_| Ok(true))
                .await;
        let e = next.err().expect("the next command stops");
        assert!(e.message.contains("unreadable"), "{}", e.message);
    }

    #[test]
    fn the_docs_list_has_each_group_the_note_names() {
        let docs =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/worker.md"))
                .expect("docs/worker.md");
        let i = docs.find("**What changes once moved.**").expect("the list");
        let list = &docs[i..];
        for group in [
            "**Sign-in, trust and reach.**",
            "**Commands.**",
            "**Deploy.**",
            "**Delete.**",
            "**A line bought as part of a Bundle.**",
            "**This machine's other environments, and other checkouts.**",
        ] {
            assert!(list.contains(group), "{group}");
        }
    }
}
