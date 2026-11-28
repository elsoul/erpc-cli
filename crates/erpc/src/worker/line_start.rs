// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A data line asked on a first deploy, started in the ERPC account for the
//! environment, once its server has an address (a gRPC or Shreds line lets
//! that address in): the account's line start, under a key kept on this
//! machine before it is sent (`worker_line_starts.json`, beside erpc's
//! config, 0600), at the plan the hourly catalogue offers.
//!
//! The price said and asked is the hourly catalogue's for the plan: the
//! account's line start takes no price, and the line is charged its own.
//! At a terminal it is asked, under `--yes` said on stderr, and nothing is
//! started without one or the other.
//!
//! A run again buys no second line: a line of the kind on the
//! environment's record is used as it is; a start kept here is sent again
//! under its key, with the same body, its price asked again (the account
//! answers a start that went through with what it put on record, sends one
//! still open on, and takes one that holds nothing as a new send); one kept
//! for another plan or address than the run asks stops it. A start open in
//! the account that this machine did not keep refuses the run, as it may
//! yet buy what it was for.
//!
//! Then the deploy waits for the line to be active with its endpoint, as
//! the deploy to an environment kept in the account takes no other.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use erpc_api::worker::money::{StartKey, StartLine, StartOf};
use erpc_api::worker::{self as account, Code as AccountCode, EnvDetail, WorkerError, Written};
use erpc_worker::manifest::LineKind;
use serde::{Deserialize, Serialize};

use crate::cli::error::{CliError, Code};
use crate::node::common::Say;
use crate::worker::App;
use crate::worker::account as kept;

/// Where the line starts are kept, beside erpc's config.
const FILE: &str = "worker_line_starts.json";

fn failed(message: String) -> CliError {
    CliError::new(Code::Failed, message)
}

/// The account's word for a line of `kind`.
pub(crate) const fn account_kind(kind: LineKind) -> account::LineKind {
    match kind {
        LineKind::Grpc => account::LineKind::Grpc,
        LineKind::Shreds => account::LineKind::Shreds,
        LineKind::Udp => account::LineKind::Udp,
        LineKind::Unlimited => account::LineKind::Unlimited,
    }
}

// --------------------------------------------------- the line starts kept here

/// A line start this machine made, kept from before it is sent until the
/// account has it on record or says it bought nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Kept {
    /// Its key.
    key: String,
    /// The plan it starts, by product id.
    product_id: String,
    /// The address a gRPC or Shreds line lets in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    /// The region of an Unlimited RPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<String>,
}

impl Kept {
    /// What it sends: the same body every time.
    fn body(&self, kind: LineKind) -> StartLine {
        StartLine::new(
            account_kind(kind),
            self.product_id.clone(),
            self.ip.clone(),
            self.region.clone(),
        )
    }
}

/// The line starts kept here, by the key of the account, app and
/// environment and the line's kind.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Starts {
    #[serde(default)]
    starts: BTreeMap<String, Kept>,
}

/// The line starts kept in `path`; none when there is no file yet. A file
/// that cannot be read is an error, never an empty list: a start in it may
/// have bought a line.
fn load(path: &Path) -> Result<Starts, String> {
    let unreadable = |error: String| {
        t!(
            "worker_first_deploy.line_unreadable",
            path = path.display(),
            error
        )
    };
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| unreadable(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Starts::default()),
        Err(e) => Err(unreadable(e.to_string())),
    }
}

/// Keeps `start` in `path` under `key`, or lets the one there go when
/// `start` is none, read and written under the lock.
fn keep(path: &Path, key: &str, start: Option<&Kept>) -> Result<(), String> {
    if start.is_none() && !path.exists() {
        return Ok(());
    }
    erpc_core::private_file::locked(path, || {
        let mut starts = load(path)?;
        match start {
            Some(start) => {
                starts.starts.insert(key.to_owned(), start.clone());
            }
            None => {
                if starts.starts.remove(key).is_none() {
                    return Ok(());
                }
            }
        }
        let text = serde_json::to_vec_pretty(&starts).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)
    })
}

/// The key a line start of `kind` is kept under, for the environment
/// [`kept::pin_key`] names.
fn file_key(pin: &str, kind: LineKind) -> String {
    format!("{pin} {}", account_kind(kind).as_str())
}

// ------------------------------------------------------------------ the reach

/// A start still open in the account that may be a line's: a line's with
/// its kind and plan, or one of a kind this version does not know, with
/// none. A server's is never one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenLine {
    pub(crate) id: String,
    pub(crate) kind: Option<account::LineKind>,
    pub(crate) product_id: Option<String>,
}

/// A plan of the hourly catalogue: its product id, its price by the hour
/// in cents of a euro, and its name.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Plan {
    pub(crate) id: String,
    pub(crate) cents: f64,
    pub(crate) name: String,
}

/// What a line start reaches: the account, the hourly catalogue and the
/// terminal. The real one is [`Live`]; a test brings a stand-in.
pub(crate) trait Reach {
    /// The account's own id, which what is kept here is filed under.
    async fn uid(&self) -> Result<String, CliError>;
    /// The environment's record.
    async fn env(&self, name: &str, env: &str) -> Result<EnvDetail, WorkerError>;
    /// The environment's starts still open that may be a line's.
    async fn open_lines(&self, name: &str, env: &str) -> Result<Vec<OpenLine>, WorkerError>;
    /// Starts a line there under `key`, kept before.
    async fn start(
        &self,
        name: &str,
        env: &str,
        key: &StartKey,
        body: &StartLine,
    ) -> Result<Written<EnvDetail>, WorkerError>;
    /// The plan of the hourly catalogue for a line of `kind`: `asked`, or
    /// the cheapest.
    async fn plan(&self, kind: LineKind, asked: Option<&str>) -> Result<Plan, CliError>;
    /// Asks `question` at the terminal.
    fn confirm(&self, question: &str) -> Result<bool, String>;
    /// A new start's key.
    fn new_key(&self) -> Result<StartKey, CliError>;
    /// Waits `pause` before the record is read again.
    async fn pause(&self, pause: Duration);
}

/// The ERPC account, the hourly catalogue user-api serves, and the
/// terminal.
pub(crate) struct Live<'a> {
    pub(crate) signed: &'a kept::Signed,
    pub(crate) api: &'a crate::worker::vps::Api,
}

impl Reach for Live<'_> {
    async fn uid(&self) -> Result<String, CliError> {
        kept::Account::uid(self.signed).await
    }

    async fn env(&self, name: &str, env: &str) -> Result<EnvDetail, WorkerError> {
        kept::Account::env(self.signed, name, env).await
    }

    async fn open_lines(&self, name: &str, env: &str) -> Result<Vec<OpenLine>, WorkerError> {
        Ok(self
            .signed
            .open_starts(name, env)
            .await?
            .into_iter()
            .filter_map(|s| {
                let kind = match s.of {
                    StartOf::Server => return None,
                    StartOf::Line(kind) => Some(kind),
                    _ => None,
                };
                Some(OpenLine {
                    id: s.id,
                    kind,
                    product_id: s.product_id,
                })
            })
            .collect())
    }

    async fn start(
        &self,
        name: &str,
        env: &str,
        key: &StartKey,
        body: &StartLine,
    ) -> Result<Written<EnvDetail>, WorkerError> {
        self.signed.start_line(name, env, key, body).await
    }

    async fn plan(&self, kind: LineKind, asked: Option<&str>) -> Result<Plan, CliError> {
        crate::worker::vps::line_plan(self.api, kind, asked).await
    }

    fn confirm(&self, question: &str) -> Result<bool, String> {
        crate::node::common::confirm(question)
    }

    fn new_key(&self) -> Result<StartKey, CliError> {
        crate::worker::server::new_key()
    }

    async fn pause(&self, pause: Duration) {
        tokio::time::sleep(pause).await;
    }
}

// -------------------------------------------------------------------- the run

/// Where a line of the environment is for: the server's address, which a
/// gRPC or Shreds line lets in, and its region, where an Unlimited RPC is
/// started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Target<'a> {
    pub(crate) ip: Ipv4Addr,
    pub(crate) region: Option<&'a str>,
}

/// How long the line is waited for once started, and how often its record
/// is read: three minutes, every five seconds.
const WAIT: (u32, Duration) = (36, Duration::from_secs(5));

/// The line of `kind` the record names that is not ended, as the deploy
/// that follows reads it ([`crate::worker::deploy_account::ended`]).
fn on_record(record: &EnvDetail, kind: LineKind) -> Option<&account::Line> {
    record
        .lines
        .iter()
        .find(|l| l.kind == account_kind(kind) && !crate::worker::deploy_account::ended(&l.state))
}

/// Whether the line of `kind` on `record` is active, with its endpoint.
fn ready(record: &EnvDetail, kind: LineKind) -> bool {
    on_record(record, kind).is_some_and(|l| {
        l.state == account::State::Active
            && !l.pending
            && l.endpoint.as_deref().is_some_and(|e| !e.trim().is_empty())
    })
}

/// The open start that may be a line of `kind`'s: one of that kind, or
/// one of a kind this version does not know, which may be.
fn open_of(open: &[OpenLine], kind: LineKind) -> Option<&OpenLine> {
    open.iter()
        .find(|s| s.kind.as_ref().is_none_or(|k| *k == account_kind(kind)))
}

/// What an answer to a line start leaves of the key kept here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    /// Settled, nothing bought: it goes.
    Gone,
    /// Kept, to be sent again under the same key.
    Again,
    /// Kept: it may have bought a line, and the next run reads the account
    /// first.
    Held,
}

/// The answers the account gives before anything is bought.
const NOTHING_BOUGHT: [AccountCode; 11] = [
    AccountCode::InvalidRequest,
    AccountCode::OutOfStock,
    AccountCode::RegionDown,
    AccountCode::InsufficientCredit,
    AccountCode::PaymentAuthRequired,
    AccountCode::BillingAddressRequired,
    AccountCode::PurchaseRefused,
    AccountCode::LimitExceeded,
    AccountCode::UdpPremiumNotOnSale,
    AccountCode::UnsupportedForAccount,
    AccountCode::WorkerNotFound,
];

/// [`After`] for the answer `e` to a line start.
fn after(e: &WorkerError) -> After {
    let WorkerError::Refused(r) = e else {
        return After::Held;
    };
    match &r.code {
        Some(AccountCode::StartPending) if r.retry() => After::Again,
        Some(AccountCode::PurchaseUnavailable | AccountCode::RateLimited) => After::Again,
        Some(AccountCode::EnvNotFound) => After::Gone,
        Some(code) if NOTHING_BOUGHT.contains(code) => After::Gone,
        _ => After::Held,
    }
}

/// Starts each line of `lines` (kind and plan asked, `None`: the cheapest)
/// that environment `app.env` of the app named `name` does not have yet,
/// for `target`, and waits for each to be active. `yes` says the price in
/// place of asking it; the store of what is kept here is `store`. What is
/// said goes to stderr, line by line, and comes back too.
pub(crate) async fn start_lines(
    reach: &impl Reach,
    (app, name): (&App, &str),
    lines: &[(LineKind, Option<String>)],
    target: Target<'_>,
    (store, yes): (&Path, bool),
) -> Result<Vec<String>, CliError> {
    let env = app.env.as_str();
    let say = Say { quiet: false };
    let mut said = Vec::new();
    let uid = reach.uid().await?;
    let pin = kept::pin_key(&uid, name, env);
    let read = |e: &WorkerError| kept::worker_error(name, app, e);
    for (kind, asked) in lines {
        let kind = *kind;
        let file_key = file_key(&pin, kind);
        let kept_here = load(store).map_err(failed)?.starts.get(&file_key).cloned();
        let record = reach.env(name, env).await.map_err(|e| read(&e))?;
        if on_record(&record, kind).is_none() {
            let open = reach.open_lines(name, env).await.map_err(|e| read(&e))?;
            // What this run would send: its address or region.
            let ip =
                matches!(kind, LineKind::Grpc | LineKind::Shreds).then(|| target.ip.to_string());
            let region = (kind == LineKind::Unlimited)
                .then(|| target.region.map(str::to_owned))
                .flatten();
            if kind == LineKind::Unlimited && region.is_none() {
                return Err(failed(t!("worker_vps.line.no_region"))
                    .hint(t!("worker_vps.line.no_region_hint")));
            }
            // One open that is not the start kept here, or of a kind this
            // version cannot tell: it may yet buy a line.
            if let Some(other) = open_of(&open, kind)
                && (other.kind.is_none()
                    || kept_here
                        .as_ref()
                        .is_none_or(|k| other.product_id.as_deref() != Some(k.product_id.as_str())))
            {
                let start = crate::storage::clean(&other.id);
                return Err(failed(t!(
                    "worker_first_deploy.line_open",
                    kind = kind.label(),
                    env,
                    start = start.as_str()
                ))
                .hint(t!("worker_server.support_hint", start = start.as_str())));
            }
            let start = start_to_send(
                reach,
                (app, kind, asked.as_deref()),
                (ip, region),
                kept_here,
                (store, &file_key, yes),
            )
            .await?;
            let key = StartKey::new(start.key.as_str()).map_err(|e| failed(e.to_string()))?;
            match reach.start(name, env, &key, &start.body(kind)).await {
                Ok(_) => {
                    keep(store, &file_key, None).map_err(failed)?;
                    let line = t!("worker_first_deploy.line_started", kind = kind.label(), env);
                    say.line(&line);
                    said.push(line);
                }
                Err(e) => return Err(not_started(&e, (app, name, kind), (store, &file_key))),
            }
        } else if kept_here.is_some() {
            // On record: what was kept here went through.
            keep(store, &file_key, None).map_err(failed)?;
        }
        wait(reach, (app, name), kind, &say).await?;
    }
    Ok(said)
}

/// The start to send for a line of `kind` (`asked`: its plan, `None`: the
/// cheapest) for `app`, with the address or region this run sends: the one
/// kept here, sent again under its key with the same body once its price is
/// asked again (the account answers it with what it put on record, sends
/// it on while it is open, and takes it as a new send when it holds
/// nothing); refused when it was kept for another plan or address. Else a
/// new one, its price asked, kept under `file_key` in `store` before it is
/// sent.
async fn start_to_send(
    reach: &impl Reach,
    (app, kind, asked): (&App, LineKind, Option<&str>),
    (ip, region): (Option<String>, Option<String>),
    kept_here: Option<Kept>,
    (store, file_key, yes): (&Path, &str, bool),
) -> Result<Kept, CliError> {
    let env = app.env.as_str();
    let say = Say { quiet: false };
    if let Some(start) = kept_here {
        let other_plan = asked.is_some_and(|p| p != start.product_id);
        if other_plan || start.ip != ip || start.region != region {
            return Err(failed(t!(
                "worker_first_deploy.line_kept_other",
                kind = kind.label(),
                env,
                plan = crate::storage::clean(&start.product_id)
            ))
            .hint(t!(
                "worker_first_deploy.line_kept_other_hint",
                scope = app.scope()
            )));
        }
        let plan = reach.plan(kind, Some(&start.product_id)).await?;
        ask(reach, (kind, &plan, env), yes, &say)?;
        return Ok(start);
    }
    let plan = reach.plan(kind, asked).await?;
    ask(reach, (kind, &plan, env), yes, &say)?;
    let start = Kept {
        key: reach.new_key()?.as_str().to_owned(),
        product_id: plan.id,
        ip,
        region,
    };
    // Kept before it is sent: an answer lost on the way leaves the next run
    // to send it again under its key.
    keep(store, file_key, Some(&start))
        .map_err(|error| failed(t!("worker_server.not_kept", error)))?;
    Ok(start)
}

/// The stop of a line start of `kind` the account answered `e`: with what
/// became of its key kept under `file_key` in `store`.
fn not_started(
    e: &WorkerError,
    (app, name, kind): (&App, &str, LineKind),
    (store, file_key): (&Path, &str),
) -> CliError {
    let kept_or_not = match after(e) {
        After::Gone => {
            keep(store, file_key, None).map(|()| t!("worker_first_deploy.line_key_let_go"))
        }
        After::Again | After::Held => Ok(t!("worker_first_deploy.line_key_kept")),
    }
    .unwrap_or_else(|error| t!("worker_server.unkept", error));
    let said = kept::worker_error(name, app, e);
    failed(format!(
        "{}\n{kept_or_not}",
        t!(
            "worker_first_deploy.line_not_started",
            kind = kind.label(),
            env = app.env.as_str(),
            why = said.message
        )
    ))
    .hint(t!(
        "worker_first_deploy.line_again_hint",
        scope = app.scope()
    ))
}

/// [`start_lines`] for the first deploy of `app`, once its server is
/// logged in to: signed in, the hourly catalogue read through user-api, and
/// the server's address and region read from the environment's record.
pub(crate) async fn for_deploy(
    app: &App,
    lines: &[(LineKind, Option<String>)],
    yes: bool,
) -> Result<(), CliError> {
    let (_, m) = crate::worker::load(&app.dir)?;
    let signed = kept::Signed::open().await?;
    let api = crate::worker::vps::Api::open().await?;
    let record = kept::Account::env(&signed, &m.name, &app.env)
        .await
        .map_err(|e| kept::worker_error(&m.name, app, &e))?;
    let (ip, region) = target_of(&record, app)?;
    let store = crate::account::session::beside_config(FILE).map_err(failed)?;
    start_lines(
        &Live {
            signed: &signed,
            api: &api,
        },
        (app, &m.name),
        lines,
        Target {
            ip,
            region: region.as_deref(),
        },
        (&store, yes),
    )
    .await
    .map(|_| ())
}

/// The address and region of the server in use `record` names, as a line
/// is started for it: refused when the record gives no IPv4 address.
fn target_of(record: &EnvDetail, app: &App) -> Result<(Ipv4Addr, Option<String>), CliError> {
    let server = record
        .servers
        .iter()
        .find(|s| s.slot == account::Slot::Active);
    let address = record
        .facts
        .host
        .as_deref()
        .or_else(|| server.and_then(|s| s.address.as_deref()));
    let ip = address
        .and_then(|a| a.trim().parse::<Ipv4Addr>().ok())
        .ok_or_else(|| {
            failed(t!(
                "worker_first_deploy.line_no_address",
                env = app.env.as_str()
            ))
            .hint(t!(
                "worker_first_deploy.line_again_hint",
                scope = app.scope()
            ))
        })?;
    Ok((ip, server.and_then(|s| s.region.clone())))
}

/// Asks the price of `plan` for a line of `kind` of environment `env`, or
/// says it under `yes`: the hourly catalogue's.
fn ask(
    reach: &impl Reach,
    (kind, plan, env): (LineKind, &Plan, &str),
    yes: bool,
    say: &Say,
) -> Result<(), CliError> {
    let price = format!("{:.4}", plan.cents / 100.0);
    let (name, product) = (plan.name.as_str(), plan.id.as_str());
    let kind = kind.label();
    if yes {
        say.line(&t!(
            "worker_first_deploy.line_note",
            kind,
            name,
            product,
            env,
            price = price.as_str()
        ));
        return Ok(());
    }
    let question = t!(
        "worker_first_deploy.line_question",
        kind,
        name,
        product,
        env,
        price = price.as_str()
    );
    if reach.confirm(&question).map_err(failed)? {
        Ok(())
    } else {
        Err(CliError::new(
            Code::Declined,
            t!("worker_first_deploy.line_declined", kind, env),
        ))
    }
}

/// Waits for the line of `kind` to be active with its endpoint, reading
/// the environment's record as [`WAIT`] says.
async fn wait(
    reach: &impl Reach,
    (app, name): (&App, &str),
    kind: LineKind,
    say: &Say,
) -> Result<(), CliError> {
    let env = app.env.as_str();
    let (tries, pause) = WAIT;
    let mut told = false;
    for _ in 0..tries {
        let record = reach
            .env(name, env)
            .await
            .map_err(|e| kept::worker_error(name, app, &e))?;
        if ready(&record, kind) {
            return Ok(());
        }
        if !told {
            say.line(&t!(
                "worker_first_deploy.line_waiting",
                kind = kind.label(),
                env
            ));
            told = true;
        }
        reach.pause(pause).await;
    }
    Err(failed(t!(
        "worker_first_deploy.line_not_ready",
        kind = kind.label(),
        env
    ))
    .hint(t!(
        "worker_first_deploy.line_not_ready_hint",
        scope = app.scope()
    )))
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;

    use erpc_api::worker::Refusal;
    use serde_json::{Value, json};

    use super::*;

    const LINE_ID: &str = "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314";
    const START_ID: &str = "5d1e2f3a-4b5c-4d6e-8f70-819a2b3c4d5e";
    const IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

    fn record(lines: &Value) -> EnvDetail {
        serde_json::from_value(json!({
            "name": "prod", "revision": 1, "factsFormat": 2,
            "facts": { "desiredCores": null, "host": "203.0.113.10", "sshUser": null,
                "sshPort": null, "hostKey": null,
                "firewall": { "sshAllow": [], "appAllow": [] }, "starting": {}, "backup": null },
            "servers": [{ "id": "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60", "slot": "active",
                "cores": 1, "memoryGb": 2, "region": "amsterdam", "hourly": true,
                "appRunning": false, "state": "active" }],
            "desiredCores": null, "activeCores": null, "coreOptions": [],
            "lines": lines, "refStates": { "backup": null }, "deployed": null,
            "deployedApp": null, "updatedAt": "2026-11-24T12:00:00.000Z"
        }))
        .expect("an environment")
    }

    fn line(kind: &str, state: &str, endpoint: Option<&str>) -> Value {
        json!({ "id": LINE_ID, "kind": kind, "hourly": true, "pending": endpoint.is_none(),
            "state": state, "endpoint": endpoint })
    }

    /// How the stand-in answers a line start.
    enum Answer {
        /// Started: the line is on record, active after `reads` more reads.
        Started { reads: u32 },
        /// Refused with this code.
        Refused(&'static str),
        /// Started, and the answer lost on the way.
        Lost,
    }

    /// The account, the catalogue and the terminal, played.
    struct Fake {
        store: PathBuf,
        lines: RefCell<Vec<Value>>,
        open: RefCell<Vec<OpenLine>>,
        answers: RefCell<Vec<Answer>>,
        /// Reads of the record left before a started line is active.
        reads_left: Cell<u32>,
        /// Each start as sent: its key, its body, and whether its key was
        /// kept here as it was sent.
        sent: RefCell<Vec<(String, Value, bool)>>,
        says_yes: RefCell<Vec<bool>>,
        asked: RefCell<Vec<String>>,
        keys: Cell<u32>,
        pauses: Cell<u32>,
    }

    impl Fake {
        fn new(dir: &tempfile::TempDir) -> Self {
            Self {
                store: dir.path().join(FILE),
                lines: RefCell::new(Vec::new()),
                open: RefCell::new(Vec::new()),
                answers: RefCell::new(Vec::new()),
                reads_left: Cell::new(0),
                sent: RefCell::new(Vec::new()),
                says_yes: RefCell::new(Vec::new()),
                asked: RefCell::new(Vec::new()),
                keys: Cell::new(0),
                pauses: Cell::new(0),
            }
        }

        fn kept(&self) -> Option<Kept> {
            load(&self.store)
                .expect("readable")
                .starts
                .get(&file_key(
                    &kept::pin_key("user-100001", "bot", "prod"),
                    LineKind::Grpc,
                ))
                .cloned()
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the stand-in answers at once; the account it stands in for is awaited"
    )]
    impl Reach for Fake {
        async fn uid(&self) -> Result<String, CliError> {
            Ok("user-100001".to_owned())
        }

        async fn env(&self, _: &str, _: &str) -> Result<EnvDetail, WorkerError> {
            let left = self.reads_left.get();
            if left > 0 {
                self.reads_left.set(left - 1);
            }
            let lines: Vec<Value> = self
                .lines
                .borrow()
                .iter()
                .map(|l| {
                    if left > 0 {
                        line(l["kind"].as_str().unwrap_or("grpc"), "provisioning", None)
                    } else {
                        l.clone()
                    }
                })
                .collect();
            Ok(record(&json!(lines)))
        }

        async fn open_lines(&self, _: &str, _: &str) -> Result<Vec<OpenLine>, WorkerError> {
            Ok(self.open.borrow().clone())
        }

        async fn start(
            &self,
            _: &str,
            _: &str,
            key: &StartKey,
            body: &StartLine,
        ) -> Result<Written<EnvDetail>, WorkerError> {
            let body = serde_json::to_value(body).expect("encodes");
            let kept_then = self.kept().is_some_and(|k| k.key == key.as_str());
            self.sent
                .borrow_mut()
                .push((key.as_str().to_owned(), body.clone(), kept_then));
            let answer = if self.answers.borrow().is_empty() {
                Answer::Started { reads: 0 }
            } else {
                self.answers.borrow_mut().remove(0)
            };
            let kind = body["kind"].as_str().unwrap_or("grpc").to_owned();
            match answer {
                Answer::Started { reads } => {
                    self.lines.borrow_mut().push(line(
                        &kind,
                        "active",
                        Some("grpc.example.net:443"),
                    ));
                    self.open.borrow_mut().clear();
                    self.reads_left.set(reads);
                    Ok(Written::new(
                        true,
                        record(&json!(self.lines.borrow().clone())),
                    ))
                }
                Answer::Lost => {
                    self.open.borrow_mut().push(OpenLine {
                        id: START_ID.to_owned(),
                        kind: Some(account_kind(LineKind::Grpc)),
                        product_id: body["productId"].as_str().map(str::to_owned),
                    });
                    Err(WorkerError::Api(erpc_api::ApiError::Malformed(
                        "lost on the way".to_owned(),
                    )))
                }
                Answer::Refused(code) => Err(WorkerError::Refused(Refusal {
                    status: 402,
                    code: Some(AccountCode::from(code)),
                    message: None,
                    data: Value::Null,
                })),
            }
        }

        async fn plan(&self, _: LineKind, asked: Option<&str>) -> Result<Plan, CliError> {
            Ok(Plan {
                id: asked.unwrap_or("prod_grpc_1").to_owned(),
                cents: 12.5,
                name: "Geyser gRPC Shared".to_owned(),
            })
        }

        fn confirm(&self, question: &str) -> Result<bool, String> {
            self.asked.borrow_mut().push(question.to_owned());
            Ok(if self.says_yes.borrow().is_empty() {
                true
            } else {
                self.says_yes.borrow_mut().remove(0)
            })
        }

        fn new_key(&self) -> Result<StartKey, CliError> {
            let n = self.keys.get() + 1;
            self.keys.set(n);
            StartKey::new(format!("{n:032x}")).map_err(|e| failed(e.to_string()))
        }

        async fn pause(&self, _: Duration) {
            self.pauses.set(self.pauses.get() + 1);
        }
    }

    fn app() -> App {
        App::at("apps/bot", "prod")
    }

    async fn go(fake: &Fake, kind: LineKind, yes: bool) -> Result<Vec<String>, CliError> {
        start_lines(
            fake,
            (&app(), "bot"),
            &[(kind, None)],
            Target {
                ip: IP,
                region: Some("amsterdam"),
            },
            (&fake.store, yes),
        )
        .await
    }

    #[tokio::test]
    async fn a_line_is_asked_at_the_catalogues_price_kept_before_it_is_sent_and_waited_for() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.answers.borrow_mut().push(Answer::Started { reads: 2 });
        let said = go(&fake, LineKind::Grpc, false).await.expect("started");
        let asked = fake.asked.borrow().clone();
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0].contains("gRPC line (Geyser gRPC Shared, product prod_grpc_1)")
                && asked[0].contains("€0.1250 an hour, the hourly catalogue's price"),
            "{}",
            asked[0]
        );
        let sent = fake.sent.borrow().clone();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].2, "kept before it was sent");
        assert_eq!(
            sent[0].1,
            json!({ "kind": "grpc", "productId": "prod_grpc_1", "ip": "203.0.113.10" })
        );
        assert_eq!(fake.kept(), None, "let go once on record");
        assert!(said[0].contains("Started a gRPC line"), "{said:?}");
        // Waited for it to be active, reading its record again.
        assert_eq!(fake.pauses.get(), 2);
    }

    #[tokio::test]
    async fn under_yes_the_price_is_said_and_a_no_starts_nothing() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let _ = crate::node::common::heard::take_printed();
        go(&fake, LineKind::Grpc, true).await.expect("started");
        assert!(fake.asked.borrow().is_empty());
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("Starting a gRPC line") && printed.contains("€0.1250 an hour"),
            "{printed}"
        );
        assert_eq!(fake.sent.borrow().len(), 1);
        // A no: declined, nothing sent or kept.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.says_yes.borrow_mut().push(false);
        let e = go(&fake, LineKind::Grpc, false)
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert!(fake.sent.borrow().is_empty());
        assert_eq!(fake.kept(), None);
    }

    #[tokio::test]
    async fn a_run_again_buys_no_second_line() {
        // The answer lost: the key stays, and the next run, the start open
        // for its plan, sends it again under the same key and body, once
        // its price is asked again.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.answers.borrow_mut().push(Answer::Lost);
        let e = go(&fake, LineKind::Grpc, false).await.expect_err("lost");
        assert!(
            e.message.contains("keeps the line start's key"),
            "{}",
            e.message
        );
        let kept = fake.kept().expect("kept");
        go(&fake, LineKind::Grpc, false).await.expect("sent again");
        let sent = fake.sent.borrow().clone();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].0, kept.key);
        assert_eq!(sent[1].0, kept.key, "the same key");
        assert_eq!(sent[0].1, sent[1].1, "the same body");
        assert_eq!(fake.asked.borrow().len(), 2, "asked again before it");
        assert_eq!(fake.keys.get(), 1, "no new key");
        // On record: nothing asked or sent, and the key kept here goes; a
        // line ended there is no line, and a new one is asked.
        let sent_before = fake.sent.borrow().len();
        go(&fake, LineKind::Grpc, false).await.expect("there");
        assert_eq!(fake.sent.borrow().len(), sent_before);
        assert_eq!(fake.asked.borrow().len(), 2);
        assert_eq!(fake.kept(), None);
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.lines
            .borrow_mut()
            .push(line("grpc", "cancelled", None));
        go(&fake, LineKind::Grpc, false).await.expect("started");
        assert_eq!(fake.sent.borrow().len(), 1);
        assert_eq!(fake.asked.borrow().len(), 1);
    }

    #[tokio::test]
    async fn a_start_kept_here_is_sent_again_under_its_key_or_stops_when_it_is_for_another() {
        let kept_at = |fake: &Fake, start: &Kept| {
            keep(
                &fake.store,
                &file_key(&kept::pin_key("user-100001", "bot", "prod"), LineKind::Grpc),
                Some(start),
            )
            .expect("kept");
        };
        let old = Kept {
            key: "f".repeat(32),
            product_id: "prod_grpc_1".to_owned(),
            ip: Some(IP.to_string()),
            region: None,
        };
        // Neither open nor on record: sent again under its key, asked.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        kept_at(&fake, &old);
        go(&fake, LineKind::Grpc, false).await.expect("started");
        let sent = fake.sent.borrow().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, old.key, "under its key");
        assert_eq!(fake.asked.borrow().len(), 1);
        assert_eq!(fake.keys.get(), 0, "no new key");
        // A no: nothing sent, the key kept.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        kept_at(&fake, &old);
        fake.says_yes.borrow_mut().push(false);
        let e = go(&fake, LineKind::Grpc, false)
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert_eq!(fake.kept(), Some(old.clone()));
        assert!(fake.sent.borrow().is_empty());
        // Kept for another plan, or another address: stopped, unsent,
        // nothing asked.
        for (other, asked) in [
            (old.clone(), Some("prod_grpc_2")),
            (
                Kept {
                    ip: Some("198.51.100.7".to_owned()),
                    ..old.clone()
                },
                None,
            ),
        ] {
            let dir = tempfile::tempdir().expect("a directory");
            let fake = Fake::new(&dir);
            kept_at(&fake, &other);
            let e = start_lines(
                &fake,
                (&app(), "bot"),
                &[(LineKind::Grpc, asked.map(str::to_owned))],
                Target {
                    ip: IP,
                    region: Some("amsterdam"),
                },
                (&fake.store, false),
            )
            .await
            .expect_err("stopped");
            assert!(
                e.message.contains("another plan or address"),
                "{}",
                e.message
            );
            assert!(fake.sent.borrow().is_empty());
            assert!(fake.asked.borrow().is_empty());
            assert_eq!(fake.kept(), Some(other));
        }
    }

    #[tokio::test]
    async fn an_open_start_not_this_machines_refuses_and_sends_nothing() {
        for (kind, product) in [
            (Some(account_kind(LineKind::Grpc)), Some("prod_grpc_1")),
            (Some(account_kind(LineKind::Grpc)), None),
            (None, None),
        ] {
            let dir = tempfile::tempdir().expect("a directory");
            let fake = Fake::new(&dir);
            fake.open.borrow_mut().push(OpenLine {
                id: START_ID.to_owned(),
                kind,
                product_id: product.map(str::to_owned),
            });
            let e = go(&fake, LineKind::Grpc, false).await.expect_err("refused");
            assert!(e.message.contains(START_ID), "{}", e.message);
            assert!(fake.sent.borrow().is_empty());
            assert!(fake.asked.borrow().is_empty());
        }
        // Kept here for another plan than the one open: not this one.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        keep(
            &fake.store,
            &file_key(&kept::pin_key("user-100001", "bot", "prod"), LineKind::Grpc),
            Some(&Kept {
                key: "f".repeat(32),
                product_id: "prod_grpc_1".to_owned(),
                ip: Some(IP.to_string()),
                region: None,
            }),
        )
        .expect("kept");
        fake.open.borrow_mut().push(OpenLine {
            id: START_ID.to_owned(),
            kind: Some(account_kind(LineKind::Grpc)),
            product_id: Some("prod_grpc_2".to_owned()),
        });
        let e = go(&fake, LineKind::Grpc, false).await.expect_err("refused");
        assert!(e.message.contains(START_ID), "{}", e.message);
        assert!(fake.sent.borrow().is_empty());
        // One of a kind erpc cannot tell, though for the plan kept here:
        // refused all the same.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        keep(
            &fake.store,
            &file_key(&kept::pin_key("user-100001", "bot", "prod"), LineKind::Grpc),
            Some(&Kept {
                key: "f".repeat(32),
                product_id: "prod_grpc_1".to_owned(),
                ip: Some(IP.to_string()),
                region: None,
            }),
        )
        .expect("kept");
        fake.open.borrow_mut().push(OpenLine {
            id: START_ID.to_owned(),
            kind: None,
            product_id: Some("prod_grpc_1".to_owned()),
        });
        let e = go(&fake, LineKind::Grpc, false).await.expect_err("refused");
        assert!(e.message.contains(START_ID), "{}", e.message);
        assert!(fake.sent.borrow().is_empty());
        // A start of another kind open is not this one's.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.open.borrow_mut().push(OpenLine {
            id: START_ID.to_owned(),
            kind: Some(account_kind(LineKind::Shreds)),
            product_id: None,
        });
        go(&fake, LineKind::Grpc, false).await.expect("started");
        assert_eq!(fake.sent.borrow().len(), 1);
    }

    #[tokio::test]
    async fn an_answer_that_buys_nothing_lets_the_key_go_and_another_keeps_it() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.answers
            .borrow_mut()
            .push(Answer::Refused("insufficient_credit"));
        let e = go(&fake, LineKind::Grpc, false).await.expect_err("refused");
        assert!(
            e.message.contains("let the line start's key go"),
            "{}",
            e.message
        );
        assert!(
            e.hint
                .as_deref()
                .is_some_and(|h| h.contains("buys no second line")),
            "{e:?}"
        );
        assert_eq!(fake.kept(), None);
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.answers
            .borrow_mut()
            .push(Answer::Refused("something_new"));
        let e = go(&fake, LineKind::Grpc, false).await.expect_err("refused");
        assert!(
            e.message.contains("keeps the line start's key"),
            "{}",
            e.message
        );
        assert!(fake.kept().is_some());
    }

    #[tokio::test]
    async fn each_kind_is_sent_with_what_it_needs() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        go(&fake, LineKind::Unlimited, false)
            .await
            .expect("started");
        go(&fake, LineKind::Shreds, false).await.expect("started");
        let sent = fake.sent.borrow().clone();
        assert_eq!(
            sent[0].1,
            json!({ "kind": "unlimited", "productId": "prod_grpc_1", "region": "amsterdam" })
        );
        assert_eq!(sent[1].1["kind"], "shreds");
        assert_eq!(sent[1].1["ip"], "203.0.113.10");
        // An Unlimited RPC with no region to start in: refused, unsent.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let e = start_lines(
            &fake,
            (&app(), "bot"),
            &[(LineKind::Unlimited, None)],
            Target {
                ip: IP,
                region: None,
            },
            (&fake.store, false),
        )
        .await
        .expect_err("refused");
        assert!(!e.message.is_empty());
        assert!(fake.sent.borrow().is_empty());
        assert_eq!(fake.kept(), None);
    }

    #[tokio::test]
    async fn a_line_not_active_in_time_stops_and_says_the_deploy_goes_on() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.answers
            .borrow_mut()
            .push(Answer::Started { reads: u32::MAX });
        let e = go(&fake, LineKind::Grpc, false)
            .await
            .expect_err("not ready");
        assert!(e.message.contains("is not active yet"), "{}", e.message);
        assert!(
            e.hint
                .as_deref()
                .is_some_and(|h| h.contains("buys nothing more")),
            "{e:?}"
        );
        assert_eq!(fake.pauses.get(), WAIT.0);
        assert_eq!(fake.sent.borrow().len(), 1);
    }

    #[test]
    fn the_address_and_region_come_from_the_record() {
        let app = app();
        let (ip, region) = target_of(&record(&json!([])), &app).expect("a target");
        assert_eq!((ip, region.as_deref()), (IP, Some("amsterdam")));
        let mut none = record(&json!([]));
        none.facts.host = None;
        let e = target_of(&none, &app).expect_err("no address");
        assert!(e.message.contains("IPv4"), "{}", e.message);
    }
}
