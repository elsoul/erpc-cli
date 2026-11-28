// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker server start`: buys a server, paid for by the hour, for an
//! environment kept in the ERPC account whose record names none yet.
//!
//! The start is sent under a key kept on this machine first
//! (`worker_starts.json` beside erpc's config, 0600), with the size and the
//! region it asks for, so that a start whose answer was lost is not made
//! twice. Each run reads the account before anything else:
//! - the environment's record names a server: nothing is started, and a
//!   start kept here is let go, unless a start is still listed open;
//! - a start of the environment is still open: no new start is made; the
//!   one kept here is sent again under its own key only when the account's
//!   last answer to it said to send it again;
//! - neither: a start kept here bought nothing that the record names, and
//!   a new one is made under a new key, once its price is said and agreed
//!   to.
//!
//! After an answer, the key is let go when the account settled the start
//! (the server is on record, the purchase was ended, or the start was
//! refused before anything was bought); otherwise it is kept, and is sent
//! again only when the account said to.
//!
//! The first `erpc worker deploy` that starts a new server
//! ([`crate::worker::first_deploy`]) starts it here too ([`for_deploy`]):
//! the cheapest size the account offers, near this machine unless
//! `--region` says otherwise, and `account = true` written to `erpc.toml`
//! after the yes and before the start is sent.

use std::collections::BTreeMap;
use std::path::Path;

use erpc_api::worker::money::{ServerPrice, ServerPrices, StartKey, StartOf, StartServer};
use erpc_api::worker::{
    self as account, Code as AccountCode, EnvDetail, Facts, PutApp, PutEnv, PutWallet, WorkerError,
    Written,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::account::commands::Outcome;
use crate::cli::error::{CliError, Code};
use crate::node::common::Say;
use crate::worker::App;
use crate::worker::account as kept;

/// The file the starts are kept in, beside erpc's config.
const FILE: &str = "worker_starts.json";

fn failed(message: String) -> CliError {
    CliError::new(Code::Failed, message)
}

/// A start of the environment that is still open, as the account lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Open {
    /// Its id.
    pub(crate) id: String,
    /// Whether it is a server's start.
    pub(crate) server: bool,
    /// The cores of a server's start.
    pub(crate) cores: Option<u16>,
    /// The region it was started in.
    pub(crate) region: Option<String>,
}

/// What the start asks of the ERPC account. The signed-in session is the
/// one that reaches it; a test brings a stand-in.
pub(crate) trait Buying {
    /// The account's own id, which the starts kept here are filed under.
    async fn uid(&self) -> Result<String, CliError>;
    /// The app named `name`.
    async fn app(&self, name: &str) -> Result<account::App, WorkerError>;
    /// Environment `env` of the app named `name`.
    async fn env(&self, name: &str, env: &str) -> Result<EnvDetail, WorkerError>;
    /// Makes the record of the app named `name`.
    async fn put_app(
        &self,
        name: &str,
        body: &PutApp,
    ) -> Result<Written<account::App>, WorkerError>;
    /// Makes the record of its environment `env`.
    async fn put_env(
        &self,
        name: &str,
        env: &str,
        body: &PutEnv,
    ) -> Result<Written<EnvDetail>, WorkerError>;
    /// The sizes a server start takes there, each with its price by the
    /// hour.
    async fn prices(&self, name: &str, env: &str) -> Result<ServerPrices, WorkerError>;
    /// The starts of the environment still open.
    async fn starts(&self, name: &str, env: &str) -> Result<Vec<Open>, WorkerError>;
    /// Starts a server there under `key`, kept before.
    async fn start(
        &self,
        name: &str,
        env: &str,
        key: &StartKey,
        body: &StartServer,
    ) -> Result<Written<EnvDetail>, WorkerError>;
}

impl Buying for kept::Signed {
    async fn uid(&self) -> Result<String, CliError> {
        kept::Account::uid(self).await
    }

    async fn app(&self, name: &str) -> Result<account::App, WorkerError> {
        kept::Account::app(self, name).await
    }

    async fn env(&self, name: &str, env: &str) -> Result<EnvDetail, WorkerError> {
        kept::Account::env(self, name, env).await
    }

    async fn put_app(
        &self,
        name: &str,
        body: &PutApp,
    ) -> Result<Written<account::App>, WorkerError> {
        self.make_app(name, body).await
    }

    async fn put_env(
        &self,
        name: &str,
        env: &str,
        body: &PutEnv,
    ) -> Result<Written<EnvDetail>, WorkerError> {
        kept::Account::put_env(self, name, env, body).await
    }

    async fn prices(&self, name: &str, env: &str) -> Result<ServerPrices, WorkerError> {
        self.server_prices(name, env).await
    }

    async fn starts(&self, name: &str, env: &str) -> Result<Vec<Open>, WorkerError> {
        Ok(self
            .open_starts(name, env)
            .await?
            .into_iter()
            .map(|s| Open {
                server: s.of == StartOf::Server,
                id: s.id,
                cores: s.cores,
                region: s.region,
            })
            .collect())
    }

    async fn start(
        &self,
        name: &str,
        env: &str,
        key: &StartKey,
        body: &StartServer,
    ) -> Result<Written<EnvDetail>, WorkerError> {
        self.start_server(name, env, key, body).await
    }
}

// ------------------------------------------------------- the starts kept here

/// A start this machine made, kept from before it is sent until the
/// account settles it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Kept {
    /// Its key.
    key: String,
    /// The cores it asks for.
    cores: u16,
    /// The region it asks for.
    region: String,
    /// Whether the account's last answer to it said to send it again under
    /// the same key.
    #[serde(default)]
    resend: bool,
}

/// The starts kept here, by the key of the account, app and environment
/// ([`kept::pin_key`]).
#[derive(Debug, Default, Serialize, Deserialize)]
struct Starts {
    #[serde(default)]
    starts: BTreeMap<String, Kept>,
}

/// The starts kept in `path`; none when there is no file yet. A file that
/// cannot be read is an error, never an empty list: a start in it may have
/// bought a server.
fn load(path: &Path) -> Result<Starts, String> {
    let unreadable = |error: String| t!("worker_server.unreadable", path = path.display(), error);
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| unreadable(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Starts::default()),
        Err(e) => Err(unreadable(e.to_string())),
    }
}

/// The start kept in `path` under `key`.
fn kept_start(path: &Path, key: &str) -> Result<Option<Kept>, String> {
    Ok(load(path)?.starts.remove(key))
}

/// Keeps `start` in `path` under `key`, or lets the one there go when
/// `start` is none, read and written under the lock: what a test sets up.
#[cfg(test)]
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

/// Keeps `start` in `path` under `file_key` in place of the start kept
/// there under `was` (none: no start): another run's start kept since is
/// not written over, and nothing is kept.
fn keep_over(path: &Path, file_key: &str, start: &Kept, was: Option<&str>) -> Result<(), String> {
    erpc_core::private_file::locked(path, || {
        let mut starts = load(path)?;
        if starts.starts.get(file_key).map(|s| s.key.as_str()) != was {
            return Err(t!("worker_server.kept_meanwhile"));
        }
        starts.starts.insert(file_key.to_owned(), start.clone());
        let text = serde_json::to_vec_pretty(&starts).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)
    })
}

/// Lets the start kept in `path` under `file_key` go, when it is still the
/// one under `key`: another run's start kept since stays.
fn let_go(path: &Path, file_key: &str, key: &str) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    erpc_core::private_file::locked(path, || {
        let mut starts = load(path)?;
        if starts.starts.get(file_key).is_none_or(|s| s.key != key) {
            return Ok(());
        }
        starts.starts.remove(file_key);
        let text = serde_json::to_vec_pretty(&starts).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)
    })
}

/// A new start's key: 16 random bytes, in lowercase hex.
pub(crate) fn new_key() -> Result<StartKey, CliError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| failed(t!("worker_server.no_key", error = e.to_string())))?;
    let hex = bytes.iter().fold(String::with_capacity(32), |mut hex, b| {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
        hex
    });
    StartKey::new(hex).map_err(|e| failed(e.to_string()))
}

// ------------------------------------------------------------------ the run

/// What was asked, and who can answer.
pub(crate) struct Asked<'a> {
    /// The cores asked for; `None`: those of the start kept here when it is
    /// sent again, else the cheapest size the account offers.
    pub(crate) cores: Option<u16>,
    /// The `--plan` asked for, when its product's name gives no size erpc
    /// reads: the start is refused with the sizes the account offers, once
    /// they are read, before anything is bought.
    pub(crate) unread: Option<&'a str>,
    /// The region.
    pub(crate) region: Region<'a>,
    /// `--yes`.
    pub(crate) yes: bool,
    /// `--json`.
    pub(crate) json: bool,
    /// Whether a person is at a terminal.
    pub(crate) terminal: bool,
    /// The command that starts it.
    pub(crate) by: By,
}

/// The size a first deploy's start asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Size<'a> {
    /// The cheapest the account offers.
    Cheapest,
    /// These cores (`--plan`'s, read from its product's name, or another
    /// size offered for it).
    Cores(u16),
    /// `--plan`, whose product's name gives no size erpc reads.
    Unread(&'a str),
}

/// The region of a start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Region<'a> {
    /// Asked for (`--region`).
    Asked(&'a str),
    /// Not asked for: that of the start kept here when it is sent again,
    /// else this one (the nearest by this machine's time zone).
    Else(&'a str),
}

impl<'a> Region<'a> {
    /// The region asked for, if one was.
    const fn asked(self) -> Option<&'a str> {
        match self {
            Self::Asked(region) => Some(region),
            Self::Else(_) => None,
        }
    }
}

/// The command that starts the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum By {
    /// `erpc worker server start`.
    ServerStart,
    /// The first `erpc worker deploy` that starts a new server.
    Deploy,
}

/// `cents` of a euro, as a price is said: `0.07`.
fn euros(cents: u64) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// The server of `price`'s size, as a person reads it: "ERPC Worker" and
/// its spec ([`crate::worker::vps::worker`]).
fn worker_of(price: &ServerPrice) -> String {
    use crate::worker::vps::{Spec, worker};
    worker(&Spec::sized(Some(price.cores), Some(price.memory_gb)))
}

/// A server of `cores` cores, as a person reads it.
fn worker_cored(cores: u16) -> String {
    use crate::worker::vps::{Spec, worker};
    worker(&Spec::sized(Some(cores), None))
}

/// One size and its price, as the refusal of another lists it.
fn size_said(price: &ServerPrice) -> String {
    t!(
        "worker_server.size",
        worker = worker_of(price),
        price = euros(price.hourly_cents)
    )
}

/// The size asked for, from `prices` (`None`: the cheapest): refused when
/// the account prices it in a currency erpc does not show, starts none, or
/// does not offer it.
fn priced(
    prices: &ServerPrices,
    env: &str,
    cores: Option<u16>,
    unread: Option<&str>,
) -> Result<ServerPrice, CliError> {
    if prices.currency != "eur" {
        return Err(failed(t!(
            "worker_server.currency",
            currency = crate::storage::clean(&prices.currency)
        )));
    }
    if prices.options.is_empty() {
        return Err(failed(t!("worker_server.no_sizes", env)));
    }
    // `--plan`, whose name gives no size: refused with the sizes offered.
    if let Some(plan) = unread {
        let offered: Vec<String> = prices.options.iter().map(size_said).collect();
        return Err(CliError::new(
            Code::Usage,
            t!(
                "worker_server.plan_unread",
                plan = crate::storage::clean(plan),
                offered = offered.join(", ")
            ),
        ));
    }
    let found = match cores {
        Some(cores) => prices.options.iter().find(|o| o.cores == cores),
        None => prices
            .options
            .iter()
            .min_by_key(|o| (o.hourly_cents, o.cores)),
    };
    match (found, cores) {
        (Some(found), _) => Ok(found.clone()),
        (None, Some(cores)) => {
            let offered: Vec<String> = prices.options.iter().map(size_said).collect();
            Err(CliError::new(
                Code::Usage,
                t!(
                    "worker_server.not_offered",
                    worker = worker_cored(cores),
                    offered = offered.join(", ")
                ),
            ))
        }
        // Offered sizes, so the cheapest is one of them.
        (None, None) => Err(failed(t!("worker_server.no_sizes", env))),
    }
}

/// Asks `question` before the start: at a terminal, unless `--yes`, which
/// says `note` on stderr instead; with nobody to ask, refused.
fn ask(
    asked: &Asked<'_>,
    (question, note): (&str, &str),
    confirm: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<(), CliError> {
    if asked.yes {
        Say { quiet: false }.line(note);
        return Ok(());
    }
    if asked.json || !asked.terminal {
        return Err(nobody());
    }
    if confirm(question).map_err(failed)? {
        Ok(())
    } else {
        Err(CliError::new(Code::Declined, t!("worker_server.declined")))
    }
}

/// What becomes of the start kept here after the account answered `e`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    /// The account settled it without a server: it goes.
    Gone,
    /// The account said to send it again under the same key.
    Again,
    /// Whether it bought a server is not known: it stays, not to be sent
    /// again.
    Held,
    /// The account did not take the request: it stays as it was.
    AsItWas,
}

/// What became of the start kept here after the answer, from what this
/// machine could write: said in a sentence of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyFate {
    /// Let go.
    LetGo,
    /// Kept, to be sent again under the same key.
    KeptAgain,
    /// Kept, not to be sent again.
    KeptHeld,
    /// This machine's record of it could not be updated, for this reason.
    Unkept(String),
}

impl KeyFate {
    /// The sentence that says it.
    fn said(&self) -> String {
        match self {
            Self::LetGo => t!("worker_server.key_let_go"),
            Self::KeptAgain => t!("worker_server.key_again"),
            Self::KeptHeld => t!("worker_server.key_held"),
            Self::Unkept(error) => t!("worker_server.unkept", error = error.as_str()),
        }
    }
}

/// The answers the account gives before anything is bought.
const NOTHING_BOUGHT: [AccountCode; 12] = [
    AccountCode::InvalidRequest,
    AccountCode::SlotOccupied,
    AccountCode::InsufficientCredit,
    AccountCode::PaymentAuthRequired,
    AccountCode::BillingAddressRequired,
    AccountCode::PurchaseRefused,
    AccountCode::OutOfStock,
    AccountCode::RegionDown,
    AccountCode::UnsupportedForAccount,
    AccountCode::WorkerNotFound,
    AccountCode::EnvNotFound,
    AccountCode::RevisionConflict,
];

/// [`After`] for the answer `e` to a start.
fn after(e: &WorkerError) -> After {
    let WorkerError::Refused(r) = e else {
        return After::Held;
    };
    match &r.code {
        Some(AccountCode::StartPending) if r.retry() => After::Again,
        Some(AccountCode::PurchaseUnavailable) => After::Again,
        // Another start is open: this key bought nothing.
        Some(AccountCode::StartPending | AccountCode::StartEnded) => After::Gone,
        Some(AccountCode::RateLimited) => After::AsItWas,
        Some(code) if NOTHING_BOUGHT.contains(code) => After::Gone,
        _ => After::Held,
    }
}

/// The refusal of a start the account answered `e`: the answer's own
/// sentence, then `fate`, what became of the start kept here, in a sentence
/// of its own.
fn refused(e: &WorkerError, then: After, name: &str, app: &App, fate: &KeyFate) -> CliError {
    let env = app.env.as_str();
    let scope = app.scope();
    let mut error = kept::worker_error(name, app, e);
    // The account's answer by its status and code alone: its message may
    // name steps erpc does not take.
    let (why, start, code, reason) = match e {
        WorkerError::Refused(r) => (
            r.code.as_ref().map_or_else(
                || format!("HTTP {}", r.status),
                |code| format!("HTTP {}, {code}", r.status),
            ),
            r.start_id(),
            r.code.clone(),
            r.reason(),
        ),
        _ => (error.message.clone(), None, None, None),
    };
    let start_said = start.clone().unwrap_or_default();
    error.message = match (then, code) {
        (After::Gone, Some(AccountCode::StartEnded)) => t!("worker_server.ended", env, why),
        (After::Gone, Some(AccountCode::StartPending)) => t!(
            "worker_server.other_open",
            env,
            start = start_said.as_str(),
            why
        ),
        (After::Gone, Some(AccountCode::RevisionConflict)) => {
            t!("worker_server.changed_before", env, why)
        }
        (After::Gone, _) => t!("worker_server.not_started", env, why),
        (After::Again, _) => t!("worker_server.again", env, why),
        (After::Held, Some(AccountCode::StartUnsettled))
            if reason.as_deref() == Some("start_mismatch") =>
        {
            t!(
                "worker_server.mismatch",
                env,
                start = start_said.as_str(),
                why
            )
        }
        (After::Held, Some(AccountCode::StartUnsettled)) => t!(
            "worker_server.unsettled",
            env,
            reason = reason.unwrap_or_default(),
            start = start_said.as_str(),
            why
        ),
        (After::Held, _) => t!("worker_server.held", env, why),
        (After::AsItWas, _) => t!("worker_server.busy", env, why),
    };
    let hint = match then {
        After::Gone if code_is(e, &AccountCode::RevisionConflict) => {
            Some(t!("worker_server.changed_hint"))
        }
        After::Gone => None,
        // The mark to send it again could not be kept: the next run does
        // not send it again.
        After::Again if matches!(fate, KeyFate::Unkept(_)) => Some(t!(
            "worker_server.again_unkept_hint",
            start = start_said.as_str()
        )),
        After::Again => Some(t!("worker_server.again_hint", scope)),
        After::Held => Some(match start {
            Some(start) => t!("worker_server.support_hint", start),
            None => t!("worker_server.held_hint", scope),
        }),
        After::AsItWas => Some(t!("worker_server.busy_hint", scope)),
    };
    // Signed out, signing in again comes first.
    if error.code != Code::NotSignedIn {
        error.hint = hint.or(error.hint);
    }
    error.message = format!("{}\n{}", error.message, fate.said());
    // What a first deploy offers another size or region for: in the
    // details, as the account's code.
    if code_is(e, &AccountCode::OutOfStock) {
        error.details = Some(json!({ "accountCode": "OUT_OF_STOCK" }));
    }
    error
}

/// Whether `e`, a start's stop, is the account's answer that nothing of
/// the size is free in the region now ([`refused`] marks it).
pub(crate) fn out_of_stock(e: &CliError) -> bool {
    e.details
        .as_ref()
        .is_some_and(|d| d["accountCode"] == "OUT_OF_STOCK")
}

/// The refusal of a start while one of the environment's is open; `kept`
/// says whether a start is kept here, and whether it is one the account
/// said to send again.
fn open_refused(env: &str, open: &Open, kept: Option<bool>) -> CliError {
    let start = crate::storage::clean(&open.id);
    let what = match (open.server, open.cores, open.region.as_deref()) {
        (true, Some(cores), Some(region)) => t!(
            "worker_server.open_server",
            worker = worker_cored(cores),
            region = crate::storage::clean(region)
        ),
        (true, _, _) => t!("worker_server.open_server_unsaid"),
        (false, _, _) => t!("worker_server.open_other"),
    };
    let message = t!("worker_server.open", env, start = start.as_str(), what);
    let message = match kept {
        None => message,
        Some(false) => format!("{message}\n{}", t!("worker_server.open_kept")),
        Some(true) => format!("{message}\n{}", t!("worker_server.open_kept_beside")),
    };
    failed(message).hint(t!("worker_server.support_hint", start = start.as_str()))
}

/// What the record says after a start that is done, with the start kept
/// here under `key` let go: `again` whether this run sent it, `None` when
/// the record named a server before anything was sent.
fn done(
    (store, file_key, key): (&Path, &str, &str),
    env: &str,
    record: &EnvDetail,
    again: Option<bool>,
) -> (Value, String) {
    let mut text = vec![match again {
        Some(_) => t!("worker_server.started", env),
        None => t!("worker_server.done_before", env),
    }];
    let unkept = let_go(store, file_key, key)
        .err()
        .map(|error| t!("worker_server.unkept", error));
    if let Some(unkept) = &unkept {
        text.push(format!("warning: {unkept}"));
    }
    text.extend(kept::account_said(record));
    let answer = json!({
        "started": true,
        "already": again.is_none(),
        "sentAgain": again.unwrap_or(false),
        "env": env,
        "recordError": unkept,
        "account": kept::account_json(record),
    });
    (answer, text.join("\n"))
}

/// The start kept here that is to be sent again, while the environment
/// has starts `open`: only that one, only when the account said to, and
/// only as it was asked for before. Any other open start refuses the run.
fn to_send_again(
    open: &[Open],
    saved: Option<Kept>,
    asked: &Asked<'_>,
    app: &App,
) -> Result<Option<Kept>, CliError> {
    let again = match (open, saved) {
        ([], _) => return Ok(None),
        (starts, Some(saved))
            if saved.resend
                && starts.iter().all(|s| {
                    s.server
                        && s.cores == Some(saved.cores)
                        && s.region.as_ref() == Some(&saved.region)
                }) =>
        {
            saved
        }
        ([first, ..], saved) => {
            return Err(open_refused(
                app.env.as_str(),
                first,
                saved.map(|s| s.resend),
            ));
        }
    };
    // What was not asked for is taken as the kept start has it.
    let cores = asked.cores.unwrap_or(again.cores);
    let region = asked.region.asked().unwrap_or(again.region.as_str());
    if (again.cores, again.region.as_str()) != (cores, region) {
        let scope = app.scope();
        let hint = match asked.by {
            By::ServerStart => t!(
                "worker_server.differs_hint",
                cores = again.cores,
                region = again.region.as_str(),
                scope = scope.as_str()
            ),
            By::Deploy => t!(
                "worker_first_deploy.differs_hint",
                region = again.region.as_str(),
                scope = scope.as_str()
            ),
        };
        return Err(CliError::new(
            Code::Usage,
            t!(
                "worker_server.differs",
                kept = worker_cored(again.cores),
                kept_region = again.region.as_str(),
                asked = worker_cored(cores),
                region
            ),
        )
        .hint(hint));
    }
    Ok(Some(again))
}

/// The question asked before the start of `price`'s size in `region`, and
/// the note said in its place under `--yes`; `name` is the app's.
fn asking(
    (app, name): (&App, &str),
    asked: &Asked<'_>,
    (price, region): (&ServerPrice, &str),
    again: bool,
) -> (String, String) {
    let (env, scope) = (app.env.as_str(), app.scope());
    let worker = worker_of(price);
    let price = euros(price.hourly_cents);
    let (price, scope) = (price.as_str(), scope.as_str());
    let (question, note) = match asked.by {
        By::ServerStart => (
            t!("worker_server.question", env, worker, region, price, scope),
            t!("worker_server.note", env, worker, region, price, scope),
        ),
        By::Deploy => (
            t!(
                "worker_first_deploy.question",
                app = name,
                env,
                worker,
                region,
                price,
                scope
            ),
            t!(
                "worker_first_deploy.note",
                app = name,
                env,
                worker,
                region,
                price,
                scope
            ),
        ),
    };
    if again {
        let same = t!("worker_server.same_start");
        (format!("{same}\n{question}"), format!("{same}\n{note}"))
    } else {
        (question, note)
    }
}

/// What erpc.toml says of the app, which its record is made from when the
/// account has none.
pub(crate) struct Making<'a> {
    /// Its chain.
    pub(crate) chain: &'a str,
    /// The template it was made from.
    pub(crate) template: Option<&'a str>,
    /// Its wallet's public side, as the app's record takes it: `None` for
    /// an app without a wallet, or one whose `erpc.toml` gives no public key
    /// (as the move makes it).
    pub(crate) wallet: Option<PutWallet>,
}

/// The failure `e` of a read or write the start makes before it is sent,
/// with the exit status of its kind; a refusal said in erpc's words, by its
/// status and code (`what` says of what): its message may send the person
/// where the request cannot be made.
fn read_failed(name: &str, app: &App, e: &WorkerError, what: &str) -> CliError {
    let mut error = kept::worker_error(name, app, e);
    if let WorkerError::Refused(r) = e
        && !matches!(
            r.code,
            Some(AccountCode::WorkerNotFound | AccountCode::EnvNotFound)
        )
    {
        let why = r.code.as_ref().map_or_else(
            || format!("HTTP {}", r.status),
            |code| format!("HTTP {}, {code}", r.status),
        );
        error.message = t!("worker_server.read_refused", what, why);
    }
    error
}

/// Whether `e` is the account's refusal with `code`.
fn code_is(e: &WorkerError, code: &AccountCode) -> bool {
    matches!(e, WorkerError::Refused(r) if r.code.as_ref() == Some(code))
}

/// Whether `e` is the account's answer that it has no such record.
fn not_found(e: &WorkerError, code: &AccountCode) -> bool {
    matches!(e, WorkerError::Refused(r) if r.code.as_ref() == Some(code))
}

/// Whether the account has the record of the app named `name`. An app of
/// that name for another chain is refused, and so is one with another
/// wallet: one whose public key is not `erpc.toml`'s, or one where
/// `erpc.toml` gives none.
async fn app_record(
    api: &impl Buying,
    app: &App,
    name: &str,
    making: &Making<'_>,
) -> Result<bool, CliError> {
    let found = match api.app(name).await {
        Ok(found) => found,
        Err(e) if not_found(&e, &AccountCode::WorkerNotFound) => return Ok(false),
        Err(e) => {
            return Err(read_failed(
                name,
                app,
                &e,
                &t!("worker_server.what_app", app = name),
            ));
        }
    };
    if found.chain != making.chain {
        return Err(failed(t!(
            "worker_server.other_chain",
            app = name,
            chain = crate::storage::clean(&found.chain)
        )));
    }
    let ours = making.wallet.as_ref().map(PutWallet::pubkey);
    if found
        .wallet
        .as_ref()
        .is_some_and(|w| Some(w.pubkey.as_str()) != ours)
    {
        return Err(failed(t!("worker_server.other_wallet", app = name)));
    }
    Ok(true)
}

/// The environment's open starts, then its record (none when the account
/// has none), read in that order: a start that closes between the two
/// reads has put its server on the record by the second.
async fn read_state(
    api: &impl Buying,
    app: &App,
    name: &str,
) -> Result<(Vec<Open>, Option<EnvDetail>), CliError> {
    let env = app.env.as_str();
    let open = match api.starts(name, env).await {
        Ok(open) => open,
        Err(e) if not_found(&e, &AccountCode::EnvNotFound) => return Ok((Vec::new(), None)),
        Err(e) => {
            return Err(read_failed(
                name,
                app,
                &e,
                &t!("worker_server.what_starts", env),
            ));
        }
    };
    match api.env(name, env).await {
        Ok(record) => Ok((open, Some(record))),
        Err(e) if not_found(&e, &AccountCode::EnvNotFound) => Ok((open, None)),
        Err(e) => Err(read_failed(
            name,
            app,
            &e,
            &t!("worker_server.what_env", env),
        )),
    }
}

/// What a run does, from what the account has.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    /// The record names a server and a start is kept here: it is done.
    Done,
    /// A new start, under a new key.
    New,
    /// The start kept here, sent again under its key.
    Again(Kept),
}

/// [`Plan`] from the environment's `record` and `open` starts and the start
/// kept here, `saved`; refused when the record names a server (and no start
/// is kept here) or an address, or a start is open that is not the one to
/// send again.
fn decide(
    record: Option<&EnvDetail>,
    open: &[Open],
    saved: Option<Kept>,
    asked: &Asked<'_>,
    app: &App,
) -> Result<Plan, CliError> {
    let env = app.env.as_str();
    if let Some(record) = record {
        kept::current_format(app, record)?;
        if !record.servers.is_empty() {
            // The start kept here went through, or the record has a server
            // another way: there is nothing left to send either way.
            return if saved.is_some() {
                match open.first() {
                    // A start still open: the kept one stays until the
                    // account settles it, and nothing is sent.
                    Some(first) => {
                        let start = crate::storage::clean(&first.id);
                        Err(
                            failed(t!("worker_server.holds_open", env, start = start.as_str()))
                                .hint(t!("worker_server.support_hint", start = start.as_str())),
                        )
                    }
                    None => Ok(Plan::Done),
                }
            } else {
                let holds = failed(t!("worker_server.holds", env));
                Err(match asked.by {
                    By::ServerStart => holds,
                    // erpc.toml may not say yet that the account keeps it.
                    By::Deploy => holds.hint(t!(
                        "worker_first_deploy.holds_hint",
                        env,
                        scope = app.scope()
                    )),
                })
            };
        }
        // An address and no server: a server of the person's own, or one
        // ended, which commands that reach the server would still take for
        // this environment's.
        if record.facts.host.is_some() {
            return Err(failed(t!("worker_server.holds_address", env)));
        }
    }
    Ok(match to_send_again(open, saved, asked, app)? {
        Some(again) => Plan::Again(again),
        None => Plan::New,
    })
}

/// Makes the records the account does not have: the app's (when
/// `has_app` is false) and the environment's, which holds nothing yet.
/// Each is said on stderr as it is made: it costs nothing.
async fn make(
    api: &impl Buying,
    app: &App,
    name: &str,
    making: &Making<'_>,
    has_app: bool,
) -> Result<u64, CliError> {
    let say = Say { quiet: false };
    let env = app.env.as_str();
    if !has_app {
        let body = PutApp::new(
            0,
            making.chain,
            making.template.map(str::to_owned),
            making.wallet.clone(),
        );
        api.put_app(name, &body)
            .await
            .map_err(|e| read_failed(name, app, &e, &t!("worker_server.what_app", app = name)))?;
        say.line(&t!("worker_server.made_app", app = name));
    }
    let made = api
        .put_env(name, env, &PutEnv::new(0, Facts::default()))
        .await
        .map_err(|e| read_failed(name, app, &e, &t!("worker_server.what_env", env)))?;
    say.line(&t!("worker_server.made_env", env));
    Ok(made.record.revision)
}

/// The refusal of a start with nobody to say yes.
fn nobody() -> CliError {
    CliError::new(Code::NeedsTerminal, t!("worker_server.needs_yes"))
        .hint(t!("worker_server.needs_yes_hint"))
}

/// The start, through `api`: what the account holds read, the price said
/// and agreed to (`confirm`), `agreed` done, the key kept in `store`, then
/// the start sent.
pub(crate) async fn run_with(
    api: &impl Buying,
    app: &App,
    name: &str,
    store: &Path,
    (making, asked): (&Making<'_>, &Asked<'_>),
    (confirm, agreed): (
        impl FnOnce(&str) -> Result<bool, String>,
        impl FnOnce() -> Result<(), CliError>,
    ),
    make_key: impl FnOnce() -> Result<StartKey, CliError>,
) -> Result<(Value, String), CliError> {
    let env = app.env.as_str();
    let uid = api.uid().await?;
    let file_key = kept::pin_key(&uid, name, env);
    let saved = kept_start(store, &file_key)
        .map_err(|error| failed(t!("worker_server.not_read", error)))?;
    let has_app = app_record(api, app, name, making).await?;
    let (open, record) = if has_app {
        read_state(api, app, name).await?
    } else {
        (Vec::new(), None)
    };
    let plan = decide(record.as_ref(), &open, saved.clone(), asked, app)?;
    if plan == Plan::Done
        && let (Some(record), Some(saved)) = (&record, &saved)
    {
        return Ok(done((store, &file_key, &saved.key), env, record, None));
    }
    let again = match &plan {
        Plan::Again(again) => Some(again.clone()),
        Plan::Done | Plan::New => None,
    };
    // The start is made only while the environment is at the revision read
    // before the price: one changed meanwhile (a server in use of another
    // tier taken in, say) is refused by the account, buying nothing.
    let revision = if let Some(record) = &record {
        record.revision
    } else {
        // The account prices a start for an environment it has: the
        // records come first, made only when someone can then say yes.
        if !asked.yes && (asked.json || !asked.terminal) {
            return Err(nobody());
        }
        make(api, app, name, making, has_app).await?
    };
    let prices = api
        .prices(name, env)
        .await
        .map_err(|e| read_failed(name, app, &e, &t!("worker_server.what_prices", env)))?;
    // A start sent again is sent as it was kept; a new one as asked, the
    // cheapest size when none was.
    let price = priced(
        &prices,
        env,
        again.as_ref().map(|a| a.cores).or(asked.cores),
        asked.unread.filter(|_| again.is_none()),
    )?;
    let region = match (&again, asked.region) {
        (Some(again), _) => again.region.as_str(),
        (None, Region::Asked(region) | Region::Else(region)) => region,
    };
    let (question, note) = asking((app, name), asked, (&price, region), again.is_some());
    ask(asked, (&question, &note), confirm)?;
    // Read again after the yes, the starts first: a start or a server that
    // came meanwhile, from another run or another machine, sends nothing.
    let (open, record) = read_state(api, app, name).await?;
    let was = saved.as_ref().map(|s| s.key.clone());
    if decide(record.as_ref(), &open, saved, asked, app)? != plan {
        return Err(failed(t!("worker_server.changed", env)).hint(t!("worker_server.changed_hint")));
    }
    // What the yes was for, before anything is sent: a stop between the two
    // leaves it done and nothing bought.
    agreed()?;
    let key = match &again {
        Some(again) => StartKey::new(again.key.as_str()).map_err(|e| failed(e.to_string()))?,
        None => make_key()?,
    };
    // Kept before it is sent, as not to be sent again: an answer lost on
    // the way leaves the next run to read the account first.
    let before = again.as_ref().is_some_and(|a| a.resend);
    let mut start = Kept {
        key: key.as_str().to_owned(),
        cores: price.cores,
        region: region.to_owned(),
        resend: false,
    };
    keep_over(store, &file_key, &start, was.as_deref())
        .map_err(|error| failed(t!("worker_server.not_kept", error)))?;
    let body = StartServer::new(price.cores, region).at_revision(revision);
    match api.start(name, env, &key, &body).await {
        Ok(written) => Ok(done(
            (store, &file_key, key.as_str()),
            env,
            &written.record,
            Some(again.is_some()),
        )),
        Err(e) => {
            let then = after(&e);
            let fate = match then {
                After::Gone => let_go(store, &file_key, key.as_str()).map(|()| KeyFate::LetGo),
                After::Again => {
                    start.resend = true;
                    keep_over(store, &file_key, &start, Some(key.as_str()))
                        .map(|()| KeyFate::KeptAgain)
                }
                After::AsItWas => {
                    start.resend = before;
                    keep_over(store, &file_key, &start, Some(key.as_str())).map(|()| {
                        if before {
                            KeyFate::KeptAgain
                        } else {
                            KeyFate::KeptHeld
                        }
                    })
                }
                // Kept already, as not to be sent again.
                After::Held => Ok(KeyFate::KeptHeld),
            }
            .unwrap_or_else(KeyFate::Unkept);
            Err(refused(&e, then, name, app, &fate))
        }
    }
}

/// The refusal of an environment `erpc.toml` keeps.
fn kept_in_erpc_toml(m: &erpc_worker::manifest::Manifest, app: &App) -> Result<(), CliError> {
    if kept::kept_there(m, &app.env) {
        Ok(())
    } else {
        Err(CliError::new(
            Code::Usage,
            t!("worker_server.in_erpc_toml", env = app.env.as_str()),
        )
        .hint(t!("worker_server.in_erpc_toml_hint", scope = app.scope())))
    }
}

async fn run(
    json: bool,
    app: &App,
    (cores, region, yes): (u16, &str, bool),
) -> Result<(Value, String), CliError> {
    let (_, m) = crate::worker::load(&app.dir)?;
    kept_in_erpc_toml(&m, app)?;
    let signed = kept::Signed::open().await?;
    let store = crate::account::session::beside_config(FILE).map_err(failed)?;
    let asked = Asked {
        cores: Some(cores),
        unread: None,
        region: Region::Asked(region),
        yes,
        json,
        terminal: crate::account::session::has_terminal(),
        by: By::ServerStart,
    };
    let making = Making {
        chain: m.chain.as_str(),
        template: m.template.as_deref(),
        wallet: crate::worker::move_account::wallet_of(&m)?,
    };
    run_with(
        &signed,
        app,
        &m.name,
        &store,
        (&making, &asked),
        (crate::node::common::confirm, || Ok(())),
        new_key,
    )
    .await
}

/// The start the first `erpc worker deploy` makes, through the signed-in
/// `signed`, for environment `app.env` of `m`: in `region`, at the
/// cheapest size the account offers (a start kept here is sent again as
/// it was kept), after a yes at the terminal (`yes` says the price on
/// stderr instead). `agreed` runs after the yes, before the start is sent.
/// What the account then keeps of the environment, said.
pub(crate) async fn for_deploy(
    signed: &kept::Signed,
    app: &App,
    m: &erpc_worker::manifest::Manifest,
    (region, yes, size): (Region<'_>, bool, Size<'_>),
    agreed: impl FnOnce() -> Result<(), CliError>,
) -> Result<String, CliError> {
    let store = crate::account::session::beside_config(FILE).map_err(failed)?;
    let (cores, unread) = match size {
        Size::Cheapest => (None, None),
        Size::Cores(cores) => (Some(cores), None),
        Size::Unread(plan) => (None, Some(plan)),
    };
    let asked = Asked {
        cores,
        unread,
        region,
        yes,
        json: false,
        terminal: true,
        by: By::Deploy,
    };
    let making = Making {
        chain: m.chain.as_str(),
        template: m.template.as_deref(),
        wallet: crate::worker::move_account::wallet_of(m)?,
    };
    run_with(
        signed,
        app,
        &m.name,
        &store,
        (&making, &asked),
        (crate::node::common::confirm, agreed),
        new_key,
    )
    .await
    .map(|(_, text)| text)
}

/// Whether a start this machine kept for environment `app.env` of the app
/// named `name`, through the signed-in `signed`, is one the account said
/// to send again under its key.
pub(crate) async fn kept_to_send_again(
    signed: &kept::Signed,
    app: &App,
    name: &str,
) -> Result<bool, CliError> {
    let uid = Buying::uid(signed).await?;
    let store = crate::account::session::beside_config(FILE).map_err(failed)?;
    kept_resendable(&store, &kept::pin_key(&uid, name, &app.env))
}

/// Whether the start kept in `store` under `file_key` is one the account
/// said to send again under its key.
fn kept_resendable(store: &Path, file_key: &str) -> Result<bool, CliError> {
    let saved =
        kept_start(store, file_key).map_err(|error| failed(t!("worker_server.not_read", error)))?;
    Ok(saved.is_some_and(|s| s.resend))
}

/// `erpc worker server start`.
pub(crate) async fn start(json: bool, app: &App, cores: u16, region: &str, yes: bool) -> Outcome {
    match run(json, app, (cores, region, yes)).await {
        Ok((answer, text)) => crate::worker::remote::done(json, &answer, text),
        Err(e) => e.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;

    use erpc_worker::manifest::Manifest;
    use serde_json::json;

    use super::*;
    use crate::worker::account::stand_in::refused;

    const SERVER_ID: &str = "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60";
    const START_ID: &str = "5d1e2f3a-4b5c-4d6e-8f70-819a2b3c4d5e";
    const OLD_KEY: &str = "0123456789abcdef0123456789abcdef";
    const NEW_KEY: &str = "fedcba9876543210fedcba9876543210";
    const OTHER_KEY: &str = "00112233445566778899aabbccddeeff";
    const MAKING: Making<'static> = Making {
        chain: "solana",
        template: Some("solana/hello@1"),
        wallet: None,
    };

    fn env_record(servers: &Value) -> EnvDetail {
        serde_json::from_value(json!({
            "name": "prod", "revision": 1, "factsFormat": 2,
            "facts": { "desiredCores": null, "host": null, "sshUser": null, "sshPort": null,
                "hostKey": null, "firewall": { "sshAllow": [], "appAllow": [] }, "starting": {},
                "backup": null },
            "servers": servers, "desiredCores": null, "activeCores": null, "coreOptions": [],
            "lines": [], "refStates": { "backup": null }, "deployed": null, "deployedApp": null,
            "updatedAt": "2026-11-24T12:00:00.000Z"
        }))
        .expect("an environment")
    }

    fn empty() -> EnvDetail {
        env_record(&json!([]))
    }

    fn holding() -> EnvDetail {
        env_record(
            &json!([{ "id": SERVER_ID, "slot": "active", "cores": 1, "memoryGb": 2,
            "region": "amsterdam", "hourly": true, "appRunning": false,
            "state": "provisioning" }]),
        )
    }

    fn app_record(chain: &str) -> account::App {
        serde_json::from_value(json!({ "id": "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13",
            "name": "bot", "chain": chain, "template": "solana/hello@1", "wallet": null,
            "revision": 1 }))
        .expect("an app")
    }

    /// How the stand-in answers the start.
    enum Answer {
        Started,
        Refused(u16, &'static str, Value),
        Silent,
        SignedOut,
    }

    /// A start as sent: its key, cores and region, and what this machine
    /// kept then.
    type Sent = (String, u16, String, Option<Kept>);

    /// The account, in memory: what it has, and how it answers the start.
    #[allow(
        clippy::struct_excessive_bools,
        reason = "a stand-in's switches, one for each case it plays"
    )]
    struct Fake {
        app: RefCell<Option<account::App>>,
        env: RefCell<Option<EnvDetail>>,
        open: RefCell<Vec<Open>>,
        prices: Value,
        answer: Answer,
        /// The message the account's refusal carries.
        message: Option<&'static str>,
        store: PathBuf,
        /// A start that is open at the first read of the account closes
        /// right after it, its server then on the record.
        closes_after_first_read: bool,
        /// A server comes on the record while the person is asked.
        comes_while_asked: bool,
        /// Another start opens while the person is asked.
        opens_while_asked: bool,
        /// The call the account refuses, by its name in `calls`, with this
        /// status and code (none: no code, as from in front of the routes).
        refuse: Option<(&'static str, u16, Option<&'static str>)>,
        /// Another run of the command on this machine keeps its own start
        /// at this call: `prices` (while the person is asked) or `start`.
        other_run_keeps: Option<&'static str>,
        /// The record of starts breaks while the start is sent: `garbage`
        /// (it cannot be read) or `shut` (its directory cannot be written).
        breaks_store: Option<&'static str>,
        /// The environment's revision moves (no server, no start) while the
        /// person is asked.
        revision_moves_while_asked: bool,
        /// The revision each start was sent at.
        revisions: RefCell<Vec<Option<u64>>>,
        reads: Cell<u32>,
        calls: RefCell<Vec<&'static str>>,
        /// Each start as sent: its key, cores and region, and what this
        /// machine kept then.
        sent: RefCell<Vec<Sent>>,
        /// Each app record made, as sent.
        made: RefCell<Vec<Value>>,
    }

    impl Fake {
        fn new(dir: &tempfile::TempDir) -> Self {
            Self {
                app: RefCell::new(Some(app_record("solana"))),
                env: RefCell::new(Some(empty())),
                open: RefCell::new(Vec::new()),
                prices: json!({ "currency": "eur", "options": [
                    { "cores": 1, "memoryGb": 2, "hourlyCents": 7 },
                    { "cores": 2, "memoryGb": 4, "hourlyCents": 13 },
                    { "cores": 4, "memoryGb": 16, "hourlyCents": 120 }
                ] }),
                answer: Answer::Started,
                message: None,
                store: dir.path().join(FILE),
                closes_after_first_read: false,
                comes_while_asked: false,
                opens_while_asked: false,
                refuse: None,
                other_run_keeps: None,
                breaks_store: None,
                revision_moves_while_asked: false,
                revisions: RefCell::new(Vec::new()),
                reads: Cell::new(0),
                calls: RefCell::new(Vec::new()),
                sent: RefCell::new(Vec::new()),
                made: RefCell::new(Vec::new()),
            }
        }

        fn kept(&self) -> Option<Kept> {
            kept_start(&self.store, &file_key()).expect("readable")
        }

        fn keep(&self, key: &str, resend: bool) {
            let start = Kept {
                key: key.to_owned(),
                cores: 1,
                region: "amsterdam".to_owned(),
                resend,
            };
            keep(&self.store, &file_key(), Some(&start)).expect("kept");
        }

        fn starts(&self) -> usize {
            self.calls
                .borrow()
                .iter()
                .filter(|c| **c == "start")
                .count()
        }

        /// After the first read: a start open then closes, its server on
        /// the record.
        fn read(&self) {
            self.reads.set(self.reads.get() + 1);
            if self.closes_after_first_read && self.reads.get() == 1 {
                self.open.borrow_mut().clear();
                *self.env.borrow_mut() = Some(holding());
            }
        }

        /// The refusal of `call`, when it is the one refused.
        fn refuses(&self, call: &str) -> Result<(), WorkerError> {
            match self.refuse {
                Some((refused, 401, _)) if refused == call => {
                    Err(WorkerError::Api(erpc_api::ApiError::Unauthorized))
                }
                Some((refused, status, code)) if refused == call => {
                    Err(WorkerError::Refused(account::Refusal {
                        status,
                        code: code.map(AccountCode::from),
                        message: self.message.map(str::to_owned),
                        data: Value::Null,
                    }))
                }
                _ => Ok(()),
            }
        }

        /// Another run's start, kept here at `call` when it is the one.
        fn other_run(&self, call: &str) {
            if self.other_run_keeps == Some(call) {
                let theirs = Kept {
                    key: OTHER_KEY.to_owned(),
                    cores: 2,
                    region: "tokyo".to_owned(),
                    resend: false,
                };
                keep(&self.store, &file_key(), Some(&theirs)).expect("kept");
            }
        }

        fn refusal(&self, status: u16, code: &str, data: Value) -> WorkerError {
            match refused(status, code, data) {
                WorkerError::Refused(mut r) => {
                    r.message = self.message.map(str::to_owned);
                    WorkerError::Refused(r)
                }
                other => other,
            }
        }
    }

    fn file_key() -> String {
        kept::pin_key("user-100001", "bot", "prod")
    }

    fn server_start(cores: u16, region: &str) -> Open {
        Open {
            id: START_ID.to_owned(),
            server: true,
            cores: Some(cores),
            region: Some(region.to_owned()),
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the stand-in answers at once; the account it stands in for is awaited"
    )]
    impl Buying for Fake {
        async fn uid(&self) -> Result<String, CliError> {
            Ok("user-100001".to_owned())
        }

        async fn app(&self, _: &str) -> Result<account::App, WorkerError> {
            self.calls.borrow_mut().push("app");
            self.refuses("app")?;
            self.app
                .borrow()
                .clone()
                .ok_or_else(|| refused(404, "worker_not_found", Value::Null))
        }

        async fn env(&self, _: &str, _: &str) -> Result<EnvDetail, WorkerError> {
            self.calls.borrow_mut().push("env");
            self.refuses("env")?;
            let env = self.env.borrow().clone();
            self.read();
            env.ok_or_else(|| refused(404, "env_not_found", Value::Null))
        }

        async fn put_app(
            &self,
            _: &str,
            body: &PutApp,
        ) -> Result<Written<account::App>, WorkerError> {
            self.calls.borrow_mut().push("put_app");
            self.refuses("put_app")?;
            self.made
                .borrow_mut()
                .push(serde_json::to_value(body).expect("encodes"));
            *self.app.borrow_mut() = Some(app_record("solana"));
            Ok(Written::new(true, app_record("solana")))
        }

        async fn put_env(
            &self,
            _: &str,
            _: &str,
            body: &PutEnv,
        ) -> Result<Written<EnvDetail>, WorkerError> {
            self.calls.borrow_mut().push("put_env");
            self.refuses("put_env")?;
            assert_eq!(body.expected_revision, 0);
            assert_eq!(body.facts, Facts::default());
            let mut made = empty();
            made.revision = 7;
            *self.env.borrow_mut() = Some(made.clone());
            Ok(Written::new(true, made))
        }

        async fn prices(&self, _: &str, _: &str) -> Result<ServerPrices, WorkerError> {
            self.calls.borrow_mut().push("prices");
            self.refuses("prices")?;
            self.other_run("prices");
            if self.comes_while_asked {
                *self.env.borrow_mut() = Some(holding());
            }
            if self.opens_while_asked {
                *self.open.borrow_mut() = vec![server_start(2, "tokyo")];
            }
            if self.revision_moves_while_asked
                && let Some(env) = self.env.borrow_mut().as_mut()
            {
                env.revision += 1;
            }
            Ok(serde_json::from_value(self.prices.clone()).expect("prices"))
        }

        async fn starts(&self, _: &str, _: &str) -> Result<Vec<Open>, WorkerError> {
            self.calls.borrow_mut().push("starts");
            self.refuses("starts")?;
            if self.env.borrow().is_none() {
                return Err(refused(404, "env_not_found", Value::Null));
            }
            let open = self.open.borrow().clone();
            self.read();
            Ok(open)
        }

        async fn start(
            &self,
            _: &str,
            _: &str,
            key: &StartKey,
            body: &StartServer,
        ) -> Result<Written<EnvDetail>, WorkerError> {
            self.calls.borrow_mut().push("start");
            self.revisions.borrow_mut().push(body.expected_revision);
            self.other_run("start");
            self.sent.borrow_mut().push((
                key.as_str().to_owned(),
                body.cores,
                body.region.clone(),
                self.kept(),
            ));
            match self.breaks_store {
                Some("garbage") => std::fs::write(&self.store, "not json").expect("written"),
                #[cfg(unix)]
                Some("shut") => set_mode(self.store.parent().expect("a directory"), 0o500),
                _ => {}
            }
            match &self.answer {
                Answer::Started => Ok(Written::new(true, holding())),
                Answer::Refused(status, code, data) => {
                    Err(self.refusal(*status, code, data.clone()))
                }
                Answer::Silent => Err(WorkerError::Api(erpc_api::ApiError::Malformed(
                    "no answer".to_owned(),
                ))),
                Answer::SignedOut => Err(WorkerError::Api(erpc_api::ApiError::Unauthorized)),
            }
        }
    }

    fn asked(cores: u16, yes: bool, json: bool, terminal: bool) -> Asked<'static> {
        Asked {
            cores: Some(cores),
            unread: None,
            region: Region::Asked("amsterdam"),
            by: By::ServerStart,
            yes,
            json,
            terminal,
        }
    }

    /// The start through `fake`, a person at the terminal answering
    /// `say_yes`; with the question they were asked, if any.
    async fn go(
        fake: &Fake,
        asked: &Asked<'_>,
        making: &Making<'_>,
        say_yes: bool,
    ) -> (Result<(Value, String), CliError>, Option<String>) {
        let question = RefCell::new(None);
        let app = App::at(fake.store.parent().expect("a directory"), "prod");
        let out = run_with(
            fake,
            &app,
            "bot",
            &fake.store,
            (making, asked),
            (
                |q: &str| {
                    *question.borrow_mut() = Some(q.to_owned());
                    Ok(say_yes)
                },
                || Ok(()),
            ),
            || Ok(StartKey::new(NEW_KEY).expect("a key")),
        )
        .await;
        (out, question.into_inner())
    }

    /// What the first deploy asks: the cheapest size, a region not asked
    /// for (`region`), and `yes`.
    fn by_deploy(region: Region<'static>, yes: bool) -> Asked<'static> {
        Asked {
            cores: None,
            unread: None,
            region,
            yes,
            json: false,
            terminal: true,
            by: By::Deploy,
        }
    }

    /// The start as the first deploy makes it through `fake`, the person
    /// answering `say_yes`, `agreed` said as a call (`"agreed"`) and
    /// refused when `agreed_fails`; with the question asked, if any.
    async fn go_deploy(
        fake: &Fake,
        asked: &Asked<'_>,
        say_yes: bool,
        agreed_fails: bool,
    ) -> (Result<(Value, String), CliError>, Option<String>) {
        let question = RefCell::new(None);
        let app = App::at(fake.store.parent().expect("a directory"), "prod");
        let out = run_with(
            fake,
            &app,
            "bot",
            &fake.store,
            (&MAKING, asked),
            (
                |q: &str| {
                    *question.borrow_mut() = Some(q.to_owned());
                    Ok(say_yes)
                },
                || {
                    fake.calls.borrow_mut().push("agreed");
                    if agreed_fails {
                        Err(failed("erpc.toml could not be written".to_owned()))
                    } else {
                        Ok(())
                    }
                },
            ),
            || Ok(StartKey::new(NEW_KEY).expect("a key")),
        )
        .await;
        (out, question.into_inner())
    }

    #[tokio::test]
    async fn the_first_deploy_starts_the_cheapest_size_near_and_agrees_after_the_yes_before_the_start()
     {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        // Offered most expensive first: the cheapest is still the one.
        fake.prices = json!({ "currency": "eur", "options": [
            { "cores": 4, "memoryGb": 16, "hourlyCents": 120 },
            { "cores": 2, "memoryGb": 4, "hourlyCents": 13 },
            { "cores": 1, "memoryGb": 2, "hourlyCents": 7 }
        ] });
        let (out, question) =
            go_deploy(&fake, &by_deploy(Region::Else("tokyo"), false), true, false).await;
        out.expect("started");
        let question = question.expect("asked");
        assert!(
            question.contains(
                "Run bot on a new ERPC Worker (1 vCPU, 2 GB memory) in your ERPC account"
            ) && question.contains("€0.07")
                && question.contains("tokyo")
                && question.contains("`account = true`"),
            "{question}"
        );
        assert_eq!(
            *fake.calls.borrow(),
            [
                "app", "starts", "env", "prices", "starts", "env", "agreed", "start"
            ]
        );
        let sent = fake.sent.borrow();
        assert_eq!((sent[0].1, sent[0].2.as_str()), (1, "tokyo"));
    }

    #[tokio::test]
    async fn the_first_deploy_agrees_to_nothing_on_a_no_and_sends_nothing_when_agreeing_fails() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let (out, _) = go_deploy(
            &fake,
            &by_deploy(Region::Else("tokyo"), false),
            false,
            false,
        )
        .await;
        assert_eq!(out.expect_err("declined").code, Code::Declined);
        assert!(!fake.calls.borrow().contains(&"agreed"));
        let (out, _) = go_deploy(&fake, &by_deploy(Region::Else("tokyo"), true), true, true).await;
        let e = out.expect_err("not agreed");
        assert!(e.message.contains("erpc.toml"), "{}", e.message);
        assert_eq!(fake.starts(), 0);
        assert_eq!(fake.kept(), None);
    }

    #[tokio::test]
    async fn the_first_deploy_sends_a_kept_start_again_as_it_was_kept() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        // Kept as a 2-core server in amsterdam (not the cheapest size, which
        // a first deploy asks for), which the account asked to send again;
        // this machine is near tokyo now.
        *fake.open.borrow_mut() = vec![server_start(2, "amsterdam")];
        let kept = Kept {
            key: OLD_KEY.to_owned(),
            cores: 2,
            region: "amsterdam".to_owned(),
            resend: true,
        };
        keep(&fake.store, &file_key(), Some(&kept)).expect("kept");
        let (out, _) = go_deploy(
            &fake,
            &by_deploy(Region::Asked("frankfurt"), true),
            true,
            false,
        )
        .await;
        let e = out.expect_err("differs");
        assert_eq!(e.code, Code::Usage);
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("`erpc worker deploy --env prod") && hint.contains("--region amsterdam"),
            "{hint}"
        );
        assert_eq!(fake.starts(), 0);
        // At the price of its own size, asked at the terminal.
        let (out, question) =
            go_deploy(&fake, &by_deploy(Region::Else("tokyo"), false), true, false).await;
        out.expect("sent again");
        let question = question.expect("asked");
        assert!(
            question.contains("ERPC Worker (2 vCPU, 4 GB memory)") && question.contains("€0.13"),
            "{question}"
        );
        assert!(!question.contains("€0.07"), "{question}");
        let sent = fake.sent.borrow();
        assert_eq!(
            (sent[0].0.as_str(), sent[0].1, sent[0].2.as_str()),
            (OLD_KEY, 2, "amsterdam")
        );
    }

    #[tokio::test]
    async fn two_first_deploys_whose_first_answer_was_lost_send_one_start() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.answer = Answer::Silent;
        let (out, _) = go_deploy(&fake, &by_deploy(Region::Else("tokyo"), true), true, false).await;
        out.expect_err("no answer");
        assert!(fake.kept().is_some(), "the key stays");
        // It went through: the server is on the record now.
        *fake.env.borrow_mut() = Some(holding());
        let (out, _) = go_deploy(&fake, &by_deploy(Region::Else("tokyo"), true), true, false).await;
        let (answer, _) = out.expect("done before");
        assert_eq!(answer["already"], true);
        assert_eq!(fake.starts(), 1);
        assert_eq!(fake.kept(), None);
        // A record with a server and no start kept here starts nothing, and
        // says how a deploy reaches it.
        let (out, _) = go_deploy(&fake, &by_deploy(Region::Else("tokyo"), true), true, false).await;
        let e = out.expect_err("holds");
        assert!(
            e.hint
                .unwrap_or_default()
                .contains("`account = true` under [env.prod]"),
            "{}",
            e.message
        );
        assert_eq!(fake.starts(), 1);
    }

    #[tokio::test]
    async fn a_start_is_asked_with_its_price_kept_before_it_is_sent_and_let_go_once_done() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let (out, question) = go(&fake, &asked(1, false, false, true), &MAKING, true).await;
        let (answer, text) = out.expect("started");
        let question = question.expect("asked");
        assert!(
            question.contains("€0.07")
                && question.contains("Start a new ERPC Worker (1 vCPU, 2 GB memory)"),
            "{question}"
        );
        assert!(question.contains("amsterdam"), "{question}");
        assert!(
            question.contains("charged by the hour until it is ended, one hour at the least"),
            "{question}"
        );
        assert!(
            question.contains("`erpc worker delete --release-server --env prod"),
            "{question}"
        );
        // Read before the question, the starts first, and again after it.
        assert_eq!(
            *fake.calls.borrow(),
            ["app", "starts", "env", "prices", "starts", "env", "start"]
        );
        let kept_then = Kept {
            key: NEW_KEY.to_owned(),
            cores: 1,
            region: "amsterdam".to_owned(),
            resend: false,
        };
        assert_eq!(
            *fake.sent.borrow(),
            [(
                NEW_KEY.to_owned(),
                1,
                "amsterdam".to_owned(),
                Some(kept_then)
            )]
        );
        assert_eq!(fake.kept(), None);
        assert_eq!(answer["started"], true);
        assert_eq!(answer["already"], false);
        assert!(text.contains("Started a new ERPC Worker"), "{text}");
    }

    #[tokio::test]
    async fn the_size_and_region_asked_for_are_the_ones_sent() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let frankfurt = Asked {
            region: Region::Asked("frankfurt"),
            ..asked(2, true, false, false)
        };
        let (out, _) = go(&fake, &frankfurt, &MAKING, true).await;
        out.expect("started");
        let sent = fake.sent.borrow();
        assert_eq!((sent[0].1, sent[0].2.as_str()), (2, "frankfurt"));
    }

    #[tokio::test]
    async fn declined_or_nobody_to_ask_sends_nothing_and_keeps_nothing() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let (out, _) = go(&fake, &asked(1, false, false, true), &MAKING, false).await;
        assert_eq!(out.expect_err("declined").code, Code::Declined);
        for (json, terminal) in [(true, true), (false, false), (true, false)] {
            let (out, question) = go(&fake, &asked(1, false, json, terminal), &MAKING, true).await;
            let e = out.expect_err("nobody");
            assert_eq!(e.code, Code::NeedsTerminal);
            assert!(
                e.message.contains("nobody can say yes here"),
                "{}",
                e.message
            );
            assert!(e.hint.unwrap_or_default().contains("without --json"));
            assert!(question.is_none());
        }
        assert_eq!(fake.starts(), 0);
        assert_eq!(fake.kept(), None);
    }

    #[tokio::test]
    async fn with_yes_the_price_is_said_on_stderr_instead_and_the_start_sent() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let _ = crate::node::common::heard::take_printed();
        let (out, question) = go(&fake, &asked(1, true, true, false), &MAKING, false).await;
        out.expect("started");
        assert!(question.is_none());
        // What the `--json` run printed, on its own.
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("€0.07")
                && printed.contains("charged by the hour until it is ended, one hour at the least"),
            "{printed}"
        );
        assert!(
            printed.contains("`erpc worker delete --release-server --env prod"),
            "{printed}"
        );
        assert_eq!(fake.starts(), 1);
        // At a terminal too, `--yes` asks nobody.
        let dir = tempfile::tempdir().expect("a directory");
        let at_terminal = Fake::new(&dir);
        let (out, question) = go(&at_terminal, &asked(1, true, false, true), &MAKING, false).await;
        out.expect("started");
        assert!(question.is_none());
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(printed.contains("€0.07"), "{printed}");
    }

    #[tokio::test]
    async fn a_record_that_names_a_server_or_an_address_or_is_older_starts_nothing() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.env.borrow_mut() = Some(holding());
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        assert!(
            out.expect_err("refused").message.contains("names a server"),
            "refused"
        );
        assert_eq!(*fake.calls.borrow(), ["app", "starts", "env"]);
        // An address and no server: refused the same.
        let mut own = empty();
        own.facts.host = Some("203.0.113.10".to_owned());
        *fake.env.borrow_mut() = Some(own);
        fake.calls.borrow_mut().clear();
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        assert!(
            out.expect_err("refused")
                .message
                .contains("names an address"),
            "refused"
        );
        assert_eq!(*fake.calls.borrow(), ["app", "starts", "env"]);
        // A record in an older form: refused.
        let mut older = empty();
        older.facts_format = 1;
        *fake.env.borrow_mut() = Some(older);
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        assert!(out.expect_err("older").message.contains("older"), "older");
        // With a start kept here and a server on record: it is done with,
        // and nothing is sent.
        *fake.env.borrow_mut() = Some(holding());
        fake.keep(OLD_KEY, false);
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let (answer, _) = out.expect("done");
        assert_eq!(answer["already"], true);
        assert_eq!(fake.kept(), None);
        assert_eq!(fake.starts(), 0);
    }

    #[tokio::test]
    async fn a_start_that_closes_between_the_reads_is_seen_and_no_other_is_made() {
        // The kept start was open when the starts were read, and closed
        // just after, its server then on the record: read in that order,
        // the record shows it, and no start is made.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        *fake.open.borrow_mut() = vec![server_start(1, "amsterdam")];
        fake.closes_after_first_read = true;
        fake.keep(OLD_KEY, false);
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        // Listed open still: not done with yet, and kept.
        assert!(out.expect_err("refused").message.contains(START_ID));
        assert_eq!(fake.starts(), 0);
        assert!(fake.kept().is_some());
        // The next run sees it closed, its server on the record: done.
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let (answer, _) = out.expect("done");
        assert_eq!(answer["already"], true);
        assert_eq!(fake.starts(), 0);
        assert_eq!(fake.kept(), None);
    }

    #[tokio::test]
    async fn what_changed_while_the_person_was_asked_sends_nothing() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.comes_while_asked = true;
        // A server another run started comes on the record: refused.
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        assert!(out.expect_err("refused").message.contains("names a server"));
        assert_eq!(fake.starts(), 0);
        // With a start kept here: what the account has changed.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.comes_while_asked = true;
        fake.keep(OLD_KEY, false);
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let e = out.expect_err("changed");
        assert!(
            e.message.contains("changed while this was asked"),
            "{}",
            e.message
        );
        assert_eq!(
            e.hint.unwrap_or_default(),
            "run the same command again: it reads the ERPC account first"
        );
        assert_eq!(fake.starts(), 0);
        // Another start that opens meanwhile: refused by it.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.opens_while_asked = true;
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        assert!(out.expect_err("open").message.contains("still open"));
        assert_eq!(fake.starts(), 0);
    }

    #[tokio::test]
    async fn a_refused_read_or_write_is_said_in_erpcs_words_and_nothing_is_started() {
        // The price refused as user-api refuses a route an erpc sign-in may
        // not reach yet: 403, no code, a message that sends the person to
        // the dashboard; and each other read and write refused the same.
        for (call, what) in [
            ("prices", "the price of a server start"),
            ("app", "app bot's record"),
            ("starts", "open starts"),
            ("env", "environment prod's record"),
            ("put_app", "app bot's record"),
            ("put_env", "environment prod's record"),
        ] {
            let dir = tempfile::tempdir().expect("a directory");
            let mut fake = Fake::new(&dir);
            if call.starts_with("put_") {
                *fake.app.borrow_mut() = None;
                *fake.env.borrow_mut() = None;
            }
            fake.refuse = Some((call, 403, None));
            fake.message =
                Some("This sign-in cannot make this request. Make it in the ERPC Dashboard");
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            let e = out.expect_err("refused");
            assert!(e.message.contains("(HTTP 403)"), "{call}: {}", e.message);
            assert!(e.message.contains(what), "{call}: {}", e.message);
            assert!(!e.message.contains("Dashboard"), "{call}: {}", e.message);
            assert_eq!(fake.starts(), 0, "{call}");
            assert_eq!(fake.kept(), None, "{call}");
        }
    }

    #[tokio::test]
    async fn a_read_refused_with_a_code_is_said_with_its_status_and_code() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.refuse = Some(("env", 429, Some("rate_limited")));
        fake.message = Some("Make it in the ERPC Dashboard");
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let e = out.expect_err("refused");
        assert!(
            e.message.contains("(HTTP 429, rate_limited)"),
            "{}",
            e.message
        );
        assert!(!e.message.contains("Dashboard"), "{}", e.message);
        assert_eq!(fake.starts(), 0);
    }

    #[tokio::test]
    async fn a_record_of_starts_that_breaks_after_the_answer_is_said_as_it_is() {
        // Unreadable after a start that went through: it is said started,
        // and that the record could not be updated (in `--json` too, as
        // `recordError`), never "nothing was started".
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.breaks_store = Some("garbage");
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let (answer, text) = out.expect("started");
        assert!(text.contains("Started a new ERPC Worker"), "{text}");
        assert!(text.contains("could not be updated"), "{text}");
        assert!(text.contains("the next run stops at it"), "{text}");
        assert!(!text.contains("nothing was started"), "{text}");
        assert!(
            answer["recordError"]
                .as_str()
                .is_some_and(|e| e.contains("could not be updated")),
            "{answer}"
        );
        // Unreadable after an answer to send it again: no promise to send
        // it again, and no word of the key kept.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.breaks_store = Some("garbage");
        fake.answer = Answer::Refused(
            409,
            "start_pending",
            json!({ "startId": START_ID, "retry": true }),
        );
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let e = out.expect_err("pending");
        assert!(e.message.contains("could not be updated"), "{}", e.message);
        assert!(!e.message.contains("nothing was started"), "{}", e.message);
        // The answer's own sentence says nothing of the key; the key's
        // sentence is the record's.
        let answer = e.message.lines().next().unwrap_or_default();
        assert!(!answer.contains("key"), "{}", e.message);
        assert!(
            !e.message.contains("keeps the start's key"),
            "{}",
            e.message
        );
        let hint = e.hint.unwrap_or_default();
        assert!(hint.contains("could not keep the mark"), "{hint}");
        assert!(hint.contains(START_ID), "{hint}");
        assert!(!hint.contains("it is sent again"), "{hint}");
        // Unreadable after an answer that lets the key go: no word of it
        // let go.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.breaks_store = Some("garbage");
        fake.answer = Answer::Refused(409, "start_pending", json!({ "startId": START_ID }));
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let e = out.expect_err("other open");
        assert!(e.message.contains("could not be updated"), "{}", e.message);
        assert!(!e.message.contains("let go"), "{}", e.message);
        assert!(!e.message.contains("key go"), "{}", e.message);
        #[cfg(unix)]
        {
            // Not writable after an answer to send it again: the same hint,
            // and the next run says it has no record of the account saying
            // so.
            let dir = tempfile::tempdir().expect("a directory");
            let shut = dir.path().join("shut");
            std::fs::create_dir(&shut).expect("a directory");
            let mut fake = Fake::new(&dir);
            fake.store = shut.join(FILE);
            fake.breaks_store = Some("shut");
            fake.answer = Answer::Refused(
                409,
                "start_pending",
                json!({ "startId": START_ID, "retry": true }),
            );
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            set_mode(&shut, 0o700);
            let e = out.expect_err("pending");
            assert!(
                e.hint
                    .unwrap_or_default()
                    .contains("could not keep the mark"),
                "{}",
                e.message
            );
            fake.breaks_store = None;
            *fake.open.borrow_mut() = vec![server_start(1, "amsterdam")];
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            let e = out.expect_err("not sent again");
            assert!(
                e.message
                    .contains("has no record that the ERPC account said to"),
                "{}",
                e.message
            );
            assert_eq!(fake.starts(), 1);
            // A record that names a server, with the start kept here, in a
            // directory that cannot be written the whole run: the warning,
            // in `--json` too, and no word of the key let go.
            let dir = tempfile::tempdir().expect("a directory");
            let shut = dir.path().join("shut");
            std::fs::create_dir(&shut).expect("a directory");
            let mut fake = Fake::new(&dir);
            fake.store = shut.join(FILE);
            *fake.env.borrow_mut() = Some(holding());
            fake.keep(OLD_KEY, false);
            set_mode(&shut, 0o500);
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            set_mode(&shut, 0o700);
            let (answer, text) = out.expect("done");
            assert!(text.contains("could not be updated"), "{text}");
            assert!(!text.contains("let"), "{text}");
            assert!(answer["recordError"].is_string(), "{answer}");
        }
    }

    #[tokio::test]
    async fn the_start_is_made_only_at_the_revision_read_before_the_price() {
        // The environment's record at revision 1: the start is sent at 1,
        // also when the revision moves while the person is asked.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.revision_moves_while_asked = true;
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        out.expect("started");
        assert_eq!(*fake.revisions.borrow(), [Some(1)]);
        // A kept start sent again while the revision moves: sent at the
        // revision read before the price too.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        *fake.open.borrow_mut() = vec![server_start(1, "amsterdam")];
        fake.keep(OLD_KEY, true);
        fake.revision_moves_while_asked = true;
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        out.expect("started");
        assert_eq!(fake.sent.borrow()[0].0, OLD_KEY);
        assert_eq!(*fake.revisions.borrow(), [Some(1)]);
        // Records made first: at the revision the environment's was made at.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.env.borrow_mut() = None;
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        out.expect("started");
        assert_eq!(*fake.revisions.borrow(), [Some(7)]);
        // Refused as changed: said so, the hint to run it again, nothing
        // kept.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.answer = Answer::Refused(409, "revision_conflict", json!({ "currentRevision": 2 }));
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let e = out.expect_err("changed");
        assert!(e.message.contains("nothing was bought"), "{}", e.message);
        assert!(
            e.message.contains("changed after it was read"),
            "{}",
            e.message
        );
        assert_eq!(
            e.hint.unwrap_or_default(),
            "run the same command again: it reads the ERPC account first"
        );
        assert_eq!(fake.kept(), None);
    }

    #[tokio::test]
    async fn a_refused_session_on_a_read_is_said_with_the_login_hint() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.refuse = Some(("app", 401, None));
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let e = out.expect_err("signed out");
        assert_eq!(e.code, Code::NotSignedIn);
        assert!(e.hint.unwrap_or_default().contains("erpc login"));
        assert_eq!(fake.starts(), 0);
    }

    #[tokio::test]
    async fn the_price_said_is_the_one_of_the_size_asked_for() {
        // 2 cores in frankfurt, at a terminal: not the first size listed.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let frankfurt = Asked {
            region: Region::Asked("frankfurt"),
            ..asked(2, false, false, true)
        };
        let (out, question) = go(&fake, &frankfurt, &MAKING, true).await;
        out.expect("started");
        let question = question.expect("asked");
        for words in ["ERPC Worker (2 vCPU, 4 GB memory)", "€0.13", "frankfurt"] {
            assert!(question.contains(words), "{words}: {question}");
        }
        assert!(!question.contains("€0.07"), "{question}");
        // 4 cores under --yes, at a price over a euro.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let _ = crate::node::common::heard::take_printed();
        let (out, _) = go(&fake, &asked(4, true, false, false), &MAKING, true).await;
        out.expect("started");
        let printed = crate::node::common::heard::take_printed().join("\n");
        for words in ["ERPC Worker (4 vCPU, 16 GB memory)", "€1.20"] {
            assert!(printed.contains(words), "{words}: {printed}");
        }
        assert!(!printed.contains("€0.07"), "{printed}");
    }

    #[tokio::test]
    async fn a_server_on_record_while_the_kept_start_is_listed_open_keeps_it() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.env.borrow_mut() = Some(holding());
        *fake.open.borrow_mut() = vec![server_start(1, "amsterdam")];
        fake.keep(OLD_KEY, true);
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let e = out.expect_err("refused");
        assert!(
            e.message
                .contains("names a server, and a start of environment prod is still open"),
            "{}",
            e.message
        );
        assert!(!e.message.contains("another start"), "{}", e.message);
        assert!(
            e.message.contains("may yet buy what it was for"),
            "{}",
            e.message
        );
        assert!(e.hint.unwrap_or_default().contains(START_ID));
        assert_eq!(
            fake.kept().map(|k| (k.key, k.resend)),
            Some((OLD_KEY.to_owned(), true))
        );
        assert_eq!(fake.starts(), 0);
    }

    #[tokio::test]
    async fn another_runs_kept_start_is_not_written_over_or_let_go() {
        // Kept while the person is asked: nothing is kept or sent.
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.other_run_keeps = Some("prices");
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        assert!(out.expect_err("not kept").message.contains("another run"));
        assert_eq!(fake.starts(), 0);
        assert_eq!(fake.kept().map(|k| k.key), Some(OTHER_KEY.to_owned()));
        // Kept while this start is sent: it stays after a start that went
        // through, and after one refused before anything was bought.
        for answer in [
            Answer::Started,
            Answer::Refused(409, "OUT_OF_STOCK", Value::Null),
            Answer::Refused(
                409,
                "start_pending",
                json!({ "startId": START_ID, "retry": true }),
            ),
            Answer::Refused(429, "rate_limited", Value::Null),
        ] {
            let dir = tempfile::tempdir().expect("a directory");
            let mut fake = Fake::new(&dir);
            fake.other_run_keeps = Some("start");
            fake.answer = answer;
            let _ = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            assert_eq!(fake.starts(), 1);
            assert_eq!(fake.kept().map(|k| k.key), Some(OTHER_KEY.to_owned()));
        }
    }

    #[tokio::test]
    async fn an_open_start_stops_any_other() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.open.borrow_mut() = vec![server_start(1, "amsterdam")];
        // None kept here, or one kept and not to be sent again.
        for kept_here in [None, Some(false)] {
            if let Some(resend) = kept_here {
                fake.keep(OLD_KEY, resend);
            }
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            let e = out.expect_err("refused");
            assert!(e.message.contains(START_ID), "{}", e.message);
            assert_eq!(
                e.message
                    .contains("has no record that the ERPC account said to"),
                kept_here.is_some(),
                "{}",
                e.message
            );
            assert!(e.hint.unwrap_or_default().contains(START_ID));
            assert_eq!(fake.kept().map(|k| k.resend), kept_here);
        }
        // Kept to be sent again, while another start is open beside it.
        fake.keep(OLD_KEY, true);
        *fake.open.borrow_mut() = vec![
            server_start(1, "amsterdam"),
            Open {
                id: START_ID.to_owned(),
                server: false,
                cores: None,
                region: None,
            },
        ];
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let e = out.expect_err("refused");
        assert!(e.message.contains("while another start"), "{}", e.message);
        // Kept to be sent again, the start open being of another size or
        // region, or not a server's.
        for open in [
            server_start(2, "amsterdam"),
            server_start(1, "frankfurt"),
            Open {
                id: START_ID.to_owned(),
                server: false,
                cores: Some(1),
                region: Some("amsterdam".to_owned()),
            },
        ] {
            *fake.open.borrow_mut() = vec![open];
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            out.expect_err("refused");
        }
        // A line's start alone, with nothing kept here.
        keep(&fake.store, &file_key(), None).expect("let go");
        *fake.open.borrow_mut() = vec![Open {
            id: START_ID.to_owned(),
            server: false,
            cores: None,
            region: None,
        }];
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        out.expect_err("refused");
        assert_eq!(fake.starts(), 0);
    }

    #[tokio::test]
    async fn a_kept_start_the_account_asked_for_again_is_sent_again_under_its_key() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.open.borrow_mut() = vec![server_start(1, "amsterdam")];
        fake.keep(OLD_KEY, true);
        // Asked for another size, or another region: nothing is sent.
        let frankfurt = Asked {
            region: Region::Asked("frankfurt"),
            ..asked(1, true, false, false)
        };
        for other in [asked(2, true, false, false), frankfurt] {
            let (out, _) = go(&fake, &other, &MAKING, true).await;
            let e = out.expect_err("differs");
            assert_eq!(e.code, Code::Usage);
            assert!(
                e.hint
                    .unwrap_or_default()
                    .contains("--cores 1 --region amsterdam")
            );
        }
        assert_eq!(fake.starts(), 0);
        let (out, question) = go(&fake, &asked(1, false, false, true), &MAKING, true).await;
        let (answer, _) = out.expect("started");
        assert!(
            question.unwrap_or_default().contains("under its own key"),
            "said"
        );
        assert_eq!(fake.sent.borrow()[0].0, OLD_KEY);
        assert_eq!(answer["sentAgain"], true);
        assert_eq!(fake.kept(), None);
    }

    #[tokio::test]
    async fn a_kept_start_the_account_has_no_trace_of_is_let_go_and_a_new_key_made() {
        for resend in [false, true] {
            let dir = tempfile::tempdir().expect("a directory");
            let fake = Fake::new(&dir);
            fake.keep(OLD_KEY, resend);
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            out.expect("started");
            assert_eq!(fake.sent.borrow()[0].0, NEW_KEY);
            assert_eq!(fake.kept(), None);
        }
    }

    #[test]
    fn only_a_start_kept_to_send_again_is_one_the_first_deploy_sends_past_the_stock() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        assert!(!kept_resendable(&fake.store, &file_key()).expect("read"));
        fake.keep(OLD_KEY, false);
        assert!(!kept_resendable(&fake.store, &file_key()).expect("read"));
        fake.keep(OLD_KEY, true);
        assert!(kept_resendable(&fake.store, &file_key()).expect("read"));
    }

    #[tokio::test]
    async fn a_plan_whose_name_gives_no_size_is_refused_with_the_sizes_offered() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let unread = Asked {
            cores: None,
            unread: Some("prod_vps_x"),
            ..asked(1, true, false, true)
        };
        let (out, question) = go(&fake, &unread, &MAKING, true).await;
        let e = out.expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        assert!(
            e.message
                .contains("the name of plan prod_vps_x gives no size")
                && e.message
                    .contains("ERPC Worker (1 vCPU, 2 GB memory), €0.07 an hour"),
            "{}",
            e.message
        );
        assert!(question.is_none());
        assert_eq!(fake.starts(), 0);
        // A start kept here to send again is sent as it was kept: the plan
        // asked does not refuse it.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.open.borrow_mut() = vec![server_start(1, "amsterdam")];
        fake.keep(OLD_KEY, true);
        let (out, _) = go(&fake, &unread, &MAKING, true).await;
        out.expect("sent again");
        assert_eq!(fake.sent.borrow()[0].0, OLD_KEY);
    }

    #[tokio::test]
    async fn an_out_of_stock_answer_is_marked_for_the_first_deploy() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        fake.answer = Answer::Refused(409, "OUT_OF_STOCK", Value::Null);
        let (out, _) = go(&fake, &asked(1, true, false, true), &MAKING, true).await;
        let e = out.expect_err("refused");
        assert!(super::out_of_stock(&e), "{e:?}");
        fake.answer = Answer::Refused(402, "insufficient_credit", Value::Null);
        let (out, _) = go(&fake, &asked(1, true, false, true), &MAKING, true).await;
        assert!(!super::out_of_stock(&out.expect_err("refused")));
    }

    #[tokio::test]
    async fn a_size_not_offered_or_not_priced_in_euros_starts_nothing() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut fake = Fake::new(&dir);
        let (out, _) = go(&fake, &asked(8, true, false, false), &MAKING, true).await;
        let e = out.expect_err("not offered");
        assert_eq!(e.code, Code::Usage);
        assert!(
            e.message.contains("ERPC Worker (8 vCPU) is not offered")
                && e.message
                    .contains("ERPC Worker (1 vCPU, 2 GB memory), €0.07 an hour")
                && e.message
                    .contains("ERPC Worker (2 vCPU, 4 GB memory), €0.13 an hour")
                && e.message
                    .contains("ERPC Worker (4 vCPU, 16 GB memory), €1.20 an hour"),
            "{}",
            e.message
        );
        fake.prices = json!({ "currency": "eur", "options": [] });
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        assert!(
            out.expect_err("none")
                .message
                .contains("offers no server start")
        );
        fake.prices = json!({ "currency": "usd",
            "options": [{ "cores": 1, "memoryGb": 2, "hourlyCents": 7 }] });
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        assert!(out.expect_err("currency").message.contains("usd"));
        assert_eq!(fake.starts(), 0);
        assert_eq!(fake.kept(), None);
    }

    /// Each answer to a start, with what stays kept here (none, or whether
    /// it is to be sent again), the exit status, and words of erpc's
    /// message.
    fn answers() -> Vec<(Answer, Option<bool>, Code, &'static str)> {
        let start = json!({ "startId": START_ID });
        // (answer, what stays kept here: none, or whether it is to be sent
        // again, the exit status, words of erpc's message)
        let mut cases = vec![
            (
                Answer::Refused(
                    409,
                    "start_pending",
                    json!({ "startId": START_ID, "retry": true }),
                ),
                Some(true),
                Code::Failed,
                "may have bought",
            ),
            (
                Answer::Refused(502, "purchase_unavailable", start.clone()),
                Some(true),
                Code::Failed,
                "may have bought",
            ),
            (
                Answer::Refused(409, "start_pending", start.clone()),
                None,
                Code::Failed,
                "another start",
            ),
            (
                Answer::Refused(409, "start_ended", Value::Null),
                None,
                Code::Failed,
                "was ended while",
            ),
            (
                Answer::Refused(
                    409,
                    "start_unsettled",
                    json!({ "startId": START_ID, "reason": "lookup_unavailable" }),
                ),
                Some(false),
                Code::Failed,
                "has not settled",
            ),
            (
                Answer::Refused(
                    409,
                    "start_unsettled",
                    json!({ "startId": START_ID, "reason": "start_mismatch" }),
                ),
                Some(false),
                Code::Failed,
                "has not put on",
            ),
            (
                Answer::Refused(409, "IDEMPOTENCY_CONFLICT", Value::Null),
                Some(false),
                Code::Failed,
                "is not known",
            ),
            (
                Answer::Refused(429, "rate_limited", Value::Null),
                Some(false),
                Code::Failed,
                "took no start",
            ),
            (
                Answer::Refused(500, "internal_error", Value::Null),
                Some(false),
                Code::Failed,
                "is not known",
            ),
            (
                Answer::Refused(409, "revision_conflict", json!({ "currentRevision": 2 })),
                None,
                Code::Failed,
                "changed after it was read for the price said",
            ),
            (Answer::Silent, Some(false), Code::Network, "is not known"),
            (
                Answer::SignedOut,
                Some(false),
                Code::NotSignedIn,
                "is not known",
            ),
        ];
        cases.extend(nothing_bought());
        cases
    }

    /// The answers given before anything is bought, each letting the key
    /// go.
    fn nothing_bought() -> Vec<(Answer, Option<bool>, Code, &'static str)> {
        let mut cases = Vec::new();
        for (status, code) in [
            (400, "invalid_request"),
            (409, "slot_occupied"),
            (402, "insufficient_credit"),
            (400, "PAYMENT_AUTH_REQUIRED"),
            (400, "billing_address_required"),
            (400, "purchase_refused"),
            (409, "OUT_OF_STOCK"),
            (409, "REGION_DOWN"),
            (409, "unsupported_for_account"),
            (404, "worker_not_found"),
            (404, "env_not_found"),
        ] {
            cases.push((
                Answer::Refused(status, code, Value::Null),
                None,
                Code::Failed,
                "did not start a server",
            ));
        }
        cases
    }

    #[tokio::test]
    async fn each_answer_lets_go_of_the_key_or_keeps_it() {
        for (answer, stays, exit, words) in answers() {
            let said = match &answer {
                Answer::Refused(status, code, _) => Some(format!("HTTP {status}, {code}")),
                _ => None,
            };
            let dir = tempfile::tempdir().expect("a directory");
            let mut fake = Fake::new(&dir);
            fake.answer = answer;
            // The account's own words are not passed on.
            fake.message = Some("end one of the lines and send the retry again");
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            let e = out.expect_err("refused");
            let what = format!("{}: {:?}", e.message, e.hint);
            assert_eq!(fake.kept().map(|k| k.resend), stays, "{what}");
            assert_eq!(e.code, exit, "{what}");
            assert!(e.message.contains(words), "{what}");
            let key = match stays {
                None => "let the start's key go",
                Some(true) => "to send it again under the same key",
                Some(false) => "does not send it again",
            };
            assert!(e.message.contains(key), "{what}");
            // The answer's own sentence says nothing of the key.
            let answer = e.message.lines().next().unwrap_or_default();
            assert!(!answer.contains("key"), "{what}");
            // Refused before anything is bought: no hint to run it again.
            if words == "did not start a server" {
                assert!(e.hint.is_none(), "{what}");
            }
            if let Some(said) = said {
                assert!(e.message.contains(&said), "{what}");
            }
            assert!(!what.contains("end one of the lines"), "{what}");
            if exit == Code::NotSignedIn {
                assert!(e.hint.unwrap_or_default().contains("erpc login"), "{what}");
            } else if stays == Some(false) && what.contains(START_ID) {
                assert!(e.hint.unwrap_or_default().contains(START_ID), "{what}");
            }
            assert_eq!(fake.starts(), 1, "{what}");
        }
    }

    #[tokio::test]
    async fn a_start_sent_again_stays_to_be_sent_again_only_while_the_account_says_so() {
        // (answer to the start sent again, whether it is to be sent again
        // after)
        for (answer, resend) in [
            (Answer::Refused(429, "rate_limited", Value::Null), true),
            (
                Answer::Refused(409, "start_unsettled", json!({ "startId": START_ID })),
                false,
            ),
            (Answer::Silent, false),
        ] {
            let dir = tempfile::tempdir().expect("a directory");
            let mut fake = Fake::new(&dir);
            *fake.open.borrow_mut() = vec![server_start(1, "amsterdam")];
            fake.keep(OLD_KEY, true);
            fake.answer = answer;
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            let e = out.expect_err("refused");
            let key = if resend {
                "to send it again under the same key"
            } else {
                "does not send it again"
            };
            assert!(e.message.contains(key), "{}", e.message);
            // Busy: the hint is to wait and run it again.
            if resend {
                assert!(
                    e.hint.unwrap_or_default().contains("wait a minute"),
                    "{}",
                    e.message
                );
            }
            assert_eq!(fake.sent.borrow()[0].0, OLD_KEY);
            assert_eq!(
                fake.kept().map(|k| (k.key, k.resend)),
                Some((OLD_KEY.to_owned(), resend))
            );
        }
    }

    #[tokio::test]
    async fn a_record_of_starts_that_cannot_be_read_or_kept_stops_it_before_anything_is_sent() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        std::fs::write(&fake.store, "not json").expect("written");
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        let e = out.expect_err("unreadable");
        assert!(e.message.contains("could not be read"), "{}", e.message);
        assert!(e.message.contains("nothing was started"), "{}", e.message);
        assert!(fake.calls.borrow().is_empty());
        // A directory nothing can be written in: the key is not kept, and
        // the start is not sent.
        #[cfg(unix)]
        {
            let shut = dir.path().join("shut");
            std::fs::create_dir(&shut).expect("a directory");
            let mut fake = Fake::new(&dir);
            fake.store = shut.join(FILE);
            set_mode(&shut, 0o500);
            let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
            set_mode(&shut, 0o700);
            assert!(
                out.expect_err("not kept")
                    .message
                    .contains("nothing was sent")
            );
            assert_eq!(fake.starts(), 0);
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set");
    }

    #[tokio::test]
    async fn under_yes_the_note_says_the_kept_start_is_sent_again() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.open.borrow_mut() = vec![server_start(1, "amsterdam")];
        fake.keep(OLD_KEY, true);
        let _ = crate::node::common::heard::take_printed();
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        out.expect("started");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(printed.contains("under its own key"), "{printed}");
    }

    #[test]
    fn only_the_start_under_its_own_key_is_let_go() {
        let dir = tempfile::tempdir().expect("a directory");
        let store = dir.path().join(FILE);
        let start = Kept {
            key: OLD_KEY.to_owned(),
            cores: 1,
            region: "amsterdam".to_owned(),
            resend: false,
        };
        keep(&store, &file_key(), Some(&start)).expect("kept");
        // Another run's start kept since: it stays.
        let_go(&store, &file_key(), NEW_KEY).expect("let go");
        assert_eq!(kept_start(&store, &file_key()).expect("read"), Some(start));
        let_go(&store, &file_key(), OLD_KEY).expect("let go");
        assert_eq!(kept_start(&store, &file_key()).expect("read"), None);
    }

    #[test]
    fn a_new_key_is_new_each_time_and_in_its_form() {
        let (a, b) = (new_key().expect("a key"), new_key().expect("a key"));
        assert_ne!(a.as_str(), b.as_str());
        for key in [a, b] {
            assert!(StartKey::new(key.as_str()).is_ok());
        }
    }

    #[tokio::test]
    async fn missing_records_are_made_first_and_only_when_someone_can_say_yes() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.app.borrow_mut() = None;
        *fake.env.borrow_mut() = None;
        // Nobody to say yes (`--json`, no terminal, or both): nothing is
        // made.
        for (json, terminal) in [(true, true), (false, false), (true, false)] {
            fake.calls.borrow_mut().clear();
            let (out, _) = go(&fake, &asked(1, false, json, terminal), &MAKING, true).await;
            assert_eq!(out.expect_err("nobody").code, Code::NeedsTerminal);
            assert_eq!(*fake.calls.borrow(), ["app"]);
        }
        // The app on record, the environment's missing: the same.
        *fake.app.borrow_mut() = Some(app_record("solana"));
        for (json, terminal) in [(true, true), (false, false), (true, false)] {
            fake.calls.borrow_mut().clear();
            let (out, _) = go(&fake, &asked(1, false, json, terminal), &MAKING, true).await;
            assert_eq!(out.expect_err("nobody").code, Code::NeedsTerminal);
            assert_eq!(*fake.calls.borrow(), ["app", "starts"]);
        }
        *fake.app.borrow_mut() = None;
        // Made, said, then priced, asked, read again and started.
        fake.calls.borrow_mut().clear();
        let _ = crate::node::common::heard::take_printed();
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        out.expect("started");
        assert_eq!(
            *fake.calls.borrow(),
            [
                "app", "put_app", "put_env", "prices", "starts", "env", "start"
            ]
        );
        assert_eq!(
            fake.made.borrow()[0],
            json!({ "expectedRevision": 0, "chain": "solana", "template": "solana/hello@1",
                    "wallet": null })
        );
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("Made app bot's record")
                && printed.contains("Made environment prod's record"),
            "{printed}"
        );
        // The app on record already: only the environment's is made.
        *fake.env.borrow_mut() = None;
        fake.calls.borrow_mut().clear();
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        out.expect("started");
        assert_eq!(
            *fake.calls.borrow(),
            [
                "app", "starts", "put_env", "prices", "starts", "env", "start"
            ]
        );
    }

    #[tokio::test]
    async fn an_app_of_another_chain_or_wallet_is_refused_and_a_wallet_apps_record_is_made() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.app.borrow_mut() = Some(app_record("ethereum"));
        let (out, _) = go(&fake, &asked(1, true, false, false), &MAKING, true).await;
        assert!(out.expect_err("other chain").message.contains("ethereum"));
        // erpc.toml names a wallet and the account has no record of the
        // app: it is made with the wallet's public side.
        let pubkey = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
        let wallet = Making {
            wallet: Some(
                PutWallet::new(pubkey, account::WalletSource::Keychain).expect("a public key"),
            ),
            ..MAKING
        };
        let dir2 = tempfile::tempdir().expect("a directory");
        let made = Fake::new(&dir2);
        *made.app.borrow_mut() = None;
        *made.env.borrow_mut() = None;
        let (out, _) = go(&made, &asked(1, true, false, false), &wallet, true).await;
        out.expect("started");
        let body = made.made.borrow()[0].clone();
        assert_eq!(body["wallet"]["pubkey"], pubkey);
        assert_eq!(body["wallet"]["sourceKind"], "keychain");
        // An app the account has with another wallet, or with one where
        // erpc.toml has none: refused, nothing made or started.
        let mut other = app_record("solana");
        other.wallet = serde_json::from_value(
            json!({ "pubkey": "11111111111111111111111111111111", "sourceKind": "keychain" }),
        )
        .expect("a wallet");
        for making in [&wallet, &MAKING] {
            *fake.app.borrow_mut() = Some(other.clone());
            fake.calls.borrow_mut().clear();
            let (out, _) = go(&fake, &asked(1, true, false, false), making, true).await;
            assert!(
                out.expect_err("another wallet")
                    .message
                    .contains("another wallet"),
            );
            assert_eq!(*fake.calls.borrow(), ["app"]);
        }
        // The same wallet: used as it is.
        let mut same = app_record("solana");
        same.wallet = serde_json::from_value(json!({ "pubkey": pubkey })).expect("a wallet");
        *fake.app.borrow_mut() = Some(same);
        *fake.env.borrow_mut() = None;
        fake.calls.borrow_mut().clear();
        let (out, _) = go(&fake, &asked(1, true, false, false), &wallet, true).await;
        out.expect("started");
        // A wallet app the account has on another chain: refused.
        *fake.app.borrow_mut() = Some(app_record("ethereum"));
        let (out, _) = go(&fake, &asked(1, true, false, false), &wallet, true).await;
        assert!(out.expect_err("other chain").message.contains("ethereum"));
        // The account has the app's record already: it is used as it is,
        // and the environment's is made.
        *fake.app.borrow_mut() = Some(app_record("solana"));
        *fake.env.borrow_mut() = None;
        fake.calls.borrow_mut().clear();
        let (out, _) = go(&fake, &asked(1, true, false, false), &wallet, true).await;
        out.expect("started");
        assert_eq!(
            *fake.calls.borrow(),
            [
                "app", "starts", "put_env", "prices", "starts", "env", "start"
            ]
        );
    }

    #[test]
    fn an_environment_erpc_toml_keeps_is_refused_by_name() {
        let app = App::at("apps/bot", "prod");
        let kept_there =
            Manifest::parse("name = \"bot\"\nchain = \"solana\"\n[env.prod]\naccount = true\n")
                .expect("a manifest");
        assert!(kept_in_erpc_toml(&kept_there, &app).is_ok());
        let here = Manifest::parse("name = \"bot\"\nchain = \"solana\"\n").expect("a manifest");
        let e = kept_in_erpc_toml(&here, &app).expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        assert!(e.hint.unwrap_or_default().contains("--new-server"));
    }
}
