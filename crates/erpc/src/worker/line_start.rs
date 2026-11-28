// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A data line asked on a first deploy, started in the ERPC account for the
//! environment once its server has an address (a gRPC or Shreds line lets
//! that address in; an Unlimited RPC is started in the server's region):
//! the account's line start, at the plan the hourly catalogue offers.
//!
//! The price said and asked is the hourly catalogue's for the plan: the
//! account's line start takes no price, and the line is charged its own. A
//! first deploy reads each line's plan before anything is made or bought
//! (a plan the catalogue does not offer is refused then), and asks each
//! line's price right after its server's, before the server is bought
//! ([`Owing`]; `--yes` says it on stderr): a no buys nothing. The lines
//! asked are kept on this machine (`worker_line_starts.json`, beside
//! erpc's config, 0600) until each is on the environment's record, so a
//! deploy that goes on from a stop starts them. A line is started only
//! after a yes in that run, or said under `--yes` (on a run again, only
//! with `--new-server`): one this run's own question agreed to at its
//! price is not asked again ([`Agreed`]); a run again that buys the server
//! asks every line to be started before it, those kept here too; one an
//! earlier run agreed to, started once the server is there, is asked once
//! more, at the catalogue's price now, and so is every other start of a
//! line. Every line is asked before any is sent. A no lets the line kept
//! here for it go; the deploy goes on without it, unless the app needs the
//! setting it gives, when the run stops, starting no line. A start kept
//! here under a key refuses a run that would buy the server
//! ([`Owing::refuse_kept_starts`]), and one the account said bought a line
//! it did not put on the record is never let go or replaced.
//!
//! Each start is sent under a key kept here before it is sent, as not to be
//! sent again, and the account's answer decides what becomes of it, as
//! [`erpc_api::worker::money`] says ([`after`]): a line on record, or an
//! answer that bought nothing (another start open, the line ended
//! meanwhile, among them), lets the key go, and the line stays asked; an
//! answer that says to send it again, or none, keeps it to be sent again
//! under the same key; any other (the start unsettled, whatever its
//! reason, a key the account had with another request, an answer this
//! version does not know) keeps it, never to be sent again. Each run reads
//! the account first ([`decide`]): a line of the kind on the record is used
//! as it is; every open start is looked at, and one of a kind erpc cannot
//! tell, two of the kind, or one that is not the start kept here to send
//! again, refuses the run; a start kept here that is not to be sent again,
//! once nothing of the kind is open or on record, is let go only after a
//! yes at a terminal, and a line started after it is a new purchase.
//!
//! Then the deploy waits for the line to be active with its endpoint, as
//! the deploy to an environment kept in the account takes no other.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use erpc_api::worker::money::{StartKey, StartLine, StartOf};
use erpc_api::worker::{self as account, Code as AccountCode, EnvDetail, WorkerError, Written};
use erpc_worker::manifest::LineKind;
use serde::{Deserialize, Serialize};

use crate::cli::error::{CliError, Code};
use crate::node::common::Say;
use crate::storage::clean;
use crate::worker::App;
use crate::worker::account as kept;

/// Where the lines asked and their starts are kept, beside erpc's config.
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

// ------------------------------------------------------ the lines kept here

/// A data line this machine keeps for an environment: asked for, and owed
/// (no key yet), then its start, under a key kept from before it is sent,
/// until the line is on the environment's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Kept {
    /// The plan, by product id.
    product_id: String,
    /// The plan's name in the hourly catalogue.
    name: String,
    /// Its price by the hour as it was last asked or said, in euros.
    price: String,
    /// Whether a yes to that price stands: from the yes until a start of
    /// the line is answered without the line.
    #[serde(default)]
    agreed: bool,
    /// The key of its start, kept before the start is sent; none while
    /// the line is owed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    /// The address a gRPC or Shreds line's start lets in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    /// The region of an Unlimited RPC's start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    /// Whether the account's last answer to the start said to send it again
    /// under the same key, or gave no answer.
    #[serde(default)]
    resend: bool,
    /// The start's id, when an answer named it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    start: Option<String>,
    /// The reason the account gave when it answered that the start is
    /// unsettled: `start_mismatch`, a line bought and not on the record,
    /// is never let go here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unsettled: Option<String>,
}

/// The reason of an unsettled start that bought a line the account did
/// not put on the environment's record.
const MISMATCH: &str = "start_mismatch";

impl Kept {
    /// A line owed at `plan`, a yes to its price standing or not.
    fn owed(plan: &Plan, agreed: bool) -> Self {
        Self {
            product_id: plan.id.clone(),
            name: plan.name.clone(),
            price: euros(plan),
            agreed,
            key: None,
            ip: None,
            region: None,
            resend: false,
            start: None,
            unsettled: None,
        }
    }

    /// Whether the account said this start bought a line it did not put
    /// on the record.
    fn mismatched(&self) -> bool {
        self.unsettled.as_deref() == Some(MISMATCH)
    }

    /// What its start sends: the same body every time.
    fn body(&self, kind: LineKind) -> StartLine {
        StartLine::new(
            account_kind(kind),
            self.product_id.clone(),
            self.ip.clone(),
            self.region.clone(),
        )
    }
}

/// A plan's price by the hour, in euros, as it is said: `0.1250`.
fn euros(plan: &Plan) -> String {
    format!("{:.4}", plan.cents / 100.0)
}

/// Where a line of `kind` is for, as said: the address a gRPC or Shreds
/// line lets in, the region of an Unlimited RPC.
fn place(kind: LineKind, (ip, region): (Option<&str>, Option<&str>)) -> String {
    match (kind, ip, region) {
        (LineKind::Grpc | LineKind::Shreds, Some(ip), _) => {
            t!("worker_first_deploy.line_for", ip = clean(ip))
        }
        (_, _, Some(region)) => t!("worker_first_deploy.line_in", region = clean(region)),
        _ => String::new(),
    }
}

/// The lines kept here, by the key of the account, app and environment
/// and the line's kind.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Starts {
    #[serde(default)]
    starts: BTreeMap<String, Kept>,
}

/// The lines kept in `path`; none when there is no file yet. A file that
/// cannot be read is an error, never an empty list: a start in it may have
/// bought a line.
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

/// Writes `starts` to `path`.
fn write(path: &Path, starts: &Starts) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(starts).map_err(|e| e.to_string())?;
    erpc_core::private_file::write(path, &text)
}

/// Keeps `line` in `path` under `file_key` (none: lets the one there go),
/// read and written under the lock, when what is there is still `was`:
/// what another run kept since is not written over, and the write refused.
fn put(path: &Path, file_key: &str, line: Option<&Kept>, was: Option<&Kept>) -> Result<(), String> {
    if line.is_none() && was.is_none() {
        return Ok(());
    }
    erpc_core::private_file::locked(path, || {
        let mut starts = load(path)?;
        if starts.starts.get(file_key) != was {
            return Err(t!("worker_first_deploy.line_kept_meanwhile"));
        }
        match line {
            Some(line) => {
                starts.starts.insert(file_key.to_owned(), line.clone());
            }
            None => {
                starts.starts.remove(file_key);
            }
        }
        write(path, &starts)
    })
}

/// Lets the line kept in `path` under `file_key` go when it is still
/// `was`, as once the line is on the environment's record; what another
/// run kept since stays.
fn forget(path: &Path, file_key: &str, was: &Kept) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    erpc_core::private_file::locked(path, || {
        let mut starts = load(path)?;
        if starts.starts.get(file_key) != Some(was) {
            return Ok(());
        }
        starts.starts.remove(file_key);
        write(path, &starts)
    })
}

/// Keeps each line of `lines` in `path` for the environment filed under
/// `pin`, owed, over what is kept for its kind unless that has a start's
/// key: that one stays, as it may have bought a line. An owed line kept
/// already stays as it is when `over` is false. With `fresh`, the lines
/// owed for the environment's other kinds go. Nothing is written when
/// nothing changes.
fn owe(
    path: &Path,
    pin: &str,
    lines: &[(LineKind, Kept)],
    (over, fresh): (bool, bool),
) -> Result<(), String> {
    if lines.is_empty() && !(fresh && path.exists()) {
        return Ok(());
    }
    erpc_core::private_file::locked(path, || {
        let mut starts = load(path)?;
        let mut changed = false;
        for (kind, line) in lines {
            let file_key = file_key(pin, *kind);
            match starts.starts.get(&file_key) {
                Some(there) if there.key.is_some() => {}
                Some(_) if !over => {}
                Some(there) if there == line => {}
                _ => {
                    starts.starts.insert(file_key, line.clone());
                    changed = true;
                }
            }
        }
        if fresh {
            for kind in LineKind::ALL {
                let file_key = file_key(pin, kind);
                if !lines.iter().any(|(k, _)| *k == kind)
                    && starts
                        .starts
                        .get(&file_key)
                        .is_some_and(|s| s.key.is_none())
                {
                    starts.starts.remove(&file_key);
                    changed = true;
                }
            }
        }
        if changed {
            write(path, &starts)
        } else {
            Ok(())
        }
    })
}

/// Lets the line of `kind` kept in `path` for the environment filed under
/// `pin` go when it is owed (no start's key): whether one went.
fn drop_owed(path: &Path, pin: &str, kind: LineKind) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    erpc_core::private_file::locked(path, || {
        let mut starts = load(path)?;
        let file_key = file_key(pin, kind);
        if starts.starts.get(&file_key).is_none_or(|s| s.key.is_some()) {
            return Ok(false);
        }
        starts.starts.remove(&file_key);
        write(path, &starts).map(|()| true)
    })
}

/// The kinds of the lines `starts` keeps for the environment filed under
/// `pin`.
fn kinds_kept(starts: &Starts, pin: &str) -> Vec<LineKind> {
    LineKind::ALL
        .into_iter()
        .filter(|kind| starts.starts.contains_key(&file_key(pin, *kind)))
        .collect()
}

/// The key a line of `kind` is kept under, for the environment
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

// ----------------------------------------------- what a first deploy owes

/// The kinds of line a run's own yes agreed to: the first deploy's line
/// questions, right after the server's price ([`Owing::agree`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Agreed(u8);

impl Agreed {
    const fn bit(kind: LineKind) -> u8 {
        match kind {
            LineKind::Grpc => 1,
            LineKind::Shreds => 2,
            LineKind::Udp => 4,
            LineKind::Unlimited => 8,
        }
    }

    /// The same, and `kind` too.
    #[must_use]
    pub(crate) const fn with(self, kind: LineKind) -> Self {
        Self(self.0 | Self::bit(kind))
    }

    /// Whether this run's yes agreed to a line of `kind`.
    #[must_use]
    pub(crate) const fn has(self, kind: LineKind) -> bool {
        self.0 & Self::bit(kind) != 0
    }
}

/// Lines of a kind each, at their plans.
pub(crate) type Planned = Vec<(LineKind, Plan)>;

/// The lines a first deploy asks for, read before anything is made or
/// bought: each one's plan of the hourly catalogue (one it does not offer
/// is refused then), and what this machine keeps of the environment's
/// lines.
pub(crate) struct Owing {
    store: PathBuf,
    pin: String,
    env: String,
    /// The lines asked before the server is bought, each at its plan now:
    /// those this run names, then (unless `fresh`) those kept here owed for
    /// the kinds it does not name, with what is kept of each.
    asked: Vec<(LineKind, Plan, Option<Kept>)>,
    /// The kinds of every line kept here for the environment.
    kept: Vec<LineKind>,
    /// The starts kept here for the environment under a key.
    started: Vec<(LineKind, Kept)>,
    /// Whether `erpc.toml` had nothing for the environment: what is kept
    /// owed for it here is let go, but for the lines asked.
    fresh: bool,
}

impl Owing {
    /// The lines `store` keeps owed (no start's key) for the environment
    /// filed under `pin` that `named` does not name, each with its plan's
    /// product id: asked again before a server is bought. None when
    /// `fresh`.
    pub(crate) fn owed_again(
        store: &Path,
        pin: &str,
        named: &[(LineKind, Option<String>)],
        fresh: bool,
    ) -> Result<Vec<(LineKind, String)>, CliError> {
        if fresh {
            return Ok(Vec::new());
        }
        let starts = load(store).map_err(failed)?;
        Ok(LineKind::ALL
            .into_iter()
            .filter(|kind| !named.iter().any(|(n, _)| n == kind))
            .filter_map(|kind| {
                starts
                    .starts
                    .get(&file_key(pin, kind))
                    .filter(|s| s.key.is_none())
                    .map(|s| (kind, s.product_id.clone()))
            })
            .collect())
    }

    /// What `store` keeps for environment `env`, filed under `pin`, with
    /// the lines `named` (this run's) and `again` (kept here owed, at their
    /// plans now) to ask; `fresh` when `erpc.toml` has nothing for it.
    pub(crate) fn read(
        store: &Path,
        (pin, env): (String, &str),
        (named, again): (Planned, Planned),
        fresh: bool,
    ) -> Result<Self, CliError> {
        let starts = load(store).map_err(failed)?;
        let kept_of = |kind: LineKind| starts.starts.get(&file_key(&pin, kind)).cloned();
        let mut asked: Vec<(LineKind, Plan, Option<Kept>)> = named
            .into_iter()
            .map(|(kind, plan)| (kind, plan, None))
            .collect();
        if !fresh {
            for (kind, plan) in again {
                if !asked.iter().any(|(k, ..)| *k == kind) {
                    asked.push((kind, plan, kept_of(kind).filter(|k| k.key.is_none())));
                }
            }
        }
        let started = LineKind::ALL
            .into_iter()
            .filter_map(|kind| kept_of(kind).filter(|k| k.key.is_some()).map(|k| (kind, k)))
            .collect();
        let kept = if fresh {
            Vec::new()
        } else {
            kinds_kept(&starts, &pin)
        };
        Ok(Self {
            store: store.to_path_buf(),
            pin,
            env: env.to_owned(),
            asked,
            kept,
            started,
            fresh,
        })
    }

    /// The kinds of the lines a deploy goes on to start: those asked, and
    /// those kept here.
    pub(crate) fn kinds(&self) -> Vec<LineKind> {
        LineKind::ALL
            .into_iter()
            .filter(|kind| self.asked.iter().any(|(a, ..)| a == kind) || self.kept.contains(kind))
            .collect()
    }

    /// Refuses, before a server is bought, a start of a line kept here
    /// under a key for the app `name` and the environment: one kept from an
    /// earlier environment, or server, of those names, whose outcome is not
    /// known.
    pub(crate) fn refuse_kept_starts(&self, app: &App, name: &str) -> Result<(), CliError> {
        let Some((kind, line)) = self.started.first() else {
            return Ok(());
        };
        let start = line.start.as_deref().map(clean);
        let named = start.as_deref().map_or_else(String::new, |start| {
            t!("worker_first_deploy.line_start_named", start)
        });
        let hint = t!(
            "worker_first_deploy.line_kept_earlier_hint",
            scope = app.scope()
        );
        let hint = match &start {
            Some(start) => format!(
                "{}; {hint}",
                t!("worker_server.support_hint", start = start.as_str())
            ),
            None => hint,
        };
        Err(failed(t!(
            "worker_first_deploy.line_kept_earlier",
            kind = kind.label(),
            app = name,
            env = self.env.as_str(),
            start = named.as_str()
        ))
        .hint(hint))
    }

    /// Asks each line's price at the terminal (`confirm`), or says it under
    /// `yes`, then keeps the lines asked here, owed, agreed to: this run's
    /// deploy, once the server is logged in to, starts them without asking
    /// again (the kinds come back). Run after the server's yes, before its
    /// start is sent: a no (which lets go what is kept owed of that line),
    /// or a line not kept, stops before anything is bought.
    pub(crate) fn agree(
        &self,
        confirm: &dyn Fn(&str) -> Result<bool, String>,
        yes: bool,
    ) -> Result<Agreed, CliError> {
        let say = Say { quiet: false };
        let env = self.env.as_str();
        for (kind, plan, earlier) in &self.asked {
            let kind = *kind;
            if let Some(earlier) = earlier.as_ref().filter(|k| k.agreed) {
                say.line(&t!(
                    "worker_first_deploy.line_owed",
                    kind = kind.label(),
                    env,
                    was = earlier.price.as_str()
                ));
            }
            let (name, product) = (clean(&plan.name), clean(&plan.id));
            let price = euros(plan);
            let place = match kind {
                LineKind::Unlimited => t!("worker_first_deploy.line_in_worker_region"),
                _ => t!("worker_first_deploy.line_for_worker"),
            };
            let (name, product, place, price) = (
                name.as_str(),
                product.as_str(),
                place.as_str(),
                price.as_str(),
            );
            if yes {
                say.line(&t!(
                    "worker_first_deploy.line_note_first",
                    kind = kind.label(),
                    name,
                    product,
                    env,
                    place,
                    price
                ));
            } else if !confirm(&t!(
                "worker_first_deploy.line_question_first",
                kind = kind.label(),
                name,
                product,
                env,
                place,
                price
            ))
            .map_err(failed)?
            {
                // A no: what is kept owed of it goes too.
                let declined = t!(
                    "worker_first_deploy.line_declined_first",
                    kind = kind.label(),
                    env
                );
                let message = match drop_owed(&self.store, &self.pin, kind) {
                    Ok(true) => format!(
                        "{declined}\n{}",
                        t!(
                            "worker_first_deploy.line_forgotten",
                            kind = kind.label(),
                            flag = kind.flag()
                        )
                    ),
                    Ok(false) => declined,
                    Err(error) => format!("{declined}\n{}", t!("worker_server.unkept", error)),
                };
                return Err(CliError::new(Code::Declined, message));
            }
        }
        self.keep(true)?;
        Ok(self
            .asked
            .iter()
            .fold(Agreed::default(), |agreed, (kind, ..)| agreed.with(*kind)))
    }

    /// Keeps the lines asked here, owed, agreed to or not (`agreed`: a
    /// line kept owed already stays as it is when not): what a deploy that
    /// goes on starts.
    pub(crate) fn keep(&self, agreed: bool) -> Result<(), CliError> {
        let lines: Vec<(LineKind, Kept)> = self
            .asked
            .iter()
            .map(|(kind, plan, _)| (*kind, Kept::owed(plan, agreed)))
            .collect();
        owe(&self.store, &self.pin, &lines, (agreed, self.fresh))
            .map_err(|error| failed(t!("worker_server.not_kept", error)))
    }
}

/// [`Owing`] for the lines `lines` asks for (each at its plan, `None`: the
/// cheapest) of environment `app.env` of the app named `name`, and (unless
/// `fresh`) those kept here owed, through the signed-in `signed`: the plans
/// read from the hourly catalogue through user-api, only when a line is to
/// be asked. A line kept here owed whose plan the catalogue no longer
/// offers is let go, and said.
pub(crate) async fn owing(
    signed: &kept::Signed,
    (app, name): (&App, &str),
    lines: &[(LineKind, Option<String>)],
    fresh: bool,
) -> Result<Owing, CliError> {
    let uid = kept::Account::uid(signed).await?;
    let pin = kept::pin_key(&uid, name, &app.env);
    let store = crate::account::session::beside_config(FILE).map_err(failed)?;
    let env = app.env.as_str();
    if lines.is_empty() && Owing::owed_again(&store, &pin, lines, fresh)?.is_empty() {
        return Owing::read(&store, (pin, env), (Vec::new(), Vec::new()), fresh);
    }
    let api = crate::worker::vps::Api::open().await?;
    let live = Live { signed, api: &api };
    owing_with(&live, (pin, env), lines, (&store, fresh)).await
}

/// [`owing`] through `reach`, for the environment `env` filed under `pin`,
/// with what is kept here in `store`.
async fn owing_with(
    reach: &impl Reach,
    (pin, env): (String, &str),
    lines: &[(LineKind, Option<String>)],
    (store, fresh): (&Path, bool),
) -> Result<Owing, CliError> {
    let mut named = Vec::new();
    for (kind, plan) in lines {
        named.push((*kind, reach.plan(*kind, plan.as_deref()).await?));
    }
    let mut again = Vec::new();
    for (kind, product) in Owing::owed_again(store, &pin, lines, fresh)? {
        if let Ok(plan) = reach.plan(kind, Some(&product)).await {
            again.push((kind, plan));
        } else {
            drop_owed(store, &pin, kind).map_err(failed)?;
            Say { quiet: false }.line(&format!(
                "note: {}",
                t!(
                    "worker_first_deploy.line_kept_unoffered",
                    kind = kind.label(),
                    plan = clean(&product)
                )
            ));
        }
    }
    Owing::read(store, (pin, env), (named, again), fresh)
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

/// What a run asks of a line's plan.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Asked {
    /// This plan, by product id, on the command line.
    Plan(String),
    /// The line on the command line, without a plan: the one kept here, or
    /// the cheapest.
    Cheapest,
    /// Not on the command line: the line kept here, at its plan.
    Kept,
}

/// The lines to start: those `lines` asks for, then those `kept` here
/// that it does not.
fn to_start(lines: &[(LineKind, Option<String>)], kept: &[LineKind]) -> Vec<(LineKind, Asked)> {
    let mut all: Vec<(LineKind, Asked)> = lines
        .iter()
        .map(|(kind, plan)| (*kind, plan.clone().map_or(Asked::Cheapest, Asked::Plan)))
        .collect();
    for kind in kept {
        if !all.iter().any(|(k, _)| k == kind) {
            all.push((*kind, Asked::Kept));
        }
    }
    all
}

/// What a run does of a line, from what the account has and what is kept
/// here.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decided {
    /// A new start, under a new key.
    New,
    /// The start kept here, sent again under its key with the same body.
    Again(Kept),
    /// A start kept here that is not sent again, with nothing of the kind
    /// open or on record: let go only after a yes at a terminal.
    Stranded(Kept),
}

/// [`Decided`] for a line of `kind` (`asked`: the plan the command line
/// names) for `here` (the address or region this run sends), from the
/// environment's `open` starts and the line kept here, `kept`, with no line
/// of the kind on the record. Refused when a start of a kind erpc cannot
/// tell is open, two of the kind are, or one that is not the start kept
/// here to send again.
fn decide(
    open: &[OpenLine],
    kept: Option<&Kept>,
    (kind, asked): (LineKind, Option<&str>),
    here: (Option<&str>, Option<&str>),
    app: &App,
) -> Result<Decided, CliError> {
    let env = app.env.as_str();
    let refuse = |message: String, start: &str| {
        failed(message).hint(t!("worker_server.support_hint", start))
    };
    if let Some(unknown) = open.iter().find(|s| s.kind.is_none()) {
        let start = clean(&unknown.id);
        return Err(refuse(
            t!(
                "worker_first_deploy.line_open_unknown",
                env,
                start = start.as_str()
            ),
            &start,
        ));
    }
    let mine: Vec<&OpenLine> = open
        .iter()
        .filter(|s| s.kind == Some(account_kind(kind)))
        .collect();
    let sent = kept.filter(|k| k.key.is_some());
    let for_here = |k: &Kept| (k.ip.as_deref(), k.region.as_deref()) == here;
    let same_plan = |k: &Kept| asked.is_none_or(|p| p == k.product_id);
    match (mine.as_slice(), sent) {
        ([], None) => Ok(Decided::New),
        ([], Some(k)) if k.resend && for_here(k) && same_plan(k) => Ok(Decided::Again(k.clone())),
        // The account said it bought a line it did not put on the record:
        // never let go here, and no other start made for it.
        ([], Some(k)) if k.mismatched() => Err(mismatch_kept(kind, k, app)),
        ([], Some(k)) => Ok(Decided::Stranded(k.clone())),
        ([one], Some(k))
            if k.resend && one.product_id.as_deref() == Some(k.product_id.as_str()) =>
        {
            let start = clean(&one.id);
            if !same_plan(k) {
                let plan_flag = format!("--{}-plan", kind.flag());
                return Err(CliError::new(
                    Code::Usage,
                    t!(
                        "worker_first_deploy.line_differs",
                        kind = kind.label(),
                        env,
                        kept = clean(&k.product_id),
                        asked = clean(asked.unwrap_or_default())
                    ),
                )
                .hint(t!(
                    "worker_first_deploy.line_differs_hint",
                    kept = clean(&k.product_id),
                    flag = plan_flag.as_str(),
                    scope = app.scope()
                )));
            }
            if !for_here(k) {
                return Err(refuse(
                    t!(
                        "worker_first_deploy.line_open_elsewhere",
                        kind = kind.label(),
                        env,
                        start = start.as_str(),
                        kept = place(kind, (k.ip.as_deref(), k.region.as_deref())),
                        now = place(kind, here)
                    ),
                    &start,
                ));
            }
            Ok(Decided::Again(k.clone()))
        }
        ([first, rest @ ..], k) => {
            let start = clean(&first.id);
            let message = if rest.is_empty() {
                t!(
                    "worker_first_deploy.line_open",
                    kind = kind.label(),
                    env,
                    start = start.as_str()
                )
            } else {
                t!(
                    "worker_first_deploy.line_open_many",
                    kind = kind.label(),
                    env,
                    count = mine.len(),
                    start = start.as_str()
                )
            };
            let note = match k {
                None => t!("worker_first_deploy.line_open_none_kept"),
                Some(k) if !k.resend => t!("worker_first_deploy.line_open_kept"),
                Some(_) => t!("worker_first_deploy.line_open_kept_beside"),
            };
            Err(refuse(format!("{message}\n{note}"), &start))
        }
    }
}

/// The stop of a run for a line of `kind` whose start kept here, `k`, the
/// account said bought a line it did not put on the record.
fn mismatch_kept(kind: LineKind, k: &Kept, app: &App) -> CliError {
    let start = k.start.as_deref().map(clean).unwrap_or_default();
    failed(t!(
        "worker_first_deploy.line_mismatch_kept",
        kind = kind.label(),
        env = app.env.as_str(),
        start = start.as_str()
    ))
    .hint(t!(
        "worker_first_deploy.line_mismatch_hint",
        kind = kind.label(),
        start = start.as_str(),
        scope = app.scope()
    ))
}

/// What becomes of the start kept here after the account answered `e`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    /// Settled without a line: its key goes, and the line stays asked.
    Gone,
    /// Kept, to be sent again under the same key: the account said to, or
    /// gave no answer.
    Again,
    /// The account took no start just now: kept, to be sent again under
    /// the same key.
    Busy,
    /// Kept, never sent again: whether it bought a line is not known.
    Held,
}

/// The answers the account gives to a line start before anything is
/// bought.
const NOTHING_BOUGHT: [AccountCode; 12] = [
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
    AccountCode::EnvNotFound,
];

/// [`After`] for the answer `e` to a line start, as
/// [`erpc_api::worker::money`] says: no answer, a start pending with a
/// retry and an unavailable purchase send the same key again; a start
/// pending without one (another is open, and this key bought nothing), one
/// ended meanwhile, and an answer that buys nothing let it go; any other
/// (unsettled, whatever its reason, an idempotency conflict, a code this
/// version does not know) is never sent again.
fn after(e: &WorkerError) -> After {
    let WorkerError::Refused(r) = e else {
        return After::Again;
    };
    match &r.code {
        Some(AccountCode::StartPending) if r.retry() => After::Again,
        Some(AccountCode::PurchaseUnavailable) => After::Again,
        Some(AccountCode::StartPending | AccountCode::StartEnded) => After::Gone,
        Some(AccountCode::RateLimited) => After::Busy,
        Some(code) if NOTHING_BOUGHT.contains(code) => After::Gone,
        _ => After::Held,
    }
}

/// How a run starts its lines: where what is kept here is (`store`),
/// whether `--yes` says the prices (`yes`), what its own yes agreed to
/// (`agreed`), and whether the app needs a line of a kind beside those of
/// the kinds given (`needs`).
pub(crate) struct Run<'a> {
    pub(crate) store: &'a Path,
    pub(crate) yes: bool,
    pub(crate) agreed: Agreed,
    pub(crate) needs: &'a dyn Fn(LineKind, &[LineKind]) -> bool,
}

/// Starts each line `lines` asks for (kind and plan, `None`: the one kept
/// here, or the cheapest), and each line kept here for the environment,
/// that environment `app.env` of the app named `name` does not have yet,
/// for `target`, and waits for each to be active. Every line is asked (said
/// under `--yes`) before any is sent, but one this run's own yes agreed to
/// at its price; a no lets the line kept here go, and the run goes on
/// without it unless the app needs it, when it stops, nothing bought. What
/// is said goes to stderr, line by line, and comes back too.
pub(crate) async fn start_lines(
    reach: &impl Reach,
    (app, name): (&App, &str),
    lines: &[(LineKind, Option<String>)],
    target: Target<'_>,
    run: &Run<'_>,
) -> Result<Vec<String>, CliError> {
    let env = app.env.as_str();
    let say = Say { quiet: false };
    let uid = reach.uid().await?;
    let pin = kept::pin_key(&uid, name, env);
    let kept_here = kinds_kept(&load(run.store).map_err(failed)?, &pin);
    let record = reach
        .env(name, env)
        .await
        .map_err(|e| kept::worker_error(name, app, &e))?;
    let mut present: Vec<LineKind> = LineKind::ALL
        .into_iter()
        .filter(|kind| on_record(&record, *kind).is_some())
        .collect();
    let (mut declined, mut ready) = (Vec::new(), Vec::new());
    // Every line asked first: a no buys nothing.
    for (kind, asked) in to_start(lines, &kept_here) {
        match Box::pin(prepare(
            reach,
            (app, name, &pin),
            (kind, &asked),
            target,
            run,
        ))
        .await?
        {
            Prepared::OnRecord => {}
            Prepared::Declined => declined.push(kind),
            Prepared::Send(line) => {
                present.push(kind);
                ready.push((kind, line));
            }
        }
    }
    if let Some(kind) = declined.iter().find(|k| (run.needs)(**k, &present)) {
        return Err(CliError::new(
            Code::Declined,
            t!(
                "worker_first_deploy.line_declined_needed",
                kind = kind.label(),
                env,
                setting = kind.setting()
            ),
        )
        .hint(t!(
            "worker_first_deploy.line_declined_needed_hint",
            flag = kind.flag(),
            scope = app.scope()
        )));
    }
    for kind in &declined {
        say.line(&format!(
            "note: {}",
            t!(
                "worker_first_deploy.line_declined_goes_on",
                kind = kind.label(),
                env
            )
        ));
    }
    let mut said = Vec::new();
    for (kind, line) in ready {
        said.push(send(reach, (app, name, &pin), kind, run.store, *line).await?);
    }
    for kind in present {
        wait(reach, (app, name), kind, &say).await?;
    }
    Ok(said)
}

/// The address and region a line of `kind` is started for, from
/// `target`: refused for an Unlimited RPC with no region.
fn here_of(
    kind: LineKind,
    target: Target<'_>,
) -> Result<(Option<String>, Option<String>), CliError> {
    let ip = matches!(kind, LineKind::Grpc | LineKind::Shreds).then(|| target.ip.to_string());
    let region = (kind == LineKind::Unlimited)
        .then(|| target.region.map(str::to_owned))
        .flatten();
    if kind == LineKind::Unlimited && region.is_none() {
        return Err(
            failed(t!("worker_vps.line.no_region")).hint(t!("worker_vps.line.no_region_hint"))
        );
    }
    Ok((ip, region))
}

/// What a run does of a line, once asked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Prepared {
    /// On the environment's record already: used as it is.
    OnRecord,
    /// Declined, and the line kept here for it let go.
    Declined,
    /// To be sent: what is kept here for it now, and the start to send.
    Send(Box<(Option<Kept>, Kept)>),
}

/// The line of `kind` (`asked` as the run asks its plan), read and asked,
/// unless the record has it: nothing sent.
async fn prepare(
    reach: &impl Reach,
    (app, name, pin): (&App, &str, &str),
    (kind, asked): (LineKind, &Asked),
    target: Target<'_>,
    run: &Run<'_>,
) -> Result<Prepared, CliError> {
    let (env, store, yes) = (app.env.as_str(), run.store, run.yes);
    let read = |e: &WorkerError| kept::worker_error(name, app, e);
    let file_key = file_key(pin, kind);
    let mut kept_now = load(store).map_err(failed)?.starts.remove(&file_key);
    let record = reach.env(name, env).await.map_err(|e| read(&e))?;
    if on_record(&record, kind).is_some() {
        // On record: what was kept here for it went through, or is not
        // needed.
        if let Some(line) = &kept_now {
            forget(store, &file_key, line).map_err(failed)?;
        }
        return Ok(Prepared::OnRecord);
    }
    let (ip, region) = here_of(kind, target)?;
    let here = (ip.as_deref(), region.as_deref());
    let open = reach.open_lines(name, env).await.map_err(|e| read(&e))?;
    let plan_asked = match asked {
        Asked::Plan(p) => Some(p.as_str()),
        Asked::Cheapest | Asked::Kept => None,
    };
    let decided = decide(&open, kept_now.as_ref(), (kind, plan_asked), here, app)?;
    let again = match decided {
        Decided::Again(line) => Some(line),
        Decided::New => None,
        Decided::Stranded(line) => {
            let_go_asked(reach, &line, kind, app, yes)?;
            put(store, &file_key, None, Some(&line))
                .map_err(|error| failed(t!("worker_server.not_kept", error)))?;
            kept_now = None;
            None
        }
    };
    let to_send = if let Some(line) = again {
        let plan = reach.plan(kind, Some(&line.product_id)).await?;
        ask(
            reach,
            (kind, &plan, env, &place(kind, here)),
            Asking::Again,
            yes,
        )?;
        Kept {
            name: plan.name.clone(),
            price: euros(&plan),
            agreed: true,
            resend: false,
            ..line
        }
    } else {
        let id = plan_asked
            .map(str::to_owned)
            .or_else(|| kept_now.as_ref().map(|k| k.product_id.clone()));
        let plan = reach.plan(kind, id.as_deref()).await?;
        match agreed_or_asked(
            reach,
            (kind, &plan, env),
            here,
            kept_now.as_ref(),
            (run.agreed, yes),
        ) {
            Ok(()) => {}
            // A no: the line kept here for it goes.
            Err(no) if no.code == Code::Declined => {
                put(store, &file_key, None, kept_now.as_ref())
                    .map_err(|error| failed(t!("worker_server.unkept", error)))?;
                return Ok(Prepared::Declined);
            }
            Err(e) => return Err(e),
        }
        Kept {
            key: Some(reach.new_key()?.as_str().to_owned()),
            ip,
            region,
            ..Kept::owed(&plan, true)
        }
    };
    Ok(Prepared::Send(Box::new((kept_now, to_send))))
}

/// Sends `to_send`, the start of a line of `kind`, kept first under its
/// key in `store` in place of `kept_now`: what was said of it.
async fn send(
    reach: &impl Reach,
    (app, name, pin): (&App, &str, &str),
    kind: LineKind,
    store: &Path,
    (kept_now, to_send): (Option<Kept>, Kept),
) -> Result<String, CliError> {
    let env = app.env.as_str();
    let file_key = file_key(pin, kind);
    let key = StartKey::new(to_send.key.clone().unwrap_or_default())
        .map_err(|e| failed(e.to_string()))?;
    // Kept before it is sent, as not to be sent again: an answer lost on
    // the way, or a stop, leaves the next run to read the account first.
    put(store, &file_key, Some(&to_send), kept_now.as_ref())
        .map_err(|error| failed(t!("worker_server.not_kept", error)))?;
    match reach.start(name, env, &key, &to_send.body(kind)).await {
        Ok(_) => {
            let say = Say { quiet: false };
            let line = t!("worker_first_deploy.line_started", kind = kind.label(), env);
            say.line(&line);
            if let Err(error) = forget(store, &file_key, &to_send) {
                say.line(&format!("warning: {}", t!("worker_server.unkept", error)));
            }
            Ok(line)
        }
        Err(e) => Err(not_started(
            &e,
            (app, name, kind),
            (store, &file_key, &to_send),
        )),
    }
}

/// A new start of a line of `kind` at `plan` for environment `env`, for
/// `here`: said, not asked, when this run's own yes (`agreed`) agreed to
/// it at this price, kept here as `kept`; else asked (said under `yes`),
/// once more for one agreed to on an earlier run, with the price agreed to
/// then when it was another.
fn agreed_or_asked(
    reach: &impl Reach,
    (kind, plan, env): (LineKind, &Plan, &str),
    here: (Option<&str>, Option<&str>),
    kept: Option<&Kept>,
    (agreed, yes): (Agreed, bool),
) -> Result<(), CliError> {
    let price = euros(plan);
    let place = place(kind, here);
    let owed = kept.filter(|k| k.key.is_none() && k.agreed && k.product_id == plan.id);
    let same = owed.is_some_and(|k| k.price == price);
    if agreed.has(kind) && same {
        Say { quiet: false }.line(&t!(
            "worker_first_deploy.line_agreed",
            kind = kind.label(),
            name = clean(&plan.name),
            product = clean(&plan.id),
            env,
            place = place.as_str(),
            price = price.as_str()
        ));
        return Ok(());
    }
    let asking = match owed {
        Some(_) if same => Asking::Earlier,
        Some(k) => Asking::New {
            since: Some(k.price.as_str()),
        },
        None => Asking::New { since: None },
    };
    ask(reach, (kind, plan, env, &place), asking, yes)
}

/// Asks whether to let `line`, a start of a `kind` line kept here that is
/// not sent again, go, the account listing no start of the kind open and
/// naming no such line: at a terminal only, never under `yes`.
fn let_go_asked(
    reach: &impl Reach,
    line: &Kept,
    kind: LineKind,
    app: &App,
    yes: bool,
) -> Result<(), CliError> {
    let env = app.env.as_str();
    let start = line.start.as_deref().map(clean);
    let named = start.as_deref().map_or_else(String::new, |start| {
        t!("worker_first_deploy.line_start_named", start)
    });
    let why = if line.resend {
        t!(
            "worker_first_deploy.line_stranded_other",
            plan = clean(&line.product_id),
            place = place(kind, (line.ip.as_deref(), line.region.as_deref()))
        )
    } else {
        t!("worker_first_deploy.line_stranded_held")
    };
    let message = t!(
        "worker_first_deploy.line_stranded",
        kind = kind.label(),
        env,
        start = named.as_str(),
        why
    );
    let hint = t!(
        "worker_first_deploy.line_stranded_hint",
        scope = app.scope()
    );
    let hint = match &start {
        Some(start) => format!(
            "{hint}; {}",
            t!("worker_server.support_hint", start = start.as_str())
        ),
        None => hint,
    };
    if yes {
        return Err(failed(message).hint(hint));
    }
    let question = format!(
        "{message}\n{}",
        t!(
            "worker_first_deploy.line_let_go_question",
            kind = kind.label()
        )
    );
    if reach.confirm(&question).map_err(failed)? {
        Ok(())
    } else {
        Err(CliError::new(Code::Declined, message).hint(hint))
    }
}

/// The stop of the start `sent` of a line of `kind` kept under `file_key`
/// in `store`, answered `e`: the answer by its status and code alone (its
/// message may name steps erpc does not take), then what became of the
/// start kept here, in a sentence of its own.
fn not_started(
    e: &WorkerError,
    (app, name, kind): (&App, &str, LineKind),
    (store, file_key, sent): (&Path, &str, &Kept),
) -> CliError {
    let env = app.env.as_str();
    let scope = app.scope();
    let then = after(e);
    let mut error = kept::worker_error(name, app, e);
    let (why, start, code, reason) = match e {
        WorkerError::Refused(r) => (
            r.code.as_ref().map_or_else(
                || format!("HTTP {}", r.status),
                |code| format!("HTTP {}, {code}", r.status),
            ),
            r.start_id().map(|s| clean(&s)),
            r.code.clone(),
            r.reason(),
        ),
        _ => (error.message.clone(), None, None, None),
    };
    let start = start.or_else(|| sent.start.clone());
    let start_said = start.clone().unwrap_or_default();
    let (kind_said, why) = (kind.label(), why.as_str());
    let fate = match then {
        After::Gone => {
            let asked = Kept {
                agreed: false,
                key: None,
                ip: None,
                region: None,
                resend: false,
                start: None,
                ..sent.clone()
            };
            put(store, file_key, Some(&asked), Some(sent))
                .map(|()| t!("worker_first_deploy.line_key_let_go", kind = kind_said))
        }
        After::Again | After::Busy => {
            let again = Kept {
                resend: true,
                start: start.clone(),
                ..sent.clone()
            };
            put(store, file_key, Some(&again), Some(sent))
                .map(|()| t!("worker_first_deploy.line_key_again"))
        }
        After::Held => {
            let held = Kept {
                start: start.clone(),
                unsettled: (code == Some(AccountCode::StartUnsettled))
                    .then(|| reason.clone().unwrap_or_default()),
                ..sent.clone()
            };
            put(store, file_key, Some(&held), Some(sent))
                .map(|()| t!("worker_first_deploy.line_key_held"))
        }
    };
    let unkept = fate.is_err();
    let fate = fate.unwrap_or_else(|error| t!("worker_server.unkept", error));
    error.message = answer_said(
        (then, code.as_ref(), reason.as_deref()),
        (kind_said, env, why),
        &start_said,
    );
    let mismatch = code == Some(AccountCode::StartUnsettled) && reason.as_deref() == Some(MISMATCH);
    let hint = answer_hint(
        (then, code.as_ref(), unkept),
        (kind_said, scope.as_str()),
        (start.as_deref(), mismatch),
    );
    // Signed out, signing in again comes first.
    if error.code != Code::NotSignedIn {
        error.hint = Some(hint);
    }
    error.message = format!("{}\n{fate}", error.message);
    error
}

/// What the account's answer to a line start says, by its class `then`,
/// its `code` and `reason`: of a line of `kind` of environment `env`, `why`
/// its status and code, `start` the start's id.
fn answer_said(
    (then, code, reason): (After, Option<&AccountCode>, Option<&str>),
    (kind, env, why): (&str, &str, &str),
    start: &str,
) -> String {
    match (then, code) {
        (After::Gone, Some(AccountCode::StartEnded)) => {
            t!("worker_first_deploy.line_ended", kind, env, why)
        }
        (After::Gone, Some(AccountCode::StartPending)) => {
            t!("worker_first_deploy.line_other_open", kind, env, start, why)
        }
        (After::Gone, _) => {
            t!("worker_first_deploy.line_not_started", kind, env, why)
        }
        (After::Again, Some(_)) => t!("worker_first_deploy.line_again", kind, env, why),
        (After::Busy, _) => t!("worker_first_deploy.line_busy", kind, env, why),
        (After::Held, Some(AccountCode::StartUnsettled)) if reason == Some("start_mismatch") => {
            t!("worker_first_deploy.line_mismatch", kind, env, start, why)
        }
        (After::Held, Some(AccountCode::StartUnsettled)) => t!(
            "worker_first_deploy.line_unsettled",
            kind,
            env,
            reason = clean(reason.unwrap_or_default()),
            start,
            why
        ),
        // No answer, or one this version does not know.
        (After::Again | After::Held, _) => {
            t!("worker_first_deploy.line_held", kind, env, why)
        }
    }
}

/// The hint of the stop of a line start answered as `then` and `code`
/// says (`unkept`: what became of its key could not be kept), for a line
/// of `kind`, in `scope`; `start` the start's id, and `mismatch` whether
/// the account said it bought a line it did not put on the record.
fn answer_hint(
    (then, code, unkept): (After, Option<&AccountCode>, bool),
    (kind, scope): (&str, &str),
    (start, mismatch): (Option<&str>, bool),
) -> String {
    match then {
        // A line bought and not on the record: support settles it.
        After::Held if mismatch => t!(
            "worker_first_deploy.line_mismatch_hint",
            kind,
            start = start.unwrap_or_default(),
            scope
        ),
        After::Gone if code == Some(&AccountCode::StartPending) => t!(
            "worker_first_deploy.line_other_open_hint",
            kind,
            start = start.unwrap_or_default(),
            scope
        ),
        After::Gone => t!("worker_first_deploy.line_asked_again_hint", kind, scope),
        // The mark to send it again could not be kept: the next run does
        // not send it again.
        After::Again | After::Busy if unkept => {
            t!("worker_first_deploy.line_again_unkept_hint", scope)
        }
        After::Again => t!("worker_first_deploy.line_again_hint", scope),
        After::Busy => t!("worker_first_deploy.line_busy_hint", scope),
        After::Held => {
            let held = t!("worker_first_deploy.line_held_hint", kind, scope);
            match start {
                Some(start) => format!("{}; {held}", t!("worker_server.support_hint", start)),
                None => held,
            }
        }
    }
}

/// The lines a deploy starts once its server is logged in to: those its
/// command line names (when it owes them), what its own yes agreed to,
/// and whether `--yes` says their prices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Lines {
    pub(crate) named: Vec<(LineKind, Option<String>)>,
    pub(crate) agreed: Agreed,
    pub(crate) yes: bool,
}

/// [`start_lines`] for the first deploy of `app`, once its server is
/// logged in to: the lines `lines` names and those kept here, signed in,
/// the hourly catalogue read through user-api ([`for_deploy_with`]).
pub(crate) async fn for_deploy(app: &App, lines: &Lines) -> Result<(), CliError> {
    let (_, m) = crate::worker::load(&app.dir)?;
    let signed = kept::Signed::open().await?;
    let api = crate::worker::vps::Api::open().await?;
    let store = crate::account::session::beside_config(FILE).map_err(failed)?;
    for_deploy_with(
        &Live {
            signed: &signed,
            api: &api,
        },
        (app, &m),
        lines,
        &store,
    )
    .await
}

/// [`for_deploy`] through `reach`, for `m` as `erpc.toml` has it, with
/// what is kept here in `store`: nothing read beyond the account's id when
/// there is no line to start; else the server's address and region read
/// from the environment's record, and whether the app needs a line told by
/// the settings `erpc.toml` requires.
async fn for_deploy_with(
    reach: &impl Reach,
    (app, m): (&App, &erpc_worker::manifest::Manifest),
    lines: &Lines,
    store: &Path,
) -> Result<(), CliError> {
    let uid = reach.uid().await?;
    let pin = kept::pin_key(&uid, &m.name, &app.env);
    if lines.named.is_empty() && kinds_kept(&load(store).map_err(failed)?, &pin).is_empty() {
        return Ok(());
    }
    let record = reach
        .env(&m.name, &app.env)
        .await
        .map_err(|e| kept::worker_error(&m.name, app, &e))?;
    let (ip, region) = target_of(&record, app)?;
    // Whether the app needs a line of `kind`, the lines of `present`
    // giving their settings.
    let needs = |kind: LineKind, present: &[LineKind]| {
        let provided: Vec<&str> = present.iter().map(|k| k.setting()).collect();
        m.missing_besides(&provided)
            .iter()
            .any(|r| r.met(|n| n == kind.setting()))
    };
    start_lines(
        reach,
        (app, &m.name),
        &lines.named,
        Target {
            ip,
            region: region.as_deref(),
        },
        &Run {
            store,
            yes: lines.yes,
            agreed: lines.agreed,
            needs: &needs,
        },
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
                "worker_first_deploy.line_no_address_hint",
                scope = app.scope()
            ))
        })?;
    Ok((ip, server.and_then(|s| s.region.clone())))
}

/// How a line's start is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asking<'a> {
    /// A new start; `since`: the price agreed to before, when it was
    /// another.
    New { since: Option<&'a str> },
    /// The start kept here, sent again under its key.
    Again,
    /// A line agreed to on an earlier run at this price, never sent: asked
    /// once more in this run.
    Earlier,
}

/// Asks the price of `plan` for a line of `kind` of environment `env`,
/// for `place`, or says it under `yes`: the hourly catalogue's.
fn ask(
    reach: &impl Reach,
    (kind, plan, env, place): (LineKind, &Plan, &str, &str),
    asking: Asking<'_>,
    yes: bool,
) -> Result<(), CliError> {
    let price = euros(plan);
    let (name, product) = (clean(&plan.name), clean(&plan.id));
    let (name, product, price_said) = (name.as_str(), product.as_str(), price.as_str());
    let before = match asking {
        Asking::Again => Some(t!("worker_first_deploy.line_same_start")),
        Asking::New { since: Some(was) } => Some(t!(
            "worker_first_deploy.line_price_since",
            kind = kind.label(),
            was,
            price = price.as_str()
        )),
        Asking::New { since: None } | Asking::Earlier => None,
    };
    let with = |text: String| match &before {
        Some(before) => format!("{before}\n{text}"),
        None => text,
    };
    let kind_said = kind.label();
    if yes {
        let note = if asking == Asking::Earlier {
            t!(
                "worker_first_deploy.line_note_agreed",
                kind = kind_said,
                name,
                product,
                env,
                place,
                price = price_said
            )
        } else {
            t!(
                "worker_first_deploy.line_note",
                kind = kind_said,
                name,
                product,
                env,
                place,
                price = price_said
            )
        };
        Say { quiet: false }.line(&with(note));
        return Ok(());
    }
    let question = if asking == Asking::Earlier {
        t!(
            "worker_first_deploy.line_question_agreed",
            kind = kind_said,
            name,
            product,
            env,
            place,
            price = price_said
        )
    } else {
        t!(
            "worker_first_deploy.line_question",
            kind = kind_said,
            name,
            product,
            env,
            place,
            price = price_said
        )
    };
    if reach.confirm(&with(question)).map_err(failed)? {
        Ok(())
    } else {
        Err(CliError::new(
            Code::Declined,
            t!(
                "worker_first_deploy.line_declined",
                kind = kind.label(),
                env
            ),
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
        /// Refused with this code and data.
        Refused(String, Value),
        /// No answer.
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
        /// kept here, as not to be sent again, as it was sent.
        sent: RefCell<Vec<(String, Value, bool)>>,
        says_yes: RefCell<Vec<bool>>,
        asked: RefCell<Vec<String>>,
        keys: Cell<u32>,
        pauses: Cell<u32>,
        /// The catalogue's price of each plan, in cents.
        cents: Cell<f64>,
        /// The plans the catalogue does not offer.
        unoffered: RefCell<Vec<&'static str>>,
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
                cents: Cell::new(12.5),
                unoffered: RefCell::new(Vec::new()),
            }
        }

        fn kept_of(&self, kind: LineKind) -> Option<Kept> {
            load(&self.store)
                .expect("readable")
                .starts
                .get(&file_key(&pin(), kind))
                .cloned()
        }

        fn kept(&self) -> Option<Kept> {
            self.kept_of(LineKind::Grpc)
        }

        fn keep(&self, kind: LineKind, line: &Kept) {
            let mut starts = load(&self.store).expect("readable");
            starts.starts.insert(file_key(&pin(), kind), line.clone());
            write(&self.store, &starts).expect("kept");
        }

        fn open_one(&self, kind: Option<LineKind>, product: Option<&str>) {
            self.open.borrow_mut().push(OpenLine {
                id: START_ID.to_owned(),
                kind: kind.map(account_kind),
                product_id: product.map(str::to_owned),
            });
        }

        fn refuse(&self, code: &str, data: Value) {
            self.answers
                .borrow_mut()
                .push(Answer::Refused(code.to_owned(), data));
        }
    }

    fn pin() -> String {
        kept::pin_key("user-100001", "bot", "prod")
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
            let kind = body["kind"].as_str().unwrap_or("grpc").to_owned();
            let kept_then = LineKind::ALL
                .into_iter()
                .filter(|k| account_kind(*k).as_str() == kind)
                .filter_map(|k| self.kept_of(k))
                .any(|k| k.key.as_deref() == Some(key.as_str()) && !k.resend);
            self.sent
                .borrow_mut()
                .push((key.as_str().to_owned(), body.clone(), kept_then));
            let answer = if self.answers.borrow().is_empty() {
                Answer::Started { reads: 0 }
            } else {
                self.answers.borrow_mut().remove(0)
            };
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
                Answer::Lost => Err(WorkerError::Api(erpc_api::ApiError::Malformed(
                    "lost on the way".to_owned(),
                ))),
                Answer::Refused(code, data) => Err(WorkerError::Refused(Refusal {
                    status: 409,
                    code: Some(AccountCode::from(code.as_str())),
                    message: Some("open the dashboard and press retry".to_owned()),
                    data,
                })),
            }
        }

        async fn plan(&self, _: LineKind, asked: Option<&str>) -> Result<Plan, CliError> {
            if asked.is_some_and(|a| self.unoffered.borrow().contains(&a)) {
                return Err(failed("not offered".to_owned()));
            }
            Ok(Plan {
                id: asked.unwrap_or("prod_grpc_1").to_owned(),
                cents: self.cents.get(),
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

    fn target() -> Target<'static> {
        Target {
            ip: IP,
            region: Some("amsterdam"),
        }
    }

    async fn run(
        fake: &Fake,
        lines: &[(LineKind, Option<String>)],
        yes: bool,
    ) -> Result<Vec<String>, CliError> {
        run_agreed(fake, lines, yes, Agreed::default()).await
    }

    /// [`run`], the lines of `agreed` agreed to by this run's own yes, and
    /// an app that needs none.
    async fn run_agreed(
        fake: &Fake,
        lines: &[(LineKind, Option<String>)],
        yes: bool,
        agreed: Agreed,
    ) -> Result<Vec<String>, CliError> {
        let needs = |_: LineKind, _: &[LineKind]| false;
        start_lines(
            fake,
            (&app(), "bot"),
            lines,
            target(),
            &Run {
                store: &fake.store,
                yes,
                agreed,
                needs: &needs,
            },
        )
        .await
    }

    async fn go(fake: &Fake, kind: LineKind, yes: bool) -> Result<Vec<String>, CliError> {
        run(fake, &[(kind, None)], yes).await
    }

    /// A line owed at the stand-in's plan and price.
    fn owed(agreed: bool) -> Kept {
        Kept::owed(
            &Plan {
                id: "prod_grpc_1".to_owned(),
                cents: 12.5,
                name: "Geyser gRPC Shared".to_owned(),
            },
            agreed,
        )
    }

    /// A start of a gRPC line kept here for `IP`.
    fn sent_kept(resend: bool) -> Kept {
        Kept {
            key: Some("f".repeat(32)),
            ip: Some(IP.to_string()),
            resend,
            ..owed(true)
        }
    }

    #[tokio::test]
    async fn a_line_is_asked_for_its_address_kept_before_it_is_sent_and_waited_for() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.answers.borrow_mut().push(Answer::Started { reads: 2 });
        let said = go(&fake, LineKind::Grpc, false).await.expect("started");
        let asked = fake.asked.borrow().clone();
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0].contains("gRPC line (Geyser gRPC Shared, product prod_grpc_1)")
                && asked[0].contains("for 203.0.113.10")
                && asked[0].contains("€0.1250 an hour, the hourly catalogue's price"),
            "{}",
            asked[0]
        );
        let sent = fake.sent.borrow().clone();
        assert_eq!(sent.len(), 1);
        assert!(
            sent[0].2,
            "kept before it was sent, as not to be sent again"
        );
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
    async fn under_yes_the_price_is_said_and_a_no_starts_nothing_and_lets_the_line_kept_go() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let _ = crate::node::common::heard::take_printed();
        go(&fake, LineKind::Grpc, true).await.expect("started");
        assert!(fake.asked.borrow().is_empty());
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("Starting a gRPC line")
                && printed.contains("for 203.0.113.10")
                && printed.contains("€0.1250 an hour"),
            "{printed}"
        );
        assert_eq!(fake.sent.borrow().len(), 1);
        // A no: nothing sent or kept, and the run goes on without it.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.says_yes.borrow_mut().push(false);
        go(&fake, LineKind::Grpc, false).await.expect("goes on");
        assert!(fake.sent.borrow().is_empty());
        assert_eq!(fake.kept(), None);
        // A no to a line kept here, owed: it is let go, and said.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &owed(false));
        fake.says_yes.borrow_mut().push(false);
        let _ = crate::node::common::heard::take_printed();
        run(&fake, &[], false).await.expect("goes on");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("no longer keeps it")
                && printed.contains("does not add a line to it yet"),
            "{printed}"
        );
        assert_eq!(fake.kept(), None);
        assert!(fake.sent.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_line_is_started_only_after_a_yes_of_its_own_run() {
        // Agreed to by this run's own yes, at this price: said, not asked
        // again.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &owed(true));
        let _ = crate::node::common::heard::take_printed();
        run_agreed(&fake, &[], false, Agreed::default().with(LineKind::Grpc))
            .await
            .expect("started");
        assert!(fake.asked.borrow().is_empty(), "not asked again");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("agreed to") && printed.contains("for 203.0.113.10"),
            "{printed}"
        );
        assert_eq!(fake.sent.borrow().len(), 1);
        assert_eq!(fake.kept(), None);
        // Agreed to on an earlier run: asked once in this one, at the
        // catalogue's price now, at the plan kept, not the cheapest.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(
            LineKind::Grpc,
            &Kept {
                product_id: "prod_grpc_2".to_owned(),
                ..owed(true)
            },
        );
        run(&fake, &[], false).await.expect("started");
        let asked = fake.asked.borrow().clone();
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0].contains("agreed to on an earlier run")
                && asked[0].contains("for 203.0.113.10")
                && asked[0].contains("€0.1250"),
            "{}",
            asked[0]
        );
        assert_eq!(fake.sent.borrow()[0].1["productId"], "prod_grpc_2");
        // Under a yes that says the prices (one a run again carries only
        // with --new-server; see the first step's tests): said, not asked.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &owed(true));
        let _ = crate::node::common::heard::take_printed();
        run(&fake, &[], true).await.expect("started");
        assert!(fake.asked.borrow().is_empty());
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(printed.contains("agreed to on an earlier run"), "{printed}");
        assert_eq!(fake.sent.borrow().len(), 1);
        // This run's yes, and the catalogue's price changed since: asked,
        // the price agreed said.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &owed(true));
        fake.cents.set(20.0);
        run_agreed(&fake, &[], false, Agreed::default().with(LineKind::Grpc))
            .await
            .expect("started");
        let asked = fake.asked.borrow().clone();
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0].contains("€0.1250") && asked[0].contains("€0.2000"),
            "{}",
            asked[0]
        );
        // This run's yes was for another kind, or the line agreed to no
        // longer, or asked for another plan: asked.
        for (line, lines, agreed) in [
            (owed(true), vec![], Agreed::default().with(LineKind::Shreds)),
            (owed(false), vec![], Agreed::default().with(LineKind::Grpc)),
            (
                owed(true),
                vec![(LineKind::Grpc, Some("prod_grpc_2".to_owned()))],
                Agreed::default().with(LineKind::Grpc),
            ),
        ] {
            let dir = tempfile::tempdir().expect("a directory");
            let fake = Fake::new(&dir);
            fake.keep(LineKind::Grpc, &line);
            run_agreed(&fake, &lines, false, agreed)
                .await
                .expect("started");
            assert_eq!(fake.asked.borrow().len(), 1);
            assert_eq!(fake.sent.borrow().len(), 1);
        }
    }

    #[tokio::test]
    async fn a_no_lets_the_line_go_and_the_deploy_goes_on_without_it_unless_the_app_needs_it() {
        // Two lines asked; a no to the first, a yes to the second.
        let both = [(LineKind::Grpc, None), (LineKind::Shreds, None)];
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &owed(true));
        *fake.says_yes.borrow_mut() = vec![false, true];
        let _ = crate::node::common::heard::take_printed();
        run(&fake, &both, false).await.expect("goes on");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("no longer keeps it") && printed.contains("goes on without it"),
            "{printed}"
        );
        assert_eq!(fake.kept(), None, "the gRPC line kept here let go");
        let sent = fake.sent.borrow().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1["kind"], "shreds");
        // The app needs the gRPC line: stopped, nothing sent at all.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        *fake.says_yes.borrow_mut() = vec![false, true];
        let needs = |kind: LineKind, present: &[LineKind]| {
            kind == LineKind::Grpc && !present.contains(&LineKind::Grpc)
        };
        let e = start_lines(
            &fake,
            (&app(), "bot"),
            &both,
            target(),
            &Run {
                store: &fake.store,
                yes: false,
                agreed: Agreed::default(),
                needs: &needs,
            },
        )
        .await
        .expect_err("stopped");
        assert_eq!(e.code, Code::Declined);
        assert!(
            e.message.contains("GRPC_ENDPOINT") && e.message.contains("no line was started"),
            "{}",
            e.message
        );
        assert!(
            e.hint.as_deref().is_some_and(|h| h.contains("--grpc")),
            "{e:?}"
        );
        assert_eq!(fake.asked.borrow().len(), 2, "every line asked first");
        assert!(fake.sent.borrow().is_empty());
        assert_eq!(fake.kept_of(LineKind::Shreds), None);
        // What a line on the record gives counts: the app needs gRPC or
        // Shreds, and a Shreds line is there already.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.lines
            .borrow_mut()
            .push(line("shreds", "active", Some("shreds.example.net:443")));
        fake.says_yes.borrow_mut().push(false);
        let either = |kind: LineKind, present: &[LineKind]| {
            kind == LineKind::Grpc && !present.contains(&LineKind::Shreds)
        };
        start_lines(
            &fake,
            (&app(), "bot"),
            &[(LineKind::Grpc, None)],
            target(),
            &Run {
                store: &fake.store,
                yes: false,
                agreed: Agreed::default(),
                needs: &either,
            },
        )
        .await
        .expect("goes on");
        assert!(fake.sent.borrow().is_empty());
    }

    /// What one answer to a line start leaves kept here: its key, and
    /// whether it is to be sent again.
    async fn answered(code: Option<(&str, Value)>) -> (Fake, CliError, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        match code {
            Some((code, data)) => fake.refuse(code, data),
            None => fake.answers.borrow_mut().push(Answer::Lost),
        }
        let e = go(&fake, LineKind::Grpc, false)
            .await
            .expect_err("not started");
        (fake, e, dir)
    }

    #[tokio::test]
    async fn an_answer_that_buys_nothing_lets_the_key_go_and_keeps_the_line_asked() {
        // The answers erpc_api::worker::money's start_server and start_line
        // say buy nothing, by the codes the account sends.
        let contract = [
            "invalid_request",
            "OUT_OF_STOCK",
            "REGION_DOWN",
            "insufficient_credit",
            "PAYMENT_AUTH_REQUIRED",
            "billing_address_required",
            "purchase_refused",
            "limit_exceeded",
            "UDP_FORWARDING_PREMIUM_NOT_ON_SALE",
            "unsupported_for_account",
            "worker_not_found",
            "env_not_found",
        ];
        let mut listed: Vec<&str> = NOTHING_BOUGHT.iter().map(AccountCode::as_str).collect();
        listed.sort_unstable();
        let mut written = contract.to_vec();
        written.sort_unstable();
        assert_eq!(listed, written);
        let gone: Vec<(&str, Value)> = contract
            .into_iter()
            .map(|c| (c, Value::Null))
            .chain([
                ("start_ended", Value::Null),
                ("start_pending", json!({ "startId": START_ID })),
            ])
            .collect();
        assert_eq!(gone.len(), 14);
        for (code, data) in gone {
            let (fake, e, _dir) = answered(Some((code, data))).await;
            let kept = fake.kept().expect("the line asked stays");
            assert_eq!(kept.key, None, "{code}: its key goes");
            assert!(!kept.agreed, "{code}: asked again");
            assert_eq!(kept.product_id, "prod_grpc_1");
            assert!(
                e.message.contains("let the line start's key go")
                    && !e.message.contains("dashboard"),
                "{code}: {}",
                e.message
            );
            let hint = e.hint.clone().unwrap_or_default();
            assert!(!hint.contains("buys no second line"), "{code}: {hint}");
            // The next run asks again, and starts it under a new key.
            go(&fake, LineKind::Grpc, false).await.expect("started");
            assert_eq!(fake.asked.borrow().len(), 2, "{code}");
            assert_eq!(fake.keys.get(), 2, "{code}: a new key");
            assert_eq!(fake.kept(), None);
        }
        // Ended meanwhile, and another start open, say so.
        let (_, e, _dir) = answered(Some(("start_ended", Value::Null))).await;
        assert!(
            e.message.contains("ended while it was being started"),
            "{}",
            e.message
        );
        let (_, e, _dir) = answered(Some(("start_pending", json!({ "startId": START_ID })))).await;
        assert!(
            e.message.contains("another start") && e.message.contains(START_ID),
            "{}",
            e.message
        );
        assert!(
            e.hint.as_deref().is_some_and(|h| h.contains(START_ID)),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn an_answer_that_says_to_send_it_again_or_none_keeps_the_key_to_send_again() {
        for (code, data) in [
            (
                Some("start_pending"),
                json!({ "retry": true, "startId": START_ID }),
            ),
            (Some("purchase_unavailable"), json!({ "startId": START_ID })),
            (Some("rate_limited"), Value::Null),
            (None, Value::Null),
        ] {
            let (fake, e, _dir) = answered(code.map(|c| (c, data))).await;
            let kept = fake.kept().expect("kept");
            assert!(kept.resend, "{code:?}: to be sent again");
            let key = kept.key.clone().expect("its key");
            assert!(
                e.message
                    .contains("keeps the line start's key, to send it again"),
                "{code:?}: {}",
                e.message
            );
            if code == Some("rate_limited") {
                assert!(e.message.contains("took no start"), "{}", e.message);
            }
            if code.is_none() {
                assert!(e.message.contains("is not known"), "{}", e.message);
            }
            // The next run, nothing open: the same key, the same body, its
            // price asked again.
            go(&fake, LineKind::Grpc, false).await.expect("sent again");
            let sent = fake.sent.borrow().clone();
            assert_eq!(sent.len(), 2, "{code:?}");
            assert_eq!(sent[1].0, key, "{code:?}: the same key");
            assert!(
                sent[1].2,
                "{code:?}: kept as not to be sent again as it is sent"
            );
            assert_eq!(sent[0].1, sent[1].1, "{code:?}: the same body");
            assert_eq!(fake.keys.get(), 1, "{code:?}: no new key");
            assert_eq!(fake.asked.borrow().len(), 2, "{code:?}");
            assert!(
                fake.asked.borrow()[1].contains("same start"),
                "{}",
                fake.asked.borrow()[1]
            );
        }
        // Open in the account as the one kept here: sent again too.
        let (fake, _, _dir) = answered(Some((
            "purchase_unavailable",
            json!({ "startId": START_ID }),
        )))
        .await;
        fake.open_one(Some(LineKind::Grpc), Some("prod_grpc_1"));
        go(&fake, LineKind::Grpc, false).await.expect("sent again");
        assert_eq!(fake.keys.get(), 1);
        assert_eq!(fake.sent.borrow().len(), 2);
    }

    #[tokio::test]
    async fn an_answer_that_settles_nothing_keeps_the_key_never_to_send_again() {
        // Every code the account may answer that is not one of the start
        // contract's classes: held, never sent again.
        let others = [
            "IDEMPOTENCY_CONFLICT",
            "something_new",
            "already_attached",
            "start_not_found",
            "slot_occupied",
            "revision_conflict",
            "servers_attached",
            "not_adoptable",
            "app_running_elsewhere",
            "user_not_found",
        ];
        let mut cases = vec![(
            "start_unsettled",
            json!({ "reason": "lookup_unavailable", "startId": START_ID }),
            "has not settled",
        )];
        cases.extend(others.map(|code| (code, Value::Null, "is not known")));
        for (code, data, said) in cases {
            let (fake, e, _dir) = answered(Some((code, data))).await;
            let kept = fake.kept().expect("kept");
            assert!(!kept.resend, "{code}: never sent again");
            assert!(
                e.message.contains(said)
                    && e.message.contains("does not send it again")
                    && !e.message.contains("dashboard"),
                "{code}: {}",
                e.message
            );
            let hint = e.hint.clone().unwrap_or_default();
            assert!(!hint.contains("buys no second line"), "{code}: {hint}");
            assert!(hint.contains("`erpc worker status"), "{code}: {hint}");
            if code == "start_unsettled" {
                assert!(
                    e.message.contains(START_ID) && hint.contains(START_ID),
                    "{code}: {e:?}"
                );
                assert_eq!(kept.start.as_deref(), Some(START_ID));
            }
            // The next run under --yes: stopped, nothing sent, the key kept.
            let e = go(&fake, LineKind::Grpc, true).await.expect_err("stopped");
            assert!(
                e.hint
                    .as_deref()
                    .is_some_and(|h| h.contains("without --yes")),
                "{e:?}"
            );
            assert_eq!(fake.sent.borrow().len(), 1);
            assert_eq!(fake.kept(), Some(kept.clone()));
            // At a terminal: asked whether to let it go; a no keeps it.
            fake.says_yes.borrow_mut().push(false);
            let e = go(&fake, LineKind::Grpc, false).await.expect_err("kept");
            assert_eq!(e.code, Code::Declined);
            assert!(
                fake.asked.borrow()[1].contains("new purchase"),
                "{}",
                fake.asked.borrow()[1]
            );
            assert_eq!(fake.kept(), Some(kept.clone()));
            assert_eq!(fake.sent.borrow().len(), 1);
            // A yes lets it go: a new start, under a new key, its price asked.
            go(&fake, LineKind::Grpc, false).await.expect("started");
            assert_eq!(fake.keys.get(), 2, "{code}");
            assert_ne!(fake.sent.borrow()[1].0, kept.key.clone().expect("a key"));
            assert_eq!(fake.asked.borrow().len(), 4, "{code}");
        }
    }

    #[tokio::test]
    async fn a_start_that_bought_a_line_not_on_the_record_is_never_let_go_nor_replaced() {
        let (fake, e, _dir) = answered(Some((
            "start_unsettled",
            json!({ "reason": "start_mismatch", "startId": START_ID }),
        )))
        .await;
        assert!(
            e.message.contains("not put on the environment's record")
                && e.message.contains("does not send it again"),
            "{}",
            e.message
        );
        let hint = e.hint.clone().unwrap_or_default();
        assert!(
            hint.contains(START_ID)
                && hint.contains("`erpc worker status")
                && !hint.contains("let"),
            "{hint}"
        );
        let kept = fake.kept().expect("kept");
        assert_eq!(kept.unsettled.as_deref(), Some(MISMATCH));
        // Each run after, at a terminal or under --yes: stopped, naming the
        // start, nothing asked or sent, the key kept.
        for yes in [false, true] {
            let e = go(&fake, LineKind::Grpc, yes).await.expect_err("stopped");
            assert!(
                e.message.contains("bought a line it has not put") && e.message.contains(START_ID),
                "{}",
                e.message
            );
            assert!(
                e.hint
                    .as_deref()
                    .is_some_and(|h| h.contains("ERPC support")),
                "{e:?}"
            );
            assert_eq!(fake.asked.borrow().len(), 1, "only the first price");
            assert_eq!(fake.sent.borrow().len(), 1);
            assert_eq!(fake.kept(), Some(kept.clone()));
        }
    }

    #[test]
    fn a_mark_to_send_again_that_cannot_be_kept_says_the_next_run_does_not() {
        // The answer's mark is written over what another run kept since:
        // refused, and said.
        let dir = tempfile::tempdir().expect("a directory");
        let store = dir.path().join(FILE);
        let sent = sent_kept(false);
        let file_key = file_key(&pin(), LineKind::Grpc);
        let e = not_started(
            &WorkerError::Api(erpc_api::ApiError::Malformed("lost".to_owned())),
            (&app(), "bot", LineKind::Grpc),
            (&store, &file_key, &sent),
        );
        assert!(
            e.hint
                .as_deref()
                .is_some_and(|h| h.contains("could not keep the mark")),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn every_open_start_is_read_and_only_the_one_kept_here_is_sent_again() {
        // The one kept here, and one of a kind erpc cannot tell: refused.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &sent_kept(true));
        fake.open_one(Some(LineKind::Grpc), Some("prod_grpc_1"));
        fake.open_one(None, None);
        let e = go(&fake, LineKind::Grpc, false).await.expect_err("refused");
        assert!(e.message.contains("does not know"), "{}", e.message);
        assert!(fake.sent.borrow().is_empty() && fake.asked.borrow().is_empty());
        // Two of the kind: refused.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &sent_kept(true));
        fake.open_one(Some(LineKind::Grpc), Some("prod_grpc_1"));
        fake.open_one(Some(LineKind::Grpc), Some("prod_grpc_1"));
        let e = go(&fake, LineKind::Grpc, false).await.expect_err("refused");
        assert!(e.message.contains("2 starts"), "{}", e.message);
        assert!(fake.sent.borrow().is_empty());
        // One this machine did not keep, one kept not to be sent again, one
        // for another plan than kept: refused, each said so.
        for (kept, product, said) in [
            (None, Some("prod_grpc_1"), "keeps no start"),
            (Some(owed(true)), Some("prod_grpc_1"), "keeps no start"),
            (
                Some(sent_kept(false)),
                Some("prod_grpc_1"),
                "did not say to",
            ),
            (Some(sent_kept(true)), Some("prod_grpc_2"), "while another"),
            (Some(sent_kept(true)), None, "while another"),
        ] {
            let dir = tempfile::tempdir().expect("a directory");
            let fake = Fake::new(&dir);
            if let Some(kept) = &kept {
                fake.keep(LineKind::Grpc, kept);
            }
            fake.open_one(Some(LineKind::Grpc), product);
            let e = go(&fake, LineKind::Grpc, false).await.expect_err("refused");
            assert!(
                e.message.contains(START_ID) && e.message.contains(said),
                "{said}: {}",
                e.message
            );
            assert!(e.hint.as_deref().is_some_and(|h| h.contains(START_ID)));
            assert!(fake.sent.borrow().is_empty() && fake.asked.borrow().is_empty());
        }
        // A start of another kind open is not this one's.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.open_one(Some(LineKind::Shreds), None);
        go(&fake, LineKind::Grpc, false).await.expect("started");
        assert_eq!(fake.sent.borrow().len(), 1);
    }

    #[tokio::test]
    async fn a_start_kept_for_another_plan_or_place_is_not_sent_there() {
        // Open, kept to be sent again, for another address, or (an
        // Unlimited RPC) another region: refused, nothing sent.
        let unlimited = Kept {
            ip: None,
            region: Some("tokyo".to_owned()),
            ..sent_kept(true)
        };
        for (kind, kept) in [
            (
                LineKind::Grpc,
                Kept {
                    ip: Some("198.51.100.7".to_owned()),
                    ..sent_kept(true)
                },
            ),
            (LineKind::Unlimited, unlimited),
        ] {
            let dir = tempfile::tempdir().expect("a directory");
            let fake = Fake::new(&dir);
            fake.keep(kind, &kept);
            fake.open_one(Some(kind), Some("prod_grpc_1"));
            let e = go(&fake, kind, false).await.expect_err("refused");
            assert!(e.message.contains("is not sent again"), "{}", e.message);
            assert!(fake.sent.borrow().is_empty() && fake.asked.borrow().is_empty());
            assert_eq!(fake.kept_of(kind), Some(kept));
        }
        // Open, for another plan than this run asks: refused, the plan to
        // send it again with said.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &sent_kept(true));
        fake.open_one(Some(LineKind::Grpc), Some("prod_grpc_1"));
        let e = run(
            &fake,
            &[(LineKind::Grpc, Some("prod_grpc_2".to_owned()))],
            false,
        )
        .await
        .expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        assert!(
            e.hint
                .as_deref()
                .is_some_and(|h| h.contains("--grpc-plan prod_grpc_1")),
            "{e:?}"
        );
        assert!(fake.sent.borrow().is_empty());
        // Nothing open, kept to be sent again, and this run asks another
        // plan: not sent again; under --yes stopped, nothing sent.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &sent_kept(true));
        let e = run(
            &fake,
            &[(LineKind::Grpc, Some("prod_grpc_2".to_owned()))],
            true,
        )
        .await
        .expect_err("stopped");
        assert!(e.message.contains("plan prod_grpc_1"), "{}", e.message);
        assert!(fake.sent.borrow().is_empty());
        assert_eq!(fake.kept(), Some(sent_kept(true)));
        // Nothing open, kept for another address: asked whether to let it
        // go, then a new start for where the server is now, asked.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let elsewhere = Kept {
            ip: Some("198.51.100.7".to_owned()),
            ..sent_kept(true)
        };
        fake.keep(LineKind::Grpc, &elsewhere);
        let e = go(&fake, LineKind::Grpc, true).await.expect_err("stopped");
        assert!(e.message.contains("for 198.51.100.7"), "{}", e.message);
        assert!(fake.sent.borrow().is_empty());
        go(&fake, LineKind::Grpc, false).await.expect("started");
        let asked = fake.asked.borrow().clone();
        assert_eq!(asked.len(), 2);
        assert!(
            asked[0].contains("Let this machine forget it"),
            "{}",
            asked[0]
        );
        assert!(asked[1].contains("for 203.0.113.10"), "{}", asked[1]);
        let sent = fake.sent.borrow().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1["ip"], "203.0.113.10");
        assert_ne!(Some(sent[0].0.clone()), elsewhere.key);
    }

    #[tokio::test]
    async fn a_line_on_record_is_used_as_it_is_and_lets_what_is_kept_go() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &sent_kept(false));
        fake.lines
            .borrow_mut()
            .push(line("grpc", "active", Some("grpc.example.net:443")));
        go(&fake, LineKind::Grpc, false).await.expect("there");
        assert!(fake.sent.borrow().is_empty() && fake.asked.borrow().is_empty());
        assert_eq!(fake.kept(), None);
        // One ended there is no line: a new one is asked.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.lines
            .borrow_mut()
            .push(line("grpc", "cancelled", None));
        go(&fake, LineKind::Grpc, false).await.expect("started");
        assert_eq!(fake.sent.borrow().len(), 1);
        assert_eq!(fake.asked.borrow().len(), 1);
        // One active without its endpoint yet is waited for.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let mut pending = line("grpc", "active", Some("grpc.example.net:443"));
        pending["pending"] = json!(true);
        fake.lines.borrow_mut().push(pending);
        let e = go(&fake, LineKind::Grpc, false).await.expect_err("waited");
        assert!(e.message.contains("is not active yet"), "{}", e.message);
        assert_eq!(fake.pauses.get(), WAIT.0);
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
        assert!(
            fake.asked.borrow()[0].contains("in amsterdam"),
            "{}",
            fake.asked.borrow()[0]
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
            &Run {
                store: &fake.store,
                yes: false,
                agreed: Agreed::default(),
                needs: &|_, _| false,
            },
        )
        .await
        .expect_err("refused");
        assert!(!e.message.is_empty());
        assert!(fake.sent.borrow().is_empty());
        assert_eq!(fake.kept_of(LineKind::Unlimited), None);
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
        assert!(
            e.hint
                .as_deref()
                .is_some_and(|h| h.contains("kept on this machine")),
            "{e:?}"
        );
    }

    fn plan(id: &str) -> Plan {
        Plan {
            id: id.to_owned(),
            cents: 12.5,
            name: "Geyser gRPC Shared".to_owned(),
        }
    }

    #[test]
    fn a_first_deploy_asks_each_line_before_the_server_and_keeps_them_owed() {
        let dir = tempfile::tempdir().expect("a directory");
        let store = dir.path().join(FILE);
        let asked = vec![
            (LineKind::Grpc, plan("prod_grpc_1")),
            (LineKind::Unlimited, plan("prod_unl_1")),
        ];
        let owing =
            Owing::read(&store, (pin(), "prod"), (asked.clone(), Vec::new()), true).expect("read");
        assert_eq!(owing.kinds(), [LineKind::Grpc, LineKind::Unlimited]);
        let questions = RefCell::new(Vec::new());
        owing
            .agree(
                &|q| {
                    questions.borrow_mut().push(q.to_owned());
                    Ok(true)
                },
                false,
            )
            .expect("agreed");
        let questions = questions.into_inner();
        assert_eq!(questions.len(), 2);
        assert!(
            questions[0].contains("lets in the ERPC Worker's address")
                && questions[0].contains("€0.1250"),
            "{}",
            questions[0]
        );
        assert!(
            questions[1].contains("in the ERPC Worker's region"),
            "{}",
            questions[1]
        );
        let starts = load(&store).expect("readable");
        let grpc = &starts.starts[&file_key(&pin(), LineKind::Grpc)];
        assert!(grpc.agreed && grpc.key.is_none());
        assert_eq!(grpc.price, "0.1250");
        // A no: nothing kept.
        let dir = tempfile::tempdir().expect("a directory");
        let store = dir.path().join(FILE);
        let owing =
            Owing::read(&store, (pin(), "prod"), (asked.clone(), Vec::new()), true).expect("read");
        let e = owing.agree(&|_| Ok(false), false).expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert!(!store.exists());
        // Nothing asked, nothing kept: nothing written.
        let owing =
            Owing::read(&store, (pin(), "prod"), (Vec::new(), Vec::new()), false).expect("read");
        owing.agree(&|_| panic!("asked"), false).expect("agreed");
        owing.keep(false).expect("kept");
        assert!(!store.exists());
        // A no to a line an earlier run kept owed: it goes too.
        let mut starts = Starts::default();
        starts
            .starts
            .insert(file_key(&pin(), LineKind::Grpc), owed(true));
        write(&store, &starts).expect("written");
        let owing =
            Owing::read(&store, (pin(), "prod"), (asked.clone(), Vec::new()), false).expect("read");
        let e = owing.agree(&|_| Ok(false), false).expect_err("declined");
        assert!(
            e.message.contains("no longer keeps the gRPC line"),
            "{}",
            e.message
        );
        assert!(load(&store).expect("readable").starts.is_empty());
        // Under --yes: said, not asked.
        let owing = Owing::read(&store, (pin(), "prod"), (asked, Vec::new()), true).expect("read");
        let _ = crate::node::common::heard::take_printed();
        owing
            .agree(&|_| panic!("asked under --yes"), true)
            .expect("agreed");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(printed.contains("Starting a gRPC line"), "{printed}");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "each way what an earlier run kept is read, one after another"
    )]
    #[test]
    fn what_an_earlier_run_kept_is_asked_kept_or_let_go_as_erpc_toml_has_it() {
        let dir = tempfile::tempdir().expect("a directory");
        let store = dir.path().join(FILE);
        let keep = |kind: LineKind, line: &Kept| {
            let mut starts = load(&store).expect("readable");
            starts.starts.insert(file_key(&pin(), kind), line.clone());
            write(&store, &starts).expect("kept");
        };
        keep(LineKind::Shreds, &owed(true));
        keep(LineKind::Unlimited, &sent_kept(false));
        keep(LineKind::Grpc, &owed(false));
        // Kept in the account: those owed asked again before the server is
        // bought, one agreed to earlier said so first; a start kept under a
        // key refuses the run.
        let again = Owing::owed_again(&store, &pin(), &[], false).expect("read");
        assert_eq!(
            again,
            [
                (LineKind::Grpc, "prod_grpc_1".to_owned()),
                (LineKind::Shreds, "prod_grpc_1".to_owned())
            ]
        );
        assert!(
            Owing::owed_again(&store, &pin(), &[], true)
                .expect("read")
                .is_empty()
        );
        let owing = Owing::read(
            &store,
            (pin(), "prod"),
            (
                Vec::new(),
                again.iter().map(|(k, id)| (*k, plan(id))).collect(),
            ),
            false,
        )
        .expect("read");
        assert_eq!(
            owing.kinds(),
            [LineKind::Grpc, LineKind::Shreds, LineKind::Unlimited]
        );
        let e = owing
            .refuse_kept_starts(&app(), "bot")
            .expect_err("refused");
        assert!(
            e.message.contains("Unlimited RPC line start") && e.message.contains("not known"),
            "{}",
            e.message
        );
        let questions = RefCell::new(Vec::new());
        let _ = crate::node::common::heard::take_printed();
        let agreed = owing
            .agree(
                &|q| {
                    questions.borrow_mut().push(q.to_owned());
                    Ok(true)
                },
                false,
            )
            .expect("agreed");
        assert_eq!(questions.borrow().len(), 2);
        assert!(agreed.has(LineKind::Grpc) && agreed.has(LineKind::Shreds));
        assert!(!agreed.has(LineKind::Unlimited));
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("Shreds line") && printed.contains("agreed to on an earlier run"),
            "{printed}"
        );
        // One kept and not agreed to is asked, not said as agreed.
        assert!(!printed.contains("gRPC line"), "{printed}");
        let mut starts = load(&store).expect("readable");
        starts.starts.remove(&file_key(&pin(), LineKind::Grpc));
        write(&store, &starts).expect("written");
        // Asked not to be agreed again: one owed already stays as it is,
        // and a start's key is never written over.
        let owing = Owing::read(
            &store,
            (pin(), "prod"),
            (
                vec![
                    (LineKind::Shreds, plan("prod_shreds_2")),
                    (LineKind::Unlimited, plan("prod_unl_2")),
                    (LineKind::Grpc, plan("prod_grpc_1")),
                ],
                Vec::new(),
            ),
            false,
        )
        .expect("read");
        owing.keep(false).expect("kept");
        let starts = load(&store).expect("readable");
        assert_eq!(
            starts.starts[&file_key(&pin(), LineKind::Shreds)],
            owed(true)
        );
        assert_eq!(
            starts.starts[&file_key(&pin(), LineKind::Unlimited)],
            sent_kept(false)
        );
        assert!(!starts.starts[&file_key(&pin(), LineKind::Grpc)].agreed);
        // Agreed to again (over what is owed): a start's key is never
        // written over.
        let owing = Owing::read(
            &store,
            (pin(), "prod"),
            (vec![(LineKind::Unlimited, plan("prod_unl_2"))], Vec::new()),
            false,
        )
        .expect("read");
        owing.agree(&|_| Ok(true), false).expect("agreed");
        assert_eq!(
            load(&store).expect("readable").starts[&file_key(&pin(), LineKind::Unlimited)],
            sent_kept(false)
        );
        // erpc.toml has nothing for it: what is owed goes, but for what is
        // asked; a start's key stays.
        let owing = Owing::read(
            &store,
            (pin(), "prod"),
            (vec![(LineKind::Grpc, plan("prod_grpc_1"))], Vec::new()),
            true,
        )
        .expect("read");
        assert_eq!(owing.kinds(), [LineKind::Grpc]);
        owing.agree(&|_| Ok(true), false).expect("agreed");
        let starts = load(&store).expect("readable");
        assert!(
            !starts
                .starts
                .contains_key(&file_key(&pin(), LineKind::Shreds))
        );
        assert!(starts.starts[&file_key(&pin(), LineKind::Grpc)].agreed);
        assert_eq!(
            starts.starts[&file_key(&pin(), LineKind::Unlimited)],
            sent_kept(false)
        );
    }

    #[test]
    fn a_no_on_the_first_question_keeps_a_start_kept_under_a_key() {
        let dir = tempfile::tempdir().expect("a directory");
        let store = dir.path().join(FILE);
        let mut starts = Starts::default();
        starts
            .starts
            .insert(file_key(&pin(), LineKind::Grpc), sent_kept(false));
        write(&store, &starts).expect("written");
        let owing = Owing::read(
            &store,
            (pin(), "prod"),
            (vec![(LineKind::Grpc, plan("prod_grpc_1"))], Vec::new()),
            false,
        )
        .expect("read");
        let e = owing.agree(&|_| Ok(false), false).expect_err("declined");
        assert!(!e.message.contains("no longer keeps"), "{}", e.message);
        assert_eq!(
            load(&store).expect("readable").starts[&file_key(&pin(), LineKind::Grpc)],
            sent_kept(false)
        );
    }

    /// An app whose erpc.toml requires `requires`.
    fn manifest(dir: &tempfile::TempDir, requires: &str) -> erpc_worker::manifest::Manifest {
        let path = dir.path().join("erpc.toml");
        std::fs::write(
            &path,
            format!("name = \"bot\"\nchain = \"solana\"\n[run]\nrequires = [{requires}]\n"),
        )
        .expect("erpc.toml");
        erpc_worker::manifest::Manifest::load(&path).expect("reads")
    }

    #[tokio::test]
    async fn the_deploy_starts_the_lines_kept_here_and_knows_which_the_app_needs() {
        // Nothing named, nothing kept: nothing read beyond the account's id.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        let m = manifest(&dir, "");
        for_deploy_with(&fake, (&app(), &m), &Lines::default(), &fake.store)
            .await
            .expect("nothing");
        assert!(fake.asked.borrow().is_empty() && fake.sent.borrow().is_empty());
        // Nothing named, one kept here: asked and started.
        fake.keep(LineKind::Grpc, &owed(true));
        for_deploy_with(&fake, (&app(), &m), &Lines::default(), &fake.store)
            .await
            .expect("started");
        assert_eq!(fake.asked.borrow().len(), 1);
        assert_eq!(fake.sent.borrow().len(), 1);
        // This run's yes agreed to it, and --yes not given: started unasked.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &owed(true));
        let agreed = Lines {
            agreed: Agreed::default().with(LineKind::Grpc),
            ..Lines::default()
        };
        for_deploy_with(&fake, (&app(), &m), &agreed, &fake.store)
            .await
            .expect("started");
        assert!(fake.asked.borrow().is_empty());
        assert_eq!(fake.sent.borrow().len(), 1);
        // The app requires the setting the line gives: a no stops.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &owed(true));
        fake.says_yes.borrow_mut().push(false);
        let m = manifest(&dir, "\"GRPC_ENDPOINT\"");
        let e = for_deploy_with(&fake, (&app(), &m), &Lines::default(), &fake.store)
            .await
            .expect_err("stopped");
        assert!(e.message.contains("GRPC_ENDPOINT"), "{}", e.message);
        assert!(fake.sent.borrow().is_empty());
        // It does not: the deploy goes on without it.
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &owed(true));
        fake.says_yes.borrow_mut().push(false);
        let m = manifest(&dir, "\"OTHER\"");
        for_deploy_with(&fake, (&app(), &m), &Lines::default(), &fake.store)
            .await
            .expect("goes on");
        assert!(fake.sent.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_line_kept_owed_is_asked_at_its_plan_now_or_let_go_when_it_is_not_offered() {
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(&dir);
        fake.keep(LineKind::Grpc, &owed(true));
        fake.keep(
            LineKind::Shreds,
            &Kept {
                product_id: "prod_gone".to_owned(),
                ..owed(true)
            },
        );
        fake.unoffered.borrow_mut().push("prod_gone");
        let _ = crate::node::common::heard::take_printed();
        let owing = owing_with(&fake, (pin(), "prod"), &[], (&fake.store, false))
            .await
            .expect("read");
        assert_eq!(owing.kinds(), [LineKind::Grpc]);
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("plan prod_gone") && printed.contains("lets it go"),
            "{printed}"
        );
        assert_eq!(fake.kept_of(LineKind::Shreds), None);
        assert!(fake.kept().is_some());
        // A plan this run names that is not offered: refused.
        fake.unoffered.borrow_mut().push("prod_grpc_9");
        let lines = [(LineKind::Grpc, Some("prod_grpc_9".to_owned()))];
        assert!(
            owing_with(&fake, (pin(), "prod"), &lines, (&fake.store, false))
                .await
                .is_err()
        );
    }
}
