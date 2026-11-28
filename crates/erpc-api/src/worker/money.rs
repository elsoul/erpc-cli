// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Starting, switching and ending what an erpc worker environment runs on,
//! through the account's worker routes: the servers and data lines are paid
//! for by the hour, and the account records each in the environment as it
//! starts it and takes it off as it ends it.
//!
//! **A start** is sent with a [`StartKey`] the caller has kept first. The
//! same key sent again is the same start, never a second purchase. The
//! answer says whether it is sent again:
//! - [`super::Code::StartPending`] with [`Refusal::retry`], and
//!   [`super::Code::PurchaseUnavailable`]: this start may have bought what
//!   it was for. The same key is sent again, or [`retry_start`] names
//!   [`Refusal::start_id`]; never a new key.
//! - [`super::Code::StartPending`] without [`Refusal::retry`]: another start
//!   of the environment is open ([`Refusal::start_id`]), and this key bought
//!   nothing. That start is settled first; this key is sent again only if
//!   the environment, read again then, shows the other start did not buy
//!   what this one is for.
//! - No answer at all (a failed connection, a timeout, a reply that could
//!   not be read): it is not known to have bought nothing. The key is kept
//!   and sent again, never a new one.
//! - [`super::Code::StartEnded`] (what it was buying was ended meanwhile)
//!   and [`super::Code::StartUnsettled`], **whatever its reason**, one this
//!   version does not know included: the key is never sent to a start
//!   again, and the start is not retried ([`retry_start`] sends a start
//!   that is still open again under the same purchase) unless the reason
//!   says so. What comes next is the reason's, by the request it answered
//!   ([`super::Code::StartUnsettled`]); another purchase takes a new key.
//!
//! A key that was lost is found again through the environment's open
//! starts ([`list_starts`]), and when there is none, through its servers
//! and lines ([`super::get_env`]): more than before means the start bought
//! what it was for.
//!
//! **An end** names what it ends by the id the environment shows it with,
//! so an end sent after a switch cannot end another server. The account
//! ends the product and takes it off the environment; one that is no longer
//! the account's is taken off without an end. An end can also be refused
//! with the product's own failure, passed on as it came: an upper-case
//! code with no details, read as [`Other`](super::Code::Other) unless this
//! version names it (as [`super::Code::PaymentAuthRequired`]); among them
//! `RATE_LIMITED`, `LOCK_HELD`, `OPERATION_IN_PROGRESS` and
//! `ROW_CHANGED_RETRY` pass if sent again later. Its message says what
//! happened.
//!
//! **A caller does not send a repoint and an end of a server for the same
//! environment at the same time**, and this module does not keep them
//! apart: a line could be left pointing at an address that is no longer
//! the account's.
//!
//! The requests that can take a while on the account's side (starts,
//! retries, resolves, ends, repoints, and deletes that end what they hold)
//! are each given [`SLOW_TIMEOUT`]; the others, the usual one.

use core::time::Duration;

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    AdoptSlot, DETAIL_MAX, EnvDetail, LineKind, Refusal, Slot, WorkerError, Written, encode,
    env_in, env_url, one_line, reply, token, written_env,
};
use crate::ApiError;

/// How long a request that can take a while on the account's side may
/// take: a start, a retry, a resolve, an end, a repoint, and a delete that
/// ends what it holds. A repoint is answered only once every line moved.
pub const SLOW_TIMEOUT: Duration = Duration::from_secs(150);

/// The key that makes a start the same one when it is sent again: 32
/// lowercase hexadecimal digits. Never printed: [`fmt::Debug`] redacts it.
///
/// [`fmt::Debug`]: core::fmt::Debug
#[derive(Clone, PartialEq, Eq)]
pub struct StartKey(String);

impl StartKey {
    /// `key`, when it is 32 lowercase hexadecimal digits.
    ///
    /// # Errors
    ///
    /// [`WorkerError::StartKey`] for anything else. The key is not kept in
    /// the error.
    pub fn new(key: impl Into<String>) -> Result<Self, WorkerError> {
        let key = key.into();
        if key.len() == 32 && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(key))
        } else {
            Err(WorkerError::StartKey)
        }
    }

    /// The key, to keep before the start is sent.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for StartKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StartKey(<redacted>)")
    }
}

/// The body that starts a server: its size and region. The account picks
/// the slot (the one in use when the environment has none, else the one
/// coming in) and, for an environment that has a server, keeps the new one
/// in the same range of sizes ([`EnvDetail::core_options`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct StartServer {
    /// Its cores: 1, 2, 4, 8 or 16.
    pub cores: u16,
    /// Its region.
    pub region: String,
    /// The revision of the environment the start was decided on: the
    /// account refuses a start of an environment at another revision
    /// ([`super::Code::RevisionConflict`]), buying nothing. A start sent
    /// again under its key while it is open, or once it is done, is
    /// answered as before, whatever this says; one the account released is
    /// checked as a new start is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
    /// The price of one hour the person was shown for it, in cents: the
    /// account refuses a start at any other price
    /// ([`super::Code::PriceChanged`], with [`Refusal::hourly_cents`]),
    /// buying nothing. A start sent again under its key while it is open,
    /// or once it is done, is answered as before, whatever this says; after
    /// a [`super::Code::PriceChanged`] the key holds nothing, and a send
    /// under it is checked again, as a new start is. Left out, the start is
    /// priced as the account prices it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hourly_cents: Option<u64>,
}

impl StartServer {
    /// A server of `cores` cores in `region`.
    #[must_use]
    pub fn new(cores: u16, region: impl Into<String>) -> Self {
        Self {
            cores,
            region: region.into(),
            expected_revision: None,
            expected_hourly_cents: None,
        }
    }

    /// The same start, made only at the price of one hour shown, `cents`.
    #[must_use]
    pub const fn at_price(mut self, cents: Option<u64>) -> Self {
        self.expected_hourly_cents = cents;
        self
    }

    /// The same start, made only while the environment is at `revision`.
    #[must_use]
    pub const fn at_revision(mut self, revision: u64) -> Self {
        self.expected_revision = Some(revision);
        self
    }
}

/// What a server start of one size costs, as the account prices it for an
/// environment ([`server_prices`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ServerPrice {
    /// The cores of the start.
    pub cores: u16,
    /// The memory of the server it buys, in GB.
    pub memory_gb: u32,
    /// The price of one hour, in cents of [`ServerPrices::currency`].
    pub hourly_cents: u64,
}

/// The sizes a server start takes for an environment now, each with its
/// price by the hour: the same plans [`start_server`] buys. The price is
/// the same in every region. It does not say whether a start can be made
/// now: the start may still be refused (out of stock, a start pending,
/// both slots held).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct ServerPrices {
    /// The currency of the prices: `eur`.
    pub currency: String,
    /// The sizes, fewest cores first; none when the account starts no
    /// server for the environment (its server in use is a bare-metal one,
    /// or of a plan it does not know).
    pub options: Vec<ServerPrice>,
    /// What a server asked about ([`server_prices`]'s `adopt`) costs by the
    /// hour now and once taken into the environment; `None` when it was not
    /// asked about, or the account does not say yet.
    #[serde(default)]
    pub adopt: Option<AdoptPrice>,
}

/// What taking a server into an environment does to its price, as the
/// account says it ([`server_prices`] asked with the server).
///
/// The names of these fields are the account's as far as they are known
/// now: they are read here only, and only here would they change.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AdoptPrice {
    /// How it is paid for: [`super::Billing::Hourly`] or
    /// [`super::Billing::Contract`]; `None` when the answer does not say.
    #[serde(default)]
    pub billing: Option<super::Billing>,
    /// What it costs by the hour now, in cents; `None` for one paid by
    /// contract.
    #[serde(default)]
    pub current_hourly_cents: Option<u64>,
    /// What it costs by the hour once taken in, in cents, which the take-in
    /// is sent with ([`super::AdoptServer::expecting`]); `None`: it keeps the
    /// price of its contract.
    #[serde(default)]
    pub hourly_cents: Option<u64>,
}

/// The body that starts a data line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct StartLine {
    /// What kind of line.
    pub kind: LineKind,
    /// The plan, by the product id the hourly catalogue gives it.
    pub product_id: String,
    /// The address a gRPC or Shreds line lets in: required for those, not
    /// sent for the others.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// The region of an Unlimited RPC: required for it, not sent for the
    /// others.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

impl StartLine {
    /// A line of `kind` on plan `product_id`, letting in `ip` (gRPC,
    /// Shreds) or in `region` (Unlimited RPC).
    #[must_use]
    pub fn new(
        kind: LineKind,
        product_id: impl Into<String>,
        ip: Option<String>,
        region: Option<String>,
    ) -> Self {
        Self {
            kind,
            product_id: product_id.into(),
            ip,
            region,
        }
    }

    /// What a retry of this start sends: the address and region it was
    /// started with.
    #[must_use]
    pub fn retry(&self) -> RetryStart {
        RetryStart {
            ip: self.ip.clone(),
            region: self.region.clone(),
        }
    }
}

/// The body of a retry: for a line, the address and region it was started
/// with; for a server, nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RetryStart {
    /// The address of a gRPC or Shreds line's start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// The region of an Unlimited RPC's start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// What a start was for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartOf {
    /// A server.
    Server,
    /// A data line of this kind.
    Line(LineKind),
    /// Something this version does not know, by the account's word,
    /// cleaned: kept, so that a start in the list is never missed.
    Other(String),
}

/// A start of the environment that is still open: the account has not yet
/// seen what it bought put on record, nor seen that it bought nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpenStart {
    /// Its id: what [`retry_start`] and [`resolve_start`] name.
    pub id: String,
    /// What it was for.
    pub of: StartOf,
    /// The cores of a server's start.
    pub cores: Option<u16>,
    /// The region it was started in.
    pub region: Option<String>,
    /// The plan of a line's start.
    pub product_id: Option<String>,
    /// When it was made.
    pub created_at: Option<String>,
    /// Whether it has been open for over an hour, after which
    /// [`resolve_start`] settles it.
    pub stale: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartWire {
    id: String,
    target: String,
    #[serde(default)]
    kind: Option<LineKind>,
    #[serde(default)]
    cores: Option<u16>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    product_id: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    stale: bool,
}

#[derive(Deserialize)]
struct StartsWire {
    starts: Vec<StartWire>,
}

/// The starts of a list, every one of them: one whose purpose this
/// version cannot tell (a target it does not know, a line without its
/// kind) is kept as [`StartOf::Other`], since a start missed is a start
/// that could be bought again.
fn open_starts(wire: StartsWire) -> Vec<OpenStart> {
    wire.starts
        .into_iter()
        .map(|s| {
            let of = match (s.target.as_str(), s.kind) {
                ("server", _) => StartOf::Server,
                ("line", Some(kind)) => StartOf::Line(kind),
                (target, _) => StartOf::Other(token(target)),
            };
            OpenStart {
                id: s.id,
                of,
                cores: s.cores,
                region: s.region,
                product_id: s.product_id,
                created_at: s.created_at,
                stale: s.stale,
            }
        })
        .collect()
}

/// How a start that had been open for over an hour was settled.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Resolved {
    /// It had bought what it was for, which is now on record in the
    /// environment. `created` is whether this request put it there.
    Committed {
        /// The environment after.
        env: Box<EnvDetail>,
        /// Whether this request put it on record.
        created: bool,
    },
    /// It had bought nothing, and is closed. A new start may be made, with
    /// a new key.
    Released,
}

/// What an end answered.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Ended {
    /// Ended and taken off (a line bought as part of a Bundle only taken
    /// off): the environment after.
    Done(Box<EnvDetail>),
    /// The end is under way and not finished; the environment keeps it on
    /// record until it is. Send the same end again later.
    Pending,
}

/// What a delete that ends what it holds answered.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Deleting {
    /// Everything was ended, but for the lines bought as part of a Bundle,
    /// which were taken off without being ended, and the record deleted.
    Deleted(super::Deleted),
    /// An end is under way and not finished. Send the same delete again
    /// later, at the revision the record then has.
    Pending,
}

/// What a repoint did to one line.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepointedLine {
    /// The line's id in the environment.
    pub id: String,
    /// Its kind.
    pub kind: LineKind,
    /// `repointed`, `already` (it pointed there), `skipped`, and on a
    /// refusal ([`Refusal::repoint_lines`]) also `pending` (not reached by
    /// this request) and `failed`. Cleaned: safe to print.
    pub outcome: String,
    /// Why it was skipped or failed. Cleaned: safe to print.
    pub reason: Option<String>,
}

#[derive(Deserialize)]
struct RepointedLineWire {
    id: String,
    kind: LineKind,
    outcome: String,
    #[serde(default)]
    reason: Option<String>,
}

impl From<RepointedLineWire> for RepointedLine {
    fn from(w: RepointedLineWire) -> Self {
        Self {
            id: w.id,
            kind: w.kind,
            outcome: token(&w.outcome),
            reason: w.reason.as_deref().map(token),
        }
    }
}

/// What a repoint answered: every line points at the server asked for, or
/// was left as it is for the reason given.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Repointed {
    /// The environment after: its lines' endpoints are the ones the app is
    /// to be given now.
    pub env: EnvDetail,
    /// What was done to each line.
    pub lines: Vec<RepointedLine>,
}

#[derive(Deserialize)]
struct RepointedWire {
    env: Value,
    lines: Vec<RepointedLineWire>,
}

impl Refusal {
    /// The open start the refusal is about, on [`super::Code::StartPending`],
    /// [`super::Code::StartUnsettled`] and [`super::Code::PurchaseUnavailable`]. Cleaned:
    /// safe to print.
    #[must_use]
    pub fn start_id(&self) -> Option<String> {
        self.data
            .get("startId")
            .and_then(Value::as_str)
            .and_then(|s| one_line(s, DETAIL_MAX))
    }

    /// Whether the start may have bought something and is to be sent again
    /// with the same key or retried, on [`super::Code::StartPending`].
    #[must_use]
    pub fn retry(&self) -> bool {
        self.data.get("retry").and_then(Value::as_bool) == Some(true)
    }

    /// The price of one hour now, in cents, on [`super::Code::PriceChanged`]
    /// (`data.hourlyCents`); `None` when the refusal does not say (a server
    /// paid by contract, or an answer of another shape).
    #[must_use]
    pub fn hourly_cents(&self) -> Option<u64> {
        self.data
            .get("hourlyCents")
            .and_then(Value::as_u64)
            .filter(|cents| *cents > 0)
    }

    /// The reason the refusal gives (`data.reason`), cleaned to the letters,
    /// digits, `_`, `-` and `.` the account uses: safe to print.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        self.data.get("reason").and_then(Value::as_str).map(token)
    }

    /// How many servers and lines are left to end, on
    /// [`super::Code::EndInProgress`].
    #[must_use]
    pub fn remaining(&self) -> Option<u64> {
        self.data.get("remaining").and_then(Value::as_u64)
    }

    /// How many lines cannot be pointed elsewhere, on [`super::Code::EndRefused`]
    /// with reason `lines_pointed`.
    #[must_use]
    pub fn not_repointable(&self) -> Option<u64> {
        self.data.get("notRepointable").and_then(Value::as_u64)
    }

    /// How long to wait before sending the same request again, in seconds,
    /// on [`super::Code::RepointIncomplete`], [`super::Code::RateLimited`] and
    /// a delete's [`super::Code::EndRefused`] while another operation holds
    /// the environment; `None` when waiting does not help (or the refusal
    /// does not say).
    #[must_use]
    pub fn retry_after(&self) -> Option<u64> {
        self.data.get("retryAfter").and_then(Value::as_u64)
    }

    /// What a repoint did to each line before it stopped, on
    /// [`super::Code::RepointIncomplete`].
    #[must_use]
    pub fn repoint_lines(&self) -> Vec<RepointedLine> {
        self.data
            .get("lines")
            .and_then(Value::as_array)
            .map(|lines| {
                lines
                    .iter()
                    .filter_map(|l| serde_json::from_value::<RepointedLineWire>(l.clone()).ok())
                    .map(RepointedLine::from)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The billing address fields the account is missing, on
    /// [`super::Code::BillingAddressRequired`]. Cleaned: safe to print.
    #[must_use]
    pub fn missing_fields(&self) -> Vec<String> {
        self.data
            .get("missingFields")
            .and_then(Value::as_array)
            .map(|f| f.iter().filter_map(Value::as_str).map(token).collect())
            .unwrap_or_default()
    }
}

/// A route under an environment.
#[derive(Debug, Clone, Copy)]
enum Route<'a> {
    ServerStart,
    ServerPrices,
    LineStart,
    Starts,
    Retry(&'a str),
    Resolve(&'a str),
    AppState(&'a Slot),
    Switch,
    ServerEnd,
    LineEnd(&'a str),
    Repoint,
}

/// The URL of `route` under environment `env` of `app`, every id and slot
/// in it checked first.
fn route_url(app: &str, env: &str, route: Route<'_>) -> Result<String, WorkerError> {
    let path = match route {
        Route::ServerStart => "server/start".to_owned(),
        Route::ServerPrices => "server/prices".to_owned(),
        Route::LineStart => "lines/start".to_owned(),
        Route::Starts => "starts".to_owned(),
        Route::Retry(id) => format!("starts/{}/retry", path_id(id)?),
        Route::Resolve(id) => format!("starts/{}/resolve", path_id(id)?),
        Route::AppState(slot) => format!("servers/{}/app-state", slot_segment(slot)?),
        Route::Switch => "server/switch".to_owned(),
        Route::ServerEnd => "server/end".to_owned(),
        Route::LineEnd(id) => format!("lines/{}/end", path_id(id)?),
        Route::Repoint => "lines/repoint".to_owned(),
    };
    Ok(format!("{}/{path}", env_url(app, env)?))
}

/// An id the account gave, as it goes into a path: a lowercase UUID.
pub(super) fn path_id(id: &str) -> Result<&str, WorkerError> {
    let b = id.as_bytes();
    let ok = b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        });
    if ok { Ok(id) } else { Err(WorkerError::Id) }
}

/// The path segment of a slot.
const fn slot_segment(slot: &Slot) -> Result<&'static str, WorkerError> {
    match slot {
        Slot::Active => Ok("active"),
        Slot::Incoming => Ok("incoming"),
        Slot::Outgoing => Ok("outgoing"),
        Slot::Other(_) => Err(WorkerError::Id),
    }
}

/// The body of a request that takes none: `{}`, which the account's check
/// of the content type still wants.
fn empty() -> Value {
    Value::Object(serde_json::Map::new())
}

/// The body that records whether the app runs on a server.
fn app_state_body(running: bool) -> Value {
    serde_json::json!({ "appRunning": running })
}

/// The body that ends server `server_id` in `slot`.
fn end_server_body(slot: &Slot, server_id: &str) -> Result<Value, WorkerError> {
    Ok(serde_json::json!({ "slot": slot_segment(slot)?, "serverId": path_id(server_id)? }))
}

/// The body that points the lines at the server in `slot`.
fn repoint_body(slot: AdoptSlot) -> Value {
    serde_json::json!({ "slot": slot })
}

async fn post_slow<B: Serialize>(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
    body: &B,
    key: Option<&StartKey>,
) -> Result<(u16, String), WorkerError> {
    Ok(client
        .post_with_token_waiting(
            Audience::AuthApi,
            url,
            access_token,
            encode(body)?,
            key.map(StartKey::as_str),
            SLOW_TIMEOUT,
        )
        .await
        .map_err(ApiError::from)?)
}

/// Reads the answer to an end: 202 is an end under way, with no record.
fn ended(status: u16, text: &str) -> Result<Ended, WorkerError> {
    if status == 202 {
        return Ok(Ended::Pending);
    }
    written_env(status, text).map(|w| Ended::Done(Box::new(w.record)))
}

/// Reads the answer to a delete that ends what it holds.
fn deleting(status: u16, text: &str) -> Result<Deleting, WorkerError> {
    if status == 202 {
        return Ok(Deleting::Pending);
    }
    reply(status, text).map(|w| Deleting::Deleted(w.record))
}

/// Reads the answer to a resolve.
fn resolved(status: u16, text: &str) -> Result<Resolved, WorkerError> {
    let w: Written<Value> = reply(status, text)?;
    match w.record.get("outcome").and_then(Value::as_str) {
        Some("released") => Ok(Resolved::Released),
        Some("committed") => {
            let env = w.record.get("env").cloned().ok_or_else(|| {
                ApiError::Malformed("a committed start without its env".to_owned())
            })?;
            let env = env_in(&env)?;
            Ok(Resolved::Committed {
                env: Box::new(env),
                created: w.created,
            })
        }
        _ => Err(ApiError::Malformed("a resolve that says neither outcome".to_owned()).into()),
    }
}

/// Reads the answer to a repoint.
fn repointed(status: u16, text: &str) -> Result<Repointed, WorkerError> {
    let w: Written<RepointedWire> = reply(status, text)?;
    let env = env_in(&w.record.env)?;
    Ok(Repointed {
        env,
        lines: w
            .record
            .lines
            .into_iter()
            .map(RepointedLine::from)
            .collect(),
    })
}

/// Starts a server for the environment `env` of `app`, paid for by the
/// hour, under `key`, which the caller has kept before calling.
///
/// # Errors
///
/// [`super::Code::PurchaseUnavailable`] when the start may have bought one:
/// send the same key again, or [`retry_start`], never a new key.
/// [`super::Code::StartPending`]: with [`Refusal::retry`], this start may
/// have bought one (send the same key again, or [`retry_start`]); without
/// it, another start is open and this key bought nothing (settle that one
/// first). [`super::Code::StartUnsettled`] (by its [`Refusal::reason`]) and
/// [`super::Code::StartEnded`]: the key is never sent to a start again, nor
/// the start retried unless the reason says so. [`super::Code::SlotOccupied`] when the
/// environment has a server in use and one coming in.
/// [`super::Code::RevisionConflict`] when [`StartServer::expected_revision`]
/// is not the environment's revision: nothing was bought.
/// [`super::Code::InvalidRequest`] for cores the environment does not offer.
/// [`super::Code::InsufficientCredit`], [`super::Code::PaymentAuthRequired`],
/// [`super::Code::BillingAddressRequired`], [`super::Code::PurchaseRefused`],
/// [`super::Code::OutOfStock`] and [`super::Code::RegionDown`] when nothing was bought.
/// [`super::Code::RateLimited`] says nothing about a start already made.
/// [`WorkerError`] otherwise.
pub async fn start_server(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    key: &StartKey,
    body: &StartServer,
) -> Result<Written<EnvDetail>, WorkerError> {
    let url = route_url(app, env, Route::ServerStart)?;
    let (status, text) = post_slow(client, access_token, &url, body, Some(key)).await?;
    written_env(status, &text)
}

/// The sizes a server start takes for the environment `env` of `app` now,
/// each with its price by the hour, and, asked with the server `adopt`
/// (its kind and number), what taking it in does to its price
/// ([`ServerPrices::adopt`]). Reads only: nothing is bought.
///
/// # Errors
///
/// [`super::Code::WorkerNotFound`] or [`super::Code::EnvNotFound`] when there is no such
/// app or environment, [`super::Code::ResourceNotFound`] when `adopt` is
/// not the person's, and [`WorkerError`] otherwise.
pub async fn server_prices(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    adopt: Option<(super::ServerKind, u64)>,
) -> Result<ServerPrices, WorkerError> {
    let url = prices_url(app, env, adopt)?;
    let (status, text) = super::get(client, access_token, &url).await?;
    reply::<ServerPrices>(status, &text).map(|w| w.record)
}

/// The URL [`server_prices`] reads, with the server asked about, if any.
fn prices_url(
    app: &str,
    env: &str,
    adopt: Option<(super::ServerKind, u64)>,
) -> Result<String, WorkerError> {
    let url = route_url(app, env, Route::ServerPrices)?;
    Ok(match adopt {
        Some((kind, id)) => format!("{url}?adoptKind={}&adoptId={id}", kind.as_str()),
        None => url,
    })
}

/// Starts a data line for the environment `env` of `app`, paid for by the
/// hour, under `key`, which the caller has kept before calling.
///
/// # Errors
///
/// As [`start_server`], and [`super::Code::LimitExceeded`] when the environment
/// has 8 lines with its open starts, [`super::Code::UdpPremiumNotOnSale`] and
/// [`super::Code::UnsupportedForAccount`] when the line is not sold to it.
pub async fn start_line(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    key: &StartKey,
    body: &StartLine,
) -> Result<Written<EnvDetail>, WorkerError> {
    let url = route_url(app, env, Route::LineStart)?;
    let (status, text) = post_slow(client, access_token, &url, body, Some(key)).await?;
    written_env(status, &text)
}

/// The environment's starts that are still open.
///
/// # Errors
///
/// [`super::Code::WorkerNotFound`] or [`super::Code::EnvNotFound`] when there is no such
/// app or environment, and [`WorkerError`] otherwise.
pub async fn list_starts(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
) -> Result<Vec<OpenStart>, WorkerError> {
    let url = route_url(app, env, Route::Starts)?;
    let (status, text) = super::get(client, access_token, &url).await?;
    reply::<StartsWire>(status, &text).map(|w| open_starts(w.record))
}

/// Sends the open start `id` again, as the same start: with `body`, the
/// address and region a line's was started with ([`StartLine::retry`]).
///
/// # Errors
///
/// [`super::Code::StartUnsettled`], read as that code says for a retry,
/// which depends on whether the start was still open; among them `released`,
/// when the start is known to have bought nothing (a new start may be made,
/// with a new key). [`super::Code::StartNotFound`] when there is no such
/// start; and otherwise as [`start_server`].
pub async fn retry_start(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    id: &str,
    body: &RetryStart,
) -> Result<Written<EnvDetail>, WorkerError> {
    let url = route_url(app, env, Route::Retry(id))?;
    let (status, text) = post_slow(client, access_token, &url, body, None).await?;
    written_env(status, &text)
}

/// Settles the start `id`, open for over an hour: puts what it bought on
/// record, or closes it when it bought nothing. Nothing is bought.
///
/// # Errors
///
/// [`super::Code::StartUnsettled`] with [`Refusal::reason`] when it cannot be
/// settled now, read as [`super::Code::StartUnsettled`] says for a resolve:
/// most reasons mean the same resolve is sent again later, which buys
/// nothing; `start_mismatch` does not clear by waiting.
/// [`super::Code::StartNotFound`] when the start is not open: for a start
/// sent here after it could not be settled, that does not mean nothing was
/// bought (see [`super::Code::StartUnsettled`]). [`WorkerError`] otherwise.
pub async fn resolve_start(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    id: &str,
) -> Result<Resolved, WorkerError> {
    let url = route_url(app, env, Route::Resolve(id))?;
    let (status, text) = post_slow(client, access_token, &url, &empty(), None).await?;
    resolved(status, &text)
}

/// Records whether the app runs on the server in `slot`. At most one slot
/// runs it: the account refuses `true` while another does.
///
/// # Errors
///
/// [`super::Code::AppRunningElsewhere`] when another slot runs it,
/// [`super::Code::ServerNotFound`] when the slot has no server, and
/// [`WorkerError`] otherwise.
pub async fn set_app_running(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    slot: &Slot,
    running: bool,
) -> Result<EnvDetail, WorkerError> {
    let url = route_url(app, env, Route::AppState(slot))?;
    let (status, text) = super::post(client, access_token, &url, &app_state_body(running)).await?;
    written_env(status, &text).map(|w| w.record)
}

/// Makes the server coming in the one in use, and the one in use the one
/// going out: only while the one coming in runs the app and the one in
/// use does not.
///
/// # Errors
///
/// [`super::Code::SwitchNotReady`] otherwise, and [`WorkerError`] when the
/// request fails or is refused for another reason.
pub async fn switch_server(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
) -> Result<EnvDetail, WorkerError> {
    let url = route_url(app, env, Route::Switch)?;
    let (status, text) = super::post(client, access_token, &url, &empty()).await?;
    written_env(status, &text).map(|w| w.record)
}

/// Ends the server `server_id` in `slot` and takes it off the environment:
/// the end of its hourly billing. The caller does not send it while a
/// repoint of the environment's lines is under way ([`repoint_lines`]).
///
/// # Errors
///
/// [`super::Code::EndRefused`] with [`Refusal::reason`] when it is not ended:
/// `server_changed` (another server is in that slot now), `not_hourly`
/// (cancel it from the dashboard, then end it again), `lines_pointed`
/// (lines still point at it while the environment has another server:
/// repoint them, or end those that cannot be, first), `not_endable` and
/// others. [`WorkerError`] otherwise.
pub async fn end_server(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    slot: &Slot,
    server_id: &str,
) -> Result<Ended, WorkerError> {
    let url = route_url(app, env, Route::ServerEnd)?;
    let body = end_server_body(slot, server_id)?;
    let (status, text) = post_slow(client, access_token, &url, &body, None).await?;
    ended(status, &text)
}

/// Ends the line `line_id` and takes it off the environment; a line bought
/// as part of a Bundle is taken off without being ended.
///
/// # Errors
///
/// [`super::Code::EndRefused`] with [`Refusal::reason`] when it is not ended,
/// [`super::Code::LineNotFound`] when the environment has no such line, and
/// [`WorkerError`] otherwise.
pub async fn end_line(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    line_id: &str,
) -> Result<Ended, WorkerError> {
    let url = route_url(app, env, Route::LineEnd(line_id))?;
    let (status, text) = post_slow(client, access_token, &url, &empty(), None).await?;
    ended(status, &text)
}

/// Points every line of the environment at the server in `slot`. The
/// caller does not send it while an end of one of the environment's
/// servers is under way ([`end_server`]). The
/// account reads that server's address itself. A line already pointing
/// there is left as it is, so the same request sent again goes on where
/// one stopped.
///
/// # Errors
///
/// [`super::Code::RepointIncomplete`] when lines are left to move
/// ([`Refusal::repoint_lines`]; send it again after
/// [`Refusal::retry_after`] seconds, or not at all when that is `None`),
/// [`super::Code::RepointNotReady`] when nothing was changed
/// ([`Refusal::reason`]: `server_not_ready`, `server_gone`,
/// `app_running_elsewhere`), [`super::Code::RateLimited`], and [`WorkerError`]
/// otherwise.
pub async fn repoint_lines(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    slot: AdoptSlot,
) -> Result<Repointed, WorkerError> {
    let url = route_url(app, env, Route::Repoint)?;
    let (status, text) = post_slow(client, access_token, &url, &repoint_body(slot), None).await?;
    repointed(status, &text)
}

/// The URL that deletes the record at `url` at `expected_revision`, ending
/// what it holds first.
fn ending_url(url: &str, expected_revision: u64) -> String {
    format!("{url}?expectedRevision={expected_revision}&endServers=true")
}

async fn delete_ending(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
    expected_revision: u64,
) -> Result<Deleting, WorkerError> {
    let (status, text) = client
        .delete_with_token_waiting(
            Audience::AuthApi,
            &ending_url(url, expected_revision),
            access_token,
            SLOW_TIMEOUT,
        )
        .await
        .map_err(ApiError::from)?;
    deleting(status, &text)
}

/// Ends every server and line of the app `app`, one at a time, then
/// deletes its record. A line bought as part of a Bundle
/// ([`super::Line::bundle_part`]) is taken off instead, without being
/// ended, whatever its state, and never stops the delete. Nothing is ended
/// unless all the rest can be.
///
/// # Errors
///
/// [`super::Code::EndInProgress`] when this request ended as many as one may
/// ([`Refusal::remaining`] are left): send it again at
/// [`Refusal::current_revision`]. [`super::Code::EndRefused`] with reason
/// `operation_in_progress` while another operation holds the environment:
/// some may be ended already; send it again after [`Refusal::retry_after`],
/// at [`Refusal::current_revision`]. [`super::Code::ServersNotEndable`] when one
/// cannot be ended (with reason `not_hourly` when one is not paid by the
/// hour: cancel it from the dashboard first), and otherwise as
/// [`super::delete_app`].
pub async fn delete_app_ending_servers(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    expected_revision: u64,
) -> Result<Deleting, WorkerError> {
    delete_ending(
        client,
        access_token,
        &super::app_url(app)?,
        expected_revision,
    )
    .await
}

/// Ends every server and line of the environment `env` of `app` (a line
/// bought as part of a Bundle taken off instead, without being ended), one
/// at a time, then deletes its record. As [`delete_app_ending_servers`].
///
/// # Errors
///
/// As [`delete_app_ending_servers`], and as [`super::delete_env`].
pub async fn delete_env_ending_servers(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    expected_revision: u64,
) -> Result<Deleting, WorkerError> {
    delete_ending(client, access_token, &env_url(app, env)?, expected_revision).await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::worker::Code;

    const START_ID: &str = "5d0c7e21-8a43-4b6f-9e12-3c4b5a6d7e8f";
    const SERVER_ID: &str = "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60";
    const LINE_ID: &str = "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314";
    const ENV: &str = "https://user-api.erpc.global/v3/worker/apps/pump-sniper/envs/prod";

    fn env_json(revision: u64) -> Value {
        json!({
            "name": "prod",
            "revision": revision,
            "factsFormat": 2,
            "facts": {
                "desiredCores": 2, "host": "203.0.113.10", "sshUser": "root", "sshPort": null,
                "hostKey": null, "firewall": { "sshAllow": [], "appAllow": [] },
                "starting": {}, "backup": null
            },
            "servers": [{
                "id": SERVER_ID, "slot": "active", "cores": 2, "memoryGb": 8, "region": "amsterdam",
                "hourly": true, "appRunning": false, "state": "active"
            }],
            "desiredCores": 2, "activeCores": 2, "coreOptions": [1, 2, 4, 8],
            "lines": [{
                "id": LINE_ID, "kind": "grpc", "hourly": true, "pending": false, "state": "active",
                "endpoint": "grpc.example.net:443"
            }],
            "refStates": { "backup": null },
            "deployed": null, "deployedApp": null,
            "updatedAt": "2026-10-29T15:40:37.000Z"
        })
    }

    fn answer(status: u16, data: &Value) -> (u16, String) {
        (
            status,
            json!({ "success": true, "message": "ok", "data": data }).to_string(),
        )
    }

    fn refusal(status: u16, body: &Value) -> Refusal {
        match reply::<Value>(status, &body.to_string()) {
            Err(WorkerError::Refused(r)) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_start_key_is_32_lowercase_hex_digits_and_never_printed() {
        let key = StartKey::new("0123456789abcdef0123456789abcdef").expect("a key");
        assert_eq!(key.as_str(), "0123456789abcdef0123456789abcdef");
        assert_eq!(format!("{key:?}"), "StartKey(<redacted>)");
        for bad in [
            "",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "start:0123456789abcdef0123456789ab",
            "0123456789abcdef0123456789abcdeg",
        ] {
            let err = StartKey::new(bad).expect_err(bad);
            assert!(matches!(err, WorkerError::StartKey), "{bad}");
            if !bad.is_empty() {
                assert!(!err.to_string().contains(bad), "{bad}");
            }
        }
    }

    #[test]
    fn every_route_has_its_url_under_the_environment() {
        let active = Slot::Active;
        let cases = [
            (Route::ServerStart, "server/start".to_owned()),
            (Route::ServerPrices, "server/prices".to_owned()),
            (Route::LineStart, "lines/start".to_owned()),
            (Route::Starts, "starts".to_owned()),
            (Route::Retry(START_ID), format!("starts/{START_ID}/retry")),
            (
                Route::Resolve(START_ID),
                format!("starts/{START_ID}/resolve"),
            ),
            (
                Route::AppState(&active),
                "servers/active/app-state".to_owned(),
            ),
            (Route::Switch, "server/switch".to_owned()),
            (Route::ServerEnd, "server/end".to_owned()),
            (Route::LineEnd(LINE_ID), format!("lines/{LINE_ID}/end")),
            (Route::Repoint, "lines/repoint".to_owned()),
        ];
        for (route, path) in cases {
            let url = route_url("pump-sniper", "prod", route).expect("a url");
            assert_eq!(url, format!("{ENV}/{path}"));
            assert!(erpc_core::endpoints::ensure_service_url(&url).is_ok());
        }
        for slot in [Slot::Incoming, Slot::Outgoing] {
            assert!(
                route_url("pump-sniper", "prod", Route::AppState(&slot))
                    .expect("a url")
                    .ends_with(&format!("servers/{slot}/app-state"))
            );
        }
        assert_eq!(
            ending_url(ENV, 7),
            format!("{ENV}?expectedRevision=7&endServers=true")
        );
    }

    #[test]
    fn an_id_or_slot_that_is_not_the_accounts_is_refused_before_a_path() {
        let unknown = Slot::Other("standby".to_owned());
        for route in [
            Route::Retry("../../seal-keys"),
            Route::Resolve("5D0C7E21-8A43-4B6F-9E12-3C4B5A6D7E8F"),
            Route::LineEnd("300003"),
            Route::LineEnd(""),
            Route::AppState(&unknown),
        ] {
            assert!(matches!(
                route_url("pump-sniper", "prod", route),
                Err(WorkerError::Id)
            ));
        }
        assert!(matches!(
            end_server_body(&Slot::Active, "200002"),
            Err(WorkerError::Id)
        ));
        assert!(matches!(
            route_url("Pump", "prod", Route::Starts),
            Err(WorkerError::Name { .. })
        ));
    }

    #[test]
    fn the_bodies_say_what_the_account_takes_and_nothing_else() {
        assert_eq!(
            serde_json::to_value(StartServer::new(4, "amsterdam")).expect("encodes"),
            json!({ "cores": 4, "region": "amsterdam" })
        );
        // At a revision: sent as `expectedRevision`.
        assert_eq!(
            serde_json::to_value(StartServer::new(2, "amsterdam").at_revision(7)).expect("encodes"),
            json!({ "cores": 2, "region": "amsterdam", "expectedRevision": 7 })
        );
        // At the price shown: sent as `expectedHourlyCents`; none, left out.
        assert_eq!(
            serde_json::to_value(
                StartServer::new(2, "amsterdam")
                    .at_revision(7)
                    .at_price(Some(13))
            )
            .expect("encodes"),
            json!({ "cores": 2, "region": "amsterdam", "expectedRevision": 7,
                "expectedHourlyCents": 13 })
        );
        assert_eq!(
            serde_json::to_value(StartServer::new(2, "amsterdam").at_price(None)).expect("encodes"),
            json!({ "cores": 2, "region": "amsterdam" })
        );
        let grpc = StartLine::new(
            LineKind::Grpc,
            "grpc-1",
            Some("203.0.113.10".to_owned()),
            None,
        );
        assert_eq!(
            serde_json::to_value(&grpc).expect("encodes"),
            json!({ "kind": "grpc", "productId": "grpc-1", "ip": "203.0.113.10" })
        );
        assert_eq!(
            serde_json::to_value(grpc.retry()).expect("encodes"),
            json!({ "ip": "203.0.113.10" })
        );
        let unlimited = StartLine::new(LineKind::Unlimited, "u-1", None, Some("tokyo".to_owned()));
        assert_eq!(
            serde_json::to_value(&unlimited).expect("encodes"),
            json!({ "kind": "unlimited", "productId": "u-1", "region": "tokyo" })
        );
        let udp = StartLine::new(LineKind::Udp, "udp-1", None, None);
        assert_eq!(
            serde_json::to_value(&udp).expect("encodes"),
            json!({ "kind": "udp", "productId": "udp-1" })
        );
        assert_eq!(
            serde_json::to_value(udp.retry()).expect("encodes"),
            json!({})
        );
        assert_eq!(empty(), json!({}));
        assert_eq!(app_state_body(true), json!({ "appRunning": true }));
        assert_eq!(
            end_server_body(&Slot::Outgoing, SERVER_ID).expect("a body"),
            json!({ "slot": "outgoing", "serverId": SERVER_ID })
        );
        assert_eq!(
            repoint_body(AdoptSlot::Incoming),
            json!({ "slot": "incoming" })
        );
        assert_eq!(repoint_body(AdoptSlot::Active), json!({ "slot": "active" }));
    }

    #[test]
    fn open_starts_are_read_by_what_they_were_for() {
        let (status, text) = answer(
            200,
            &json!({ "starts": [
                { "id": START_ID, "target": "server", "state": "open", "cores": 2,
                  "region": "amsterdam", "productId": null, "createdAt": "2026-10-29T15:40:37.000Z",
                  "stale": false },
                { "id": LINE_ID, "target": "line", "kind": "shreds", "state": "open", "cores": null,
                  "region": null, "productId": "shreds-1", "createdAt": "2026-10-29T15:40:37.000Z",
                  "stale": true },
                { "id": SERVER_ID, "target": "pool", "state": "open", "stale": false },
                { "id": SERVER_ID, "target": "line", "state": "open", "stale": false }
            ] }),
        );
        let starts = reply::<StartsWire>(status, &text)
            .map(|w| open_starts(w.record))
            .expect("reads");
        // One this version cannot tell the purpose of is kept, not
        // dropped: a start missed could be bought again.
        assert_eq!(starts.len(), 4);
        assert_eq!(starts[2].of, StartOf::Other("pool".to_owned()));
        assert_eq!(starts[3].of, StartOf::Other("line".to_owned()));
        assert_eq!(starts[0].of, StartOf::Server);
        assert_eq!((starts[0].cores, starts[0].stale), (Some(2), false));
        assert_eq!(starts[1].of, StartOf::Line(LineKind::Shreds));
        assert_eq!(starts[1].product_id.as_deref(), Some("shreds-1"));
        assert!(starts[1].stale);
    }

    #[test]
    fn a_server_start_s_prices_are_read_by_size() {
        let (status, text) = answer(
            200,
            &json!({ "currency": "eur", "options": [
                { "cores": 1, "memoryGb": 2, "hourlyCents": 7 },
                { "cores": 2, "memoryGb": 4, "hourlyCents": 13 }
            ] }),
        );
        let prices = reply::<ServerPrices>(status, &text)
            .map(|w| w.record)
            .expect("reads");
        assert_eq!(prices.currency, "eur");
        assert_eq!(
            prices.options[1],
            ServerPrice {
                cores: 2,
                memory_gb: 4,
                hourly_cents: 13
            }
        );
        let (status, text) = answer(200, &json!({ "currency": "eur", "options": [] }));
        let none = reply::<ServerPrices>(status, &text)
            .map(|w| w.record)
            .expect("reads");
        assert!(none.options.is_empty());
        assert_eq!(none.adopt, None, "not asked about, or not said yet");
        // Asked with a server: what taking it in does to its price.
        let (status, text) = answer(
            200,
            &json!({ "currency": "eur", "options": [], "adopt": {
                "billing": "hourly", "currentHourlyCents": 7, "hourlyCents": 11 } }),
        );
        let adopt = reply::<ServerPrices>(status, &text)
            .map(|w| w.record)
            .expect("reads")
            .adopt
            .expect("said");
        assert_eq!(adopt.billing, Some(super::super::Billing::Hourly));
        assert_eq!(
            (adopt.current_hourly_cents, adopt.hourly_cents),
            (Some(7), Some(11))
        );
        let (status, text) = answer(
            200,
            &json!({ "currency": "eur", "options": [], "adopt": {
                "billing": "contract", "currentHourlyCents": null, "hourlyCents": null } }),
        );
        let contract = reply::<ServerPrices>(status, &text)
            .map(|w| w.record)
            .expect("reads")
            .adopt
            .expect("said");
        assert_eq!(contract.billing, Some(super::super::Billing::Contract));
        assert_eq!(contract.hourly_cents, None);
        // Another shape is an error, never read as nothing said.
        let (status, text) = answer(
            200,
            &json!({ "currency": "eur", "options": [], "adopt": { "hourlyCents": "11" } }),
        );
        assert!(reply::<ServerPrices>(status, &text).is_err());
    }

    #[test]
    fn the_prices_of_a_server_to_take_in_are_asked_with_its_kind_and_number() {
        assert_eq!(
            prices_url("pump-sniper", "prod", None).expect("a url"),
            format!("{ENV}/server/prices")
        );
        for (kind, said) in [
            (super::super::ServerKind::Vps, "vps"),
            (super::super::ServerKind::SuperVps, "super-vps"),
            (super::super::ServerKind::PremiumVps, "premium-vps"),
            (super::super::ServerKind::BareMetal, "bare-metal"),
        ] {
            assert_eq!(
                prices_url("pump-sniper", "prod", Some((kind, 100_001))).expect("a url"),
                format!("{ENV}/server/prices?adoptKind={said}&adoptId=100001")
            );
            // The same word the take-in's body sends.
            assert_eq!(serde_json::to_value(kind).expect("encodes"), json!(said));
        }
    }

    #[test]
    fn a_price_changed_refusal_says_the_price_now_when_it_does() {
        let r = |data: Value| Refusal {
            status: 409,
            code: Some(super::super::Code::from("price_changed")),
            message: None,
            data,
        };
        assert_eq!(r(json!({})).code, Some(super::super::Code::PriceChanged));
        assert_eq!(r(json!({ "hourlyCents": 11 })).hourly_cents(), Some(11));
        assert_eq!(r(json!({ "hourlyCents": null })).hourly_cents(), None);
        assert_eq!(r(json!({ "hourlyCents": "11" })).hourly_cents(), None);
        assert_eq!(r(Value::Null).hourly_cents(), None);
    }

    #[test]
    fn an_end_is_done_with_the_environment_or_under_way_with_nothing() {
        let (status, text) = answer(200, &env_json(9));
        match ended(status, &text).expect("reads") {
            Ended::Done(env) => assert_eq!(env.revision, 9),
            Ended::Pending => panic!("done"),
        }
        let pending =
            json!({ "success": true, "code": "end_pending", "message": "under way" }).to_string();
        assert_eq!(ended(202, &pending).expect("reads"), Ended::Pending);
        assert_eq!(deleting(202, &pending).expect("reads"), Deleting::Pending);
        let (status, text) = answer(200, &json!({ "name": "prod", "deleted": true }));
        assert!(matches!(
            deleting(status, &text).expect("reads"),
            Deleting::Deleted(d) if d.name == "prod" && d.deleted
        ));
    }

    #[test]
    fn an_end_or_a_repoint_answered_in_a_newer_format_may_already_have_happened() {
        let mut newer = env_json(9);
        newer["factsFormat"] = json!(3);
        let (status, text) = answer(200, &newer);
        assert!(matches!(
            ended(status, &text),
            Err(WorkerError::NewerFormat {
                found: 3,
                after_write: true
            })
        ));
        let (status, text) = answer(200, &json!({ "env": newer, "lines": [] }));
        assert!(matches!(
            repointed(status, &text),
            Err(WorkerError::NewerFormat {
                found: 3,
                after_write: true
            })
        ));
    }

    #[test]
    fn a_servers_address_and_readiness_and_a_lines_sources_are_unknown_until_given() {
        let env: EnvDetail = serde_json::from_value(env_json(1)).expect("reads");
        assert_eq!(
            (env.servers[0].address.as_deref(), env.servers[0].ready),
            (None, None)
        );
        assert_eq!(env.lines[0].sources, None);
        let mut given = env_json(1);
        given["servers"][0]["address"] = json!("203.0.113.10");
        given["servers"][0]["ready"] = json!(true);
        given["lines"][0]["sources"] = json!(["198.51.100.21"]);
        let env: EnvDetail = serde_json::from_value(given).expect("reads");
        assert_eq!(env.servers[0].address.as_deref(), Some("203.0.113.10"));
        assert_eq!(env.servers[0].ready, Some(true));
        assert_eq!(
            env.lines[0].sources.as_deref(),
            Some(&["198.51.100.21".to_owned()][..])
        );
    }

    #[test]
    fn a_resolve_says_committed_with_the_environment_or_released() {
        let (status, text) = answer(201, &json!({ "outcome": "committed", "env": env_json(4) }));
        match resolved(status, &text).expect("reads") {
            Resolved::Committed { env, created } => {
                assert!(created);
                assert_eq!(env.servers[0].id, SERVER_ID);
            }
            Resolved::Released => panic!("committed"),
        }
        let (status, text) = answer(200, &json!({ "outcome": "committed", "env": env_json(4) }));
        assert!(matches!(
            resolved(status, &text).expect("reads"),
            Resolved::Committed { created: false, .. }
        ));
        let (status, text) = answer(200, &json!({ "outcome": "released" }));
        assert_eq!(resolved(status, &text).expect("reads"), Resolved::Released);
        for data in [
            json!({ "outcome": "committed" }),
            json!({ "outcome": "maybe" }),
        ] {
            let (status, text) = answer(200, &data);
            assert!(matches!(
                resolved(status, &text),
                Err(WorkerError::Api(ApiError::Malformed(_)))
            ));
        }
        let mut newer = env_json(4);
        newer["factsFormat"] = json!(3);
        let (status, text) = answer(200, &json!({ "outcome": "committed", "env": newer }));
        assert!(matches!(
            resolved(status, &text),
            Err(WorkerError::NewerFormat {
                found: 3,
                after_write: true
            })
        ));
    }

    #[test]
    fn a_repoint_reads_the_environment_and_each_line() {
        let (status, text) = answer(
            200,
            &json!({ "env": env_json(5), "lines": [
                { "id": LINE_ID, "kind": "grpc", "outcome": "repointed" },
                { "id": SERVER_ID, "kind": "udp", "outcome": "skipped", "reason": "gone" }
            ] }),
        );
        let done = repointed(status, &text).expect("reads");
        assert_eq!(
            done.env.lines[0].endpoint.as_deref(),
            Some("grpc.example.net:443")
        );
        assert_eq!(done.lines[0].outcome, "repointed");
        assert_eq!(done.lines[1].kind, LineKind::Udp);
        assert_eq!(done.lines[1].reason.as_deref(), Some("gone"));
    }

    #[test]
    fn an_ends_own_failure_is_read_as_other_unless_named() {
        // Passed on as the product answered it: an upper-case code, no
        // details. A 429 that is the end's own is not the account's
        // rate limit, and says no wait.
        for (status, text) in [
            (429, "RATE_LIMITED"),
            (503, "LOCK_HELD"),
            (409, "OPERATION_IN_PROGRESS"),
            (409, "ROW_CHANGED_RETRY"),
        ] {
            let r = refusal(
                status,
                &json!({ "success": false, "code": text, "message": "no" }),
            );
            assert_eq!(r.code, Some(Code::Other(text.to_owned())), "{text}");
            assert_eq!(r.retry_after(), None, "{text}");
        }
        let auth = refusal(
            400,
            &json!({ "success": false, "code": "PAYMENT_AUTH_REQUIRED", "message": "no" }),
        );
        assert_eq!(auth.code, Some(Code::PaymentAuthRequired));
    }

    #[test]
    fn each_new_code_is_read_with_its_details() {
        let cases = [
            (409, "IDEMPOTENCY_CONFLICT", Code::IdempotencyConflict),
            (409, "start_unsettled", Code::StartUnsettled),
            (409, "start_ended", Code::StartEnded),
            (502, "purchase_unavailable", Code::PurchaseUnavailable),
            (404, "start_not_found", Code::StartNotFound),
            (404, "server_not_found", Code::ServerNotFound),
            (404, "line_not_found", Code::LineNotFound),
            (400, "PAYMENT_AUTH_REQUIRED", Code::PaymentAuthRequired),
            (
                400,
                "billing_address_required",
                Code::BillingAddressRequired,
            ),
            (400, "purchase_refused", Code::PurchaseRefused),
            (402, "insufficient_credit", Code::InsufficientCredit),
            (409, "OUT_OF_STOCK", Code::OutOfStock),
            (409, "REGION_DOWN", Code::RegionDown),
            (
                409,
                "UDP_FORWARDING_PREMIUM_NOT_ON_SALE",
                Code::UdpPremiumNotOnSale,
            ),
            (409, "unsupported_for_account", Code::UnsupportedForAccount),
            (429, "rate_limited", Code::RateLimited),
            (409, "end_refused", Code::EndRefused),
            (409, "end_in_progress", Code::EndInProgress),
            (409, "servers_not_endable", Code::ServersNotEndable),
            (409, "switch_not_ready", Code::SwitchNotReady),
            (409, "repoint_incomplete", Code::RepointIncomplete),
            (409, "repoint_not_ready", Code::RepointNotReady),
        ];
        for (status, text, code) in cases {
            let r = refusal(
                status,
                &json!({ "success": false, "code": text, "message": "no" }),
            );
            assert_eq!(r.code.as_ref(), Some(&code), "{text}");
            assert_eq!(code.as_str(), text);
        }
        let pending = refusal(
            409,
            &json!({ "success": false, "code": "start_pending", "message": "no",
                     "data": { "startId": START_ID, "retry": true } }),
        );
        assert_eq!(pending.start_id().as_deref(), Some(START_ID));
        assert!(pending.retry());
        // Another start is open: no retry flag, and this key bought nothing.
        let other = refusal(
            409,
            &json!({ "success": false, "code": "start_pending", "message": "no",
                     "data": { "startId": START_ID } }),
        );
        assert_eq!(other.start_id().as_deref(), Some(START_ID));
        assert!(!other.retry());
        let unsettled = refusal(
            409,
            &json!({ "success": false, "code": "start_unsettled", "message": "no",
                     "data": { "startId": START_ID, "reason": "start_mismatch" } }),
        );
        assert_eq!(unsettled.reason().as_deref(), Some("start_mismatch"));
        assert!(!unsettled.retry());
        let ending = refusal(
            409,
            &json!({ "success": false, "code": "end_in_progress", "message": "no",
                     "data": { "remaining": 3, "currentRevision": 12 } }),
        );
        assert_eq!(
            (ending.remaining(), ending.current_revision()),
            (Some(3), Some(12))
        );
        let pointed = refusal(
            409,
            &json!({ "success": false, "code": "end_refused", "message": "no",
                     "data": { "reason": "lines_pointed", "lines": 2, "notRepointable": 1 } }),
        );
        assert_eq!(pointed.lines(), Some(2));
        assert_eq!(pointed.not_repointable(), Some(1));
        let address = refusal(
            400,
            &json!({ "success": false, "code": "billing_address_required", "message": "no",
                     "data": { "missingFields": ["line1", "postal code\u{1b}[2J"] } }),
        );
        assert_eq!(address.missing_fields(), ["line1", "postal?code??2J"]);
        // A reason is cleaned before it is printed.
        let odd = refusal(
            409,
            &json!({ "success": false, "code": "end_refused", "message": "no",
                     "data": { "reason": "not\u{202e}ended" } }),
        );
        assert_eq!(odd.reason().as_deref(), Some("not?ended"));
    }

    #[test]
    fn a_repoint_that_stops_says_what_is_left_and_when_to_send_it_again() {
        let incomplete = refusal(
            409,
            &json!({ "success": false, "code": "repoint_incomplete", "message": "no",
                     "data": { "retryAfter": 30, "lines": [
                         { "id": LINE_ID, "kind": "unlimited", "outcome": "failed",
                           "reason": "provisioning" },
                         { "id": SERVER_ID, "kind": "grpc", "outcome": "pending" }
                     ] } }),
        );
        assert_eq!(incomplete.retry_after(), Some(30));
        let lines = incomplete.repoint_lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].reason.as_deref(), Some("provisioning"));
        assert_eq!(
            (lines[1].outcome.as_str(), lines[1].reason.as_deref()),
            ("pending", None)
        );
        let stuck = refusal(
            409,
            &json!({ "success": false, "code": "repoint_incomplete", "message": "no",
                     "data": { "retryAfter": null, "lines": [] } }),
        );
        assert_eq!(stuck.retry_after(), None);
        let not_ready = refusal(
            409,
            &json!({ "success": false, "code": "repoint_not_ready", "message": "no",
                     "data": { "reason": "server_not_ready" } }),
        );
        assert_eq!(not_ready.reason().as_deref(), Some("server_not_ready"));
        let limited = refusal(
            429,
            &json!({ "success": false, "code": "rate_limited", "message": "no",
                     "data": { "retryAfter": 60 } }),
        );
        assert_eq!(limited.retry_after(), Some(60));
    }
}
