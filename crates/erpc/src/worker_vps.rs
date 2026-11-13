// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The ERPC servers `erpc worker deploy` puts a worker on: a VPS the
//! account has, or a new one started by the hour.
//!
//! A new one is the cheapest VPS plan the hourly catalogue offers, in the
//! region nearest this machine. Nearest is read from the machine's time
//! zone: user-api names no per-region host erpc could time, and erpc asks
//! no outside service where the operator is. `--region` and `--plan`
//! choose otherwise. Starting it, waiting for it, and making it key-only
//! go through the same steps `erpc ai` uses. A start shows the price and
//! the balance, which user-api gives, and is answered by the person at the
//! terminal, or by `--yes` on a deploy, which says them and goes ahead.
//! Ending one is always the person's to answer.
//!
//! A data line (an hourly gRPC, Shreds or Unlimited RPC line) is started
//! for the server the same way, at the cheapest plan unless one is asked
//! for. It lets in the server's address only, and takes no token. A gRPC
//! or Shreds line is told the address when it starts; an Unlimited RPC is
//! started in the server's region, and its whitelist is set after.
//!
//! A start's request is kept on record from before it leaves until its
//! outcome is known ([`StartRecord`]), so that one that got no answer is
//! sent again with the same key and never with a new one. What each answer
//! does to it is [`Answer`].

use erpc_ai::actions::StartError;
use erpc_ai::confirm::Confirm;
use erpc_ai::servers::Servers as _;
use erpc_ai::session::Access as _;
use erpc_api::{account, hourly};
use erpc_auth::AuthClient;
use erpc_ssh::Target;
use std::net::Ipv4Addr;
use std::time::Duration;

use erpc_worker::manifest::{Env, Line, LineKind, Resource, ResourceKind, Start};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::error::{CliError, Code};
use crate::node_common::Say;

/// The regions a VPS can be started in.
pub(crate) const REGIONS: [&str; 7] = [
    "amsterdam",
    "frankfurt",
    "london",
    "ny",
    "tokyo",
    "singapore",
    "sydney",
];

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

/// Says what a start would have asked, and goes ahead: the answer `--yes`
/// gives. An hourly product is paid from ERPC Credit, which is bought
/// beforehand, and user-api refuses a start the credit does not cover; so
/// a command line that names what to start, with `--yes`, is the yes. The
/// product, its price, the credit and how long it lasts are still said, on
/// standard error, whether or not the output is JSON.
#[derive(Default)]
struct Accepted;

impl Confirm for Accepted {
    fn confirm<'a>(
        &'a self,
        ask: &'a erpc_ai::confirm::Confirmation,
    ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
        eprintln!("{}", accepted_text(&ask.text()));
        Box::pin(async { true })
    }
}

/// What [`Accepted`] says in place of the question: what would have been
/// asked, and that `--yes` answered it.
fn accepted_text(asked: &str) -> String {
    format!("{asked}\n  {}", t!("worker_vps.accepted"))
}

/// A session with user-api, and a way to ask the person.
pub(crate) struct Api {
    client: AuthClient,
    token: SecretString,
    confirm: crate::ai::TerminalConfirm,
    /// Whether `--yes` answers what a start asks; `None` for a command that
    /// has no such flag, which a refusal then does not name.
    yes: Option<bool>,
    accepted: Accepted,
}

impl Api {
    /// Signs in with the stored session.
    pub(crate) async fn open() -> Result<Self, CliError> {
        let client = AuthClient::new().map_err(|e| CliError::new(Code::Network, e.to_string()))?;
        let access = crate::ai::StoreAccess::open(client.clone()).map_err(|o| {
            o.error()
                .unwrap_or_else(|| CliError::new(Code::NotSignedIn, t!("worker_vps.no_session")))
        })?;
        let token = access
            .access_token()
            .await
            .map_err(|e| CliError::new(Code::NotSignedIn, e).hint(t!("worker_vps.login_hint")))?;
        Ok(Self {
            client,
            token,
            confirm: crate::ai::TerminalConfirm::default(),
            yes: None,
            accepted: Accepted,
        })
    }

    /// The same session, with `--yes` answering what a start asks (the
    /// price of an hourly product) and the first login to a server erpc
    /// has not made key-only yet. Ending something is still the person's
    /// to say.
    #[must_use]
    pub(crate) fn accepting(mut self, yes: bool) -> Self {
        self.yes = Some(yes);
        self
    }

    /// One that reaches nothing, for tests that never call user-api.
    #[cfg(test)]
    pub(crate) fn offline() -> Self {
        Self {
            client: AuthClient::new().expect("client"),
            token: SecretString::from(String::new()),
            confirm: crate::ai::TerminalConfirm::default(),
            yes: None,
            accepted: Accepted,
        }
    }

    /// The confirmation `who` gives.
    fn by(&self, who: Answerer) -> &dyn Confirm {
        match who {
            Answerer::Yes => &self.accepted,
            Answerer::Person => &self.confirm,
        }
    }

    /// Who answers an end: the person at the terminal, or nobody, whatever
    /// `--yes` says.
    fn confirm(&self) -> Option<&dyn Confirm> {
        answerer(Asked::End, self.yes, crate::session::has_terminal()).map(|who| self.by(who))
    }

    /// Who answers a start: `--yes`, else the person at the terminal.
    ///
    /// # Errors
    ///
    /// With neither, what to do about it: a start is never refused with
    /// words meant for a model.
    fn confirm_start(&self) -> Result<&dyn Confirm, CliError> {
        answerer(Asked::Start, self.yes, crate::session::has_terminal())
            .map(|who| self.by(who))
            .ok_or_else(|| nobody(Asked::Start, self.yes))
    }

    /// Who answers the first login to a server: `--yes`, else the person
    /// at the terminal.
    ///
    /// # Errors
    ///
    /// With neither, what the login is and what to do about it: it starts
    /// nothing and has no price, and is not refused as a start is.
    fn confirm_login(&self) -> Result<&dyn Confirm, CliError> {
        answerer(Asked::Login, self.yes, crate::session::has_terminal())
            .map(|who| self.by(who))
            .ok_or_else(|| nobody(Asked::Login, self.yes))
    }

    /// What user-api answers at `url`, one of the account's own reads.
    pub(crate) async fn read(&self, url: &str) -> Result<Value, CliError> {
        account::read(&self.client, &self.token, url)
            .await
            .map_err(|e| CliError::new(Code::Network, t!("worker_vps.api_silent", error = e)))
    }
}

/// What is asked before something is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// The start of an hourly product, at its price.
    Start,
    /// The first login to a server erpc has not made key-only yet: once,
    /// with its password, to put the key in and turn password logins off.
    /// It starts nothing and has no price.
    Login,
    /// The end of an hourly product.
    End,
}

/// Who answers what is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answerer {
    /// `--yes` on the command line.
    Yes,
    /// The person at the terminal.
    Person,
}

/// Who answers `asked`, from whether `--yes` was given (`None`: the
/// command has no such flag) and whether a person is at a terminal; `None`
/// when nobody can. `--yes` answers a start and a first login, and comes
/// first there, so that a script, an agent or a person who passed it is not
/// asked again. It never answers an end: ending something is the person's
/// to say, at a terminal.
fn answerer(asked: Asked, yes: Option<bool>, terminal: bool) -> Option<Answerer> {
    match (asked, yes) {
        (Asked::Start | Asked::Login, Some(true)) => Some(Answerer::Yes),
        _ => terminal.then_some(Answerer::Person),
    }
}

/// The refusal of a start or a first login that nobody can answer, in
/// words for whoever ran the command. The way out it names is one the
/// command has: `--yes` only where there is such a flag.
fn nobody(asked: Asked, yes: Option<bool>) -> CliError {
    let (message, hint) = match (asked, yes) {
        (Asked::Login, Some(_)) => (
            t!("worker_vps.login.needs_yes"),
            t!("worker_vps.login.needs_yes_hint"),
        ),
        (Asked::Login, None) => (
            t!("worker_vps.login.needs_yes"),
            t!("worker_vps.login.needs_terminal_hint"),
        ),
        (Asked::Start | Asked::End, Some(_)) => {
            (t!("worker_vps.needs_yes"), t!("worker_vps.needs_yes_hint"))
        }
        (Asked::Start | Asked::End, None) => (
            t!("worker_vps.needs_yes"),
            t!("worker_vps.needs_terminal_hint"),
        ),
    };
    CliError::new(Code::NeedsTerminal, message).hint(hint)
}

/// Where a start's request is kept from before it leaves until its outcome
/// is on record. A start that got no answer (a timeout, a connection that
/// broke, erpc stopped) is then sent again with the same key, never with a
/// new one. `erpc worker run` has no such record: what it implements keeps
/// nothing, and its hints say so.
pub(crate) trait StartRecord {
    /// The request on record for what is being started: one a run left
    /// without learning its outcome.
    fn pending(&self) -> Option<Start>;

    /// Puts `start` on record. Called before its request leaves.
    fn begin(&mut self, start: &Start) -> Result<(), String>;

    /// Takes the request off the record: user-api answered for it, and
    /// nothing was started under it.
    fn settle(&mut self) -> Result<(), String>;

    /// What to do after an answer that did not settle the start, in the
    /// words of whoever keeps the record: what becomes of the request, and
    /// the way on.
    fn stays_hint(&self, why: Stays) -> String;

    /// What to do about a request on record that is for another purchase
    /// than the one asked for now. Only a record that keeps requests is
    /// asked.
    fn other_hint(&self) -> String {
        String::new()
    }
}

/// A line's [`StartRecord`], which also takes the line user-api names.
pub(crate) trait LineRecord: StartRecord {
    /// Puts line `id` on record the moment user-api names it, started or
    /// not; its request leaves the record with that.
    fn named(&mut self, id: &str) -> Result<(), CliError>;
}

/// The key a start's request carries, from the request on record.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyFor {
    /// None on record: a new key, put on record before the request leaves.
    New,
    /// One on record for the same purchase, which got no answer: its key
    /// again, and no new one.
    Again(String),
    /// One on record for another purchase (another plan, region or
    /// address). Its key is not this purchase's, and it may have gone
    /// through: nothing is sent, since starting this one could buy both.
    Other,
}

impl KeyFor {
    fn of(on_record: Option<&Start>, wanted: &Start) -> Self {
        match on_record {
            None => Self::New,
            Some(start) if start.same_purchase(wanted) => Self::Again(start.key.clone()),
            Some(_) => Self::Other,
        }
    }
}

/// Why a start is not settled after a run, and its request stays where it
/// is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stays {
    /// No answer to go by: the same command sends it again.
    Unanswered,
    /// The purchase is still being made: the same command again, shortly.
    InProgress,
    /// user-api answered, and not for this request: whether it went
    /// through is to be looked up, and the request cleared by hand once
    /// nothing was started.
    NotKnown,
    /// A purchase exists under the request, most likely the earlier
    /// request's own, and user-api does not give it to this command. It is
    /// to be looked up, taken up or ended, and the request then cleared by
    /// hand; nothing is sent again.
    Exists,
    /// user-api says it started the product and did not name it: the same,
    /// for a purchase that was made for certain.
    Unnamed,
}

/// What an answer to a start says of its request on record.
///
/// The rule: **a request sent again leaves the record only when the answer
/// is the purchase itself**, a 2xx that names it. No refusal of a request
/// sent again says what became of the first, and the one that names the
/// key (`IDEMPOTENCY_CONFLICT`) says a row made under it exists. A first
/// request, whose key this run made and nobody sent before, also leaves on
/// a certain refusal. A request dropped on a guess is bought again, with a
/// new key, by the next run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// 2xx with its id: user-api made the purchase, or answers with the
    /// one made under this key. The request leaves the record with the
    /// product put there.
    Made,
    /// 2xx that says it started the product and does not name it: a
    /// purchase exists that erpc cannot put on record. The request stays.
    Unnamed,
    /// A first request refused for certain: its key had never been sent,
    /// so nothing was made under it. The request leaves the record.
    Refused,
    /// A first request answered 409 `IDEMPOTENCY_CONFLICT`: the key, made
    /// by this run, is another purchase's, which cannot be an earlier
    /// request of erpc's. The request leaves the record, and nothing is
    /// sent again by itself.
    OtherPurchase,
    /// A request sent again and answered 409 `IDEMPOTENCY_CONFLICT`: a
    /// purchase exists under its key, and user-api does not give it to
    /// this command. The key is random and was sent for this purchase
    /// only, so that purchase may well be the earlier request's own. The
    /// request stays, nothing is started and nothing sent again.
    Unmatched,
    /// 409 `PURCHASE_IN_PROGRESS`: the account's hourly lock is held, by
    /// the first request of this very key perhaps, or the row it made is
    /// not linked yet. The request stays, and the same command sends it
    /// again shortly.
    InProgress,
    /// A request sent again and refused by any other answer: an edge's
    /// 403, a 400, no credit, no stock. It says nothing about the first
    /// request, which may have gone through or be in flight still. The
    /// request stays.
    Unrelated,
    /// A 409 with a code erpc does not know or with none, or a 2xx that
    /// says it started nothing: what became of the request is not known.
    /// It stays.
    NotKnown,
    /// No answer, or one that says only that user-api did not get to it
    /// (a timeout, too many requests, a fault of its own). The request
    /// stays, and the same command sends it again.
    Unanswered,
}

impl Answer {
    /// From the HTTP status of user-api's answer (`None` when none came),
    /// the reply's failure code ([`failure_code`]), whether it says the
    /// product was started (`done`) and names it (`named`), and whether
    /// the request had been sent before (`again`: it was on record when
    /// this run began).
    fn of(status: Option<u16>, code: Option<&str>, done: bool, named: bool, again: bool) -> Self {
        let Some(status) = status else {
            return Self::Unanswered;
        };
        if (200..=299).contains(&status) {
            return match (done, named) {
                (true, true) => Self::Made,
                (true, false) => Self::Unnamed,
                (false, _) => Self::NotKnown,
            };
        }
        if status == 409 && code == Some("PURCHASE_IN_PROGRESS") {
            return Self::InProgress;
        }
        // A timeout, too many requests, a fault of user-api's, or nothing
        // it answers a start with: it did not get to the request.
        if matches!(status, 408 | 429) || !(400..=499).contains(&status) {
            return Self::Unanswered;
        }
        let conflict = status == 409 && code == Some("IDEMPOTENCY_CONFLICT");
        // A refusal. A request sent again stays whatever it is refused
        // with: only the purchase itself, above, takes it off the record.
        if again {
            return if conflict {
                Self::Unmatched
            } else {
                Self::Unrelated
            };
        }
        // A first request: its key was made by this run, so no answer to
        // it is about an earlier one. A refusal is certain, but for a 409
        // erpc cannot read: the routes refuse for want of stock, or a
        // region that is down, before they write anything.
        if conflict {
            Self::OtherPurchase
        } else if status != 409 || matches!(code, Some("OUT_OF_STOCK" | "REGION_DOWN")) {
            Self::Refused
        } else {
            Self::NotKnown
        }
    }

    /// What is said of an answer that leaves the request where it is, and
    /// why it stays; `None` for one that takes it off the record, with the
    /// product put there ([`Self::Made`]) or because nothing was made
    /// under it. `status` and `reason` are user-api's own.
    fn stays(self, status: &Value, reason: &str) -> Option<(String, Stays)> {
        Some(match self {
            Self::Made | Self::Refused | Self::OtherPurchase => return None,
            Self::Unnamed => (t!("worker_vps.start.unnamed", status), Stays::Unnamed),
            // Without user-api's own sentence for it, which tells a client
            // to start a new purchase with a new key: here that would buy
            // a second.
            Self::Unmatched => (t!("worker_vps.start.unmatched", status), Stays::Exists),
            Self::InProgress => (
                t!("worker_vps.start.in_progress", status, reason),
                Stays::InProgress,
            ),
            Self::Unrelated => (
                t!("worker_vps.start.unrelated", status, reason),
                Stays::NotKnown,
            ),
            Self::NotKnown => (
                t!("worker_vps.start.not_known", status, reason),
                Stays::NotKnown,
            ),
            Self::Unanswered => {
                let why = t!("worker_vps.start.answered", status, reason);
                (t!("worker_vps.start.unanswered", why), Stays::Unanswered)
            }
        })
    }
}

/// The failure code of user-api's answer to a start. The VPS route gives
/// it as `code`. The gRPC, Shreds and Unlimited routes give a key's
/// conflict, and a duplicate insert's "in progress", as the whole
/// `message`, with no `code`.
fn failure_code(started: &Value) -> Option<&str> {
    started["code"].as_str().or_else(|| {
        started["message"]
            .as_str()
            .filter(|message| matches!(*message, "IDEMPOTENCY_CONFLICT" | "PURCHASE_IN_PROGRESS"))
    })
}

/// A purchase as a refusal names it: `vps prod_… (amsterdam)`.
pub(crate) fn purchase_name(start: &Start) -> String {
    let at = start.region.as_deref().or(start.ip.as_deref());
    match at {
        Some(at) => format!("{} {} ({at})", start.family, start.product),
        None => format!("{} {}", start.family, start.product),
    }
}

/// What a start's request made the caller ask for the key with.
pub(crate) type Key<'a> = &'a mut dyn FnMut() -> Result<String, String>;

/// What user-api's answer leaves the caller of [`start_on_record`] to do.
#[derive(Debug)]
pub(crate) enum Sent {
    /// The purchase, by the id user-api names it with. The caller puts it
    /// on record, and its request leaves with it.
    Made {
        /// Its id in the account.
        id: String,
        /// user-api's reply.
        started: Value,
    },
    /// Refused, and its request is off the record: user-api's reply, for
    /// the caller to say.
    Refused(Value),
}

/// The id user-api names what it started by, under `field` of its reply.
fn named_id(started: &Value, field: &str) -> Option<String> {
    started[field]
        .as_i64()
        .map(|n| n.to_string())
        .or_else(|| started[field].as_str().map(ToOwned::to_owned))
}

/// One start, by way of its record. `wanted` is the purchase, its key not
/// chosen yet; `id_field` is where user-api's reply names what it started;
/// `send` makes the request, asking for the key once the start has been
/// agreed to and is about to leave.
///
/// The request on record for the same purchase is sent again with its key.
/// With none on record a new key goes on record first. One on record for
/// another purchase refuses the start. What comes back decides what
/// becomes of the request ([`Answer`]), here and nowhere else:
///
/// - The purchase itself: returned with its id. The caller puts what was
///   started on record, and the request leaves with it.
/// - A first request refused for certain: the request is taken off the
///   record, and the reply returned for the caller to say.
/// - Anything else leaves the request where it is, and is an error that
///   says what user-api answered; the record's hint says what becomes of
///   the request and the way on.
pub(crate) async fn start_on_record(
    wanted: &Start,
    id_field: &str,
    record: &mut dyn StartRecord,
    say: &Say,
    send: impl AsyncFnOnce(Key<'_>) -> Result<Value, StartError>,
) -> Result<Sent, CliError> {
    let again = match KeyFor::of(record.pending().as_ref(), wanted) {
        KeyFor::New => None,
        KeyFor::Again(key) => {
            say.line(&t!("worker_vps.start.again"));
            Some(key)
        }
        KeyFor::Other => {
            let was = record.pending().as_ref().map(purchase_name);
            return Err(failed(t!(
                "worker_vps.start.other",
                was = was.unwrap_or_default(),
                now = purchase_name(wanted)
            ))
            .hint(record.other_hint()));
        }
    };
    // Whether this run put a request on record.
    let mut begun = false;
    let outcome = {
        let mut key = || {
            if let Some(key) = &again {
                return Ok(key.clone());
            }
            let key = erpc_ai::actions::purchase_key()?;
            let start = Start {
                key: key.clone(),
                ..wanted.clone()
            };
            record
                .begin(&start)
                .map_err(|error| t!("worker_vps.start.not_on_record", error))?;
            begun = true;
            Ok(key)
        };
        send(&mut key).await
    };
    let started = match outcome {
        Ok(started) => started,
        // Refused before it left, or by user-api before it did anything. A
        // request this run put on record goes; one an earlier run left is
        // as unanswered as it was.
        Err(StartError::NotStarted(why)) => {
            if begun {
                let _ = record.settle();
            }
            return Err(failed(why));
        }
        Err(StartError::Unanswered(why)) => {
            return Err(failed(t!("worker_vps.start.unanswered", why))
                .hint(record.stays_hint(Stays::Unanswered)));
        }
    };
    let http = started["httpStatus"]
        .as_u64()
        .and_then(|status| u16::try_from(status).ok());
    let done = started["done"] == json!(true);
    let id = named_id(&started, id_field);
    let code = failure_code(&started);
    let answer = Answer::of(http, code, done, id.is_some(), again.is_some());
    let (status, reason) = (started["httpStatus"].clone(), reason(&started));
    let Some((message, why)) = answer.stays(&status, &reason) else {
        // It leaves the record: with the purchase, which the caller puts
        // there in the same write, or here, as nothing was made under it.
        return Ok(match id {
            Some(id) if answer == Answer::Made => Sent::Made { id, started },
            _ => {
                let _ = record.settle();
                Sent::Refused(started)
            }
        });
    };
    Err(failed(message).hint(record.stays_hint(why)))
}

/// What is said of a start user-api refused, its request off the record:
/// that its key was another purchase's, when that is what user-api says;
/// else the caller's own hint.
fn refused_hint(started: &Value, own: Option<String>) -> Option<String> {
    if failure_code(started) == Some("IDEMPOTENCY_CONFLICT") {
        Some(t!("worker_vps.start.other_purchase"))
    } else {
        own
    }
}

/// Whether user-api refused a start for want of stock, or because the
/// region is down: what another region may not lack.
fn elsewhere_may_do(started: &Value) -> bool {
    matches!(
        started["code"].as_str(),
        Some("OUT_OF_STOCK" | "REGION_DOWN")
    )
}

/// The account's API keys for the shared RPC as its dashboard gives them:
/// the primary one first, then its other active keys, each once.
fn account_keys(message: &Value) -> Vec<zeroize::Zeroizing<String>> {
    let others = message["activeApiKeys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    let mut keys: Vec<zeroize::Zeroizing<String>> = Vec::new();
    for key in message["apiKey"].as_str().into_iter().chain(others) {
        if !key.is_empty() && !keys.iter().any(|kept| kept.as_str() == key) {
            keys.push(zeroize::Zeroizing::new(key.to_owned()));
        }
    }
    keys
}

/// What the shared RPC makes of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accepted,
    /// 401 or 403: the key has ended, was revoked, has no plan, or is
    /// limited to other addresses than the one it was tried from.
    Refused,
    /// The RPC could not be asked, or answered something else.
    Unknown,
}

/// What the shared RPC makes of a key, from how it answered the call made
/// with it: the HTTP status, or `None` when no answer came (the RPC was
/// not reached, the connection broke, or nothing came in time).
///
/// Only 401 and 403 are the key's refusal. A rate limit (429), a failure
/// of the RPC's own (5xx), a redirect, any other status and silence say
/// nothing of the key, for it or against it: what becomes of such a key is
/// [`usable`]'s to say.
fn verdict(answered: Option<reqwest::StatusCode>) -> Verdict {
    match answered {
        Some(status) if status.is_success() => Verdict::Accepted,
        Some(reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN) => {
            Verdict::Refused
        }
        _ => Verdict::Unknown,
    }
}

/// Where a key is asked about, and how long the answer is waited for: the
/// shared Solana RPC, which is given 8 seconds for one key. One pair, so
/// that a test reads what [`asked`] is handed.
const QUESTION: (&str, Duration) = (erpc_core::endpoints::SHARED_RPC_URL, Duration::from_secs(8));

/// Asks the shared RPC whether it takes `key`, with a call that costs
/// next to nothing. Nothing of the answer is kept or shown: an error of
/// the HTTP client carries the URL, and the URL carries the key.
async fn asked(key: zeroize::Zeroizing<String>) -> Verdict {
    let (base, wait) = QUESTION;
    asked_at(base, wait, key).await
}

/// [`asked`], of the RPC at `base` and waiting `wait` at most: the pair
/// [`QUESTION`], except in a test, which names a double of its own on
/// loopback.
async fn asked_at(base: &str, wait: Duration, key: zeroize::Zeroizing<String>) -> Verdict {
    let Ok(mut url) = reqwest::Url::parse(base) else {
        return verdict(None);
    };
    url.query_pairs_mut().append_pair("api-key", &key);
    let Ok(client) = crate::rpc_call::client() else {
        return verdict(None);
    };
    let sent = client
        .post(url)
        .timeout(wait)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "getHealth" }))
        .send()
        .await;
    verdict(sent.ok().map(|answer| answer.status()))
}

/// The key to use, of the account's keys in order, and whether the shared
/// RPC accepted it.
///
/// The first it accepts is the one, and no key after it is asked about.
/// A key it could not be asked about is passed over for one it accepts:
/// the RPC being away says nothing for the key either. Only when it
/// accepts none is the first of those it could not be asked about the one
/// (not known to be a bad one), and by then every key was asked about.
/// `None` when it refuses every one.
async fn usable<F, Asking>(
    keys: &[zeroize::Zeroizing<String>],
    ask: F,
) -> Option<(zeroize::Zeroizing<String>, bool)>
where
    F: Fn(zeroize::Zeroizing<String>) -> Asking,
    Asking: Future<Output = Verdict>,
{
    let mut unasked = None;
    for key in keys {
        match ask(key.clone()).await {
            Verdict::Accepted => return Some((key.clone(), true)),
            Verdict::Unknown => {
                unasked.get_or_insert_with(|| key.clone());
            }
            Verdict::Refused => {}
        }
    }
    unasked.map(|key| (key, false))
}

/// What choosing the account's key asks of the outside: user-api for the
/// account's keys, and the shared RPC about one of them. The real one is
/// [`Api`]; a test brings its own, which answers from a script and keeps
/// what it was asked.
pub(crate) trait KeySource {
    /// The account's dashboard, as user-api answers it.
    async fn dashboard(&self) -> Result<Value, CliError>;

    /// What the shared RPC makes of `key`.
    async fn takes(&self, key: zeroize::Zeroizing<String>) -> Verdict;
}

impl KeySource for Api {
    async fn dashboard(&self) -> Result<Value, CliError> {
        self.read(account::DASHBOARD_URL).await
    }

    async fn takes(&self, key: zeroize::Zeroizing<String>) -> Verdict {
        asked(key).await
    }
}

/// Which of the account's keys one is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccountKey {
    /// The one its dashboard gives as the account's API key.
    Primary,
    /// Another of its active keys.
    Other,
}

impl AccountKey {
    /// As `--json` names it.
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Other => "other",
        }
    }
}

/// What trying the account's keys from this machine came to. It holds a
/// key, and has no `Debug` to print one with.
pub(crate) enum Tried {
    /// A key to use ([`usable`]).
    Usable {
        key: zeroize::Zeroizing<String>,
        /// Whether the shared RPC accepted it. When not, it accepted none
        /// of the account's keys, and this is the first it could not be
        /// asked about: a call made with it tells, and a caller that keeps
        /// the key for later has nothing to go by.
        accepted: bool,
        /// Whether it is the account's primary key.
        which: AccountKey,
    },
    /// It refused every one of them.
    ///
    /// That is this machine's answer, and may not be a server's. A key can
    /// be limited to the addresses it is used from, and one limited to a
    /// server's address is refused here though it works there. Only the
    /// status is read, so a 401 or 403 from anything between this machine
    /// and the RPC reads as a refusal too.
    Refused {
        /// The first of the account's keys: its primary one, when it has
        /// one.
        primary: zeroize::Zeroizing<String>,
        /// How many keys were tried.
        tried: usize,
    },
}

/// The account's keys for the shared RPC, tried from this machine in
/// order, with one `getHealth` each, until one is accepted ([`usable`]).
/// An account can have several, and its primary one can have run out (a
/// key can be given an end date) while another works, so the primary key
/// is not taken on trust.
///
/// # Errors
///
/// user-api's, when the dashboard cannot be read, and that the account
/// has no key. That every key was refused is not an error here, nor that
/// none was accepted and one could not be asked about: what either means
/// depends on where the key is going to be used, so each caller says
/// ([`Tried`]).
pub(crate) async fn keys_tried(from: &impl KeySource) -> Result<Tried, CliError> {
    let reply = from.dashboard().await?;
    let message = &reply["message"];
    let keys = account_keys(message);
    let Some(first) = keys.first().cloned() else {
        return Err(failed(t!("worker_vps.no_api_key")).hint(t!("worker_vps.no_api_key_hint")));
    };
    Ok(match usable(&keys, |key| from.takes(key)).await {
        Some((key, accepted)) => {
            // The primary key is the one the dashboard gives as the
            // account's; the first of an account that has none is another.
            let which = if message["apiKey"].as_str() == Some(key.as_str()) {
                AccountKey::Primary
            } else {
                AccountKey::Other
            };
            Tried::Usable {
                key,
                accepted,
                which,
            }
        }
        None => Tried::Refused {
            primary: first,
            tried: keys.len(),
        },
    })
}

/// That the shared RPC refused all `tried` keys of the account, from this
/// machine, as an error. It carries a count and never a key; the caller
/// adds the hint, which says the way out for what it was doing.
pub(crate) fn keys_refused(tried: usize) -> CliError {
    failed(t!("worker_vps.keys_refused", count = tried))
}

/// The account's API key for a call made from this machine (`erpc rpc
/// call`, `erpc webhook`): of its keys, the first the shared RPC accepts,
/// or, when it accepts none, the first it could not be asked about
/// ([`keys_tried`]): the call itself, which comes next, tells what the
/// key is worth. A key this machine is refused with is of no use to a
/// call made from here, so every key refused is an error.
pub(crate) async fn shared_api_key(
    from: &impl KeySource,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    match keys_tried(from).await? {
        Tried::Usable { key, .. } => Ok(key),
        Tried::Refused { tried, .. } => {
            Err(keys_refused(tried).hint(t!("worker_vps.keys_refused_hint")))
        }
    }
}

/// The signed-in account's keys for the shared RPC, tried from this
/// machine ([`keys_tried`]), for `erpc worker secret put --from-account`.
pub(crate) async fn account_keys_tried() -> Result<Tried, CliError> {
    let api = Api::open().await?;
    keys_tried(&api).await
}

/// A server the worker will run on.
pub(crate) struct Server {
    pub(crate) target: Target,
    pub(crate) resource: Resource,
}

/// The account's VPSs that are running, as (id, address, region, plan).
pub(crate) async fn running(api: &Api) -> Result<Vec<(i64, String, String, String)>, CliError> {
    let reply = api
        .read(erpc_ai::ready::vps_status_url().map_err(failed)?)
        .await?;
    Ok(reply["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["status"].as_str() == Some("on"))
        .filter_map(|row| {
            Some((
                row["userVpsId"].as_i64()?,
                row["ip"].as_str()?.to_owned(),
                row["region"].as_str().unwrap_or("").to_owned(),
                row["vpsVersion"]
                    .as_str()
                    .or_else(|| row["productName"].as_str())
                    .unwrap_or("VPS")
                    .to_owned(),
            ))
        })
        .collect())
}

/// VPS `id` of the account, made key-only when erpc has not done so yet:
/// one login with its password, which puts the key in and turns password
/// logins off, after a yes from the person or from `--yes`. A server erpc
/// made key-only before is asked nothing.
pub(crate) async fn existing(api: &Api, id: i64, hourly: bool) -> Result<Server, CliError> {
    let reply = api
        .read(erpc_ai::ready::vps_status_url().map_err(failed)?)
        .await?;
    let row =
        erpc_ai::ready::vps_row(&reply, id).ok_or_else(|| failed(t!("worker_vps.vps.none", id)))?;
    let ip = row["ip"]
        .as_str()
        .ok_or_else(|| failed(t!("worker_vps.vps.no_address", id)))?
        .to_owned();
    let region = row["region"].as_str().map(ToOwned::to_owned);
    // Billed by the hour when it was just started so, or when the credit
    // snapshot lists it among the hourly resources, as ending one reads it.
    let hourly = hourly
        || api
            .read(account::CREDIT_SNAPSHOT_URL)
            .await
            .is_ok_and(|snapshot| {
                snapshot["message"]["hourlyResources"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|r| {
                        r["productType"].as_str() == Some("vps")
                            && r["userProductId"].as_i64() == Some(id)
                    })
            });
    let servers = crate::vps_access::SshServers;
    // The login is asked only of a server erpc has not made key-only yet;
    // for one it has, nobody need be there to answer.
    let confirm = if servers.secured(id, &ip) {
        &api.confirm as &dyn Confirm
    } else {
        api.confirm_login()?
    };
    let secured = erpc_ai::servers::secure_vps(
        &api.client,
        &api.token,
        &json!({ "userVpsId": id }),
        Some(confirm),
        Some(&servers),
    )
    .await
    .map_err(failed)?;
    if secured["done"] != json!(true) {
        return Err(failed(t!("worker_vps.vps.not_key_only", id)));
    }
    let target = crate::vps_access::pinned_target(&ip).map_err(failed)?;
    Ok(Server {
        target,
        resource: Resource {
            kind: ResourceKind::Vps,
            id: id.to_string(),
            region,
            hourly,
        },
    })
}

/// The region nearest this machine, by its time zone; Frankfurt when the
/// zone says nothing.
pub(crate) fn nearest_region() -> &'static str {
    let zone = std::env::var("TZ")
        .ok()
        .filter(|z| !z.is_empty())
        .or_else(|| {
            std::fs::read_link("/etc/localtime").ok().and_then(|p| {
                let text = p.to_string_lossy().into_owned();
                text.split_once("zoneinfo/").map(|(_, z)| z.to_owned())
            })
        });
    region_for_zone(zone.as_deref().unwrap_or(""))
}

fn region_for_zone(zone: &str) -> &'static str {
    let city = zone.rsplit('/').next().unwrap_or(zone);
    match zone.split('/').next().unwrap_or("") {
        "Asia" => match city {
            "Tokyo" | "Seoul" | "Pyongyang" | "Sakhalin" | "Vladivostok" => "tokyo",
            "Dubai" | "Riyadh" | "Tehran" | "Baku" | "Tbilisi" | "Yerevan" | "Qatar" | "Kuwait" => {
                "frankfurt"
            }
            _ => "singapore",
        },
        "Australia" | "Pacific" | "Antarctica" => "sydney",
        "America" | "US" | "Canada" | "Atlantic" => "ny",
        "Europe" | "Africa" => match city {
            "London" | "Dublin" | "Lisbon" | "Belfast" | "Guernsey" | "Isle_of_Man" | "Jersey" => {
                "london"
            }
            "Amsterdam" | "Brussels" | "Luxembourg" => "amsterdam",
            _ => "frankfurt",
        },
        "Japan" => "tokyo",
        _ => "frankfurt",
    }
}

/// A plan's id, price per hour in cents, and name.
struct Plan {
    id: String,
    cents: f64,
    name: String,
}

/// The name of product `id`, as user-api gives it.
async fn product_name(api: &Api, id: &str) -> Option<String> {
    let product = account::read_query(
        &api.client,
        &api.token,
        account::PRODUCT_URL,
        &[("productId", id)],
    )
    .await
    .ok()?;
    product
        .get("message")
        .unwrap_or(&product)
        .get("name")
        .and_then(Value::as_str)
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty())
}

/// The cheapest plan of hourly `family` the catalogue offers (for a VPS,
/// one to run an app on), or the one asked for.
async fn plan(api: &Api, family: &str, asked: Option<&str>) -> Result<Plan, CliError> {
    let catalog = api.read(hourly::CATALOG_URL).await?;
    let plans: Vec<(String, f64)> = catalog["families"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["family"].as_str() == Some(family))
        .flat_map(|f| f["plans"].as_array().cloned().unwrap_or_default())
        .filter_map(|p| {
            Some((
                p["productId"].as_str()?.to_owned(),
                p["hourlyCents"].as_f64()?,
            ))
        })
        .collect();
    if let Some(id) = asked {
        let (id, cents) = plans
            .into_iter()
            .find(|(p, _)| p == id)
            .ok_or_else(|| failed(t!("worker_vps.plan.not_offered", id, family)))?;
        let name = product_name(api, &id).await.unwrap_or_else(|| id.clone());
        return Ok(Plan { id, cents, name });
    }
    let mut offered = Vec::new();
    for (id, cents) in plans {
        let name = product_name(api, &id).await;
        // The VPS family also sells add-ons, such as the monitoring VPS,
        // which are not servers to run an app on: they are known by their
        // names.
        if family == "vps" && name.as_deref().is_none_or(is_add_on) {
            continue;
        }
        let name = name.unwrap_or_else(|| id.clone());
        offered.push(Plan { id, cents, name });
    }
    offered
        .into_iter()
        .min_by(|a, b| a.cents.total_cmp(&b.cents))
        .ok_or_else(|| failed(t!("worker_vps.plan.none", family)))
}

/// How a plan was chosen, as the line about buying it says.
fn how_chosen(asked_plan: Option<&str>) -> String {
    if asked_plan.is_some() {
        t!("worker_vps.plan.as_asked")
    } else {
        t!("worker_vps.plan.cheapest")
    }
}

/// Why user-api did not start a product, as its reply says.
fn reason(started: &Value) -> String {
    started["message"]
        .as_str()
        .or_else(|| started["error"].as_str())
        .map_or_else(|| t!("worker_vps.no_reason"), ToOwned::to_owned)
}

/// Whether a product of the VPS family is an add-on rather than a server.
fn is_add_on(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("monitoring") || lower.contains("grafana")
}

/// Starts a new hourly VPS, once its price is answered (by the person, or
/// by `--yes`, which says it), and returns it as erpc.toml records it,
/// before it is ready: the caller puts it on record at once, then [`wait`]
/// and [`secure`] make it a server. Its request goes through `record`, so
/// that a start that gets no answer is sent again with the same key.
pub(crate) async fn buy(
    api: &Api,
    region: Option<&str>,
    asked_plan: Option<&str>,
    scope: &str,
    say: &Say,
    record: &mut dyn StartRecord,
) -> Result<Resource, CliError> {
    let region_asked = region.is_some();
    let region = match region {
        Some(r) if REGIONS.contains(&r) => r.to_owned(),
        Some(r) => {
            return Err(CliError::new(
                Code::Usage,
                t!(
                    "worker_vps.buy.bad_region",
                    region = r,
                    regions = REGIONS.join(", ")
                ),
            ));
        }
        None => nearest_region().to_owned(),
    };
    let chosen = plan(api, "vps", asked_plan).await?;
    let (product, cents) = (chosen.id.clone(), chosen.cents);
    say.line(&t!(
        "worker_vps.buy.buying",
        name = chosen.name,
        product,
        how = how_chosen(asked_plan),
        price = format!("{:.4}", cents / 100.0),
        region,
        why = if region_asked {
            t!("worker_vps.buy.region_asked")
        } else {
            t!("worker_vps.buy.region_nearest")
        }
    ));
    let confirm = api.confirm_start()?;
    let wanted = Start {
        key: String::new(),
        family: "vps".to_owned(),
        product: product.clone(),
        region: Some(region.clone()),
        ip: None,
    };
    let input = json!({ "family": "vps", "fields": { "productId": product, "region": region } });
    let sent = start_on_record(&wanted, "userVpsId", record, say, async |key| {
        erpc_ai::actions::start_hourly_product_with_key(
            &api.client,
            &api.token,
            &input,
            Some(confirm),
            key,
        )
        .await
    })
    .await?;
    let id = match sent {
        Sent::Made { id, .. } => id,
        // Refused, and its request is off the record (`start_on_record`).
        Sent::Refused(started) => {
            let error = failed(t!(
                "worker_vps.buy.not_started",
                status = started["httpStatus"],
                reason = reason(&started)
            ));
            let own =
                elsewhere_may_do(&started).then(|| t!("worker_vps.buy.other_region_hint", scope));
            return Err(match refused_hint(&started, own) {
                Some(hint) => error.hint(hint),
                None => error,
            });
        }
    };
    say.line(&t!("worker_vps.buy.started", id));
    Ok(Resource {
        kind: ResourceKind::Vps,
        id,
        region: Some(region),
        hourly: true,
    })
}

/// The id of VPS `resource`.
fn vps_id(resource: &Resource) -> Result<i64, CliError> {
    resource
        .id
        .parse()
        .map_err(|_| failed(t!("worker_vps.vps.bad_id", id = resource.id)))
}

/// Waits, up to five minutes, for VPS `resource` (one just bought, or one
/// on record from a deploy that stopped before it was ready) to be up. It
/// asks nothing, so it can run beside a build.
pub(crate) async fn wait(api: &Api, resource: &Resource, say: &Say) -> Result<(), CliError> {
    let id = vps_id(resource)?;
    say.line(&t!("worker_vps.ready.waiting", id));
    let ready = erpc_ai::ready::wait_until_ready(
        &api.client,
        &api.token,
        &json!({ "family": "vps", "userVpsId": id }),
    )
    .await
    .map_err(|e| failed(t!("worker_vps.ready.failed", id, reason = e)))?;
    if ready["ready"] == json!(false) {
        return Err(failed(t!(
            "worker_vps.ready.failed",
            id,
            reason = ready["status"]
                .as_str()
                .map_or_else(|| t!("worker_vps.no_reason"), ToOwned::to_owned)
        )));
    }
    Ok(())
}

/// Once VPS `resource` is up ([`wait`]): makes it key-only, which shows
/// its host key and asks the person, or says it under `--yes`. Nothing
/// else may be printing then.
pub(crate) async fn secure(api: &Api, resource: &Resource) -> Result<Server, CliError> {
    let id = vps_id(resource)?;
    let mut server = existing(api, id, resource.hourly).await?;
    if server.resource.region.is_none() {
        server.resource.region.clone_from(&resource.region);
    }
    Ok(server)
}

/// Ends the hourly VPS `env` runs on, after the person's yes.
pub(crate) async fn end(env: &Env, say: &Say) -> Result<Value, CliError> {
    let resource = env
        .resource
        .as_ref()
        .filter(|r| r.hourly)
        .ok_or_else(|| failed(t!("worker_vps.end.not_hourly")))?;
    let id: i64 = resource
        .id
        .parse()
        .map_err(|_| failed(t!("worker_vps.vps.bad_id", id = resource.id)))?;
    let product_type = match resource.kind {
        ResourceKind::BareMetal => "bare_metal",
        _ => "vps",
    };
    let api = Api::open().await?;
    say.line(&t!("worker_vps.end.ending", kind = product_type, id));
    let ended = erpc_ai::actions::end_hourly_product(
        &api.client,
        &api.token,
        &json!({ "productType": product_type, "userProductId": id }),
        api.confirm(),
    )
    .await
    .map_err(failed)?;
    if ended["done"] != json!(true) {
        return Err(failed(t!(
            "worker_vps.end.failed",
            kind = product_type,
            id,
            answer = ended
        )));
    }
    Ok(ended)
}

/// How user-api names a data line of each kind.
struct LineProduct {
    /// The hourly family that starts one.
    family: &'static str,
    /// The start reply's field with its id.
    id_field: &'static str,
    /// Its `productType` in the credit snapshot, which ending it takes.
    product_type: &'static str,
    /// Its key in [`account::SERVICE_STATUS_URLS`].
    status_key: &'static str,
    /// How long it may take to become active, and how often to look.
    wait: Duration,
    poll: Duration,
}

const fn line_product(kind: LineKind) -> LineProduct {
    match kind {
        LineKind::Grpc => LineProduct {
            family: "grpc",
            id_field: "userGrpcId",
            product_type: "grpc",
            status_key: "grpc",
            wait: Duration::from_mins(3),
            poll: Duration::from_secs(5),
        },
        LineKind::Shreds => LineProduct {
            family: "shreds-shared",
            id_field: "userShredsId",
            product_type: "shreds",
            status_key: "shreds",
            wait: Duration::from_mins(3),
            poll: Duration::from_secs(5),
        },
        // A dedicated server is set up for it: user-api allows 45 minutes.
        LineKind::Unlimited => LineProduct {
            family: "user-unlimited",
            id_field: "userUnlimitedId",
            product_type: "unlimited",
            status_key: "unlimited_rpc",
            wait: Duration::from_mins(50),
            poll: Duration::from_secs(15),
        },
    }
}

/// The hourly products the account is charged for now, as (`productType`,
/// `userProductId`), from the credit snapshot: the record of what is
/// charged, which a status list (set up, or not yet) is not.
pub(crate) async fn charged(api: &Api) -> Result<Vec<(String, i64)>, CliError> {
    let snapshot = api.read(account::CREDIT_SNAPSHOT_URL).await?;
    let rows = snapshot["message"]["hourlyResources"]
        .as_array()
        .ok_or_else(|| failed(t!("worker_vps.end.no_hourly_list")))?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some((
                r["productType"].as_str()?.to_owned(),
                r["userProductId"].as_i64()?,
            ))
        })
        .collect())
}

/// Whether a line on record is gone from the account: the one rule deploy
/// and delete both go by. Only a line billed by the hour, seen with its
/// endpoint before, and neither listed nor charged for is gone. A line just
/// started (both can be behind for a minute) or not billed by the hour never
/// is: the operator says so, with `--forget-line`.
/// `on_record` is the line's (billed by the hour, pending: its endpoint
/// never seen).
pub(crate) const fn is_gone(on_record: (bool, bool), listed: bool, charged: bool) -> bool {
    let (hourly, pending) = on_record;
    hourly && !pending && !listed && !charged
}

/// Whether `line` is among what [`charged`] lists.
pub(crate) fn is_charged(charged: &[(String, i64)], line: &Line) -> bool {
    line.id.parse::<i64>().is_ok_and(|id| {
        charged
            .iter()
            .any(|(t, n)| *n == id && is_product_of(line.kind, t))
    })
}

/// Whether a credit snapshot's `product_type` is the one a line of `kind`
/// is charged as.
pub(crate) fn is_product_of(kind: LineKind, product_type: &str) -> bool {
    line_product(kind).product_type == product_type
}

/// The account's data line `id` of `kind`, as its status lists it, or
/// `None` when the account has no such line.
pub(crate) async fn line_row(
    api: &Api,
    kind: LineKind,
    id: &str,
) -> Result<Option<Value>, CliError> {
    Ok(line_rows(api, kind).await?.into_iter().find(|row| {
        row["id"].as_i64().map(|n| n.to_string()).as_deref() == Some(id)
            || row["id"].as_str() == Some(id)
    }))
}

/// The id of the account's active data line of `kind` that lets in `ip`,
/// if it has one: what `erpc worker run` takes up rather than buy another.
pub(crate) async fn line_letting_in(
    api: &Api,
    kind: LineKind,
    ip: Ipv4Addr,
) -> Result<Option<String>, CliError> {
    let ip = ip.to_string();
    Ok(line_rows(api, kind).await?.iter().find_map(|row| {
        (row["status"] == "active" && line_ips(row).contains(&ip.as_str())).then(|| {
            row["id"]
                .as_i64()
                .map(|n| n.to_string())
                .or_else(|| row["id"].as_str().map(ToOwned::to_owned))
        })?
    }))
}

/// The account's data lines of `kind`, as their status lists them.
async fn line_rows(api: &Api, kind: LineKind) -> Result<Vec<Value>, CliError> {
    let product = line_product(kind);
    let url = account::SERVICE_STATUS_URLS
        .iter()
        .find(|(k, _)| *k == product.status_key)
        .map(|(_, url)| *url)
        .ok_or_else(|| failed(t!("worker_vps.line.no_status", kind = kind.label())))?;
    let reply = api.read(url).await?;
    // A reply with no list says nothing about the line: not taken as
    // "the account has none", which would let a deploy buy another.
    let rows = [reply.get("data"), reply.get("message")]
        .into_iter()
        .flatten()
        .find_map(Value::as_array)
        .ok_or_else(|| failed(t!("worker_vps.line.no_list", kind = kind.label())))?;
    Ok(rows.clone())
}

/// The addresses a line's status row lets in: one for gRPC and Shreds, a
/// list for Unlimited RPC.
fn line_ips(row: &Value) -> Vec<&str> {
    match &row["whitelistIps"] {
        Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
        _ => row["whiteListIp"].as_str().into_iter().collect(),
    }
}

/// A line's endpoint as the app dials it. user-api gives gRPC and Shreds
/// as `http://<host>`, served over TLS on 443 too, which is what the app
/// gets; an Unlimited RPC is `http://<address>:<port>`, served without
/// TLS, and kept as it is.
fn line_endpoint(kind: LineKind, given: &str) -> Option<String> {
    if kind == LineKind::Unlimited {
        let given = given.trim_end_matches('/');
        return kind.endpoint_ok(given).then(|| given.to_owned());
    }
    let host = ["https://", "http://"]
        .iter()
        .find_map(|scheme| given.strip_prefix(scheme))?
        .trim_end_matches('/');
    erpc_worker::net::is_host(host).then(|| ["https", host].join("://"))
}

/// Starts an hourly data line of `kind` for the server at `ip` in
/// `region`, once its price is answered (by the person, or by `--yes` on a
/// deploy, which says it). It may not be active yet, nor let the server
/// in: [`wait_line`] sees to both. Its request goes through `record`, as a
/// VPS's does ([`buy`]), and so does the line user-api names.
#[allow(
    clippy::too_many_arguments,
    reason = "each is its own input to the one user-api call, and the hint names the scope"
)]
pub(crate) async fn start_line(
    api: &Api,
    kind: LineKind,
    ip: Ipv4Addr,
    region: Option<&str>,
    asked_plan: Option<&str>,
    scope: &str,
    say: &Say,
    record: &mut dyn LineRecord,
) -> Result<String, CliError> {
    let product = line_product(kind);
    // What makes it this purchase, besides its plan: an Unlimited RPC's
    // region, or the address a gRPC or Shreds line lets in.
    let (fields, region, let_in) = if kind == LineKind::Unlimited {
        let region = region.ok_or_else(|| {
            failed(t!("worker_vps.line.no_region")).hint(t!("worker_vps.line.no_region_hint"))
        })?;
        (json!({ "region": region }), Some(region.to_owned()), None)
    } else {
        (json!({ "ip": ip.to_string() }), None, Some(ip.to_string()))
    };
    let chosen = plan(api, product.family, asked_plan).await?;
    say.line(&t!(
        "worker_vps.line.buying",
        kind = kind.label(),
        name = chosen.name,
        product = chosen.id,
        how = how_chosen(asked_plan),
        price = format!("{:.4}", chosen.cents / 100.0),
        ip,
    ));
    let mut fields = fields;
    fields["productId"] = json!(chosen.id);
    let confirm = api.confirm_start()?;
    let wanted = Start {
        key: String::new(),
        family: product.family.to_owned(),
        product: chosen.id.clone(),
        region,
        ip: let_in,
    };
    let input = json!({ "family": product.family, "fields": fields });
    let sent = start_on_record(&wanted, product.id_field, record, say, async |key| {
        erpc_ai::actions::start_hourly_product_with_key(
            &api.client,
            &api.token,
            &input,
            Some(confirm),
            key,
        )
        .await
    })
    .await?;
    let (id, started) = match sent {
        Sent::Made { id, started } => (id, started),
        // Refused, and its request is off the record (`start_on_record`).
        // A line user-api names all the same goes on record (`named`), so
        // that the next deploy finds it rather than buy another.
        Sent::Refused(started) => {
            let error = failed(t!(
                "worker_vps.line.not_started",
                kind = kind.label(),
                status = started["httpStatus"],
                reason = reason(&started)
            ));
            let hint = if let Some(id) = named_id(&started, product.id_field) {
                record.named(&id)?;
                Some(t!("worker_vps.line.made_anyway", id, scope))
            } else {
                refused_hint(&started, None)
            };
            return Err(match hint {
                Some(hint) => error.hint(hint),
                None => error,
            });
        }
    };
    record.named(&id)?;
    if let Some(warning) = started["registerWarning"].as_str() {
        say.line(&t!("worker_vps.line.warned", warning));
    }
    say.line(&t!("worker_vps.line.started", kind = kind.label(), id));
    Ok(id)
}

/// Line `id` of `kind` as erpc.toml keeps it, once its status lists it
/// with an endpoint: right after a start, before it is active, so that it
/// is on record however the wait ends.
pub(crate) async fn first_sight(
    api: &Api,
    kind: LineKind,
    id: &str,
    hourly: bool,
    scope: &str,
) -> Result<Line, CliError> {
    for _ in 0..20 {
        if let Some(endpoint) = line_row(api, kind, id).await?.and_then(|row| {
            row["endpoint"]
                .as_str()
                .and_then(|e| line_endpoint(kind, e))
        }) {
            return Ok(Line {
                kind,
                id: id.to_owned(),
                endpoint,
                hourly,
            });
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    Err(
        failed(t!("worker_vps.line.no_endpoint", kind = kind.label(), id))
            .hint(t!("worker_vps.line.no_endpoint_hint", scope)),
    )
}

/// Lets `ip` in to Unlimited RPC `id`, keeping the addresses it lets in
/// already (`allowed`; user-api replaces the whole list). `Ok(false)` when
/// user-api kept the whitelist but could not apply it to the line's server
/// yet, which it says while the server is still being set up.
async fn let_in(api: &Api, id: &str, ip: Ipv4Addr, allowed: &[&str]) -> Result<bool, CliError> {
    let number = id
        .parse()
        .map_err(|_| failed(t!("worker_vps.line.bad_id", id)))?;
    let list = whitelist(ip, allowed);
    match account::set_unlimited_whitelist(&api.client, &api.token, number, &list).await {
        Ok(_) => Ok(true),
        Err(erpc_api::ApiError::Refused {
            status: 502,
            message,
        }) if message.to_ascii_lowercase().contains("saved") => Ok(false),
        Err(e) => Err(
            failed(t!("worker_vps.line.let_in_failed", ip, id, error = e))
                .hint(t!("worker_vps.line.let_in_hint")),
        ),
    }
}

/// `ip` and the addresses in `allowed`, once each: the whitelist erpc sets.
/// user-api's whitelist takes single IPv4 addresses only, so nothing else
/// can be in `allowed` to keep.
fn whitelist(ip: Ipv4Addr, allowed: &[&str]) -> Vec<Ipv4Addr> {
    let mut list: Vec<Ipv4Addr> = allowed.iter().filter_map(|a| a.parse().ok()).collect();
    if !list.contains(&ip) {
        list.push(ip);
    }
    list
}

/// Waits for data line `id` of `kind` to be active and to let in `ip`, and
/// returns it as erpc.toml keeps it. An Unlimited RPC's whitelist is set
/// to `ip` while it is set up, and again once it is active, which is when
/// user-api can apply it to the line's server for certain.
pub(crate) async fn wait_line(
    api: &Api,
    kind: LineKind,
    id: &str,
    ip: Ipv4Addr,
    hourly: bool,
    say: &Say,
) -> Result<Line, CliError> {
    // A person at a terminal sees a spinner while the line is set up, which
    // can take a while with nothing else to show; its message carries what
    // would otherwise be said in lines, which a spinner's redraws would
    // break. The caller says what came of the wait.
    let spinner = (!say.quiet && crate::ui::stderr_drawn()).then(|| {
        crate::prompt::Spinner::start(&t!("worker_vps.line.waiting_for", kind = kind.label(), id))
    });
    let tell = |text: String| match &spinner {
        Some(spinner) => spinner.set_message(&text),
        None => say.line(&text),
    };
    let waited = wait_line_saying(api, kind, id, ip, hourly, &tell).await;
    if let Some(spinner) = spinner {
        spinner.done();
    }
    waited
}

async fn wait_line_saying(
    api: &Api,
    kind: LineKind,
    id: &str,
    ip: Ipv4Addr,
    hourly: bool,
    tell: &dyn Fn(String),
) -> Result<Line, CliError> {
    let product = line_product(kind);
    let mut last = t!("worker_vps.line.not_listed");
    let started = std::time::Instant::now();
    let mut kept = false;
    let mut applied = false;
    while started.elapsed() < product.wait {
        if let Some(row) = line_row(api, kind, id).await? {
            let status = row["status"].as_str().unwrap_or("unknown");
            let allowed = line_ips(&row);
            if !allowed.is_empty() && !allowed.contains(&ip.to_string().as_str()) {
                return Err(failed(t!(
                    "worker_vps.line.wrong_ip",
                    kind = kind.label(),
                    id,
                    allowed = allowed.join(", "),
                    ip
                )));
            }
            if kind == LineKind::Unlimited
                && !applied
                && ((allowed.is_empty() && !kept) || status == "active")
            {
                applied = let_in(api, id, ip, &allowed).await?;
                if !kept {
                    tell(if applied {
                        t!("worker_vps.line.lets_in", id, ip)
                    } else {
                        t!("worker_vps.line.lets_in_later", id, ip)
                    });
                }
                kept = true;
            }
            let endpoint = row["endpoint"]
                .as_str()
                .and_then(|e| line_endpoint(kind, e));
            let let_in_now = if kind == LineKind::Unlimited {
                applied
            } else {
                !allowed.is_empty()
            };
            match (status, endpoint) {
                ("active", Some(endpoint)) if let_in_now => {
                    return Ok(Line {
                        kind,
                        id: id.to_owned(),
                        endpoint,
                        hourly,
                    });
                }
                ("suspended", _) => {
                    return Err(
                        failed(t!("worker_vps.line.suspended", kind = kind.label(), id))
                            .hint(t!("worker_vps.line.suspended_hint")),
                    );
                }
                (status, _) => {
                    if status != last {
                        if kind == LineKind::Unlimited {
                            tell(t!(
                                "worker_vps.line.waiting",
                                id,
                                status,
                                minutes = started.elapsed().as_secs() / 60
                            ));
                        }
                        status.clone_into(&mut last);
                    }
                }
            }
        }
        tokio::time::sleep(product.poll).await;
    }
    Err(failed(tn!(
        "worker_vps.line.not_active",
        product.wait.as_secs() / 60,
        kind = kind.label(),
        id,
        last
    )))
}

/// Ends hourly data line `line`, after the person's yes.
pub(crate) async fn end_line(api: &Api, line: &Line, say: &Say) -> Result<Value, CliError> {
    let product = line_product(line.kind);
    let id: i64 = line
        .id
        .parse()
        .map_err(|_| failed(t!("worker_vps.line.bad_id", id = line.id)))?;
    say.line(&t!("worker_vps.line.ending", kind = line.kind.label(), id));
    let ended = erpc_ai::actions::end_hourly_product(
        &api.client,
        &api.token,
        &json!({ "productType": product.product_type, "userProductId": id }),
        api.confirm(),
    )
    .await
    .map_err(failed)?;
    if ended["done"] != json!(true) {
        return Err(failed(t!(
            "worker_vps.line.end_failed",
            kind = line.kind.label(),
            id,
            answer = ended
        )));
    }
    Ok(ended)
}

/// In a test: a [`KeySource`] that reaches neither user-api nor the RPC.
#[cfg(test)]
pub(crate) mod fake {
    use std::cell::{Cell, RefCell};

    use serde_json::{Value, json};

    use super::{CliError, KeySource, Verdict};

    /// An account as a script describes it: what user-api answers for its
    /// dashboard, and what the shared RPC makes of each of its keys, which
    /// is that it takes them unless the script says otherwise. It keeps
    /// the keys it was asked about, in order, and counts the reads of the
    /// dashboard.
    pub(crate) struct Scripted {
        reply: Result<Value, CliError>,
        verdicts: Vec<(&'static str, Verdict)>,
        pub(crate) asked: RefCell<Vec<String>>,
        pub(crate) reads: Cell<usize>,
    }

    impl Scripted {
        /// An account whose dashboard answers `message`.
        pub(crate) fn account(message: &Value) -> Self {
            Self::answering(Ok(json!({ "message": message })))
        }

        /// An account whose dashboard read ends as `reply`.
        pub(crate) fn answering(reply: Result<Value, CliError>) -> Self {
            Self {
                reply,
                verdicts: Vec::new(),
                asked: RefCell::new(Vec::new()),
                reads: Cell::new(0),
            }
        }

        /// The same, with the shared RPC making `verdict` of `key`.
        #[must_use]
        pub(crate) fn with(mut self, key: &'static str, verdict: Verdict) -> Self {
            self.verdicts.push((key, verdict));
            self
        }

        /// The keys the shared RPC was asked about, in order.
        pub(crate) fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }
    }

    impl KeySource for Scripted {
        fn dashboard(&self) -> impl Future<Output = Result<Value, CliError>> {
            self.reads.set(self.reads.get() + 1);
            core::future::ready(self.reply.clone())
        }

        fn takes(&self, key: zeroize::Zeroizing<String>) -> impl Future<Output = Verdict> {
            self.asked.borrow_mut().push(key.as_str().to_owned());
            let verdict = self
                .verdicts
                .iter()
                .find(|(named, _)| *named == key.as_str())
                .map_or(Verdict::Accepted, |(_, verdict)| *verdict);
            core::future::ready(verdict)
        }
    }

    /// The same account, lent: a test that hands it over to be opened can
    /// still look at what it was asked.
    impl KeySource for &Scripted {
        fn dashboard(&self) -> impl Future<Output = Result<Value, CliError>> {
            Scripted::dashboard(self)
        }

        fn takes(&self, key: zeroize::Zeroizing<String>) -> impl Future<Output = Verdict> {
            Scripted::takes(self, key)
        }
    }
}

#[cfg(test)]
mod tests {
    use erpc_worker::manifest::{LineKind, Start};
    use serde_json::json;

    use super::{Say, is_add_on, line_endpoint, line_ips, region_for_zone};

    #[tokio::test]
    async fn the_key_the_shared_rpc_takes_is_the_one_used() {
        use super::{Verdict, account_keys, usable};
        // The primary key first, then the others, each once and none empty.
        let keys = account_keys(&json!({
            "apiKey": "primary",
            "activeApiKeys": ["primary", "second", "", "third", "second"],
        }));
        let names: Vec<&str> = keys.iter().map(|k| k.as_str()).collect();
        assert_eq!(names, ["primary", "second", "third"]);
        assert!(account_keys(&json!({ "apiKey": "" })).is_empty());
        assert_eq!(account_keys(&json!({ "apiKey": "only" })).len(), 1);

        // The key picked and whether the RPC accepted it, with the keys it
        // was asked about, in order.
        let picked = |refused: &'static [&'static str], away: &'static [&'static str]| {
            let keys = keys.clone();
            async move {
                let asked = std::cell::RefCell::new(Vec::new());
                let picked = usable(&keys, |key| {
                    asked.borrow_mut().push(key.as_str().to_owned());
                    async move {
                        if refused.contains(&key.as_str()) {
                            Verdict::Refused
                        } else if away.contains(&key.as_str()) {
                            Verdict::Unknown
                        } else {
                            Verdict::Accepted
                        }
                    }
                })
                .await
                .map(|(key, accepted)| (key.as_str().to_owned(), accepted));
                (picked, asked.into_inner().join(" "))
            }
        };
        let (accepted, unconfirmed) = (
            |key: &str| Some((key.to_owned(), true)),
            |key: &str| Some((key.to_owned(), false)),
        );
        // Accepted: the one, and no key after it is asked about.
        assert_eq!(
            picked(&[], &[]).await,
            (accepted("primary"), "primary".to_owned())
        );
        // A primary key that has run out does not hide one that works.
        assert_eq!(
            picked(&["primary"], &[]).await,
            (accepted("second"), "primary second".to_owned())
        );
        assert_eq!(
            picked(&["primary", "second"], &[]).await,
            (accepted("third"), "primary second third".to_owned())
        );
        // Nor does one the RPC could not be asked about: a key it accepts
        // is the one, wherever it comes after.
        assert_eq!(
            picked(&[], &["primary"]).await,
            (accepted("second"), "primary second".to_owned())
        );
        assert_eq!(
            picked(&["second"], &["primary"]).await,
            (accepted("third"), "primary second third".to_owned())
        );
        // None accepted: an RPC that cannot be asked does not make a key
        // a bad one, so the first it could not be asked about is used, and
        // said to be unconfirmed. Every key was asked about by then.
        assert_eq!(
            picked(&[], &["primary", "second", "third"]).await,
            (unconfirmed("primary"), "primary second third".to_owned())
        );
        assert_eq!(
            picked(&["primary"], &["second", "third"]).await,
            (unconfirmed("second"), "primary second third".to_owned())
        );
        assert_eq!(
            picked(&["second", "third"], &["primary"]).await,
            (unconfirmed("primary"), "primary second third".to_owned())
        );
        // Never a key it refused.
        assert_eq!(
            picked(&["primary", "second", "third"], &[]).await,
            (None, "primary second third".to_owned())
        );
    }

    /// The table from what the shared RPC answered to what that says of
    /// the key.
    #[test]
    fn only_401_and_403_are_the_keys_refusal() {
        use super::{Verdict, verdict};
        for (status, expected) in [
            (200, Verdict::Accepted),
            (204, Verdict::Accepted),
            (401, Verdict::Refused),
            (403, Verdict::Refused),
            // The plan's rate limit, the RPC's own failures, a redirect
            // and any other refusal of the request are not the key's.
            (429, Verdict::Unknown),
            (500, Verdict::Unknown),
            (502, Verdict::Unknown),
            (503, Verdict::Unknown),
            (301, Verdict::Unknown),
            (302, Verdict::Unknown),
            (307, Verdict::Unknown),
            (400, Verdict::Unknown),
            (402, Verdict::Unknown),
            (404, Verdict::Unknown),
        ] {
            let answered = reqwest::StatusCode::from_u16(status).expect("a status");
            assert_eq!(verdict(Some(answered)), expected, "HTTP {status}");
        }
        // No answer at all, which is how the HTTP client reports a
        // connection that failed and a wait that ran out alike (each is
        // driven on the wire in the test below).
        assert_eq!(verdict(None), Verdict::Unknown);
    }

    /// What a double of the shared RPC does with a request.
    #[derive(Debug, Clone, Copy)]
    enum Reply {
        /// Answers with this status.
        Status(u16),
        /// Answers 302, with another path of its own to go to.
        Redirect,
        /// Closes the connection without a word: a transport error.
        Hangup,
        /// Keeps the connection and never answers: a timeout.
        Silence,
    }

    /// The requests a double of the shared RPC got: the first line and the
    /// body of each.
    type Got = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

    /// A double of the shared RPC on loopback, which does `reply` with
    /// every request. Returns its URL, and the requests it got.
    fn rpc_double(reply: Reply) -> (String, Got) {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a port");
        let port = listener.local_addr().expect("bound").port();
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = got.clone();
        std::thread::spawn(move || {
            // Connections left open for as long as the double lives.
            let mut open = Vec::new();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().expect("a second handle"));
                let mut first = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if first.is_empty() {
                        first = line.trim_end().to_owned();
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().expect("a length");
                    }
                }
                let mut body = vec![0; length];
                if reader.read_exact(&mut body).is_err() {
                    continue;
                }
                seen.lock()
                    .expect("the requests")
                    .push((first, String::from_utf8_lossy(&body).into_owned()));
                let head = match reply {
                    Reply::Status(status) => format!("HTTP/1.1 {status} Said"),
                    Reply::Redirect => "HTTP/1.1 302 Found\r\nlocation: /elsewhere".to_owned(),
                    Reply::Hangup => continue,
                    Reply::Silence => {
                        open.push(stream);
                        continue;
                    }
                };
                let _ = write!(
                    stream,
                    "{head}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
            }
        });
        (format!("http://127.0.0.1:{port}"), got)
    }

    /// The question itself, against a double of the shared RPC: one POST
    /// of `getHealth` with the key in the query, and the verdict from how
    /// it ends.
    #[tokio::test]
    async fn a_key_is_asked_about_with_one_get_health_and_judged_by_how_it_ends() {
        use super::{Verdict, asked_at};
        use std::time::Duration;
        let key = || zeroize::Zeroizing::new("the-key".to_owned());
        for (reply, expected) in [
            (Reply::Status(200), Verdict::Accepted),
            (Reply::Status(401), Verdict::Refused),
            (Reply::Status(403), Verdict::Refused),
            (Reply::Status(429), Verdict::Unknown),
            (Reply::Status(500), Verdict::Unknown),
            (Reply::Redirect, Verdict::Unknown),
            (Reply::Hangup, Verdict::Unknown),
            (Reply::Silence, Verdict::Unknown),
        ] {
            let (url, got) = rpc_double(reply);
            // Silence is waited out, for long enough that the double has
            // read the request by then; the rest answer at once.
            let wait = match reply {
                Reply::Silence => Duration::from_secs(1),
                _ => Duration::from_secs(20),
            };
            let started = std::time::Instant::now();
            assert_eq!(asked_at(&url, wait, key()).await, expected, "{reply:?}");
            // The wait it is handed is the one kept to: silence ends the
            // question after its second, long before the 30 seconds the
            // HTTP client would wait of its own.
            let took = started.elapsed();
            assert!(took < Duration::from_secs(15), "{reply:?}: {took:?}");
            // Asked once: a redirect is not followed, and nothing is sent
            // again after a connection that broke or a wait that ran out.
            let got = got.lock().expect("the requests");
            assert_eq!(got.len(), 1, "{reply:?}: {got:?}");
            let (first, body) = &got[0];
            assert_eq!(first, "POST /?api-key=the-key HTTP/1.1", "{reply:?}");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(body).expect("JSON"),
                json!({ "jsonrpc": "2.0", "id": 1, "method": "getHealth" }),
                "{reply:?}"
            );
        }
        // An address that is none asks nothing, and says nothing of the key.
        assert_eq!(
            asked_at("not an address", Duration::from_secs(1), key()).await,
            Verdict::Unknown
        );
    }

    /// What the real question is handed: the shared Solana RPC, whatever
    /// chain is called after, and 8 seconds for a key, which the guide
    /// says.
    #[test]
    fn a_key_is_asked_about_at_the_shared_solana_rpc_for_eight_seconds_at_most() {
        let (base, wait) = super::QUESTION;
        let url = reqwest::Url::parse(base).expect("an address");
        assert_eq!(
            (url.scheme(), url.host_str(), url.path(), url.query()),
            ("https", Some("edge.erpc.global"), "/", None)
        );
        assert_ne!(base, erpc_core::endpoints::ETH_RPC_URL);
        assert_eq!(wait, std::time::Duration::from_secs(8));
    }

    /// `shared_api_key`, the function every caller uses, with user-api and
    /// the shared RPC scripted.
    #[tokio::test]
    async fn the_accounts_keys_are_tried_in_order_from_the_primary_one() {
        use super::fake::Scripted;
        use super::{Verdict, shared_api_key};
        // The dashboard lists the primary key among the active ones, and
        // not first: it is still the one tried first.
        let account = || {
            Scripted::account(&json!({
                "apiKey": "primary",
                "activeApiKeys": ["second", "primary", "third"],
            }))
        };
        let picked = |from: &Scripted, key: &zeroize::Zeroizing<String>| {
            (key.as_str().to_owned(), from.asked())
        };
        // Taken: the primary key, and nothing more is asked.
        let from = account();
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(
            picked(&from, &key),
            ("primary".to_owned(), vec!["primary".to_owned()])
        );
        assert_eq!(from.reads.get(), 1);
        // The first refused and the second taken: the second.
        let from = account().with("primary", Verdict::Refused);
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(
            picked(&from, &key),
            (
                "second".to_owned(),
                vec!["primary".to_owned(), "second".to_owned()]
            )
        );
        // The first could not be asked about and the second is taken: the
        // second, which the RPC is known to take.
        let from = account().with("primary", Verdict::Unknown);
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(
            picked(&from, &key),
            (
                "second".to_owned(),
                vec!["primary".to_owned(), "second".to_owned()]
            )
        );
        // None taken, and one the RPC could not be asked about: a call
        // made from here goes on with that one, which is not known to be
        // a bad one, once every key was asked about. The call tells.
        let all = || {
            vec![
                "primary".to_owned(),
                "second".to_owned(),
                "third".to_owned(),
            ]
        };
        let from = account()
            .with("primary", Verdict::Unknown)
            .with("second", Verdict::Refused)
            .with("third", Verdict::Refused);
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(picked(&from, &key), ("primary".to_owned(), all()));
        let from = account()
            .with("primary", Verdict::Refused)
            .with("second", Verdict::Unknown)
            .with("third", Verdict::Unknown);
        let key = shared_api_key(&from).await.expect("a key");
        assert_eq!(picked(&from, &key), ("second".to_owned(), all()));
    }

    /// What trying the keys came to, as a test compares it: `Tried` holds
    /// a key and has no `Debug`.
    fn came_to(tried: super::Tried) -> String {
        match tried {
            super::Tried::Usable {
                key,
                accepted,
                which,
            } => {
                let standing = if accepted { "accepted" } else { "unconfirmed" };
                format!("{}: {standing}, {}", key.as_str(), which.word())
            }
            super::Tried::Refused { primary, tried } => {
                format!("{}: refused, {tried} tried", primary.as_str())
            }
        }
    }

    /// `keys_tried` says of the key it gives whether the shared RPC
    /// accepted it, and whether it is the account's primary key.
    #[tokio::test]
    async fn a_key_to_use_is_said_to_be_accepted_or_not_and_primary_or_not() {
        use super::fake::Scripted;
        use super::{Verdict, keys_tried};
        let account = || {
            Scripted::account(&json!({
                "apiKey": "primary",
                "activeApiKeys": ["second", "primary", "third"],
            }))
        };
        let tried = async |from: Scripted| {
            let came = came_to(keys_tried(&from).await.expect("tried"));
            (came, from.asked().join(" "))
        };
        // The primary key accepted: nothing else is asked.
        assert_eq!(
            tried(account()).await,
            (
                "primary: accepted, primary".to_owned(),
                "primary".to_owned()
            )
        );
        // The primary key refused, or not to be asked about, and the
        // second accepted: the second, one of the account's other keys.
        for verdict in [Verdict::Refused, Verdict::Unknown] {
            assert_eq!(
                tried(account().with("primary", verdict)).await,
                (
                    "second: accepted, other".to_owned(),
                    "primary second".to_owned()
                ),
                "{verdict:?}"
            );
        }
        // The primary key not to be asked about, and no other accepted:
        // the primary one, unconfirmed, after every key was asked about.
        assert_eq!(
            tried(
                account()
                    .with("primary", Verdict::Unknown)
                    .with("second", Verdict::Refused)
                    .with("third", Verdict::Refused)
            )
            .await,
            (
                "primary: unconfirmed, primary".to_owned(),
                "primary second third".to_owned()
            )
        );
        // The same of another key, the first of two not to be asked about.
        assert_eq!(
            tried(
                account()
                    .with("primary", Verdict::Refused)
                    .with("second", Verdict::Unknown)
                    .with("third", Verdict::Unknown)
            )
            .await,
            (
                "second: unconfirmed, other".to_owned(),
                "primary second third".to_owned()
            )
        );
        // An account alone with its primary key, which cannot be asked
        // about: that one, unconfirmed.
        let alone = Scripted::account(&json!({ "apiKey": "only" })).with("only", Verdict::Unknown);
        assert_eq!(
            tried(alone).await,
            ("only: unconfirmed, primary".to_owned(), "only".to_owned())
        );
        // An account whose dashboard gives no primary key: the first of
        // its active keys is tried first, and is not said to be primary.
        let no_primary = Scripted::account(&json!({ "activeApiKeys": ["first", "next"] }));
        assert_eq!(
            tried(no_primary).await,
            ("first: accepted, other".to_owned(), "first".to_owned())
        );
    }

    #[tokio::test]
    async fn an_account_whose_keys_are_all_refused_or_that_has_none_is_an_error() {
        use super::fake::Scripted;
        use super::{Verdict, keys_tried, shared_api_key};
        use crate::error::{CliError, Code};
        crate::ui::force_drawn(false);
        // Every key refused: each was tried, once.
        let refused = || {
            Scripted::account(&json!({
                "apiKey": "primary",
                "activeApiKeys": ["second", "primary", "third"],
            }))
            .with("primary", Verdict::Refused)
            .with("second", Verdict::Refused)
            .with("third", Verdict::Refused)
        };
        // What that means is the caller's to say, so it is handed the
        // primary key and how many were tried.
        let from = refused();
        assert_eq!(
            came_to(keys_tried(&from).await.expect("tried")),
            "primary: refused, 3 tried"
        );
        assert_eq!(from.asked(), ["primary", "second", "third"]);
        // For a call made from this machine it is an error. It says where
        // the keys were tried from and what that leaves open, counts them,
        // and names none.
        let from = refused();
        let e = shared_api_key(&from).await.expect_err("none taken");
        assert_eq!(from.asked(), ["primary", "second", "third"]);
        assert_eq!(e.code, Code::Failed);
        assert_eq!(
            e.text(),
            "error: the shared RPC takes none of the account's API keys from this machine (3 \
             tried)\nhint: the keys were tried from this machine, where a key limited to other \
             addresses is refused though it works from those; a key can also have an end date, \
             and the account's RPC plan can have ended: the ERPC dashboard shows both, and makes \
             a new key"
        );
        let said = format!("{} {}", e.text(), e.json());
        for key in ["primary", "second", "third"] {
            assert!(!said.contains(key), "{said}");
        }
        // Said in the language of the run, the count with it.
        for lang in [
            erpc_core::i18n::Lang::Ja,
            erpc_core::i18n::Lang::Zh,
            erpc_core::i18n::Lang::Ru,
        ] {
            let there = crate::i18n::speaking(lang, || {
                super::keys_refused(3).hint(t!("worker_vps.keys_refused_hint"))
            });
            assert_ne!(there.message, e.message, "{lang:?}");
            assert_ne!(there.hint, e.hint, "{lang:?}");
            assert!(there.message.contains('3'), "{}", there.message);
            assert!(!there.text().contains('{'), "{}", there.text());
        }
        // An account with no key at all: said as that, and nothing is
        // asked of the RPC.
        for message in [json!({}), json!({ "apiKey": "", "activeApiKeys": [""] })] {
            let from = Scripted::account(&message);
            let e = shared_api_key(&from).await.expect_err("no key");
            assert_eq!(e.message, "the account has no API key for the shared RPC");
            assert_eq!(e.hint.as_deref(), Some("the ERPC dashboard makes one"));
            assert!(from.asked().is_empty());
        }
        // user-api silent: its error, and nothing is asked of the RPC.
        let silent = CliError::new(Code::Network, "user-api did not answer: timed out");
        let from = Scripted::answering(Err(silent.clone()));
        assert_eq!(shared_api_key(&from).await.expect_err("no reply"), silent);
        assert!(from.asked().is_empty());
    }

    #[test]
    fn a_start_is_answered_by_yes_or_by_the_person_and_refused_without_either() {
        use super::{Answerer, Asked, answerer, nobody};
        use crate::error::Code;
        // --yes answers it, at a terminal or not: a person who passed it is
        // not asked again, and a script or an agent can start what it names.
        for asked in [Asked::Start, Asked::Login] {
            assert_eq!(answerer(asked, Some(true), false), Some(Answerer::Yes));
            assert_eq!(answerer(asked, Some(true), true), Some(Answerer::Yes));
            // Without it, the person at the terminal is asked.
            assert_eq!(answerer(asked, Some(false), true), Some(Answerer::Person));
            assert_eq!(answerer(asked, None, true), Some(Answerer::Person));
            // With neither, nobody answers.
            assert_eq!(answerer(asked, Some(false), false), None);
            assert_eq!(answerer(asked, None, false), None);
        }
        // The refusal says what to pass, in words for whoever ran the
        // command.
        let refused = nobody(Asked::Start, Some(false));
        assert_eq!(refused.code, Code::NeedsTerminal);
        let hint = refused.hint.expect("a hint");
        assert!(hint.contains("--yes"), "{hint}");
        assert!(!refused.message.contains("erpc ai"), "{}", refused.message);
        // A command with no --yes (`run`) is not told to pass one.
        let refused = nobody(Asked::Start, None);
        assert_eq!(refused.code, Code::NeedsTerminal);
        let hint = refused.hint.expect("a hint");
        assert!(!hint.contains("--yes"), "{hint}");
    }

    #[test]
    fn an_end_is_the_persons_to_answer_whatever_yes_says() {
        use super::{Answerer, Asked, answerer};
        // --yes was given: at a terminal the person is still asked, and
        // with nobody there nobody answers. It is never --yes.
        for yes in [Some(true), Some(false), None] {
            assert_eq!(
                answerer(Asked::End, yes, true),
                Some(Answerer::Person),
                "{yes:?}"
            );
            assert_eq!(answerer(Asked::End, yes, false), None, "{yes:?}");
        }
        // The session a deploy --yes makes hands out, for an end, what the
        // decision above says: the person's confirmation, or none.
        let api = super::Api::offline().accepting(true);
        assert_eq!(
            api.confirm().is_some(),
            crate::session::has_terminal(),
            "an end was answered by --yes, or not asked of the person"
        );
        assert!(api.confirm_start().is_ok(), "--yes answers a start");
    }

    #[test]
    fn a_first_login_nobody_can_answer_is_not_refused_as_a_start() {
        use super::{Asked, nobody};
        use crate::error::Code;
        let start = nobody(Asked::Start, Some(false));
        let login = nobody(Asked::Login, Some(false));
        assert_eq!(login.code, Code::NeedsTerminal);
        // It starts nothing and has no price, and says what it does.
        assert_ne!(login.message, start.message);
        assert!(!login.message.contains("by the hour"), "{}", login.message);
        assert!(
            login.message.contains("password logins off"),
            "{}",
            login.message
        );
        let hint = login.hint.expect("a hint");
        assert!(hint.contains("--yes") && !hint.contains("price"), "{hint}");
        // A command with no --yes is not told to pass one.
        let hint = nobody(Asked::Login, None).hint.expect("a hint");
        assert!(!hint.contains("--yes"), "{hint}");
    }

    /// A record kept in memory, as erpc.toml keeps one: the request on
    /// it, and how often one was put there.
    #[derive(Default)]
    struct Kept {
        start: Option<Start>,
        begun: u32,
        /// The record cannot be written.
        read_only: bool,
    }

    impl super::StartRecord for Kept {
        fn pending(&self) -> Option<Start> {
            self.start.clone()
        }

        fn begin(&mut self, start: &Start) -> Result<(), String> {
            if self.read_only {
                return Err("the disk is full".to_owned());
            }
            self.start = Some(start.clone());
            self.begun += 1;
            Ok(())
        }

        fn settle(&mut self) -> Result<(), String> {
            self.start = None;
            Ok(())
        }

        fn stays_hint(&self, why: super::Stays) -> String {
            match why {
                super::Stays::Unanswered => "run the same command again",
                super::Stays::InProgress => "run the same command again shortly",
                super::Stays::NotKnown => "see the dashboard, then clear it by hand",
                super::Stays::Exists | super::Stays::Unnamed => {
                    "take it up or end it, then clear it by hand"
                }
            }
            .to_owned()
        }

        fn other_hint(&self) -> String {
            "clear it by hand".to_owned()
        }
    }

    /// The id of the purchase a start came back with.
    fn made(sent: super::Sent) -> String {
        match sent {
            super::Sent::Made { id, .. } => id,
            super::Sent::Refused(reply) => panic!("refused: {reply}"),
        }
    }

    /// The reply a start was refused with, its request off the record.
    fn refused(sent: super::Sent) -> serde_json::Value {
        match sent {
            super::Sent::Refused(reply) => reply,
            super::Sent::Made { id, .. } => panic!("made {id}"),
        }
    }

    /// A new VPS in `region`, its key not chosen yet.
    fn vps(region: &str) -> Start {
        Start {
            key: String::new(),
            family: "vps".to_owned(),
            product: "prod_Vps1".to_owned(),
            region: Some(region.to_owned()),
            ip: None,
        }
    }

    const QUIET: Say = Say { quiet: true };

    #[test]
    fn a_purchase_takes_the_key_on_record_only_when_it_is_the_same_purchase() {
        use super::KeyFor;
        let wanted = vps("amsterdam");
        // None on record: a new key.
        assert_eq!(KeyFor::of(None, &wanted), KeyFor::New);
        // The same purchase got no answer: its key again.
        let on_record = Start {
            key: "a".repeat(32),
            ..wanted.clone()
        };
        assert_eq!(
            KeyFor::of(Some(&on_record), &wanted),
            KeyFor::Again("a".repeat(32))
        );
        // Another region, plan or address is another purchase: the key is
        // not sent for it, and no new one is made beside it.
        assert_eq!(KeyFor::of(Some(&on_record), &vps("tokyo")), KeyFor::Other);
        let other_plan = Start {
            product: "prod_Vps2".to_owned(),
            ..wanted.clone()
        };
        assert_eq!(KeyFor::of(Some(&on_record), &other_plan), KeyFor::Other);
        let grpc = |ip: &str| Start {
            key: "b".repeat(32),
            family: "grpc".to_owned(),
            product: "prod_Grpc1".to_owned(),
            region: None,
            ip: Some(ip.to_owned()),
        };
        assert_eq!(
            KeyFor::of(Some(&grpc("203.0.113.10")), &grpc("203.0.113.11")),
            KeyFor::Other
        );
        assert_eq!(
            super::purchase_name(&on_record),
            "vps prod_Vps1 (amsterdam)"
        );
        assert_eq!(
            super::purchase_name(&grpc("203.0.113.10")),
            "grpc prod_Grpc1 (203.0.113.10)"
        );
    }

    #[test]
    fn an_answer_is_judged_by_its_status_its_code_and_whether_it_was_sent_before() {
        use super::Answer::{
            self, InProgress, Made, NotKnown, OtherPurchase, Refused, Unanswered, Unmatched,
            Unnamed, Unrelated,
        };
        // A refusal: not started, and nothing named.
        let refusal = |status, code, again| Answer::of(Some(status), code, false, false, again);
        for again in [false, true] {
            // No answer, or one that says user-api did not get to it: the
            // request may have arrived.
            assert_eq!(Answer::of(None, None, false, false, again), Unanswered);
            for status in [408, 429, 500, 502, 503, 504, 599, 100, 301, 600] {
                assert_eq!(refusal(status, None, again), Unanswered, "{status}");
            }
            for status in [200, 201, 202] {
                // The purchase itself: started, and named.
                assert_eq!(Answer::of(Some(status), None, true, true, again), Made);
                // Started and not named: it exists, and erpc cannot put it
                // on record.
                assert_eq!(Answer::of(Some(status), None, true, false, again), Unnamed);
                // A 2xx that says it started nothing says too little.
                assert_eq!(
                    Answer::of(Some(status), None, false, false, again),
                    NotKnown
                );
            }
            // Still being made, first send or resend.
            assert_eq!(
                refusal(409, Some("PURCHASE_IN_PROGRESS"), again),
                InProgress
            );
        }
        // A first request: a refusal is certain, as nothing was made under
        // a key never sent before.
        for status in [400, 401, 402, 403, 404, 410, 422] {
            assert_eq!(refusal(status, None, false), Refused, "{status}");
        }
        for code in ["OUT_OF_STOCK", "REGION_DOWN"] {
            assert_eq!(refusal(409, Some(code), false), Refused, "{code}");
        }
        // A key made by this run that is another purchase's is not an
        // earlier request of erpc's: it goes.
        assert_eq!(
            refusal(409, Some("IDEMPOTENCY_CONFLICT"), false),
            OtherPurchase
        );
        // But a 409 erpc cannot read is not taken for a refusal.
        for code in [
            None,
            Some("SOMETHING_NEW"),
            Some("PAID_HOUR_TOKENS_USED_UP"),
        ] {
            assert_eq!(refusal(409, code, false), NotKnown, "{code:?}");
        }
        // A request sent again: the same conflict says a purchase exists
        // under its key, which may well be the earlier request's own.
        assert_eq!(refusal(409, Some("IDEMPOTENCY_CONFLICT"), true), Unmatched);
        // And no other refusal says what became of the first.
        for status in [400, 401, 402, 403, 404, 410, 422] {
            assert_eq!(refusal(status, None, true), Unrelated, "{status}");
        }
        for code in [
            None,
            Some("OUT_OF_STOCK"),
            Some("REGION_DOWN"),
            Some("SOMETHING_NEW"),
        ] {
            assert_eq!(refusal(409, code, true), Unrelated, "{code:?}");
        }
        // The codes count with a 409 only.
        assert_eq!(refusal(400, Some("IDEMPOTENCY_CONFLICT"), true), Unrelated);
        assert_eq!(refusal(400, Some("IDEMPOTENCY_CONFLICT"), false), Refused);
        assert_eq!(
            refusal(503, Some("PURCHASE_IN_PROGRESS"), false),
            Unanswered
        );
    }

    /// The rule, over every answer there can be: a request sent again
    /// leaves the record only when the answer is the purchase itself.
    #[test]
    fn a_request_sent_again_leaves_the_record_only_on_the_purchase_itself() {
        use super::Answer;
        let status = json!(0);
        let codes = [
            None,
            Some("PURCHASE_IN_PROGRESS"),
            Some("IDEMPOTENCY_CONFLICT"),
            Some("OUT_OF_STOCK"),
            Some("REGION_DOWN"),
            Some("SOMETHING_NEW"),
        ];
        let statuses = core::iter::once(None).chain((100..=599).map(Some));
        for http in statuses {
            for code in codes {
                for (done, named) in [(false, false), (false, true), (true, false), (true, true)] {
                    let answer = Answer::of(http, code, done, named, true);
                    let leaves = answer.stays(&status, "").is_none();
                    let purchase =
                        http.is_some_and(|http| (200..=299).contains(&http)) && done && named;
                    assert_eq!(
                        leaves, purchase,
                        "{http:?} {code:?} done {done} named {named}: {answer:?}"
                    );
                    assert_eq!(answer == Answer::Made, purchase);
                }
            }
        }
        // A first request leaves on a certain refusal too, and on nothing
        // that leaves its outcome open.
        for (http, code, leaves) in [
            (402, None, true),
            (409, Some("OUT_OF_STOCK"), true),
            (409, Some("IDEMPOTENCY_CONFLICT"), true),
            (409, Some("PURCHASE_IN_PROGRESS"), false),
            (409, None, false),
            (503, None, false),
        ] {
            let answer = Answer::of(Some(http), code, false, false, false);
            assert_eq!(
                answer.stays(&status, "").is_none(),
                leaves,
                "{http} {code:?}: {answer:?}"
            );
        }
    }

    #[test]
    fn a_failure_code_is_read_from_code_or_from_a_message_that_is_one() {
        use super::failure_code;
        // The VPS route.
        let vps = json!({ "code": "PURCHASE_IN_PROGRESS", "message": "Another purchase is already in progress. Please retry shortly." });
        assert_eq!(failure_code(&vps), Some("PURCHASE_IN_PROGRESS"));
        // The gRPC, Shreds and Unlimited routes: the code is the message.
        for code in ["IDEMPOTENCY_CONFLICT", "PURCHASE_IN_PROGRESS"] {
            assert_eq!(failure_code(&json!({ "message": code })), Some(code));
        }
        // A sentence is no code, and neither is a word erpc does not act on.
        for message in [
            "Stored purchase identity is invalid; retry with the same key.",
            "OUT_OF_STOCK",
            "idempotency_conflict",
        ] {
            assert_eq!(failure_code(&json!({ "message": message })), None);
        }
        assert_eq!(failure_code(&json!({})), None);
    }

    /// The end-to-end case, short of user-api: a start times out, and the
    /// same command run again sends the same key.
    #[tokio::test]
    async fn a_start_that_got_no_answer_is_sent_again_with_the_same_key() {
        use super::{StartError, start_on_record};
        let mut record = Kept::default();
        let wanted = vps("amsterdam");
        let mut sent: Vec<String> = Vec::new();
        // The request leaves, and no answer comes back.
        let lost = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Err(StartError::Unanswered("it timed out".to_owned()))
        })
        .await
        .expect_err("no answer");
        assert!(
            lost.message.contains("may or may not have gone through"),
            "{}",
            lost.message
        );
        assert_eq!(lost.hint.as_deref(), Some("run the same command again"));
        // Its key was on record before it left, and stays there.
        let on_record = record.start.clone().expect("on record");
        assert_eq!(on_record.key, sent[0]);
        assert!(on_record.same_purchase(&wanted));
        // Run again: the same key, nothing new on record, and user-api
        // here answers with what it made.
        let answered = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Ok(json!({ "done": true, "httpStatus": 200, "userVpsId": 7 }))
        })
        .await
        .expect("answered");
        assert_eq!(made(answered), "7");
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], sent[1]);
        assert_eq!(record.begun, 1);
        // The request is the caller's to take off with the VPS put on
        // record: until then it stays.
        assert_eq!(record.start, Some(on_record));
    }

    #[tokio::test]
    async fn an_answer_that_is_none_leaves_the_request_and_a_refusal_before_it_left_takes_it_off() {
        use super::{StartError, start_on_record};
        let wanted = vps("amsterdam");
        // user-api's own fault, or too many requests: as good as no answer.
        for status in [503, 429, 408] {
            let mut record = Kept::default();
            let open = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                key()?;
                Ok(json!({ "done": false, "httpStatus": status, "message": "try later" }))
            })
            .await
            .expect_err("no answer to go by");
            assert!(
                open.message.contains(&status.to_string()),
                "{}",
                open.message
            );
            assert!(open.hint.is_some());
            assert!(record.start.is_some(), "{status}");
        }
        // A refusal of a first request is certain: its key goes, and the
        // reply is returned for the caller to say.
        let mut record = Kept::default();
        let answered = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            key()?;
            Ok(json!({ "done": false, "httpStatus": 402 }))
        })
        .await
        .expect("answered");
        assert_eq!(refused(answered)["httpStatus"], json!(402));
        assert_eq!((record.begun, record.start), (1, None));
        // The session refused after the key went on record: nothing was
        // started under it, and it goes.
        let mut record = Kept::default();
        let refused = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            key()?;
            Err(StartError::NotStarted("the session was refused".to_owned()))
        })
        .await
        .expect_err("refused");
        assert_eq!(refused.message, "the session was refused");
        assert_eq!((record.begun, record.start.clone()), (1, None));
        // The person said no before a key was asked for: nothing was put
        // on record.
        let said_no = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |_| {
            Err(StartError::NotStarted("the user said no".to_owned()))
        })
        .await;
        assert!(said_no.is_err());
        assert_eq!((record.begun, record.start.clone()), (1, None));
        // And a no to a start an earlier run left unanswered leaves it as
        // unanswered as it was.
        let earlier = Start {
            key: "c".repeat(32),
            ..wanted.clone()
        };
        let mut record = Kept {
            start: Some(earlier.clone()),
            ..Kept::default()
        };
        let said_no = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |_| {
            Err(StartError::NotStarted("the user said no".to_owned()))
        })
        .await;
        assert!(said_no.is_err());
        assert_eq!(record.start, Some(earlier));
    }

    /// user-api's answer to a start, as `start_hourly_product` passes it
    /// on: the status, and the reply's `code` or `message`.
    fn answer(status: u16, code: Option<&str>, message: &str) -> serde_json::Value {
        let mut reply = json!({ "done": false, "httpStatus": status, "success": false });
        if let Some(code) = code {
            reply["code"] = json!(code);
        }
        if !message.is_empty() {
            reply["message"] = json!(message);
        }
        reply
    }

    /// The answer while the account's hourly lock is held, by the first
    /// request of the same key perhaps, or while its row is not linked.
    fn in_progress() -> serde_json::Value {
        answer(
            409,
            Some("PURCHASE_IN_PROGRESS"),
            "Another purchase is already in progress. Please retry shortly.",
        )
    }

    /// A start left on record by an earlier run that learnt no outcome.
    fn left_by_an_earlier_run(wanted: &Start) -> (Kept, Start) {
        let earlier = Start {
            key: "e".repeat(32),
            ..wanted.clone()
        };
        let record = Kept {
            start: Some(earlier.clone()),
            ..Kept::default()
        };
        (record, earlier)
    }

    /// The sequence that bought twice: a start times out while user-api is
    /// still making the purchase, the rerun is answered 409 in progress,
    /// and the run after that must still send the first key.
    #[tokio::test]
    async fn a_timeout_then_a_409_in_progress_then_a_rerun_send_one_key() {
        use super::{StartError, start_on_record};
        let mut record = Kept::default();
        let wanted = vps("amsterdam");
        let mut sent: Vec<String> = Vec::new();
        start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Err(StartError::Unanswered("it timed out".to_owned()))
        })
        .await
        .expect_err("no answer");
        // The rerun: the first request still holds the account's lock.
        let waiting = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Ok(in_progress())
        })
        .await
        .expect_err("still being made is not an outcome");
        assert!(
            waiting.message.contains("still being made"),
            "{}",
            waiting.message
        );
        let hint = waiting.hint.expect("a hint");
        assert!(hint.contains("same command again"), "{hint}");
        // Neither a new request nor another region: either would buy a
        // second while the first completes.
        for wrong in ["new request", "new one", "region"] {
            assert!(!hint.contains(wrong), "{wrong}: {hint}");
        }
        let entry = record.start.clone().expect("the request stays on record");
        assert_eq!(entry.key, sent[0]);
        // The first purchase has completed meanwhile: the third run sends
        // the same key, and here user-api answers with what it made.
        let answered = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Ok(json!({ "done": true, "httpStatus": 200, "userVpsId": 8 }))
        })
        .await
        .expect("answered");
        assert_eq!(made(answered), "8");
        assert_eq!(sent, [entry.key.clone(), entry.key.clone(), entry.key]);
        assert_eq!(record.begun, 1, "one key was made in all");
    }

    #[tokio::test]
    async fn a_first_request_answered_409_in_progress_keeps_its_key() {
        use super::start_on_record;
        let mut record = Kept::default();
        let mut sent: Vec<String> = Vec::new();
        // Its row may have been made before the answer: the key is the
        // only thing that leads back to it.
        let waiting = start_on_record(
            &vps("amsterdam"),
            "userVpsId",
            &mut record,
            &QUIET,
            async |key| {
                sent.push(key()?);
                Ok(in_progress())
            },
        )
        .await
        .expect_err("still being made");
        assert!(
            !waiting.hint.unwrap_or_default().contains("region"),
            "another region would buy a second"
        );
        assert_eq!(record.start.expect("on record").key, sent[0]);
        // The gRPC, Shreds and Unlimited routes answer a duplicate insert
        // with the code as the whole message, and no `code`.
        let mut record = Kept::default();
        let bare = answer(409, None, "PURCHASE_IN_PROGRESS");
        start_on_record(
            &vps("amsterdam"),
            "userVpsId",
            &mut record,
            &QUIET,
            async |key| {
                key()?;
                Ok(bare)
            },
        )
        .await
        .expect_err("still being made");
        assert!(record.start.is_some());
    }

    #[tokio::test]
    async fn a_request_sent_again_and_refused_for_another_reason_stays_on_record() {
        use super::start_on_record;
        let wanted = vps("amsterdam");
        // None of these speaks for the key: an edge's 403, a bad request,
        // no credit, no stock say nothing of the first request, which may
        // have gone through or be in flight still.
        for refusal in [
            answer(403, None, "Forbidden"),
            answer(400, None, "Unknown hourly plan"),
            answer(402, None, "Insufficient credit"),
            answer(409, Some("OUT_OF_STOCK"), "out of stock"),
            answer(409, Some("REGION_DOWN"), "This region is down right now."),
            answer(404, None, ""),
        ] {
            let (mut record, earlier) = left_by_an_earlier_run(&wanted);
            let said = refusal.to_string();
            let refused = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                key()?;
                Ok(refusal)
            })
            .await
            .expect_err("a refusal of the resend is no outcome of the first");
            assert_eq!(record.start, Some(earlier), "{said}");
            assert!(
                refused
                    .message
                    .contains("says nothing about the earlier one"),
                "{said}: {}",
                refused.message
            );
            assert!(
                refused.hint.is_some_and(|hint| hint.contains("clear")),
                "{said}"
            );
        }
        // The same refusals of a first request are certain: nothing was
        // made under a key that had never been sent, and the request goes.
        for refusal in [
            answer(403, None, "Forbidden"),
            answer(402, None, "Insufficient credit"),
            answer(409, Some("OUT_OF_STOCK"), "out of stock"),
            answer(409, Some("REGION_DOWN"), "This region is down right now."),
        ] {
            let mut record = Kept::default();
            let said = refusal.to_string();
            let answered =
                start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                    key()?;
                    Ok(refusal)
                })
                .await
                .expect("refused for certain");
            assert_eq!(refused(answered)["done"], json!(false));
            assert_eq!((record.begun, record.start), (1, None), "{said}");
        }
    }

    /// The answer that a request's key belongs to another purchase, as
    /// the VPS route gives it and as the line routes do (the code as the
    /// whole message).
    fn conflicts() -> [serde_json::Value; 2] {
        [
            answer(
                409,
                Some("IDEMPOTENCY_CONFLICT"),
                "This idempotency key belongs to a different VPS purchase. Start a new purchase with a new key.",
            ),
            answer(409, None, "IDEMPOTENCY_CONFLICT"),
        ]
    }

    #[tokio::test]
    async fn a_conflict_answered_to_a_request_sent_again_keeps_it_on_record() {
        use super::start_on_record;
        let wanted = vps("amsterdam");
        for conflict in conflicts() {
            let (mut record, earlier) = left_by_an_earlier_run(&wanted);
            let mut sends = 0;
            let unmatched =
                start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                    key()?;
                    sends += 1;
                    Ok(conflict)
                })
                .await
                .expect_err("a purchase exists under the key");
            // The key was sent for this purchase only: what user-api has
            // under it may well be the earlier request's own. The request
            // stays, and nothing is started or sent again.
            assert_eq!(record.start, Some(earlier));
            assert_eq!((sends, record.begun), (1, 0));
            assert!(
                unmatched
                    .message
                    .contains("has a purchase under this request"),
                "{}",
                unmatched.message
            );
            // Neither the answer nor the way on speaks of a new request.
            let said = format!(
                "{} {}",
                unmatched.message,
                unmatched.hint.unwrap_or_default()
            );
            for wrong in ["new request", "makes a new", "new one", "new key"] {
                assert!(!said.contains(wrong), "{wrong}: {said}");
            }
            assert!(said.contains("take it up or end it"), "{said}");
        }
    }

    #[tokio::test]
    async fn a_conflict_answered_to_a_first_request_takes_it_off_the_record() {
        use super::start_on_record;
        // The key was made by this run and never sent before: the purchase
        // it belongs to is not an earlier request of erpc's.
        for conflict in conflicts() {
            let mut record = Kept::default();
            let mut sends = 0;
            let answered = start_on_record(
                &vps("amsterdam"),
                "userVpsId",
                &mut record,
                &QUIET,
                async |key| {
                    key()?;
                    sends += 1;
                    Ok(conflict)
                },
            )
            .await
            .expect("refused, and settled");
            let reply = refused(answered);
            assert_eq!((record.begun, record.start), (1, None));
            // Not sent again by itself.
            assert_eq!(sends, 1);
            let hint = super::refused_hint(&reply, None).expect("a hint");
            assert!(hint.contains("another purchase"), "{hint}");
        }
    }

    /// The sequence the gate probed: a start times out and the VPS is
    /// made; the rerun is answered that the key is another purchase's; the
    /// run after that must send the first key still, and nothing new.
    #[tokio::test]
    async fn a_timeout_then_a_conflict_then_a_rerun_send_one_key() {
        use super::{StartError, start_on_record};
        let mut record = Kept::default();
        let wanted = vps("amsterdam");
        let mut sent: Vec<String> = Vec::new();
        start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            sent.push(key()?);
            Err(StartError::Unanswered("it timed out".to_owned()))
        })
        .await
        .expect_err("no answer");
        let [conflict, _] = conflicts();
        for run in [2, 3] {
            let conflict = conflict.clone();
            let unmatched =
                start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                    sent.push(key()?);
                    Ok(conflict)
                })
                .await;
            assert!(
                unmatched.is_err(),
                "run {run}: a purchase exists under the key"
            );
            assert_eq!(
                record.start.as_ref().map(|start| start.key.clone()),
                Some(sent[0].clone()),
                "run {run}: the request stays on record"
            );
        }
        assert_eq!(sent, [sent[0].clone(), sent[0].clone(), sent[0].clone()]);
        assert_eq!(record.begun, 1, "one key was made in all");
    }

    #[tokio::test]
    async fn a_start_user_api_does_not_name_stays_with_the_way_out() {
        use super::start_on_record;
        // Started, by user-api's word, and no id to put on record.
        for again in [false, true] {
            let wanted = vps("amsterdam");
            let mut record = if again {
                left_by_an_earlier_run(&wanted).0
            } else {
                Kept::default()
            };
            let unnamed = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                key()?;
                Ok(json!({ "done": true, "httpStatus": 202, "success": true }))
            })
            .await
            .expect_err("nothing to put on record");
            assert!(record.start.is_some(), "resend {again}");
            assert!(
                unnamed.message.contains("did not say which"),
                "{}",
                unnamed.message
            );
            // Not "run it again", which would never settle: the way out.
            assert_eq!(
                unnamed.hint.as_deref(),
                Some("take it up or end it, then clear it by hand")
            );
        }
        // A line is named under its own field, by a number or a string.
        for id in [json!(100_002), json!("100002")] {
            let reply = json!({ "done": true, "httpStatus": 200, "userGrpcId": id });
            assert_eq!(
                super::named_id(&reply, "userGrpcId").as_deref(),
                Some("100002")
            );
            assert_eq!(super::named_id(&reply, "userVpsId"), None);
        }
    }

    /// What user-api answered is said without a word about a record: the
    /// record's own hint says what becomes of the request, and
    /// `erpc worker run` keeps none.
    #[tokio::test]
    async fn what_user_api_answered_is_said_without_a_word_about_a_record() {
        use super::{StartError, start_on_record};
        let wanted = vps("amsterdam");
        let replies = [
            in_progress(),
            answer(409, None, "Stored purchase identity is invalid."),
            answer(503, None, "try later"),
            json!({ "done": true, "httpStatus": 202, "success": true }),
            json!({ "done": false, "httpStatus": 200, "success": false }),
        ];
        let mut messages = Vec::new();
        for reply in replies {
            let mut record = Kept::default();
            let error = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                key()?;
                Ok(reply)
            })
            .await
            .expect_err("not settled");
            messages.push(error.message);
        }
        let mut record = Kept::default();
        let lost = start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
            key()?;
            Err(StartError::Unanswered("it timed out".to_owned()))
        })
        .await
        .expect_err("no answer");
        messages.push(lost.message);
        for message in messages {
            for wrong in ["record", "same command", "same request"] {
                assert!(!message.contains(wrong), "{wrong}: {message}");
            }
        }
    }

    #[tokio::test]
    async fn a_409_with_a_code_erpc_does_not_know_keeps_the_request() {
        use super::start_on_record;
        let wanted = vps("amsterdam");
        // A code of another route, a verdict in place of a code, a sentence
        // and nothing at all: never a reason to make a new key.
        for unknown in [
            answer(409, Some("SOMETHING_NEW"), "a code from a later user-api"),
            answer(
                409,
                None,
                "Stored placement differs from current placement; retry with the original route.",
            ),
            answer(409, None, ""),
            json!({ "done": false, "httpStatus": 409, "success": false, "verdict": "conflict" }),
        ] {
            for resend in [false, true] {
                let mut record = if resend {
                    left_by_an_earlier_run(&wanted).0
                } else {
                    Kept::default()
                };
                let said = unknown.to_string();
                let answer = unknown.clone();
                let not_known =
                    start_on_record(&wanted, "userVpsId", &mut record, &QUIET, async |key| {
                        key()?;
                        Ok(answer)
                    })
                    .await
                    .expect_err("not known");
                assert!(record.start.is_some(), "{said}, resend {resend}");
                let hint = not_known.hint.expect("a hint");
                assert!(
                    hint.contains("dashboard") && hint.contains("clear"),
                    "{said}: {hint}"
                );
            }
        }
    }

    #[tokio::test]
    async fn nothing_is_sent_for_another_purchase_or_without_a_record() {
        use super::start_on_record;
        // A request for Amsterdam got no answer; the command now asks for
        // Tokyo. Neither key is sent, and the record is left as it is.
        let earlier = Start {
            key: "d".repeat(32),
            ..vps("amsterdam")
        };
        let mut record = Kept {
            start: Some(earlier.clone()),
            ..Kept::default()
        };
        let refused = start_on_record(
            &vps("tokyo"),
            "userVpsId",
            &mut record,
            &QUIET,
            async |_| unreachable!("sent a start beside one that may have gone through"),
        )
        .await
        .expect_err("refused");
        assert!(
            refused.message.contains("vps prod_Vps1 (amsterdam)")
                && refused.message.contains("vps prod_Vps1 (tokyo)"),
            "{}",
            refused.message
        );
        assert_eq!(refused.hint.as_deref(), Some("clear it by hand"));
        assert_eq!(record.start, Some(earlier));
        // A record that cannot be written: the key is not handed out, so
        // the request does not leave.
        let mut record = Kept {
            read_only: true,
            ..Kept::default()
        };
        let mut left = false;
        let refused = start_on_record(
            &vps("tokyo"),
            "userVpsId",
            &mut record,
            &QUIET,
            async |key| {
                let key = key()?;
                left = true;
                Ok(json!({ "done": true, "httpStatus": 200, "key": key }))
            },
        )
        .await
        .expect_err("not on record");
        assert!(!left);
        assert!(
            refused.message.contains("the disk is full"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_refusal_says_the_key_was_another_purchases_or_what_else_to_try() {
        let own = || Some("another region".to_owned());
        // The key is another purchase's: that, whatever else could be said.
        for conflict in [
            answer(409, Some("IDEMPOTENCY_CONFLICT"), "a different purchase"),
            answer(409, None, "IDEMPOTENCY_CONFLICT"),
        ] {
            let said = super::refused_hint(&conflict, own()).expect("a hint");
            assert!(said.contains("another purchase"), "{said}");
            // True of a deploy and of a run alike: no word of a record,
            // nor of what the next run does.
            for wrong in ["record", "new request", "again makes"] {
                assert!(!said.contains(wrong), "{wrong}: {said}");
            }
        }
        // Any other refusal keeps the caller's hint, or has none.
        let no_stock = answer(409, Some("OUT_OF_STOCK"), "out of stock");
        assert_eq!(super::refused_hint(&no_stock, own()), own());
        let no_credit = answer(402, None, "Insufficient credit");
        assert_eq!(super::refused_hint(&no_credit, None), None);
        // Another region is worth a try only where this one had no stock
        // or is down, never for want of credit.
        assert!(super::elsewhere_may_do(&no_stock));
        assert!(super::elsewhere_may_do(&answer(
            409,
            Some("REGION_DOWN"),
            ""
        )));
        assert!(!super::elsewhere_may_do(&no_credit));
        assert!(!super::elsewhere_may_do(&in_progress()));
    }

    #[test]
    fn what_yes_answered_is_still_said() {
        let said = super::accepted_text("Start VPS Plus hourly?\n  Price  €0.07 per hour");
        assert!(
            said.starts_with("Start VPS Plus hourly?\n  Price  €0.07 per hour\n"),
            "{said}"
        );
        assert!(said.contains("--yes"), "{said}");
    }

    /// The assistant stops an erpc deploy it runs after a limit of its
    /// own, which must outlast the longest wait a deploy has: the slowest
    /// line to be ready, with a build and a new server before it.
    #[test]
    fn the_assistants_limit_for_a_deploy_outlasts_the_slowest_line() {
        use core::time::Duration;
        let slowest = [LineKind::Grpc, LineKind::Shreds, LineKind::Unlimited]
            .map(|kind| super::line_product(kind).wait)
            .into_iter()
            .max()
            .expect("a line");
        assert!(
            erpc_ai::commands::DEPLOY_LIMIT >= slowest + Duration::from_mins(30),
            "a line can take {slowest:?}"
        );
    }

    #[test]
    fn a_line_endpoint_is_dialled_over_tls_but_unlimited() {
        // Built, not written out: the endpoint gate reads literals.
        let url = |scheme: &str, rest: &str| [scheme, rest].join("://");
        let host = "edge.erpc.global";
        for given in [url("http", host), url("https", &format!("{host}/"))] {
            assert_eq!(
                line_endpoint(LineKind::Grpc, &given),
                Some(url("https", host))
            );
        }
        assert_eq!(line_endpoint(LineKind::Grpc, host), None);
        assert_eq!(line_endpoint(LineKind::Grpc, "http://"), None);
        let unlimited = url("http", "203.0.113.5:8899");
        assert_eq!(
            line_endpoint(LineKind::Unlimited, &format!("{unlimited}/")),
            Some(unlimited)
        );
        assert_eq!(line_endpoint(LineKind::Unlimited, &url("http", host)), None);
    }

    #[test]
    fn a_line_is_charged_when_the_snapshot_lists_its_type_and_id() {
        use erpc_worker::manifest::Line;
        let line = |kind, id: &str| Line {
            kind,
            id: id.to_owned(),
            endpoint: String::new(),
            hourly: true,
        };
        let charged = vec![
            ("grpc".to_owned(), 100_002),
            ("unlimited".to_owned(), 100_003),
        ];
        assert!(super::is_charged(&charged, &line(LineKind::Grpc, "100002")));
        assert!(super::is_charged(
            &charged,
            &line(LineKind::Unlimited, "100003")
        ));
        // The same id under another type is another product.
        assert!(!super::is_charged(
            &charged,
            &line(LineKind::Shreds, "100002")
        ));
        assert!(!super::is_charged(
            &charged,
            &line(LineKind::Grpc, "100009")
        ));
    }

    #[test]
    fn letting_the_server_in_keeps_the_others() {
        let ip: std::net::Ipv4Addr = "203.0.113.10".parse().expect("ip");
        assert_eq!(super::whitelist(ip, &[]), [ip]);
        assert_eq!(
            super::whitelist(ip, &["198.51.100.7", "203.0.113.10"]),
            [
                "198.51.100.7".parse::<std::net::Ipv4Addr>().expect("ip"),
                ip
            ]
        );
        assert_eq!(super::whitelist(ip, &["not an address"]), [ip]);
    }

    #[test]
    fn a_line_lets_in_one_address_or_a_list() {
        assert_eq!(
            line_ips(&json!({ "whiteListIp": "203.0.113.5" })),
            ["203.0.113.5"]
        );
        assert_eq!(
            line_ips(&json!({ "whitelistIps": ["203.0.113.5", "203.0.113.6"] })),
            ["203.0.113.5", "203.0.113.6"]
        );
        assert!(line_ips(&json!({ "whitelistIps": null })).is_empty());
    }

    #[test]
    fn the_monitoring_vps_is_not_a_server_to_run_an_app_on() {
        assert!(is_add_on("📊 SLV VPS for Advanced Monitoring"));
        assert!(!is_add_on(
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4"
        ));
    }

    #[test]
    fn a_time_zone_picks_the_nearest_region() {
        for (zone, region) in [
            ("Asia/Tokyo", "tokyo"),
            ("Asia/Hong_Kong", "singapore"),
            ("Europe/Amsterdam", "amsterdam"),
            ("Europe/Berlin", "frankfurt"),
            ("Europe/London", "london"),
            ("America/Los_Angeles", "ny"),
            ("Australia/Sydney", "sydney"),
            ("", "frankfurt"),
            ("UTC", "frankfurt"),
        ] {
            assert_eq!(region_for_zone(zone), region, "{zone}");
        }
    }

    #[test]
    fn a_line_that_never_became_active_is_said_in_the_chosen_language() {
        use erpc_core::i18n::Lang;
        let say = || {
            tn!(
                "worker_vps.line.not_active",
                3,
                kind = "gRPC",
                id = "100002",
                last = "pending"
            )
        };
        let english = say();
        assert_eq!(
            english,
            "gRPC line 100002 did not become active in 3 minutes (it is pending)"
        );
        for lang in [Lang::Ja, Lang::Ru] {
            let said = crate::i18n::speaking(lang, say);
            assert_ne!(said, english);
            assert!(!said.contains('{'), "{said}");
            assert!(
                said.contains("100002") && said.contains("pending"),
                "{said}"
            );
        }
        // Russian says three minutes as a few.
        assert!(crate::i18n::speaking(Lang::Ru, say).contains("3 минуты"));
    }
}
