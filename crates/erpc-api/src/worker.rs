// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! erpc worker apps kept in the ERPC account: an app's record, its
//! environments, and the servers and data lines taken into them.
//!
//! An app and an environment are named, not numbered: every route here is
//! `/v3/worker/apps/<app>` or `/v3/worker/apps/<app>/envs/<env>`, and a name
//! is checked against the rules erpc.toml already holds it to before it is
//! put in a path. Ids that do come back (the app's, a server's, a line's) are
//! opaque strings. The types here have no place for what a server or a line
//! is in the account -- its product and its number: an environment is read
//! with its servers by slot, size and region and its lines by kind, and
//! anything else a reply says about them is not read.
//!
//! Every put and delete is a compare-and-swap on the record's revision:
//! `expected_revision` `n` changes or deletes the record only if it is still
//! at `n`, and on a put, 0 makes the record and fails if it is there (no
//! record is at revision 0, so a delete expecting 0 is refused). Taking a
//! server or a line in carries no revision: the same request sent again is
//! a success, and one that would move it is refused. A write sent again
//! with the same content after its reply was lost is answered as a success.
//! No route here starts or ends anything that is paid for.
//!
//! A closed account is refused on every route with [`Code::AccountClosed`],
//! not taken for a session that has ended.
//!
//! Replies are read leniently: a field this version does not know is
//! ignored, and a slot, state or kind it does not know is kept as
//! [`Other`](Slot::Other) rather than refused, so an account that has moved
//! on still reads in an older erpc. An environment whose facts are in a
//! newer format than [`FACTS_FORMAT`] is the exception: it is refused with
//! [`WorkerError::NewerFormat`], so that it is never edited and written back
//! by a version that would drop what it does not know.
//!
//! Cleaned of control and reordering characters, and so safe to print: an
//! unknown value an open enum keeps as `Other`, and of a [`Refusal`] its
//! Display (and so [`WorkerError`]'s), its `code`, its `message`, and
//! [`Refusal::field`], [`Refusal::limit`] and [`Refusal::envs`]. A
//! refusal's `data`, and the fields of a record (a host, a host key, a
//! template, a region, …), are the account's text as sent: a caller escapes
//! them before printing.

use std::collections::BTreeMap;
use std::fmt;

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::ApiError;

/// The apps: `GET` lists them; one app is under it by name.
pub const APPS_URL: &str = "https://user-api.erpc.global/v3/worker/apps";

/// The format of [`Facts`] this version reads and writes. A record in a
/// newer format is not read: its fields could mean something this version
/// would get wrong.
pub const FACTS_FORMAT: u32 = 2;

/// Why a call about a worker app did not do what it was asked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkerError {
    /// The request failed, the session was refused, or the reply could not
    /// be read.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The account refused the request and said why.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// An app or environment name that cannot be one, caught before it
    /// was put in a path.
    #[error("{what} name {name:?} is not one erpc can send: {rule}")]
    Name {
        /// `app` or `environment`.
        what: &'static str,
        /// The name, as given.
        name: String,
        /// The rule it breaks.
        rule: &'static str,
    },
    /// The environment's facts are in a format newer than this version
    /// reads ([`FACTS_FORMAT`]). Reading them anyway and writing them back
    /// would drop what this version does not know. When the reply answered
    /// a write, the account had already taken the write.
    #[error("{}", newer_format_line(*found, *after_write))]
    NewerFormat {
        /// The format the record is in.
        found: u64,
        /// Whether the reply answered a write (`put_env`, `adopt_server`,
        /// `adopt_line`), which the account may already have applied.
        after_write: bool,
    },
    /// A wallet key the account does not take, caught before it was sent:
    /// it takes a public key of 32 bytes, in base58.
    #[error("wallet public key {key:?} is not 32 bytes in base58")]
    WalletKey {
        /// The key, as given.
        key: String,
    },
}

fn newer_format_line(found: u64, after_write: bool) -> String {
    let newer = format!(
        "the environment's record is in format {found}, newer than this erpc reads \
         ({FACTS_FORMAT})"
    );
    if after_write {
        format!(
            "{newer}; the write may already have been applied: update erpc before touching this \
             environment again"
        )
    } else {
        format!("{newer}; update erpc")
    }
}

/// A refusal from the account: the HTTP status, the code when there is one,
/// the message cut to one printable line, and the details the code carries
/// (`data`), as sent.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{}", self.line())]
pub struct Refusal {
    /// The HTTP status.
    pub status: u16,
    /// What was refused, when the reply named it. Some refusals come from
    /// in front of the worker routes and carry no code: a body that is not
    /// JSON, a session of a kind the route does not take.
    pub code: Option<Code>,
    /// The message, cut to one printable line.
    pub message: Option<String>,
    /// The details, or `null`.
    pub data: Value,
}

impl Refusal {
    fn line(&self) -> String {
        let code = self.code.as_ref().map(Code::as_str);
        match (code, &self.message) {
            (Some(code), Some(message)) => {
                format!(
                    "user-api refused the request ({}, {code}): {message}",
                    self.status
                )
            }
            (Some(code), None) => format!("user-api refused the request ({}, {code})", self.status),
            (None, Some(message)) => {
                format!("user-api refused the request ({}): {message}", self.status)
            }
            (None, None) => format!("user-api refused the request ({})", self.status),
        }
    }

    /// The revision the record is at, on [`Code::RevisionConflict`].
    #[must_use]
    pub fn current_revision(&self) -> Option<u64> {
        self.data.get("currentRevision").and_then(Value::as_u64)
    }

    /// The field the refusal points at, from the root of the request body
    /// (`facts.backup`, `id`, …), on [`Code::InvalidRequest`] and
    /// [`Code::ResourceNotFound`]. Cleaned like the message: safe to print.
    #[must_use]
    pub fn field(&self) -> Option<String> {
        self.data
            .get("field")
            .and_then(Value::as_str)
            .and_then(|f| one_line(f, DETAIL_MAX))
    }

    /// Which limit was reached, on [`Code::LimitExceeded`] (`line` for an
    /// environment's data lines). Cleaned like the message: safe to print.
    #[must_use]
    pub fn limit(&self) -> Option<String> {
        self.data
            .get("limit")
            .and_then(Value::as_str)
            .and_then(|l| one_line(l, DETAIL_MAX))
    }

    /// The environments that hold a start not yet on record, on
    /// [`Code::StartPending`]. Cleaned like the message: safe to print.
    #[must_use]
    pub fn envs(&self) -> Vec<String> {
        self.data
            .get("envs")
            .and_then(Value::as_array)
            .map(|envs| {
                envs.iter()
                    .filter_map(Value::as_str)
                    .filter_map(|e| one_line(e, DETAIL_MAX))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The longest message a [`Refusal`] keeps, in characters.
const MESSAGE_MAX: usize = 300;

/// The longest detail a [`Refusal`] hands out, in characters.
const DETAIL_MAX: usize = 128;

/// The longest unknown value an open enum keeps, in characters.
const OTHER_MAX: usize = 64;

/// The first line of `text` without control or reordering characters, at
/// most `max` characters; `None` when nothing is left.
fn one_line(text: &str, max: usize) -> Option<String> {
    let line: String = text
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control() && !crate::reorders(*c))
        .take(max)
        .collect();
    (!line.is_empty()).then_some(line)
}

/// An unknown value as an open enum keeps it: ASCII letters, digits, `_`,
/// `-` and `.`, anything else as `?`, at most [`OTHER_MAX`] characters. The
/// values the account uses are all of that shape, and one that is not is
/// not printed as sent.
fn token(text: &str) -> String {
    text.chars()
        .take(OTHER_MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Defines an enum read from a string the account sends, with the strings
/// this version knows and [`Other`](Slot::Other) for the rest.
macro_rules! open_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident = $text:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
            /// A value this version does not know, cleaned to letters,
            /// digits, `_`, `-` and `.` (anything else as `?`), at most 64
            /// characters.
            Other(String),
        }

        impl $name {
            /// The string the account uses.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Other(text) => text,
                }
            }
        }

        impl From<&str> for $name {
            fn from(text: &str) -> Self {
                match text {
                    $($text => Self::$variant,)+
                    other => Self::Other(token(other)),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Ok(Self::from(text.as_str()))
            }
        }
    };
}

open_enum! {
    /// What a refusal was about.
    Code {
        /// A name, type, length, count or address the account does not take
        /// ([`Refusal::field`] says which).
        InvalidRequest = "invalid_request",
        /// The facts are in a format the account does not read.
        UnsupportedFactsFormat = "unsupported_facts_format",
        /// The route is erpc's alone; a browser session came.
        DeviceSessionRequired = "device_session_required",
        /// An account access token came; no worker route takes one.
        AccessTokenNotAllowed = "access_token_not_allowed",
        /// No such app on this account.
        WorkerNotFound = "worker_not_found",
        /// No such environment in the app.
        EnvNotFound = "env_not_found",
        /// No such secret in the app.
        SecretNotFound = "secret_not_found",
        /// No such sealing key on this account.
        SealKeyNotFound = "seal_key_not_found",
        /// The server, line or storage key named is not this account's
        /// ([`Refusal::field`] says which).
        ResourceNotFound = "resource_not_found",
        /// A create (expected revision 0) found the record there.
        AlreadyExists = "already_exists",
        /// The record moved since it was read
        /// ([`Refusal::current_revision`]).
        RevisionConflict = "revision_conflict",
        /// An environment holds a start not yet on record
        /// ([`Refusal::envs`]).
        StartPending = "start_pending",
        /// A sealing key that cannot be used.
        SealKeyUnusable = "seal_key_unusable",
        /// A sealing key that is revoked.
        SealKeyRevoked = "seal_key_revoked",
        /// A fingerprint that does not match the key.
        FingerprintMismatch = "fingerprint_mismatch",
        /// The account is closed. Every route answers it, with status 401
        /// (409 when the account closed while the request was handled),
        /// and it is a refusal, not an ended session: signing in again
        /// does not help.
        AccountClosed = "ACCOUNT_CLOSED",
        /// The account has no user record.
        UserNotFound = "user_not_found",
        /// A limit was reached ([`Refusal::limit`]).
        LimitExceeded = "limit_exceeded",
        /// The server or line is already in another environment or slot.
        AlreadyAttached = "already_attached",
        /// That slot of the environment holds another server.
        SlotOccupied = "slot_occupied",
        /// Another slot of the environment already runs the app.
        AppRunningElsewhere = "app_running_elsewhere",
    }
}

open_enum! {
    /// Where a server sits in an environment. One environment has at most
    /// one of each: the one in use, and during a change of size the one
    /// coming in and the one going out.
    Slot {
        /// The server the environment runs on.
        Active = "active",
        /// The server taking over.
        Incoming = "incoming",
        /// The server being let go.
        Outgoing = "outgoing",
    }
}

open_enum! {
    /// The state of what a server or line is in the account: the status
    /// its product has there, or `gone` when it no longer is this
    /// account's, or no longer exists. Each kind of product has its own
    /// statuses (`available`, `provisioning`, `maintenance`, `suspended`,
    /// and for some lines `applying`, `error` or `cancelled`, among
    /// others), and they grow with the products: only `active` and `gone`
    /// are named here, and the rest are kept as [`Other`](State::Other).
    State {
        /// In use.
        Active = "active",
        /// Not this account's any more, or not there.
        Gone = "gone",
    }
}

open_enum! {
    /// What kind of ERPC data line.
    LineKind {
        /// A Geyser gRPC line.
        Grpc = "grpc",
        /// A Shreds line.
        Shreds = "shreds",
        /// A UDP forwarding line.
        Udp = "udp",
        /// An Unlimited RPC endpoint.
        Unlimited = "unlimited",
    }
}

open_enum! {
    /// Where the app's wallet key is kept on the operator's side. The key
    /// itself is never sent.
    WalletSource {
        /// A 1Password item.
        OnePassword = "1password",
        /// The system keychain.
        Keychain = "keychain",
        /// erpc's encrypted keystore.
        Keystore = "keystore",
    }
}

open_enum! {
    /// Where a deployed app's secret came from.
    SecretSource {
        /// A 1Password item.
        OnePassword = "1password",
        /// The system keychain.
        Keychain = "keychain",
        /// erpc's encrypted keystore.
        Keystore = "keystore",
        /// Sealed in the ERPC account.
        Erpc = "erpc",
    }
}

open_enum! {
    /// A service the app runs beside it.
    Service {
        /// Redis.
        Redis = "redis",
        /// PostgreSQL.
        Postgres = "postgres",
    }
}

/// What kind of server is taken into an environment. Sent, never read
/// back: a reply does not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerKind {
    /// A VPS.
    Vps,
    /// A Super VPS.
    SuperVps,
    /// A Premium VPS.
    PremiumVps,
    /// A bare-metal server.
    BareMetal,
}

/// The slot a server is taken into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdoptSlot {
    /// As the server the environment runs on.
    Active,
    /// As the server taking over.
    Incoming,
}

/// An app, as the account keeps it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct App {
    /// The app's id in the account: opaque, and the same for as long as
    /// the app is.
    pub id: String,
    /// Its name.
    pub name: String,
    /// The chain it is for.
    pub chain: String,
    /// The template it was made from.
    #[serde(default)]
    pub template: Option<String>,
    /// Its wallet's public side.
    #[serde(default)]
    pub wallet: Option<Wallet>,
    /// The revision of the app's own record.
    pub revision: u64,
    /// When it was made.
    #[serde(default)]
    pub created_at: Option<String>,
    /// When it last changed.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// Its environments.
    #[serde(default)]
    pub envs: Vec<EnvSummary>,
    /// Its sealed secrets: names and versions, never values. Only when one
    /// app is read.
    #[serde(default)]
    pub secrets: Vec<SecretSummary>,
}

/// The public side of an app's wallet, as a reply shows it. A write sends
/// a [`PutWallet`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Wallet {
    /// The public key, base58.
    pub pubkey: String,
    /// Where the key is kept. Read leniently: absent when a reply does not
    /// say.
    #[serde(default)]
    pub source_kind: Option<WalletSource>,
}

/// The public side of an app's wallet, as a write sends it: its public key
/// and where the private key is kept, which the account takes only
/// together. Nothing else about the wallet is sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PutWallet {
    /// The public key: 32 bytes, base58.
    pub pubkey: String,
    /// Where the private key is kept.
    pub source_kind: WalletSource,
}

impl PutWallet {
    /// The wallet with public key `pubkey`, its private key kept in
    /// `source_kind`.
    ///
    /// # Errors
    ///
    /// [`WorkerError::WalletKey`] when `pubkey` is not 32 bytes in base58,
    /// which the account would refuse.
    pub fn new(pubkey: impl Into<String>, source_kind: WalletSource) -> Result<Self, WorkerError> {
        let pubkey = pubkey.into();
        if base58_len(&pubkey) != Some(32) {
            return Err(WorkerError::WalletKey { key: pubkey });
        }
        Ok(Self {
            pubkey,
            source_kind,
        })
    }
}

/// How many bytes `text` is in base58, or `None` when it is not base58 or
/// is longer than a 32-byte key can be (44 characters).
fn base58_len(text: &str) -> Option<usize> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if text.len() > 44 {
        return None;
    }
    // The number, little-endian, without the zero bytes the leading `1`s
    // stand for.
    let mut number: Vec<u8> = Vec::with_capacity(33);
    for c in text.bytes() {
        let mut carry = u32::try_from(ALPHABET.iter().position(|&a| a == c)?).ok()?;
        for byte in &mut number {
            carry += u32::from(*byte) * 58;
            *byte = carry.to_le_bytes()[0];
            carry >>= 8;
        }
        while carry > 0 {
            number.push(carry.to_le_bytes()[0]);
            carry >>= 8;
        }
    }
    let zeros = text.bytes().take_while(|&c| c == b'1').count();
    Some(zeros + number.len())
}

/// A sealed secret's record: never its value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SecretSummary {
    /// The setting's name.
    pub name: String,
    /// Its version.
    pub version: u64,
    /// Who set it: `browser` or `erpc-cli`.
    #[serde(default)]
    pub set_via: Option<String>,
    /// How it was sealed: `base` or `auth`.
    #[serde(default)]
    pub seal_mode: Option<String>,
    /// The key of the machine that sealed it, in `auth` mode.
    #[serde(default)]
    pub sender_seal_key_id: Option<String>,
    /// The keys it is sealed to.
    #[serde(default)]
    pub sealed_key_ids: Vec<String>,
    /// Approved keys it is not sealed to.
    #[serde(default)]
    pub missing_key_ids: Vec<String>,
    /// When it last changed.
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// One environment of an app, as a list shows it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct EnvSummary {
    /// Its name.
    pub name: String,
    /// The revision of its record.
    pub revision: u64,
    /// Its servers, by slot.
    #[serde(default)]
    pub servers: Vec<Server>,
    /// The cores asked for.
    #[serde(default)]
    pub desired_cores: Option<u16>,
    /// The cores of the server in use.
    #[serde(default)]
    pub active_cores: Option<u16>,
    /// The sizes the server in use can change to, in cores.
    #[serde(default)]
    pub core_options: Vec<u16>,
    /// The server's address.
    #[serde(default)]
    pub host: Option<String>,
    /// Its data lines.
    #[serde(default)]
    pub lines: Vec<Line>,
    /// Whether a start is not yet on record.
    #[serde(default)]
    pub start_pending: bool,
    /// The last deploy.
    #[serde(default)]
    pub deployed: Option<Deployed>,
}

/// One environment of an app, whole.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct EnvDetail {
    /// Its name.
    pub name: String,
    /// The revision of its record.
    pub revision: u64,
    /// The format its facts are in ([`FACTS_FORMAT`]).
    pub facts_format: u32,
    /// What erpc wrote about the server.
    pub facts: Facts,
    /// Its servers, by slot.
    #[serde(default)]
    pub servers: Vec<Server>,
    /// The cores asked for.
    #[serde(default)]
    pub desired_cores: Option<u16>,
    /// The cores of the server in use.
    #[serde(default)]
    pub active_cores: Option<u16>,
    /// The sizes the server in use can change to, in cores.
    #[serde(default)]
    pub core_options: Vec<u16>,
    /// Its data lines, with their endpoints.
    #[serde(default)]
    pub lines: Vec<Line>,
    /// The state of what the facts refer to.
    #[serde(default)]
    pub ref_states: RefStates,
    /// The last deploy.
    #[serde(default)]
    pub deployed: Option<Deployed>,
    /// What the last deploy shipped.
    #[serde(default)]
    pub deployed_app: Option<DeployedApp>,
    /// When it last changed.
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// A server in an environment, without what it is in the account.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Server {
    /// Its id in the environment: opaque.
    pub id: String,
    /// Where it sits.
    pub slot: Slot,
    /// Its cores, when known.
    #[serde(default)]
    pub cores: Option<u16>,
    /// Its memory in GB, when known.
    #[serde(default)]
    pub memory_gb: Option<u32>,
    /// Its region.
    #[serde(default)]
    pub region: Option<String>,
    /// Whether it is paid by the hour.
    #[serde(default)]
    pub hourly: bool,
    /// Whether the app runs on it, as erpc last wrote.
    #[serde(default)]
    pub app_running: bool,
    /// Its state in the account.
    pub state: State,
}

/// A data line in an environment, by kind, without its number.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Line {
    /// Its id in the environment: opaque.
    pub id: String,
    /// What kind of line.
    pub kind: LineKind,
    /// Whether it is paid by the hour.
    #[serde(default)]
    pub hourly: bool,
    /// Whether its endpoint is not ready yet.
    #[serde(default)]
    pub pending: bool,
    /// Its state in the account.
    pub state: State,
    /// Where the app reaches it, when one environment is read whole.
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// The state of what the facts refer to.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RefStates {
    /// The backup's storage key, when there is a backup.
    #[serde(default)]
    pub backup: Option<State>,
}

/// A deploy, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Deployed {
    /// The release.
    pub release: String,
    /// When.
    pub at: String,
    /// The machine it was deployed from, by host name. Not in a list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

impl Deployed {
    /// A deploy of `release` at `at` (RFC 3339), from the machine named
    /// `from`.
    #[must_use]
    pub fn new(release: impl Into<String>, at: impl Into<String>, from: impl Into<String>) -> Self {
        Self {
            release: release.into(),
            at: at.into(),
            from: Some(from.into()),
        }
    }
}

/// What a deploy shipped: the app's definition at that moment, without a
/// value or a reference to one.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DeployedApp {
    /// The chain.
    pub chain: String,
    /// The template.
    #[serde(default)]
    pub template: Option<String>,
    /// The port the app listens on.
    #[serde(default)]
    pub run_port: Option<u16>,
    /// The web application firewall in front of it.
    #[serde(default)]
    pub waf: Option<DeployedWaf>,
    /// The services beside it.
    #[serde(default)]
    pub services: Vec<Service>,
    /// The names of its plain settings.
    #[serde(default)]
    pub var_names: Vec<String>,
    /// Its secrets, by name and where each came from.
    #[serde(default)]
    pub secrets: Vec<DeployedSecret>,
}

/// The web application firewall of a deploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeployedWaf {
    /// The port it listens on.
    pub port: u16,
}

impl DeployedWaf {
    /// A firewall on `port`.
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self { port }
    }
}

/// A secret of a deploy: its name and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeployedSecret {
    /// The setting's name.
    pub name: String,
    /// Where its value came from.
    pub kind: SecretSource,
}

impl DeployedSecret {
    /// The secret `name`, from `kind`.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: SecretSource) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}

/// What erpc keeps about an environment's server in the account, in format
/// [`FACTS_FORMAT`]. Which server and which lines the environment has are
/// not here: they are taken in with [`adopt_server`] and [`adopt_line`].
///
/// Every field is sent, `null` included: the account requires each one,
/// and refuses a write that leaves one out with [`Code::InvalidRequest`]
/// naming it ([`Refusal::field`]). An empty firewall is two empty lists,
/// and no start is an empty map.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Facts {
    /// The server's address.
    #[serde(default)]
    pub host: Option<String>,
    /// The account erpc signs in to over SSH.
    #[serde(default)]
    pub ssh_user: Option<String>,
    /// The SSH port, when it is not 22.
    #[serde(default)]
    pub ssh_port: Option<u16>,
    /// The server's pinned SSH host key, one OpenSSH public key line.
    #[serde(default)]
    pub host_key: Option<String>,
    /// Who may reach the server.
    #[serde(default)]
    pub firewall: Firewall,
    /// The starts not yet on record, by what was being started.
    #[serde(default)]
    pub starting: BTreeMap<String, Start>,
    /// The storage key a backup uses.
    #[serde(default)]
    pub backup: Option<Backup>,
    /// The cores asked for: 1, 2, 4, 8 or 16.
    #[serde(default)]
    pub desired_cores: Option<u16>,
}

/// Who may reach a server: addresses in CIDR form.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Firewall {
    /// Who may reach SSH.
    #[serde(default)]
    pub ssh_allow: Vec<String>,
    /// Who may reach the app.
    #[serde(default)]
    pub app_allow: Vec<String>,
}

impl Firewall {
    /// A firewall letting `ssh_allow` reach SSH and `app_allow` the app.
    #[must_use]
    pub const fn new(ssh_allow: Vec<String>, app_allow: Vec<String>) -> Self {
        Self {
            ssh_allow,
            app_allow,
        }
    }
}

/// A start whose outcome is not on record yet. Its key is what makes the
/// start the same one when it is sent again, and is never printed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Start {
    /// The idempotency key: 32 lowercase hex digits.
    pub key: String,
    /// The product family.
    pub family: String,
    /// The product.
    pub product: String,
    /// The region.
    #[serde(default)]
    pub region: Option<String>,
    /// The address a line is opened for.
    #[serde(default)]
    pub ip: Option<String>,
}

impl Start {
    /// A start of `product` of `family` under `key`.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        family: impl Into<String>,
        product: impl Into<String>,
        region: Option<String>,
        ip: Option<String>,
    ) -> Self {
        Self {
            key: key.into(),
            family: family.into(),
            product: product.into(),
            region,
            ip,
        }
    }
}

impl fmt::Debug for Start {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Start")
            .field("key", &"<redacted>")
            .field("family", &self.family)
            .field("product", &self.product)
            .field("region", &self.region)
            .field("ip", &self.ip)
            .finish()
    }
}

/// The storage key a backup uses: ids, not secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Backup {
    /// The storage access key's id.
    pub access_key: u64,
    /// The id of the backup repository's key: 64 hex digits.
    pub restic_key: String,
    /// The storage host.
    pub host: String,
}

impl Backup {
    /// A backup through access key `access_key` to `host`.
    #[must_use]
    pub fn new(access_key: u64, restic_key: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            access_key,
            restic_key: restic_key.into(),
            host: host.into(),
        }
    }
}

/// The body that makes or changes an app's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PutApp {
    /// 0 to make it, else the revision it was read at.
    pub expected_revision: u64,
    /// The chain it is for.
    pub chain: String,
    /// The template it was made from.
    pub template: Option<String>,
    /// Its wallet's public side, or `None` for an app without a wallet.
    pub wallet: Option<PutWallet>,
}

impl PutApp {
    /// A write of an app for `chain`, expecting it at `expected_revision`.
    #[must_use]
    pub fn new(
        expected_revision: u64,
        chain: impl Into<String>,
        template: Option<String>,
        wallet: Option<PutWallet>,
    ) -> Self {
        Self {
            expected_revision,
            chain: chain.into(),
            template,
            wallet,
        }
    }
}

/// The body that makes or changes an environment's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PutEnv {
    /// 0 to make it, else the revision it was read at.
    pub expected_revision: u64,
    /// Always [`FACTS_FORMAT`].
    pub facts_format: u32,
    /// The facts.
    pub facts: Facts,
    /// The last deploy. Left out when `None`, which the account takes as
    /// `null`: no deploy on record. A put replaces the whole environment,
    /// so a write that is not a deploy sends the last one again to keep it
    /// ([`PutEnv::with_deploy`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployed: Option<Deployed>,
    /// What the last deploy shipped, the same way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployed_app: Option<DeployedApp>,
}

impl PutEnv {
    /// A write of `facts`, expecting the record at `expected_revision`,
    /// with no deploy on record: one already there is cleared.
    #[must_use]
    pub const fn new(expected_revision: u64, facts: Facts) -> Self {
        Self {
            expected_revision,
            facts_format: FACTS_FORMAT,
            facts,
            deployed: None,
            deployed_app: None,
        }
    }

    /// The same write, with `deployed` on record: a new deploy, or the last
    /// one sent again to keep it.
    #[must_use]
    pub fn with_deploy(mut self, deployed: Deployed, deployed_app: DeployedApp) -> Self {
        self.deployed = Some(deployed);
        self.deployed_app = Some(deployed_app);
        self
    }
}

/// The body that takes a server the account already has into an
/// environment. Nothing is started or paid for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AdoptServer {
    /// What kind of server.
    pub kind: ServerKind,
    /// Its number in the account.
    pub id: u64,
    /// The slot to put it in.
    pub slot: AdoptSlot,
    /// Whether the app runs on it now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_running: Option<bool>,
}

impl AdoptServer {
    /// Server `id` of `kind` into `slot`.
    #[must_use]
    pub const fn new(
        kind: ServerKind,
        id: u64,
        slot: AdoptSlot,
        app_running: Option<bool>,
    ) -> Self {
        Self {
            kind,
            id,
            slot,
            app_running,
        }
    }
}

/// The body that takes a data line the account already has into an
/// environment. Nothing is started or paid for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AdoptLine {
    /// What kind of line.
    pub kind: LineKind,
    /// Its number in the account.
    pub id: u64,
}

impl AdoptLine {
    /// Line `id` of `kind`.
    #[must_use]
    pub const fn new(kind: LineKind, id: u64) -> Self {
        Self { kind, id }
    }
}

/// A record written: whether it was made by this write, and the record as
/// it now is.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Written<T> {
    /// `true` when this write made the record, `false` when it changed one
    /// or was the same write sent again.
    pub created: bool,
    /// The record after the write.
    pub record: T,
}

/// What deleting an app or an environment answers.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct Deleted {
    /// The app or environment.
    pub name: String,
    /// Whether it was deleted.
    pub deleted: bool,
}

/// The rule an app name follows: up to 32 characters, a lowercase letter
/// first, then lowercase letters and digits, single dashes between them.
const NAME_RULE: &str = "up to 32 characters: a lowercase letter, then lowercase letters, digits \
                         and single dashes, not ending in a dash";

fn is_slug(name: &str, max: usize) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > max || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut dash = false;
    for &b in &bytes[1..] {
        match b {
            b'-' if dash => return false,
            b'-' => dash = true,
            b'a'..=b'z' | b'0'..=b'9' => dash = false,
            _ => return false,
        }
    }
    !dash
}

/// Whether `name` can name an app: up to 32 characters.
#[must_use]
pub fn is_app_name(name: &str) -> bool {
    is_slug(name, 32)
}

/// Whether `name` can name an environment: up to 16 characters.
#[must_use]
pub fn is_env_name(name: &str) -> bool {
    is_slug(name, 16)
}

fn app_url(app: &str) -> Result<String, WorkerError> {
    if !is_app_name(app) {
        return Err(WorkerError::Name {
            what: "app",
            name: app.to_owned(),
            rule: NAME_RULE,
        });
    }
    Ok(format!("{APPS_URL}/{app}"))
}

fn env_url(app: &str, env: &str) -> Result<String, WorkerError> {
    let app = app_url(app)?;
    if !is_env_name(env) {
        return Err(WorkerError::Name {
            what: "environment",
            name: env.to_owned(),
            rule: "up to 16 characters: a lowercase letter, then lowercase letters, digits and \
                   single dashes, not ending in a dash",
        });
    }
    Ok(format!("{app}/envs/{env}"))
}

/// The message of a reply, cut to one printable line.
fn message_of(body: &Value) -> Option<String> {
    one_line(body.get("message").and_then(Value::as_str)?, MESSAGE_MAX)
}

/// Reads a reply: `data` of a success, with whether it was a 201, or the
/// refusal. A 401 is an ended session, unless it says the account is
/// closed.
fn reply<T: DeserializeOwned>(status: u16, text: &str) -> Result<Written<T>, WorkerError> {
    let body: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        let data = body
            .get("data")
            .filter(|_| body.get("success").and_then(Value::as_bool) != Some(false))
            .cloned()
            .ok_or_else(|| ApiError::Malformed("a success without data".to_owned()))?;
        let record =
            serde_json::from_value(data).map_err(|e| ApiError::Malformed(e.to_string()))?;
        return Ok(Written {
            created: status == 201,
            record,
        });
    }
    let code = body.get("code").and_then(Value::as_str).map(Code::from);
    if status == 401 && code != Some(Code::AccountClosed) {
        return Err(ApiError::Unauthorized.into());
    }
    Err(Refusal {
        status,
        code,
        message: message_of(&body),
        data: body.get("data").cloned().unwrap_or(Value::Null),
    }
    .into())
}

/// Reads a reply that is an environment's record: as [`reply`], except that
/// a success with facts in a format newer than [`FACTS_FORMAT`] is
/// [`WorkerError::NewerFormat`], before its facts are read at all (they may
/// not even parse). `after_write` says the reply answered a write.
fn env_reply(
    status: u16,
    text: &str,
    after_write: bool,
) -> Result<Written<EnvDetail>, WorkerError> {
    if (200..300).contains(&status)
        && let Ok(body) = serde_json::from_str::<Value>(text)
        && let Some(found) = body
            .get("data")
            .and_then(|data| data.get("factsFormat"))
            .and_then(Value::as_u64)
        && found > u64::from(FACTS_FORMAT)
    {
        return Err(WorkerError::NewerFormat { found, after_write });
    }
    reply(status, text)
}

fn encode<T: Serialize>(body: &T) -> Result<Vec<u8>, WorkerError> {
    serde_json::to_vec(body).map_err(|e| ApiError::Malformed(e.to_string()).into())
}

async fn get(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
) -> Result<(u16, String), WorkerError> {
    Ok(client
        .get_with_token(Audience::AuthApi, url, access_token)
        .await
        .map_err(ApiError::from)?)
}

async fn put<B: Serialize>(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
    body: &B,
) -> Result<(u16, String), WorkerError> {
    Ok(client
        .put_with_token(Audience::AuthApi, url, access_token, encode(body)?)
        .await
        .map_err(ApiError::from)?)
}

async fn post<B: Serialize>(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
    body: &B,
) -> Result<(u16, String), WorkerError> {
    Ok(client
        .post_with_token(Audience::AuthApi, url, access_token, encode(body)?, None)
        .await
        .map_err(ApiError::from)?)
}

async fn delete(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
    expected_revision: u64,
) -> Result<(u16, String), WorkerError> {
    let url = format!("{url}?expectedRevision={expected_revision}");
    Ok(client
        .delete_with_token(Audience::AuthApi, &url, access_token, None)
        .await
        .map_err(ApiError::from)?)
}

/// The account's apps, each with its environments and without secrets.
/// The list is whole, in one reply: an account has at most 100 apps (one
/// more is refused with [`Code::LimitExceeded`], limit `worker`), an app at
/// most 16 environments, and an environment at most 8 lines.
///
/// # Errors
///
/// [`WorkerError`] when the request fails or is refused.
pub async fn list_apps(
    client: &AuthClient,
    access_token: &SecretString,
) -> Result<Vec<App>, WorkerError> {
    let (status, text) = get(client, access_token, APPS_URL).await?;
    reply(status, &text).map(|w| w.record)
}

/// The app `app`, with its environments and its secrets' records.
///
/// # Errors
///
/// [`Code::WorkerNotFound`] when the account has no such app, and
/// [`WorkerError`] when the request fails or is refused otherwise.
pub async fn get_app(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
) -> Result<App, WorkerError> {
    let (status, text) = get(client, access_token, &app_url(app)?).await?;
    reply(status, &text).map(|w| w.record)
}

/// Makes the app `app` (expected revision 0) or changes it.
///
/// # Errors
///
/// [`Code::AlreadyExists`] or [`Code::RevisionConflict`] when the record is
/// not where `body` expects it, and [`WorkerError`] when the request fails
/// or is refused otherwise.
pub async fn put_app(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    body: &PutApp,
) -> Result<Written<App>, WorkerError> {
    let (status, text) = put(client, access_token, &app_url(app)?, body).await?;
    reply(status, &text)
}

/// Deletes the app `app`'s record: its environments, lines and secrets
/// with it. Nothing it runs on is stopped or ended.
///
/// # Errors
///
/// [`Code::StartPending`] while an environment holds a start not yet on
/// record, [`Code::RevisionConflict`] when the app moved since
/// `expected_revision`, [`Code::WorkerNotFound`] when there is no such app,
/// and [`WorkerError`] when the request fails or is refused otherwise. An
/// `expected_revision` of 0 does not mean "whatever it is at": it matches
/// no app, so it is a conflict when the app is there.
pub async fn delete_app(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    expected_revision: u64,
) -> Result<Deleted, WorkerError> {
    let (status, text) = delete(client, access_token, &app_url(app)?, expected_revision).await?;
    reply(status, &text).map(|w| w.record)
}

/// The environment `env` of `app`, whole: its facts, servers, lines with
/// their endpoints, and last deploy.
///
/// # Errors
///
/// [`Code::WorkerNotFound`] or [`Code::EnvNotFound`] when there is no such
/// app or environment, [`WorkerError::NewerFormat`] when its facts are in a
/// format newer than this version reads, and [`WorkerError`] when the
/// request fails or is refused otherwise.
pub async fn get_env(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
) -> Result<EnvDetail, WorkerError> {
    let (status, text) = get(client, access_token, &env_url(app, env)?).await?;
    env_reply(status, &text, false).map(|w| w.record)
}

/// Makes the environment `env` of `app` (expected revision 0) or replaces
/// its record: its facts and its deploy (see [`PutEnv::deployed`]). Its
/// servers and lines are not touched.
///
/// # Errors
///
/// [`Code::AlreadyExists`] or [`Code::RevisionConflict`] when the record is
/// not where `body` expects it, [`Code::InvalidRequest`] and
/// [`Code::ResourceNotFound`] for a fact the account does not take,
/// [`WorkerError::NewerFormat`] when the record comes back in a newer format
/// than this version reads (the write may already have been applied), and
/// [`WorkerError`] when the request fails or is refused otherwise.
pub async fn put_env(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    body: &PutEnv,
) -> Result<Written<EnvDetail>, WorkerError> {
    let (status, text) = put(client, access_token, &env_url(app, env)?, body).await?;
    env_reply(status, &text, true)
}

/// Deletes the environment `env` of `app`'s record. Nothing it runs on is
/// stopped or ended.
///
/// # Errors
///
/// [`Code::StartPending`] while it holds a start not yet on record,
/// [`Code::RevisionConflict`] when it moved since `expected_revision`,
/// [`Code::WorkerNotFound`] or [`Code::EnvNotFound`] when there is no such
/// app or environment, and [`WorkerError`] when the request fails or is
/// refused otherwise.
pub async fn delete_env(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    expected_revision: u64,
) -> Result<Deleted, WorkerError> {
    let (status, text) =
        delete(client, access_token, &env_url(app, env)?, expected_revision).await?;
    reply(status, &text).map(|w| w.record)
}

/// Takes a server the account already has into the environment `env` of
/// `app`. The same request sent again is a success; nothing is started or
/// paid for.
///
/// # Errors
///
/// [`Code::ResourceNotFound`] when the server is not this account's,
/// [`Code::AlreadyAttached`], [`Code::SlotOccupied`] and
/// [`Code::AppRunningElsewhere`] when it cannot go where asked,
/// [`WorkerError::NewerFormat`] when the environment comes back in a newer
/// format than this version reads (the server may already have been taken
/// in), and [`WorkerError`] when the request fails or is refused otherwise.
pub async fn adopt_server(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    body: &AdoptServer,
) -> Result<Written<EnvDetail>, WorkerError> {
    let url = format!("{}/server/adopt", env_url(app, env)?);
    let (status, text) = post(client, access_token, &url, body).await?;
    env_reply(status, &text, true)
}

/// Takes a data line the account already has into the environment `env` of
/// `app`. The same request sent again is a success; nothing is started or
/// paid for.
///
/// # Errors
///
/// [`Code::ResourceNotFound`] when the line is not this account's,
/// [`Code::AlreadyAttached`] when another environment has it,
/// [`Code::LimitExceeded`] when the environment has as many lines as it
/// may, [`WorkerError::NewerFormat`] when the environment comes back in a
/// newer format than this version reads (the line may already have been
/// taken in), and [`WorkerError`] when the request fails or is refused
/// otherwise.
pub async fn adopt_line(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    body: &AdoptLine,
) -> Result<Written<EnvDetail>, WorkerError> {
    let url = format!("{}/lines/adopt", env_url(app, env)?);
    let (status, text) = post(client, access_token, &url, body).await?;
    env_reply(status, &text, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const APP_ID: &str = "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13";
    const SERVER_ID: &str = "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60";
    const LINE_ID: &str = "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314";
    const KEY_ID: &str = "e2d95b18-7a4c-4f03-b6e9-51c8a2d7f0b4";

    fn env_detail_json() -> Value {
        json!({
            "name": "prod",
            "revision": 7,
            "factsFormat": 2,
            "facts": {
                "host": "203.0.113.10",
                "sshUser": "ubuntu",
                "sshPort": null,
                "hostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyNotARealKey000000000000000",
                "firewall": { "sshAllow": ["198.51.100.7/32"], "appAllow": [] },
                "starting": {},
                "backup": null,
                "desiredCores": 4
            },
            "servers": [{
                "id": SERVER_ID, "slot": "active", "cores": 2, "memoryGb": 8,
                "region": "amsterdam", "hourly": true, "appRunning": true, "state": "active"
            }],
            "desiredCores": 4,
            "activeCores": 2,
            "coreOptions": [1, 2, 4, 8],
            "lines": [{
                "id": LINE_ID, "kind": "grpc", "hourly": true, "pending": false,
                "state": "active", "endpoint": "grpc.example.net:443"
            }],
            "refStates": { "backup": null },
            "deployed": {
                "release": "20261029T154037Z-6914df5f",
                "at": "2026-10-29T15:40:37.000Z",
                "from": "deploy-laptop"
            },
            "deployedApp": {
                "chain": "solana", "template": "solana/pumpfun@1", "runPort": 3000, "waf": null,
                "services": ["redis"], "varNames": ["API_PORT", "RUST_LOG"],
                "secrets": [
                    { "name": "ERPC_API_KEY", "kind": "keychain" },
                    { "name": "API_TOKEN", "kind": "erpc" }
                ]
            },
            "updatedAt": "2026-10-29T15:40:37.000Z"
        })
    }

    fn ok(status: u16, data: &Value) -> (u16, String) {
        (
            status,
            json!({ "success": true, "message": "ok", "data": data }).to_string(),
        )
    }

    #[test]
    fn the_apps_endpoint_is_a_declared_host_the_allowlist_permits() {
        assert!(erpc_core::endpoints::ensure_service_url(APPS_URL).is_ok());
        for url in [
            APPS_URL.to_owned(),
            app_url("pump-sniper").expect("app"),
            env_url("pump-sniper", "prod").expect("env"),
        ] {
            assert!(
                erpc_auth::allowlist::ensure_token_destination(Audience::AuthApi, &url).is_ok(),
                "{url}"
            );
        }
    }

    #[test]
    fn paths_are_built_from_checked_names_only() {
        assert_eq!(
            env_url("pump-sniper", "prod").expect("env"),
            "https://user-api.erpc.global/v3/worker/apps/pump-sniper/envs/prod"
        );
        for bad in [
            "",
            "Pump",
            "1app",
            "a--b",
            "a-",
            "a/b",
            "a?x=1",
            "..",
            "a b",
            "a%2f",
            "abcdefghijklmnopqrstuvwxyzabcdefg",
        ] {
            assert!(app_url(bad).is_err(), "{bad:?}");
        }
        assert!(is_app_name(&"a".repeat(32)));
        assert!(is_env_name(&"a".repeat(16)));
        assert!(!is_env_name(&"a".repeat(17)));
        assert!(matches!(
            env_url("pump-sniper", "../x"),
            Err(WorkerError::Name {
                what: "environment",
                ..
            })
        ));
    }

    #[test]
    fn an_environment_is_read_whole() {
        let (status, text) = ok(200, &env_detail_json());
        let w: Written<EnvDetail> = reply(status, &text).expect("reads");
        assert!(!w.created);
        let env = w.record;
        assert_eq!(env.facts_format, FACTS_FORMAT);
        assert_eq!(env.facts.host.as_deref(), Some("203.0.113.10"));
        assert_eq!(env.facts.firewall.ssh_allow, ["198.51.100.7/32"]);
        assert_eq!(env.facts.desired_cores, Some(4));
        assert_eq!(env.servers.len(), 1);
        let server = &env.servers[0];
        assert_eq!(server.id, SERVER_ID);
        assert_eq!(server.slot, Slot::Active);
        assert_eq!((server.cores, server.memory_gb), (Some(2), Some(8)));
        assert!(server.app_running);
        assert_eq!(server.state, State::Active);
        assert_eq!((env.desired_cores, env.active_cores), (Some(4), Some(2)));
        assert_eq!(env.core_options, [1, 2, 4, 8]);
        assert_eq!(env.lines[0].kind, LineKind::Grpc);
        assert_eq!(
            env.lines[0].endpoint.as_deref(),
            Some("grpc.example.net:443")
        );
        assert_eq!(env.ref_states.backup, None);
        assert_eq!(
            env.deployed.as_ref().and_then(|d| d.from.as_deref()),
            Some("deploy-laptop")
        );
        let app = env.deployed_app.expect("deployed app");
        assert_eq!(app.services, [Service::Redis]);
        assert_eq!(app.secrets[1].kind, SecretSource::Erpc);
    }

    #[test]
    fn a_reply_names_no_server_product_or_number() {
        // What a server is in the account is not in the types: a reply that
        // carries it anyway is read without it.
        let mut detail = env_detail_json();
        detail["servers"][0]["kind"] = json!("vps");
        detail["servers"][0]["refId"] = json!(200_002);
        detail["lines"][0]["refId"] = json!(300_003);
        let env: EnvDetail = serde_json::from_value(detail).expect("reads");
        let shown = format!("{env:?}");
        assert!(
            !shown.contains("200002") && !shown.contains("300003"),
            "{shown}"
        );
        assert!(
            !shown.contains("\"vps\"") && !shown.contains("Vps"),
            "{shown}"
        );
    }

    #[test]
    fn unknown_fields_and_values_from_a_newer_account_are_kept_not_refused() {
        let mut detail = env_detail_json();
        detail["somethingNew"] = json!({ "x": 1 });
        detail["servers"][0]["slot"] = json!("standby");
        detail["servers"][0]["state"] = json!("suspended");
        detail["lines"][0]["kind"] = json!("laser");
        detail["deployedApp"]["services"] = json!(["redis", "kafka"]);
        let env: EnvDetail = serde_json::from_value(detail).expect("reads");
        assert_eq!(env.servers[0].slot, Slot::Other("standby".to_owned()));
        assert_eq!(env.servers[0].state.as_str(), "suspended");
        assert_eq!(env.lines[0].kind.to_string(), "laser");
        assert_eq!(
            env.deployed_app.expect("app").services[1],
            Service::Other("kafka".to_owned())
        );
    }

    #[test]
    fn a_server_with_nothing_known_about_it_still_reads() {
        let server: Server = serde_json::from_value(json!({
            "id": SERVER_ID, "slot": "outgoing", "cores": null, "memoryGb": null,
            "region": null, "hourly": false, "appRunning": false, "state": "gone"
        }))
        .expect("reads");
        assert_eq!(server.slot, Slot::Outgoing);
        assert_eq!(server.state, State::Gone);
        assert_eq!(server.cores, None);
    }

    #[test]
    fn apps_are_listed_with_their_environments() {
        let list = json!([{
            "id": APP_ID,
            "name": "pump-sniper",
            "chain": "solana",
            "template": "solana/pumpfun@1",
            "wallet": { "pubkey": "11111111111111111111111111111111" },
            "revision": 3,
            "createdAt": "2026-10-29T15:40:37.000Z",
            "updatedAt": "2026-10-29T15:40:37.000Z",
            "envs": [{
                "name": "prod",
                "revision": 7,
                "servers": [],
                "desiredCores": null,
                "activeCores": null,
                "coreOptions": [],
                "host": "203.0.113.10",
                "lines": [{ "id": LINE_ID, "kind": "shreds", "hourly": true, "pending": true, "state": "active" }],
                "startPending": false,
                "deployed": { "release": "20261029T154037Z-6914df5f", "at": "2026-10-29T15:40:37.000Z" }
            }]
        }]);
        let (status, text) = ok(200, &list);
        let apps: Written<Vec<App>> = reply(status, &text).expect("reads");
        let app = &apps.record[0];
        assert_eq!(app.id, APP_ID);
        assert_eq!(
            app.wallet.as_ref().map(|w| w.source_kind.is_none()),
            Some(true)
        );
        assert!(app.secrets.is_empty());
        let env = &app.envs[0];
        assert_eq!(env.host.as_deref(), Some("203.0.113.10"));
        assert!(env.lines[0].pending);
        assert_eq!(env.lines[0].endpoint, None);
        assert_eq!(env.deployed.as_ref().and_then(|d| d.from.clone()), None);
    }

    #[test]
    fn one_app_reads_with_its_secrets_records() {
        let app = json!({
            "id": APP_ID, "name": "pump-sniper", "chain": "solana", "template": null,
            "wallet": { "pubkey": "11111111111111111111111111111111", "sourceKind": "keystore" },
            "revision": 1, "createdAt": "2026-10-29T15:40:37.000Z", "updatedAt": "2026-10-29T15:40:37.000Z",
            "envs": [],
            "secrets": [{
                "name": "API_TOKEN", "version": 2, "setVia": "browser", "sealMode": "base",
                "senderSealKeyId": null, "sealedKeyIds": [KEY_ID], "missingKeyIds": [],
                "updatedAt": "2026-10-29T15:40:37.000Z"
            }]
        });
        let (status, text) = ok(201, &app);
        let w: Written<App> = reply(status, &text).expect("reads");
        assert!(w.created);
        assert_eq!(
            w.record.wallet.and_then(|w| w.source_kind),
            Some(WalletSource::Keystore)
        );
        assert_eq!(w.record.secrets[0].sealed_key_ids, [KEY_ID]);
    }

    #[test]
    fn the_app_write_sends_the_wallets_public_side_only() {
        let body = PutApp::new(
            0,
            "solana",
            Some("solana/pumpfun@1".to_owned()),
            Some(
                PutWallet::new("11111111111111111111111111111111", WalletSource::Keystore)
                    .expect("a 32-byte key"),
            ),
        );
        assert_eq!(
            serde_json::to_value(&body).expect("encodes"),
            json!({
                "expectedRevision": 0,
                "chain": "solana",
                "template": "solana/pumpfun@1",
                "wallet": { "pubkey": "11111111111111111111111111111111", "sourceKind": "keystore" }
            })
        );
        let bare = PutApp::new(3, "solana", None, None);
        assert_eq!(
            serde_json::to_value(&bare).expect("encodes"),
            json!({ "expectedRevision": 3, "chain": "solana", "template": null, "wallet": null })
        );
    }

    #[test]
    fn a_wallet_key_is_sent_only_when_it_is_32_bytes_in_base58() {
        for key in [
            "11111111111111111111111111111111",
            "So11111111111111111111111111111111111111112",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        ] {
            let wallet = PutWallet::new(key, WalletSource::OnePassword).expect(key);
            assert_eq!(
                serde_json::to_value(&wallet).expect("encodes"),
                json!({ "pubkey": key, "sourceKind": "1password" })
            );
        }
        let long = "z".repeat(44);
        let longer = "1".repeat(45);
        let secret_shaped = "2".repeat(88);
        for key in [
            "",
            "1111",
            "1111111111111111111111111111111",
            "111111111111111111111111111111111",
            "0OIl111111111111111111111111111111111111111",
            "So1111111111111111111111111111111111111111+",
            long.as_str(),
            longer.as_str(),
            secret_shaped.as_str(),
        ] {
            match PutWallet::new(key, WalletSource::Keystore) {
                Err(e @ WorkerError::WalletKey { .. }) => assert_eq!(
                    e.to_string(),
                    format!("wallet public key {key:?} is not 32 bytes in base58")
                ),
                other => panic!("{key:?}: expected WalletKey, got {other:?}"),
            }
        }
        // A leading `1` is a zero byte; 255 is "5Q" and 256, two bytes, "5R".
        assert_eq!(base58_len("1"), Some(1));
        assert_eq!(base58_len("2"), Some(1));
        assert_eq!(base58_len("5Q"), Some(1));
        assert_eq!(base58_len("5R"), Some(2));
        assert_eq!(base58_len("15R"), Some(3));
    }

    #[test]
    fn the_environment_write_says_every_fact_and_no_server_or_line() {
        let mut facts = Facts {
            host: Some("203.0.113.10".to_owned()),
            ssh_user: Some("ubuntu".to_owned()),
            host_key: Some("ssh-ed25519 AAAAexample".to_owned()),
            firewall: Firewall::new(vec!["198.51.100.7/32".to_owned()], vec![]),
            desired_cores: Some(2),
            ..Facts::default()
        };
        facts.backup = Some(Backup::new(400_004, "a".repeat(64), "storage.example.net"));
        let body = PutEnv::new(6, facts).with_deploy(
            Deployed::new(
                "20261029T154037Z-6914df5f",
                "2026-10-29T15:40:37Z",
                "deploy-laptop",
            ),
            DeployedApp {
                chain: "solana".to_owned(),
                template: Some("solana/pumpfun@1".to_owned()),
                run_port: Some(3000),
                waf: None,
                services: vec![Service::Redis],
                var_names: vec!["API_PORT".to_owned(), "RUST_LOG".to_owned()],
                secrets: vec![
                    DeployedSecret::new("ERPC_API_KEY", SecretSource::Keychain),
                    DeployedSecret::new("API_TOKEN", SecretSource::Erpc),
                ],
            },
        );
        assert_eq!(
            serde_json::to_value(&body).expect("encodes"),
            json!({
                "expectedRevision": 6,
                "factsFormat": 2,
                "facts": {
                    "host": "203.0.113.10",
                    "sshUser": "ubuntu",
                    "sshPort": null,
                    "hostKey": "ssh-ed25519 AAAAexample",
                    "firewall": { "sshAllow": ["198.51.100.7/32"], "appAllow": [] },
                    "starting": {},
                    "backup": { "accessKey": 400_004, "resticKey": "a".repeat(64), "host": "storage.example.net" },
                    "desiredCores": 2
                },
                "deployed": {
                    "release": "20261029T154037Z-6914df5f",
                    "at": "2026-10-29T15:40:37Z",
                    "from": "deploy-laptop"
                },
                "deployedApp": {
                    "chain": "solana", "template": "solana/pumpfun@1", "runPort": 3000, "waf": null,
                    "services": ["redis"], "varNames": ["API_PORT", "RUST_LOG"],
                    "secrets": [
                        { "name": "ERPC_API_KEY", "kind": "keychain" },
                        { "name": "API_TOKEN", "kind": "erpc" }
                    ]
                }
            })
        );
        let plain = serde_json::to_value(PutEnv::new(0, Facts::default())).expect("encodes");
        assert!(plain.get("deployed").is_none() && plain.get("deployedApp").is_none());
        assert!(plain["facts"].get("resource").is_none() && plain["facts"].get("lines").is_none());
    }

    #[test]
    fn a_start_key_is_never_in_debug_output() {
        let mut facts = Facts::default();
        facts.starting.insert(
            "server".to_owned(),
            Start::new(
                "0123456789abcdef0123456789abcdef",
                "vps",
                "standard-2",
                Some("amsterdam".to_owned()),
                None,
            ),
        );
        let shown = format!("{facts:?}");
        assert!(!shown.contains("0123456789abcdef"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
        // It is still sent: the account needs it to recognise the start.
        let sent = serde_json::to_value(&facts).expect("encodes");
        assert_eq!(
            sent["starting"]["server"]["key"],
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn adopting_sends_kind_number_and_slot() {
        assert_eq!(
            serde_json::to_value(AdoptServer::new(
                ServerKind::Vps,
                200_002,
                AdoptSlot::Active,
                Some(true)
            ))
            .expect("encodes"),
            json!({ "kind": "vps", "id": 200_002, "slot": "active", "appRunning": true })
        );
        assert_eq!(
            serde_json::to_value(AdoptServer::new(
                ServerKind::SuperVps,
                200_002,
                AdoptSlot::Incoming,
                None
            ))
            .expect("encodes"),
            json!({ "kind": "super-vps", "id": 200_002, "slot": "incoming" })
        );
        assert_eq!(
            serde_json::to_value(ServerKind::PremiumVps).expect("encodes"),
            json!("premium-vps")
        );
        assert_eq!(
            serde_json::to_value(ServerKind::BareMetal).expect("encodes"),
            json!("bare-metal")
        );
        assert_eq!(
            serde_json::to_value(AdoptLine::new(LineKind::Grpc, 300_003)).expect("encodes"),
            json!({ "kind": "grpc", "id": 300_003 })
        );
        for kind in ["shreds", "udp", "unlimited"] {
            assert_eq!(LineKind::from(kind).as_str(), kind);
        }
    }

    #[test]
    fn an_adopt_sent_again_is_a_success_not_a_creation() {
        let (_, text) = ok(200, &env_detail_json());
        let again: Written<EnvDetail> = reply(200, &text).expect("reads");
        assert!(!again.created);
        let first: Written<EnvDetail> = reply(201, &text).expect("reads");
        assert!(first.created);
    }

    fn refusal(status: u16, body: &Value) -> Refusal {
        match reply::<Value>(status, &body.to_string()) {
            Err(WorkerError::Refused(r)) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn every_code_is_read_with_its_details() {
        let cases = [
            (400, "invalid_request", Code::InvalidRequest),
            (
                400,
                "unsupported_facts_format",
                Code::UnsupportedFactsFormat,
            ),
            (403, "device_session_required", Code::DeviceSessionRequired),
            (403, "access_token_not_allowed", Code::AccessTokenNotAllowed),
            (404, "worker_not_found", Code::WorkerNotFound),
            (404, "env_not_found", Code::EnvNotFound),
            (404, "secret_not_found", Code::SecretNotFound),
            (404, "seal_key_not_found", Code::SealKeyNotFound),
            (404, "resource_not_found", Code::ResourceNotFound),
            (404, "user_not_found", Code::UserNotFound),
            (409, "already_exists", Code::AlreadyExists),
            (409, "revision_conflict", Code::RevisionConflict),
            (409, "start_pending", Code::StartPending),
            (409, "seal_key_unusable", Code::SealKeyUnusable),
            (409, "seal_key_revoked", Code::SealKeyRevoked),
            (409, "fingerprint_mismatch", Code::FingerprintMismatch),
            (409, "ACCOUNT_CLOSED", Code::AccountClosed),
            (409, "already_attached", Code::AlreadyAttached),
            (409, "slot_occupied", Code::SlotOccupied),
            (409, "app_running_elsewhere", Code::AppRunningElsewhere),
            (422, "limit_exceeded", Code::LimitExceeded),
        ];
        for (status, text, code) in cases {
            let r = refusal(
                status,
                &json!({ "success": false, "code": text, "message": "no" }),
            );
            assert_eq!(r.status, status);
            assert_eq!(r.code.as_ref(), Some(&code), "{text}");
            assert_eq!(code.as_str(), text);
        }
        let conflict = refusal(
            409,
            &json!({ "success": false, "code": "revision_conflict", "message": "moved",
                     "data": { "currentRevision": 8 } }),
        );
        assert_eq!(conflict.current_revision(), Some(8));
        let field = refusal(
            404,
            &json!({ "success": false, "code": "resource_not_found", "message": "no",
                     "data": { "field": "id" } }),
        );
        assert_eq!(field.field().as_deref(), Some("id"));
        let limit = refusal(
            422,
            &json!({ "success": false, "code": "limit_exceeded", "message": "no",
                     "data": { "limit": "line" } }),
        );
        assert_eq!(limit.limit().as_deref(), Some("line"));
        let pending = refusal(
            409,
            &json!({ "success": false, "code": "start_pending", "message": "no",
                     "data": { "envs": ["prod", "staging"] } }),
        );
        assert_eq!(pending.envs(), ["prod", "staging"]);
        let new = refusal(
            409,
            &json!({ "success": false, "code": "switch_not_ready" }),
        );
        assert_eq!(new.code, Some(Code::Other("switch_not_ready".to_owned())));
    }

    #[test]
    fn refusals_without_a_code_are_still_refusals() {
        // A 400 without a code, a 403 with a message and no code, and a
        // 403 with neither code nor message.
        for (status, body) in [
            (
                400,
                json!({ "success": false, "message": "Content-Type must be application/json" }),
            ),
            (
                403,
                json!({ "success": false, "message": "this sign-in cannot use that" }),
            ),
            (403, json!({ "error": "Forbidden" })),
        ] {
            let r = refusal(status, &body);
            assert_eq!((r.status, r.code), (status, None));
        }
        let r = refusal(502, &Value::Null);
        assert_eq!(r.to_string(), "user-api refused the request (502)");
        for body in [
            "{}",
            "",
            r#"{"success":false,"code":"invalid_token","message":"expired"}"#,
        ] {
            assert!(
                matches!(
                    reply::<Value>(401, body),
                    Err(WorkerError::Api(ApiError::Unauthorized))
                ),
                "{body:?}"
            );
        }
    }

    #[test]
    fn a_closed_account_is_a_refusal_not_an_ended_session() {
        let closed = json!({ "success": false, "code": "ACCOUNT_CLOSED", "message": "closed" });
        let r = refusal(401, &closed);
        assert_eq!((r.status, r.code.clone()), (401, Some(Code::AccountClosed)));
        assert_eq!(
            r.to_string(),
            "user-api refused the request (401, ACCOUNT_CLOSED): closed"
        );
        // An environment's reply too, on a read and after a write.
        for after_write in [false, true] {
            assert!(matches!(
                env_reply(401, &closed.to_string(), after_write),
                Err(WorkerError::Refused(Refusal {
                    status: 401,
                    code: Some(Code::AccountClosed),
                    ..
                }))
            ));
        }
        // The same code while the request was handled.
        assert_eq!(refusal(409, &closed).code, Some(Code::AccountClosed));
    }

    #[test]
    fn a_refusal_message_is_one_printable_line() {
        let r = refusal(
            400,
            &json!({ "success": false, "code": "invalid_request",
                     "message": "bad\u{1b}[2J name\u{202e}x\nsecond line" }),
        );
        let message = r.message.clone().expect("message");
        assert!(!message.contains('\u{1b}') && !message.contains('\u{202e}'));
        assert!(!message.contains("second line"));
        assert_eq!(
            r.to_string(),
            format!("user-api refused the request (400, invalid_request): {message}")
        );
    }

    #[test]
    fn a_success_that_is_not_one_is_not_read_as_one() {
        assert!(matches!(
            reply::<Value>(200, "<!DOCTYPE html>"),
            Err(WorkerError::Api(ApiError::Malformed(_)))
        ));
        assert!(matches!(
            reply::<Value>(200, r#"{"success":false,"data":{}}"#),
            Err(WorkerError::Api(ApiError::Malformed(_)))
        ));
        assert!(matches!(
            reply::<EnvDetail>(200, r#"{"success":true,"data":{"name":"prod"}}"#),
            Err(WorkerError::Api(ApiError::Malformed(_)))
        ));
    }

    #[test]
    fn deleting_an_app_or_an_environment_reads_what_was_deleted() {
        for name in ["pump-sniper", "prod"] {
            let (status, text) = ok(200, &json!({ "name": name, "deleted": true }));
            let w: Written<Deleted> = reply(status, &text).expect("reads");
            assert_eq!(
                w.record,
                Deleted {
                    name: name.to_owned(),
                    deleted: true
                }
            );
        }
        let (status, text) = ok(200, &json!({ "deleted": true }));
        assert!(matches!(
            reply::<Deleted>(status, &text),
            Err(WorkerError::Api(ApiError::Malformed(_)))
        ));
    }

    #[test]
    fn an_environment_in_the_older_format_reads_without_its_server_or_lines() {
        // Format 1 kept the server and the lines in the facts; format 2
        // takes them in by adopting. A format-1 record reads, and what it
        // says about them is not read.
        let older = json!({
            "name": "prod",
            "revision": 4,
            "factsFormat": 1,
            "facts": {
                "resource": { "kind": "vps", "id": 200_002, "region": "amsterdam", "hourly": true },
                "host": "203.0.113.10",
                "sshUser": "ubuntu",
                "sshPort": null,
                "hostKey": "ssh-ed25519 AAAAexample",
                "firewall": { "sshAllow": ["198.51.100.7/32"], "appAllow": [] },
                "lines": [{ "kind": "grpc", "id": 300_003, "endpoint": "grpc.example.net:443",
                            "hourly": true, "sources": [] }],
                "starting": {},
                "backup": null
            },
            "refStates": { "resource": "active", "lines": ["active"], "backup": null },
            "deployed": null,
            "deployedApp": null,
            "updatedAt": "2026-10-29T15:40:37.000Z"
        });
        for (status, after_write) in [(200, false), (200, true), (201, true)] {
            let (status, text) = ok(status, &older);
            let env = env_reply(status, &text, after_write)
                .expect("format 1 reads")
                .record;
            assert_eq!(env.facts_format, 1);
            assert_eq!(env.facts.host.as_deref(), Some("203.0.113.10"));
            assert_eq!(env.facts.desired_cores, None);
            assert!(env.servers.is_empty() && env.lines.is_empty());
            assert_eq!(env.ref_states.backup, None);
            let shown = format!("{env:?}");
            assert!(
                !shown.contains("200002") && !shown.contains("300003"),
                "{shown}"
            );
            assert!(!shown.contains("grpc.example.net"), "{shown}");
        }
    }

    #[test]
    fn an_environment_in_a_newer_format_is_refused_on_read_and_on_write() {
        let mut newer = env_detail_json();
        newer["factsFormat"] = json!(3);
        // A field of the newer format this version could not even parse.
        newer["facts"]["host"] = json!({ "v4": "203.0.113.10" });

        // get_env: the record is refused, and erpc is to be updated.
        let (status, text) = ok(200, &newer);
        match env_reply(status, &text, false) {
            Err(
                e @ WorkerError::NewerFormat {
                    found: 3,
                    after_write: false,
                },
            ) => {
                let shown = e.to_string();
                assert_eq!(
                    shown,
                    "the environment's record is in format 3, newer than this erpc reads (2); \
                     update erpc"
                );
            }
            other => panic!("expected NewerFormat after a read, got {other:?}"),
        }

        // put_env (200, 201) and adopt_server / adopt_line (201, and 200 for
        // one sent again): the account took the write before it answered.
        for status in [200, 201] {
            let (status, text) = ok(status, &newer);
            match env_reply(status, &text, true) {
                Err(
                    e @ WorkerError::NewerFormat {
                        found: 3,
                        after_write: true,
                    },
                ) => {
                    assert!(
                        e.to_string().ends_with(
                            "; the write may already have been applied: update erpc before \
                             touching this environment again"
                        ),
                        "{e}"
                    );
                }
                other => panic!("{status}: expected NewerFormat after a write, got {other:?}"),
            }
        }

        // The format this version writes, and an older one, are read.
        for format in [1, 2] {
            let mut detail = env_detail_json();
            detail["factsFormat"] = json!(format);
            let (status, text) = ok(200, &detail);
            assert!(env_reply(status, &text, false).is_ok(), "{format}");
            assert!(env_reply(status, &text, true).is_ok(), "{format}");
        }

        // Only an environment's record is checked: delete_env, and every
        // other call, read their reply with `reply`, which does not look.
        let (status, text) = ok(
            200,
            &json!({ "name": "prod", "deleted": true, "factsFormat": 3 }),
        );
        assert!(reply::<Deleted>(status, &text).is_ok());
        // A refusal is a refusal, whatever its data says.
        let r = refusal(
            409,
            &json!({ "code": "revision_conflict", "data": { "factsFormat": 3 } }),
        );
        assert_eq!(r.code, Some(Code::RevisionConflict));
        assert!(matches!(
            env_reply(
                409,
                &json!({ "code": "revision_conflict", "data": { "factsFormat": 3 } }).to_string(),
                true
            ),
            Err(WorkerError::Refused(_))
        ));
    }

    #[test]
    fn an_unknown_value_from_the_account_is_printed_clean() {
        let r = refusal(
            409,
            &json!({ "success": false, "code": "evil\u{1b}[2J\u{202e}code", "message": "no" }),
        );
        let code = r.code.clone().expect("code");
        assert_eq!(code, Code::Other("evil??2J?code".to_owned()));
        let shown = r.to_string();
        assert!(
            !shown.contains('\u{1b}') && !shown.contains('\u{202e}'),
            "{shown}"
        );
        assert_eq!(
            shown,
            "user-api refused the request (409, evil??2J?code): no"
        );
        let long = Code::from("x".repeat(500).as_str());
        assert_eq!(long.as_str().len(), 64);
        for shown in [
            Slot::from("stand\u{1b}by").to_string(),
            State::from("\u{202e}gone").to_string(),
            LineKind::from("la\nser").to_string(),
            WalletSource::from("key\u{7}chain").to_string(),
            SecretSource::from("e\u{2066}rpc").to_string(),
            Service::from("ka\u{9b}fka").to_string(),
        ] {
            assert!(shown.chars().all(|c| c.is_ascii_graphic()), "{shown:?}");
            assert!(shown.contains('?'), "{shown:?}");
        }
        // Known values are matched before cleaning, and stay what they are.
        assert_eq!(Slot::from("active"), Slot::Active);
        assert_eq!(Code::from("ACCOUNT_CLOSED"), Code::AccountClosed);
        assert_eq!(WalletSource::from("1password"), WalletSource::OnePassword);
    }

    #[test]
    fn the_details_a_refusal_hands_out_are_clean() {
        let r = refusal(
            400,
            &json!({ "success": false, "code": "invalid_request", "message": "no",
                     "data": { "field": "facts.lines[1].id\u{1b}[31m", "limit": "li\u{202e}ne",
                               "envs": ["prod\u{7}", "\u{2067}staging"] } }),
        );
        assert_eq!(r.field().as_deref(), Some("facts.lines[1].id[31m"));
        assert_eq!(r.limit().as_deref(), Some("line"));
        assert_eq!(r.envs(), ["prod", "staging"]);
    }
}
