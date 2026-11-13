// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc.toml`: one app, how it is built and run, and where each of its
//! environments is deployed.
//!
//! The file is meant to be committed, so it never holds a secret value.
//! A secret is a reference to 1Password (`op://<vault-id>/<item-id>/<field>`),
//! to the OS keychain (`keychain:<service>/<account>`) or to erpc's
//! encrypted keystore on the operator's machine
//! (`keystore:<service>/<account>`); `erpc worker` reads the value when it
//! needs it and sends it to the server without writing it down there. The
//! trading key is the same, under `[wallet]`, and is the one secret that
//! never reaches a disk on the server either.
//!
//! The key is named by `[wallet]` and by nothing else. A setting reaches
//! the app in its environment and is read with nobody at a terminal; the
//! key is handed over on a pipe, and only for a person at one. So a
//! `[secrets]` line that names the entry `[wallet]` names, or an entry
//! filed as a key (a keychain or keystore account ending in `.wallet`), is
//! a problem with the file ([`Manifest::key_as_setting`]).
//!
//! What the file gets wrong is reported all at once, with where each
//! problem is, so a hand-edited file is fixed in one pass. Unknown keys are
//! refused: a misspelt `[firewal]` must not quietly mean "no firewall".

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use erpc_secret::OpRef;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::net::{Cidr, is_host};
use crate::server::NewConnections;
use crate::waf::{Ban, MIN_LISTEN_PORT, Rate, WafConfig};

/// The manifest's file name, at the app's root.
pub const FILE_NAME: &str = "erpc.toml";

/// The environment used when `--env` is not given.
pub const DEFAULT_ENV: &str = "default";

/// The largest manifest read. A real one is a few hundred bytes.
const MAX_BYTES: u64 = 256 * 1024;

/// The most addresses one firewall list holds, as the SSH allow list on an
/// ERPC VPS does.
pub const MAX_ALLOW: usize = 16;

/// The chain an app is written for. Each has its own templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    /// Solana mainnet.
    Solana,
}

impl Chain {
    /// Every chain `erpc worker` has templates for.
    pub const ALL: [Self; 1] = [Self::Solana];

    /// The name the file and `--chain` use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Solana => "solana",
        }
    }

    /// The chain called `name`, if `erpc worker` has templates for it.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a secret is read from on the operator's machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// A 1Password field, by vault and item id.
    OnePassword(OpRef),
    /// An OS keychain entry.
    Keychain {
        /// The keychain service name.
        service: String,
        /// The account under that service.
        account: String,
    },
    /// An entry of erpc's encrypted keystore on the operator's machine.
    Keystore {
        /// The service the entry is filed under.
        service: String,
        /// The account under that service.
        account: String,
    },
}

/// Whether `account` is one a trading key is filed under in the keychain
/// or the keystore: `<app>.wallet`. Case is not looked at: a file system or
/// a keychain that ignores it takes `<app>.WALLET` for the same entry.
#[must_use]
pub fn is_key_account(account: &str) -> bool {
    account.to_ascii_lowercase().ends_with(".wallet")
}

/// Whether `s` may be the service or the account of a `keychain:` or
/// `keystore:` reference.
fn is_ref_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl SecretRef {
    /// Parses `op://<vault-id>/<item-id>/<field>`,
    /// `keychain:<service>/<account>` or `keystore:<service>/<account>`.
    ///
    /// # Errors
    ///
    /// A message saying which form was expected and what is wrong.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.starts_with("op://") {
            return OpRef::parse(raw)
                .map(Self::OnePassword)
                .map_err(|e| e.to_string());
        }
        if let Some(rest) = raw.strip_prefix("keychain:") {
            let Some((service, account)) = rest.split_once('/') else {
                return Err("a keychain reference is keychain:<service>/<account>".to_owned());
            };
            if !is_ref_part(service) || !is_ref_part(account) {
                return Err(
                    "a keychain service and account are letters, digits, `.`, `_` and `-`"
                        .to_owned(),
                );
            }
            return Ok(Self::Keychain {
                service: service.to_owned(),
                account: account.to_owned(),
            });
        }
        if let Some(rest) = raw.strip_prefix("keystore:") {
            let Some((service, account)) = rest.split_once('/') else {
                return Err("a keystore reference is keystore:<service>/<account>".to_owned());
            };
            // The two name a file, so neither is `.`, `..` or a hidden one.
            let part = |s: &str| is_ref_part(s) && !s.starts_with('.');
            if !part(service) || !part(account) {
                return Err(
                    "a keystore service and account are letters, digits, `.`, `_` and `-`, \
                     and do not start with `.`"
                        .to_owned(),
                );
            }
            return Ok(Self::Keystore {
                service: service.to_owned(),
                account: account.to_owned(),
            });
        }
        Err(
            "a secret is a reference, op://<vault-id>/<item-id>/<field>, \
             keychain:<service>/<account> or keystore:<service>/<account>, never the value \
             itself"
                .to_owned(),
        )
    }

    /// Whether what this names is kept on one machine only, the one that
    /// kept it: its keychain, or its keystore.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Keychain { .. } | Self::Keystore { .. })
    }

    /// Whether this names an entry filed as a trading key: a keychain or
    /// keystore account that [`is_key_account`]. A 1Password item is
    /// named by its id, which says nothing of what it holds.
    #[must_use]
    pub fn is_key_entry(&self) -> bool {
        match self {
            Self::OnePassword(_) => false,
            Self::Keychain { account, .. } | Self::Keystore { account, .. } => {
                is_key_account(account)
            }
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OnePassword(r) => r.fmt(f),
            Self::Keychain { service, account } => write!(f, "keychain:{service}/{account}"),
            Self::Keystore { service, account } => write!(f, "keystore:{service}/{account}"),
        }
    }
}

impl Serialize for SecretRef {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// The platform a deploy builds for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Target {
    /// 64-bit x86 Linux with glibc: every ERPC VPS and most bare metal.
    #[default]
    #[serde(rename = "x86_64-unknown-linux-gnu")]
    X86_64Gnu,
    /// 64-bit x86 Linux, statically linked.
    #[serde(rename = "x86_64-unknown-linux-musl")]
    X86_64Musl,
    /// 64-bit Arm Linux with glibc.
    #[serde(rename = "aarch64-unknown-linux-gnu")]
    Aarch64Gnu,
    /// 64-bit Arm Linux, statically linked.
    #[serde(rename = "aarch64-unknown-linux-musl")]
    Aarch64Musl,
}

impl Target {
    /// The Rust target triple.
    #[must_use]
    pub const fn triple(self) -> &'static str {
        match self {
            Self::X86_64Gnu => "x86_64-unknown-linux-gnu",
            Self::X86_64Musl => "x86_64-unknown-linux-musl",
            Self::Aarch64Gnu => "aarch64-unknown-linux-gnu",
            Self::Aarch64Musl => "aarch64-unknown-linux-musl",
        }
    }
}

/// `[build]`: how the app is built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// The build command, as words, run in the app's directory.
    #[serde(default = "default_command")]
    pub command: Vec<String>,
    /// The binary's name, as Cargo builds it. Default: the app's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin: Option<String>,
    /// The platform `deploy` builds for. `run` builds for this machine.
    #[serde(default)]
    pub target: Target,
    /// A binary already built for `target`, by any toolchain: its path
    /// inside the app. `build` and `deploy` ship it as it is instead of
    /// running `command`, so an app need not be written in Rust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prebuilt: Option<String>,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            command: default_command(),
            bin: None,
            target: Target::default(),
            prebuilt: None,
        }
    }
}

fn default_command() -> Vec<String> {
    ["cargo", "build", "--release"]
        .map(ToOwned::to_owned)
        .to_vec()
}

/// One entry of `run.requires`: a setting, or a set of settings of which
/// one is enough. The first of a set is the one erpc suggests setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Requirement {
    /// A setting that has to be set.
    One(String),
    /// Settings of which one has to be set; the first is the one to suggest.
    AnyOf(Vec<String>),
}

impl Requirement {
    /// The names, one or more.
    #[must_use]
    pub fn names(&self) -> &[String] {
        match self {
            Self::One(name) => core::slice::from_ref(name),
            Self::AnyOf(names) => names,
        }
    }

    /// The name to suggest: the only one, or the first of the set.
    #[must_use]
    pub fn first(&self) -> &str {
        self.names().first().map_or("", String::as_str)
    }

    /// Whether `is_set` holds for any of the names.
    pub fn met(&self, mut is_set: impl FnMut(&str) -> bool) -> bool {
        self.names().iter().any(|n| is_set(n))
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.names().join(" or "))
    }
}

/// `[run]`: how the app is started, wherever it runs.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    /// Arguments after the binary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Files, relative to the app's root, shipped with every release and
    /// found beside the binary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// Settings the app cannot start without: a name, or a set of names of
    /// which one is enough (`["ERPC_API_KEY", "SOLANA_RPC_ENDPOINT"]`).
    /// `check` says which are not set; `run` and `deploy` refuse until they
    /// are.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Requirement>,
    /// The TCP port the app listens on, which `firewall.app_allow` opens on
    /// its server. Without it the app is reached from nowhere outside. With
    /// `[waf]` it is where the WAF forwards to, on loopback, and it is the
    /// WAF's port that is opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// How a fresh start is judged healthy. Without it: still running
    /// after the default number of seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Health>,
}

/// `[run.health]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    /// A loopback URL that answers 2xx once the app is ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<String>,
    /// How long a start has to become healthy, in seconds.
    #[serde(default = "default_health_timeout")]
    pub timeout_secs: u32,
}

const fn default_health_timeout() -> u32 {
    30
}

/// What `[waf]` says of a protection that can be turned off: `false`, or
/// the protection's own value. A key left out is the default, which is why
/// `true` is not read: it would say nothing the file does not say without
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffOr<T> {
    /// `false`: off.
    Off,
    /// Its own value.
    On(T),
}

impl<T> OffOr<T> {
    /// What is in force: `default` where the file says nothing, nothing
    /// where it says `false`.
    fn in_force(said: Option<Self>, default: Option<T>) -> Option<T> {
        match said {
            None => default,
            Some(Self::Off) => None,
            Some(Self::On(value)) => Some(value),
        }
    }
}

impl<T: Serialize> Serialize for OffOr<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Off => s.serialize_bool(false),
            Self::On(value) => value.serialize(s),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OffOr<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::value::MapAccessDeserializer;
        use serde::de::{Error, IntoDeserializer as _, MapAccess, Visitor};

        struct Read<T>(core::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for Read<T> {
            type Value = OffOr<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("`false` to turn it off, or its own value")
            }

            fn visit_bool<E: Error>(self, on: bool) -> Result<Self::Value, E> {
                if on {
                    return Err(E::custom(
                        "`true` is not a value here: leave the key out for the default, give \
                         its own value, or `false` to turn it off",
                    ));
                }
                Ok(OffOr::Off)
            }

            fn visit_i64<E: Error>(self, n: i64) -> Result<Self::Value, E> {
                T::deserialize(n.into_deserializer()).map(OffOr::On)
            }

            fn visit_u64<E: Error>(self, n: u64) -> Result<Self::Value, E> {
                T::deserialize(n.into_deserializer()).map(OffOr::On)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(OffOr::On)
            }
        }

        d.deserialize_any(Read(core::marker::PhantomData))
    }
}

/// `[waf]`: the app is reached from outside through a web application
/// firewall, an HTTP proxy `deploy` runs in front of it on the server
/// ([`crate::waf`]). The proxy listens on `port`, which is then the port
/// `firewall.app_allow` opens, and forwards what its rules let through to
/// the app on loopback at `run.port`, which is never opened.
///
/// Only `port` is required. Every other key left out is its default
/// ([`WafConfig::default_for`] for the proxy's, [`NewConnections::DEFAULT`]
/// for the firewall's); `rate`, `max_connections_per_address`, `ban` and
/// `new_connections` are turned off with `false`. What each key means, and
/// its bounds, is on the field of the same name in [`WafConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waf {
    /// The public TCP port the WAF listens on: [`MIN_LISTEN_PORT`] or
    /// above, and not `run.port`.
    pub port: u16,
    /// The methods forwarded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    /// The paths forwarded; none listed is every path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_paths: Option<Vec<String>>,
    /// The paths refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_paths: Option<Vec<String>>,
    /// The largest request body forwarded, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    /// The largest request head, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_header_bytes: Option<u32>,
    /// The request rate allowed from one client address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<OffOr<Rate>>,
    /// How many connections one client address may hold at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections_per_address: Option<OffOr<u32>>,
    /// When an address that keeps being blocked is refused altogether.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ban: Option<OffOr<Ban>>,
    /// Whether requests that look like a scanner's are refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_probes: Option<bool>,
    /// How many seconds a client has to send a request's head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_timeout_secs: Option<u32>,
    /// How many seconds a request's body may take in all, the time the
    /// proxy waits on the app for not counted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_timeout_secs: Option<u32>,
    /// How many seconds the app has to start answering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_timeout_secs: Option<u32>,
    /// The firewall's own limit on new connections to `port` from one
    /// client address, which holds before the proxy sees a connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_connections: Option<OffOr<NewConnections>>,
}

impl Waf {
    /// The proxy's config for worker `id`, whose app listens on
    /// `run_port`: listening on every IPv4 address at `port`, forwarding
    /// to loopback, each key the file has over its default.
    #[must_use]
    pub fn config(&self, id: &str, run_port: u16) -> WafConfig {
        use core::net::{Ipv4Addr, SocketAddr};
        let default = WafConfig::default_for(
            id,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.port)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, run_port)),
        );
        WafConfig {
            methods: self.methods.clone().unwrap_or(default.methods),
            allow_paths: self.allow_paths.clone().unwrap_or(default.allow_paths),
            deny_paths: self.deny_paths.clone().unwrap_or(default.deny_paths),
            max_body_bytes: self.max_body_bytes.unwrap_or(default.max_body_bytes),
            max_header_bytes: self.max_header_bytes.unwrap_or(default.max_header_bytes),
            rate: OffOr::in_force(self.rate, default.rate),
            max_connections_per_address: OffOr::in_force(
                self.max_connections_per_address,
                default.max_connections_per_address,
            ),
            ban: OffOr::in_force(self.ban, default.ban),
            block_probes: self.block_probes.unwrap_or(default.block_probes),
            header_timeout_secs: self
                .header_timeout_secs
                .unwrap_or(default.header_timeout_secs),
            body_timeout_secs: self.body_timeout_secs.unwrap_or(default.body_timeout_secs),
            upstream_timeout_secs: self
                .upstream_timeout_secs
                .unwrap_or(default.upstream_timeout_secs),
            ..default
        }
    }

    /// The firewall's limit on new connections to the WAF's port, when it
    /// has one.
    #[must_use]
    pub fn new_connections(&self) -> Option<NewConnections> {
        OffOr::in_force(self.new_connections, Some(NewConnections::DEFAULT))
    }
}

/// `[wallet]`: the trading key. Read from `source` when the app starts and
/// handed to it on a pipe. It is never written to a file on the server,
/// and to none unencrypted: a `keystore:` source is a sealed file on the
/// operator's machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wallet {
    /// Where the key is kept on the operator's machine.
    pub source: SecretRef,
    /// Its public key, to show and to check the key read against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
}

/// `[deploy]`: what every environment's deploys share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deploy {
    /// How many releases a server keeps to roll back to, the live one
    /// included.
    #[serde(default = "default_keep")]
    pub keep_releases: u8,
}

impl Default for Deploy {
    fn default() -> Self {
        Self {
            keep_releases: default_keep(),
        }
    }
}

const fn default_keep() -> u8 {
    5
}

/// What kind of ERPC server an environment runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    /// A VPS.
    Vps,
    /// A Super VPS.
    SuperVps,
    /// A Premium VPS.
    PremiumVps,
    /// A bare-metal server.
    BareMetal,
}

impl ResourceKind {
    /// What the operator reads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vps => "VPS",
            Self::SuperVps => "Super VPS",
            Self::PremiumVps => "Premium VPS",
            Self::BareMetal => "bare metal server",
        }
    }
}

/// `[env.<name>.resource]`: the ERPC server behind an environment, when it
/// is one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    /// What kind of server.
    pub kind: ResourceKind,
    /// Its id in the ERPC account.
    pub id: String,
    /// Its region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Whether it is billed by the hour, and so ends when it is released.
    #[serde(default)]
    pub hourly: bool,
}

/// What kind of ERPC data line an environment's server reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LineKind {
    /// A Geyser gRPC line.
    Grpc,
    /// A Shreds Shared (Shredstream gRPC) line.
    Shreds,
    /// An Unlimited RPC: a dedicated RPC endpoint in the server's region.
    /// It serves `sendTransaction` and a short list of reads, not
    /// `getProgramAccounts` and the like, so the app sends through it and
    /// reads elsewhere.
    Unlimited,
}

impl Line {
    /// Whether user-api has named no endpoint for it yet: a line on record
    /// from the moment it was bought, which the next deploy takes up.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.endpoint.is_empty()
    }
}

impl LineKind {
    /// Every kind, in order.
    pub const ALL: [Self; 3] = [Self::Grpc, Self::Shreds, Self::Unlimited];

    /// The setting the line's endpoint is given to the app as.
    #[must_use]
    pub const fn setting(self) -> &'static str {
        match self {
            Self::Grpc => "GRPC_ENDPOINT",
            Self::Shreds => "SHREDS_ENDPOINT",
            Self::Unlimited => "SOLANA_SEND_RPC_ENDPOINT",
        }
    }

    /// What the operator reads.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Grpc => "gRPC",
            Self::Shreds => "Shreds",
            Self::Unlimited => "Unlimited RPC",
        }
    }

    /// The flag that starts a line of this kind on `deploy` (and on `run`,
    /// for gRPC and Shreds), without its dashes.
    #[must_use]
    pub const fn flag(self) -> &'static str {
        match self {
            Self::Grpc => "grpc",
            Self::Shreds => "shreds",
            Self::Unlimited => "unlimited",
        }
    }

    /// Whether `endpoint` is one a line of this kind has: `https://<host>`
    /// for gRPC and Shreds, `http://<address>:<port>` for Unlimited, which
    /// is served without TLS.
    #[must_use]
    pub fn endpoint_ok(self, endpoint: &str) -> bool {
        match self {
            Self::Grpc | Self::Shreds => endpoint
                .strip_prefix("https://")
                .is_some_and(|host| is_host(host.trim_end_matches('/'))),
            Self::Unlimited => endpoint
                .strip_prefix("http://")
                .and_then(|rest| rest.trim_end_matches('/').rsplit_once(':'))
                .is_some_and(|(host, port)| {
                    is_host(host) && port.parse::<u16>().is_ok_and(|p| p != 0)
                }),
        }
    }
}

/// A data line ERPC sells by the hour, opened for the environment's server
/// by its address. Its endpoint is no secret: the line lets in the
/// server's address and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Line {
    /// Which kind.
    pub kind: LineKind,
    /// Its id in the ERPC account.
    pub id: String,
    /// Where the app connects.
    pub endpoint: String,
    /// Whether it is billed by the hour, and so ends when it is released.
    #[serde(default)]
    pub hourly: bool,
}

/// What a start with no outcome on record yet was starting: the
/// environment's server, or one of its data lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartOf {
    /// The server: a new hourly VPS.
    Server,
    /// A Geyser gRPC line.
    Grpc,
    /// A Shreds line.
    Shreds,
    /// An Unlimited RPC.
    Unlimited,
}

impl StartOf {
    /// The start of a line of `kind`.
    #[must_use]
    pub const fn line(kind: LineKind) -> Self {
        match kind {
            LineKind::Grpc => Self::Grpc,
            LineKind::Shreds => Self::Shreds,
            LineKind::Unlimited => Self::Unlimited,
        }
    }

    /// The key it has under `[env.<name>.starting]`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Grpc => "grpc",
            Self::Shreds => "shreds",
            Self::Unlimited => "unlimited",
        }
    }
}

/// One entry of `[env.<name>.starting]`: the start of an hourly product
/// whose request was sent, or was about to be, and whose outcome is not on
/// record yet.
///
/// The entry is written before the request leaves, so that a start that
/// got no answer is sent again with this key, and never with a new one,
/// which could buy a second. What the request was for is kept beside the
/// key, so that a command that asks for another plan, region or address
/// does not send this key for another purchase. The entry leaves the record
/// with the purchase it made, or once nothing was made under it.
/// The key is no secret: it names a request, and buys nothing without the
/// account's session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    /// The request's `idempotency-key`.
    pub key: String,
    /// The hourly family that starts it, as user-api's catalogue names it.
    pub family: String,
    /// The plan, by product id.
    pub product: String,
    /// The region it is started in: a server's, or an Unlimited RPC's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The address it lets in: a gRPC or Shreds line's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

impl Start {
    /// Whether `other` is the same purchase: the same family, plan, region
    /// and address. The keys are not compared.
    #[must_use]
    pub fn same_purchase(&self, other: &Self) -> bool {
        self.family == other.family
            && self.product == other.product
            && self.region == other.region
            && self.ip == other.ip
    }
}

/// `[env.<name>.firewall]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    /// Who may reach SSH.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_allow: Vec<Cidr>,
    /// Who may reach the app's own port, or its WAF's when it has one.
    /// Empty: nobody from outside. `0.0.0.0/0` and `::/0`, everyone, only
    /// to a WAF's port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_allow: Vec<Cidr>,
}

/// `[env.<name>.inventory]`: the environment's server facts are kept in a
/// 1Password item instead of in this file.
///
/// Then the item is the one place they are written. Any machine signed in
/// to 1Password reads the same server, host key and firewall from it, and
/// reaches the server with the SSH key in 1Password's agent, so a fresh
/// machine needs only `erpc login` and the app's repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// The vault the item is in, by its 26-character id: a name can be
    /// reassigned, an id cannot.
    pub vault: String,
}

/// `[env.<name>]`: one place the app is deployed.
///
/// Its server facts -- `resource`, `host`, `ssh_user`, `ssh_port`,
/// `host_key`, `firewall`, `lines`, `starting`, `backup` -- are written
/// here, or kept in 1Password when `inventory` is set, never both: two
/// copies drift, and nobody can tell which is right.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Env {
    /// Where the server facts are kept, when not in this file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<Inventory>,
    /// The ERPC server, when it is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    /// The server's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The account erpc signs in to over SSH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_user: Option<String>,
    /// The SSH port, when it is not 22.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
    /// The server's pinned SSH host key, as one OpenSSH public key line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    /// Who may reach the server.
    #[serde(default, skip_serializing_if = "Firewall::is_empty")]
    pub firewall: Firewall,
    /// The ERPC data lines opened for the server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<Line>,
    /// The starts whose outcome is not on record yet, by what was being
    /// started. An entry goes when user-api answers: with the product put
    /// on record, or with nothing started.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub starting: BTreeMap<StartOf, Start>,
    /// The keys `erpc worker backup on` gave the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<Backup>,
}

/// `[env.<name>.backup]`: the keys `erpc worker backup on` gave the
/// server, so `off` and `delete` revoke these by id, listed or not, besides
/// any labelled for the worker on its server. Ids, not secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    /// The access key's number, as `erpc storage keys list` shows it.
    pub access_key: u64,
    /// The restic key's id.
    pub restic_key: String,
    /// The name the snapshots carry.
    pub host: String,
}

impl Firewall {
    /// Whether neither list has an entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ssh_allow.is_empty() && self.app_allow.is_empty()
    }
}

impl Env {
    /// The settings this environment's data lines set on the server, each
    /// to its line's endpoint, over `[vars]`.
    pub fn line_vars(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.lines
            .iter()
            .filter(|line| !line.is_pending())
            .map(|line| (line.kind.setting(), line.endpoint.as_str()))
    }

    /// The SSH port.
    #[must_use]
    pub fn ssh_port(&self) -> u16 {
        self.ssh_port.unwrap_or(22)
    }

    /// The server facts written in this file, by key, for the message that
    /// says they belong in 1Password.
    fn written_facts(&self) -> Vec<&'static str> {
        [
            ("resource", self.resource.is_some()),
            ("host", self.host.is_some()),
            ("ssh_user", self.ssh_user.is_some()),
            ("ssh_port", self.ssh_port.is_some()),
            ("host_key", self.host_key.is_some()),
            ("firewall", !self.firewall.is_empty()),
            ("lines", !self.lines.is_empty()),
            ("starting", !self.starting.is_empty()),
            ("backup", self.backup.is_some()),
        ]
        .into_iter()
        .filter_map(|(key, set)| set.then_some(key))
        .collect()
    }
}

/// `[services]`: what the app needs running beside it on its server. A
/// deploy installs and starts each one, and gives the app its address
/// unless `[vars]` sets it: Redis for what is kept a while (a cache, a
/// ban list, recent trades), PostgreSQL for what must last.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Services {
    /// Redis on 127.0.0.1:6379, as `REDIS_URL`.
    #[serde(default)]
    pub redis: bool,
    /// PostgreSQL over its local socket, with a role and database for the
    /// worker and no password, as `DATABASE_URL`.
    #[serde(default)]
    pub postgres: bool,
}

/// The `REDIS_URL` a deploy gives an app with `services.redis`.
pub const REDIS_URL: &str = "redis://127.0.0.1:6379/";
/// The `DATABASE_URL` a deploy gives an app with `services.postgres`: the
/// local socket, and the role and database named after the user the app
/// runs as.
pub const DATABASE_URL: &str = "postgresql:///?host=/var/run/postgresql";

impl Services {
    /// Whether nothing is asked for.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.redis && !self.postgres
    }

    /// Each service asked for, by the name it has here, with the setting
    /// it gives the app.
    #[must_use]
    pub fn provided(&self) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        if self.redis {
            out.push(("redis", "REDIS_URL"));
        }
        if self.postgres {
            out.push(("postgres", "DATABASE_URL"));
        }
        out
    }

    /// The settings these give the app.
    #[must_use]
    pub fn vars(&self) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        if self.redis {
            out.push(("REDIS_URL", REDIS_URL));
        }
        if self.postgres {
            out.push(("DATABASE_URL", DATABASE_URL));
        }
        out
    }
}

/// The whole of `erpc.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// The app's name. It names its service on every server.
    pub name: String,
    /// The chain it is written for.
    pub chain: Chain,
    /// The template it was made from: `<chain>/<template>@<version>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// How it is built.
    #[serde(default)]
    pub build: Build,
    /// How it is run.
    #[serde(default)]
    pub run: Run,
    /// The web application firewall in front of it, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waf: Option<Waf>,
    /// Plain settings, given to the app as environment variables. They
    /// reach the server as they are written here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
    /// Secret settings, given to the app as environment variables, by
    /// reference.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretRef>,
    /// The trading key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<Wallet>,
    /// What deploys share.
    #[serde(default)]
    pub deploy: Deploy,
    /// Local services the app needs on its server, which deploy installs.
    #[serde(default, skip_serializing_if = "Services::is_empty")]
    pub services: Services,
    /// Where it is deployed, by environment name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, Env>,
}

/// Why a manifest could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The file could not be read.
    Read(String),
    /// The file is not TOML of the expected shape.
    Syntax(String),
    /// It parsed, and these are what is wrong with what it says.
    Invalid(Vec<String>),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(message) => f.write_str(message),
            Self::Syntax(message) => write!(f, "{FILE_NAME} is not valid: {message}"),
            Self::Invalid(problems) => {
                write!(f, "{FILE_NAME} has {} problem(s):", problems.len())?;
                for problem in problems {
                    write!(f, "\n  - {problem}")?;
                }
                Ok(())
            }
        }
    }
}

impl core::error::Error for ManifestError {}

impl Manifest {
    /// Parses and checks the text of an `erpc.toml`.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Syntax`] for TOML that does not have the expected
    /// shape, [`ManifestError::Invalid`] with every problem otherwise.
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        let manifest: Self =
            toml::from_str(text).map_err(|e| ManifestError::Syntax(e.message().to_owned()))?;
        let problems = manifest.problems();
        if problems.is_empty() {
            Ok(manifest)
        } else {
            Err(ManifestError::Invalid(problems))
        }
    }

    /// Reads, parses and checks the `erpc.toml` at `path`.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`], and [`ManifestError::Read`] when the file cannot
    /// be read or is far larger than a manifest is.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let read = |e: std::io::Error| {
            ManifestError::Read(format!("could not read {}: {e}", path.display()))
        };
        let size = std::fs::metadata(path).map_err(read)?.len();
        if size > MAX_BYTES {
            return Err(ManifestError::Read(format!(
                "{} is {size} bytes; a manifest is at most {MAX_BYTES}",
                path.display()
            )));
        }
        Self::parse(&std::fs::read_to_string(path).map_err(read)?)
    }

    /// The binary's name.
    #[must_use]
    pub fn bin(&self) -> &str {
        self.build.bin.as_deref().unwrap_or(&self.name)
    }

    /// The environment called `name`.
    ///
    /// # Errors
    ///
    /// A message naming the environments there are.
    pub fn env(&self, name: &str) -> Result<&Env, String> {
        self.env.get(name).ok_or_else(|| {
            if self.env.is_empty() {
                format!("{FILE_NAME} has no environments yet")
            } else {
                let known: Vec<&str> = self.env.keys().map(String::as_str).collect();
                format!(
                    "{FILE_NAME} has no [env.{name}]; it has {}",
                    known.join(", ")
                )
            }
        })
    }

    /// What names this app's service in environment `env` on a server:
    /// `<name>-<env>`. Two workers on one server differ in it.
    #[must_use]
    pub fn unit_id(&self, env: &str) -> String {
        format!("{}-{env}", self.name)
    }

    /// The config of this app's WAF in environment `env`, as `deploy`
    /// hands it to the server; none without `[waf]`.
    #[must_use]
    pub fn waf_config(&self, env: &str) -> Option<WafConfig> {
        let waf = self.waf.as_ref()?;
        // A checked manifest with `[waf]` has `run.port`.
        Some(waf.config(&self.unit_id(env), self.run.port?))
    }

    /// Why `reference` may not be read as a setting, when it may not: it
    /// is the trading key's. None for any other reference.
    ///
    /// For a `[secrets]` line, and for anything else read the way one is
    /// (a URL `erpc worker bench` is given by reference).
    #[must_use]
    pub fn key_as_setting(&self, reference: &SecretRef) -> Option<String> {
        const WHY: &str = "erpc hands the trading key to the app through [wallet] alone, on a \
                           pipe and only for a person at a terminal, and never reads it as a \
                           setting";
        if self.wallet.as_ref().is_some_and(|w| w.source == *reference) {
            return Some(format!(
                "{reference} is wallet.source, the trading key: {WHY}"
            ));
        }
        reference.is_key_entry().then(|| {
            format!(
                "{reference} is an entry filed as a trading key (its account ends in \
                 `.wallet`): {WHY}; a key is named under [wallet], and a setting is kept \
                 under another name"
            )
        })
    }

    /// The requirements in `run.requires` that neither `[vars]` nor
    /// `[secrets]` meets.
    #[must_use]
    pub fn missing(&self) -> Vec<&Requirement> {
        self.missing_besides(&[])
    }

    /// The requirements in `run.requires` that neither `[vars]`,
    /// `[secrets]` nor `provided` meets: `provided` are the settings a data
    /// line sets on the server ([`Env::line_vars`]). A set is met when any
    /// of its names is set.
    #[must_use]
    pub fn missing_besides(&self, provided: &[&str]) -> Vec<&Requirement> {
        let services = self.services.vars();
        self.run
            .requires
            .iter()
            .filter(|req| {
                !req.met(|n| {
                    self.vars.contains_key(n)
                        || self.secrets.contains_key(n)
                        || provided.contains(&n)
                        || services.iter().any(|(name, _)| *name == n)
                })
            })
            .collect()
    }

    /// The plain settings whose values carry a credential, with what kind
    /// each is: `[vars]` reach the server, and the repository, as written.
    /// Only the kinds that are seldom anything else ([`Credential::sure`]).
    /// `check` warns of each in the language of the run. A setting whose
    /// name already says it is a secret is in [`Self::warnings`] instead.
    #[must_use]
    pub fn credentials_in_vars(&self) -> Vec<(&str, Credential)> {
        self.vars
            .iter()
            .filter(|(name, _)| !looks_secret(name))
            .filter_map(|(name, value)| {
                // Only what is seldom anything else: see `Credential::sure`.
                let kind = credential_in(value).filter(|kind| kind.sure())?;
                Some((name.as_str(), kind))
            })
            .collect()
    }

    /// Things that are allowed but probably not meant. A credential in a
    /// `[vars]` value is one more, told by [`Self::credentials_in_vars`].
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for name in self.vars.keys() {
            if looks_secret(name) {
                out.push(format!(
                    "vars.{name} looks like a secret; [vars] reach the server as written, \
                     so move it to [secrets] as a reference"
                ));
            }
        }
        // A setting every environment's data line sets is not missing.
        let everywhere: Vec<&str> = LineKind::ALL
            .into_iter()
            .filter(|kind| {
                !self.env.is_empty()
                    && self
                        .env
                        .values()
                        .all(|e| e.lines.iter().any(|l| l.kind == *kind))
            })
            .map(LineKind::setting)
            .collect();
        for req in self.missing_besides(&everywhere) {
            // A line's setting comes from the line: say so, rather than
            // send the reader to [vars] for an endpoint erpc provides.
            let line = LineKind::ALL
                .into_iter()
                .find(|k| k.setting() == req.first());
            out.push(match line {
                Some(kind) if kind == LineKind::Unlimited => format!(
                    "{req} is required (run.requires) and not set; `--{}` on deploy starts a \
                     line that provides it, or add it to [vars]",
                    kind.flag()
                ),
                Some(kind) => format!(
                    "{req} is required (run.requires) and not set; `--{flag}` on deploy, or on \
                     run with `--ip <IPV4>`, starts a line that provides it; or add it to [vars]",
                    flag = kind.flag()
                ),
                None => format!(
                    "{req} is required (run.requires) and not set; add it to [vars], or to \
                     [secrets] as a reference"
                ),
            });
        }
        if self.wallet.as_ref().is_some_and(|w| w.pubkey.is_none()) {
            out.push(
                "wallet.pubkey is not set, so the key read cannot be checked against it".to_owned(),
            );
        }
        for (name, env) in &self.env {
            if env.host.is_some() && env.firewall.ssh_allow.is_empty() {
                out.push(format!(
                    "env.{name}.firewall.ssh_allow is empty; deploy will allow SSH only from \
                     the address it runs from"
                ));
            }
        }
        // Opening the port does nothing for an app that listens on loopback,
        // which is where the templates listen unless told otherwise. Behind
        // a WAF loopback is where it should listen.
        if self.waf.is_none()
            && self.env.values().any(|e| !e.firewall.app_allow.is_empty())
            && !self.vars.keys().any(|k| k.ends_with("BIND"))
        {
            out.push(
                "firewall.app_allow opens run.port, and the app still listens on loopback only \
                 unless a setting says otherwise (the pumpfun template: API_BIND = \"0.0.0.0\")"
                    .to_owned(),
            );
        }
        // An app whose servers are reached from any machine through
        // 1Password still cannot start from another machine if its keys are
        // in this one's keychain or keystore.
        if self.env.values().any(|e| e.inventory.is_some()) {
            let local = self
                .secrets
                .iter()
                .map(|(name, r)| (format!("secrets.{name}"), r))
                .chain(
                    self.wallet
                        .iter()
                        .map(|w| ("wallet.source".to_owned(), &w.source)),
                )
                .filter(|(_, r)| r.is_local());
            for (at, reference) in local {
                out.push(format!(
                    "{at} is {reference}, which only this machine has; the servers are in \
                     1Password, so keep it in 1Password too or another machine cannot start \
                     the app"
                ));
            }
        }
        out
    }

    /// Every problem with what the manifest says.
    fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !is_slug(&self.name, 32) {
            out.push(format!(
                "name `{}` must be 1 to 32 lowercase letters, digits and single hyphens, \
                 starting with a letter",
                self.name
            ));
        }
        if let Some(template) = &self.template
            && let Err(problem) = check_template(template, self.chain)
        {
            out.push(format!("template: {problem}"));
        }
        self.build_problems(&mut out);
        self.run_problems(&mut out);
        self.waf_problems(&mut out);
        for (name, value) in &self.vars {
            if let Err(problem) = check_env_name(name) {
                out.push(format!("vars.{name}: {problem}"));
            }
            if let Err(problem) = check_var_value(value) {
                out.push(format!("vars.{name}: {problem}"));
            }
        }
        for (name, reference) in &self.secrets {
            if let Err(problem) = check_env_name(name) {
                out.push(format!("secrets.{name}: {problem}"));
            }
            if self.vars.contains_key(name) {
                out.push(format!("{name} is in both [vars] and [secrets]"));
            }
            if let Some(problem) = self.key_as_setting(reference) {
                out.push(format!("secrets.{name}: {problem}; remove the line"));
            }
        }
        if let Some(pubkey) = self.wallet.as_ref().and_then(|w| w.pubkey.as_deref())
            && !is_pubkey(self.chain, pubkey)
        {
            out.push(format!(
                "wallet.pubkey `{pubkey}` is not a {} public key",
                self.chain
            ));
        }
        if !(1..=20).contains(&self.deploy.keep_releases) {
            out.push("deploy.keep_releases must be 1 to 20".to_owned());
        }
        for (name, env) in &self.env {
            if !is_slug(name, 16) {
                out.push(format!(
                    "env.{name}: an environment name is 1 to 16 lowercase letters, digits and \
                     single hyphens, starting with a letter"
                ));
            }
            env_problems(name, env, &mut out);
            allow_problems(name, &env.firewall, self.waf.is_some(), &mut out);
            line_problems(&format!("env.{name}.lines"), &env.lines, &mut out);
            start_problems(&format!("env.{name}.starting"), &env.starting, &mut out);
            for (setting, _) in env.line_vars() {
                if self.secrets.contains_key(setting) {
                    out.push(format!(
                        "env.{name}.lines sets {setting}, which is also in [secrets]"
                    ));
                }
            }
            if !env.firewall.app_allow.is_empty() && self.run.port.is_none() {
                out.push(format!(
                    "env.{name}.firewall.app_allow needs run.port: the port it opens"
                ));
            }
        }
        if let Some(port) = self.run.port
            && (port == 0 || self.env.values().any(|e| e.ssh_port() == port))
        {
            out.push(format!(
                "run.port {port} is not a port the app can be given: not 0, nor SSH's"
            ));
        }
        out
    }

    /// What is wrong with `[waf]`, each problem naming its key. The
    /// ports are this file's to check; the rest is the proxy's config the
    /// table makes, checked by the proxy's own rules ([`WafConfig`]), and
    /// the firewall's limit by its own ([`NewConnections`]).
    fn waf_problems(&self, out: &mut Vec<String>) {
        let Some(waf) = &self.waf else {
            return;
        };
        let port = waf.port;
        match self.run.port {
            None => out.push(
                "waf needs run.port: the port the app listens on, on loopback, where the WAF \
                 forwards to"
                    .to_owned(),
            ),
            Some(app) if app == port => out.push(format!(
                "waf.port {port} is run.port too: the WAF listens on waf.port, and the app \
                 behind it on a port of its own"
            )),
            Some(_) => {}
        }
        if port < MIN_LISTEN_PORT {
            out.push(format!(
                "waf.port {port} is below {MIN_LISTEN_PORT}: the WAF runs without the \
                 privilege a lower port takes"
            ));
        }
        if self.env.values().any(|e| e.ssh_port() == port) {
            out.push(format!("waf.port {port} is SSH's port"));
        }
        let probed = self.run.health.as_ref().and_then(|h| h.http.as_deref());
        if probed
            .and_then(crate::server::health_address)
            .is_some_and(|address| address.port() == port)
        {
            out.push(format!(
                "waf.port {port} is the port run.health.http asks: the health check is the \
                 app's own, on run.port"
            ));
        }
        let config = waf.config(&self.name, self.run.port.unwrap_or(0));
        out.extend(config.rule_problems().iter().map(|p| format!("waf.{p}")));
        if let Some(limit) = waf.new_connections() {
            let problems = limit.problems();
            out.extend(problems.iter().map(|p| format!("waf.new_connections.{p}")));
        }
    }

    fn build_problems(&self, out: &mut Vec<String>) {
        if self.build.command.is_empty()
            || self.build.command.iter().any(std::string::String::is_empty)
        {
            out.push("build.command must be a list of non-empty words".to_owned());
        }
        if self.build.command.iter().any(|w| w.contains('\0')) {
            out.push("build.command has a NUL byte".to_owned());
        }
        if let Some(prebuilt) = &self.build.prebuilt {
            // A path a deploy can read from the app's directory, by the
            // rule `run.files` goes by.
            let plain = crate::release::is_inside(prebuilt)
                && prebuilt
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b));
            if !is_relative_inside(prebuilt) || !plain {
                out.push(format!(
                    "build.prebuilt: `{prebuilt}` must be a path inside the app in plain parts \
                     (letters, digits, `.`, `_`, `-`), without `..`"
                ));
            }
            if self.build.command != default_command() {
                out.push(
                    "build.prebuilt and build.command: one or the other; a prebuilt binary is \
                     shipped as it is"
                        .to_owned(),
                );
            }
        }
        if let Some(bin) = &self.build.bin {
            let ok = !bin.is_empty()
                && bin.len() <= 64
                && bin
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
            if !ok {
                out.push(format!(
                    "build.bin `{bin}` must be 1 to 64 letters, digits, `-` and `_`"
                ));
            }
        }
    }

    fn run_problems(&self, out: &mut Vec<String>) {
        if self.run.args.len() > 64 || self.run.args.iter().any(|a| a.contains('\0')) {
            out.push("run.args: at most 64 arguments, none with a NUL byte".to_owned());
        }
        for req in &self.run.requires {
            if matches!(req, Requirement::AnyOf(names) if names.len() < 2) {
                out.push("run.requires: a set of settings needs two or more names".to_owned());
            }
            for name in req.names() {
                if let Err(problem) = check_env_name(name) {
                    out.push(format!("run.requires: {name}: {problem}"));
                }
            }
        }
        if self.run.files.len() > 64 {
            out.push("run.files: at most 64 files".to_owned());
        }
        let mut seen = BTreeSet::new();
        for file in &self.run.files {
            // What a deploy can upload (`RemotePath`) and the agent install
            // (`release::is_inside`): plain parts, no `..`, `.` or empty ones.
            let plain = crate::release::is_inside(file)
                && file
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b));
            if !is_relative_inside(file) || !plain {
                out.push(format!(
                    "run.files: `{file}` must be a path inside the app in plain parts (letters, \
                     digits, `.`, `_`, `-`), without `..`"
                ));
            } else if !seen.insert(file) {
                out.push(format!("run.files: `{file}` is listed twice"));
            }
        }
        if let Some(health) = &self.run.health {
            if let Some(url) = &health.http
                && !is_loopback_url(url)
            {
                out.push(format!(
                    "run.health.http `{url}` must be http://127.0.0.1:<port>/…, \
                         http://localhost:<port>/… or http://[::1]:<port>/…: it is checked on \
                         the server itself"
                ));
            }
            if !(1..=600).contains(&health.timeout_secs) {
                out.push("run.health.timeout_secs must be 1 to 600".to_owned());
            }
        }
    }
}

fn env_problems(name: &str, env: &Env, out: &mut Vec<String>) {
    let at = |field: &str| format!("env.{name}.{field}");
    if let Some(inventory) = &env.inventory {
        if !is_vault_id(&inventory.vault) {
            out.push(format!(
                "{}: `{}` must be a 26-character 1Password vault id, not a name: a name can be \
                 reassigned",
                at("inventory.vault"),
                inventory.vault
            ));
        }
        let written = env.written_facts();
        if !written.is_empty() {
            out.push(format!(
                "env.{name}: its server facts are kept in 1Password (inventory), so {} must not \
                 also be written here; remove {}",
                written.join(", "),
                if written.len() == 1 { "it" } else { "them" }
            ));
        }
    }
    if let Some(host) = &env.host
        && !is_host(host)
    {
        out.push(format!(
            "{}: `{host}` is not an IP address or a DNS name",
            at("host")
        ));
    }
    if let Some(user) = &env.ssh_user {
        let ok = !user.is_empty()
            && user.len() <= 32
            && user
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
            && user
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'));
        if !ok {
            out.push(format!(
                "{}: `{user}` is not a Linux user name",
                at("ssh_user")
            ));
        }
    }
    if env.ssh_port == Some(0) {
        out.push(format!("{}: 0 is not a port", at("ssh_port")));
    }
    if let Some(key) = &env.host_key {
        if env.host.is_none() {
            out.push(format!("{}: a host key needs a host", at("host_key")));
        }
        let shaped = key.lines().count() == 1
            && ["ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "sk-"]
                .iter()
                .any(|p| key.starts_with(p));
        if !shaped {
            out.push(format!(
                "{}: must be one OpenSSH public key line, such as `ssh-ed25519 AAAA…`",
                at("host_key")
            ));
        }
    }
    if let Some(resource) = &env.resource {
        let ok = !resource.id.is_empty()
            && resource.id.len() <= 64
            && resource
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
        if !ok {
            out.push(format!(
                "{}: `{}` is not a resource id",
                at("resource.id"),
                resource.id
            ));
        }
        if let Some(region) = &resource.region
            && !is_slug(region, 32)
        {
            out.push(format!(
                "{}: `{region}` is not a region name",
                at("resource.region")
            ));
        }
    }
}

/// What is wrong with an environment's two allow lists. Everyone
/// (`0.0.0.0/0`, `::/0`) may reach a WAF's port, `behind_waf`, and nothing
/// else: SSH never, and an app's own port never.
fn allow_problems(name: &str, firewall: &Firewall, behind_waf: bool, out: &mut Vec<String>) {
    for (field, list) in [
        ("ssh_allow", &firewall.ssh_allow),
        ("app_allow", &firewall.app_allow),
    ] {
        let at = format!("env.{name}.firewall.{field}");
        if list.len() > MAX_ALLOW {
            out.push(format!("{at}: at most {MAX_ALLOW} entries"));
        }
        let mut seen = BTreeSet::new();
        for cidr in list {
            if !seen.insert(cidr) {
                out.push(format!("{at}: {cidr} is listed twice"));
            }
            if cidr.is_everyone() && field == "app_allow" && !behind_waf {
                out.push(format!(
                    "{at}: {cidr} allows every address, which only an app behind a WAF may \
                     be open to: add [waf], or list the addresses that need access instead"
                ));
            } else if cidr.is_everyone() && field == "ssh_allow" {
                out.push(format!(
                    "{at}: {cidr} allows every address; list the addresses that need access \
                     instead"
                ));
            }
        }
    }
}

/// What is wrong with an environment's data lines, `at` naming them.
fn line_problems(at: &str, lines: &[Line], out: &mut Vec<String>) {
    let mut kinds = BTreeSet::new();
    for line in lines {
        let id_ok = !line.id.is_empty() && line.id.bytes().all(|b| b.is_ascii_digit());
        if !id_ok || !(line.is_pending() || line.kind.endpoint_ok(&line.endpoint)) {
            out.push(format!(
                "{at}: a line is a numeric id and its endpoint (https://<host>; \
                 http://<address>:<port> for unlimited)"
            ));
        }
        if !kinds.insert(line.kind) {
            out.push(format!("{at}: one line of each kind"));
        }
    }
}

/// What is wrong with an environment's starts on record, `at` naming them.
fn start_problems(at: &str, starting: &BTreeMap<StartOf, Start>, out: &mut Vec<String>) {
    for (of, start) in starting {
        let key_ok = start.key.len() == 32
            && start
                .key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let product_ok = !start.product.is_empty()
            && start.product.len() <= 128
            && start
                .product
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
        let region_ok = start.region.as_deref().is_none_or(|r| is_slug(r, 32));
        let ip_ok = start
            .ip
            .as_deref()
            .is_none_or(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok());
        if !(key_ok && is_slug(&start.family, 32) && product_ok && region_ok && ip_ok) {
            out.push(format!(
                "{at}.{}: a start on record is its request key (32 hex digits), the hourly \
                 family, the product id, and its region or the IPv4 address it lets in",
                of.as_str()
            ));
        }
    }
}

/// Finds the `erpc.toml` that governs `start`: in it or the nearest
/// directory above it that has one, as Cargo finds `Cargo.toml`.
#[must_use]
pub fn locate(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|dir| dir.join(FILE_NAME))
        .find(|candidate| candidate.is_file())
}

/// Lowercase letters, digits and single hyphens, starting with a letter,
/// not ending with a hyphen, at most `max` long: safe in a unit name, a
/// directory name and a Linux user name alike.
#[must_use]
pub fn is_slug(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && !s.ends_with('-')
        && !s.contains("--")
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A 1Password id: 26 lowercase letters and digits, as `op://` references
/// take them.
fn is_vault_id(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Variable names the server sets itself, or that change how a program is
/// loaded, which an app's settings must not replace.
const RESERVED_NAMES: [&str; 8] = [
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "CREDENTIALS_DIRECTORY",
    "NOTIFY_SOCKET",
    "LISTEN_FDS",
    "LISTEN_PID",
];

/// Whether `name` may name a setting in `[vars]` or `[secrets]`.
///
/// # Errors
///
/// Why it may not.
pub fn check_setting_name(name: &str) -> Result<(), String> {
    check_env_name(name)
}

/// The most bytes a setting's value under `[vars]` has.
pub const MAX_VAR_VALUE: usize = 4096;

/// Whether `value` may be a setting's value under `[vars]`: one line, as
/// an environment file on the server holds it.
///
/// # Errors
///
/// Why it may not.
pub fn check_var_value(value: &str) -> Result<(), String> {
    if value.len() > MAX_VAR_VALUE || value.contains(['\n', '\r', '\0']) {
        return Err("a value is one line of at most 4096 bytes".to_owned());
    }
    Ok(())
}

fn check_env_name(name: &str) -> Result<(), String> {
    let shaped = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_uppercase() || b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && name.len() <= 128;
    if !shaped {
        return Err("a variable name is uppercase letters, digits and `_`".to_owned());
    }
    if name.starts_with("ERPC_WORKER_") {
        return Err("names starting with ERPC_WORKER_ are set by erpc itself".to_owned());
    }
    if name.starts_with("LD_") || RESERVED_NAMES.contains(&name) {
        return Err("this name is set by the server and cannot be replaced".to_owned());
    }
    Ok(())
}

/// Whether a setting's name says its value is a secret: what `check` warns
/// of in `[vars]`.
#[must_use]
pub fn looks_secret(name: &str) -> bool {
    [
        "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE", "API_KEY", "APIKEY", "MNEMONIC", "SEED",
    ]
    .iter()
    .any(|word| name.contains(word))
}

/// What in a value is a credential: what `import` does not copy out of an
/// example file, and, for the kinds that are [`Credential::sure`], what
/// `check` warns of under `[vars]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// A URL with a password, or a token, before its host:
    /// `scheme://user:password@host`, `scheme://token@host`. A short name
    /// alone there (`git`, `deploy-bot`) is a user's, and is not one.
    UrlUserinfo,
    /// A private key, by its PEM header.
    PrivateKey,
    /// What an `Authorization` header carries: `Bearer <token>`,
    /// `Basic <base64>`.
    Authorization,
    /// A JSON Web Token.
    Jwt,
    /// A token of a service's own shape: Stripe's, AWS's, GitHub's and
    /// Slack's, GitLab's personal access tokens (`glpat-…`), Google's API
    /// keys (`AIza…`), `sk-…` keys, a Telegram bot's token, or the address
    /// of a Slack or Discord webhook.
    Token,
    /// A `name=value` pair, as in a URL's query, whose name says the value
    /// is a key, a token, a password or a signature.
    Parameter,
    /// A wallet's key as Solana tools write one: 64 bytes in base58, or a
    /// keypair file's 64 numbers.
    WalletKey,
    /// 12, 15, 18, 21 or 24 short lowercase words and nothing else, as a
    /// recovery phrase is written. Any such list of words has the shape.
    Phrase,
    /// A long part of a URL's path, where RPC providers put a key. An id
    /// or a hash in a path has the shape too.
    UrlPath,
}

impl Credential {
    /// Whether the shape is seldom anything but a credential.
    ///
    /// `import` holds back a value of any kind: a wrong hold there costs
    /// one line to move in `erpc.toml`, which names what was held. `check`
    /// runs before every deploy, so it warns only of these: a warning on
    /// every run for an id in a URL's path, or for a list of words, would
    /// teach to pass the others over.
    #[must_use]
    pub const fn sure(self) -> bool {
        !matches!(self, Self::Phrase | Self::UrlPath)
    }
}

/// Whether a value carries a credential in it, as a URL with a key in its
/// query does.
#[must_use]
pub fn carries_credential(value: &str) -> bool {
    credential_in(value).is_some()
}

/// The credential `value` carries, the first kind found. It reads shapes,
/// not meanings: a secret that looks like none of these is not found, and
/// a value shaped like one is taken for one.
///
/// The time it takes grows faster than the value: a caller that reads
/// values of any length bounds them first ([`MAX_VAR_VALUE`], which every
/// value under `[vars]` is within).
#[must_use]
pub fn credential_in(value: &str) -> Option<Credential> {
    let found = [
        (url_userinfo(value), Credential::UrlUserinfo),
        (private_key(value), Credential::PrivateKey),
        (authorization(value), Credential::Authorization),
        (json_web_token(value), Credential::Jwt),
        (service_token(value), Credential::Token),
        (credential_parameter(value), Credential::Parameter),
        (wallet_key(value), Credential::WalletKey),
        // The two that are not sure come last: a value that also has a
        // sure kind is told by that one.
        (recovery_phrase(value), Credential::Phrase),
        (url_path_key(value), Credential::UrlPath),
    ];
    found.into_iter().find_map(|(is, kind)| is.then_some(kind))
}

/// The byte before `at` in `text`, when there is one.
fn before(text: &str, at: usize) -> Option<u8> {
    at.checked_sub(1)
        .and_then(|i| text.as_bytes().get(i).copied())
}

/// A URL with a password, or a token, before its host. A URL runs to the
/// next space, and its authority to the first `/`, `?` or `#`.
///
/// What stands before the last `@` of the authority is judged: what
/// follows a colon there is a password, whatever it is; with none, or an
/// empty one, a short name is a user's (`ssh://git@…`,
/// `postgres://app_user@…`), which is no secret, and anything else is a
/// token.
///
/// A password may itself hold a `/`, a `?` or a `#`, written as it is and
/// not as a URL wants it. So when the authority has no `@`, and what
/// follows its colon is not a port, the last `@` of the whole URL is taken
/// to end a password. An `@` after a host, or after a host and its port,
/// is an address or a path (a handle after the host, `…/@handle`), and is
/// left alone.
///
/// A port is read up to what ends an entry of a list, and is one of:
///
/// - one to five digits;
/// - nothing, when nothing follows the colon either (`host:` before a
///   path); nothing before what ends an entry is no port;
/// - a placeholder for one: `${…}` with a name in it, at the end or before
///   what ends an entry, or `$` and a name of capitals, digits and `_`
///   (`$PORT`, `$1`).
fn url_userinfo(value: &str) -> bool {
    value.match_indices("://").any(|(at, mark)| {
        let url = value[at + mark.len()..]
            .split(char::is_whitespace)
            .next()
            .unwrap_or_default();
        let authority = url.split(['/', '?', '#']).next().unwrap_or_default();
        // What follows a host's colon is its port when it is at most five
        // digits, read up to what ends an entry of a list: after
        // `host:5672,` the next address begins.
        let port = |text: &str| {
            // A placeholder for one stands for one: `${…}`, or `$` and a
            // name in capitals (`$PORT`). Any other text after a `$` is
            // not: a password may well start with one.
            if let Some(braced) = text.strip_prefix("${") {
                return braced.split_once('}').is_some_and(|(name, after)| {
                    !name.is_empty() && (after.is_empty() || after.starts_with(ends_entry))
                });
            }
            let digits = text.split(ends_entry).next().unwrap_or_default();
            let named = digits.strip_prefix('$').is_some_and(|name| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            });
            // No digits at all is a port only when nothing follows the
            // colon: `host:` before a path. Before what ends an entry it
            // is the start of something else, a password among them.
            let number = if digits.is_empty() {
                text.is_empty()
            } else {
                digits.len() <= 5 && digits.bytes().all(|b| b.is_ascii_digit())
            };
            named || number
        };
        let userinfo = match authority.rsplit_once('@') {
            Some((userinfo, _)) => Some(userinfo),
            None => authority
                .split_once(':')
                .filter(|(host, after)| !host.starts_with('[') && !port(after))
                .and_then(|_| url.rsplit_once('@'))
                .map(|(userinfo, _)| userinfo),
        };
        before(value, at).is_some_and(|b| b.is_ascii_alphanumeric())
            && userinfo.is_some_and(|userinfo| {
                let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                !password.is_empty() || !user_name(user)
            })
    })
}

/// Whether what stands alone before a URL's host is a user's name and not
/// a token: nothing, or under 16 letters with `-`, `_` or `.` between
/// them, starting with a letter. A digit in it, a number alone, or 16
/// characters and more is a token's: `deploy-bot` is a name; `tok3n`,
/// `8675309` and a long run of letters are not.
fn user_name(text: &str) -> bool {
    text.is_empty()
        || (text.len() < 16
            && text.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
            && text
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || matches!(b, b'-' | b'_' | b'.')))
}

/// A PEM header that names a private key. A certificate or a public key
/// under the same kind of header is not a secret.
fn private_key(value: &str) -> bool {
    value.match_indices("-----BEGIN ").any(|(at, begin)| {
        value[at + begin.len()..]
            .split("-----")
            .next()
            .is_some_and(|label| label.contains("PRIVATE KEY"))
    })
}

/// Whether `token` is long and mixed enough to be a credential and not a
/// word: `Bearer` before `tokens`, or `Basic` before `settings`,
/// `Calculator` or `realm=example`, is prose. A word is letters with no
/// capital past the first.
fn opaque(token: &str) -> bool {
    let word = token.bytes().all(|b| b.is_ascii_alphabetic())
        && token.bytes().skip(1).all(|b| b.is_ascii_lowercase());
    token.len() >= 8
        && !word
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        && token
            .bytes()
            .any(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

/// `Bearer` or `Basic`, in any case, before a token.
fn authorization(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["bearer ", "basic "].iter().any(|scheme| {
        lower.match_indices(scheme).any(|(at, _)| {
            let token = value[at + scheme.len()..]
                .split_whitespace()
                .next()
                .unwrap_or_default();
            !before(value, at).is_some_and(|b| b.is_ascii_alphanumeric()) && opaque(token)
        })
    })
}

/// How many bytes at the start of `text` are base64url's.
fn base64url_run(text: &str) -> usize {
    text.bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        .count()
}

/// Three base64url parts joined by dots, the first starting `eyJ`: a JSON
/// object, which is what a token's header is.
fn json_web_token(value: &str) -> bool {
    value.match_indices("eyJ").any(|(at, _)| {
        let inside = before(value, at)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
        let rest = &value[at..];
        let head = base64url_run(rest);
        let Some(rest) = rest[head..].strip_prefix('.') else {
            return false;
        };
        let body = base64url_run(rest);
        let Some(rest) = rest[body..].strip_prefix('.') else {
            return false;
        };
        !inside && head > 3 && body > 0 && base64url_run(rest) > 0
    })
}

/// The prefixes services give their tokens: Stripe's secret and restricted
/// keys, GitHub's tokens, Slack's.
const TOKEN_PREFIXES: [&str; 15] = [
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xoxa-",
    "xoxb-",
    "xoxp-",
    "xoxr-",
    "xoxs-",
];

/// Prefixes that are also the start of plain words (`sk-learn`), each with
/// how many token characters must follow it: `sk-…` keys (`sk-proj-…`
/// among them), GitLab's `glpat-…`, Google's `AIza…`.
const LONG_TOKEN_PREFIXES: [(&str, usize); 3] = [("sk-", 20), ("glpat-", 20), ("AIza", 30)];

/// How many bytes at the start of `text` are a token's: letters, digits,
/// `-` and `_`.
fn token_run(text: &str) -> usize {
    base64url_run(text)
}

/// A Telegram bot's token: 8 to 12 digits, a colon, and 30 or more token
/// characters. A host and its port have neither.
fn telegram_token(value: &str) -> bool {
    value.match_indices(':').any(|(at, _)| {
        let id = value[..at]
            .bytes()
            .rev()
            .take(13)
            .take_while(u8::is_ascii_digit)
            .count();
        (8..=12).contains(&id) && token_run(&value[at + 1..]) >= 30
    })
}

/// A token by the shape its service gives it: one of [`TOKEN_PREFIXES`]
/// at the start of a word, one of [`LONG_TOKEN_PREFIXES`] before enough
/// of a token, an AWS access key id (`AKIA` or `ASIA` and 16 capitals or
/// digits), a Telegram bot's token, or the address of a Slack or Discord
/// webhook.
fn service_token(value: &str) -> bool {
    let starts_word =
        |at: usize| !before(value, at).is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
    let long = LONG_TOKEN_PREFIXES.iter().any(|(prefix, least)| {
        value
            .match_indices(prefix)
            .any(|(at, _)| starts_word(at) && token_run(&value[at + prefix.len()..]) >= *least)
    });
    let lower = value.to_ascii_lowercase();
    let webhook = [
        "hooks.slack.com/services/",
        "discord.com/api/webhooks/",
        "discordapp.com/api/webhooks/",
    ]
    .iter()
    .any(|address| lower.contains(address));
    let prefixed = TOKEN_PREFIXES.iter().any(|prefix| {
        value.match_indices(prefix).any(|(at, _)| {
            starts_word(at)
                && value[at + prefix.len()..]
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
        })
    });
    let aws = ["AKIA", "ASIA"].iter().any(|prefix| {
        value.match_indices(prefix).any(|(at, _)| {
            let id = &value.as_bytes()[at + prefix.len()..];
            starts_word(at)
                && id.len() >= 16
                && id[..16]
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
    });
    prefixed || long || aws || webhook || telegram_token(value)
}

/// What a `token` is called when it is one to trade, or to page by, and
/// not a credential: `inputToken`, `quote_token`, `pageToken`.
const NOT_SECRET_TOKENS: [&str; 28] = [
    "input",
    "output",
    "in",
    "out",
    "base",
    "quote",
    "from",
    "to",
    "src",
    "dst",
    "source",
    "target",
    "sell",
    "buy",
    "pay",
    "fee",
    "reward",
    "stake",
    "lp",
    "pool",
    "native",
    "wrapped",
    "vs",
    "page",
    "next",
    "prev",
    "continuation",
    "cursor",
];

/// What a `key` is called when it is one to look up or to order by, and
/// not a credential: `sort_key`, `cache.key`, `public_key`.
const NOT_SECRET_KEYS: [&str; 23] = [
    "sort",
    "cache",
    "public",
    "pub",
    "primary",
    "foreign",
    "partition",
    "group",
    "order",
    "index",
    "idx",
    "map",
    "hash",
    "row",
    "object",
    "lookup",
    "routing",
    "shard",
    "range",
    "start",
    "end",
    "min",
    "max",
];

/// Names in one lowercase word that end in `key` and are a credential's.
/// Most words that end so are not (`monkey`), so these are listed.
const JOINED_KEYS: [&str; 8] = [
    "secretkey",
    "privatekey",
    "accesskey",
    "authkey",
    "masterkey",
    "signingkey",
    "licensekey",
    "passkey",
];

/// The endings that make a name a credential's whatever stands before
/// them, in the name taken whole and in lowercase: `sslpassword`,
/// `passWord`, `client_secret`, `X-Amz-Signature`, `myapikey`.
const SECRET_ENDINGS: [&str; 6] = ["password", "passwd", "pwd", "secret", "signature", "apikey"];

/// The words of a parameter's name, in lowercase: parted at `-`, `_` and
/// `.`; where a capital follows a small letter or a digit
/// (`trustStorePassword`, `oauth2Token`); and, with `acronyms`, before the
/// last of a run of capitals when a small letter follows it, so that an
/// acronym is a word of its own (`RPCKey` is `rpc`, `key`).
fn name_words(name: &str, acronyms: bool) -> Vec<String> {
    let letters: Vec<char> = name.chars().collect();
    let mut words = vec![String::new()];
    for (at, &c) in letters.iter().enumerate() {
        if matches!(c, '-' | '_' | '.') {
            words.push(String::new());
            continue;
        }
        let earlier = at.checked_sub(1).and_then(|at| letters.get(at));
        let after_small = earlier.is_some_and(|e| e.is_ascii_lowercase() || e.is_ascii_digit());
        let ends_capitals = acronyms
            && earlier.is_some_and(char::is_ascii_uppercase)
            && letters.get(at + 1).is_some_and(char::is_ascii_lowercase);
        if c.is_ascii_uppercase() && (after_small || ends_capitals) {
            words.push(String::new());
        }
        if let Some(word) = words.last_mut() {
            word.push(c.to_ascii_lowercase());
        }
    }
    words.retain(|word| !word.is_empty());
    words
}

/// The endings of [`SECRET_ENDINGS`] that name a password: its value is
/// one whatever it looks like.
const PASSWORD_ENDINGS: [&str; 3] = ["password", "passwd", "pwd"];

/// A parameter's name without what may follow its last word: a number or
/// a separator (`password2`, `api_key_1`, `pwd-`).
fn bare_name(name: &str) -> &str {
    name.trim_end_matches(|c: char| c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

/// Whether a parameter's name is a password's: its value is a credential
/// even when it is a short word or a number.
fn names_password(name: &str) -> bool {
    let whole = bare_name(name).to_ascii_lowercase();
    PASSWORD_ENDINGS.iter().any(|end| whole.ends_with(end))
}

/// Whether a parameter's name says its value is a credential. The name is
/// read without what follows its last word ([`bare_name`]):
///
/// - the name, whole and in lowercase, ends in one of [`SECRET_ENDINGS`];
/// - its last word ([`name_words`]) ends in `token`, unless what stands
///   before that, in the word or as the word before, is one of
///   [`NOT_SECRET_TOKENS`] (`access_token`, `userToken`; not `inputToken`);
/// - its last word is `key`, alone or after a word that is not one of
///   [`NOT_SECRET_KEYS`] (`api-key`, `service_key`, `RPCKey`; not
///   `sort_key`);
/// - its last word is one of [`JOINED_KEYS`]. `monkey` is none of these.
///
/// The words are taken three ways, and the name is a credential's by any
/// of them, so that no way of writing a name hides it:
///
/// - parted at capitals, an acronym being a word of its own
///   ([`name_words`]): `RPCKey`;
/// - parted at capitals where one follows a small letter or a digit, and
///   nowhere else, for capitals that start no word after an owner
///   (`myTOKen`, `userKEy`);
/// - parted at `-`, `_` and `.` alone, for a name whose capitals start no
///   word at all (`TOKen`, `SECRETkey`). This way reads a last word only
///   as it stands, not by what it ends in: `myInputToken` is one word that
///   way, and is left to the others.
///
/// A word that is no credential's is so by the way that parts it: after an
/// acronym it is told by the first way and missed by the second, so
/// `DBSortKey` is held though `sort_key` is not.
///
/// It errs towards a credential: a name wrongly taken for one costs a
/// line to move in `erpc.toml`, one missed puts a key in a file that is
/// committed.
fn names_credential(name: &str) -> bool {
    let name = bare_name(name);
    let whole = name.to_ascii_lowercase();
    if SECRET_ENDINGS.iter().any(|end| whole.ends_with(end)) {
        return true;
    }
    let plainly: Vec<String> = whole
        .split(['-', '_', '.'])
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect();
    last_word_says(&name_words(name, true), true)
        || last_word_says(&name_words(name, false), true)
        || last_word_says(&plainly, false)
}

/// Whether the last of a name's `words` says a credential, with the word
/// before it. `inside` is whether a last word that only ends in `token`
/// is read for what stands before that in it (`usertoken`).
fn last_word_says(words: &[String], inside: bool) -> bool {
    let Some((last, earlier)) = words.split_last() else {
        return false;
    };
    let earlier = earlier.last().map(String::as_str);
    match last.strip_suffix("token") {
        Some("") => return !NOT_SECRET_TOKENS.contains(&earlier.unwrap_or_default()),
        Some(lead) if inside => return !NOT_SECRET_TOKENS.contains(&lead),
        _ => {}
    }
    if last == "key" {
        return earlier.is_none_or(|owner| !NOT_SECRET_KEYS.contains(&owner));
    }
    JOINED_KEYS.contains(&last.as_str())
}

/// Text too short and plain to be a credential: a word or a number under
/// 16 characters (`value`, `true`, `1`, `git`), or nothing.
fn plain(value: &str) -> bool {
    value.len() < 16
        && (value.bytes().all(|b| b.is_ascii_alphabetic())
            || value.bytes().all(|b| b.is_ascii_digit()))
}

/// How many characters of what a parameter is given are read.
const GIVEN_READ: usize = 64;

/// What a parameter is given, by its start, for a name that is no
/// password's. Spaces after the `=` are passed over. In quotes it is what
/// stands between them, whatever that holds; else it runs to what ends a
/// parameter (`&`, `;`, `,`, `#`, a quote, a space). No more than
/// [`GIVEN_READ`] characters are read.
fn given(after: &str) -> String {
    let after = after.trim_start_matches([' ', '\t']);
    match after.chars().next() {
        Some(quote @ ('"' | '\'')) => after[1..]
            .chars()
            .take(GIVEN_READ)
            .take_while(|c| *c != quote)
            .collect(),
        _ => after
            .chars()
            .take(GIVEN_READ)
            .take_while(|c| !(matches!(c, '&' | ';' | ',' | '#' | '"' | '\'') || c.is_whitespace()))
            .collect(),
    }
}

/// Whether a parameter's value ends where `rest` starts, having given
/// nothing: only white space is left of the text, with at most one `;`
/// in it that closes the parameter; or, `in_query`, an `&` stands there
/// after any white space, which in a URL's query is the next parameter.
/// Anywhere else a `;` or an `&` is the first character of what is
/// given: a `;` parts parameters in some formats only, and nothing tells
/// here which one a text is in.
fn ends_empty(rest: &str, in_query: bool) -> bool {
    let rest = rest.trim_start();
    match rest.chars().next() {
        None => true,
        Some(';') => rest[1..].trim_start().is_empty(),
        Some('&') => in_query,
        Some(_) => false,
    }
}

/// Whether a password's parameter is given anything. A password can be
/// any text, so this does not read what it is, only that it is there.
/// `in_query` is whether the name stands after a `?` or an `&`.
///
/// Nothing is given when, after the `=`, the value ends empty
/// ([`ends_empty`]), or quotes close as they open (`''`, `""`) and it ends
/// empty after them. Anything else is a password: one that starts with
/// `#`, a comma, a brace, a `;` or an `&`, or with its own quote written
/// twice (`"""…"`), in quotes or not; and so is an empty one with another
/// parameter after it (`Password=;Database=app`), which is held rather
/// than read for where it ends.
fn password_given(after: &str, in_query: bool) -> bool {
    if ends_empty(after, in_query) {
        return false;
    }
    let after = after.trim_start();
    let closed = ['"', '\'']
        .into_iter()
        .find_map(|quote| after.strip_prefix(quote)?.strip_prefix(quote));
    closed.is_none_or(|rest| !ends_empty(rest, in_query))
}

/// A `name=value` pair whose name is a credential's; spaces about the `=`
/// are not part of either side (`Password = …`).
///
/// - A password's name (`password`, `passwd`, `pwd`): a credential
///   whenever it is given anything ([`password_given`]), wherever it
///   stands and whatever the value is (`password=swordfish`,
///   `password='#…'`).
/// - Any other name, in a URL's query (after `?` or `&`): a credential
///   whenever it is given anything ([`given`]). That is where a key goes,
///   and an example's placeholder stands for one.
/// - Any other name elsewhere: only when what it is given is more than a
///   plain word ([`plain`]), so that `key=value` and `token=true` are left
///   alone.
fn credential_parameter(value: &str) -> bool {
    let in_name = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    value.match_indices('=').any(|(at, _)| {
        let head = value[..at].trim_end_matches([' ', '\t']);
        let start = head.trim_end_matches(in_name).len();
        let name = &head[start..];
        let after = &value[at + 1..];
        if !names_credential(name) {
            return false;
        }
        let in_query = before(value, start).is_some_and(|b| matches!(b, b'?' | b'&'));
        if names_password(name) {
            return password_given(after, in_query);
        }
        let given = given(after);
        !given.is_empty() && (in_query || !plain(&given))
    })
}

/// Whether `b` is one of base58's characters: letters and digits without
/// `0`, `O`, `I` and `l`.
const fn is_base58(b: u8) -> bool {
    b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l')
}

/// The characters a URL in a list ends at, besides a space: what stands
/// between the entries of a list, or closes it.
const fn ends_entry(c: char) -> bool {
    matches!(c, ',' | ';' | '"' | '\'' | ')' | ']' | '}' | '>' | '|')
}

/// A wallet's key as Solana tools write one:
///
/// - 64 bytes in base58, as a wallet exports a secret key: a run of 86 to
///   88 base58 characters, no longer. A transaction's signature has the
///   same shape. In a URL, right after a `/`, the run is taken for one (an
///   explorer's address for it) and left alone; anywhere else it is taken
///   for a key.
/// - a keypair file's content: 64 numbers from 0 to 255 between brackets.
///
/// An address is 32 bytes (43 or 44 characters) and is neither. A key in
/// hexadecimal is not told from a hash or another chain's address, and is
/// not looked for.
fn wallet_key(value: &str) -> bool {
    // Whether the run that starts at `start` is a part of a URL's path:
    // right after a `/`, in an entry that has a `://` before it.
    let in_path = |start: usize| {
        let head = &value[..start];
        // Parted by characters, never by a byte count: a space can be
        // two or three bytes wide.
        let entry = head
            .rsplit(|c: char| c.is_whitespace() || ends_entry(c))
            .next()
            .unwrap_or(head);
        head.ends_with('/') && entry.contains("://")
    };
    let mut start = 0;
    let mut base58 = false;
    for (at, c) in value.char_indices().chain([(value.len(), ' ')]) {
        if c.is_ascii_alphanumeric() {
            continue;
        }
        let run = &value[start..at];
        base58 |= (86..=88).contains(&run.len()) && run.bytes().all(is_base58) && !in_path(start);
        start = at + c.len_utf8();
    }
    let keypair = value.split('[').skip(1).any(|after| {
        after.split_once(']').is_some_and(|(inside, _)| {
            let mut numbers = 0;
            inside.split(',').all(|number| {
                numbers += 1;
                number.trim().parse::<u8>().is_ok()
            }) && numbers == 64
        })
    });
    base58 || keypair
}

/// A value shaped as a recovery phrase is written: 12, 15, 18, 21 or 24
/// words of 3 to 8 lowercase letters, and nothing else. The words are not
/// held against the list phrases are drawn from, so any such list of
/// words has the shape.
fn recovery_phrase(value: &str) -> bool {
    let words: Vec<&str> = value.split_whitespace().collect();
    matches!(words.len(), 12 | 15 | 18 | 21 | 24)
        && words.iter().all(|word| {
            (3..=8).contains(&word.len()) && word.bytes().all(|b| b.is_ascii_lowercase())
        })
}

/// A key as a part of a URL's path, where RPC providers and bots' APIs
/// put theirs. A URL runs to the next space, and its path from the host to
/// the query. A part of the path (between `/`; and between `.`, a comma
/// and the other characters of [`ends_entry`], so that `<key>.json` and
/// the URLs of a list are each read) is a key when it is 32 or more
/// letters, digits, `-` and `_`, with a letter and a digit in it.
///
/// Left alone, being what a URL names more often than a key: a part
/// shaped like an address on Solana (43 or 44 base58 characters) or like
/// a transaction's signature (86 to 88), and hexadecimal after `0x`.
fn url_path_key(value: &str) -> bool {
    let key = |part: &str| {
        let base58 = part.bytes().all(is_base58);
        let named = base58 && matches!(part.len(), 43 | 44 | 86..=88);
        let hex = part
            .strip_prefix("0x")
            .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()));
        part.len() >= 32
            && !named
            && !hex
            && token_run(part) == part.len()
            && part.bytes().any(|b| b.is_ascii_digit())
            && part.bytes().any(|b| b.is_ascii_alphabetic())
    };
    value.match_indices("://").any(|(at, mark)| {
        value[at + mark.len()..]
            .split(char::is_whitespace)
            .next()
            .unwrap_or_default()
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .split('/')
            .skip(1)
            .any(|part| part.split(|c| c == '.' || ends_entry(c)).any(key))
    })
}

fn check_template(template: &str, chain: Chain) -> Result<(), String> {
    let shape =
        || format!("`{template}` is not <chain>/<template>@<version>, such as solana/pumpfun@1");
    let (path, version) = template.split_once('@').ok_or_else(shape)?;
    let (of, name) = path.split_once('/').ok_or_else(shape)?;
    if !is_slug(name, 32) || version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(shape());
    }
    if of != chain.as_str() {
        return Err(format!(
            "`{template}` is for {of}, and this app is for {chain}"
        ));
    }
    Ok(())
}

fn is_relative_inside(path: &str) -> bool {
    let path = Path::new(path);
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

fn is_loopback_url(url: &str) -> bool {
    ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"]
        .iter()
        .find_map(|prefix| url.strip_prefix(prefix))
        .is_some_and(|rest| {
            let port: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let after = &rest[port.len()..];
            port.parse::<u16>().is_ok_and(|p| p != 0)
                && (after.is_empty() || after.starts_with('/'))
        })
}

fn is_pubkey(chain: Chain, key: &str) -> bool {
    match chain {
        // Base58 of 32 bytes: 32 to 44 characters, without 0, O, I or l.
        Chain::Solana => {
            (32..=44).contains(&key.len())
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Chain, Credential, FILE_NAME, LineKind, Manifest, ManifestError, SecretRef, Target,
        is_key_account, locate,
    };

    #[test]
    fn one_setting_of_a_set_is_enough() {
        let text = "name = \"bot\"\nchain = \"solana\"\n[run]\nrequires = [\"API_TOKEN\", [\"ERPC_API_KEY\", \"SOLANA_RPC_ENDPOINT\"]]\n";
        let m = Manifest::parse(text).expect("parsed");
        let missing: Vec<String> = m.missing().iter().map(ToString::to_string).collect();
        assert_eq!(
            missing,
            ["API_TOKEN", "ERPC_API_KEY or SOLANA_RPC_ENDPOINT"]
        );
        // The first of the set is the one to suggest.
        assert_eq!(m.missing()[1].first(), "ERPC_API_KEY");
        let with_rpc = format!("{text}[vars]\nSOLANA_RPC_ENDPOINT = \"set\"\n");
        let m = Manifest::parse(&with_rpc).expect("parsed");
        assert_eq!(m.missing().len(), 1, "{:?}", m.missing());
        assert!(
            m.warnings()
                .iter()
                .any(|w| w.starts_with("API_TOKEN is required")),
            "{:?}",
            m.warnings()
        );
        // A set of one is a mistake, and a bad name in a set is found.
        let one = "name = \"bot\"\nchain = \"solana\"\n[run]\nrequires = [[\"ONLY\"]]\n";
        assert!(
            problems(one)
                .iter()
                .any(|p| p.contains("two or more names"))
        );
        let bad =
            "name = \"bot\"\nchain = \"solana\"\n[run]\nrequires = [[\"A\", \"not a name\"]]\n";
        assert!(
            problems(bad)
                .iter()
                .any(|p| p.contains("run.requires: not a name"))
        );
    }

    #[test]
    fn a_missing_line_setting_names_the_flag_that_provides_it() {
        let m = Manifest::parse(
            "name = \"bot\"\nchain = \"solana\"\n[run]\nrequires = [\"GRPC_ENDPOINT\", \"SOLANA_SEND_RPC_ENDPOINT\"]\n",
        )
        .expect("parsed");
        let warnings = m.warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("`--grpc` on deploy") && w.contains("`--ip <IPV4>`")),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("`--unlimited` on deploy") && !w.contains("--ip")),
            "{warnings:?}"
        );
    }

    #[test]
    fn services_give_the_app_their_urls_and_count_as_set() {
        let m = Manifest::parse(
            "name = \"bot\"\nchain = \"solana\"\n[run]\nrequires = [\"REDIS_URL\", \"DATABASE_URL\"]\n[services]\nredis = true\npostgres = true\n",
        )
        .expect("parsed");
        assert!(
            m.missing_besides(&[]).is_empty(),
            "{:?}",
            m.missing_besides(&[])
        );
        assert_eq!(
            m.services.vars(),
            vec![
                ("REDIS_URL", super::REDIS_URL),
                ("DATABASE_URL", super::DATABASE_URL)
            ]
        );
        // Each service is named with the setting it gives, the same ones.
        assert_eq!(
            m.services.provided(),
            vec![("redis", "REDIS_URL"), ("postgres", "DATABASE_URL")]
        );
        assert!(super::Services::default().provided().is_empty());
        assert!(
            Manifest::parse("name = \"bot\"\nchain = \"solana\"\n[services]\nmysql = true\n")
                .is_err()
        );
    }

    const VAULT: &str = "abcdefghijklmnopqrstuvwxyz";
    const ITEM: &str = "0123456789abcdefghijklmnop";

    fn full() -> String {
        format!(
            r#"
name     = "pump-sniper"
chain    = "solana"
template = "solana/pumpfun@1"

[build]
bin = "pump-sniper"

[run]
files  = ["config.jsonc"]
health = {{ http = "http://127.0.0.1:3000/healthz", timeout_secs = 20 }}

[vars]
RUST_LOG = "info"

[secrets]
X_TOKEN = "op://{VAULT}/{ITEM}/x-token"
ERPC_API_KEY = "keychain:erpc-worker/pump-sniper-api-key"
API_TOKEN = "keystore:erpc-worker/pump-sniper.API_TOKEN"

[wallet]
source = "op://{VAULT}/{ITEM}/keypair"
pubkey = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"

[env.default]
resource = {{ kind = "vps", id = "uv_123", region = "frankfurt", hourly = true }}
host     = "203.0.113.10"
ssh_user = "solv"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"

[env.default.firewall]
ssh_allow = ["198.51.100.7"]
"#
        )
    }

    fn problems(text: &str) -> Vec<String> {
        match Manifest::parse(text) {
            Err(ManifestError::Invalid(problems)) => problems,
            other => panic!("expected problems, got {other:?}"),
        }
    }

    #[test]
    fn a_prebuilt_binary_is_a_path_inside_the_app_and_takes_the_place_of_the_command() {
        let with = |build: &str| format!("name = \"mine\"\nchain = \"solana\"\n[build]\n{build}\n");
        let m = Manifest::parse(&with("prebuilt = \"dist/mine-linux\"")).expect("valid");
        assert_eq!(m.build.prebuilt.as_deref(), Some("dist/mine-linux"));
        assert_eq!(m.bin(), "mine", "named after the app on the server");
        for outside in ["../mine", "/usr/bin/mine", "dist/../../mine", "a b"] {
            let said = problems(&with(&format!("prebuilt = \"{outside}\"")));
            assert!(
                said.iter().any(|p| p.contains("build.prebuilt")),
                "{outside}: {said:?}"
            );
        }
        let both = problems(&with(
            "prebuilt = \"dist/mine\"\ncommand = [\"make\", \"release\"]",
        ));
        assert!(
            both.iter().any(|p| p.contains("one or the other")),
            "{both:?}"
        );
    }

    #[test]
    fn a_full_manifest_parses_with_its_defaults() {
        let m = Manifest::parse(&full()).expect("valid");
        assert_eq!(m.chain, Chain::Solana);
        assert_eq!(m.bin(), "pump-sniper");
        assert_eq!(m.build.command, ["cargo", "build", "--release"]);
        assert_eq!(m.build.target, Target::X86_64Gnu);
        assert_eq!(m.deploy.keep_releases, 5);
        let env = m.env("default").expect("env");
        assert_eq!(env.ssh_port(), 22);
        assert_eq!(env.firewall.ssh_allow[0].to_string(), "198.51.100.7/32");
        assert_eq!(m.unit_id("default"), "pump-sniper-default");
        assert!(matches!(
            m.secrets.get("ERPC_API_KEY"),
            Some(SecretRef::Keychain { service, .. }) if service == "erpc-worker"
        ));
        assert!(matches!(
            m.secrets.get("API_TOKEN"),
            Some(SecretRef::Keystore { service, account })
                if service == "erpc-worker" && account == "pump-sniper.API_TOKEN"
        ));
        assert!(m.warnings().is_empty(), "{:?}", m.warnings());
    }

    #[test]
    fn the_smallest_manifest_is_a_name_and_a_chain() {
        let m = Manifest::parse("name = \"bot\"\nchain = \"solana\"\n").expect("valid");
        assert_eq!(m.bin(), "bot");
        assert!(m.env("default").is_err());
    }

    #[test]
    fn a_manifest_round_trips_through_toml() {
        let m = Manifest::parse(&full()).expect("valid");
        let text = toml::to_string(&m).expect("serialize");
        assert_eq!(Manifest::parse(&text).expect("reparse"), m);
    }

    #[test]
    fn unknown_keys_and_chains_are_refused() {
        for text in [
            "name = \"bot\"\nchain = \"solana\"\n[firewal]\n",
            "name = \"bot\"\nchain = \"solana\"\n[env.default]\nfirewal = {}\n",
            "name = \"bot\"\nchain = \"tron\"\n",
        ] {
            assert!(
                matches!(Manifest::parse(text), Err(ManifestError::Syntax(_))),
                "{text}"
            );
        }
    }

    #[test]
    fn a_secret_value_is_refused_where_a_reference_belongs() {
        let text = "name = \"bot\"\nchain = \"solana\"\n[secrets]\nX_TOKEN = \"abc123\"\n";
        let Err(ManifestError::Syntax(message)) = Manifest::parse(text) else {
            panic!("expected refusal");
        };
        assert!(message.contains("never the value itself"), "{message}");
        // A reference by vault name is refused too: it does not pin what is read.
        let text =
            "name = \"bot\"\nchain = \"solana\"\n[wallet]\nsource = \"op://Private/bot/key\"\n";
        assert!(Manifest::parse(text).is_err());
    }

    #[test]
    fn a_keystore_reference_parses_and_prints_as_it_was_written() {
        for raw in [
            "keystore:erpc-worker/bot.wallet",
            "keystore:erpc-worker/bot.API_TOKEN",
            "keystore:a/b-c_d.E9",
        ] {
            let parsed = SecretRef::parse(raw).expect(raw);
            assert!(matches!(parsed, SecretRef::Keystore { .. }), "{raw}");
            assert!(parsed.is_local());
            assert_eq!(parsed.to_string(), raw);
            // As erpc.toml and `--json` carry it.
            let json = serde_json::to_string(&parsed).expect("serialize");
            assert_eq!(json, format!("\"{raw}\""));
            assert_eq!(
                serde_json::from_str::<SecretRef>(&json).expect("deserialize"),
                parsed
            );
        }
        let parsed = SecretRef::parse("keystore:erpc-worker/bot.wallet").expect("parses");
        assert_eq!(
            parsed,
            SecretRef::Keystore {
                service: "erpc-worker".to_owned(),
                account: "bot.wallet".to_owned(),
            }
        );
        // Not the keychain entry of the same name.
        assert_ne!(
            parsed,
            SecretRef::parse("keychain:erpc-worker/bot.wallet").expect("parses")
        );
        assert!(
            !SecretRef::parse(&format!("op://{VAULT}/{ITEM}/f"))
                .expect("parses")
                .is_local()
        );
    }

    #[test]
    fn a_keystore_reference_that_could_leave_its_directory_is_refused() {
        for raw in [
            "keystore:",
            "keystore:erpc-worker",
            "keystore:/bot.wallet",
            "keystore:erpc-worker/",
            "keystore:../bot.wallet",
            "keystore:erpc-worker/..",
            "keystore:erpc-worker/.",
            "keystore:erpc-worker/.hidden",
            "keystore:.erpc/bot.wallet",
            "keystore:erpc-worker/a/b",
            "keystore:erpc-worker/a b",
            "keystore:erpc-worker/a\\b",
            "keystore:erpc-worker/bot.wallet\n",
            "Keystore:erpc-worker/bot.wallet",
        ] {
            assert!(SecretRef::parse(raw).is_err(), "{raw:?}");
        }
        let long = "a".repeat(129);
        assert!(SecretRef::parse(&format!("keystore:erpc-worker/{long}")).is_err());
        let text = "name = \"bot\"\nchain = \"solana\"\n[wallet]\nsource = \"keystore:../x\"\n";
        assert!(Manifest::parse(text).is_err());
    }

    #[test]
    fn a_secret_that_names_the_trading_key_is_refused() {
        let head = "name = \"bot\"\nchain = \"solana\"\n";
        let wallet = |source: &str| format!("[wallet]\nsource = \"{source}\"\n");
        let op = format!("op://{VAULT}/{ITEM}/keypair");
        // The entry [wallet] names, in each store.
        for source in [
            "keystore:erpc-worker/bot.wallet",
            "keychain:erpc-worker/bot.wallet",
            "keychain:my-service/trading",
            op.as_str(),
        ] {
            let text = format!(
                "{head}[secrets]\nKEY_COPY = \"{source}\"\n{}",
                wallet(source)
            );
            let found = problems(&text);
            assert_eq!(found.len(), 1, "{found:#?}");
            assert!(
                found[0].starts_with(&format!(
                    "secrets.KEY_COPY: {source} is wallet.source, the trading key: "
                )),
                "{found:#?}"
            );
            assert!(found[0].contains("through [wallet] alone"), "{found:#?}");
            assert!(found[0].ends_with("; remove the line"), "{found:#?}");
            // Without the line the file is as good as before.
            Manifest::parse(&format!("{head}{}", wallet(source))).expect("valid");
        }
        // An entry filed as a key, with no [wallet] here to name it: the
        // erpc.toml of a second directory. In any case, since a keychain
        // or a file system that ignores case takes them for one entry.
        for source in [
            "keystore:erpc-worker/bot.wallet",
            "keystore:erpc-worker/bot.WALLET",
            "keystore:erpc-worker/other.Wallet",
            "keychain:erpc-worker/bot.wallet",
            "keychain:erpc-worker/bot.WALLET",
            "keychain:any-service/x.wallet",
        ] {
            for rest in [String::new(), wallet(&op)] {
                let text = format!("{head}[secrets]\nWALLET = \"{source}\"\n{rest}");
                let found = problems(&text);
                assert_eq!(found.len(), 1, "{found:#?}");
                assert!(
                    found[0].starts_with(&format!(
                        "secrets.WALLET: {source} is an entry filed as a trading key"
                    )),
                    "{found:#?}"
                );
                assert!(found[0].contains("named under [wallet]"), "{found:#?}");
            }
        }
        // What is not a key's entry is a setting as ever: a name that only
        // has `wallet` in it, and the same reference under two settings.
        let text = format!(
            "{head}[secrets]\n\
             WALLET = \"keystore:erpc-worker/bot.WALLET_LABEL\"\n\
             A_TOKEN = \"keychain:erpc-worker/bot.wallet-api\"\n\
             B_TOKEN = \"keychain:erpc-worker/bot.wallet-api\"\n\
             C_TOKEN = \"op://{VAULT}/{ITEM}/credential\"\n{}",
            wallet("keystore:erpc-worker/bot.wallet")
        );
        let m = Manifest::parse(&text).expect("valid");
        // The same question, asked of a reference that is not in the file.
        let reference = |raw: &str| SecretRef::parse(raw).expect(raw);
        assert!(
            m.key_as_setting(&reference("keystore:erpc-worker/bot.wallet"))
                .is_some_and(|why| why.contains("is wallet.source"))
        );
        assert!(
            m.key_as_setting(&reference("keychain:erpc-worker/bot.WALLET"))
                .is_some_and(|why| why.contains("filed as a trading key"))
        );
        assert_eq!(
            m.key_as_setting(&reference("keystore:erpc-worker/bot.API_TOKEN")),
            None
        );
        assert!(is_key_account("bot.wallet") && is_key_account("bot.WaLLeT"));
        assert!(!is_key_account("bot.wallet2") && !is_key_account("wallet"));
        assert!(!reference(&op).is_key_entry());
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let text = r#"
name  = "Pump_Sniper"
chain = "solana"
template = "eth/pumpfun@1"
[run]
files  = ["../secret.json", "a", "a", "./b", "c//d", "e f"]
health = { http = "http://127.0.0.1:0/healthz" }
[vars]
PATH = "/tmp"
lower = "x"
[deploy]
keep_releases = 0
[env.Prod]
host = "root@203.0.113.10"
host_key = "AAAA"
[env.Prod.firewall]
ssh_allow = ["198.51.100.7", "198.51.100.7/32"]
"#;
        let found = problems(text);
        for needle in [
            "name `Pump_Sniper`",
            "template:",
            "`../secret.json`",
            "`a` is listed twice",
            "`./b`",
            "`c//d`",
            "`e f`",
            "run.health.http",
            "vars.PATH",
            "vars.lower",
            "keep_releases",
            "env.Prod:",
            "env.Prod.host",
            "env.Prod.host_key",
            "198.51.100.7/32 is listed twice",
        ] {
            assert!(
                found.iter().any(|p| p.contains(needle)),
                "missing {needle} in {found:#?}"
            );
        }
    }

    #[test]
    fn an_app_port_is_opened_only_with_run_port_set() {
        let base = "name = \"bot\"\nchain = \"solana\"\n[env.default]\nhost = \"203.0.113.10\"\n\
                    [env.default.firewall]\nssh_allow = [\"198.51.100.7\"]\napp_allow = [\"198.51.100.0/24\"]\n";
        assert!(problems(base).iter().any(|p| p.contains("needs run.port")));
        let with_port = format!("{base}[run]\nport = 3000\n");
        let m = Manifest::parse(&with_port).expect("valid");
        // Listening on loopback, the opening reaches nobody: said.
        assert!(
            m.warnings().iter().any(|w| w.contains("API_BIND")),
            "{:?}",
            m.warnings()
        );
        let ssh = format!("{base}[run]\nport = 22\n");
        assert!(problems(&ssh).iter().any(|p| p.contains("run.port 22")));
    }

    #[test]
    fn a_list_that_allows_every_address_is_a_problem_with_its_place() {
        for (list, everyone) in [
            ("ssh_allow", "0.0.0.0/0"),
            ("ssh_allow", "::/0"),
            ("app_allow", "0.0.0.0/0"),
            ("app_allow", "::/0"),
        ] {
            let text = format!(
                "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n[env.prod]\n\
                 host = \"203.0.113.10\"\n[env.prod.firewall]\n{list} = [\"{everyone}\"]\n"
            );
            let found = problems(&text);
            let said = format!("env.prod.firewall.{list}: {everyone} allows every address");
            assert!(found.iter().any(|p| p.starts_with(&said)), "{found:#?}");
        }
    }

    /// An app on port 3000 with `[waf]` holding `waf`, deployed to one
    /// server whose `app_allow` is `allow`.
    fn behind_waf(waf: &str, allow: &str) -> String {
        format!(
            "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n[waf]\n{waf}\n\
             [env.prod]\nhost = \"203.0.113.10\"\n\
             [env.prod.firewall]\nssh_allow = [\"198.51.100.7\"]\napp_allow = [{allow}]\n"
        )
    }

    #[test]
    fn a_waf_needs_only_its_port_and_takes_the_defaults_for_the_rest() {
        use crate::server::NewConnections;
        use crate::waf::WafConfig;
        let m = Manifest::parse(&behind_waf("port = 8080", "")).expect("valid");
        let config = m.waf_config("prod").expect("a config");
        assert_eq!(
            config,
            WafConfig::default_for(
                "bot-prod",
                "0.0.0.0:8080".parse().expect("listen"),
                "127.0.0.1:3000".parse().expect("upstream"),
            )
        );
        assert_eq!(config.stats_path, "/run/erpc-waf-bot-prod/stats.json");
        // What the manifest makes is what the proxy takes.
        assert_eq!(config.validate(), Ok(()));
        let waf = m.waf.as_ref().expect("waf");
        assert_eq!(waf.new_connections(), Some(NewConnections::DEFAULT));
        // Behind a WAF the app is meant to listen on loopback: no warning.
        let open = Manifest::parse(&behind_waf("port = 8080", "\"198.51.100.0/24\"")).expect("ok");
        assert!(open.warnings().is_empty(), "{:?}", open.warnings());
        // Without the table there is no config.
        let plain = Manifest::parse("name = \"bot\"\nchain = \"solana\"\n").expect("valid");
        assert_eq!(plain.waf_config("prod"), None);
    }

    #[test]
    fn every_waf_key_reaches_the_config_the_proxy_reads() {
        use crate::server::NewConnections;
        use crate::waf::{Ban, Rate};
        let waf = "port = 9000\nmethods = [\"GET\", \"HEAD\"]\nallow_paths = [\"/api/*\"]\n\
                   deny_paths = [\"/api/admin/*\"]\nmax_body_bytes = 4096\n\
                   max_header_bytes = 8192\nrate = { per_second = 5, burst = 9 }\n\
                   max_connections_per_address = 4\n\
                   ban = { after = 3, window_secs = 30, for_secs = 90 }\nblock_probes = false\n\
                   header_timeout_secs = 7\nbody_timeout_secs = 9\n\
                   upstream_timeout_secs = 11\nnew_connections = { per_second = 6, burst = 8 }";
        let m = Manifest::parse(&behind_waf(waf, "")).expect("valid");
        let config = m.waf_config("prod").expect("a config");
        assert_eq!(config.listen.to_string(), "0.0.0.0:9000");
        assert_eq!(config.upstream.to_string(), "127.0.0.1:3000");
        assert_eq!(config.methods, ["GET", "HEAD"]);
        assert_eq!(config.allow_paths, ["/api/*"]);
        assert_eq!(config.deny_paths, ["/api/admin/*"]);
        assert_eq!(
            (config.max_body_bytes, config.max_header_bytes),
            (4096, 8192)
        );
        assert_eq!(
            config.rate,
            Some(Rate {
                per_second: 5,
                burst: 9
            })
        );
        assert_eq!(config.max_connections_per_address, Some(4));
        assert_eq!(
            config.ban,
            Some(Ban {
                after: 3,
                window_secs: 30,
                for_secs: 90
            })
        );
        assert!(!config.block_probes);
        assert_eq!(
            (
                config.header_timeout_secs,
                config.body_timeout_secs,
                config.upstream_timeout_secs
            ),
            (7, 9, 11)
        );
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(
            m.waf.as_ref().expect("waf").new_connections(),
            Some(NewConnections {
                per_second: 6,
                burst: 8
            })
        );
        // The file says the same again once written out.
        let text = toml::to_string(&m).expect("serialize");
        assert_eq!(Manifest::parse(&text).expect("reparse"), m);
    }

    #[test]
    fn false_turns_a_protection_off_and_true_is_not_read() {
        let off = "port = 8080\nrate = false\nmax_connections_per_address = false\n\
                   ban = false\nnew_connections = false";
        let m = Manifest::parse(&behind_waf(off, "")).expect("valid");
        let config = m.waf_config("prod").expect("a config");
        assert_eq!(config.rate, None);
        assert_eq!(config.max_connections_per_address, None);
        assert_eq!(config.ban, None);
        assert_eq!(m.waf.as_ref().expect("waf").new_connections(), None);
        // Off stays off through the file, and is not mistaken for absent.
        let text = toml::to_string(&m).expect("serialize");
        assert!(text.contains("rate = false"), "{text}");
        assert_eq!(Manifest::parse(&text).expect("reparse"), m);
        for (waf, says) in [
            ("port = 8080\nrate = true", "leave the key out"),
            ("port = 8080\nban = true", "leave the key out"),
            ("port = 8080\nmax_connections_per_address = true", "leave"),
            ("port = 8080\nnew_connections = true", "leave the key out"),
            ("port = 8080\nrate = \"fast\"", "`false` to turn it off"),
            ("port = 8080\nrate = { per_sec = 5, burst = 9 }", "per_sec"),
            ("port = 8080\nban = { after = 3 }", "window_secs"),
            ("port = 8080\nmax_connections_per_address = -1", "u32"),
            ("port = 8080\ntls = true", "tls"),
            ("methods = [\"GET\"]", "port"),
        ] {
            let Err(ManifestError::Syntax(message)) = Manifest::parse(&behind_waf(waf, "")) else {
                panic!("{waf} was read");
            };
            assert!(message.contains(says), "{waf}: {message}");
        }
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "one table of keys")]
    fn each_thing_wrong_with_a_waf_names_its_key() {
        for (waf, says) in [
            ("port = 80", "waf.port 80 is below 1024"),
            ("port = 3000", "waf.port 3000 is run.port too"),
            ("port = 8080\nmethods = [\"get\"]", "waf.methods: `get`"),
            ("port = 8080\nmethods = []", "waf.methods lists 1 to 16"),
            (
                "port = 8080\nmethods = [\"CONNECT\"]",
                "waf.methods: CONNECT",
            ),
            (
                "port = 8080\nallow_paths = [\"api\"]",
                "waf.allow_paths: `api`",
            ),
            (
                "port = 8080\ndeny_paths = [\"/a/*/b\"]",
                "waf.deny_paths: `/a/*/b`",
            ),
            (
                "port = 8080\nmax_body_bytes = 67108865",
                "waf.max_body_bytes is 67108865; it is 0 to 67108864",
            ),
            (
                "port = 8080\nmax_header_bytes = 10",
                "waf.max_header_bytes is 10; it is 1024 to 65536",
            ),
            (
                "port = 8080\nrate = { per_second = 0, burst = 5 }",
                "waf.rate.per_second is 0",
            ),
            (
                "port = 8080\nrate = { per_second = 9, burst = 5 }",
                "waf.rate.burst is 5; it is 9 to 100000",
            ),
            (
                "port = 8080\nmax_connections_per_address = 0",
                "waf.max_connections_per_address is 0",
            ),
            (
                "port = 8080\nban = { after = 0, window_secs = 60, for_secs = 600 }",
                "waf.ban.after is 0",
            ),
            (
                "port = 8080\nban = { after = 5, window_secs = 0, for_secs = 600 }",
                "waf.ban.window_secs is 0",
            ),
            (
                "port = 8080\nban = { after = 5, window_secs = 60, for_secs = 2592001 }",
                "waf.ban.for_secs is 2592001",
            ),
            (
                "port = 8080\nheader_timeout_secs = 0",
                "waf.header_timeout_secs is 0",
            ),
            (
                "port = 8080\nbody_timeout_secs = 0",
                "waf.body_timeout_secs is 0; it is 1 to 600",
            ),
            (
                "port = 8080\nupstream_timeout_secs = 601",
                "waf.upstream_timeout_secs is 601",
            ),
            (
                "port = 8080\nnew_connections = { per_second = 0, burst = 5 }",
                "waf.new_connections.per_second is 0",
            ),
            (
                "port = 8080\nnew_connections = { per_second = 5, burst = 100001 }",
                "waf.new_connections.burst is 100001",
            ),
        ] {
            let found = problems(&behind_waf(waf, ""));
            assert_eq!(found.len(), 1, "{waf}: {found:#?}");
            assert!(found[0].starts_with(says), "{waf}: {found:#?}");
        }
        // All of them at once, as the rest of the file is reported.
        let found = problems(&behind_waf(
            "port = 80\nmethods = [\"get\"]\nmax_header_bytes = 10\nrate = { per_second = 0, burst = 0 }",
            "",
        ));
        assert_eq!(found.len(), 4, "{found:#?}");
        // The app's own port has to be there, and neither SSH's nor the
        // health check's is the WAF's.
        let no_port = "name = \"bot\"\nchain = \"solana\"\n[waf]\nport = 8080\n";
        assert!(
            problems(no_port)
                .iter()
                .any(|p| p.starts_with("waf needs run.port")),
            "{:?}",
            problems(no_port)
        );
        let ssh = "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n[waf]\nport = 2222\n\
                   [env.prod]\nhost = \"203.0.113.10\"\nssh_port = 2222\n";
        assert!(
            problems(ssh)
                .iter()
                .any(|p| p == "waf.port 2222 is SSH's port")
        );
        let probed = "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n\
                      health = { http = \"http://127.0.0.1:8080/healthz\" }\n[waf]\nport = 8080\n";
        assert!(
            problems(probed)
                .iter()
                .any(|p| p.starts_with("waf.port 8080 is the port run.health.http asks")),
            "{:?}",
            problems(probed)
        );
    }

    #[test]
    fn everyone_may_reach_a_wafs_port_and_nothing_else() {
        let everyone = "\"0.0.0.0/0\", \"::/0\"";
        let m = Manifest::parse(&behind_waf("port = 8080", everyone)).expect("valid");
        let allow = &m.env["prod"].firewall.app_allow;
        assert!(allow.iter().all(crate::net::Cidr::is_everyone) && allow.len() == 2);
        // Not the app's own port, with or without the WAF's table...
        let direct = behind_waf("port = 8080", everyone).replace("[waf]\nport = 8080\n", "");
        let found = problems(&direct);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(found.iter().all(|p| {
            p.starts_with("env.prod.firewall.app_allow: ") && p.contains("behind a WAF")
        }));
        // ...and never SSH.
        let ssh = behind_waf("port = 8080", "").replace("\"198.51.100.7\"", "\"0.0.0.0/0\"");
        let found = problems(&ssh);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].starts_with("env.prod.firewall.ssh_allow: 0.0.0.0/0 allows every"));
    }

    #[test]
    fn a_name_in_both_vars_and_secrets_is_refused() {
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n[vars]\nX_TOKEN = \"a\"\n[secrets]\nX_TOKEN = \"op://{VAULT}/{ITEM}/f\"\n"
        );
        assert!(problems(&text).iter().any(|p| p.contains("both")));
    }

    #[test]
    fn a_data_line_sets_its_endpoint_setting() {
        // Built, not written out: the endpoint gate reads literals.
        let endpoint = ["https", "edge.erpc.global"].join("://");
        let line = format!(
            "lines = [{{ kind = \"grpc\", id = \"7\", endpoint = \"{endpoint}\", hourly = true }}]\n"
        );
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n[run]\nrequires = [\"GRPC_ENDPOINT\"]\n\
             [env.default]\nhost = \"203.0.113.10\"\n{line}"
        );
        let m = Manifest::parse(&text).expect("valid");
        assert_eq!(
            m.missing()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["GRPC_ENDPOINT"]
        );
        assert!(m.missing_besides(&["GRPC_ENDPOINT"]).is_empty());
        // Every environment has the line, so nothing is said to be missing.
        assert!(
            !m.warnings().iter().any(|w| w.contains("GRPC_ENDPOINT")),
            "{:?}",
            m.warnings()
        );
        let env = &m.env["default"];
        let launch = crate::server::Launch::for_app(&m, env).expect("launch");
        assert_eq!(launch.vars["GRPC_ENDPOINT"], endpoint);
        let in_secrets = format!("{text}[secrets]\nGRPC_ENDPOINT = \"op://{VAULT}/{ITEM}/f\"\n");
        assert!(
            problems(&in_secrets)
                .iter()
                .any(|p| p.contains("also in [secrets]"))
        );
    }

    #[test]
    fn a_start_on_record_round_trips_and_is_checked_like_the_rest() {
        use super::{Start, StartOf};
        let key = "0a".repeat(16);
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n[env.default.starting]\n\
             server = {{ key = \"{key}\", family = \"vps\", product = \"prod_Vps1\", region = \"amsterdam\" }}\n\
             grpc = {{ key = \"{key}\", family = \"grpc\", product = \"prod_Grpc1\", ip = \"203.0.113.10\" }}\n"
        );
        let m = Manifest::parse(&text).expect("valid");
        let starting = &m.env["default"].starting;
        assert_eq!(
            starting.keys().copied().collect::<Vec<_>>(),
            [StartOf::Server, StartOf::Grpc]
        );
        let server = &starting[&StartOf::Server];
        assert_eq!(
            server,
            &Start {
                key: key.clone(),
                family: "vps".to_owned(),
                product: "prod_Vps1".to_owned(),
                region: Some("amsterdam".to_owned()),
                ip: None,
            }
        );
        let again = toml::to_string(&m).expect("serialize");
        assert_eq!(Manifest::parse(&again).expect("reparse"), m);
        // The same purchase is the same family, plan, region and address,
        // whatever the key.
        let other_key = Start {
            key: "f".repeat(32),
            ..server.clone()
        };
        assert!(server.same_purchase(&other_key));
        for other in [
            Start {
                product: "prod_Vps2".to_owned(),
                ..server.clone()
            },
            Start {
                region: Some("tokyo".to_owned()),
                ..server.clone()
            },
            Start {
                family: "baremetal".to_owned(),
                ..server.clone()
            },
            Start {
                ip: Some("203.0.113.10".to_owned()),
                ..server.clone()
            },
        ] {
            assert!(!server.same_purchase(&other), "{other:?}");
        }
        // What is being started is one of four things.
        let unknown = text.replace("grpc = {", "storage = {");
        assert!(matches!(
            Manifest::parse(&unknown),
            Err(ManifestError::Syntax(_))
        ));
        // Each field is checked.
        let upper = key.to_uppercase();
        for (from, to) in [
            (key.as_str(), "0a0a"),
            (key.as_str(), upper.as_str()),
            ("family = \"vps\"", "family = \"V P S\""),
            ("prod_Vps1", "prod Vps1"),
            ("amsterdam", "Amster dam"),
            ("203.0.113.10", "203.0.113.999"),
        ] {
            let found = problems(&text.replacen(from, to, 1));
            assert!(
                found.iter().any(|p| p.starts_with("env.default.starting.")),
                "{from} -> {to}: {found:?}"
            );
        }
        // An inventory environment keeps them in its item, with the rest.
        let both = format!(
            "name = \"bot\"\nchain = \"solana\"\n[env.default]\ninventory = {{ vault = \"{VAULT}\" }}\n\
             [env.default.starting]\nserver = {{ key = \"{key}\", family = \"vps\", product = \"prod_Vps1\" }}\n"
        );
        assert!(
            problems(&both)
                .iter()
                .any(|p| p.contains("starting must not also be written here")),
            "{:?}",
            problems(&both)
        );
    }

    #[test]
    fn each_kind_of_line_has_its_own_endpoint_shape() {
        // Built, not written out: the endpoint gate reads literals.
        let url = |scheme: &str, rest: &str| [scheme, rest].join("://");
        assert!(LineKind::Grpc.endpoint_ok(&url("https", "edge.erpc.global")));
        assert!(!LineKind::Grpc.endpoint_ok(&url("http", "203.0.113.5:8899")));
        assert!(LineKind::Unlimited.endpoint_ok(&url("http", "203.0.113.5:8899")));
        assert!(LineKind::Unlimited.endpoint_ok(&url("http", "203.0.113.5:8899/")));
        assert!(!LineKind::Unlimited.endpoint_ok(&url("http", "203.0.113.5")));
        assert!(!LineKind::Unlimited.endpoint_ok(&url("http", "203.0.113.5:0")));
        assert!(!LineKind::Unlimited.endpoint_ok(&url("https", "edge.erpc.global")));
        assert_eq!(LineKind::Unlimited.setting(), "SOLANA_SEND_RPC_ENDPOINT");
    }

    #[test]
    fn plain_settings_that_look_secret_are_warned_about() {
        let text = r#"
name  = "bot"
chain = "solana"
[vars]
API_TOKEN = "x"
SOLANA_RPC_ENDPOINT = "rpc-host/?api-key=abc"
[wallet]
source = "keychain:erpc-worker/bot"
[env.default]
host = "203.0.113.10"
"#;
        let m = Manifest::parse(text).expect("valid");
        let warnings = m.warnings();
        assert_eq!(warnings.len(), 3, "{warnings:#?}");
        // The value that carries a key is told apart, for `check` to say
        // in the language of the run; the name that looks secret is not
        // told twice.
        assert_eq!(
            m.credentials_in_vars(),
            [("SOLANA_RPC_ENDPOINT", Credential::Parameter)]
        );
    }

    /// A credential's shape, joined from parts so that no file holds one
    /// whole: the gates that look for real ones read this file too.
    fn joined(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn a_value_that_carries_a_credential_is_told_by_its_shape() {
        use super::{Credential as C, credential_in};
        let jwt = joined(&[
            "eyJ",
            "hbGciOiJIUzI1NiJ9",
            ".",
            "eyJ",
            "zdWIiOiIxIn0",
            ".",
            "c2ln",
        ]);
        let aws = joined(&["AKIA", "ABCDEFGHIJKLMNOP"]);
        let pem = joined(&["-----BEGIN", " OPENSSH ", "PRIVATE KEY", "-----"]);
        let hook = joined(&["https", "://", "hooks.slack.com", "/services/", "T0/B0/x"]);
        for (value, kind) in [
            // A user, a password or a token before the host of a URL.
            (
                joined(&["https", "://user:hunter2", "@", "rpc-host/"]),
                C::UrlUserinfo,
            ),
            (
                joined(&["postgres", "://admin:pw", "@", "db/app"]),
                C::UrlUserinfo,
            ),
            (
                joined(&["redis", "://tok3n", "@", "cache:6379"]),
                C::UrlUserinfo,
            ),
            (pem, C::PrivateKey),
            // What an Authorization header carries, in any case.
            (joined(&["Bearer ", "abcDEF123456"]), C::Authorization),
            (joined(&["basic ", "dXNlcjpwYXNz"]), C::Authorization),
            (format!("Bearer {jwt}"), C::Authorization),
            (jwt, C::Jwt),
            // Tokens by the shape their service gives them.
            (joined(&["sk_", "live_", "abc123"]), C::Token),
            (joined(&["sk_", "test_", "abc123"]), C::Token),
            (joined(&["rk_", "live_", "abc123"]), C::Token),
            (aws.clone(), C::Token),
            (aws.replace("AKIA", "ASIA"), C::Token),
            (joined(&["ghp", "_", "abc123"]), C::Token),
            (joined(&["gho", "_", "abc123"]), C::Token),
            (joined(&["ghu", "_", "abc123"]), C::Token),
            (joined(&["ghs", "_", "abc123"]), C::Token),
            (joined(&["github", "_pat_", "abc123"]), C::Token),
            (joined(&["xox", "b-", "123-abc"]), C::Token),
            (joined(&["xox", "p-", "123-abc"]), C::Token),
            (hook, C::Token),
            // A parameter named as a key, in a query and out of one.
            ("rpc-host/?api-key=abc".to_owned(), C::Parameter),
            ("rpc-host/?a=1&API_KEY=abc".to_owned(), C::Parameter),
            ("rpc-host/?apikey=abc".to_owned(), C::Parameter),
            ("rpc-host/?key=abc".to_owned(), C::Parameter),
            ("rpc-host/?token=abc".to_owned(), C::Parameter),
            ("rpc-host/?access_token=abc".to_owned(), C::Parameter),
            ("rpc-host/?x-token=abc".to_owned(), C::Parameter),
            ("rpc-host/?secret=abc".to_owned(), C::Parameter),
            ("rpc-host/?Password=abc".to_owned(), C::Parameter),
            ("rpc-host/?X-Amz-Signature=abc".to_owned(), C::Parameter),
            ("host=db user=app password=hunter2".to_owned(), C::Parameter),
            (joined(&["token=", "0123456789abcdef"]), C::Parameter),
            (
                "Server=db;User Id=app;Pwd=hunter2x9".to_owned(),
                C::Parameter,
            ),
            ("rpc-host/?accessToken=abc".to_owned(), C::Parameter),
            ("rpc-host/?x-api-key=abc".to_owned(), C::Parameter),
            (
                joined(&["aws_secret_access_key=", "0123456789abcdef"]),
                C::Parameter,
            ),
        ] {
            assert_eq!(credential_in(&value), Some(kind), "{value}");
        }
    }

    /// The shapes the first list did not have: a token alone before a
    /// host that is a number, the keys of the chain itself, a key in a
    /// URL's path, and more services' tokens. Each is made here, so that
    /// no file holds one.
    #[test]
    fn a_wallets_key_a_key_in_a_path_and_more_tokens_are_told_too() {
        use super::{Credential as C, credential_in};
        let numbers = |n: usize| format!("[{}]", vec!["7"; n].join(", "));
        let words = |n: usize| vec!["abandon"; n].join(" ");
        let token = |n: usize| "a1B2".repeat(n);
        for (value, kind) in [
            (
                joined(&["redis", "://8675309", "@", "cache:6379"]),
                C::UrlUserinfo,
            ),
            // A secret key in base58: 64 bytes are 86 to 88 characters.
            ("Ab3".repeat(29), C::WalletKey),
            (format!("key {} here", "2".repeat(88)), C::WalletKey),
            ("z".repeat(86), C::WalletKey),
            // A keypair file's content, and a recovery phrase's shape.
            (numbers(64), C::WalletKey),
            (words(12), C::Phrase),
            (words(24), C::Phrase),
            // A key in a URL's path.
            (
                format!("{}rpc-host/v2/{}", joined(&["https", "://"]), token(8)),
                C::UrlPath,
            ),
            (
                format!("{}rpc-host/{}/", joined(&["wss", "://"]), "0a".repeat(20)),
                C::UrlPath,
            ),
            // Tokens of more services, and a bot's.
            (joined(&["sk", "-", &token(5)]), C::Token),
            (joined(&["sk", "-proj-", &token(5)]), C::Token),
            (joined(&["glpat", "-", &token(5)]), C::Token),
            (joined(&["AI", "za", &token(8)]), C::Token),
            (joined(&["123456789", ":", &token(9)]), C::Token),
            (
                format!("{}discord.com/api/webhooks/1/x", joined(&["https", "://"])),
                C::Token,
            ),
        ] {
            assert_eq!(credential_in(&value), Some(kind), "{value}");
        }
    }

    /// What the third review found passing that an earlier commit held,
    /// and what the guide said was told and was not: a key as the user
    /// before an empty password, a long run of letters before a host, a
    /// name that ends as a credential's does, and a key in the path of a
    /// URL that stands in a list.
    #[test]
    fn a_name_that_ends_as_a_credentials_does_and_a_key_in_a_list_of_urls_are_told() {
        use super::{Credential as C, credential_in};
        let hex = "0a1b".repeat(10);
        let scheme = joined(&["https", "://"]);
        for value in [
            format!("{scheme}{hex}:@api-host/v1"),
            format!(
                "{scheme}{}@git-host/acme/bot.git",
                "MadeUpOfLettersOnly".repeat(2)
            ),
        ] {
            assert_eq!(credential_in(&value), Some(C::UrlUserinfo), "{value}");
        }
        for name in [
            "dbPassword",
            "sslpassword",
            "trustStorePassword",
            "proxyPassword",
            "appSecret",
            "consumerSecret",
            "jwtSecret",
            "webhookSecret",
            "hmacSignature",
            "botToken",
            "userToken",
            "jwtToken",
            "oauthToken",
            "oauth2Token",
            "service_key",
            "rpc_key",
            "wallet_key",
            "ssh_key",
            "hmac_key",
            "server_key",
            "write_key",
            "account_key",
            "subscription-key",
            "serviceKey",
            "secretkey",
            "myapikey",
        ] {
            let query = format!("stream-host/ws?mode=fast&{name}=abc");
            assert_eq!(credential_in(&query), Some(C::Parameter), "{query}");
            let pair = format!("Server=db;User Id=bot;{name}=hunter2x9");
            assert_eq!(credential_in(&pair), Some(C::Parameter), "{pair}");
        }
        for value in [
            format!("{scheme}rpc-host/v2/{hex},{scheme}api-host"),
            format!("[\"{scheme}rpc-host/v2/{hex}\"]"),
            format!("{scheme}rpc-host/v2/{hex};{scheme}api-host"),
            format!("({scheme}rpc-host/v2/{hex})"),
            format!("{scheme}rpc-host/keys/{hex}.json"),
        ] {
            assert_eq!(credential_in(&value), Some(C::UrlPath), "{value}");
        }
    }

    /// What the fourth review found copied: a password that holds a `/`, a
    /// `?` or a `#` as it is, a name whose word before `key` is an
    /// acronym, a name with a capital inside its ending, a key after a `/`
    /// that is in no URL, and a key in a path that has a comma before it.
    #[test]
    fn a_password_with_a_slash_an_acronym_before_key_and_a_capital_in_an_ending_are_told() {
        use super::{Credential as C, credential_in};
        let scheme = joined(&["postgres", "://"]);
        for password in ["Zk3v#9Qm2Xw7", "Zk3v/9Qm2Xw7", "Zk3v?9Qm2Xw7", "a/b?c#d"] {
            let value = format!("{scheme}app:{password}@db-host:5432/app");
            assert_eq!(credential_in(&value), Some(C::UrlUserinfo), "{value}");
        }
        for name in [
            "RPCKey",
            "AWSKey",
            "SASKey",
            "APIKey",
            "IDToken",
            "passWord",
            "PassWord",
            "passWd",
            "userPassWord",
            "dbpasswd",
            "clientSecret",
        ] {
            let query = format!("stream-host/ws?mode=fast&{name}=abc");
            assert_eq!(credential_in(&query), Some(C::Parameter), "{query}");
            let pair = format!("Server=db;User Id=bot;{name}=hunter2x9");
            assert_eq!(credential_in(&pair), Some(C::Parameter), "{pair}");
        }
        let key = "Ab3".repeat(29);
        for value in [format!("keys/{key}"), format!("./{key}"), format!("/{key}")] {
            assert_eq!(credential_in(&value), Some(C::WalletKey), "{value}");
        }
        let value = format!(
            "{}host/a,b/{}",
            joined(&["https", "://"]),
            "0a1b".repeat(10)
        );
        assert_eq!(credential_in(&value), Some(C::UrlPath), "{value}");
    }

    /// Each number the reading goes by, with a value on each side of it.
    #[test]
    #[allow(clippy::too_many_lines, reason = "one table of edges")]
    fn each_edge_of_the_reading_is_held_on_both_sides() {
        use super::{Credential as C, credential_in};
        let scheme = joined(&["https", "://"]);
        // `n` base58 characters with a letter and a digit among them.
        let base58 = |n: usize| "Ab3".repeat(n / 3 + 1)[..n].to_owned();
        let told = |value: String| credential_in(&value);

        // A user's name before a host: under 16 letters.
        assert_eq!(told(format!("{scheme}{}@host/x", "a".repeat(15))), None);
        assert_eq!(
            told(format!("{scheme}{}@host/x", "a".repeat(16))),
            Some(C::UrlUserinfo)
        );
        // An `@` after a host and its port is no password's end; after
        // something that is no port, it is.
        assert_eq!(told(format!("{scheme}host:8080/a@b")), None);
        assert_eq!(told(format!("{scheme}host:65535/a@b")), None);
        assert_eq!(
            told(format!("{scheme}host:8080x/a@b")),
            Some(C::UrlUserinfo)
        );
        assert_eq!(told(format!("{scheme}[::1]:8080/a@b")), None);

        // A part of a path: 32 characters and more.
        let part = |n: usize| "a1".repeat(n / 2 + 1)[..n].to_owned();
        assert_eq!(told(format!("{scheme}host/v2/{}", part(31))), None);
        assert_eq!(
            told(format!("{scheme}host/v2/{}", part(32))),
            Some(C::UrlPath)
        );
        // It needs a letter and a digit.
        assert_eq!(told(format!("{scheme}host/v2/{}", "a".repeat(40))), None);
        assert_eq!(told(format!("{scheme}host/v2/{}", "1".repeat(40))), None);
        // An address is 43 or 44 base58 characters, a signature 86 to 88:
        // left alone in a path, and only at those lengths.
        for (n, kind) in [
            (42, Some(C::UrlPath)),
            (43, None),
            (44, None),
            (45, Some(C::UrlPath)),
            (85, Some(C::UrlPath)),
            (86, None),
            (87, None),
            (88, None),
            (89, Some(C::UrlPath)),
        ] {
            assert_eq!(told(format!("{scheme}host/x/{}", base58(n))), kind, "{n}");
        }
        // Not in base58 (a `0`), the same lengths are a key's.
        for n in [43, 44, 86, 88] {
            let part = format!("0{}", base58(n - 1));
            assert_eq!(
                told(format!("{scheme}host/x/{part}")),
                Some(C::UrlPath),
                "{n}"
            );
        }
        // Hexadecimal after `0x` is left alone; anything else after it is
        // not.
        for digits in [40, 64] {
            assert_eq!(
                told(format!("{scheme}host/x/0x{}", "0a".repeat(digits / 2))),
                None
            );
            assert_eq!(
                told(format!("{scheme}host/x/0x{}g", "0a".repeat(digits / 2))),
                Some(C::UrlPath)
            );
        }
        // What ends a part: each of these after a key leaves the key.
        for end in [",", ";", "\"", "'", ")", "]", "}", ">", "|", ".json", "/"] {
            assert_eq!(
                told(format!("{scheme}host/v2/{}{end}rest", part(40))),
                Some(C::UrlPath),
                "{end}"
            );
        }
        // And what does not: the part is then longer, and no key's shape.
        assert_eq!(told(format!("{scheme}host/v2/{}~rest", part(40))), None);

        // A wallet's key alone: 86 to 88 base58 characters.
        for (n, kind) in [
            (85, None),
            (86, Some(C::WalletKey)),
            (87, Some(C::WalletKey)),
            (88, Some(C::WalletKey)),
            (89, None),
        ] {
            assert_eq!(told(base58(n)), kind, "{n}");
        }
        // A keypair's numbers: 64 of them, each up to 255.
        let numbers = |n: usize, each: &str| format!("[{}]", vec![each; n].join(","));
        assert_eq!(told(numbers(63, "255")), None);
        assert_eq!(told(numbers(64, "255")), Some(C::WalletKey));
        assert_eq!(told(numbers(64, "256")), None);
        assert_eq!(told(numbers(65, "255")), None);

        // A phrase: 12, 15, 18, 21 or 24 words of 3 to 8 letters.
        for count in 11..=25 {
            let phrase = vec!["abandon"; count].join(" ");
            let kind = matches!(count, 12 | 15 | 18 | 21 | 24).then_some(C::Phrase);
            assert_eq!(told(phrase), kind, "{count}");
        }
        for (word, kind) in [
            ("ab", None),
            ("abc", Some(C::Phrase)),
            ("abcdefgh", Some(C::Phrase)),
            ("abcdefghi", None),
            ("Abandon", None),
            ("aband0n", None),
        ] {
            assert_eq!(told([word; 12].join(" ")), kind, "{word}");
        }
    }

    /// What the fifth review found: a space that is two or three bytes
    /// wide, before a URL whose path ends in a key's shape, was stepped
    /// over as if it were one byte, and the reading panicked.
    #[test]
    fn a_wide_space_before_a_signature_in_a_path_is_read_like_any_space() {
        use super::{Credential as C, credential_in};
        let scheme = joined(&["https", "://"]);
        let signature = "Ab3".repeat(29);
        for space in [" ", "\u{a0}", "\u{2028}", "\u{3000}", "\t"] {
            // In an explorer's address: a transaction, left alone.
            let noted = format!("最後の取引{space}{scheme}explorer/tx/{signature}");
            assert_eq!(credential_in(&noted), None, "{noted}");
            // After the space, in no URL: a key.
            let bare = format!("{scheme}explorer/tx{space}keys/{signature}");
            assert_eq!(credential_in(&bare), Some(C::WalletKey), "{bare}");
        }
        // Only the entry the run stands in counts: a URL earlier in a
        // list does not make a later path an explorer's.
        for end in [",", ";", " ", "\""] {
            let listed = format!("{scheme}explorer/x{end}keys/{signature}");
            assert_eq!(credential_in(&listed), Some(C::WalletKey), "{listed}");
        }
        // And only right after a `/`: elsewhere in a URL it is a key.
        let given = format!("{scheme}explorer/tx?sig={signature}");
        assert_eq!(credential_in(&given), Some(C::WalletKey), "{given}");
    }

    /// The reading meets whatever text an example file holds. This runs it
    /// over text made from the pieces it parts at, with characters of
    /// every width among them, and asks only that it answers.
    #[test]
    fn the_reading_answers_for_any_text() {
        use super::{credential_in, names_credential};
        // Among them İ and ẞ, whose lowercase is not as long as they are:
        // an index taken in lowered text would not fit the text itself.
        let pieces: [&str; 48] = [
            "\u{130}", "\u{1e9e}", "{", "}", "://", "/", "?", "#", "@", ":", "=", "&", ",", ";",
            " ", "\u{a0}", "\u{2028}", "\u{3000}", "é", "日本", "🔑", "eyJ", ".", "-", "_", "[",
            "]", "0x", "Bearer ", "Basic ", "sk-", "AKIA", "glpat-", "AIza", "password", "token",
            "Key", "host", "8080", "12345678", "\n", "\t", "\"", "'", "a1B2", "7", ")", "|",
        ];
        let runs = ["Ab3".repeat(14), "Ab3".repeat(29), "0a".repeat(20)];
        // A small generator of its own: the same text on every run.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move |below: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % 1_000_003).expect("small") % below
        };
        for _ in 0..40_000 {
            let mut text = String::new();
            for _ in 0..=next(24) {
                match next(pieces.len() + runs.len()) {
                    piece if piece < pieces.len() => text.push_str(pieces[piece]),
                    run => text.push_str(&runs[run - pieces.len()]),
                }
            }
            // Answered, whatever the answer.
            let _ = credential_in(&text);
            let _ = names_credential(&text);
        }
    }

    /// The fifth review's other cases: a password that is a plain word, a
    /// list of addresses with ports, and names the last change stopped
    /// holding (a separator or a number after the ending, capitals where
    /// no word starts).
    #[test]
    fn a_plain_password_a_list_of_hosts_and_names_with_odd_capitals_are_read_right() {
        use super::{Credential as C, credential_in};
        // A password's value is one whatever it looks like.
        for pair in [
            "password=swordfish",
            "Password=20240131",
            "Pwd=correcthorse",
            "dbPassWord=a",
        ] {
            let value = format!("Server=db;User Id=bot;{pair}");
            assert_eq!(credential_in(&value), Some(C::Parameter), "{value}");
        }
        // A key's or a token's, outside a query, is one when it is more
        // than a plain word or number: 16 characters, or mixed.
        for (given, kind) in [
            ("letmein".to_owned(), None),
            ("a".repeat(15), None),
            ("a".repeat(16), Some(C::Parameter)),
            ("1".repeat(15), None),
            ("1".repeat(16), Some(C::Parameter)),
            ("letme1n".to_owned(), Some(C::Parameter)),
        ] {
            for name in ["accessToken", "api_key", "client_secret"] {
                let value = format!("Server=db;{name}={given}");
                assert_eq!(credential_in(&value), kind, "{value}");
            }
        }
        // A list of addresses, each with its port, has no password in it.
        for value in [
            joined(&["amqp", "://mq1:5672,", "amqp", "://guest", "@", "mq2:5672"]),
            joined(&["http", "://n1:8899,", "http", "://n2/", "@", "scope/pkg"]),
            joined(&["http", "://n1:8899;", "http", "://n2/", "@", "scope"]),
        ] {
            assert_eq!(credential_in(&value), None, "{value}");
        }
        // A port is at most five digits; a password may hold a comma.
        let scheme = joined(&["postgres", "://"]);
        for (authority, kind) in [
            ("host:65535/a@b", None),
            ("host:123456/a@b", Some(C::UrlUserinfo)),
            ("app:a,b/c@db/app", Some(C::UrlUserinfo)),
            ("-app@db", Some(C::UrlUserinfo)),
            ("_app@db", Some(C::UrlUserinfo)),
            (".app@db", Some(C::UrlUserinfo)),
        ] {
            let value = format!("{scheme}{authority}");
            assert_eq!(credential_in(&value), kind, "{value}");
        }
        // Names: what follows the last word is not part of it, and
        // capitals that start no word do not hide one.
        for name in [
            "client_secret_",
            "pwd-",
            "password.",
            "password2",
            "api_key_1",
            "apiKey2",
            "TOken",
            "TOKen",
            "TOKEn",
            "KEy",
            "x_TOKen",
            "api_KEy",
            "SECRETkey",
            "ACCESSkey",
            "PASSkey",
            "s3Key",
        ] {
            let query = format!("stream-host/ws?mode=fast&{name}=abc");
            assert_eq!(credential_in(&query), Some(C::Parameter), "{query}");
        }
        // The words that are no credential stay so, read any of the ways.
        for name in ["myInputToken", "sort_key2", "inputtoken", "my_input_token"] {
            let query = format!("stream-host/ws?mode=fast&{name}=abc");
            assert_eq!(credential_in(&query), None, "{query}");
        }
    }

    /// What the sixth review found copied: a password given in quotes or
    /// with spaces about its `=`, as database clients write it, and names
    /// with capitals that start no word after an owner.
    #[test]
    fn a_quoted_password_and_capitals_after_an_owner_are_told() {
        use super::{Credential as C, credential_in};
        for value in [
            "host=db user=app password='Tr0ub4dor9xZ' sslmode=require",
            "username=\"app\" password=\"Tr0ub4dor9xZ\";",
            "Server=db;Password=\"Tr0ub4dor9;xZ\";",
            "Server=db;Password = Tr0ub4dor9xZ;",
            "Server=db;Password\t=\t'swordfish'",
            "Server=db;Pwd={Tr0ub4dor9xZ};",
            "Server=db;accessToken=\"Tr0ub4dor9xZ\"",
            // A plain word under each password's name, and after a number.
            "Server=db;passwd=swordfish",
            "Server=db;password2=swordfish",
            "Server=db;db_pwd_1=20240131",
        ] {
            assert_eq!(credential_in(value), Some(C::Parameter), "{value}");
        }
        // A key's or a token's plain word stays one in quotes.
        for value in ["Server=db;key=\"value\"", "Server=db;token = 'true'"] {
            assert_eq!(credential_in(value), None, "{value}");
        }
        // Braces are not passed over for any name: with them, what is
        // given is more than a plain word.
        for value in [
            "Server=db;accessToken={#Tr0ub4dor9xZ}",
            "Server=db;Pwd={}",
            "Server=db;key={value}",
        ] {
            assert_eq!(credential_in(value), Some(C::Parameter), "{value}");
        }
        // In quotes, a key's or a token's value is what stands between
        // them, whatever it holds.
        for (value, kind) in [
            (
                "Server=db;accessToken=\"#Tr0ub4dor9 xZ\"",
                Some(C::Parameter),
            ),
            ("Server=db;accessToken='two words'", Some(C::Parameter)),
            ("Server=db;accessToken='oneword'", None),
            ("Server=db;accessToken=''", None),
        ] {
            assert_eq!(credential_in(value), kind, "{value}");
        }
        // Capitals that start no word, after an owner written in one with
        // it; an acronym before a word that is no credential's is held
        // too, by the way of parting that does not know acronyms.
        for name in [
            "myTOKen",
            "userKEy",
            "mySECRETkey",
            "usertoken",
            "DBSortKey",
            "APIPublicKey",
            "AWSInputToken",
        ] {
            let query = format!("stream-host/ws?mode=fast&{name}=abc");
            assert_eq!(credential_in(&query), Some(C::Parameter), "{query}");
        }
        // A password that starts with what ends an entry of a list, and
        // holds a `/`: no port stands before it, so it is one. With a port
        // there, it is the next entry of a list.
        let db = joined(&["postgres", "://"]);
        for first in [",", ";", "\"", "'", ")", "]", "}", ">", "|"] {
            let value = format!("{db}app:{first}ecr3t/pw@db-host/app");
            assert_eq!(credential_in(&value), Some(C::UrlUserinfo), "{value}");
            let listed = format!("{db}db-host:5432{first}ecr3t/pw@db-host/app");
            assert_eq!(credential_in(&listed), None, "{listed}");
        }
        // Nothing after the colon is still a port left out.
        let value = format!("{db}db-host:/app@x");
        assert_eq!(credential_in(&value), None, "{value}");
        // A placeholder for a port is a port: no password before the `@`
        // of a path. Other text after a `$` is no placeholder: what the
        // seventh review found, a password that starts with one.
        let scheme = joined(&["http", "://"]);
        for (port, kind) in [
            ("${PORT}", None),
            ("${PORT:-8080}", None),
            ("$PORT", None),
            ("$API_PORT_2", None),
            ("8080", None),
            ("$ecr3t", Some(C::UrlUserinfo)),
            ("$", Some(C::UrlUserinfo)),
            ("${}", Some(C::UrlUserinfo)),
            ("${PORT}x", Some(C::UrlUserinfo)),
            ("$Port", Some(C::UrlUserinfo)),
        ] {
            let value = format!("{scheme}localhost:{port}/x@y");
            assert_eq!(credential_in(&value), kind, "{value}");
        }
        // A placeholder before what ends an entry of a list is that
        // entry's port, as digits there are.
        for end in [",", ";", "\"", "'", ")", "]", "}", ">", "|"] {
            let value = format!("{scheme}localhost:${{PORT}}{end}{scheme}other:${{PORT}}/x@y");
            assert_eq!(credential_in(&value), None, "{value}");
            let value = format!("{scheme}localhost:$PORT{end}{scheme}other:$PORT/x@y");
            assert_eq!(credential_in(&value), None, "{value}");
        }
    }

    /// A password's parameter, by what follows its `=`: the guide's
    /// sentence on it says what this table and the next test's say, cell
    /// for cell. It is one whatever it starts with, written bare, in
    /// either quote or in braces. The eighth review found a bare one that
    /// starts with `;` or `&`, and a quoted one that starts with its own
    /// quote, read as nothing given.
    #[test]
    fn a_password_is_one_by_any_first_character_bare_quoted_or_in_braces() {
        use super::{Credential as C, credential_in};
        // Every printable ASCII character and some wider ones, first.
        let wide = ['é', '日', '\u{3000}', '\u{a0}', '🔑', '\u{2028}'];
        // Where a password stands: after spaces, after `;`, alone, as a
        // command's option, on a line of an option file; last in the text
        // and with a parameter after it.
        let frames = [
            ("host=db user=app ", ""),
            ("host=db user=app ", " sslmode=require"),
            ("Server=db;User Id=app;", ";"),
            ("Server=db;User Id=app;", ";Database=app;"),
            ("", ""),
            ("--user=app --", ""),
            ("[client]\nuser=app\n", "\n"),
        ];
        for first in (' '..='~').chain(wide) {
            for (head, tail) in frames {
                for name in ["password", "Pwd", "PASSWD"] {
                    for equals in ["=", " = "] {
                        for (open, close) in [("", ""), ("'", "'"), ("\"", "\""), ("{", "}")] {
                            let value = format!(
                                "{head}{name}{equals}{open}{first}Tr0ub4dor9xZ{close}{tail}"
                            );
                            assert_eq!(credential_in(&value), Some(C::Parameter), "{value}");
                        }
                    }
                }
            }
        }
        // The same in a URL's query, but for an `&` first: there it is
        // the next parameter, written bare or after quotes that close.
        for first in (' '..='~').filter(|first| *first != '&') {
            for (open, close) in [("", ""), ("'", "'"), ("\"", "\"")] {
                for head in ["db-host/app?password=", "db-host/app?user=app&pwd="] {
                    let value = format!("{head}{open}{first}Tr0ub4dor9xZ{close}&ssl=true");
                    assert_eq!(credential_in(&value), Some(C::Parameter), "{value}");
                }
            }
        }
        // A quote written twice inside its own quotes, as one format
        // writes a quote there, and a backslash before it, as another.
        for value in [
            "Server=db;User Id=app;Password=\"\"\"Tr0ub4'dor9xZ\";",
            "Server=db;User Id=app;Password='''Tr0ub4\"dor9xZ';",
            "host=db user=app password='\\'Tr0ub4dor9xZ'",
            "host=db user=app password=\"\\\"Tr0ub4dor9xZ\"",
        ] {
            assert_eq!(credential_in(value), Some(C::Parameter), "{value}");
        }
    }

    /// A password's parameter is none only where its value ends with an
    /// empty form or, in a URL's query, an `&` follows at once: the other
    /// half of the guide's sentence.
    #[test]
    fn a_password_is_none_only_where_its_value_ends_with_an_empty_form() {
        use super::{Credential as C, credential_in};
        // Nothing given: the value ends at the `=`, after spaces, after
        // one `;`, or after quotes that close as they open.
        for nothing in [
            "",
            " ",
            "\t",
            "\u{3000}",
            ";",
            "; ",
            " ;",
            "\u{3000};\n",
            "''",
            "\"\"",
            "'';",
            "\"\" ; ",
            " ''",
            // Any white space, before the quotes, between them and the
            // `;`, and after it.
            "\t''",
            "\u{3000}\"\"",
            "''\t;",
            "\"\"\u{3000};\u{a0}",
            ";\u{3000}",
        ] {
            for head in ["Server=db;Password", "host=db user=app password", "pwd"] {
                for equals in ["=", " = "] {
                    let value = format!("{head}{equals}{nothing}");
                    assert_eq!(credential_in(&value), None, "{value:?}");
                }
            }
        }
        // The empty forms, each way they can be put together: spaces,
        // quotes that close at once, one closing `;`, in that order, each
        // there or not, and then the end. One more character after any of
        // them is something given.
        for quotes in ["", "''", "\"\""] {
            for semicolon in ["", ";"] {
                for (a, b, c) in [("", "", ""), (" ", "", ""), ("", " ", ""), ("", "", "\t")] {
                    let form = format!("{a}{quotes}{b}{semicolon}{c}");
                    let value = format!("host=db user=app password={form}");
                    assert_eq!(credential_in(&value), None, "{value:?}");
                    for more in ["&", ",", "#", "x", "'", "\"", "=", "{", "}", "é"] {
                        let value = format!("host=db user=app password={form}{more}");
                        assert_eq!(credential_in(&value), Some(C::Parameter), "{value:?}");
                    }
                    if !semicolon.is_empty() {
                        let value = format!("host=db user=app password={form};");
                        assert_eq!(credential_in(&value), Some(C::Parameter), "{value:?}");
                    }
                    // In a query an `&` stands where the `;` would.
                    if semicolon.is_empty() {
                        let value = format!("db-host/app?user=app&password={form}&Tr0ub4dor9xZ");
                        assert_eq!(credential_in(&value), None, "{value:?}");
                    }
                }
            }
        }
        // The same forms with anything after them are held: a `;` and an
        // `&` part parameters in some formats only, and what follows may
        // as well be the password's own text. An empty password before
        // another parameter is held with them.
        for held in [
            "Server=db;Password=;Database=app",
            "Server=db;Password=; Database=app",
            "Server=db;Password=;;",
            "Server=db;Password=\"\";Database=app",
            "Server=db;Password='' Database=app",
            "host=db user=app password= dbname=app",
            "host=db user=app password='' dbname=app",
            "host=db user=app password=&",
            "host=db user=app password=''&",
            "host=db user=app password='',",
            "host=db user=app password=''#",
            "host=db user=app password=''x",
            "host=db user=app password=' '",
            "host=db user=app password='\"",
            "Server=db;Pwd={}",
            // The quotes come before the `;`, not after it.
            "host=db user=app password=;''",
            "Server=db;Password=;\"\"",
            // Quotes close at once one time: a second pair is something.
            "host=db user=app password=''''",
            "host=db user=app password=''\"\"",
            "Server=db;Password=\"\"\"\";",
            // In a query a `;` at once is no empty form unless the value
            // ends after it: an `&` after it does not make it one.
            "db-host/app?user=app&password=;&ssl=true",
            "db-host/app?user=app&password='';&ssl=true",
        ] {
            assert_eq!(credential_in(held), Some(C::Parameter), "{held}");
        }
        // In a URL's query, a name after `?` or `&`: an `&` at once is the
        // next parameter, bare or after quotes that close.
        for nothing in [
            "db-host/app?password=&ssl=true",
            "db-host/app?user=app&password=&ssl=true",
            "db-host/app?user=app&password=&",
            "db-host/app?user=app&password= &ssl=true",
            "db-host/app?user=app&password=''&ssl=true",
            "db-host/app?user=app&password=\"\"&ssl=true",
            "db-host/app?user=app&password=",
            "db-host/app?user=app&password=;",
            "user=app&password=&ssl=true",
        ] {
            assert_eq!(credential_in(nothing), None, "{nothing}");
        }
        // The first parameter of a text that has no `?` is not in a query.
        let value = "password=&user=app";
        assert_eq!(credential_in(value), Some(C::Parameter), "{value}");
    }

    /// What a key's, a token's or a secret's parameter is given, where it
    /// starts and where it ends: the reading of [`super::given`], each
    /// edge on both sides.
    #[test]
    fn what_a_keys_parameter_is_given_starts_after_spaces_and_ends_at_a_separator() {
        use super::{Credential as C, credential_in};
        // Spaces and a tab after the `=` are not what is given. (The text
        // is put together here so that no scanner takes it for a key.)
        let given = "a1B2".repeat(4);
        for value in [
            format!("Server=db;accessToken = {given}"),
            format!("Server=db;accessToken=\t{given}"),
            format!("Server=db;api_key =  '{given}'"),
        ] {
            assert_eq!(credential_in(&value), Some(C::Parameter), "{value}");
        }
        for value in ["Server=db;accessToken = ", "Server=db;accessToken=\t;"] {
            assert_eq!(credential_in(value), None, "{value}");
        }
        // A bare value ends at each of these, so a plain word before one
        // stays a plain word.
        for end in ["&", ";", ",", "#", "\"", "'", " ", "\t", "\n", "\u{3000}"] {
            let value = format!("Server=db;token=true{end}next-part-of-the-text");
            assert_eq!(credential_in(&value), None, "{value:?}");
            let value = format!("Server=db;key=12345{end}6789012345678901");
            assert_eq!(credential_in(&value), None, "{value:?}");
        }
        // Any other character does not end it.
        for inside in ["-", ".", "/", ":", "+", "=", "@", "é"] {
            let value = format!("Server=db;token=true{inside}next");
            assert_eq!(credential_in(&value), Some(C::Parameter), "{value}");
        }
        // In quotes it ends at the same quote only: the other one is part
        // of it.
        for (value, kind) in [
            ("Server=db;api_key=\"abc'def\"", Some(C::Parameter)),
            ("Server=db;api_key='abc\"def'", Some(C::Parameter)),
            ("Server=db;api_key=\"abc\"'def'", None),
            ("Server=db;api_key='abc'\"def\"", None),
        ] {
            assert_eq!(credential_in(value), kind, "{value}");
        }
    }

    /// The lengths the services' own shapes go by, each on both sides.
    #[test]
    fn each_services_shape_is_held_at_its_length_and_not_under_it() {
        use super::{Credential as C, credential_in};
        let mixed = |n: usize| "a1B2".repeat(n / 4 + 1)[..n].to_owned();
        let told = |value: String| credential_in(&value);
        // After `Bearer`: 8 characters and more.
        assert_eq!(told(format!("Bearer {}", mixed(7))), None);
        assert_eq!(told(format!("Bearer {}", mixed(8))), Some(C::Authorization));
        // A JSON Web Token's head is more than `eyJ` itself.
        assert_eq!(told(joined(&["eyJ", ".", "eyJx", ".", "c2ln"])), None);
        assert_eq!(
            told(joined(&["eyJh", ".", "eyJx", ".", "c2ln"])),
            Some(C::Jwt)
        );
        // `sk-` and `glpat-` before 20 token characters, `AIza` before 30.
        for (prefix, least) in [(joined(&["sk", "-"]), 20), (joined(&["glpat", "-"]), 20)] {
            assert_eq!(
                told(format!("{prefix}{}", mixed(least - 1))),
                None,
                "{prefix}"
            );
            assert_eq!(
                told(format!("{prefix}{}", mixed(least))),
                Some(C::Token),
                "{prefix}"
            );
        }
        let google = joined(&["AI", "za"]);
        assert_eq!(told(format!("{google}{}", mixed(29))), None);
        assert_eq!(told(format!("{google}{}", mixed(30))), Some(C::Token));
        // An AWS access key id: 16 capitals or digits after its prefix.
        let aws = joined(&["AK", "IA"]);
        assert_eq!(
            told(format!("{aws}{}", "A1".repeat(8)[..15].to_owned())),
            None
        );
        assert_eq!(told(format!("{aws}{}", "A1".repeat(8))), Some(C::Token));
        // A Telegram bot's token: 8 to 12 digits, a colon, 30 characters.
        for (digits, kind) in [
            (7, None),
            (8, Some(C::Token)),
            (12, Some(C::Token)),
            (13, None),
        ] {
            let value = format!("{}:{}", "7".repeat(digits), mixed(30));
            assert_eq!(told(value), kind, "{digits}");
        }
        assert_eq!(told(format!("{}:{}", "7".repeat(9), mixed(29))), None);
    }

    /// A token to trade and a key to sort by are named as a credential is,
    /// and are none; nor is what a URL names more often than a key.
    #[test]
    fn a_token_to_trade_a_key_to_sort_by_and_a_hash_in_a_path_are_left_alone() {
        use super::credential_in;
        let scheme = joined(&["https", "://"]);
        for value in [
            "stream-host/ws?vsToken=abc".to_owned(),
            "stream-host/ws?pageToken=abc".to_owned(),
            "stream-host/ws?quote_token=abc".to_owned(),
            "stream-host/ws?outputtoken=abc".to_owned(),
            "stream-host/ws?sort_key=abc".to_owned(),
            "stream-host/ws?partitionKey=abc".to_owned(),
            "stream-host/ws?hotkey=abc".to_owned(),
            // A transaction's signature, and another chain's address and
            // hash, as explorers' URLs name them.
            format!("{scheme}explorer/tx/{}", "Ab3".repeat(29)),
            format!("{scheme}explorer/token/0x{}", "0a".repeat(20)),
            format!("{scheme}explorer/tx/0x{}", "0a".repeat(32)),
        ] {
            assert_eq!(credential_in(&value), None, "{value}");
        }
    }

    /// `check` warns before every deploy, so only of what is seldom
    /// anything but a credential. A long part of a path and a list of
    /// words are held back by `import` and passed over by `check`.
    #[test]
    fn check_warns_only_of_the_kinds_that_are_seldom_anything_else() {
        use super::Credential as C;
        for kind in [
            C::UrlUserinfo,
            C::PrivateKey,
            C::Authorization,
            C::Jwt,
            C::Token,
            C::Parameter,
            C::WalletKey,
        ] {
            assert!(kind.sure(), "{kind:?}");
        }
        assert!(!C::Phrase.sure() && !C::UrlPath.sure());
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n[vars]\n\
             RPC = \"{}rpc-host/v2/{}\"\nWATCH = \"{}\"\nSIGNER = \"{}\"\n",
            joined(&["https", "://"]),
            "0a1b".repeat(10),
            ["abandon"; 12].join(" "),
            "Ab3".repeat(29),
        );
        let m = Manifest::parse(&text).expect("valid");
        assert_eq!(m.credentials_in_vars(), [("SIGNER", C::WalletKey)]);
    }

    /// What was taken for a credential and is none: a user's name before a
    /// host, a word after `Basic`, a name that only ends like a key's, an
    /// address, and what falls short of a key's shape.
    #[test]
    fn names_words_and_addresses_are_not_taken_for_credentials() {
        use super::credential_in;
        let address = "So11111111111111111111111111111111111111112";
        let numbers = |n: usize| format!("[{}]", vec!["7"; n].join(", "));
        let words = |n: usize| vec!["abandon"; n].join(" ");
        for value in [
            joined(&["ssh", "://deploy-bot", "@", "host"]),
            joined(&["postgres", "://app_user", "@", "localhost/app"]),
            joined(&["postgres", "://app:", "@", "localhost/app"]),
            "Basic Calculator".to_owned(),
            "Bearer Authentication".to_owned(),
            "sort_key=created_at".to_owned(),
            "rpc-host/?sort_key=created_at".to_owned(),
            "cache.key=per_user_v2".to_owned(),
            "public_key=0123456789abcdef".to_owned(),
            format!("rpc-host/?inputToken={address}"),
            // An address, alone and in a URL's path; a path of words.
            address.to_owned(),
            format!("{}explorer/address/{address}", joined(&["https", "://"])),
            format!("{}host/{}", joined(&["https", "://"]), "a".repeat(40)),
            format!("{}host/{}", joined(&["https", "://"]), "a1".repeat(15)),
            // Short of a key: 85 and 89 characters, 63 and 65 numbers, a
            // number past 255, 11 words, a word of two letters.
            "Ab3".repeat(28) + "A",
            "2".repeat(89),
            numbers(63),
            numbers(65),
            numbers(63).replace(']', ", 256]"),
            "[1, 2, 3]".to_owned(),
            words(11),
            words(11) + " an",
            "the quick brown fox jumps over the lazy dog and runs Away".to_owned(),
            // A hash, or another chain's address: not told from a key.
            format!("0x{}", "0f".repeat(32)),
            // Words that start like a token, and a host with its port.
            "sk-learn".to_owned(),
            "AIzaShort".to_owned(),
            "host:8080".to_owned(),
            joined(&["1234567", ":", &"a1B2".repeat(9)]),
        ] {
            assert_eq!(credential_in(&value), None, "{value}");
        }
    }

    #[test]
    fn a_value_that_only_looks_like_a_credential_is_left_alone() {
        use super::credential_in;
        let cert = joined(&["-----BEGIN", " CERTIFICATE", "-----"]);
        for value in [
            // A URL without a user, with an @ past its host, and an address.
            joined(&["https", "://rpc-host/v1?commitment=processed"]),
            joined(&["https", "://rpc-host/@handle?to=ops@team"]),
            joined(&["redis", "://127.0.0.1:6379/"]),
            "ops@team".to_owned(),
            // A user's name before the host, with no password.
            joined(&["ssh", "://git", "@", "forge/team/app.git"]),
            joined(&["sftp", "://deploy", "@", "files"]),
            joined(&["https", "://", "@", "rpc-host/"]),
            // key=value settings whose value is a word or a number.
            "key=value".to_owned(),
            "token=true".to_owned(),
            "secret=no,key=1".to_owned(),
            "sort_key=name".to_owned(),
            "rpc-host/?api-key=".to_owned(),
            // Not a key's name, though it ends like one.
            joined(&["monkey=", "0123456789abcdef"]),
            // The words alone, and before a word.
            "Bearer".to_owned(),
            "Basic".to_owned(),
            "Bearer token".to_owned(),
            "Basic settings".to_owned(),
            "Basic realm=example".to_owned(),
            // A prefix alone, in the middle of a word, or cut short.
            joined(&["sk_", "live_"]),
            joined(&["desk_", "test_", "mode"]),
            joined(&["AKIA", "ABC"]),
            joined(&["xox", "b"]),
            "eyJ".to_owned(),
            "eyJhbGci.only-two".to_owned(),
            cert,
            "info".to_owned(),
            "8080".to_owned(),
            String::new(),
        ] {
            assert_eq!(credential_in(&value), None, "{value}");
        }
    }

    #[test]
    fn an_environment_can_keep_its_server_in_1password() {
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n\
             [wallet]\nsource = \"op://{VAULT}/{ITEM}/keypair\"\n\
             pubkey = \"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"\n\
             [env.prod]\ninventory = {{ vault = \"{VAULT}\" }}\n"
        );
        let m = Manifest::parse(&text).expect("valid");
        let env = m.env("prod").expect("env");
        assert_eq!(env.inventory.as_ref().expect("inventory").vault, VAULT);
        assert!(env.host.is_none());
        assert!(m.warnings().is_empty(), "{:?}", m.warnings());
        let text = toml::to_string(&m).expect("serialize");
        assert_eq!(Manifest::parse(&text).expect("reparse"), m);
    }

    #[test]
    fn server_facts_are_written_in_one_place_only() {
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n\
             [env.prod]\ninventory = {{ vault = \"{VAULT}\" }}\nhost = \"203.0.113.10\"\nssh_port = 2222\n\
             [env.prod.firewall]\nssh_allow = [\"198.51.100.7\"]\n"
        );
        let found = problems(&text);
        assert!(
            found
                .iter()
                .any(|p| p.contains("host, ssh_port, firewall must not also be written here")),
            "{found:#?}"
        );
        let text =
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\ninventory = { vault = \"Private\" }\n";
        assert!(problems(text).iter().any(|p| p.contains("inventory.vault")));
    }

    #[test]
    fn a_keychain_key_is_warned_about_when_servers_are_in_1password() {
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n\
             [secrets]\nX_TOKEN = \"keychain:erpc-worker/bot-x-token\"\n\
             [wallet]\nsource = \"keychain:erpc-worker/bot\"\n\
             pubkey = \"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"\n\
             [env.prod]\ninventory = {{ vault = \"{VAULT}\" }}\n"
        );
        let warnings = Manifest::parse(&text).expect("valid").warnings();
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(warnings.iter().all(|w| w.contains("only this machine has")));
    }

    #[test]
    fn a_keystore_key_is_warned_about_when_servers_are_in_1password() {
        let app = |env: &str| {
            format!(
                "name = \"bot\"\nchain = \"solana\"\n\
                 [secrets]\nX_TOKEN = \"keystore:erpc-worker/bot.X_TOKEN\"\n\
                 API_TOKEN = \"op://{VAULT}/{ITEM}/credential\"\n\
                 [wallet]\nsource = \"keystore:erpc-worker/bot.wallet\"\n\
                 pubkey = \"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"\n{env}"
            )
        };
        let inventory = format!("[env.prod]\ninventory = {{ vault = \"{VAULT}\" }}\n");
        let warnings = Manifest::parse(&app(&inventory)).expect("valid").warnings();
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(warnings[0].starts_with("secrets.X_TOKEN is keystore:erpc-worker/bot.X_TOKEN"));
        assert!(warnings[1].starts_with("wallet.source is keystore:erpc-worker/bot.wallet"));
        assert!(warnings.iter().all(|w| w.contains("only this machine has")));
        // With no environment in 1Password there is no other machine to
        // warn about.
        let warnings = Manifest::parse(&app("")).expect("valid").warnings();
        assert!(warnings.is_empty(), "{warnings:#?}");
    }

    #[test]
    fn the_nearest_manifest_above_a_directory_is_found() {
        let root = std::env::temp_dir().join(format!("erpc-worker-locate-{}", std::process::id()));
        let deep = root.join("src").join("bin");
        std::fs::create_dir_all(&deep).expect("dirs");
        std::fs::write(root.join(FILE_NAME), "name = \"bot\"\nchain = \"solana\"\n")
            .expect("write");
        assert_eq!(locate(&deep), Some(root.join(FILE_NAME)));
        let loaded = Manifest::load(&root.join(FILE_NAME)).expect("load");
        assert_eq!(loaded.name, "bot");
        let _ = std::fs::remove_dir_all(&root);
    }
}
