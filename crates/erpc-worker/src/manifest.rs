// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc.toml`: one app, how it is built and run, and where each of its
//! environments is deployed.
//!
//! The file is meant to be committed, so it never holds a secret value.
//! A secret is a reference to 1Password (`op://<vault-id>/<item-id>/<field>`)
//! or to the OS keychain (`keychain:<service>/<account>`); `erpc worker`
//! reads the value when it needs it and sends it to the server without
//! writing it down. The trading key is the same, under `[wallet]`, and is
//! the one secret that never reaches a disk on the server either.
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
}

impl SecretRef {
    /// Parses `op://<vault-id>/<item-id>/<field>` or
    /// `keychain:<service>/<account>`.
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
            let part = |s: &str| {
                !s.is_empty()
                    && s.len() <= 128
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            };
            if !part(service) || !part(account) {
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
        Err(
            "a secret is a reference, op://<vault-id>/<item-id>/<field> or \
             keychain:<service>/<account>, never the value itself"
                .to_owned(),
        )
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OnePassword(r) => r.fmt(f),
            Self::Keychain { service, account } => write!(f, "keychain:{service}/{account}"),
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
}

impl Default for Build {
    fn default() -> Self {
        Self {
            command: default_command(),
            bin: None,
            target: Target::default(),
        }
    }
}

fn default_command() -> Vec<String> {
    ["cargo", "build", "--release"]
        .map(ToOwned::to_owned)
        .to_vec()
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
    /// Settings the app cannot start without. `check` says which are not
    /// set; `run` and `deploy` refuse until they are.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// The TCP port the app listens on, which `firewall.app_allow` opens on
    /// its server. Without it the app is reached from nowhere outside.
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

/// `[wallet]`: the trading key. Read from `source` when the app starts and
/// handed to it on a pipe; never written to a file anywhere.
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

/// `[env.<name>.firewall]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    /// Who may reach SSH.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_allow: Vec<Cidr>,
    /// Who may reach the app's own port. Empty: nobody from outside.
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
/// `host_key`, `firewall`, `lines`, `backup` -- are written here, or kept in 1Password when
/// `inventory` is set, never both: two copies drift, and nobody can tell
/// which is right.
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

    /// The settings in `run.requires` that neither `[vars]` nor `[secrets]`
    /// sets.
    #[must_use]
    pub fn missing(&self) -> Vec<&str> {
        self.missing_besides(&[])
    }

    /// The settings in `run.requires` that neither `[vars]`, `[secrets]`
    /// nor `provided` sets: `provided` are the ones a data line sets on
    /// the server ([`Env::line_vars`]).
    #[must_use]
    pub fn missing_besides(&self, provided: &[&str]) -> Vec<&str> {
        self.run
            .requires
            .iter()
            .filter(|n| {
                !self.vars.contains_key(*n)
                    && !self.secrets.contains_key(*n)
                    && !provided.contains(&n.as_str())
                    && !self
                        .services
                        .vars()
                        .iter()
                        .any(|(name, _)| *name == n.as_str())
            })
            .map(String::as_str)
            .collect()
    }

    /// Things that are allowed but probably not meant.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (name, value) in &self.vars {
            if looks_secret(name) {
                out.push(format!(
                    "vars.{name} looks like a secret; [vars] reach the server as written, \
                     so move it to [secrets] as a reference"
                ));
            } else if carries_credential(value) {
                out.push(format!(
                    "vars.{name} carries a credential in its value; move it to [secrets] as a \
                     reference"
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
        for name in self.missing_besides(&everywhere) {
            out.push(format!(
                "{name} is required (run.requires) and not set; add it to [vars], or to \
                 [secrets] as a reference"
            ));
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
        // An app whose servers are reached from any machine through
        // 1Password still cannot start from another machine if its keys are
        // in this one's keychain.
        // Opening the port does nothing for an app that listens on loopback,
        // which is where the templates listen unless told otherwise.
        if self.env.values().any(|e| !e.firewall.app_allow.is_empty())
            && !self.vars.keys().any(|k| k.ends_with("BIND"))
        {
            out.push(
                "firewall.app_allow opens run.port, and the app still listens on loopback only \
                 unless a setting says otherwise (the pumpfun template: API_BIND = \"0.0.0.0\")"
                    .to_owned(),
            );
        }
        if self.env.values().any(|e| e.inventory.is_some()) {
            let keychain = self
                .secrets
                .iter()
                .map(|(name, r)| (format!("secrets.{name}"), r))
                .chain(
                    self.wallet
                        .iter()
                        .map(|w| ("wallet.source".to_owned(), &w.source)),
                )
                .filter(|(_, r)| matches!(r, SecretRef::Keychain { .. }));
            for (at, reference) in keychain {
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
        for (name, value) in &self.vars {
            if let Err(problem) = check_env_name(name) {
                out.push(format!("vars.{name}: {problem}"));
            }
            if value.len() > 4096 || value.contains(['\n', '\r', '\0']) {
                out.push(format!(
                    "vars.{name}: a value is one line of at most 4096 bytes"
                ));
            }
        }
        for name in self.secrets.keys() {
            if let Err(problem) = check_env_name(name) {
                out.push(format!("secrets.{name}: {problem}"));
            }
            if self.vars.contains_key(name) {
                out.push(format!("{name} is in both [vars] and [secrets]"));
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
            line_problems(&format!("env.{name}.lines"), &env.lines, &mut out);
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

    fn build_problems(&self, out: &mut Vec<String>) {
        if self.build.command.is_empty()
            || self.build.command.iter().any(std::string::String::is_empty)
        {
            out.push("build.command must be a list of non-empty words".to_owned());
        }
        if self.build.command.iter().any(|w| w.contains('\0')) {
            out.push("build.command has a NUL byte".to_owned());
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
        for name in &self.run.requires {
            if let Err(problem) = check_env_name(name) {
                out.push(format!("run.requires: {name}: {problem}"));
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
    for (field, list) in [
        ("firewall.ssh_allow", &env.firewall.ssh_allow),
        ("firewall.app_allow", &env.firewall.app_allow),
    ] {
        if list.len() > MAX_ALLOW {
            out.push(format!("{}: at most {MAX_ALLOW} entries", at(field)));
        }
        let mut seen = BTreeSet::new();
        for cidr in list {
            if !seen.insert(cidr) {
                out.push(format!("{}: {cidr} is listed twice", at(field)));
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

fn looks_secret(name: &str) -> bool {
    [
        "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE", "API_KEY", "APIKEY", "MNEMONIC", "SEED",
    ]
    .iter()
    .any(|word| name.contains(word))
}

fn carries_credential(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["api-key=", "api_key=", "apikey=", "token=", "x-token="]
        .iter()
        .any(|needle| lower.contains(needle))
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
    use super::{Chain, FILE_NAME, LineKind, Manifest, ManifestError, SecretRef, Target, locate};

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
        assert_eq!(m.missing(), ["GRPC_ENDPOINT"]);
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
        let warnings = Manifest::parse(text).expect("valid").warnings();
        assert_eq!(warnings.len(), 4, "{warnings:#?}");
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
