// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The server security check's wire protocol.
//!
//! A request carries only enums, integers, booleans and validated version
//! tokens: nothing a person types and nothing read verbatim from the server,
//! such as a path, a command line or a file's contents. A reply names
//! findings from a fixed catalog and points back into the inventory by
//! index, so the terminal adds the local details itself.

use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::ApiError;

/// The account's servers that can be checked.
pub const SERVERS_URL: &str = "https://user-api.erpc.global/v3/ai/security-check/servers";

/// Starts a check; a check's state is read at this URL followed by its id.
pub const START_URL: &str = "https://user-api.erpc.global/v3/ai/security-check";

/// The only check this client knows.
pub const CHECK: &str = "server_security_v1";

/// The terms statement the customer confirmed before the request was sent.
pub const TERMS: &str = "v1";

/// The largest request body the service accepts.
pub const MAX_BODY: usize = 64 * 1024;

macro_rules! wire_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        $vis enum $name {
            $(
                #[doc = concat!("`", $wire, "` on the wire.")]
                #[serde(rename = $wire)]
                $variant,
            )+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The value's name on the wire.
            #[must_use]
            pub const fn wire(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }
        }
    };
}

wire_enum! {
    /// How much of a source the collector or the scanner could read.
    pub enum Coverage {
        Complete => "complete",
        Partial => "partial",
        Unreadable => "unreadable",
        Absent => "absent",
    }
}

impl Coverage {
    /// `self`, lowered to partial if it claimed to be complete.
    #[must_use]
    pub const fn at_most_partial(self) -> Self {
        match self {
            Self::Complete => Self::Partial,
            other => other,
        }
    }
}

wire_enum! {
    /// An answer the collector could not always give.
    pub enum Tristate {
        Yes => "yes",
        No => "no",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// The operating system's family, from `/etc/os-release`.
    pub enum OsFamily {
        Ubuntu => "ubuntu",
        Debian => "debian",
        Rhel => "rhel",
        Rocky => "rocky",
        Alma => "alma",
        Fedora => "fedora",
        Amazon => "amazon",
        Other => "other",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// The transport of a listening socket.
    pub enum Proto {
        Tcp => "tcp",
        Udp => "udp",
    }
}

wire_enum! {
    /// Which addresses a socket is bound to.
    pub enum Bind {
        Loopback => "loopback",
        Wildcard => "wildcard",
        Public => "public",
        Private => "private",
        LinkLocal => "link_local",
    }
}

wire_enum! {
    /// The program behind a socket, by its executable's name.
    pub enum App {
        AgaveValidator => "agave_validator",
        SolanaValidator => "solana_validator",
        Firedancer => "firedancer",
        JitoRelayer => "jito_relayer",
        JitoShredstream => "jito_shredstream",
        Geth => "geth",
        Reth => "reth",
        Erigon => "erigon",
        Nethermind => "nethermind",
        Besu => "besu",
        BscGeth => "bsc_geth",
        OpNode => "op_node",
        Lighthouse => "lighthouse",
        Prysm => "prysm",
        Teku => "teku",
        Nimbus => "nimbus",
        Lodestar => "lodestar",
        Bitcoind => "bitcoind",
        Avalanchego => "avalanchego",
        SuiNode => "sui_node",
        AptosNode => "aptos_node",
        Neard => "neard",
        HlNode => "hl_node",
        Monad => "monad",
        Sshd => "sshd",
        DockerProxy => "docker_proxy",
        Dockerd => "dockerd",
        Containerd => "containerd",
        Nginx => "nginx",
        Caddy => "caddy",
        Haproxy => "haproxy",
        Envoy => "envoy",
        Redis => "redis",
        Postgres => "postgres",
        Mysql => "mysql",
        Mongod => "mongod",
        Node => "node",
        Python => "python",
        Java => "java",
        Grafana => "grafana",
        Prometheus => "prometheus",
        NodeExporter => "node_exporter",
        ErpcWorker => "erpc_worker",
        ErpcGateway => "erpc_gateway",
        Other => "other",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// Who owns a socket: the superuser, a system account or a person's.
    pub enum Owner {
        Root => "root",
        Service => "service",
        User => "user",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// The Solana validator program.
    pub enum SolanaApp {
        AgaveValidator => "agave_validator",
        SolanaValidator => "solana_validator",
        Firedancer => "firedancer",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// Whether and how SSH accepts the superuser.
    pub enum RootLogin {
        Yes => "yes",
        ProhibitPassword => "prohibit_password",
        ForcedCommandsOnly => "forced_commands_only",
        No => "no",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// The host firewall's tool.
    pub enum FirewallTool {
        Ufw => "ufw",
        Nftables => "nftables",
        Iptables => "iptables",
        Firewalld => "firewalld",
        None => "none",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// What the host firewall does with traffic no rule names.
    pub enum Policy {
        Drop => "drop",
        Reject => "reject",
        Accept => "accept",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// The installed packages the check reads versions of.
    pub enum PackageName {
        OpensshServer => "openssh_server",
        Openssl => "openssl",
        Libssl => "libssl",
        Sudo => "sudo",
        Libc6 => "libc6",
        Systemd => "systemd",
        Polkit => "polkit",
        XzUtils => "xz_utils",
        DockerCe => "docker_ce",
        DockerIo => "docker_io",
        Containerd => "containerd",
        Runc => "runc",
        Nginx => "nginx",
        Apache2 => "apache2",
        Haproxy => "haproxy",
        RedisServer => "redis_server",
        Postgresql => "postgresql",
        MysqlServer => "mysql_server",
        MariadbServer => "mariadb_server",
        Mongodb => "mongodb",
        Nodejs => "nodejs",
        Python3 => "python3",
    }
}

wire_enum! {
    /// What kind of exposed secret was found.
    pub enum KeyKind {
        SolanaKeypair => "solana_keypair",
        EvmPrivateKey => "evm_private_key",
        Mnemonic => "mnemonic",
        UnencryptedKeystore => "unencrypted_keystore",
        EnvSecret => "env_secret",
        ProcessEnvSecret => "process_env_secret",
        HistorySecret => "history_secret",
    }
}

wire_enum! {
    /// What a found key is for, decided on the server it was found on.
    pub enum KeyRole {
        ValidatorIdentity => "validator_identity",
        VoteAuthority => "vote_authority",
        WithdrawAuthority => "withdraw_authority",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// Where a secret was found, as a class rather than a path.
    pub enum KeyLocation {
        Home => "home",
        RootHome => "root_home",
        Etc => "etc",
        Opt => "opt",
        Srv => "srv",
        Var => "var",
        Tmp => "tmp",
        Docker => "docker",
        ProcessEnv => "process_env",
        ShellHistory => "shell_history",
        Other => "other",
    }
}

wire_enum! {
    /// Who can read where a secret was found.
    pub enum Access {
        OwnerOnly => "owner_only",
        Group => "group",
        World => "world",
    }
}

/// At most `MAX` items. Built only by [`Bounded::new`], which drops what
/// does not fit and says so, so a request cannot exceed the bounds the
/// service enforces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Bounded<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> Bounded<T, MAX> {
    /// The first `MAX` of `items`, and whether any were dropped.
    #[must_use]
    pub fn new(mut items: Vec<T>) -> (Self, bool) {
        let dropped = items.len() > MAX;
        items.truncate(MAX);
        (Self(items), dropped)
    }

    /// The items.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.0
    }
}

impl<T, const MAX: usize> Default for Bounded<T, MAX> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

/// A list the collector read, with how completely it read it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Section<T, const MAX: usize> {
    coverage: Coverage,
    items: Bounded<T, MAX>,
}

impl<T, const MAX: usize> Section<T, MAX> {
    /// `items` read with `coverage`; lowered to partial when some had to be
    /// dropped to stay within the bound.
    #[must_use]
    pub fn new(coverage: Coverage, items: Vec<T>) -> Self {
        let (items, dropped) = Bounded::new(items);
        let coverage = if dropped {
            coverage.at_most_partial()
        } else {
            coverage
        };
        Self { coverage, items }
    }

    /// A source that could not be read at all.
    #[must_use]
    pub fn unreadable() -> Self {
        Self {
            coverage: Coverage::Unreadable,
            items: Bounded::default(),
        }
    }

    /// How completely the source was read.
    #[must_use]
    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }

    /// The items, in the order the request carries them.
    #[must_use]
    pub fn items(&self) -> &[T] {
        self.items.items()
    }
}

/// A version as the package database or the kernel states it, limited to
/// the characters versions use. It goes only to the service's advisory
/// matching.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Token(String);

impl Token {
    /// The longest token accepted.
    pub const MAX: usize = 48;

    /// `value` as a token, or `None` when it is empty, too long, or has a
    /// character versions do not use.
    #[must_use]
    pub fn new(value: &str) -> Option<Self> {
        let bytes = value.as_bytes();
        let valid = bytes.len() <= Self::MAX
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b".+~:_-".contains(b));
        valid.then(|| Self(value.to_owned()))
    }

    /// The token's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The operating system.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Os {
    /// How completely it was read.
    pub coverage: Coverage,
    /// Its family.
    pub family: OsFamily,
    /// Its release, such as `24.04`.
    pub version: Option<Token>,
    /// The running kernel's release.
    pub kernel: Option<Token>,
}

/// A listening socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Listener {
    /// Its transport.
    pub proto: Proto,
    /// Its port.
    pub port: NonZeroU16,
    /// The addresses it is bound to.
    pub bind: Bind,
    /// The program that holds it.
    pub app: App,
    /// The kind of account that owns it.
    pub owner: Owner,
    /// Whether Docker publishes it.
    pub docker: bool,
}

/// A Solana validator process and its RPC settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SolanaNode {
    /// The program.
    pub app: SolanaApp,
    /// The RPC port, when RPC is enabled.
    pub rpc_port: Option<NonZeroU16>,
    /// The RPC bind address, when one is set.
    pub rpc_bind: Option<Bind>,
    /// Whether the full RPC API is enabled.
    pub full_rpc_api: bool,
    /// Whether the RPC port is kept out of gossip.
    pub private_rpc: bool,
    /// Whether transaction history is served.
    pub rpc_tx_history: bool,
    /// Whether the identity keypair is a file on this server.
    pub identity_on_disk: Tristate,
    /// Whether the vote account's withdraw authority is on this server.
    pub withdrawer_on_disk: Tristate,
}

/// The SSH server's effective settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Ssh {
    /// How completely the configuration was read.
    pub coverage: Coverage,
    /// Whether passwords are accepted.
    pub password_auth: Tristate,
    /// Whether and how the superuser may sign in.
    pub root_login: RootLogin,
    /// Whether keyboard-interactive sign-in is accepted.
    pub kbd_interactive: Tristate,
    /// The ports it listens on.
    pub ports: Bounded<NonZeroU16, 8>,
}

/// The host firewall, as configured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Firewall {
    /// How completely the configuration was read.
    pub coverage: Coverage,
    /// The tool.
    pub tool: FirewallTool,
    /// Whether it is enabled.
    pub enabled: Tristate,
    /// What it does with incoming traffic no rule names.
    pub input_policy: Policy,
}

/// An installed package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Package {
    /// Which one.
    pub name: PackageName,
    /// Its version.
    pub version: Token,
}

/// Exposed secrets of one kind, role, location and access, counted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeyGroup {
    /// What was found.
    pub kind: KeyKind,
    /// What it is for.
    pub role: KeyRole,
    /// Where, as a class.
    pub location: KeyLocation,
    /// Who can read it.
    pub access: Access,
    /// How many, from 1 to [`KeyGroup::MAX_COUNT`].
    pub count: u32,
}

impl KeyGroup {
    /// The largest count a group carries.
    pub const MAX_COUNT: u32 = 100_000;
}

/// Listening sockets, at most 256.
pub type Listeners = Section<Listener, 256>;
/// Solana validator processes, at most 8.
pub type SolanaNodes = Section<SolanaNode, 8>;
/// Installed packages, at most 64.
pub type Packages = Section<Package, 64>;
/// Exposed secrets, at most 128 groups.
pub type Keys = Section<KeyGroup, 128>;

/// Everything the collector reports about the server it runs on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Inventory {
    /// Whether the collector ran as the superuser and so saw everything.
    pub privileged: bool,
    /// The operating system.
    pub os: Os,
    /// Listening sockets.
    pub listeners: Listeners,
    /// Solana validator processes.
    pub solana: SolanaNodes,
    /// The SSH server.
    pub ssh: Ssh,
    /// The host firewall.
    pub firewall: Firewall,
    /// Installed packages.
    pub packages: Packages,
    /// Exposed secrets.
    pub keys: Keys,
}

/// The request body that starts a check of `server` with `inventory`.
///
/// # Errors
/// Returns [`ApiError::Malformed`] when a key group's count is out of range
/// or the body exceeds [`MAX_BODY`].
pub fn request_body(server: &ServerId, inventory: &Inventory) -> Result<Vec<u8>, ApiError> {
    if inventory
        .keys
        .items()
        .iter()
        .any(|group| group.count == 0 || group.count > KeyGroup::MAX_COUNT)
    {
        return Err(ApiError::Malformed("key count out of range".to_owned()));
    }
    let body = json!({
        "check": CHECK,
        "server": server.as_str(),
        "terms": TERMS,
        "inventory": inventory,
    });
    let bytes = serde_json::to_vec(&body).map_err(|e| ApiError::Malformed(e.to_string()))?;
    if bytes.len() > MAX_BODY {
        return Err(ApiError::Malformed("request too large".to_owned()));
    }
    Ok(bytes)
}

wire_enum! {
    /// The kind of an ERPC server.
    pub enum ServerKind {
        Vps => "vps",
        SuperVps => "super_vps",
        PremiumVps => "premium_vps",
        BareMetal => "bare_metal",
    }
}

/// A server's id: its kind and its number, such as `vps:123`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct ServerId {
    kind: ServerKind,
    id: String,
}

impl ServerId {
    /// The id's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// The server's kind.
    #[must_use]
    pub const fn kind(&self) -> ServerKind {
        self.kind
    }
}

impl TryFrom<String> for ServerId {
    type Error = String;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        let (kind, number) = id.split_once(':').ok_or("not a server id")?;
        let kind = ServerKind::ALL
            .iter()
            .copied()
            .find(|k| k.wire() == kind)
            .ok_or("not a server kind")?;
        let valid = (1..=16).contains(&number.len())
            && !number.starts_with('0')
            && number.bytes().all(|b| b.is_ascii_digit());
        if valid {
            Ok(Self { kind, id })
        } else {
            Err("not a server number".to_owned())
        }
    }
}

/// Text from the service for display only: one line of at most 64
/// printable characters. It is never sent back.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Label(String);

impl Label {
    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Label {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        // Control characters, including the terminal's escape sequences and
        // the bidirectional overrides, never reach the screen.
        let printable = !text.chars().any(|c| {
            c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        });
        if printable && text.chars().count() <= 64 {
            Ok(Self(text))
        } else {
            Err("not a label".to_owned())
        }
    }
}

/// A server that can be checked.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// Its id.
    pub id: ServerId,
    /// Its kind.
    pub kind: ServerKind,
    /// Its name in the account.
    pub label: Label,
    /// Its primary address.
    pub address: Ipv4Addr,
    /// Where it runs.
    pub region: Label,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerList {
    servers: Vec<Server>,
}

/// The most servers a list carries.
pub const MAX_SERVERS: usize = 100;

/// A started check's id: a UUID, checked before it goes into a path.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct CheckId(String);

impl CheckId {
    /// The URL that reads this check.
    #[must_use]
    pub fn url(&self) -> String {
        format!("{START_URL}/{}", self.0)
    }
}

impl TryFrom<String> for CheckId {
    type Error = String;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        let valid = id.len() == 36
            && id.char_indices().all(|(i, c)| match i {
                8 | 13 | 18 | 23 => c == '-',
                _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
            });
        if valid {
            Ok(Self(id))
        } else {
            Err("not a check id".to_owned())
        }
    }
}

wire_enum! {
    /// Why the service refused a request.
    pub enum Refusal {
        Invalid => "invalid_security_check",
        Denied => "security_check_denied",
        SourceMismatch => "source_mismatch",
        NotEligible => "server_not_eligible",
        Active => "security_check_active",
        Limited => "security_check_limited",
        Unavailable => "security_check_unavailable",
        NotFound => "not_found",
    }
}

/// Why a security check request did not succeed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request failed or the reply could not be read.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The service refused, and said why.
    #[error("the security check was refused: {}", .0.wire())]
    Refused(Refusal),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorBody {
    error: String,
}

fn refusal(status: u16, body: &str) -> Error {
    if status == 401 {
        return Error::Api(ApiError::Unauthorized);
    }
    let code = serde_json::from_str::<ErrorBody>(body)
        .ok()
        .map(|b| b.error);
    let refusal = code.and_then(|code| Refusal::ALL.iter().copied().find(|r| r.wire() == code));
    let expected = |r: Refusal| match r {
        Refusal::Invalid => status == 400,
        Refusal::Denied | Refusal::SourceMismatch | Refusal::NotEligible => status == 403,
        Refusal::NotFound => status == 404,
        Refusal::Active => status == 409,
        Refusal::Limited => status == 429,
        Refusal::Unavailable => status == 503,
    };
    match refusal {
        Some(r) if expected(r) => Error::Refused(r),
        _ => Error::Api(ApiError::Status(status)),
    }
}

fn malformed() -> Error {
    Error::Api(ApiError::Malformed(
        "invalid security check response".to_owned(),
    ))
}

fn servers_reply(status: u16, body: &str) -> Result<Vec<Server>, Error> {
    if status != 200 {
        return Err(refusal(status, body));
    }
    let list = serde_json::from_str::<ServerList>(body).map_err(|_| malformed())?;
    let consistent =
        list.servers.len() <= MAX_SERVERS && list.servers.iter().all(|s| s.id.kind() == s.kind);
    if consistent {
        Ok(list.servers)
    } else {
        Err(malformed())
    }
}

/// The account's servers that can be checked.
///
/// # Errors
/// Returns [`Error`] when the request fails, is refused or the reply is
/// invalid.
pub async fn servers(client: &AuthClient, token: &SecretString) -> Result<Vec<Server>, Error> {
    let (status, body) = client
        .get_with_token(Audience::AuthApi, SERVERS_URL, token)
        .await
        .map_err(ApiError::from)?;
    servers_reply(status, &body)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Started {
    id: CheckId,
    status: Status,
}

fn start_reply(status: u16, body: &str) -> Result<CheckId, Error> {
    if status != 202 {
        return Err(refusal(status, body));
    }
    match serde_json::from_str::<Started>(body) {
        Ok(Started {
            id,
            status: Status::Running,
        }) => Ok(id),
        _ => Err(malformed()),
    }
}

/// Starts a check of `server` with `inventory`.
///
/// # Errors
/// Returns [`Error`] when the request fails, is refused or the reply is
/// invalid.
pub async fn start(
    client: &AuthClient,
    token: &SecretString,
    server: &ServerId,
    inventory: &Inventory,
) -> Result<CheckId, Error> {
    let body = request_body(server, inventory)?;
    let (status, reply) = client
        .post_with_token(Audience::AuthApi, START_URL, token, body, None)
        .await
        .map_err(ApiError::from)?;
    start_reply(status, &reply)
}

/// A check's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Running,
    Done,
    Failed,
}

wire_enum! {
    /// Why a check ended without a report.
    pub enum FailReason {
        Unavailable => "unavailable",
        Cancelled => "cancelled",
        ScanFailed => "scan_failed",
    }
}

wire_enum! {
    /// How much of the server's outside the scanner could check.
    pub enum ExternalCoverage {
        Complete => "complete",
        Partial => "partial",
        Failed => "failed",
    }
}

wire_enum! {
    /// A service, identified by how it answers rather than by its port.
    pub enum Service {
        SolanaRpc => "solana_rpc",
        SolanaWs => "solana_ws",
        SolanaGossip => "solana_gossip",
        SolanaTpu => "solana_tpu",
        YellowstoneGrpc => "yellowstone_grpc",
        JitoShredstream => "jito_shredstream",
        EvmRpc => "evm_rpc",
        EvmWs => "evm_ws",
        EvmP2p => "evm_p2p",
        BeaconApi => "beacon_api",
        BitcoinRpc => "bitcoin_rpc",
        BitcoinP2p => "bitcoin_p2p",
        Ssh => "ssh",
        Http => "http",
        Https => "https",
        DockerApi => "docker_api",
        Redis => "redis",
        Postgres => "postgres",
        Mysql => "mysql",
        Mongodb => "mongodb",
        PrometheusMetrics => "prometheus_metrics",
        Grafana => "grafana",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// A finding in the check's catalog.
    pub enum FindingId {
        SolanaRpcPublic => "solana_rpc_public",
        SolanaFullRpcApiPublic => "solana_full_rpc_api_public",
        SolanaWsPublic => "solana_ws_public",
        EvmRpcPublic => "evm_rpc_public",
        EvmAdminApiPublic => "evm_admin_api_public",
        DockerApiPublic => "docker_api_public",
        DatabasePublic => "database_public",
        RedisNoAuthPublic => "redis_no_auth_public",
        MetricsPublic => "metrics_public",
        UnknownServicePublic => "unknown_service_public",
        TlsLegacyProtocol => "tls_legacy_protocol",
        SshPasswordAuth => "ssh_password_auth",
        SshRootLogin => "ssh_root_login",
        NoHostFirewall => "no_host_firewall",
        DockerBypassesFirewall => "docker_bypasses_firewall",
        WildcardListenerExposed => "wildcard_listener_exposed",
        PackageVulnerable => "package_vulnerable",
        OsEndOfLife => "os_end_of_life",
        PlaintextWalletKey => "plaintext_wallet_key",
        KeyWorldReadable => "key_world_readable",
        WithdrawAuthorityOnServer => "withdraw_authority_on_server",
        ValidatorIdentityPermissions => "validator_identity_permissions",
        MnemonicOnDisk => "mnemonic_on_disk",
        UnencryptedKeystore => "unencrypted_keystore",
        SecretInEnvFile => "secret_in_env_file",
        SecretInProcessEnv => "secret_in_process_env",
        SecretInShellHistory => "secret_in_shell_history",
        ScanIncomplete => "scan_incomplete",
        LocalViewPartial => "local_view_partial",
    }
}

wire_enum! {
    /// How urgent a finding is.
    pub enum Severity {
        Critical => "critical",
        High => "high",
        Medium => "medium",
        Low => "low",
        Info => "info",
    }
}

wire_enum! {
    /// What a reference points into.
    pub enum RefSource {
        ExternalTcp => "external_tcp",
        ExternalUdp => "external_udp",
        Listener => "listener",
        Solana => "solana",
        Ssh => "ssh",
        Firewall => "firewall",
        Package => "package",
        Key => "key",
    }
}

wire_enum! {
    /// What an attacker reaches by an exposure path.
    pub enum PathKind {
        RemoteCodeExecution => "remote_code_execution",
        FundTheft => "fund_theft",
        ValidatorTakeover => "validator_takeover",
        ServiceDisruption => "service_disruption",
        DataExposure => "data_exposure",
    }
}

/// A public advisory's id: CVE, GitHub, Ubuntu or Debian.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Advisory(String);

impl Advisory {
    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn digits(s: &str, lengths: std::ops::RangeInclusive<usize>) -> bool {
    lengths.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

impl TryFrom<String> for Advisory {
    type Error = String;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        let valid = if let Some(rest) = id.strip_prefix("CVE-") {
            rest.split_once('-')
                .is_some_and(|(year, n)| digits(year, 4..=4) && digits(n, 4..=7))
        } else if let Some(rest) = id.strip_prefix("GHSA-") {
            let parts: Vec<&str> = rest.split('-').collect();
            parts.len() == 3
                && parts.iter().all(|p| {
                    p.len() == 4 && p.bytes().all(|b| b"23456789cfghjmpqrvwx".contains(&b))
                })
        } else if let Some(rest) = id.strip_prefix("USN-").or_else(|| id.strip_prefix("DSA-")) {
            rest.split_once('-')
                .is_some_and(|(n, r)| digits(n, 3..=5) && digits(r, 1..=2))
        } else {
            false
        };
        if valid {
            Ok(Self(id))
        } else {
            Err("not an advisory id".to_owned())
        }
    }
}

/// A finding's pointer into the report or the inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ref {
    /// What it points into.
    pub source: RefSource,
    /// The item's position there.
    pub index: u16,
}

/// A finding.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Which catalog entry.
    pub id: FindingId,
    /// How urgent.
    pub severity: Severity,
    /// What it is about.
    pub refs: Vec<Ref>,
    /// The advisories it matched.
    pub advisories: Vec<Advisory>,
}

/// Findings that together lead somewhere.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposurePath {
    /// Where they lead.
    pub kind: PathKind,
    /// The findings, by position in the report, in the order an attacker
    /// would use them.
    pub steps: Vec<u8>,
}

/// An open TCP port seen from outside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalTcp {
    /// The port.
    pub port: NonZeroU16,
    /// What answers there.
    pub service: Service,
    /// Whether it speaks TLS.
    pub tls: bool,
}

/// A UDP port seen answering from outside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalUdp {
    /// The port.
    pub port: NonZeroU16,
    /// What answers there.
    pub service: Service,
}

/// What the scanner saw from outside.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct External {
    /// Open TCP ports.
    pub tcp: Vec<ExternalTcp>,
    /// Answering UDP ports.
    pub udp: Vec<ExternalUdp>,
}

/// How much the report could cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportCoverage {
    /// From outside.
    pub external: ExternalCoverage,
    /// On the server.
    pub local: Coverage,
}

/// A finished check.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    check: String,
    server: ServerId,
    /// How much it could cover.
    pub coverage: ReportCoverage,
    /// What was seen from outside.
    pub external: External,
    /// The findings, most urgent first.
    pub findings: Vec<Finding>,
    /// The exposure paths.
    pub paths: Vec<ExposurePath>,
}

impl Report {
    fn valid(&self, server: &ServerId, inventory: &Inventory) -> bool {
        let len = |source: RefSource| match source {
            RefSource::ExternalTcp => self.external.tcp.len(),
            RefSource::ExternalUdp => self.external.udp.len(),
            RefSource::Listener => inventory.listeners.items().len(),
            RefSource::Solana => inventory.solana.items().len(),
            RefSource::Package => inventory.packages.items().len(),
            RefSource::Key => inventory.keys.items().len(),
            RefSource::Ssh | RefSource::Firewall => 1,
        };
        let finding_ok = |f: &Finding| {
            f.refs.len() <= 16
                && f.advisories.len() <= 16
                && f.refs.iter().all(|r| usize::from(r.index) < len(r.source))
        };
        let path_ok = |p: &ExposurePath| {
            let mut steps = p.steps.clone();
            steps.sort_unstable();
            steps.dedup();
            (1..=8).contains(&p.steps.len())
                && steps.len() == p.steps.len()
                && p.steps
                    .iter()
                    .all(|&s| usize::from(s) < self.findings.len())
        };
        self.check == CHECK
            && self.server == *server
            && self.external.tcp.len() <= 1024
            && self.external.udp.len() <= 256
            && self.findings.len() <= 64
            && self.paths.len() <= 8
            && self.findings.iter().all(finding_ok)
            && self.paths.iter().all(path_ok)
    }
}

/// Where a check is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Poll {
    /// Still running.
    Running,
    /// Finished, with its report.
    Done(Box<Report>),
    /// Ended without a report.
    Failed(FailReason),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPoll {
    status: Status,
    report: Option<Report>,
    reason: Option<FailReason>,
}

fn poll_reply(
    status: u16,
    body: &str,
    server: &ServerId,
    inventory: &Inventory,
) -> Result<Poll, Error> {
    if status != 200 {
        return Err(refusal(status, body));
    }
    let raw = serde_json::from_str::<RawPoll>(body).map_err(|_| malformed())?;
    match (raw.status, raw.report, raw.reason) {
        (Status::Running, None, None) => Ok(Poll::Running),
        (Status::Done, Some(report), None) if report.valid(server, inventory) => {
            Ok(Poll::Done(Box::new(report)))
        }
        (Status::Failed, None, Some(reason)) => Ok(Poll::Failed(reason)),
        _ => Err(malformed()),
    }
}

/// Reads check `id`, started for `server` with `inventory`.
///
/// # Errors
/// Returns [`Error`] when the request fails, is refused or the reply is
/// invalid, including a report that does not match what was sent.
pub async fn poll(
    client: &AuthClient,
    token: &SecretString,
    id: &CheckId,
    server: &ServerId,
    inventory: &Inventory,
) -> Result<Poll, Error> {
    let (status, body) = client
        .get_with_token(Audience::AuthApi, &id.url(), token)
        .await
        .map_err(ApiError::from)?;
    poll_reply(status, &body, server, inventory)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(n: u16) -> NonZeroU16 {
        NonZeroU16::new(n).unwrap_or(NonZeroU16::MIN)
    }

    fn server() -> ServerId {
        ServerId::try_from("vps:123".to_owned()).unwrap_or_else(|e| panic!("{e}"))
    }

    fn inventory() -> Inventory {
        Inventory {
            privileged: true,
            os: Os {
                coverage: Coverage::Complete,
                family: OsFamily::Ubuntu,
                version: Token::new("24.04"),
                kernel: Token::new("6.8.0-49-generic"),
            },
            listeners: Section::new(
                Coverage::Complete,
                vec![Listener {
                    proto: Proto::Tcp,
                    port: port(8899),
                    bind: Bind::Wildcard,
                    app: App::AgaveValidator,
                    owner: Owner::Service,
                    docker: false,
                }],
            ),
            solana: Section::new(
                Coverage::Complete,
                vec![SolanaNode {
                    app: SolanaApp::AgaveValidator,
                    rpc_port: Some(port(8899)),
                    rpc_bind: Some(Bind::Wildcard),
                    full_rpc_api: true,
                    private_rpc: false,
                    rpc_tx_history: false,
                    identity_on_disk: Tristate::Yes,
                    withdrawer_on_disk: Tristate::Unknown,
                }],
            ),
            ssh: Ssh {
                coverage: Coverage::Complete,
                password_auth: Tristate::No,
                root_login: RootLogin::ProhibitPassword,
                kbd_interactive: Tristate::No,
                ports: Bounded::new(vec![port(22)]).0,
            },
            firewall: Firewall {
                coverage: Coverage::Complete,
                tool: FirewallTool::Ufw,
                enabled: Tristate::Yes,
                input_policy: Policy::Drop,
            },
            packages: Section::new(
                Coverage::Complete,
                vec![Package {
                    name: PackageName::OpensshServer,
                    version: Token::new("1:9.6p1-3ubuntu13.5").unwrap_or_else(|| panic!("token")),
                }],
            ),
            keys: Section::new(
                Coverage::Complete,
                vec![KeyGroup {
                    kind: KeyKind::SolanaKeypair,
                    role: KeyRole::ValidatorIdentity,
                    location: KeyLocation::Home,
                    access: Access::OwnerOnly,
                    count: 1,
                }],
            ),
        }
    }

    #[test]
    fn every_url_is_a_declared_destination_for_the_account_token() {
        let id = CheckId::try_from("123e4567-e89b-42d3-a456-426614174000".to_owned())
            .unwrap_or_else(|e| panic!("{e}"));
        for url in [SERVERS_URL, START_URL, &id.url()] {
            assert!(
                erpc_core::endpoints::ensure_service_url(url).is_ok(),
                "{url}"
            );
            assert!(
                erpc_auth::allowlist::ensure_token_destination(Audience::AuthApi, url).is_ok(),
                "{url}"
            );
        }
        assert_eq!(
            id.url(),
            "https://user-api.erpc.global/v3/ai/security-check/123e4567-e89b-42d3-a456-426614174000"
        );
    }

    #[test]
    fn only_a_lowercase_uuid_becomes_a_check_id() {
        for bad in [
            "",
            "../servers",
            "123E4567-E89B-42D3-A456-426614174000",
            "123e4567-e89b-42d3-a456-42661417400?",
            "123e4567e89b42d3a456426614174000aaaa",
        ] {
            assert!(CheckId::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_request_carries_only_the_fixed_names_enums_and_tokens() {
        let body = request_body(&server(), &inventory()).unwrap_or_else(|e| panic!("{e}"));
        let value: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            value,
            json!({
                "check": "server_security_v1",
                "server": "vps:123",
                "terms": "v1",
                "inventory": {
                    "privileged": true,
                    "os": {"coverage": "complete", "family": "ubuntu", "version": "24.04", "kernel": "6.8.0-49-generic"},
                    "listeners": {"coverage": "complete", "items": [
                        {"proto": "tcp", "port": 8899, "bind": "wildcard", "app": "agave_validator", "owner": "service", "docker": false}
                    ]},
                    "solana": {"coverage": "complete", "items": [
                        {"app": "agave_validator", "rpc_port": 8899, "rpc_bind": "wildcard", "full_rpc_api": true,
                         "private_rpc": false, "rpc_tx_history": false, "identity_on_disk": "yes", "withdrawer_on_disk": "unknown"}
                    ]},
                    "ssh": {"coverage": "complete", "password_auth": "no", "root_login": "prohibit_password", "kbd_interactive": "no", "ports": [22]},
                    "firewall": {"coverage": "complete", "tool": "ufw", "enabled": "yes", "input_policy": "drop"},
                    "packages": {"coverage": "complete", "items": [{"name": "openssh_server", "version": "1:9.6p1-3ubuntu13.5"}]},
                    "keys": {"coverage": "complete", "items": [
                        {"kind": "solana_keypair", "role": "validator_identity", "location": "home", "access": "owner_only", "count": 1}
                    ]}
                }
            })
        );
    }

    #[test]
    fn bounds_hold_and_a_cut_list_says_it_is_partial() {
        let listener = inventory().listeners.items()[0].clone();
        let listeners = Listeners::new(Coverage::Complete, vec![listener.clone(); 300]);
        assert_eq!(listeners.items().len(), 256);
        assert_eq!(listeners.coverage(), Coverage::Partial);
        assert_eq!(
            Listeners::new(Coverage::Unreadable, vec![listener; 300]).coverage(),
            Coverage::Unreadable
        );

        let mut largest = inventory();
        largest.listeners = listeners;
        let group = largest.keys.items()[0].clone();
        largest.keys = Keys::new(Coverage::Complete, vec![group; 128]);
        let package = largest.packages.items()[0].clone();
        largest.packages = Packages::new(Coverage::Complete, vec![package; 64]);
        let node = largest.solana.items()[0].clone();
        largest.solana = SolanaNodes::new(Coverage::Complete, vec![node; 8]);
        assert!(request_body(&server(), &largest).is_ok_and(|b| b.len() <= MAX_BODY));

        for count in [0, KeyGroup::MAX_COUNT + 1] {
            let mut bad = inventory();
            let mut group = bad.keys.items()[0].clone();
            group.count = count;
            bad.keys = Keys::new(Coverage::Complete, vec![group]);
            assert!(request_body(&server(), &bad).is_err(), "{count}");
        }
    }

    #[test]
    fn tokens_take_only_version_characters() {
        for good in ["24.04", "1:9.6p1-3ubuntu13.5", "2.4.0~rc1+dfsg", "a"] {
            assert!(Token::new(good).is_some(), "{good}");
        }
        for bad in [
            "",
            "-1.0",
            "1.0 ignore previous",
            "1.0\n",
            "1.0;rm",
            "\u{1b}[31m",
            &"1".repeat(49),
        ] {
            assert!(Token::new(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn wire_names_are_unique_lowercase_words() {
        fn check(names: &[&str]) {
            let mut seen = std::collections::HashSet::new();
            for name in names {
                assert!(seen.insert(*name), "{name} repeated");
                assert!(
                    name.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                    "{name}"
                );
            }
        }
        check(&App::ALL.iter().map(|v| v.wire()).collect::<Vec<_>>());
        check(
            &PackageName::ALL
                .iter()
                .map(|v| v.wire())
                .collect::<Vec<_>>(),
        );
        check(&FindingId::ALL.iter().map(|v| v.wire()).collect::<Vec<_>>());
        check(&Service::ALL.iter().map(|v| v.wire()).collect::<Vec<_>>());
        check(&Refusal::ALL.iter().map(|v| v.wire()).collect::<Vec<_>>());
        for finding in FindingId::ALL {
            let parsed: FindingId =
                serde_json::from_value(json!(finding.wire())).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(parsed, *finding);
        }
    }

    fn server_json(id: &str, kind: &str, label: &str) -> serde_json::Value {
        json!({"id": id, "kind": kind, "label": label, "address": "203.0.113.10", "region": "Frankfurt"})
    }

    #[test]
    fn server_lists_are_read_strictly() {
        let good = json!({"servers": [server_json("vps:123", "vps", "my node"), server_json("bare_metal:7", "bare_metal", "")]});
        let servers = servers_reply(200, &good.to_string()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].id.as_str(), "vps:123");
        assert_eq!(servers[1].address, Ipv4Addr::new(203, 0, 113, 10));

        let many = json!({"servers": vec![server_json("vps:1", "vps", "x"); MAX_SERVERS + 1]});
        for bad in [
            json!({"servers": [server_json("vps:123", "bare_metal", "x")]}).to_string(),
            json!({"servers": [server_json("vps:0123", "vps", "x")]}).to_string(),
            json!({"servers": [server_json("vps:../1", "vps", "x")]}).to_string(),
            json!({"servers": [server_json("vps:1", "vps", "\u{1b}]0;title\u{7}")]}).to_string(),
            json!({"servers": [server_json("vps:1", "vps", "a\u{202e}b")]}).to_string(),
            json!({"servers": [server_json("vps:1", "vps", &"x".repeat(65))]}).to_string(),
            json!({"servers": [], "extra": 1}).to_string(),
            r#"{"servers":[],"servers":[]}"#.to_owned(),
            many.to_string(),
        ] {
            assert!(
                matches!(
                    servers_reply(200, &bad),
                    Err(Error::Api(ApiError::Malformed(_)))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn refusals_are_named_only_with_their_own_status() {
        let body = |code: &str| json!({"error": code}).to_string();
        for (status, code, refusal) in [
            (400, "invalid_security_check", Refusal::Invalid),
            (403, "source_mismatch", Refusal::SourceMismatch),
            (403, "server_not_eligible", Refusal::NotEligible),
            (403, "security_check_denied", Refusal::Denied),
            (404, "not_found", Refusal::NotFound),
            (409, "security_check_active", Refusal::Active),
            (429, "security_check_limited", Refusal::Limited),
            (503, "security_check_unavailable", Refusal::Unavailable),
        ] {
            assert!(
                matches!(start_reply(status, &body(code)), Err(Error::Refused(r)) if r == refusal),
                "{code}"
            );
        }
        assert!(matches!(
            start_reply(500, &body("source_mismatch")),
            Err(Error::Api(ApiError::Status(500)))
        ));
        assert!(matches!(
            start_reply(403, "arbitrary text"),
            Err(Error::Api(ApiError::Status(403)))
        ));
        assert!(matches!(
            start_reply(401, &body("source_mismatch")),
            Err(Error::Api(ApiError::Unauthorized))
        ));
        let started = json!({"id": "123e4567-e89b-42d3-a456-426614174000", "status": "running"});
        assert!(start_reply(202, &started.to_string()).is_ok());
        for bad in [
            json!({"id": "123e4567-e89b-42d3-a456-426614174000", "status": "done"}),
            json!({"id": "../servers", "status": "running"}),
            json!({"id": "123e4567-e89b-42d3-a456-426614174000", "status": "running", "x": 1}),
        ] {
            assert!(start_reply(202, &bad.to_string()).is_err(), "{bad}");
        }
    }

    fn report() -> serde_json::Value {
        json!({
            "check": "server_security_v1",
            "server": "vps:123",
            "coverage": {"external": "complete", "local": "complete"},
            "external": {"tcp": [{"port": 8899, "service": "solana_rpc", "tls": false}], "udp": []},
            "findings": [
                {"id": "solana_full_rpc_api_public", "severity": "critical",
                 "refs": [{"source": "external_tcp", "index": 0}, {"source": "solana", "index": 0}], "advisories": []},
                {"id": "package_vulnerable", "severity": "high",
                 "refs": [{"source": "package", "index": 0}], "advisories": ["CVE-2024-6387", "USN-6859-1"]},
                {"id": "ssh_password_auth", "severity": "high", "refs": [{"source": "ssh", "index": 0}], "advisories": []}
            ],
            "paths": [{"kind": "service_disruption", "steps": [0]}, {"kind": "remote_code_execution", "steps": [2, 1]}]
        })
    }

    fn poll(body: &serde_json::Value) -> Result<Poll, Error> {
        poll_reply(200, &body.to_string(), &server(), &inventory())
    }

    #[test]
    fn a_report_must_match_the_request_and_stay_in_range() {
        assert!(matches!(
            poll(&json!({"status": "running"})),
            Ok(Poll::Running)
        ));
        assert!(matches!(
            poll(&json!({"status": "failed", "reason": "scan_failed"})),
            Ok(Poll::Failed(FailReason::ScanFailed))
        ));
        let done = poll(&json!({"status": "done", "report": report()}));
        assert!(
            matches!(&done, Ok(Poll::Done(r)) if r.findings.len() == 3 && r.paths[1].steps == [2, 1])
        );

        let edit = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = report();
            change(&mut value);
            json!({"status": "done", "report": value})
        };
        for bad in [
            json!({"status": "running", "report": report()}),
            json!({"status": "done"}),
            json!({"status": "failed", "reason": "arbitrary text"}),
            json!({"status": "running", "note": "arbitrary text"}),
            edit(&|r| r["server"] = json!("vps:124")),
            edit(&|r| r["check"] = json!("solana_rpc_bind")),
            edit(&|r| r["findings"][0]["id"] = json!("arbitrary_text")),
            edit(&|r| r["findings"][0]["refs"][0]["index"] = json!(1)),
            edit(&|r| r["findings"][0]["refs"][1] = json!({"source": "key", "index": 1})),
            edit(&|r| r["findings"][2]["refs"][0]["index"] = json!(1)),
            edit(&|r| r["findings"][1]["advisories"] = json!(["CVE-24-1"])),
            edit(&|r| r["findings"][1]["advisories"] = json!(["CVE-2024-6387 and more"])),
            edit(&|r| r["findings"][0]["note"] = json!("arbitrary text")),
            edit(&|r| r["paths"][1]["steps"] = json!([2, 2])),
            edit(&|r| r["paths"][1]["steps"] = json!([3])),
            edit(&|r| r["paths"][1]["steps"] = json!([])),
            edit(&|r| r["external"]["tcp"][0]["banner"] = json!("arbitrary text")),
        ] {
            assert!(
                matches!(poll(&bad), Err(Error::Api(ApiError::Malformed(_)))),
                "{bad}"
            );
        }
        assert!(matches!(
            poll_reply(
                404,
                &json!({"error": "not_found"}).to_string(),
                &server(),
                &inventory()
            ),
            Err(Error::Refused(Refusal::NotFound))
        ));
    }

    #[test]
    fn advisories_take_the_four_id_forms_only() {
        for good in [
            "CVE-2024-6387",
            "CVE-2021-1234567",
            "GHSA-jfh8-c2jp-5v3q",
            "USN-6859-1",
            "DSA-5724-1",
        ] {
            assert!(Advisory::try_from(good.to_owned()).is_ok(), "{good}");
        }
        for bad in [
            "",
            "CVE-2024-123",
            "CVE-2024-6387 ",
            "GHSA-jfh8-c2jp-5v3",
            "GHSA-JFH8-C2JP-5V3Q",
            "USN-1-1",
            "RHSA-2024:1234",
        ] {
            assert!(Advisory::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }
}
