// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Security check entry points for authenticated ERPC server rentals.

#[path = "posture_billing.rs"]
mod billing;

#[path = "posture_details.rs"]
mod posture_details;

#[path = "posture_keys.rs"]
mod posture_keys;

#[path = "posture_view.rs"]
mod posture_view;

use posture_details::{
    Firewall, FirewallEvidence, Jail, Metadata, Ports, Ssh, Switch, UpdateStatus, Updates,
};

use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use erpc_ai::session::Access as _;
use erpc_auth::client::{JsonResponseLimits, REQUEST_TIMEOUT};
use erpc_auth::credential::Audience;
use erpc_auth::{AuthClient, HttpError};
use erpc_core::endpoints::{
    SECURITY_CHECK_QUOTE_URL, SECURITY_CHECK_SELECT_URL, SECURITY_CHECK_SERVERS_URL,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::account::commands::{Outcome, Said};
use crate::ai::vps_access::HostLogin;

#[derive(clap::Args)]
#[command(next_help_heading = "Server Security Check")]
pub(crate) struct Args {
    /// Run a metered, read-only posture check for an eligible ERPC rental.
    #[arg(long, conflicts_with_all = ["message", "continue_last", "model"])]
    security_check: bool,
    /// List eligible server rentals from the signed-in ERPC account.
    #[arg(long, requires = "security_check", conflicts_with_all = ["kind", "id", "host_key"])]
    list: bool,
    /// Limit the security check to this kind of ERPC rental.
    #[arg(long, value_enum, requires_all = ["security_check", "id"])]
    kind: Option<Kind>,
    /// Use the numeric part of the ERPC rental ID shown by --list.
    #[arg(long, requires_all = ["security_check", "kind"])]
    id: Option<u64>,
    /// Verify SSH against this independently trusted Ed25519 host public key.
    #[arg(long, requires_all = ["security_check", "kind", "id", "ssh_user"])]
    host_key: Option<String>,
    /// Use this SSH login with the independently trusted host public key.
    #[arg(long, requires = "host_key")]
    ssh_user: Option<String>,
    /// After the report, print every result the check read, as a detailed
    /// list. --json is the same with or without it.
    #[arg(long, requires = "security_check", conflicts_with = "list")]
    details: bool,
}

impl Args {
    pub(crate) async fn run(self, json: bool) -> Option<Outcome> {
        if !self.security_check {
            return None;
        }
        Some(if self.list {
            list(json).await
        } else {
            menu(
                json,
                self.details,
                self.kind.zip(self.id),
                self.host_key.zip(self.ssh_user),
            )
            .await
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Vps,
    BareMetal,
}

impl Kind {
    const fn wire(self) -> &'static str {
        match self {
            Self::Vps => "vps",
            Self::BareMetal => "bare_metal",
        }
    }

    /// The kind as `--kind` takes it: `vps` or `bare-metal`.
    fn flag(self) -> String {
        clap::ValueEnum::to_possible_value(&self)
            .map(|value| value.get_name().to_owned())
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize)]
struct Server {
    kind: Kind,
    id: u64,
}

impl Server {
    fn canonical_id(self) -> String {
        format!("{}:{}", self.kind.wire(), self.id)
    }
}

fn region(value: &str) -> Option<&'static str> {
    [
        "amsterdam",
        "frankfurt",
        "ny",
        "chicago",
        "stockholm",
        "saltlakecity",
        "tokyo",
        "london",
        "singapore",
        "dublin",
        "sydney",
        "losangeles",
        "hongkong",
    ]
    .into_iter()
    .find(|region| *region == value)
}

fn inventory_failed() -> Outcome {
    Outcome::Failed(t!("node_check.inventory_failed"))
}

// The account API stores IDs as safe JavaScript integers.
const MAX_RENTAL_ID: u64 = (1 << 53) - 1;
const MAX_INVENTORY_SERVERS: usize = 256;
const INVENTORY_LIMITS: JsonResponseLimits = preflight_limits(128 * 1024);
const SELECTION_LIMITS: JsonResponseLimits = preflight_limits(4096);
const QUOTE_LIMITS: JsonResponseLimits = preflight_limits(4096);

const fn preflight_limits(ok_bytes: usize) -> JsonResponseLimits {
    JsonResponseLimits {
        timeout: REQUEST_TIMEOUT,
        ok_bytes,
        other_bytes: 1024,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListedServer {
    id: String,
    kind: Kind,
    #[serde(rename = "label")]
    _label: String,
    address: Ipv4Addr,
    region: String,
}

impl ListedServer {
    fn project(self) -> Option<EligibleServer> {
        let (_, id) = self.id.split_once(':')?;
        let id = id.parse::<u64>().ok()?;
        let rental = Server {
            kind: self.kind,
            id,
        };
        if !(1..=MAX_RENTAL_ID).contains(&id)
            || self.id != rental.canonical_id()
            || !erpc_api::udp::is_public_destination(self.address)
        {
            return None;
        }
        Some(EligibleServer {
            rental,
            address: self.address,
            region: region(&self.region),
        })
    }
}

struct EligibleServer {
    rental: Server,
    address: Ipv4Addr,
    region: Option<&'static str>,
}

impl EligibleServer {
    fn label(&self) -> String {
        let id = self.rental.canonical_id();
        match self.region {
            Some(region) => format!("{id}  {region}"),
            None => id,
        }
    }

    fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.rental.kind,
            "id": self.rental.canonical_id(),
            "region": self.region,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EligibleReply {
    servers: Vec<ListedServer>,
}

fn parse_eligible(body: &str) -> Option<Vec<EligibleServer>> {
    if body.len() > INVENTORY_LIMITS.ok_bytes {
        return None;
    }
    let EligibleReply { servers } = serde_json::from_str(body).ok()?;
    if servers.len() > MAX_INVENTORY_SERVERS {
        return None;
    }
    let mut rentals = HashSet::with_capacity(servers.len());
    let mut eligible = Vec::with_capacity(servers.len());
    for listed in servers {
        let server = listed.project()?;
        if !rentals.insert(server.rental) {
            return None;
        }
        eligible.push(server);
    }
    Some(eligible)
}

fn selection_body(server: Server) -> serde_json::Value {
    serde_json::json!({ "server": server.canonical_id() })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preflight {
    status: String,
    checks: PreflightChecks,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightChecks {
    session: String,
    rental: String,
    provisioning: String,
    listeners: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionReply {
    server: ListedServer,
    report: Preflight,
}

struct AuthorizedServer {
    rental: Server,
    address: Ipv4Addr,
}

fn verify_selection(
    status: u16,
    body: &str,
    selected: &EligibleServer,
) -> Result<AuthorizedServer, Outcome> {
    let refused = || Outcome::Failed(t!("node_check.preflight_failed"));
    match status {
        200 if body.len() <= SELECTION_LIMITS.ok_bytes => {}
        401 => return Err(sign_in()),
        _ => return Err(refused()),
    }
    let SelectionReply { server, report } = serde_json::from_str(body).map_err(|_| refused())?;
    let server = server.project().ok_or_else(refused)?;
    (server.rental == selected.rental
        && server.address == selected.address
        && report.status == "preflight-only"
        && report.checks.session == "verified"
        && report.checks.rental == "active"
        && report.checks.provisioning == "ready"
        && report.checks.listeners == "not-observed")
        .then_some(AuthorizedServer {
            rental: selected.rental,
            address: server.address,
        })
        .ok_or_else(refused)
}

fn list_body(status: u16, body: String) -> Result<Zeroizing<String>, Outcome> {
    let body = Zeroizing::new(body);
    match status {
        200 => Ok(body),
        401 => Err(sign_in()),
        _ => Err(inventory_failed()),
    }
}

struct Account {
    client: AuthClient,
    access: crate::ai::StoreAccess,
}

impl Account {
    fn open() -> Result<Self, Outcome> {
        let client = AuthClient::new().map_err(|_| inventory_failed())?;
        let access = crate::ai::StoreAccess::open(client.clone()).map_err(|_| sign_in())?;
        Ok(Self { client, access })
    }

    async fn read_list(
        &self,
        url: &str,
        limits: JsonResponseLimits,
    ) -> Result<Zeroizing<String>, Outcome> {
        let token = self.access.access_token().await.map_err(|_| sign_in())?;
        let (status, body) = self
            .client
            .get_with_token_bounded(Audience::AuthApi, url, &token, limits)
            .await
            .map_err(|error| match error {
                HttpError::ResponseLimit { status: 401, .. } => sign_in(),
                _ => inventory_failed(),
            })?;
        list_body(status, body)
    }

    /// The price quote, or why there is none: the HTTP status and the
    /// service's allowlisted error code, a timeout or a failed request.
    async fn read_quote(&self) -> Result<Zeroizing<String>, Outcome> {
        let token = self.access.access_token().await.map_err(|_| sign_in())?;
        quote_reply(
            self.client
                .get_with_token_bounded(
                    Audience::AuthApi,
                    SECURITY_CHECK_QUOTE_URL,
                    &token,
                    QUOTE_LIMITS,
                )
                .await,
        )
    }

    async fn eligible(&self) -> Result<Vec<EligibleServer>, Outcome> {
        let body = self
            .read_list(SECURITY_CHECK_SERVERS_URL, INVENTORY_LIMITS)
            .await?;
        parse_eligible(&body).ok_or_else(inventory_failed)
    }

    async fn select_rental(&self, server: Server) -> Result<(u16, Zeroizing<String>), Outcome> {
        let refused = || Outcome::Failed(t!("node_check.preflight_failed"));
        let token = self.access.access_token().await.map_err(|_| sign_in())?;
        let request = selection_body(server);
        let (status, body) = self
            .client
            .post_with_token_bounded(
                Audience::AuthApi,
                SECURITY_CHECK_SELECT_URL,
                &token,
                request.to_string().into_bytes(),
                None,
                SELECTION_LIMITS,
            )
            .await
            .map_err(|error| match error {
                HttpError::ResponseLimit { status: 401, .. } => sign_in(),
                _ => refused(),
            })?;
        Ok((status, Zeroizing::new(body)))
    }
}

/// The quote's body, or what the operator is told instead.
fn quote_reply(reply: Result<(u16, String), HttpError>) -> Result<Zeroizing<String>, Outcome> {
    use billing::QuoteFailure as Failure;
    let (status, body) = reply.map_err(|error| match error {
        HttpError::ResponseLimit { status: 401, .. } => sign_in(),
        HttpError::ResponseLimit { status, .. } => Failure::Oversized(status).outcome(),
        HttpError::Timeout { .. } => Failure::Timeout.outcome(),
        HttpError::Malformed { .. } => Failure::Unreadable.outcome(),
        _ => Failure::Transport.outcome(),
    })?;
    let body = Zeroizing::new(body);
    match status {
        200 => Ok(body),
        401 => Err(sign_in()),
        _ => Err(Failure::refused(status, &body).outcome()),
    }
}

fn sign_in() -> Outcome {
    Outcome::NoSession(t!("node_check.sign_in"))
}

async fn list(json: bool) -> Outcome {
    let account = match Account::open() {
        Ok(account) => account,
        Err(outcome) => return outcome,
    };
    let servers = match account.eligible().await {
        Ok(servers) => servers,
        Err(outcome) => return outcome,
    };
    if json {
        let summaries = servers
            .iter()
            .map(EligibleServer::summary)
            .collect::<Vec<_>>();
        return Said::Json(serde_json::json!({ "servers": summaries })).done();
    }
    if servers.is_empty() {
        return Outcome::Done(t!("node_check.no_servers"));
    }
    let labels = servers
        .iter()
        .map(EligibleServer::label)
        .collect::<Vec<_>>();
    Outcome::Done(labels.join("\n"))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Nftables {
    TablesPresent,
    NoTablesObserved,
    NotObserved,
}

impl Nftables {
    fn report(&self) -> String {
        match self {
            Self::TablesPresent => t!("node_check.nftables_present"),
            Self::NoTablesObserved => t!("node_check.nftables_empty"),
            Self::NotObserved => t!("node_check.nftables_unknown"),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Posture {
    listeners: erpc_api::node_check::Finding,
    nftables: Nftables,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ports: Option<Ports>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh: Option<Ssh>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    firewall: Option<Firewall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fail2ban: Option<Jail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<Metadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updates: Option<Updates>,
    /// The plain-text key search: local to this screen, never in the
    /// billing facts, and without its places in `--json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keys: Option<posture_keys::Keys>,
}

impl Posture {
    fn valid(&self) -> bool {
        self.ports.as_ref().is_none_or(Ports::valid)
            && self.metadata.as_ref().is_none_or(Metadata::valid)
            && self.updates.as_ref().is_none_or(Updates::valid)
            && self.keys.as_ref().is_none_or(posture_keys::Keys::valid)
    }

    /// The local findings, by id, for `localFindings`: the `EnvironmentFile`
    /// policy review, then those the key search raises.
    fn local_findings(&self) -> Vec<&'static str> {
        let mut ids = Vec::new();
        if self
            .metadata
            .as_ref()
            .is_some_and(Metadata::has_environment_reference)
        {
            ids.push("review_env_file_use");
        }
        if let Some(keys) = &self.keys {
            ids.extend(keys.findings());
        }
        ids
    }

    pub(super) fn report(&self) -> String {
        let mut text = String::new();
        let _ = writeln!(
            text,
            "{}\n{}",
            super::check::summary(self.listeners),
            self.nftables.report()
        );
        if let Some(ports) = &self.ports {
            ports.describe(&mut text);
        }
        if let Some(ssh) = &self.ssh {
            ssh.describe(&mut text);
        }
        if let Some(firewall) = &self.firewall {
            firewall.describe(&mut text);
        }
        if let Some(jail) = self.fail2ban {
            jail.describe(&mut text);
        }
        if let Some(metadata) = &self.metadata {
            metadata.describe(&mut text);
        }
        if let Some(updates) = &self.updates {
            updates.describe(&mut text);
        }
        if let Some(keys) = &self.keys {
            keys.describe(&mut text);
        }
        text.push_str(&t!("node_check.remote_limits"));
        text
    }

    pub(super) fn billing_facts(&self) -> serde_json::Value {
        let (tcp, udp) = self
            .ports
            .as_ref()
            .map_or(("unknown", "unknown"), Ports::facts);
        let (redis_binding, daemon_review) = self
            .ports
            .as_ref()
            .map_or(("unknown", "unknown"), Ports::category_facts);
        let (service_env, credential_sources) = self
            .metadata
            .as_ref()
            .map_or(("unknown", "unknown"), Metadata::facts);
        serde_json::json!({
            "listeners": self.listeners,
            "nftables": self.nftables,
            "tcp": tcp,
            "udp": udp,
            "redis_binding": redis_binding,
            "daemon_review": daemon_review,
            "ssh_password": self.ssh.as_ref().map_or(Switch::Unknown, |ssh| ssh.password.billing_fact()),
            "ssh_keyboard_interactive": self.ssh.as_ref().map_or(Switch::Unknown, |ssh| ssh.keyboard_interactive.billing_fact()),
            "firewall_ipv4": self.firewall.as_ref().map_or(FirewallEvidence::Unknown, |filter| filter.ipv4),
            "firewall_ipv6": self.firewall.as_ref().map_or(FirewallEvidence::Unknown, |filter| filter.ipv6),
            "fail2ban": self.fail2ban.unwrap_or(Jail::Unknown),
            "service_env": service_env,
            "credential_sources": credential_sources,
            "updates": self.updates.as_ref().map_or(UpdateStatus::Unknown, |updates| updates.status),
        })
    }
}

/// How the check logs in to `rental` at `address`, from `identity` (the
/// key erpc logs in with) and the host key it checks: `--host-key` with
/// `--ssh-user`, else erpc's pin of this VPS from `pinned`. When it cannot,
/// a line for each piece it lacks. Read on this machine only: nothing
/// reaches the server or the account.
fn login(
    (rental, address): (Server, Ipv4Addr),
    explicit_key: Option<(&str, &str)>,
    identity: Option<erpc_ssh::Identity>,
    pinned: impl FnOnce(&str, u64) -> Option<HostLogin>,
) -> Result<erpc_ssh::Target, String> {
    let host = address.to_string();
    let host_login = match explicit_key {
        Some((key, user)) => erpc_ssh::HostKey::parse(key)
            .map(|host_key| HostLogin {
                host_key,
                user: user.to_owned(),
                port: 22,
            })
            .map_err(|_| t!("node_check.login_bad_host_key")),
        None => (rental.kind == Kind::Vps)
            .then(|| pinned(&host, rental.id))
            .flatten()
            .ok_or_else(|| {
                t!(
                    "node_check.login_no_pin",
                    kind = rental.kind.flag(),
                    id = rental.id
                )
            }),
    };
    match (identity, host_login) {
        (Some(identity), Ok(host_login)) => Ok(host_login.target(host, identity)),
        (identity, host_login) => {
            let mut missing = Vec::new();
            if identity.is_none() {
                missing.push(t!("node_check.login_no_identity"));
            }
            missing.extend(host_login.err());
            Err(missing.join("\n"))
        }
    }
}

/// [`login`] with this machine's key and pins.
fn login_here(
    rental: Server,
    address: Ipv4Addr,
    explicit_key: Option<(&str, &str)>,
) -> Result<erpc_ssh::Target, String> {
    login(
        (rental, address),
        explicit_key,
        crate::ai::vps_access::security_identity(),
        crate::ai::vps_access::security_pin,
    )
}

/// Stops a run that cannot log in to `server` before anything is asked or
/// quoted, saying which piece is missing.
fn able_to_log_in(
    server: &EligibleServer,
    login: Result<erpc_ssh::Target, String>,
) -> Result<(), Outcome> {
    login.map(drop).map_err(|missing| {
        Outcome::Failed(format!(
            "{}\n{missing}",
            t!(
                "node_check.login_unavailable",
                server = server.rental.canonical_id()
            )
        ))
    })
}

fn observe_remote(
    server: &AuthorizedServer,
    explicit_key: Option<(&str, &str)>,
) -> Result<Posture, Outcome> {
    // Read again for the verified address: what was found before the
    // questions may have changed since.
    let target = login_here(server.rental, server.address, explicit_key).map_err(|missing| {
        Outcome::Failed(format!("{}\n{missing}", t!("node_check.remote_failed")))
    })?;
    collect_posture(&target).map_err(|failure| Outcome::Failed(failure.message()))
}

#[derive(Debug)]
enum PostureFailure {
    HostConfig,
    Capture(erpc_ssh::PrivateCaptureError),
    InvalidJson,
    InvalidPosture,
}

impl PostureFailure {
    fn message(&self) -> String {
        format!(
            "{}\n{} [{}]",
            t!("node_check.remote_failed"),
            self.reason(),
            self.code()
        )
    }

    fn code(&self) -> &'static str {
        match self {
            Self::HostConfig => "ssh_config",
            Self::Capture(failure) => failure.code(),
            Self::InvalidJson => "invalid_json",
            Self::InvalidPosture => "invalid_posture",
        }
    }

    fn reason(&self) -> String {
        use erpc_ssh::PrivateCaptureError as Capture;

        match self {
            Self::HostConfig => t!("node_check.diag_config"),
            Self::InvalidJson => t!("node_check.diag_json"),
            Self::InvalidPosture => t!("node_check.diag_posture"),
            Self::Capture(error) => match error {
                Capture::InvalidLimits => t!("node_check.diag_invalid_limits"),
                Capture::Start => t!("node_check.diag_start"),
                Capture::Io => t!("node_check.diag_io"),
                Capture::Timeout => t!("node_check.diag_timeout"),
                Capture::OutputLimit => t!("node_check.diag_output_limit"),
                Capture::HostKey => t!("node_check.diag_host_key"),
                Capture::AgentDenied => t!("node_check.diag_agent"),
                Capture::AuthenticationDenied => t!("node_check.diag_authentication"),
                Capture::TransportTimeout => t!("node_check.diag_transport_timeout"),
                Capture::TransportFailure => t!("node_check.diag_transport_failure"),
                Capture::SshExit => t!("node_check.diag_ssh_exit"),
                Capture::Exit(status) => t!("node_check.diag_exit", status = status),
                Capture::UnexpectedStderr => t!("node_check.diag_stderr"),
            },
        }
    }
}

fn decode_posture(output: &[u8]) -> Result<Posture, PostureFailure> {
    let posture: Posture = serde_json::from_slice(output).map_err(|error| {
        if error.is_syntax() || error.is_eof() {
            PostureFailure::InvalidJson
        } else {
            PostureFailure::InvalidPosture
        }
    })?;
    if !posture.valid() {
        return Err(PostureFailure::InvalidPosture);
    }
    Ok(posture)
}

fn collect_posture(target: &erpc_ssh::Target) -> Result<Posture, PostureFailure> {
    let session = erpc_ssh::Session::open(target).map_err(|_| PostureFailure::HostConfig)?;
    let result = session.run_posture().map_err(PostureFailure::Capture)?;
    decode_posture(result.expose())
}

fn select_server(
    servers: Vec<EligibleServer>,
    selection: Option<(Kind, u64)>,
) -> Result<Option<EligibleServer>, Outcome> {
    let mut servers = servers;
    if let Some((kind, id)) = selection {
        return servers
            .into_iter()
            .find(|server| server.rental == (Server { kind, id }))
            .map(Some)
            .ok_or_else(|| Outcome::Failed(t!("node_check.server_ineligible")));
    }
    let mut picker = cliclack::select(t!("node_check.select_server"))
        .item(None, t!("node_check.cancel"), "")
        .initial_value(None);
    for (index, server) in servers.iter().enumerate() {
        picker = picker.item(Some(index), server.label(), "");
    }
    match picker.interact() {
        Ok(Some(index)) => Ok(Some(servers.swap_remove(index))),
        Ok(None) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(None),
        Err(_) => Err(Outcome::Failed(t!("node_check.menu_failed"))),
    }
}

fn inspection_scope(server: &EligibleServer) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        t!("node_check.remote_scope", server = server.label()),
        t!("node_check.keys_scope"),
        t!("node_check.readonly_sudo"),
        t!("node_check.authorization"),
    )
}

async fn menu(
    json: bool,
    details: bool,
    selection: Option<(Kind, u64)>,
    explicit_key: Option<(String, String)>,
) -> Outcome {
    if !crate::account::session::has_terminal() {
        return Outcome::NeedsTerminal(t!("node_check.terminal_required"));
    }
    let account = match Account::open() {
        Ok(account) => account,
        Err(outcome) => return outcome,
    };
    let servers = match account.eligible().await {
        Ok(servers) => servers,
        Err(outcome) => return outcome,
    };
    if servers.is_empty() && selection.is_none() {
        return Outcome::Done(t!("node_check.no_servers"));
    }
    let server = match select_server(servers, selection) {
        Ok(Some(server)) => server,
        Ok(None) => return Outcome::Done(String::new()),
        Err(outcome) => return outcome,
    };
    let explicit = explicit_key
        .as_ref()
        .map(|(key, user)| (key.as_str(), user.as_str()));
    let late_key = explicit_key.clone();
    let completed = run_selected(
        &server,
        |server| able_to_log_in(server, login_here(server.rental, server.address, explicit)),
        ask_confirmation,
        || async {
            tokio::time::timeout(std::time::Duration::from_secs(45), account.read_quote())
                .await
                .map_err(|_| billing::QuoteFailure::Timeout.outcome())?
        },
        async |rental| account.select_rental(rental).await,
        async |verified| collect_selected(verified, late_key).await,
        async |submission| submission.submit(&account).await,
    )
    .await;
    match completed {
        Ok(Some(completed)) => completed
            .render(&server, json, details, posture_view::Look::here())
            .done(),
        Ok(None) => Outcome::Done(String::new()),
        Err(outcome) => outcome,
    }
}

fn ask_confirmation(prompt: String) -> Result<bool, Outcome> {
    match cliclack::confirm(prompt).initial_value(false).interact() {
        Ok(answer) => Ok(answer),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(false),
        Err(_) => Err(Outcome::Failed(t!("node_check.menu_failed"))),
    }
}

struct Completed {
    id: String,
    result: Posture,
    model: Result<billing::Receipt, billing::ReportFailure>,
}

impl Completed {
    /// `--json`'s record, or the report a person reads, drawn as `look`
    /// says, with the full evidence after it under `details`.
    fn render(
        &self,
        server: &EligibleServer,
        json: bool,
        details: bool,
        look: posture_view::Look,
    ) -> Said {
        let Self { id, result, model } = self;
        if json {
            let mut output = serde_json::json!({
                "server": server.summary(), "source": "pinned_ssh", "posture": result, "requestId": id,
            });
            let local = result.local_findings();
            if !local.is_empty() {
                output["localFindings"] = local
                    .into_iter()
                    .map(|id| serde_json::json!({ "id": id, "source": "pinned_ssh" }))
                    .collect();
            }
            match model {
                Ok(receipt) => output["modelReport"] = serde_json::json!(receipt),
                Err(state) => {
                    output["reportSource"] = serde_json::json!("local_rules");
                    output["settlement"] = serde_json::json!(state.settlement);
                    output["settlementDetail"] = serde_json::json!(state);
                }
            }
            return Said::Json(output);
        }
        let evidence = details.then(|| self.evidence(server));
        Said::Text(posture_view::render(
            server,
            result,
            model,
            id,
            look,
            evidence.as_deref(),
        ))
    }

    /// Every result the check collected, as the report showed them before
    /// it was grouped: what `--details` prints after the report.
    fn evidence(&self, server: &EligibleServer) -> String {
        let message = match &self.model {
            Ok(receipt) => receipt.summary(),
            Err(state) => state.message(&self.id),
        };
        format!("{}\n{}\n{message}", server.label(), self.result.report())
    }
}

async fn run_selected(
    server: &EligibleServer,
    reach: impl FnOnce(&EligibleServer) -> Result<(), Outcome>,
    mut confirm: impl FnMut(String) -> Result<bool, Outcome>,
    quote: impl AsyncFnOnce() -> Result<Zeroizing<String>, Outcome>,
    select: impl AsyncFnOnce(Server) -> Result<(u16, Zeroizing<String>), Outcome>,
    observe: impl AsyncFnOnce(AuthorizedServer) -> Result<Posture, Outcome>,
    submit: impl AsyncFnOnce(
        billing::ReportSubmission,
    ) -> Result<billing::Receipt, billing::ReportFailure>,
) -> Result<Option<Completed>, Outcome> {
    // A run that cannot log in stops before anything is asked or quoted.
    reach(server)?;
    if !confirm(inspection_scope(server))? {
        return Ok(None);
    }
    let Some(approved) =
        billing::ApprovedReport::from_quote(&quote().await?, server.rental, confirm)?
    else {
        return Ok(None);
    };
    // Resolve the assignment again after consent and before opening SSH.
    let (status, body) = select(server.rental).await?;
    let verified = verify_selection(status, &body, server)?;
    let result = observe(verified).await?;
    let submission = approved.submission(&result);
    let id = submission.idempotency_key.clone();
    let model = submit(submission).await;
    Ok(Some(Completed { id, result, model }))
}

async fn collect_selected(
    verified: AuthorizedServer,
    explicit_key: Option<(String, String)>,
) -> Result<Posture, Outcome> {
    tokio::task::spawn_blocking(move || {
        let key = explicit_key
            .as_ref()
            .map(|(key, user)| (key.as_str(), user.as_str()));
        observe_remote(&verified, key)
    })
    .await
    .map_err(|_| Outcome::Failed(t!("node_check.remote_failed")))?
}

#[cfg(test)]
mod tests {
    use erpc_core::i18n::Lang;
    use serde_json::json;
    use zeroize::Zeroizing;

    use super::{
        Kind, Posture, PostureFailure, billing, decode_posture, inspection_scope, list_body,
        parse_eligible, select_server, selection_body, verify_selection,
    };

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FixtureQuote {
        Internal,
        Customer,
        WithFallback,
    }

    fn quote_fixture(valid: bool, terms: FixtureQuote) -> Zeroizing<String> {
        let mut quote = json!({
            "model":"fixture-model-a", "meterVersion":"posture1", "currency":"ai_credits",
            "baseCredits":512, "weights":{"input":3,"output":12},
            "limits":{"input":8192,"output":256},
            "maximumCredits": if valid { 28160 } else { 28161 },
        });
        if terms != FixtureQuote::Internal {
            quote["consentVersion"] = json!("security-check-local-posture-v1");
        }
        if terms == FixtureQuote::WithFallback {
            quote["fallback"] = json!({
                "model":"fixture-model-b", "meterVersion":"posture1", "currency":"ai_credits",
                "baseCredits":512, "weights":{"input":1,"output":3},
                "limits":{"input":8192,"output":256}, "maximumCredits":9472,
            });
        }
        Zeroizing::new(quote.to_string())
    }

    fn receipt_fixture(
        request: &billing::ReportSubmission,
        terms: FixtureQuote,
    ) -> billing::Receipt {
        let mut headers = vec![("idempotency-key", request.idempotency_key.as_str())];
        if terms != FixtureQuote::Internal {
            headers.push((
                "x-erpc-security-check-consent",
                "security-check-local-posture-v1",
            ));
        }
        if terms == FixtureQuote::WithFallback {
            headers.push(("x-erpc-security-check-fallback", "fixture-model-b"));
        }
        assert_eq!(request.headers(), headers);
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("prepared report");
        assert_eq!(body["requestId"], request.idempotency_key);
        assert_eq!(body["server"], "bare_metal:7");
        assert_eq!(body["maximumCredits"], 28160);
        assert_eq!(body["posture"]["listeners"], "no_listener");
        let wire = |model, charge| {
            json!({
                "status":"completed", "model":model, "findings":[],
                "billing":{"meterVersion":"posture1","chargedCredits":charge,
                    "baseCredits":512,"inputTokens":1,"outputTokens":1},
            })
            .to_string()
        };
        let fallback = wire("fixture-model-b", 516);
        if terms == FixtureQuote::WithFallback {
            request
                .fixture_receipt(&fallback)
                .expect("approved fallback receipt")
        } else {
            assert!(request.fixture_receipt(&fallback).is_err());
            request
                .fixture_receipt(&wire("fixture-model-a", 527))
                .expect("approved primary receipt")
        }
    }

    fn selection_fixture(
        mut selected: serde_json::Value,
        lease_valid: bool,
    ) -> (u16, Zeroizing<String>) {
        if !lease_valid {
            selected["address"] = json!("8.8.8.5");
        }
        let body = json!({
            "server": selected,
            "report": { "status": "preflight-only", "checks": {
                "session": "verified", "rental": "active",
                "provisioning": "ready", "listeners": "not-observed",
            } },
        });
        (200, Zeroizing::new(body.to_string()))
    }

    #[tokio::test]
    async fn production_security_check_gates_ssh_and_metered_submission() {
        use self::FixtureQuote::{Customer, Internal, WithFallback};
        use crate::account::commands::Outcome;
        use std::cell::RefCell;

        let listed = json!({
            "id": "bare_metal:7", "kind": "bare_metal", "label": "fixture",
            "address": "8.8.8.4", "region": "tokyo",
        });
        let mut eligible = parse_eligible(&json!({"servers": [listed.clone()]}).to_string())
            .expect("eligible fixture");
        let server = eligible.pop().expect("fixture server");
        let completed = &[
            "login", "scope", "quote", "price", "verify", "ssh", "submit",
        ][..];
        for (refusal, quote_valid, lease_valid, terms, expected) in [
            (Some("scope"), true, true, Internal, &["login", "scope"][..]),
            (None, false, true, Internal, &["login", "scope", "quote"]),
            (
                Some("price"),
                true,
                true,
                WithFallback,
                &["login", "scope", "quote", "price"],
            ),
            (
                None,
                true,
                false,
                Internal,
                &["login", "scope", "quote", "price", "verify"],
            ),
            (None, true, true, Internal, completed),
            (None, true, true, Customer, completed),
            (None, true, true, WithFallback, completed),
        ] {
            let steps = RefCell::new(Vec::new());
            let result = super::run_selected(
                &server,
                |_| {
                    steps.borrow_mut().push("login");
                    Ok(())
                },
                |prompt| {
                    assert!(!prompt.contains("fixture-model"), "{prompt}");
                    let stage = if prompt.contains("authorized to assess") {
                        "scope"
                    } else {
                        assert!(prompt.contains("28160"));
                        if terms != Internal {
                            assert!(prompt.contains("bare_metal:7"));
                            assert_eq!(prompt.contains("9472"), terms == WithFallback);
                        }
                        "price"
                    };
                    steps.borrow_mut().push(stage);
                    Ok(refusal != Some(stage))
                },
                async || {
                    steps.borrow_mut().push("quote");
                    Ok(quote_fixture(quote_valid, terms))
                },
                async |rental| {
                    steps.borrow_mut().push("verify");
                    assert_eq!(rental.canonical_id(), "bare_metal:7");
                    Ok(selection_fixture(listed.clone(), lease_valid))
                },
                async |verified| {
                    steps.borrow_mut().push("ssh");
                    assert_eq!(verified.rental.canonical_id(), "bare_metal:7");
                    assert_eq!(verified.address.to_string(), "8.8.8.4");
                    Ok(
                        decode_posture(br#"{"listeners":"no_listener","nftables":"not_observed"}"#)
                            .expect("fixed SSH fixture"),
                    )
                },
                async |request| {
                    steps.borrow_mut().push("submit");
                    Ok(receipt_fixture(&request, terms))
                },
            )
            .await;
            assert_eq!(*steps.borrow(), expected);
            if !quote_valid || !lease_valid {
                assert!(matches!(result, Err(Outcome::Failed(_))));
            } else if refusal.is_some() {
                assert!(matches!(result, Ok(None)));
            } else {
                assert!(matches!(
                    result,
                    Ok(Some(super::Completed { model: Ok(_), .. }))
                ));
            }
        }
    }

    const LOGIN_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/";

    /// A machine for the login check: a home with the default key and one
    /// without, no `ssh_key` setting, `vps:9`'s pin, another VPS's pin at
    /// `vps:10`'s address, and at `bare_metal:7`'s address a pin of VPS 7,
    /// which a bare-metal rental never uses; and those three rentals.
    struct LoginFixture {
        dir: tempfile::TempDir,
        servers: Vec<super::EligibleServer>,
    }

    impl LoginFixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("dir");
            let ssh = dir.path().join("home/.ssh");
            std::fs::create_dir_all(&ssh).expect("ssh dir");
            std::fs::write(ssh.join("id_ed25519.pub"), format!("{LOGIN_KEY} fixture\n"))
                .expect("default key");
            std::fs::create_dir_all(dir.path().join("empty")).expect("empty home");
            let pin = |vps: u64| {
                json!({"hostKey": HOST_KEY, "user": "ubuntu", "port": 22,
                    "vpsId": vps, "keyOnly": true})
            };
            let pins = json!({"8.8.8.9": pin(9), "8.8.8.10": pin(11), "8.8.8.4": pin(7)});
            std::fs::write(dir.path().join("vps_hosts.json"), pins.to_string()).expect("pins");
            let row = |id: &str, kind: &str, address: &str| {
                json!({"id": id, "kind": kind, "label": "fixture",
                    "address": address, "region": "tokyo"})
            };
            let servers = parse_eligible(
                &json!({"servers": [
                    row("vps:9", "vps", "8.8.8.9"),
                    row("vps:10", "vps", "8.8.8.10"),
                    row("bare_metal:7", "bare_metal", "8.8.8.4"),
                ]})
                .to_string(),
            )
            .expect("eligible fixture");
            Self { dir, servers }
        }

        fn home(&self, with_key: bool) -> std::path::PathBuf {
            self.dir
                .path()
                .join(if with_key { "home" } else { "empty" })
        }

        /// [`super::login`] with this machine's key and pins, read as the
        /// check reads them.
        fn login(
            &self,
            server: &super::EligibleServer,
            with_key: bool,
            explicit: Option<(&str, &str)>,
        ) -> Result<erpc_ssh::Target, String> {
            let config = self.dir.path().join("config.toml");
            let pins = self.dir.path().join("vps_hosts.json");
            super::login(
                (server.rental, server.address),
                explicit,
                crate::ai::vps_access::security_identity_from(
                    Some(&config),
                    Some(&self.home(with_key)),
                    None,
                ),
                |ip, id| crate::ai::vps_access::security_pin_at(&pins, ip, id),
            )
        }
    }

    /// A run that cannot log in stops before the first question, and so
    /// before the quote is asked for, saying which piece is missing: the key
    /// erpc logs in with (`ssh_key`, else `~/.ssh/id_ed25519.pub`), or the
    /// host key (erpc's pin of this VPS, or `--host-key` with `--ssh-user`).
    #[tokio::test]
    async fn a_run_that_cannot_log_in_stops_before_the_questions_and_the_quote() {
        use crate::account::commands::Outcome;

        let machine = LoginFixture::new();
        let [pinned, unpinned, bare_metal] = &machine.servers[..] else {
            panic!("three fixture servers");
        };
        let no_key = "erpc config set ssh_key /path/to/key.pub";
        let no_pin = "--host-key '<public-key>' --ssh-user '<login>'";
        let bad_key = "The --host-key value is not an Ed25519 SSH host public key";
        for (server, with_key, explicit, said, unsaid) in [
            (pinned, false, None, vec![no_key], vec![no_pin, bad_key]),
            (
                unpinned,
                true,
                None,
                vec![no_pin, "--kind vps --id 10 "],
                vec![no_key, bad_key],
            ),
            (
                bare_metal,
                true,
                None,
                vec![no_pin, "--kind bare-metal --id 7 "],
                vec![no_key, bad_key],
            ),
            (unpinned, false, None, vec![no_key, no_pin], vec![bad_key]),
            (
                bare_metal,
                true,
                Some(("ssh-ed25519 not-base64", "root")),
                vec![bad_key],
                vec![no_key, no_pin],
            ),
        ] {
            let result = super::run_selected(
                server,
                |server| super::able_to_log_in(server, machine.login(server, with_key, explicit)),
                |_| panic!("a question was asked"),
                async || panic!("the quote was asked for"),
                async |_| panic!("the assignment was verified"),
                async |_| panic!("SSH was opened"),
                async |_| panic!("a report was sent"),
            )
            .await;
            let Err(Outcome::Failed(text)) = result else {
                panic!("a run that cannot log in must stop");
            };
            let lead = format!(
                "The check cannot log in to {}, so it stopped before asking for approval: \
                 nothing was quoted or reserved.\n",
                server.rental.canonical_id()
            );
            assert!(text.starts_with(&lead), "{text}");
            for piece in said {
                assert!(text.contains(piece), "{piece} not in {text}");
            }
            for piece in unsaid {
                assert!(!text.contains(piece), "{piece} in {text}");
            }
        }
    }

    /// With the key and the host key, the login is the pinned one (or the
    /// one given) with the key beside home, and the run goes on to the
    /// first question.
    #[tokio::test]
    async fn a_run_with_a_key_and_a_host_key_goes_on_to_the_questions() {
        let machine = LoginFixture::new();
        let [pinned, _, bare_metal] = &machine.servers[..] else {
            panic!("three fixture servers");
        };
        let target = machine.login(pinned, true, None).expect("logs in");
        assert_eq!(
            (target.host.as_str(), target.port, target.user.as_str()),
            ("8.8.8.9", 22, "ubuntu")
        );
        assert_eq!(target.host_key.to_openssh(), HOST_KEY);
        assert_eq!(
            target.identity,
            erpc_ssh::Identity::File(machine.home(true).join(".ssh/id_ed25519"))
        );
        let given = Some((HOST_KEY, "root"));
        let target = machine.login(bare_metal, true, given).expect("logs in");
        assert_eq!(
            (target.host.as_str(), target.port, target.user.as_str()),
            ("8.8.8.4", 22, "root")
        );
        for (server, explicit) in [(pinned, None), (bare_metal, given)] {
            let mut asked = Vec::new();
            let result = super::run_selected(
                server,
                |server| super::able_to_log_in(server, machine.login(server, true, explicit)),
                |prompt| {
                    asked.push(prompt);
                    Ok(false)
                },
                async || panic!("refused at the first question"),
                async |_| panic!("refused at the first question"),
                async |_| panic!("refused at the first question"),
                async |_| panic!("refused at the first question"),
            )
            .await;
            assert!(matches!(result, Ok(None)));
            assert_eq!(asked.len(), 1);
            assert!(asked[0].contains("authorized to assess"), "{}", asked[0]);
        }
    }

    #[test]
    fn security_check_endpoints_accept_only_the_account_access_audience() {
        use erpc_auth::allowlist::ensure_token_destination;
        use erpc_auth::credential::Audience;
        use erpc_core::endpoints::{
            SECURITY_CHECK_QUOTE_URL, SECURITY_CHECK_REPORT_URL, SECURITY_CHECK_SELECT_URL,
            SECURITY_CHECK_SERVERS_URL,
        };

        for endpoint in [
            SECURITY_CHECK_SERVERS_URL,
            SECURITY_CHECK_SELECT_URL,
            SECURITY_CHECK_QUOTE_URL,
            SECURITY_CHECK_REPORT_URL,
        ] {
            assert!(ensure_token_destination(Audience::AuthApi, endpoint).is_ok());
            assert!(ensure_token_destination(Audience::McpUserApi, endpoint).is_err());
        }
    }

    #[tokio::test]
    async fn ambiguous_quotes_stop_before_price_approval_ssh_and_submission() {
        use crate::account::commands::Outcome;
        use zeroize::Zeroizing;

        let listed = json!({ "servers": [{
            "id": "bare_metal:7", "kind": "bare_metal", "label": "fixture",
            "address": "8.8.4.4", "region": "tokyo",
        }] });
        let server = parse_eligible(&listed.to_string())
            .expect("eligible fixture")
            .pop()
            .expect("fixture server");
        let quote = r#"{"model":"fixture-model-a","meterVersion":"posture1","currency":"ai_credits","baseCredits":512,"weights":{"input":3,"output":12},"limits":{"input":8192,"output":256},"maximumCredits":28160}"#;
        assert!(billing::ApprovedReport::from_quote(quote, server.rental, |_| Ok(false)).is_ok());
        let invalid_internal = [
            (
                r#""maximumCredits":28160"#,
                r#""maximumCredits":40000,"maximumCredits":28160"#,
            ),
            (
                r#""maximumCredits":28160"#,
                r#""maximum\u0043redits":40000,"maximumCredits":28160"#,
            ),
            (r#""output":12"#, r#""output":99,"output":12"#),
            (r#""input":8192"#, r#""inp\u0075t":9999,"input":8192"#),
            (r#"{"input":3,"output":12}"#, "[3,12]"),
        ]
        .map(|(key, bad)| quote.replace(key, bad));
        let external = quote_fixture(true, FixtureQuote::WithFallback);
        let invalid_external = [
            (
                r#""consentVersion":"security-check-local-posture-v1""#,
                r#""consent\u0056ersion":"unknown","consentVersion":"security-check-local-posture-v1""#,
            ),
            (
                r#""maximumCredits":9472"#,
                r#""maximum\u0043redits":9999,"maximumCredits":9472"#,
            ),
        ]
        .map(|(key, bad)| external.replace(key, bad));
        for invalid in invalid_internal.into_iter().chain(invalid_external) {
            let result = super::run_selected(
                &server,
                |_| Ok(()),
                |prompt| {
                    assert!(
                        prompt.contains("authorized to assess"),
                        "unexpected price prompt"
                    );
                    Ok(true)
                },
                async || Ok(Zeroizing::new(invalid)),
                async |_| panic!("invalid quote reached assignment verification"),
                async |_| panic!("invalid quote reached SSH"),
                async |_| panic!("invalid quote reached report submission"),
            )
            .await;
            assert!(matches!(result, Err(Outcome::Failed(_))));
        }
    }

    #[test]
    fn each_quote_reply_maps_to_its_reason() {
        use crate::account::commands::Outcome;
        use erpc_auth::HttpError;

        let host = "user-api.erpc.global";
        let reason = |reply: Result<(u16, String), HttpError>| match super::quote_reply(reply) {
            Ok(body) => format!("ok {}", body.as_str()),
            Err(Outcome::NoSession(_)) => "sign in".to_owned(),
            Err(Outcome::Failed(text)) => text.rsplit('\n').next().unwrap_or_default().to_owned(),
            Err(_) => "other".to_owned(),
        };
        let transport = || HttpError::Transport {
            host,
            reason: "private peer detail".to_owned(),
        };
        for (reply, expected) in [
            (Ok((200, "{}".to_owned())), "ok {}"),
            (Ok((401, String::new())), "sign in"),
            (
                Ok((403, r#"{"error":"posture_report_not_funded"}"#.to_owned())),
                "HTTP 403 (posture_report_not_funded)",
            ),
            (
                Ok((502, "private peer detail".to_owned())),
                "HTTP 502 (unknown_response)",
            ),
            (Err(HttpError::Timeout { host }), "[request_timeout]"),
            (Err(transport()), "[request_transport]"),
            (
                Err(HttpError::Malformed {
                    host,
                    reason: "private peer detail".to_owned(),
                }),
                "[unreadable_reply]",
            ),
            (
                Err(HttpError::ResponseLimit { host, status: 200 }),
                "HTTP 200 (response_limit)",
            ),
            (
                Err(HttpError::ResponseLimit { host, status: 401 }),
                "sign in",
            ),
        ] {
            assert_eq!(reason(reply), expected);
        }
    }

    #[test]
    fn rental_inventory_limits_rows_bytes_and_duplicates() {
        let row = |id| {
            json!({
                "id": format!("vps:{id}"), "kind": "vps", "label": "fixture",
                "address": "8.8.8.4", "region": "tokyo",
            })
        };
        let mut servers: Vec<_> = (1..=super::MAX_INVENTORY_SERVERS).map(row).collect();
        let eligible = parse_eligible(&json!({ "servers": servers }).to_string())
            .expect("inventory at supported capacity");
        assert_eq!(eligible.len(), 256);
        assert_eq!(eligible[0].rental.canonical_id(), "vps:1");
        assert_eq!(eligible[255].rental.canonical_id(), "vps:256");
        servers.push(row(257));
        assert!(parse_eligible(&json!({ "servers": servers }).to_string()).is_none());
        assert!(parse_eligible(&json!({ "servers": [row(1), row(1)] }).to_string()).is_none());
        let oversized = format!(
            "{{\"servers\":[]}}{}",
            " ".repeat(super::INVENTORY_LIMITS.ok_bytes)
        );
        assert!(parse_eligible(&oversized).is_none());
    }

    #[test]
    fn node_check_verifies_the_canonical_id_and_unchanged_public_assignment() {
        let wire_server = json!({
            "id": "bare_metal:7",
            "kind": "bare_metal",
            "label": "synthetic host details",
            "address": "8.8.8.4",
            "region": "tokyo",
        });
        let list = json!({ "servers": [wire_server.clone()] }).to_string();
        let eligible = || parse_eligible(&list).expect("eligible");
        assert!(select_server(eligible(), Some((Kind::Vps, 7))).is_err());
        let selected = select_server(eligible(), Some((Kind::BareMetal, 7)))
            .expect("active rental")
            .expect("selected");
        assert_eq!(
            selected.summary(),
            json!({ "kind": "bare_metal", "id": "bare_metal:7", "region": "tokyo" })
        );
        assert!(inspection_scope(&selected).contains("authorized to assess it"));
        assert!(inspection_scope(&selected).contains("without reselling it"));
        for language in [Lang::En, Lang::Ja, Lang::Ru, Lang::Zh] {
            let scope = crate::cli::i18n::speaking(language, || inspection_scope(&selected));
            assert!(scope.contains("bare_metal:7"), "{scope}");
            assert!(!scope.contains('%'), "{scope}");
            assert!(!scope.contains('{'), "{scope}");
        }
        assert_eq!(
            selection_body(selected.rental),
            json!({ "server": "bare_metal:7" })
        );
        let mut preflight = json!({
            "server": wire_server.clone(),
            "report": {
                "status": "preflight-only",
                "checks": { "session": "verified", "rental": "active", "provisioning": "ready", "listeners": "not-observed" }
            }
        });
        assert_eq!(
            verify_selection(200, &preflight.to_string(), &selected)
                .expect("verified public target")
                .address
                .to_string(),
            "8.8.8.4"
        );
        for status in [400, 401, 403, 404, 409, 500, 503] {
            assert!(list_body(status, list.clone()).is_err());
            assert!(verify_selection(status, &preflight.to_string(), &selected).is_err());
        }
        for (field, refused) in [
            ("kind", "vps"),
            ("id", "bare_metal:8"),
            ("address", "8.8.8.5"),
            ("address", "192.0.2.4"),
            ("address", "::ffff:8.8.8.4"),
        ] {
            preflight["server"][field] = json!(refused);
            assert!(verify_selection(200, &preflight.to_string(), &selected).is_err());
            preflight["server"] = wire_server.clone();
        }
        preflight["report"]["checks"]["rental"] = json!("expired");
        assert!(verify_selection(200, &preflight.to_string(), &selected).is_err());
    }

    #[test]
    fn node_check_rejects_malformed_wire_targets_and_displays_only_safe_fields() {
        let vps = json!({
            "id": "vps:9",
            "kind": "vps",
            "label": "synthetic host label",
            "address": "8.8.8.9",
            "region": "not an allowed region",
        });
        let parsed = parse_eligible(&json!({"servers": [vps.clone()]}).to_string())
            .expect("valid wire target");
        assert_eq!(parsed[0].label(), "vps:9");
        assert_eq!(
            parsed[0].summary(),
            json!({"id": "vps:9", "kind": "vps", "region": null}),
        );
        for invalid in [
            "vps:09",
            "vps:0",
            "vps:9007199254740992",
            "bare_metal:9",
            "9",
        ] {
            let mut row = vps.clone();
            row["id"] = json!(invalid);
            assert!(parse_eligible(&json!({"servers": [row]}).to_string()).is_none());
        }
        let mut unexpected = vps.clone();
        unexpected["password"] = json!("extra field");
        assert!(parse_eligible(&json!({"servers": [unexpected]}).to_string()).is_none());
        assert!(parse_eligible(&json!({"servers": [vps.clone(), vps]}).to_string()).is_none());
    }

    #[test]
    fn posture_decode_separates_bad_json_from_typed_validation() {
        assert!(matches!(
            decode_posture(b"{"),
            Err(PostureFailure::InvalidJson)
        ));
        assert!(matches!(
            decode_posture(br#"{"listeners":"unrecognized","nftables":"tables_present"}"#),
            Err(PostureFailure::InvalidPosture)
        ));
        assert!(matches!(
            decode_posture(br#"{"listeners":"no_listener","nftables":"tables_present","updates":{"status":"available","packages":0}}"#),
            Err(PostureFailure::InvalidPosture)
        ));
    }

    #[test]
    fn billing_preserves_positive_redis_and_valkey_observations() {
        for (service, incomplete, wildcard, expected) in [
            ("valkey", false, true, "non_loopback_observed"),
            ("redis", true, true, "non_loopback_observed"),
            ("valkey", true, true, "non_loopback_observed"),
            ("redis", true, false, "unknown"),
            ("valkey", false, false, "loopback_only"),
            ("ssh", false, true, "none_observed"),
        ] {
            let entry = json!([{"port": 6379,"services": [service]}]);
            let udp = if incomplete {
                json!([{"port": 5353,"services": ["unknown"]}])
            } else {
                json!([])
            };
            let raw = json!({
                "listeners": "no_listener",
                "nftables": "not_observed",
                "ports": {
                    "tcp": { "coverage": "complete", "interface": [],
                        "wildcard": if wildcard { entry.clone() } else { json!([]) },
                        "loopback": if wildcard { json!([]) } else { entry } },
                    "udp": { "coverage": "complete", "wildcard": [], "interface": [], "loopback": udp },
                    "truncated": false,
                },
            });
            let posture = decode_posture(raw.to_string().as_bytes()).expect("bounded posture");
            assert_eq!(posture.billing_facts()["redis_binding"], expected, "{raw}");
        }
    }

    #[test]
    fn billing_keeps_partial_metadata_positives_and_marks_missing_evidence_unknown() {
        for (coverage, broad, expected) in [
            ("observed", 0, "none_observed"),
            ("partial", 0, "unknown"),
            ("partial", 1, "broad_mode_observed"),
        ] {
            let raw = json!({
                "listeners": "no_listener", "nftables": "not_observed",
                "metadata": {
                    "coverage": coverage, "units_with_evidence": 1, "truncated": false,
                    "environment_files": {"owner_only": 0, "group_or_other_access": broad, "unknown": 0},
                    "service_env": {"owner_only": 0, "group_or_other_access": broad, "unknown": 0},
                    "credential_sources": {"owner_only": 0, "group_or_other_access": broad, "unknown": 0},
                },
            });
            let posture = decode_posture(raw.to_string().as_bytes()).expect("bounded metadata");
            for key in ["service_env", "credential_sources"] {
                assert_eq!(posture.billing_facts()[key], expected);
            }
            if coverage == "partial" {
                assert!(posture.report().contains("Partial systemd metadata"));
            }
        }
    }

    #[test]
    fn the_evidence_keeps_confirmed_environment_references_independent_of_file_modes() {
        use crate::account::commands::Said;

        let listed = json!({ "servers": [{
            "id": "bare_metal:7", "kind": "bare_metal", "label": "fixture",
            "address": "8.8.8.4", "region": "tokyo",
        }] });
        let server = parse_eligible(&listed.to_string())
            .expect("eligible fixture")
            .pop()
            .expect("fixture server");
        for (coverage, owner_only, unknown, expected) in [
            ("observed", 1, 0, "owner_only_modes_observed"),
            ("observed", 0, 0, "none_observed"),
            ("partial", 1, 0, "owner_only_modes_observed"),
            ("partial", 0, 1, "unknown"),
            ("partial", 1, 1, "unknown"),
            ("partial", 0, 0, "unknown"),
        ] {
            let observed_reference = owner_only + unknown > 0;
            let permission_counts =
                json!({ "owner_only": owner_only, "group_or_other_access": 0, "unknown": unknown });
            let wire = json!({
                "listeners":"no_listener", "nftables":"not_observed",
                "metadata":{
                    "coverage":coverage, "units_with_evidence":1, "truncated":false,
                    "environment_files": permission_counts,
                    "service_env":{"owner_only":0,"group_or_other_access":0,"unknown":0},
                    "credential_sources":{"owner_only":0,"group_or_other_access":0,"unknown":0},
                },
            });
            for receipt in [
                Some(("fixture-model-a", 527)),
                Some(("fixture-model-b", 516)),
                None,
            ] {
                let model = if let Some((model, charged)) = receipt {
                    Ok(serde_json::from_value(json!({
                        "status":"completed", "model":model, "findings":["review_ssh_jail"],
                        "billing":{"meterVersion":"posture1","chargedCredits":charged,
                            "baseCredits":512,"inputTokens":1,"outputTokens":1},
                    }))
                    .expect("receipt fixture"))
                } else {
                    Err(super::billing::ReportFailure::from_response(
                        409,
                        r#"{"error":"posture_report_no_actionable_candidates"}"#,
                    ))
                };
                let result =
                    decode_posture(wire.to_string().as_bytes()).expect("valid mixed evidence");
                assert_eq!(result.billing_facts()["service_env"], expected);
                let completed = super::Completed {
                    id: "fixture-request".into(),
                    result,
                    model,
                };
                // The evidence `--details` prints, as the report printed it before.
                let text = completed.evidence(&server);
                assert_eq!(
                    text.contains("Local SSH finding · EnvironmentFile policy review"),
                    observed_reference
                );
                if let Some((model, charged)) = receipt {
                    assert!(
                        text.contains(&format!("ERPC AI tokens charged: {charged} (base 512,"))
                    );
                    assert!(!text.contains(model), "{text}");
                } else {
                    assert!(text.contains("No AI tokens were charged"));
                }
                let Said::Json(record) =
                    completed.render(&server, true, false, super::posture_view::Look::PLAIN)
                else {
                    panic!("JSON report expected");
                };
                if observed_reference {
                    assert_eq!(
                        record["localFindings"],
                        json!([
                            { "id":"review_env_file_use", "source":"pinned_ssh" }
                        ])
                    );
                } else {
                    assert!(record.get("localFindings").is_none());
                }
                assert_eq!(
                    record["posture"]["metadata"]["environment_files"],
                    permission_counts
                );
                if let Some((model, charged)) = receipt {
                    assert!(record["modelReport"].get("model").is_none());
                    assert!(!record.to_string().contains(model), "{record}");
                    assert_eq!(record["modelReport"]["billing"]["chargedCredits"], charged);
                } else {
                    assert!(record.get("modelReport").is_none());
                    assert_eq!(record["settlement"], "no_charge");
                }
            }
        }
    }

    /// `--json` carries no model id: not the primary's nor the fallback's
    /// a receipt names, while the receipt's status, findings and billing
    /// stay as they came, and the receipt is still checked by its model.
    #[test]
    fn the_printed_json_carries_no_model_id() {
        use crate::account::commands::Said;

        let server = fixture_server();
        for (terms, model, charged) in [
            (FixtureQuote::Internal, "fixture-model-a", 527),
            (FixtureQuote::WithFallback, "fixture-model-b", 516),
        ] {
            let approved = billing::ApprovedReport::from_quote(
                &quote_fixture(true, terms),
                server.rental,
                |_| Ok(true),
            )
            .expect("approved quote")
            .expect("approved");
            let posture =
                decode_posture(br#"{"listeners":"no_listener","nftables":"not_observed"}"#)
                    .expect("fixture posture");
            let submission = approved.submission(&posture);
            let wire = json!({
                "status":"completed", "model":model, "findings":["review_ssh_jail"],
                "billing":{"meterVersion":"posture1","chargedCredits":charged,
                    "baseCredits":512,"inputTokens":1,"outputTokens":1},
            });
            let receipt = submission
                .fixture_receipt(&wire.to_string())
                .expect("a receipt the quote allows");
            // Checked by its model: another name at the same charge is refused.
            let other = wire.to_string().replace(model, "fixture-model-c");
            assert!(submission.fixture_receipt(&other).is_err());
            let done = super::Completed {
                id: "fixture-request".into(),
                result: posture,
                model: Ok(receipt),
            };
            let Said::Json(record) =
                done.render(&server, true, false, super::posture_view::Look::PLAIN)
            else {
                panic!("JSON report expected");
            };
            let mut expected = wire;
            expected
                .as_object_mut()
                .expect("receipt object")
                .remove("model");
            assert_eq!(record["modelReport"], expected);
            let printed = record.to_string();
            assert!(!printed.contains("fixture-model"), "{printed}");
        }
    }

    #[test]
    fn collector_diagnostics_translate_the_reason_without_changing_the_code() {
        use erpc_ssh::PrivateCaptureError;
        let failure = PostureFailure::Capture(PrivateCaptureError::Exit(19));
        let english = crate::cli::i18n::speaking(Lang::En, || failure.reason());
        assert_eq!(english, "The collector exited with status 19.");
        for lang in [Lang::Ja, Lang::Ru, Lang::Zh] {
            let reason = crate::cli::i18n::speaking(lang, || failure.reason());
            assert_ne!(reason, english);
            assert!(reason.contains("19"));
            let full = crate::cli::i18n::speaking(lang, || failure.message());
            assert!(full.ends_with(&format!("{reason} [collector_exit]")));
        }
    }

    #[test]
    fn remote_posture_preserves_legacy_fields_and_projects_only_fixed_billing_facts() {
        let raw = json!({
            "listeners": "no_listener",
            "nftables": "tables_present",
            "ports": {
                "tcp":{"coverage":"complete","loopback":[],"wildcard":[{"port":16379,"services":["redis"]}],"interface":[]},
                "udp":{"coverage":"partial","loopback":[{"port":5353,"services":["unknown"]}],"wildcard":[],"interface":[]},
                "truncated":true
            },
            "ssh":{"source":"default_config_for_connection","password":"disabled","keyboard_interactive":"unknown"},
            "firewall":{"ipv4":"input_default_drop","ipv6":"unknown","truncated":false},
            "fail2ban":"sshd_jail_observed",
            "metadata":{
                "coverage":"observed","units_with_evidence":1,"truncated":false,
                "environment_files":{"owner_only":2,"group_or_other_access":0,"unknown":0},
                "service_env":{"owner_only":1,"group_or_other_access":0,"unknown":0},
                "credential_sources":{"owner_only":0,"group_or_other_access":1,"unknown":0},
                "distinct_credential_sources":{"as_is":1,"encrypted":1}
            },
            "updates":{"status":"available","packages":2}
        });
        let posture: Posture = serde_json::from_value(raw.clone()).expect("valid bounded posture");
        assert!(posture.valid());
        assert_eq!(
            serde_json::to_value(&posture).expect("public report shape"),
            raw
        );
        let text = posture.report();
        assert!(text.contains("16379 (Redis)"));
        assert!(text.contains("EnvironmentFile policy review"));
        assert!(text.contains("Named .env files"));
        assert!(text.contains("LoadCredential: 1"));
        assert!(text.contains("LoadCredentialEncrypted: 1"));
        assert!(text.contains("does not establish the underlying file format"));
        assert!(text.contains("owner only 2, group or other access 0, unknown 0"));
        assert!(text.contains("2 packages with security updates"));
        for language in [Lang::En, Lang::Ja, Lang::Ru, Lang::Zh] {
            let text = crate::cli::i18n::speaking(language, || posture.report());
            assert!(!text.contains('%'), "{text}");
            assert!(!text.contains('{'), "{text}");
        }
        assert_eq!(
            posture.billing_facts(),
            json!({
                "listeners":"no_listener", "nftables":"tables_present",
                "tcp":"non_loopback_observed","udp":"unknown",
            "redis_binding":"non_loopback_observed","daemon_review":"unknown",
                "ssh_password":"unknown","ssh_keyboard_interactive":"unknown",
                "firewall_ipv4":"input_default_drop","firewall_ipv6":"unknown",
                "fail2ban":"sshd_jail_observed","service_env":"owner_only_modes_observed",
                "credential_sources":"broad_mode_observed","updates":"available"
            })
        );
        let mut attributed = raw.clone();
        attributed["ports"]["truncated"] = json!(false);
        attributed["ports"]["udp"]["coverage"] = json!("complete");
        attributed["ports"]["udp"]["loopback"][0]["services"] = json!(["unclassified"]);
        let attributed: Posture = serde_json::from_value(attributed).expect("complete attribution");
        assert_eq!(
            attributed.billing_facts()["redis_binding"],
            "non_loopback_observed"
        );
        assert_eq!(
            attributed.billing_facts()["daemon_review"],
            "unclassified_observed"
        );
        let mut malicious = raw.clone();
        malicious["ports"]["tcp"]["wildcard"][0]["address"] = json!("192.0.2.5");
        assert!(serde_json::from_value::<Posture>(malicious).is_err());
        let mut malformed = raw;
        malformed["ports"]["tcp"]["wildcard"] = json!([{"port":0,"services":["redis"]}]);
        let malformed: Posture = serde_json::from_value(malformed).expect("wire typing");
        assert!(!malformed.valid());
    }

    /// A collector report shaped as one from a real rental: TCP 22 on
    /// every address with its program unseen, two ports on loopback, both
    /// firewalls dropping by default, fail2ban's sshd jail, one service
    /// environment file other accounts can read (named for the screen),
    /// partial systemd metadata, no security updates, and a key search that
    /// could not read everything and found nothing.
    pub(in crate::node) fn sample_wire() -> serde_json::Value {
        json!({
            "listeners": "no_listener", "nftables": "tables_present",
            "ports": {
                "tcp": {"coverage": "complete", "wildcard": [{"port": 22, "services": ["unknown"]}],
                    "interface": [], "loopback": [{"port": 53, "services": ["unknown"]},
                        {"port": 3000, "services": ["unknown"]}]},
                "udp": {"coverage": "complete", "wildcard": [], "interface": [],
                    "loopback": [{"port": 53, "services": ["unknown"]}]},
                "truncated": false,
            },
            "ssh": {"source": "default_config_for_connection", "password": "unknown",
                "keyboard_interactive": "unknown"},
            "firewall": {"ipv4": "input_default_drop", "ipv6": "input_default_drop",
                "truncated": false},
            "fail2ban": "sshd_jail_observed",
            "metadata": {"coverage": "partial", "units_with_evidence": 2, "truncated": false,
                "environment_files": {"owner_only": 0, "group_or_other_access": 1, "unknown": 0},
                "service_env": {"owner_only": 0, "group_or_other_access": 0, "unknown": 0},
                "credential_sources": {"owner_only": 0, "group_or_other_access": 0, "unknown": 0},
                "distinct_credential_sources": {"as_is": 0, "encrypted": 0},
                "files": [{"source": "environment_file", "unit": "erpc-worker-example.service",
                    "path": "/etc/example.env", "type": "file", "mode": 0o644}],
                "files_more": 0},
            "updates": {"status": "none_in_cached_candidates", "packages": 0},
            "keys": {"coverage": "partial", "groups": []},
        })
    }

    /// The rental the sample came from, with made-up ids.
    pub(in crate::node) fn sample_server() -> super::EligibleServer {
        let listed = json!({ "servers": [{
            "id": "vps:100001", "kind": "vps", "label": "fixture",
            "address": "8.8.8.4", "region": "frankfurt",
        }] });
        parse_eligible(&listed.to_string())
            .expect("eligible fixture")
            .pop()
            .expect("fixture server")
    }

    fn fixture_server() -> super::EligibleServer {
        let listed = json!({ "servers": [{
            "id": "bare_metal:7", "kind": "bare_metal", "label": "fixture",
            "address": "8.8.8.4", "region": "tokyo",
        }] });
        parse_eligible(&listed.to_string())
            .expect("eligible fixture")
            .pop()
            .expect("fixture server")
    }

    fn with_keys(keys: &serde_json::Value) -> Posture {
        let raw = json!({"listeners": "no_listener", "nftables": "not_observed", "keys": keys});
        decode_posture(raw.to_string().as_bytes()).expect("bounded key section")
    }

    fn completed(result: Posture) -> super::Completed {
        super::Completed {
            id: "fixture-request".into(),
            result,
            model: Err(billing::ReportFailure::from_response(
                409,
                r#"{"error":"posture_report_no_actionable_candidates"}"#,
            )),
        }
    }

    fn key_group(
        kind: &str,
        role: &str,
        location: &str,
        access: &str,
        count: u32,
        places: &[&str],
    ) -> serde_json::Value {
        let more = count - u32::try_from(places.len()).expect("few places");
        json!({"kind": kind, "role": role, "location": location, "access": access,
            "count": count, "places": places, "more": more})
    }

    #[test]
    fn key_findings_list_their_places_escaped_in_the_details_and_never_in_json() {
        use crate::account::commands::Said;

        let keys = json!({"coverage": "complete", "groups": [
            key_group("solana_keypair", "validator_identity", "home", "owner_only", 1,
                &["/home/sol/backup/id.json"]),
            key_group("solana_keypair", "validator_identity", "home", "group", 12,
                &["/home/sol/validator-keypair.json"]),
            key_group("evm_private_key", "unknown", "tmp", "world", 1,
                &["/tmp/%1B[2Jkey%E2%80%AEtxt.json%0A"]),
            key_group("history_secret", "unknown", "shell_history", "owner_only", 3,
                &["/root/.bash_history", "/home/a%5Cxff%FF/.bash_history"]),
        ]});
        let done = completed(with_keys(&keys));
        // The evidence `--details` prints; the report above it lists the
        // same places (posture_view's tests).
        let text = done.evidence(&fixture_server());
        assert!(text.contains("Plain-text key search · complete\n"));
        assert!(text.contains(
            "Local SSH finding · The validator identity keypair can be read by accounts other \
             than its owner. Make the identity keypair readable by the validator's own user only \
             (chmod 600).\n  - solana_keypair (validator_identity) in home, readable by group: \
             12\n      /home/sol/validator-keypair.json\n      and 11 more\n"
        ));
        assert!(text.contains(
            "Validator identity keypairs readable by their owner only:\n  - solana_keypair \
             (validator_identity) in home, readable by owner_only: 1\n      \
             /home/sol/backup/id.json\n"
        ));
        assert!(text.contains(
            "  - evm_private_key (unknown) in tmp, readable by world: 1\n      \
             /tmp/\\u{1b}[2Jkey\\u{202e}txt.json\\u{a}\n"
        ));
        assert!(text.contains(
            "      /root/.bash_history\n      /home/a\\\\xff\\xff/.bash_history\n      and 1 more\n"
        ));
        // Every account can read the key in /tmp: a finding of its own,
        // whose group is not listed with its places twice.
        assert!(text.contains(
            "Local SSH finding · A private key or secret on this server can be read by every \
             account. Make the file readable by its owner only (chmod 600), and move it off the \
             server if it controls funds.\n  - evm_private_key (unknown) in tmp, readable by \
             world: 1\nThis snapshot"
        ));
        assert_eq!(text.matches("txt.json").count(), 1);
        assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'));

        let Said::Json(record) = done.render(
            &fixture_server(),
            true,
            false,
            super::posture_view::Look::PLAIN,
        ) else {
            panic!("JSON report expected");
        };
        assert_eq!(
            record["localFindings"],
            json!([
                {"id": "plaintext_wallet_key", "source": "pinned_ssh"},
                {"id": "validator_identity_permissions", "source": "pinned_ssh"},
                {"id": "secret_in_shell_history", "source": "pinned_ssh"},
                {"id": "key_world_readable", "source": "pinned_ssh"},
            ])
        );
        assert_eq!(
            record["posture"]["keys"]["groups"][1],
            json!({"kind": "solana_keypair", "role": "validator_identity", "location": "home",
                "access": "group", "count": 12})
        );
        let record = record.to_string();
        for place in [
            "/home",
            "/root",
            "/tmp",
            "bash_history",
            "id.json",
            "places",
            "more",
        ] {
            assert!(!record.contains(place), "{place} in {record}");
        }
        for language in [Lang::En, Lang::Ja, Lang::Ru, Lang::Zh] {
            let plain = with_keys(&json!({"coverage": "partial", "groups": [
                key_group("mnemonic", "unknown", "opt", "world", 12, &["/opt/bot/seed.txt"]),
            ]}));
            let text = crate::cli::i18n::speaking(language, || plain.report());
            assert!(text.contains("/opt/bot/seed.txt"), "{text}");
            assert!(!text.contains('{') && !text.contains('%'), "{text}");
        }
    }

    #[test]
    fn the_prompt_before_the_check_says_it_reads_file_contents_for_keys() {
        let server = fixture_server();
        let scope = inspection_scope(&server);
        assert!(scope.contains(
            "reads the contents of files under /root, /home, /etc, /opt, /srv, /var/lib, /tmp \
             and /var/tmp, shell histories and the environments of running processes, looking \
             for private keys and seed phrases"
        ));
        assert!(scope.contains("nothing about the keys is sent to ERPC"));
        for language in [Lang::Ja, Lang::Ru, Lang::Zh] {
            let scope = crate::cli::i18n::speaking(language, || inspection_scope(&server));
            assert!(
                scope.contains("/var/tmp") && scope.contains("ERPC"),
                "{scope}"
            );
        }
    }

    #[test]
    fn no_key_section_or_an_empty_one_changes_nothing_else() {
        let plain = decode_posture(br#"{"listeners":"no_listener","nftables":"not_observed"}"#)
            .expect("legacy posture");
        for (keys, heading) in [
            (
                json!({"coverage": "complete", "groups": []}),
                "Plain-text key search · complete\nNo private keys",
            ),
            (
                json!({"coverage": "partial", "groups": []}),
                "Plain-text key search · partial.",
            ),
            (
                json!({"coverage": "unreadable", "groups": []}),
                "Plain-text key search · no result.",
            ),
        ] {
            let posture = with_keys(&keys);
            assert_eq!(posture.billing_facts(), plain.billing_facts());
            assert!(posture.report().contains(heading), "{}", posture.report());
            assert!(posture.local_findings().is_empty());
        }
        assert!(!plain.report().contains("key search"));
    }

    #[test]
    fn the_strict_parser_refuses_a_key_section_out_of_bounds() {
        let good = key_group("mnemonic", "unknown", "opt", "world", 1, &["/opt/seed.txt"]);
        assert!(with_keys(&json!({"coverage": "complete", "groups": [good]})).valid());
        for bad in [
            json!({"coverage": "complete", "groups": [good], "paths": []}),
            json!({"coverage": "complete"}),
            json!({"coverage": "unreadable", "groups": [good]}),
            json!({"coverage": "complete", "groups": [good, good]}),
            json!({"coverage": "complete", "groups": [
                key_group("mnemonic", "unknown", "opt", "world", 1, &["opt/seed.txt"])]}),
            json!({"coverage": "complete", "groups": [
                key_group("mnemonic", "unknown", "opt", "world", 1, &["/opt/se\u{e9}d.txt"])]}),
            json!({"coverage": "complete", "groups": [
                key_group("mnemonic", "validator_identity", "opt", "world", 1, &[])]}),
            json!({"coverage": "complete", "groups": [
                key_group("mnemonic", "unknown", "opt", "world", 100_001, &[])]}),
        ] {
            let raw = json!({"listeners": "no_listener", "nftables": "not_observed", "keys": bad});
            assert!(
                matches!(
                    decode_posture(raw.to_string().as_bytes()),
                    Err(PostureFailure::InvalidPosture)
                ),
                "{bad}"
            );
        }
    }

    /// The largest report the strict parser accepts, key section and the
    /// services' files included, fits what the capture takes from the
    /// collector.
    #[test]
    fn the_largest_valid_report_fits_the_capture_limit() {
        use super::posture_details::{FILES_BUDGET, FILES_SHOWN};
        use super::posture_keys::{PLACE_LIMIT, PLACES_BUDGET, tests::every_group};

        let services = [
            "container",
            "dns",
            "erpc_worker",
            "mysql",
            "postgresql",
            "redis",
            "solana",
            "ssh",
            "time_sync",
            "unclassified",
            "unknown",
            "valkey",
            "web",
        ];
        let rows = |from: u16| -> Vec<serde_json::Value> {
            (from..from + 64)
                .map(|port| json!({"port": port, "services": services}))
                .collect()
        };
        let counts = json!({"owner_only": 22, "group_or_other_access": 21, "unknown": 21});
        // Places that cost the most: every byte written as %HH.
        let place = format!("/{}", "%FF".repeat((PLACE_LIMIT - 4) / 3));
        let shown = PLACES_BUDGET / (place.len() + 3);
        let groups: Vec<serde_json::Value> = every_group()
            .iter()
            .enumerate()
            .map(|(index, [kind, role, location, access])| {
                let places = if index == 0 {
                    vec![place.clone(); shown]
                } else {
                    Vec::new()
                };
                json!({"kind": kind, "role": role, "location": location, "access": access,
                    "count": 100_000, "places": places, "more": 100_000 - places.len()})
            })
            .collect();
        // As many files as are listed, of the longest unit name, with the
        // budget shared between them: each costs more than its path.
        let file = json!({"source": "environment_file",
            "unit": format!("erpc-backup-{}.service", "a".repeat(64)),
            "path": format!("/{}", "b".repeat(FILES_BUDGET / FILES_SHOWN - 4)),
            "type": "directory", "mode": 0o7777});
        let files = vec![file; FILES_SHOWN];
        let largest = json!({
            "listeners": "loopback_binding", "nftables": "no_tables_observed",
            "ports": {
                "tcp": {"coverage": "partial", "wildcard": rows(10_000), "interface": [], "loopback": []},
                "udp": {"coverage": "partial", "wildcard": rows(20_000), "interface": [], "loopback": []},
                "truncated": true,
            },
            "ssh": {"source": "default_config_for_connection", "password": "disabled",
                "keyboard_interactive": "disabled"},
            "firewall": {"ipv4": "configured_drop_or_reject_rule",
                "ipv6": "configured_drop_or_reject_rule", "truncated": true},
            "fail2ban": "sshd_jail_not_listed",
            "metadata": {"coverage": "observed", "units_with_evidence": 16, "truncated": true,
                "environment_files": counts, "service_env": counts, "credential_sources": counts,
                "distinct_credential_sources": {"as_is": 64, "encrypted": 64},
                "files": files, "files_more": u16::MAX},
            "updates": {"status": "none_in_cached_candidates", "packages": 0},
            "keys": {"coverage": "partial", "groups": groups},
        });
        // The collector prints it compact, as this, and a newline.
        let printed = largest.to_string().len() + 1;
        assert!(decode_posture(largest.to_string().as_bytes()).is_ok());
        assert!(
            printed <= erpc_ssh::exec::POSTURE_OUTPUT_LIMIT,
            "{printed} bytes"
        );
        let keys = largest["keys"].to_string().len();
        assert!(keys < 24 * 1024, "{keys} bytes of keys");
    }

    /// The report request built from a server full of keys carries none of
    /// them, nor where they are: the collector's own key search, run on a
    /// fixture tree its tests make, with keys made as it runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn nothing_the_key_search_finds_reaches_the_request() {
        use crate::account::commands::Said;

        let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-ssh/src/node-security-keys-test.py");
        let driver = "import json, runpy, sys\n\
            tests = runpy.run_path(sys.argv[1])\n\
            tree, secrets = tests['key_host']()\n\
            try:\n    \
                print(json.dumps({'keys': tests['search'](tree.root), 'secrets': secrets, 'root': str(tree.root)}))\n\
            finally:\n    \
                tree.remove()\n";
        let Ok(output) = std::process::Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg(driver)
            .arg(&tests)
            .output()
        else {
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reply: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("fixture reply");
        let posture = with_keys(&reply["keys"]);
        assert_eq!(reply["keys"]["groups"].as_array().map(Vec::len), Some(11));
        let server = fixture_server();
        let approved = billing::ApprovedReport::from_quote(
            &quote_fixture(true, FixtureQuote::Customer),
            server.rental,
            |_| Ok(true),
        )
        .expect("approved quote")
        .expect("approved");
        let body = String::from_utf8(approved.submission(&posture).body).expect("text body");
        let root = reply["root"].as_str().expect("root");
        // Neither the keys nor any part of where they are, anywhere off
        // this screen.
        let mut local: Vec<&str> = reply["secrets"]
            .as_array()
            .expect("secrets")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        local.extend([
            root,
            "erpc-keys-",
            "/home",
            "/root",
            "/proc",
            "/tmp",
            "/var",
            "/etc",
            "/opt",
            "/srv",
            "validator-keypair",
            "id.json",
            ".env",
            "bash_history",
            "fish_history",
            "deployer",
            "seed.txt",
            "keystore.json",
            "places",
        ]);
        // Nor, in the request, that there are keys at all.
        let classes = [
            "keys",
            "wallet",
            "history",
            "mnemonic",
            "keystore",
            "solana_keypair",
        ];
        for fragment in local.iter().chain(&classes) {
            assert!(!body.contains(fragment), "{fragment} reached the request");
        }
        let plain = decode_posture(br#"{"listeners":"no_listener","nftables":"not_observed"}"#)
            .expect("legacy posture");
        assert_eq!(posture.billing_facts(), plain.billing_facts());
        // The places are on the operator's screen (here, in the evidence
        // `--details` prints); --json does not carry them.
        let done = completed(posture);
        let text = done.evidence(&server);
        assert!(text.contains("/home/sol/validator-keypair.json"));
        assert!(text.contains("/root/.bash_history"));
        let Said::Json(record) =
            done.render(&server, true, false, super::posture_view::Look::PLAIN)
        else {
            panic!("JSON report expected");
        };
        let record = record.to_string();
        for fragment in &local {
            assert!(!record.contains(fragment), "{fragment} reached --json");
        }
    }

    /// `--json` is as it was: the services' files stay on the screen.
    #[test]
    fn the_printed_json_carries_none_of_the_services_files() {
        use crate::account::commands::Said;

        let wire = sample_wire();
        let done = completed(decode_posture(wire.to_string().as_bytes()).expect("sample"));
        let server = sample_server();
        let Said::Json(record) =
            done.render(&server, true, false, super::posture_view::Look::PLAIN)
        else {
            panic!("JSON report expected");
        };
        let mut before = wire["metadata"].clone();
        let metadata = before.as_object_mut().expect("metadata");
        metadata.remove("files");
        metadata.remove("files_more");
        assert_eq!(record["posture"]["metadata"], before);
        let printed = record.to_string();
        for detail in [
            "erpc-worker-example",
            "/etc/example.env",
            "\"files",
            "files_more",
        ] {
            assert!(!printed.contains(detail), "{detail} in {printed}");
        }
        let Said::Text(text) = done.render(&server, false, false, super::posture_view::Look::PLAIN)
        else {
            panic!("report expected");
        };
        assert!(text.contains("erpc-worker-example.service → /etc/example.env (0644)"));
        // --details adds today's evidence, which counts the files and names none.
        let Said::Text(detailed) =
            done.render(&server, false, true, super::posture_view::Look::PLAIN)
        else {
            panic!("report expected");
        };
        let evidence = done.evidence(&server);
        assert_eq!(detailed, format!("{text}\n\nDetails\n{evidence}"));
        assert!(evidence.starts_with("vps:100001  frankfurt\nNo listener observed on TCP 8899.\n"));
        assert!(evidence.contains(
            "Service EnvironmentFile references · owner only 0, group or other access 1, unknown 0"
        ));
        assert!(!evidence.contains("/etc/example.env"));
    }

    /// The units the parser takes are the ones the collector reads: its
    /// fixed list and its pattern for ERPC units. Should either change, the
    /// parser would refuse every report naming a file of such a unit.
    #[test]
    fn the_parser_takes_the_units_the_collector_reads() {
        let script = erpc_ssh::command::NODE_SECURITY_POSTURE_SCRIPT;
        let fixed = script
            .split_once("FIXED_UNITS = (")
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(list, _)| list)
            .expect("the collector's fixed units");
        let mut named: Vec<&str> = fixed
            .split(',')
            .map(|name| name.trim().trim_matches('"'))
            .filter(|name| !name.is_empty())
            .collect();
        named.sort_unstable();
        let mut parsed = super::posture_details::COLLECTOR_UNITS.to_vec();
        parsed.sort_unstable();
        assert_eq!(named, parsed);
        let pattern =
            r#"ERPC_UNIT = re.compile(r"erpc-(?:worker|waf|backup)-[a-z0-9-]{1,64}\.service\Z")"#;
        assert_eq!(script.lines().filter(|line| *line == pattern).count(), 1);
    }

    #[test]
    fn the_collector_keeps_to_the_service_file_bounds_the_parser_holds_it_to() {
        use super::posture_details::{FILE_PATH_LIMIT, FILES_BUDGET, FILES_SHOWN};

        let script = erpc_ssh::command::NODE_SECURITY_POSTURE_SCRIPT;
        for (name, value) in [
            ("FILES_SHOWN", FILES_SHOWN),
            ("FILE_PATH_LIMIT", FILE_PATH_LIMIT),
            ("FILES_BUDGET", FILES_BUDGET),
        ] {
            let line = format!("{name} = {value}");
            assert_eq!(script.lines().filter(|l| *l == line).count(), 1, "{line}");
        }
    }

    /// The services' files the parser takes: a unit the collector reads, a
    /// path in the key search's encoding, a mode only for a file or a
    /// directory, within the bounds, and never more of a kind than counted.
    #[test]
    fn the_strict_parser_refuses_service_files_out_of_bounds() {
        use super::posture_details::{FILE_PATH_LIMIT, FILES_BUDGET, FILES_SHOWN};

        let decoded = |files: serde_json::Value, broad: u16, truncated: bool| {
            let mut wire = sample_wire();
            wire["metadata"]["files"] = files;
            wire["metadata"]["truncated"] = json!(truncated);
            wire["metadata"]["environment_files"]["group_or_other_access"] = json!(broad);
            decode_posture(wire.to_string().as_bytes()).is_ok()
        };
        let entry = |unit: &str, path: &str, kind: serde_json::Value, mode: serde_json::Value| json!({"source": "environment_file", "unit": unit, "path": path, "type": kind, "mode": mode});
        let good = |unit: &str| entry(unit, "/etc/example.env", json!("file"), json!(0o644));
        for unit in [
            "ssh.service",
            "fail2ban.service",
            "erpc-worker-a.service",
            "erpc-waf-x-1.service",
            &format!("erpc-backup-{}.service", "a".repeat(64)),
        ] {
            assert!(decoded(json!([good(unit)]), 1, false), "{unit}");
        }
        for unit in [
            "example.service",
            "erpc-worker-.service",
            "erpc-worker-A.service",
            "erpc-other-a.service",
            "erpc-worker-a.socket",
            &format!("erpc-waf-{}.service", "a".repeat(65)),
            "ssh.service\u{1b}",
        ] {
            assert!(!decoded(json!([good(unit)]), 1, false), "{unit}");
        }
        let unit = "ssh.service";
        for (path, kind, mode) in [
            ("etc/example.env", json!("file"), json!(0o644)),
            ("/etc/%41.env", json!("file"), json!(0o644)),
            ("/etc/a\"b", json!("file"), json!(0o644)),
            ("/etc/example.env", json!("file"), json!(null)),
            ("/etc/example.env", json!("other"), json!(0o644)),
            ("/etc/example.env", json!(null), json!(0o644)),
            ("/etc/example.env", json!("file"), json!(0o10000)),
            ("/etc/example.env", json!("socket"), json!(null)),
        ] {
            assert!(
                !decoded(
                    json!([entry(unit, path, kind.clone(), mode.clone())]),
                    1,
                    false
                ),
                "{path} {kind} {mode}"
            );
        }
        let long = format!("/{}", "a".repeat(FILE_PATH_LIMIT));
        assert!(!decoded(
            json!([entry(unit, &long, json!("file"), json!(0o644))]),
            1,
            false
        ));
        let path = |n: usize| format!("/etc/{n}.env");
        let many: Vec<_> = (0..=FILES_SHOWN)
            .map(|n| entry(unit, &path(n), json!("file"), json!(0o644)))
            .collect();
        assert!(!decoded(json!(many), 64, false));
        assert!(decoded(json!(many[..FILES_SHOWN]), 64, false));
        let costly = format!("/{}", "b".repeat(FILES_BUDGET / 2 - 3));
        let over = vec![entry(unit, &costly, json!("file"), json!(0o644)); 2];
        assert!(decoded(json!(over[..1]), 1, false));
        assert!(!decoded(json!(over), 2, false));
        // Two paths open to others when one was counted: refused, unless the
        // collector ran out of room; one path of two units counts once.
        let two = json!([
            good(unit),
            entry(unit, "/etc/other.env", json!("file"), json!(0o644))
        ]);
        assert!(!decoded(two.clone(), 1, false));
        assert!(decoded(two, 1, true));
        assert!(decoded(
            json!([good("ssh.service"), good("sshd.service")]),
            1,
            false
        ));
        assert!(!decoded(
            json!([entry(unit, "/etc/example.env", json!("file"), json!(0o600))]),
            1,
            false
        ));
        let mut unknown = sample_wire();
        unknown["metadata"] = json!({"coverage": "unknown", "units_with_evidence": 0, "truncated": false,
            "environment_files": {"owner_only": 0, "group_or_other_access": 0, "unknown": 0},
            "service_env": {"owner_only": 0, "group_or_other_access": 0, "unknown": 0},
            "credential_sources": {"owner_only": 0, "group_or_other_access": 0, "unknown": 0},
            "files": [], "files_more": 1});
        assert!(decode_posture(unknown.to_string().as_bytes()).is_err());
    }

    /// The collector's own code, run on a tree with a service's files in
    /// it: what it reports is what the parser takes, its paths reach the
    /// screen, and neither the request nor `--json` carries them.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_collectors_service_files_reach_the_screen_and_nothing_else() {
        use crate::account::commands::Said;

        let collector = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-ssh/src/node-security-posture.py");
        let driver = "import json, runpy, sys, tempfile\n\
            from pathlib import Path\n\
            from unittest.mock import patch\n\
            metadata = runpy.run_path(sys.argv[1])['metadata_policy']\n\
            with tempfile.TemporaryDirectory() as d:\n    \
                root = Path(d)\n    \
                env = root / 'example.env'\n    \
                env.write_text('fixture')\n    \
                env.chmod(0o644)\n    \
                token = root / 'token'\n    \
                token.write_text('fixture')\n    \
                token.chmod(0o600)\n    \
                props = f'a(sb) 1 \"{env}\" false\\na(ss) 1 \"token\" \"{token}\"\\na(ss) 0\\n'.encode()\n    \
                def capture(args, **_):\n        \
                    if 'GetUnit' in args:\n            \
                        return b'o \"/org/freedesktop/systemd1/unit/worker\"\\n', False\n        \
                    return props, False\n    \
                units = lambda _: (('erpc-worker-example.service',), set(), False, False)\n    \
                with patch.dict(metadata.__globals__, capture=capture, unit_names=units):\n        \
                    print(json.dumps({'metadata': metadata(set(), False), 'root': d}))\n";
        let Ok(output) = std::process::Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg(driver)
            .arg(&collector)
            .output()
        else {
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reply: serde_json::Value = serde_json::from_slice(&output.stdout).expect("reply");
        let root = reply["root"].as_str().expect("root");
        let wire = json!({"listeners": "no_listener", "nftables": "not_observed", "metadata": reply["metadata"]});
        let posture =
            decode_posture(wire.to_string().as_bytes()).expect("the collector's metadata");
        let server = sample_server();
        let approved = billing::ApprovedReport::from_quote(
            &quote_fixture(true, FixtureQuote::Customer),
            server.rental,
            |_| Ok(true),
        )
        .expect("approved quote")
        .expect("approved");
        let body = String::from_utf8(approved.submission(&posture).body).expect("text body");
        let done = completed(posture);
        let Said::Text(text) = done.render(&server, false, false, super::posture_view::Look::PLAIN)
        else {
            panic!("report expected");
        };
        assert!(
            text.contains(&format!(
                "erpc-worker-example.service → {root}/example.env (0644)"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!("→ sudo chmod 600 {root}/example.env")),
            "{text}"
        );
        let Said::Json(record) = done.render(&server, true, true, super::posture_view::Look::PLAIN)
        else {
            panic!("JSON expected");
        };
        let record = record.to_string();
        for fragment in [root, "example.env", "erpc-worker-example", "token"] {
            assert!(!body.contains(fragment), "{fragment} reached the request");
            assert!(!record.contains(fragment), "{fragment} reached --json");
        }
    }

    #[test]
    fn node_check_rejects_free_form_remote_output() {
        assert!(
            serde_json::from_value::<Posture>(json!({
                "listeners": "loopback_binding", "nftables": "not_observed"
            }))
            .is_ok()
        );
        for bad in [
            json!({"listeners": "raw addresses", "nftables": "not_observed"}),
            json!({"listeners": "no_listener", "nftables": "tables_present", "extra": "raw data"}),
            json!({"listeners": "no_listener", "nftables": "arbitrary text"}),
        ] {
            assert!(serde_json::from_value::<Posture>(bad).is_err());
        }
    }
}
