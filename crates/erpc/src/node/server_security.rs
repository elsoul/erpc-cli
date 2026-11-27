// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Security check entry points for authenticated ERPC server rentals.

#[path = "posture_billing.rs"]
mod billing;

#[path = "posture_details.rs"]
mod posture_details;

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
}

impl Posture {
    fn valid(&self) -> bool {
        self.ports.as_ref().is_none_or(Ports::valid)
            && self.metadata.as_ref().is_none_or(Metadata::valid)
            && self.updates.as_ref().is_none_or(Updates::valid)
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

fn target(
    server: &AuthorizedServer,
    explicit_key: Option<(&str, &str)>,
) -> Option<erpc_ssh::Target> {
    let address = server.address.to_string();
    if let Some((key, user)) = explicit_key {
        return Some(erpc_ssh::Target {
            host: address,
            port: 22,
            user: user.to_owned(),
            host_key: erpc_ssh::HostKey::parse(key).ok()?,
            identity: crate::ai::vps_access::security_identity()?,
        });
    }
    if server.rental.kind == Kind::Vps {
        return crate::ai::vps_access::security_target(&address, server.rental.id);
    }
    None
}

fn observe_remote(
    server: &AuthorizedServer,
    explicit_key: Option<(&str, &str)>,
) -> Result<Posture, Outcome> {
    let target = target(server, explicit_key)
        .ok_or_else(|| Outcome::Failed(t!("node_check.remote_pin_required")))?;
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
        "{}\n{}\n{}",
        t!("node_check.remote_scope", server = server.label()),
        t!("node_check.readonly_sudo"),
        t!("node_check.authorization"),
    )
}

async fn menu(
    json: bool,
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
    let completed = run_selected(
        &server,
        ask_confirmation,
        || async {
            let unavailable = || Outcome::Failed(t!("node_check.quote_unavailable"));
            tokio::time::timeout(
                std::time::Duration::from_secs(45),
                account.read_list(SECURITY_CHECK_QUOTE_URL, QUOTE_LIMITS),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())
        },
        async |rental| account.select_rental(rental).await,
        async |verified| collect_selected(verified, explicit_key).await,
        async |submission| submission.submit(&account).await,
    )
    .await;
    match completed {
        Ok(Some(completed)) => completed.render(&server, json).done(),
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
    fn render(&self, server: &EligibleServer, json: bool) -> Said {
        let Self { id, result, model } = self;
        if json {
            let mut output = serde_json::json!({
                "server": server.summary(), "source": "pinned_ssh", "posture": result, "requestId": id,
            });
            if result
                .metadata
                .as_ref()
                .is_some_and(Metadata::has_environment_reference)
            {
                output["localFindings"] = serde_json::json!([
                    { "id": "review_env_file_use", "source": "pinned_ssh" }
                ]);
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
        let message = match model {
            Ok(receipt) => receipt.summary(),
            Err(state) => state.message(id),
        };
        Said::Text(format!(
            "{}\n{}\n{}",
            server.label(),
            result.report(),
            message
        ))
    }
}

async fn run_selected(
    server: &EligibleServer,
    mut confirm: impl FnMut(String) -> Result<bool, Outcome>,
    quote: impl AsyncFnOnce() -> Result<Zeroizing<String>, Outcome>,
    select: impl AsyncFnOnce(Server) -> Result<(u16, Zeroizing<String>), Outcome>,
    observe: impl AsyncFnOnce(AuthorizedServer) -> Result<Posture, Outcome>,
    submit: impl AsyncFnOnce(
        billing::ReportSubmission,
    ) -> Result<billing::Receipt, billing::ReportFailure>,
) -> Result<Option<Completed>, Outcome> {
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
            "model":"claude-mythos-5-2", "meterVersion":"posture1", "currency":"ai_credits",
            "baseCredits":512, "weights":{"input":3,"output":12},
            "limits":{"input":8192,"output":256},
            "maximumCredits": if valid { 28160 } else { 28161 },
        });
        if terms != FixtureQuote::Internal {
            quote["consentVersion"] = json!("security-check-local-posture-v1");
        }
        if terms == FixtureQuote::WithFallback {
            quote["fallback"] = json!({
                "model":"claude-sonnet-5-5", "meterVersion":"posture1", "currency":"ai_credits",
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
            headers.push(("x-erpc-security-check-fallback", "claude-sonnet-5-5"));
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
        let fallback = wire("claude-sonnet-5-5", 516);
        if terms == FixtureQuote::WithFallback {
            request
                .fixture_receipt(&fallback)
                .expect("approved fallback receipt")
        } else {
            assert!(request.fixture_receipt(&fallback).is_err());
            request
                .fixture_receipt(&wire("claude-mythos-5-2", 527))
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
        let completed = &["scope", "quote", "price", "verify", "ssh", "submit"][..];
        for (refusal, quote_valid, lease_valid, terms, expected) in [
            (Some("scope"), true, true, Internal, &["scope"][..]),
            (None, false, true, Internal, &["scope", "quote"]),
            (
                Some("price"),
                true,
                true,
                WithFallback,
                &["scope", "quote", "price"],
            ),
            (
                None,
                true,
                false,
                Internal,
                &["scope", "quote", "price", "verify"],
            ),
            (None, true, true, Internal, completed),
            (None, true, true, Customer, completed),
            (None, true, true, WithFallback, completed),
        ] {
            let steps = RefCell::new(Vec::new());
            let result = super::run_selected(
                &server,
                |prompt| {
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
        let quote = r#"{"model":"claude-mythos-5-2","meterVersion":"posture1","currency":"ai_credits","baseCredits":512,"weights":{"input":3,"output":12},"limits":{"input":8192,"output":256},"maximumCredits":28160}"#;
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
    fn final_report_keeps_confirmed_environment_references_independent_of_file_modes() {
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
                Some(("claude-mythos-5-2", 527)),
                Some(("claude-sonnet-5-5", 516)),
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
                let Said::Text(text) = completed.render(&server, false) else {
                    panic!("human report expected");
                };
                assert_eq!(
                    text.contains("Local SSH finding · EnvironmentFile policy review"),
                    observed_reference
                );
                if let Some((model, charged)) = receipt {
                    assert!(text.contains(&format!("ERPC AI tokens charged: {charged} ({model},")));
                } else {
                    assert!(text.contains("No AI tokens were charged"));
                }
                let Said::Json(record) = completed.render(&server, true) else {
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
                    assert_eq!(record["modelReport"]["model"], model);
                    assert_eq!(record["modelReport"]["billing"]["chargedCredits"], charged);
                } else {
                    assert!(record.get("modelReport").is_none());
                    assert_eq!(record["settlement"], "no_charge");
                }
            }
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
