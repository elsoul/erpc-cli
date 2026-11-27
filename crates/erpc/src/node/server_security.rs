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

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use erpc_ai::session::Access as _;
use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::account::commands::{Outcome, Said};

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Run the metered Security Check for an owned ERPC server.
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

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
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

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
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

const SERVERS_URL: &str = "https://user-api.erpc.global/v3/ai/security-check/servers";
const SELECT_URL: &str = "https://user-api.erpc.global/v3/ai/security-check/servers/select";
// The account API stores IDs as safe JavaScript integers.
const MAX_RENTAL_ID: u64 = (1 << 53) - 1;

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
    let EligibleReply { servers } = serde_json::from_str(body).ok()?;
    let mut eligible: Vec<EligibleServer> = Vec::with_capacity(servers.len());
    for listed in servers {
        let server = listed.project()?;
        if eligible.iter().any(|row| row.rental == server.rental) {
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
        200 => {}
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

    async fn read_list(&self, url: &str) -> Result<Zeroizing<String>, Outcome> {
        let token = self.access.access_token().await.map_err(|_| sign_in())?;
        let (status, body) = self
            .client
            .get_with_token(Audience::AuthApi, url, &token)
            .await
            .map_err(|_| inventory_failed())?;
        list_body(status, body)
    }

    async fn eligible(&self) -> Result<Vec<EligibleServer>, Outcome> {
        let body = self.read_list(SERVERS_URL).await?;
        parse_eligible(&body).ok_or_else(inventory_failed)
    }

    async fn verify_rental(&self, server: &EligibleServer) -> Result<AuthorizedServer, Outcome> {
        let refused = || Outcome::Failed(t!("node_check.preflight_failed"));
        let token = self.access.access_token().await.map_err(|_| sign_in())?;
        let request = selection_body(server.rental);
        let (status, body) = self
            .client
            .post_with_token(
                Audience::AuthApi,
                SELECT_URL,
                &token,
                request.to_string().into_bytes(),
                None,
            )
            .await
            .map_err(|_| refused())?;
        verify_selection(status, &Zeroizing::new(body), server)
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
            "ssh_password": self.ssh.as_ref().map_or(Switch::Unknown, |ssh| ssh.password),
            "ssh_keyboard_interactive": self.ssh.as_ref().map_or(Switch::Unknown, |ssh| ssh.keyboard_interactive),
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
    collect_posture(&target).map_err(|failure| {
        Outcome::Failed(format!(
            "{}\n{failure} [{}]",
            t!("node_check.remote_failed"),
            failure.code()
        ))
    })
}

#[derive(Debug)]
enum PostureFailure {
    HostConfig,
    Capture(erpc_ssh::PrivateCaptureError),
    InvalidJson,
    InvalidPosture,
}

impl PostureFailure {
    fn code(&self) -> &'static str {
        match self {
            Self::HostConfig => "ssh_config",
            Self::Capture(failure) => failure.code(),
            Self::InvalidJson => "invalid_json",
            Self::InvalidPosture => "invalid_posture",
        }
    }
}

impl std::fmt::Display for PostureFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostConfig => {
                formatter.write_str("The pinned SSH host configuration could not be verified.")
            }
            Self::Capture(error) => write!(formatter, "{error}."),
            Self::InvalidJson => formatter.write_str("The collector response was not valid JSON."),
            Self::InvalidPosture => formatter
                .write_str("The collector response failed posture schema or range validation."),
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
    match cliclack::confirm(inspection_scope(&server))
        .initial_value(false)
        .interact()
    {
        Ok(true) => {}
        Ok(false) => return Outcome::Done(String::new()),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            return Outcome::Done(String::new());
        }
        Err(_) => return Outcome::Failed(t!("node_check.menu_failed")),
    }
    let approved = match billing::ApprovedReport::ask(&account).await {
        Ok(Some(approved)) => approved,
        Ok(None) => return Outcome::Done(String::new()),
        Err(outcome) => return outcome,
    };
    // Resolve the assignment again after consent and before opening SSH.
    let verified = match account.verify_rental(&server).await {
        Ok(verified) => verified,
        Err(outcome) => return outcome,
    };
    let observation = tokio::task::spawn_blocking(move || {
        let key = explicit_key
            .as_ref()
            .map(|(key, user)| (key.as_str(), user.as_str()));
        observe_remote(&verified, key)
    })
    .await;
    let result = match observation {
        Ok(Ok(result)) => result,
        Ok(Err(outcome)) => return outcome,
        Err(_) => return Outcome::Failed(t!("node_check.remote_failed")),
    };
    let id = approved.request_id.clone();
    let model = approved.submit(&account, server.rental, &result).await;
    if json {
        let mut output = serde_json::json!({
            "server": server.summary(), "source": "pinned_ssh", "posture": result, "requestId": id,
        });
        match model {
            Ok(receipt) => output["modelReport"] = serde_json::json!(receipt),
            Err(state) => {
                output["reportSource"] = serde_json::json!("local_rules");
                output["settlement"] = serde_json::json!(state.settlement);
                output["settlementDetail"] = serde_json::json!(state);
            }
        }
        return Said::Json(output).done();
    }
    let message = match model {
        Ok(receipt) => receipt.summary(),
        Err(state) => state.message(&id),
    };
    Outcome::Done(format!(
        "{}\n{}\n{}",
        server.label(),
        result.report(),
        message
    ))
}

#[cfg(test)]
mod tests {
    use erpc_core::i18n::Lang;
    use serde_json::json;

    use super::{
        Kind, Posture, PostureFailure, decode_posture, inspection_scope, list_body, parse_eligible,
        select_server, selection_body, verify_selection,
    };

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
    fn remote_posture_preserves_legacy_fields_and_projects_only_fixed_billing_facts() {
        let raw = json!({
            "listeners": "no_listener",
            "nftables": "tables_present",
            "ports": {
                "tcp":{"coverage":"complete","loopback":[],"wildcard":[{"port":16379,"services":["redis"]}],"interface":[]},
                "udp":{"coverage":"partial","loopback":[{"port":5353,"services":["unknown"]}],"wildcard":[],"interface":[]},
                "truncated":true
            },
            "ssh":{"password":"disabled","keyboard_interactive":"unknown"},
            "firewall":{"ipv4":"input_default_drop","ipv6":"unknown","truncated":false},
            "fail2ban":"sshd_jail_observed",
            "metadata":{
                "coverage":"observed","units_with_evidence":1,"truncated":false,
                "environment_files":{"owner_only":2,"group_or_other_access":0,"unknown":0},
                "service_env":{"owner_only":1,"group_or_other_access":0,"unknown":0},
                "credential_sources":{"owner_only":0,"group_or_other_access":1,"unknown":0},
                "credential_declarations":{"as_is":1,"encrypted":1}
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
            "redis_binding":"unknown","daemon_review":"unknown",
                "ssh_password":"disabled","ssh_keyboard_interactive":"unknown",
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
