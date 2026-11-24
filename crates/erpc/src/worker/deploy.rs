// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker deploy`: the app built for its server, shipped, and
//! running there, with the server's firewall up before the app starts.
//!
//! In order, so that what needs the person is asked first and not after a
//! long build, and nothing is paid for before erpc.toml has been checked.
//! A build that fails after a VPS was bought leaves that VPS charged and
//! on record, for the next deploy to take up:
//!
//! 1. erpc.toml is checked: every setting the app requires is set, and the
//!    secret gate lets this process read the trading key.
//! 2. The server: the one `[env.<name>]` names, an ERPC VPS of the account,
//!    a new hourly one ([`crate::worker::vps`]), or `--host`, chosen and
//!    agreed to now. Its host key is pinned here, or, for a VPS bought or
//!    taken up, once it is up and the build is done (step 3), before
//!    anything connects to it. A VPS bought here
//!    is on record the moment user-api names it, before it is ready, so a
//!    deploy that stops after that leaves it where the next deploy takes it
//!    up and `delete --release-server` ends it. Its start's request is on
//!    record from before it is sent (`[env.<name>.starting]`), so a start
//!    that gets no answer is sent again with the same key by the next
//!    deploy, and never with a new one ([`vps::StartRecord`]).
//! 3. The app is built for the server ([`crate::worker::build`]), while a
//!    VPS bought or taken up gets ready. A build that fails leaves such a
//!    VPS on record, charged, for the next deploy.
//! 4. The agent is installed when its digest differs, its unit written,
//!    and the agent started when it does not run (it starts locked: it has
//!    no key). One that runs is left running, whatever was replaced: it
//!    holds the key, and steps 5 to 7 can fail.
//! 5. The firewall ([`crate::worker::firewall`]): SSH only from
//!    `firewall.ssh_allow` and the address this deploy comes from, every
//!    other inbound connection dropped but for `run.port` from
//!    `firewall.app_allow`, and the port of a UDP Forwarding line on
//!    record from the addresses it sends from (when user-api names none,
//!    the port stays closed unless `--udp-any-source` opens it to any IPv4
//!    address). Each table goes under a rollback timer and is kept only
//!    once a fresh connection gets in. An app behind a WAF
//!    (`[waf]`) has the WAF's port opened in place of its own, and here
//!    only when the WAF an earlier deploy left runs the very config
//!    erpc.toml now makes, as a process of the agent step 4 installed.
//!    Where none runs the port stays closed until step 10. Where one runs
//!    other rules, or is a process of an agent from before the one
//!    installed, the opening in force stays as it is until step 10,
//!    unless erpc.toml only narrows it, which is applied here with the
//!    limit on new connections that is in force
//!    ([`crate::worker::firewall::decide`]). So a deploy that fails
//!    between here and step 10, and a `--prepare`, leave the old rules
//!    with the audience and the limit they had, never a wider one. The
//!    UDP port is not the WAF's to hold: it is opened as the line's
//!    record says, whatever step 5 does with the TCP port.
//! 6. The data lines asked for (`--grpc`, `--shreds`, `--udp`,
//!    `--unlimited`): the one erpc.toml names is taken up again, or a new
//!    hourly one is started for the server, at its price, and waited for,
//!    its request on record first as a VPS's is. Its endpoint reaches the
//!    app as `GRPC_ENDPOINT`, `SHREDS_ENDPOINT` or
//!    `SOLANA_SEND_RPC_ENDPOINT`; a UDP Forwarding line is pointed at the
//!    server's address and a UDP port of its own (`--udp-port`), which the
//!    app gets as `SHREDS_UDP_BIND`. A UDP Forwarding line on record that
//!    was not asked for again has the addresses it sends from read again.
//!    Then the firewall is applied again when what the lines let in
//!    changed.
//! 7. The release is uploaded and installed, its digests checked.
//! 8. The key and the secrets are read. An agent step 4 left running
//!    although it is not the one installed, or its unit changed, is
//!    restarted only now, and the key and the secrets go to the agent's
//!    memory at once. A `--prepare` ends before this, so it restarts
//!    nothing.
//! 9. The release is activated: the agent restarts the app from it and
//!    reports it healthy, or the server goes back to the release before.
//! 10. The WAF ([`crate::worker::waf`]), for an app with `[waf]`: its
//!     config goes to the agent, which writes it, starts the proxy (or
//!     restarts one whose files changed, or that is not a process of the
//!     agent installed) and answers once it listens, and only then is the
//!     WAF's port made what erpc.toml asks, its limit on new connections
//!     included, wherever step 5 left it otherwise
//!     ([`crate::worker::firewall::open_as_asked`]). A WAF that does not
//!     come up fails the deploy with why, the release still running, the
//!     firewall as step 5 left it and the WAF from before, if there was
//!     one, back with its own rules. An app without `[waf]` has a WAF an
//!     earlier deploy left removed. `--prepare` stops before this, as it
//!     stops before the app is started.
//! 11. `[env.<name>]` in erpc.toml gets the server, its pinned key, the
//!     allow list and the lines, or, for an inventory environment, its
//!     1Password item does and erpc.toml names the vault (decision 9). A
//!     new environment is an inventory one when `erpc login` keeps the
//!     session in 1Password (`--vault` names another vault, `--inline`
//!     keeps it in erpc.toml). The app is entered in this machine's
//!     index. This is written right after step 5, and again after each
//!     line, so a failure later leaves the server and the lines on record.

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use erpc_core::i18n::Lang;
use erpc_ssh::worker::{Command as Worker, Digest, ReleaseId, RunningAgent, UnitId, Verb};
use erpc_ssh::{RemoteCommand, RemotePath, Session, Target};
use erpc_worker::manifest::{
    Env, Firewall, Inventory, Line, LineKind, Manifest, Resource, ResourceKind, Start, StartOf,
};
use erpc_worker::net::Cidr;
use erpc_worker::server::Launch;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::account::commands::Outcome;
use crate::cli::error::{CliError, Code};
use crate::node::common::{Say, go_ahead};
use crate::worker::remote::{ctl, ctl_ok, failed, open, unlock_request};
use crate::worker::vps::{self, Api, LineRecord, LineTarget, Server, StartRecord, Stays};
use crate::worker::{App, EnvRecord, load_env};

/// A `t!` message said in `lang` rather than the run's language: what a
/// command also puts in its `--json` output is English there, for the
/// scripts that read it. `said_in!(lang, t!("area.key", name))`.
macro_rules! said_in {
    ($lang:expr, t!($key:literal $(, $name:ident $(= $value:expr)?)* $(,)?)) => {
        $crate::cli::i18n::CATALOG.text(
            $lang,
            $key,
            &[$((stringify!($name), &$crate::cli::i18n::arg!($name $(= $value)?) as &dyn ::std::fmt::Display)),*],
        )
    };
}

pub(crate) use said_in;

/// Where uploads are staged on the server.
pub(crate) const UPLOADS: &str = "/opt/erpc/uploads";

/// Where the server is, when erpc.toml does not say yet.
#[derive(Debug, Clone, Default)]
pub(crate) struct Where {
    pub(crate) host: Option<String>,
    pub(crate) user: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) fingerprint: Option<String>,
    pub(crate) vps: Option<i64>,
    pub(crate) new_vps: bool,
    pub(crate) region: Option<String>,
    pub(crate) plan: Option<String>,
    /// The data lines asked for, each at a plan (`None`: the cheapest).
    pub(crate) lines: Vec<(LineKind, Option<String>)>,
    /// The UDP port a UDP Forwarding line sends to (`None`: the port of
    /// the line on record, else [`vps::DEFAULT_UDP_PORT`]).
    pub(crate) udp_port: Option<u16>,
    /// The region a UDP Forwarding line sends from (`None`: the server's).
    pub(crate) udp_region: Option<String>,
    /// Open the UDP Forwarding line's port to any IPv4 address when
    /// user-api names none it sends from; without it the port stays closed.
    pub(crate) udp_any_source: bool,
    /// For a new environment: keep its server facts in this 1Password vault.
    pub(crate) vault: Option<String>,
    /// For a new environment: keep its server facts in erpc.toml.
    pub(crate) inline: bool,
    /// Lines on record the operator says are gone: they leave the record
    /// before the lines are looked at.
    pub(crate) forget_lines: Vec<String>,
    /// Who answers what a start asks.
    pub(crate) starts: Starts,
    /// How far the deploy goes.
    pub(crate) upto: Upto,
}

/// Who answers what a start asks (an hourly product's price) and the
/// first login to a server erpc has not made key-only yet, a new one or
/// one named with `--vps`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Starts {
    /// The person at the terminal.
    #[default]
    Asked,
    /// `--yes`: the command line named what to start, and that is the yes.
    Accepted,
}

impl Starts {
    /// From `--yes`.
    pub(crate) const fn from_yes(yes: bool) -> Self {
        if yes { Self::Accepted } else { Self::Asked }
    }

    const fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// How far a deploy goes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Upto {
    /// The key and the secrets handed over, and the release started.
    #[default]
    Started,
    /// `--prepare`: everything that needs neither the key nor a secret --
    /// the server, the firewall, the lines, a release on the server -- and
    /// nothing started, stopped or restarted. The next deploy hands them
    /// over and starts the app, from a release it builds and installs
    /// itself: a release is named after the time it was built, so the one
    /// installed here is not the one that is started.
    Prepared,
}

impl Upto {
    /// From `--prepare`.
    pub(crate) const fn from_prepare(prepare: bool) -> Self {
        if prepare {
            Self::Prepared
        } else {
            Self::Started
        }
    }

    const fn prepares(self) -> bool {
        matches!(self, Self::Prepared)
    }

    /// What becomes of an agent that step 4 left running although a newer
    /// one is installed (`waits`). A restarted agent has neither the key
    /// nor the secrets, and its app stays down until they are handed over.
    /// So a deploy restarts it only when it is about to hand them over,
    /// and a `--prepare`, which hands nothing over, leaves it running.
    const fn waiting_agent(self, waits: bool) -> WaitingAgent {
        match (waits, self) {
            (false, _) => WaitingAgent::None,
            (true, Self::Prepared) => WaitingAgent::Kept,
            (true, Self::Started) => WaitingAgent::Restart,
        }
    }
}

/// What becomes of an agent step 4 left running although a newer one is
/// installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitingAgent {
    /// None waits: the agent that runs is the one installed, or it did not
    /// run and was started.
    None,
    /// `--prepare`: it runs on, and the new one takes over at the next
    /// deploy.
    Kept,
    /// It is restarted right before the key is handed over.
    Restart,
}

/// Whether the setup of step 4 left an agent running that is older than
/// what is now on the server: its answer says the agent was kept and that
/// its unit or its binary waits for the next restart, or this deploy
/// replaced the binary.
fn agent_waits(set_up: &Value, agent_changed: bool) -> bool {
    set_up["agent"] == json!("kept") && (agent_changed || set_up["newer_waits"] == json!(true))
}

/// Step 4's setup, sent through `ctl`: always [`RunningAgent::Keep`]. An
/// agent that runs holds the key, and the firewall, a line or the upload
/// can still fail, so whatever was replaced it is left running; one that
/// does not run is started, locked. Returns setup's answer, and what
/// becomes of an agent it kept although a newer one is installed.
fn keep_agent(
    upto: Upto,
    agent_changed: bool,
    ctl: impl FnOnce(Verb) -> Result<Value, CliError>,
) -> Result<(Value, WaitingAgent), CliError> {
    let set_up = ctl(Verb::Setup(RunningAgent::Keep))?;
    let waiting = upto.waiting_agent(agent_waits(&set_up, agent_changed));
    Ok((set_up, waiting))
}

/// Step 8, in the one order that leaves a running app running for as long
/// as it can:
///
/// 1. `read` the key and the secrets. A key nobody allowed ends the deploy
///    here, with the agent untouched.
/// 2. When an agent `waiting` to be replaced was left running at step 4,
///    restart it (`restarting` says so first). It comes back locked, which
///    stops the app.
/// 3. Unlock: the key and the secrets go to the agent at once.
///
/// A `--prepare` (`upto`) does none of it: nothing is read, and nothing
/// is asked of the agent. That is decided here and nowhere else, so that
/// the one function that reads the key is also the one that knows when
/// not to.
///
/// Returns whether the agent was restarted, or `None` when nothing was
/// handed over. A failure after the restart says that it was
/// ([`after_restart`]).
fn hand_over(
    upto: Upto,
    waiting: WaitingAgent,
    scope: &str,
    read: impl FnOnce() -> Result<zeroize::Zeroizing<Vec<u8>>, CliError>,
    restarting: impl FnOnce(),
    mut ctl: impl FnMut(Verb, Option<&[u8]>) -> Result<Value, CliError>,
) -> Result<Option<bool>, CliError> {
    if upto.prepares() {
        return Ok(None);
    }
    let request = read()?;
    let restart = waiting == WaitingAgent::Restart;
    if restart {
        restarting();
        ctl(Verb::Setup(RunningAgent::Restart), None).map_err(|e| after_restart(e, scope))?;
    }
    match ctl(Verb::Unlock, Some(&request)) {
        Ok(_) => Ok(Some(restart)),
        Err(e) if restart => Err(after_restart(e, scope)),
        Err(e) => Err(e),
    }
}

/// A failure of step 8 once the agent was restarted for a newer one: the
/// restart happened, and the key did not reach the agent, so the app that
/// ran is stopped. Said in the hint, and for `--json` in the details.
fn after_restart(e: CliError, scope: &str) -> CliError {
    let next = t!("worker_deploy.agent.restarted_hint", scope);
    let hint = match e.hint.clone() {
        Some(hint) => t!("worker_deploy.and_then", hint, next),
        None => next,
    };
    agent_restarted(e.hint(hint))
}

/// `e`, with `agent.restarted` in its details for `--json`: what a failure
/// after the restart of step 8 carries, since no answer follows it.
fn agent_restarted(e: CliError) -> CliError {
    let mut details = match e.details.clone() {
        Some(Value::Object(details)) => details,
        _ => serde_json::Map::new(),
    };
    details.insert("agent".to_owned(), json!({ "restarted": true }));
    e.details(Value::Object(details))
}

/// Why step 4's setup could not write the rule that keeps needrestart
/// from the workers, when it could not: the agent's own words.
fn needrestart_error(set_up: &Value) -> Option<&str> {
    set_up["needrestart_error"].as_str()
}

/// What a deploy says when that rule could not be written. Said, not
/// fatal: the worker runs, but a package run on the server can restart
/// it, and a restarted worker waits for its key.
fn needrestart_said(set_up: &Value, scope: &str) -> Option<String> {
    needrestart_error(set_up).map(|error| t!("worker_deploy.agent.needrestart", error, scope))
}

/// What the answer says of the agent, for `--json`: the one installed,
/// what became of the one that ran, and why the needrestart rule could not
/// be written, when it could not, since the line that says so is not
/// printed then.
fn agent_said(agent: &Agent, set_up: &Value, changed: bool, kept: bool, restarted: bool) -> Value {
    json!({
        "sha256": agent.sha256,
        "source": agent.source.as_str(),
        "changed": changed,
        "kept": kept,
        "restarted": restarted,
        "needrestart_error": needrestart_error(set_up),
    })
}

/// The failure of step 9, from an activation's answer that is not `ok`:
/// the agent's own words for why, what became of the release that ran,
/// and where to look. A start refused because the app's health port is
/// taken says what to change instead of pointing at the log.
fn activation_failed(answer: &Value, release: &str, scope: &str) -> CliError {
    let why = answer["error"]
        .as_str()
        .map_or_else(|| t!("worker_deploy.failed.unhealthy"), str::to_owned);
    let back = if answer["unchanged"] == json!(true) {
        // The agent refused before it switched anything: the release in
        // use, when there is one, was never stopped.
        t!("worker_deploy.failed.unchanged")
    } else if answer["rolled_back"] == json!(true) {
        let to = answer["running"]
            .as_str()
            .map_or_else(|| t!("worker_deploy.failed.previous"), str::to_owned);
        if answer["running_healthy"] == json!(true) {
            t!("worker_deploy.failed.back_healthy", to)
        } else {
            t!("worker_deploy.failed.back_unhealthy", to)
        }
    } else {
        t!("worker_deploy.failed.no_earlier")
    };
    let hint = crate::worker::remote::port_hint(&why)
        .unwrap_or_else(|| t!("worker_deploy.failed.logs", scope));
    failed(t!("worker_deploy.failed.release", release, why, back)).hint(hint)
}

impl Where {
    /// The lines asked for, each with its plan.
    fn lines(&self) -> Vec<(LineKind, Option<&str>)> {
        self.lines
            .iter()
            .map(|(kind, plan)| (*kind, plan.as_deref()))
            .collect()
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The agents this erpc carries, by machine (see `build.rs`); empty in a
/// build made without them.
const EMBEDDED_AGENTS: [(&str, &[u8]); 2] = [
    (
        "x86_64",
        include_bytes!(concat!(env!("OUT_DIR"), "/erpc-worker-agent-x86_64-linux")),
    ),
    (
        "aarch64",
        include_bytes!(concat!(env!("OUT_DIR"), "/erpc-worker-agent-aarch64-linux")),
    ),
];

/// The agent this erpc carries for `machine`, if it carries one.
pub(crate) fn embedded_agent(machine: &str) -> Option<&'static [u8]> {
    EMBEDDED_AGENTS
        .iter()
        .find(|(m, bytes)| *m == machine && !bytes.is_empty())
        .map(|(_, bytes)| *bytes)
}

/// Where the agent a deploy installs comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentSource {
    /// The one this erpc carries, which the release's signature covers.
    Embedded,
    /// `ERPC_WORKER_AGENT`: a build of one's own.
    Named,
    /// The file beside this erpc, in a build that carries none.
    Beside,
}

impl AgentSource {
    /// `ERPC_WORKER_AGENT` first, when set; else what this erpc carries;
    /// else the file beside it.
    const fn choose(named: bool, carried: bool) -> Self {
        match (named, carried) {
            (true, _) => Self::Named,
            (false, true) => Self::Embedded,
            (false, false) => Self::Beside,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Named => "ERPC_WORKER_AGENT",
            Self::Beside => "beside erpc",
        }
    }
}

/// The agent a deploy installs, where it came from, and its digest.
struct Agent {
    bytes: Vec<u8>,
    source: AgentSource,
    sha256: String,
}

/// The agent for `target`'s machine ([`AgentSource::choose`]). One named by
/// `ERPC_WORKER_AGENT` that differs from the agent this erpc carries is said
/// on standard error whether or not output is quiet. The deploy's report
/// names the agent's source and digest in every case, since an agent from
/// `ERPC_WORKER_AGENT` or found beside erpc is not the one the release's
/// signature covers.
fn agent_binary(triple: &str) -> Result<Agent, CliError> {
    let machine = triple.split('-').next().unwrap_or(triple);
    let carried = embedded_agent(machine);
    let source = AgentSource::choose(
        std::env::var_os("ERPC_WORKER_AGENT").is_some(),
        carried.is_some(),
    );
    let bytes = match (source, carried) {
        (AgentSource::Embedded, Some(bytes)) => bytes.to_vec(),
        _ => other_agent(machine)?,
    };
    let sha256 = hex(&Sha256::digest(&bytes));
    if source == AgentSource::Named && carried.is_some_and(|c| c != bytes.as_slice()) {
        crate::cli::interrupt::say(&format!(
            "warning: {}",
            t!("worker_deploy.agent.named", sha256)
        ));
    }
    Ok(Agent {
        bytes,
        source,
        sha256,
    })
}

/// An agent from `ERPC_WORKER_AGENT`, or beside this erpc.
fn other_agent(machine: &str) -> Result<Vec<u8>, CliError> {
    let path = match std::env::var_os("ERPC_WORKER_AGENT") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(Path::to_owned))
            .map(|dir| dir.join(format!("erpc-worker-agent-{machine}-linux")))
            .ok_or_else(|| failed(t!("worker_deploy.agent.no_exe")))?,
    };
    std::fs::read(&path).map_err(|e| {
        let path = path.display();
        failed(t!("worker_deploy.agent.none", machine, path, error = e))
            .hint(t!("worker_deploy.agent.none_hint"))
    })
}

fn remote_path(path: &str) -> Result<RemotePath, CliError> {
    RemotePath::new(path).map_err(|e| failed(e.to_string()))
}

/// Writes `bytes` to `path` on the server and checks they arrived whole.
pub(crate) fn upload(session: &Session, path: &str, bytes: &[u8]) -> Result<(), CliError> {
    let remote = remote_path(path)?;
    session
        .run(&RemoteCommand::WriteFile(remote.clone()), Some(bytes))
        .map_err(|e| failed(t!("worker_deploy.upload.failed", path, error = e)))?;
    let out = session
        .run(&RemoteCommand::Sha256(remote), None)
        .map_err(|e| failed(t!("worker_deploy.upload.not_checked", path, error = e)))?;
    let got = String::from_utf8_lossy(&out.stdout);
    if got.split_whitespace().next() == Some(hex(&Sha256::digest(bytes)).as_str()) {
        Ok(())
    } else {
        Err(failed(t!("worker_deploy.upload.not_whole", path)))
    }
}

/// `key=value` lines' value for `key`.
fn value(stdout: &[u8], key: &str) -> Option<String> {
    String::from_utf8_lossy(stdout).lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|v| v.trim().to_owned())
    })
}

/// Where a new environment keeps its server facts: in a 1Password vault
/// when `--vault` names one, or when `erpc login` keeps the session in
/// 1Password and a vault is chosen; else in erpc.toml.
fn new_inventory(at: &Where) -> Result<Option<Inventory>, CliError> {
    if at.inline {
        return Ok(None);
    }
    match crate::worker::secrets::choose(None, at.vault.as_deref()) {
        Ok(crate::worker::secrets::Store::OnePassword { vault }) => Ok(Some(Inventory { vault })),
        // --vault given, and not usable: said, not passed over.
        Err(e) if at.vault.is_some() => Err(CliError::new(Code::Usage, e)),
        _ => Ok(None),
    }
}

/// The server a line of `kind` is for: its address; for a UDP Forwarding
/// line, the port the shreds are sent to (`--udp-port`, else the port of
/// the line on record, else [`vps::DEFAULT_UDP_PORT`]) and the
/// region they are sent from (`--udp-region`, else the server's); for the
/// others, the server's region.
fn line_target(
    kind: LineKind,
    at: &Where,
    ip: Ipv4Addr,
    region: Option<&str>,
    lines: &[Line],
) -> LineTarget {
    let region = region.map(ToOwned::to_owned);
    if kind != LineKind::Udp {
        return LineTarget {
            ip,
            udp_port: None,
            region,
        };
    }
    let on_record = lines
        .iter()
        .find(|l| l.kind == LineKind::Udp)
        .and_then(vps::udp_port);
    LineTarget {
        ip,
        udp_port: Some(at.udp_port.or(on_record).unwrap_or(vps::DEFAULT_UDP_PORT)),
        region: at.udp_region.clone().or(region),
    }
}

/// `e` with `more` after the hint it has: what the step that failed said of
/// its own trouble (a UDP line's destination that will never be taken, say)
/// is kept, and what becomes of the line is said after it.
fn and_hint(e: CliError, more: String) -> CliError {
    match e.hint.clone() {
        Some(hint) => e.hint(format!("{hint}\n{more}")),
        None => e.hint(more),
    }
}

/// Refuses a server address UDP Forwarding cannot send to: one that is not
/// a public IPv4 address ([`erpc_api::udp::is_public_destination`]).
/// user-api would refuse to point the line there, after a Standard line
/// was started and charged.
fn udp_public(ip: Ipv4Addr) -> Result<(), CliError> {
    if erpc_api::udp::is_public_destination(ip) {
        return Ok(());
    }
    Err(
        CliError::new(Code::Usage, t!("worker_deploy.line.udp_not_public", ip))
            .hint(t!("worker_deploy.line.udp_not_public_hint")),
    )
}

/// The region a UDP Forwarding line of this deploy would send from, as far
/// as it is known before anything is bought, decided as [`server`] decides
/// the server: `--udp-region`; else the region of the server on record (a
/// server of the user's own has none, and needs `--udp-region`); else the
/// region of a VPS a stopped deploy left on record; a server named with
/// `--host` has none; one named with `--vps` is read with it, and checked
/// before any line is started (`None` here); a new VPS is bought in
/// `--region`, else the nearest region. Chosen at a terminal from the
/// account's servers, it is checked before any line is started too.
fn udp_region_before(at: &Where, env: &Env) -> Result<Option<String>, CliError> {
    if let Some(region) = &at.udp_region {
        return Ok(Some(region.clone()));
    }
    let on_record = env.resource.as_ref().and_then(|r| r.region.clone());
    if env.host.is_some() {
        return on_record.map(Some).ok_or_else(vps::udp_no_region);
    }
    if pending_vps(Some(env)).is_some() {
        return Ok(on_record);
    }
    if at.host.is_some() {
        return Err(vps::udp_no_region());
    }
    if at.new_vps {
        let region = at
            .region
            .clone()
            .unwrap_or_else(|| vps::nearest_region().to_owned());
        return Ok(Some(region));
    }
    Ok(None)
}

/// The server's address, where it is known before anything is bought, as
/// `server()` takes it: the one on record, else none while a VPS on record
/// is still to be reached (its address is checked once it is), else
/// `--host`. A host name is not judged.
fn udp_host_before<'a>(at: &'a Where, env: &'a Env) -> Option<Ipv4Addr> {
    let host = match (&env.host, pending_vps(Some(env))) {
        (Some(host), _) => Some(host.as_str()),
        (None, Some(_)) => None,
        (None, None) => at.host.as_deref(),
    };
    host.and_then(|host| host.parse().ok())
}

/// What the UDP step would be refused for, asked before the server and the
/// other lines are bought (refused after them, they would be left charged):
/// the port, the server's address where it is known, the region, and what
/// user-api says of the plan and the product's lines ([`vps::udp_ready`]),
/// through the session `open` gives. Nothing when no UDP line is asked for,
/// and no session is opened then.
async fn udp_before_buying<O, F>(
    at: &Where,
    env: &Env,
    run_port: Option<u16>,
    scope: &str,
    open: O,
) -> Result<(), CliError>
where
    O: FnOnce() -> F,
    F: core::future::Future<Output = Result<Api, CliError>>,
{
    let Some((_, plan)) = at.lines.iter().find(|(kind, _)| *kind == LineKind::Udp) else {
        return Ok(());
    };
    // A line `--forget-line` takes off the record is not the environment's
    // own any more.
    let on_record = env
        .lines
        .iter()
        .find(|l| l.kind == LineKind::Udp && !at.forget_lines.contains(&l.id));
    let port = at
        .udp_port
        .or_else(|| on_record.and_then(vps::udp_port))
        .unwrap_or(vps::DEFAULT_UDP_PORT);
    let ports = Ports {
        ssh: at.port.or(env.ssh_port).unwrap_or(22),
        run: run_port,
        others_udp: Vec::new(),
    };
    udp_port_free(port, &ports)?;
    if let Some(ip) = udp_host_before(at, env) {
        udp_public(ip)?;
    }
    let region = udp_region_before(at, env)?;
    let api = open().await?;
    let check = vps::UdpCheck {
        plan: plan.as_deref(),
        on_record: on_record.map(|l| l.id.as_str()),
        pending: env.starting.contains_key(&StartOf::Udp),
        region: region.as_deref(),
        nothing_bought: true,
        scope,
    };
    vps::udp_ready(&api, &check).await
}

/// The ports of the server a UDP Forwarding line's port is checked
/// against.
#[derive(Debug, Default)]
struct Ports {
    /// SSH's.
    ssh: u16,
    /// The app's own (`run.port`).
    run: Option<u16>,
    /// The UDP ports the server's other workers receive on, by worker, as
    /// its firewall has them.
    others_udp: Vec<(String, u16)>,
}

/// Refuses a UDP port the server has in use already: SSH's, the app's own
/// (`run.port`), or the one another worker on the server receives on.
fn udp_port_free(port: u16, ports: &Ports) -> Result<(), CliError> {
    let taken = if port == ports.ssh {
        t!("worker_deploy.line.udp_port_ssh")
    } else if ports.run == Some(port) {
        t!("worker_deploy.line.udp_port_app")
    } else if let Some((worker, _)) = ports.others_udp.iter().find(|(_, p)| *p == port) {
        t!("worker_deploy.line.udp_port_worker", worker)
    } else {
        return Ok(());
    };
    Err(CliError::new(
        Code::Usage,
        t!("worker_deploy.line.udp_port_taken", port, taken),
    )
    .hint(t!("worker_deploy.line.udp_port_hint")))
}

/// The UDP ports the server's other workers receive on, from the openings
/// its firewall keeps (`firewall-show`): what a new UDP Forwarding line
/// must not be pointed at. The server's answer is read, not trusted to be
/// well formed: an opening without a UDP port names none.
fn others_udp_ports(shown: &Value, me: &str) -> Vec<(String, u16)> {
    shown["openings"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(worker, _)| worker.as_str() != me)
        .filter_map(|(worker, opening)| {
            let port = u16::try_from(opening["udp"]["port"].as_u64()?).ok()?;
            Some((worker.clone(), port))
        })
        .collect()
}

/// Where the lines step keeps what it starts, and how it speaks.
#[derive(Clone, Copy)]
struct Step<'a> {
    /// The environment's record, written as each line is named.
    record: &'a EnvRecord<'a>,
    /// What this deploy has put on record that is charged.
    on_record: &'a RefCell<Vec<String>>,
    /// The app and environment, as a hint's command names them.
    scope: &'a str,
    say: &'a Say,
}

/// Ends line `id` of `kind`, started by this deploy, after a step failed
/// with `e`: asked as every end is, since the line is charged from its
/// start and the step that failed may not pass on a second try. Ended, it
/// leaves the record; kept, the hint says how to carry on with it.
async fn end_started(
    api: &Api,
    (kind, id): (LineKind, &str),
    env: &mut Env,
    step: Step<'_>,
    e: CliError,
) -> CliError {
    let Step {
        record,
        on_record,
        scope,
        say,
    } = step;
    say.line(&t!("worker_deploy.line.charged", message = e.message));
    let Some(line) = env.lines.iter().find(|l| l.kind == kind).cloned() else {
        return e;
    };
    let ended = match vps::end_line(api, &line, say).await {
        Ok(_) => {
            env.lines.retain(|l| l.kind != kind);
            let _ = record.save(env, None);
            let ended = line_name(kind, id);
            on_record.borrow_mut().retain(|w| *w != ended);
            Ended::Yes
        }
        // Refused for good: deploying again would not point it either, so it
        // is not among what the next deploy carries on with.
        Err(_) if vps::is_refused_for_good(&e) => {
            let kept = line_name(kind, id);
            on_record.borrow_mut().retain(|w| *w != kept);
            Ended::KeptRefused
        }
        Err(_) => Ended::Kept,
    };
    end_said(e, ended, id, scope)
}

/// What became of a line [`end_started`] offered to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    Yes,
    /// Not ended, and the step failed for good: deploying again does not
    /// carry on with it.
    KeptRefused,
    /// Not ended: deploying again carries on with it.
    Kept,
}

/// The step's error `e`, with what became of line `id` after its own hint
/// ([`and_hint`]): ended; kept, charged until it is ended, and how to end
/// it alone; or kept, and how to carry on with it.
fn end_said(e: CliError, ended: Ended, id: &str, scope: &str) -> CliError {
    match ended {
        Ended::Yes => and_hint(e, t!("worker_deploy.line.ended", id)),
        Ended::KeptRefused => and_hint(e, t!("worker_deploy.line.udp_end_alone", id, scope)),
        Ended::Kept => and_hint(e, t!("worker_deploy.line.not_ended", id, scope)),
    }
}

/// What becomes of line `id` of `kind` whose wait failed with `e`, `new`
/// when this deploy started it.
#[derive(Debug)]
enum AfterWait {
    /// Cancelled while it was waited for, started here or before: charged
    /// no more, and neither to be ended nor waited for again; its own hint
    /// says what is left to do.
    Cancelled(CliError),
    /// Started here: offered to be ended ([`end_started`]).
    EndStarted(CliError),
    /// On record from before, or an Unlimited RPC, which cannot be ended
    /// while it is being set up: said with what to do about it.
    Said(CliError),
}

/// Decides [`AfterWait`], in this order: a cancelled UDP Forwarding line
/// first, since one this deploy started is no longer one to end.
fn after_wait(kind: LineKind, id: &str, new: bool, e: CliError, scope: &str) -> AfterWait {
    if kind == LineKind::Udp && vps::is_udp_cancelled(&e, id) {
        return AfterWait::Cancelled(e);
    }
    if new && kind != LineKind::Unlimited {
        return AfterWait::EndStarted(e);
    }
    // Refused for good: waiting again does not help; ending it does.
    if kind == LineKind::Udp && vps::is_refused_for_good(&e) {
        return AfterWait::Said(and_hint(
            e,
            t!("worker_deploy.line.udp_end_alone", id, scope),
        ));
    }
    AfterWait::Said(and_hint(
        e,
        t!("worker_deploy.line.still_waiting", id, scope),
    ))
}

/// The UDP Forwarding line's port, region and list again, now that the
/// server (`ip` in `region`) and the other workers on it are known, before
/// any line is started: refused at the UDP step, the lines before it would
/// be left charged. Nothing when no UDP line is asked for.
async fn udp_before_lines(
    api: &Api,
    at: &Where,
    ports: &Ports,
    (ip, region): (Ipv4Addr, Option<&str>),
    env: &Env,
    (nothing_bought, scope): (bool, &str),
) -> Result<(), CliError> {
    let Some((_, plan)) = at
        .lines()
        .into_iter()
        .find(|(kind, _)| *kind == LineKind::Udp)
    else {
        return Ok(());
    };
    udp_public(ip)?;
    let target = line_target(LineKind::Udp, at, ip, region, &env.lines);
    let (port, udp_region) = vps::udp_target(&target)?;
    udp_port_free(port, ports)?;
    let check = vps::UdpCheck {
        plan,
        on_record: env
            .lines
            .iter()
            .find(|l| l.kind == LineKind::Udp)
            .map(|l| l.id.as_str()),
        pending: env.starting.contains_key(&StartOf::Udp),
        region: Some(udp_region),
        nothing_bought,
        scope,
    };
    vps::udp_ready(api, &check).await
}

/// The data lines asked for: one `env` names and the account still has
/// is taken up again, else a new one is started for the server, its
/// request on record first ([`LineStart`]). A new line goes into erpc.toml
/// as soon as user-api names it, before it is active, so a deploy that
/// stops waiting leaves it on record: the next one takes it up, and
/// `delete --release-server` ends it. A new gRPC, Shreds or UDP Forwarding
/// line that user-api does not list after its start, or that does not
/// become active, is offered to be ended at once; an Unlimited RPC cannot
/// be ended while it is being set up.
async fn lines(
    at: &Where,
    ports: &Ports,
    server: &Server,
    env: &mut Env,
    step: Step<'_>,
) -> Result<(), CliError> {
    let api = Api::open().await?.accepting(at.starts.accepted());
    lines_with(&api, at, ports, server, env, step).await
}

/// [`lines`], through `api`.
async fn lines_with(
    api: &Api,
    at: &Where,
    ports: &Ports,
    server: &Server,
    env: &mut Env,
    step: Step<'_>,
) -> Result<(), CliError> {
    let Step {
        record,
        on_record,
        scope,
        say,
    } = step;
    let host = &server.target.host;
    let region = server.resource.region.as_deref();
    let ip: Ipv4Addr = host.parse().map_err(|_| {
        failed(t!("worker_deploy.line.not_ipv4", host)).hint(t!("worker_deploy.line.not_ipv4_hint"))
    })?;
    let nothing_bought = on_record.borrow().is_empty();
    udp_before_lines(api, at, ports, (ip, region), env, (nothing_bought, scope)).await?;
    for (kind, plan) in at.lines() {
        let target = line_target(kind, at, ip, region, &env.lines);
        let (known, next) = line_next(api, kind, env, record, say).await?;
        let (id, hourly, new) = match (known, next) {
            (Some(line), LineNext::TakeUp) => {
                say.line(&t!("worker_deploy.line.taking_up", id = line.id));
                (line.id, line.hourly, false)
            }
            (Some(line), LineNext::Wait(why)) => {
                let (name, id, why) = (line_name(kind, &line.id), &line.id, why.says());
                let hint = if line.hourly {
                    t!("worker_deploy.line.wait_hint", id)
                } else {
                    t!("worker_deploy.line.wait_hint_unbilled", id)
                };
                return Err(failed(t!("worker_deploy.line.wait", name, why)).hint(hint));
            }
            _ => {
                let mut start = LineStart {
                    kind,
                    env: &mut *env,
                    record,
                    on_record,
                    scope,
                };
                let id = vps::start_line(api, kind, &target, plan, scope, say, &mut start).await?;
                match vps::first_sight(api, kind, &id, true, scope).await {
                    Ok(line) => keep(env, line, record)?,
                    // Started and charged, and user-api does not show it:
                    // offered to be ended, as one that never becomes active
                    // is.
                    Err(e) if kind != LineKind::Unlimited => {
                        return Err(end_started(api, (kind, &id), env, step, e).await);
                    }
                    Err(e) => return Err(e),
                }
                (id, true, true)
            }
        };
        say.line(&t!("worker_deploy.line.waiting", id));
        if kind == LineKind::Unlimited {
            say.line(&t!("worker_deploy.line.unlimited_slow"));
        }
        match vps::wait_line(api, kind, &id, &target, hourly, say).await {
            Ok(line) => {
                let endpoint = &line.endpoint;
                say.line(&t!("worker_deploy.line.active", id, endpoint));
                // Said here, where it stays on the screen: the line is up
                // and nothing can reach the app from it, or anything can.
                if kind == LineKind::Udp && line.sources.is_empty() {
                    let said = if at.udp_any_source {
                        t!("worker_deploy.line.udp_unnamed_open", id)
                    } else {
                        t!("worker_deploy.line.udp_unnamed_closed", id, scope)
                    };
                    say.line(&format!("warning: {said}"));
                }
                keep(env, line, record)?;
            }
            Err(e) => {
                return Err(match after_wait(kind, &id, new, e, scope) {
                    AfterWait::Cancelled(e) => {
                        let ended = line_name(kind, &id);
                        on_record.borrow_mut().retain(|w| *w != ended);
                        e
                    }
                    AfterWait::EndStarted(e) => end_started(api, (kind, &id), env, step, e).await,
                    AfterWait::Said(e) => e,
                });
            }
        }
    }
    Ok(())
}

/// Takes lines `ids` off `env`'s record, as the operator asked, and
/// returns them; an id not on record changes nothing and is a usage error.
/// erpc then no longer knows of them: one that still runs is charged until
/// it is ended in the dashboard.
pub(crate) fn take_lines(env: &mut Env, ids: &[String]) -> Result<Vec<Line>, CliError> {
    if let Some(id) = ids
        .iter()
        .find(|id| !env.lines.iter().any(|l| &l.id == *id))
    {
        return Err(CliError::new(
            Code::Usage,
            t!("worker_deploy.line.not_on_record", id),
        ));
    }
    let (gone, kept) = env.lines.drain(..).partition(|l| ids.contains(&l.id));
    env.lines = kept;
    Ok(gone)
}

/// What is said of lines taken off the record with `--forget-line`.
pub(crate) fn say_forgotten(lines: &[Line]) -> Option<String> {
    (!lines.is_empty()).then(|| {
        let names: Vec<String> = lines.iter().map(|l| line_name(l.kind, &l.id)).collect();
        let names = names.join(", ");
        tn!("worker_deploy.line.forgotten", lines.len(), names)
    })
}

/// The line of `kind` `env` has on record, and what to do about it. One
/// that is gone leaves the record here.
async fn line_next(
    api: &Api,
    kind: LineKind,
    env: &mut Env,
    record: &EnvRecord<'_>,
    say: &Say,
) -> Result<(Option<Line>, LineNext), CliError> {
    let known = env.lines.iter().find(|l| l.kind == kind).cloned();
    // Whether it exists comes from what the account is charged for; the
    // status list says only whether it is set up yet.
    let next = match &known {
        Some(line) => {
            let listed = vps::line_row(api, kind, &line.id).await?.is_some();
            let charged = vps::is_charged(&vps::charged(api).await?, line);
            LineNext::of(
                kind,
                Some((line.hourly, line.is_pending())),
                listed,
                charged,
            )
        }
        None => LineNext::of(kind, None, false, false),
    };
    if next == LineNext::Forget
        && let Some(gone) = &known
    {
        let name = line_name(kind, &gone.id);
        say.line(&t!("worker_deploy.line.gone", name));
        env.lines.retain(|l| l.kind != kind);
        record.save(env, None).map_err(failed)?;
    }
    Ok((known, next))
}

/// Why a line on record is not taken up yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitWhy {
    /// Charged, not listed: being set up.
    SettingUp,
    /// Listed, not among the charges yet: the credit snapshot is cached
    /// for up to a minute.
    NotYetCharged,
    /// Not billed by the hour, and not listed: erpc cannot tell, and does
    /// not guess.
    Unbilled,
    /// Started, never seen with its endpoint, and shown by neither: right
    /// after a start both can be behind, so erpc does not take it for gone.
    NotSeenYet,
}

impl WaitWhy {
    fn says(self) -> String {
        match self {
            Self::SettingUp => t!("worker_deploy.wait.setting_up"),
            Self::NotYetCharged => t!("worker_deploy.wait.not_yet_charged"),
            Self::Unbilled => t!("worker_deploy.wait.unbilled"),
            Self::NotSeenYet => t!("worker_deploy.wait.not_seen_yet"),
        }
    }
}

/// What a deploy does about a line it is asked for. Whether a line on
/// record still exists is decided by what the account is charged for (the
/// credit snapshot); the status list decides only whether it is ready to
/// take up. A line not billed by the hour is never dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineNext {
    /// Take up the one on record.
    TakeUp,
    /// Refuse, and buy nothing: buying another could charge for two.
    Wait(WaitWhy),
    /// The one on record is neither charged nor listed: it is gone. It
    /// leaves the record, and one is bought, its price asked or, under
    /// `--yes`, said.
    Forget,
    /// None on record: buy one, its price asked or, under `--yes`, said.
    Buy,
}

impl LineNext {
    /// `on_record` is the line on record, as (billed by the hour, pending:
    /// its endpoint never seen); `None` when there is none.
    const fn of(
        kind: LineKind,
        on_record: Option<(bool, bool)>,
        listed: bool,
        charged: bool,
    ) -> Self {
        let Some((hourly, pending)) = on_record else {
            return Self::Buy;
        };
        // A UDP Forwarding line is charged from the start (Standard) or
        // once it is pointed at the server (Premium), which is what taking
        // it up does: one on record that user-api lists is taken up whether
        // or not the charges show it yet.
        if matches!(kind, LineKind::Udp) && pending && listed {
            return Self::TakeUp;
        }
        if vps::is_gone((hourly, pending), listed, charged) {
            return Self::Forget;
        }
        match (hourly, listed, charged) {
            (false, true, _) | (true, true, true) => Self::TakeUp,
            (false, false, _) => Self::Wait(WaitWhy::Unbilled),
            (true, false, true) => Self::Wait(WaitWhy::SettingUp),
            (true, true, false) => Self::Wait(WaitWhy::NotYetCharged),
            (true, false, false) => Self::Wait(WaitWhy::NotSeenYet),
        }
    }
}

/// Addresses as a message lists them; for none, that user-api names none.
fn sources_said(sources: &[Ipv4Addr]) -> String {
    if sources.is_empty() {
        t!("worker_deploy.line.udp_no_address")
    } else {
        sources
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Reads again where the UDP Forwarding line on record sends from, and
/// keeps the record current: ERPC may move a line, and the firewall lets
/// in what the record says. One that is pending has nothing to read yet; a
/// read that fails (a source that is not an IPv4 address is one), or a
/// line user-api no longer lists, is said, and the record kept. `session`
/// is asked for only when there is a line to read.
async fn refresh_udp_sources<S>(
    session: impl FnOnce() -> S,
    env: &mut Env,
    record: &EnvRecord<'_>,
    say: &Say,
) -> Result<(), CliError>
where
    S: core::future::Future<Output = Result<Api, CliError>>,
{
    let Some(line) = env
        .lines
        .iter()
        .find(|l| l.kind == LineKind::Udp && !l.is_pending())
        .cloned()
    else {
        return Ok(());
    };
    let (id, kept) = (line.id.clone(), sources_said(&line.sources));
    let read = match session().await {
        Ok(api) => vps::udp_sources_now(&api, &id).await,
        Err(e) => Err(e),
    };
    match read {
        Ok(Some(sources)) if sources != line.sources => {
            let now = sources_said(&sources);
            say.line(&t!(
                "worker_deploy.line.udp_sources_changed",
                id,
                before = kept,
                now
            ));
            keep(env, Line { sources, ..line }, record)
        }
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            say.line(&format!(
                "warning: {}",
                t!("worker_deploy.line.udp_not_listed", id, sources = kept)
            ));
            Ok(())
        }
        Err(e) => {
            say.line(&format!(
                "warning: {}",
                t!(
                    "worker_deploy.line.udp_sources_unread",
                    id,
                    error = e.message,
                    sources = kept
                )
            ));
            Ok(())
        }
    }
}

/// The UDP ports the server's other workers receive on, asked of its
/// firewall. A server that does not answer is said, and the check goes
/// without it: the line's port is still checked against SSH's and the
/// app's own.
fn others_udp(target: &Target, id: &UnitId, say: &Say) -> Vec<(String, u16)> {
    let shown = open(target).and_then(|session| ctl(&session, id, Verb::FirewallShow, None));
    match shown {
        Ok(shown) if shown["openings"].is_object() => others_udp_ports(&shown, id.as_str()),
        Ok(_) | Err(_) => {
            say.line(&format!(
                "warning: {}",
                t!("worker_deploy.line.udp_ports_unread")
            ));
            Vec::new()
        }
    }
}

/// Whether the account is charged for the pending UDP Forwarding line
/// `line` now, when the credit snapshot can be read; `None` when it cannot
/// (no session, or user-api did not answer).
async fn pending_udp_charged(line: &Line) -> Option<bool> {
    let api = Api::open().await.ok()?;
    let charged = vps::charged(&api).await.ok()?;
    Some(vps::is_charged(&charged, line))
}

/// What the deploy's summary says of UDP Forwarding line `line`, in
/// `lang`. Pointed at the server: its port, and what the firewall lets in
/// there (its sources; any IPv4 address when user-api names none and
/// `any_source` was asked; nothing otherwise, with how to open it).
/// Pending, it sends nothing yet and may be charged all the same:
/// `charged` is what the credit snapshot says, when it could be read.
fn udp_line_said(
    lang: Lang,
    line: &Line,
    any_source: bool,
    charged: Option<bool>,
    scope: &str,
) -> String {
    let name = line_name_in(lang, line.kind, &line.id);
    let Some(port) = vps::udp_port(line) else {
        return match charged {
            Some(true) => said_in!(
                lang,
                t!("worker_deploy.done.udp_pending_charged", name, scope)
            ),
            Some(false) => said_in!(
                lang,
                t!("worker_deploy.done.udp_pending_uncharged", name, scope)
            ),
            None => said_in!(lang, t!("worker_deploy.done.udp_pending", name, scope)),
        };
    };
    if line.sources.is_empty() && !any_source {
        return if line.hourly {
            said_in!(
                lang,
                t!(
                    "worker_deploy.done.udp_line_closed_hourly",
                    name,
                    port,
                    scope
                )
            )
        } else {
            said_in!(
                lang,
                t!("worker_deploy.done.udp_line_closed", name, port, scope)
            )
        };
    }
    let from = if line.sources.is_empty() {
        said_in!(lang, t!("worker_deploy.done.udp_any"))
    } else {
        let sources = sources_said(&line.sources);
        said_in!(lang, t!("worker_deploy.done.udp_from", sources))
    };
    if line.hourly {
        said_in!(
            lang,
            t!(
                "worker_deploy.done.udp_line_hourly",
                name,
                port,
                from,
                scope
            )
        )
    } else {
        said_in!(lang, t!("worker_deploy.done.udp_line", name, port, from))
    }
}

/// Puts `line` in `env` in place of any line of its kind, and saves.
fn keep(env: &mut Env, line: Line, record: &EnvRecord<'_>) -> Result<(), CliError> {
    let id = line.id.clone();
    let kind = line.kind;
    env.lines.retain(|l| l.kind != kind);
    env.lines.push(line);
    env.lines.sort_by_key(|l| l.kind);
    record.save(env, None).map_err(|e| {
        failed(t!("worker_deploy.line.not_kept", id, error = e))
            .hint(t!("worker_deploy.line.not_kept_hint"))
    })
}

/// Puts `start`, the request of a start of `of`, on `env`'s record
/// (`[env.<name>.starting]`, or the 1Password item's `starting`), the way
/// a bought VPS or line is written: before the request leaves, so that a
/// start that gets no answer is sent again with its key.
fn begin_start(
    env: &mut Env,
    of: StartOf,
    start: &Start,
    record: &EnvRecord<'_>,
) -> Result<(), String> {
    env.starting.insert(of, start.clone());
    let saved = record.save(env, None);
    if saved.is_err() {
        env.starting.remove(&of);
    }
    saved
}

/// How a start's request is taken off `env`'s record by hand. erpc has no
/// flag that drops one: only the account shows whether it went through.
fn remove_said(lang: Lang, of: StartOf, env: &Env, env_name: &str) -> String {
    let slot = of.as_str();
    if env.inventory.is_some() {
        said_in!(lang, t!("worker_deploy.start.remove_item", slot))
    } else {
        said_in!(
            lang,
            t!("worker_deploy.start.remove_toml", slot, env = env_name)
        )
    }
}

/// How a start left on record is carried on with, or cleared by hand.
fn clear_hint(lang: Lang, of: StartOf, env: &Env, env_name: &str) -> String {
    let remove = remove_said(lang, of, env, env_name);
    said_in!(lang, t!("worker_deploy.start.carry_on_or_clear", remove))
}

/// What to do about a request that stays on `env`'s record after a run:
/// that it stays, and the way on. For an answer that left the outcome
/// open, the same command sends the same request again; where the answer
/// did not speak for it, also where to look and how to take the request
/// off by hand once nothing was started. For a purchase that exists and is
/// on no record, nothing is sent again: it is looked up, taken up or
/// ended, and the request then removed by hand.
fn stays_hint(why: Stays, of: StartOf, env: &Env, env_name: &str, scope: &str) -> String {
    let remove = remove_said(crate::cli::i18n::lang(), of, env, env_name);
    let server = of == StartOf::Server;
    // `status` reaches the environment's server: with none on record yet
    // there is only the dashboard to look at.
    let look = || {
        if env.host.is_some() {
            t!("worker_deploy.start.look_status", scope)
        } else {
            t!("worker_deploy.start.look")
        }
    };
    match why {
        Stays::Unanswered => t!("worker_deploy.start.again_hint"),
        Stays::InProgress => {
            t!(
                "worker_deploy.start.in_progress_hint",
                look = look(),
                remove
            )
        }
        Stays::NotKnown => t!("worker_deploy.start.not_known_hint", look = look(), remove),
        Stays::Exists if server => t!("worker_deploy.start.exists_server_hint", scope, remove),
        Stays::Exists => t!("worker_deploy.start.exists_line_hint", remove),
        Stays::Unnamed if server => t!("worker_deploy.start.unnamed_server_hint", scope, remove),
        Stays::Unnamed => t!("worker_deploy.start.unnamed_line_hint", remove),
    }
}

/// The request of a new VPS's start, on the environment's record.
struct ServerStart<'a> {
    /// The environment as it is on record, the request included.
    env: Env,
    record: &'a EnvRecord<'a>,
    /// Whether the environment was on no record before this run: one the
    /// request alone put there leaves with it when user-api refuses.
    fresh: bool,
    /// The app and environment, as a hint's command names them.
    scope: &'a str,
}

impl StartRecord for ServerStart<'_> {
    fn pending(&self) -> Option<Start> {
        self.env.starting.get(&StartOf::Server).cloned()
    }

    fn begin(&mut self, start: &Start) -> Result<(), String> {
        begin_start(&mut self.env, StartOf::Server, start, self.record)
    }

    fn settle(&mut self) -> Result<(), String> {
        if self.env.starting.remove(&StartOf::Server).is_none() {
            return Ok(());
        }
        if self.fresh && erpc_worker::inventory::stripped(&self.env) == self.env {
            self.record.forget(&self.env)
        } else {
            self.record.save(&self.env, None)
        }
    }

    fn stays_hint(&self, why: Stays) -> String {
        let env_name = self.record.env;
        stays_hint(why, StartOf::Server, &self.env, env_name, self.scope)
    }

    fn other_hint(&self) -> String {
        let lang = crate::cli::i18n::lang();
        clear_hint(lang, StartOf::Server, &self.env, self.record.env)
    }
}

/// The request of a line's start, and the line it makes, on the
/// environment's record.
struct LineStart<'a> {
    kind: LineKind,
    env: &'a mut Env,
    record: &'a EnvRecord<'a>,
    on_record: &'a RefCell<Vec<String>>,
    /// The app and environment, as a hint's command names them.
    scope: &'a str,
}

impl StartRecord for LineStart<'_> {
    fn pending(&self) -> Option<Start> {
        self.env.starting.get(&StartOf::line(self.kind)).cloned()
    }

    fn begin(&mut self, start: &Start) -> Result<(), String> {
        begin_start(self.env, StartOf::line(self.kind), start, self.record)
    }

    fn settle(&mut self) -> Result<(), String> {
        if self
            .env
            .starting
            .remove(&StartOf::line(self.kind))
            .is_none()
        {
            return Ok(());
        }
        self.record.save(self.env, None)
    }

    fn stays_hint(&self, why: Stays) -> String {
        let (of, env_name) = (StartOf::line(self.kind), self.record.env);
        stays_hint(why, of, self.env, env_name, self.scope)
    }

    fn other_hint(&self) -> String {
        let lang = crate::cli::i18n::lang();
        clear_hint(lang, StartOf::line(self.kind), self.env, self.record.env)
    }
}

impl LineRecord for LineStart<'_> {
    /// On record the moment user-api names it, its endpoint to come: a
    /// deploy that stops after that leaves it for the next to take up.
    /// Its request is answered, and leaves the record in the same write.
    fn named(&mut self, id: &str) -> Result<(), CliError> {
        let pending = Line {
            kind: self.kind,
            id: id.to_owned(),
            endpoint: String::new(),
            hourly: true,
            sources: Vec::new(),
        };
        self.env.starting.remove(&StartOf::line(self.kind));
        keep(self.env, pending, self.record)?;
        self.on_record.borrow_mut().push(line_name(self.kind, id));
        Ok(())
    }
}

/// The starts on `env`'s record that got no answer and that this command,
/// which asks for the lines `asked`, does not carry on with: the server's
/// (a VPS bought by this run has left the record by now), and the lines of
/// kinds it does not ask for. They are left as they are, and said.
fn starts_left<'a>(env: &'a Env, asked: &[(LineKind, Option<&str>)]) -> Vec<(StartOf, &'a Start)> {
    env.starting
        .iter()
        .filter(|(of, _)| !asked.iter().any(|(kind, _)| StartOf::line(*kind) == **of))
        .map(|(of, start)| (*of, start))
        .collect()
}

/// What is said of each start in `left`, in `lang`.
fn starts_left_said(
    lang: Lang,
    left: &[(StartOf, &Start)],
    env: &Env,
    env_name: &str,
) -> Vec<String> {
    left.iter()
        .map(|(of, start)| {
            let what = vps::purchase_name(start);
            let clear = clear_hint(lang, *of, env, env_name);
            said_in!(lang, t!("worker_deploy.start.left", what, clear))
        })
        .collect()
}

/// A data line as it is named to the operator: `gRPC line 100002`.
fn line_name(kind: LineKind, id: &str) -> String {
    line_name_in(crate::cli::i18n::lang(), kind, id)
}

/// [`line_name`] in `lang`.
fn line_name_in(lang: Lang, kind: LineKind, id: &str) -> String {
    let kind = kind.label();
    said_in!(lang, t!("worker_deploy.line.name", kind, id))
}

/// What [`server`] found or made.
struct Found {
    server: Waiting,
    /// The environment had no server on record.
    new_env: bool,
    /// It was bought just now, its price answered by the person or by
    /// `--yes`.
    bought: bool,
}

/// The server, or the VPS to wait for before it is one.
enum Waiting {
    Ready(Server),
    /// Bought, or taken up, and on record; not yet ready.
    Vps(Api, Resource),
}

impl Waiting {
    /// Waits for a VPS to be up, asking nothing: it runs beside the build.
    async fn wait(&self, say: &Say) -> Result<(), CliError> {
        match self {
            Self::Ready(_) => Ok(()),
            Self::Vps(api, resource) => vps::wait(api, resource, say).await,
        }
    }

    /// The server, once a VPS is up: making it key-only asks about its
    /// host key, so this runs once the build has stopped printing.
    async fn secured(self) -> Result<Server, CliError> {
        match self {
            Self::Ready(server) => Ok(server),
            Self::Vps(api, resource) => vps::secure(&api, &resource).await,
        }
    }

    /// Where it goes, as the go-ahead names it: the address, or the VPS
    /// before it has one.
    fn named(&self) -> String {
        match self {
            Self::Ready(server) => format!("{}@{}", server.target.user, server.target.host),
            Self::Vps(_, resource) => format!("VPS {}", resource.id),
        }
    }
}

/// The line to say before the go-ahead, when there is one to ask: every
/// server but a VPS bought just now, whose price was the question (asked,
/// or answered by `--yes`).
fn go_ahead_line(server: &Waiting, bought: bool, name: &str, worker: &str) -> Option<String> {
    (!bought).then(|| t!("worker_deploy.target", name, to = server.named(), worker))
}

/// Buys a new hourly VPS and puts it on record at once; the caller waits
/// for it. Its request is on record from before it leaves (`start`), and
/// leaves the record in the write that puts the VPS there.
async fn buy(
    api: Api,
    at: &Where,
    mut start: ServerStart<'_>,
    on_record: &RefCell<Vec<String>>,
    scope: &str,
    say: &Say,
) -> Result<Waiting, CliError> {
    let (region, plan) = (at.region.as_deref(), at.plan.as_deref());
    let resource = vps::buy(&api, region, plan, scope, say, &mut start).await?;
    let ServerStart {
        env: mut base,
        record: kept,
        ..
    } = start;
    base.starting.remove(&StartOf::Server);
    let save = |r: &Resource| {
        kept.save(
            &Env {
                resource: Some(r.clone()),
                ..base.clone()
            },
            None,
        )
    };
    on_record_then(resource, save, on_record, scope, |r| async move {
        Ok(Waiting::Vps(api, r))
    })
    .await
}

/// Puts `resource`, just bought, on record (`save`), then waits for it
/// (`ready`): in that order, so that whatever the wait does, the next
/// deploy finds it. A record that cannot be written says what is charged.
async fn on_record_then<F, T>(
    resource: Resource,
    save: impl FnOnce(&Resource) -> Result<(), String>,
    on_record: &RefCell<Vec<String>>,
    scope: &str,
    ready: impl FnOnce(Resource) -> F,
) -> Result<T, CliError>
where
    F: core::future::Future<Output = Result<T, CliError>>,
{
    let id = resource.id.clone();
    save(&resource).map_err(|e| {
        let hint = t!("worker_deploy.vps.not_kept_hint", id, scope);
        failed(t!("worker_deploy.vps.not_kept", id, error = e)).hint(hint)
    })?;
    on_record.borrow_mut().push(format!("VPS {id}"));
    ready(resource).await
}

/// The server: the environment's, one on record that was bought and not
/// yet ready, or one chosen, started or named now.
async fn server(
    m: &Manifest,
    app: &App,
    at: &Where,
    base: &Env,
    kept: &EnvRecord<'_>,
    on_record: &RefCell<Vec<String>>,
    say: &Say,
) -> Result<Found, CliError> {
    let env_name = app.env.as_str();
    let scope = &app.scope();
    let found = |server, new_env, bought| Found {
        server,
        new_env,
        bought,
    };
    if let Some(env) = m.env.get(env_name).filter(|e| e.host.is_some()) {
        let target = crate::worker::remote::target(app, env)?;
        let resource = env.resource.clone().unwrap_or(Resource {
            kind: erpc_worker::manifest::ResourceKind::Vps,
            id: String::new(),
            region: None,
            hourly: false,
        });
        return Ok(found(
            Waiting::Ready(Server { target, resource }),
            false,
            false,
        ));
    }
    // A VPS an earlier deploy bought and put on record, which stopped
    // before the VPS was ready: taken up rather than bought again. `base`
    // is the record, less a VPS the person took off it ([`drop_ended_vps`]).
    if let Some(resource) = pending_vps(Some(base)) {
        say.line(&t!("worker_deploy.vps.taking_up", id = resource.id));
        on_record.borrow_mut().push(format!("VPS {}", resource.id));
        let api = Api::open().await?.accepting(at.starts.accepted());
        return Ok(found(Waiting::Vps(api, resource.clone()), true, false));
    }
    if let Some(host) = &at.host {
        let port = at.port.unwrap_or(22);
        let host_key =
            crate::node::common::host_key(host, port, None, at.fingerprint.as_deref(), say)
                .map_err(failed)?;
        let (_, identity) = crate::ai::vps_access::login_key().map_err(failed)?;
        return Ok(found(
            Waiting::Ready(Server {
                target: Target {
                    host: host.clone(),
                    port,
                    user: at.user.clone().unwrap_or_else(|| "root".to_owned()),
                    host_key,
                    identity,
                },
                resource: Resource {
                    kind: erpc_worker::manifest::ResourceKind::Vps,
                    id: String::new(),
                    region: None,
                    hourly: false,
                },
            }),
            true,
            false,
        ));
    }
    let api = Api::open().await?.accepting(at.starts.accepted());
    if let Some(id) = at.vps {
        return Ok(found(
            Waiting::Ready(vps::existing(&api, id, false).await?),
            true,
            false,
        ));
    }
    let start = || ServerStart {
        env: base.clone(),
        record: kept,
        fresh: !m.env.contains_key(env_name),
        scope,
    };
    if at.new_vps {
        let server = buy(api, at, start(), on_record, scope, say).await?;
        return Ok(found(server, true, true));
    }
    if !crate::account::session::has_terminal() {
        return Err(CliError::new(
            Code::NeedsTerminal,
            t!("worker_deploy.server.no_terminal", env = env_name),
        )
        .hint(t!("worker_deploy.server.no_terminal_hint")));
    }
    let running = vps::running(&api).await?;
    let mut options: Vec<String> = running
        .iter()
        .map(|(id, ip, region, plan)| format!("VPS {id}  {ip}  {region}  {plan}"))
        .collect();
    let region = vps::nearest_region();
    options.push(t!("worker_deploy.server.new_vps", region));
    let question = t!("worker_deploy.server.which");
    let i = crate::cli::prompt::pick(&question, &options, None).map_err(failed)?;
    if let Some((id, ..)) = running.get(i) {
        Ok(found(
            Waiting::Ready(vps::existing(&api, *id, false).await?),
            true,
            false,
        ))
    } else {
        let server = buy_picked(api, at, region, start(), on_record, say).await?;
        Ok(found(server, true, true))
    }
}

/// Buys the new VPS picked at the terminal, in `--region`, else `nearest`:
/// first asked whether a UDP Forwarding line asked for sends from there
/// ([`udp_region_for_new_vps`]), since a VPS bought where its line cannot
/// be would be left charged.
async fn buy_picked(
    api: Api,
    at: &Where,
    nearest: &str,
    start: ServerStart<'_>,
    on_record: &RefCell<Vec<String>>,
    say: &Say,
) -> Result<Waiting, CliError> {
    udp_region_for_new_vps(&api, at, nearest).await?;
    let scope = start.scope;
    buy(api, at, start, on_record, scope, say).await
}

/// A new VPS picked at the terminal, about to be bought in `--region`,
/// else `nearest`: where a UDP Forwarding line asked for would send from
/// is known now, and refused before the VPS is bought there when its plan
/// does not send from it. Nothing to ask without `--udp`, or with
/// `--udp-region`, which was checked before the server was chosen.
async fn udp_region_for_new_vps(api: &Api, at: &Where, nearest: &str) -> Result<(), CliError> {
    match at.lines.iter().find(|(kind, _)| *kind == LineKind::Udp) {
        Some((_, plan)) if at.udp_region.is_none() => {
            let region = at.region.as_deref().unwrap_or(nearest);
            vps::udp_region_ready(api, plan.as_deref(), region).await
        }
        _ => Ok(()),
    }
}

/// What the summary says of a UDP Forwarding line besides its record.
#[derive(Debug, Clone, Copy, Default)]
struct UdpState {
    /// `--udp-any-source`: its port is open to any IPv4 address when
    /// user-api names none it sends from.
    any_source: bool,
    /// Whether a pending line is charged now, as the credit snapshot says;
    /// `None` when there is none, or the snapshot could not be read.
    pending_charged: Option<bool>,
}

/// What the environment has on record and is charged for, as the end of a
/// deploy says it: each line and where it lets the server in from, and the
/// hourly server.
fn on_record_said(
    lang: Lang,
    env: &Env,
    resource: &Resource,
    udp: UdpState,
    scope: &str,
) -> Vec<String> {
    let mut text = Vec::new();
    for line in &env.lines {
        if line.kind == LineKind::Udp {
            let charged = udp.pending_charged.filter(|_| line.is_pending());
            text.push(udp_line_said(lang, line, udp.any_source, charged, scope));
            continue;
        }
        let (name, endpoint) = (line_name_in(lang, line.kind, &line.id), &line.endpoint);
        text.push(if line.hourly {
            said_in!(
                lang,
                t!("worker_deploy.done.line_hourly", name, endpoint, scope)
            )
        } else {
            said_in!(lang, t!("worker_deploy.done.line", name, endpoint))
        });
    }
    if resource.hourly {
        text.push(said_in!(lang, t!("worker_deploy.done.hourly_vps", scope)));
    }
    text
}

/// Takes off the record (`kept`) a VPS an earlier deploy bought and never
/// reached that is missing from the account signed in to
/// ([`vps::on_account`]), once the person at the terminal says so:
/// it has ended outside erpc (in the dashboard, or by support), or it is
/// another account's, which only they can tell. Then this
/// deploy goes on as for an environment with no server, asking for one as
/// it would, instead of waiting for one that is not there. With nobody to
/// ask (no terminal, `--json`) it stops and says how to take it off the
/// record; `--yes` does not answer this. When the account cannot be read,
/// or has it, the record stays and the deploy takes the VPS up.
async fn drop_ended_vps(
    env: &mut Env,
    kept: &EnvRecord<'_>,
    scope: &str,
    say: &Say,
) -> Result<(), CliError> {
    let Some(resource) = pending_vps(Some(env)).cloned() else {
        return Ok(());
    };
    let Ok(api) = Api::open().await else {
        return Ok(());
    };
    let seen = vps::on_account(&api, &resource, say).await;
    let asking = Asking {
        can_ask: vps::can_ask(say.quiet, crate::account::session::has_terminal()),
        ask: |question: &str| crate::node::common::confirm(question).map_err(failed),
    };
    let save = |without: &Env| kept.save(without, None);
    record_without_missing(env, &seen, scope, asking, save, say)
}

/// Whether a person can be asked (`can_ask`), and how (`ask`).
struct Asking<A> {
    can_ask: bool,
    ask: A,
}

/// [`drop_ended_vps`] once the account was asked (`seen`): the record
/// without the VPS is saved (`save`) and becomes `env` when it leaves
/// ([`without_missing_vps`]); otherwise nothing is written.
fn record_without_missing(
    env: &mut Env,
    seen: &vps::OnAccount,
    scope: &str,
    asking: Asking<impl FnOnce(&str) -> Result<bool, CliError>>,
    save: impl FnOnce(&Env) -> Result<(), String>,
    say: &Say,
) -> Result<(), CliError> {
    let id = pending_vps(Some(env))
        .map(|r| r.id.clone())
        .unwrap_or_default();
    let Some(without) = without_missing_vps(env, seen, scope, asking.can_ask, asking.ask)? else {
        return Ok(());
    };
    save(&without).map_err(|e| failed(t!("worker_deploy.vps.not_dropped", id, error = e)))?;
    *env = without;
    say.line(&t!("worker_deploy.vps.dropped", id));
    Ok(())
}

/// The record to write in place of `env`, without the VPS bought and never
/// reached that is on it, when it leaves ([`forget_missing`]); `None` when
/// the record stays as it is.
fn without_missing_vps(
    env: &Env,
    seen: &vps::OnAccount,
    scope: &str,
    can_ask: bool,
    ask: impl FnOnce(&str) -> Result<bool, CliError>,
) -> Result<Option<Env>, CliError> {
    let Some(resource) = pending_vps(Some(env)) else {
        return Ok(None);
    };
    Ok(
        forget_missing(seen, &resource.id, scope, can_ask, ask)?.then(|| Env {
            resource: None,
            ..env.clone()
        }),
    )
}

/// Whether VPS `id`, bought and never reached, leaves the record, from
/// what the account signed in to says of it (`seen`): only when it is
/// missing from it and the person says so (`ask`, when `can_ask`). With
/// nobody to ask, or a no, the deploy stops with the way to take it off
/// the record by hand.
fn forget_missing(
    seen: &vps::OnAccount,
    id: &str,
    scope: &str,
    can_ask: bool,
    ask: impl FnOnce(&str) -> Result<bool, CliError>,
) -> Result<bool, CliError> {
    let Some(account) = seen.missing_from() else {
        return Ok(false);
    };
    let hint = t!(
        "worker_deploy.vps.missing_hint",
        delete = format!("erpc worker delete --release-server{scope}")
    );
    if !can_ask {
        return Err(CliError::new(
            Code::NeedsTerminal,
            t!("worker_deploy.vps.missing", id, account),
        )
        .hint(hint));
    }
    if ask(&t!("worker_deploy.vps.missing_ask", id, account))? {
        Ok(true)
    } else {
        Err(CliError::new(Code::Declined, t!("worker_deploy.vps.missing_kept", id)).hint(hint))
    }
}

/// Stops a deploy while a UDP Forwarding line billed by the hour is on
/// record (`env`) and no server it reached is (`host`): the server the line
/// was pointed at has left the record (a VPS that ended outside erpc, which
/// [`drop_ended_vps`] or `delete` took off, a VPS bought and never reached,
/// or a `delete --release-server` that ended the server and not the line),
/// so the server this deploy reaches is another one. A line on
/// record that is not asked for again (`--udp`) nor forgotten
/// (`--forget-line`) keeps sending where it was pointed, never at that
/// server, and is charged all the same. Judged on the record, not on what
/// this run took off it, so a deploy run again stops the same way. Nothing
/// is bought; the error names the line and how to point it at the server
/// or end it.
fn udp_left_unpointed(env: &Env, at: &Where, scope: &str) -> Result<(), CliError> {
    if env.host.is_some() || at.lines.iter().any(|(kind, _)| *kind == LineKind::Udp) {
        return Ok(());
    }
    let Some(line) = env
        .lines
        .iter()
        .find(|l| l.kind == LineKind::Udp && l.hourly && !at.forget_lines.contains(&l.id))
    else {
        return Ok(());
    };
    Err(CliError::new(
        Code::Usage,
        t!("worker_deploy.vps.udp_left", line = line.id),
    )
    .hint(t!("worker_deploy.vps.udp_left_hint", scope, line = line.id)))
}

/// The VPS `env` has on record without a server to reach yet: one a deploy
/// bought and stopped before it was ready.
fn pending_vps(env: Option<&Env>) -> Option<&Resource> {
    let env = env?;
    env.resource
        .as_ref()
        .filter(|r| env.host.is_none() && r.kind == ResourceKind::Vps && !r.id.is_empty())
}

/// `erpc worker deploy`.
pub(crate) async fn deploy(json: bool, app: &App, at: &Where, yes: bool) -> Outcome {
    let say = Say { quiet: json };
    let on_record = RefCell::new(Vec::new());
    // The summary is English in `--json` output, which scripts read.
    let lang = if json {
        Lang::En
    } else {
        crate::cli::i18n::lang()
    };
    let result = run(&say, lang, app, at, yes, &on_record).await;
    let scope = app.scope();
    // A failure once a server is on record says what is charged, and how
    // the next command carries on with it.
    let result = result.map_err(|e| match on_record.take() {
        what if !what.is_empty() => {
            let names = what.join(&t!("worker_deploy.and"));
            let next = tn!("worker_deploy.still_charged", what.len(), names, scope);
            let hint = match e.hint.clone() {
                Some(hint) => t!("worker_deploy.and_then", hint, next),
                None => next,
            };
            e.hint(hint)
        }
        _ => e,
    });
    match result {
        Ok(report) => {
            if json {
                crate::print_json(&report);
                Outcome::Done(String::new())
            } else {
                Outcome::Done(crate::cli::ui::decorate(
                    report["text"].as_str().unwrap_or_default(),
                    "🚀",
                ))
            }
        }
        Err(e) => e.into(),
    }
}

/// The start of step 1: the app's `erpc.toml`, read, with everything
/// about the app's settings, its key and its secrets that refuses a deploy
/// before this machine's tools are looked for, a server is chosen or
/// anything is bought.
///
/// What the app keeps in the keystore is where a `--prepare` and a deploy
/// part. A deploy hands the key and the secrets over, so it opens the
/// keystore now: a passphrase nobody can type must not be found out after
/// a server is bought. A `--prepare` reads neither, so it only looks that
/// the entries are there, asks for no passphrase, and is not stopped by a
/// keystore that is locked.
fn app_ready(app: &App, at: &Where) -> Result<(PathBuf, Manifest), CliError> {
    app_ready_in(crate::worker::secrets::context(), app, at)
}

/// [`app_ready`], for a process in `context` as the secret gate reads it:
/// this process's, except in a test, which says who is there.
fn app_ready_in(
    context: erpc_secret::gate::Context,
    app: &App,
    at: &Where,
) -> Result<(PathBuf, Manifest), CliError> {
    let (path, m) = load_env(app)?;
    let asked_lines = at.lines();
    let mut provided: Vec<&str> = asked_lines.iter().map(|(k, _)| k.setting()).collect();
    if let Some(env) = m.env.get(&app.env) {
        provided.extend(env.line_vars().map(|(setting, _)| setting));
    }
    let missing = m.missing_besides(&provided);
    if !missing.is_empty() {
        let (scope, first) = (app.dir.scope(), missing[0].first());
        let settings = missing
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        // A line's setting comes from the line's flag, not from a secret.
        let hint = match LineKind::ALL.into_iter().find(|k| k.setting() == first) {
            Some(kind) => t!(
                "worker_deploy.missing_line_hint",
                first,
                flag = kind.flag(),
                scope = app.scope()
            ),
            // A secret is kept with the flag that gives its value, when
            // nobody has to type it: as `init`'s next steps name it.
            None => t!(
                "worker_deploy.missing_hint",
                first,
                how = crate::worker::secret_flag(&m, first),
                dir_scope = scope
            ),
        };
        return Err(failed(t!("worker_deploy.missing", name = m.name, settings)).hint(hint));
    }
    Launch::for_app(&m, &Env::default()).map_err(failed)?;
    // The key is read at step 8, which a --prepare never reaches: asked
    // for here, before anything is bought, only when it will be.
    if m.wallet.is_some() && !at.upto.prepares() {
        crate::worker::secrets::gate(context).map_err(failed)?;
    }
    if at.upto.prepares() {
        crate::worker::secrets::kept_for(&m).map_err(failed)?;
    } else {
        crate::worker::secrets::ready_for(&m).map_err(failed)?;
    }
    Ok((path, m))
}

/// Where erpc's index of apps finds the app whose erpc.toml is at `path`:
/// its directory, absolute, as the index keeps it (`.` for an erpc.toml
/// named with no directory, whose parent is the empty path).
fn index_root(path: &Path) -> PathBuf {
    let root = crate::worker::build::app_root(path);
    std::fs::canonicalize(&root).unwrap_or(root)
}

/// What a deploy has once nothing refuses it before anything is bought:
/// the app's erpc.toml and where it is, the worker's name, and the
/// environment's record as it is before this run.
#[derive(Debug)]
struct Ready {
    path: PathBuf,
    m: Manifest,
    id: UnitId,
    env_before: Env,
}

/// Step 1 of a deploy, and what refuses one before anything is bought, in
/// this order: the app and its settings, key and secrets ([`app_ready`]);
/// what the build needs on this machine, the Rust that would build the app
/// asked in its directory (`rustc`, `rustup`), and the key to log in with
/// (`login`); the lines to forget; a VPS on record that has ended outside
/// erpc (`ended`, [`drop_ended_vps`] in a deploy); and what a UDP Forwarding
/// line would be refused for ([`udp_before_buying`], through the session
/// `open` gives):
/// refused after the server or another line is bought, they would be left
/// charged. A new environment's record starts as where it is kept, so that
/// a VPS bought next goes on record at once.
async fn before_buying<O, F>(
    app: &App,
    at: &Where,
    scope: &str,
    login: impl FnOnce() -> Result<(), String>,
    ended: impl AsyncFnOnce(&mut Env, &EnvRecord<'_>) -> Result<(), CliError>,
    open: O,
) -> Result<Ready, CliError>
where
    O: FnOnce() -> F,
    F: core::future::Future<Output = Result<Api, CliError>>,
{
    let (path, m) = app_ready(app, at)?;
    let id = UnitId::new(&m.unit_id(&app.env)).map_err(failed)?;
    // A build that fails after a VPS was bought leaves it charged; so does
    // a Rust too old for the app, which only a probe that asks `rustc`
    // finds.
    let root = crate::worker::build::app_root(&path);
    let mut lacking =
        crate::worker::build::missing_tools(&m, &root, crate::worker::build::Probe::Toolchain);
    if let Err(no_key) = login() {
        lacking.push((no_key, String::new()));
    }
    if !lacking.is_empty() {
        let what: Vec<&str> = lacking.iter().map(|(what, _)| what.as_str()).collect();
        let hints: Vec<&str> = lacking
            .iter()
            .map(|(_, hint)| hint.as_str())
            .filter(|h| !h.is_empty())
            .collect();
        let e = failed(t!("worker_deploy.not_ready", what = what.join("; ")));
        return Err(if hints.is_empty() {
            e
        } else {
            e.hint(hints.join("; "))
        });
    }
    // Lines to forget are checked now, before anything is built or bought.
    take_lines(
        &mut m.env.get(&app.env).cloned().unwrap_or_default(),
        &at.forget_lines,
    )?;
    let mut env_before = match m.env.get(&app.env) {
        Some(env) => env.clone(),
        None => Env {
            inventory: new_inventory(at)?,
            ..Env::default()
        },
    };
    // A VPS on record that has ended outside erpc leaves the record first,
    // so that the UDP checks below judge the server this deploy will have.
    let kept = EnvRecord {
        path: &path,
        app: &m.name,
        env: &app.env,
    };
    ended(&mut env_before, &kept).await?;
    udp_left_unpointed(&env_before, at, scope)?;
    // Its port and, where the server is known, its region are decided here
    // as the lines step decides them.
    udp_before_buying(at, &env_before, m.run.port, scope, open).await?;
    Ok(Ready {
        path,
        m,
        id,
        env_before,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the steps are one sequence, read top to bottom"
)]
async fn run(
    say: &Say,
    lang: Lang,
    app: &App,
    at: &Where,
    yes: bool,
    on_record: &RefCell<Vec<String>>,
) -> Result<Value, CliError> {
    // 1. The app, and all that refuses the deploy before anything is
    // bought. Every next command a hint names is for this app and
    // environment.
    let scope = app.scope();
    let Ready {
        path,
        m,
        id,
        env_before,
    } = before_buying(
        app,
        at,
        &scope,
        || crate::ai::vps_access::login_key().map(drop),
        async |env: &mut Env, kept: &EnvRecord<'_>| drop_ended_vps(env, kept, &scope, say).await,
        || async { Ok(Api::open().await?.accepting(at.starts.accepted())) },
    )
    .await?;
    let kept = EnvRecord {
        path: &path,
        app: &m.name,
        env: &app.env,
    };
    let asked_lines = at.lines();

    // 2. The server, chosen and agreed to before the build, so that the
    // person is asked at the start and not after it.
    let Found {
        server,
        new_env,
        bought,
    } = server(&m, app, at, &env_before, &kept, on_record, say).await?;
    // A VPS bought here answered its request, which left the record with
    // it (`buy`); any other start an earlier run left without an answer,
    // and which this command does not ask for again, stays, and is said.
    let env_before = if bought {
        let mut env = env_before;
        env.starting.remove(&StartOf::Server);
        env
    } else {
        env_before
    };
    for said in starts_left_said(
        crate::cli::i18n::lang(),
        &starts_left(&env_before, &asked_lines),
        &env_before,
        &app.env,
    ) {
        say.line(&said);
    }
    if let Some(line) = go_ahead_line(&server, bought, &m.name, id.as_str()) {
        say.line(&line);
        go_ahead(yes, &t!("worker_deploy.nothing_deployed"))?;
    }

    // 3. The build, while a VPS gets ready.
    let building = {
        let (m, path, quiet) = (m.clone(), path.clone(), say.quiet);
        tokio::task::spawn_blocking(move || {
            crate::worker::build::for_servers(&m, &path, &Say { quiet })
        })
    };
    let (built, up) = tokio::join!(building, server.wait(say));
    let built = built.map_err(|e| failed(t!("worker_deploy.build_stopped", error = e)))??;
    up?;
    // The build is done and quiet: the host key can be read and agreed to.
    let server = server.secured().await?;
    let release = ReleaseId::new(&built.release.id).map_err(failed)?;
    let agent = agent_binary(&built.release.target)?;
    // The record from here on is the one that names the bought VPS.
    let env_before = Env {
        resource: env_before
            .resource
            .clone()
            .or_else(|| (!server.resource.id.is_empty()).then(|| server.resource.clone())),
        ..env_before
    };
    let to = format!("{}@{}", server.target.user, server.target.host);
    let (name, worker, rel) = (&m.name, id.as_str(), release.as_str());
    say.line(&t!("worker_deploy.plan", name, release = rel, to, worker));
    let session = open(&server.target)?;
    let controller = crate::worker::firewall::controller(&session);

    // 4. The agent and its unit.
    let staged_agent = format!("{UPLOADS}/agent/erpc-worker-agent");
    upload(&session, &staged_agent, &agent.bytes)?;
    let installed = session
        .run(
            &RemoteCommand::Worker(Worker::InstallAgent {
                staged: remote_path(&staged_agent)?,
                sha256: Digest::new(&agent.sha256).map_err(failed)?,
            }),
            None,
        )
        .map_err(|e| failed(t!("worker_deploy.agent.not_installed", error = e)))?;
    let agent_changed = value(&installed.stdout, "agent").as_deref() == Some("installed");
    say.line(&if agent_changed {
        t!("worker_deploy.agent.installed")
    } else {
        t!("worker_deploy.agent.unchanged")
    });
    // An agent that runs is left running here, whatever was replaced, and
    // one that does not run is started, locked (`keep_agent`). What becomes
    // of one kept although a newer one waits: restarted at step 8, right
    // before the key is handed over; or, under --prepare, left for the
    // next deploy, which is said, since the app runs under the old one
    // until then.
    let (set_up, waiting) = keep_agent(at.upto, agent_changed, |verb| {
        ctl_ok(&session, &id, verb, None)
    })?;
    if waiting == WaitingAgent::Kept {
        say.line(&t!("worker_deploy.agent.kept"));
    }
    // This first setup is the one that tells needrestart to leave the
    // workers alone, before anything installs a package. When it could
    // not, that is said here, and carried in the answer for --json.
    if let Some(said) = needrestart_said(&set_up, &scope) {
        say.line(&said);
    }
    // The local services erpc.toml asks for, installed and running before
    // the app can need them.
    if !m.services.is_empty() {
        let names: Vec<&str> = [
            ("Redis", m.services.redis),
            ("PostgreSQL", m.services.postgres),
        ]
        .iter()
        .filter_map(|(n, on)| on.then_some(*n))
        .collect();
        say.line(&t!("worker_deploy.services", names = names.join(", ")));
        ctl_ok(
            &session,
            &id,
            Verb::Services {
                redis: m.services.redis,
                postgres: m.services.postgres,
            },
            None,
        )?;
    }

    // 5. The firewall, before anything runs: SSH from the allow list and
    // this machine only, every other inbound connection dropped, the app's
    // port open only to `app_allow`. A WAF's port is opened as erpc.toml
    // asks only where the WAF on the server runs erpc.toml's rules
    // already: else what is asked is held (the port closed, or left open
    // to those it was open to, with the limit on new connections it had),
    // and applied at step 10, which is handed what this step did, whole.
    // The UDP Forwarding line's port is opened as its record says.
    let ask = crate::worker::firewall::Ask {
        udp_any_source: at.udp_any_source,
        scope: &scope,
    };
    let firewall = crate::worker::firewall::Remote {
        session: &session,
        target: &server.target,
        id: &id,
    };
    let mut synced =
        crate::worker::firewall::sync(&firewall, &m, &app.env, &env_before, controller, ask, say)?;
    let ssh_allow = synced.ssh_allow().to_vec();

    // erpc.toml names the server from here on, whatever fails later: the
    // server is set up, and `logs`, `status` and a second deploy reach it.
    let mut env = Env {
        resource: (!server.resource.id.is_empty()).then(|| server.resource.clone()),
        host: Some(server.target.host.clone()),
        ssh_user: Some(server.target.user.clone()),
        ssh_port: (server.target.port != 22).then_some(server.target.port),
        host_key: Some(server.target.host_key.to_openssh()),
        firewall: Firewall {
            ssh_allow: ssh_allow
                .iter()
                .filter_map(|a| Cidr::parse(&a.to_string()).ok())
                .collect(),
            app_allow: env_before.firewall.app_allow.clone(),
        },
        ..env_before
    };
    let saved = kept.save(&env, None);
    let root = index_root(&path);
    let _ = crate::account::session::beside_config(erpc_worker::index::FILE_NAME)
        .and_then(|p| erpc_worker::index::update(&p, |i| Ok(((), i.remember(&m.name, &root)?))));

    // 6. The data lines, now that the server's address is known and on
    // record; the app gets their endpoints when it starts. A line the
    // operator says is gone leaves the record first.
    let forgotten = take_lines(&mut env, &at.forget_lines)?;
    if let Some(said) = say_forgotten(&forgotten) {
        kept.save(&env, None).map_err(failed)?;
        say.line(&said);
    }
    let udp_asked = asked_lines.iter().any(|(k, _)| *k == LineKind::Udp);
    let lined = if asked_lines.is_empty() {
        Ok(())
    } else {
        let ports = Ports {
            ssh: server.target.port,
            run: m.run.port,
            // Asked of the server only for a UDP line: its firewall knows
            // which UDP ports its other workers receive on.
            others_udp: if udp_asked {
                others_udp(&server.target, &id, say)
            } else {
                Vec::new()
            },
        };
        let step = Step {
            record: &kept,
            on_record,
            scope: &scope,
            say,
        };
        lines(at, &ports, &server, &mut env, step).await
    };
    // A UDP Forwarding line on record that was not asked for again still
    // sends: where from is read again, since ERPC may have moved it.
    if lined.is_ok() && !udp_asked {
        refresh_udp_sources(Api::open, &mut env, &kept, say).await?;
    }
    // The firewall follows the lines, whether or not every asked line came:
    // a UDP Forwarding line pointed at the server just now, or whose
    // addresses changed, or one that left the record, changes what its
    // port lets in, and is on record before the next kind is tried. When
    // both fail, the lines error is the one to report.
    // The WAF's port stays as step 5 left it: only the UDP port changes.
    if let Err(e) = crate::worker::firewall::reopen(
        &firewall,
        &mut synced,
        crate::worker::firewall::udp_opening(&env, at.udp_any_source),
        &crate::worker::firewall::say_udp(&env, ask),
        say,
    ) {
        if lined.is_ok() {
            return Err(e);
        }
        say.line(&format!(
            "warning: {}",
            t!(
                "worker_deploy.line.firewall_not_followed",
                error = e.message,
                scope
            )
        ));
    }
    lined?;
    // A pending UDP Forwarding line is said with whether it is charged now.
    let pending_udp = env
        .lines
        .iter()
        .find(|l| l.kind == LineKind::Udp && l.is_pending());
    let udp_state = UdpState {
        any_source: at.udp_any_source,
        pending_charged: match pending_udp {
            Some(line) => pending_udp_charged(line).await,
            None => None,
        },
    };
    let launch = Launch::for_app(&m, &env).map_err(failed)?;

    // 7. The release.
    let session = open(&server.target)?;
    let dir = format!("{UPLOADS}/{}/{}", id.as_str(), release.as_str());
    // The bytes the build read, checked and hashed: the file is not read
    // again, so what is uploaded is what the release's record names.
    upload(
        &session,
        &format!("{dir}/{}", built.release.bin),
        &built.bytes,
    )?;
    let record = serde_json::to_vec_pretty(&built.release).map_err(|e| failed(e.to_string()))?;
    upload(
        &session,
        &format!("{dir}/{}", erpc_worker::release::FILE_NAME),
        &record,
    )?;
    let launch_json = serde_json::to_vec_pretty(&launch).map_err(|e| failed(e.to_string()))?;
    upload(
        &session,
        &format!("{dir}/{}", erpc_worker::server::LAUNCH_FILE),
        &launch_json,
    )?;
    let root = crate::worker::build::app_root(&path);
    for file in &built.release.files {
        let bytes = std::fs::read(root.join(&file.path)).map_err(|e| {
            let path = &file.path;
            failed(t!("worker_deploy.could_not_read", path, error = e))
        })?;
        upload(&session, &format!("{dir}/{}", file.path), &bytes)?;
    }
    ctl_ok(&session, &id, Verb::Install(release.clone()), None)?;
    say.line(&t!("worker_deploy.installed", release = release.as_str()));

    // 8. The key and the secrets, in `hand_over`'s order: read first, so
    // that a key nobody allowed leaves the app that runs running; then an
    // agent that step 4 left running although a newer one is installed is
    // restarted, which stops the app; then the key goes to it at once.
    // Nothing between step 4 and here asked the agent for more than its
    // status.
    let handed = hand_over(
        at.upto,
        waiting,
        &scope,
        || unlock_request(&m),
        || {
            crate::worker::remote::positions_warning(&m, app, say);
            say.line(&t!("worker_deploy.agent.restarting"));
        },
        |verb, stdin| ctl_ok(&session, &id, verb, stdin),
    )?;
    // A --prepare ends here, with nothing handed over: the server, the
    // firewall, the lines and the release are in place, and nothing that
    // needs the key or a secret was read. Nothing was started, stopped or
    // restarted: the app that runs there, if any, runs on, from the release
    // and under the agent it had (step 4 left a running agent running).
    let Some(restarted) = handed else {
        let host = &server.target.host;
        let from = ssh_allow
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let mut text = vec![
            said_in!(
                lang,
                t!(
                    "worker_deploy.done.prepared",
                    name,
                    release = rel,
                    host,
                    worker
                )
            ),
            said_in!(lang, t!("worker_deploy.done.prepared_next", scope)),
            said_in!(lang, t!("worker_deploy.done.ssh_only", from)),
        ];
        if waiting == WaitingAgent::Kept {
            text.push(said_in!(lang, t!("worker_deploy.done.agent_kept", scope)));
        }
        // The WAF is put in place with the app, by the deploy that starts it.
        text.extend(crate::worker::waf::prepared(lang, &m));
        if let Err(error) = &saved {
            text.push(format!(
                "warning: {}",
                said_in!(lang, t!("worker_deploy.done.not_kept", error))
            ));
        }
        text.extend(on_record_said(
            lang,
            &env,
            &server.resource,
            udp_state,
            &scope,
        ));
        text.extend(starts_left_said(
            lang,
            &starts_left(&env, &[]),
            &env,
            &app.env,
        ));
        return Ok(json!({
            "text": text.join("\n"),
            "prepared": true,
            "release": built.release,
            "host": server.target.host,
            "worker": id.as_str(),
            "agent": agent_said(
                &agent,
                &set_up,
                agent_changed,
                waiting == WaitingAgent::Kept,
                false,
            ),
            "ssh_allow": ssh_allow,
            // Not touched: the deploy that starts the app puts it in place.
            "waf": m.waf.as_ref().map(|waf| json!({ "port": waf.port, "applied": false })),
            "lines": env.lines,
            "lines_forgotten": forgotten.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
            "starting": env.starting,
            "erpc_toml_updated": saved.is_ok(),
            "next": [format!("erpc worker deploy{scope}")],
        }));
    };
    // What a failure from here on carries for --json: the agent was
    // restarted, whatever became of the start.
    let restarted_said = |e: CliError| if restarted { agent_restarted(e) } else { e };

    // 9. Activation, which restarts an app already running there.
    if !restarted {
        crate::worker::remote::positions_warning(&m, app, say);
    }
    say.line(&t!("worker_deploy.starting"));
    let answer =
        ctl(&session, &id, Verb::Activate(release.clone()), None).map_err(restarted_said)?;

    if answer["ok"].as_bool() != Some(true) {
        return Err(restarted_said(activation_failed(
            &answer,
            release.as_str(),
            &scope,
        )));
    }
    let host = &server.target.host;
    let from = ssh_allow
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut text = vec![
        said_in!(
            lang,
            t!("worker_deploy.done.runs", name, release = rel, host, worker)
        ),
        said_in!(lang, t!("worker_deploy.done.ssh_only", from)),
    ];
    if let Some(previous) = answer["previous"].as_str() {
        text.push(said_in!(
            lang,
            t!("worker_deploy.done.rollback", scope, previous)
        ));
    }
    // An inventory environment's item also records what runs, and when.
    let saved = match (&saved, &env.inventory) {
        (Ok(()), Some(_)) => kept.save(
            &env,
            Some(&crate::worker::inventory::deployed(release.as_str())),
        ),
        _ => saved,
    };

    // What the deploy says after the WAF's lines, and reports besides the
    // WAF: neither depends on the last step.
    let mut after = Vec::new();
    match (&saved, &env.inventory) {
        (Ok(()), Some(i)) if new_env => {
            let (vault, title) = (&i.vault, erpc_worker::inventory::title(&m.name, &app.env));
            after.push(said_in!(
                lang,
                t!("worker_deploy.done.in_vault", vault, title)
            ));
        }
        (Ok(()), None) if new_env => {
            after.push(said_in!(
                lang,
                t!("worker_deploy.done.in_toml", env = app.env)
            ));
        }
        (Ok(()), _) => {}
        (Err(error), _) => after.push(format!(
            "warning: {}",
            said_in!(lang, t!("worker_deploy.done.not_kept", error))
        )),
    }
    after.extend(on_record_said(
        lang,
        &env,
        &server.resource,
        udp_state,
        &scope,
    ));
    after.extend(starts_left_said(
        lang,
        &starts_left(&env, &[]),
        &env,
        &app.env,
    ));
    let report = json!({
        "release": built.release,
        "host": server.target.host,
        "worker": id.as_str(),
        "activation": answer,
        "agent": agent_said(&agent, &set_up, agent_changed, false, restarted),
        "ssh_allow": ssh_allow,
        "lines": env.lines,
        "lines_forgotten": forgotten.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
        "starting": env.starting,
        "erpc_toml_updated": saved.is_ok(),
    });

    // 10. The WAF, now that the app answers behind it; then its port as
    // erpc.toml asks, wherever the firewall step left it otherwise.
    ended(
        &crate::worker::waf::Deploy {
            server: &crate::worker::firewall::Remote {
                session: &session,
                target: &server.target,
                id: &id,
            },
            scope: &scope,
            lang,
            say,
        },
        (&m, &app.env, rel),
        &synced,
        (text, after),
        report,
    )
}

/// How a deploy that started the app ends: its step 10, the WAF and then
/// its port as erpc.toml asks ([`crate::worker::waf::Deploy::settle`],
/// handed `synced`, what the firewall step did), and its report. `said`
/// is what the deploy says before the WAF's lines and after them, and
/// `report` what it reports besides the WAF; the WAF's part of both is
/// added here, as `text` and as `waf`.
///
/// # Errors
///
/// When the last step fails: the WAF did not come up, or the server did
/// not take the opening. There is no report then, and the deploy fails.
fn ended(
    waf: &crate::worker::waf::Deploy<'_>,
    (m, env_name, release): (&Manifest, &str, &str),
    synced: &crate::worker::firewall::Synced,
    said: (Vec<String>, Vec<String>),
    mut report: Value,
) -> Result<Value, CliError> {
    let settled = waf.settle(m, env_name, release, synced)?;
    let (before, after) = said;
    let text: Vec<String> = before
        .into_iter()
        .chain(settled.text)
        .chain(after)
        .collect();
    report["text"] = json!(text.join("\n"));
    report["waf"] = settled.json;
    Ok(report)
}

#[cfg(test)]
mod tests {

    /// A made-up 1Password vault id, of the shape a real one has.
    const OP_VAULT: &str = "abcdefghijklmnopqrstuvwxyz";
    use erpc_ssh::HostKey;

    use std::cell::RefCell;

    use super::AgentSource;

    fn bought() -> Resource {
        Resource {
            kind: ResourceKind::Vps,
            id: "100001".to_owned(),
            region: Some("amsterdam".to_owned()),
            hourly: true,
        }
    }

    /// The first step of a deploy, with the keystore locked and nobody at
    /// a terminal: the case of an agent that prepares a deploy for a
    /// person to finish.
    #[test]
    fn a_prepare_looks_for_what_the_keystore_holds_and_only_a_deploy_opens_it() {
        use super::{Upto, Where, app_ready};
        use crate::worker::keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        use crate::worker::secrets::Store;
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _keystore = set_up(&desk);
        let token = zeroize::Zeroizing::new("tok-1".to_owned());
        let kept = crate::worker::secrets::put(
            &Store::Keystore { by_default: false },
            "bot",
            "X_TOKEN",
            &token,
        )
        .expect("kept");
        let home = tempfile::tempdir().expect("a directory");
        let app = super::App {
            dir: crate::worker::Dir::at(home.path()),
            env: "default".to_owned(),
        };
        let written = |secrets: &str| {
            let text = format!("name = \"bot\"\nchain = \"solana\"\n[secrets]\n{secrets}");
            std::fs::write(home.path().join("erpc.toml"), text).expect("erpc.toml");
        };
        let ready = |upto| {
            app_ready(
                &app,
                &Where {
                    upto,
                    ..Where::default()
                },
            )
        };
        desk.lock();
        desk.terminal.set(false);
        let asked = desk.asked();

        // Every entry the app names is kept here.
        written(&format!("X_TOKEN = \"{kept}\"\n"));
        // --prepare goes on, and asks for nothing.
        let (path, m) = ready(Upto::Prepared).expect("a --prepare goes on");
        assert_eq!(path, home.path().join("erpc.toml"));
        assert_eq!(m.name, "bot");
        // A deploy, which hands the secrets over, stops here, before
        // anything is bought, and names the command that unlocks.
        let e = ready(Upto::Started).expect_err("locked");
        assert_eq!(
            e.text(),
            "error: the keystore is locked, and nobody is at a terminal to type its passphrase: \
             run `erpc worker secret unlock` at a terminal, then this again"
        );

        // An entry that is not here is named by both, before a server is
        // bought for an app that could not be started on it.
        written(&format!(
            "X_TOKEN = \"{kept}\"\nY_TOKEN = \"keystore:erpc-worker/bot.Y_TOKEN\"\n"
        ));
        for upto in [Upto::Prepared, Upto::Started] {
            let e = ready(upto).expect_err("not here");
            assert_eq!(
                e.text(),
                "error: nothing is kept under keystore:erpc-worker/bot.Y_TOKEN on this machine",
                "{upto:?}"
            );
        }
        // None of it asked for the passphrase, and the keystore is still
        // locked.
        assert_eq!(desk.asked(), asked);
        assert!(!desk.is_unlocked());
    }

    /// A deploy of an app that lacks a setting names the command that
    /// keeps it, with the flag that gives its value when nobody has to
    /// type it: the one `init` named for the app's template.
    #[test]
    fn a_deploy_names_a_missing_secret_with_the_flag_that_gives_its_value() {
        use super::{Where, app_ready_in};
        use crate::cli::i18n::speaking;
        use erpc_core::i18n::Lang;
        use erpc_secret::gate::Context;
        let home = tempfile::tempdir().expect("a directory");
        let app = super::App {
            dir: crate::worker::Dir::at(home.path()),
            env: "default".to_owned(),
        };
        let scope = app.dir.scope();
        let hint = |template: &str, requires: &str| {
            let text = format!(
                "name = \"bot\"\nchain = \"solana\"\n{template}[run]\nrequires = [{requires}]\n"
            );
            std::fs::write(home.path().join("erpc.toml"), text).expect("erpc.toml");
            let e = app_ready_in(Context::empty(), &app, &Where::default()).expect_err("missing");
            assert!(e.message.contains("bot"), "{}", e.message);
            e.hint.expect("a hint")
        };
        let said = |command: &str| format!("`{command}{scope}`, or set it in [vars]");
        let pumpfun = "template = \"solana/pumpfun@1\"\n";
        // The bot's own token is made, and the RPC key is the account's.
        let made = hint(pumpfun, "\"API_TOKEN\"");
        assert_eq!(made, said("erpc worker secret put API_TOKEN --generate"));
        assert_eq!(
            hint(pumpfun, "[\"ERPC_API_KEY\", \"SOLANA_RPC_ENDPOINT\"]"),
            said("erpc worker secret put ERPC_API_KEY --from-account")
        );
        // A secret the operator has to give is typed, and so is every
        // secret of an app that was made by hand.
        assert_eq!(
            hint(pumpfun, "\"X_TOKEN\""),
            said("erpc worker secret put X_TOKEN")
        );
        assert_eq!(
            hint("", "\"API_TOKEN\""),
            said("erpc worker secret put API_TOKEN")
        );
        // Each is a command erpc takes.
        for flag in [" --generate", " --from-account", ""] {
            let words = format!("erpc worker secret put API_TOKEN{flag}{scope}");
            assert!(
                <crate::Cli as clap::Parser>::try_parse_from(words.split_whitespace()).is_ok(),
                "{words}"
            );
        }
        // Said in the language of the run, with the same command.
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let there = speaking(lang, || hint(pumpfun, "\"API_TOKEN\""));
            assert_ne!(there, made, "{lang:?}");
            let command = format!("`erpc worker secret put API_TOKEN --generate{scope}`");
            assert!(there.contains(&command), "{there}");
            assert!(!there.contains('{'), "{there}");
        }
    }

    /// The same first step for an app that trades, whose key is kept: a
    /// deploy reads the key, so it asks the key's gate, before anything is
    /// bought; a `--prepare` reads none, and does not ask.
    #[test]
    fn a_prepare_does_not_ask_whether_the_key_may_be_read_and_a_deploy_does() {
        use super::{Upto, Where, app_ready_in};
        use crate::worker::keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        use crate::worker::secrets::Store;
        use erpc_secret::gate::Context;
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _keystore = set_up(&desk);
        let key = erpc_chain_solana::identity::Keypair::generate().expect("random");
        let store = Store::Keystore { by_default: false };
        let kept = crate::worker::secrets::put_key(&store, "bot", &key).expect("kept");
        let home = tempfile::tempdir().expect("a directory");
        let text = format!(
            "name = \"bot\"\nchain = \"solana\"\n[wallet]\nsource = \"{kept}\"\npubkey = \"{}\"\n",
            key.pubkey()
        );
        std::fs::write(home.path().join("erpc.toml"), text).expect("erpc.toml");
        let app = super::App {
            dir: crate::worker::Dir::at(home.path()),
            env: "default".to_owned(),
        };
        let ready = |context, upto| {
            let at = Where {
                upto,
                ..Where::default()
            };
            app_ready_in(context, &app, &at)
        };
        // The keystore locked, and whoever runs the command not a person
        // at a terminal: an agent, say, that prepares a deploy.
        desk.lock();
        let (nobody, asked) = (Context::empty(), desk.asked());
        // --prepare goes on: it is not asked whether it may read the key.
        let (_, m) = ready(nobody, Upto::Prepared).expect("a --prepare goes on");
        assert!(m.wallet.is_some());
        // A deploy is refused by the key's gate, and that before the
        // keystore is opened: nothing was asked for.
        let e = ready(nobody, Upto::Started).expect_err("the gate refuses");
        assert_eq!(
            e.text(),
            "error: erpc will not read the trading key here: no terminal is attached, and this key \
             needs a person present"
        );
        assert_eq!(desk.asked(), asked);
        // A person at a terminal passes the gate, and the deploy then
        // opens the keystore: the passphrase is asked for, once.
        let at_a_desk = Context {
            has_tty: true,
            ..Context::empty()
        };
        desk.will_type(&[PASSPHRASE]);
        let (_, m) = ready(at_a_desk, Upto::Started).expect("a deploy goes on");
        assert!(m.wallet.is_some());
        assert_eq!(desk.asked(), asked + 1);
        assert!(desk.is_unlocked());
    }

    #[test]
    fn a_deploy_ends_with_its_waf_applied_its_port_opened_and_both_in_its_report() {
        use crate::worker::firewall::recorded::Recorded;
        use erpc_core::i18n::Lang;
        use erpc_worker::manifest::Manifest;
        use serde_json::{Value, json};
        let app = |waf: &str, allow: &str| {
            Manifest::parse(&format!(
                "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n{waf}\
                 [env.default]\nhost = \"203.0.113.10\"\n\
                 [env.default.firewall]\napp_allow = [{allow}]\n"
            ))
            .expect("valid")
        };
        let say = crate::node::common::Say { quiet: true };
        let me = Some("198.51.100.7".parse().expect("an address"));
        // The deploy's firewall step, and then its end: what it has said
        // so far and has still to say, and what it reports besides the WAF.
        let end = |m: &Manifest, server: &Recorded| {
            let synced = crate::worker::firewall::sync(
                server,
                m,
                "default",
                &m.env["default"],
                me,
                crate::worker::firewall::Ask::from_record(""),
                &say,
            )
            .expect("the firewall step");
            let step_5 = server.asked();
            let waf = crate::worker::waf::Deploy {
                server,
                scope: " --env default",
                lang: Lang::En,
                say: &say,
            };
            let report = super::ended(
                &waf,
                (m, "default", "20261111T090000Z-1a2b3c4d"),
                &synced,
                (vec!["bot runs.".to_owned()], vec!["Kept.".to_owned()]),
                json!({ "worker": "bot-default" }),
            );
            (step_5, server.asked(), report)
        };
        let m = app("[waf]\nport = 8080\n", "\"0.0.0.0/0\", \"::/0\"");

        // A first deploy with a WAF: the port is closed until the release
        // runs; then the WAF is put in place, and only then its port
        // opened as erpc.toml asks.
        let none = Recorded::with(&Value::Null, "bot-default", None);
        let (step_5, step_10, report) = end(&m, &none);
        assert_eq!(step_5, ["allow-ssh 198.51.100.7", "firewall-show", "close"]);
        assert_eq!(
            step_10,
            [
                "waf-apply 0.0.0.0:8080",
                "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
            ]
        );
        // The report is what it was handed, with the WAF's part: under
        // `waf`, and in the text between what came before and after.
        let report = report.expect("a report");
        assert_eq!(report["worker"], "bot-default");
        assert_eq!(report["waf"]["port"], 8080);
        assert_eq!(report["waf"]["open_to"], json!(["0.0.0.0/0", "::/0"]));
        let text: Vec<&str> = report["text"].as_str().expect("text").lines().collect();
        assert_eq!(text.len(), 4, "{text:?}");
        assert_eq!((text[0], text[3]), ("bot runs.", "Kept."));
        assert!(
            text[1].starts_with("Its WAF listens on port 8080 and forwards to the app on "),
            "{text:?}"
        );
        assert!(text[1].ends_with("the port is open to 0.0.0.0/0, ::/0, with new connections over 50 a second from one address dropped."));
        assert!(text[2].starts_with("`erpc worker firewall list --env default` "));

        // A WAF that does not come up fails the deploy there: no report,
        // and the port stays as the firewall step left it.
        let mut down = Recorded::with(&Value::Null, "bot-default", None);
        down.waf_applied = json!({ "ok": false, "error": "it did not come up" });
        let (_, step_10, report) = end(&m, &down);
        assert_eq!(step_10, ["waf-apply 0.0.0.0:8080"]);
        let failed = report.expect_err("failed");
        assert!(
            failed
                .message
                .ends_with("its WAF did not come up: it did not come up"),
            "{}",
            failed.message
        );
        // So does a server that does not take the opening: the deploy
        // does not report a port open that is not.
        let mut shut = Recorded::with(&Value::Null, "bot-default", None);
        shut.fails = vec!["open 8080 to 0.0.0.0/0, ::/0, limit 50/100"];
        let (_, step_10, report) = end(&m, &shut);
        assert_eq!(step_10.len(), 2, "{step_10:?}");
        assert_eq!(
            report.expect_err("failed").message,
            "the server did not do it: open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
        );

        // An app without `[waf]`, on a server that has none: the server
        // is asked to remove one, and nothing of a WAF is reported.
        let mut plain = Recorded::with(&Value::Null, "bot-default", None);
        plain.waf_removed = json!({ "ok": true, "removed": false });
        let (step_5, step_10, report) = end(&app("", "\"198.51.100.7\""), &plain);
        assert_eq!(
            step_5,
            ["allow-ssh 198.51.100.7", "open 3000 to 198.51.100.7/32"]
        );
        assert_eq!(step_10, ["waf-remove"]);
        let report = report.expect("a report");
        assert!(report["waf"].is_null(), "{report}");
        assert_eq!(report["text"], "bot runs.\nKept.");
    }

    #[test]
    fn the_end_of_a_deploy_names_what_is_charged_and_how_to_end_it() {
        use erpc_core::i18n::Lang;
        use erpc_worker::manifest::{Env, Line, LineKind};
        let env = Env {
            lines: vec![Line {
                kind: LineKind::Grpc,
                id: "7".to_owned(),
                endpoint: "line-7.example".to_owned(),
                hourly: true,
                sources: Vec::new(),
            }],
            ..Env::default()
        };
        let said = super::on_record_said(
            Lang::En,
            &env,
            &bought(),
            super::UdpState::default(),
            " --env prod bot",
        );
        assert_eq!(said.len(), 2, "{said:?}");
        assert!(
            said.iter()
                .all(|line| line.contains("delete --release-server --env prod bot")),
            "{said:?}"
        );
        // Nothing hourly: nothing to say.
        let own = Resource {
            hourly: false,
            ..bought()
        };
        let udp = super::UdpState::default();
        assert!(super::on_record_said(Lang::En, &Env::default(), &own, udp, "").is_empty());
    }

    #[test]
    fn an_agent_that_waits_is_restarted_only_by_a_deploy_that_hands_the_key_over() {
        use super::{Upto, WaitingAgent};
        let (prepare, deploy) = (Upto::from_prepare(true), Upto::from_prepare(false));
        assert_eq!(deploy, Upto::default());
        // A newer agent waits for the one that runs. --prepare hands
        // neither the key nor a secret over, so it leaves it running; a
        // deploy restarts it, at step 8, right before it hands them over.
        assert_eq!(prepare.waiting_agent(true), WaitingAgent::Kept);
        assert_eq!(deploy.waiting_agent(true), WaitingAgent::Restart);
        // None waits: nothing to keep, and nothing to restart.
        for upto in [prepare, deploy] {
            assert_eq!(upto.waiting_agent(false), WaitingAgent::None);
        }
    }

    #[test]
    fn step_4_asks_setup_to_keep_the_agent_whatever_the_deploy() {
        use super::{Upto, WaitingAgent, keep_agent};
        use erpc_ssh::worker::{RunningAgent, Verb};
        use serde_json::json;
        let kept = json!({ "ok": true, "agent": "kept", "newer_waits": true });
        for upto in [Upto::from_prepare(true), Upto::from_prepare(false)] {
            for agent_changed in [false, true] {
                // The one verb step 4 sends: an agent that runs holds the
                // key, and nothing hands it back before step 8.
                let sent = RefCell::new(Vec::new());
                let (set_up, waiting) = keep_agent(upto, agent_changed, |verb| {
                    sent.borrow_mut().push(verb);
                    Ok(kept.clone())
                })
                .expect("set up");
                assert_eq!(*sent.borrow(), [Verb::Setup(RunningAgent::Keep)]);
                assert_eq!(set_up, kept);
                // A newer one waits: a --prepare leaves it for the next
                // deploy, and a deploy restarts it at step 8.
                let then = if upto.prepares() {
                    WaitingAgent::Kept
                } else {
                    WaitingAgent::Restart
                };
                assert_eq!(waiting, then);
            }
        }
        // Started just now, or running what is installed: none waits.
        for answer in [
            json!({ "ok": true, "agent": "started", "newer_waits": false }),
            json!({ "ok": true, "agent": "kept", "newer_waits": false }),
        ] {
            let (_, waiting) =
                keep_agent(Upto::default(), false, |_| Ok(answer.clone())).expect("set up");
            assert_eq!(waiting, WaitingAgent::None);
        }
        // A setup that fails is the deploy's failure.
        let refused = keep_agent(Upto::default(), true, |_| Err(super::failed("no sudo")));
        assert_eq!(refused.expect_err("refused").message, "no sudo");
    }

    #[test]
    fn step_8_reads_the_key_then_restarts_the_agent_then_unlocks() {
        use super::{Upto, WaitingAgent, hand_over};
        use erpc_ssh::worker::{RunningAgent, Verb};
        use serde_json::json;
        // What step 8 did, in order; `fail` names the event that fails.
        let walk_upto = |upto, waiting, fail: &'static str| {
            let events = RefCell::new(Vec::new());
            let note = |event: &str| {
                events.borrow_mut().push(event.to_owned());
                if event == fail {
                    Err(super::failed(format!("{event} failed")))
                } else {
                    Ok(())
                }
            };
            let done = hand_over(
                upto,
                waiting,
                " --env prod bot",
                || note("read").map(|()| zeroize::Zeroizing::new(b"the key".to_vec())),
                || {
                    let _ = note("said");
                },
                |verb, stdin| {
                    let event = match (&verb, stdin) {
                        (Verb::Setup(RunningAgent::Restart), None) => "restart",
                        (Verb::Unlock, Some(b"the key")) => "unlock",
                        _ => panic!("step 8 sent {verb:?}"),
                    };
                    note(event).map(|()| json!({ "ok": true }))
                },
            );
            (done, events.into_inner())
        };
        let walk = |waiting, fail| walk_upto(Upto::Started, waiting, fail);
        // A --prepare hands nothing over, whatever waits: the key is not
        // read, and the agent is asked nothing, so the app that runs there
        // runs on.
        for waiting in [
            WaitingAgent::None,
            WaitingAgent::Kept,
            WaitingAgent::Restart,
        ] {
            let (done, events) = walk_upto(Upto::Prepared, waiting, "");
            assert!(events.is_empty(), "{waiting:?}: {events:?}");
            assert_eq!(done.ok(), Some(None), "{waiting:?}");
        }
        // A newer agent waits: the key is read first, then the agent is
        // restarted, and the key goes to it at once.
        let (done, events) = walk(WaitingAgent::Restart, "");
        assert_eq!(events, ["read", "said", "restart", "unlock"]);
        assert_eq!(done.ok(), Some(Some(true)));
        // None waits: nothing is restarted.
        for waiting in [WaitingAgent::None, WaitingAgent::Kept] {
            let (done, events) = walk(waiting, "");
            assert_eq!(events, ["read", "unlock"], "{waiting:?}");
            assert_eq!(done.ok(), Some(Some(false)));
        }
        // A key nobody allowed: the agent is not touched, and the app that
        // runs runs on.
        let (done, events) = walk(WaitingAgent::Restart, "read");
        assert_eq!(events, ["read"]);
        let refused = done.expect_err("no key");
        assert_eq!((refused.hint, refused.details), (None, None));
        // A failure once the agent was restarted says that it was, and how
        // the key is handed over; --json has it in the details.
        for fail in ["restart", "unlock"] {
            let (done, _) = walk(WaitingAgent::Restart, fail);
            let failed = done.expect_err("failed");
            assert_eq!(failed.message, format!("{fail} failed"));
            let hint = failed.hint.expect("a hint");
            assert!(
                hint.contains("agent was restarted")
                    && hint.contains("`erpc worker start --env prod bot`"),
                "{hint}"
            );
            assert_eq!(
                failed.details,
                Some(json!({ "agent": { "restarted": true } }))
            );
        }
        // An unlock that fails with the agent as it was says nothing of a
        // restart.
        let (done, _) = walk(WaitingAgent::None, "unlock");
        assert_eq!(done.expect_err("failed").details, None);
        // What a later failure carries keeps the details it had.
        let earlier = super::failed("unhealthy").details(json!({ "release": "r1" }));
        assert_eq!(
            super::agent_restarted(earlier).details,
            Some(json!({ "release": "r1", "agent": { "restarted": true } }))
        );
    }

    #[test]
    fn a_needrestart_rule_that_could_not_be_written_is_said_and_carried_for_json() {
        use serde_json::{Value, json};
        let error = "could not write the rule: Permission denied (os error 13)";
        let agent = super::Agent {
            bytes: Vec::new(),
            source: AgentSource::Embedded,
            sha256: "ab".repeat(32),
        };
        let set_up = json!({ "ok": true, "agent": "started", "needrestart_error": error });
        // Said where a person reads it, with how the key is handed over
        // should a package run restart the worker.
        let said = super::needrestart_said(&set_up, " --env prod bot").expect("said");
        assert!(
            said.contains(error) && said.contains("`erpc worker start --env prod bot`"),
            "{said}"
        );
        // --json prints no such line: its answer carries the agent's words,
        // beside what it already said of the agent.
        let answer = super::agent_said(&agent, &set_up, true, false, true);
        assert_eq!(
            answer,
            json!({
                "sha256": "ab".repeat(32),
                "source": "embedded",
                "changed": true,
                "kept": false,
                "restarted": true,
                "needrestart_error": error,
            })
        );
        // The rule written, or an agent that says nothing of it: nothing
        // is said, and the answer has null.
        for written in [
            json!({ "ok": true, "needrestart_error": null }),
            json!({ "ok": true }),
        ] {
            assert_eq!(super::needrestart_said(&written, ""), None);
            let answer = super::agent_said(&agent, &written, false, true, false);
            assert_eq!(answer["needrestart_error"], Value::Null);
            assert_eq!(answer["kept"], true);
        }
    }

    #[test]
    fn a_release_refused_for_its_port_says_what_stayed_and_what_to_change() {
        use crate::cli::i18n::speaking;
        use erpc_core::i18n::Lang;
        use erpc_worker::server::port_taken;
        use serde_json::{Value, json};
        let failed = |answer: &Value| super::activation_failed(answer, "r2", " --env prod bot");
        let taken = port_taken(3000, Some("api-default"));

        // Refused before anything was switched. The release was installed
        // by then, and the agent may have been restarted for a newer one,
        // so this speaks of the release in use, not of the server.
        let unchanged = json!({ "ok": false, "release": "r2", "error": taken, "unchanged": true });
        let refused = failed(&unchanged);
        assert_eq!(
            refused.message,
            format!("release r2 failed: {taken}; the release in use, if any, was left as it was")
        );
        let hint = refused.hint.expect("a hint");
        assert!(
            hint.contains("port 3000") && hint.contains("erpc.toml"),
            "{hint}"
        );
        for (lang, release, server) in [
            (Lang::Ja, "リリース", "サーバー"),
            (Lang::Zh, "版本", "服务器"),
            (Lang::Ru, "релиз", "сервер"),
        ] {
            let said = speaking(lang, || failed(&unchanged).message);
            let (_, stayed) = said.split_once(taken.as_str()).expect("the agent's words");
            assert!(
                stayed.contains(release) && !stayed.contains(server) && !stayed.contains('{'),
                "{lang:?}: {stayed}"
            );
        }

        // Refused by the agent's own look at the port, once the release
        // was switched to: the server went back, and the hint is the same.
        let rolled_back = failed(&json!({
            "ok": false,
            "error": port_taken(3000, None),
            "rolled_back": true,
            "running": "r1",
            "running_healthy": true,
        }));
        assert!(
            rolled_back
                .message
                .ends_with("; the server went back to r1, which is healthy"),
            "{}",
            rolled_back.message
        );
        assert!(rolled_back.hint.expect("a hint").contains("port 3000"));

        // Any other failure points at the log, and says nothing of a port.
        let unhealthy = failed(&json!({
            "ok": false,
            "error": "release r2 was not healthy within 35s (state starting, last exit none)",
            "rolled_back": false,
        }));
        assert!(
            unhealthy.message.ends_with("so it is stopped"),
            "{}",
            unhealthy.message
        );
        assert_eq!(
            unhealthy.hint.as_deref(),
            Some("`erpc worker logs --env prod bot` shows why")
        );
    }

    #[test]
    fn a_newer_agent_waits_when_the_one_that_runs_was_kept_over_it() {
        use serde_json::json;
        let kept = |waits: bool| json!({ "ok": true, "agent": "kept", "newer_waits": waits });
        // Its unit or its binary waits, as setup saw it; or this deploy
        // replaced the binary, whatever setup could tell.
        assert!(super::agent_waits(&kept(true), false));
        assert!(super::agent_waits(&kept(false), true));
        // Kept, and nothing newer: it runs what is installed.
        assert!(!super::agent_waits(&kept(false), false));
        // It did not run, and was started with what is installed.
        let started = json!({ "ok": true, "agent": "started", "newer_waits": false });
        assert!(!super::agent_waits(&started, true));
    }

    #[test]
    fn every_server_but_one_bought_just_now_asks_to_go_ahead() {
        let taken_up = super::Waiting::Vps(super::Api::offline(), bought());
        let line = super::go_ahead_line(&taken_up, false, "bot", "erpc-worker-bot")
            .expect("a VPS taken up from an earlier deploy asks");
        assert!(line.contains("VPS 100001"), "{line}");
        assert!(super::go_ahead_line(&taken_up, true, "bot", "erpc-worker-bot").is_none());
    }

    #[tokio::test]
    async fn a_bought_vps_is_on_record_before_it_is_waited_for() {
        let log = RefCell::new(Vec::new());
        let on_record = RefCell::new(Vec::new());
        let result = super::on_record_then(
            bought(),
            |r| {
                log.borrow_mut().push(format!("saved {}", r.id));
                Ok(())
            },
            &on_record,
            " --env staging",
            |r| {
                log.borrow_mut().push(format!("waited for {}", r.id));
                async { Err::<(), _>(super::failed("it did not get ready")) }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*log.borrow(), ["saved 100001", "waited for 100001"]);
        // The failure is then told what is charged (deploy's wrapper).
        assert_eq!(*on_record.borrow(), ["VPS 100001"]);
    }

    #[tokio::test]
    async fn a_vps_that_cannot_be_put_on_record_is_not_waited_for() {
        let waited = RefCell::new(false);
        let on_record = RefCell::new(Vec::new());
        let e = super::on_record_then(
            bought(),
            |_| Err("the disk is full".to_owned()),
            &on_record,
            " --env staging",
            |_| {
                *waited.borrow_mut() = true;
                async { Err::<(), _>(super::failed("unreachable")) }
            },
        )
        .await
        .expect_err("refused");
        assert!(!*waited.borrow());
        assert!(
            e.message.contains("could not be put on record"),
            "{}",
            e.message
        );
        // The way to take it up names the environment it is for.
        assert!(
            e.hint
                .unwrap_or_default()
                .contains("`erpc worker deploy --vps 100001 --env staging`")
        );
    }

    /// The request of a start of `family`, as it goes on record.
    fn request(family: &str, region: Option<&str>, ip: Option<&str>) -> super::Start {
        super::Start {
            key: "0a".repeat(16),
            family: family.to_owned(),
            product: "prod_One".to_owned(),
            region: region.map(ToOwned::to_owned),
            ip: ip.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn a_vps_start_is_on_record_before_it_leaves_and_goes_with_a_refusal() {
        use super::{EnvRecord, ServerStart, StartOf, StartRecord as _};
        use erpc_worker::manifest::Manifest;
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("erpc.toml");
        std::fs::write(&path, "name = \"bot\"\nchain = \"solana\"\n").expect("write");
        let record = EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let on_record = || Manifest::load(&path).expect("valid").env;
        let vps = request("vps", Some("amsterdam"), None);
        // A new environment: the request is what puts it on record.
        let mut start = ServerStart {
            env: Env::default(),
            record: &record,
            fresh: true,
            scope: " bot",
        };
        assert_eq!(start.pending(), None);
        start.begin(&vps).expect("on record");
        assert_eq!(on_record()["default"].starting[&StartOf::Server], vps);
        assert_eq!(start.pending(), Some(vps.clone()));
        // Refused: the environment the request alone made leaves with it,
        // and erpc.toml is as it was.
        start.settle().expect("settled");
        assert!(on_record().is_empty());
        assert_eq!(start.pending(), None);
        // An environment that was there before stays, without the request.
        let before = Env {
            lines: vec![Line {
                kind: LineKind::Grpc,
                id: "100002".to_owned(),
                endpoint: String::new(),
                hourly: true,
                sources: Vec::new(),
            }],
            ..Env::default()
        };
        let mut start = ServerStart {
            env: before.clone(),
            record: &record,
            fresh: false,
            scope: " bot",
        };
        start.begin(&vps).expect("on record");
        assert_eq!(on_record()["default"].starting.len(), 1);
        start.settle().expect("settled");
        assert_eq!(on_record()["default"], before);
        // The way out of a request for another purchase names where it is.
        let hint = start.other_hint();
        assert!(
            hint.contains("`server`") && hint.contains("[env.default.starting]"),
            "{hint}"
        );
    }

    #[test]
    fn what_to_do_about_a_request_that_stays_never_makes_a_new_one() {
        use super::{StartOf, Stays, stays_hint};
        let new_env = Env::default();
        let deployed = Env {
            host: Some("203.0.113.10".to_owned()),
            ..Env::default()
        };
        let hint = |why, of, env: &Env| stays_hint(why, of, env, "prod", " --env prod bot");
        let every = [
            Stays::Unanswered,
            Stays::InProgress,
            Stays::NotKnown,
            Stays::Exists,
            Stays::Unnamed,
        ];
        for (of, env) in [(StartOf::Server, &new_env), (StartOf::Grpc, &deployed)] {
            for why in every {
                let said = hint(why, of, env);
                // Whatever the answer, the request stays on record, and no
                // way on makes a new one or tries another region: either
                // would buy a second.
                assert!(said.contains("stays on record"), "{why:?}: {said}");
                for wrong in ["new request", "new one", "new key", "region"] {
                    assert!(!said.contains(wrong), "{why:?} says {wrong}: {said}");
                }
            }
            // An outcome left open: the same command sends the same
            // request again.
            for why in [Stays::Unanswered, Stays::InProgress, Stays::NotKnown] {
                let said = hint(why, of, env);
                assert!(said.contains("same command again"), "{why:?}: {said}");
                assert!(said.contains("same request"), "{why:?}: {said}");
            }
            // Still being made: again, shortly.
            assert!(hint(Stays::InProgress, of, env).contains("shortly"));
        }
        // An answer that did not speak for the request: where to look, and
        // how to clear it by hand once nothing was started.
        for why in [Stays::InProgress, Stays::NotKnown] {
            let server = hint(why, StartOf::Server, &new_env);
            assert!(
                server.contains("dashboard")
                    && server.contains("remove `server` from [env.prod.starting] in erpc.toml"),
                "{server}"
            );
            // No server on record yet: nothing `status` could reach.
            assert!(!server.contains("erpc worker status"), "{server}");
            let line = hint(why, StartOf::Grpc, &deployed);
            assert!(
                line.contains("dashboard")
                    && line.contains("`erpc worker status --env prod bot`")
                    && line.contains("remove `grpc` from [env.prod.starting]"),
                "{line}"
            );
        }
        // A purchase that exists and is on no record: nothing is sent
        // again. It is looked up, taken up or ended, and the request then
        // removed by hand.
        for why in [Stays::Exists, Stays::Unnamed] {
            let server = hint(why, StartOf::Server, &new_env);
            assert!(!server.contains("same command"), "{server}");
            assert!(
                server.contains("account's servers")
                    && server.contains("`erpc ai`")
                    && server
                        .contains("`erpc worker deploy --vps <ID> --env prod bot` takes one up")
                    && server
                        .contains("Then remove `server` from [env.prod.starting] in erpc.toml"),
                "{server}"
            );
            let line = hint(why, StartOf::Grpc, &deployed);
            assert!(
                !line.contains("same command") && !line.contains("--vps"),
                "{line}"
            );
            assert!(
                line.contains("account's lines")
                    && line.contains("cannot take up a line that is not on record")
                    && line.contains("remove `grpc` from [env.prod.starting]"),
                "{line}"
            );
        }
        // The conflict answered to a request sent again leads with what it
        // most likely means.
        assert!(
            hint(Stays::Exists, StartOf::Server, &new_env)
                .starts_with("the server may well have been started by the earlier request")
        );
        assert!(
            hint(Stays::Exists, StartOf::Grpc, &deployed)
                .starts_with("the line may well have been started by the earlier request")
        );
        // An inventory environment keeps the request in its item.
        let inventory = Env {
            inventory: Some(erpc_worker::manifest::Inventory {
                vault: OP_VAULT.to_owned(),
            }),
            ..deployed
        };
        for why in [Stays::NotKnown, Stays::Exists] {
            assert!(hint(why, StartOf::Grpc, &inventory).contains("1Password item"));
        }
    }

    #[test]
    fn a_line_named_goes_on_record_and_its_request_off_it_in_one_write() {
        use super::{EnvRecord, LineRecord as _, LineStart, StartOf, StartRecord as _};
        use erpc_worker::manifest::Manifest;
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("erpc.toml");
        std::fs::write(&path, "name = \"bot\"\nchain = \"solana\"\n").expect("write");
        let record = EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let on_record = || Manifest::load(&path).expect("valid").env["default"].clone();
        let named = RefCell::new(Vec::new());
        let mut env = Env {
            host: Some("203.0.113.10".to_owned()),
            // A VPS start an earlier run left: not this start's to touch.
            starting: [(StartOf::Server, request("vps", Some("tokyo"), None))].into(),
            ..Env::default()
        };
        let grpc = request("grpc", None, Some("203.0.113.10"));
        let mut start = LineStart {
            kind: LineKind::Grpc,
            env: &mut env,
            record: &record,
            on_record: &named,
            scope: " bot",
        };
        start.begin(&grpc).expect("on record");
        assert_eq!(on_record().starting[&StartOf::Grpc], grpc);
        assert!(on_record().lines.is_empty());
        // user-api names the line: it is on record, and the request is not.
        start.named("100002").expect("named");
        let kept = on_record();
        assert_eq!(kept.lines.len(), 1);
        assert_eq!(kept.lines[0].id, "100002");
        assert!(kept.lines[0].is_pending());
        assert_eq!(
            kept.starting.keys().copied().collect::<Vec<_>>(),
            [StartOf::Server]
        );
        assert_eq!(*named.borrow(), ["gRPC line 100002"]);
        // A refusal takes only its own request off.
        let shreds = request("shreds-shared", None, Some("203.0.113.10"));
        let mut start = LineStart {
            kind: LineKind::Shreds,
            env: &mut env,
            record: &record,
            on_record: &named,
            scope: " bot",
        };
        start.begin(&shreds).expect("on record");
        assert_eq!(on_record().starting.len(), 2);
        start.settle().expect("settled");
        assert_eq!(on_record(), kept);
        assert_eq!(env, kept);
    }

    /// A UDP Forwarding line's start is kept as the others are, under
    /// `udp`: in erpc.toml from before its request leaves, until user-api
    /// names the line. Its request names no region and no address (the
    /// start route takes none), so a deploy that asks for another port or
    /// region sends the same request again, and never buys a second line.
    #[test]
    fn a_udp_lines_start_is_on_record_under_its_own_key_and_sent_again_as_it_was() {
        use super::{EnvRecord, LineRecord as _, LineStart, StartOf, StartRecord as _};
        use erpc_core::i18n::Lang;
        use erpc_worker::manifest::Manifest;
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("erpc.toml");
        std::fs::write(&path, "name = \"bot\"\nchain = \"solana\"\n").expect("write");
        let record = EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let on_record = || Manifest::load(&path).expect("valid").env["default"].clone();
        let named = RefCell::new(Vec::new());
        let mut env = Env {
            host: Some("203.0.113.10".to_owned()),
            ..Env::default()
        };
        let udp = request("udp-forwarding", None, None);
        let mut start = LineStart {
            kind: LineKind::Udp,
            env: &mut env,
            record: &record,
            on_record: &named,
            scope: " bot",
        };
        start.begin(&udp).expect("on record");
        let text = std::fs::read_to_string(&path).expect("erpc.toml");
        assert!(
            text.contains("[env.default.starting]\nudp = { key = "),
            "{text}"
        );
        assert_eq!(on_record().starting[&StartOf::Udp], udp);
        assert_eq!(start.pending(), Some(udp.clone()));
        // Asked again with another port or region: the same purchase.
        assert!(udp.same_purchase(&request("udp-forwarding", None, None)));
        assert!(!udp.same_purchase(&request("udp-forwarding-premium", None, None)));
        // Not asked for by this command: left as it is, and said.
        let written = on_record();
        let left = super::starts_left(&written, &[(LineKind::Grpc, None)]);
        assert_eq!(
            left.iter().map(|(of, _)| *of).collect::<Vec<_>>(),
            [StartOf::Udp]
        );
        let said = super::starts_left_said(Lang::En, &left, &written, "default");
        assert!(
            said[0].contains("udp-forwarding prod_One")
                && said[0].contains("remove `udp` from [env.default.starting]"),
            "{said:?}"
        );
        assert!(super::starts_left(&written, &[(LineKind::Udp, None)]).is_empty());
        // user-api names the line: on record, pending, and the request off.
        start.named("100004").expect("named");
        let kept = on_record();
        assert!(kept.starting.is_empty());
        assert_eq!(
            (kept.lines[0].kind, kept.lines[0].id.as_str()),
            (LineKind::Udp, "100004")
        );
        assert!(kept.lines[0].is_pending());
        assert_eq!(*named.borrow(), ["UDP Forwarding line 100004"]);
    }

    #[test]
    fn a_start_left_by_an_earlier_run_is_said_when_the_command_does_not_ask_for_it() {
        use super::StartOf;
        use erpc_core::i18n::Lang;
        let env = Env {
            starting: [
                (StartOf::Server, request("vps", Some("amsterdam"), None)),
                (StartOf::Grpc, request("grpc", None, Some("203.0.113.10"))),
            ]
            .into(),
            ..Env::default()
        };
        // --grpc carries on with the line's; the server's is not asked for
        // (a VPS bought by this run has left the record by now).
        let left = super::starts_left(&env, &[(LineKind::Grpc, None)]);
        assert_eq!(
            left.iter().map(|(of, _)| *of).collect::<Vec<_>>(),
            [StartOf::Server]
        );
        let said = super::starts_left_said(Lang::En, &left, &env, "prod");
        assert_eq!(said.len(), 1);
        assert!(
            said[0].contains("vps prod_One (amsterdam)")
                && said[0].contains("remove `server` from [env.prod.starting] in erpc.toml"),
            "{said:?}"
        );
        // No line asked for: both are left, and said.
        assert_eq!(super::starts_left(&env, &[]).len(), 2);
        // An inventory environment keeps them in its 1Password item.
        let inventory = Env {
            inventory: Some(erpc_worker::manifest::Inventory {
                vault: OP_VAULT.to_owned(),
            }),
            ..env
        };
        let left = super::starts_left(&inventory, &[]);
        let said = super::starts_left_said(Lang::En, &left, &inventory, "prod");
        assert!(said[0].contains("1Password item"), "{said:?}");
        // Nothing left: nothing said.
        assert!(super::starts_left(&Env::default(), &[]).is_empty());
    }

    #[test]
    fn lines_to_forget_are_all_on_record_or_none_is_taken() {
        let line = |id: &str| Line {
            kind: LineKind::Grpc,
            id: id.to_owned(),
            endpoint: String::new(),
            hourly: true,
            sources: Vec::new(),
        };
        let mut env = Env {
            lines: vec![line("100002"), line("100003")],
            ..Env::default()
        };
        let asked = ["100002".to_owned(), "100009".to_owned()];
        assert!(super::take_lines(&mut env, &asked).is_err());
        assert_eq!(env.lines.len(), 2);
        let gone = super::take_lines(&mut env, &["100002".to_owned()]).expect("on record");
        assert_eq!(gone.len(), 1);
        assert_eq!(env.lines, [line("100003")]);
        assert!(super::say_forgotten(&gone).is_some_and(|s| s.contains("100002 leaves")));
        assert!(
            super::take_lines(&mut env, &[])
                .expect("nothing")
                .is_empty()
        );
        assert!(super::say_forgotten(&[]).is_none());
    }

    #[test]
    fn a_line_on_record_is_bought_again_only_once_nothing_is_charged_for_it() {
        use super::{LineNext, WaitWhy};
        let on_records = [
            None,
            Some((false, false)),
            Some((false, true)),
            Some((true, false)),
            Some((true, true)),
        ];
        for kind in [LineKind::Grpc, LineKind::Shreds, LineKind::Unlimited] {
            for on_record in on_records {
                for listed in [false, true] {
                    for charged in [false, true] {
                        let next = LineNext::of(kind, on_record, listed, charged);
                        // Forgotten only when hourly, seen with its endpoint
                        // before, and shown by neither.
                        let forget = on_record == Some((true, false)) && !listed && !charged;
                        assert_eq!(
                            next == LineNext::Forget,
                            forget,
                            "{kind:?} {on_record:?} {listed} {charged}"
                        );
                        if matches!(on_record, Some((true, _))) && next == LineNext::TakeUp {
                            assert!(listed && charged);
                        }
                        if on_record.is_none() {
                            assert_eq!(next, LineNext::Buy);
                        }
                    }
                }
            }
        }
        let grpc =
            |on_record, listed, charged| LineNext::of(LineKind::Grpc, on_record, listed, charged);
        assert_eq!(
            grpc(Some((true, true)), false, false),
            LineNext::Wait(WaitWhy::NotSeenYet)
        );
        assert_eq!(
            grpc(Some((true, false)), true, false),
            LineNext::Wait(WaitWhy::NotYetCharged)
        );
        assert_eq!(
            grpc(Some((true, true)), false, true),
            LineNext::Wait(WaitWhy::SettingUp)
        );
        assert_eq!(
            grpc(Some((false, false)), false, false),
            LineNext::Wait(WaitWhy::Unbilled)
        );
    }

    #[test]
    fn a_udp_line_never_pointed_at_the_server_is_taken_up_once_listed() {
        use super::{LineNext, WaitWhy};
        let udp =
            |on_record, listed, charged| LineNext::of(LineKind::Udp, on_record, listed, charged);
        // Pointing it at the server is what taking it up does, and what
        // makes Premium charged: listed is enough, charged or not.
        assert_eq!(udp(Some((true, true)), true, false), LineNext::TakeUp);
        assert_eq!(udp(Some((true, true)), true, true), LineNext::TakeUp);
        assert_eq!(udp(Some((false, true)), true, false), LineNext::TakeUp);
        assert_eq!(
            udp(Some((true, true)), false, false),
            LineNext::Wait(WaitWhy::NotSeenYet)
        );
        assert_eq!(
            udp(Some((true, true)), false, true),
            LineNext::Wait(WaitWhy::SettingUp)
        );
        // Once pointed, it goes by the rule the other kinds go by.
        assert_eq!(
            udp(Some((true, false)), true, false),
            LineNext::Wait(WaitWhy::NotYetCharged)
        );
        assert_eq!(udp(Some((true, false)), true, true), LineNext::TakeUp);
        assert_eq!(udp(Some((true, false)), false, false), LineNext::Forget);
        assert_eq!(udp(None, false, false), LineNext::Buy);
    }

    #[test]
    fn a_udp_line_sends_to_the_port_asked_else_the_one_on_record_else_the_default() {
        let ip: std::net::Ipv4Addr = "203.0.113.10".parse().expect("ip");
        let at = super::Where::default();
        let on_record = Line {
            kind: LineKind::Udp,
            id: "7".to_owned(),
            endpoint: "0.0.0.0:20000".to_owned(),
            hourly: true,
            sources: Vec::new(),
        };
        let target = super::line_target(LineKind::Udp, &at, ip, Some("tokyo"), &[]);
        assert_eq!(
            (target.ip, target.udp_port, target.region.as_deref()),
            (ip, Some(10001), Some("tokyo"))
        );
        let target = super::line_target(
            LineKind::Udp,
            &at,
            ip,
            Some("tokyo"),
            std::slice::from_ref(&on_record),
        );
        assert_eq!(target.udp_port, Some(20000));
        let asked = super::Where {
            udp_port: Some(30000),
            udp_region: Some("dublin".to_owned()),
            ..super::Where::default()
        };
        let target = super::line_target(LineKind::Udp, &asked, ip, Some("tokyo"), &[on_record]);
        assert_eq!(
            (target.udp_port, target.region.as_deref()),
            (Some(30000), Some("dublin"))
        );
        // A --host server has no region on record: the line needs --udp-region.
        assert!(
            super::line_target(LineKind::Udp, &at, ip, None, &[])
                .region
                .is_none()
        );
        // The other kinds are for the server's region, and send to no port.
        let other = super::line_target(LineKind::Unlimited, &asked, ip, Some("tokyo"), &[]);
        assert_eq!(
            (other.udp_port, other.region.as_deref()),
            (None, Some("tokyo"))
        );
    }

    /// A server UDP Forwarding cannot send to is refused before anything
    /// is bought: user-api would refuse to point the line there after a
    /// Standard line was started and charged. (The documentation ranges
    /// are among those refused, so a public resolver's address stands for
    /// a public one.)
    #[test]
    fn a_server_without_a_public_ipv4_address_takes_no_udp_line() {
        assert!(super::udp_public("8.8.8.8".parse().expect("ip")).is_ok());
        for private in [
            "10.0.0.5",
            "192.168.1.2",
            "100.100.1.1",
            "127.0.0.1",
            "203.0.113.10",
        ] {
            let e = super::udp_public(private.parse().expect("ip")).expect_err(private);
            assert!(e.message.contains(private), "{}", e.message);
            assert!(
                e.hint
                    .as_deref()
                    .is_some_and(|h| h.contains("100.64.0.0/10")),
                "{:?}",
                e.hint
            );
        }
    }

    /// The region a UDP line would send from is known before anything is
    /// bought wherever the deploy decides the server itself: refused then
    /// (a mistyped region, sydney, a server of one's own with no region),
    /// nothing is charged. A VPS named with `--vps` is checked once it is
    /// read, before any line is started.
    #[test]
    fn the_udp_region_is_decided_before_anything_is_bought() {
        use erpc_worker::manifest::{Resource, ResourceKind};
        let region = |at: &super::Where, env: &Env| super::udp_region_before(at, env);
        let none = Env::default();
        let asked = super::Where {
            udp_region: Some("tokio".to_owned()),
            ..super::Where::default()
        };
        // --udp-region, whatever the server: checked against the product.
        assert_eq!(
            region(&asked, &none).expect("asked").as_deref(),
            Some("tokio")
        );
        // A new VPS: its --region, else the nearest.
        let sydney = super::Where {
            new_vps: true,
            region: Some("sydney".to_owned()),
            ..super::Where::default()
        };
        assert_eq!(
            region(&sydney, &none).expect("new").as_deref(),
            Some("sydney")
        );
        let nearest = super::Where {
            new_vps: true,
            ..super::Where::default()
        };
        assert_eq!(
            region(&nearest, &none).expect("new").as_deref(),
            Some(crate::worker::vps::nearest_region())
        );
        // A server of one's own: no region erpc knows.
        let own = super::Where {
            host: Some("203.0.113.10".to_owned()),
            ..super::Where::default()
        };
        assert!(region(&own, &none).is_err());
        let own_on_record = Env {
            host: Some("203.0.113.10".to_owned()),
            ..Env::default()
        };
        assert!(region(&super::Where::default(), &own_on_record).is_err());
        // An ERPC server on record: its region.
        let vps = Env {
            host: Some("203.0.113.10".to_owned()),
            resource: Some(Resource {
                kind: ResourceKind::Vps,
                id: "100001".to_owned(),
                region: Some("frankfurt".to_owned()),
                hourly: true,
            }),
            ..Env::default()
        };
        assert_eq!(
            region(&super::Where::default(), &vps)
                .expect("on record")
                .as_deref(),
            Some("frankfurt")
        );
        // --vps: read with it, checked later; and nothing asked yet.
        let named = super::Where {
            vps: Some(100_001),
            ..super::Where::default()
        };
        assert_eq!(region(&named, &none).expect("later"), None);
        assert_eq!(
            region(&super::Where::default(), &none).expect("picked"),
            None
        );
    }

    #[test]
    fn a_udp_port_the_server_has_in_use_is_refused() {
        let ports = |run| super::Ports {
            ssh: 22,
            run,
            others_udp: vec![("other-prod".to_owned(), 10002)],
        };
        assert!(super::udp_port_free(10001, &ports(Some(3000))).is_ok());
        assert!(super::udp_port_free(10001, &ports(None)).is_ok());
        let ssh = super::udp_port_free(22, &ports(None)).expect_err("the SSH port");
        assert!(ssh.message.contains("SSH"), "{}", ssh.message);
        let app = super::udp_port_free(3000, &ports(Some(3000))).expect_err("the app's port");
        assert!(app.message.contains("run.port"), "{}", app.message);
        assert!(app.hint.is_some_and(|h| h.contains("--udp-port")));
        // Another worker on the server receives on it already.
        let other = super::udp_port_free(10002, &ports(None)).expect_err("another worker's");
        assert!(
            other.message.contains("10002") && other.message.contains("other-prod"),
            "{}",
            other.message
        );
        assert!(other.hint.is_some_and(|h| h.contains("--udp-port")));
    }

    #[test]
    fn the_address_checked_before_buying_is_the_one_the_deploy_uses() {
        let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().ok();
        let own = super::Where {
            host: Some("10.0.0.5".to_owned()),
            ..super::Where::default()
        };
        // --host, with nothing on record.
        assert_eq!(
            super::udp_host_before(&own, &Env::default()),
            ip("10.0.0.5")
        );
        // The record's address first, as server() takes it.
        let recorded = Env {
            host: Some("203.0.113.10".to_owned()),
            ..Env::default()
        };
        assert_eq!(super::udp_host_before(&own, &recorded), ip("203.0.113.10"));
        // A VPS on record and not yet reached is the server, whatever
        // --host says: its address is checked once it is known.
        let pending = Env {
            resource: Some(bought()),
            ..Env::default()
        };
        assert_eq!(super::udp_host_before(&own, &pending), None);
        // A host name is not judged.
        let named = super::Where {
            host: Some("bot.example.invalid".to_owned()),
            ..super::Where::default()
        };
        assert_eq!(super::udp_host_before(&named, &Env::default()), None);
    }

    /// The UDP step's refusals are asked before the first line is started:
    /// asked at the UDP step, the lines before it would be left charged.
    /// A stubbed session refuses every start before it is sent, so what
    /// shows the order is which refusal comes: the UDP line's, not the
    /// gRPC line's start, which the catalogue offers a plan for.
    #[tokio::test]
    async fn no_line_is_started_when_the_udp_line_would_be_refused() {
        use crate::worker::vps::stub::{Request, Stub};
        let stub = Stub::serve(|request: &Request| match request.path.as_str() {
            "/v3/billing/hourly-catalog" => (
                200,
                json!({ "families": [
                    { "family": "grpc",
                      "plans": [{ "productId": "prod_grpc", "hourlyCents": 34.0 }] },
                ] }),
            ),
            _ => (200, json!({ "success": true, "data": [] })),
        })
        .await;
        let quiet = crate::node::common::Say { quiet: true };
        let (_dir, path) = app_on_disk();
        let record = super::EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let key = HostKey::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        )
        .expect("key");
        let server = |host: &str| super::Server {
            target: erpc_ssh::Target {
                host: host.to_owned(),
                port: 22,
                user: "root".to_owned(),
                host_key: key.clone(),
                identity: erpc_ssh::Identity::File("/nonexistent/key".into()),
            },
            resource: bought(),
        };
        let ports = super::Ports {
            ssh: 22,
            run: Some(3000),
            others_udp: Vec::new(),
        };
        let asked = |udp_port| super::Where {
            lines: vec![(LineKind::Grpc, None), (LineKind::Udp, None)],
            udp_port,
            ..super::Where::default()
        };
        // A server address UDP Forwarding does not send to; the app's own
        // port; a catalogue that offers no UDP plan. The documentation
        // ranges are refused like the rest, so a public resolver stands
        // for a public address.
        for (host, at, says) in [
            ("10.0.0.5", asked(None), "public IPv4"),
            ("8.8.8.8", asked(Some(3000)), "run.port"),
            ("8.8.8.8", asked(None), "no udp-forwarding"),
        ] {
            let on_record = RefCell::new(Vec::new());
            let step = super::Step {
                record: &record,
                on_record: &on_record,
                scope: " --env default",
                say: &quiet,
            };
            let mut env = Env::default();
            let api = stub.api().accepting(true);
            let e = super::lines_with(&api, &at, &ports, &server(host), &mut env, step)
                .await
                .expect_err(says);
            assert!(e.message.contains(says), "{}", e.message);
            assert!(env.lines.is_empty() && on_record.borrow().is_empty());
        }
    }

    /// A UDP Forwarding line on record that ends while the deploy waits
    /// for it: charged no more, so neither named as charged nor said to be
    /// waited for again; its own hint says what is left to do.
    #[tokio::test]
    async fn a_line_cancelled_while_it_is_waited_for_is_not_called_charged() {
        use crate::worker::vps::stub::{Request, Stub};
        // Active through the checks before the lines; cancelled once the
        // credit snapshot, which only the line step reads, has been read.
        let mut snapshot_read = false;
        let stub = Stub::serve(move |request: &Request| match request.path.as_str() {
            "/v3/billing/hourly-catalog" => (
                200,
                json!({ "families": [
                    { "family": "udp-forwarding",
                      "plans": [{ "productId": "prod_standard", "hourlyCents": 69.0 }] },
                ] }),
            ),
            "/v3/user/credit-snapshot" => {
                snapshot_read = true;
                (
                    200,
                    json!({ "message": { "hourlyResources": [
                        { "productType": "one_hop_direct", "userProductId": 7 },
                    ] } }),
                )
            }
            "/v3/udp-forwarding/my" => (
                200,
                json!({ "success": true, "data": [{
                    "id": 7, "productKey": "one_hop_direct",
                    "status": if snapshot_read { "cancelled" } else { "active" },
                    "region": "amsterdam", "destination": "8.8.8.8:10001",
                    "sourceIp": "198.51.100.20",
                }] }),
            ),
            _ => (200, json!({ "success": true, "data": [] })),
        })
        .await;
        let quiet = crate::node::common::Say { quiet: true };
        let (_dir, path) = app_on_disk();
        let record = super::EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let on_record = RefCell::new(vec!["UDP Forwarding line 7".to_owned()]);
        let step = super::Step {
            record: &record,
            on_record: &on_record,
            scope: " --env default",
            say: &quiet,
        };
        let key = HostKey::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        )
        .expect("key");
        // A public resolver stands for a public address: the documentation
        // ranges are refused.
        let server = super::Server {
            target: erpc_ssh::Target {
                host: "8.8.8.8".to_owned(),
                port: 22,
                user: "root".to_owned(),
                host_key: key,
                identity: erpc_ssh::Identity::File("/nonexistent/key".into()),
            },
            resource: bought(),
        };
        let ports = super::Ports {
            ssh: 22,
            run: Some(3000),
            others_udp: Vec::new(),
        };
        let at = super::Where {
            lines: vec![(LineKind::Udp, None)],
            ..super::Where::default()
        };
        let mut env = Env {
            lines: vec![udp_line("0.0.0.0:10001", &["198.51.100.20"])],
            ..Env::default()
        };
        let api = stub.api().accepting(true);
        let e = super::lines_with(&api, &at, &ports, &server, &mut env, step)
            .await
            .expect_err("cancelled");
        assert!(e.message.contains("is cancelled"), "{}", e.message);
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("--forget-line 7") && !hint.contains("charged by the hour"),
            "{hint}"
        );
        assert!(on_record.borrow().is_empty(), "{:?}", on_record.borrow());
    }

    /// What the UDP step would be refused for is asked before the server
    /// is bought, through a session opened only when a UDP line is asked
    /// for.
    #[tokio::test]
    async fn a_udp_line_is_refused_before_anything_is_bought() {
        use crate::worker::vps::stub::{Request, Stub};
        let offers = |udp: bool| {
            let families = if udp {
                json!([{ "family": "udp-forwarding",
                         "plans": [{ "productId": "prod_standard", "hourlyCents": 69.0 }] }])
            } else {
                json!([{ "family": "grpc",
                         "plans": [{ "productId": "prod_grpc", "hourlyCents": 34.0 }] }])
            };
            move |request: &Request| match request.path.as_str() {
                "/v3/billing/hourly-catalog" => (200, json!({ "families": families })),
                _ => (200, json!({ "success": true, "data": [] })),
            }
        };
        let (with_udp, without_udp) = (
            Stub::serve(offers(true)).await,
            Stub::serve(offers(false)).await,
        );
        let udp = |udp_port| super::Where {
            lines: vec![(LineKind::Udp, None)],
            udp_port,
            ..super::Where::default()
        };
        // A public resolver stands for a public address: the documentation
        // ranges are refused.
        let on = |host: &str| Env {
            host: Some(host.to_owned()),
            resource: Some(bought()),
            ..Env::default()
        };
        let check = |at: super::Where, env: Env, stub: &Stub| {
            let api = stub.api().accepting(true);
            async move {
                super::udp_before_buying(&at, &env, Some(3000), " --env default", || async {
                    Ok(api)
                })
                .await
            }
        };
        check(udp(None), on("8.8.8.8"), &with_udp)
            .await
            .expect("nothing to refuse");
        for (at, env, stub, says) in [
            (udp(None), on("10.0.0.5"), &with_udp, "public IPv4"),
            (udp(Some(3000)), on("8.8.8.8"), &with_udp, "run.port"),
            (udp(None), on("8.8.8.8"), &without_udp, "no udp-forwarding"),
        ] {
            let e = check(at, env, stub).await.expect_err(says);
            assert!(e.message.contains(says), "{}", e.message);
        }
        // A new VPS in a region the product does not send from: refused
        // before the VPS is bought there.
        let sydney = super::Where {
            new_vps: true,
            region: Some("sydney".to_owned()),
            ..udp(None)
        };
        let e = check(sydney, Env::default(), &with_udp)
            .await
            .expect_err("sydney");
        assert!(e.message.contains("sydney"), "{}", e.message);
        // No UDP line asked for: no session is opened.
        super::udp_before_buying(
            &super::Where::default(),
            &Env::default(),
            None,
            "",
            || async { panic!("no session is opened") },
        )
        .await
        .expect("nothing asked");
    }

    /// An app on disk that this machine builds with no tool at all: its
    /// `build.prebuilt` binary is one the servers run.
    fn app_built() -> (tempfile::TempDir, super::App) {
        use crate::worker::elf::fixture::{GLIBC_X86_64, X86_64, linked};
        let dir = tempfile::tempdir().expect("a directory");
        std::fs::create_dir(dir.path().join("dist")).expect("dist");
        let binary = linked(X86_64, GLIBC_X86_64, b"\0GLIBC_2.17\0");
        std::fs::write(dir.path().join("dist/bot"), binary).expect("a binary");
        std::fs::write(
            dir.path().join("erpc.toml"),
            "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n\
             [build]\nprebuilt = \"dist/bot\"\n",
        )
        .expect("erpc.toml");
        let app = super::App {
            dir: crate::worker::Dir::at(dir.path()),
            env: "default".to_owned(),
        };
        (dir, app)
    }

    /// What a deploy is asked with in these tests: its environment's facts
    /// kept in erpc.toml (`--inline`), so that no store this machine's erpc
    /// is set up with is consulted.
    fn kept_inline() -> super::Where {
        super::Where {
            inline: true,
            ..super::Where::default()
        }
    }

    /// [`super::before_buying`] for `app` and `at`, with `login` as the
    /// key's check and `api`, when there is one, as the session; asking for
    /// a session where there is none fails the test.
    async fn before_buying(
        app: &super::App,
        at: &super::Where,
        login: Result<(), String>,
        api: Option<super::Api>,
    ) -> Result<super::Ready, crate::cli::error::CliError> {
        let open = move || async move {
            match api {
                Some(api) => Ok(api),
                None => panic!("a session was opened"),
            }
        };
        let ended = async |_: &mut super::Env, _: &crate::worker::EnvRecord<'_>| Ok(());
        super::before_buying(app, at, " --env default", move || login, ended, open).await
    }

    /// The app's directory goes into erpc's index absolute, however the
    /// app was named: `--dir erpc.toml` too, whose parent is empty.
    #[test]
    fn the_index_is_given_the_apps_directory_absolute() {
        // Compared canonical on both sides: on Windows a canonical path
        // carries the `\\?\` prefix a plain one does not.
        let here = std::env::current_dir()
            .and_then(std::fs::canonicalize)
            .expect("a directory");
        let named = |path: &str| super::index_root(std::path::Path::new(path));
        assert_eq!(named("erpc.toml"), here);
        assert_eq!(named("./erpc.toml"), here);
        let dir = tempfile::tempdir().expect("a directory");
        let real = std::fs::canonicalize(dir.path()).expect("absolute");
        assert_eq!(super::index_root(&dir.path().join("erpc.toml")), real);
    }

    /// What `run` takes its app and record from refuses a deploy before
    /// anything is bought, in its order: the key to log in with; a UDP
    /// Forwarding line refused for its port, or its server's address,
    /// before a session is opened; and one refused for its region through
    /// the session. A deploy without a UDP line asks user-api nothing.
    #[tokio::test]
    async fn a_deploy_is_refused_before_anything_is_bought() {
        use crate::worker::vps::stub::{Request, Stub};
        let (_dir, app) = app_built();
        let ready = before_buying(&app, &kept_inline(), Ok(()), None)
            .await
            .expect("ready");
        assert_eq!(
            (ready.m.name.as_str(), ready.id.as_str()),
            ("bot", "bot-default")
        );
        assert_eq!(ready.env_before, Env::default());
        let no_key = before_buying(&app, &kept_inline(), Err("no SSH key".into()), None)
            .await
            .expect_err("no key");
        assert!(no_key.message.contains("no SSH key"), "{}", no_key.message);
        let udp = |more: super::Where| super::Where {
            lines: vec![(LineKind::Udp, None)],
            ..more
        };
        for (at, says) in [
            (
                udp(super::Where {
                    udp_port: Some(3000),
                    ..kept_inline()
                }),
                "run.port",
            ),
            (
                udp(super::Where {
                    host: Some("10.0.0.5".to_owned()),
                    ..kept_inline()
                }),
                "public IPv4",
            ),
        ] {
            let e = before_buying(&app, &at, Ok(()), None)
                .await
                .expect_err(says);
            assert!(e.message.contains(says), "{}", e.message);
        }
        let stub = Stub::serve(|request: &Request| match request.path.as_str() {
            "/v3/billing/hourly-catalog" => (
                200,
                json!({ "families": [
                    { "family": "udp-forwarding",
                      "plans": [{ "productId": "prod_standard", "hourlyCents": 69.0 }] },
                ] }),
            ),
            _ => (200, json!({ "success": true, "data": [] })),
        })
        .await;
        let new_vps = |region: &str| {
            udp(super::Where {
                new_vps: true,
                region: Some(region.to_owned()),
                ..kept_inline()
            })
        };
        let api = || Some(stub.api().accepting(true));
        let e = before_buying(&app, &new_vps("sydney"), Ok(()), api())
            .await
            .expect_err("sydney");
        assert!(e.message.contains("`sydney` is not a"), "{}", e.message);
        before_buying(&app, &new_vps("amsterdam"), Ok(()), api())
            .await
            .expect("amsterdam");
        assert!(stub.asked().iter().all(|asked| asked.starts_with("GET ")));
    }

    /// An app whose erpc.toml has `env` as its `[env.default]`, built as
    /// [`app_built`] makes it.
    fn app_with_env(env: &str) -> (tempfile::TempDir, super::App) {
        let (dir, app) = app_built();
        let path = dir.path().join("erpc.toml");
        let mut toml = std::fs::read_to_string(&path).expect("erpc.toml");
        toml.push_str("[env.default]\n");
        toml.push_str(env);
        std::fs::write(&path, toml).expect("erpc.toml");
        (dir, app)
    }

    /// An hourly UDP Forwarding line on record while no server it reached
    /// is stops the deploy before anything is bought, judged on the record:
    /// a VPS that ended and leaves the record in this run, the record that
    /// run saved (as a deploy run again finds it), and a VPS bought and
    /// never reached. The error names the line, and the hint how to point
    /// it at the server or end it. With a server on record the deploy goes
    /// on, and so it does once the line is forgotten (`--forget-line`).
    #[tokio::test]
    async fn a_udp_line_with_no_server_on_record_stops_the_deploy() {
        const UDP: &str = "lines = [{ kind = \"udp\", id = \"200002\", \
                           endpoint = \"0.0.0.0:10001\", hourly = true }]\n";
        const VPS: &str = "resource = { kind = \"vps\", id = \"100001\", \
                           region = \"frankfurt\", hourly = true }\n";
        let never = || async { panic!("no session is opened") };
        let gone = async |env: &mut super::Env, _: &crate::worker::EnvRecord<'_>| {
            env.resource = None;
            Ok(())
        };
        let stays = async |_: &mut super::Env, _: &crate::worker::EnvRecord<'_>| Ok(());
        let at = kept_inline();
        let stopped = |e: crate::cli::error::CliError| {
            assert!(e.message.contains("200002"), "{}", e.message);
            let hint = e.hint.unwrap_or_default();
            for command in [
                "erpc worker deploy --udp --env default",
                "--forget-line 200002",
                "erpc worker delete --release-server --env default",
            ] {
                assert!(hint.contains(command), "{command}: {hint}");
            }
        };

        // The VPS ends and leaves the record in this run.
        let (_dir, app) = app_with_env(&format!("{VPS}{UDP}"));
        let e = super::before_buying(&app, &at, " --env default", || Ok(()), gone, never)
            .await
            .expect_err("stops");
        stopped(e);
        // The record that run saved, as the next deploy finds it.
        let (_dir, app) = app_with_env(UDP);
        let e = super::before_buying(&app, &at, " --env default", || Ok(()), stays, never)
            .await
            .expect_err("stops again");
        stopped(e);
        // A VPS bought and never reached: the line was not pointed at it.
        let (_dir, app) = app_with_env(&format!("{VPS}{UDP}"));
        let e = super::before_buying(&app, &at, " --env default", || Ok(()), stays, never)
            .await
            .expect_err("stops");
        stopped(e);

        // A server on record: the line sends to it, and the deploy goes on.
        let (_dir, app) = app_with_env(&format!(
            "{VPS}host = \"203.0.113.10\"\nssh_user = \"ubuntu\"\n\
             host_key = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\"\n{UDP}"
        ));
        super::before_buying(&app, &at, " --env default", || Ok(()), stays, never)
            .await
            .expect("a server on record");
        // Forgotten, the line is not the environment's any more.
        let (_dir, app) = app_with_env(UDP);
        let forgotten = super::Where {
            forget_lines: vec!["200002".to_owned()],
            ..kept_inline()
        };
        super::before_buying(&app, &forgotten, " --env default", || Ok(()), stays, never)
            .await
            .expect("forgotten");
    }

    /// With no server on record, only an hourly UDP Forwarding line neither
    /// asked for again (`--udp`) nor forgotten (`--forget-line`) stops a
    /// deploy.
    #[test]
    fn only_an_unasked_hourly_udp_line_with_no_server_stops_a_deploy() {
        let line = |kind, hourly| erpc_worker::manifest::Line {
            kind,
            id: "200002".to_owned(),
            endpoint: "0.0.0.0:10001".to_owned(),
            hourly,
            sources: Vec::new(),
        };
        let env = |lines| Env {
            lines,
            ..Env::default()
        };
        let left = env(vec![line(LineKind::Udp, true)]);
        let stop = |at: &super::Where, env: &Env| super::udp_left_unpointed(env, at, "");
        let e = stop(&super::Where::default(), &left).expect_err("stops");
        assert!(e.message.contains("200002"), "{}", e.message);
        let asked = super::Where {
            lines: vec![(LineKind::Udp, None)],
            ..super::Where::default()
        };
        stop(&asked, &left).expect("pointed at the server");
        let forgotten = super::Where {
            forget_lines: vec!["200002".to_owned()],
            ..super::Where::default()
        };
        stop(&forgotten, &left).expect("forgotten");
        let none = super::Where::default();
        let served = Env {
            host: Some("203.0.113.10".to_owned()),
            ..left.clone()
        };
        stop(&none, &served).expect("a server on record");
        stop(&none, &env(vec![line(LineKind::Udp, false)])).expect("not hourly");
        stop(&none, &env(vec![line(LineKind::Grpc, true)])).expect("no UDP line");
        stop(&none, &Env::default()).expect("no line");
    }

    /// The Rust that would build the app is asked of `rustc` before
    /// anything is bought: an app that needs a newer one than this machine
    /// has is refused there, ahead of its UDP Forwarding line's checks. A
    /// probe that only looked, as `check`'s does, would not find it.
    #[tokio::test]
    async fn a_deploy_asks_the_rust_that_would_build_the_app() {
        let dir = tempfile::tempdir().expect("a directory");
        std::fs::write(
            dir.path().join("erpc.toml"),
            "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n",
        )
        .expect("erpc.toml");
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"bot\"\nversion = \"0.1.0\"\nrust-version = \"99.0\"\n",
        )
        .expect("Cargo.toml");
        let app = super::App {
            dir: crate::worker::Dir::at(dir.path()),
            env: "default".to_owned(),
        };
        let at = super::Where {
            lines: vec![(LineKind::Udp, None)],
            udp_port: Some(3000),
            ..kept_inline()
        };
        let e = before_buying(&app, &at, Ok(()), None)
            .await
            .expect_err("too old a Rust");
        assert!(e.message.contains("99.0"), "{}", e.message);
    }

    /// A VPS picked at the terminal is checked for the UDP Forwarding line
    /// asked for before it is bought: in a region the line's plan does not
    /// send from, the line's refusal comes, and nothing is started.
    #[tokio::test]
    async fn a_vps_picked_at_the_terminal_is_checked_for_its_udp_line_first() {
        use crate::worker::vps::stub::{Request, Stub};
        let stub = Stub::serve(|request: &Request| match request.path.as_str() {
            "/v3/billing/hourly-catalog" => (
                200,
                json!({ "families": [
                    { "family": "udp-forwarding",
                      "plans": [{ "productId": "prod_standard", "hourlyCents": 69.0 }] },
                ] }),
            ),
            _ => (200, json!({ "success": true, "data": [] })),
        })
        .await;
        let quiet = crate::node::common::Say { quiet: true };
        let (_dir, path) = app_on_disk();
        let record = super::EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let start = super::ServerStart {
            env: Env::default(),
            record: &record,
            fresh: true,
            scope: " --env default",
        };
        let on_record = RefCell::new(Vec::new());
        let at = super::Where {
            lines: vec![(LineKind::Udp, None)],
            region: Some("sydney".to_owned()),
            ..super::Where::default()
        };
        let picked = super::buy_picked(
            stub.api().accepting(true),
            &at,
            "amsterdam",
            start,
            &on_record,
            &quiet,
        )
        .await;
        let Err(e) = picked else {
            panic!("bought in sydney");
        };
        assert!(e.message.contains("`sydney` is not a"), "{}", e.message);
        assert_eq!(stub.asked(), ["GET /v3/billing/hourly-catalog"]);
        assert!(on_record.borrow().is_empty());
    }

    /// What becomes of a line whose wait failed, in the order the line step
    /// asks: a UDP Forwarding line cancelled meanwhile first, one this
    /// deploy started included, which is then not offered to be ended; a
    /// line this deploy started is offered to be ended; one from before, or
    /// an Unlimited RPC, is said with what to do, after the hint of the
    /// step that failed.
    #[test]
    fn a_failed_wait_is_decided_in_order_and_keeps_the_steps_own_hint() {
        use super::{AfterWait, after_wait};
        let scope = " --env staging";
        let cancelled = || super::failed(t!("worker_vps.line.udp_cancelled", id = "7"));
        let for_good = || {
            super::failed("could not point UDP Forwarding line 7")
                .hint(t!("worker_vps.line.udp_point_hint_end"))
        };
        let other = || super::failed("not active in time").hint("its own hint");
        for new in [true, false] {
            let decided = after_wait(LineKind::Udp, "7", new, cancelled(), scope);
            assert!(
                matches!(decided, AfterWait::Cancelled(_)),
                "{new}: {decided:?}"
            );
        }
        for kind in [LineKind::Udp, LineKind::Grpc, LineKind::Shreds] {
            let decided = after_wait(kind, "7", true, for_good(), scope);
            assert!(
                matches!(decided, AfterWait::EndStarted(_)),
                "{kind:?}: {decided:?}"
            );
        }
        let AfterWait::Said(e) = after_wait(LineKind::Udp, "7", false, for_good(), scope) else {
            panic!("said");
        };
        let alone = t!("worker_deploy.line.udp_end_alone", id = "7", scope);
        let own = t!("worker_vps.line.udp_point_hint_end");
        assert_eq!(e.hint, Some(format!("{own}\n{alone}")));
        let waiting = t!("worker_deploy.line.still_waiting", id = "7", scope);
        for (kind, new) in [(LineKind::Grpc, false), (LineKind::Unlimited, true)] {
            let AfterWait::Said(e) = after_wait(kind, "7", new, other(), scope) else {
                panic!("{kind:?} said");
            };
            assert_eq!(e.hint, Some(format!("its own hint\n{waiting}")), "{kind:?}");
        }
    }

    /// What became of a line offered to be ended is said after the hint of
    /// the step that failed, which stays: ended; kept, refused for good,
    /// and how to end it alone; or kept, and how to carry on with it.
    #[test]
    fn what_became_of_a_line_offered_to_be_ended_follows_the_steps_own_hint() {
        use super::Ended;
        let scope = " --env staging";
        for (ended, then) in [
            (Ended::Yes, t!("worker_deploy.line.ended", id = "7")),
            (
                Ended::KeptRefused,
                t!("worker_deploy.line.udp_end_alone", id = "7", scope),
            ),
            (
                Ended::Kept,
                t!("worker_deploy.line.not_ended", id = "7", scope),
            ),
        ] {
            let hinted =
                super::end_said(super::failed("x").hint("its own hint"), ended, "7", scope);
            assert_eq!(
                hinted.hint,
                Some(format!("its own hint\n{then}")),
                "{ended:?}"
            );
            let bare = super::end_said(super::failed("x"), ended, "7", scope);
            assert_eq!(bare.hint, Some(then), "{ended:?}");
        }
    }

    /// A pointing refused for good on a line on record: not to be waited
    /// for again, but ended, and the hint says how to end it alone.
    #[tokio::test]
    async fn a_line_refused_for_good_is_not_waited_for_again() {
        use crate::worker::vps::stub::{Request, Stub};
        let stub = Stub::serve(|request: &Request| match request.path.as_str() {
            "/v3/billing/hourly-catalog" => (
                200,
                json!({ "families": [
                    { "family": "udp-forwarding",
                      "plans": [{ "productId": "prod_standard", "hourlyCents": 69.0 }] },
                ] }),
            ),
            "/v3/user/credit-snapshot" => (
                200,
                json!({ "message": { "hourlyResources": [
                    { "productType": "one_hop_direct", "userProductId": 7 },
                ] } }),
            ),
            // Pointed elsewhere: the deploy points it at this server.
            "/v3/udp-forwarding/my" => (
                200,
                json!({ "success": true, "data": [{
                    "id": 7, "productKey": "one_hop_direct", "status": "active",
                    "region": "amsterdam", "destination": "1.1.1.1:10001",
                }] }),
            ),
            "/v3/udp-forwarding/destination" => (
                400,
                json!({ "success": false, "code": "INVALID_DESTINATION",
                        "message": "the destination is not allowed" }),
            ),
            _ => (200, json!({ "success": true, "data": [] })),
        })
        .await;
        let quiet = crate::node::common::Say { quiet: true };
        let (_dir, path) = app_on_disk();
        let record = super::EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let on_record = RefCell::new(Vec::new());
        let step = super::Step {
            record: &record,
            on_record: &on_record,
            scope: " --env default",
            say: &quiet,
        };
        let key = HostKey::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        )
        .expect("key");
        let server = super::Server {
            target: erpc_ssh::Target {
                host: "8.8.8.8".to_owned(),
                port: 22,
                user: "root".to_owned(),
                host_key: key,
                identity: erpc_ssh::Identity::File("/nonexistent/key".into()),
            },
            resource: bought(),
        };
        let ports = super::Ports {
            ssh: 22,
            run: Some(3000),
            others_udp: Vec::new(),
        };
        let at = super::Where {
            lines: vec![(LineKind::Udp, None)],
            ..super::Where::default()
        };
        let mut env = Env {
            lines: vec![udp_line("0.0.0.0:10001", &["198.51.100.20"])],
            ..Env::default()
        };
        let api = stub.api().accepting(true);
        let e = super::lines_with(&api, &at, &ports, &server, &mut env, step)
            .await
            .expect_err("refused");
        assert!(e.message.contains("could not point"), "{}", e.message);
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("comes back the same")
                && hint.contains("`erpc worker deploy --env default --forget-line 7`")
                && !hint.contains("waits for it again"),
            "{hint}"
        );
    }

    /// A line this deploy started, refused for good and not ended: said how
    /// to end it, and not among what the next deploy carries on with.
    #[tokio::test]
    async fn a_started_line_refused_for_good_is_said_how_to_end() {
        use crate::worker::vps::stub::{Request, Stub};
        let stub = Stub::serve(|request: &Request| match request.path.as_str() {
            "/v3/user/credit-snapshot" => (
                200,
                json!({ "message": { "hourlyResources": [
                    { "productType": "one_hop_direct", "userProductId": 7 },
                ] } }),
            ),
            _ => (200, json!({ "success": true, "data": [] })),
        })
        .await;
        let quiet = crate::node::common::Say { quiet: true };
        let (_dir, path) = app_on_disk();
        let record = super::EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let on_record = RefCell::new(vec![
            "VPS 100001".to_owned(),
            "UDP Forwarding line 7".to_owned(),
        ]);
        let step = super::Step {
            record: &record,
            on_record: &on_record,
            scope: " --env staging",
            say: &quiet,
        };
        let mut env = Env {
            lines: vec![udp_line("", &[])],
            ..Env::default()
        };
        let refused = super::failed("could not point UDP Forwarding line 7")
            .hint(t!("worker_vps.line.udp_point_hint_end"));
        let e =
            super::end_started(&stub.api(), (LineKind::Udp, "7"), &mut env, step, refused).await;
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("stays charged by the hour until it is ended")
                && hint.contains("`erpc worker deploy --env staging --forget-line 7`")
                && !hint.contains("deploy again"),
            "{hint}"
        );
        assert_eq!(*on_record.borrow(), ["VPS 100001"]);
    }

    #[test]
    fn a_hint_added_keeps_the_one_before_it() {
        let bare = super::and_hint(super::failed("x"), "then".to_owned());
        assert_eq!(bare.hint.as_deref(), Some("then"));
        let hinted = super::and_hint(super::failed("x").hint("first"), "then".to_owned());
        assert_eq!(hinted.hint.as_deref(), Some("first\nthen"));
        // A line cancelled while it was waited for is told apart: nothing
        // is said of waiting for it again.
        let cancelled = super::failed(t!("worker_vps.line.udp_cancelled", id = "7"));
        assert!(crate::worker::vps::is_udp_cancelled(&cancelled, "7"));
        assert!(!crate::worker::vps::is_udp_cancelled(&cancelled, "8"));
        assert!(!crate::worker::vps::is_udp_cancelled(
            &super::failed("x"),
            "7"
        ));
    }

    #[test]
    fn the_other_workers_udp_ports_are_read_from_the_servers_openings() {
        // `firewall-show`, as the agent answers it.
        let shown = json!({
            "ok": true,
            "table": "table inet erpc_worker { }",
            "openings": {
                "bot-default": { "port": 0, "allow": [],
                    "udp": { "port": 10001, "allow": ["198.51.100.20"] } },
                "other-prod": { "port": 3000, "allow": ["203.0.113.0/24"],
                    "udp": { "port": 10002, "allow": [], "any_source": true } },
                "web-prod": { "port": 8080, "allow": ["203.0.113.0/24"] },
            },
            "pending": false,
        });
        // This worker's own port is not another's.
        assert_eq!(
            super::others_udp_ports(&shown, "bot-default"),
            [("other-prod".to_owned(), 10002)]
        );
        assert_eq!(super::others_udp_ports(&shown, "new-default").len(), 2);
        // A server with no worker firewall yet, or an answer that is not
        // one, names none.
        assert!(super::others_udp_ports(&json!({ "openings": {} }), "bot-default").is_empty());
        assert!(super::others_udp_ports(&json!({ "ok": false }), "bot-default").is_empty());
        let odd = json!({ "openings": { "x-prod": { "udp": { "port": 70000 } } } });
        assert!(super::others_udp_ports(&odd, "bot-default").is_empty());
    }

    fn udp_line(endpoint: &str, sources: &[&str]) -> Line {
        Line {
            kind: LineKind::Udp,
            id: "7".to_owned(),
            endpoint: endpoint.to_owned(),
            hourly: true,
            sources: sources.iter().map(|s| s.parse().expect("ip")).collect(),
        }
    }

    #[test]
    fn the_summary_names_a_udp_line_whatever_state_it_is_in() {
        use erpc_core::i18n::Lang;
        let said = |line: &Line, any_source, charged| {
            super::udp_line_said(Lang::En, line, any_source, charged, " --env staging")
        };
        // Pointed, with its sources.
        let pointed = said(&udp_line("0.0.0.0:10001", &["198.51.100.20"]), false, None);
        assert!(
            pointed.contains("UDP port 10001 from 198.51.100.20")
                && pointed.contains("charged by the hour"),
            "{pointed}"
        );
        // Pointed, and user-api names no source: closed, with how to open
        // it, and charged all the same.
        let unnamed = udp_line("0.0.0.0:10001", &[]);
        let closed = said(&unnamed, false, None);
        assert!(
            closed.contains("UDP port 10001, which stays closed")
                && closed.contains("`erpc worker deploy --env staging --udp --udp-any-source`")
                && closed.contains("charged by the hour"),
            "{closed}"
        );
        let open = said(&unnamed, true, None);
        assert!(
            open.contains("open to any IPv4 address, as --udp-any-source asked"),
            "{open}"
        );
        // Pending: never pointed at the server. It was left out before,
        // though a Standard line is charged from its start.
        let pending = udp_line("", &[]);
        let charged = said(&pending, false, Some(true));
        assert!(
            charged.contains("UDP Forwarding line 7")
                && charged.contains("pointed at no server")
                && charged.contains("it is charged by the hour until")
                && charged.contains("`erpc worker delete --release-server --env staging`")
                && charged.contains("`erpc worker deploy --env staging --udp`"),
            "{charged}"
        );
        let uncharged = said(&pending, false, Some(false));
        assert!(uncharged.contains("do not show it now"), "{uncharged}");
        // The charges could not be read: what each product is charged.
        let unknown = said(&pending, false, None);
        assert!(
            unknown.contains("A Standard line is charged by the hour from its start"),
            "{unknown}"
        );
        // Said in the run's language, as the rest of the summary is.
        let japanese = super::udp_line_said(Lang::Ja, &pending, false, Some(true), "");
        assert_ne!(
            japanese,
            super::udp_line_said(Lang::En, &pending, false, Some(true), "")
        );
        assert!(!japanese.contains('{'), "{japanese}");
    }

    /// An app's erpc.toml in a directory of its own, for a record to be
    /// written to.
    fn app_on_disk() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("erpc.toml");
        std::fs::write(&path, "name = \"bot\"\nchain = \"solana\"\n").expect("erpc.toml");
        (dir, path)
    }

    #[tokio::test]
    async fn the_sources_on_record_follow_what_user_api_lists_and_stay_when_it_cannot_be_read() {
        use crate::worker::vps::stub::{Request, Stub};
        let quiet = crate::node::common::Say { quiet: true };
        let (_dir, path) = app_on_disk();
        let record = super::EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let on_record = || Env {
            host: Some("203.0.113.10".to_owned()),
            lines: vec![udp_line("0.0.0.0:10001", &["198.51.100.20"])],
            ..Env::default()
        };
        let listing = |row: Value| async move {
            Stub::serve(move |request: &Request| match request.path.as_str() {
                "/v3/udp-forwarding/my" => (200, json!({ "success": true, "data": [row] })),
                _ => (200, json!({ "success": true, "data": [] })),
            })
            .await
        };

        // ERPC moved the line: the record follows, in memory and on disk.
        let moved = listing(json!({ "id": 7, "sourceIp": "198.51.100.30" })).await;
        let mut env = on_record();
        super::refresh_udp_sources(|| async { Ok(moved.api()) }, &mut env, &record, &quiet)
            .await
            .expect("read");
        assert_eq!(
            env.lines[0].sources,
            ["198.51.100.30".parse::<std::net::Ipv4Addr>().expect("ip")]
        );
        let written = std::fs::read_to_string(&path).expect("erpc.toml");
        assert!(written.contains("198.51.100.30"), "{written}");
        assert_eq!(moved.asked(), ["GET /v3/udp-forwarding/my"]);

        // A source that is not an IPv4 address, a line user-api no longer
        // lists, a list it refuses, and no session at all: each is said,
        // and the record stays as it was.
        let odd = listing(json!({ "id": 7, "sourceIp": "2001:db8::30" })).await;
        let unlisted = listing(json!({ "id": 8, "sourceIp": "198.51.100.31" })).await;
        let refused = Stub::serve(|_: &Request| (403, json!({ "message": "not open" }))).await;
        for stub in [&odd, &unlisted, &refused] {
            let mut env = on_record();
            super::refresh_udp_sources(|| async { Ok(stub.api()) }, &mut env, &record, &quiet)
                .await
                .expect("goes on");
            assert_eq!(env, on_record());
        }
        let mut env = on_record();
        let no_session = || async { Err(super::failed("there is no session")) };
        super::refresh_udp_sources(no_session, &mut env, &record, &quiet)
            .await
            .expect("goes on");
        assert_eq!(env, on_record());

        // A pending line has nothing to read: no session is asked for.
        let mut pending = Env {
            lines: vec![udp_line("", &[])],
            ..Env::default()
        };
        let never = || async { panic!("no session is needed for a pending line") };
        super::refresh_udp_sources(never, &mut pending, &record, &quiet)
            .await
            .expect("nothing to do");
    }

    #[tokio::test]
    async fn a_line_started_and_then_not_seen_is_offered_to_be_ended() {
        use crate::worker::vps::stub::{Request, Stub};
        // The step after the start failed. Ending the line is the
        // person's to confirm, and a stubbed session has no one to ask:
        // the offer is made, nothing is ended, and the hint says how to
        // carry on with the line that stays on record.
        let stub = Stub::serve(|request: &Request| match request.path.as_str() {
            "/v3/user/credit-snapshot" => (
                200,
                json!({ "message": { "hourlyResources": [
                    { "productType": "one_hop_direct", "userProductId": 7 },
                ] } }),
            ),
            _ => (200, json!({ "success": true, "data": [] })),
        })
        .await;
        let quiet = crate::node::common::Say { quiet: true };
        let (_dir, path) = app_on_disk();
        let record = super::EnvRecord {
            path: &path,
            app: "bot",
            env: "default",
        };
        let on_record = RefCell::new(vec!["UDP Forwarding line 7".to_owned()]);
        let step = super::Step {
            record: &record,
            on_record: &on_record,
            scope: " --env staging",
            say: &quiet,
        };
        let mut env = Env {
            lines: vec![udp_line("", &[])],
            ..Env::default()
        };
        let failed = super::failed("UDP Forwarding line 7 started, and user-api does not list it");
        let e = super::end_started(&stub.api(), (LineKind::Udp, "7"), &mut env, step, failed).await;
        assert!(e.message.contains("does not list it"), "{}", e.message);
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("line 7 was not ended")
                && hint.contains("`erpc worker delete --release-server --env staging`"),
            "{hint}"
        );
        // Which product to end was looked up: the end got as far as asking.
        assert!(
            stub.asked()
                .contains(&"GET /v3/user/credit-snapshot".to_owned()),
            "{:?}",
            stub.asked()
        );
        // Not ended: still on record, and still named as charged.
        assert_eq!(env.lines.len(), 1);
        assert_eq!(*on_record.borrow(), ["UDP Forwarding line 7"]);
    }

    #[test]
    fn the_agent_named_comes_first_then_the_one_erpc_carries() {
        assert_eq!(AgentSource::choose(true, true), AgentSource::Named);
        assert_eq!(AgentSource::choose(true, false), AgentSource::Named);
        assert_eq!(AgentSource::choose(false, true), AgentSource::Embedded);
        assert_eq!(AgentSource::choose(false, false), AgentSource::Beside);
    }
    use erpc_worker::manifest::{Env, Line, LineKind, Resource, ResourceKind};
    use serde_json::{Value, json};

    #[test]
    fn a_vps_bought_and_not_yet_reached_is_taken_up() {
        let bought = Env {
            resource: Some(Resource {
                kind: ResourceKind::Vps,
                id: "100001".to_owned(),
                region: Some("amsterdam".to_owned()),
                hourly: true,
            }),
            ..Env::default()
        };
        assert_eq!(
            super::pending_vps(Some(&bought)).map(|r| r.id.as_str()),
            Some("100001")
        );
        // Reached already: the server is the one the environment names.
        let reached = Env {
            host: Some("203.0.113.10".to_owned()),
            ..bought.clone()
        };
        assert!(super::pending_vps(Some(&reached)).is_none());
        // A server of one's own has no resource to take up.
        assert!(super::pending_vps(Some(&Env::default())).is_none());
        assert!(super::pending_vps(None).is_none());
    }

    #[test]
    fn what_deploy_says_is_said_in_the_language_of_the_run_and_json_in_english() {
        use crate::cli::i18n::speaking;
        use erpc_core::i18n::Lang;
        let english = super::line_name(LineKind::Grpc, "100002");
        assert_eq!(english, "gRPC line 100002");
        let forgotten = |n: usize| {
            let lines: Vec<Line> = (0..n)
                .map(|i| Line {
                    kind: LineKind::Grpc,
                    id: format!("10000{i}"),
                    endpoint: String::new(),
                    hourly: true,
                    sources: Vec::new(),
                })
                .collect();
            super::say_forgotten(&lines).expect("said")
        };
        for lang in [Lang::Ja, Lang::Ru] {
            let said = speaking(lang, || super::line_name(LineKind::Grpc, "100002"));
            assert_ne!(said, english);
            assert!(said.contains("gRPC") && said.contains("100002"), "{said}");
            let said = speaking(lang, || forgotten(2));
            assert_ne!(said, forgotten(2));
            assert!(!said.contains('{'), "{said}");
            // What `--json` carries stays English whatever the run speaks.
            let json = speaking(lang, || super::line_name_in(Lang::En, LineKind::Grpc, "1"));
            assert_eq!(json, "gRPC line 1");
        }
    }

    #[test]
    fn a_pinned_host_key_round_trips_as_one_openssh_line() {
        let line =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let key = HostKey::parse(line).expect("key");
        assert_eq!(key.to_openssh(), line);
    }

    /// A VPS bought and never reached leaves the record only when it is
    /// missing from the account signed in to and the person, asked with
    /// that account named, says so. With nobody to ask, or a no, the deploy
    /// stops with the way to take it off the record by hand; when the
    /// account has it or cannot be read, nobody is asked and it stays.
    #[test]
    fn a_vps_missing_from_the_account_leaves_the_record_only_on_the_persons_yes() {
        use super::forget_missing;
        use crate::cli::error::Code;
        use crate::worker::vps::OnAccount;
        use std::cell::RefCell;

        let missing = OnAccount::Missing {
            account: "Example Account".to_owned(),
        };
        let asked = RefCell::new(Vec::new());
        let answer = |yes: bool| {
            let asked = &asked;
            move |q: &str| {
                asked.borrow_mut().push(q.to_owned());
                Ok(yes)
            }
        };
        let scope = " --env prod --dir app";
        for seen in [OnAccount::There, OnAccount::Unknown] {
            assert!(!forget_missing(&seen, "100001", scope, true, answer(true)).expect("kept"));
        }
        assert!(asked.borrow().is_empty(), "nobody is asked");

        assert!(forget_missing(&missing, "100001", scope, true, answer(true)).expect("yes"));
        assert!(
            asked.borrow()[0].contains("VPS 100001")
                && asked.borrow()[0].contains("(Example Account)"),
            "{:?}",
            asked.borrow()
        );

        let no = forget_missing(&missing, "100001", scope, true, answer(false)).expect_err("no");
        assert_eq!(no.code, Code::Declined);
        let hint = no.hint.unwrap_or_default();
        assert!(
            hint.contains("`erpc worker delete --release-server --env prod --dir app`"),
            "{hint}"
        );

        let before = asked.borrow().len();
        let nobody =
            forget_missing(&missing, "100001", scope, false, answer(true)).expect_err("nobody");
        assert_eq!(nobody.code, Code::NeedsTerminal);
        assert!(
            nobody.message.contains("(Example Account)"),
            "{}",
            nobody.message
        );
        assert_eq!(asked.borrow().len(), before, "nobody to ask is never asked");

        let broken = forget_missing(&missing, "100001", scope, true, |_| {
            Err(super::failed("the terminal went away"))
        });
        assert!(broken.is_err());
    }

    /// The record is rewritten without the VPS only when it is missing and
    /// the person says so; a VPS that is there or not known, or a record
    /// with no VPS bought and never reached, is left as it is, and nobody
    /// is asked. A person is asked only at a terminal and not under
    /// `--json`.
    #[test]
    fn the_record_loses_a_vps_only_when_it_is_missing_and_the_person_says_so() {
        use super::without_missing_vps;
        use crate::worker::vps::OnAccount;
        use crate::worker::vps::can_ask;
        use erpc_worker::manifest::{Env, Resource, ResourceKind};

        let pending = Env {
            resource: Some(Resource {
                kind: ResourceKind::Vps,
                id: "100001".to_owned(),
                region: None,
                hourly: true,
            }),
            ..Env::default()
        };
        let reached = Env {
            host: Some("203.0.113.10".to_owned()),
            ..pending.clone()
        };
        let missing = OnAccount::Missing {
            account: "Example Account".to_owned(),
        };
        let never = |_: &str| -> Result<bool, crate::cli::error::CliError> {
            panic!("nobody is to be asked")
        };
        for seen in [OnAccount::There, OnAccount::Unknown] {
            assert_eq!(
                without_missing_vps(&pending, &seen, "", true, never).expect("kept"),
                None
            );
        }
        assert_eq!(
            without_missing_vps(&reached, &missing, "", true, never).expect("kept"),
            None
        );
        assert_eq!(
            without_missing_vps(&Env::default(), &missing, "", true, never).expect("kept"),
            None
        );
        let without = without_missing_vps(&pending, &missing, "", true, |_| Ok(true))
            .expect("asked")
            .expect("rewritten");
        assert_eq!(without, Env::default());
        assert!(without_missing_vps(&pending, &missing, "", true, |_| Ok(false)).is_err());
        assert!(without_missing_vps(&pending, &missing, "", false, never).is_err());

        assert!(can_ask(false, true));
        assert!(!can_ask(true, true), "--json");
        assert!(!can_ask(false, false), "no terminal");
        assert!(!can_ask(true, false));
    }

    /// Once the account was asked, the record is written without the VPS,
    /// and the deploy goes on with that record, only when it is missing
    /// and the person says so; otherwise nothing is written and the record
    /// the deploy goes on with is the one it had.
    #[test]
    fn the_record_without_the_vps_is_written_and_used_only_after_a_yes() {
        use super::{Asking, record_without_missing};
        use crate::worker::vps::OnAccount;
        use erpc_worker::manifest::{Env, Resource, ResourceKind};
        use std::cell::RefCell;

        let pending = Env {
            resource: Some(Resource {
                kind: ResourceKind::Vps,
                id: "100001".to_owned(),
                region: None,
                hourly: true,
            }),
            ..Env::default()
        };
        let missing = OnAccount::Missing {
            account: "Example Account".to_owned(),
        };
        let quiet = crate::node::common::Say { quiet: true };
        let saved = RefCell::new(Vec::new());
        let save = |env: &Env| {
            saved.borrow_mut().push(env.clone());
            Ok(())
        };
        let yes = || Asking {
            can_ask: true,
            ask: |_: &str| Ok(true),
        };

        let mut env = pending.clone();
        record_without_missing(&mut env, &missing, "", yes(), save, &quiet).expect("dropped");
        assert_eq!(env, Env::default(), "the deploy goes on without it");
        assert_eq!(saved.borrow().as_slice(), [Env::default()]);

        for seen in [OnAccount::There, OnAccount::Unknown] {
            let mut env = pending.clone();
            record_without_missing(&mut env, &seen, "", yes(), save, &quiet).expect("kept");
            assert_eq!(env, pending);
        }
        let mut env = pending.clone();
        let no = Asking {
            can_ask: true,
            ask: |_: &str| Ok(false),
        };
        assert!(record_without_missing(&mut env, &missing, "", no, save, &quiet).is_err());
        assert_eq!(env, pending);
        let mut env = pending.clone();
        let failing = |_: &Env| Err("read-only".to_owned());
        let refused = record_without_missing(&mut env, &missing, "", yes(), failing, &quiet)
            .expect_err("not written");
        assert!(refused.message.contains("read-only"), "{}", refused.message);
        assert_eq!(env, pending, "a record not written is not gone on with");
        assert_eq!(saved.borrow().len(), 1, "only the one yes wrote");
    }
}
