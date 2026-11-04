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
//!    a new hourly one ([`crate::worker_vps`]), or `--host`, chosen and
//!    agreed to now. Its host key is pinned here, or, for a VPS bought or
//!    taken up, once it is up and the build is done (step 3), before
//!    anything connects to it. A VPS bought here
//!    is on record the moment user-api names it, before it is ready, so a
//!    deploy that stops after that leaves it where the next deploy takes it
//!    up and `delete --release-server` ends it.
//! 3. The app is built for the server ([`crate::worker_build`]), while a
//!    VPS bought or taken up gets ready. A build that fails leaves such a
//!    VPS on record, charged, for the next deploy.
//! 4. The agent is installed when its digest differs, its unit written and
//!    started (it starts locked: it has no key).
//! 5. The firewall ([`crate::worker_firewall`]): SSH only from
//!    `firewall.ssh_allow` and the address this deploy comes from, every
//!    other inbound connection dropped but for `run.port` from
//!    `firewall.app_allow`. Each table goes under a rollback timer and is
//!    kept only once a fresh connection gets in.
//! 6. The data lines asked for (`--grpc`, `--shreds`, `--unlimited`): the
//!    one erpc.toml names is taken up again, or a new hourly one is
//!    started for the server, at its price, and waited for. Its endpoint
//!    reaches the app as `GRPC_ENDPOINT`, `SHREDS_ENDPOINT` or
//!    `SOLANA_SEND_RPC_ENDPOINT`.
//! 7. The release is uploaded and installed, its digests checked.
//! 8. The key and the secrets go to the agent's memory.
//! 9. The release is activated: the agent restarts the app from it and
//!    reports it healthy, or the server goes back to the release before.
//! 10. `[env.<name>]` in erpc.toml gets the server, its pinned key, the
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
use erpc_ssh::worker::{Command as Worker, Digest, ReleaseId, UnitId, Verb};
use erpc_ssh::{RemoteCommand, RemotePath, Session, Target};
use erpc_worker::manifest::{
    Env, Firewall, Inventory, Line, LineKind, Manifest, Resource, ResourceKind,
};
use erpc_worker::net::Cidr;
use erpc_worker::server::Launch;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::node_common::{Say, go_ahead};
use crate::worker::{App, EnvRecord, load_env};
use crate::worker_remote::{ctl, ctl_ok, failed, open, unlock_request};
use crate::worker_vps::{self, Api, Server};

/// A `t!` message said in `lang` rather than the run's language: what a
/// command also puts in its `--json` output is English there, for the
/// scripts that read it. `said_in!(lang, t!("area.key", name))`.
macro_rules! said_in {
    ($lang:expr, t!($key:literal $(, $name:ident $(= $value:expr)?)* $(,)?)) => {
        $crate::i18n::CATALOG.text(
            $lang,
            $key,
            &[$((stringify!($name), &$crate::i18n::arg!($name $(= $value)?) as &dyn ::std::fmt::Display)),*],
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
    /// For a new environment: keep its server facts in this 1Password vault.
    pub(crate) vault: Option<String>,
    /// For a new environment: keep its server facts in erpc.toml.
    pub(crate) inline: bool,
    /// Lines on record the operator says are gone: they leave the record
    /// before the lines are looked at.
    pub(crate) forget_lines: Vec<String>,
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
        crate::interrupt::say(&format!(
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
    match crate::worker_secrets::choose(None, at.vault.as_deref()) {
        Ok(crate::worker_secrets::Store::OnePassword { vault }) => Ok(Some(Inventory { vault })),
        // --vault given, and not usable: said, not passed over.
        Err(e) if at.vault.is_some() => Err(CliError::new(Code::Usage, e)),
        _ => Ok(None),
    }
}

/// The data lines asked for: one `env` names and the account still has
/// is taken up again, else a new one is started for `host`. A new line
/// goes into erpc.toml as soon as user-api names its endpoint, before it
/// is active, so a deploy that stops waiting leaves it on record: the next
/// one takes it up, and `delete --release-server` ends it. A new gRPC or
/// Shreds line that does not become active is offered to be ended at once;
/// an Unlimited RPC cannot be ended while it is being set up.
async fn lines(
    asked: &[(LineKind, Option<&str>)],
    server: &Server,
    env: &mut Env,
    record: &EnvRecord<'_>,
    on_record: &RefCell<Vec<String>>,
    scope: &str,
    say: &Say,
) -> Result<(), CliError> {
    let host = &server.target.host;
    let region = server.resource.region.as_deref();
    let ip: Ipv4Addr = host.parse().map_err(|_| {
        failed(t!("worker_deploy.line.not_ipv4", host)).hint(t!("worker_deploy.line.not_ipv4_hint"))
    })?;
    let api = Api::open().await?;
    for &(kind, plan) in asked {
        let (known, next) = line_next(&api, kind, env, record, say).await?;
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
                // On record the moment user-api names it, its endpoint to
                // come: a deploy that stops after that leaves it for the
                // next to take up.
                let mut named = |id: &str| {
                    let pending = Line {
                        kind,
                        id: id.to_owned(),
                        endpoint: String::new(),
                        hourly: true,
                    };
                    keep(env, pending, record)?;
                    on_record.borrow_mut().push(line_name(kind, id));
                    Ok(())
                };
                let id =
                    worker_vps::start_line(&api, kind, ip, region, plan, scope, say, &mut named)
                        .await?;
                let line = worker_vps::first_sight(&api, kind, &id, true, scope).await?;
                keep(env, line, record)?;
                (id, true, true)
            }
        };
        say.line(&t!("worker_deploy.line.waiting", id));
        if kind == LineKind::Unlimited {
            say.line(&t!("worker_deploy.line.unlimited_slow"));
        }
        match worker_vps::wait_line(&api, kind, &id, ip, hourly, say).await {
            Ok(line) => {
                let endpoint = &line.endpoint;
                say.line(&t!("worker_deploy.line.active", id, endpoint));
                keep(env, line, record)?;
            }
            Err(e) if new && kind != LineKind::Unlimited => {
                say.line(&t!("worker_deploy.line.charged", message = e.message));
                let Some(line) = env.lines.iter().find(|l| l.kind == kind).cloned() else {
                    return Err(e);
                };
                return Err(match worker_vps::end_line(&api, &line, say).await {
                    Ok(_) => {
                        env.lines.retain(|l| l.kind != kind);
                        let _ = record.save(env, None);
                        let ended = line_name(kind, &id);
                        on_record.borrow_mut().retain(|w| *w != ended);
                        e.hint(t!("worker_deploy.line.ended", id))
                    }
                    Err(_) => e.hint(t!("worker_deploy.line.not_ended", id, scope)),
                });
            }
            Err(e) => {
                return Err(e.hint(t!("worker_deploy.line.still_waiting", id, scope)));
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
            let listed = worker_vps::line_row(api, kind, &line.id).await?.is_some();
            let charged = worker_vps::is_charged(&worker_vps::charged(api).await?, line);
            LineNext::of(Some((line.hourly, line.is_pending())), listed, charged)
        }
        None => LineNext::of(None, false, false),
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
    /// leaves the record, and one is bought after asking.
    Forget,
    /// None on record: buy one, after asking.
    Buy,
}

impl LineNext {
    /// `on_record` is the line on record, as (billed by the hour, pending:
    /// its endpoint never seen); `None` when there is none.
    const fn of(on_record: Option<(bool, bool)>, listed: bool, charged: bool) -> Self {
        let Some((hourly, pending)) = on_record else {
            return Self::Buy;
        };
        if worker_vps::is_gone((hourly, pending), listed, charged) {
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

/// A data line as it is named to the operator: `gRPC line 100002`.
fn line_name(kind: LineKind, id: &str) -> String {
    line_name_in(crate::i18n::lang(), kind, id)
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
    /// It was bought just now, after the person's yes to its price.
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
            Self::Vps(api, resource) => worker_vps::wait(api, resource, say).await,
        }
    }

    /// The server, once a VPS is up: making it key-only asks about its
    /// host key, so this runs once the build has stopped printing.
    async fn secured(self) -> Result<Server, CliError> {
        match self {
            Self::Ready(server) => Ok(server),
            Self::Vps(api, resource) => worker_vps::secure(&api, &resource).await,
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
/// server but a VPS bought just now, which had its yes at its price.
fn go_ahead_line(server: &Waiting, bought: bool, name: &str, worker: &str) -> Option<String> {
    (!bought).then(|| t!("worker_deploy.target", name, to = server.named(), worker))
}

/// Buys a new hourly VPS and puts it on record at once; the caller waits
/// for it.
async fn buy(
    api: Api,
    at: &Where,
    base: &Env,
    kept: &EnvRecord<'_>,
    on_record: &RefCell<Vec<String>>,
    scope: &str,
    say: &Say,
) -> Result<Waiting, CliError> {
    let resource =
        worker_vps::buy(&api, at.region.as_deref(), at.plan.as_deref(), scope, say).await?;
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
        let target = crate::worker_remote::target(app, env)?;
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
    // before the VPS was ready: taken up rather than bought again.
    if let Some(resource) = pending_vps(m.env.get(env_name)) {
        say.line(&t!("worker_deploy.vps.taking_up", id = resource.id));
        on_record.borrow_mut().push(format!("VPS {}", resource.id));
        let api = Api::open().await?;
        return Ok(found(Waiting::Vps(api, resource.clone()), true, false));
    }
    if let Some(host) = &at.host {
        let port = at.port.unwrap_or(22);
        let host_key =
            crate::node_common::host_key(host, port, None, at.fingerprint.as_deref(), say)
                .map_err(failed)?;
        let (_, identity) = crate::vps_access::login_key().map_err(failed)?;
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
    let api = Api::open().await?;
    if let Some(id) = at.vps {
        return Ok(found(
            Waiting::Ready(worker_vps::existing(&api, id, false).await?),
            true,
            false,
        ));
    }
    if at.new_vps {
        let server = buy(api, at, base, kept, on_record, scope, say).await?;
        return Ok(found(server, true, true));
    }
    if !crate::session::has_terminal() {
        return Err(CliError::new(
            Code::NeedsTerminal,
            t!("worker_deploy.server.no_terminal", env = env_name),
        )
        .hint(t!("worker_deploy.server.no_terminal_hint")));
    }
    let running = worker_vps::running(&api).await?;
    let mut options: Vec<String> = running
        .iter()
        .map(|(id, ip, region, plan)| format!("VPS {id}  {ip}  {region}  {plan}"))
        .collect();
    let region = worker_vps::nearest_region();
    options.push(t!("worker_deploy.server.new_vps", region));
    let question = t!("worker_deploy.server.which");
    let i = crate::prompt::pick(&question, &options, None).map_err(failed)?;
    if let Some((id, ..)) = running.get(i) {
        Ok(found(
            Waiting::Ready(worker_vps::existing(&api, *id, false).await?),
            true,
            false,
        ))
    } else {
        let server = buy(api, at, base, kept, on_record, scope, say).await?;
        Ok(found(server, true, true))
    }
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
    let lang = if json { Lang::En } else { crate::i18n::lang() };
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
                Outcome::Done(crate::ui::decorate(
                    report["text"].as_str().unwrap_or_default(),
                    "🚀",
                ))
            }
        }
        Err(e) => e.into(),
    }
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
    // 1. The app. Every next command a hint names is for this app and
    // environment.
    let scope = app.scope();
    let (path, m) = load_env(app)?;
    let kept = EnvRecord {
        path: &path,
        app: &m.name,
        env: &app.env,
    };
    let asked_lines = at.lines();
    let mut provided: Vec<&str> = asked_lines.iter().map(|(k, _)| k.setting()).collect();
    if let Some(env) = m.env.get(&app.env) {
        provided.extend(env.line_vars().map(|(setting, _)| setting));
    }
    let missing = m.missing_besides(&provided);
    if !missing.is_empty() {
        let (scope, first, settings) = (app.dir.scope(), &missing[0], missing.join(", "));
        let hint = t!("worker_deploy.missing_hint", first, dir_scope = scope);
        return Err(failed(t!("worker_deploy.missing", name = m.name, settings)).hint(hint));
    }
    Launch::for_app(&m, &Env::default()).map_err(failed)?;
    if m.wallet.is_some() {
        crate::worker_secrets::may_read_key().map_err(failed)?;
    }
    let id = UnitId::new(&m.unit_id(&app.env)).map_err(failed)?;
    // Lines to forget are checked now, before anything is built or bought.
    take_lines(
        &mut m.env.get(&app.env).cloned().unwrap_or_default(),
        &at.forget_lines,
    )?;

    // 2. The server, chosen and agreed to before the build, so that the
    // person is asked at the start and not after it. A new environment's
    // record starts as where it is kept, so that a VPS bought here goes on
    // record at once.
    let env_before = match m.env.get(&app.env) {
        Some(env) => env.clone(),
        None => Env {
            inventory: new_inventory(at)?,
            ..Env::default()
        },
    };
    let Found {
        server,
        new_env,
        bought,
    } = server(&m, app, at, &env_before, &kept, on_record, say).await?;
    if let Some(line) = go_ahead_line(&server, bought, &m.name, id.as_str()) {
        say.line(&line);
        go_ahead(yes, &t!("worker_deploy.nothing_deployed"))?;
    }

    // 3. The build, while a VPS gets ready.
    let building = {
        let (m, path, quiet) = (m.clone(), path.clone(), say.quiet);
        tokio::task::spawn_blocking(move || {
            crate::worker_build::for_servers(&m, &path, &Say { quiet })
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
    let controller = crate::worker_firewall::controller(&session);

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
    ctl_ok(
        &session,
        &id,
        Verb::Setup {
            restart_agent: agent_changed,
        },
        None,
    )?;
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
    // port open only to `app_allow`.
    let synced =
        crate::worker_firewall::sync(&m, &env_before, &server.target, &id, controller, say)?;
    let ssh_allow = synced.ssh_allow;

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
    if let Some(root) = path.parent() {
        let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_owned());
        let _ = crate::session::beside_config(erpc_worker::index::FILE_NAME).and_then(|p| {
            erpc_worker::index::update(&p, |i| Ok(((), i.remember(&m.name, &root)?)))
        });
    }

    // 6. The data lines, now that the server's address is known and on
    // record; the app gets their endpoints when it starts. A line the
    // operator says is gone leaves the record first.
    let forgotten = take_lines(&mut env, &at.forget_lines)?;
    if let Some(said) = say_forgotten(&forgotten) {
        kept.save(&env, None).map_err(failed)?;
        say.line(&said);
    }
    if !asked_lines.is_empty() {
        lines(
            &asked_lines,
            &server,
            &mut env,
            &kept,
            on_record,
            &scope,
            say,
        )
        .await?;
    }
    let launch = Launch::for_app(&m, &env).map_err(failed)?;

    // 7. The release.
    let session = open(&server.target)?;
    let dir = format!("{UPLOADS}/{}/{}", id.as_str(), release.as_str());
    let binary = std::fs::read(&built.binary).map_err(|e| {
        let path = built.binary.display();
        failed(t!("worker_deploy.could_not_read", path, error = e))
    })?;
    upload(&session, &format!("{dir}/{}", built.release.bin), &binary)?;
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
    let root = path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_owned);
    for file in &built.release.files {
        let bytes = std::fs::read(root.join(&file.path)).map_err(|e| {
            let path = &file.path;
            failed(t!("worker_deploy.could_not_read", path, error = e))
        })?;
        upload(&session, &format!("{dir}/{}", file.path), &bytes)?;
    }
    ctl_ok(&session, &id, Verb::Install(release.clone()), None)?;
    say.line(&t!("worker_deploy.installed", release = release.as_str()));

    // 8. The key and the secrets.
    let request = unlock_request(&m)?;
    ctl_ok(&session, &id, Verb::Unlock, Some(&request))?;
    drop(request);

    // 9. Activation.
    say.line(&t!("worker_deploy.starting"));
    let answer = ctl(&session, &id, Verb::Activate(release.clone()), None)?;

    if answer["ok"].as_bool() != Some(true) {
        // The agent's own words for why, when it gives them.
        let why = answer["error"]
            .as_str()
            .map_or_else(|| t!("worker_deploy.failed.unhealthy"), str::to_owned);
        let back = if answer["rolled_back"] == json!(true) {
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
        let release = release.as_str();
        return Err(
            failed(t!("worker_deploy.failed.release", release, why, back))
                .hint(t!("worker_deploy.failed.logs", scope)),
        );
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
            Some(&crate::worker_inventory::deployed(release.as_str())),
        ),
        _ => saved,
    };
    match (&saved, &env.inventory) {
        (Ok(()), Some(i)) if new_env => {
            let (vault, title) = (&i.vault, erpc_worker::inventory::title(&m.name, &app.env));
            text.push(said_in!(
                lang,
                t!("worker_deploy.done.in_vault", vault, title)
            ));
        }
        (Ok(()), None) if new_env => {
            text.push(said_in!(
                lang,
                t!("worker_deploy.done.in_toml", env = app.env)
            ));
        }
        (Ok(()), _) => {}
        (Err(error), _) => text.push(format!(
            "warning: {}",
            said_in!(lang, t!("worker_deploy.done.not_kept", error))
        )),
    }
    for line in &env.lines {
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
    if server.resource.hourly {
        text.push(said_in!(lang, t!("worker_deploy.done.hourly_vps", scope)));
    }
    Ok(json!({
        "text": text.join("\n"),
        "release": built.release,
        "host": server.target.host,
        "worker": id.as_str(),
        "activation": answer,
        "agent": {
            "sha256": agent.sha256,
            "source": agent.source.as_str(),
            "changed": agent_changed,
        },
        "ssh_allow": ssh_allow,
        "lines": env.lines,
        "lines_forgotten": forgotten.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
        "erpc_toml_updated": saved.is_ok(),
    }))
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn lines_to_forget_are_all_on_record_or_none_is_taken() {
        let line = |id: &str| Line {
            kind: LineKind::Grpc,
            id: id.to_owned(),
            endpoint: String::new(),
            hourly: true,
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
        for on_record in on_records {
            for listed in [false, true] {
                for charged in [false, true] {
                    let next = LineNext::of(on_record, listed, charged);
                    // Forgotten only when hourly, seen with its endpoint
                    // before, and shown by neither.
                    let forget = on_record == Some((true, false)) && !listed && !charged;
                    assert_eq!(
                        next == LineNext::Forget,
                        forget,
                        "{on_record:?} {listed} {charged}"
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
        assert_eq!(
            LineNext::of(Some((true, true)), false, false),
            LineNext::Wait(WaitWhy::NotSeenYet)
        );
        assert_eq!(
            LineNext::of(Some((true, false)), true, false),
            LineNext::Wait(WaitWhy::NotYetCharged)
        );
        assert_eq!(
            LineNext::of(Some((true, true)), false, true),
            LineNext::Wait(WaitWhy::SettingUp)
        );
        assert_eq!(
            LineNext::of(Some((false, false)), false, false),
            LineNext::Wait(WaitWhy::Unbilled)
        );
    }

    #[test]
    fn the_agent_named_comes_first_then_the_one_erpc_carries() {
        assert_eq!(AgentSource::choose(true, true), AgentSource::Named);
        assert_eq!(AgentSource::choose(true, false), AgentSource::Named);
        assert_eq!(AgentSource::choose(false, true), AgentSource::Embedded);
        assert_eq!(AgentSource::choose(false, false), AgentSource::Beside);
    }
    use erpc_worker::manifest::{Env, Line, LineKind, Resource, ResourceKind};

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
        use crate::i18n::speaking;
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
}
