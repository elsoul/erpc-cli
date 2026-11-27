// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Who may reach a worker's server, as `[env.<name>.firewall]` says, and
//! `erpc worker firewall list|allow|deny|sync`.
//!
//! Two tables, each applied under a rollback timer and kept only once a
//! fresh SSH connection gets through it:
//!
//! - The SSH allow list (`inet erpc_ssh`, as `erpc ai` applies it): SSH
//!   from `firewall.ssh_allow` and the address erpc connects from, which is
//!   always added so erpc cannot shut itself out.
//! - The worker firewall (`inet erpc_worker`, made by the agent from every
//!   worker's opening): every other inbound connection dropped, but for
//!   each worker's `run.port` from its `firewall.app_allow`, and the UDP
//!   port of its UDP Forwarding line from the IPv4 addresses the line
//!   sends from (`lines[].sources`). When user-api names none the port
//!   stays closed, unless the operator opens it to any IPv4 address for
//!   that deploy (`deploy --udp-any-source`): nothing on record says so,
//!   and a sync from the record closes it again, saying so.
//!
//! An app behind a WAF (`[waf]`) has the WAF's port opened in place of its
//! own, with the firewall's limit on new connections, and only once the
//! WAF listens there: until a deploy has put the WAF in place the port
//! stays closed, so that it is never open to whatever else might listen
//! on it. `firewall.app_allow` may then name everyone (`0.0.0.0/0`,
//! `::/0`), which no app's own port is opened to.
//!
//! And the port is opened as `erpc.toml` asks only under the rules
//! `erpc.toml` makes. The server's agent reports its WAF's config file,
//! whether the WAF was started after its files last changed (that file
//! and its unit), and whether the WAF is a process of the agent installed
//! there, whose code the WAF is. While the config is not the one `[waf]`
//! now makes, the WAF was started before one of its files last changed,
//! or the WAF is an earlier agent's
//! process, a change that lets nobody new in is applied at once (closing
//! the port always works), and any other is held: the opening in force
//! stays as it is until a deploy has put the new rules in place
//! ([`decide`]). So tightening `[waf]` and widening `app_allow` in one
//! edit never opens the port to the new audience under the old rules.
//!
//! A deploy ends with the firewall as `erpc.toml` asks: once its WAF
//! listens with `erpc.toml`'s rules, the opening `erpc.toml` asks for is
//! put in force wherever it is not the one in force already
//! ([`open_as_asked`]). That is an opening its firewall step held, and
//! also one that step narrowed, which kept the limit on new connections
//! then in force. Outside a deploy that limit stays, and `allow`, `deny`
//! and `sync` say so ([`Synced::limit_kept`]).
//!
//! The UDP port is no WAF's: what is said above of holding and narrowing
//! is of the TCP port alone. A sync opens the UDP port as the line's
//! record says, whatever it does with the TCP port, and a deploy whose
//! lines changed what the UDP port lets in applies it again, the TCP port
//! as the sync left it ([`reopen`]).
//!
//! What a sync and the last step of a deploy ask of the server is a
//! [`Server`], so that the tests run the same steps against one that
//! writes down what it was asked, in order. What the firewall step found
//! and did reaches the last step as one value, a [`Synced`], which only a
//! sync makes.

use std::net::{IpAddr, Ipv4Addr};

use erpc_ssh::worker::{UnitId, Verb};
use erpc_ssh::{RemoteCommand, Session, Target};
use erpc_worker::manifest::{Env, Line, LineKind, Manifest};
use erpc_worker::net::Cidr;
use erpc_worker::server::{FirewallRequest, NewConnections, Opening, UdpOpening};
use erpc_worker::waf::WafConfig;
use serde_json::{Value, json};

use crate::account::commands::{Outcome, Said};
use crate::cli::error::{CliError, Code};
use crate::node::common::{Say, go_ahead};
use crate::worker::account as kept;
use crate::worker::remote::{ctl, ctl_ok, failed, open, target};
use crate::worker::waf::{Rules, addresses};
use crate::worker::{App, Port, load_env};

/// `key=value` lines' value for `key`.
fn value(stdout: &[u8], key: &str) -> Option<String> {
    String::from_utf8_lossy(stdout).lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|v| v.trim().to_owned())
    })
}

/// The address the server sees this machine connect from.
pub(crate) fn controller(session: &Session) -> Option<IpAddr> {
    session
        .run(&RemoteCommand::VpsController, None)
        .ok()
        .and_then(|out| value(&out.stdout, "controller"))
        .and_then(|c| c.parse().ok())
}

/// The most addresses the ERPC account keeps that may reach SSH, for an
/// environment kept there.
pub(crate) const ACCOUNT_SSH_MAX: usize = 16;

/// The SSH addresses to allow: `ssh_allow` and `me`.
fn ssh_addresses(
    env: &Env,
    me: Option<IpAddr>,
    say: &Say,
    scope: &str,
) -> Result<Vec<IpAddr>, CliError> {
    // An environment kept in the ERPC account has its list there: said so,
    // not as erpc.toml's keys, with the command that takes a network off.
    let in_account = env.account;
    let mut out: Vec<IpAddr> = Vec::new();
    for cidr in &env.firewall.ssh_allow {
        let single = if cidr.address().is_ipv4() { 32 } else { 128 };
        if cidr.prefix() != single {
            return Err(if in_account {
                failed(t!("worker_firewall.ssh_network_account", cidr)).hint(t!(
                    "worker_firewall.ssh_network_account_hint",
                    cidr,
                    scope
                ))
            } else {
                failed(t!("worker_firewall.ssh_network", cidr))
            });
        }
        out.push(cidr.address());
    }
    let mut added = None;
    if let Some(me) = me
        && !out.contains(&me)
    {
        if !env.firewall.ssh_allow.is_empty() {
            added = Some(me);
        }
        out.push(me);
    }
    if out.is_empty() {
        return Err(if in_account {
            failed(t!("worker_firewall.no_address_account"))
                .hint(t!("worker_firewall.no_address_account_hint", scope))
        } else {
            failed(t!("worker_firewall.no_address")).hint(t!("worker_firewall.no_address_hint"))
        });
    }
    // The account keeps so many and no more: refused here, before the
    // server's firewall is changed, rather than after it.
    if in_account && out.len() > ACCOUNT_SSH_MAX {
        return Err(failed(t!(
            "worker_firewall.account_list_full",
            max = ACCOUNT_SSH_MAX,
            count = out.len()
        ))
        .hint(t!("worker_firewall.account_list_hint", scope)));
    }
    // Said once the list is taken, not before a refusal of it.
    if let Some(me) = added {
        say.line(&if in_account {
            t!("worker_firewall.me_added_account", me)
        } else {
            t!("worker_firewall.me_added", me)
        });
    }
    Ok(out)
}

/// Applies the SSH allow list, kept once a fresh connection gets in.
fn allow_ssh(target: &Target, addresses: Vec<IpAddr>) -> Result<(), CliError> {
    let list = erpc_ssh::vps::AllowList::new(addresses, target.port).map_err(failed)?;
    open(target)?
        .run(&RemoteCommand::VpsAllowSsh(list), None)
        .map_err(|e| {
            failed(t!(
                "worker_firewall.ssh_apply_unfinished",
                error = e,
                seconds = erpc_ssh::vps::ROLLBACK_SECONDS
            ))
        })?;
    let kept = open(target)?
        .run(&RemoteCommand::VpsConfirmAllow, None)
        .map_err(|e| {
            failed(t!(
                "worker_firewall.ssh_locked_out",
                error = e,
                seconds = erpc_ssh::vps::ROLLBACK_SECONDS
            ))
        })?;
    match value(&kept.stdout, "firewall").as_deref() {
        Some("confirmed") => Ok(()),
        other => Err(failed(t!(
            "worker_firewall.ssh_not_kept",
            state = format!("{other:?}")
        ))),
    }
}

/// Applies this worker's opening to the server's firewall, kept once a
/// fresh connection gets in.
fn apply_worker(target: &Target, id: &UnitId, opening: Option<Opening>) -> Result<(), CliError> {
    let request = serde_json::to_vec(&FirewallRequest {
        ssh_port: target.port,
        opening,
    })
    .map_err(|e| failed(e.to_string()))?;
    ctl_ok(&open(target)?, id, Verb::FirewallApply, Some(&request)).map_err(|e| {
        failed(t!(
            "worker_firewall.not_applied",
            error = e.message,
            seconds = erpc_worker::server::FIREWALL_ROLLBACK_SECONDS
        ))
    })?;
    let kept = ctl(&open(target)?, id, Verb::FirewallConfirm, None)?;
    if kept["firewall"] == json!("confirmed") {
        Ok(())
    } else {
        Err(failed(t!(
            "worker_firewall.not_kept",
            why = kept["error"]
                .as_str()
                .map_or_else(|| t!("worker_firewall.no_reason"), str::to_owned)
        )))
    }
}

/// A worker's server, as a sync and the last step of a deploy change it:
/// its two firewall tables and its WAF. [`Remote`] is the server over SSH;
/// the tests have one that writes down what it was asked, in order, and
/// answers as they say.
pub(crate) trait Server {
    /// Applies the SSH allow list, kept once a fresh connection gets in.
    fn allow_ssh(&self, addresses: Vec<IpAddr>) -> Result<(), CliError>;
    /// What the agent's `firewall-show` answers: the openings in force,
    /// by worker, and how this worker's WAF is, with its config file and
    /// whether that is what it runs.
    fn shown(&self) -> Result<Value, CliError>;
    /// Applies this worker's opening, none to close its port, kept once a
    /// fresh connection gets in.
    fn apply(&self, opening: Option<Opening>) -> Result<(), CliError>;
    /// Hands `config` to the agent's `waf-apply`: its answer, `ok` or not.
    fn waf_apply(&self, config: &WafConfig) -> Result<Value, CliError>;
    /// The agent's `waf-remove`: its answer, `ok` or not.
    fn waf_remove(&self) -> Result<Value, CliError>;
}

/// A worker's server, over SSH.
pub(crate) struct Remote<'a> {
    /// A connection already made, for what needs no fresh one.
    pub(crate) session: &'a Session,
    /// The server, for the fresh connections a firewall change takes.
    pub(crate) target: &'a Target,
    /// The worker.
    pub(crate) id: &'a UnitId,
}

impl Server for Remote<'_> {
    fn allow_ssh(&self, addresses: Vec<IpAddr>) -> Result<(), CliError> {
        allow_ssh(self.target, addresses)
    }

    fn shown(&self) -> Result<Value, CliError> {
        ctl_ok(&open(self.target)?, self.id, Verb::FirewallShow, None)
    }

    fn apply(&self, opening: Option<Opening>) -> Result<(), CliError> {
        apply_worker(self.target, self.id, opening)
    }

    fn waf_apply(&self, config: &WafConfig) -> Result<Value, CliError> {
        let request = serde_json::to_vec(config).map_err(|e| failed(e.to_string()))?;
        ctl(self.session, self.id, Verb::WafApply, Some(&request))
    }

    fn waf_remove(&self) -> Result<Value, CliError> {
        ctl(self.session, self.id, Verb::WafRemove, None)
    }
}

/// Why an opening `erpc.toml` asks for was not put in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    /// No WAF runs on the server: its port is not opened to whatever else
    /// might listen there.
    NoWaf,
    /// The WAF on the server runs rules that are not `erpc.toml`'s: its
    /// port is not opened wider under them.
    OtherRules,
    /// The server does not say which rules its WAF runs (an agent from
    /// before it reported them), so they are not taken for `erpc.toml`'s.
    UnsaidRules,
    /// The WAF on the server does not run the agent installed there (an
    /// earlier one started it, or the server could not tell), so what it
    /// runs is not taken for `erpc.toml`'s rules until a deploy has
    /// restarted it.
    EarlierAgent,
    /// The WAF on the server was started before its config or its unit
    /// there last changed, or a deploy that was writing them was ended
    /// before it restarted it (or the server could not tell when), so what it
    /// runs is not known to be the config the server reports, under the
    /// unit there, and is not taken for `erpc.toml`'s rules until a
    /// deploy has restarted it.
    BeforeConfig,
    /// As [`Why::BeforeConfig`], kept so by something at the path of the
    /// note a deploy leaves while it writes the WAF's files that cannot be
    /// removed ([`crate::worker::waf::Rules::NoteKept`]): a deploy opens
    /// the port, and outside one it is held, until root removes that path.
    NoteKept,
}

impl Why {
    /// Its name in `--json`.
    const fn name(self) -> &'static str {
        match self {
            Self::NoWaf => "no_waf",
            Self::OtherRules => "other_rules",
            Self::UnsaidRules => "unreported_rules",
            Self::EarlierAgent => "earlier_agent",
            Self::BeforeConfig => "before_config",
            Self::NoteKept => "note_kept",
        }
    }

    /// What is said of the server's rules where a port was left as it is
    /// because of them; nothing for a port held closed for want of a WAF.
    fn rules_said(self) -> String {
        match self {
            Self::NoWaf => String::new(),
            Self::OtherRules => t!("worker_firewall.rules_other"),
            Self::UnsaidRules => t!("worker_firewall.rules_unsaid"),
            Self::EarlierAgent => t!("worker_firewall.rules_earlier"),
            Self::BeforeConfig => t!("worker_firewall.rules_before_config"),
            Self::NoteKept => t!("worker_firewall.rules_note_kept"),
        }
    }
}

/// An opening `erpc.toml` asks for that was not put in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Held {
    /// The opening asked for.
    pub(crate) opening: Opening,
    /// Why it waits.
    pub(crate) why: Why,
}

/// What a sync does with the port of an app behind a WAF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decision {
    /// The opening to put in force; none closes the port.
    pub(crate) apply: Option<Opening>,
    /// What `erpc.toml` asks for and is left for a deploy, with why.
    pub(crate) held: Option<Held>,
}

/// Whether going from `in_force` to `wanted` lets nobody in who is not let
/// in now: the port closed, or the same port to addresses that are each,
/// as written, among the ones in force. An address inside a network in
/// force is not "as written" one of them, and counts as new. The limit on
/// new connections is not looked at: it is the firewall's, not who is let
/// in.
fn narrows(wanted: Option<&Opening>, in_force: Option<&Opening>) -> bool {
    match (wanted, in_force) {
        (None, _) => true,
        (Some(wanted), Some(now)) => {
            wanted.port == now.port && wanted.allow.iter().all(|a| now.allow.contains(a))
        }
        (Some(_), None) => false,
    }
}

/// What to do with the port of an app behind a WAF: `wanted` is the
/// opening `erpc.toml` asks for (none when `firewall.app_allow` lists
/// nobody), `waf` the config its `[waf]` makes, `on_server` the server's
/// WAF as its agent reports it, and `in_force` the worker's opening in
/// force there (none when its port is closed).
///
/// The rule it keeps: while the rules the server's WAF runs are not the
/// ones `erpc.toml` now makes, the WAF's port is never open to more than
/// it is now.
///
/// - No WAF runs there: the port is closed, and what is wanted held until
///   a deploy has started one.
/// - One runs the config `erpc.toml` makes: what is wanted is applied.
/// - One runs another config, the server does not say which, or the one
///   that runs is not the agent installed there or was started before
///   its config or its unit last changed, so that the config reported is
///   not what it runs: a change
///   that only narrows ([`narrows`]) is applied at once, so that closing
///   the port, or taking an address off, always works. It keeps the limit
///   on new connections that is in force: the one `erpc.toml` gives is a
///   part of its rules, which are not there yet, and may be the looser. A
///   deploy applies that one once they are ([`open_as_asked`]).
///   Any other change leaves the opening in force as it is, and what is
///   wanted is held until a deploy has put `erpc.toml`'s rules in place.
pub(crate) fn decide(
    wanted: Option<Opening>,
    waf: &WafConfig,
    on_server: &Value,
    in_force: Option<&Opening>,
) -> Decision {
    let (apply, why) = match crate::worker::waf::rules(on_server, waf) {
        Rules::Asked => (wanted.clone(), None),
        Rules::NotRunning => (None, Some(Why::NoWaf)),
        Rules::Other
        | Rules::Unsaid
        | Rules::EarlierAgent
        | Rules::BeforeConfig
        | Rules::NoteKept
            if narrows(wanted.as_ref(), in_force) =>
        {
            let narrowed = wanted.as_ref().zip(in_force).map(|(wanted, now)| Opening {
                limit: now.limit,
                ..wanted.clone()
            });
            (narrowed, None)
        }
        Rules::Other => (in_force.cloned(), Some(Why::OtherRules)),
        Rules::Unsaid => (in_force.cloned(), Some(Why::UnsaidRules)),
        Rules::EarlierAgent => (in_force.cloned(), Some(Why::EarlierAgent)),
        Rules::BeforeConfig => (in_force.cloned(), Some(Why::BeforeConfig)),
        Rules::NoteKept => (in_force.cloned(), Some(Why::NoteKept)),
    };
    Decision {
        apply,
        held: why.zip(wanted).map(|(why, opening)| Held { opening, why }),
    }
}

/// The opening in force for `worker` on the server, by the agent's
/// `firewall-show`: the one it kept when the last change was confirmed.
/// None when the worker's port is closed.
///
/// # Errors
///
/// When the answer does not say. Without it a port could be opened wider
/// than it is, so the sync stops and the port is left as it is.
fn in_force(shown: &Value, worker: &str) -> Result<Option<Opening>, CliError> {
    let unknown = || failed(t!("worker_firewall.in_force_unknown", worker));
    let openings = shown["openings"].as_object().ok_or_else(unknown)?;
    match openings.get(worker) {
        None | Some(Value::Null) => Ok(None),
        Some(kept) => serde_json::from_value(kept.clone())
            .map(Some)
            .map_err(|_| unknown()),
    }
}

/// What a sync is asked besides what is on record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ask<'a> {
    /// Open the UDP Forwarding line's port to any IPv4 address when
    /// user-api names none it sends from (`deploy --udp-any-source`).
    pub(crate) udp_any_source: bool,
    /// The app and environment, as a hint's command names them.
    pub(crate) scope: &'a str,
}

impl<'a> Ask<'a> {
    /// What `firewall allow`, `deny` and `sync` ask: the record and nothing
    /// more. Opening a UDP port to any address is for a deploy to be told.
    pub(crate) const fn from_record(scope: &'a str) -> Self {
        Self {
            udp_any_source: false,
            scope,
        }
    }
}

/// The UDP Forwarding line on record that has its port, which is once it
/// is pointed at the server, with that port.
fn udp_line(env: &Env) -> Option<(&Line, u16)> {
    let line = env
        .lines
        .iter()
        .find(|l| l.kind == LineKind::Udp && !l.is_pending())?;
    Some((line, crate::worker::vps::udp_port(line)?))
}

/// The UDP part of the worker's opening: the port of the line on record,
/// to the addresses it sends from. A line that names none opens nothing,
/// unless `any_source`: an empty list is never read as "everyone".
pub(crate) fn udp_opening(env: &Env, any_source: bool) -> Option<UdpOpening> {
    let (line, port) = udp_line(env)?;
    if line.sources.is_empty() && !any_source {
        return None;
    }
    Some(UdpOpening {
        port,
        allow: line.sources.clone(),
        any_source: line.sources.is_empty(),
    })
}

/// The TCP part of `opening`: none when it opens no TCP port (port 0,
/// for a worker that opens its UDP port alone), else it without its UDP
/// port. What a WAF's rules decide, and what is said of the app's port.
fn tcp_part(opening: Option<&Opening>) -> Option<Opening> {
    opening.filter(|o| o.port != 0).map(|o| Opening {
        udp: None,
        ..o.clone()
    })
}

/// IPv4 addresses as a message lists them.
fn senders(allow: &[Ipv4Addr]) -> String {
    allow
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What the firewall does about the UDP Forwarding line's port, as a step
/// says it: open to the line's addresses, open to any as asked, closed for
/// want of an address (with how to open it), or no line at all.
pub(crate) fn say_udp(env: &Env, ask: Ask<'_>) -> String {
    let Some((line, port)) = udp_line(env) else {
        return t!("worker_firewall.udp_closed");
    };
    match (line.sources.is_empty(), ask.udp_any_source) {
        (false, _) => t!(
            "worker_firewall.udp_open",
            port,
            addresses = senders(&line.sources)
        ),
        (true, true) => t!("worker_firewall.udp_open_any", port),
        (true, false) => t!("worker_firewall.udp_unnamed", port, scope = ask.scope),
    }
}

/// What a sync applied, and what it left for a deploy. Only [`sync`]
/// makes one, and a deploy hands the one its firewall step made to its
/// last step whole ([`open_as_asked`]): what was asked for, held or
/// narrowed cannot be left behind on the way.
pub(crate) struct Synced {
    /// The addresses SSH is allowed from.
    ssh_allow: Vec<IpAddr>,
    /// The opening erpc.toml asks for; none when `firewall.app_allow`
    /// lists nobody and no UDP port is opened.
    wanted: Option<Opening>,
    /// The worker's opening now in force.
    opening: Option<Opening>,
    /// The opening erpc.toml asks for and this sync did not put in force,
    /// with why: a WAF's port, while no WAF listens on it, or while the
    /// one that does runs rules that are not erpc.toml's.
    held: Option<Held>,
    /// Whether the environment is kept in the ERPC account, whose lists
    /// these are: said as the account's, not erpc.toml's.
    in_account: bool,
}

impl Synced {
    /// The addresses SSH is allowed from.
    pub(crate) fn ssh_allow(&self) -> &[IpAddr] {
        &self.ssh_allow
    }

    /// The limit on new connections this sync left in force on a WAF's
    /// port where it is not the one erpc.toml gives, as (in force,
    /// erpc.toml's), each none for no limit: a change that only narrowed
    /// was applied under rules that are not erpc.toml's ([`decide`]).
    /// None when the limit in force is erpc.toml's, when the port is
    /// closed, and when the opening was held, which is said as that.
    fn limit_kept(&self) -> Option<(Option<NewConnections>, Option<NewConnections>)> {
        let (wanted, now) = (
            tcp_part(self.wanted.as_ref())?,
            tcp_part(self.opening.as_ref())?,
        );
        (self.held.is_none() && wanted.limit != now.limit).then_some((now.limit, wanted.limit))
    }
}

/// What is said of an opening's limit on new connections, after its
/// addresses; nothing without one.
fn limit_said(opening: &Opening) -> String {
    opening.limit.map_or_else(String::new, |limit| {
        t!(
            "worker_firewall.waf_limit",
            per_second = limit.per_second,
            burst = limit.burst
        )
    })
}

/// What a port left as it is under rules that are not erpc.toml's is
/// said to be: open to those it was open to, or closed.
fn kept(waf_port: u16, in_force: Option<&Opening>) -> String {
    match in_force {
        Some(o) => t!(
            "worker_firewall.kept_open",
            port = o.port,
            addresses = addresses(&o.allow)
        ),
        None => t!("worker_firewall.kept_closed", port = waf_port),
    }
}

/// What a sync says it does about the worker's port: `waf_port` is the
/// WAF's when the app has one.
fn dropping(waf_port: Option<u16>, decided: &Decision, in_account: bool, scope: &str) -> String {
    let opening = decided.apply.as_ref();
    let why = decided.held.as_ref().map(|held| held.why);
    match (waf_port, opening, why) {
        (None, Some(o), _) => t!(
            "worker_firewall.dropping_open",
            port = o.port,
            addresses = addresses(&o.allow)
        ),
        (None, None, _) => t!("worker_firewall.dropping_closed"),
        (Some(port), _, Some(Why::NoWaf)) => t!("worker_firewall.dropping_waf_held", port),
        (Some(port), in_force, Some(why)) => t!(
            "worker_firewall.dropping_waf_kept",
            rules = why.rules_said(),
            now = kept(port, in_force)
        ),
        (Some(_), Some(o), None) => t!(
            "worker_firewall.dropping_waf_open",
            port = o.port,
            addresses = addresses(&o.allow),
            limit = limit_said(o)
        ),
        (Some(port), None, None) if in_account => {
            t!("worker_firewall.dropping_waf_nobody_account", port, scope)
        }
        (Some(port), None, None) => t!("worker_firewall.dropping_waf_nobody", port),
    }
}

/// What the last firewall step of a deploy says it does, where it does
/// something ([`open_as_asked`]): that it opens the port a sync held, now
/// that a WAF listens there, or now that the one there runs erpc.toml's
/// rules; or, for a port open to the same addresses already, what becomes
/// of its limit on new connections. None where the opening in force is
/// the one erpc.toml asks for, and where erpc.toml lists nobody.
fn asked_said(synced: &Synced) -> Option<String> {
    let wanted = tcp_part(synced.wanted.as_ref());
    let o = wanted
        .as_ref()
        .filter(|o| Some(*o) != tcp_part(synced.opening.as_ref()).as_ref())?;
    let (port, addresses) = (o.port, addresses(&o.allow));
    Some(match synced.held.as_ref().map(|held| held.why) {
        Some(Why::NoWaf) => {
            let limit = limit_said(o);
            t!("worker_firewall.opening_waf", port, addresses, limit)
        }
        Some(
            Why::OtherRules
            | Why::UnsaidRules
            | Why::EarlierAgent
            | Why::BeforeConfig
            | Why::NoteKept,
        ) => {
            let limit = limit_said(o);
            t!("worker_firewall.opening_waf_rules", port, addresses, limit)
        }
        None => {
            let limit = if o.limit.is_some() {
                limit_said(o)
            } else {
                t!("worker_firewall.limit_off")
            };
            t!("worker_firewall.limit_waf", port, addresses, limit)
        }
    })
}

/// The firewall step that ends a deploy, taken once `waf-apply` has
/// answered `ok`: the WAF listens on its port with erpc.toml's rules, so
/// the opening erpc.toml asks for is put in force wherever it is not the
/// one `synced`, the deploy's firewall step, left in force. That is an
/// opening that step held, and one it narrowed with the limit on new
/// connections then in force, where erpc.toml gives another or none.
/// Where the two are the same the server is asked nothing.
///
/// Returns the worker's opening in force after it.
pub(crate) fn open_as_asked(
    server: &dyn Server,
    synced: &Synced,
    say: &Say,
) -> Result<Option<Opening>, CliError> {
    if synced.wanted == synced.opening {
        return Ok(synced.opening.clone());
    }
    if let Some(said) = asked_said(synced) {
        say.line(&said);
    }
    server.apply(synced.wanted.clone())?;
    Ok(synced.wanted.clone())
}

/// Makes the server's firewall what `env`, `m`'s environment `env_name`,
/// says: the SSH allow list, then the worker's ports. An app's own port is
/// opened as erpc.toml asks. A WAF's is opened as [`decide`] has it, from
/// what the server says of its WAF and of the opening in force. The UDP
/// Forwarding line's port is opened as its record says ([`udp_opening`]),
/// whatever is decided of the TCP port.
pub(crate) fn sync(
    server: &dyn Server,
    m: &Manifest,
    env_name: &str,
    env: &Env,
    me: Option<IpAddr>,
    ask: Ask<'_>,
    say: &Say,
) -> Result<Synced, CliError> {
    // The account's lists are not held to erpc.toml's checks where they
    // are written: checked before anything ([`account_lists_usable`]), and
    // again here, before the firewall is changed. Entries erpc does not
    // read are not in `env`, so they are not checked here.
    if env.account {
        account_lists_usable(m, env, &Unread::default(), ask.scope)?;
    }
    let ssh_allow = ssh_addresses(env, me, say, ask.scope)?;
    say.line(&t!(
        "worker_firewall.allowing_ssh",
        addresses = ssh_allow
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    server.allow_ssh(ssh_allow.clone())?;
    // The app's port, or its WAF's: the app's own is never opened then.
    let wanted = Opening::for_app(m, env);
    let waf_port = m.waf.as_ref().map(|waf| waf.port);
    let decided = match m.waf_config(env_name) {
        Some(config) => {
            let shown = server.shown()?;
            let in_force = in_force(&shown, &m.unit_id(env_name))?;
            let in_force = tcp_part(in_force.as_ref());
            decide(wanted.clone(), &config, &shown["waf"], in_force.as_ref())
        }
        // An app with no WAF: its own port, as erpc.toml asks. (A `[waf]`
        // makes no config only without `run.port`, which no checked
        // erpc.toml has; its port would stay closed.)
        None => Decision {
            apply: wanted.clone().filter(|_| m.waf.is_none()),
            held: None,
        },
    };
    say.line(&dropping(waf_port, &decided, env.account, ask.scope));
    if udp_line(env).is_some() {
        say.line(&say_udp(env, ask));
    }
    let Decision {
        apply: opening,
        held,
    } = decided;
    let udp = udp_opening(env, ask.udp_any_source);
    let opening = Opening::with_udp(opening, udp.clone());
    let wanted = Opening::with_udp(wanted, udp);
    server.apply(opening.clone())?;
    // What a person needs to know once it is in force: an open port reaches
    // an app that may still listen on loopback (a WAF listens beyond it),
    // and the SSH list outlives the address it was made from.
    if let (Some(o), None) = (tcp_part(opening.as_ref()), waf_port) {
        say.line(&t!("worker_firewall.app_loopback", port = o.port));
    }
    say.line(&if env.account {
        t!("worker_firewall.lockout_note_account")
    } else {
        t!("worker_firewall.lockout_note")
    });
    Ok(Synced {
        ssh_allow,
        wanted,
        opening,
        held,
        in_account: env.account,
    })
}

/// Applies the worker's opening again with `udp` as its UDP port, once a
/// deploy's lines have changed what that port should let in: a UDP
/// Forwarding line pointed at the server just now, one whose addresses
/// changed, or one that left the record. The TCP port stays as the sync
/// that made `synced` left it, held or narrowed: this never opens it, nor
/// changes its limit. `said` is what that does to the line's port
/// ([`say_udp`]). The server is asked nothing when the opening in force has
/// that UDP port already.
pub(crate) fn reopen(
    server: &dyn Server,
    synced: &mut Synced,
    udp: Option<UdpOpening>,
    said: &str,
    say: &Say,
) -> Result<(), CliError> {
    let opening = Opening::with_udp(tcp_part(synced.opening.as_ref()), udp.clone());
    if opening == synced.opening {
        return Ok(());
    }
    say.line(said);
    server.apply(opening.clone())?;
    synced.opening = opening;
    synced.wanted = Opening::with_udp(tcp_part(synced.wanted.as_ref()), udp);
    Ok(())
}

fn reach(app: &App) -> Result<(std::path::PathBuf, Manifest, Env, Target, UnitId), CliError> {
    let (path, m) = load_env(app)?;
    let env = crate::worker::env_of(&m, app)?.clone();
    let target = target(app, &env)?;
    let id = UnitId::new(&m.unit_id(&app.env)).map_err(failed)?;
    Ok((path, m, env, target, id))
}

/// Who a list lets in, or that it lets nobody in.
fn allowed(list: &[Cidr]) -> String {
    if list.is_empty() {
        t!("worker_firewall.describe.nobody")
    } else {
        addresses(list)
    }
}

/// The firewall's lines: SSH, then `port`, what is said of the worker's
/// own port, then its UDP Forwarding line's port, then everything else.
fn table(env: &Env, port: Vec<String>) -> Vec<String> {
    let ssh = t!(
        "worker_firewall.describe.ssh",
        list = allowed(&env.firewall.ssh_allow)
    );
    let mut lines = vec![format!("  {ssh}")];
    lines.extend(port);
    // As the record says it: a line that names no address has its port
    // closed by anything that applies the record.
    if let Some((line, port)) = udp_line(env) {
        let from = if line.sources.is_empty() {
            t!("worker_firewall.describe.udp_unnamed")
        } else {
            senders(&line.sources)
        };
        lines.push(format!("  udp {port:<5} {from}"));
    }
    lines.push(format!("  {}", t!("worker_firewall.describe.all_else")));
    lines
}

fn describe(env: &Env, run_port: Option<u16>) -> Vec<String> {
    let app = match run_port {
        Some(port) => format!("  app {port:<5} {}", allowed(&env.firewall.app_allow)),
        None => format!("  {}", t!("worker_firewall.describe.app_closed")),
    };
    table(env, vec![app])
}

/// The firewall erpc.toml asks for, as `list`, `allow`, `deny` and `sync`
/// show it: [`describe`], or, for an app behind a WAF, the WAF's port in
/// the app's place, with where the WAF forwards to and the firewall's
/// limit.
fn plan(env: &Env, m: &Manifest) -> Vec<String> {
    let (Some(waf), Some(app)) = (&m.waf, m.run.port) else {
        return describe(env, m.run.port);
    };
    let limit = waf.new_connections().map_or_else(String::new, |limit| {
        t!(
            "worker_firewall.describe.waf_limit",
            per_second = limit.per_second,
            burst = limit.burst
        )
    });
    let port = format!("  waf {:<5} {}", waf.port, allowed(&env.firewall.app_allow));
    let forwards = t!("worker_firewall.describe.waf", app, limit);
    table(env, vec![port, format!("            {forwards}")])
}

/// What `firewall list` shows of `m`'s environment `env_name` on `host`:
/// the firewall erpc.toml asks for, the table the server has (`server` is
/// the agent's `firewall-show`), and the WAF: how it is, what it blocked
/// by rule, and whether the rules it runs are erpc.toml's.
fn listed(m: &Manifest, env_name: &str, host: &str, server: &Value, scope: &str) -> String {
    let worker = m.unit_id(env_name);
    let default = Env::default();
    let env = m.env.get(env_name).unwrap_or(&default);
    let mut lines = vec![t!("worker_firewall.list.title", worker, host)];
    lines.extend(plan(env, m));
    lines.push(String::new());
    lines.push(t!("worker_firewall.list.on_server"));
    if let Some(table) = server["table"].as_str() {
        lines.extend(table.lines().map(|l| format!("  {l}")));
    } else {
        lines.push(format!(
            "  {}",
            t!(
                "worker_firewall.list.none_yet",
                command = format!("erpc worker firewall sync{scope}")
            )
        ));
    }
    match crate::worker::waf::said(&server["waf"], scope) {
        Some(waf) => {
            lines.push(waf);
            if let Some(blocked) = crate::worker::waf::blocked_by_rule(&server["waf"]) {
                lines.push(format!("  {blocked}"));
            }
        }
        None if m.waf.is_some() => lines.push(crate::worker::waf::absent(scope)),
        None => {}
    }
    lines.extend(crate::worker::waf::out_of_step(
        m,
        env_name,
        &server["waf"],
        scope,
    ));
    if server["pending"] == json!(true) {
        lines.push(format!("warning: {}", t!("worker_firewall.list.pending")));
    }
    lines.join("\n")
}

/// The refusal for "everyone" (`0.0.0.0/0`, `::/0`) given to `--to app`
/// of an app that has no WAF: only a WAF's port is opened to everyone.
fn refuse_everyone(to: Port, given: &[Cidr], behind_waf: bool) -> Option<CliError> {
    let everyone = given.iter().find(|c| c.is_everyone())?;
    (to == Port::App && !behind_waf).then(|| {
        CliError::new(
            Code::Usage,
            t!("worker_firewall.everyone_needs_waf", address = everyone),
        )
        .hint(t!("worker_firewall.everyone_hint"))
    })
}

/// `erpc worker firewall list`: what erpc.toml says, and what the server has.
pub(crate) fn list(json: bool, app: &App) -> Outcome {
    let run = || -> Result<Outcome, CliError> {
        let (_, m, env, target, id) = reach(app)?;
        let server = ctl(&open(&target)?, &id, Verb::FirewallShow, None)?;
        if json {
            crate::print_json(&json!({
                "erpc_toml": env.firewall,
                "run_port": m.run.port,
                "waf_port": m.waf.as_ref().map(|waf| waf.port),
                // The UDP Forwarding line's port and who sends to it, as
                // the record has them.
                "udp": udp_line(&env).map(|(line, port)| {
                    json!({ "port": port, "sources": line.sources })
                }),
                // Whether the WAF on the server runs erpc.toml's rules.
                "waf_rules": crate::worker::waf::rules_named(&m, &app.env, &server["waf"]),
                "server": server,
            }));
            return Ok(Outcome::Done(String::new()));
        }
        let text = listed(&m, &app.env, &target.host, &server, &app.scope());
        Ok(Outcome::Done(crate::cli::ui::decorate(&text, "🛡️")))
    };
    run().unwrap_or_else(Into::into)
}

/// The environment's lists once `addresses` are let in to `to` (`allow`)
/// or taken off its list: none when that changes nothing.
///
/// # Errors
///
/// Before anything is changed or the server asked: something that is not
/// an address, everyone (`0.0.0.0/0`, `::/0`) to the port of an app that
/// is not `behind_waf` ([`refuse_everyone`]), and a network to SSH.
fn edited(
    behind_waf: bool,
    env: &Env,
    to: Port,
    addresses: &[String],
    allow: bool,
) -> Result<Option<Env>, CliError> {
    let parsed = addresses
        .iter()
        .map(|a| Cidr::parse_any(a).map_err(|e| CliError::new(Code::Usage, e)))
        .collect::<Result<Vec<_>, _>>()?;
    if allow && let Some(refused) = refuse_everyone(to, &parsed, behind_waf) {
        return Err(refused);
    }
    // Refused here, before the plan is shown: the SSH allow list
    // (`ssh_addresses`) takes single addresses only.
    // A network the account's SSH list holds is taken off by `deny`, which
    // is the way out its refusal names.
    if to == Port::Ssh
        && (allow || !env.account)
        && let Some(network) = parsed.iter().find(|c| !is_single(c))
    {
        return Err(CliError::new(
            Code::Usage,
            t!("worker_firewall.ssh_network_given", network),
        )
        .hint(t!("worker_firewall.ssh_network_hint")));
    }
    let mut env = env.clone();
    let list = match to {
        Port::Ssh => &mut env.firewall.ssh_allow,
        Port::App => &mut env.firewall.app_allow,
    };
    let before = list.clone();
    for cidr in parsed {
        if allow {
            if !list.contains(&cidr) {
                list.push(cidr);
            }
        } else {
            list.retain(|c| *c != cidr);
        }
    }
    let changed = *list != before;
    Ok(changed.then_some(env))
}

/// What `allow` and `deny` say when the list is as asked already: nothing
/// was changed, in erpc.toml or on the server, which is not asked. `env`
/// is the environment as erpc.toml has it.
///
/// Under `--json` the answer is JSON, as every other answer of the two
/// is: `changed` is false, where the answer to a change has it true
/// ([`reported_change`]). What is in force on the server is not in it,
/// since the server was not asked; `erpc_toml` has the lists erpc.toml
/// asks for, as `firewall list` names them, and for an environment kept in
/// the account `account` has the account's lists as it keeps them (put in
/// by the caller, from the record).
fn unchanged(
    json: bool,
    worker: &str,
    env: &Env,
    addresses: &[String],
    allow: bool,
    scope: &str,
) -> Said {
    if json {
        let kept_in = if env.account { "account" } else { "erpc_toml" };
        return Said::Json(json!({
            "worker": worker,
            "changed": false,
            kept_in: env.firewall,
        }));
    }
    let (addresses, command) = (
        addresses.join(", "),
        format!("erpc worker firewall sync{scope}"),
    );
    let text = match (allow, env.account) {
        (true, false) => t!("worker_firewall.unchanged.allowed", addresses, command),
        (false, false) => t!("worker_firewall.unchanged.denied", addresses, command),
        (true, true) => t!(
            "worker_firewall.unchanged.allowed_account",
            addresses,
            command
        ),
        (false, true) => t!(
            "worker_firewall.unchanged.denied_account",
            addresses,
            command
        ),
    };
    Said::Text(crate::cli::ui::decorate(&text, "👌"))
}

/// `erpc worker firewall allow|deny`: changes erpc.toml's list, then the server.
///
/// The addresses are looked at before the server is: what is not an
/// address is refused, and a list that is as asked already is answered
/// ([`unchanged`]), without the server's address, its host key or this
/// machine's SSH key, none of which that needs.
pub(crate) fn change(
    json: bool,
    app: &App,
    to: Port,
    addresses: &[String],
    allow: bool,
    yes: bool,
) -> Outcome {
    let say = Say { quiet: json };
    let run = || -> Result<Outcome, CliError> {
        let (path, on_file) = load_env(app)?;
        let env = crate::worker::env_of(&on_file, app)?.clone();
        let id = UnitId::new(&on_file.unit_id(&app.env)).map_err(failed)?;
        let Some(env) = edited(on_file.waf.is_some(), &env, to, addresses, allow)? else {
            let scope = app.scope();
            return Ok(unchanged(json, id.as_str(), &env, addresses, allow, &scope).done());
        };
        let target = target(app, &env)?;
        // Checked as erpc.toml would be with the change written inline,
        // wherever it is kept.
        let text = std::fs::read_to_string(&path).map_err(|e| failed(e.to_string()))?;
        let inline = Env {
            inventory: None,
            ..env.clone()
        };
        let changed = erpc_worker::edit::set_env(&text, &app.env, &inline).map_err(failed)?;
        let m = Manifest::parse(&changed).map_err(|e| failed(e.to_string()))?;
        say.line(&t!("worker_firewall.will_be"));
        for line in plan(&env, &m) {
            say.line(&line);
        }
        go_ahead(yes, &t!("worker_firewall.nothing_changed"))?;
        let session = open(&target)?;
        let me = controller(&session);
        let server = Remote {
            session: &session,
            target: &target,
            id: &id,
        };
        let scope = app.scope();
        let synced = sync(
            &server,
            &m,
            &app.env,
            &env,
            me,
            Ask::from_record(&scope),
            &say,
        )?;
        // erpc.toml has the change whether or not all of it is in force
        // yet: what is held is what the next deploy applies.
        crate::worker::EnvRecord {
            path: &path,
            app: &m.name,
            env: &app.env,
        }
        .save(&env, None)
        .map_err(failed)?;
        let body = reported_change(id.as_str(), &synced);
        report_as(json, &id, &m, &synced, &app.scope(), body)
    };
    run().unwrap_or_else(Into::into)
}

/// `erpc worker firewall sync`: makes the server's firewall what erpc.toml says.
pub(crate) fn sync_verb(json: bool, app: &App, yes: bool) -> Outcome {
    let say = Say { quiet: json };
    let run = || -> Result<Outcome, CliError> {
        let (_, m, env, target, id) = reach(app)?;
        say.line(&t!("worker_firewall.will_be"));
        for line in plan(&env, &m) {
            say.line(&line);
        }
        go_ahead(yes, &t!("worker_firewall.nothing_changed"))?;
        let session = open(&target)?;
        let me = controller(&session);
        let server = Remote {
            session: &session,
            target: &target,
            id: &id,
        };
        let scope = app.scope();
        let synced = sync(
            &server,
            &m,
            &app.env,
            &env,
            me,
            Ask::from_record(&scope),
            &say,
        )?;
        report(json, &id, &m, &synced, &scope)
    };
    run().unwrap_or_else(Into::into)
}

// ------------------------------------------ kept in the ERPC account

/// The word `--to` takes for `to`.
const fn port_arg(to: Port) -> &'static str {
    match to {
        Port::Ssh => "ssh",
        Port::App => "app",
    }
}

/// Whether `cidr` is one address, as SSH takes them.
fn is_single(cidr: &Cidr) -> bool {
    cidr.prefix() == if cidr.address().is_ipv4() { 32 } else { 128 }
}

/// `cidr` as the account takes it: an IPv4-mapped IPv6 address in hex
/// (`::ffff:102:304`), which the account's form has, not dotted as Rust
/// writes it; every other address as erpc writes it.
pub(crate) fn account_text(cidr: &Cidr) -> String {
    if let IpAddr::V6(v6) = cidr.address()
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        let [a, b, c, d] = v4.octets();
        return format!(
            "::ffff:{:x}:{:x}/{}",
            u16::from_be_bytes([a, b]),
            u16::from_be_bytes([c, d]),
            cidr.prefix()
        );
    }
    cidr.to_string()
}

/// `list` as written to the account: each address the account holds
/// already (`raw`) in its own text, a new one as the account takes it
/// ([`account_text`]).
pub(crate) fn written_text(raw: &[String], list: &[Cidr]) -> Vec<String> {
    list.iter()
        .map(|cidr| {
            raw.iter()
                .find(|e| Cidr::parse_any(e).is_ok_and(|c| c == *cidr))
                .cloned()
                .unwrap_or_else(|| account_text(cidr))
        })
        .collect()
}

/// The entries of the account's lists that erpc does not read as an
/// address with its prefix length (an address with bits set past its
/// prefix, or no address at all), each as the account has it. They are
/// never applied, and never dropped from the account without a word.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Unread {
    /// Of the list of who may reach SSH.
    pub(crate) ssh: Vec<String>,
    /// Of the list of who may reach the app.
    pub(crate) app: Vec<String>,
}

impl Unread {
    /// Those of `record`'s lists.
    pub(crate) fn of(record: &erpc_api::worker::EnvDetail) -> Self {
        let unread = |list: &[String]| -> Vec<String> {
            list.iter()
                .filter(|e| Cidr::parse_any(e).is_err())
                .cloned()
                .collect()
        };
        Self {
            ssh: unread(&record.facts.firewall.ssh_allow),
            app: unread(&record.facts.firewall.app_allow),
        }
    }
}

/// `env`'s lists with each address once, and a line for each list that
/// had one more than once: the meaning is the same, and the account's
/// record is written with each once.
fn once_each(env: &Env) -> (Env, Vec<String>) {
    let mut env = env.clone();
    let mut said = Vec::new();
    for (to, list) in [
        (Port::Ssh, &mut env.firewall.ssh_allow),
        (Port::App, &mut env.firewall.app_allow),
    ] {
        let mut seen: Vec<Cidr> = Vec::new();
        let mut twice: Vec<String> = Vec::new();
        for cidr in core::mem::take(list) {
            if seen.contains(&cidr) {
                if !twice.contains(&cidr.to_string()) {
                    twice.push(cidr.to_string());
                }
            } else {
                seen.push(cidr);
            }
        }
        *list = seen;
        if !twice.is_empty() {
            let entries = twice.join(", ");
            said.push(match to {
                Port::Ssh => t!("worker_firewall.account_twice_ssh", entries),
                Port::App => t!("worker_firewall.account_twice_app", entries),
            });
        }
    }
    (env, said)
}

/// What stops the account's lists from being put on the server as they
/// are, all of it at once: for each list, every entry that stops it, as
/// `deny` takes it off; what each kind of problem is, said; and the ways
/// out besides `deny`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Stops {
    /// The entries of the SSH list that stop it, as `deny` takes them.
    pub(crate) ssh: Vec<String>,
    /// The entries of the app's list that stop it, as `deny` takes them.
    pub(crate) app: Vec<String>,
    /// What each kind of problem is.
    said: Vec<String>,
    /// The ways out besides `deny`: a WAF, `run.port`.
    also: Vec<String>,
}

impl Stops {
    /// Whether nothing stops the lists.
    pub(crate) fn is_empty(&self) -> bool {
        self.said.is_empty()
    }

    /// The `deny` commands that clear it, one per list, each naming every
    /// entry of its list that stops it.
    fn commands(&self, scope: &str) -> String {
        [(Port::Ssh, &self.ssh), (Port::App, &self.app)]
            .into_iter()
            .filter(|(_, entries)| !entries.is_empty())
            .map(|(to, entries)| {
                format!(
                    "`erpc worker firewall deny --to {} {}{scope}`",
                    port_arg(to),
                    entries
                        .iter()
                        .map(|e| crate::worker::shell_word(e))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            })
            .collect::<Vec<_>>()
            .join(&t!("worker_firewall.stop_and"))
    }

    /// What is said of it: every problem, and every way out.
    fn hint(&self, scope: &str) -> String {
        let mut hint = t!(
            "worker_firewall.account_stopped_hint",
            commands = self.commands(scope)
        );
        for also in &self.also {
            hint.push_str(&t!("worker_firewall.stop_or", also));
        }
        hint
    }

    /// The refusal: nothing was changed.
    fn error(&self, scope: &str) -> CliError {
        failed(t!(
            "worker_firewall.account_stopped",
            problems = self.said.join(&t!("worker_firewall.stop_sep"))
        ))
        .hint(self.hint(scope))
    }
}

/// What stops `env`'s lists, kept in the account (`unread` the entries
/// erpc does not read), from being put on the server: an entry erpc does
/// not read, a network on the SSH list, everyone on the app's list with no
/// WAF in front of the app, and addresses on the app's list with no
/// `run.port` for them to reach. The account holds none of these to
/// erpc.toml's checks where they are written.
pub(crate) fn stops(m: &Manifest, env: &Env, unread: &Unread) -> Stops {
    let mut stops = Stops::default();
    let push = |list: &mut Vec<String>, entry: String| {
        if !list.contains(&entry) {
            list.push(entry);
        }
    };
    if !unread.ssh.is_empty() {
        let shown: Vec<String> = unread.ssh.iter().map(|e| kept::shown(e)).collect();
        stops.said.push(t!(
            "worker_firewall.stop_unread_ssh",
            entries = shown.join(", ")
        ));
        for e in shown {
            push(&mut stops.ssh, e);
        }
    }
    let networks: Vec<String> = env
        .firewall
        .ssh_allow
        .iter()
        .filter(|c| !is_single(c))
        .map(ToString::to_string)
        .collect();
    if !networks.is_empty() {
        stops.said.push(t!(
            "worker_firewall.stop_network",
            entries = networks.join(", ")
        ));
        for e in networks {
            push(&mut stops.ssh, e);
        }
    }
    if !unread.app.is_empty() {
        let shown: Vec<String> = unread.app.iter().map(|e| kept::shown(e)).collect();
        stops.said.push(t!(
            "worker_firewall.stop_unread_app",
            entries = shown.join(", ")
        ));
        for e in shown {
            push(&mut stops.app, e);
        }
    }
    let everyone: Vec<String> = env
        .firewall
        .app_allow
        .iter()
        .filter(|c| c.is_everyone())
        .map(ToString::to_string)
        .collect();
    if m.waf.is_none() && !everyone.is_empty() {
        stops.said.push(t!(
            "worker_firewall.stop_everyone",
            entries = everyone.join(", ")
        ));
        stops.also.push(t!("worker_firewall.stop_also_waf"));
        for e in everyone {
            push(&mut stops.app, e);
        }
    }
    if m.run.port.is_none() && !(env.firewall.app_allow.is_empty() && unread.app.is_empty()) {
        stops.said.push(t!("worker_firewall.stop_no_port"));
        stops.also.push(t!("worker_firewall.stop_also_port"));
        for e in env.firewall.app_allow.iter().map(ToString::to_string) {
            push(&mut stops.app, e);
        }
    }
    stops
}

/// Refuses, before anything is changed or the server asked, lists of an
/// environment kept in the account that erpc would not put on the server
/// as they are ([`stops`], every problem at once, with the `deny` for each
/// list that clears it), and more than the account keeps in a list.
pub(crate) fn account_lists_usable(
    m: &Manifest,
    env: &Env,
    unread: &Unread,
    scope: &str,
) -> Result<(), CliError> {
    let stopped = stops(m, env, unread);
    if !stopped.is_empty() {
        return Err(stopped.error(scope));
    }
    for (to, list) in [
        (Port::Ssh, &env.firewall.ssh_allow),
        (Port::App, &env.firewall.app_allow),
    ] {
        if list.len() > ACCOUNT_SSH_MAX {
            return Err(CliError::new(
                Code::Usage,
                t!(
                    "worker_firewall.account_list_too_long",
                    max = ACCOUNT_SSH_MAX,
                    count = list.len()
                ),
            )
            .hint(t!(
                "worker_firewall.account_list_too_long_hint",
                port = port_arg(to),
                scope
            )));
        }
    }
    Ok(())
}

/// What `allow` or `deny` asks of an environment kept in the account.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Change<'a> {
    /// Which list.
    pub(crate) to: Port,
    /// The addresses, as typed.
    pub(crate) addresses: &'a [String],
    /// Let them in, or take them off.
    pub(crate) allow: bool,
}

/// The lists once `change` is made to `env`, with what is left `unread`:
/// none when nothing changes. `deny` takes an entry erpc does not read off
/// by its text as the account has it, or as erpc shows it.
fn account_edited(
    behind_waf: bool,
    env: &Env,
    unread: &Unread,
    change: Change<'_>,
) -> Result<Option<(Env, Unread)>, CliError> {
    let mut left = unread.clone();
    let mut rest: Vec<String> = Vec::new();
    let mut taken = false;
    for typed in change.addresses {
        let typed = typed.trim();
        let list = match change.to {
            Port::Ssh => &mut left.ssh,
            Port::App => &mut left.app,
        };
        let names = |e: &String| e == typed || kept::shown(e) == typed;
        if !change.allow && list.iter().any(names) {
            list.retain(|e| !names(e));
            taken = true;
        } else {
            rest.push(typed.to_owned());
        }
    }
    let changed = if rest.is_empty() {
        None
    } else {
        edited(behind_waf, env, change.to, &rest, change.allow)?
    };
    Ok(match (changed, taken) {
        (Some(env), _) => Some((env, left)),
        (None, true) => Some((env.clone(), left)),
        (None, false) => None,
    })
}

/// `raw`, one of the account's lists as it keeps it, with only what is
/// left after a `deny`: the entries still `unread`, and those whose
/// address is in `kept`, each as the account had it.
fn raw_left(raw: &[String], unread: &[String], kept: &[Cidr]) -> Vec<String> {
    raw.iter()
        .filter(|e| match Cidr::parse_any(e) {
            Ok(cidr) => kept.contains(&cidr),
            Err(_) => unread.contains(e),
        })
        .cloned()
        .collect()
}

/// A worker's server, reached over a connection of its own.
pub(crate) struct Reached {
    session: Session,
    target: Target,
    id: UnitId,
}

impl Reached {
    /// Reaches the server `env` names for `app`, with the address this
    /// machine connects from, when the server says it.
    fn open(app: &App, env: &Env, id: &UnitId) -> Result<(Self, Option<IpAddr>), CliError> {
        let target = target(app, env)?;
        let session = open(&target)?;
        let me = controller(&session);
        Ok((
            Self {
                session,
                target,
                id: id.clone(),
            },
            me,
        ))
    }

    fn remote(&self) -> Remote<'_> {
        Remote {
            session: &self.session,
            target: &self.target,
            id: &self.id,
        }
    }
}

impl Server for Reached {
    fn allow_ssh(&self, addresses: Vec<IpAddr>) -> Result<(), CliError> {
        self.remote().allow_ssh(addresses)
    }

    fn shown(&self) -> Result<Value, CliError> {
        self.remote().shown()
    }

    fn apply(&self, opening: Option<Opening>) -> Result<(), CliError> {
        self.remote().apply(opening)
    }

    fn waf_apply(&self, config: &WafConfig) -> Result<Value, CliError> {
        self.remote().waf_apply(config)
    }

    fn waf_remove(&self) -> Result<Value, CliError> {
        self.remote().waf_remove()
    }
}

/// What a write to the account's record that did not go as sent is said
/// as, `server` what became of the server's firewall: changed, or not.
fn unwritten_said(
    unwritten: crate::worker::deploy_account::Unwritten,
    app: &App,
    repair: Option<&str>,
) -> CliError {
    use crate::worker::deploy_account::Unwritten;
    let (env, scope) = (app.env.as_str(), app.scope());
    let server_changed = repair.is_none();
    let server = if server_changed {
        t!("worker_firewall.server_changed")
    } else {
        t!("worker_firewall.server_not_changed")
    };
    // A repair (the server not changed) is finished by the same deny, named
    // in full: a sync is refused while something still stops the lists.
    let again = |hint: String| match repair {
        None => hint,
        Some(command) => t!("worker_firewall.account_repair_again_hint", command),
    };
    match unwritten {
        Unwritten::Conflict => failed(t!("worker_firewall.account_conflict", env, server))
            .hint(again(t!("worker_firewall.account_conflict_hint", scope))),
        Unwritten::Lost(error) => failed(t!(
            "worker_firewall.account_write_unknown",
            env,
            server,
            error
        ))
        .hint(again(t!(
            "worker_firewall.account_write_unknown_hint",
            scope
        ))),
        Unwritten::Differs => failed(t!("worker_firewall.account_answer_differs", env, server))
            .hint(t!("worker_firewall.account_answer_differs_hint", scope)),
        Unwritten::Refused(error) => failed(t!(
            "worker_firewall.account_not_written",
            env,
            server,
            error
        ))
        .hint(again(t!("worker_firewall.account_not_written_hint", scope))),
        Unwritten::NotSignedIn(error) => CliError::new(
            Code::NotSignedIn,
            t!("worker_firewall.account_not_written", env, server, error),
        )
        .hint(t!("worker_vps.login_hint")),
        Unwritten::TooLong => failed(t!(
            "worker_firewall.account_too_long_to_write",
            env,
            server,
            max = ACCOUNT_SSH_MAX
        )),
    }
}

/// Writes `ssh` and `app_allow`, each entry as written to the account, to
/// its record of the environment `held` keeps, built on the record read
/// and trusted as written. `repair` is the deny that changes the account
/// alone, the server not changed, which finishes the write when it does
/// not go as sent; none when the server has the change by then. What this
/// machine's record could not follow is said on stderr, under `--json`
/// too: nothing is trusted unasked after it.
async fn write_lists(
    api: &impl kept::Account,
    (held, pins): (&kept::Kept, &std::path::Path),
    app: &App,
    (ssh, app_allow): (&[String], &[String]),
    repair: Option<&str>,
) -> Result<(), CliError> {
    let mut account = crate::worker::deploy_account::Deploying::new(
        api,
        &held.manifest.name,
        held,
        pins.to_path_buf(),
    );
    let written = account.write_lists(app, ssh, app_allow).await;
    for warning in &account.warnings {
        Say { quiet: false }.line(&format!("warning: {warning}"));
    }
    written.map_err(|u| unwritten_said(u, app, repair))
}

/// The firewall step for an environment kept in the account, on `server`
/// (`me` the address this machine connects from): the server first, as
/// for erpc.toml, then the account's record of the lists, through `api`:
/// SSH as the server now lets it in (erpc's own address added), the app's
/// list as `env` has it. The app's list put on the server is then the one
/// this machine last saw; a record of it that cannot be written is said on
/// stderr, under `--json` too.
async fn apply_account(
    server: &dyn Server,
    me: Option<IpAddr>,
    api: &impl kept::Account,
    (held, pins): (&kept::Kept, &std::path::Path),
    app: &App,
    env: &Env,
    say: &Say,
) -> Result<Synced, CliError> {
    let scope = app.scope();
    let synced = sync(
        server,
        &held.manifest,
        &app.env,
        env,
        me,
        Ask::from_record(&scope),
        say,
    )?;
    let raw = &held.record.facts.firewall;
    let ssh_now: Vec<Cidr> = synced
        .ssh_allow
        .iter()
        .filter_map(|a| Cidr::parse(&a.to_string()).ok())
        .collect();
    let ssh = written_text(&raw.ssh_allow, &ssh_now);
    let app_allow = written_text(&raw.app_allow, &env.firewall.app_allow);
    write_lists(api, (held, pins), app, (&ssh, &app_allow), None).await?;
    let key = kept::pin_key(&held.uid, &held.manifest.name, &app.env);
    if let Err(error) = kept::see_app(pins, &key, &app_allow) {
        Say { quiet: false }.line(&format!(
            "warning: {}",
            t!("worker_deploy_account.seen_not_updated", error)
        ));
    }
    Ok(synced)
}

/// After the yes and before the server is asked: the account's record is
/// read again, and a record another sign-in changed since `held` read it
/// changes nothing.
async fn still_as_read(
    api: &impl kept::Account,
    held: &kept::Kept,
    app: &App,
) -> Result<(), CliError> {
    let env = app.env.as_str();
    let fresh = api
        .env(&held.manifest.name, env)
        .await
        .map_err(|e| kept::worker_error(&held.manifest.name, app, &e))?;
    if fresh.revision != held.record.revision {
        return Err(
            failed(t!("worker_firewall.account_changed_since_read", env))
                .hint(t!("worker_firewall.account_changed_since_read_hint")),
        );
    }
    Ok(())
}

/// What changed in the account's list of who may reach the app since this
/// machine last put it on the server (`seen`), in a line: none when
/// nothing did. A list never seen here is said whole.
fn app_changes(seen: Option<&[String]>, now: &[String]) -> Option<String> {
    let shown = |list: &[&String]| -> String {
        list.iter()
            .map(|e| kept::shown(e))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match seen {
        None if now.is_empty() => None,
        None => Some(t!(
            "worker_firewall.app_list_first_seen",
            entries = shown(&now.iter().collect::<Vec<_>>())
        )),
        Some(seen) => {
            let added: Vec<&String> = now.iter().filter(|e| !seen.contains(e)).collect();
            let removed: Vec<&String> = seen.iter().filter(|e| !now.contains(e)).collect();
            if added.is_empty() && removed.is_empty() {
                return None;
            }
            let none = t!("worker_firewall.app_list_none");
            Some(t!(
                "worker_firewall.app_list_changed",
                added = if added.is_empty() {
                    none.clone()
                } else {
                    shown(&added)
                },
                removed = if removed.is_empty() {
                    none
                } else {
                    shown(&removed)
                }
            ))
        }
    }
}

/// [`app_changes`] for the environment `held` keeps, by this machine's
/// record beside its pins at `pins`: unreadable is read as never seen.
pub(crate) fn app_changes_of(
    held: &kept::Kept,
    pins: &std::path::Path,
    app: &App,
) -> Option<String> {
    let key = kept::pin_key(&held.uid, &held.manifest.name, &app.env);
    let seen = kept::app_seen(pins, &key).ok().flatten();
    app_changes(seen.as_deref(), &held.record.facts.firewall.app_allow)
}

/// The account's lists as it keeps them, each entry shown safe, and what
/// erpc does not read of them.
fn account_lists_json(record: &erpc_api::worker::EnvDetail) -> Value {
    let shown = |list: &[String]| -> Vec<String> { list.iter().map(|e| kept::shown(e)).collect() };
    json!({
        "ssh_allow": shown(&record.facts.firewall.ssh_allow),
        "app_allow": shown(&record.facts.firewall.app_allow),
    })
}

/// What `erpc worker firewall list --json` answers for an environment kept
/// in the account, `shown` what the server has.
fn list_json(
    (m, app, held, pins): (&Manifest, &App, &kept::Kept, &std::path::Path),
    shown: &Value,
) -> Value {
    let record = &held.record;
    let unread = Unread::of(record);
    let clean = |list: &[String]| -> Vec<String> { list.iter().map(|e| kept::shown(e)).collect() };
    let stopped = crate::worker::env_of(m, app)
        .ok()
        .and_then(|env| account_lists_usable(m, env, &unread, &app.scope()).err())
        .map(|e| e.message);
    json!({
        "account": account_lists_json(record),
        "unread": { "ssh_allow": clean(&unread.ssh), "app_allow": clean(&unread.app) },
        "app_allow_changed": app_changes_of(held, pins, app),
        "stopped": stopped,
        "run_port": m.run.port,
        "waf_port": m.waf.as_ref().map(|waf| waf.port),
        "waf_rules": crate::worker::waf::rules_named(m, &app.env, &shown["waf"]),
        "server": shown,
    })
}

/// `erpc worker firewall list` of an environment kept in the account, with
/// the server reached through `reach`: the account's lists as it keeps
/// them, what erpc does not read of them, what the server has, what
/// changed in the app's list since this machine put it there, and, as a
/// warning, what would stop a change.
fn list_in<S: Server>(
    json: bool,
    app: &App,
    held: &kept::Kept,
    pins: &std::path::Path,
    reach: impl FnOnce(&Env) -> Result<(S, Option<IpAddr>), CliError>,
) -> Result<Outcome, CliError> {
    let m = &held.manifest;
    let env = crate::worker::env_of(m, app)?.clone();
    let unread = Unread::of(&held.record);
    let (server, _) = reach(&env)?;
    let shown = server.shown()?;
    if json {
        crate::print_json(&list_json((m, app, held, pins), &shown));
        return Ok(Outcome::Done(String::new()));
    }
    let host = env.host.clone().unwrap_or_default();
    let mut lines = vec![listed(m, &app.env, &host, &shown, &app.scope())];
    lines.extend(app_changes_of(held, pins, app));
    let (_, twice) = once_each(&env);
    lines.extend(twice);
    if let Err(e) = account_lists_usable(m, &env, &unread, &app.scope()) {
        lines.push(format!("warning: {}", e.message));
        if let Some(hint) = e.hint {
            lines.push(format!("hint: {hint}"));
        }
    }
    Ok(Outcome::Done(crate::cli::ui::decorate(
        &lines.join("\n"),
        "🛡️",
    )))
}

/// How `allow`, `deny` and `sync` of an environment kept in the account go
/// on: `--json`, the yes, the server, and this machine's pins.
pub(crate) struct Going<'a, S, F, R> {
    /// `--json`.
    pub(crate) json: bool,
    /// Asks to go ahead (`go_ahead`, which `--yes` answers).
    pub(crate) go_ahead: F,
    /// Reaches the server the lists are put on.
    pub(crate) reach: R,
    /// This machine's pins.
    pub(crate) pins: std::path::PathBuf,
    /// Where progress is said.
    pub(crate) say: &'a Say,
    _server: core::marker::PhantomData<S>,
}

impl<'a, S, F, R> Going<'a, S, F, R>
where
    S: Server,
    F: FnOnce() -> Result<(), CliError>,
    R: FnOnce(&Env) -> Result<(S, Option<IpAddr>), CliError>,
{
    pub(crate) const fn new(
        json: bool,
        go_ahead: F,
        reach: R,
        pins: std::path::PathBuf,
        say: &'a Say,
    ) -> Self {
        Self {
            json,
            go_ahead,
            reach,
            pins,
            say,
            _server: core::marker::PhantomData,
        }
    }
}

/// Says what changed in the app's list since this machine put it on the
/// server: on stderr, under `--json` too, before anything is asked or
/// done.
fn say_app_changes(held: &kept::Kept, pins: &std::path::Path, app: &App) {
    if let Some(line) = app_changes_of(held, pins, app) {
        Say { quiet: false }.line(&line);
    }
}

/// The lists of `env` as erpc puts them for an environment kept in the
/// account, checked, said and agreed to; then the record read again, the
/// server, and the account's record.
async fn put_account<S, F, R>(
    api: &impl kept::Account,
    held: &kept::Kept,
    app: &App,
    env: &Env,
    unread: &Unread,
    going: Going<'_, S, F, R>,
) -> Result<(UnitId, Synced), CliError>
where
    S: Server,
    F: FnOnce() -> Result<(), CliError>,
    R: FnOnce(&Env) -> Result<(S, Option<IpAddr>), CliError>,
{
    let m = &held.manifest;
    let id = UnitId::new(&m.unit_id(&app.env)).map_err(failed)?;
    let scope = app.scope();
    let (env, twice) = once_each(env);
    account_lists_usable(m, &env, unread, &scope)?;
    say_app_changes(held, &going.pins, app);
    for line in twice {
        going.say.line(&line);
    }
    going.say.line(&t!("worker_firewall.will_be"));
    for line in plan(&env, m) {
        going.say.line(&line);
    }
    (going.go_ahead)()?;
    still_as_read(api, held, app).await?;
    let (server, me) = (going.reach)(&env)?;
    let synced = apply_account(&server, me, api, (held, &going.pins), app, &env, going.say).await?;
    Ok((id, synced))
}

/// A `deny` that only takes entries off while something still stops the
/// lists (`stopped`): written to the account's record alone, each entry
/// left as the account had it, the server's firewall not changed. It ends
/// with a failure that says so and what still stops them, as a held port
/// does, for a script to tell.
#[allow(
    clippy::too_many_arguments,
    reason = "the change, what is left of it, and how it goes on"
)]
async fn repair_account<S, F, R>(
    api: &impl kept::Account,
    held: &kept::Kept,
    app: &App,
    change: Change<'_>,
    (env, left): (&Env, &Unread),
    stopped: &Stops,
    going: Going<'_, S, F, R>,
) -> Result<Outcome, CliError>
where
    S: Server,
    F: FnOnce() -> Result<(), CliError>,
    R: FnOnce(&Env) -> Result<(S, Option<IpAddr>), CliError>,
{
    let scope = app.scope();
    let raw = &held.record.facts.firewall;
    let (ssh, app_allow) = match change.to {
        Port::Ssh => (
            raw_left(&raw.ssh_allow, &left.ssh, &env.firewall.ssh_allow),
            raw.app_allow.clone(),
        ),
        Port::App => (
            raw.ssh_allow.clone(),
            raw_left(&raw.app_allow, &left.app, &env.firewall.app_allow),
        ),
    };
    let (before, after) = match change.to {
        Port::Ssh => (&raw.ssh_allow, &ssh),
        Port::App => (&raw.app_allow, &app_allow),
    };
    let removed: Vec<String> = before
        .iter()
        .filter(|e| !after.contains(e))
        .map(|e| kept::shown(e))
        .collect();
    let problems = stopped.said.join(&t!("worker_firewall.stop_sep"));
    let what = match change.to {
        Port::Ssh => t!("worker_firewall.list_ssh"),
        Port::App => t!("worker_firewall.list_app"),
    };
    say_app_changes(held, &going.pins, app);
    going.say.line(&t!(
        "worker_firewall.repair_plan",
        what = what.as_str(),
        removed = removed.join(", "),
        problems = problems.as_str()
    ));
    (going.go_ahead)()?;
    still_as_read(api, held, app).await?;
    let again = format!(
        "erpc worker firewall deny --to {} {}{scope}",
        port_arg(change.to),
        change
            .addresses
            .iter()
            .map(|a| crate::worker::shell_word(a.trim()))
            .collect::<Vec<_>>()
            .join(" ")
    );
    write_lists(
        api,
        (held, &going.pins),
        app,
        (&ssh, &app_allow),
        Some(&again),
    )
    .await?;
    Err(failed(t!(
        "worker_firewall.repaired",
        what = what.as_str(),
        removed = removed.join(", "),
        problems,
        scope = scope.as_str()
    ))
    .hint(stopped.hint(&scope))
    .details(json!({
        "changed": true,
        "account_only": true,
        "removed": removed,
        "stopped_by": { "ssh_allow": stopped.ssh, "app_allow": stopped.app },
    })))
}

/// What `allow` and `deny` of an environment kept in the account say when
/// the list is as asked already ([`unchanged`]), with the account's lists
/// as it keeps them (`record`) under `account` in the JSON.
fn unchanged_in_account(
    json: bool,
    worker: &str,
    (env, record): (&Env, &erpc_api::worker::EnvDetail),
    change: Change<'_>,
    scope: &str,
) -> Said {
    match unchanged(json, worker, env, change.addresses, change.allow, scope) {
        Said::Json(mut body) => {
            body["account"] = account_lists_json(record);
            Said::Json(body)
        }
        text @ Said::Text(_) => text,
    }
}

/// `erpc worker firewall allow|deny` of an environment kept in the
/// account, through `api` and `going`: checked before anything, the server
/// first, then the account's record of the lists; erpc.toml is not
/// changed. A `deny` that only takes entries off always lands: while
/// something else still stops the lists, in the account's record alone
/// ([`repair_account`]).
async fn change_in<S, F, R>(
    api: &impl kept::Account,
    held: &kept::Kept,
    app: &App,
    change: Change<'_>,
    going: Going<'_, S, F, R>,
) -> Result<Outcome, CliError>
where
    S: Server,
    F: FnOnce() -> Result<(), CliError>,
    R: FnOnce(&Env) -> Result<(S, Option<IpAddr>), CliError>,
{
    let m = &held.manifest;
    let env = crate::worker::env_of(m, app)?.clone();
    let id = UnitId::new(&m.unit_id(&app.env)).map_err(failed)?;
    let scope = app.scope();
    let json = going.json;
    let say = going.say;
    let unread = Unread::of(&held.record);
    let Some((after, left)) = account_edited(m.waf.is_some(), &env, &unread, change)? else {
        // Nothing to change: what stops the lists, if anything does, is
        // said rather than "sync applies them again".
        let stopped = stops(m, &env, &unread);
        if !stopped.is_empty() {
            return Err(stopped.error(&scope));
        }
        let said = unchanged_in_account(json, id.as_str(), (&env, &held.record), change, &scope);
        return Ok(said.done());
    };
    let stopped = stops(m, &after, &left);
    if !stopped.is_empty() {
        if change.allow {
            return Err(stopped.error(&scope));
        }
        return repair_account(api, held, app, change, (&after, &left), &stopped, going).await;
    }
    let (id, synced) = put_account(api, held, app, &after, &left, going).await?;
    // Taking erpc's own address off SSH would lock this machine out: it
    // stays, and is said to.
    if change.to == Port::Ssh && !change.allow {
        for typed in change.addresses {
            if let Ok(cidr) = Cidr::parse_any(typed)
                && synced.ssh_allow.contains(&cidr.address())
            {
                say.line(&t!("worker_firewall.kept_own", address = cidr.address()));
            }
        }
    }
    let body = reported_change(id.as_str(), &synced);
    report_as(json, &id, m, &synced, &scope, body)
}

/// `erpc worker firewall sync` of an environment kept in the account,
/// through `api` and `going`: the server's firewall made what the
/// account's lists say, and erpc's own address written back when it was
/// added.
async fn sync_in<S, F, R>(
    api: &impl kept::Account,
    held: &kept::Kept,
    app: &App,
    going: Going<'_, S, F, R>,
) -> Result<Outcome, CliError>
where
    S: Server,
    F: FnOnce() -> Result<(), CliError>,
    R: FnOnce(&Env) -> Result<(S, Option<IpAddr>), CliError>,
{
    let m = &held.manifest;
    let env = crate::worker::env_of(m, app)?.clone();
    let unread = Unread::of(&held.record);
    let json = going.json;
    let (id, synced) = put_account(api, held, app, &env, &unread, going).await?;
    report(json, &id, m, &synced, &app.scope())
}

/// What `erpc worker firewall` was asked to do, of which app.
#[derive(Debug, Clone)]
pub(crate) enum FirewallAsk {
    List,
    Sync {
        yes: bool,
    },
    Change {
        to: Port,
        addresses: Vec<String>,
        allow: bool,
        yes: bool,
    },
}

/// `erpc worker firewall` of an environment kept in the account, through
/// `api`, `pins` and `reach`, asking as `go_ahead` does (`--yes` answers).
pub(crate) async fn account<S, R>(
    json: bool,
    app: &App,
    ask: FirewallAsk,
    (api, held): (&impl kept::Account, &kept::Kept),
    pins: std::path::PathBuf,
    reach: R,
) -> Outcome
where
    S: Server,
    R: FnOnce(&Env) -> Result<(S, Option<IpAddr>), CliError>,
{
    let say = Say { quiet: json };
    let refused = t!("worker_firewall.nothing_changed");
    let run = async {
        match ask {
            FirewallAsk::List => list_in(json, app, held, &pins, reach),
            FirewallAsk::Sync { yes } => {
                let going = Going::new(json, || go_ahead(yes, &refused), reach, pins, &say);
                sync_in(api, held, app, going).await
            }
            FirewallAsk::Change {
                to,
                addresses,
                allow,
                yes,
            } => {
                let going = Going::new(json, || go_ahead(yes, &refused), reach, pins, &say);
                let change = Change {
                    to,
                    addresses: &addresses,
                    allow,
                };
                change_in(api, held, app, change, going).await
            }
        }
    };
    run.await.unwrap_or_else(Into::into)
}

/// [`account`], through `api` and this machine's pins at `pins`, reaching
/// the server over SSH.
pub(crate) async fn account_kept(
    json: bool,
    app: &App,
    ask: FirewallAsk,
    (api, held): (&impl kept::Account, &kept::Kept),
    pins: std::path::PathBuf,
) -> Outcome {
    let id = match UnitId::new(&held.manifest.unit_id(&app.env)).map_err(failed) {
        Ok(id) => id,
        Err(e) => return e.into(),
    };
    account(json, app, ask, (api, held), pins, |env: &Env| {
        Reached::open(app, env, &id)
    })
    .await
}

/// What the worker's port is now, in the sentence that says the firewall
/// is in force: the app's own, or behind a WAF the WAF's, open, or closed
/// because nobody is listed. A port that was held is not said here: that
/// is an error of its own ([`held_back`]).
fn port_said(m: &Manifest, synced: &Synced) -> String {
    let waf_port = m.waf.as_ref().map(|waf| waf.port);
    let tcp = match (waf_port, &tcp_part(synced.opening.as_ref())) {
        (None, None) => t!("worker_firewall.app_closed"),
        (None, Some(o)) => t!(
            "worker_firewall.app_open",
            port = o.port,
            addresses = addresses(&o.allow)
        ),
        (Some(_), Some(o)) => t!(
            "worker_firewall.waf_open",
            port = o.port,
            addresses = addresses(&o.allow)
        ),
        (Some(port), None) if synced.in_account => t!("worker_firewall.waf_closed_account", port),
        (Some(port), None) => t!("worker_firewall.waf_closed", port),
    };
    match synced.opening.as_ref().and_then(|o| o.udp.as_ref()) {
        Some(udp) if udp.any_source => {
            let udp = t!("worker_firewall.udp_from_any", port = udp.port);
            format!("{tcp}; {udp}")
        }
        Some(udp) => {
            let udp = t!(
                "worker_firewall.udp_from",
                port = udp.port,
                addresses = senders(&udp.allow)
            );
            format!("{tcp}; {udp}")
        }
        None => tcp,
    }
}

/// The failure `allow`, `deny` and `sync` end with when the opening
/// erpc.toml asks for was held: the rest of the firewall is in force, the
/// WAF's port is not what was asked, and a script must be able to tell
/// that from success. It says what the port is now and why, and names the
/// deploy that puts erpc.toml's rules in place and opens it.
fn held_back(worker: &str, synced: &Synced, held: &Held, scope: &str) -> CliError {
    let ssh = synced
        .ssh_allow
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let (port, addresses) = (held.opening.port, addresses(&held.opening.allow));
    match held.why {
        Why::NoWaf => failed(t!(
            "worker_firewall.held_no_waf",
            port,
            addresses,
            worker,
            ssh
        ))
        .hint(t!("worker_firewall.held_no_waf_hint", scope)),
        why @ (Why::OtherRules
        | Why::UnsaidRules
        | Why::EarlierAgent
        | Why::BeforeConfig
        | Why::NoteKept) => {
            let held = failed(t!(
                "worker_firewall.held_other_rules",
                port,
                addresses,
                rules = why.rules_said(),
                now = kept(port, tcp_part(synced.opening.as_ref()).as_ref()),
                worker,
                ssh
            ));
            held.hint(match why {
                Why::EarlierAgent => t!("worker_firewall.held_earlier_hint", scope),
                // A deploy does not end this; root removing the path does.
                Why::NoteKept => t!(
                    "worker_firewall.held_note_hint",
                    path = erpc_worker::server::waf_note_path(worker),
                    scope
                ),
                _ => t!("worker_firewall.held_other_rules_hint", scope),
            })
        }
    }
}

/// A limit on new connections, as it is named beside another.
fn limit_named(limit: Option<NewConnections>) -> String {
    limit.map_or_else(
        || t!("worker_firewall.limit_none"),
        |limit| {
            t!(
                "worker_firewall.limit_is",
                per_second = limit.per_second,
                burst = limit.burst
            )
        },
    )
}

/// What `allow`, `deny` and `sync` say when nothing was held: the firewall
/// in force; and under it, where a narrowing left the WAF's port with a
/// limit on new connections that is not erpc.toml's
/// ([`Synced::limit_kept`]), a line that says so and names the deploy
/// that applies erpc.toml's. That is no failure: the narrowing did what
/// was asked.
fn in_force_said(worker: &str, m: &Manifest, synced: &Synced, scope: &str) -> String {
    let mut text = t!(
        "worker_firewall.in_force",
        worker,
        ssh = synced
            .ssh_allow
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        app = port_said(m, synced)
    );
    if let (Some((now, asked)), Some(o)) = (synced.limit_kept(), tcp_part(synced.opening.as_ref()))
    {
        let kept = t!(
            "worker_firewall.limit_kept",
            port = o.port,
            now = limit_named(now),
            asked = limit_named(asked),
            scope
        );
        text.push_str("\nwarning: ");
        text.push_str(&kept);
    }
    text
}

/// What `allow`, `deny` and `sync` did, for `--json`: `opening`, the
/// worker's opening now in force; `held` and `held_because`, the opening
/// asked for and why it waits; and `new_connections_kept`, null unless
/// the limit in force on a WAF's port is not the one erpc.toml gives
/// ([`Synced::limit_kept`]), then both, as `in_force` and `erpc_toml`,
/// each null for no limit.
fn reported(worker: &str, synced: &Synced) -> Value {
    json!({
        "worker": worker,
        "ssh_allow": synced.ssh_allow,
        "opening": synced.opening,
        "held": synced.held.as_ref().map(|held| &held.opening),
        "held_because": synced.held.as_ref().map(|held| held.why.name()),
        "new_connections_kept": synced.limit_kept().map(|(in_force, erpc_toml)| {
            json!({ "in_force": in_force, "erpc_toml": erpc_toml })
        }),
    })
}

/// [`reported`], for `allow` and `deny` that changed erpc.toml's list:
/// the same, with `changed` true. It is true whether or not all of the
/// change is in force on the server yet (`held`), since erpc.toml has it
/// by then; an `allow` or `deny` with nothing to change says false
/// ([`unchanged`]). `sync`, which changes no list, has no such field.
fn reported_change(worker: &str, synced: &Synced) -> Value {
    let mut body = reported(worker, synced);
    body["changed"] = json!(true);
    body
}

/// What `allow`, `deny` and `sync` end with: the firewall in force
/// ([`in_force_said`]), or, when the WAF's port was held, a failure that
/// says so ([`held_back`]) and carries the same facts for `--json`
/// ([`reported`]).
fn report(
    json: bool,
    id: &UnitId,
    m: &Manifest,
    synced: &Synced,
    scope: &str,
) -> Result<Outcome, CliError> {
    report_as(json, id, m, synced, scope, reported(id.as_str(), synced))
}

/// [`report`], with `body` as the facts for `--json`.
fn report_as(
    json: bool,
    id: &UnitId,
    m: &Manifest,
    synced: &Synced,
    scope: &str,
    body: Value,
) -> Result<Outcome, CliError> {
    if let Some(held) = &synced.held {
        return Err(held_back(id.as_str(), synced, held, scope).details(body));
    }
    if json {
        crate::print_json(&body);
        return Ok(Outcome::Done(String::new()));
    }
    Ok(Outcome::Done(crate::cli::ui::decorate(
        &in_force_said(id.as_str(), m, synced, scope),
        "🛡️",
    )))
}

/// A server for the tests of what is asked of one, and in which order.
#[cfg(test)]
pub(crate) mod recorded {
    use std::cell::RefCell;
    use std::net::IpAddr;

    use erpc_worker::server::Opening;
    use erpc_worker::waf::WafConfig;
    use serde_json::{Value, json};

    use super::Server;
    use crate::cli::error::CliError;
    use crate::worker::remote::failed;
    use crate::worker::waf::addresses;

    /// A server that changes nothing: it writes down what it was asked, in
    /// order, and answers as the test has it.
    pub(crate) struct Recorded {
        asked: RefCell<Vec<String>>,
        /// What `firewall-show` answers.
        pub(crate) shown: Value,
        /// What `waf-apply` answers.
        pub(crate) waf_applied: Value,
        /// What `waf-remove` answers.
        pub(crate) waf_removed: Value,
        /// What it does not do: a request written down as one of these
        /// fails, as one the server could not be reached for does.
        pub(crate) fails: Vec<&'static str>,
    }

    impl Recorded {
        /// One whose `firewall-show` answers `shown`, and whose WAF verbs
        /// answer that they did what they were asked.
        pub(crate) fn showing(shown: Value) -> Self {
            Self {
                asked: RefCell::new(Vec::new()),
                shown,
                waf_applied: json!({ "ok": true, "changed": true, "proxy": "started" }),
                waf_removed: json!({ "ok": true, "removed": true }),
                fails: Vec::new(),
            }
        }

        /// One whose `firewall-show` says the worker's WAF is as `waf` has
        /// it, and `worker`'s opening in force is `in_force` (none when
        /// its port is closed).
        pub(crate) fn with(waf: &Value, worker: &str, in_force: Option<&Opening>) -> Self {
            let mut openings = serde_json::Map::new();
            if let Some(opening) = in_force {
                openings.insert(worker.to_owned(), json!(opening));
            }
            Self::showing(json!({
                "ok": true,
                "table": null,
                "openings": openings,
                "pending": false,
                "waf": waf,
            }))
        }

        /// What it was asked since the last time this was asked, in order.
        pub(crate) fn asked(&self) -> Vec<String> {
            core::mem::take(&mut *self.asked.borrow_mut())
        }

        /// Writes down `what` it was asked, and fails where the test has
        /// it fail ([`Self::fails`]), saying what it did not do.
        fn note(&self, what: String) -> Result<(), CliError> {
            let done = if self.fails.contains(&what.as_str()) {
                Err(failed(format!("the server did not do it: {what}")))
            } else {
                Ok(())
            };
            self.asked.borrow_mut().push(what);
            done
        }
    }

    impl Server for Recorded {
        fn allow_ssh(&self, addresses: Vec<IpAddr>) -> Result<(), CliError> {
            let list: Vec<String> = addresses.iter().map(ToString::to_string).collect();
            self.note(format!("allow-ssh {}", list.join(", ")))
        }

        fn shown(&self) -> Result<Value, CliError> {
            self.note("firewall-show".to_owned())?;
            Ok(self.shown.clone())
        }

        fn apply(&self, opening: Option<Opening>) -> Result<(), CliError> {
            self.note(match opening {
                Some(o) => format!(
                    "open {} to {}{}{}",
                    o.port,
                    addresses(&o.allow),
                    o.limit.map_or_else(String::new, |limit| format!(
                        ", limit {}/{}",
                        limit.per_second, limit.burst
                    )),
                    o.udp.map_or_else(String::new, |udp| if udp.any_source {
                        format!(", udp {} from any", udp.port)
                    } else {
                        let from: Vec<String> = udp.allow.iter().map(ToString::to_string).collect();
                        format!(", udp {} from {}", udp.port, from.join(", "))
                    })
                ),
                None => "close".to_owned(),
            })
        }

        fn waf_apply(&self, config: &WafConfig) -> Result<Value, CliError> {
            self.note(format!("waf-apply {}", config.listen))?;
            Ok(self.waf_applied.clone())
        }

        fn waf_remove(&self) -> Result<Value, CliError> {
            self.note("waf-remove".to_owned())?;
            Ok(self.waf_removed.clone())
        }
    }

    /// What a server's agent reports of a WAF that runs `config`.
    pub(crate) fn running(config: &WafConfig) -> Value {
        json!({
            "unit": "erpc-waf-bot-prod.service",
            "state": "active",
            "active": true,
            "listen": config.listen,
            "port": config.listen.port(),
            "upstream": config.upstream,
            "config": config,
            "started": "after_config",
            "binary": "installed",
            "config_error": null,
            "stats": null,
            "stats_error": null,
        })
    }
}

#[cfg(test)]
mod tests {
    use erpc_core::i18n::Lang;
    use erpc_worker::manifest::{Env, Manifest};
    use erpc_worker::net::Cidr;
    use erpc_worker::server::{Opening, UdpOpening};
    use serde_json::{Value, json};

    use super::recorded::{Recorded, running};
    use super::{Decision, Held, Port, Synced, Why};
    use crate::cli::error::Code;
    use crate::node::common::Say;

    const SCOPE: &str = " --env prod";

    /// An app on port 3000 deployed to one server, with `waf` as its
    /// `[waf]` table (none when empty) and `allow` as its `app_allow`.
    fn app(waf: &str, allow: &str) -> Manifest {
        Manifest::parse(&format!(
            "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n{waf}\
             [env.prod]\nhost = \"203.0.113.10\"\n\
             [env.prod.firewall]\nssh_allow = [\"198.51.100.7\"]\napp_allow = [{allow}]\n"
        ))
        .expect("valid")
    }

    const WAF: &str = "[waf]\nport = 8080\n";
    const EVERYONE: &str = "\"0.0.0.0/0\", \"::/0\"";

    /// What the agent's `firewall-show` answers for a worker behind a WAF
    /// that runs and has counted.
    fn shown() -> serde_json::Value {
        json!({
            "ok": true,
            "table": "table inet erpc_worker {\n\tchain input {\n\t\ttcp dport 22 accept\n\t}\n}",
            "openings": {},
            "pending": false,
            "waf": {
                "unit": "erpc-waf-bot-prod.service",
                "state": "active",
                "active": true,
                "listen": "0.0.0.0:8080",
                "port": 8080,
                "upstream": "127.0.0.1:3000",
                "config": app(WAF, EVERYONE).waf_config("prod"),
                "started": "after_config",
                "binary": "installed",
                "stats": {
                    "format": 1,
                    "since": "2026-11-11T09:00:00Z",
                    "requests": 120,
                    "forwarded": 100,
                    "blocked": { "probe": 7, "rate": 5, "banned": 3, "method": 0 },
                    "banned_now": 1,
                    "upstream_errors": 0
                }
            }
        })
    }

    #[test]
    fn the_plan_of_an_app_behind_a_waf_names_the_wafs_port_and_where_it_forwards() {
        let m = app(WAF, EVERYONE);
        assert_eq!(
            super::plan(&m.env["prod"], &m),
            [
                "  ssh       198.51.100.7/32 (and the address erpc connects from)",
                "  waf 8080  0.0.0.0/0, ::/0",
                "            the WAF there forwards to the app on 127.0.0.1:3000, whose own port \
                 stays closed; new connections over 50 a second from one address are dropped \
                 (burst 100)",
                "  all else  dropped"
            ]
        );
        // Without the firewall's limit, and with nobody listed.
        let m = app("[waf]\nport = 8080\nnew_connections = false\n", "");
        let lines = super::plan(&m.env["prod"], &m);
        assert_eq!(lines[1], "  waf 8080  nobody");
        assert!(
            lines[2].ends_with("whose own port stays closed"),
            "{lines:?}"
        );
        // An app without a WAF is told as it was.
        let m = app("", "\"198.51.100.0/24\"");
        assert_eq!(
            super::plan(&m.env["prod"], &m),
            super::describe(&m.env["prod"], Some(3000))
        );
        assert_eq!(
            super::plan(&m.env["prod"], &m)[1],
            "  app 3000  198.51.100.0/24"
        );
    }

    #[test]
    fn firewall_list_shows_the_waf_and_what_it_blocked_by_rule() {
        let m = app(WAF, EVERYONE);
        let listed = |m: &Manifest, server: &serde_json::Value| {
            super::listed(m, "prod", "203.0.113.10", server, SCOPE)
        };
        assert_eq!(
            listed(&m, &shown()),
            "bot-prod on 203.0.113.10:\n\
             \x20 ssh       198.51.100.7/32 (and the address erpc connects from)\n\
             \x20 waf 8080  0.0.0.0/0, ::/0\n\
             \x20           the WAF there forwards to the app on 127.0.0.1:3000, whose own port \
             stays closed; new connections over 50 a second from one address are dropped (burst \
             100)\n\
             \x20 all else  dropped\n\
             \n\
             On the server:\n\
             \x20 table inet erpc_worker {\n\
             \x20 \tchain input {\n\
             \x20 \t\ttcp dport 22 accept\n\
             \x20 \t}\n\
             \x20 }\n\
             WAF: listening on port 8080, forwarding to 127.0.0.1:3000, since \
             2026-11-11T09:00:00Z; requests 120, forwarded 100, blocked 12, connections refused 3, app errors 0, \
             addresses banned now 1\n\
             \x20 blocked by rule: probe 7, rate 5, banned 3"
        );
        // erpc.toml asks for a WAF the server does not have yet.
        let mut none = shown();
        none["waf"] = serde_json::Value::Null;
        assert!(
            listed(&m, &none).ends_with(
                "\nWAF: erpc.toml asks for one and the server has none yet; `erpc worker deploy \
                 --env prod` puts it in place"
            ),
            "{}",
            listed(&m, &none)
        );
        // An app without one is told nothing of one, as before.
        let plain = app("", "");
        let said = listed(&plain, &none);
        assert!(!said.contains("WAF"), "{said}");
        assert!(said.ends_with("\n  }"), "{said}");
    }

    #[test]
    fn firewall_list_says_when_the_server_runs_rules_that_are_not_erpc_tomls() {
        let listed =
            |m: &Manifest, server: &Value| super::listed(m, "prod", "203.0.113.10", server, SCOPE);
        // erpc.toml's `[waf]` was tightened since the deploy that put the
        // server's in place.
        let tightened = app(
            "[waf]\nport = 8080\ndeny_paths = [\"/admin/*\"]\n",
            EVERYONE,
        );
        let said = listed(&tightened, &shown());
        assert!(
            said.ends_with(
                "\n  blocked by rule: probe 7, rate 5, banned 3\n\
                 WAF: the rules it runs are not erpc.toml's; `erpc worker deploy --env prod` \
                 puts erpc.toml's in place, and until then its port is not opened wider"
            ),
            "{said}"
        );
        // The same rules: nothing is said of it.
        assert!(!listed(&app(WAF, EVERYONE), &shown()).contains("are not erpc.toml's"));
        // An agent from before it reported the config it runs.
        let mut older = shown();
        older["waf"]
            .as_object_mut()
            .expect("the WAF")
            .remove("config");
        let said = listed(&app(WAF, EVERYONE), &older);
        assert!(
            said.ends_with(
                "\nWAF: the server does not say which rules it runs (its agent is from before \
                 this erpc), so they are not taken for erpc.toml's; `erpc worker deploy --env \
                 prod` puts erpc.toml's in place, and until then its port is not opened wider"
            ),
            "{said}"
        );
        // The proxy there was started by an agent from before the one
        // installed, with the very config erpc.toml makes.
        let mut earlier = shown();
        earlier["waf"]["binary"] = "other".into();
        let said = listed(&app(WAF, EVERYONE), &earlier);
        assert!(
            said.ends_with(
                "\n  blocked by rule: probe 7, rate 5, banned 3\n\
                 WAF: it was started by an earlier agent than the one installed, or the server \
                 could not tell which, so the rules it runs are not taken for erpc.toml's; `erpc \
                 worker deploy --env prod` restarts it, and until then its port is not opened \
                 wider"
            ),
            "{said}"
        );
        // The proxy there was started before its config or its unit last
        // changed.
        let mut before = shown();
        before["waf"]["started"] = "before_config".into();
        let said = listed(&app(WAF, EVERYONE), &before);
        assert!(
            said.ends_with(
                "\n  blocked by rule: probe 7, rate 5, banned 3\n\
                 WAF: it was started before its config or its unit on the server last changed, \
                 or a deploy that was writing them was ended before it restarted the WAF, or the \
                 server could not tell when it was started, so the rules it runs are not taken \
                 for erpc.toml's; `erpc worker deploy --env prod` restarts it, and until then \
                 its port is not opened wider"
            ),
            "{said}"
        );
        // erpc.toml has no `[waf]` any more, and the server still has one.
        let said = listed(&app("", ""), &shown());
        assert!(
            said.ends_with(
                "\nWAF: erpc.toml has no [waf] any more; `erpc worker deploy --env prod` \
                 removes the one on the server"
            ),
            "{said}"
        );
    }

    /// What `firewall-show` answers: the WAF as `waf` has it, and this
    /// worker's opening in force (none when its port is closed).
    fn server(waf: &Value, in_force: Option<&Opening>) -> Recorded {
        Recorded::with(waf, "bot-prod", in_force)
    }

    fn opening(port: u16, allow: &[&str]) -> Opening {
        Opening {
            port,
            allow: allow
                .iter()
                .map(|a| Cidr::parse_any(a).expect("an address"))
                .collect(),
            limit: Some(erpc_worker::server::NewConnections::DEFAULT),
            udp: None,
        }
    }

    const QUIET: Say = Say { quiet: true };
    /// What `allow`, `deny` and `sync` ask: the record alone.
    const ASK: super::Ask<'static> = super::Ask::from_record(SCOPE);
    const ONE: &str = "\"198.51.100.7\"";

    #[test]
    #[allow(clippy::too_many_lines, reason = "one table of cases")]
    fn the_wafs_port_is_never_opened_wider_under_rules_that_are_not_erpc_tomls() {
        let m = app(WAF, EVERYONE);
        let config = m.waf_config("prod").expect("a config");
        let wanted = Opening::for_app(&m, &m.env["prod"]);
        let everyone = wanted.clone().expect("an opening");
        let one = opening(8080, &["198.51.100.7"]);
        let two = opening(8080, &["198.51.100.7", "203.0.113.0/24"]);
        // What an earlier deploy left running: the same port, other rules.
        let mut earlier = config.clone();
        earlier.deny_paths = Vec::new();
        earlier.allow_paths = vec!["/old/*".to_owned()];
        assert_ne!(earlier, config);
        let (asked, other) = (running(&config), running(&earlier));
        let held = |why| {
            Some(Held {
                opening: everyone.clone(),
                why,
            })
        };

        // No WAF on the server, or one that does not run: closed, whatever
        // was open, and what is wanted held.
        let mut stopped = asked.clone();
        stopped["active"] = false.into();
        stopped["state"] = "failed".into();
        for none in [Value::Null, stopped] {
            assert_eq!(
                super::decide(wanted.clone(), &config, &none, Some(&one)),
                Decision {
                    apply: None,
                    held: held(Why::NoWaf)
                }
            );
        }
        // It runs the config erpc.toml makes: opened as erpc.toml asks.
        assert_eq!(
            super::decide(wanted.clone(), &config, &asked, Some(&one)),
            Decision {
                apply: wanted.clone(),
                held: None
            }
        );
        // It runs another: the opening in force stays as it is, open to
        // one address or closed, and what is wanted is held.
        assert_eq!(
            super::decide(wanted.clone(), &config, &other, Some(&one)),
            Decision {
                apply: Some(one.clone()),
                held: held(Why::OtherRules)
            }
        );
        assert_eq!(
            super::decide(wanted.clone(), &config, &other, None),
            Decision {
                apply: None,
                held: held(Why::OtherRules)
            }
        );
        // So does an agent that does not say which config it runs, one
        // whose config does not read, and one that reports something that
        // is not a config.
        let mut unsaid = asked.clone();
        unsaid.as_object_mut().expect("the WAF").remove("config");
        let mut unread = asked.clone();
        unread["config"] = Value::Null;
        let mut odd = asked.clone();
        odd["config"] = json!({ "listen": "0.0.0.0:8080" });
        for (not_known, why) in [
            (unsaid, Why::UnsaidRules),
            (unread, Why::OtherRules),
            (odd, Why::OtherRules),
        ] {
            assert_eq!(
                super::decide(wanted.clone(), &config, &not_known, Some(&one)),
                Decision {
                    apply: Some(one.clone()),
                    held: held(why)
                },
                "{not_known}"
            );
        }
        // And so does the very config erpc.toml makes in a proxy that is
        // not the agent installed on the server (an earlier one started
        // it), or that the server cannot tell of: what runs is not known
        // to be what the file reads as.
        for binary in ["other", "unknown"] {
            let mut earlier_agent = asked.clone();
            earlier_agent["binary"] = binary.into();
            assert_eq!(
                super::decide(wanted.clone(), &config, &earlier_agent, Some(&one)),
                Decision {
                    apply: Some(one.clone()),
                    held: held(Why::EarlierAgent)
                },
                "{binary}"
            );
            assert_eq!(
                super::decide(wanted.clone(), &config, &earlier_agent, None),
                Decision {
                    apply: None,
                    held: held(Why::EarlierAgent)
                },
                "{binary}"
            );
            // Narrowing is applied under it as under other rules.
            assert_eq!(
                super::decide(Some(one.clone()), &config, &earlier_agent, Some(&two)),
                Decision {
                    apply: Some(one.clone()),
                    held: None
                },
                "{binary}"
            );
        }
        // And so does that config in a proxy started before the file was
        // last changed, or that the server cannot tell of: what runs is
        // the file from before.
        for started in ["before_config", "unknown"] {
            let mut before_config = asked.clone();
            before_config["started"] = started.into();
            assert_eq!(
                super::decide(wanted.clone(), &config, &before_config, Some(&one)),
                Decision {
                    apply: Some(one.clone()),
                    held: held(Why::BeforeConfig)
                },
                "{started}"
            );
            assert_eq!(
                super::decide(wanted.clone(), &config, &before_config, None),
                Decision {
                    apply: None,
                    held: held(Why::BeforeConfig)
                },
                "{started}"
            );
            // Narrowing is applied under it as under other rules.
            assert_eq!(
                super::decide(Some(one.clone()), &config, &before_config, Some(&two)),
                Decision {
                    apply: Some(one.clone()),
                    held: None
                },
                "{started}"
            );
        }
        // One more address, a network that holds the one in force, the
        // same addresses on another port: each lets someone new in, or
        // may, and is held.
        for wider in [
            two.clone(),
            opening(8080, &["198.51.100.0/24"]),
            opening(9090, &["198.51.100.7"]),
        ] {
            let decided = super::decide(Some(wider.clone()), &config, &other, Some(&one));
            assert_eq!(decided.apply, Some(one.clone()), "{wider:?}");
            assert_eq!(decided.held.map(|h| h.opening), Some(wider));
        }
        // A change that only narrows is applied at once, under whatever
        // rules: closing the port, taking an address off, the same list.
        for (narrower, from) in [
            (None, Some(&two)),
            (None, None),
            (Some(one.clone()), Some(&two)),
            (Some(two.clone()), Some(&two)),
        ] {
            assert_eq!(
                super::decide(narrower.clone(), &config, &other, from),
                Decision {
                    apply: narrower,
                    held: None
                }
            );
        }
        // What is narrowed keeps the limit on new connections in force:
        // erpc.toml's own, here none at all, comes with its rules.
        let unlimited = Opening {
            limit: None,
            ..one.clone()
        };
        assert_eq!(
            super::decide(Some(unlimited.clone()), &config, &other, Some(&two)),
            Decision {
                apply: Some(one.clone()),
                held: None
            }
        );
        // Under erpc.toml's rules its limit is the one applied.
        assert_eq!(
            super::decide(Some(unlimited.clone()), &config, &asked, Some(&two)).apply,
            Some(unlimited)
        );
        // With the rules erpc.toml makes, nobody listed is the port closed.
        assert_eq!(
            super::decide(None, &config, &asked, Some(&one)),
            Decision {
                apply: None,
                held: None
            }
        );
    }

    #[test]
    fn a_sync_asks_the_server_what_runs_there_and_applies_only_what_was_decided() {
        let me = Some("198.51.100.7".parse().expect("an address"));
        let m = app(WAF, EVERYONE);
        let env = &m.env["prod"];
        let config = m.waf_config("prod").expect("a config");
        let everyone = Opening::for_app(&m, env).expect("an opening");
        let one = opening(8080, &["198.51.100.7"]);

        // No WAF on the server yet: the port is closed, not opened.
        let none = server(&Value::Null, None);
        let synced = super::sync(&none, &m, "prod", env, me, ASK, &QUIET).expect("synced");
        assert_eq!(
            none.asked(),
            ["allow-ssh 198.51.100.7", "firewall-show", "close"]
        );
        assert_eq!(synced.opening, None);
        assert_eq!(
            synced.held,
            Some(Held {
                opening: everyone.clone(),
                why: Why::NoWaf
            })
        );

        // The WAF there runs an earlier deploy's rules, with the port open
        // to one address: it stays open to that address and no other.
        let mut earlier = config.clone();
        earlier.deny_paths = vec!["/old/*".to_owned()];
        let other = server(&running(&earlier), Some(&one));
        let synced = super::sync(&other, &m, "prod", env, me, ASK, &QUIET).expect("synced");
        assert_eq!(
            other.asked(),
            [
                "allow-ssh 198.51.100.7",
                "firewall-show",
                "open 8080 to 198.51.100.7/32, limit 50/100"
            ]
        );
        assert_eq!(synced.opening, Some(one.clone()));
        assert_eq!(
            synced.held,
            Some(Held {
                opening: everyone.clone(),
                why: Why::OtherRules
            })
        );
        // Closing it is applied at once, under the same rules.
        let closing = app(WAF, "");
        let synced = super::sync(
            &other,
            &closing,
            "prod",
            &closing.env["prod"],
            me,
            ASK,
            &QUIET,
        )
        .expect("synced");
        assert_eq!(
            other.asked(),
            ["allow-ssh 198.51.100.7", "firewall-show", "close"]
        );
        assert!(synced.opening.is_none() && synced.held.is_none());

        // The WAF there runs erpc.toml's rules: opened as erpc.toml asks.
        let asked = server(&running(&config), Some(&one));
        let synced = super::sync(&asked, &m, "prod", env, me, ASK, &QUIET).expect("synced");
        assert_eq!(
            asked.asked(),
            [
                "allow-ssh 198.51.100.7",
                "firewall-show",
                "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
            ]
        );
        assert_eq!(synced.opening, Some(everyone));
        assert_eq!(synced.held, None);

        // An app with no WAF: its own port, as erpc.toml says, and the
        // server is not asked what runs there.
        let direct = app("", ONE);
        let plain = server(&Value::Null, None);
        let synced = super::sync(
            &plain,
            &direct,
            "prod",
            &direct.env["prod"],
            me,
            ASK,
            &QUIET,
        )
        .expect("synced");
        assert_eq!(
            plain.asked(),
            ["allow-ssh 198.51.100.7", "open 3000 to 198.51.100.7/32"]
        );
        assert!(synced.held.is_none());

        // A server that does not say which openings are in force: nothing
        // is opened or closed.
        let silent = Recorded::showing(json!({ "ok": true, "waf": running(&config) }));
        let refused = super::sync(&silent, &m, "prod", env, me, ASK, &QUIET)
            .err()
            .expect("refused");
        assert_eq!(silent.asked(), ["allow-ssh 198.51.100.7", "firewall-show"]);
        assert!(
            refused
                .message
                .starts_with("the server did not say which opening is in force for bot-prod; "),
            "{}",
            refused.message
        );
        let mut garbled = server(&running(&config), None);
        garbled.shown["openings"]["bot-prod"] = json!({ "port": "8080" });
        assert!(super::sync(&garbled, &m, "prod", env, me, ASK, &QUIET).is_err());
        assert_eq!(garbled.asked(), ["allow-ssh 198.51.100.7", "firewall-show"]);
    }

    #[test]
    fn a_sync_says_which_port_it_opens_holds_or_leaves_closed() {
        let m = app(WAF, EVERYONE);
        let opening = Opening::for_app(&m, &m.env["prod"]).expect("an opening");
        let decided = |apply: Option<&Opening>, why: Option<Why>| Decision {
            apply: apply.cloned(),
            held: why.map(|why| Held {
                opening: opening.clone(),
                why,
            }),
        };
        assert_eq!(
            super::dropping(Some(8080), &decided(Some(&opening), None), false, ""),
            "dropping every other inbound connection; the WAF's port 8080 open to 0.0.0.0/0, \
             ::/0, new connections over 50 a second from one address dropped (burst 100)"
        );
        assert_eq!(
            super::dropping(Some(8080), &decided(None, Some(Why::NoWaf)), false, ""),
            "dropping every other inbound connection; the WAF's port 8080 stays closed until \
             the WAF listens there"
        );
        assert_eq!(
            super::dropping(Some(8080), &decided(None, None), false, ""),
            "dropping every other inbound connection; the WAF's port 8080 stays closed: \
             firewall.app_allow lists nobody"
        );
        // Held under rules that are not erpc.toml's: left open to those it
        // was open to, or closed.
        let one = self::opening(8080, &["198.51.100.7"]);
        assert_eq!(
            super::dropping(
                Some(8080),
                &decided(Some(&one), Some(Why::OtherRules)),
                false,
                ""
            ),
            "dropping every other inbound connection; the WAF on the server runs rules that \
             are not erpc.toml's, so port 8080 stays open to 198.51.100.7/32 and no wider until \
             a deploy puts erpc.toml's in place"
        );
        assert_eq!(
            super::dropping(Some(8080), &decided(None, Some(Why::OtherRules)), false, ""),
            "dropping every other inbound connection; the WAF on the server runs rules that \
             are not erpc.toml's, so the WAF's port 8080 stays closed until a deploy puts \
             erpc.toml's in place"
        );
        assert_eq!(
            super::dropping(
                Some(8080),
                &decided(Some(&one), Some(Why::UnsaidRules)),
                false,
                ""
            ),
            "dropping every other inbound connection; the server does not say which rules \
             its WAF runs (its agent is from before this erpc), so they are not taken for \
             erpc.toml's, so port 8080 stays open to 198.51.100.7/32 and no wider until a \
             deploy puts erpc.toml's in place"
        );
        assert_eq!(
            super::dropping(
                Some(8080),
                &decided(Some(&one), Some(Why::EarlierAgent)),
                false,
                ""
            ),
            "dropping every other inbound connection; the WAF on the server was started by an \
             earlier agent than the one installed there, or the server could not tell which, so \
             what it runs is not taken for erpc.toml's rules, so port 8080 stays open to \
             198.51.100.7/32 and no wider until a deploy puts erpc.toml's in place"
        );
        assert_eq!(
            super::dropping(
                Some(8080),
                &decided(Some(&one), Some(Why::BeforeConfig)),
                false,
                ""
            ),
            "dropping every other inbound connection; the WAF on the server was started before \
             its config or its unit there last changed, or a deploy that was writing them was \
             ended before it restarted the WAF, or the server could not tell when it was \
             started, so what it runs is not taken for erpc.toml's rules, so port 8080 stays \
             open to 198.51.100.7/32 and no wider until a deploy puts erpc.toml's in place"
        );
        // An app's own port, as it was said before.
        let direct = app("", "\"198.51.100.0/24\"");
        let own = Opening::for_app(&direct, &direct.env["prod"]).expect("an opening");
        assert_eq!(
            super::dropping(None, &decided(Some(&own), None), false, ""),
            "dropping every other inbound connection; port 3000 open to 198.51.100.0/24"
        );
        assert_eq!(
            super::dropping(None, &decided(None, None), false, ""),
            "dropping every other inbound connection; the app's port stays closed"
        );
    }

    #[test]
    fn the_report_says_what_the_wafs_port_is_now() {
        let m = app(WAF, EVERYONE);
        let opening = Opening::for_app(&m, &m.env["prod"]);
        let synced = |opening: Option<Opening>| Synced {
            ssh_allow: Vec::new(),
            wanted: opening.clone(),
            opening,
            held: None,
            in_account: false,
        };
        assert_eq!(
            super::port_said(&m, &synced(opening)),
            "the WAF's port 8080 from 0.0.0.0/0, ::/0"
        );
        assert_eq!(
            super::port_said(&m, &synced(None)),
            "the WAF's port 8080 closed (firewall.app_allow lists nobody)"
        );
        let direct = app("", "");
        assert_eq!(
            super::port_said(&direct, &synced(None)),
            "the app's port closed"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "one case after another")]
    fn a_held_port_ends_allow_deny_and_sync_with_a_failure_that_names_the_deploy() {
        use erpc_ssh::worker::UnitId;
        let m = app(WAF, EVERYONE);
        let id = UnitId::new("bot-prod").expect("id");
        let everyone = Opening::for_app(&m, &m.env["prod"]).expect("an opening");
        let one = opening(8080, &["198.51.100.7"]);
        let synced = |opening: Option<Opening>, why| Synced {
            ssh_allow: vec!["198.51.100.7".parse().expect("an address")],
            wanted: Some(everyone.clone()),
            opening,
            held: Some(Held {
                opening: everyone.clone(),
                why,
            }),
            in_account: false,
        };
        // Held under other rules, the port left open to one address.
        let kept = synced(Some(one.clone()), Why::OtherRules);
        let failed = super::report(false, &id, &m, &kept, SCOPE).expect_err("held");
        assert_eq!(failed.code, Code::Failed);
        assert_eq!(
            failed.message,
            "the WAF's port 8080 was not opened to 0.0.0.0/0, ::/0: the WAF on the server runs \
             rules that are not erpc.toml's, and its port is not opened wider meanwhile, so \
             port 8080 stays open to 198.51.100.7/32 and no wider. The rest of bot-prod's \
             server firewall is in force: SSH from 198.51.100.7, everything else dropped"
        );
        assert_eq!(
            failed.hint.as_deref(),
            Some(
                "`erpc worker deploy --env prod` puts erpc.toml's rules in place, then opens \
                 the port to the list of who may reach the app"
            )
        );
        // What a script reads: the same facts, under --json too.
        let under_json = super::report(true, &id, &m, &kept, SCOPE).expect_err("held");
        assert_eq!(under_json, failed);
        assert_eq!(
            failed.details,
            Some(json!({
                "worker": "bot-prod",
                "ssh_allow": ["198.51.100.7"],
                "opening": one,
                "held": everyone,
                "held_because": "other_rules",
                "new_connections_kept": null,
            }))
        );
        // Held because the server's agent does not say which rules run.
        let unsaid = synced(None, Why::UnsaidRules);
        let failed = super::report(false, &id, &m, &unsaid, SCOPE).expect_err("held");
        assert_eq!(
            failed.message,
            "the WAF's port 8080 was not opened to 0.0.0.0/0, ::/0: the server does not say \
             which rules its WAF runs (its agent is from before this erpc), so they are not \
             taken for erpc.toml's, and its port is not opened wider meanwhile, so the WAF's \
             port 8080 stays closed. The rest of bot-prod's server firewall is in force: SSH \
             from 198.51.100.7, everything else dropped"
        );
        assert!(
            failed
                .hint
                .is_some_and(|h| h.starts_with("`erpc worker deploy --env prod` "))
        );
        assert_eq!(
            failed.details.expect("details")["held_because"],
            "unreported_rules"
        );
        // Held because the proxy there is not the agent installed.
        let earlier = synced(Some(one.clone()), Why::EarlierAgent);
        let failed = super::report(false, &id, &m, &earlier, SCOPE).expect_err("held");
        assert_eq!(
            failed.message,
            "the WAF's port 8080 was not opened to 0.0.0.0/0, ::/0: the WAF on the server was \
             started by an earlier agent than the one installed there, or the server could not \
             tell which, so what it runs is not taken for erpc.toml's rules, and its port is not \
             opened wider meanwhile, so port 8080 stays open to 198.51.100.7/32 and no wider. \
             The rest of bot-prod's server firewall is in force: SSH from 198.51.100.7, \
             everything else dropped"
        );
        assert_eq!(
            failed.hint.as_deref(),
            Some(
                "`erpc worker deploy --env prod` restarts the WAF as the agent installed, with \
                 erpc.toml's rules, then opens the port to the list of who may reach the app"
            )
        );
        assert_eq!(
            failed.details.expect("details")["held_because"],
            "earlier_agent"
        );
        // Held because the proxy there was started before its config or
        // its unit last changed: the deploy named puts erpc.toml's rules
        // in place, by restarting it.
        let before = synced(Some(one.clone()), Why::BeforeConfig);
        let failed = super::report(false, &id, &m, &before, SCOPE).expect_err("held");
        assert_eq!(
            failed.message,
            "the WAF's port 8080 was not opened to 0.0.0.0/0, ::/0: the WAF on the server was \
             started before its config or its unit there last changed, or a deploy that was \
             writing them was ended before it restarted the WAF, or the server could not tell \
             when it was started, so what it runs is not taken for erpc.toml's rules, and its \
             port is not opened wider meanwhile, so port 8080 stays open to 198.51.100.7/32 \
             and no wider. The rest of bot-prod's server firewall is in force: SSH from \
             198.51.100.7, everything else dropped"
        );
        assert_eq!(
            failed.hint.as_deref(),
            Some(
                "`erpc worker deploy --env prod` puts erpc.toml's rules in place, then opens \
                 the port to the list of who may reach the app"
            )
        );
        assert_eq!(
            failed.details.expect("details")["held_because"],
            "before_config"
        );
        // Held because no WAF runs there yet.
        let closed = synced(None, Why::NoWaf);
        let failed = super::report(false, &id, &m, &closed, SCOPE).expect_err("held");
        assert_eq!(
            failed.message,
            "the WAF's port 8080 was not opened to 0.0.0.0/0, ::/0: no WAF listens on it yet, \
             and it stays closed until one does. The rest of bot-prod's server firewall is in \
             force: SSH from 198.51.100.7, everything else dropped"
        );
        assert_eq!(
            failed.hint.as_deref(),
            Some(
                "`erpc worker deploy --env prod` starts the WAF, then opens the port to the \
                 list of who may reach the app"
            )
        );
        assert_eq!(failed.details.expect("details")["held_because"], "no_waf");
        // Nothing held: the firewall is in force, and that is success.
        let open = Synced {
            held: None,
            in_account: false,
            ..synced(Some(everyone.clone()), Why::NoWaf)
        };
        assert!(super::report(false, &id, &m, &open, SCOPE).is_ok());
    }

    #[test]
    fn a_narrowing_that_kept_the_limit_in_force_says_so_and_is_no_failure() {
        use erpc_ssh::worker::UnitId;
        let me = Some("198.51.100.7".parse().expect("an address"));
        let id = UnitId::new("bot-prod").expect("id");
        // What the last deploy left: its rules, and the port open to two,
        // with the default limit on new connections.
        let last = app(WAF, "\"198.51.100.7\", \"203.0.113.0/24\"");
        let on_server = running(&last.waf_config("prod").expect("a config"));
        let two = Opening::for_app(&last, &last.env["prod"]).expect("an opening");
        let tighter = "[waf]\nport = 8080\ndeny_paths = [\"/admin/*\"]\n";

        // `[waf]` was tightened, with a limit of its own, and one address
        // taken off: the narrowing is applied, with the limit in force.
        let m = app(
            &format!("{tighter}new_connections = {{ per_second = 5, burst = 10 }}\n"),
            ONE,
        );
        let server = self::server(&on_server, Some(&two));
        let synced =
            super::sync(&server, &m, "prod", &m.env["prod"], me, ASK, &QUIET).expect("synced");
        assert_eq!(
            server.asked(),
            [
                "allow-ssh 198.51.100.7",
                "firewall-show",
                "open 8080 to 198.51.100.7/32, limit 50/100"
            ]
        );
        assert_eq!(
            super::in_force_said("bot-prod", &m, &synced, SCOPE),
            "bot-prod's server firewall is in force: SSH from 198.51.100.7; the WAF's port 8080 \
             from 198.51.100.7/32; everything else dropped.\n\
             warning: port 8080 keeps the limit on new connections that is in force (50 a second \
             from one address, burst 100), not erpc.toml's (5 a second from one address, burst \
             10): erpc.toml's comes with its rules, which the WAF on the server is not known to \
             run yet; `erpc worker deploy --env prod` puts both in place"
        );
        // It did what was asked: no failure, and --json carries the two.
        assert!(super::report(false, &id, &m, &synced, SCOPE).is_ok());
        let body = super::reported("bot-prod", &synced);
        assert_eq!(
            body["new_connections_kept"],
            json!({
                "in_force": { "per_second": 50, "burst": 100 },
                "erpc_toml": { "per_second": 5, "burst": 10 },
            })
        );
        assert_eq!(
            body["opening"]["limit"],
            json!({ "per_second": 50, "burst": 100 })
        );
        assert!(body["held"].is_null() && body["held_because"].is_null());
        // `status` and `firewall list` say meanwhile that the rules there
        // are not erpc.toml's, with the deploy that applies both.
        let rules = "WAF: the rules it runs are not erpc.toml's; `erpc worker deploy --env prod` \
                     puts erpc.toml's in place, and until then its port is not opened wider";
        assert!(
            super::listed(&m, "prod", "203.0.113.10", &server.shown, SCOPE).ends_with(rules),
            "firewall list"
        );
        assert_eq!(
            crate::worker::waf::status_lines(&m, "prod", &server.shown["waf"], SCOPE)[1],
            rules,
            "status"
        );

        // erpc.toml gives no limit, or the server has none: said as none.
        let off = app(&format!("{tighter}new_connections = false\n"), ONE);
        let synced =
            super::sync(&server, &off, "prod", &off.env["prod"], me, ASK, &QUIET).expect("synced");
        assert!(
            super::in_force_said("bot-prod", &off, &synced, SCOPE).contains(
                "that is in force (50 a second from one address, burst 100), not erpc.toml's \
                 (none): "
            )
        );
        assert_eq!(
            super::reported("bot-prod", &synced)["new_connections_kept"],
            json!({ "in_force": { "per_second": 50, "burst": 100 }, "erpc_toml": null })
        );
        let unlimited = Opening {
            limit: None,
            ..two.clone()
        };
        let none = self::server(&on_server, Some(&unlimited));
        let synced =
            super::sync(&none, &m, "prod", &m.env["prod"], me, ASK, &QUIET).expect("synced");
        assert_eq!(
            none.asked()[2],
            "open 8080 to 198.51.100.7/32",
            "narrowed, and still without one"
        );
        assert!(
            super::in_force_said("bot-prod", &m, &synced, SCOPE)
                .contains("that is in force (none), not erpc.toml's (5 a second from one address")
        );

        // What a deploy says of it at its last step, once the rules are
        // erpc.toml's: the port stays open to the same, with the limit
        // erpc.toml gives, or without one.
        let synced =
            super::sync(&server, &m, "prod", &m.env["prod"], me, ASK, &QUIET).expect("synced");
        assert_eq!(
            super::asked_said(&synced).as_deref(),
            Some(
                "the WAF runs erpc.toml's rules now: port 8080 stays open to 198.51.100.7/32, \
                 new connections over 5 a second from one address dropped (burst 10)"
            )
        );
        let synced =
            super::sync(&server, &off, "prod", &off.env["prod"], me, ASK, &QUIET).expect("synced");
        assert_eq!(
            super::asked_said(&synced).as_deref(),
            Some(
                "the WAF runs erpc.toml's rules now: port 8080 stays open to 198.51.100.7/32, \
                 with no limit on new connections any more"
            )
        );
        server.asked();

        // The limit in force is erpc.toml's: one line, and nothing kept.
        let same = app(tighter, ONE);
        let synced = super::sync(&server, &same, "prod", &same.env["prod"], me, ASK, &QUIET)
            .expect("synced");
        let said = super::in_force_said("bot-prod", &same, &synced, SCOPE);
        assert!(!said.contains('\n'), "{said}");
        assert!(super::reported("bot-prod", &synced)["new_connections_kept"].is_null());
        assert_eq!(super::asked_said(&synced), None);
        // So is it under erpc.toml's rules, which have erpc.toml's limit
        // applied, and for a port that is closed.
        let asked = self::server(
            &running(&m.waf_config("prod").expect("a config")),
            Some(&two),
        );
        let synced =
            super::sync(&asked, &m, "prod", &m.env["prod"], me, ASK, &QUIET).expect("synced");
        assert_eq!(asked.asked()[2], "open 8080 to 198.51.100.7/32, limit 5/10");
        assert_eq!(synced.limit_kept(), None);
        let closed = app(tighter, "");
        let synced = super::sync(
            &server,
            &closed,
            "prod",
            &closed.env["prod"],
            me,
            ASK,
            &QUIET,
        )
        .expect("synced");
        assert_eq!(synced.limit_kept(), None);

        // And for an opening that was held, which is said as that: the
        // limit in force differs from erpc.toml's there too, and nothing
        // is said to have been kept beside what was held.
        let wider = app(
            &format!("{tighter}new_connections = {{ per_second = 5, burst = 10 }}\n"),
            EVERYONE,
        );
        let synced = super::sync(&server, &wider, "prod", &wider.env["prod"], me, ASK, &QUIET)
            .expect("synced");
        assert_eq!(
            synced.held.as_ref().map(|held| held.why),
            Some(Why::OtherRules)
        );
        assert_ne!(
            synced.wanted.as_ref().and_then(|o| o.limit),
            synced.opening.as_ref().and_then(|o| o.limit)
        );
        assert_eq!(synced.limit_kept(), None);
        let body = super::reported("bot-prod", &synced);
        assert!(body["new_connections_kept"].is_null(), "{body}");
        assert_eq!(body["held_because"], "other_rules");

        // In every language, with the command as it is typed.
        let synced =
            super::sync(&server, &m, "prod", &m.env["prod"], me, ASK, &QUIET).expect("synced");
        let english = super::in_force_said("bot-prod", &m, &synced, SCOPE);
        let english_asked = super::asked_said(&synced).expect("a line");
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let (said, asked) = crate::cli::i18n::speaking(lang, || {
                (
                    super::in_force_said("bot-prod", &m, &synced, SCOPE),
                    super::asked_said(&synced).expect("a line"),
                )
            });
            let (_, kept) = said.split_once("\nwarning: ").expect("the second line");
            assert!(
                kept.contains("`erpc worker deploy --env prod`") && !kept.contains('{'),
                "{kept}"
            );
            assert!(kept.contains("8080") && kept.contains("100") && kept.contains("10"));
            assert_ne!(said, english);
            assert!(
                asked.contains("8080") && asked.contains("198.51.100.7/32") && !asked.contains('{'),
                "{asked}"
            );
            assert_ne!(asked, english_asked);
        }
    }

    #[test]
    fn allow_refuses_everyone_to_an_app_with_no_waf_before_anything_is_changed() {
        let direct = app("", ONE);
        let env = &direct.env["prod"];
        let everyone = ["0.0.0.0/0".to_owned()];
        let refused = super::edited(false, env, Port::App, &everyone, true).expect_err("refused");
        assert_eq!(refused.code, Code::Usage);
        assert_eq!(
            refused.message,
            "0.0.0.0/0 lets every address in, and erpc opens only a WAF's port to everyone; \
             this app has no [waf]"
        );
        // Behind a WAF it is added to the list.
        let allowed = super::edited(true, env, Port::App, &everyone, true)
            .expect("allowed")
            .expect("a change");
        assert_eq!(
            crate::worker::waf::addresses(&allowed.firewall.app_allow),
            "198.51.100.7/32, 0.0.0.0/0"
        );
        assert_eq!(allowed.firewall.ssh_allow, env.firewall.ssh_allow);
        // Taking it off a list that has it is no widening, WAF or not;
        // off one that does not, or on one that does, nothing changes.
        assert!(
            super::edited(false, &allowed, Port::App, &everyone, false)
                .expect("denied")
                .is_some_and(|env| env.firewall.app_allow.len() == 1)
        );
        assert_eq!(
            super::edited(false, env, Port::App, &everyone, false),
            Ok(None)
        );
        let listed = ["198.51.100.7".to_owned()];
        assert_eq!(
            super::edited(false, env, Port::App, &listed, true),
            Ok(None)
        );
        // SSH takes single addresses, and never everyone.
        for network in [["198.51.100.0/24".to_owned()], everyone.clone()] {
            let refused = super::edited(true, env, Port::Ssh, &network, true).expect_err("ssh");
            assert_eq!(refused.code, Code::Usage, "{network:?}");
        }
        assert!(super::edited(true, env, Port::App, &["nonsense".to_owned()], true).is_err());
    }

    /// `allow` of an address that is let in already, and `deny` of one
    /// that is not: nothing changes, and that is said as text, or under
    /// `--json` as JSON, as every other answer of the two is.
    #[test]
    fn nothing_to_change_is_said_as_text_and_under_json_as_json() {
        use crate::account::commands::Said;
        use crate::cli::i18n::speaking;
        crate::cli::ui::force_drawn(false);
        let m = app("", ONE);
        let env = &m.env["prod"];
        let (listed, absent) = (["198.51.100.7".to_owned()], ["203.0.113.9".to_owned()]);
        let said = |json, addresses: &[String], allow| {
            // What the command comes to before it says this: no change.
            assert_eq!(
                super::edited(false, env, Port::App, addresses, allow),
                Ok(None)
            );
            super::unchanged(json, "bot-prod", env, addresses, allow, SCOPE)
        };
        let again = "`erpc worker firewall sync --env prod` applies erpc.toml again";
        let allowed = said(false, &listed, true);
        assert_eq!(
            allowed,
            Said::Text(format!(
                "nothing to change: 198.51.100.7 is allowed already; {again}"
            ))
        );
        let denied = said(false, &absent, false);
        assert_eq!(
            denied,
            Said::Text(format!(
                "nothing to change: 203.0.113.9 is not allowed already; {again}"
            ))
        );
        // Under --json: that nothing changed, and the lists erpc.toml has.
        // Nothing of what is in force on the server, which was not asked.
        let body = json!({
            "worker": "bot-prod",
            "changed": false,
            "erpc_toml": {
                "ssh_allow": ["198.51.100.7/32"],
                "app_allow": ["198.51.100.7/32"],
            },
        });
        assert_eq!(said(true, &listed, true), Said::Json(body.clone()));
        assert_eq!(said(true, &absent, false), Said::Json(body));
        // The text follows the language of the run; the JSON does not.
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            for (english, addresses, allow) in
                [(&allowed, &listed, true), (&denied, &absent, false)]
            {
                let Said::Text(there) = speaking(lang, || said(false, addresses, allow)) else {
                    panic!("{lang:?}: not text");
                };
                assert_ne!(Said::Text(there.clone()), *english, "{lang:?}");
                assert!(
                    there.contains("`erpc worker firewall sync --env prod`"),
                    "{there}"
                );
                assert!(
                    there.contains(&addresses[0]) && !there.contains('{'),
                    "{there}"
                );
            }
        }
    }

    /// The answer `allow` and `deny` give to a change says `changed`, in
    /// force or held; `sync`, which changes no list, has no such field.
    #[test]
    fn an_answer_to_a_change_says_that_erpc_toml_changed() {
        use erpc_ssh::worker::UnitId;
        let m = app(WAF, EVERYONE);
        let id = UnitId::new("bot-prod").expect("an id");
        let opening = Opening::for_app(&m, &m.env["prod"]);
        let in_force = Synced {
            ssh_allow: vec!["198.51.100.7".parse().expect("an address")],
            wanted: opening.clone(),
            opening: opening.clone(),
            held: None,
            in_account: false,
        };
        let synced = super::reported("bot-prod", &in_force);
        let changed = super::reported_change("bot-prod", &in_force);
        assert!(synced.get("changed").is_none(), "{synced}");
        assert_eq!(changed["changed"], true);
        // Beside it, the same facts.
        let mut rest = changed.clone();
        rest.as_object_mut().expect("an object").remove("changed");
        assert_eq!(rest, synced);
        // Held: erpc.toml has the change all the same, and the failure
        // carries it.
        let held = Synced {
            opening: None,
            held: Some(Held {
                opening: opening.expect("an opening"),
                why: Why::NoWaf,
            }),
            in_account: false,
            ..in_force
        };
        let body = super::reported_change("bot-prod", &held);
        let failed = super::report_as(true, &id, &m, &held, SCOPE, body).expect_err("held");
        let details = failed.details.expect("the facts");
        assert_eq!(details["changed"], true);
        assert_eq!(details["held_because"], "no_waf");
        let failed = super::report(true, &id, &m, &held, SCOPE).expect_err("held");
        assert!(failed.details.expect("the facts").get("changed").is_none());
    }

    #[test]
    fn everyone_is_let_in_to_an_app_behind_a_waf_only() {
        let everyone = [Cidr::parse_any("0.0.0.0/0").expect("everyone")];
        let v6 = [
            Cidr::parse("198.51.100.7").expect("one"),
            Cidr::parse_any("::/0").expect("everyone"),
        ];
        let some = [Cidr::parse("198.51.100.0/24").expect("net")];
        assert!(super::refuse_everyone(Port::App, &everyone, true).is_none());
        assert!(super::refuse_everyone(Port::App, &v6, true).is_none());
        assert!(super::refuse_everyone(Port::App, &some, false).is_none());
        let refused = super::refuse_everyone(Port::App, &everyone, false).expect("refused");
        assert_eq!(
            refused.message,
            "0.0.0.0/0 lets every address in, and erpc opens only a WAF's port to everyone; \
             this app has no [waf]"
        );
        assert!(
            refused
                .hint
                .is_some_and(|h| h.starts_with("add [waf] with a port")),
            "the way to open it to everyone"
        );
        let refused = super::refuse_everyone(Port::App, &v6, false).expect("refused");
        assert!(refused.message.starts_with("::/0 lets every address in"));
        // SSH is refused everyone by the check that it takes single
        // addresses, whatever the app has.
        assert!(super::refuse_everyone(Port::Ssh, &everyone, false).is_none());
    }

    #[test]
    fn what_is_said_of_a_wafs_port_follows_the_language_of_the_run() {
        let m = app(WAF, EVERYONE);
        let english = super::plan(&m.env["prod"], &m).join("\n");
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let wanted = Opening::for_app(&m, &m.env["prod"]).expect("an opening");
            let held = |why| Decision {
                apply: None,
                held: Some(Held {
                    opening: wanted.clone(),
                    why,
                }),
            };
            let (plan, held, kept, unsaid, earlier, before) =
                crate::cli::i18n::speaking(lang, || {
                    (
                        super::plan(&m.env["prod"], &m).join("\n"),
                        super::dropping(Some(8080), &held(Why::NoWaf), false, ""),
                        super::dropping(Some(8080), &held(Why::OtherRules), false, ""),
                        super::dropping(Some(8080), &held(Why::UnsaidRules), false, ""),
                        super::dropping(Some(8080), &held(Why::EarlierAgent), false, ""),
                        super::dropping(Some(8080), &held(Why::BeforeConfig), false, ""),
                    )
                });
            assert_ne!(plan, english);
            assert!(plan.contains("  waf 8080  0.0.0.0/0, ::/0"), "{plan}");
            for said in [&plan, &held, &kept, &unsaid, &earlier, &before] {
                assert!(!said.contains('{'), "{said}");
                assert!(said.contains("8080"), "{said}");
            }
            assert!(
                held != kept && kept != unsaid && unsaid != earlier && kept != earlier,
                "{held}\n{kept}\n{unsaid}\n{earlier}"
            );
            assert!(
                ![&held, &kept, &unsaid, &earlier].contains(&&before),
                "{before}"
            );
            // The hint for a proxy an earlier agent started names the
            // deploy as it is typed.
            let synced = Synced {
                ssh_allow: Vec::new(),
                wanted: Some(wanted.clone()),
                opening: None,
                held: Some(Held {
                    opening: wanted.clone(),
                    why: Why::EarlierAgent,
                }),
                in_account: false,
            };
            let hint = crate::cli::i18n::speaking(lang, || {
                let held = synced.held.as_ref().expect("held");
                super::held_back("bot-prod", &synced, held, SCOPE).hint
            })
            .expect("a hint");
            assert!(
                hint.contains("`erpc worker deploy --env prod`") && !hint.contains('{'),
                "{hint}"
            );
        }
    }

    /// What the hint for a port held behind a note says, in each
    /// language's own words: "as root", removing the path (not only the
    /// parenthesis that only root can), and that a deploy after a change
    /// to `[waf]` or `run.port` fails.
    const HELD_NOTE: [(Lang, &str, &str); 3] = [
        (
            Lang::Ja,
            "root で削除",
            "[waf] か run.port を変えたデプロイ",
        ),
        (
            Lang::Zh,
            "以 root 身份删除",
            "改动 [waf] 或 run.port 后的部署",
        ),
        (
            Lang::Ru,
            "от имени root",
            "развёртывание после изменения [waf] или run.port",
        ),
    ];

    #[allow(
        clippy::too_many_lines,
        reason = "one scene, the note the server keeps and every way it is said"
    )]
    #[test]
    fn a_port_held_behind_a_note_no_deploy_removes_names_the_path_to_remove_as_root() {
        use erpc_ssh::worker::UnitId;
        let m = app(WAF, EVERYONE);
        let config = m.waf_config("prod").expect("a config");
        let wanted = Opening::for_app(&m, &m.env["prod"]);
        let everyone = wanted.clone().expect("an opening");
        let (one, two) = (
            opening(8080, &["198.51.100.7"]),
            opening(8080, &["198.51.100.7", "203.0.113.0/24"]),
        );
        // The very config erpc.toml makes, under a note the server cannot
        // remove: held as `before_config` is, and a narrowing applied.
        let mut kept = running(&config);
        kept["started"] = "before_config".into();
        kept["note_error"] = "/etc/erpc/worker-waf/bot-prod.applying: is a directory".into();
        let held = Some(Held {
            opening: everyone.clone(),
            why: Why::NoteKept,
        });
        let decided = super::decide(wanted.clone(), &config, &kept, Some(&one));
        assert_eq!(
            decided,
            Decision {
                apply: Some(one.clone()),
                held: held.clone()
            }
        );
        let narrowed = super::decide(Some(one.clone()), &config, &kept, Some(&two));
        assert_eq!(narrowed.apply, Some(one.clone()));
        assert_eq!(narrowed.held, None);
        // Said without "a deploy was ended", and the hint names the path
        // and who can remove it.
        let rules = "the note the server keeps while a deploy writes the WAF's files cannot be \
                     removed there, so what the WAF runs is not taken for erpc.toml's rules";
        assert_eq!(
            super::dropping(Some(8080), &decided, false, ""),
            format!(
                "dropping every other inbound connection; {rules}, so port 8080 stays open to \
                 198.51.100.7/32 and no wider until a deploy puts erpc.toml's in place"
            )
        );
        let synced = Synced {
            ssh_allow: vec!["198.51.100.7".parse().expect("an address")],
            wanted: wanted.clone(),
            opening: Some(one.clone()),
            held,
            in_account: false,
        };
        let id = UnitId::new("bot-prod").expect("id");
        let failed = super::report(false, &id, &m, &synced, SCOPE).expect_err("held");
        assert_eq!(
            failed.message,
            format!(
                "the WAF's port 8080 was not opened to 0.0.0.0/0, ::/0: {rules}, and its port is \
                 not opened wider meanwhile, so port 8080 stays open to 198.51.100.7/32 and no \
                 wider. The rest of bot-prod's server firewall is in force: SSH from \
                 198.51.100.7, everything else dropped"
            )
        );
        assert_eq!(
            failed.hint.as_deref(),
            Some(
                "remove /etc/erpc/worker-waf/bot-prod.applying on the server as root (only root \
                 can); until then `erpc worker deploy --env prod` restarts the WAF, then opens the \
                 port to the list of who may reach the app, as long as it leaves the WAF's config and unit as they \
                 are; a deploy after a change to [waf] or run.port, or from an erpc that writes \
                 the WAF's unit differently, fails"
            )
        );
        assert_eq!(
            failed.details.expect("details")["held_because"],
            "note_kept"
        );
        // In every language: its own words, not `before_config`'s, and the
        // path, "as root", a failing deploy ([`HELD_NOTE`]) and the deploy
        // as they are typed.
        for (lang, as_root, fails) in HELD_NOTE {
            let (dropping, before, hint) = crate::cli::i18n::speaking(lang, || {
                let before = Decision {
                    held: Some(Held {
                        opening: everyone.clone(),
                        why: Why::BeforeConfig,
                    }),
                    ..decided.clone()
                };
                let held = synced.held.as_ref().expect("held");
                (
                    super::dropping(Some(8080), &decided, false, ""),
                    super::dropping(Some(8080), &before, false, ""),
                    super::held_back("bot-prod", &synced, held, SCOPE).hint,
                )
            });
            assert_ne!(dropping, before);
            assert!(
                dropping.contains("8080") && !dropping.contains('{'),
                "{dropping}"
            );
            assert!(!dropping.contains("the note"), "{dropping}");
            let hint = hint.expect("a hint");
            for typed in [
                "/etc/erpc/worker-waf/bot-prod.applying",
                as_root,
                fails,
                "`erpc worker deploy --env prod`",
            ] {
                assert!(hint.contains(typed), "{hint}");
            }
            assert!(!hint.contains('{') && !hint.contains("as root"), "{hint}");
        }
    }

    #[test]
    fn the_plan_is_told_in_the_operators_language() {
        let said = || super::describe(&Env::default(), None).join("\n");
        let english = said();
        assert!(english.contains("all else  dropped"), "{english}");
        for lang in [Lang::Ja, Lang::Ru] {
            let text = crate::cli::i18n::speaking(lang, said);
            assert_ne!(text, english);
            assert!(!text.contains('{'), "{text}");
        }
    }

    fn udp_line(endpoint: &str, sources: &[&str]) -> erpc_worker::manifest::Line {
        erpc_worker::manifest::Line {
            kind: erpc_worker::manifest::LineKind::Udp,
            id: "7".to_owned(),
            endpoint: endpoint.to_owned(),
            hourly: true,
            sources: sources.iter().map(|s| s.parse().expect("ip")).collect(),
        }
    }

    fn port_only(port: Option<u16>) -> Manifest {
        let run = port.map_or_else(String::new, |p| format!("port = {p}\n"));
        Manifest::parse(&format!("name = \"bot\"\nchain = \"solana\"\n[run]\n{run}"))
            .expect("a manifest")
    }

    /// The opening a sync asks for: the app's port, and the UDP port as
    /// the line's record says.
    fn wanted(m: &Manifest, env: &Env, any_source: bool) -> Option<Opening> {
        Opening::with_udp(
            Opening::for_app(m, env),
            super::udp_opening(env, any_source),
        )
    }

    fn senders(port: u16, allow: &[&str]) -> UdpOpening {
        UdpOpening {
            port,
            allow: allow.iter().map(|a| a.parse().expect("ip")).collect(),
            any_source: false,
        }
    }

    #[test]
    fn the_opening_has_the_app_port_the_udp_port_or_both() {
        let allow = vec![Cidr::parse("203.0.113.0/24").expect("net")];
        let with_app = Env {
            firewall: erpc_worker::manifest::Firewall {
                ssh_allow: Vec::new(),
                app_allow: allow.clone(),
            },
            ..Env::default()
        };
        // Nothing: no port, or a port nobody may reach.
        assert_eq!(wanted(&port_only(None), &with_app, false), None);
        assert_eq!(wanted(&port_only(Some(3000)), &Env::default(), false), None);
        // The app's port alone, as before.
        assert_eq!(
            wanted(&port_only(Some(3000)), &with_app, false),
            Some(Opening {
                port: 3000,
                allow: allow.clone(),
                limit: None,
                udp: None,
            })
        );
        // A UDP Forwarding line alone: no TCP port, its sources as they are.
        let udp_only = Env {
            lines: vec![udp_line(
                "0.0.0.0:10001",
                &["198.51.100.20", "198.51.100.21"],
            )],
            ..Env::default()
        };
        let from_sources = Some(Opening {
            port: 0,
            allow: Vec::new(),
            limit: None,
            udp: Some(senders(10001, &["198.51.100.20", "198.51.100.21"])),
        });
        assert_eq!(wanted(&port_only(None), &udp_only, false), from_sources);
        // Asking for any address changes nothing while sources are named.
        assert_eq!(wanted(&port_only(None), &udp_only, true), from_sources);
        // No port of the app's is open then, and none is spoken of: this
        // used to say "port 0 is open at the server's firewall".
        assert_eq!(super::tcp_part(from_sources.as_ref()), None);
        // A pending line has no port yet, and opens nothing, asked or not.
        let pending = Env {
            lines: vec![udp_line("", &[])],
            ..Env::default()
        };
        assert_eq!(wanted(&port_only(None), &pending, false), None);
        assert_eq!(wanted(&port_only(None), &pending, true), None);
    }

    #[test]
    fn a_line_that_names_no_source_opens_nothing_unless_any_address_is_asked_for() {
        let allow = vec![Cidr::parse("203.0.113.0/24").expect("net")];
        let unnamed = Env {
            firewall: erpc_worker::manifest::Firewall {
                ssh_allow: Vec::new(),
                app_allow: allow.clone(),
            },
            lines: vec![udp_line("0.0.0.0:20000", &[])],
            ..Env::default()
        };
        // From the record alone, as `firewall sync` and a deploy without
        // the flag read it: the app's port, and no UDP port.
        assert_eq!(
            wanted(&port_only(Some(3000)), &unnamed, false),
            Some(Opening {
                port: 3000,
                allow: allow.clone(),
                limit: None,
                udp: None,
            })
        );
        // With no app port either, there is nothing to open at all.
        let udp_only = Env {
            lines: unnamed.lines.clone(),
            ..Env::default()
        };
        assert_eq!(wanted(&port_only(None), &udp_only, false), None);
        // Asked for (`deploy --udp-any-source`): open, and said to be.
        assert_eq!(
            wanted(&port_only(Some(3000)), &unnamed, true),
            Some(Opening {
                port: 3000,
                allow,
                limit: None,
                udp: Some(UdpOpening {
                    port: 20000,
                    allow: Vec::new(),
                    any_source: true,
                }),
            })
        );
        // The step says which it is, and how to open a port left closed,
        // for this app and environment.
        let ask = |udp_any_source| super::Ask {
            udp_any_source,
            scope: " --env staging",
        };
        let closed = super::say_udp(&unnamed, ask(false));
        assert!(
            closed.starts_with("UDP port 20000 stays closed")
                && closed.contains("`erpc worker deploy --env staging --udp --udp-any-source`"),
            "{closed}"
        );
        let open = super::say_udp(&unnamed, ask(true));
        assert!(
            open.starts_with("UDP port 20000 open to any IPv4 address"),
            "{open}"
        );
    }

    #[test]
    fn the_udp_port_is_described_and_reported_with_what_may_send_to_it() {
        let env = Env {
            lines: vec![udp_line("0.0.0.0:10001", &["198.51.100.20"])],
            ..Env::default()
        };
        let described = super::describe(&env, None).join("\n");
        assert!(described.contains("udp 10001 198.51.100.20"), "{described}");
        assert!(
            super::describe(&Env::default(), None)
                .iter()
                .all(|l| !l.contains("udp")),
        );
        // Behind a WAF too: the UDP port is no WAF's.
        let mut behind = app(WAF, ONE);
        behind
            .env
            .get_mut("prod")
            .expect("prod")
            .lines
            .push(udp_line("0.0.0.0:10001", &["198.51.100.20"]));
        let planned = super::plan(&behind.env["prod"], &behind).join("\n");
        assert!(
            planned.contains("waf 8080") && planned.contains("udp 10001 198.51.100.20"),
            "{planned}"
        );
        // The record of a line that names no address says its port is
        // closed: that is what applying the record does.
        let unnamed = Env {
            lines: vec![udp_line("0.0.0.0:10001", &[])],
            ..Env::default()
        };
        let described = super::describe(&unnamed, None).join("\n");
        assert!(described.contains("udp 10001 closed"), "{described}");

        assert_eq!(
            super::say_udp(&env, ASK),
            "UDP port 10001 open to 198.51.100.20"
        );
        assert_eq!(super::say_udp(&Env::default(), ASK), "no UDP port open");
        let synced = |opening| Synced {
            ssh_allow: Vec::new(),
            wanted: None,
            opening,
            held: None,
            in_account: false,
        };
        let m = port_only(None);
        assert_eq!(
            super::port_said(&m, &synced(wanted(&m, &env, false))),
            "the app's port closed; UDP port 10001 from 198.51.100.20"
        );
        assert_eq!(
            super::port_said(&m, &synced(wanted(&m, &unnamed, true))),
            "the app's port closed; UDP port 10001 from any IPv4 address"
        );
        assert_eq!(super::port_said(&m, &synced(None)), "the app's port closed");
    }

    /// A WAF's port held by a sync, and a UDP Forwarding line on record:
    /// the sync opens the UDP port all the same, and a deploy that points
    /// the line again changes the UDP port alone. The TCP port stays as
    /// the sync left it, until the deploy's last step opens it.
    #[test]
    fn the_udp_port_is_opened_and_changed_whatever_is_held_of_the_wafs() {
        let me = Some("198.51.100.7".parse().expect("an address"));
        let mut m = app(WAF, EVERYONE);
        let env = m.env.get_mut("prod").expect("prod");
        env.lines
            .push(udp_line("0.0.0.0:10001", &["198.51.100.20"]));
        let env = m.env["prod"].clone();
        let one = opening(8080, &["198.51.100.7"]);
        let config = m.waf_config("prod").expect("a config");
        let mut earlier = config.clone();
        earlier.deny_paths = vec!["/old/*".to_owned()];

        // No WAF on the server: the WAF's port closed, the UDP port open.
        let none = server(&Value::Null, None);
        let synced = super::sync(&none, &m, "prod", &env, me, ASK, &QUIET).expect("synced");
        assert_eq!(
            none.asked(),
            [
                "allow-ssh 198.51.100.7",
                "firewall-show",
                "open 0 to , udp 10001 from 198.51.100.20"
            ]
        );
        assert_eq!(
            synced
                .held
                .as_ref()
                .map(|held| (held.why, held.opening.udp.clone())),
            Some((Why::NoWaf, None))
        );

        // Other rules on the server, with the port open to one address and
        // the line's port to an old source: the TCP opening in force stays
        // as it is, the UDP port follows the record.
        let mut in_force = one.clone();
        in_force.udp = Some(senders(10001, &["198.51.100.9"]));
        let other = server(&running(&earlier), Some(&in_force));
        let mut synced = super::sync(&other, &m, "prod", &env, me, ASK, &QUIET).expect("synced");
        assert_eq!(
            other.asked(),
            [
                "allow-ssh 198.51.100.7",
                "firewall-show",
                "open 8080 to 198.51.100.7/32, limit 50/100, udp 10001 from 198.51.100.20"
            ]
        );
        assert_eq!(
            synced.held.as_ref().map(|held| held.why),
            Some(Why::OtherRules)
        );

        // The lines step moved the line: only its port changes, the WAF's
        // stays open to the one address it was, never to everyone.
        let moved = Some(senders(10001, &["198.51.100.30"]));
        super::reopen(&other, &mut synced, moved.clone(), "moved", &QUIET).expect("reopened");
        assert_eq!(
            other.asked(),
            ["open 8080 to 198.51.100.7/32, limit 50/100, udp 10001 from 198.51.100.30"]
        );
        // The same again asks the server nothing.
        super::reopen(&other, &mut synced, moved, "moved", &QUIET).expect("reopened");
        assert!(other.asked().is_empty());
        // The deploy's last step, once the WAF runs erpc.toml's rules,
        // opens the WAF's port as asked with the line's port as it is now.
        let mut ended = super::sync(&other, &m, "prod", &env, me, ASK, &QUIET).expect("synced");
        other.asked();
        let moved = Some(senders(10001, &["198.51.100.30"]));
        super::reopen(&other, &mut ended, moved, "moved", &QUIET).expect("reopened");
        other.asked();
        super::open_as_asked(&other, &ended, &QUIET).expect("opened");
        assert_eq!(
            other.asked(),
            ["open 8080 to 0.0.0.0/0, ::/0, limit 50/100, udp 10001 from 198.51.100.30"]
        );
        // A line that left the record closes its port, and that alone; the
        // last step then opens the WAF's port with no UDP port.
        super::reopen(&other, &mut synced, None, "gone", &QUIET).expect("reopened");
        assert_eq!(
            other.asked(),
            ["open 8080 to 198.51.100.7/32, limit 50/100"]
        );
        super::open_as_asked(&other, &synced, &QUIET).expect("opened");
        assert_eq!(
            other.asked(),
            ["open 8080 to 0.0.0.0/0, ::/0, limit 50/100"]
        );
    }

    #[test]
    fn an_environment_kept_in_the_account_is_told_of_its_list_there_and_held_to_its_size() {
        use std::net::IpAddr;

        use erpc_worker::net::Cidr;

        use crate::worker::firewall::ssh_addresses;
        let say = Say { quiet: true };
        let mut env = Env {
            account: true,
            ..Env::default()
        };
        // Sixteen addresses, and erpc's own would be the seventeenth:
        // refused before anything is changed.
        env.firewall.ssh_allow = (1..=16)
            .map(|i| Cidr::parse(&format!("198.51.100.{i}")).expect("an address"))
            .collect();
        let me: IpAddr = "203.0.113.9".parse().expect("an address");
        let e = ssh_addresses(&env, Some(me), &say, "").expect_err("refused");
        assert!(e.message.contains("at most 16"), "{}", e.message);
        assert!(
            e.hint
                .unwrap_or_default()
                .contains("firewall deny --to ssh")
        );
        // erpc's own already on it: sixteen, taken.
        assert_eq!(
            ssh_addresses(
                &env,
                Some("198.51.100.1".parse().expect("an address")),
                &say,
                ""
            )
            .expect("taken")
            .len(),
            16
        );
        // A network on the account's list is said as the account's.
        env.firewall.ssh_allow = vec![Cidr::parse("198.51.100.0/24").expect("a network")];
        let e = ssh_addresses(&env, Some(me), &say, "").expect_err("refused");
        assert!(
            e.message.contains("the ERPC account's list"),
            "{}",
            e.message
        );
        // Kept in erpc.toml: no limit of the account's.
        env.account = false;
        env.firewall.ssh_allow = (1..=16)
            .map(|i| Cidr::parse(&format!("198.51.100.{i}")).expect("an address"))
            .collect();
        assert_eq!(
            ssh_addresses(&env, Some(me), &say, "")
                .expect("taken")
                .len(),
            17
        );
    }

    #[test]
    fn a_sync_of_an_environment_kept_in_the_account_names_no_key_or_command_refused_there() {
        // An address not on the account's list: the note that adds it.
        let me = Some("198.51.100.8".parse().expect("an address"));
        let m = app(WAF, EVERYONE);
        let mut env = m.env["prod"].clone();
        env.account = true;
        // The account's starting shape: nobody may reach the app yet.
        env.firewall.app_allow.clear();
        let none = server(&Value::Null, None);
        let _ = crate::node::common::heard::take();
        super::sync(&none, &m, "prod", &env, me, ASK, &QUIET).expect("synced");
        let mut said = crate::node::common::heard::take();
        assert!(said.join("\n").contains("8080"), "{said:?}");
        // The note that erpc's own address is added, among the lines held.
        assert!(
            said.iter()
                .any(|l| l.contains("198.51.100.8") && l.contains("does not have")),
            "{said:?}"
        );
        // No address at all, and a network on the list: the refusals.
        let mut empty = env.clone();
        empty.firewall.ssh_allow.clear();
        let mut network = env.clone();
        network.firewall.ssh_allow = vec![Cidr::parse_any("198.51.100.0/24").expect("a network")];
        // A list the account would hold more than 16 of: refused before the
        // server is asked anything.
        let mut full = env.clone();
        full.firewall.ssh_allow = (1..=16)
            .map(|n| Cidr::parse(&format!("203.0.113.{n}")).expect("an address"))
            .collect();
        let untouched = server(&Value::Null, None);
        let Err(e) = super::sync(&untouched, &m, "prod", &full, me, ASK, &QUIET) else {
            panic!("refused");
        };
        assert!(e.message.contains("16"), "{}", e.message);
        assert!(untouched.asked().is_empty(), "{:?}", untouched.asked());
        said.push(e.message);
        for (refused_env, me) in [(&empty, None), (&network, me)] {
            let Err(e) = super::sync(&none, &m, "prod", refused_env, me, ASK, &QUIET) else {
                panic!("refused");
            };
            said.push(e.message);
            said.push(e.hint.unwrap_or_default());
        }
        // And what the step says of the worker's port in every case it can
        // decide, with a WAF and without, opened, held and closed.
        let opening = Opening::for_app(&m, &m.env["prod"]).expect("an opening");
        let whys = [
            None,
            Some(Why::NoWaf),
            Some(Why::OtherRules),
            Some(Why::UnsaidRules),
            Some(Why::EarlierAgent),
            Some(Why::BeforeConfig),
            Some(Why::NoteKept),
        ];
        for waf in [Some(8080), None] {
            for apply in [Some(&opening), None] {
                for why in whys {
                    let decided = Decision {
                        apply: apply.cloned(),
                        held: why.map(|why| Held {
                            opening: opening.clone(),
                            why,
                        }),
                    };
                    said.push(super::dropping(waf, &decided, true, ""));
                }
            }
        }
        for line in &said {
            for refused in ["firewall.ssh_allow", "firewall.app_allow", "[env."] {
                assert!(!line.contains(refused), "{refused} in: {line}");
            }
        }
    }

    // ---------------------------------------- kept in the ERPC account

    use std::net::IpAddr;

    use erpc_worker::waf::WafConfig;

    use crate::account::commands::Said;
    use crate::cli::error::CliError;

    /// A server the account path reaches, the test keeping its log.
    struct By<'a>(&'a Recorded);

    impl super::Server for By<'_> {
        fn allow_ssh(&self, addresses: Vec<IpAddr>) -> Result<(), CliError> {
            self.0.allow_ssh(addresses)
        }

        fn shown(&self) -> Result<Value, CliError> {
            self.0.shown()
        }

        fn apply(&self, opening: Option<Opening>) -> Result<(), CliError> {
            self.0.apply(opening)
        }

        fn waf_apply(&self, config: &WafConfig) -> Result<Value, CliError> {
            self.0.waf_apply(config)
        }

        fn waf_remove(&self) -> Result<Value, CliError> {
            self.0.waf_remove()
        }
    }

    /// The account's record of environment prod, its lists as written
    /// there.
    fn record_with(ssh: &[&str], app_allow: &[&str]) -> erpc_api::worker::EnvDetail {
        serde_json::from_value(json!({
            "name": "prod", "revision": 7, "factsFormat": 2,
            "facts": { "desiredCores": null, "host": "203.0.113.10", "sshUser": null,
                "sshPort": null, "hostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtest",
                "firewall": { "sshAllow": ssh, "appAllow": app_allow },
                "starting": {}, "backup": null },
            "servers": [{ "id": "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60", "slot": "active",
                "cores": 2, "memoryGb": 8, "region": "amsterdam", "hourly": true,
                "appRunning": true, "state": "active" }],
            "desiredCores": null, "activeCores": 2, "coreOptions": [], "lines": [],
            "refStates": { "backup": null }, "deployed": null, "deployedApp": null,
            "updatedAt": "2026-10-29T15:40:37.000Z"
        }))
        .expect("an environment")
    }

    /// What `held` carries for `record`: erpc.toml (`top` its tables
    /// before the environment) with the account's facts in place.
    fn held_of(top: &str, record: &erpc_api::worker::EnvDetail) -> crate::worker::account::Kept {
        let mut m = Manifest::parse(&format!(
            "name = \"bot\"\nchain = \"solana\"\n{top}[env.prod]\naccount = true\n"
        ))
        .expect("valid");
        let mut env = crate::worker::account::facts_env(record);
        env.account = true;
        m.env.insert("prod".to_owned(), env);
        crate::worker::account::Kept {
            manifest: m,
            record: record.clone(),
            app_id: "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13".to_owned(),
            uid: "user-100001".to_owned(),
        }
    }

    /// The server of `held`'s environment, its WAF running what erpc.toml
    /// asks when it has one.
    fn on(held: &crate::worker::account::Kept) -> Recorded {
        match held.manifest.waf_config("prod") {
            Some(config) => server(&running(&config), None),
            None => server(&Value::Null, None),
        }
    }

    const PORT_WAF: &str = "[run]\nport = 3000\n[waf]\nport = 8080\n";
    const PORT: &str = "[run]\nport = 3000\n";

    fn bot() -> crate::worker::App {
        crate::worker::App::at("apps/bot", "prod")
    }

    /// Goes ahead, reaching `server`, with erpc connecting from
    /// 198.51.100.7.
    #[allow(
        clippy::type_complexity,
        reason = "the two closures are the seam under test, named where they are made"
    )]
    fn going<'a>(
        server: &'a Recorded,
        pins: std::path::PathBuf,
    ) -> super::Going<
        'a,
        By<'a>,
        impl FnOnce() -> Result<(), CliError>,
        impl FnOnce(&Env) -> Result<(By<'a>, Option<IpAddr>), CliError>,
    > {
        super::Going::new(
            true,
            || Ok(()),
            move |_: &Env| {
                Ok((
                    By(server),
                    Some("198.51.100.7".parse().expect("an address")),
                ))
            },
            pins,
            &QUIET,
        )
    }

    /// Asks nobody and reaches nothing: what is refused before either.
    #[allow(
        clippy::type_complexity,
        reason = "the two closures are the seam under test, named where they are made"
    )]
    fn refused_before<'a>(
        pins: std::path::PathBuf,
    ) -> super::Going<
        'a,
        By<'a>,
        impl FnOnce() -> Result<(), CliError>,
        impl FnOnce(&Env) -> Result<(By<'a>, Option<IpAddr>), CliError>,
    > {
        super::Going::new(
            true,
            || -> Result<(), CliError> { panic!("nobody is asked") },
            |_: &Env| -> Result<(By<'a>, Option<IpAddr>), CliError> {
                panic!("the server is not reached")
            },
            pins,
            &QUIET,
        )
    }

    fn change(to: Port, addresses: &[String], allow: bool) -> super::Change<'_> {
        super::Change {
            to,
            addresses,
            allow,
        }
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|&a| a.to_owned()).collect()
    }

    #[tokio::test]
    async fn a_network_on_the_accounts_ssh_list_is_refused_and_the_deny_it_names_clears_it() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let record = record_with(&["198.51.100.0/24", "198.51.100.7/32"], &[]);
        let fake = Fake::new(record.clone());
        let held = held_of(PORT_WAF, &record);
        // Sync: refused, nobody asked, the command that clears it named.
        let Err(e) = super::sync_in(&fake, &held, &bot(), refused_before(pins.clone())).await
        else {
            panic!("refused");
        };
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("`erpc worker firewall deny --to ssh 198.51.100.0/24"),
            "{hint}"
        );
        // An allow before that deny is refused the same way.
        let more = strings(&["198.51.100.9"]);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::Ssh, &more, true),
            refused_before(pins.clone()),
        )
        .await
        else {
            panic!("refused");
        };
        assert!(e.message.contains("198.51.100.0/24"), "{}", e.message);
        assert!(fake.log.borrow().is_empty());
        // The deny it names is taken, and the account's list follows.
        let network = strings(&["198.51.100.0/24"]);
        let on_server = on(&held);
        super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::Ssh, &network, false),
            going(&on_server, pins.clone()),
        )
        .await
        .expect("taken");
        assert_eq!(
            fake.env.borrow().facts.firewall.ssh_allow,
            ["198.51.100.7/32"]
        );
        // Then sync goes through.
        let now = fake.env.borrow().clone();
        let held = held_of(PORT_WAF, &now);
        let on_server = on(&held);
        super::sync_in(&fake, &held, &bot(), going(&on_server, pins))
            .await
            .expect("synced");
        // An environment kept in erpc.toml still takes no network to SSH.
        let toml = app(WAF, ONE);
        let env = toml.env["prod"].clone();
        assert!(super::edited(true, &env, Port::Ssh, &network, false).is_err());
    }

    #[tokio::test]
    async fn everyone_with_no_waf_names_every_such_entry_and_its_deny_clears_it() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        for (listed, named) in [
            (vec!["::/0"], "deny --to app ::/0"),
            (vec!["0.0.0.0/0", "::/0"], "deny --to app 0.0.0.0/0 ::/0"),
        ] {
            let record = record_with(&["198.51.100.7/32"], &listed);
            let fake = Fake::new(record.clone());
            let held = held_of(PORT, &record);
            let Err(e) = super::sync_in(&fake, &held, &bot(), refused_before(pins.clone())).await
            else {
                panic!("refused");
            };
            let hint = e.hint.unwrap_or_default();
            assert!(hint.contains(named), "{hint}");
            // What it names, denied: the list is empty, and sync goes on.
            let typed = strings(&listed);
            let on_server = server(&Value::Null, None);
            super::change_in(
                &fake,
                &held,
                &bot(),
                change(Port::App, &typed, false),
                going(&on_server, pins.clone()),
            )
            .await
            .expect("taken");
            assert!(fake.env.borrow().facts.firewall.app_allow.is_empty());
            let now = fake.env.borrow().clone();
            let on_server = server(&Value::Null, None);
            super::sync_in(
                &fake,
                &held_of(PORT, &now),
                &bot(),
                going(&on_server, pins.clone()),
            )
            .await
            .expect("synced");
        }
        // Behind a WAF, everyone may reach its port.
        let record = record_with(&["198.51.100.7/32"], &["0.0.0.0/0"]);
        let fake = Fake::new(record.clone());
        let held = held_of(PORT_WAF, &record);
        let on_server = on(&held);
        super::sync_in(&fake, &held, &bot(), going(&on_server, pins))
            .await
            .expect("synced behind a WAF");
    }

    #[tokio::test]
    async fn an_entry_erpc_does_not_read_is_refused_never_dropped_and_denied_by_its_text() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let record = record_with(
            &["198.51.100.7/32"],
            &["10.0.0.1/24", "198.51.100.30/32", "198.51.100.30/32"],
        );
        let fake = Fake::new(record.clone());
        let held = held_of(PORT_WAF, &record);
        let more = strings(&["198.51.100.20"]);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &more, true),
            refused_before(pins.clone()),
        )
        .await
        else {
            panic!("refused");
        };
        assert!(e.message.contains("10.0.0.1/24"), "{}", e.message);
        assert!(
            e.hint
                .unwrap_or_default()
                .contains("deny --to app 10.0.0.1/24"),
            "named"
        );
        assert!(fake.log.borrow().is_empty());
        // Denied by its text: gone, and the address listed twice written
        // once.
        let typed = strings(&["10.0.0.1/24"]);
        let on_server = on(&held);
        super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &typed, false),
            going(&on_server, pins),
        )
        .await
        .expect("taken");
        assert_eq!(
            fake.env.borrow().facts.firewall.app_allow,
            ["198.51.100.30/32"]
        );
    }

    #[tokio::test]
    async fn a_record_changed_after_it_was_read_is_not_put_on_the_server() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let record = record_with(&["198.51.100.7/32"], &[]);
        let held = held_of(PORT_WAF, &record);
        let mut moved = record.clone();
        moved.revision = 8;
        let fake = Fake::new(moved);
        let more = strings(&["198.51.100.20"]);
        let going = super::Going::new(
            true,
            || Ok(()),
            |_: &Env| -> Result<(By<'_>, Option<IpAddr>), CliError> {
                panic!("the server is not reached")
            },
            dir.path().join("worker_account.json"),
            &QUIET,
        );
        let Err(e) =
            super::change_in(&fake, &held, &bot(), change(Port::App, &more, true), going).await
        else {
            panic!("refused");
        };
        assert!(
            e.message.contains("after this command read it"),
            "{}",
            e.message
        );
        assert!(fake.log.borrow().is_empty());
    }

    #[tokio::test]
    async fn nothing_reaches_the_server_or_the_account_without_the_yes() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let record = record_with(&["198.51.100.7/32"], &[]);
        let held = held_of(PORT_WAF, &record);
        let fake = Fake::new(record);
        let more = strings(&["198.51.100.20"]);
        let no = || Err(CliError::new(Code::Declined, "no".to_owned()));
        let never = |_: &Env| -> Result<(By<'_>, Option<IpAddr>), CliError> {
            panic!("the server is not reached")
        };
        let going = super::Going::new(
            true,
            no,
            never,
            dir.path().join("worker_account.json"),
            &QUIET,
        );
        let Err(e) =
            super::change_in(&fake, &held, &bot(), change(Port::App, &more, true), going).await
        else {
            panic!("declined");
        };
        assert_eq!(e.code, Code::Declined);
        let going = super::Going::new(
            true,
            no,
            never,
            dir.path().join("worker_account.json"),
            &QUIET,
        );
        assert!(super::sync_in(&fake, &held, &bot(), going).await.is_err());
        assert!(fake.log.borrow().is_empty());
    }

    #[tokio::test]
    async fn sixteen_at_most_and_an_app_list_needs_run_port_before_anything() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let full: Vec<String> = (1..=16).map(|n| format!("203.0.113.{n}/32")).collect();
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        let record = record_with(&["198.51.100.7/32"], &full);
        let fake = Fake::new(record.clone());
        let more = strings(&["198.51.100.20"]);
        let Err(e) = super::change_in(
            &fake,
            &held_of(PORT_WAF, &record),
            &bot(),
            change(Port::App, &more, true),
            refused_before(pins.clone()),
        )
        .await
        else {
            panic!("refused");
        };
        assert!(e.message.contains("17"), "{}", e.message);
        assert!(e.hint.unwrap_or_default().contains("deny --to app"));
        // No run.port: an app list has no port to open.
        let record = record_with(&["198.51.100.7/32"], &[]);
        let fake = Fake::new(record.clone());
        let Err(e) = super::change_in(
            &fake,
            &held_of("", &record),
            &bot(),
            change(Port::App, &more, true),
            refused_before(pins),
        )
        .await
        else {
            panic!("refused");
        };
        assert!(e.message.contains("run.port"), "{}", e.message);
        assert!(fake.log.borrow().is_empty());
    }

    #[tokio::test]
    async fn sync_writes_back_the_address_erpc_connects_from_and_a_deny_of_it_says_it_stays() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let record = record_with(&["203.0.113.9/32"], &[]);
        let fake = Fake::new(record.clone());
        let on_server = server(&Value::Null, None);
        super::sync_in(
            &fake,
            &held_of(PORT_WAF, &record),
            &bot(),
            going(&on_server, pins.clone()),
        )
        .await
        .expect("synced");
        assert_eq!(
            fake.env.borrow().facts.firewall.ssh_allow,
            ["203.0.113.9/32", "198.51.100.7/32"]
        );
        // Denying erpc's own address: it stays, and that is said.
        let now = fake.env.borrow().clone();
        let own = strings(&["198.51.100.7"]);
        let on_server = server(&Value::Null, None);
        let _ = crate::node::common::heard::take();
        super::change_in(
            &fake,
            &held_of(PORT_WAF, &now),
            &bot(),
            change(Port::Ssh, &own, false),
            going(&on_server, pins),
        )
        .await
        .expect("taken");
        let heard = crate::node::common::heard::take().join("\n");
        assert!(
            heard.contains("198.51.100.7 is the address erpc connects from"),
            "{heard}"
        );
    }

    #[tokio::test]
    async fn what_the_account_did_with_a_write_is_what_is_said() {
        use crate::worker::account::stand_in::{Fake, refused};
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let more = strings(&["198.51.100.20"]);
        for (answer, said) in [
            (
                Some(refused(409, "revision_conflict", Value::Null)),
                "as this command read them",
            ),
            (Some(refused(500, "internal", Value::Null)), "is not known"),
            (
                Some(refused(400, "invalid_request", Value::Null)),
                "does not",
            ),
            (None, "took the lists"),
        ] {
            let record = record_with(&["198.51.100.7/32"], &[]);
            let fake = Fake::new(record.clone());
            match answer {
                Some(answer) => fake.answers.borrow_mut().push(answer),
                None => *fake.meddle.borrow_mut() = Some("203.0.113.99".to_owned()),
            }
            let on_server = server(&Value::Null, None);
            let Err(e) = super::change_in(
                &fake,
                &held_of(PORT_WAF, &record),
                &bot(),
                change(Port::App, &more, true),
                going(&on_server, pins.clone()),
            )
            .await
            else {
                panic!("not as sent");
            };
            assert!(e.message.contains(said), "{said}: {}", e.message);
            assert!(!on_server.asked().is_empty());
        }
    }

    #[test]
    fn unchanged_and_list_name_the_accounts_lists_as_it_keeps_them() {
        let record = record_with(&["198.51.100.7/32"], &["10.0.0.1/24"]);
        let held = held_of(PORT_WAF, &record);
        let env = held.manifest.env["prod"].clone();
        let Said::Json(body) = super::unchanged(true, "bot-prod", &env, &[], true, SCOPE) else {
            panic!("JSON");
        };
        assert!(
            body.get("account").is_some() && body.get("erpc_toml").is_none(),
            "{body}"
        );
        let lists = super::account_lists_json(&record);
        assert_eq!(lists["app_allow"], json!(["10.0.0.1/24"]));
        assert_eq!(super::Unread::of(&record).app, ["10.0.0.1/24"]);
    }

    #[test]
    fn an_environment_kept_in_the_account_is_refused_by_the_erpc_toml_path() {
        let dir = tempfile::tempdir().expect("a directory");
        std::fs::write(
            dir.path().join("erpc.toml"),
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\naccount = true\n",
        )
        .expect("written");
        let app = crate::worker::App::at(dir.path().to_str().expect("a path"), "prod");
        let e = crate::worker::load_env(&app).expect_err("refused");
        assert!(
            e.message.contains("kept in the ERPC account"),
            "{}",
            e.message
        );
    }

    #[test]
    fn the_firewall_step_itself_refuses_an_account_list_before_the_server_is_asked() {
        // What the deploy reaches as its step 5, whatever was checked before.
        for (top, ssh, app_allow) in [
            ("[run]\nport = 3000\n", "198.51.100.7/32", "0.0.0.0/0"),
            (PORT_WAF, "198.51.100.0/24", "198.51.100.20/32"),
        ] {
            let held = held_of(top, &record_with(&[ssh], &[app_allow]));
            let env = held.manifest.env["prod"].clone();
            let untouched = server(&Value::Null, None);
            let me = Some("198.51.100.7".parse().expect("an address"));
            let Err(e) = super::sync(&untouched, &held.manifest, "prod", &env, me, ASK, &QUIET)
            else {
                panic!("refused");
            };
            assert!(
                e.message.contains("the firewall was not changed"),
                "{}",
                e.message
            );
            assert!(untouched.asked().is_empty(), "{:?}", untouched.asked());
        }
    }

    /// The `deny` commands a refusal's hint names: which list, and the
    /// entries, as typed.
    fn hinted_denies(hint: &str) -> Vec<(Port, Vec<String>)> {
        hint.split('`')
            .filter_map(|part| part.strip_prefix("erpc worker firewall deny --to "))
            .map(|rest| {
                let (to, rest) = rest.split_once(' ').expect("a list");
                let entries = rest.split(" --env ").next().expect("entries");
                let to = if to == "ssh" { Port::Ssh } else { Port::App };
                // As a shell reads them: a quoted entry without its quotes.
                let word = |w: &str| w.trim_matches('\'').replace("'\\''", "'");
                (to, entries.split(' ').map(word).collect())
            })
            .collect()
    }

    #[tokio::test]
    async fn following_only_the_hinted_denies_clears_every_mix_of_problems() {
        use crate::worker::account::stand_in::Fake;
        // unread SSH, network SSH, unread app, everyone without a WAF, no
        // run.port.
        for mask in 0u8..32 {
            let has = |bit: u8| mask & (1 << bit) != 0;
            let mut ssh = vec!["198.51.100.7/32"];
            let mut app_allow = vec!["198.51.100.30/32"];
            if has(0) {
                ssh.push("10.0.0.1/24");
            }
            if has(1) {
                ssh.push("198.51.100.0/24");
            }
            if has(2) {
                app_allow.push("10.0.0.2/24");
            }
            if has(3) {
                app_allow.push("0.0.0.0/0");
            }
            // A WAF needs run.port; everyone is a problem only without one.
            let top = match (has(3), has(4)) {
                (_, true) => "",
                (true, false) => PORT,
                (false, false) => PORT_WAF,
            };
            let dir = tempfile::tempdir().expect("a directory");
            let pins = dir.path().join("worker_account.json");
            let fake = Fake::new(record_with(&ssh, &app_allow));
            let mut steps = 0;
            loop {
                let now = fake.env.borrow().clone();
                let held = held_of(top, &now);
                let on_server = on(&held);
                let Err(e) =
                    super::sync_in(&fake, &held, &bot(), going(&on_server, pins.clone())).await
                else {
                    break;
                };
                let hint = e.hint.unwrap_or_default();
                let denies = hinted_denies(&hint);
                assert!(!denies.is_empty(), "{mask:05b}: {}: {hint}", e.message);
                for (to, entries) in denies {
                    let now = fake.env.borrow().clone();
                    let held = held_of(top, &now);
                    let on_server = on(&held);
                    // Taken: on the server, or in the account's record
                    // alone while something else still stops the lists.
                    match super::change_in(
                        &fake,
                        &held,
                        &bot(),
                        change(to, &entries, false),
                        going(&on_server, pins.clone()),
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err(e) => assert_eq!(
                            e.details.as_ref().map(|d| d["account_only"].clone()),
                            Some(Value::Bool(true)),
                            "{mask:05b}: {}",
                            e.message
                        ),
                    }
                }
                steps += 1;
                assert!(steps <= 3, "{mask:05b}: no way out after {steps} rounds");
            }
            // What was not named stays, as the account had it.
            let left = fake.env.borrow().facts.firewall.clone();
            assert!(
                left.ssh_allow.contains(&"198.51.100.7/32".to_owned()),
                "{mask:05b}"
            );
            if !has(4) {
                assert!(
                    left.app_allow.contains(&"198.51.100.30/32".to_owned()),
                    "{mask:05b}: {left:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_deny_while_something_else_stops_the_lists_lands_in_the_account_alone() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let record = record_with(
            &["198.51.100.7/32", "10.0.0.1/24"],
            &["10.0.0.2/24", "198.51.100.30/32"],
        );
        let fake = Fake::new(record.clone());
        let held = held_of(PORT_WAF, &record);
        let typed = strings(&["10.0.0.1/24"]);
        let never = |_: &Env| -> Result<(By<'_>, Option<IpAddr>), CliError> {
            panic!("the server is not reached")
        };
        let going = super::Going::new(true, || Ok(()), never, pins.clone(), &QUIET);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::Ssh, &typed, false),
            going,
        )
        .await
        else {
            panic!("said as the account's alone");
        };
        assert!(
            e.message
                .contains("was not changed, and lets in whatever of them"),
            "{}",
            e.message
        );
        assert!(
            e.hint
                .unwrap_or_default()
                .contains("deny --to app 10.0.0.2/24")
        );
        // The SSH entry gone; the app's list as the account had it, the
        // entry erpc does not read included.
        let now = fake.env.borrow().facts.firewall.clone();
        assert_eq!(now.ssh_allow, ["198.51.100.7/32"]);
        assert_eq!(now.app_allow, ["10.0.0.2/24", "198.51.100.30/32"]);
        // An SSH entry erpc does not read is never dropped by a sync.
        let fake = Fake::new(record_with(&["198.51.100.7/32", "10.0.0.1/24"], &[]));
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        assert!(
            super::sync_in(&fake, &held, &bot(), refused_before(pins))
                .await
                .is_err()
        );
        assert!(fake.log.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_record_changed_while_the_question_waits_is_not_put_on_the_server() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let record = record_with(&["198.51.100.7/32"], &[]);
        let held = held_of(PORT_WAF, &record);
        let fake = Fake::new(record);
        let more = strings(&["198.51.100.20"]);
        let meanwhile = || {
            fake.env.borrow_mut().revision += 1;
            Ok(())
        };
        let never = |_: &Env| -> Result<(By<'_>, Option<IpAddr>), CliError> {
            panic!("the server is not reached")
        };
        let going = super::Going::new(
            true,
            meanwhile,
            never,
            dir.path().join("worker_account.json"),
            &QUIET,
        );
        let Err(e) =
            super::change_in(&fake, &held, &bot(), change(Port::App, &more, true), going).await
        else {
            panic!("refused");
        };
        assert!(
            e.message.contains("after this command read it"),
            "{}",
            e.message
        );
        assert!(fake.log.borrow().is_empty());
    }

    #[tokio::test]
    async fn the_dispatch_asks_as_go_ahead_does_and_lists_through_the_account() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let record = record_with(&["198.51.100.7/32"], &["10.0.0.2/24"]);
        let held = held_of(PORT_WAF, &record);
        let fake = Fake::new(record);
        let never = |_: &Env| -> Result<(By<'static>, Option<IpAddr>), CliError> {
            panic!("the server is not reached")
        };
        // No --yes and no terminal here: refused before anything.
        let clean = held_of(PORT_WAF, &record_with(&["198.51.100.7/32"], &[]));
        let ask = super::FirewallAsk::Sync { yes: false };
        let said = super::account(false, &bot(), ask, (&fake, &clean), pins.clone(), never).await;
        assert!(
            matches!(&said, crate::account::commands::Outcome::Error(e) if e.code == Code::NeedsTerminal),
            "{said:?}"
        );
        let ask = super::FirewallAsk::Change {
            to: Port::App,
            addresses: strings(&["198.51.100.20"]),
            allow: true,
            yes: false,
        };
        let said = super::account(false, &bot(), ask, (&fake, &clean), pins.clone(), never).await;
        assert!(
            matches!(&said, crate::account::commands::Outcome::Error(e) if e.code == Code::NeedsTerminal),
            "{said:?}"
        );
        assert!(fake.log.borrow().is_empty());
        // `list` reads the account's lists, and says what stops them.
        let on_server = on(&held);
        let reach = |_: &Env| Ok((By(&on_server), None));
        let said = super::account(
            false,
            &bot(),
            super::FirewallAsk::List,
            (&fake, &held),
            pins.clone(),
            reach,
        )
        .await;
        let crate::account::commands::Outcome::Done(text) = said else {
            panic!("listed: {said:?}");
        };
        assert!(
            text.contains("warning:") && text.contains("10.0.0.2/24"),
            "{text}"
        );
        assert!(text.contains("has not put"), "{text}");
        let listed = super::list_json((&held.manifest, &bot(), &held, &pins), &Value::Null);
        assert_eq!(listed["account"]["app_allow"], json!(["10.0.0.2/24"]));
        assert_eq!(listed["unread"]["app_allow"], json!(["10.0.0.2/24"]));
    }

    #[tokio::test]
    async fn what_changed_in_the_apps_list_since_it_was_put_on_the_server_is_said_first() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let fake = Fake::new(record_with(&["198.51.100.7/32"], &["198.51.100.30/32"]));
        // Never put there from here: said whole, on stderr under --json too.
        let _ = crate::node::common::heard::take_printed();
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let on_server = on(&held);
        super::sync_in(&fake, &held, &bot(), going(&on_server, pins.clone()))
            .await
            .expect("synced");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("has not put") && printed.contains("198.51.100.30/32"),
            "{printed}"
        );
        // Another sign-in changes it: what was added and removed is said.
        fake.env.borrow_mut().facts.firewall = erpc_api::worker::Firewall::new(
            vec!["198.51.100.7/32".to_owned()],
            vec!["198.51.100.40/32".to_owned()],
        );
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let on_server = on(&held);
        let _ = crate::node::common::heard::take();
        super::sync_in(&fake, &held, &bot(), going(&on_server, pins.clone()))
            .await
            .expect("synced");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("added 198.51.100.40/32; removed 198.51.100.30/32"),
            "{printed}"
        );
        // The plan is said too, and nothing more is new after.
        let heard = crate::node::common::heard::take().join("\n");
        assert!(heard.contains("The firewall will be:"), "{heard}");
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        assert!(super::app_changes_of(&held, &pins, &bot()).is_none());
    }

    #[tokio::test]
    async fn a_record_of_this_machine_that_cannot_be_written_is_said_under_json_too() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        // The pins' place is a directory: nothing can be written there.
        let pins = dir.path().join("pins");
        std::fs::create_dir_all(&pins).expect("a directory");
        let fake = Fake::new(record_with(&["198.51.100.7/32"], &["198.51.100.30/32"]));
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let on_server = on(&held);
        let _ = crate::node::common::heard::take_printed();
        // An address let in to SSH changes how the server is reached: the
        // pin follows the write, and the app's list is recorded as put.
        super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::Ssh, &strings(&["203.0.113.5"]), true),
            going(&on_server, pins),
        )
        .await
        .expect("let in");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("record of what it trusts could not follow"),
            "{printed}"
        );
        assert!(
            printed.contains("as last put on the server, could not be written"),
            "{printed}"
        );
    }

    #[tokio::test]
    async fn sixteen_fit_and_listed_twice_is_said() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let full: Vec<String> = (1..=15).map(|n| format!("203.0.113.{n}/32")).collect();
        let mut listed: Vec<&str> = full.iter().map(String::as_str).collect();
        listed.push("203.0.113.1/32");
        let fake = Fake::new(record_with(&["198.51.100.7/32"], &listed));
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let on_server = on(&held);
        let _ = crate::node::common::heard::take();
        super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &strings(&["203.0.113.16"]), true),
            going(&on_server, pins),
        )
        .await
        .expect("sixteen fit");
        assert_eq!(fake.env.borrow().facts.firewall.app_allow.len(), 16);
        let heard = crate::node::common::heard::take().join("\n");
        assert!(heard.contains("more than once: 203.0.113.1/32"), "{heard}");
    }

    #[test]
    fn a_write_is_said_by_what_became_of_it() {
        use crate::worker::deploy_account::Unwritten;
        use erpc_api::worker::WorkerError;
        let of = |e: WorkerError| Unwritten::of(&e);
        assert!(matches!(
            of(WorkerError::Api(erpc_api::ApiError::Malformed(
                "cut".to_owned()
            ))),
            Unwritten::Lost(_)
        ));
        assert!(matches!(
            of(WorkerError::Api(erpc_api::ApiError::Status(502))),
            Unwritten::Lost(_)
        ));
        assert!(matches!(
            of(WorkerError::NewerFormat {
                found: 9,
                after_write: true
            }),
            Unwritten::Lost(_)
        ));
        assert!(matches!(
            of(WorkerError::NewerFormat {
                found: 9,
                after_write: false
            }),
            Unwritten::Refused(_)
        ));
        assert!(matches!(
            of(WorkerError::Session("expired".to_owned())),
            Unwritten::NotSignedIn(_)
        ));
        assert!(matches!(
            of(WorkerError::Api(erpc_api::ApiError::Status(400))),
            Unwritten::Refused(_)
        ));
        let e = super::unwritten_said(Unwritten::NotSignedIn("x".to_owned()), &bot(), None);
        assert_eq!(e.code, Code::NotSignedIn);
        let env = held_of(PORT_WAF, &record_with(&["198.51.100.7/32"], &[]))
            .manifest
            .env["prod"]
            .clone();
        let Said::Text(text) = super::unchanged(
            false,
            "bot-prod",
            &env,
            &strings(&["198.51.100.7"]),
            true,
            SCOPE,
        ) else {
            panic!("text");
        };
        assert!(text.contains("ERPC account's lists"), "{text}");
    }

    #[tokio::test]
    async fn a_waf_nobody_may_reach_is_said_as_the_accounts_list() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let fake = Fake::new(record_with(&["198.51.100.7/32"], &[]));
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let on_server = on(&held);
        let going = super::Going::new(
            false,
            || Ok(()),
            |_: &Env| {
                Ok((
                    By(&on_server),
                    Some("198.51.100.7".parse().expect("an address")),
                ))
            },
            dir.path().join("worker_account.json"),
            &QUIET,
        );
        let said = super::sync_in(&fake, &held, &bot(), going)
            .await
            .expect("synced");
        let crate::account::commands::Outcome::Done(text) = said else {
            panic!("{said:?}");
        };
        assert!(
            text.contains("the ERPC account's list of who may reach the app has nobody"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn every_stopping_entry_is_named_and_what_is_not_denied_stays_as_the_account_had_it() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let ssh = ["198.51.100.7/32", "10.0.0.1/24", "10.0.0.3/24"];
        let app_allow = ["10.0.0.2/24", "198.51.100.30/32"];
        let fake = Fake::new(record_with(&ssh, &app_allow));
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        // Two entries of one list: both named in one deny.
        let Err(e) = super::sync_in(&fake, &held, &bot(), refused_before(pins.clone())).await
        else {
            panic!("refused");
        };
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("deny --to ssh 10.0.0.1/24 10.0.0.3/24 "),
            "{hint}"
        );
        assert!(hint.contains("deny --to app 10.0.0.2/24 "), "{hint}");
        // Denying one of them: the other stays, as the account had it, and
        // so does the app's list.
        let never = |_: &Env| -> Result<(By<'_>, Option<IpAddr>), CliError> {
            panic!("the server is not reached")
        };
        let one = strings(&["10.0.0.1/24"]);
        let first = super::Going::new(true, || Ok(()), never, pins.clone(), &QUIET);
        let _ = super::change_in(&fake, &held, &bot(), change(Port::Ssh, &one, false), first).await;
        let now = fake.env.borrow().facts.firewall.clone();
        assert_eq!(now.ssh_allow, ["198.51.100.7/32", "10.0.0.3/24"]);
        assert_eq!(now.app_allow, app_allow);
        // Denying the app's entry: the SSH list stays as the account has it.
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let app_one = strings(&["10.0.0.2/24"]);
        let second = super::Going::new(true, || Ok(()), never, pins.clone(), &QUIET);
        let _ = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &app_one, false),
            second,
        )
        .await;
        let now = fake.env.borrow().facts.firewall.clone();
        assert_eq!(now.ssh_allow, ["198.51.100.7/32", "10.0.0.3/24"]);
        assert_eq!(now.app_allow, ["198.51.100.30/32"]);
        // An entry holding terminal control is named as shown, and denied
        // by that.
        let fake = Fake::new(record_with(&["198.51.100.7/32"], &["10.0.0.\u{1b}5/24"]));
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let Err(e) = super::sync_in(&fake, &held, &bot(), refused_before(pins.clone())).await
        else {
            panic!("refused");
        };
        let named = hinted_denies(&e.hint.unwrap_or_default());
        assert_eq!(named.len(), 1);
        assert!(!named[0].1[0].contains('\u{1b}'), "{named:?}");
        let on_server = on(&held);
        super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &named[0].1, false),
            going(&on_server, pins),
        )
        .await
        .expect("taken");
        assert!(fake.env.borrow().facts.firewall.app_allow.is_empty());
    }

    #[tokio::test]
    async fn a_repair_says_what_changed_before_it_asks_and_advances_nothing() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let record = record_with(
            &["198.51.100.7/32", "10.0.0.1/24"],
            &["198.51.100.30/32", "10.0.0.2/24"],
        );
        let held = held_of(PORT_WAF, &record);
        let fake = Fake::new(record);
        let typed = strings(&["10.0.0.1/24"]);
        let never = |_: &Env| -> Result<(By<'_>, Option<IpAddr>), CliError> {
            panic!("the server is not reached")
        };
        // Said before the question; a no writes nothing.
        let _ = crate::node::common::heard::take_printed();
        let no = || {
            let printed = crate::node::common::heard::take_printed().join("\n");
            assert!(printed.contains("has not put"), "said first: {printed}");
            Err(CliError::new(Code::Declined, "no".to_owned()))
        };
        let going = super::Going::new(true, no, never, pins.clone(), &QUIET);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::Ssh, &typed, false),
            going,
        )
        .await
        else {
            panic!("declined");
        };
        assert_eq!(e.code, Code::Declined);
        assert!(fake.log.borrow().is_empty());
        // A yes: written to the account alone, the removal said in the
        // message and its details, and the app's list not taken as seen.
        let going = super::Going::new(true, || Ok(()), never, pins.clone(), &QUIET);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::Ssh, &typed, false),
            going,
        )
        .await
        else {
            panic!("said as the account's alone");
        };
        assert!(
            e.message.contains("no longer has 10.0.0.1/24")
                && e.message.contains("the server's firewall was not changed"),
            "{}",
            e.message
        );
        assert_eq!(
            e.details.expect("details")["removed"],
            json!(["10.0.0.1/24"])
        );
        let key = crate::worker::account::pin_key("user-100001", "bot", "prod");
        assert_eq!(
            crate::worker::account::app_seen(&pins, &key).expect("read"),
            None
        );
        // Its hints name the same deny, not a sync that is refused.
        let fake = Fake::new(record_with(
            &["198.51.100.7/32", "10.0.0.1/24"],
            &["10.0.0.2/24"],
        ));
        fake.answers
            .borrow_mut()
            .push(crate::worker::account::stand_in::refused(
                400,
                "invalid_request",
                Value::Null,
            ));
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let going = super::Going::new(true, || Ok(()), never, pins, &QUIET);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::Ssh, &typed, false),
            going,
        )
        .await
        else {
            panic!("refused");
        };
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("deny") && !hint.contains("firewall sync"),
            "{hint}"
        );
    }

    #[tokio::test]
    async fn an_ipv4_mapped_address_is_written_as_the_account_takes_it_and_its_own_text_kept() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let cidr = Cidr::parse_any("::ffff:1.2.3.4").expect("an address");
        assert_eq!(super::account_text(&cidr), "::ffff:102:304/128");
        // Held in the account in its own text: kept so.
        let record = record_with(&["198.51.100.7/32", "::FFFF:102:304/128"], &[]);
        let fake = Fake::new(record.clone());
        let held = held_of(PORT_WAF, &record);
        let on_server = on(&held);
        super::sync_in(&fake, &held, &bot(), going(&on_server, pins.clone()))
            .await
            .expect("synced");
        assert_eq!(
            fake.env.borrow().facts.firewall.ssh_allow,
            ["198.51.100.7/32", "::FFFF:102:304/128"]
        );
        // A new one, typed dotted: written in hex, which the account takes.
        let fake = Fake::new(record_with(&["198.51.100.7/32"], &[]));
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let on_server = on(&held);
        super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::Ssh, &strings(&["::ffff:1.2.3.4"]), true),
            going(&on_server, pins),
        )
        .await
        .expect("taken");
        assert!(
            fake.env
                .borrow()
                .facts
                .firewall
                .ssh_allow
                .contains(&"::ffff:102:304/128".to_owned()),
            "{:?}",
            fake.env.borrow().facts.firewall
        );
    }

    #[tokio::test]
    async fn the_list_says_unread_ssh_entries_and_twice_and_nothing_to_change_says_what_stops() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let record = record_with(
            &["198.51.100.7/32", "10.0.0.1/24"],
            &["198.51.100.30/32", "198.51.100.30/32"],
        );
        let held = held_of(PORT_WAF, &record);
        let listed = super::list_json((&held.manifest, &bot(), &held, &pins), &Value::Null);
        assert_eq!(listed["unread"]["ssh_allow"], json!(["10.0.0.1/24"]));
        assert!(
            listed["stopped"]
                .as_str()
                .is_some_and(|s| s.contains("10.0.0.1/24"))
        );
        let on_server = on(&held);
        let text = match super::list_in(false, &bot(), &held, &pins, |_: &Env| {
            Ok((By(&on_server), None))
        }) {
            Ok(crate::account::commands::Outcome::Done(text)) => text,
            other => panic!("{other:?}"),
        };
        assert!(text.contains("more than once: 198.51.100.30/32"), "{text}");
        // Nothing to change while something stops the lists: what stops
        // them is said, not "sync applies them again".
        let fake = Fake::new(record);
        let absent = strings(&["203.0.113.99"]);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &absent, false),
            refused_before(pins),
        )
        .await
        else {
            panic!("stopped");
        };
        assert!(
            e.message.contains("cannot be put on the server"),
            "{}",
            e.message
        );
    }

    #[test]
    fn unchanged_json_has_the_accounts_lists_as_it_keeps_them() {
        let record = record_with(&["198.51.100.7/32"], &["198.51.100.30/32", "203.0.113.7"]);
        let held = held_of(PORT_WAF, &record);
        let lists = super::account_lists_json(&held.record);
        assert_eq!(
            lists["app_allow"],
            json!(["198.51.100.30/32", "203.0.113.7"])
        );
    }

    #[test]
    fn nothing_to_change_answers_with_the_accounts_lists_as_it_keeps_them() {
        // An entry the account keeps in its own text, not as erpc writes it.
        let record = record_with(&["198.51.100.7/32"], &["2001:DB8::1/128"]);
        let held = held_of(PORT_WAF, &record);
        let env = held.manifest.env["prod"].clone();
        let typed = strings(&["2001:db8::1"]);
        let Said::Json(body) = super::unchanged_in_account(
            true,
            "bot-prod",
            (&env, &held.record),
            change(Port::App, &typed, true),
            SCOPE,
        ) else {
            panic!("JSON");
        };
        assert_eq!(
            body["account"]["app_allow"],
            json!(["2001:DB8::1/128"]),
            "{body}"
        );
        assert!(body.get("erpc_toml").is_none(), "{body}");
    }

    #[tokio::test]
    async fn the_list_put_on_the_server_is_the_one_seen_and_a_later_change_is_said() {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let key = crate::worker::account::pin_key("user-100001", "bot", "prod");
        let fake = Fake::new(record_with(&["198.51.100.7/32"], &["198.51.100.66/32"]));
        // A deny changes the app's list: what was put there is what is seen.
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let on_server = on(&held);
        super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &strings(&["198.51.100.66"]), false),
            going(&on_server, pins.clone()),
        )
        .await
        .expect("taken");
        assert_eq!(
            crate::worker::account::app_seen(&pins, &key).expect("read"),
            Some(Vec::<String>::new())
        );
        // An allow: the same.
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let on_server = on(&held);
        super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &strings(&["198.51.100.20"]), true),
            going(&on_server, pins.clone()),
        )
        .await
        .expect("taken");
        assert_eq!(
            crate::worker::account::app_seen(&pins, &key).expect("read"),
            Some(vec!["198.51.100.20/32".to_owned()])
        );
        // Another sign-in puts the address back: the next command and the
        // list say so.
        fake.env.borrow_mut().facts.firewall = erpc_api::worker::Firewall::new(
            vec!["198.51.100.7/32".to_owned()],
            vec!["198.51.100.20/32".to_owned(), "198.51.100.66/32".to_owned()],
        );
        let held = held_of(PORT_WAF, &fake.env.borrow().clone());
        let listed = super::list_json((&held.manifest, &bot(), &held, &pins), &Value::Null);
        assert!(
            listed["app_allow_changed"]
                .as_str()
                .is_some_and(|c| c.contains("added 198.51.100.66/32")),
            "{listed}"
        );
        let _ = crate::node::common::heard::take_printed();
        let on_server = on(&held);
        super::sync_in(&fake, &held, &bot(), going(&on_server, pins))
            .await
            .expect("synced");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(printed.contains("added 198.51.100.66/32"), "{printed}");
    }

    #[tokio::test]
    async fn a_repair_is_read_again_after_the_yes_and_its_hint_is_the_whole_deny() {
        use crate::worker::account::stand_in::{Fake, refused};
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let record = record_with(
            &["198.51.100.7/32"],
            &["198.51.100.2/24", "198.51.100.3/24"],
        );
        let held = held_of(PORT_WAF, &record);
        let fake = Fake::new(record.clone());
        let typed = strings(&["198.51.100.2/24"]);
        let never = |_: &Env| -> Result<(By<'_>, Option<IpAddr>), CliError> {
            panic!("the server is not reached")
        };
        // Changed while the question waits: nothing written.
        let meanwhile = || {
            fake.env.borrow_mut().revision += 1;
            Ok(())
        };
        let going = super::Going::new(true, meanwhile, never, pins.clone(), &QUIET);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &typed, false),
            going,
        )
        .await
        else {
            panic!("refused");
        };
        assert!(
            e.message.contains("after this command read it"),
            "{}",
            e.message
        );
        assert!(fake.log.borrow().is_empty());
        // A write it cannot make: the hint is the same deny, whole.
        let fake = Fake::new(record);
        fake.answers
            .borrow_mut()
            .push(refused(400, "invalid_request", Value::Null));
        let going = super::Going::new(true, || Ok(()), never, pins, &QUIET);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &typed, false),
            going,
        )
        .await
        else {
            panic!("refused");
        };
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("`erpc worker firewall deny --to app 198.51.100.2/24 --env prod"),
            "{hint}"
        );
        // The server was not touched, and that is said.
        assert!(
            e.message.contains("the server's firewall was not changed"),
            "{}",
            e.message
        );
        assert!(!e.message.contains("the server's firewall has the change"));
    }

    #[tokio::test]
    async fn the_accounts_own_text_is_kept_on_the_apps_list_and_a_mapped_network_keeps_its_prefix()
    {
        use crate::worker::account::stand_in::Fake;
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let net = Cidr::parse_any("::ffff:198.51.100.0/120").expect("a network");
        assert_eq!(super::account_text(&net), "::ffff:c633:6400/120");
        let record = record_with(&["198.51.100.7/32"], &["2001:DB8::1/128"]);
        let fake = Fake::new(record.clone());
        let held = held_of(PORT_WAF, &record);
        let on_server = on(&held);
        super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &strings(&["::ffff:198.51.100.0/120"]), true),
            going(&on_server, pins),
        )
        .await
        .expect("taken");
        assert_eq!(
            fake.env.borrow().facts.firewall.app_allow,
            ["2001:DB8::1/128", "::ffff:c633:6400/120"]
        );
    }

    #[tokio::test]
    async fn a_repair_of_several_entries_names_each_in_its_hint() {
        use crate::worker::account::stand_in::{Fake, refused};
        let dir = tempfile::tempdir().expect("a directory");
        let record = record_with(
            &["198.51.100.7/32"],
            &["198.51.100.2/24", "198.51.100.3/24", "198.51.100.4/24"],
        );
        let held = held_of(PORT_WAF, &record);
        let fake = Fake::new(record);
        fake.answers
            .borrow_mut()
            .push(refused(400, "invalid_request", Value::Null));
        let never = |_: &Env| -> Result<(By<'_>, Option<IpAddr>), CliError> {
            panic!("the server is not reached")
        };
        let going = super::Going::new(
            true,
            || Ok(()),
            never,
            dir.path().join("worker_account.json"),
            &QUIET,
        );
        let typed = strings(&[" 198.51.100.2/24 ", "198.51.100.3/24"]);
        let Err(e) = super::change_in(
            &fake,
            &held,
            &bot(),
            change(Port::App, &typed, false),
            going,
        )
        .await
        else {
            panic!("refused");
        };
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains(
                "`erpc worker firewall deny --to app 198.51.100.2/24 198.51.100.3/24 --env prod --dir apps/bot`"
            ),
            "{hint}"
        );
    }

    #[test]
    fn the_empty_ssh_list_hint_is_a_command_scoped_to_its_app_in_every_language() {
        use erpc_core::i18n::Lang;
        let mut env = Env {
            account: true,
            ..Env::default()
        };
        env.firewall.ssh_allow.clear();
        for lang in [Lang::En, Lang::Ja, Lang::Zh, Lang::Ru] {
            let hint = crate::cli::i18n::speaking(lang, || {
                super::ssh_addresses(&env, None, &QUIET, " --env prod")
                    .expect_err("refused")
                    .hint
                    .unwrap_or_default()
            });
            assert!(
                hint.contains("`erpc worker firewall allow --to ssh <ADDRESS> --env prod`"),
                "{lang:?}: {hint}"
            );
            assert!(
                !hint.contains('{') && !hint.contains('}'),
                "{lang:?}: {hint}"
            );
        }
    }
}
