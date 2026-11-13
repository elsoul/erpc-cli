// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! An app's WAF, as `erpc worker` handles it: what `[waf]` in erpc.toml
//! will do, for `check`; putting it in front of the app, or taking it
//! away, at the end of a `deploy`; and how it is, for `status` and
//! `firewall list`.
//!
//! The WAF is an HTTP proxy the server runs in front of the app
//! ([`erpc_worker::waf`]). `[waf]` names its port; every other key has a
//! default, so what is in force is read from the config the table makes
//! and not from the table.
//!
//! A deploy puts it in place once the release is active and healthy: the
//! agent's `waf-apply` is handed the config, writes it with the proxy's
//! unit, and answers when the proxy listens. Only then is its port made
//! what erpc.toml asks in the server's firewall, wherever the firewall
//! step left it otherwise: [`crate::worker_firewall::sync`] keeps the port
//! closed while no WAF listens there, and no wider than it is, with the
//! limit on new connections it has, while the WAF there runs rules that
//! are not erpc.toml's ([`rules`]). `erpc worker api` and the health check
//! do not pass through it: they reach the app on loopback, which is the
//! operator's way in.

use erpc_core::i18n::Lang;
use erpc_worker::manifest::Manifest;
use erpc_worker::net::Cidr;
use erpc_worker::server::Opening;
use erpc_worker::waf::WafConfig;
use serde_json::{Value, json};

use crate::error::CliError;
use crate::node_common::Say;
use crate::worker_deploy::said_in;
use crate::worker_firewall::{Server, Synced};
use crate::worker_remote::failed;

/// The rules the proxy counts what it blocked by, as its stats name them
/// ([`erpc_worker::waf::Blocked`]). They are said as they are in every
/// language: they are the names `--json` has too.
const RULES: [&str; 12] = [
    "method",
    "path",
    "denied",
    "not_allowed",
    "probe",
    "rate",
    "body",
    "malformed",
    "banned",
    "connections",
    "upgrade",
    "body_timeout",
];

/// Of [`RULES`], the ones that close a connection unanswered: no request
/// was read, so they are not among the requests the proxy counts.
const CONNECTION_RULES: [&str; 2] = ["banned", "connections"];

/// `list` as a line names addresses.
pub(crate) fn addresses(list: &[Cidr]) -> String {
    list.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// How the rules of the WAF on a server stand to the ones erpc.toml makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rules {
    /// No WAF runs there: the server has none, or one that is not active.
    NotRunning,
    /// One runs, with the config erpc.toml makes.
    Asked,
    /// One runs with another config, or with one that does not read.
    Other,
    /// One runs, and the server does not say with which config, or not
    /// which agent's proxy it is: its agent is from before it reported
    /// them. Not taken for erpc.toml's.
    Unsaid,
    /// One runs, and not as the agent installed on the server: an earlier
    /// agent started it, or the server could not tell which did. The
    /// config the server reports is the file as the installed agent reads
    /// it, which is not what such a proxy runs. Not taken for erpc.toml's.
    EarlierAgent,
    /// One runs, and was started before its config file or its unit on
    /// the server last changed, or a deploy that was writing them was
    /// ended there before it restarted it (the server says
    /// `before_config` for both), or the server could not tell when it was
    /// started. The config the server reports is the file as it is now,
    /// which such a proxy is not known to have read, under the unit as it
    /// is now, which it is not known to run under. Not taken for
    /// erpc.toml's.
    BeforeConfig,
}

/// How the rules the server's WAF runs stand to `wanted`, the config
/// erpc.toml makes ([`Manifest::waf_config`]). `waf` is what the agent's
/// `status` and `firewall-show` report of the WAF: its `config` is the
/// file its `waf-apply` wrote, as the agent installed there reads and
/// checks it; its `binary` says whether the proxy that runs is that
/// agent (`installed`), another (`other`), or could not be told
/// (`unknown`); and its `started` says whether the proxy was started
/// after its files last changed, that file and its unit (`after_config`),
/// before one of them did (`before_config`), or could not be told
/// (`unknown`).
///
/// They are erpc.toml's only when all three hold: the proxy runs the
/// agent installed, so that the config reported is read as the proxy
/// reads it; it was started after its files last changed, so that the
/// config reported is the one it was started with; and that config is
/// `wanted`, compared as values, every key of them: the same port with
/// other paths, methods or limits is another config. A proxy an earlier
/// agent started is its own case whatever the file says, and so is one
/// started before one of its files last changed. Where the server could
/// not tell which agent the proxy runs it is the first of those cases,
/// and where it could not tell when the proxy was started, the second:
/// a deploy restarts it either way. An agent that reports no `config`,
/// no `binary` or no `started` is from before it reported them.
pub(crate) fn rules(waf: &Value, wanted: &WafConfig) -> Rules {
    if waf["active"] != json!(true) {
        return Rules::NotRunning;
    }
    let (Some(reported), Some(binary), Some(started)) =
        (waf.get("config"), waf.get("binary"), waf.get("started"))
    else {
        return Rules::Unsaid;
    };
    if binary != "installed" {
        return Rules::EarlierAgent;
    }
    if started != "after_config" {
        return Rules::BeforeConfig;
    }
    match serde_json::from_value::<WafConfig>(reported.clone()) {
        Ok(in_force) if in_force == *wanted => Rules::Asked,
        _ => Rules::Other,
    }
}

/// What `status` and `firewall list` say where the server has a WAF whose
/// rules are not the ones erpc.toml now makes, with the deploy that makes
/// them so. None when they are, when no WAF runs there (which is said as
/// that), and when the server has none.
pub(crate) fn out_of_step(m: &Manifest, env: &str, waf: &Value, scope: &str) -> Option<String> {
    if waf.is_null() {
        return None;
    }
    let Some(wanted) = m.waf_config(env) else {
        return Some(t!("worker_waf.status.not_asked", scope));
    };
    // One that does not run is said as that, and so is a config that does
    // not read (no port), each with the same deploy.
    let read = waf["port"].is_u64();
    match rules(waf, &wanted) {
        Rules::Other if read => Some(t!("worker_waf.status.other_rules", scope)),
        Rules::EarlierAgent if read => Some(t!("worker_waf.status.earlier_agent", scope)),
        Rules::BeforeConfig if read => Some(t!("worker_waf.status.before_config", scope)),
        Rules::Unsaid => Some(t!("worker_waf.status.unsaid_rules", scope)),
        Rules::NotRunning
        | Rules::Asked
        | Rules::Other
        | Rules::EarlierAgent
        | Rules::BeforeConfig => None,
    }
}

/// What `erpc worker status` says of the WAF, a line each: how it is
/// ([`said`]), or that erpc.toml asks for one the server does not have
/// ([`absent`]); then, when the rules it runs are not erpc.toml's, that
/// ([`out_of_step`]). Nothing for an app with no `[waf]` on a server with
/// no WAF.
pub(crate) fn status_lines(m: &Manifest, env: &str, waf: &Value, scope: &str) -> Vec<String> {
    said(waf, scope)
        .or_else(|| m.waf.is_some().then(|| absent(scope)))
        .into_iter()
        .chain(out_of_step(m, env, waf, scope))
        .collect()
}

/// The same for `--json`, as `waf_rules`: null when the server has no WAF
/// for the worker, else `erpc_toml`, `other`, `earlier_agent` (the proxy
/// does not run the agent installed, or the server could not tell),
/// `before_config` (the proxy was started before its config or its unit
/// last changed, or the server could not tell when), `unreported` (an agent
/// that does not say which config it runs, which agent runs it, or
/// whether it was started after its config), `not_running`, or
/// `not_in_erpc_toml` when erpc.toml has no `[waf]` any more.
pub(crate) fn rules_named(m: &Manifest, env: &str, waf: &Value) -> Value {
    if waf.is_null() {
        return Value::Null;
    }
    let Some(wanted) = m.waf_config(env) else {
        return json!("not_in_erpc_toml");
    };
    json!(match rules(waf, &wanted) {
        Rules::NotRunning => "not_running",
        Rules::Asked => "erpc_toml",
        Rules::Other => "other",
        Rules::EarlierAgent => "earlier_agent",
        Rules::BeforeConfig => "before_config",
        Rules::Unsaid => "unreported",
    })
}

/// How the worker's WAF is, in one line, from what the agent's `status`
/// and `firewall-show` report as `waf`: where it listens and forwards to,
/// since when, and what it has counted since. None when the server has no
/// WAF for the worker.
///
/// The agent has checked what it reports, and it is checked again here,
/// where it is printed: the state is one of systemd's words, the address
/// an address, `since` a time ([`erpc_worker::waf::is_timestamp`]), each
/// count a number, each rule one of [`RULES`]; anything else is `?`. Why a
/// config does not read is the one free text, and is printed on its
/// line without a control character ([`crate::storage::clean`]).
pub(crate) fn said(waf: &Value, scope: &str) -> Option<String> {
    if waf.is_null() {
        return None;
    }
    let state = waf["state"]
        .as_str()
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        .unwrap_or("unknown");
    let Some(port) = waf["port"].as_u64() else {
        let error = waf["config_error"]
            .as_str()
            .map_or_else(|| "it has none".to_owned(), crate::storage::clean);
        return Some(t!("worker_waf.status.unread", state, error, scope));
    };
    if waf["active"] != json!(true) {
        return Some(t!("worker_waf.status.down", state, port, scope));
    }
    let upstream = waf["upstream"]
        .as_str()
        .filter(|address| address.parse::<core::net::SocketAddr>().is_ok())
        .unwrap_or("?");
    let counted = &waf["stats"];
    if !counted.is_object() {
        return Some(t!("worker_waf.status.no_counts", port, upstream));
    }
    let count = |name: &str| counted[name].as_u64().unwrap_or(0);
    // A request that was answered with a refusal is one of the requests; a
    // connection closed unanswered (a banned address, one over its
    // connection limit) never became one, so the two are said apart and
    // the requests add up.
    let by = |connection: bool| -> u64 {
        RULES
            .iter()
            .filter(|rule| CONNECTION_RULES.contains(rule) == connection)
            .filter_map(|rule| counted["blocked"][rule].as_u64())
            .sum()
    };
    Some(t!(
        "worker_waf.status.listening",
        port,
        upstream,
        since = counted["since"]
            .as_str()
            .filter(|since| erpc_worker::waf::is_timestamp(since))
            .unwrap_or("?"),
        requests = count("requests"),
        forwarded = count("forwarded"),
        blocked = by(false),
        refused = by(true),
        errors = count("upstream_errors"),
        banned = count("banned_now")
    ))
}

/// What the WAF blocked since it started, by rule, leaving out the rules
/// that blocked nothing. None when it has written no stats.
pub(crate) fn blocked_by_rule(waf: &Value) -> Option<String> {
    let stats = &waf["stats"];
    if !stats.is_object() {
        return None;
    }
    let rules: Vec<String> = RULES
        .iter()
        .filter_map(|rule| {
            let count = stats["blocked"][rule].as_u64().filter(|n| *n > 0)?;
            Some(format!("{rule} {count}"))
        })
        .collect();
    Some(if rules.is_empty() {
        t!("worker_waf.status.nothing_blocked")
    } else {
        t!("worker_waf.status.blocked", rules = rules.join(", "))
    })
}

/// What is said where erpc.toml asks for a WAF and the server has none.
pub(crate) fn absent(scope: &str) -> String {
    t!("worker_waf.status.absent", scope)
}

/// What a `--prepare` says of the WAF it did not touch; none without
/// `[waf]`.
pub(crate) fn prepared(lang: Lang, m: &Manifest) -> Option<String> {
    let port = m.waf.as_ref()?.port;
    Some(said_in!(lang, t!("worker_waf.done.prepared", port)))
}

/// A deploy, as far as the WAF is concerned.
pub(crate) struct Deploy<'a> {
    /// The worker's server.
    pub(crate) server: &'a dyn Server,
    /// What a hint adds to a command so that it acts on this app.
    pub(crate) scope: &'a str,
    /// The language of the summary: English under `--json`.
    pub(crate) lang: Lang,
    /// Where progress is said.
    pub(crate) say: &'a Say,
}

/// What a deploy did about the WAF.
pub(crate) struct Settled {
    /// For `--json`, as `waf`: null when the app has no WAF and the server
    /// had none.
    pub(crate) json: Value,
    /// The lines of the deploy's summary.
    pub(crate) text: Vec<String>,
}

impl Deploy<'_> {
    /// Makes the server's WAF what `m` says, once `release` is active and
    /// healthy. With `[waf]`: the config is applied and the proxy waited
    /// for, and only once the agent has answered that it listens is the
    /// firewall made what erpc.toml asks, where `synced`, what this
    /// deploy's firewall step did, left it otherwise
    /// ([`crate::worker_firewall::open_as_asked`]): an opening it held (no
    /// WAF listened on the port, or the one that did ran other rules), or
    /// one it narrowed with the limit on new connections then in force.
    /// Where the opening in force is erpc.toml's already, the firewall is
    /// asked nothing more. Without `[waf]`: a WAF an earlier deploy left
    /// is removed.
    ///
    /// # Errors
    ///
    /// When the proxy does not come up, with the agent's words for why
    /// (what systemd calls its unit, and the end of its journal). The
    /// release runs all the same, and the firewall is not touched: the
    /// port stays as the firewall step left it, closed or open to those
    /// it was open to, under the rules from before, which the agent has
    /// put back.
    pub(crate) fn settle(
        &self,
        m: &Manifest,
        env: &str,
        release: &str,
        synced: &Synced,
    ) -> Result<Settled, CliError> {
        let Some(config) = m.waf_config(env) else {
            return Ok(self.remove());
        };
        let (port, upstream) = (config.listen.port(), config.upstream);
        self.say
            .line(&t!("worker_waf.deploy.applying", port, upstream));
        let answer = self.server.waf_apply(&config)?;
        if answer["ok"] != json!(true) {
            // The agent's words, with the end of the proxy's journal in
            // them: on one line, and nothing a terminal acts on.
            let why = answer["error"]
                .as_str()
                .map_or_else(|| t!("worker_waf.deploy.no_reason"), crate::storage::clean);
            return Err(failed(t!("worker_waf.deploy.failed", release, why))
                .hint(t!("worker_waf.deploy.failed_hint", scope = self.scope)));
        }
        let changed = answer["changed"] == json!(true);
        self.say.line(&applied_said(port, &answer));
        // As erpc.toml asks, now that the WAF listens there with
        // erpc.toml's rules, where the firewall step left it otherwise:
        // the first deploy with a WAF, one that moved its port, one that
        // changed its rules and widened who is let in, or one that
        // changed its rules and the firewall's limit on new connections.
        let opening = crate::worker_firewall::open_as_asked(self.server, synced, self.say)?;
        let open_to: &[Cidr] = opening.as_ref().map_or(&[], |o| &o.allow);
        Ok(Settled {
            json: json!({
                "port": port,
                "listen": config.listen,
                "upstream": upstream,
                "changed": changed,
                "proxy": answer["proxy"],
                "restarted_because": answer["restarted_because"],
                "open_to": open_to,
                "new_connections": opening.as_ref().and_then(|o| o.limit),
            }),
            text: summary(self.lang, &config, opening.as_ref(), self.scope),
        })
    }

    /// Removes the WAF an earlier deploy left for an app that no longer
    /// has `[waf]`. One that cannot be removed is said and does not fail
    /// the deploy: the firewall no longer opens its port.
    fn remove(&self) -> Settled {
        let removed = self.server.waf_remove().and_then(|answer| {
            if answer["ok"] == json!(true) {
                Ok(answer["removed"] == json!(true))
            } else {
                // The agent's words, on one line as in `settle`.
                Err(failed(answer["error"].as_str().map_or_else(
                    || t!("worker_waf.deploy.no_reason"),
                    crate::storage::clean,
                )))
            }
        });
        match removed {
            Ok(false) => Settled {
                json: Value::Null,
                text: Vec::new(),
            },
            Ok(true) => {
                self.say.line(&t!("worker_waf.deploy.removed"));
                Settled {
                    json: json!({ "removed": true }),
                    text: vec![said_in!(self.lang, t!("worker_waf.done.removed"))],
                }
            }
            Err(e) => {
                let error = e.message;
                self.say
                    .line(&t!("worker_waf.deploy.not_removed", error = &error));
                let said = said_in!(self.lang, t!("worker_waf.deploy.not_removed", error));
                Settled {
                    json: json!({ "removed": false, "error": error }),
                    text: vec![format!("warning: {said}")],
                }
            }
        }
    }
}

/// What a deploy says once `waf-apply` has answered `ok`, from that
/// `answer`: that the WAF listens on `port`; and, where neither of its
/// files was written, that it does as before, or that it was restarted
/// and for what. Restarted for its start: it had been started before its
/// config or its unit last changed, or the server could not tell when,
/// so it runs the two as they are from now on, which it may not have.
/// Restarted for its agent: it was a proxy of an agent from before
/// the one installed, or the server could not tell, and its rules are as
/// they were.
fn applied_said(port: u16, answer: &Value) -> String {
    let changed = answer["changed"] == json!(true);
    let restarted = !changed && answer["proxy"] == json!("restarted");
    let because = answer["restarted_because"].as_str();
    let for_its_start = matches!(because, Some("older_than_config" | "unknown_start"));
    if changed {
        t!("worker_waf.deploy.listening", port)
    } else if restarted && for_its_start {
        t!("worker_waf.deploy.restarted_config", port)
    } else if restarted {
        t!("worker_waf.deploy.restarted", port)
    } else {
        t!("worker_waf.deploy.unchanged", port)
    }
}

/// What the end of a deploy says of the WAF: where it listens and
/// forwards, who is let in (`opening`, none for nobody) with the command
/// that lets someone in, and how to see what it blocks.
fn summary(lang: Lang, config: &WafConfig, opening: Option<&Opening>, scope: &str) -> Vec<String> {
    let (port, upstream) = (config.listen.port(), config.upstream);
    let first = match opening {
        Some(open) => {
            let limit = open.limit.map_or_else(String::new, |limit| {
                said_in!(
                    lang,
                    t!("worker_waf.done.limit", per_second = limit.per_second)
                )
            });
            said_in!(
                lang,
                t!(
                    "worker_waf.done.open",
                    port,
                    upstream,
                    addresses = addresses(&open.allow),
                    limit
                )
            )
        }
        None => said_in!(lang, t!("worker_waf.done.nobody", port, upstream, scope)),
    };
    vec![first, said_in!(lang, t!("worker_waf.done.see", scope))]
}

/// What the WAF `m` asks for will do, in two lines: what it listens on and
/// forwards, then what it holds each client address to. None when the app
/// has no `[waf]`.
pub(crate) fn described(m: &Manifest) -> Option<[String; 2]> {
    let waf = m.waf.as_ref()?;
    // The worker's id is in the config only as the name of its stats file.
    let config = waf.config(&m.name, m.run.port?);
    Some([
        listens(&config),
        limits(&config, waf.new_connections().as_ref()),
    ])
}

fn listens(config: &WafConfig) -> String {
    let every = t!("worker_waf.check.every_path");
    let allowed = if config.allow_paths.is_empty() {
        every
    } else {
        t!(
            "worker_waf.check.allowed",
            paths = config.allow_paths.join(", ")
        )
    };
    let paths = if config.deny_paths.is_empty() {
        allowed
    } else {
        t!(
            "worker_waf.check.denied",
            allowed,
            paths = config.deny_paths.join(", ")
        )
    };
    t!(
        "worker_waf.check.listens",
        port = config.listen.port(),
        upstream = config.upstream.port(),
        methods = config.methods.join(", "),
        paths,
        body = config.max_body_bytes,
        body_secs = config.body_timeout_secs
    )
}

fn limits(
    config: &WafConfig,
    new_connections: Option<&erpc_worker::server::NewConnections>,
) -> String {
    let rate = config.rate.map_or_else(
        || t!("worker_waf.check.rate_off"),
        |r| {
            t!(
                "worker_waf.check.rate",
                per_second = r.per_second,
                burst = r.burst
            )
        },
    );
    let connections = config.max_connections_per_address.map_or_else(
        || t!("worker_waf.check.connections_off"),
        |n| t!("worker_waf.check.connections", n),
    );
    let ban = config.ban.map_or_else(
        || t!("worker_waf.check.ban_off"),
        |b| {
            t!(
                "worker_waf.check.ban",
                after = b.after,
                window_secs = b.window_secs,
                for_secs = b.for_secs
            )
        },
    );
    let probes = if config.block_probes {
        t!("worker_waf.check.probes")
    } else {
        t!("worker_waf.check.probes_off")
    };
    let firewall = new_connections.map_or_else(
        || t!("worker_waf.check.firewall_off"),
        |limit| {
            t!(
                "worker_waf.check.firewall",
                per_second = limit.per_second,
                burst = limit.burst
            )
        },
    );
    t!(
        "worker_waf.check.limits",
        rate,
        connections,
        ban,
        probes,
        firewall
    )
}

#[cfg(test)]
mod tests {
    use erpc_core::i18n::Lang;
    use erpc_worker::manifest::Manifest;

    fn app(waf: &str) -> Manifest {
        Manifest::parse(&format!(
            "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n{waf}"
        ))
        .expect("valid")
    }

    #[test]
    fn check_says_what_a_waf_left_to_its_defaults_will_do() {
        let [listens, limits] = super::described(&app("[waf]\nport = 8080\n")).expect("a WAF");
        assert_eq!(
            listens,
            "port 8080, in front of the app on 127.0.0.1:3000: forwards GET, POST, PUT, DELETE \
             on every path, bodies up to 1048576 bytes that arrive within 30 s, not counting the \
             time the app takes to accept them"
        );
        assert_eq!(
            limits,
            "per address: 50 requests a second (burst 100), 32 connections at once, a 600 s \
             ban after 100 blocked requests in 60 s; scanner probes refused; the firewall drops \
             new connections over 50 a second (burst 100)"
        );
        assert_eq!(super::described(&app("")), None);
    }

    #[test]
    fn check_says_what_is_listed_and_what_is_off() {
        let waf = "[waf]\nport = 8080\nmethods = [\"GET\"]\nallow_paths = [\"/api/*\", \"/healthz\"]\n\
                   deny_paths = [\"/api/admin/*\"]\nrate = false\n\
                   max_connections_per_address = false\nban = false\nblock_probes = false\n\
                   new_connections = false\n";
        let [listens, limits] = super::described(&app(waf)).expect("a WAF");
        assert!(
            listens.contains("forwards GET on /api/*, /healthz only, never /api/admin/*,"),
            "{listens}"
        );
        assert_eq!(
            limits,
            "per address: no rate limit, no limit on connections, no ban; scanner probes not \
             looked for; the firewall does not limit new connections"
        );
        let only_denied = "[waf]\nport = 8080\ndeny_paths = [\"/admin\"]\n";
        let [listens, _] = super::described(&app(only_denied)).expect("a WAF");
        assert!(
            listens.contains("on every path, never /admin,"),
            "{listens}"
        );
    }

    /// What the agent reports of a WAF that runs and has counted: its
    /// `status`, as `crates/erpc-worker-agent/src/wafctl.rs` makes it.
    fn serving() -> serde_json::Value {
        serde_json::json!({
            "unit": "erpc-waf-bot-default.service",
            "state": "active",
            "active": true,
            "listen": "0.0.0.0:8080",
            "port": 8080,
            "upstream": "127.0.0.1:3000",
            "config": app(WAF).waf_config("default"),
            "started": "after_config",
            "binary": "installed",
            "config_error": null,
            "stats": {
                "format": 1,
                "since": "2026-11-11T09:00:00Z",
                "requests": 120,
                "forwarded": 100,
                "blocked": {
                    "method": 1, "path": 0, "denied": 2, "not_allowed": 0, "probe": 7,
                    "rate": 5, "body": 0, "malformed": 1, "banned": 3, "connections": 0,
                    "upgrade": 0
                },
                "banned_now": 1,
                "upstream_errors": 1
            },
            "stats_error": null
        })
    }

    const SCOPE: &str = " --env default";
    /// The `[waf]` the server's WAF in [`serving`] was deployed from.
    const WAF: &str = "[waf]\nport = 8080\n";

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "a case for every field of the config"
    )]
    fn the_servers_rules_are_erpc_tomls_only_when_every_key_of_the_config_is() {
        use super::Rules;
        use core::net::SocketAddr;
        use erpc_worker::waf::{Ban, Rate, WafConfig};
        let waf = serving();
        let rules = |toml: &str, waf: &serde_json::Value| {
            super::rules(waf, &app(toml).waf_config("default").expect("a config"))
        };
        assert_eq!(rules(WAF, &waf), Rules::Asked);
        // The same port, and one rule more, one fewer, or another number:
        // each is another config.
        for changed in [
            "[waf]\nport = 8080\ndeny_paths = [\"/admin/*\"]\n",
            "[waf]\nport = 8080\nallow_paths = [\"/api/*\"]\n",
            "[waf]\nport = 8080\nmethods = [\"GET\"]\n",
            "[waf]\nport = 8080\nmax_body_bytes = 4096\n",
            "[waf]\nport = 8080\nrate = false\n",
            "[waf]\nport = 8080\nban = { after = 5, window_secs = 60, for_secs = 600 }\n",
            "[waf]\nport = 8080\nblock_probes = false\n",
            "[waf]\nport = 8080\nbody_timeout_secs = 5\n",
            "[waf]\nport = 9090\n",
        ] {
            assert_eq!(rules(changed, &waf), Rules::Other, "{changed}");
        }
        // The firewall's own limit is not the proxy's config.
        assert_eq!(
            rules("[waf]\nport = 8080\nnew_connections = false\n", &waf),
            Rules::Asked
        );
        // Every field of the config, each changed alone, is another
        // config, whichever of the two has the change. The config is
        // taken apart here field by field, with none left out: a field
        // added to it does not compile until it is changed here too.
        let config = app(WAF).waf_config("default").expect("a config");
        let WafConfig {
            format,
            listen,
            upstream,
            methods,
            allow_paths,
            deny_paths,
            max_body_bytes,
            max_header_bytes,
            rate,
            max_connections_per_address,
            ban,
            block_probes,
            header_timeout_secs,
            body_timeout_secs,
            upstream_timeout_secs,
            stats_path,
        } = config.clone();
        let Rate { per_second, burst } = rate.expect("a rate");
        let Ban {
            after,
            window_secs,
            for_secs,
        } = ban.expect("a ban");
        let one_more = |list: &[String], item: &str| [list, &[item.to_owned()]].concat();
        let with = |change: &dyn Fn(&mut WafConfig)| {
            let mut changed = config.clone();
            change(&mut changed);
            changed
        };
        let each = [
            ("format", with(&|c| c.format = format + 1)),
            (
                "listen",
                with(&|c| c.listen = SocketAddr::new(listen.ip(), listen.port() + 1)),
            ),
            (
                "upstream",
                with(&|c| c.upstream = SocketAddr::new(upstream.ip(), upstream.port() + 1)),
            ),
            ("methods", with(&|c| c.methods = one_more(&methods, "HEAD"))),
            (
                "allow_paths",
                with(&|c| c.allow_paths = one_more(&allow_paths, "/api/*")),
            ),
            (
                "deny_paths",
                with(&|c| c.deny_paths = one_more(&deny_paths, "/admin/*")),
            ),
            (
                "max_body_bytes",
                with(&|c| c.max_body_bytes = max_body_bytes + 1),
            ),
            (
                "max_header_bytes",
                with(&|c| c.max_header_bytes = max_header_bytes + 1),
            ),
            ("rate", with(&|c| c.rate = None)),
            (
                "rate.per_second",
                with(&|c| {
                    c.rate = Some(Rate {
                        per_second: per_second + 1,
                        burst,
                    });
                }),
            ),
            (
                "rate.burst",
                with(&|c| {
                    c.rate = Some(Rate {
                        per_second,
                        burst: burst + 1,
                    });
                }),
            ),
            (
                "max_connections_per_address",
                with(&|c| {
                    c.max_connections_per_address = max_connections_per_address.map(|n| n + 1);
                }),
            ),
            (
                "max_connections_per_address off",
                with(&|c| c.max_connections_per_address = None),
            ),
            ("ban", with(&|c| c.ban = None)),
            (
                "ban.after",
                with(&|c| {
                    c.ban = Some(Ban {
                        after: after + 1,
                        window_secs,
                        for_secs,
                    });
                }),
            ),
            (
                "ban.window_secs",
                with(&|c| {
                    c.ban = Some(Ban {
                        after,
                        window_secs: window_secs + 1,
                        for_secs,
                    });
                }),
            ),
            (
                "ban.for_secs",
                with(&|c| {
                    c.ban = Some(Ban {
                        after,
                        window_secs,
                        for_secs: for_secs + 1,
                    });
                }),
            ),
            ("block_probes", with(&|c| c.block_probes = !block_probes)),
            (
                "header_timeout_secs",
                with(&|c| c.header_timeout_secs = header_timeout_secs + 1),
            ),
            (
                "body_timeout_secs",
                with(&|c| c.body_timeout_secs = body_timeout_secs + 1),
            ),
            (
                "upstream_timeout_secs",
                with(&|c| c.upstream_timeout_secs = upstream_timeout_secs + 1),
            ),
            (
                "stats_path",
                with(&|c| c.stats_path = format!("{stats_path}.other")),
            ),
        ];
        assert_eq!(super::rules(&waf, &config), Rules::Asked);
        for (field, changed) in &each {
            assert_ne!(*changed, config, "{field}");
            // erpc.toml makes the changed one, the server runs the other.
            assert_eq!(super::rules(&waf, changed), Rules::Other, "{field}");
            // And the other way round.
            let mut runs_changed = waf.clone();
            runs_changed["config"] = serde_json::to_value(changed).expect("json");
            assert_eq!(
                super::rules(&runs_changed, &config),
                Rules::Other,
                "{field}"
            );
            assert_eq!(
                super::rules(&runs_changed, changed),
                Rules::Asked,
                "{field}"
            );
        }
        // Another worker's config is not this one's, though all else is
        // the same: its stats file is named after its worker.
        let other = Manifest::parse(
            "name = \"other\"\nchain = \"solana\"\n[run]\nport = 3000\n[waf]\nport = 8080\n",
        )
        .expect("valid");
        assert_eq!(
            super::rules(&waf, &other.waf_config("default").expect("a config")),
            Rules::Other
        );
        // No report is not erpc.toml's rules: an agent from before it
        // reported one, a config that does not read, something else.
        let mut unsaid = waf.clone();
        unsaid.as_object_mut().expect("the WAF").remove("config");
        assert_eq!(rules(WAF, &unsaid), Rules::Unsaid);
        let mut unread = waf.clone();
        unread["config"] = serde_json::Value::Null;
        assert_eq!(rules(WAF, &unread), Rules::Other);
        unread["config"] = serde_json::json!("0.0.0.0:8080");
        assert_eq!(rules(WAF, &unread), Rules::Other);
        // The very config, run by a proxy that is not the agent installed
        // on the server, or that the server cannot tell of: the file reads
        // as erpc.toml's, and what runs is not taken for it. Nor is it
        // with another config, which a deploy replaces all the same.
        for binary in ["other", "unknown", "", "Installed"] {
            let mut earlier = waf.clone();
            earlier["binary"] = binary.into();
            assert_eq!(rules(WAF, &earlier), Rules::EarlierAgent, "{binary:?}");
            assert_eq!(
                rules("[waf]\nport = 8080\nmethods = [\"GET\"]\n", &earlier),
                Rules::EarlierAgent,
                "{binary:?}"
            );
        }
        let mut odd = waf.clone();
        odd["binary"] = true.into();
        assert_eq!(rules(WAF, &odd), Rules::EarlierAgent);
        odd["binary"] = serde_json::Value::Null;
        assert_eq!(rules(WAF, &odd), Rules::EarlierAgent);
        // An agent from before it said which binary runs says nothing of
        // it: unreported, as one that reports no config.
        let mut silent = waf.clone();
        silent.as_object_mut().expect("the WAF").remove("binary");
        assert_eq!(rules(WAF, &silent), Rules::Unsaid);
        // And a WAF that does not run runs no rules, whatever its file.
        let mut down = waf.clone();
        down["active"] = false.into();
        assert_eq!(rules(WAF, &down), Rules::NotRunning);
        down["binary"] = "other".into();
        assert_eq!(rules(WAF, &down), Rules::NotRunning);
        assert_eq!(rules(WAF, &serde_json::Value::Null), Rules::NotRunning);
    }

    #[test]
    fn a_proxy_started_before_its_config_last_changed_does_not_run_erpc_tomls_rules() {
        use super::Rules;
        use serde_json::json;
        let waf = serving();
        let rules = |toml: &str, waf: &serde_json::Value| {
            super::rules(waf, &app(toml).waf_config("default").expect("a config"))
        };
        let other = "[waf]\nport = 8080\nmethods = [\"GET\"]\n";
        assert_eq!(rules(WAF, &waf), Rules::Asked);
        // The very config erpc.toml makes, in a file the proxy was started
        // before, or is not known to have been started after: what runs is
        // the file from before. Nor is it with another config, which a
        // deploy replaces all the same.
        for started in [
            json!("before_config"),
            json!("unknown"),
            json!(""),
            json!("After_config"),
            json!("after_config "),
            json!(true),
            json!(1),
            json!(["after_config"]),
            json!(null),
        ] {
            let mut before = waf.clone();
            before["started"] = started.clone();
            assert_eq!(rules(WAF, &before), Rules::BeforeConfig, "{started}");
            assert_eq!(rules(other, &before), Rules::BeforeConfig, "{started}");
        }
        // A proxy an earlier agent started is said as that, whenever it
        // was started.
        let mut before = waf.clone();
        before["started"] = "before_config".into();
        let mut earlier = before.clone();
        earlier["binary"] = "other".into();
        assert_eq!(rules(WAF, &earlier), Rules::EarlierAgent);
        // An agent from before it said when its proxy was started says
        // nothing of it: unreported, as one that reports no config.
        let mut silent = waf.clone();
        silent.as_object_mut().expect("the WAF").remove("started");
        assert_eq!(rules(WAF, &silent), Rules::Unsaid);
        // And a WAF that does not run runs no rules.
        let mut down = before.clone();
        down["active"] = false.into();
        assert_eq!(rules(WAF, &down), Rules::NotRunning);

        // `status` and `firewall list` say so, with the deploy that
        // restarts it, and `--json` names it.
        let mut untold = waf.clone();
        untold["started"] = "unknown".into();
        for started in [&before, &untold] {
            assert_eq!(
                super::out_of_step(&app(WAF), "default", started, SCOPE).as_deref(),
                Some(
                    "WAF: it was started before its config or its unit on the server last \
                     changed, or a deploy that was writing them was ended before it restarted \
                     the WAF, or the server could not tell when it was started, so the rules it \
                     runs are not taken for erpc.toml's; `erpc worker deploy --env default` \
                     restarts it, and until then its port is not opened wider"
                )
            );
            assert_eq!(
                super::rules_named(&app(WAF), "default", started),
                json!("before_config")
            );
            let lines = super::status_lines(&app(WAF), "default", started, SCOPE);
            assert_eq!(lines.len(), 2, "{lines:?}");
            assert!(lines[0].starts_with("WAF: listening on port 8080, "));
        }
        // Down, or with a config that does not read, it is said as that.
        let mut unread = before.clone();
        unread["port"] = serde_json::Value::Null;
        unread["config"] = serde_json::Value::Null;
        for said_otherwise in [&down, &unread] {
            assert_eq!(
                super::out_of_step(&app(WAF), "default", said_otherwise, SCOPE),
                None
            );
        }
        assert_eq!(
            super::rules_named(&app(WAF), "default", &unread),
            json!("before_config")
        );
        // In every language, in words of its own, with the command as it
        // is typed.
        let mut by_agent = waf.clone();
        by_agent["binary"] = "other".into();
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let (said, of_agent) = crate::i18n::speaking(lang, || {
                (
                    super::out_of_step(&app(WAF), "default", &before, SCOPE).expect("a line"),
                    super::out_of_step(&app(WAF), "default", &by_agent, SCOPE).expect("a line"),
                )
            });
            assert!(
                said.contains("`erpc worker deploy --env default`") && !said.contains('{'),
                "{said}"
            );
            assert!(!said.contains("it was started before"), "{said}");
            assert_ne!(said, of_agent);
        }
    }

    #[test]
    fn a_deploy_says_whether_the_waf_was_written_restarted_or_left_running() {
        use serde_json::json;
        let said = |answer: serde_json::Value| super::applied_said(8080, &answer);
        // A file was written: it listens, started or restarted with it.
        for proxy in ["started", "restarted"] {
            assert_eq!(
                said(json!({
                    "ok": true, "changed": true, "proxy": proxy, "restarted_because": "changed"
                })),
                "the WAF listens on port 8080"
            );
        }
        // Nothing written: left running, or started where it had stopped.
        for proxy in ["running", "started"] {
            assert_eq!(
                said(json!({
                    "ok": true, "changed": false, "proxy": proxy, "restarted_because": null
                })),
                "the WAF listens on port 8080, as before"
            );
        }
        // Nothing written, and restarted: for the agent it ran, with the
        // rules it had; or for when it was started, with the rules of the
        // file, which it may not have run.
        let restarted = |because: &str| {
            said(json!({
                "ok": true, "changed": false, "proxy": "restarted", "restarted_because": because
            }))
        };
        for because in ["other_binary", "unknown_binary"] {
            assert_eq!(
                restarted(because),
                "the WAF listens on port 8080, restarted to run the agent installed now; its \
                 rules are as before"
            );
        }
        for because in ["older_than_config", "unknown_start"] {
            assert_eq!(
                restarted(because),
                "the WAF listens on port 8080, restarted with its config and its unit on the \
                 server as they are now: it had been started before one of them last changed, or \
                 a deploy that was writing them had been ended before it restarted the WAF, or \
                 the server could not tell when"
            );
        }
        // In every language, each in its own words.
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let lines = crate::i18n::speaking(lang, || {
                [
                    restarted("other_binary"),
                    restarted("older_than_config"),
                    said(json!({ "ok": true, "changed": false, "proxy": "running" })),
                    said(json!({ "ok": true, "changed": true, "proxy": "started" })),
                ]
            });
            for (at, line) in lines.iter().enumerate() {
                assert!(line.contains("8080") && !line.contains('{'), "{line}");
                assert!(!line.contains("the WAF listens"), "{line}");
                assert!(!lines[..at].contains(line), "{lines:?}");
            }
        }
    }

    /// A WAF the server calls `before_config` may have been started after
    /// both of its files last changed: where a deploy that was writing
    /// them was ended before it restarted the WAF, and systemd started it
    /// again since. The three sentences that give the reason name that
    /// case too, in every language.
    #[test]
    fn a_deploy_ended_before_its_restart_is_among_the_reasons_in_every_language() {
        use serde_json::json;
        let said = || {
            let mut before = serving();
            before["started"] = "before_config".into();
            [
                super::out_of_step(&app(WAF), "default", &before, SCOPE).expect("a line"),
                t!("worker_firewall.rules_before_config"),
                super::applied_said(
                    8080,
                    &json!({
                        "ok": true, "changed": false, "proxy": "restarted",
                        "restarted_because": "older_than_config",
                    }),
                ),
            ]
        };
        for line in said() {
            assert!(
                line.contains("a deploy that was writing them")
                    && line.contains("restarted the WAF"),
                "{line}"
            );
        }
        for (lang, ended, restart) in [
            (Lang::Ja, "デプロイが WAF を再起動する前に中断", "再起動"),
            (Lang::Zh, "部署在重启 WAF 之前被中断", "重启"),
            (
                Lang::Ru,
                "деплой, который их записывал, был прерван",
                "перезапуска WAF",
            ),
        ] {
            for line in crate::i18n::speaking(lang, said) {
                assert!(line.contains(ended) && line.contains(restart), "{line}");
                assert!(!line.contains("a deploy that was writing"), "{line}");
            }
        }
    }

    #[test]
    fn a_config_comes_back_from_a_server_as_erpc_toml_made_it() {
        // The config in force is compared with erpc.toml's once it has come
        // back in an agent's answer, where a character a terminal acts on
        // is replaced. No path pattern erpc.toml may hold has one, so a
        // config that was applied reads back equal, whatever its paths.
        for c in (0..=0x2_ffff).filter_map(char::from_u32) {
            let pattern = format!("/a{c}b");
            if erpc_worker::waf::path_pattern(&pattern).is_ok() {
                assert_eq!(
                    crate::worker_remote::shown(&pattern),
                    pattern,
                    "U+{:04X}",
                    u32::from(c)
                );
            }
        }
        let m = app("[waf]\nport = 8080\ndeny_paths = [\"/caf\u{e9}/\u{65e5}\u{672c}/*\"]\n");
        let config = m.waf_config("default").expect("a config");
        let mut waf = serving();
        waf["config"] = serde_json::to_value(&config).expect("json");
        let sent =
            serde_json::to_vec(&serde_json::json!({ "ok": true, "waf": waf })).expect("json");
        let answer = crate::worker_remote::answer(&sent).expect("an answer");
        assert_eq!(super::rules(&answer["waf"], &config), super::Rules::Asked);
    }

    #[test]
    fn status_says_when_the_server_runs_rules_that_are_not_erpc_tomls() {
        let waf = serving();
        let tightened = app("[waf]\nport = 8080\ndeny_paths = [\"/admin/*\"]\n");
        assert_eq!(
            super::out_of_step(&tightened, "default", &waf, SCOPE).as_deref(),
            Some(
                "WAF: the rules it runs are not erpc.toml's; `erpc worker deploy --env default` \
                 puts erpc.toml's in place, and until then its port is not opened wider"
            )
        );
        assert_eq!(
            super::rules_named(&tightened, "default", &waf),
            serde_json::json!("other")
        );
        // In `status`, under the line that says how the WAF is.
        let lines = super::status_lines(&tightened, "default", &waf, SCOPE);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].starts_with("WAF: listening on port 8080, "),
            "{lines:?}"
        );
        assert!(lines[1].starts_with("WAF: the rules it runs are not erpc.toml's; "));
        // The same rules: nothing to say, and --json says so.
        assert_eq!(super::out_of_step(&app(WAF), "default", &waf, SCOPE), None);
        assert_eq!(
            super::status_lines(&app(WAF), "default", &waf, SCOPE).len(),
            1
        );
        assert_eq!(
            super::rules_named(&app(WAF), "default", &waf),
            serde_json::json!("erpc_toml")
        );
        // An agent that does not say which config it runs.
        let mut unsaid = waf.clone();
        unsaid.as_object_mut().expect("the WAF").remove("config");
        let said = super::out_of_step(&app(WAF), "default", &unsaid, SCOPE).expect("a line");
        assert!(
            said.starts_with("WAF: the server does not say which rules it runs ")
                && said.contains("`erpc worker deploy --env default`"),
            "{said}"
        );
        assert_eq!(
            super::rules_named(&app(WAF), "default", &unsaid),
            serde_json::json!("unreported")
        );
        // The config erpc.toml makes, in a proxy an earlier agent started
        // (a newer one was installed since), or one the server cannot
        // tell of.
        let mut earlier = waf.clone();
        earlier["binary"] = "other".into();
        let mut untold = waf.clone();
        untold["binary"] = "unknown".into();
        for started in [&earlier, &untold] {
            assert_eq!(
                super::out_of_step(&app(WAF), "default", started, SCOPE).as_deref(),
                Some(
                    "WAF: it was started by an earlier agent than the one installed, or the \
                     server could not tell which, so the rules it runs are not taken for \
                     erpc.toml's; `erpc worker deploy --env default` restarts it, and until then \
                     its port is not opened wider"
                )
            );
            assert_eq!(
                super::rules_named(&app(WAF), "default", started),
                serde_json::json!("earlier_agent")
            );
            let lines = super::status_lines(&app(WAF), "default", started, SCOPE);
            assert_eq!(lines.len(), 2, "{lines:?}");
            assert!(lines[1].starts_with("WAF: it was started by an earlier agent "));
        }
        // erpc.toml has no [waf] any more.
        assert_eq!(
            super::out_of_step(&app(""), "default", &waf, SCOPE).as_deref(),
            Some(
                "WAF: erpc.toml has no [waf] any more; `erpc worker deploy --env default` \
                 removes the one on the server"
            )
        );
        assert_eq!(
            super::rules_named(&app(""), "default", &waf),
            serde_json::json!("not_in_erpc_toml")
        );
        // A WAF that is down, or whose config does not read, is said as
        // that, and one the server does not have as absent.
        let mut down = waf.clone();
        down["active"] = false.into();
        assert_eq!(
            super::out_of_step(&tightened, "default", &down, SCOPE),
            None
        );
        assert_eq!(
            super::rules_named(&tightened, "default", &down),
            serde_json::json!("not_running")
        );
        let mut unread = waf.clone();
        unread["port"] = serde_json::Value::Null;
        unread["config"] = serde_json::Value::Null;
        assert_eq!(
            super::out_of_step(&app(WAF), "default", &unread, SCOPE),
            None
        );
        assert_eq!(
            super::rules_named(&app(WAF), "default", &unread),
            serde_json::json!("other")
        );
        // The same of a proxy an earlier agent started: down, or with a
        // config that does not read, is what is said of it.
        let mut down_earlier = down.clone();
        down_earlier["binary"] = "unknown".into();
        let mut unread_earlier = unread.clone();
        unread_earlier["binary"] = "other".into();
        for said_otherwise in [&down_earlier, &unread_earlier] {
            assert_eq!(
                super::out_of_step(&app(WAF), "default", said_otherwise, SCOPE),
                None
            );
            assert_eq!(
                super::status_lines(&app(WAF), "default", said_otherwise, SCOPE).len(),
                1
            );
        }
        assert_eq!(
            super::rules_named(&app(WAF), "default", &unread_earlier),
            serde_json::json!("earlier_agent")
        );
        let none = serde_json::Value::Null;
        assert_eq!(
            super::status_lines(&tightened, "default", &none, SCOPE),
            [super::absent(SCOPE)]
        );
        assert!(super::status_lines(&app(""), "default", &none, SCOPE).is_empty());
        assert_eq!(
            super::out_of_step(&tightened, "default", &none, SCOPE),
            None
        );
        assert_eq!(super::rules_named(&tightened, "default", &none), none);
        // In every language, with the command as it is typed.
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let said = crate::i18n::speaking(lang, || {
                [
                    super::out_of_step(&tightened, "default", &waf, SCOPE).expect("a line"),
                    super::out_of_step(&app(WAF), "default", &unsaid, SCOPE).expect("a line"),
                    super::out_of_step(&app(WAF), "default", &earlier, SCOPE).expect("a line"),
                    super::out_of_step(&app(""), "default", &waf, SCOPE).expect("a line"),
                ]
            });
            for line in &said {
                assert!(
                    line.contains("`erpc worker deploy --env default`") && !line.contains('{'),
                    "{line}"
                );
                assert!(!line.contains("the rules it runs"), "{line}");
            }
            // Each its own words.
            assert!(
                said[0] != said[1] && said[1] != said[2] && said[0] != said[2],
                "{said:?}"
            );
        }
    }

    /// An app behind the WAF `waf` describes, deployed to one server, with
    /// `allow` as its `app_allow`.
    fn deployed(waf: &str, allow: &str) -> Manifest {
        app(&format!(
            "{waf}[env.default]\nhost = \"203.0.113.10\"\n\
             [env.default.firewall]\napp_allow = [{allow}]\n"
        ))
    }

    const EVERYONE: &str = "\"0.0.0.0/0\", \"::/0\"";
    const ONE: &str = "\"198.51.100.7\"";
    const RELEASE: &str = "20261111T090000Z-1a2b3c4d";

    /// What a deploy asks of `server` about the firewall and the WAF, in
    /// order: at its firewall step, before the release
    /// ([`crate::worker_firewall::sync`]), and then at its last step,
    /// once the release runs ([`super::Deploy::settle`]), which is handed
    /// what the firewall step did; and what the last step answered.
    fn deploy(
        m: &Manifest,
        server: &crate::worker_firewall::recorded::Recorded,
    ) -> (
        Vec<String>,
        Vec<String>,
        Result<super::Settled, crate::error::CliError>,
    ) {
        let say = crate::node_common::Say { quiet: true };
        let me = Some("198.51.100.7".parse().expect("an address"));
        let synced =
            crate::worker_firewall::sync(server, m, "default", &m.env["default"], me, &say)
                .expect("the firewall step");
        let before = server.asked();
        let settled = super::Deploy {
            server,
            scope: SCOPE,
            lang: Lang::En,
            say: &say,
        }
        .settle(m, "default", RELEASE, &synced);
        (before, server.asked(), settled)
    }

    #[test]
    fn a_deploy_opens_the_held_port_only_after_waf_apply_has_answered_ok() {
        use crate::worker_firewall::recorded::{Recorded, running};
        use erpc_worker::server::Opening;
        let m = deployed(WAF, EVERYONE);
        let config = m.waf_config("default").expect("a config");
        let everyone = Opening::for_app(&m, &m.env["default"]).expect("an opening");
        // What an earlier deploy left: other rules, the port open to one
        // address.
        let mut earlier = config.clone();
        earlier.deny_paths = vec!["/old/*".to_owned()];
        let narrow = deployed(WAF, ONE);
        let one = Opening::for_app(&narrow, &narrow.env["default"]).expect("an opening");
        let first = || Recorded::with(&serde_json::Value::Null, "bot-default", None);
        let second = || Recorded::with(&running(&earlier), "bot-default", Some(&one));

        // A first deploy. The port stays closed at the firewall step; the
        // WAF comes up, its config first, and only then the port.
        let (before, after, settled) = deploy(&m, &first());
        assert_eq!(before, ["allow-ssh 198.51.100.7", "firewall-show", "close"]);
        assert_eq!(
            after,
            [
                "waf-apply 0.0.0.0:8080",
                "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
            ]
        );
        let settled = settled.expect("settled");
        assert_eq!(
            settled.json["open_to"],
            serde_json::json!(["0.0.0.0/0", "::/0"])
        );
        assert!(settled.text[0].contains("the port is open to 0.0.0.0/0, ::/0"));
        // The same where it was held under an earlier deploy's rules: left
        // open to the one address until the new rules are there.
        let (before, after, settled) = deploy(&m, &second());
        assert_eq!(
            before,
            [
                "allow-ssh 198.51.100.7",
                "firewall-show",
                "open 8080 to 198.51.100.7/32, limit 50/100"
            ]
        );
        assert_eq!(
            after,
            [
                "waf-apply 0.0.0.0:8080",
                "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
            ]
        );
        assert_eq!(settled.expect("settled").json["changed"], true);

        // The WAF does not come up: the deploy fails with the agent's
        // words, on one line whatever they hold, and the firewall is not
        // touched.
        for mut server in [first(), second()] {
            server.waf_applied = serde_json::json!({
                "ok": false,
                "error": "the WAF did not come up on 0.0.0.0:8080 within 10 s; its journal \
                          ends:\n\tcould not listen",
                "unit": "erpc-waf-bot-default.service",
            });
            let (_, after, settled) = deploy(&m, &server);
            assert_eq!(after, ["waf-apply 0.0.0.0:8080"]);
            let failed = settled.err().expect("failed");
            assert_eq!(
                failed.message,
                "release 20261111T090000Z-1a2b3c4d runs, and its WAF did not come up: the WAF \
                 did not come up on 0.0.0.0:8080 within 10 s; its journal ends:??could not listen"
            );
            assert!(
                failed
                    .hint
                    .is_some_and(|h| h.contains("`erpc worker deploy --env default`")),
            );
            // An answer that does not say it is ok is not one.
            server.waf_applied = serde_json::json!({});
            let (_, after, settled) = deploy(&m, &server);
            assert!(settled.is_err());
            assert_eq!(after, ["waf-apply 0.0.0.0:8080"]);
        }

        // The server runs erpc.toml's rules and has the opening erpc.toml
        // asks for: the config is applied, and the firewall asked nothing
        // more.
        let same = Recorded::with(&running(&config), "bot-default", Some(&everyone));
        let (before, after, settled) = deploy(&m, &same);
        assert_eq!(
            before,
            [
                "allow-ssh 198.51.100.7",
                "firewall-show",
                "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
            ]
        );
        assert_eq!(after, ["waf-apply 0.0.0.0:8080"]);
        let settled = settled.expect("settled");
        assert_eq!(
            settled.json["open_to"],
            serde_json::json!(["0.0.0.0/0", "::/0"])
        );
        assert_eq!(
            settled.json["new_connections"],
            serde_json::json!({ "per_second": 50, "burst": 100 })
        );
    }

    #[test]
    fn a_deploy_fails_when_the_server_does_not_take_one_of_its_last_steps() {
        use crate::worker_firewall::recorded::Recorded;
        let m = deployed(WAF, EVERYONE);
        let first = || Recorded::with(&serde_json::Value::Null, "bot-default", None);
        let (waf_apply, open) = (
            "waf-apply 0.0.0.0:8080",
            "open 8080 to 0.0.0.0/0, ::/0, limit 50/100",
        );
        // `waf-apply` could not be asked, or its answer did not come back:
        // not taken for one that says ok. The deploy fails there, and the
        // port is not opened.
        let mut server = first();
        server.fails = vec![waf_apply];
        let (_, after, settled) = deploy(&m, &server);
        assert_eq!(after, [waf_apply]);
        assert_eq!(
            settled.err().expect("failed").message,
            "the server did not do it: waf-apply 0.0.0.0:8080"
        );
        // The WAF is up and the server does not take the opening: the
        // deploy fails, and does not report a port open that is not.
        let mut server = first();
        server.fails = vec![open];
        let (_, after, settled) = deploy(&m, &server);
        assert_eq!(after, [waf_apply, open]);
        assert_eq!(
            settled.err().expect("failed").message,
            "the server did not do it: open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
        );
        // The same of its firewall step, before the release: one that
        // fails ends the deploy there, and nothing is asked after it.
        let say = crate::node_common::Say { quiet: true };
        for (fails, asked) in [
            ("allow-ssh 198.51.100.7", 1),
            ("firewall-show", 2),
            ("close", 3),
        ] {
            let mut server = first();
            server.fails = vec![fails];
            let me = Some("198.51.100.7".parse().expect("an address"));
            let synced =
                crate::worker_firewall::sync(&server, &m, "default", &m.env["default"], me, &say);
            assert_eq!(
                synced.err().expect("failed").message,
                format!("the server did not do it: {fails}")
            );
            assert_eq!(server.asked().len(), asked, "{fails}");
        }
    }

    #[test]
    fn a_deploy_says_each_thing_it_does_about_the_waf_and_its_port() {
        use crate::node_common::heard;
        use crate::worker_firewall::recorded::{Recorded, running};
        use erpc_worker::server::Opening;
        let m = deployed(WAF, EVERYONE);
        let config = m.waf_config("default").expect("a config");
        let everyone = Opening::for_app(&m, &m.env["default"]).expect("an opening");
        let narrow = deployed(WAF, ONE);
        let one = Opening::for_app(&narrow, &narrow.env["default"]).expect("an opening");
        let mut earlier = config.clone();
        earlier.deny_paths = vec!["/old/*".to_owned()];
        // What the last step says, after the firewall step's own lines.
        let last_step = |server: &Recorded| {
            let (_, after, settled) = deploy(&m, server);
            assert!(settled.is_ok());
            let said = heard::take();
            let from = said
                .iter()
                .position(|line| line.starts_with("putting the WAF in front of it"))
                .expect("the last step begins");
            (after, said[from..].to_vec())
        };
        let applying = "putting the WAF in front of it: port 8080, forwarding to 127.0.0.1:3000";
        let limit = "new connections over 50 a second from one address dropped (burst 100)";

        // A first deploy: the WAF is put in place, and its port opened
        // because a WAF listens there now.
        let (after, said) = last_step(&Recorded::with(
            &serde_json::Value::Null,
            "bot-default",
            None,
        ));
        assert_eq!(after.len(), 2, "{after:?}");
        assert_eq!(
            said,
            [
                applying.to_owned(),
                "the WAF listens on port 8080".to_owned(),
                format!("the WAF listens there now: opening port 8080 to 0.0.0.0/0, ::/0, {limit}"),
            ]
        );
        // One that replaces an earlier deploy's rules: its port is opened
        // because the WAF runs erpc.toml's rules now.
        let (after, said) = last_step(&Recorded::with(
            &running(&earlier),
            "bot-default",
            Some(&one),
        ));
        assert_eq!(after.len(), 2, "{after:?}");
        assert_eq!(
            said[2],
            format!(
                "the WAF runs erpc.toml's rules now: opening port 8080 to 0.0.0.0/0, ::/0, \
                 {limit}"
            )
        );
        // One that finds everything as erpc.toml has it: the WAF is said
        // to be as before, and nothing is said of a port not touched.
        let mut same = Recorded::with(&running(&config), "bot-default", Some(&everyone));
        same.waf_applied = serde_json::json!({ "ok": true, "changed": false, "proxy": "running" });
        let (after, said) = last_step(&same);
        assert_eq!(after, ["waf-apply 0.0.0.0:8080"]);
        assert_eq!(
            said,
            [
                applying.to_owned(),
                "the WAF listens on port 8080, as before".to_owned()
            ]
        );
    }

    #[test]
    fn a_deploy_that_installed_a_newer_agent_widens_the_port_only_once_the_proxy_was_restarted() {
        use crate::worker_firewall::recorded::{Recorded, running};
        use erpc_worker::server::Opening;
        // erpc.toml asks for everyone. The server has the very config
        // erpc.toml makes and the port open to one address; the deploy's
        // step 4 has just installed a newer agent, so the proxy that runs
        // is a process of the one from before.
        let m = deployed(WAF, EVERYONE);
        let narrow = deployed(WAF, ONE);
        let one = Opening::for_app(&narrow, &narrow.env["default"]).expect("an opening");
        let everyone = Opening::for_app(&m, &m.env["default"]).expect("an opening");
        let config = m.waf_config("default").expect("a config");
        let step_5 = |opening: &str| {
            [
                "allow-ssh 198.51.100.7".to_owned(),
                "firewall-show".to_owned(),
                opening.to_owned(),
            ]
        };
        // What `waf-apply` answers when it restarts a proxy for its binary
        // alone: neither file changed.
        let restarted = |because: &str| {
            serde_json::json!({
                "ok": true,
                "changed": false,
                "proxy": "restarted",
                "restarted_because": because,
            })
        };
        for (binary, because) in [("other", "other_binary"), ("unknown", "unknown_binary")] {
            let mut on_server = running(&config);
            on_server["binary"] = binary.into();
            // The firewall step, before the release: the widening is held
            // and the port left as it is, though the file reads as
            // erpc.toml's. `waf-apply` restarts the proxy, and only then
            // is the port opened as erpc.toml asks.
            let mut server = Recorded::with(&on_server, "bot-default", Some(&one));
            server.waf_applied = restarted(because);
            let (before, after, settled) = deploy(&m, &server);
            assert_eq!(
                before,
                step_5("open 8080 to 198.51.100.7/32, limit 50/100"),
                "{binary}"
            );
            assert_eq!(
                after,
                [
                    "waf-apply 0.0.0.0:8080",
                    "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
                ],
                "{binary}"
            );
            let settled = settled.expect("settled");
            assert_eq!(settled.json["changed"], false);
            assert_eq!(settled.json["proxy"], "restarted");
            assert_eq!(settled.json["restarted_because"], because);
            assert_eq!(
                settled.json["open_to"],
                serde_json::json!(["0.0.0.0/0", "::/0"])
            );

            // A proxy that does not come back up: the port stays as the
            // firewall step left it, open to the one address.
            server.waf_applied = serde_json::json!({ "ok": false, "error": "it did not" });
            let (before, after, settled) = deploy(&m, &server);
            assert_eq!(before, step_5("open 8080 to 198.51.100.7/32, limit 50/100"));
            assert_eq!(after, ["waf-apply 0.0.0.0:8080"]);
            assert!(settled.is_err());

            // The port closed: it stays closed until the proxy was
            // restarted.
            let mut server = Recorded::with(&on_server, "bot-default", None);
            server.waf_applied = restarted(because);
            let (before, after, _) = deploy(&m, &server);
            assert_eq!(before, step_5("close"));
            assert_eq!(
                after,
                [
                    "waf-apply 0.0.0.0:8080",
                    "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
                ]
            );

            // The opening in force is the one erpc.toml asks for: nothing
            // is widened, so it is applied again as it is; the proxy is
            // restarted, and the firewall asked nothing more.
            let mut server = Recorded::with(&on_server, "bot-default", Some(&everyone));
            server.waf_applied = restarted(because);
            let (before, after, settled) = deploy(&m, &server);
            assert_eq!(before, step_5("open 8080 to 0.0.0.0/0, ::/0, limit 50/100"));
            assert_eq!(after, ["waf-apply 0.0.0.0:8080"]);
            assert_eq!(settled.expect("settled").json["restarted_because"], because);
        }
    }

    #[test]
    fn a_deploy_restarts_a_proxy_started_before_its_config_and_only_then_widens_the_port() {
        use crate::worker_firewall::recorded::{Recorded, running};
        use erpc_worker::server::Opening;
        // A deploy before this one ended between writing the WAF's config
        // and restarting the proxy: the file on the server is the config
        // erpc.toml makes, and the proxy runs the one from before. Or the
        // server cannot tell when the proxy was started. erpc.toml asks
        // for everyone, and the port is open to one address.
        let m = deployed(WAF, EVERYONE);
        let narrow = deployed(WAF, ONE);
        let one = Opening::for_app(&narrow, &narrow.env["default"]).expect("an opening");
        let config = m.waf_config("default").expect("a config");
        let step_5 = [
            "allow-ssh 198.51.100.7",
            "firewall-show",
            "open 8080 to 198.51.100.7/32, limit 50/100",
        ];
        for (started, because) in [
            ("before_config", "older_than_config"),
            ("unknown", "unknown_start"),
        ] {
            let mut on_server = running(&config);
            on_server["started"] = started.into();
            // The firewall step holds the widening, though the file reads
            // as erpc.toml's. `waf-apply` restarts the proxy, writing
            // nothing, and only then is the port opened as erpc.toml asks.
            let mut server = Recorded::with(&on_server, "bot-default", Some(&one));
            server.waf_applied = serde_json::json!({
                "ok": true,
                "changed": false,
                "proxy": "restarted",
                "restarted_because": because,
            });
            let (before, after, settled) = deploy(&m, &server);
            assert_eq!(before, step_5, "{started}");
            assert_eq!(
                after,
                [
                    "waf-apply 0.0.0.0:8080",
                    "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
                ],
                "{started}"
            );
            let settled = settled.expect("settled");
            assert_eq!(settled.json["changed"], false);
            assert_eq!(settled.json["proxy"], "restarted");
            assert_eq!(settled.json["restarted_because"], because);
            assert_eq!(
                settled.json["open_to"],
                serde_json::json!(["0.0.0.0/0", "::/0"])
            );
            // A proxy that does not come back up: the port stays as the
            // firewall step left it, open to the one address.
            server.waf_applied = serde_json::json!({ "ok": false, "error": "it did not" });
            let (before, after, settled) = deploy(&m, &server);
            assert_eq!(before, step_5, "{started}");
            assert_eq!(after, ["waf-apply 0.0.0.0:8080"]);
            assert!(settled.is_err());
        }
    }

    #[test]
    fn a_deploy_reaches_waf_apply_where_the_servers_config_does_not_read() {
        use crate::worker_firewall::recorded::{Recorded, running};
        use erpc_worker::server::Opening;
        // The WAF on the server runs, and its config does not read there
        // (the agent installed does not take the file): the agent reports
        // no config and no port.
        let m = deployed(WAF, EVERYONE);
        let mut unread = running(&m.waf_config("default").expect("a config"));
        for gone in ["config", "listen", "port", "upstream"] {
            unread[gone] = serde_json::Value::Null;
        }
        unread["config_error"] = "the WAF config is not valid: missing field `format`".into();
        let step_5 = |opening: &str| {
            [
                "allow-ssh 198.51.100.7".to_owned(),
                "firewall-show".to_owned(),
                opening.to_owned(),
            ]
        };

        // Its port is open to everyone, which is what erpc.toml asks for.
        // The firewall step asks for the opening in force again, as it
        // is, limit and all: the one request the agent takes for everyone
        // on a port whose WAF it cannot read (its
        // `the_opening_in_force_is_applied_again_though_the_wafs_config_does_not_read`).
        // So the deploy gets to `waf-apply`, which writes a config that
        // reads.
        let tighter = deployed(
            "[waf]\nport = 8080\nnew_connections = { per_second = 5, burst = 10 }\n",
            EVERYONE,
        );
        let in_force = Opening::for_app(&tighter, &tighter.env["default"]).expect("an opening");
        let server = Recorded::with(&unread, "bot-default", Some(&in_force));
        let (before, after, settled) = deploy(&m, &server);
        assert_eq!(
            before,
            step_5("open 8080 to 0.0.0.0/0, ::/0, limit 5/10"),
            "the opening in force, not erpc.toml's"
        );
        // And then the opening erpc.toml asks for, under a config the
        // agent reads.
        assert_eq!(
            after,
            [
                "waf-apply 0.0.0.0:8080",
                "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
            ]
        );
        assert!(settled.is_ok());

        // Open to one address, with everyone asked for: the opening in
        // force again, the wider one only after `waf-apply`.
        let narrow = deployed(WAF, ONE);
        let one = Opening::for_app(&narrow, &narrow.env["default"]).expect("an opening");
        let server = Recorded::with(&unread, "bot-default", Some(&one));
        let (before, after, _) = deploy(&m, &server);
        assert_eq!(before, step_5("open 8080 to 198.51.100.7/32, limit 50/100"));
        assert_eq!(
            after,
            [
                "waf-apply 0.0.0.0:8080",
                "open 8080 to 0.0.0.0/0, ::/0, limit 50/100"
            ]
        );
    }

    #[test]
    fn a_deploy_leaves_the_firewall_with_the_limit_on_new_connections_erpc_toml_gives() {
        use crate::worker_firewall::recorded::{Recorded, running};
        use erpc_worker::server::Opening;
        // What the last deploy left on the server: its rules, and the port
        // open to one address, with a limit on new connections or without.
        let last = deployed(WAF, ONE);
        let on_server = running(&last.waf_config("default").expect("a config"));
        let limited = Opening::for_app(&last, &last.env["default"]).expect("an opening");
        let unlimited = Opening {
            limit: None,
            ..limited.clone()
        };
        let tighter = "[waf]\nport = 8080\ndeny_paths = [\"/admin/*\"]\n";
        let step_5 = |opening: &str| {
            [
                "allow-ssh 198.51.100.7".to_owned(),
                "firewall-show".to_owned(),
                opening.to_owned(),
            ]
        };

        // `[waf]` gains a rule and a tighter limit, for the same address.
        // The firewall step keeps the limit in force, under the old rules;
        // once the new ones are there, the limit is erpc.toml's.
        let m = deployed(
            &format!("{tighter}new_connections = {{ per_second = 5, burst = 10 }}\n"),
            ONE,
        );
        let server = Recorded::with(&on_server, "bot-default", Some(&limited));
        let (before, after, settled) = deploy(&m, &server);
        assert_eq!(before, step_5("open 8080 to 198.51.100.7/32, limit 50/100"));
        assert_eq!(
            after,
            [
                "waf-apply 0.0.0.0:8080",
                "open 8080 to 198.51.100.7/32, limit 5/10"
            ]
        );
        let settled = settled.expect("settled");
        assert_eq!(
            settled.json["new_connections"],
            serde_json::json!({ "per_second": 5, "burst": 10 })
        );
        assert!(
            settled.text[0].ends_with(
                "the port is open to 198.51.100.7/32, with new connections over 5 a second \
                 from one address dropped."
            ),
            "{:?}",
            settled.text
        );

        // `[waf]` gains a rule and its default limit, with none in force.
        let m = deployed(tighter, ONE);
        let server = Recorded::with(&on_server, "bot-default", Some(&unlimited));
        let (before, after, settled) = deploy(&m, &server);
        assert_eq!(before, step_5("open 8080 to 198.51.100.7/32"));
        assert_eq!(
            after,
            [
                "waf-apply 0.0.0.0:8080",
                "open 8080 to 198.51.100.7/32, limit 50/100"
            ]
        );
        assert_eq!(
            settled.expect("settled").json["new_connections"],
            serde_json::json!({ "per_second": 50, "burst": 100 })
        );

        // `[waf]` gains a rule and turns the limit off, with one in force.
        let m = deployed(&format!("{tighter}new_connections = false\n"), ONE);
        let server = Recorded::with(&on_server, "bot-default", Some(&limited));
        let (before, after, settled) = deploy(&m, &server);
        assert_eq!(before, step_5("open 8080 to 198.51.100.7/32, limit 50/100"));
        assert_eq!(
            after,
            ["waf-apply 0.0.0.0:8080", "open 8080 to 198.51.100.7/32"]
        );
        let settled = settled.expect("settled");
        assert!(settled.json["new_connections"].is_null());
        assert!(
            settled.text[0].ends_with("the port is open to 198.51.100.7/32."),
            "{:?}",
            settled.text
        );

        // `[waf]` gains a rule and nothing of the opening differs: the
        // firewall is asked nothing more once the rules are there.
        let m = deployed(tighter, ONE);
        let server = Recorded::with(&on_server, "bot-default", Some(&limited));
        let (before, after, settled) = deploy(&m, &server);
        assert_eq!(before, step_5("open 8080 to 198.51.100.7/32, limit 50/100"));
        assert_eq!(after, ["waf-apply 0.0.0.0:8080"]);
        assert_eq!(
            settled.expect("settled").json["new_connections"],
            serde_json::json!({ "per_second": 50, "burst": 100 })
        );
        // Nor where nobody is listed: the port is closed, and stays so.
        let m = deployed(tighter, "");
        let server = Recorded::with(&on_server, "bot-default", Some(&limited));
        let (before, after, settled) = deploy(&m, &server);
        assert_eq!(before, step_5("close"));
        assert_eq!(after, ["waf-apply 0.0.0.0:8080"]);
        assert_eq!(
            settled.expect("settled").json["open_to"],
            serde_json::json!([])
        );
    }

    #[test]
    fn a_deploy_without_waf_removes_the_one_an_earlier_deploy_left() {
        use crate::worker_firewall::recorded::Recorded;
        // The app's own port, opened as erpc.toml asks at the firewall
        // step, is not touched again.
        let plain = deployed("", ONE);
        let none = serde_json::Value::Null;
        let server = Recorded::with(&none, "bot-default", None);
        let (before, after, settled) = deploy(&plain, &server);
        assert_eq!(
            before,
            ["allow-ssh 198.51.100.7", "open 3000 to 198.51.100.7/32"]
        );
        assert_eq!(after, ["waf-remove"]);
        let settled = settled.expect("settled");
        assert_eq!(settled.json, serde_json::json!({ "removed": true }));
        assert_eq!(
            settled.text,
            ["The WAF is removed from the server: erpc.toml has no [waf] any more."]
        );
        // None was there: asked all the same, and nothing to say.
        let mut server = Recorded::with(&none, "bot-default", None);
        server.waf_removed = serde_json::json!({ "ok": true, "removed": false });
        let (_, after, settled) = deploy(&plain, &server);
        assert_eq!(after, ["waf-remove"]);
        let settled = settled.expect("settled");
        assert!(settled.json.is_null() && settled.text.is_empty());
        // One that could not be removed is said, and does not fail the
        // deploy.
        server.waf_removed =
            serde_json::json!({ "ok": false, "error": "could not remove it:\n\tbusy" });
        let (_, _, settled) = deploy(&plain, &server);
        let settled = settled.expect("settled");
        assert_eq!(
            settled.json,
            serde_json::json!({ "removed": false, "error": "could not remove it:??busy" })
        );
        assert_eq!(
            settled.text,
            [
                "warning: the WAF an earlier deploy left could not be removed: could not remove \
              it:??busy"
            ]
        );
    }

    #[test]
    fn status_says_where_the_waf_listens_since_when_and_what_it_counted() {
        let waf = serving();
        assert_eq!(
            super::said(&waf, SCOPE).as_deref(),
            Some(
                "WAF: listening on port 8080, forwarding to 127.0.0.1:3000, since \
                 2026-11-11T09:00:00Z; requests 120, forwarded 100, blocked 16, connections refused 3, app errors 1, \
                 addresses banned now 1"
            )
        );
        assert_eq!(
            super::blocked_by_rule(&waf).as_deref(),
            Some("blocked by rule: method 1, denied 2, probe 7, rate 5, malformed 1, banned 3")
        );
        // No WAF on the server: nothing to say of it.
        assert_eq!(super::said(&serde_json::Value::Null, SCOPE), None);
        assert_eq!(super::blocked_by_rule(&serde_json::Value::Null), None);
        assert_eq!(
            super::absent(SCOPE),
            "WAF: erpc.toml asks for one and the server has none yet; `erpc worker deploy --env \
             default` puts it in place"
        );
    }

    #[test]
    fn status_says_a_waf_that_has_counted_nothing_is_down_or_does_not_read() {
        let mut waf = serving();
        waf["stats"]["blocked"] = serde_json::json!({});
        assert_eq!(
            super::blocked_by_rule(&waf).as_deref(),
            Some("nothing blocked yet")
        );
        // Just started: no stats file yet.
        waf["stats"] = serde_json::Value::Null;
        assert_eq!(
            super::said(&waf, SCOPE).as_deref(),
            Some(
                "WAF: listening on port 8080, forwarding to 127.0.0.1:3000; it has written no \
                 counts yet"
            )
        );
        assert_eq!(super::blocked_by_rule(&waf), None);
        // Not running: said with how to see why and how to start it.
        waf["active"] = false.into();
        waf["state"] = "failed".into();
        assert_eq!(
            super::said(&waf, SCOPE).as_deref(),
            Some(
                "WAF: not running (failed); it is to listen on port 8080. `erpc worker logs \
                 --waf --env default` shows why, and `erpc worker deploy --env default` starts \
                 it again"
            )
        );
        // A config the agent could not read.
        waf["port"] = serde_json::Value::Null;
        waf["config_error"] = "the WAF config is not valid: EOF".into();
        assert_eq!(
            super::said(&waf, SCOPE).as_deref(),
            Some(
                "WAF: failed, and its config on the server does not read (the WAF config is \
                 not valid: EOF); `erpc worker deploy --env default` writes it again"
            )
        );
    }

    #[test]
    fn what_a_server_says_of_its_waf_is_printed_only_as_what_it_should_be() {
        // What a terminal would act on: a title, a bell, a screen clear.
        let escapes = "\u{1b}]0;owned\u{7}\u{1b}[2J";
        let safe = |line: &str| !line.chars().any(char::is_control);
        // `since` is a time or it is not said.
        let mut waf = serving();
        waf["stats"]["since"] = escapes.into();
        let said = super::said(&waf, SCOPE).expect("a line");
        assert!(said.contains(", since ?; requests 120,"), "{said:?}");
        assert!(safe(&said), "{said:?}");
        waf["stats"]["since"] = format!("2026-11-11T09:00:00Z{escapes}").into();
        assert!(safe(&super::said(&waf, SCOPE).expect("a line")));
        // A count that is not a number is nothing, and a rule the proxy
        // does not have is not named.
        waf["stats"]["requests"] = escapes.into();
        waf["stats"]["blocked"][escapes] = 9.into();
        waf["stats"]["blocked"]["probe"] = escapes.into();
        waf["upstream"] = format!("127.0.0.1:3000{escapes}").into();
        let said = super::said(&waf, SCOPE).expect("a line");
        assert!(
            said.starts_with("WAF: listening on port 8080, forwarding to ?, since ?; requests 0, "),
            "{said:?}"
        );
        assert!(safe(&said), "{said:?}");
        let blocked = super::blocked_by_rule(&waf).expect("a line");
        assert_eq!(
            blocked,
            "blocked by rule: method 1, denied 2, rate 5, malformed 1, banned 3"
        );
        // The state is one of systemd's words, and why a config does not
        // read is shown without what a terminal acts on.
        waf["active"] = false.into();
        waf["state"] = format!("failed{escapes}").into();
        let said = super::said(&waf, SCOPE).expect("a line");
        assert!(said.starts_with("WAF: not running (unknown); "), "{said:?}");
        assert!(safe(&said), "{said:?}");
        waf["port"] = serde_json::Value::Null;
        waf["config_error"] = format!("not valid: {escapes}\r\nerror: fake").into();
        let said = super::said(&waf, SCOPE).expect("a line");
        assert!(
            said.contains("does not read (not valid: ?]0;owned??[2J??error: fake); ")
                && !said.contains('\n'),
            "{said:?}"
        );
        assert!(safe(&said), "{said:?}");
    }

    #[test]
    fn the_end_of_a_deploy_says_who_is_let_in_and_how_to_see_what_is_blocked() {
        use erpc_worker::server::Opening;
        let m = app(
            "[waf]\nport = 8080\n[env.default]\nhost = \"203.0.113.10\"\n\
                     [env.default.firewall]\napp_allow = [\"0.0.0.0/0\", \"::/0\"]\n",
        );
        let config = m.waf_config("default").expect("a config");
        let opening = Opening::for_app(&m, &m.env["default"]).expect("an opening");
        let said = super::summary(Lang::En, &config, Some(&opening), SCOPE);
        assert_eq!(
            said,
            [
                "Its WAF listens on port 8080 and forwards to the app on 127.0.0.1:3000; the \
                 port is open to 0.0.0.0/0, ::/0, with new connections over 50 a second from one \
                 address dropped.",
                "`erpc worker firewall list --env default` shows what the WAF blocked, by rule; \
                 `erpc worker logs --waf --env default` shows each request it refused."
            ]
        );
        // Nobody listed: said, with the command that opens it.
        let said = super::summary(Lang::En, &config, None, SCOPE);
        assert_eq!(
            said[0],
            "Its WAF listens on port 8080 and forwards to the app on 127.0.0.1:3000; nobody is \
             let in yet: `erpc worker firewall allow --to app <ADDRESS> --env default` opens the \
             port to an address, and to everyone with 0.0.0.0/0."
        );
        // Without the firewall's limit nothing is said of one.
        let unlimited = Opening {
            limit: None,
            ..opening
        };
        let said = super::summary(Lang::En, &config, Some(&unlimited), SCOPE);
        assert!(
            said[0].ends_with("the port is open to 0.0.0.0/0, ::/0."),
            "{said:?}"
        );
        // A --prepare leaves it for the deploy that starts the app.
        assert_eq!(
            super::prepared(Lang::En, &m).as_deref(),
            Some("Its WAF, on port 8080, is put in place by the deploy that starts the app.")
        );
        assert_eq!(super::prepared(Lang::En, &app("")), None);
        // Under --json the summary is English whatever the run speaks.
        let japanese =
            crate::i18n::speaking(Lang::Ja, || super::summary(Lang::En, &config, None, SCOPE));
        assert_eq!(japanese, super::summary(Lang::En, &config, None, SCOPE));
    }

    #[test]
    fn the_wafs_state_is_said_in_the_language_of_the_run() {
        let waf = serving();
        let english = super::said(&waf, SCOPE).expect("a line");
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let (said, blocked, absent) = crate::i18n::speaking(lang, || {
                (
                    super::said(&waf, SCOPE).expect("a line"),
                    super::blocked_by_rule(&waf).expect("a line"),
                    super::absent(SCOPE),
                )
            });
            assert_ne!(said, english);
            for line in [&said, &blocked, &absent] {
                assert!(!line.contains('{'), "{line}");
            }
            // The counts, and the rules by the names --json has.
            assert!(said.contains("120") && said.contains("8080"), "{said}");
            assert!(blocked.contains("probe 7"), "{blocked}");
            assert!(
                absent.contains("`erpc worker deploy --env default`"),
                "{absent}"
            );
        }
    }

    #[test]
    fn check_says_it_in_the_language_of_the_run() {
        let m = app("[waf]\nport = 8080\n");
        let english = super::described(&m).expect("a WAF");
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let said = crate::i18n::speaking(lang, || super::described(&m).expect("a WAF"));
            for (line, english) in said.iter().zip(&english) {
                assert_ne!(line, english);
                assert!(!line.contains('{'), "{line}");
                // The numbers and the methods are the same in every language.
                assert!(line.contains("8080") || line.contains("50"), "{line}");
            }
        }
    }
}
