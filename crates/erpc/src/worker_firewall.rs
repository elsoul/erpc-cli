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
//!   each worker's `run.port` from its `firewall.app_allow`.

use std::net::IpAddr;

use erpc_ssh::worker::{UnitId, Verb};
use erpc_ssh::{RemoteCommand, Session, Target};
use erpc_worker::manifest::{Env, Manifest};
use erpc_worker::net::Cidr;
use erpc_worker::server::{FirewallRequest, Opening};
use serde_json::{Value, json};

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::node_common::{Say, go_ahead};
use crate::worker::{App, Port, load_env};
use crate::worker_remote::{ctl, ctl_ok, failed, open, target};

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

/// The SSH addresses to allow: `ssh_allow` and `me`.
fn ssh_addresses(env: &Env, me: Option<IpAddr>, say: &Say) -> Result<Vec<IpAddr>, CliError> {
    let mut out: Vec<IpAddr> = Vec::new();
    for cidr in &env.firewall.ssh_allow {
        let single = if cidr.address().is_ipv4() { 32 } else { 128 };
        if cidr.prefix() != single {
            return Err(failed(t!("worker_firewall.ssh_network", cidr)));
        }
        out.push(cidr.address());
    }
    if let Some(me) = me
        && !out.contains(&me)
    {
        if !env.firewall.ssh_allow.is_empty() {
            say.line(&t!("worker_firewall.me_added", me));
        }
        out.push(me);
    }
    if out.is_empty() {
        return Err(
            failed(t!("worker_firewall.no_address")).hint(t!("worker_firewall.no_address_hint"))
        );
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

/// What a sync applied.
pub(crate) struct Synced {
    pub(crate) ssh_allow: Vec<IpAddr>,
    pub(crate) opening: Option<Opening>,
}

/// Makes the server's firewall what `env` says for `m`'s worker.
pub(crate) fn sync(
    m: &Manifest,
    env: &Env,
    target: &Target,
    id: &UnitId,
    me: Option<IpAddr>,
    say: &Say,
) -> Result<Synced, CliError> {
    let ssh_allow = ssh_addresses(env, me, say)?;
    say.line(&t!(
        "worker_firewall.allowing_ssh",
        addresses = ssh_allow
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    allow_ssh(target, ssh_allow.clone())?;
    let opening = match (m.run.port, env.firewall.app_allow.is_empty()) {
        (Some(port), false) => Some(Opening {
            port,
            allow: env.firewall.app_allow.clone(),
        }),
        _ => None,
    };
    say.line(&match &opening {
        Some(o) => t!(
            "worker_firewall.dropping_open",
            port = o.port,
            addresses = o
                .allow
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        None => t!("worker_firewall.dropping_closed"),
    });
    apply_worker(target, id, opening.clone())?;
    Ok(Synced { ssh_allow, opening })
}

fn reach(app: &App) -> Result<(std::path::PathBuf, Manifest, Env, Target, UnitId), CliError> {
    let (path, m) = load_env(app)?;
    let env = crate::worker::env_of(&m, app)?.clone();
    let target = target(app, &env)?;
    let id = UnitId::new(&m.unit_id(&app.env)).map_err(failed)?;
    Ok((path, m, env, target, id))
}

fn describe(env: &Env, run_port: Option<u16>) -> Vec<String> {
    let list = |l: &[Cidr]| {
        if l.is_empty() {
            t!("worker_firewall.describe.nobody")
        } else {
            l.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    vec![
        format!(
            "  {}",
            t!(
                "worker_firewall.describe.ssh",
                list = list(&env.firewall.ssh_allow)
            )
        ),
        match run_port {
            Some(port) => format!("  app {port:<5} {}", list(&env.firewall.app_allow)),
            None => format!("  {}", t!("worker_firewall.describe.app_closed")),
        },
        format!("  {}", t!("worker_firewall.describe.all_else")),
    ]
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
                "server": server,
            }));
            return Ok(Outcome::Done(String::new()));
        }
        let mut lines = vec![t!(
            "worker_firewall.list.title",
            worker = id.as_str(),
            host = target.host
        )];
        lines.extend(describe(&env, m.run.port));
        lines.push(String::new());
        lines.push(t!("worker_firewall.list.on_server"));
        if let Some(table) = server["table"].as_str() {
            lines.extend(table.lines().map(|l| format!("  {l}")));
        } else {
            let scope = app.scope();
            lines.push(format!(
                "  {}",
                t!(
                    "worker_firewall.list.none_yet",
                    command = format!("erpc worker firewall sync{scope}")
                )
            ));
        }
        if server["pending"] == json!(true) {
            lines.push(format!("warning: {}", t!("worker_firewall.list.pending")));
        }
        Ok(Outcome::Done(crate::ui::decorate(&lines.join("\n"), "🛡️")))
    };
    run().unwrap_or_else(Into::into)
}

/// `erpc worker firewall allow|deny`: changes erpc.toml's list, then the server.
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
        let (path, _, mut env, target, id) = reach(app)?;
        let parsed = addresses
            .iter()
            .map(|a| Cidr::parse(a).map_err(|e| CliError::new(Code::Usage, e)))
            .collect::<Result<Vec<_>, _>>()?;
        // Refused here, before the plan is shown: the SSH allow list
        // (`ssh_addresses`) takes single addresses only.
        if to == Port::Ssh
            && let Some(network) = parsed
                .iter()
                .find(|c| c.prefix() != if c.address().is_ipv4() { 32 } else { 128 })
        {
            return Err(CliError::new(
                Code::Usage,
                t!("worker_firewall.ssh_network_given", network),
            )
            .hint(t!("worker_firewall.ssh_network_hint")));
        }
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
        if *list == before {
            let scope = app.scope();
            return Ok(Outcome::Done(crate::ui::decorate(
                &if allow {
                    t!(
                        "worker_firewall.unchanged.allowed",
                        addresses = addresses.join(", "),
                        command = format!("erpc worker firewall sync{scope}")
                    )
                } else {
                    t!(
                        "worker_firewall.unchanged.denied",
                        addresses = addresses.join(", "),
                        command = format!("erpc worker firewall sync{scope}")
                    )
                },
                "👌",
            )));
        }
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
        for line in describe(&env, m.run.port) {
            say.line(&line);
        }
        go_ahead(yes, &t!("worker_firewall.nothing_changed"))?;
        let session = open(&target)?;
        let me = controller(&session);
        let synced = sync(&m, &env, &target, &id, me, &say)?;
        crate::worker::EnvRecord {
            path: &path,
            app: &m.name,
            env: &app.env,
        }
        .save(&env, None)
        .map_err(failed)?;
        Ok(report(json, &id, &synced))
    };
    run().unwrap_or_else(Into::into)
}

/// `erpc worker firewall sync`: makes the server's firewall what erpc.toml says.
pub(crate) fn sync_verb(json: bool, app: &App, yes: bool) -> Outcome {
    let say = Say { quiet: json };
    let run = || -> Result<Outcome, CliError> {
        let (_, m, env, target, id) = reach(app)?;
        say.line(&t!("worker_firewall.will_be"));
        for line in describe(&env, m.run.port) {
            say.line(&line);
        }
        go_ahead(yes, &t!("worker_firewall.nothing_changed"))?;
        let me = controller(&open(&target)?);
        let synced = sync(&m, &env, &target, &id, me, &say)?;
        Ok(report(json, &id, &synced))
    };
    run().unwrap_or_else(Into::into)
}

fn report(json: bool, id: &UnitId, synced: &Synced) -> Outcome {
    let body: Value = json!({
        "worker": id.as_str(),
        "ssh_allow": synced.ssh_allow,
        "opening": synced.opening,
    });
    if json {
        crate::print_json(&body);
        return Outcome::Done(String::new());
    }
    Outcome::Done(crate::ui::decorate(
        &t!(
            "worker_firewall.in_force",
            worker = id.as_str(),
            ssh = synced
                .ssh_allow
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            app = synced.opening.as_ref().map_or_else(
                || t!("worker_firewall.app_closed"),
                |o| t!(
                    "worker_firewall.app_open",
                    port = o.port,
                    addresses = o
                        .allow
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            )
        ),
        "🛡️",
    ))
}

#[cfg(test)]
mod tests {
    use erpc_core::i18n::Lang;
    use erpc_worker::manifest::Env;

    #[test]
    fn the_plan_is_told_in_the_operators_language() {
        let said = || super::describe(&Env::default(), None).join("\n");
        let english = said();
        assert!(english.contains("all else  dropped"), "{english}");
        for lang in [Lang::Ja, Lang::Ru] {
            let text = crate::i18n::speaking(lang, said);
            assert_ne!(text, english);
            assert!(!text.contains('{'), "{text}");
        }
    }
}
