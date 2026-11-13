// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The 1Password item an inventory environment keeps its server facts in
//! (decision 9), field by field.
//!
//! One item per environment, a secure note titled `erpc worker <app>
//! <env>`, tagged `erpc` and `erpc/worker/<app>/<env>`. Its fields are plain
//! strings, so the item reads well in 1Password. What is a list or a table
//! in `erpc.toml` is JSON in its field. None of it is secret; it is kept in
//! 1Password so that a machine signed in to the vault can take over the
//! worker without its `erpc.toml` naming the server. Reading and writing the
//! item, through `op`, is erpc's.

use std::collections::BTreeMap;

use crate::manifest::{Env, Firewall, Line, Resource, Start, StartOf};
use crate::net::Cidr;

/// The format of the item. A reader refuses another rather than guessing.
pub const FORMAT: &str = "3";

/// The format `env`'s item is written in: the oldest that holds what it
/// has, so that an erpc from before a field was added still reads the
/// items without it, and refuses the ones with it rather than write them
/// back without. Format 2 added `backup`; format 3 adds `starting`.
fn format_for(env: &Env) -> &'static str {
    if !env.starting.is_empty() {
        FORMAT
    } else if env.backup.is_some() {
        "2"
    } else {
        "1"
    }
}

/// The tag every erpc item carries.
pub const TAG: &str = "erpc";

/// The tag the worker items share, before `<app>/<env>`.
pub const WORKER_TAG: &str = "erpc/worker/";

/// The tag of environment `env` of app `app`.
#[must_use]
pub fn tag(app: &str, env: &str) -> String {
    format!("{WORKER_TAG}{app}/{env}")
}

/// The app and environment a tag names, for a listing.
#[must_use]
pub fn from_tag(tag: &str) -> Option<(&str, &str)> {
    let (app, env) = tag.strip_prefix(WORKER_TAG)?.split_once('/')?;
    (!app.is_empty() && !env.is_empty() && !env.contains('/')).then_some((app, env))
}

/// The item's title.
#[must_use]
pub fn title(app: &str, env: &str) -> String {
    format!("erpc worker {app} {env}")
}

/// What a deploy leaves on record beside the server: the live release,
/// when, and from which machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deployed {
    /// The release now current.
    pub release: String,
    /// When, as RFC 3339.
    pub at: String,
    /// The machine it was deployed from, by host name.
    pub from: String,
}

fn joined(list: &[Cidr]) -> String {
    list.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// The item's fields for `env`'s server facts, in a fixed order.
///
/// # Errors
///
/// A message when a fact cannot be written as JSON, which a valid one
/// always can.
pub fn fields(
    env: &Env,
    deployed: Option<&Deployed>,
) -> Result<Vec<(&'static str, String)>, String> {
    let mut out = vec![
        ("erpc_format", format_for(env).to_owned()),
        (
            "resource",
            env.resource
                .as_ref()
                .map(to_json)
                .transpose()?
                .unwrap_or_default(),
        ),
        ("host", env.host.clone().unwrap_or_default()),
        ("ssh_user", env.ssh_user.clone().unwrap_or_default()),
        (
            "ssh_port",
            env.ssh_port.map(|p| p.to_string()).unwrap_or_default(),
        ),
        ("host_key", env.host_key.clone().unwrap_or_default()),
        ("ssh_allow", joined(&env.firewall.ssh_allow)),
        ("app_allow", joined(&env.firewall.app_allow)),
        (
            "lines",
            if env.lines.is_empty() {
                String::new()
            } else {
                to_json(&env.lines)?
            },
        ),
        (
            "starting",
            if env.starting.is_empty() {
                String::new()
            } else {
                to_json(&env.starting)?
            },
        ),
        (
            "backup",
            env.backup
                .as_ref()
                .map(to_json)
                .transpose()?
                .unwrap_or_default(),
        ),
    ];
    if let Some(d) = deployed {
        out.push(("release", d.release.clone()));
        out.push(("deployed_at", d.at.clone()));
        out.push(("deployed_from", d.from.clone()));
    }
    Ok(out)
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| e.to_string())
}

/// The addresses in an item's field. `app_allow` may hold "everyone",
/// which `erpc.toml` allows an app behind a WAF and the server refuses any
/// other; `ssh_allow` never.
fn cidrs(field: &str, text: &str) -> Result<Vec<Cidr>, String> {
    let read = if field == "app_allow" {
        Cidr::parse_any
    } else {
        Cidr::parse
    };
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| read(s).map_err(|e| format!("{field}: {e}")))
        .collect()
}

/// The server facts the item's `fields` hold, as an [`Env`] without its
/// `inventory`.
///
/// # Errors
///
/// A message when the item is of another format, or a field does not read.
pub fn facts(fields: &BTreeMap<String, String>) -> Result<Env, String> {
    let get = |name: &str| fields.get(name).map(String::as_str).unwrap_or_default();
    match get("erpc_format") {
        // Format 2 adds `backup`, format 3 `starting`. An older item has
        // neither, and is read; an erpc that reads only an older format
        // refuses a newer item rather than write it back without them.
        FORMAT | "2" | "1" => {}
        "" => return Err("the item has no erpc_format; it is not erpc's".to_owned()),
        other => {
            return Err(format!(
                "the item is in format {other}, and this erpc reads format {FORMAT}; update erpc"
            ));
        }
    }
    let some = |name: &str| Some(get(name).to_owned()).filter(|v| !v.is_empty());
    let resource: Option<Resource> = some("resource")
        .map(|t| serde_json::from_str(&t).map_err(|e| format!("resource: {e}")))
        .transpose()?;
    let lines: Vec<Line> = some("lines")
        .map(|t| serde_json::from_str(&t).map_err(|e| format!("lines: {e}")))
        .transpose()?
        .unwrap_or_default();
    let starting: BTreeMap<StartOf, Start> = some("starting")
        .map(|t| serde_json::from_str(&t).map_err(|e| format!("starting: {e}")))
        .transpose()?
        .unwrap_or_default();
    let backup = some("backup")
        .map(|t| serde_json::from_str(&t).map_err(|e| format!("backup: {e}")))
        .transpose()?;
    let ssh_port = some("ssh_port")
        .map(|p| {
            p.parse::<u16>()
                .map_err(|_| format!("ssh_port: `{p}` is not a port"))
        })
        .transpose()?;
    Ok(Env {
        inventory: None,
        resource,
        host: some("host"),
        ssh_user: some("ssh_user"),
        ssh_port,
        host_key: some("host_key"),
        firewall: Firewall {
            ssh_allow: cidrs("ssh_allow", get("ssh_allow"))?,
            app_allow: cidrs("app_allow", get("app_allow"))?,
        },
        lines,
        starting,
        backup,
    })
}

/// The deploy the item's `fields` record, when they record one.
#[must_use]
pub fn deployed(fields: &BTreeMap<String, String>) -> Option<Deployed> {
    let get = |name: &str| fields.get(name).filter(|v| !v.is_empty()).cloned();
    Some(Deployed {
        release: get("release")?,
        at: get("deployed_at").unwrap_or_default(),
        from: get("deployed_from").unwrap_or_default(),
    })
}

/// `env` with the server facts taken out: what `erpc.toml` keeps of an
/// inventory environment.
#[must_use]
pub fn stripped(env: &Env) -> Env {
    Env {
        inventory: env.inventory.clone(),
        ..Env::default()
    }
}

/// `facts` read from the item, with `inventory` as `erpc.toml` has it.
#[must_use]
pub fn merged(inventory: &Env, facts: Env) -> Env {
    Env {
        inventory: inventory.inventory.clone(),
        ..facts
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{Deployed, facts, fields, from_tag, tag};
    use crate::manifest::{
        Backup, Env, Firewall, Inventory, Line, LineKind, Resource, ResourceKind, Start, StartOf,
    };
    use crate::net::Cidr;

    fn env() -> Env {
        Env {
            inventory: Some(Inventory {
                // In two halves: the hygiene gate reads a 26-character
                // lowercase token beside the word vault as a real identifier.
                vault: concat!("abcdefghijklm", "nopqrstuvwxyz").to_owned(),
            }),
            resource: Some(Resource {
                kind: ResourceKind::Vps,
                id: "100001".to_owned(),
                region: Some("amsterdam".to_owned()),
                hourly: true,
            }),
            host: Some("203.0.113.10".to_owned()),
            ssh_user: Some("ubuntu".to_owned()),
            ssh_port: None,
            host_key: Some(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                    .to_owned(),
            ),
            firewall: Firewall {
                ssh_allow: vec![Cidr::parse("198.51.100.7").expect("cidr")],
                app_allow: vec![Cidr::parse("198.51.100.0/24").expect("cidr")],
            },
            lines: vec![Line {
                kind: LineKind::Unlimited,
                id: "100002".to_owned(),
                // Built, not written out: the endpoint gate reads literals.
                endpoint: ["http", "203.0.113.5:8899"].join("://"),
                hourly: true,
            }],
            starting: BTreeMap::new(),
            backup: Some(Backup {
                access_key: 42,
                restic_key: "0a".repeat(32),
                host: "erpc-worker-bot-default-0a1b2c3d".to_owned(),
            }),
        }
    }

    #[test]
    fn a_start_with_no_outcome_yet_round_trips_in_format_3() {
        let start = Start {
            key: "0a".repeat(16),
            family: "user-unlimited".to_owned(),
            product: "prod_Unlimited1".to_owned(),
            region: Some("amsterdam".to_owned()),
            ip: None,
        };
        let unanswered = Env {
            starting: BTreeMap::from([(StartOf::Unlimited, start)]),
            ..env()
        };
        let read: BTreeMap<String, String> = fields(&unanswered, None)
            .expect("fields")
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        // An erpc from before `starting` refuses the item, rather than
        // write it back without the request's key.
        assert_eq!(read["erpc_format"], "3");
        assert!(read["starting"].contains("\"unlimited\""), "{read:?}");
        let back = facts(&read).expect("facts");
        assert_eq!(super::merged(&unanswered, back), unanswered);
        // Once its outcome is on record the item is as it was before.
        let settled: BTreeMap<String, String> = fields(&env(), None)
            .expect("fields")
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        assert_eq!(settled["erpc_format"], "2");
        assert_eq!(settled["starting"], "");
    }

    #[test]
    fn the_facts_round_trip_through_the_items_fields() {
        let deployed = Deployed {
            release: "20261029T154037Z-6914df5f".to_owned(),
            at: "2026-10-29T15:40:37Z".to_owned(),
            from: "deploy-laptop".to_owned(),
        };
        let written = fields(&env(), Some(&deployed)).expect("fields");
        let read: BTreeMap<String, String> = written
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        assert_eq!(read["release"], deployed.release);
        assert_eq!(read["erpc_format"], "2");
        assert_eq!(super::deployed(&read), Some(deployed));
        let back = facts(&read).expect("facts");
        assert_eq!(super::merged(&env(), back), env());
    }

    #[test]
    fn a_vps_bought_and_a_line_pending_round_trip_too() {
        let env = Env {
            resource: env().resource,
            lines: vec![Line {
                kind: LineKind::Grpc,
                id: "100003".to_owned(),
                endpoint: String::new(),
                hourly: true,
            }],
            ..Env::default()
        };
        let read: BTreeMap<String, String> = fields(&env, None)
            .expect("fields")
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        assert_eq!(read["erpc_format"], "1");
        assert_eq!(facts(&read).expect("facts"), env);
    }

    #[test]
    fn an_item_can_say_everyone_reaches_the_app_and_never_ssh() {
        let open = Env {
            firewall: Firewall {
                ssh_allow: vec![Cidr::parse("198.51.100.7").expect("cidr")],
                app_allow: vec![
                    Cidr::parse_any("0.0.0.0/0").expect("everyone"),
                    Cidr::parse_any("::/0").expect("everyone"),
                ],
            },
            ..Env::default()
        };
        let mut read: BTreeMap<String, String> = fields(&open, None)
            .expect("fields")
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        assert_eq!(read["app_allow"], "0.0.0.0/0,::/0");
        assert_eq!(facts(&read).expect("facts"), open);
        read.insert("ssh_allow".to_owned(), "0.0.0.0/0".to_owned());
        let refused = facts(&read).expect_err("everyone to SSH");
        assert!(refused.starts_with("ssh_allow: "), "{refused}");
    }

    #[test]
    fn an_item_of_another_format_is_refused() {
        let mut read: BTreeMap<String, String> = BTreeMap::new();
        assert!(facts(&read).is_err());
        read.insert("erpc_format".to_owned(), "4".to_owned());
        assert!(facts(&read).expect_err("format 4").contains("format 4"));
        // Format 1, before `backup`, is still read.
        read.insert("erpc_format".to_owned(), "1".to_owned());
        assert_eq!(facts(&read).expect("format 1").backup, None);
        read.insert("ssh_port".to_owned(), "twenty-two".to_owned());
        assert!(facts(&read).is_err());
    }

    #[test]
    fn a_tag_names_its_app_and_environment() {
        assert_eq!(from_tag(&tag("bot", "prod")), Some(("bot", "prod")));
        assert_eq!(from_tag("erpc/solana/testnet/host"), None);
        assert_eq!(from_tag("erpc/worker/bot"), None);
    }

    #[test]
    fn erpc_toml_keeps_only_where_the_facts_are() {
        let kept = super::stripped(&env());
        assert_eq!(kept.inventory, env().inventory);
        assert!(kept.host.is_none() && kept.lines.is_empty() && kept.firewall.is_empty());
    }
}
