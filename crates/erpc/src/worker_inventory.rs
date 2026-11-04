// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The 1Password item an inventory environment keeps its server facts in
//! (decision 9; the fields are [`erpc_worker::inventory`]'s), read and
//! written through `op`.
//!
//! A command reads the item once and keeps it in memory, with the version
//! it had. A write rereads it first and refuses if the version moved since:
//! another machine deployed meanwhile. 1Password has no compare-and-swap, so
//! this narrows the race rather than closing it; the worker's lock on the
//! server covers the rest. Everything goes to `op` on standard input, never
//! as an argument a process listing would show.

use std::collections::BTreeMap;
use std::sync::Mutex;

use erpc_auth::store::one_password::OpRunner as _;
use erpc_worker::inventory::{self, Deployed};
use erpc_worker::manifest::Env;
use serde::Deserialize;
use serde_json::{Value, json};

/// The items read by this command, by tag: their id, their version, and
/// the deploy they record, which a write that is not a deploy keeps.
type Seen = BTreeMap<String, (String, u64, Option<Deployed>)>;
static SEEN: Mutex<Seen> = Mutex::new(BTreeMap::new());

/// One item of `op item get --format json`.
#[derive(Deserialize)]
struct OpItem {
    id: String,
    #[serde(default)]
    version: u64,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    fields: Vec<OpField>,
}

#[derive(Deserialize)]
struct OpField {
    #[serde(default)]
    label: String,
    #[serde(default)]
    value: Option<String>,
}

impl OpItem {
    fn plain(&self) -> BTreeMap<String, String> {
        self.fields
            .iter()
            .filter_map(|f| Some((f.label.clone(), f.value.clone()?)))
            .collect()
    }
}

fn op(args: &[&str], stdin: Option<&str>, doing: &str) -> Result<String, String> {
    let runner = crate::node_common::op_runner()?;
    let out = runner.run(args, stdin).map_err(|e| e.to_string())?;
    if out.success {
        Ok(out.stdout)
    } else {
        let why = out
            .stderr
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map_or_else(|| t!("worker_inventory.no_reason"), str::to_owned)
            .chars()
            .filter(|c| !c.is_control())
            .take(300)
            .collect::<String>();
        Err(t!("worker_inventory.op_failed", doing, why))
    }
}

/// The items in `vault` tagged `tag`, read whole.
fn items(vault: &str, tag: &str) -> Result<Vec<OpItem>, String> {
    let list = op(
        &[
            "item", "list", "--vault", vault, "--tags", tag, "--format", "json",
        ],
        None,
        &t!("worker_inventory.doing.list"),
    )?;
    let listed: Vec<Value> =
        serde_json::from_str(&list).map_err(|_| t!("worker_inventory.listing_not_json"))?;
    if listed.is_empty() {
        return Ok(Vec::new());
    }
    let got = op(
        &["item", "get", "-", "--format", "json"],
        Some(&list),
        &t!("worker_inventory.doing.read_all"),
    )?;
    let items: Result<Vec<OpItem>, _> = serde_json::Deserializer::from_str(&got)
        .into_iter::<OpItem>()
        .collect();
    items.map_err(|_| t!("worker_inventory.items_not_json"))
}

fn get(vault: &str, id: &str) -> Result<OpItem, String> {
    let text = op(
        &["item", "get", id, "--vault", vault, "--format", "json"],
        None,
        &t!("worker_inventory.doing.read"),
    )?;
    serde_json::from_str(&text).map_err(|_| t!("worker_inventory.item_not_json"))
}

/// Environment `env` of app `app` as its item in `vault` has it, or `None`
/// when there is no item yet (a first deploy makes it).
pub(crate) fn read(vault: &str, app: &str, env: &str) -> Result<Option<Env>, String> {
    let tag = inventory::tag(app, env);
    let mut found: Vec<OpItem> = items(vault, &tag)?
        .into_iter()
        // A listing by tag can also match a tag's prefix.
        .filter(|i| i.tags.contains(&tag))
        .collect();
    let Some(item) = found.pop() else {
        return Ok(None);
    };
    if !found.is_empty() {
        return Err(t!("worker_inventory.more_than_one", vault, tag));
    }
    let plain = item.plain();
    let facts = inventory::facts(&plain)
        .map_err(|e| t!("worker_inventory.item_error", id = item.id, error = e))?;
    SEEN.lock()
        .map_err(|_| t!("worker_inventory.record_unusable"))?
        .insert(tag, (item.id, item.version, inventory::deployed(&plain)));
    Ok(Some(facts))
}

/// The item document `op` is given on stdin.
fn template(app: &str, env: &str, fields: &[(&'static str, String)]) -> String {
    let list: Vec<Value> = fields
        .iter()
        .map(|(label, value)| json!({ "id": label, "label": label, "type": "STRING", "value": value }))
        .collect();
    json!({
        "title": inventory::title(app, env),
        "category": "SECURE_NOTE",
        "tags": [inventory::TAG, inventory::tag(app, env)],
        "fields": list,
    })
    .to_string()
}

/// Every field reads back as written.
fn verify(item: &OpItem, fields: &[(&'static str, String)]) -> Result<(), String> {
    let back = item.plain();
    for (label, value) in fields {
        if back.get(*label).map(String::as_str).unwrap_or_default() != value {
            return Err(t!("worker_inventory.not_read_back", id = item.id, label));
        }
    }
    Ok(())
}

/// Writes `facts` as environment `env_name`'s item in `vault`: a new item,
/// or the one this command read, refused when it changed since.
pub(crate) fn write(
    vault: &str,
    app: &str,
    env_name: &str,
    facts: &Env,
    deployed: Option<&Deployed>,
) -> Result<(), String> {
    let tag = inventory::tag(app, env_name);
    let seen = SEEN
        .lock()
        .map_err(|_| t!("worker_inventory.record_unusable"))?
        .get(&tag)
        .cloned();
    // A write that is not a deploy keeps the deploy the item records.
    let deployed = deployed
        .cloned()
        .or_else(|| seen.as_ref().and_then(|(_, _, d)| d.clone()));
    let fields = inventory::fields(facts, deployed.as_ref())?;
    let document = template(app, env_name, &fields);
    let id = if let Some((id, version, _)) = seen {
        if get(vault, &id)?.version != version {
            return Err(t!(
                "worker_inventory.changed",
                title = inventory::title(app, env_name)
            ));
        }
        op(
            &["item", "edit", &id, "--vault", vault],
            Some(&document),
            &t!("worker_inventory.doing.update"),
        )?;
        id
    } else {
        if read(vault, app, env_name)?.is_some() {
            return Err(t!(
                "worker_inventory.appeared",
                title = inventory::title(app, env_name)
            ));
        }
        let created = op(
            &["item", "create", "-", "--vault", vault, "--format", "json"],
            Some(&document),
            &t!("worker_inventory.doing.create"),
        )?;
        let created: OpItem =
            serde_json::from_str(&created).map_err(|_| t!("worker_inventory.new_item_not_json"))?;
        created.id
    };
    let back = get(vault, &id)?;
    verify(&back, &fields)?;
    SEEN.lock()
        .map_err(|_| t!("worker_inventory.record_unusable"))?
        .insert(tag, (id, back.version, deployed));
    Ok(())
}

/// Archives environment `env_name`'s item, which 1Password keeps
/// recoverable. Whether there was one.
pub(crate) fn archive(vault: &str, app: &str, env_name: &str) -> Result<bool, String> {
    let tag = inventory::tag(app, env_name);
    let mut archived = false;
    for item in items(vault, &tag)?
        .into_iter()
        .filter(|i| i.tags.contains(&tag))
    {
        op(
            &["item", "delete", &item.id, "--vault", vault, "--archive"],
            None,
            &t!("worker_inventory.doing.archive"),
        )?;
        archived = true;
    }
    Ok(archived)
}

/// The worker items in `vault`, as (app, environment). From the listing
/// alone: it names each item's tags and no field, so the other erpc items
/// in the vault, some with concealed fields, are not read.
pub(crate) fn list(vault: &str) -> Result<Vec<(String, String)>, String> {
    let list = op(
        &[
            "item",
            "list",
            "--vault",
            vault,
            "--tags",
            inventory::TAG,
            "--format",
            "json",
        ],
        None,
        &t!("worker_inventory.doing.list"),
    )?;
    let listed: Vec<Value> =
        serde_json::from_str(&list).map_err(|_| t!("worker_inventory.listing_not_json"))?;
    let mut out: Vec<(String, String)> = listed
        .iter()
        .filter_map(|item| {
            item["tags"].as_array()?.iter().find_map(|t| {
                let (app, env) = inventory::from_tag(t.as_str()?)?;
                Some((app.to_owned(), env.to_owned()))
            })
        })
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// What a deploy leaves on record: `release`, now, and this machine.
pub(crate) fn deployed(release: &str) -> Deployed {
    let from = std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    Deployed {
        release: release.to_owned(),
        at: erpc_ops::run::utc_now(),
        from,
    }
}

#[cfg(test)]
mod tests {
    use erpc_core::i18n::Lang;

    #[test]
    fn a_moved_item_is_told_in_the_operators_language() {
        let said = || t!("worker_inventory.changed", title = "erpc worker bot prod");
        let english = said();
        assert!(
            english.starts_with("erpc worker bot prod changed"),
            "{english}"
        );
        for lang in [Lang::Ja, Lang::Ru] {
            let text = crate::i18n::speaking(lang, said);
            assert_ne!(text, english);
            assert!(!text.contains('{'), "{text}");
        }
    }
}
