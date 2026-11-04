// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The node commands that are implemented, as they are implemented.
//!
//! `erpc v list`: the validators in the inventory, with the primary and
//! spare hosts of each, read from 1Password.

use std::fmt::Write as _;

use erpc_chain::inventory::{Inventory, Role};

use crate::commands::Outcome;

/// The inventory of one network, read with the `op` this machine has.
fn inventory(network: &str, vault: &str) -> Result<Inventory, String> {
    let runner = crate::node_common::op_runner()?;
    crate::node_common::store(&runner, vault, "solana", network)?
        .load()
        .map_err(|e| e.to_string())
}

/// Runs `erpc v list`, for one network or every network with a vault.
pub fn list_validators(network: Option<&str>, json: bool) -> Outcome {
    let keyless = match crate::keyless::path().and_then(|p| crate::keyless::load(&p)) {
        Ok(keyless) => keyless,
        Err(e) => return Outcome::Failed(e),
    };
    let networks: Vec<(String, String)> = keyless
        .networks
        .iter()
        .filter(|(name, _)| network.is_none_or(|n| n == name.as_str()))
        .map(|(name, vault)| (name.clone(), vault.vault_id.clone()))
        .collect();
    if networks.is_empty() {
        let hint = "no validators yet: create one with `erpc v init -n testnet`";
        if json {
            crate::print_json(&serde_json::json!({ "validators": [] }));
            return Outcome::Done(String::new());
        }
        return Outcome::Done(hint.to_owned());
    }
    let mut all = Vec::new();
    for (name, vault) in &networks {
        match inventory(name, vault) {
            Ok(inventory) => all.push((name.clone(), inventory)),
            Err(e) => return Outcome::Failed(format!("{name}: {e}")),
        }
    }
    if json {
        let validators: Vec<serde_json::Value> = all
            .iter()
            .flat_map(|(network, inventory)| {
                inventory.validators.iter().map(move |v| {
                    serde_json::json!({
                        "network": network,
                        "name": v.name,
                        "identity": v.identity_account,
                        "client": v.client,
                        "version": v.version,
                        "region": v.region,
                        "hosts": inventory.hosts_of(&v.name).iter().map(|h| serde_json::json!({
                            "name": h.name,
                            "role": h.role.map(Role::as_str),
                            "address": h.address,
                            "last_result": h.last_result,
                        })).collect::<Vec<_>>(),
                    })
                })
            })
            .collect();
        crate::print_json(&serde_json::json!({ "validators": validators }));
        return Outcome::Done(String::new());
    }
    Outcome::Done(render(&all))
}

fn render(all: &[(String, Inventory)]) -> String {
    let mut out = String::new();
    for (network, inventory) in all {
        if inventory.validators.is_empty() {
            let _ = writeln!(out, "{network}: no validators");
            continue;
        }
        for v in &inventory.validators {
            let _ = writeln!(
                out,
                "{network}  {}  {} {}  region {}",
                v.name,
                v.client,
                v.version,
                if v.region.is_empty() { "-" } else { &v.region }
            );
            for h in inventory.hosts_of(&v.name) {
                let _ = writeln!(
                    out,
                    "  {:<8} {:<20} {:<16} {}",
                    h.role.map_or("?", Role::as_str),
                    h.name,
                    h.address,
                    if h.last_result.is_empty() {
                        "not deployed"
                    } else {
                        &h.last_result
                    }
                );
            }
        }
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::{Host, Inventory, Role, Validator};

    use super::render;

    #[test]
    fn a_validator_is_shown_with_its_primary_then_its_spare() {
        let inventory = Inventory {
            validators: vec![Validator {
                name: "tv1".to_owned(),
                client: "agave".to_owned(),
                version: "v4.4.0-beta.1".to_owned(),
                region: "ny".to_owned(),
                ..Validator::default()
            }],
            hosts: vec![
                Host {
                    name: "tv1-b".to_owned(),
                    validator: "tv1".to_owned(),
                    role: Some(Role::Spare),
                    address: "203.0.113.6".to_owned(),
                    ..Host::default()
                },
                Host {
                    name: "tv1-a".to_owned(),
                    validator: "tv1".to_owned(),
                    role: Some(Role::Primary),
                    address: "203.0.113.5".to_owned(),
                    last_result: "ok".to_owned(),
                    ..Host::default()
                },
            ],
        };
        let shown = render(&[("testnet".to_owned(), inventory)]);
        let lines: Vec<&str> = shown.lines().collect();
        assert!(
            lines[0].starts_with("testnet  tv1  agave v4.4.0-beta.1  region ny"),
            "{shown}"
        );
        assert!(
            lines[1].contains("primary")
                && lines[1].contains("203.0.113.5")
                && lines[1].ends_with("ok"),
            "{shown}"
        );
        assert!(
            lines[2].contains("spare") && lines[2].contains("not deployed"),
            "{shown}"
        );
    }
}
