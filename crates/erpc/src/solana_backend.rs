// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Select the recorded Solana backend without reading concealed inventory fields.
use crate::{
    commands::Outcome,
    error::{CliError, Code},
    node_common,
    solana_native::one,
};
use clap::ArgMatches;
use erpc_chain::inventory::solana_listing::Backend;
use serde_json::{Value, json};
use std::fmt::Write as _;

fn choose(recorded: Backend, explicit: Option<&str>, init: bool) -> Result<bool, String> {
    match (recorded, explicit) {
        (Backend::Migration, _) => Err("this host has a pending original Solv migration; use migration status or resume".into()),
        (Backend::Native, Some("solv")) => Err("this node has native ownership; solv cannot operate it".into()),
        (Backend::New, Some("solv")) => Err("new Solana nodes use isolated native accounts; --backend solv only resumes an existing node".into()),
        (Backend::Solv, Some("native")) if !init => Err("the existing solv node requires explicit verified migration before native operations".into()),
        (_, Some("native")) | (Backend::Native | Backend::New, None) => Ok(true),
        (Backend::Solv, None | Some("solv")) => Ok(false),
        _ => Err("invalid Solana backend selector".into()),
    }
}

pub(crate) fn native_selected(
    args: &ArgMatches,
    network: Option<&str>,
    rpc: bool,
    init: bool,
) -> Result<bool, CliError> {
    let network = network
        .ok_or_else(|| CliError::new(Code::Usage, "Solana node operations require --network"))?;
    if !["mainnet", "testnet"].contains(&network) {
        return Err("unsupported Solana network".into());
    }
    let name = one(args, "name")
        .ok_or_else(|| CliError::new(Code::Usage, "Solana node operations require --name"))?;
    let vault = vault(network, one(args, "vault"), &pass_vault(rpc))?;
    let store = node_common::store(&node_common::op_runner()?, &vault, "solana", network)?;
    let recorded = store.solana_backend(name, rpc).map_err(|e| e.to_string())?;
    let native = choose(recorded, one(args, "backend"), init)?;
    if !native && !init && one(args, "vault").is_some() {
        let keyless = crate::keyless::load(&crate::keyless::path()?)?;
        if keyless
            .networks
            .get(network)
            .is_none_or(|saved| saved.vault_id != vault)
        {
            return Err("legacy operations require the original saved network vault; the supplied vault differs".into());
        }
    }
    Ok(native)
}

/// The vault the network's Solana inventory is in: `flag`, or the one a
/// node's init saved on this machine. With neither, the failure says so, and
/// its hint is `next`.
fn vault(network: &str, flag: Option<&str>, next: &str) -> Result<String, CliError> {
    node_common::vault_given(network, flag)?.ok_or_else(|| {
        CliError::new(Code::Failed, format!("no vault is set for {network}")).hint(next)
    })
}

/// What to do without a vault, for a verb that takes --vault.
fn pass_vault(rpc: bool) -> String {
    format!(
        "pass --vault <vault id> (`op vault list` prints them); a new node's init saves it \
         on this machine, see `erpc {} --chain solana init --help`",
        if rpc { "rpc" } else { "v" }
    )
}

/// What to do without a vault, for `erpc v keys` and `vote-account`, which
/// take no --vault.
const SAVED_VAULT: &str = "a validator's init saves it on this machine with --vault <vault id>; \
     `erpc v --chain solana init --help` lists what init takes";

/// Legacy key commands must not cross a pending migration before fetching secrets.
pub(crate) fn legacy_key_preflight(
    network: &str,
    name: &str,
    transaction: bool,
) -> Result<Backend, CliError> {
    let vault = vault(network, None, SAVED_VAULT)?;
    let store = node_common::store(&node_common::op_runner()?, &vault, "solana", network)?;
    let recorded = store
        .solana_backend(name, false)
        .map_err(|e| e.to_string())?;
    legacy_key_backend(recorded, transaction)?;
    Ok(recorded)
}
fn legacy_key_backend(recorded: Backend, transaction: bool) -> Result<(), String> {
    if recorded == Backend::Migration {
        return Err(
            "original Solv migration is pending; legacy key and vote-account operations are fenced"
                .into(),
        );
    }
    if matches!(recorded, Backend::Native | Backend::New) && transaction {
        return Err(
            "native vote-account registration uses external signing; use erpc v registration"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn keys(args: &ArgMatches, json_out: bool) -> Outcome {
    let (Some(network), Some(name)) = (one(args, "network"), one(args, "name")) else {
        return Outcome::Usage("erpc v keys needs --network and --name".into());
    };
    match legacy_key_preflight(network, name, false) {
        Err(error) => Outcome::from(error),
        Ok(Backend::Native) => match native_keys(args, network, name) {
            Ok(value) if json_out => {
                crate::print_json(&value);
                Outcome::Done(String::new())
            }
            Ok(value) => Outcome::Done(serde_json::to_string_pretty(&value).unwrap_or_default()),
            Err(error) => Outcome::from(error),
        },
        Ok(_) => crate::validator_keys::run(
            &crate::validator_keys::Args {
                network: network.into(),
                name: name.into(),
                vote: one(args, "vote-account").map(str::to_owned),
                authority: one(args, "authority").map(str::to_owned),
                ssh_key: args.get_one::<std::path::PathBuf>("ssh-key").cloned(),
                ssh_agent: args.get_one::<std::path::PathBuf>("ssh-agent").cloned(),
                source_fingerprint: one(args, "source-fingerprint").map(str::to_owned),
                yes: args.get_flag("yes"),
            },
            json_out,
        ),
    }
}
fn native_keys(args: &ArgMatches, network: &str, name: &str) -> Result<Value, CliError> {
    if ["vote-account", "authority", "source-fingerprint"]
        .iter()
        .any(|key| one(args, key).is_some())
        || ["ssh-key", "ssh-agent"]
            .iter()
            .any(|key| args.get_one::<std::path::PathBuf>(key).is_some())
    {
        return Err("native key view accepts public original accounts only; legacy import options cannot replace them".into());
    }
    let vault = vault(network, None, SAVED_VAULT)?;
    let store = node_common::store(&node_common::op_runner()?, &vault, "solana", network)?;
    let keys = store
        .public_native_solana_keys(name)
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"validator":keys.name,"identity":keys.identity_account,"vote_account":keys.vote_account,
        "authority":keys.authority_account,"backend":"native","custody_inspected":false}),
    )
}

fn list(args: &ArgMatches, network: Option<&str>, rpc: bool) -> Result<Value, String> {
    if network.is_some_and(|n| !["mainnet", "testnet"].contains(&n)) {
        return Err("unsupported Solana network".into());
    }
    let networks = if let Some(vault) = one(args, "vault") {
        vec![(
            network.ok_or("--vault requires --network")?.to_owned(),
            vault.to_owned(),
        )]
    } else {
        let keyless = crate::keyless::load(&crate::keyless::path()?)?;
        keyless
            .networks
            .into_iter()
            .filter(|(n, _)| {
                ["mainnet", "testnet"].contains(&n.as_str())
                    && network.is_none_or(|wanted| wanted == n)
            })
            .map(|(n, v)| (n, v.vault_id))
            .collect()
    };
    let mut rows = Vec::new();
    for (network, vault) in networks {
        let store = node_common::store(&node_common::op_runner()?, &vault, "solana", &network)?;
        let values = store
            .solana_node_summaries(rpc)
            .map_err(|e| format!("{network}: {e}"))?;
        rows.extend(
            values
                .into_iter()
                .filter(|row| one(args, "backend").is_none_or(|backend| row["backend"] == backend)),
        );
    }
    Ok(if rpc {
        json!({"nodes":rows})
    } else {
        json!({"validators":rows})
    })
}

pub(crate) fn list_nodes(
    args: &ArgMatches,
    network: Option<&str>,
    rpc: bool,
    json_out: bool,
) -> Outcome {
    report(
        list(args, network, rpc),
        rpc,
        one(args, "backend"),
        json_out,
    )
}

/// The list is the command's result, so it is returned for standard output
/// (`Outcome::Done`), never written as a progress line on standard error.
fn report(
    result: Result<Value, String>,
    rpc: bool,
    backend: Option<&str>,
    json_out: bool,
) -> Outcome {
    match result {
        Ok(value) if json_out => {
            crate::print_json(&value);
            Outcome::Done(String::new())
        }
        Ok(value) => Outcome::Done(render(&value, rpc, backend)),
        Err(error) => Outcome::Failed(error),
    }
}

/// A public summary field as a person reads it: `-` where the backend does
/// not record it (a native node's version and last result come from
/// `status`), and `empty` where it is recorded and empty.
fn shown<'a>(row: &'a Value, key: &str, empty: &'a str) -> &'a str {
    match row[key].as_str() {
        Some("") => empty,
        Some(text) => text,
        None => "-",
    }
}

fn host_line(out: &mut String, host: &Value) {
    let _ = writeln!(
        out,
        "  {:<8} {:<20} {:<16} {}",
        shown(host, "role", "?"),
        shown(host, "name", "-"),
        shown(host, "address", "-"),
        shown(host, "last_result", "not deployed"),
    );
}

/// The rows as `erpc v list` and `erpc r --chain solana list` showed them
/// before there were two backends, with each node's backend ending its line.
/// `backend` is the `--backend` the rows were filtered by.
fn render(value: &Value, rpc: bool, backend: Option<&str>) -> String {
    let rows = value[if rpc { "nodes" } else { "validators" }]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if rows.is_empty() {
        if let Some(backend) = backend {
            let kind = if rpc {
                "Solana RPC nodes"
            } else {
                "validators"
            };
            return format!("no {kind} with the {backend} backend");
        }
        // A new node is a native one, whose init takes more flags than a
        // line here can show.
        return if rpc {
            "no Solana RPC nodes yet: `erpc rpc --chain solana init --help` and \
             docs/solana-native.md show how to set one up"
        } else {
            "no validators yet: `erpc v --chain solana init --help` and \
             docs/solana-native.md show how to set one up"
        }
        .to_owned();
    }
    let mut out = String::new();
    for row in rows {
        let (network, name) = (shown(row, "network", "-"), shown(row, "name", "-"));
        // A validator's registration without a host is neither backend's
        // node yet: what an init stored before it stopped.
        let backend = if !rpc && row.get("backend").is_some_and(Value::is_null) {
            "no host yet"
        } else {
            shown(row, "backend", "-")
        };
        if rpc {
            let _ = writeln!(
                out,
                "{network}  {name:<16} {:<16} {:<10} {:<10} {:<16} {}  [{backend}]",
                shown(row, "address", "-"),
                shown(row, "client", "-"),
                shown(row, "type", "-"),
                shown(row, "version", "-"),
                shown(row, "last_result", "not set up"),
            );
            continue;
        }
        let _ = writeln!(
            out,
            "{network}  {name}  {} {}  region {}  [{backend}]",
            shown(row, "client", "-"),
            shown(row, "version", "-"),
            shown(row, "region", "-"),
        );
        for host in row["hosts"].as_array().into_iter().flatten() {
            host_line(&mut out, host);
        }
        // A pending migration names its one host on the row itself.
        if row["host_name"].is_string() {
            host_line(
                &mut out,
                &json!({"name":row["host_name"],"address":row["address"]}),
            );
        }
    }
    out.trim_end().to_owned()
}

pub(crate) fn legacy_options(args: &ArgMatches) -> Result<(), String> {
    for name in [
        "identity-reference",
        "identity-public",
        "sync-reference",
        "sync-public",
        "vote-public",
        "withdraw-public",
        "accounts-uuid",
        "ledger-uuid",
        "snapshots-uuid",
        "commission",
        "component",
        "build-intent",
        "abandon-build",
        "restore-custody",
        "recover-cutover",
        "clear-rpc-allow",
        "clear-management-allow",
        "activate-validator",
        "bls-public",
        "exclusive-identity",
        "upgrade-source-authority",
        "original-client-record",
    ] {
        if args.try_contains_id(name).unwrap_or(false)
            && args.value_source(name) == Some(clap::parser::ValueSource::CommandLine)
        {
            return Err(format!(
                "--{name} requires native ownership; existing solv nodes need explicit migration"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_migration_refuses_every_backend_and_legacy_key_route() {
        for explicit in [None, Some("solv"), Some("native")] {
            for init in [false, true] {
                assert!(choose(Backend::Migration, explicit, init).is_err());
            }
        }
        for transaction in [false, true] {
            assert!(legacy_key_backend(Backend::Migration, transaction).is_err());
        }
        assert!(
            legacy_key_backend(Backend::Native, true)
                .unwrap_err()
                .contains("external signing")
        );
        assert!(legacy_key_backend(Backend::New, true).is_err());
        assert!(legacy_key_backend(Backend::Solv, true).is_ok());
    }
    #[test]
    fn new_nodes_default_to_native_and_existing_nodes_cannot_silently_switch() {
        assert_eq!(choose(Backend::New, None, true), Ok(true));
        assert!(choose(Backend::New, Some("solv"), true).is_err());
        assert_eq!(choose(Backend::Solv, None, false), Ok(false));
        assert_eq!(choose(Backend::Native, None, false), Ok(true));
        assert!(choose(Backend::Native, Some("solv"), false).is_err());
        assert!(choose(Backend::Solv, Some("native"), false).is_err());
        // An interrupted public logical reservation can resume native init;
        // native init still rejects any actual legacy host before host preparation.
        assert_eq!(choose(Backend::Solv, Some("native"), true), Ok(true));
    }
    #[test]
    fn a_solana_verb_without_a_vault_is_told_what_works_as_written() {
        // A verb that takes --vault.
        assert_eq!(
            pass_vault(false),
            "pass --vault <vault id> (`op vault list` prints them); a new node's init saves it \
             on this machine, see `erpc v --chain solana init --help`"
        );
        assert_eq!(
            pass_vault(true),
            "pass --vault <vault id> (`op vault list` prints them); a new node's init saves it \
             on this machine, see `erpc rpc --chain solana init --help`"
        );
        // `erpc v keys` and `vote-account`, which take none.
        assert_eq!(
            SAVED_VAULT,
            "a validator's init saves it on this machine with --vault <vault id>; \
             `erpc v --chain solana init --help` lists what init takes"
        );
        assert!(!SAVED_VAULT.contains("pass --vault"));
    }
    #[test]
    fn a_list_is_the_table_people_read_and_names_each_backend() {
        let validators = json!({"validators":[
            {"network":"testnet","name":"mv1","host_name":"mv1-1","backend":"migration",
             "address":"192.0.2.13","identity":"I","migration_complete":false,"ready":null,
             "runtime_inspected":false},
            {"network":"testnet","name":"nv1","backend":"native","identity":"I","client":"agave",
             "version":null,"region":"","hosts":[
                {"name":"nv1","role":"primary","address":"192.0.2.12","last_result":null}]},
            {"network":"testnet","name":"nv2","backend":null,"identity":"I","client":"agave",
             "version":"4.4.0","region":"","hosts":[]},
            {"network":"testnet","name":"tv1","backend":"solv","identity":"I","client":"agave",
             "version":"v4.4.0-beta.1","region":"dallas","hosts":[
                {"name":"tv1-1","role":"primary","address":"192.0.2.10","last_result":"deploy ok"},
                {"name":"tv1-2","role":"spare","address":"192.0.2.11","last_result":""}]}]});
        assert_eq!(
            render(&validators, false, None),
            "testnet  mv1  - -  region -  [migration]\n  \
             -        mv1-1                192.0.2.13       -\n\
             testnet  nv1  agave -  region -  [native]\n  \
             primary  nv1                  192.0.2.12       -\n\
             testnet  nv2  agave 4.4.0  region -  [no host yet]\n\
             testnet  tv1  agave v4.4.0-beta.1  region dallas  [solv]\n  \
             primary  tv1-1                192.0.2.10       deploy ok\n  \
             spare    tv1-2                192.0.2.11       not deployed"
        );
        let nodes = json!({"nodes":[
            {"network":"mainnet","name":"rn1","backend":"native","address":"192.0.2.31",
             "client":"agave","type":"native","version":null,"identity":"I","rpc_allow":null,
             "last_result":null},
            {"network":"mainnet","name":"rpc1","backend":"solv","address":"192.0.2.30",
             "client":"jito","type":"send-tx","version":"v4.3.2-jito","identity":"I",
             "rpc_allow":[],"last_result":""}]});
        assert_eq!(
            render(&nodes, true, None),
            "mainnet  rn1              192.0.2.31       agave      native     -                \
             -  [native]\n\
             mainnet  rpc1             192.0.2.30       jito       send-tx    v4.3.2-jito      \
             not set up  [solv]"
        );
    }
    #[test]
    fn a_list_is_returned_as_the_result_and_an_empty_one_says_how_to_begin() {
        let Outcome::Done(text) = report(Ok(json!({"validators":[]})), false, None, false) else {
            panic!("an empty list is not a failure");
        };
        // A command that runs as written, where a partial init would not.
        assert_eq!(
            text,
            "no validators yet: `erpc v --chain solana init --help` and \
             docs/solana-native.md show how to set one up"
        );
        let Outcome::Done(text) = report(Ok(json!({"nodes":[]})), true, None, false) else {
            panic!("an empty list is not a failure");
        };
        assert_eq!(
            text,
            "no Solana RPC nodes yet: `erpc rpc --chain solana init --help` and \
             docs/solana-native.md show how to set one up"
        );
        // Filtered by --backend, an empty list says nothing about the others.
        let Outcome::Done(text) = report(Ok(json!({"nodes":[]})), true, Some("native"), false)
        else {
            panic!("an empty list is not a failure");
        };
        assert_eq!(text, "no Solana RPC nodes with the native backend");
        let listed = json!({"validators":[{"network":"testnet","name":"tv1","backend":"solv"}]});
        let Outcome::Done(text) = report(Ok(listed), false, None, false) else {
            panic!("a list is not a failure");
        };
        assert!(text.starts_with("testnet  tv1  "), "{text}");
        assert!(matches!(
            report(Err("inert".into()), false, None, false),
            Outcome::Failed(reason) if reason == "inert"
        ));
    }
}
