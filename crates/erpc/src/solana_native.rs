// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated native hosts: public inventory, sealed preparation and typed control.
use crate::{
    commands::Outcome,
    error::{CliError, Code},
    node_common::{self, Say},
};
use clap::{Arg, ArgAction, ArgMatches, Command};
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{
    Store, Validator,
    solana_native::{NativeConfig, NativeHost},
    solana_public::PublicValidator,
};
use erpc_chain_solana_native::{
    self as native,
    contract::{Contract, Volumes, host_binding},
};
use erpc_core::chain::Verb;
use erpc_ops::bundle::{Built, Bundle};
use erpc_ssh::{
    HostKey, Identity, RemoteCommand, Session, Target,
    solana_native::{Command as Remote, Revision},
};
use serde_json::{Value, json};

pub(crate) fn one<'a>(args: &'a ArgMatches, key: &str) -> Option<&'a str> {
    args.try_get_one::<String>(key)
        .ok()
        .flatten()
        .map(String::as_str)
}
pub(crate) fn flag(args: &ArgMatches, key: &str) -> bool {
    args.try_get_one::<bool>(key)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
pub(crate) fn access_values(args: &ArgMatches, key: &str) -> Option<Vec<String>> {
    if flag(args, &format!("clear-{key}")) {
        return Some(Vec::new());
    }
    args.try_get_many::<String>(key)
        .ok()
        .flatten()
        .map(|values| {
            values
                .map(|value| {
                    let value = value.trim();
                    value.parse::<std::net::IpAddr>().map_or_else(
                        |_| value.to_owned(),
                        |address| format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
                    )
                })
                .collect()
        })
}
/// A native confirmation that was refused: `declined` when the answer was
/// no, `needs_terminal` when nobody was at a terminal to give one, with its
/// hint. It has no text of its own, so `to_string()` cannot make it a plain
/// `failed`; `?` hands it on as the [`CliError`] it is.
pub(crate) struct Refusal(CliError);

impl From<Refusal> for CliError {
    fn from(refusal: Refusal) -> Self {
        refusal.0
    }
}

/// Asks before a native verb changes a node, unless --yes was given. Every
/// native confirmation is asked here.
pub(crate) fn confirm(args: &ArgMatches, refused: &str) -> Result<(), Refusal> {
    node_common::go_ahead(flag(args, "yes"), refused).map_err(Refusal)
}
fn explicit(args: &ArgMatches, key: &str) -> bool {
    args.try_contains_id(key).unwrap_or(false)
        && args.value_source(key) == Some(clap::parser::ValueSource::CommandLine)
}
fn supported_options(args: &ArgMatches) -> Result<(), String> {
    for key in [
        "identity",
        "vote-account",
        "authority",
        "source-fingerprint",
        "spare",
        "host-name",
        "type",
        "version",
        "geyser-version",
        "monitoring-allow",
        "follow",
        "purge-data",
    ] {
        if explicit(args, key) {
            return Err(format!(
                "--{key} belongs to the solv workflow or is unsupported by this native profile"
            ));
        }
    }
    if explicit(args, "client") && one(args, "client") != Some("agave") {
        return Err("native deployment uses the qualified Agave source profile".into());
    }
    if explicit(args, "service") && one(args, "service") != Some("validator") {
        return Err("native operations cannot select a legacy supporting service".into());
    }
    if explicit(args, "source") && !matches!(one(args, "source"), Some("validator" | "journal")) {
        return Err("native journals use --component node, gateway, firewall or build".into());
    }
    Ok(())
}
fn add(sub: Command, argument: Arg) -> Command {
    if sub
        .get_arguments()
        .any(|value| value.get_id() == argument.get_id())
    {
        sub
    } else {
        sub.arg(argument)
    }
}
// Keep the native option table alongside its shared/legacy flag composition.
#[allow(clippy::too_many_lines)]
pub(crate) fn args(mut sub: Command, verb: &Verb) -> Command {
    sub = sub.arg(
        Arg::new("backend")
            .long("backend")
            .value_parser(["native", "solv"])
            .help("Default: native for new nodes, recorded backend for existing nodes; solv only resumes existing nodes"),
    );
    sub = add(
        sub,
        Arg::new("vault")
            .long("vault")
            .help("Network inventory vault identifier"),
    );
    if verb.name != "list" {
        for id in ["ssh-key", "ssh-agent"] {
            sub = add(
                sub,
                Arg::new(id)
                    .long(id)
                    .value_parser(clap::value_parser!(std::path::PathBuf)),
            );
        }
    }
    if !verb.read_only {
        sub = add(
            sub,
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue),
        );
    }
    if verb.name == "init" {
        sub = sub.arg(Arg::new("upgrade-source-authority").long("upgrade-source-authority")
            .action(ArgAction::SetTrue).requires("original-client-record")
            .help("Explicitly stop and upgrade a previously managed native host using independent highest-used client history"));
        sub = sub.arg(Arg::new("original-client-record").long("original-client-record")
            .requires("upgrade-source-authority").value_parser(clap::value_parser!(std::path::PathBuf))
            .help("Original public JSON record: schema, client, network, highest-used version and commit"));
        for (id, help) in [
            (
                "identity-reference",
                "Identifier-only 1Password reference to the dedicated identity JSON keypair",
            ),
            ("identity-public", "Dedicated node identity public key"),
            (
                "sync-reference",
                "Validator synchronization identity reference; separate from the registered identity",
            ),
            (
                "sync-public",
                "Validator synchronization identity public key",
            ),
            ("vote-public", "Externally created vote account public key"),
            (
                "withdraw-public",
                "External withdrawal authority public key",
            ),
            (
                "accounts-uuid",
                "Existing /mnt/erpc-solana-accounts filesystem UUID",
            ),
            (
                "ledger-uuid",
                "Existing /mnt/erpc-solana-ledger filesystem UUID",
            ),
            (
                "snapshots-uuid",
                "Existing /mnt/erpc-solana-snapshots filesystem UUID",
            ),
        ] {
            sub = sub.arg(Arg::new(id).long(id).help(help));
        }
        sub = sub.arg(
            Arg::new("commission")
                .long("commission")
                .value_parser(clap::value_parser!(u8))
                .help("The vote account's commission, 0 to 100 percent; a validator needs it, an RPC host takes none"),
        );
    }
    if matches!(verb.name, "init" | "update-config" | "plan") {
        for (id, help) in [
            (
                "rpc-allow",
                "Who may reach a native RPC host's RPC ports (7211, 7212): addresses or networks such as 198.51.100.0/24, repeated or comma-separated; a validator takes none",
            ),
            (
                "management-allow",
                "Who may reach SSH, besides the machine that deploys: addresses or networks such as 198.51.100.0/24, repeated or comma-separated",
            ),
        ] {
            sub = add(
                sub,
                Arg::new(id)
                    .long(id)
                    .action(ArgAction::Append)
                    .value_delimiter(',')
                    .help(help),
            );
        }
    }
    if matches!(verb.name, "update-config" | "plan") {
        sub = sub.arg(
            Arg::new("clear-rpc-allow")
                .long("clear-rpc-allow")
                .action(ArgAction::SetTrue)
                .conflicts_with("rpc-allow")
                .help("Remove every RPC client allow rule from the native profile"),
        );
        sub = sub.arg(Arg::new("clear-management-allow").long("clear-management-allow").action(ArgAction::SetTrue).conflicts_with("management-allow")
            .help("Remove additional management ranges; retain this deployment's observed SSH caller"));
    }
    if verb.name == "logs" {
        sub = sub.arg(Arg::new("component").long("component").value_parser(["node","gateway","firewall","build"])
            .help("Native service journal; build uses the pending or approved source-build intent"));
        sub = sub.arg(
            Arg::new("build-intent")
                .long("build-intent")
                .requires("component")
                .help("Original source-build intent whose retained journal to inspect"),
        );
        sub = add(
            sub,
            Arg::new("lines")
                .long("lines")
                .value_parser(clap::value_parser!(u32))
                .default_value("100"),
        );
    }
    if verb.name == "plan" {
        sub = add(
            sub,
            Arg::new("change")
                .long("change")
                .default_value("deploy")
                .value_parser(["deploy", "update", "update-config"]),
        );
    }
    if matches!(verb.name, "deploy" | "update" | "update-config") {
        sub = sub.arg(Arg::new("recover-cutover").long("recover-cutover").value_name("ORIGINAL_INTENT")
            .conflicts_with_all(["abandon-build", "restore-custody"])
            .help("Stop and archive this interrupted cutover without starting a deployment; retain original keys and data"));
        sub = sub.arg(Arg::new("abandon-build").long("abandon-build").action(ArgAction::SetTrue)
            .help("Cancel the pending build without starting another or changing an approved runtime"));
        sub = sub.arg(
            Arg::new("restore-custody")
                .long("restore-custody")
                .action(ArgAction::SetTrue)
                .conflicts_with("abandon-build")
                .help("Restore the original identity during deployment, then continue to startup"),
        );
    }
    if matches!(verb.name, "deploy" | "plan") {
        let activation = Arg::new("activate-validator").long("activate-validator")
            .action(ArgAction::SetTrue).requires_all(["bls-public", "exclusive-identity"])
            .help("Explicitly activate this host's original registered voting identity after native BLS and public registration checks");
        sub = sub.arg(if verb.name == "deploy" {
            activation.conflicts_with_all(["recover-cutover", "abandon-build"])
        } else {
            activation
        });
        sub = sub.arg(Arg::new("bls-public").long("bls-public").requires("activate-validator")
            .help("Registered BLS public key; must match offline native derivation from the original identity"));
        sub = sub.arg(Arg::new("exclusive-identity").long("exclusive-identity").requires("activate-validator")
            .action(ArgAction::SetTrue).help("Confirm this dedicated identity is not running or being activated on another host"));
    }
    sub
}

fn open(network: &str, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    if !matches!(network, "mainnet" | "testnet") {
        return Err("native Solana requires mainnet or testnet".into());
    }
    let vault = node_common::vault_for(
        network,
        one(args, "vault"),
        "initialize with --vault <vault identifier>",
    )?;
    let store = node_common::store(&node_common::op_runner()?, &vault, "solana", network)?;
    Ok((store, vault))
}
pub(crate) fn target(node: &NativeHost, args: &ArgMatches) -> Result<Target, String> {
    Ok(Target {
        host: node.address.clone(),
        port: node.ssh_port,
        user: node.ssh_user.clone(),
        host_key: HostKey::parse(&node.host_key).map_err(|e| e.to_string())?,
        identity: Identity::Agent {
            socket: node_common::agent_socket(
                args.try_get_one::<std::path::PathBuf>("ssh-agent")
                    .ok()
                    .flatten()
                    .map(std::path::PathBuf::as_path),
            )?,
            public_key: args
                .try_get_one::<std::path::PathBuf>("ssh-key")
                .ok()
                .flatten()
                .cloned()
                .ok_or("pass --ssh-key <management public key file>")?,
        },
    })
}
pub(crate) fn request(session: &Session, command: Remote, body: &Value) -> Result<Value, String> {
    let out = session
        .run(
            &RemoteCommand::SolanaNative(command),
            Some(body.to_string().as_bytes()),
        )
        .map_err(|_| "native Solana operation failed; inspect its owned run or journal")?;
    serde_json::from_slice(&out.stdout).map_err(|_| "invalid native controller response".into())
}
pub(crate) fn probe(session: &Session, node: &NativeHost) -> Result<Value, String> {
    request(session, Remote::Probe, &json!({"contract":node.contract}))
}
pub(crate) fn control(session: &Session, node: &NativeHost, action: &str) -> Result<Value, String> {
    let before = probe(session, node)?;
    let revision = Revision::new(
        before["helper_revision"]
            .as_str()
            .ok_or("native host preparation is incomplete; resume init")?,
    )?;
    request(
        session,
        Remote::Control(revision),
        &json!({"action":action,"contract":node.contract}),
    )
}
fn bundle(node: &NativeHost, preflight: bool) -> Result<Built, String> {
    let request = if preflight {
        json!({"action":"preflight","role":if node.contract.is_rpc(){"rpc"}else{"validator"},"network":node.contract.network,"volumes":node.contract.volumes})
    } else {
        json!({"action":"prepare","contract":node.contract})
    };
    request_bundle(node, &request)
}
pub(crate) fn request_bundle(node: &NativeHost, request: &Value) -> Result<Built, String> {
    let inventory = json!({"all":{"hosts":{node.contract.name.clone():{
        "ansible_connection":"local", "solana_native_loader":native::carried_loader(),
        "solana_native_request":request
    }}}});
    let mut bundle = Bundle::new();
    for path in native::files() {
        bundle
            .add(
                path,
                native::file(path)
                    .ok_or("compiled native file is missing")?
                    .to_vec(),
            )
            .map_err(|e| e.to_string())?;
    }
    bundle
        .add("rpc-firewall.py", erpc_ops::RPC_FIREWALL.to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add("inventory.yml", inventory.to_string().into_bytes())
        .map_err(|e| e.to_string())?;
    bundle.finish().map_err(|e| e.to_string())
}
pub(crate) fn play(
    node: &NativeHost,
    session: &Session,
    target: &Target,
    preflight: bool,
    say: &Say,
) -> Result<(), String> {
    let built = bundle(node, preflight)?;
    let play = if preflight {
        "ansible/solana-native/preflight.yml"
    } else {
        "ansible/solana-native/initialize.yml"
    };
    let run = erpc_ops::run::start(session, &built, play).map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Resume native init with the original inventory name",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "native preparation failed (run {}); original data retained",
            run.as_str()
        ));
    }
    Ok(())
}
/// The settings a new native host is given. `registers` is whether init will
/// store the validator's registration, rather than take over one that is
/// stored already.
fn settings(
    args: &ArgMatches,
    contract: &Contract,
    registers: bool,
) -> Result<NativeConfig, String> {
    let list = |id| access_values(args, id).unwrap_or_default();
    let configuration = NativeConfig {
        identity_ref: one(args, "identity-reference")
            .ok_or("new native host requires --identity-reference")?
            .into(),
        sync_ref: one(args, "sync-reference").map(str::to_owned),
        sync_identity: one(args, "sync-public").map(str::to_owned),
        commission: args.try_get_one::<u8>("commission").ok().flatten().copied(),
        rpc_allow: list("rpc-allow"),
        management_allow: list("management-allow"),
    };
    if !contract.is_rpc() {
        // What a validator cannot go without, by its flag; the rules for the
        // values are `NativeConfig::validate`'s.
        for (flag, given) in [
            ("sync-reference", configuration.sync_ref.is_some()),
            ("sync-public", configuration.sync_identity.is_some()),
            ("commission", configuration.commission.is_some()),
        ] {
            if !given {
                return Err(format!("new native validator requires --{flag}"));
            }
        }
    }
    configuration
        .validate(contract)
        .map_err(|e| e.to_string())?;
    // The registration a validator's init stores names its identity by the
    // field `keypair` only; say so before any host is contacted. One stored
    // already, by an init that stopped before its host, is taken over as it
    // is.
    if registers
        && !contract.is_rpc()
        && erpc_secret::OpRef::parse(&configuration.identity_ref)
            .is_ok_and(|reference| reference.field() != "keypair")
    {
        return Err(
            "the --identity-reference of a native validator must name the field `keypair`, \
             as in op://<vault-id>/<item-id>/keypair"
                .into(),
        );
    }
    Ok(configuration)
}
fn fresh(
    network: &str,
    name: &str,
    rpc: bool,
    registers: bool,
    args: &ArgMatches,
    say: &Say,
) -> Result<(NativeHost, NativeConfig), String> {
    let required = |key| {
        one(args, key)
            .map(str::to_owned)
            .ok_or_else(|| format!("new native host requires --{key}"))
    };
    let address = required("host")?;
    erpc_ssh::config::check_host(&address).map_err(|e| e.to_string())?;
    let ssh_user = one(args, "user").unwrap_or("ubuntu").to_owned();
    let ssh_port = args
        .try_get_one::<u16>("port")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(22);
    let mut contract = Contract {
        schema: 1,
        profile: if rpc {
            "agave-native-rpc"
        } else {
            "agave-native"
        }
        .into(),
        inventory_id: "a".repeat(26),
        name: name.into(),
        network: network.into(),
        host_binding: "b".repeat(64),
        identity_account: required("identity-public")?,
        vote_account: one(args, "vote-public").map(str::to_owned),
        authority_account: one(args, "withdraw-public").map(str::to_owned),
        volumes: Volumes {
            accounts: required("accounts-uuid")?,
            ledger: required("ledger-uuid")?,
            snapshots: required("snapshots-uuid")?,
        },
    };
    contract.validate()?;
    let config = settings(args, &contract, registers)?;
    let host_key = node_common::host_key(&address, ssh_port, None, one(args, "fingerprint"), say)?
        .to_openssh();
    contract.host_binding = host_binding(&address, &ssh_user, ssh_port, &host_key);
    let mut node = NativeHost {
        contract,
        address,
        ssh_user,
        ssh_port,
        host_key,
        item_version: 0,
    };
    node.validate().map_err(|e| e.to_string())?;
    node.contract.inventory_id.clear();
    Ok((node, config))
}
fn immutable_options(
    node: &NativeHost,
    config: &NativeConfig,
    args: &ArgMatches,
) -> Result<(), String> {
    if (explicit(args, "user") && one(args, "user") != Some(node.ssh_user.as_str()))
        || (explicit(args, "port") && args.get_one::<u16>("port").copied() != Some(node.ssh_port))
        || (explicit(args, "commission")
            && args.get_one::<u8>("commission").copied() != config.commission)
    {
        return Err("native init cannot change the management login or commission".into());
    }
    for (key, expected) in [
        ("rpc-allow", &config.rpc_allow),
        ("management-allow", &config.management_allow),
    ] {
        if explicit(args, key) && access_values(args, key).as_ref() != Some(expected) {
            return Err(format!(
                "native init cannot change --{key}; use update-config"
            ));
        }
    }
    for (id, expected) in [
        ("host", Some(node.address.as_str())),
        (
            "identity-public",
            Some(node.contract.identity_account.as_str()),
        ),
        ("identity-reference", Some(config.identity_ref.as_str())),
        ("sync-public", config.sync_identity.as_deref()),
        ("sync-reference", config.sync_ref.as_deref()),
        ("vote-public", node.contract.vote_account.as_deref()),
        (
            "withdraw-public",
            node.contract.authority_account.as_deref(),
        ),
        (
            "accounts-uuid",
            Some(node.contract.volumes.accounts.as_str()),
        ),
        ("ledger-uuid", Some(node.contract.volumes.ledger.as_str())),
        (
            "snapshots-uuid",
            Some(node.contract.volumes.snapshots.as_str()),
        ),
    ] {
        if one(args, id).is_some_and(|actual| Some(actual) != expected) {
            return Err(format!("native init cannot change --{id}"));
        }
    }
    Ok(())
}
/// Stores the validator's registration, or takes over `registered`, the one
/// init read before it contacted the host. Storing the host compares the
/// registration again, under the inventory's lock, and storing a
/// registration refuses a name that has one by then.
fn logical(
    store: &Store<OpCli>,
    node: &NativeHost,
    config: &NativeConfig,
    registered: Option<&PublicValidator>,
) -> Result<(), String> {
    if node.contract.is_rpc() {
        return Ok(());
    }
    if let Some(existing) = registered {
        if existing.identity_account != node.contract.identity_account
            || Some(&existing.vote_account) != node.contract.vote_account.as_ref()
            || Some(&existing.authority_account) != node.contract.authority_account.as_ref()
        {
            return Err("logical validator registration differs from native ownership".into());
        }
        return Ok(());
    }
    let catalog = native::catalog()?;
    let source = catalog
        .networks
        .get(&node.contract.network)
        .ok_or("native network is not qualified")?;
    let validator = Validator {
        name: node.contract.name.clone(),
        identity_account: node.contract.identity_account.clone(),
        identity_ref: config.identity_ref.clone(),
        vote_account: node.contract.vote_account.clone().unwrap_or_default(),
        authority_account: node.contract.authority_account.clone().unwrap_or_default(),
        client: "agave".into(),
        version: source.version.clone(),
        commit: source.commit.clone(),
        ..Validator::default()
    };
    store
        .add_native_solana_validator(&validator, node)
        .map_err(|e| e.to_string())?;
    Ok(())
}
fn init(
    store: &Store<OpCli>,
    vault: &str,
    network: &str,
    rpc: bool,
    args: &ArgMatches,
    say: &Say,
) -> Result<Value, CliError> {
    let name = one(args, "name").ok_or("native init requires --name")?;
    // The rule the host holds a native name to, before the inventory is read.
    native::contract::check_name(name)?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let previous = store
        .solana_native_hosts()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.contract.name == name);
    let source_history = if flag(args, "upgrade-source-authority") {
        if previous.is_none() {
            return Err("source-authority upgrade requires an existing native reservation".into());
        }
        let path = args
            .get_one::<std::path::PathBuf>("original-client-record")
            .ok_or("original client record is required")?;
        Some(crate::solana_source_upgrade::read(path, network)?)
    } else {
        None
    };
    // A validator's registration stored already, by an init that stopped
    // before its host, is taken over as it is; only one this init stores is
    // held to the registration's rules. It is read before any host is
    // contacted.
    let mut registered = None;
    let (mut node, config) = if let Some(node) = previous {
        let config = store
            .solana_native_config(&node)
            .map_err(|e| e.to_string())?;
        immutable_options(&node, &config, args)?;
        (node, config)
    } else {
        if !rpc {
            registered = store
                .public_solana_validators()
                .map_err(|e| e.to_string())?
                .into_iter()
                .find(|v| v.name == name);
        }
        fresh(network, name, rpc, registered.is_none(), args, say)?
    };
    if node.contract.is_rpc() != rpc {
        return Err("native inventory role differs".into());
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    probe(&session, &node)?;
    confirm(args, "native host preparation was not confirmed")?;
    if let Some(document) = source_history {
        return Ok(crate::solana_source_upgrade::apply(
            &node, &session, &target, &document, say,
        )?);
    }
    if node.contract.inventory_id.is_empty() {
        // The sealed inspection run writes only its own public bundle/logs. No
        // inventory, account, key, kernel setting or node data is changed yet.
        play(&node, &session, &target, true, say)?;
        logical(store, &node, &config, registered.as_ref())?;
        node = store
            .add_configured_solana_native_host(&node, &config)
            .map_err(|e| e.to_string())?;
    }
    node_common::save_vault(network, vault)?;
    play(&node, &session, &target, false, say)?;
    let after = probe(&session, &node)?;
    Revision::new(
        after["helper_revision"]
            .as_str()
            .ok_or("native preparation did not publish its helper receipt")?,
    )?;
    if after["initialized"] != true {
        return Err("native ownership preparation remains incomplete".into());
    }
    Ok(json!({"name":name,"network":network,"prepared":true,"services_started_by_init":false}))
}
fn operation(
    verb: &str,
    args: &ArgMatches,
    network: &str,
    rpc: bool,
    say: &Say,
) -> Result<Value, CliError> {
    supported_options(args)?;
    let (store, vault) = open(network, args)?;
    if verb == "init" {
        return init(&store, &vault, network, rpc, args, say);
    }
    let nodes = store.solana_native_hosts().map_err(|e| e.to_string())?;
    if verb == "list" {
        return Ok(
            json!({"nodes":nodes.into_iter().filter(|n|n.contract.is_rpc()==rpc).collect::<Vec<_>>()}),
        );
    }
    let name = one(args, "name").ok_or("native operation requires --name")?;
    let Some(node) = nodes
        .into_iter()
        .find(|n| n.contract.name == name && n.contract.is_rpc() == rpc)
    else {
        // A validator registered without a host is what an init stored
        // before it stopped.
        let registered = !rpc
            && store
                .public_solana_validators()
                .map_err(|e| e.to_string())?
                .iter()
                .any(|v| v.name == name);
        return Err(unknown(name, network, rpc, registered));
    };
    if verb == "plan" {
        let config = store
            .solana_native_config(&node)
            .map_err(|e| e.to_string())?;
        let target = target(&node, args)?;
        let session = Session::open(&target).map_err(|e| e.to_string())?;
        let observed = control(&session, &node, "deployment")?;
        return Ok(crate::solana_native_plan::render(
            &node, &config, args, &observed,
        )?);
    }
    if matches!(verb, "deploy" | "update" | "update-config") {
        return crate::solana_native_deploy::run(verb, args, &node, &store, say);
    }
    if !matches!(
        verb,
        "status" | "logs" | "start" | "stop" | "restart" | "destroy"
    ) {
        return Err("native deployment continuation for this verb is not connected yet".into());
    }
    if flag(args, "purge-data") {
        return Err(
            "native destroy retains original data and credentials; purge is not supported".into(),
        );
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if !matches!(verb, "status" | "logs") {
        confirm(args, "native operation was not confirmed")?;
    }
    if verb == "logs" {
        let lines = args.get_one::<u32>("lines").copied().unwrap_or(100);
        if !(1..=1000).contains(&lines) {
            return Err("native logs requires --lines between 1 and 1000".into());
        }
        let before = probe(&session, &node)?;
        let revision = Revision::new(
            before["helper_revision"]
                .as_str()
                .ok_or("native host is not prepared")?,
        )?;
        let component = one(args, "component").unwrap_or("node");
        if one(args, "build-intent").is_some() && component != "build" {
            return Err("--build-intent requires --component build".into());
        }
        let mut body =
            json!({"action":"logs","contract":node.contract,"lines":lines,"component":component});
        if let Some(intent) = one(args, "build-intent") {
            body["intent"] = json!(intent);
        }
        return Ok(request(&session, Remote::Control(revision), &body)?);
    }
    Ok(control(&session, &node, verb)?)
}
/// A name neither backend has set up on the network: no native host, and
/// no solv node either, or the backend would have been solv. A validator
/// that is `registered` all the same is one an init stored before it
/// stopped, and the same init resumes it.
fn unknown(name: &str, network: &str, rpc: bool, registered: bool) -> CliError {
    if registered {
        return CliError::new(
            Code::Failed,
            format!(
                "validator {name:?} is registered on {network} but has no host: \
                 the init that registered it stopped before its host"
            ),
        )
        .hint("run the same init again to resume it; `erpc v --chain solana init --help` lists its flags");
    }
    let (role, kind, kinds) = if rpc {
        ("rpc", "RPC node", "RPC nodes")
    } else {
        ("v", "validator", "validators")
    };
    let list = format!("`erpc {role} --chain solana list -n {network}` shows the {kinds} there");
    // A new node is a native one, and init sets one up only under a name the
    // native rule accepts.
    let next = match native::contract::check_name(name) {
        Ok(()) => format!(
            "{list}; `erpc {role} --chain solana init --help` and docs/solana-native.md \
             show how to set up {name:?}"
        ),
        Err(refused) => format!("{list}; {refused}"),
    };
    CliError::new(
        Code::Failed,
        format!("there is no Solana {kind} {name:?} set up on {network}"),
    )
    .hint(next)
}
pub(crate) fn report_status(
    rpc: bool,
    result: Result<Value, String>,
    json_out: bool,
    output: &mut dyn FnMut(&str),
) -> Outcome {
    crate::node_report::status(
        result,
        if rpc {
            "/rpc_ready"
        } else {
            "/validator_ready"
        },
        json_out,
        output,
    )
}

pub(crate) fn run(
    verb: &str,
    args: &ArgMatches,
    network: Option<&str>,
    rpc: bool,
    json_out: bool,
) -> Outcome {
    let Some(network) = network else {
        return Outcome::Usage("native Solana operation requires --network".into());
    };
    let say = Say { quiet: json_out };
    match operation(verb, args, network, rpc, &say) {
        // `status` reports what it observed: a node that is not ready is
        // `problems_found`. A failure is any verb's, with its hint.
        Ok(value) if verb == "status" => {
            report_status(rpc, Ok(value), json_out, &mut crate::print_line)
        }
        result => outcome(result, json_out),
    }
}

/// What a native verb did is its result, for standard output: one JSON line
/// with `--json`, indented for a person otherwise. `say` is for progress only.
/// A failure keeps its code: a confirmation said no to is `declined`, one
/// nobody could answer is `needs_terminal`. A migration's result is one too.
pub(crate) fn outcome(result: Result<Value, CliError>, json_out: bool) -> Outcome {
    match result {
        Ok(value) if json_out => {
            crate::print_json(&value);
            Outcome::Done(String::new())
        }
        Ok(value) => Outcome::Done(serde_json::to_string_pretty(&value).unwrap_or_default()),
        Err(error) => Outcome::from(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_core::chain::{COMMON_VERBS, Chain, Role};
    #[test]
    fn first_voting_activation_requires_explicit_public_key_and_exclusive_identity() {
        let tree = crate::tree::command(Role::Validator, Chain::Solana);
        for verb in ["deploy", "plan"] {
            for options in [
                vec!["--activate-validator"],
                vec!["--bls-public", "public"],
                vec!["--exclusive-identity"],
                vec!["--activate-validator", "--bls-public", "public"],
            ] {
                let mut args = vec!["validator", verb];
                args.extend(options);
                assert!(tree.clone().try_get_matches_from(args).is_err());
            }
            let parsed = tree
                .clone()
                .try_get_matches_from([
                    "validator",
                    verb,
                    "--activate-validator",
                    "--bls-public",
                    "public",
                    "--exclusive-identity",
                ])
                .unwrap();
            let args = parsed.subcommand().unwrap().1;
            assert!(flag(args, "activate-validator"));
            assert!(crate::solana_backend::legacy_options(args).is_err());
        }
        for mode in ["--abandon-build", "--recover-cutover"] {
            let mut args = vec![
                "validator",
                "deploy",
                "--activate-validator",
                "--bls-public",
                "public",
                "--exclusive-identity",
                mode,
            ];
            if mode == "--recover-cutover" {
                args.push("original");
            }
            assert!(tree.clone().try_get_matches_from(args).is_err());
        }
    }
    #[test]
    fn recovery_names_one_original_intent_and_cannot_run_with_other_recovery_actions() {
        for role in [Role::Rpc, Role::Validator] {
            for verb in ["deploy", "update", "update-config"] {
                let command = crate::tree::command(role, Chain::Solana);
                assert!(
                    command
                        .clone()
                        .try_get_matches_from([role.as_str(), verb, "--recover-cutover"])
                        .is_err()
                );
                let id = "a".repeat(32);
                let parsed = command
                    .clone()
                    .try_get_matches_from([role.as_str(), verb, "--recover-cutover", &id])
                    .unwrap();
                assert_eq!(
                    one(parsed.subcommand().unwrap().1, "recover-cutover"),
                    Some(id.as_str())
                );
                for option in ["--abandon-build", "--restore-custody"] {
                    assert!(
                        command
                            .clone()
                            .try_get_matches_from([
                                role.as_str(),
                                verb,
                                "--recover-cutover",
                                &id,
                                option
                            ])
                            .is_err()
                    );
                }
            }
        }
    }
    #[test]
    fn explicit_access_revocation_is_distinct_from_preserving_the_existing_policy() {
        for role in [Role::Rpc, Role::Validator] {
            for verb in ["plan", "update-config"] {
                for key in ["rpc-allow", "management-allow"] {
                    let clear = format!("--clear-{key}");
                    let plain = format!("--{key}");
                    let parsed = crate::tree::command(role, Chain::Solana)
                        .try_get_matches_from([role.as_str(), verb, &clear])
                        .unwrap();
                    assert_eq!(
                        access_values(parsed.subcommand().unwrap().1, key),
                        Some(Vec::new())
                    );
                    assert!(
                        crate::tree::command(role, Chain::Solana)
                            .try_get_matches_from([
                                role.as_str(),
                                verb,
                                &clear,
                                &plain,
                                "192.0.2.1"
                            ])
                            .is_err()
                    );
                    let omitted = crate::tree::command(role, Chain::Solana)
                        .try_get_matches_from([role.as_str(), verb])
                        .unwrap();
                    assert_eq!(access_values(omitted.subcommand().unwrap().1, key), None);
                    assert!(
                        crate::solana_backend::legacy_options(parsed.subcommand().unwrap().1)
                            .is_err()
                    );
                }
            }
        }
    }
    #[test]
    fn native_access_lists_normalize_single_addresses_without_broadening_networks() {
        let parsed = crate::tree::command(Role::Rpc, Chain::Solana)
            .try_get_matches_from([
                "rpc",
                "init",
                "--backend",
                "native",
                "--rpc-allow",
                "192.0.2.3,2001:db8::1,192.0.2.7/24",
            ])
            .unwrap();
        assert_eq!(
            access_values(parsed.subcommand().unwrap().1, "rpc-allow").unwrap(),
            ["192.0.2.3/32", "2001:db8::1/128", "192.0.2.7/24"]
        );
        // Host bits in an explicit network stay visible for NativeConfig::validate
        // to reject, rather than silently widening an operator's access list.
    }
    #[test]
    fn native_flags_compose_with_all_existing_solana_verbs() {
        for role in [Role::Rpc, Role::Validator] {
            let command = crate::tree::command(role, Chain::Solana);
            command.clone().debug_assert();
            for verb in COMMON_VERBS {
                let args = command
                    .clone()
                    .try_get_matches_from([
                        role.as_str(),
                        verb.name,
                        "--backend",
                        "native",
                        "-n",
                        "testnet",
                        "--vault",
                        "fixture",
                    ])
                    .unwrap();
                assert_eq!(one(args.subcommand().unwrap().1, "backend"), Some("native"));
            }
        }
    }
    #[test]
    fn a_native_result_is_the_output_for_a_person_and_not_a_progress_line() {
        let done = json!({"name":"nv1","network":"testnet","prepared":true,
            "services_started_by_init":false});
        let Outcome::Done(text) = outcome(Ok(done.clone()), false) else {
            panic!("a result is not a failure");
        };
        // The whole record, as `finish` prints it on standard output.
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), done);
        assert!(text.lines().count() > 1, "indented for a person: {text}");
        let failure = outcome(Err("inert".into()), false).error().unwrap();
        assert_eq!(
            (failure.code, failure.message.as_str()),
            (Code::Failed, "inert")
        );
    }
    /// A native verb as every one asks: `confirm(..)?`, then its work.
    fn asking(asked: Result<(), Refusal>) -> Result<Value, CliError> {
        asked?;
        Ok(json!({"done":true}))
    }
    #[test]
    fn a_refused_native_confirmation_keeps_its_code_and_hint() {
        let start = |extra: &[&'static str]| {
            let mut line = vec!["validator", "start"];
            line.extend(extra);
            crate::tree::command(Role::Validator, Chain::Solana)
                .try_get_matches_from(line)
                .unwrap()
        };
        // --yes: nothing is asked.
        let yes = start(&["--yes"]);
        let asked = confirm(
            yes.subcommand().unwrap().1,
            "native operation was not confirmed",
        );
        assert!(matches!(asking(asked), Ok(value) if value["done"] == true));
        // What `confirm` refuses with when the answer is no, and when no one
        // is at a terminal to give one.
        let declined = CliError::new(
            Code::Declined,
            "native operation was not confirmed: you said no",
        );
        let unanswered = CliError::new(
            Code::NeedsTerminal,
            "native operation was not confirmed: no one is at a terminal to say yes",
        )
        .hint("pass --yes to go ahead without being asked");
        // Nobody at a terminal, as in CI or a pipe: the refusal is asked for
        // real. At a terminal, `confirm` would ask instead.
        if !crate::session::has_terminal() {
            let asked = start(&[]);
            let refused = confirm(
                asked.subcommand().unwrap().1,
                "native operation was not confirmed",
            )
            .map_err(CliError::from)
            .unwrap_err();
            assert_eq!(refused, unanswered);
        }
        for json_out in [false, true] {
            for (refusal, exit) in [(&declined, 6), (&unanswered, 3)] {
                let result = asking(Err(Refusal(refusal.clone())));
                let failure = outcome(result, json_out)
                    .error()
                    .expect("a refusal is a failure");
                assert_eq!(failure, *refusal);
                assert_eq!(failure.json()["error"]["exit"], exit);
            }
        }
    }
    #[test]
    fn every_native_confirmation_is_asked_through_confirm() {
        // `confirm`'s refusal has no text, so `to_string()` cannot turn it
        // into a plain failure; `go_ahead`'s error, asked for directly, could.
        for (file, source, asked) in [
            ("solana_native.rs", include_str!("solana_native.rs"), 1),
            (
                "solana_native_deploy.rs",
                include_str!("solana_native_deploy.rs"),
                0,
            ),
            (
                "solana_migration_execute.rs",
                include_str!("solana_migration_execute.rs"),
                0,
            ),
        ] {
            let code = source
                .split("\n#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or(source);
            assert_eq!(code.matches("go_ahead(").count(), asked, "{file}");
        }
    }
    fn new_host(rpc: bool) -> Contract {
        Contract {
            schema: 1,
            profile: if rpc {
                "agave-native-rpc"
            } else {
                "agave-native"
            }
            .into(),
            inventory_id: "a".repeat(26),
            name: "tv2".into(),
            network: "testnet".into(),
            host_binding: "b".repeat(64),
            identity_account: "2".repeat(44),
            vote_account: (!rpc).then(|| "3".repeat(44)),
            authority_account: (!rpc).then(|| "4".repeat(44)),
            volumes: Volumes {
                accounts: "10000000-0000-0000-0000-000000000001".into(),
                ledger: "10000000-0000-0000-0000-000000000002".into(),
                snapshots: "10000000-0000-0000-0000-000000000003".into(),
            },
        }
    }
    /// `settings` for a first `init`, which stores the validator's
    /// registration, with every flag the role needs, changed by `changes`: a
    /// flag given `None` is left out, one not there is added.
    fn init_settings(rpc: bool, changes: &[(&str, Option<&str>)]) -> Result<NativeConfig, String> {
        native_settings(rpc, true, changes)
    }
    /// `settings` for the `init` that takes over a validator's registration
    /// stored already, as `init_settings` otherwise.
    fn takeover_settings(changes: &[(&str, Option<&str>)]) -> Result<NativeConfig, String> {
        native_settings(false, false, changes)
    }
    fn native_settings(
        rpc: bool,
        registers: bool,
        changes: &[(&str, Option<&str>)],
    ) -> Result<NativeConfig, String> {
        let identity = format!("op://{}/{}/keypair", "a".repeat(26), "b".repeat(26));
        let sync = format!("op://{}/{}/keypair", "a".repeat(26), "c".repeat(26));
        let sync_public = "5".repeat(44);
        let mut flags: Vec<(&str, Option<&str>)> = vec![("--identity-reference", Some(&identity))];
        if !rpc {
            flags.extend([
                ("--sync-reference", Some(sync.as_str())),
                ("--sync-public", Some(&sync_public)),
                ("--commission", Some("5")),
            ]);
        }
        for (flag, value) in changes {
            match flags.iter_mut().find(|(known, _)| known == flag) {
                Some(known) => known.1 = *value,
                None => flags.push((flag, *value)),
            }
        }
        let role = if rpc { Role::Rpc } else { Role::Validator };
        let mut line = vec![role.as_str(), "init"];
        for (flag, value) in flags {
            if let Some(value) = value {
                line.extend([flag, value]);
            }
        }
        let parsed = crate::tree::command(role, Chain::Solana)
            .try_get_matches_from(line)
            .unwrap();
        settings(parsed.subcommand().unwrap().1, &new_host(rpc), registers)
    }
    #[test]
    fn an_init_that_takes_over_a_stored_registration_keeps_its_identity_reference() {
        // A first init that stopped after storing the validator's
        // registration is resumed by the same init, which takes the
        // registration over: the `keypair` field is the rule of a
        // registration init stores, and an earlier version may have stored
        // one with another field.
        let credential = format!("op://{}/{}/credential", "a".repeat(26), "b".repeat(26));
        let identity = [("--identity-reference", Some(credential.as_str()))];
        assert_eq!(
            takeover_settings(&identity).unwrap().identity_ref,
            credential
        );
        assert_eq!(
            init_settings(false, &identity).unwrap_err(),
            "the --identity-reference of a native validator must name the field `keypair`, \
             as in op://<vault-id>/<item-id>/keypair"
        );
        // Every other rule still holds for the host the takeover adds.
        assert_eq!(
            takeover_settings(&[("--commission", None)]).unwrap_err(),
            "new native validator requires --commission"
        );
        assert_eq!(
            takeover_settings(&[("--identity-reference", Some("op://Private/My Item/keypair"))])
                .unwrap_err(),
            "the identity reference is not usable: the vault must be a 26-character \
             1Password id, not a name: a name can be reassigned and so does not pin what is read"
        );
    }
    #[test]
    fn native_init_names_the_flag_or_the_rule_a_setting_breaks() {
        let config = init_settings(false, &[]).unwrap();
        assert_eq!(config.commission, Some(5));
        // A single address is that address's own network.
        let config = init_settings(false, &[("--management-allow", Some("192.0.2.3"))]).unwrap();
        assert_eq!(config.management_allow, ["192.0.2.3/32"]);
        // The keypair field is the validator registration's rule only.
        let rpc_identity = format!("op://{}/{}/identity", "a".repeat(26), "b".repeat(26));
        init_settings(true, &[("--identity-reference", Some(&rpc_identity))]).unwrap();
        let identity = format!("op://{}/{}/keypair", "a".repeat(26), "b".repeat(26));
        let identity_public = "2".repeat(44);
        for (rpc, changes, message) in [
            (
                false,
                vec![("--identity-reference", None)],
                "new native host requires --identity-reference".to_owned(),
            ),
            (
                false,
                vec![("--sync-reference", None)],
                "new native validator requires --sync-reference".to_owned(),
            ),
            (
                false,
                vec![("--sync-public", None)],
                "new native validator requires --sync-public".to_owned(),
            ),
            (
                false,
                vec![("--commission", None)],
                "new native validator requires --commission".to_owned(),
            ),
            (
                false,
                vec![("--commission", Some("101"))],
                "a validator needs a commission from 0 to 100".to_owned(),
            ),
            (
                false,
                vec![("--rpc-allow", Some("198.51.100.20/32"))],
                "a validator takes no RPC allow list".to_owned(),
            ),
            (
                false,
                vec![("--sync-reference", Some(identity.as_str()))],
                "the synchronization identity reference must differ from the identity reference"
                    .to_owned(),
            ),
            (
                false,
                vec![("--sync-public", Some(identity_public.as_str()))],
                "the synchronization identity must differ from the validator identity".to_owned(),
            ),
            (
                false,
                vec![("--management-allow", Some("192.0.2.7/24"))],
                r#""192.0.2.7/24" in the management allow list is not the first address of a /24 network"#
                    .to_owned(),
            ),
            (
                false,
                vec![("--management-allow", Some("example.com"))],
                r#""example.com" in the management allow list is not a network such as 198.51.100.0/24"#
                    .to_owned(),
            ),
            (
                false,
                vec![("--identity-reference", Some("op://Private/My Item/keypair"))],
                "the identity reference is not usable: the vault must be a 26-character \
                 1Password id, not a name: a name can be reassigned and so does not pin what is read"
                    .to_owned(),
            ),
            (
                false,
                vec![("--identity-reference", Some(rpc_identity.as_str()))],
                "the --identity-reference of a native validator must name the field `keypair`, \
                 as in op://<vault-id>/<item-id>/keypair"
                    .to_owned(),
            ),
            (
                true,
                vec![("--commission", Some("5"))],
                "an RPC host takes no synchronization identity and no commission".to_owned(),
            ),
            (
                true,
                vec![("--sync-public", Some("5".repeat(44).as_str()))],
                "an RPC host takes no synchronization identity and no commission".to_owned(),
            ),
            (
                true,
                vec![("--rpc-allow", Some("198.51.100.20/24"))],
                r#""198.51.100.20/24" in the RPC allow list is not the first address of a /24 network"#
                    .to_owned(),
            ),
        ] {
            let error = init_settings(rpc, &changes).unwrap_err();
            assert_eq!(error, message, "{changes:?}");
            assert!(!error.contains("could not be read"), "{error}");
        }
    }
    #[test]
    fn a_name_neither_backend_has_says_where_to_look_and_how_to_begin() {
        // The next step is the hint, in commands that run as written: the
        // list, and what setting one up takes rather than a partial init.
        assert_eq!(
            unknown("nosuch", "testnet", false, false).text(),
            "error: there is no Solana validator \"nosuch\" set up on testnet\n\
             hint: `erpc v --chain solana list -n testnet` shows the validators there; \
             `erpc v --chain solana init --help` and docs/solana-native.md show how to set up \
             \"nosuch\""
        );
        assert_eq!(
            unknown("rn1", "mainnet", true, false).text(),
            "error: there is no Solana RPC node \"rn1\" set up on mainnet\n\
             hint: `erpc rpc --chain solana list -n mainnet` shows the RPC nodes there; \
             `erpc rpc --chain solana init --help` and docs/solana-native.md show how to set up \
             \"rn1\""
        );
        // A name a new node cannot have is not offered an init: the rule is
        // said instead.
        assert_eq!(
            unknown("My_Val", "testnet", false, false).text(),
            "error: there is no Solana validator \"My_Val\" set up on testnet\n\
             hint: `erpc v --chain solana list -n testnet` shows the validators there; \
             \"My_Val\" is not a native Solana node name: start with a lowercase letter \
             and use at most 32 lowercase letters, digits and `-`"
        );
        assert_eq!(
            unknown("nosuch", "testnet", false, false).code,
            Code::Failed
        );
        // What the person typed stays inside its quotes.
        assert!(
            unknown("a`b c", "testnet", false, false)
                .message
                .contains(r#""a`b c""#)
        );
    }
    #[test]
    fn a_validator_registered_without_a_host_is_resumed_by_its_init() {
        // What an init stored before it stopped: there is a validator by that
        // name, and no host for a verb to reach yet.
        let error = unknown("nv1", "testnet", false, true);
        assert_eq!(
            error.text(),
            "error: validator \"nv1\" is registered on testnet but has no host: \
             the init that registered it stopped before its host\n\
             hint: run the same init again to resume it; \
             `erpc v --chain solana init --help` lists its flags"
        );
        // `status` and every other verb fail with it as it is: code and hint.
        for json_out in [false, true] {
            assert_eq!(
                outcome(Err(error.clone()), json_out).error().as_ref(),
                Some(&error)
            );
        }
        assert_eq!(error.json()["error"]["exit"], 1);
    }
    #[test]
    fn explicit_legacy_semantics_are_refused_before_opening_inventory() {
        for (role, verb, key, value) in [
            (Role::Rpc, "init", "--type", "grpc"),
            (Role::Rpc, "init", "--client", "jito"),
            (Role::Rpc, "start", "--service", "faithful"),
            (Role::Rpc, "update", "--version", "v4.3.2"),
            (Role::Validator, "init", "--identity", "new"),
            (Role::Validator, "init", "--vote-account", "new"),
        ] {
            let parsed = crate::tree::command(role, Chain::Solana)
                .try_get_matches_from([role.as_str(), verb, "--backend", "native", key, value])
                .unwrap();
            assert!(
                supported_options(parsed.subcommand().unwrap().1).is_err(),
                "{key}"
            );
        }
        for role in [Role::Rpc, Role::Validator] {
            let parsed = crate::tree::command(role, Chain::Solana)
                .try_get_matches_from([role.as_str(), "init", "--backend", "native"])
                .unwrap();
            supported_options(parsed.subcommand().unwrap().1).unwrap();
        }
    }
}
