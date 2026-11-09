// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Dedicated consensus custody, follower activation and external unsigned plans.
use crate::{
    commands::Outcome,
    hyperliquid_ops as rpc,
    node_common::{self, Say},
};
use clap::{Arg, ArgAction, ArgMatches, Command};
use erpc_chain::inventory::{
    hyperliquid::HyperliquidNode,
    hyperliquid_validator::{Mode, ValidatorNode},
};
use erpc_chain_hyperliquid::{Network, contract::Contract, validator::HotMaterial};
use erpc_core::chain::Verb;
use erpc_secret::OpRef;
use erpc_ssh::{
    RemoteCommand, Session,
    hyperliquid::{Command as HostCommand, Owner},
};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub(crate) fn args(mut command: Command, verb: &Verb) -> Command {
    if ["init", "update-config", "plan"].contains(&verb.name) {
        command = command.mut_arg("rpc-allow", |arg| {
            arg.hide(true)
                .help("Public RPC access is refused for a validator host")
        });
    }
    if verb.name == "init" {
        for name in ["validator-address", "hot-key-ref", "max-hot-usdc"] {
            command = command.arg(Arg::new(name).long(name));
        }
        command = command.arg(
            Arg::new("keys-unhosted")
                .long("keys-unhosted")
                .action(ArgAction::SetTrue)
                .help("Attest this dedicated consensus key is not hosted on any other node"),
        );
    }
    if verb.name == "deploy" {
        command=command.arg(Arg::new("activate-validator").long("activate-validator").action(ArgAction::SetTrue)
            .help("After synchronized follower and external registration, mount the original hot key and run consensus"));
    }
    if verb.name == "update-config" {
        command=command.arg(Arg::new("recover-private-filesystem").long("recover-private-filesystem")
            .conflicts_with_all(["management-allow","rpc-allow","recover-preparation","restore-key"])
            .help("Upgrade stopped private-state authority using an independently recorded original filesystem UUID; no startup or key change"));
        command=command.arg(Arg::new("restore-key").long("restore-key").action(ArgAction::SetTrue)
            .conflicts_with_all(["management-allow","rpc-allow","recover-preparation"])
            .help("Stop owned services and restore exactly the original concealed key; no restart"));
    }
    if verb.name == "plan" {
        command = command
            .arg(Arg::new("step").long("step").value_parser([
                "register",
                "jail",
                "unjail",
                "deposit",
                "delegate",
                "undelegate",
                "withdraw",
            ]))
            .arg(Arg::new("amount-wei").long("amount-wei"))
            .arg(Arg::new("validator-name").long("validator-name"))
            .arg(Arg::new("description").long("description"));
    }
    command.about(match verb.name {
        "init"=>"Reserve an original validator host and import its dedicated hot key into encrypted custody",
        "deploy"=>"Deploy a follower, or explicitly activate the externally registered original signer",
        "plan"=>"Inspect the native profile or prepare an unsigned external financial action",
        "destroy"=>"Stop and retire owned services while retaining all private history and encrypted keys",
        _=>verb.about,
    })
}
fn filesystem_recovery_inventory(
    name: &str,
    contract: &impl Serialize,
    original_uuid: &str,
) -> Result<String, String> {
    let parts: Vec<_> = original_uuid.split('-').collect();
    if parts.iter().map(|value| value.len()).collect::<Vec<_>>() != [8, 4, 4, 4, 12]
        || !parts.iter().all(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        || original_uuid.bytes().all(|byte| b"0-".contains(&byte))
    {
        return Err("supply the independently recorded original lowercase filesystem UUID".into());
    }
    Ok(json!({"all":{"hosts":{name:{"ansible_connection":"local",
        "hyperliquid_request":{"contract":contract,"original_uuid":original_uuid}}}}})
    .to_string())
}
fn request(node: &ValidatorNode, action: &str, intent: &str) -> Result<Value, String> {
    let mut value = rpc::request(&node.host, action, intent)?;
    value["target"]["mode"] = json!(node.mode.name());
    Ok(value)
}
fn inventory(
    node: &ValidatorNode,
    facts: &crate::eth_rpc::Facts,
    intent: &str,
) -> Result<String, String> {
    let mut value: Value = serde_json::from_str(&rpc::inventory(&node.host, facts, intent)?)
        .map_err(|_| "invalid public validator inventory")?;
    value["all"]["hosts"][&node.host.name]["hyperliquid_request"] =
        request(node, "prepare", intent)?;
    Ok(value.to_string())
}
fn settings(node: &mut ValidatorNode, args: &ArgMatches) -> Result<(), String> {
    rpc::settings(&mut node.host, args)?;
    if !node.host.rpc_allow.is_empty() {
        return Err("validator hosts cannot expose the public RPC gateway".into());
    }
    Ok(())
}
fn material(reference: &str) -> Result<HotMaterial, String> {
    let reference = OpRef::parse(reference)
        .map_err(|_| "identifier-only concealed hot-key reference required")?;
    let value = crate::rollup_credentials::read_concealed(&node_common::op_runner()?, &reference)?;
    HotMaterial::parse(value).map_err(str::to_owned)
}
#[derive(Serialize)]
struct PrivateImport<'a> {
    action: &'static str,
    contract: &'a Contract,
    key_file: &'a str,
    restore: bool,
    keys_unhosted: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    custody: String,
    restored: bool,
}

fn import_key(
    session: &Session,
    node: &ValidatorNode,
    key: &HotMaterial,
    restore: bool,
    unhosted: bool,
) -> Result<Value, String> {
    let identity = node
        .host
        .contract
        .validator
        .as_ref()
        .ok_or("validator identity is absent")?;
    if &key
        .identity(&identity.validator, &identity.max_hot_usdc)
        .map_err(str::to_owned)?
        != identity
    {
        return Err("concealed key differs from the original dedicated signer".into());
    }
    let payload = PrivateImport {
        action: "import-validator",
        contract: &node.host.contract,
        key_file: key.original().expose_secret(),
        restore,
        keys_unhosted: unhosted,
    };
    // Only stdin carries the original secret. No Value tree, argument, carried
    // bundle, diagnostic or public inventory contains these bytes.
    let mut encoded = Zeroizing::new(Vec::with_capacity(16_384));
    serde_json::to_writer(&mut *encoded, &payload)
        .map_err(|_| "cannot encode private custody request")?;
    let response = session
        .run(
            &RemoteCommand::Hyperliquid(HostCommand::Control),
            Some(encoded.as_slice()),
        )
        .map_err(|_| "original consensus custody refused; owned services remain stopped")?;
    let stdout = Zeroizing::new(response.stdout);
    let _stderr = Zeroizing::new(response.stderr);
    let result: Receipt =
        serde_json::from_slice(&stdout).map_err(|_| "invalid public custody result")?;
    if result.custody != "original" || result.restored != restore {
        return Err("unexpected original custody outcome".into());
    }
    Ok(json!({"custody":"original","restored":result.restored,"started":false}))
}
fn required<'a>(args: &'a ArgMatches, key: &str) -> Result<&'a str, String> {
    rpc::one(args, key).ok_or_else(|| format!("pass --{key}"))
}
fn initial_record(
    network: Network,
    args: &ArgMatches,
    name: &str,
    previous: Option<&ValidatorNode>,
    key: &HotMaterial,
) -> Result<ValidatorNode, String> {
    let profile = network.profile()?;
    let node = if let Some(node) = previous {
        let identity = node
            .host
            .contract
            .validator
            .as_ref()
            .ok_or("missing original validator identity")?;
        for (flag, stored) in [
            ("host", node.host.address.as_str()),
            ("user", node.host.ssh_user.as_str()),
            ("public-ip", node.host.contract.public_ip.as_str()),
            ("validator-address", identity.validator.as_str()),
            ("max-hot-usdc", identity.max_hot_usdc.as_str()),
            ("hot-key-ref", node.hot_key_ref.as_str()),
        ] {
            if rpc::one(args, flag).is_some_and(|v| v != stored) {
                return Err("original validator host and custody contract are immutable".into());
            }
        }
        if args
            .get_one::<u16>("port")
            .is_some_and(|p| *p != node.host.ssh_port)
        {
            return Err("original SSH port cannot change".into());
        }
        node.clone()
    } else {
        if !rpc::flag(args, "keys-unhosted") {
            return Err(
                "first custody requires --keys-unhosted; never duplicate an operating signer"
                    .into(),
            );
        }
        ValidatorNode {
            host: HyperliquidNode {
                id: None,
                item_version: 0,
                name: name.into(),
                address: required(args, "host")?.into(),
                ssh_user: rpc::one(args, "user").unwrap_or("ubuntu").into(),
                ssh_port: args.get_one::<u16>("port").copied().unwrap_or(22),
                host_key: String::new(),
                contract: Contract {
                    owner: rpc::nonce()?,
                    network,
                    role: "validator".into(),
                    public_ip: required(args, "public-ip")?.into(),
                    validator: Some(
                        key.identity(
                            required(args, "validator-address")?,
                            required(args, "max-hot-usdc")?,
                        )
                        .map_err(str::to_owned)?,
                    ),
                },
                supervisor_sha256: profile["supervisor"]["sha256"]
                    .as_str()
                    .ok_or("invalid supervisor")?
                    .into(),
                signed_at: profile["supervisor"]["signed_at"]
                    .as_u64()
                    .ok_or("invalid signature time")?,
                rpc_allow: vec![],
                management_allow: vec![],
                last_run: String::new(),
                last_result: String::new(),
            },
            hot_key_ref: required(args, "hot-key-ref")?.into(),
            mode: Mode::Follower,
        }
    };
    Ok(node)
}
fn init(network: Network, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let name = required(args, "name")?;
    let (store, vault) = rpc::open(network, args)?;
    let previous = store
        .hyperliquid_validators()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.host.name == name);
    let key = material(previous.as_ref().map_or_else(
        || required(args, "hot-key-ref"),
        |n| Ok(n.hot_key_ref.as_str()),
    )?)?;
    let mut node = initial_record(network, args, name, previous.as_ref(), &key)?;
    node.host.contract.validate()?;
    settings(&mut node, args)?;
    erpc_ssh::config::check_host(&node.host.address).map_err(|e| e.to_string())?;
    node.host.host_key = node_common::host_key(
        &node.host.address,
        node.host.ssh_port,
        previous.as_ref().map(|n| n.host.host_key.as_str()),
        rpc::one(args, "fingerprint"),
        say,
    )?
    .to_openssh();
    let target = rpc::target(&node.host, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = validator_facts(&session)?;
    node_common::go_ahead(
        rpc::flag(args, "yes"),
        "Hyperliquid validator host unchanged",
    )
    .map_err(|e| e.to_string())?;
    let vars = inventory(&node, &facts, &rpc::nonce()?)?;
    rpc::play(&session, &target, &vars, "preflight", say)?;
    node = if previous.is_some() {
        store.update_hyperliquid_validator(&node)
    } else {
        store.add_hyperliquid_validator(&node)
    }
    .map_err(|e| e.to_string())?;
    let (run, _) = rpc::play(&session, &target, &vars, "initialize", say)?;
    let imported = import_key(
        &session,
        &node,
        &key,
        false,
        rpc::flag(args, "keys-unhosted"),
    )?;
    node.host.last_run = run.as_str().into();
    node.host.last_result = "initialized; original hot custody imported".into();
    store
        .update_hyperliquid_validator(&node)
        .map_err(|e| e.to_string())?;
    node_common::save_vault(network.name(), &vault)?;
    Ok(
        json!({"name":name,"role":"validator","network":network.name(),"mode":"follower","started":false,"custody":imported}),
    )
}
fn validator_facts(session: &Session) -> Result<crate::eth_rpc::Facts, String> {
    let facts = rpc::facts(session)?;
    if facts.cpus < 32 {
        return Err(
            "Hyperliquid validator requires 32 CPU cores,128GB RAM and a1TB-class native volume"
                .into(),
        );
    }
    Ok(facts)
}
fn amount(args: &ArgMatches) -> Result<u64, String> {
    let text = required(args, "amount-wei")?;
    if text.is_empty()
        || text.len() > 20
        || !text.bytes().all(|b| b.is_ascii_digit())
        || text.starts_with('0')
    {
        return Err("amount-wei must be an explicit positive canonical integer".into());
    }
    text.parse::<u64>()
        .map_err(|_| "amount-wei exceeds the native unsigned bound".into())
}
fn validate_plan(args: &ArgMatches) -> Result<(), String> {
    let step = rpc::one(args, "step");
    let financial = step.is_some_and(|value| {
        ["register", "deposit", "delegate", "undelegate", "withdraw"].contains(&value)
    });
    if financial {
        amount(args)?;
    } else if rpc::one(args, "amount-wei").is_some() {
        return Err("this action does not accept an amount".into());
    }
    if step == Some("register") {
        let name = required(args, "validator-name")?;
        let description = required(args, "description")?;
        if name.is_empty()
            || name.len() > 64
            || description.len() > 1024
            || name
                .chars()
                .chain(description.chars())
                .any(char::is_control)
        {
            return Err("bounded printable validator name and description required".into());
        }
    } else if rpc::one(args, "validator-name").is_some() || rpc::one(args, "description").is_some()
    {
        return Err("public profile fields belong only to --step register".into());
    }
    Ok(())
}
fn unsigned_plan(node: &ValidatorNode, args: &ArgMatches) -> Result<Value, String> {
    validate_plan(args)?;
    let identity = node
        .host
        .contract
        .validator
        .as_ref()
        .ok_or("missing original validator identity")?;
    let step = required(args, "step")?;
    let mut result = json!({"step":step,"network":node.host.contract.network.name(),"validator":identity.validator,
        "signer":identity.signer,"signing_authority":if ["jail","unjail"].contains(&step){"dedicated consensus signer"}else{"external validator/funds wallet"},
        "signed":false,"submitted":false,"source":"https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/README.md",
        "execution":"External signing workstation only; ERPC never reads the cold key or submits this action"});
    let tokens = match step {
        "register" => {
            let name = required(args, "validator-name")?;
            let description = required(args, "description")?;
            result["unsigned_action"] = json!({"type":"CValidatorAction","register":{"profile":{"node_ip":{"Ip":node.host.contract.public_ip},
                "signer":identity.signer,"name":name,"description":description},"initial_wei":amount(args)?}});
            vec![
                "send-signed-action".to_owned(),
                result["unsigned_action"].to_string(),
            ]
        }
        "jail" | "unjail" => {
            let mut action = json!({"type":"CSignerAction"});
            action[if step == "jail" {
                "jailSelf"
            } else {
                "unjailSelf"
            }] = Value::Null;
            result["unsigned_action"] = action;
            vec![
                "send-signed-action".to_owned(),
                result["unsigned_action"].to_string(),
            ]
        }
        "deposit" => vec!["staking-deposit".into(), amount(args)?.to_string()],
        "withdraw" => vec!["staking-withdrawal".into(), amount(args)?.to_string()],
        "delegate" | "undelegate" => {
            let mut tokens = vec![
                "delegate".into(),
                identity.validator.clone(),
                amount(args)?.to_string(),
            ];
            if step == "undelegate" {
                tokens.push("--undelegate".into());
            }
            tokens
        }
        _ => return Err("unsupported external validator action".into()),
    };
    result["native_subcommand_arguments"] = json!(tokens);
    result["native_chain"] = json!(if node.host.contract.network == Network::Mainnet {
        "Mainnet"
    } else {
        "Testnet"
    });
    result["operator_checks"] = json!([
        "Use the externally selected original authority and current public registration state",
        "Registration is initially jailed; first inspect synchronized native consensus output before external unjail",
        "Before planned shutdown, externally jail and wait to leave the active set; emergency local stop remains available",
        "Amounts and current staking/admission rules require external confirmation; this plan never reserves funds"
    ]);
    Ok(result)
}
fn operation(
    verb: &str,
    network: Network,
    args: &ArgMatches,
    json_out: bool,
) -> Result<Value, String> {
    let say = Say { quiet: json_out };
    if verb == "init" {
        return init(network, args, &say);
    }
    if verb == "plan" && rpc::one(args, "name").is_none() {
        if rpc::one(args, "step").is_some() {
            return Err(
                "an external action plan requires --name and its original public contract".into(),
            );
        }
        return Ok(
            json!({"network":network.name(),"role":"validator","qualified_profile":network.profile()?,
            "initial_mode":"follower","cpu_cores":32,"memory_gb":128,"storage_gb":1000,
            "hot_custody":"original dedicated key from a concealed 1Password field; encrypted host credential",
            "cold_authority":"external","financial_signing_by_erpc":false,"submission_by_erpc":false,"changed":false}),
        );
    }
    let (store, _) = rpc::open(network, args)?;
    let nodes = store.hyperliquid_validators().map_err(|e| e.to_string())?;
    if verb == "list" {
        return Ok(
            json!({"nodes":nodes.iter().map(|node|json!({"name":node.host.name,"network":network.name(),
        "mode":node.mode,"identity":node.host.contract.validator,"last_result":node.host.last_result})).collect::<Vec<_>>()}),
        );
    }
    let name = required(args, "name")?;
    let mut node = nodes
        .into_iter()
        .find(|node| node.host.name == name)
        .ok_or("validator host is not initialized in this network")?;
    node.host.contract.validate()?;
    settings(&mut node, args)?;
    if verb == "plan" {
        return if rpc::one(args, "step").is_some() {
            unsigned_plan(&node, args)
        } else {
            Ok(
                json!({"contract":node.host.contract,"mode":node.mode,"qualified_profile":network.profile()?,
                "changed":false,"financial_signing_by_erpc":false,"submission_by_erpc":false}),
            )
        };
    }
    let target = rpc::target(&node.host, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if verb == "logs" {
        session.stream(&RemoteCommand::Hyperliquid(HostCommand::Logs{owner:Owner::new(&node.host.contract.owner)?,
            lines:args.get_one::<u32>("lines").copied().unwrap_or(100),follow:rpc::flag(args,"follow")}),&mut|stream,line|{
            if json_out{crate::print_line(&json!({"journal":line,"stream":match stream{erpc_ssh::Stream::Stdout=>"stdout",erpc_ssh::Stream::Stderr=>"stderr"}}).to_string())}
            else{say.line(line)}
        }).map_err(|_|"owned validator journal failed")?;
        return Ok(json!({"journal":"ended"}));
    }
    if verb == "status" {
        return rpc::control(
            &session,
            &json!({"action":"status","contract":node.host.contract}),
        );
    }
    node_common::go_ahead(
        rpc::flag(args, "yes"),
        "Hyperliquid validator host unchanged",
    )
    .map_err(|e| e.to_string())?;
    if let Some(original_uuid) = rpc::one(args, "recover-private-filesystem") {
        if verb != "update-config" {
            return Err("private filesystem recovery requires update-config".into());
        }
        let inventory =
            filesystem_recovery_inventory(&node.host.name, &node.host.contract, original_uuid)?;
        let (run, _) = rpc::play(
            &session,
            &target,
            &inventory,
            "recover-private-filesystem",
            &say,
        )?;
        return Ok(
            json!({"private_filesystem_upgraded":true,"stopped":true,"history_preserved":true,
            "next_action":"deploy the qualified current controller before starting","run":run.as_str()}),
        );
    }
    if rpc::flag(args, "restore-key") {
        if verb != "update-config" {
            return Err("restoration requires explicit update-config --restore-key".into());
        }
        return import_key(&session, &node, &material(&node.hot_key_ref)?, true, false);
    }
    if ["start", "stop", "restart", "destroy"].contains(&verb) {
        return rpc::control(
            &session,
            &json!({"action":if verb=="destroy"{"retire"}else{verb},"contract":node.host.contract}),
        );
    }
    if !["deploy", "update", "update-config"].contains(&verb) {
        return Err("unsupported validator operation".into());
    }
    deploy(verb, network, args, &say, &store, node, (&target, &session))
}
fn deploy(
    verb: &str,
    network: Network,
    args: &ArgMatches,
    say: &Say,
    store: &erpc_chain::inventory::Store<erpc_auth::store::one_password::OpCli>,
    mut node: ValidatorNode,
    connection: (&erpc_ssh::Target, &Session),
) -> Result<Value, String> {
    let (target, session) = connection;
    if rpc::flag(args, "activate-validator") {
        if verb != "deploy" {
            return Err(
                "validator activation requires explicit deploy --activate-validator".into(),
            );
        }
        node.mode = Mode::Validator;
    }
    let profile = network.profile()?;
    let sha = profile["supervisor"]["sha256"]
        .as_str()
        .ok_or("invalid qualified supervisor")?;
    let signed_at = profile["supervisor"]["signed_at"]
        .as_u64()
        .ok_or("invalid qualified signature time")?;
    if signed_at < node.host.signed_at {
        return Err("supervisor signature-time downgrade is refused".into());
    }
    if node.host.supervisor_sha256 != sha && verb != "update" {
        return Err("qualified supervisor changed; inspect plan then select update".into());
    }
    let facts = validator_facts(session)?;
    let intent = rpc::nonce()?;
    if rpc::flag(args, "recover-preparation") {
        rpc::control(
            session,
            &json!({"action":"recover-preparation","contract":node.host.contract}),
        )?;
    }
    rpc::control(session, &request(&node, "authorize", &intent)?)?;
    let vars = inventory(&node, &facts, &intent)?;
    rpc::play(session, target, &vars, "prepare", say)?;
    let (firewall_run, firewall_sha) = rpc::play(session, target, &vars, "firewall", say)?;
    let mut confirm = request(&node, "firewall-confirm", &intent)?;
    confirm["firewall"] = json!({"run":firewall_run.as_str(),"bundle":firewall_sha});
    let fresh = Session::open(target)
        .map_err(|_| "fresh SSH confirmation failed; firewall rollback remains armed")?;
    rpc::control(&fresh, &confirm)?;
    let activated = erpc_ops::firewall_inventory(&vars, &firewall_run, &firewall_sha)?;
    let (run, _) = rpc::play(&fresh, target, &activated, "activate", say)?;
    node.host.supervisor_sha256 = sha.into();
    node.host.signed_at = signed_at;
    node.host.last_run = run.as_str().into();
    node.host.last_result =
        "started; native health and public registration observation pending".into();
    store
        .update_hyperliquid_validator(&node)
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"name":node.host.name,"network":network.name(),"mode":node.mode,"started":true,
        "ready":"inspect native status and external registration separately","financial_signing_by_erpc":false,"submitted_by_erpc":false}),
    )
}
/// CLI routing is behind the common explicit network/production mutation guards.
pub(crate) fn run(verb: &str, args: &ArgMatches, network: Option<&str>, json_out: bool) -> Outcome {
    let Some(network) = network.and_then(Network::parse) else {
        return Outcome::Usage(
            "Hyperliquid validator requires --network mainnet or testnet".into(),
        );
    };
    if !["plan", "list"].contains(&verb) && rpc::one(args, "name").is_none() {
        return Outcome::Usage("pass --name <validator inventory host>".into());
    }
    if verb == "plan"
        && let Err(error) = validate_plan(args)
    {
        return Outcome::Usage(error);
    }
    match operation(verb, network, args, json_out) {
        Ok(value) => {
            let not_ready = verb == "status" && value["ready"] != true;
            let text = if json_out {
                crate::print_line(&value.to_string());
                String::new()
            } else {
                serde_json::to_string_pretty(&value).unwrap_or_default()
            };
            if not_ready {
                Outcome::Problems(text)
            } else {
                Outcome::Done(text)
            }
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_core::chain::{COMMON_VERBS, Chain, Role};
    fn fixture() -> ValidatorNode {
        let key =
            HotMaterial::parse(format!("{{\"key\":\"{}\"}}", "01".repeat(32)).into()).unwrap();
        let pin = Network::Testnet.profile().unwrap();
        ValidatorNode {
            host: HyperliquidNode {
                id: None,
                item_version: 0,
                name: "fixture".into(),
                address: "192.0.2.10".into(),
                ssh_user: "operator".into(),
                ssh_port: 2222,
                host_key: String::new(),
                contract: Contract {
                    owner: "a".repeat(32),
                    network: Network::Testnet,
                    role: "validator".into(),
                    public_ip: "8.8.8.8".into(),
                    validator: Some(
                        key.identity(&format!("0x{}", "ab".repeat(20)), "0.01")
                            .unwrap(),
                    ),
                },
                supervisor_sha256: pin["supervisor"]["sha256"].as_str().unwrap().into(),
                signed_at: pin["supervisor"]["signed_at"].as_u64().unwrap(),
                rpc_allow: vec![],
                management_allow: vec![],
                last_run: String::new(),
                last_result: String::new(),
            },
            hot_key_ref: format!("op://{}/{}/consensus", "a".repeat(26), "b".repeat(26)),
            mode: Mode::Follower,
        }
    }
    #[test]
    fn all_twelve_verbs_are_typed_and_custody_mutations_have_no_read_only_route() {
        for verb in COMMON_VERBS {
            let matches = crate::tree::command(Role::Validator, Chain::Hyperliquid)
                .try_get_matches_from(["v", "--network", "testnet", verb.name])
                .unwrap();
            if !["list", "plan"].contains(&verb.name) {
                assert!(matches!(
                    run(
                        verb.name,
                        matches.subcommand_matches(verb.name).unwrap(),
                        Some("testnet"),
                        false
                    ),
                    Outcome::Usage(_)
                ));
            }
            for (flag, allowed) in [
                ("--restore-key", verb.name == "update-config"),
                ("--activate-validator", verb.name == "deploy"),
            ] {
                assert_eq!(
                    crate::tree::command(Role::Validator, Chain::Hyperliquid)
                        .try_get_matches_from(["v", verb.name, flag])
                        .is_ok(),
                    allowed
                );
            }
        }
    }
    #[test]
    fn stopped_private_volume_recovery_is_validator_only_and_carries_no_key_or_activation() {
        let uuid = "00000000-0000-0000-0000-000000000001";
        let node = fixture();
        let value: Value = serde_json::from_str(
            &filesystem_recovery_inventory("fixture", &node.host.contract, uuid).unwrap(),
        )
        .unwrap();
        assert_eq!(
            value["all"]["hosts"]["fixture"]["hyperliquid_request"],
            json!({"contract":node.host.contract,"original_uuid":uuid})
        );
        for invalid in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "/dev/nvme0n1",
            "automatic",
        ] {
            assert!(
                filesystem_recovery_inventory("fixture", &node.host.contract, invalid).is_err()
            );
        }
        for role in [Role::Rpc, Role::Validator] {
            for verb in COMMON_VERBS {
                assert_eq!(
                    crate::tree::command(role, Chain::Hyperliquid)
                        .try_get_matches_from([
                            "node",
                            verb.name,
                            "--recover-private-filesystem",
                            uuid
                        ])
                        .is_ok(),
                    role == Role::Validator && verb.name == "update-config"
                );
            }
        }
        for conflict in ["--restore-key", "--recover-preparation"] {
            assert!(
                crate::tree::command(Role::Validator, Chain::Hyperliquid)
                    .try_get_matches_from([
                        "node",
                        "update-config",
                        "--recover-private-filesystem",
                        uuid,
                        conflict
                    ])
                    .is_err()
            );
        }
        let play = std::str::from_utf8(
            erpc_chain_hyperliquid::file("ansible/hyperliquid/recover-private-filesystem.yml")
                .unwrap(),
        )
        .unwrap();
        assert!(play.contains("recover-validator-filesystem"));
        assert!(!play.contains("activate"));
        assert!(!play.contains("key_file"));
    }
    #[test]
    fn all_external_action_steps_require_explicit_amounts_and_never_sign() {
        let node = fixture();
        for step in [
            "register",
            "jail",
            "unjail",
            "deposit",
            "delegate",
            "undelegate",
            "withdraw",
        ] {
            let mut argv = vec!["v", "plan", "--step", step];
            let financial = !["jail", "unjail"].contains(&step);
            if financial {
                argv.extend(["--amount-wei", "1000000000000"]);
            }
            if step == "register" {
                argv.extend([
                    "--validator-name",
                    "public fixture",
                    "--description",
                    "public fixture description",
                ]);
            }
            let matches = crate::tree::command(Role::Validator, Chain::Hyperliquid)
                .try_get_matches_from(argv)
                .unwrap();
            let result = unsigned_plan(&node, matches.subcommand_matches("plan").unwrap()).unwrap();
            assert_eq!(result["signed"], false);
            assert_eq!(result["submitted"], false);
            assert!(!result.to_string().contains(&node.hot_key_ref));
            assert_eq!(result["native_chain"], "Testnet");
            if step == "register" {
                assert_eq!(
                    result["unsigned_action"]["register"]["profile"]["signer"],
                    node.host.contract.validator.as_ref().unwrap().signer
                );
            }
            let missing = crate::tree::command(Role::Validator, Chain::Hyperliquid)
                .try_get_matches_from(["v", "plan", "--step", step])
                .unwrap();
            assert_eq!(
                unsigned_plan(&node, missing.subcommand_matches("plan").unwrap()).is_err(),
                financial
            );
        }
        for amount in ["0", "-1", "1e9", "01", "18446744073709551616"] {
            let matches = crate::tree::command(Role::Validator, Chain::Hyperliquid)
                .try_get_matches_from([
                    "v",
                    "plan",
                    "--step",
                    "deposit",
                    &format!("--amount-wei={amount}"),
                ])
                .unwrap();
            assert!(unsigned_plan(&node, matches.subcommand_matches("plan").unwrap()).is_err());
        }
    }
    #[test]
    fn invalid_financial_plan_is_rejected_before_inventory_or_external_tools() {
        for values in [
            vec![
                "v",
                "plan",
                "--name",
                "fixture",
                "--step",
                "deposit",
                "--amount-wei",
                "0",
            ],
            vec!["v", "plan", "--step", "register"],
            vec!["v", "plan", "--amount-wei", "1"],
            vec!["v", "plan", "--step", "jail", "--amount-wei", "1"],
        ] {
            let matches = crate::tree::command(Role::Validator, Chain::Hyperliquid)
                .try_get_matches_from(values)
                .unwrap();
            assert!(matches!(
                run(
                    "plan",
                    matches.subcommand_matches("plan").unwrap(),
                    Some("testnet"),
                    false
                ),
                Outcome::Usage(_)
            ));
        }
    }

    #[test]
    fn public_inventory_binds_native_mode_and_never_carries_concealed_reference() {
        let mut node = fixture();
        let facts = crate::eth_rpc::Facts {
            controller: "192.0.2.20".into(),
            ssh_port: 22,
            ..Default::default()
        };
        for mode in [Mode::Follower, Mode::Validator] {
            node.mode = mode;
            let encoded = inventory(&node, &facts, &"b".repeat(32)).unwrap();
            assert!(!encoded.contains(&node.hot_key_ref));
            let value: Value = serde_json::from_str(&encoded).unwrap();
            let request = &value["all"]["hosts"]["fixture"]["hyperliquid_request"];
            assert_eq!(request["target"]["mode"], mode.name());
            assert_eq!(request["contract"]["role"], "validator");
            assert_eq!(value["all"]["hosts"]["fixture"]["hyperliquid_ssh_port"], 22);
        }
        let matches = crate::tree::command(Role::Validator, Chain::Hyperliquid)
            .try_get_matches_from(["v", "update-config", "--rpc-allow", "192.0.2.20"])
            .unwrap();
        assert!(
            settings(
                &mut node,
                matches.subcommand_matches("update-config").unwrap()
            )
            .is_err()
        );
    }
}
