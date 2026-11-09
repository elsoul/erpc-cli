// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Original Robinhood Defensive assertion-validator CLI orchestration.
use crate::{
    commands::Outcome,
    node_common::{self, Say},
    robinhood_bundle as bundle, robinhood_custody as custody,
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, robinhood_validator::Validator};
use erpc_chain_nitro::robinhood_validator::{self as validator, Network, Phase};
use erpc_secret::OpRef;
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

fn one<'a>(args: &'a ArgMatches, name: &str) -> Option<&'a str> {
    args.try_get_one::<String>(name)
        .ok()
        .flatten()
        .map(String::as_str)
}
fn flag(args: &ArgMatches, name: &str) -> bool {
    args.try_get_one::<bool>(name)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
fn intent() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "cannot allocate original creation intent")?;
    Ok(format!("{:032x}", u128::from_be_bytes(bytes)))
}
fn network(args: &ArgMatches) -> Result<Network, String> {
    one(args, "network")
        .and_then(Network::parse)
        .ok_or("Robinhood requires explicit mainnet or testnet".into())
}
fn open(args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let selected = network(args)?;
    let vault = node_common::vault_for(
        selected.name(),
        one(args, "vault"),
        "erpc v --chain robinhood init --network mainnet --vault <vault>",
    )?;
    Ok((
        node_common::store(
            &node_common::op_runner()?,
            &vault,
            "robinhood",
            selected.name(),
        )?,
        vault,
    ))
}
fn target(
    address: &str,
    user: &str,
    port: u16,
    key: &str,
    args: &ArgMatches,
) -> Result<Target, String> {
    Ok(Target {
        host: address.into(),
        user: user.into(),
        port,
        host_key: HostKey::parse(key).map_err(|e| e.to_string())?,
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
                .ok_or("pass --ssh-key with the operator public key")?
                .clone(),
        },
    })
}
fn owned_target(node: &Validator, args: &ArgMatches) -> Result<Target, String> {
    target(
        &node.address,
        &node.ssh_user,
        node.ssh_port,
        &node.host_key,
        args,
    )
}
fn request(node: &Validator, action: &str) -> Result<Value, String> {
    Ok(json!({"action":action,"contract":node.contract().map_err(|e|e.to_string())?}))
}
fn control(session: &Session, request: &Value) -> Result<Value, String> {
    let output = session
        .run(
            &RemoteCommand::RobinhoodValidatorControl {
                testnet: request["contract"]["network"]
                    .as_str()
                    .and_then(Network::parse)
                    .ok_or("invalid original Robinhood network")?
                    == Network::Testnet,
            },
            Some(request.to_string().as_bytes()),
        )
        .map_err(
            |_| "original validator operation failed; inspect owned status and retry safely",
        )?;
    if output.stdout.len() > 262_144 {
        return Err("validator result exceeds limit".into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "invalid validator controller response".into())
}
fn private_body(mut public: Value, secret: &SecretString) -> Result<SecretString, String> {
    if public
        .as_object_mut()
        .ok_or("invalid private request envelope")?
        .remove("secret")
        .is_some()
    {
        return Err("unexpected preexisting secret field".into());
    }
    let quoted = SecretString::from(
        serde_json::to_string(secret.expose_secret())
            .map_err(|_| "cannot encode private validator input")?,
    );
    let prefix = public.to_string();
    let body = SecretString::from(format!(
        "{},\"secret\":{}}}",
        prefix
            .strip_suffix('}')
            .ok_or("invalid private request object")?,
        quoted.expose_secret()
    ));
    Ok(body)
}
fn play(
    session: &Session,
    target: &Target,
    inventory: &str,
    network: Network,
    path: &str,
    say: &Say,
) -> Result<(erpc_ssh::RunId, String), String> {
    let built = bundle::build(network, inventory)?;
    let run = erpc_ops::run::start(session, &built, path).map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Retry using the original Robinhood validator inventory; never replace its wallet",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "validator run {} failed; original custody/data retained",
            run.as_str()
        ));
    }
    Ok((run, built.sha256))
}
fn carried_proof(
    session: &Session,
    target: &Target,
    name: &str,
    network: Network,
    request: &Value,
    say: &Say,
) -> Result<(erpc_ssh::RunId, String, Value), String> {
    let inventory = bundle::control_inventory(name, request)?;
    let (run, digest) = play(
        session,
        target,
        &inventory,
        network,
        bundle::CONTROL_PLAY,
        say,
    )?;
    let output = session
        .run(&RemoteCommand::RobinhoodValidatorResult(run.clone()), None)
        .map_err(|_| "completed validator public result could not be authenticated")?;
    let result = validator::public_result(
        &output.stdout,
        run.as_str(),
        &digest,
        &bundle::helpers(network)?,
        request,
    )?;
    Ok((run, digest, result))
}

fn carried(
    session: &Session,
    target: &Target,
    name: &str,
    network: Network,
    request: &Value,
    say: &Say,
) -> Result<Value, String> {
    carried_proof(session, target, name, network, request, say).map(|(_, _, result)| result)
}

struct WalletStagePermit {
    run: erpc_ssh::RunId,
    bundle: String,
    helpers: String,
    request: String,
}

enum WalletStageDecision<T> {
    ObserverRequired,
    Ready,
    Import(T),
}

fn stage_wallet_with<T>(
    mut authorize: impl FnMut() -> Result<WalletStageDecision<T>, String>,
    observe: impl FnOnce() -> Result<(), String>,
    read: impl FnOnce() -> Result<custody::Original, String>,
    deliver: impl FnOnce(T, &SecretString) -> Result<(), String>,
) -> Result<(), String> {
    let mut decision = authorize()?;
    if matches!(decision, WalletStageDecision::ObserverRequired) {
        observe()?;
        decision = authorize()?;
    }
    if matches!(decision, WalletStageDecision::ObserverRequired) {
        return Err("original healthy observer is not yet established; inspect status and retry active deployment".into());
    }
    // No concealed backup is read until original host qualification succeeds.
    let original = read()?;
    if let WalletStageDecision::Import(permit) = decision {
        deliver(permit, &original.secret)?;
    }
    Ok(())
}

fn wallet_stage_request(node: &Validator, intent: &str, restore: bool) -> Result<Value, String> {
    let mut value = request(node, "wallet-stage-authorize")?;
    value["intent"] = json!(intent);
    value["restore"] = json!(restore);
    Ok(value)
}

fn stage_wallet(
    session: &Session,
    target: &Target,
    node: &Validator,
    vault: &str,
    intent: &str,
    args: &ArgMatches,
    say: &Say,
) -> Result<(), String> {
    let restore = flag(args, "restore-custody");
    let public = wallet_stage_request(node, intent, restore)?;
    stage_wallet_with(
        || {
            let (run, bundle, result) =
                carried_proof(session, target, &node.name, node.network, &public, say)?;
            if result.as_object().is_none_or(|fields| fields.len() != 6)
                || result["contract"] != public["contract"]
                || result["wallet"] != node.wallet
                || result["intent"] != intent
                || result["restore"].as_bool() != Some(restore)
            {
                return Err("original wallet staging authorization differs".into());
            }
            let needed = result["requires_import"]
                .as_bool()
                .ok_or("missing original wallet staging decision")?;
            let observing = result["observer_required"]
                .as_bool()
                .ok_or("missing original observer requirement")?;
            if observing {
                if needed {
                    return Err("conflicting custody staging decision".into());
                }
                return Ok(WalletStageDecision::ObserverRequired);
            }
            if !needed {
                return Ok(WalletStageDecision::Ready);
            }
            Ok(WalletStageDecision::Import(WalletStagePermit {
                run,
                bundle,
                helpers: bundle::helpers(node.network)?,
                request: validator::request_digest(&public)?,
            }))
        },
        || {
            // Only the host's no-history decision permits this non-financial
            // bootstrap. Its own transition guard independently rejects any
            // already activated signer. The public desired mode stays active.
            let mut observer = node.clone();
            observer.desired = Phase::Observing;
            deploy(session, target, &observer, args, vault, say).map(|_| ())
        },
        || original(node, vault, None),
        |permit, secret| {
            let mut private = public.clone();
            private["action"] = json!("wallet-stage-import");
            let body = private_body(private, secret)?;
            let result = session
                .run(
                    &RemoteCommand::RobinhoodValidatorStage {
                        testnet: node.network == Network::Testnet,
                        run: permit.run,
                        bundle: permit.bundle,
                        helpers: permit.helpers,
                        request: permit.request,
                    },
                    Some(body.expose_secret().as_bytes()),
                )
                .map_err(|_| "original root-encrypted wallet staging failed")?;
            let _stdout = zeroize::Zeroizing::new(result.stdout);
            let _stderr = zeroize::Zeroizing::new(result.stderr);
            Ok(())
        },
    )
}

fn provider_stage_request(node: &Validator, intent: &str) -> Result<Value, String> {
    let mut public = request(node, "provider-stage-authorize")?;
    public["intent"] = json!(intent);
    Ok(public)
}

fn stage_upstreams(
    session: &Session,
    target: &Target,
    node: &Validator,
    intent: &str,
    say: &Say,
) -> Result<(), String> {
    let public = provider_stage_request(node, intent)?;
    let (run, bundle, result) =
        carried_proof(session, target, &node.name, node.network, &public, say)?;
    if result.as_object().is_none_or(|fields| fields.len() != 3)
        || result["contract"] != public["contract"]
        || result["intent"] != intent
        || result["requires_import"] != true
    {
        return Err("original parent recovery authorization differs".into());
    }
    // Read provider material only after the original host has durably stopped.
    let upstream = crate::rollup_credentials::read(
        &node_common::op_runner()?,
        &OpRef::parse(&node.upstreams_ref).map_err(|_| "invalid original parent reference")?,
    )?;
    let mut private = public.clone();
    private["action"] = json!("provider-stage-import");
    let body = private_body(private, upstream.secret())?;
    let output = session
        .run(
            &RemoteCommand::RobinhoodValidatorStage {
                testnet: node.network == Network::Testnet,
                run,
                bundle,
                helpers: bundle::helpers(node.network)?,
                request: validator::request_digest(&public)?,
            },
            Some(body.expose_secret().as_bytes()),
        )
        .map_err(|_| "original stopped parent credential recovery failed")?;
    let _stdout = zeroize::Zeroizing::new(output.stdout);
    let _stderr = zeroize::Zeroizing::new(output.stderr);
    Ok(())
}

fn account_binding<'a>(
    node: &'a Validator,
    vault: &'a str,
) -> Result<custody::Binding<'a>, String> {
    Ok(custody::Binding {
        vault,
        network: node.network.name(),
        owner: node
            .id
            .as_deref()
            .ok_or("missing original inventory reservation")?,
        creation: &node.creation,
        address: &node.wallet,
    })
}
fn original(
    node: &Validator,
    vault: &str,
    fresh: Option<&SecretString>,
) -> Result<custody::Original, String> {
    let value = custody::original(
        &node_common::op_runner()?,
        &account_binding(node, vault)?,
        fresh,
    )?;
    if !node.signer_ref.is_empty() && node.signer_ref != value.reference {
        return Err("original concealed signer reference changed".into());
    }
    Ok(value)
}
fn host_check(facts: &crate::eth_rpc::Facts) -> Result<(), String> {
    if facts.os != "ubuntu 24.04"
        || facts.machine != "x86_64"
        || !facts.sudo
        || facts.mem_kb < 120 * 1024 * 1024
        || facts.cpus < 16
        || facts.ssh_port == 0
    {
        return Err("Robinhood assertion validators require dedicated Ubuntu24.04 x86-64, 128GB RAM, 16 cores, sudo and an observed SSH listener".into());
    }
    Ok(())
}
fn initialize(args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let (store, vault) = open(args)?;
    let name = one(args, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|_| "invalid inventory name")?;
    let existing = store
        .robinhood_validators()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|v| v.name == name);
    if let Some(node) = &existing
        && (one(args, "host").is_some_and(|v| v != node.address)
            || one(args, "l1-upstreams").is_some_and(|v| v != node.upstreams_ref))
    {
        return Err("init cannot retarget an original validator".into());
    }
    let address = existing
        .as_ref()
        .map(|v| v.address.as_str())
        .or(one(args, "host"))
        .ok_or("fresh init requires --host")?;
    let port = existing.as_ref().map_or_else(
        || args.get_one::<u16>("port").copied().unwrap_or(22),
        |v| v.ssh_port,
    );
    let user = existing.as_ref().map_or_else(
        || one(args, "user").unwrap_or("ubuntu"),
        |v| v.ssh_user.as_str(),
    );
    let key = if let Some(node) = &existing {
        node.host_key.clone()
    } else {
        node_common::host_key(address, port, None, one(args, "fingerprint"), say)?.to_openssh()
    };
    let target = target(address, user, port, &key, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    host_check(&crate::eth_rpc::facts(&session)?)?;
    // A retry can have durable public custody before remote init exists. It
    // keeps that original contract and lets init verify/recover partial host
    // authority; only a new reservation uses the fresh empty-host preflight.
    let observed = if existing.is_none() {
        carried(
            &session,
            &target,
            name,
            network(args)?,
            &json!({"action":"preflight"}),
            say,
        )?
    } else {
        Value::Null
    };
    node_common::go_ahead(
        flag(args, "yes"),
        "no validator inventory, key or host changed",
    )
    .map_err(|e| e.to_string())?;
    let mut node = custody_stage(
        existing,
        || reserve_pending(&store, name, args, &target, &observed),
        |node, fresh| original(node, &vault, fresh),
        |node| {
            store
                .update_robinhood_validator(node)
                .map_err(|e| e.to_string())
        },
    )?;
    let result = carried(
        &session,
        &target,
        name,
        node.network,
        &request(&node, "init")?,
        say,
    )?;
    node.last_result = "initialized; observing deployment required".into();
    store
        .update_robinhood_validator(&node)
        .map_err(|e| e.to_string())?;
    node_common::save_vault(node.network.name(), &vault)?;
    Ok(result)
}
fn custody_stage(
    existing: Option<Validator>,
    reserve: impl FnOnce() -> Result<(Validator, SecretString), String>,
    read: impl FnOnce(&Validator, Option<&SecretString>) -> Result<custody::Original, String>,
    save: impl FnOnce(&Validator) -> Result<Validator, String>,
) -> Result<Validator, String> {
    let (mut node, fresh) = if let Some(node) = existing {
        (node, None)
    } else {
        let (node, secret) = reserve()?;
        (node, Some(secret))
    };
    let original = read(&node, fresh.as_ref())?;
    if !node.signer_ref.is_empty() && node.signer_ref != original.reference {
        return Err("original signer reference changed".into());
    }
    node.signer_ref = original.reference;
    save(&node)
}
fn reserve_pending(
    store: &Store<OpCli>,
    name: &str,
    args: &ArgMatches,
    target: &Target,
    observed: &Value,
) -> Result<(Validator, SecretString), String> {
    let reference = one(args, "l1-upstreams").ok_or("fresh init requires --l1-upstreams")?;
    OpRef::parse(reference)
        .map_err(|_| "parent credentials require an identifier-only reference")?;
    let keypair =
        erpc_wallet::evm::EvmKey::generate().map_err(|_| "fresh signer entropy unavailable")?;
    let wallet = keypair.address().to_string().to_lowercase();
    let secret = SecretString::from(keypair.secret_hex().to_string());
    let host_key = target.host_key.to_openssh();
    let node = Validator {
        id: None,
        item_version: 0,
        name: name.into(),
        network: network(args)?,
        address: target.host.clone(),
        ssh_user: target.user.clone(),
        ssh_port: target.port,
        host_binding: validator::host_binding(&target.host, &target.user, target.port, &host_key)?,
        host_key,
        data_uuid: observed["data_uuid"]
            .as_str()
            .ok_or("preflight omitted original data UUID")?
            .into(),
        wallet,
        creation: intent()?,
        signer_ref: String::new(),
        upstreams_ref: reference.into(),
        desired: Phase::Observing,
        management_allow: management(args, &[])?,
        last_run: String::new(),
        last_result: "custody-pending".into(),
    };
    Ok((
        store
            .add_robinhood_validator(&node)
            .map_err(|e| e.to_string())?,
        secret,
    ))
}

fn management(args: &ArgMatches, old: &[String]) -> Result<Vec<String>, String> {
    let values = args
        .try_get_many::<String>("management-allow")
        .ok()
        .flatten()
        .map_or_else(|| old.to_vec(), |v| v.cloned().collect());
    crate::arc_rpc::allow_list("management", &values, false)
}
fn deployment_order(
    desired: Phase,
    stage_wallet: impl FnOnce() -> Result<(), String>,
    prepare: impl FnOnce() -> Result<(), String>,
    upstreams: impl FnOnce() -> Result<(), String>,
    finish: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    upstreams()?;
    if desired == Phase::Active {
        stage_wallet()?;
    }
    prepare()?;
    finish()
}

fn desired_phase(current: Phase, args: &ArgMatches) -> Result<Phase, String> {
    let wanted = if flag(args, "activate-signer") {
        Phase::Active
    } else {
        current
    };
    if flag(args, "restore-custody") && wanted != Phase::Active {
        return Err("custody restore requires the original active signer mode".into());
    }
    Ok(wanted)
}

fn deploy(
    session: &Session,
    target: &Target,
    node: &Validator,
    args: &ArgMatches,
    vault: &str,
    say: &Say,
) -> Result<String, String> {
    let facts = crate::eth_rpc::facts(session)?;
    host_check(&facts)?;
    let token = intent()?;
    let inventory = bundle::deploy_inventory(node, &facts, &token)?;
    deployment_order(
        node.desired,
        || stage_wallet(session, target, node, vault, &token, args, say),
        || {
            play(
                session,
                target,
                &inventory,
                node.network,
                "validator/ansible/prepare.yml",
                say,
            )
            .map(|_| ())
        },
        || stage_upstreams(session, target, node, &token, say),
        || {
            let (prepared, digest) = play(
                session,
                target,
                &inventory,
                node.network,
                "validator/ansible/firewall.yml",
                say,
            )?;
            let fresh = Session::open(target).map_err(|e| e.to_string())?;
            let mut confirm = request(node, "firewall-confirm")?;
            confirm["intent"] = json!(token);
            confirm["operation"] = json!(prepared.as_str());
            confirm["bundle"] = json!(digest);
            control(&fresh, &confirm)?;
            let confirmed = erpc_ops::firewall_inventory(&inventory, &prepared, &digest)?;
            let (run, _) = play(
                session,
                target,
                &confirmed,
                node.network,
                "validator/ansible/deploy.yml",
                say,
            )?;
            Ok(run.as_str().into())
        },
    )
}

fn logs(session: &Session, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    session
        .stream(
            &RemoteCommand::NitroLogs {
                robinhood: true,
                lines: args.get_one::<u32>("lines").copied().unwrap_or(100),
                follow: flag(args, "follow"),
            },
            &mut |_, line| {
                if say.quiet {
                    crate::print_line(&json!({"journal":line}).to_string());
                } else {
                    say.line(line);
                }
            },
        )
        .map_err(|_| "validator journal stream failed")?;
    Ok(json!({"logs":"complete"}))
}
fn operation(verb: &str, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    if verb == "init" {
        return initialize(args, say);
    }
    let (store, vault) = open(args)?;
    let nodes = store.robinhood_validators().map_err(|e| e.to_string())?;
    if verb == "list" {
        return Ok(json!({"validators":nodes}));
    }
    let name = one(args, "name").ok_or("validator operation requires --name")?;
    let mut node = nodes
        .into_iter()
        .find(|v| v.name == name)
        .ok_or("original validator is not initialized")?;
    if let Some(version) = one(args, "version")
        && version != validator::VERSION
    {
        return Err("version is outside the reviewed assertion-validator catalog".into());
    }
    if verb == "plan" {
        return Ok(
            json!({"name":node.name,"network":node.network,"role":"defensive-validator","strategy":"Defensive","phase":node.desired,"change":one(args,"change").unwrap_or("deploy"),"version":validator::VERSION,"commit":validator::COMMIT,"helpers_sha256":bundle::helpers(node.network)?,"financial_registration":"external funding, wrap and allowance; explicit active mode uses original native Defensive rival assertion/stake signer; no confirmation or challenge-edge sends","data_and_history_preserved":true}),
        );
    }
    let target = owned_target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if verb == "logs" {
        let owner = request(&node, "metadata")?;
        if control(&session, &owner).is_err() {
            carried(&session, &target, name, node.network, &owner, say)?;
        }
        return logs(&session, args, say);
    }
    let action = match verb {
        "prepare-registration" => "registration-prepare",
        "validate-registration" => "registration-validate",
        "registration-status" => "registration-status",
        value => value,
    };
    if [
        "status",
        "registration-prepare",
        "registration-validate",
        "registration-status",
    ]
    .contains(&action)
    {
        return carried(
            &session,
            &target,
            name,
            node.network,
            &request(&node, action)?,
            say,
        );
    }
    node_common::go_ahead(flag(args, "yes"), "no original validator changed")
        .map_err(|e| e.to_string())?;
    if ["stop", "destroy", "start", "restart"].contains(&verb) {
        let query = request(&node, verb)?;
        let result = match control(&session, &query) {
            Ok(value) => value,
            Err(_) => carried(&session, &target, name, node.network, &query, say)?,
        };
        node.last_result = format!("{verb} requested; readiness observed separately");
        store
            .update_robinhood_validator(&node)
            .map_err(|e| e.to_string())?;
        return Ok(result);
    }
    if !["deploy", "update", "update-config"].contains(&verb) {
        return Err("unsupported assertion-validator operation".into());
    }
    node.desired = desired_phase(node.desired, args)?;
    if let Some(reference) = one(args, "l1-upstreams") {
        OpRef::parse(reference).map_err(|_| "invalid parent credential reference")?;
        node.upstreams_ref = reference.into();
    }
    node.management_allow = management(args, &node.management_allow)?;
    node = store
        .update_robinhood_validator(&node)
        .map_err(|e| e.to_string())?;
    node.last_run = deploy(&session, &target, &node, args, &vault, say)?;
    node.last_result = format!("{verb} submitted; readiness observed separately");
    store
        .update_robinhood_validator(&node)
        .map_err(|e| e.to_string())?;
    control(&session, &request(&node, "status")?)
}
pub(crate) fn report_status(
    result: Result<Value, String>,
    json_out: bool,
    output: &mut dyn FnMut(&str),
) -> Outcome {
    crate::node_report::status(result, "/validator_ready", json_out, output)
}

pub(crate) fn run(verb: &str, args: &ArgMatches, network: Option<&str>, json_out: bool) -> Outcome {
    if network.and_then(Network::parse).is_none() {
        return Outcome::Usage(
            "Robinhood Defensive validators require explicit mainnet or testnet".into(),
        );
    }
    if verb != "list"
        && one(args, "name").is_none_or(|name| erpc_chain::inventory::check_name(name).is_err())
    {
        return Outcome::Usage(
            "Robinhood validator operation requires a valid --name before inventory access".into(),
        );
    }
    let say = Say { quiet: json_out };
    let result = operation(verb, args, &say);
    if verb == "status" {
        return report_status(result, json_out, &mut crate::print_line);
    }
    match result {
        Ok(value) => {
            if json_out {
                crate::print_line(&value.to_string());
            } else {
                say.line(&serde_json::to_string_pretty(&value).unwrap_or_default());
            }
            Outcome::Done(String::new())
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn fixture(network: Network) -> Validator {
        let mut node:Validator=serde_json::from_value(json!({"name":"fixture","network":network,"address":"192.0.2.1","ssh_user":"ubuntu","ssh_port":2222,"host_key":"fixture-key","host_binding":validator::host_binding("192.0.2.1","ubuntu",2222,"fixture-key").unwrap(),"data_uuid":"00000000-0000-0000-0000-000000000001","wallet":format!("0x{}","1".repeat(40)),"creation":"2".repeat(32),"signer_ref":"","upstreams_ref":format!("op://{}/{}/credential","v".repeat(26),"u".repeat(26)),"desired":"observing","management_allow":[],"last_run":"","last_result":"custody-pending"})).unwrap();
        node.id = Some("i".repeat(26));
        node.item_version = 1;
        node
    }
    #[test]
    fn allowlist_selector_matches_the_exact_public_native_abi() {
        assert_eq!(
            &erpc_wallet::evm::keccak256(b"isValidator(address)")[..4],
            &[0xfa, 0xcd, 0x74, 0x3b]
        );
    }
    #[test]
    fn both_parsed_networks_keep_explicit_activation_and_provider_before_wallet_or_history() {
        use erpc_core::chain::{Chain, Role};
        use std::cell::RefCell;
        for network in [Network::Mainnet, Network::Testnet] {
            let tree = crate::tree::command(Role::Validator, Chain::Robinhood);
            tree.clone().debug_assert();
            for (flags, old, wanted) in [
                (vec![], Phase::Observing, Phase::Observing),
                (vec!["--activate-signer"], Phase::Observing, Phase::Active),
                (vec!["--restore-custody"], Phase::Active, Phase::Active),
            ] {
                let mut arguments = vec!["validator", "deploy", "--network", network.name()];
                arguments.extend(flags);
                let parsed = tree.clone().try_get_matches_from(arguments).unwrap();
                let args = parsed.subcommand_matches("deploy").unwrap();
                assert_eq!(super::network(args).unwrap(), network);
                assert_eq!(desired_phase(old, args).unwrap(), wanted);
                let events = RefCell::new(Vec::new());
                deployment_order(
                    wanted,
                    || {
                        events.borrow_mut().push("wallet");
                        Ok(())
                    },
                    || {
                        events.borrow_mut().push("history");
                        Ok(())
                    },
                    || {
                        events.borrow_mut().push("provider");
                        Ok(())
                    },
                    || {
                        events.borrow_mut().push("start");
                        Ok("fixture".into())
                    },
                )
                .unwrap();
                assert_eq!(
                    *events.borrow(),
                    if wanted == Phase::Active {
                        vec!["provider", "wallet", "history", "start"]
                    } else {
                        vec!["provider", "history", "start"]
                    }
                );
            }
            let node = fixture(network);
            assert_eq!(
                request(&node, "status").unwrap()["contract"]["network"],
                network.name()
            );
            assert_eq!(
                account_binding(&node, "fixture-vault").unwrap().network,
                network.name()
            );
        }
        let tree = crate::tree::command(Role::Validator, Chain::Robinhood);
        for args in [
            ["deploy", "--strategy", "MakeNodes"],
            ["init", "--import-used-key", "fixture"],
            ["destroy", "--purge-data", "yes"],
        ] {
            assert!(
                tree.clone()
                    .try_get_matches_from(std::iter::once("validator").chain(args))
                    .is_err()
            );
        }
    }
    #[test]
    fn refused_original_parent_or_wallet_never_reaches_native_preparation() {
        assert!(
            deployment_order(
                Phase::Active,
                || panic!("wallet"),
                || panic!("prepare"),
                || Err("inert refused parent".into()),
                || panic!("start")
            )
            .is_err()
        );
        assert!(
            stage_wallet_with::<()>(
                || Err("inert foreign custody".into()),
                || panic!("observe"),
                || panic!("backup"),
                |(), _| panic!("deliver")
            )
            .is_err()
        );
    }
}
