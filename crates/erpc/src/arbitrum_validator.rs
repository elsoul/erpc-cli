// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Original Arbitrum One assertion-validator CLI orchestration.
use crate::{
    arbitrum_bundle as bundle, arbitrum_custody as custody,
    commands::Outcome,
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, arbitrum_validator::Validator};
use erpc_chain_nitro::validator::{self, Phase};
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
fn open(args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        "mainnet",
        one(args, "vault"),
        "erpc v --chain arbitrum init --network mainnet --vault <vault>",
    )?;
    Ok((
        node_common::store(&node_common::op_runner()?, &vault, "arbitrum", "mainnet")?,
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
            &RemoteCommand::NitroValidatorControl,
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
    path: &str,
    say: &Say,
) -> Result<(erpc_ssh::RunId, String), String> {
    let built = bundle::build(inventory)?;
    let run = erpc_ops::run::start(session, &built, path).map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Retry using the original Arbitrum validator inventory; never replace its wallet",
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
    request: &Value,
    say: &Say,
) -> Result<(erpc_ssh::RunId, String, Value), String> {
    let inventory = bundle::control_inventory(name, request)?;
    let (run, digest) = play(session, target, &inventory, bundle::CONTROL_PLAY, say)?;
    let output = session
        .run(&RemoteCommand::NitroValidatorResult(run.clone()), None)
        .map_err(|_| "completed validator public result could not be authenticated")?;
    let result = validator::public_result(
        &output.stdout,
        run.as_str(),
        &digest,
        &bundle::helpers()?,
        request,
    )?;
    Ok((run, digest, result))
}

fn carried(
    session: &Session,
    target: &Target,
    name: &str,
    request: &Value,
    say: &Say,
) -> Result<Value, String> {
    carried_proof(session, target, name, request, say).map(|(_, _, result)| result)
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
            let (run, bundle, result) = carried_proof(session, target, &node.name, &public, say)?;
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
                helpers: bundle::helpers()?,
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
                    &RemoteCommand::NitroValidatorStage {
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
    let (run, bundle, result) = carried_proof(session, target, &node.name, &public, say)?;
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
            &RemoteCommand::NitroValidatorStage {
                run,
                bundle,
                helpers: bundle::helpers()?,
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
        network: "mainnet",
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
        return Err("Arbitrum assertion validators require dedicated Ubuntu24.04 x86-64, 128GB RAM, 16 cores, sudo and an observed SSH listener".into());
    }
    Ok(())
}
fn initialize(args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let (store, vault) = open(args)?;
    let name = one(args, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|_| "invalid inventory name")?;
    let existing = store
        .arbitrum_validators()
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
        carried(&session, &target, name, &json!({"action":"preflight"}), say)?
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
                .update_arbitrum_validator(node)
                .map_err(|e| e.to_string())
        },
    )?;
    let result = carried(&session, &target, name, &request(&node, "init")?, say)?;
    node.last_result = "initialized; observing deployment required".into();
    store
        .update_arbitrum_validator(&node)
        .map_err(|e| e.to_string())?;
    node_common::save_vault("mainnet", &vault)?;
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
            .add_arbitrum_validator(&node)
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
                robinhood: false,
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
fn upgrade_volume_authority(args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let original = crate::arbitrum_volume::read(
        args.get_one::<std::path::PathBuf>("original-root-volume-record")
            .map(std::path::PathBuf::as_path),
    )?;
    let (store, _) = open(args)?;
    let name = one(args, "name").ok_or("original volume upgrade requires --name")?;
    let node = store
        .arbitrum_validators()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|node| node.name == name)
        .ok_or("original validator is not initialized")?;
    let query =
        crate::arbitrum_volume::request(&node.contract().map_err(|e| e.to_string())?, &original)?;
    node_common::go_ahead(flag(args, "yes"), "no original validator changed")
        .map_err(|e| e.to_string())?;
    let target = owned_target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    // Always use the exact sealed carried source. No wallet read, inventory
    // rewrite, native activation or deployment follows this stopped upgrade.
    carried(&session, &target, name, &query, say)
}

fn operation(verb: &str, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    if verb == "init" && flag(args, "upgrade-volume-authority") {
        return upgrade_volume_authority(args, say);
    }
    if verb == "init" {
        return initialize(args, say);
    }
    let (store, vault) = open(args)?;
    let nodes = store.arbitrum_validators().map_err(|e| e.to_string())?;
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
            json!({"name":node.name,"network":"mainnet","role":"assertion-validator","phase":node.desired,"change":one(args,"change").unwrap_or("deploy"),"version":validator::VERSION,"commit":validator::COMMIT,"helpers_sha256":bundle::helpers()?,"financial_registration":"external funding, wrap and allowance; explicit active mode uses original native assertion signer","data_and_history_preserved":true}),
        );
    }
    let target = owned_target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if verb == "logs" {
        let owner = request(&node, "metadata")?;
        if control(&session, &owner).is_err() {
            carried(&session, &target, name, &owner, say)?;
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
        return carried(&session, &target, name, &request(&node, action)?, say);
    }
    node_common::go_ahead(flag(args, "yes"), "no original validator changed")
        .map_err(|e| e.to_string())?;
    if ["stop", "destroy", "start", "restart"].contains(&verb) {
        let query = request(&node, verb)?;
        let result = match control(&session, &query) {
            Ok(value) => value,
            Err(_) => carried(&session, &target, name, &query, say)?,
        };
        node.last_result = format!("{verb} requested; readiness observed separately");
        store
            .update_arbitrum_validator(&node)
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
        .update_arbitrum_validator(&node)
        .map_err(|e| e.to_string())?;
    node.last_run = deploy(&session, &target, &node, args, &vault, say)?;
    node.last_result = format!("{verb} submitted; readiness observed separately");
    store
        .update_arbitrum_validator(&node)
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
    if network != Some("mainnet") {
        return Outcome::Usage("assertion validators support explicit Arbitrum One mainnet only; Nova, Sepolia and Robinhood admission are not implemented".into());
    }
    if verb != "list"
        && one(args, "name").is_none_or(|name| erpc_chain::inventory::check_name(name).is_err())
    {
        return Outcome::Usage(
            "Arbitrum validator operation requires a valid --name before inventory access".into(),
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
    use std::cell::RefCell;
    pub(crate) fn fixture() -> Validator {
        let mut node:Validator=serde_json::from_value(json!({"name":"fixture","address":"192.0.2.1","ssh_user":"ubuntu","ssh_port":2222,"host_key":"fixture-key","host_binding":validator::host_binding("192.0.2.1","ubuntu",2222,"fixture-key").unwrap(),"data_uuid":"00000000-0000-0000-0000-000000000001","wallet":format!("0x{}","1".repeat(40)),"creation":"2".repeat(32),"signer_ref":"","upstreams_ref":format!("op://{}/{}/credential","v".repeat(26),"u".repeat(26)),"desired":"observing","management_allow":[],"last_run":"","last_result":"custody-pending"})).unwrap();
        node.id = Some("i".repeat(26));
        node.item_version = 1;
        node
    }
    #[cfg(unix)]
    #[test]
    fn actual_wallet_authorization_request_reaches_carried_play_dispatch_and_private_custody() {
        let node = fixture();
        let query = super::wallet_stage_request(&node, &"e".repeat(32), false).unwrap();
        actual_public_stage(&node, &query);
    }

    #[cfg(unix)]
    #[test]
    fn actual_provider_authorization_request_reaches_carried_play_and_private_recovery() {
        let node = fixture();
        let query = super::provider_stage_request(&node, &"e".repeat(32)).unwrap();
        actual_public_stage(&node, &query);
    }

    #[cfg(unix)]
    fn actual_public_stage(node: &Validator, query: &Value) {
        use std::io::Write as _;
        let inventory = super::bundle::control_inventory(&node.name, query).unwrap();
        let built = super::bundle::build(&inventory).unwrap();
        let python = std::env::var("ERPC_TEST_ANSIBLE_PYTHON").unwrap_or_else(|_| "python3".into());
        let mut command = std::process::Command::new(python);
        command.args(["-I", "-B"]).arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/arbitrum_wallet_stage_play.py"),
        );
        if std::env::var_os("ERPC_TEST_ANSIBLE_PYTHON").is_some() {
            command.env("ERPC_REQUIRE_PINNED_ANSIBLE", "1");
        }
        let mut child = command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&built.bytes).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let raw: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let validated = super::validator::public_result(
            &result.stdout,
            raw["run"].as_str().unwrap(),
            &built.sha256,
            &super::bundle::helpers().unwrap(),
            query,
        )
        .unwrap();
        assert_eq!(validated["contract"], query["contract"]);
        assert_eq!(validated["requires_import"], true);
    }

    #[test]
    fn parsed_deploy_orders_public_qualification_then_original_backup_and_cipher_before_preparation()
     {
        use erpc_core::chain::{Chain, Role};
        use std::cell::RefCell;
        for (extra, current, active, restore) in [
            (vec![], Phase::Observing, false, false),
            (vec!["--activate-signer"], Phase::Observing, true, false),
            (vec!["--restore-custody"], Phase::Active, true, true),
        ] {
            let mut arguments = vec!["validator", "deploy", "--network", "mainnet"];
            arguments.extend(extra);
            let parsed = crate::tree::command(Role::Validator, Chain::Arbitrum)
                .try_get_matches_from(arguments)
                .unwrap();
            let args = parsed.subcommand_matches("deploy").unwrap();
            let desired = super::desired_phase(current, args).unwrap();
            assert_eq!(super::flag(args, "restore-custody"), restore);
            let events = RefCell::new(Vec::new());
            let result = super::deployment_order(
                desired,
                || {
                    super::stage_wallet_with(
                        || {
                            events.borrow_mut().push("public original authority");
                            Ok(super::WalletStageDecision::Import(()))
                        },
                        || panic!("healthy original observer must not be bootstrapped"),
                        || {
                            events.borrow_mut().push("original backup read");
                            Ok(super::custody::Original {
                                reference: "public-reference".into(),
                                secret: secrecy::SecretString::from("inert public fixture"),
                            })
                        },
                        |(), _| {
                            events.borrow_mut().push("root-encrypted private import");
                            Ok(())
                        },
                    )
                },
                || {
                    events.borrow_mut().push("prepare observer-drain-history");
                    Ok(())
                },
                || {
                    events.borrow_mut().push("provider import");
                    Ok(())
                },
                || {
                    events.borrow_mut().push("guarded deploy");
                    Ok("public-run".into())
                },
            )
            .unwrap();
            assert_eq!(result, "public-run");
            let expected = if active {
                vec![
                    "provider import",
                    "public original authority",
                    "original backup read",
                    "root-encrypted private import",
                    "prepare observer-drain-history",
                    "guarded deploy",
                ]
            } else {
                vec![
                    "provider import",
                    "prepare observer-drain-history",
                    "guarded deploy",
                ]
            };
            assert_eq!(*events.borrow(), expected);
        }
    }

    #[test]
    fn refused_parent_recovery_never_reaches_wallet_or_prepare() {
        for desired in [Phase::Observing, Phase::Active] {
            assert!(
                super::deployment_order(
                    desired,
                    || panic!("no wallet read after parent refusal"),
                    || panic!("no preparation after parent refusal"),
                    || Err("inert original parent recovery refused".into()),
                    || panic!("no native activation after parent refusal"),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn failed_or_already_ready_custody_does_not_deliver_a_new_private_copy() {
        assert!(
            super::stage_wallet_with::<()>(
                || Err("inert original NSS refusal".into()),
                || panic!("refused host must not bootstrap an observer"),
                || panic!("refused host must not read the concealed backup"),
                |(), _| panic!("no private delivery")
            )
            .is_err()
        );
        assert!(
            super::deployment_order(
                Phase::Active,
                || Err("inert stage refusal".into()),
                || panic!("failed staging must not prepare"),
                || Ok(()),
                || panic!("no activation")
            )
            .is_err()
        );
        super::stage_wallet_with(
            || Ok(super::WalletStageDecision::<()>::Ready),
            || panic!("healthy original must not bootstrap"),
            || {
                Ok(super::custody::Original {
                    reference: "public-reference".into(),
                    secret: secrecy::SecretString::from("inert original backup"),
                })
            },
            |(), _| panic!("healthy original ciphertext is not rewritten"),
        )
        .unwrap();
    }

    #[test]
    fn interrupted_first_activation_bootstraps_only_an_observer_then_reauthorizes_before_backup() {
        use std::cell::{Cell, RefCell};
        let count = Cell::new(0);
        let events = RefCell::new(Vec::new());
        super::stage_wallet_with(
            || {
                events.borrow_mut().push("qualify");
                count.set(count.get() + 1);
                Ok(if count.get() == 1 {
                    super::WalletStageDecision::ObserverRequired
                } else {
                    super::WalletStageDecision::Import(())
                })
            },
            || {
                events.borrow_mut().push("original observer deploy");
                Ok(())
            },
            || {
                events.borrow_mut().push("backup read");
                Ok(super::custody::Original {
                    reference: "public-original-reference".into(),
                    secret: secrecy::SecretString::from("inert original backup"),
                })
            },
            |(), _| {
                events.borrow_mut().push("root cipher import");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            *events.borrow(),
            vec![
                "qualify",
                "original observer deploy",
                "qualify",
                "backup read",
                "root cipher import"
            ]
        );
        assert!(
            super::stage_wallet_with::<()>(
                || Ok(super::WalletStageDecision::ObserverRequired),
                || Ok(()),
                || panic!("unhealthy observer must not read a wallet"),
                |(), _| panic!("no key delivery")
            )
            .is_err()
        );
    }

    #[test]
    fn actual_custody_stage_reserves_before_create_and_retries_never_generate() {
        let steps = RefCell::new(Vec::new());
        let first = custody_stage(
            None,
            || {
                steps.borrow_mut().push("reserve");
                Ok((fixture(), SecretString::from("inert-new-key")))
            },
            |node, fresh| {
                steps.borrow_mut().push("readback");
                assert!(node.id.is_some());
                assert_eq!(fresh.unwrap().expose_secret(), "inert-new-key");
                Ok(custody::Original {
                    reference: "original-reference".into(),
                    secret: SecretString::from("inert-new-key"),
                })
            },
            |node| {
                steps.borrow_mut().push("save-reference");
                Ok(node.clone())
            },
        )
        .unwrap();
        assert_eq!(*steps.borrow(), ["reserve", "readback", "save-reference"]);
        let resumed = custody_stage(
            Some(first),
            || panic!("retry cannot regenerate"),
            |_, fresh| {
                assert!(fresh.is_none());
                Ok(custody::Original {
                    reference: "original-reference".into(),
                    secret: SecretString::from("inert-new-key"),
                })
            },
            |node| Ok(node.clone()),
        )
        .unwrap();
        assert_eq!(resumed.signer_ref, "original-reference");
        assert!(
            custody_stage(
                Some(resumed),
                || panic!("retry cannot regenerate"),
                |_, _| Ok(custody::Original {
                    reference: "replacement".into(),
                    secret: SecretString::from("inert-new-key")
                }),
                |_| panic!("replacement cannot persist")
            )
            .is_err()
        );
    }
    #[test]
    fn ambiguous_reservation_or_missing_original_prevents_host_continuation() {
        let result = custody_stage(
            None,
            || Err("ambiguous public reservation".into()),
            |_, _| panic!("no concealed creation before durable reservation"),
            |_| panic!("no update"),
        );
        assert!(result.is_err());
        let result = custody_stage(
            Some(fixture()),
            || panic!("no retry key generation"),
            |_, fresh| {
                assert!(fresh.is_none());
                Err("original missing after ambiguous create".into())
            },
            |_| panic!("no host-authorizing update"),
        );
        assert!(result.is_err());
    }
    #[test]
    fn private_input_is_only_in_concealed_stdin_and_preserves_nested_contract() {
        let node = fixture();
        let mut public = request(&node, "import-wallet").unwrap();
        public["intent"] = json!("a".repeat(32));
        public["restore"] = json!(true);
        let secret = SecretString::from("inert quoted \" source");
        let encoded = private_body(public.clone(), &secret).unwrap();
        let decoded: Value = serde_json::from_str(encoded.expose_secret()).unwrap();
        assert_eq!(decoded["contract"], public["contract"]);
        assert_eq!(decoded["secret"], secret.expose_secret());
        assert!(!public.to_string().contains("inert quoted"));
        assert!(
            !RemoteCommand::NitroValidatorControl
                .line()
                .contains("inert quoted")
        );
        public["secret"] = json!("already present");
        assert!(private_body(public, &secret).is_err());
    }

    #[test]
    fn supporting_host_requires_observed_port_and_qualified_platform() {
        let mut facts = crate::eth_rpc::Facts {
            os: "ubuntu 24.04".into(),
            machine: "x86_64".into(),
            sudo: true,
            mem_kb: 128 * 1024 * 1024,
            cpus: 16,
            ssh_port: 22,
            ..Default::default()
        };
        assert!(host_check(&facts).is_ok());
        facts.ssh_port = 0;
        assert!(host_check(&facts).is_err());
        facts.ssh_port = 22;
        facts.os = "ubuntu 26.04".into();
        assert!(host_check(&facts).is_err());
    }
}
