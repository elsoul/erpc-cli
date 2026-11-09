// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Resume the original build, confirm ingress, then enter one fenced cutover.
use crate::{
    error::CliError,
    node_common::{self, Say},
    solana_native as node,
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{
    Store,
    solana_native::{NativeConfig, NativeHost},
};
use erpc_chain_solana_native as native;
use erpc_ssh::{
    RemoteCommand, Session, Target,
    solana_native::{Command, Revision},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use zeroize::Zeroizing;

trait Driver {
    fn invoke(&mut self, action: &str, fields: Value) -> Result<Value, String>;
    fn firewall(&mut self, intent: &str) -> Result<Value, String>;
    fn import(&mut self, intent: &str) -> Result<(), String>;
    fn wait(&mut self, phase: &str, attempt: u32);
}

fn phases(
    driver: &mut impl Driver,
    intent: &str,
    reuse: bool,
    activation: bool,
) -> Result<Value, String> {
    if !reuse {
        driver.invoke("toolchain", json!({"intent":intent}))?;
        driver.invoke("build-phase", json!({"intent":intent,"phase":"prepare"}))?;
        for phase in ["fetch", "compile"] {
            let mut complete = false;
            for attempt in 0..2160 {
                let result =
                    driver.invoke("build-phase", json!({"intent":intent,"phase":phase}))?;
                match result["state"].as_str() {
                    Some("complete") => {
                        complete = true;
                        break;
                    }
                    Some("submitted" | "queued" | "running") => driver.wait(phase, attempt),
                    _ => {
                        return Err(format!(
                            "native {phase} failed; inspect its journal and explicitly abandon the failed build before replacing it"
                        ));
                    }
                }
            }
            if !complete {
                return Err(format!(
                    "native {phase} is still running; repeat the same command to resume"
                ));
            }
        }
        driver.invoke("build-phase", json!({"intent":intent,"phase":"publish"}))?;
    }
    let receipt = driver.firewall(intent)?;
    driver.invoke("begin-runtime", json!({"intent":intent}))?;
    driver.import(intent)?;
    if activation {
        driver.invoke("prove-validator", json!({"intent":intent}))?;
    }
    driver.invoke(
        "install-runtime",
        json!({"intent":intent,"firewall":receipt}),
    )?;
    driver.invoke("activate-runtime", json!({"intent":intent}))
}

fn intent(
    before: &Value,
    operation: &str,
    mode: &str,
    identity: &str,
    network: &str,
) -> Result<String, String> {
    if before["recovery"]["phase"] == "prepared" {
        return Err("complete --recover-cutover with the recorded recovery intent before starting a fresh deployment".into());
    }
    let pending = &before["pending"];
    if !pending.is_null() {
        let catalog = native::catalog()?;
        let source = catalog
            .networks
            .get(network)
            .ok_or("native network is not qualified")?;
        if pending["current"] != true
            || pending["action"] != operation
            || pending["target"]["mode"] != mode
            || pending["target"]["identity"] != identity
            || pending["target"]["network"] != network
            || pending["target"]["version"] != source.version
            || pending["target"]["commit"] != source.commit
            || pending["target"]["helper_revision"] != native::helper_revision()?
        {
            return Err(if before["cutover"] == true {
                "native cutover was interrupted or canceled; use --recover-cutover <original intent> to stop and archive it before a fresh deployment".into()
            } else {
                "pending native deployment differs or was cancelled; resume its original CLI/configuration or explicitly --abandon-build before replacing it".into()
            });
        }
        let value = pending["intent"]
            .as_str()
            .ok_or("invalid pending native operation identity")?;
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid pending native operation identity".into());
        }
        return Ok(value.into());
    }
    if before["cutover"] != false {
        return Err(
            "native cutover is incomplete; restore its original deployment authority".into(),
        );
    }
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "cannot create native deployment intent")?;
    Ok(bytes.iter().fold(String::new(), |mut value, byte| {
        let _ = write!(value, "{byte:02x}");
        value
    }))
}

struct Remote<'a> {
    session: &'a Session,
    target: &'a Target,
    node: &'a NativeHost,
    config: &'a NativeConfig,
    revision: Revision,
    mode: &'a str,
    identity: &'a str,
    restore: bool,
    say: &'a Say,
}

impl Remote<'_> {
    fn body(&self, action: &str, mut fields: Value) -> Result<Value, String> {
        let fields = fields
            .as_object_mut()
            .ok_or("invalid native request fields")?;
        fields.insert("action".into(), json!(action));
        fields.insert("contract".into(), json!(self.node.contract));
        Ok(Value::Object(fields.clone()))
    }
    fn access(&self) -> Result<Value, String> {
        let result = self
            .session
            .run(&RemoteCommand::SolanaNative(Command::Facts), None)
            .map_err(|_| "cannot inspect the current native SSH connection")?;
        let text = std::str::from_utf8(&result.stdout).map_err(|_| "invalid native SSH facts")?;
        let facts = crate::eth_rpc::Facts::parse(text);
        let controller: std::net::IpAddr = facts
            .controller
            .parse()
            .map_err(|_| "SSH controller address is unavailable")?;
        if !facts.sudo || facts.ssh_port == 0 {
            return Err("native management login or SSH listener is unavailable".into());
        }
        Ok(
            json!({"controller":controller.to_string(),"ssh_port":facts.ssh_port,
            "management":self.config.management_allow,"rpc":self.config.rpc_allow}),
        )
    }
}
impl Driver for Remote<'_> {
    fn invoke(&mut self, action: &str, fields: Value) -> Result<Value, String> {
        node::request(
            self.session,
            Command::Control(self.revision.clone()),
            &self.body(action, fields)?,
        )
    }
    fn firewall(&mut self, intent: &str) -> Result<Value, String> {
        self.say
            .line("native ingress: applying the requested access policy");
        let body = self.body(
            "firewall-prepare",
            json!({"intent":intent,"access":self.access()?,
            "source_sha256":format!("{:x}",Sha256::digest(erpc_ops::RPC_FIREWALL))}),
        )?;
        let bundle = node::request_bundle(self.node, &body)?;
        let run = erpc_ops::run::start(self.session, &bundle, "ansible/solana-native/firewall.yml")
            .map_err(|e| e.to_string())?;
        let result = node_common::follow(
            self.target,
            &run,
            "Resume the same native deployment after inspecting its firewall run",
            self.say,
        )?;
        if !result.ok() {
            return Err(format!(
                "native firewall operation failed (run {})",
                run.as_str()
            ));
        }
        let fresh = Session::open(self.target)
            .map_err(|_| "new SSH connection could not confirm native ingress")?;
        let response = node::request(
            &fresh,
            Command::Control(self.revision.clone()),
            &self.body(
                "firewall-confirm",
                json!({"intent":intent,"run":run.as_str(),"bundle":bundle.sha256}),
            )?,
        )?;
        if response["firewall_confirmed"] != true
            || response["run"] != run.as_str()
            || response["bundle"] != bundle.sha256
        {
            return Err(
                "native firewall confirmation did not match the submitted operation".into(),
            );
        }
        Ok(json!({"run":run.as_str(),"bundle":bundle.sha256}))
    }
    fn import(&mut self, intent: &str) -> Result<(), String> {
        let reference = if self.mode == "sync" {
            self.config
                .sync_ref
                .as_deref()
                .ok_or("synchronization identity reference missing")?
        } else {
            self.config.identity_ref.as_str()
        };
        let reference = erpc_secret::OpRef::parse(reference)
            .map_err(|_| "invalid native identity reference")?;
        let secret =
            crate::rollup_credentials::read_concealed(&node_common::op_runner()?, &reference)?;
        let header = self
            .body(
                "import-identity",
                json!({"intent":intent,"role":self.mode,
            "expected":self.identity,"restore":self.restore}),
            )?
            .to_string();
        let mut body = Zeroizing::new(Vec::new());
        body.extend_from_slice(
            header
                .strip_suffix('}')
                .ok_or("invalid native credential header")?
                .as_bytes(),
        );
        body.extend_from_slice(b",\"key_file\":");
        serde_json::to_writer(&mut *body, secret.expose_secret())
            .map_err(|_| "cannot encode native credential request")?;
        body.push(b'}');
        let output = self
            .session
            .run(
                &RemoteCommand::SolanaNative(Command::Control(self.revision.clone())),
                Some(&body),
            )
            .map_err(|_| "native original identity import or restoration failed")?;
        let raw = SecretString::from(
            String::from_utf8(output.stdout).map_err(|_| "invalid native custody response")?,
        );
        let response: Value = serde_json::from_str(raw.expose_secret())
            .map_err(|_| "invalid native custody response")?;
        if response["identity"] != self.identity
            || response["role"] != self.mode
            || response["custody_verified"] != true
        {
            return Err(
                "native custody receipt differs from the selected original identity".into(),
            );
        }
        Ok(())
    }
    fn wait(&mut self, phase: &str, attempt: u32) {
        if attempt.is_multiple_of(6) {
            self.say.line(&format!("native {phase}: working; interruption leaves this build available for explicit resume"));
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

fn recover_cutover(
    node: &NativeHost,
    session: &Session,
    target: &Target,
    intent: &str,
    args: &ArgMatches,
    say: &Say,
) -> Result<Value, CliError> {
    if intent.len() != 32
        || !intent
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("cutover recovery requires its original 32-character intent from plan or deployment output".into());
    }
    if ["rpc-allow", "management-allow"]
        .iter()
        .any(|key| node::access_values(args, key).is_some())
    {
        return Err(
            "cutover recovery is stop/archive-only; apply access changes in a later deployment"
                .into(),
        );
    }
    node::confirm(args, "native cutover recovery was not confirmed")?;
    let built = node::request_bundle(
        node,
        &json!({"action":"recover-cutover","contract":node.contract,"intent":intent}),
    )?;
    let run = erpc_ops::run::start(session, &built, "ansible/solana-native/recover.yml")
        .map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Repeat recovery with the same original cutover intent",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "native cutover recovery failed (run {}); original data retained",
            run.as_str()
        )
        .into());
    }
    Ok(
        json!({"recovered":true,"intent":intent,"runtime_started":false,"data_preserved":true,"run":run.as_str()}),
    )
}

pub(crate) fn runtime_selection(
    node: &NativeHost,
    config: &NativeConfig,
    observed: &Value,
    activation: bool,
) -> Result<(&'static str, String), String> {
    let mode = if node.contract.is_rpc() {
        if activation {
            return Err("RPC hosts cannot activate a voting identity".into());
        }
        "rpc"
    } else if activation || observed["approved"]["target"]["mode"] == "validator" {
        "validator"
    } else {
        "sync"
    };
    let identity = if mode == "sync" {
        config
            .sync_identity
            .clone()
            .ok_or("synchronization identity public key missing")?
    } else {
        node.contract.identity_account.clone()
    };
    Ok((mode, identity))
}

pub(crate) fn run(
    verb: &str,
    args: &ArgMatches,
    original: &NativeHost,
    store: &Store<OpCli>,
    say: &Say,
) -> Result<Value, CliError> {
    let mut node = original.clone();
    let activation = node::flag(args, "activate-validator");
    if activation && (node.contract.is_rpc() || verb != "deploy") {
        return Err("explicit voting activation requires a native validator deployment".into());
    }
    let mut config = store
        .solana_native_config(&node)
        .map_err(|e| e.to_string())?;
    if verb == "update-config" {
        for (key, list) in [
            ("rpc-allow", &mut config.rpc_allow),
            ("management-allow", &mut config.management_allow),
        ] {
            if let Some(values) = node::access_values(args, key) {
                *list = values;
            }
        }
        config.validate(&node.contract).map_err(|e| e.to_string())?;
    }
    let target = node::target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if let Some(intent) = node::one(args, "recover-cutover") {
        return recover_cutover(&node, &session, &target, intent, args, say);
    }
    let before = node::control(&session, &node, "deployment")?;
    node::confirm(args, "native deployment was not confirmed")?;
    if node::flag(args, "abandon-build") {
        let intent = before["pending"]["intent"]
            .as_str()
            .ok_or("there is no native build to abandon")?;
        let observed = node::probe(&session, &node)?;
        let revision = Revision::new(
            observed["helper_revision"]
                .as_str()
                .ok_or("native preparation is incomplete")?,
        )?;
        return Ok(node::request(
            &session,
            Command::Control(revision),
            &json!({"action":"abandon-build","contract":node.contract,"intent":intent}),
        )?);
    }
    let (mode, identity) = runtime_selection(&node, &config, &before, activation)?;
    let operation = if activation {
        "activate-validator"
    } else {
        verb
    };
    let intent = intent(&before, operation, mode, &identity, &node.contract.network)?;
    let registration = if activation {
        Some(registration(&node, &config, args)?)
    } else {
        None
    };
    if verb == "update-config" {
        node = store
            .update_solana_native_config(&node, &config)
            .map_err(|e| e.to_string())?;
    }
    node::play(&node, &session, &target, false, say)?;
    let observed = node::probe(&session, &node)?;
    let expected = native::helper_revision()?;
    if observed["helper_revision"] != expected {
        return Err("installed native helpers differ from this CLI".into());
    }
    let mut remote = Remote {
        session: &session,
        target: &target,
        node: &node,
        config: &config,
        revision: Revision::new(&expected)?,
        mode,
        identity: &identity,
        restore: node::flag(args, "restore-custody"),
        say,
    };
    if let Some(registration) = registration {
        let authorized = remote.invoke(
            "authorize-validator",
            json!({"intent":intent,"registration":registration,"exclusive_identity":true}),
        )?;
        if authorized["runtime_published"] == true {
            return Ok(remote.invoke("activate-runtime", json!({"intent":intent}))?);
        }
    } else {
        remote.invoke(
            "authorize-build",
            json!({"intent":intent,"operation":verb,"mode":mode,"identity":identity}),
        )?;
    }
    Ok(phases(
        &mut remote,
        &intent,
        activation || verb == "update-config",
        activation,
    )?)
}

pub(crate) fn registration(
    node: &NativeHost,
    config: &NativeConfig,
    args: &ArgMatches,
) -> Result<Value, String> {
    if node.contract.is_rpc() || !node::flag(args, "exclusive-identity") {
        return Err("voting activation requires the original validator host and explicit exclusive identity confirmation".into());
    }
    let value = erpc_chain_solana::validator_profile::Registration {
        network: node.contract.network.clone(),
        identity: node.contract.identity_account.clone(),
        vote_account: node
            .contract
            .vote_account
            .clone()
            .ok_or("original vote account is missing")?,
        withdrawer: node
            .contract
            .authority_account
            .clone()
            .ok_or("original external withdrawer is missing")?,
        bls: node::one(args, "bls-public")
            .ok_or("activation requires --bls-public")?
            .into(),
        commission: config.commission.ok_or("original commission is missing")?,
    };
    value.validate()?;
    serde_json::to_value(value).map_err(|_| "cannot encode public registration".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Fixture {
        calls: Vec<String>,
        fail: Option<&'static str>,
        polls: u8,
    }
    impl Driver for Fixture {
        fn invoke(&mut self, action: &str, fields: Value) -> Result<Value, String> {
            let key = if action == "build-phase" {
                fields["phase"].as_str().unwrap()
            } else {
                action
            };
            self.calls.push(key.into());
            if self.fail == Some(key) {
                return Err("inert failure".into());
            }
            if key == "compile" && self.polls == 0 {
                self.polls += 1;
                return Ok(json!({"state":"running"}));
            }
            Ok(json!({"state":"complete","runtime_started":action=="activate-runtime"}))
        }
        fn firewall(&mut self, _: &str) -> Result<Value, String> {
            self.invoke("firewall", json!({}))
        }
        fn import(&mut self, _: &str) -> Result<(), String> {
            self.invoke("import", json!({})).map(|_| ())
        }
        fn wait(&mut self, _: &str, _: u32) {
            self.calls.push("wait".into());
        }
    }
    #[test]
    fn source_build_and_firewall_precede_any_cutover_or_key_read() {
        let mut driver = Fixture::default();
        assert_eq!(
            phases(&mut driver, &"a".repeat(32), false, false).unwrap()["runtime_started"],
            true
        );
        assert_eq!(
            driver.calls,
            [
                "toolchain",
                "prepare",
                "fetch",
                "compile",
                "wait",
                "compile",
                "publish",
                "firewall",
                "begin-runtime",
                "import",
                "install-runtime",
                "activate-runtime"
            ]
        );
        for failed in [
            "toolchain",
            "fetch",
            "compile",
            "publish",
            "firewall",
            "begin-runtime",
            "import",
            "install-runtime",
        ] {
            let mut driver = Fixture {
                fail: Some(failed),
                ..Fixture::default()
            };
            assert!(phases(&mut driver, &"a".repeat(32), false, false).is_err());
            assert_eq!(driver.calls.last().unwrap(), failed);
            assert!(!driver.calls.iter().any(|v| v == "activate-runtime"));
        }
    }
    #[test]
    fn configuration_update_reuses_verified_build() {
        let mut driver = Fixture::default();
        phases(&mut driver, &"a".repeat(32), true, false).unwrap();
        assert_eq!(
            driver.calls,
            [
                "firewall",
                "begin-runtime",
                "import",
                "install-runtime",
                "activate-runtime"
            ]
        );
    }
    #[test]
    fn voting_activation_proves_original_key_before_unit_install_and_never_compiles() {
        let mut driver = Fixture::default();
        phases(&mut driver, &"a".repeat(32), true, true).unwrap();
        assert_eq!(
            driver.calls,
            [
                "firewall",
                "begin-runtime",
                "import",
                "prove-validator",
                "install-runtime",
                "activate-runtime"
            ]
        );
        let mut driver = Fixture {
            fail: Some("prove-validator"),
            ..Fixture::default()
        };
        assert!(phases(&mut driver, &"a".repeat(32), true, true).is_err());
        assert_eq!(
            driver.calls.last().map(String::as_str),
            Some("prove-validator")
        );
    }
}
