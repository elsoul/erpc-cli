// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Complete immutable source profile and public-only Arbitrum run inventories.
use crate::eth_rpc::Facts;
use erpc_chain::inventory::arbitrum_validator::Validator;
use erpc_chain_nitro::validator::{Deployment, helper_files, helpers_digest, request_digest};
use erpc_ops::bundle::{Built, Bundle};
use serde_json::{Value, json};

pub(crate) const CONTROL_PLAY: &str = "validator/ansible/control.yml";
const CONTROL: &str = "/usr/local/lib/erpc/arbitrum-validator/control.py";

fn add(dir: &include_dir::Dir<'_>, bundle: &mut Bundle) -> Result<(), String> {
    for file in dir.files() {
        bundle
            .add(
                file.path()
                    .to_str()
                    .ok_or("invalid validator source path")?,
                file.contents().to_vec(),
            )
            .map_err(|e| e.to_string())?;
    }
    for child in dir.dirs() {
        add(child, bundle)?;
    }
    Ok(())
}
pub(crate) fn helpers() -> Result<String, String> {
    helpers_digest(&helper_files(erpc_chain_rollup::UPSTREAM_PROXY.as_bytes())?)
}
pub(crate) fn build(inventory: &str) -> Result<Built, String> {
    let mut bundle = Bundle::new();
    add(
        erpc_chain_nitro::TEMPLATES
            .get_dir("validator")
            .ok_or("missing validator source")?,
        &mut bundle,
    )?;
    bundle
        .add(
            "validator/node/upstreams.py",
            erpc_chain_rollup::UPSTREAM_PROXY.as_bytes().to_vec(),
        )
        .map_err(|e| e.to_string())?;
    bundle
        .add("rpc-firewall.py", erpc_ops::RPC_FIREWALL.to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add("inventory.yml", inventory.as_bytes().to_vec())
        .map_err(|e| e.to_string())?;
    bundle.finish().map_err(|e| e.to_string())
}
pub(crate) fn control_inventory(name: &str, request: &Value) -> Result<String, String> {
    erpc_chain::inventory::check_name(name).map_err(|_| "invalid validator inventory name")?;
    Ok(
        json!({"all":{"hosts":{name:{"ansible_connection":"local","validator_request":request}}}})
            .to_string(),
    )
}
pub(crate) fn deploy_inventory(
    node: &Validator,
    facts: &Facts,
    intent: &str,
) -> Result<String, String> {
    let mut management = crate::arc_rpc::allow_list("management", &node.management_allow, false)?;
    let mut ipv6 = Vec::new();
    match facts.controller_ip()? {
        std::net::IpAddr::V4(ip) => {
            let value = ip.to_string();
            if !management.contains(&value) {
                management.push(value);
            }
        }
        std::net::IpAddr::V6(ip) => ipv6.push(ip.to_string()),
    }
    if facts.ssh_port == 0 || !erpc_chain_nitro::validator::hex(intent, 32) {
        return Err("missing observed SSH port or original deployment intent".into());
    }
    let config = request_digest(
        &json!({"upstreams_ref":node.upstreams_ref,"management_v4":management,"management_v6":ipv6,"ssh_port":facts.ssh_port}),
    )?;
    let target = Deployment::new(node.desired, helpers()?, config)?;
    let contract = node.contract().map_err(|e| e.to_string())?;
    let vars = json!({"ansible_connection":"local","validator_request":{"action":"prepare","contract":contract,"intent":intent,"target":target},"validator_family":"arbitrum","validator_management_v4":management,"validator_management_v6":ipv6,"validator_ssh_port":facts.ssh_port,"validator_runtime_command":erpc_ssh::python::systemd_command(CONTROL)?,"validator_condition_command":erpc_ssh::python::systemd_condition_command(CONTROL)?});
    Ok(json!({"all":{"hosts":{node.name.clone():vars}}}).to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn actual_bundle_uses_complete_source_profile_and_observed_ssh_port() {
        use std::io::Write;
        let node = crate::arbitrum_validator::tests::fixture();
        let mut facts = Facts {
            controller: "192.0.2.10".into(),
            ssh_port: 22,
            ..Default::default()
        };
        let inventory = deploy_inventory(&node, &facts, &"a".repeat(32)).unwrap();
        let archive = build(&inventory).unwrap();
        let mut child = std::process::Command::new("python3")
            .arg("-B")
            .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/arbitrum_bundle.py"))
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&archive.bytes)
            .unwrap();
        assert!(child.wait().unwrap().success());
        facts.ssh_port = 0;
        assert!(deploy_inventory(&node, &facts, &"a".repeat(32)).is_err());
    }
}
