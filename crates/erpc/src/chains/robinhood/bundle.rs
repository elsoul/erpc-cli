// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Complete immutable source profile and public-only Robinhood Defensive run inventories.
use crate::eth_rpc::Facts;
use erpc_chain::inventory::robinhood_validator::Validator;
use erpc_chain_nitro::robinhood_validator::{
    Deployment, Network, helper_files, helpers_digest, request_digest,
};
use erpc_ops::bundle::{Built, Bundle};
use serde_json::{Value, json};

pub(crate) const CONTROL_PLAY: &str = "validator/ansible/control.yml";

pub(crate) fn helpers(network: Network) -> Result<String, String> {
    helpers_digest(&helper_files(
        network,
        erpc_chain_rollup::UPSTREAM_PROXY.as_bytes(),
    )?)
}
pub(crate) fn build(network: Network, inventory: &str) -> Result<Built, String> {
    let mut bundle = Bundle::new();
    let plays = erpc_chain_nitro::TEMPLATES
        .get_dir("validator/ansible")
        .ok_or("missing reviewed validator plays")?;
    for file in plays.files() {
        let name = file
            .path()
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or("invalid validator play path")?;
        if [
            "nitro.service.j2",
            "upstreams.service.j2",
            "firewall.service.j2",
        ]
        .contains(&name)
        {
            continue;
        }
        bundle
            .add(
                &format!("validator/ansible/{name}"),
                file.contents().to_vec(),
            )
            .map_err(|e| e.to_string())?;
    }
    for name in [
        "nitro.service.j2",
        "upstreams.service.j2",
        "firewall.service.j2",
    ] {
        let path = format!("robinhood-validator/ansible/{}/{name}", network.name());
        let file = erpc_chain_nitro::TEMPLATES
            .get_file(path)
            .ok_or("missing fixed-network validator unit")?;
        bundle
            .add(
                &format!("validator/ansible/{name}"),
                file.contents().to_vec(),
            )
            .map_err(|e| e.to_string())?;
    }
    for (name, contents) in helper_files(network, erpc_chain_rollup::UPSTREAM_PROXY.as_bytes())? {
        bundle
            .add(&format!("validator/node/{name}"), contents)
            .map_err(|e| e.to_string())?;
    }
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
    if facts.ssh_port == 0 || !erpc_chain_nitro::robinhood_validator::hex(intent, 32) {
        return Err("missing observed SSH port or original deployment intent".into());
    }
    let config = request_digest(
        &json!({"upstreams_ref":node.upstreams_ref,"management_v4":management,"management_v6":ipv6,"ssh_port":facts.ssh_port}),
    )?;
    let target = Deployment::new(node.desired, helpers(node.network)?, config)?;
    let contract = node.contract().map_err(|e| e.to_string())?;
    let control = format!(
        "/usr/local/lib/erpc/{}/control.py",
        node.network.namespace()
    );
    let vars = json!({"ansible_connection":"local","validator_request":{"action":"prepare","contract":contract,"intent":intent,"target":target},"validator_family":"robinhood","validator_management_v4":management,"validator_management_v6":ipv6,"validator_ssh_port":facts.ssh_port,"validator_runtime_command":erpc_ssh::python::systemd_command(&control)?,"validator_condition_command":erpc_ssh::python::systemd_condition_command(&control)?});
    Ok(json!({"all":{"hosts":{node.name.clone():vars}}}).to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn compiled_network_bundles_render_and_reach_original_initialization() {
        use std::io::Write as _;
        let mut facts = Facts {
            controller: "192.0.2.10".into(),
            ssh_port: 22,
            ..Default::default()
        };
        for network in [Network::Mainnet, Network::Testnet] {
            let node = crate::robinhood_validator::tests::fixture(network);
            let inventory = deploy_inventory(&node, &facts, &"a".repeat(32)).unwrap();
            let built = build(network, &inventory).unwrap();
            let python =
                std::env::var("ERPC_TEST_ANSIBLE_PYTHON").unwrap_or_else(|_| "python3".into());
            let mut command = std::process::Command::new(python);
            command.args(["-I", "-B"]).arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/robinhood_bundle.py"),
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
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            facts.ssh_port = 0;
            assert!(deploy_inventory(&node, &facts, &"a".repeat(32)).is_err());
            facts.ssh_port = 22;
        }
    }
}
