// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public follower run bundles. Provider values never enter an Ansible inventory.
use erpc_chain::inventory::rollup::RollupRpc;
use erpc_chain_op::{
    network,
    release::{self, Architecture},
    snapshot::Prepared,
};
use erpc_chain_rollup::profile::{Family, L1, Profile};
use erpc_ops::bundle::{Built, Bundle};
use serde_json::{Value, json};

pub(crate) fn contract(node: &RollupRpc) -> Result<Value, String> {
    let owner = node.id.as_deref().unwrap_or_default();
    if !owner.bytes().all(|b| b.is_ascii_alphanumeric()) || owner.len() > 80 {
        return Err("invalid follower inventory owner".into());
    }
    Ok(
        json!({"owner": owner, "family": node.family, "network": node.network, "history": node.history}),
    )
}

pub(crate) fn request(node: &RollupRpc, action: &str) -> Result<Value, String> {
    Ok(
        json!({"contract": contract(node)?, "action": action, "pair": node.pair, "bootstrap": node.bootstrap}),
    )
}

fn templates(directory: &include_dir::Dir<'_>, bundle: &mut Bundle) -> Result<(), String> {
    for file in directory.files() {
        bundle
            .add(
                file.path().to_str().ok_or("invalid carried path")?,
                file.contents().to_vec(),
            )
            .map_err(|e| e.to_string())?;
    }
    for child in directory.dirs() {
        templates(child, bundle)?;
    }
    Ok(())
}

pub(crate) fn architecture(node: &RollupRpc) -> Result<Architecture, String> {
    serde_json::from_value(node.pair["architecture"].clone())
        .map_err(|_| "stored follower platform is invalid".into())
}

pub(crate) fn vars(
    node: &RollupRpc,
    profile: Profile,
    facts: &crate::eth_rpc::Facts,
    have_manifest: bool,
) -> Result<Value, String> {
    if node.family != profile.family.name() || node.network != profile.network {
        return Err("follower record differs from selected chain/network".into());
    }
    let architecture = architecture(node)?;
    let pair = release::qualify(profile.family, architecture, &node.pair)?;
    let pair_json =
        serde_json::to_value(&pair).map_err(|_| "cannot encode reviewed client pair")?;
    let controller: std::net::IpAddr = facts
        .controller
        .parse()
        .map_err(|_| "cannot identify the SSH controller address")?;
    if facts.ssh_port == 0 {
        return Err("cannot identify the host SSH port".into());
    }
    let target = if architecture == Architecture::Amd64 {
        "x86_64-unknown-linux-gnu"
    } else {
        "aarch64-unknown-linux-gnu"
    };
    let native = [&pair.execution, &pair.consensus].iter().map(|client| json!({
        "program": client.name, "sha256": client.sha256,
        "url": format!("https://github.com/base/base/releases/download/v{}/{name}-v{}-{target}.tar.gz", client.version, client.version, name=client.name)
    })).collect::<Vec<_>>();
    let native = if profile.family == Family::Base {
        native
    } else {
        Vec::new()
    };
    let execution_image = if profile.family == Family::Base {
        String::new()
    } else {
        format!(
            "us-docker.pkg.dev/oplabs-tools-artifacts/images/op-reth@sha256:{}",
            pair.execution.sha256
        )
    };
    let consensus_image = if profile.family == Family::Base {
        String::new()
    } else {
        format!(
            "us-docker.pkg.dev/oplabs-tools-artifacts/images/op-node@sha256:{}",
            pair.consensus.sha256
        )
    };
    Ok(json!({
        "ansible_connection": "local", "op_family": profile.family.name(), "op_request": request(node, "prepare")?,
        "op_pair": pair_json, "op_execution_chain": profile.execution_chain, "op_consensus_chain": profile.consensus_chain,
        "op_l1": match profile.l1 { L1::Mainnet => "mainnet", L1::Sepolia => "sepolia" },
        "op_advertise_ip": node.advertise_ip, "op_controller_ip": controller.to_string(), "op_ssh_port": facts.ssh_port,
        "op_rpc_allow": node.rpc_allow, "op_management_allow": node.management_allow, "op_monitoring_allow": node.monitoring_allow,
        "op_rpc_v6": node.rpc_allow.iter().any(|c| c.contains(':')), "op_monitoring_v6": node.monitoring_allow.iter().any(|c| c.contains(':')),
        "op_execution_image": execution_image, "op_consensus_image": consensus_image, "op_base_artifacts": native,
        "op_base_release": format!("/opt/erpc/{}/releases/{}-{target}", profile.family.name(), pair.execution.version),
        "op_have_manifest": have_manifest,
        "op_identity": {"chain_id": profile.chain_id, "l1_chain_id": if profile.l1 == L1::Mainnet {1} else {11_155_111},
            "anchor": network::anchor(profile).ok_or("unsupported rollup identity")?,
            "execution_chain": profile.execution_chain, "consensus_chain": profile.consensus_chain}
    }))
}

pub(crate) fn build(
    node: &RollupRpc,
    profile: Profile,
    facts: &crate::eth_rpc::Facts,
    prepared: Option<&Prepared>,
    firewall: Option<(&erpc_ssh::RunId, &str)>,
    intent: Option<&str>,
) -> Result<Built, String> {
    let manifest = prepared.and_then(|p| p.manifest.as_ref());
    let mut variables = vars(node, profile, facts, manifest.is_some())?;
    if let Some(intent) = intent {
        variables["op_request"]["intent"] = json!(intent);
    }
    let mut inventory = json!({"all": {"hosts": {node.name.clone(): variables}}}).to_string();
    if let Some((run, digest)) = firewall {
        inventory = erpc_ops::firewall_inventory(&inventory, run, digest)?;
    }
    let mut bundle = Bundle::new();
    templates(&erpc_chain_op::TEMPLATES, &mut bundle)?;
    bundle
        .add("inventory.yml", inventory.into_bytes())
        .map_err(|e| e.to_string())?;
    bundle
        .add("rpc-firewall.py", erpc_ops::RPC_FIREWALL.to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add(
            "rollup-upstreams.py",
            erpc_chain_rollup::UPSTREAM_PROXY.as_bytes().to_vec(),
        )
        .map_err(|e| e.to_string())?;
    if let Some(manifest) = manifest {
        bundle
            .add("base-manifest.json", manifest.clone())
            .map_err(|e| e.to_string())?;
    }
    bundle.finish().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_qualified_bundle_if_requested(bundle: &Built) {
        use std::io::Write as _;
        let Some(python) = std::env::var_os("ERPC_TEST_ANSIBLE_PYTHON") else {
            return;
        };
        let mut child = std::process::Command::new(python)
            .args(["-I", "-B"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/op_release_play.py"
            ))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&bundle.bytes)
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("qualified bundle rendered"));
    }

    #[test]
    fn every_profile_carries_its_own_pair_and_no_provider_reference() {
        for family in [Family::Optimism, Family::Base, Family::Soneium] {
            for network in [
                "mainnet",
                if family == Family::Soneium {
                    "minato"
                } else {
                    "sepolia"
                },
            ] {
                let profile = erpc_chain_rollup::profile::get(family, network).expect("profile");
                for architecture in [Architecture::Amd64, Architecture::Arm64] {
                    let mut node = RollupRpc {
                        id: Some("syntheticowner".into()),
                        name: "follower".into(),
                        family: family.name().into(),
                        network: network.into(),
                        history: "full".into(),
                        advertise_ip: "8.8.8.8".into(),
                        upstream_ref: "never-copy-this-reference-into-a-bundle".into(),
                        pair: serde_json::to_value(release::recommended(family, architecture))
                            .expect("pair"),
                        ..RollupRpc::default()
                    };
                    let facts = crate::eth_rpc::Facts {
                        controller: "192.0.2.3".into(),
                        ssh_port: 2222,
                        ..Default::default()
                    };
                    let public =
                        vars(&node, profile, &facts, false).expect("public bundle variables");
                    assert!(!public.to_string().contains(&node.upstream_ref));
                    assert_eq!(public["op_identity"]["chain_id"], profile.chain_id);
                    assert_eq!(public["op_request"]["contract"]["network"], network);
                    if family == Family::Base {
                        assert_eq!(
                            public["op_base_artifacts"]
                                .as_array()
                                .expect("archives")
                                .len(),
                            2
                        );
                        assert_eq!(public["op_execution_image"], "");
                    } else {
                        assert!(
                            public["op_base_artifacts"]
                                .as_array()
                                .expect("archives")
                                .is_empty()
                        );
                        assert!(
                            public["op_execution_image"]
                                .as_str()
                                .expect("image")
                                .contains("@sha256:")
                        );
                    }
                    let bundle = build(&node, profile, &facts, None, None, None)
                        .expect("carried files form valid bundle");
                    render_qualified_bundle_if_requested(&bundle);
                    node.pair["execution"]["sha256"] = json!("f".repeat(64));
                    assert!(vars(&node, profile, &facts, false).is_err());
                }
            }
        }
    }
    #[test]
    fn original_op_pair_can_reach_resume_without_selecting_unreviewed_artifacts() {
        let stored = json!({"architecture":"amd64", "execution":{
                "name":"op-reth","version":"2.6.1","commit":"e16bffa18420c86dbab693097bc33117f74a5f7d",
                "sha256":"02be1f9c1eef42abadcf7b6440a311ee0d63fe6e7289e784e544d5cb5a4de473","distribution":"op-image"},
                "consensus":{"name":"op-node","version":"1.19.11","commit":"43c071cbff8ad7512581561aa2d43c990544b650",
                "sha256":"dc7a525974c88d0c369bcffaea0f735ca268e64a354507e688328f426c0c363a","distribution":"op-image"}});
        for family in [Family::Optimism, Family::Soneium] {
            let profile = erpc_chain_rollup::profile::get(family, "mainnet").unwrap();
            let mut node = RollupRpc {
                id: Some("syntheticowner".into()),
                name: "follower".into(),
                family: family.name().into(),
                network: "mainnet".into(),
                history: "full".into(),
                pair: stored.clone(),
                ..Default::default()
            };
            let facts = crate::eth_rpc::Facts {
                controller: "192.0.2.3".into(),
                ssh_port: 22,
                ..Default::default()
            };
            let original = vars(&node, profile, &facts, false).unwrap();
            render_qualified_bundle_if_requested(
                &build(&node, profile, &facts, None, None, None).unwrap(),
            );
            assert_eq!(original["op_pair"], stored);
            assert!(
                original["op_execution_image"]
                    .as_str()
                    .unwrap()
                    .ends_with(stored["execution"]["sha256"].as_str().unwrap())
            );
            node.pair =
                serde_json::to_value(release::recommended(family, Architecture::Amd64)).unwrap();
            let next = vars(&node, profile, &facts, false).unwrap();
            assert_eq!(next["op_pair"]["execution"]["version"], "2.8.0");
            assert_ne!(next["op_execution_image"], original["op_execution_image"]);
            node.pair["execution"]["commit"] = json!("0".repeat(40));
            assert!(vars(&node, profile, &facts, false).is_err());
        }
    }
}
