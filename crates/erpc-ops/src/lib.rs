// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-ops`: Node operation bundles and remote execution for the erpc CLI.
//!
//! A run packs the plays and what erpc adds for the host into a bundle
//! ([`bundle`]), sends it over SSH, and has the node run it itself under a
//! transient systemd unit ([`run`]): Ansible on the node, from hash-pinned
//! wheels, so the operator's machine needs no Python and no Ansible.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod run;

/// Operation-bound RPC firewall controller carried in deployment bundles.
pub const RPC_FIREWALL: &[u8] = include_bytes!("../templates/rpc-firewall.py");

/// Bind a long deployment phase to its freshly confirmed firewall preparation.
///
/// # Errors
/// Refuses invalid receipts or inventories other than one generated host.
pub fn firewall_inventory(
    inventory: &str,
    run: &erpc_ssh::RunId,
    digest: &str,
) -> Result<String, String> {
    erpc_ssh::firewall::FirewallToken::new(run.clone(), digest)?;
    let mut value: serde_json::Value =
        serde_json::from_str(inventory).map_err(|e| e.to_string())?;
    let hosts = value["all"]["hosts"]
        .as_object_mut()
        .ok_or("missing generated hosts")?;
    if hosts.len() != 1 {
        return Err("firewall receipt requires one host".into());
    }
    for host in hosts.values_mut() {
        let vars = host
            .as_object_mut()
            .ok_or("invalid generated host variables")?;
        vars.insert("erpc_fw_confirmed_run".into(), run.as_str().into());
        vars.insert("erpc_fw_confirmed_bundle".into(), digest.into());
    }
    Ok(value.to_string())
}

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-ops";

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn firewall_controller_rejects_stale_and_superseded_confirmations() {
        let status = std::process::Command::new("python3")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/firewall.py"))
            .status()
            .expect("python3 is required for offline controller verification");
        assert!(status.success(), "firewall failure-path regressions failed");
    }

    #[cfg(unix)]
    #[test]
    fn isolated_python_and_sealed_run_failure_paths() {
        let status = std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/python_isolation.py"
            ))
            .status()
            .expect("python3 is required for offline isolation verification");
        assert!(
            status.success(),
            "Python startup/run sealing regression failed"
        );
    }

    #[test]
    fn deployment_receipt_is_in_the_only_host_and_cannot_be_replaced_by_old_inventory() {
        let run = erpc_ssh::RunId::new("r-20261026t120000-abc123").unwrap();
        let digest = "a".repeat(64);
        let input = r#"{"all":{"hosts":{"node":{"keep":true,"erpc_fw_confirmed_run":"stale"}}}}"#;
        let text = super::firewall_inventory(input, &run, &digest).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["all"]["hosts"]["node"]["keep"], true);
        assert_eq!(
            value["all"]["hosts"]["node"]["erpc_fw_confirmed_run"],
            run.as_str()
        );
        assert_eq!(
            value["all"]["hosts"]["node"]["erpc_fw_confirmed_bundle"],
            digest
        );
        for invalid in [
            r#"{"all":{"hosts":{}}}"#,
            r#"{"all":{"hosts":{"a":{},"b":{}}}}"#,
            "{}",
        ] {
            assert!(super::firewall_inventory(invalid, &run, &digest).is_err());
        }
        assert!(super::firewall_inventory(input, &run, "a; command").is_err());
    }

    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
