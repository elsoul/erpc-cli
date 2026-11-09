// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Original Ethereum RPC controller. Public requests travel only on stdin.

/// Exact immutable helper profile, in the digest order of the host publisher.
pub const PROFILE: &[&str] = &[
    "control.py",
    "eth_files.py",
    "eth_state.py",
    "eth_accounts.py",
    "eth_layout.py",
    "eth_namespace.py",
    "eth_process.py",
    "eth_units.py",
    "eth_trust.py",
    "network.yml",
    "eth_migration.py",
    "eth_artifacts.py",
    "eth_source_floor.py",
];

pub(crate) fn control() -> String {
    crate::python::release_command("/usr/local/lib/erpc/ethereum-rpc", "control.py", &[PROFILE])
        .unwrap_or_else(|_| "exit 1".to_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_request_or_current_nss_name_can_redirect_the_original_controller() {
        let command = super::control();
        assert_ne!(command, "exit 1");
        assert!(command.starts_with("sudo -n /usr/bin/python3 -I -c "));
        assert!(command.contains("trusted_release"));
        assert!(command.contains("ethereum-rpc"));
        assert!(!command.contains("systemctl start"));
        assert!(!command.contains("$("));
    }

    #[cfg(unix)]
    #[test]
    fn actual_emitted_ssh_loader_refuses_namespace_drift_before_interpretation() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-eth/tests/authority_entrypoints.py");
        let result = std::process::Command::new("python3")
            .arg("-B")
            .arg(path)
            .arg("--ssh")
            .arg(super::control())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
