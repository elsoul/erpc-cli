// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed remote Ethereum validator commands. Custody is accepted only on stdin.

/// Exact immutable dedicated-validator helper profile.
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
    "eth_validator_control.py",
    "eth_validator_custody.py",
    "eth_validator_history.py",
    "eth_validator_native.py",
    "eth_validator_runtime.py",
    "eth_validator_tls.py",
    "eth_validator_transport.py",
    "eth_validator_units.py",
    "eth_validator_peer.py",
    "eth_validator_migration.py",
    "eth_validator_engine.py",
    "eth_validator_health.py",
    "eth_validator_keys.py",
];

/// Authenticate the original protected release before interpreting any helper.
pub(crate) fn control() -> String {
    crate::python::release_command(
        "/usr/local/lib/erpc/ethereum-validator",
        "eth_validator_control.py",
        &[PROFILE],
    )
    .unwrap_or_else(|_| "exit 1".into())
}

/// Journal request, with no user-controlled unit name or signing material.
pub(crate) fn logs(lines: u32, follow: bool) -> String {
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} -u erpc-eth-validator -u erpc-eth-beacon -u erpc-eth-execution{}",
        if follow { " -f" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn actual_validator_ssh_loader_authenticates_before_interpretation() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-eth/tests/authority_entrypoints.py");
        let result = std::process::Command::new("python3")
            .arg("-B")
            .arg(path)
            .arg("--validator-ssh")
            .arg(super::control())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn control_has_no_secret_arguments() {
        let command = super::control();
        assert!(command.starts_with("sudo -n /usr/bin/python3 -I -c "));
        assert!(command.contains("trusted_release"));
        assert!(command.contains("ethereum-validator"));
        assert!(
            !command
                .contains("sudo -n /usr/bin/python3 -I /usr/local/lib/erpc/eth-validator-control")
        );
        assert!(!super::logs(10, false).ends_with(" -f"));
        assert!(super::logs(10, true).ends_with(" -f"));
    }
}
