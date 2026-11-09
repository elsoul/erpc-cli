// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Original public Ethereum host authority, independent of current NSS names.
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Complete immutable runtime profile, in the host publisher's digest order.
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

/// Exact immutable dedicated-validator helper profile.
pub const VALIDATOR_PROFILE: &[&str] = &[
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

/// Public immutable role, network, inventory owner and management connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Original authority schema.
    pub schema: u8,
    /// RPC or dedicated validator, never inferred from the remote service name.
    pub role: String,
    /// Original network-scoped inventory item identifier.
    pub owner: String,
    /// Native network identifier.
    pub network: String,
    /// Full/archive RPC data or dedicated validator data.
    pub kind: String,
    /// Digest of the original pinned management connection.
    pub host_binding: String,
}
impl Contract {
    /// Check the closed supported role and immutable public identity.
    /// # Errors
    /// Refuses unknown roles, unsafe selectors or missing original inventory.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1
            || self.owner.is_empty()
            || self.owner.len() > 80
            || !self.owner.bytes().all(|b| b.is_ascii_alphanumeric())
            || self.host_binding.len() != 64
            || !self
                .host_binding
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !((self.role == "rpc"
                && self.network == "mainnet"
                && matches!(self.kind.as_str(), "full" | "archive"))
                || (self.role == "validator"
                    && matches!(self.network.as_str(), "mainnet" | "hoodi")
                    && self.kind == "validator"))
        {
            return Err("invalid original Ethereum authority contract");
        }
        Ok(())
    }
}

/// Bind address/login/port to the exact independently pinned SSH public key.
#[must_use]
pub fn host_binding(address: &str, user: &str, port: u16, host_key: &str) -> String {
    let mut hash = Sha256::new();
    for value in [address, user, &port.to_string(), host_key] {
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    format!("{:x}", hash.finalize())
}

/// Execute a carried controller only after authenticating its sealed directory.
/// The script pathname is the first fixed argv; requests use stdin.
#[must_use]
pub fn carried_loader() -> String {
    format!(
        "{}\nimport runpy,sys\nfrom pathlib import Path\np=Path(sys.argv[1])\ntrusted_imports(str(p.absolute().parent))\nsys.argv=sys.argv[1:]\nrunpy.run_path(str(p),run_name='__main__')\n",
        include_str!("../templates/authority/eth_trust.py")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_connection_and_closed_role_are_not_replaced_by_a_current_user_name() {
        let mut value = Contract {
            schema: 1,
            role: "rpc".into(),
            owner: "a".repeat(26),
            network: "mainnet".into(),
            kind: "full".into(),
            host_binding: host_binding("192.0.2.10", "ubuntu", 22, "inert verified host key"),
        };
        value.validate().unwrap();
        assert_ne!(
            value.host_binding,
            host_binding("192.0.2.10", "ubuntu", 2200, "inert verified host key")
        );
        assert_ne!(
            value.host_binding,
            host_binding("192.0.2.10", "other", 22, "inert verified host key")
        );
        value.network = "hoodi".into();
        assert!(value.validate().is_err());
        value.role = "validator".into();
        value.kind = "validator".into();
        value.validate().unwrap();
        value.owner = "$(id)".into();
        assert!(value.validate().is_err());
    }
}
