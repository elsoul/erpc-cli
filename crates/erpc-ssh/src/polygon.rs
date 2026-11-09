// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed Polygon helper entrypoints. Concealed parent configuration uses stdin.

/// One checked host contract for journal access without reading stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract(String);
impl Contract {
    /// Bind the exact network, unique inventory owner and both chain identities.
    /// # Errors
    /// Refuses shell syntax, unsupported profiles or incomplete identifiers.
    pub fn new(
        network: &str,
        owner: &str,
        architecture: &str,
        bor: &str,
        heimdall: &str,
    ) -> Result<Self, String> {
        let hex = |value: &str, size: usize| {
            value.len() == size
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !["mainnet", "amoy"].contains(&network)
            || !["x86_64", "aarch64"].contains(&architecture)
            || owner.len() != 26
            || !owner
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || !bor.strip_prefix("0x").is_some_and(|value| hex(value, 64))
            || !hex(heimdall, 64)
        {
            return Err("invalid Polygon ownership contract".into());
        }
        Ok(Self(format!(
            "{network} {owner} {architecture} {bor} {heimdall}"
        )))
    }

    /// Bind validator journals to the dedicated signer and external stake owner.
    /// # Errors
    /// Refuses incomplete addresses or a signer that is also the stake owner.
    pub fn validator(mut self, signer: &str, stake_owner: &str) -> Result<Self, String> {
        let address = |value: &str| {
            value.strip_prefix("0x").is_some_and(|hex| {
                hex.len() == 40
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && hex.bytes().any(|b| b != b'0')
            })
        };
        if !address(signer) || !address(stake_owner) || signer == stake_owner {
            return Err("invalid Polygon validator journal authority".into());
        }
        self.0.push_str(" validator ");
        self.0.push_str(signer);
        self.0.push(' ');
        self.0.push_str(stake_owner);
        Ok(self)
    }
}

/// A fixed, validated command; arbitrary commands cannot enter this wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command(String);
impl Command {
    fn prefix() -> Result<String, String> {
        crate::python::release_command(
            "/usr/local/lib/erpc/polygon",
            "control.py",
            &[
                &[
                    "accounts.py",
                    "admission.py",
                    "artifacts.py",
                    "broker.py",
                    "broker_docker.py",
                    "broker_runtime.py",
                    "broker_storage.py",
                    "checkpoint.py",
                    "configure.py",
                    "control.py",
                    "gateway.py",
                    "host.py",
                    "host_resources.py",
                    "identity.py",
                    "install.py",
                    "launch.py",
                    "local_tls.py",
                    "native_authority.py",
                    "native_peer.py",
                    "observe.py",
                    "parent.py",
                    "signer.py",
                    "signatures.py",
                    "state.py",
                    "upstreams.py",
                    "validator_activation.py",
                    "validator_runtime.py",
                    "volume.py",
                ],
                &[
                    "accounts.py",
                    "admission.py",
                    "artifacts.py",
                    "checkpoint.py",
                    "configure.py",
                    "control.py",
                    "host.py",
                    "identity.py",
                    "install.py",
                    "launch.py",
                    "observe.py",
                    "parent.py",
                    "signer.py",
                    "state.py",
                    "upstreams.py",
                ],
                &[
                    "accounts.py",
                    "artifacts.py",
                    "configure.py",
                    "control.py",
                    "host.py",
                    "identity.py",
                    "install.py",
                    "launch.py",
                    "observe.py",
                    "parent.py",
                    "state.py",
                    "upstreams.py",
                ],
                &[
                    "artifacts.py",
                    "configure.py",
                    "control.py",
                    "host.py",
                    "identity.py",
                    "install.py",
                    "launch.py",
                    "observe.py",
                    "parent.py",
                    "state.py",
                    "upstreams.py",
                ],
            ],
        )
    }
    /// Public or concealed structured operation, supplied exclusively on stdin.
    /// # Errors
    /// A malformed compiled helper profile prevents execution.
    pub fn request() -> Result<Self, String> {
        Ok(Self(format!("{} request", Self::prefix()?)))
    }
    /// Read-only host platform/connection/storage facts.
    #[must_use]
    pub fn facts() -> Self {
        Self(crate::eth::NODE_FACTS.replace("/var/lib/ethereum", "/var/lib/polygon"))
    }
    /// Follow only this owned node's fixed native journals.
    /// # Errors
    /// Refuses unknown components or unbounded line counts.
    pub fn logs(
        contract: &Contract,
        component: &str,
        lines: u32,
        follow: bool,
    ) -> Result<Self, String> {
        if !["bor", "heimdall", "parent", "broker", "all"].contains(&component)
            || !(1..=10_000).contains(&lines)
        {
            return Err("invalid Polygon journal selection".into());
        }
        Ok(Self(format!(
            "{} logs {} {component} {lines} {}",
            Self::prefix()?,
            contract.0,
            if follow { "follow" } else { "once" }
        )))
    }
    pub(crate) fn line(&self) -> String {
        self.0.clone()
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn fixed_profiles_and_journals_cannot_inject_shell_arguments() {
        let contract = super::Contract::new(
            "amoy",
            &"i".repeat(26),
            "x86_64",
            &format!("0x{}", "a".repeat(64)),
            &"b".repeat(64),
        )
        .unwrap();
        assert!(
            super::Command::logs(&contract, "bor", 100, false)
                .unwrap()
                .line()
                .ends_with("bor 100 once")
        );
        for component in ["../node", "bor;id", "", "polygon-heimdall.service"] {
            assert!(super::Command::logs(&contract, component, 100, false).is_err());
        }
        assert!(super::Command::logs(&contract, "all", 10_001, false).is_err());
        assert!(
            super::Contract::new(
                "amoy",
                "foreign id",
                "x86_64",
                &format!("0x{}", "a".repeat(64)),
                &"b".repeat(64)
            )
            .is_err()
        );
        let command = super::Command::request().unwrap().line();
        assert!(command.contains("trusted_release"));
        assert!(command.ends_with(" request"));
    }
}
