// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bounded Sui loopback probes and fixed lifecycle commands; never arbitrary shell input.
use crate::arc::Action;

/// Expected immutable ownership of the remote Sui paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contract {
    network: &'static str,
    role: &'static str,
    genesis: &'static str,
}
impl Contract {
    /// Build shell-safe expectations from reviewed network metadata.
    /// # Errors
    /// Refuses unsupported roles/networks or a malformed genesis digest.
    pub fn new(
        network: &'static str,
        role: &'static str,
        genesis: &'static str,
    ) -> Result<Self, String> {
        if !["mainnet", "testnet"].contains(&network)
            || !["fullnode", "validator"].contains(&role)
            || genesis.len() != 64
            || !genesis
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("invalid Sui host contract".to_owned());
        }
        Ok(Self {
            network,
            role,
            genesis,
        })
    }
    fn command(self, operation: &str) -> String {
        format!(
            "sudo -n /usr/local/lib/erpc/erpc-sui-control.py {operation} {} {} {}",
            self.network, self.role, self.genesis
        )
    }
}

/// A public, per-run correlation token that cannot contain shell syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirmation([u8; 16]);
impl Confirmation {
    /// Construct from the caller's fresh random bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    /// Lowercase hexadecimal representation for the run inventory and SSH command.
    #[must_use]
    pub fn text(self) -> String {
        use std::fmt::Write as _;
        self.0
            .iter()
            .fold(String::with_capacity(32), |mut text, byte| {
                let _ = write!(text, "{byte:02x}");
                text
            })
    }
}

/// Supported remote Sui operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Read hardware and connection facts.
    Facts,
    /// Probe systemd, checkpoint metrics and gRPC.
    Status,
    /// Change the one Sui service.
    Service(Action, Contract),
    /// Read/follow a bounded number of journal lines.
    Logs {
        /// Tail line count.
        lines: u32,
        /// Continue following.
        follow: bool,
    },
    /// Confirm the firewall over a fresh connection.
    ConfirmFirewall(Contract, Confirmation),
    /// Start only the exact deployment that this caller confirmed.
    StartConfirmed(Contract, Confirmation),
    /// Retain interrupted bootstrap data in quarantine before a new verified restore.
    RecoverBootstrap(Contract),
    /// Import original validator signing keys from SSH stdin under the host lock.
    ValidatorImport(Contract),
    /// Restore original keys on the same stopped host, retaining prior ciphertext.
    ValidatorRestore(Contract),
    /// Verify stored validator keys without importing or generating any key.
    ValidatorCheck(Contract),
    /// Observe active-set membership over the network's fixed public gRPC endpoint.
    ValidatorStatus(Contract),
}
impl Command {
    pub(crate) fn shell(self) -> String {
        match self {
            Self::Facts => crate::eth::NODE_FACTS.replace("/var/lib/ethereum", "/var/lib/sui"),
            Self::Status => "sudo -n /usr/local/lib/erpc/erpc-sui-status.py".to_owned(),
            Self::Service(action, contract) => contract.command(match action {
                Action::Start => "start",
                Action::Stop => "stop",
                Action::Restart => "restart",
            }),
            Self::RecoverBootstrap(contract) => contract.command("recover-bootstrap"),
            Self::ValidatorImport(contract) => contract.command("import-validator"),
            Self::ValidatorRestore(contract) => contract.command("restore-validator"),
            Self::ValidatorCheck(contract) => contract.command("check-validator"),
            Self::ValidatorStatus(contract) => contract.command("validator-status"),
            Self::Logs { lines, follow } => format!(
                "sudo -n journalctl --no-pager -o short-iso -n {} -u sui-node -u sui-bootstrap{}",
                lines.min(10000),
                if follow { " -f" } else { "" }
            ),
            Self::ConfirmFirewall(contract, intent) => {
                format!("{} {}", contract.command("confirm"), intent.text())
            }
            Self::StartConfirmed(contract, intent) => {
                format!("{} {}", contract.command("start-confirmed"), intent.text())
            }
        }
    }
}
