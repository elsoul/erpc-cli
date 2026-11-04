// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed TRON lifecycle operations; credentials travel only on stdin.
use crate::firewall::FirewallToken;

/// Immutable expected public ownership of the remote node and signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract(String);
impl Contract {
    /// Validate every token before assembling a remote command.
    /// # Errors
    /// Refuses unknown profiles, malformed public identifiers and shell metacharacters.
    pub fn new(
        network: &str,
        role: &str,
        genesis: &str,
        architecture: &str,
        owner: &str,
        signer: &str,
        inventory_owner: &str,
    ) -> Result<Self, String> {
        let address = |s: &str| {
            s.len() == 34
                && s.starts_with('T')
                && s.bytes().all(|b| {
                    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b)
                })
        };
        let identity = match role {
            "fullnode" if owner.is_empty() && signer.is_empty() => "- -".to_owned(),
            "validator" if address(owner) && address(signer) && owner != signer => {
                format!("{owner} {signer}")
            }
            _ => return Err("invalid TRON ownership profile".into()),
        };
        if inventory_owner.len() != 26
            || !inventory_owner
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || !["mainnet", "nile"].contains(&network)
            || !["x86_64", "aarch64"].contains(&architecture)
            || genesis.len() != 64
            || !genesis
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid TRON network contract".into());
        }
        Ok(Self(format!(
            "{network} {role} {genesis} {architecture} {identity} {inventory_owner}"
        )))
    }
    fn command(&self, operation: &str) -> String {
        format!(
            "sudo -n /usr/bin/python3 /usr/local/lib/erpc/tron/control.py {operation} {}",
            self.0
        )
    }
}

/// Supported independent host operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Query local progress and public membership.
    Status,
    /// Start a previously activated node after checking current authorization.
    Start,
    /// Stop the node and revoke outstanding deployment intents.
    Stop,
    /// Restart a previously activated node after checks.
    Restart,
    /// Authenticate the stored native keystore without importing another key.
    CheckKeys,
    /// Read public candidate/election/permission state.
    Registration,
    /// Verify both custody and current network permission.
    ValidateRegistration,
}
impl Action {
    const fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::CheckKeys => "check-keys",
            Self::Registration => "registration",
            Self::ValidateRegistration => "validate-registration",
        }
    }
}

/// Typed TRON operations, including operation-bound firewall confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Hardware and connection facts only.
    Facts,
    /// An independent lifecycle operation with expected ownership.
    Operation(Action, Contract),
    /// Import/restore the original native keystore and password from stdin.
    Import {
        /// Public expected ownership.
        contract: Contract,
        /// Original caller deployment intent.
        intent: crate::sui::Confirmation,
        /// Explicit same-host restoration.
        restore: bool,
    },
    /// Confirm precisely the prepared policy over a new connection.
    Confirm {
        /// Public expected ownership.
        contract: Contract,
        /// Original caller deployment intent.
        intent: crate::sui::Confirmation,
        /// Shared firewall receipt.
        token: FirewallToken,
    },
    /// Bounded journal output, after verifying host ownership.
    Logs {
        /// Public expected ownership.
        contract: Contract,
        /// Maximum initial lines.
        lines: u32,
        /// Continue following.
        follow: bool,
    },
}
impl Command {
    pub(crate) fn shell(&self) -> String {
        match self {
            Self::Facts => crate::eth::NODE_FACTS.replace("/var/lib/ethereum", "/var/lib/tron"),
            Self::Operation(action, contract) => contract.command(action.name()),
            Self::Import {
                contract,
                intent,
                restore,
            } => format!(
                "{} {}",
                contract.command(if *restore { "restore" } else { "import" }),
                intent.text()
            ),
            Self::Confirm {
                contract,
                intent,
                token,
            } => format!(
                "{} {} {} {}",
                contract.command("confirm"),
                intent.text(),
                token.run.as_str(),
                token.bundle
            ),
            Self::Logs {
                contract,
                lines,
                follow,
            } => format!(
                "{} >/dev/null && sudo -n journalctl --no-pager -o short-iso -n {} -u tron-node{}",
                contract.command("guard"),
                lines.min(&10000),
                if *follow { " -f" } else { "" }
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contract_refuses_shell_tokens_and_keeps_confirmation_identity() {
        assert!(
            Contract::new(
                "nile; id",
                "fullnode",
                &"a".repeat(64),
                "x86_64",
                "",
                "",
                &"i".repeat(26)
            )
            .is_err()
        );
        assert!(
            Contract::new(
                "nile",
                "validator",
                &"a".repeat(64),
                "x86_64",
                "$(id)",
                "x",
                &"i".repeat(26)
            )
            .is_err()
        );
        let contract = Contract::new(
            "nile",
            "fullnode",
            &"a".repeat(64),
            "x86_64",
            "",
            "",
            &"i".repeat(26),
        )
        .unwrap();
        let run = crate::RunId::new("r-20261026t120000-abc123").unwrap();
        let command = Command::Confirm {
            contract,
            intent: crate::sui::Confirmation::new([1; 16]),
            token: FirewallToken::new(run, &"b".repeat(64)).unwrap(),
        }
        .shell();
        assert!(command.contains(" confirm nile fullnode "));
        assert!(command.ends_with(&format!("r-20261026t120000-abc123 {}", "b".repeat(64))));
    }
}
