// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Closed remote NEAR operations with bounded public ownership arguments.

use base64::{Engine, engine::general_purpose::STANDARD};

/// Validated public ownership, encoded without shell metacharacters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract(String);
impl Contract {
    /// Bound the public contract before rendering a command.
    /// # Errors
    /// Oversized payloads are refused; the host validates the exact schema.
    pub fn new(json: &[u8]) -> Result<Self, String> {
        if json.len() > 1024 || json.is_empty() {
            return Err("invalid NEAR ownership contract size".into());
        }
        Ok(Self(STANDARD.encode(json)))
    }
    /// Public encoded value used in the carried service configuration.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.0
    }
}

/// Closed set of lifecycle requests supported by the installed controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read-only status.
    Status,
    /// Start through immutable ownership and receipt guards.
    Start,
    /// Gracefully stop the owned process/container.
    Stop,
    /// Guarded restart.
    Restart,
    /// Persist retirement before stopping.
    Retire,
    /// Import original consensus material through stdin into encrypted custody.
    ImportValidator,
    /// Observe public staking-pool and epoch state.
    Registration,
    /// Validate original custody and public staking-pool state.
    ValidateRegistration,
}

pub(crate) fn control(action: Action, contract: &Contract) -> String {
    let action = match action {
        Action::Status => "status",
        Action::Start => "start",
        Action::Stop => "stop",
        Action::Restart => "restart",
        Action::Retire => "retire",
        Action::ImportValidator => "import-validator",
        Action::Registration => "registration",
        Action::ValidateRegistration => "validate-registration",
    };
    format!("{} {action} {}", crate::python::near_control(), contract.0)
}
pub(crate) fn logs(lines: u32, follow: bool) -> String {
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} -u near-node{}",
        if follow { " -f" } else { "" }
    )
}
pub(crate) fn confirm(token: &crate::firewall::FirewallToken) -> String {
    format!(
        "{} firewall-confirm {} {}",
        crate::python::near_control(),
        token.run.as_str(),
        token.bundle
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn ownership_bytes_cannot_change_the_remote_shell_command() {
        let value = super::Contract::new(b"$(id);'\n").expect("bounded");
        let line = super::control(super::Action::Status, &value);
        assert!(!line.contains("$("));
        assert!(line.starts_with("sudo -n /usr/bin/python3 -I -c '"));
        assert!(super::Contract::new(&[0; 1025]).is_err());
    }
}
