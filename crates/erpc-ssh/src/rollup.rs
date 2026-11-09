// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Closed follower commands. Contracts and concealed provider data travel on stdin.

/// Follower service family; never an arbitrary shell or unit fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// OP Mainnet/Sepolia.
    Optimism,
    /// Base Mainnet/Sepolia.
    Base,
    /// Soneium Mainnet/Minato.
    Soneium,
}
impl Family {
    /// Canonical service namespace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Optimism => "optimism",
            Self::Base => "base",
            Self::Soneium => "soneium",
        }
    }
    /// Select only a recognized family.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "optimism" => Some(Self::Optimism),
            "base" => Some(Self::Base),
            "soneium" => Some(Self::Soneium),
            _ => None,
        }
    }
}

pub(crate) const CONTROL: &str =
    "sudo -n /usr/bin/python3 -I /usr/local/lib/erpc/rollup_control.py";

pub(crate) fn preflight() -> String {
    let script = include_str!("rollup_contract.py").replace('\'', "'\\''");
    format!("sudo -n /usr/bin/python3 -I -c '{script}'")
}

pub(crate) fn confirm(family: Family, token: &crate::firewall::FirewallToken) -> String {
    format!(
        "sudo -n /usr/bin/python3 -I /usr/local/lib/erpc/rpc-firewall.py {} confirm {} {}",
        family.name(),
        token.run.as_str(),
        token.bundle
    )
}

pub(crate) fn logs(family: Family, lines: u32, follow: bool) -> String {
    let prefix = family.name();
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} -u erpc-{prefix}-execution -u erpc-{prefix}-consensus -u erpc-{prefix}-upstreams -u erpc-{prefix}-bootstrap -u erpc-{prefix}-rpc{}",
        if follow { " -f" } else { "" }
    )
}

/// Closed follower operation, rendered without interpolating request contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Read remote ownership before reserving inventory.
    Preflight,
    /// Installed guarded controller, request on stdin.
    Control,
    /// Confirm exactly the submitted firewall operation.
    FirewallConfirm {
        /// Service namespace.
        family: Family,
        /// Immutable caller receipt.
        token: crate::firewall::FirewallToken,
    },
    /// Read the owned journals.
    Logs {
        /// Service namespace.
        family: Family,
        /// Number of recent records.
        lines: u32,
        /// Continue streaming.
        follow: bool,
    },
}
impl Command {
    pub(crate) fn shell(&self) -> String {
        match self {
            Self::Preflight => preflight(),
            Self::Control => CONTROL.into(),
            Self::FirewallConfirm { family, token } => confirm(*family, token),
            Self::Logs {
                family,
                lines,
                follow,
            } => logs(*family, *lines, *follow),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn closed_commands_are_valid_shell_without_request_values() {
        use std::io::Write;
        let mut scripts = vec![Command::Preflight.shell(), Command::Control.shell()];
        for family in [Family::Optimism, Family::Base, Family::Soneium] {
            scripts.push(
                Command::Logs {
                    family,
                    lines: 100,
                    follow: true,
                }
                .shell(),
            );
            let run = crate::RunId::new("r-offlinetest").expect("run identifier");
            let token = crate::firewall::FirewallToken::new(run, &"a".repeat(64)).expect("receipt");
            scripts.push(Command::FirewallConfirm { family, token }.shell());
        }
        for script in scripts {
            let mut child = std::process::Command::new("sh")
                .arg("-n")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .expect("shell parser");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(script.as_bytes())
                .expect("syntax input");
            assert!(child.wait().expect("syntax result").success());
        }
        assert!(Family::parse("base; touch /tmp/unsafe").is_none());
    }
}
