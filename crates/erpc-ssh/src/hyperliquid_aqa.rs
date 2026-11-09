// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Separate AQA controller; secret import travels only through stdin.

/// Exact immutable publisher helper profile in digest order.
pub const RUNTIME_FILES: &[&str] = &[
    "catalog.json",
    "control.py",
    "erpc_aqa_common.py",
    "erpc_aqa_state.py",
    "erpc_aqa_accounts.py",
    "erpc_aqa_host.py",
    "erpc_aqa_artifact.py",
    "erpc_aqa_custody.py",
    "erpc_aqa_public.py",
    "erpc_aqa_process.py",
    "erpc_aqa_units.py",
    "erpc_aqa_trust.py",
];

/// A checked original publisher ownership token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner(String);
impl Owner {
    /// Accept only the original public 128-bit identifier.
    /// # Errors
    /// Rejects shell syntax or an invalid width.
    pub fn new(value: &str) -> Result<Self, String> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid original AQA owner".into());
        }
        Ok(Self(value.into()))
    }
}

/// A fixed remote publisher operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Public control or concealed original key import on stdin.
    Control,
    /// Typed lifecycle events; never native/private-environment diagnostics.
    Logs {
        /// Original publisher owner.
        owner: Owner,
        /// Bounded recent event count.
        lines: u32,
        /// Follow later public lifecycle events.
        follow: bool,
    },
}
impl Command {
    pub(crate) fn shell(&self) -> String {
        let command = crate::python::release_command(
            "/usr/local/lib/erpc/hyperliquid-aqa",
            "control.py",
            &[RUNTIME_FILES],
        )
        .unwrap_or_else(|_| "false".into());
        match self {
            Self::Control => command,
            Self::Logs {
                owner,
                lines,
                follow,
            } => format!(
                "{command} logs {} {} {}",
                owner.0,
                lines.min(&10000),
                if *follow { "follow" } else { "once" }
            ),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installed_bytes_are_authenticated_outside_the_release_before_execution() {
        assert!(Owner::new("$(id)").is_err());
        let command = Command::Control.shell();
        assert!(command.contains("/usr/bin/python3 -I -c"));
        assert!(
            command.find("selected = trusted_release(").unwrap()
                < command.find("runpy.run_path(").unwrap()
        );
        let logs = Command::Logs {
            owner: Owner::new(&"ab".repeat(16)).unwrap(),
            lines: u32::MAX,
            follow: true,
        }
        .shell();
        assert!(logs.ends_with(" 10000 follow"));
    }
    #[cfg(unix)]
    #[test]
    fn actual_remote_commands_refuse_untrusted_profiles_before_interpretation() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-hyperliquid/tests/aqa_entrypoints.py");
        for operation in [
            Command::Control,
            Command::Logs {
                owner: Owner::new(&"ab".repeat(16)).unwrap(),
                lines: 50,
                follow: false,
            },
        ] {
            let result = std::process::Command::new("python3")
                .arg("-I")
                .arg(&script)
                .arg("--ssh")
                .arg(operation.shell())
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}
