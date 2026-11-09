// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! External namespace authentication before any installed node controller executes.
/// Exact immutable runtime profile, in digest order.
pub const RPC_RUNTIME_FILES: &[&str] = &[
    "catalog.json",
    "control.py",
    "erpc_hl_artifact.py",
    "erpc_hl_common.py",
    "erpc_hl_gateway.py",
    "erpc_hl_host.py",
    "erpc_hl_processes.py",
    "erpc_hl_public.py",
    "erpc_hl_setup.py",
    "erpc_hl_state.py",
    "erpc_hl_trust.py",
    "erpc_hl_units.py",
    "retention.py",
];
/// Complete validator-capable runtime; legacy RPC profiles remain readable.
pub const RUNTIME_FILES: &[&str] = &[
    "catalog.json",
    "control.py",
    "erpc_hl_artifact.py",
    "erpc_hl_common.py",
    "erpc_hl_gateway.py",
    "erpc_hl_host.py",
    "erpc_hl_processes.py",
    "erpc_hl_public.py",
    "erpc_hl_setup.py",
    "erpc_hl_state.py",
    "erpc_hl_trust.py",
    "erpc_hl_units.py",
    "retention.py",
    "erpc_hl_validator.py",
    "erpc_hl_validator_public.py",
];
/// A public ownership nonce, validated separately from the shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner(String);
impl Owner {
    /// Parse canonical 128-bit ownership.
    /// # Errors
    /// Refuses incorrect width or shell syntax.
    pub fn new(value: &str) -> Result<Self, String> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid Hyperliquid owner".into());
        }
        Ok(Self(value.into()))
    }
}
/// Fixed controller operations; private custody payloads may travel only on stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Controller request carried on stdin.
    Control,
    /// Journal after validating the exact original public owner.
    Logs {
        /// Expected original owner.
        owner: Owner,
        /// Bounded initial lines.
        lines: u32,
        /// Follow subsequent output.
        follow: bool,
    },
}
impl Command {
    pub(crate) fn shell(&self) -> String {
        let control = crate::python::release_command(
            "/usr/local/lib/erpc/hyperliquid",
            "control.py",
            &[RPC_RUNTIME_FILES, RUNTIME_FILES],
        )
        .unwrap_or_else(|_| "false".into());
        match self {
            Self::Control => control,
            Self::Logs {
                owner,
                lines,
                follow,
            } => format!(
                "{control} logs {} {} {}",
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
            .join("../erpc-chain-hyperliquid/tests/entrypoints_test.py");
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
