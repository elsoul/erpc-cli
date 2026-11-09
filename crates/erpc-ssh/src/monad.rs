// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Fixed Monad helper entrypoints; the controller validates every stdin contract.
/// Public ownership nonce, never shell text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner(String);
impl Owner {
    /// Validate a canonical public 128-bit ownership nonce.
    /// # Errors
    /// Rejects wrong widths and shell metacharacters.
    pub fn new(value: &str) -> Result<Self, String> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid Monad owner".into());
        }
        Ok(Self(value.into()))
    }
}
/// Narrow controller transport; concealed native keys only travel on stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Invoke the installed ownership-checking controller.
    Control,
    /// Check ownership before reserving an inventory item; no helper installation.
    Probe,
    /// Read hardware/connection facts, without initializing a device.
    Facts,
    /// Stream bounded native journal output after ownership verification.
    Logs {
        /// Expected public inventory ownership.
        owner: Owner,
        /// Number of recent journal lines.
        lines: u32,
        /// Follow subsequent lines.
        follow: bool,
    },
}
impl Command {
    pub(crate) fn shell(&self) -> String {
        match self {
            Self::Control => crate::python::command("/usr/local/lib/erpc/monad/control.py")
                .unwrap_or_else(|_| "false".into()),
            Self::Probe => {
                let script = include_str!("monad_probe.py").replace('\'', "'\\''");
                format!("sudo -n /usr/bin/python3 -I -c '{script}'")
            }
            Self::Facts => {
                crate::eth::NODE_FACTS.replace("/var/lib/ethereum", "/var/lib/erpc-monad/data")
            }
            Self::Logs {
                owner,
                lines,
                follow,
            } => format!(
                "{} logs {} {} {}",
                crate::python::command("/usr/local/lib/erpc/monad/control.py")
                    .unwrap_or_else(|_| "false".into()),
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
    fn ownership_cannot_inject_commands_and_keys_never_enter_argv() {
        assert!(Owner::new("$(id)").is_err());
        let text = Command::Logs {
            owner: Owner::new(&"ab".repeat(16)).unwrap(),
            lines: u32::MAX,
            follow: true,
        }
        .shell();
        assert!(text.ends_with(" 10000 follow"));
        assert!(text.contains("/usr/bin/python3 -I"));
        assert!(!Command::Control.shell().contains("password"));
    }
    #[cfg(unix)]
    #[test]
    fn actual_installed_commands_authenticate_before_interpretation() {
        for command in [
            Command::Control,
            Command::Logs {
                owner: Owner::new(&"a".repeat(32)).unwrap(),
                lines: 10,
                follow: false,
            },
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../erpc-chain-monad/tests/entrypoints_test.py");
            let result = std::process::Command::new("python3")
                .arg("-I")
                .arg(path)
                .arg("--ssh")
                .arg(command.shell())
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
