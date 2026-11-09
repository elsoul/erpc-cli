// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed BSC commands; neither a unit name nor a shell fragment comes from input.

/// Closed command for a complete, hash-bound BSC helper release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control(String);
impl Control {
    /// Build the isolated loader, supporting both original RPC and signer profiles.
    /// # Errors
    /// Refuses invalid built-in profile/path metadata before connecting.
    pub fn new() -> Result<Self, String> {
        crate::python::release_command(
            "/usr/local/lib/erpc/bsc",
            "control.py",
            &[
                &["control.py", "bootstrap.py", "catalog.json"],
                &["control.py", "bootstrap.py", "validator.py", "catalog.json"],
            ],
        )
        .map(Self)
    }
    pub(crate) fn shell(&self) -> String {
        self.0.clone()
    }
}
pub(crate) fn logs(lines: u32, follow: bool) -> String {
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} -u erpc-bsc -u erpc-bsc-activation{}",
        if follow { " -f" } else { "" }
    )
}
pub(crate) fn confirm(control: &Control, token: &crate::firewall::FirewallToken) -> String {
    format!(
        "{} firewall-confirm {} {}",
        control.shell(),
        token.run.as_str(),
        token.bundle
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn controller_uses_an_isolated_hash_checked_release_loader() {
        let command = super::Control::new().expect("closed profile").shell();
        assert!(command.starts_with("sudo -n /usr/bin/python3 -I -c "));
        assert!(command.contains("trusted_release"));
        assert!(command.contains("validator.py"));
        #[cfg(unix)]
        assert!(
            std::process::Command::new("bash")
                .args(["-n", "-c", &command])
                .status()
                .expect("bash")
                .success()
        );
    }
}
