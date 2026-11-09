// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed Kaia commands; neither a unit name nor a shell fragment comes from input.

/// Closed command for a complete, hash-bound Kaia helper release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control(String);
impl Control {
    /// Build the isolated loader, supporting the reviewed RPC helper profile.
    /// # Errors
    /// Refuses invalid built-in profile/path metadata before connecting.
    pub fn new() -> Result<Self, String> {
        crate::python::release_command(
            "/usr/local/lib/erpc/kaia",
            "control.py",
            &[
                &["control.py", "bootstrap.py", "catalog.json"],
                &[
                    "control.py",
                    "bootstrap.py",
                    "custody.py",
                    "corecell.py",
                    "coreaccount.py",
                    "catalog.json",
                ],
            ],
        )
        .map(Self)
    }
    /// Concealed same-owner custody operation; request and response travel on pipes.
    /// # Errors
    /// Refuses invalid built-in profile metadata before connecting.
    pub fn custody() -> Result<Self, String> {
        Self::new().map(|command| Self(format!("{} custody", command.0)))
    }
    pub(crate) fn shell(&self) -> String {
        self.0.clone()
    }
}
pub(crate) fn logs(lines: u32, follow: bool) -> String {
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} -u erpc-kaia{}",
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
        assert!(command.contains("bootstrap.py"));
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
