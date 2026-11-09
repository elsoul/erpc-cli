// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public Arc host facts and journal access, plus original authority requests.
//! Mutating operations never use raw systemctl or ciphertext overwrite commands.

/// The execution layer's unit.
pub const EXECUTION_UNIT: &str = "arc-execution";
/// The consensus layer's unit.
pub const CONSENSUS_UNIT: &str = "arc-consensus";
/// The one-shot unit that fetches snapshots.
pub const SNAPSHOTS_UNIT: &str = "arc-snapshots";
/// Which layer a command is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// `arc-execution`.
    Execution,
    /// `arc-consensus`.
    Consensus,
    /// Both, in dependency order.
    Both,
}

impl Layer {
    /// From `--layer`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "execution" => Some(Self::Execution),
            "consensus" => Some(Self::Consensus),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

/// What to do to the services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Start.
    Start,
    /// Stop; the chain backend defines persistent cancellation semantics.
    Stop,
    /// Restart.
    Restart,
}

/// The host's facts, as `key=value` lines.
pub(crate) const NODE_FACTS: &str = r#"export LC_ALL=C
printf 'machine=%s\n' "$(uname -m)"
printf 'mem_kb=%s\n' "$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
printf 'cpus=%s\n' "$(nproc)"
printf 'cpu_max_mhz=%s\n' "$(lscpu 2>/dev/null | awk -F: '/^CPU max MHz/ {gsub(/ /, "", $2); printf "%d", $2}')"
printf 'root_free_kb=%s\n' "$(df -Pk / | awk 'NR == 2 {print $4}')"
printf 'data_free_kb=%s\n' "$(df -Pk /var/lib/arc 2>/dev/null | awk 'NR == 2 {print $4}')"
printf 'data_mount=%s\n' "$(findmnt -no SOURCE --mountpoint /var/lib/arc 2>/dev/null)"
printf 'systemd=%s\n' "$(systemctl --version | awk 'NR == 1 {print $2}')"
printf 'tpm=%s\n' "$([ -e /dev/tpmrm0 ] && echo yes || echo no)"
printf 'controller=%s\n' "${SSH_CLIENT%% *}"
printf 'ssh_port=%s\n' "$(echo "$SSH_CONNECTION" | awk '{print $4}')"
printf 'sudo=%s\n' "$(sudo -n true 2>/dev/null && echo yes || echo no)"
true"#;

/// The journal of `layer`; `both` includes the snapshot fetch.
pub(crate) fn logs(layer: Layer, lines: u32, follow: bool) -> String {
    let units: &[&str] = match layer {
        Layer::Execution => &[EXECUTION_UNIT],
        Layer::Consensus => &[CONSENSUS_UNIT],
        Layer::Both => &[EXECUTION_UNIT, CONSENSUS_UNIT, SNAPSHOTS_UNIT],
    };
    let units: Vec<String> = units.iter().map(|u| format!("-u {u}")).collect();
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} {}{}",
        units.join(" "),
        if follow { " -f" } else { "" }
    )
}

pub(crate) fn validator_logs(layer: Layer, lines: u32, follow: bool) -> String {
    let units: &[&str] = match layer {
        Layer::Execution => &["erpc-arc-validator-execution.service"],
        Layer::Consensus => &["erpc-arc-validator-consensus.service"],
        Layer::Both => &[
            "erpc-arc-validator-execution.service",
            "erpc-arc-validator-consensus.service",
            "erpc-arc-validator-bootstrap.service",
        ],
    };
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} {}{}",
        units
            .iter()
            .map(|unit| format!("-u {unit}"))
            .collect::<Vec<_>>()
            .join(" "),
        if follow { " -f" } else { "" }
    )
}

/// A fixed Arc helper entrypoint authenticated before any installed code runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control(String);

impl Control {
    /// Qualify the compiled immutable module profile; requests remain on stdin.
    ///
    /// # Errors
    /// Refuses an invalid or incomplete helper profile.
    pub fn new(profile: &[&str]) -> Result<Self, String> {
        crate::python::release_command("/usr/local/lib/erpc/arc", "control.py", &[profile])
            .map(Self)
    }

    /// Dedicated validator namespace; it cannot select the RPC controller.
    /// # Errors
    /// Refuses an incomplete, oversized or non-flat original helper profile.
    pub fn validator(profile: &[&str]) -> Result<Self, String> {
        crate::python::release_command(
            "/usr/local/lib/erpc/arc-validator",
            "control.py",
            &[profile],
        )
        .map(Self)
    }

    pub(crate) fn command(&self) -> String {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn original_control_uses_external_profile_authentication_and_rejects_traversal() {
        let value = super::Control::new(&["arc_trust.py", "control.py"])
            .unwrap()
            .command();
        assert!(value.starts_with("sudo -n /usr/bin/python3 -I"));
        assert!(value.contains("trusted_release"));
        assert!(value.contains("/usr/local/lib/erpc/arc"));
        assert!(super::Control::new(&["../control.py"]).is_err());
        assert!(super::Control::new(&["arc_trust.py"]).is_err());
    }

    #[test]
    fn journals_use_only_closed_component_names() {
        let line = super::logs(super::Layer::Both, 20, false);
        assert!(
            line.contains("-u arc-execution")
                && line.contains("-u arc-consensus")
                && line.contains("-u arc-snapshots")
        );
        assert!(!line.contains(" -f"));
        assert!(super::logs(super::Layer::Consensus, 20, true).ends_with(" -f"));
    }

    #[cfg(unix)]
    #[test]
    fn emitted_control_facts_and_journal_are_valid_shell() {
        for line in [
            super::NODE_FACTS.to_owned(),
            super::logs(super::Layer::Both, 20, false),
            super::Control::new(&["arc_trust.py", "control.py"])
                .unwrap()
                .command(),
        ] {
            let status = std::process::Command::new("bash")
                .args(["-n", "-c", &line])
                .status()
                .unwrap();
            assert!(status.success());
        }
    }
}
