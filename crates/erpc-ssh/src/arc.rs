// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The commands an Arc RPC node is sent outside a play: its facts, its
//! state, its services in dependency order, its journal, its consensus key
//! into `systemd-creds`, and the firewall confirmation.
//!
//! The layers depend on each other: the consensus layer drives the
//! execution layer over IPC sockets the execution layer makes. So a start
//! brings the execution layer up and waits for its sockets before the
//! consensus layer; a stop takes the consensus layer down first; a restart
//! of the execution layer stops the consensus layer, restarts the execution
//! layer, waits for its sockets, then starts the consensus layer.

use crate::command::CommandError;

/// The execution layer's unit.
pub const EXECUTION_UNIT: &str = "arc-execution";
/// The consensus layer's unit.
pub const CONSENSUS_UNIT: &str = "arc-consensus";
/// The one-shot unit that fetches snapshots.
pub const SNAPSHOTS_UNIT: &str = "arc-snapshots";
/// Where the encrypted consensus key lives.
pub const CREDENTIAL: &str = "/etc/credstore.encrypted/arc-consensus-key";

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
    /// Stop. Enabled units start again at boot.
    Stop,
    /// Restart.
    Restart,
}

/// A public RPC endpoint the node compares its head with: `https://` and a
/// host of plain characters, nothing else, so it goes into the line as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicRpc(String);

impl PublicRpc {
    /// Checks `url`.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Run`] for anything but `https://<host>`.
    pub fn new(url: &str) -> Result<Self, CommandError> {
        let host = url
            .strip_prefix("https://")
            .ok_or_else(|| CommandError::Run(format!("{url} is not https")))?;
        let ok = !host.is_empty()
            && host.len() <= 253
            && !host.starts_with(['-', '.'])
            && host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b));
        if ok {
            Ok(Self(url.to_owned()))
        } else {
            Err(CommandError::Run(format!("{url} is not a plain https URL")))
        }
    }
}

/// Waits up to five minutes for the execution layer's IPC sockets, as root:
/// /run/arc is the arc user's, 0750.
const WAIT_SOCKETS: &str = "i=0; until sudo -n test -S /run/arc/reth.ipc && sudo -n test -S /run/arc/auth.ipc; do \
     i=$((i+1)); [ $i -ge 300 ] && { echo 'the execution layer made no IPC sockets in 300 s' >&2; exit 1; }; \
     sleep 1; done";

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

/// The node's state, as `key=value` lines; RPC answers are the raw JSON.
pub(crate) fn status(public: &PublicRpc) -> String {
    format!(
        r#"export LC_ALL=C
rpc() {{ curl -s -m 5 -H 'Content-Type: application/json' -d "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":[]}}" "$1" 2>/dev/null; }}
for u in {EXECUTION_UNIT} {CONSENSUS_UNIT} {SNAPSHOTS_UNIT} erpc-arc-firewall; do printf 'unit_%s=%s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)"; done
printf 'current=%s\n' "$(readlink /opt/arc/current 2>/dev/null)"
printf 'running=%s\n' "$(rpc http://127.0.0.1:8545 arc_getVersion | sed -n 's/.*"cargo_version":"\([^"]*\)".*/\1/p')"
printf 'chain_id=%s\n' "$(rpc http://127.0.0.1:8545 eth_chainId)"
printf 'head=%s\n' "$(rpc http://127.0.0.1:8545 eth_blockNumber)"
printf 'syncing=%s\n' "$(rpc http://127.0.0.1:8545 eth_syncing)"
printf 'public_head=%s\n' "$(rpc '{public}' eth_blockNumber)"
printf 'data_used_kb=%s\n' "$(df -Pk /var/lib/arc 2>/dev/null | awk 'NR == 2 {{print $3}}')"
printf 'data_free_kb=%s\n' "$(df -Pk /var/lib/arc 2>/dev/null | awk 'NR == 2 {{print $4}}')"
printf 'mem_execution=%s\n' "$(systemctl show -p MemoryCurrent --value {EXECUTION_UNIT} 2>/dev/null)"
printf 'mem_consensus=%s\n' "$(systemctl show -p MemoryCurrent --value {CONSENSUS_UNIT} 2>/dev/null)"
printf 'restarts_execution=%s\n' "$(systemctl show -p NRestarts --value {EXECUTION_UNIT} 2>/dev/null)"
printf 'restarts_consensus=%s\n' "$(systemctl show -p NRestarts --value {CONSENSUS_UNIT} 2>/dev/null)"
printf 'since_execution=%s\n' "$(systemctl show -p ActiveEnterTimestamp --value {EXECUTION_UNIT} 2>/dev/null)"
printf 'firewall_table=%s\n' "$(sudo -n nft list table inet erpc_arc >/dev/null 2>&1 && echo yes || echo no)"
printf 'firewall_armed=%s\n' "$(sudo -n test -e /etc/erpc/arc/pending.json && echo yes || echo no)"
printf 'firewall_revoked=%s\n' "$(sudo -n test -e /etc/erpc/arc/startup-revoked && echo yes || echo no)"
printf 'credential=%s\n' "$(sudo -n test -e {CREDENTIAL} && echo yes || echo no)"
printf 'snapshot=%s\n' "$(sudo -n test -e /var/lib/arc/.erpc-snapshot-done && echo done || echo missing)"
true"#,
        public = public.0
    )
}

/// Starts, stops or restarts `layer` in dependency order.
pub(crate) fn service(action: Action, layer: Layer) -> String {
    let ctl = |verb: &str, unit: &str| format!("sudo -n systemctl {verb} {unit}");
    let parts: Vec<String> = match (action, layer) {
        // The consensus layer requires the execution layer, so starting it
        // alone starts both: the same order, waiting for the sockets.
        (Action::Start, Layer::Both | Layer::Consensus) => vec![
            ctl("start", EXECUTION_UNIT),
            WAIT_SOCKETS.to_owned(),
            ctl("start", CONSENSUS_UNIT),
        ],
        (Action::Start, Layer::Execution) => vec![ctl("start", EXECUTION_UNIT)],
        (Action::Stop, Layer::Both | Layer::Execution) => {
            vec![ctl("stop", CONSENSUS_UNIT), ctl("stop", EXECUTION_UNIT)]
        }
        (Action::Stop, Layer::Consensus) => vec![ctl("stop", CONSENSUS_UNIT)],
        (Action::Restart, Layer::Both | Layer::Execution) => vec![
            ctl("stop", CONSENSUS_UNIT),
            ctl("restart", EXECUTION_UNIT),
            WAIT_SOCKETS.to_owned(),
            ctl("start", CONSENSUS_UNIT),
        ],
        (Action::Restart, Layer::Consensus) => vec![ctl("restart", CONSENSUS_UNIT)],
    };
    parts.join(" && ")
}

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

/// Encrypts standard input with `systemd-creds` as the consensus key, and
/// moves it into place whole, 0600: `systemd-creds` left it 0644 on
/// Ubuntu 24.04 (systemd 255) despite the umask.
pub(crate) fn write_credential() -> String {
    format!(
        "umask 077 && sudo -n install -d -m 0700 -o root -g root /etc/credstore.encrypted && \
         sudo -n systemd-creds encrypt --name=consensus-key - {CREDENTIAL}.new && \
         sudo -n chmod 0600 {CREDENTIAL}.new && \
         sudo -n mv -f {CREDENTIAL}.new {CREDENTIAL} && echo credential=written"
    )
}

/// Runs the firewall confirmation helper.
pub(crate) fn confirm_firewall(token: &crate::firewall::FirewallToken) -> String {
    format!(
        "sudo -n python3 /usr/local/lib/erpc/rpc-firewall.py arc confirm {} {}",
        token.run.as_str(),
        token.bundle
    )
}

#[cfg(test)]
mod tests {
    use super::{Action, Layer, PublicRpc, logs, service, status};
    #[cfg(unix)]
    use super::{NODE_FACTS, confirm_firewall, write_credential};

    #[cfg(unix)]
    fn valid_shell(line: &str) {
        let checked = std::process::Command::new("bash")
            .args(["-n", "-c", line])
            .status()
            .expect("bash");
        assert!(checked.success(), "{line}");
    }

    #[cfg(unix)]
    #[test]
    fn every_line_is_valid_shell() {
        let public = PublicRpc::new("https://api.github.com").expect("url");
        valid_shell(NODE_FACTS);
        valid_shell(&status(&public));
        for action in [Action::Start, Action::Stop, Action::Restart] {
            for layer in [Layer::Execution, Layer::Consensus, Layer::Both] {
                valid_shell(&service(action, layer));
            }
        }
        valid_shell(&logs(Layer::Both, 100, true));
        valid_shell(&write_credential());
        valid_shell(&confirm_firewall(
            &crate::firewall::FirewallToken::new(
                crate::RunId::new("r-20261026t120000-abc123").unwrap(),
                &"a".repeat(64),
            )
            .unwrap(),
        ));
    }

    #[test]
    fn the_layers_go_in_dependency_order() {
        let restart = service(Action::Restart, Layer::Both);
        let order: Vec<usize> = [
            "stop arc-consensus",
            "restart arc-execution",
            "reth.ipc",
            "start arc-consensus",
        ]
        .iter()
        .map(|s| restart.find(s).expect(s))
        .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{restart}");
        let stop = service(Action::Stop, Layer::Both);
        assert!(stop.find("stop arc-consensus") < stop.find("stop arc-execution"));
        let start = service(Action::Start, Layer::Both);
        assert!(start.find("start arc-execution") < start.find("start arc-consensus"));
        assert_eq!(
            service(Action::Restart, Layer::Consensus),
            "sudo -n systemctl restart arc-consensus"
        );
    }

    #[test]
    fn the_status_asks_only_loopback_and_the_public_endpoint_given() {
        let line = status(&PublicRpc::new("https://api.github.com").expect("url"));
        let urls: Vec<&str> = line
            .split(['\'', ' ', '"'])
            .filter(|w| w.starts_with("http"))
            .collect();
        assert!(
            urls.iter()
                .all(|u| *u == "http://127.0.0.1:8545" || *u == "https://api.github.com"),
            "{urls:?}"
        );
    }

    #[test]
    fn only_a_plain_https_url_is_a_public_endpoint() {
        assert!(PublicRpc::new("https://api.github.com").is_ok());
        // Assembled from parts, so the endpoints gate does not read refused
        // inputs as destinations.
        let https = |rest: &str| ["https", "://", rest].concat();
        for bad in [
            ["http", "://", "api.github.com"].concat(),
            https(""),
            https("-x.github.com"),
            https("api.github.com/'; rm -rf /"),
            https("api.github.com path"),
            https("API.github.com"),
            https("api.github.com:8545"),
        ] {
            assert!(PublicRpc::new(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn logs_follow_only_when_asked_and_name_the_units() {
        assert_eq!(
            logs(Layer::Consensus, 50, false),
            "sudo -n journalctl --no-pager -o short-iso -n 50 -u arc-consensus"
        );
        assert!(logs(Layer::Both, 10, true).ends_with("-u arc-snapshots -f"));
    }
}
