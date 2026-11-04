// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The commands an Ethereum RPC node is sent outside a play: its facts, its
//! state, its services in dependency order, its journal, and the firewall
//! confirmation.
//!
//! Lighthouse drives Reth over the engine API on 127.0.0.1:8551. So a start
//! brings Reth up and waits for that port before Lighthouse; a stop takes
//! Lighthouse down first; a restart of Reth stops Lighthouse, restarts Reth,
//! waits for the port, then starts Lighthouse. The actions and layers are
//! Arc's ([`crate::arc::Action`], [`crate::arc::Layer`]): execution is
//! Reth, consensus is Lighthouse.

use crate::arc::{Action, Layer};

/// Reth's unit.
pub const EXECUTION_UNIT: &str = "reth";
/// Lighthouse's unit.
pub const CONSENSUS_UNIT: &str = "lighthouse";
/// The one-shot unit that fetches Reth's snapshot.
pub const SNAPSHOT_UNIT: &str = "reth-snapshot";

/// Waits up to ten minutes for Reth's engine port.
const WAIT_ENGINE: &str = "i=0; until (exec 3<>/dev/tcp/127.0.0.1/8551) 2>/dev/null; do \
     i=$((i+1)); [ $i -ge 600 ] && { echo 'Reth opened no engine port in 600 s' >&2; exit 1; }; \
     sleep 1; done";

/// The host's facts, as `key=value` lines.
pub(crate) const NODE_FACTS: &str = r#"export LC_ALL=C
. /etc/os-release 2>/dev/null
printf 'os=%s\n' "${ID:-} ${VERSION_ID:-}"
printf 'machine=%s\n' "$(uname -m)"
printf 'mem_kb=%s\n' "$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
printf 'cpus=%s\n' "$(nproc)"
printf 'x86_64_v3=%s\n' "$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -c -x -E 'avx2|bmi2|fma|movbe')"
printf 'root_free_kb=%s\n' "$(df -Pk / | awk 'NR == 2 {print $4}')"
printf 'data_free_kb=%s\n' "$(df -Pk /var/lib/ethereum 2>/dev/null | awk 'NR == 2 {print $4}')"
printf 'controller=%s\n' "${SSH_CLIENT%% *}"
printf 'ssh_port=%s\n' "$(echo "$SSH_CONNECTION" | awk '{print $4}')"
printf 'sudo=%s\n' "$(sudo -n true 2>/dev/null && echo yes || echo no)"
true"#;

/// The node's state, as `key=value` lines; RPC answers are the raw JSON.
/// It asks only the node's own loopback ports.
pub(crate) fn status() -> String {
    format!(
        r#"export LC_ALL=C
rpc() {{ curl -s -m 5 -H 'Content-Type: application/json' -d "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}}" http://127.0.0.1:8545 2>/dev/null; }}
beacon() {{ local p="$1"; curl -s -m 10 "http://127.0.0.1:5052/${{p#/}}" 2>/dev/null; }}
for u in {EXECUTION_UNIT} {CONSENSUS_UNIT} {SNAPSHOT_UNIT} erpc-eth-firewall; do printf 'unit_%s=%s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)"; done
printf 'current=%s\n' "$(readlink /opt/ethereum/current 2>/dev/null)"
printf 'client_version=%s\n' "$(rpc web3_clientVersion)"
printf 'chain_id=%s\n' "$(rpc eth_chainId)"
printf 'head=%s\n' "$(rpc eth_blockNumber)"
printf 'syncing=%s\n' "$(rpc eth_syncing)"
printf 'peers=%s\n' "$(rpc net_peerCount)"
printf 'cl_syncing=%s\n' "$(beacon /eth/v1/node/syncing)"
printf 'cl_peers=%s\n' "$(beacon /eth/v1/node/peer_count)"
printf 'cl_head_block=%s\n' "$(beacon /eth/v2/beacon/blocks/head | jq -r '.data.message.body.execution_payload.block_number // empty' 2>/dev/null)"
printf 'data_used_kb=%s\n' "$(df -Pk /var/lib/ethereum 2>/dev/null | awk 'NR == 2 {{print $3}}')"
printf 'data_free_kb=%s\n' "$(df -Pk /var/lib/ethereum 2>/dev/null | awk 'NR == 2 {{print $4}}')"
printf 'mem_execution=%s\n' "$(systemctl show -p MemoryCurrent --value {EXECUTION_UNIT} 2>/dev/null)"
printf 'mem_consensus=%s\n' "$(systemctl show -p MemoryCurrent --value {CONSENSUS_UNIT} 2>/dev/null)"
printf 'restarts_execution=%s\n' "$(systemctl show -p NRestarts --value {EXECUTION_UNIT} 2>/dev/null)"
printf 'restarts_consensus=%s\n' "$(systemctl show -p NRestarts --value {CONSENSUS_UNIT} 2>/dev/null)"
printf 'since_execution=%s\n' "$(systemctl show -p ActiveEnterTimestamp --value {EXECUTION_UNIT} 2>/dev/null)"
printf 'firewall_table=%s\n' "$(sudo -n nft list table inet erpc_eth >/dev/null 2>&1 && echo yes || echo no)"
printf 'firewall_armed=%s\n' "$(sudo -n test -e /etc/erpc/eth/pending.json && echo yes || echo no)"
printf 'firewall_revoked=%s\n' "$(sudo -n test -e /etc/erpc/eth/startup-revoked && echo yes || echo no)"
printf 'jwt=%s\n' "$(sudo -n test -e /etc/ethereum/jwt.hex && echo yes || echo no)"
printf 'snapshot=%s\n' "$(sudo -n test -e /var/lib/ethereum/reth/.erpc-snapshot-done && echo done || echo missing)"
true"#
    )
}

/// Starts, stops or restarts `layer` in dependency order.
pub(crate) fn service(action: Action, layer: Layer) -> String {
    let ctl = |verb: &str, unit: &str| format!("sudo -n systemctl {verb} {unit}");
    let parts: Vec<String> = match (action, layer) {
        // Lighthouse wants Reth's engine: starting it starts Reth first.
        (Action::Start, Layer::Both | Layer::Consensus) => vec![
            ctl("start", EXECUTION_UNIT),
            WAIT_ENGINE.to_owned(),
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
            WAIT_ENGINE.to_owned(),
            ctl("start", CONSENSUS_UNIT),
        ],
        (Action::Restart, Layer::Consensus) => vec![ctl("restart", CONSENSUS_UNIT)],
    };
    parts.join(" && ")
}

/// The journal of `layer`; `both` includes the snapshot download.
pub(crate) fn logs(layer: Layer, lines: u32, follow: bool) -> String {
    let units: &[&str] = match layer {
        Layer::Execution => &[EXECUTION_UNIT],
        Layer::Consensus => &[CONSENSUS_UNIT],
        Layer::Both => &[EXECUTION_UNIT, CONSENSUS_UNIT, SNAPSHOT_UNIT],
    };
    let units: Vec<String> = units.iter().map(|u| format!("-u {u}")).collect();
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} {}{}",
        units.join(" "),
        if follow { " -f" } else { "" }
    )
}

/// Runs the firewall confirmation helper.
pub(crate) fn confirm_firewall(token: &crate::firewall::FirewallToken) -> String {
    format!(
        "sudo -n python3 /usr/local/lib/erpc/rpc-firewall.py eth confirm {} {}",
        token.run.as_str(),
        token.bundle
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{NODE_FACTS, confirm_firewall};
    use super::{logs, service, status};
    use crate::arc::{Action, Layer};

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
        valid_shell(NODE_FACTS);
        valid_shell(&status());
        for action in [Action::Start, Action::Stop, Action::Restart] {
            for layer in [Layer::Execution, Layer::Consensus, Layer::Both] {
                valid_shell(&service(action, layer));
            }
        }
        valid_shell(&logs(Layer::Both, 100, true));
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
            "stop lighthouse",
            "restart reth",
            "8551",
            "start lighthouse",
        ]
        .iter()
        .map(|s| restart.find(s).expect(s))
        .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{restart}");
        let stop = service(Action::Stop, Layer::Both);
        assert!(stop.find("stop lighthouse") < stop.find("stop reth"));
        assert_eq!(
            service(Action::Restart, Layer::Consensus),
            "sudo -n systemctl restart lighthouse"
        );
    }

    #[test]
    fn the_status_asks_only_the_nodes_own_ports() {
        let line = status();
        let urls: Vec<&str> = line
            .split(['\'', ' ', '"'])
            .filter(|w| w.starts_with("http"))
            .collect();
        assert!(
            urls.iter()
                .all(|u| *u == "http://127.0.0.1:8545" || u.starts_with("http://127.0.0.1:5052")),
            "{urls:?}"
        );
    }

    #[test]
    fn logs_follow_only_when_asked_and_name_the_units() {
        assert_eq!(
            logs(Layer::Consensus, 50, false),
            "sudo -n journalctl --no-pager -o short-iso -n 50 -u lighthouse"
        );
        assert!(logs(Layer::Both, 10, true).ends_with("-u reth-snapshot -f"));
    }
}
