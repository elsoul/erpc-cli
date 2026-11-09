// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The commands a Solana RPC node is sent outside a play: its state, its
//! services, its logs, and the firewall confirmation.
//!
//! They run as `solv`, which `create_user` gives sudo without a password.
//! The validator is the `solv` unit; Old Faithful is `faithful`.

use crate::arc::Action;

/// Where agave writes the validator's log.
pub const VALIDATOR_LOG: &str = "/home/solv/solana-validator.log";

/// Which service a command is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// The validator.
    Validator,
    /// Old Faithful.
    Faithful,
}

impl Service {
    const fn unit(self) -> &'static str {
        match self {
            Self::Validator => "solv",
            Self::Faithful => "faithful",
        }
    }
}

/// What `logs` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    /// The validator's own log file.
    Validator,
    /// The journal of the validator's unit: why it did not start.
    Journal,
    /// Old Faithful's journal.
    Faithful,
    /// The firewall's unit and its rollback.
    Firewall,
}

impl LogSource {
    /// From `--source`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "validator" => Some(Self::Validator),
            "journal" => Some(Self::Journal),
            "faithful" => Some(Self::Faithful),
            "firewall" => Some(Self::Firewall),
            _ => None,
        }
    }
}

/// The node's state, as `key=value` lines; RPC answers are the raw JSON.
pub(crate) fn status() -> String {
    r#"export LC_ALL=C
rpc() { curl -s -m 5 -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\"}" "$1" 2>/dev/null; }
for u in solv faithful of1-index-sync.timer erpc-solana-rpc-firewall; do printf 'unit_%s=%s\n' "${u%%.*}" "$(systemctl is-active "$u" 2>/dev/null)"; done
printf 'identity_link=%s\n' "$(readlink "$HOME/identity.json" 2>/dev/null)"
printf 'identity=%s\n' "$("$HOME/.local/share/solana/install/active_release/bin/solana-keygen" pubkey "$HOME/identity.json" 2>/dev/null | tail -n 1)"
printf 'health=%s\n' "$(rpc http://127.0.0.1:7211 getHealth)"
printf 'slot=%s\n' "$(rpc http://127.0.0.1:7211 getSlot)"
printf 'version=%s\n' "$(rpc http://127.0.0.1:7211 getVersion)"
printf 'faithful=%s\n' "$(rpc http://127.0.0.1:8888 getVersion)"
printf 'grpc_listen=%s\n' "$(ss -Hltn 'sport = :10000' 2>/dev/null | grep -q . && echo yes || echo no)"
printf 'geyser_version=%s\n' "$(curl -s -m 5 http://127.0.0.1:8999/metrics 2>/dev/null | sed -n 's/^yellowstone_grpc_geyser_version{.*version="\([^"]*\)".*/\1/p' | head -n 1)"
printf 'restarts=%s\n' "$(systemctl show -p NRestarts --value solv 2>/dev/null)"
printf 'since=%s\n' "$(systemctl show -p ActiveEnterTimestamp --value solv 2>/dev/null)"
printf 'ledger_used_kb=%s\n' "$(df -Pk /mnt/ledger 2>/dev/null | awk 'NR == 2 {print $3}')"
printf 'ledger_free_kb=%s\n' "$(df -Pk /mnt/ledger 2>/dev/null | awk 'NR == 2 {print $4}')"
printf 'accounts_free_kb=%s\n' "$(df -Pk /mnt/accounts 2>/dev/null | awk 'NR == 2 {print $4}')"
printf 'firewall_table=%s\n' "$(sudo -n nft list table inet erpc_solana_rpc >/dev/null 2>&1 && echo yes || echo no)"
printf 'firewall_armed=%s\n' "$(sudo -n test -e /etc/erpc/solana-rpc/pending.json && echo yes || echo no)"
printf 'firewall_revoked=%s\n' "$(sudo -n test -e /etc/erpc/solana-rpc/startup-revoked && echo yes || echo no)"
true"#
        .to_owned()
}

/// Starts, stops or restarts a service.
pub(crate) fn service(action: Action, service: Service) -> String {
    let verb = match action {
        Action::Start => "start",
        Action::Stop => "stop",
        Action::Restart => "restart",
    };
    format!("sudo -n systemctl {verb} {}", service.unit())
}

/// The last `lines` lines of a log, and more as they come with `follow`.
pub(crate) fn logs(source: LogSource, lines: u32, follow: bool) -> String {
    let journal = |args: &str| {
        format!(
            "sudo -n journalctl --no-pager -o short-iso -n {lines} {args}{}",
            if follow { " -f" } else { "" }
        )
    };
    match source {
        LogSource::Validator => format!(
            "tail -n {lines}{} {VALIDATOR_LOG}",
            if follow { " -F" } else { "" }
        ),
        LogSource::Journal => journal("-u solv"),
        LogSource::Faithful => journal("-u faithful -u of1-index-sync"),
        LogSource::Firewall => journal(
            "-u erpc-solana-rpc-firewall -u 'erpc-solana-rpc-firewall-rollback-*' -t erpc-solana-rpc-firewall",
        ),
    }
}

/// Runs the firewall confirmation helper.
pub(crate) fn confirm_firewall(token: &crate::firewall::FirewallToken) -> String {
    format!(
        "sudo -n /usr/bin/python3 -I /usr/local/lib/erpc/rpc-firewall.py solana-rpc confirm {} {}",
        token.run.as_str(),
        token.bundle
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::confirm_firewall;
    use super::{LogSource, Service, logs, service, status};
    use crate::arc::Action;

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
        valid_shell(&status());
        for action in [Action::Start, Action::Stop, Action::Restart] {
            valid_shell(&service(action, Service::Validator));
        }
        for source in ["validator", "journal", "faithful", "firewall"] {
            let source = LogSource::parse(source).expect("source");
            valid_shell(&logs(source, 100, true));
            valid_shell(&logs(source, 100, false));
        }
        valid_shell(&service(Action::Restart, Service::Faithful));
        valid_shell(&confirm_firewall(
            &crate::firewall::FirewallToken::new(
                crate::RunId::new("r-20261026t120000-abc123").unwrap(),
                &"a".repeat(64),
            )
            .unwrap(),
        ));
    }

    #[test]
    fn the_status_asks_only_loopback() {
        let line = status();
        let urls: Vec<&str> = line
            .split(['\'', ' ', '"'])
            .filter(|w| w.starts_with("http"))
            .collect();
        assert!(
            urls.iter().all(|u| u.starts_with("http://127.0.0.1:7211")
                || u.starts_with("http://127.0.0.1:8888")
                || u.starts_with("http://127.0.0.1:8999/metrics")),
            "{urls:?}"
        );
        assert!(line.contains("for u in solv faithful"));
        assert!(line.contains("solana-keygen\" pubkey"));
    }

    #[test]
    fn services_and_logs_name_their_units() {
        assert_eq!(
            service(Action::Stop, Service::Validator),
            "sudo -n systemctl stop solv"
        );
        assert_eq!(
            logs(LogSource::Validator, 50, false),
            "tail -n 50 /home/solv/solana-validator.log"
        );
        assert!(logs(LogSource::Journal, 10, true).ends_with("-u solv -f"));
        assert_eq!(LogSource::parse("other"), None);
    }
}
