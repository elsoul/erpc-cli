// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The host firewall, as its configuration states it. The rules the kernel
//! holds now are not read; the scan from outside shows what they let in.

use std::path::Path;

use erpc_api::security_check::{Coverage, Firewall, FirewallTool, Policy, Tristate};

const FILE_LIMIT: u64 = 1024 * 1024;

fn read_file(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(FILE_LIMIT)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

fn enabled_unit(root: &Path, unit: &str) -> Tristate {
    let wanted = ["multi-user.target.wants", "sysinit.target.wants"]
        .iter()
        .any(|target| {
            root.join("etc/systemd/system")
                .join(target)
                .join(unit)
                .exists()
        });
    if wanted {
        Tristate::Yes
    } else {
        Tristate::Unknown
    }
}

/// The firewall configured under `root`.
pub(super) fn read(root: &Path) -> Firewall {
    if root.join("etc/ufw").is_dir() {
        return ufw(root);
    }
    if root.join("etc/firewalld/firewalld.conf").is_file() {
        return Firewall {
            coverage: Coverage::Partial,
            tool: FirewallTool::Firewalld,
            enabled: enabled_unit(root, "firewalld.service"),
            input_policy: Policy::Unknown,
        };
    }
    if let Some(config) = read_file(&root.join("etc/nftables.conf")) {
        return Firewall {
            coverage: Coverage::Partial,
            tool: FirewallTool::Nftables,
            enabled: enabled_unit(root, "nftables.service"),
            input_policy: nft_input_policy(&config),
        };
    }
    let iptables = read_file(&root.join("proc/net/ip_tables_names"))
        .is_some_and(|tables| !tables.trim().is_empty());
    Firewall {
        coverage: Coverage::Partial,
        tool: if iptables {
            FirewallTool::Iptables
        } else {
            FirewallTool::Unknown
        },
        enabled: Tristate::Unknown,
        input_policy: Policy::Unknown,
    }
}

fn ufw(root: &Path) -> Firewall {
    let value = |text: &str, key: &str| {
        text.lines().find_map(|line| {
            let (k, v) = line.trim().split_once('=')?;
            (k.trim() == key).then(|| v.trim().trim_matches('"').to_ascii_lowercase())
        })
    };
    let conf = read_file(&root.join("etc/ufw/ufw.conf"));
    let defaults = read_file(&root.join("etc/default/ufw"));
    let enabled = match conf.as_deref().and_then(|c| value(c, "ENABLED")).as_deref() {
        Some("yes") => Tristate::Yes,
        Some("no") => Tristate::No,
        _ => Tristate::Unknown,
    };
    let input_policy = match defaults
        .as_deref()
        .and_then(|d| value(d, "DEFAULT_INPUT_POLICY"))
        .as_deref()
    {
        Some("drop") => Policy::Drop,
        Some("reject") => Policy::Reject,
        Some("accept") => Policy::Accept,
        _ => Policy::Unknown,
    };
    Firewall {
        coverage: if conf.is_some() && defaults.is_some() {
            Coverage::Complete
        } else {
            Coverage::Partial
        },
        tool: FirewallTool::Ufw,
        enabled,
        input_policy,
    }
}

/// The policy of the first chain hooked to input, without a policy
/// statement meaning accept.
fn nft_input_policy(config: &str) -> Policy {
    let mut in_input = false;
    for statement in config.split(['\n', ';', '{']) {
        let statement = statement.trim();
        if statement.starts_with("chain ") {
            in_input = false;
        }
        if statement.contains("hook input") {
            in_input = true;
            if let Some(policy) = statement.split("policy").nth(1) {
                return policy_word(policy);
            }
            continue;
        }
        if in_input {
            if let Some(policy) = statement.strip_prefix("policy") {
                return policy_word(policy);
            }
            if statement.starts_with('}') {
                return Policy::Accept;
            }
        }
    }
    Policy::Unknown
}

fn policy_word(text: &str) -> Policy {
    match text.trim().trim_end_matches(';').trim() {
        "drop" => Policy::Drop,
        "accept" => Policy::Accept,
        _ => Policy::Unknown,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use erpc_api::security_check::{Coverage, FirewallTool, Policy, Tristate};

    use super::{nft_input_policy, read};

    #[test]
    fn ufw_is_read_from_its_two_files() {
        let root = crate::node::security::fixture("ufw");
        std::fs::create_dir_all(root.join("etc/ufw")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir_all(root.join("etc/default")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(
            root.join("etc/ufw/ufw.conf"),
            "# comment\nENABLED=yes\nLOGLEVEL=low\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(
            root.join("etc/default/ufw"),
            "DEFAULT_INPUT_POLICY=\"DROP\"\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let firewall = read(&root);
        assert_eq!(
            (
                firewall.coverage,
                firewall.tool,
                firewall.enabled,
                firewall.input_policy
            ),
            (
                Coverage::Complete,
                FirewallTool::Ufw,
                Tristate::Yes,
                Policy::Drop
            )
        );
        std::fs::remove_file(root.join("etc/default/ufw")).unwrap_or_else(|e| panic!("{e}"));
        let firewall = read(&root);
        assert_eq!(
            (firewall.coverage, firewall.input_policy),
            (Coverage::Partial, Policy::Unknown)
        );
        let _ = std::fs::remove_dir_all(&root);

        let none = crate::node::security::fixture("no-firewall");
        let firewall = read(&none);
        assert_eq!(
            (firewall.coverage, firewall.tool, firewall.enabled),
            (Coverage::Partial, FirewallTool::Unknown, Tristate::Unknown)
        );
        let _ = std::fs::remove_dir_all(&none);
    }

    #[test]
    fn nftables_input_policy_is_the_input_chains() {
        let drop = "table inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n  tcp dport 22 accept\n }\n chain output { type filter hook output priority 0; policy accept; }\n}\n";
        assert_eq!(nft_input_policy(drop), Policy::Drop);
        let default = "table inet filter {\n chain input {\n  type filter hook input priority filter;\n }\n}\n";
        assert_eq!(nft_input_policy(default), Policy::Accept);
        let split = "table inet t {\n chain input {\n  type filter hook input priority 0\n  policy drop\n }\n}\n";
        assert_eq!(nft_input_policy(split), Policy::Drop);
        assert_eq!(nft_input_policy("flush ruleset\n"), Policy::Unknown);
    }
}
