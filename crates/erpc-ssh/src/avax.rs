// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed Avalanche SSH operations. Secret bundles use pipes, never argv or journals.
use crate::arc::Action;
/// Immutable, public remote ownership contract. Booleans prevent shell injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contract {
    /// Mainnet rather than Fuji.
    pub mainnet: bool,
    /// Explicit Primary Network validator intent.
    pub validator: bool,
    /// C-Chain archive rather than pruned history.
    pub archive: bool,
}
impl Contract {
    /// Check ownership immediately before fixed remote operations.
    pub(crate) fn check(self, allow_missing: bool) -> String {
        let network = if self.mainnet { "mainnet" } else { "fuji" };
        let kind = if self.archive { "archive" } else { "full" };
        let validator = if self.validator { "True" } else { "False" };
        let missing = if allow_missing { "True" } else { "False" };
        format!(
            r#"sudo -n python3 -c 'import json,pathlib,sys
p=pathlib.Path("/etc/avalanchego/contract.json")
expected={{"network":"{network}","validator":{validator},"type":"{kind}"}}
if p.is_file():
    ok=json.loads(p.read_text())==expected
else:
    ok={missing} and not any(pathlib.Path(x).exists() for x in ["/etc/systemd/system/avalanchego.service","/etc/systemd/system/avalanche-rpc.service","/var/lib/avalanchego/db"]) and not any(pathlib.Path("/var/lib/avalanchego/staking").glob("*"))
if not ok:
    print("Avalanche host contract mismatch or missing; operation refused",file=sys.stderr)
    sys.exit(1)
'"#
        )
    }
}
/// Identity operations with fixed paths; no caller-supplied remote shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAction {
    /// Read public file digests.
    Hashes,
    /// Export to in-memory concealed storage.
    Backup,
    /// Restore from stdin on the same stopped host.
    Restore,
}
/// Fixed command for an identity operation.
pub(crate) fn identity(action: IdentityAction, contract: Contract) -> String {
    let action = match action {
        IdentityAction::Hashes => "hashes",
        IdentityAction::Backup => "backup",
        IdentityAction::Restore => "restore",
    };
    format!(
        "{} && sudo -n python3 /usr/local/lib/erpc/avax-identity.py {action}",
        contract.check(false)
    )
}
/// Status never prints private files.
pub(crate) fn status() -> String {
    format!(
        "python3 - <<'ERPC_AVAX_STATUS'\n{}\nERPC_AVAX_STATUS",
        include_str!("avax_status.py")
    )
}
/// Start/stop both services in dependency order.
pub(crate) fn service(action: Action, contract: Contract) -> String {
    let operation = match action {
        Action::Start => {
            "sudo -n systemctl start avalanchego && sudo -n systemctl start avalanche-rpc"
        }
        Action::Stop => {
            "sudo -n systemctl stop avalanche-rpc && sudo -n systemctl stop avalanchego"
        }
        Action::Restart => {
            "sudo -n systemctl stop avalanche-rpc && sudo -n systemctl restart avalanchego && sudo -n systemctl start avalanche-rpc"
        }
    };
    format!("{} && {operation}", contract.check(false))
}
/// The client journal only; identity operations never enter it.
pub(crate) fn logs(lines: u32, follow: bool) -> String {
    format!(
        "sudo -n journalctl --no-pager -o short-iso -u avalanchego -u avalanche-rpc -n {lines}{}",
        if follow { " -f" } else { "" }
    )
}
/// Caller-owned immutable operation token for firewall confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallToken {
    run: crate::RunId,
    bundle: String,
}
impl FirewallToken {
    /// Bind confirmation to the run and exact bundle submitted by this caller.
    /// # Errors
    /// Rejects malformed SHA-256, preventing shell interpolation of unchecked input.
    pub fn new(run: crate::RunId, bundle: &str) -> Result<Self, String> {
        if bundle.len() != 64
            || !bundle
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid firewall bundle digest".into());
        }
        Ok(Self {
            run,
            bundle: bundle.into(),
        })
    }
}
/// Confirm only the intended run, after checking host ownership again.
pub(crate) fn confirm(contract: Contract, token: &FirewallToken) -> String {
    format!(
        "{} && sudo -n python3 /usr/local/lib/erpc/avax-firewall.py confirm {} {}",
        contract.check(false),
        token.run.as_str(),
        token.bundle
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn contract_rejection_precedes_every_fixed_mutator() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path();
        std::fs::write(
            path.join("contract.json"),
            r#"{"network":"mainnet","validator":false,"type":"full"}"#,
        )
        .unwrap();
        let calls = path.join("calls");
        let ctl = path.join("systemctl");
        std::fs::write(
            &ctl,
            format!("#!/bin/sh\necho called >> '{}'\n", calls.display()),
        )
        .unwrap();
        std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o700)).unwrap();
        let good = Contract {
            mainnet: true,
            validator: false,
            archive: false,
        };
        let execute = |command: String| {
            let command = command
                .replace("sudo -n ", "")
                .replace(
                    "/usr/local/lib/erpc",
                    path.join("helpers").to_str().unwrap(),
                )
                .replace(
                    "/etc/avalanchego/contract.json",
                    path.join("contract.json").to_str().unwrap(),
                );
            std::process::Command::new("bash")
                .args(["-c", &command])
                .env(
                    "PATH",
                    format!(
                        "{}:{}",
                        path.display(),
                        std::env::var("PATH").unwrap_or_default()
                    ),
                )
                .output()
                .unwrap()
        };
        for wrong in [
            Contract {
                mainnet: false,
                ..good
            },
            Contract {
                validator: true,
                ..good
            },
            Contract {
                archive: true,
                ..good
            },
        ] {
            let mut commands = vec![
                wrong.check(true),
                confirm(
                    wrong,
                    &FirewallToken::new(
                        crate::RunId::new("r-20261026t120000-abc123").unwrap(),
                        &"a".repeat(64),
                    )
                    .unwrap(),
                ),
                identity(IdentityAction::Backup, wrong),
                identity(IdentityAction::Restore, wrong),
            ];
            for action in [Action::Start, Action::Stop, Action::Restart] {
                commands.push(service(action, wrong));
            }
            for command in commands {
                let output = execute(command);
                assert!(!output.status.success());
                assert!(String::from_utf8_lossy(&output.stderr).contains("contract mismatch"));
                assert!(
                    !calls.exists(),
                    "a mismatched operation reached service control"
                );
            }
        }
        assert!(execute(service(Action::Stop, good)).status.success());
        assert_eq!(std::fs::read_to_string(calls).unwrap().lines().count(), 2);
    }
}
