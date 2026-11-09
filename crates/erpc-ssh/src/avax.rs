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
    /// Domain-separated digest of the stable inventory item, absent only before reservation.
    pub owner: Option<[u8; 32]>,
}
impl Contract {
    /// Public opaque host-ownership binding; never carries a vault/item locator.
    #[must_use]
    pub fn owner_label(self) -> Option<String> {
        use std::fmt::Write;
        self.owner.map(|bytes| {
            let mut value = String::with_capacity(64);
            for byte in bytes {
                let _ = write!(value, "{byte:02x}");
            }
            value
        })
    }
    /// Check ownership immediately before fixed remote operations.
    pub(crate) fn check(self, allow_missing: bool) -> String {
        let network = if self.mainnet { "mainnet" } else { "fuji" };
        let kind = if self.archive { "archive" } else { "full" };
        let validator = if self.validator { "True" } else { "False" };
        let missing = if allow_missing { "True" } else { "False" };
        let owner = self
            .owner_label()
            .map_or_else(|| "None".into(), |value| format!("\"{value}\""));
        format!(
            r#"sudo -n /usr/bin/python3 -I -c 'import json,pathlib,sys
p=pathlib.Path("/etc/avalanchego/contract.json")
expected={{"network":"{network}","validator":{validator},"type":"{kind}"}}
expected_owner={owner}
if p.is_file():
    actual=json.loads(p.read_text())
    protocol=actual.pop("authority_protocol",None)
    original=actual.pop("original_account",None)
    actual_owner=actual.pop("owner",None)
    bound=dict(expected,owner=expected_owner)
    ok=actual==expected and ((protocol is None and actual_owner is None) or (protocol==2 and expected_owner is not None and actual_owner==expected_owner and isinstance(original,dict) and original.get("contract")==bound and original.get("protocol")==2))
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
        "{} && {} {action}",
        contract.check(false),
        crate::python::avax_control()
    )
}
/// Status never prints private files.
pub(crate) fn status() -> String {
    format!("{} status", crate::python::avax_control())
}
/// Start/stop both services in dependency order.
pub(crate) fn service(action: Action, contract: Contract) -> String {
    let operation = match action {
        Action::Start => "start",
        Action::Stop => "stop",
        Action::Restart => "restart",
    };
    format!(
        "{} && {} {operation}",
        contract.check(false),
        crate::python::avax_control()
    )
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
    intent: String,
}
impl FirewallToken {
    /// Bind confirmation to the run and exact bundle submitted by this caller.
    /// # Errors
    /// Rejects malformed SHA-256, preventing shell interpolation of unchecked input.
    pub fn new(run: crate::RunId, bundle: &str, intent: &str) -> Result<Self, String> {
        if intent.len() != 32
            || !intent
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid Avalanche intent".into());
        }
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
            intent: intent.into(),
        })
    }
}
/// Confirm only the intended run, after checking host ownership again.
pub(crate) fn confirm(contract: Contract, token: &FirewallToken) -> String {
    format!(
        "{} && {} confirm {} {} {}",
        contract.check(false),
        crate::python::avax_control(),
        token.run.as_str(),
        token.bundle,
        token.intent
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
            owner: Some([1; 32]),
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
                        &"b".repeat(32),
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
        assert!(execute(good.check(false)).status.success());
        assert!(
            !calls.exists(),
            "scope verification must not invoke service control"
        );
    }
}
