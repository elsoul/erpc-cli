// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A finished check as the customer reads it: each finding's text from this
//! program's own catalog, with the details it points to filled in from the
//! report and from what was read on this server.

use std::fmt::Write as _;

use erpc_api::security_check::{
    Advisory, Coverage, ExternalCoverage, Finding, FindingId, Inventory, PathKind, Ref, RefSource,
    Report, Server, ServerId, Severity,
};
use serde_json::{Value, json};

/// The report for a terminal.
pub(crate) fn render(report: &Report, server: &Server, inventory: &Inventory) -> String {
    let mut out = t!(
        "security_check.report.title",
        label = server.label.as_str(),
        address = server.address
    );
    out.push('\n');
    match report.coverage.external {
        ExternalCoverage::Complete => {}
        ExternalCoverage::Partial => line(&mut out, &t!("security_check.report.external_partial")),
        ExternalCoverage::Failed => line(&mut out, &t!("security_check.report.external_failed")),
    }
    if report.coverage.local != Coverage::Complete {
        line(&mut out, &t!("security_check.report.local_partial"));
    }
    if report.findings.is_empty() {
        line(&mut out, &t!("security_check.report.none"));
    }
    for (index, finding) in report.findings.iter().enumerate() {
        out.push('\n');
        let _ = writeln!(
            out,
            "{}. [{}] {}",
            index + 1,
            severity(finding.severity),
            describe(finding.id)
        );
        for reference in &finding.refs {
            let _ = writeln!(out, "   - {}", detail(*reference, report, inventory));
        }
        if !finding.advisories.is_empty() {
            let list: Vec<&str> = finding.advisories.iter().map(Advisory::as_str).collect();
            let _ = writeln!(
                out,
                "   {}",
                t!("security_check.report.advisories", list = list.join(", "))
            );
        }
        let _ = writeln!(
            out,
            "   {}",
            t!("security_check.report.fix", fix = fix(finding.id))
        );
    }
    if !report.paths.is_empty() {
        out.push('\n');
        line(&mut out, &t!("security_check.report.paths"));
        for path in &report.paths {
            let steps: Vec<String> = path.steps.iter().map(|s| (s + 1).to_string()).collect();
            let _ = writeln!(out, "  {}: {}", path_kind(path.kind), steps.join(" → "));
        }
    }
    out.push('\n');
    out.push_str(&t!("security_check.report.limits"));
    out
}

fn line(out: &mut String, text: &str) {
    out.push_str(text);
    out.push('\n');
}

/// The report for a program: ids, severities and references, without the
/// details read on this server.
pub(crate) fn json(report: &Report, server: &ServerId) -> Value {
    let findings: Vec<Value> = report
        .findings
        .iter()
        .map(|f: &Finding| {
            json!({
                "id": f.id.wire(),
                "severity": f.severity.wire(),
                "refs": f.refs.iter().map(|r| json!({"source": r.source.wire(), "index": r.index})).collect::<Vec<_>>(),
                "advisories": f.advisories.iter().map(Advisory::as_str).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "check": erpc_api::security_check::CHECK,
        "server": server.as_str(),
        "coverage": {
            "external": report.coverage.external.wire(),
            "local": report.coverage.local.wire(),
        },
        "findings": findings,
        "paths": report.paths.iter().map(|p| json!({"kind": p.kind.wire(), "steps": p.steps})).collect::<Vec<_>>(),
    })
}

fn severity(severity: Severity) -> String {
    match severity {
        Severity::Critical => t!("security_check.severity.critical"),
        Severity::High => t!("security_check.severity.high"),
        Severity::Medium => t!("security_check.severity.medium"),
        Severity::Low => t!("security_check.severity.low"),
        Severity::Info => t!("security_check.severity.info"),
    }
}

fn path_kind(kind: PathKind) -> String {
    match kind {
        PathKind::RemoteCodeExecution => t!("security_check.path.remote_code_execution"),
        PathKind::FundTheft => t!("security_check.path.fund_theft"),
        PathKind::ValidatorTakeover => t!("security_check.path.validator_takeover"),
        PathKind::ServiceDisruption => t!("security_check.path.service_disruption"),
        PathKind::DataExposure => t!("security_check.path.data_exposure"),
    }
}

/// One detail a finding points to. The reply was checked against the
/// inventory, so an index out of range cannot reach here; it reads as
/// nothing if it did.
fn detail(reference: Ref, report: &Report, inventory: &Inventory) -> String {
    let at = usize::from(reference.index);
    let found = match reference.source {
        RefSource::ExternalTcp => report.external.tcp.get(at).map(|p| {
            t!(
                "security_check.detail.external_tcp",
                port = p.port,
                service = p.service.wire()
            )
        }),
        RefSource::ExternalUdp => report.external.udp.get(at).map(|p| {
            t!(
                "security_check.detail.external_udp",
                port = p.port,
                service = p.service.wire()
            )
        }),
        RefSource::Listener => inventory.listeners.items().get(at).map(|l| {
            t!(
                "security_check.detail.listener",
                proto = l.proto.wire(),
                port = l.port,
                bind = l.bind.wire(),
                app = l.app.wire()
            )
        }),
        RefSource::Solana => inventory.solana.items().get(at).map(|n| match n.rpc_port {
            Some(port) => t!("security_check.detail.solana", app = n.app.wire(), port),
            None => t!("security_check.detail.solana_no_rpc", app = n.app.wire()),
        }),
        RefSource::Ssh => Some(t!("security_check.detail.ssh")),
        RefSource::Firewall => Some(t!(
            "security_check.detail.firewall",
            tool = inventory.firewall.tool.wire()
        )),
        RefSource::Package => inventory.packages.items().get(at).map(|p| {
            t!(
                "security_check.detail.package",
                name = p.name.wire(),
                version = p.version.as_str()
            )
        }),
        RefSource::Key => inventory.keys.items().get(at).map(|k| {
            t!(
                "security_check.detail.key",
                kind = k.kind.wire(),
                role = k.role.wire(),
                location = k.location.wire(),
                access = k.access.wire(),
                count = k.count
            )
        }),
    };
    found.unwrap_or_default()
}

fn describe(id: FindingId) -> String {
    match id {
        FindingId::SolanaRpcPublic => t!("security_check.finding.solana_rpc_public"),
        FindingId::SolanaFullRpcApiPublic => {
            t!("security_check.finding.solana_full_rpc_api_public")
        }
        FindingId::SolanaWsPublic => t!("security_check.finding.solana_ws_public"),
        FindingId::EvmRpcPublic => t!("security_check.finding.evm_rpc_public"),
        FindingId::EvmAdminApiPublic => t!("security_check.finding.evm_admin_api_public"),
        FindingId::DockerApiPublic => t!("security_check.finding.docker_api_public"),
        FindingId::DatabasePublic => t!("security_check.finding.database_public"),
        FindingId::RedisNoAuthPublic => t!("security_check.finding.redis_no_auth_public"),
        FindingId::MetricsPublic => t!("security_check.finding.metrics_public"),
        FindingId::UnknownServicePublic => t!("security_check.finding.unknown_service_public"),
        FindingId::TlsLegacyProtocol => t!("security_check.finding.tls_legacy_protocol"),
        FindingId::SshPasswordAuth => t!("security_check.finding.ssh_password_auth"),
        FindingId::SshRootLogin => t!("security_check.finding.ssh_root_login"),
        FindingId::NoHostFirewall => t!("security_check.finding.no_host_firewall"),
        FindingId::DockerBypassesFirewall => t!("security_check.finding.docker_bypasses_firewall"),
        FindingId::WildcardListenerExposed => {
            t!("security_check.finding.wildcard_listener_exposed")
        }
        FindingId::PackageVulnerable => t!("security_check.finding.package_vulnerable"),
        FindingId::OsEndOfLife => t!("security_check.finding.os_end_of_life"),
        FindingId::PlaintextWalletKey => t!("security_check.finding.plaintext_wallet_key"),
        FindingId::KeyWorldReadable => t!("security_check.finding.key_world_readable"),
        FindingId::WithdrawAuthorityOnServer => {
            t!("security_check.finding.withdraw_authority_on_server")
        }
        FindingId::ValidatorIdentityPermissions => {
            t!("security_check.finding.validator_identity_permissions")
        }
        FindingId::MnemonicOnDisk => t!("security_check.finding.mnemonic_on_disk"),
        FindingId::UnencryptedKeystore => t!("security_check.finding.unencrypted_keystore"),
        FindingId::SecretInEnvFile => t!("security_check.finding.secret_in_env_file"),
        FindingId::SecretInProcessEnv => t!("security_check.finding.secret_in_process_env"),
        FindingId::SecretInShellHistory => t!("security_check.finding.secret_in_shell_history"),
        FindingId::ScanIncomplete => t!("security_check.finding.scan_incomplete"),
        FindingId::LocalViewPartial => t!("security_check.finding.local_view_partial"),
    }
}

fn fix(id: FindingId) -> String {
    match id {
        FindingId::SolanaRpcPublic => t!("security_check.fix.solana_rpc_public"),
        FindingId::SolanaFullRpcApiPublic => t!("security_check.fix.solana_full_rpc_api_public"),
        FindingId::SolanaWsPublic => t!("security_check.fix.solana_ws_public"),
        FindingId::EvmRpcPublic => t!("security_check.fix.evm_rpc_public"),
        FindingId::EvmAdminApiPublic => t!("security_check.fix.evm_admin_api_public"),
        FindingId::DockerApiPublic => t!("security_check.fix.docker_api_public"),
        FindingId::DatabasePublic => t!("security_check.fix.database_public"),
        FindingId::RedisNoAuthPublic => t!("security_check.fix.redis_no_auth_public"),
        FindingId::MetricsPublic => t!("security_check.fix.metrics_public"),
        FindingId::UnknownServicePublic => t!("security_check.fix.unknown_service_public"),
        FindingId::TlsLegacyProtocol => t!("security_check.fix.tls_legacy_protocol"),
        FindingId::SshPasswordAuth => t!("security_check.fix.ssh_password_auth"),
        FindingId::SshRootLogin => t!("security_check.fix.ssh_root_login"),
        FindingId::NoHostFirewall => t!("security_check.fix.no_host_firewall"),
        FindingId::DockerBypassesFirewall => t!("security_check.fix.docker_bypasses_firewall"),
        FindingId::WildcardListenerExposed => t!("security_check.fix.wildcard_listener_exposed"),
        FindingId::PackageVulnerable => t!("security_check.fix.package_vulnerable"),
        FindingId::OsEndOfLife => t!("security_check.fix.os_end_of_life"),
        FindingId::PlaintextWalletKey => t!("security_check.fix.plaintext_wallet_key"),
        FindingId::KeyWorldReadable => t!("security_check.fix.key_world_readable"),
        FindingId::WithdrawAuthorityOnServer => {
            t!("security_check.fix.withdraw_authority_on_server")
        }
        FindingId::ValidatorIdentityPermissions => {
            t!("security_check.fix.validator_identity_permissions")
        }
        FindingId::MnemonicOnDisk => t!("security_check.fix.mnemonic_on_disk"),
        FindingId::UnencryptedKeystore => t!("security_check.fix.unencrypted_keystore"),
        FindingId::SecretInEnvFile => t!("security_check.fix.secret_in_env_file"),
        FindingId::SecretInProcessEnv => t!("security_check.fix.secret_in_process_env"),
        FindingId::SecretInShellHistory => t!("security_check.fix.secret_in_shell_history"),
        FindingId::ScanIncomplete => t!("security_check.fix.scan_incomplete"),
        FindingId::LocalViewPartial => t!("security_check.fix.local_view_partial"),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use erpc_api::security_check::{
        App, Bind, Coverage, FindingId, Firewall, FirewallTool, Inventory, Listener, Listeners, Os,
        OsFamily, Owner, Package, Packages, PathKind, Policy, Proto, Report, RootLogin, Server,
        Severity, SolanaNodes, Ssh, Token, Tristate,
    };
    use erpc_core::i18n::Lang;
    use serde_json::json;

    fn inventory() -> Inventory {
        Inventory {
            privileged: false,
            os: Os {
                coverage: Coverage::Complete,
                family: OsFamily::Ubuntu,
                version: Token::new("24.04"),
                kernel: None,
            },
            listeners: Listeners::new(
                Coverage::Partial,
                vec![Listener {
                    proto: Proto::Tcp,
                    port: NonZeroU16::new(2375).unwrap_or(NonZeroU16::MIN),
                    bind: Bind::Wildcard,
                    app: App::Dockerd,
                    owner: Owner::Root,
                    docker: false,
                }],
            ),
            solana: SolanaNodes::new(Coverage::Absent, Vec::new()),
            ssh: Ssh {
                coverage: Coverage::Complete,
                password_auth: Tristate::Yes,
                root_login: RootLogin::No,
                kbd_interactive: Tristate::No,
                ports: erpc_api::security_check::Bounded::default(),
            },
            firewall: Firewall {
                coverage: Coverage::Complete,
                tool: FirewallTool::Ufw,
                enabled: Tristate::No,
                input_policy: Policy::Drop,
            },
            packages: Packages::new(
                Coverage::Complete,
                vec![Package {
                    name: erpc_api::security_check::PackageName::OpensshServer,
                    version: Token::new("1:9.6p1-3ubuntu13.4").unwrap_or_else(|| panic!("token")),
                }],
            ),
            keys: erpc_api::security_check::Keys::unreadable(),
        }
    }

    fn parse<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
        serde_json::from_value(value).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn a_report_reads_with_its_details_fixes_and_paths() {
        let server: Server = parse(json!({"id": "vps:9", "kind": "vps", "label": "trader",
            "address": "203.0.113.9", "region": "Frankfurt"}));
        let report: Report = parse(json!({
            "check": "server_security_v1", "server": "vps:9",
            "coverage": {"external": "partial", "local": "partial"},
            "external": {"tcp": [{"port": 2375, "service": "docker_api", "tls": false}], "udp": []},
            "findings": [
                {"id": "docker_api_public", "severity": "critical",
                 "refs": [{"source": "external_tcp", "index": 0}, {"source": "listener", "index": 0}], "advisories": []},
                {"id": "ssh_password_auth", "severity": "high", "refs": [{"source": "ssh", "index": 0}],
                 "advisories": []},
                {"id": "package_vulnerable", "severity": "medium", "refs": [{"source": "package", "index": 0}],
                 "advisories": ["CVE-2024-6387"]}
            ],
            "paths": [{"kind": "remote_code_execution", "steps": [0]}]
        }));
        let text =
            crate::cli::i18n::speaking(Lang::En, || super::render(&report, &server, &inventory()));
        for expected in [
            "Security check of trader (203.0.113.9)",
            "The scan from outside covered only part of the server.",
            "Part of this server could not be read.",
            "1. [critical] The Docker Engine API answers from the internet",
            "   - TCP 2375 answers from the internet: docker_api",
            "   - tcp 2375 bound to wildcard addresses by dockerd",
            "2. [high] SSH accepts passwords",
            "   - openssh_server 1:9.6p1-3ubuntu13.4",
            "   Advisories: CVE-2024-6387",
            "   Fix: Install the security updates",
            "  running code on the server: 1",
            "It does not try exploits or passwords",
        ] {
            assert!(text.contains(expected), "{expected:?} not in:\n{text}");
        }

        let record = super::json(&report, &server.id);
        assert_eq!(record["findings"][0]["id"], "docker_api_public");
        assert_eq!(
            record["findings"][2]["advisories"],
            json!(["CVE-2024-6387"])
        );
        assert!(!record.to_string().contains("1:9.6p1"));
    }

    #[test]
    fn every_finding_has_its_own_words_in_every_language() {
        for lang in [Lang::En, Lang::Ja, Lang::Zh, Lang::Ru] {
            crate::cli::i18n::speaking(lang, || {
                let mut seen = std::collections::HashSet::new();
                for id in FindingId::ALL {
                    let text = super::describe(*id);
                    assert!(
                        !text.is_empty() && seen.insert(text.clone()),
                        "{lang:?} {id:?}"
                    );
                    assert!(!super::fix(*id).is_empty(), "{lang:?} {id:?}");
                }
                for severity in Severity::ALL {
                    assert!(!super::severity(*severity).is_empty());
                }
                for kind in PathKind::ALL {
                    assert!(!super::path_kind(*kind).is_empty());
                }
            });
        }
    }
}
