// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed Nitro follower and assertion-validator commands. Custody uses stdin only.

/// Journal request, with no user-controlled unit name or signing material.
pub(crate) fn logs(robinhood: bool, lines: u32, follow: bool) -> String {
    let family = if robinhood { "robinhood" } else { "arbitrum" };
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} -u erpc-{family}-nitro -u erpc-{family}-upstreams{}",
        if follow { " -f" } else { "" }
    )
}

pub(crate) fn confirm(robinhood: bool, token: &crate::firewall::FirewallToken) -> String {
    let family = if robinhood { "robinhood" } else { "arbitrum" };
    format!(
        "sudo -n /usr/bin/python3 -I /usr/local/lib/erpc/rpc-firewall.py {family} confirm {} {}",
        token.run.as_str(),
        token.bundle
    )
}

pub(crate) fn public_result(run: &crate::RunId) -> String {
    let program = include_str!("nitro-validator-result.py").replace('\'', "'\\''");
    format!(
        "sudo -n /usr/bin/python3 -I -c '{program}' '{}'",
        run.as_str()
    )
}

/// Read only the completed, request-bound Robinhood admission result.
pub(crate) fn robinhood_admission_result(run: &crate::RunId) -> String {
    let program = include_str!("nitro-validator-result.py").replace('\'', "'\\''");
    format!(
        "sudo -n /usr/bin/python3 -I -c '{program}' '{}' robinhood-admission",
        run.as_str()
    )
}

pub(crate) fn private_stage(
    run: &crate::RunId,
    bundle: &str,
    helpers: &str,
    request: &str,
) -> String {
    if [bundle, helpers, request].iter().any(|value| {
        value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return "printf '%s\\n' 'Original custody stage hashes are invalid' >&2; exit 1".into();
    }
    let program = include_str!("nitro-validator-stage.py").replace('\'', "'\\''");
    format!(
        "sudo -n /usr/bin/python3 -I -c '{program}' '{}' '{bundle}' '{helpers}' '{request}'",
        run.as_str()
    )
}

pub(crate) fn robinhood_validator_result(run: &crate::RunId) -> String {
    let program = include_str!("nitro-validator-result.py").replace('\'', "'\\''");
    format!(
        "sudo -n /usr/bin/python3 -I -c '{program}' '{}' robinhood-defensive",
        run.as_str()
    )
}

pub(crate) fn robinhood_private_stage(
    testnet: bool,
    run: &crate::RunId,
    bundle: &str,
    helpers: &str,
    request: &str,
) -> String {
    let command = private_stage(run, bundle, helpers, request);
    let profile = if testnet {
        "robinhood-testnet"
    } else {
        "robinhood-mainnet"
    };
    format!("{command} {profile}")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn public_result_reader_authenticates_actual_generated_entrypoint() {
        use std::io::Write;
        let run = crate::RunId::new("r-public-fixture").unwrap();
        for command in [
            crate::RemoteCommand::NitroValidatorResult(run.clone()),
            crate::RemoteCommand::RobinhoodValidatorResult(run.clone()),
            crate::RemoteCommand::RobinhoodAdmissionResult(run),
        ] {
            let line = command.line();
            let mut child = std::process::Command::new("python3")
                .arg("-I")
                .arg("-B")
                .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/nitro_result.py"))
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(line.as_bytes())
                .unwrap();
            assert!(child.wait().unwrap().success());
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_stage_uses_the_completed_exact_carried_profile_before_reading_secret_stdin() {
        use std::io::Write as _;
        let command = crate::RemoteCommand::NitroValidatorStage {
            run: crate::RunId::new("r-private-fixture").unwrap(),
            bundle: "a".repeat(64),
            helpers: "b".repeat(64),
            request: "c".repeat(64),
        }
        .line();
        let commands = [
            command,
            crate::RemoteCommand::RobinhoodValidatorStage {
                testnet: false,
                run: crate::RunId::new("r-private-fixture").unwrap(),
                bundle: "a".repeat(64),
                helpers: "b".repeat(64),
                request: "c".repeat(64),
            }
            .line(),
            crate::RemoteCommand::RobinhoodValidatorStage {
                testnet: true,
                run: crate::RunId::new("r-private-fixture").unwrap(),
                bundle: "a".repeat(64),
                helpers: "b".repeat(64),
                request: "c".repeat(64),
            }
            .line(),
        ];
        for command in commands {
            let mut child = std::process::Command::new("python3")
                .args(["-I", "-B"])
                .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/nitro_stage.py"))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(command.as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        assert!(
            !super::private_stage(
                &crate::RunId::new("r-private-fixture").unwrap(),
                "bad",
                &"b".repeat(64),
                &"c".repeat(64)
            )
            .contains("python3")
        );
    }

    #[test]
    fn control_has_no_secret_arguments() {
        let validator = crate::RemoteCommand::NitroValidatorControl.line();
        assert!(validator.contains("/usr/local/lib/erpc/arbitrum-validator/control.py"));
        assert!(!validator.contains("secret"));
        assert!(
            validator.find("trusted_imports(").unwrap()
                < validator.find("runpy.run_path(").unwrap()
        );
        let command = crate::RemoteCommand::NitroControl.line();
        assert!(command.starts_with("sudo -n /usr/bin/python3 -I -c '"));
        assert!(command.contains(&include_str!("python-trust.py").replace('\'', "'\\''")));
        assert!(
            command.find("trusted_imports(").unwrap() < command.find("runpy.run_path(").unwrap()
        );
        assert!(command.contains("/usr/local/lib/erpc/nitro-control"));
        assert!(!super::logs(false, 10, false).ends_with(" -f"));
        assert!(super::logs(true, 10, true).ends_with(" -f"));
    }
}
