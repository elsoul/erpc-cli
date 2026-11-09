// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Isolated execution compatible with installed helpers predating this CLI.

const TRUST: &str = include_str!("python-trust.py");
const RELEASE: &str = include_str!("python-release.py");

/// Build an isolated root helper command without consuming standard input.
///
/// Only root-owned real helper directories may supply sibling imports. Callers
/// append separately validated shell arguments; this prefix contains no secrets.
///
/// # Errors
/// Refuses non-absolute paths, traversal, shell syntax and paths outside erpc's
/// installed helper namespace. Runtime ancestry validation also refuses symlinks.
pub fn command(path: &str) -> Result<String, String> {
    let relative = path
        .strip_prefix("/usr/local/lib/erpc/")
        .ok_or("helper must be installed under /usr/local/lib/erpc")?;
    if !relative.split('/').all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    }) {
        return Err("invalid installed helper path".into());
    }
    let (directory, _) = path.rsplit_once('/').ok_or("missing helper directory")?;
    Ok(assemble(path, directory))
}

/// Execute through a root-owned `current` pointer to a complete immutable release.
///
/// `profiles` lists supported revisions' exact file names in their digest order.
/// The selected directory must equal the SHA-256 of those concatenated bytes.
/// Unknown pointers, target symlinks, extra files and incomplete profiles fail.
///
/// # Errors
/// Refuses invalid namespace/file names, duplicate profile members or profiles
/// that do not include the entrypoint. Runtime checks validate ownership/hash.
pub fn release_command(
    namespace: &str,
    entrypoint: &str,
    profiles: &[&[&str]],
) -> Result<String, String> {
    // Reuse the strict lexical namespace check without executing its loader.
    command(&format!("{namespace}/{entrypoint}"))?;
    let plain = |name: &str| {
        !name.is_empty()
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    };
    if !plain(entrypoint)
        || profiles.is_empty()
        || profiles.len() > 8
        || profiles.iter().any(|profile| {
            profile.is_empty()
                || profile.len() > 64
                || !profile.contains(&entrypoint)
                || profile.iter().any(|name| !plain(name))
                || profile
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != profile.len()
        })
    {
        return Err("invalid helper release profile".into());
    }
    let program = format!(
        "{TRUST}\n{RELEASE}\nimport runpy\nselected = trusted_release('{namespace}', {profiles:?})\nrunpy.run_path(selected + '/{entrypoint}', run_name='__main__')"
    );
    Ok(quoted(&program))
}

/// Build an isolated systemd command that validates the helper before execution.
/// The inline bootstrap is hex encoded to avoid unit escaping/specifier syntax.
/// # Errors
/// Refuses the same unsupported helper paths as [`command`].
pub fn systemd_command(path: &str) -> Result<String, String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    command(path)?;
    let (directory, _) = path.rsplit_once('/').ok_or("missing helper directory")?;
    let program = format!(
        "{TRUST}\nimport runpy\ntrusted_imports('{directory}')\nrunpy.run_path('{path}', run_name='__main__')"
    );
    let encoded: String = program
        .bytes()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect();
    Ok(format!(
        "/usr/bin/python3 -I -c \"exec(bytes.fromhex('{encoded}'))\""
    ))
}

/// Build the first systemd credential-authority condition. Python loader/helper
/// exceptions map to exit 255 instead of the 1..254 range systemd treats as a
/// skipped successful condition. Normal returns and explicit zero stay successful.
/// # Errors
/// Refuses the same unsupported helper paths as [`command`].
pub fn systemd_condition_command(path: &str) -> Result<String, String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let checked = systemd_command(path)?;
    let expression = checked
        .strip_prefix("/usr/bin/python3 -I -c \"")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or("invalid checked condition command")?;
    let program = format!(
        "try:\n    {expression}\nexcept SystemExit as error:\n    if error.code not in (None, 0):\n        raise SystemExit(255) from None\nexcept BaseException:\n    raise SystemExit(255) from None\n"
    );
    let encoded: String = program
        .bytes()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect();
    Ok(format!(
        "/usr/bin/python3 -I -c \"exec(bytes.fromhex('{encoded}'))\""
    ))
}

pub(crate) fn near_control() -> String {
    assemble(
        "/usr/local/lib/erpc/near/control.py",
        "/usr/local/lib/erpc/near",
    )
}

pub(crate) fn avax_control() -> String {
    assemble(
        "/usr/local/lib/erpc/avax/control.py",
        "/usr/local/lib/erpc/avax",
    )
}

pub(crate) fn sui_control() -> String {
    assemble(
        "/usr/local/lib/erpc/sui/erpc-sui-control.py",
        "/usr/local/lib/erpc/sui",
    )
}

pub(crate) fn sui_status() -> String {
    assemble(
        "/usr/local/lib/erpc/sui/erpc-sui-status.py",
        "/usr/local/lib/erpc/sui",
    )
}

pub(crate) fn nitro_validator_control() -> String {
    assemble(
        "/usr/local/lib/erpc/arbitrum-validator/control.py",
        "/usr/local/lib/erpc/arbitrum-validator",
    )
}

pub(crate) fn robinhood_validator_control(testnet: bool) -> String {
    if testnet {
        assemble(
            "/usr/local/lib/erpc/robinhood-testnet-validator/control.py",
            "/usr/local/lib/erpc/robinhood-testnet-validator",
        )
    } else {
        assemble(
            "/usr/local/lib/erpc/robinhood-mainnet-validator/control.py",
            "/usr/local/lib/erpc/robinhood-mainnet-validator",
        )
    }
}

pub(crate) fn nitro_control() -> String {
    assemble("/usr/local/lib/erpc/nitro-control", "/usr/local/lib/erpc")
}

pub(crate) fn tron_control() -> String {
    assemble(
        "/usr/local/lib/erpc/tron/control.py",
        "/usr/local/lib/erpc/tron",
    )
}

fn assemble(path: &str, directory: &str) -> String {
    // -c keeps stdin available for credential import; runpy supplies __file__
    // and argv[0] while preserving separately supplied validated arguments.
    let program = format!(
        "{TRUST}\nimport runpy\ntrusted_imports('{directory}')\nrunpy.run_path('{path}', run_name='__main__')"
    );
    quoted(&program)
}

fn quoted(program: &str) -> String {
    format!(
        "sudo -n /usr/bin/python3 -I -c '{}'",
        program.replace('\'', "'\\''")
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn systemd_bootstrap_is_a_single_inline_program_without_unit_expansion() {
        let command = super::systemd_command("/usr/local/lib/erpc/tron/control.py").unwrap();
        let encoded = command
            .strip_prefix("/usr/bin/python3 -I -c \"exec(bytes.fromhex('")
            .unwrap()
            .strip_suffix("'))\"")
            .unwrap();
        assert!(encoded.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let decoded: Vec<u8> = encoded
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let program = String::from_utf8(decoded).unwrap();
        assert!(program.starts_with(super::TRUST));
        assert!(program.contains("trusted_imports('/usr/local/lib/erpc/tron')"));
        assert!(program.ends_with(
            "runpy.run_path('/usr/local/lib/erpc/tron/control.py', run_name='__main__')"
        ));
        assert!(!command.contains(['%', '$', '\n']));
        assert!(super::systemd_command("/usr/local/lib/erpc/../unsafe").is_err());
    }
    #[cfg(unix)] // The emitted helper validates Linux/POSIX ownership paths.
    #[test]
    fn condition_loader_maps_unsafe_ancestry_and_helper_failures_to_failed_units() {
        let command =
            super::systemd_condition_command("/usr/local/lib/erpc/condition-fixture.py").unwrap();
        assert!(!command.contains(['%', '$', '\n']));
        let expression = command
            .strip_prefix("/usr/bin/python3 -I -c \"")
            .unwrap()
            .strip_suffix('"')
            .unwrap();
        // Kernel metadata is inertly modeled; the actual generated outer
        // bootstrap and its embedded trusted_imports execute in isolated Python.
        // No root path, credential, service or account is created.
        let fixture = r"import os,runpy,stat,sys
from types import SimpleNamespace
unsafe=sys.argv[1].startswith('unsafe')
outcome=sys.argv[2]
os.lstat=lambda path:SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|(0o777 if sys.argv[1]=='unsafe' else 0o755))
entry=SimpleNamespace(name='condition-fixture.py',path='/usr/local/lib/erpc/condition-fixture.py',stat=lambda **kwargs:SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o666,st_nlink=1))
os.scandir=lambda path:[entry] if sys.argv[1]=='unsafe-file' else []
def execute(path,run_name):
    print('inert helper reached')
    if unsafe:raise AssertionError('unsafe loader reached helper')
    if outcome=='zero':raise SystemExit(0)
    if outcome=='skip':raise SystemExit(1)
    if outcome=='failure':raise ValueError('inert helper failure')
runpy.run_path=execute
";
        for (authority, outcome, expected, reached) in [
            ("unsafe", "normal", 255, false),
            ("unsafe-file", "normal", 255, false),
            ("safe", "normal", 0, true),
            ("safe", "zero", 0, true),
            ("safe", "skip", 255, true),
            ("safe", "failure", 255, true),
        ] {
            let output =
                std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
                    .args([
                        "-I",
                        "-c",
                        &format!("{fixture}\n{expression}"),
                        authority,
                        outcome,
                    ])
                    .output()
                    .expect("Python 3 is required");
            assert_eq!(
                output.status.code(),
                Some(expected),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&output.stdout).contains("inert helper reached"),
                reached
            );
        }
        assert!(super::systemd_condition_command("/usr/local/lib/erpc/../unsafe").is_err());
    }

    #[test]
    fn release_profile_bound_supports_closed_multiclient_helpers_without_becoming_unbounded() {
        let mut names = vec!["control.py".to_string()];
        names.extend((1..64).map(|index| format!("module_{index}.py")));
        let profile = names.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(
            super::release_command("/usr/local/lib/erpc/polygon", "control.py", &[&profile])
                .is_ok()
        );
        names.push("excess.py".into());
        let oversized = names.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(
            super::release_command("/usr/local/lib/erpc/polygon", "control.py", &[&oversized])
                .is_err()
        );
    }

    #[test]
    fn release_loader_accepts_only_complete_plain_profiles() {
        let old: &[&str] = &["control.py", "bootstrap.py", "catalog.json"];
        let new: &[&str] = &["control.py", "bootstrap.py", "validator.py", "catalog.json"];
        let command =
            super::release_command("/usr/local/lib/erpc/bsc", "control.py", &[old, new]).unwrap();
        assert!(command.contains("trusted_release"));
        for invalid in [
            vec![],
            vec!["bootstrap.py"],
            vec!["control.py", "control.py"],
            vec!["control.py", "../outside.py"],
            vec!["control.py", "a'b.py"],
        ] {
            assert!(
                super::release_command("/usr/local/lib/erpc/bsc", "control.py", &[&invalid])
                    .is_err()
            );
        }
        let names: Vec<String> = (0..65).map(|n| format!("module-{n}.py")).collect();
        let profile: Vec<&str> = names.iter().map(String::as_str).collect();
        assert!(
            super::release_command("/usr/local/lib/erpc/fixture", profile[0], &[&profile[..64]])
                .is_ok()
        );
        assert!(
            super::release_command("/usr/local/lib/erpc/fixture", profile[0], &[&profile]).is_err()
        );
        assert!(super::release_command("/tmp/bsc", "control.py", &[old]).is_err());
        assert!(
            super::release_command("/usr/local/lib/erpc/bsc", "../control.py", &[old]).is_err()
        );
        #[cfg(unix)]
        assert!(
            std::process::Command::new("bash")
                .args(["-n", "-c", &command])
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn bounded_expanded_profiles_keep_exact_names_and_reject_the_next_member() {
        let mut names = vec!["control.py".to_owned()];
        names.extend((1..64).map(|index| format!("module_{index}.py")));
        let profile = names.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(
            super::release_command(
                "/usr/local/lib/erpc/arc-validator",
                "control.py",
                &[&profile]
            )
            .is_ok()
        );
        names.push("too_many.py".into());
        let profile = names.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(
            super::release_command(
                "/usr/local/lib/erpc/arc-validator",
                "control.py",
                &[&profile]
            )
            .is_err()
        );
    }

    #[test]
    fn helper_paths_cannot_escape_or_inject_program_text() {
        for path in [
            "/usr/local/lib/erpc/tron/control.py",
            "/usr/local/lib/erpc/bsc/current/control.py",
            "/usr/local/lib/erpc/nitro-control",
        ] {
            assert!(
                super::command(path)
                    .unwrap()
                    .starts_with("sudo -n /usr/bin/python3 -I -c '")
            );
        }
        for path in [
            "/tmp/control.py",
            "/usr/local/lib/erpc/",
            "/usr/local/lib/erpc/../control.py",
            "/usr/local/lib/erpc//control.py",
            "/usr/local/lib/erpc/a'b.py",
            "/usr/local/lib/erpc/$(id).py",
            "/usr/local/lib/erpc/./control.py",
        ] {
            assert!(super::command(path).is_err(), "{path}");
        }
    }
}
