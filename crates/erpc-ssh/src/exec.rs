// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Running OpenSSH: a session to one node, its commands, and `ssh-keyscan`.
//!
//! The system's own `ssh` is used, from a fixed path so `PATH` cannot put
//! another in its place, with an environment of its own: the operator's agent
//! and proxy variables do not reach it, because the generated configuration
//! names the agent, if any, itself. Before anything connects, `ssh -G`
//! reports the configuration it would actually use, and the session refuses
//! to start unless every setting that matters is what erpc wrote.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::command::RemoteCommand;
use crate::config::{ALIAS, RunDir, Target, TargetError};
use crate::hostkey::{self, HostKey, HostKeyError};

/// What went wrong talking to a node.
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    /// No OpenSSH client where it should be.
    #[error("OpenSSH is not installed here (looked for {0})")]
    NoOpenSsh(String),
    /// The target cannot be configured.
    #[error(transparent)]
    Target(#[from] TargetError),
    /// `ssh -G` reported a setting other than the one erpc wrote.
    #[error("ssh would not use the configuration erpc wrote: {0}")]
    Effective(String),
    /// The node's host key is not the pinned one.
    #[error(
        "the host key of the node is not the one pinned in its 1Password item; \
         nothing was sent. If the server was reinstalled, pin its new key again"
    )]
    HostKeyMismatch,
    /// `ssh-keyscan` found no usable key.
    #[error("the node offered no ssh-ed25519 host key: {0}")]
    NoHostKey(HostKeyError),
    /// The command ran and failed.
    #[error("the command failed on the node (exit {status}): {message}")]
    Failed {
        /// The exit status, or -1 when killed by a signal.
        status: i32,
        /// The last line `ssh` or the command wrote to stderr.
        message: String,
    },
    /// The process could not be started or talked to.
    #[error("could not run ssh: {0}")]
    Io(#[from] std::io::Error),
}

/// Where OpenSSH's tools are, in the order they are tried.
pub(crate) const SSH_PATHS: [&str; 2] = ["/usr/bin/ssh", r"C:\Windows\System32\OpenSSH\ssh.exe"];
const KEYSCAN_PATHS: [&str; 2] = [
    "/usr/bin/ssh-keyscan",
    r"C:\Windows\System32\OpenSSH\ssh-keyscan.exe",
];

const ADD_PATHS: [&str; 2] = [
    "/usr/bin/ssh-add",
    r"C:\Windows\System32\OpenSSH\ssh-add.exe",
];

/// Whether the agent at `socket` holds the public key `key_line`
/// (`type base64 [comment]`): asked with `ssh-add -L`, by its full path and
/// with only the environment it needs.
#[must_use]
pub fn agent_holds(socket: &Path, key_line: &str) -> bool {
    let Some(blob) = key_line.split_whitespace().nth(1) else {
        return false;
    };
    let Ok(add) = find(&ADD_PATHS) else {
        return false;
    };
    tool(&add)
        .arg("-L")
        .env("SSH_AUTH_SOCK", socket)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|l| l.split_whitespace().nth(1) == Some(blob))
        })
}

pub(crate) fn find(paths: &[&str]) -> Result<PathBuf, SshError> {
    paths
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .ok_or_else(|| SshError::NoOpenSsh(paths.join(" or ")))
}

/// A command for an OpenSSH tool, with only the environment it needs.
pub(crate) fn tool(program: &Path) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in ["HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "SystemRoot"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(windows)]
    {
        // Win32 OpenSSH initializes ProgramData paths before its logging/argument
        // setup; omitting it makes even ssh -G exit before reporting an error.
        // Native OpenSSH also needs the profile and system environment. Keep
        // this explicit: never inherit agent, proxy or application credentials.
        for name in [
            "USERPROFILE",
            "USERNAME",
            "HOMEDRIVE",
            "HOMEPATH",
            "SystemDrive",
            "ProgramData",
            "TEMP",
            "TMP",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.env(
            "PATH",
            r"C:\Windows\System32\OpenSSH;C:\Windows\System32;C:\Windows",
        );
    }
    #[cfg(not(windows))]
    command.env("PATH", "/usr/bin:/bin");
    command
}

/// Settings `ssh -G` must report, as it prints them.
fn required(target: &Target, known_hosts: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("hostname", target.host.to_ascii_lowercase()),
        ("port", target.port.to_string()),
        ("user", target.user.clone()),
        ("hostkeyalias", ALIAS.to_owned()),
        ("hostkeyalgorithms", hostkey::ALGORITHM.to_owned()),
        ("stricthostkeychecking", "true".to_owned()),
        ("userknownhostsfile", known_hosts.display().to_string()),
        ("globalknownhostsfile", "/dev/null".to_owned()),
        ("updatehostkeys", "false".to_owned()),
        ("batchmode", "yes".to_owned()),
        ("identitiesonly", "yes".to_owned()),
        ("passwordauthentication", "no".to_owned()),
        ("kbdinteractiveauthentication", "no".to_owned()),
        ("forwardagent", "no".to_owned()),
        ("forwardx11", "no".to_owned()),
        ("clearallforwardings", "yes".to_owned()),
        ("permitlocalcommand", "no".to_owned()),
        ("requesttty", "false".to_owned()),
        ("controlmaster", "false".to_owned()),
        ("tunnel", "false".to_owned()),
    ]
}

/// Settings that must not appear at all: each would send the connection, a
/// channel or a command somewhere erpc did not choose.
const FORBIDDEN: [&str; 12] = [
    "proxycommand",
    "proxyjump",
    "localcommand",
    "remotecommand",
    "localforward",
    "remoteforward",
    "dynamicforward",
    "knownhostscommand",
    "pkcs11provider",
    "controlpath",
    "include",
    "setenv",
];

/// Checks `ssh -G` output against the configuration erpc wrote.
///
/// # Errors
///
/// Returns [`SshError::Effective`] naming the first setting that differs.
pub fn check_effective(output: &str, target: &Target, known_hosts: &Path) -> Result<(), SshError> {
    check_settings(output, &required(target, known_hosts))
}

/// Checks `ssh -G` output: none of [`FORBIDDEN`] set, and each of
/// `required` set as given.
pub(crate) fn check_settings(output: &str, required: &[(&str, String)]) -> Result<(), SshError> {
    let settings: Vec<(&str, &str)> = output.lines().filter_map(|l| l.split_once(' ')).collect();
    for name in FORBIDDEN {
        if let Some((_, value)) = settings.iter().find(|(k, _)| *k == name) {
            return Err(SshError::Effective(format!("{name} is set ({value})")));
        }
    }
    for (name, want) in required {
        match settings.iter().find(|(k, _)| k == name) {
            // `a|b`: either is what was written, as versions print it.
            Some((_, value)) if want.split('|').any(|w| w == *value) => {}
            Some((_, value)) => {
                return Err(SshError::Effective(format!(
                    "{name} is {value}, not {want}"
                )));
            }
            None => return Err(SshError::Effective(format!("{name} is not set"))),
        }
    }
    Ok(())
}

/// What a command printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error, `ssh`'s own messages included.
    pub stderr: Vec<u8>,
}

/// Which stream a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// A checked connection setup for one node. Nothing connects until a command
/// runs; each command is its own `ssh` process.
#[derive(Debug)]
pub struct Session {
    ssh: PathBuf,
    run: RunDir,
}

impl Session {
    /// Writes the configuration for `target` and checks, with `ssh -G`, that
    /// OpenSSH would use it as written.
    ///
    /// # Errors
    ///
    /// Returns [`SshError`] when OpenSSH is missing, the target cannot be
    /// configured, or the effective configuration differs.
    pub fn open(target: &Target) -> Result<Self, SshError> {
        target.check()?;
        let ssh = find(&SSH_PATHS)?;
        let run = RunDir::new(target)?;
        let output = tool(&ssh)
            .arg("-F")
            .arg(run.config())
            .arg("-G")
            .arg(ALIAS)
            .stdin(Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err(SshError::Effective(format!(
                "ssh -G exited {}: {}",
                output.status,
                last_line(&output.stderr)
            )));
        }
        check_effective(
            &String::from_utf8_lossy(&output.stdout),
            target,
            &run.known_hosts(),
        )?;
        Ok(Self { ssh, run })
    }

    fn command(&self, remote: &RemoteCommand) -> Command {
        let mut command = tool(&self.ssh);
        command
            .arg("-F")
            .arg(self.run.config())
            .arg(ALIAS)
            .arg("--")
            .arg(remote.line());
        command
    }

    /// Runs `remote`, with `stdin` as its standard input, and returns what it
    /// printed.
    ///
    /// # Errors
    ///
    /// Returns [`SshError`] when `ssh` cannot run, the host key does not
    /// match, or the command exits with a failure.
    pub fn run(&self, remote: &RemoteCommand, stdin: Option<&[u8]>) -> Result<Output, SshError> {
        let mut child = self
            .command(remote)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(bytes)?;
        }
        let output = child.wait_with_output()?;
        finish(output.status, &output.stderr)?;
        Ok(Output {
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    /// Runs `remote` and hands each line it prints to `on_line` as it
    /// arrives.
    ///
    /// # Errors
    ///
    /// As [`Session::run`].
    pub fn stream(
        &self,
        remote: &RemoteCommand,
        on_line: &mut dyn FnMut(Stream, &str),
    ) -> Result<(), SshError> {
        let mut child = self
            .command(remote)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stderr = child.stderr.take();
        // stderr is read on its own thread so neither pipe can fill and stall
        // the other.
        let errors = std::thread::spawn(move || {
            let mut text = Vec::new();
            if let Some(pipe) = stderr.as_mut() {
                let _ = pipe.read_to_end(&mut text);
            }
            text
        });
        if let Some(stdout) = child.stdout.take() {
            for line in BufReader::new(stdout).lines() {
                on_line(Stream::Stdout, &line?);
            }
        }
        let stderr = errors.join().unwrap_or_default();
        for line in String::from_utf8_lossy(&stderr).lines() {
            on_line(Stream::Stderr, line);
        }
        finish(child.wait()?, &stderr)
    }
}

pub(crate) fn finish(status: std::process::ExitStatus, stderr: &[u8]) -> Result<(), SshError> {
    if status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(stderr);
    if text.contains("Host key verification failed")
        || text.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
    {
        return Err(SshError::HostKeyMismatch);
    }
    Err(SshError::Failed {
        status: status.code().unwrap_or(-1),
        message: last_line(stderr),
    })
}

/// The last non-empty line of `bytes`, printable and short.
pub(crate) fn last_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("");
    line.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(300)
        .collect()
}

/// Asks the node at `host`:`port` for its `ssh-ed25519` host key, for the
/// operator to confirm by its fingerprint before it is pinned.
///
/// # Errors
///
/// Returns [`SshError`] when `ssh-keyscan` is missing or fails, or the node
/// offers no usable key.
pub fn keyscan(host: &str, port: u16) -> Result<HostKey, SshError> {
    // The same check a target's host gets, so it cannot become an option.
    crate::config::check_host(host)?;
    let output = tool(&find(&KEYSCAN_PATHS)?)
        .args(["-t", hostkey::ALGORITHM, "-T", "10", "-p"])
        .arg(port.to_string())
        .arg(host)
        .stdin(Stdio::null())
        .output()?;
    hostkey::from_keyscan(&String::from_utf8_lossy(&output.stdout)).map_err(SshError::NoHostKey)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{SSH_PATHS, Session, SshError, check_effective, find};
    use crate::config::tests::{fixture_path, target};

    #[test]
    fn a_setting_may_read_as_any_of_its_spellings() {
        let want = [("pubkeyauthentication", "false|no".to_owned())];
        for (printed, ok) in [
            ("false", true),
            ("no", true),
            ("yes", false),
            ("true", false),
        ] {
            let output = format!("pubkeyauthentication {printed}\n");
            assert_eq!(
                super::check_settings(&output, &want).is_ok(),
                ok,
                "{printed}"
            );
        }
    }

    fn effective(known_hosts: &str) -> String {
        let identity = fixture_path("/home/op/.ssh/id_ed25519");
        let identity = identity.display();
        format!(
            "user ubuntu\nhostname 203.0.113.5\nport 22\nbatchmode yes\ncheckhostip no\n\
             controlmaster false\nclearallforwardings yes\nforwardx11 no\nidentitiesonly yes\n\
             kbdinteractiveauthentication no\npasswordauthentication no\npermitlocalcommand no\n\
             requesttty false\nstricthostkeychecking true\ntunnel false\nupdatehostkeys false\n\
             hostkeyalgorithms ssh-ed25519\nhostkeyalias erpc-node\nidentityagent none\n\
             identityfile {identity}\nglobalknownhostsfile /dev/null\n\
             userknownhostsfile {known_hosts}\nforwardagent no\nconnecttimeout 20\n"
        )
    }

    #[test]
    fn the_configuration_as_written_passes() {
        let k = Path::new("/tmp/r/known_hosts");
        check_effective(&effective("/tmp/r/known_hosts"), &target(), k).expect("passes");
    }

    #[test]
    fn a_proxy_or_a_forward_from_anywhere_is_refused() {
        let k = Path::new("/tmp/r/known_hosts");
        for extra in [
            "proxycommand nc evil 22",
            "proxyjump bastion",
            "localforward 8080 [127.0.0.1]:80",
            "remotecommand id",
            "knownhostscommand /bin/true",
        ] {
            let output = format!("{}{extra}\n", effective("/tmp/r/known_hosts"));
            let err = check_effective(&output, &target(), k).expect_err(extra);
            assert!(matches!(err, SshError::Effective(_)), "{extra}");
        }
    }

    #[test]
    fn a_weaker_setting_is_refused() {
        let k = Path::new("/tmp/r/known_hosts");
        for (from, to) in [
            ("stricthostkeychecking true", "stricthostkeychecking ask"),
            ("forwardagent no", "forwardagent yes"),
            (
                "userknownhostsfile /tmp/r/known_hosts",
                "userknownhostsfile ~/.ssh/known_hosts",
            ),
            (
                "hostkeyalgorithms ssh-ed25519",
                "hostkeyalgorithms ssh-rsa,ssh-ed25519",
            ),
        ] {
            let output = effective("/tmp/r/known_hosts").replace(from, to);
            assert!(check_effective(&output, &target(), k).is_err(), "{to}");
        }
    }

    #[test]
    fn ssh_environment_contains_no_inherited_agent_proxy_or_application_credentials() {
        let command = super::tool(std::path::Path::new("ssh"));
        for (name, value) in command.get_envs() {
            let name = name.to_string_lossy();
            assert!(
                [
                    "HOME",
                    "USER",
                    "LOGNAME",
                    "LANG",
                    "TMPDIR",
                    "SystemRoot",
                    "PATH",
                    "USERPROFILE",
                    "USERNAME",
                    "HOMEDRIVE",
                    "HOMEPATH",
                    "SystemDrive",
                    "ProgramData",
                    "TEMP",
                    "TMP"
                ]
                .iter()
                .any(|allowed| name.eq_ignore_ascii_case(allowed)),
                "unexpected inherited environment name"
            );
            assert!(value.is_some());
        }
        let expected = if cfg!(windows) {
            r"C:\Windows\System32\OpenSSH;C:\Windows\System32;C:\Windows"
        } else {
            "/usr/bin:/bin"
        };
        assert!(
            command.get_envs().any(
                |(name, value)| name == "PATH" && value == Some(std::ffi::OsStr::new(expected))
            )
        );
    }

    #[test]
    fn real_openssh_accepts_the_generated_configuration_unchanged() {
        // `ssh -G` reads the configuration without connecting, so this runs
        // wherever OpenSSH is installed and is skipped where it is not.
        if find(&SSH_PATHS).is_err() {
            return;
        }
        Session::open(&target()).expect("ssh -G reports the configuration as written");
    }
}
