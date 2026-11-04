// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The one login erpc makes with a password: the first, to an ERPC VPS
//! whose only way in is the password ERPC set, to put the operator's key in
//! place. Everything after goes over the key, and password logins are then
//! turned off ([`crate::vps`]).
//!
//! The password is never on a command line or in an environment. OpenSSH
//! asks a helper for it (`SSH_ASKPASS`, forced); the helper reads it from a
//! FIFO in the run's private directory, which erpc writes once per login and
//! which holds nothing on disk. Everything else is as strict as a key
//! session: the host key pinned, no agent, no forwarding, `ssh -G` checked
//! before connecting.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;

use zeroize::Zeroizing;

use crate::command::RemoteCommand;
use crate::config::{ALIAS, check_host, known_hosts_line, path_value, restrict, write_private};
use crate::exec::{Output, SSH_PATHS, SshError, check_settings, find, finish, tool};
use crate::hostkey::{self, HostKey};

/// A checked password login to one VPS. Each command is its own `ssh`.
#[derive(Debug)]
pub struct PasswordLogin {
    ssh: PathBuf,
    dir: tempfile::TempDir,
}

/// The configuration: a key session's, with the password the only way in.
fn render(host: &str, port: u16, user: &str, known_hosts: &str) -> String {
    let mut text = format!("Host {ALIAS}\n");
    for (key, value) in [
        ("HostName", host),
        ("Port", &port.to_string()),
        ("User", user),
        ("HostKeyAlias", ALIAS),
        ("HostKeyAlgorithms", hostkey::ALGORITHM),
        ("StrictHostKeyChecking", "yes"),
        ("UserKnownHostsFile", known_hosts),
        ("GlobalKnownHostsFile", "/dev/null"),
        ("UpdateHostKeys", "no"),
        ("CheckHostIP", "no"),
        ("BatchMode", "no"),
        ("PreferredAuthentications", "password"),
        ("PasswordAuthentication", "yes"),
        ("NumberOfPasswordPrompts", "1"),
        ("PubkeyAuthentication", "no"),
        ("KbdInteractiveAuthentication", "no"),
        ("HostbasedAuthentication", "no"),
        ("GSSAPIAuthentication", "no"),
        ("IdentitiesOnly", "yes"),
        ("IdentityAgent", "none"),
        ("ForwardAgent", "no"),
        ("ForwardX11", "no"),
        ("ClearAllForwardings", "yes"),
        ("PermitLocalCommand", "no"),
        ("ProxyCommand", "none"),
        ("ProxyJump", "none"),
        ("RequestTTY", "no"),
        ("ControlMaster", "no"),
        ("ControlPath", "none"),
        ("ConnectTimeout", "20"),
        ("LogLevel", "ERROR"),
    ] {
        let _ = writeln!(text, "  {key} {value}");
    }
    text
}

/// What `ssh -G` must report for it.
fn required(host: &str, port: u16, user: &str, known_hosts: &str) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = vec![
        ("hostname", host.to_ascii_lowercase()),
        ("port", port.to_string()),
        ("user", user.to_owned()),
        ("userknownhostsfile", known_hosts.to_owned()),
    ];
    for (name, value) in [
        ("hostkeyalias", ALIAS),
        ("hostkeyalgorithms", hostkey::ALGORITHM),
        ("stricthostkeychecking", "true"),
        ("globalknownhostsfile", "/dev/null"),
        ("updatehostkeys", "false"),
        ("preferredauthentications", "password"),
        ("passwordauthentication", "yes"),
        // 8.9 and later print `false`; before, `no`.
        ("pubkeyauthentication", "false|no"),
        ("kbdinteractiveauthentication", "no"),
        ("identityagent", "none"),
        ("forwardagent", "no"),
        ("forwardx11", "no"),
        ("clearallforwardings", "yes"),
        ("permitlocalcommand", "no"),
        ("requesttty", "false"),
        ("controlmaster", "false"),
        ("tunnel", "false"),
    ] {
        out.push((name, value.to_owned()));
    }
    out
}

/// Whether `ssh -V`'s line names an OpenSSH that obeys
/// `SSH_ASKPASS_REQUIRE=force`: 8.4 or later.
fn askpass_forced(version: &str) -> bool {
    let Some(rest) = version.strip_prefix("OpenSSH_") else {
        return false;
    };
    let mut numbers = rest
        .split(|c: char| !c.is_ascii_digit())
        .map(|n| n.parse::<u32>().ok());
    match (numbers.next().flatten(), numbers.next().flatten()) {
        (Some(major), Some(minor)) => (major, minor) >= (8, 4),
        _ => false,
    }
}

impl PasswordLogin {
    /// Writes the configuration, the pinned host key and the password
    /// helper into a new private directory under `base`, and checks with
    /// `ssh -G` that OpenSSH would use them as written. `base` is erpc's
    /// own state directory: the helper is run from there, and a temporary
    /// directory may be mounted `noexec`.
    ///
    /// # Errors
    ///
    /// [`SshError`] when OpenSSH is missing, a value cannot be written, or
    /// the effective configuration differs.
    pub fn open(
        host: &str,
        port: u16,
        user: &str,
        host_key: &HostKey,
        base: &std::path::Path,
    ) -> Result<Self, SshError> {
        check_host(host)?;
        crate::config::check_user(user)?;
        let ssh = find(&SSH_PATHS)?;
        // Before 8.4 OpenSSH ignores SSH_ASKPASS_REQUIRE and asks on the
        // terminal, where no one answers: the console would hang.
        let version = tool(&ssh).arg("-V").stdin(Stdio::null()).output()?;
        let version = String::from_utf8_lossy(&version.stderr).trim().to_owned();
        if !askpass_forced(&version) {
            return Err(SshError::Effective(format!(
                "the first password login needs OpenSSH 8.4 or later, and this is {version:?}; \
                 update OpenSSH, then ask again"
            )));
        }
        std::fs::create_dir_all(base)?;
        let dir = tempfile::Builder::new()
            .prefix("erpc-ssh-")
            .tempdir_in(base)?;
        restrict(dir.path(), 0o700)?;
        let known_hosts = dir.path().join("known_hosts");
        write_private(&known_hosts, known_hosts_line(host_key).as_bytes())?;
        let known = path_value(&known_hosts)?;
        write_private(
            &dir.path().join("config"),
            render(host, port, user, &known).as_bytes(),
        )?;
        let fifo = dir.path().join("secret");
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&fifo)
            .status()?;
        if !made.success() {
            return Err(SshError::Effective(
                "could not make the password FIFO".to_owned(),
            ));
        }
        let helper = dir.path().join("askpass");
        write_private(
            &helper,
            format!("#!/bin/sh\nexec /bin/cat {}\n", path_value(&fifo)?).as_bytes(),
        )?;
        restrict(&helper, 0o700)?;
        let login = Self { ssh, dir };
        let output = tool(&login.ssh)
            .arg("-F")
            .arg(login.dir.path().join("config"))
            .arg("-G")
            .arg(ALIAS)
            .stdin(Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err(SshError::Effective(crate::exec::last_line(&output.stderr)));
        }
        let known = known_hosts.display().to_string();
        check_settings(
            &String::from_utf8_lossy(&output.stdout),
            &required(host, port, user, &known),
        )?;
        Ok(login)
    }

    /// Logs in with `password` and runs `remote` with `stdin`.
    ///
    /// # Errors
    ///
    /// As [`crate::Session::run`]; a refused password is
    /// [`SshError::Failed`] with OpenSSH's `Permission denied`.
    pub fn run(
        &self,
        remote: &RemoteCommand,
        password: &str,
        stdin: Option<&[u8]>,
    ) -> Result<Output, SshError> {
        let fifo = self.dir.path().join("secret");
        let mut secret = Zeroizing::new(Vec::with_capacity(password.len() + 1));
        secret.extend_from_slice(password.as_bytes());
        secret.push(b'\n');
        // Opening a FIFO to write waits for its reader, the helper OpenSSH
        // starts; the write happens on a thread of its own.
        let writer = {
            let fifo = fifo.clone();
            std::thread::spawn(move || {
                if let Ok(mut pipe) = std::fs::OpenOptions::new().write(true).open(&fifo) {
                    let _ = pipe.write_all(&secret);
                }
            })
        };
        let ran = (|| {
            let mut child = tool(&self.ssh)
                .env("SSH_ASKPASS", self.dir.path().join("askpass"))
                .env("SSH_ASKPASS_REQUIRE", "force")
                .arg("-F")
                .arg(self.dir.path().join("config"))
                .arg(ALIAS)
                .arg("--")
                .arg(remote.line())
                .stdin(if stdin.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            // A write that fails (OpenSSH gave up before reading) is not
            // the error: how OpenSSH ended is, so it is still waited for.
            if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
                let _ = pipe.write_all(bytes);
            }
            child.wait_with_output()
        })();
        // OpenSSH never asked (it failed before, or never started): hold
        // the reading end open until the writer is done, so it is not left
        // waiting however far it got, and the password goes nowhere. This
        // runs whatever happened above.
        let reader = (!writer.is_finished()).then(|| reader(&fifo));
        let _ = writer.join();
        drop(reader);
        let output = ran?;
        finish(output.status, &output.stderr)?;
        Ok(Output {
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

/// `fifo`'s reading end, so a writer waiting for a reader, or about to,
/// gets one. Opened without blocking: when the writer has just ended, a
/// blocking open would wait for a writer that never comes.
#[cfg(unix)]
fn reader(fifo: &std::path::Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const O_NONBLOCK: i32 = 0o4000;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const O_NONBLOCK: i32 = 0x0004;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(fifo)
        .ok()
}

#[cfg(not(unix))]
fn reader(_: &std::path::Path) -> Option<std::fs::File> {
    None
}

/// Whether `error` is the server refusing the password.
#[must_use]
pub fn refused(error: &SshError) -> bool {
    matches!(error, SshError::Failed { message, .. } if message.contains("Permission denied"))
}

#[cfg(test)]
mod tests {
    use super::{PasswordLogin, render};
    use crate::exec::{SSH_PATHS, find};
    use crate::hostkey::HostKey;

    #[test]
    fn only_an_openssh_that_obeys_the_helper_is_used() {
        for (line, ok) in [
            (
                "OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13 30 Jan 2024",
                true,
            ),
            ("OpenSSH_8.4p1, LibreSSL 3.3.6", true),
            ("OpenSSH_10.0p2, LibreSSL 3.3.6", true),
            ("OpenSSH_8.2p1 Ubuntu-4ubuntu0.11, OpenSSL 1.1.1f", false),
            ("OpenSSH_7.4p1", false),
            ("Sun_SSH_1.1", false),
            ("", false),
        ] {
            assert_eq!(super::askpass_forced(line), ok, "{line}");
        }
    }

    #[test]
    fn the_password_is_the_only_way_in_and_nothing_else_is_loosened() {
        let text = render("203.0.113.5", 22, "ubuntu", "\"/tmp/k\"");
        for line in [
            "PreferredAuthentications password",
            "PubkeyAuthentication no",
            "IdentityAgent none",
            "StrictHostKeyChecking yes",
            "ForwardAgent no",
            "ProxyCommand none",
            "NumberOfPasswordPrompts 1",
        ] {
            assert!(text.contains(line), "{line}");
        }
    }

    #[test]
    fn real_openssh_accepts_the_password_configuration_unchanged() {
        if find(&SSH_PATHS).is_err() || !std::path::Path::new("/usr/bin/mkfifo").exists() {
            return;
        }
        let key = HostKey::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        )
        .expect("key");
        PasswordLogin::open("203.0.113.5", 22, "ubuntu", &key, &std::env::temp_dir())
            .expect("ssh -G as written");
    }
}
