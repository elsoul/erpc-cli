// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The `ssh_config` and `known_hosts` a connection uses, written for it and
//! nothing else.
//!
//! `ssh -F <file>` reads that file alone: neither `~/.ssh/config` nor the
//! system configuration applies, so an `Include`, a `Match`, a `ProxyCommand`
//! or a forwarding the operator set up for other work cannot reach a node
//! erpc talks to. The host key comes from the host's 1Password item and is
//! written to a `known_hosts` file that exists only for the run; the
//! directory holding both is private to the user and removed when the run
//! ends.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::hostkey::{ALGORITHM, HostKey};

/// The name the generated configuration knows the node by. `HostKeyAlias`
/// files the pinned key under it, so the key matches whatever address the
/// node is reached at.
pub const ALIAS: &str = "erpc-node";

/// How long to wait for a connection, in seconds.
const CONNECT_TIMEOUT: u32 = 20;

/// Where a node is and how to log in to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// An IP address or a DNS name.
    pub host: String,
    /// The SSH port, usually 22.
    pub port: u16,
    /// The login user: `ubuntu` before `solv` exists, `solv` after.
    pub user: String,
    /// The pinned host key.
    pub host_key: HostKey,
    /// How to authenticate.
    pub identity: Identity,
}

/// The key that logs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// A private key file, or a `.pub` file whose private half is in an
    /// agent, as OpenSSH accepts for `IdentityFile`.
    File(PathBuf),
    /// An agent socket (1Password's, for example), with the public key that
    /// selects which of its keys to use.
    Agent {
        /// The agent's socket.
        socket: PathBuf,
        /// The `.pub` file of the key to offer.
        public_key: PathBuf,
    },
}

/// Why a target cannot be written into a configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    /// The host is not a plain address or DNS name.
    #[error("{0:?} is not an IP address or a host name")]
    Host(String),
    /// The user name has characters a login name does not.
    #[error("{0:?} is not a login name")]
    User(String),
    /// A path cannot be written into `ssh_config` safely.
    #[error("{0:?} cannot be used as a path in ssh_config")]
    Path(String),
}

impl Target {
    /// Checks every value that goes into the configuration, so none can end a
    /// line, start a new option or add a token.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError`] for the first value that cannot be written.
    pub fn check(&self) -> Result<(), TargetError> {
        check_host(&self.host)?;
        check_user(&self.user)?;
        for path in self.paths() {
            path_value(path)?;
        }
        Ok(())
    }

    fn paths(&self) -> Vec<&Path> {
        match &self.identity {
            Identity::File(path) => vec![path],
            Identity::Agent { socket, public_key } => vec![socket, public_key],
        }
    }
}

/// A login user name that is plain enough to be written into a
/// configuration: what both key and password logins accept.
pub(crate) fn check_user(user: &str) -> Result<(), TargetError> {
    let ok = !user.is_empty()
        && user.len() <= 32
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(TargetError::User(user.to_owned()))
    }
}

/// Checks that `host` is an IP address or a DNS name: letters, digits, `.`,
/// `-` and `:`, not starting with `-` or `.`, so it can be neither an option
/// nor more than one token.
///
/// # Errors
///
/// Returns [`TargetError::Host`] otherwise.
pub fn check_host(host: &str) -> Result<(), TargetError> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['-', '.'])
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.:".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(TargetError::Host(host.to_owned()))
    }
}

/// A path as an `ssh_config` value: quoted, and refused when it holds a quote,
/// a control character or a `%` or `$` token.
pub(crate) fn path_value(path: &Path) -> Result<String, TargetError> {
    let text = path
        .to_str()
        .ok_or_else(|| TargetError::Path(path.display().to_string()))?;
    let bad = text.is_empty()
        || !path.is_absolute()
        || text.chars().any(|c| c.is_control() || "\"%$".contains(c));
    if bad {
        return Err(TargetError::Path(text.to_owned()));
    }
    Ok(format!("\"{text}\""))
}

/// The configuration for `target`, with the `known_hosts` at `known_hosts`.
///
/// # Errors
///
/// Returns [`TargetError`] when the target does not pass [`Target::check`].
pub fn render(target: &Target, known_hosts: &Path) -> Result<String, TargetError> {
    target.check()?;
    // Every option a connection to a node needs, and every one that could
    // carry it somewhere else or open a channel back, set explicitly.
    let mut text = format!("Host {ALIAS}\n");
    let mut push = |key: &str, value: &str| {
        let _ = writeln!(text, "  {key} {value}");
    };
    push("HostName", &target.host);
    push("Port", &target.port.to_string());
    push("User", &target.user);
    push("HostKeyAlias", ALIAS);
    push("HostKeyAlgorithms", ALGORITHM);
    push("StrictHostKeyChecking", "yes");
    push("UserKnownHostsFile", &path_value(known_hosts)?);
    push("GlobalKnownHostsFile", "/dev/null");
    push("UpdateHostKeys", "no");
    push("CheckHostIP", "no");
    push("BatchMode", "yes");
    push("IdentitiesOnly", "yes");
    match &target.identity {
        Identity::File(path) => {
            push("IdentityFile", &path_value(path)?);
            push("IdentityAgent", "none");
        }
        Identity::Agent { socket, public_key } => {
            push("IdentityFile", &path_value(public_key)?);
            push("IdentityAgent", &path_value(socket)?);
        }
    }
    push("PasswordAuthentication", "no");
    push("KbdInteractiveAuthentication", "no");
    push("ForwardAgent", "no");
    push("ForwardX11", "no");
    push("ClearAllForwardings", "yes");
    push("PermitLocalCommand", "no");
    push("ProxyCommand", "none");
    push("ProxyJump", "none");
    push("RequestTTY", "no");
    push("ControlMaster", "no");
    push("ControlPath", "none");
    push("ConnectTimeout", &CONNECT_TIMEOUT.to_string());
    push("ServerAliveInterval", "15");
    push("ServerAliveCountMax", "4");
    push("LogLevel", "ERROR");
    Ok(text)
}

/// The `known_hosts` line that pins `key` under [`ALIAS`].
#[must_use]
pub fn known_hosts_line(key: &HostKey) -> String {
    format!("{ALIAS} {}\n", key.to_openssh())
}

/// A run's private directory, holding its `ssh_config` and `known_hosts`.
/// Removed, with both files, when dropped.
#[derive(Debug)]
pub struct RunDir {
    dir: tempfile::TempDir,
}

impl RunDir {
    /// Writes the configuration and the pinned host key for `target`.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory or a file cannot be written, or the
    /// target does not pass [`Target::check`].
    pub fn new(target: &Target) -> std::io::Result<Self> {
        target
            .check()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let dir = tempfile::Builder::new().prefix("erpc-ssh-").tempdir()?;
        restrict(dir.path(), 0o700)?;
        let known_hosts = dir.path().join("known_hosts");
        write_private(&known_hosts, known_hosts_line(&target.host_key).as_bytes())?;
        let config = render(target, &known_hosts)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        write_private(&dir.path().join("config"), config.as_bytes())?;
        Ok(Self { dir })
    }

    /// The `ssh_config` to pass with `-F`.
    #[must_use]
    pub fn config(&self) -> PathBuf {
        self.dir.path().join("config")
    }

    /// The `known_hosts` holding the pin.
    #[must_use]
    pub fn known_hosts(&self) -> PathBuf {
        self.dir.path().join("known_hosts")
    }
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

#[cfg(unix)]
pub(crate) fn restrict(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
pub(crate) fn restrict(_: &Path, _: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    #[cfg(unix)]
    use super::RunDir;
    use super::{ALIAS, Identity, Target, TargetError, known_hosts_line, render};
    use crate::hostkey::HostKey;

    /// An absolute fixture on the controller platform, with predictable spelling.
    pub(crate) fn fixture_path(value: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:{value}"))
        } else {
            PathBuf::from(value)
        }
    }

    pub(crate) fn target() -> Target {
        Target {
            host: "203.0.113.5".to_owned(),
            port: 22,
            user: "ubuntu".to_owned(),
            host_key: HostKey::parse(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/",
            )
            .expect("key"),
            identity: Identity::File(fixture_path("/home/op/.ssh/id_ed25519")),
        }
    }

    #[test]
    fn the_configuration_pins_the_key_and_shuts_every_side_door() {
        let known_hosts = fixture_path("/tmp/x/known_hosts");
        let config = render(&target(), &known_hosts).expect("renders");
        assert!(config.contains(&format!(
            "  UserKnownHostsFile \"{}\"\n",
            known_hosts.display()
        )));
        for line in [
            "Host erpc-node",
            "HostName 203.0.113.5",
            "HostKeyAlias erpc-node",
            "HostKeyAlgorithms ssh-ed25519",
            "StrictHostKeyChecking yes",
            "GlobalKnownHostsFile /dev/null",
            "BatchMode yes",
            "IdentitiesOnly yes",
            "IdentityAgent none",
            "ForwardAgent no",
            "ClearAllForwardings yes",
            "PermitLocalCommand no",
            "ProxyCommand none",
            "ProxyJump none",
            "RequestTTY no",
            "ControlMaster no",
        ] {
            assert!(
                config.contains(&format!("  {line}\n")) || config.starts_with(line),
                "{line}\n{config}"
            );
        }
    }

    #[test]
    fn an_agent_identity_names_its_socket_and_key() {
        let mut t = target();
        t.identity = Identity::Agent {
            socket: fixture_path("/home/op/.1password agent/agent.sock"),
            public_key: fixture_path("/home/op/.ssh/node.pub"),
        };
        let config = render(&t, &fixture_path("/tmp/k")).expect("renders");
        for (name, path) in [
            ("IdentityAgent", "/home/op/.1password agent/agent.sock"),
            ("IdentityFile", "/home/op/.ssh/node.pub"),
        ] {
            assert!(config.contains(&format!("  {name} \"{}\"\n", fixture_path(path).display())));
        }
    }

    #[test]
    fn values_that_could_inject_an_option_are_refused() {
        let mut t = target();
        t.host = "203.0.113.5\n  ProxyCommand nc evil 22".to_owned();
        assert!(matches!(t.check(), Err(TargetError::Host(_))));
        let mut t = target();
        t.host = "-oProxyCommand=x".to_owned();
        assert!(matches!(t.check(), Err(TargetError::Host(_))));
        let mut t = target();
        t.user = "root@evil".to_owned();
        assert!(matches!(t.check(), Err(TargetError::User(_))));
        for bad in [
            "relative/key",
            "/tmp/a\"b",
            "/tmp/%h",
            "/tmp/$HOME",
            "/tmp/a\nb",
        ] {
            let mut t = target();
            t.identity = Identity::File(PathBuf::from(bad));
            assert!(matches!(t.check(), Err(TargetError::Path(_))), "{bad}");
        }
    }

    #[test]
    fn the_pin_is_filed_under_the_alias() {
        let line = known_hosts_line(&target().host_key);
        assert!(line.starts_with(&format!("{ALIAS} ssh-ed25519 ")), "{line}");
    }

    #[cfg(unix)]
    #[test]
    fn the_run_directory_is_private_and_gone_when_dropped() {
        use std::os::unix::fs::PermissionsExt as _;
        let run = RunDir::new(&target()).expect("written");
        let dir = run.config().parent().expect("dir").to_path_buf();
        let mode = |p: &std::path::Path| {
            std::fs::metadata(p).expect("exists").permissions().mode() & 0o777
        };
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&run.config()), 0o600);
        assert_eq!(mode(&run.known_hosts()), 0o600);
        drop(run);
        assert!(!dir.exists(), "the run directory outlived the run");
    }
}
