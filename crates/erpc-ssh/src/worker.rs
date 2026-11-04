// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What erpc runs on a worker's server: the agent installed from a staged
//! upload after its digest checks, the agent's `ctl` verbs, and the
//! worker's journal. Every value on these lines is checked to need no
//! quoting; the key and the secrets go in on standard input, to `ctl
//! unlock`.

/// Where the agent is installed.
pub const AGENT: &str = "/usr/local/lib/erpc/erpc-worker-agent";
/// Where the pinned restic is installed, for a worker's backup.
pub const RESTIC: &str = "/usr/local/lib/erpc/restic";

/// A time of day, `HH:MM`, 24-hour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeOfDay(String);

impl TimeOfDay {
    /// Checks `text`.
    ///
    /// # Errors
    ///
    /// A message when it is not a time of day.
    pub fn new(text: &str) -> Result<Self, String> {
        let b = text.as_bytes();
        let ok = b.len() == 5
            && b[2] == b':'
            && [b[0], b[1], b[3], b[4]].iter().all(u8::is_ascii_digit)
            && (b[0] - b'0') * 10 + (b[1] - b'0') < 24
            && (b[3] - b'0') * 10 + (b[4] - b'0') < 60;
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(format!("{text:?} is not a time of day such as 03:00"))
        }
    }

    /// The time.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A worker's id, `<app>-<env>`: lowercase letters, digits and single
/// hyphens, starting with a letter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitId(String);

impl UnitId {
    /// Checks `id`.
    ///
    /// # Errors
    ///
    /// A message when it is not a worker id.
    pub fn new(id: &str) -> Result<Self, String> {
        let ok = !id.is_empty()
            && id.len() <= 49
            && id.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && !id.ends_with('-')
            && !id.contains("--")
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(id.to_owned()))
        } else {
            Err(format!("{id:?} is not a worker id"))
        }
    }

    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A release id, `<YYYYMMDD>T<HHMMSS>Z-<8 hex>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseId(String);

impl ReleaseId {
    /// Checks `id`.
    ///
    /// # Errors
    ///
    /// A message when it is not a release id.
    pub fn new(id: &str) -> Result<Self, String> {
        let b = id.as_bytes();
        let ok = b.len() == 25
            && b[..8].iter().all(u8::is_ascii_digit)
            && b[8] == b'T'
            && b[9..15].iter().all(u8::is_ascii_digit)
            && b[15] == b'Z'
            && b[16] == b'-'
            && b[17..]
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c));
        if ok {
            Ok(Self(id.to_owned()))
        } else {
            Err(format!("{id:?} is not a release id"))
        }
    }

    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A SHA-256 digest, 64 lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest(String);

impl Digest {
    /// Checks `hex`.
    ///
    /// # Errors
    ///
    /// A message when it is not a digest.
    pub fn new(hex: &str) -> Result<Self, String> {
        if hex.len() == 64
            && hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            Ok(Self(hex.to_owned()))
        } else {
            Err(format!("{hex:?} is not a SHA-256 digest"))
        }
    }
}

/// What `ctl` is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verb {
    /// Writes the unit and starts the agent; restarts it when its binary
    /// was just replaced.
    Setup {
        /// Restart a running agent.
        restart_agent: bool,
    },
    /// Moves a staged release into the worker's releases, checked.
    Install(ReleaseId),
    /// The agent's status, and the releases.
    Status,
    /// The key and the secrets, on standard input.
    Unlock,
    /// Forgets the key and the secrets.
    Lock,
    /// Runs the app.
    Start,
    /// Stops the app.
    Stop,
    /// Restarts the app.
    Restart,
    /// Makes a release current, or goes back.
    Activate(ReleaseId),
    /// Goes back to the previous release, or to the one named.
    Rollback(Option<ReleaseId>),
    /// Lists the releases.
    Releases,
    /// Stops and removes the worker: unit, releases, state.
    Remove,
    /// Applies this worker's opening (a request on standard input) to the
    /// server's firewall, under a rollback timer.
    FirewallApply,
    /// Keeps the firewall just applied; run over a fresh connection.
    FirewallConfirm,
    /// The server's firewall table and its openings.
    FirewallShow,
    /// Time JSON-RPC calls from the server; the request, which can carry
    /// keys, goes on standard input.
    BenchRpc,
    /// Back the worker's state up daily at a time; restic's credentials go
    /// on standard input.
    BackupSetup(TimeOfDay),
    /// Stop backing the worker up.
    BackupRemove,
    /// Whether the worker is backed up, and how the last run went.
    BackupStatus,
    /// Install and start the local services erpc.toml asks for.
    Services {
        /// Redis.
        redis: bool,
        /// PostgreSQL, with a role and database for the worker.
        postgres: bool,
    },
    /// Back the worker up now.
    BackupNow,
}

/// A worker command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Installs the agent staged at `staged` when its digest is `sha256`;
    /// prints `agent=installed` or `agent=unchanged`.
    InstallAgent {
        /// The staged upload, under `/opt/erpc/uploads/`.
        staged: crate::RemotePath,
        /// Its digest.
        sha256: Digest,
    },
    /// Installs the restic staged at `staged` when its digest is `sha256`;
    /// prints `restic=installed` or `restic=unchanged`.
    InstallRestic {
        /// The staged upload, under `/opt/erpc/uploads/`.
        staged: crate::RemotePath,
        /// Its digest.
        sha256: Digest,
    },
    /// One `ctl` verb, as root.
    Ctl {
        /// The worker.
        id: UnitId,
        /// The verb.
        verb: Verb,
    },
    /// The worker's journal.
    Logs {
        /// The worker.
        id: UnitId,
        /// How many lines from the end.
        lines: u32,
        /// Keep printing new lines.
        follow: bool,
    },
}

impl Command {
    pub(crate) fn shell(&self) -> String {
        match self {
            Self::InstallAgent { staged, sha256 } => {
                let dir = staged.parent();
                let staged = staged.as_str();
                let sha = &sha256.0;
                format!(
                    "set -eu; \
                     printf '%s  %s\\n' '{sha}' '{staged}' | sha256sum -c --quiet - >/dev/null; \
                     if sudo -n test -x '{AGENT}' && \
                        [ \"$(sudo -n sha256sum '{AGENT}' | cut -d' ' -f1)\" = '{sha}' ]; then \
                       echo agent=unchanged; \
                     else \
                       sudo -n install -D -o root -g root -m 0755 -- '{staged}' '{AGENT}'; \
                       echo agent=installed; \
                     fi; \
                     rm -f -- '{staged}'; \
                     rmdir -- '{dir}' 2>/dev/null || true"
                )
            }
            Self::InstallRestic { staged, sha256 } => {
                let dir = staged.parent();
                let staged = staged.as_str();
                let sha = &sha256.0;
                format!(
                    "set -eu; \
                     printf '%s  %s\\n' '{sha}' '{staged}' | sha256sum -c --quiet - >/dev/null; \
                     if sudo -n test -x '{RESTIC}' && \
                        [ \"$(sudo -n sha256sum '{RESTIC}' | cut -d' ' -f1)\" = '{sha}' ]; then \
                       echo restic=unchanged; \
                     else \
                       sudo -n install -D -o root -g root -m 0755 -- '{staged}' '{RESTIC}'; \
                       echo restic=installed; \
                     fi; \
                     rm -f -- '{staged}'; \
                     rmdir -- '{dir}' 2>/dev/null || true"
                )
            }
            Self::Ctl { id, verb } => {
                let args = match verb {
                    Verb::Setup { restart_agent } => {
                        if *restart_agent {
                            "setup --restart-agent".to_owned()
                        } else {
                            "setup".to_owned()
                        }
                    }
                    Verb::Install(release) => format!("install '{}'", release.as_str()),
                    Verb::Status => "status".to_owned(),
                    Verb::Unlock => "unlock".to_owned(),
                    Verb::Lock => "lock".to_owned(),
                    Verb::Start => "start".to_owned(),
                    Verb::Stop => "stop".to_owned(),
                    Verb::Restart => "restart".to_owned(),
                    Verb::Activate(release) => format!("activate '{}'", release.as_str()),
                    Verb::Rollback(None) => "rollback".to_owned(),
                    Verb::Rollback(Some(to)) => format!("rollback --to '{}'", to.as_str()),
                    Verb::Releases => "releases".to_owned(),
                    Verb::Remove => "remove".to_owned(),
                    Verb::FirewallApply => "firewall-apply".to_owned(),
                    Verb::FirewallConfirm => "firewall-confirm".to_owned(),
                    Verb::FirewallShow => "firewall-show".to_owned(),
                    Verb::BenchRpc => "bench-rpc".to_owned(),
                    Verb::BackupSetup(at) => format!("backup-setup --at '{}'", at.as_str()),
                    Verb::BackupRemove => "backup-remove".to_owned(),
                    Verb::BackupStatus => "backup-status".to_owned(),
                    Verb::BackupNow => "backup-now".to_owned(),
                    Verb::Services { redis, postgres } => format!(
                        "services{}{}",
                        if *redis { " --redis" } else { "" },
                        if *postgres { " --postgres" } else { "" }
                    ),
                };
                format!("sudo -n '{AGENT}' ctl --id '{}' {args}", id.as_str())
            }
            Self::Logs { id, lines, follow } => format!(
                "sudo -n journalctl --no-pager -o short-iso -n {lines} -u 'erpc-worker-{}.service'{}",
                id.as_str(),
                if *follow { " -f" } else { "" }
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, ReleaseId, UnitId};

    #[test]
    fn values_that_would_need_quoting_are_refused() {
        assert!(UnitId::new("bot-default").is_ok());
        for bad in ["", "Bot", "a'b", "a b", "-a", "a-", "a--b", "$(x)"] {
            assert!(UnitId::new(bad).is_err(), "{bad}");
        }
        assert!(ReleaseId::new("20261029T121314Z-1a2b3c4d").is_ok());
        assert!(ReleaseId::new("20261029T121314Z-1a2b3c4d'").is_err());
        assert!(Digest::new(&"a".repeat(64)).is_ok());
        assert!(Digest::new(&"A".repeat(64)).is_err());
        assert!(super::TimeOfDay::new("23:59").is_ok());
        for bad in ["24:00", "3:00", "03:60", "03:0'", "03-00", "03:00;"] {
            assert!(super::TimeOfDay::new(bad).is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn every_line_is_valid_shell() {
        use std::io::Write as _;

        use super::{Command, Verb};
        let id = UnitId::new("bot-default").expect("id");
        let release = ReleaseId::new("20261029T121314Z-1a2b3c4d").expect("release");
        let mut commands = vec![
            Command::InstallAgent {
                staged: crate::RemotePath::new("/opt/erpc/uploads/agent/erpc-worker-agent")
                    .expect("path"),
                sha256: Digest::new(&"a".repeat(64)).expect("digest"),
            },
            Command::InstallRestic {
                staged: crate::RemotePath::new("/opt/erpc/uploads/restic/restic").expect("path"),
                sha256: Digest::new(&"b".repeat(64)).expect("digest"),
            },
            Command::Logs {
                id: id.clone(),
                lines: 100,
                follow: true,
            },
        ];
        for verb in [
            Verb::Setup {
                restart_agent: true,
            },
            Verb::Install(release.clone()),
            Verb::Status,
            Verb::Unlock,
            Verb::Lock,
            Verb::Start,
            Verb::Stop,
            Verb::Restart,
            Verb::Activate(release.clone()),
            Verb::Rollback(Some(release)),
            Verb::Rollback(None),
            Verb::Remove,
            Verb::Releases,
            Verb::FirewallApply,
            Verb::FirewallConfirm,
            Verb::FirewallShow,
            Verb::BenchRpc,
            Verb::BackupSetup(super::TimeOfDay::new("03:05").expect("time")),
            Verb::BackupRemove,
            Verb::BackupStatus,
            Verb::BackupNow,
            Verb::Services {
                redis: true,
                postgres: true,
            },
        ] {
            commands.push(Command::Ctl {
                id: id.clone(),
                verb,
            });
        }
        for command in commands {
            let line = command.shell();
            let mut child = std::process::Command::new("sh")
                .arg("-n")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .expect("sh");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(line.as_bytes())
                .expect("write");
            assert!(child.wait().expect("wait").success(), "{line}");
        }
    }
}
