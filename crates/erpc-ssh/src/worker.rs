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
    /// prints `agent=installed` or `agent=unchanged`. Whether the check and
    /// the install succeed or fail, it then removes the staged file and any
    /// temporary an interrupted upload left beside it, and their directory
    /// too when it is empty and sudo allows, keeping its exit status and
    /// output.
    InstallAgent {
        /// The staged upload, under `/opt/erpc/uploads/`.
        staged: crate::RemotePath,
        /// Its digest.
        sha256: Digest,
    },
    /// Installs the restic staged at `staged` when its digest is `sha256`;
    /// prints `restic=installed` or `restic=unchanged`. Cleans up as
    /// [`Command::InstallAgent`] does.
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
    /// One request to the app's API on its loopback port, with `curl`
    /// reading its whole configuration (method, URL, headers, body) from
    /// standard input, so that the API token is on no command line and in
    /// no log. The body comes back on standard output, then the HTTP
    /// status on a last line of its own; the command fails only when the
    /// app gave no answer.
    Api {
        /// The app's `run.port`.
        port: u16,
    },
}

impl Command {
    pub(crate) fn shell(&self) -> String {
        match self {
            // In both install lines the trap cleans up when the line exits,
            // after a success or a failure. It is quiet and cannot fail, so
            // the line keeps its own exit status and output. The `rm` at the
            // end stays, so that a staged file which cannot be removed still
            // fails the line. A line that a signal ends runs no trap in every
            // shell (dash's does not), and leaves the staging as it was.
            Self::InstallAgent { staged, sha256 } => {
                let dir = staged.parent();
                let staged = staged.as_str();
                let sha = &sha256.0;
                format!(
                    "set -eu; \
                     trap 'rm -f -- \"{staged}\" \"{dir}\"/.upload-* 2>/dev/null || true; \
                       sudo -n rmdir -- \"{dir}\" 2>/dev/null || true' EXIT; \
                     printf '%s  %s\\n' '{sha}' '{staged}' | sha256sum -c --quiet - >/dev/null; \
                     if sudo -n test -x '{AGENT}' && \
                        [ \"$(sudo -n sha256sum '{AGENT}' | cut -d' ' -f1)\" = '{sha}' ]; then \
                       echo agent=unchanged; \
                     else \
                       sudo -n install -D -o root -g root -m 0755 -- '{staged}' '{AGENT}'; \
                       echo agent=installed; \
                     fi; \
                     rm -f -- '{staged}'"
                )
            }
            Self::InstallRestic { staged, sha256 } => {
                let dir = staged.parent();
                let staged = staged.as_str();
                let sha = &sha256.0;
                format!(
                    "set -eu; \
                     trap 'rm -f -- \"{staged}\" \"{dir}\"/.upload-* 2>/dev/null || true; \
                       sudo -n rmdir -- \"{dir}\" 2>/dev/null || true' EXIT; \
                     printf '%s  %s\\n' '{sha}' '{staged}' | sha256sum -c --quiet - >/dev/null; \
                     if sudo -n test -x '{RESTIC}' && \
                        [ \"$(sudo -n sha256sum '{RESTIC}' | cut -d' ' -f1)\" = '{sha}' ]; then \
                       echo restic=unchanged; \
                     else \
                       sudo -n install -D -o root -g root -m 0755 -- '{staged}' '{RESTIC}'; \
                       echo restic=installed; \
                     fi; \
                     rm -f -- '{staged}'"
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
            // The port is in the command only so that the line reads for
            // what it is; the URL curl uses comes from its configuration.
            // curl fails only when the app gave no answer; an answer comes
            // back whole, with its HTTP status on a last line of its own,
            // for the caller to judge.
            Self::Api { port } => {
                format!("curl -sS --max-time 30 -w '\\n%{{http_code}}' -K - # 127.0.0.1:{port}")
            }
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

    /// The install lines run as erpc sends them, on Linux as the servers
    /// are: their `sha256sum` and `install -D` are GNU coreutils'.
    #[cfg(target_os = "linux")]
    mod install_lines {
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::Path;

        use sha2::Digest as _;

        use super::super::{AGENT, Command, Digest, RESTIC};

        /// `sudo -n` for the tests: runs its command as this test's user, or
        /// answers for the command named in `REFUSE` as sudo does when it
        /// would need a password.
        const STUB_SUDO: &str = "#!/bin/sh\n\
            [ \"$1\" = -n ] || { echo \"stub sudo: not -n: $*\" >&2; exit 2; }\n\
            shift\n\
            if [ \"$1\" = \"$REFUSE\" ]; then echo 'sudo: a password is required' >&2; exit 1; fi\n\
            exec \"$@\"\n";
        const BINARY: &[u8] = b"the binary";
        /// A temporary that an interrupted upload left beside the staged file.
        const STALE: &str = ".upload-5dac0e3b9f1a4c2e8d7b6a5f4e3d2c1b";

        /// What the install finds where it installs to.
        #[derive(Clone, Copy)]
        enum Lib {
            /// The staged binary, installed before: nothing to install.
            Current,
            /// A plain file where its directory goes: the install fails.
            Blocked,
        }

        /// What a run of the line left.
        #[derive(Debug)]
        struct Ran {
            output: std::process::Output,
            /// The names left in the staging directory; `None` once it is gone.
            left: Option<Vec<String>>,
        }

        /// One install line, run by `shell` with its paths moved under a
        /// temporary root and the stub sudo in `bin` first on `PATH`.
        struct Install<'a> {
            command: Command,
            dir: &'a str,
            file: &'a str,
            target: &'a str,
            bin: &'a Path,
            shell: &'a str,
        }

        impl Install<'_> {
            /// Runs the line on a root as an upload leaves it: `content`
            /// staged, `beside` in the same directory (a directory for a name
            /// ending in `/`), and `lib`. With `locked`, nothing can be
            /// removed from the staging directory while the line runs.
            fn run(
                &self,
                content: &[u8],
                beside: &[&str],
                lib: Lib,
                refuse: &str,
                locked: bool,
            ) -> Ran {
                let root = tempfile::tempdir().expect("tempdir");
                let staging = root.path().join("uploads").join(self.dir);
                std::fs::create_dir_all(&staging).expect("staging");
                std::fs::write(staging.join(self.file), content).expect("staged");
                for name in beside {
                    match name.strip_suffix('/') {
                        Some(name) => std::fs::create_dir(staging.join(name)).expect("beside"),
                        None => std::fs::write(staging.join(name), b"left").expect("beside"),
                    }
                }
                let installed = root
                    .path()
                    .join("lib")
                    .join(self.target.rsplit_once('/').expect("a name").1);
                match lib {
                    Lib::Current => {
                        std::fs::create_dir(root.path().join("lib")).expect("lib");
                        std::fs::write(&installed, BINARY).expect("installed");
                        let mode = std::fs::Permissions::from_mode(0o755);
                        std::fs::set_permissions(&installed, mode).expect("mode");
                    }
                    Lib::Blocked => std::fs::write(root.path().join("lib"), b"").expect("lib"),
                }
                if locked {
                    let mode = std::fs::Permissions::from_mode(0o555);
                    std::fs::set_permissions(&staging, mode).expect("lock");
                }
                let moved = root.path().to_str().expect("a plain temporary path");
                let line = self
                    .command
                    .shell()
                    .replace("/opt/erpc/uploads", &format!("{moved}/uploads"))
                    .replace("/usr/local/lib/erpc", &format!("{moved}/lib"));
                // Nothing on the line may reach this machine's own paths.
                assert!(!line.contains("/opt/") && !line.contains("/usr/"), "{line}");
                let path = std::env::var("PATH").unwrap_or_default();
                let output = std::process::Command::new(self.shell)
                    .args(["-c", &line])
                    .env("PATH", format!("{}:{path}", self.bin.display()))
                    .env("REFUSE", refuse)
                    .output()
                    .expect(self.shell);
                // Nothing but the staged file, the temporary and their
                // directory is removed.
                assert!(root.path().join("uploads").is_dir());
                if let Lib::Current = lib {
                    assert_eq!(std::fs::read(&installed).expect("installed"), BINARY);
                }
                let left = std::fs::read_dir(&staging).ok().map(|entries| {
                    let mut names: Vec<String> = entries
                        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                        .collect();
                    names.sort();
                    names
                });
                if locked {
                    // So that the temporary root can be removed.
                    let mode = std::fs::Permissions::from_mode(0o755);
                    std::fs::set_permissions(&staging, mode).expect("unlock");
                }
                Ran { output, left }
            }
        }

        /// Whether every line of `stderr` is one `tool` wrote, and there is one.
        fn said_only_by(stderr: &[u8], tool: &str) -> bool {
            let text = String::from_utf8_lossy(stderr);
            !text.is_empty() && text.lines().all(|line| line.starts_with(tool))
        }

        #[test]
        fn installing_removes_what_was_staged_after_success_or_failure() {
            let bin = tempfile::tempdir().expect("tempdir");
            let sudo = bin.path().join("sudo");
            std::fs::write(&sudo, STUB_SUDO).expect("stub");
            std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).expect("mode");
            let sha256 = Digest::new(&format!("{:x}", sha2::Sha256::digest(BINARY))).expect("sha");
            // `/proc/self` belongs to the user the test runs as.
            let as_root = std::os::unix::fs::MetadataExt::uid(
                &std::fs::metadata("/proc/self").expect("proc"),
            ) == 0;
            for (dir, file, target) in [
                ("agent", "erpc-worker-agent", AGENT),
                ("restic", "restic", RESTIC),
            ] {
                let staged = crate::RemotePath::new(&format!("/opt/erpc/uploads/{dir}/{file}"))
                    .expect("path");
                let sha256 = sha256.clone();
                let command = if dir == "agent" {
                    Command::InstallAgent { staged, sha256 }
                } else {
                    Command::InstallRestic { staged, sha256 }
                };
                for shell in ["sh", "bash"] {
                    let command = command.clone();
                    let line = Install {
                        command,
                        dir,
                        file,
                        target,
                        bin: bin.path(),
                        shell,
                    };
                    let done = line.run(BINARY, &[STALE], Lib::Current, "", false);
                    assert!(done.output.status.success(), "{done:?}");
                    assert_eq!(
                        done.output.stdout,
                        format!("{dir}=unchanged\n").into_bytes()
                    );
                    assert!(done.output.stderr.is_empty(), "{done:?}");
                    assert_eq!(done.left, None, "{done:?}");
                    // A refused rmdir leaves the directory, emptied, and the
                    // status and the output as they were.
                    let refused = line.run(BINARY, &[STALE], Lib::Current, "rmdir", false);
                    assert_eq!(refused.output, done.output, "{refused:?}");
                    assert_eq!(refused.left, Some(vec![]), "{refused:?}");
                    // Anything else in the directory stays, even a directory
                    // named as a temporary, and so does the directory.
                    let beside = [STALE, "other", ".upload-held/"];
                    let kept = line.run(BINARY, &beside, Lib::Current, "", false);
                    assert_eq!(kept.output, done.output, "{kept:?}");
                    let left = [".upload-held", "other"].map(str::to_owned).to_vec();
                    assert_eq!(kept.left, Some(left), "{kept:?}");
                    // A digest that differs fails as it did, and cleans up.
                    let wrong = line.run(b"another binary", &[STALE], Lib::Current, "", false);
                    assert_eq!(wrong.output.status.code(), Some(1), "{wrong:?}");
                    assert!(wrong.output.stdout.is_empty(), "{wrong:?}");
                    assert!(
                        said_only_by(&wrong.output.stderr, "sha256sum: "),
                        "{wrong:?}"
                    );
                    assert_eq!(wrong.left, None, "{wrong:?}");
                    // So does an install that fails.
                    let failed = line.run(BINARY, &[STALE], Lib::Blocked, "", false);
                    assert!(!failed.output.status.success(), "{failed:?}");
                    assert!(failed.output.stdout.is_empty(), "{failed:?}");
                    assert!(
                        said_only_by(&failed.output.stderr, "install: "),
                        "{failed:?}"
                    );
                    assert_eq!(failed.left, None, "{failed:?}");
                    // The login removes the staged file and the temporary
                    // itself: a sudo that refuses `rm` changes nothing.
                    let no_sudo_rm = line.run(BINARY, &[STALE], Lib::Current, "rm", false);
                    assert_eq!(no_sudo_rm.output, done.output, "{no_sudo_rm:?}");
                    assert_eq!(no_sudo_rm.left, None, "{no_sudo_rm:?}");
                    // A staged file that cannot be removed fails the line,
                    // after the install, with rm's own message. Root removes
                    // it all the same, so this is shown only as a user.
                    if !as_root {
                        let stuck = line.run(BINARY, &[STALE], Lib::Current, "", true);
                        assert_eq!(stuck.output.status.code(), Some(1), "{stuck:?}");
                        assert_eq!(stuck.output.stdout, done.output.stdout, "{stuck:?}");
                        assert!(said_only_by(&stuck.output.stderr, "rm: "), "{stuck:?}");
                        let left = [STALE, file].map(str::to_owned).to_vec();
                        assert_eq!(stuck.left, Some(left), "{stuck:?}");
                    }
                }
            }
        }
    }
}
