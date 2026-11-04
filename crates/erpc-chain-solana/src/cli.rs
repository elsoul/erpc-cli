// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The Solana CLI on the operator's machine, run with keys from 1Password
//! and no key file.
//!
//! The CLI takes its signers as paths, and reads a path more than once. erpc
//! writes each key to a file only this user can read, in a directory only
//! this user can enter, for as long as the command runs, and overwrites it
//! with zeros and removes it as soon as the command ends ([`Pipes`]).
//!
//! A process stopped by a signal, or by a panic in a release build, runs no
//! destructors, so the directories alive are also registered for the way
//! out to wipe ([`wipe_live`]); and each holds a lock while its process
//! lives, so one left by a process that is gone can be told apart and wiped
//! later ([`sweep`]).
//!
//! The CLI is found on `PATH`, or where `agave-install` puts it, and its
//! version is read before it is used: registering a BLS key needs 4.1.0.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::versions::{self, Release};

/// Each network's public RPC, which the CLI sends to.
pub const RPC_URLS: [(&str, &str); 1] = [("testnet", "https://api.testnet.solana.com")];

/// The RPC of `network`.
#[must_use]
pub fn rpc_url(network: &str) -> Option<&'static str> {
    RPC_URLS
        .iter()
        .find(|(n, _)| *n == network)
        .map(|(_, u)| *u)
}

/// The oldest CLI erpc runs.
pub const MIN_VERSION: &str = "4.0.0";
/// The oldest CLI that registers a BLS key (`--use-v2-instruction`).
pub const BLS_VERSION: &str = "4.1.0";

/// Why the CLI could not be used.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// No `solana` on `PATH` or where `agave-install` puts it.
    #[error(
        "the Solana CLI is not installed: install Agave's CLI (agave-install) or put `solana` on PATH"
    )]
    NotFound,
    /// It printed no version erpc can read, or one too old.
    #[error("{0}")]
    Version(String),
    /// A pipe or the directory could not be made.
    #[error("could not prepare the signers: {0}")]
    Pipes(String),
    /// The CLI could not be started.
    #[error("could not run solana: {0}")]
    Io(#[from] std::io::Error),
    /// It ran and failed.
    #[error("solana {command} failed: {message}")]
    Failed {
        /// The subcommand.
        command: String,
        /// The last line it wrote to stderr.
        message: String,
    },
}

/// The Solana CLI found on this machine.
#[derive(Debug, Clone)]
pub struct SolanaCli {
    path: PathBuf,
    /// As `solana --version` printed it.
    pub version: String,
    release: Release,
}

/// One argument of a command: text, or a signer, which becomes a pipe.
pub enum Arg<'a> {
    /// Passed as it is.
    Text(&'a str),
    /// A keypair in the `solana-keygen` JSON form, given as a pipe.
    Signer(&'a Zeroizing<String>),
}

impl SolanaCli {
    /// Finds `solana` and reads its version.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NotFound`] when there is none, and
    /// [`CliError::Version`] when it is older than [`MIN_VERSION`].
    pub fn find() -> Result<Self, CliError> {
        let path = candidates()
            .into_iter()
            .find(|p| is_executable(p))
            .ok_or(CliError::NotFound)?;
        let out = Command::new(&path)
            .arg("--version")
            .stdin(Stdio::null())
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let version = text
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let release = versions::read(&version).ok_or_else(|| {
            CliError::Version(format!(
                "{} printed no version erpc can read: {text:?}",
                path.display()
            ))
        })?;
        let cli = Self {
            path,
            version,
            release,
        };
        cli.require(MIN_VERSION, "erpc")?;
        Ok(cli)
    }

    /// Refuses a CLI older than `version`, naming what needs it.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Version`] with how to update.
    pub fn require(&self, version: &str, what: &str) -> Result<(), CliError> {
        if versions::read(version).is_some_and(|min| self.release < min) {
            return Err(CliError::Version(format!(
                "{what} needs solana-cli {version} or later, and {} is {}: \
                 update it with `agave-install init {version}`",
                self.path.display(),
                self.version
            )));
        }
        Ok(())
    }

    /// Where it is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs `solana <args>`, each signer given as a pipe that is removed when
    /// the command ends, and returns what it printed.
    ///
    /// # Errors
    ///
    /// Returns [`CliError`] when the pipes cannot be made, the CLI does not
    /// start, or it fails.
    pub fn run(&self, args: &[Arg<'_>], pipes_in: &Path) -> Result<String, CliError> {
        let mut keys: Vec<&Zeroizing<String>> = Vec::new();
        for arg in args {
            if let Arg::Signer(key) = arg {
                keys.push(key);
            }
        }
        let pipes = Pipes::new(pipes_in, &keys)?;
        let mut next = 0;
        let mut line: Vec<String> = Vec::with_capacity(args.len());
        for arg in args {
            match arg {
                Arg::Text(t) => line.push((*t).to_owned()),
                Arg::Signer(_) => {
                    line.push(pipes.path(next).display().to_string());
                    next += 1;
                }
            }
        }
        // No CLI configuration of the operator's own: every command names its
        // URL and its signers, so nothing falls back to ~/.config/solana.
        let config = pipes.dir().join("config.yml");
        let mut command = Command::new(&self.path);
        command.args(&line).arg("--config").arg(&config);
        let ran = run_with_timeout(command);
        drop(pipes);
        let (ok, stdout, stderr) = ran.map_err(|e| match e {
            CliError::Failed { message, .. } => CliError::Failed {
                command: line.first().cloned().unwrap_or_default(),
                message,
            },
            other => other,
        })?;
        if ok {
            return Ok(stdout);
        }
        let message = failure_line(&stderr, &stdout).chars().take(300).collect();
        Err(CliError::Failed {
            command: line.first().cloned().unwrap_or_default(),
            message,
        })
    }
}

/// The line that says why a command failed: its `Error:` line, else the
/// last line of its stderr, else of its stdout. The CLI prints progress
/// ("Requesting airdrop of 1 SOL") on stdout and the reason on stderr.
fn failure_line<'a>(stderr: &'a str, stdout: &'a str) -> &'a str {
    let last = |t: &'a str| t.lines().map(str::trim).rfind(|l| !l.is_empty());
    stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|l| l.starts_with("Error"))
        .or_else(|| last(stderr))
        .or_else(|| last(stdout))
        .unwrap_or("no message")
}

/// `PATH`, then `agave-install`'s active release.
fn candidates() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("solana"))
                .collect()
        })
        .unwrap_or_default();
    if let Some(home) = std::env::var_os("HOME") {
        out.push(PathBuf::from(home).join(".local/share/solana/install/active_release/bin/solana"));
    }
    out.retain(|p| p.is_absolute());
    out
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// How long a command may take; a slow cluster is the usual reason.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Runs `command` to its end or [`TIMEOUT`], and returns its status and
/// output.
fn run_with_timeout(mut command: Command) -> Result<(bool, String, String), CliError> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let read = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_string(&mut text);
            }
            text
        })
    };
    let out = read(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
    );
    let err = read(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
    );
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if started.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let (out, err) = (
        out.join().unwrap_or_default(),
        err.join().unwrap_or_default(),
    );
    match status {
        Some(status) => Ok((status.success(), out, err)),
        None => Err(CliError::Failed {
            command: String::new(),
            message: format!(
                "it did not finish in {} seconds and was stopped",
                TIMEOUT.as_secs()
            ),
        }),
    }
}

/// Each signer as a key file in a private directory, for as long as one
/// command runs.
///
/// The CLI opens a signer path more than once (`create-vote-account` opens
/// each twice: to check it, then to sign), so a named pipe that serves the
/// key once leaves it waiting, and one that serves it again can hand a reader
/// two copies in a row; the standard library cannot tell when a pipe's
/// reader has let go. So the key is a file: 0600, in a 0700 directory of its
/// own under erpc's state directory, written just before the command and
/// overwritten with zeros and removed as soon as it ends, or when this is
/// dropped for any other reason.
pub struct Pipes {
    dir: PathBuf,
    paths: Vec<PathBuf>,
    /// Locked for as long as this lives: how [`sweep`] tells a directory
    /// in use from one left behind.
    owner: Option<std::fs::File>,
}

/// The signer directories this process has alive, for [`wipe_live`].
static LIVE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
/// The lock file in each signer directory.
const OWNER: &str = ".owner";

/// The name a signer directory has until its lock is held.
const STAGING: &str = ".signers-";
/// How old a directory from before the lock files must be to count as left
/// behind: an erpc of that version may still be running a command, and no
/// command runs for a day.
const UNLOCKED_STALE: Duration = Duration::from_hours(24);

/// Overwrites every file in `dir` with zeros, then removes it all.
fn wipe_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            // Zeros over the key before the name goes, so the blocks the
            // file had do not keep it.
            if let Ok(meta) = std::fs::symlink_metadata(&path)
                && meta.is_file()
                && let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path)
            {
                let zeros = vec![0_u8; usize::try_from(meta.len()).unwrap_or(0)];
                let _ = f.write_all(&zeros);
                let _ = f.sync_all();
            }
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Wipes every signer directory this process has alive. For the ways out
/// that run no destructors: a signal's, and a panic's in a release build.
/// It never waits: a lock held elsewhere is left alone.
pub fn wipe_live() {
    if let Ok(live) = LIVE.try_lock() {
        for dir in live.iter() {
            wipe_dir(dir);
        }
    }
}

/// The signer directories under `base` left by an erpc that is no longer
/// running: their lock is free, or, from before the locks, they are old.
#[must_use]
pub fn leftovers(base: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    let live: Vec<PathBuf> = LIVE.try_lock().map(|l| l.clone()).unwrap_or_default();
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|dir| {
            dir.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("signers-") || n.starts_with(STAGING))
                && std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir())
                && !live.contains(dir)
        })
        .filter(|dir| {
            let old = || {
                std::fs::symlink_metadata(dir)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > UNLOCKED_STALE)
            };
            // A directory still being made holds no key yet, and its lock
            // may not be taken yet: only an old one is left over.
            if dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(STAGING))
            {
                return old();
            }
            match std::fs::File::open(dir.join(OWNER)) {
                // Free means its process is gone: a lock ends with it.
                Ok(owner) => owner.try_lock().is_ok(),
                Err(_) => old(),
            }
        })
        .collect();
    found.sort();
    found
}

/// Wipes the signer directories under `base` that an erpc stopped part way
/// left behind; returns them.
#[must_use]
pub fn sweep(base: &Path) -> Vec<PathBuf> {
    let found = leftovers(base);
    for dir in &found {
        wipe_dir(dir);
    }
    found
}

impl Pipes {
    /// Makes `<base>/signers-<random>/` (0700) and one file (0600) per key.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Pipes`] when the directory or a file cannot be
    /// made; what was made is wiped.
    pub fn new(base: &Path, keys: &[&Zeroizing<String>]) -> Result<Self, CliError> {
        let mut name = [0_u8; 8];
        getrandom::fill(&mut name).map_err(|e| CliError::Pipes(e.to_string()))?;
        let name = name.iter().fold(String::new(), |mut s, b| {
            use core::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        // What an earlier erpc left was swept when this one started.
        std::fs::create_dir_all(base).map_err(|e| CliError::Pipes(e.to_string()))?;
        // Made and locked under a name a sweep passes over until it is old,
        // then given its real one: another erpc's sweep never sees it
        // unlocked.
        let staging = base.join(format!("{STAGING}{name}"));
        let failed = |path: &Path, e: std::io::Error| {
            let _ = std::fs::remove_dir_all(path);
            CliError::Pipes(format!("{}: {e}", path.display()))
        };
        make_private_dir(&staging)
            .map_err(|e| CliError::Pipes(format!("{}: {e}", staging.display())))?;
        let owner = staging.join(OWNER);
        let lock = write_private(&owner, b"")
            .and_then(|()| std::fs::File::open(&owner))
            .and_then(|f| f.lock().map(|()| f))
            .map_err(|e| failed(&staging, e))?;
        let dir = base.join(format!("signers-{name}"));
        std::fs::rename(&staging, &dir).map_err(|e| failed(&staging, e))?;
        if let Ok(mut live) = LIVE.lock() {
            live.push(dir.clone());
        }
        let mut files = Self {
            dir,
            paths: Vec::new(),
            owner: Some(lock),
        };
        for (i, key) in keys.iter().enumerate() {
            let path = files.dir.join(format!("k{i}.json"));
            write_private(&path, key.as_bytes())
                .map_err(|e| CliError::Pipes(format!("{}: {e}", path.display())))?;
            files.paths.push(path);
        }
        Ok(files)
    }

    /// The file of key `i`.
    #[must_use]
    pub fn path(&self, i: usize) -> &Path {
        &self.paths[i]
    }

    /// The directory the files are in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Pipes {
    fn drop(&mut self) {
        wipe_dir(&self.dir);
        // Let go of the lock only once nothing is left to find.
        drop(self.owner.take());
        if let Ok(mut live) = LIVE.lock() {
            live.retain(|d| d != &self.dir);
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(bytes)
}

fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(dir)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;

    use zeroize::Zeroizing;

    use super::{Pipes, SolanaCli, rpc_url};
    use crate::identity::Keypair;

    #[test]
    fn a_directory_being_made_is_not_swept() {
        let base = tempfile::tempdir().expect("dir");
        // Another erpc between making its directory and locking it.
        let making = base
            .path()
            .join(format!("{}0011223344556677", super::STAGING));
        std::fs::create_dir(&making).expect("staging");
        std::fs::write(making.join(super::OWNER), b"").expect("owner");
        assert!(super::sweep(base.path()).is_empty());
        assert!(making.exists());
        let key = Zeroizing::new("[1,2,3]".to_owned());
        let pipes = Pipes::new(base.path(), &[&key]).expect("pipes");
        assert!(
            pipes
                .dir()
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("signers-")),
            "renamed once locked"
        );
        assert!(super::leftovers(base.path()).is_empty(), "its lock is held");
    }

    #[test]
    fn a_signer_file_is_private_while_it_lasts_and_then_gone() {
        let base = tempfile::tempdir().expect("dir");
        let key = Zeroizing::new("[1,2,3]".to_owned());
        let other = Zeroizing::new("[4,5,6]".to_owned());
        let dir;
        {
            let pipes = Pipes::new(base.path(), &[&key, &other]).expect("pipes");
            dir = pipes.dir().to_owned();
            let mode = std::fs::metadata(&dir).expect("dir").permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
            let file = std::fs::metadata(pipes.path(0)).expect("file");
            assert_eq!(file.permissions().mode() & 0o777, 0o600);
            let mut text = String::new();
            std::fs::File::open(pipes.path(0))
                .expect("open")
                .read_to_string(&mut text)
                .expect("read");
            assert_eq!(text, "[1,2,3]");
            // Read twice, as the CLI does.
            let mut again = String::new();
            std::fs::File::open(pipes.path(0))
                .expect("open")
                .read_to_string(&mut again)
                .expect("read");
            assert_eq!(again, "[1,2,3]");
        }
        assert!(!dir.exists(), "the signer directory is removed");
    }

    #[test]
    fn the_reason_is_the_error_line_not_the_progress() {
        assert_eq!(
            super::failure_line(
                "Error: airdrop request failed. This can happen when the rate limit is reached.\n",
                "Requesting airdrop of 1 SOL\n"
            ),
            "Error: airdrop request failed. This can happen when the rate limit is reached."
        );
        assert_eq!(
            super::failure_line("warning\nfatal thing\n", "out"),
            "fatal thing"
        );
        assert_eq!(super::failure_line("", ""), "no message");
    }

    #[test]
    fn only_the_networks_erpc_knows_have_an_rpc() {
        assert!(
            rpc_url("testnet")
                .is_some_and(|u| { erpc_core::endpoints::ensure_service_url(u).is_ok() })
        );
        assert_eq!(rpc_url("localnet"), None);
    }

    /// Runs the real CLI with a pipe signer: `solana address` prints the
    /// public key of the key it read.
    #[test]
    #[ignore = "needs the Solana CLI"]
    fn the_cli_reads_a_signer_from_a_pipe() {
        let cli = SolanaCli::find().expect("solana");
        let keypair = Keypair::generate().expect("key");
        let json = keypair.to_json();
        let base = tempfile::tempdir().expect("dir");
        let out = cli
            .run(
                &[
                    super::Arg::Text("address"),
                    super::Arg::Text("--keypair"),
                    super::Arg::Signer(&json),
                ],
                base.path(),
            )
            .expect("address");
        assert_eq!(out.trim(), keypair.pubkey());
        // And over the network: a new key's balance on testnet is 0.
        let url = rpc_url("testnet").expect("testnet");
        let out = cli
            .run(
                &[
                    super::Arg::Text("balance"),
                    super::Arg::Text("--keypair"),
                    super::Arg::Signer(&json),
                    super::Arg::Text("--url"),
                    super::Arg::Text(url),
                ],
                base.path(),
            )
            .expect("balance");
        assert_eq!(out.trim(), "0 SOL");
        assert_eq!(std::fs::read_dir(base.path()).expect("dir").count(), 0);
    }
}
