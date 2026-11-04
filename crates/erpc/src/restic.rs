// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! restic, at one pinned version, and how erpc runs it.
//!
//! The release archive comes from GitHub and is checked against the SHA-256
//! compiled in here, which is restic's own `SHA256SUMS` for [`VERSION`]
//! (that file is signed by restic's release key, `CF8F 18F2 8445 7597 3F79
//! D4E1 91A6 868B D3F7 A907`, checked when the digests were taken). The
//! archive is bzip2, which the system's `bunzip2` unpacks, and the program
//! that comes out is checked against its own pinned digest too, so neither
//! the network nor the unpacker is trusted. A newer digest is never taken
//! from the network: a new restic is a new erpc release.
//!
//! restic runs with a cleared environment. The repository, the access key
//! and the repository password reach it through environment variables, so
//! none of them is on its command line or in a URL.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};

/// The restic erpc installs.
pub const VERSION: &str = "0.19.1";

/// The repository: user-api's restic REST backend, in the account's default
/// region. The same one a worker's server is given, and checks it is given.
pub const REPOSITORY: &str = erpc_worker::server::BACKUP_REPOSITORY;

/// One build of restic: its release archive and the program inside.
struct Pin {
    os: &'static str,
    arch: &'static str,
    archive: &'static str,
    program: &'static str,
}

const PINS: &[Pin] = &[
    Pin {
        os: "linux",
        arch: "amd64",
        archive: "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c",
        program: "20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639",
    },
    Pin {
        os: "linux",
        arch: "arm64",
        archive: "a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465",
        program: "2fb45ac6f9071b6f20eb883953a188f9e7c7cb6bbe43c67a2e47ada4e85ee7f0",
    },
    Pin {
        os: "darwin",
        arch: "amd64",
        archive: "c38d579622cf602f665234c5a8c315030b6cf70656028fe6dc29a786b60e5f35",
        program: "b2b553b402b9971b0c3f673d880397a421526f55a08f21fe5b82b5dd9e049a08",
    },
    Pin {
        os: "darwin",
        arch: "arm64",
        archive: "7be0a144ccc377880f294204aa271d76e4b79554b42a751151d425ce6ebac143",
        program: "06582569ff2f10e1935a6f12187c76db02f0bae99e6e54098f2cdc374766d768",
    },
];

/// The largest archive or program erpc accepts. restic is about 30 MB.
const MAX_BYTES: usize = 96 * 1024 * 1024;

/// restic's exit statuses that erpc tells apart.
pub mod exit {
    /// Some files could not be read; the snapshot was made without them.
    pub const INCOMPLETE: i32 = 3;
    /// There is no repository there.
    pub const NO_REPOSITORY: i32 = 10;
    /// The repository is locked by another run.
    pub const LOCKED: i32 = 11;
    /// The password opens no key of the repository.
    pub const WRONG_PASSWORD: i32 = 12;
}

/// The build for this machine.
fn pin() -> Result<&'static Pin, String> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => return Err(format!("erpc backup does not run on {other}")),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => return Err(format!("erpc backup does not run on {other}")),
    };
    PINS.iter()
        .find(|p| p.os == os && p.arch == arch)
        .ok_or_else(|| format!("erpc backup has no restic for {os}/{arch}"))
}

/// Where the pinned restic is kept.
pub(crate) fn program_path() -> Result<PathBuf, String> {
    crate::session::beside_config(&format!("bin/restic-{VERSION}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Whether the file at `path` is the pinned program.
fn is_pinned(path: &Path, pin: &Pin) -> bool {
    std::fs::read(path).is_ok_and(|bytes| sha256_hex(&bytes) == pin.program)
}

/// The pinned Linux restic for `machine` (`x86_64` or `aarch64`), for a
/// server: downloaded and checked like [`ensure`]'s, and kept beside it so
/// the next server does not download it again. Its digest is checked each
/// time it is read.
///
/// # Errors
///
/// When there is no build for `machine`, or it cannot be downloaded or does
/// not match its digests.
pub async fn linux_program(machine: &str) -> Result<(Vec<u8>, &'static str), String> {
    let arch = match machine {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => return Err(format!("erpc has no restic for {other} Linux")),
    };
    let pin = PINS
        .iter()
        .find(|p| p.os == "linux" && p.arch == arch)
        .ok_or_else(|| format!("erpc has no restic for {machine} Linux"))?;
    let path = crate::session::beside_config(&format!("bin/restic-{VERSION}-linux-{arch}"))?;
    if let Ok(bytes) = std::fs::read(&path)
        && sha256_hex(&bytes) == pin.program
    {
        return Ok((bytes, pin.program));
    }
    let program = fetch(pin).await?;
    keep(&path, &program)?;
    Ok((program, pin.program))
}

/// Downloads `pin`'s archive and unpacks it, checking both digests.
async fn fetch(pin: &Pin) -> Result<Vec<u8>, String> {
    let url = format!(
        "https://github.com/restic/restic/releases/download/v{VERSION}/restic_{VERSION}_{}_{}.bz2",
        pin.os, pin.arch
    );
    let archive = download(&url).await?;
    if sha256_hex(&archive) != pin.archive {
        return Err(format!(
            "the restic {VERSION} archive does not match the digest erpc pinned; nothing was installed"
        ));
    }
    let program = unpack(&archive)?;
    if sha256_hex(&program) != pin.program {
        return Err(format!(
            "the restic {VERSION} program does not match the digest erpc pinned; nothing was installed"
        ));
    }
    Ok(program)
}

/// The pinned restic, installed first if it is not there or not intact.
///
/// # Errors
///
/// When it cannot be downloaded, does not match its digest, or cannot be
/// kept.
pub async fn ensure() -> Result<PathBuf, String> {
    let pin = pin()?;
    let path = program_path()?;
    if is_pinned(&path, pin) {
        return Ok(path);
    }
    if path.exists() {
        crate::interrupt::say(&format!(
            "{} is not the restic {VERSION} erpc pinned; installing it again.",
            path.display()
        ));
    } else {
        crate::interrupt::say(&format!("Installing restic {VERSION}..."));
    }
    let program = fetch(pin).await?;
    keep(&path, &program)?;
    Ok(path)
}

/// Downloads `url`, following GitHub's redirect to its asset host, and
/// checking every host on the way against the declared ones.
async fn download(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("erpc-restic-install")
        .build()
        .map_err(|_| "could not make the download client")?;
    let mut url = url.to_owned();
    for _ in 0..5 {
        erpc_core::endpoints::ensure_service_url(&url).map_err(|e| e.to_string())?;
        let mut response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("could not download restic: {e}"))?;
        if response.status().is_redirection() {
            url = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or("the restic download redirected nowhere")?
                .to_owned();
            continue;
        }
        if !response.status().is_success() {
            return Err(format!(
                "the restic download was refused ({})",
                response.status()
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| format!("the restic download broke off: {e}"))?
        {
            if body.len() + chunk.len() > MAX_BYTES {
                return Err("the restic download is larger than restic is".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        return Ok(body);
    }
    Err("the restic download redirected too often".to_owned())
}

/// The program inside a bzip2 archive, unpacked by the system's `bunzip2`.
fn unpack(archive: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::{Read as _, Write as _};
    let bunzip2 = ["/usr/bin/bunzip2", "/bin/bunzip2"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .ok_or("unpacking restic needs bunzip2; install bzip2 and run this again")?;
    let mut child = Command::new(bunzip2)
        .arg("-c")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not run bunzip2: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("bunzip2 has no input")?;
    let archive = archive.to_vec();
    let feeder = std::thread::spawn(move || stdin.write_all(&archive));
    let mut program = Vec::new();
    child
        .stdout
        .take()
        .ok_or("bunzip2 has no output")?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut program)
        .map_err(|e| format!("could not read what bunzip2 unpacked: {e}"))?;
    let fed = feeder.join().map_err(|_| "feeding bunzip2 failed")?;
    let status = child
        .wait()
        .map_err(|e| format!("bunzip2 did not finish: {e}"))?;
    if fed.is_err() || !status.success() || program.len() > MAX_BYTES {
        return Err("bunzip2 could not unpack the restic archive".to_owned());
    }
    Ok(program)
}

/// Keeps the checked program at `path`, executable by its owner.
fn keep(path: &Path, program: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let dir = path.parent().ok_or("the bin directory has no parent")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    let mut file = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("could not write in {}: {e}", dir.display()))?;
    file.write_all(program)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|e| format!("could not write restic: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("could not make restic executable: {e}"))?;
    }
    file.persist(path)
        .map_err(|e| format!("could not keep {}: {}", path.display(), e.error))?;
    Ok(())
}

/// What restic signs in and opens the repository with.
pub struct Credentials {
    /// The storage access key id (`erpcsk_…`).
    pub key_id: String,
    /// Its secret.
    pub key_secret: SecretString,
    /// A password that opens a key of the repository.
    pub password: SecretString,
}

/// A restic command against the repository, with a cleared environment.
#[must_use]
pub fn command(program: &Path, credentials: &Credentials) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in ["HOME", "TMPDIR", "USER", "LOGNAME", "TERM", "COLUMNS"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Ok(cache) = crate::session::beside_config("cache/restic") {
        command.env("RESTIC_CACHE_DIR", cache);
    }
    command
        .env("RESTIC_REPOSITORY", REPOSITORY)
        .env("RESTIC_REST_USERNAME", &credentials.key_id)
        .env(
            "RESTIC_REST_PASSWORD",
            credentials.key_secret.expose_secret(),
        )
        .env("RESTIC_PASSWORD", credentials.password.expose_secret());
    command
}

/// What a restic run left: its status and what it wrote to stderr.
pub struct Ran {
    /// How it exited.
    pub status: ExitStatus,
    /// What it printed, standard output first.
    pub stdout: String,
    /// What it complained about.
    pub stderr: String,
}

impl Ran {
    /// The exit code, or -1 when it was killed by a signal.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.status.code().unwrap_or(-1)
    }

    /// The last thing restic said, for an error message.
    #[must_use]
    pub fn reason(&self) -> String {
        self.stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .map_or_else(
                || format!("restic exited with {}", self.code()),
                |l| crate::storage::clean(l.trim()),
            )
    }
}

/// Runs `command` quietly, keeping what it printed.
///
/// # Errors
///
/// When restic cannot be started.
pub fn quiet(mut command: Command) -> Result<Ran, String> {
    let out = command
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run restic: {e}"))?;
    Ok(Ran {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Runs `command` with its output on the terminal.
///
/// # Errors
///
/// When restic cannot be started.
pub fn loud(mut command: Command) -> Result<ExitStatus, String> {
    command
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("could not run restic: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pin_is_a_sha256() {
        for p in PINS {
            for digest in [p.archive, p.program] {
                assert_eq!(digest.len(), 64);
                assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
            }
        }
        assert_ne!(PINS[0].archive, PINS[0].program);
    }

    #[test]
    fn this_machine_has_a_build() {
        if cfg!(any(target_os = "linux", target_os = "macos"))
            && cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
        {
            assert!(pin().is_ok());
        }
    }

    #[test]
    fn a_file_is_pinned_only_when_its_digest_matches() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("restic");
        std::fs::write(&path, b"not restic").expect("write");
        let fake = Pin {
            os: "linux",
            arch: "amd64",
            archive: "",
            program: "",
        };
        assert!(!is_pinned(&path, &fake));
        let matching = Pin {
            program: Box::leak(sha256_hex(b"not restic").into_boxed_str()),
            ..fake
        };
        assert!(is_pinned(&path, &matching));
        assert!(!is_pinned(&dir.path().join("absent"), &matching));
    }

    #[cfg(unix)]
    #[test]
    fn restic_gets_the_secrets_from_its_environment_only() {
        let credentials = Credentials {
            key_id: "erpcsk_TESTONLY".to_owned(),
            key_secret: SecretString::from("access-secret".to_owned()),
            password: SecretString::from("repository-password".to_owned()),
        };
        let command = command(Path::new("/usr/bin/env"), &credentials);
        let args: Vec<_> = command.get_args().collect();
        assert!(args.is_empty());
        let envs: Vec<(String, String)> = command
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_owned(), v?.to_str()?.to_owned())))
            .collect();
        assert!(envs.contains(&(
            "RESTIC_REST_PASSWORD".to_owned(),
            "access-secret".to_owned()
        )));
        assert!(envs.contains(&("RESTIC_REPOSITORY".to_owned(), REPOSITORY.to_owned())));
        let out = quiet(command).expect("runs");
        assert!(
            !out.stdout.contains("PATH="),
            "the environment was not cleared"
        );
    }
}
