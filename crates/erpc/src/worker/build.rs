// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker build`: the app built for the servers it deploys to.
//!
//! The operator's machine is a Mac or another Linux; the servers are x86
//! Linux. `cargo zigbuild` cross-builds with zig as the linker, without
//! Docker, and for a glibc target pins the oldest glibc the binary may need
//! ([`GLIBC_FLOOR`]), so one build runs on every supported Ubuntu.
//!
//! `build.command` says how the app builds for this machine (`cargo build
//! --release`, as `run` uses it); the cross-build is the same command as
//! `cargo zigbuild … --target <triple>`. The binary's digest, the commit it
//! came from and the files shipped with it go into `release.json` beside
//! it ([`erpc_worker::release`]), which `deploy` carries to the server.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use erpc_worker::manifest::{Manifest, Target};
use erpc_worker::release::{self, Release, Shipped, Source};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::account::commands::Outcome;
use crate::cli::error::{CliError, Code};
use crate::node_common::Say;
use crate::worker::{Dir, load};

/// The oldest glibc a `-gnu` build may need: Ubuntu 20.04's. Every Ubuntu
/// ERPC servers run is newer.
pub(crate) const GLIBC_FLOOR: &str = "2.31";

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn could_not_read(path: &Path, error: &std::io::Error) -> CliError {
    let path = path.display();
    failed(t!("worker_build.could_not_read", path, error))
}

/// The bytes of the file at `path`.
fn read(path: &Path) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|e| could_not_read(path, &e))
}

fn sha256_file(path: &Path) -> Result<(String, u64), CliError> {
    let bytes = read(path)?;
    Ok((hex(&Sha256::digest(&bytes)), bytes.len() as u64))
}

/// A release built: its record and where the binary is.
pub(crate) struct Built {
    pub(crate) release: Release,
    pub(crate) binary: PathBuf,
    pub(crate) record: PathBuf,
    /// The binary as it was read, once: the bytes that were checked for
    /// the servers and hashed into the release. A deploy uploads these,
    /// so what was checked, what the record names and what is shipped
    /// cannot differ, whatever happens to the file meanwhile.
    pub(crate) bytes: Vec<u8>,
}

/// `erpc worker build`.
pub(crate) fn build(json: bool, dir: &Dir) -> Outcome {
    let say = Say { quiet: json };
    let built = match load(dir).and_then(|(path, m)| for_servers(&m, &path, &say)) {
        Ok(built) => built,
        Err(e) => return e.into(),
    };
    let r = &built.release;
    if json {
        crate::print_json(&json!({
            "release": r,
            "binary": built.binary,
            "record": built.record,
        }));
        return Outcome::Done(String::new());
    }
    #[allow(
        clippy::cast_precision_loss,
        reason = "a size shown, not computed with"
    )]
    let mib = r.size as f64 / (1024.0 * 1024.0);
    let size = format!("{mib:.1} MiB");
    let (app, id, binary) = (&r.app, &r.id, built.binary.display());
    let built_line = t!("worker_build.built", app, id);
    let glibc = r
        .glibc
        .as_deref()
        .map_or_else(String::new, |glibc| t!("worker_build.glibc", glibc));
    let target = format!("{}{glibc}", r.target);
    let mut lines = vec![
        built_line.clone(),
        format!("  {}", t!("worker_build.binary_for", binary, target, size)),
        format!("  sha256 {}", r.sha256),
    ];
    let commit = |s: &Source| s.commit[..s.commit.len().min(12)].to_owned();
    match &r.source {
        Some(s) if s.dirty => lines.push(format!(
            "  {}",
            t!("worker_build.from_dirty", commit = commit(s))
        )),
        Some(s) => lines.push(format!("  {}", t!("worker_build.from", commit = commit(s)))),
        None => lines.push(format!("  {}", t!("worker_build.not_from_git"))),
    }
    lines.push(format!("  {}", built.record.display()));
    let source = match &r.source {
        Some(s) if s.dirty => t!("worker_build.dirty", commit = commit(s)),
        Some(s) => commit(s),
        None => t!("worker_build.not_from_git"),
    };
    let drawn = crate::cli::ui::Report::new().done(built_line).fields([
        (t!("worker_build.field.binary"), binary.to_string()),
        (t!("worker_build.field.target"), target),
        (t!("worker_build.field.size"), size),
        ("sha256".to_owned(), r.sha256.clone()),
        (t!("worker_build.field.source"), source),
        (
            t!("worker_build.field.record"),
            built.record.display().to_string(),
        ),
    ]);
    Outcome::Done(drawn.or_plain(lines.join("\n")))
}

/// The app's directory, from the path of its erpc.toml: the file's
/// directory, or `.` for one given with none (`--dir erpc.toml`), whose
/// parent is the empty path, where no program can be started.
pub(crate) fn app_root(manifest_path: &Path) -> PathBuf {
    match manifest_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_owned(),
        _ => PathBuf::from("."),
    }
}

/// Builds the app at `manifest_path` for its servers and writes its
/// `release.json`.
pub(crate) fn for_servers(
    m: &Manifest,
    manifest_path: &Path,
    say: &Say,
) -> Result<Built, CliError> {
    let root = app_root(manifest_path);
    let triple = m.build.target.triple();
    let files = shipped(m, &root)?;
    let (binary, glibc, bytes) = binary_for_servers(m, &root, say)?;
    let (sha256, size) = (hex(&Sha256::digest(&bytes)), bytes.len() as u64);
    let (manifest_sha256, _) = sha256_file(manifest_path)?;
    let built_at = erpc_ops::run::utc_now();
    let release = Release {
        format: release::FORMAT,
        id: release::id(&built_at, &sha256),
        app: m.name.clone(),
        bin: m.bin().to_owned(),
        target: triple.to_owned(),
        glibc,
        sha256,
        size,
        built_at,
        source: source(&root),
        manifest_sha256,
        files,
        erpc_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    // Beside the binary cargo built; a prebuilt binary's directory is the
    // operator's, so its record goes with erpc's own build output.
    let record_name = format!("{}.{}", m.bin(), release::FILE_NAME);
    let record = if m.build.prebuilt.is_some() {
        let dir = target_dir(&root).join("erpc");
        std::fs::create_dir_all(&dir).map_err(|e| {
            let path = dir.display();
            failed(t!("worker_build.could_not_write", path, error = e))
        })?;
        dir.join(record_name)
    } else {
        binary.with_file_name(record_name)
    };
    let text = serde_json::to_string_pretty(&release).map_err(|e| failed(e.to_string()))?;
    std::fs::write(&record, format!("{text}\n")).map_err(|e| {
        let path = record.display();
        failed(t!("worker_build.could_not_write", path, error = e))
    })?;
    Ok(Built {
        release,
        binary,
        record,
        bytes,
    })
}

/// The app's binary for its servers, built or taken as it is: where it
/// is, the glibc it needs, and its bytes. The file is read once: what is
/// checked here is what is hashed and what a deploy uploads.
fn binary_for_servers(
    m: &Manifest,
    root: &Path,
    say: &Say,
) -> Result<(PathBuf, Option<String>, Vec<u8>), CliError> {
    let triple = m.build.target.triple();
    match way(m, root, Probe::Toolchain).map_err(first_lacking)? {
        Way::Prebuilt(path) => {
            let (binary, elf, bytes) = prebuilt(m, root, &path, say)?;
            Ok((binary, elf.glibc(), bytes))
        }
        Way::Cross => {
            let glibc = is_gnu(m.build.target).then(|| GLIBC_FLOOR.to_owned());
            let zig_target = glibc
                .as_deref()
                .map_or_else(|| triple.to_owned(), |g| format!("{triple}.{g}"));
            let binary = cargo(m, root, "zigbuild", &zig_target, say)?;
            let bytes = read(&binary)?;
            Ok((binary, glibc, bytes))
        }
        Way::Native => {
            let binary = cargo(m, root, "build", triple, say)?;
            let bytes = read(&binary)?;
            // Linked against this machine's glibc, not the floor the
            // cross-build pins: what it needs is read from the binary.
            let glibc = fit(&bytes, &binary, m.build.target)?.glibc();
            say.line(&match &glibc {
                Some(glibc) => t!("worker_build.native", glibc, floor = GLIBC_FLOOR),
                None => t!("worker_build.native_no_glibc"),
            });
            Ok((binary, glibc, bytes))
        }
    }
}

/// How the binary for the servers comes to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Way {
    /// `build.prebuilt`: built already, by any toolchain; shipped as it is.
    Prebuilt(String),
    /// `cargo zigbuild`: from any machine, for the oldest glibc the servers
    /// may run ([`GLIBC_FLOOR`]).
    Cross,
    /// `cargo build` on a Linux machine of the servers' kind, when the
    /// cross-build's tools are not installed: nothing to install, and the
    /// binary needs the glibc it was linked against.
    Native,
}

/// The way this machine builds `m` for its servers, or what it lacks for
/// any, each with what installs it.
pub(crate) fn way(m: &Manifest, root: &Path, probe: Probe) -> Result<Way, Vec<(String, String)>> {
    if let Some(path) = &m.build.prebuilt {
        return Ok(Way::Prebuilt(path.clone()));
    }
    let search = search_path();
    let mut lacking = Vec::new();
    if !on_path("cargo", &search) {
        lacking.push((
            t!("worker_build.no_cargo"),
            t!("worker_build.no_cargo_hint"),
        ));
        return Err(lacking);
    }
    // The Rust that would build the app, whichever way it is built: none
    // that runs, or one older than the app asks for, and cargo refuses the
    // build, which for a deploy is after the server was bought.
    if probe == Probe::Toolchain {
        let (rustc, named) = compiler();
        lacking.extend(rust_lacking(
            rust_here(root, &rustc),
            rust_needed(root),
            named,
        ));
    }
    let (zig, zigbuild) = (on_path("zig", &search), on_path("cargo-zigbuild", &search));
    if !(zig && zigbuild)
        && builds_natively(m.build.target, std::env::consts::OS, std::env::consts::ARCH)
    {
        return if lacking.is_empty() {
            Ok(Way::Native)
        } else {
            Err(lacking)
        };
    }
    if !zig {
        lacking.push((t!("worker_build.no_zig"), t!("worker_build.no_zig_hint")));
    }
    if !zigbuild {
        lacking.push((
            t!("worker_build.no_zigbuild"),
            t!("worker_build.no_zigbuild_hint"),
        ));
    }
    let triple = m.build.target.triple();
    // Without rustup the toolchain is the operator's own; cargo says what
    // is missing then.
    if probe == Probe::Toolchain
        && let Ok(out) = Command::new("rustup")
            .args(["target", "list", "--installed"])
            .current_dir(root)
            .stdin(Stdio::null())
            .output()
    {
        let installed = String::from_utf8_lossy(&out.stdout);
        if out.status.success() && !installed.lines().any(|l| l.trim() == triple) {
            lacking.push((
                t!("worker_build.no_std", triple),
                t!("worker_build.no_std_hint", triple),
            ));
        }
    }
    if lacking.is_empty() {
        Ok(Way::Cross)
    } else {
        Err(lacking)
    }
}

/// What the Rust that would build the app lacks: the compiler not running
/// there at all (`have` is `None`), or older than the app asks for
/// (`need`). `named` is the variable that named the compiler, when one did
/// ([`compiler`]): what to do is then about that variable, not rustup.
fn rust_lacking(
    have: Option<String>,
    need: Option<String>,
    named: Option<&str>,
) -> Option<(String, String)> {
    let Some(have) = have else {
        return Some(match named {
            Some(var) => (
                t!("worker_build.no_rustc_named", var),
                t!("worker_build.no_rustc_named_hint", var),
            ),
            None => (
                t!("worker_build.no_rustc"),
                t!("worker_build.no_rustc_hint"),
            ),
        });
    };
    let need = need.filter(|need| older(&have, need))?;
    let hint = match named {
        Some(var) => t!("worker_build.old_rust_named_hint", var, need),
        None => t!("worker_build.old_rust_hint", need),
    };
    Some((t!("worker_build.old_rust", have, need), hint))
}

/// The Rust the app at `root` says it needs: `package.rust-version` in its
/// `Cargo.toml`, or, where that is `{ workspace = true }`, the workspace's
/// (`workspace.package.rust-version`), in that file or the first
/// `Cargo.toml` above it that has a `[workspace]`.
fn rust_needed(root: &Path) -> Option<String> {
    // Walked up from the app's absolute path: a relative one (`--dir .` in
    // a workspace's member) has no parent to walk to.
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_owned());
    let read = |dir: &Path| -> Option<toml::Table> {
        std::fs::read_to_string(dir.join("Cargo.toml"))
            .ok()?
            .parse()
            .ok()
    };
    let cargo = read(&root)?;
    let declared = cargo.get("package")?.get("rust-version")?;
    if let Some(version) = declared.as_str() {
        return Some(version.to_owned());
    }
    if declared.get("workspace").and_then(toml::Value::as_bool) != Some(true) {
        return None;
    }
    let workspace = std::iter::once(cargo)
        .chain(root.ancestors().skip(1).filter_map(read))
        .find_map(|table| table.get("workspace").cloned())?;
    workspace
        .get("package")?
        .get("rust-version")?
        .as_str()
        .map(str::to_owned)
}

/// The compiler cargo builds with, as cargo picks it from the
/// environment: the one `RUSTC` names, else `CARGO_BUILD_RUSTC`, else
/// `rustc`; with the variable that named it. A `build.rustc` in the app's
/// cargo configuration is not read.
fn compiler() -> (std::ffi::OsString, Option<&'static str>) {
    ["RUSTC", "CARGO_BUILD_RUSTC"]
        .into_iter()
        .find_map(|var| {
            std::env::var_os(var)
                .filter(|named| !named.is_empty())
                .map(|named| (named, Some(var)))
        })
        .unwrap_or_else(|| ("rustc".into(), None))
}

/// The Rust that builds the app at `root`: `rustc --version` asked of the
/// compiler cargo builds with ([`compiler`]), run there, where a
/// `rust-toolchain.toml` of the app's picks it (a `RUSTUP_TOOLCHAIN` in the
/// environment outranks that file). `None` when it does not run, which
/// cargo then says.
fn rust_here(root: &Path, rustc: &std::ffi::OsStr) -> Option<String> {
    let out = Command::new(rustc)
        .arg("--version")
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| rust_version_of(&String::from_utf8_lossy(&out.stdout)))
        .flatten()
}

/// The version in `rustc --version`'s line (`rustc 1.98.0 (…)`), without a
/// pre-release tag (`1.99.0-nightly` is `1.99.0`).
fn rust_version_of(line: &str) -> Option<String> {
    let version = line.strip_prefix("rustc ")?.split_whitespace().next()?;
    Some(version.split('-').next().unwrap_or(version).to_owned())
}

/// Whether Rust `have` is older than `need`, each `major.minor` or
/// `major.minor.patch`, as Cargo compares `rust-version`.
fn older(have: &str, need: &str) -> bool {
    let parts = |version: &str| {
        let mut parts: Vec<u64> = version
            .split('.')
            .map(|part| part.parse().unwrap_or(0))
            .collect();
        parts.resize(3, 0);
        parts
    };
    parts(have) < parts(need)
}

/// Whether a machine running `os` on `arch` builds for `target` with its
/// own toolchain: Linux of the target's architecture, for a glibc target.
/// A musl target needs a musl toolchain, which the cross-build brings.
fn builds_natively(target: Target, os: &str, arch: &str) -> bool {
    os == "linux" && is_gnu(target) && target.triple().starts_with(&format!("{arch}-"))
}

/// The first thing this machine lacks, as the build's failure.
fn first_lacking(lacking: Vec<(String, String)>) -> CliError {
    match lacking.into_iter().next() {
        Some((what, hint)) => failed(what).hint(hint),
        None => failed(t!("worker_build.no_way")),
    }
}

/// Why a file is not a program, in the words of the run.
fn said(why: crate::worker::elf::NotAProgram) -> String {
    use crate::worker::elf::NotAProgram;
    match why {
        NotAProgram::MacOs => t!("worker_build.elf.macos"),
        NotAProgram::Windows => t!("worker_build.elf.windows"),
        NotAProgram::Script => t!("worker_build.elf.script"),
        NotAProgram::NotElf => t!("worker_build.elf.not_elf"),
        NotAProgram::Bits32 => t!("worker_build.elf.bits32"),
        NotAProgram::BigEndian => t!("worker_build.elf.big_endian"),
        NotAProgram::CutShort => t!("worker_build.elf.cut_short"),
        NotAProgram::NotExecutable => t!("worker_build.elf.not_executable"),
        NotAProgram::NothingToLoad => t!("worker_build.elf.nothing_to_load"),
        NotAProgram::SharedLibrary => t!("worker_build.elf.shared_library"),
    }
}

/// Checks that `bytes`, the binary at `binary`, are a program for
/// `target`'s machine and C library: what the servers can run.
fn fit(bytes: &[u8], binary: &Path, target: Target) -> Result<crate::worker::elf::Elf, CliError> {
    use crate::worker::elf::Libc;
    let path = binary.display();
    let elf = crate::worker::elf::inspect(bytes).map_err(|why| {
        let refused = failed(t!("worker_build.not_for_servers", path, why = said(why)));
        // A static program built to load anywhere is told from a library
        // by a flag its linker writes. One without it reads as a library,
        // though it runs: the way out is said.
        if why == crate::worker::elf::NotAProgram::SharedLibrary {
            refused.hint(t!("worker_build.elf.shared_library_hint"))
        } else {
            refused
        }
    })?;
    let triple = target.triple();
    let arch = elf.machine.arch();
    if !triple.starts_with(&format!("{arch}-")) {
        return Err(failed(t!("worker_build.other_machine", path, arch, triple))
            .hint(t!("worker_build.other_machine_hint")));
    }
    // A static binary runs on any of them. One linked against a C library
    // needs the server to have that library, with its loader at the path
    // the binary names: glibc on a `-gnu` target, which is every ERPC
    // server; musl's loader is on none of them, nor is any other.
    let fits = match &elf.libc {
        Libc::Static => true,
        Libc::Glibc(_) => is_gnu(target),
        Libc::Musl | Libc::Other(_) => false,
    };
    if fits {
        Ok(elf)
    } else {
        let loader = match &elf.libc {
            Libc::Musl => "musl".to_owned(),
            Libc::Other(path) => path.clone(),
            Libc::Glibc(_) | Libc::Static => "glibc".to_owned(),
        };
        Err(failed(t!("worker_build.other_libc", path, loader, triple))
            .hint(t!("worker_build.other_libc_hint")))
    }
}

/// The most that is read of a binary built outside erpc: 1 GiB. `check`
/// reads the one `build.prebuilt` names, in a directory that may be
/// anyone's: whatever is under that name is not read without end.
const MAX_PREBUILT: u64 = 1024 * 1024 * 1024;

/// The prebuilt binary `build.prebuilt` names, read once and checked for
/// the servers: where it is, what it is, and its bytes. Nothing of it is
/// run. A deploy asks this before it buys anything, `check` before a
/// deploy, and the build to ship it: each in the same words.
fn prebuilt_read(
    m: &Manifest,
    root: &Path,
    path: &str,
) -> Result<(PathBuf, crate::worker::elf::Elf, Vec<u8>), CliError> {
    use std::io::Read as _;
    let binary = root.join(path);
    let not_there = || {
        let full = binary.display();
        failed(t!("worker_build.no_prebuilt", path, full)).hint(t!("worker_build.no_prebuilt_hint"))
    };
    let too_large = || {
        failed(t!(
            "worker_build.prebuilt_too_large",
            path = binary.display()
        ))
    };
    // Looked at before it is opened: opening a pipe waits for a writer.
    if !binary.is_file() {
        return Err(not_there());
    }
    // A file of the app: a link under that name that leads out of the
    // app's directory would have `check` read, and a deploy ship, a file
    // from elsewhere on this machine.
    let inside = match (std::fs::canonicalize(root), std::fs::canonicalize(&binary)) {
        (Ok(root), Ok(real)) => real.starts_with(root),
        _ => false,
    };
    if !inside {
        let full = binary.display();
        return Err(failed(t!("worker_build.prebuilt_outside", path, full))
            .hint(t!("worker_build.prebuilt_outside_hint")));
    }
    let file = std::fs::File::open(&binary).map_err(|e| could_not_read(&binary, &e))?;
    let opened = file.metadata().map_err(|e| could_not_read(&binary, &e))?;
    if !opened.is_file() {
        return Err(not_there());
    }
    if opened.len() > MAX_PREBUILT {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(MAX_PREBUILT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| could_not_read(&binary, &e))?;
    if bytes.len() as u64 > MAX_PREBUILT {
        return Err(too_large());
    }
    let elf = fit(&bytes, &binary, m.build.target)?;
    Ok((binary, elf, bytes))
}

/// The prebuilt binary `build.prebuilt` names, checked for the servers
/// and said to be shipped.
fn prebuilt(
    m: &Manifest,
    root: &Path,
    path: &str,
    say: &Say,
) -> Result<(PathBuf, crate::worker::elf::Elf, Vec<u8>), CliError> {
    let read = prebuilt_read(m, root, path)?;
    say.line(&match read.1.glibc() {
        Some(glibc) => t!("worker_build.prebuilt_glibc", path, glibc),
        None => t!("worker_build.prebuilt", path),
    });
    Ok(read)
}

/// The prebuilt binary, for `erpc worker run` on this machine: the same
/// file, when this machine can run what the servers run.
pub(crate) fn prebuilt_here(
    m: &Manifest,
    root: &Path,
    path: &str,
    say: &Say,
) -> Result<PathBuf, CliError> {
    let (binary, ..) = prebuilt(m, root, path, say)?;
    let triple = m.build.target.triple();
    let here = format!("{}-", std::env::consts::ARCH);
    if std::env::consts::OS == "linux" && triple.starts_with(&here) {
        Ok(binary)
    } else {
        Err(failed(t!(
            "worker_build.prebuilt_not_here",
            path,
            triple,
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH
        ))
        .hint(t!("worker_build.prebuilt_not_here_hint")))
    }
}

/// Runs `cargo <subcommand> … --target <target>` for the app and returns
/// the binary it built. cargo's own lines (compiling, the app's warnings)
/// are kept in a log beside the build, not shown: they are the app's, and
/// read as erpc's trouble. A failed build shows them on stderr, with
/// --json too, since they say what to fix.
fn cargo(
    m: &Manifest,
    root: &Path,
    subcommand: &str,
    target: &str,
    say: &Say,
) -> Result<PathBuf, CliError> {
    let rest = cargo_build_args(m)?;
    let triple = m.build.target.triple();
    let args = rest.join(" ");
    say.line(&t!("worker_build.building", subcommand, target, args));
    let out = Command::new("cargo")
        .arg(subcommand)
        .args(&rest)
        .args(["--target", target])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| failed(t!("worker_build.could_not_run", subcommand, error = e)))?;
    let log = target_dir(root).join(BUILD_LOG);
    let mut text = out.stdout;
    text.extend_from_slice(&out.stderr);
    let kept = std::fs::create_dir_all(target_dir(root)).and_then(|()| std::fs::write(&log, &text));
    if !out.status.success() {
        eprint!("{}", String::from_utf8_lossy(&out.stderr));
        let status = out.status;
        let e = failed(t!("worker_build.failed", triple, status));
        return Err(match failure_hint(kept.is_ok(), &log) {
            Some(hint) => e.hint(hint),
            None => e,
        });
    }
    let count = warnings(&String::from_utf8_lossy(&text));
    if let Some(line) = warnings_line(count, &log, kept.as_ref().err()) {
        say.line(&line);
    }
    let profile = if rest.iter().any(|a| a == "--release" || a == "-r") {
        "release"
    } else {
        "debug"
    };
    let binary = target_dir(root).join(triple).join(profile).join(m.bin());
    if !binary.is_file() {
        let bin = binary.display();
        return Err(
            failed(t!("worker_build.no_binary", bin)).hint(t!("worker_build.no_binary_hint"))
        );
    }
    Ok(binary)
}

const fn is_gnu(target: Target) -> bool {
    matches!(target, Target::X86_64Gnu | Target::Aarch64Gnu)
}

/// The arguments after `cargo build` in `build.command`, which the
/// cross-build passes to `cargo zigbuild`. A `--target` there is refused:
/// the target is `build.target`'s.
fn cargo_build_args(m: &Manifest) -> Result<Vec<String>, CliError> {
    let command = &m.build.command;
    match command.as_slice() {
        [cargo, build, rest @ ..] if cargo == "cargo" && build == "build" => {
            if rest
                .iter()
                .any(|a| a == "--target" || a.starts_with("--target="))
            {
                return Err(failed(t!("worker_build.command_has_target")));
            }
            Ok(rest.to_vec())
        }
        _ => {
            let command = command.join(" ");
            Err(failed(t!("worker_build.not_cargo", command)))
        }
    }
}

/// How far [`missing_tools`] may go to find out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    /// Look only: nothing is run. For `check`, which `erpc ai` runs
    /// without asking, in a directory that may be anyone's: `cargo` and
    /// `rustup` read the directory they run in (`.cargo/config.toml`,
    /// `rust-toolchain.toml`), and an alias there runs whatever it names.
    Look,
    /// Also ask, in the app's directory, `rustc` which Rust would build
    /// the app, and `rustup` whether the target's standard library is
    /// installed. For a build (a deploy's, before it buys anything), which
    /// runs cargo there anyway.
    Toolchain,
}

/// Everything this machine lacks to build `m` for its servers, each with
/// what installs it: all of them at once, so that a deploy can say so
/// before anything is bought, and `check` before a deploy. Nothing when
/// this is a Linux machine of the servers' kind, which builds the app
/// with cargo alone.
///
/// An app built already (`build.prebuilt`) needs no tool, and its binary
/// has to be one a server runs: it is read here as the build reads it
/// ([`prebuilt_read`]), so that a script, a binary for another system or
/// one cut short stops a deploy before a server is bought for it, not
/// after.
///
/// `cargo`, `zig` and `cargo-zigbuild` are looked for on `PATH` (and in
/// cargo's own `bin`), not run; a prebuilt binary is read, not run.
pub(crate) fn missing_tools(m: &Manifest, root: &Path, probe: Probe) -> Vec<(String, String)> {
    match way(m, root, probe) {
        Ok(Way::Prebuilt(path)) => prebuilt_read(m, root, &path)
            .err()
            .map(|e| (e.message, e.hint.unwrap_or_default()))
            .into_iter()
            .collect(),
        Ok(_) => Vec::new(),
        Err(lacking) => lacking,
    }
}

/// The directories a program is looked for in: `PATH`, then cargo's
/// `bin` (`$CARGO_HOME/bin`, else `~/.cargo/bin`), where cargo finds its
/// subcommands too.
fn search_path() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")));
    dirs.extend(cargo_home.map(|c| c.join("bin")));
    dirs
}

/// Whether `program` is an executable file in one of `dirs`. Nothing is
/// run to find out.
fn on_path(program: &str, dirs: &[PathBuf]) -> bool {
    let names: &[String] = &if cfg!(windows) {
        vec![
            format!("{program}.exe"),
            format!("{program}.cmd"),
            program.to_owned(),
        ]
    } else {
        vec![program.to_owned()]
    };
    dirs.iter()
        .flat_map(|d| names.iter().map(move |n| d.join(n)))
        .any(|candidate| is_executable(&candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Where cargo's output from the last build is kept, in the target
/// directory.
const BUILD_LOG: &str = "erpc-build.log";

/// The hint on a failed build: where its full output is, when it was kept.
fn failure_hint(kept: bool, log: &Path) -> Option<String> {
    kept.then(|| t!("worker_build.log_hint", path = log.display()))
}

/// The line after a build that succeeded with warnings: how many, and
/// where they are, or why they could not be kept. None without warnings.
fn warnings_line(count: usize, log: &Path, unkept: Option<&std::io::Error>) -> Option<String> {
    let path = log.display();
    (count > 0).then(|| match unkept {
        None => t!("worker_build.warnings", count, path),
        Some(error) => t!("worker_build.warnings_no_log", count, path, error),
    })
}

/// How many warnings cargo's output holds: its own count per crate, else
/// the warnings themselves. A manifest's warnings are cargo's about
/// Cargo.toml, not the code's, and are left out.
fn warnings(output: &str) -> usize {
    // cargo's summary per crate and target: "warning: `bot` (bin "bot")
    // generated 6 warnings (2 duplicates)". The duplicates are counted in
    // another summary already; a manifest's are about Cargo.toml.
    let summaries: Vec<&str> = output
        .lines()
        .filter(|l| l.starts_with("warning: `") && l.contains(" generated "))
        .collect();
    if summaries.is_empty() {
        return output.lines().filter(|l| l.starts_with("warning:")).count();
    }
    summaries
        .iter()
        .filter(|l| !l.contains(" (manifest) "))
        .filter_map(|l| {
            let (_, after) = l.split_once(" generated ")?;
            let count: usize = after.split_whitespace().next()?.parse().ok()?;
            let duplicates = after
                .split_once('(')
                .and_then(|(_, d)| d.split_whitespace().next()?.parse::<usize>().ok())
                .filter(|_| after.contains(" duplicate"))
                .unwrap_or(0);
            Some(count.saturating_sub(duplicates))
        })
        .sum()
}

fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || root.join("target"),
        |d| {
            let d = PathBuf::from(d);
            if d.is_absolute() { d } else { root.join(d) }
        },
    )
}

/// The files `run.files` names, with their digests; a missing one is an
/// error now rather than a release without it.
fn shipped(m: &Manifest, root: &Path) -> Result<Vec<Shipped>, CliError> {
    m.run
        .files
        .iter()
        .map(|path| {
            let full = root.join(path);
            if !full.is_file() {
                let full = full.display();
                return Err(failed(t!("worker_build.not_a_file", path, full)));
            }
            Ok(Shipped {
                path: path.clone(),
                sha256: sha256_file(&full)?.0,
            })
        })
        .collect()
}

/// The commit checked out at `root`, and whether there are changes, when
/// `root` is in a git repository.
fn source(root: &Path) -> Option<Source> {
    let vcs = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    };
    let commit = vcs(&["rev-parse", "HEAD"]).filter(|c| c.len() >= 40)?;
    let dirty = vcs(&["status", "--porcelain"]).is_none_or(|s| !s.is_empty());
    Some(Source { commit, dirty })
}

#[cfg(test)]
mod tests {

    /// `check` is run by `erpc ai` without asking, in a directory that may
    /// be anyone's. Finding the tools must run none of them: a `zig` or a
    /// `cargo-zigbuild` that does something when run is found, and has
    /// done nothing.
    #[cfg(unix)]
    #[test]
    fn the_tools_are_found_without_running_any_of_them() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let marker = dir.path().join("ran");
        for tool in ["zig", "cargo-zigbuild"] {
            let file = dir.path().join(tool);
            std::fs::write(
                &file,
                format!("#!/bin/sh\necho {tool} >> '{}'\n", marker.display()),
            )
            .expect("a tool");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).expect("mode");
        }
        let dirs = vec![dir.path().to_path_buf()];
        assert!(super::on_path("zig", &dirs));
        assert!(super::on_path("cargo-zigbuild", &dirs));
        assert!(!marker.exists(), "a tool was run to find it");
        // A file that cannot be run is not the tool, nor is a directory.
        std::fs::write(dir.path().join("plain"), "").expect("a file");
        std::fs::create_dir(dir.path().join("folder")).expect("a directory");
        assert!(!super::on_path("plain", &dirs));
        assert!(!super::on_path("folder", &dirs));
        assert!(!super::on_path("absent", &dirs));
    }

    /// The child's side of the probe tests, run in the directory it was
    /// started in: `look` and `toolchain` run [`super::missing_tools`] with
    /// that probe, `check` runs what `erpc worker check` runs
    /// ([`crate::worker::deploy_needs`]), and `needed` reads the Rust the
    /// app asks for from the root a relative `erpc.toml` gives, as `--dir`
    /// gives it. What it found goes to `ERPC_TEST_PROBE_OUT`, a line each.
    /// Without `ERPC_TEST_PROBE` it does nothing, which is how it runs
    /// among the other tests.
    #[test]
    fn probe_child() {
        let Ok(probe) = std::env::var("ERPC_TEST_PROBE") else {
            return;
        };
        let root = std::env::current_dir().expect("a directory");
        let m = Manifest::parse("name = \"bot\"\nchain = \"solana\"\n").expect("a manifest");
        let found: Vec<String> =
            crate::cli::i18n::speaking(erpc_core::i18n::Lang::En, || match probe.as_str() {
                "look" => super::missing_tools(&m, &root, super::Probe::Look)
                    .into_iter()
                    .map(|(what, _)| what)
                    .collect(),
                "check" => crate::worker::deploy_needs(&m, &root.join("erpc.toml")),
                "needed" => ["erpc.toml", "./erpc.toml"]
                    .into_iter()
                    .map(|path| {
                        let root = super::app_root(std::path::Path::new(path));
                        super::rust_needed(&root).unwrap_or_default()
                    })
                    .collect(),
                _ => super::missing_tools(&m, &root, super::Probe::Toolchain)
                    .into_iter()
                    .map(|(what, _)| what)
                    .collect(),
            });
        if let Some(out) = std::env::var_os("ERPC_TEST_PROBE_OUT") {
            std::fs::write(out, found.join("\n")).expect("what was found");
        }
    }

    /// Runs [`probe_child`] as `probe`, from `app`, with `env` besides, and
    /// returns what it found.
    fn child(probe: &str, app: &std::path::Path, env: &[(&str, &std::ffi::OsStr)]) -> String {
        let out = app.with_file_name("found");
        // libtest names a test by its path without the crate's name.
        let (_, module) = module_path!().split_once("::").expect("a crate's module");
        let probe_child = format!("{module}::probe_child");
        let status = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(["--exact", &probe_child, "--nocapture"])
            .env("ERPC_TEST_PROBE", probe)
            .env("ERPC_TEST_PROBE_OUT", &out)
            .envs(env.iter().copied())
            .current_dir(app)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("the child");
        assert!(status.success(), "the child failed: {status}");
        std::fs::read_to_string(&out).unwrap_or_default()
    }

    /// A `rust-version` the app takes from the workspace it is a member of
    /// is read whether the app is named by an absolute path or a relative
    /// one: `--dir .` in the member, or `--dir erpc.toml`, whose directory
    /// is the empty path.
    #[test]
    fn a_workspaces_rust_version_is_read_from_a_relative_root() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let member = dir.path().join("bot");
        std::fs::create_dir_all(&member).expect("a directory");
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"bot\"]\n[workspace.package]\nrust-version = \"1.98.1\"\n",
        )
        .expect("Cargo.toml");
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"bot\"\nrust-version.workspace = true\n",
        )
        .expect("Cargo.toml");
        assert_eq!(super::rust_needed(&member).as_deref(), Some("1.98.1"));
        assert_eq!(child("needed", &member, &[]), "1.98.1\n1.98.1");
        assert_eq!(
            super::app_root(std::path::Path::new("erpc.toml")),
            std::path::Path::new(".")
        );
        assert_eq!(
            super::app_root(std::path::Path::new("bot/erpc.toml")),
            std::path::Path::new("bot")
        );
    }

    fn app(build: &str) -> Manifest {
        Manifest::parse(&format!(
            "name = \"bot\"\nchain = \"solana\"\n[build]\n{build}\n"
        ))
        .expect("a manifest")
    }

    #[test]
    fn a_rust_that_does_not_run_or_is_too_old_is_named() {
        use super::rust_lacking;
        let v = |s: &str| Some(s.to_owned());
        let what = |lacking: Option<(String, String)>| lacking.map(|(what, _)| what);
        // No rustc that runs in the app's directory: cargo would not build.
        assert!(what(rust_lacking(None, None, None)).is_some_and(|w| w.contains("rustc")));
        assert!(rust_lacking(None, v("1.98.1"), None).is_some());
        // Older than the app asks for, with a hint that makes the newer
        // one the app's, not only installs it, and says what outranks that.
        let (old, hint) = rust_lacking(v("1.98.0"), v("1.98.1"), None).expect("too old");
        assert!(old.contains("1.98.0") && old.contains("1.98.1"), "{old}");
        assert!(hint.contains("rustup override set 1.98.1"), "{hint}");
        assert!(
            hint.contains("a RUSTUP_TOOLCHAIN set in the environment outranks that override"),
            "{hint}"
        );
        // A compiler a variable named: what to do is about the variable.
        let (none, hint) = rust_lacking(None, v("1.98.1"), Some("RUSTC")).expect("none");
        assert!(
            none.contains("the compiler RUSTC names does not run"),
            "{none}"
        );
        assert!(
            hint.contains("unset RUSTC") && !hint.contains("rustup"),
            "{hint}"
        );
        let (_, hint) =
            rust_lacking(v("1.98.0"), v("1.98.1"), Some("CARGO_BUILD_RUSTC")).expect("too old");
        assert!(
            hint.contains("make CARGO_BUILD_RUSTC name a rustc of 1.98.1 or newer")
                && !hint.contains("rustup"),
            "{hint}"
        );
        // New enough, or asked for nothing.
        assert!(rust_lacking(v("1.98.1"), v("1.98.1"), None).is_none());
        assert!(rust_lacking(v("1.98.0"), None, Some("RUSTC")).is_none());
    }

    #[test]
    fn a_rust_version_a_workspace_gives_its_members_is_read() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let member = dir.path().join("bot");
        std::fs::create_dir_all(&member).expect("a directory");
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"bot\"\nrust-version.workspace = true\n",
        )
        .expect("Cargo.toml");
        // No workspace above it says one: nothing asked for.
        assert_eq!(super::rust_needed(&member), None);
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"bot\"]\n[workspace.package]\nrust-version = \"1.98.1\"\n",
        )
        .expect("Cargo.toml");
        assert_eq!(super::rust_needed(&member).as_deref(), Some("1.98.1"));
        // The app is the workspace itself.
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"bot\"\nrust-version.workspace = true\n\
             [workspace]\n[workspace.package]\nrust-version = \"1.99\"\n",
        )
        .expect("Cargo.toml");
        assert_eq!(super::rust_needed(&member).as_deref(), Some("1.99"));
    }

    #[test]
    fn the_rust_an_app_asks_for_is_compared_as_cargo_compares_it() {
        use super::{older, rust_version_of};
        assert_eq!(
            rust_version_of("rustc 1.98.0 (17067e9ac 2026-08-04)\n").as_deref(),
            Some("1.98.0")
        );
        assert_eq!(
            rust_version_of("rustc 1.99.0-nightly (abc 2026-09-01)").as_deref(),
            Some("1.99.0")
        );
        assert_eq!(rust_version_of("cargo 1.98.0"), None);
        assert!(older("1.98.0", "1.98.1"));
        assert!(older("1.97.1", "1.98"));
        assert!(!older("1.98.1", "1.98.1"));
        assert!(!older("1.98.0", "1.98"));
        assert!(!older("1.99.0", "1.98.1"));
        assert!(!older("2.0.0", "1.98.1"));
    }

    /// An app that asks for a newer Rust than the one that would build it
    /// is told so before anything is bought, whichever way it is built;
    /// one that asks for none, or for an older one, is not.
    #[test]
    fn an_app_that_needs_a_newer_rust_is_told_before_anything_is_bought() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let m = app("");
        let cargo = |rust: &str| {
            let package = format!("[package]\nname = \"bot\"\nversion = \"0.1.0\"\n{rust}");
            std::fs::write(dir.path().join("Cargo.toml"), package).expect("Cargo.toml");
        };
        let said = |probe| match super::way(&m, dir.path(), probe) {
            Ok(_) => Vec::new(),
            Err(lacking) => lacking.into_iter().map(|(what, _)| what).collect(),
        };
        cargo("rust-version = \"99.0\"\n");
        assert_eq!(super::rust_needed(dir.path()).as_deref(), Some("99.0"));
        let lacking = said(super::Probe::Toolchain);
        assert!(
            lacking.iter().any(|what| what.contains("99.0")),
            "{lacking:?}"
        );
        // Looking only runs nothing, rustc included.
        assert!(
            !said(super::Probe::Look)
                .iter()
                .any(|what| what.contains("99.0"))
        );
        cargo("rust-version = \"1.0\"\n");
        assert!(
            !said(super::Probe::Toolchain)
                .iter()
                .any(|what| what.contains("rust-version"))
        );
        cargo("");
        assert_eq!(super::rust_needed(dir.path()), None);
    }

    #[test]
    fn a_linux_machine_of_the_servers_kind_builds_without_the_cross_build() {
        use super::builds_natively;
        use erpc_worker::manifest::Target;
        // The servers' own kind: cargo alone builds for it.
        assert!(builds_natively(Target::X86_64Gnu, "linux", "x86_64"));
        assert!(builds_natively(Target::Aarch64Gnu, "linux", "aarch64"));
        // Another architecture, another system, or a musl target: the
        // cross-build is what builds those.
        assert!(!builds_natively(Target::X86_64Gnu, "linux", "aarch64"));
        assert!(!builds_natively(Target::X86_64Gnu, "macos", "x86_64"));
        assert!(!builds_natively(Target::X86_64Gnu, "windows", "x86_64"));
        assert!(!builds_natively(Target::X86_64Musl, "linux", "x86_64"));
    }

    /// What the review found: before a server was bought a prebuilt
    /// binary only had to be there. What it is was read by the build,
    /// after the purchase.
    #[test]
    fn a_prebuilt_binary_is_read_before_anything_is_bought() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let m = app("prebuilt = \"dist/bot\"");
        assert_eq!(
            super::way(&m, dir.path(), super::Probe::Look),
            Ok(super::Way::Prebuilt("dist/bot".to_owned()))
        );
        let lacking = || {
            crate::cli::i18n::speaking(erpc_core::i18n::Lang::En, || {
                super::missing_tools(&m, dir.path(), super::Probe::Look)
            })
        };
        // Not there yet: said, with what to do.
        let absent = lacking();
        assert_eq!(absent.len(), 1, "{absent:?}");
        assert!(
            absent[0].0.contains("build.prebuilt names dist/bot"),
            "{absent:?}"
        );
        assert!(
            absent[0].1.contains("build the app's Linux binary"),
            "{absent:?}"
        );
        // There, and nothing a server runs: said for what it is, in the
        // words the build fails with.
        std::fs::create_dir(dir.path().join("dist")).expect("dist");
        let binary = dir.path().join("dist/bot");
        for (bytes, why) in [
            (&b"#!/bin/sh\nexec python3 bot.py\n"[..], "it is a script"),
            (
                &[0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1][..],
                "it is a macOS binary",
            ),
            (&b"MZ\x90\0"[..], "it is a Windows binary"),
            (&b"anything"[..], "it is not a Linux (ELF) binary"),
            (&b"\x7fELF\x02\x01\x01"[..], "it is cut short"),
        ] {
            std::fs::write(&binary, bytes).expect("a file");
            let said = lacking();
            assert_eq!(said.len(), 1, "{said:?}");
            assert!(said[0].0.contains("cannot run on a server"), "{said:?}");
            assert!(said[0].0.contains(why), "{said:?}");
            let built = crate::cli::i18n::speaking(erpc_core::i18n::Lang::En, || {
                super::prebuilt_read(&m, dir.path(), "dist/bot").expect_err("refused")
            });
            assert_eq!(built.message, said[0].0, "the build's own words");
        }
        // More than is read of one: refused by its size, not read. Where
        // a file can be that long and hold nothing.
        #[cfg(unix)]
        {
            let huge = std::fs::File::create(&binary).expect("a file");
            huge.set_len(super::MAX_PREBUILT + 1).expect("sparse");
            let said = lacking();
            assert!(said[0].0.contains("larger than 1 GiB"), "{said:?}");
        }
        // A directory under the name is not a binary that is there.
        std::fs::remove_file(&binary).expect("removed");
        std::fs::create_dir(&binary).expect("a directory");
        assert!(lacking()[0].0.contains("is not a file"));
        // A link that leads out of the app is not the app's binary: not
        // read, whatever is there. One to a file inside the app is.
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = tempfile::tempdir().expect("another directory");
            let elsewhere = outside.path().join("bot");
            std::fs::write(
                &elsewhere,
                b"#!/bin/sh
",
            )
            .expect("a file elsewhere");
            std::fs::remove_dir(&binary).expect("removed");
            symlink(&elsewhere, &binary).expect("a link out");
            let said = lacking();
            assert_eq!(said.len(), 1, "{said:?}");
            assert!(
                said[0].0.contains("leads out of the app's directory")
                    && said[0]
                        .1
                        .contains("copy the binary into the app's directory"),
                "{said:?}"
            );
            std::fs::remove_file(&binary).expect("removed");
            std::fs::write(
                dir.path().join("dist/real"),
                b"#!/bin/sh
",
            )
            .expect("a file inside");
            symlink("real", &binary).expect("a link inside");
            assert!(lacking()[0].0.contains("it is a script"), "{:?}", lacking());
        }
    }

    /// The prebuilt binary is read once: the bytes checked for the
    /// servers are the ones hashed into the release and handed to the
    /// deploy to upload.
    #[test]
    fn a_prebuilt_binary_is_read_once_for_the_check_the_hash_and_the_upload() {
        use crate::worker::elf::fixture::{GLIBC_X86_64, X86_64, linked};
        use sha2::{Digest as _, Sha256};
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir(dir.path().join("dist")).expect("dist");
        let binary = dir.path().join("dist/bot");
        let program = linked(X86_64, GLIBC_X86_64, b"\0GLIBC_2.17\0GLIBC_2.34\0");
        std::fs::write(&binary, &program).expect("a binary");
        let manifest = dir.path().join("erpc.toml");
        let text = "name = \"bot\"\nchain = \"solana\"\n[build]\nprebuilt = \"dist/bot\"\n";
        std::fs::write(&manifest, text).expect("erpc.toml");
        let m = Manifest::parse(text).expect("a manifest");
        assert!(super::missing_tools(&m, dir.path(), super::Probe::Look).is_empty());
        let say = crate::node_common::Say { quiet: true };
        let built = super::for_servers(&m, &manifest, &say).expect("built");
        assert_eq!(built.binary, binary);
        // What was checked, what the record names and what a deploy
        // uploads are the same bytes.
        assert_eq!(built.bytes, program);
        assert_eq!(built.release.size, program.len() as u64);
        assert_eq!(built.release.sha256, super::hex(&Sha256::digest(&program)));
        assert_eq!(built.release.glibc.as_deref(), Some("2.34"));
    }

    #[test]
    fn a_prebuilt_binary_is_shipped_only_when_the_servers_can_run_it() {
        use crate::worker::elf::fixture::{AARCH64, GLIBC_X86_64, X86_64, elf, linked};
        use erpc_worker::manifest::Target;
        let path = std::path::Path::new("dist/bot");
        let fit = |bytes: &[u8], target| {
            crate::cli::i18n::speaking(erpc_core::i18n::Lang::En, || {
                super::fit(bytes, path, target)
            })
        };
        // A script, and a binary for another system: refused for what
        // they are.
        let script = fit(b"#!/bin/sh\n", Target::X86_64Gnu).expect_err("a script");
        assert!(script.message.contains("script"), "{}", script.message);
        // A program linked against glibc fits a glibc target of its
        // machine, and says the glibc it needs.
        let glibc = linked(X86_64, GLIBC_X86_64, b"\0GLIBC_2.39\0");
        let elf_read = fit(&glibc, Target::X86_64Gnu).expect("fits");
        assert_eq!(elf_read.glibc().as_deref(), Some("2.39"));
        let other = fit(&glibc, Target::Aarch64Gnu).expect_err("another machine");
        assert!(other.message.contains("x86_64"), "{}", other.message);
        // On a musl target there is no glibc to load it.
        let musl = fit(&glibc, Target::X86_64Musl).expect_err("no glibc there");
        assert!(musl.message.contains("glibc"), "{}", musl.message);
        // A static one runs on every target of its machine.
        let fixed = elf(2, AARCH64, None, &[], b"");
        assert!(fit(&fixed, Target::Aarch64Gnu).is_ok());
        assert!(fit(&fixed, Target::Aarch64Musl).is_ok());
        // One linked against musl's loader, or glibc's somewhere a
        // server does not have it, runs on none.
        for loader in [
            "/lib/ld-musl-x86_64.so.1",
            "/store/lib/ld-linux-x86-64.so.2",
        ] {
            let linked = linked(X86_64, loader, b"");
            for target in [Target::X86_64Gnu, Target::X86_64Musl] {
                let refused = fit(&linked, target).expect_err("no such loader there");
                assert!(
                    refused.message.contains("is linked against"),
                    "{}",
                    refused.message
                );
            }
        }
        // A library and a binary cut short are no program at all.
        let library = elf(3, X86_64, None, &[(1, 1)], b"");
        let refused = fit(&library, Target::X86_64Gnu).expect_err("a library");
        assert!(
            refused.message.contains("shared library"),
            "{}",
            refused.message
        );
        // A static program without its linker's flag reads as a library:
        // the way out is in the hint.
        assert!(
            refused
                .hint
                .as_deref()
                .is_some_and(|hint| hint.contains("-no-pie") && hint.contains("-static-pie")),
            "{:?}",
            refused.hint
        );
        let refused = fit(&glibc[..200], Target::X86_64Gnu).expect_err("cut short");
        assert!(refused.message.contains("cut short"), "{}", refused.message);
        assert_eq!(refused.hint, None);
    }

    /// Runs the probe in a child process, as `erpc ai` would run `check`:
    /// from an app's directory whose cargo configuration runs its own code
    /// for `cargo zigbuild`, with a `PATH` that holds only a `cargo`, a
    /// `rustup`, a `zig`, a `cargo-zigbuild` and a `rustc` that each write
    /// their name when run (the `rustc` then fails: no Rust runs there).
    /// Returns the names written, what the probe ran, and what it found.
    #[cfg(unix)]
    fn ran_by(probe: &str) -> (String, String) {
        ran_by_with(probe, None)
    }

    /// [`ran_by`], with `var` (`RUSTC` or `CARGO_BUILD_RUSTC`) naming a
    /// compiler of its own, `named-rustc`, that says it is Rust `version`
    /// (or fails, for an empty one), for an app that asks for 1.98.1.
    #[cfg(unix)]
    fn ran_by_with(probe: &str, named: Option<(&str, &str)>) -> (String, String) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (bin, app) = (dir.path().join("bin"), dir.path().join("app"));
        let marker = dir.path().join("ran");
        std::fs::create_dir_all(app.join(".cargo")).expect("the app");
        std::fs::create_dir(&bin).expect("bin");
        for tool in ["cargo", "rustup", "zig", "cargo-zigbuild", "rustc"] {
            let file = bin.join(tool);
            let exit = u8::from(tool == "rustc");
            let script = format!(
                "#!/bin/sh\necho {tool} >> '{}'\nexit {exit}\n",
                marker.display()
            );
            std::fs::write(&file, script).expect("a tool");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).expect("mode");
        }
        let named_rustc = bin.join("named-rustc");
        if let Some((_, version)) = named {
            let says = if version.is_empty() {
                "exit 1".to_owned()
            } else {
                format!("echo 'rustc {version} (0 2026-11-01)'")
            };
            let script = format!(
                "#!/bin/sh\necho named-rustc >> '{}'\n{says}\n",
                marker.display()
            );
            std::fs::write(&named_rustc, script).expect("a compiler");
            std::fs::set_permissions(&named_rustc, std::fs::Permissions::from_mode(0o755))
                .expect("mode");
            std::fs::write(
                app.join("Cargo.toml"),
                "[package]\nname = \"bot\"\nversion = \"0.1.0\"\nrust-version = \"1.98.1\"\n",
            )
            .expect("Cargo.toml");
        }
        // What made the look dangerous: cargo run from here runs the app.
        std::fs::write(
            app.join(".cargo/config.toml"),
            "[alias]\nzigbuild = [\"run\", \"--\"]\n",
        )
        .expect("the app's cargo config");
        std::fs::write(
            app.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.98.0\"\n",
        )
        .expect("the app's toolchain");
        // Both variables are given, empty unless named: none of the
        // environment's own reaches the child.
        let var = |which: &str| {
            if named.is_some_and(|(var, _)| var == which) {
                named_rustc.clone().into_os_string()
            } else {
                std::ffi::OsString::new()
            }
        };
        let (rustc, cargo_build_rustc) = (var("RUSTC"), var("CARGO_BUILD_RUSTC"));
        let found = child(
            probe,
            &app,
            &[
                ("PATH", bin.as_os_str()),
                ("HOME", dir.path().as_os_str()),
                ("ERPC_HOME", dir.path().join("erpc-home").as_os_str()),
                ("CARGO_HOME", dir.path().join("cargo-home").as_os_str()),
                ("RUSTC", rustc.as_os_str()),
                ("CARGO_BUILD_RUSTC", cargo_build_rustc.as_os_str()),
            ],
        );
        (std::fs::read_to_string(&marker).unwrap_or_default(), found)
    }

    /// `check`'s look starts no program at all, so nothing in the app's
    /// directory gets to run: not cargo with the app's aliases, not
    /// rustup with its toolchain file, not rustc, not the tools themselves.
    /// Held for the look itself and for what `erpc worker check` runs.
    #[cfg(unix)]
    #[test]
    fn a_look_runs_nothing_from_the_apps_directory() {
        assert_eq!(ran_by("look").0, "", "the look ran a program");
        let (ran, found) = ran_by("check");
        assert_eq!(ran, "", "check ran a program");
        // It looked all the same: what a deploy would lack is said.
        assert!(found.contains("SSH key"), "{found}");
    }

    /// The harness catches a program that is run: a build's probe does ask
    /// rustc and rustup, and only those; a rustc that does not run there is
    /// named, as cargo would not build either.
    #[cfg(unix)]
    #[test]
    fn a_builds_probe_asks_rustc_and_rustup_and_runs_no_tool() {
        let (ran, found) = ran_by("toolchain");
        assert_eq!(ran, "rustc\nrustup\n");
        assert!(
            found.contains("rustc does not run in the app's directory"),
            "{found}"
        );
        assert!(!ran_by("look").1.contains("rustc"));
    }

    /// The Rust asked is the one cargo builds with: the compiler `RUSTC`,
    /// else `CARGO_BUILD_RUSTC`, names, when one is set, not the `rustc` on
    /// `PATH`. Older than the app asks for, or not running, it is named
    /// with the variable; new enough, nothing is.
    #[cfg(unix)]
    #[test]
    fn a_builds_probe_asks_the_compiler_the_environment_names() {
        for var in ["RUSTC", "CARGO_BUILD_RUSTC"] {
            let (ran, found) = ran_by_with("toolchain", Some((var, "1.98.1")));
            assert_eq!(ran, "named-rustc\nrustup\n", "{var}");
            assert!(
                !found.contains("does not run") && !found.contains("builds the app here"),
                "{var}: {found}"
            );
            let (_, found) = ran_by_with("toolchain", Some((var, "1.98.0")));
            assert!(
                found.contains("Rust 1.98.0 builds the app here, and it needs 1.98.1"),
                "{var}: {found}"
            );
            let (_, found) = ran_by_with("toolchain", Some((var, "")));
            assert!(
                found.contains(&format!("the compiler {var} names does not run")),
                "{var}: {found}"
            );
        }
    }
    use super::cargo_build_args;
    use erpc_worker::manifest::Manifest;

    fn with_command(command: &str) -> Manifest {
        Manifest::parse(&format!(
            "name = \"bot\"\nchain = \"solana\"\n[build]\ncommand = {command}\n"
        ))
        .expect("valid")
    }

    #[test]
    fn warnings_are_counted_from_cargos_own_summary() {
        let out = "warning: unused import: `x`\n --> src/main.rs:7:60\n\
                   warning: `bot` (bin \"bot\") generated 6 warnings (run `cargo fix`)\n\
                   warning: `bot` (bin \"notify-test\") generated 1 warning\n\
                   Finished `release` profile [optimized] target(s) in 1.01s\n";
        assert_eq!(super::warnings(out), 7);
        assert_eq!(super::warnings("warning: a\nwarning: b\n"), 2);
        assert_eq!(super::warnings("Finished `release` profile\n"), 0);
        // As cargo prints them: the manifest's own line, then its summary.
        assert_eq!(
            super::warnings(
                "warning: Cargo.toml: unused manifest key: package.foo\n\
                 warning: `bot` (manifest) generated 1 warning\n"
            ),
            0
        );
        assert_eq!(
            super::warnings(
                "warning: `bot` (bin \"bot\") generated 2 warnings\n\
                 warning: `bot` (bin \"bot\" test) generated 2 warnings (2 duplicates)\n"
            ),
            2
        );
    }

    #[test]
    fn a_build_says_where_its_output_is_or_why_it_is_not() {
        crate::cli::i18n::speaking(erpc_core::i18n::Lang::En, || {
            let log = std::path::Path::new("/app/target/erpc-build.log");
            assert_eq!(
                super::failure_hint(true, log).as_deref(),
                Some("the full output is in /app/target/erpc-build.log")
            );
            assert_eq!(super::failure_hint(false, log), None);
            assert_eq!(super::warnings_line(0, log, None), None);
            let line = super::warnings_line(7, log, None).expect("said");
            assert!(
                line.contains("warnings: 7") && line.contains("erpc-build.log"),
                "{line}"
            );
            let full = std::io::Error::other("disk full");
            let line = super::warnings_line(2, log, Some(&full)).expect("said");
            assert!(
                line.contains("warnings: 2") && line.contains("disk full"),
                "{line}"
            );
        });
    }

    #[test]
    fn the_cross_build_takes_the_arguments_after_cargo_build() {
        let m = with_command(r#"["cargo", "build", "--release", "--locked"]"#);
        assert_eq!(
            cargo_build_args(&m).expect("cargo"),
            ["--release", "--locked"]
        );
        assert!(cargo_build_args(&with_command(r#"["make", "release"]"#)).is_err());
        assert!(cargo_build_args(&with_command(r#"["cargo", "build", "--target", "x"]"#)).is_err());
    }

    #[test]
    fn what_build_says_is_said_in_the_language_of_the_run() {
        use crate::cli::i18n::speaking;
        use erpc_core::i18n::Lang;
        let english = t!("worker_build.built", app = "bot", id = "r1");
        assert_eq!(english, "Built bot release r1");
        for lang in [Lang::Ja, Lang::Ru] {
            let said = speaking(lang, || t!("worker_build.built", app = "bot", id = "r1"));
            assert_ne!(said, english);
            assert!(!said.contains('{'), "{said}");
            assert!(said.contains("bot") && said.contains("r1"), "{said}");
        }
    }
}
