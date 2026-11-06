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

use crate::commands::Outcome;
use crate::error::{CliError, Code};
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

fn sha256_file(path: &Path) -> Result<(String, u64), CliError> {
    let bytes = std::fs::read(path).map_err(|e| {
        let path = path.display();
        failed(t!("worker_build.could_not_read", path, error = e))
    })?;
    Ok((hex(&Sha256::digest(&bytes)), bytes.len() as u64))
}

/// A release built: its record and where the binary is.
pub(crate) struct Built {
    pub(crate) release: Release,
    pub(crate) binary: PathBuf,
    pub(crate) record: PathBuf,
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
    let drawn = crate::ui::Report::new().done(built_line).fields([
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

/// Builds the app at `manifest_path` for its servers and writes its
/// `release.json`.
pub(crate) fn for_servers(
    m: &Manifest,
    manifest_path: &Path,
    say: &Say,
) -> Result<Built, CliError> {
    let root = manifest_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_owned);
    let rest = cargo_build_args(m)?;
    let triple = m.build.target.triple();
    let glibc = is_gnu(m.build.target).then(|| GLIBC_FLOOR.to_owned());
    let zig_target = glibc
        .as_deref()
        .map_or_else(|| triple.to_owned(), |g| format!("{triple}.{g}"));
    check_tools(triple, &root)?;
    let files = shipped(m, &root)?;
    let args = rest.join(" ");
    say.line(&t!("worker_build.building", target = zig_target, args));
    // cargo's own lines (compiling, the app's warnings) are kept in a log
    // beside the build, not shown: they are the app's, and read as erpc's
    // trouble. A failed build shows them on stderr, with --json too, since
    // they say what to fix.
    let out = Command::new("cargo")
        .arg("zigbuild")
        .args(&rest)
        .args(["--target", &zig_target])
        .current_dir(&root)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| failed(t!("worker_build.could_not_run", error = e)))?;
    let log = target_dir(&root).join(BUILD_LOG);
    let mut text = out.stdout;
    text.extend_from_slice(&out.stderr);
    let kept =
        std::fs::create_dir_all(target_dir(&root)).and_then(|()| std::fs::write(&log, &text));
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
    let binary = target_dir(&root).join(triple).join(profile).join(m.bin());
    if !binary.is_file() {
        let bin = binary.display();
        return Err(
            failed(t!("worker_build.no_binary", bin)).hint(t!("worker_build.no_binary_hint"))
        );
    }
    let (sha256, size) = sha256_file(&binary)?;
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
    let record = binary.with_file_name(format!("{}.{}", m.bin(), release::FILE_NAME));
    let text = serde_json::to_string_pretty(&release).map_err(|e| failed(e.to_string()))?;
    std::fs::write(&record, format!("{text}\n")).map_err(|e| {
        let path = record.display();
        failed(t!("worker_build.could_not_write", path, error = e))
    })?;
    Ok(Built {
        release,
        binary,
        record,
    })
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

/// Says what to install when a tool the cross-build needs is not here.
fn check_tools(triple: &str, root: &Path) -> Result<(), CliError> {
    match missing_tools(triple, root, Probe::Toolchain)
        .into_iter()
        .next()
    {
        Some((what, hint)) => Err(failed(what).hint(hint)),
        None => Ok(()),
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
    /// Also ask `rustup`, in the app's directory, whether the target's
    /// standard library is installed. For a build, which runs cargo there
    /// anyway.
    Toolchain,
}

/// Every tool the cross-build for `triple` needs and this machine lacks,
/// each with what installs it: all of them at once, so that a deploy can
/// say so before anything is bought, and `check` before a deploy.
///
/// `zig` and `cargo-zigbuild` are looked for on `PATH` (and in cargo's own
/// `bin`), not run.
pub(crate) fn missing_tools(triple: &str, root: &Path, probe: Probe) -> Vec<(String, String)> {
    let search = search_path();
    let mut lacking = Vec::new();
    if !on_path("zig", &search) {
        lacking.push((t!("worker_build.no_zig"), t!("worker_build.no_zig_hint")));
    }
    if !on_path("cargo-zigbuild", &search) {
        lacking.push((
            t!("worker_build.no_zigbuild"),
            t!("worker_build.no_zigbuild_hint"),
        ));
    }
    if probe == Probe::Look {
        return lacking;
    }
    // Without rustup the toolchain is the operator's own; cargo says what
    // is missing then.
    if let Ok(out) = Command::new("rustup")
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
    lacking
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

    /// The child's side of the probe tests: runs [`super::missing_tools`]
    /// in the directory it was started in. Without `ERPC_TEST_PROBE` it
    /// does nothing, which is how it runs among the other tests.
    #[test]
    fn probe_child() {
        let Ok(probe) = std::env::var("ERPC_TEST_PROBE") else {
            return;
        };
        let probe = match probe.as_str() {
            "look" => super::Probe::Look,
            _ => super::Probe::Toolchain,
        };
        let root = std::env::current_dir().expect("a directory");
        let _ = super::missing_tools("x86_64-unknown-linux-gnu", &root, probe);
    }

    /// Runs the probe in a child process, as `erpc ai` would run `check`:
    /// from an app's directory whose cargo configuration runs its own code
    /// for `cargo zigbuild`, with a `PATH` that holds only a `cargo`, a
    /// `rustup`, a `zig` and a `cargo-zigbuild` that each write their name
    /// when run. Returns the names written: what the probe ran.
    #[cfg(unix)]
    fn ran_by(probe: &str) -> String {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (bin, app) = (dir.path().join("bin"), dir.path().join("app"));
        let marker = dir.path().join("ran");
        std::fs::create_dir_all(app.join(".cargo")).expect("the app");
        std::fs::create_dir(&bin).expect("bin");
        for tool in ["cargo", "rustup", "zig", "cargo-zigbuild"] {
            let file = bin.join(tool);
            let script = format!("#!/bin/sh\necho {tool} >> '{}'\nexit 0\n", marker.display());
            std::fs::write(&file, script).expect("a tool");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).expect("mode");
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
        let status = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(["--exact", "worker_build::tests::probe_child", "--nocapture"])
            .env("ERPC_TEST_PROBE", probe)
            .env("PATH", &bin)
            .env("HOME", dir.path())
            .env("CARGO_HOME", dir.path().join("cargo-home"))
            .current_dir(&app)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("the child");
        assert!(status.success(), "the child failed: {status}");
        std::fs::read_to_string(&marker).unwrap_or_default()
    }

    /// `check`'s look starts no program at all, so nothing in the app's
    /// directory gets to run: not cargo with the app's aliases, not
    /// rustup with its toolchain file, not the tools themselves.
    #[cfg(unix)]
    #[test]
    fn a_look_runs_nothing_from_the_apps_directory() {
        assert_eq!(ran_by("look"), "", "the look ran a program");
    }

    /// The harness catches a program that is run: a build's probe does ask
    /// rustup, and only rustup.
    #[cfg(unix)]
    #[test]
    fn a_builds_probe_asks_rustup_and_runs_no_tool() {
        assert_eq!(ran_by("toolchain"), "rustup\n");
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
        crate::i18n::speaking(erpc_core::i18n::Lang::En, || {
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
        use crate::i18n::speaking;
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
