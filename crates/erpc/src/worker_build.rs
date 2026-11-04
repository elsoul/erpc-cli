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
    let found = |program: &str, args: &[&str]| {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if !found("zig", &["version"]) {
        return Err(failed(t!("worker_build.no_zig")).hint(t!("worker_build.no_zig_hint")));
    }
    if !found("cargo", &["zigbuild", "--help"]) {
        return Err(
            failed(t!("worker_build.no_zigbuild")).hint(t!("worker_build.no_zigbuild_hint"))
        );
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
            let hint = t!("worker_build.no_std_hint", triple);
            return Err(failed(t!("worker_build.no_std", triple)).hint(hint));
        }
    }
    Ok(())
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
