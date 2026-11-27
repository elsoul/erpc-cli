// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the public command line without an account or a network request.

#![allow(clippy::expect_used)]

use std::io::Write as _;
use std::process::{Command, Stdio};

fn isolated_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("isolated configuration");
    // Even a regression that sends the slash command to the session cannot
    // read from a developer's keychain or a 1Password vault.
    std::fs::write(
        home.path().join("config.toml"),
        "credential_store = \"file\"\n",
    )
    .expect("choose an empty fixture credential store");
    home
}

fn erpc_command(args: &[&str], home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
    command
        .args(args)
        .env_clear()
        .env("ERPC_HOME", home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("PATH", home)
        .env("ERPC_LANG", "en")
        .env("LC_ALL", "C");
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", root);
    }
    command
}

fn erpc(args: &[&str]) -> std::process::Output {
    let home = isolated_home();
    erpc_command(args, home.path())
        .stdin(Stdio::null())
        .output()
        .expect("run erpc")
}

#[test]
fn ai_help_and_completions_only_list_security_checks_in_the_pilot_build() {
    let output = erpc(&["ai", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    for option in ["--message", "--continue", "--model"] {
        assert!(help.contains(option));
    }
    let output = erpc(&["completions", "bash"]);
    assert!(output.status.success());
    let completions = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "--node-check",
        "--security-check-remote",
        "--list-unverified",
    ] {
        assert!(!help.contains(flag));
        assert!(!completions.contains(flag));
    }
    for output in [&help, &completions] {
        assert_eq!(
            output
                .split_whitespace()
                .any(|arg| arg.trim_matches('"') == "--security-check"),
            cfg!(feature = "security-check-pilot")
        );
    }
    assert_eq!(
        erpc(&["--json", "ai", "--security-check"]).status.code(),
        Some(if cfg!(feature = "security-check-pilot") {
            3
        } else {
            2
        })
    );
}

#[cfg(not(feature = "security-check-pilot"))]
#[test]
fn the_standard_build_rejects_the_pilot_flag() {
    let output = erpc(&["--json", "ai", "--security-check"]);
    assert_eq!(output.status.code(), Some(2));
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error record");
    assert_eq!(reply["error"]["code"], "usage");
}

#[test]
fn node_check_slash_input_cannot_be_sent_as_a_chat_message() {
    let home = isolated_home();
    std::fs::write(home.path().join("config.toml"), "invalid TOML")
        .expect("set a broken fixture credential configuration");
    let direct = erpc_command(
        &["--json", "ai", "--message", "/node-check dummy-host"],
        home.path(),
    )
    .stdin(Stdio::null())
    .output()
    .expect("run erpc");
    let mut child = erpc_command(&["--json", "ai"], home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start erpc");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b" /node-check\n")
        .expect("send stdin");
    let piped = child.wait_with_output().expect("run erpc");
    for output in [direct, piped] {
        assert_eq!(output.status.code(), Some(2));
        let reply: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("error record");
        assert_eq!(reply["error"]["code"], "usage");
        assert_eq!(
            reply["error"]["message"],
            "The old node check has been retired. Use erpc ai --security-check in a Security Check pilot build."
        );
    }
}

#[test]
fn security_check_slash_stays_local_in_one_shot_modes() {
    let home = isolated_home();
    std::fs::write(home.path().join("config.toml"), "invalid TOML")
        .expect("prove handling precedes opening credential configuration");
    let direct = erpc_command(
        &["--json", "ai", "--message", "/security-check vps:1"],
        home.path(),
    )
    .stdin(Stdio::null())
    .output()
    .expect("run erpc");
    let mut child = erpc_command(&["--json", "ai"], home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start erpc");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b" /security-check\tvps:1\n")
        .expect("send stdin");
    let piped = child.wait_with_output().expect("run erpc");
    let expected = if cfg!(feature = "security-check-pilot") {
        "Run erpc ai --security-check in your terminal to open Security Check."
    } else {
        "Unknown command: /security-check · /help"
    };
    for output in [direct, piped] {
        assert_eq!(output.status.code(), Some(2));
        let reply: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("error record");
        assert_eq!(reply["error"]["code"], "usage");
        assert_eq!(reply["error"]["message"], expected);
    }
}

#[test]
fn retired_flag_is_rejected_without_starting_a_check() {
    for args in [
        &[][..],
        &["node.example"],
        &["--port", "80"],
        &["--list"],
        &["--kind", "vps", "--id", "5"],
        &["--message", "a question"],
        &["--continue"],
        &["--model", "small"],
    ] {
        let mut command = vec!["--json", "ai", "--node-check"];
        command.extend(args);
        let output = erpc(&command);
        assert_eq!(output.status.code(), Some(2));
        let reply: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("error record");
        assert_eq!(reply["error"]["code"], "usage");
    }
}

#[cfg(feature = "security-check-pilot")]
#[test]
fn ai_remote_check_refuses_arguments_and_chat_flags() {
    for args in [
        &["node.example"][..],
        &["--port", "80"],
        &["--kind", "vps"],
        &["--kind", "bare-metal", "--id", "not-a-number"],
        &["--list", "--node-check"],
        &["--list", "--kind", "vps", "--id", "5"],
        &["--list-unverified"],
        &["--security-check-remote"],
        &["--list-unverified", "--kind", "vps", "--id", "5"],
        &[
            "--kind",
            "vps",
            "--id",
            "5",
            "--host-key",
            "key-without-ssh-user",
        ],
        &[
            "--kind",
            "vps",
            "--id",
            "5",
            "--ssh-user",
            "user-without-host-key",
        ],
        &["--message", "a question"],
        &["--continue"],
        &["--model", "small"],
    ] {
        let mut command = vec!["--json", "ai", "--security-check"];
        command.extend(args);
        let output = erpc(&command);
        assert_eq!(output.status.code(), Some(2));
    }
}

#[cfg(feature = "security-check-pilot")]
#[test]
fn ai_remote_check_requires_a_terminal_and_inventory_requires_a_session() {
    for args in [
        &["--json", "ai", "--security-check"][..],
        &[
            "--json",
            "ai",
            "--security-check",
            "--kind",
            "bare-metal",
            "--id",
            "5",
        ],
    ] {
        let output = erpc(args);
        assert_eq!(output.status.code(), Some(3));
        let reply: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("error record");
        assert_eq!(reply["error"]["code"], "needs_terminal");
    }
    let output = erpc(&["--json", "ai", "--security-check", "--list"]);
    assert_eq!(output.status.code(), Some(4));
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error record");
    assert_eq!(reply["error"]["code"], "not_signed_in");
}
