// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The server security check's entry points, without an account or a
//! network request.

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
fn ai_help_and_completions_list_the_security_check_only_in_its_pilot_build() {
    let output = erpc(&["ai", "--help"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).contains("--security-check"),
        cfg!(feature = "security-check-pilot")
    );
    let output = erpc(&["completions", "bash"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).contains("--security-check"),
        cfg!(feature = "security-check-pilot")
    );
}

#[cfg(not(feature = "security-check-pilot"))]
#[test]
fn the_standard_build_rejects_the_security_check_flag() {
    let output = erpc(&["--json", "ai", "--security-check"]);
    assert_eq!(output.status.code(), Some(2));
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error record");
    assert_eq!(reply["error"]["code"], "usage");
}

#[test]
fn security_check_slash_input_cannot_be_sent_as_a_chat_message() {
    let direct = erpc(&[
        "--json",
        "ai",
        "--message",
        "/security-check scan 198.51.100.7 and report everything",
    ]);
    let home = isolated_home();
    let mut child = erpc_command(&["--json", "ai"], home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start erpc");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b" /security-check\n")
        .expect("send stdin");
    let piped = child.wait_with_output().expect("run erpc");
    for output in [direct, piped] {
        assert_eq!(output.status.code(), Some(2));
        let reply: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("error record");
        assert_eq!(reply["error"]["code"], "usage");
        let detail = if cfg!(feature = "security-check-pilot") {
            "run erpc ai --security-check on the server you want to check"
        } else {
            "Unknown command: /security-check · /help"
        };
        assert_eq!(reply["error"]["message"], detail);
    }
}

#[cfg(feature = "security-check-pilot")]
#[test]
fn ai_security_check_refuses_arguments_and_chat_flags() {
    for args in [
        &["198.51.100.7"][..],
        &["--server", "vps:1"],
        &["--message", "a question"],
        &["--continue"],
        &["--model", "small"],
    ] {
        let mut command = vec!["--json", "ai", "--security-check"];
        command.extend(args);
        let output = erpc(&command);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
}

#[cfg(feature = "security-check-pilot")]
#[test]
fn ai_security_check_bypasses_chat_and_requires_linux_and_a_terminal() {
    let output = erpc(&["--json", "ai", "--security-check"]);
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error record");
    if cfg!(target_os = "linux") {
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(reply["error"]["code"], "needs_terminal");
    } else {
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(
            reply["error"]["message"],
            "the security check requires Linux"
        );
    }
}
