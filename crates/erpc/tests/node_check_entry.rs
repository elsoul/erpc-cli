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
fn ai_help_and_completions_only_list_the_local_menu_in_the_pilot_build() {
    let output = erpc(&["ai", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    for option in ["--message", "--continue", "--model"] {
        assert!(help.contains(option));
    }
    assert_eq!(
        help.contains("--node-check"),
        cfg!(feature = "node-check-pilot")
    );

    let output = erpc(&["completions", "bash"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).contains("--node-check"),
        cfg!(feature = "node-check-pilot")
    );
}

#[cfg(not(feature = "node-check-pilot"))]
#[test]
fn the_standard_build_rejects_the_node_check_flag() {
    let output = erpc(&["--json", "ai", "--node-check"]);
    assert_eq!(output.status.code(), Some(2));
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error record");
    assert_eq!(reply["error"]["code"], "usage");
}

#[test]
fn node_check_slash_input_cannot_be_sent_as_a_chat_message() {
    let direct = erpc(&["--json", "ai", "--message", "/node-check dummy-host"]);
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
        .write_all(b" /node-check\n")
        .expect("send stdin");
    let piped = child.wait_with_output().expect("run erpc");
    for output in [direct, piped] {
        assert_eq!(output.status.code(), Some(2));
        let reply: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("error record");
        assert_eq!(reply["error"]["code"], "usage");
        let detail = if cfg!(feature = "node-check-pilot") {
            "open local node checks from the interactive erpc ai console"
        } else {
            "Unknown command: /node-check · /help"
        };
        assert_eq!(reply["error"]["message"], detail);
    }
}

#[cfg(feature = "node-check-pilot")]
#[test]
fn ai_node_check_refuses_arguments_and_chat_flags() {
    for args in [
        &["node.example"][..],
        &["--port", "80"],
        &["--message", "a question"],
        &["--continue"],
        &["--model", "small"],
    ] {
        let mut command = vec!["--json", "ai", "--node-check"];
        command.extend(args);
        let output = erpc(&command);
        assert_eq!(output.status.code(), Some(2));
    }
}

#[cfg(feature = "node-check-pilot")]
#[test]
fn ai_node_check_bypasses_chat_and_requires_linux_and_a_terminal() {
    let output = erpc(&["--json", "ai", "--node-check"]);
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error record");
    if cfg!(target_os = "linux") {
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(reply["error"]["code"], "needs_terminal");
    } else {
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(reply["error"]["message"], "the node check requires Linux");
    }
}
