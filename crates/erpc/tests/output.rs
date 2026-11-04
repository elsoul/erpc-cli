// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A command whose output cannot be written fails, rather than reporting
//! success with nothing written.

use std::process::{Command, Stdio};

#[test]
fn output_that_cannot_be_written_fails_the_command() {
    let home = tempfile::tempdir().expect("a temporary directory");
    for args in [
        &["config", "path"][..],
        &["version"],
        &["--json", "version"],
    ] {
        // Its stdout is a pipe nobody reads any more.
        let (reader, writer) = std::io::pipe().expect("a pipe");
        drop(reader);
        let status = Command::new(env!("CARGO_BIN_EXE_erpc"))
            .args(args)
            .env("ERPC_HOME", home.path())
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(Stdio::null())
            .status()
            .expect("erpc runs");
        assert_eq!(status.code(), Some(1), "erpc {}: {status}", args.join(" "));
    }
}
