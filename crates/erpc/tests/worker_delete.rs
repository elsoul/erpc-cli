// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker delete --release-server --yes` stops before anything is
//! removed, or any server reached, when another app on this machine's list
//! is on the server it would end.

use std::process::{Command, Stdio};

#[test]
fn delete_release_server_yes_stops_at_a_server_another_app_is_on() {
    let home = tempfile::tempdir().unwrap();
    let apps = tempfile::tempdir().unwrap();
    let record = "[env.prod]\nhost = \"203.0.113.10\"\n\
                  resource = { kind = \"vps\", id = \"100001\", hourly = true }\n";
    let list = home.path().join("workers.toml");
    for name in ["bot", "sniper"] {
        let dir = apps.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("erpc.toml"),
            format!("name = \"{name}\"\nchain = \"solana\"\n[run]\nport = 3000\n{record}"),
        )
        .unwrap();
        erpc_worker::index::update(&list, |i| Ok(((), i.remember(name, &dir)?))).unwrap();
    }
    let bot = apps.path().join("bot").join("erpc.toml");
    let before = std::fs::read_to_string(&bot).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_erpc"));
    command
        .env_clear()
        .env("ERPC_HOME", home.path())
        .env("PATH", home.path());
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", root);
    }
    command.args([
        "--json",
        "worker",
        "delete",
        "--env",
        "prod",
        "--release-server",
        "--yes",
    ]);
    command.arg("--dir").arg(apps.path().join("bot"));
    let output = command.stdin(Stdio::null()).output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(2), "{text}");
    assert!(text.contains("sniper --env prod"), "{text}");
    // Nothing was removed: the record is as it was.
    assert_eq!(std::fs::read_to_string(&bot).unwrap(), before);
}
