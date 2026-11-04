// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Probes a real node through `erpc-ssh`, for checking it by hand:
//!
//! ```text
//! cargo run -p erpc-ssh --example probe -- keyscan <host>
//! cargo run -p erpc-ssh --example probe -- run <host> <user> <agent-socket> <public-key>
//! ```
//!
//! `run` pins the key `keyscan` printed (pass it as `ERPC_PROBE_HOST_KEY`),
//! checks the configuration with `ssh -G`, and runs the read-only commands
//! and a file write under /opt/erpc/.

// A tool run by hand at a terminal: printing is its output.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;

use erpc_ssh::{HostKey, Identity, RemoteCommand, RemotePath, Session, Target, keyscan};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["keyscan", host] => keyscan(host, 22).map(|key| {
            println!("{}", key.to_openssh());
            println!("{}", key.fingerprint());
        }),
        ["run", host, user, socket, public_key] => run(host, user, socket, public_key),
        _ => {
            eprintln!(
                "usage: probe keyscan <host> | probe run <host> <user> <agent-socket> <public-key>"
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(host: &str, user: &str, socket: &str, public_key: &str) -> Result<(), erpc_ssh::SshError> {
    let pinned = std::env::var("ERPC_PROBE_HOST_KEY").unwrap_or_default();
    let host_key = HostKey::parse(&pinned).map_err(erpc_ssh::SshError::NoHostKey)?;
    let target = Target {
        host: host.to_owned(),
        port: 22,
        user: user.to_owned(),
        host_key,
        identity: Identity::Agent {
            socket: PathBuf::from(socket),
            public_key: PathBuf::from(public_key),
        },
    };
    let session = Session::open(&target)?;
    println!("ssh -G: the configuration is used as written");
    for command in [RemoteCommand::Uname, RemoteCommand::OsRelease] {
        let out = session.run(&command, None)?;
        let text = String::from_utf8_lossy(&out.stdout);
        println!("{}: {}", command.line(), text.lines().next().unwrap_or(""));
    }
    let path = RemotePath::new(&format!("/opt/erpc/probe/{}", std::process::id()))
        .map_err(|e| erpc_ssh::SshError::Effective(e.to_string()))?;
    session.run(
        &RemoteCommand::WriteFile(path.clone()),
        Some(b"erpc probe\n"),
    )?;
    let out = session.run(&RemoteCommand::Sha256(path.clone()), None)?;
    println!(
        "wrote {} ({})",
        path.as_str(),
        String::from_utf8_lossy(&out.stdout).trim()
    );
    session.run(&RemoteCommand::Remove(path.clone()), None)?;
    println!("removed {}", path.as_str());
    Ok(())
}
