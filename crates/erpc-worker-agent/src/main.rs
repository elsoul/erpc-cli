// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-worker-agent`: runs an erpc worker app on a Linux server.
//!
//! - `supervise --id <id>` is the worker's systemd unit: it holds the
//!   trading key and the secrets in memory, runs the app from `current`,
//!   and starts it again when it ends.
//! - `ctl --id <id> <verb>` is what erpc runs as root over SSH: it changes
//!   which release is current, checks a release before it runs, and
//!   forwards the rest to `supervise` over its socket.
//!
//! What each does, and the layout they share, is in
//! [`erpc_worker::server`].

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

#[cfg(target_os = "linux")]
mod backup;
#[cfg(target_os = "linux")]
mod services;
// Not Linux-only, so it is checked on any host; only `ctl` calls it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod bench;
// Not Linux-only either, so it is tested on any host.
#[cfg(target_os = "linux")]
mod ctl;
#[cfg(target_os = "linux")]
mod firewall;
#[cfg(target_os = "linux")]
mod supervise;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod wiped;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "erpc-worker-agent",
    version,
    about = "Runs an erpc worker app on this server"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Where a worker's files are; each defaults to its place in
/// [`erpc_worker::server`].
#[derive(clap::Args, Clone)]
struct Place {
    /// The worker: `<app>-<env>`.
    #[arg(long)]
    id: String,
    /// The worker's directory.
    #[arg(long, value_name = "DIR")]
    dir: Option<PathBuf>,
    /// The agent's socket.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the worker: hold its key, run its app, keep it running.
    Supervise {
        #[command(flatten)]
        place: Place,
        /// The agent's state directory.
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
    },
    /// Change or ask about the worker (as root).
    Ctl {
        #[command(flatten)]
        place: Place,
        #[command(subcommand)]
        verb: Verb,
    },
}

/// What `ctl` does.
#[derive(Subcommand, Clone)]
pub(crate) enum Verb {
    /// Write the worker's unit and start its agent.
    Setup {
        /// Restart the agent when it runs: its binary was just replaced.
        #[arg(long)]
        restart_agent: bool,
    },
    /// Move a staged upload into the worker's releases, checked.
    Install {
        /// The release.
        release: String,
    },
    /// Stop the worker and remove its unit, releases and state.
    Remove,
    /// Apply this worker's opening (a request on stdin) to the server's
    /// firewall, under a rollback timer.
    FirewallApply,
    /// Keep the firewall just applied: run over a fresh connection.
    FirewallConfirm,
    /// The server's firewall table and the openings it is made from.
    FirewallShow,
    /// How the worker is, and its releases.
    Status,
    /// Hand over the key and the secrets: one JSON object on standard input.
    Unlock,
    /// Forget the key and the secrets, and stop the app.
    Lock,
    /// Run the app, and keep it running.
    Start,
    /// Stop the app, and keep it stopped.
    Stop,
    /// Stop the app and start it again.
    Restart,
    /// Make a release current, check it comes up healthy, and go back when it does not.
    Activate {
        /// The release.
        release: String,
    },
    /// Go back to the previous release, or to the one named.
    Rollback {
        /// The release to go back to.
        #[arg(long)]
        to: Option<String>,
    },
    /// List the releases kept.
    Releases,
    /// Time JSON-RPC calls from this server: a request on standard input.
    BenchRpc,
    /// Back the worker's state up daily at `--at`: restic's credentials on
    /// standard input.
    BackupSetup {
        /// The time of day, `HH:MM`, 24-hour, in the server's time.
        #[arg(long)]
        at: String,
    },
    /// Stop backing the worker up; what is in the repository stays.
    BackupRemove,
    /// Whether the worker is backed up, and how the last run went.
    BackupStatus,
    /// Back the worker up now, and wait for it.
    BackupNow,
    /// Install and start the local services erpc.toml asks for.
    Services {
        /// Redis, on 127.0.0.1.
        #[arg(long)]
        redis: bool,
        /// PostgreSQL, with a role and database for the worker.
        #[arg(long)]
        postgres: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let id = match &cli.command {
        Command::Supervise { place, .. } | Command::Ctl { place, .. } => place.id.clone(),
    };
    if !erpc_worker::server::is_unit_id(&id) {
        eprintln!("erpc-worker-agent: `{id}` is not a worker id");
        return ExitCode::from(2);
    }
    run(cli.command)
}

#[cfg(target_os = "linux")]
fn run(command: Command) -> ExitCode {
    use erpc_worker::server;
    match command {
        Command::Supervise { place, state } => {
            let dir = place.dir.unwrap_or_else(|| server::worker_dir(&place.id));
            let socket = place
                .socket
                .unwrap_or_else(|| server::socket_path(&place.id));
            let state = state.unwrap_or_else(|| server::state_dir(&place.id));
            match supervise::run(&dir, &socket, &state) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("erpc-worker-agent: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Ctl { place, verb } => {
            let dir = place.dir.unwrap_or_else(|| server::worker_dir(&place.id));
            let socket = place
                .socket
                .unwrap_or_else(|| server::socket_path(&place.id));
            ctl::run(&place.id, &dir, &socket, &verb)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_command: Command) -> ExitCode {
    eprintln!("erpc-worker-agent runs on Linux servers only");
    ExitCode::FAILURE
}
