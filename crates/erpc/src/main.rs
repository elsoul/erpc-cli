// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc` command line entry point.
//!
//! Phase 0 ships only `erpc version`. The command tree (role-first with a
//! chain context, see `docs/architecture.md`) is added from Phase 1 onwards.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Exit codes shared by every command (documented in `docs/architecture.md`).
mod exit {
    pub const OK: u8 = 0;
    pub const FAILURE: u8 = 1;
}

#[derive(Parser)]
#[command(
    name = "erpc",
    version,
    about = "ERPC command line for node operators and ERPC account holders",
    long_about = None,
    propagate_version = true
)]
struct Cli {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true, env = "ERPC_JSON")]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show version, build and workspace component information.
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            let info = erpc_core::version::VersionInfo::current();
            if cli.json {
                match serde_json::to_string_pretty(&info) {
                    Ok(s) => println!("{s}"),
                    Err(_) => return ExitCode::from(exit::FAILURE),
                }
            } else {
                println!("{info}");
            }
            ExitCode::from(exit::OK)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
