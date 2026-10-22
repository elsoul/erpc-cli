// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc` command line entry point.
//!
//! Phase 1 adds the session commands. Wiring only: the decisions live in
//! `erpc-auth`, and this file turns them into output and exit codes.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use erpc_auth::store::StoreKind;

mod session;

/// Exit codes shared by every command.
mod exit {
    /// The command did what was asked.
    pub const OK: u8 = 0;
    /// The command failed.
    pub const FAILURE: u8 = 1;
    /// The command needs a person at a terminal and there is none.
    pub const NEEDS_TERMINAL: u8 = 3;
    /// There is no usable session; run `erpc login`.
    pub const SESSION_EXPIRED: u8 = 4;
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

/// Which credential store to use, when the operator wants to choose.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum StoreChoice {
    /// 1Password through the desktop application.
    #[value(name = "1password-desktop")]
    OnePasswordDesktop,
    /// 1Password through a service account token.
    #[value(name = "1password-service-account")]
    OnePasswordServiceAccount,
    /// The operating system keychain.
    Keychain,
    /// A file on disk. Leaves a secret on this machine.
    File,
}

impl From<StoreChoice> for StoreKind {
    fn from(choice: StoreChoice) -> Self {
        match choice {
            StoreChoice::OnePasswordDesktop => Self::OnePasswordDesktop,
            StoreChoice::OnePasswordServiceAccount => Self::OnePasswordServiceAccount,
            StoreChoice::Keychain => Self::OsKeychain,
            StoreChoice::File => Self::File,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Show version, build and workspace component information.
    Version,
    /// Sign in to your ERPC account.
    Login {
        /// Keep the session in this store instead of the detected one.
        #[arg(long, value_enum)]
        store: Option<StoreChoice>,
        /// Print the URL and code instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Sign out and remove the stored session.
    Logout {
        /// Remove the session from this store instead of the detected one.
        #[arg(long, value_enum)]
        store: Option<StoreChoice>,
    },
    /// Show who the stored session belongs to.
    Whoami,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Login { store, no_browser } => login(cli.json, store, no_browser),
        Command::Logout { store } => logout(cli.json, store),
        Command::Whoami => whoami(cli.json),
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

/// Reports the store a session would go to, and stops.
///
/// The device grant's HTTP side is the next piece of this phase. Until it
/// is here, this says so plainly rather than printing a success it did not
/// achieve.
fn login(json: bool, store: Option<StoreChoice>, no_browser: bool) -> ExitCode {
    let selection = session::plan_store(store.map(Into::into));
    let report = session::StoreReport::from(selection);

    if !no_browser && !session::has_terminal() {
        emit_error(
            json,
            "erpc login needs a terminal, or --no-browser to print the code instead",
        );
        return ExitCode::from(exit::NEEDS_TERMINAL);
    }

    if json {
        let body = serde_json::json!({
            "status": "not-implemented",
            "audience": session::LOGIN_AUDIENCE.as_str(),
            "store": report,
        });
        print_json(&body);
    } else {
        println!("Sign-in would use the {} store.", report.store);
        println!("  because {}", report.reason);
        if report.writes_to_disk {
            println!("  warning: {}", session::DISK_WARNING);
        }
        println!("The sign-in exchange itself is not wired up yet in this build.");
    }
    ExitCode::from(exit::FAILURE)
}

/// Removes the stored session.
fn logout(json: bool, store: Option<StoreChoice>) -> ExitCode {
    let selection = session::plan_store(store.map(Into::into));
    let report = session::StoreReport::from(selection);
    if json {
        print_json(&serde_json::json!({
            "status": "not-implemented",
            "store": report,
        }));
    } else {
        println!(
            "Sign-out would clear the session from the {} store.",
            report.store
        );
        println!("The sign-out exchange itself is not wired up yet in this build.");
    }
    ExitCode::from(exit::FAILURE)
}

/// Shows who the stored session belongs to.
fn whoami(json: bool) -> ExitCode {
    if json {
        print_json(&serde_json::json!({
            "status": "no-session",
            "hint": "run `erpc login`",
        }));
    } else {
        println!("Not signed in. Run `erpc login`.");
    }
    ExitCode::from(exit::SESSION_EXPIRED)
}

/// Prints a JSON body, or fails loudly if it cannot be rendered.
fn print_json(body: &serde_json::Value) {
    match serde_json::to_string_pretty(body) {
        Ok(text) => println!("{text}"),
        Err(e) => eprintln!("could not render JSON: {e}"),
    }
}

/// Prints an error the same way in both output modes.
fn emit_error(json: bool, message: &str) {
    if json {
        print_json(&serde_json::json!({ "status": "error", "message": message }));
    } else {
        eprintln!("error: {message}");
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
