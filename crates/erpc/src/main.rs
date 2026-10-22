// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc` command line entry point.
//!
//! Phase 1 adds the session commands. Wiring only: the decisions live in
//! `erpc-auth`, and this file turns them into output and exit codes.
//!
//! One store is built here rather than in `erpc-auth`, because choosing a
//! concrete backend needs the machine's own facts -- where `op` is, what
//! this host is called -- and the library should not go looking for them.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use erpc_auth::store::{StoreError, StoreKind};

mod browser;
mod commands;
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
    Whoami {
        /// Look in this store instead of the detected one.
        #[arg(long, value_enum)]
        store: Option<StoreChoice>,
    },
}

/// Every store this build can use, behind one object.
///
/// Boxed so that the command bodies are written once rather than once per
/// backend.
///
/// # Errors
///
/// Returns [`StoreError::Unavailable`] when the chosen backend is not
/// usable here: `op` missing for a 1Password store, or no vault
/// configured for it.
pub fn store_for(kind: StoreKind) -> Result<Box<dyn erpc_auth::CredentialStore>, StoreError> {
    use erpc_auth::store::one_password::{Mode, OnePassword, OpCli};
    match kind {
        StoreKind::File => Ok(Box::new(erpc_auth::store::file::FileStore::new(
            session::state_dir().join("credentials.toml"),
        ))),
        StoreKind::OsKeychain => Ok(Box::new(erpc_auth::store::keychain::OsKeychain::new())),
        StoreKind::OnePasswordDesktop | StoreKind::OnePasswordServiceAccount => {
            let mode = if kind == StoreKind::OnePasswordDesktop {
                Mode::Desktop
            } else {
                Mode::ServiceAccount
            };
            let runner = OpCli::from_env(mode, |n| std::env::var_os(n))?;
            let vault =
                std::env::var("ERPC_CREDENTIAL_VAULT").map_err(|_| StoreError::Unavailable {
                    kind,
                    reason: "no vault is configured; set ERPC_CREDENTIAL_VAULT to a 1Password \
                             vault id, or use --store keychain"
                        .to_owned(),
                })?;
            Ok(Box::new(OnePassword::new(
                runner,
                mode,
                vault,
                session::host_label(),
            )))
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Login { store, no_browser } => {
            commands::login(cli.json, store.map(Into::into), no_browser).await
        }
        Command::Logout { store } => commands::logout(cli.json, store.map(Into::into)).await,
        Command::Whoami { store } => commands::whoami(cli.json, store.map(Into::into)).await,
        Command::Version => {
            let info = erpc_core::version::VersionInfo::current();
            if cli.json {
                print_json(&serde_json::to_value(&info).unwrap_or_default());
            } else {
                println!("{info}");
            }
            return ExitCode::from(exit::OK);
        }
    };

    match outcome {
        commands::Outcome::Done(message) => {
            if !message.is_empty() {
                println!("{message}");
            }
            ExitCode::from(exit::OK)
        }
        commands::Outcome::Failed(message) => {
            if !message.is_empty() {
                eprintln!("error: {message}");
            }
            ExitCode::from(exit::FAILURE)
        }
        commands::Outcome::NoSession(message) => {
            if !message.is_empty() {
                println!("{message}");
            }
            ExitCode::from(exit::SESSION_EXPIRED)
        }
        commands::Outcome::NeedsTerminal(message) => {
            eprintln!("error: {message}");
            ExitCode::from(exit::NEEDS_TERMINAL)
        }
    }
}

/// Prints a JSON body, or fails loudly if it cannot be rendered.
pub fn print_json(body: &serde_json::Value) {
    match serde_json::to_string_pretty(body) {
        Ok(text) => println!("{text}"),
        Err(e) => eprintln!("could not render JSON: {e}"),
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
