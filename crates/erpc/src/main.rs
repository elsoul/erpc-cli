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
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use erpc_auth::store::{StoreError, StoreKind};

#[macro_use]
mod i18n;
mod account_secret;
mod ai;
mod arc_deploy;
mod arc_init;
mod arc_ops;
mod arc_rpc;
mod avax_ops;
mod avax_tree;
mod backup;
mod backup_schedule;
mod bitcoin_rpc;
mod bitcoin_tree;
mod browser;
mod commands;
mod config;
mod conversations;
mod credit_wallet;
mod doctor;
mod error;
mod eth_deploy;
mod eth_init;
mod eth_ops;
mod eth_rpc;
mod eth_tree;
mod eth_validator;
mod eth_validator_tree;
mod interrupt;
mod keyless;
mod memory;
mod nitro_rpc;
mod nitro_tree;
mod node_common;
mod nodes;
mod prompt;
mod restic;
mod rollup_bundle;
mod rollup_credentials;
mod rollup_ops;
mod rollup_tree;
mod session;
#[cfg(test)]
mod skill_check;
mod skills;
mod solana_rpc;
mod solana_rpc_deploy;
mod solana_rpc_init;
mod solana_rpc_ops;
mod storage;
mod storage_crypt;
mod storage_key;
mod sui_node;
mod sui_tree;
mod tree;
mod tron_node;
mod tron_tree;
mod tui;
mod ui;
mod validator_deploy;
mod validator_init;
mod validator_keys;
mod validator_vote;
mod vps_access;
mod worker;
mod worker_backup;
mod worker_bench;
mod worker_build;
mod worker_deploy;
mod worker_firewall;
mod worker_inventory;
mod worker_keys;
mod worker_remote;
mod worker_run;
mod worker_secrets;
mod worker_vps;

/// Exit statuses outside a failure's own ([`error::Code::exit`]).
mod exit {
    /// The command did what was asked.
    pub const OK: u8 = 0;
    /// erpc itself could not run or write its output.
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

    /// The language erpc speaks: en, ja, zh or ru (default: the `locale`
    /// setting, else the system's).
    #[arg(long, global = true, value_name = "CODE", value_parser = ["en", "ja", "zh", "ru"])]
    lang: Option<String>,

    /// Without a command, erpc opens the AI console.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Which credential store to use, when the operator wants to choose.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum StoreChoice {
    /// 1Password through the desktop application.
    #[value(name = "1password-desktop", alias = "1password", alias = "op")]
    OnePasswordDesktop,
    /// 1Password through a service account token.
    #[value(name = "1password-service-account")]
    OnePasswordServiceAccount,
    /// The operating system keychain.
    Keychain,
    /// A file on disk. Leaves a secret on this machine.
    File,
}

impl From<ConfigAction> for commands::ConfigRequest {
    fn from(action: ConfigAction) -> Self {
        match action {
            ConfigAction::Get { key } => Self::Get(key),
            ConfigAction::Set { key, value } => Self::Set(key, value),
            ConfigAction::Path => Self::Path,
            ConfigAction::Init => Self::Init,
        }
    }
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
        /// Keep the session in this store, without asking. Without it,
        /// erpc asks at a terminal and otherwise uses the keychain.
        #[arg(long, value_enum)]
        store: Option<StoreChoice>,
        /// The 1Password vault id to keep the session in, without asking.
        #[arg(long, value_name = "VAULT_ID")]
        vault: Option<String>,
        /// Print the URL and code instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Sign out and remove the stored session.
    Logout {
        /// Remove the session from this store instead of the one `erpc login` chose.
        #[arg(long, value_enum)]
        store: Option<StoreChoice>,
    },
    /// Report what this machine is doing with your session.
    Doctor {
        /// Report on this store instead of the one `erpc login` chose.
        #[arg(long, value_enum)]
        store: Option<StoreChoice>,
    },
    /// Validator commands (Solana, Ethereum, Avalanche, Sui and TRON).
    #[command(visible_alias = "v", disable_help_flag = true)]
    Validator {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// RPC node commands (Solana, Arc, Ethereum, Avalanche, Sui, Bitcoin, Arbitrum, Robinhood, TRON, Optimism, Base, Soneium; pick one with --chain).
    #[command(visible_alias = "r", disable_help_flag = true)]
    Rpc {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Node commands (Avalanche and Sui RPC compatibility aliases).
    #[command(visible_alias = "n", disable_help_flag = true)]
    Node {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Apps you run on your own server: make one from a template, run it here, deploy it.
    #[command(visible_alias = "w")]
    Worker {
        // Boxed: deploy's flags make it the largest command by far.
        #[command(subcommand)]
        action: Box<worker::Action>,
    },
    /// Talk to the ERPC assistant. Without -m, a conversation.
    Ai {
        /// Ask one question and print the answer.
        #[arg(short = 'm', long)]
        message: Option<String>,
        /// Continue the most recent conversation: in the console, or with
        /// `-m` or a question piped in, which is then saved to it.
        #[arg(short = 'c', long = "continue")]
        continue_last: bool,
    },
    /// Continue a saved conversation. Without an id, pick one from a list.
    Resume {
        /// The conversation's id, as printed when the console closes.
        id: Option<String>,
    },
    /// Open the ERPC dashboard's sign-up page.
    Signup {
        /// Print the URL instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// The assistant's skills: list them, or write them to this machine.
    Skills {
        #[command(subcommand)]
        action: SkillsAction,
    },
    /// What erpc ai remembers about you between conversations.
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
    },
    /// The Base wallet that buys ERPC Credit in EURC, kept in 1Password.
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    /// ERPC Global Storage: usage, files, access keys and the plan.
    #[command(visible_alias = "st")]
    Storage {
        #[command(subcommand)]
        action: storage::Action,
    },
    /// Back this machine up to ERPC Global Storage with restic, encrypted.
    Backup {
        #[command(subcommand)]
        action: backup::Action,
    },
    /// Read and write ~/.erpc/config.toml (public settings only).
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Show who the stored session belongs to.
    Whoami {
        /// Look in this store instead of the one `erpc login` chose.
        #[arg(long, value_enum)]
        store: Option<StoreChoice>,
    },
}

/// Every command and option, one line each, for the assistant's system
/// prompt. Made from the same definition as `--help`, so it cannot list a
/// command this binary does not have.
#[must_use]
pub fn command_reference() -> String {
    use core::fmt::Write as _;
    fn walk(command: &clap::Command, path: &str, out: &mut Vec<String>) {
        for sub in command.get_subcommands() {
            let name = sub.get_name();
            if name == "help" {
                continue;
            }
            let full = format!("{path} {name}");
            let mut usage = full.clone();
            for arg in sub.get_arguments() {
                let id = arg.get_id().as_str();
                if matches!(id, "json" | "help" | "version" | "args") {
                    continue;
                }
                if let Some(long) = arg.get_long() {
                    let takes = arg.get_num_args().is_some_and(|n| n.takes_values());
                    let _ = if takes {
                        write!(usage, " [--{long} <{}>]", id.to_uppercase())
                    } else {
                        write!(usage, " [--{long}]")
                    };
                } else {
                    let _ = write!(usage, " <{}>", id.to_uppercase());
                }
            }
            let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
            out.push(format!("- `{usage}` — {about}"));
            walk(sub, &full, out);
        }
    }
    let mut out = Vec::new();
    walk(&<Cli as clap::CommandFactory>::command(), "erpc", &mut out);
    out.join("\n")
}

/// What `erpc wallet` does.
#[derive(Subcommand)]
enum WalletAction {
    /// Set up your one Base wallet: the ERPC wallet already in 1Password
    /// if there is one, else a new one whose key goes only to 1Password.
    /// Fund it with EURC to buy ERPC Credit.
    Create {
        /// The 1Password vault a new wallet goes in, by id or name (default:
        /// the one `erpc login` keeps the session in).
        #[arg(long)]
        vault: Option<String>,
        /// Do not let erpc ai ask to pay from it. Without this it may ask,
        /// and every payment still waits for your yes.
        #[arg(long)]
        no_ai: bool,
    },
    /// The wallet erpc buys credit from, if one is set up.
    Show,
}

/// What `erpc memory` does.
#[derive(Subcommand)]
enum MemoryAction {
    /// Show every remembered fact, with its number.
    List,
    /// Delete one fact, by its number.
    Forget {
        /// The fact's number, as `erpc memory list` shows it.
        id: u32,
    },
    /// Delete every fact.
    Clear,
}

/// What `erpc skills` does.
#[derive(Subcommand)]
enum SkillsAction {
    /// Name every skill, with what it is about.
    List,
    /// Write the skills to ~/.erpc/skills, and to an agent's skills directory.
    #[command(visible_alias = "sync")]
    Install {
        /// Also write them where this agent reads skills. Repeat for more.
        #[arg(long, value_enum)]
        agent: Vec<skills::Agent>,
    },
}

/// What `erpc config` does.
#[derive(Subcommand)]
enum ConfigAction {
    /// Show one setting, or every setting without a key.
    Get {
        /// The setting to show.
        key: Option<String>,
    },
    /// Change a setting, after checking the value.
    Set {
        /// The setting to change.
        key: String,
        /// Its new value.
        value: String,
    },
    /// Print where the configuration file is.
    Path,
    /// Write a commented starting file, unless there is one.
    Init,
}

/// Every store this build can use, behind one object.
///
/// Shared so that the command bodies are written once rather than once per
/// backend, and `Send + Sync` so that a session read can wait for the
/// store on the blocking pool rather than on the command's task.
///
/// # Errors
///
/// Returns [`StoreError::Unavailable`] when the chosen backend is not
/// usable here: `op` missing for a 1Password store, or no vault chosen
/// for it by `vault`, the configuration or `ERPC_CREDENTIAL_VAULT`.
pub fn store_for(
    kind: StoreKind,
    vault: Option<&str>,
) -> Result<Arc<dyn erpc_auth::CredentialStore + Send + Sync>, StoreError> {
    use erpc_auth::store::one_password::{Mode, OnePassword, OpCli};
    match kind {
        StoreKind::File => {
            let dir = session::state_dir().map_err(|reason| StoreError::Unavailable {
                kind: StoreKind::File,
                reason,
            })?;
            Ok(Arc::new(erpc_auth::store::file::FileStore::new(
                dir.join("credentials.toml"),
            )))
        }
        StoreKind::OsKeychain => Ok(Arc::new(erpc_auth::store::keychain::OsKeychain::new())),
        StoreKind::OnePasswordDesktop | StoreKind::OnePasswordServiceAccount => {
            let mode = if kind == StoreKind::OnePasswordDesktop {
                Mode::Desktop
            } else {
                Mode::ServiceAccount
            };
            let runner = OpCli::from_env(mode, |n| std::env::var_os(n))?;
            // The environment overrides the vault `erpc login` recorded, so
            // CI can point one run elsewhere without editing the file.
            let vault = std::env::var("ERPC_CREDENTIAL_VAULT")
                .ok()
                .filter(|v| !v.is_empty())
                .or_else(|| vault.map(ToOwned::to_owned))
                .ok_or_else(|| StoreError::Unavailable {
                    kind,
                    reason: "no 1Password vault is chosen; run `erpc login` and pick one, pass \
                             --vault, or set ERPC_CREDENTIAL_VAULT"
                        .to_owned(),
                })?;
            Ok(Arc::new(OnePassword::new(
                runner,
                mode,
                vault,
                session::host_label(),
            )))
        }
    }
}

/// Wipes Solana signer files an erpc stopped part way left behind (one
/// killed with SIGKILL, or by a power cut), and says so.
fn sweep_signers() {
    let Ok(state) = session::state_dir() else {
        return;
    };
    for dir in erpc_chain_solana::cli::sweep(&state) {
        interrupt::say(&format!(
            "erpc: wiped signer key files an earlier erpc left behind ({})",
            dir.display()
        ));
    }
}

/// The stack erpc's work runs on. The command line and the commands'
/// futures need about a megabyte in a debug build, which is all Windows
/// gives a program's first thread: `erpc config path` overflowed it there.
/// The work runs on a thread of its own with room to spare instead.
const STACK: usize = 8 * 1024 * 1024;

fn main() -> ExitCode {
    interrupt::install();
    sweep_signers();
    let worker = std::thread::Builder::new()
        .name("erpc".to_owned())
        .stack_size(STACK)
        .spawn(|| run_to_end(run()));
    let code = match worker.map(std::thread::JoinHandle::join) {
        Ok(Ok(Ok(code))) => code,
        // A panic has printed itself already.
        Ok(Err(_)) => ExitCode::from(exit::FAILURE),
        Ok(Ok(Err(e))) | Err(e) => {
            interrupt::say(&format!("error: could not start: {e}"));
            ExitCode::from(exit::FAILURE)
        }
    };
    // Output that did not arrive is a command that did not do what it was
    // asked, whatever it returned.
    if let Some(e) = LOST_OUTPUT.get() {
        interrupt::say(&format!("error: could not write the output: {e}"));
        return ExitCode::from(exit::FAILURE);
    }
    code
}

/// Runs `work` on a single-threaded runtime and returns as soon as it is
/// done, without waiting for what is still on the runtime's blocking pool.
/// A read from 1Password that the operator gave up on -- Ctrl-C on the
/// splash while `op` waits for the app's approval -- can block there for as
/// long as nobody answers, and dropping the runtime would hold the shell's
/// prompt back until it did.
///
/// The one thing waited for is a session rotation under way: its old
/// refresh token is already spent, so leaving before the new one is saved
/// or parked would sign the account out. From then on no rotation starts.
/// Ctrl-C during that wait goes to [`interrupt`], which parks the session
/// rather than wait for a store that does not answer.
fn run_to_end<F: std::future::Future>(work: F) -> std::io::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let output = runtime.block_on(work);
    let leaving = erpc_auth::session::Leaving::start();
    if leaving.rotating() {
        interrupt::say("erpc: saving the refreshed session before leaving");
        runtime.block_on(leaving.settled());
    }
    runtime.shutdown_background();
    Ok(output)
}

async fn run() -> ExitCode {
    let lang = i18n::choose();
    let parsed = i18n::localized(<Cli as clap::CommandFactory>::command(), lang)
        .try_get_matches()
        .and_then(|mut m| <Cli as clap::FromArgMatches>::from_arg_matches_mut(&mut m));
    let cli = match parsed {
        Ok(cli) => cli,
        // clap's own words for a bad command line are good ones; with
        // --json they go in the same object as every other failure.
        Err(e) if json_mode() && e.use_stderr() => {
            let message = e
                .render()
                .to_string()
                .lines()
                .next()
                .unwrap_or_default()
                .trim_start_matches("error: ")
                .to_owned();
            return finish(commands::Outcome::Usage(message));
        }
        Err(e)
            if i18n::wraps_itself(lang)
                && matches!(
                    e.kind(),
                    clap::error::ErrorKind::DisplayHelp
                        | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                ) =>
        {
            i18n::print_help(&e)
        }
        Err(e) => e.exit(),
    };
    let Some(command) = cli.command else {
        let outcome = ai::run(cli.json, None, ai::Start::Fresh).await;
        return finish(outcome);
    };
    // `erpc skills` is how the notice is acted on; it says nothing itself.
    let skills_command = matches!(command, Command::Skills { .. });
    let outcome = match command {
        Command::Login {
            store,
            vault,
            no_browser,
        } => commands::login(cli.json, store.map(Into::into), vault, no_browser).await,
        Command::Logout { store } => commands::logout(cli.json, store.map(Into::into)).await,
        Command::Whoami { store } => commands::whoami(cli.json, store.map(Into::into)).await,
        Command::Doctor { store } => commands::doctor(cli.json, store.map(Into::into)),
        Command::Signup { no_browser } => commands::signup(cli.json, no_browser),
        Command::Ai {
            message,
            continue_last,
        } => {
            let start = if continue_last {
                ai::Start::Latest
            } else {
                ai::Start::Fresh
            };
            ai::run(cli.json, message, start).await
        }
        Command::Resume { id } => ai::run(cli.json, None, ai::Start::Resume(id)).await,
        Command::Validator { args } => {
            tree::run(erpc_core::chain::Role::Validator, &args, cli.json).await
        }
        Command::Rpc { args } => tree::run(erpc_core::chain::Role::Rpc, &args, cli.json).await,
        Command::Node { args } => tree::run(erpc_core::chain::Role::Node, &args, cli.json).await,
        Command::Worker { action } => worker::run(cli.json, *action).await,
        Command::Config { action } => commands::config(cli.json, action.into()),
        Command::Storage { action } => storage::run(cli.json, action).await,
        Command::Backup { action } => backup::run(cli.json, action).await,
        Command::Memory { action } => match action {
            MemoryAction::List => memory::list(cli.json),
            MemoryAction::Forget { id } => memory::forget(cli.json, id),
            MemoryAction::Clear => memory::clear(cli.json),
        },
        Command::Wallet { action } => match action {
            WalletAction::Create { vault, no_ai } => {
                credit_wallet::create_command(cli.json, vault.as_deref(), !no_ai)
            }
            WalletAction::Show => credit_wallet::show_command(cli.json),
        },
        Command::Skills { action } => match action {
            SkillsAction::List => skills::list(cli.json),
            SkillsAction::Install { agent } => skills::install(cli.json, &agent),
        },
        Command::Version => {
            version(cli.json);
            return ExitCode::from(exit::OK);
        }
    };

    let code = finish(outcome);
    // After the command's own output, so it does not read as part of it.
    if !cli.json && !skills_command {
        skills::notice_once();
    }
    code
}

/// `erpc version`, with the digests of the worker agents this erpc
/// carries, which a server's installed agent can be checked against.
fn version(json: bool) {
    use core::fmt::Write as _;
    use sha2::Digest as _;
    let info = erpc_core::version::VersionInfo::current();
    let agents: Vec<(&str, String)> = ["x86_64", "aarch64"]
        .into_iter()
        .filter_map(|m| {
            let bytes = worker_deploy::embedded_agent(m)?;
            let hex =
                sha2::Sha256::digest(bytes)
                    .iter()
                    .fold(String::with_capacity(64), |mut out, b| {
                        let _ = write!(out, "{b:02x}");
                        out
                    });
            Some((m, hex))
        })
        .collect();
    if json {
        let mut body = serde_json::to_value(&info).unwrap_or_default();
        body["worker_agents"] = agents
            .iter()
            .map(|(m, hex)| (format!("{m}-linux"), serde_json::json!(hex)))
            .collect::<serde_json::Map<_, _>>()
            .into();
        print_json(&body);
    } else {
        let mut text = info.to_string();
        for (m, hex) in &agents {
            let _ = write!(text, "\nworker agent {m}-linux sha256 {hex}");
        }
        print_line(&text);
    }
}

/// Prints a JSON body, or fails loudly if it cannot be rendered.
pub fn print_json(body: &serde_json::Value) {
    match serde_json::to_string_pretty(body) {
        Ok(text) => print_line(&text),
        Err(e) => interrupt::say(&format!("could not render JSON: {e}")),
    }
}

/// The first write to stdout that failed, if one did. `main` then fails.
static LOST_OUTPUT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Writes a line to stdout, and notes it in [`LOST_OUTPUT`] if it could not.
///
/// `println!` panics when it cannot write -- a full disk, a closed pipe, a
/// closed terminal -- and a release build aborts on a panic. A session
/// rotation still waiting for the issuer would go with it. [`interrupt::say`]
/// is the same for stderr, where nothing is noted: there is nowhere left to
/// report it.
pub fn print_line(line: &str) {
    use std::io::Write as _;
    if let Err(e) = writeln!(std::io::stdout(), "{line}") {
        let _ = LOST_OUTPUT.set(e.to_string());
    }
}

/// Prints an outcome and turns it into an exit status: the one place a
/// failure is shown, so every command shows it the same way
/// ([`error::CliError`]). With `--json` a failure is a JSON object on
/// standard output; otherwise it is `error:` and `hint:` lines on standard
/// error. An empty message means the command printed its own report.
fn finish(outcome: commands::Outcome) -> ExitCode {
    match outcome {
        commands::Outcome::Done(message) => {
            if !message.is_empty() {
                print_line(&message);
            }
            ExitCode::from(exit::OK)
        }
        commands::Outcome::Problems(report) => {
            if !report.is_empty() {
                print_line(&report);
            }
            ExitCode::from(error::Code::ProblemsFound.exit())
        }
        failure => {
            let Some(failure) = failure.error() else {
                return ExitCode::from(exit::OK);
            };
            if !failure.message.is_empty() {
                if json_mode() {
                    print_json(&failure.json());
                } else if ui::stderr_drawn() {
                    interrupt::say(&failure.drawn());
                } else {
                    interrupt::say(&failure.text());
                }
            }
            ExitCode::from(failure.code.exit())
        }
    }
}

/// Whether output is JSON: `--json` or `ERPC_JSON`, read as clap reads
/// them, for the failures reported before or outside a command.
fn json_mode() -> bool {
    *JSON.get_or_init(|| {
        std::env::args_os().skip(1).any(|a| a == "--json")
            || std::env::var("ERPC_JSON").is_ok_and(|v| {
                matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
            })
    })
}

static JSON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::{Cli, run_to_end};
    use clap::CommandFactory;
    use erpc_auth::session::Refresher;
    use erpc_auth::{
        Audience, CredKey, Credential, CredentialStore, HttpError, StoreError, StoreKind,
        current_session,
    };
    use secrecy::{ExposeSecret as _, SecretString};

    /// Taken by every test that runs [`run_to_end`]. It stops rotations
    /// from starting while it leaves, for the whole process, so one test
    /// leaving would refuse another's rotation.
    static LEAVING: Mutex<()> = Mutex::new(());

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn leaving_does_not_wait_for_work_left_on_the_blocking_pool() {
        let _leaving = LEAVING.lock().expect("not poisoned");
        let started = Instant::now();
        let answer = run_to_end(async {
            // A store read nobody is waiting for any more.
            drop(tokio::task::spawn_blocking(|| {
                std::thread::sleep(Duration::from_secs(5));
            }));
            tokio::task::yield_now().await;
            42
        })
        .expect("a runtime");
        assert_eq!(answer, 42);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "waited {:?}",
            started.elapsed()
        );
    }

    fn session(tag: &str) -> Credential {
        Credential {
            access_token: SecretString::from(format!("acc.{tag}.s")),
            refresh_token: SecretString::from(format!("ref.{tag}.s")),
            expires_at: 1_000,
        }
    }

    /// Rotates any session into `session("NEW")`, a moment after it is
    /// asked.
    #[derive(Clone, Default)]
    struct SlowIssuer {
        asked: Arc<AtomicBool>,
    }

    impl Refresher for SlowIssuer {
        fn refresh(
            &self,
            _audience: Audience,
            _refresh_token: &SecretString,
            _now: i64,
        ) -> impl Future<Output = Result<Credential, HttpError>> + Send {
            self.asked.store(true, Ordering::SeqCst);
            async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok(session("NEW"))
            }
        }
    }

    struct MemoryStore {
        held: Mutex<Credential>,
    }

    impl MemoryStore {
        fn refresh_token(&self) -> String {
            let held = self.held.lock().expect("not poisoned");
            held.refresh_token.expose_secret().to_owned()
        }
    }

    impl CredentialStore for MemoryStore {
        fn load(&self, _key: &CredKey) -> Result<Option<Credential>, StoreError> {
            Ok(Some(self.held.lock().expect("not poisoned").clone()))
        }
        fn save(&self, _key: &CredKey, cred: &Credential) -> Result<(), StoreError> {
            *self.held.lock().expect("not poisoned") = cred.clone();
            Ok(())
        }
        fn delete(&self, _key: &CredKey) -> Result<(), StoreError> {
            Ok(())
        }
        fn kind(&self) -> StoreKind {
            StoreKind::OnePasswordDesktop
        }
    }

    #[test]
    fn leaving_waits_for_a_session_rotation_under_way() {
        // Ctrl-C on the splash while an expiring session is refreshed. The
        // issuer has spent the old refresh token, so leaving before the new
        // one is saved signs the account out.
        let _leaving = LEAVING.lock().expect("not poisoned");
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(MemoryStore {
            held: Mutex::new(session("OLD")),
        });
        let issuer = SlowIssuer::default();
        let key = CredKey::new(crate::session::LOGIN_AUDIENCE, "alice");
        run_to_end(async {
            let mut asking =
                std::pin::pin!(current_session(&issuer, &store, &key, dir.path(), 2_000));
            while !issuer.asked.load(Ordering::SeqCst) {
                tokio::select! {
                    _ = &mut asking => panic!("done before the caller stopped waiting"),
                    () = tokio::time::sleep(Duration::from_millis(5)) => {}
                }
            }
            // The caller gives up here, with the refresh still out.
        })
        .expect("a runtime");
        assert_eq!(store.refresh_token(), "ref.NEW.s");
    }
}
