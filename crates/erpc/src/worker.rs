// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker` (`erpc w`): make an app from a template, run it here, and
//! deploy it to a VPS or bare-metal server, wrangler-style, from the
//! `erpc.toml` at the app's root.
//!
//! Every verb finds the app the same way: `--dir`, or the directory erpc
//! runs in, and the nearest `erpc.toml` at or above it. The manifest is
//! checked whole before anything else happens, so a verb never acts on
//! half of a file it could not read. A verb whose step is not done yet
//! says which step it waits for.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use erpc_worker::index::{self, Index};
use erpc_worker::manifest::{self, Chain, DEFAULT_ENV, LineKind, Manifest, ManifestError};
use erpc_worker::template::{self, Template};
use serde_json::json;

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::worker_secrets::StoreFlag;
use crate::{
    worker_backup, worker_bench, worker_build, worker_deploy, worker_firewall, worker_import,
    worker_keys, worker_remote, worker_run,
};

/// Where the app is: its name, or its directory.
#[derive(Args, Debug, Clone, Default)]
pub(crate) struct Dir {
    /// The app, by the name erpc knows it by (`erpc worker list`)
    /// (default: the app the current directory is in).
    #[arg(id = "app_name", value_name = "APP", conflicts_with = "dir")]
    name: Option<String>,
    /// The app's directory, or a directory inside it; an app's name works
    /// too (default: the current directory).
    #[arg(long, value_name = "DIR")]
    dir: Option<PathBuf>,
}

/// Where the app is, for a command whose own arguments are positional:
/// `--dir` only, which takes an app's name too.
#[derive(Args, Debug, Clone, Default)]
pub(crate) struct DirFlag {
    /// The app's directory, or a directory inside it, or the app's name
    /// (default: the current directory).
    #[arg(long, value_name = "DIR")]
    dir: Option<PathBuf>,
}

impl From<DirFlag> for Dir {
    fn from(flag: DirFlag) -> Self {
        Self {
            name: None,
            dir: flag.dir,
        }
    }
}

impl Dir {
    /// The app at `dir`.
    pub(crate) fn at(dir: &Path) -> Self {
        Self {
            name: None,
            dir: Some(dir.to_path_buf()),
        }
    }

    /// What a hint adds to an app-level `erpc worker` command (check,
    /// key, secret, run, build) so that following it finds this app:
    /// `--dir <dir>` when one was given. An app given by name is named by
    /// the directory the name stands for, never by the name: `--dir <name>`
    /// would mean a directory of that name wherever the hint is followed.
    /// A hint binds it as `dir_scope`.
    pub(crate) fn scope(&self) -> String {
        self.scope_with(by_name, Path::exists)
    }

    /// [`Dir::scope`], with names resolved by `resolve` and paths looked
    /// for with `exists`: a name given as the app, or as a `--dir` that is
    /// not a path here, is named by the directory it stands for, as
    /// [`locate`] finds it.
    fn scope_with(
        &self,
        resolve: impl Fn(&str) -> Result<PathBuf, CliError>,
        exists: impl Fn(&Path) -> bool,
    ) -> String {
        match (&self.name, &self.dir) {
            (Some(name), _) => named_scope(name, resolve(name)),
            (None, Some(dir)) => match dir
                .to_str()
                .filter(|n| !exists(dir) && manifest::is_slug(n, 32))
            {
                Some(name) => named_scope(name, resolve(name)),
                None => dir_scope_of(dir),
            },
            (None, None) => String::new(),
        }
    }
}

/// How a hint names an app erpc knows as `name`: after a verb that takes
/// the app as its argument (`check`, `run`, `deploy`), and after one whose
/// own arguments come first and which takes the app by `--dir` only
/// (`secret put`, `secret rm`, `key import`, `firewall allow`, `api`).
pub(crate) fn name_scopes(name: &str) -> (String, String) {
    let name = shell_word(name);
    (format!(" {name}"), format!(" --dir {name}"))
}

/// The scope of an app given by `name`, which `found` resolved: its
/// directory. Only a name that did not resolve, which the command fails on
/// before it gives any hint, is said as itself.
fn named_scope(name: &str, found: Result<PathBuf, CliError>) -> String {
    found.map_or_else(
        |_| format!(" --dir {}", shell_word(name)),
        |dir| dir_scope_of(&dir),
    )
}

/// ` --dir <dir>`, quoted for the shell; the current directory, which a
/// bare file name's parent is, as `.`.
fn dir_scope_of(dir: &Path) -> String {
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    format!(" --dir {}", shell_word(&dir.to_string_lossy()))
}

/// The scope of the app whose erpc.toml is `manifest`: its directory,
/// wherever the command was run from.
pub(crate) fn manifest_scope(manifest: &Path) -> String {
    manifest.parent().map(dir_scope_of).unwrap_or_default()
}

/// `app`'s environment in `m`, or why there is none, with the deploy that
/// makes one named for this app and environment. (Delete, which must not
/// be pointed at a purchase, reads the environment itself.)
pub(crate) fn env_of<'m>(
    m: &'m Manifest,
    app: &App,
) -> Result<&'m erpc_worker::manifest::Env, CliError> {
    m.env(&app.env).map_err(|e| {
        let error = CliError::new(Code::Failed, e);
        if m.env.is_empty() {
            let scope = app.scope();
            error.hint(t!("worker.env.none", scope))
        } else {
            error
        }
    })
}

/// `word` as a shell reads it back: as it is when it is plain, else in
/// single quotes.
pub(crate) fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:@%".contains(c));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// Where the app is, and which of its environments.
#[derive(Args, Debug, Clone)]
pub(crate) struct App {
    #[command(flatten)]
    pub(crate) dir: Dir,
    /// The environment: an `[env.<name>]` table in erpc.toml.
    #[arg(long, short = 'e', value_name = "NAME", default_value = DEFAULT_ENV)]
    pub(crate) env: String,
}

/// Where the app is and which environment, for a command whose own
/// arguments are positional: `--dir` only.
#[derive(Args, Debug, Clone)]
pub(crate) struct AppFlag {
    #[command(flatten)]
    pub(crate) dir: DirFlag,
    /// The environment: an `[env.<name>]` table in erpc.toml.
    #[arg(long, short = 'e', value_name = "NAME", default_value = DEFAULT_ENV)]
    pub(crate) env: String,
}

impl From<AppFlag> for App {
    fn from(flag: AppFlag) -> Self {
        Self {
            dir: flag.dir.into(),
            env: flag.env,
        }
    }
}

impl App {
    /// What a hint adds to an `erpc worker` command so that following it
    /// acts on this app and environment, never another: ` --env <name>`,
    /// and ` --dir <dir>` when one was given.
    pub(crate) fn scope(&self) -> String {
        format!(" --env {}{}", shell_word(&self.env), self.dir.scope())
    }
}

/// What `erpc worker` does.
#[derive(Subcommand, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "parsed once per run and boxed at the top (Command::Worker); deploy's flags are what make it large"
)]
pub(crate) enum Action {
    /// Make a new app from a template, with its erpc.toml.
    Init {
        /// The chain the app is for.
        #[arg(long, value_parser = parse_chain, default_value = "solana")]
        chain: Chain,
        /// What to make, without asking: helloworld, hft or pumpfun-bot, or a
        /// template id such as pumpfun (default: pick with the arrow keys; in
        /// a script, helloworld).
        #[arg(long, short = 't')]
        template: Option<String>,
        /// The app's name, and its directory's (default: the choice's own,
        /// such as hello-world, with -2, -3… when that directory is taken).
        #[arg(long, short = 'n')]
        name: Option<String>,
        /// Where to make the app's directory (default: the current directory).
        #[arg(long, value_name = "DIR")]
        into: Option<PathBuf>,
        /// Do not make it a git repository.
        #[arg(long)]
        no_git: bool,
        /// Make it without asking anything.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Take an app you already have into erpc worker: write its erpc.toml
    /// from what its directory holds, without changing its code.
    Import {
        /// The app's directory (default: the current directory).
        #[arg(value_name = "DIR")]
        dir: Option<PathBuf>,
        /// The app's name (default: the package's, or the binary's).
        #[arg(long, short = 'n')]
        name: Option<String>,
        /// A Linux binary already built, by any toolchain, to ship as it is:
        /// its path inside the app (default: build the Cargo package there).
        #[arg(long, value_name = "PATH", conflicts_with = "bin")]
        binary: Option<String>,
        /// The binary cargo builds, when the package has several.
        #[arg(long, value_name = "NAME")]
        bin: Option<String>,
        /// The TCP port the app listens on (default: the one its .env files
        /// or its Dockerfile name).
        #[arg(long, value_name = "PORT")]
        port: Option<u16>,
        /// A path that answers 2xx once the app is ready, such as /healthz.
        #[arg(long, value_name = "PATH")]
        health: Option<String>,
        /// The chain the app is for.
        #[arg(long, value_parser = parse_chain, default_value = "solana")]
        chain: Chain,
    },
    /// Check erpc.toml and say what it describes, without changing anything.
    Check {
        #[command(flatten)]
        dir: Dir,
        /// Also require this environment to be there: an `[env.<NAME>]` table in erpc.toml, one server the app is deployed to (`deploy --env <NAME>` makes it).
        #[arg(long, short = 'e', value_name = "NAME")]
        env: Option<String>,
    },
    /// The trading key: kept in 1Password, the keychain or erpc's encrypted keystore, never in a file unencrypted.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Secret settings: kept in 1Password, the keychain or erpc's encrypted keystore, named in erpc.toml.
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Build the app for this machine and run it here, with its key on a pipe.
    Run {
        #[command(flatten)]
        dir: Dir,
        /// Start it, wait until it is healthy, stop it, and say how it went.
        #[arg(long)]
        check: bool,
        /// Give the app a gRPC line that lets in this machine (--ip) as
        /// `GRPC_ENDPOINT`: one of the account's that lets it in already,
        /// else a new hourly one (its price is shown first).
        #[arg(long, requires = "ip")]
        grpc: bool,
        /// The hourly plan of a new gRPC line, by product id (default: the cheapest).
        #[arg(long, value_name = "PRODUCT_ID", requires = "grpc")]
        grpc_plan: Option<String>,
        /// Give the app a Shreds line that lets in this machine (--ip) as
        /// `SHREDS_ENDPOINT`: one of the account's that lets it in already,
        /// else a new hourly one (its price is shown first).
        #[arg(long, requires = "ip")]
        shreds: bool,
        /// The hourly plan of a new Shreds line, by product id (default: the cheapest).
        #[arg(long, value_name = "PRODUCT_ID", requires = "shreds")]
        shreds_plan: Option<String>,
        /// This machine's public IPv4 address, the one the lines let in
        /// (`curl -4 https://api.ipify.org` shows it).
        #[arg(long, value_name = "IPV4")]
        ip: Option<std::net::Ipv4Addr>,
        /// Keep the lines when the run ends, still charged by the hour; the
        /// next run with the same --ip takes them up (default: they are ended).
        #[arg(long)]
        keep_lines: bool,
    },
    /// Build the app for the servers it deploys to, without deploying.
    Build {
        #[command(flatten)]
        dir: Dir,
    },
    /// Deploy the app to an environment's server: build, upload, firewall, start.
    Deploy {
        #[command(flatten)]
        app: App,
        /// A server of your own, by address, when erpc.toml has no server for the environment: Ubuntu or Debian with systemd and nftables, reached as root or a user with passwordless sudo; the worker's firewall then drops every inbound connection to it but SSH and the app's port.
        #[arg(long, value_name = "ADDRESS")]
        host: Option<String>,
        /// The account to log in to on --host.
        #[arg(long, value_name = "USER", requires = "host")]
        user: Option<String>,
        /// The SSH port on --host.
        #[arg(long, value_name = "PORT", requires = "host")]
        port: Option<u16>,
        /// The SSH host key fingerprint --host should offer, instead of being asked.
        #[arg(long, value_name = "SHA256:…", requires = "host")]
        fingerprint: Option<String>,
        /// An ERPC VPS of the account, by its id.
        #[arg(long, value_name = "ID", conflicts_with = "host")]
        vps: Option<i64>,
        /// Start a new hourly ERPC VPS for it (its price is shown first).
        #[arg(long, conflicts_with_all = ["host", "vps"])]
        new_vps: bool,
        /// The region of a new VPS (default: nearest by this machine's time zone).
        #[arg(long, value_name = "REGION")]
        region: Option<String>,
        /// The hourly plan of a new VPS, by product id (default: the cheapest).
        #[arg(long, value_name = "PRODUCT_ID")]
        plan: Option<String>,
        /// Start an hourly gRPC line that lets in the server, and set
        /// `GRPC_ENDPOINT` to it (its price is shown first).
        #[arg(long)]
        grpc: bool,
        /// The hourly plan of the gRPC line, by product id (default: the cheapest).
        #[arg(long, value_name = "PRODUCT_ID", requires = "grpc")]
        grpc_plan: Option<String>,
        /// Start an hourly Shreds line that lets in the server, and set
        /// `SHREDS_ENDPOINT` to it (its price is shown first).
        #[arg(long)]
        shreds: bool,
        /// The hourly plan of the Shreds line, by product id (default: the cheapest).
        #[arg(long, value_name = "PRODUCT_ID", requires = "shreds")]
        shreds_plan: Option<String>,
        /// Start an hourly Unlimited RPC in the server's region, let the
        /// server in, and send transactions through it
        /// (`SOLANA_SEND_RPC_ENDPOINT`; its price is shown first).
        #[arg(long)]
        unlimited: bool,
        /// The hourly plan of the Unlimited RPC, by product id (default: the cheapest).
        #[arg(long, value_name = "PRODUCT_ID", requires = "unlimited")]
        unlimited_plan: Option<String>,
        /// For a new environment: keep its server facts in this 1Password
        /// vault (default: the one `erpc login` keeps the session in, when
        /// that is 1Password).
        #[arg(long, value_name = "VAULT_ID", conflicts_with = "inline")]
        vault: Option<String>,
        /// For a new environment: keep its server facts in erpc.toml.
        #[arg(long)]
        inline: bool,
        /// Take a data line off the record first, by its id: one ended
        /// outside erpc (in the dashboard) that deploy waits for. Repeatable.
        #[arg(long, value_name = "LINE_ID")]
        forget_line: Vec<String>,
        /// Do everything that needs neither the key nor a secret (the
        /// server, its firewall, the lines, the release on the server) and
        /// start nothing; the next deploy hands them over and starts it.
        #[arg(long)]
        prepare: bool,
        /// Go ahead without asking: a new VPS's or line's price is said, not
        /// asked (it is paid from ERPC Credit; ending one is always asked).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Time RPC calls from an environment's server: ERPC's shared RPC, its
    /// Unlimited RPC, and any other, side by side.
    Bench {
        #[command(flatten)]
        app: App,
        /// The JSON-RPC method: getSlot, getBlockHeight, getLatestBlockhash or getHealth.
        #[arg(long, default_value = "getSlot")]
        method: String,
        /// Calls per endpoint, counted after two warm-up calls.
        #[arg(long, default_value_t = 100, value_name = "N")]
        rounds: u32,
        /// A pause between rounds, in milliseconds, for an RPC whose plan
        /// limits calls per second (a shared RPC plan, a free tier).
        #[arg(long, default_value_t = 0, value_name = "MS")]
        interval: u32,
        /// Another endpoint to compare, such as an RPC from another
        /// provider: NAME=URL, NAME=op://…, NAME=keychain:… or NAME=keystore:… (where the URL
        /// is kept, so a key in it stays out of shell history), or NAME=-
        /// to type it unseen. Only its scheme, host and port are shown.
        #[arg(long = "url", value_name = "NAME=URL")]
        urls: Vec<String>,
        /// Leave out ERPC's shared RPC.
        #[arg(long)]
        no_shared: bool,
    },
    /// Show whether the app runs on an environment's server, and which release.
    Status {
        #[command(flatten)]
        app: App,
    },
    /// Show the app's log on an environment's server.
    Logs {
        #[command(flatten)]
        app: App,
        /// Keep showing new lines as they come.
        #[arg(long, short = 'f')]
        follow: bool,
        /// How many recent lines to show.
        #[arg(long, short = 'n', default_value_t = 100)]
        lines: u32,
        /// Show the WAF's log instead: each request it refused, and when it started and stopped.
        #[arg(long)]
        waf: bool,
    },
    /// One request to the app's API on its server, over SSH; the app's
    /// `API_TOKEN`, when it has one, is read here and never shown; prints the
    /// answer.
    Api {
        /// The path, such as /api/trade/status.
        path: String,
        #[command(flatten)]
        app: AppFlag,
        /// GET, POST, PUT or DELETE.
        #[arg(long, short = 'X', default_value = "GET", value_name = "METHOD")]
        method: String,
        /// A JSON body to send.
        #[arg(long, short = 'd', value_name = "JSON")]
        data: Option<String>,
    },
    /// The app's trades on its server: the history, or the profit per trade.
    Trades {
        #[command(flatten)]
        app: App,
        /// The profit per buy→sell pair instead of the history.
        #[arg(long)]
        profit: bool,
    },
    /// Start the app on an environment's server, sending its key if needed.
    Start {
        #[command(flatten)]
        app: App,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Stop the app on an environment's server.
    Stop {
        #[command(flatten)]
        app: App,
        /// Also drop the key from the server's memory; `start` sends it again.
        #[arg(long)]
        lock: bool,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Restart the app on an environment's server.
    Restart {
        #[command(flatten)]
        app: App,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Go back to the previous release, or to the one named.
    Rollback {
        #[command(flatten)]
        app: App,
        /// The release to go back to, as `releases` names it.
        #[arg(long, value_name = "RELEASE")]
        to: Option<String>,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// List the releases an environment's server keeps.
    Releases {
        #[command(flatten)]
        app: App,
    },
    /// Who may reach an environment's server.
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },
    /// Back the app's state up from its server to ERPC Global Storage.
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Remove the app from an environment's server.
    Delete {
        #[command(flatten)]
        app: App,
        /// Also end the hourly ERPC server it runs on.
        #[arg(long)]
        release_server: bool,
        /// Do not reach the server: the worker no longer runs there (the
        /// server is gone, say), and the record goes without it.
        #[arg(long)]
        forget: bool,
        /// Take a data line off the record without ending it, by its id:
        /// one ended outside erpc. Repeatable.
        #[arg(long, value_name = "LINE_ID")]
        forget_line: Vec<String>,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// List the apps on this machine and where each is deployed.
    List {
        /// First take the apps whose erpc.toml is gone off the list. Their
        /// directories and servers are not touched.
        #[arg(long)]
        prune: bool,
    },
}

/// What `erpc worker key` does.
#[derive(Subcommand, Debug)]
pub(crate) enum KeyAction {
    /// Make a new key in memory and keep it only in 1Password, the keychain or erpc's encrypted keystore.
    New {
        #[command(flatten)]
        dir: Dir,
        #[command(flatten)]
        store: StoreArgs,
    },
    /// Move a key file into 1Password, the keychain or erpc's encrypted keystore, then offer to wipe the file.
    Import {
        #[command(flatten)]
        dir: DirFlag,
        /// The key file, as the Solana CLI writes one.
        file: PathBuf,
        #[command(flatten)]
        store: StoreArgs,
        /// Wipe the key file once the key is in the store, without asking.
        #[arg(long)]
        wipe: bool,
    },
    /// Show the key's public key and where it is kept.
    Show {
        #[command(flatten)]
        dir: Dir,
    },
    /// Show the key's balance, through the app's own RPC setting.
    Balance {
        #[command(flatten)]
        dir: Dir,
        /// Ask this RPC instead of the app's.
        #[arg(long, value_name = "URL")]
        rpc: Option<String>,
    },
    /// Send SOL out of the trading wallet to one address, after your yes;
    /// the key is read here and the transfer signed in memory.
    Send {
        #[command(flatten)]
        dir: Dir,
        /// The address to send to.
        #[arg(long, value_name = "PUBKEY")]
        to: String,
        /// How much, in SOL.
        #[arg(long, value_name = "AMOUNT", conflicts_with = "all")]
        sol: Option<f64>,
        /// Everything but the fee.
        #[arg(long)]
        all: bool,
        /// Send through this RPC instead of the app's.
        #[arg(long, value_name = "URL")]
        rpc: Option<String>,
    },
}

/// Where a new key or secret is kept.
#[derive(Args, Debug, Clone, Default)]
pub(crate) struct StoreArgs {
    /// 1Password, the keychain or the keystore (default: 1Password when
    /// `erpc login` keeps the session there, else the keychain, else, where
    /// the keychain forgets at a reboot, the keystore: an encrypted file on
    /// this machine).
    #[arg(long, value_enum)]
    store: Option<StoreFlag>,
    /// The 1Password vault, by id (default: the session's).
    #[arg(long, value_name = "VAULT_ID")]
    vault: Option<String>,
}

/// Where a new secret's value comes from, when it is neither typed nor
/// piped in. One of the two at most: clap refuses both together.
#[derive(Args, Debug, Clone, Copy, Default)]
pub(crate) struct ValueArgs {
    /// Make the value here instead of asking for it: 64 random
    /// hexadecimal characters, for a token of the app's own such as
    /// `API_TOKEN`.
    #[arg(long, conflicts_with = "from_account")]
    generate: bool,
    /// Take the value from the signed-in ERPC account instead of asking
    /// for it: its RPC API key, for `ERPC_API_KEY`.
    #[arg(long)]
    from_account: bool,
}

impl ValueArgs {
    /// The source the flags name: the account, here, or the person.
    const fn value(self) -> worker_keys::Value {
        if self.from_account {
            worker_keys::Value::Account
        } else if self.generate {
            worker_keys::Value::Generated
        } else {
            worker_keys::Value::Typed
        }
    }
}

/// What `erpc worker secret` does.
#[derive(Subcommand, Debug)]
pub(crate) enum SecretAction {
    /// Keep a secret setting and name it in [secrets]: its value piped in, typed unseen, made by erpc (`--generate`) or read from your account (`--from-account`).
    Put {
        #[command(flatten)]
        dir: DirFlag,
        /// The setting's name, such as `X_TOKEN`.
        name: String,
        #[command(flatten)]
        store: StoreArgs,
        /// Keep a new value for a name that is set already.
        #[arg(long)]
        replace: bool,
        #[command(flatten)]
        value: ValueArgs,
    },
    /// List the secret settings by name and where each is kept.
    List {
        #[command(flatten)]
        dir: Dir,
    },
    /// Remove a secret setting from erpc.toml; its value stays in 1Password or the keychain, and is deleted from the keystore.
    Rm {
        #[command(flatten)]
        dir: DirFlag,
        /// The setting's name.
        name: String,
    },
    /// Unlock this machine's keystore: type its passphrase once, and the commands after it do not ask (Linux: kept in the kernel keyring until it is locked, the machine restarts or the keyring's idle expiry).
    Unlock,
    /// Lock this machine's keystore: drop the unlock, so the next command that needs it asks for the passphrase.
    Lock,
}

/// Which firewall list an address goes in.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Port {
    /// SSH.
    Ssh,
    /// The app's own port, or its WAF's when it is behind one.
    App,
}

/// What `erpc worker backup` does.
#[derive(Subcommand, Debug)]
pub(crate) enum BackupAction {
    /// Back the app's state up every day, encrypted, with an append-only
    /// key on the server.
    On {
        #[command(flatten)]
        app: App,
        /// The time of day, `HH:MM`, 24-hour, in the server's time.
        #[arg(long, default_value = "03:00")]
        at: String,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Stop backing up, and remove the server's backup keys. The snapshots
    /// stay.
    Off {
        #[command(flatten)]
        app: App,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Whether the app is backed up, when next, and how the last run went.
    Status {
        #[command(flatten)]
        app: App,
    },
    /// Back the app up now, and wait for it.
    Now {
        #[command(flatten)]
        app: App,
    },
}

/// What `erpc worker firewall` does.
#[derive(Subcommand, Debug)]
pub(crate) enum FirewallAction {
    /// Show who may reach the server, as erpc.toml says and as the server has it.
    List {
        #[command(flatten)]
        app: App,
    },
    /// Let an address or network in, and apply it.
    Allow {
        #[command(flatten)]
        app: AppFlag,
        /// Which port it may reach.
        #[arg(long, value_enum, default_value = "ssh")]
        to: Port,
        /// The addresses, such as 198.51.100.7; a network such as 198.51.100.0/24 only with --to app, since SSH is allowed from single addresses; everyone (`0.0.0.0/0`, `::/0`) only with --to app of an app behind a WAF.
        #[arg(required = true)]
        addresses: Vec<String>,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Stop letting an address or network in, and apply it.
    Deny {
        #[command(flatten)]
        app: AppFlag,
        /// Which port it may no longer reach.
        #[arg(long, value_enum, default_value = "ssh")]
        to: Port,
        /// The addresses or networks.
        #[arg(required = true)]
        addresses: Vec<String>,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Make the server's firewall what erpc.toml says.
    Sync {
        #[command(flatten)]
        app: App,
        /// Go ahead without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

fn parse_chain(name: &str) -> Result<Chain, String> {
    Chain::parse(name).ok_or_else(|| {
        let known: Vec<&str> = Chain::ALL.iter().map(|c| c.as_str()).collect();
        t!("worker.chain.unknown", chains = known.join(", "))
    })
}

/// Runs one `erpc worker` verb.
#[allow(clippy::too_many_lines, reason = "one arm per verb, each a call")]
pub(crate) async fn run(json: bool, action: Action) -> Outcome {
    match action {
        Action::Init {
            chain,
            template,
            name,
            into,
            no_git,
            yes,
        } => init(
            json,
            &InitRequest {
                chain,
                template: template.as_deref(),
                name: name.as_deref(),
                into: into.as_deref(),
                git: !no_git,
                ask: !yes && !json && crate::session::has_terminal(),
            },
        ),
        Action::Import {
            dir,
            name,
            binary,
            bin,
            port,
            health,
            chain,
        } => worker_import::import(
            json,
            &worker_import::Request {
                dir: dir.as_deref(),
                name: name.as_deref(),
                binary: binary.as_deref(),
                bin: bin.as_deref(),
                port,
                health: health.as_deref(),
                chain,
            },
        ),
        Action::Check { dir, env } => check(json, &dir, env.as_deref()),
        Action::Key { action } => match action {
            KeyAction::New { dir, store } => {
                worker_keys::new(json, &dir, store.store, store.vault.as_deref())
            }
            KeyAction::Import {
                dir,
                file,
                store,
                wipe,
            } => worker_keys::import(
                json,
                &dir.into(),
                &file,
                store.store,
                store.vault.as_deref(),
                wipe,
            ),
            KeyAction::Show { dir } => worker_keys::show(json, &dir),
            KeyAction::Balance { dir, rpc } => {
                worker_keys::balance(json, &dir, rpc.as_deref()).await
            }
            KeyAction::Send {
                dir,
                to,
                sol,
                all,
                rpc,
            } => worker_keys::send(json, &dir, &to, sol, all, rpc.as_deref()).await,
        },
        Action::Secret { action } => match action {
            SecretAction::Put {
                dir,
                name,
                store,
                replace,
                value,
            } => {
                worker_keys::put(
                    json,
                    &dir.into(),
                    &name,
                    store.store,
                    store.vault.as_deref(),
                    replace,
                    value.value(),
                )
                .await
            }
            SecretAction::List { dir } => worker_keys::list(json, &dir),
            SecretAction::Rm { dir, name } => worker_keys::remove(json, &dir.into(), &name),
            SecretAction::Unlock => crate::worker_keystore::unlock_command(json),
            SecretAction::Lock => crate::worker_keystore::lock_command(json),
        },
        Action::Run {
            dir,
            check,
            grpc,
            grpc_plan,
            shreds,
            shreds_plan,
            ip,
            keep_lines,
        } => {
            let kinds = [
                (LineKind::Grpc, grpc, grpc_plan),
                (LineKind::Shreds, shreds, shreds_plan),
            ]
            .into_iter()
            .filter_map(|(kind, asked, plan)| asked.then_some((kind, plan)))
            .collect();
            let lines = worker_run::Lines {
                kinds,
                ip,
                keep: keep_lines,
            };
            worker_run::run(json, &dir, check, &lines).await
        }
        Action::Build { dir } => worker_build::build(json, &dir),
        Action::Deploy {
            app,
            host,
            user,
            port,
            fingerprint,
            vps,
            new_vps,
            region,
            plan,
            grpc,
            grpc_plan,
            shreds,
            shreds_plan,
            unlimited,
            unlimited_plan,
            vault,
            inline,
            forget_line,
            prepare,
            yes,
        } => {
            let at = worker_deploy::Where {
                host,
                user,
                port,
                fingerprint,
                vps,
                new_vps,
                region,
                plan,
                lines: [
                    (LineKind::Grpc, grpc, grpc_plan),
                    (LineKind::Shreds, shreds, shreds_plan),
                    (LineKind::Unlimited, unlimited, unlimited_plan),
                ]
                .into_iter()
                .filter(|(_, asked, _)| *asked)
                .map(|(kind, _, plan)| (kind, plan))
                .collect(),
                vault,
                inline,
                forget_lines: forget_line,
                starts: worker_deploy::Starts::from_yes(yes),
                upto: worker_deploy::Upto::from_prepare(prepare),
            };
            worker_deploy::deploy(json, &app, &at, yes).await
        }
        Action::Bench {
            app,
            method,
            rounds,
            interval,
            urls,
            no_shared,
        } => {
            let asked = worker_bench::Asked {
                method,
                rounds,
                interval_ms: interval,
                urls,
                shared: !no_shared,
            };
            worker_bench::bench(json, &app, &asked).await
        }
        Action::Status { app } => worker_remote::status(json, &app).await,
        Action::Logs {
            app,
            follow,
            lines,
            waf,
        } => worker_remote::logs(&app, lines, follow, waf),
        Action::Api {
            path,
            app,
            method,
            data,
        } => worker_remote::api(&app.into(), &method, &path, data.as_deref()),
        Action::Trades { app, profit } => worker_remote::api(
            &app,
            "GET",
            if profit {
                "/api/trades/profit"
            } else {
                "/api/trades/history"
            },
            None,
        ),
        Action::Start { app, yes } => worker_remote::start(json, &app, yes, false),
        Action::Stop { app, lock, yes } => worker_remote::stop(json, &app, lock, yes),
        Action::Restart { app, yes } => worker_remote::start(json, &app, yes, true),
        Action::Rollback { app, to, yes } => {
            worker_remote::rollback(json, &app, to.as_deref(), yes)
        }
        Action::Releases { app } => worker_remote::releases(json, &app),
        Action::Delete {
            app,
            release_server,
            forget,
            forget_line,
            yes,
        } => {
            let ask = worker_remote::DeleteAsk {
                release_server,
                forget,
                forget_lines: forget_line,
                yes,
            };
            worker_remote::delete(json, &app, &ask).await
        }
        Action::Firewall { action } => match action {
            FirewallAction::List { app } => worker_firewall::list(json, &app),
            FirewallAction::Allow {
                app,
                to,
                addresses,
                yes,
            } => worker_firewall::change(json, &app.into(), to, &addresses, true, yes),
            FirewallAction::Deny {
                app,
                to,
                addresses,
                yes,
            } => worker_firewall::change(json, &app.into(), to, &addresses, false, yes),
            FirewallAction::Sync { app, yes } => worker_firewall::sync_verb(json, &app, yes),
        },
        Action::Backup { action } => match action {
            BackupAction::On { app, at, yes } => worker_backup::on(json, &app, &at, yes).await,
            BackupAction::Off { app, yes } => worker_backup::off(json, &app, yes).await,
            BackupAction::Status { app } => worker_backup::status(json, &app),
            BackupAction::Now { app } => worker_backup::now(json, &app),
        },
        Action::List { prune } => list(json, prune),
    }
}

/// The `erpc.toml` that governs `dir`, and what it says.
pub(crate) fn load(dir: &Dir) -> Result<(PathBuf, Manifest), CliError> {
    let path = locate(dir)?;
    let manifest = Manifest::load(&path).map_err(|e| manifest_error(&path, &e))?;
    Ok((path, manifest))
}

/// [`load`], with environment `app.env`'s server facts read from its
/// 1Password item when the environment keeps them there (decision 9): one
/// `op` read, then the rest of the command works as for an inline one. An
/// inventory environment with no item yet has no server: a deploy gives it
/// one.
pub(crate) fn load_env(app: &App) -> Result<(PathBuf, Manifest), CliError> {
    let (path, mut m) = load(&app.dir)?;
    if let Some(env) = m.env.get(&app.env).cloned()
        && let Some(inventory) = &env.inventory
    {
        let facts = crate::worker_inventory::read(&inventory.vault, &m.name, &app.env)
            .map_err(|e| CliError::new(Code::Failed, e))?;
        if let Some(facts) = facts {
            m.env
                .insert(app.env.clone(), erpc_worker::inventory::merged(&env, facts));
        }
    }
    Ok((path, m))
}

/// Where environment `env` of app `app` is written: the `erpc.toml` at
/// `path`, and for an inventory environment its 1Password item.
pub(crate) struct EnvRecord<'a> {
    pub(crate) path: &'a Path,
    pub(crate) app: &'a str,
    pub(crate) env: &'a str,
}

impl EnvRecord<'_> {
    /// Saves `env`. An inventory environment's facts go to its item, and
    /// erpc.toml keeps only where they are; an inline one's go to
    /// erpc.toml. `deployed` is put on the item only.
    pub(crate) fn save(
        &self,
        env: &manifest::Env,
        deployed: Option<&erpc_worker::inventory::Deployed>,
    ) -> Result<(), String> {
        let in_file = if let Some(inventory) = &env.inventory {
            crate::worker_inventory::write(&inventory.vault, self.app, self.env, env, deployed)?;
            erpc_worker::inventory::stripped(env)
        } else {
            env.clone()
        };
        std::fs::read_to_string(self.path)
            .map_err(|e| e.to_string())
            .and_then(|text| erpc_worker::edit::set_env(&text, self.env, &in_file))
            .and_then(|text| erpc_worker::edit::save(self.path, &text))
    }

    /// Removes the environment: from erpc.toml, and its item, archived (it
    /// stays recoverable in 1Password).
    pub(crate) fn forget(&self, env: &manifest::Env) -> Result<(), String> {
        if let Some(inventory) = &env.inventory {
            crate::worker_inventory::archive(&inventory.vault, self.app, self.env)?;
        }
        std::fs::read_to_string(self.path)
            .map_err(|e| e.to_string())
            .and_then(|text| erpc_worker::edit::remove_env(&text, self.env))
            .and_then(|(text, _)| erpc_worker::edit::save(self.path, &text))
    }
}

fn locate(dir: &Dir) -> Result<PathBuf, CliError> {
    if let Some(name) = &dir.name {
        return by_name(name).map(|d| d.join(manifest::FILE_NAME));
    }
    // A --dir that is not there and reads as an app's name is that app; a
    // directory that is there wins.
    if let Some(path) = &dir.dir
        && !path.exists()
        && let Some(name) = path.to_str().filter(|n| manifest::is_slug(n, 32))
    {
        return by_name(name).map(|d| d.join(manifest::FILE_NAME));
    }
    let start = match &dir.dir {
        Some(path) if path.file_name().is_some_and(|n| n == manifest::FILE_NAME) => {
            return if path.is_file() {
                Ok(path.clone())
            } else {
                Err(CliError::new(
                    Code::Failed,
                    t!("worker.find.no_file", path = path.display()),
                ))
            };
        }
        Some(path) => path.clone(),
        None => std::env::current_dir()
            .map_err(|e| CliError::new(Code::Failed, t!("worker.find.no_cwd", error = e)))?,
    };
    manifest::locate(&start).ok_or_else(|| {
        CliError::new(
            Code::Failed,
            t!(
                "worker.find.no_manifest",
                file = manifest::FILE_NAME,
                dir = start.display()
            ),
        )
        .hint(if dir.dir.is_some() {
            t!("worker.find.no_app_here")
        } else {
            t!("worker.find.init_or_dir")
        })
    })
}

/// The directory of the app erpc knows as `name`, from the list `erpc
/// worker list` reads.
pub(crate) fn by_name(name: &str) -> Result<PathBuf, CliError> {
    let index =
        index_path().and_then(|p| Index::load(&p).map_err(|e| CliError::new(Code::Failed, e)))?;
    named(&index, name)
}

/// The directory `index` has for the app named `name`.
///
/// The name is the one in each app's erpc.toml, as `erpc worker list`
/// shows it, not the one the list was written with: an app renamed in its
/// erpc.toml is found by its new name only.
pub(crate) fn named(index: &Index, name: &str) -> Result<PathBuf, CliError> {
    let dirs: Vec<&PathBuf> = index
        .workers
        .iter()
        .filter(|e| manifest_name(&e.dir).as_deref() == Some(name))
        .map(|e| &e.dir)
        .collect();
    match dirs.as_slice() {
        [dir] => Ok((*dir).clone()),
        [] => Err(unread(index, name).unwrap_or_else(|| {
            CliError::new(Code::Failed, t!("worker.find.unknown", name))
                .hint(t!("worker.find.unknown_hint"))
                .mark("🔎")
        })),
        many => Err(CliError::new(
            Code::Failed,
            t!(
                "worker.find.ambiguous",
                name,
                dirs = many
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .hint(t!("worker.find.ambiguous_hint"))),
    }
}

/// Why no app is named `name` when `index` has one that was added under
/// that name and whose erpc.toml no longer says a name: a file that does
/// not parse, or one that is gone. erpc knows the app; it cannot read it.
fn unread(index: &Index, name: &str) -> Option<CliError> {
    let entry = index
        .workers
        .iter()
        .find(|e| e.name == name && manifest_name(&e.dir).is_none())?;
    let path = entry.dir.join(manifest::FILE_NAME);
    let dir_scope = manifest_scope(&path);
    Some(
        CliError::new(
            Code::Failed,
            t!("worker.find.unreadable", name, path = path.display()),
        )
        .hint(t!(
            "worker.manifest.fix",
            file = manifest::FILE_NAME,
            dir_scope
        )),
    )
}

/// The `name` in the erpc.toml in `dir`, when it can be read.
fn manifest_name(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join(manifest::FILE_NAME)).ok()?;
    let table: toml::Table = text.parse().ok()?;
    table.get("name")?.as_str().map(ToOwned::to_owned)
}

fn manifest_error(path: &Path, error: &ManifestError) -> CliError {
    let message = match error {
        ManifestError::Read(_) => error.to_string(),
        ManifestError::Syntax(_) | ManifestError::Invalid(_) => {
            format!("{}: {error}", path.display())
        }
    };
    let dir_scope = manifest_scope(path);
    CliError::new(Code::Failed, message).hint(t!(
        "worker.manifest.fix",
        file = manifest::FILE_NAME,
        dir_scope
    ))
}

/// `erpc worker check`: what erpc.toml describes, or every problem with it.
fn check(json: bool, dir: &Dir, env: Option<&str>) -> Outcome {
    let path = match locate(dir) {
        Ok(path) => path,
        Err(e) => return e.into(),
    };
    let manifest = match Manifest::load(&path) {
        Ok(manifest) => manifest,
        Err(ManifestError::Invalid(problems)) => {
            return problems_found(json, &path, &problems);
        }
        Err(e) => return manifest_error(&path, &e).into(),
    };
    if let Some(env) = env
        && let Err(message) = manifest.env(env)
    {
        return problems_found(json, &path, &[message]);
    }
    let mut warnings = manifest.warnings();
    // A credential written under [vars] is in the file that is committed
    // and reaches the server as text: said, and the app still deploys.
    let dir_scope = manifest_scope(&path);
    for (name, kind) in manifest.credentials_in_vars() {
        let what = credential_said(kind);
        warnings.push(t!("worker.check.var_credential", name, what, dir_scope));
    }
    // What a deploy from this machine would lack, said now rather than
    // after a server is bought.
    let root = path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_owned);
    // Looked for, not run: `check` runs nothing in the app's directory.
    let probe = crate::worker_build::Probe::Look;
    for (what, hint) in crate::worker_build::missing_tools(&manifest, &root, probe) {
        let what = if hint.is_empty() {
            what
        } else {
            format!("{what}; {hint}")
        };
        warnings.push(t!("worker.check.deploy_needs", what));
    }
    if let Err(no_key) = crate::vps_access::login_key() {
        warnings.push(t!("worker.check.deploy_needs", what = no_key));
    }
    warnings.extend(keystore_warnings(&manifest));
    if json {
        crate::print_json(&json!({
            "path": path,
            "valid": true,
            "manifest": manifest,
            "warnings": warnings,
        }));
        return Outcome::Done(String::new());
    }
    Outcome::Done(
        describe_drawn(&path, &manifest, &warnings, &manifest_scope(&path))
            .or_plain(describe(&path, &manifest, &warnings)),
    )
}

/// A warning for each `keystore:` reference this machine's keystore has no
/// entry for: the value was kept on another machine, and nothing here can
/// start the app with it. Looked for, not read: no passphrase is asked.
fn keystore_warnings(m: &Manifest) -> Vec<String> {
    m.secrets
        .iter()
        .map(|(name, r)| (format!("secrets.{name}"), r))
        .chain(
            m.wallet
                .iter()
                .map(|w| ("wallet.source".to_owned(), &w.source)),
        )
        .filter_map(|(at, reference)| {
            let manifest::SecretRef::Keystore { service, account } = reference else {
                return None;
            };
            match crate::worker_keystore::has(service, account) {
                Ok(true) => None,
                Ok(false) => Some(t!("worker.check.keystore_missing", at, reference)),
                Err(error) => Some(t!("worker.check.keystore_unread", at, reference, error)),
            }
        })
        .collect()
}

/// What kind of credential a `[vars]` value carries, in the words of the
/// run.
fn credential_said(kind: manifest::Credential) -> String {
    use manifest::Credential;
    match kind {
        Credential::UrlUserinfo => t!("worker.check.credential.url_userinfo"),
        Credential::PrivateKey => t!("worker.check.credential.private_key"),
        Credential::Authorization => t!("worker.check.credential.authorization"),
        Credential::Jwt => t!("worker.check.credential.jwt"),
        Credential::Token => t!("worker.check.credential.token"),
        Credential::Parameter => t!("worker.check.credential.parameter"),
        Credential::WalletKey => t!("worker.check.credential.wallet_key"),
        Credential::Phrase => t!("worker.check.credential.phrase"),
        Credential::UrlPath => t!("worker.check.credential.url_path"),
    }
}

fn problems_found(json: bool, path: &Path, problems: &[String]) -> Outcome {
    if json {
        crate::print_json(&json!({
            "path": path,
            "valid": false,
            "problems": problems,
        }));
        return Outcome::Problems(String::new());
    }
    let head = tn!(
        "worker.check.problems",
        problems.len(),
        path = path.display()
    );
    let mut report = head.clone();
    for problem in problems {
        report.push_str("\n  - ");
        report.push_str(problem);
    }
    let drawn = problems
        .iter()
        .fold(crate::ui::Report::new().marked("🩺", head), |r, p| {
            r.detail(format!("• {p}"))
        });
    Outcome::Problems(drawn.or_plain(report))
}

/// The services a deploy puts on the server, with what each gives the app;
/// none when `[services]` names none.
fn services_named(m: &Manifest) -> Option<String> {
    let names: Vec<String> = m
        .services
        .vars()
        .iter()
        .map(|(var, _)| {
            let service = if *var == "REDIS_URL" {
                "redis"
            } else {
                "postgres"
            };
            format!("{service} ({var})")
        })
        .collect();
    (!names.is_empty()).then(|| names.join(", "))
}

/// What `check` shows at a terminal: the app, then its settings aligned.
fn describe_drawn(
    path: &Path,
    m: &Manifest,
    warnings: &[String],
    dir_scope: &str,
) -> crate::ui::Report {
    let scope = format!(" --env {DEFAULT_ENV}{dir_scope}");
    let mut fields: Vec<(String, String)> = vec![("chain".into(), m.chain.to_string())];
    if let Some(template) = &m.template {
        fields.push(("template".into(), template.clone()));
    }
    fields.push((
        "build".into(),
        match &m.build.prebuilt {
            Some(prebuilt) => t!("worker.check.prebuilt_drawn", prebuilt, bin = m.bin()),
            None => format!("{}  → {}", m.build.command.join(" "), m.bin()),
        },
    ));
    if !m.vars.is_empty() {
        fields.push((
            "vars".into(),
            m.vars
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if let Some(services) = services_named(m) {
        fields.push(("services".into(), services));
    }
    if let Some([listens, limits]) = crate::worker_waf::described(m) {
        fields.push(("waf".into(), listens));
        fields.push((String::new(), limits));
    }
    for (name, reference) in &m.secrets {
        fields.push(("secret".into(), format!("{name} ← {reference}")));
    }
    if let Some(wallet) = &m.wallet {
        fields.push((
            "wallet".into(),
            wallet
                .pubkey
                .as_deref()
                .map_or_else(|| t!("worker.check.no_pubkey"), ToOwned::to_owned),
        ));
    }
    for (name, env) in &m.env {
        let place = if env.inventory.is_some() {
            t!("worker.check.in_1password")
        } else {
            env.host
                .clone()
                .unwrap_or_else(|| t!("worker.check.no_server"))
        };
        fields.push(("env".into(), format!("{name}: {place}")));
    }
    // "Ready" only when nothing is left to set.
    let head = crate::ui::Report::new();
    let head = if warnings.is_empty() {
        head.done(t!("worker.check.ready", name = m.name))
    } else {
        head.marked("📦", m.name.clone())
    };
    let mut report = head.detail(crate::ui::tidy(path)).fields(fields);
    for warning in warnings {
        report = report.warning(warning.clone());
    }
    let mut next = Vec::new();
    if lacks_its_key(m) {
        next.push(format!("erpc worker key new{dir_scope}"));
    }
    if m.env.is_empty() {
        next.push(format!("erpc worker deploy{scope}"));
    }
    report.next(next)
}

/// Whether the app trades with a key and has none yet: one made from a
/// template that does. An app that needs no key (the hello app, one made by
/// hand) is not told to make one.
pub(crate) fn lacks_its_key(m: &Manifest) -> bool {
    m.wallet.is_none()
        && m.template
            .as_deref()
            .and_then(template::of_tag)
            .is_some_and(|made_from| made_from.wallet)
}

/// The flag `erpc worker secret put` takes for `setting` of app `m`, with
/// its leading space, when the value need not be typed: what the template
/// the app was made from says of the setting ([`Template::secret_flag`]),
/// which is the choice `init`'s next steps make. Empty for a secret the
/// operator has to give, and for an app made by hand or from a template
/// this erpc does not carry.
pub(crate) fn secret_flag(m: &Manifest, setting: &str) -> &'static str {
    m.template
        .as_deref()
        .and_then(template::of_tag)
        .map_or("", |made_from| made_from.secret_flag(setting))
}

/// How the app's binary comes to be, as `check` says it: the command that
/// builds it, or the prebuilt binary shipped as it is.
fn built_as(m: &Manifest) -> String {
    match &m.build.prebuilt {
        Some(prebuilt) => t!(
            "worker.check.prebuilt",
            prebuilt,
            bin = m.bin(),
            target = m.build.target.triple()
        ),
        None => t!(
            "worker.check.build",
            command = m.build.command.join(" "),
            bin = m.bin(),
            target = m.build.target.triple()
        ),
    }
}

/// The human-readable summary `check` prints.
fn describe(path: &Path, m: &Manifest, warnings: &[String]) -> String {
    let dir_scope = manifest_scope(path);
    let scope = format!(" --env {DEFAULT_ENV}{dir_scope}");
    let mut lines = vec![
        format!("{}  ({})", m.name, path.display()),
        format!("  chain     {}", m.chain),
    ];
    if let Some(template) = &m.template {
        lines.push(format!("  template  {template}"));
    }
    lines.push(format!("  build     {}", built_as(m)));
    if !m.vars.is_empty() {
        let names: Vec<&str> = m.vars.keys().map(String::as_str).collect();
        lines.push(format!("  vars      {}", names.join(", ")));
    }
    if let Some(services) = services_named(m) {
        lines.push(format!("  services  {services}"));
    }
    if let Some([listens, limits]) = crate::worker_waf::described(m) {
        lines.push(format!("  waf       {listens}"));
        lines.push(format!("            {limits}"));
    }
    for (name, reference) in &m.secrets {
        lines.push(format!("  secret    {name} ← {reference}"));
    }
    match &m.wallet {
        Some(wallet) => lines.push(format!(
            "  wallet    {} ← {}",
            wallet
                .pubkey
                .clone()
                .unwrap_or_else(|| t!("worker.check.no_pubkey")),
            wallet.source
        )),
        None if lacks_its_key(m) => lines.push(format!(
            "  wallet    {}",
            t!("worker.check.no_wallet", dir_scope)
        )),
        None => {}
    }
    if m.env.is_empty() {
        lines.push(format!("  env       {}", t!("worker.check.no_env", scope)));
    }
    for (name, env) in &m.env {
        if let Some(inventory) = &env.inventory {
            lines.push(format!(
                "  env       {}",
                t!(
                    "worker.check.env_in_1password",
                    name,
                    vault = inventory.vault,
                    service = m.unit_id(name)
                )
            ));
            continue;
        }
        let host = env
            .host
            .clone()
            .unwrap_or_else(|| t!("worker.check.no_server"));
        let resource = env.resource.as_ref().map_or_else(String::new, |r| {
            format!(
                "  [{}{}{}]",
                serde_json::to_value(r.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(ToOwned::to_owned))
                    .unwrap_or_default(),
                r.region
                    .as_ref()
                    .map_or_else(String::new, |g| format!(" {g}")),
                if r.hourly {
                    t!("worker.check.hourly")
                } else {
                    String::new()
                }
            )
        });
        lines.push(format!(
            "  env       {}",
            t!(
                "worker.check.env",
                name,
                host,
                resource,
                service = m.unit_id(name)
            )
        ));
    }
    for warning in warnings {
        lines.push(format!("warning: {warning}"));
    }
    lines.join("\n")
}

/// What `erpc worker init` was asked for.
struct InitRequest<'a> {
    chain: Chain,
    template: Option<&'a str>,
    name: Option<&'a str>,
    into: Option<&'a Path>,
    git: bool,
    /// Whether a person is there to pick.
    ask: bool,
}

/// `erpc worker init`: a new app directory from a template, its erpc.toml
/// included, entered in this machine's index.
fn init(json: bool, req: &InitRequest<'_>) -> Outcome {
    // A person at a terminal sees the exchange drawn: a heading, the picker,
    // a spinner while the app is made, and the next steps in a box. A
    // script (--yes, --json, no terminal) gets plain lines or JSON.
    // Drawn only when the result goes to a terminal too: `init > log` keeps
    // the plain lines on stdout.
    let drawn = req.ask && crate::ui::stdout_drawn();
    if drawn {
        crate::prompt::intro("erpc worker init");
    }
    let (template, name, dest) = match choose(req).and_then(|(template, default_name)| {
        let (name, dest) = app_name(req, default_name)?;
        Ok((template, name, dest))
    }) {
        Ok(chosen) => chosen,
        Err(e) => {
            if drawn {
                crate::prompt::outro_cancel(&t!("worker.init.nothing_made"));
            }
            return e.into();
        }
    };
    let spinner = drawn.then(|| {
        crate::prompt::Spinner::start(&t!("worker.init.making", name, template = template.tag()))
    });
    let files = match template.write(&name, &dest) {
        Ok(files) => files,
        Err(e) => {
            if let Some(spinner) = spinner {
                spinner.error(&e);
                crate::prompt::outro_cancel(&t!("worker.init.nothing_made"));
            }
            return CliError::new(Code::Failed, e)
                .hint(t!("worker.init.pick_another"))
                .into();
        }
    };
    let dest = std::fs::canonicalize(&dest).unwrap_or(dest);
    let git = if req.git {
        repository(&dest)
    } else {
        Repository::Skipped("--no-git")
    };
    // The app is made; an index that cannot be written only costs `list`.
    let indexed = index_path()
        .and_then(|p| {
            index::update(&p, |i| Ok(((), i.remember(&name, &dest)?)))
                .map_err(|e| CliError::new(Code::Failed, e))
        })
        .err();
    // Each step names the new app, wherever it is run from: by its name
    // when erpc knows it, else by its directory.
    let by_its_name = indexed.is_none() && by_name(&name).is_ok_and(|d| d == dest);
    let (dir_scope, flag_scope) = if by_its_name {
        name_scopes(&name)
    } else {
        let by_dir = dir_scope_of(&dest);
        (by_dir.clone(), by_dir)
    };
    let next = next_steps(&dest, &dir_scope, &flag_scope, &template);
    if json {
        crate::print_json(&json!({
            "name": name,
            "dir": dest,
            "template": template.tag(),
            "files": files,
            "repository": git.json(),
            "indexed": indexed.is_none(),
            "next": next,
        }));
        return Outcome::Done(String::new());
    }
    // An app that trades is warned about its funds; one with nothing to set
    // up is told so, since that is the news.
    let closing = if template.wallet {
        Closing::Funds(t!("worker.init.funds", dir_scope))
    } else {
        Closing::Ready(t!("worker.init.ready"))
    };
    if let Some(spinner) = spinner {
        spinner.stop(&tn!(
            "worker.init.made",
            files.len(),
            name,
            template = template.tag()
        ));
        crate::prompt::info(&t!("worker.init.at", dir = near(&dest).display()));
        draw_made(&git, indexed.as_ref(), &next, &closing);
        return Outcome::Done(String::new());
    }
    let made = tn!(
        "worker.init.made_in",
        files.len(),
        name,
        template = template.tag(),
        dir = dest.display()
    );
    let mut lines = vec![made, git.text()];
    if let Some(e) = indexed {
        lines.push(format!(
            "warning: {}",
            t!("worker.init.unlisted", error = e.message)
        ));
    }
    lines.push(String::new());
    lines.push("Next:".to_owned());
    lines.extend(next.iter().map(|step| format!("  {step}")));
    lines.push(String::new());
    lines.push(closing.text().to_owned());
    Outcome::Done(lines.join("\n"))
}

/// The last word `init` has on the app it made.
enum Closing {
    /// It trades: what that means for the funds in its wallet.
    Funds(String),
    /// It needs nothing set up first.
    Ready(String),
}

impl Closing {
    fn text(&self) -> &str {
        match self {
            Self::Funds(text) | Self::Ready(text) => text,
        }
    }
}

/// `dir` as short as it can be said from here: relative when it is under
/// the current directory.
fn near(dir: &Path) -> PathBuf {
    std::env::current_dir()
        .ok()
        .and_then(|cwd| dir.strip_prefix(&cwd).ok().map(Path::to_path_buf))
        .filter(|rel| !rel.as_os_str().is_empty())
        .unwrap_or_else(|| dir.to_path_buf())
}

/// What to do next, from what the new app's erpc.toml says it lacks: the
/// key when its template trades with one, a `secret put` for each setting
/// nothing provides (with the flag that gives its value, when nobody has
/// to type it), the check, a run with the flag of each line whose setting
/// it needs, then the deploy with the same flags. The same order as
/// `docs/worker.md` and the erpc-worker skill give.
///
/// `dir_scope` names the app after a verb that takes it as its argument,
/// and `flag_scope` after `secret put`, whose own argument comes first and
/// which takes the app by `--dir` only.
fn next_steps(dest: &Path, dir_scope: &str, flag_scope: &str, made_from: &Template) -> Vec<String> {
    let trades = made_from.wallet;
    let manifest = std::fs::read_to_string(dest.join(manifest::FILE_NAME))
        .ok()
        .and_then(|text| Manifest::parse(&text).ok());
    let mut next = vec![format!("cd {}", shell_word(&near(dest).to_string_lossy()))];
    if trades && manifest.as_ref().is_none_or(|m| m.wallet.is_none()) {
        next.push(format!("erpc worker key new{dir_scope}"));
    }
    let mut run_flags = String::new();
    for req in manifest.iter().flat_map(Manifest::missing) {
        match LineKind::ALL
            .into_iter()
            .find(|k| k.setting() == req.first())
        {
            Some(LineKind::Unlimited) => {}
            Some(kind) => {
                run_flags.push_str(" --");
                run_flags.push_str(kind.flag());
            }
            None => {
                let dir_scope = flag_scope;
                let (setting, how) = (req.first(), made_from.secret_flag(req.first()));
                next.push(format!("erpc worker secret put {setting}{how}{dir_scope}"));
            }
        }
    }
    next.push(format!("erpc worker check{dir_scope}"));
    if run_flags.is_empty() {
        next.push(format!("erpc worker run{dir_scope}"));
    } else {
        next.push(format!("erpc worker run{dir_scope}{run_flags} --ip <IPV4>"));
    }
    // With no server named, deploy lists the account's and offers a new
    // hourly one, its price asked first. A new app has no environment but
    // the default one, which a deploy without `--env` means: its scope is
    // the app's.
    let scope = dir_scope;
    next.push(format!("erpc worker deploy{scope}{run_flags}"));
    next
}

/// The rest of `init`'s exchange at a terminal, once the spinner stopped:
/// the repository, a list that could not be updated, the next steps in a
/// box, and the warning about funds.
fn draw_made(git: &Repository, indexed: Option<&CliError>, next: &[String], closing: &Closing) {
    match git {
        Repository::Failed(why) => {
            crate::prompt::warning(&t!("worker.init.git.failed_drawn", why));
        }
        _ => crate::prompt::info(&git.text()),
    }
    if let Some(e) = indexed {
        crate::prompt::warning(&t!("worker.init.unlisted", error = e.message));
    }
    crate::prompt::note("Next", &next.join("\n"));
    match closing {
        Closing::Funds(text) => crate::prompt::warning(text),
        Closing::Ready(text) => crate::prompt::info(text),
    }
    crate::prompt::outro(&t!("worker.init.done"));
}

/// The app's name and directory: `--name`'s, or the choice's own. For a
/// person picking, -2, -3… when a directory of that name is there already;
/// nothing else is asked, the picker is the one question. With nobody to
/// ask, the name is the choice's own, and one that is taken fails as it
/// did, so that a script running init again does not make another app.
fn app_name(req: &InitRequest<'_>, default_name: &str) -> Result<(String, PathBuf), CliError> {
    let parent = parent_dir(req)?;
    let name = match req.name {
        Some(name) => name.to_owned(),
        None if req.ask => free_name(default_name, |n| parent.join(n).exists()),
        None => default_name.to_owned(),
    };
    if manifest::is_slug(&name, 32) {
        let dest = parent.join(&name);
        Ok((name, dest))
    } else {
        Err(CliError::new(Code::Usage, t!("worker.init.bad_name", name)))
    }
}

/// `base`, or `base-2`, `base-3`… up to `base-99`: the first that `taken`
/// does not report. When all are, `base`, which then fails as taken.
fn free_name(base: &str, taken: impl Fn(&str) -> bool) -> String {
    std::iter::once(base.to_owned())
        .chain((2..100).map(|n| format!("{base}-{n}")))
        .find(|n| !taken(n))
        .unwrap_or_else(|| base.to_owned())
}

/// Where the app's directory goes: `--into`, or the current directory.
fn parent_dir(req: &InitRequest<'_>) -> Result<PathBuf, CliError> {
    let parent = match req.into {
        Some(dir) => dir.to_owned(),
        None => std::env::current_dir()
            .map_err(|e| CliError::new(Code::Failed, t!("worker.find.no_cwd", error = e)))?,
    };
    Ok(parent)
}

/// The template to make the app from, and the name it is given: what
/// `--template` names (a choice, such as hft, or a template id), the one
/// picked with the arrow keys, or, with nobody to ask, the first template:
/// the one to start from, which needs nothing set up.
fn choose(req: &InitRequest<'_>) -> Result<(Template, &'static str), CliError> {
    if let Some(asked) = req.template {
        if let Some(kind) = template::find_kind(req.chain, asked) {
            let made = kind.template().map_err(|e| CliError::new(Code::Usage, e))?;
            return Ok((made, kind.default_name));
        }
        let made = template::find(req.chain, asked).map_err(|_| {
            let kinds: Vec<&str> = template::kinds_for(req.chain)
                .iter()
                .filter(|k| k.template.is_some())
                .map(|k| k.label)
                .collect();
            let ids: Vec<&str> = template::for_chain(req.chain)
                .iter()
                .map(|t| t.id)
                .collect();
            let or = format!(" {} ", t!("worker.init.or"));
            CliError::new(
                Code::Usage,
                t!(
                    "worker.init.nothing_called",
                    chain = req.chain,
                    asked,
                    kinds = kinds.join(&or),
                    ids = ids.join(&or)
                ),
            )
        })?;
        return Ok((made, made.default_name));
    }
    let kinds = template::kinds_for(req.chain);
    if req.ask && !kinds.is_empty() {
        return pick_kind(&kinds);
    }
    template::for_chain(req.chain)
        .first()
        .map(|first| (*first, first.default_name))
        .ok_or_else(|| {
            CliError::new(
                Code::Failed,
                t!("worker.init.no_templates", chain = req.chain),
            )
        })
}

/// What to make, picked with the arrow keys. One that is coming soon says
/// so, and the list comes back with the cursor where it was.
fn pick_kind(kinds: &[template::Kind]) -> Result<(Template, &'static str), CliError> {
    let options: Vec<(&str, &str)> = kinds.iter().map(|k| (k.label, k.about)).collect();
    let mut at = 0;
    loop {
        at = crate::prompt::pick_described(&t!("worker.init.what"), &options, Some(at))
            .map_err(|e| CliError::new(Code::Failed, e))?;
        match kinds[at].template() {
            Ok(made) => return Ok((made, kinds[at].default_name)),
            Err(soon) => crate::prompt::info(&soon),
        }
    }
}

/// What `init` did about a repository for the app.
enum Repository {
    Made,
    Skipped(&'static str),
    Failed(String),
}

impl Repository {
    fn json(&self) -> serde_json::Value {
        match self {
            Self::Made => json!("initialized"),
            Self::Skipped(why) => json!({ "skipped": why }),
            Self::Failed(why) => json!({ "failed": why }),
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Made => t!("worker.init.git.made"),
            Self::Skipped(why) => t!("worker.init.git.skipped", why = skipped(why)),
            Self::Failed(why) => format!("warning: {}", t!("worker.init.git.failed", why)),
        }
    }
}

/// Why no repository was made, as a person reads it; `--no-git` as it is.
/// (The JSON keeps the English the variant holds.)
fn skipped(why: &str) -> String {
    match why {
        "git is not installed" => t!("worker.init.git.not_installed"),
        "it is inside a git repository already" => t!("worker.init.git.inside"),
        other => other.to_owned(),
    }
}

/// Makes `dir` a git repository, unless git is missing or `dir` is already
/// inside one (an app in a monorepo belongs to that repository).
fn repository(dir: &Path) -> Repository {
    let vcs = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
    };
    match vcs(&["rev-parse", "--is-inside-work-tree"]) {
        Err(_) => return Repository::Skipped("git is not installed"),
        Ok(out) if out.status.success() => {
            return Repository::Skipped("it is inside a git repository already");
        }
        Ok(_) => {}
    }
    match vcs(&["init", "-q"]) {
        Ok(out) if out.status.success() => Repository::Made,
        Ok(out) => Repository::Failed(String::from_utf8_lossy(&out.stderr).trim().to_owned()),
        Err(e) => Repository::Failed(e.to_string()),
    }
}

/// Where the index of apps on this machine is.
fn index_path() -> Result<PathBuf, CliError> {
    crate::session::beside_config(index::FILE_NAME).map_err(|e| CliError::new(Code::Failed, e))
}

/// `erpc worker list`: every app this machine knows, as its erpc.toml says.
fn list(json: bool, prune: bool) -> Outcome {
    let pruned = match prune.then(prune_gone).transpose() {
        Ok(n) => n,
        Err(e) => return e.into(),
    };
    let index = match index_path()
        .and_then(|p| Index::load(&p).map_err(|e| CliError::new(Code::Failed, e)))
    {
        Ok(index) => index,
        Err(e) => return e.into(),
    };
    let rows: Vec<serde_json::Value> = index
        .workers
        .iter()
        .map(|entry| {
            let path = entry.dir.join(manifest::FILE_NAME);
            match Manifest::load(&path) {
                Ok(m) => json!({
                    "name": m.name,
                    "dir": entry.dir,
                    "chain": m.chain,
                    "state": "ok",
                    "envs": m.env.iter().map(|(name, env)| json!({
                        "name": name,
                        "host": env.host,
                        "inventory_vault": env.inventory.as_ref().map(|i| &i.vault),
                        "service": m.unit_id(name),
                    })).collect::<Vec<_>>(),
                }),
                Err(ManifestError::Read(_)) => json!({
                    "name": entry.name,
                    "dir": entry.dir,
                    "state": "missing",
                }),
                Err(_) => json!({
                    "name": entry.name,
                    "dir": entry.dir,
                    "state": "invalid",
                }),
            }
        })
        .collect();
    // The worker items in the login vault that no app here names: workers
    // deployed from another machine, which a clone of their app takes up.
    let (vault_rows, vault_note) = elsewhere(&rows);
    if json {
        crate::print_json(&json!({
            "workers": rows,
            "in_vault": vault_rows,
            "vault_note": vault_note,
            "pruned": pruned,
        }));
        return Outcome::Done(String::new());
    }
    let mut drawn = list_drawn(&rows, &vault_rows, vault_note.as_ref());
    let pruned_line = pruned
        .filter(|n| *n > 0)
        .map(|count| t!("worker.list.pruned", count));
    if let Some(line) = &pruned_line {
        drawn = drawn.done(line.clone());
    }
    let any_gone = rows.iter().any(|r| r["state"] == "missing");
    if any_gone {
        drawn = drawn.hint(t!("worker.list.prune_hint"));
    }
    if rows.is_empty() && vault_rows.is_empty() {
        let mut text = t!("worker.list.none");
        if let Some(note) = vault_note {
            text.push('\n');
            text.push_str(&note);
        }
        return Outcome::Done(drawn.or_plain(text));
    }
    let mut lines = list_plain(&rows);
    vault_lines(&vault_rows, vault_note, &mut lines);
    if let Some(line) = pruned_line {
        lines.push(line);
    }
    if any_gone {
        lines.push(format!("hint: {}", t!("worker.list.prune_hint")));
    }
    Outcome::Done(drawn.or_plain(lines.join("\n")))
}

/// The plain lines `list` prints for the apps here.
fn list_plain(rows: &[serde_json::Value]) -> Vec<String> {
    let mut lines = Vec::new();
    for row in rows {
        let name = row["name"].as_str().unwrap_or_default();
        let dir = row["dir"].as_str().unwrap_or_default();
        match row["state"].as_str() {
            Some("ok") => {
                let envs: Vec<String> = row["envs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|e| {
                        format!(
                            "{}={}",
                            e["name"].as_str().unwrap_or_default(),
                            e["host"]
                                .as_str()
                                .unwrap_or(if e["inventory_vault"].is_string() {
                                    "1password"
                                } else {
                                    "-"
                                })
                        )
                    })
                    .collect();
                let envs = if envs.is_empty() {
                    t!("worker.list.not_deployed")
                } else {
                    envs.join(" ")
                };
                lines.push(format!("{name}  {dir}  {envs}"));
            }
            Some("missing") => lines.push(format!("{name}  {dir}  {}", t!("worker.list.gone"))),
            _ => {
                let dir_scope = dir_scope_of(Path::new(dir));
                lines.push(format!(
                    "{name}  {dir}  {}",
                    t!("worker.list.invalid", dir_scope)
                ));
            }
        }
    }
    lines
}

/// Takes the apps whose erpc.toml is gone off the list; how many.
fn prune_gone() -> Result<usize, CliError> {
    let path = index_path()?;
    erpc_worker::index::update(&path, |i| {
        let gone = gone_apps(i);
        for dir in &gone {
            i.forget(dir);
        }
        Ok((gone.len(), !gone.is_empty()))
    })
    .map_err(|e| CliError::new(Code::Failed, e))
}

/// The directories on the list with no erpc.toml in them any more: an app
/// moved or deleted. One that cannot be read for another reason (its
/// erpc.toml has problems) stays.
fn gone_apps(index: &Index) -> Vec<PathBuf> {
    index
        .workers
        .iter()
        .filter(|e| !e.dir.join(manifest::FILE_NAME).exists())
        .map(|e| e.dir.clone())
        .collect()
}

/// What `list` shows at a terminal: each app, marked, its directory under it.
fn list_drawn(
    rows: &[serde_json::Value],
    vault_rows: &[serde_json::Value],
    vault_note: Option<&String>,
) -> crate::ui::Report {
    let mut drawn = crate::ui::Report::new();
    if rows.is_empty() && vault_rows.is_empty() {
        drawn = drawn
            .info(t!("worker.list.none_drawn"))
            .next(["erpc worker init"]);
    }
    for row in rows {
        let name = row["name"].as_str().unwrap_or_default();
        let dir = row["dir"].as_str().unwrap_or_default();
        drawn = match row["state"].as_str() {
            Some("ok") => {
                let envs: Vec<String> = row["envs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|e| e["name"].as_str().unwrap_or_default().to_owned())
                    .collect();
                let state = if envs.is_empty() {
                    t!("worker.list.not_deployed")
                } else {
                    t!("worker.list.deployed", envs = envs.join(", "))
                };
                drawn
                    .marked("📦", format!("{name}  ·  {state}"))
                    .detail(crate::ui::tidy(Path::new(dir)))
            }
            Some("missing") => drawn.warning(t!("worker.list.gone_drawn", name, dir)),
            _ => drawn.warning(t!("worker.list.invalid_drawn", name)).hint({
                let dir_scope = dir_scope_of(Path::new(dir));
                format!("`erpc worker check{dir_scope}`")
            }),
        };
    }
    for row in vault_rows {
        drawn = drawn.marked(
            "🔐",
            t!(
                "worker.list.in_vault",
                name = row["name"].as_str().unwrap_or_default(),
                env = row["env"].as_str().unwrap_or_default()
            ),
        );
    }
    if let Some(note) = vault_note {
        drawn = drawn.info(note.clone());
    }
    drawn
}

/// The lines `list` adds for the worker items found only in 1Password.
fn vault_lines(
    vault_rows: &[serde_json::Value],
    vault_note: Option<String>,
    lines: &mut Vec<String>,
) {
    if !vault_rows.is_empty() {
        lines.push(String::new());
        lines.push(t!("worker.list.in_vault_heading"));
        for row in vault_rows {
            lines.push(format!(
                "{}  env {}  vault {}",
                row["name"].as_str().unwrap_or_default(),
                row["env"].as_str().unwrap_or_default(),
                row["vault"].as_str().unwrap_or_default()
            ));
        }
    }
    if let Some(note) = vault_note {
        lines.push(note);
    }
}

/// The worker items in the vault `erpc login` keeps the session in, less
/// the environments `rows` (the apps on this machine) already show, and a
/// note when the vault could not be read. Nothing when the session is not
/// in 1Password.
fn elsewhere(rows: &[serde_json::Value]) -> (Vec<serde_json::Value>, Option<String>) {
    let Ok(crate::worker_secrets::Store::OnePassword { vault }) =
        crate::worker_secrets::choose(None, None)
    else {
        return (Vec::new(), None);
    };
    let known: std::collections::BTreeSet<(String, String)> = rows
        .iter()
        .flat_map(|row| {
            let name = row["name"].as_str().unwrap_or_default().to_owned();
            row["envs"].as_array().into_iter().flatten().map(move |e| {
                (
                    name.clone(),
                    e["name"].as_str().unwrap_or_default().to_owned(),
                )
            })
        })
        .collect();
    match crate::worker_inventory::list(&vault) {
        Ok(items) => (
            items
                .into_iter()
                .filter(|item| !known.contains(item))
                .map(|(name, env)| json!({ "name": name, "env": env, "vault": vault }))
                .collect(),
            None,
        ),
        Err(e) => (
            Vec::new(),
            Some(t!("worker.list.vault_unread", vault, error = e)),
        ),
    }
}

#[cfg(test)]
mod tests {

    use super::{App, Dir, check, locate};
    use crate::commands::Outcome;

    #[test]
    fn a_hint_names_an_app_given_by_name_by_its_directory() {
        // From inside another app with a directory called `bot`, `--dir
        // bot` would be that directory: a hint names where `bot` is, both
        // for the APP argument and for a --dir that named it.
        let resolve = |name: &str| -> Result<std::path::PathBuf, super::CliError> {
            assert_eq!(name, "bot");
            Ok("/srv/apps/bot".into())
        };
        let by_app = Dir {
            name: Some("bot".into()),
            dir: None,
        };
        let nowhere = |_: &std::path::Path| false;
        assert_eq!(by_app.scope_with(resolve, nowhere), " --dir /srv/apps/bot");
        // `--dir bot` where there is no path `bot`: the app named bot.
        let by_flag = Dir {
            name: None,
            dir: Some("bot".into()),
        };
        assert_eq!(by_flag.scope_with(resolve, nowhere), " --dir /srv/apps/bot");
        // Where there is a path `bot`, that is the app, and no name is
        // looked up.
        assert_eq!(
            by_flag.scope_with(
                |_| panic!("a path there is not looked up"),
                |p| p == std::path::Path::new("bot")
            ),
            " --dir bot"
        );
    }

    #[test]
    fn an_app_is_found_by_the_name_in_its_erpc_toml_once_and_only_once() {
        use erpc_worker::index::{Entry, Index};
        let root = std::env::temp_dir().join(format!("erpc-w-named-{}", std::process::id()));
        let (a, b) = (root.join("a/hft-bot"), root.join("b/other"));
        for (dir, name) in [(&a, "hft-bot"), (&b, "other")] {
            std::fs::create_dir_all(dir).expect("dir");
            std::fs::write(dir.join("erpc.toml"), format!("name = \"{name}\"\n")).expect("toml");
        }
        let entry = |name: &str, dir: &std::path::Path| Entry {
            name: name.into(),
            dir: dir.into(),
        };
        let one = Index {
            workers: vec![entry("hft-bot", &a), entry("other", &b)],
        };
        assert_eq!(super::named(&one, "hft-bot").expect("found"), a);
        assert_eq!(super::named(&one, "other").expect("found"), b);
        // Renamed in its erpc.toml after the list was written: found by the
        // new name only, as `list` shows it.
        let renamed = Index {
            workers: vec![entry("old-name", &a)],
        };
        assert!(super::named(&renamed, "old-name").is_err());
        assert_eq!(super::named(&renamed, "hft-bot").expect("found"), a);
        // Unknown, two of one name, or an app no longer there: an error,
        // never a guess.
        assert!(super::named(&one, "nothing").is_err());
        // An app erpc knows whose erpc.toml no longer parses is not an
        // unknown app: the error names the file and how to see what is
        // wrong with it.
        std::fs::write(a.join("erpc.toml"), "name = \"hft-bot\"\n[run\n").expect("broken");
        let broken = super::named(&one, "hft-bot").expect_err("unreadable");
        assert!(
            broken.message.contains("cannot be read") && broken.message.contains("erpc.toml"),
            "{}",
            broken.message
        );
        assert!(
            broken
                .hint
                .as_deref()
                .is_some_and(|h| h.contains("erpc worker check")),
            "{:?}",
            broken.hint
        );
        assert!(
            !broken.message.contains("knows no app"),
            "{}",
            broken.message
        );
        std::fs::write(a.join("erpc.toml"), "name = \"hft-bot\"\n").expect("restored");
        let two = Index {
            workers: vec![
                entry("hft-bot", &a),
                entry("hft-bot", &a.join("..").join("..").join("a/hft-bot")),
                entry("x", &b),
            ],
        };
        let e = super::named(&two, "hft-bot").expect_err("two");
        assert!(e.message.contains("more than one"), "{}", e.message);
        std::fs::remove_file(a.join("erpc.toml")).expect("rm");
        assert!(super::named(&one, "hft-bot").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every `erpc worker …` a hint names, in the worker's sources outside
    /// comments and tests, with Rust's line continuations joined.
    fn named_sources() -> Vec<(&'static str, &'static str)> {
        vec![
            ("worker.rs", include_str!("worker.rs")),
            ("worker_backup.rs", include_str!("worker_backup.rs")),
            ("worker_bench.rs", include_str!("worker_bench.rs")),
            ("worker_build.rs", include_str!("worker_build.rs")),
            ("worker_charges.rs", include_str!("worker_charges.rs")),
            ("worker_deploy.rs", include_str!("worker_deploy.rs")),
            ("worker_firewall.rs", include_str!("worker_firewall.rs")),
            ("worker_import.rs", include_str!("worker_import.rs")),
            ("worker_inventory.rs", include_str!("worker_inventory.rs")),
            ("worker_keys.rs", include_str!("worker_keys.rs")),
            ("worker_keystore.rs", include_str!("worker_keystore.rs")),
            ("worker_remote.rs", include_str!("worker_remote.rs")),
            ("worker_run.rs", include_str!("worker_run.rs")),
            ("worker_secrets.rs", include_str!("worker_secrets.rs")),
            ("worker_vps.rs", include_str!("worker_vps.rs")),
            ("worker_waf.rs", include_str!("worker_waf.rs")),
            ("node_common.rs", include_str!("node_common.rs")),
            (
                "erpc-worker/manifest.rs",
                include_str!("../../erpc-worker/src/manifest.rs"),
            ),
            (
                "erpc-worker/edit.rs",
                include_str!("../../erpc-worker/src/edit.rs"),
            ),
            (
                "erpc-worker/inventory.rs",
                include_str!("../../erpc-worker/src/inventory.rs"),
            ),
            (
                "erpc-worker/release.rs",
                include_str!("../../erpc-worker/src/release.rs"),
            ),
            (
                "erpc-worker/template.rs",
                include_str!("../../erpc-worker/src/template.rs"),
            ),
            (
                "erpc-worker/bench.rs",
                include_str!("../../erpc-worker/src/bench.rs"),
            ),
            (
                "erpc-worker/index.rs",
                include_str!("../../erpc-worker/src/index.rs"),
            ),
        ]
    }

    /// The English catalogs of the worker's words, where a hint's command
    /// is once its words are translated: its scope a placeholder named as
    /// the source binds it (`{scope}`, `{dir_scope}`).
    fn named_catalogs() -> Vec<(String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("locales/en");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("locales/en").flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let toml = entry.path().extension().is_some_and(|e| e == "toml");
            if name.starts_with("worker") && toml {
                let text = std::fs::read_to_string(entry.path()).expect("catalog");
                out.push((format!("en/{name}"), text));
            }
        }
        out
    }

    fn named_commands() -> Vec<(String, char, String)> {
        let mut found = Vec::new();
        let sources = named_sources()
            .into_iter()
            .map(|(file, source)| (file.to_owned(), source.to_owned(), "//"));
        let catalogs = named_catalogs()
            .into_iter()
            .map(|(file, text)| (file, text, "#"));
        for (file, source, comment) in sources.chain(catalogs) {
            let code = source
                .split("\n#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or(&source);
            let mut joined = String::new();
            let mut continued = false;
            for line in code.lines() {
                // A continued string goes on after the next line's indent.
                let line = if continued { line.trim_start() } else { line };
                if line.trim_start().starts_with(comment) {
                    continued = false;
                    joined.push('\n');
                    continue;
                }
                if let Some(head) = line.strip_suffix('\\') {
                    joined.push_str(head);
                    continued = true;
                } else {
                    joined.push_str(line);
                    joined.push('\n');
                    continued = false;
                }
            }
            // In backticks, in prose; or a string of its own (a next step).
            for quote in ['`', '"'] {
                let mut rest = joined.as_str();
                let start = format!("{quote}erpc worker ");
                while let Some(at) = rest.find(&start) {
                    let after = &rest[at + 1..];
                    let end = after.find(quote).unwrap_or(after.len());
                    found.push((file.clone(), quote, after[..end].to_owned()));
                    rest = &after[end..];
                }
            }
        }
        found
    }

    /// The `erpc worker` verbs that act on one environment, the ones that
    /// act on an app as a whole, and the ones about no one app.
    const ENV_VERBS: [&str; 14] = [
        "deploy", "delete", "logs", "rollback", "firewall", "status", "start", "stop", "restart",
        "releases", "bench", "backup", "api", "trades",
    ];
    const DIR_VERBS: [&str; 5] = ["check", "key", "secret", "run", "build"];
    const NO_APP_VERBS: [&str; 3] = ["init", "import", "list"];
    /// The verbs under `secret` that act on this machine's keystore, not
    /// on an app: they take no `--dir`.
    const MACHINE_VERBS: [&str; 2] = ["secret unlock", "secret lock"];

    #[test]
    fn every_command_a_hint_names_is_scoped_to_its_app() {
        // Followed as printed, a hint acts on the app and environment it
        // was printed for, never on [env.default] or the app in the
        // current directory. An environment's command carries App::scope()
        // (bound as `scope`), an app's carries Dir::scope() (`dir_scope`),
        // and one about no app carries neither.
        let commands = named_commands();
        assert!(
            commands.len() > 30,
            "the scan finds the hints: {commands:?}"
        );
        let wrong: Vec<_> = commands
            .iter()
            .filter(|(_, quote, c)| {
                let verb = c
                    .trim_start_matches("erpc worker ")
                    .split([' ', '{'])
                    .next()
                    .unwrap_or_default();
                let (env, dir) = (c.contains("{scope}"), c.contains("{dir_scope}"));
                let of_the_machine = MACHINE_VERBS
                    .iter()
                    .any(|m| c.trim_start_matches("erpc worker ") == *m);
                if of_the_machine {
                    env || dir
                } else if ENV_VERBS.contains(&verb) {
                    !env || dir
                } else if DIR_VERBS.contains(&verb) {
                    env || !dir
                } else if NO_APP_VERBS.contains(&verb) {
                    env || dir
                } else {
                    // In backticks, a verb this test does not know: say
                    // which kind it is. A string of its own that starts
                    // with no verb is a title or prose (`erpc worker {app}
                    // {env}`), not a command.
                    *quote == '`'
                }
            })
            .collect();
        assert!(wrong.is_empty(), "hints with the wrong scope: {wrong:#?}");
    }

    #[test]
    fn check_warns_of_what_this_machines_keystore_does_not_hold() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _kept = set_up(&desk);
        crate::worker_keystore::write(
            "erpc-worker",
            "bot.API_TOKEN",
            erpc_auth::store::keystore::Kind::Secret,
            "tok-1",
            true,
        )
        .expect("kept");
        desk.lock();
        desk.terminal.set(false);
        let m = erpc_worker::manifest::Manifest::parse(
            "name = \"bot\"\nchain = \"solana\"\n[secrets]\n\
             API_TOKEN = \"keystore:erpc-worker/bot.API_TOKEN\"\n\
             X_TOKEN = \"keystore:erpc-worker/bot.X_TOKEN\"\n\
             Y_TOKEN = \"keychain:erpc-worker/bot.Y_TOKEN\"\n\
             [wallet]\nsource = \"keystore:erpc-worker/bot.wallet\"\n",
        )
        .expect("manifest");
        // What is here is not warned about; what is not is named, the key
        // too. Looked for, never read: locked, with nobody to ask.
        let warnings = super::keystore_warnings(&m);
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(
            warnings[0].starts_with(
                "secrets.X_TOKEN is keystore:erpc-worker/bot.X_TOKEN, which this machine's \
                 keystore does not hold"
            ),
            "{warnings:#?}"
        );
        assert!(
            warnings[1].starts_with("wallet.source is keystore:erpc-worker/bot.wallet"),
            "{warnings:#?}"
        );
        assert_eq!(desk.asked(), 2);
    }

    #[test]
    fn every_worker_source_is_scanned() {
        let scanned: Vec<&str> = named_sources().iter().map(|(name, _)| *name).collect();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for entry in std::fs::read_dir(&src).expect("src") {
            let name = entry.expect("entry").file_name();
            let name = name.to_string_lossy();
            if name.starts_with("worker") && name.ends_with(".rs") {
                assert!(
                    scanned.contains(&name.as_ref()),
                    "{name} is not scanned for hints"
                );
            }
        }
        let lib = src.join("../../erpc-worker/src");
        for entry in std::fs::read_dir(&lib).expect("erpc-worker/src") {
            let name = entry.expect("entry").file_name();
            let name = format!("erpc-worker/{}", name.to_string_lossy());
            let skipped = [
                "erpc-worker/lib.rs",
                "erpc-worker/net.rs",
                "erpc-worker/server.rs",
                "erpc-worker/waf.rs",
            ];
            assert!(
                scanned.contains(&name.as_str()) || skipped.contains(&name.as_str()),
                "{name} is not scanned for hints"
            );
        }
    }

    #[test]
    fn each_scope_parses_for_the_verbs_it_is_for() {
        // The scopes as hints render them, through erpc's own parser: an
        // environment's command takes App::scope(), an app's Dir::scope()
        // (and not --env), init neither.
        let parses = |line: &str| {
            let words = line.split_whitespace();
            <crate::Cli as clap::Parser>::try_parse_from(words).is_ok()
        };
        let app = App {
            dir: Dir {
                name: None,
                dir: Some("apps/bot".into()),
            },
            env: "staging".to_owned(),
        };
        let here = super::manifest_scope(std::path::Path::new("erpc.toml"));
        assert_eq!(here, " --dir .");
        let up = super::manifest_scope(std::path::Path::new("../erpc.toml"));
        for verb in [
            "deploy",
            "deploy --vps 100001",
            "delete --release-server --forget --forget-line 100002",
            "logs",
            "logs --waf",
            "rollback",
            "firewall sync",
            "firewall list",
            "firewall allow --to app 0.0.0.0/0",
            "status",
            "start",
            "stop",
            "restart",
            "releases",
            "bench",
        ] {
            let line = format!("erpc worker {verb}{}", app.scope());
            assert!(parses(&line), "{line}");
        }
        for verb in [
            "check",
            "key new",
            "key show",
            "secret put NAME",
            "run",
            "build",
        ] {
            for scope in [app.dir.scope(), here.clone(), up.clone()] {
                let line = format!("erpc worker {verb}{scope}");
                assert!(parses(&line), "{line}");
            }
            // check takes --env too, to require an environment; the rest
            // are the app's as a whole.
            let with_env = format!("erpc worker {verb}{}", app.scope());
            assert_eq!(parses(&with_env), verb == "check", "{with_env}");
        }
        assert!(parses("erpc worker init"));
        assert!(!parses(&format!("erpc worker init{}", app.dir.scope())));
        assert!(parses("erpc worker list"));
    }

    /// `erpc worker secret put`'s value comes from one place: the flags
    /// name the account or erpc itself, neither names the person, and both
    /// together are a usage error (exit 2) before anything is read.
    #[test]
    fn secret_put_takes_its_value_from_one_place() {
        use crate::worker_keys::Value;
        let parsed = |flags: &str| {
            let line = format!("erpc worker secret put API_TOKEN {flags}");
            <crate::Cli as clap::Parser>::try_parse_from(line.split_whitespace()).map(|cli| {
                match cli.command {
                    Some(crate::Command::Worker { action }) => match *action {
                        super::Action::Secret {
                            action: super::SecretAction::Put { value, .. },
                        } => value.value(),
                        other => panic!("not secret put: {other:?}"),
                    },
                    _ => panic!("not a worker command"),
                }
            })
        };
        assert_eq!(parsed("").ok(), Some(Value::Typed));
        assert_eq!(parsed("--replace --dir apps/bot").ok(), Some(Value::Typed));
        assert_eq!(parsed("--generate").ok(), Some(Value::Generated));
        assert_eq!(parsed("--generate --replace").ok(), Some(Value::Generated));
        assert_eq!(parsed("--from-account").ok(), Some(Value::Account));
        assert_eq!(
            parsed("--from-account --store keystore").ok(),
            Some(Value::Account)
        );
        for both in [
            "--generate --from-account",
            "--from-account --generate",
            "--from-account --replace --generate",
        ] {
            let e = parsed(both).expect_err("both flags");
            assert_eq!(e.kind(), clap::error::ErrorKind::ArgumentConflict, "{both}");
            assert_eq!(e.exit_code(), 2, "{both}");
            assert!(e.to_string().contains("cannot be used with"), "{e}");
        }
    }

    fn request(template: Option<&str>) -> super::InitRequest<'_> {
        super::InitRequest {
            chain: super::Chain::Solana,
            template,
            name: None,
            into: None,
            git: false,
            ask: false,
        }
    }

    #[test]
    fn what_to_make_is_named_by_a_choice_or_a_template() {
        use super::choose;
        let made = |asked: Option<&str>| {
            choose(&request(asked)).map(|(template, name)| (template.tag(), name))
        };
        let pumpfun = "solana/pumpfun@1".to_owned();
        // A choice, in any case: its template, and its own name.
        assert_eq!(made(Some("hft")).ok(), Some((pumpfun.clone(), "hft-bot")));
        assert_eq!(made(Some("HFT")).ok(), Some((pumpfun.clone(), "hft-bot")));
        assert_eq!(
            made(Some("Pumpfun-Bot")).ok(),
            Some((pumpfun.clone(), "pumpfun-bot"))
        );
        // A template id: the template's own name.
        assert_eq!(
            made(Some("pumpfun")).ok(),
            Some((pumpfun.clone(), "pumpfun-bot"))
        );
        assert_eq!(
            made(Some("solana/pumpfun")).ok(),
            Some((pumpfun, "pumpfun-bot"))
        );
        // The one to start from, under its choice's name or its id.
        let hello = "solana/hello@1".to_owned();
        assert_eq!(
            made(Some("HelloWorld")).ok(),
            Some((hello.clone(), "hello-world"))
        );
        assert_eq!(
            made(Some("hello")).ok(),
            Some((hello.clone(), "hello-world"))
        );
        // Nobody to ask and nothing named: the one to start from.
        assert_eq!(made(None).ok(), Some((hello, "hello-world")));
        // Coming soon, and nothing: a usage error that says which.
        let soon = made(Some("stablecoin")).expect_err("coming soon");
        assert_eq!(soon.code, super::Code::Usage);
        assert!(soon.message.contains("coming soon"), "{}", soon.message);
        let unknown = made(Some("nothing")).expect_err("unknown");
        assert_eq!(unknown.code, super::Code::Usage);
        assert!(
            unknown.message.contains("HelloWorld or HFT or pumpfun-bot"),
            "{}",
            unknown.message
        );
    }

    #[test]
    fn check_names_a_key_only_to_an_app_that_trades() {
        use erpc_worker::template;
        let rendered = |id: &str| {
            let files = template::find(super::Chain::Solana, id)
                .expect("template")
                .render("my-app")
                .expect("renders");
            let (_, text) = files
                .into_iter()
                .find(|(p, _)| p.as_os_str() == "erpc.toml")
                .expect("erpc.toml");
            super::Manifest::parse(&String::from_utf8(text).expect("utf8")).expect("valid")
        };
        let path = std::path::Path::new("/apps/my-app/erpc.toml");
        // The bot is told how to make its key; the hello app, which needs
        // none, is not, and neither is an app made by hand.
        let bot = rendered("pumpfun");
        assert!(super::lacks_its_key(&bot));
        assert!(super::describe(path, &bot, &[]).contains("erpc worker key new"));
        let hello = rendered("hello");
        assert!(!super::lacks_its_key(&hello));
        assert!(!super::describe(path, &hello, &[]).contains("key new"));
        let by_hand =
            super::Manifest::parse("name = \"mine\"\nchain = \"solana\"\n").expect("valid");
        assert!(!super::lacks_its_key(&by_hand));
    }

    #[test]
    fn the_next_steps_ask_for_a_key_only_of_an_app_that_trades() {
        use super::next_steps;
        use erpc_worker::template;
        let root = std::env::temp_dir().join(format!("erpc-w-next-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        let steps = |id: &str, name: &str| {
            let made = template::find(super::Chain::Solana, id).expect("template");
            let dest = root.join(name);
            made.write(name, &dest).expect("writes");
            next_steps(&dest, &format!(" {name}"), &format!(" --dir {name}"), &made)
        };
        // Nothing to set up: check, run, deploy.
        let hello = steps("hello", "my-api");
        assert_eq!(
            hello[1..],
            [
                "erpc worker check my-api",
                "erpc worker run my-api",
                "erpc worker deploy my-api"
            ],
            "{hello:?}"
        );
        // A bot: its key and its settings first, and the line it needs on
        // the run and the deploy alike.
        let bot = steps("pumpfun", "my-bot");
        assert_eq!(bot[1], "erpc worker key new my-bot", "{bot:?}");
        // `secret put` takes the app by --dir: its own argument comes
        // first. Neither value has to be typed: the bot's own token is
        // made, and the RPC key is the account's.
        assert_eq!(
            bot[2..4],
            [
                "erpc worker secret put API_TOKEN --generate --dir my-bot",
                "erpc worker secret put ERPC_API_KEY --from-account --dir my-bot"
            ],
            "{bot:?}"
        );
        for step in &bot {
            let words: Vec<String> = std::iter::once("erpc".to_owned())
                .chain(step.split_whitespace().skip(1).map(ToOwned::to_owned))
                .collect();
            if step.starts_with("erpc ") && !step.contains('<') {
                assert!(
                    <crate::Cli as clap::Parser>::try_parse_from(&words).is_ok(),
                    "`{step}` does not parse"
                );
            }
        }
        assert_eq!(
            bot[bot.len() - 2..],
            [
                "erpc worker run my-bot --grpc --ip <IPV4>",
                "erpc worker deploy my-bot --grpc"
            ],
            "{bot:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The flag a hint names for a secret is the one `init` named when it
    /// made the app: the template's, found again from what erpc.toml says
    /// the app was made from.
    #[test]
    fn a_hint_keeps_a_secret_with_the_flag_the_apps_template_names() {
        use super::{Manifest, secret_flag};
        use erpc_worker::template;
        let app = |template: &str| {
            Manifest::parse(&format!("name = \"bot\"\nchain = \"solana\"\n{template}"))
                .expect("valid")
        };
        let bot = app("template = \"solana/pumpfun@1\"\n");
        assert_eq!(secret_flag(&bot, "API_TOKEN"), " --generate");
        assert_eq!(secret_flag(&bot, "ERPC_API_KEY"), " --from-account");
        // A secret the operator has to give is typed.
        assert_eq!(secret_flag(&bot, "X_TOKEN"), "");
        // A template with no token of its own: only the account's key
        // need not be typed.
        let hello = app("template = \"solana/hello@1\"\n");
        assert_eq!(secret_flag(&hello, "API_TOKEN"), "");
        assert_eq!(secret_flag(&hello, "ERPC_API_KEY"), " --from-account");
        // An app made by hand, or from a template this erpc does not
        // carry: nothing is known of its settings, so each is typed.
        for by_hand in [app(""), app("template = \"solana/nope@1\"\n")] {
            for setting in ["API_TOKEN", "ERPC_API_KEY"] {
                assert_eq!(secret_flag(&by_hand, setting), "", "{:?}", by_hand.template);
            }
        }
        // For every template, the choice `init`'s next steps make.
        for made_from in template::ALL {
            let m = app(&format!("template = \"{}\"\n", made_from.tag()));
            for setting in ["API_TOKEN", "ERPC_API_KEY", "X_TOKEN"] {
                assert_eq!(secret_flag(&m, setting), made_from.secret_flag(setting));
            }
        }
    }

    #[test]
    fn only_a_person_picking_gets_a_numbered_name() {
        use super::app_name;
        let into = std::env::temp_dir().join(format!("erpc-w-names-{}", std::process::id()));
        std::fs::create_dir_all(into.join("hft-bot")).expect("dirs");
        let mut req = request(None);
        req.into = Some(&into);
        // A script: the choice's own name, which then fails as taken.
        let (name, _) = app_name(&req, "hft-bot").expect("named");
        assert_eq!(name, "hft-bot");
        // A person at the picker: the next free one.
        req.ask = true;
        let (name, dest) = app_name(&req, "hft-bot").expect("named");
        assert_eq!(name, "hft-bot-2");
        assert_eq!(dest, into.join("hft-bot-2"));
        // --name is kept as given, taken or not.
        req.name = Some("hft-bot");
        assert_eq!(app_name(&req, "hft-bot").expect("named").0, "hft-bot");
        let _ = std::fs::remove_dir_all(&into);
    }

    #[test]
    fn a_name_taken_by_a_directory_gets_the_next_number() {
        use super::free_name;
        assert_eq!(free_name("hft-bot", |_| false), "hft-bot");
        let taken = ["hft-bot", "hft-bot-2"];
        assert_eq!(free_name("hft-bot", |n| taken.contains(&n)), "hft-bot-3");
        // All taken: the plain name, which then fails as taken.
        assert_eq!(free_name("hft-bot", |_| true), "hft-bot");
    }

    #[test]
    fn a_hint_names_the_environment_and_directory_it_is_for() {
        let app = |dir: Option<&str>, env: &str| App {
            dir: Dir {
                name: None,
                dir: dir.map(Into::into),
            },
            env: env.to_owned(),
        };
        assert_eq!(app(None, "default").scope(), " --env default");
        assert_eq!(
            app(Some("apps/bot"), "staging").scope(),
            " --env staging --dir apps/bot"
        );
        // A path a shell would split or expand is quoted, as it reads back.
        assert_eq!(
            app(Some("my app/it's"), "prod").scope(),
            " --env prod --dir 'my app/it'\\''s'"
        );
        assert_eq!(
            app(Some("$HOME"), "prod").scope(),
            " --env prod --dir '$HOME'"
        );
    }

    fn app_dir(tag: &str, manifest: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("erpc-w-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("src")).expect("dirs");
        std::fs::write(root.join("erpc.toml"), manifest).expect("write");
        root
    }

    #[test]
    fn the_manifest_is_found_from_inside_the_app() {
        let root = app_dir("find", "name = \"bot\"\nchain = \"solana\"\n");
        let dir = Dir {
            name: None,
            dir: Some(root.join("src")),
        };
        assert_eq!(locate(&dir).expect("found"), root.join("erpc.toml"));
        let file = Dir {
            name: None,
            dir: Some(root.join("erpc.toml")),
        };
        assert_eq!(locate(&file).expect("found"), root.join("erpc.toml"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn check_reports_problems_as_a_finding_not_a_failure() {
        let root = app_dir("bad", "name = \"Bot\"\nchain = \"solana\"\n");
        let dir = Dir {
            name: None,
            dir: Some(root.clone()),
        };
        assert!(
            matches!(check(false, &dir, None), Outcome::Problems(r) if r.contains("name `Bot`"))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn check_requires_the_environment_asked_for() {
        let root = app_dir("env", "name = \"bot\"\nchain = \"solana\"\n");
        let dir = Dir {
            name: None,
            dir: Some(root.clone()),
        };
        assert!(matches!(check(false, &dir, None), Outcome::Done(_)));
        assert!(matches!(
            check(false, &dir, Some("prod")),
            Outcome::Problems(_)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn check_says_what_the_waf_will_do_and_what_is_wrong_with_it() {
        crate::ui::force_drawn(false);
        let app = "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n";
        let root = app_dir("waf", &format!("{app}[waf]\nport = 8080\n"));
        let Outcome::Done(report) = check(false, &Dir::at(&root), None) else {
            panic!("a report");
        };
        assert!(
            report.contains("\n  waf       port 8080, in front of the app on 127.0.0.1:3000: "),
            "{report}"
        );
        assert!(
            report.contains("\n            per address: 50 requests a second (burst 100), "),
            "{report}"
        );
        let _ = std::fs::remove_dir_all(root);
        // An app without the table is told nothing of one.
        let root = app_dir("plain", app);
        let Outcome::Done(report) = check(false, &Dir::at(&root), None) else {
            panic!("a report");
        };
        assert!(!report.contains("\n  waf "), "{report}");
        let _ = std::fs::remove_dir_all(root);
        // What is wrong with the table is a finding that names its key.
        let root = app_dir(
            "waf-bad",
            &format!("{app}[waf]\nport = 80\nrate = {{ per_second = 0, burst = 1 }}\n"),
        );
        let Outcome::Problems(report) = check(false, &Dir::at(&root), None) else {
            panic!("a finding");
        };
        assert!(report.contains("waf.port 80 is below 1024"), "{report}");
        assert!(report.contains("waf.rate.per_second is 0"), "{report}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn check_says_its_findings_in_the_language_of_the_run() {
        use crate::i18n::speaking;
        use erpc_core::i18n::Lang;
        crate::ui::force_drawn(false);
        let root = app_dir("lang", "name = \"Bot\"\nchain = \"solana\"\n");
        let dir = Dir::at(&root);
        let said = |lang| match speaking(lang, || check(false, &dir, None)) {
            Outcome::Problems(r) => r,
            _ => panic!("a finding"),
        };
        // erpc's own words follow the run; the manifest's problem, from
        // erpc-worker, stays as it is.
        let ja = said(Lang::Ja);
        assert!(ja.contains("問題が 1 件あります"), "{ja}");
        assert!(ja.contains("name `Bot`"), "{ja}");
        let ru = said(Lang::Ru);
        assert!(ru.contains(": 1 проблема"), "{ru}");
        assert!(said(Lang::En).contains(": 1 problem\n"));
        let _ = std::fs::remove_dir_all(root);
    }

    /// What a deploy would find only after it bought a server: `check`
    /// reads the binary `build.prebuilt` names, and says what it is.
    #[test]
    fn check_warns_of_a_prebuilt_binary_no_server_can_run() {
        use crate::i18n::speaking;
        use erpc_core::i18n::Lang;
        crate::ui::force_drawn(false);
        let root = app_dir(
            "prebuilt",
            "name = \"bot\"\nchain = \"solana\"\n[build]\nprebuilt = \"dist/bot\"\n",
        );
        std::fs::create_dir_all(root.join("dist")).expect("dist");
        let dir = Dir::at(&root);
        let said = || match speaking(Lang::En, || check(false, &dir, None)) {
            Outcome::Done(said) => said,
            _ => panic!("a warning, not a finding"),
        };
        let absent = said();
        assert!(
            absent.contains("before a deploy from this machine: build.prebuilt names dist/bot"),
            "{absent}"
        );
        for (bytes, why) in [
            (&b"#!/bin/sh\nexec python3 bot.py\n"[..], "it is a script"),
            (
                &[0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1][..],
                "it is a macOS binary",
            ),
            (&b"just some text"[..], "it is not a Linux (ELF) binary"),
        ] {
            std::fs::write(root.join("dist/bot"), bytes).expect("a file");
            let said = said();
            let warned = said
                .lines()
                .find(|line| line.contains("before a deploy from this machine"))
                .unwrap_or_else(|| panic!("no warning: {said}"));
            assert!(warned.contains("cannot run on a server"), "{said}");
            assert!(warned.contains(why), "{said}");
        }
        // What it is, is said in the language of the run.
        let Outcome::Done(ja) = speaking(Lang::Ja, || check(false, &dir, None)) else {
            panic!("a warning, not a finding");
        };
        assert!(ja.contains("Linux（ELF）のバイナリではありません"), "{ja}");
        // A program for the servers' machine is not warned of.
        let program = {
            use crate::elf::fixture::{GLIBC_X86_64, X86_64, linked};
            linked(X86_64, GLIBC_X86_64, b"\0GLIBC_2.31\0")
        };
        std::fs::write(root.join("dist/bot"), program).expect("a binary");
        let said = said();
        assert!(!said.contains("build.prebuilt"), "{said}");
        assert!(!said.contains("cannot run on a server"), "{said}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn check_warns_of_a_credential_under_vars_and_the_app_still_passes() {
        use crate::i18n::speaking;
        use erpc_core::i18n::Lang;
        crate::ui::force_drawn(false);
        // Joined from parts: no file holds a URL with a password whole.
        let url = ["postgres", "://app:devpass", "@", "db/app"].concat();
        let root = app_dir(
            "cred",
            &format!(
                "name = \"bot\"\nchain = \"solana\"\n\
                 [vars]\nDATABASE_URL = \"{url}\"\nLOG_LEVEL = \"info\"\n"
            ),
        );
        let dir = Dir::at(&root);
        // A warning, in the language of the run, on an app that is valid:
        // one deployed before the rule was there still deploys.
        for (lang, words) in [
            (
                Lang::En,
                "carries a credential in its value (a URL with a password",
            ),
            (Lang::Ja, "認証情報が含まれています"),
            (Lang::Zh, "带有凭据"),
            (Lang::Ru, "содержит учётные данные"),
        ] {
            let Outcome::Done(said) = speaking(lang, || check(false, &dir, None)) else {
                panic!("a warning, not a finding");
            };
            assert!(said.contains(words), "{said}");
            assert!(
                said.contains("`erpc worker secret put DATABASE_URL --dir "),
                "{said}"
            );
            assert!(!said.contains("LOG_LEVEL carries"), "{said}");
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
