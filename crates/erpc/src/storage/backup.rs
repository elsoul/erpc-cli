// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc backup`: this machine backed up to ERPC Global Storage with
//! restic.
//!
//! Who holds what:
//! - **The account**, in the store `erpc login` chose: the repository's
//!   master password ([`PASSWORD`]) and a `read_write` storage access key
//!   ([`ADMIN_KEY`]). Only `init` and `prune` use them.
//! - **This machine**, in `~/.erpc/backup.env` (0600): an `append_only`
//!   access key and the password of this machine's own restic key. `run`,
//!   `snapshots`, `restore` and `check` use only these. A machine that holds
//!   only these can add snapshots but not delete them, and its restic key
//!   can be removed without touching the others. The machine `init` ran on
//!   holds the account's secrets and the erpc session as well, so this
//!   protects only the machines that hold neither.
//!
//! restic encrypts everything before it leaves the machine; ERPC never
//! holds a password that opens the repository.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use erpc_api::storage::{self as api, Permission};
use erpc_auth::AuthClient;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::account_secret::{self, Slot};
use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::restic::{self, Credentials};

/// The repository's master password.
pub const PASSWORD: Slot = Slot {
    tag: "erpc-backup-password",
    title: "ERPC backup repository password",
    note: "erpc backup's restic repository opens with this password. Without it, and without \
           every machine's own key, the backups cannot be read.",
    service: "erpc-backup-password",
    file: "backup-password",
    what: "the backup repository password",
    instead: "",
};

/// The `read_write` storage access key `init` and `prune` sign in with, as
/// `<access key id>:<secret>`.
pub const ADMIN_KEY: Slot = Slot {
    tag: "erpc-backup-admin-key",
    title: "ERPC backup admin access key",
    note: "erpc backup signs in with this read_write storage access key to set up machines and \
           to prune.",
    service: "erpc-backup-admin-key",
    file: "backup-admin-key",
    what: "the backup admin access key",
    instead: "",
};

/// This machine's backup credentials, beside the config.
const HOST_FILE: &str = "backup.env";

/// What `erpc backup` does.
#[derive(Subcommand)]
pub enum Action {
    /// Set this machine up: restic, the access keys, the repository, and
    /// this machine's own restic key.
    Init {
        /// Use the password in this file for a repository made before, for
        /// example by `slv backup` (`~/.slv/restic-password`).
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
    /// Back up this machine: on Linux `/` less system and volatile paths,
    /// elsewhere the paths given. Known key-file names are left out
    /// (docs/backup.md lists them).
    Run {
        /// What to back up (default on Linux: `/`).
        paths: Vec<PathBuf>,
        /// Leave this path or glob out too (repeatable).
        #[arg(long)]
        exclude: Vec<String>,
        /// Show what would be backed up, and send nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// The snapshots of this machine.
    #[command(visible_alias = "ls")]
    Snapshots {
        /// Every machine's snapshots.
        #[arg(long)]
        all_hosts: bool,
    },
    /// Restore a snapshot into a new directory, or over this machine with
    /// --in-place.
    Restore {
        /// The snapshot's id, or `latest`.
        snapshot: String,
        /// The directory to restore into (default: ./erpc-restore-<id>; it
        /// must not exist yet).
        #[arg(long, conflicts_with = "in_place")]
        target: Option<PathBuf>,
        /// Write the files back where they were, over what is there now.
        #[arg(long)]
        in_place: bool,
        /// Restore a snapshot another machine made.
        #[arg(long)]
        from_host: Option<String>,
        /// Restore this machine's disks, network and SSH host identity too
        /// (/etc/fstab, /boot, /etc/netplan, /etc/machine-id, SSH host keys).
        #[arg(long)]
        include_system: bool,
        /// Restore only this directory of the snapshot, as an absolute path
        /// in it, e.g. /etc. Its contents land in the target, or with
        /// --in-place back in that directory.
        #[arg(long)]
        path: Option<String>,
        /// Go ahead without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Check the repository, reading back a part of the data.
    Check {
        /// How much of the data to read back, e.g. `5%` or `1/20`.
        #[arg(long, default_value = "5%")]
        read_data: String,
    },
    /// Forget old snapshots of one machine and free their space.
    Prune {
        /// Daily snapshots to keep.
        #[arg(long, default_value_t = 7)]
        keep_daily: u32,
        /// Weekly snapshots to keep.
        #[arg(long, default_value_t = 4)]
        keep_weekly: u32,
        /// Monthly snapshots to keep.
        #[arg(long, default_value_t = 6)]
        keep_monthly: u32,
        /// The machine whose snapshots to prune (default: this one).
        #[arg(long)]
        host: Option<String>,
        /// Show what would be forgotten, and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Go ahead without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Run `erpc backup run` on a timer: systemd on Linux, launchd on
    /// macOS.
    Schedule {
        /// How often, or `off` to stop.
        every: crate::backup_schedule::Every,
        /// The time of day, 24-hour.
        #[arg(long, default_value = "03:00")]
        at: String,
        /// What to back up (default on Linux: `/`).
        paths: Vec<PathBuf>,
        /// Leave this path or glob out too (repeatable).
        #[arg(long)]
        exclude: Vec<String>,
    },
    /// The schedule, and what the last run did.
    Status,
    /// Print the repository's master password, to keep a copy away from
    /// this machine.
    Password {
        /// Print it. Anyone who sees it, and can sign in to this account,
        /// can read every backup.
        #[arg(long)]
        show: bool,
    },
}

/// Runs `erpc backup <action>`.
pub async fn run(json: bool, action: Action) -> Outcome {
    let result = match action {
        Action::Init { password_file } => init(json, password_file.as_deref()).await,
        Action::Run {
            paths,
            exclude,
            dry_run,
        } => backup(json, &paths, &exclude, dry_run).await,
        Action::Snapshots { all_hosts } => snapshots(json, all_hosts).await,
        Action::Restore {
            snapshot,
            target,
            in_place,
            from_host,
            include_system,
            path,
            yes,
        } => {
            restore(
                json,
                &snapshot,
                &Restore {
                    target,
                    in_place,
                    from_host,
                    include_system,
                    path,
                    yes,
                },
            )
            .await
        }
        Action::Check { read_data } => check(json, &read_data).await,
        Action::Prune {
            keep_daily,
            keep_weekly,
            keep_monthly,
            host,
            dry_run,
            yes,
        } => {
            prune(
                json,
                [keep_daily, keep_weekly, keep_monthly],
                host.as_deref(),
                dry_run,
                yes,
            )
            .await
        }
        Action::Schedule {
            every,
            at,
            paths,
            exclude,
        } => schedule(json, every, &at, paths, exclude),
        Action::Status => Ok(crate::backup_schedule::status(json)),
        Action::Password { show } => password(json, show),
    };
    result.unwrap_or_else(Outcome::from)
}

/// Key material and credentials, relative to a home directory. A backup
/// never carries them and a restore never writes them: the same list as
/// `slv backup`, plus erpc's own. In restic a `*` stays inside one path
/// component and `**` stands for any number of directories, none
/// included, so the key-file names are matched at any depth under a home
/// directory and the fixed places are matched where they are.
const HOME_SECRETS: &[&str] = &[
    "**/*keypair*.json",
    "**/*identity*.json",
    ".config/solana/id.json",
    ".slv/keys",
    ".slv/wallet-rescue",
    ".slv/api.yml",
    ".slv/gateway/gateway.json",
    ".slv/backup.env",
    ".slv/restic-password",
    ".ssh/id_*",
    ".erpc/state/credentials.toml*",
    ".erpc/storage-key",
    ".erpc/backup.env",
    ".erpc/backup-password",
    ".erpc/backup-admin-key",
    ".erpc/keyless.toml",
];

/// Key material and credentials at fixed places.
const SYSTEM_SECRETS: &[&str] = &[
    "/etc/ssh/ssh_host_*_key",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/wireguard",
    "/etc/doublezero/keys",
    "/etc/ssl/private",
    "/etc/nginx/ssl",
];

/// Pseudo-filesystems, mounts and volatile paths a backup of `/` leaves out.
const VOLATILE: &[&str] = &[
    "/dev/*",
    "/proc/*",
    "/sys/*",
    "/tmp/*",
    "/run/*",
    "/mnt/*",
    "/media/*",
    "/lost+found",
    "/swapfile",
    "/snap/*",
    "/var/log/*",
    "backup-*.tar.zst",
    "backup-*.tar.gz",
];

/// What belongs to one machine's disks, network and SSH identity. A backup
/// keeps it; a restore leaves it alone unless asked.
const SYSTEM_IDENTITY: &[&str] = &[
    "/etc/fstab",
    "/boot",
    "/etc/netplan",
    "/etc/machine-id",
    "/etc/ssh/ssh_host_*",
];

/// The home directories [`HOME_SECRETS`] is written out for.
const HOMES: &[&str] = &["/root", "/home/*", "/Users/*", "/var/root"];

/// Every key-material pattern, written out for each home.
fn secret_patterns() -> Vec<String> {
    secret_patterns_in(HOMES)
}

/// [`secret_patterns`], for the home directories `homes`.
fn secret_patterns_in(homes: &[&str]) -> Vec<String> {
    let mut patterns: Vec<String> = homes
        .iter()
        .flat_map(|home| HOME_SECRETS.iter().map(move |p| format!("{home}/{p}")))
        .collect();
    patterns.extend(SYSTEM_SECRETS.iter().map(|p| (*p).to_owned()));
    if let Ok(cache) = crate::session::beside_config("cache") {
        patterns.push(cache.display().to_string());
    }
    patterns
}

/// The exclude arguments of a backup.
fn backup_excludes(whole_system: bool, extra: &[String]) -> Result<Vec<String>, String> {
    if let Some(bad) = extra
        .iter()
        .find(|e| e.trim().is_empty() || e.trim_start().starts_with('!'))
    {
        return Err(format!(
            "--exclude {bad:?} is refused: restic reads a pattern that starts with ! as one \
             that takes files back in"
        ));
    }
    let mut patterns = secret_patterns();
    if whole_system {
        patterns.extend(VOLATILE.iter().map(|p| (*p).to_owned()));
    }
    patterns.extend(extra.iter().cloned());
    Ok(patterns
        .into_iter()
        .flat_map(|p| ["--exclude".to_owned(), p])
        .collect())
}

/// The exclude arguments of a restore.
///
/// Restoring part of a snapshot (`<id>:<dir>`), restic matches the
/// patterns against paths under `<dir>`, so each pattern is written again
/// relative to it; one that cannot reach under `<dir>` is left out.
fn restore_excludes(include_system: bool, under: Option<&str>) -> Vec<String> {
    let mut patterns = secret_patterns();
    if !include_system {
        patterns.extend(SYSTEM_IDENTITY.iter().map(|p| (*p).to_owned()));
    }
    patterns
        .iter()
        .filter_map(|p| match under {
            Some(dir) => relative_to(p, dir),
            None => Some(p.clone()),
        })
        .flat_map(|p| ["--exclude".to_owned(), p])
        .collect()
}

/// What restic restores, and where. restic names a part of a snapshot as
/// `<id>:<dir>` (it refuses `--include` beside `--exclude`), and writes
/// that directory's contents into the target. So in place, a part goes
/// back into its own directory, never into `/`.
fn restore_plan(
    snapshot: &Snapshot,
    under: Option<&str>,
    in_place: bool,
    target: Option<&Path>,
) -> (String, PathBuf) {
    let source = under.map_or_else(
        || snapshot.id.clone(),
        |dir| format!("{}:{dir}", snapshot.id),
    );
    let target = match (in_place, under, target) {
        (true, Some(dir), _) => PathBuf::from(dir),
        (true, None, _) => PathBuf::from("/"),
        (false, _, Some(target)) => target.to_owned(),
        (false, _, None) => PathBuf::from(format!("erpc-restore-{}", snapshot.short_id)),
    };
    (source, target)
}

/// `path` as a directory in a snapshot: absolute, and every component a
/// plain name. `.`, `..` and empty components are refused rather than
/// resolved: restic would resolve them, and the excludes must be written
/// for the same directory restic restores.
fn snapshot_dir(path: &str) -> Result<String, String> {
    let refused = || format!("--path {path:?} is not a directory in the snapshot such as /etc");
    let rest = path.strip_prefix('/').ok_or_else(refused)?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() {
        return Err(refused());
    }
    if rest
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == ".." || c.chars().any(char::is_control))
    {
        return Err(refused());
    }
    Ok(format!("/{rest}"))
}

/// Whether one path component matches a pattern component in which `*`
/// stands for any characters.
fn component_matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, rest)) => {
            let Some(after) = name.strip_prefix(head) else {
                return false;
            };
            (0..=after.len())
                .filter(|&i| after.is_char_boundary(i))
                .any(|i| component_matches(rest, &after[i..]))
        }
    }
}

/// `pattern`, an absolute restic pattern, as it applies to the paths under
/// the directory `dir`; `None` when it matches nothing there.
fn relative_to(pattern: &str, dir: &str) -> Option<String> {
    let pat: Vec<&str> = pattern.split('/').filter(|c| !c.is_empty()).collect();
    let dir: Vec<&str> = dir.split('/').filter(|c| !c.is_empty()).collect();
    if !pattern.starts_with('/') {
        // Not anchored: restic matches it at any depth already.
        return Some(pattern.to_owned());
    }
    for (i, name) in dir.iter().enumerate() {
        match pat.get(i) {
            // The pattern names `dir` itself or a directory above it: all of
            // it is left out.
            None => return Some("/**".to_owned()),
            // From here the rest matches at any depth.
            Some(&"**") => return Some(format!("/**/{}", pat[i + 1..].join("/"))),
            Some(component) if component_matches(component, name) => {}
            Some(_) => return None,
        }
    }
    match &pat[dir.len()..] {
        [] => Some("/**".to_owned()),
        rest => Some(format!("/{}", rest.join("/"))),
    }
}

/// A failure as `erpc backup` reports it.
pub(crate) struct Failure(pub(crate) CliError);

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self(CliError::new(Code::Failed, message))
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Self(CliError::new(Code::Failed, message.to_owned()))
    }
}

impl From<CliError> for Failure {
    fn from(e: CliError) -> Self {
        Self(e)
    }
}

impl From<api::StorageError> for Failure {
    fn from(e: api::StorageError) -> Self {
        Self(crate::storage::refused(e))
    }
}

impl From<Failure> for Outcome {
    fn from(f: Failure) -> Self {
        f.0.into()
    }
}

type Done = Result<Outcome, Failure>;

/// This machine's credentials, as kept in [`HOST_FILE`].
struct Host {
    name: String,
    credentials: Credentials,
    restic_key: String,
}

fn host_path() -> Result<PathBuf, String> {
    crate::session::beside_config(HOST_FILE)
}

impl Host {
    fn render(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "# erpc backup: this machine's credentials. Keep this file private.\n\
             RESTIC_REPOSITORY={}\n\
             RESTIC_REST_USERNAME={}\n\
             RESTIC_REST_PASSWORD={}\n\
             RESTIC_PASSWORD={}\n\
             ERPC_BACKUP_HOST={}\n\
             ERPC_BACKUP_RESTIC_KEY={}\n",
            restic::REPOSITORY,
            self.credentials.key_id,
            self.credentials.key_secret.expose_secret(),
            self.credentials.password.expose_secret(),
            self.name,
            self.restic_key,
        ))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let get = |name: &str| {
            text.lines()
                .filter_map(|l| l.split_once('='))
                .find(|(k, _)| k.trim() == name)
                .map(|(_, v)| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{HOST_FILE} has no {name}"))
        };
        Ok(Self {
            name: get("ERPC_BACKUP_HOST")?,
            credentials: Credentials {
                key_id: get("RESTIC_REST_USERNAME")?,
                key_secret: SecretString::from(get("RESTIC_REST_PASSWORD")?),
                password: SecretString::from(get("RESTIC_PASSWORD")?),
            },
            restic_key: get("ERPC_BACKUP_RESTIC_KEY")?,
        })
    }

    fn load() -> Result<Option<Self>, String> {
        account_secret::read_private(&host_path()?)?
            .map(|text| Self::parse(&text))
            .transpose()
    }

    /// This machine's credentials, or what to run to have them.
    fn require() -> Result<Self, Failure> {
        Self::load()?.ok_or_else(|| {
            Failure(
                CliError::new(Code::Failed, "this machine is not set up for backups")
                    .hint("run `erpc backup init` first"),
            )
        })
    }
}

/// A secret of 32 random bytes, in hex.
pub(crate) fn random_secret() -> Result<Zeroizing<String>, String> {
    use std::fmt::Write as _;
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|e| format!("no randomness: {e}"))?;
    let mut hex = Zeroizing::new(String::with_capacity(64));
    for b in bytes.iter() {
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// The session `erpc login` holds, for making access keys.
pub(crate) async fn signed_in() -> Result<(AuthClient, SecretString), Failure> {
    let client = AuthClient::new().map_err(|e| Failure(crate::error::classify(&e)))?;
    match crate::storage::access_token(&client).await {
        Ok(token) => Ok((client, token)),
        Err(outcome) => {
            Err(Failure(outcome.error().unwrap_or_else(|| {
                CliError::new(Code::NotSignedIn, "not signed in")
            })))
        }
    }
}

/// The account's admin access key, when one is kept.
pub(crate) fn kept_admin_key() -> Result<Option<(String, SecretString)>, Failure> {
    let (Some(kept), _) = ADMIN_KEY.read()? else {
        return Ok(None);
    };
    let (id, secret) = kept
        .split_once(':')
        .ok_or("the kept backup admin access key is not <id>:<secret>")?;
    Ok(Some((id.to_owned(), SecretString::from(secret.to_owned()))))
}

/// The account's admin access key, made and kept first if there is none.
async fn admin_key(
    client: &AuthClient,
    token: &SecretString,
) -> Result<(String, SecretString), Failure> {
    if let Some(kept) = kept_admin_key()? {
        return Ok(kept);
    }
    let made = api::create_access_key(
        client,
        token,
        Some("erpc backup admin"),
        Permission::ReadWrite,
    )
    .await?;
    let joined = Zeroizing::new(format!(
        "{}:{}",
        made.key.access_key_id,
        made.secret.expose_secret()
    ));
    if let Err(e) = ADMIN_KEY.write(&joined) {
        let _ = api::revoke_access_key(client, token, made.key.id).await;
        return Err(e.into());
    }
    Ok((made.key.access_key_id, made.secret))
}

/// Whether `credentials` open the repository: restic's exit code for
/// `cat config`.
pub(crate) fn probe(program: &Path, credentials: &Credentials) -> Result<restic::Ran, String> {
    let mut command = restic::command(program, credentials);
    command.args(["cat", "config", "--no-lock"]);
    restic::quiet(command)
}

/// The account's side of backups, ready: its admin key, its master
/// password, and the repository they open.
pub(crate) struct Account {
    /// The admin key with the master password.
    pub(crate) admin: Credentials,
    /// Where the master password is kept.
    pub(crate) kind: erpc_auth::store::StoreKind,
    /// Whether the repository was made just now.
    pub(crate) made_repository: bool,
    /// Whether the master password was kept just now.
    pub(crate) kept_password: bool,
}

/// Makes and keeps what the account needs for backups when it is not
/// there yet: the admin key, the master password (the one in
/// `password_file`, for a repository made before), and the repository.
pub(crate) async fn account(
    program: &Path,
    client: &AuthClient,
    token: &SecretString,
    password_file: Option<&Path>,
) -> Result<Account, Failure> {
    let (admin_id, admin_secret) = admin_key(client, token).await?;

    // The master password: the kept one, the one given, or a new one.
    let (kept, kind) = PASSWORD.read()?;
    let given = match password_file {
        Some(path) => Some(Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| format!("could not read {}: {e}", path.display()))?
                .trim()
                .to_owned(),
        )),
        None => None,
    };
    let password = match (kept.as_ref(), given) {
        (Some(kept), Some(given)) if kept.as_str() != given.as_str() => {
            return Err(Failure(
                CliError::new(
                    Code::Failed,
                    format!(
                        "a different backup repository password is kept already, in {}",
                        PASSWORD.place(kind)
                    ),
                )
                .hint("erpc does not replace it: backups made with it would become unreadable"),
            ));
        }
        (Some(kept), _) => kept.clone(),
        (None, Some(given)) if given.is_empty() => {
            return Err(Failure::from("the password file is empty"));
        }
        (None, Some(given)) => given,
        (None, None) => random_secret()?,
    };
    let admin = Credentials {
        key_id: admin_id,
        key_secret: admin_secret,
        password: SecretString::from(password.to_string()),
    };

    let mut made_repository = false;
    let probed = probe(program, &admin)?;
    match probed.code() {
        0 => {}
        restic::exit::NO_REPOSITORY => {
            if kept.is_none() {
                PASSWORD.write(&password)?;
            }
            let mut command = restic::command(program, &admin);
            command.arg("init");
            let ran = restic::quiet(command)?;
            if !ran.status.success() {
                return Err(
                    format!("restic could not make the repository: {}", ran.reason()).into(),
                );
            }
            made_repository = true;
        }
        restic::exit::WRONG_PASSWORD => {
            return Err(Failure(
                CliError::new(
                    Code::Failed,
                    "there is a backup repository already, and this password does not open it",
                )
                .hint(
                    "if `slv backup` made it, run `erpc backup init --password-file ~/.slv/restic-password`",
                ),
            ));
        }
        _ => {
            return Err(
                format!("restic could not reach the repository: {}", probed.reason()).into(),
            );
        }
    }
    let kind = if kept.is_none() && !made_repository {
        PASSWORD.write(&password)?
    } else {
        kind
    };
    Ok(Account {
        admin,
        kind,
        made_repository,
        kept_password: kept.is_none(),
    })
}

#[allow(clippy::too_many_lines)] // one setup, read top to bottom
async fn init(json: bool, password_file: Option<&Path>) -> Done {
    let program = restic::ensure().await?;
    let (client, token) = signed_in().await?;
    let Account {
        admin,
        kind,
        made_repository,
        ..
    } = account(&program, &client, &token, password_file).await?;

    // This machine's own key, unless the one it has still works.
    let name = crate::session::host_label();
    let old = Host::load()?;
    if let Some(host) = &old
        && probe(&program, &host.credentials)?.status.success()
    {
        return Ok(done(
            json,
            &json!({ "host": host.name, "repository": "ready", "machine": "ready" }),
            format!(
                "Backups are set up on {} already.\n  repository password  {}\n  this machine         {}",
                host.name,
                PASSWORD.place(kind),
                host_path()?.display()
            ),
        ));
    }
    let made = api::create_access_key(
        &client,
        &token,
        Some(&format!("erpc backup {name}")),
        Permission::AppendOnly,
    )
    .await?;
    let host_password = random_secret()?;
    let restic_key = match add_restic_key(&program, &admin, &name, &host_password) {
        Ok(id) => id,
        Err(e) => {
            let _ = api::revoke_access_key(&client, &token, made.key.id).await;
            return Err(e.into());
        }
    };
    let host = Host {
        name: name.clone(),
        credentials: Credentials {
            key_id: made.key.access_key_id,
            key_secret: made.secret,
            password: SecretString::from(host_password.to_string()),
        },
        restic_key,
    };
    // Checked before it is written, so a failure leaves the file as it was.
    let kept = probe(&program, &host.credentials)
        .and_then(|checked| {
            if checked.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "this machine's new key does not open the repository: {}",
                    checked.reason()
                ))
            }
        })
        .and_then(|()| account_secret::write_private(&host_path()?, &host.render(), true));
    if let Err(e) = kept {
        // Nothing half-made is left behind to count against the ten keys.
        let _ = remove_restic_key(&program, &admin, &host.restic_key);
        let _ = api::revoke_access_key(&client, &token, made.key.id).await;
        return Err(e.into());
    }
    // The credentials this machine had before, which no longer worked.
    if let Some(old) = old {
        if old.restic_key != host.restic_key {
            let _ = remove_restic_key(&program, &admin, &old.restic_key);
        }
        if let Ok(keys) = api::access_keys(&client, &token).await
            && let Some(row) = keys
                .iter()
                .find(|k| k.access_key_id == old.credentials.key_id)
        {
            let _ = api::revoke_access_key(&client, &token, row.id).await;
        }
    }
    Ok(done(
        json,
        &json!({
            "host": name,
            "repository": if made_repository { "made" } else { "ready" },
            "machine": "ready",
            "resticKey": host.restic_key,
        }),
        format!(
            "Backups are set up on {name}.\n  repository           {}\n  repository password  {}\n  this machine         {} (an append-only key)\n\n\
             Keep a copy of the repository password away from this machine:\n  erpc backup password --show\n\
             Then back up with `erpc backup run`.\n\n\
             This machine also holds the erpc session and the account's backup admin key, so whoever \
             takes it over can delete backups. The append-only key protects them only on a machine \
             that holds neither.",
            if made_repository {
                "made now"
            } else {
                "already there"
            },
            PASSWORD.place(kind),
            host_path()?.display(),
        ),
    ))
}

/// Removes a restic key. Callers cleaning up after a failure ignore the
/// error: a key left over there is harmless, since its password is gone.
///
/// # Errors
///
/// When `id` is not a key id, or restic does not remove it.
pub(crate) fn remove_restic_key(
    program: &Path,
    admin: &Credentials,
    id: &str,
) -> Result<(), String> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{id:?} is not a restic key id"));
    }
    let mut command = restic::command(program, admin);
    command.args(["key", "remove", id]);
    let ran = restic::quiet(command)?;
    if ran.status.success() {
        Ok(())
    } else {
        Err(format!(
            "restic could not remove key {id}: {}",
            ran.reason()
        ))
    }
}

/// Adds a restic key for this machine and says its id.
pub(crate) fn add_restic_key(
    program: &Path,
    admin: &Credentials,
    name: &str,
    password: &str,
) -> Result<String, String> {
    // restic takes the new password from a file. It lives only while restic
    // reads it, 0600, beside the config.
    let dir = crate::session::beside_config("")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    let file = tempfile::NamedTempFile::new_in(&dir)
        .map_err(|e| format!("could not write in {}: {e}", dir.display()))?;
    std::fs::write(file.path(), password).map_err(|e| format!("could not write: {e}"))?;
    let mut command = restic::command(program, admin);
    command
        .args(["key", "add", "--host", name, "--new-password-file"])
        .arg(file.path());
    let ran = restic::quiet(command)?;
    drop(file);
    if !ran.status.success() {
        return Err(format!(
            "restic could not add this machine's key: {}",
            ran.reason()
        ));
    }
    let as_host = Credentials {
        key_id: admin.key_id.clone(),
        key_secret: admin.key_secret.clone(),
        password: SecretString::from(password.to_owned()),
    };
    let mut command = restic::command(program, &as_host);
    command.args(["key", "list", "--json"]);
    let listed = restic::quiet(command)?;
    if !listed.status.success() {
        return Err(format!(
            "restic could not list the keys: {}",
            listed.reason()
        ));
    }
    current_key(&listed.stdout)
        .ok_or_else(|| "restic did not say which key is this machine's".to_owned())
}

/// The id of the key marked current in `restic key list --json`.
fn current_key(listing: &str) -> Option<String> {
    let keys: Vec<Value> = serde_json::from_str(listing).ok()?;
    keys.iter()
        .find(|k| k["current"].as_bool() == Some(true))
        .and_then(|k| k["id"].as_str())
        .filter(|id| id.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(ToOwned::to_owned)
}

fn done(json: bool, value: &Value, text: String) -> Outcome {
    if json {
        crate::print_json(value);
        return Outcome::Done(String::new());
    }
    Outcome::Done(text)
}

async fn backup(json: bool, paths: &[PathBuf], exclude: &[String], dry_run: bool) -> Done {
    let host = Host::require()?;
    let program = restic::ensure().await?;
    let whole_system = paths.is_empty();
    if whole_system && !cfg!(target_os = "linux") {
        return Err(Failure(
            CliError::new(Code::Usage, "name what to back up").hint(
                "for example `erpc backup run ~/Documents`; only Linux backs up / by default",
            ),
        ));
    }
    let mut command = restic::command(&program, &host.credentials);
    command.args(["backup", "--host", &host.name, "--tag", "erpc"]);
    command.args(backup_excludes(whole_system, exclude)?);
    if dry_run {
        command.args(["--dry-run", "-v"]);
    }
    if json {
        command.arg("--json");
    }
    if whole_system {
        command.arg("/");
    } else {
        command.arg("--");
        command.args(paths);
    }
    let status = restic::loud(command)?;
    if !dry_run {
        crate::backup_schedule::record(&host.name, status.code().unwrap_or(-1));
    }
    match status.code() {
        Some(0) => Ok(Outcome::Done(if json || dry_run {
            String::new()
        } else {
            format!("Backed up {}.", host.name)
        })),
        Some(restic::exit::INCOMPLETE) => Ok(Outcome::Done(
            "Backed up, except files restic could not read (listed above).".to_owned(),
        )),
        Some(restic::exit::LOCKED) => Err(Failure(
            CliError::new(Code::Failed, "the repository is locked by another run")
                .hint("wait for it to finish; a lock left by a crash expires by itself"),
        )),
        _ => Err("the backup failed (restic said why, above)".into()),
    }
}

async fn snapshots(json: bool, all_hosts: bool) -> Done {
    let host = Host::require()?;
    let program = restic::ensure().await?;
    let mut command = restic::command(&program, &host.credentials);
    command.arg("snapshots");
    if !all_hosts {
        command.args(["--host", &host.name]);
    }
    if json {
        command.arg("--json");
    }
    let status = restic::loud(command)?;
    if status.success() {
        Ok(Outcome::Done(String::new()))
    } else {
        Err("restic could not list the snapshots (it said why, above)".into())
    }
}

/// How `restore` was asked to restore.
struct Restore {
    target: Option<PathBuf>,
    in_place: bool,
    from_host: Option<String>,
    include_system: bool,
    path: Option<String>,
    yes: bool,
}

/// One snapshot as `restic snapshots --json` lists it.
struct Snapshot {
    id: String,
    short_id: String,
    host: String,
    time: String,
}

fn find_snapshot(
    program: &Path,
    credentials: &Credentials,
    wanted: &str,
    host: &str,
) -> Result<Snapshot, Failure> {
    let mut command = restic::command(program, credentials);
    command.args(["snapshots", "--json"]);
    if wanted == "latest" {
        command.args(["--latest", "1", "--host", host]);
    } else {
        if wanted.is_empty() || !wanted.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Failure(CliError::new(
                Code::Usage,
                "a snapshot is its id (hex, as `erpc backup snapshots` shows it) or `latest`",
            )));
        }
        command.arg(wanted);
    }
    let ran = restic::quiet(command)?;
    if !ran.status.success() {
        return Err(format!("restic could not find the snapshot: {}", ran.reason()).into());
    }
    let listed: Vec<Value> =
        serde_json::from_str(&ran.stdout).map_err(|_| "restic's snapshot list was unreadable")?;
    let item = listed.last().ok_or_else(|| {
        if wanted == "latest" {
            format!("{host} has no snapshots yet")
        } else {
            format!("there is no snapshot {wanted}")
        }
    })?;
    let text = |k: &str| item[k].as_str().unwrap_or_default().to_owned();
    Ok(Snapshot {
        id: text("id"),
        short_id: text("short_id"),
        host: text("hostname"),
        time: text("time"),
    })
}

async fn restore(json: bool, wanted: &str, how: &Restore) -> Done {
    // The directory, written one way only, so restic restores the same
    // directory the excludes are written again for.
    let under = how
        .path
        .as_deref()
        .map(snapshot_dir)
        .transpose()
        .map_err(|e| Failure(CliError::new(Code::Usage, e)))?;
    let excludes = restore_excludes(how.include_system, under.as_deref());
    if excludes.chunks(2).any(|pair| pair[1] == "/**") {
        return Err(Failure(CliError::new(
            Code::Usage,
            "that directory is left out of every restore: it is key material, or this machine's \
             system identity (see --include-system)",
        )));
    }
    let host = Host::require()?;
    let program = restic::ensure().await?;
    let from = how.from_host.clone().unwrap_or_else(|| host.name.clone());
    let snapshot = find_snapshot(&program, &host.credentials, wanted, &from)?;
    if snapshot.host != from {
        return Err(Failure(
            CliError::new(
                Code::Failed,
                format!(
                    "snapshot {} was made on {}, not {from}",
                    snapshot.short_id,
                    crate::storage::clean(&snapshot.host)
                ),
            )
            .hint(format!(
                "pass --from-host {} to restore it here",
                crate::storage::clean(&snapshot.host)
            )),
        ));
    }
    let (source, target) = restore_plan(
        &snapshot,
        under.as_deref(),
        how.in_place,
        how.target.as_deref(),
    );
    if how.in_place {
        crate::interrupt::say(&format!(
            "Restore {} of snapshot {} of {} ({}) over this machine, into {}. Files it holds \
             replace the ones there.",
            under.as_deref().unwrap_or("everything"),
            snapshot.short_id,
            crate::storage::clean(&snapshot.host),
            crate::storage::clean(&snapshot.time),
            target.display(),
        ));
        crate::node_common::go_ahead(how.yes, "nothing was restored")?;
    } else if target.exists() {
        return Err(Failure(
            CliError::new(Code::Failed, format!("{} exists already", target.display()))
                .hint("a restore goes into a new directory; name another with --target"),
        ));
    }
    let mut command = restic::command(&program, &host.credentials);
    command
        .args(["restore", &source, "--target"])
        .arg(&target)
        .args(excludes);
    if json {
        command.arg("--json");
    }
    let status = restic::loud(command)?;
    if !status.success() {
        return Err("the restore failed (restic said why, above)".into());
    }
    if json {
        // restic printed its own JSON; a second document would break it.
        return Ok(Outcome::Done(String::new()));
    }
    Ok(Outcome::Done(format!(
        "Restored snapshot {} into {}.\nThe key-file names docs/backup.md lists were left out{}.",
        snapshot.short_id,
        target.display(),
        if how.include_system {
            ""
        } else {
            ", and so was this machine's system identity"
        }
    )))
}

async fn check(json: bool, read_data: &str) -> Done {
    if !read_data
        .bytes()
        .all(|b| b.is_ascii_digit() || b"%/.".contains(&b))
        || read_data.is_empty()
    {
        return Err(Failure(CliError::new(
            Code::Usage,
            "--read-data is a share, such as 5% or 1/20",
        )));
    }
    let host = Host::require()?;
    let program = restic::ensure().await?;
    let mut command = restic::command(&program, &host.credentials);
    command.args(["check", "--read-data-subset", read_data]);
    if json {
        command.arg("--json");
    }
    let status = restic::loud(command)?;
    if status.success() {
        Ok(Outcome::Done(String::new()))
    } else {
        Err("the check found a problem (restic said what, above)".into())
    }
}

async fn prune(
    json: bool,
    [daily, weekly, monthly]: [u32; 3],
    host: Option<&str>,
    dry_run: bool,
    yes: bool,
) -> Done {
    let name = host.map_or_else(crate::session::host_label, ToOwned::to_owned);
    let (Some(password), _) = PASSWORD.read()? else {
        return Err(Failure(
            CliError::new(
                Code::Failed,
                "the backup repository password is not kept here",
            )
            .hint("prune from the machine `erpc backup init` was first run on"),
        ));
    };
    let program = restic::ensure().await?;
    // A dry run changes nothing, so it does not make an admin key either.
    let (key_id, key_secret) = if dry_run {
        kept_admin_key()?.ok_or_else(|| {
            Failure(
                CliError::new(Code::Failed, "there is no backup admin access key here")
                    .hint("`erpc backup init` makes one"),
            )
        })?
    } else {
        let (client, token) = signed_in().await?;
        admin_key(&client, &token).await?
    };
    let admin = Credentials {
        key_id,
        key_secret,
        password: SecretString::from(password.to_string()),
    };
    if !dry_run {
        crate::interrupt::say(&format!(
            "Forget {name}'s snapshots beyond the last {daily} daily, {weekly} weekly and \
             {monthly} monthly ones, and delete the data only they held."
        ));
        crate::node_common::go_ahead(yes, "nothing was pruned")?;
    }
    let mut command = restic::command(&program, &admin);
    command.args([
        "forget",
        "--host",
        &name,
        "--keep-daily",
        &daily.to_string(),
        "--keep-weekly",
        &weekly.to_string(),
        "--keep-monthly",
        &monthly.to_string(),
        "--prune",
    ]);
    if dry_run {
        command.arg("--dry-run");
    }
    if json {
        command.arg("--json");
    }
    let status = restic::loud(command)?;
    if status.success() {
        Ok(Outcome::Done(String::new()))
    } else {
        Err("pruning failed (restic said why, above)".into())
    }
}

fn schedule(
    json: bool,
    every: crate::backup_schedule::Every,
    at: &str,
    paths: Vec<PathBuf>,
    exclude: Vec<String>,
) -> Done {
    use crate::backup_schedule::{Every, Plan};
    let at = crate::backup_schedule::parse_at(at).map_err(|e| CliError::new(Code::Usage, e))?;
    if every != Every::Off {
        Host::require()?;
        backup_excludes(paths.is_empty(), &exclude)?;
        if paths.is_empty() && !cfg!(target_os = "linux") {
            return Err(Failure(
                CliError::new(Code::Usage, "name what to back up")
                    .hint("for example `erpc backup schedule daily ~/Documents`"),
            ));
        }
    }
    // A newline or other control character would end the unit file's line
    // and start another.
    if paths
        .iter()
        .map(|p| p.display().to_string())
        .chain(exclude.iter().cloned())
        .any(|v| v.chars().any(char::is_control))
    {
        return Err(Failure(CliError::new(
            Code::Usage,
            "a path or an exclude holds a control character",
        )));
    }
    // Paths as the timer will see them: it does not start in this directory.
    let paths = paths
        .into_iter()
        .map(|p| std::path::absolute(&p).map_err(|e| format!("{}: {e}", p.display())))
        .collect::<Result<Vec<_>, _>>()?;
    let plan = Plan {
        // Where the program really is, so the unit does not run whatever a
        // link is later pointed at.
        program: std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|e| format!("could not tell where erpc is: {e}"))?,
        at,
        every,
        paths,
        exclude,
        home: std::env::home_dir().ok_or("no home directory")?,
        erpc_home: std::env::var_os("ERPC_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from),
    };
    let said = crate::backup_schedule::apply(&plan)?;
    Ok(done(
        json,
        &json!({ "every": format!("{every:?}").to_lowercase(), "at": format!("{:02}:{:02}", at.0, at.1) }),
        said,
    ))
}

fn password(json: bool, show: bool) -> Done {
    if !show {
        return Err(Failure(
            CliError::new(Code::Usage, "the password is printed only with --show")
                .hint("anyone who has it and can sign in to this account can read every backup"),
        ));
    }
    let (Some(password), kind) = PASSWORD.read()? else {
        return Err(
            "there is no backup repository password here; `erpc backup init` makes one".into(),
        );
    };
    Ok(done(
        json,
        &json!({ "password": password.as_str() }),
        format!(
            "{}\n\nThe backup repository password, kept in {}. Keep a copy away from this machine.",
            password.as_str(),
            PASSWORD.place(kind)
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(args: &[String]) -> Vec<&str> {
        args.chunks(2)
            .map(|pair| {
                assert_eq!(pair[0], "--exclude");
                pair[1].as_str()
            })
            .collect()
    }

    #[test]
    fn a_backup_never_carries_key_material() {
        let args = backup_excludes(false, &[]).expect("excludes");
        let patterns = pairs(&args);
        for wanted in [
            "/root/.ssh/id_*",
            "/home/*/**/*keypair*.json",
            "/home/*/.config/solana/id.json",
            "/Users/*/.erpc/backup.env",
            "/root/.erpc/state/credentials.toml*",
            "/etc/shadow",
            "/etc/ssh/ssh_host_*_key",
        ] {
            assert!(patterns.contains(&wanted), "{wanted} is not left out");
        }
        assert!(!patterns.contains(&"/proc/*"), "a named path is not /");
        let whole = backup_excludes(true, &[]).expect("excludes");
        assert!(pairs(&whole).contains(&"/proc/*"));
    }

    /// Runs the pinned restic, as `erpc backup init` installed it, over a
    /// tree of sample files and checks which ones a backup would carry.
    /// Ignored by default: it needs that restic and no network.
    /// `cargo test -p erpc --bin erpc -- --ignored restic_leaves_out`
    #[test]
    #[ignore = "needs the pinned restic in ~/.erpc/bin"]
    fn restic_leaves_out_key_material_at_any_depth() {
        let program = crate::session::beside_config(&format!("bin/restic-{}", restic::VERSION))
            .expect("config dir");
        assert!(program.is_file(), "run `erpc backup init` first");
        let dir = tempfile::tempdir().expect("dir");
        let home = dir.path().join("home/solv");
        let files = [
            ("validator-keypair.json", false),
            ("validator/vote-account-keypair.json", false),
            ("a/b/c/staked-identity.json", false),
            (".config/solana/id.json", false),
            (".ssh/id_ed25519", false),
            (".ssh/known_hosts", true),
            (".erpc/storage-key", false),
            ("notes/keypairs.txt", true),
            ("app/config.json", true),
        ];
        for (name, _) in files {
            let path = home.join(name);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, b"x").expect("write");
        }
        let homes = format!("{}/home/*", dir.path().display());
        let mut args: Vec<String> = Vec::new();
        for p in secret_patterns_in(&[&homes]) {
            args.push("--exclude".to_owned());
            args.push(p);
        }
        let repo = dir.path().join("repo");
        let run = |extra: &[&str]| {
            std::process::Command::new(&program)
                .env_clear()
                .env("RESTIC_REPOSITORY", &repo)
                .env("RESTIC_PASSWORD", "test-only")
                .env("RESTIC_CACHE_DIR", dir.path().join("cache"))
                .args(extra)
                .output()
                .expect("restic")
        };
        assert!(run(&["init"]).status.success());
        let mut backup = vec!["backup", "--dry-run", "-vv"];
        backup.extend(args.iter().map(String::as_str));
        let home_arg = home.display().to_string();
        backup.push(&home_arg);
        let out = run(&backup);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let said = String::from_utf8_lossy(&out.stdout);
        // A restore of part of the snapshot still leaves key material out.
        let full = run(&["backup", "-q", &home_arg]);
        assert!(full.status.success());
        let target = dir.path().join("restored");
        let mut restore = vec![
            "restore".to_owned(),
            format!("latest:{home_arg}"),
            "--target".to_owned(),
            target.display().to_string(),
        ];
        for p in secret_patterns_in(&[&homes]) {
            if let Some(p) = relative_to(&p, &home_arg) {
                restore.push("--exclude".to_owned());
                restore.push(p);
            }
        }
        let restore: Vec<&str> = restore.iter().map(String::as_str).collect();
        let out = run(&restore);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        for (name, kept) in files {
            assert_eq!(target.join(name).exists(), kept, "restored {name}");
        }
        for (name, kept) in files {
            let listed = said.lines().any(|l| {
                l.starts_with("new ")
                    && l.split_once(", saved")
                        .is_some_and(|(path, _)| path.ends_with(&format!("/{name}")))
            });
            assert_eq!(listed, kept, "{name}: kept {listed}, wanted {kept}\n{said}");
        }
    }

    #[test]
    fn an_exclude_cannot_take_key_material_back_in() {
        assert!(backup_excludes(false, &["!/root/.ssh/id_ed25519".to_owned()]).is_err());
        assert!(backup_excludes(false, &["  !x".to_owned()]).is_err());
        assert!(backup_excludes(false, &[String::new()]).is_err());
        let extra = backup_excludes(false, &["/var/cache/**".to_owned()]).expect("a path");
        assert_eq!(pairs(&extra).last(), Some(&"/var/cache/**"));
    }

    #[test]
    fn a_restore_leaves_the_system_identity_alone_unless_asked() {
        let default = restore_excludes(false, None);
        let default = pairs(&default);
        assert!(default.contains(&"/etc/machine-id"));
        assert!(default.contains(&"/root/.ssh/id_*"));
        let system = restore_excludes(true, None);
        let system = pairs(&system);
        assert!(!system.contains(&"/etc/machine-id"));
        assert!(
            system.contains(&"/root/.ssh/id_*"),
            "key material came back"
        );
    }

    #[test]
    fn a_pattern_is_written_again_under_a_restored_directory() {
        let cases = [
            (
                "/home/*/**/*keypair*.json",
                "/home/solv",
                Some("/**/*keypair*.json"),
            ),
            (
                "/home/*/**/*keypair*.json",
                "/home/solv/val/a",
                Some("/**/*keypair*.json"),
            ),
            ("/home/*/.ssh/id_*", "/home/solv", Some("/.ssh/id_*")),
            ("/home/*/.ssh/id_*", "/home/solv/.ssh", Some("/id_*")),
            ("/home/*/.ssh/id_*", "/etc", None),
            ("/etc/shadow", "/etc", Some("/shadow")),
            ("/etc/wireguard", "/etc/wireguard/peers", Some("/**")),
            (
                "/etc/ssh/ssh_host_*_key",
                "/etc/ssh",
                Some("/ssh_host_*_key"),
            ),
            ("/root/.erpc/storage-key", "/home/solv", None),
        ];
        for (pattern, dir, want) in cases {
            assert_eq!(
                relative_to(pattern, dir).as_deref(),
                want,
                "{pattern} under {dir}"
            );
        }
        for (path, want) in [
            ("/etc", Ok("/etc")),
            ("/home/solv/", Ok("/home/solv")),
            ("/home/solv/.", Err(())),
            ("/home/./solv", Err(())),
            ("/home//solv", Err(())),
            ("/home/../root", Err(())),
            ("/", Err(())),
            ("etc", Err(())),
        ] {
            assert_eq!(snapshot_dir(path).as_deref().map_err(drop), want, "{path}");
        }
        assert!(component_matches("ssh_host_*_key", "ssh_host_ed25519_key"));
        assert!(!component_matches(
            "ssh_host_*_key",
            "ssh_host_ed25519_key.pub"
        ));
        assert!(component_matches("*keypair*.json", "vote-keypair.json"));
    }

    #[test]
    fn a_part_restored_in_place_goes_back_into_its_own_directory() {
        let snapshot = Snapshot {
            id: "abcdef0123".to_owned(),
            short_id: "abcdef01".to_owned(),
            host: "node".to_owned(),
            time: String::new(),
        };
        let plan = |under, in_place, target: Option<&str>| {
            restore_plan(&snapshot, under, in_place, target.map(Path::new))
        };
        assert_eq!(
            plan(Some("/etc"), true, None),
            ("abcdef0123:/etc".to_owned(), PathBuf::from("/etc"))
        );
        assert_eq!(
            plan(None, true, None),
            ("abcdef0123".to_owned(), PathBuf::from("/"))
        );
        assert_eq!(
            plan(Some("/etc"), false, None),
            (
                "abcdef0123:/etc".to_owned(),
                PathBuf::from("erpc-restore-abcdef01")
            )
        );
        assert_eq!(
            plan(None, false, Some("/srv/r")),
            ("abcdef0123".to_owned(), PathBuf::from("/srv/r"))
        );
    }

    #[test]
    fn the_host_file_reads_back_what_was_written() {
        let host = Host {
            name: "node-1".to_owned(),
            credentials: Credentials {
                key_id: "erpcsk_TESTONLY".to_owned(),
                key_secret: SecretString::from("s3cret".to_owned()),
                password: SecretString::from("pa55".to_owned()),
            },
            restic_key: "abcdef01".to_owned(),
        };
        let back = Host::parse(&host.render()).expect("parses");
        assert_eq!(back.name, "node-1");
        assert_eq!(back.credentials.key_id, "erpcsk_TESTONLY");
        assert_eq!(back.credentials.key_secret.expose_secret(), "s3cret");
        assert_eq!(back.credentials.password.expose_secret(), "pa55");
        assert_eq!(back.restic_key, "abcdef01");
        assert!(Host::parse("RESTIC_REST_USERNAME=x\n").is_err());
    }

    #[test]
    fn the_current_key_is_the_one_restic_marks() {
        let listing = r#"[{"current":false,"id":"aaaa1111","hostName":"a"},{"current":true,"id":"bbbb2222","hostName":"b"}]"#;
        assert_eq!(current_key(listing).as_deref(), Some("bbbb2222"));
        assert_eq!(current_key(r#"[{"current":true,"id":"../x"}]"#), None);
        assert_eq!(current_key("not json"), None);
    }

    #[test]
    fn a_random_secret_is_64_hex_digits_and_new_each_time() {
        let a = random_secret().expect("random");
        let b = random_secret().expect("random");
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a.as_str(), b.as_str());
    }
}
