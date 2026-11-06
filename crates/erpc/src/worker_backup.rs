// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker backup`: a worker's state backed up daily from its server
//! to ERPC Global Storage, with restic.
//!
//! Set up from this machine, so the server never holds the erpc session,
//! the account's admin key or its master password:
//! - This machine makes the worker's own `append_only` access key and its
//!   own restic key, named for the worker and its server ([`Whose`]), with
//!   the account's admin key and master password
//!   ([`crate::backup::account`]).
//! - The server gets the pinned Linux restic, checked against its digest,
//!   and the credentials on standard input to the agent's `backup-setup`,
//!   which keeps them root-only and runs restic from a systemd timer over
//!   the worker's state ([`erpc_worker::server::backup_service`]).
//!
//! The account has one repository, and every restic key opens it. A
//! server taken over cannot delete snapshots, but it can read every
//! machine's, keeps the repository's key, and can add snapshots under
//! another machine's name; `on` says so before it asks. Revoking its
//! access key is what cuts it off: `off` does so first, whether or not the
//! server answers, and `erpc worker delete` once it goes ahead. Snapshots are restored from this machine with `erpc backup
//! restore --from-host <its name>`.

use core::fmt::Write as _;

use erpc_api::storage::{self as api, Permission};
use erpc_auth::AuthClient;
use std::path::PathBuf;

use erpc_ssh::worker::{Command as Worker, Digest, TimeOfDay, UnitId, Verb};
use erpc_ssh::{HostKey, RemoteCommand, Session, Target};
use erpc_worker::manifest::{Backup, Env};
use erpc_worker::server;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::backup::{self, Account};
use crate::commands::Outcome;
use crate::error::CliError;
use crate::node_common::go_ahead;
use crate::restic::{self, Credentials};
use crate::worker::{App, load_env};
use crate::worker_remote::{ctl, ctl_ok, done, failed, open, reach, target};

/// The longest access-key label user-api keeps.
const LABEL_MAX: usize = 64;

/// What to do about keys `off` or `delete` could not revoke.
fn by_hand() -> String {
    t!("worker_backup.by_hand")
}

/// The way out, for environment `env`, when user-api will not take a key
/// off that is gone.
pub(crate) fn stuck(env: &str) -> String {
    t!("worker_backup.stuck", env)
}

/// Two hints said as one: `first`, then `then`.
fn both(first: &str, then: &str) -> String {
    t!("worker_backup.both", first, then)
}

/// Whose backup: a worker, on one server. Worker ids are `<app>-<env>`, so
/// two apps, or one app moved to a new server, can share one; the tag,
/// from the server's pinned host key and the id, keeps their keys and
/// snapshots apart.
pub(crate) struct Whose {
    id: UnitId,
    tag: String,
}

impl Whose {
    pub(crate) fn new(id: UnitId, host_key: &HostKey) -> Self {
        let digest = Sha256::digest(format!("{}\n{}", host_key.to_openssh(), id.as_str()));
        let tag = digest[..4].iter().fold(String::new(), |mut tag, b| {
            let _ = write!(tag, "{b:02x}");
            tag
        });
        Self { id, tag }
    }

    /// The name its snapshots and restic key carry.
    fn host(&self) -> String {
        server::backup_host(self.id.as_str(), &self.tag)
    }

    /// The label of its access key.
    fn label(&self) -> String {
        label(&self.tag, self.id.as_str())
    }

    /// Whether `label` is the access key of a worker of this id on another
    /// server.
    fn elsewhere(&self, other: &str) -> bool {
        other
            .strip_prefix("erpc worker ")
            .and_then(|rest| rest.split_once(' '))
            .is_some_and(|(tag, _)| {
                tag != self.tag
                    && tag.len() == 8
                    && tag.bytes().all(|b| b.is_ascii_hexdigit())
                    && label(tag, self.id.as_str()) == other
            })
    }
}

/// `erpc worker <tag> <id>`, the id cut short to fit; the tag alone tells
/// keys apart.
fn label(tag: &str, id: &str) -> String {
    let mut label = format!("erpc worker {tag} {id}");
    // Ids and tags are ASCII, so this cuts between characters.
    label.truncate(LABEL_MAX);
    label
}

fn from(f: backup::Failure) -> CliError {
    f.0
}

/// The server's machine, from `uname`.
fn machine(session: &Session) -> Result<String, CliError> {
    let out = session
        .run(&RemoteCommand::Uname, None)
        .map_err(|e| failed(t!("worker_backup.machine.ask_failed", error = e)))?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .last()
        .map(ToOwned::to_owned)
        .ok_or_else(|| failed(t!("worker_backup.machine.unknown")))
}

/// The access keys to revoke, by number, from `keys` (number, label): the
/// one on record, listed or not, and any other labelled for `whose`, but
/// `keep`. Also how many belong to a worker of this id on another server,
/// which are left.
fn access_to_revoke(
    keys: &[(u64, Option<&str>)],
    whose: &Whose,
    recorded: Option<u64>,
    keep: Option<u64>,
) -> (Vec<u64>, usize) {
    let label = whose.label();
    let mut chosen = Vec::new();
    let mut elsewhere = 0;
    for (id, other) in keys {
        if Some(*id) == keep {
            continue;
        }
        if Some(*id) == recorded || *other == Some(label.as_str()) {
            chosen.push(*id);
        } else if other.is_some_and(|o| whose.elsewhere(o)) {
            elsewhere += 1;
        }
    }
    // A list that left it out does not keep it.
    if let Some(id) = recorded
        && Some(id) != keep
        && !chosen.contains(&id)
    {
        chosen.push(id);
    }
    (chosen, elsewhere)
}

/// Whether user-api said it has no such key: one revoked before.
fn not_found(e: &api::StorageError) -> bool {
    matches!(
        e,
        api::StorageError::Api(
            erpc_api::ApiError::Status(404) | erpc_api::ApiError::Refused { status: 404, .. }
        )
    )
}

/// What user-api answered to revoking a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// It revoked it.
    Revoked,
    /// It has no such key.
    NoSuchKey,
}

/// What became of the access keys revoking was asked for: from user-api's
/// answer for each (`asked`) and the list of keys read after (`after`, when
/// it could be read). A key the list still shows is left; one it does not
/// show is gone. Without the list, a key is gone only when user-api said
/// it revoked it: a "no such key" alone, which a wrong route answers too,
/// is not taken as gone. Says how many were revoked, and what is left.
fn settle(asked: &[(u64, Result<Asked, String>)], after: Option<&[u64]>) -> (usize, Vec<String>) {
    let mut revoked = 0;
    let mut left = Vec::new();
    for (id, answer) in asked {
        match (answer, after) {
            // Said with whether the list still shows it: a key it no longer
            // shows, refused again and again, is what [`stuck`] is for.
            (Err(e), Some(list)) if !list.contains(id) => {
                left.push(t!("worker_backup.left.no_longer_listed", reason = e));
            }
            (Err(e), _) => left.push(e.clone()),
            (Ok(_), Some(list)) if list.contains(id) => {
                left.push(t!("worker_backup.left.still_listed", id));
            }
            (Ok(Asked::Revoked), _) => revoked += 1,
            (Ok(Asked::NoSuchKey), Some(_)) => {}
            (Ok(Asked::NoSuchKey), None) => left.push(t!("worker_backup.left.unchecked", id)),
        }
    }
    (revoked, left)
}

/// Revokes the access keys `ids`, then reads the list to see them gone
/// ([`settle`]).
async fn revoke_all(
    client: &AuthClient,
    token: &SecretString,
    ids: &[u64],
) -> (usize, Vec<String>) {
    if ids.is_empty() {
        return (0, Vec::new());
    }
    let mut asked = Vec::new();
    for &id in ids {
        let answer = match api::revoke_access_key(client, token, id).await {
            Ok(()) => Ok(Asked::Revoked),
            Err(e) if not_found(&e) => Ok(Asked::NoSuchKey),
            Err(e) => Err(t!("worker_backup.left.access_key", id, error = e)),
        };
        asked.push((id, answer));
    }
    // A list with a key of number 0 lost its numbers; it is not read.
    let after: Option<Vec<u64>> = api::access_keys(client, token)
        .await
        .ok()
        .map(|keys| keys.iter().map(|k| k.id).collect::<Vec<u64>>())
        .filter(|ids| !ids.contains(&0));
    settle(&asked, after.as_deref())
}

/// The restic keys to remove, from `restic key list --json`: the one on
/// record and any other named `host`, but `keep`.
fn restic_to_remove(
    listing: &[Value],
    host: &str,
    recorded: Option<&str>,
    keep: &str,
) -> Vec<String> {
    listing
        .iter()
        .filter(|k| {
            let id = k["id"].as_str();
            id != Some(keep) && (id == recorded || k["hostName"].as_str() == Some(host))
        })
        .filter_map(|k| k["id"].as_str())
        .map(ToOwned::to_owned)
        .collect()
}

/// `restic key list --json`.
fn restic_listing(program: &std::path::Path, admin: &Credentials) -> Result<Vec<Value>, String> {
    let mut command = restic::command(program, admin);
    command.args(["key", "list", "--json"]);
    let ran = restic::quiet(command)?;
    if !ran.status.success() {
        return Err(t!(
            "worker_backup.restic.list_failed",
            reason = ran.reason()
        ));
    }
    serde_json::from_str(&ran.stdout)
        .map_err(|e| t!("worker_backup.restic.list_unreadable", error = e))
}

/// The account's admin key and master password, when this machine keeps
/// them.
fn kept_admin() -> Result<Option<Credentials>, String> {
    let key = backup::kept_admin_key().map_err(|f| f.0.message)?;
    let (password, _) = backup::PASSWORD.read()?;
    Ok(key
        .zip(password)
        .map(|((key_id, key_secret), password)| Credentials {
            key_id,
            key_secret,
            password: SecretString::from(password.to_string()),
        }))
}

/// What became of a worker's backup keys.
#[derive(Default)]
struct Revoked {
    /// Access keys revoked.
    access: usize,
    /// Restic keys removed.
    restic: usize,
    /// Access keys of a worker of the same id on another server, left.
    elsewhere: usize,
    /// Access keys, or the server's credentials, that could not be
    /// revoked or removed, and why: these still let the server in.
    left: Vec<String>,
    /// Restic keys that could not be removed, and why. The server knows
    /// the repository's key anyway; without its access key it cannot
    /// reach the repository, so these do not hold anything up.
    restic_left: Vec<String>,
}

impl Revoked {
    /// Its access keys revoked: the one on record and any labelled for it,
    /// but `keep`.
    async fn access(
        &mut self,
        client: &AuthClient,
        token: &SecretString,
        whose: &Whose,
        recorded: Option<u64>,
        keep: Option<u64>,
    ) {
        let keys = match api::access_keys(client, token).await {
            Ok(keys) => keys,
            Err(e) => {
                // The one on record is revoked all the same; the ones a lost
                // record would leave cannot be looked for.
                let on_record: Vec<u64> = recorded
                    .filter(|id| Some(*id) != keep)
                    .into_iter()
                    .collect();
                let (revoked, left) = revoke_all(client, token, &on_record).await;
                self.access += revoked;
                self.left.extend(left);
                self.left.push(t!(
                    "worker_backup.left.not_looked_for",
                    label = whose.label(),
                    error = e
                ));
                return;
            }
        };
        let listed: Vec<(u64, Option<&str>)> =
            keys.iter().map(|k| (k.id, k.label.as_deref())).collect();
        let (chosen, elsewhere) = access_to_revoke(&listed, whose, recorded, keep);
        self.elsewhere += elsewhere;
        let (revoked, left) = revoke_all(client, token, &chosen).await;
        self.access += revoked;
        self.left.extend(left);
    }

    /// Its access keys revoked, signed in first.
    async fn access_signed_in(&mut self, whose: &Whose, recorded: Option<u64>) {
        match backup::signed_in().await {
            Ok((client, token)) => self.access(&client, &token, whose, recorded, None).await,
            Err(f) => self.left.push(t!(
                "worker_backup.left.not_revoked_label",
                label = whose.label(),
                reason = f.0.message
            )),
        }
    }

    /// Its restic keys removed: the one on record and any named for it, but
    /// `keep`.
    fn restic(
        &mut self,
        program: &std::path::Path,
        admin: &Credentials,
        host: &str,
        recorded: Option<&str>,
        keep: &str,
    ) {
        let listing = match restic_listing(program, admin) {
            Ok(listing) => listing,
            Err(e) => {
                self.restic_left
                    .push(t!("worker_backup.restic.its_key", host, error = e));
                return;
            }
        };
        for key in restic_to_remove(&listing, host, recorded, keep) {
            match backup::remove_restic_key(program, admin, &key) {
                Ok(()) => self.restic += 1,
                Err(e) => {
                    self.restic_left
                        .push(t!("worker_backup.restic.key", key, host, error = e));
                }
            }
        }
    }

    /// Its restic keys removed, with the account's secrets this machine
    /// keeps.
    async fn restic_kept(&mut self, host: &str, recorded: Option<&str>) {
        let admin = match kept_admin() {
            Ok(Some(admin)) => admin,
            Ok(None) => {
                self.restic_left
                    .push(t!("worker_backup.restic.no_admin", host));
                return;
            }
            Err(e) => {
                self.restic_left
                    .push(t!("worker_backup.restic.its_key", host, error = e));
                return;
            }
        };
        match restic::ensure().await {
            Ok(program) => self.restic(&program, &admin, host, recorded, ""),
            Err(e) => self
                .restic_left
                .push(t!("worker_backup.restic.its_key", host, error = e)),
        }
    }

    /// The lines that say what is left.
    fn lines(&self, id: &UnitId) -> Vec<String> {
        let mut lines: Vec<String> = self
            .left
            .iter()
            .map(|what| t!("worker_backup.left.line", what))
            .collect();
        lines.extend(
            self.restic_left
                .iter()
                .map(|what| t!("worker_backup.left.kept", what)),
        );
        if self.elsewhere > 0 {
            lines.push(tn!(
                "worker_backup.left.elsewhere",
                self.elsewhere,
                id = id.as_str()
            ));
        }
        lines
    }
}

/// The access keys `delete` revokes: the one on record, listed or not,
/// since one revoked before settles as gone once the list no longer shows
/// it ([`settle`]); and any labelled for
/// the worker on this server, which a record lost would leave out.
fn delete_revokes(
    listed: &[(u64, Option<&str>)],
    whose: Option<&Whose>,
    recorded: Option<u64>,
) -> Vec<u64> {
    match whose {
        Some(w) => access_to_revoke(listed, w, recorded, None).0,
        None => recorded.into_iter().collect(),
    }
}

/// `erpc worker delete`'s part: the worker's backup keys revoked, the ones
/// on record (`keys`) and any labelled for it on the server whose host key
/// is `host_key`. Says what was done, or, when an access key is not
/// revoked, what is left; a restic key that stays is said, and holds
/// nothing up. Without a record, keys are looked for only when a session
/// can list them, so a worker that never had backups is not held up.
pub(crate) async fn forget(
    id: &UnitId,
    host_key: Option<&HostKey>,
    keys: Option<&Backup>,
) -> Result<Vec<String>, Vec<String>> {
    let whose = host_key.map(|k| Whose::new(id.clone(), k));
    let recorded = keys.map(|k| k.access_key);
    let mut gone = Revoked::default();
    let mut said = Vec::new();
    match backup::signed_in().await {
        Err(f) => match recorded {
            Some(n) => gone.left.push(t!(
                "worker_backup.left.not_revoked",
                id = n,
                reason = f.0.message
            )),
            None => return Ok(Vec::new()),
        },
        Ok((client, token)) => {
            let listed = match api::access_keys(&client, &token).await {
                Ok(listed) => listed,
                Err(e) if recorded.is_some() => {
                    said.push(t!("worker_backup.forget.not_looked_for", error = e));
                    Vec::new()
                }
                Err(_) => return Ok(Vec::new()),
            };
            let pairs: Vec<(u64, Option<&str>)> =
                listed.iter().map(|k| (k.id, k.label.as_deref())).collect();
            let chosen = delete_revokes(&pairs, whose.as_ref(), recorded);
            let (revoked, left) = revoke_all(&client, &token, &chosen).await;
            gone.access += revoked;
            gone.left.extend(left);
        }
    }
    let host = keys
        .map(|k| k.host.clone())
        .or_else(|| whose.as_ref().map(Whose::host));
    if let Some(host) = host
        && (keys.is_some() || gone.access > 0)
    {
        gone.restic_kept(&host, keys.map(|k| k.restic_key.as_str()))
            .await;
        if gone.access > 0 {
            said.insert(0, t!("worker_backup.forget.revoked", host));
        }
    }
    let notes = gone
        .restic_left
        .iter()
        .map(|what| t!("worker_backup.left.kept", what));
    if gone.left.is_empty() {
        said.extend(notes);
        Ok(said)
    } else {
        Err(gone.left.into_iter().chain(notes).collect())
    }
}

/// The credentials the server gets, written into room made first, so no
/// copy is left behind unwiped.
fn credentials(key_id: &str, key_secret: &str, password: &str, host: &str) -> Zeroizing<String> {
    let parts = [
        ("RESTIC_REPOSITORY", restic::REPOSITORY),
        ("RESTIC_REST_USERNAME", key_id),
        ("RESTIC_REST_PASSWORD", key_secret),
        ("RESTIC_PASSWORD", password),
        ("RESTIC_HOST", host),
    ];
    let room = parts.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
    let mut env = Zeroizing::new(String::with_capacity(room));
    for (key, value) in parts {
        env.push_str(key);
        env.push('=');
        env.push_str(value);
        env.push('\n');
    }
    env
}

/// The worker, and its environment as erpc.toml or its item has it. Its
/// keys are named from the pinned host key alone, so `off` revokes them
/// before it needs anything to reach the server with.
struct Place {
    path: PathBuf,
    app_name: String,
    env: Env,
    whose: Whose,
    /// What a deploy puts on the server beside the app, whose data a
    /// backup leaves out.
    services: erpc_worker::manifest::Services,
}

impl Place {
    fn of(app: &App) -> Result<Self, CliError> {
        let (path, m) = load_env(app)?;
        let env = crate::worker::env_of(&m, app)?.clone();
        let host_key = env
            .host_key
            .as_deref()
            .ok_or_else(|| failed(t!("worker_backup.no_host_key", env = app.env)))
            .and_then(|k| HostKey::parse(k).map_err(|e| failed(e.to_string())))?;
        let id = UnitId::new(&m.unit_id(&app.env)).map_err(failed)?;
        Ok(Self {
            path,
            services: m.services,
            app_name: m.name,
            env,
            whose: Whose::new(id, &host_key),
        })
    }

    /// The server, to reach it with.
    fn server(&self, app: &App) -> Result<Target, CliError> {
        target(app, &self.env)
    }

    /// Keeps `backup` on record for the environment.
    fn record(&self, app: &App, backup: Option<Backup>) -> Result<(), String> {
        let env = Env {
            backup,
            ..self.env.clone()
        };
        crate::worker::EnvRecord {
            path: &self.path,
            app: &self.app_name,
            env: &app.env,
        }
        .save(&env, None)
    }
}

/// What to keep of the repository password, said where it was made or
/// first kept, whether or not the rest of `on` goes through.
fn custody(made_repository: bool, kind: erpc_auth::store::StoreKind) -> String {
    let place = backup::PASSWORD.place(kind);
    if made_repository {
        t!("worker_backup.custody.made", place)
    } else {
        t!("worker_backup.custody.kept", place)
    }
}

/// Revokes what `on` made when it cannot go on, and says what it could not.
async fn undo(
    client: &AuthClient,
    token: &SecretString,
    access_key: u64,
    restic_key: Option<(&std::path::Path, &Credentials, &str)>,
    e: CliError,
) -> CliError {
    let mut left = Vec::new();
    if let Some((program, admin, key)) = restic_key
        && let Err(why) = backup::remove_restic_key(program, admin, key)
    {
        left.push(why);
    }
    left.extend(revoke_all(client, token, &[access_key]).await.1);
    if left.is_empty() {
        e
    } else {
        let more = t!(
            "worker_backup.undo.left",
            reasons = left.join("; "),
            by_hand = by_hand()
        );
        let hint = match e.hint.clone() {
            Some(h) => both(&h, &more),
            None => more,
        };
        e.hint(hint)
    }
}

/// `erpc worker backup on`.
#[allow(clippy::too_many_lines)] // one setup, read top to bottom
pub(crate) async fn on(json: bool, app: &App, at: &str, yes: bool) -> Outcome {
    let run = async || -> Result<Outcome, CliError> {
        let at = TimeOfDay::new(at).map_err(|e| CliError::new(crate::error::Code::Usage, e))?;
        let place = Place::of(app)?;
        let whose = &place.whose;
        let id = &whose.id;
        let host = whose.host();
        crate::interrupt::say(&t!(
            "worker_backup.on.ask",
            id = id.as_str(),
            at = at.as_str(),
            host
        ));
        // Redis and PostgreSQL keep their data outside the app's state
        // directory: a backup of this bot without them is an empty one.
        let services: Vec<&str> = place
            .services
            .vars()
            .iter()
            .map(|(var, _)| {
                if *var == "REDIS_URL" {
                    "Redis"
                } else {
                    "PostgreSQL"
                }
            })
            .collect();
        if !services.is_empty() {
            crate::interrupt::say(&t!(
                "worker_backup.on.services_excluded",
                names = services.join(" and ")
            ));
        }
        go_ahead(yes, &t!("worker_backup.nothing_changed"))?;

        // The server first, so a server that cannot be reached leaves the
        // account as it was. restic on it, checked as the agent is.
        let session = open(&place.server(app)?)?;
        let machine = machine(&session)?;
        let (bytes, digest) = restic::linux_program(&machine).await.map_err(failed)?;
        let staged = format!("{}/restic/restic", crate::worker_deploy::UPLOADS);
        crate::worker_deploy::upload(&session, &staged, &bytes)?;
        session
            .run(
                &RemoteCommand::Worker(Worker::InstallRestic {
                    staged: erpc_ssh::RemotePath::new(&staged)
                        .map_err(|e| failed(e.to_string()))?,
                    sha256: Digest::new(digest).map_err(failed)?,
                }),
                None,
            )
            .map_err(|e| failed(t!("worker_backup.on.install_failed", error = e)))?;

        let program = restic::ensure().await.map_err(failed)?;
        let (client, token) = backup::signed_in().await.map_err(from)?;
        let Account {
            admin,
            kind,
            made_repository,
            kept_password,
        } = backup::account(&program, &client, &token, None)
            .await
            .map_err(from)?;
        // Said now: what follows can fail, and the password is kept anyway.
        // A repository made now, with a password kept by an `on` that
        // failed before, is said too.
        let told = kept_password || made_repository;
        if told {
            crate::interrupt::say(&custody(made_repository, kind));
        }

        // What an earlier `on` for this worker on this server made, revoked
        // before anything new is made: a key replaced and still live would
        // not be on record, and `delete` revokes only what is.
        let before = place.env.backup.clone();
        let mut old = Revoked::default();
        old.access(
            &client,
            &token,
            whose,
            before.as_ref().map(|b| b.access_key),
            None,
        )
        .await;
        if !old.left.is_empty() {
            let hint = if old.access > 0 {
                t!("worker_backup.on.old_partly_revoked", by_hand = by_hand())
            } else {
                by_hand()
            };
            return Err(failed(t!(
                "worker_backup.on.old_left",
                reasons = old.left.join("; ")
            ))
            .hint(hint));
        }
        old.restic(
            &program,
            &admin,
            &host,
            before.as_ref().map(|b| b.restic_key.as_str()),
            "",
        );
        // From here, a failure leaves the worker without a backup until `on`
        // goes through: its earlier keys are revoked.
        let replaced = before.is_some() || old.access > 0;
        let set_up: Result<Outcome, CliError> = async {
            // The worker's own keys. The access key is found again by its
            // number, and its label checked, since `off` relies on both.
            let made = api::create_access_key(
                &client,
                &token,
                Some(&whose.label()),
                Permission::AppendOnly,
            )
            .await
            .map_err(crate::storage::refused)?;
            if made.key.id == 0 {
                return Err(failed(t!("worker_backup.on.no_number")));
            }
            let labelled = api::access_keys(&client, &token)
                .await
                .map_err(|e| e.to_string())
                .and_then(|keys| {
                    keys.iter()
                        .find(|k| k.id == made.key.id)
                        .map(|k| k.label.as_deref() == Some(whose.label().as_str()))
                        .ok_or_else(|| t!("worker_backup.on.not_in_list"))
                });
            match labelled {
                Ok(true) => {}
                Ok(false) => {
                    let e = failed(t!("worker_backup.on.label_lost"));
                    return Err(undo(&client, &token, made.key.id, None, e).await);
                }
                Err(why) => {
                    let e = failed(t!("worker_backup.on.unchecked", why));
                    return Err(undo(&client, &token, made.key.id, None, e).await);
                }
            }
            let password = backup::random_secret().map_err(failed)?;
            let restic_key = match backup::add_restic_key(&program, &admin, &host, &password) {
                Ok(key) => key,
                Err(e) => return Err(undo(&client, &token, made.key.id, None, failed(e)).await),
            };
            let made_keys = Some((program.as_path(), &admin, restic_key.as_str()));
            // On record before the server gets them, so a key that lets the
            // server in is never off the record.
            if let Err(why) = place.record(
                app,
                Some(Backup {
                    access_key: made.key.id,
                    restic_key: restic_key.clone(),
                    host: host.clone(),
                }),
            ) {
                let e = failed(t!("worker_backup.on.not_recorded", why));
                return Err(undo(&client, &token, made.key.id, made_keys, e).await);
            }
            let env = credentials(
                &made.key.access_key_id,
                made.secret.expose_secret(),
                &password,
                &host,
            );
            // A server that fails the setup keeps the credentials it had, which
            // were revoked above: the backup stays off until `on` runs again.
            let set = if server::backup_env_ok(id.as_str(), &env) {
                ctl_ok(
                    &session,
                    id,
                    Verb::BackupSetup(at.clone()),
                    Some(env.as_bytes()),
                )
                .map(|_| ())
            } else {
                Err(failed(t!("worker_backup.on.bad_credentials")))
            };
            // The record keeps the new keys, revoked or not: `off` and `delete`
            // revoke them again, and a key revoked before settles as gone once
            // the list no longer shows it.
            if let Err(e) = set {
                return Err(undo(&client, &token, made.key.id, made_keys, e).await);
            }
            let kept_in = if place.env.inventory.is_some() {
                t!("worker_backup.on.kept_in_item")
            } else {
                t!("worker_backup.on.kept_in_toml")
            };

            let mut text = t!(
                "worker_backup.on.done",
                id = id.as_str(),
                at = at.as_str(),
                host,
                scope = app.scope(),
                source = server::backup_source(id.as_str()).display(),
                env = app.env,
                kept_in,
                place = backup::PASSWORD.place(kind),
            );
            for line in old.lines(id) {
                text.push('\n');
                text.push_str(&line);
            }
            Ok(done(
                json,
                &json!({
                    "worker": id.as_str(),
                    "on": true,
                    "at": at.as_str(),
                    "host": host,
                    "repository": if made_repository { "made" } else { "ready" },
                    "password_kept_now": kept_password,
                    "custody_said": told,
                    "kept": old.restic_left,
                }),
                text,
            ))
        }
        .await;
        set_up.map_err(|e| {
            if !replaced {
                return e;
            }
            let off = t!("worker_backup.on.replaced");
            let hint = match e.hint.clone() {
                Some(h) => both(&off, &h),
                None => off,
            };
            e.hint(hint)
        })
    };
    run().await.unwrap_or_else(Into::into)
}

/// `erpc worker backup off`: the keys revoked first, whether or not the
/// server answers, since they are what lets it in; then the timer and the
/// credentials off the server.
pub(crate) async fn off(json: bool, app: &App, yes: bool) -> Outcome {
    let run = async || -> Result<Outcome, CliError> {
        let place = Place::of(app)?;
        let whose = &place.whose;
        let recorded = place.env.backup.clone();
        let host = recorded
            .as_ref()
            .map_or_else(|| whose.host(), |b| b.host.clone());
        crate::interrupt::say(&t!("worker_backup.off.ask", id = whose.id.as_str(), host));
        go_ahead(yes, &t!("worker_backup.nothing_changed"))?;
        let mut gone = Revoked::default();
        gone.access_signed_in(whose, recorded.as_ref().map(|b| b.access_key))
            .await;
        gone.restic_kept(&host, recorded.as_ref().map(|b| b.restic_key.as_str()))
            .await;
        let removed = place
            .server(app)
            .and_then(|t| open(&t))
            .and_then(|s| ctl_ok(&s, &whose.id, Verb::BackupRemove, None));
        match &removed {
            Err(e) => gone
                .left
                .push(t!("worker_backup.off.server_left", error = e.message)),
            // The server had a backup, none is on record, and no key of it
            // was found by label: it is not called done. A key on record
            // and not listed was revoked before.
            Ok(answer)
                if answer["removed"].as_bool() == Some(true)
                    && recorded.is_none()
                    && gone.access == 0
                    && gone.left.is_empty() =>
            {
                gone.left
                    .push(t!("worker_backup.off.unfound", label = whose.label()));
            }
            Ok(_) => {}
        }
        if gone.left.is_empty()
            && recorded.is_some()
            && let Err(e) = place.record(app, None)
        {
            gone.left
                .push(t!("worker_backup.off.still_recorded", error = e));
        }
        let mut text = t!(
            "worker_backup.off.summary",
            id = whose.id.as_str(),
            access = tn!("worker_backup.off.access", gone.access),
            restic = tn!("worker_backup.off.restic", gone.restic),
            server = if removed.is_ok() {
                t!("worker_backup.off.server_off")
            } else {
                String::new()
            }
        );
        for line in gone.lines(&whose.id) {
            text.push_str("\n  ");
            text.push_str(&line);
        }
        let answer = json!({
            "worker": whose.id.as_str(),
            "on": removed.is_err(),
            "revoked": gone.access,
            "removed": gone.restic,
            "server": removed.is_ok(),
            "left": gone.left,
            "kept": gone.restic_left,
        });
        if gone.left.is_empty() {
            Ok(done(json, &answer, text))
        } else {
            Err(failed(text)
                .hint(t!(
                    "worker_backup.off.hint",
                    by_hand = by_hand(),
                    scope = app.scope(),
                    stuck = stuck(&app.env)
                ))
                .details(answer))
        }
    };
    run().await.unwrap_or_else(Into::into)
}

/// What the server says about the backup, as lines.
fn describe(answer: &Value) -> String {
    if answer["on"].as_bool() != Some(true) {
        return t!("worker_backup.status.off");
    }
    let last = &answer["last"];
    // systemd says a unit that has not run since boot succeeded with 0;
    // only the empty time of its exit tells it apart. A start that failed
    // before restic ran has no exit time either, and says so in its result.
    let ran = last["at"].as_str().is_some_and(|a| !a.is_empty());
    let result = last["result"].as_str();
    let outcome = match (result, last["exit"].as_i64()) {
        _ if !ran && matches!(result, Some("success" | "") | None) => {
            t!("worker_backup.status.never")
        }
        (_, None) | (Some(""), _) => t!("worker_backup.status.unknown"),
        (Some("success"), Some(0)) => t!("worker_backup.status.succeeded"),
        (Some("success"), Some(3)) => t!("worker_backup.status.partly"),
        (result, exit) => t!(
            "worker_backup.status.failed",
            result = result.unwrap_or("?"),
            exit = exit.unwrap_or(-1)
        ),
    };
    t!(
        "worker_backup.status.on",
        next = crate::storage::clean(answer["next"].as_str().unwrap_or("?")),
        outcome,
        at = last["at"]
            .as_str()
            .filter(|a| !a.is_empty())
            .map(|a| t!("worker_backup.status.at", at = crate::storage::clean(a)))
            .unwrap_or_default()
    )
}

/// `erpc worker backup status`.
pub(crate) fn status(json: bool, app: &App) -> Outcome {
    let run = || -> Result<Outcome, CliError> {
        let (_, id, session) = reach(app)?;
        let answer = ctl_ok(&session, &id, Verb::BackupStatus, None)?;
        let text = t!(
            "worker_backup.status.line",
            id = id.as_str(),
            state = describe(&answer)
        );
        Ok(done(json, &answer, text))
    };
    run().unwrap_or_else(Into::into)
}

/// `erpc worker backup now`.
pub(crate) fn now(json: bool, app: &App) -> Outcome {
    let run = || -> Result<Outcome, CliError> {
        let (_, id, session) = reach(app)?;
        crate::interrupt::say(&t!("worker_backup.now.running", id = id.as_str()));
        let answer = ctl(&session, &id, Verb::BackupNow, None)?;
        if answer["ok"].as_bool() == Some(false) && answer["on"].is_null() {
            return Err(failed(answer["error"].as_str().map_or_else(
                || t!("worker_backup.now.refused"),
                ToOwned::to_owned,
            )));
        }
        let text = t!(
            "worker_backup.status.line",
            id = id.as_str(),
            state = describe(&answer)
        );
        if answer["ok"].as_bool() == Some(false) {
            return Err(failed(t!(
                "worker_backup.now.failed",
                text,
                unit = server::backup_service_name(id.as_str())
            )));
        }
        Ok(done(json, &answer, text))
    };
    run().unwrap_or_else(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> HostKey {
        // ssh-ed25519 wire form: string "ssh-ed25519", string <32 bytes>.
        let mut blob = vec![0, 0, 0, 11];
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&[0, 0, 0, 32]);
        blob.extend_from_slice(&[n; 32]);
        let text = format!("ssh-ed25519 {}", base64(&blob));
        HostKey::parse(&text).expect("key")
    }

    fn base64(bytes: &[u8]) -> String {
        const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(ABC[(n >> (18 - 6 * i)) as usize & 63]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn a_label_fits_for_the_longest_worker_id() {
        let id = UnitId::new(&format!("a{}", "b".repeat(48))).expect("id");
        let whose = Whose::new(id, &key(1));
        assert_eq!(whose.label().len(), LABEL_MAX);
        assert!(
            whose
                .label()
                .starts_with(&format!("erpc worker {} a", whose.tag))
        );
    }

    #[test]
    fn workers_of_one_id_on_two_servers_are_told_apart() {
        let id = UnitId::new("bot-default").expect("id");
        let here = Whose::new(id.clone(), &key(1));
        let there = Whose::new(id, &key(2));
        assert_ne!(here.tag, there.tag);
        assert_ne!(here.host(), there.host());
        assert!(server::is_backup_host("bot-default", &here.host()));
        assert!(here.elsewhere(&there.label()));
        assert!(!here.elsewhere(&here.label()));
        let other_app = Whose::new(UnitId::new("bot-prod").expect("id"), &key(2));
        assert!(!here.elsewhere(&other_app.label()));
        assert!(!here.elsewhere("erpc backup my-mac"));
        // The same worker on the same server, always the same.
        let again = Whose::new(UnitId::new("bot-default").expect("id"), &key(1));
        assert_eq!(again.label(), here.label());
    }

    #[test]
    fn off_revokes_the_key_on_record_and_its_own_by_label_only() {
        let id = UnitId::new("bot-default").expect("id");
        let here = Whose::new(id.clone(), &key(1));
        let there = Whose::new(id, &key(2));
        let (mine, theirs, mac) = (here.label(), there.label(), "erpc backup my-mac".to_owned());
        let keys = [
            (1, Some(mine.as_str())),
            (2, Some(theirs.as_str())),
            (3, Some(mac.as_str())),
            (4, None),
            (5, Some(mine.as_str())),
        ];
        assert_eq!(access_to_revoke(&keys, &here, None, None), (vec![1, 5], 1));
        // The one on record, whatever its label; and the new one kept.
        assert_eq!(
            access_to_revoke(&keys, &here, Some(4), Some(5)),
            (vec![1, 4], 1)
        );
        // On record and not listed: asked anyway; the new one is not.
        assert_eq!(access_to_revoke(&[], &here, Some(4), None), (vec![4], 0));
        assert_eq!(access_to_revoke(&[], &here, Some(4), Some(4)), (vec![], 0));

        let listing = vec![
            json!({ "id": "aa", "hostName": here.host() }),
            json!({ "id": "bb", "hostName": there.host() }),
            json!({ "id": "cc", "hostName": "my-mac" }),
            json!({ "id": "dd", "hostName": here.host() }),
        ];
        assert_eq!(restic_to_remove(&listing, &here.host(), None, "dd"), ["aa"]);
        assert_eq!(
            restic_to_remove(&listing, &here.host(), Some("cc"), ""),
            ["aa", "cc", "dd"]
        );
    }

    #[test]
    fn delete_revokes_the_key_on_record_even_unlisted_and_its_own_by_label() {
        let here = Whose::new(UnitId::new("bot-default").expect("id"), &key(1));
        let there = Whose::new(UnitId::new("bot-default").expect("id"), &key(2));
        let (mine, theirs) = (here.label(), there.label());
        let keys = [(1, Some(mine.as_str())), (2, Some(theirs.as_str()))];
        assert_eq!(delete_revokes(&keys, Some(&here), None), [1]);
        // On record and not listed: asked anyway.
        assert_eq!(delete_revokes(&keys, Some(&here), Some(7)), [1, 7]);
        assert_eq!(delete_revokes(&keys, Some(&here), Some(1)), [1]);
        // No host key: the record only.
        assert_eq!(delete_revokes(&keys, None, Some(7)), [7]);
        assert!(delete_revokes(&keys, None, None).is_empty());
    }

    #[test]
    fn a_key_is_gone_only_when_the_list_after_does_not_show_it() {
        let asked = [
            (1, Ok(Asked::Revoked)),
            (2, Ok(Asked::NoSuchKey)),
            (3, Err("access key 3: refused".to_owned())),
            (4, Ok(Asked::Revoked)),
            (5, Ok(Asked::NoSuchKey)),
        ];
        // The list after shows 4 and 5: whatever user-api said, they are
        // left, a "no such key" for a listed key too.
        let (revoked, left) = settle(&asked, Some(&[4, 5, 9]));
        assert_eq!(revoked, 1);
        assert_eq!(left.len(), 3);
        assert_eq!(left[0], "access key 3: refused (no longer listed)");
        assert!(left[1].contains("access key 4: still listed"));
        assert!(left[2].contains("access key 5: still listed"));
        // No list after: a "no such key" is not believed.
        let (revoked, left) = settle(&asked, None);
        assert_eq!(revoked, 2);
        assert!(left.iter().any(|l| l.starts_with("access key 2:")));
        assert!(settle(&[], None).1.is_empty());
    }

    #[test]
    fn only_a_key_user_api_does_not_have_counts_as_revoked_before() {
        use erpc_api::ApiError;
        let gone = api::StorageError::Api(ApiError::Status(404));
        let refused = api::StorageError::Api(ApiError::Refused {
            status: 404,
            message: "no such key".to_owned(),
        });
        assert!(not_found(&gone) && not_found(&refused));
        for other in [
            api::StorageError::Api(ApiError::Status(500)),
            api::StorageError::Api(ApiError::Unauthorized),
            api::StorageError::Api(ApiError::Refused {
                status: 403,
                message: "forbidden".to_owned(),
            }),
        ] {
            assert!(!not_found(&other), "{other}");
        }
    }

    #[test]
    fn the_server_and_this_machine_install_restic_at_one_path() {
        assert_eq!(erpc_ssh::worker::RESTIC, server::RESTIC_PATH);
    }

    #[test]
    fn the_credentials_are_what_the_server_takes() {
        let id = UnitId::new("bot-default").expect("id");
        let whose = Whose::new(id, &key(1));
        let env = credentials("erpcsk_TESTONLY", "abc-DEF_123", "0123abcd", &whose.host());
        assert!(server::backup_env_ok("bot-default", &env));
        assert_eq!(env.len(), env.capacity());
    }

    #[test]
    fn the_status_reads_as_a_person_would_say_it() {
        assert_eq!(describe(&json!({ "ok": true, "on": false })), "off");
        let ok = json!({ "on": true, "next": "Fri 2026-10-30 03:12:00 UTC",
                         "last": { "result": "success", "exit": 0, "at": "Thu 2026-10-29 03:20:01 UTC" } });
        assert_eq!(
            describe(&ok),
            "on, next run Fri 2026-10-30 03:12:00 UTC\n  last run succeeded, at Thu 2026-10-29 03:20:01 UTC"
        );
        // What systemd says of a unit that has not run since boot.
        let never = json!({ "on": true, "next": "x", "last": { "result": "success", "exit": 0, "at": "" } });
        assert!(describe(&never).contains("last run none since the server started"));
        let failed = json!({ "on": true, "next": "x", "last": { "result": "exit-code", "exit": 1, "at": "t" } });
        assert!(describe(&failed).contains("failed (exit-code, exit 1)"));
        // A start that failed before restic ran.
        let unstarted = json!({ "on": true, "next": "x", "last": { "result": "resources", "exit": 0, "at": "" } });
        assert!(describe(&unstarted).contains("failed (resources"));
    }

    #[test]
    fn the_status_is_said_in_the_chosen_language() {
        use erpc_core::i18n::Lang;
        let ok = json!({ "on": true, "next": "Fri 2026-10-30 03:12:00 UTC",
                         "last": { "result": "success", "exit": 0, "at": "Thu 2026-10-29 03:20:01 UTC" } });
        let english = describe(&ok);
        for lang in [Lang::Ja, Lang::Ru] {
            let said = crate::i18n::speaking(lang, || describe(&ok));
            assert_ne!(said, english);
            assert!(!said.contains('{'), "{said}");
            assert!(said.contains("Fri 2026-10-30 03:12:00 UTC"), "{said}");
            assert!(said.contains("\n  "), "the last run stays a detail: {said}");
        }
    }
}
