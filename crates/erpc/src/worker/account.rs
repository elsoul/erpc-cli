// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! An environment kept in the ERPC account (`account = true` under
//! `[env.<name>]`): its server facts are the account's record, not
//! erpc.toml's or a 1Password item's, and the account holds its servers and
//! lines by ids of its own, never by product number.
//!
//! What this machine trusts about such an environment is pinned here
//! (`worker_account.json` beside the config, 0600), per ERPC account, app
//! and environment: the app's id in the account, the server's address, SSH
//! user and port, its host key, and who may reach its SSH. The account is
//! not taken at its word on these: a first sighting and every change are
//! shown, the host key by its fingerprint, and go on only after a yes at a
//! terminal. Nothing accepts one for the person, `--yes` included.
//!
//! Only some commands work on such an environment yet. The rest refuse it
//! by name ([`not_yet`]) rather than read it as one with no server, which a
//! deploy would answer by buying one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use erpc_ai::session::Access as _;
use erpc_api::worker::{self as account, EnvDetail, Line, Server, WorkerError};
use erpc_auth::AuthClient;
use erpc_ssh::HostKey;
use erpc_ssh::worker::{UnitId, Verb};
use erpc_worker::manifest::{Env, Firewall, LineKind, Manifest};
use erpc_worker::net::Cidr;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::cli::error::{CliError, Code};
use crate::worker::App;

/// Whether environment `env` of `m` is kept in the ERPC account.
pub(crate) fn kept_there(m: &Manifest, env: &str) -> bool {
    m.env.get(env).is_some_and(|e| e.account)
}

/// The refusal of a command that does not work on an environment kept in
/// the account yet.
pub(crate) fn not_yet(app: &App) -> CliError {
    CliError::new(
        Code::Failed,
        t!("worker_account.not_yet", env = app.env.as_str()),
    )
    .hint(t!("worker_account.not_yet_hint", scope = app.scope()))
}

/// Text the account sent, as a terminal may be given it: a control
/// character, and a character that reorders the text around it, become
/// `?`. The account refuses them in what it keeps, and this side does not
/// rely on that.
pub(crate) fn shown(text: &str) -> String {
    crate::storage::clean(text)
}

// ------------------------------------------------------------------ pins

/// What this machine pins of an environment kept in the account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Anchor {
    /// The app's id in the account: made again, the app has another.
    pub(crate) app_id: String,
    /// The server's address.
    pub(crate) host: Option<String>,
    /// Its host key, one OpenSSH public key line.
    pub(crate) host_key: Option<String>,
    /// The account erpc signs in to.
    pub(crate) ssh_user: Option<String>,
    /// The SSH port.
    pub(crate) ssh_port: Option<u16>,
    /// Who may reach SSH.
    #[serde(default)]
    pub(crate) ssh_allow: Vec<String>,
    /// The account's id of the server in use, or none for a server it
    /// knows only by its address (the person's own). A server in use that
    /// leaves the record, as when the account ends it, is a change.
    #[serde(default)]
    pub(crate) server: Option<String>,
    /// Whether `server` was recorded: a pin written before it was is not
    /// read as one that names no server in use.
    #[serde(default)]
    pub(crate) server_recorded: bool,
}

impl Anchor {
    /// What `env` of the app `app_id` says, as erpc uses it: the SSH user
    /// and port it defaults to when none is given, and the host key in its
    /// own form, without its comment. Two records that reach the same
    /// server the same way are the same anchor.
    pub(crate) fn of(app_id: &str, env: &EnvDetail) -> Self {
        let server = env
            .servers
            .iter()
            .find(|s| s.slot == account::Slot::Active)
            .map(|s| s.id.clone());
        Self::of_facts(app_id, &env.facts, server)
    }

    /// The same, of server facts as written (this machine's own record,
    /// before the account has them), with the account's id of the server
    /// in use.
    pub(crate) fn of_facts(app_id: &str, facts: &account::Facts, server: Option<String>) -> Self {
        let host_key = facts
            .host_key
            .as_deref()
            .map(|k| HostKey::parse(k).map_or_else(|_| k.to_owned(), |key| key.to_openssh()));
        Self {
            app_id: app_id.to_owned(),
            host: facts.host.clone(),
            host_key,
            ssh_user: Some(facts.ssh_user.clone().unwrap_or_else(|| "root".to_owned())),
            ssh_port: Some(facts.ssh_port.unwrap_or(22)),
            ssh_allow: facts.firewall.ssh_allow.clone(),
            server,
            server_recorded: true,
        }
    }

    /// Each field, labelled, as a person checks it: the host key by its
    /// fingerprint, every value cleaned for the terminal.
    fn rows(&self) -> Vec<(String, String)> {
        let none = || t!("worker_account.trust.none");
        let key = self.host_key.as_deref().map_or_else(none, |k| {
            HostKey::parse(k).map_or_else(
                |_| t!("worker_account.trust.unreadable_key"),
                |key| key.fingerprint(),
            )
        });
        vec![
            (
                t!("worker_account.trust.row_host"),
                self.host.as_deref().map_or_else(none, shown),
            ),
            (t!("worker_account.trust.row_host_key"), key),
            (
                t!("worker_account.trust.row_user"),
                self.ssh_user
                    .as_deref()
                    .map_or_else(|| "root".to_owned(), shown),
            ),
            (
                t!("worker_account.trust.row_port"),
                self.ssh_port.unwrap_or(22).to_string(),
            ),
            (
                t!("worker_account.trust.row_ssh_allow"),
                if self.ssh_allow.is_empty() {
                    none()
                } else {
                    shown(&self.ssh_allow.join(", "))
                },
            ),
            (t!("worker_account.trust.row_app"), shown(&self.app_id)),
            (
                t!("worker_account.trust.row_server"),
                match (&self.server, self.server_recorded) {
                    (_, false) => t!("worker_account.trust.not_recorded"),
                    (Some(id), true) => shown(id),
                    (None, true) => t!("worker_account.trust.own_server"),
                },
            ),
        ]
    }
}

/// How what the account says now stands against what is pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Sighting {
    /// As pinned.
    Same,
    /// Nothing pinned yet.
    First,
    /// Pinned, and the account now says otherwise.
    Changed(Anchor),
}

/// How `now` stands against `pinned`.
pub(crate) fn sighting(pinned: Option<&Anchor>, now: &Anchor) -> Sighting {
    match pinned {
        None => Sighting::First,
        Some(before) if before == now => Sighting::Same,
        Some(before) => Sighting::Changed(before.clone()),
    }
}

/// What a person is shown before trusting `now`: what it says, and for a
/// change, each field that changed, before and now.
pub(crate) fn shown_sighting(app: &str, env: &str, sighting: &Sighting, now: &Anchor) -> String {
    let mut lines = Vec::new();
    match sighting {
        Sighting::Same => {}
        Sighting::First => {
            lines.push(t!("worker_account.trust.first", app, env));
            for (label, value) in now.rows() {
                lines.push(format!("  {label:<16} {value}"));
            }
        }
        Sighting::Changed(before) => {
            lines.push(t!("worker_account.trust.changed", app, env));
            if before.app_id != now.app_id {
                lines.push(format!("  {}", t!("worker_account.trust.app_remade")));
            }
            for ((label, was), (_, is)) in before.rows().into_iter().zip(now.rows()) {
                if was != is {
                    lines.push(format!("  {label:<16} {was}  →  {is}"));
                }
            }
        }
    }
    lines.join("\n")
}

/// The file the pins are kept in.
pub(crate) fn pins_path() -> Result<PathBuf, String> {
    crate::account::session::beside_config("worker_account.json")
}

/// The pins, by key, and beside them the list of who may reach the app as
/// this machine last saw it ([`app_seen`]).
#[derive(Debug, Default, Serialize, Deserialize)]
struct Pins {
    #[serde(default)]
    pins: BTreeMap<String, Anchor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    seen: BTreeMap<String, Vec<String>>,
}

/// The key a pin is kept under: the ERPC account (by a digest of its id,
/// which says nothing of whose it is), the app and the environment.
pub(crate) fn pin_key(uid: &str, app: &str, env: &str) -> String {
    format!("{}/{app}/{env}", uid_tag(uid))
}

/// What this machine files an ERPC account's records under: the first 8
/// bytes of the SHA-256 of its id, in hex, so the id itself is not kept.
pub(crate) fn uid_tag(uid: &str) -> String {
    let digest = Sha256::digest(uid.as_bytes());
    digest[..8]
        .iter()
        .fold(String::with_capacity(16), |mut tag, b| {
            use std::fmt::Write as _;
            let _ = write!(tag, "{b:02x}");
            tag
        })
}

/// The pins in `path`; none when there is no file yet. A file that cannot
/// be read is an error, never an empty list: writing a pin over it would
/// lose every other.
fn load_pins(path: &Path) -> Result<Pins, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            t!(
                "worker_account.pins_unreadable",
                path = path.display(),
                error = e
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Pins::default()),
        Err(e) => Err(t!(
            "worker_account.pins_unreadable",
            path = path.display(),
            error = e
        )),
    }
}

/// What is pinned in `path` under `key`.
pub(crate) fn pinned(path: &Path, key: &str) -> Result<Option<Anchor>, String> {
    Ok(load_pins(path)?.pins.remove(key))
}

/// Pins `anchor` in `path` under `key`, read and written under the lock so
/// that two commands pinning at once keep both.
pub(crate) fn pin(path: &Path, key: &str, anchor: &Anchor) -> Result<(), String> {
    erpc_core::private_file::locked(path, || {
        let mut pins = load_pins(path)?;
        pins.pins.insert(key.to_owned(), anchor.clone());
        let text = serde_json::to_vec_pretty(&pins).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)
    })
}

/// The account's list of who may reach the app for `key`, each entry as
/// the account keeps it, as this machine last put it on the server or saw
/// a deploy put it there: none when it never has.
pub(crate) fn app_seen(path: &Path, key: &str) -> Result<Option<Vec<String>>, String> {
    Ok(load_pins(path)?.seen.remove(key))
}

/// Records `list` as the account's list of who may reach the app for
/// `key`, as this machine last put it on the server.
pub(crate) fn see_app(path: &Path, key: &str, list: &[String]) -> Result<(), String> {
    erpc_core::private_file::locked(path, || {
        let mut pins = load_pins(path)?;
        pins.seen.insert(key.to_owned(), list.to_vec());
        let text = serde_json::to_vec_pretty(&pins).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)
    })
}

/// Takes the pin for `key` out of `path`, when there is one, and the list
/// last seen beside it.
pub(crate) fn unpin(path: &Path, key: &str) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    erpc_core::private_file::locked(path, || {
        let mut pins = load_pins(path)?;
        let seen = pins.seen.remove(key).is_some();
        if pins.pins.remove(key).is_none() && !seen {
            return Ok(());
        }
        let text = serde_json::to_vec_pretty(&pins).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)
    })
}

/// Trusts `now` for `key` in `path`: as pinned, or after a person says yes
/// at a terminal (`ask`) to a first sighting or a change, which is then
/// pinned. With no terminal (`terminal` false), a first sighting or a
/// change is refused, whatever else the command was given.
pub(crate) fn trust(
    path: &Path,
    key: &str,
    (name, app): (&str, &App),
    now: &Anchor,
    terminal: bool,
    ask: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<(), CliError> {
    let failed = |e: String| CliError::new(Code::Failed, e);
    let pinned = pinned(path, key).map_err(failed)?;
    let sighting = sighting(pinned.as_ref(), now);
    if sighting == Sighting::Same {
        return Ok(());
    }
    let shown = shown_sighting(name, &app.env, &sighting, now);
    if !terminal {
        return Err(CliError::new(Code::NeedsTerminal, shown)
            .hint(t!("worker_account.trust.at_terminal", scope = app.scope())));
    }
    let question = format!("{shown}\n{}", t!("worker_account.trust.question"));
    if !ask(&question).map_err(failed)? {
        return Err(CliError::new(
            Code::Declined,
            t!("worker_account.trust.declined"),
        ));
    }
    pin(path, key, now).map_err(failed)
}

// --------------------------------------------------------------- reading

/// The signed-in session, for the account's worker routes.
pub(crate) struct Signed {
    client: AuthClient,
    access: crate::ai::StoreAccess,
}

impl Signed {
    /// Signs in with the stored session.
    /// In a test: never this machine's own sign-in (its config, its
    /// credential store), nor the ERPC account. Whatever a test drives up to
    /// here stops as not signed in.
    #[cfg(test)]
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "the same signature as the real one"
    )]
    pub(crate) async fn open() -> Result<Self, CliError> {
        Err(CliError::new(
            Code::NotSignedIn,
            "a test does not open this machine's ERPC sign-in".to_owned(),
        ))
    }

    #[cfg(not(test))]
    pub(crate) async fn open() -> Result<Self, CliError> {
        let client = AuthClient::new().map_err(|e| CliError::new(Code::Network, e.to_string()))?;
        let access = crate::ai::StoreAccess::open(client.clone()).map_err(|o| {
            o.error()
                .unwrap_or_else(|| CliError::new(Code::NotSignedIn, t!("worker_vps.no_session")))
        })?;
        // Signed in at all: asked now, so that a missing sign-in is said
        // before anything else is done.
        access
            .access_token()
            .await
            .map_err(|e| CliError::new(Code::NotSignedIn, e).hint(t!("worker_vps.login_hint")))?;
        Ok(Self { client, access })
    }

    /// A token for one request. The session renews it when it has to, so a
    /// request made after a prompt waited is not sent with an expired one.
    async fn token(&self) -> Result<SecretString, WorkerError> {
        self.access
            .access_token()
            .await
            .map_err(WorkerError::Session)
    }

    /// The account's sealing keys, revoked ones included.
    pub(crate) async fn seal_keys(
        &self,
    ) -> Result<Vec<erpc_api::worker::seal::SealKey>, WorkerError> {
        erpc_api::worker::seal::list_seal_keys(&self.client, &self.token().await?).await
    }

    /// Registers `public_key` as one of the account's sealing keys, or
    /// finds it registered already.
    pub(crate) async fn register_seal_key(
        &self,
        public_key: &str,
    ) -> Result<account::Written<erpc_api::worker::seal::RegisteredKey>, WorkerError> {
        erpc_api::worker::seal::register_seal_key(
            &self.client,
            &self.token().await?,
            public_key,
            None,
        )
        .await
    }

    /// Revokes the account's sealing key `id`, for good.
    pub(crate) async fn revoke_seal_key(
        &self,
        id: &str,
    ) -> Result<erpc_api::worker::seal::RegisteredKey, WorkerError> {
        erpc_api::worker::seal::revoke_seal_key(&self.client, &self.token().await?, id).await
    }

    /// Makes the record of the app named `name`.
    pub(crate) async fn make_app(
        &self,
        name: &str,
        body: &account::PutApp,
    ) -> Result<account::Written<account::App>, WorkerError> {
        account::put_app(&self.client, &self.token().await?, name, body).await
    }

    /// The sizes a server start takes for environment `env` of app `name`,
    /// each with its price by the hour.
    pub(crate) async fn server_prices(
        &self,
        name: &str,
        env: &str,
    ) -> Result<account::money::ServerPrices, WorkerError> {
        account::money::server_prices(&self.client, &self.token().await?, name, env).await
    }

    /// The first login of server `server` of environment `env` of app
    /// `name`: read once, for that login.
    pub(crate) async fn server_first_login(
        &self,
        name: &str,
        env: &str,
        server: &str,
    ) -> Result<account::login::FirstLogin, WorkerError> {
        account::login::first_login(&self.client, &self.token().await?, name, env, server).await
    }

    /// The starts of environment `env` of app `name` still open.
    pub(crate) async fn open_starts(
        &self,
        name: &str,
        env: &str,
    ) -> Result<Vec<account::money::OpenStart>, WorkerError> {
        account::money::list_starts(&self.client, &self.token().await?, name, env).await
    }

    /// Starts a server for environment `env` of app `name`, paid for by the
    /// hour, under `key`, which the caller has kept before.
    pub(crate) async fn start_server(
        &self,
        name: &str,
        env: &str,
        key: &account::money::StartKey,
        body: &account::money::StartServer,
    ) -> Result<account::Written<EnvDetail>, WorkerError> {
        account::money::start_server(&self.client, &self.token().await?, name, env, key, body).await
    }

    /// The account's own id, which its pins are kept under.
    async fn uid(&self) -> Result<String, CliError> {
        let token = self.token().await.map_err(|e| {
            CliError::new(Code::NotSignedIn, e.to_string()).hint(t!("worker_vps.login_hint"))
        })?;
        erpc_api::get_user(&self.client, &token)
            .await
            .map(|u| u.uid)
            .map_err(|e| uid_failed(&e))
    }
}

/// A failed read of the account's own id, with the exit status of its
/// kind: a session refused as not signed in, with the login hint; a
/// sign-in with no ERPC account behind it as failed; anything else as the
/// network.
fn uid_failed(e: &erpc_api::ApiError) -> CliError {
    match e {
        erpc_api::ApiError::Unauthorized => {
            CliError::new(Code::NotSignedIn, e.to_string()).hint(t!("worker_vps.login_hint"))
        }
        erpc_api::ApiError::NoAccount => CliError::new(Code::Failed, e.to_string()),
        _ => CliError::new(Code::Network, e.to_string()),
    }
}

/// What erpc asks of the ERPC account for an environment kept there. The
/// signed-in session is the one that reaches it; a test brings a stand-in.
pub(crate) trait Account {
    /// The account's own id.
    async fn uid(&self) -> Result<String, CliError>;
    /// Whether the account lets this sign-in end what environment `env` of
    /// the app named `name` runs on once it is kept there: answered by
    /// reading the environment's open starts, a route of the same group as
    /// those that end servers and lines. An app or environment not there
    /// yet is an answer too: the route is open.
    async fn may_manage(&self, name: &str, env: &str) -> Result<(), WorkerError>;
    /// The app named `name`.
    async fn app(&self, name: &str) -> Result<account::App, WorkerError>;
    /// Makes or changes the app named `name`.
    async fn put_app(
        &self,
        name: &str,
        body: &account::PutApp,
    ) -> Result<account::Written<account::App>, WorkerError>;
    /// The environment `env` of the app named `name`.
    async fn env(&self, name: &str, env: &str) -> Result<EnvDetail, WorkerError>;
    /// Replaces the environment's record, expecting it at the revision
    /// `body` names.
    async fn put_env(
        &self,
        name: &str,
        env: &str,
        body: &account::PutEnv,
    ) -> Result<account::Written<EnvDetail>, WorkerError>;
    /// Takes a server the account already has into it.
    async fn adopt_server(
        &self,
        name: &str,
        env: &str,
        body: &account::AdoptServer,
    ) -> Result<account::Written<EnvDetail>, WorkerError>;
    /// Takes a line the account already has into it.
    async fn adopt_line(
        &self,
        name: &str,
        env: &str,
        body: &account::AdoptLine,
    ) -> Result<account::Written<EnvDetail>, WorkerError>;
    /// Deletes the record of the app named `name`, expecting it at
    /// `revision`: its environments, secrets and seals with it. Nothing is
    /// ended, and the account refuses while an environment of it still has
    /// a server, a line or an open start on record.
    async fn delete_app(&self, name: &str, revision: u64) -> Result<account::Deleted, WorkerError>;
    /// Ends every server and line of the environment (a line bought as part
    /// of a Bundle is taken off instead, not ended), then deletes its
    /// record, expecting it at `revision`.
    async fn delete_env_ending(
        &self,
        name: &str,
        env: &str,
        revision: u64,
    ) -> Result<account::money::Deleting, WorkerError>;
    /// Records whether the app runs on the server in `slot`.
    async fn set_app_running(
        &self,
        name: &str,
        env: &str,
        slot: &account::Slot,
        running: bool,
    ) -> Result<EnvDetail, WorkerError>;
    /// How many starts of the environment are still open: bought, or
    /// perhaps bought, and not on its record yet.
    async fn open_starts(&self, name: &str, env: &str) -> Result<usize, WorkerError>;
    /// Ends the server `server_id` in `slot` and takes it off the
    /// environment's record (`POST …/server/end`).
    async fn end_server(
        &self,
        name: &str,
        env: &str,
        slot: &account::Slot,
        server_id: &str,
    ) -> Result<account::money::Ended, WorkerError>;
}

impl Account for Signed {
    async fn uid(&self) -> Result<String, CliError> {
        Self::uid(self).await
    }

    async fn may_manage(&self, name: &str, env: &str) -> Result<(), WorkerError> {
        match account::money::list_starts(&self.client, &self.token().await?, name, env).await {
            Ok(_) => Ok(()),
            Err(WorkerError::Refused(r))
                if matches!(
                    r.code,
                    Some(account::Code::WorkerNotFound | account::Code::EnvNotFound)
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn app(&self, name: &str) -> Result<account::App, WorkerError> {
        account::get_app(&self.client, &self.token().await?, name).await
    }

    async fn put_app(
        &self,
        name: &str,
        body: &account::PutApp,
    ) -> Result<account::Written<account::App>, WorkerError> {
        account::put_app(&self.client, &self.token().await?, name, body).await
    }

    async fn env(&self, name: &str, env: &str) -> Result<EnvDetail, WorkerError> {
        account::get_env(&self.client, &self.token().await?, name, env).await
    }

    async fn put_env(
        &self,
        name: &str,
        env: &str,
        body: &account::PutEnv,
    ) -> Result<account::Written<EnvDetail>, WorkerError> {
        account::put_env(&self.client, &self.token().await?, name, env, body).await
    }

    async fn adopt_server(
        &self,
        name: &str,
        env: &str,
        body: &account::AdoptServer,
    ) -> Result<account::Written<EnvDetail>, WorkerError> {
        account::adopt_server(&self.client, &self.token().await?, name, env, body).await
    }

    async fn adopt_line(
        &self,
        name: &str,
        env: &str,
        body: &account::AdoptLine,
    ) -> Result<account::Written<EnvDetail>, WorkerError> {
        account::adopt_line(&self.client, &self.token().await?, name, env, body).await
    }

    async fn delete_app(&self, name: &str, revision: u64) -> Result<account::Deleted, WorkerError> {
        account::delete_app(&self.client, &self.token().await?, name, revision).await
    }

    async fn delete_env_ending(
        &self,
        name: &str,
        env: &str,
        revision: u64,
    ) -> Result<account::money::Deleting, WorkerError> {
        let token = self.token().await?;
        account::money::delete_env_ending_servers(&self.client, &token, name, env, revision).await
    }

    async fn set_app_running(
        &self,
        name: &str,
        env: &str,
        slot: &account::Slot,
        running: bool,
    ) -> Result<EnvDetail, WorkerError> {
        let token = self.token().await?;
        account::money::set_app_running(&self.client, &token, name, env, slot, running).await
    }

    async fn open_starts(&self, name: &str, env: &str) -> Result<usize, WorkerError> {
        account::money::list_starts(&self.client, &self.token().await?, name, env)
            .await
            .map(|starts| starts.len())
    }

    async fn end_server(
        &self,
        name: &str,
        env: &str,
        slot: &account::Slot,
        server_id: &str,
    ) -> Result<account::money::Ended, WorkerError> {
        let token = self.token().await?;
        account::money::end_server(&self.client, &token, name, env, slot, server_id).await
    }
}

/// An account's refusal or failure, said, for the app named `name`.
pub(crate) fn worker_error(name: &str, app: &App, e: &WorkerError) -> CliError {
    let code = match e {
        WorkerError::Refused(r) if r.code == Some(account::Code::WorkerNotFound) => {
            return CliError::new(Code::Failed, t!("worker_account.no_app", app = name));
        }
        WorkerError::Refused(r) if r.code == Some(account::Code::EnvNotFound) => {
            return CliError::new(
                Code::Failed,
                t!("worker_account.no_env", env = app.env.as_str()),
            );
        }
        WorkerError::Api(erpc_api::ApiError::Unauthorized) | WorkerError::Session(_) => {
            return CliError::new(Code::NotSignedIn, e.to_string())
                .hint(t!("worker_vps.login_hint"));
        }
        WorkerError::Api(_) => Code::Network,
        _ => Code::Failed,
    };
    CliError::new(code, e.to_string())
}

/// The environment `app.env` of the app named `name`, as the account keeps
/// it, with the app's id.
async fn read(api: &impl Account, app: &App, name: &str) -> Result<(String, EnvDetail), CliError> {
    let record = api
        .app(name)
        .await
        .map_err(|e| worker_error(name, app, &e))?;
    let env = api
        .env(name, &app.env)
        .await
        .map_err(|e| worker_error(name, app, &e))?;
    current_format(app, &env)?;
    Ok((record.id, env))
}

/// Refuses an environment the account keeps in an older form than this
/// erpc reads: its server and lines were in the old facts, which are not
/// read, so it would read as one without them.
pub(crate) fn current_format(app: &App, env: &EnvDetail) -> Result<(), CliError> {
    if env.facts_format < account::FACTS_FORMAT {
        return Err(CliError::new(
            Code::Failed,
            t!("worker_account.older_format", env = app.env.as_str()),
        ));
    }
    Ok(())
}

/// The server facts of `env` as erpc.toml would hold them, to reach the
/// server with: no server or line by number, since the account names
/// none. Addresses the account sent that do not read as one are left out
/// of the allow list.
pub(crate) fn facts_env(env: &EnvDetail) -> Env {
    let cidrs = |list: &[String]| -> Vec<Cidr> {
        list.iter()
            .filter_map(|c| Cidr::parse_any(c).ok())
            .collect()
    };
    Env {
        account: true,
        host: env.facts.host.clone(),
        ssh_user: env.facts.ssh_user.clone(),
        ssh_port: env.facts.ssh_port,
        host_key: env.facts.host_key.clone(),
        firewall: Firewall {
            ssh_allow: cidrs(&env.facts.firewall.ssh_allow),
            app_allow: cidrs(&env.facts.firewall.app_allow),
        },
        ..Env::default()
    }
}

// ---------------------------------------------------------------- status

/// A server of the environment, as `status --json` gives it.
fn server_json(s: &Server) -> Value {
    json!({
        "id": shown(&s.id),
        "slot": s.slot.as_str(),
        "cores": s.cores,
        "memoryGb": s.memory_gb,
        "region": s.region.as_deref().map(shown),
        "hourly": s.hourly,
        "appRunning": s.app_running,
        "state": s.state.as_str(),
    })
}

/// A line of the environment, as `status --json` gives it.
fn line_json(l: &Line) -> Value {
    json!({
        "id": shown(&l.id),
        "kind": l.kind.as_str(),
        "hourly": l.hourly,
        "bundlePart": l.bundle_part,
        "pending": l.pending,
        "state": l.state.as_str(),
        "endpoint": l.endpoint.as_deref().map(shown),
    })
}

/// What the account keeps of the environment, as `status --json` gives it.
pub(crate) fn account_json(env: &EnvDetail) -> Value {
    json!({
        "revision": env.revision,
        "servers": env.servers.iter().map(server_json).collect::<Vec<_>>(),
        "lines": env.lines.iter().map(line_json).collect::<Vec<_>>(),
        "desiredCores": env.desired_cores,
        "activeCores": env.active_cores,
        "deployed": env.deployed.as_ref().map(|d| json!({
            "release": shown(&d.release),
            "at": shown(&d.at),
        })),
    })
}

/// A server's slot as the operator reads it.
fn slot_said(slot: &account::Slot) -> String {
    match slot {
        account::Slot::Active => t!("worker_account.status.slot_active"),
        account::Slot::Incoming => t!("worker_account.status.slot_incoming"),
        account::Slot::Outgoing => t!("worker_account.status.slot_outgoing"),
        other => shown(other.as_str()),
    }
}

/// A server's or a line's state as the operator reads it: in use, or no
/// longer the account's, in words; any other, the account's word (the
/// product's own status, which grows with the products).
fn state_said(state: &account::State) -> String {
    match state {
        account::State::Active => t!("worker_account.status.state_active"),
        account::State::Gone => t!("worker_account.status.state_gone"),
        other => shown(other.as_str()),
    }
}

/// A line's state, as [`state_said`] says a server's: a word of its own
/// where a language makes it agree with the line.
fn line_state_said(state: &account::State) -> String {
    match state {
        account::State::Active => t!("worker_account.status.line_state_active"),
        account::State::Gone => t!("worker_account.status.line_state_gone"),
        other => shown(other.as_str()),
    }
}

/// A line's kind as the operator reads it: the product's name for the
/// kinds erpc knows, else the account's word.
pub(crate) fn kind_label(kind: &account::LineKind) -> String {
    let known = match kind {
        account::LineKind::Grpc => Some(LineKind::Grpc),
        account::LineKind::Shreds => Some(LineKind::Shreds),
        account::LineKind::Udp => Some(LineKind::Udp),
        account::LineKind::Unlimited => Some(LineKind::Unlimited),
        _ => None,
    };
    known.map_or_else(|| shown(kind.as_str()), |k| k.label().to_owned())
}

/// What `status` says the account keeps of the environment: each server by
/// its slot, size, region and state, each line by its kind, and the size
/// asked for when it is not the size in use. Never a product or a number.
pub(crate) fn account_said(env: &EnvDetail) -> Vec<String> {
    let yes_no = |hourly: bool| {
        if hourly {
            t!("worker_account.status.hourly")
        } else {
            String::new()
        }
    };
    let mut lines = vec![t!("worker_account.status.kept")];
    if env.servers.is_empty() {
        lines.push(format!("  {}", t!("worker_account.status.no_server")));
    }
    for s in &env.servers {
        // An ERPC Worker, with its spec as far as the account gives it.
        let size = crate::worker::vps::Spec::sized(s.cores, s.memory_gb)
            .said()
            .unwrap_or_default();
        let running = if s.app_running {
            t!("worker_account.status.app_running")
        } else {
            t!("worker_account.status.app_stopped")
        };
        lines.push(format!(
            "  {}",
            t!(
                "worker_account.status.server",
                slot = slot_said(&s.slot),
                size,
                region = s.region.as_deref().map_or_else(String::new, shown),
                state = state_said(&s.state),
                hourly = yes_no(s.hourly),
                running
            )
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
        ));
    }
    if let (Some(want), Some(now)) = (env.desired_cores, env.active_cores)
        && want != now
    {
        lines.push(format!(
            "  {}",
            t!("worker_account.status.size_asked", want, now)
        ));
    }
    for l in &env.lines {
        let endpoint = l
            .endpoint
            .as_deref()
            .filter(|e| !e.is_empty())
            .map_or_else(|| t!("worker_account.status.pending"), shown);
        lines.push(format!(
            "  {}",
            t!(
                "worker_account.status.line",
                kind = kind_label(&l.kind),
                state = line_state_said(&l.state),
                hourly = if l.bundle_part {
                    t!("worker_account.status.bundle_part")
                } else {
                    yes_no(l.hourly)
                },
                endpoint
            )
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
        ));
    }
    lines
}

/// An environment kept in the account, as a command that reaches its
/// server over SSH and writes nothing to `erpc.toml` is given it.
#[derive(Debug, Clone)]
pub(crate) struct Kept {
    /// `erpc.toml` as read, with the environment's server facts from the
    /// account in place of its `account = true`: given to SSH only, and
    /// never saved.
    pub(crate) manifest: Manifest,
    /// The account's record.
    pub(crate) record: EnvDetail,
    /// The app's id in the account.
    pub(crate) app_id: String,
    /// The account's own id, which this machine's pins are kept under.
    pub(crate) uid: String,
}

/// Environment `app.env` of the app named `name` as the account keeps it,
/// as SSH is given it: read in the form this erpc reads, refused when it
/// is not to be reached ([`reachable`], before anyone is asked), and
/// trusted as this machine pinned it.
pub(crate) async fn for_ssh(
    api: &impl Account,
    app: &App,
    m: &Manifest,
    pins: &Path,
    terminal: bool,
    ask: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<Kept, CliError> {
    let uid = api.uid().await?;
    let (app_id, record) = read(api, app, &m.name).await?;
    // What is not reached is refused before anyone is asked to trust it:
    // a server that is not in use as it should be, and a server in use
    // this machine pinned that the record no longer names (ended, or no
    // longer the person's; its address may be someone else's now).
    let key = pin_key(&uid, &m.name, &app.env);
    let now = Anchor::of(&app_id, &record);
    let before = pinned(pins, &key).map_err(|e| CliError::new(Code::Failed, e))?;
    reachable(app, &record, before.as_ref())?;
    trust(pins, &key, (&m.name, app), &now, terminal, ask)?;
    let mut manifest = m.clone();
    manifest.env.insert(app.env.clone(), facts_env(&record));
    Ok(Kept {
        manifest,
        record,
        app_id,
        uid,
    })
}

/// Whether the server of `record` is to be reached, given what this
/// machine pinned (`before`): the one decision `status` and every command
/// that reaches the server make, before anyone is asked to trust it.
/// Refused: a server in use that is not active (gone, given back, held);
/// a server in use this machine pinned that the record no longer names
/// (ended, or no longer the person's); no address or host key yet. Such an
/// address may be someone else's now.
pub(crate) fn reachable(
    app: &App,
    record: &EnvDetail,
    before: Option<&Anchor>,
) -> Result<(), CliError> {
    unreachable(app, record)?;
    let in_use = record
        .servers
        .iter()
        .any(|s| s.slot == account::Slot::Active);
    if !in_use && before.is_some_and(|b| b.server_recorded && b.server.is_some()) {
        return Err(gone(app));
    }
    Ok(())
}

/// [`reachable`], of the record alone.
fn unreachable(app: &App, record: &EnvDetail) -> Result<(), CliError> {
    if let Some(server) = record
        .servers
        .iter()
        .find(|s| s.slot == account::Slot::Active)
    {
        // Only a server the account has in use, active, is reached: one
        // gone, given back or held for maintenance may be someone else's.
        match &server.state {
            account::State::Active => {}
            account::State::Gone => return Err(gone(app)),
            other => {
                // A suspended server is said the same whatever its `hourly`
                // says: which way brings it back is the account's to decide.
                // Every way it may come back is said, none as sure, and none
                // is said to be ended.
                let hint = if other.as_str() == "suspended" {
                    t!("worker_account.server_suspended_hint", scope = app.scope())
                } else {
                    t!("worker_account.server_not_active_hint", scope = app.scope())
                };
                return Err(CliError::new(
                    Code::Failed,
                    t!(
                        "worker_account.server_not_active",
                        env = app.env.as_str(),
                        id = shown(&server.id),
                        state = shown(other.as_str())
                    ),
                )
                .hint(hint));
            }
        }
    }
    if record.facts.host.is_none() || record.facts.host_key.is_none() {
        return Err(CliError::new(
            Code::Failed,
            t!("worker_account.unreachable", env = app.env.as_str()),
        )
        .hint(t!("worker_account.unreachable_hint", scope = app.scope())));
    }
    Ok(())
}

/// The refusal of a server in use that is gone, or that the record no
/// longer names.
fn gone(app: &App) -> CliError {
    CliError::new(
        Code::Failed,
        t!("worker_account.server_gone", env = app.env.as_str()),
    )
    .hint(t!("worker_account.server_gone_hint", scope = app.scope()))
}

/// A signed-in session and environment `app.env` as the account keeps it,
/// when it is kept there; `None` when `erpc.toml` keeps it.
pub(crate) async fn held(json: bool, app: &App) -> Result<Option<(Signed, Kept)>, CliError> {
    let (_, m) = crate::worker::load(&app.dir)?;
    if !kept_there(&m, &app.env) {
        return Ok(None);
    }
    let signed = Signed::open().await?;
    let pins = pins_path().map_err(|e| CliError::new(Code::Failed, e))?;
    let kept = for_ssh(
        &signed,
        app,
        &m,
        &pins,
        crate::account::session::has_terminal() && !json,
        crate::node::common::confirm,
    )
    .await?;
    Ok(Some((signed, kept)))
}

/// How many times a write the account answered "too many at once" is sent
/// again, after the wait it asks for.
const BUSY_TRIES: u32 = 3;

/// The longest wait taken for one, in seconds.
const BUSY_WAIT_MAX: u64 = 30;

/// Why the account did not record whether the app runs: what it answered,
/// and whether the same request sent later may be recorded (it was busy or
/// out of reach, and may even have taken it), as against a refusal that
/// sending it again does not change, or a sign-in to renew first.
#[derive(Debug)]
pub(crate) struct Unrecorded {
    /// What the account answered, said.
    pub(crate) error: CliError,
    /// Whether sending it again later may record it.
    pub(crate) again: bool,
    /// Whether its outcome is not known: the account may have taken it.
    pub(crate) unknown: bool,
    /// Whether the sign-in must be renewed first.
    pub(crate) sign_in: bool,
}

/// Records in the account whether the app runs on the server in use of
/// environment `app.env` of the app named `name`. A write the account
/// answers "too many at once" is sent again after the wait it asks for.
pub(crate) async fn record_running(
    api: &impl Account,
    app: &App,
    name: &str,
    running: bool,
) -> Result<EnvDetail, Unrecorded> {
    let refused = |message: String| Unrecorded {
        error: CliError::new(Code::Failed, message),
        again: false,
        unknown: false,
        sign_in: false,
    };
    let mut tries = 0;
    loop {
        tries += 1;
        match api
            .set_app_running(name, &app.env, &account::Slot::Active, running)
            .await
        {
            Ok(record) => return Ok(record),
            Err(WorkerError::Refused(r)) if r.code == Some(account::Code::RateLimited) => {
                if tries >= BUSY_TRIES {
                    // Answered before the account tried the write: not taken.
                    return Err(Unrecorded {
                        error: CliError::new(Code::Failed, WorkerError::Refused(r).to_string()),
                        again: true,
                        unknown: false,
                        sign_in: false,
                    });
                }
                let wait = r.retry_after().unwrap_or(6).min(BUSY_WAIT_MAX);
                tokio::time::sleep(core::time::Duration::from_secs(wait)).await;
            }
            Err(WorkerError::Refused(r)) if r.code == Some(account::Code::AppRunningElsewhere) => {
                return Err(refused(t!(
                    "worker_account.running_elsewhere",
                    env = app.env.as_str()
                )));
            }
            Err(WorkerError::Refused(r)) if r.code == Some(account::Code::ServerNotFound) => {
                return Err(refused(t!(
                    "worker_account.no_server_in_use",
                    env = app.env.as_str()
                )));
            }
            Err(e) => {
                // Busy, out of reach or failing: later may record it. A
                // sign-in to renew is not fixed by sending it again.
                let sign_in = matches!(
                    e,
                    WorkerError::Api(erpc_api::ApiError::Unauthorized) | WorkerError::Session(_)
                );
                // Out of reach, failing, or answered in a form this erpc
                // does not read after the write: the account may have taken
                // it, and sending it again may record it.
                let unknown = !sign_in
                    && match &e {
                        WorkerError::Api(_) => true,
                        WorkerError::Refused(r) => r.status >= 500,
                        WorkerError::NewerFormat { after_write, .. } => *after_write,
                        _ => false,
                    };
                return Err(Unrecorded {
                    error: worker_error(name, app, &e),
                    again: unknown,
                    unknown,
                    sign_in,
                });
            }
        }
    }
}

/// Whether the account names a server in use for the environment: one it
/// records the app's state for. A server of the person's own, which the
/// account knows only by its address, has none.
pub(crate) fn has_server_in_use(record: &EnvDetail) -> bool {
    record
        .servers
        .iter()
        .any(|s| s.slot == account::Slot::Active)
}

/// Whether the account's record says the app runs on the server in use.
pub(crate) fn says_running(record: &EnvDetail) -> bool {
    record
        .servers
        .iter()
        .any(|s| s.slot == account::Slot::Active && s.app_running)
}

/// What the environment kept in the account pays for by the hour, said
/// when the app is stopped: stopping ends none of it.
pub(crate) fn still_charged(record: &EnvDetail, scope: &str) -> Option<String> {
    // What is gone from the account, or cancelled, is ended, and charges
    // nothing more.
    let live =
        |state: &account::State| *state != account::State::Gone && state.as_str() != "cancelled";
    let mut items: Vec<String> = Vec::new();
    // A server is billed while it is active (or suspended for credit).
    let billed =
        |state: &account::State| *state == account::State::Active || state.as_str() == "suspended";
    if record.servers.iter().any(|s| s.hourly && billed(&s.state)) {
        items.push(t!("worker_account.charged_server"));
    }
    for line in record.lines.iter().filter(|l| l.hourly && live(&l.state)) {
        items.push(t!(
            "worker_account.charged_line",
            kind = kind_label(&line.kind)
        ));
    }
    (!items.is_empty()).then(|| {
        let items = items.join(&t!("worker_account.list_sep"));
        // With no server of the account's in use, the delete asks at a
        // terminal only (it may be a server of the person's own): the
        // dashboard ends a line there too.
        if has_server_in_use(record) {
            t!("worker_account.still_charged", items, scope)
        } else {
            t!("worker_account.still_charged_lines", items, scope)
        }
    })
}

/// What `status` does with an environment kept in the account, once the
/// account's record is read.
pub(crate) enum StatusPlan {
    /// The record alone, with why the server is not reached.
    Alone {
        /// The answer for `--json`.
        answer: Value,
        /// The text.
        text: String,
    },
    /// Reach the server, trusted as pinned, and say the record after it.
    Reach {
        /// The answer for `--json`, the record in it.
        answer: Value,
        /// The record, said.
        kept: Vec<String>,
        /// The server's address.
        host: String,
        /// The server facts to reach it with.
        env: Box<Env>,
    },
}

/// [`status`]'s decision: the record read, then [`reachable`] (the same
/// decision every command that reaches the server makes), and the server
/// trusted only when it is to be reached. A record not reached is shown
/// alone, nobody is asked, and the pin is left as it is.
pub(crate) async fn status_plan(
    api: &impl Account,
    app: &App,
    m: &Manifest,
    pins: &Path,
    terminal: bool,
    ask: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<StatusPlan, CliError> {
    let uid = api.uid().await?;
    let (app_id, env) = read(api, app, &m.name).await?;
    let kept = account_said(&env);
    let answer = json!({ "account": account_json(&env) });
    let key = pin_key(&uid, &m.name, &app.env);
    let before = pinned(pins, &key).map_err(|e| CliError::new(Code::Failed, e))?;
    if let Err(why) = reachable(app, &env, before.as_ref()) {
        let text = format!("{}\n{}", why.message, kept.join("\n"));
        return Ok(StatusPlan::Alone { answer, text });
    }
    let Some(host) = env.facts.host.clone() else {
        return Ok(StatusPlan::Alone {
            answer,
            text: kept.join("\n"),
        });
    };
    trust(
        pins,
        &key,
        (&m.name, app),
        &Anchor::of(&app_id, &env),
        terminal,
        ask,
    )?;
    Ok(StatusPlan::Reach {
        answer,
        kept,
        host,
        env: Box::new(facts_env(&env)),
    })
}

/// `erpc worker status` of an environment kept in the account: the
/// account's record, trusted as pinned, and the worker's own state from its
/// server when it has one.
pub(crate) async fn status(
    json: bool,
    app: &App,
    m: &Manifest,
) -> Result<(Value, String), CliError> {
    let signed = Signed::open().await?;
    let pins = pins_path().map_err(|e| CliError::new(Code::Failed, e))?;
    let plan = status_plan(
        &signed,
        app,
        m,
        &pins,
        crate::account::session::has_terminal() && !json,
        crate::node::common::confirm,
    )
    .await?;
    let (mut answer, kept, host, facts) = match plan {
        StatusPlan::Alone { answer, text } => return Ok((answer, text)),
        StatusPlan::Reach {
            answer,
            kept,
            host,
            env,
        } => (answer, kept, host, env),
    };
    let id = UnitId::new(&m.unit_id(&app.env)).map_err(|e| CliError::new(Code::Failed, e))?;
    let target = crate::worker::remote::target(app, facts.as_ref())?;
    let session = crate::worker::remote::open(&target)?;
    let mut agent = crate::worker::remote::ctl(&session, &id, Verb::Status, None)?;
    let text =
        crate::worker::remote::status_said(m, &app.env, &host, &mut agent, None, &app.scope());
    // The agent's answer, then the account's record over it: an agent
    // that answered with an `account` of its own does not replace it.
    if let (Some(into), Some(from)) = (answer.as_object_mut(), agent.as_object()) {
        for (k, v) in from {
            into.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    Ok((answer, format!("{text}\n{}", kept.join("\n"))))
}

/// The account, stood in for in memory, for tests here and of the commands
/// that reach it.
#[cfg(test)]
pub(crate) mod stand_in {
    use std::cell::RefCell;

    use serde_json::{Value, json};

    use super::*;

    /// The account, in memory: one app and its environment, and the
    /// answers a write of the app's state gets, in turn.
    pub(crate) struct Fake {
        pub(crate) env: RefCell<EnvDetail>,
        pub(crate) answers: RefCell<Vec<WorkerError>>,
        pub(crate) written: RefCell<Vec<bool>>,
        /// Every write of the app's state, and whatever a test adds, in
        /// the order they came.
        pub(crate) log: RefCell<Vec<String>>,
        /// Another sign-in's host, written over the next put as it lands.
        pub(crate) meddle: RefCell<Option<String>>,
        /// The next delete answers that an end is under way.
        pub(crate) pending: RefCell<bool>,
        /// The environment was deleted.
        pub(crate) gone: RefCell<bool>,
        /// Failures the next reads of the environment answer, in turn.
        pub(crate) reads: RefCell<Vec<WorkerError>>,
        /// What the next ends of a server answer, in turn, each with the
        /// environment as it is after it (`None`: as it was); with none
        /// left, the server is ended and taken off, as the account does.
        #[allow(clippy::type_complexity, reason = "a test's script of answers")]
        pub(crate) ends: RefCell<
            Vec<(
                Result<account::money::Ended, WorkerError>,
                Option<EnvDetail>,
            )>,
        >,
        /// A failure the read of the environment with this number (1 for
        /// the first) answers.
        pub(crate) fail_read: RefCell<Option<(usize, WorkerError)>>,
        /// How many reads of the environment were made.
        pub(crate) read_count: RefCell<usize>,
        /// The environment as it is from the read with this number on,
        /// as when another sign-in changes it.
        pub(crate) changes_at: RefCell<Option<(usize, EnvDetail)>>,
        /// How many starts of the environment are open, read in turn
        /// (the last one stays).
        pub(crate) open: RefCell<Vec<usize>>,
        /// The app's environments by name, this one among them until it is
        /// deleted: by default it has another, so its record stays.
        pub(crate) app_envs: RefCell<Vec<&'static str>>,
        /// What the next deletes of the app answer, in turn.
        pub(crate) app_answers: RefCell<Vec<WorkerError>>,
        /// The app's record was deleted.
        pub(crate) app_gone: RefCell<bool>,
        /// The id of the app by that name once the environment is deleted,
        /// as when another app took the name meanwhile.
        pub(crate) app_id_after: RefCell<Option<&'static str>>,
    }

    impl Fake {
        pub(crate) fn new(env: EnvDetail) -> Self {
            Self {
                env: RefCell::new(env),
                answers: RefCell::new(Vec::new()),
                written: RefCell::new(Vec::new()),
                log: RefCell::new(Vec::new()),
                meddle: RefCell::new(None),
                pending: RefCell::new(false),
                gone: RefCell::new(false),
                reads: RefCell::new(Vec::new()),
                ends: RefCell::new(Vec::new()),
                fail_read: RefCell::new(None),
                read_count: RefCell::new(0),
                changes_at: RefCell::new(None),
                open: RefCell::new(vec![0]),
                app_envs: RefCell::new(vec!["prod", "staging"]),
                app_answers: RefCell::new(Vec::new()),
                app_gone: RefCell::new(false),
                app_id_after: RefCell::new(None),
            }
        }
    }

    pub(crate) fn refused(status: u16, code: &str, data: Value) -> WorkerError {
        WorkerError::Refused(account::Refusal {
            status,
            code: Some(account::Code::from(code)),
            message: None,
            data,
        })
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the stand-in answers at once; the account it stands in for is awaited"
    )]
    impl Account for Fake {
        async fn uid(&self) -> Result<String, CliError> {
            Ok("user-100001".to_owned())
        }

        async fn app(&self, name: &str) -> Result<account::App, WorkerError> {
            if *self.app_gone.borrow() {
                return Err(refused(404, "worker_not_found", Value::Null));
            }
            // The environment deleted is no longer among the app's.
            let this = self.env.borrow().name.clone();
            let envs: Vec<Value> = self
                .app_envs
                .borrow()
                .iter()
                .filter(|e| !(*self.gone.borrow() && **e == this))
                .map(|e| json!({ "name": e, "revision": 1 }))
                .collect();
            let id = match *self.app_id_after.borrow() {
                Some(other) if *self.gone.borrow() => other,
                _ => "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13",
            };
            Ok(
                serde_json::from_value(json!({ "id": id, "name": name, "chain": "solana",
                "template": null, "wallet": null, "revision": 1, "envs": envs }))
                .expect("an app"),
            )
        }

        async fn env(&self, _: &str, _: &str) -> Result<EnvDetail, WorkerError> {
            *self.read_count.borrow_mut() += 1;
            let mut changes = self.changes_at.borrow_mut();
            if changes
                .as_ref()
                .is_some_and(|(n, _)| *n == *self.read_count.borrow())
            {
                *self.env.borrow_mut() = changes.take().expect("a change").1;
            }
            let mut fail = self.fail_read.borrow_mut();
            if fail
                .as_ref()
                .is_some_and(|(n, _)| *n == *self.read_count.borrow())
            {
                return Err(fail.take().expect("a failure").1);
            }
            let mut reads = self.reads.borrow_mut();
            if !reads.is_empty() {
                return Err(reads.remove(0));
            }
            if *self.gone.borrow() {
                return Err(refused(404, "env_not_found", Value::Null));
            }
            Ok(self.env.borrow().clone())
        }

        async fn put_env(
            &self,
            _: &str,
            _: &str,
            body: &account::PutEnv,
        ) -> Result<account::Written<EnvDetail>, WorkerError> {
            self.log.borrow_mut().push("put_env".to_owned());
            let mut answers = self.answers.borrow_mut();
            if !answers.is_empty() {
                return Err(answers.remove(0));
            }
            // As the account does: an address is taken only with its prefix
            // length.
            if body
                .facts
                .firewall
                .ssh_allow
                .iter()
                .chain(&body.facts.firewall.app_allow)
                .any(|a| !a.contains('/') || (a.contains(':') && a.contains('.')))
            {
                // Nor does it take an IPv6 address written with dots.
                return Err(refused(400, "invalid_request", Value::Null));
            }
            let mut env = self.env.borrow_mut();
            if body.expected_revision != env.revision {
                return Err(refused(409, "revision_conflict", Value::Null));
            }
            env.revision += 1;
            env.facts = body.facts.clone();
            // A put replaces the whole environment: what it leaves out is
            // cleared, as the account does.
            env.deployed.clone_from(&body.deployed);
            env.deployed_app.clone_from(&body.deployed_app);
            if let Some(meddled) = self.meddle.borrow_mut().take() {
                env.facts.host = Some(meddled);
            }
            Ok(account::Written::new(false, env.clone()))
        }

        async fn may_manage(&self, _: &str, _: &str) -> Result<(), WorkerError> {
            Ok(())
        }

        async fn put_app(
            &self,
            _: &str,
            _: &account::PutApp,
        ) -> Result<account::Written<account::App>, WorkerError> {
            unreachable!("not asked of this stand-in")
        }

        async fn adopt_server(
            &self,
            _: &str,
            _: &str,
            _: &account::AdoptServer,
        ) -> Result<account::Written<EnvDetail>, WorkerError> {
            unreachable!("not asked of this stand-in")
        }

        async fn adopt_line(
            &self,
            _: &str,
            _: &str,
            _: &account::AdoptLine,
        ) -> Result<account::Written<EnvDetail>, WorkerError> {
            unreachable!("not asked of this stand-in")
        }

        async fn delete_app(
            &self,
            name: &str,
            revision: u64,
        ) -> Result<account::Deleted, WorkerError> {
            self.log
                .borrow_mut()
                .push(format!("delete app at {revision}"));
            let mut answers = self.app_answers.borrow_mut();
            if !answers.is_empty() {
                return Err(answers.remove(0));
            }
            *self.app_gone.borrow_mut() = true;
            Ok(serde_json::from_value(json!({ "name": name, "deleted": true })).expect("deleted"))
        }

        async fn delete_env_ending(
            &self,
            name: &str,
            _: &str,
            revision: u64,
        ) -> Result<account::money::Deleting, WorkerError> {
            self.log
                .borrow_mut()
                .push(format!("delete env at {revision}"));
            let mut answers = self.answers.borrow_mut();
            if !answers.is_empty() {
                return Err(answers.remove(0));
            }
            if self.pending.replace(false) {
                self.env.borrow_mut().revision += 1;
                return Ok(account::money::Deleting::Pending);
            }
            *self.gone.borrow_mut() = true;
            Ok(account::money::Deleting::Deleted(
                serde_json::from_value(json!({ "name": name, "deleted": true })).expect("deleted"),
            ))
        }

        async fn set_app_running(
            &self,
            _: &str,
            _: &str,
            _: &account::Slot,
            running: bool,
        ) -> Result<EnvDetail, WorkerError> {
            self.written.borrow_mut().push(running);
            self.log.borrow_mut().push(format!("record {running}"));
            let mut answers = self.answers.borrow_mut();
            if answers.is_empty() {
                // Every change moves the revision, as the account's does.
                let mut env = self.env.borrow_mut();
                env.revision += 1;
                for server in &mut env.servers {
                    if server.slot == account::Slot::Active {
                        server.app_running = running;
                    }
                }
                Ok(env.clone())
            } else {
                Err(answers.remove(0))
            }
        }

        async fn open_starts(&self, _: &str, _: &str) -> Result<usize, WorkerError> {
            let mut open = self.open.borrow_mut();
            Ok(if open.len() > 1 {
                open.remove(0)
            } else {
                open.first().copied().unwrap_or(0)
            })
        }

        async fn end_server(
            &self,
            _: &str,
            _: &str,
            slot: &account::Slot,
            server_id: &str,
        ) -> Result<account::money::Ended, WorkerError> {
            self.log.borrow_mut().push(format!("end {server_id}"));
            let mut ends = self.ends.borrow_mut();
            if !ends.is_empty() {
                let (answer, after) = ends.remove(0);
                if let Some(after) = after {
                    *self.env.borrow_mut() = after;
                }
                return answer;
            }
            // The account keeps the address in the facts: erpc clears it.
            let mut env = self.env.borrow_mut();
            env.servers
                .retain(|s| !(s.slot == *slot && s.id == server_id));
            env.revision += 1;
            Ok(account::money::Ended::Done(Box::new(env.clone())))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::stand_in::{Fake, refused};
    use super::*;

    const APP_ID: &str = "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13";
    const SERVER_ID: &str = "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60";
    const LINE_ID: &str = "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314";
    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    fn env_detail() -> EnvDetail {
        serde_json::from_value(json!({
            "name": "prod",
            "revision": 7,
            "factsFormat": 2,
            "facts": {
                "desiredCores": 4, "host": "203.0.113.10", "sshUser": "ubuntu", "sshPort": null,
                "hostKey": HOST_KEY,
                "firewall": { "sshAllow": ["198.51.100.7/32"], "appAllow": ["0.0.0.0/0"] },
                "starting": {}, "backup": null
            },
            "servers": [{
                "id": SERVER_ID, "slot": "active", "cores": 2, "memoryGb": 8, "region": "amsterdam",
                "hourly": true, "appRunning": true, "state": "active"
            }],
            "desiredCores": 4, "activeCores": 2, "coreOptions": [1, 2, 4, 8],
            "lines": [
                { "id": LINE_ID, "kind": "grpc", "hourly": true, "pending": false, "state": "active",
                  "endpoint": "grpc.example.net:443" },
                { "id": SERVER_ID, "kind": "unlimited", "hourly": true, "pending": true,
                  "state": "provisioning", "endpoint": null }
            ],
            "refStates": { "backup": null },
            "deployed": { "release": "20261029T154037Z-6914df5f", "at": "2026-10-29T15:40:37.000Z" },
            "deployedApp": null,
            "updatedAt": "2026-10-29T15:40:37.000Z"
        }))
        .expect("an environment")
    }

    fn app() -> App {
        App::at("apps/bot", "prod")
    }

    #[test]
    fn a_pin_is_kept_per_account_app_and_environment_and_names_no_account() {
        let key = pin_key("user-100001", "bot", "prod");
        assert!(key.ends_with("/bot/prod"), "{key}");
        assert!(!key.contains("100001"), "{key}");
        assert_eq!(key, pin_key("user-100001", "bot", "prod"));
        assert_ne!(key, pin_key("user-200002", "bot", "prod"));
        assert_ne!(key, pin_key("user-100001", "bot", "staging"));
    }

    #[test]
    fn what_the_account_says_is_trusted_once_by_a_person_and_then_as_pinned() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("worker_account.json");
        let key = pin_key("user-100001", "bot", "prod");
        let now = Anchor::of(APP_ID, &env_detail());
        // No terminal: a first sighting is refused, shown, and not pinned.
        let e = trust(&path, &key, ("bot", &app()), &now, false, |_| {
            panic!("nobody is asked without a terminal")
        })
        .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert!(e.message.contains("203.0.113.10"), "{}", e.message);
        assert!(e.message.contains("SHA256:"), "{}", e.message);
        assert!(!e.message.contains("AAAAC3"), "{}", e.message);
        assert_eq!(pinned(&path, &key).expect("reads"), None);
        // A person says no: nothing pinned.
        let e =
            trust(&path, &key, ("bot", &app()), &now, true, |_| Ok(false)).expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert_eq!(pinned(&path, &key).expect("reads"), None);
        // Yes: pinned, and the next time nobody is asked.
        trust(&path, &key, ("bot", &app()), &now, true, |_| Ok(true)).expect("trusted");
        assert_eq!(pinned(&path, &key).expect("reads").as_ref(), Some(&now));
        trust(&path, &key, ("bot", &app()), &now, false, |_| {
            panic!("the same is not asked again")
        })
        .expect("as pinned");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("a file")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // The account then says another host key: shown as a change, and
        // refused without a person.
        let mut moved = env_detail();
        moved.facts.host_key = Some("ssh-ed25519 AAAA".to_owned());
        let changed = Anchor::of(APP_ID, &moved);
        let e = trust(&path, &key, ("bot", &app()), &changed, false, |_| {
            panic!("nobody is asked without a terminal")
        })
        .expect_err("refused");
        assert!(e.message.contains("→"), "{}", e.message);
        assert_eq!(pinned(&path, &key).expect("reads").as_ref(), Some(&now));
    }

    #[test]
    fn a_change_shows_what_changed_and_an_app_made_again() {
        let before = Anchor::of(APP_ID, &env_detail());
        let mut moved = env_detail();
        moved.facts.host = Some("198.51.100.20".to_owned());
        let now = Anchor::of("2c1d5e3a-7b4f-4a9e-8d6c-0f1e2a3b4c5d", &moved);
        let sighting = sighting(Some(&before), &now);
        assert_eq!(sighting, Sighting::Changed(before.clone()));
        let text = shown_sighting("bot", "prod", &sighting, &now);
        assert!(text.contains("203.0.113.10  →  198.51.100.20"), "{text}");
        assert!(text.contains("made again"), "{text}");
        // An unchanged field is not shown.
        assert!(!text.contains("ubuntu"), "{text}");
        assert_eq!(sighting_of_same(&before), Sighting::Same);
    }

    #[test]
    fn the_same_server_said_another_way_is_the_same_anchor() {
        let given = Anchor::of(APP_ID, &env_detail());
        // The defaults erpc uses, said or left out; a host key's comment.
        let mut plain = env_detail();
        plain.facts.ssh_user = Some("ubuntu".to_owned());
        plain.facts.ssh_port = Some(22);
        plain.facts.host_key = Some(format!("{HOST_KEY} root@box"));
        assert_eq!(Anchor::of(APP_ID, &plain), given);
        let mut root = env_detail();
        root.facts.ssh_user = None;
        let mut said_root = env_detail();
        said_root.facts.ssh_user = Some("root".to_owned());
        assert_eq!(Anchor::of(APP_ID, &root), Anchor::of(APP_ID, &said_root));
        // Another port is another anchor.
        let mut other = env_detail();
        other.facts.ssh_port = Some(2222);
        assert_ne!(Anchor::of(APP_ID, &other), given);
    }

    fn sighting_of_same(a: &Anchor) -> Sighting {
        sighting(Some(a), a)
    }

    #[test]
    fn a_pins_file_that_cannot_be_read_is_an_error_not_an_empty_list() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("worker_account.json");
        std::fs::write(&path, b"{ not json").expect("written");
        let anchor = Anchor::of(APP_ID, &env_detail());
        assert!(pinned(&path, "k").is_err());
        assert!(pin(&path, "k", &anchor).is_err());
        assert_eq!(std::fs::read(&path).expect("kept"), b"{ not json");
    }

    #[test]
    fn status_says_servers_by_slot_and_size_and_lines_by_kind_never_a_number() {
        let env = env_detail();
        let said = account_said(&env).join("\n");
        assert!(said.contains("ERPC Worker (in use)"), "{said}");
        assert!(said.contains("2 vCPU, 8 GB memory"), "{said}");
        assert!(
            !said.contains("VPS") && !said.contains("server ("),
            "{said}"
        );
        assert!(said.contains("amsterdam"), "{said}");
        assert!(said.contains("app running"), "{said}");
        assert!(
            said.contains("4 vCPU asked for; the server in use has 2"),
            "{said}"
        );
        assert!(said.contains("gRPC line"), "{said}");
        assert!(said.contains("grpc.example.net:443"), "{said}");
        assert!(said.contains("Unlimited RPC line"), "{said}");
        assert!(said.contains("endpoint not ready"), "{said}");
        assert!(
            !said.contains(SERVER_ID) && !said.contains(LINE_ID),
            "{said}"
        );
        let json = account_json(&env);
        assert_eq!(json["servers"][0]["slot"], "active");
        assert_eq!(json["servers"][0]["cores"], 2);
        assert_eq!(json["lines"][1]["pending"], true);
        assert_eq!(json["deployed"]["release"], "20261029T154037Z-6914df5f");
        assert!(json["servers"][0].get("refId").is_none());
        assert_eq!(json["lines"][0]["bundlePart"], false);
        // A line bought as part of a Bundle: said so in place of whether
        // it is paid by the hour.
        let mut part = env_detail();
        part.lines[0].bundle_part = true;
        let said = account_said(&part).join("\n");
        assert!(
            said.contains("gRPC line active part of a Bundle grpc.example.net:443"),
            "{said}"
        );
        assert!(!said.contains("gRPC line active hourly"), "{said}");
        assert_eq!(account_json(&part)["lines"][0]["bundlePart"], true);
        // No server yet: said so.
        let mut empty = env_detail();
        empty.servers.clear();
        assert!(
            account_said(&empty)
                .iter()
                .any(|l| l.contains("no server yet"))
        );
    }

    #[test]
    fn an_environment_kept_in_an_older_form_is_refused_not_read_as_without_a_server() {
        assert!(current_format(&app(), &env_detail()).is_ok());
        let mut older = env_detail();
        older.facts_format = 1;
        let e = current_format(&app(), &older).expect_err("refused");
        assert!(e.message.contains("older form"), "{}", e.message);
    }

    #[test]
    fn a_line_and_a_server_say_their_state_each_in_its_own_word() {
        let said = account_said(&env_detail()).join("\n");
        assert!(
            said.contains("gRPC line  active") || said.contains("gRPC line active"),
            "{said}"
        );
    }

    #[test]
    fn what_the_account_sent_is_cleaned_before_it_is_printed() {
        let mut env = env_detail();
        env.servers[0].region = Some("amster\u{1b}[2Jdam\u{202e}".to_owned());
        let said = account_said(&env).join("\n");
        assert!(
            !said.contains('\u{1b}') && !said.contains('\u{202e}'),
            "{said:?}"
        );
    }

    #[test]
    fn the_server_facts_are_the_accounts_with_no_server_or_line_by_number() {
        let facts = facts_env(&env_detail());
        assert!(facts.account);
        assert_eq!(facts.host.as_deref(), Some("203.0.113.10"));
        assert_eq!(facts.ssh_user.as_deref(), Some("ubuntu"));
        assert_eq!(facts.firewall.ssh_allow.len(), 1);
        assert!(facts.resource.is_none() && facts.lines.is_empty() && facts.starting.is_empty());
    }

    #[test]
    fn a_command_that_does_not_read_the_account_refuses_an_environment_kept_there() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("erpc.toml");
        std::fs::write(
            &path,
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\naccount = true\n",
        )
        .expect("erpc.toml");
        let app = App::at(dir.path(), "prod");
        let e = crate::worker::load_env(&app).expect_err("refused");
        assert!(
            e.message.contains("kept in the ERPC account"),
            "{}",
            e.message
        );
        assert!(
            e.hint
                .as_deref()
                .unwrap_or_default()
                .contains("erpc worker status")
        );
        let (_, m) = crate::worker::load(&app.dir).expect("read");
        assert!(kept_there(&m, "prod"));
        assert!(!kept_there(&m, "staging"));
    }

    fn manifest() -> Manifest {
        Manifest::parse("name = \"bot\"\nchain = \"solana\"\n[env.prod]\naccount = true\n")
            .expect("a manifest")
    }

    fn never(_: &str) -> Result<bool, String> {
        panic!("nobody is asked")
    }

    #[tokio::test]
    async fn a_pinned_record_is_handed_to_ssh_as_server_facts_never_as_erpc_toml() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let fake = Fake::new(env_detail());
        pin(
            &pins,
            &pin_key("user-100001", "bot", "prod"),
            &Anchor::of(APP_ID, &env_detail()),
        )
        .expect("pinned");
        let kept = for_ssh(&fake, &app(), &manifest(), &pins, false, never)
            .await
            .expect("handed over");
        let env = &kept.manifest.env["prod"];
        assert!(env.account);
        assert_eq!(env.host.as_deref(), Some("203.0.113.10"));
        assert_eq!(env.ssh_user.as_deref(), Some("ubuntu"));
        assert_eq!(env.host_key.as_deref(), Some(HOST_KEY));
        assert!(env.resource.is_none() && env.lines.is_empty());
        assert_eq!(kept.record.servers.len(), 1);
    }

    #[tokio::test]
    async fn a_record_not_trusted_yet_is_asked_about_at_a_terminal_only() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let fake = Fake::new(env_detail());
        // Nobody at a terminal (or --json): refused, and nothing pinned.
        let e = for_ssh(&fake, &app(), &manifest(), &pins, false, never)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert!(!pins.exists());
        // At a terminal, a no: refused, nothing pinned.
        let e = for_ssh(&fake, &app(), &manifest(), &pins, true, |_| Ok(false))
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert!(!pins.exists());
        // A yes: pinned, and handed over.
        for_ssh(&fake, &app(), &manifest(), &pins, true, |_| Ok(true))
            .await
            .expect("trusted");
        assert!(pins.exists());
        // Then the record says another host key: asked again, and without a
        // terminal refused.
        fake.env.borrow_mut().facts.host_key = Some(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxKi4i8Zcbq0z6y5H3d0r9sXv4iF8bGkqN2ly5pW7tH"
                .to_owned(),
        );
        let e = for_ssh(&fake, &app(), &manifest(), &pins, false, never)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
    }

    #[tokio::test]
    async fn a_pinned_server_in_use_that_leaves_the_record_is_refused_before_anyone_is_asked() {
        // Pinned with its server in use; then the account ends it, which
        // takes it off the record and leaves the address and host key.
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        pin(
            &pins,
            &pin_key("user-100001", "bot", "prod"),
            &Anchor::of(APP_ID, &env_detail()),
        )
        .expect("pinned");
        let mut ended = env_detail();
        ended.servers.clear();
        // Even at a terminal nobody is asked: refused as gone.
        let e = for_ssh(&Fake::new(ended), &app(), &manifest(), &pins, true, never)
            .await
            .expect_err("refused");
        assert!(e.message.contains("is gone"), "{}", e.message);
    }

    #[tokio::test]
    async fn status_shows_alone_a_record_whose_pinned_server_left_and_asks_nobody() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let key = pin_key("user-100001", "bot", "prod");
        let before = Anchor::of(APP_ID, &env_detail());
        pin(&pins, &key, &before).expect("pinned");
        let mut ended = env_detail();
        ended.servers.clear();
        let fake = Fake::new(ended);
        // At a terminal, still nobody is asked: the record alone, with why.
        match status_plan(&fake, &app(), &manifest(), &pins, true, never)
            .await
            .expect("planned")
        {
            StatusPlan::Alone { text, .. } => assert!(text.contains("is gone"), "{text}"),
            StatusPlan::Reach { .. } => panic!("reached"),
        }
        // The pin is as it was, and the commands still refuse.
        assert_eq!(pinned(&pins, &key).expect("read"), Some(before));
        let e = for_ssh(&fake, &app(), &manifest(), &pins, true, never)
            .await
            .expect_err("refused");
        assert!(e.message.contains("is gone"), "{}", e.message);
        // A record as pinned is reached.
        let fake = Fake::new(env_detail());
        let plan = status_plan(&fake, &app(), &manifest(), &pins, false, never)
            .await
            .expect("planned");
        assert!(matches!(plan, StatusPlan::Reach { .. }));
    }

    #[tokio::test]
    async fn a_pin_written_before_the_server_in_use_was_recorded_is_asked_about_again() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let mut old = Anchor::of(APP_ID, &env_detail());
        old.server = None;
        old.server_recorded = false;
        pin(&pins, &pin_key("user-100001", "bot", "prod"), &old).expect("pinned");
        // The record names no server in use: not read as the same.
        let mut ended = env_detail();
        ended.servers.clear();
        let e = for_ssh(&Fake::new(ended), &app(), &manifest(), &pins, false, never)
            .await
            .expect_err("asked about");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert!(e.message.contains("not recorded"), "{}", e.message);
    }

    #[tokio::test]
    async fn only_a_server_in_use_that_is_active_is_reached() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let mut given_back = env_detail();
        given_back.servers[0].state = account::State::from("available");
        let e = for_ssh(
            &Fake::new(given_back),
            &app(),
            &manifest(),
            &pins,
            true,
            never,
        )
        .await
        .expect_err("refused");
        assert!(
            e.message.contains("is available, not active"),
            "{}",
            e.message
        );
    }

    #[tokio::test]
    async fn a_server_in_use_gone_from_the_account_is_not_reached() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let mut gone = env_detail();
        gone.servers[0].state = account::State::Gone;
        pin(
            &pins,
            &pin_key("user-100001", "bot", "prod"),
            &Anchor::of(APP_ID, &gone),
        )
        .expect("pinned");
        let e = for_ssh(&Fake::new(gone), &app(), &manifest(), &pins, false, never)
            .await
            .expect_err("refused");
        assert!(e.message.contains("is gone"), "{}", e.message);
    }

    #[test]
    fn a_session_that_cannot_give_a_token_is_said_as_a_sign_in_with_its_reason() {
        let e = worker_error(
            "bot",
            &app(),
            &WorkerError::Session("the refresh was refused".to_owned()),
        );
        assert_eq!(e.code, Code::NotSignedIn);
        assert!(
            e.message.contains("the refresh was refused"),
            "{}",
            e.message
        );
        assert!(e.hint.is_some());
    }

    #[test]
    fn a_failed_read_of_the_accounts_id_keeps_the_exit_status_of_its_kind() {
        let e = uid_failed(&erpc_api::ApiError::Unauthorized);
        assert_eq!(e.code, Code::NotSignedIn);
        assert!(e.hint.is_some());
        let e = uid_failed(&erpc_api::ApiError::Status(503));
        assert_eq!(e.code, Code::Network);
        let e = uid_failed(&erpc_api::ApiError::Malformed("cut off".to_owned()));
        assert_eq!(e.code, Code::Network);
        let e = uid_failed(&erpc_api::ApiError::NoAccount);
        assert_eq!(e.code, Code::Failed);
    }

    #[tokio::test]
    async fn a_record_with_no_server_to_reach_or_in_an_older_form_is_not_reached() {
        let dir = tempfile::tempdir().expect("a directory");
        let pins = dir.path().join("worker_account.json");
        let mut bare = env_detail();
        bare.facts.host_key = None;
        let fake = Fake::new(bare.clone());
        pin(
            &pins,
            &pin_key("user-100001", "bot", "prod"),
            &Anchor::of(APP_ID, &bare),
        )
        .expect("pinned");
        let e = for_ssh(&fake, &app(), &manifest(), &pins, false, never)
            .await
            .expect_err("refused");
        assert!(
            e.message.contains("no address or host key"),
            "{}",
            e.message
        );
        let mut older = env_detail();
        older.facts_format = 1;
        let e = for_ssh(&Fake::new(older), &app(), &manifest(), &pins, false, never)
            .await
            .expect_err("refused");
        assert!(e.message.contains("older form"), "{}", e.message);
    }

    #[tokio::test]
    async fn whether_the_app_runs_is_written_again_after_a_busy_answer_and_refusals_are_said() {
        let fake = Fake::new(env_detail());
        fake.answers
            .borrow_mut()
            .push(refused(429, "rate_limited", json!({ "retryAfter": 0 })));
        record_running(&fake, &app(), "bot", true)
            .await
            .expect("recorded");
        assert_eq!(*fake.written.borrow(), [true, true]);
        // Running on another server of the environment.
        fake.answers
            .borrow_mut()
            .push(refused(409, "app_running_elsewhere", Value::Null));
        let e = record_running(&fake, &app(), "bot", true)
            .await
            .expect_err("refused");
        assert!(
            e.error.message.contains("another server"),
            "{}",
            e.error.message
        );
        assert!(!e.again);
        // Busy every time: given up after a few, said as the account said it.
        let fake = Fake::new(env_detail());
        for _ in 0..BUSY_TRIES {
            fake.answers.borrow_mut().push(refused(
                429,
                "rate_limited",
                json!({ "retryAfter": 0 }),
            ));
        }
        let e = record_running(&fake, &app(), "bot", false)
            .await
            .expect_err("busy");
        assert!(e.again);
        assert_eq!(
            fake.written.borrow().len(),
            usize::try_from(BUSY_TRIES).expect("small")
        );
        // No server in use: sending it again does not change that.
        let fake = Fake::new(env_detail());
        fake.answers
            .borrow_mut()
            .push(refused(404, "server_not_found", Value::Null));
        let e = record_running(&fake, &app(), "bot", false)
            .await
            .expect_err("refused");
        assert!(!e.again && e.error.message.contains("no server in use"));
    }

    #[test]
    fn stopping_says_what_is_still_charged_by_the_hour_from_the_accounts_record() {
        let said = still_charged(&env_detail(), "").expect("charged");
        assert!(
            said.starts_with("its server, its gRPC line, its "),
            "{said}"
        );
        assert!(said.contains("delete --release-server"), "{said}");
        // With no ERPC server in use the delete may not end it: a line is
        // ended on the dashboard.
        let mut own = env_detail();
        own.servers.clear();
        let said = still_charged(&own, "").expect("its lines");
        assert!(said.contains("dashboard"), "{said}");
        assert!(said.contains("asks at a terminal"), "{said}");
        let mut free = env_detail();
        free.servers.clear();
        free.lines.clear();
        assert_eq!(still_charged(&free, ""), None);
        // What is gone from the account is ended: not said as charged.
        let mut ended = env_detail();
        for line in &mut ended.lines {
            line.state = account::State::Gone;
        }
        let said = still_charged(&ended, "").expect("the server");
        assert!(said.starts_with("its server:"), "{said}");
        ended.servers[0].state = account::State::Gone;
        assert_eq!(still_charged(&ended, ""), None);
        // A server given back is not billed.
        let mut given_back = env_detail();
        given_back.lines.clear();
        given_back.servers[0].state = account::State::from("available");
        assert_eq!(still_charged(&given_back, ""), None);
        // A cancelled line is ended too.
        let mut cancelled = env_detail();
        cancelled.servers.clear();
        cancelled.lines.truncate(1);
        cancelled.lines[0].state = account::State::from("cancelled");
        assert_eq!(still_charged(&cancelled, ""), None);
    }

    #[test]
    fn a_server_not_active_is_not_reached_and_a_suspended_one_is_told_how_it_comes_back() {
        let mut suspended = env_detail();
        suspended.servers[0].state = account::State::from("suspended");
        let e = reachable(&app(), &suspended, None).expect_err("refused");
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("ERPC Credit") && hint.contains("soon"),
            "{hint}"
        );
        assert!(!hint.contains("end it"), "{hint}");
        // Resuming is never promised: the account makes it conditional.
        assert!(
            hint.contains("may resume") && !hint.contains("resumes it by itself"),
            "{hint}"
        );
        for (lang, may, sure) in [
            (
                erpc_core::i18n::Lang::Ja,
                "再開することがあります",
                "自動で再開します",
            ),
            (erpc_core::i18n::Lang::Zh, "可能会恢复", "它会自行恢复"),
            (
                erpc_core::i18n::Lang::Ru,
                "может возобновиться",
                "возобновится сам",
            ),
        ] {
            let said = crate::cli::i18n::speaking(lang, || {
                reachable(&app(), &suspended, None)
                    .expect_err("refused")
                    .hint
                    .unwrap_or_default()
            });
            assert!(
                said.contains(may) && !said.contains(sure),
                "{lang:?}: {said}"
            );
        }
        // The server is named by its id, which support is asked with.
        let e = reachable(&app(), &suspended, None).expect_err("refused");
        assert!(
            e.message.contains(&suspended.servers[0].id),
            "{}",
            e.message
        );
        // Whatever its `hourly` says: the same hint, with every way it may
        // resume.
        let mut period = suspended.clone();
        period.servers[0].hourly = false;
        let hint = reachable(&app(), &period, None)
            .expect_err("refused")
            .hint
            .unwrap_or_default();
        let hourly = reachable(&app(), &suspended, None)
            .expect_err("refused")
            .hint
            .unwrap_or_default();
        assert_eq!(hint, hourly);
        assert!(
            hint.contains("next period's charge")
                && hint.contains("unpaid invoice")
                && hint.contains("hourly charges")
                && hint.contains("soon")
                && !hint.contains("resumes by itself"),
            "{hint}"
        );
        let mut held = env_detail();
        held.servers[0].state = account::State::from("maintenance");
        let hint = reachable(&app(), &held, None)
            .expect_err("refused")
            .hint
            .unwrap_or_default();
        assert!(
            hint.contains("once it is active") && hint.contains("ERPC support"),
            "{hint}"
        );
    }

    #[test]
    fn a_server_not_active_is_said_in_every_language_with_its_id() {
        let mut suspended = env_detail();
        suspended.servers[0].state = account::State::from("suspended");
        let mut period = suspended.clone();
        period.servers[0].hourly = false;
        // In every language: the credit and the card ways, and the server's
        // id for support, paid by the hour or not, and in another state.
        let mut other = suspended.clone();
        other.servers[0].state = account::State::from("maintenance");
        for (lang, credit, card, id) in [
            (
                erpc_core::i18n::Lang::Ja,
                "次の期間分",
                "未払いの請求",
                "サーバーの id",
            ),
            (
                erpc_core::i18n::Lang::Zh,
                "下一个周期的费用",
                "未付账单",
                "服务器的 id",
            ),
            (
                erpc_core::i18n::Lang::Ru,
                "следующий период",
                "неоплаченный счёт",
                "id сервера",
            ),
        ] {
            let hint_of = |r: &EnvDetail| {
                crate::cli::i18n::speaking(lang, || {
                    reachable(&app(), r, None)
                        .expect_err("refused")
                        .hint
                        .unwrap_or_default()
                })
            };
            let said = hint_of(&period);
            assert!(
                said.contains(credit) && said.contains(card) && said.contains(id),
                "{lang:?}: {said}"
            );
            assert!(hint_of(&suspended).contains(id), "{lang:?}");
            assert!(hint_of(&other).contains(id), "{lang:?}");
            // Whatever its recorded `hourly` says, the same hint, and
            // nothing said to end or sure to resume.
            assert_eq!(hint_of(&period), hint_of(&suspended), "{lang:?}");
            for r in [&suspended, &other] {
                let said = hint_of(r);
                for end in [
                    "終了してください",
                    "自動で戻ります",
                    "请终止",
                    "会自动恢复",
                    "завершите",
                    "возобновится сам",
                ] {
                    assert!(!said.contains(end), "{lang:?} {end}: {said}");
                }
            }
        }
        for r in [&suspended, &period, &other] {
            let hint = reachable(&app(), r, None)
                .expect_err("refused")
                .hint
                .unwrap_or_default();
            assert!(hint.contains("with the server's id"), "{hint}");
        }
        // The id is shown clean.
        let mut odd = suspended.clone();
        odd.servers[0].id = "0b8e7c52\u{1b}[2K".to_owned();
        let e = reachable(&app(), &odd, None).expect_err("refused");
        assert!(
            !e.message.contains('\u{1b}') && e.message.contains("0b8e7c52"),
            "{}",
            e.message
        );
    }
}
