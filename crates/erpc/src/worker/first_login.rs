// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The first login to a server `erpc worker server start` started for an
//! environment kept in the ERPC account, before `erpc worker deploy`
//! reaches it.
//!
//! What it reads is the record: a server in use with no host key on it,
//! and no address on it but the server's own. Before the deploy goes on,
//! this:
//!
//! 1. Asks only at a terminal (`--yes` is not enough, and `--json` asks
//!    nobody): the first login fixes which host key this machine and the
//!    account trust, as trusting a record does.
//! 2. Waits for the account to say the server is ready and for its SSH to
//!    answer, within a limit; a wait that runs out says to run the deploy
//!    again, and ends nothing.
//! 3. Asks, naming the address, the host key the server offers and the key
//!    erpc logs in with.
//! 4. Reads the record again, and goes on only when it names the same
//!    server at the same address, still ready and with no host key.
//! 5. Reads the server's first login from the account, once (each read
//!    takes one of the writes the account allows, and is a line in its
//!    audit history), and logs
//!    in with its password once, to put the person's key on the server and
//!    turn password logins off ([`crate::ai::vps_access`]). An earlier attempt
//!    that got as far as the key is taken up from the key, without the
//!    password; one that finished is not logged in to again.
//! 6. Writes the address, the host key and the login name to the account's
//!    record, expecting it at the revision read, and only once password
//!    logins are off. This machine does not trust the record yet: the
//!    deploy then asks, as for any record it has not trusted, showing all
//!    that the account now has of the server.
//!
//! The password is never printed, and is held only for that login.

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::net::Ipv4Addr;

use erpc_ai::servers::{Prepared, Secured};
use erpc_api::worker::login::{FirstLogin, PasswordStatus};
use erpc_api::worker::{self as account, Code as AccountCode, EnvDetail, PutEnv, WorkerError};
use secrecy::SecretString;

use crate::cli::error::{CliError, Code};
use crate::node::common::Say;
use crate::worker::App;
use crate::worker::account as kept;

/// How long the wait for the server is paused between reads.
const PAUSE: Duration = Duration::from_secs(15);

/// How many reads the wait for the server takes at most: about ten
/// minutes, longer while SSH is slow to answer a scan.
const WAIT_TRIES: u32 = 40;

/// How many writes of the record are sent at most: the first, and again
/// after the account was busy or the record changed under the write (the
/// server and its address being the same).
const WRITE_TRIES: u32 = 3;

/// The SSH port erpc logs in on.
const PORT: u16 = 22;

/// A future the SSH side gives.
pub(crate) type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Why the SSH side could not get ready to log in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotReady {
    /// SSH does not answer yet: waited for.
    Yet(String),
    /// A reason to stop: a host key other than the one pinned at an
    /// earlier attempt, or no key of the person's to log in with.
    Stop(String),
}

/// The SSH side of the first login. The real one is
/// [`crate::ai::vps_access::AccountLogins`]; a test brings a stand-in.
pub(crate) trait Logins {
    /// The host key `ip` offers and the key erpc would log in with, and
    /// whether an earlier first login of `server` at `ip` got as far as
    /// the key. The login name is not known yet: it is left empty.
    fn prepare<'a>(&'a self, server: &'a str, ip: &'a str) -> Fut<'a, Result<Prepared, NotReady>>;

    /// The host key and login name erpc pinned for the machine offering
    /// `host_key` at `ip` when it made it key-only, if it did, whichever way
    /// it was reached.
    fn done(&self, ip: &str, host_key: &str) -> Option<(String, String)>;

    /// The first login: the key put in place, then password logins off and
    /// checked refused. `password` is the server's, or why there is none.
    fn secure<'a>(
        &'a self,
        prepared: &'a Prepared,
        server: &'a str,
        password: Result<&'a SecretString, &'a str>,
    ) -> Fut<'a, Result<Secured, String>>;
}

/// What the first login asks of the ERPC account. The signed-in session is
/// the one that reaches it; a test brings a stand-in.
pub(crate) trait Reading {
    /// Environment `env` of the app named `name`.
    async fn env(&self, name: &str, env: &str) -> Result<EnvDetail, WorkerError>;
    /// Replaces the environment's record, expecting it at the revision
    /// `body` names.
    async fn put_env(
        &self,
        name: &str,
        env: &str,
        body: &PutEnv,
    ) -> Result<account::Written<EnvDetail>, WorkerError>;
    /// The first login of server `server` of the environment.
    async fn first_login(
        &self,
        name: &str,
        env: &str,
        server: &str,
    ) -> Result<FirstLogin, WorkerError>;
}

impl Reading for kept::Signed {
    async fn env(&self, name: &str, env: &str) -> Result<EnvDetail, WorkerError> {
        kept::Account::env(self, name, env).await
    }

    async fn put_env(
        &self,
        name: &str,
        env: &str,
        body: &PutEnv,
    ) -> Result<account::Written<EnvDetail>, WorkerError> {
        kept::Account::put_env(self, name, env, body).await
    }

    async fn first_login(
        &self,
        name: &str,
        env: &str,
        server: &str,
    ) -> Result<FirstLogin, WorkerError> {
        self.server_first_login(name, env, server).await
    }
}

fn failed(message: String) -> CliError {
    CliError::new(Code::Failed, message)
}

/// The server in use of `record`, when it is to be logged in to first: one on
/// its way to ready or ready (`available`, `provisioning` or `active`), with
/// no host key on record, and no address on record other than the server's
/// own. `None` for every other record, which the deploy goes on with as
/// before: one suspended or held for maintenance is said as such there.
fn to_log_in(record: &EnvDetail) -> Option<&account::Server> {
    let server = record
        .servers
        .iter()
        .find(|s| s.slot == account::Slot::Active)?;
    let fits = matches!(
        server.state.as_str(),
        "available" | "provisioning" | "active"
    ) && record.facts.host_key.is_none()
        && record
            .facts
            .host
            .as_deref()
            .is_none_or(|host| Some(host) == server.address.as_deref());
    fits.then_some(server)
}

/// The address of `server`, when the account says it is ready and gives
/// one that is an IPv4 address.
fn ready_at(server: &account::Server) -> Option<Ipv4Addr> {
    if server.ready != Some(true) {
        return None;
    }
    server.address.as_deref()?.parse().ok()
}

/// Who answers the question.
#[derive(Clone, Copy)]
pub(crate) struct Asking {
    /// `--json`: nobody is asked.
    pub(crate) json: bool,
    /// A terminal to ask at.
    pub(crate) terminal: bool,
}

/// The first login of environment `app.env` of the app named `name`, when
/// its server in use has no host key on the account's record ([`to_log_in`]);
/// nothing for any other record. Through `api` and `logins`; `pause` is the wait between reads.
pub(crate) async fn run_with(
    api: &impl Reading,
    logins: &impl Logins,
    (app, name): (&App, &str),
    asking: Asking,
    confirm: impl FnOnce(&str) -> Result<bool, String>,
    pause: Duration,
) -> Result<(), CliError> {
    let env = app.env.as_str();
    let record = api
        .env(name, env)
        .await
        .map_err(|e| kept::worker_error(name, app, &e))?;
    let Some(server) = to_log_in(&record) else {
        return Ok(());
    };
    if asking.json || !asking.terminal {
        return Err(CliError::new(
            Code::NeedsTerminal,
            t!("worker_first_login.needs_terminal", env),
        )
        .hint(t!(
            "worker_first_login.needs_terminal_hint",
            scope = app.scope()
        )));
    }
    let say = Say { quiet: false };
    let id = server.id.clone();
    let (ip, prepared) = wait_ready(api, logins, (app, name), record, &id, pause, &say).await?;
    let done = logins.done(&ip.to_string(), &prepared.host_key);
    // One erpc made key-only before (on this machine, through either way)
    // is not logged in to again: only recorded.
    let question = if done.is_some() {
        t!(
            "worker_first_login.question_done",
            env,
            ip = ip.to_string(),
            fingerprint = kept::shown(&prepared.fingerprint)
        )
    } else {
        t!(
            "worker_first_login.question",
            env,
            ip = ip.to_string(),
            fingerprint = kept::shown(&prepared.fingerprint),
            key = kept::shown(&prepared.login_key)
        )
    };
    if !confirm(&question).map_err(failed)? {
        return Err(CliError::new(
            Code::Declined,
            t!("worker_first_login.declined"),
        ));
    }
    // Read again after the yes: the server asked about, at the address
    // asked about, still ready and still with no host key on record.
    let record = api
        .env(name, env)
        .await
        .map_err(|e| kept::worker_error(name, app, &e))?;
    let same = to_log_in(&record).filter(|s| s.id == id).and_then(ready_at) == Some(ip);
    if !same {
        return Err(failed(t!("worker_first_login.changed", env))
            .hint(t!("worker_first_login.again_hint", scope = app.scope())));
    }
    let logged_in = done.is_none();
    let (host_key, user) = if let Some(done) = done {
        done
    } else {
        let login = read_login(api, (app, name), &id).await?;
        let user = login
            .login_name()
            .ok_or_else(|| failed(t!("worker_first_login.odd_name", env)))?
            .to_owned();
        let prepared = Prepared {
            user: user.clone(),
            ..prepared
        };
        let why = no_password(&login);
        let password = login.password().ok_or(why.as_str());
        logins
            .secure(&prepared, &id, password)
            .await
            .map_err(|why| {
                failed(t!(
                    "worker_first_login.not_secured",
                    env,
                    why = kept::shown(&why)
                ))
                .hint(t!("worker_first_login.settled_hint", scope = app.scope()))
            })?;
        (prepared.host_key, user)
    };
    write_facts(api, (app, name), record, (&id, ip), (&host_key, &user)).await?;
    // Not trusted here: what the account answered may not be what was
    // written. The deploy asks, showing what the account has.
    say.line(&if logged_in {
        t!("worker_first_login.done", env, ip = ip.to_string())
    } else {
        t!("worker_first_login.recorded", env, ip = ip.to_string())
    });
    Ok(())
}

/// Waits for the account to say server `id` of `record` is ready, and for
/// its SSH to answer; gives the address and what the SSH side prepared.
async fn wait_ready(
    api: &impl Reading,
    logins: &impl Logins,
    (app, name): (&App, &str),
    mut record: EnvDetail,
    id: &str,
    pause: Duration,
    say: &Say,
) -> Result<(Ipv4Addr, Prepared), CliError> {
    let env = app.env.as_str();
    let secs = pause.as_secs().to_string();
    // At a terminal, a spinner with tips from the first round that finds
    // the server not ready until this returns ([`crate::worker::tips`]).
    let mut waiting: Option<crate::worker::tips::Busy> = None;
    for read in 1..=WAIT_TRIES {
        let server = to_log_in(&record).filter(|s| s.id == id).ok_or_else(|| {
            failed(t!("worker_first_login.changed", env))
                .hint(t!("worker_first_login.again_hint", scope = app.scope()))
        })?;
        if let Some(ip) = ready_at(server) {
            match logins.prepare(id, &ip.to_string()).await {
                Ok(prepared) => return Ok((ip, prepared)),
                Err(NotReady::Stop(why)) => {
                    return Err(failed(t!(
                        "worker_first_login.cannot_log_in",
                        env,
                        why = kept::shown(&why)
                    )));
                }
                Err(NotReady::Yet(_)) => {}
            }
        }
        if read == WAIT_TRIES {
            break;
        }
        let line = t!("worker_first_login.waiting", env, secs = secs.as_str());
        match &waiting {
            Some(waiting) => waiting.again(say, line),
            None => waiting = Some(crate::worker::tips::busy(say, line)),
        }
        tokio::time::sleep(pause).await;
        record = api
            .env(name, env)
            .await
            .map_err(|e| kept::worker_error(name, app, &e))?;
    }
    Err(failed(t!("worker_first_login.not_ready", env))
        .hint(t!("worker_first_login.again_hint", scope = app.scope())))
}

/// The server's first login from the account, read once.
async fn read_login(
    api: &impl Reading,
    (app, name): (&App, &str),
    id: &str,
) -> Result<FirstLogin, CliError> {
    let env = app.env.as_str();
    api.first_login(name, env, id).await.map_err(|e| match &e {
        WorkerError::Refused(r) if r.code == Some(AccountCode::RateLimited) => failed(t!(
            "worker_first_login.busy",
            secs = r.retry_after().unwrap_or(60).to_string()
        ))
        .hint(t!("worker_first_login.again_hint", scope = app.scope())),
        WorkerError::Refused(r) if r.code == Some(AccountCode::CredentialUnavailable) => {
            let message = if r.reason().as_deref() == Some("server_gone") {
                t!("worker_first_login.gone", env)
            } else {
                t!("worker_first_login.no_machine", env)
            };
            failed(message).hint(t!("worker_first_login.again_hint", scope = app.scope()))
        }
        WorkerError::Refused(r) if r.code == Some(AccountCode::ServerNotFound) => {
            failed(t!("worker_first_login.changed", env))
                .hint(t!("worker_first_login.again_hint", scope = app.scope()))
        }
        // A reply that could not be read is not quoted: it may hold the
        // password.
        WorkerError::Api(erpc_api::ApiError::Malformed(_)) => {
            failed(t!("worker_first_login.unreadable", env))
        }
        _ => kept::worker_error(name, app, &e),
    })
}

/// Why `login` has no password to log in with, for the person.
fn no_password(login: &FirstLogin) -> String {
    match login.password_status {
        PasswordStatus::Visible => t!("worker_first_login.no_password_empty"),
        PasswordStatus::Pending => t!("worker_first_login.no_password_pending"),
        PasswordStatus::Deleted => t!("worker_first_login.no_password_deleted"),
        _ => t!("worker_first_login.no_password_none"),
    }
}

/// Writes the address, `host_key` and `user` of server `id` at `ip` to the
/// account's record, expecting `record`'s revision. A busy account is
/// waited for; a record changed under the write is read again and written
/// again while it names the same server at the same address with no host
/// key. Each way it stops says that the key is on the server already.
async fn write_facts(
    api: &impl Reading,
    (app, name): (&App, &str),
    mut record: EnvDetail,
    (id, ip): (&str, Ipv4Addr),
    (host_key, user): (&str, &str),
) -> Result<(), CliError> {
    let env = app.env.as_str();
    let stop = |key: &str| {
        failed(match key {
            "busy" => t!("worker_first_login.not_written_busy", env),
            _ => t!("worker_first_login.not_written", env),
        })
        .hint(t!("worker_first_login.again_hint", scope = app.scope()))
    };
    // Any other failure of the account's, said with the key on the server.
    // A failed write is said as not written only when it surely was not.
    let key_in = |e: &WorkerError, sent: bool| {
        let unknown = sent && !surely_not_written(e);
        let e = kept::worker_error(name, app, e);
        let hint = e
            .hint
            .clone()
            .unwrap_or_else(|| t!("worker_first_login.again_hint", scope = app.scope()));
        let why = e.message.as_str();
        let message = if unknown {
            t!("worker_first_login.not_written_unknown", env, why)
        } else {
            t!("worker_first_login.not_written_error", env, why)
        };
        CliError { message, ..e }.hint(hint)
    };
    let mut last = "changed";
    for write in 1..=WRITE_TRIES {
        let mut facts = record.facts.clone();
        facts.host = Some(ip.to_string());
        facts.host_key = Some(host_key.to_owned());
        facts.ssh_user = Some(user.to_owned());
        facts.ssh_port = (PORT != 22).then_some(PORT);
        let body = PutEnv::new(record.revision, facts).keeping_deploy(&record);
        match api.put_env(name, env, &body).await {
            Ok(_) => return Ok(()),
            Err(WorkerError::Refused(r)) if r.code == Some(AccountCode::RateLimited) => {
                last = "busy";
                if write < WRITE_TRIES {
                    tokio::time::sleep(Duration::from_secs(r.retry_after().unwrap_or(6).min(30)))
                        .await;
                }
            }
            Err(WorkerError::Refused(r)) if r.code == Some(AccountCode::RevisionConflict) => {
                last = "changed";
                if write == WRITE_TRIES {
                    break;
                }
                record = api.env(name, env).await.map_err(|e| key_in(&e, false))?;
                let same = to_log_in(&record)
                    .filter(|s| s.id == id)
                    .and_then(|s| s.address.as_deref())
                    == Some(ip.to_string().as_str());
                if !same {
                    return Err(stop("changed"));
                }
            }
            Err(e) => return Err(key_in(&e, true)),
        }
    }
    Err(stop(last))
}

/// Whether a write that failed with `e` surely was not taken: the account
/// refused it with a code (a 4xx), the session was refused (a 401), or it
/// was never sent. Anything else may have been taken: no answer, one that
/// could not be read, a 5xx, or a refusal with no code from in front of
/// the account.
fn surely_not_written(e: &WorkerError) -> bool {
    use erpc_api::ApiError;
    match e {
        WorkerError::Refused(r) => r.code.is_some() && (400..500).contains(&r.status),
        WorkerError::Api(
            ApiError::Unauthorized
            | ApiError::NoAccount
            | ApiError::Http(erpc_auth::HttpError::Client(_)),
        )
        | WorkerError::Session(_)
        | WorkerError::Name { .. }
        | WorkerError::WalletKey { .. }
        | WorkerError::StartKey
        | WorkerError::Id => true,
        _ => false,
    }
}

/// The first login before `erpc worker deploy` of environment `app.env`,
/// kept in the account, of the app named `name`.
pub(crate) async fn before_deploy(json: bool, app: &App, name: &str) -> Result<(), CliError> {
    let signed = kept::Signed::open().await?;
    run_with(
        &signed,
        &crate::ai::vps_access::AccountLogins,
        (app, name),
        Asking {
            json,
            terminal: crate::account::session::has_terminal(),
        },
        crate::node::common::confirm,
        PAUSE,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::Path;

    use secrecy::ExposeSecret as _;
    use serde_json::{Value, json};

    use super::*;
    use crate::worker::account::stand_in::refused;

    const SERVER_ID: &str = "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60";
    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const FINGERPRINT: &str = "SHA256:made-up-100001";
    const PASSWORD: &str = "made-up-password-200002";
    const QUESTION: &str = "erpc logs in once to the server of environment prod, at 203.0.113.10, to put your key on it and turn password logins off. The host key it offers: SHA256:made-up-100001. Your key: /home/test/.ssh/id_ed25519.pub (ssh-ed25519). This starts nothing and has no price; the address and that host key then go into the ERPC account's record, and the deploy asks whether to trust what the account then has. Go on?";

    /// The record `server start` leaves: a server in use with no address
    /// or host key in the facts, ready as `ready` says.
    fn started(revision: u64, ready: bool) -> EnvDetail {
        serde_json::from_value(json!({
            "name": "prod", "revision": revision, "factsFormat": 2,
            "facts": { "desiredCores": 1, "host": null, "sshUser": null, "sshPort": null,
                "hostKey": null, "firewall": { "sshAllow": [], "appAllow": [] },
                "starting": {}, "backup": null },
            "servers": [{ "id": SERVER_ID, "slot": "active", "cores": 1, "memoryGb": 2,
                "region": "amsterdam", "hourly": true, "appRunning": false, "state": "active",
                "address": "203.0.113.10", "ready": ready }],
            "desiredCores": 1, "activeCores": 1, "coreOptions": [1, 2, 4],
            "lines": [], "refStates": { "backup": null }, "deployed": null,
            "deployedApp": null, "updatedAt": "2026-11-25T08:00:00.000Z"
        }))
        .expect("an environment")
    }

    fn login(status: &str, password: &Value, username: &str) -> FirstLogin {
        serde_json::from_value(json!({
            "username": username, "password": password,
            "passwordStatus": status, "passwordExpiresAt": null
        }))
        .expect("a first login")
    }

    /// The account: the records it gives, one per read (the last again),
    /// what it answers to the first login and to each write.
    struct Account {
        records: RefCell<VecDeque<EnvDetail>>,
        login: RefCell<Option<Result<FirstLogin, WorkerError>>>,
        writes: RefCell<VecDeque<Result<(), WorkerError>>>,
        calls: RefCell<Vec<String>>,
        written: RefCell<Vec<PutEnv>>,
        /// The read of the record (1 for the first) the account refuses, and
        /// how.
        refuse_read: Option<(usize, fn() -> WorkerError)>,
    }

    impl Account {
        fn new(records: Vec<EnvDetail>) -> Self {
            Self {
                records: RefCell::new(records.into()),
                login: RefCell::new(Some(Ok(login("visible", &json!(PASSWORD), "ubuntu")))),
                writes: RefCell::new(VecDeque::new()),
                calls: RefCell::new(Vec::new()),
                written: RefCell::new(Vec::new()),
                refuse_read: None,
            }
        }

        fn count(&self, call: &str) -> usize {
            self.calls.borrow().iter().filter(|c| *c == call).count()
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the stand-in answers at once; the account it stands in for is awaited"
    )]
    impl Reading for Account {
        async fn env(&self, _: &str, _: &str) -> Result<EnvDetail, WorkerError> {
            self.calls.borrow_mut().push("env".to_owned());
            if let Some((read, error)) = self.refuse_read
                && read == self.count("env")
            {
                return Err(error());
            }
            let mut records = self.records.borrow_mut();
            let record = if records.len() > 1 {
                records.pop_front()
            } else {
                records.front().cloned()
            };
            Ok(record.expect("a record"))
        }

        async fn put_env(
            &self,
            _: &str,
            _: &str,
            body: &PutEnv,
        ) -> Result<account::Written<EnvDetail>, WorkerError> {
            self.calls.borrow_mut().push("put_env".to_owned());
            self.written.borrow_mut().push(body.clone());
            self.writes.borrow_mut().pop_front().unwrap_or(Ok(()))?;
            let mut record = started(body.expected_revision + 1, true);
            record.facts = body.facts.clone();
            Ok(account::Written::new(false, record))
        }

        async fn first_login(&self, _: &str, _: &str, _: &str) -> Result<FirstLogin, WorkerError> {
            self.calls.borrow_mut().push("first_login".to_owned());
            self.login.borrow_mut().take().expect("read once")
        }
    }

    /// The SSH side: what `prepare` answers each time, whether a first
    /// login finished before, and what each `secure` was given.
    struct Ssh {
        prepares: RefCell<VecDeque<Result<Prepared, NotReady>>>,
        done: Option<(String, String)>,
        resumable: bool,
        secured: RefCell<Vec<(String, Result<String, String>)>>,
    }

    impl Ssh {
        fn new() -> Self {
            Self {
                prepares: RefCell::new(VecDeque::new()),
                done: None,
                resumable: false,
                secured: RefCell::new(Vec::new()),
            }
        }

        fn prepared(&self) -> Prepared {
            Prepared {
                resumable: self.resumable,
                vps_id: 0,
                ip: "203.0.113.10".to_owned(),
                user: String::new(),
                host_key: HOST_KEY.to_owned(),
                fingerprint: FINGERPRINT.to_owned(),
                login_key: "/home/test/.ssh/id_ed25519.pub (ssh-ed25519)".to_owned(),
            }
        }
    }

    impl Logins for Ssh {
        fn prepare<'a>(
            &'a self,
            server: &'a str,
            ip: &'a str,
        ) -> Fut<'a, Result<Prepared, NotReady>> {
            assert_eq!((server, ip), (SERVER_ID, "203.0.113.10"));
            let answer = self
                .prepares
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Ok(self.prepared()));
            Box::pin(async move { answer })
        }

        fn done(&self, ip: &str, host_key: &str) -> Option<(String, String)> {
            assert_eq!((ip, host_key), ("203.0.113.10", HOST_KEY));
            self.done.clone()
        }

        fn secure<'a>(
            &'a self,
            prepared: &'a Prepared,
            server: &'a str,
            password: Result<&'a SecretString, &'a str>,
        ) -> Fut<'a, Result<Secured, String>> {
            assert_eq!(server, SERVER_ID);
            let given = password
                .map(|p| p.expose_secret().to_owned())
                .map_err(ToOwned::to_owned);
            self.secured
                .borrow_mut()
                .push((prepared.user.clone(), given.clone()));
            // As the real one: with no password, only an earlier attempt's
            // key is a way in.
            let answer = match given {
                Err(why) if !prepared.resumable => Err(why),
                _ => Ok(Secured {
                    controller: Some("198.51.100.7".to_owned()),
                    sudo_needed_password: false,
                }),
            };
            Box::pin(async move { answer })
        }
    }

    fn app() -> App {
        App::at("apps/bot", "prod")
    }

    const AT_TERMINAL: Asking = Asking {
        json: false,
        terminal: true,
    };

    async fn run(
        account: &Account,
        ssh: &Ssh,
        pins: &Path,
        asking: Asking,
        confirm: impl FnOnce(&str) -> Result<bool, String>,
    ) -> Result<(), CliError> {
        let _ = pins;
        // A wait that rounds draws no spinner from a test, wherever it is
        // run from.
        crate::cli::ui::force_drawn(false);
        run_with(
            account,
            ssh,
            (&app(), "bot"),
            asking,
            confirm,
            Duration::ZERO,
        )
        .await
    }

    fn never(_: &str) -> Result<bool, String> {
        panic!("nobody is asked")
    }

    #[tokio::test]
    async fn a_started_server_is_waited_for_asked_about_logged_in_to_once_and_recorded() {
        crate::cli::ui::force_drawn(false);
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        // Not ready at the first read, then ready; ready again after the yes.
        let account = Account::new(vec![started(3, false), started(3, true), started(3, true)]);
        let ssh = Ssh::new();
        let asked = RefCell::new(String::new());
        run(&account, &ssh, &pins, AT_TERMINAL, |q| {
            asked.replace(q.to_owned());
            Ok(true)
        })
        .await
        .expect("logged in to");
        assert_eq!(asked.take(), QUESTION);
        assert_eq!(
            *account.calls.borrow(),
            ["env", "env", "env", "first_login", "put_env"]
        );
        assert_eq!(
            *ssh.secured.borrow(),
            [("ubuntu".to_owned(), Ok(PASSWORD.to_owned()))]
        );
        let written = account.written.borrow().clone();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].expected_revision, 3);
        assert_eq!(written[0].facts.host.as_deref(), Some("203.0.113.10"));
        assert_eq!(written[0].facts.host_key.as_deref(), Some(HOST_KEY));
        assert_eq!(written[0].facts.ssh_user.as_deref(), Some("ubuntu"));
        assert_eq!(written[0].facts.ssh_port, None);
        assert_eq!(written[0].facts.desired_cores, Some(1));
        // Not trusted here: nothing is pinned, and the deploy asks at a
        // terminal, showing what the account now has.
        assert!(!pins.exists());
        let mut after = started(4, true);
        after.facts = written[0].facts.clone();
        let manifest = erpc_worker::manifest::Manifest::parse(
            "name = \"bot\"\nchain = \"solana\"\n[env.prod]\naccount = true\n",
        )
        .expect("a manifest");
        let e = kept::for_ssh(
            &kept::stand_in::Fake::new(after.clone()),
            &app(),
            &manifest,
            &pins,
            false,
            never,
        )
        .await
        .expect_err("asked at a terminal only");
        assert_eq!(e.code, Code::NeedsTerminal);
        let fingerprint = erpc_ssh::HostKey::parse(HOST_KEY)
            .expect("a host key")
            .fingerprint();
        let held = kept::for_ssh(
            &kept::stand_in::Fake::new(after),
            &app(),
            &manifest,
            &pins,
            true,
            |q| {
                asked.replace(q.to_owned());
                Ok(true)
            },
        )
        .await
        .expect("trusted after a yes");
        let q = asked.take();
        assert!(
            q.contains("203.0.113.10") && q.contains(&fingerprint),
            "{q}"
        );
        let facts = &held.manifest.env["prod"];
        assert_eq!(facts.host.as_deref(), Some("203.0.113.10"));
        assert_eq!(facts.host_key.as_deref(), Some(HOST_KEY));
    }

    #[tokio::test]
    async fn a_record_erpc_has_logged_in_to_or_not_on_its_way_to_ready_is_left_to_the_deploy() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let mut known = started(3, true);
        known.facts.host = Some("203.0.113.10".to_owned());
        known.facts.host_key = Some(HOST_KEY.to_owned());
        let mut none = started(3, true);
        none.servers.clear();
        let mut elsewhere = started(3, true);
        elsewhere.facts.host = Some("198.51.100.20".to_owned());
        let mut gone = started(3, true);
        gone.servers[0].state = account::State::Gone;
        let mut suspended = started(3, true);
        suspended.servers[0].state = account::State::from("suspended");
        let mut held = started(3, true);
        held.servers[0].state = account::State::from("maintenance");
        let mut incoming = started(3, true);
        incoming.servers[0].slot = account::Slot::Incoming;
        for record in [known, none, elsewhere, gone, suspended, held, incoming] {
            let account = Account::new(vec![record]);
            let ssh = Ssh::new();
            run(&account, &ssh, &pins, AT_TERMINAL, never)
                .await
                .expect("nothing to do");
            assert_eq!(*account.calls.borrow(), ["env"]);
            assert!(ssh.secured.borrow().is_empty());
        }
        assert!(!pins.exists());
    }

    #[tokio::test]
    async fn the_first_login_is_asked_at_a_terminal_only_and_nothing_is_read_before() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        for asking in [
            Asking {
                json: true,
                terminal: true,
            },
            Asking {
                json: false,
                terminal: false,
            },
        ] {
            let account = Account::new(vec![started(3, true)]);
            let e = run(&account, &Ssh::new(), &pins, asking, never)
                .await
                .expect_err("refused");
            assert_eq!(e.code, Code::NeedsTerminal);
            assert_eq!(
                e.message,
                "the ERPC account has no host key on record for the server of environment prod yet; erpc records one only after asking at a terminal (--yes is not enough), since that decides which host key is trusted"
            );
            assert_eq!(*account.calls.borrow(), ["env"]);
        }
    }

    #[tokio::test]
    async fn a_no_a_changed_record_or_a_server_never_ready_reads_no_login() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        // A no.
        let account = Account::new(vec![started(3, true)]);
        let ssh = Ssh::new();
        let e = run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(false))
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert_eq!(*account.calls.borrow(), ["env"]);
        // Another address after the yes: nothing sent.
        let mut moved = started(3, true);
        moved.servers[0].address = Some("198.51.100.20".to_owned());
        let account = Account::new(vec![started(3, true), moved]);
        let e = run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("changed");
        assert!(
            e.message.contains("changed while erpc waited or asked"),
            "{}",
            e.message
        );
        assert_eq!(*account.calls.borrow(), ["env", "env"]);
        // Never ready: the wait runs out, and says to run the deploy again.
        // Off a drawn terminal each round that waits says so, as a line.
        crate::cli::ui::force_drawn(false);
        let _ = crate::node::common::heard::take_printed();
        let account = Account::new(vec![started(3, false)]);
        let e = run(&account, &ssh, &pins, AT_TERMINAL, never)
            .await
            .expect_err("not ready");
        assert_eq!(
            e.message,
            "the server of environment prod was not ready to log in to after about ten minutes of waiting; nothing was changed on it"
        );
        let rounds = crate::node::common::heard::take_printed();
        assert_eq!(rounds.len(), 39, "{rounds:?}");
        assert!(
            rounds.iter().all(|l| l
                == "the server of environment prod is not ready to log in to yet; asking the ERPC account again in 0 s"),
            "{rounds:?}"
        );
        assert_eq!(account.count("env"), 40);
        assert_eq!(account.count("first_login"), 0);
        assert!(ssh.secured.borrow().is_empty());
        assert!(!pins.exists());
    }

    #[tokio::test]
    async fn ssh_that_does_not_answer_yet_is_waited_for_and_another_host_key_stops_it() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let account = Account::new(vec![started(3, true)]);
        let ssh = Ssh::new();
        ssh.prepares
            .borrow_mut()
            .push_back(Err(NotReady::Yet("connection refused".to_owned())));
        run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect("logged in to");
        assert_eq!(account.count("env"), 3);
        let account = Account::new(vec![started(3, true)]);
        let ssh = Ssh::new();
        ssh.prepares
            .borrow_mut()
            .push_back(Err(NotReady::Stop("another host key".to_owned())));
        let e = run(&account, &ssh, &pins, AT_TERMINAL, never)
            .await
            .expect_err("stopped");
        assert_eq!(
            e.message,
            "erpc cannot log in to the server of environment prod: another host key"
        );
        assert_eq!(*account.calls.borrow(), ["env"]);
    }

    #[tokio::test]
    async fn the_accounts_refusals_of_the_login_are_said_and_it_is_read_once() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let cases = [
            (
                refused(429, "rate_limited", json!({ "retryAfter": 6 })),
                "the ERPC account asks to wait 6 s before the server's first login is read again; nothing was sent to the server",
            ),
            (
                refused(
                    409,
                    "credential_unavailable",
                    json!({ "reason": "server_gone" }),
                ),
                "the ERPC account says the server of environment prod is gone; it is not logged in to",
            ),
            (
                refused(409, "credential_unavailable", json!({ "reason": "no_box" })),
                "the ERPC account has no machine attached to the server of environment prod; it is not logged in to",
            ),
            (
                WorkerError::Api(erpc_api::ApiError::Malformed(format!("quoting {PASSWORD}"))),
                "the ERPC account's answer with the first login of the server of environment prod could not be read; it is not logged in to",
            ),
        ];
        for (answer, said) in cases {
            let account = Account::new(vec![started(3, true)]);
            *account.login.borrow_mut() = Some(Err(answer));
            let ssh = Ssh::new();
            let e = run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(true))
                .await
                .expect_err("refused");
            assert_eq!(e.message, said);
            assert_eq!(account.count("first_login"), 1);
            assert_eq!(account.count("put_env"), 0);
            assert!(ssh.secured.borrow().is_empty());
        }
        // A login name erpc does not use: nothing is logged in to.
        let account = Account::new(vec![started(3, true)]);
        *account.login.borrow_mut() =
            Some(Ok(login("visible", &json!(PASSWORD), "-oProxyCommand")));
        let ssh = Ssh::new();
        let e = run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("refused");
        assert!(e.message.contains("login name"), "{}", e.message);
        assert!(ssh.secured.borrow().is_empty());
        assert!(!pins.exists());
    }

    #[tokio::test]
    async fn with_no_password_only_an_earlier_attempts_key_goes_on() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let reasons = [
            (
                "pending",
                "the ERPC account has not handed its password over yet; run the deploy again in a minute",
            ),
            (
                "deleted",
                "the ERPC account has removed its password, as it does a day after handing it over, so erpc cannot make the first login; ERPC support can help",
            ),
            (
                "none",
                "the ERPC account has no password for it, so erpc cannot make the first login; ERPC support can help",
            ),
            (
                "visible",
                "the ERPC account gave an empty password for it, so erpc cannot make the first login; ERPC support can help",
            ),
        ];
        for (status, why) in reasons {
            let password = if status == "visible" {
                json!("")
            } else {
                json!(null)
            };
            // No earlier attempt: stopped with the reason, nothing written.
            let account = Account::new(vec![started(3, true)]);
            *account.login.borrow_mut() = Some(Ok(login(status, &password, "ubuntu")));
            let ssh = Ssh::new();
            let e = run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(true))
                .await
                .expect_err("stopped");
            assert_eq!(
                e.message,
                format!("the first login to the server of environment prod did not finish: {why}")
            );
            assert_eq!(account.count("put_env"), 0);
            // An earlier attempt got as far as the key: taken up from it.
            let account = Account::new(vec![started(3, true)]);
            *account.login.borrow_mut() = Some(Ok(login(status, &password, "ubuntu")));
            let ssh = Ssh {
                resumable: true,
                ..Ssh::new()
            };
            run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(true))
                .await
                .expect("taken up");
            assert_eq!(
                *ssh.secured.borrow(),
                [("ubuntu".to_owned(), Err(why.to_owned()))]
            );
            assert_eq!(account.count("put_env"), 1);
        }
    }

    #[tokio::test]
    async fn a_login_that_finished_before_is_not_made_again_and_only_recorded() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let account = Account::new(vec![started(3, true)]);
        let ssh = Ssh {
            done: Some((HOST_KEY.to_owned(), "root".to_owned())),
            ..Ssh::new()
        };
        let asked = RefCell::new(String::new());
        run(&account, &ssh, &pins, AT_TERMINAL, |q| {
            asked.replace(q.to_owned());
            Ok(true)
        })
        .await
        .expect("recorded");
        assert_eq!(
            asked.take(),
            "erpc made the server of environment prod, at 203.0.113.10, key-only before; the host key it offers: SHA256:made-up-100001. This starts nothing and has no price; the address and that host key now go into the ERPC account's record, and the deploy asks whether to trust what the account then has. Go on?"
        );
        assert_eq!(account.count("first_login"), 0);
        assert!(ssh.secured.borrow().is_empty());
        let written = account.written.borrow();
        assert_eq!(written[0].facts.ssh_user.as_deref(), Some("root"));
        assert_eq!(written[0].facts.host_key.as_deref(), Some(HOST_KEY));
    }

    #[tokio::test]
    async fn a_record_changed_under_the_write_is_written_again_without_logging_in_again() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        // Read, read after the yes, then read again after the conflict.
        let account = Account::new(vec![started(3, true), started(3, true), started(5, true)]);
        account.writes.borrow_mut().push_back(Err(refused(
            409,
            "revision_conflict",
            json!({ "currentRevision": 5 }),
        )));
        let ssh = Ssh::new();
        run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect("recorded");
        let revisions: Vec<u64> = account
            .written
            .borrow()
            .iter()
            .map(|w| w.expected_revision)
            .collect();
        assert_eq!(revisions, [3, 5]);
        assert_eq!(account.count("first_login"), 1);
        assert_eq!(ssh.secured.borrow().len(), 1);
        // Changed to another address meanwhile: not written, and said so.
        let mut moved = started(5, true);
        moved.servers[0].address = Some("198.51.100.20".to_owned());
        let account = Account::new(vec![started(3, true), started(3, true), moved]);
        account.writes.borrow_mut().push_back(Err(refused(
            409,
            "revision_conflict",
            json!({ "currentRevision": 5 }),
        )));
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("not written");
        assert!(e.message.contains("did not write"), "{}", e.message);
        assert_eq!(account.count("put_env"), 1);
    }

    #[tokio::test]
    async fn a_server_on_its_way_to_ready_or_with_its_own_address_on_record_is_logged_in_to() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let mut available = started(3, false);
        available.servers[0].state = account::State::from("available");
        let mut provisioning = started(3, false);
        provisioning.servers[0].state = account::State::from("provisioning");
        let mut own = started(3, true);
        own.facts.host = Some("203.0.113.10".to_owned());
        for first in [available, provisioning, own] {
            let account = Account::new(vec![first, started(3, true)]);
            let ssh = Ssh::new();
            run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(true))
                .await
                .expect("logged in to");
            assert_eq!(account.count("first_login"), 1);
            assert_eq!(account.count("put_env"), 1);
        }
    }

    #[tokio::test]
    async fn another_server_or_a_record_that_changed_after_the_yes_reads_no_login() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let other = "1a2b3c4d-0000-4000-8000-000000000000";
        // Another server while waiting.
        let mut swapped = started(3, true);
        swapped.servers[0].id = other.to_owned();
        let account = Account::new(vec![started(3, false), swapped.clone()]);
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, never)
            .await
            .expect_err("changed");
        assert!(
            e.message.contains("changed while erpc waited or asked"),
            "{}",
            e.message
        );
        // After the yes: another server, a server no longer ready, a host
        // key on record.
        let mut unready = started(3, true);
        unready.servers[0].ready = Some(false);
        let mut keyed = started(3, true);
        keyed.facts.host_key = Some(HOST_KEY.to_owned());
        for after in [swapped, unready, keyed] {
            let account = Account::new(vec![started(3, true), after]);
            let ssh = Ssh::new();
            let e = run(&account, &ssh, &pins, AT_TERMINAL, |_| Ok(true))
                .await
                .expect_err("changed");
            assert!(
                e.message.contains("changed while erpc waited or asked"),
                "{}",
                e.message
            );
            assert_eq!(account.count("first_login"), 0);
            assert!(ssh.secured.borrow().is_empty());
        }
        // The account no longer has the server when the login is read.
        let account = Account::new(vec![started(3, true)]);
        *account.login.borrow_mut() = Some(Err(refused(404, "server_not_found", Value::Null)));
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("changed");
        assert!(
            e.message.contains("changed while erpc waited or asked"),
            "{}",
            e.message
        );
    }

    #[tokio::test]
    async fn a_write_is_waited_for_when_busy_and_every_stop_after_the_login_says_the_key_is_in() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        // Busy once: sent again on the same record, without reading it.
        let account = Account::new(vec![started(3, true)]);
        account.writes.borrow_mut().push_back(Err(refused(
            429,
            "rate_limited",
            json!({ "retryAfter": 0 }),
        )));
        run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect("written");
        let revisions: Vec<u64> = account
            .written
            .borrow()
            .iter()
            .map(|w| w.expected_revision)
            .collect();
        assert_eq!(revisions, [3, 3]);
        assert_eq!(account.count("env"), 2);
        // Busy every time: said as busy, not as changed.
        let account = Account::new(vec![started(3, true)]);
        for _ in 0..3 {
            account.writes.borrow_mut().push_back(Err(refused(
                429,
                "rate_limited",
                json!({ "retryAfter": 0 }),
            )));
        }
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("not written");
        assert_eq!(
            e.message,
            "your key is on the server of environment prod and password logins are off, but the ERPC account stayed too busy to take its address and host key"
        );
        assert_eq!(account.count("put_env"), 3);
        // Another server after a conflict: not written again.
        let mut swapped = started(5, true);
        swapped.servers[0].id = "1a2b3c4d-0000-4000-8000-000000000000".to_owned();
        let account = Account::new(vec![started(3, true), started(3, true), swapped]);
        account.writes.borrow_mut().push_back(Err(refused(
            409,
            "revision_conflict",
            json!({ "currentRevision": 5 }),
        )));
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("not written");
        assert!(e.message.contains("did not write"), "{}", e.message);
        assert_eq!(account.count("put_env"), 1);
        // A 500: perhaps taken, said with the key on the server.
        let account = Account::new(vec![started(3, true)]);
        account
            .writes
            .borrow_mut()
            .push_back(Err(refused(500, "internal", Value::Null)));
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("not known");
        let why = kept::worker_error("bot", &app(), &refused(500, "internal", Value::Null)).message;
        assert_eq!(
            e.message,
            format!(
                "your key is on the server of environment prod and password logins are off, but whether its address and host key were written to the ERPC account's record is not known: {why}"
            )
        );
    }

    /// What fails a write, the error, and what it is said as.
    type Case = (&'static str, fn() -> WorkerError, &'static str);

    #[tokio::test]
    async fn a_failed_write_is_said_as_not_written_only_when_it_surely_was_not() {
        use erpc_api::ApiError;
        use erpc_auth::HttpError;
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let cases: Vec<Case> = vec![
            (
                "no answer",
                || {
                    WorkerError::Api(ApiError::Http(HttpError::Transport {
                        host: "user-api",
                        reason: "the connection closed".to_owned(),
                    }))
                },
                "not known",
            ),
            (
                "an unreadable answer",
                || WorkerError::Api(ApiError::Malformed("the answer broke off".to_owned())),
                "not known",
            ),
            (
                "a 502 with no code",
                || {
                    WorkerError::Refused(account::Refusal {
                        status: 502,
                        code: None,
                        message: None,
                        data: Value::Null,
                    })
                },
                "not known",
            ),
            (
                "a 400 with no code",
                || {
                    WorkerError::Refused(account::Refusal {
                        status: 400,
                        code: None,
                        message: None,
                        data: Value::Null,
                    })
                },
                "not known",
            ),
            (
                "a 503 with a code",
                || refused(503, "unavailable", Value::Null),
                "not known",
            ),
            (
                "a 403 with a code",
                || refused(403, "forbidden", Value::Null),
                "did not write",
            ),
            (
                "a 401",
                || WorkerError::Api(ApiError::Unauthorized),
                "did not write",
            ),
            (
                "no client",
                || WorkerError::Api(ApiError::Http(HttpError::Client("no TLS".to_owned()))),
                "did not write",
            ),
            (
                "no session",
                || WorkerError::Session("the sign-in could not be renewed".to_owned()),
                "did not write",
            ),
        ];
        for (what, error, said) in cases {
            let account = Account::new(vec![started(3, true)]);
            account.writes.borrow_mut().push_back(Err(error()));
            let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
                .await
                .expect_err(what);
            let why = kept::worker_error("bot", &app(), &error()).message;
            let expected = if said == "not known" {
                format!(
                    "your key is on the server of environment prod and password logins are off, but whether its address and host key were written to the ERPC account's record is not known: {why}"
                )
            } else {
                format!(
                    "your key is on the server of environment prod and password logins are off, but this run did not write its address and host key to the ERPC account's record: {why}"
                )
            };
            assert_eq!(e.message, expected, "{what}");
            assert_eq!(account.count("put_env"), 1, "{what}");
        }
    }

    #[tokio::test]
    async fn a_read_after_a_refused_write_that_gets_no_answer_says_not_written() {
        use erpc_api::ApiError;
        use erpc_auth::HttpError;
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let mut account = Account::new(vec![started(3, true)]);
        account.refuse_read = Some((3, || {
            WorkerError::Api(ApiError::Http(HttpError::Transport {
                host: "user-api",
                reason: "the connection closed".to_owned(),
            }))
        }));
        account.writes.borrow_mut().push_back(Err(refused(
            409,
            "revision_conflict",
            json!({ "currentRevision": 5 }),
        )));
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("not written");
        assert!(
            e.message.starts_with("your key is on the server of environment prod and password logins are off, but this run did not write its address and host key to the ERPC account's record: "),
            "{}",
            e.message
        );
        assert_eq!(account.count("put_env"), 1);
    }

    #[tokio::test]
    async fn the_last_deploy_on_record_is_carried_by_the_write() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let mut deployed = started(3, true);
        deployed.deployed = Some(account::Deployed::new("r1", "2026-11-25T08:00:00.000Z"));
        let account = Account::new(vec![deployed]);
        run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect("written");
        assert_eq!(
            account.written.borrow()[0]
                .deployed
                .as_ref()
                .map(|d| d.release.as_str()),
            Some("r1")
        );
    }

    #[tokio::test]
    async fn after_a_conflict_a_read_that_fails_or_a_host_key_on_record_says_the_key_is_in() {
        let dir = tempfile::tempdir().expect("dir");
        let pins = dir.path().join("worker_account.json");
        let conflict = || {
            Err(refused(
                409,
                "revision_conflict",
                json!({ "currentRevision": 5 }),
            ))
        };
        // The read after the conflict fails: said with the key on the
        // server, and not written again.
        let mut account = Account::new(vec![started(3, true)]);
        account.refuse_read = Some((3, || refused(503, "unavailable", Value::Null)));
        account.writes.borrow_mut().push_back(conflict());
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("not written");
        assert!(
            e.message.starts_with("your key is on the server of environment prod and password logins are off, but this run did not write its address and host key to the ERPC account's record: "),
            "{}",
            e.message
        );
        assert_eq!(account.count("put_env"), 1);
        // A host key on record by then: not written over.
        let mut keyed = started(5, true);
        keyed.facts.host_key = Some(HOST_KEY.to_owned());
        let account = Account::new(vec![started(3, true), started(3, true), keyed]);
        account.writes.borrow_mut().push_back(conflict());
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("not written");
        assert!(e.message.contains("did not write"), "{}", e.message);
        assert_eq!(account.count("put_env"), 1);
        // Three conflicts: three writes, and no read after the last.
        let account = Account::new(vec![started(3, true)]);
        for _ in 0..3 {
            account.writes.borrow_mut().push_back(conflict());
        }
        let e = run(&account, &Ssh::new(), &pins, AT_TERMINAL, |_| Ok(true))
            .await
            .expect_err("not written");
        assert!(e.message.contains("did not write"), "{}", e.message);
        assert_eq!(account.count("put_env"), 3);
        assert_eq!(account.count("env"), 4);
    }
}
