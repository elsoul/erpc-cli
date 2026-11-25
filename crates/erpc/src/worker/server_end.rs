// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker server end`: ends the server an environment kept in the
//! ERPC account uses, when it is the only server on the environment's
//! record and the environment has no line that is not ended, then clears
//! its address, host key, login name and SSH port from the record, so that
//! `erpc worker server start` can start another for it. A line bought as
//! part of a Bundle counts: `erpc worker delete --release-server` is the
//! command that ends the lines and the server together.
//!
//! The address cleared is only ever the server's own: the one the account
//! gives for it, or, for a server gone since (the account gives none
//! then), the one this machine recorded for that very server of that app
//! before it set out to end it. A record whose address is neither (one of
//! the person's own, or a gone server's this machine did not record) is
//! refused, with nothing sent.
//!
//! The account takes an ended server off the record and keeps the address
//! erpc wrote in its facts; erpc clears it. Before the end is sent, this
//! machine records which server of which app it sets out to end, at which
//! address. A record with no server and that address on it is cleared only
//! from that record: so the same command finishes a run that stopped after
//! the end. It is no record of trust: nothing reached over SSH reads it.
//!
//! The yes is given on the record read before the question; the record is
//! read and decided on again after it, and the end is sent only for the
//! same server at the same address. After any answer to the end but this
//! run's own 200, the record is read again, and what is said comes from
//! it: the server still on it, no longer on it (the clear goes on), or not
//! known (the read failed). The same holds for the clear.

use core::time::Duration;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use erpc_api::worker::money::Ended;
use erpc_api::worker::{self as account, Code as AccountCode, EnvDetail, PutEnv, WorkerError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::account::commands::Outcome;
use crate::cli::error::{CliError, Code};
use crate::node::common::Say;
use crate::worker::App;
use crate::worker::account::{self as kept, Account};

fn failed(message: String) -> CliError {
    CliError::new(Code::Failed, message)
}

/// How many writes the clear sends at most.
const WRITE_TRIES: usize = 3;

/// The longest wait a busy answer is given.
const BUSY_WAIT_MAX: u64 = 30;

/// Whether something on the record is not ended.
fn live(state: &account::State) -> bool {
    *state != account::State::Gone && state.as_str() != "cancelled"
}

// ------------------------------------------------- what this machine ends

/// The server this machine ends for an environment, recorded before the
/// end is sent: so that the same command, run again after the account took
/// the server off the record, clears its address. Not a record of trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Ending {
    /// The app's id in the account: made again, the app has another.
    pub(crate) app_id: String,
    /// The account's id of the server.
    pub(crate) server: String,
    /// The address the record named for it, when it named one.
    pub(crate) host: Option<String>,
}

/// What is being ended, by environment.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Endings {
    #[serde(default)]
    ending: BTreeMap<String, Ending>,
}

fn load(path: &Path) -> Result<Endings, String> {
    let unreadable =
        |error: String| t!("worker_server_end.unreadable", path = path.display(), error);
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| unreadable(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Endings::default()),
        Err(e) => Err(unreadable(e.to_string())),
    }
}

/// What `path` records as being ended for `key`.
fn ending(path: &Path, key: &str) -> Result<Option<Ending>, String> {
    Ok(load(path)?.ending.remove(key))
}

/// Records `what` for `key` in `path`, or forgets it (`None`), under the
/// lock.
fn keep_ending(path: &Path, key: &str, what: Option<&Ending>) -> Result<(), String> {
    if what.is_none() && !path.exists() {
        return Ok(());
    }
    erpc_core::private_file::locked(path, || {
        let mut all = load(path)?;
        match what {
            Some(what) => {
                all.ending.insert(key.to_owned(), what.clone());
            }
            None => {
                if all.ending.remove(key).is_none() {
                    return Ok(());
                }
            }
        }
        let text = serde_json::to_vec_pretty(&all).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)
    })
}

// ------------------------------------------------- what a run does

/// What a run does with the record it read.
#[derive(Debug, Clone, PartialEq)]
enum Plan {
    /// End the server in use. `host` is the record's address, the server's
    /// own (none when the record names none).
    End {
        server: account::Server,
        host: Option<String>,
    },
    /// Clear the address `host` of a server this machine set out to end
    /// earlier, no longer on the record.
    Clear { host: String },
    /// Put away what this machine kept of a server it set out to end,
    /// when the record holds neither it nor an address.
    Tidy,
}

/// The address the account gives for `server`, read as IPv4.
fn address_of(server: &account::Server) -> Option<Ipv4Addr> {
    server.address.as_deref()?.parse().ok()
}

/// What a run does with `record` of the app `app_id`, given what this
/// machine recorded as being ended (`earlier`). The refusals change
/// nothing.
fn decide(
    (record, open): (&EnvDetail, usize),
    earlier: Option<&Ending>,
    app_id: &str,
    app: &App,
) -> Result<Plan, CliError> {
    let env = app.env.as_str();
    let scope = app.scope();
    let in_use = record
        .servers
        .iter()
        .find(|s| s.slot == account::Slot::Active);
    let others = record
        .servers
        .iter()
        .filter(|s| s.slot != account::Slot::Active)
        .count();
    if others > 0 {
        return Err(failed(t!("worker_server_end.other_servers", env))
            .hint(t!("worker_server_end.status_hint", scope = &scope)));
    }
    let ours = |host: Option<&str>| {
        earlier.is_some_and(|e| e.app_id == app_id && e.host.as_deref() == host)
    };
    let Some(server) = in_use else {
        let Some(host) = record.facts.host.clone() else {
            return if earlier.is_some_and(|e| e.app_id == app_id) {
                Ok(Plan::Tidy)
            } else {
                Err(failed(t!("worker_server_end.no_server", env)))
            };
        };
        return if ours(Some(&host)) {
            Ok(Plan::Clear { host })
        } else {
            Err(failed(t!(
                "worker_server_end.address_only",
                env,
                host = crate::storage::clean(&host)
            )))
        };
    };
    let lines = record.lines.iter().filter(|l| live(&l.state)).count();
    if lines > 0 {
        return Err(failed(t!("worker_server_end.lines_live", env, lines))
            .hint(t!("worker_server_end.lines_live_hint", scope = &scope)));
    }
    if open > 0 {
        return Err(failed(t!("worker_server_end.open_starts", env, open))
            .hint(t!("worker_server_end.status_hint", scope = &scope)));
    }
    if live(&server.state) && !server.hourly {
        return Err(failed(t!("worker_server_end.not_hourly", env)));
    }
    // Only the server's own address is ever cleared: the one the account
    // gives for it, or, for a server gone since (the account gives none
    // then), the one this machine recorded for that very server of that
    // app before it set out to end it.
    let recorded = !live(&server.state)
        && earlier.is_some_and(|e| {
            e.app_id == app_id && e.server == server.id && e.host == record.facts.host
        });
    if let Some(host) = &record.facts.host
        && !recorded
        && host
            .parse::<Ipv4Addr>()
            .ok()
            .is_none_or(|h| Some(h) != address_of(server))
    {
        let given = address_of(server).map_or_else(
            || t!("worker_server_end.no_address_given"),
            |a| a.to_string(),
        );
        return Err(failed(t!(
            "worker_server_end.not_its_address",
            env,
            host = crate::storage::clean(host),
            given
        ))
        .hint(t!("worker_server_end.status_hint", scope = &scope)));
    }
    Ok(Plan::End {
        server: server.clone(),
        host: record.facts.host.clone(),
    })
}

/// Who says yes to the end, which cannot be undone.
#[derive(Clone, Copy)]
pub(crate) struct Asking {
    /// `--yes`.
    pub(crate) yes: bool,
    /// `--json`: nobody is asked.
    pub(crate) json: bool,
    /// A terminal to ask at.
    pub(crate) terminal: bool,
}

/// What the end keeps on this machine, and puts away after.
pub(crate) struct Local<'a> {
    /// This machine's record of what it trusts.
    pub(crate) pins: PathBuf,
    /// The key the environment is kept under in it, and in `endings`.
    pub(crate) pin_key: String,
    /// What is being ended ([`Ending`]).
    pub(crate) endings: PathBuf,
    /// The other environments on this machine's list that are, or may be,
    /// on the server at an address, by name.
    pub(crate) sharing: &'a dyn Fn(&str) -> Result<crate::worker::remote::Sharing, CliError>,
}

/// The server, said for the question: its size and region, as far as the
/// record has them.
fn server_said(server: &account::Server) -> String {
    let size = match (server.cores, server.memory_gb) {
        (Some(cores), Some(memory)) => Some(t!("worker_account.status.size", cores, memory)),
        (Some(cores), None) => Some(t!("worker_account.status.cores", cores)),
        _ => None,
    };
    let region = server.region.as_deref().map(crate::storage::clean);
    match (size, region) {
        (Some(size), Some(region)) => t!("worker_server_end.said_sized_in", size, region),
        (Some(size), None) => size,
        (None, Some(region)) => t!("worker_server_end.said_in", region),
        (None, None) => t!("worker_server_end.said_plain"),
    }
}

/// Asks about the end of `server`: at a terminal, or not at all under
/// `--yes`. What this machine's list may have on it, by the address the
/// account gives for it, is named in the question, and then only a
/// terminal will do; a server with no address given is compared with
/// nothing.
fn ask(
    server: &account::Server,
    local: &Local<'_>,
    asking: Asking,
    (app, name): (&App, &str),
    confirm: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<(), CliError> {
    let env = app.env.as_str();
    let scope = app.scope();
    // The server's own address, which the record's is when it names one.
    let sharing = match address_of(server) {
        Some(at) => (local.sharing)(&at.to_string())?,
        None => crate::worker::remote::Sharing::default(),
    };
    let what = server_said(server);
    let question = if live(&server.state) {
        t!("worker_server_end.question", env, app = name, what)
    } else {
        t!("worker_server_end.question_gone", env, app = name)
    };
    if !sharing.named.is_empty() {
        let others = sharing.named.join(&t!("worker_account.list_sep"));
        if asking.yes || asking.json || !asking.terminal {
            let code = if asking.yes {
                Code::Usage
            } else {
                Code::NeedsTerminal
            };
            return Err(
                CliError::new(code, t!("worker_server_end.shared", env, others)).hint(
                    if sharing.unread {
                        t!("worker_server_end.shared_unread_hint", scope = &scope)
                    } else {
                        t!("worker_server_end.shared_hint", scope = &scope)
                    },
                ),
            );
        }
        let note = t!("worker_server_end.shared_note", others);
        return said_yes(&format!("{note} {question}"), confirm);
    }
    if asking.yes {
        return Ok(());
    }
    if asking.json || !asking.terminal {
        return Err(
            CliError::new(Code::NeedsTerminal, t!("worker_server_end.needs_yes", env))
                .hint(t!("worker_server_end.needs_yes_hint", scope = &scope)),
        );
    }
    said_yes(&question, confirm)
}

fn said_yes(
    question: &str,
    confirm: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<(), CliError> {
    if confirm(question).map_err(failed)? {
        Ok(())
    } else {
        Err(CliError::new(
            Code::Declined,
            t!("worker_server_end.declined"),
        ))
    }
}

/// The wait a busy answer `r` is given: what it asks for, else `pause`,
/// and never more than [`BUSY_WAIT_MAX`].
fn busy_wait(r: &account::Refusal, pause: Duration) -> Duration {
    r.retry_after()
        .map_or(pause, Duration::from_secs)
        .min(Duration::from_secs(BUSY_WAIT_MAX))
}

/// Why `e` failed, said in erpc's words: a refusal by its status, code and
/// reason, never by the account's own text (which may say to end
/// something); any other failure as erpc says it.
fn why(e: &WorkerError, (app, name): (&App, &str)) -> CliError {
    match e {
        WorkerError::Refused(r) => {
            let code = r
                .code
                .as_ref()
                .map_or_else(|| "none".to_owned(), |c| crate::storage::clean(c.as_str()));
            let status = r.status;
            failed(match r.reason() {
                Some(reason) => t!("worker_server_end.refused_why_reason", status, code, reason),
                None => t!("worker_server_end.refused_why", status, code),
            })
        }
        _ => kept::worker_error(name, app, e),
    }
}

/// What the account's answer `e` to the end of a server still on the
/// record (as `state`) is said as, with what to do.
fn still_there(e: &WorkerError, state: &account::State, (app, name): (&App, &str)) -> CliError {
    let env = app.env.as_str();
    let scope = app.scope();
    let why = why(e, (app, name));
    let state = crate::storage::clean(state.as_str());
    let reason = match e {
        WorkerError::Refused(r) if r.code == Some(AccountCode::EndRefused) => r.reason(),
        _ => None,
    };
    let hint = match reason.as_deref() {
        Some("not_hourly") => Some(t!("worker_server_end.not_hourly_hint")),
        Some("operation_in_progress") => {
            let seconds = match e {
                WorkerError::Refused(r) => r.retry_after().unwrap_or(30),
                _ => 30,
            };
            Some(t!("worker_server_end.busy_hint", scope = &scope, seconds))
        }
        _ if matches!(e, WorkerError::Refused(_)) => {
            Some(t!("worker_server_end.status_hint", scope = &scope))
        }
        _ => why.hint.clone(),
    };
    let e = failed(t!(
        "worker_server_end.still_there",
        env,
        state,
        why = why.message.as_str()
    ));
    match hint {
        Some(hint) => e.hint(hint),
        None => e,
    }
}

/// Sends the end of `server`, and reads the record after it: from this
/// run's own 200, or read again after any other answer. The record with
/// the server off it, and whether it was this run's 200; or why the run
/// stops.
async fn end(
    api: &impl Account,
    server: &account::Server,
    (app, name): (&App, &str),
) -> Result<(EnvDetail, bool), CliError> {
    let env = app.env.as_str();
    let scope = app.scope();
    let answer = api
        .end_server(name, env, &account::Slot::Active, &server.id)
        .await;
    let error = match answer {
        Ok(Ended::Done(after)) => return Ok((*after, true)),
        Ok(_) => None,
        Err(e) => Some(e),
    };
    let now = match api.env(name, env).await {
        Ok(now) => now,
        Err(read) => {
            let why = match &error {
                Some(e) => why(e, (app, name)).message,
                None => why(&read, (app, name)).message,
            };
            return Err(failed(t!("worker_server_end.end_unknown", env, why))
                .hint(t!("worker_server_end.status_hint", scope = &scope)));
        }
    };
    if let Some(still) = now.servers.iter().find(|s| s.id == server.id) {
        return Err(match &error {
            Some(e) => still_there(e, &still.state, (app, name)),
            None => failed(t!(
                "worker_server_end.pending",
                env,
                state = crate::storage::clean(still.state.as_str())
            ))
            .hint(t!("worker_server_end.again_hint", scope = &scope)),
        });
    }
    if !now.servers.is_empty() {
        return Err(failed(t!("worker_server_end.changed", env))
            .hint(t!("worker_server_end.status_hint", scope = &scope)));
    }
    Ok((now, false))
}

/// The facts of `record` with the server's address, host key and login
/// cleared.
fn cleared(record: &EnvDetail) -> PutEnv {
    let mut facts = record.facts.clone();
    facts.host = None;
    facts.host_key = None;
    facts.ssh_user = None;
    facts.ssh_port = None;
    PutEnv::new(record.revision, facts).keeping_deploy(record)
}

/// What became of the address a run set out to clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Address {
    /// This run's write of the record without it was answered.
    Cleared,
    /// The record, as read, no longer holds it.
    Gone,
}

/// Clears the address `host` from `record`, a record with no server on
/// it: written at the revision read, after a busy answer again, and after
/// a revision conflict again while the record, read again, holds that
/// address and no server; after any other failure, said from the record
/// read again.
async fn clear(
    api: &impl Account,
    mut record: EnvDetail,
    host: &str,
    (app, name): (&App, &str),
    pause: Duration,
) -> Result<Address, CliError> {
    let env = app.env.as_str();
    let scope = app.scope();
    let shown = crate::storage::clean(host);
    let changed = || {
        failed(t!(
            "worker_server_end.clear_changed",
            env,
            host = shown.as_str()
        ))
        .hint(t!("worker_server_end.status_hint", scope = &scope))
    };
    if !record.servers.is_empty() {
        return Err(changed());
    }
    match record.facts.host.as_deref() {
        None => return Ok(Address::Gone),
        Some(at) if at != host => return Err(changed()),
        Some(_) => {}
    }
    let mut write = 0;
    loop {
        write += 1;
        let Err(e) = api.put_env(name, env, &cleared(&record)).await else {
            return Ok(Address::Cleared);
        };
        if let WorkerError::Refused(r) = &e
            && r.code == Some(AccountCode::RateLimited)
            && write < WRITE_TRIES
        {
            tokio::time::sleep(busy_wait(r, pause)).await;
            continue;
        }
        let why = why(&e, (app, name)).message;
        let Ok(now) = api.env(name, env).await else {
            return Err(failed(t!("worker_server_end.clear_unknown", env, why))
                .hint(t!("worker_server_end.status_hint", scope = &scope)));
        };
        if !now.servers.is_empty() {
            return Err(changed());
        }
        match now.facts.host.as_deref() {
            None => return Ok(Address::Gone),
            Some(at) if at != host => return Err(changed()),
            Some(_) => {}
        }
        let conflict =
            matches!(&e, WorkerError::Refused(r) if r.code == Some(AccountCode::RevisionConflict));
        if !conflict || write == WRITE_TRIES {
            return Err(failed(t!(
                "worker_server_end.clear_failed",
                env,
                host = shown.as_str(),
                why
            ))
            .hint(t!("worker_server_end.clear_hint", scope = &scope)));
        }
        record = now;
    }
}

/// The server in use as decided on after the yes (`again`), when it is
/// the one asked about: the same server, as live or as gone as it was,
/// at the same address.
fn asked_about(
    again: Plan,
    server: &account::Server,
    host: Option<&String>,
    app: &App,
) -> Result<account::Server, CliError> {
    match again {
        Plan::End { server: s, host: h }
            if s.id == server.id && h.as_ref() == host && live(&s.state) == live(&server.state) =>
        {
            Ok(s)
        }
        _ => Err(failed(t!(
            "worker_server_end.changed_asked",
            env = app.env.as_str()
        ))
        .hint(t!("worker_server_end.status_hint", scope = &app.scope()))),
    }
}

/// The end, through `api`: read and decided, asked, read and decided
/// again, recorded here, ended in the account, the address cleared from
/// the record, and this machine's records of it put away. `pause` is the
/// wait after a busy answer that names none.
pub(crate) async fn run_with(
    api: &impl Account,
    (app, name): (&App, &str),
    local: &Local<'_>,
    asking: Asking,
    confirm: impl FnOnce(&str) -> Result<bool, String>,
    pause: Duration,
) -> Result<(Value, String), CliError> {
    let env = app.env.as_str();
    let read = || async {
        let record = api
            .env(name, env)
            .await
            .map_err(|e| kept::worker_error(name, app, &e))?;
        kept::current_format(app, &record)?;
        let open = api
            .open_starts(name, env)
            .await
            .map_err(|e| kept::worker_error(name, app, &e))?;
        Ok::<_, CliError>((record, open))
    };
    let (record, open) = read().await?;
    let app_id = api
        .app(name)
        .await
        .map_err(|e| kept::worker_error(name, app, &e))?
        .id;
    // Unreadable is read as nothing being ended: an address is then not
    // cleared.
    let earlier = ending(&local.endings, &local.pin_key).ok().flatten();
    let plan = decide((&record, open), earlier.as_ref(), &app_id, app)?;
    let mut text = Vec::new();
    let (after, host, server, ours) = match plan {
        Plan::End { server, host } => {
            ask(&server, local, asking, (app, name), confirm)?;
            // The yes was given on the record read before the question:
            // the end goes only to the same server at the same address.
            let (now, open) = read().await?;
            let again = decide((&now, open), earlier.as_ref(), &app_id, app)?;
            let server = asked_about(again, &server, host.as_ref(), app)?;
            let what = Ending {
                app_id,
                server: server.id.clone(),
                host: host.clone(),
            };
            keep_ending(&local.endings, &local.pin_key, Some(&what))
                .map_err(|error| failed(t!("worker_server_end.not_recorded", env, error)))?;
            // Said on stderr under --json too: it cannot be undone.
            Say { quiet: false }.line(&t!("worker_server_end.ending", env));
            let (after, ours) = end(api, &server, (app, name)).await?;
            text.push(match (ours, live(&server.state)) {
                (true, true) => t!("worker_server_end.ended", env),
                (true, false) => t!("worker_server_end.taken_off", env),
                (false, _) => t!("worker_server_end.off_record", env),
            });
            (Some(after), host, Some(server), ours)
        }
        Plan::Clear { host } => {
            text.push(t!("worker_server_end.ended_before", env));
            (Some(record), Some(host), None, false)
        }
        Plan::Tidy => {
            text.push(t!("worker_server_end.tidied", env));
            (None, None, None, false)
        }
    };
    let address = match (after, &host) {
        (Some(after), Some(host)) => match clear(api, after, host, (app, name), pause)
            .await
            .inspect_err(|_| {
                // What the end did is said even when the clear stops.
                if let Some(first) = text.first() {
                    Say { quiet: false }.line(first);
                }
            })? {
            Address::Cleared => {
                text.push(t!("worker_server_end.cleared"));
                "cleared"
            }
            Address::Gone => {
                text.push(t!("worker_server_end.address_gone"));
                "already_gone"
            }
        },
        _ => "none",
    };
    let forgotten = keep_ending(&local.endings, &local.pin_key, None)
        .and_then(|()| kept::unpin(&local.pins, &local.pin_key));
    if let Err(error) = &forgotten {
        text.push(format!(
            "warning: {}",
            t!("worker_server_end.not_forgotten", error)
        ));
    }
    let answer = json!({
        "env": env,
        "account": true,
        "ended": ours && server.as_ref().is_some_and(|s| live(&s.state)),
        "taken_off": ours,
        "server": server.map(|s| s.id),
        "address": address,
        "forgotten_here": forgotten.is_ok(),
    });
    Ok((answer, text.join("\n")))
}

/// The end, signed in, with this machine's terminal.
async fn run(json: bool, app: &App, yes: bool) -> Result<(Value, String), CliError> {
    let (path, m) = crate::worker::load(&app.dir)?;
    if !kept::kept_there(&m, &app.env) {
        return Err(CliError::new(
            Code::Usage,
            t!("worker_server_end.in_erpc_toml", env = app.env.as_str()),
        ));
    }
    let signed = kept::Signed::open().await?;
    let uid = signed.uid().await?;
    let sharing = |host: &str| crate::worker::remote::sharing_host(&path, &m, &app.env, host);
    let local = Local {
        pins: kept::pins_path().map_err(failed)?,
        pin_key: kept::pin_key(&uid, &m.name, &app.env),
        endings: crate::account::session::beside_config("worker_server_end.json")
            .map_err(failed)?,
        sharing: &sharing,
    };
    run_with(
        &signed,
        (app, &m.name),
        &local,
        Asking {
            yes,
            json,
            terminal: crate::account::session::has_terminal(),
        },
        crate::node::common::confirm,
        Duration::from_secs(6),
    )
    .await
}

/// `erpc worker server end`.
pub(crate) async fn end_server(json: bool, app: &App, yes: bool) -> Outcome {
    match run(json, app, yes).await {
        Ok((answer, text)) => crate::worker::remote::done(json, &answer, text),
        Err(e) => e.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use serde_json::json;

    use super::*;
    use crate::worker::account::stand_in::{Fake, refused};

    const APP_ID: &str = "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13";
    const SERVER: &str = "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60";
    const HOST: &str = "203.0.113.10";
    const NOW: Duration = Duration::ZERO;

    fn app() -> App {
        App::at("apps/bot", "prod")
    }

    /// An environment with one server in use at [`HOST`], recorded by a
    /// first login, and no line.
    fn record() -> EnvDetail {
        serde_json::from_value(json!({
            "name": "prod", "revision": 7, "factsFormat": 2,
            "facts": { "desiredCores": null, "host": HOST, "sshUser": "erpc",
                "sshPort": 2222, "hostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEYEXAMPLEKEYEXAMPLEKEYEXAMPLEKEY01",
                "firewall": { "sshAllow": [], "appAllow": [] }, "starting": {}, "backup": null },
            "servers": [{ "id": SERVER, "slot": "active",
                "cores": 2, "memoryGb": 8, "region": "amsterdam", "hourly": true,
                "appRunning": true, "state": "active", "address": HOST, "ready": true }],
            "desiredCores": null, "activeCores": 2, "coreOptions": [],
            "lines": [], "deployed": null, "deployedApp": null
        }))
        .map(|mut r: EnvDetail| {
            r.deployed = Some(account::Deployed::new("r1", "2026-11-25T08:00:00.000Z"));
            r
        })
        .expect("a record")
    }

    fn with(f: impl FnOnce(&mut EnvDetail)) -> EnvDetail {
        let mut r = record();
        f(&mut r);
        r
    }

    fn line(state: &str, bundle_part: bool) -> account::Line {
        serde_json::from_value(
            json!({ "id": "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314", "kind": "grpc",
            "hourly": true, "bundlePart": bundle_part, "pending": false, "state": state,
            "endpoint": null }),
        )
        .expect("a line")
    }

    /// The record after the end: the server off it, its address kept.
    fn off() -> EnvDetail {
        with(|r| {
            r.servers.clear();
            r.revision = 8;
        })
    }

    struct Here {
        dir: tempfile::TempDir,
    }

    impl Here {
        fn new() -> Self {
            let here = Self {
                dir: tempfile::tempdir().expect("dir"),
            };
            kept::pin(&here.pins(), "k", &kept::Anchor::of(APP_ID, &record())).expect("pinned");
            here
        }

        fn pins(&self) -> PathBuf {
            self.dir.path().join("worker_account.json")
        }

        fn endings(&self) -> PathBuf {
            self.dir.path().join("worker_server_end.json")
        }

        fn local(&self) -> Local<'_> {
            Local {
                pins: self.pins(),
                pin_key: "k".to_owned(),
                endings: self.endings(),
                sharing: &alone,
            }
        }

        fn ending(&self) -> Option<Ending> {
            ending(&self.endings(), "k").expect("read")
        }

        fn pinned(&self) -> bool {
            kept::pinned(&self.pins(), "k").expect("read").is_some()
        }
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "it stands in for the list, which can fail to be read"
    )]
    fn alone(_: &str) -> Result<crate::worker::remote::Sharing, CliError> {
        Ok(crate::worker::remote::Sharing::default())
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "it stands in for the list, which can fail to be read"
    )]
    /// Another app on the server at [`HOST`], and nothing elsewhere.
    fn shared(at: &str) -> Result<crate::worker::remote::Sharing, CliError> {
        Ok(if at == HOST {
            crate::worker::remote::Sharing::named(vec!["bot (staging)".to_owned()])
        } else {
            crate::worker::remote::Sharing::default()
        })
    }

    const AT_TERMINAL: Asking = Asking {
        yes: false,
        json: false,
        terminal: true,
    };

    fn never(_: &str) -> Result<bool, String> {
        panic!("nobody is to be asked")
    }

    async fn run(
        fake: &Fake,
        local: &Local<'_>,
        asking: Asking,
    ) -> Result<(Value, String), CliError> {
        run_with(fake, (&app(), "bot"), local, asking, |_| Ok(true), NOW).await
    }

    fn ends(fake: &Fake) -> usize {
        fake.log
            .borrow()
            .iter()
            .filter(|l| l.starts_with("end "))
            .count()
    }

    fn writes(fake: &Fake) -> usize {
        fake.log.borrow().iter().filter(|l| *l == "put_env").count()
    }

    fn ours() -> Ending {
        Ending {
            app_id: APP_ID.to_owned(),
            server: SERVER.to_owned(),
            host: Some(HOST.to_owned()),
        }
    }

    #[test]
    fn what_is_ended_is_decided_by_the_record_and_what_this_machine_was_ending() {
        let decide =
            |r: &EnvDetail, earlier: Option<&Ending>| decide((r, 0), earlier, APP_ID, &app());
        let refused = |r: &EnvDetail, earlier: Option<&Ending>| {
            decide(r, earlier).expect_err("refused").message
        };
        // The one server in use, with its address on record.
        assert_eq!(
            decide(&record(), None).expect("ended"),
            Plan::End {
                server: record().servers[0].clone(),
                host: Some(HOST.to_owned())
            }
        );
        // Another server on record, coming in or gone: refused.
        let mut other = record().servers[0].clone();
        other.slot = account::Slot::from("incoming");
        other.id = "1a2b3c4d-0000-4000-8000-000000000000".to_owned();
        let two = with(|r| r.servers.push(other.clone()));
        assert_eq!(
            refused(&two, None),
            "environment prod's record names a server besides the one in use (one coming in or going out, or one gone); this command ends a server only when it is the environment's only one, and nothing was sent"
        );
        other.state = account::State::Gone;
        assert!(decide(&with(|r| r.servers.push(other.clone())), None).is_err());
        // A line not ended, a Bundle's part too: refused, said with a count.
        for (state, part) in [("active", false), ("active", true), ("suspended", false)] {
            let e = decide(&with(|r| r.lines.push(line(state, part))), None).expect_err("refused");
            assert_eq!(
                e.message,
                "environment prod has lines that are not ended (1; a line bought as part of a Bundle counts): ending its server would leave them pointing at an address that reaches nothing, billed as before; nothing was sent"
            );
            assert_eq!(
                e.hint.as_deref(),
                Some(
                    "`erpc worker delete --release-server --env prod --dir apps/bot` ends the environment's servers and lines together (a line bought as part of a Bundle is taken off, not ended) and deletes its record"
                )
            );
        }
        // Lines that are ended do not count.
        for state in ["gone", "cancelled"] {
            assert!(decide(&with(|r| r.lines.push(line(state, false))), None).is_ok());
        }
        // A server not paid for by the hour: refused; one gone is taken off.
        let not_hourly = with(|r| r.servers[0].hourly = false);
        assert_eq!(
            refused(&not_hourly, None),
            "the server of environment prod is not paid for by the hour: this command ends only a server paid for by the hour, and nothing was sent"
        );
        // A gone server: the account gives it no address.
        let gone = |host: Option<&str>| {
            with(|r| {
                r.servers[0].hourly = false;
                r.servers[0].state = account::State::Gone;
                r.servers[0].address = None;
                r.facts.host = host.map(ToOwned::to_owned);
            })
        };
        assert!(matches!(decide(&gone(None), None), Ok(Plan::End { .. })));
        assert_eq!(
            refused(&gone(Some(HOST)), None),
            "environment prod's record names the address 203.0.113.10, but the ERPC account gives no address for its server in use: this command ends a server only when the record names its own address or none, so that no other address is ever cleared; nothing was sent"
        );
        // Only the server's own address: another, a name, or none given.
        let mismatch = with(|r| r.facts.host = Some("198.51.100.7".to_owned()));
        assert_eq!(
            refused(&mismatch, None),
            "environment prod's record names the address 198.51.100.7, but the ERPC account gives 203.0.113.10 for its server in use: this command ends a server only when the record names its own address or none, so that no other address is ever cleared; nothing was sent"
        );
        assert!(
            decide(
                &with(|r| r.facts.host = Some("bot.example.com".to_owned())),
                None
            )
            .is_err()
        );
        assert!(decide(&with(|r| r.servers[0].address = None), None).is_err());
        // A start not settled yet: its line may not be on the record.
        let e = super::decide((&record(), 1), None, APP_ID, &app()).expect_err("open");
        assert_eq!(
            e.message,
            "environment prod has starts that are not settled yet (1): what they bought may not be on its record, so this command does not end its server now, and nothing was sent"
        );
        // No address on the record: nothing to clear, ended all the same.
        assert_eq!(
            decide(&with(|r| r.facts.host = None), None).expect("ended"),
            Plan::End {
                server: record().servers[0].clone(),
                host: None
            }
        );
    }

    #[test]
    fn a_record_with_no_server_is_cleared_or_tidied_only_for_what_this_machine_set_out_to_end() {
        let decide =
            |r: &EnvDetail, earlier: Option<&Ending>| decide((r, 0), earlier, APP_ID, &app());
        let refused = |r: &EnvDetail, earlier: Option<&Ending>| {
            decide(r, earlier).expect_err("refused").message
        };
        // No server and no address: nothing to end; what this machine set
        // out to end, for the same app, is put away.
        let empty = with(|r| {
            r.servers.clear();
            r.facts.host = None;
        });
        assert_eq!(
            refused(&empty, None),
            "environment prod's record names no server and no address: there is nothing to end, and nothing was sent"
        );
        assert_eq!(decide(&empty, Some(&ours())).expect("tidy"), Plan::Tidy);
        let other_app = Ending {
            app_id: "9d0e1f2a-0000-4000-8000-000000000000".to_owned(),
            ..ours()
        };
        assert!(decide(&empty, Some(&other_app)).is_err());
        // An address and no server: cleared only for what this machine was
        // ending, of the same app at the same address.
        assert_eq!(
            decide(&off(), Some(&ours())).expect("cleared"),
            Plan::Clear {
                host: HOST.to_owned()
            }
        );
        let address_only = "environment prod's record names no server, but the address 203.0.113.10: a server of your own, or one that was ended, which this machine has no record of ending; nothing was changed";
        assert_eq!(refused(&off(), None), address_only);
        let other_app = Ending {
            app_id: "9d0e1f2a-0000-4000-8000-000000000000".to_owned(),
            ..ours()
        };
        assert_eq!(refused(&off(), Some(&other_app)), address_only);
        // What this machine recorded with no address never clears one.
        let no_host = Ending {
            host: None,
            ..ours()
        };
        assert_eq!(refused(&off(), Some(&no_host)), address_only);
        let other_host = Ending {
            host: Some("203.0.113.20".to_owned()),
            ..ours()
        };
        assert_eq!(refused(&off(), Some(&other_host)), address_only);
    }

    #[tokio::test]
    async fn an_end_at_a_terminal_ends_clears_the_address_and_puts_away_what_this_machine_kept() {
        let here = Here::new();
        let fake = Fake::new(record());
        let asked = Cell::new(None);
        let (answer, text) = run_with(
            &fake,
            (&app(), "bot"),
            &here.local(),
            AT_TERMINAL,
            |q| {
                asked.set(Some(q.to_owned()));
                Ok(true)
            },
            NOW,
        )
        .await
        .expect("ended");
        assert_eq!(
            asked.take().as_deref(),
            Some(
                "End the server of environment prod of bot (2 vCPU, 8 GB, in amsterdam)? Its billing by the hour stops, and what is on it is lost. This cannot be undone."
            )
        );
        assert_eq!(
            *fake.log.borrow(),
            vec![format!("end {SERVER}"), "put_env".to_owned()]
        );
        let after = fake.env.borrow().clone();
        // What `server start` takes: no server, and no address.
        assert!(after.servers.is_empty());
        assert_eq!(after.facts.host, None);
        assert_eq!(after.facts.host_key, None);
        assert_eq!(after.facts.ssh_user, None);
        assert_eq!(after.facts.ssh_port, None);
        // The last deploy is carried by the write.
        assert_eq!(
            after.deployed.as_ref().map(|d| d.release.as_str()),
            Some("r1")
        );
        assert_eq!(answer["ended"], true);
        assert_eq!(answer["taken_off"], true);
        assert_eq!(answer["server"], SERVER);
        assert_eq!(answer["address"], "cleared");
        assert_eq!(answer["forgotten_here"], true);
        assert_eq!(
            text,
            "ended the server of environment prod: its billing by the hour stopped\ncleared its address, host key, login name and SSH port from the ERPC account's record"
        );
        assert_eq!(here.ending(), None);
        assert!(!here.pinned());
    }

    #[tokio::test]
    async fn nobody_to_ask_sends_nothing_and_yes_asks_nobody() {
        for asking in [
            Asking {
                yes: false,
                json: true,
                terminal: true,
            },
            Asking {
                yes: false,
                json: false,
                terminal: false,
            },
        ] {
            let here = Here::new();
            let fake = Fake::new(record());
            let e = run_with(&fake, (&app(), "bot"), &here.local(), asking, never, NOW)
                .await
                .expect_err("nobody");
            assert_eq!(e.code, Code::NeedsTerminal);
            assert_eq!(
                e.message,
                "ending the server of environment prod cannot be undone, and nobody is here to say yes; nothing was sent"
            );
            assert_eq!(ends(&fake), 0);
            assert_eq!(here.ending(), None);
            assert!(here.pinned());
        }
        let here = Here::new();
        let fake = Fake::new(record());
        let yes = Asking {
            yes: true,
            json: true,
            terminal: false,
        };
        run_with(&fake, (&app(), "bot"), &here.local(), yes, never, NOW)
            .await
            .expect("ended");
        assert_eq!(ends(&fake), 1);
        // A no sends nothing and records nothing.
        let here = Here::new();
        let fake = Fake::new(record());
        let e = run_with(
            &fake,
            (&app(), "bot"),
            &here.local(),
            AT_TERMINAL,
            |_| Ok(false),
            NOW,
        )
        .await
        .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert_eq!(ends(&fake), 0);
        assert_eq!(here.ending(), None);
    }

    #[tokio::test]
    async fn a_server_others_may_be_on_is_ended_only_after_a_yes_at_a_terminal_that_names_them() {
        let here = Here::new();
        let local = Local {
            sharing: &shared,
            ..here.local()
        };
        for (asking, code) in [
            (
                Asking {
                    yes: true,
                    json: false,
                    terminal: true,
                },
                Code::Usage,
            ),
            (
                Asking {
                    yes: false,
                    json: true,
                    terminal: true,
                },
                Code::NeedsTerminal,
            ),
        ] {
            let fake = Fake::new(record());
            let e = run_with(&fake, (&app(), "bot"), &local, asking, never, NOW)
                .await
                .expect_err("refused");
            assert_eq!(e.code, code);
            assert_eq!(
                e.message,
                "by this machine's list of apps, the server of environment prod may also run bot (staging), which ending it ends too. Such a server is ended only after a yes at a terminal, to a question that names them; nothing was sent"
            );
            assert_eq!(ends(&fake), 0);
        }
        // With no address in the facts, the server's own is compared.
        let fake = Fake::new(with(|r| r.facts.host = None));
        let yes = Asking {
            yes: true,
            json: false,
            terminal: true,
        };
        let e = run_with(&fake, (&app(), "bot"), &local, yes, never, NOW)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        assert_eq!(ends(&fake), 0);
        let fake = Fake::new(record());
        let asked = Cell::new(None);
        run_with(
            &fake,
            (&app(), "bot"),
            &local,
            AT_TERMINAL,
            |q| {
                asked.set(Some(q.to_owned()));
                Ok(true)
            },
            NOW,
        )
        .await
        .expect("ended");
        assert!(
            asked
                .take()
                .is_some_and(|q| q.starts_with("By this machine's list of apps, the server may also run bot (staging), which ending it ends too. End the server")),
        );
        assert_eq!(ends(&fake), 1);
    }

    #[tokio::test]
    async fn after_an_answer_without_the_record_what_is_said_comes_from_the_record_read_again() {
        // The account says the end is under way, and the server is still
        // on record: said so; nothing cleared, what this machine was ending
        // kept.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.ends.borrow_mut().push((Ok(Ended::Pending), None));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("pending");
        assert_eq!(
            e.message,
            "the ERPC account says the end of the server of environment prod is under way; the server is still on the record (active)"
        );
        assert_eq!(
            e.hint.as_deref(),
            Some("run `erpc worker server end --env prod --dir apps/bot` again later")
        );
        assert_eq!(writes(&fake), 0);
        assert_eq!(here.ending(), Some(ours()));
        assert!(here.pinned());
        // Under way, and off the record by the time it is read again: the
        // clear goes on.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.ends
            .borrow_mut()
            .push((Ok(Ended::Pending), Some(off())));
        let (answer, text) = run(&fake, &here.local(), AT_TERMINAL).await.expect("ended");
        assert_eq!(answer["ended"], false);
        assert!(
            text.starts_with(
                "the server of environment prod is no longer on the ERPC account's record\n"
            ),
            "{text}"
        );
        assert_eq!(fake.env.borrow().facts.host, None);
        // A refusal, the server still on record: the account's reason, and
        // what to do.
        let here = Here::new();
        let fake = Fake::new(record());
        let not_hourly = || refused(409, "end_refused", json!({ "reason": "not_hourly" }));
        fake.ends.borrow_mut().push((Err(not_hourly()), None));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("refused");
        let why = "the ERPC account answered 409 (end_refused, not_hourly)";
        assert_eq!(
            e.message,
            format!(
                "the server of environment prod is still on the ERPC account's record (active): {why}"
            )
        );
        assert_eq!(
            e.hint.as_deref(),
            Some(
                "the ERPC account says it is not paid for by the hour, and this command ends only a server that is"
            )
        );
        let here = Here::new();
        let fake = Fake::new(record());
        fake.ends.borrow_mut().push((
            Err(refused(
                409,
                "end_refused",
                json!({ "reason": "operation_in_progress", "retryAfter": 20 }),
            )),
            None,
        ));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("busy");
        assert_eq!(
            e.hint.as_deref(),
            Some(
                "another change to the environment is under way; run `erpc worker server end --env prod --dir apps/bot` again in 20 seconds"
            )
        );
    }

    #[tokio::test]
    async fn after_a_failed_end_the_record_read_again_says_whether_it_ended() {
        // A failure the server is off the record after (a 500 after the
        // end, or a repeat refused once the first had ended it): the clear
        // goes on.
        for answer in [
            refused(500, "internal", Value::Null),
            refused(404, "server_not_found", Value::Null),
        ] {
            let here = Here::new();
            let fake = Fake::new(record());
            fake.ends.borrow_mut().push((Err(answer), Some(off())));
            let (answer, text) = run(&fake, &here.local(), AT_TERMINAL).await.expect("ended");
            // Not this run's 200: said as off the record, not as ended.
            assert_eq!(answer["ended"], false);
            assert_eq!(answer["taken_off"], false);
            assert_eq!(answer["address"], "cleared");
            assert!(
                text.starts_with(
                    "the server of environment prod is no longer on the ERPC account's record\n"
                ),
                "{text}"
            );
            assert_eq!(here.ending(), None);
        }
        // The read after fails: not known.
        let here = Here::new();
        let fake = Fake::new(record());
        let lost = || refused(503, "unavailable", Value::Null);
        fake.ends.borrow_mut().push((Err(lost()), None));
        *fake.fail_read.borrow_mut() = Some((3, refused(500, "internal", Value::Null)));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("not known");
        let why = "the ERPC account answered 503 (unavailable)";
        assert_eq!(
            e.message,
            format!("whether the server of environment prod was ended is not known: {why}")
        );
        assert_eq!(here.ending(), Some(ours()));
        // Another server in use by then: said, and nothing cleared.
        let here = Here::new();
        let fake = Fake::new(record());
        let mut another = record();
        another.servers[0].id = "1a2b3c4d-0000-4000-8000-000000000000".to_owned();
        fake.ends.borrow_mut().push((
            Err(refused(
                409,
                "end_refused",
                json!({ "reason": "server_changed" }),
            )),
            Some(another),
        ));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("changed");
        assert_eq!(
            e.message,
            "the server of environment prod is no longer on the ERPC account's record, which now names another server; nothing more was changed"
        );
        assert_eq!(writes(&fake), 0);
    }

    #[tokio::test]
    async fn the_clear_is_written_again_after_a_conflict_or_a_busy_answer_and_said_from_the_record_after_anything_else()
     {
        // A conflict, then written at the revision read again.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(409, "revision_conflict", Value::Null));
        *fake.changes_at.borrow_mut() = Some((
            3,
            with(|r| {
                r.servers.clear();
                r.revision = 12;
            }),
        ));
        run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect("cleared");
        assert_eq!(writes(&fake), 2);
        assert_eq!(fake.env.borrow().facts.host, None);
        // Busy twice, then written: three writes, and no more.
        let here = Here::new();
        let fake = Fake::new(record());
        for _ in 0..2 {
            fake.answers
                .borrow_mut()
                .push(refused(429, "rate_limited", Value::Null));
        }
        run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect("cleared");
        assert_eq!(writes(&fake), 3);
        // Busy throughout: three writes, then said from the record.
        let here = Here::new();
        let fake = Fake::new(record());
        for _ in 0..3 {
            fake.answers
                .borrow_mut()
                .push(refused(429, "rate_limited", Value::Null));
        }
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("busy");
        assert_eq!(writes(&fake), 3);
        assert!(e.message.starts_with("the server of environment prod is off the ERPC account's record, but its address 203.0.113.10 is still on the record: "), "{}", e.message);
        // A 500, the address still on record: said, with the run again
        // kept possible.
        let here = Here::new();
        let fake = Fake::new(record());
        let failure = || refused(500, "internal", Value::Null);
        fake.answers.borrow_mut().push(failure());
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("left");
        let why = "the ERPC account answered 500 (internal)";
        assert_eq!(
            e.message,
            format!(
                "the server of environment prod is off the ERPC account's record, but its address 203.0.113.10 is still on the record: {why}"
            )
        );
        assert_eq!(
            e.hint.as_deref(),
            Some(
                "run `erpc worker server end --env prod --dir apps/bot` again: it clears the address of a server this machine was ending"
            )
        );
        assert_eq!(writes(&fake), 1);
        assert_eq!(here.ending(), Some(ours()));
        assert!(here.pinned());
        // The same command, run again, clears it without ending anything.
        let (answer, text) = run(
            &fake,
            &here.local(),
            Asking {
                yes: false,
                json: true,
                terminal: false,
            },
        )
        .await
        .expect("cleared");
        assert_eq!(ends(&fake), 1);
        assert_eq!(answer["ended"], false);
        assert_eq!(answer["taken_off"], false);
        assert_eq!(answer["address"], "cleared");
        assert!(text.starts_with("the server of environment prod this machine set out to end is no longer on the ERPC account's record\n"));
        assert_eq!(fake.env.borrow().facts.host, None);
        assert_eq!(here.ending(), None);
        assert!(!here.pinned());
    }

    #[tokio::test]
    async fn after_a_failed_clear_what_is_said_comes_from_the_record_read_again() {
        let failure = || refused(500, "internal", Value::Null);
        let why = "the ERPC account answered 500 (internal)";
        // A failure the read after fails: not known.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.answers.borrow_mut().push(failure());
        *fake.fail_read.borrow_mut() = Some((3, refused(503, "unavailable", Value::Null)));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("not known");
        assert_eq!(
            e.message,
            format!(
                "the server of environment prod is off the ERPC account's record, but whether its address was cleared from it is not known: {why}"
            )
        );
        // A failure the address is gone after: said as gone, not as
        // cleared by this run.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.answers.borrow_mut().push(failure());
        fake.ends.borrow_mut().push((
            Ok(Ended::Done(Box::new(off()))),
            Some(with(|r| {
                r.servers.clear();
                r.facts.host = None;
            })),
        ));
        let (answer, text) = run(&fake, &here.local(), AT_TERMINAL).await.expect("ended");
        assert_eq!(answer["address"], "already_gone");
        assert!(
            text.ends_with("\nits address is no longer on the ERPC account's record"),
            "{text}"
        );
        assert_eq!(writes(&fake), 1);
        assert_eq!(here.ending(), None);
        // Another address by then: left as it is, and said.
        let here = Here::new();
        let fake = Fake::new(record());
        let moved = with(|r| {
            r.servers.clear();
            r.facts.host = Some("203.0.113.20".to_owned());
        });
        fake.ends
            .borrow_mut()
            .push((Ok(Ended::Done(Box::new(moved.clone()))), Some(moved)));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("changed");
        assert_eq!(
            e.message,
            "the server of environment prod is off the ERPC account's record, but the record changed meanwhile: it names a server, or an address other than 203.0.113.10; erpc left it as it is"
        );
        assert_eq!(writes(&fake), 0);
        // A conflict, and another address on the record read again.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(409, "revision_conflict", Value::Null));
        *fake.meddle.borrow_mut() = None;
        fake.ends.borrow_mut().push((
            Ok(Ended::Done(Box::new(off()))),
            Some(with(|r| {
                r.servers.clear();
                r.facts.host = Some("203.0.113.20".to_owned());
            })),
        ));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("changed");
        assert_eq!(
            e.message,
            "the server of environment prod is off the ERPC account's record, but the record changed meanwhile: it names a server, or an address other than 203.0.113.10; erpc left it as it is"
        );
        assert_eq!(
            e.hint.as_deref(),
            Some(
                "`erpc worker status --env prod --dir apps/bot` shows what the ERPC account's record holds now"
            )
        );
        assert_eq!(writes(&fake), 1);
    }

    #[tokio::test]
    async fn a_server_on_the_record_by_the_clear_leaves_the_address_as_it_is() {
        // A conflict, and a server on the record read again, at the same
        // address: left as it is.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(409, "revision_conflict", Value::Null));
        fake.ends
            .borrow_mut()
            .push((Ok(Ended::Done(Box::new(off()))), Some(record())));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("changed");
        assert!(
            e.message.ends_with("; erpc left it as it is"),
            "{}",
            e.message
        );
        assert_eq!(writes(&fake), 1);
        // A server on the record the end answered with: no write.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.ends
            .borrow_mut()
            .push((Ok(Ended::Done(Box::new(record()))), None));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("changed");
        assert!(
            e.message.ends_with("; erpc left it as it is"),
            "{}",
            e.message
        );
        assert_eq!(writes(&fake), 0);
    }

    #[tokio::test]
    async fn what_cannot_be_recorded_here_is_not_ended() {
        let here = Here::new();
        // Its parent is a file: nothing can be written there.
        let blocked = here.dir.path().join("blocked");
        std::fs::write(&blocked, b"").expect("file");
        let local = Local {
            endings: blocked.join("worker_server_end.json"),
            ..here.local()
        };
        let fake = Fake::new(record());
        let e = run(&fake, &local, AT_TERMINAL)
            .await
            .expect_err("not recorded");
        assert!(
            e.message
                .starts_with("this machine could not record which server it ends ("),
            "{}",
            e.message
        );
        assert_eq!(ends(&fake), 0);
    }

    #[tokio::test]
    async fn a_gone_server_is_taken_off_and_said_so() {
        let here = Here::new();
        let gone = with(|r| {
            r.servers[0].state = account::State::Gone;
            r.servers[0].address = None;
            r.facts.host = None;
        });
        let fake = Fake::new(gone);
        let asked = Cell::new(None);
        let (answer, text) = run_with(
            &fake,
            (&app(), "bot"),
            &here.local(),
            AT_TERMINAL,
            |q| {
                asked.set(Some(q.to_owned()));
                Ok(true)
            },
            NOW,
        )
        .await
        .expect("taken off");
        assert_eq!(
            asked.take().as_deref(),
            Some(
                "The ERPC account says the server of environment prod of bot is gone (ended, or not this account's). Take it off the environment's record?"
            )
        );
        assert_eq!(answer["ended"], false);
        assert_eq!(answer["taken_off"], true);
        assert_eq!(
            text,
            "took the gone server of environment prod off its record"
        );
    }

    #[tokio::test]
    async fn a_server_with_no_address_on_record_is_ended_with_nothing_to_clear() {
        let here = Here::new();
        let fake = Fake::new(with(|r| {
            r.facts.host = None;
            r.facts.host_key = None;
        }));
        let (answer, text) = run(&fake, &here.local(), AT_TERMINAL).await.expect("ended");
        assert_eq!(writes(&fake), 0);
        assert_eq!(answer["address"], "none");
        assert_eq!(
            text,
            "ended the server of environment prod: its billing by the hour stopped"
        );
        assert_eq!(here.ending(), None);
        // The address gone from the record the end answered with: nothing
        // to clear either.
        let here = Here::new();
        let fake = Fake::new(record());
        let bare = with(|r| {
            r.servers.clear();
            r.facts.host = None;
        });
        fake.ends
            .borrow_mut()
            .push((Ok(Ended::Done(Box::new(bare.clone()))), Some(bare)));
        let (answer, _) = run(&fake, &here.local(), AT_TERMINAL).await.expect("ended");
        assert_eq!(writes(&fake), 0);
        assert_eq!(answer["address"], "already_gone");
    }

    #[tokio::test]
    async fn conflicts_throughout_stop_the_clear_after_three_writes() {
        let here = Here::new();
        let fake = Fake::new(record());
        for _ in 0..3 {
            fake.answers
                .borrow_mut()
                .push(refused(409, "revision_conflict", Value::Null));
        }
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("left");
        assert_eq!(writes(&fake), 3);
        assert!(e.message.starts_with("the server of environment prod is off the ERPC account's record, but its address 203.0.113.10 is still on the record: "), "{}", e.message);
        assert_eq!(here.ending(), Some(ours()));
    }

    #[tokio::test]
    async fn a_record_in_an_older_form_is_refused_before_anything_is_sent() {
        let here = Here::new();
        let fake = Fake::new(with(|r| r.facts_format = 1));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("older");
        assert_eq!(e.message, t!("worker_account.older_format", env = "prod"));
        assert_eq!(ends(&fake), 0);
    }

    #[tokio::test]
    async fn the_record_is_read_and_decided_on_again_after_the_yes() {
        // A line added while asked: refused, nothing sent or recorded.
        let here = Here::new();
        let fake = Fake::new(record());
        *fake.changes_at.borrow_mut() = Some((2, with(|r| r.lines.push(line("active", false)))));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("refused");
        assert!(
            e.message
                .starts_with("environment prod has lines that are not ended (1;"),
            "{}",
            e.message
        );
        assert_eq!(ends(&fake), 0);
        assert_eq!(here.ending(), None);
        // Another server in use by then: not the one asked about.
        let here = Here::new();
        let fake = Fake::new(record());
        *fake.changes_at.borrow_mut() = Some((
            2,
            with(|r| r.servers[0].id = "1a2b3c4d-0000-4000-8000-000000000000".to_owned()),
        ));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("changed");
        assert_eq!(
            e.message,
            "environment prod's record changed while you were asked: it no longer names the same server at the same address; nothing was sent"
        );
        assert_eq!(ends(&fake), 0);
        // The address gone from the record by then: not the one asked
        // about either.
        let here = Here::new();
        let fake = Fake::new(record());
        *fake.changes_at.borrow_mut() = Some((2, with(|r| r.facts.host = None)));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("changed");
        assert!(
            e.message
                .starts_with("environment prod's record changed while you were asked"),
            "{}",
            e.message
        );
        assert_eq!(ends(&fake), 0);
        // Under --yes too.
        let here = Here::new();
        let fake = Fake::new(record());
        *fake.changes_at.borrow_mut() = Some((2, with(|r| r.lines.push(line("active", true)))));
        let yes = Asking {
            yes: true,
            json: true,
            terminal: false,
        };
        assert!(
            run_with(&fake, (&app(), "bot"), &here.local(), yes, never, NOW)
                .await
                .is_err()
        );
        assert_eq!(ends(&fake), 0);
    }

    #[tokio::test]
    async fn what_this_machine_set_out_to_end_is_put_away_once_the_record_holds_nothing() {
        let here = Here::new();
        keep_ending(&here.endings(), "k", Some(&ours())).expect("kept");
        let fake = Fake::new(with(|r| {
            r.servers.clear();
            r.facts.host = None;
        }));
        let (answer, text) = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect("tidied");
        assert_eq!(
            text,
            "nothing is left to end for environment prod: its record names no server and no address"
        );
        assert_eq!(answer["ended"], false);
        assert_eq!(answer["address"], "none");
        assert_eq!(answer["forgotten_here"], true);
        assert_eq!(ends(&fake), 0);
        assert_eq!(writes(&fake), 0);
        assert_eq!(here.ending(), None);
        assert!(!here.pinned());
    }

    #[tokio::test]
    async fn a_server_ended_or_back_while_asked_is_not_said_as_asked_about() {
        // Live when asked, gone by the read after the yes (ended
        // elsewhere): not sent, not said as ended.
        let here = Here::new();
        let bare = || with(|r| r.facts.host = None);
        let fake = Fake::new(bare());
        let mut gone = bare();
        gone.servers[0].state = account::State::Gone;
        gone.servers[0].address = None;
        *fake.changes_at.borrow_mut() = Some((2, gone.clone()));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("changed");
        assert!(
            e.message
                .starts_with("environment prod's record changed while you were asked"),
            "{}",
            e.message
        );
        assert_eq!(ends(&fake), 0);
        // Gone when asked, live by then: not ended on a take-off's yes.
        let here = Here::new();
        let fake = Fake::new(gone);
        *fake.changes_at.borrow_mut() = Some((2, bare()));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("changed");
        assert!(
            e.message
                .starts_with("environment prod's record changed while you were asked"),
            "{}",
            e.message
        );
        assert_eq!(ends(&fake), 0);
        // A start opened by then: not sent.
        let here = Here::new();
        let fake = Fake::new(record());
        *fake.open.borrow_mut() = vec![0, 1];
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("open");
        assert!(
            e.message
                .starts_with("environment prod has starts that are not settled yet (1)"),
            "{}",
            e.message
        );
        assert_eq!(ends(&fake), 0);
    }

    #[tokio::test]
    async fn the_accounts_own_text_of_a_refusal_is_not_said() {
        let here = Here::new();
        let fake = Fake::new(record());
        let pointed = WorkerError::Refused(account::Refusal {
            status: 409,
            code: Some(account::Code::from("end_refused")),
            message: Some(
                "Lines still point at this server; end that one first (lines/x/end).".to_owned(),
            ),
            data: json!({ "reason": "lines_pointed", "lines": 1 }),
        });
        fake.ends.borrow_mut().push((Err(pointed), None));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("refused");
        assert_eq!(
            e.message,
            "the server of environment prod is still on the ERPC account's record (active): the ERPC account answered 409 (end_refused, lines_pointed)"
        );
        assert_eq!(
            e.hint.as_deref(),
            Some(
                "`erpc worker status --env prod --dir apps/bot` shows what the ERPC account's record holds now"
            )
        );
    }

    #[tokio::test]
    async fn a_server_at_another_address_is_not_taken_for_one_others_are_on() {
        let here = Here::new();
        let local = Local {
            sharing: &shared,
            ..here.local()
        };
        let fake = Fake::new(with(|r| {
            r.facts.host = None;
            r.servers[0].address = Some("203.0.113.30".to_owned());
        }));
        let yes = Asking {
            yes: true,
            json: false,
            terminal: true,
        };
        run_with(&fake, (&app(), "bot"), &local, yes, never, NOW)
            .await
            .expect("ended");
        assert_eq!(ends(&fake), 1);
    }

    #[tokio::test]
    async fn what_the_end_did_is_said_when_the_clear_stops() {
        let here = Here::new();
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(500, "internal", Value::Null));
        let _ = crate::node::common::heard::take();
        run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("left");
        assert!(crate::node::common::heard::take().contains(
            &"ended the server of environment prod: its billing by the hour stopped".to_owned()
        ));
    }

    /// The record with the server in use gone, still on it, and its
    /// address still in the facts.
    fn gone_on_record() -> EnvDetail {
        with(|r| {
            r.servers[0].state = account::State::Gone;
            r.servers[0].address = None;
        })
    }

    #[test]
    fn a_gone_servers_address_is_its_own_only_as_this_machine_recorded_it() {
        let decide =
            |earlier: Option<&Ending>| decide((&gone_on_record(), 0), earlier, APP_ID, &app());
        assert_eq!(
            decide(Some(&ours())).expect("taken off"),
            Plan::End {
                server: gone_on_record().servers[0].clone(),
                host: Some(HOST.to_owned())
            }
        );
        // Nothing recorded, another server, another app, no address or
        // another address recorded: refused.
        assert!(decide(None).is_err());
        for earlier in [
            Ending {
                server: "1a2b3c4d-0000-4000-8000-000000000000".to_owned(),
                ..ours()
            },
            Ending {
                app_id: "9d0e1f2a-0000-4000-8000-000000000000".to_owned(),
                ..ours()
            },
            Ending {
                host: None,
                ..ours()
            },
            Ending {
                host: Some("203.0.113.20".to_owned()),
                ..ours()
            },
        ] {
            assert!(decide(Some(&earlier)).is_err(), "{earlier:?}");
        }
        // A live server is held to the address the account gives, whatever
        // this machine recorded.
        let live_elsewhere = with(|r| r.servers[0].address = Some("203.0.113.20".to_owned()));
        assert!(super::decide((&live_elsewhere, 0), Some(&ours()), APP_ID, &app()).is_err());
    }

    #[tokio::test]
    async fn a_run_again_takes_off_a_server_the_account_ended_but_left_on_the_record() {
        // The account ends the server, then fails to take it off: a 500,
        // and the server gone on the record with its address.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.ends.borrow_mut().push((
            Err(refused(500, "internal", Value::Null)),
            Some(gone_on_record()),
        ));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("left");
        assert_eq!(
            e.message,
            "the server of environment prod is still on the ERPC account's record (gone): the ERPC account answered 500 (internal)"
        );
        assert_eq!(here.ending(), Some(ours()));
        // Run again: asked about as gone, taken off, its address cleared.
        let asked = Cell::new(None);
        let (answer, text) = run_with(
            &fake,
            (&app(), "bot"),
            &here.local(),
            AT_TERMINAL,
            |q| {
                asked.set(Some(q.to_owned()));
                Ok(true)
            },
            NOW,
        )
        .await
        .expect("taken off");
        assert!(asked.take().is_some_and(|q| {
            q.starts_with("The ERPC account says the server of environment prod of bot is gone")
        }));
        assert_eq!(answer["taken_off"], true);
        assert_eq!(answer["ended"], false);
        assert_eq!(answer["address"], "cleared");
        assert_eq!(
            text,
            "took the gone server of environment prod off its record\ncleared its address, host key, login name and SSH port from the ERPC account's record"
        );
        let after = fake.env.borrow().clone();
        assert!(after.servers.is_empty());
        assert_eq!(after.facts.host, None);
        assert_eq!(here.ending(), None);
        assert!(!here.pinned());
        // A busy answer, and the server gone by the read: the hint's run
        // again in so many seconds is not refused either.
        let here = Here::new();
        let fake = Fake::new(record());
        fake.ends.borrow_mut().push((
            Err(refused(
                409,
                "end_refused",
                json!({ "reason": "operation_in_progress", "retryAfter": 20 }),
            )),
            Some(gone_on_record()),
        ));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("busy");
        assert!(e.hint.is_some_and(|h| h.ends_with("again in 20 seconds")));
        run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect("taken off");
        assert_eq!(fake.env.borrow().facts.host, None);
    }

    #[tokio::test]
    async fn an_open_start_is_refused_before_anyone_is_asked() {
        let here = Here::new();
        let fake = Fake::new(record());
        *fake.open.borrow_mut() = vec![1];
        let e = run_with(
            &fake,
            (&app(), "bot"),
            &here.local(),
            AT_TERMINAL,
            never,
            NOW,
        )
        .await
        .expect_err("open");
        assert!(
            e.message
                .starts_with("environment prod has starts that are not settled yet (1)"),
            "{}",
            e.message
        );
        assert_eq!(ends(&fake), 0);
    }

    #[tokio::test]
    async fn after_an_end_under_way_a_failed_read_is_said_with_the_reads_reason() {
        let here = Here::new();
        let fake = Fake::new(record());
        fake.ends.borrow_mut().push((Ok(Ended::Pending), None));
        *fake.fail_read.borrow_mut() = Some((3, refused(503, "unavailable", Value::Null)));
        let e = run(&fake, &here.local(), AT_TERMINAL)
            .await
            .expect_err("not known");
        assert_eq!(
            e.message,
            "whether the server of environment prod was ended is not known: the ERPC account answered 503 (unavailable)"
        );
    }
}
