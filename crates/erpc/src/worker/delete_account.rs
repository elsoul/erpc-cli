// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker delete --release-server` of an environment kept in the
//! ERPC account: the account ends every server and line the environment
//! holds (a line bought as part of a Bundle is taken off instead, not
//! ended), at most a few in one request, then deletes its record; this
//! machine's record of what it trusts for the environment, and its table
//! in `erpc.toml`, go after. When it is the app's last environment in the
//! account, the question says so, and the app's record is deleted too,
//! with the settings and secrets the account keeps for the app, once the
//! environment's is gone: what the first deploy made goes as a whole.
//! While the app has another environment there, its record stays.
//!
//! The app's record is deleted with `delete_app`, which ends nothing and
//! is refused while an environment of the app still holds a server, a
//! line or an open start: everything ended was ended by the environment's
//! own delete, under the question. (Its sibling that ends what the app's
//! environments hold would end at the app's revision whatever another
//! sign-in put in an environment after the question.) It is sent only
//! when the account, read again, names the app the person was asked about
//! with no environment left, and a run that stopped before it, or at it,
//! is finished by the same command: `erpc.toml` and this machine's records
//! stay until then.
//!
//! The account decides what is ended, from its own record, and checks
//! first that it can end all of it, a Bundle's lines aside. It ends a few at a time, and one end
//! can fail part way: what is left stays on record, and the same command
//! finishes it. When it stops, "nothing was ended" is said only when every
//! answer in the run is one the account gives before it ends anything, and
//! the record still holds all that was asked about; anything else is said
//! as part may be ended. The first delete is sent at the revision the
//! person was asked about; a server or line that appears after that is not
//! ended unasked.
//!
//! The account takes a server it ended off the environment's record and
//! keeps its address, so a record that names an address and no server in
//! use may be an environment whose server was ended already, or one on a
//! server of the person's own; the record does not tell them apart. Such
//! a record is asked about at a terminal only, told both, unless this
//! machine recorded, before a delete of it was sent, that the person agreed
//! to end what it held at that address: then the same command finishes it.
//! That record of what was agreed to is no record of trust: nothing reached
//! over SSH reads it.

use core::time::Duration;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use erpc_api::worker::money::Deleting;
use erpc_api::worker::{self as account, Code as AccountCode, EnvDetail, WorkerError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::account::commands::Outcome;
use crate::cli::error::{CliError, Code};
use crate::node::common::Say;
use crate::worker::App;
use crate::worker::account::{self as kept, Account};
use crate::worker::remote::DeleteAsk;

fn failed(message: String) -> CliError {
    CliError::new(Code::Failed, message)
}

/// How many times a delete is sent before erpc stops and says to run it
/// again: enough for an end under way to finish, and no more.
const TRIES: u32 = 24;

/// How long erpc waits after the account says an end is under way before
/// it asks again: an end is not hurried by being asked for again.
const PAUSE: Duration = Duration::from_secs(15);

/// The wait before a delete is sent again after a revision conflict.
const CONFLICT_PAUSE: Duration = Duration::from_secs(2);

/// The longest wait a busy answer is given.
const BUSY_WAIT_MAX: Duration = Duration::from_secs(120);

/// Refusals of the account's that mean "not now": sent again after a
/// wait. Whether anything was ended before one is not known: an end's own
/// failure may be passed on with one, after others in the request ended.
const BUSY: [&str; 6] = [
    "rate_limited",
    "RATE_LIMITED",
    "LOCK_HELD",
    "OPERATION_IN_PROGRESS",
    "operation_in_progress",
    "ROW_CHANGED_RETRY",
];

/// Whether something on the record is not ended: what the question names.
fn live(state: &account::State) -> bool {
    *state != account::State::Gone && state.as_str() != "cancelled"
}

/// What ending everything takes from the account's record, for the
/// question: its servers, by count, and each line by kind, but for a
/// Bundle's parts, which the delete takes off without ending them.
fn ends(record: &EnvDetail) -> Option<String> {
    let mut items: Vec<String> = Vec::new();
    let servers = record.servers.iter().filter(|s| live(&s.state)).count();
    if servers > 0 {
        items.push(tn!("worker_delete_account.servers", servers));
    }
    for line in record
        .lines
        .iter()
        .filter(|l| live(&l.state) && !l.bundle_part)
    {
        items.push(t!(
            "worker_account.charged_line",
            kind = kept::kind_label(&line.kind)
        ));
    }
    (!items.is_empty()).then(|| items.join(&t!("worker_account.list_sep")))
}

/// The lines on `record` bought as part of a Bundle: the delete takes them
/// off the environment without ending them.
fn parts(record: &EnvDetail) -> Vec<&account::Line> {
    record
        .lines
        .iter()
        .filter(|l| l.bundle_part && live(&l.state))
        .collect()
}

/// `parts`, each by kind, for a sentence.
fn parts_said(parts: &[&account::Line]) -> Option<String> {
    (!parts.is_empty()).then(|| {
        parts
            .iter()
            .map(|l| {
                t!(
                    "worker_account.charged_line",
                    kind = kept::kind_label(&l.kind)
                )
            })
            .collect::<Vec<_>>()
            .join(&t!("worker_account.list_sep"))
    })
}

/// The ids of the servers and lines `record` holds.
fn ids(record: &EnvDetail) -> Vec<&str> {
    record
        .servers
        .iter()
        .map(|s| s.id.as_str())
        .chain(record.lines.iter().map(|l| l.id.as_str()))
        .collect()
}

/// The ids of what `record` holds that is ended.
fn ended_ids(record: &EnvDetail) -> Vec<&str> {
    record
        .servers
        .iter()
        .filter(|s| !live(&s.state))
        .map(|s| s.id.as_str())
        .chain(
            record
                .lines
                .iter()
                .filter(|l| !live(&l.state))
                .map(|l| l.id.as_str()),
        )
        .collect()
}

/// Whether `e` says the account has no such app or environment.
fn not_found(e: &WorkerError) -> bool {
    matches!(e, WorkerError::Refused(r) if matches!(
        r.code,
        Some(AccountCode::EnvNotFound | AccountCode::WorkerNotFound)
    ))
}

/// The wait a busy answer `r` is given: what it asks for, else `pause`,
/// and never more than [`BUSY_WAIT_MAX`].
fn busy_wait(r: &account::Refusal, pause: Duration) -> Duration {
    r.retry_after()
        .map_or(pause, Duration::from_secs)
        .min(BUSY_WAIT_MAX)
}

/// `e`, the reason an end stopped, said with what became of the rest:
/// part may be ended (`part`), or nothing was.
fn said_as(e: CliError, part: bool, app: &App) -> CliError {
    let message = if part {
        t!("worker_delete_account.part_ended", why = e.message)
    } else {
        t!("worker_delete_account.nothing_ended", why = e.message)
    };
    let again = t!("worker_delete_account.again", scope = app.scope());
    let hint = match e.hint {
        Some(hint) => hint,
        None => again,
    };
    CliError::new(e.code, message).hint(hint)
}

/// What a delete refused by the account calls for next.
enum Next {
    /// The environment is gone already.
    Done,
    /// Sent again after this wait; `true` when it waits for an end under
    /// way rather than for a busy account.
    Again(Duration, bool),
    /// Stopped, with why, and whether the account gives this answer before
    /// it ends anything in the request.
    Stop(CliError, bool),
}

/// What a run has seen of the account's answers.
#[derive(Debug, Clone, Copy)]
struct Seen {
    /// An answer said an end is under way, or that a request ended as many
    /// as it may.
    ended_some: bool,
    /// Every answer so far is one the account gives before it ends
    /// anything.
    clean: bool,
}

/// How the account's refusal `r` of a delete is read, and what it tells of
/// the run.
fn after_refusal(
    r: account::Refusal,
    seen: &mut Seen,
    pause: Duration,
    name: &str,
    app: &App,
) -> Next {
    let env = app.env.as_str();
    let code = r
        .code
        .as_ref()
        .map(|c| c.as_str().to_owned())
        .unwrap_or_default();
    match code.as_str() {
        "env_not_found" | "worker_not_found" => Next::Done,
        // As many as one request may were ended: the rest at once, at the
        // revision read next.
        "end_in_progress" => {
            seen.ended_some = true;
            seen.clean = false;
            Next::Again(Duration::ZERO, true)
        }
        // Another operation holds the environment (a line being pointed
        // elsewhere, or an end): the account is busy, and says how long to
        // wait (`retryAfter`). The request may have ended some before it
        // (the run is no longer clean); whether it did is not said.
        "end_refused" if r.reason().as_deref() == Some("operation_in_progress") => {
            seen.clean = false;
            Next::Again(busy_wait(&r, pause), false)
        }
        // Given before the ends, and after them when the record moved
        // meanwhile.
        "revision_conflict" => {
            seen.clean = false;
            Next::Again(pause.min(CONFLICT_PAUSE), false)
        }
        c if BUSY.contains(&c) => {
            seen.clean = false;
            Next::Again(busy_wait(&r, pause), false)
        }
        "servers_not_endable" if r.reason().as_deref() == Some("not_hourly") => Next::Stop(
            failed(t!("worker_delete_account.not_hourly", env)).hint(t!(
                "worker_delete_account.not_hourly_hint",
                scope = app.scope()
            )),
            true,
        ),
        // Right after an end under way, the account may still be putting
        // away what it ended: waited for.
        "servers_not_endable" if seen.ended_some => Next::Again(pause, true),
        "servers_not_endable" => Next::Stop(
            failed(t!("worker_delete_account.not_endable", env)).hint(t!(
                "worker_delete_account.not_endable_hint",
                scope = app.scope()
            )),
            true,
        ),
        "start_pending" => Next::Stop(
            failed(t!("worker_delete_account.start_pending", env))
                .hint(t!("worker_delete_account.start_pending_hint")),
            true,
        ),
        _ => Next::Stop(failing(name, app, &WorkerError::Refused(r)), false),
    }
}

/// The account's failure `e`, with its exit status, and a hint that says
/// to run the command again after the one the failure has (signing in).
fn failing(name: &str, app: &App, e: &WorkerError) -> CliError {
    let e = kept::worker_error(name, app, e);
    let again = t!("worker_delete_account.again", scope = app.scope());
    let hint = match e.hint {
        Some(hint) => format!("{hint}{}{again}", t!("worker_account.hint_sep")),
        None => again,
    };
    CliError::new(e.code, e.message).hint(hint)
}

/// Ends everything environment `app.env` of the app named `name` holds (a
/// Bundle's line is taken off instead) and deletes its record. The first delete goes at `asked`, the record the
/// person was asked about; later ones at the revision the record then has,
/// refused when it holds a server or line the question did not name.
/// `pause` is the wait after an end under way. An environment the account
/// no longer has is already deleted. When it stops, the record is read
/// again to say whether part may be ended.
pub(crate) async fn end_and_delete(
    api: &impl Account,
    app: &App,
    name: &str,
    asked: &EnvDetail,
    pause: Duration,
    say: &Say,
) -> Result<(), CliError> {
    let env = app.env.as_str();
    let named = ids(asked);
    let mut revision = asked.revision;
    let mut seen = Seen {
        ended_some: false,
        clean: true,
    };
    let (why, before_ends) = 'rounds: {
        for round in 0..TRIES {
            let last = round + 1 == TRIES;
            if round > 0 {
                match api.env(name, env).await {
                    Ok(record) => {
                        if ids(&record).iter().any(|id| !named.contains(id)) {
                            break 'rounds (
                                failed(t!("worker_delete_account.grew", env))
                                    .hint(t!("worker_delete_account.again", scope = app.scope())),
                                true,
                            );
                        }
                        revision = record.revision;
                    }
                    Err(e) if not_found(&e) => return Ok(()),
                    Err(e) => break 'rounds (failing(name, app, &e), false),
                }
            }
            match api.delete_env_ending(name, env, revision).await {
                Ok(Deleting::Deleted(_)) => return Ok(()),
                // An end is under way: asked again after a wait, not at once.
                Ok(_) => {
                    seen.ended_some = true;
                    seen.clean = false;
                    // The last round stops at once: nothing more is sent.
                    if !last {
                        say.line(&t!(
                            "worker_delete_account.waiting",
                            env,
                            secs = pause.as_secs()
                        ));
                        tokio::time::sleep(pause).await;
                    }
                }
                Err(WorkerError::Refused(r)) => match after_refusal(r, &mut seen, pause, name, app)
                {
                    Next::Done => return Ok(()),
                    Next::Again(wait, ending) => {
                        if !last {
                            if !wait.is_zero() {
                                say.line(&if ending {
                                    t!("worker_delete_account.waiting", env, secs = wait.as_secs())
                                } else {
                                    t!("worker_delete_account.busy", secs = wait.as_secs())
                                });
                            }
                            tokio::time::sleep(wait).await;
                        }
                    }
                    Next::Stop(e, before) => break 'rounds (e, before),
                },
                // Out of reach, or failing: whether it ended anything is not
                // known.
                Err(e) => break 'rounds (failing(name, app, &e), false),
            }
        }
        let why = if seen.ended_some {
            t!("worker_delete_account.still_ending", env)
        } else {
            t!("worker_delete_account.busy_throughout", env)
        };
        (
            failed(why).hint(t!("worker_delete_account.again", scope = app.scope())),
            true,
        )
    };
    // What became of the rest, from the record: an id asked about that it
    // no longer holds, or holds as ended, was ended.
    let changed = match api.env(name, env).await {
        Ok(now) => {
            let left = ids(&now);
            let ended = ended_ids(&now);
            named
                .iter()
                .any(|id| !left.contains(id) || ended.contains(id))
        }
        Err(e) if not_found(&e) => return Ok(()),
        Err(_) => true,
    };
    let part = !(seen.clean && before_ends) || changed;
    Err(said_as(why, part, app))
}

// ------------------------------------------------- what was agreed to

/// What the person agreed to end for an environment, recorded on this
/// machine before a delete of it was sent: so that the same command, run
/// again after the account took a server it ended off the record, finishes
/// it. Not a record of trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Agreed {
    /// The app's id in the account: made again, the app has another.
    pub(crate) app_id: String,
    /// The address the record named.
    pub(crate) host: Option<String>,
    /// The servers and lines agreed to.
    pub(crate) ids: Vec<String>,
    /// Those of them that are lines bought as part of a Bundle, which the
    /// delete takes off without ending: one gone since was not ended.
    #[serde(default)]
    pub(crate) parts: Vec<String>,
    /// Whether the person was told the environment is the app's last in
    /// the account, and agreed to the app's record going with it.
    #[serde(default)]
    pub(crate) app_too: bool,
}

/// What was agreed to, by environment.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Agreements {
    #[serde(default)]
    agreed: BTreeMap<String, Agreed>,
}

fn load_agreed(path: &Path) -> Result<Agreements, String> {
    let unreadable = |error: String| {
        t!(
            "worker_delete_account.agreed_unreadable",
            path = path.display(),
            error
        )
    };
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| unreadable(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Agreements::default()),
        Err(e) => Err(unreadable(e.to_string())),
    }
}

/// What `path` records as agreed to for `key`.
fn agreed(path: &Path, key: &str) -> Result<Option<Agreed>, String> {
    Ok(load_agreed(path)?.agreed.remove(key))
}

/// Records `what` for `key` in `path`, or forgets it (`None`), under the
/// lock.
fn record_agreed(path: &Path, key: &str, what: Option<&Agreed>) -> Result<(), String> {
    if what.is_none() && !path.exists() {
        return Ok(());
    }
    erpc_core::private_file::locked(path, || {
        let mut all = load_agreed(path)?;
        match what {
            Some(what) => {
                all.agreed.insert(key.to_owned(), what.clone());
            }
            None => {
                if all.agreed.remove(key).is_none() {
                    return Ok(());
                }
            }
        }
        let text = serde_json::to_vec_pretty(&all).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)
    })
}

/// Whether `agreed` covers `record` of the app `app_id`: the same app, the
/// same address, and nothing on the record the person did not agree to.
fn covers(agreed: Option<&Agreed>, app_id: &str, record: &EnvDetail) -> bool {
    agreed.is_some_and(|a| {
        a.app_id == app_id
            && a.host == record.facts.host
            && ids(record).iter().all(|id| a.ids.iter().any(|x| x == id))
    })
}

// ------------------------------------------------------------ asking

/// Who says yes to the delete, which cannot be undone.
#[derive(Clone, Copy)]
struct Asking {
    /// `--yes`.
    yes: bool,
    /// `--json`: nobody is asked.
    json: bool,
    /// A terminal to ask at.
    terminal: bool,
}

/// Asks `question` before the delete: at a terminal, unless `yes` and
/// `yes_will_do`; with nobody to ask, refused with `nobody`.
fn ask(
    asking: Asking,
    yes_will_do: bool,
    question: &str,
    nobody: CliError,
    confirm: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<(), CliError> {
    if asking.yes && yes_will_do {
        return Ok(());
    }
    if asking.json || !asking.terminal {
        return Err(nobody);
    }
    if confirm(question).map_err(failed)? {
        Ok(())
    } else {
        Err(CliError::new(
            Code::Declined,
            t!("worker_delete_account.declined"),
        ))
    }
}

/// What the delete keeps on this machine, and puts away after.
pub(crate) struct Local<'a> {
    /// This machine's record of what it trusts.
    pub(crate) pins: PathBuf,
    /// The key the environment is kept under in it, and in `agreed`.
    pub(crate) pin_key: String,
    /// What was agreed to ([`Agreed`]).
    pub(crate) agreed: PathBuf,
    /// `erpc.toml`.
    pub(crate) path: &'a Path,
    /// The other environments on this machine's list that are, or may be,
    /// on the server at an address, by name.
    pub(crate) sharing: &'a dyn Fn(&str) -> Result<crate::worker::remote::Sharing, CliError>,
}

/// What else is, or may be, on the servers the delete ends, said as one:
/// such a server is ended only after a yes at a terminal, to a question
/// that names them. The server in use is compared with this machine's list
/// by its address; with no address on record, and for a server coming in
/// or going out (whose address the record does not hold), nothing can be
/// compared, and the server is one something may be on.
fn shared(
    record: &EnvDetail,
    local: &Local<'_>,
    asking: Asking,
    app: &App,
) -> Result<Option<String>, CliError> {
    let ended: Vec<&account::Server> = record.servers.iter().filter(|s| live(&s.state)).collect();
    if ended.is_empty() {
        return Ok(None);
    }
    // What this machine's list names, and the servers nothing can be
    // compared by: said apart, since only the first comes from the list.
    let mut listed = Vec::new();
    let mut unmatched = Vec::new();
    let mut unread = false;
    if ended.iter().any(|s| s.slot == account::Slot::Active) {
        match record.facts.host.as_deref() {
            Some(at) => {
                let sharing = (local.sharing)(at)?;
                unread = sharing.unread;
                listed.extend(sharing.named);
            }
            None => unmatched.push(t!("worker_delete_account.no_address_server")),
        }
    }
    match ended
        .iter()
        .filter(|s| s.slot != account::Slot::Active)
        .count()
    {
        0 => {}
        1 => unmatched.push(t!("worker_delete_account.moving_server")),
        _ => unmatched.push(t!("worker_delete_account.moving_servers")),
    }
    if listed.is_empty() && unmatched.is_empty() {
        return Ok(None);
    }
    let sep = t!("worker_account.list_sep");
    let others = listed
        .iter()
        .chain(&unmatched)
        .cloned()
        .collect::<Vec<_>>()
        .join(&sep);
    if asking.yes || asking.json || !asking.terminal {
        let code = if asking.yes {
            Code::Usage
        } else {
            Code::NeedsTerminal
        };
        return Err(CliError::new(
            code,
            t!(
                "worker_delete_account.server_shared",
                env = app.env.as_str(),
                others
            ),
        )
        .hint(if unread {
            t!(
                "worker_delete_account.server_shared_unread_hint",
                scope = app.scope()
            )
        } else {
            t!(
                "worker_delete_account.server_shared_hint",
                scope = app.scope()
            )
        }));
    }
    let mut note = Vec::new();
    if !listed.is_empty() {
        note.push(t!(
            "worker_delete_account.shared_note",
            others = listed.join(&sep)
        ));
    }
    if !unmatched.is_empty() {
        note.push(t!(
            "worker_delete_account.cannot_tell_note",
            which = unmatched.join(&sep)
        ));
    }
    Ok(Some(note.join(&t!("worker_delete_account.sentence_sep"))))
}

/// How what a delete ends is said as it starts: on stderr, under `--json`
/// too, as the erpc.toml delete says it.
const fn ending_say() -> Say {
    Say { quiet: false }
}

/// What a run agrees to of `record`, with what an earlier run of the same
/// agreement (`earlier`) agreed to added; and whether that earlier run
/// ended something the record no longer holds. A Bundle's line it took
/// off was not ended.
fn agreement(
    record: &EnvDetail,
    (app_id, app_too): (String, bool),
    earlier: Option<Agreed>,
) -> (Agreed, bool) {
    let mut ids: Vec<String> = ids(record).into_iter().map(ToOwned::to_owned).collect();
    let mut parts: Vec<String> = parts(record).iter().map(|l| l.id.clone()).collect();
    let (earlier, earlier_parts) = earlier.map(|b| (b.ids, b.parts)).unwrap_or_default();
    let ended_earlier = earlier
        .iter()
        .any(|id| !ids.contains(id) && !earlier_parts.contains(id));
    for id in earlier {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    for id in earlier_parts {
        if !parts.contains(&id) {
            parts.push(id);
        }
    }
    let agreed = Agreed {
        app_id,
        host: record.facts.host.clone(),
        ids,
        parts,
        app_too,
    };
    (agreed, ended_earlier)
}

/// Asks about, ends and deletes `record`, the account's environment, and
/// says whether it is the app's last one there, whose record then goes
/// too. Whether what it ran on there was ended, now or by an earlier run of
/// the same agreement; and the app's id when its record is to go.
async fn end_kept(
    api: &impl Account,
    app: &App,
    name: &str,
    record: &EnvDetail,
    local: &Local<'_>,
    asking: Asking,
    confirm: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<(bool, Option<String>), CliError> {
    let env = app.env.as_str();
    let scope = app.scope();
    kept::current_format(app, record)?;
    let app_record = api
        .app(name)
        .await
        .map_err(|e| kept::worker_error(name, app, &e))?;
    let app_id = app_record.id;
    // The app's last environment there: its record goes with it.
    // Listed alone: a reply that lists none says nothing of the others.
    let last = matches!(app_record.envs.as_slice(), [only] if only.name == env);
    // Unreadable is read as nothing agreed to: asked, never taken as yes.
    let before = agreed(&local.agreed, &local.pin_key).ok().flatten();
    let agreed_before = covers(before.as_ref(), &app_id, record);
    let host = record.facts.host.as_deref().map(crate::storage::clean);
    let serverless = !kept::has_server_in_use(record) && host.is_some();
    let shared = shared(record, local, asking, app)?;
    let parts_note =
        parts_said(&parts(record)).map(|lines| t!("worker_delete_account.parts_note", lines));
    let last_note = last.then(|| t!("worker_delete_account.last_note", env, app = name));
    let note = [shared, parts_note, last_note]
        .into_iter()
        .flatten()
        .reduce(|a, b| format!("{a}{}{b}", t!("worker_delete_account.sentence_sep")));
    let noted = |question: String| match &note {
        Some(note) => format!(
            "{note}{}{question}",
            t!("worker_delete_account.sentence_sep")
        ),
        None => question,
    };
    let asked = if let (true, false, Some(host)) = (serverless, agreed_before, host.as_deref()) {
        // An ended server's address, or a server of the person's own: told
        // both, and asked at a terminal only.
        let question = match ends(record) {
            Some(ends) => t!(
                "worker_delete_account.question_unknown",
                env,
                app = name,
                host,
                ends
            ),
            None => t!(
                "worker_delete_account.question_unknown_nothing",
                env,
                app = name,
                host
            ),
        };
        let nobody = CliError::new(
            Code::NeedsTerminal,
            t!("worker_delete_account.unknown_server", env, host),
        )
        .hint(t!(
            "worker_delete_account.unknown_server_hint",
            scope = &scope
        ));
        ask(asking, false, &noted(question), nobody, confirm)
    } else {
        let question = match ends(record) {
            Some(ends) => t!("worker_delete_account.question", env, app = name, ends),
            None if !parts(record).is_empty() => {
                t!("worker_delete_account.question_parts_only", env, app = name)
            }
            None => t!("worker_delete_account.question_nothing", env, app = name),
        };
        let nobody = CliError::new(
            Code::NeedsTerminal,
            t!("worker_delete_account.needs_yes", env),
        )
        .hint(t!("worker_delete_account.needs_yes_hint", scope = &scope));
        ask(asking, true, &noted(question), nobody, confirm)
    };
    // A no undoes what an earlier run recorded as agreed to.
    if let Err(e) = &asked
        && e.code == Code::Declined
    {
        let _ = record_agreed(&local.agreed, &local.pin_key, None);
    }
    asked?;
    // What was agreed to, recorded before anything is sent; nothing is
    // sent when it cannot be.
    let (agreement, ended_earlier) = agreement(
        record,
        (app_id.clone(), last),
        before.filter(|_| agreed_before),
    );
    record_agreed(&local.agreed, &local.pin_key, Some(&agreement))
        .map_err(|error| failed(t!("worker_delete_account.not_agreed", env, error)))?;
    let say = Say { quiet: asking.json };
    let now = ends(record);
    // What it ends is said on stderr under --json too, as the erpc.toml
    // delete says it.
    if let Some(ends) = &now {
        ending_say().line(&t!("worker_delete_account.ending", env, ends));
    }
    // So is the app's record going, which `--yes` asked nobody about.
    if last {
        ending_say().line(&t!("worker_delete_account.ending_app", env, app = name));
    }
    end_and_delete(api, app, name, record, PAUSE, &say).await?;
    Ok((now.is_some() || ended_earlier, last.then_some(app_id)))
}

/// What became of the app's record after its last environment was deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppRecord {
    /// Deleted, now or before.
    Gone,
    /// It stays: the account has an environment of it again, or names
    /// another app by that name.
    Stays,
}

/// How many times the app's delete is sent when the record moved under
/// it.
const APP_TRIES: u32 = 3;

/// Deletes the record of the app named `name`, the one with id `app_id`
/// the person agreed to delete with its last environment, once the account
/// names it with no environment: read first, then deleted at the revision
/// read.
async fn delete_app_record(
    api: &impl Account,
    app: &App,
    name: &str,
    app_id: &str,
) -> Result<AppRecord, CliError> {
    let env = app.env.as_str();
    let not_deleted = |e: &WorkerError| {
        let e = kept::worker_error(name, app, e);
        let why = e.message.as_str();
        CliError::new(
            e.code,
            t!(
                "worker_delete_account.app_not_deleted",
                env,
                app = name,
                why
            ),
        )
        .hint(t!("worker_delete_account.app_again", scope = app.scope()))
    };
    for _ in 0..APP_TRIES {
        let record = match api.app(name).await {
            Ok(record) => record,
            Err(e) if not_found(&e) => return Ok(AppRecord::Gone),
            Err(e) => return Err(not_deleted(&e)),
        };
        if record.id != app_id || !record.envs.is_empty() {
            return Ok(AppRecord::Stays);
        }
        match api.delete_app(name, record.revision).await {
            Ok(_) => return Ok(AppRecord::Gone),
            Err(e) if not_found(&e) => return Ok(AppRecord::Gone),
            // Moved since it was read: read again.
            Err(WorkerError::Refused(r)) if r.code == Some(AccountCode::RevisionConflict) => {}
            Err(e) => return Err(not_deleted(&e)),
        }
    }
    Err(CliError::new(
        Code::Failed,
        t!(
            "worker_delete_account.app_not_deleted",
            env,
            app = name,
            why = t!("worker_delete_account.app_moving")
        ),
    )
    .hint(t!("worker_delete_account.app_again", scope = app.scope())))
}

/// The delete, through `api`: read and checked, asked, ended and deleted
/// in the account, then put away here. An environment the account no
/// longer has is only put away here: at once when this machine trusted it
/// under this sign-in, asked first otherwise.
pub(crate) async fn run_with(
    api: &impl Account,
    app: &App,
    name: &str,
    local: &Local<'_>,
    (yes, json, terminal): (bool, bool, bool),
    confirm: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<(Value, String), CliError> {
    let env = app.env.as_str();
    let asking = Asking {
        yes,
        json,
        terminal,
    };
    // The Bundle's parts the delete takes off, read before it.
    let mut taken_off: Vec<String> = Vec::new();
    let mut taken_off_said = None;
    // With the app whose record goes with its last environment, by its id.
    let (ended, app_to_go) = match api.env(name, env).await {
        Ok(record) => {
            let (ended, app_too) =
                end_kept(api, app, name, &record, local, asking, confirm).await?;
            let parts = parts(&record);
            taken_off = parts.iter().map(|l| l.kind.as_str().to_owned()).collect();
            taken_off_said = parts_said(&parts);
            (Some(ended), app_too)
        }
        Err(e) if not_found(&e) => {
            // Signed in to another account, it would look the same: what
            // this machine never trusted under this sign-in is asked about.
            let pin = kept::pinned(&local.pins, &local.pin_key).ok().flatten();
            if pin.is_none() {
                let nobody = CliError::new(
                    Code::NeedsTerminal,
                    t!("worker_delete_account.gone_needs_yes", env),
                )
                .hint(t!(
                    "worker_delete_account.needs_yes_hint",
                    scope = app.scope()
                ));
                let question = t!("worker_delete_account.question_gone", env, app = name);
                ask(asking, true, &question, nobody, confirm)?;
            }
            // A run that deleted the environment and stopped before the
            // app's record, which the person agreed to delete with it, is
            // finished: the agreement stays until then.
            let app_too = agreed(&local.agreed, &local.pin_key)
                .ok()
                .flatten()
                .filter(|a| a.app_too)
                .map(|a| a.app_id);
            (None, app_too)
        }
        Err(e) => return Err(kept::worker_error(name, app, &e)),
    };
    // Before anything here is put away, so that the same command finishes
    // it when it stops.
    let app_record = match &app_to_go {
        Some(app_id) => Some(delete_app_record(api, app, name, app_id).await?),
        None => None,
    };
    let mut text = vec![match (ended, taken_off_said) {
        (None, _) => t!("worker_delete_account.already_gone", env),
        (Some(true), None) => t!("worker_delete_account.deleted", env),
        (Some(false), None) => t!("worker_delete_account.deleted_nothing", env),
        (Some(true), Some(lines)) => t!("worker_delete_account.deleted_but_parts", env, lines),
        (Some(false), Some(lines)) => t!("worker_delete_account.deleted_parts_only", env, lines),
    }];
    match app_record {
        Some(AppRecord::Gone) => text.push(t!("worker_delete_account.app_deleted", app = name)),
        Some(AppRecord::Stays) => text.push(t!("worker_delete_account.app_stays", app = name)),
        None => {}
    }
    // What was agreed to goes first: once the account no longer has the
    // environment, nothing may be finished under it again.
    let forgotten = record_agreed(&local.agreed, &local.pin_key, None)
        .and_then(|()| kept::unpin(&local.pins, &local.pin_key))
        .and_then(|()| {
            crate::worker::EnvRecord {
                path: local.path,
                app: name,
                env,
            }
            .forget(&crate::worker::EnvRecord::kept_in_account())
        });
    match &forgotten {
        Ok(()) => text.push(t!("worker_delete_account.forgotten_here")),
        Err(error) => text.push(format!(
            "warning: {}",
            t!(
                "worker_delete_account.not_forgotten",
                error,
                scope = app.scope()
            )
        )),
    }
    let answer = json!({
        "deleted": true,
        "env": env,
        "account": true,
        "already_gone": ended.is_none(),
        "ended": ended.unwrap_or(false),
        "bundle_parts_taken_off": taken_off,
        "app_deleted": app_record == Some(AppRecord::Gone),
        "erpc_toml": forgotten.is_ok(),
        "erpc_toml_error": forgotten.err(),
    });
    Ok((answer, text.join("\n")))
}

/// The refusals of flags, before anything is reached.
fn refuse_flags(app: &App, ask: &DeleteAsk) -> Result<(), CliError> {
    let env = app.env.as_str();
    if ask.forget || !ask.forget_lines.is_empty() {
        return Err(CliError::new(
            Code::Usage,
            t!("worker_delete_account.no_forget", env),
        ));
    }
    if !ask.release_server {
        return Err(
            CliError::new(Code::Usage, t!("worker_delete_account.needs_release", env)).hint(t!(
                "worker_delete_account.needs_release_hint",
                scope = app.scope()
            )),
        );
    }
    Ok(())
}

/// The delete, signed in, with this machine's terminal.
async fn run(json: bool, app: &App, ask: &DeleteAsk) -> Result<(Value, String), CliError> {
    let (path, m) = crate::worker::load(&app.dir)?;
    refuse_flags(app, ask)?;
    let signed = kept::Signed::open().await?;
    // What putting it away here needs is read before anything is ended.
    let uid = signed.uid().await?;
    let sharing = |host: &str| crate::worker::remote::sharing_host(&path, &m, &app.env, host);
    let local = Local {
        pins: kept::pins_path().map_err(failed)?,
        pin_key: kept::pin_key(&uid, &m.name, &app.env),
        agreed: crate::account::session::beside_config("worker_delete.json").map_err(failed)?,
        path: &path,
        sharing: &sharing,
    };
    run_with(
        &signed,
        app,
        &m.name,
        &local,
        (ask.yes, json, crate::account::session::has_terminal()),
        crate::node::common::confirm,
    )
    .await
}

/// `erpc worker delete` of an environment kept in the account.
pub(crate) async fn delete(json: bool, app: &App, ask: &DeleteAsk) -> Outcome {
    match run(json, app, ask).await {
        Ok((answer, text)) => crate::worker::remote::done(json, &answer, text),
        Err(e) => e.into(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::worker::account::stand_in::{Fake, refused};

    const QUIET: Say = Say { quiet: true };
    const APP_ID: &str = "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13";

    fn record() -> EnvDetail {
        serde_json::from_value(json!({
            "name": "prod", "revision": 7, "factsFormat": 2,
            "facts": { "desiredCores": null, "host": "203.0.113.10", "sshUser": null,
                "sshPort": null, "hostKey": null,
                "firewall": { "sshAllow": [], "appAllow": [] }, "starting": {}, "backup": null },
            "servers": [{ "id": "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60", "slot": "active",
                "cores": 2, "memoryGb": 8, "region": "amsterdam", "hourly": true,
                "appRunning": true, "state": "active" }],
            "desiredCores": null, "activeCores": 2, "coreOptions": [],
            "lines": [{ "id": "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314", "kind": "grpc",
                "hourly": true, "pending": false, "state": "active",
                "endpoint": null }],
            "refStates": { "backup": null }, "deployed": null, "deployedApp": null,
            "updatedAt": "2026-10-29T15:40:37.000Z"
        }))
        .expect("an environment")
    }

    /// The record once the account has ended and taken off its server and
    /// line, the address kept.
    fn emptied() -> EnvDetail {
        let mut r = record();
        r.servers.clear();
        r.lines.clear();
        r.revision = 9;
        r
    }

    fn app() -> App {
        App::at("apps/bot", "prod")
    }

    /// A checkout with two environments kept in the account, and where
    /// this machine keeps its records of them.
    struct Checkout {
        dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Checkout {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("a directory");
            let path = dir.path().join("erpc.toml");
            std::fs::write(
                &path,
                "name = \"bot\"\nchain = \"solana\"\n[env.prod]\naccount = true\n[env.staging]\naccount = true\n",
            )
            .expect("erpc.toml");
            Self { dir, path }
        }

        fn local(&self) -> Local<'_> {
            Local {
                pins: self.dir.path().join("worker_account.json"),
                pin_key: "k".to_owned(),
                agreed: self.dir.path().join("worker_delete.json"),
                path: &self.path,
                sharing: &alone,
            }
        }

        fn pin(&self) {
            kept::pin(
                &self.local().pins,
                "k",
                &kept::Anchor::of(APP_ID, &record()),
            )
            .expect("pinned");
        }

        fn names_prod(&self) -> bool {
            erpc_worker::manifest::Manifest::load(&self.path)
                .expect("read")
                .env
                .contains_key("prod")
        }
    }

    fn never(_: &str) -> Result<bool, String> {
        panic!("nobody is asked")
    }

    /// No other environment on this machine's list is on the server.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "it stands in for the list, which can fail to be read"
    )]
    fn alone(_: &str) -> Result<crate::worker::remote::Sharing, CliError> {
        Ok(crate::worker::remote::Sharing::default())
    }

    async fn ended_with(fake: &Fake, asked: &EnvDetail) -> Result<(), CliError> {
        end_and_delete(fake, &app(), "bot", asked, Duration::ZERO, &QUIET).await
    }

    fn no_code(status: u16) -> WorkerError {
        WorkerError::Refused(account::Refusal {
            status,
            code: None,
            message: None,
            data: Value::Null,
        })
    }

    #[tokio::test]
    async fn an_end_under_way_is_asked_about_again_after_a_wait_at_the_revision_read() {
        let fake = Fake::new(record());
        *fake.pending.borrow_mut() = true;
        ended_with(&fake, &record()).await.expect("deleted");
        assert_eq!(*fake.log.borrow(), ["delete env at 7", "delete env at 8"]);
    }

    #[tokio::test]
    async fn the_first_delete_goes_at_the_revision_asked_about_and_a_record_that_grew_is_not_ended()
    {
        let fake = Fake::new(record());
        fake.env.borrow_mut().revision = 8;
        fake.answers
            .borrow_mut()
            .push(refused(409, "revision_conflict", Value::Null));
        let mut grown = fake.env.borrow().lines[0].clone();
        grown.id = "9d2b7f31-5e8a-4c61-b0f4-2a7e9c1d6b58".to_owned();
        fake.env.borrow_mut().lines.push(grown);
        let e = ended_with(&fake, &record()).await.expect_err("refused");
        assert!(e.message.contains("not in the question"), "{}", e.message);
        // A conflict may come after ends: not "nothing".
        assert!(e.message.contains("may be ended already"), "{}", e.message);
        assert_eq!(*fake.log.borrow(), ["delete env at 7"]);
        assert!(!*fake.gone.borrow());
    }

    #[tokio::test]
    async fn as_many_as_one_request_may_end_is_followed_by_the_rest() {
        let fake = Fake::new(record());
        fake.answers.borrow_mut().push(refused(
            409,
            "end_in_progress",
            json!({ "remaining": 1, "currentRevision": 8 }),
        ));
        ended_with(&fake, &record()).await.expect("deleted");
        assert_eq!(fake.log.borrow().len(), 2);
        assert!(*fake.gone.borrow());
    }

    #[tokio::test]
    async fn nothing_was_ended_is_said_only_where_the_account_ends_nothing_first() {
        // (earlier answers, the stop, the record left as asked, nothing?)
        let busy = || refused(429, "RATE_LIMITED", json!({ "retryAfter": 0 }));
        let not_endable = || refused(409, "servers_not_endable", json!({ "lines": 1 }));
        let cases: Vec<(Vec<WorkerError>, bool, bool)> = vec![
            (vec![not_endable()], true, true),
            (
                vec![refused(409, "start_pending", json!({ "envs": ["prod"] }))],
                true,
                true,
            ),
            (
                vec![refused(
                    409,
                    "servers_not_endable",
                    json!({ "reason": "not_hourly" }),
                )],
                true,
                true,
            ),
            // A busy answer may be an end's own failure, passed on.
            (vec![busy(), not_endable()], true, false),
            // A conflict may follow ends.
            (
                vec![
                    refused(409, "revision_conflict", Value::Null),
                    not_endable(),
                ],
                true,
                false,
            ),
            // An end that went through, and taking it off was refused.
            (
                vec![refused(
                    409,
                    "end_refused",
                    json!({ "reason": "not_ended" }),
                )],
                true,
                false,
            ),
            // A gateway's answer, with no code.
            (vec![no_code(524)], true, false),
            (vec![refused(502, "end_failed", Value::Null)], true, false),
            // Before any end, but the record shows the line gone.
            (vec![not_endable()], false, false),
        ];
        for (answers, as_asked, nothing) in cases {
            let mut now = record();
            if !as_asked {
                now.lines.clear();
            }
            let fake = Fake::new(now);
            *fake.answers.borrow_mut() = answers;
            let e = ended_with(&fake, &record()).await.expect_err("stopped");
            assert_eq!(
                e.message.contains("nothing was ended"),
                nothing,
                "{}",
                e.message
            );
            assert_eq!(
                e.message.contains("may be ended already"),
                !nothing,
                "{}",
                e.message
            );
        }
    }

    #[tokio::test]
    async fn what_cannot_be_ended_is_said_by_its_reason() {
        let fake = Fake::new(record());
        fake.answers.borrow_mut().push(refused(
            409,
            "servers_not_endable",
            json!({ "reason": "not_hourly" }),
        ));
        let e = ended_with(&fake, &record()).await.expect_err("refused");
        assert!(e.message.contains("not paid by the hour"), "{}", e.message);
        assert!(e.hint.unwrap_or_default().contains("dashboard"));
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(409, "start_pending", json!({ "envs": ["prod"] })));
        let e = ended_with(&fake, &record()).await.expect_err("refused");
        assert!(e.message.contains("no outcome yet"), "{}", e.message);
        assert!(e.hint.unwrap_or_default().contains("settled"));
    }

    #[tokio::test]
    async fn a_busy_answer_is_waited_for_and_never_longer_than_two_minutes() {
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(429, "RATE_LIMITED", json!({ "retryAfter": 0 })));
        ended_with(&fake, &record()).await.expect("deleted");
        assert_eq!(fake.log.borrow().len(), 2);
        let long = account::Refusal {
            status: 429,
            code: Some(AccountCode::from("RATE_LIMITED")),
            message: None,
            data: json!({ "retryAfter": 600 }),
        };
        assert_eq!(busy_wait(&long, PAUSE), BUSY_WAIT_MAX);
        let none = account::Refusal {
            data: Value::Null,
            ..long
        };
        assert_eq!(busy_wait(&none, PAUSE), PAUSE);
    }

    #[tokio::test]
    async fn out_of_tries_it_stops_and_says_what_the_record_says() {
        // An end under way at every round.
        let fake = Fake::new(record());
        for _ in 0..TRIES {
            fake.answers.borrow_mut().push(refused(
                409,
                "end_in_progress",
                json!({ "remaining": 1 }),
            ));
        }
        let e = ended_with(&fake, &record()).await.expect_err("stopped");
        assert!(e.message.contains("still ending"), "{}", e.message);
        assert!(e.message.contains("may be ended already"), "{}", e.message);
        assert_eq!(fake.log.borrow().len(), TRIES as usize);
        // Busy at every round: nothing was ended, and said so.
        let fake = Fake::new(record());
        for _ in 0..TRIES {
            fake.answers.borrow_mut().push(refused(
                429,
                "RATE_LIMITED",
                json!({ "retryAfter": 0 }),
            ));
        }
        let e = ended_with(&fake, &record()).await.expect_err("stopped");
        assert!(e.message.contains("stayed busy"), "{}", e.message);
        assert!(e.message.contains("may be ended already"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_sign_in_lost_part_way_keeps_its_status_and_says_to_sign_in() {
        let fake = Fake::new(record());
        *fake.pending.borrow_mut() = true;
        fake.reads
            .borrow_mut()
            .push(WorkerError::Api(erpc_api::ApiError::Unauthorized));
        let e = ended_with(&fake, &record()).await.expect_err("stopped");
        assert_eq!(e.code, Code::NotSignedIn);
        let hint = e.hint.unwrap_or_default();
        assert!(
            hint.contains("erpc login") && hint.contains("again"),
            "{hint}"
        );
        assert!(e.message.contains("may be ended already"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_delete_asks_first_records_the_agreement_and_puts_away_only_this_environment() {
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        // Nobody to ask: refused before anything is sent or recorded.
        let fake = Fake::new(record());
        let e = run_with(&fake, &app(), "bot", &local, (false, true, false), never)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert!(fake.log.borrow().is_empty());
        assert!(!local.agreed.exists());
        // A no at a terminal: nothing sent.
        let e = run_with(&fake, &app(), "bot", &local, (false, false, true), |_| {
            Ok(false)
        })
        .await
        .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert!(fake.log.borrow().is_empty());
        assert!(!local.agreed.exists());
        // A yes: deleted in the account, then put away here, this
        // environment only.
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            assert!(q.contains("1 ERPC Worker") && q.contains("gRPC"), "{q}");
            Ok(true)
        })
        .await
        .expect("deleted");
        assert!(*fake.gone.borrow());
        assert_eq!(answer["already_gone"], false);
        assert_eq!(answer["ended"], true);
        assert_eq!(answer["erpc_toml"], true);
        assert!(
            text.contains("ended") && text.contains("erpc.toml no longer"),
            "{text}"
        );
        let after = erpc_worker::manifest::Manifest::load(&c.path).expect("read");
        assert!(!after.env.contains_key("prod") && after.env.contains_key("staging"));
        assert_eq!(kept::pinned(&local.pins, "k").expect("readable"), None);
        assert_eq!(agreed(&local.agreed, "k").expect("readable"), None);
    }

    /// `record()` with its gRPC line bought as part of a Bundle, and an
    /// hourly Shreds line.
    fn with_part() -> EnvDetail {
        serde_json::from_value(json!({
            "name": "prod", "revision": 7, "factsFormat": 2,
            "facts": { "desiredCores": null, "host": "203.0.113.10", "sshUser": null,
                "sshPort": null, "hostKey": null,
                "firewall": { "sshAllow": [], "appAllow": [] }, "starting": {}, "backup": null },
            "servers": [{ "id": "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60", "slot": "active",
                "cores": 2, "memoryGb": 8, "region": "amsterdam", "hourly": true,
                "appRunning": true, "state": "active" }],
            "desiredCores": null, "activeCores": 2, "coreOptions": [],
            "lines": [
                { "id": "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314", "kind": "grpc", "hourly": false,
                  "bundlePart": true, "pending": false, "state": "active", "endpoint": null },
                { "id": "5d2e8f14-6a0b-4c97-b3e1-0f7a9c4d2b68", "kind": "shreds", "hourly": true,
                  "pending": false, "state": "active", "endpoint": null }
            ],
            "refStates": { "backup": null }, "deployed": null, "deployedApp": null,
            "updatedAt": "2026-10-29T15:40:37.000Z"
        }))
        .expect("an environment")
    }

    #[tokio::test]
    async fn a_line_bought_as_part_of_a_bundle_is_said_as_taken_off_not_ended() {
        const NOTE: &str = "What was bought as part of a Bundle is taken off the environment and not ended: its gRPC line. Each is billed with its Bundle.";
        // With a server and an hourly line: the question ends those, and
        // names the Bundle's line apart.
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(with_part());
        let asked = std::cell::RefCell::new(String::new());
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            asked.replace(q.to_owned());
            Ok(true)
        })
        .await
        .expect("deleted");
        assert_eq!(
            asked.take(),
            format!(
                "{NOTE} Delete environment prod of bot from the ERPC account, ending 1 ERPC Worker, its Shreds line? This cannot be undone."
            )
        );
        assert_eq!(
            text.lines().next(),
            Some(
                "Deleted environment prod from the ERPC account, with what it ran on there ended but for what was bought as part of a Bundle, taken off it and not ended: its gRPC line. Each is billed with its Bundle."
            )
        );
        assert_eq!(answer["ended"], true);
        assert_eq!(answer["bundle_parts_taken_off"], json!(["grpc"]));
        // Only the Bundle's lines, one of them gone and one suspended, and
        // no address: nothing is ended, the gone one is not named, the
        // suspended one is, and the question and the answer say so.
        let c = Checkout::new();
        let local = c.local();
        let mut only = with_part();
        only.servers.clear();
        only.lines[1].bundle_part = true;
        only.lines[1].state = account::State::Gone;
        only.lines.push(
            serde_json::from_value(json!({
                "id": "9e4b1c07-2d8f-4a63-b5e0-71c3f9a2d846", "kind": "unlimited",
                "hourly": false, "bundlePart": true, "pending": false,
                "state": "suspended", "endpoint": null
            }))
            .expect("a line"),
        );
        only.facts.host = None;
        let fake = Fake::new(only);
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            asked.replace(q.to_owned());
            Ok(true)
        })
        .await
        .expect("deleted");
        assert_eq!(
            asked.take(),
            "What was bought as part of a Bundle is taken off the environment and not ended: its gRPC line, its Unlimited RPC line. Each is billed with its Bundle. Delete environment prod of bot from the ERPC account, ending nothing? This cannot be undone."
        );
        assert_eq!(
            text.lines().next(),
            Some(
                "Deleted environment prod from the ERPC account, ending nothing: what was bought as part of a Bundle was taken off it and not ended (its gRPC line, its Unlimited RPC line). Each is billed with its Bundle."
            )
        );
        assert_eq!(answer["ended"], false);
        assert_eq!(
            answer["bundle_parts_taken_off"],
            json!(["grpc", "unlimited"])
        );
        // None: the list is empty, and the words are as before.
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            asked.replace(q.to_owned());
            Ok(true)
        })
        .await
        .expect("deleted");
        assert_eq!(
            asked.take(),
            "Delete environment prod of bot from the ERPC account, ending 1 ERPC Worker, its gRPC line? This cannot be undone."
        );
        assert_eq!(answer["bundle_parts_taken_off"], json!([]));
        assert_eq!(
            text.lines().next(),
            Some(
                "Deleted environment prod from the ERPC account, with what it ran on there ended."
            )
        );
    }

    #[tokio::test]
    async fn a_bundles_line_is_named_on_the_told_both_question_and_with_nobody_to_say_yes() {
        // An address and no server in use: the told-both question, with the
        // Bundle's line named before it.
        let c = Checkout::new();
        let local = c.local();
        let mut told = with_part();
        told.servers.clear();
        told.lines.truncate(1);
        let fake = Fake::new(told);
        let asked = std::cell::RefCell::new(String::new());
        run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            asked.replace(q.to_owned());
            Ok(true)
        })
        .await
        .expect("deleted");
        let q = asked.take();
        assert!(
            q.starts_with("What was bought as part of a Bundle is taken off the environment and not ended: its gRPC line. Each is billed with its Bundle. The ERPC account names no server in use for environment prod of bot, only the address 203.0.113.10"),
            "{q}"
        );
        // Nobody to say yes: said with the Bundle's line set aside.
        let c = Checkout::new();
        let local = c.local();
        let fake = Fake::new(with_part());
        let e = run_with(&fake, &app(), "bot", &local, (false, true, false), never)
            .await
            .expect_err("refused");
        assert_eq!(
            e.message,
            "deleting environment prod from the ERPC account ends what it runs on (a line bought as part of a Bundle is only taken off) and cannot be undone, and nobody is here to say yes"
        );
        assert!(fake.log.borrow().is_empty());
        // No --release-server: said the same way.
        let e = refuse_flags(
            &app(),
            &DeleteAsk {
                release_server: false,
                forget: false,
                forget_lines: vec![],
                yes: false,
            },
        )
        .expect_err("refused");
        assert_eq!(
            e.message,
            "environment prod is kept in the ERPC account, and deleting it there ends its servers and lines (a line bought as part of a Bundle is only taken off)"
        );
    }

    #[tokio::test]
    async fn a_bundles_line_an_earlier_run_took_off_is_not_said_as_ended() {
        let part = "c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314";
        let c = Checkout::new();
        let local = c.local();
        // A record of one Bundle's line and no address. The first run is
        // agreed to, records which line is a Bundle's, and stops when the
        // account's delete fails.
        let mut only = with_part();
        only.servers.clear();
        only.lines.truncate(1);
        only.facts.host = None;
        let fake = Fake::new(only);
        fake.answers
            .borrow_mut()
            .push(refused(500, "internal", Value::Null));
        run_with(&fake, &app(), "bot", &local, (false, false, true), |_| {
            Ok(true)
        })
        .await
        .expect_err("stopped");
        let first = agreed(&local.agreed, "k")
            .expect("readable")
            .expect("recorded");
        assert_eq!(
            (first.ids.clone(), first.parts),
            (vec![part.to_owned()], vec![part.to_owned()])
        );
        // The account took the line off. A second run stops too: what it
        // records keeps the line as a Bundle's.
        let mut left = with_part();
        left.servers.clear();
        left.lines.clear();
        left.facts.host = None;
        *fake.env.borrow_mut() = left;
        fake.answers
            .borrow_mut()
            .push(refused(500, "internal", Value::Null));
        run_with(&fake, &app(), "bot", &local, (false, false, true), |_| {
            Ok(true)
        })
        .await
        .expect_err("stopped");
        let second = agreed(&local.agreed, "k")
            .expect("readable")
            .expect("recorded");
        assert_eq!(second.parts, vec![part.to_owned()]);
        // The third run finishes, and does not say the line was ended.
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (false, false, true), |_| {
            Ok(true)
        })
        .await
        .expect("deleted");
        assert_eq!(answer["ended"], false);
        assert_eq!(
            text.lines().next(),
            Some("Deleted environment prod from the ERPC account; its record held nothing to end.")
        );
    }

    #[test]
    fn an_agreement_recorded_before_bundle_lines_were_kept_is_read_with_none() {
        let c = Checkout::new();
        let local = c.local();
        std::fs::write(
            &local.agreed,
            json!({ "agreed": { "k": {
                "appId": APP_ID, "host": "203.0.113.10",
                "ids": ["c47a1e09-3b6d-4c28-a5f1-98e2d0b7a314"]
            } } })
            .to_string(),
        )
        .expect("written");
        let read = agreed(&local.agreed, "k")
            .expect("readable")
            .expect("recorded");
        assert_eq!(read.ids.len(), 1);
        assert!(read.parts.is_empty());
    }

    #[test]
    fn the_bundle_sentences_say_the_same_in_each_language() {
        use erpc_core::i18n::Lang;
        let said = || {
            [
                t!("worker_delete_account.parts_note", lines = "L"),
                t!(
                    "worker_delete_account.question_parts_only",
                    env = "prod",
                    app = "bot"
                ),
                t!(
                    "worker_delete_account.deleted_but_parts",
                    env = "prod",
                    lines = "L"
                ),
                t!(
                    "worker_delete_account.deleted_parts_only",
                    env = "prod",
                    lines = "L"
                ),
                t!("worker_delete_account.needs_yes", env = "prod"),
                t!("worker_delete_account.needs_release", env = "prod"),
            ]
        };
        let meant = [
            (
                Lang::Ja,
                [
                    "Bundle の一部として買ったものは、環境から外し、終了しません: L。それぞれ Bundle と一緒に課金されます。",
                    "bot の環境 prod を ERPC のアカウントから削除しますか？終了するものはありません。元に戻せません。",
                    "環境 prod を ERPC のアカウントから削除し、そこで使っていたものを終了しました。ただし Bundle の一部として買ったものは、終了せずに環境から外しました: L。それぞれ Bundle と一緒に課金されます。",
                    "環境 prod を ERPC のアカウントから削除しました。終了したものはありません。Bundle の一部として買ったものは、終了せずに環境から外しました（L）。それぞれ Bundle と一緒に課金されます。",
                    "環境 prod を ERPC のアカウントから削除すると、使っているものが終了し（Bundle の一部として買った回線は外すだけです）、元に戻せません。yes と答える人がいません",
                    "環境 prod は ERPC のアカウントに保管されていて、そこで削除するとサーバーと回線が終了します（Bundle の一部として買った回線は外すだけです）",
                ],
            ),
            (
                Lang::Zh,
                [
                    "作为 Bundle 一部分购买的内容会从环境中移除，但不会终止：L。每一项都随其 Bundle 计费。",
                    "要从 ERPC 账户删除 bot 的环境 prod 吗？不会终止任何内容。此操作无法撤回。",
                    "已从 ERPC 账户删除环境 prod，并终止了其在那里使用的内容；但作为 Bundle 一部分购买的内容已从环境中移除，未被终止：L。每一项都随其 Bundle 计费。",
                    "已从 ERPC 账户删除环境 prod，未终止任何内容；作为 Bundle 一部分购买的内容已从环境中移除，未被终止（L）。每一项都随其 Bundle 计费。",
                    "从 ERPC 账户删除环境 prod 会终止其使用的内容（作为 Bundle 一部分购买的线路只会被移除）且无法撤回，而这里没有人可以确认",
                    "环境 prod 保存在 ERPC 账户中，在那里删除会终止其服务器和线路（作为 Bundle 一部分购买的线路只会被移除）",
                ],
            ),
            (
                Lang::Ru,
                [
                    "Купленное как часть Bundle снимается с окружения и не завершается: L. Каждая такая линия оплачивается вместе со своим Bundle.",
                    "Удалить окружение prod приложения bot из аккаунта ERPC, ничего не завершая? Это нельзя отменить.",
                    "Окружение prod удалено из аккаунта ERPC, а то, на чём оно там работало, завершено, кроме купленного как часть Bundle: оно снято с окружения и не завершено (L). Каждая такая линия оплачивается вместе со своим Bundle.",
                    "Окружение prod удалено из аккаунта ERPC, ничего не завершено; купленное как часть Bundle снято с окружения и не завершено (L). Каждая такая линия оплачивается вместе со своим Bundle.",
                    "удаление окружения prod из аккаунта ERPC завершит то, на чём оно работает (линия, купленная как часть Bundle, только снимается), и его нельзя отменить, а подтвердить его некому",
                    "окружение prod хранится в аккаунте ERPC, и удаление там завершает его серверы и линии (линия, купленная как часть Bundle, только снимается)",
                ],
            ),
        ];
        for (lang, expected) in meant {
            assert_eq!(crate::cli::i18n::speaking(lang, said), expected, "{lang:?}");
        }
    }

    #[tokio::test]
    async fn a_run_that_stopped_leaves_this_machine_as_it_was_and_running_it_again_finishes_it() {
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        // The account ends the line and the server, then the delete of the
        // record fails.
        let fake = Fake::new(record());
        fake.answers
            .borrow_mut()
            .push(refused(500, "internal", Value::Null));
        let e = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect_err("stopped");
        assert!(e.message.contains("may be ended already"), "{}", e.message);
        assert!(c.names_prod());
        assert!(kept::pinned(&local.pins, "k").expect("readable").is_some());
        let agreement = agreed(&local.agreed, "k")
            .expect("readable")
            .expect("recorded");
        assert_eq!(agreement.app_id, APP_ID);
        assert_eq!(agreement.host.as_deref(), Some("203.0.113.10"));
        assert_eq!(agreement.ids.len(), 2);
        // The account has taken them off; the address stays. Run again
        // with --yes and nobody there: what was agreed to finishes it.
        *fake.env.borrow_mut() = emptied();
        let (answer, _) = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect("deleted");
        assert_eq!(answer["ended"], true);
        assert!(*fake.gone.borrow());
        assert!(!c.names_prod());
    }

    #[tokio::test]
    async fn the_last_environment_takes_the_apps_record_with_it_and_the_question_says_so() {
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        *fake.app_envs.borrow_mut() = vec!["prod"];
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            assert!(
                q.contains("app bot's last environment")
                    && q.contains("settings and secrets")
                    && q.contains("Delete environment prod"),
                "{q}"
            );
            Ok(true)
        })
        .await
        .expect("deleted");
        // The app's record goes after the environment's, at its revision.
        assert_eq!(
            *fake.log.borrow(),
            ["delete env at 7".to_owned(), "delete app at 1".to_owned()]
        );
        assert!(*fake.app_gone.borrow());
        assert_eq!(answer["app_deleted"], true);
        assert!(text.contains("App bot's record is gone"), "{text}");
        assert!(!c.names_prod());
        assert_eq!(agreed(&local.agreed, "k").expect("readable"), None);
    }

    #[tokio::test]
    async fn with_another_environment_the_apps_record_stays_and_is_not_asked_about() {
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            assert!(!q.contains("last environment"), "{q}");
            Ok(true)
        })
        .await
        .expect("deleted");
        assert_eq!(*fake.log.borrow(), ["delete env at 7".to_owned()]);
        assert_eq!(answer["app_deleted"], false);
        assert!(!text.contains("App bot"), "{text}");
        // Nor when its other environment went while the person was asked:
        // what they were told is what is done.
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        run_with(&fake, &app(), "bot", &local, (false, false, true), |_| {
            fake.app_envs.borrow_mut().retain(|e| *e == "prod");
            Ok(true)
        })
        .await
        .expect("deleted");
        assert!(
            !fake
                .log
                .borrow()
                .iter()
                .any(|l| l.starts_with("delete app"))
        );
        assert!(!*fake.app_gone.borrow());
        // Nor when the account's answer lists no environment at all, this
        // one included: it says nothing of the others.
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        fake.app_envs.borrow_mut().clear();
        let (answer, _) = run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            assert!(!q.contains("last environment"), "{q}");
            Ok(true)
        })
        .await
        .expect("deleted");
        assert!(
            !fake
                .log
                .borrow()
                .iter()
                .any(|l| l.starts_with("delete app"))
        );
        assert_eq!(answer["app_deleted"], false);
    }

    #[tokio::test]
    async fn under_yes_the_apps_record_going_is_said_on_stderr() {
        let c = Checkout::new();
        c.pin();
        let fake = Fake::new(record());
        *fake.app_envs.borrow_mut() = vec!["prod"];
        let _ = crate::node::common::heard::take_printed();
        run_with(&fake, &app(), "bot", &c.local(), (true, true, false), never)
            .await
            .expect("deleted");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("deleting app bot's record from the ERPC account too")
                && printed.contains("settings and secrets"),
            "{printed}"
        );
        assert!(*fake.app_gone.borrow());
    }

    #[tokio::test]
    async fn only_this_environment_listed_alone_is_the_apps_last() {
        // The app's record lists one environment, another one: this is not
        // its last, and nothing of the app's goes.
        let c = Checkout::new();
        c.pin();
        let fake = Fake::new(record());
        *fake.app_envs.borrow_mut() = vec!["staging"];
        let (answer, _) = run_with(
            &fake,
            &app(),
            "bot",
            &c.local(),
            (false, false, true),
            |q| {
                assert!(!q.contains("last environment"), "{q}");
                Ok(true)
            },
        )
        .await
        .expect("deleted");
        assert_eq!(answer["app_deleted"], false);
        assert!(
            !fake
                .log
                .borrow()
                .iter()
                .any(|l| l.starts_with("delete app"))
        );
    }

    #[tokio::test]
    async fn another_app_by_the_name_by_then_keeps_its_record() {
        let c = Checkout::new();
        c.pin();
        let fake = Fake::new(record());
        *fake.app_envs.borrow_mut() = vec!["prod"];
        *fake.app_id_after.borrow_mut() = Some("0d4b2c1a-9e8f-4a7b-b6c5-d4e3f2a1b0c9");
        let (answer, text) = run_with(
            &fake,
            &app(),
            "bot",
            &c.local(),
            (false, false, true),
            |_| Ok(true),
        )
        .await
        .expect("deleted");
        assert_eq!(answer["app_deleted"], false);
        assert!(text.contains("App bot's record stays"), "{text}");
        assert!(
            !fake
                .log
                .borrow()
                .iter()
                .any(|l| l.starts_with("delete app"))
        );
        assert!(!*fake.app_gone.borrow());
    }

    #[tokio::test]
    async fn an_environment_gone_takes_the_apps_record_only_as_the_agreement_says() {
        // The environment went in an earlier run whose question did not
        // name the app (its other environment was there then); the app now
        // has none: its record stays, not asked about.
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        *fake.app_envs.borrow_mut() = vec!["prod"];
        *fake.gone.borrow_mut() = true;
        record_agreed(
            &local.agreed,
            &local.pin_key,
            Some(&Agreed {
                app_id: APP_ID.to_owned(),
                host: None,
                ids: Vec::new(),
                parts: Vec::new(),
                app_too: false,
            }),
        )
        .expect("recorded");
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect("put away");
        assert_eq!(answer["already_gone"], true);
        assert_eq!(answer["app_deleted"], false);
        assert!(!text.contains("App bot"), "{text}");
        assert!(
            !fake
                .log
                .borrow()
                .iter()
                .any(|l| l.starts_with("delete app"))
        );
        assert!(!*fake.app_gone.borrow());
    }

    #[tokio::test]
    async fn an_apps_record_gone_by_the_time_a_stopped_run_finishes_is_gone() {
        // The environment went, and the app's record with it, before this
        // machine heard: the same command finds both gone and puts away here.
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        *fake.gone.borrow_mut() = true;
        *fake.app_gone.borrow_mut() = true;
        record_agreed(
            &local.agreed,
            &local.pin_key,
            Some(&Agreed {
                app_id: APP_ID.to_owned(),
                host: None,
                ids: Vec::new(),
                parts: Vec::new(),
                app_too: true,
            }),
        )
        .expect("recorded");
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect("finished");
        assert_eq!(answer["already_gone"], true);
        assert_eq!(answer["app_deleted"], true);
        assert!(text.contains("App bot's record is gone"), "{text}");
        assert!(
            !fake
                .log
                .borrow()
                .iter()
                .any(|l| l.starts_with("delete app"))
        );
        assert!(!c.names_prod());
    }

    #[tokio::test]
    async fn an_app_that_has_an_environment_again_by_then_keeps_its_record() {
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        *fake.app_envs.borrow_mut() = vec!["prod"];
        // Another sign-in makes one while the person is asked.
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (false, false, true), |_| {
            fake.app_envs.borrow_mut().push("staging");
            Ok(true)
        })
        .await
        .expect("deleted");
        assert!(
            !fake
                .log
                .borrow()
                .iter()
                .any(|l| l.starts_with("delete app"))
        );
        assert_eq!(answer["app_deleted"], false);
        assert!(text.contains("App bot's record stays"), "{text}");
        assert!(!c.names_prod());
    }

    #[tokio::test]
    async fn a_run_that_stopped_at_the_apps_record_is_finished_by_the_same_command() {
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        *fake.app_envs.borrow_mut() = vec!["prod"];
        fake.app_answers.borrow_mut().push(no_code(503));
        // --yes, nobody there: the environment goes, the app's record not.
        let e = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect_err("stopped");
        assert!(*fake.gone.borrow());
        assert!(
            e.message.contains(
                "environment prod is deleted from the ERPC account, and app bot's record is not yet"
            ),
            "{}",
            e.message
        );
        assert!(
            e.hint
                .unwrap_or_default()
                .contains("`erpc worker delete --release-server --env prod")
        );
        // Nothing here is put away: the same command finds it again.
        assert!(c.names_prod());
        assert!(kept::pinned(&local.pins, "k").expect("readable").is_some());
        let agreement = agreed(&local.agreed, "k")
            .expect("readable")
            .expect("recorded");
        assert!(agreement.app_too);
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect("finished");
        assert_eq!(answer["already_gone"], true);
        assert_eq!(answer["app_deleted"], true);
        assert!(text.contains("App bot's record is gone"), "{text}");
        assert_eq!(
            fake.log
                .borrow()
                .iter()
                .filter(|l| l.starts_with("delete app"))
                .count(),
            2
        );
        assert!(!c.names_prod());
        assert_eq!(agreed(&local.agreed, "k").expect("readable"), None);
    }

    #[tokio::test]
    async fn the_apps_delete_is_sent_again_when_its_record_moved_and_a_gone_one_is_gone() {
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        *fake.app_envs.borrow_mut() = vec!["prod"];
        fake.app_answers.borrow_mut().extend([
            refused(409, "revision_conflict", Value::Null),
            refused(404, "worker_not_found", Value::Null),
        ]);
        let (answer, _) = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect("deleted");
        assert_eq!(answer["app_deleted"], true);
        assert_eq!(
            fake.log
                .borrow()
                .iter()
                .filter(|l| l.starts_with("delete app"))
                .count(),
            2
        );
        // Out of tries while it keeps moving: stopped, said, finished later.
        let c = Checkout::new();
        c.pin();
        let local = c.local();
        let fake = Fake::new(record());
        *fake.app_envs.borrow_mut() = vec!["prod"];
        fake.app_answers
            .borrow_mut()
            .extend((0..APP_TRIES).map(|_| refused(409, "revision_conflict", Value::Null)));
        let e = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect_err("stopped");
        assert!(e.message.contains("kept changing"), "{}", e.message);
        assert!(c.names_prod());
    }

    #[test]
    fn an_agreement_recorded_before_the_apps_record_could_go_with_it_is_read_without_it() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("worker_delete.json");
        std::fs::write(
            &path,
            r#"{ "agreed": { "k": { "appId": "a", "host": null, "ids": [] } } }"#,
        )
        .expect("written");
        let read = agreed(&path, "k").expect("readable").expect("there");
        assert!(!read.app_too);
    }

    #[tokio::test]
    async fn an_address_with_no_server_and_nothing_agreed_is_asked_at_a_terminal_only() {
        let c = Checkout::new();
        let local = c.local();
        let fake = Fake::new(emptied());
        // `--yes` is not enough, nor `--json` at a terminal.
        for asking in [
            (true, false, false),
            (true, true, true),
            (false, true, true),
        ] {
            let e = run_with(&fake, &app(), "bot", &local, asking, never)
                .await
                .expect_err("refused");
            assert_eq!(e.code, Code::NeedsTerminal);
            assert!(e.message.contains("203.0.113.10"), "{}", e.message);
        }
        assert!(fake.log.borrow().is_empty());
        // An agreement of another address, or another app, does not count.
        for stale in [
            Agreed {
                app_id: APP_ID.to_owned(),
                host: Some("198.51.100.77".to_owned()),
                ids: vec![],
                parts: vec![],
                app_too: false,
            },
            Agreed {
                app_id: "1a2b3c4d-0000-4000-8000-000000000000".to_owned(),
                host: Some("203.0.113.10".to_owned()),
                ids: vec![],
                parts: vec![],
                app_too: false,
            },
        ] {
            record_agreed(&local.agreed, "k", Some(&stale)).expect("recorded");
            let e = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
                .await
                .expect_err("refused");
            assert_eq!(e.code, Code::NeedsTerminal);
        }
        // At a terminal, told both; a yes deletes it, and says nothing was
        // there to end.
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            assert!(
                q.contains("of your own") && q.contains("ended already"),
                "{q}"
            );
            Ok(true)
        })
        .await
        .expect("deleted");
        assert_eq!(answer["ended"], false);
        assert!(text.contains("nothing to end"), "{text}");
    }

    #[tokio::test]
    async fn the_told_both_question_is_asked_at_a_terminal_even_with_yes_and_a_no_undoes_an_agreement()
     {
        let c = Checkout::new();
        let local = c.local();
        let fake = Fake::new(emptied());
        let e = run_with(&fake, &app(), "bot", &local, (true, false, true), |q| {
            assert!(q.contains("of your own"), "{q}");
            Ok(false)
        })
        .await
        .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert!(fake.log.borrow().is_empty());
        // An agreement from an earlier run, then a no to the question: gone.
        record_agreed(
            &local.agreed,
            "k",
            Some(&Agreed {
                app_id: APP_ID.to_owned(),
                host: Some("203.0.113.10".to_owned()),
                ids: vec![],
                parts: vec![],
                app_too: false,
            }),
        )
        .expect("recorded");
        let fake = Fake::new(emptied());
        run_with(&fake, &app(), "bot", &local, (false, false, true), |_| {
            Ok(false)
        })
        .await
        .expect_err("declined");
        assert_eq!(agreed(&local.agreed, "k").expect("readable"), None);
    }

    #[tokio::test]
    async fn nothing_is_sent_when_what_was_agreed_to_cannot_be_recorded() {
        let c = Checkout::new();
        // A directory where the file would be: neither read nor written.
        let blocked = c.dir.path().join("worker_delete.json");
        std::fs::create_dir(&blocked).expect("a directory");
        let local = Local {
            agreed: blocked,
            ..c.local()
        };
        let fake = Fake::new(record());
        let e = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect_err("refused");
        assert!(e.message.contains("nothing was sent"), "{}", e.message);
        assert!(fake.log.borrow().is_empty());
        assert!(c.names_prod());
    }

    #[tokio::test]
    async fn a_server_another_environment_here_may_be_on_is_not_ended_with_yes() {
        let c = Checkout::new();
        let shared = |host: &str| -> Result<crate::worker::remote::Sharing, CliError> {
            assert_eq!(host, "203.0.113.10");
            Ok(crate::worker::remote::Sharing::named(vec![
                "relay --env prod".to_owned(),
            ]))
        };
        let local = Local {
            sharing: &shared,
            ..c.local()
        };
        let fake = Fake::new(record());
        let e = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        assert!(e.message.contains("relay --env prod"), "{}", e.message);
        assert!(fake.log.borrow().is_empty());
        // At a terminal, the question names them.
        run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            assert!(q.contains("relay --env prod"), "{q}");
            Ok(true)
        })
        .await
        .expect("deleted");
    }

    #[tokio::test]
    async fn an_agreement_does_not_cover_what_was_added_since() {
        let c = Checkout::new();
        let local = c.local();
        record_agreed(
            &local.agreed,
            "k",
            Some(&Agreed {
                app_id: APP_ID.to_owned(),
                host: Some("203.0.113.10".to_owned()),
                ids: vec!["0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60".to_owned()],
                parts: vec![],
                app_too: false,
            }),
        )
        .expect("recorded");
        // The server came off; a line the agreement does not name is there.
        let mut now = record();
        now.servers.clear();
        let fake = Fake::new(now);
        let e = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert!(fake.log.borrow().is_empty());
    }

    #[tokio::test]
    async fn an_environment_the_account_no_longer_has_is_only_put_away_here() {
        // Trusted here under this sign-in: put away without asking.
        let c = Checkout::new();
        c.pin();
        let fake = Fake::new(record());
        *fake.gone.borrow_mut() = true;
        let (answer, text) = run_with(
            &fake,
            &app(),
            "bot",
            &c.local(),
            (false, true, false),
            never,
        )
        .await
        .expect("put away");
        assert_eq!(answer["already_gone"], true);
        assert!(text.contains("no longer has"), "{text}");
        assert!(fake.log.borrow().is_empty());
        assert!(!c.names_prod());
        // An app the account no longer has, never trusted here: asked
        // first, and `--yes` goes ahead.
        let c = Checkout::new();
        let fake = Fake::new(record());
        fake.reads
            .borrow_mut()
            .push(refused(404, "worker_not_found", Value::Null));
        let e = run_with(
            &fake,
            &app(),
            "bot",
            &c.local(),
            (false, true, false),
            never,
        )
        .await
        .expect_err("asked first");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert!(c.names_prod());
        fake.reads
            .borrow_mut()
            .push(refused(404, "worker_not_found", Value::Null));
        run_with(&fake, &app(), "bot", &c.local(), (true, true, false), never)
            .await
            .expect("put away");
        assert!(!c.names_prod());
    }

    #[tokio::test]
    async fn a_local_step_that_fails_is_said_and_erpc_toml_is_not_said_to_be_updated() {
        let c = Checkout::new();
        let missing = c.dir.path().join("gone").join("erpc.toml");
        let local = Local {
            path: &missing,
            ..c.local()
        };
        let fake = Fake::new(record());
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect("deleted in the account");
        assert_eq!(answer["erpc_toml"], false);
        assert!(answer["erpc_toml_error"].is_string());
        assert!(text.contains("warning:"), "{text}");
        assert!(!text.contains("erpc.toml no longer"), "{text}");
    }

    #[test]
    fn flags_that_do_not_belong_are_refused_before_anything_is_reached() {
        let ask = |release_server: bool, forget: bool, forget_lines: Vec<String>| DeleteAsk {
            release_server,
            forget,
            forget_lines,
            yes: true,
        };
        let e = refuse_flags(&app(), &ask(false, false, vec![])).expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        assert!(e.hint.unwrap_or_default().contains("--release-server"));
        for asked in [
            ask(true, true, vec![]),
            ask(true, false, vec!["c47a1e09".to_owned()]),
        ] {
            assert_eq!(
                refuse_flags(&app(), &asked).expect_err("refused").code,
                Code::Usage
            );
        }
        refuse_flags(&app(), &ask(true, false, vec![])).expect("taken");
    }

    #[tokio::test]
    async fn a_server_with_nothing_to_compare_by_is_one_something_may_be_on() {
        let c = Checkout::new();
        // In use with no address on record, and one coming in.
        let mut no_address = record();
        no_address.facts.host = None;
        let mut moving = record();
        let mut incoming = moving.servers[0].clone();
        incoming.id = "1c9e7d52-91d4-4f6a-8e23-7d1a5c9b3e61".to_owned();
        incoming.slot = account::Slot::Incoming;
        moving.servers.push(incoming);
        for r in [no_address, moving] {
            let fake = Fake::new(r);
            // --yes, and --json with nobody to ask: refused, nothing sent.
            for asking in [
                (true, false, true),
                (true, true, false),
                (false, true, true),
                (false, false, false),
            ] {
                let e = run_with(&fake, &app(), "bot", &c.local(), asking, never)
                    .await
                    .expect_err("refused");
                let code = if asking.0 {
                    Code::Usage
                } else {
                    Code::NeedsTerminal
                };
                assert_eq!(e.code, code, "{asking:?}");
                assert!(e.message.contains("only after a yes"), "{}", e.message);
                let hint = e.hint.unwrap_or_default();
                assert!(
                    hint.contains("--json") && !hint.contains("delete those"),
                    "{hint}"
                );
            }
            assert!(fake.log.borrow().is_empty());
            // At a terminal, the question names it.
            run_with(
                &fake,
                &app(),
                "bot",
                &c.local(),
                (false, false, true),
                |q| {
                    assert!(
                        q.starts_with(
                            "This machine cannot tell whether another app or environment is on "
                        ) && q.contains("; whatever is there ends with the delete. Delete ")
                            && !q.contains("may also run"),
                        "{q}"
                    );
                    Ok(true)
                },
            )
            .await
            .expect("deleted");
        }
    }

    #[tokio::test]
    async fn a_list_that_cannot_be_read_sends_nothing() {
        let c = Checkout::new();
        let unreadable = |_: &str| -> Result<crate::worker::remote::Sharing, CliError> {
            Err(failed("workers.toml could not be read".to_owned()))
        };
        let local = Local {
            sharing: &unreadable,
            ..c.local()
        };
        let fake = Fake::new(record());
        let e = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect_err("refused");
        assert!(e.message.contains("could not be read"), "{}", e.message);
        assert!(fake.log.borrow().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_agreement_goes_first_and_a_later_local_step_that_fails_is_finished_by_running_again()
     {
        use std::os::unix::fs::PermissionsExt as _;
        let c = Checkout::new();
        let trust = c.dir.path().join("trust");
        std::fs::create_dir(&trust).expect("made");
        let local = Local {
            pins: trust.join("worker_account.json"),
            ..c.local()
        };
        kept::pin(&local.pins, "k", &kept::Anchor::of(APP_ID, &record())).expect("pinned");
        // This machine's record of what it trusts cannot be written.
        std::fs::set_permissions(&trust, std::fs::Permissions::from_mode(0o500)).expect("held");
        let fake = Fake::new(record());
        let (answer, text) = run_with(&fake, &app(), "bot", &local, (true, true, false), never)
            .await
            .expect("deleted in the account");
        std::fs::set_permissions(&trust, std::fs::Permissions::from_mode(0o700)).expect("freed");
        assert_eq!(answer["erpc_toml"], false);
        assert!(text.contains("warning:"), "{text}");
        // The agreement is gone, the pin and erpc.toml are as they were.
        assert_eq!(agreed(&local.agreed, "k").expect("readable"), None);
        assert!(kept::pinned(&local.pins, "k").expect("readable").is_some());
        assert!(c.names_prod());
        // Run again, nobody there: the account no longer has it, this
        // machine trusted it, so it is put away without asking.
        run_with(&fake, &app(), "bot", &local, (false, true, false), never)
            .await
            .expect("put away");
        assert!(!c.names_prod());
        assert_eq!(kept::pinned(&local.pins, "k").expect("readable"), None);
    }

    #[tokio::test]
    async fn a_server_only_coming_in_or_going_out_is_named_in_the_told_both_question_too() {
        let c = Checkout::new();
        for slot in [account::Slot::Incoming, account::Slot::Outgoing] {
            let mut r = record();
            r.servers[0].slot = slot;
            let fake = Fake::new(r);
            for asking in [
                (true, false, true),
                (true, true, false),
                (false, true, true),
                (false, false, false),
            ] {
                let e = run_with(&fake, &app(), "bot", &c.local(), asking, never)
                    .await
                    .expect_err("refused");
                let code = if asking.0 {
                    Code::Usage
                } else {
                    Code::NeedsTerminal
                };
                assert_eq!(e.code, code, "{asking:?}");
            }
            assert!(fake.log.borrow().is_empty());
            run_with(
                &fake,
                &app(),
                "bot",
                &c.local(),
                (false, false, true),
                |q| {
                    assert!(
                        q.starts_with(
                            "This machine cannot tell whether another app or environment is on a \
                             server coming in or going out (the account's record ties it to no \
                             address); whatever is there ends with the delete. "
                        ),
                        "{q}"
                    );
                    // The address may be that server's: "ended already" only
                    // of one the account no longer lists.
                    assert!(q.contains("names no server in use"), "{q}");
                    assert!(
                        q.contains(
                            "an ERPC Worker the account no longer lists for this environment, \
                             it is ended already"
                        ),
                        "{q}"
                    );
                    Ok(true)
                },
            )
            .await
            .expect("deleted");
        }
    }

    #[tokio::test]
    async fn a_server_shared_by_the_list_is_said_so_and_yes_at_a_terminal_is_not_enough() {
        let c = Checkout::new();
        let shared = |_: &str| -> Result<crate::worker::remote::Sharing, CliError> {
            Ok(crate::worker::remote::Sharing::named(vec![
                "relay --env prod".to_owned(),
            ]))
        };
        let local = Local {
            sharing: &shared,
            ..c.local()
        };
        let fake = Fake::new(record());
        let e = run_with(&fake, &app(), "bot", &local, (true, false, true), never)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        let e = run_with(&fake, &app(), "bot", &local, (false, true, true), never)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert!(fake.log.borrow().is_empty());
        run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
            assert!(
                q.starts_with(
                    "By this machine's list of apps, the server in use may also run relay \
                     --env prod, which ending it ends too."
                ),
                "{q}"
            );
            Ok(true)
        })
        .await
        .expect("deleted");
    }

    #[tokio::test]
    async fn a_live_server_that_is_not_active_is_one_something_may_be_on_too() {
        let c = Checkout::new();
        let mut in_use = record();
        in_use.facts.host = None;
        in_use.servers[0].state = account::State::from("suspended");
        let mut suspended_incoming = record();
        suspended_incoming.servers[0].slot = account::Slot::Incoming;
        suspended_incoming.servers[0].state = account::State::from("suspended");
        let mut provisioning_incoming = record();
        provisioning_incoming.servers[0].slot = account::Slot::Incoming;
        provisioning_incoming.servers[0].state = account::State::from("provisioning");
        for r in [in_use, suspended_incoming, provisioning_incoming] {
            let fake = Fake::new(r);
            for asking in [
                (true, false, true),
                (false, true, true),
                (false, false, false),
            ] {
                let e = run_with(&fake, &app(), "bot", &c.local(), asking, never)
                    .await
                    .expect_err("refused");
                assert!(e.message.contains("only after a yes"), "{}", e.message);
            }
            assert!(fake.log.borrow().is_empty());
        }
    }

    #[tokio::test]
    async fn what_a_delete_ends_is_printed_under_json_too() {
        let c = Checkout::new();
        let fake = Fake::new(record());
        let _ = crate::node::common::heard::take_printed();
        run_with(&fake, &app(), "bot", &c.local(), (true, true, false), never)
            .await
            .expect("deleted");
        let printed = crate::node::common::heard::take_printed().join("\n");
        assert!(
            printed.contains("ending 1 ERPC Worker, its gRPC line and deleting environment prod"),
            "{printed}"
        );
    }

    #[tokio::test]
    async fn fixing_a_file_is_offered_only_when_one_could_not_be_read() {
        let c = Checkout::new();
        for (unread, offered) in [(false, false), (true, true)] {
            let shared = move |_: &str| -> Result<crate::worker::remote::Sharing, CliError> {
                Ok(crate::worker::remote::Sharing {
                    named: vec!["relay --env prod".to_owned()],
                    unread,
                })
            };
            let local = Local {
                sharing: &shared,
                ..c.local()
            };
            let fake = Fake::new(record());
            let e = run_with(&fake, &app(), "bot", &local, (true, false, true), never)
                .await
                .expect_err("refused");
            let hint = e.hint.unwrap_or_default();
            assert_eq!(hint.contains("could not be read"), offered, "{hint}");
        }
        // A server with no address alone: nothing to fix.
        let mut r = record();
        r.facts.host = None;
        let fake = Fake::new(r);
        let e = run_with(&fake, &app(), "bot", &c.local(), (true, false, true), never)
            .await
            .expect_err("refused");
        assert!(!e.hint.unwrap_or_default().contains("could not be read"));
    }

    #[test]
    fn two_servers_in_transit_are_named_as_two_and_japanese_reads_without_a_gap() {
        use erpc_core::i18n::Lang;
        let c = Checkout::new();
        let mut r = record();
        r.servers[0].slot = account::Slot::Incoming;
        let mut out = r.servers[0].clone();
        out.slot = account::Slot::Outgoing;
        out.id = "1c9d8e63-02f5-4b7a-9f34-8e2b6d0a4c71".to_owned();
        r.servers.push(out);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        let fake = Fake::new(r.clone());
        runtime
            .block_on(run_with(
                &fake,
                &app(),
                "bot",
                &c.local(),
                (false, false, true),
                |q| {
                    assert!(q.contains("the servers coming in and going out"), "{q}");
                    Ok(false)
                },
            ))
            .expect_err("declined");
        for (lang, stop) in [(Lang::Ja, "。 "), (Lang::Zh, "。 ")] {
            let fake = Fake::new(r.clone());
            crate::cli::i18n::speaking(lang, || {
                runtime.block_on(run_with(
                    &fake,
                    &app(),
                    "bot",
                    &c.local(),
                    (false, false, true),
                    |q| {
                        assert!(!q.contains(stop) && !q.contains("。 "), "{lang:?}: {q}");
                        Ok(false)
                    },
                ))
            })
            .expect_err("declined");
        }
    }

    #[tokio::test]
    async fn a_server_in_use_that_is_not_active_is_compared_with_the_list_by_its_address() {
        let c = Checkout::new();
        let shared = |host: &str| -> Result<crate::worker::remote::Sharing, CliError> {
            assert_eq!(host, "203.0.113.10");
            Ok(crate::worker::remote::Sharing::named(vec![
                "relay --env prod".to_owned(),
            ]))
        };
        let local = Local {
            sharing: &shared,
            ..c.local()
        };
        for state in ["suspended", "provisioning"] {
            let mut r = record();
            r.servers[0].state = account::State::from(state);
            let fake = Fake::new(r);
            for (asking, code) in [
                ((true, false, true), Code::Usage),
                ((false, true, true), Code::NeedsTerminal),
                ((false, false, false), Code::NeedsTerminal),
            ] {
                let e = run_with(&fake, &app(), "bot", &local, asking, never)
                    .await
                    .expect_err("refused");
                assert_eq!(e.code, code, "{state}: {asking:?}");
                assert!(e.message.contains("relay --env prod"), "{}", e.message);
            }
            assert!(fake.log.borrow().is_empty(), "{state}");
            run_with(&fake, &app(), "bot", &local, (false, false, true), |q| {
                assert!(
                    q.starts_with(
                        "By this machine's list of apps, the server in use may also run relay"
                    ),
                    "{state}: {q}"
                );
                Ok(false)
            })
            .await
            .expect_err("declined");
        }
    }

    #[test]
    fn another_operation_on_the_environment_is_waited_for_as_a_busy_account() {
        let refusal = |code: &str, data: Value| account::Refusal {
            status: 409,
            code: Some(AccountCode::from(code)),
            message: None,
            data,
        };
        let next = |r| {
            let mut seen = Seen {
                ended_some: false,
                clean: true,
            };
            let next = after_refusal(r, &mut seen, PAUSE, "bot", &app());
            (next, seen)
        };
        let held = |wait: Value| {
            refusal(
                "end_refused",
                json!({
                    "reason": "operation_in_progress", "retryAfter": wait,
                    "remaining": 2, "currentRevision": 8
                }),
            )
        };
        // Its wait, said as a busy account; the run no longer clean, as the
        // request may have ended some first; nothing taken as an end under
        // way.
        let (n, seen) = next(held(json!(30)));
        assert!(matches!(n, Next::Again(wait, false) if wait == Duration::from_secs(30)));
        assert!(!seen.clean);
        assert!(!seen.ended_some);
        // Never longer than the longest wait; without a wait, the pause.
        let (n, _) = next(held(json!(150)));
        assert!(matches!(n, Next::Again(wait, false) if wait == BUSY_WAIT_MAX));
        let (n, _) = next(held(Value::Null));
        assert!(matches!(n, Next::Again(wait, false) if wait == PAUSE));
        // Any other refusal to end stops, as before.
        let (n, _) = next(refusal(
            "end_refused",
            json!({ "reason": "server_changed" }),
        ));
        assert!(matches!(n, Next::Stop(_, false)));
        let (n, _) = next(refusal("end_refused", Value::Null));
        assert!(matches!(n, Next::Stop(_, false)));
    }

    #[tokio::test]
    async fn a_delete_waits_while_another_operation_holds_the_environment_and_says_so() {
        let fake = Fake::new(record());
        fake.answers.borrow_mut().push(refused(
            409,
            "end_refused",
            json!({
                "reason": "operation_in_progress", "retryAfter": 1,
                "remaining": 1, "currentRevision": 8
            }),
        ));
        let _ = crate::node::common::heard::take();
        let began = std::time::Instant::now();
        ended_with(&fake, &record()).await.expect("deleted");
        assert!(began.elapsed() >= Duration::from_secs(1));
        assert_eq!(fake.log.borrow().len(), 2);
        let said = crate::node::common::heard::take();
        assert!(
            said.iter()
                .any(|l| l == "the ERPC account is busy; asking again in 1 s"),
            "{said:?}"
        );
        assert!(!said.iter().any(|l| l.contains("is ending")), "{said:?}");
    }

    #[tokio::test]
    async fn held_throughout_it_stops_and_never_says_nothing_was_ended() {
        let fake = Fake::new(record());
        for _ in 0..TRIES {
            fake.answers.borrow_mut().push(refused(
                409,
                "end_refused",
                json!({ "reason": "operation_in_progress", "retryAfter": 0, "remaining": 1 }),
            ));
        }
        let e = ended_with(&fake, &record()).await.expect_err("stopped");
        assert!(e.message.contains("stayed busy"), "{}", e.message);
        assert!(e.message.contains("may be ended already"), "{}", e.message);
        assert!(!e.message.contains("nothing was ended"), "{}", e.message);
        assert_eq!(fake.log.borrow().len(), TRIES as usize);
    }
}
