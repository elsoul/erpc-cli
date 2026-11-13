// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The verbs that act on a deployed worker: `status`, `logs`, `start`,
//! `stop`, `restart`, `rollback`, `releases` and `delete`, each one SSH
//! connection to the server `[env.<name>]` names, pinned to its host key,
//! running the agent's `ctl` ([`erpc_worker::server`]).
//!
//! `start` and `restart` hand the key and the secrets over first when the
//! worker is locked: after a reboot, or a restart of its agent, the server
//! holds neither.

use erpc_ssh::worker::{Command as Worker, ReleaseId, UnitId, Verb};
use erpc_ssh::{HostKey, RemoteCommand, Session, Stream, Target};
use erpc_worker::manifest::{Env, Line, Manifest, Resource};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::node_common::{Say, go_ahead};
use crate::worker::{App, load_env};
use crate::worker_secrets;

pub(crate) fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

/// The SSH target `env` names, with the user's key.
pub(crate) fn target(app: &App, env: &Env) -> Result<Target, CliError> {
    let env_name = &app.env;
    let scope = app.scope();
    let host = env.host.clone().ok_or_else(|| {
        failed(match &env.inventory {
            Some(i) => t!(
                "worker_remote.target.none_in_vault",
                env = env_name,
                vault = i.vault,
                command = format!("erpc worker deploy{scope}")
            ),
            None => t!(
                "worker_remote.target.no_host",
                env = env_name,
                command = format!("erpc worker deploy{scope}")
            ),
        })
    })?;
    let host_key = env
        .host_key
        .as_deref()
        .ok_or_else(|| failed(t!("worker_remote.target.no_host_key", env = env_name)))
        .and_then(|k| HostKey::parse(k).map_err(|e| failed(e.to_string())))?;
    let (_, identity) = crate::vps_access::login_key().map_err(failed)?;
    Ok(Target {
        host,
        port: env.ssh_port(),
        user: env.ssh_user.clone().unwrap_or_else(|| "root".to_owned()),
        host_key,
        identity,
    })
}

pub(crate) fn open(target: &Target) -> Result<Session, CliError> {
    Session::open(target).map_err(|e| CliError::new(Code::Network, e.to_string()))
}

/// Text a server sent, as a terminal may be given it: a control character
/// other than a line break or a tab, and a character that reorders the
/// text around it, become `?` ([`crate::storage::clean`]). A server is not
/// this machine: what runs there, an app or a proxy that faces the
/// network, may have put an escape sequence in what it says.
pub(crate) fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for piece in text.split_inclusive(['\n', '\t']) {
        let (body, end) = match piece.char_indices().next_back() {
            Some((at, '\n' | '\t')) => piece.split_at(at),
            _ => (piece, ""),
        };
        out.push_str(&crate::storage::clean(body));
        out.push_str(end);
    }
    out
}

/// Every string in an agent's answer, the names of its fields among them,
/// as [`shown`] has it: what is printed from the answer, as text or as
/// `--json`, is then nothing a terminal acts on, whatever the server sent.
fn plain(value: &mut Value) {
    match value {
        Value::String(text) => *text = shown(text),
        Value::Array(items) => items.iter_mut().for_each(plain),
        Value::Object(fields) => {
            for (name, mut value) in core::mem::take(fields) {
                plain(&mut value);
                fields.insert(shown(&name), value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// The answer in what `ctl` printed: its last line that is a JSON object,
/// with every string made safe to show ([`plain`]).
pub(crate) fn answer(stdout: &[u8]) -> Result<Value, CliError> {
    let text = String::from_utf8_lossy(stdout);
    let line = text
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or_default();
    let mut answer: Value = serde_json::from_str(line).map_err(|_| {
        failed(t!(
            "worker_remote.agent.unreadable",
            answer = shown(text.trim())
        ))
    })?;
    plain(&mut answer);
    Ok(answer)
}

/// Runs `ctl <verb>` and returns its answer. An answer with `ok: false`
/// is returned too, for the caller to read; only a broken one is an error.
pub(crate) fn ctl(
    session: &Session,
    id: &UnitId,
    verb: Verb,
    stdin: Option<&[u8]>,
) -> Result<Value, CliError> {
    let out = session
        .run(
            &RemoteCommand::Worker(Worker::Ctl {
                id: id.clone(),
                verb,
            }),
            stdin,
        )
        .map_err(|e| failed(t!("worker_remote.agent.unreachable", error = e)))?;
    answer(&out.stdout)
}

/// [`ctl`], with an answer that says it failed made an error.
pub(crate) fn ctl_ok(
    session: &Session,
    id: &UnitId,
    verb: Verb,
    stdin: Option<&[u8]>,
) -> Result<Value, CliError> {
    let answer = ctl(session, id, verb, stdin)?;
    if answer["ok"].as_bool() == Some(false) {
        return Err(refusal(&answer));
    }
    Ok(answer)
}

/// An answer that says it failed, as an error: the agent's own words for
/// why and, when the app's port is not free, what to change
/// ([`port_hint`]).
fn refusal(answer: &Value) -> CliError {
    let why = answer["error"]
        .as_str()
        .map_or_else(|| t!("worker_remote.agent.refused"), str::to_owned);
    match port_hint(&why) {
        Some(hint) => failed(why).hint(hint),
        None => failed(why),
    }
}

/// What to change, when the agent refused a start because the app's port
/// is not free on the server: the agent names the port and who has it,
/// and this says where the app's own port is set.
pub(crate) fn port_hint(refusal: &str) -> Option<String> {
    erpc_worker::server::taken_port(refusal).map(|port| t!("worker_remote.agent.port_taken", port))
}

/// The unlock request: the secrets read from their stores and the key,
/// as one JSON line in a buffer that is wiped. Built around the values
/// rather than through a serializer, and in a buffer sized for all of it
/// before anything goes in: a buffer that grows leaves the copy it grew
/// from behind, unwiped.
pub(crate) fn unlock_request(m: &Manifest) -> Result<Zeroizing<Vec<u8>>, CliError> {
    use core::fmt::Write as _;
    let mut secrets: Vec<(String, Zeroizing<String>)> = Vec::new();
    for (name, reference) in &m.secrets {
        let value = worker_secrets::read(reference).map_err(failed)?;
        let quoted = json_string(&value);
        let name = serde_json::to_string(name).map_err(|e| failed(e.to_string()))?;
        secrets.push((name, quoted));
    }
    let keypair = match &m.wallet {
        Some(wallet) => Some(
            worker_secrets::read_key(&wallet.source, wallet.pubkey.as_deref()).map_err(failed)?,
        ),
        None => None,
    };
    // Every byte is at most "255," for the key, and the rest is known.
    let size = 64
        + secrets
            .iter()
            .map(|(n, v)| n.len() + v.len() + 2)
            .sum::<usize>()
        + keypair.as_ref().map_or(4, |k| k.bytes().len() * 4 + 2);
    let mut line = Zeroizing::new(String::with_capacity(size));
    line.push_str("{\"op\":\"unlock\",\"secrets\":{");
    for (i, (name, quoted)) in secrets.iter().enumerate() {
        if i > 0 {
            line.push(',');
        }
        line.push_str(name);
        line.push(':');
        line.push_str(quoted);
    }
    line.push_str("},\"key\":");
    match &keypair {
        Some(keypair) => {
            line.push('[');
            for (i, b) in keypair.bytes().iter().enumerate() {
                if i > 0 {
                    line.push(',');
                }
                let _ = write!(line, "{b}");
            }
            line.push(']');
        }
        None => line.push_str("null"),
    }
    line.push_str("}\n");
    debug_assert!(line.len() <= size, "the unlock buffer was sized too small");
    let mut out = Zeroizing::new(Vec::with_capacity(line.len()));
    out.extend_from_slice(line.as_bytes());
    Ok(out)
}

/// `value` as a JSON string, in a buffer sized for the longest it can be
/// (every character escaped as `\u00XX`), so that it never grows and
/// leaves an unwiped copy behind.
fn json_string(value: &str) -> Zeroizing<String> {
    use core::fmt::Write as _;
    let mut out = Zeroizing::new(String::with_capacity(value.len() * 6 + 2));
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The app and environment, the worker's id, and a session to its server.
pub(crate) fn reach(app: &App) -> Result<(Manifest, UnitId, Session), CliError> {
    let (_, m) = load_env(app)?;
    let env = crate::worker::env_of(&m, app)?;
    let id = UnitId::new(&m.unit_id(&app.env)).map_err(failed)?;
    let session = open(&target(app, env)?)?;
    Ok((m, id, session))
}

pub(crate) fn done(json: bool, answer: &Value, text: String) -> Outcome {
    if json {
        crate::print_json(answer);
        Outcome::Done(String::new())
    } else {
        // At a terminal: the worker's state as a mark when the answer
        // carries one, else ✅.
        let state = answer["status"]["state"]
            .as_str()
            .or_else(|| answer["agent"]["state"].as_str());
        let mark = state.map_or("✅", crate::ui::state_mark);
        Outcome::Done(if crate::ui::stdout_drawn() {
            crate::ui::decorate(&text, mark)
        } else {
            text
        })
    }
}

/// Seconds as a person reads a duration: `3d 4h`, `2h 05m`, `12m 05s`, `45s`.
fn humane(secs: u64) -> String {
    let (d, h, m, s) = (
        secs / 86_400,
        secs % 86_400 / 3_600,
        secs % 3_600 / 60,
        secs % 60,
    );
    match (d, h, m) {
        (d, h, _) if d > 0 => format!("{d}d {h}h"),
        (_, h, m) if h > 0 => format!("{h}h {m:02}m"),
        (_, _, m) if m > 0 => format!("{m}m {s:02}s"),
        _ => format!("{s}s"),
    }
}

/// A one-line summary of the agent's status.
fn describe(agent: &Value) -> String {
    let state = agent["state"]
        .as_str()
        .map_or_else(|| t!("worker_remote.describe.unknown"), str::to_owned);
    let mut parts = vec![state];
    if let Some(r) = agent["release"].as_str() {
        parts.push(t!("worker_remote.describe.release", release = r));
    }
    if let Some(pid) = agent["pid"].as_u64() {
        parts.push(t!("worker_remote.describe.pid", pid));
    }
    if let Some(up) = agent["up_secs"].as_u64() {
        parts.push(t!("worker_remote.describe.up", time = humane(up)));
    }
    if let Some(n) = agent["restarts"].as_u64().filter(|n| *n > 0) {
        parts.push(tn!("worker_remote.describe.restarts", n));
    }
    if let Some(e) = agent["last_exit"].as_str() {
        parts.push(t!("worker_remote.describe.last_exit", exit = e));
    }
    if let Some(r) = agent["reason"].as_str() {
        parts.push(format!("({r})"));
    }
    parts.join(", ")
}

/// What the environment pays for by the hour, each in words: its server,
/// then its lines. Empty when nothing on record is hourly.
fn hourly_items(env: &Env) -> Vec<String> {
    let mut items = Vec::new();
    if let Some(r) = env
        .resource
        .as_ref()
        .filter(|r| r.hourly && !r.id.is_empty())
    {
        items.push(t!(
            "worker_remote.hourly.server",
            kind = r.kind.as_str(),
            id = r.id
        ));
    }
    for line in env.lines.iter().filter(|l| l.hourly) {
        items.push(t!(
            "worker_remote.hourly.line",
            kind = line.kind.label(),
            id = line.id
        ));
    }
    items
}

/// What keeps being charged after a command that does not end it, and how
/// to end it; none when nothing on record is hourly.
fn still_charged_line(env: &Env, scope: &str) -> Option<String> {
    let items = hourly_items(env);
    (!items.is_empty()).then(|| {
        t!(
            "worker_remote.hourly.still_charged",
            items = items.join(", "),
            scope
        )
    })
}

/// What the status says of what the environment pays for by the hour: the
/// account's own list when it could be read, with a price for each item,
/// else what is on record, which is all erpc knows then.
fn hourly_said(
    env: Option<&Env>,
    priced: Option<&crate::worker_charges::Charges>,
    scope: &str,
) -> Option<String> {
    match priced {
        Some(priced) => Some(priced.lines(scope).join("\n  ")),
        None => env.and_then(|e| still_charged_line(e, scope)),
    }
}

/// Before the app is stopped, restarted, rolled back, redeployed or
/// removed: an app that trades with a key may hold positions, which wait
/// while it is down.
pub(crate) fn positions_warning(m: &Manifest, app: &App, say: &Say) {
    if m.wallet.is_some() {
        say.line(&t!("worker_remote.positions.warning", scope = app.scope()));
    }
}

/// `erpc worker status`.
pub(crate) async fn status(json: bool, app: &App) -> Outcome {
    let run = async || -> Result<Outcome, CliError> {
        let (m, id, session) = reach(app)?;
        let (answer, text) = status_from(&m, app, |verb| ctl(&session, &id, verb, None)).await?;
        Ok(done(json, &answer, text))
    };
    run()
        .await
        .map_err(|e| unreached(app, e))
        .unwrap_or_else(Into::into)
}

/// What `status` does once the worker's server is reached: `ask` runs the
/// agent's `ctl` there and gives its answer. The agent is asked its
/// status; the answer gets what the environment pays for by the hour, and
/// is said ([`status_said`]). Returns the answer, as `--json` prints it,
/// and the text.
async fn status_from(
    m: &Manifest,
    app: &App,
    ask: impl FnOnce(Verb) -> Result<Value, CliError>,
) -> Result<(Value, String), CliError> {
    let mut answer = ask(Verb::Status)?;
    let env = m.env.get(&app.env);
    let host = env.and_then(|e| e.host.clone()).unwrap_or_default();
    // What the environment pays for by the hour, beside what the agent
    // says: the server and the lines on record.
    if let Some(env) = env {
        answer["hourly"] = json!({
            "server": env.resource.as_ref().filter(|r| r.hourly),
            "lines": env.lines.iter().filter(|l| l.hourly).collect::<Vec<_>>(),
        });
    }
    // What each of them costs now is the account's to say; without
    // it (not signed in, user-api away), what is on record.
    let priced = match env {
        Some(env) => crate::worker_charges::read(env).await,
        None => None,
    };
    if let Some(priced) = &priced {
        answer["hourly"]["charged"] = priced.json();
    }
    let charged = hourly_said(env, priced.as_ref(), &app.scope());
    let text = status_said(m, &app.env, &host, &mut answer, charged, &app.scope());
    Ok((answer, text))
}

/// What `erpc worker status` says of `m`'s environment `env_name` on
/// `host`, from the agent's `answer`: how the worker is and which
/// releases it has; then its WAF, as the agent reports it (`waf` in the
/// answer, which `--json` carries as it is), where it listens, since when
/// and what it has counted, and whether the rules it runs are erpc.toml's
/// ([`crate::worker_waf::status_lines`]); then `charged`, what it is
/// charged for by the hour. The answer gets `waf_rules` for `--json`
/// ([`crate::worker_waf::rules_named`]).
fn status_said(
    m: &Manifest,
    env_name: &str,
    host: &str,
    answer: &mut Value,
    charged: Option<String>,
    scope: &str,
) -> String {
    let none = || t!("worker_remote.status.none");
    let mut text = format!(
        "{}\n  {}",
        t!(
            "worker_remote.status.title",
            worker = m.unit_id(env_name),
            host,
            agent = answer["agent"].as_object().map_or_else(
                || t!(
                    "worker_remote.status.no_answer",
                    error = answer["error"].as_str().unwrap_or("")
                ),
                |_| describe(&answer["agent"])
            )
        ),
        tn!(
            "worker_remote.status.releases",
            answer["releases"].as_u64().unwrap_or(0),
            current = answer["current"].as_str().map_or_else(none, str::to_owned),
            previous = answer["previous"].as_str().map_or_else(none, str::to_owned)
        ),
    );
    for line in crate::worker_waf::status_lines(m, env_name, &answer["waf"], scope) {
        text.push_str("\n  ");
        text.push_str(&line);
    }
    answer["waf_rules"] = crate::worker_waf::rules_named(m, env_name, &answer["waf"]);
    if let Some(charged) = charged {
        text.push_str("\n  ");
        text.push_str(&charged);
    }
    text
}

/// A string as curl's configuration file quotes it: between double quotes,
/// with the quote, the backslash and line breaks escaped.
fn curl_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// What the app answered, from curl's output: the body, then the HTTP
/// status on a last line of its own. A status that is not a success is a
/// failure that keeps the body, which is where an API says why.
fn api_answer(out: &str) -> Result<String, (String, String)> {
    let (body, status) = out.rsplit_once('\n').unwrap_or(("", out));
    let body = body.trim_end().to_owned();
    match status.trim().parse::<u16>() {
        Ok(status) if (200..300).contains(&status) => Ok(body),
        Ok(status) => Err((format!("HTTP {status}"), body)),
        Err(_) => Err(("no HTTP status".to_owned(), out.trim_end().to_owned())),
    }
}

/// curl's configuration for one request to the app, read on its standard
/// input: the method, the URL, the bearer token when the app has one, and
/// the JSON body when there is one.
fn api_request(
    method: &str,
    url: &str,
    token: Option<&str>,
    data: Option<&str>,
) -> Zeroizing<String> {
    use core::fmt::Write as _;
    let mut config = Zeroizing::new(format!("request = \"{method}\"\nurl = \"{url}\"\n"));
    if let Some(token) = token {
        let _ = writeln!(
            config,
            "header = \"Authorization: Bearer {}\"",
            curl_quoted(token)
        );
    }
    if let Some(data) = data {
        config.push_str("header = \"Content-Type: application/json\"\n");
        let _ = writeln!(config, "data = \"{}\"", curl_quoted(data));
    }
    config
}

/// A request the app did not answer with a 2xx: its answer, and, when it
/// refused a request that carried no token (an app whose `API_TOKEN`
/// erpc.toml does not name), where one goes.
fn api_refused(why: &str, body: &str, sent_token: bool, dir_scope: &str) -> CliError {
    let refused = failed(t!("worker_remote.api.failed", why, body));
    if !sent_token && why == "HTTP 401" {
        refused.hint(t!("worker_remote.api.no_token", dir_scope))
    } else {
        refused
    }
}

/// `erpc worker api`: one request to the app's API on its server, over the
/// SSH session. The API token, when the app has one (`API_TOKEN` in
/// `[secrets]`), is read on this machine and reaches curl on its standard
/// input, as part of its configuration, so it is on no command line, in no
/// shell history and in no journal. An app without one is asked without.
pub(crate) fn api(app: &App, method: &str, path: &str, data: Option<&str>) -> Outcome {
    let run = || -> Result<Outcome, CliError> {
        let method = method.to_ascii_uppercase();
        if !["GET", "POST", "PUT", "DELETE"].contains(&method.as_str()) {
            return Err(CliError::new(
                Code::Usage,
                t!("worker_remote.api.bad_method", method),
            ));
        }
        // A path as a URL has it: no spaces, quotes or control characters,
        // which would also break curl's configuration lines.
        if !path.starts_with('/')
            || !path
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
        {
            return Err(CliError::new(
                Code::Usage,
                t!("worker_remote.api.bad_path", path),
            ));
        }
        let (m, _, session) = reach(app)?;
        let port = m
            .run
            .port
            .ok_or_else(|| failed(t!("worker_remote.api.no_port")))?;
        let token = m
            .secrets
            .get("API_TOKEN")
            .map(|token| worker_secrets::read(token).map_err(failed))
            .transpose()?;
        // The URL is put together on its own, the host and port first: the
        // endpoint gate reads a host only where a port or a path ends it.
        let mut url = format!("http://127.0.0.1:{port}");
        url.push_str(path);
        let config = api_request(&method, &url, token.as_deref().map(String::as_str), data);
        let out = session
            .run(
                &RemoteCommand::Worker(Worker::Api { port }),
                Some(config.as_bytes()),
            )
            .map_err(|e| failed(e.to_string()))?;
        // No answer at all is curl's failure, and the session's error above.
        // An answer is judged by its status, not by whether anything was
        // written to standard error, where ssh speaks too.
        match api_answer(&String::from_utf8_lossy(&out.stdout)) {
            Ok(body) => Ok(Outcome::Done(body)),
            Err((why, body)) => Err(api_refused(&why, &body, token.is_some(), &app.dir.scope())),
        }
    };
    run()
        .map_err(|e| unreached(app, e))
        .unwrap_or_else(Into::into)
}

/// A journal from a server, line by line: `stream` runs the command that
/// reads it and hands over each line as it arrives
/// ([`Session::stream`]), and `print` is given each as [`shown`] has it.
/// What an app or a proxy wrote to its journal is text here, never an
/// escape sequence the terminal acts on.
fn journal<E: core::fmt::Display>(
    stream: impl FnOnce(&mut dyn FnMut(Stream, &str)) -> Result<(), E>,
    print: &mut dyn FnMut(&str),
) -> Result<(), CliError> {
    stream(&mut |_, line| print(&shown(line))).map_err(|e| failed(e.to_string()))
}

/// `erpc worker logs`: the journal of the worker's unit, the app's and the
/// agent's; with `waf`, that of its WAF's unit instead, where each request
/// it refused is a line ([`logs_from`]).
pub(crate) fn logs(app: &App, lines: u32, follow: bool, waf: bool) -> Outcome {
    let run = || -> Result<Outcome, CliError> {
        let (_, id, session) = reach(app)?;
        logs_from(
            id,
            (lines, follow),
            waf,
            |command, on_line| session.stream(command, on_line),
            &mut |line| crate::print_line(line),
        )?;
        Ok(Outcome::Done(String::new()))
    };
    run()
        .map_err(|e| unreached(app, e))
        .unwrap_or_else(Into::into)
}

/// What `logs` does once the worker's server is reached: `stream` runs a
/// command there and hands over each line it prints
/// ([`Session::stream`]). The journal of worker `id`'s unit is read, or
/// with `waf` that of its WAF's unit, its last `lines` and then, with
/// `follow`, what is added to it; and each line is given to `print` by
/// [`journal`], which is what makes it text a terminal only shows.
fn logs_from<E: core::fmt::Display>(
    id: UnitId,
    (lines, follow): (u32, bool),
    waf: bool,
    stream: impl FnOnce(&RemoteCommand, &mut dyn FnMut(Stream, &str)) -> Result<(), E>,
    print: &mut dyn FnMut(&str),
) -> Result<(), CliError> {
    let unit = if waf {
        Worker::WafLogs { id, lines, follow }
    } else {
        Worker::Logs { id, lines, follow }
    };
    let command = RemoteCommand::Worker(unit);
    journal(|on_line| stream(&command, on_line), print)
}

/// Hands the key and the secrets over when the worker is locked.
fn unlock_if_locked(
    m: &Manifest,
    id: &UnitId,
    session: &Session,
    say: &Say,
) -> Result<(), CliError> {
    let answer = ctl(session, id, Verb::Status, None)?;
    let held = answer["agent"]["key_held"].as_bool().unwrap_or(false) || m.wallet.is_none();
    let secrets_held = answer["agent"]["secrets_held"]
        .as_array()
        .map_or(0, Vec::len);
    if held && secrets_held >= m.secrets.len() {
        return Ok(());
    }
    say.line(&t!("worker_remote.unlocking"));
    let request = unlock_request(m)?;
    ctl_ok(session, id, Verb::Unlock, Some(&request))?;
    Ok(())
}

/// `erpc worker start` and `erpc worker restart`.
pub(crate) fn start(json: bool, app: &App, yes: bool, again: bool) -> Outcome {
    let say = Say { quiet: json };
    let run = || -> Result<Outcome, CliError> {
        let (m, id, session) = reach(app)?;
        say.line(&if again {
            t!("worker_remote.start.restart_prompt", id = id.as_str())
        } else {
            t!("worker_remote.start.start_prompt", id = id.as_str())
        });
        if again {
            positions_warning(&m, app, &say);
        }
        go_ahead(yes, &t!("worker_remote.start.refused"))?;
        unlock_if_locked(&m, &id, &session, &say)?;
        let verb = if again { Verb::Restart } else { Verb::Start };
        let answer = ctl_ok(&session, &id, verb, None)?;
        let text = format!("{}: {}", id.as_str(), describe(&answer["status"]));
        Ok(done(json, &answer, text))
    };
    run()
        .map_err(|e| unreached(app, e))
        .unwrap_or_else(Into::into)
}

/// `erpc worker stop`.
pub(crate) fn stop(json: bool, app: &App, lock: bool, yes: bool) -> Outcome {
    let run = || -> Result<Outcome, CliError> {
        let (m, id, session) = reach(app)?;
        positions_warning(&m, app, &Say { quiet: json });
        go_ahead(yes, &t!("worker_remote.stop.refused"))?;
        let answer = ctl_ok(
            &session,
            &id,
            if lock { Verb::Lock } else { Verb::Stop },
            None,
        )?;
        let mut text = if lock {
            t!("worker_remote.stop.locked", id = id.as_str())
        } else {
            t!("worker_remote.stop.stopped", id = id.as_str())
        };
        // Stopping the app ends none of what is charged by the hour.
        if let Some(charged) = m
            .env
            .get(&app.env)
            .and_then(|e| still_charged_line(e, &app.scope()))
        {
            text.push('\n');
            text.push_str(&charged);
        }
        Ok(done(json, &answer, text))
    };
    run()
        .map_err(|e| unreached(app, e))
        .unwrap_or_else(Into::into)
}

/// `erpc worker rollback`.
pub(crate) fn rollback(json: bool, app: &App, to: Option<&str>, yes: bool) -> Outcome {
    let say = Say { quiet: json };
    let run = || -> Result<Outcome, CliError> {
        let to = to
            .map(ReleaseId::new)
            .transpose()
            .map_err(|e| CliError::new(Code::Usage, e))?;
        let (m, id, session) = reach(app)?;
        positions_warning(&m, app, &say);
        go_ahead(yes, &t!("worker_remote.rollback.refused"))?;
        unlock_if_locked(&m, &id, &session, &say)?;
        let answer = ctl_ok(&session, &id, Verb::Rollback(to), None)?;
        let release = answer["release"].as_str().unwrap_or("?");
        let text = match answer["previous"].as_str() {
            Some(previous) => t!(
                "worker_remote.rollback.done_was",
                id = id.as_str(),
                release,
                previous
            ),
            None => t!("worker_remote.rollback.done", id = id.as_str(), release),
        };
        Ok(done(json, &answer, text))
    };
    run()
        .map_err(|e| unreached(app, e))
        .unwrap_or_else(Into::into)
}

/// `erpc worker releases`.
pub(crate) fn releases(json: bool, app: &App) -> Outcome {
    let run = || -> Result<Outcome, CliError> {
        let (_, id, session) = reach(app)?;
        let answer = ctl_ok(&session, &id, Verb::Releases, None)?;
        let (current, previous) = (
            t!("worker_remote.releases.current"),
            t!("worker_remote.releases.previous"),
        );
        let width = [&current, &previous]
            .iter()
            .map(|l| unicode_width::UnicodeWidthStr::width(l.as_str()))
            .max()
            .unwrap_or(0);
        let pad = |label: &str| {
            let have = unicode_width::UnicodeWidthStr::width(label);
            format!("{label}{}", " ".repeat(width.saturating_sub(have)))
        };
        let lines: Vec<String> = answer["releases"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| {
                let mark = if r["current"] == json!(true) {
                    pad(&current)
                } else if r["previous"] == json!(true) {
                    pad(&previous)
                } else {
                    pad("")
                };
                format!(
                    "{mark} {}  {}{}",
                    r["id"].as_str().unwrap_or("?"),
                    r["commit"].as_str().map_or("-", |c| &c[..c.len().min(12)]),
                    if r["dirty"] == json!(true) {
                        t!("worker_remote.releases.dirty")
                    } else {
                        String::new()
                    }
                )
            })
            .collect();
        let text = if lines.is_empty() {
            t!("worker_remote.releases.none")
        } else {
            lines.join("\n")
        };
        Ok(done(json, &answer, text))
    };
    run()
        .map_err(|e| unreached(app, e))
        .unwrap_or_else(Into::into)
}

/// What `erpc worker delete` is asked to do.
pub(crate) struct DeleteAsk {
    /// Also end the hourly server and the lines.
    pub(crate) release_server: bool,
    /// Do not reach the server: the operator says the worker no longer
    /// runs there.
    pub(crate) forget: bool,
    /// Lines to take off the record without ending them.
    pub(crate) forget_lines: Vec<String>,
    /// Go ahead without asking.
    pub(crate) yes: bool,
}

/// `erpc worker delete`: the worker off its server, and its environment
/// out of erpc.toml; with `--release-server`, the hourly VPS ended too.
#[allow(
    clippy::too_many_lines,
    reason = "the steps are one sequence, read top to bottom"
)]
pub(crate) async fn delete(json: bool, app: &App, ask: &DeleteAsk) -> Outcome {
    let release_server = ask.release_server;
    let say = Say { quiet: json };
    let (path, m) = match load_env(app) {
        Ok(found) => found,
        Err(e) => return e.into(),
    };
    let mut env = match m.env(&app.env) {
        Ok(env) => env.clone(),
        Err(e) => return failed(e).into(),
    };
    let id = match UnitId::new(&m.unit_id(&app.env)) {
        Ok(id) => id,
        Err(e) => return failed(e).into(),
    };
    let forgotten = match crate::worker_deploy::take_lines(&mut env, &ask.forget_lines) {
        Ok(lines) => lines,
        Err(e) => return e.into(),
    };
    let scope = app.scope();
    if let Some(e) = refuse_delete(&env, release_server, &scope) {
        return e.into();
    }
    positions_warning(&m, app, &say);
    say.line(&delete_prompt(
        &env,
        &id,
        &app.env,
        release_server,
        ask.forget,
    ));
    if let Some(asked) = forget_prompt(&forgotten) {
        say.line(&asked);
    }
    // A start that got no answer is named by this record alone, and goes
    // with it: said before the yes, since it may have gone through.
    for start in env.starting.values() {
        let what = crate::worker_vps::purchase_name(start);
        say.line(&t!("worker_remote.delete.start_unanswered", what));
    }
    if let Err(e) = go_ahead(ask.yes, &t!("worker_remote.delete.refused")) {
        return e.into();
    }
    let removal = match &env.host {
        None => Removal::NoHost,
        Some(_) if ask.forget => Removal::Skipped,
        Some(_) => match target(app, &env)
            .and_then(|t| open(&t))
            .and_then(|s| ctl_ok(&s, &id, Verb::Remove, None))
        {
            Ok(answer) => {
                // The worker is gone and its port closed; a WAF the agent
                // could not take with it is said, not passed over.
                if let Some(error) = answer["waf_error"].as_str() {
                    let unit = erpc_worker::server::waf_unit_name(id.as_str());
                    say.line(&t!("worker_remote.delete.waf_left", error, unit));
                }
                Removal::Done
            }
            Err(e) if release_server => {
                say.line(&if ends_server(&env) {
                    t!("worker_remote.delete.not_removed_ending", error = e.message)
                } else {
                    t!("worker_remote.delete.not_removed", error = e.message)
                });
                Removal::Failed(e.message)
            }
            Err(e) => {
                let more = t!(
                    "worker_remote.delete.nothing_removed",
                    hint = unreached_hint(&env, &forgotten, &scope)
                );
                let hint = match e.hint.clone() {
                    Some(h) => format!("{h}; {more}"),
                    None => more,
                };
                return e.hint(hint).into();
            }
        },
    };
    // Its backup keys, revoked whether or not the server was reached: the
    // worker leaves the record, and they would let its server in. What
    // could not be revoked stays on record, for the next delete.
    let host_key = env.host_key.as_deref().and_then(|k| HostKey::parse(k).ok());
    let (backup, backup_problem) = if env.backup.is_some() || host_key.is_some() {
        let keys = env.backup.clone();
        let forgotten = crate::worker_backup::forget(&id, host_key.as_ref(), keys.as_ref()).await;
        backup_forgotten(&mut env, forgotten)
    } else {
        (Vec::new(), None)
    };
    for line in &backup {
        say.line(line);
    }
    let released = if release_server {
        release(&env, &say).await
    } else {
        Released::default()
    };
    let record = crate::worker::EnvRecord {
        path: &path,
        app: &m.name,
        env: &app.env,
    };
    // What could not be ended or removed stays on record, for the next
    // delete or the dashboard; the rest goes.
    let mut problems = released.failed.clone();
    if let Some(why) = must_keep(&removal, &released, env.host.as_deref()) {
        problems.insert(0, why);
    }
    problems.extend(backup_problem);
    if !problems.is_empty() {
        let again = Again {
            release_server,
            scope: &scope,
            env: &app.env,
        };
        let (e, kept) = partly_released(&record, &env, &released, &removal, &problems, &again);
        if kept && let Some(said) = crate::worker_deploy::say_forgotten(&forgotten) {
            say.line(&said);
        }
        let left = kept.then(|| left_over(&env, &released, &removal));
        return e
            .details(failure_details(
                &removal,
                &released,
                &forgotten,
                left.as_ref(),
            ))
            .into();
    }
    let rewritten = record.forget(&env);
    // What still runs and is no longer on record: every line on a plain
    // delete, the ones erpc does not end on a release.
    let left_running: Vec<&Line> = env
        .lines
        .iter()
        .filter(|l| !release_server || released.kept_ids.contains(&l.id))
        .collect();
    let answer = json!({
        "removed": matches!(removal, Removal::Done).then_some(id.as_str()),
        "removal": removal.as_str(),
        "server_ended": released.server.clone().unwrap_or(Value::Null),
        "lines_ended": released.lines,
        "lines_dropped": released.dropped,
        "lines_kept": released.kept,
        "lines_forgotten": ids(&forgotten),
        "lines_left_running": left_running,
        "server_left_running": server_left_running(&env, release_server),
        "starts_forgotten": env.starting,
        "backup": backup,
        "erpc_toml": rewritten.is_ok(),
    });
    let mut text = match (&removal, &env.host) {
        (Removal::Done, _) => t!("worker_remote.delete.removed", id = id.as_str()),
        (Removal::Skipped, Some(host)) => {
            t!("worker_remote.delete.skipped", env = app.env, host)
        }
        _ => t!("worker_remote.delete.forgotten", env = app.env),
    };
    if release_server {
        say_released(&mut text, &released, ends_server(&env));
    } else {
        // What the account is charged for now, when it can be read: an
        // ended server or line is not said to be charged.
        let hourly =
            server_left_running(&env, false).is_some() || env.lines.iter().any(|l| l.hourly);
        let charged = if hourly {
            match crate::worker_vps::Api::open().await {
                Ok(api) => crate::worker_vps::charged(&api).await.ok(),
                Err(_) => None,
            }
        } else {
            None
        };
        say_still_charged(&mut text, &env, charged.as_deref());
    }
    match rewritten {
        Ok(()) => {
            if let Some(said) = crate::worker_deploy::say_forgotten(&forgotten) {
                text.push('\n');
                text.push_str(&said);
            }
        }
        Err(e) => {
            use core::fmt::Write as _;
            let _ = write!(
                text,
                "\nwarning: {}",
                t!(
                    "worker_remote.delete.still_in_toml",
                    env = app.env,
                    error = e
                )
            );
        }
    }
    done(json, &answer, text)
}

/// What a failed delete tells a script: what it ended and dropped, and,
/// when what is left was written (`on_record`), the lines it forgot and
/// what stays on record. Null where the write failed: nothing changed.
fn failure_details(
    removal: &Removal,
    released: &Released,
    forgotten: &[Line],
    on_record: Option<&Env>,
) -> Value {
    json!({
        "removal": removal.as_str(),
        "server_ended": released.server.clone().unwrap_or(Value::Null),
        "lines_ended": released.lines,
        "lines_dropped": released.dropped,
        "lines_forgotten": on_record.map(|_| ids(forgotten)),
        "on_record": on_record,
    })
}

/// The hourly ERPC server a plain delete forgets while it still runs and
/// is charged; none on a release, which ends it or fails.
fn server_left_running(env: &Env, release_server: bool) -> Option<&Resource> {
    env.resource
        .as_ref()
        .filter(|r| !release_server && r.hourly && !r.id.is_empty())
}

/// The ids of `lines`.
fn ids(lines: &[Line]) -> Vec<&str> {
    lines.iter().map(|l| l.id.as_str()).collect()
}

/// What `delete` asks before it takes lines off the record.
fn forget_prompt(lines: &[Line]) -> Option<String> {
    (!lines.is_empty()).then(|| {
        let names: Vec<String> = lines
            .iter()
            .map(|l| t!("worker_remote.line_label", kind = l.kind.label(), id = l.id))
            .collect();
        tn!(
            "worker_remote.forget_prompt",
            lines.len(),
            lines = names.join(", ")
        )
    })
}

/// What ssh says when it could not connect at all, rather than a command
/// failing on the server.
const NOT_CONNECTED: [&str; 6] = [
    "ssh: connect to host",
    "Could not resolve hostname",
    "Network is unreachable",
    "No route to host",
    "Connection timed out",
    "Connection refused",
];

/// `e`, or, when ssh could not reach the server at all, an error that says
/// so in erpc's words and how to take a server that is gone (an ended VPS)
/// off the record, instead of ssh's own line.
fn unreached(app: &App, e: CliError) -> CliError {
    if !NOT_CONNECTED.iter().any(|m| e.message.contains(m)) {
        return e;
    }
    let Ok((_, m)) = load_env(app) else {
        return e;
    };
    let Some(env) = m.env.get(&app.env) else {
        return e;
    };
    let host = env.host.as_deref().unwrap_or_default();
    let vps = env
        .resource
        .as_ref()
        .filter(|r| !r.id.is_empty())
        .map_or_else(String::new, |r| format!(" (VPS {})", r.id));
    CliError::new(
        Code::Network,
        t!("worker_remote.unreached.message", host, vps),
    )
    .hint(unreached_hint(env, &[], &app.scope()))
}

/// The way out when the server cannot be reached: `--forget`, with
/// `--release-server` whenever anything charged by the hour is on record,
/// so that following it never forgets what is still charged beyond the
/// lines the operator asked to forget (`forgotten`), which it repeats.
fn unreached_hint(env: &Env, forgotten: &[Line], scope: &str) -> String {
    let charged = ends_server(env) || env.lines.iter().any(|l| l.hourly);
    let mut command = if charged {
        "--release-server --forget".to_owned()
    } else {
        "--forget".to_owned()
    };
    for line in forgotten {
        command.push_str(" --forget-line ");
        command.push_str(&line.id);
    }
    let command = format!("erpc worker delete {command}{scope}");
    let mut hint = if charged {
        t!("worker_remote.unreached.charged", command)
    } else {
        t!("worker_remote.unreached.plain", command)
    };
    if env.backup.is_some() {
        hint.push_str(&t!(
            "worker_remote.unreached.backup",
            command = format!("erpc worker backup off{scope}")
        ));
    }
    hint
}

/// What `delete` says it is about to do.
fn delete_prompt(
    env: &Env,
    id: &UnitId,
    env_name: &str,
    release_server: bool,
    forget: bool,
) -> String {
    format!(
        "{}{}",
        match (&env.host, &env.resource) {
            (Some(host), _) if forget => t!(
                "worker_remote.delete_prompt.forget_unreached",
                env = env_name,
                host,
                id = id.as_str()
            ),
            (Some(host), _) => t!("worker_remote.delete_prompt.remove", id = id.as_str(), host),
            (None, Some(_)) => t!("worker_remote.delete_prompt.never_reached", env = env_name),
            (None, None) => t!("worker_remote.delete_prompt.no_server", env = env_name),
        },
        match (release_server, env.lines.is_empty(), ends_server(env)) {
            (true, true, true) => t!("worker_remote.delete_prompt.then_server"),
            (true, false, true) => t!("worker_remote.delete_prompt.then_lines_and_server"),
            (true, false, false) => t!("worker_remote.delete_prompt.then_lines"),
            (true, true, false) => t!("worker_remote.delete_prompt.no_server_to_end"),
            // A plain delete leaves the hourly server and lines running:
            // said before the yes, not only after.
            (false, ..) => {
                let items = hourly_items(env);
                if items.is_empty() {
                    String::new()
                } else {
                    t!(
                        "worker_remote.delete_prompt.keeps_charging",
                        items = items.join(", ")
                    )
                }
            }
        }
    )
}

/// How taking the worker off its server went.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Removal {
    /// Removed.
    Done,
    /// No server is on record: nothing is on one.
    NoHost,
    /// Not reached, as the operator asked (`--forget`): they say the
    /// worker no longer runs there.
    Skipped,
    /// It could not be removed, and why.
    Failed(String),
}

impl Removal {
    /// The name a script reads.
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Done => "removed",
            Self::NoHost => "no_server_on_record",
            Self::Skipped => "not_reached_as_asked",
            Self::Failed(_) => "failed",
        }
    }
}

/// A delete refused before anything is done: a plain delete of an
/// environment whose server was bought and never reached would forget the
/// only record of it, still charged.
fn refuse_delete(env: &Env, release_server: bool, scope: &str) -> Option<CliError> {
    let resource = env.resource.as_ref()?;
    if release_server || env.host.is_some() {
        return None;
    }
    Some(
        failed(if resource.hourly {
            t!(
                "worker_remote.refuse.hourly",
                kind = resource.kind.as_str(),
                id = resource.id
            )
        } else {
            t!(
                "worker_remote.refuse.plain",
                kind = resource.kind.as_str(),
                id = resource.id
            )
        })
        .hint(t!(
            "worker_remote.refuse.hint",
            deploy = format!("erpc worker deploy{scope}"),
            delete = format!("erpc worker delete --release-server{scope}")
        )),
    )
}

/// Why the record must stay after the removal and the release: a worker
/// that could not be removed may still run (with its key), unless its
/// server was ended.
fn must_keep(removal: &Removal, released: &Released, host: Option<&str>) -> Option<String> {
    match removal {
        Removal::Failed(e) if released.server.is_none() => Some(t!(
            "worker_remote.must_keep",
            host = host.map_or_else(|| t!("worker_remote.its_server"), str::to_owned),
            error = e
        )),
        _ => None,
    }
}

/// After a plain delete: what still runs, perhaps charged, and is no
/// longer on record. With what the account is charged for (`charged`), an
/// hourly server or line not among it is not mentioned: it is gone.
fn say_still_charged(text: &mut String, env: &Env, charged: Option<&[(String, i64)]>) {
    use core::fmt::Write as _;
    let server_charged = |r: &erpc_worker::manifest::Resource| {
        let kind = match r.kind {
            erpc_worker::manifest::ResourceKind::BareMetal => "bare_metal",
            _ => "vps",
        };
        charged.is_none_or(|c| {
            r.id.parse::<i64>()
                .is_ok_and(|id| c.iter().any(|(t, n)| t == kind && *n == id))
        })
    };
    if let Some(r) = server_left_running(env, false).filter(|r| server_charged(r)) {
        let _ = write!(
            text,
            "\nwarning: {}",
            t!(
                "worker_remote.still_charged.server",
                kind = r.kind.as_str(),
                id = r.id
            )
        );
    }
    for hourly in [true, false] {
        let ids: Vec<&str> = env
            .lines
            .iter()
            .filter(|l| l.hourly == hourly)
            .filter(|l| !hourly || charged.is_none_or(|c| crate::worker_vps::is_charged(c, l)))
            .map(|l| l.id.as_str())
            .collect();
        if !ids.is_empty() {
            let ids = ids.join(", ");
            let _ = write!(
                text,
                "\nwarning: {}",
                if hourly {
                    t!("worker_remote.still_charged.line_hourly", ids)
                } else {
                    t!("worker_remote.still_charged.line_not_hourly", ids)
                }
            );
        }
    }
}

/// What `delete --release-server` ended, and what it could not.
#[derive(Default)]
struct Released {
    /// The lines ended, as user-api answered.
    lines: Vec<Value>,
    /// The lines on record the account is no longer charged for.
    dropped: Vec<String>,
    /// The server ended, as user-api answered.
    server: Option<Value>,
    /// What could not be ended, and why.
    failed: Vec<String>,
    /// The ids of the lines that could not be ended.
    lines_failed: Vec<String>,
    /// The lines not billed by the hour, which erpc does not end.
    kept: Vec<String>,
    /// Their ids, which stay on record if anything else does.
    kept_ids: Vec<String>,
}

/// What a release ended, dropped and kept, in words.
fn say_released(text: &mut String, released: &Released, had_server: bool) {
    use core::fmt::Write as _;
    if !released.lines.is_empty() {
        text.push_str(&t!("worker_remote.released.lines"));
    }
    for gone in &released.dropped {
        text.push_str(&t!("worker_remote.released.dropped", line = gone));
    }
    if released.server.is_some() {
        text.push_str(&t!("worker_remote.released.server"));
    } else if !had_server {
        text.push_str(&t!("worker_remote.released.no_server"));
    }
    for kept in &released.kept {
        let _ = write!(
            text,
            "\nwarning: {}",
            t!("worker_remote.released.kept", line = kept)
        );
    }
}

/// What a release does with one recorded line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineEnd {
    /// End it.
    End,
    /// Nothing to end: the account is not charged for it.
    Drop,
    /// Not billed by the hour: erpc does not end it, and says so.
    Keep,
}

/// What a release does with `line`, given whether user-api lists it and
/// what the account is charged for (`None` where that could not be read:
/// then it tries to end it). It is dropped only when it is gone by the rule
/// deploy goes by too ([`crate::worker_vps::is_gone`]): a line just started
/// is ended, and stays on record if that fails.
fn line_end(line: &Line, listed: Option<bool>, charged: Option<&[(String, i64)]>) -> LineEnd {
    if !line.hourly {
        return LineEnd::Keep;
    }
    match (listed, charged) {
        (Some(listed), Some(charged))
            if crate::worker_vps::is_gone(
                (true, line.is_pending()),
                listed,
                crate::worker_vps::is_charged(charged, line),
            ) =>
        {
            LineEnd::Drop
        }
        _ => LineEnd::End,
    }
}

/// Whether `env` has an hourly ERPC server on record to end. One that has
/// none (a server of one's own, or what a partial release left) has
/// nothing to end, which is not a failure.
fn ends_server(env: &Env) -> bool {
    env.resource
        .as_ref()
        .is_some_and(|r| r.hourly && !r.id.is_empty())
}

/// Ends `env`'s lines, then its hourly server, whatever happens to each
/// line: a line that cannot be ended never keeps the server charged.
async fn release(env: &Env, say: &Say) -> Released {
    let mut out = Released::default();
    if !env.lines.is_empty() {
        match crate::worker_vps::Api::open().await {
            Ok(api) => {
                // What the account is charged for: a line on record that is
                // not among it has nothing to end.
                let charged = crate::worker_vps::charged(&api).await.ok();
                for line in &env.lines {
                    let label = format!("{} line {}", line.kind.label(), line.id);
                    // Whether it is listed matters only for one not charged.
                    let listed = match &charged {
                        Some(c) if !crate::worker_vps::is_charged(c, line) => {
                            crate::worker_vps::line_row(&api, line.kind, &line.id)
                                .await
                                .ok()
                                .map(|row| row.is_some())
                        }
                        _ => None,
                    };
                    match line_end(line, listed, charged.as_deref()) {
                        LineEnd::Drop => {
                            out.dropped.push(label);
                            continue;
                        }
                        LineEnd::Keep => {
                            out.kept.push(label);
                            out.kept_ids.push(line.id.clone());
                            continue;
                        }
                        LineEnd::End => {}
                    }
                    match crate::worker_vps::end_line(&api, line, say).await {
                        Ok(answer) => out.lines.push(answer),
                        Err(e) => {
                            out.failed.push(format!(
                                "{}: {}",
                                t!(
                                    "worker_remote.line_label",
                                    kind = line.kind.label(),
                                    id = line.id
                                ),
                                e.message
                            ));
                            out.lines_failed.push(line.id.clone());
                        }
                    }
                }
            }
            Err(e) => {
                for line in &env.lines {
                    out.lines_failed.push(line.id.clone());
                }
                out.failed
                    .push(t!("worker_remote.release.lines_failed", error = e.message));
            }
        }
    }
    if ends_server(env) {
        match crate::worker_vps::end(env, say).await {
            Ok(answer) => out.server = Some(answer),
            Err(e) => out
                .failed
                .push(t!("worker_remote.release.server_failed", error = e.message)),
        }
    }
    out
}

/// What became of the backup keys on record, from `forget`: the lines that
/// say it, and the problem that keeps the record when its access key is
/// not revoked. The record loses the keys only once they are revoked.
fn backup_forgotten(
    env: &mut Env,
    forgotten: Result<Vec<String>, Vec<String>>,
) -> (Vec<String>, Option<String>) {
    match forgotten {
        Ok(said) => {
            env.backup = None;
            (said, None)
        }
        Err(left) => (
            left.iter().map(|l| format!("left: {l}")).collect(),
            Some(t!(
                "worker_remote.backup_not_revoked",
                why = left.join("; ")
            )),
        ),
    }
}

/// How a delete was asked, for the hint that runs it again.
struct Again<'a> {
    release_server: bool,
    scope: &'a str,
    env: &'a str,
}

/// The failure of a delete that did not end or remove everything, with
/// what was not kept on record, and whether what is left was written.
fn partly_released(
    record: &crate::worker::EnvRecord<'_>,
    env: &Env,
    released: &Released,
    removal: &Removal,
    problems: &[String],
    again: &Again<'_>,
) -> (CliError, bool) {
    let kept = record.save(&left_over(env, released, removal), None);
    let written = kept.is_ok();
    let problems = problems.join("; ");
    let e = failed(match removal {
        Removal::Done => t!("worker_remote.partly.removed", problems),
        Removal::NoHost => t!("worker_remote.partly.no_host", problems),
        Removal::Skipped => t!("worker_remote.partly.skipped", problems),
        Removal::Failed(_) => t!("worker_remote.partly.not_removed", problems),
    })
    .hint(match kept {
        Ok(()) => retry_hint(env, released, removal, again),
        Err(err) => t!("worker_remote.partly.not_kept", error = err),
    });
    (e, written)
}

/// How to carry on after a delete that left something on record.
fn retry_hint(env: &Env, released: &Released, removal: &Removal, again: &Again<'_>) -> String {
    let flags = match (again.release_server, matches!(removal, Removal::Skipped)) {
        (true, true) => " --release-server --forget",
        (true, false) => " --release-server",
        (false, true) => " --forget",
        (false, false) => "",
    };
    let mut hint = t!(
        "worker_remote.retry.again",
        command = format!("erpc worker delete{flags}{scope}", scope = again.scope)
    );
    if env.backup.is_some() {
        hint.push_str(&t!("worker_remote.retry.backup"));
        hint.push_str(&crate::worker_backup::stuck(again.env));
    }
    if ends_server(env) && released.server.is_none() {
        hint.push_str(&t!("worker_remote.retry.server"));
    }
    if !released.lines_failed.is_empty() {
        hint.push_str(&t!("worker_remote.retry.lines"));
    }
    if matches!(removal, Removal::Failed(_)) {
        hint.push_str(&t!("worker_remote.retry.forget"));
    }
    hint
}

/// What stays on record after a delete that did not do everything: the
/// lines not ended, and the server, whole, when the worker may still run
/// on it or it was not ended.
fn left_over(env: &Env, released: &Released, removal: &Removal) -> Env {
    // The lines not ended, and the ones erpc does not end (not hourly).
    let lines = env
        .lines
        .iter()
        .filter(|l| released.lines_failed.contains(&l.id) || released.kept_ids.contains(&l.id))
        .cloned()
        .collect();
    // The server is gone from the record once it is ended, or when there
    // was none to end and the worker is off it.
    let worker_off = !matches!(removal, Removal::Failed(_));
    if released.server.is_some() || (worker_off && !ends_server(env)) {
        // The backup keys stay while they are not revoked.
        Env {
            inventory: env.inventory.clone(),
            lines,
            backup: env.backup.clone(),
            ..Env::default()
        }
    } else {
        Env {
            lines,
            ..env.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use erpc_worker::manifest::{Env, Line, LineKind, Resource, ResourceKind};
    use serde_json::json;

    use erpc_ssh::worker::UnitId;

    #[test]
    fn logs_prints_each_line_of_a_journal_without_what_a_terminal_acts_on() {
        use erpc_ssh::Stream;
        // What a server's journal holds is the app's, or the proxy's, to
        // write: a title change, a screen clear, a carriage return.
        let lines = [
            (
                Stream::Stdout,
                "blocked reason=probe path=\"/x\"\tstatus=403",
            ),
            (Stream::Stdout, "a\u{1b}]0;owned\u{7}\u{1b}[2Jb\rc"),
            (Stream::Stderr, "warn\u{9b}2J \u{202e}txt"),
        ];
        let mut printed = Vec::new();
        super::journal(
            |on_line| {
                for (stream, line) in lines {
                    on_line(stream, line);
                }
                Ok::<(), String>(())
            },
            &mut |line| printed.push(line.to_owned()),
        )
        .expect("read");
        assert_eq!(
            printed,
            [
                "blocked reason=probe path=\"/x\"\tstatus=403",
                "a?]0;owned??[2Jb?c",
                "warn?2J ?txt"
            ]
        );
        // A journal that could not be read is the command's failure.
        let failed =
            super::journal(|_| Err("the connection was closed"), &mut |_| {}).expect_err("failed");
        assert_eq!(failed.message, "the connection was closed");
    }

    #[test]
    fn logs_reads_the_journal_asked_for_and_prints_each_line_as_text() {
        use erpc_ssh::worker::Command as Worker;
        use erpc_ssh::{RemoteCommand, Stream};
        let id = || UnitId::new("bot-prod").expect("id");
        // What the server streams back, whichever journal it is asked
        // for: a line as it should be, and one a terminal would act on.
        let read = |lines: u32, follow: bool, waf: bool| {
            let (mut asked, mut printed) = (Vec::new(), Vec::new());
            super::logs_from(
                id(),
                (lines, follow),
                waf,
                |command: &RemoteCommand, on_line: &mut dyn FnMut(Stream, &str)| {
                    asked.push(command.clone());
                    on_line(Stream::Stdout, "blocked reason=probe status=403");
                    on_line(Stream::Stderr, "a\u{1b}]0;owned\u{7}\u{1b}[2Jb");
                    Ok::<(), String>(())
                },
                &mut |line| printed.push(line.to_owned()),
            )
            .expect("read");
            (asked, printed)
        };
        // The worker's journal, and with `--waf` its WAF's: the server is
        // sent the command for that unit, with the lines and the
        // following asked for.
        let worker = Worker::Logs {
            id: id(),
            lines: 50,
            follow: false,
        };
        let waf = Worker::WafLogs {
            id: id(),
            lines: 7,
            follow: true,
        };
        for (unit, got) in [(worker, read(50, false, false)), (waf, read(7, true, true))] {
            let (asked, printed) = got;
            assert_eq!(asked, [RemoteCommand::Worker(unit)]);
            // Each line is printed, and as text: what the server sent
            // reaches the terminal as `?` where it would act on it.
            assert_eq!(
                printed,
                ["blocked reason=probe status=403", "a?]0;owned??[2Jb"]
            );
        }
        // A journal that could not be read fails the command.
        let failed = super::logs_from(
            id(),
            (7, false),
            true,
            |_: &RemoteCommand, _: &mut dyn FnMut(Stream, &str)| Err("the connection was closed"),
            &mut |_| {},
        )
        .expect_err("failed");
        assert_eq!(failed.message, "the connection was closed");
    }

    #[tokio::test]
    async fn status_asks_the_agent_for_its_status_and_says_the_waf_under_the_worker() {
        use crate::worker::{App, AppFlag, DirFlag};
        use erpc_ssh::worker::Verb;
        let m = erpc_worker::manifest::Manifest::parse(
            "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n[waf]\nport = 8080\n\
             [env.prod]\nhost = \"203.0.113.10\"\n",
        )
        .expect("valid");
        let app = App::from(AppFlag {
            dir: DirFlag::default(),
            env: "prod".to_owned(),
        });
        // What the agent answers: the worker, and a WAF that was started
        // before its config or its unit on the server last changed.
        let answer = json!({
            "ok": true,
            "agent": { "state": "running", "release": "20261111T090000Z-1a2b3c4d" },
            "current": "20261111T090000Z-1a2b3c4d",
            "previous": null,
            "releases": 1,
            "waf": {
                "unit": "erpc-waf-bot-prod.service",
                "state": "active",
                "active": true,
                "listen": "0.0.0.0:8080",
                "port": 8080,
                "upstream": "127.0.0.1:3000",
                "config": m.waf_config("prod"),
                "started": "before_config",
                "binary": "installed",
                "config_error": null,
                "stats": null,
                "stats_error": null,
            },
        });
        let mut asked = Vec::new();
        let (reported, text) = super::status_from(&m, &app, |verb| {
            asked.push(verb);
            Ok(answer.clone())
        })
        .await
        .expect("a status");
        assert_eq!(asked, [Verb::Status]);
        // The worker, its releases, and the WAF: how it is, and that the
        // rules it runs are not taken for erpc.toml's, with the deploy
        // for this environment.
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!(
            lines[0],
            "bot-prod on 203.0.113.10: running, release 20261111T090000Z-1a2b3c4d"
        );
        assert!(lines[1].starts_with("  current 20261111T090000Z-1a2b3c4d, "));
        assert!(lines[2].starts_with("  WAF: listening on port 8080, "));
        assert!(
            lines[3].starts_with("  WAF: it was started before its config or its unit on ")
                && lines[3].contains("`erpc worker deploy --env prod` restarts it"),
            "{text}"
        );
        // What `--json` prints: the agent's answer, with whose rules the
        // WAF runs and what is paid for by the hour, here nothing.
        assert_eq!(reported["waf"], answer["waf"]);
        assert_eq!(reported["waf_rules"], "before_config");
        assert_eq!(reported["hourly"], json!({ "server": null, "lines": [] }));
        // An agent that could not be asked fails the command.
        let failed = super::status_from(&m, &app, |_| Err(super::failed("no answer")))
            .await
            .expect_err("failed");
        assert_eq!(failed.message, "no answer");
    }

    #[test]
    fn status_says_how_the_waf_is_under_the_worker_and_json_says_whose_rules_it_runs() {
        let app = |waf: &str| {
            erpc_worker::manifest::Manifest::parse(&format!(
                "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n{waf}"
            ))
            .expect("valid")
        };
        let m = app("[waf]\nport = 8080\n");
        // The agent's answer: the worker, and a WAF that runs the config
        // erpc.toml makes and has written no counts yet.
        let answer = || {
            json!({
                "ok": true,
                "agent": { "state": "running", "release": "20261111T090000Z-1a2b3c4d" },
                "current": "20261111T090000Z-1a2b3c4d",
                "previous": null,
                "releases": 1,
                "waf": {
                    "unit": "erpc-waf-bot-prod.service",
                    "state": "active",
                    "active": true,
                    "listen": "0.0.0.0:8080",
                    "port": 8080,
                    "upstream": "127.0.0.1:3000",
                    "config": m.waf_config("prod"),
                    "started": "after_config",
                    "binary": "installed",
                    "config_error": null,
                    "stats": null,
                    "stats_error": null,
                },
            })
        };
        let said = |m: &erpc_worker::manifest::Manifest, answer: &mut serde_json::Value| {
            super::status_said(m, "prod", "203.0.113.10", answer, None, " --env prod")
        };
        let mut reported = answer();
        assert_eq!(
            said(&m, &mut reported),
            "bot-prod on 203.0.113.10: running, release 20261111T090000Z-1a2b3c4d\n\
             \x20 current 20261111T090000Z-1a2b3c4d, previous none, 1 release kept\n\
             \x20 WAF: listening on port 8080, forwarding to 127.0.0.1:3000; it has written no \
             counts yet"
        );
        assert_eq!(reported["waf_rules"], "erpc_toml");
        // `[waf]` was tightened since the deploy: a line more, and --json
        // says so.
        let tightened = app("[waf]\nport = 8080\ndeny_paths = [\"/admin/*\"]\n");
        let mut reported = answer();
        let text = said(&tightened, &mut reported);
        assert!(
            text.ends_with(
                "counts yet\n  WAF: the rules it runs are not erpc.toml's; `erpc worker deploy \
                 --env prod` puts erpc.toml's in place, and until then its port is not opened \
                 wider"
            ),
            "{text}"
        );
        assert_eq!(reported["waf_rules"], "other");
        // What it is charged for comes after the WAF.
        let mut reported = answer();
        let charged = Some("Charged by the hour".to_owned());
        let text = super::status_said(&m, "prod", "203.0.113.10", &mut reported, charged, "");
        assert!(
            text.ends_with("counts yet\n  Charged by the hour"),
            "{text}"
        );
        // An app without a WAF on a server without one: no line, and null.
        let mut plain = answer();
        plain["waf"] = serde_json::Value::Null;
        let text = said(&app(""), &mut plain);
        assert!(!text.contains("WAF"), "{text}");
        assert!(plain["waf_rules"].is_null());
    }

    #[test]
    fn what_a_server_sent_is_shown_without_what_a_terminal_acts_on() {
        use super::shown;
        // A journal line, as `logs` and `logs --waf` print one: an escape
        // sequence, a carriage return and a character that reorders text
        // are not passed to the terminal; a tab and other scripts are.
        assert_eq!(
            shown("2026-11-11T09:00:00+00:00 host erpc-worker-agent[1]: blocked\tpath=\"/x\""),
            "2026-11-11T09:00:00+00:00 host erpc-worker-agent[1]: blocked\tpath=\"/x\""
        );
        assert_eq!(
            shown("a\u{1b}]0;owned\u{7}\u{1b}[2Jb\rc\u{9b}2Jd\u{7f}e\u{202e}f"),
            "a?]0;owned??[2Jb?c?2Jd?e?f"
        );
        assert_eq!(shown("日本語 ✓ ünï\n\tnext\n"), "日本語 ✓ ünï\n\tnext\n");
        assert_eq!(shown(""), "");

        // An agent's answer: every string in it, and every name, whether
        // it is then printed as text or as --json. The table keeps its
        // line breaks and its tabs.
        let sent = "noise\n{\"ok\":true,\"table\":\"table inet erpc_worker {\\n\\tchain input\\n}\",\
                    \"waf\":{\"state\":\"active\\u001b[2J\",\"stats\":{\"since\":\"\\u001b]0;x\\u0007\",\
                    \"requests\":3},\"list\":[\"a\\u009bb\"]},\"na\\u001bme\":1}\n";
        let answer = super::answer(sent.as_bytes()).expect("an answer");
        assert_eq!(
            answer,
            json!({
                "ok": true,
                "table": "table inet erpc_worker {\n\tchain input\n}",
                "waf": {
                    "state": "active?[2J",
                    "stats": { "since": "?]0;x?", "requests": 3 },
                    "list": ["a?b"]
                },
                "na?me": 1
            })
        );
        // One that does not read is quoted in the error, and is shown the
        // same way.
        let refused =
            super::answer(b"sudo: \x1b[2Ja password is required\n").expect_err("no answer");
        assert!(
            refused.message.contains("sudo: ?[2Ja password is required"),
            "{}",
            refused.message
        );
    }

    use super::{
        Again, LineEnd, Released, Removal, delete_prompt, ends_server, failure_details,
        forget_prompt, hourly_items, left_over, line_end, must_keep, refuse_delete, retry_hint,
        say_still_charged, server_left_running, still_charged_line, unreached_hint,
    };

    fn again(scope: &str) -> Again<'_> {
        Again {
            release_server: true,
            scope,
            env: "default",
        }
    }

    fn env() -> Env {
        Env {
            resource: Some(Resource {
                kind: ResourceKind::Vps,
                id: "100001".to_owned(),
                region: None,
                hourly: true,
            }),
            host: Some("203.0.113.10".to_owned()),
            lines: ["100002", "100003"]
                .into_iter()
                .map(|id| Line {
                    kind: if id == "100002" {
                        LineKind::Grpc
                    } else {
                        LineKind::Shreds
                    },
                    id: id.to_owned(),
                    endpoint: String::new(),
                    hourly: true,
                })
                .collect(),
            ..Env::default()
        }
    }

    #[test]
    fn only_a_refusal_for_a_taken_port_says_where_the_port_is_set() {
        use erpc_worker::server::port_taken;
        // As `ctl install`, `activate` and `rollback` word it, by the
        // neighbour's name, and as the agent does before a start.
        for refusal in [
            port_taken(3000, Some("api-default")),
            port_taken(3000, None),
        ] {
            let hint = super::port_hint(&refusal).expect("a hint");
            assert!(
                hint.contains("port 3000") && hint.contains("erpc.toml"),
                "{hint}"
            );
            // What `install` and `rollback` fail with carries it.
            let failed = super::refusal(&json!({ "ok": false, "error": refusal }));
            assert_eq!(failed.message, refusal);
            assert_eq!(failed.hint, Some(hint));
        }
        // Anything else the agent refuses with gets no such hint.
        for other in [
            "locked: the trading key has not been handed over",
            "release r2 was not healthy within 35s (state starting, last exit none)",
            "another erpc is changing this worker; try again when it is done",
            "port is taken",
        ] {
            assert_eq!(super::port_hint(other), None, "{other}");
            let failed = super::refusal(&json!({ "ok": false, "error": other }));
            assert_eq!((failed.message.as_str(), failed.hint), (other, None));
        }
        // An answer without words of its own.
        let failed = super::refusal(&json!({ "ok": false }));
        assert_eq!(failed.message, "the server's agent refused");
    }

    #[test]
    fn only_a_connection_that_never_happened_is_called_unreached() {
        let says = |text: &str| super::NOT_CONNECTED.iter().any(|m| text.contains(m));
        assert!(says(
            "the command failed on the node (exit 255): ssh: connect to host 192.0.2.48 port 22: Network is unreachable"
        ));
        assert!(says("ssh: connect to host h port 22: Connection timed out"));
        assert!(!says(
            "the command failed on the node (exit 1): no such unit"
        ));
    }

    #[test]
    fn a_second_release_of_what_a_partial_one_left_has_no_server_to_end() {
        let released = Released {
            server: Some(json!({ "done": true })),
            lines_failed: vec!["100003".to_owned()],
            failed: vec!["Shreds line 100003: refused".to_owned()],
            ..Released::default()
        };
        let left = left_over(&env(), &released, &Removal::Done);
        // No server is left to end: a second release does not fail on it.
        assert!(!ends_server(&left));
        // The line left, seen before, is ended if charged or listed, and
        // dropped if neither: either way nothing remains.
        let mut line = left.lines[0].clone();
        line.endpoint = "203.0.113.20:20000".to_owned();
        let charged = vec![("shreds".to_owned(), 100_003)];
        assert_eq!(line_end(&line, Some(false), Some(&charged)), LineEnd::End);
        assert_eq!(line_end(&line, Some(true), Some(&[])), LineEnd::End);
        assert_eq!(line_end(&line, Some(false), Some(&[])), LineEnd::Drop);
        assert_eq!(line_end(&line, None, Some(&[])), LineEnd::End);
        assert_eq!(line_end(&line, Some(false), None), LineEnd::End);
        assert!(ends_server(&env()));
    }

    #[test]
    fn a_line_just_started_is_ended_and_never_dropped() {
        // Never seen with its endpoint, and shown by neither: right after
        // a start both can be behind. It is ended, and stays on record if
        // that fails.
        let line = &env().lines[0];
        assert!(line.is_pending());
        assert_eq!(line_end(line, Some(false), Some(&[])), LineEnd::End);
        assert_eq!(line_end(line, None, None), LineEnd::End);
    }

    #[test]
    fn a_plain_delete_never_forgets_a_server_bought_and_not_reached() {
        let bought = Env {
            host: None,
            lines: Vec::new(),
            ..env()
        };
        assert!(refuse_delete(&bought, false, "").is_some());
        // --release-server ends it, and a reached server is removed.
        assert!(refuse_delete(&bought, true, "").is_none());
        assert!(refuse_delete(&env(), false, "").is_none());
        assert!(refuse_delete(&Env::default(), false, "").is_none());
    }

    #[test]
    fn a_worker_that_may_still_run_keeps_its_whole_server_on_record() {
        let own = Env {
            resource: None,
            ..env()
        };
        let released = Released {
            failed: Vec::new(),
            ..Released::default()
        };
        let left = left_over(&own, &released, &Removal::Failed("refused".to_owned()));
        assert_eq!(left.host, own.host);
        // Removed, with no server to end: nothing of the server stays.
        let left = left_over(&own, &released, &Removal::Done);
        assert!(left.host.is_none());
        let left = left_over(&own, &released, &Removal::Skipped);
        assert!(left.host.is_none());
    }

    #[test]
    fn the_backup_keys_leave_the_record_only_once_revoked() {
        let keys = erpc_worker::manifest::Backup {
            access_key: 42,
            restic_key: "0a".repeat(32),
            host: "erpc-worker-bot-default-0a1b2c3d".to_owned(),
        };
        let mut own = Env {
            backup: Some(keys.clone()),
            ..env()
        };
        let (said, problem) =
            super::backup_forgotten(&mut own, Err(vec!["access key 42: refused".to_owned()]));
        assert_eq!(own.backup, Some(keys));
        assert!(
            problem
                .expect("a problem")
                .contains("access key 42: refused")
        );
        assert_eq!(said, ["left: access key 42: refused"]);
        let (said, problem) = super::backup_forgotten(&mut own, Ok(vec!["revoked".to_owned()]));
        assert_eq!(own.backup, None);
        assert!(problem.is_none());
        assert_eq!(said, ["revoked"]);
    }

    #[test]
    fn backup_keys_not_revoked_stay_on_record_and_the_hint_runs_delete_again() {
        let keys = erpc_worker::manifest::Backup {
            access_key: 42,
            restic_key: "0a".repeat(32),
            host: "erpc-worker-bot-default-0a1b2c3d".to_owned(),
        };
        let own = Env {
            resource: None,
            backup: Some(keys.clone()),
            ..env()
        };
        let left = left_over(&own, &Released::default(), &Removal::Done);
        assert!(left.host.is_none());
        assert_eq!(left.backup, Some(keys));
        // A server that cannot be reached: `off` revokes the keys first.
        let hint = super::unreached_hint(&own, &[], " --env prod");
        assert!(
            hint.contains("`erpc worker backup off --env prod` revokes"),
            "{hint}"
        );
        assert!(!super::unreached_hint(&env(), &[], "").contains("backup off"));
        let plain = Again {
            release_server: false,
            scope: " --env prod",
            env: "prod",
        };
        let hint = retry_hint(&own, &Released::default(), &Removal::Done, &plain);
        assert!(hint.contains("remove [env.prod.backup]"), "{hint}");
        assert!(
            hint.contains("`erpc worker delete --env prod` again"),
            "{hint}"
        );
        assert!(hint.contains("erpc storage keys revoke"), "{hint}");
    }

    #[test]
    fn a_server_that_cannot_be_reached_has_a_way_out() {
        let own = Env {
            resource: None,
            lines: Vec::new(),
            ..env()
        };
        let failed = Removal::Failed("connection refused".to_owned());
        let hint = retry_hint(&own, &Released::default(), &failed, &again(""));
        assert!(hint.contains("--forget"), "{hint}");
        // No ERPC server and no line on record: no dashboard to point at.
        assert!(!hint.contains("dashboard"), "{hint}");
        // A line that could not be ended: its way out is named.
        let released = Released {
            lines_failed: vec!["100002".to_owned()],
            ..Released::default()
        };
        assert!(
            retry_hint(&env(), &released, &Removal::Done, &again("")).contains("--forget-line")
        );
        // The lines and the server both failed: both ways out are named.
        let both = retry_hint(&env(), &released, &Removal::Done, &again(""));
        assert!(
            both.contains("server can also be ended in the dashboard"),
            "{both}"
        );
        // Not reached, as asked: the re-run is asked the same way.
        let skipped = retry_hint(&env(), &released, &Removal::Skipped, &again(""));
        assert!(skipped.contains("`erpc worker delete --release-server --forget` again"));
    }

    #[test]
    fn an_uptime_reads_as_a_person_says_it() {
        assert_eq!(super::humane(45), "45s");
        assert_eq!(super::humane(725), "12m 05s");
        assert_eq!(super::humane(7_500), "2h 05m");
        assert_eq!(super::humane(273_600), "3d 4h");
    }

    #[test]
    fn a_token_and_a_body_are_quoted_for_curls_configuration() {
        assert_eq!(super::curl_quoted("plain-token"), "plain-token");
        assert_eq!(
            super::curl_quoted("say \"hi\"\\\n"),
            "say \\\"hi\\\"\\\\\\n"
        );
    }

    #[test]
    fn a_request_carries_a_token_only_when_the_app_has_one() {
        let url = concat!("http://127.0.0.1", ":3000/");
        let with = super::api_request("GET", url, Some("tok\"en"), None);
        assert_eq!(
            with.as_str(),
            format!(
                "request = \"GET\"\nurl = \"{url}\"\nheader = \"Authorization: Bearer tok\\\"en\"\n"
            )
        );
        // An app with no API_TOKEN in [secrets], such as the hello app, is
        // asked without one, and a body goes as JSON either way.
        let without = super::api_request("POST", url, None, Some("{\"a\":1}"));
        assert!(!without.contains("Authorization"), "{}", without.as_str());
        assert!(
            without.ends_with(
                "header = \"Content-Type: application/json\"\ndata = \"{\\\"a\\\":1}\"\n"
            ),
            "{}",
            without.as_str()
        );
    }

    #[test]
    fn an_app_that_refuses_a_request_without_a_token_is_told_where_one_goes() {
        let refused = super::api_refused("HTTP 401", "unauthorized", false, " --dir bot");
        let hint = refused.hint.expect("a hint");
        assert!(
            hint.contains("erpc worker secret put API_TOKEN --dir bot"),
            "{hint}"
        );
        assert!(refused.message.contains("HTTP 401"), "{}", refused.message);
        // A token was sent and refused, or the app said something else:
        // the app's answer is all there is to say.
        assert!(super::api_refused("HTTP 401", "", true, "").hint.is_none());
        assert!(super::api_refused("HTTP 404", "", false, "").hint.is_none());
    }

    #[test]
    fn the_status_says_the_accounts_list_when_it_has_it_and_the_record_when_not() {
        use serde_json::json;
        let env = env();
        // With the account's list: a price for what is on it.
        let priced = crate::worker_charges::from_snapshot(
            &env,
            &json!({ "message": {
                "balance": { "balanceCents": 900 },
                "hourlyResources": [
                    { "productType": "vps", "userProductId": 100_001, "hourlyCents": 7 },
                ],
                "burnRateCentsPerHour": 7,
                "timeToZeroHours": 128,
            } }),
        )
        .expect("something hourly, and the list");
        let said = super::hourly_said(Some(&env), Some(&priced), " --env prod").expect("said");
        assert!(said.contains("€0.07 per hour"), "{said}");
        assert!(
            said.contains("not among the account's charges now"),
            "{said}"
        );
        // Without it (no session, user-api away): what is on record, as
        // before, and no price.
        let said = super::hourly_said(Some(&env), None, " --env prod").expect("said");
        assert_eq!(
            Some(said.clone()),
            still_charged_line(&env, " --env prod"),
            "the record's own sentence"
        );
        assert!(!said.contains('€'), "{said}");
        // Nothing on record: nothing said either way.
        assert_eq!(super::hourly_said(None, None, ""), None);
        assert_eq!(super::hourly_said(Some(&Env::default()), None, ""), None);
    }

    #[test]
    fn what_keeps_being_charged_is_said_with_the_way_to_end_it() {
        use erpc_core::i18n::Lang;
        // An hourly server and hourly lines: named, with --release-server.
        let said = still_charged_line(&env(), " bot --env prod").expect("hourly things");
        assert!(said.contains("--release-server bot --env prod"), "{said}");
        for item in hourly_items(&env()) {
            assert!(said.contains(&item), "{said} lacks {item}");
        }
        // The prompt of a plain delete says so before the yes: that this
        // does not end them, and that what still runs stays charged. Not
        // that they keep running: one may have been ended elsewhere, and
        // erpc has not looked.
        let id = UnitId::new("bot-prod").expect("unit id");
        let prompt = delete_prompt(&env(), &id, "prod", false, false);
        let items = hourly_items(&env()).join(", ");
        assert!(
            prompt.ends_with(&format!(
                "; its hourly {items} are not ended by this: any that still runs stays charged \
                 (add `--release-server` to end them)"
            )),
            "{prompt}"
        );
        assert!(!prompt.contains("keep running"), "{prompt}");
        // In every language: its own sentence, with the flag as it is
        // typed and the things it is about, saying that they are not
        // ended and not that they keep running.
        for (lang, not_ended, keep_running) in [
            (Lang::Ja, "この操作では終了しません", "動き続け"),
            (Lang::Zh, "这不会终止", "继续运行"),
            (Lang::Ru, "при этом не завершаются", "продолжают работать"),
        ] {
            let (said, items) = crate::i18n::speaking(lang, || {
                (
                    delete_prompt(&env(), &id, "prod", false, false),
                    hourly_items(&env()),
                )
            });
            assert!(!said.contains("are not ended by this"), "{said}");
            assert!(
                said.contains("`--release-server`") && !said.contains('{'),
                "{said}"
            );
            assert!(said.contains(not_ended), "{said}");
            assert!(!said.contains(keep_running), "{said}");
            for item in items {
                assert!(said.contains(&item), "{said} lacks {item}");
            }
        }
        // Nothing hourly on record: nothing to say.
        let own = Env {
            resource: None,
            lines: env()
                .lines
                .into_iter()
                .map(|l| Line { hourly: false, ..l })
                .collect(),
            ..env()
        };
        assert!(still_charged_line(&own, "").is_none());
        assert!(!delete_prompt(&own, &id, "prod", false, false).contains("--release-server"));
    }

    #[test]
    fn the_way_out_of_an_unreachable_server_never_forgets_what_is_charged() {
        // An hourly server, or an hourly line: --release-server with it.
        assert!(unreached_hint(&env(), &[], "").contains("--release-server --forget"));
        let lines_only = Env {
            resource: None,
            ..env()
        };
        assert!(unreached_hint(&lines_only, &[], "").contains("--release-server --forget"));
        // Nothing charged by the hour on record: --forget alone.
        let own = Env {
            resource: None,
            lines: Vec::new(),
            ..env()
        };
        let hint = unreached_hint(&own, &[], "");
        assert!(hint.contains("`erpc worker delete --forget`"), "{hint}");
        // The lines asked to be forgotten are asked again, and nothing else.
        let hint = unreached_hint(&own, &env().lines[..1], "");
        assert!(
            hint.contains("`erpc worker delete --forget --forget-line 100002`"),
            "{hint}"
        );
    }

    #[test]
    fn every_way_out_names_the_environment_it_is_for() {
        // Following a hint printed for another environment must never act
        // on [env.default]: each command names its own.
        let scope = " --env staging --dir app";
        let failed = Removal::Failed("connection refused".to_owned());
        let hint = retry_hint(&env(), &Released::default(), &failed, &again(scope));
        assert!(
            hint.contains("`erpc worker delete --release-server --env staging --dir app` again"),
            "{hint}"
        );
        let hint = unreached_hint(&env(), &env().lines[..1], scope);
        assert!(
            hint.contains(
                "`erpc worker delete --release-server --forget --forget-line 100002 --env \
                 staging --dir app`"
            ),
            "{hint}"
        );
        let bought = Env {
            host: None,
            ..env()
        };
        let refused = refuse_delete(&bought, false, scope).expect("refused");
        let hint = refused.hint.unwrap_or_default();
        assert!(
            hint.contains("`erpc worker deploy --env staging --dir app`"),
            "{hint}"
        );
        assert!(
            hint.contains("`erpc worker delete --release-server --env staging --dir app`"),
            "{hint}"
        );
    }

    /// An answer is a success by its HTTP status alone; a refusal keeps
    /// the body, where the app says why.
    #[test]
    fn an_api_answer_is_judged_by_its_status_and_keeps_its_body() {
        assert_eq!(
            super::api_answer("{\"running\":true}\n200"),
            Ok("{\"running\":true}".to_owned())
        );
        assert_eq!(super::api_answer("\n204"), Ok(String::new()));
        assert_eq!(
            super::api_answer("line one\nline two\n201"),
            Ok("line one\nline two".to_owned())
        );
        assert_eq!(
            super::api_answer("{\"error\":\"unauthorized\"}\n401"),
            Err((
                "HTTP 401".to_owned(),
                "{\"error\":\"unauthorized\"}".to_owned()
            ))
        );
        assert_eq!(
            super::api_answer("\n000"),
            Err(("HTTP 0".to_owned(), String::new()))
        );
        assert_eq!(
            super::api_answer("not what curl prints"),
            Err((
                "no HTTP status".to_owned(),
                "not what curl prints".to_owned()
            ))
        );
    }

    #[test]
    fn a_failed_delete_tells_a_script_what_it_did() {
        let released = Released {
            server: Some(json!({ "done": true })),
            dropped: vec!["Shreds line 100003".to_owned()],
            ..Released::default()
        };
        let forgotten = &env().lines[..1];
        let left = Env::default();
        let written = failure_details(&Removal::Done, &released, forgotten, Some(&left));
        assert_eq!(written["removal"], "removed");
        assert_eq!(written["server_ended"]["done"], true);
        assert_eq!(written["lines_dropped"][0], "Shreds line 100003");
        assert_eq!(written["lines_forgotten"], json!(["100002"]));
        assert!(written["on_record"].is_object());
        // The record could not be written: nothing was forgotten.
        let failed = Removal::Failed("refused".to_owned());
        let unwritten = failure_details(&failed, &released, forgotten, None);
        assert_eq!(unwritten["removal"], "failed");
        assert!(unwritten["lines_forgotten"].is_null());
        assert!(unwritten["on_record"].is_null());
    }

    #[test]
    fn a_plain_delete_names_the_charged_server_it_forgets() {
        assert_eq!(server_left_running(&env(), false), env().resource.as_ref());
        // A release ends it, or fails and keeps it on record.
        assert!(server_left_running(&env(), true).is_none());
        let mut not_hourly = env();
        if let Some(r) = not_hourly.resource.as_mut() {
            r.hourly = false;
        }
        assert!(server_left_running(&not_hourly, false).is_none());
    }

    #[test]
    fn the_prompt_says_what_would_leave_the_record() {
        assert!(forget_prompt(&[]).is_none());
        let asked = forget_prompt(&env().lines[..1]).expect("one line");
        assert!(
            asked.contains("take gRPC line 100002 off the record"),
            "{asked}"
        );
        assert!(!asked.contains("leaves"), "{asked}");
    }

    #[test]
    fn the_prompt_says_what_is_on_record() {
        let id = UnitId::new("app-prod").expect("id");
        let bought = Env {
            host: None,
            ..env()
        };
        assert!(delete_prompt(&bought, &id, "prod", true, false).contains("never reached"));
        assert!(
            delete_prompt(&Env::default(), &id, "prod", false, false)
                .contains("no server is on record")
        );
        let skipped = delete_prompt(&env(), &id, "prod", false, true);
        assert!(
            skipped.contains("without reaching 203.0.113.10"),
            "{skipped}"
        );
    }

    #[test]
    fn a_plain_delete_says_how_each_line_left_is_billed() {
        let mut lines = env();
        lines.lines[1].hourly = false;
        let mut text = String::new();
        say_still_charged(&mut text, &lines, None);
        assert!(
            text.contains("100002 still runs and is charged by the hour"),
            "{text}"
        );
        // The account read, and charged for nothing: nothing hourly is said
        // to be charged.
        let mut text = String::new();
        say_still_charged(&mut text, &lines, Some(&[]));
        assert!(!text.contains("charged by the hour"), "{text}");
        assert!(
            text.contains("100003 still runs and is not billed by the hour"),
            "{text}"
        );
    }

    #[test]
    fn a_worker_not_removed_keeps_its_record_unless_its_server_ended() {
        let failed = Removal::Failed("connection refused".to_owned());
        let nothing_ended = Released::default();
        assert!(must_keep(&failed, &nothing_ended, Some("203.0.113.10")).is_some());
        let server_ended = Released {
            server: Some(json!({ "done": true })),
            ..Released::default()
        };
        assert!(must_keep(&failed, &server_ended, Some("203.0.113.10")).is_none());
        assert!(must_keep(&Removal::Done, &nothing_ended, None).is_none());
        // The operator says it no longer runs there: the record goes.
        assert!(must_keep(&Removal::Skipped, &nothing_ended, Some("203.0.113.10")).is_none());
        assert!(must_keep(&Removal::NoHost, &nothing_ended, None).is_none());
    }

    #[test]
    fn lines_erpc_does_not_end_stay_on_record_with_what_was_not_ended() {
        let released = Released {
            server: Some(json!({ "done": true })),
            lines_failed: vec!["100002".to_owned()],
            kept_ids: vec!["100003".to_owned()],
            failed: vec!["gRPC line 100002: refused".to_owned()],
            ..Released::default()
        };
        let left = left_over(&env(), &released, &Removal::Done);
        let ids: Vec<&str> = left.lines.iter().map(|l| l.id.as_str()).collect();
        assert_eq!(ids, ["100002", "100003"]);
    }

    #[test]
    fn a_line_not_billed_by_the_hour_is_never_ended_or_dropped() {
        let mut line = env().lines[0].clone();
        line.hourly = false;
        assert_eq!(line_end(&line, Some(false), Some(&[])), LineEnd::Keep);
        assert_eq!(line_end(&line, None, None), LineEnd::Keep);
    }

    #[test]
    fn what_was_not_ended_stays_on_record() {
        // The server ended, one line did not: only that line is left.
        let released = Released {
            server: Some(json!({ "done": true })),
            lines_failed: vec!["100003".to_owned()],
            failed: vec!["Shreds line 100003: refused".to_owned()],
            ..Released::default()
        };
        let left = left_over(&env(), &released, &Removal::Done);
        assert!(left.resource.is_none() && left.host.is_none());
        assert_eq!(left.lines.len(), 1);
        assert_eq!(left.lines[0].id, "100003");
        // The server did not end: it stays, with the line that did not.
        let released = Released {
            lines_failed: vec!["100002".to_owned()],
            failed: vec!["the server: refused".to_owned()],
            ..Released::default()
        };
        let left = left_over(&env(), &released, &Removal::Done);
        assert_eq!(left.resource, env().resource);
        assert_eq!(left.lines.len(), 1);
        assert_eq!(left.lines[0].id, "100002");
    }

    #[test]
    fn the_delete_prompt_is_told_in_the_operators_language() {
        use erpc_core::i18n::Lang;
        let id = UnitId::new("app-prod").expect("id");
        let said = || delete_prompt(&env(), &id, "prod", true, false);
        let english = said();
        for lang in [Lang::Ja, Lang::Ru] {
            let text = crate::i18n::speaking(lang, said);
            assert_ne!(text, english);
            assert!(!text.contains('{'), "{text}");
        }
        // Russian counts in three forms.
        let restarts =
            |n: u64| crate::i18n::speaking(Lang::Ru, || tn!("worker_remote.describe.restarts", n));
        assert_eq!(restarts(1), "1 перезапуск");
        assert_eq!(restarts(3), "3 перезапуска");
        assert_eq!(restarts(5), "5 перезапусков");
    }

    #[test]
    fn a_secret_is_quoted_as_json_reads_it() {
        for value in [
            "plain",
            "a\"b\\c",
            "line\nbreak\ttab\r",
            "\u{1}\u{1f}",
            "ünï 秘密",
        ] {
            let quoted = super::json_string(value);
            let back: String = serde_json::from_str(&quoted).expect("json");
            assert_eq!(back, value);
            // Sized once, for the worst case, and never grown.
            assert_eq!(quoted.capacity(), value.len() * 6 + 2, "{value:?}");
        }
    }
}
