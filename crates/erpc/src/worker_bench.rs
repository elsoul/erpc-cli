// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker bench`: how fast each RPC answers from the worker's
//! server, side by side.
//!
//! The endpoints are ERPC's shared RPC, with the app's `ERPC_API_KEY`
//! secret or else the account's API key, the environment's Unlimited RPC
//! when it has one, and any `--url` given: another provider's RPC, say,
//! kept in 1Password, the keychain or the keystore like the app's secrets.
//! The account's key is the first of its keys the shared RPC accepts when
//! they are tried from this machine, or, when it accepts none, the first
//! it could not be asked about; refused with all of them, the bench goes
//! on with the primary one and says so, since the calls are the server's
//! to make and a key can be limited to its address ([`shared_key`]). The
//! agent on the server times the calls
//! ([`erpc_worker::bench`]): measured there, the numbers are what the app
//! gets, not what this machine's own distance adds. The request, keys and
//! all, goes to the agent on standard input; the table shows each endpoint
//! by its scheme, host and port only.

use core::fmt::Write as _;

use erpc_ssh::worker::Verb;
use erpc_worker::bench::{self, Measured, Request, Summary, Target};
use erpc_worker::manifest::{Env, LineKind, Manifest, SecretRef};
use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::worker::App;
use crate::worker_remote::{ctl_ok, failed, reach};
use crate::worker_vps::{KeySource, Tried, keys_tried};

use erpc_core::endpoints::SHARED_RPC_URL as SHARED_RPC;

/// What `erpc worker bench` was asked.
pub(crate) struct Asked {
    pub(crate) method: String,
    pub(crate) rounds: u32,
    pub(crate) interval_ms: u32,
    /// `NAME=URL` pairs.
    pub(crate) urls: Vec<String>,
    pub(crate) shared: bool,
}

/// `erpc worker bench`.
pub(crate) async fn bench(json: bool, app: &App, asked: &Asked) -> Outcome {
    match run(app, asked).await {
        Ok((body, text)) => {
            if json {
                crate::print_json(&body);
                Outcome::Done(String::new())
            } else {
                Outcome::Done(crate::ui::decorate(&text, "⏱️"))
            }
        }
        Err(e) => e.into(),
    }
}

async fn run(app: &App, asked: &Asked) -> Result<(serde_json::Value, String), CliError> {
    let (m, id, session) = reach(app)?;
    let env = crate::worker::env_of(&m, app)?.clone();
    let (request, refused_here) =
        request_for(&m, &env, asked, crate::worker_vps::Api::open).await?;
    let line = Zeroizing::new(serde_json::to_vec(&request).map_err(|e| failed(e.to_string()))?);
    drop(request);
    let answer = ctl_ok(&session, &id, Verb::BenchRpc, Some(&line))?;
    drop(line);
    let measured: Vec<Measured> = serde_json::from_value(answer["measured"].clone())
        .map_err(|e| failed(t!("worker_bench.not_readable", error = e)))?;
    let summaries = bench::summarize(&measured);
    let host = env.host.clone().unwrap_or_default();
    let region = env.resource.as_ref().and_then(|r| r.region.clone());
    let at = At {
        worker: id.as_str(),
        host: &host,
        region: region.as_deref(),
    };
    Ok(report(asked, &at, &summaries, refused_here))
}

/// The request the agent is sent for `asked`, of app `m` in `env`; and how
/// many of the account's keys this machine was refused with, when it was
/// refused with all of them ([`shared_key`]).
///
/// Everything the command can be refused for by itself comes before the
/// key of `shared`: each `--url` pair and what it names ([`endpoint`]),
/// that there is something to measure, and the request's method, rounds,
/// interval, names and count ([`Request::problems`]), which are checked
/// with `shared` in its place and no key in it yet. Only then is the key
/// read, from the app's secret or from the account, which `account` opens:
/// so a command that is going to be refused reads nothing from user-api,
/// and sends no key to the shared RPC.
async fn request_for<K: KeySource>(
    m: &Manifest,
    env: &Env,
    asked: &Asked,
    account: impl AsyncFnOnce() -> Result<K, CliError>,
) -> Result<(Request, Option<usize>), CliError> {
    let mut targets = Vec::new();
    if asked.shared {
        targets.push(Target {
            name: "shared".to_owned(),
            url: SHARED_RPC.to_owned(),
        });
    }
    // A line whose endpoint user-api has not named yet has nothing to call.
    for line in env
        .lines
        .iter()
        .filter(|l| l.kind == LineKind::Unlimited && !l.is_pending())
    {
        targets.push(Target {
            name: "unlimited".to_owned(),
            url: line.endpoint.clone(),
        });
    }
    let mut asked_on_stdin = false;
    for pair in &asked.urls {
        let (name, url) = pair.split_once('=').ok_or_else(|| {
            let said = bench::host_of(pair).map_or_else(
                || t!("worker_bench.url_not_pair_unknown"),
                |given| t!("worker_bench.url_not_pair", given),
            );
            CliError::new(Code::Usage, said)
        })?;
        let url = endpoint(m, name, url, &mut asked_on_stdin)?;
        targets.push(Target {
            name: name.to_owned(),
            url: url.as_str().to_owned(),
        });
    }
    if targets.is_empty() {
        return Err(CliError::new(Code::Usage, t!("worker_bench.nothing"))
            .hint(t!("worker_bench.nothing_hint")));
    }
    let mut request = Request {
        method: asked.method.clone(),
        rounds: asked.rounds,
        interval_ms: asked.interval_ms,
        targets,
    };
    let problems = request.problems();
    if !problems.is_empty() {
        return Err(CliError::new(Code::Usage, problems.join("; ")));
    }
    let mut refused_here = None;
    // `shared` is the first of the targets when it is one of them.
    if let Some(shared) = request.targets.first_mut().filter(|_| asked.shared) {
        let (key, refused) = shared_key(m, account).await?;
        refused_here = refused;
        shared.url = format!("{SHARED_RPC}?api-key={}", key.as_str());
    }
    Ok((request, refused_here))
}

/// The key `shared` is measured with: the app's `ERPC_API_KEY` secret when
/// it has one, else the account's, opened with `account` and tried from
/// this machine ([`crate::worker_vps::keys_tried`]).
///
/// The calls are made from the server, not from here. So when this
/// machine is refused with every key of the account, the bench goes on
/// with the primary one, which may be limited to the server's address,
/// and says so: the second of the pair is then how many keys were tried.
/// A key the shared RPC could not be asked about, when it accepted none,
/// is measured with as an accepted one is: the `shared` row tells.
async fn shared_key<K: KeySource>(
    m: &Manifest,
    account: impl AsyncFnOnce() -> Result<K, CliError>,
) -> Result<(Zeroizing<String>, Option<usize>), CliError> {
    if let Some(reference) = m.secrets.get("ERPC_API_KEY") {
        let key = crate::worker_secrets::read(reference).map_err(failed)?;
        return Ok((key, None));
    }
    Ok(match keys_tried(&account().await?).await? {
        Tried::Usable { key, .. } => (key, None),
        Tried::Refused { primary, tried } => (primary, Some(tried)),
    })
}

/// Where the calls were made from: the worker, its server and the
/// server's region.
struct At<'a> {
    worker: &'a str,
    host: &'a str,
    region: Option<&'a str>,
}

/// What the bench answers: the JSON, and the text. `refused_here` is how
/// many of the account's keys this machine was refused with, when it was
/// refused with all and `shared` was measured with the primary one
/// ([`shared_key`]): said in one line under the table, and in the JSON as
/// `shared_key_refused_here`.
fn report(
    asked: &Asked,
    at: &At<'_>,
    summaries: &[Summary],
    refused_here: Option<usize>,
) -> (serde_json::Value, String) {
    let mut text = render(
        &asked.method,
        asked.rounds,
        asked.interval_ms,
        at.worker,
        at.host,
        at.region,
        summaries,
    );
    if let Some(count) = refused_here {
        text.push('\n');
        text.push_str(&t!("worker_bench.shared_unconfirmed", count));
    }
    let body = json!({
        "worker": at.worker,
        "server": at.host,
        "region": at.region,
        "method": asked.method,
        "rounds": asked.rounds,
        "interval_ms": asked.interval_ms,
        "warm_up": bench::WARM_UP,
        "shared_key_refused_here": refused_here.is_some(),
        "results": summaries,
    });
    (body, text)
}

/// The URL `--url NAME=VALUE` names. VALUE is the URL itself, a
/// reference to where it is kept (`op://…`, `keychain:…`, `keystore:…`),
/// so a URL that carries a key need not be typed where shell history keeps
/// it, or `-`: read from standard input, or asked for without echo (one
/// `-` a run).
///
/// A reference is read as a setting of `m` is, so it may not be the
/// trading key's either: what it holds goes to the server as a URL.
fn endpoint(
    m: &Manifest,
    name: &str,
    value: &str,
    asked: &mut bool,
) -> Result<Zeroizing<String>, CliError> {
    if value == "-" {
        if std::mem::replace(asked, true) {
            return Err(CliError::new(Code::Usage, t!("worker_bench.one_stdin")));
        }
        return crate::worker_keys::read_secret(&t!("worker_bench.url_of", name));
    }
    if ["op://", "keychain:", "keystore:"]
        .iter()
        .any(|scheme| value.starts_with(scheme))
    {
        let reference = SecretRef::parse(value).map_err(|e| CliError::new(Code::Usage, e))?;
        if let Some(why) = m.key_as_setting(&reference) {
            return Err(CliError::new(Code::Usage, format!("--url {name}: {why}")));
        }
        return crate::worker_secrets::read(&reference)
            .map(|url| Zeroizing::new(url.trim().to_owned()))
            .map_err(failed);
    }
    Ok(Zeroizing::new(value.to_owned()))
}

/// Each endpoint that failed, with its first failure.
fn failures(out: &mut String, rows: &[Summary]) {
    for row in rows {
        if let Some(e) = &row.first_error {
            let name = &row.name;
            let _ = writeln!(
                out,
                "{}",
                tn!("worker_bench.failures", row.failed, name, error = e)
            );
            if row.name == "shared" && e.starts_with("HTTP 401") {
                let _ = writeln!(out, "  {}", t!("worker_bench.shared_refused"));
            }
        }
    }
}

/// Milliseconds as the table shows them.
fn ms(value: Option<f64>) -> String {
    match value {
        Some(v) if v < 10.0 => format!("{v:.2} ms"),
        Some(v) => format!("{v:.1} ms"),
        None => "—".to_owned(),
    }
}

/// The table, and what it says.
fn render(
    method: &str,
    rounds: u32,
    interval_ms: u32,
    worker: &str,
    host: &str,
    region: Option<&str>,
    rows: &[Summary],
) -> String {
    let at = format!(
        "{host}{}",
        region.map(|r| format!(" ({r})")).unwrap_or_default()
    );
    let each = tn!("worker_bench.each", rounds);
    let warm = tn!("worker_bench.warm_up", bench::WARM_UP);
    let apart = if interval_ms > 0 {
        t!("worker_bench.apart", ms = interval_ms)
    } else {
        String::new()
    };
    let title = t!("worker_bench.title", method, worker, at, each, warm, apart);
    let mut out = format!("{title}\n\n");
    let header = [
        t!("worker_bench.column.endpoint"),
        t!("worker_bench.column.host"),
        "p50".to_owned(),
        "p90".to_owned(),
        "p99".to_owned(),
        "min".to_owned(),
        "max".to_owned(),
        t!("worker_bench.column.failed"),
        t!("worker_bench.column.slots_behind"),
    ];
    let cells: Vec<[String; 9]> = rows
        .iter()
        .map(|r| {
            [
                r.name.clone(),
                r.host.clone(),
                ms(r.p50),
                ms(r.p90),
                ms(r.p99),
                ms(r.min),
                ms(r.max),
                format!("{}/{}", r.failed, r.ok + r.failed),
                r.slots_behind
                    .map_or_else(|| "—".to_owned(), |b| format!("{b:.2}")),
            ]
        })
        .collect();
    // Columns line up by the width a terminal gives each character, which
    // is two for a Japanese or Chinese one.
    let width = |text: &str| unicode_width::UnicodeWidthStr::width(text);
    let mut widths: Vec<usize> = header.iter().map(|h| width(h)).collect();
    for row in &cells {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(width(cell));
        }
    }
    let mut line = |cells: &[&str]| {
        let mut text = String::new();
        for (i, (cell, w)) in cells.iter().zip(&widths).enumerate() {
            let pad = " ".repeat(w.saturating_sub(width(cell)));
            // Names and hosts to the left, numbers to the right.
            if i < 2 {
                let _ = write!(text, "{cell}{pad}  ");
            } else {
                let _ = write!(text, "{pad}{cell}  ");
            }
        }
        out.push_str(text.trim_end());
        out.push('\n');
    };
    line(&header.iter().map(String::as_str).collect::<Vec<_>>());
    let rule: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
    line(&rule.iter().map(String::as_str).collect::<Vec<_>>());
    for row in &cells {
        line(&row.iter().map(String::as_str).collect::<Vec<_>>());
    }
    let mut ranked: Vec<&Summary> = rows.iter().filter(|r| r.p50.is_some()).collect();
    ranked.sort_by(|a, b| {
        a.p50
            .unwrap_or(f64::MAX)
            .total_cmp(&b.p50.unwrap_or(f64::MAX))
    });
    if let [fastest, rest @ ..] = ranked.as_slice() {
        out.push('\n');
        for other in rest {
            if let (Some(a), Some(b)) = (fastest.p50, other.p50)
                && a > 0.0
            {
                let (fastest, other) = (&fastest.name, &other.name);
                let times = format!("{:.1}", b / a);
                let (a, b) = (ms(Some(a)), ms(Some(b)));
                let said = t!("worker_bench.faster", fastest, times, other, a, b);
                let _ = writeln!(out, "{said}");
            }
        }
        if rest.is_empty() {
            let (name, time) = (&fastest.name, ms(fastest.p50));
            let _ = writeln!(out, "{}", t!("worker_bench.alone", name, time));
        }
    }
    failures(&mut out, rows);
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {

    /// A made-up 1Password vault id, of the shape a real one has.
    const OP_VAULT: &str = "abcdefghijklmnopqrstuvwxyz";
    use erpc_worker::bench::Summary;

    fn row(name: &str, p50: f64) -> Summary {
        Summary {
            name: name.to_owned(),
            host: ["http", "203.0.113.5:8899"].join("://"),
            ok: 100,
            failed: 0,
            min: Some(p50 / 2.0),
            p50: Some(p50),
            p90: Some(p50 * 1.5),
            p99: Some(p50 * 3.0),
            max: Some(p50 * 4.0),
            mean: Some(p50),
            slots_behind: Some(0.0),
            first_error: None,
        }
    }

    fn manifest(rest: &str) -> erpc_worker::manifest::Manifest {
        erpc_worker::manifest::Manifest::parse(&format!(
            "name = \"bot\"\nchain = \"solana\"\n{rest}"
        ))
        .expect("a manifest")
    }

    #[test]
    fn a_url_is_given_kept_somewhere_or_typed_once() {
        let m = manifest("");
        let url = ["https", "edge.erpc.global"].join("://");
        let mut asked = false;
        assert_eq!(
            super::endpoint(&m, "other", &url, &mut asked)
                .expect("plain")
                .as_str(),
            url
        );
        assert!(super::endpoint(&m, "other", "keychain:", &mut asked).is_err());
        assert!(super::endpoint(&m, "other", "keystore:", &mut asked).is_err());
        assert!(super::endpoint(&m, "other", "keystore:../x", &mut asked).is_err());
        // A second `-` cannot be read: standard input was the first one's.
        let mut asked = true;
        assert!(super::endpoint(&m, "other", "-", &mut asked).is_err());
    }

    #[test]
    fn a_url_by_reference_is_never_the_trading_key() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _kept = set_up(&desk);
        let store = crate::worker_secrets::Store::Keystore { by_default: true };
        let key = erpc_chain_solana::identity::Keypair::generate().expect("random");
        crate::worker_secrets::put_key(&store, "bot", &key).expect("kept");
        let asked = desk.asked();
        let refused = |m: &erpc_worker::manifest::Manifest, value: &str| {
            let e = super::endpoint(m, "other", value, &mut false).expect_err("refused");
            assert_eq!(e.code, crate::error::Code::Usage, "{value}");
            e.text()
        };
        // An entry filed as a key, in an app with no [wallet] of its own;
        // in any case, and in the keychain too. The keystore is unlocked,
        // and is not reached.
        let plain = manifest("");
        for value in [
            "keystore:erpc-worker/bot.wallet",
            "keystore:erpc-worker/bot.WALLET",
            "keychain:erpc-worker/bot.wallet",
        ] {
            let said = refused(&plain, value);
            assert!(
                said.contains(&format!(
                    "--url other: {value} is an entry filed as a trading key"
                )),
                "{said}"
            );
            assert!(said.contains("[wallet]"), "{said}");
        }
        // What [wallet] names, whatever it is called and wherever it is.
        let vault = OP_VAULT;
        for source in [
            "keystore:erpc-worker/bot.wallet".to_owned(),
            "keychain:my-service/trading".to_owned(),
            format!("op://{vault}/{vault}/keypair"),
        ] {
            let m = manifest(&format!("[wallet]\nsource = \"{source}\"\n"));
            let said = refused(&m, &source);
            assert!(
                said.contains(&format!("--url other: {source} is wallet.source")),
                "{said}"
            );
        }
        assert!(desk.is_unlocked());
        assert_eq!(desk.asked(), asked, "nothing was asked for");
        // A URL kept as a secret is read as before.
        let url = ["https", "rpc.example.com/?api-key=k"].join("://");
        let kept = crate::worker_secrets::put(
            &store,
            "bot",
            "OTHER_RPC",
            &zeroize::Zeroizing::new(format!("{url}\n")),
        )
        .expect("kept");
        assert_eq!(
            super::endpoint(&plain, "other", &kept.to_string(), &mut false)
                .expect("read")
                .as_str(),
            url
        );
    }

    /// `erpc worker bench` as asked, with `shared` among its endpoints.
    fn asked(method: &str, rounds: u32, interval_ms: u32, urls: &[String]) -> super::Asked {
        super::Asked {
            method: method.to_owned(),
            rounds,
            interval_ms,
            urls: urls.to_vec(),
            shared: true,
        }
    }

    /// An address of another provider's RPC, joined from parts.
    fn elsewhere() -> String {
        ["https", "rpc.example.com"].join("://")
    }

    /// What the command can be refused for by itself is said before the
    /// account is opened: user-api is not read, and no key goes to the RPC.
    #[tokio::test]
    async fn a_bench_that_is_going_to_be_refused_does_not_read_the_account() {
        use crate::error::Code;
        use crate::worker_vps::fake::Scripted;
        use erpc_worker::manifest::Env;
        let (m, env) = (manifest(""), Env::default());
        let account = Scripted::account(&serde_json::json!({ "apiKey": "primary" }));
        let opened = std::cell::Cell::new(0);
        let refused = async |asked: super::Asked| {
            let request = super::request_for(&m, &env, &asked, async || {
                opened.set(opened.get() + 1);
                Ok(&account)
            });
            let e = request.await.expect_err("refused");
            assert_eq!(e.code, Code::Usage, "{}", e.text());
            let read = (opened.get(), account.reads.get(), account.asked().len());
            assert_eq!(read, (0, 0, 0), "{}", e.text());
            e.message
        };
        let url = |name: &str| format!("{name}={}", elsewhere());
        // A --url that is no NAME=URL pair, with a host to name or without.
        let e = refused(asked("getSlot", 100, 0, &["other".to_owned()])).await;
        assert_eq!(e, "--url takes NAME=URL, not `that`");
        let e = refused(asked("getSlot", 100, 0, &[elsewhere()])).await;
        assert_eq!(e, format!("--url takes NAME=URL, not `{}`", elsewhere()));
        // What a --url names: a reference that is none, and a URL that is
        // not one the bench can call.
        refused(asked(
            "getSlot",
            100,
            0,
            &["other=keystore:../x".to_owned()],
        ))
        .await;
        let ftp = format!("other={}", ["ftp", "rpc.example.com"].join("://"));
        let e = refused(asked("getSlot", 100, 0, &[ftp])).await;
        assert!(e.starts_with("other: the URL is not an "), "{e}");
        // The method, the rounds and the interval.
        let e = refused(asked("getBalance", 100, 0, &[])).await;
        assert!(e.starts_with("`getBalance` is not a method"), "{e}");
        let e = refused(asked("getSlot", 0, 0, &[])).await;
        assert_eq!(e, "rounds must be 1 to 1000");
        let e = refused(asked("getSlot", 100, 10_001, &[])).await;
        assert_eq!(e, "the interval is at most 10000 ms");
        // The names and the count, which `shared` is one of before its key
        // is read: a --url called `shared`, and six beside it.
        let e = refused(asked("getSlot", 100, 0, &[url("shared")])).await;
        assert_eq!(e, "`shared` is named twice");
        let six: Vec<String> = (1..=6).map(|n| url(&format!("other-{n}"))).collect();
        let e = refused(asked("getSlot", 100, 0, &six)).await;
        assert_eq!(e, "a run compares 1 to 6 endpoints");
        // Nothing to measure at all.
        let nothing = super::Asked {
            shared: false,
            ..asked("getSlot", 100, 0, &[])
        };
        assert_eq!(refused(nothing).await, "there is nothing to measure");
    }

    /// With all of that in order the account is read, once, and its key
    /// goes into `shared`, which stays the first of the endpoints.
    #[tokio::test]
    async fn a_bench_reads_the_account_once_its_request_holds() {
        use crate::worker_vps::Verdict;
        use crate::worker_vps::fake::Scripted;
        use erpc_core::endpoints::SHARED_RPC_URL;
        use erpc_worker::manifest::{Env, Line, LineKind};
        let m = manifest("");
        let unlimited = ["https", "unlimited.example.com"].join("://");
        let with_lines = |lines: &[(LineKind, &str)]| Env {
            lines: lines
                .iter()
                .map(|(kind, endpoint)| Line {
                    kind: *kind,
                    id: "300003".to_owned(),
                    endpoint: (*endpoint).to_owned(),
                    hourly: true,
                })
                .collect(),
            ..Env::default()
        };
        let env = with_lines(&[(LineKind::Unlimited, &unlimited)]);
        let urls = [format!("other={}", elsewhere())];
        let named = |request: &erpc_worker::bench::Request| -> Vec<(String, String)> {
            let targets = request.targets.iter();
            targets.map(|t| (t.name.clone(), t.url.clone())).collect()
        };
        let rest = [
            ("unlimited".to_owned(), unlimited),
            ("other".to_owned(), elsewhere()),
        ];
        let account = || Scripted::account(&serde_json::json!({ "apiKey": "primary" }));
        // The account's key, in `shared`'s URL.
        let from = account();
        let wanted = asked("getSlot", 100, 0, &urls);
        let (request, refused_here) = super::request_for(&m, &env, &wanted, async || Ok(&from))
            .await
            .expect("a request");
        assert_eq!(
            (from.reads.get(), from.asked()),
            (1, vec!["primary".to_owned()])
        );
        let shared = (
            "shared".to_owned(),
            format!("{SHARED_RPC_URL}?api-key=primary"),
        );
        assert_eq!(named(&request), [&[shared.clone()][..], &rest[..]].concat());
        assert_eq!(refused_here, None);
        assert!(request.problems().is_empty());
        // Refused from here with it: the same request, and that is said.
        let from = account().with("primary", Verdict::Refused);
        let (request, refused_here) = super::request_for(&m, &env, &wanted, async || Ok(&from))
            .await
            .expect("a request");
        assert_eq!(named(&request), [&[shared][..], &rest[..]].concat());
        assert_eq!(refused_here, Some(1));
        // --no-shared: the account is not opened, and no key is anywhere.
        let from = account();
        let wanted = super::Asked {
            shared: false,
            ..wanted
        };
        let (request, refused_here) = super::request_for(&m, &env, &wanted, async || Ok(&from))
            .await
            .expect("a request");
        assert_eq!((from.reads.get(), from.asked().len()), (0, 0));
        assert_eq!((named(&request), refused_here), (rest.to_vec(), None));
        // A line that is no Unlimited RPC is not measured, nor an Unlimited
        // RPC whose endpoint user-api has not named yet.
        let env = with_lines(&[(LineKind::Grpc, &elsewhere()), (LineKind::Unlimited, "")]);
        let (request, _) = super::request_for(&m, &env, &wanted, async || Ok(&from))
            .await
            .expect("a request");
        assert_eq!(named(&request), rest[1..]);
    }

    /// The key `shared` is measured with, with the account scripted.
    #[tokio::test]
    async fn the_shared_rpc_is_measured_with_the_apps_key_or_the_accounts() {
        use crate::error::{CliError, Code};
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        use crate::worker_vps::Verdict;
        use crate::worker_vps::fake::Scripted;
        use serde_json::json;
        let account = || {
            Scripted::account(&json!({
                "apiKey": "primary",
                "activeApiKeys": ["second", "primary"],
            }))
        };
        let plain = manifest("");
        // The account's key, the first the shared RPC takes from here.
        let (key, refused_here) = super::shared_key(&plain, async || Ok(account()))
            .await
            .expect("a key");
        assert_eq!((key.as_str(), refused_here), ("primary", None));
        let ended = account().with("primary", Verdict::Refused);
        let (key, refused_here) = super::shared_key(&plain, async || Ok(ended))
            .await
            .expect("a key");
        assert_eq!((key.as_str(), refused_here), ("second", None));
        // A primary key the RPC could not be asked about: the second,
        // which it takes. With none taken, the bench goes on with the one
        // it could not be asked about, and has nothing to say of it: it
        // was not refused, and the `shared` row tells.
        let away = account().with("primary", Verdict::Unknown);
        let (key, refused_here) = super::shared_key(&plain, async || Ok(away))
            .await
            .expect("a key");
        assert_eq!((key.as_str(), refused_here), ("second", None));
        let unconfirmed = account()
            .with("primary", Verdict::Refused)
            .with("second", Verdict::Unknown);
        let (key, refused_here) = super::shared_key(&plain, async || Ok(unconfirmed))
            .await
            .expect("the bench goes on");
        assert_eq!((key.as_str(), refused_here), ("second", None));
        // This machine refused with every one: the calls are made from
        // the server, so the bench goes on, with the primary key, and
        // carries how many were tried, to say so.
        let limited = account()
            .with("primary", Verdict::Refused)
            .with("second", Verdict::Refused);
        let (key, refused_here) = super::shared_key(&plain, async || Ok(limited))
            .await
            .expect("the bench goes on");
        assert_eq!((key.as_str(), refused_here), ("primary", Some(2)));
        // No session, or user-api silent: still an error.
        let no_session = CliError::new(Code::NotSignedIn, "there is no session");
        let e = super::shared_key(&plain, async || Err::<Scripted, _>(no_session.clone()))
            .await
            .expect_err("no account");
        assert_eq!(e, no_session);
        // An app with ERPC_API_KEY of its own is measured with that, and
        // the account is not opened.
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _keystore = set_up(&desk);
        let kept = crate::worker_secrets::put(
            &crate::worker_secrets::Store::Keystore { by_default: false },
            "bot",
            "ERPC_API_KEY",
            &zeroize::Zeroizing::new("the-apps-own-key".to_owned()),
        )
        .expect("kept");
        let with_secret = manifest(&format!("[secrets]\nERPC_API_KEY = \"{kept}\"\n"));
        let (key, refused_here) = super::shared_key(&with_secret, async || {
            Err::<Scripted, _>(CliError::new(Code::Failed, "the account was opened"))
        })
        .await
        .expect("the app's key");
        assert_eq!((key.as_str(), refused_here), ("the-apps-own-key", None));
    }

    #[test]
    fn a_key_this_machine_was_refused_with_is_said_under_the_table_and_in_the_json() {
        use crate::i18n::speaking;
        use erpc_core::i18n::Lang;
        let asked = super::Asked {
            method: "getSlot".to_owned(),
            rounds: 100,
            interval_ms: 0,
            urls: Vec::new(),
            shared: true,
        };
        let at = super::At {
            worker: "bot-default",
            host: "198.51.100.7",
            region: Some("amsterdam"),
        };
        let rows = [row("shared", 3.4)];
        let table = super::render(
            "getSlot",
            100,
            0,
            "bot-default",
            "198.51.100.7",
            Some("amsterdam"),
            &rows,
        );
        // Confirmed, or not the account's: the table alone.
        let (body, text) = super::report(&asked, &at, &rows, None);
        assert_eq!(text, table);
        assert_eq!(body["shared_key_refused_here"], false);
        // Refused from here with all three: one line more, and a field.
        let (body, text) = super::report(&asked, &at, &rows, Some(3));
        assert_eq!(
            text,
            format!(
                "{table}\nThe shared RPC took none of the account's API keys when they were \
                 tried from this machine (3 tried), so `shared` was measured with the account's \
                 primary key: a key limited to the server's address is refused here and works \
                 there."
            )
        );
        assert_eq!(body["shared_key_refused_here"], true);
        assert_eq!(body["worker"], "bot-default");
        assert_eq!(body["results"][0]["name"], "shared");
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let (_, said) = speaking(lang, || super::report(&asked, &at, &rows, Some(3)));
            let line = said.lines().last().expect("a line");
            assert_ne!(line, text.lines().last().expect("a line"), "{lang:?}");
            assert!(line.contains('3') && line.contains("`shared`"), "{line}");
            assert!(!line.contains('{'), "{line}");
        }
    }

    #[test]
    fn the_table_lines_up_and_says_which_is_faster() {
        let text = super::render(
            "getSlot",
            100,
            0,
            "bot-default",
            "198.51.100.7",
            Some("amsterdam"),
            &[row("shared", 3.4), row("unlimited", 0.85)],
        );
        assert!(text.starts_with("getSlot from bot-default's server 198.51.100.7 (amsterdam)"));
        assert!(text.contains("unlimited answered 4.0× faster than shared at the median (0.85 ms against 3.40 ms)."), "{text}");
        let widths: Vec<usize> = text
            .lines()
            .skip(2)
            .take(4)
            .map(|l| l.chars().count())
            .collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "{text}");
    }

    #[test]
    fn the_table_is_said_in_the_language_of_the_run_and_still_lines_up() {
        use crate::i18n::speaking;
        use erpc_core::i18n::Lang;
        let rows = [row("shared", 3.4), row("unlimited", 0.85)];
        let table = || super::render("getSlot", 100, 0, "bot", "198.51.100.7", None, &rows);
        let english = table();
        for lang in [Lang::Ja, Lang::Ru] {
            let said = speaking(lang, table);
            assert_ne!(said, english);
            assert!(!said.contains('{'), "{said}");
            let widths: Vec<usize> = said
                .lines()
                .skip(2)
                .take(4)
                .map(unicode_width::UnicodeWidthStr::width)
                .collect();
            assert!(widths.windows(2).all(|w| w[0] == w[1]), "{said}");
        }
    }
}
