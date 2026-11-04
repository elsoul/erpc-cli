// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker bench`: how fast each RPC answers from the worker's
//! server, side by side.
//!
//! The endpoints are ERPC's shared RPC, with the account's API key (or the
//! app's `ERPC_API_KEY` secret), the environment's Unlimited RPC when it
//! has one, and any `--url` given: another provider's RPC, say, kept in
//! 1Password or the keychain like the app's secrets. The agent on the server times the calls
//! ([`erpc_worker::bench`]): measured there, the numbers are what the app
//! gets, not what this machine's own distance adds. The request, keys and
//! all, goes to the agent on standard input; the table shows each endpoint
//! by its scheme, host and port only.

use core::fmt::Write as _;

use erpc_ssh::worker::Verb;
use erpc_worker::bench::{self, Measured, Request, Summary, Target};
use erpc_worker::manifest::{LineKind, SecretRef};
use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::worker::App;
use crate::worker_remote::{ctl_ok, failed, reach};

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
    let mut targets = Vec::new();
    if asked.shared {
        let key = if let Some(reference) = m.secrets.get("ERPC_API_KEY") {
            crate::worker_secrets::read(reference).map_err(failed)?
        } else {
            let api = crate::worker_vps::Api::open().await?;
            crate::worker_vps::shared_api_key(&api).await?
        };
        targets.push(Target {
            name: "shared".to_owned(),
            url: format!("{SHARED_RPC}?api-key={}", key.as_str()),
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
        let url = endpoint(name, url, &mut asked_on_stdin)?;
        targets.push(Target {
            name: name.to_owned(),
            url: url.as_str().to_owned(),
        });
    }
    if targets.is_empty() {
        return Err(CliError::new(Code::Usage, t!("worker_bench.nothing"))
            .hint(t!("worker_bench.nothing_hint")));
    }
    let request = Request {
        method: asked.method.clone(),
        rounds: asked.rounds,
        interval_ms: asked.interval_ms,
        targets,
    };
    let problems = request.problems();
    if !problems.is_empty() {
        return Err(CliError::new(Code::Usage, problems.join("; ")));
    }
    let line = Zeroizing::new(serde_json::to_vec(&request).map_err(|e| failed(e.to_string()))?);
    drop(request);
    let answer = ctl_ok(&session, &id, Verb::BenchRpc, Some(&line))?;
    drop(line);
    let measured: Vec<Measured> = serde_json::from_value(answer["measured"].clone())
        .map_err(|e| failed(t!("worker_bench.not_readable", error = e)))?;
    let summaries = bench::summarize(&measured);
    let host = env.host.clone().unwrap_or_default();
    let region = env.resource.as_ref().and_then(|r| r.region.clone());
    let text = render(
        &asked.method,
        asked.rounds,
        asked.interval_ms,
        id.as_str(),
        &host,
        region.as_deref(),
        &summaries,
    );
    let body = json!({
        "worker": id.as_str(),
        "server": host,
        "region": region,
        "method": asked.method,
        "rounds": asked.rounds,
        "interval_ms": asked.interval_ms,
        "warm_up": bench::WARM_UP,
        "results": summaries,
    });
    Ok((body, text))
}

/// The URL `--url NAME=VALUE` names. VALUE is the URL itself, a
/// reference to where it is kept (`op://…`, `keychain:…`), so a URL that
/// carries a key need not be typed where shell history keeps it, or `-`:
/// read from standard input, or asked for without echo (one `-` a run).
fn endpoint(name: &str, value: &str, asked: &mut bool) -> Result<Zeroizing<String>, CliError> {
    if value == "-" {
        if std::mem::replace(asked, true) {
            return Err(CliError::new(Code::Usage, t!("worker_bench.one_stdin")));
        }
        return crate::worker_keys::read_secret(&t!("worker_bench.url_of", name));
    }
    if value.starts_with("op://") || value.starts_with("keychain:") {
        let reference = SecretRef::parse(value).map_err(|e| CliError::new(Code::Usage, e))?;
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

    #[test]
    fn a_url_is_given_kept_somewhere_or_typed_once() {
        let url = ["https", "edge.erpc.global"].join("://");
        let mut asked = false;
        assert_eq!(
            super::endpoint("other", &url, &mut asked)
                .expect("plain")
                .as_str(),
            url
        );
        assert!(super::endpoint("other", "keychain:", &mut asked).is_err());
        // A second `-` cannot be read: standard input was the first one's.
        let mut asked = true;
        assert!(super::endpoint("other", "-", &mut asked).is_err());
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
