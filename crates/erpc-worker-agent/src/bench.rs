// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `ctl bench-rpc`: times JSON-RPC calls from this server
//! ([`erpc_worker::bench`]). The request, URLs and any keys in them, is
//! read from standard input and kept in memory; what is printed names each
//! endpoint by its scheme, host and port only.

use std::time::{Duration, Instant};

use erpc_worker::bench::{self, Measured, Request};
use serde_json::{Value, json};

/// The biggest request read from standard input.
const MAX_REQUEST: u64 = 64 * 1024;
/// How long one call may take before it counts as failed.
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// One call's time in milliseconds, and the slot when the answer is one.
fn call(
    client: &reqwest::blocking::Client,
    url: &str,
    body: &str,
) -> Result<(f64, Option<u64>), String> {
    let started = Instant::now();
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_owned())
        .send()
        .map_err(|e| e.without_url().to_string())?;
    let status = response.status();
    let text = response.text().map_err(|e| e.without_url().to_string())?;
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    if !status.is_success() {
        // The provider's own words say why (a refused key, a rate limit),
        // cut short and kept to one printable line.
        let said: String = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message").or(Some(e)))
                    .or_else(|| v.get("message"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or(text)
            .chars()
            .filter(|c| !c.is_control())
            .take(160)
            .collect();
        return Err(if said.trim().is_empty() {
            format!("HTTP {}", status.as_u16())
        } else {
            format!("HTTP {}: {}", status.as_u16(), said.trim())
        });
    }
    let answer: Value =
        serde_json::from_str(&text).map_err(|_| "the answer is not JSON".to_owned())?;
    if let Some(error) = answer.get("error") {
        let message = error["message"].as_str().unwrap_or("an RPC error");
        return Err(message.chars().take(200).collect());
    }
    Ok((ms, answer["result"].as_u64()))
}

/// Runs the request on standard input.
pub(crate) fn run() -> Result<Value, String> {
    // The request can carry an API key: read into one buffer, wiped.
    #[allow(clippy::cast_possible_truncation, reason = "64 KiB")]
    let text = crate::wiped::read(&mut std::io::stdin().lock(), MAX_REQUEST as usize, false)
        .map_err(|e| format!("could not read standard input: {e}"))?
        .ok_or("the request on standard input is too long")?;
    let request: Request = serde_json::from_slice(&text)
        .map_err(|e| format!("standard input is not a benchmark request: {e}"))?;
    let problems = request.problems();
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    let body = request.body();
    // One client, so one kept-alive connection, per target.
    let clients = request
        .targets
        .iter()
        .map(|_| {
            reqwest::blocking::Client::builder()
                .timeout(CALL_TIMEOUT)
                .pool_max_idle_per_host(1)
                .build()
                .map_err(|e| format!("could not make an HTTP client: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (target, client) in request.targets.iter().zip(&clients) {
        for _ in 0..bench::WARM_UP {
            let _ = call(client, &target.url, &body);
        }
    }
    let mut measured: Vec<Measured> = request
        .targets
        .iter()
        .map(|t| Measured {
            name: t.name.clone(),
            host: bench::host_of(&t.url).unwrap_or_default(),
            ms: Vec::new(),
            slots: Vec::new(),
            first_error: None,
        })
        .collect();
    let count = request.targets.len();
    let pause = Duration::from_millis(u64::from(request.interval_ms));
    for round in 0..request.rounds as usize {
        if round > 0 && !pause.is_zero() {
            std::thread::sleep(pause);
        }
        // Who goes first moves round by round.
        for k in 0..count {
            let i = (round + k) % count;
            let (Some(target), Some(client), Some(out)) =
                (request.targets.get(i), clients.get(i), measured.get_mut(i))
            else {
                continue;
            };
            match call(client, &target.url, &body) {
                Ok((ms, slot)) => {
                    out.ms.push(Some(ms));
                    out.slots.push(slot);
                }
                Err(e) => {
                    out.ms.push(None);
                    out.slots.push(None);
                    out.first_error.get_or_insert(e);
                }
            }
        }
    }
    Ok(
        json!({ "ok": true, "method": request.method, "rounds": request.rounds, "measured": measured }),
    )
}
