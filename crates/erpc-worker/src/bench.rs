// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The RPC latency benchmark `erpc worker bench` runs on a worker's
//! server: what erpc asks the agent for, what the agent measures, and the
//! summary erpc shows.
//!
//! The agent sends the same JSON-RPC call to every target, round after
//! round, rotating which goes first so none is always warmer, over one
//! kept-alive connection per target. A couple of calls each are made first
//! and not counted, so a TLS handshake is not taken for latency. A target's
//! URL can carry an API key: it reaches the agent on standard input, and
//! only its scheme, host and port ([`host_of`]) are ever shown.

use serde::{Deserialize, Serialize};

/// The most targets one run compares.
pub const MAX_TARGETS: usize = 6;
/// The most rounds one run makes.
pub const MAX_ROUNDS: u32 = 1000;
/// The longest pause between rounds, in milliseconds.
pub const MAX_INTERVAL_MS: u32 = 10_000;
/// The calls a target gets before the counted ones.
pub const WARM_UP: u32 = 2;

/// The methods a run may call: reads with no parameters that every Solana
/// RPC serves, ERPC's Unlimited endpoint included.
pub const METHODS: &[&str] = &[
    "getSlot",
    "getBlockHeight",
    "getLatestBlockhash",
    "getHealth",
];

/// What erpc asks the agent to measure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The JSON-RPC method, one of [`METHODS`].
    pub method: String,
    /// The counted calls per target.
    pub rounds: u32,
    /// A pause between rounds, in milliseconds, for an endpoint whose plan
    /// limits calls per second: without one, the calls go back to back.
    #[serde(default)]
    pub interval_ms: u32,
    /// What to call.
    pub targets: Vec<Target>,
}

/// One endpoint to measure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// What the table calls it: lowercase letters, digits and hyphens.
    pub name: String,
    /// Its URL, which may carry a key: never shown whole.
    pub url: String,
}

/// What the agent measured for one target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Measured {
    /// The target's name.
    pub name: String,
    /// Its scheme, host and port.
    pub host: String,
    /// Each round's time in milliseconds, `None` when the call failed.
    pub ms: Vec<Option<f64>>,
    /// Each round's slot, for `getSlot`.
    pub slots: Vec<Option<u64>>,
    /// The first failure, without the URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_error: Option<String>,
}

/// One target's numbers, as the table shows them.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    /// The target's name.
    pub name: String,
    /// Its scheme, host and port.
    pub host: String,
    /// Calls that answered.
    pub ok: usize,
    /// Calls that failed.
    pub failed: usize,
    /// Milliseconds, over the calls that answered.
    pub min: Option<f64>,
    /// The median.
    pub p50: Option<f64>,
    /// The 90th percentile.
    pub p90: Option<f64>,
    /// The 99th percentile.
    pub p99: Option<f64>,
    /// The slowest.
    pub max: Option<f64>,
    /// The mean.
    pub mean: Option<f64>,
    /// How many slots behind the freshest answer of the same round it was,
    /// on average, for `getSlot`.
    pub slots_behind: Option<f64>,
    /// The first failure, without the URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_error: Option<String>,
}

impl Request {
    /// What is wrong with the request, every problem at once.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !METHODS.contains(&self.method.as_str()) {
            out.push(format!(
                "`{}` is not a method the benchmark calls; it calls {}",
                self.method,
                METHODS.join(", ")
            ));
        }
        if !(1..=MAX_ROUNDS).contains(&self.rounds) {
            out.push(format!("rounds must be 1 to {MAX_ROUNDS}"));
        }
        if self.interval_ms > MAX_INTERVAL_MS {
            out.push(format!("the interval is at most {MAX_INTERVAL_MS} ms"));
        }
        if self.targets.is_empty() || self.targets.len() > MAX_TARGETS {
            out.push(format!("a run compares 1 to {MAX_TARGETS} endpoints"));
        }
        let mut names = std::collections::BTreeSet::new();
        for target in &self.targets {
            let name_ok = !target.name.is_empty()
                && target.name.len() <= 24
                && target
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !name_ok {
                out.push(format!(
                    "`{}` is not an endpoint name: 1 to 24 lowercase letters, digits and hyphens",
                    target.name
                ));
            }
            if !names.insert(target.name.as_str()) {
                out.push(format!("`{}` is named twice", target.name));
            }
            if host_of(&target.url).is_none() {
                out.push(format!(
                    "{}: the URL is not an http:// or https:// address",
                    target.name
                ));
            }
        }
        out
    }

    /// The JSON-RPC body each call sends.
    #[must_use]
    pub fn body(&self) -> String {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": self.method }).to_string()
    }
}

/// `url`'s scheme, host and port, with no user, path or query, which is
/// where a key would be; `None` when it is not an http(s) URL.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.split_once(']').map(|(ip, _)| ip))
        .unwrap_or_else(|| host.split(':').next().unwrap_or(host));
    if bare.is_empty() || !crate::net::is_host(bare) {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

/// The value at quantile `q` (0 to 1) of `sorted`, by nearest rank.
fn quantile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "a rank among at most MAX_ROUNDS samples"
    )]
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted.get(rank - 1).copied()
}

/// Each target's numbers. Slots behind are measured against the freshest
/// slot any target answered in the same round.
#[must_use]
pub fn summarize(measured: &[Measured]) -> Vec<Summary> {
    let rounds = measured.iter().map(|m| m.slots.len()).max().unwrap_or(0);
    let freshest: Vec<Option<u64>> = (0..rounds)
        .map(|i| {
            measured
                .iter()
                .filter_map(|m| m.slots.get(i).copied().flatten())
                .max()
        })
        .collect();
    measured
        .iter()
        .map(|m| {
            let mut ok: Vec<f64> = m.ms.iter().filter_map(|v| *v).collect();
            ok.sort_by(f64::total_cmp);
            #[allow(clippy::cast_precision_loss, reason = "at most MAX_ROUNDS samples")]
            let mean = (!ok.is_empty()).then(|| ok.iter().sum::<f64>() / ok.len() as f64);
            let behind: Vec<u64> = m
                .slots
                .iter()
                .zip(&freshest)
                .filter_map(|(slot, top)| Some(top.as_ref()?.saturating_sub((*slot)?)))
                .collect();
            #[allow(
                clippy::cast_precision_loss,
                reason = "slot differences and counts this small are exact"
            )]
            let slots_behind = (!behind.is_empty())
                .then(|| behind.iter().sum::<u64>() as f64 / behind.len() as f64);
            Summary {
                name: m.name.clone(),
                host: m.host.clone(),
                ok: ok.len(),
                failed: m.ms.len() - ok.len(),
                min: ok.first().copied(),
                p50: quantile(&ok, 0.5),
                p90: quantile(&ok, 0.9),
                p99: quantile(&ok, 0.99),
                max: ok.last().copied(),
                mean,
                slots_behind,
                first_error: m.first_error.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Measured, Request, Target, host_of, summarize};

    // Built, not written out: the endpoint gate reads literals.
    fn url(scheme: &str, rest: &str) -> String {
        [scheme, rest].join("://")
    }

    #[test]
    fn only_the_scheme_host_and_port_of_a_url_are_shown() {
        assert_eq!(
            host_of(&url("https", "edge.erpc.global?api-key=secret")),
            Some(url("https", "edge.erpc.global"))
        );
        assert_eq!(
            host_of(&url("http", "203.0.113.5:8899/")),
            Some(url("http", "203.0.113.5:8899"))
        );
        assert_eq!(
            host_of(&url("https", "user:pw@edge.erpc.global/k")),
            Some(url("https", "edge.erpc.global"))
        );
        assert_eq!(host_of(&url("ws", "edge.erpc.global")), None);
        assert_eq!(host_of("edge.erpc.global"), None);
    }

    #[test]
    fn a_request_is_checked_whole() {
        let ok = Request {
            method: "getSlot".to_owned(),
            rounds: 50,
            interval_ms: 100,
            targets: vec![Target {
                name: "shared".to_owned(),
                url: url("https", "edge.erpc.global?api-key=k"),
            }],
        };
        assert!(ok.problems().is_empty(), "{:?}", ok.problems());
        let bad = Request {
            method: "getProgramAccounts".to_owned(),
            rounds: 0,
            interval_ms: 60_000,
            targets: vec![
                Target {
                    name: "Shared".to_owned(),
                    url: "nope".to_owned(),
                },
                Target {
                    name: "Shared".to_owned(),
                    url: url("https", "edge.erpc.global"),
                },
            ],
        };
        assert_eq!(bad.problems().len(), 7, "{:?}", bad.problems());
    }

    #[test]
    fn the_summary_ranks_and_compares_slots() {
        let a = Measured {
            name: "a".to_owned(),
            host: url("http", "203.0.113.5:8899"),
            ms: (1..=100).map(|i| Some(f64::from(i))).collect(),
            slots: vec![Some(10), Some(11)],
            first_error: None,
        };
        let b = Measured {
            name: "b".to_owned(),
            host: url("https", "edge.erpc.global"),
            ms: vec![Some(5.0), None],
            slots: vec![Some(9), None],
            first_error: Some("timed out".to_owned()),
        };
        let s = summarize(&[a, b]);
        assert_eq!(
            (s[0].p50, s[0].p90, s[0].p99),
            (Some(50.0), Some(90.0), Some(99.0))
        );
        assert_eq!(
            (s[0].min, s[0].max, s[0].mean),
            (Some(1.0), Some(100.0), Some(50.5))
        );
        assert_eq!(s[0].slots_behind, Some(0.0));
        assert_eq!((s[1].ok, s[1].failed), (1, 1));
        assert_eq!(s[1].slots_behind, Some(1.0));
    }
}
