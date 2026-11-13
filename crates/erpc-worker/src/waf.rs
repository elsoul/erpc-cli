// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What `erpc worker` and `erpc-worker-agent waf` agree on about a worker's
//! web application firewall: the config file erpc writes for it, and the
//! stats file it writes back.
//!
//! The WAF is an HTTP reverse proxy in front of the app. It listens on a
//! public port, judges each request by the rules in [`WafConfig`], and
//! forwards what passes to the app on loopback. What it checks, and what it
//! does not, is in the agent's `waf` module; this module is only the
//! contract between the two programs. Neither file holds a secret.

use core::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// The format of the config file and of the stats file.
pub const WAF_FORMAT: u32 = 1;

/// The largest `max_body_bytes`: 64 MiB.
pub const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;
/// The smallest and the largest `max_header_bytes`: 1 KiB and 64 KiB.
pub const HEADER_BYTES: (u32, u32) = (1024, 64 * 1024);
/// The largest `rate.per_second`.
pub const MAX_RATE_PER_SECOND: u32 = 10_000;
/// The largest `rate.burst`.
pub const MAX_RATE_BURST: u32 = 100_000;
/// The largest `max_connections_per_address`, which is also how many
/// connections the proxy holds at once from every address together.
pub const MAX_CONNECTIONS: u32 = 1024;
/// The largest `ban.after`.
pub const MAX_BAN_AFTER: u32 = 1000;
/// The largest `ban.window_secs`: a day.
pub const MAX_BAN_WINDOW_SECS: u32 = 86_400;
/// The largest `ban.for_secs`: thirty days.
pub const MAX_BAN_FOR_SECS: u32 = 30 * 86_400;
/// The largest `header_timeout_secs`.
pub const MAX_HEADER_TIMEOUT_SECS: u32 = 120;
/// The largest `upstream_timeout_secs`.
pub const MAX_UPSTREAM_TIMEOUT_SECS: u32 = 600;
/// The largest `body_timeout_secs`.
pub const MAX_BODY_TIMEOUT_SECS: u32 = 600;
/// The `body_timeout_secs` of a config that does not say one.
pub const DEFAULT_BODY_TIMEOUT_SECS: u32 = 30;
/// The most methods in `methods`, and the longest a method is, in letters.
pub const MAX_METHODS: usize = 16;
/// The most patterns in `allow_paths`, and in `deny_paths`.
pub const MAX_PATHS: usize = 256;
/// The longest path pattern, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// The lowest port the proxy listens on: it runs without any capability,
/// so it cannot bind a port below this.
pub const MIN_LISTEN_PORT: u16 = 1024;
/// The most of a stats file that is read: 4 KiB. The largest the proxy can
/// write, every count at its largest, is under a fifth of that (a test
/// here holds it), so a newer proxy's further counts fit, and a file past
/// it is not one the proxy wrote.
pub const MAX_STATS_BYTES: u64 = 4096;

/// How many requests one client address may make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rate {
    /// Requests a second, sustained: 1 to [`MAX_RATE_PER_SECOND`].
    pub per_second: u32,
    /// Requests at once before the rate applies: `per_second` to
    /// [`MAX_RATE_BURST`].
    pub burst: u32,
}

/// When a client address is refused altogether.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ban {
    /// How many blocked requests it takes: 1 to [`MAX_BAN_AFTER`].
    pub after: u32,
    /// Within how many seconds: 1 to [`MAX_BAN_WINDOW_SECS`].
    pub window_secs: u32,
    /// For how many seconds its connections are then refused: 1 to
    /// [`MAX_BAN_FOR_SECS`]. Held in memory: a restart of the proxy forgets
    /// it.
    pub for_secs: u32,
}

/// `/etc/erpc/worker-waf/<id>.json`: what one worker's WAF listens on,
/// forwards to and refuses. Written by `erpc worker deploy`, read by
/// `erpc-worker-agent waf --config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WafConfig {
    /// [`WAF_FORMAT`].
    pub format: u32,
    /// The address and port the proxy listens on, as `IP:port`
    /// (`0.0.0.0:8080`, `[::]:8080`). The port is [`MIN_LISTEN_PORT`] or
    /// above. It speaks plain HTTP/1.1 there: no TLS.
    pub listen: SocketAddr,
    /// The app: a loopback address (`127.0.0.0/8` or `::1`) and its port.
    /// Nothing else is accepted, so a changed config cannot point the
    /// proxy at another machine.
    pub upstream: SocketAddr,
    /// The methods forwarded, as upper-case letters (`GET`, `POST`): 1 to
    /// [`MAX_METHODS`] of them. A request with another gets 405. `CONNECT`
    /// is refused here: the proxy makes no tunnels.
    pub methods: Vec<String>,
    /// The paths forwarded, at most [`MAX_PATHS`] patterns of at most
    /// [`MAX_PATH_BYTES`] each; empty for every path. A pattern starts with
    /// `/` and is compared with the request's path after percent-decoding,
    /// byte for byte, so it is case-sensitive. It names one path, or every
    /// path under a prefix when it ends in `*`, which is the only wildcard:
    /// `/api/*` is `/api` and everything below `/api/`, and `/api*` is
    /// every path starting with `/api`. A trailing slash makes no
    /// difference, on the pattern or on the request: `/healthz` is also
    /// `/healthz/`. A request to a path not listed gets 404.
    pub allow_paths: Vec<String>,
    /// The paths refused with 403, as in `allow_paths`. Checked first: a
    /// path in both lists is refused.
    pub deny_paths: Vec<String>,
    /// The largest request body forwarded, in bytes: 0 to
    /// [`MAX_BODY_BYTES`]. A larger one gets 413.
    pub max_body_bytes: u64,
    /// The largest request head (request line and headers), in bytes:
    /// [`HEADER_BYTES`]. A larger one gets 431.
    pub max_header_bytes: u32,
    /// The request rate allowed from one client address; absent for no
    /// limit. A request over it gets 429.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<Rate>,
    /// How many connections one client address may hold at once: 1 to
    /// [`MAX_CONNECTIONS`]; absent for no limit of its own. One over it is
    /// closed unanswered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections_per_address: Option<u32>,
    /// When an address that keeps being blocked is refused altogether;
    /// absent for never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ban: Option<Ban>,
    /// Whether requests that look like a scanner's are refused with 403
    /// before they reach the app. The list is short and built in; it is a
    /// noise filter, not a guarantee. An app that itself serves `.php`,
    /// `.asp` or `.jsp` paths turns this off.
    pub block_probes: bool,
    /// How many seconds a client has to send a request's head, 1 to
    /// [`MAX_HEADER_TIMEOUT_SECS`]. Also the longest the proxy waits on a
    /// client that has stopped sending a request's body, or stopped taking
    /// the answer.
    pub header_timeout_secs: u32,
    /// How many seconds a request's body may take in all, the time the
    /// proxy waits on the app for not counted: 1 to
    /// [`MAX_BODY_TIMEOUT_SECS`]. The time runs, from the end of the head,
    /// whenever the proxy could hand the app more of the body and has none
    /// to hand: the client has sent no more, or the proxy has not read yet
    /// what the client sent. It stands still while the proxy waits for the
    /// app to accept what it was handed: a slow app does not cost its
    /// client the request. A body still coming once the time is used up
    /// gets 408, whether it came a byte a second or a byte at a time as
    /// fast as the proxy read them, and the request to the app is
    /// abandoned unfinished: a client cannot hold a connection, and the
    /// app's, by sending a body a byte at a time.
    ///
    /// The one key with a default, [`DEFAULT_BODY_TIMEOUT_SECS`]: a config
    /// written before there was one still reads, so that a server deployed
    /// then keeps a WAF its agent can report and a port its firewall knows
    /// as the WAF's, and its next deploy does not fail on the file before
    /// it has written the config anew.
    ///
    /// The default says how this version reads such a file, not what the
    /// proxy that runs does: one started by an agent from before the key
    /// has no such limit, whatever the file reads as now. That is safe
    /// because a config read here is never by itself taken for the rules
    /// in force: the agent also reports whether the proxy runs the agent
    /// installed, erpc opens the WAF's port wider only when it does, and
    /// `waf-apply` restarts a proxy that does not. So a proxy from before
    /// the key is not taken for the one `erpc.toml` asks for until the
    /// agent installed has restarted it, with this limit.
    #[serde(default = "default_body_timeout_secs")]
    pub body_timeout_secs: u32,
    /// How many seconds the app has to accept a connection, and then to
    /// start answering once it has the request: 1 to
    /// [`MAX_UPSTREAM_TIMEOUT_SECS`]. Also the longest pause allowed inside
    /// its answer.
    pub upstream_timeout_secs: u32,
    /// Where the proxy writes its [`WafStats`]: an absolute path, in a
    /// directory it may write to.
    pub stats_path: String,
}

const fn default_body_timeout_secs() -> u32 {
    DEFAULT_BODY_TIMEOUT_SECS
}

impl WafConfig {
    /// The config erpc writes when `erpc.toml` says no more than that a
    /// worker has a WAF: every protection on, every path forwarded, for
    /// `GET`, `POST`, `PUT` and `DELETE`. `id` is the worker, whose stats
    /// file it names ([`crate::server::waf_stats_path`]).
    ///
    /// A request over the rate is a blocked request too, so the ban takes
    /// no fewer of them than the burst lets through: with fewer, a client
    /// was banned for one burst a little over its limit.
    #[must_use]
    pub fn default_for(id: &str, listen: SocketAddr, upstream: SocketAddr) -> Self {
        Self {
            format: WAF_FORMAT,
            listen,
            upstream,
            methods: ["GET", "POST", "PUT", "DELETE"].map(str::to_owned).to_vec(),
            allow_paths: Vec::new(),
            deny_paths: Vec::new(),
            max_body_bytes: 1024 * 1024,
            max_header_bytes: 16 * 1024,
            rate: Some(Rate {
                per_second: 50,
                burst: 100,
            }),
            max_connections_per_address: Some(32),
            ban: Some(Ban {
                after: 100,
                window_secs: 60,
                for_secs: 600,
            }),
            block_probes: true,
            header_timeout_secs: 10,
            body_timeout_secs: DEFAULT_BODY_TIMEOUT_SECS,
            upstream_timeout_secs: 30,
            stats_path: crate::server::waf_stats_path(id),
        }
    }

    /// Parses a config file, refusing another format, an unknown field,
    /// and any value [`Self::validate`] refuses.
    ///
    /// # Errors
    ///
    /// A message naming the field that is wrong.
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self =
            serde_json::from_str(text).map_err(|e| format!("the WAF config is not valid: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Checks every field against its bounds. The proxy refuses to start
    /// on a config that fails, and erpc checks before it writes one.
    ///
    /// # Errors
    ///
    /// A message naming the first field that is wrong.
    pub fn validate(&self) -> Result<(), String> {
        self.problems().into_iter().next().map_or(Ok(()), Err)
    }

    /// Everything that is wrong with the config, each problem naming its
    /// field; nothing when it is valid.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.format != WAF_FORMAT {
            out.push(format!(
                "the WAF config is format {}, and this version reads {WAF_FORMAT}",
                self.format
            ));
        }
        self.address_problems(&mut out);
        out.extend(self.rule_problems());
        let stats = &self.stats_path;
        let plain = stats.starts_with('/')
            && !stats.ends_with('/')
            && stats.len() <= 4096
            && !stats.bytes().any(|b| b.is_ascii_control())
            && !stats.split('/').any(|part| part == "." || part == "..");
        if !plain {
            out.push(format!(
                "stats_path `{}` is not an absolute path to a file",
                stats.escape_debug()
            ));
        }
        out
    }

    /// What is wrong with what the proxy forwards and refuses, whatever it
    /// listens on and forwards to: the methods, the paths and the numbers.
    /// `[waf]` in `erpc.toml` has these fields as its keys and is checked
    /// with this, so each bound is written once, here.
    #[must_use]
    pub fn rule_problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.method_problems(&mut out);
        for (field, patterns) in [
            ("allow_paths", &self.allow_paths),
            ("deny_paths", &self.deny_paths),
        ] {
            if patterns.len() > MAX_PATHS {
                out.push(format!("{field} has more than {MAX_PATHS} patterns"));
            }
            for pattern in patterns {
                if let Err(why) = path_pattern(pattern) {
                    out.push(format!("{field}: `{}` {why}", pattern.escape_debug()));
                }
            }
        }
        self.number_problems(&mut out);
        out
    }

    fn address_problems(&self, out: &mut Vec<String>) {
        if self.listen.port() < MIN_LISTEN_PORT {
            out.push(format!(
                "listen port {} is below {MIN_LISTEN_PORT}; the proxy runs without the \
                 capability to bind it",
                self.listen.port()
            ));
        }
        if !self.upstream.ip().is_loopback() {
            out.push(format!(
                "upstream {} is not a loopback address; the proxy forwards to the app on this \
                 server only",
                self.upstream
            ));
        }
        if self.upstream.port() == 0 {
            out.push("upstream has no port".to_owned());
        }
        let same_host = self.listen.ip().is_unspecified() || self.listen.ip().is_loopback();
        if same_host && self.listen.port() == self.upstream.port() {
            out.push(format!(
                "listen and upstream are both port {}; the proxy would forward to itself",
                self.listen.port()
            ));
        }
    }

    fn method_problems(&self, out: &mut Vec<String>) {
        if self.methods.is_empty() || self.methods.len() > MAX_METHODS {
            out.push(format!("methods lists 1 to {MAX_METHODS} methods"));
        }
        for (i, method) in self.methods.iter().enumerate() {
            let letters = !method.is_empty()
                && method.len() <= MAX_METHODS
                && method.bytes().all(|b| b.is_ascii_uppercase());
            if !letters {
                out.push(format!(
                    "methods: `{}` is not a method in upper-case letters",
                    method.escape_debug()
                ));
            } else if method == "CONNECT" {
                out.push(
                    "methods: CONNECT asks for a tunnel, which the proxy does not make".to_owned(),
                );
            } else if self.methods.iter().take(i).any(|m| m == method) {
                out.push(format!("methods: {method} is listed twice"));
            }
        }
    }

    fn number_problems(&self, out: &mut Vec<String>) {
        let mut within = |field: &str, value: u64, low: u64, high: u64| {
            if !(low..=high).contains(&value) {
                out.push(format!("{field} is {value}; it is {low} to {high}"));
            }
        };
        within("max_body_bytes", self.max_body_bytes, 0, MAX_BODY_BYTES);
        within(
            "max_header_bytes",
            self.max_header_bytes.into(),
            HEADER_BYTES.0.into(),
            HEADER_BYTES.1.into(),
        );
        if let Some(rate) = self.rate {
            within(
                "rate.per_second",
                rate.per_second.into(),
                1,
                MAX_RATE_PER_SECOND.into(),
            );
            within(
                "rate.burst",
                rate.burst.into(),
                rate.per_second.into(),
                MAX_RATE_BURST.into(),
            );
        }
        if let Some(connections) = self.max_connections_per_address {
            within(
                "max_connections_per_address",
                connections.into(),
                1,
                MAX_CONNECTIONS.into(),
            );
        }
        if let Some(ban) = self.ban {
            within("ban.after", ban.after.into(), 1, MAX_BAN_AFTER.into());
            within(
                "ban.window_secs",
                ban.window_secs.into(),
                1,
                MAX_BAN_WINDOW_SECS.into(),
            );
            within(
                "ban.for_secs",
                ban.for_secs.into(),
                1,
                MAX_BAN_FOR_SECS.into(),
            );
        }
        within(
            "header_timeout_secs",
            self.header_timeout_secs.into(),
            1,
            MAX_HEADER_TIMEOUT_SECS.into(),
        );
        within(
            "body_timeout_secs",
            self.body_timeout_secs.into(),
            1,
            MAX_BODY_TIMEOUT_SECS.into(),
        );
        within(
            "upstream_timeout_secs",
            self.upstream_timeout_secs.into(),
            1,
            MAX_UPSTREAM_TIMEOUT_SECS.into(),
        );
    }
}

/// Whether `pattern` is a path pattern, and why not when it is not.
///
/// It starts with `/`, is written as the path reads after percent-decoding
/// (so it has no `%`), and has no `?`, `#`, backslash, space or control
/// character, no empty or dot segment, and no `*` except as its last
/// character. Nor has it a character that reorders the text around it (a
/// bidirectional mark or override): a pattern is shown, in `check`, in the
/// proxy's journal and in the config a server reports back, and reads
/// there as what it is.
///
/// # Errors
///
/// What is wrong with it, to follow the pattern in a message.
pub fn path_pattern(pattern: &str) -> Result<(), &'static str> {
    if !pattern.starts_with('/') {
        return Err("does not start with `/`");
    }
    if pattern.len() > MAX_PATH_BYTES {
        return Err("is too long");
    }
    let body = pattern.strip_suffix('*').unwrap_or(pattern);
    if body.contains('*') {
        return Err("has a `*` that is not its last character; only a trailing `*` is a wildcard");
    }
    if body.contains('%') {
        return Err("has a `%`; write the path as it reads after percent-decoding");
    }
    if body
        .chars()
        .any(|c| c.is_control() || matches!(c, ' ' | '?' | '#' | '\\'))
    {
        return Err("has a space, a control character, `?`, `#` or a backslash");
    }
    if body.chars().any(reorders) {
        return Err("has a character that reorders the text around it");
    }
    // The first part is what precedes the leading slash, and the last what
    // follows a trailing one or is still to come after a `*`.
    let parts: Vec<&str> = body.split('/').collect();
    let inner = parts.get(1..parts.len().saturating_sub(1)).unwrap_or(&[]);
    if inner.iter().any(|part| part.is_empty()) {
        return Err("has an empty segment (`//`), which no request is forwarded with");
    }
    if parts.iter().any(|part| *part == "." || *part == "..") {
        return Err("has a `.` or `..` segment, which no request is forwarded with");
    }
    Ok(())
}

/// Whether `c` changes the order the text around it is shown in: the
/// Arabic letter mark, the left-to-right and right-to-left marks, and the
/// bidirectional embeddings, overrides and isolates.
const fn reorders(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Whether `text` is an RFC 3339 time as the proxy writes one, or as
/// another writer of the format might: `2026-11-11T09:00:00Z`, with or
/// without a fraction of a second, in UTC (`Z`) or with an offset
/// (`+09:00`). Digits and those marks only, each number within its range,
/// so that a `since` that passes can be shown as it is.
#[must_use]
pub fn is_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    let number = |at: usize, low: u8, high: u8| {
        bytes.get(at..at + 2).is_some_and(|pair| {
            pair.iter().all(u8::is_ascii_digit)
                && (low..=high).contains(&((pair[0] - b'0') * 10 + (pair[1] - b'0')))
        })
    };
    let mark = |at: usize, is: u8| bytes.get(at) == Some(&is);
    let date = bytes
        .get(..4)
        .is_some_and(|y| y.iter().all(u8::is_ascii_digit))
        && mark(4, b'-')
        && number(5, 1, 12)
        && mark(7, b'-')
        && number(8, 1, 31);
    let time = mark(10, b'T')
        && number(11, 0, 23)
        && mark(13, b':')
        && number(14, 0, 59)
        && mark(16, b':')
        && number(17, 0, 60);
    if !(date && time) {
        return false;
    }
    let mut at = 19;
    if mark(at, b'.') {
        let digits = bytes.get(at + 1..).map_or(0, |rest| {
            rest.iter().take_while(|b| b.is_ascii_digit()).count()
        });
        if !(1..=9).contains(&digits) {
            return false;
        }
        at += 1 + digits;
    }
    match bytes.get(at) {
        Some(b'Z') => bytes.len() == at + 1,
        Some(b'+' | b'-') => {
            number(at + 1, 0, 23)
                && mark(at + 3, b':')
                && number(at + 4, 0, 59)
                && bytes.len() == at + 6
        }
        _ => false,
    }
}

/// `stats.json`: what the proxy has done since it started. Written every
/// few seconds and when it stops, whole, so a reader never sees half of
/// one. Counts only: no address, path or header is in it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WafStats {
    /// [`WAF_FORMAT`].
    pub format: u32,
    /// When the proxy started, RFC 3339 UTC. Every count is since then.
    pub since: String,
    /// Requests received: every one whose head arrived, or began to and
    /// was refused. Each is then counted once more, as forwarded, blocked
    /// (under a rule that counts requests) or an upstream error, unless
    /// its client left before it was answered. A head that arrives on a
    /// connection whose address was banned after the connection was taken
    /// is not counted here: the connection is closed unanswered, and
    /// counted under `blocked.banned`.
    pub requests: u64,
    /// Requests the app answered.
    pub forwarded: u64,
    /// What was refused, by rule.
    pub blocked: Blocked,
    /// Addresses whose connections are refused right now.
    pub banned_now: u64,
    /// Requests that passed every rule and that the app did not answer:
    /// it was not listening (502) or took too long (504).
    pub upstream_errors: u64,
}

/// What the proxy refused, by the rule that refused it. Each is a count of
/// requests, except `banned` and `connections`, which count connections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocked {
    /// A method not in `methods` (405).
    pub method: u64,
    /// A path that is not in normal form: a dot segment, an encoded slash,
    /// a control byte, bad percent-encoding (400).
    pub path: u64,
    /// A path in `deny_paths` (403).
    pub denied: u64,
    /// A path not in `allow_paths` (404).
    pub not_allowed: u64,
    /// A scanner's probe (403).
    pub probe: u64,
    /// Over the address's rate (429).
    pub rate: u64,
    /// A body over `max_body_bytes` (413).
    pub body: u64,
    /// A head that could not be read as one unambiguous request, was too
    /// large, or took too long (400, 431, 408).
    pub malformed: u64,
    /// Connections closed unanswered because their address is banned: new
    /// ones, and open ones on which another request arrived.
    pub banned: u64,
    /// Connections refused because their address, or the proxy, held too
    /// many.
    pub connections: u64,
    /// Requests asking to change protocol (`Upgrade`, as a WebSocket
    /// does), which the proxy does not pass on (501).
    #[serde(default)]
    pub upgrade: u64,
    /// A body still coming once its time, `body_timeout_secs`, was used up
    /// (408).
    #[serde(default)]
    pub body_timeout: u64,
}

impl WafStats {
    /// Parses a stats file, refusing another format and a `since` that is
    /// not a time ([`is_timestamp`]). A field this version does not know
    /// is ignored, so a newer proxy's file still reads, and is not in what
    /// is returned.
    ///
    /// What is returned is safe to show: `since` is a time, and everything
    /// else is a number under a name this type gives it. The file is the
    /// proxy's to write, and the proxy is the one program that faces the
    /// network, so its reader takes nothing else from it.
    ///
    /// # Errors
    ///
    /// A message when the text is not a stats file this version reads.
    pub fn parse(text: &str) -> Result<Self, String> {
        let stats: Self =
            serde_json::from_str(text).map_err(|e| format!("the WAF stats are not valid: {e}"))?;
        stats.validate()?;
        Ok(stats)
    }

    /// Refuses another format, and a `since` that is not a time.
    ///
    /// # Errors
    ///
    /// Which of the two it is, without a word of what `since` held.
    pub fn validate(&self) -> Result<(), String> {
        if self.format != WAF_FORMAT {
            return Err(format!(
                "the WAF stats are format {}, and this version reads {WAF_FORMAT}",
                self.format
            ));
        }
        if !is_timestamp(&self.since) {
            return Err("the WAF stats are not valid: `since` is not a time".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Ban, Blocked, MAX_STATS_BYTES, Rate, WAF_FORMAT, WafConfig, WafStats, is_timestamp,
        path_pattern,
    };

    /// The example in the contract, as erpc writes it.
    const EXAMPLE: &str = r#"{
      "format": 1,
      "listen": "0.0.0.0:8080",
      "upstream": "127.0.0.1:3000",
      "methods": ["GET", "POST", "PUT", "DELETE"],
      "allow_paths": ["/api/*", "/healthz"],
      "deny_paths": ["/api/admin/*"],
      "max_body_bytes": 1048576,
      "max_header_bytes": 16384,
      "rate": { "per_second": 50, "burst": 100 },
      "max_connections_per_address": 32,
      "ban": { "after": 100, "window_secs": 60, "for_secs": 600 },
      "block_probes": true,
      "header_timeout_secs": 10,
      "body_timeout_secs": 30,
      "upstream_timeout_secs": 30,
      "stats_path": "/run/erpc-waf-bot-prod/stats.json"
    }"#;

    #[test]
    fn the_example_is_accepted_and_is_the_default_plus_its_paths() {
        let config = WafConfig::parse(EXAMPLE).expect("the example");
        assert_eq!(config.listen.port(), 8080);
        assert!(config.upstream.ip().is_loopback());
        let mut default = WafConfig::default_for(
            "bot-prod",
            "0.0.0.0:8080".parse().expect("listen"),
            "127.0.0.1:3000".parse().expect("upstream"),
        );
        default.validate().expect("the default is valid");
        assert!(default.allow_paths.is_empty() && default.deny_paths.is_empty());
        assert_eq!(
            default.rate,
            Some(Rate {
                per_second: 50,
                burst: 100
            })
        );
        assert_eq!(
            default.ban,
            Some(Ban {
                after: 100,
                window_secs: 60,
                for_secs: 600
            })
        );
        default.allow_paths = vec!["/api/*".to_owned(), "/healthz".to_owned()];
        default.deny_paths = vec!["/api/admin/*".to_owned()];
        assert_eq!(default, config);
        // What erpc writes is what the proxy reads.
        let written = serde_json::to_string_pretty(&config).expect("json");
        assert_eq!(WafConfig::parse(&written).expect("reparse"), config);
    }

    #[test]
    fn the_protections_that_may_be_left_out_are_off_when_they_are() {
        let without = EXAMPLE
            .replace(r#""rate": { "per_second": 50, "burst": 100 },"#, "")
            .replace(r#""max_connections_per_address": 32,"#, "")
            .replace(
                r#""ban": { "after": 100, "window_secs": 60, "for_secs": 600 },"#,
                "",
            );
        let config = WafConfig::parse(&without).expect("without the optional ones");
        assert_eq!(config.rate, None);
        assert_eq!(config.ban, None);
        assert_eq!(config.max_connections_per_address, None);
        let written = serde_json::to_string(&config).expect("json");
        assert!(!written.contains("rate") && !written.contains("ban"));
        // A config written before `body_timeout_secs` reads with its
        // default, and is written out with the key.
        let before = EXAMPLE.replace(r#""body_timeout_secs": 30,"#, "");
        assert_ne!(before, EXAMPLE);
        let read = WafConfig::parse(&before).expect("a config from before");
        assert_eq!(read, WafConfig::parse(EXAMPLE).expect("the example"));
        assert_eq!(read.body_timeout_secs, 30);
        assert!(
            serde_json::to_string(&read)
                .expect("json")
                .contains("\"body_timeout_secs\":30")
        );
        // Every other field is required: none has a default to hide behind.
        for field in [
            "format",
            "listen",
            "upstream",
            "methods",
            "allow_paths",
            "deny_paths",
            "max_body_bytes",
            "max_header_bytes",
            "block_probes",
            "header_timeout_secs",
            "upstream_timeout_secs",
            "stats_path",
        ] {
            let renamed = EXAMPLE.replace(&format!("\"{field}\""), "\"other\"");
            assert_ne!(renamed, EXAMPLE, "{field}");
            let refused = WafConfig::parse(&renamed).expect_err(field);
            assert!(refused.contains("not valid"), "{field}: {refused}");
        }
    }

    /// The example with one field's value replaced.
    fn with(field: &str, was: &str, now: &str) -> Result<WafConfig, String> {
        let from = format!("\"{field}\": {was}");
        assert!(EXAMPLE.contains(&from), "the example has no {from}");
        WafConfig::parse(&EXAMPLE.replace(&from, &format!("\"{field}\": {now}")))
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "one table of fields")]
    fn each_bad_field_is_refused() {
        for (field, was, now, says) in [
            ("format", "1", "2", "format 2"),
            ("listen", "\"0.0.0.0:8080\"", "\"0.0.0.0:80\"", "below 1024"),
            ("listen", "\"0.0.0.0:8080\"", "\"0.0.0.0\"", "not valid"),
            (
                "listen",
                "\"0.0.0.0:8080\"",
                "\"localhost:8080\"",
                "not valid",
            ),
            ("listen", "\"0.0.0.0:8080\"", "\"0.0.0.0:3000\"", "itself"),
            ("listen", "\"0.0.0.0:8080\"", "\"127.0.0.1:3000\"", "itself"),
            (
                "upstream",
                "\"127.0.0.1:3000\"",
                "\"198.51.100.7:3000\"",
                "loopback",
            ),
            (
                "upstream",
                "\"127.0.0.1:3000\"",
                "\"0.0.0.0:3000\"",
                "loopback",
            ),
            (
                "upstream",
                "\"127.0.0.1:3000\"",
                "\"[::ffff:127.0.0.1]:3000\"",
                "loopback",
            ),
            ("upstream", "\"127.0.0.1:3000\"", "\"127.0.0.1:0\"", "port"),
            (
                "upstream",
                "\"127.0.0.1:3000\"",
                "\"127.0.0.1\"",
                "not valid",
            ),
            ("max_body_bytes", "1048576", "67108865", "max_body_bytes"),
            ("max_body_bytes", "1048576", "-1", "not valid"),
            ("max_header_bytes", "16384", "1023", "max_header_bytes"),
            ("max_header_bytes", "16384", "65537", "max_header_bytes"),
            (
                "rate",
                "{ \"per_second\": 50, \"burst\": 100 }",
                "{ \"per_second\": 0, \"burst\": 40 }",
                "rate.per_second",
            ),
            (
                "rate",
                "{ \"per_second\": 50, \"burst\": 100 }",
                "{ \"per_second\": 10001, \"burst\": 20000 }",
                "rate.per_second",
            ),
            (
                "rate",
                "{ \"per_second\": 50, \"burst\": 100 }",
                "{ \"per_second\": 20, \"burst\": 19 }",
                "rate.burst",
            ),
            (
                "rate",
                "{ \"per_second\": 50, \"burst\": 100 }",
                "{ \"per_second\": 20, \"burst\": 100001 }",
                "rate.burst",
            ),
            (
                "rate",
                "{ \"per_second\": 50, \"burst\": 100 }",
                "{ \"per_second\": 20 }",
                "not valid",
            ),
            (
                "max_connections_per_address",
                "32",
                "0",
                "max_connections_per_address",
            ),
            (
                "max_connections_per_address",
                "32",
                "1025",
                "max_connections_per_address",
            ),
            (
                "ban",
                "{ \"after\": 100, \"window_secs\": 60, \"for_secs\": 600 }",
                "{ \"after\": 0, \"window_secs\": 60, \"for_secs\": 600 }",
                "ban.after",
            ),
            (
                "ban",
                "{ \"after\": 100, \"window_secs\": 60, \"for_secs\": 600 }",
                "{ \"after\": 1001, \"window_secs\": 60, \"for_secs\": 600 }",
                "ban.after",
            ),
            (
                "ban",
                "{ \"after\": 100, \"window_secs\": 60, \"for_secs\": 600 }",
                "{ \"after\": 20, \"window_secs\": 0, \"for_secs\": 600 }",
                "ban.window_secs",
            ),
            (
                "ban",
                "{ \"after\": 100, \"window_secs\": 60, \"for_secs\": 600 }",
                "{ \"after\": 20, \"window_secs\": 86401, \"for_secs\": 600 }",
                "ban.window_secs",
            ),
            (
                "ban",
                "{ \"after\": 100, \"window_secs\": 60, \"for_secs\": 600 }",
                "{ \"after\": 20, \"window_secs\": 60, \"for_secs\": 0 }",
                "ban.for_secs",
            ),
            (
                "ban",
                "{ \"after\": 100, \"window_secs\": 60, \"for_secs\": 600 }",
                "{ \"after\": 20, \"window_secs\": 60, \"for_secs\": 2592001 }",
                "ban.for_secs",
            ),
            ("block_probes", "true", "\"yes\"", "not valid"),
            ("header_timeout_secs", "10", "0", "header_timeout_secs"),
            ("header_timeout_secs", "10", "121", "header_timeout_secs"),
            ("body_timeout_secs", "30", "0", "body_timeout_secs"),
            ("body_timeout_secs", "30", "601", "body_timeout_secs"),
            ("upstream_timeout_secs", "30", "0", "upstream_timeout_secs"),
            (
                "upstream_timeout_secs",
                "30",
                "601",
                "upstream_timeout_secs",
            ),
            (
                "stats_path",
                "\"/run/erpc-waf-bot-prod/stats.json\"",
                "\"stats.json\"",
                "stats_path",
            ),
            (
                "stats_path",
                "\"/run/erpc-waf-bot-prod/stats.json\"",
                "\"/run/erpc-waf-bot-prod/\"",
                "stats_path",
            ),
            (
                "stats_path",
                "\"/run/erpc-waf-bot-prod/stats.json\"",
                "\"/run/../etc/stats.json\"",
                "stats_path",
            ),
        ] {
            let refused = with(field, was, now).expect_err(now);
            assert!(refused.contains(says), "{field} = {now}: {refused}");
        }
        // The bounds themselves are inside.
        for (field, was, now) in [
            ("listen", "\"0.0.0.0:8080\"", "\"[::]:1024\""),
            ("listen", "\"0.0.0.0:8080\"", "\"198.51.100.7:3000\""),
            ("upstream", "\"127.0.0.1:3000\"", "\"[::1]:3000\""),
            ("upstream", "\"127.0.0.1:3000\"", "\"127.8.9.10:3000\""),
            ("max_body_bytes", "1048576", "0"),
            ("max_body_bytes", "1048576", "67108864"),
            ("max_header_bytes", "16384", "1024"),
            ("max_header_bytes", "16384", "65536"),
            ("header_timeout_secs", "10", "120"),
            ("body_timeout_secs", "30", "1"),
            ("body_timeout_secs", "30", "600"),
            ("upstream_timeout_secs", "30", "600"),
            ("max_connections_per_address", "32", "1024"),
        ] {
            with(field, was, now).unwrap_or_else(|e| panic!("{field} = {now}: {e}"));
        }
        // And a field the proxy does not know is not ignored.
        let unknown = EXAMPLE.replace("\"block_probes\"", "\"tls\": true, \"block_probes\"");
        assert!(WafConfig::parse(&unknown).is_err());
    }

    #[test]
    fn every_problem_is_listed_and_the_first_is_what_validate_says() {
        let mut config = WafConfig::parse(EXAMPLE).expect("the example");
        assert!(config.problems().is_empty());
        assert!(config.rule_problems().is_empty());
        config.listen = "0.0.0.0:80".parse().expect("listen");
        config.methods = vec!["get".to_owned(), "POST".to_owned(), "POST".to_owned()];
        config.deny_paths = vec!["admin".to_owned()];
        config.max_header_bytes = 10;
        config.rate = Some(Rate {
            per_second: 0,
            burst: 0,
        });
        config.ban = Some(Ban {
            after: 0,
            window_secs: 0,
            for_secs: 0,
        });
        let problems = config.problems();
        let starts: Vec<&str> = problems
            .iter()
            .map(|p| p.split([' ', ':']).next().unwrap_or_default())
            .collect();
        assert_eq!(
            starts,
            [
                "listen",
                "methods",
                "methods",
                "deny_paths",
                "max_header_bytes",
                "rate.per_second",
                "ban.after",
                "ban.window_secs",
                "ban.for_secs"
            ],
            "{problems:#?}"
        );
        assert_eq!(config.validate().as_ref(), Err(&problems[0]));
        // The rules alone leave out what it listens on and forwards to.
        assert_eq!(config.rule_problems(), problems[1..]);
    }

    #[test]
    fn a_ban_takes_more_blocked_requests_than_a_burst_lets_through() {
        let default = WafConfig::default_for(
            "bot-prod",
            "0.0.0.0:8080".parse().expect("listen"),
            "127.0.0.1:3000".parse().expect("upstream"),
        );
        let (rate, ban) = (default.rate.expect("rate"), default.ban.expect("ban"));
        assert_eq!((rate.per_second, rate.burst), (50, 100));
        assert_eq!((ban.after, ban.window_secs, ban.for_secs), (100, 60, 600));
        // Each request over the rate is a blocked request: it takes a
        // burst's worth of those, on top of the burst, to be banned.
        assert!(ban.after >= rate.burst);
    }

    #[test]
    fn methods_are_upper_case_letters_listed_once() {
        let methods = "[\"GET\", \"POST\", \"PUT\", \"DELETE\"]";
        for good in ["[\"GET\"]", "[\"GET\", \"HEAD\", \"OPTIONS\", \"PATCH\"]"] {
            with("methods", methods, good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in [
            "[]",
            "[\"get\"]",
            "[\"GET \"]",
            "[\"G-T\"]",
            "[\"\"]",
            "[\"GET\", \"GET\"]",
            "[\"CONNECT\"]",
            "[\"ABCDEFGHIJKLMNOPQ\"]",
            "[\"A\",\"B\",\"C\",\"D\",\"E\",\"F\",\"G\",\"H\",\"I\",\"J\",\"K\",\"L\",\"M\",\"N\",\"O\",\"P\",\"Q\"]",
        ] {
            let refused = with("methods", methods, bad).expect_err(bad);
            assert!(refused.contains("methods"), "{bad}: {refused}");
        }
    }

    #[test]
    fn a_path_pattern_starts_with_a_slash_and_only_ends_in_a_star() {
        for good in [
            "/",
            "/*",
            "/healthz",
            "/api/*",
            "/api*",
            "/api/v1/",
            "/a.b/c-d_e",
            "/caf\u{e9}",
        ] {
            assert_eq!(path_pattern(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "api",
            "*",
            "/api/*/x",
            "/**",
            "/a*b",
            "/api/%61dmin",
            "/api?x=1",
            "/api#x",
            "/a b",
            "/a\\b",
            "/a\tb",
            "/a\0b",
            "/a\u{7f}b",
            "/a\u{85}b",
            "/a\u{9b}2J",
            "/a\u{202e}b",
            "/a\u{200f}",
            "/a\u{2066}b/*",
            "//",
            "/a//b",
            "//a",
            "/a/./b",
            "/a/..",
            "/../a",
            "/a/../*",
        ] {
            assert!(path_pattern(bad).is_err(), "{bad:?}");
        }
        assert!(path_pattern(&format!("/{}", "a".repeat(1024))).is_err());
        let refused = with("deny_paths", "[\"/api/admin/*\"]", "[\"/api/*/admin\"]")
            .expect_err("a star inside");
        assert!(
            refused.contains("deny_paths") && refused.contains("/api/*/admin"),
            "{refused}"
        );
        let many: Vec<String> = (0..257).map(|i| format!("\"/p{i}\"")).collect();
        let refused = with(
            "allow_paths",
            "[\"/api/*\", \"/healthz\"]",
            &format!("[{}]", many.join(",")),
        )
        .expect_err("too many");
        assert!(refused.contains("allow_paths"), "{refused}");
    }

    #[test]
    fn stats_read_back_and_another_format_is_refused() {
        let text = r#"{"format":1,"since":"2026-11-11T09:00:00Z","requests":12,"forwarded":7,
            "blocked":{"method":1,"path":0,"denied":1,"not_allowed":0,"probe":2,"rate":0,
            "body":0,"malformed":1,"banned":3,"connections":0},"banned_now":1,
            "upstream_errors":0}"#;
        let stats = WafStats::parse(text).expect("stats");
        assert_eq!(stats.format, WAF_FORMAT);
        assert_eq!((stats.requests, stats.forwarded), (12, 7));
        assert_eq!((stats.blocked.probe, stats.blocked.banned), (2, 3));
        // Written before `upgrade` and `body_timeout` were counted.
        assert_eq!((stats.blocked.upgrade, stats.blocked.body_timeout), (0, 0));
        let written = serde_json::to_string(&stats).expect("json");
        assert_eq!(WafStats::parse(&written).expect("reparse"), stats);
        // A newer proxy's extra count does not make the file unreadable.
        let newer = text.replace("\"banned_now\"", "\"later\":5,\"banned_now\"");
        assert_eq!(WafStats::parse(&newer).expect("newer"), stats);
        assert!(WafStats::parse(&text.replace("\"format\":1", "\"format\":2")).is_err());
        assert!(WafStats::parse("{}").is_err());
    }

    #[test]
    fn a_since_is_a_time_and_nothing_else() {
        for good in [
            "2026-11-11T09:00:00Z",
            "1970-01-01T00:00:00Z",
            "2026-12-31T23:59:60Z",
            "2026-11-11T09:00:00.5Z",
            "2026-11-11T09:00:00.123456789Z",
            "2026-11-11T18:00:00+09:00",
            "2026-11-11T04:00:00.25-05:00",
        ] {
            assert!(is_timestamp(good), "{good}");
        }
        for bad in [
            "",
            "now",
            "2026-11-11",
            "2026-11-11 09:00:00Z",
            "2026-11-11T09:00:00",
            "2026-11-11T09:00:00z",
            "2026-13-11T09:00:00Z",
            "2026-11-32T09:00:00Z",
            "2026-00-11T09:00:00Z",
            "2026-11-11T24:00:00Z",
            "2026-11-11T09:60:00Z",
            "2026-11-11T09:00:61Z",
            "2026-11-11T09:00:00.Z",
            "2026-11-11T09:00:00.1234567890Z",
            "2026-11-11T09:00:00+0900",
            "2026-11-11T09:00:00+24:00",
            "2026-11-11T09:00:00+09:60",
            // An offset is hours, a colon and minutes, and the colon is
            // nothing else.
            "2026-11-11T18:00:00+09 00",
            "2026-11-11T18:00:00+09-00",
            "2026-11-11T18:00:00+09000",
            "2026-11-11T18:00:00+09\u{1b}00",
            "2026-11-11T04:00:00.25-05\n00",
            // Nothing follows an offset, as nothing follows `Z`.
            "2026-11-11T18:00:00+09:00 ",
            "2026-11-11T18:00:00+09:00Z",
            "2026-11-11T18:00:00+09:00:00",
            "2026-11-11T18:00:00+09:00\n",
            "2026-11-11T18:00:00+09:00\u{1b}[2J",
            "2026-11-11T04:00:00.25-05:00\u{1b}]0;owned\u{7}",
            "2026-11-11T09:00:00Z ",
            " 2026-11-11T09:00:00Z",
            "2026-11-11T09:00:00Z\n",
            "2026-11-11T09:00:00Z\u{1b}[2J",
            "\u{1b}]0;owned\u{7}\u{1b}[2J",
            "２０２６-11-11T09:00:00Z",
            "+026-11-11T09:00:00Z",
        ] {
            assert!(!is_timestamp(bad), "{bad:?}");
        }
        // Stats whose `since` is anything else do not read, and why they
        // do not says nothing of what was there.
        let stats = |since: &str| {
            serde_json::to_string(&WafStats {
                format: WAF_FORMAT,
                since: since.to_owned(),
                ..WafStats::default()
            })
            .expect("json")
        };
        assert!(WafStats::parse(&stats("2026-11-11T09:00:00Z")).is_ok());
        let refused = WafStats::parse(&stats("\u{1b}]0;owned\u{7}")).expect_err("not a time");
        assert_eq!(
            refused,
            "the WAF stats are not valid: `since` is not a time"
        );
    }

    #[test]
    fn the_largest_stats_the_proxy_can_write_are_well_under_what_is_read() {
        let most = u64::MAX;
        let largest = WafStats {
            format: u32::MAX,
            since: "2026-11-11T09:00:00.123456789+09:00".to_owned(),
            requests: most,
            forwarded: most,
            blocked: Blocked {
                method: most,
                path: most,
                denied: most,
                not_allowed: most,
                probe: most,
                rate: most,
                body: most,
                malformed: most,
                banned: most,
                connections: most,
                upgrade: most,
                body_timeout: most,
            },
            banned_now: most,
            upstream_errors: most,
        };
        let written = serde_json::to_string_pretty(&largest).expect("json");
        let size = u64::try_from(written.len()).expect("small");
        assert!(size * 5 < MAX_STATS_BYTES, "{size} bytes");
    }
}
