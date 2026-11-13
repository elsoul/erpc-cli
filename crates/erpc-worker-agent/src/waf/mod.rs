// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-worker-agent waf`: the HTTP proxy in front of a worker's app.
//!
//! The server's firewall decides who may connect; this decides what they
//! may ask. It listens on a public port, reads each request, and forwards
//! to the app on loopback only what its config
//! ([`erpc_worker::waf::WafConfig`]) lets through. It is a process and a
//! unit of its own ([`erpc_worker::server::waf_unit`]): it shares nothing
//! with `supervise`, holds no key and no secret, reads its config file and
//! writes its stats file.
//!
//! # What it checks
//!
//! A connection is closed at once, unanswered, when its address is banned,
//! holds `max_connections_per_address` already, or the proxy holds 1024
//! (every address together). Then for each request, in this order, the
//! first rule that fails being the answer:
//!
//! 1. The head must be one unambiguous HTTP/1.0 or 1.1 request
//!    ([`head::parse`] lists what is refused: both `Transfer-Encoding` and
//!    `Content-Length`, two of either, a folded header, a bare line feed
//!    and more), at most `max_header_bytes`, and whole within
//!    `header_timeout_secs`: 400, 431, 408.
//! 2. The method must be in `methods`: 405, with `Allow`.
//! 3. The path must be in normal form ([`rules::normalise`]): 400.
//! 4. The path must not be in `deny_paths` (403) and, when `allow_paths`
//!    has any, must be in it (404).
//! 5. With `block_probes`, the path and query must not be a known scanner
//!    probe (the table in [`rules`]): 403.
//! 6. A request with an `Upgrade` header is refused: 501 (see below). It
//!    is a blocked request like the others, held against its address.
//! 7. The address must be within its `rate`: 429, with `Retry-After`.
//! 8. A `Content-Length` must not be over `max_body_bytes`: 413. A chunked
//!    body is counted as it goes by; when it passes the limit the request
//!    to the app is abandoned unfinished and the client gets 413.
//! 9. The body must arrive whole within `body_timeout_secs`, the time
//!    the proxy waits on the app for not counted: one still coming then
//!    gets 408, however steadily and however fast its bytes come, and the
//!    request to the app is abandoned unfinished.
//!
//! A request that passes is sent to the app over a connection of its own:
//! the same method, the same target byte for byte, the same `Host`, and
//! the client's headers but for those that belong to its connection to the
//! proxy, those whose name has an underscore, and `Forwarded`, `X-Real-IP`
//! and `X-Forwarded-Proto`, which are the proxy's to say. The proxy sets
//! `X-Real-IP` to the client's address, adds that address to the end of
//! `X-Forwarded-For`, sets `X-Forwarded-Proto: http`, and writes
//! `Content-Length` as the number it read. The app's answer is passed back
//! as it arrives. An app that is not listening is 502; one that does not
//! start answering within `upstream_timeout_secs` is 504.
//!
//! Every answer of the proxy's own to a blocked request ends the
//! connection. Each blocked request is counted against its address;
//! `ban.after` of them within `ban.window_secs` ban the address for
//! `ban.for_secs`. An address is an IPv4 address, or an IPv6 `/64`.
//!
//! Nothing here grows with what a client sends: a head is at most
//! `max_header_bytes`, a body is passed on in pieces and never held whole,
//! every read from a client and every write to it has a time limit, at most
//! 1024 connections are open, and at most 8192 addresses are remembered,
//! the one heard from longest ago making room for a new one.
//!
//! # What it writes down
//!
//! On standard output, which is the journal: a line when it starts (what
//! it listens on and what is in force), a line when it stops, a line when
//! an address is banned, a line when the app stops answering and when it
//! answers again, and a line for each blocked request: the rule, the
//! status, the client's address, the method, and the first 200 bytes of
//! the target with anything not printable written as `\xNN`. No header and
//! no body is ever written, so an `Authorization` header is not; the
//! target's query is, as far as those 200 bytes reach, so a secret that a
//! blocked request carries in its query is in the journal. A forwarded
//! request leaves no line. A refused connection leaves none either: it is
//! counted. Every line is written as printable ASCII ([`printable`]),
//! whatever it was made from, so that nothing a request, the config or
//! the system put in one can break the line or reach a terminal that
//! shows the journal as anything but text. The counts are in the stats file
//! ([`erpc_worker::waf::WafStats`]), written every five seconds and when
//! it stops.
//!
//! # What it does not do
//!
//! - **No TLS.** It speaks plain HTTP/1.1. It does not speak HTTP/2, and
//!   answers 400 to it.
//! - **No upgrades.** A WebSocket, or any other `Upgrade`, is refused with
//!   501: once a connection has changed protocol its bytes are no longer
//!   requests, and nothing here could judge them.
//! - **No look inside bodies.** A body is measured, never read. The probe
//!   list looks at the path and the query only.
//! - **No authentication.** Who may call the app is the app's to decide,
//!   and the firewall's allow list's.
//! - **The probe list is a noise filter, not a guarantee.** It is short,
//!   it knows a handful of what scanners ask for, and anything written
//!   another way goes through. The app still has to check its input.
//! - **A path is compared as the bytes it decodes to.** An app that reads
//!   paths more loosely than that (routes that ignore case, `;` path
//!   parameters, a second round of decoding) can be reached under a name
//!   a `deny_paths` pattern does not cover. `allow_paths` does not have
//!   that weakness: what is not listed is not forwarded.
//! - **`X-Forwarded-For` is the client's word but for its last entry.**
//!   What the client sent in it is passed on, with the address the proxy
//!   saw added at the end. `X-Real-IP` is the proxy's alone. The client's
//!   other headers are passed on as they came, `Authorization` and
//!   `Cookie` among them.
//! - **The ban list and the counts are in memory.** A restart of the proxy
//!   starts both again. The release build ends the process on a panic, as
//!   every erpc binary does; the unit starts it again. And an address is
//!   forgotten, its ban with it, once 8192 others have been heard from
//!   since it last was: someone with that many addresses is not held by a
//!   ban on one.
//! - **One address is one client.** Clients behind one NAT, or behind one
//!   proxy, share a rate and a ban, and a client with many addresses has
//!   as many rates.
//! - **A slow reader is not a stalled one.** A head has a time to arrive
//!   whole, and so has a body, less the time the proxy waits on the app.
//!   An answer has none to be taken in: the limit there is on a client
//!   that stops taking it, and one that keeps taking it, however slowly,
//!   is served to its end, on one of its address's connections.
//! - A request's trailers are not passed on, an empty line before a
//!   request is refused rather than skipped, and each request is sent to
//!   the app over a new connection.

mod head;
mod limits;
mod proxy;
mod rules;
mod stats;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use erpc_worker::waf::{MAX_CONNECTIONS, WafConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use self::limits::Refused;
use self::proxy::{Clock, Log, Shared};
use self::rules::Reason;

/// How often the stats file is written.
const STATS_EVERY: Duration = Duration::from_secs(5);
/// How long requests in hand have to finish once the proxy is told to stop.
const GRACE: Duration = Duration::from_secs(10);
/// How long accepting pauses when the system refuses another connection
/// (no descriptor left, most likely), instead of asking again at once.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// The largest config file read.
const MAX_CONFIG: u64 = 1024 * 1024;
/// How many log lines wait to be written before new ones are dropped.
const LOG_QUEUE: usize = 1024;

/// At most `most` bytes of `text`, as a line of the journal or of an answer
/// to erpc may hold them: a byte that is not printable ASCII is written as
/// `\xNN`, and what is cut is marked with `...`. Whatever a client, a file
/// or another program put in `text`, it stays on one line and is nothing a
/// terminal acts on.
pub(crate) fn printable(text: &str, most: usize) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(text.len().min(most) + 3);
    for byte in text.bytes().take(most) {
        if matches!(byte, b' '..=b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "\\x{byte:02x}");
        }
    }
    if text.len() > most {
        out.push_str("...");
    }
    out
}

/// A proxy that is listening and has not yet started to serve.
struct Proxy {
    listener: TcpListener,
    serving: Serving,
}

/// What a proxy serves with, once it listens.
struct Serving {
    shared: Arc<Shared>,
    /// When it started, as the stats file says it.
    since: String,
    /// Whether the stats file could not be written last time, so that it
    /// is said once.
    stats_failed: AtomicBool,
    /// How many connections it holds at once, from every address together.
    most: u32,
}

/// One connection's place among those of its address, given back when it
/// ends however it ends.
struct Held {
    shared: Arc<Shared>,
    key: IpAddr,
    _slot: OwnedSemaphorePermit,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.shared.limits().disconnect(self.key);
    }
}

impl Serving {
    /// Writes the stats file, saying once when it cannot be.
    fn write_stats(&self) {
        let shared = &self.shared;
        let banned = shared.limits().banned_now(shared.now());
        let stats = shared.counters.snapshot(&self.since, banned);
        let path = Path::new(&shared.config.stats_path);
        match stats::write(path, &stats) {
            Ok(()) => self.stats_failed.store(false, Ordering::Relaxed),
            Err(error) => {
                if !self.stats_failed.swap(true, Ordering::Relaxed) {
                    shared.say(format!(
                        "could not write the stats to {}: {error}",
                        path.display()
                    ));
                }
            }
        }
    }

    /// Takes a new connection, or closes it when its address is banned or
    /// there are too many.
    fn admit(
        &self,
        slots: &Arc<Semaphore>,
        stopping: &watch::Receiver<bool>,
        stream: TcpStream,
        peer: IpAddr,
    ) {
        let shared = &self.shared;
        let Ok(slot) = Arc::clone(slots).try_acquire_owned() else {
            shared.counters.block(Reason::Connections);
            return;
        };
        let key = limits::key(peer);
        let taken = shared.limits().connect(key, shared.now());
        match taken {
            Ok(()) => {}
            Err(Refused::Banned) => return shared.counters.block(Reason::Banned),
            Err(Refused::TooMany) => return shared.counters.block(Reason::Connections),
        }
        let held = Held {
            shared: Arc::clone(shared),
            key,
            _slot: slot,
        };
        let stopping = stopping.clone();
        tokio::spawn(async move {
            proxy::serve(Arc::clone(&held.shared), stream, peer, stopping).await;
            drop(held);
        });
    }
}

impl Proxy {
    /// Listens on the config's address.
    async fn bind(shared: Shared) -> std::io::Result<Self> {
        let listener = TcpListener::bind(shared.config.listen).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Ok(Self {
            listener,
            serving: Serving {
                shared: Arc::new(shared),
                since: stats::rfc3339(now.as_secs()),
                stats_failed: AtomicBool::new(false),
                most: MAX_CONNECTIONS,
            },
        })
    }

    /// The address it listens on: the config's, with the port the system
    /// chose when the config's is 0 (in a test).
    fn address(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// What is in force, in one line, for the log.
    fn describe(&self) -> String {
        let config = &self.serving.shared.config;
        let paths = |list: &[String], none: &str| {
            if list.is_empty() {
                none.to_owned()
            } else {
                list.join(" ")
            }
        };
        let off = || "off".to_owned();
        format!(
            "listening on {}, forwarding to {}; methods {}; allow {}; deny {}; body up to {} \
             bytes within {} seconds (the time the app takes to accept it not counted), head up \
             to {}; rate {}; connections per address {}; ban {}; probes {}",
            self.address().unwrap_or(config.listen),
            config.upstream,
            config.methods.join(" "),
            paths(&config.allow_paths, "every path"),
            paths(&config.deny_paths, "none"),
            config.max_body_bytes,
            config.body_timeout_secs,
            config.max_header_bytes,
            config.rate.map_or_else(off, |r| format!(
                "{} a second, burst {}",
                r.per_second, r.burst
            )),
            config
                .max_connections_per_address
                .map_or_else(off, |c| c.to_string()),
            config.ban.map_or_else(off, |b| format!(
                "after {} blocked within {} seconds, for {} seconds",
                b.after, b.window_secs, b.for_secs
            )),
            if config.block_probes {
                "blocked"
            } else {
                "not blocked"
            },
        )
    }

    /// Serves until `stop` is done, then lets the requests in hand finish
    /// for up to [`GRACE`], writes the stats a last time and returns.
    async fn run(self, stop: impl Future<Output = ()>) {
        let Self { listener, serving } = self;
        let slots = Arc::new(Semaphore::new(
            usize::try_from(serving.most).unwrap_or(usize::MAX),
        ));
        let (stop_all, stopping) = watch::channel(false);
        let mut every = tokio::time::interval(STATS_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(stop);
        loop {
            tokio::select! {
                biased;
                () = &mut stop => break,
                _ = every.tick() => serving.write_stats(),
                accepted = listener.accept() => match accepted {
                    Ok((stream, from)) => serving.admit(&slots, &stopping, stream, from.ip()),
                    // The client had gone again before it was taken.
                    Err(error) if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                    // No descriptor left, most likely: asking again at once
                    // would only spin.
                    Err(_) => tokio::time::sleep(ACCEPT_PAUSE).await,
                },
            }
        }
        // Closed here: from now on a client is refused by the system.
        drop(listener);
        serving.shared.say(format!(
            "stopping: no new connections, and up to {} seconds for the requests in hand",
            GRACE.as_secs()
        ));
        let _ = stop_all.send(true);
        // Every connection holds one of the slots: all of them free is
        // none left open.
        let finished = tokio::time::timeout(GRACE, slots.acquire_many(serving.most))
            .await
            .is_ok();
        serving.write_stats();
        serving.shared.say(if finished {
            "stopped".to_owned()
        } else {
            format!(
                "stopped: connections still open after {} seconds were cut",
                GRACE.as_secs()
            )
        });
    }
}

/// Writes `line` to the log as one line of printable ASCII
/// ([`printable`]). What a request put in a line is escaped where the line
/// is made ([`proxy::escape`]); this is where every line passes, so the
/// rest of it (a path pattern of the config, the system's words for an
/// error) cannot carry a line break or an escape sequence either.
fn write_line(out: &mut impl std::io::Write, line: &str) {
    let _ = writeln!(out, "{}", printable(line, usize::MAX));
}

/// Where the log goes when the proxy runs as a unit: standard output,
/// which is the journal, a line at a time, from a thread of its own. A
/// journal that cannot keep up must not hold the proxy up, and a client
/// that makes it write a line for every request must not either: lines
/// that find the queue full are dropped, and how many is said.
fn stdout_log() -> (Log, std::thread::JoinHandle<()>) {
    let (queue, lines) = std::sync::mpsc::sync_channel::<String>(LOG_QUEUE);
    let dropped = Arc::new(AtomicU64::new(0));
    let missed = Arc::clone(&dropped);
    let writer = std::thread::spawn(move || {
        let stdout = std::io::stdout();
        for line in lines {
            let mut out = stdout.lock();
            write_line(&mut out, &line);
            let missed = missed.swap(0, Ordering::Relaxed);
            if missed > 0 {
                let _ = writeln!(out, "{missed} log lines were dropped: too many at once");
            }
        }
    });
    let log: Log = Arc::new(move |line| {
        if queue.try_send(line).is_err() {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    });
    (log, writer)
}

/// Done when the process is told to stop: SIGTERM, as systemd sends, or
/// SIGINT.
fn told_to_stop() -> std::io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    })
}

/// The config file's text, when it is no larger than a config can be.
fn read_config(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("could not open it: {e}"))?;
    let mut text = String::new();
    file.take(MAX_CONFIG + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("could not read it: {e}"))?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIG {
        return Err("it is larger than a WAF config can be".to_owned());
    }
    Ok(text)
}

/// Runs the proxy of the config at `path` until SIGTERM or SIGINT. Exit 2
/// when the config is refused, 1 when it cannot listen, and 0 once it was
/// told to stop and has.
pub(crate) fn run(path: &Path) -> ExitCode {
    let config = match read_config(path).and_then(|text| WafConfig::parse(&text)) {
        Ok(config) => config,
        Err(why) => {
            // The config's own words may be in why it is refused.
            let said = format!("erpc-worker-agent: {}: {why}", path.display());
            write_line(&mut std::io::stderr(), &said);
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("erpc-worker-agent: could not start: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (log, writer) = stdout_log();
    let started = std::time::Instant::now();
    let clock: Clock =
        Arc::new(move || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    let listen = config.listen;
    let served = runtime.block_on(async {
        let stop = told_to_stop().map_err(|e| format!("could not take signals: {e}"))?;
        let proxy = Proxy::bind(Shared::new(config, clock, log))
            .await
            .map_err(|e| format!("could not listen on {listen}: {e}"))?;
        proxy.serving.shared.say(proxy.describe());
        proxy.run(stop).await;
        Ok::<(), String>(())
    });
    // Ends every connection still open, and with the last of them the
    // log's queue: the writer then writes what is left and ends.
    drop(runtime);
    let _ = writer.join();
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            write_line(&mut std::io::stderr(), &format!("erpc-worker-agent: {why}"));
            ExitCode::FAILURE
        }
    }
}
