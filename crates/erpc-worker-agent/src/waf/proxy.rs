// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! One client connection: read a request's head, judge it, answer it here
//! or forward it to the app, and go round again.
//!
//! The head is read and judged before hyper is involved at all
//! ([`super::head`], [`super::rules`]). A request that passes is then
//! served by hyper from an [`Wire`] that gives it that request's bytes
//! and not one more: the head, as many body bytes as its `Content-Length`
//! says, and then the end of input. So hyper never reads a second head,
//! and what follows a request on the connection is read here, strictly,
//! as the next one. A chunked body has no length to count to, so the
//! connection ends with that request.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use erpc_worker::waf::WafConfig;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead as _, AsyncReadExt as _, AsyncWrite as _, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Instant, Sleep};

use super::head::{self, Framing, Head};
use super::limits::{self, Limits, Millis};
use super::rules::{Block, Reason, Rules};
use super::stats::Counters;

/// The time, in milliseconds since the proxy started.
pub(super) type Clock = Arc<dyn Fn() -> Millis + Send + Sync>;
/// Where a log line goes.
pub(super) type Log = Arc<dyn Fn(String) + Send + Sync>;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Answer = Response<UnsyncBoxBody<Bytes, BoxError>>;

/// How long a connection the proxy has answered on is kept to take what
/// the client is still sending, and how much of it.
const LINGER: Duration = Duration::from_secs(1);
const LINGER_BYTES: usize = 256 * 1024;
/// The largest head the app's answer may have, and how much of an answer
/// hyper reads ahead of the client taking it.
const UPSTREAM_BUFFER: usize = 64 * 1024;
/// How much is read from a client at a time.
const READ: usize = 8192;

static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
static X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// What every connection of one proxy shares.
pub(super) struct Shared {
    pub(super) config: WafConfig,
    pub(super) rules: Rules,
    limits: Mutex<Limits>,
    pub(super) counters: Counters,
    clock: Clock,
    log: Log,
    /// How long a client has for a head, and may stall after it.
    pub(super) client_wait: Duration,
    /// How long a request's body may take, the time the proxy waits on
    /// the app for not counted ([`BodyTime`]).
    pub(super) body_wait: Duration,
    /// How long the app has to take a connection and to start answering.
    pub(super) upstream_wait: Duration,
    /// Whether the app did not answer the last request sent to it, so that
    /// it is said when that changes and not for every request.
    upstream_down: AtomicBool,
    /// When this was made: what [`Judged::progress`] counts from.
    started: Instant,
}

impl Shared {
    pub(super) fn new(config: WafConfig, clock: Clock, log: Log) -> Self {
        Self {
            rules: Rules::new(&config),
            limits: Mutex::new(Limits::new(&config, limits::TRACKED)),
            counters: Counters::default(),
            clock,
            log,
            client_wait: Duration::from_secs(config.header_timeout_secs.into()),
            body_wait: Duration::from_secs(config.body_timeout_secs.into()),
            upstream_wait: Duration::from_secs(config.upstream_timeout_secs.into()),
            upstream_down: AtomicBool::new(false),
            started: Instant::now(),
            config,
        }
    }

    /// What is remembered about each address. A panic while it was held
    /// leaves counts, not something half-written, so it is used all the
    /// same.
    pub(super) fn limits(&self) -> MutexGuard<'_, Limits> {
        self.limits.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn now(&self) -> Millis {
        (self.clock)()
    }

    pub(super) fn say(&self, line: String) {
        (self.log)(line);
    }

    /// Counts a refusal, says it, and holds it against the address.
    fn blocked(&self, block: &Block, peer: IpAddr, method: &str, target: &str) {
        self.counters.block(block.reason);
        self.say(format!(
            "blocked reason={} status={} peer={peer} method={} path=\"{}\" detail=\"{}\"",
            block.reason.name(),
            block.status,
            escape(method, 16),
            escape(target, 200),
            block.detail
        ));
        if !block.reason.is_violation() {
            return;
        }
        let key = limits::key(peer);
        let banned = self.limits().violation(key, self.now());
        if banned && let Some(ban) = self.config.ban {
            self.say(format!(
                "banned address={key}{} seconds={} after={} blocked requests within {} seconds",
                if key.is_ipv6() { "/64" } else { "" },
                ban.for_secs,
                ban.after,
                ban.window_secs
            ));
        }
    }

    /// The app did not answer: counted, and said when it is news.
    fn upstream_failed(&self, status: u16) {
        self.counters.upstream_error();
        if !self.upstream_down.swap(true, Ordering::Relaxed) {
            self.say(format!(
                "upstream {} is not answering: {status} to the client",
                self.config.upstream
            ));
        }
    }

    /// The app answered: counted, and said when it had not been.
    fn upstream_answered(&self) {
        self.counters.forwarded();
        if self.upstream_down.swap(false, Ordering::Relaxed) {
            self.say(format!(
                "upstream {} is answering again",
                self.config.upstream
            ));
        }
    }
}

/// At most `most` bytes of `text` for a log line. A byte that is not
/// printable ASCII, a quote and a backslash are written as `\xNN`, so that
/// a request cannot start a log line of its own or end the quotes it is
/// put in; what is cut is marked with `...`.
pub(super) fn escape(text: &str, most: usize) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(text.len().min(most) + 3);
    for byte in text.bytes().take(most) {
        if matches!(byte, b' '..=b'~') && byte != b'"' && byte != b'\\' {
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

/// A client's connection and what has been read from it and not yet used:
/// never more than `max_header_bytes`.
pub(super) struct Wire {
    stream: TcpStream,
    unread: Vec<u8>,
}

/// How reading a head ended when it did not end with one.
enum End {
    /// Nothing to answer: the client sent nothing, or left, or the proxy
    /// is stopping.
    Quiet,
    /// Answer with this status, and why.
    Refuse(u16, &'static str),
}

/// Reads until `wire.unread` starts with one whole head, and says how long
/// it is. A client that connects and says nothing for `client_wait` is
/// closed without a word, as one between two requests is; one that starts
/// a head has `client_wait` from its first byte to finish it.
async fn read_head(
    shared: &Shared,
    wire: &mut Wire,
    stopping: &mut watch::Receiver<bool>,
) -> Result<usize, End> {
    let most = usize::try_from(shared.config.max_header_bytes).unwrap_or(usize::MAX);
    let mut deadline = Instant::now() + shared.client_wait;
    let mut looked = 0;
    let mut scratch = [0_u8; 4096];
    loop {
        if !head::plausible(&wire.unread) {
            return Err(End::Refuse(400, "not an HTTP request"));
        }
        if let Some(end) = head::end(&wire.unread, looked) {
            return Ok(end);
        }
        looked = wire.unread.len().saturating_sub(3);
        let room = most.saturating_sub(wire.unread.len()).min(scratch.len());
        let Some(into) = scratch.get_mut(..room).filter(|into| !into.is_empty()) else {
            return Err(End::Refuse(431, "the head is over max_header_bytes"));
        };
        let idle = wire.unread.is_empty();
        if idle && *stopping.borrow() {
            return Err(End::Quiet);
        }
        let got = tokio::select! {
            biased;
            got = wire.stream.read(into) => got,
            () = tokio::time::sleep_until(deadline) => {
                return Err(if idle {
                    End::Quiet
                } else {
                    End::Refuse(408, "the head was not sent in time")
                });
            }
            _ = stopping.changed(), if idle => return Err(End::Quiet),
        };
        match got {
            Ok(0) if idle => return Err(End::Quiet),
            Ok(0) => return Err(End::Refuse(400, "the connection ended inside the head")),
            Ok(n) => {
                if idle {
                    deadline = Instant::now() + shared.client_wait;
                }
                wire.unread
                    .extend_from_slice(scratch.get(..n).unwrap_or_default());
            }
            Err(_) => return Err(End::Quiet),
        }
    }
}

/// The answer the proxy writes itself, before hyper is involved: short,
/// and the last on its connection.
fn canned(status: u16, extra: &str, head_only: bool) -> String {
    let reason = StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("Error");
    let body = format!("{status} {reason}\n");
    let mut text = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain; charset=utf-8\r\n\
         content-length: {}\r\nconnection: close\r\n{extra}\r\n",
        body.len()
    );
    if !head_only {
        text.push_str(&body);
    }
    text
}

/// Ends a connection the proxy has answered on. A socket closed with
/// unread input resets the connection, and a reset can take the answer
/// with it: so the sending side is closed first, and what the client is
/// still sending is taken for a moment and thrown away.
async fn linger(stream: &mut TcpStream) {
    let _ = stream.shutdown().await;
    let drain = async {
        let mut scratch = [0_u8; 4096];
        let mut left = LINGER_BYTES;
        while left > 0 {
            match stream.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(n) => left = left.saturating_sub(n),
            }
        }
    };
    let _ = tokio::time::timeout(LINGER, drain).await;
}

/// Answers a request the rules refuse, and ends its connection.
async fn refuse(
    shared: &Shared,
    wire: &mut Wire,
    peer: IpAddr,
    block: &Block,
    method: &str,
    target: &str,
) {
    use std::fmt::Write as _;

    shared.blocked(block, peer, method, target);
    let mut extra = String::new();
    if block.reason == Reason::Method {
        let _ = write!(extra, "allow: {}\r\n", shared.rules.allowed_methods());
    }
    if let Some(seconds) = block.retry_after {
        let _ = write!(extra, "retry-after: {seconds}\r\n");
    }
    let text = canned(block.status, &extra, method == "HEAD");
    let written =
        tokio::time::timeout(shared.client_wait, wire.stream.write_all(text.as_bytes())).await;
    if matches!(written, Ok(Ok(()))) {
        linger(&mut wire.stream).await;
    }
}

/// The rules in their order, for a head that could be read: the method
/// and the target ([`Rules::judge`]), a change of protocol, the address's
/// rate, the body's length when the head says it.
fn verdict(shared: &Shared, head: &Head, key: IpAddr) -> Result<(), Block> {
    shared.rules.judge(&head.method, &head.target)?;
    if head.upgrade {
        return Err(Block::new(
            Reason::Upgrade,
            501,
            "a change of protocol is not passed on",
        ));
    }
    if let Err(seconds) = shared.limits().take(key, shared.now()) {
        return Err(Block {
            retry_after: Some(seconds),
            ..Block::new(Reason::Rate, 429, "over the address's rate")
        });
    }
    if let Framing::Length(said) = head.framing
        && said > shared.config.max_body_bytes
    {
        return Err(Block::new(
            Reason::Body,
            413,
            "Content-Length is over max_body_bytes",
        ));
    }
    Ok(())
}

/// Serves one client connection until it ends: a request at a time, each
/// read and judged afresh.
pub(super) async fn serve(
    shared: Arc<Shared>,
    stream: TcpStream,
    peer: IpAddr,
    mut stopping: watch::Receiver<bool>,
) {
    let _ = stream.set_nodelay(true);
    let peer = peer.to_canonical();
    let key = limits::key(peer);
    let mut wire = Wire {
        stream,
        unread: Vec::new(),
    };
    loop {
        let len = match read_head(&shared, &mut wire, &mut stopping).await {
            Ok(len) => len,
            Err(End::Quiet) => return,
            Err(End::Refuse(status, why)) => {
                shared.counters.request();
                let block = Block::new(Reason::Malformed, status, why);
                refuse(&shared, &mut wire, peer, &block, "-", "-").await;
                return;
            }
        };
        // Banned since this connection was taken: closed unanswered, as a
        // new connection of its address is, and counted with those, not
        // among the requests.
        if shared.limits().is_banned(key, shared.now()) {
            shared.counters.block(Reason::Banned);
            return;
        }
        shared.counters.request();
        let head = match head::parse(wire.unread.get(..len).unwrap_or_default()) {
            Ok(head) => head,
            Err(fault) => {
                let block = Block::new(Reason::Malformed, fault.status, fault.why);
                let (method, target) = fault
                    .line
                    .unwrap_or_else(|| ("-".to_owned(), "-".to_owned()));
                refuse(&shared, &mut wire, peer, &block, &method, &target).await;
                return;
            }
        };
        if let Err(block) = verdict(&shared, &head, key) {
            refuse(&shared, &mut wire, peer, &block, &head.method, &head.target).await;
            return;
        }
        match forward(&shared, wire, &head, len, peer).await {
            Some(back) if !*stopping.borrow() => wire = back,
            _ => return,
        }
    }
}

/// A request that passed the rules, as the proxy read it.
struct Judged {
    method: String,
    target: String,
    /// How its body is delimited, as its head was read.
    framing: Framing,
    peer: IpAddr,
    /// Whether its body went over `max_body_bytes` on the way to the app.
    over_limit: AtomicBool,
    /// Whether its body could not be read from the client.
    unreadable: AtomicBool,
    /// Whether its body was still arriving when its time
    /// ([`BodyTime`]) came to `body_timeout_secs`.
    late: AtomicBool,
    /// Whether it was refused after all, once hyper had it: its connection
    /// then ends with the answer, as after any refusal.
    refused: AtomicBool,
    /// Whether all of it has been handed to the app.
    sent: AtomicBool,
    /// Whether the app is waiting for a piece of it that the client has
    /// not sent yet.
    awaited: AtomicBool,
    /// When the last piece of it was handed to the app, in nanoseconds
    /// since [`Shared::started`] ([`stamp`]): the time itself, not
    /// rounded, so that two pieces are never one and the time the app
    /// has from it ([`Judged::answer_due`]) is never short.
    progress: AtomicU64,
}

/// The time a request's body has taken, as `body_timeout_secs` counts
/// it: the time in which the app could be handed more of the body and the
/// proxy has none to hand. That is the whole time the body takes, from
/// the first look for a piece of it that finds none, less the time the
/// proxy waits on the app.
///
/// hyper asks the [`Guard`] for a piece of the body whenever it can take
/// one on its way to the app, and not while it is still writing out what
/// it was handed. So the time runs from a look that finds no piece until
/// a piece is there, and stands still from a piece handed over until the
/// next look. While it runs, the client has not sent the piece, or the
/// piece has arrived and the proxy has not read it yet: the proxy's own
/// time to read counts, so that a client that keeps the proxy busy, a
/// byte at a time as fast as they are read, uses its time up as one that
/// sends a byte a second does. While it stands still, the app is what is
/// waited for: a slow app does not cost its client the request.
struct BodyTime {
    /// How long a body may take: `body_timeout_secs`.
    limit: Duration,
    /// How much of it is used, the stretch that runs now left out.
    used: Duration,
    /// Since when it runs: the look that found no piece, when no piece
    /// has been there since.
    wanting: Option<Instant>,
}

impl BodyTime {
    fn new(limit: Duration) -> Self {
        Self {
            limit,
            used: Duration::ZERO,
            wanting: None,
        }
    }

    /// A look for a piece found none: the time runs, from the first such
    /// look since a piece was there, and this is what is left of it, or
    /// none when it is used up. A part of a millisecond left is still
    /// time: the body is late only once all of its time has passed, so
    /// that it is never called late before `body_timeout_secs`.
    fn wanted(&mut self, now: Instant) -> Option<Duration> {
        let since = *self.wanting.get_or_insert(now);
        let left = self
            .limit
            .saturating_sub(self.used + now.saturating_duration_since(since));
        (!left.is_zero()).then_some(left)
    }

    /// A look for a piece found one, or the body's end: the time stands
    /// still until the next look that finds none.
    fn given(&mut self, now: Instant) {
        if let Some(since) = self.wanting.take() {
            self.used += now.saturating_duration_since(since);
        }
    }
}

/// The moment `at` as a [`Judged`] keeps it: in nanoseconds since `since`,
/// which is as fine as the clock tells it. Read back as `since` and that
/// many nanoseconds, it is `at` again, and never a moment before it.
fn stamp(since: Instant, at: Instant) -> u64 {
    u64::try_from(at.saturating_duration_since(since).as_nanos()).unwrap_or(u64::MAX)
}

impl Judged {
    /// A piece of it was handed to the app at `at`: the last, when `all`.
    /// `since` is when the proxy started ([`Shared::started`]).
    fn progressed(&self, since: Instant, at: Instant, all: bool) {
        self.progress.store(stamp(since, at), Ordering::Relaxed);
        if all {
            self.sent.store(true, Ordering::Relaxed);
        }
    }

    /// The last piece of it handed to the app, as it is kept, and when
    /// the app is to have started answering by: `wait` after that piece,
    /// and never sooner. `since` is when the proxy started.
    fn answer_due(&self, since: Instant, wait: Duration) -> (u64, Instant) {
        let last = self.progress.load(Ordering::Relaxed);
        (last, since + Duration::from_nanos(last) + wait)
    }
}

/// Forwards one request through hyper, and gives the connection back when
/// another request can follow on it.
async fn forward(
    shared: &Arc<Shared>,
    wire: Wire,
    head: &Head,
    len: usize,
    peer: IpAddr,
) -> Option<Wire> {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    let allowance = match head.framing {
        Framing::None => Some(len),
        Framing::Length(said) => Some(len.saturating_add(said)),
        Framing::Chunked => None,
    };
    let judged = Arc::new(Judged {
        method: head.method.clone(),
        target: head.target.clone(),
        framing: head.framing,
        peer,
        over_limit: AtomicBool::new(false),
        unreadable: AtomicBool::new(false),
        late: AtomicBool::new(false),
        refused: AtomicBool::new(false),
        sent: AtomicBool::new(false),
        awaited: AtomicBool::new(false),
        progress: AtomicU64::new(0),
    });
    // Boxed, so that the connection can be polled where it stands and the
    // socket taken back from it however it ends.
    let service = service_fn({
        let shared = Arc::clone(shared);
        let judged = Arc::clone(&judged);
        move |request| -> Pin<Box<dyn Future<Output = Result<Answer, Infallible>> + Send>> {
            Box::pin(relay(Arc::clone(&shared), Arc::clone(&judged), request))
        }
    });
    let buffer = usize::try_from(shared.config.max_header_bytes)
        .unwrap_or(READ)
        .max(READ)
        + READ;
    let mut http = hyper::server::conn::http1::Builder::new();
    http.half_close(true)
        .keep_alive(!head.close)
        .header_read_timeout(None::<Duration>)
        .max_buf_size(buffer);
    let io = ClientWire::new(wire, allowance, shared.client_wait);
    let mut connection = http.serve_connection(io, service);
    let served = std::future::poll_fn(|cx| connection.poll_without_shutdown(cx)).await;
    let parts = connection.into_parts();
    // Another request may follow only where this one is known to have
    // ended: hyper took every byte of it, and none besides.
    let whole = parts.io.left == Some(0) && parts.read_buf.is_empty();
    let mut wire = parts.io.into_wire();
    let refused = judged.refused.load(Ordering::Relaxed);
    match served {
        Ok(()) if whole && !head.close && !refused => return Some(wire),
        Ok(()) => {}
        // hyper answers a head it cannot read with 400 itself. One that
        // was read here and not there is malformed all the same.
        Err(error) if error.is_parse() => {
            let block = Block::new(Reason::Malformed, 400, "hyper could not read the head");
            shared.blocked(&block, peer, &head.method, &head.target);
        }
        // The client left, or stalled.
        Err(_) => return None,
    }
    linger(&mut wire.stream).await;
    None
}

/// Why a request that passed the rules was not answered by the app.
enum Failure {
    /// It turned out to break a rule after all.
    Block(Block),
    /// The app did not answer: 502 or 504.
    Gateway(u16),
}

/// hyper's service for the one request of a connection: sends it to the
/// app and gives back the app's answer, or the proxy's own.
async fn relay(
    shared: Arc<Shared>,
    judged: Arc<Judged>,
    request: Request<Incoming>,
) -> Result<Answer, Infallible> {
    Ok(match pass(&shared, &judged, request).await {
        Ok(answer) => {
            shared.upstream_answered();
            answer
        }
        Err(Failure::Block(block)) => {
            judged.refused.store(true, Ordering::Relaxed);
            shared.blocked(&block, judged.peer, &judged.method, &judged.target);
            let mut answer = plain(block.status);
            answer
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
            answer
        }
        Err(Failure::Gateway(status)) => {
            shared.upstream_failed(status);
            plain(status)
        }
    })
}

/// A short answer of the proxy's own, written by hyper.
fn plain(status: u16) -> Answer {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let text = format!(
        "{} {}\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Error")
    );
    let body = Full::new(Bytes::from(text))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut answer = Response::new(body);
    *answer.status_mut() = status;
    answer.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    answer
}

/// Whether a header is for one connection and not for the request: the
/// ones HTTP names, and `Proxy-Connection`, which some clients send.
fn hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// The headers a `Connection` header names as its own. `Host` and
/// `Content-Length` are never among them: a client cannot have the proxy
/// take off what the app reads the request by.
fn named_by_connection(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty() && name != "host" && name != "content-length")
        .collect()
}

/// Whether a header the client sent is one the proxy speaks for itself,
/// so that the client's own is not passed on: where the request came from
/// and how (`Forwarded`, `X-Real-IP`, `X-Forwarded-Proto`). The client's
/// `X-Forwarded-For` is kept, with the proxy's word added after it.
fn spoken_by_the_proxy(name: &HeaderName) -> bool {
    *name == header::FORWARDED || *name == X_REAL_IP || *name == X_FORWARDED_PROTO
}

/// The headers the app is sent: the client's, without
///
/// - those of its connection to the proxy, and `Expect`, which the proxy
///   has answered;
/// - any whose name has an underscore: an app server that reads `_` as `-`
///   (as CGI and WSGI do) would take `Content_Length` or
///   `X_Forwarded_For` for the header the proxy judged or wrote;
/// - `Forwarded`, `X-Real-IP` and `X-Forwarded-Proto` as the client sent
///   them.
///
/// And with the proxy's own: the client's address as `X-Real-IP` and added
/// to the end of `X-Forwarded-For`, `X-Forwarded-Proto`, and
/// `Content-Length` as the number the proxy read, whatever digits the
/// client wrote it in.
fn upstream_headers(from: HeaderMap, judged: &Judged, upstream: std::net::SocketAddr) -> HeaderMap {
    let named = named_by_connection(&from);
    let mut headers = HeaderMap::with_capacity(from.len() + 2);
    let mut forwarded_for = Vec::new();
    let mut current = None;
    for (name, value) in from {
        // A repeated header comes without its name.
        if name.is_some() {
            current = name;
        }
        let Some(name) = &current else { continue };
        if *name == X_FORWARDED_FOR {
            if !forwarded_for.is_empty() {
                forwarded_for.extend_from_slice(b", ");
            }
            forwarded_for.extend_from_slice(value.as_bytes());
        } else if !(hop_by_hop(name)
            || named.iter().any(|n| n == name.as_str())
            || *name == header::EXPECT
            || spoken_by_the_proxy(name)
            || name.as_str().contains('_'))
        {
            headers.append(name.clone(), value);
        }
    }
    let peer = judged.peer.to_string();
    if !forwarded_for.is_empty() {
        forwarded_for.extend_from_slice(b", ");
    }
    forwarded_for.extend_from_slice(peer.as_bytes());
    if let Ok(value) =
        HeaderValue::from_bytes(&forwarded_for).or_else(|_| HeaderValue::from_str(&peer))
    {
        headers.insert(X_FORWARDED_FOR.clone(), value);
    }
    if let Ok(value) = HeaderValue::from_str(&peer) {
        headers.insert(X_REAL_IP.clone(), value);
    }
    headers.insert(X_FORWARDED_PROTO.clone(), HeaderValue::from_static("http"));
    match judged.framing {
        // Said outright, or hyper would send a GET's body as none.
        Framing::Chunked => {
            headers.insert(
                header::TRANSFER_ENCODING,
                HeaderValue::from_static("chunked"),
            );
        }
        // The number that was read, not the text it was read from: `0010`
        // is ten here, and must not be something else to the app.
        Framing::Length(length) => {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
        }
        Framing::None => {}
    }
    // HTTP/1.0 may come without one, and the app is spoken to in 1.1.
    if !headers.contains_key(header::HOST)
        && let Ok(value) = HeaderValue::from_str(&upstream.to_string())
    {
        headers.insert(header::HOST, value);
    }
    headers
}

/// Sends a judged request to the app and reads the head of its answer.
async fn pass(
    shared: &Shared,
    judged: &Arc<Judged>,
    request: Request<Incoming>,
) -> Result<Answer, Failure> {
    // What hyper read must be what was judged: the same method, and the
    // same target byte for byte. It is, for every head this proxy lets
    // through; were it ever not, the request stops here.
    let same = request.method().as_str() == judged.method
        && request.uri().scheme().is_none()
        && request.uri().authority().is_none()
        && request
            .uri()
            .path_and_query()
            .is_some_and(|target| target.as_str() == judged.target);
    if !same {
        return Err(Failure::Block(Block::new(
            Reason::Malformed,
            400,
            "hyper read another request than the one judged",
        )));
    }
    let wait = shared.upstream_wait;
    let stream = match tokio::time::timeout(wait, TcpStream::connect(shared.config.upstream)).await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return Err(Failure::Gateway(502)),
        Err(_) => return Err(Failure::Gateway(504)),
    };
    let _ = stream.set_nodelay(true);
    let mut http = hyper::client::conn::http1::Builder::new();
    // The buffer's size is where hyper stops reading ahead, not what it
    // refuses; the head's is.
    http.max_buf_size(UPSTREAM_BUFFER)
        .max_header_size(UPSTREAM_BUFFER);
    let Ok((sender, connection)) = http.handshake::<_, Guard>(TokioIo::new(stream)).await else {
        return Err(Failure::Gateway(502));
    };
    // The connection to the app is this request's alone, and ends with it.
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut app = AppLink {
        sender,
        task: task.abort_handle(),
    };

    let (parts, body) = request.into_parts();
    let mut forwarded = Request::new(Guard {
        body,
        left: shared.config.max_body_bytes,
        time: BodyTime::new(shared.body_wait),
        due: Box::pin(tokio::time::sleep(shared.body_wait)),
        judged: Arc::clone(judged),
        since: shared.started,
    });
    *forwarded.method_mut() = parts.method;
    *forwarded.uri_mut() = parts.uri;
    *forwarded.version_mut() = Version::HTTP_11;
    *forwarded.headers_mut() = upstream_headers(parts.headers, judged, shared.config.upstream);

    // The app has `upstream_wait` to start answering, counted from the
    // last piece of the request it was handed. Where the app is taking the
    // request and the client is not sending it, the time is the client's,
    // and the limit that applies is the one on the socket it sends from.
    let whole = forwarded.body().is_end_stream();
    judged.progressed(shared.started, Instant::now(), whole);
    let sending = app.sender.send_request(forwarded);
    tokio::pin!(sending);
    let (mut last, mut deadline) = judged.answer_due(shared.started, wait);
    let answered = loop {
        tokio::select! {
            biased;
            answered = &mut sending => break answered,
            () = tokio::time::sleep_until(deadline) => {}
        }
        // A piece handed over since the time was set moves it on: the
        // app has its whole time from the last one.
        let (now, due) = judged.answer_due(shared.started, wait);
        if now != last {
            (last, deadline) = (now, due);
        } else if !judged.sent.load(Ordering::Relaxed) && judged.awaited.load(Ordering::Relaxed) {
            deadline = Instant::now() + wait;
        } else {
            return Err(Failure::Gateway(504));
        }
    };
    match answered {
        Ok(answer) if answer.status() != StatusCode::SWITCHING_PROTOCOLS => {
            Ok(returned(answer, wait, app))
        }
        Err(_) if judged.over_limit.load(Ordering::Relaxed) => Err(Failure::Block(Block::new(
            Reason::Body,
            413,
            "the body went over max_body_bytes",
        ))),
        Err(_) if judged.late.load(Ordering::Relaxed) => Err(Failure::Block(Block::new(
            Reason::BodyTimeout,
            408,
            "the body had not arrived within body_timeout_secs",
        ))),
        Err(_) if judged.unreadable.load(Ordering::Relaxed) => Err(Failure::Block(Block::new(
            Reason::Malformed,
            400,
            "the body could not be read",
        ))),
        // No answer, or one that changes protocol, which the proxy did
        // not ask for.
        Ok(_) | Err(_) => Err(Failure::Gateway(502)),
    }
}

/// The app's answer as the client is given it: without the headers of the
/// app's connection to the proxy, and with its body paced.
fn returned(answer: Response<Incoming>, wait: Duration, app: AppLink) -> Answer {
    let (mut parts, body) = answer.into_parts();
    for name in named_by_connection(&parts.headers) {
        parts.headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        parts.headers.remove(name);
    }
    parts.headers.remove("keep-alive");
    parts.headers.remove("proxy-connection");
    // hyper writes the version the client spoke.
    parts.version = Version::HTTP_11;
    let body = Paced {
        body,
        wait,
        quiet: Box::pin(tokio::time::sleep(wait)),
        asked: false,
        _app: app,
    };
    Response::from_parts(parts, body.boxed_unsync())
}

/// The connection to the app that one request has, and the task that
/// drives it. Dropped, it ends that task where it stands, and with it the
/// connection and what it held of the client's request.
///
/// hyper would end the connection by itself once nothing waits on it, but
/// only after writing out what it has buffered: an app that has stopped
/// reading would keep it, and the client's connection behind it, for
/// ever.
struct AppLink {
    sender: hyper::client::conn::http1::SendRequest<Guard>,
    task: tokio::task::AbortHandle,
}

impl Drop for AppLink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A request's body on its way to the app: counted against
/// `max_body_bytes`, and ended with an error, which ends the request to
/// the app unfinished, when it goes over, or when it is still coming once
/// its time is used up ([`BodyTime`]): however the client sends it, a
/// byte a second or a byte at a time as fast as the proxy reads them. An
/// app that is slow to take a body does not get its client refused: the
/// time the proxy waits on the app is not the body's. Its trailers are
/// not passed on.
struct Guard {
    body: Incoming,
    left: u64,
    /// How long it has taken, against `body_timeout_secs`.
    time: BodyTime,
    /// Done when the body's time is up, if no piece comes before: set,
    /// each time the body is asked for and has no piece ready, to what is
    /// then left of its time.
    due: Pin<Box<Sleep>>,
    judged: Arc<Judged>,
    since: Instant,
}

impl Body for Guard {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        loop {
            let polled = Pin::new(&mut self.body).poll_frame(cx);
            self.judged
                .awaited
                .store(polled.is_pending(), Ordering::Relaxed);
            let now = Instant::now();
            if polled.is_ready() {
                self.time.given(now);
            }
            let frame = match polled {
                Poll::Ready(None) => {
                    self.judged.progressed(self.since, now, true);
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Ok(frame))) => frame,
                Poll::Ready(Some(Err(error))) => {
                    self.judged.unreadable.store(true, Ordering::Relaxed);
                    return Poll::Ready(Some(Err(error.into())));
                }
                // No piece is ready: the body's time runs. It is waited
                // for until that time is used up, and no longer, however
                // steadily the pieces come and however fast. Woken when
                // what is left of the time has passed, which is when it
                // is up if no piece comes meanwhile, and looked at again
                // then. The timer is never done before the moment it was
                // set to (it goes by whole milliseconds, rounded up), so
                // the look after it finds the time used up.
                Poll::Pending => {
                    let Some(left) = self.time.wanted(now) else {
                        self.judged.late.store(true, Ordering::Relaxed);
                        return Poll::Ready(Some(Err("the request body took too long".into())));
                    };
                    self.due.as_mut().reset(now + left);
                    ready!(self.due.as_mut().poll(cx));
                    continue;
                }
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
            if size > self.left {
                self.judged.over_limit.store(true, Ordering::Relaxed);
                return Poll::Ready(Some(Err("the request body is over the limit".into())));
            }
            self.left -= size;
            self.judged
                .progressed(self.since, now, self.body.is_end_stream());
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// The app's answer on its way to the client: ended with an error, which
/// ends the client's connection, when the app pauses longer than `wait`
/// inside it. The time counts from when the client's side asks for more
/// and the app has none: while the client is slow to take what there is,
/// nothing is asked of the app.
struct Paced {
    body: Incoming,
    wait: Duration,
    quiet: Pin<Box<Sleep>>,
    /// Whether `quiet` is running: the app has been asked and has not
    /// answered.
    asked: bool,
    /// The connection to the app, held until the answer is through.
    _app: AppLink,
}

impl Body for Paced {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match Pin::new(&mut self.body).poll_frame(cx) {
            Poll::Ready(frame) => {
                self.asked = false;
                Poll::Ready(frame.map(|frame| frame.map_err(Into::into)))
            }
            Poll::Pending => {
                if !self.asked {
                    self.asked = true;
                    let until = Instant::now() + self.wait;
                    self.quiet.as_mut().reset(until);
                }
                ready!(self.quiet.as_mut().poll(cx));
                Poll::Ready(Some(Err("the app stopped inside its answer".into())))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// What hyper reads one request from and writes its answer to: a
/// [`Wire`], cut to that request.
///
/// It gives hyper `left` bytes (what was read ahead first, then the
/// socket) and then the end of input, whatever the client goes on to
/// send; with no `left`, a chunked body, it gives everything. A read that
/// waits on the client longer than `wait`, and a write the client does not
/// take for as long, fail: a client cannot hold a connection by stalling.
struct ClientWire {
    wire: Wire,
    /// How much of `wire.unread` hyper has taken.
    taken: usize,
    left: Option<u64>,
    wait: Duration,
    reading: Option<Pin<Box<Sleep>>>,
    writing: Option<Pin<Box<Sleep>>>,
}

impl ClientWire {
    fn new(wire: Wire, left: Option<u64>, wait: Duration) -> Self {
        Self {
            wire,
            taken: 0,
            left,
            wait,
            reading: None,
            writing: None,
        }
    }

    /// The connection again, with what hyper did not take still unread.
    fn into_wire(mut self) -> Wire {
        let taken = self.taken.min(self.wire.unread.len());
        self.wire.unread.drain(..taken);
        self.wire
    }

    fn gave(&mut self, bytes: usize) {
        if let Some(left) = &mut self.left {
            *left = left.saturating_sub(u64::try_from(bytes).unwrap_or(u64::MAX));
        }
    }
}

/// Pending until `timer`, started now if it is not running, runs out; then
/// the error a stalled client gets.
fn stalled<T>(
    timer: &mut Option<Pin<Box<Sleep>>>,
    wait: Duration,
    cx: &mut Context<'_>,
) -> Poll<io::Result<T>> {
    let timer = timer.get_or_insert_with(|| Box::pin(tokio::time::sleep(wait)));
    ready!(timer.as_mut().poll(cx));
    Poll::Ready(Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "the client stalled",
    )))
}

impl Read for ClientWire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let allowed = this.left.map_or(usize::MAX, |left| {
            usize::try_from(left).unwrap_or(usize::MAX)
        });
        let room = buf.remaining().min(allowed).min(READ);
        if room == 0 {
            // The request's last byte has been given: the end of input.
            return Poll::Ready(Ok(()));
        }
        let ahead = this.wire.unread.get(this.taken..).unwrap_or_default();
        if !ahead.is_empty() {
            let give = ahead.get(..room).unwrap_or(ahead);
            buf.put_slice(give);
            let count = give.len();
            this.taken += count;
            this.gave(count);
            return Poll::Ready(Ok(()));
        }
        let mut scratch = [0_u8; READ];
        let mut read = ReadBuf::new(scratch.get_mut(..room).unwrap_or_default());
        match Pin::new(&mut this.wire.stream).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                this.reading = None;
                buf.put_slice(read.filled());
                let count = read.filled().len();
                this.gave(count);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => stalled(&mut this.reading, this.wait, cx),
        }
    }
}

impl Write for ClientWire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.wire.stream).poll_write(cx, buf) {
            Poll::Ready(written) => {
                this.writing = None;
                Poll::Ready(written)
            }
            Poll::Pending => stalled(&mut this.writing, this.wait, cx),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The connection is closed by `serve`, which may have another
        // request to read from it.
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use erpc_worker::waf::WafConfig;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::{BodyTime, Framing, Judged, Shared, relay};

    #[test]
    fn a_bodys_time_runs_while_a_piece_is_wanted_and_stands_still_while_the_app_has_one() {
        let secs = |seconds: u64| Some(Duration::from_secs(seconds));
        let start = tokio::time::Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let mut time = BodyTime::new(Duration::from_secs(30));
        // The first look that finds no piece starts it, and it runs on
        // while every look finds none.
        assert_eq!(time.wanted(at(0)), secs(30));
        assert_eq!(time.wanted(at(4)), secs(26));
        assert_eq!(time.wanted(at(10)), secs(20));
        // A piece is there: handed to the app, which takes a minute over
        // it before it asks again. None of that minute is the body's.
        time.given(at(12));
        assert_eq!(time.wanted(at(72)), secs(18));
        assert_eq!(time.wanted(at(80)), secs(10));
        // Pieces that are there at every look use nothing, however many
        // and however long the app takes over each.
        time.given(at(81));
        time.given(at(200));
        time.given(at(300));
        assert_eq!(time.wanted(at(400)), secs(9));
        // Pieces that keep coming, each a little after it was looked for,
        // use what they were waited for, added up.
        for step in 0..8 {
            time.wanted(at(400 + step));
            time.given(at(401 + step));
        }
        assert_eq!(time.wanted(at(408)), secs(1));
        // Used up, and no less than that.
        assert_eq!(time.wanted(at(409)), None);
        assert_eq!(time.wanted(at(900)), None);
        time.given(at(901));
        assert_eq!(time.wanted(at(902)), None);
    }

    #[test]
    fn a_body_is_late_only_once_all_of_its_time_has_passed() {
        let start = tokio::time::Instant::now();
        let at = |micros: u64| start + Duration::from_micros(micros);
        let mut time = BodyTime::new(Duration::from_secs(30));
        assert_eq!(time.wanted(at(0)), Some(Duration::from_secs(30)));
        // A millisecond left, a part of one, a microsecond, a nanosecond:
        // each is still time, which the timer waits out.
        assert_eq!(time.wanted(at(29_999_000)), Some(Duration::from_millis(1)));
        assert_eq!(
            time.wanted(at(29_999_500)),
            Some(Duration::from_micros(500))
        );
        assert_eq!(time.wanted(at(29_999_999)), Some(Duration::from_micros(1)));
        assert_eq!(
            time.wanted(start + Duration::from_nanos(29_999_999_999)),
            Some(Duration::from_nanos(1))
        );
        // All of it passed, to the nanosecond: none is left, and none
        // after that.
        assert_eq!(time.wanted(at(30_000_000)), None);
        assert_eq!(time.wanted(at(30_000_001)), None);
    }

    /// A request judged to be `method target`, with no body, of which
    /// nothing has been handed to the app yet.
    fn judged(method: &str, target: &str) -> Judged {
        Judged {
            method: method.to_owned(),
            target: target.to_owned(),
            framing: Framing::None,
            peer: IpAddr::from([127, 0, 0, 1]),
            over_limit: AtomicBool::new(false),
            unreadable: AtomicBool::new(false),
            late: AtomicBool::new(false),
            refused: AtomicBool::new(false),
            sent: AtomicBool::new(false),
            awaited: AtomicBool::new(false),
            progress: AtomicU64::new(0),
        }
    }

    #[test]
    fn the_app_has_its_whole_time_to_answer_from_the_last_piece_it_was_handed() {
        let since = tokio::time::Instant::now();
        let wait = Duration::from_millis(300);
        let request = judged("POST", "/api/x");
        let after = |nanos: u64| since + Duration::from_nanos(nanos);
        // A piece handed over part-way through a millisecond, 12.9 ms
        // after the proxy started, and at other moments, to the
        // nanosecond: the app has `wait` from that moment, and its time
        // is never up before then.
        for nanos in [
            0,
            1,
            999,
            900_000,
            999_999,
            1_000_000,
            12_900_000,
            12_999_999,
            3_600_000_000_123,
        ] {
            request.progressed(since, after(nanos), false);
            let (kept, due) = request.answer_due(since, wait);
            assert_eq!(kept, nanos);
            assert!(due >= after(nanos) + wait, "{nanos} ns: short of its time");
            assert_eq!(due, after(nanos) + wait, "{nanos} ns");
        }
        assert!(!request.sent.load(Ordering::Relaxed));
        // Two pieces within one millisecond are two pieces: the second is
        // told from the first, and the time runs from the second.
        request.progressed(since, after(12_100_000), false);
        let (first, _) = request.answer_due(since, wait);
        request.progressed(since, after(12_900_000), true);
        let (second, due) = request.answer_due(since, wait);
        assert_ne!(first, second);
        assert_eq!(due, after(12_900_000) + wait);
        assert!(request.sent.load(Ordering::Relaxed), "the last piece");
        // A moment before the proxy started is the start, not later.
        assert_eq!(super::stamp(after(5), since), 0);
    }

    /// Serves `sent` with hyper as if the proxy had judged it to be
    /// `method target`, and returns what the client is answered.
    async fn served_as(shared: &Arc<Shared>, method: &str, target: &str, sent: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let judged = Arc::new(judged(method, target));
        let shared = Arc::clone(shared);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let service =
                service_fn(move |request| relay(Arc::clone(&shared), Arc::clone(&judged), request));
            let _ = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let mut client = TcpStream::connect(address).await.expect("connect");
        client.write_all(sent.as_bytes()).await.expect("send");
        let mut answer = String::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut answer))
            .await
            .expect("an answer in time")
            .expect("read");
        answer
    }

    #[tokio::test]
    async fn a_request_hyper_reads_otherwise_than_it_was_judged_is_not_forwarded() {
        // An app that counts the connections made to it.
        let app = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the app");
        let upstream = app.local_addr().expect("address");
        let reached = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&reached);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = app.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let mut asked = [0_u8; 1024];
                let _ = stream.read(&mut asked).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        });
        let lines = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&lines);
        let config =
            WafConfig::default_for("test", "127.0.0.1:0".parse().expect("listen"), upstream);
        let shared = Arc::new(Shared::new(
            config,
            Arc::new(|| 0),
            Arc::new(move |line| log.lock().expect("log").push(line)),
        ));
        let host = "Host: a\r\nConnection: close\r\n\r\n";
        for (method, target, sent) in [
            // Another path, another query, another method, and a full
            // URL, whose path alone is the one judged.
            (
                "GET",
                "/api/judged",
                format!("GET /api/other HTTP/1.1\r\n{host}"),
            ),
            (
                "GET",
                "/api/x",
                format!("GET /api/x?admin=1 HTTP/1.1\r\n{host}"),
            ),
            (
                "GET",
                "/api/x?a=1",
                format!("GET /api/x HTTP/1.1\r\n{host}"),
            ),
            ("GET", "/api/x", format!("DELETE /api/x HTTP/1.1\r\n{host}")),
            ("GET", "/api/x", format!("GET /api/X HTTP/1.1\r\n{host}")),
            (
                "GET",
                "/api/x",
                format!("GET http://127.0.0.1/api/x HTTP/1.1\r\n{host}"),
            ),
        ] {
            let answer = served_as(&shared, method, target, &sent).await;
            assert!(
                answer.starts_with("HTTP/1.1 400 "),
                "{sent:?} -> {answer:?}"
            );
            let line = lines.lock().expect("log").pop().expect("a line");
            assert!(
                line.contains("detail=\"hyper read another request than the one judged\""),
                "{line}"
            );
        }
        assert_eq!(reached.load(Ordering::SeqCst), 0, "none reached the app");
        // The one judged is forwarded.
        let sent = format!("GET /api/x?a=1 HTTP/1.1\r\n{host}");
        let answer = served_as(&shared, "GET", "/api/x?a=1", &sent).await;
        assert!(answer.starts_with("HTTP/1.1 200 "), "{answer}");
        assert!(answer.ends_with("ok"), "{answer}");
        assert_eq!(reached.load(Ordering::SeqCst), 1);
        let counts = shared.counters.snapshot("", 0);
        assert_eq!((counts.blocked.malformed, counts.forwarded), (6, 1));
    }
}
