// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The proxy over real sockets: a client on one side, a small app on the
//! other, both on loopback. What the app was asked is counted by the app
//! itself, so "never reached the app" is the app's word and not the
//! proxy's.

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use erpc_worker::waf::{Ban, Rate, WafConfig, WafStats};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::Proxy;
use super::proxy::{Shared, escape};

/// A secret no log line may hold.
const SECRET: &str = "s3cr3t-T0KEN-do-not-log";
/// An answer larger than the system will buffer for a client that does not
/// read it.
const HUGE: usize = 48 * 1024 * 1024;

/// One request, as the app got it.
#[derive(Debug, Clone)]
struct Asked {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Whether its body arrived whole.
    whole: bool,
}

impl Asked {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A small app on loopback that remembers what it was asked.
struct App {
    address: SocketAddr,
    /// Requests whose head arrived.
    begun: Arc<AtomicUsize>,
    /// Requests it read to the end of, or until they broke off.
    asked: Arc<Mutex<Vec<Asked>>>,
}

impl App {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the app");
        let address = listener.local_addr().expect("the app's address");
        let begun = Arc::new(AtomicUsize::new(0));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (count, record) = (Arc::clone(&begun), Arc::clone(&asked));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (count, record) = (Arc::clone(&count), Arc::clone(&record));
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        answer(Arc::clone(&count), Arc::clone(&record), request)
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            address,
            begun,
            asked,
        }
    }

    fn begun(&self) -> usize {
        self.begun.load(Ordering::SeqCst)
    }

    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().expect("asked").clone()
    }

    /// Waits until the app has finished with `count` requests.
    async fn finished(&self, count: usize) -> Vec<Asked> {
        let started = Instant::now();
        loop {
            let asked = self.asked();
            if asked.len() >= count {
                return asked;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the app finished {} of {count} requests",
                asked.len()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// What the app answers: by path, so a test picks its behaviour.
async fn answer(
    begun: Arc<AtomicUsize>,
    asked: Arc<Mutex<Vec<Asked>>>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    begun.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    if path == "/api/early" {
        // Answers without reading what it was sent.
        return Ok(Response::new(Full::new(Bytes::from("early\n"))));
    }
    let (body, whole) = match body.collect().await {
        Ok(collected) => (collected.to_bytes().to_vec(), true),
        Err(_) => (Vec::new(), false),
    };
    asked.lock().expect("asked").push(Asked {
        method: parts.method.to_string(),
        target: parts.uri.to_string(),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: body.clone(),
        whole,
    });
    let mut response = match path.as_str() {
        "/api/slow" => {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Response::new(Full::new(Bytes::from("slow\n")))
        }
        "/api/never" => std::future::pending().await,
        "/api/big" => Response::new(Full::new(Bytes::from(vec![b'x'; 2 * 1024 * 1024]))),
        "/api/huge" => Response::new(Full::new(Bytes::from(vec![b'x'; HUGE]))),
        "/api/echo" => Response::new(Full::new(Bytes::from(body))),
        "/api/missing" => {
            let mut response = Response::new(Full::new(Bytes::from("no such thing\n")));
            *response.status_mut() = hyper::StatusCode::NOT_FOUND;
            response
        }
        _ => Response::new(Full::new(Bytes::from("hello from the app\n"))),
    };
    let headers = response.headers_mut();
    headers.insert("x-app", "yes".parse().expect("value"));
    if path == "/api/hop" {
        headers.insert("connection", "x-internal".parse().expect("value"));
        headers.insert("x-internal", "1".parse().expect("value"));
        headers.insert("keep-alive", "timeout=5".parse().expect("value"));
    }
    Ok(response)
}

/// What a test may change before the proxy starts.
struct Setup {
    config: WafConfig,
    client_wait: Duration,
    body_wait: Duration,
    upstream_wait: Duration,
    /// How many connections it holds at once.
    most: u32,
}

/// A proxy in front of an app, with a clock the test moves and a log the
/// test reads.
struct Waf {
    address: SocketAddr,
    shared: Arc<Shared>,
    clock: Arc<AtomicU64>,
    lines: Arc<Mutex<Vec<String>>>,
    stop: Option<oneshot::Sender<()>>,
    done: Option<JoinHandle<()>>,
    stats: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Waf {
    /// A proxy with no rate, ban or connection limit, and every path
    /// forwarded, unless `tune` says otherwise.
    async fn start(app: SocketAddr, tune: impl FnOnce(&mut Setup)) -> Self {
        let dir = tempfile::tempdir().expect("tmp");
        let stats = dir.path().join("stats.json");
        let mut config =
            WafConfig::default_for("test", "127.0.0.1:0".parse().expect("listen"), app);
        config.stats_path = stats.to_str().expect("a UTF-8 path").to_owned();
        config.rate = None;
        config.ban = None;
        config.max_connections_per_address = None;
        let mut setup = Setup {
            config,
            client_wait: Duration::from_secs(3),
            body_wait: Duration::from_secs(3),
            upstream_wait: Duration::from_secs(3),
            most: erpc_worker::waf::MAX_CONNECTIONS,
        };
        tune(&mut setup);
        let clock = Arc::new(AtomicU64::new(0));
        let lines = Arc::new(Mutex::new(Vec::new()));
        let (time, log) = (Arc::clone(&clock), Arc::clone(&lines));
        let mut shared = Shared::new(
            setup.config,
            Arc::new(move || time.load(Ordering::SeqCst)),
            Arc::new(move |line| log.lock().expect("log").push(line)),
        );
        shared.client_wait = setup.client_wait;
        shared.body_wait = setup.body_wait;
        shared.upstream_wait = setup.upstream_wait;
        let mut proxy = Proxy::bind(shared).await.expect("bind the proxy");
        proxy.serving.most = setup.most;
        let address = proxy.address().expect("the proxy's address");
        let shared = Arc::clone(&proxy.serving.shared);
        let (stop, stopped) = oneshot::channel::<()>();
        let done = tokio::spawn(proxy.run(async move {
            let _ = stopped.await;
        }));
        Self {
            address,
            shared,
            clock,
            lines,
            stop: Some(stop),
            done: Some(done),
            stats,
            _dir: dir,
        }
    }

    fn lines(&self) -> Vec<String> {
        self.lines.lock().expect("log").clone()
    }

    fn counts(&self) -> WafStats {
        self.shared.counters.snapshot("", 0)
    }

    /// Tells the proxy to stop, waits until it has, and reads the stats
    /// file it leaves.
    async fn stop(&mut self) -> WafStats {
        self.stop
            .take()
            .expect("stopped once")
            .send(())
            .expect("still running");
        tokio::time::timeout(Duration::from_secs(15), self.done.take().expect("once"))
            .await
            .expect("the proxy stops")
            .expect("and does not panic");
        let text = std::fs::read_to_string(&self.stats).expect("the stats file");
        WafStats::parse(&text).expect("stats")
    }

    /// Sends `request` on a connection of its own and returns everything
    /// answered until the proxy closes it.
    async fn ask(&self, request: impl AsRef<[u8]>) -> String {
        let mut stream = TcpStream::connect(self.address).await.expect("connect");
        stream.write_all(request.as_ref()).await.expect("send");
        rest(&mut stream).await
    }
}

/// Everything a connection still says, until it is closed.
async fn rest(stream: &mut TcpStream) -> String {
    let mut all = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut all)).await;
    // A reset after the answer is an end too.
    let _ = read.expect("the connection is closed in time");
    String::from_utf8_lossy(&all).into_owned()
}

/// The status of a raw answer.
fn status(answer: &str) -> u16 {
    answer
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("not an answer: {answer:?}"))
}

/// One answer with a `Content-Length` from a connection that stays open:
/// its status, its head in lower case, and its body.
async fn one(stream: &mut TcpStream) -> (u16, String, Vec<u8>) {
    let read = async {
        let mut bytes = Vec::new();
        let end = loop {
            if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let mut piece = [0_u8; 4096];
            let n = stream.read(&mut piece).await.expect("read");
            assert!(
                n > 0,
                "closed inside an answer's head: {:?}",
                String::from_utf8_lossy(&bytes)
            );
            bytes.extend_from_slice(&piece[..n]);
        };
        let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .expect("an answer with a length")
            .trim()
            .parse()
            .expect("a number");
        let mut body = bytes.split_off(end);
        while body.len() < length {
            let mut piece = [0_u8; 4096];
            let n = stream.read(&mut piece).await.expect("read");
            assert!(n > 0, "closed inside an answer's body");
            body.extend_from_slice(&piece[..n]);
        }
        assert_eq!(body.len(), length, "no more than the answer");
        let code = head
            .strip_prefix("http/1.1 ")
            .and_then(|rest| rest.get(..3))
            .and_then(|code| code.parse().ok())
            .expect("a status");
        (code, head, body)
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("an answer in time")
}

/// A GET that asks for the connection to end after it.
fn get(target: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: bot.example:8080\r\nConnection: close\r\n\r\n")
}

#[tokio::test]
async fn the_line_it_starts_with_says_what_is_in_force() {
    let config = WafConfig::default_for(
        "test",
        "127.0.0.1:0".parse().expect("listen"),
        "127.0.0.1:3000".parse().expect("upstream"),
    );
    let shared = Shared::new(config, Arc::new(|| 0), Arc::new(|_| {}));
    let proxy = Proxy::bind(shared).await.expect("bind the proxy");
    let address = proxy.address().expect("the proxy's address");
    // What a body's time is a limit on is said as `check` and the guide
    // say it: the app's time to take the body is not the body's.
    assert_eq!(
        proxy.describe(),
        format!(
            "listening on {address}, forwarding to 127.0.0.1:3000; methods GET POST PUT DELETE; \
             allow every path; deny none; body up to 1048576 bytes within 30 seconds (the time \
             the app takes to accept it not counted), head up to 16384; rate 50 a second, burst \
             100; connections per address 32; ban after 100 blocked within 60 seconds, for 600 \
             seconds; probes blocked"
        )
    );
}

#[tokio::test]
async fn a_get_and_a_post_reach_the_app_as_they_were_sent_with_the_client_added() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;

    let answer = waf.ask(get("/api/trades/123?limit=10&cursor=a%2Fb")).await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.ends_with("hello from the app\n"), "{answer}");
    assert!(
        answer.to_ascii_lowercase().contains("x-app: yes"),
        "{answer}"
    );

    let body = r#"{"side":"buy","size":1}"#;
    let answer = waf
        .ask(format!(
            "POST /api/echo HTTP/1.1\r\nHost: bot.example:8080\r\nConnection: close, X-Hop\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nAuthorization: Bearer \
             {SECRET}\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\nProxy-Authorization: Basic abc\r\n\
             TE: trailers\r\nX-Keep: kept\r\nX-Forwarded-For: 203.0.113.9\r\n\
             X-Forwarded-Proto: https\r\n\r\n{body}",
            body.len()
        ))
        .await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.ends_with(body), "the app's echo: {answer}");

    let asked = app.finished(2).await;
    let get = &asked[0];
    assert_eq!(get.method, "GET");
    // Byte for byte: the encoded slash in the query is still encoded.
    assert_eq!(get.target, "/api/trades/123?limit=10&cursor=a%2Fb");
    assert_eq!(get.header("host"), Some("bot.example:8080"));
    assert_eq!(get.header("x-forwarded-for"), Some("127.0.0.1"));
    assert_eq!(get.header("x-forwarded-proto"), Some("http"));
    assert!(get.body.is_empty() && get.whole);

    let post = &asked[1];
    assert_eq!(
        (post.method.as_str(), post.target.as_str()),
        ("POST", "/api/echo")
    );
    assert_eq!(post.body, body.as_bytes());
    assert_eq!(post.header("content-length"), Some("23"));
    assert_eq!(post.header("content-type"), Some("application/json"));
    assert_eq!(
        post.header("authorization"),
        Some(&*format!("Bearer {SECRET}"))
    );
    assert_eq!(post.header("x-keep"), Some("kept"));
    // The client's word first, what the proxy saw last; the scheme is the
    // proxy's to say.
    assert_eq!(
        post.header("x-forwarded-for"),
        Some("203.0.113.9, 127.0.0.1")
    );
    assert_eq!(post.header("x-forwarded-proto"), Some("http"));
    // What belonged to the client's connection stays on it.
    for gone in [
        "connection",
        "x-hop",
        "keep-alive",
        "proxy-authorization",
        "te",
    ] {
        assert_eq!(post.header(gone), None, "{gone}");
    }
    assert_eq!(app.begun(), 2);
    let counts = waf.counts();
    assert_eq!((counts.requests, counts.forwarded), (2, 2));
}

#[tokio::test]
async fn the_client_cannot_speak_for_the_proxy_in_what_the_app_reads() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;
    // The second request of the body, to an app server that took
    // `Transfer_Encoding` for `Transfer-Encoding`.
    let body = "0\r\n\r\nGET /api/admin/x HTTP/1.1\r\nHost: a\r\n\r\n";
    let answer = waf
        .ask(format!(
            "POST /api/echo HTTP/1.1\r\nHost: bot.example\r\nConnection: close\r\n\
             X-Forwarded-For: 198.51.100.1\r\nX-Forwarded-For: 198.51.100.2\r\n\
             X_Forwarded_For: 198.51.100.3\r\nX-Real-IP: 198.51.100.4\r\n\
             x-real-ip: 198.51.100.5\r\nForwarded: for=198.51.100.6\r\n\
             X-Forwarded-Proto: https\r\nTransfer_Encoding: chunked\r\nContent_Length: 0\r\n\
             X_Real_IP: 198.51.100.7\r\nX-Keep: kept\r\nContent-Length: 00{}\r\n\r\n{body}",
            body.len()
        ))
        .await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.ends_with(body), "the body is a body: {answer}");
    let asked = app.finished(1).await;
    let post = &asked[0];
    assert_eq!(post.body, body.as_bytes());
    // The length is the number that was read, not the digits it came in.
    assert_eq!(
        post.header("content-length"),
        Some(&*body.len().to_string())
    );
    // No name with an underscore reaches the app, whatever it would have
    // been taken for.
    let names: Vec<&str> = post.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(!names.iter().any(|n| n.contains('_')), "{names:?}");
    // Where the request came from is the proxy's to say: its own word in
    // `X-Real-IP`, and last in `X-Forwarded-For` after the client's.
    assert_eq!(
        names.iter().filter(|n| **n == "x-real-ip").count(),
        1,
        "{names:?}"
    );
    assert_eq!(post.header("x-real-ip"), Some("127.0.0.1"));
    assert_eq!(
        post.header("x-forwarded-for"),
        Some("198.51.100.1, 198.51.100.2, 127.0.0.1")
    );
    assert_eq!(post.header("forwarded"), None);
    assert_eq!(post.header("x-forwarded-proto"), Some("http"));
    assert_eq!(post.header("x-keep"), Some("kept"));
    assert_eq!(
        app.begun(),
        1,
        "one request, and no second one out of its body"
    );

    // A request with none of them is given the proxy's all the same.
    assert_eq!(status(&waf.ask(get("/api/x")).await), 200);
    let asked = app.finished(2).await;
    assert_eq!(asked[1].header("x-real-ip"), Some("127.0.0.1"));
    assert_eq!(asked[1].header("x-forwarded-for"), Some("127.0.0.1"));
    assert_eq!(asked[1].header("content-length"), None);
}

#[tokio::test]
async fn the_apps_answer_comes_back_whole_without_what_was_its_connections() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;

    let answer = waf.ask(get("/api/hop")).await;
    let lower = answer.to_ascii_lowercase();
    assert_eq!(status(&answer), 200);
    assert!(lower.contains("x-app: yes"), "{answer}");
    for gone in ["x-internal", "keep-alive", "x-internal: 1"] {
        assert!(!lower.contains(gone), "{gone} in {answer}");
    }

    // The app's own statuses are the app's to give.
    let answer = waf.ask(get("/api/missing")).await;
    assert_eq!(status(&answer), 404);
    assert!(answer.ends_with("no such thing\n"));

    // Two megabytes come through whole.
    let answer = waf.ask(get("/api/big")).await;
    let body = answer.split_once("\r\n\r\n").expect("a body").1;
    assert_eq!(body.len(), 2 * 1024 * 1024);
    assert!(body.bytes().all(|b| b == b'x'));

    // HTTP/1.0, with no Host: the app is asked in 1.1 and given one.
    let answer = waf.ask("GET /api/old HTTP/1.0\r\n\r\n").await;
    assert!(answer.starts_with("HTTP/1.0 200 "), "{answer}");
    assert!(answer.ends_with("hello from the app\n"), "{answer}");
    let asked = app.finished(4).await;
    assert_eq!(asked[3].target, "/api/old");
    assert_eq!(asked[3].header("host"), Some(&*app.address.to_string()));
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one table of requests")]
async fn each_rule_answers_with_its_status_and_the_app_never_sees_the_request() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.config.allow_paths = vec!["/api/*".to_owned(), "/healthz".to_owned()];
        setup.config.deny_paths = vec!["/api/admin/*".to_owned()];
        setup.config.max_body_bytes = 64;
    })
    .await;
    let host = "Host: bot.example\r\nConnection: close\r\n";
    let cases: Vec<(String, u16, &str)> = vec![
        // 2. The method.
        (
            format!("PATCH /api/x HTTP/1.1\r\n{host}\r\n"),
            405,
            "method",
        ),
        (format!("OPTIONS * HTTP/1.1\r\n{host}\r\n"), 405, "method"),
        (
            format!("TRACE /api/x HTTP/1.1\r\n{host}\r\n"),
            405,
            "method",
        ),
        // 3. The path's normal form.
        (get("/api/x/../admin/users"), 400, "path"),
        (get("/api/%2e%2e/admin"), 400, "path"),
        (get("/api/x%2fy"), 400, "path"),
        (get("/api/x%5Cy"), 400, "path"),
        (get("/api/x%00"), 400, "path"),
        (get("/api/x%zz"), 400, "path"),
        (get("/api//x"), 400, "path"),
        (get("http://127.0.0.1/api/x"), 400, "path"),
        // 4. Deny, then allow.
        (get("/api/admin/users"), 403, "denied"),
        (get("/api/%61dmin/users"), 403, "denied"),
        (get("/api/admin"), 403, "denied"),
        (get("/metrics"), 404, "not_allowed"),
        (get("/"), 404, "not_allowed"),
        // 5. Probes, on an allowed path.
        (get("/api/.env"), 403, "probe"),
        (get("/api/x.php"), 403, "probe"),
        (get("/api/items?id=1+UNION+SELECT+1"), 403, "probe"),
        (get("/api/search?q=%3Cscript%3E"), 403, "probe"),
        // 6. A change of protocol.
        (
            "GET /api/ws HTTP/1.1\r\nHost: bot.example\r\nConnection: Upgrade\r\nUpgrade: \
             websocket\r\nSec-WebSocket-Version: 13\r\n\r\n"
                .to_owned(),
            501,
            "upgrade",
        ),
        // 8. A body the head says is too long.
        (
            format!("POST /api/x HTTP/1.1\r\n{host}Content-Length: 65\r\n\r\n"),
            413,
            "body",
        ),
        // 1. A head that is not one unambiguous request.
        (
            format!(
                "POST /api/x HTTP/1.1\r\n{host}Transfer-Encoding: chunked\r\nContent-Length: \
                 4\r\n\r\n0\r\n\r\n"
            ),
            400,
            "malformed",
        ),
        (
            format!(
                "POST /api/x HTTP/1.1\r\n{host}Content-Length: 4\r\nTransfer-Encoding: \
                 chunked\r\n\r\n0\r\n\r\n"
            ),
            400,
            "malformed",
        ),
        (
            format!(
                "POST /api/x HTTP/1.1\r\n{host}Content-Length: 4\r\nContent-Length: 5\r\n\r\nabcde"
            ),
            400,
            "malformed",
        ),
        (
            format!(
                "POST /api/x HTTP/1.1\r\n{host}Content-Length: 4\r\nContent-Length: 4\r\n\r\nabcd"
            ),
            400,
            "malformed",
        ),
        (
            format!(
                "POST /api/x HTTP/1.1\r\n{host}Transfer-Encoding:\r\n chunked\r\n\r\n0\r\n\r\n"
            ),
            400,
            "malformed",
        ),
        (
            format!(
                "POST /api/x HTTP/1.1\r\n{host}Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"
            ),
            400,
            "malformed",
        ),
        (
            format!("GET /api/x HTTP/1.1\r\n{host}X-A: 1\nX-B: 2\r\n\r\n"),
            400,
            "malformed",
        ),
        (
            "GET /api/x HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n".to_owned(),
            400,
            "malformed",
        ),
        (
            "GET /api/x HTTP/1.1\r\nConnection: close\r\n\r\n".to_owned(),
            400,
            "malformed",
        ),
        (
            format!("GET /api/x#frag HTTP/1.1\r\n{host}\r\n"),
            400,
            "malformed",
        ),
        (
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_owned(),
            400,
            "malformed",
        ),
        (
            "get /api/x HTTP/1.1\r\nHost: a\r\n\r\n".to_owned(),
            400,
            "malformed",
        ),
        (
            "\r\nGET /api/x HTTP/1.1\r\nHost: a\r\n\r\n".to_owned(),
            400,
            "malformed",
        ),
    ];
    for (n, (request, code, reason)) in cases.iter().enumerate() {
        let answer = waf.ask(request).await;
        assert_eq!(status(&answer), *code, "{request:?} -> {answer:?}");
        let lower = answer.to_ascii_lowercase();
        assert!(lower.contains("connection: close"), "{answer}");
        let line = waf.lines().pop().expect("a line for each");
        assert!(
            line.starts_with(&format!(
                "blocked reason={reason} status={code} peer=127.0.0.1 "
            )),
            "{request:?} -> {line}"
        );
        assert_eq!(waf.lines().len(), n + 1, "one line each");
    }
    // A TLS hello sent to the plain port is refused at its first bytes.
    let answer = waf
        .ask(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")
        .await;
    assert_eq!(status(&answer), 400);

    // What the 405 and the 501 carry.
    let answer = waf.ask(&cases[0].0).await;
    assert!(
        answer.contains("allow: GET, POST, PUT, DELETE\r\n"),
        "{answer}"
    );

    // Not one of them reached the app, which is there and answering.
    assert_eq!(app.begun(), 0);
    assert!(app.asked().is_empty());
    assert_eq!(status(&waf.ask(get("/api/x")).await), 200);
    assert_eq!(status(&waf.ask(get("/healthz")).await), 200);
    assert_eq!(app.begun(), 2);

    let counts = waf.counts();
    let blocked = counts.blocked;
    assert_eq!(
        (
            blocked.method,
            blocked.path,
            blocked.denied,
            blocked.not_allowed
        ),
        (4, 8, 3, 2)
    );
    assert_eq!((blocked.probe, blocked.upgrade, blocked.body), (4, 1, 1));
    assert_eq!(blocked.malformed, 14);
    assert_eq!(counts.forwarded, 2);
    assert_eq!(counts.requests, 4 + 8 + 3 + 2 + 4 + 1 + 1 + 14 + 2);
    assert_eq!(counts.upstream_errors, 0);
}

#[tokio::test]
async fn a_head_may_be_as_large_as_the_config_says_and_no_larger() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| setup.config.max_header_bytes = 2048).await;
    let with = |pad: usize| {
        let start = "GET /api/x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nX-Pad: ";
        format!("{start}{}\r\n\r\n", "p".repeat(pad - start.len() - 4))
    };
    assert_eq!(with(2048).len(), 2048);
    assert_eq!(status(&waf.ask(with(2048)).await), 200);
    assert_eq!(app.begun(), 1);
    let answer = waf.ask(with(2049)).await;
    assert_eq!(status(&answer), 431, "{answer}");
    // However much follows, no more than the limit is taken in.
    let answer = waf.ask(with(200_000)).await;
    assert_eq!(status(&answer), 431, "{answer}");
    // More headers than a head may have.
    let many = (0..101).fold(String::new(), |mut many, n| {
        let _ = write!(many, "X-{n}: 1\r\n");
        many
    });
    let answer = waf
        .ask(format!("GET /api/x HTTP/1.1\r\nHost: a\r\n{many}\r\n"))
        .await;
    assert_eq!(status(&answer), 431, "{answer}");
    assert_eq!(app.begun(), 1);
    assert_eq!(waf.counts().blocked.malformed, 3);
}

#[tokio::test]
async fn a_request_hidden_in_a_body_is_a_body() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.config.deny_paths = vec!["/api/admin/*".to_owned()];
    })
    .await;
    // The body is, to the letter, a request for a denied path; another
    // request follows on the same connection.
    let hidden = "GET /api/admin/keys HTTP/1.1\r\nHost: bot.example\r\n\r\n";
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(
            format!(
                "POST /api/echo HTTP/1.1\r\nHost: bot.example\r\nContent-Length: {}\r\n\r\n\
                 {hidden}GET /api/after HTTP/1.1\r\nHost: bot.example\r\n\r\n",
                hidden.len()
            )
            .as_bytes(),
        )
        .await
        .expect("send");
    let (code, _, body) = one(&mut stream).await;
    assert_eq!(code, 200);
    assert_eq!(body, hidden.as_bytes(), "echoed as the body it is");
    let (code, _, body) = one(&mut stream).await;
    assert_eq!((code, body.as_slice()), (200, &b"hello from the app\n"[..]));
    let asked = app.finished(2).await;
    assert_eq!(
        asked.iter().map(|a| a.target.as_str()).collect::<Vec<_>>(),
        ["/api/echo", "/api/after"]
    );
    assert_eq!(asked[0].body, hidden.as_bytes());
    assert_eq!(app.begun(), 2, "and the denied path was never asked for");
}

#[tokio::test]
async fn a_connection_carries_one_request_after_another_until_one_is_blocked() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    // Two at once, then one more after their answers.
    stream
        .write_all(
            b"GET /api/one HTTP/1.1\r\nHost: a\r\n\r\nPOST /api/echo HTTP/1.1\r\nHost: \
              a\r\nContent-Length: 3\r\n\r\ntwo",
        )
        .await
        .expect("send");
    let (code, head, _) = one(&mut stream).await;
    assert_eq!(code, 200);
    assert!(!head.contains("connection: close"), "{head}");
    let (code, _, body) = one(&mut stream).await;
    assert_eq!((code, body.as_slice()), (200, &b"two"[..]));
    stream
        .write_all(b"GET /api/three HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .expect("send");
    assert_eq!(one(&mut stream).await.0, 200);
    // A blocked request ends the connection, and what was sent behind it
    // is not read.
    stream
        .write_all(
            b"GET /.git/config HTTP/1.1\r\nHost: a\r\n\r\nGET /api/behind HTTP/1.1\r\nHost: \
              a\r\n\r\n",
        )
        .await
        .expect("send");
    let last = rest(&mut stream).await;
    assert_eq!(status(&last), 403);
    assert_eq!(last.matches("HTTP/1.1 ").count(), 1, "{last}");
    let targets: Vec<String> = app
        .finished(3)
        .await
        .into_iter()
        .map(|a| a.target)
        .collect();
    assert_eq!(targets, ["/api/one", "/api/echo", "/api/three"]);
    assert_eq!(app.begun(), 3);
    let counts = waf.counts();
    assert_eq!(
        (counts.requests, counts.forwarded, counts.blocked.probe),
        (4, 3, 1)
    );
}

#[tokio::test]
async fn a_body_announced_with_expect_is_asked_for_and_forwarded() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(
            b"POST /api/echo HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: \
              5\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("send the head");
    let mut go_on = [0_u8; 25];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut go_on))
        .await
        .expect("asked to go on in time")
        .expect("read");
    assert_eq!(&go_on, b"HTTP/1.1 100 Continue\r\n\r\n");
    stream.write_all(b"hello").await.expect("send the body");
    let answer = rest(&mut stream).await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.ends_with("hello"));
    let asked = app.finished(1).await;
    assert_eq!(asked[0].body, b"hello");
    assert_eq!(asked[0].header("expect"), None, "answered by the proxy");
}

#[tokio::test]
async fn a_chunked_body_is_forwarded_whole_and_cut_when_it_passes_the_limit() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| setup.config.max_body_bytes = 100).await;
    let head = "POST /api/echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";

    // Within the limit: a hundred bytes in three chunks.
    let within = format!(
        "{head}28\r\n{}\r\n28\r\n{}\r\n14\r\n{}\r\n0\r\n\r\n",
        "a".repeat(40),
        "b".repeat(40),
        "c".repeat(20)
    );
    let answer = waf.ask(within).await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.to_ascii_lowercase().contains("connection: close"));
    let asked = app.finished(1).await;
    assert!(asked[0].whole);
    assert_eq!(
        asked[0].body,
        format!("{}{}{}", "a".repeat(40), "b".repeat(40), "c".repeat(20)).as_bytes()
    );
    assert_eq!(asked[0].header("transfer-encoding"), Some("chunked"));
    assert_eq!(asked[0].header("content-length"), None);

    // One byte over, and the client is still sending when it is cut.
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(format!("{head}40\r\n{}\r\n", "d".repeat(64)).as_bytes())
        .await
        .expect("send the first chunk");
    tokio::time::sleep(Duration::from_millis(50)).await;
    stream
        .write_all(format!("25\r\n{}\r\n", "e".repeat(37)).as_bytes())
        .await
        .expect("send the second chunk");
    let answer = rest(&mut stream).await;
    assert_eq!(status(&answer), 413, "{answer}");
    // The app was sent the start of it, and never the end.
    let asked = app.finished(2).await;
    assert!(!asked[1].whole, "the request to the app was abandoned");
    assert!(asked[1].body.is_empty());
    assert_eq!(app.begun(), 2);
    let counts = waf.counts();
    assert_eq!((counts.forwarded, counts.blocked.body), (1, 1));
    let line = waf.lines().pop().expect("a line");
    assert!(
        line.starts_with("blocked reason=body status=413 "),
        "{line}"
    );
}

#[tokio::test]
async fn a_client_that_stalls_is_not_waited_for() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.client_wait = Duration::from_millis(300);
    })
    .await;

    // Half a head, and then nothing.
    let started = Instant::now();
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(b"GET /api/x HTTP/1.1\r\nHost: a\r\nX-Slow: ")
        .await
        .expect("send");
    let answer = rest(&mut stream).await;
    let took = started.elapsed();
    assert_eq!(status(&answer), 408, "{answer}");
    assert!(took >= Duration::from_millis(300), "{took:?}");
    assert!(took < Duration::from_secs(3), "{took:?}");

    // A head sent a byte at a time has the same time in all, not per byte.
    let started = Instant::now();
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    let drip = tokio::spawn(async move {
        for byte in b"GET /api/x HTTP/1.1\r\nHost: a\r\nX-Slow: 0123456789" {
            if stream.write_all(&[*byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        rest(&mut stream).await
    });
    let answer = drip.await.expect("drip");
    assert_eq!(status(&answer), 408, "{answer}");
    assert!(started.elapsed() < Duration::from_secs(4));

    // A request written with bare line feeds never ends its head: it is
    // answered when the head's time is up, not at once.
    let started = Instant::now();
    let answer = waf.ask("GET /api/x HTTP/1.1\nHost: a\n\n").await;
    assert_eq!(status(&answer), 408, "{answer}");
    assert!(started.elapsed() >= Duration::from_millis(300));

    // Nothing at all: closed without a word, and not held against anyone.
    let started = Instant::now();
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    assert_eq!(rest(&mut stream).await, "");
    assert!(started.elapsed() >= Duration::from_millis(300));

    // A body that stops halfway: the connection ends, and the app never
    // has the whole of it.
    let started = Instant::now();
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(b"POST /api/echo HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nhalf")
        .await
        .expect("send");
    let answer = rest(&mut stream).await;
    assert_eq!(status(&answer), 400, "{answer}");
    assert!(started.elapsed() < Duration::from_secs(3));
    let asked = app.finished(1).await;
    assert!(!asked[0].whole);
    let line = waf.lines().pop().expect("a line");
    assert!(
        line.starts_with("blocked reason=malformed status=400 ")
            && line.ends_with("detail=\"the body could not be read\""),
        "{line}"
    );

    let counts = waf.counts();
    assert_eq!(counts.forwarded, 0);
    assert_eq!(counts.blocked.malformed, 4, "{counts:?}");
    assert_eq!(app.begun(), 1, "only the request whose head was whole");
}

/// Sends `head`, then `body` a byte at a time, `every` apart, until all of
/// it is sent or the proxy has closed the connection; returns everything
/// the proxy answered.
async fn dripped(waf: &Waf, head: &str, body: &[u8], every: Duration) -> String {
    let stream = TcpStream::connect(waf.address).await.expect("connect");
    let (mut from, mut to) = stream.into_split();
    let answered = tokio::spawn(async move {
        let mut all = Vec::new();
        let _ = from.read_to_end(&mut all).await;
        String::from_utf8_lossy(&all).into_owned()
    });
    to.write_all(head.as_bytes()).await.expect("send the head");
    for byte in body {
        if answered.is_finished() || to.write_all(&[*byte]).await.is_err() {
            break;
        }
        tokio::time::sleep(every).await;
    }
    tokio::time::timeout(Duration::from_secs(10), answered)
        .await
        .expect("the connection is closed in time")
        .expect("read")
}

#[tokio::test]
async fn a_body_still_arriving_when_its_time_is_up_is_408_and_held_against_the_address() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.body_wait = Duration::from_millis(500);
        setup.config.ban = Some(Ban {
            after: 1,
            window_secs: 60,
            for_secs: 600,
        });
    })
    .await;
    let head = "POST /api/echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: ";

    // A body that comes in pieces and is whole in time is forwarded.
    let answer = dripped(
        &waf,
        &format!("{head}5\r\n\r\n"),
        b"hello",
        Duration::from_millis(20),
    )
    .await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.ends_with("hello"), "{answer}");

    // One that keeps coming, a byte every 40 ms, never stalls (the client
    // has three seconds between bytes here) and is not whole in time.
    let started = Instant::now();
    let answer = dripped(
        &waf,
        &format!("{head}200\r\n\r\n"),
        &[b'x'; 200],
        Duration::from_millis(40),
    )
    .await;
    let took = started.elapsed();
    assert_eq!(status(&answer), 408, "{answer}");
    assert!(
        answer.to_ascii_lowercase().contains("connection: close"),
        "{answer}"
    );
    assert!(took >= Duration::from_millis(500), "{took:?}");
    assert!(took < Duration::from_secs(3), "{took:?}");
    // The app was sent the start of it, and its request abandoned.
    let asked = app.finished(2).await;
    assert!(asked[0].whole && !asked[1].whole, "{asked:?}");
    assert_eq!(app.begun(), 2);
    let lines = waf.lines();
    assert_eq!(
        lines[0],
        "blocked reason=body_timeout status=408 peer=127.0.0.1 method=POST path=\"/api/echo\" \
         detail=\"the body had not arrived within body_timeout_secs\""
    );
    // A blocked request like the others: it counts towards the ban, which
    // here takes one.
    assert!(
        lines[1].starts_with("banned address=127.0.0.1 "),
        "{lines:?}"
    );
    assert_eq!(waf.ask(get("/api/x")).await, "", "banned");
    let counts = waf.counts();
    assert_eq!(
        (
            counts.requests,
            counts.forwarded,
            counts.blocked.body_timeout,
            counts.blocked.malformed,
            counts.blocked.banned
        ),
        (2, 1, 1, 0, 1)
    );
}

#[tokio::test]
async fn a_body_that_goes_silent_is_408_when_its_time_is_up_with_no_byte_to_wake_the_proxy() {
    // The client may stall for three seconds, and the body has half a
    // second in all: half of it sent, then silence on an open connection.
    // Nothing arrives to have the proxy look at the time again.
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.body_wait = Duration::from_millis(500);
    })
    .await;
    let started = Instant::now();
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(b"POST /api/echo HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nhalf")
        .await
        .expect("send");
    let answer = rest(&mut stream).await;
    let took = started.elapsed();
    assert_eq!(status(&answer), 408, "{answer}");
    assert!(took >= Duration::from_millis(500), "{took:?}");
    assert!(took < Duration::from_millis(2500), "{took:?}");
    assert_eq!(waf.counts().blocked.body_timeout, 1);
}

#[tokio::test]
async fn a_body_that_trickles_and_then_goes_silent_is_408_when_its_time_is_up_and_no_later() {
    // A body has 1.5 s. A byte every 50 ms for 1.2 s of it, and then
    // silence: its time is up 0.3 s into the silence, not another 1.5 s
    // after the last byte. What the bytes used of the time is used.
    let wait = Duration::from_millis(1500);
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| setup.body_wait = wait).await;
    let started = Instant::now();
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(b"POST /api/echo HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n")
        .await
        .expect("send the head");
    for _ in 0..24 {
        stream.write_all(b"x").await.expect("send a byte");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let trickled = started.elapsed();
    let answer = rest(&mut stream).await;
    let took = started.elapsed();
    assert_eq!(status(&answer), 408, "{answer}");
    assert!(took >= wait, "{took:?}");
    assert!(
        trickled < wait,
        "the bytes took {trickled:?}: the body's time was up before the silence, which shows \
         nothing"
    );
    // A second time from the last byte would be 2.7 s.
    assert!(took < Duration::from_millis(2400), "{took:?}");
    assert_eq!(waf.counts().blocked.body_timeout, 1);
}

/// Sends `head` and then a body a byte at a time, each byte a write of its
/// own, as fast as the proxy takes them, until the proxy answers. From a
/// thread of its own, and not from the proxy's: there is a byte whenever
/// the proxy looks, as there is from a client on another machine. Returns
/// what the proxy answered and how long the answer took to begin, counted
/// from before the head was sent: the proxy starts a body's time once it
/// has the head, so that count is never the shorter of the two.
fn flooded(address: SocketAddr, head: &str) -> (String, Duration) {
    use std::io::{Read as _, Write as _};
    use std::sync::atomic::AtomicBool;

    let mut stream = std::net::TcpStream::connect(address).expect("connect");
    stream.set_nodelay(true).expect("no delay");
    let mut reading = stream.try_clone().expect("the reading side");
    reading
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("a time to read in");
    let started = Instant::now();
    stream.write_all(head.as_bytes()).expect("send the head");
    let answered = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&answered);
    let reader = std::thread::spawn(move || {
        let (mut all, mut piece, mut after) = (Vec::new(), [0_u8; 4096], None);
        while let Ok(n) = reading.read(&mut piece) {
            if n == 0 {
                break;
            }
            after.get_or_insert_with(|| started.elapsed());
            seen.store(true, Ordering::SeqCst);
            all.extend_from_slice(&piece[..n]);
        }
        seen.store(true, Ordering::SeqCst);
        (String::from_utf8_lossy(&all).into_owned(), after)
    });
    while !answered.load(Ordering::SeqCst) && stream.write_all(b"x").is_ok() {}
    let (answer, after) = reader.join().expect("the reader");
    (answer, after.expect("an answer"))
}

#[tokio::test]
async fn a_body_sent_a_byte_at_a_time_as_fast_as_it_is_read_is_408_when_its_time_is_up() {
    // The bytes never stop and never slow down: the proxy is not kept
    // waiting on the client's connection, it is kept busy by it. The
    // body's time is up all the same, for one such client and for four at
    // once, which leave the proxy no time between them.
    let wait = Duration::from_millis(500);
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.config.max_body_bytes = 64 * 1024 * 1024;
        setup.body_wait = wait;
    })
    .await;
    let head = "POST /api/echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: \
                67108864\r\n\r\n";
    for clients in [1, 4] {
        let floods: Vec<_> = (0..clients)
            .map(|_| {
                let address = waf.address;
                tokio::task::spawn_blocking(move || flooded(address, head))
            })
            .collect();
        for flood in floods {
            let (answer, after) = tokio::time::timeout(Duration::from_secs(40), flood)
                .await
                .expect("answered in time")
                .expect("the client");
            assert_eq!(status(&answer), 408, "{clients} at once: {answer}");
            // Not before all of its time has passed: no part of a
            // millisecond of it is given up.
            assert!(after >= wait, "{clients} at once: {after:?}");
            // And when it is up, not a second such time later.
            assert!(
                after < wait * 2,
                "{clients} at once: answered after {after:?}, and the body had {wait:?}"
            );
        }
    }
    let counts = waf.counts();
    assert_eq!(
        (counts.forwarded, counts.blocked.body_timeout),
        (0, 5),
        "{:?}",
        waf.lines()
    );
}

/// An app that reads a request's head and then its body no faster than
/// `piece` bytes every `every`, until it has `length` of it, and answers
/// with how many bytes of body it read.
async fn unhurried(length: usize, piece: usize, every: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut asked = Vec::new();
                let mut buffer = vec![0_u8; piece];
                let head = loop {
                    if let Some(at) = asked.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                    match stream.read(&mut buffer).await {
                        Ok(n) if n > 0 => asked.extend_from_slice(&buffer[..n]),
                        _ => return,
                    }
                };
                let mut read = asked.len() - head;
                while read < length {
                    tokio::time::sleep(every).await;
                    match stream.read(&mut buffer).await {
                        Ok(n) if n > 0 => read += n,
                        _ => break,
                    }
                }
                let body = read.to_string();
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(answer.as_bytes()).await;
            });
        }
    });
    address
}

#[tokio::test]
async fn a_body_the_app_is_slow_to_take_is_forwarded_whole_and_a_slow_client_is_still_408() {
    // 16 MiB, more than the system holds for an app that is not reading,
    // to an app that takes at most 64 KiB every few milliseconds: over a
    // second for all of it, where a body has 300 ms.
    const LENGTH: usize = 16 * 1024 * 1024;
    let body_wait = Duration::from_millis(300);
    let app = unhurried(LENGTH, 64 * 1024, Duration::from_millis(4)).await;
    let waf = Waf::start(app, |setup| {
        setup.config.max_body_bytes = 64 * 1024 * 1024;
        setup.body_wait = body_wait;
    })
    .await;
    let head = format!(
        "POST /api/x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: \
         {LENGTH}\r\n\r\n"
    );

    // A client that sends as fast as it is read: the wait is the app's,
    // and the client is answered by the app.
    let started = Instant::now();
    let stream = TcpStream::connect(waf.address).await.expect("connect");
    let (mut reading, mut writing) = stream.into_split();
    let request = head.clone();
    let sender = tokio::spawn(async move {
        writing.write_all(request.as_bytes()).await.expect("head");
        let piece = vec![b'x'; 64 * 1024];
        for _ in 0..LENGTH / piece.len() {
            if writing.write_all(&piece).await.is_err() {
                break;
            }
        }
        (writing, started.elapsed())
    });
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), reading.read_to_end(&mut answer))
        .await
        .expect("answered in time")
        .ok();
    let answer = String::from_utf8_lossy(&answer);
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.ends_with(&LENGTH.to_string()), "{answer}");
    let (_writing, sent_after) = sender.await.expect("the sender");
    assert!(
        sent_after > body_wait,
        "the client had sent all of it after {sent_after:?}: the app was not slow enough for \
         this to show anything"
    );
    let counts = waf.counts();
    assert_eq!(
        (counts.forwarded, counts.blocked.body_timeout),
        (1, 0),
        "{:?}",
        waf.lines()
    );

    // A client that sends a byte every 40 ms to the same app: the wait is
    // the client's, and its time is up as it would be before any app.
    let started = Instant::now();
    let answer = dripped(&waf, &head, &[b'x'; 200], Duration::from_millis(40)).await;
    let took = started.elapsed();
    assert_eq!(status(&answer), 408, "{answer}");
    assert!(took >= body_wait, "{took:?}");
    assert!(took < Duration::from_millis(2500), "{took:?}");
    let counts = waf.counts();
    assert_eq!((counts.forwarded, counts.blocked.body_timeout), (1, 1));
}

#[tokio::test]
async fn an_address_over_its_rate_is_told_when_to_come_back() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.config.rate = Some(Rate {
            per_second: 1,
            burst: 2,
        });
    })
    .await;
    assert_eq!(status(&waf.ask(get("/api/x")).await), 200);
    assert_eq!(status(&waf.ask(get("/api/x")).await), 200);
    let answer = waf.ask(get("/api/x")).await;
    assert_eq!(status(&answer), 429, "{answer}");
    assert!(answer.contains("retry-after: 1\r\n"), "{answer}");
    // A blocked request takes nothing from the rate: these are refused
    // for what they are, and the next good one waits no longer for them.
    for _ in 0..5 {
        assert_eq!(status(&waf.ask(get("/.env")).await), 403);
    }
    waf.clock.fetch_add(999, Ordering::SeqCst);
    assert_eq!(status(&waf.ask(get("/api/x")).await), 429);
    waf.clock.fetch_add(1, Ordering::SeqCst);
    assert_eq!(status(&waf.ask(get("/api/x")).await), 200);
    assert_eq!(status(&waf.ask(get("/api/x")).await), 429);
    assert_eq!(app.begun(), 3);
    let counts = waf.counts();
    assert_eq!(
        (counts.forwarded, counts.blocked.rate, counts.blocked.probe),
        (3, 3, 5)
    );
}

#[tokio::test]
async fn an_address_that_keeps_being_blocked_is_banned_and_later_let_back() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.config.ban = Some(Ban {
            after: 3,
            window_secs: 60,
            for_secs: 600,
        });
    })
    .await;
    // A change of protocol is refused, and held against it like any
    // other refusal.
    let upgrade =
        "GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    assert_eq!(status(&waf.ask(upgrade).await), 501);
    assert_eq!(status(&waf.ask(get("/.env")).await), 403);
    assert_eq!(
        status(&waf.ask(get("/api/x")).await),
        200,
        "two are not three"
    );
    // The third, of any kind, bans it: it still gets its own answer.
    assert_eq!(
        status(&waf.ask("BREW /pot HTTP/1.1\r\nHost: a\r\n\r\n").await),
        405
    );
    let said = waf.lines();
    assert_eq!(
        said.last().map(String::as_str),
        Some("banned address=127.0.0.1 seconds=600 after=3 blocked requests within 60 seconds")
    );
    // From then on its connections are closed unanswered.
    assert_eq!(waf.ask(get("/api/x")).await, "");
    assert_eq!(waf.ask(get("/.env")).await, "");
    assert_eq!(waf.lines().len(), said.len(), "and nothing more is said");
    assert_eq!(app.begun(), 1);
    assert_eq!(waf.shared.limits().banned_now(waf.shared.now()), 1);
    // Just before the time is up it still is; when it is up, it is not.
    waf.clock.fetch_add(599_999, Ordering::SeqCst);
    assert_eq!(waf.ask(get("/api/x")).await, "");
    waf.clock.fetch_add(1, Ordering::SeqCst);
    assert_eq!(status(&waf.ask(get("/api/x")).await), 200);
    assert_eq!(app.begun(), 2);
    let counts = waf.counts();
    assert_eq!(counts.blocked.banned, 3);
    assert_eq!(
        (
            counts.blocked.upgrade,
            counts.blocked.probe,
            counts.blocked.method
        ),
        (1, 1, 1)
    );
}

#[tokio::test]
async fn a_ban_ends_a_connection_that_was_already_open() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.config.ban = Some(Ban {
            after: 1,
            window_secs: 60,
            for_secs: 600,
        });
    })
    .await;
    let mut open = TcpStream::connect(waf.address).await.expect("connect");
    open.write_all(b"GET /api/x HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .expect("send");
    assert_eq!(one(&mut open).await.0, 200);
    // Banned over another connection, while this one is open.
    assert_eq!(status(&waf.ask(get("/.env")).await), 403);
    open.write_all(b"GET /api/x HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .expect("send");
    assert_eq!(rest(&mut open).await, "", "closed unanswered");
    assert_eq!(app.begun(), 1);
    // A connection refused, not a request: the requests are the one
    // forwarded and the one blocked, and add up.
    let counts = waf.counts();
    assert_eq!(counts.blocked.banned, 1);
    assert_eq!(
        (counts.requests, counts.forwarded, counts.blocked.probe),
        (2, 1, 1)
    );
}

#[tokio::test]
async fn an_address_holds_only_as_many_connections_as_it_may() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.config.max_connections_per_address = Some(2);
    })
    .await;
    let mut first = TcpStream::connect(waf.address).await.expect("connect");
    let mut second = TcpStream::connect(waf.address).await.expect("connect");
    // Both are served: the proxy has taken them.
    for stream in [&mut first, &mut second] {
        stream
            .write_all(b"GET /api/x HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .expect("send");
        assert_eq!(one(stream).await.0, 200);
    }
    // A third is closed unanswered.
    assert_eq!(waf.ask(get("/api/x")).await, "");
    assert_eq!(waf.counts().blocked.connections, 1);
    // When one ends there is room again.
    drop(first);
    let started = Instant::now();
    loop {
        let answer = waf.ask(get("/api/x")).await;
        if !answer.is_empty() {
            assert_eq!(status(&answer), 200);
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no room was made"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(second);
    assert_eq!(app.begun(), 3);
}

/// An address nothing accepts on, and the socket that keeps it so. The
/// socket is bound to the address and never listens: a connection there
/// is refused, as it is where an app is down, and while the socket is
/// kept the system gives the port to nobody else. A port only let go can
/// be given to another test's app the moment after, which would answer.
fn deaf() -> (rustix::fd::OwnedFd, SocketAddr) {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, bind, getsockname, socket_with};
    let held = socket_with(
        AddressFamily::INET,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("socket");
    let loopback = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
    bind(&held, &loopback).expect("bind");
    let address: SocketAddr = getsockname(&held)
        .expect("address")
        .try_into()
        .expect("an IP address");
    assert!(
        std::net::TcpStream::connect(address).is_err(),
        "a socket that does not listen accepts nothing"
    );
    (held, address)
}

#[tokio::test]
async fn an_app_that_is_down_is_502_and_one_that_does_not_answer_is_504() {
    let (_held, nobody) = deaf();
    let waf = Waf::start(nobody, |_| {}).await;
    for _ in 0..2 {
        let answer = waf.ask(get("/api/x")).await;
        assert_eq!(status(&answer), 502, "{answer}");
    }
    // Said once, not for every request.
    let said: Vec<String> = waf.lines();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].starts_with(&format!("upstream {nobody} is not answering")));
    let counts = waf.counts();
    assert_eq!(
        (counts.requests, counts.forwarded, counts.upstream_errors),
        (2, 0, 2)
    );

    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.upstream_wait = Duration::from_millis(300);
    })
    .await;
    let started = Instant::now();
    let answer = waf.ask(get("/api/never")).await;
    assert_eq!(status(&answer), 504, "{answer}");
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(started.elapsed() < Duration::from_secs(3));
    // The app is slow, not gone: the next request is answered, and the
    // log says both.
    assert_eq!(status(&waf.ask(get("/api/x")).await), 200);
    let said = waf.lines();
    assert_eq!(said.len(), 2, "{said:?}");
    assert!(said[0].contains("is not answering: 504"), "{said:?}");
    assert!(said[1].ends_with("is answering again"), "{said:?}");
    // A 502 or a 504 is the app's failing, not the client's.
    let counts = waf.counts();
    assert_eq!((counts.forwarded, counts.upstream_errors), (1, 1));
    assert_eq!(counts.blocked, erpc_worker::waf::Blocked::default());
}

#[tokio::test]
async fn the_apps_time_to_answer_runs_from_the_last_piece_of_the_request_it_was_handed() {
    // The app has a second to start answering. A request's body is whole
    // 800 ms after its head, and the app answers 300 ms after it has all
    // of it: 1.1 s after the head, which is past the app's time counted
    // from there, and 300 ms after the last piece, which is well within
    // it. With a length the last piece is the last of the body; chunked,
    // it is the body's end.
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.upstream_wait = Duration::from_secs(1);
    })
    .await;
    let sent_late = |head: &'static str, first: &'static str, last: &'static str| {
        let address = waf.address;
        async move {
            let started = Instant::now();
            let mut stream = TcpStream::connect(address).await.expect("connect");
            stream
                .write_all(format!("{head}{first}").as_bytes())
                .await
                .expect("send the head and half the body");
            tokio::time::sleep(Duration::from_millis(800)).await;
            stream
                .write_all(last.as_bytes())
                .await
                .expect("send the rest");
            (rest(&mut stream).await, started.elapsed())
        }
    };
    let with_length = sent_late(
        "POST /api/slow HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: 10\r\n\r\n",
        "half-",
        "whole",
    );
    let chunked = sent_late(
        "POST /api/slow HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        "5\r\nhalf-\r\n",
        "5\r\nwhole\r\n0\r\n\r\n",
    );
    for (answer, took) in <[_; 2]>::from(tokio::join!(with_length, chunked)) {
        assert_eq!(status(&answer), 200, "{answer}");
        assert!(answer.ends_with("slow\n"), "{answer}");
        assert!(took >= Duration::from_millis(1100), "{took:?}");
    }
    let counts = waf.counts();
    assert_eq!((counts.forwarded, counts.upstream_errors), (2, 0));
    for asked in app.finished(2).await {
        assert_eq!(asked.body, b"half-whole");
    }
}

#[tokio::test]
async fn an_app_that_answers_before_the_body_is_sent_is_passed_on() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(b"POST /api/early HTTP/1.1\r\nHost: a\r\nContent-Length: 100000\r\n\r\nstart")
        .await
        .expect("send");
    let answer = rest(&mut stream).await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.ends_with("early\n"), "{answer}");
}

#[tokio::test]
async fn a_connection_is_not_read_again_when_a_request_was_not_taken_whole() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;
    // The app answers at once, without the body, and the client has sent
    // only the start of the hundred bytes its head announced.
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(b"POST /api/early HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nstart")
        .await
        .expect("send");
    let (code, _, body) = one(&mut stream).await;
    assert_eq!((code, body.as_slice()), (200, &b"early\n"[..]));
    // What comes next on the connection is the rest of that body,
    // whatever it looks like: here, to the letter, a request. It is not
    // read as one: where the first request ended was never reached.
    // (The proxy may have closed already, and the write fail.)
    let _ = stream
        .write_all(b"GET /api/second HTTP/1.1\r\nHost: a\r\n\r\n")
        .await;
    assert_eq!(rest(&mut stream).await, "", "nothing more is answered");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(app.begun(), 1, "and the app was asked once");
    let counts = waf.counts();
    assert_eq!((counts.requests, counts.forwarded), (1, 1));
}

#[tokio::test]
async fn nothing_secret_and_nothing_raw_reaches_the_log() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.config.deny_paths = vec!["/api/admin/*".to_owned()];
    })
    .await;
    let secret = format!("Authorization: Bearer {SECRET}\r\nCookie: session={SECRET}\r\n");
    let long = format!("/api/admin/{}?token={SECRET}", "a".repeat(400));
    for request in [
        // Forwarded.
        format!("GET /api/x HTTP/1.1\r\nHost: a\r\n{secret}Connection: close\r\n\r\n"),
        format!(
            "POST /api/echo HTTP/1.1\r\nHost: a\r\n{secret}Content-Length: {}\r\nConnection: \
             close\r\n\r\n{SECRET}",
            SECRET.len()
        ),
        // Blocked by each kind of rule, with the secret in a header.
        format!("GET /.env HTTP/1.1\r\nHost: a\r\n{secret}\r\n"),
        format!("GET /api/admin/x HTTP/1.1\r\nHost: a\r\n{secret}\r\n"),
        format!("PATCH /api/x HTTP/1.1\r\nHost: a\r\n{secret}\r\n"),
        format!("GET /api/../x HTTP/1.1\r\nHost: a\r\n{secret}\r\n"),
        // A malformed head, with the secret before and after the fault,
        // and in a body.
        format!(
            "POST /api/x HTTP/1.1\r\nHost: a\r\n{secret}Content-Length: 4\r\nTransfer-Encoding: \
             chunked\r\n\r\n{SECRET}"
        ),
        format!("GET /api/x HTTP/1.1\r\n{secret} folded: {SECRET}\r\n\r\n"),
        format!("GET /api/x HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {SECRET}\n\r\n\r\n"),
        // A long target: cut before the secret in its query.
        format!("GET {long} HTTP/1.1\r\nHost: a\r\n\r\n"),
    ] {
        let _ = waf.ask(request).await;
    }
    let said = waf.lines();
    assert_eq!(
        said.len(),
        8,
        "one line for each of the eight blocked: {said:?}"
    );
    for line in &said {
        assert!(!line.contains(SECRET), "{line}");
        assert!(
            !line.to_ascii_lowercase().contains("authorization"),
            "{line}"
        );
        assert!(!line.to_ascii_lowercase().contains("cookie"), "{line}");
        assert!(!line.contains('\n') && !line.contains('\r'), "{line:?}");
        assert!(line.starts_with("blocked reason="), "{line}");
    }
    // What is said: the rule, the status, who, and what was asked for.
    assert_eq!(
        said[0],
        "blocked reason=probe status=403 peer=127.0.0.1 method=GET path=\"/.env\" detail=\"an \
         environment file, where credentials are kept\""
    );
    assert_eq!(
        said[4],
        "blocked reason=malformed status=400 peer=127.0.0.1 method=POST path=\"/api/x\" \
         detail=\"both Transfer-Encoding and Content-Length\""
    );
    // The long one is cut at two hundred bytes.
    let cut = format!("path=\"/api/admin/{}...\"", "a".repeat(189));
    assert!(said[7].contains(&cut), "{}", said[7]);
    assert_eq!(app.begun(), 2);

    // What a request could put in a line is written so that it stays one
    // line and inside its quotes.
    assert_eq!(escape("/a b", 200), "/a b");
    assert_eq!(
        escape("/x\r\nblocked reason=fake \"q\" \\ \u{7f}\u{e9}\0", 200),
        "/x\\x0d\\x0ablocked reason=fake \\x22q\\x22 \\x5c \\x7f\\xc3\\xa9\\x00"
    );
    assert_eq!(escape("abcdef", 3), "abc...");
    assert_eq!(escape("abc", 3), "abc");
    assert_eq!(escape("", 3), "");
}

/// Whether `line` is printable ASCII and nothing else.
fn plain(line: &str) -> bool {
    line.bytes().all(|b| matches!(b, b' '..=b'~'))
}

#[tokio::test]
async fn a_request_cannot_put_an_escape_sequence_or_a_line_break_in_the_log() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;
    let requests: [&[u8]; 7] = [
        // A terminal's title, a bell and a screen clear, in the target.
        b"GET /a\x1b]0;owned\x07\x1b[2J HTTP/1.1\r\nHost: a\r\n\r\n",
        // The same, percent-encoded: it decodes to control bytes.
        b"GET /a%1b%5d0%3bowned%07%0d%0ablocked HTTP/1.1\r\nHost: a\r\n\r\n",
        // Bytes that are not ASCII: a letter, a C1 control, a line
        // separator, and one that is not UTF-8 at all.
        b"GET /caf\xc3\xa9\xc2\x9b2J\xe2\x80\xa8 HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET /x\xff\xfe HTTP/1.1\r\nHost: a\r\n\r\n",
        // In a header of a request that is blocked, and in a method.
        b"GET /.env HTTP/1.1\r\nHost: a\r\nX-Evil: \x1b[2J\r\n\r\n",
        b"GE\x1bT /.env HTTP/1.1\r\nHost: a\r\n\r\n",
        // A quote and a backslash, which would end the quotes it is put in.
        b"GET /.env?a=\"%20detail=\"x\\ HTTP/1.1\r\nHost: a\r\n\r\n",
    ];
    for request in requests {
        let answer = waf.ask(request).await;
        assert!(
            [400, 403].contains(&status(&answer)),
            "{:?} -> {answer:?}",
            String::from_utf8_lossy(request)
        );
    }
    let said = waf.lines();
    assert_eq!(said.len(), requests.len(), "one line each: {said:#?}");
    for line in &said {
        assert!(plain(line), "{line:?}");
        assert!(line.starts_with("blocked reason="), "{line}");
        // One `path="…"` and one `detail="…"`, and the line ends with the
        // second: nothing a request sent closed a quote.
        assert_eq!(line.matches('"').count(), 4, "{line}");
        assert!(line.ends_with('"'), "{line}");
    }
    assert!(
        said[6].contains("path=\"/.env?a=\\x22%20detail=\\x22x\\x5c\""),
        "{}",
        said[6]
    );
    assert_eq!(app.begun(), 0);

    // Where every line is written, whatever it was made from: a path
    // pattern of the config may hold any character but an ASCII control,
    // and the system's words for an error are the system's.
    let mut written = Vec::new();
    super::write_line(
        &mut written,
        "listening; deny /caf\u{e9} /a\u{9b}2J /b\u{2028}c\r\nblocked reason=fake \u{1b}[2J\u{7f}",
    );
    super::write_line(&mut written, "blocked reason=probe path=\"/x\\x1b\"");
    assert_eq!(
        String::from_utf8(written).expect("ASCII"),
        "listening; deny /caf\\xc3\\xa9 /a\\xc2\\x9b2J /b\\xe2\\x80\\xa8c\\x0d\\x0ablocked \
         reason=fake \\x1b[2J\\x7f\nblocked reason=probe path=\"/x\\x1b\"\n"
    );
    assert_eq!(super::printable("abcdef", 3), "abc...");
    assert_eq!(super::printable("", 3), "");
}

#[tokio::test]
async fn told_to_stop_it_lets_the_request_in_hand_finish() {
    let app = App::start().await;
    let mut waf = Waf::start(app.address, |_| {}).await;
    // One connection between two requests, and one request in hand.
    let mut idle = TcpStream::connect(waf.address).await.expect("connect");
    idle.write_all(b"GET /api/x HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .expect("send");
    assert_eq!(one(&mut idle).await.0, 200);
    let mut busy = TcpStream::connect(waf.address).await.expect("connect");
    busy.write_all(b"GET /api/slow HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .expect("send");
    app.finished(2).await;

    let address = waf.address;
    let started = Instant::now();
    let stats = waf.stop().await;
    // It waited for the slow answer and no longer: not the ten seconds it
    // would give.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    let answer = rest(&mut busy).await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.ends_with("slow\n"), "{answer}");
    assert_eq!(rest(&mut idle).await, "", "the idle one was closed");
    assert!(
        TcpStream::connect(address).await.is_err(),
        "nothing listens"
    );
    // The stats it leaves are the final ones.
    assert_eq!((stats.requests, stats.forwarded), (2, 2));
    let said = waf.lines();
    assert_eq!(
        said,
        [
            "stopping: no new connections, and up to 10 seconds for the requests in hand",
            "stopped"
        ]
    );
}

#[tokio::test]
async fn the_stats_file_says_what_was_done() {
    let app = App::start().await;
    let mut waf = Waf::start(app.address, |setup| {
        setup.config.allow_paths = vec!["/api/*".to_owned()];
        setup.config.deny_paths = vec!["/api/admin/*".to_owned()];
        setup.config.ban = Some(Ban {
            after: 6,
            window_secs: 60,
            for_secs: 600,
        });
    })
    .await;
    // Written when it starts, before anything is asked.
    let started = Instant::now();
    while !waf.stats.exists() {
        assert!(started.elapsed() < Duration::from_secs(5), "no stats file");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let first =
        WafStats::parse(&std::fs::read_to_string(&waf.stats).expect("read")).expect("stats");
    assert_eq!(first.requests, 0);

    for (request, code) in [
        (get("/api/x"), 200),
        (get("/api/y"), 200),
        (get("/api/admin/x"), 403),
        (get("/other"), 404),
        (get("/api/.git/config"), 403),
        (get("/api/a/../b"), 400),
        ("PATCH /api/x HTTP/1.1\r\nHost: a\r\n\r\n".to_owned(), 405),
        ("GET /api/x HTTP/1.1\r\n\r\n".to_owned(), 400),
    ] {
        assert_eq!(status(&waf.ask(&request).await), code, "{request}");
    }
    // Banned by the sixth: two connections refused.
    assert_eq!(waf.ask(get("/api/x")).await, "");
    assert_eq!(waf.ask(get("/api/x")).await, "");

    let stats = waf.stop().await;
    let text = std::fs::read_to_string(&waf.stats).expect("read");
    let json: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(
        json,
        serde_json::json!({
            "format": 1,
            "since": first.since,
            "requests": 8,
            "forwarded": 2,
            "blocked": {
                "method": 1, "path": 1, "denied": 1, "not_allowed": 1, "probe": 1,
                "rate": 0, "body": 0, "malformed": 1, "banned": 2, "connections": 0,
                "upgrade": 0, "body_timeout": 0
            },
            "banned_now": 1,
            "upstream_errors": 0
        })
    );
    assert_eq!(stats.blocked.banned, 2);
    // RFC 3339, UTC, to the second.
    let since = first.since.as_bytes();
    assert_eq!(since.len(), 20, "{}", first.since);
    assert!(first.since.starts_with("20") && first.since.ends_with('Z'));
    assert_eq!(
        (since[4], since[7], since[10], since[13], since[16]),
        (b'-', b'-', b'T', b':', b':')
    );
}

/// An app that reads a request's head and then says exactly `says`,
/// holding the connection open after it when `hold`.
async fn scripted(says: Vec<u8>, hold: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let says = says.clone();
            tokio::spawn(async move {
                let mut asked = Vec::new();
                let mut piece = [0_u8; 1024];
                while !asked.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut piece).await {
                        Ok(n) if n > 0 => asked.extend_from_slice(&piece[..n]),
                        _ => return,
                    }
                }
                let _ = stream.write_all(&says).await;
                if hold {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            });
        }
    });
    address
}

#[tokio::test]
async fn an_app_that_answers_wrongly_or_stops_inside_its_answer_is_not_passed_on() {
    // Not HTTP, a head larger than the proxy takes, and a change of
    // protocol nobody asked for: each is 502, and none is passed on.
    let mut too_large = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
    too_large.extend(std::iter::repeat_n(b'p', 100_000));
    too_large.extend_from_slice(b"\r\nContent-Length: 2\r\n\r\nok");
    for says in [
        b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
        too_large,
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\nraw"
            .to_vec(),
        Vec::new(),
    ] {
        let waf = Waf::start(scripted(says.clone(), false).await, |_| {}).await;
        let answer = waf.ask(get("/api/x")).await;
        assert_eq!(status(&answer), 502, "{:?}", String::from_utf8_lossy(&says));
        assert!(answer.ends_with("502 Bad Gateway\n"), "{answer}");
        assert!(!answer.contains("raw"), "{answer}");
        assert_eq!(waf.counts().upstream_errors, 1);
    }

    // A whole head and half a body, and then nothing: the client is not
    // left waiting for the rest.
    let half = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhalf of it".to_vec();
    let waf = Waf::start(scripted(half, true).await, |setup| {
        setup.upstream_wait = Duration::from_millis(300);
    })
    .await;
    let started = Instant::now();
    let answer = waf.ask(get("/api/x")).await;
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(status(&answer), 200);
    assert!(
        answer.ends_with("half of it"),
        "cut where the app stopped: {answer}"
    );
}

#[tokio::test]
async fn a_client_that_does_not_take_its_answer_is_cut_off() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.client_wait = Duration::from_millis(300);
    })
    .await;
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(get("/api/huge").as_bytes())
        .await
        .expect("send");
    // Long enough for the system's buffers to fill and the proxy to give
    // up on it; a proxy that waited would have the rest ready after.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let answer = rest(&mut stream).await;
    assert_eq!(status(&answer), 200);
    assert!(
        answer.len() < HUGE,
        "the whole answer arrived: the proxy waited for a client that was not reading"
    );
    // The proxy is none the worse for it.
    assert_eq!(status(&waf.ask(get("/api/x")).await), 200);
}

#[tokio::test]
async fn a_target_hyper_will_not_read_is_refused_as_malformed() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;
    // Bytes a client must percent-encode, in the query and in the path.
    for target in ["/api/x?q=a<b", "/api/x?q=\"a\"", "/api/a`b", "/api/a>b"] {
        let answer = waf.ask(get(target)).await;
        assert_eq!(status(&answer), 400, "{target}: {answer}");
        let line = waf.lines().pop().expect("a line");
        assert!(
            line.starts_with("blocked reason=malformed status=400 peer=127.0.0.1 method=GET "),
            "{line}"
        );
    }
    assert_eq!(app.begun(), 0);
    let counts = waf.counts();
    assert_eq!(
        (counts.requests, counts.blocked.malformed, counts.forwarded),
        (4, 4, 0)
    );
}

#[tokio::test]
async fn a_head_request_is_answered_without_a_body_and_the_connection_goes_on() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.config.methods.push("HEAD".to_owned());
    })
    .await;
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(b"HEAD /api/x HTTP/1.1\r\nHost: a\r\n\r\nGET /api/y HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .expect("send");
    // The head says the length of the body there would be; the next
    // thing on the connection is the next answer.
    let mut bytes = Vec::new();
    let mut piece = [0_u8; 4096];
    let both = async {
        while bytes
            .windows(19)
            .filter(|w| *w == b"hello from the app\n")
            .count()
            < 1
        {
            let n = stream.read(&mut piece).await.expect("read");
            assert!(n > 0, "closed early");
            bytes.extend_from_slice(&piece[..n]);
        }
    };
    tokio::time::timeout(Duration::from_secs(5), both)
        .await
        .expect("both answers");
    let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
    assert_eq!(text.matches("http/1.1 200 ok").count(), 2, "{text}");
    assert_eq!(text.matches("content-length: 19").count(), 2, "{text}");
    assert_eq!(text.matches("hello from the app").count(), 1, "{text}");
    let asked = app.finished(2).await;
    assert_eq!(
        (asked[0].method.as_str(), asked[1].method.as_str()),
        ("HEAD", "GET")
    );

    // A blocked HEAD is answered without a body too.
    let answer = waf.ask("HEAD /.env HTTP/1.1\r\nHost: a\r\n\r\n").await;
    assert_eq!(status(&answer), 403);
    assert!(answer.ends_with("\r\n\r\n"), "{answer:?}");
    assert!(answer.contains("content-length: 14\r\n"), "{answer}");
}

#[tokio::test]
async fn what_follows_a_chunked_request_on_its_connection_is_not_read() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |_| {}).await;
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(
            b"POST /api/echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
              3\r\nabc\r\n0\r\n\r\nGET /api/behind HTTP/1.1\r\nHost: a\r\n\r\n",
        )
        .await
        .expect("send");
    let answer = rest(&mut stream).await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert_eq!(answer.matches("HTTP/1.1 ").count(), 1, "{answer}");
    assert!(answer.ends_with("abc"), "{answer}");
    let asked = app.finished(1).await;
    assert_eq!(asked[0].body, b"abc");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(app.begun(), 1);
}

#[tokio::test]
async fn the_proxy_holds_only_so_many_connections_in_all() {
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| setup.most = 2).await;
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(waf.address).await.expect("connect");
        stream
            .write_all(b"GET /api/x HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .expect("send");
        assert_eq!(one(&mut stream).await.0, 200);
        held.push(stream);
    }
    assert_eq!(
        waf.ask(get("/api/x")).await,
        "",
        "a third is closed unanswered"
    );
    assert_eq!(waf.counts().blocked.connections, 1);
    assert_eq!(app.begun(), 2);
}

#[tokio::test]
async fn many_clients_at_once_are_each_answered() {
    let app = App::start().await;
    let waf = Arc::new(Waf::start(app.address, |_| {}).await);
    let mut clients = Vec::new();
    for n in 0..100 {
        let waf = Arc::clone(&waf);
        clients.push(tokio::spawn(async move {
            let body = format!("client {n}");
            let answer = waf
                .ask(format!(
                    "POST /api/echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: \
                     {}\r\n\r\n{body}",
                    body.len()
                ))
                .await;
            assert_eq!(status(&answer), 200, "{answer}");
            assert!(answer.ends_with(&body), "each its own answer: {answer}");
        }));
    }
    for client in clients {
        client.await.expect("a client");
    }
    assert_eq!(app.begun(), 100);
    let counts = waf.counts();
    assert_eq!((counts.requests, counts.forwarded), (100, 100));
    // Every connection has been given back.
    let started = Instant::now();
    while waf.shared.limits().connections() > 0 {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "connections still counted"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn a_request_that_is_not_getting_through_is_the_fault_of_whoever_holds_it_up() {
    // The client stops halfway through its body, and has longer to do so
    // than the app has to answer: that is not the app being slow.
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.client_wait = Duration::from_millis(700);
        setup.upstream_wait = Duration::from_millis(200);
    })
    .await;
    let started = Instant::now();
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(b"POST /api/echo HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nhalf")
        .await
        .expect("send");
    let answer = rest(&mut stream).await;
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "{:?}",
        started.elapsed()
    );
    assert!(!answer.starts_with("HTTP/1.1 504"), "{answer}");
    assert!(!answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert_eq!(waf.counts().upstream_errors, 0);
    assert!(
        !waf.lines().iter().any(|line| line.starts_with("upstream")),
        "{:?}",
        waf.lines()
    );

    // The app takes the head and then reads no more, while the client
    // sends all it can: that is the app, and the client is told so.
    let deaf = scripted(Vec::new(), true).await;
    let waf = Waf::start(deaf, |setup| {
        setup.config.max_body_bytes = 64 * 1024 * 1024;
        setup.upstream_wait = Duration::from_millis(300);
    })
    .await;
    let started = Instant::now();
    let stream = TcpStream::connect(waf.address).await.expect("connect");
    let (mut reading, mut writing) = stream.into_split();
    let sender = tokio::spawn(async move {
        let head = "POST /api/x HTTP/1.1\r\nHost: a\r\nContent-Length: 33554432\r\n\r\n";
        let _ = writing.write_all(head.as_bytes()).await;
        let piece = vec![b'x'; 64 * 1024];
        for _ in 0..512 {
            if writing.write_all(&piece).await.is_err() {
                break;
            }
        }
    });
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), reading.read_to_end(&mut answer))
        .await
        .expect("answered in time")
        .ok();
    let answer = String::from_utf8_lossy(&answer);
    assert_eq!(status(&answer), 504, "{answer}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(waf.counts().upstream_errors, 1);
    sender.abort();
    // Neither connection is kept for an app that will never take the rest.
    let started = Instant::now();
    while waf.shared.limits().connections() > 0 {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the connection is still held"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn a_client_that_pauses_while_taking_a_long_answer_gets_all_of_it() {
    // The client stops reading for longer than the app is given between
    // two pieces of its answer: the app had nothing asked of it meanwhile,
    // and is not the one cut off.
    let app = App::start().await;
    let waf = Waf::start(app.address, |setup| {
        setup.upstream_wait = Duration::from_millis(200);
    })
    .await;
    let mut stream = TcpStream::connect(waf.address).await.expect("connect");
    stream
        .write_all(get("/api/huge").as_bytes())
        .await
        .expect("send");
    let mut start = vec![0_u8; 64 * 1024];
    stream
        .read_exact(&mut start)
        .await
        .expect("the start of it");
    tokio::time::sleep(Duration::from_millis(700)).await;
    let answer = rest(&mut stream).await;
    let head = String::from_utf8_lossy(&start);
    let head = head.split_once("\r\n\r\n").expect("a head").0;
    assert_eq!(
        start.len() + answer.len(),
        head.len() + 4 + HUGE,
        "all of it"
    );
    assert_eq!(waf.counts().forwarded, 1);
}
