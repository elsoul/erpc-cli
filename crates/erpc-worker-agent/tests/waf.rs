// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-worker-agent waf` as the unit runs it: the built binary, a config
//! file, standard output, a signal and an exit code.

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    reason = "a broken loopback fixture must fail the integration test"
)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use erpc_worker::waf::{WafConfig, WafStats};

/// A secret no log line may hold.
const SECRET: &str = "s3cr3t-T0KEN-do-not-log";

/// An app on loopback that answers every request with `app`, and counts
/// them.
fn app() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the app");
    let address = listener.local_addr().expect("the app's address");
    let asked = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&asked);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut head = Vec::new();
            let mut piece = [0_u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut piece) {
                    Ok(n) if n > 0 => head.extend_from_slice(&piece[..n]),
                    _ => break,
                }
            }
            count.fetch_add(1, Ordering::SeqCst);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\napp");
        }
    });
    (address, asked)
}

/// A port nothing listens on: bound, read, and let go.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

/// The proxy, running, with what it has written to standard output.
struct Running {
    child: Child,
    said: Receiver<String>,
    listen: SocketAddr,
}

impl Running {
    /// Starts the built agent on `config` and waits until it listens.
    fn start(config: &Path, listen: SocketAddr) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_erpc-worker-agent"))
            .args(["waf", "--config"])
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start the agent");
        let stdout = child.stdout.take().expect("its standard output");
        let (lines, said) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if lines.send(line).is_err() {
                    break;
                }
            }
        });
        let first = said
            .recv_timeout(Duration::from_secs(20))
            .expect("a line when it starts");
        assert!(
            first.starts_with(&format!("listening on {listen}, forwarding to 127.0.0.1:")),
            "{first}"
        );
        Self {
            child,
            said,
            listen,
        }
    }

    /// One request on a connection of its own, and everything answered.
    fn ask(&self, request: &str) -> String {
        let mut stream = TcpStream::connect(self.listen).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        stream.write_all(request.as_bytes()).expect("send");
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        answer
    }

    /// Sends `signal`, waits for the process to end, and returns its exit
    /// code and everything it wrote to standard output after its first
    /// line.
    fn stop(mut self, signal: rustix::process::Signal) -> (Option<i32>, Vec<String>) {
        let pid = rustix::process::Pid::from_child(&self.child);
        rustix::process::kill_process(pid, signal).expect("signal it");
        let started = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("wait") {
                break status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "it did not stop"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        // The sender ends with its standard output.
        (status.code(), self.said.iter().collect())
    }
}

/// A config for `listen` and `upstream`, written in `dir`.
fn config(dir: &Path, listen: SocketAddr, upstream: SocketAddr) -> std::path::PathBuf {
    let mut config = WafConfig::default_for("bot-prod", listen, upstream);
    config.stats_path = dir.join("stats.json").to_string_lossy().into_owned();
    config.deny_paths = vec!["/api/admin/*".to_owned()];
    config.validate().expect("a valid config");
    let path = dir.join("waf.json");
    std::fs::write(&path, serde_json::to_string_pretty(&config).expect("json"))
        .expect("write the config");
    path
}

#[test]
fn it_serves_logs_writes_its_stats_and_stops_with_exit_0_on_sigterm() {
    let dir = tempfile::tempdir().expect("tmp");
    let (upstream, asked) = app();
    let listen: SocketAddr = format!("127.0.0.1:{}", free_port())
        .parse()
        .expect("listen");
    let running = Running::start(&config(dir.path(), listen, upstream), listen);

    let auth = format!("Authorization: Bearer {SECRET}\r\nConnection: close\r\n");
    let answer = running.ask(&format!(
        "GET /api/trades/123?limit=10 HTTP/1.1\r\nHost: bot.example\r\n{auth}\r\n"
    ));
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.ends_with("app"), "{answer}");
    assert_eq!(asked.load(Ordering::SeqCst), 1);

    for (request, status) in [
        (
            format!("GET /.env HTTP/1.1\r\nHost: bot.example\r\n{auth}\r\n"),
            "403",
        ),
        (
            format!(
                "GET /api/admin/keys?token={SECRET} HTTP/1.1\r\nHost: bot.example\r\n{auth}\r\n"
            ),
            "403",
        ),
        (
            format!(
                "POST /api/x HTTP/1.1\r\nHost: bot.example\r\n{auth}Content-Length: \
                 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ),
            "400",
        ),
    ] {
        let answer = running.ask(&request);
        assert!(
            answer.starts_with(&format!("HTTP/1.1 {status} ")),
            "{request:?} -> {answer:?}"
        );
    }
    assert_eq!(
        asked.load(Ordering::SeqCst),
        1,
        "none of them reached the app"
    );

    let (code, said) = running.stop(rustix::process::Signal::TERM);
    assert_eq!(code, Some(0), "{said:?}");
    assert_eq!(
        said,
        [
            "blocked reason=probe status=403 peer=127.0.0.1 method=GET path=\"/.env\" \
             detail=\"an environment file, where credentials are kept\""
                .to_owned(),
            format!(
                "blocked reason=denied status=403 peer=127.0.0.1 method=GET \
                 path=\"/api/admin/keys?token={SECRET}\" detail=\"the path is denied\""
            ),
            "blocked reason=malformed status=400 peer=127.0.0.1 method=POST path=\"/api/x\" \
             detail=\"both Transfer-Encoding and Content-Length\""
                .to_owned(),
            "stopping: no new connections, and up to 10 seconds for the requests in hand"
                .to_owned(),
            "stopped".to_owned(),
        ]
    );
    // A header never reaches the log. A query does, up to two hundred
    // bytes of the target: that is said where the log is described.
    for line in &said {
        assert!(!line.contains("Bearer"), "{line}");
        assert!(
            !line.to_ascii_lowercase().contains("authorization"),
            "{line}"
        );
    }

    let stats = dir.path().join("stats.json");
    let read =
        WafStats::parse(&std::fs::read_to_string(&stats).expect("the stats file")).expect("stats");
    assert_eq!((read.requests, read.forwarded), (4, 1));
    assert_eq!(
        (
            read.blocked.probe,
            read.blocked.denied,
            read.blocked.malformed
        ),
        (1, 1, 1)
    );
    let mode = std::fs::metadata(&stats)
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);
    let mut left: Vec<_> = std::fs::read_dir(dir.path())
        .expect("dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    left.sort();
    assert_eq!(left, ["stats.json", "waf.json"]);
    assert!(
        TcpStream::connect(listen).is_err(),
        "nothing listens any more"
    );
}

#[test]
fn it_stops_with_exit_0_on_sigint_too() {
    let dir = tempfile::tempdir().expect("tmp");
    let (upstream, _) = app();
    let listen: SocketAddr = format!("127.0.0.1:{}", free_port())
        .parse()
        .expect("listen");
    let running = Running::start(&config(dir.path(), listen, upstream), listen);
    let (code, said) = running.stop(rustix::process::Signal::INT);
    assert_eq!(code, Some(0), "{said:?}");
    assert_eq!(said.last().map(String::as_str), Some("stopped"));
}

#[test]
fn a_config_it_cannot_serve_ends_it_before_it_listens() {
    let dir = tempfile::tempdir().expect("tmp");
    let agent = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_erpc-worker-agent"));
        command.stdin(Stdio::null());
        command
    };
    let run = |path: &Path| {
        let out = agent()
            .args(["waf", "--config"])
            .arg(path)
            .output()
            .expect("run the agent");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    // No file, a file that is not a config, and a config that names an
    // upstream on another machine: exit 2, and why.
    let (code, stdout, stderr) = run(&dir.path().join("absent.json"));
    assert_eq!((code, stdout.as_str()), (Some(2), ""), "{stderr}");
    assert!(stderr.contains("could not open it"), "{stderr}");

    let path = dir.path().join("waf.json");
    std::fs::write(&path, "{}").expect("write");
    let (code, stdout, stderr) = run(&path);
    assert_eq!((code, stdout.as_str()), (Some(2), ""), "{stderr}");
    assert!(stderr.contains("not valid"), "{stderr}");

    let listen: SocketAddr = format!("127.0.0.1:{}", free_port())
        .parse()
        .expect("listen");
    let good = config(
        dir.path(),
        listen,
        "127.0.0.1:3000".parse().expect("upstream"),
    );
    let text = std::fs::read_to_string(&good).expect("read");
    std::fs::write(&path, text.replace("127.0.0.1:3000", "198.51.100.7:3000")).expect("write");
    let (code, _, stderr) = run(&path);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("not a loopback address"), "{stderr}");

    // A port that is taken: exit 1.
    let taken = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = taken.local_addr().expect("address").port();
    std::fs::write(
        &path,
        text.replace(&listen.to_string(), &format!("127.0.0.1:{port}")),
    )
    .expect("write");
    let (code, stdout, stderr) = run(&path);
    assert_eq!((code, stdout.as_str()), (Some(1), ""), "{stderr}");
    assert!(stderr.contains("could not listen on"), "{stderr}");

    // And `waf` needs its config named.
    let out = agent().arg("waf").output().expect("run the agent");
    assert_eq!(out.status.code(), Some(2));
}
