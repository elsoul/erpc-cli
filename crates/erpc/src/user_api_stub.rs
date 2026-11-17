// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A loopback HTTP server that stands in for user-api in tests, and the
//! plain client that reaches it.
//!
//! The session's own client sends a token to user-api over TLS and nowhere
//! else, so it cannot be pointed here. A stubbed [`super::Api`] sends the
//! same requests (the path and query of the URL it would have read, the
//! body it would have put) with this client and no token, and reads the
//! reply with the functions the real one reads user-api's with
//! (`erpc_api::account::read_reply`, `udp_forwarding_reply`). What a test
//! then covers is the conversation: which routes are asked, in which
//! order, and what each answer leads to.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// A request the stub got.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Request {
    pub(crate) method: String,
    /// The path, with its query.
    pub(crate) path: String,
    /// The JSON body; null without one.
    pub(crate) body: Value,
}

/// The server, for as long as it is held.
pub(crate) struct Stub {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Request>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Stub {
    /// Serves on a loopback port of the system's choosing. `answer` gets
    /// each request and returns the status and the JSON body of the reply.
    pub(crate) async fn serve(
        mut answer: impl FnMut(&Request) -> (u16, Value) + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("its address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kept = seen.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let Some(request) = read_request(&mut socket).await else {
                    continue;
                };
                let (status, body) = answer(&request);
                kept.lock().expect("requests").push(request);
                let body = body.to_string();
                let reply = format!(
                    "HTTP/1.1 {status} stub\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            }
        });
        Self { addr, seen, task }
    }

    /// A session whose requests come here.
    pub(crate) fn api(&self) -> super::Api {
        super::Api::stubbed(self.addr)
    }

    /// Every request so far, in order.
    pub(crate) fn seen(&self) -> Vec<Request> {
        self.seen.lock().expect("requests").clone()
    }

    /// The requests so far as `METHOD path`, in order.
    pub(crate) fn asked(&self) -> Vec<String> {
        self.seen()
            .iter()
            .map(|r| format!("{} {}", r.method, r.path))
            .collect()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(socket: &mut TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line).await.ok()?;
    let mut words = line.split_whitespace();
    let (method, path) = (words.next()?.to_owned(), words.next()?.to_owned());
    let mut length = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line).await.ok()? == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.ok()?;
    Some(Request {
        method,
        path,
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    })
}

/// Sends `method` for the path and query of `url` to the stub at `stub`,
/// with `body` as JSON when there is one: the reply's status and body.
pub(crate) async fn send(
    stub: SocketAddr,
    method: &str,
    url: &str,
    body: Option<&Value>,
) -> (u16, String) {
    let path = url
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .expect("an absolute URL with a path");
    let body = body.map(Value::to_string).unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nhost: {stub}\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut socket = TcpStream::connect(stub).await.expect("the stub listens");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("the request");
    let mut reply = String::new();
    socket.read_to_string(&mut reply).await.expect("the reply");
    let (head, body) = reply.split_once("\r\n\r\n").expect("a reply with a body");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("a status");
    (status, body.to_owned())
}
