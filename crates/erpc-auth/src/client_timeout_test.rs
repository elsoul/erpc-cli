// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Token-free loopback fixtures for JSON response limits.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use super::{HttpError, JsonResponseLimits, json_request, send_json};

fn limits(timeout: Duration) -> JsonResponseLimits {
    JsonResponseLimits {
        timeout,
        ok_bytes: 16 * 1024,
        other_bytes: 1024,
    }
}

async fn loopback_json(
    limits: Option<JsonResponseLimits>,
    respond: impl FnOnce(&mut TcpStream) + Send + 'static,
) -> Result<(u16, String), HttpError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let port = listener.local_addr().expect("loopback address").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("local request");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("bounded fixture read");
        let mut headers = BufReader::new(&mut stream);
        let mut line = String::new();
        loop {
            line.clear();
            if headers.read_line(&mut line).expect("request headers") == 0 || line == "\r\n" {
                break;
            }
        }
        respond(&mut stream);
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(200))
        .build()
        .expect("loopback fixture client");
    let request = client.post(format!("http://127.0.0.1:{port}/"));
    let response = send_json(request, "127.0.0.1", limits).await;
    server.join().expect("loopback fixture finished");
    response
}

async fn delayed_json(timeout: Option<Duration>) -> Result<(u16, String), HttpError> {
    loopback_json(timeout.map(limits), |stream| {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
            .expect("response headers");
        // Delay the body, so the test covers the entire transfer deadline.
        thread::sleep(Duration::from_millis(500));
        let _ = stream.write_all(b"{}");
    })
    .await
}

#[tokio::test]
async fn json_request_caps_chunked_bodies_by_status_before_the_end_of_the_stream() {
    for (status, maximum) in [(200, 16 * 1024), (403, 1024)] {
        for overflow in [false, true] {
            let received = loopback_json(Some(limits(Duration::from_secs(3))), move |stream| {
                write!(
                    stream,
                    "HTTP/1.1 {status} Fixture\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                .expect("chunked headers");
                let chunk = vec![b' '; maximum / 4];
                for _ in 0..4 {
                    write!(stream, "{:x}\r\n", chunk.len()).expect("chunk size");
                    stream.write_all(&chunk).expect("chunk bytes");
                    stream.write_all(b"\r\n").expect("chunk ending");
                }
                // For overflow, deliberately omit the terminator. Reading
                // through EOF instead of stopping at the cap would fail.
                let ending: &[u8] = if overflow {
                    b"1\r\nx\r\n"
                } else {
                    b"0\r\n\r\n"
                };
                stream.write_all(ending).expect("fixture ending");
            })
            .await;
            if overflow {
                assert!(
                    matches!(received, Err(HttpError::ResponseLimit { status: found, .. }) if found == status)
                );
            } else {
                let (received_status, body) = received.expect("exact byte limit");
                assert_eq!(received_status, status);
                assert_eq!(body.len(), maximum);
            }
        }
    }
}

#[tokio::test]
async fn json_request_reports_a_broken_bounded_body_as_transport_failure() {
    let result = loopback_json(Some(limits(Duration::from_secs(3))), |stream| {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}")
            .expect("short fixture");
    })
    .await;
    assert!(matches!(result, Err(HttpError::Transport { .. })));
}

#[tokio::test]
async fn json_request_override_allows_a_body_delayed_past_the_default_deadline() {
    let default = delayed_json(None).await.expect("default headers arrived");
    // Preserve the legacy helper's empty-body fallback for existing callers.
    assert_eq!(default, (200, String::new()));
    let paid = delayed_json(Some(Duration::from_secs(3)))
        .await
        .expect("longer deadline allows the body");
    assert_eq!(paid, (200, "{}".into()));
}

#[tokio::test]
async fn json_request_explicit_timeout_is_reported_when_the_body_stalls() {
    assert!(matches!(
        delayed_json(Some(Duration::from_millis(200))).await,
        Err(HttpError::Timeout { host: "127.0.0.1" })
    ));
}

#[test]
fn json_post_attaches_the_supplied_idempotency_header_and_preserves_the_body() {
    let request = json_request(
        reqwest::Client::new().post(erpc_core::endpoints::SECURITY_CHECK_REPORT_URL),
        &secrecy::SecretString::from("test-only"),
        br#"{"requestId":"fixture-id"}"#.to_vec(),
        Some("fixture-id"),
    )
    .build()
    .expect("JSON request");
    assert_eq!(request.headers()["idempotency-key"], "fixture-id");
    assert_eq!(request.headers()["content-type"], "application/json");
    let body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .expect("unchanged bytes");
    let body: serde_json::Value = serde_json::from_slice(body).expect("JSON body");
    assert_eq!(
        body["requestId"],
        request.headers()["idempotency-key"]
            .to_str()
            .expect("header")
    );
}
