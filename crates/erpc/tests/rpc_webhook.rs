// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the shipped command parser, HTTP client and WebSocket delivery together.

#![allow(
    clippy::expect_used,
    reason = "a broken loopback fixture must fail the integration test"
)]

use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{Message, accept};

fn cli(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_erpc"))
        .env("ERPC_HOME", home)
        .env_remove("ERPC_CHAIN")
        .env_remove("ERPC_JSON")
        .args(["--json", "--lang", "en"])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run CLI")
}

fn success(home: &Path, args: &[&str]) -> Value {
    let result = cli(home, args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    serde_json::from_slice(&result.stdout).expect("JSON stdout")
}

fn listen() -> TcpListener {
    TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback")
}

fn http(listener: &TcpListener, reply: &str) -> Value {
    let (mut stream, _) = listener.accept().expect("accept");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let mut reader = BufReader::new(&stream);
    let mut length = None;
    for line in reader.by_ref().lines() {
        let line = line.expect("header");
        if line.is_empty() {
            break;
        }
        let lc = line.to_ascii_lowercase();
        if let Some(size) = lc.strip_prefix("content-length: ") {
            length = Some(size.parse::<usize>().expect("length"));
        }
        assert!(
            !lc.contains("authorization:")
                && !lc.contains("api-key=")
                && !lc.contains("payment-signature:")
        );
    }
    let mut body = vec![0; length.expect("request length")];
    reader.read_exact(&mut body).expect("request");
    write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",reply.len()).expect("reply");
    serde_json::from_slice(&body).expect("body")
}

#[test]
fn call_sends_params_and_treats_rpc_errors_as_failures() {
    let home = tempfile::tempdir().expect("home");
    for (reply, ok) in [
        (json!({"jsonrpc":"2.0","id":1,"result":null}), true),
        (
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}),
            false,
        ),
    ] {
        let server = listen();
        let url = format!(
            "http://127.0.0.1:{}",
            server.local_addr().expect("addr").port()
        );
        let receiving = thread::spawn(move || http(&server, &reply.to_string()));
        let result = cli(
            home.path(),
            &["rpc", "call", "test", r#"{"n":42}"#, "--endpoint-url", &url],
        );
        assert_eq!(
            result.status.success(),
            ok,
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        assert_eq!(
            receiving.join().expect("receive"),
            json!({"jsonrpc":"2.0","id":1,"method":"test","params":{"n":42}})
        );
    }
    assert!(
        !cli(home.path(), &["r", "call", "getSlot", "42"])
            .status
            .success()
    );
    let help = cli(home.path(), &["r", "call", "--help"]);
    assert!(
        help.status.success() && String::from_utf8_lossy(&help.stdout).contains("--params-file")
    );
}

#[test]
fn local_webhook_matches_subscription_and_manages_its_lifecycle() {
    let home = tempfile::tempdir().expect("home");
    let cb = listen();
    let callback = format!(
        "http://127.0.0.1:{}/private-callback",
        cb.local_addr().expect("addr").port()
    );
    let hook = success(
        home.path(),
        &[
            "webhook",
            "create",
            "--name",
            "slots",
            "--network",
            "solana-mainnet",
            "--url",
            &callback,
            "--method",
            "slotSubscribe",
        ],
    );
    assert_eq!(hook["id"], 1);
    assert!(!hook.to_string().contains("private-callback"));
    let ws = listen();
    let url = format!("ws://127.0.0.1:{}", ws.local_addr().expect("addr").port());
    let posted = thread::spawn(move || http(&cb, "{}"));
    let subscription = thread::spawn(move || {
        let (stream, _) = ws.accept().expect("socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut ws = accept(stream).expect("websocket");
        let request: Value =
            serde_json::from_str(ws.read().expect("request").to_text().expect("text"))
                .expect("json");
        assert_eq!(
            request,
            json!({"jsonrpc":"2.0","id":1,"method":"slotSubscribe","params":[]})
        );
        for frame in [
            json!({"jsonrpc":"2.0","id":1,"result":7}),
            json!({"jsonrpc":"2.0","method":"slotNotification","params":{"subscription":99,"result":0}}),
            json!({"jsonrpc":"2.0","method":"slotNotification","params":{"subscription":7,"result":{"slot":42}}}),
        ] {
            ws.send(Message::Text(frame.to_string().into()))
                .expect("send frame");
        }
    });
    let report = success(
        home.path(),
        &["webhook", "run", "1", "--endpoint-url", &url, "--once"],
    );
    assert_eq!(report["delivered"], 1);
    subscription.join().expect("subscription");
    let posted = posted.join().expect("callback");
    assert_eq!(posted["notification"]["params"]["result"]["slot"], 42);
    assert_eq!(posted["webhook_id"], 1);
    assert!(
        !cli(home.path(), &["webhook", "pause", "1"])
            .status
            .success()
    );
    assert_eq!(
        success(home.path(), &["webhook", "pause", "1", "--yes"])["enabled"],
        false
    );
    assert!(!cli(home.path(), &["webhook", "run", "1"]).status.success());
    assert_eq!(
        success(home.path(), &["webhook", "enabled-count"])["enabled"],
        0
    );
    assert_eq!(
        success(home.path(), &["webhook", "activate", "1", "--yes"])["enabled"],
        true
    );
    assert_eq!(
        success(home.path(), &["webhook", "show", "1"])["name"],
        "slots"
    );
    success(home.path(), &["webhook", "delete", "1", "--yes"]);
    assert_eq!(success(home.path(), &["webhook", "list"]), json!([]));
}

#[test]
fn templates_build_chain_specific_subscriptions() {
    let home = tempfile::tempdir().expect("home");
    let account = "11111111111111111111111111111111";
    let contract = "0x0000000000000000000000000000000000000001";
    let cases = [
        (
            "solana-mainnet",
            "solana-wallet",
            account,
            "logsSubscribe",
            json!([{"mentions":[account]},{"commitment":"confirmed"}]),
        ),
        (
            "ethereum-mainnet",
            "evm-contract-events",
            contract,
            "eth_subscribe",
            json!(["logs",{"address":contract}]),
        ),
    ];
    for (network, template, address, method, params) in cases {
        let reply = success(
            home.path(),
            &[
                "webhook",
                "create",
                "--name",
                "events",
                "--network",
                network,
                "--url",
                "http://127.0.0.1/events",
                "--template",
                template,
                "--address",
                address,
            ],
        );
        assert_eq!(reply["method"], method);
        assert_eq!(reply["params"], params);
    }
}
