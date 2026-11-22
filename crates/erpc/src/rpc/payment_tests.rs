// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the production payment exchange against a loopback x402 server.

use super::{Call, Outcome, STANDARD, Url, Value, json, send_request};
use base64::Engine as _;
use erpc_wallet::eurc::{EURC_CONTRACT, TREASURY};
use erpc_wallet::evm::EvmKey;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[derive(Clone, Copy)]
enum Reply {
    Success,
    Disconnect,
    Http500,
    AnotherChallenge,
}

#[derive(Clone, Copy)]
enum Challenge {
    Header,
    Body,
    InvalidBase64,
    InvalidJson,
}

struct Request {
    body: Value,
    payment: Option<Value>,
}

async fn read_request(socket: &mut TcpStream) -> Request {
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    let mut length = None;
    let mut payment = None;
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).await.expect("headers"), 0);
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.trim().parse().expect("content length"));
            }
            if name.eq_ignore_ascii_case("payment-signature") {
                let decoded = STANDARD.decode(value.trim()).expect("encoded proof");
                payment = Some(serde_json::from_slice(&decoded).expect("JSON proof"));
            }
        }
    }
    let mut body = vec![0; length.expect("body length")];
    reader.read_exact(&mut body).await.expect("body");
    Request {
        body: serde_json::from_slice(&body).expect("RPC JSON"),
        payment,
    }
}

async fn serve(
    listener: TcpListener,
    mut stop: oneshot::Receiver<()>,
    url: Url,
    retry: Reply,
    offer: Challenge,
) -> Vec<Request> {
    let challenge = json!({"x402Version":2,"resource":{"url":url.as_str()},"accepts":[{
        "scheme":"exact","network":"eip155:8453","asset":EURC_CONTRACT,"payTo":TREASURY,
        "amount":"1000","maxTimeoutSeconds":120,"extra":{"name":"EURC","version":"2",
        "erpc":{"methods":["getSlot"]}}
    }]});
    let mut seen = Vec::new();
    loop {
        let (mut socket, _) = tokio::select! {
            () = async { let _ = (&mut stop).await; } => break,
            incoming = listener.accept() => incoming.expect("connection"),
        };
        seen.push(read_request(&mut socket).await);
        let (status, body, fields) = if seen.len() == 1 || matches!(retry, Reply::AnotherChallenge)
        {
            // Malformed headers accompany a valid body so a silent fallback would pay.
            let fields = match offer {
                Challenge::Header => format!(
                    "Payment-Required: {}\r\n",
                    STANDARD.encode(challenge.to_string())
                ),
                Challenge::Body => String::new(),
                Challenge::InvalidBase64 => "Payment-Required: %%%\r\n".into(),
                Challenge::InvalidJson => {
                    format!("Payment-Required: {}\r\n", STANDARD.encode("not json"))
                }
            };
            let body = if matches!(offer, Challenge::Header) {
                json!({"error":"payment required"})
            } else {
                challenge.clone()
            };
            ("402 Payment Required", body, fields)
        } else {
            match retry {
                Reply::Disconnect => continue,
                Reply::Success => (
                    "200 OK",
                    json!({"jsonrpc":"2.0","id":1,"result":17}),
                    String::new(),
                ),
                Reply::Http500 => ("500 Internal Server Error", Value::Null, String::new()),
                Reply::AnotherChallenge => unreachable!(),
            }
        };
        let body = body.to_string();
        let response = format!(
            "HTTP/1.1 {status}\r\n{fields}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("response");
    }
    seen
}

struct Exchange {
    result: Result<Value, Outcome>,
    requests: Vec<Request>,
    confirmations: usize,
    key_reads: usize,
}

#[derive(Clone, Copy)]
enum Mode {
    Quote,
    NoTerminal,
    Json,
    Decline,
    Approve,
}

async fn exchange(mode: Mode, retry: Reply, offer: Challenge) -> Exchange {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listen");
    let url = Url::parse(&format!(
        "http://127.0.0.1:{}/v1/solana-mainnet",
        listener.local_addr().expect("address").port()
    ))
    .expect("URL");
    let (stop, rx) = oneshot::channel();
    let server = tokio::spawn(serve(listener, rx, url.clone(), retry, offer));
    let call = Call {
        method: "getSlot".into(),
        params: None,
        params_file: None,
        network: None,
        endpoint_url: None,
        x402: true,
        quote: matches!(mode, Mode::Quote),
    };
    let body = json!({"id":1,"jsonrpc":"2.0","method":"getSlot","params":[]});
    let mut confirmations = 0;
    let mut key_reads = 0;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        send_request(
            &call,
            &url,
            &body,
            !matches!(mode, Mode::NoTerminal),
            matches!(mode, Mode::Json),
            |prompt| {
                confirmations += 1;
                assert!(prompt.contains("0.001000 EURC") && prompt.contains("getSlot"));
                Ok(!matches!(mode, Mode::Decline))
            },
            || {
                key_reads += 1;
                EvmKey::generate().map_err(|e| e.to_string())
            },
        ),
    )
    .await
    .expect("request completed");
    stop.send(()).expect("server running");
    let requests = server.await.expect("server");
    assert!(requests.iter().all(|r| r.body == body));
    assert!(requests[0].payment.is_none());
    Exchange {
        result,
        requests,
        confirmations,
        key_reads,
    }
}

#[tokio::test]
async fn quotes_and_refusals_never_read_a_wallet_or_send_a_payment() {
    for mode in [Mode::Quote, Mode::NoTerminal, Mode::Json, Mode::Decline] {
        let e = exchange(mode, Reply::Success, Challenge::Header).await;
        let confirmations = usize::from(matches!(mode, Mode::Decline));
        match mode {
            Mode::Quote => assert_eq!(e.result.expect("quote")["paid"], false),
            Mode::NoTerminal | Mode::Json => {
                assert!(matches!(e.result, Err(Outcome::NeedsTerminal(_))));
            }
            Mode::Decline => assert!(matches!(e.result, Err(Outcome::Failed(_)))),
            Mode::Approve => unreachable!(),
        }
        assert_eq!(
            (e.confirmations, e.key_reads, e.requests.len()),
            (confirmations, 0, 1)
        );
    }
}

#[tokio::test]
async fn a_paid_request_is_sent_once_even_when_the_response_is_lost_or_rejected() {
    for retry in [
        Reply::Success,
        Reply::Disconnect,
        Reply::Http500,
        Reply::AnotherChallenge,
    ] {
        let e = exchange(Mode::Approve, retry, Challenge::Body).await;
        assert_eq!((e.confirmations, e.key_reads, e.requests.len()), (1, 1, 2));
        let proof = e.requests[1].payment.as_ref().expect("paid retry");
        assert_eq!(proof["payload"]["authorization"]["value"], "1000");
        assert!(
            proof["payload"]["signature"]
                .as_str()
                .is_some_and(|s| s.len() == 132)
        );
        if matches!(retry, Reply::Success) {
            assert_eq!(e.result.expect("paid result")["result"], 17);
        } else {
            let err = e
                .result
                .expect_err("failed paid response")
                .error()
                .expect("operator error");
            assert!(err.text().contains("Check the wallet before paying again"));
        }
    }
}

#[test]
fn shared_websocket_targets_carry_the_account_key_only_on_the_selected_host() {
    for (network, host) in [
        (super::Network::SolanaMainnet, "edge.erpc.global"),
        (super::Network::EthereumMainnet, "eth.erpc.global"),
    ] {
        let url = network
            .shared_url("sample&key", true)
            .expect("shared endpoint");
        assert_eq!(url.scheme(), "wss");
        assert_eq!(url.host_str(), Some(host));
        assert_eq!(url.path(), "/");
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![("api-key".into(), "sample&key".into())]
        );
    }
}

#[tokio::test]
async fn a_malformed_challenge_header_never_falls_back_to_a_payable_body() {
    for offer in [Challenge::InvalidBase64, Challenge::InvalidJson] {
        let e = exchange(Mode::Approve, Reply::Success, offer).await;
        assert!(matches!(e.result, Err(Outcome::Failed(_))));
        assert_eq!((e.confirmations, e.key_reads, e.requests.len()), (0, 0, 1));
    }
}
