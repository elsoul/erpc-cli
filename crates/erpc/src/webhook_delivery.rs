// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Deliver notifications only after the RPC acknowledges this subscription ID.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use reqwest::Url;
use serde_json::{Value, json};
use tokio::time::{interval, timeout};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

use crate::commands::Outcome;
use crate::rpc_call::{Network, client, network_error, operator_url};
use crate::webhook::{Hook, Registry};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

fn failed(message: &str) -> Outcome {
    Outcome::Failed(message.to_owned())
}

fn runner_lock(path: &Path, id: u64) -> Result<File, Outcome> {
    // A stable sidecar keeps two processes from posting the same live stream.
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .open(path.with_file_name(format!("webhook-{id}.lock")))
        .map_err(|e| failed(&e.to_string()))?;
    lock.try_lock()
        .map_err(|_| failed("another runner owns this webhook or its lock is unavailable"))?;
    Ok(lock)
}

async fn next_json(socket: &mut Socket) -> Result<Value, Outcome> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text)
                    .map_err(|_| failed("RPC sent an invalid JSON frame"));
            }
            Some(Ok(Message::Ping(_))) => socket
                .flush()
                .await
                .map_err(|_| failed("RPC heartbeat failed"))?,
            Some(Ok(Message::Pong(_))) => (),
            _ => return Err(failed("RPC WebSocket closed or sent an unsupported frame")),
        }
    }
}

async fn subscribe(url: &Url, hook: &Hook) -> Result<(Socket, Value), Outcome> {
    let (mut socket, _) = connect_async(url.as_str())
        .await
        .map_err(|_| failed("could not open the RPC WebSocket"))?;
    let request = json!({"jsonrpc":"2.0","id":1,"method":hook.method,"params":hook.params});
    socket
        .send(Message::Text(request.to_string().into()))
        .await
        .map_err(|_| failed("could not send the subscription"))?;
    let reply = next_json(&mut socket).await?;
    if reply["id"] != 1
        || reply["jsonrpc"] != "2.0"
        || reply.get("error").is_some()
        || !(reply["result"].is_string() || reply["result"].is_u64())
    {
        return Err(failed(
            "RPC rejected the subscription or returned an invalid subscription ID",
        ));
    }
    Ok((socket, reply["result"].clone()))
}

fn enabled(path: &Path, id: u64, generation: u64) -> Result<bool, Outcome> {
    Ok(Registry::read(path)
        .map_err(Outcome::Failed)?
        .hooks
        .get(&id)
        .is_some_and(|h| h.enabled && h.generation == generation))
}

pub(crate) async fn run(
    path: &Path,
    id: u64,
    endpoint: Option<&str>,
    once: bool,
) -> Result<Value, Outcome> {
    let hook = Registry::read(path)
        .map_err(Outcome::Failed)?
        .hooks
        .remove(&id)
        .ok_or_else(|| Outcome::Usage("unknown webhook id".into()))?;
    if !hook.enabled {
        return Err(failed("webhook is paused"));
    }
    let _lock = runner_lock(path, id)?;
    let callback = operator_url(&hook.url, false).map_err(Outcome::Usage)?;
    let url = if let Some(raw) = endpoint {
        operator_url(raw, true).map_err(Outcome::Usage)?
    } else {
        hook.network.account_url(true).await?
    };
    let (mut socket, subscription) = timeout(Duration::from_secs(30), subscribe(&url, &hook))
        .await
        .map_err(|_| failed("timed out subscribing to RPC"))??;
    let method = match hook.network {
        Network::EthereumMainnet => "eth_subscription".into(),
        Network::SolanaMainnet => {
            format!("{}Notification", hook.method.trim_end_matches("Subscribe"))
        }
    };
    let client = client()?;
    let mut pulse = interval(Duration::from_secs(1));
    let mut delivered = 0u64;
    loop {
        let event = tokio::select! {
            _ = pulse.tick() => {
                if !enabled(path, id, hook.generation)? { break; }
                continue;
            },
            frame = next_json(&mut socket) => frame?,
        };
        if event["jsonrpc"] != "2.0"
            || event["method"] != method
            || event["params"]["subscription"] != subscription
            || event["params"].get("result").is_none()
        {
            continue;
        }
        if !enabled(path, id, hook.generation)? {
            break;
        }
        let payload = json!({"webhook_id":id,"network":hook.network,"notification":event});
        let response = client
            .post(callback.clone())
            .json(&payload)
            .send()
            .await
            .map_err(network_error)?;
        if !response.status().is_success() {
            return Err(failed(&format!(
                "callback returned HTTP {}",
                response.status()
            )));
        }
        delivered += 1;
        if once {
            break;
        }
    }
    Ok(json!({"id":id,"delivered":delivered}))
}
