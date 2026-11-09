// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! One JSON-RPC request, separate from the chain-specific node lifecycle.

use std::io::Read as _;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args, ValueEnum};
use erpc_core::endpoints::{ETH_RPC_URL, SHARED_RPC_URL, X402_ETH_URL, X402_SOLANA_URL};
use reqwest::{Client, Response, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::commands::Outcome;

#[derive(Clone, Copy, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Network {
    SolanaMainnet,
    #[value(alias = "eth-mainnet")]
    EthereumMainnet,
}

impl Network {
    fn paid_url(self) -> &'static str {
        match self {
            Self::SolanaMainnet => X402_SOLANA_URL,
            Self::EthereumMainnet => X402_ETH_URL,
        }
    }

    fn shared_url(self, key: &str, websocket: bool) -> Result<Url, Outcome> {
        let base = match self {
            Self::SolanaMainnet => SHARED_RPC_URL,
            Self::EthereumMainnet => ETH_RPC_URL,
        };
        let mut url = Url::parse(base).map_err(|e| Outcome::Failed(e.to_string()))?;
        if websocket {
            url.set_scheme("wss")
                .map_err(|()| Outcome::Failed("invalid shared WebSocket endpoint".into()))?;
        }
        url.query_pairs_mut().append_pair("api-key", key);
        Ok(url)
    }

    pub(crate) async fn account_url(self, websocket: bool) -> Result<Url, Outcome> {
        let api = crate::worker_vps::Api::open()
            .await
            .map_err(Outcome::from)?;
        let key = crate::worker_vps::shared_api_key(&api)
            .await
            .map_err(Outcome::from)?;
        self.shared_url(&key, websocket)
    }
}

#[derive(Args)]
pub(crate) struct Call {
    /// JSON-RPC method, e.g. getSlot or `eth_blockNumber`.
    method: String,
    /// JSON array or object, or - for stdin. Defaults to [].
    params: Option<String>,
    /// Read params from a file, or - for stdin.
    #[arg(short = 'f', long, conflicts_with = "params")]
    params_file: Option<PathBuf>,
    /// ERPC mainnet (inferred from the method when omitted).
    #[arg(short = 'n', long, value_enum)]
    network: Option<Network>,
    /// Operator-supplied RPC endpoint. Uses only the credentials in this URL.
    #[arg(long, visible_alias="url", conflicts_with_all=["x402","network"])]
    endpoint_url: Option<String>,
    /// Request a quote and confirm a one-time Base EURC payment from the ERPC wallet.
    #[arg(long)]
    x402: bool,
    /// Print the x402 quote without reading a wallet or making a payment.
    #[arg(long, requires = "x402")]
    quote: bool,
}

fn params(call: &Call) -> Result<Value, String> {
    let value = if call.params.as_deref() == Some("-")
        || call.params_file.as_deref() == Some(std::path::Path::new("-"))
    {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&input)
    } else if let Some(path) = &call.params_file {
        serde_json::from_reader(
            std::fs::File::open(path).map_err(|e| format!("cannot open params file: {e}"))?,
        )
    } else {
        serde_json::from_str(call.params.as_deref().unwrap_or("[]"))
    }
    .map_err(|e| {
        format!(
            "invalid JSON params at line {}, column {}",
            e.line(),
            e.column()
        )
    })?;
    match value {
        Value::Object(_) | Value::Array(_) => Ok(value),
        _ => Err("params must be a JSON array or object".into()),
    }
}

/// Validate operator-named destinations separately from account and x402 hosts.
pub(crate) fn operator_url(raw: &str, websocket: bool) -> Result<Url, String> {
    erpc_core::endpoints::ensure_user_supplied_url(raw)
        .map_err(|_| "use a secure endpoint URL (or loopback), without userinfo")?;
    let url = Url::parse(raw).map_err(|_| "invalid endpoint URL")?;
    let (secure, plain) = if websocket {
        ("wss", "ws")
    } else {
        ("https", "http")
    };
    if url.fragment().is_some() || ![secure, plain].contains(&url.scheme()) {
        return Err(format!(
            "use {secure} (or {plain} on loopback), without userinfo or a fragment"
        ));
    }
    Ok(url)
}

pub(crate) fn client() -> Result<Client, Outcome> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(network_error)
}

pub(crate) fn network_error(e: reqwest::Error) -> Outcome {
    crate::error::CliError::new(crate::error::Code::Network, e.without_url().to_string()).into()
}

pub(crate) fn output(value: &Value, json: bool) -> Outcome {
    if json {
        Outcome::Done(value.to_string())
    } else {
        match serde_json::to_string_pretty(value) {
            Ok(s) => Outcome::Done(s),
            Err(e) => Outcome::Failed(e.to_string()),
        }
    }
}

pub(crate) async fn run(call: &Call, json: bool) -> Outcome {
    match execute(call, json).await {
        Ok(value) => output(&value, json),
        Err(outcome) => outcome,
    }
}

async fn execute(call: &Call, json: bool) -> Result<Value, Outcome> {
    if call.method.trim().is_empty() || call.method.chars().any(char::is_control) {
        return Err(Outcome::Usage(
            "RPC method must be nonempty and contain no control characters".into(),
        ));
    }
    let body = json!({"jsonrpc":"2.0","id":1,"method":call.method,"params":params(call).map_err(Outcome::Usage)?});
    let network = call.network.unwrap_or_else(|| {
        if call.method.contains('_') {
            Network::EthereumMainnet
        } else {
            Network::SolanaMainnet
        }
    });
    let url = if let Some(url) = &call.endpoint_url {
        operator_url(url, false).map_err(Outcome::Usage)?
    } else if call.x402 {
        Url::parse(network.paid_url()).map_err(|e| Outcome::Failed(e.to_string()))?
    } else {
        network.account_url(false).await?
    };
    send_request(
        call,
        &url,
        &body,
        crate::session::has_terminal(),
        json,
        confirm_payment,
        || crate::credit_wallet::read_wallet_key(false),
    )
    .await
}

fn confirm_payment(prompt: &str) -> Result<bool, Outcome> {
    dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .map_err(|_| Outcome::Failed("could not confirm payment".into()))
}

async fn payment_offer(response: Response) -> Result<Value, Outcome> {
    if let Some(header) = response.headers().get("Payment-Required") {
        let data = STANDARD
            .decode(header.as_bytes())
            .map_err(|_| Outcome::Failed("invalid Payment-Required encoding".into()))?;
        serde_json::from_slice(&data)
            .map_err(|_| Outcome::Failed("invalid Payment-Required JSON".into()))
    } else {
        // ERPC also serves the v2 payment requirements in the JSON response body.
        response.json::<Value>().await.map_err(network_error)
    }
}

async fn send_request(
    call: &Call,
    url: &Url,
    body: &Value,
    terminal: bool,
    json: bool,
    confirm: impl FnOnce(&str) -> Result<bool, Outcome>,
    wallet: impl FnOnce() -> Result<erpc_wallet::evm::EvmKey, String>,
) -> Result<Value, Outcome> {
    let client = client()?;
    let request = || client.post(url.clone()).json(body);
    let mut response = request().send().await.map_err(network_error)?;
    if call.x402 && response.status() == StatusCode::PAYMENT_REQUIRED {
        let offer = payment_offer(response).await?;
        let quote =
            erpc_x402::Quote::parse(&offer, url.as_str(), &call.method).map_err(Outcome::Failed)?;
        let quoted_units = quote.amount();
        let amount = erpc_wallet::eurc::format_eurc(quoted_units);
        if call.quote {
            return Ok(
                json!({"method":call.method,"resource":url.as_str(),"amount_eurc":amount,"paid":false}),
            );
        }
        if !terminal || json {
            return Err(Outcome::NeedsTerminal(format!(
                "Payment of {amount} EURC requires terminal confirmation; use --x402 --quote to inspect it"
            )));
        }
        let approved = confirm(&format!(
            "Pay {amount} EURC on Base for {} at {}?",
            call.method,
            url.path()
        ))?;
        if !approved {
            return Err(Outcome::Failed("payment cancelled".into()));
        }
        let key = wallet().map_err(Outcome::Failed)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Outcome::Failed(e.to_string()))?
            .as_secs();
        let proof = quote
            .sign(&key, quoted_units, now)
            .map_err(Outcome::Failed)?;
        drop(key);
        response = request()
            .header("Payment-Signature", proof)
            .send()
            .await
            .map_err(|e| crate::error::CliError::new(crate::error::Code::Network, format!(
                "Payment was submitted but the RPC response was lost ({}). Check the wallet before paying again.",
                e.without_url()
            )))?;
        return rpc_response(response)
            .await
            .map_err(|outcome| match outcome.error() {
                Some(e) => e
                    .hint("Payment was submitted. Check the wallet before paying again.")
                    .into(),
                None => Outcome::Failed("could not read the paid RPC response".into()),
            });
    }
    rpc_response(response).await
}

async fn rpc_response(response: Response) -> Result<Value, Outcome> {
    if !response.status().is_success() {
        return Err(Outcome::Failed(format!(
            "RPC endpoint returned HTTP {}",
            response.status()
        )));
    }
    let reply = response.json::<Value>().await.map_err(network_error)?;
    if reply["jsonrpc"] != "2.0" || reply["id"] != 1 {
        return Err(Outcome::Failed(
            "unexpected JSON-RPC response version or id".into(),
        ));
    }
    if let Some(error) = reply.get("error") {
        return Err(crate::error::CliError::new(
            crate::error::Code::Failed,
            format!(
                "RPC error {}: {}",
                error["code"],
                error["message"]
                    .as_str()
                    .unwrap_or("unknown error")
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect::<String>()
            ),
        )
        .details(error.clone())
        .into());
    }
    reply
        .get("result")
        .ok_or_else(|| Outcome::Failed("missing JSON-RPC result".into()))?;
    Ok(reply)
}

#[cfg(test)]
#[path = "rpc_payment_tests.rs"]
mod payment_tests;
