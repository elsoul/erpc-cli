// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bounded public observations for external Solana vote-account operations.
//! These observations are advisory, never a signature or host activation grant.

use crate::validator_profile::{Registration, VoteState, public_bytes, source};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAINNET: &str = "https://api.mainnet-beta.solana.com";
const TESTNET: &str = "https://api.testnet.solana.com";
const VOTE_PROGRAM: &str = "Vote111111111111111111111111111111111111111";
const LIMIT: usize = 262_144;

trait Reader {
    async fn call(&self, method: &'static str, params: Value) -> Result<Value, String>;
}

struct PublicRpc {
    client: reqwest::Client,
    url: &'static str,
}

impl Reader for PublicRpc {
    async fn call(&self, method: &'static str, params: Value) -> Result<Value, String> {
        let mut response = self
            .client
            .post(self.url)
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| "public Solana RPC request failed")?;
        if !response.status().is_success()
            || response
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .is_some_and(|v| v != "identity")
            || response.content_length().is_some_and(|n| n > LIMIT as u64)
        {
            return Err("public Solana RPC rejected the request or exceeded its bound".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "public Solana RPC response failed")?
        {
            if chunk.len() > LIMIT.saturating_sub(bytes.len()) {
                return Err("public Solana RPC response exceeds its bound".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = crate::validator_json::parse(&bytes)?;
        rpc_result(value)
    }
}

fn rpc_result(mut value: Value) -> Result<Value, String> {
    if value["jsonrpc"] != "2.0" || value["id"] != 1 || value.get("error").is_some() {
        return Err("public Solana RPC returned an error or mismatched envelope".into());
    }
    value
        .as_object_mut()
        .and_then(|value| value.remove("result"))
        .ok_or_else(|| "missing public Solana RPC result".into())
}

/// A finalized, epoch-bounded public vote-account observation.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Cluster epoch shared by the surrounding observations.
    pub epoch: u64,
    /// Account observation slot, bounded by finalized epoch observations.
    pub slot: u64,
    /// UNIX time returned for the final surrounding block.
    pub block_time: u64,
    /// None means a successful explicit null account result, never an RPC failure.
    pub vote: Option<VoteState>,
    /// Current account-size rent quote; not an admission or transaction-fee quote.
    pub rent_lamports: Option<u64>,
    /// Original public parsed account data, including native commission collectors.
    pub account: Value,
}

impl Observation {
    /// Public report. A present account can still differ from the reservation.
    #[must_use]
    pub fn report(&self, registration: &Registration) -> Value {
        let binding = self.vote.as_ref().map(|vote| {
            vote.bind(
                &registration.identity,
                &registration.withdrawer,
                &registration.bls,
                registration.commission,
            )
        });
        let mut account = self.account.clone();
        if let Some(balance) = account.get("lamports").and_then(Value::as_u64) {
            account["lamports"] = json!(balance.to_string());
        }
        json!({"network":registration.network,"vote_account":registration.vote_account,
            "epoch":self.epoch,"slot":self.slot,"block_time":self.block_time,
            "exists":self.vote.is_some(),"matches":matches!(binding, Some(Ok(()))),
            "mismatch":binding.and_then(Result::err),
            "rent_lamports":self.rent_lamports.map(|n| n.to_string()),"account":account,
            "authority":"public RPC observation; external signer must revalidate before submission"})
    }
}

/// Read only fixed official RPC endpoints; no key, proxy, redirect or transaction.
/// # Errors
/// Refuses malformed, stale, wrong-genesis, cross-epoch or unparsed observations.
pub async fn observe(registration: &Registration) -> Result<Observation, String> {
    registration.validate()?;
    let url = match registration.network.as_str() {
        "mainnet" => MAINNET,
        "testnet" => TESTNET,
        _ => return Err("unsupported public observer network".into()),
    };
    erpc_core::endpoints::ensure_service_url(url).map_err(|e| e.to_string())?;
    let rpc = PublicRpc {
        url,
        client: reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .user_agent("erpc-public-solana-observer")
            .build()
            .map_err(|_| "cannot create public RPC client")?,
    };
    observe_with(&rpc, registration, unix_time).await
}

fn unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "invalid local clock".into())
}

fn uint(value: &Value, field: &str) -> Result<u64, String> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("missing or invalid public {field}"))
}

fn epoch(value: &Value) -> Result<(u64, u64), String> {
    let epoch = uint(value, "epoch")?;
    let slot = uint(value, "absoluteSlot")?;
    let index = uint(value, "slotIndex")?;
    let size = uint(value, "slotsInEpoch")?;
    if size == 0 || index >= size || index > slot {
        return Err("invalid public epoch position".into());
    }
    Ok((epoch, slot))
}

fn freshness(block_time: &Value, now: u64) -> Result<u64, String> {
    let block = block_time.as_u64().ok_or("missing public block time")?;
    if now.saturating_sub(block) > 180 || block.saturating_sub(now) > 30 {
        return Err("public block time is stale or in the future".into());
    }
    Ok(block)
}

async fn observe_with(
    rpc: &impl Reader,
    registration: &Registration,
    now: impl Fn() -> Result<u64, String>,
) -> Result<Observation, String> {
    registration.validate()?;
    let started = now()?;
    let expected = source(&registration.network).ok_or("unsupported network")?;
    if rpc.call("getGenesisHash", json!([])).await? != expected.genesis {
        return Err("public RPC genesis differs from the selected network".into());
    }
    let first = rpc
        .call("getEpochInfo", json!([{"commitment":"finalized"}]))
        .await?;
    let (first_epoch, first_slot) = epoch(&first)?;
    freshness(
        &rpc.call("getBlockTime", json!([first_slot])).await?,
        now()?,
    )?;
    let account = rpc
        .call(
            "getAccountInfo",
            json!([registration.vote_account,
        {"commitment":"finalized","encoding":"jsonParsed","minContextSlot":first_slot}]),
        )
        .await?;
    let account_slot = uint(&account["context"], "slot")?;
    if account_slot < first_slot {
        return Err("public account context moved backwards".into());
    }
    let value = account.get("value").ok_or("missing account value")?;
    let vote = parse_account(value, first_epoch)?;
    let rent = if vote.is_some() {
        let space = uint(value, "space")?;
        if !(1..=16_384).contains(&space) {
            return Err("invalid vote account size".into());
        }
        Some(
            rpc.call(
                "getMinimumBalanceForRentExemption",
                json!([space,{"commitment":"finalized"}]),
            )
            .await?
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("invalid public rent quote")?,
        )
    } else {
        None
    };
    let last = rpc
        .call(
            "getEpochInfo",
            json!([{"commitment":"finalized","minContextSlot":account_slot}]),
        )
        .await?;
    let (last_epoch, last_slot) = epoch(&last)?;
    if first_epoch != last_epoch
        || last_slot < account_slot
        || last_slot.saturating_sub(first_slot) > 300
    {
        return Err(
            "public observations crossed an epoch or exceeded their slot window; retry".into(),
        );
    }
    let block_time = freshness(&rpc.call("getBlockTime", json!([last_slot])).await?, now()?)?;
    let finished = now()?;
    if finished < started || finished - started > 60 {
        return Err("public observation took too long; retry".into());
    }
    Ok(Observation {
        epoch: first_epoch,
        slot: account_slot,
        block_time,
        vote,
        rent_lamports: rent,
        account: value.clone(),
    })
}

fn parse_account(account: &Value, epoch: u64) -> Result<Option<VoteState>, String> {
    if account.is_null() {
        return Ok(None);
    }
    if account["owner"] != VOTE_PROGRAM
        || account["executable"] != false
        || account["data"]["program"] != "vote"
        || account["data"]["parsed"]["type"] != "vote"
    {
        return Err("reserved address is not a parsed native vote account".into());
    }
    let info = &account["data"]["parsed"]["info"];
    let voters = info["authorizedVoters"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 64)
        .ok_or("invalid native public voter schedule")?;
    let mut schedule = serde_json::Map::new();
    for voter in voters {
        let when = uint(voter, "epoch")?.to_string();
        let key = voter["authorizedVoter"]
            .as_str()
            .ok_or("missing public voter")?;
        public_bytes(key, 32)?;
        if schedule.insert(when, json!(key)).is_some() {
            return Err("duplicate native voter epoch".into());
        }
    }
    // Current native source rounds legacy commission up from basis points.
    // A fractional fee must not accidentally match the integer profile.
    let commission = uint(info, "commission")?;
    if uint(info, "inflationRewardsCommissionBps")?
        != commission.checked_mul(100).ok_or("invalid commission")?
    {
        return Err(
            "fractional native commission does not match the integer commission profile".into(),
        );
    }
    VoteState::parse(
        &json!({"validatorIdentity":info["nodePubkey"],
        "authorizedWithdrawer":info["authorizedWithdrawer"],"authorizedVoters":schedule,
        "commission":commission,"accountBalance":uint(account,"lamports")?,
        "blsPubkeyCompressed":info["blsPubkeyCompressed"]}),
        epoch,
    )
    .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    struct Mock(RefCell<VecDeque<(&'static str, Value)>>);
    impl Reader for Mock {
        fn call(
            &self,
            method: &'static str,
            _params: Value,
        ) -> impl std::future::Future<Output = Result<Value, String>> {
            let (expected, value) = self.0.borrow_mut().pop_front().expect("unexpected RPC");
            assert_eq!(method, expected);
            std::future::ready(Ok(value))
        }
    }
    fn reservation() -> Registration {
        Registration {
            network: "testnet".into(),
            identity: crate::identity::base58(&[7; 32]),
            vote_account: crate::identity::base58(&[8; 32]),
            withdrawer: crate::identity::base58(&[9; 32]),
            bls: crate::identity::base58(&[10; 48]),
            commission: 5,
        }
    }
    fn native() -> Value {
        let r = reservation();
        json!({"owner":VOTE_PROGRAM,"executable":false,"lamports":1_000_000_000_u64,"space":3762,
            "data":{"program":"vote","parsed":{"type":"vote","info":{
                "nodePubkey":r.identity,"authorizedWithdrawer":r.withdrawer,
                "authorizedVoters":[{"epoch":10,"authorizedVoter":r.identity}],
                "commission":5,"inflationRewardsCommissionBps":500,"blsPubkeyCompressed":r.bls}}}})
    }
    fn responses(account: &Value) -> Vec<(&'static str, Value)> {
        let position = json!({"epoch":11,"absoluteSlot":110,"slotIndex":10,"slotsInEpoch":100});
        let mut result = vec![
            ("getGenesisHash", json!(source("testnet").unwrap().genesis)),
            ("getEpochInfo", position.clone()),
            ("getBlockTime", json!(1000)),
            (
                "getAccountInfo",
                json!({"context":{"slot":110},"value":account}),
            ),
        ];
        if !account.is_null() {
            result.push(("getMinimumBalanceForRentExemption", json!(30_000_000)));
        }
        result.extend([("getEpochInfo", position), ("getBlockTime", json!(1000))]);
        result
    }
    async fn run(values: Vec<(&'static str, Value)>) -> Result<Observation, String> {
        observe_with(&Mock(RefCell::new(values.into())), &reservation(), || {
            Ok(1001)
        })
        .await
    }
    #[tokio::test]
    async fn observes_present_or_explicitly_absent_accounts() {
        let present = run(responses(&native())).await.unwrap();
        assert_eq!(present.report(&reservation())["matches"], true);
        assert_eq!(
            present.report(&reservation())["account"]["lamports"],
            "1000000000"
        );
        assert!(run(responses(&Value::Null)).await.unwrap().vote.is_none());
        let mut values = responses(&Value::Null);
        values[3].1.as_object_mut().unwrap().remove("value");
        assert!(run(values).await.is_err());
    }
    #[tokio::test]
    async fn refuses_wrong_network_stale_cross_epoch_and_backward_context() {
        for index in 0..5 {
            let mut values = responses(&native());
            match index {
                0 => values[0].1 = json!(source("mainnet").unwrap().genesis),
                1 => values[2].1 = json!(800),
                2 => values[5].1["epoch"] = json!(12),
                3 => values[3].1["context"]["slot"] = json!(109),
                _ => values[5].1["absoluteSlot"] = json!(109),
            }
            assert!(run(values).await.is_err(), "mutation {index}");
        }
    }
    #[test]
    fn rejects_native_shape_confusion_duplicate_epochs_and_rounded_fees() {
        for index in 0..5 {
            let mut account = native();
            match index {
                0 => account["owner"] = json!(reservation().identity),
                1 => account["executable"] = json!(true),
                2 => {
                    account["data"]["parsed"]["info"]["inflationRewardsCommissionBps"] = json!(499);
                }
                3 => {
                    let voters = account["data"]["parsed"]["info"]["authorizedVoters"]
                        .as_array_mut()
                        .unwrap();
                    voters.push(voters[0].clone());
                }
                _ => account["lamports"] = json!("100"),
            }
            assert!(parse_account(&account, 11).is_err(), "mutation {index}");
        }
        assert!(rpc_result(json!({"jsonrpc":"2.0","id":1,"error":{},"result":null})).is_err());
        assert!(rpc_result(json!({"jsonrpc":"2.0","id":2,"result":null})).is_err());
        assert!(rpc_result(json!({"jsonrpc":"2.0","id":1})).is_err());
    }
    #[tokio::test]
    async fn transport_bounds_responses_refuses_redirects_and_redacts_errors() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        for (status, headers, body, success) in [
            (200, "", r#"{"jsonrpc":"2.0","id":1,"result":null}"#, true),
            (
                200,
                "",
                r#"{"jsonrpc":"2.0","id":1,"result":null,"result":7}"#,
                false,
            ),
            (
                200,
                "",
                r#"{"jsonrpc":"2.0","id":1,"error":{"message":"untrusted private-looking marker"}}"#,
                false,
            ),
            (200, "Content-Encoding: gzip\r\n", "invalid gzip", false),
            (302, "Location: http://127.0.0.1:9/\r\n", "", false),
            (503, "", "untrusted private-looking marker", false),
            (200, "", "oversized", false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let thread = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = vec![0; 8192];
                let count = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..count]).to_lowercase();
                assert!(!request.contains("authorization:"));
                assert!(!request.contains("cookie:"));
                write!(stream, "HTTP/1.1 {status} Test\r\nConnection: close\r\n{headers}Content-Length: {}\r\n\r\n{body}", if body == "oversized" { LIMIT + 1 } else { body.len() }).unwrap();
            });
            let rpc = PublicRpc {
                url: Box::leak(format!("http://127.0.0.1:{}", address.port()).into_boxed_str()),
                client: reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(5))
                    .build()
                    .unwrap(),
            };
            let outcome = rpc.call("getGenesisHash", json!([])).await;
            assert_eq!(outcome.is_ok(), success);
            if let Err(error) = outcome {
                assert!(!error.contains("marker"));
            }
            thread.join().unwrap();
        }
    }
    #[test]
    fn observer_endpoints_are_declared_but_legacy_sender_stays_testnet_only() {
        for url in [MAINNET, TESTNET] {
            erpc_core::endpoints::ensure_service_url(url).unwrap();
        }
        assert!(crate::cli::rpc_url("mainnet").is_none());
    }
}
