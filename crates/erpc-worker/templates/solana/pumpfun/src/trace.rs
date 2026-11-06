//! Following banned creators' money (`POST /api/bans/trace`).
//!
//! A wallet that opens pools to pull them is cheap to replace, and is
//! usually replaced from the same purse. For each banned creator not traced
//! yet, the wallet that first sent it SOL is its funder; the funder, and
//! every other wallet the funder sent SOL to lately, are banned with it.
//! Running it again traces the wallets it banned, a step further each run.
//!
//! A wallet with a long history is never blamed: a creator with
//! `HISTORY_LIMIT` transactions or more is no throwaway, and a funder with
//! that many, or one that funded more than `MAX_FUNDED` wallets lately, is
//! an exchange or a service paying many people. The bot's own wallet is
//! never banned. Bans only stop the bot buying pools those wallets create.
//!
//! Every read goes to the read RPC, a few at a time: a run reads about two
//! hundred transactions per creator, so it is a command to run now and then,
//! not on every ban. Nothing here is on the trading path, where a ban is a
//! map lookup.

use crate::state::AppState;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_rpc_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_sdk::pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction, UiInstruction, UiMessage, UiTransactionEncoding,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A wallet with this many transactions or more has history: not a
/// throwaway creator, and as a funder, one that pays many.
const HISTORY_LIMIT: usize = 1_000;
/// The oldest transactions of a creator read for its funding.
const FIRST_TXS: usize = 5;
/// The funder's latest transactions read for the wallets it funded.
const FUNDER_SCAN: usize = 200;
/// A funder that sent SOL to more wallets than this lately pays many people.
const MAX_FUNDED: usize = 50;
/// Reads in flight at once.
const CONCURRENCY: usize = 8;
/// The Redis set of creators traced already.
pub const TRACED_KEY: &str = "pumpfun:traced_creators";

const SYSTEM_PROGRAM: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

/// What `POST /api/bans/trace` did.
#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub struct TraceReport {
    /// Creators traced this run.
    pub traced: Vec<String>,
    /// Wallets banned this run, and why.
    pub banned: Vec<TracedBan>,
    /// Creators not traced, and why. Ones the RPC failed on are tried
    /// again next run.
    pub skipped: Vec<Skipped>,
    /// Banned creators still not traced, for another run.
    pub left: usize,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TracedBan {
    pub address: String,
    pub reason: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Skipped {
    pub creator: String,
    pub why: String,
}

/// Why a creator led nowhere; `retry` when the RPC is to blame.
struct DeadEnd {
    why: String,
    retry: bool,
}

impl DeadEnd {
    fn settled(why: impl Into<String>) -> Self {
        Self { why: why.into(), retry: false }
    }
    fn rpc(e: impl std::fmt::Display) -> Self {
        Self { why: format!("the RPC failed: {e}"), retry: true }
    }
}

/// The SOL transfers of a transaction, inner ones included: (from, to,
/// lamports). None for a transaction that failed, or whose outcome is not
/// there to read: its transfers moved nothing, and a wallet is not banned
/// for money it never sent.
pub fn sol_transfers(tx: &EncodedConfirmedTransactionWithStatusMeta) -> Vec<(Pubkey, Pubkey, u64)> {
    let EncodedTransaction::Json(ui) = &tx.transaction.transaction else { return Vec::new() };
    let UiMessage::Raw(msg) = &ui.message else { return Vec::new() };
    let meta = tx.transaction.meta.as_ref();
    if meta.is_none_or(|m| m.err.is_some()) {
        return Vec::new();
    }
    let mut keys: Vec<Option<Pubkey>> = msg.account_keys.iter().map(|k| k.parse().ok()).collect();
    if let Some(OptionSerializer::Some(loaded)) = meta.map(|m| &m.loaded_addresses) {
        keys.extend(loaded.writable.iter().chain(&loaded.readonly).map(|k| k.parse().ok()));
    }
    let key = |i: u8| keys.get(i as usize).copied().flatten();
    let mut compiled: Vec<_> = msg.instructions.iter().collect();
    if let Some(OptionSerializer::Some(inner)) = meta.map(|m| &m.inner_instructions) {
        compiled.extend(inner.iter().flat_map(|i| &i.instructions).filter_map(|ix| match ix {
            UiInstruction::Compiled(c) => Some(c),
            UiInstruction::Parsed(_) => None,
        }));
    }
    compiled
        .into_iter()
        .filter(|ix| key(ix.program_id_index) == Some(SYSTEM_PROGRAM))
        .filter_map(|ix| {
            let data = bs58::decode(&ix.data).into_vec().ok()?;
            // SystemInstruction::Transfer: 2 as a u32, then the lamports.
            if data.len() != 12 || data[..4] != [2, 0, 0, 0] {
                return None;
            }
            let lamports = u64::from_le_bytes(data[4..].try_into().ok()?);
            Some((key(*ix.accounts.first()?)?, key(*ix.accounts.get(1)?)?, lamports))
        })
        .collect()
}

/// An address's signatures, newest first, up to `HISTORY_LIMIT`.
async fn signatures(rpc: &RpcClient, address: &Pubkey) -> Result<Vec<Signature>, DeadEnd> {
    let config = GetConfirmedSignaturesForAddress2Config {
        limit: Some(HISTORY_LIMIT),
        commitment: Some(CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let found = rpc
        .get_signatures_for_address_with_config(address, config)
        .await
        .map_err(DeadEnd::rpc)?;
    Ok(found.iter().filter_map(|s| s.signature.parse().ok()).collect())
}

async fn transaction(rpc: &RpcClient, sig: Signature) -> Option<EncodedConfirmedTransactionWithStatusMeta> {
    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };
    rpc.get_transaction_with_config(&sig, config).await.ok()
}

/// The wallet that first sent `creator` SOL.
async fn funder_of(rpc: &RpcClient, creator: &Pubkey) -> Result<Pubkey, DeadEnd> {
    let sigs = signatures(rpc, creator).await?;
    if sigs.len() >= HISTORY_LIMIT {
        return Err(DeadEnd::settled("too long a history to be a throwaway wallet"));
    }
    for sig in sigs.iter().rev().take(FIRST_TXS) {
        let Some(tx) = transaction(rpc, *sig).await else { continue };
        if let Some((from, ..)) = sol_transfers(&tx).into_iter().find(|(from, to, _)| to == creator && from != creator) {
            return Ok(from);
        }
    }
    Err(DeadEnd::settled("no SOL sent to it in its first transactions"))
}

/// The wallets `funder` sent SOL to lately.
async fn funded_by(rpc: &RpcClient, funder: &Pubkey) -> Result<BTreeSet<Pubkey>, DeadEnd> {
    let sigs = signatures(rpc, funder).await?;
    if sigs.len() >= HISTORY_LIMIT {
        return Err(DeadEnd::settled(format!("its funder {funder} has a long history: an exchange or a service")));
    }
    let txs: Vec<_> = stream::iter(sigs.into_iter().take(FUNDER_SCAN))
        .map(|sig| transaction(rpc, sig))
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;
    let funded: BTreeSet<Pubkey> = txs
        .iter()
        .flatten()
        .flat_map(sol_transfers)
        .filter(|(from, to, _)| from == funder && to != funder)
        .map(|(_, to, _)| to)
        .collect();
    if funded.len() > MAX_FUNDED {
        return Err(DeadEnd::settled(format!(
            "its funder {funder} sent SOL to {} wallets lately: it pays many people",
            funded.len()
        )));
    }
    Ok(funded)
}

/// Who to ban for `creator`: its funder, then the wallets the funder sent
/// SOL to, each with why. Never `keep`, never `creator` itself.
async fn trace_one(rpc: &RpcClient, creator: Pubkey, keep: Option<Pubkey>) -> Result<Vec<(Pubkey, String)>, DeadEnd> {
    let funder = funder_of(rpc, &creator).await?;
    if Some(funder) == keep {
        return Err(DeadEnd::settled("funded by this bot's own wallet"));
    }
    let funded = funded_by(rpc, &funder).await?;
    let mut bans = vec![(funder, format!("funded banned creator {creator}"))];
    bans.extend(
        funded
            .into_iter()
            .filter(|w| *w != creator && Some(*w) != keep)
            .map(|w| (w, format!("funded by {funder}, which funded banned creator {creator}"))),
    );
    Ok(bans)
}

/// Traces up to `limit` banned creators not traced yet, and bans what it
/// finds, in memory and in Redis.
pub async fn trace(state: &Arc<RwLock<AppState>>, rpc: &RpcClient, limit: usize) -> TraceReport {
    let (to_trace, left, keep) = {
        let s = state.read().await;
        let untraced: Vec<Pubkey> = s.creators.untraced();
        let keep = s.wallet.as_ref().map(|w| solana_sdk::signer::Signer::pubkey(w.as_ref()));
        let left = untraced.len().saturating_sub(limit);
        (untraced.into_iter().take(limit).collect::<Vec<_>>(), left, keep)
    };
    let mut report = TraceReport { left, ..Default::default() };
    for creator in to_trace {
        let found = trace_one(rpc, creator, keep).await;
        let mut s = state.write().await;
        match found {
            Err(DeadEnd { why, retry: true }) => {
                report.skipped.push(Skipped { creator: creator.to_string(), why });
                report.left += 1;
                continue;
            }
            Err(DeadEnd { why, .. }) => report.skipped.push(Skipped { creator: creator.to_string(), why }),
            Ok(bans) => {
                for (wallet, reason) in bans {
                    if s.creators.ban(wallet, &reason) {
                        log::info!("Banned {wallet}: {reason}");
                        crate::creators::persist_ban(s.redis_client.as_ref(), wallet, reason.clone());
                        report.banned.push(TracedBan { address: wallet.to_string(), reason });
                    }
                }
            }
        }
        s.creators.mark_traced(creator);
        persist_traced(s.redis_client.as_ref(), creator);
        report.traced.push(creator.to_string());
    }
    report
}

fn persist_traced(client: Option<&redis::Client>, creator: Pubkey) {
    let Some(client) = client.cloned() else { return };
    tokio::spawn(async move {
        let result: Result<(), redis::RedisError> = async {
            let mut con = client.get_multiplexed_async_connection().await?;
            redis::cmd("SADD").arg(TRACED_KEY).arg(creator.to_string()).query_async(&mut con).await
        }
        .await;
        if let Err(e) = result {
            log::warn!("Could not save {creator} as traced to Redis: {e:?}");
        }
    });
}

/// The creators traced before, read at start.
pub async fn load_traced(client: &redis::Client) -> Vec<Pubkey> {
    let result: Result<Vec<String>, redis::RedisError> = async {
        let mut con = client.get_multiplexed_async_connection().await?;
        redis::cmd("SMEMBERS").arg(TRACED_KEY).query_async(&mut con).await
    }
    .await;
    match result {
        Ok(rows) => rows.iter().filter_map(|k| k.parse().ok()).collect(),
        Err(e) => {
            log::warn!("Could not read traced creators from Redis: {e:?}");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sol_transfers_are_read_top_level_and_inner_through_lookup_tables() {
        let a = Pubkey::new_from_array([1; 32]);
        let b = Pubkey::new_from_array([2; 32]);
        let c = Pubkey::new_from_array([3; 32]);
        let transfer = |lamports: u64| {
            let mut d = vec![2, 0, 0, 0];
            d.extend_from_slice(&lamports.to_le_bytes());
            bs58::encode(d).into_string()
        };
        let tx: EncodedConfirmedTransactionWithStatusMeta = serde_json::from_value(serde_json::json!({
            "slot": 1,
            "blockTime": null,
            // As getTransaction answers: the transaction and its meta beside the slot.
            "transaction": {
                "signatures": ["1111111111111111111111111111111111111111111111111111111111111111"],
                "message": {
                    "header": {"numRequiredSignatures": 1, "numReadonlySignedAccounts": 0, "numReadonlyUnsignedAccounts": 1},
                    "accountKeys": [a.to_string(), b.to_string(), SYSTEM_PROGRAM.to_string()],
                    "recentBlockhash": "11111111111111111111111111111111",
                    "instructions": [
                        {"programIdIndex": 2, "accounts": [0, 1], "data": transfer(5), "stackHeight": null},
                        // Not a transfer: CreateAccount.
                        {"programIdIndex": 2, "accounts": [0, 1], "data": bs58::encode([0u8; 52]).into_string(), "stackHeight": null}
                    ]
                }
            },
            "meta": {
                "err": null, "status": {"Ok": null}, "fee": 5000,
                "preBalances": [], "postBalances": [],
                "innerInstructions": [{"index": 0, "instructions": [
                    {"programIdIndex": 2, "accounts": [1, 3], "data": transfer(7), "stackHeight": 2}
                ]}],
                "loadedAddresses": {"writable": [c.to_string()], "readonly": []}
            }
        }))
        .unwrap();
        assert_eq!(sol_transfers(&tx), vec![(a, b, 5), (b, c, 7)]);

        // The same transaction, failed: nothing moved.
        let mut failed = serde_json::to_value(&tx).unwrap();
        failed["meta"]["err"] = serde_json::json!({"InstructionError": [0, {"Custom": 1}]});
        failed["meta"]["status"] = serde_json::json!({"Err": {"InstructionError": [0, {"Custom": 1}]}});
        let failed: EncodedConfirmedTransactionWithStatusMeta = serde_json::from_value(failed).unwrap();
        assert!(sol_transfers(&failed).is_empty());
        // And with no outcome to read.
        let mut unknown = serde_json::to_value(&tx).unwrap();
        unknown["meta"] = serde_json::Value::Null;
        let unknown: EncodedConfirmedTransactionWithStatusMeta = serde_json::from_value(unknown).unwrap();
        assert!(sol_transfers(&unknown).is_empty());
    }
}
