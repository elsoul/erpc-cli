use crate::amm::{self, NewPool};
use crate::engine::{check_and_sell_positions, handle_new_pool};
use crate::state::AppState;
use crate::timing::{Sighting, Via};
use log::info;
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_stream_sdk::{GeyserSubscribeUpdate, GeyserUpdateOneof};
use std::sync::Arc;
use tokio::sync::RwLock;
use ultima_swap_pumpfun as pumpswap;

// Debounce removed: every swap event triggers immediate sell check
// for minimal latency on price spikes.

pub async fn process_updates(
    mut updates_rx: tokio::sync::mpsc::Receiver<GeyserSubscribeUpdate>,
    state: Arc<RwLock<AppState>>,
    rpc_client: Arc<RpcClient>,
    send_rpc_client: Arc<RpcClient>,
) {
    while let Some(update) = updates_rx.recv().await {
        handle_update(
            &update,
            state.clone(),
            rpc_client.clone(),
            send_rpc_client.clone(),
        )
        .await;
    }
}

/// Whether a pool `creator` just created may be bought: not during the
/// warm-up, and not from a creator banned now or before.
async fn creator_allows(state: &Arc<RwLock<AppState>>, pool: Pubkey, creator: Pubkey) -> bool {
    use crate::creators::Verdict;
    let mut s = state.write().await;
    let now = std::time::Instant::now();
    let window = std::time::Duration::from_secs(s.config.creator_window_secs);
    let max_pools = s.config.creator_max_pools;
    let verdict = s.creators.on_create(pool, creator, now, window, max_pools);
    s.creators.prune(now, window);
    match verdict {
        Verdict::Fine => {}
        Verdict::Banned(reason) => {
            info!("Skipping pool {pool}: creator {creator} is banned ({reason})");
            return false;
        }
        Verdict::NewlyBanned(reason) => {
            info!("Banned creator {creator}: {reason}; skipping pool {pool}");
            crate::creators::persist_ban(s.redis_client.as_ref(), creator, reason);
            return false;
        }
    }
    let warm = s.started.elapsed().as_secs();
    if warm < s.config.warmup_secs {
        info!(
            "Skipping pool {pool}: warming up ({warm}/{} s), learning creators first",
            s.config.warmup_secs
        );
        return false;
    }
    true
}

/// An instruction of a transaction, with its accounts resolved: one at the
/// top level, or one a top-level instruction called.
struct Ix<'a> {
    program: Pubkey,
    accounts: Vec<Pubkey>,
    data: &'a [u8],
    /// The program of the top-level instruction it runs under (its own
    /// when it is at the top level).
    called_by: Pubkey,
}

/// Every instruction of a transaction, inner ones included: pump.fun's
/// migration creates a graduation's pool from inside its own instruction,
/// and aggregators swap on PumpSwap from inside theirs.
fn instructions<'a>(
    msg: &'a solana_stream_sdk::yellowstone_grpc_proto::prelude::Message,
    meta: Option<&'a solana_stream_sdk::yellowstone_grpc_proto::prelude::TransactionStatusMeta>,
    keys: &[Pubkey],
) -> Vec<Ix<'a>> {
    let resolve = |indexes: &[u8]| -> Vec<Pubkey> {
        indexes.iter().filter_map(|&i| keys.get(i as usize).copied()).collect()
    };
    let program_of = |index: u32| keys.get(index as usize).copied();
    let mut out = Vec::new();
    let mut top_programs = Vec::with_capacity(msg.instructions.len());
    for ix in &msg.instructions {
        let program = program_of(ix.program_id_index);
        top_programs.push(program);
        if let Some(program) = program {
            out.push(Ix { program, accounts: resolve(&ix.accounts), data: &ix.data, called_by: program });
        }
    }
    for inner in meta.map(|m| m.inner_instructions.as_slice()).unwrap_or_default() {
        let Some(Some(called_by)) = top_programs.get(inner.index as usize).copied() else {
            continue;
        };
        for ix in &inner.instructions {
            if let Some(program) = program_of(ix.program_id_index) {
                out.push(Ix { program, accounts: resolve(&ix.accounts), data: &ix.data, called_by });
            }
        }
    }
    out
}

async fn handle_update(
    update: &GeyserSubscribeUpdate,
    state: Arc<RwLock<AppState>>,
    rpc_client: Arc<RpcClient>,
    send_rpc_client: Arc<RpcClient>,
) {
    let now = std::time::Instant::now();

    let (watch_address, grpc_streaming, timing) = {
        let s = state.read().await;
        (s.watch_address, s.grpc_streaming, s.timing.clone())
    };

    // The slots' progress, which the timing of migrations is measured to.
    if let Some(GeyserUpdateOneof::Slot(slot)) = &update.update_oneof {
        use solana_stream_sdk::yellowstone_grpc_proto::geyser::SlotStatus;
        let mut timing = timing.lock().expect("timing lock");
        match SlotStatus::try_from(slot.status) {
            Ok(SlotStatus::SlotFirstShredReceived) => timing.on_slot_started(slot.slot, now),
            Ok(SlotStatus::SlotConfirmed) => timing.on_slot_confirmed(slot.slot, now),
            Ok(SlotStatus::SlotDead) => timing.on_slot_dead(slot.slot),
            _ => {}
        }
        return;
    }

    // Skip processing if gRPC streaming is paused.
    if !grpc_streaming {
        return;
    }

    let Some(GeyserUpdateOneof::Transaction(tx_update)) = &update.update_oneof else {
        return;
    };
    let Some(tx_info) = &tx_update.transaction else { return };
    let Some(tx) = &tx_info.transaction else { return };
    let Some(msg) = &tx.message else { return };
    let meta = tx_info.meta.as_ref();
    let signature = tx
        .signatures
        .first()
        .and_then(|s| <[u8; 64]>::try_from(s.as_slice()).ok())
        .map(solana_signature::Signature::from);
    // A migration seen in the Shreds stream, now processed.
    if let Some(sig) = signature {
        let mut timing = timing.lock().expect("timing lock");
        if timing.tracks(&sig) {
            timing.on_processed(sig, tx_update.slot, now);
        }
    }

    // The message's own keys, then those its address lookup tables load,
    // writable before read-only: the order instructions index them in.
    let as_key = |k: &Vec<u8>| <[u8; 32]>::try_from(k.as_slice()).ok().map(Pubkey::new_from_array);
    let mut account_keys: Vec<Pubkey> = msg.account_keys.iter().filter_map(as_key).collect();
    if let Some(meta) = meta {
        account_keys.extend(meta.loaded_writable_addresses.iter().filter_map(as_key));
        account_keys.extend(meta.loaded_readonly_addresses.iter().filter_map(as_key));
    }

    for ix in instructions(msg, meta, &account_keys) {
        // Only process instructions targeting the watched AMM program.
        if ix.program != watch_address {
            continue;
        }

        // ── create_pool detection: a graduation, or a pool made by hand ──
        if let Some(new_pool) = amm::parse_create_pool(ix.data, &ix.accounts, ix.called_by) {
            if new_pool.graduated {
                if let Some(sig) = signature {
                    timing.lock().expect("timing lock").on_processed(sig, tx_update.slot, now);
                }
                warm_lookup_tables(msg, &state, &rpc_client).await;
            }
            let sighting = Sighting { slot: tx_update.slot, seen: now, via: Via::Geyser };
            on_create_pool(new_pool, sighting, &state, &rpc_client, &send_rpc_client).await;
            continue;
        }

        // ── withdraw: the creator pulling liquidity ──
        if let Some((pool, user)) = crate::creators::withdraw_of(ix.data, &ix.accounts) {
            let mut s = state.write().await;
            if let Some(creator) = s.creators.on_withdraw(pool, user) {
                let reason = format!("pulled liquidity from pool {pool}");
                info!("Banned creator {creator}: {reason}");
                crate::creators::persist_ban(s.redis_client.as_ref(), creator, reason);
            }
            continue;
        }

        // ── swap (buy/sell) detection → trigger sell check ──
        if let Some(swap) = pumpswap::try_parse_swap(ix.data, &ix.accounts) {
            // We only care about swaps on pools where we hold positions.
            let side = {
                let s = state.read().await;
                s.positions
                    .values()
                    .find(|p| p.pool == swap.pool && p.status == crate::state::PositionStatus::Active)
                    .map(|p| p.side)
            };
            let Some(side) = side else { continue };
            info!(
                "Detected swap on held pool {}: {:?} base={} quote={}",
                swap.pool, swap.direction, swap.base_amount, swap.quote_amount
            );
            on_swap(swap.pool, side, &ix.accounts, &account_keys, meta, &state, &rpc_client, &send_rpc_client);
        }
    }
}

/// Reads, off the hot path, the lookup tables a migration used that are not
/// known yet: the next migration through them, seen in the Shreds stream,
/// finds them read.
async fn warm_lookup_tables(
    msg: &solana_stream_sdk::yellowstone_grpc_proto::prelude::Message,
    state: &Arc<RwLock<AppState>>,
    rpc_client: &Arc<RpcClient>,
) {
    let luts = state.read().await.luts.clone();
    let unknown: Vec<Pubkey> = msg
        .address_table_lookups
        .iter()
        .filter_map(|l| <[u8; 32]>::try_from(l.account_key.as_slice()).ok().map(Pubkey::new_from_array))
        .filter(|t| !luts.knows(t))
        .collect();
    if unknown.is_empty() {
        return;
    }
    let rpc = rpc_client.clone();
    tokio::spawn(async move { luts.fetch(&rpc, &unknown).await });
}

/// A pool seen created, in the Geyser stream or the Shreds stream: checked,
/// then bought in its own task.
pub async fn on_create_pool(
    new_pool: NewPool,
    sighting: Sighting,
    state: &Arc<RwLock<AppState>>,
    rpc_client: &Arc<RpcClient>,
    send_rpc_client: &Arc<RpcClient>,
) {
    let creator = new_pool.creator();
    info!(
        "Detected create_pool: pool={} {} creator={} via {:?} in slot {}",
        new_pool.pool,
        if new_pool.graduated { "graduation" } else { "made by hand" },
        creator,
        sighting.via,
        sighting.slot
    );
    if let Some(why) = new_pool.not_tradable() {
        info!("Skipping pool {}: {}", new_pool.pool, why);
        return;
    }
    if !creator_allows(state, new_pool.pool, creator).await {
        return;
    }
    let (state, rpc, send_rpc) = (state.clone(), rpc_client.clone(), send_rpc_client.clone());
    tokio::spawn(async move {
        handle_new_pool(new_pool, sighting, state, rpc, send_rpc).await;
    });
}

/// A swap on a pool a position is held on: its reserves after the swap,
/// from the transaction's token balances when they are there (no RPC
/// round trip), from the RPC otherwise; then the sell check.
#[allow(clippy::too_many_arguments)]
fn on_swap(
    pool: Pubkey,
    side: amm::Side,
    ix_accounts: &[Pubkey],
    account_keys: &[Pubkey],
    meta: Option<&solana_stream_sdk::yellowstone_grpc_proto::prelude::TransactionStatusMeta>,
    state: &Arc<RwLock<AppState>>,
    rpc_client: &Arc<RpcClient>,
    send_rpc_client: &Arc<RpcClient>,
) {
    // PumpSwap swap instruction account layout:
    // [0]=pool [1]=user [2]=global_config [3]=base_mint [4]=quote_mint
    // [5]=user_base_ata [6]=user_quote_ata
    // [7]=pool_base_vault [8]=pool_quote_vault ...
    // If PumpSwap changes this layout, fallback to RPC fetch.
    let mut reserves_from_meta: Option<(u64, u64)> = None;
    if let (Some(meta), true) = (meta, ix_accounts.len() >= 9) {
        let (base_vault, quote_vault) = (ix_accounts[7], ix_accounts[8]);
        let (mut base_r, mut quote_r) = (None, None);
        for tb in &meta.post_token_balances {
            let Some(acct) = account_keys.get(tb.account_index as usize) else { continue };
            let Some(amt) = tb.ui_token_amount.as_ref().and_then(|u| u.amount.parse::<u64>().ok()) else {
                continue;
            };
            if *acct == base_vault {
                base_r = Some(amt);
            } else if *acct == quote_vault {
                quote_r = Some(amt);
            }
        }
        if let (Some(b), Some(q)) = (base_r, quote_r) {
            reserves_from_meta = Some(side.sol_and_token(b, q));
        }
    }

    let (state, rpc, send_rpc) = (state.clone(), rpc_client.clone(), send_rpc_client.clone());
    tokio::spawn(async move {
        let (sol_reserves, token_reserves) = match reserves_from_meta {
            Some(r) => r,
            // Fallback: fetch from RPC (processed commitment)
            None => {
                let Ok(Some(account)) = rpc
                    .get_account_with_commitment(&pool, CommitmentConfig::processed())
                    .await
                    .map(|r| r.value)
                else {
                    return;
                };
                let Ok(pool_data) = crate::engine::deserialize_pool_lenient(&account.data) else { return };
                let (sol_vault, token_vault) = side.vaults(&pool_data);
                let balance = |vault: Pubkey| {
                    let rpc = rpc.clone();
                    async move { rpc.get_token_account_balance(&vault).await.ok().and_then(|b| b.amount.parse::<u64>().ok()) }
                };
                match (balance(sol_vault).await, balance(token_vault).await) {
                    (Some(sol), Some(tokens)) => (sol, tokens),
                    _ => return,
                }
            }
        };
        check_and_sell_positions(state, rpc, send_rpc, pool, token_reserves, sol_reserves).await;
    });
}
