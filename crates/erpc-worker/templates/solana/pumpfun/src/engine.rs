use crate::state::{AppState, PendingSell, Position, PositionStatus, TradeLog};
#[cfg(test)]
use crate::state::MAX_SELL_FAILURES;
use crate::i18n;
use crate::webhook::notify;
use chrono::Utc;
use log::{error, info, warn};
use rand::Rng;
use solana_commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use solana_instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use std::{sync::Arc, time::Duration};
use tokio::{sync::RwLock, time::sleep};
use crate::amm::{self, Market, NewPool, Side};
use crate::timing::Sighting;
use ultima_swap_pumpfun::{self as pumpswap, Pool};

const FEE_RECIPIENT_COUNT: usize = 8;
const TX_FEE_RESERVE: u64 = 10_000_000; // 0.01 SOL
const POOL_FETCH_RETRIES: usize = 10;
const POOL_FETCH_RETRY_DELAY_MS: u64 = 80;
/// Solana's base fee for a transaction with one signature.
const TX_FEE_LAMPORTS: u64 = 5_000;
/// The base fees of a whole trade: the buy, the sell, and closing the token
/// account.
const ROUND_TRIP_TX_FEES: u64 = 3 * TX_FEE_LAMPORTS;

/// What a take-profit sell must be sure to bring in: the buy times the
/// multiplier, plus the trade's fees. The sell is exact-out, so it brings
/// in exactly its minimum out, and that is what is held to this: the trade
/// then ends at least `buy × (multiplier − 1)` up. What a sell leaves is
/// sold only when that sell brings in more than its own fee.
///
/// `failed_sells` are the position's sells that landed and failed: each
/// paid a fee too, and is added.
fn take_profit_target(buy_price_lamports: u64, sell_multiplier: f64, failed_sells: u32) -> u64 {
    (buy_price_lamports as f64 * sell_multiplier) as u64
        + ROUND_TRIP_TX_FEES
        + u64::from(failed_sells) * TX_FEE_LAMPORTS
}

/// Whether tokens worth `current_value` now are sold to take profit: what
/// the exact-out sell is sure to bring in reaches the target.
fn take_profit_reached(
    current_value: u64,
    slippage_bps: u64,
    buy_price_lamports: u64,
    sell_multiplier: f64,
    failed_sells: u32,
) -> bool {
    pumpswap::with_slippage_min(current_value, slippage_bps).unwrap_or(0)
        >= take_profit_target(buy_price_lamports, sell_multiplier, failed_sells)
}

/// Whether a sell sure to bring in `min_out_lamports` is worth its fee. The
/// account is closed either way, in one transaction that brings the rent
/// back and burns what is left, so a sell costs one fee more than burning:
/// it is sent only when what it is sure to bring in is more than that.
fn worth_selling(min_out_lamports: u64) -> bool {
    min_out_lamports > TX_FEE_LAMPORTS
}

/// Token-2022 extensions a token may have and still be bought: metadata and
/// groups, which do not touch transfers.
const ALLOWED_MINT_EXTENSIONS: [u16; 6] = [
    18, // MetadataPointer
    19, // TokenMetadata
    20, // GroupPointer
    21, // TokenGroup
    22, // GroupMemberPointer
    23, // TokenGroupMember
];

/// Why the holders of a mint might be stopped from selling or closing, if
/// they might: a freeze authority, or a Token-2022 extension that can stop,
/// hook or tax transfers. Such a token buys fine and then fails every sell.
fn mint_blocks_selling(data: &[u8], owner: &Pubkey) -> Option<String> {
    // A mint is 82 bytes; the freeze authority is a COption<Pubkey> at 46,
    // its 4-byte tag non-zero when it is set.
    const MINT_LEN: usize = 82;
    const FREEZE_AUTHORITY: usize = 46;
    // Token-2022: the mint padded to an account's 165 bytes, the account
    // type, then type-length-value extensions.
    const EXTENSIONS: usize = 166;
    if *owner != pumpswap::TOKEN_PROGRAM && *owner != pumpswap::TOKEN_2022_PROGRAM {
        return Some(format!("owned by {}, not a token program", owner));
    }
    if data.len() < MINT_LEN {
        return Some("not a mint".to_string());
    }
    if data[FREEZE_AUTHORITY..FREEZE_AUTHORITY + 4] != [0, 0, 0, 0] {
        return Some("it has a freeze authority".to_string());
    }
    if data.len() == MINT_LEN {
        return None;
    }
    if *owner != pumpswap::TOKEN_2022_PROGRAM || data.len() < EXTENSIONS {
        return Some("its account data is not a mint's".to_string());
    }
    let mut at = EXTENSIONS;
    while at + 4 <= data.len() {
        let ty = u16::from_le_bytes([data[at], data[at + 1]]);
        let len = u16::from_le_bytes([data[at + 2], data[at + 3]]) as usize;
        if ty == 0 {
            break; // Uninitialized: the rest is padding.
        }
        if !ALLOWED_MINT_EXTENSIONS.contains(&ty) {
            return Some(format!("Token-2022 extension {} can stop, hook or tax transfers", ty));
        }
        at += 4 + len;
        if at > data.len() {
            return Some("its extensions cannot be read".to_string());
        }
    }
    None
}

/// Every transaction is simulated against the latest state before it is
/// sent, so one that would fail is refused for free instead of landing and
/// costing its fee. (Processed, so that a pool just created is there.)
fn send_config() -> RpcSendTransactionConfig {
    RpcSendTransactionConfig {
        skip_preflight: false,
        preflight_commitment: Some(CommitmentLevel::Processed),
        ..Default::default()
    }
}

/// A buy of a graduation goes out without a simulation: the send RPC may
/// not have the pool yet, a simulation there would refuse it, and the slot
/// it would land in is the one that counts. One that lands and fails pays
/// its fee.
fn buy_now_config() -> RpcSendTransactionConfig {
    RpcSendTransactionConfig {
        skip_preflight: true,
        ..Default::default()
    }
}

/// Confirm a transaction on-chain. Returns:
/// - Ok(true) if confirmed and successful
/// - Ok(false) if confirmed but failed (on-chain error)
/// - Err(msg) if timeout or RPC error
async fn confirm_transaction(rpc_client: &RpcClient, sig: &Signature, max_polls: u32) -> Result<bool, String> {
    for _ in 0..max_polls {
        sleep(Duration::from_millis(500)).await;
        match rpc_client.get_signature_statuses(&[*sig]).await {
            Ok(resp) => {
                if let Some(Some(status)) = resp.value.first() {
                    if status.satisfies_commitment(CommitmentConfig::confirmed()) {
                        return Ok(status.err.is_none());
                    }
                }
            }
            Err(e) => {
                warn!("getSignatureStatuses error for {}: {:?}", sig, e);
            }
        }
    }
    Err(format!("Tx {} not confirmed after {} polls", sig, max_polls))
}

/// Fetch the actual SOL change for a wallet from a confirmed transaction.
/// Returns the lamport difference (post - pre) for account index 0 (fee payer).
async fn fetch_actual_sol_change(rpc_client: &RpcClient, sig: &Signature) -> Option<i64> {
    match rpc_client.get_transaction_with_config(
        sig,
        solana_rpc_client_api::config::RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        },
    ).await {
        Ok(tx) => {
            let meta = tx.transaction.meta?;
            // Account index 0 = fee payer (our wallet). This holds for
            // self-signed transactions; multi-signer TXs would need
            // explicit index lookup.
            let pre = *meta.pre_balances.first()?;
            let post = *meta.post_balances.first()?;
            Some(post as i64 - pre as i64)
        }
        Err(e) => {
            warn!("Failed to fetch tx details for {}: {:?}", sig, e);
            None
        }
    }
}

/// Process a detected create_pool event. Performs a buy if conditions are met.
///
/// A pool takes a slot before anything is fetched, and gives it back when
/// its buy is over: buys under way count against max_positions, and no pool
/// is bought twice.
pub async fn handle_new_pool(
    new_pool: NewPool,
    sighting: Sighting,
    state: Arc<RwLock<AppState>>,
    rpc_client: Arc<RpcClient>,
    send_rpc_client: Arc<RpcClient>,
) {
    let Some((token_mint, _)) = new_pool.token() else {
        return;
    };
    let pool_address = new_pool.pool;
    {
        let mut s = state.write().await;
        if !s.running || s.sell_only {
            return;
        }
        if s.config.graduated_only && !new_pool.graduated {
            info!("Pool {} skipped: made by hand, and graduated_only is set", pool_address);
            return;
        }
        if let Err(why) = s.reserve_buy(pool_address, token_mint) {
            info!("Pool {} skipped: {}", pool_address, why);
            return;
        }
    }
    buy_new_pool(new_pool, sighting, token_mint, state.clone(), rpc_client, send_rpc_client).await;
    state.write().await.release_buy(&pool_address);
}

/// The pool to buy into and its reserves now, (SOL, token).
///
/// A graduation is taken as its `create_pool` made it: pump.fun's program
/// made the pool and minted the token, with no freeze authority and
/// metadata only, so nothing has to be read first. `graduated` is set in
/// two places only, each of which has that from pump.fun's program and not
/// from a transaction's word: `parse_create_pool` for a `create_pool` the
/// program called in a transaction that ran, and `Migration::new_pool` for
/// one not run yet, whose curve the program holds at the mint's address.
/// A pool made by hand is read from the chain, its token checked for what
/// could stop a sell.
async fn market_of(
    new_pool: &NewPool,
    rpc_client: &RpcClient,
) -> Result<(Market, u64, u64), String> {
    let Some(side) = new_pool.side() else {
        return Err("not a WSOL/token pool".to_owned());
    };
    if new_pool.graduated {
        let (_, token_program) = new_pool.token().expect("a WSOL/token pool");
        let (sol, tokens) = new_pool.sol_and_token().expect("a WSOL/token pool");
        let market = Market { pool: new_pool.pool, data: new_pool.data.clone(), side, token_program };
        return Ok((market, sol, tokens));
    }
    let pool_account = fetch_pool_account_with_retry(rpc_client, new_pool.pool)
        .await
        .map_err(|e| format!(
            "Fetch pool failed after {} retries ({} ms delay): {:?}",
            POOL_FETCH_RETRIES, POOL_FETCH_RETRY_DELAY_MS, e,
        ))?;
    let data = deserialize_pool_lenient(&pool_account.data).map_err(|e| format!("Deserialize pool failed: {:?}", e))?;
    if Side::of(&data) != Some(side) {
        return Err("the pool is not as its create_pool said".to_owned());
    }
    if let Some(why) = amm::not_tradable(&data, Some(&pool_account.data)) {
        return Err(format!("skipped: {why}"));
    }
    let (sol_vault, token_vault) = side.vaults(&data);
    let sol = fetch_token_balance_with_retry(rpc_client, &sol_vault)
        .await
        .map_err(|e| format!("Fetch SOL vault failed after retries: {:?}", e))?;
    let tokens = fetch_token_balance_with_retry(rpc_client, &token_vault)
        .await
        .map_err(|e| format!("Fetch token vault failed after retries: {:?}", e))?;
    let token_mint = side.token_mint(&data);
    let mint_account = rpc_client
        .get_account(&token_mint)
        .await
        .map_err(|e| format!("Failed to fetch mint account for token program detection: {:?}", e))?;
    // A token whose holders can be stopped from selling buys fine and then
    // fails every sell: it is not bought.
    if let Some(why) = mint_blocks_selling(&mint_account.data, &mint_account.owner) {
        return Err(format!("skipped: token {}: {}", token_mint, why));
    }
    Ok((Market { pool: new_pool.pool, data, side, token_program: mint_account.owner }, sol, tokens))
}

async fn buy_new_pool(
    new_pool: NewPool,
    sighting: Sighting,
    base_mint: Pubkey,
    state: Arc<RwLock<AppState>>,
    rpc_client: Arc<RpcClient>,
    send_rpc_client: Arc<RpcClient>,
) {
    let pool_address = new_pool.pool;
    // Read config first (needed for min_pool_sol check before notification).
    let (
        buy_amount_lamports,
        slippage_bps,
        sell_multiplier,
        min_pool_sol,
        webhook_url,
        wallet,
        (cu_price, cu_limit, priority_fee),
        timing,
    ) = {
        let s = state.read().await;
        let wallet = s.wallet.clone();
        (
            s.config.buy_amount_lamports,
            s.config.slippage_bps,
            s.config.sell_multiplier,
            s.config.min_pool_sol_lamports,
            s.webhook_url.clone(),
            wallet,
            (s.config.priority_fee_micro_lamports, s.config.compute_unit_limit, s.config.priority_fee_lamports()),
            s.timing.clone(),
        )
    };

    let keypair = match wallet {
        Some(kp) => kp,
        None => {
            error!("No wallet loaded, cannot buy");
            return;
        }
    };

    // The balance and a blockhash in one round trip, before anything else.
    let wallet_pubkey = keypair.pubkey();
    let (balance, blockhash) = tokio::join!(
        rpc_client.get_balance(&wallet_pubkey),
        rpc_client.get_latest_blockhash_with_commitment(CommitmentConfig::confirmed()),
    );
    let balance = match balance {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to fetch balance: {:?}", e);
            return;
        }
    };

    if balance < buy_amount_lamports + priority_fee + TX_FEE_RESERVE {
        let needed = buy_amount_lamports + priority_fee + TX_FEE_RESERVE;
        let error_msg = format!(
            "Insufficient balance: {} lamports (need {})",
            balance, needed
        );
        error!("{}", error_msg);
        state.write().await.push_log(TradeLog::error(
            pool_address, base_mint, buy_amount_lamports as f64 / 1e9, 0, None, error_msg,
        ));
        notify(
            webhook_url,
            i18n::insufficient_balance(
                &pool_address.to_string(),
                &base_mint.to_string(),
                &wallet_pubkey.to_string(),
                balance as f64 / 1e9,
                needed as f64 / 1e9,
            ),
        );
        return;
    }

    let (recent_blockhash, last_valid_block_height) = match blockhash {
        Ok(v) => v,
        Err(e) => {
            push_error_log(
                &state,
                pool_address,
                base_mint,
                buy_amount_lamports,
                format!("Blockhash failed: {:?}", e),
            )
            .await;
            return;
        }
    };

    let (market, sol_reserves, token_reserves) = match market_of(&new_pool, &rpc_client).await {
        Ok(m) => m,
        Err(why) if why.starts_with("skipped") => {
            info!("Pool {} {}", pool_address, why);
            return;
        }
        Err(why) => {
            push_error_log_with_webhook(&state, &webhook_url, pool_address, base_mint, buy_amount_lamports, why).await;
            return;
        }
    };
    let quote_token_program = market.token_program;

    // Check minimum pool SOL liquidity
    if sol_reserves < min_pool_sol {
        info!(
            "Pool {} skipped: SOL reserves {} < min_pool_sol {}",
            pool_address, sol_reserves, min_pool_sol
        );
        return;
    }

    // Notify via webhook + record in logs
    {
        let mut s = state.write().await;
        let pool_str = pool_address.to_string();
        let mint_str = base_mint.to_string();
        let sol = sol_reserves as f64 / 1e9;
        let ts = Utc::now().to_rfc3339();
        let msg = i18n::pool_qualified_log(&pool_str, &mint_str, sol, &ts);
        s.push_notification(pool_address, base_mint, msg);
        notify(webhook_url.clone(), i18n::pool_qualified_webhook(&pool_str, &mint_str, sol, &ts));
    }

    // At most buy_amount_lamports is spent, for at least the tokens it buys
    // now less the slippage allowance.
    let base_amount_out = match market
        .side
        .tokens_for_sol(sol_reserves, token_reserves, buy_amount_lamports)
        .and_then(|expected| pumpswap::with_slippage_min(expected, slippage_bps))
    {
        Ok(a) => a,
        Err(e) => {
            push_error_log(
                &state,
                pool_address,
                base_mint,
                buy_amount_lamports,
                format!("AMM math error: {:?}", e),
            )
            .await;
            return;
        }
    };

    let fee_idx = rand::thread_rng().gen_range(0..FEE_RECIPIENT_COUNT);

    info!(
        "Buying at least {} token atoms for at most {} lamports on pool {} ({:?})",
        base_amount_out, buy_amount_lamports, pool_address, market.side
    );

    // A priority fee, when one is set; the token's account; the SOL to
    // spend, wrapped; the buy; the WSOL account closed, its rent and what is
    // left coming back.
    let user = keypair.pubkey();
    let mut instructions = compute_budget(cu_price, cu_limit);
    instructions.push(pumpswap::create_ata_if_needed(&user, &base_mint, &quote_token_program));
    instructions.extend(amm::wrap_sol(&user, buy_amount_lamports));
    let buy_ix = match market.buy_ix(user, buy_amount_lamports, base_amount_out, fee_idx) {
        Ok(ix) => ix,
        Err(e) => {
            push_error_log(
                &state,
                pool_address,
                base_mint,
                buy_amount_lamports,
                format!("Build buy ix failed: {:?}", e),
            )
            .await;
            return;
        }
    };
    instructions.push(buy_ix);
    instructions.push(amm::unwrap_sol(&user));

    let tx = Transaction::new_signed_with_payer(&instructions, Some(&user), &[keypair.as_ref()], recent_blockhash);

    // The signature is the transaction's own, known before it is sent.
    let sig = tx.signatures[0];
    let sig_str = sig.to_string();
    // A graduation is bought without a simulation: the pool may not be on
    // the send RPC yet, and a simulation there would refuse the buy.
    let config = if new_pool.graduated { buy_now_config() } else { send_config() };
    let sending = std::time::Instant::now();
    let landed = match send_rpc_client.send_transaction_with_config(&tx, config).await {
        // Refused by its simulation: it never went out, at no cost.
        Err(e) if refused_by_preflight(&e) => {
            push_error_log_with_webhook(
                &state, &webhook_url, pool_address, base_mint, buy_amount_lamports,
                format!("Buy tx refused by its simulation: {:?}", e),
            ).await;
            false
        }
        // Sent, or an error that can follow a transaction that went out:
        // watched until it lands, fails, or its blockhash is past.
        sent => {
            timing.lock().expect("timing lock").on_buy_sent(pool_address.to_string(), &sighting, sending);
            match &sent {
                Ok(_) => info!("Buy tx sent: sig={} tokens={}", sig_str, base_amount_out),
                Err(e) => warn!("Buy tx send returned an error, and it may have gone out: {:?}", e),
            }
            let settled = settle_buy(&rpc_client, &sig, last_valid_block_height).await;
            if matches!(settled, Pending::Landed | Pending::FailedOnChain) {
                record_landing(rpc_client.clone(), timing.clone(), pool_address, sig);
            }
            match settled {
                Pending::Landed => true,
                Pending::FailedOnChain => {
                    // Buy failed on-chain (slippage, etc). Only tx fee lost (~0.000005 SOL).
                    push_error_log(
                        &state, pool_address, base_mint, buy_amount_lamports,
                        format!("Buy tx confirmed but failed on-chain: {}", sig_str),
                    ).await;
                    false
                }
                // Expired unseen, or the RPC could not say: tokens in the
                // wallet still mean it landed, and it is tracked rather than
                // left. (No position in this token is open: reserve_buy.)
                settled => match read_holding(
                    &rpc_client, &keypair.pubkey(), &base_mint, &quote_token_program,
                ).await {
                    Holding::Held(held) if held > 0 => {
                        warn!("Buy {} not confirmed but {} tokens are held: tracking the position", sig_str, held);
                        true
                    }
                    holding => {
                        push_error_log_with_webhook(
                            &state, &webhook_url, pool_address, base_mint, buy_amount_lamports,
                            format!(
                                "Buy tx not tracked (sig {}: {:?}; wallet: {:?}); a restart takes it up if it landed",
                                sig_str, settled, holding
                            ),
                        ).await;
                        false
                    }
                },
            }
        }
    };
    if !landed {
        return;
    }
    info!("Buy tx landed: sig={}", sig_str);

    // The amount bought, from the chain. When it cannot be read yet, the
    // estimate is kept, marked unknown: the monitor reads it before any
    // decision, so a take-profit is never judged on the estimate.
    let (final_amount, amount_known) = match read_holding(
        &rpc_client, &keypair.pubkey(), &base_mint, &quote_token_program,
    ).await {
        Holding::Held(n) if n > 0 => (n, true),
        _ => (base_amount_out, false),
    };
    if final_amount != base_amount_out {
        info!("Buy actual tokens: {} (estimated: {})", final_amount, base_amount_out);
    }

    // What the buy cost, the priority fee in it: a take-profit covers both.
    let position = Position {
        amount_known,
        ..Position::opened(
            pool_address, base_mint, buy_amount_lamports + priority_fee, final_amount, quote_token_program, market.side,
        )
    };
    {
        let mut s = state.write().await;
        s.positions.insert(position.id.clone(), position);
        s.record(TradeLog::buy(pool_address, base_mint, buy_amount_lamports as f64 / 1e9, final_amount, sig_str.clone()));
    }
    notify(
        webhook_url,
        i18n::buy_confirmed(
            &pool_address.to_string(),
            &base_mint.to_string(),
            buy_amount_lamports as f64 / 1e9,
            final_amount,
            &sig_str,
        ),
    );
    spawn_sell_monitor(state, rpc_client, send_rpc_client, pool_address, sell_multiplier);
}

/// ComputeBudget's instructions setting a buy's compute unit limit and
/// price, or none when no price is set.
fn compute_budget(micro_lamports: u64, limit: u32) -> Vec<Instruction> {
    if micro_lamports == 0 {
        return Vec::new();
    }
    let mut set_limit = vec![2];
    set_limit.extend_from_slice(&limit.to_le_bytes());
    let mut set_price = vec![3];
    set_price.extend_from_slice(&micro_lamports.to_le_bytes());
    [set_limit, set_price]
        .into_iter()
        .map(|data| Instruction { program_id: COMPUTE_BUDGET_PROGRAM, accounts: Vec::new(), data })
        .collect()
}

const COMPUTE_BUDGET_PROGRAM: Pubkey = Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");

/// Notes, off the buy's path, the slot a buy landed in (it may have failed
/// there): how many slots after its pool's is what `GET /api/timing` shows.
fn record_landing(
    rpc_client: Arc<RpcClient>,
    timing: Arc<std::sync::Mutex<crate::timing::Timing>>,
    pool: Pubkey,
    sig: Signature,
) {
    tokio::spawn(async move {
        match rpc_client.get_signature_statuses_with_history(&[sig]).await {
            Ok(resp) => {
                if let Some(Some(status)) = resp.value.first() {
                    timing.lock().expect("timing lock").on_buy_landed(&pool.to_string(), status.slot);
                }
            }
            Err(e) => warn!("Could not read the slot buy {} landed in: {:?}", sig, e),
        }
    });
}

/// Watches the pool of a position and sells when its time comes: take
/// profit, timeout, liquidity collapse, a retry after a failure, the rest of
/// a partial sell. It runs while a position on the pool is open, one being
/// sold included, so that none of these waits on a swap by someone else.
fn spawn_sell_monitor(
    state: Arc<RwLock<AppState>>,
    rpc_client: Arc<RpcClient>,
    send_rpc_client: Arc<RpcClient>,
    pool_address: Pubkey,
    sell_multiplier: f64,
) {
    tokio::spawn(async move {
        info!("Sell monitor started for pool {} (target {}x)", pool_address, sell_multiplier);
        let mut poll_count: u64 = 0;
        loop {
            sleep(Duration::from_millis(500)).await;
            poll_count += 1;
            if poll_count <= 3 || poll_count.is_multiple_of(60) {
                info!("Sell monitor poll #{} for pool {}", poll_count, pool_address);
            }
            if !state.read().await.pool_has_open_position(&pool_address) {
                info!("Sell monitor exiting for pool {} (no open position)", pool_address);
                break;
            }

            let pool_account = match rpc_client
                .get_account_with_commitment(&pool_address, CommitmentConfig::confirmed())
                .await
            {
                Ok(resp) => match resp.value {
                    Some(a) => a,
                    None => { warn!("Sell monitor: pool account not found for {}", pool_address); continue; },
                },
                Err(e) => { warn!("Sell monitor: RPC error fetching pool {}: {:?}", pool_address, e); continue; },
            };
            let pool_data = match deserialize_pool_lenient(&pool_account.data) {
                Ok(p) => p,
                Err(e) => { warn!("Sell monitor: pool deserialize failed for {}: {:?}", pool_address, e); continue; },
            };

            let Some(side) = Side::of(&pool_data) else {
                warn!("Sell monitor: pool {} is not a WSOL/token pool", pool_address);
                continue;
            };
            let (sol_vault, token_vault) = side.vaults(&pool_data);
            let token_reserves = match fetch_token_balance_with_retry(&rpc_client, &token_vault).await {
                Ok(b) => b,
                Err(e) => { warn!("Sell monitor: token reserves fetch failed: {:?}", e); continue; },
            };
            let sol_reserves = match fetch_token_balance_with_retry(&rpc_client, &sol_vault).await {
                Ok(b) => b,
                Err(e) => { warn!("Sell monitor: SOL reserves fetch failed: {:?}", e); continue; },
            };

            check_and_sell_positions(
                state.clone(),
                rpc_client.clone(),
                send_rpc_client.clone(),
                pool_address,
                token_reserves,
                sol_reserves,
            ).await;
        }
    });
}

/// Check all active positions for sell targets.
///
/// Each position claimed for selling goes through the same steps: a sell
/// sent before and not yet settled is settled first, so nothing new is
/// signed while it can still land; what the wallet holds is read from the
/// chain, never taken from memory; then it is sold, or burned and closed
/// when a sell would not bring in more than its fee.
pub async fn check_and_sell_positions(
    state: Arc<RwLock<AppState>>,
    rpc_client: Arc<RpcClient>,
    send_rpc_client: Arc<RpcClient>,
    pool_address: Pubkey,
    current_token_reserves: u64,
    current_sol_reserves: u64,
) {
    let (sell_multiplier, slippage_bps, sell_timeout_secs, exit_pool_sol_lamports, wallet) = {
        let s = state.read().await;
        let wb = s.wallet.clone();
        (
            s.config.sell_multiplier,
            s.config.slippage_bps,
            s.config.sell_timeout_secs,
            s.config.exit_pool_sol_lamports,
            wb,
        )
    };

    let keypair = match wallet {
        Some(kp) => kp,
        None => return,
    };

    // B2 fix: collect IDs, not indices.
    let ids_to_sell: Vec<String> = {
        let s = state.read().await;
        let now = Utc::now();
        s.positions
            .values()
            .filter(|p| {
                if p.pool != pool_address || !s.may_sell(p, now) {
                    return false;
                }
                if claimed_on_every_check(p) {
                    info!(
                        "Drain or settle: position {} total_sell={} pending={} closing={}",
                        p.id, p.total_sell_lamports, p.pending_sell.is_some(), p.closing
                    );
                    return true;
                }
                let elapsed_secs = (Utc::now() - p.bought_at).num_seconds().max(0) as u64;
                // Forced retreat modes
                if let Some(why) =
                    forced_exit_reason(elapsed_secs, sell_timeout_secs, current_sol_reserves, exit_pool_sol_lamports)
                {
                    info!("Forced exit: pos={} {} amount={}", p.id, why, p.base_amount);
                    return true;
                }
                let current_value = p
                    .side
                    .sol_for_tokens(current_sol_reserves, current_token_reserves, p.base_amount)
                    .unwrap_or(0);
                let should_sell = take_profit_reached(
                    current_value, slippage_bps, p.buy_price_lamports, sell_multiplier, p.sell_failures,
                );
                if !should_sell {
                    info!("Sell check: pos={} val={} target={} base_r={} quote_r={} amount={}",
                        p.id, current_value, take_profit_target(p.buy_price_lamports, sell_multiplier, p.sell_failures),
                        current_sol_reserves, current_token_reserves, p.base_amount);
                }
                should_sell
            })
            .map(|p| p.id.clone())
            .collect()
    };

    for id in ids_to_sell {
        // Active → Selling in one step: the monitor and every swap on the
        // pool check at once, and only the one that claims it sells.
        let mut position = match state.write().await.claim_for_sell(&id, Utc::now()) {
            Some(p) => p,
            None => continue,
        };
        let mut last_sell_sig: Option<String> = None;

        // 1. A sell sent before is settled before anything new is signed.
        if let Some(pending) = position.pending_sell.clone() {
            match resolve_pending(&rpc_client, &pending.signature, pending.last_valid_block_height).await {
                Pending::Landed => {
                    info!("Earlier sell {} of position {} landed", pending.signature, id);
                    record_sell_proceeds(&state, &rpc_client, &id, &position, &pending).await;
                    last_sell_sig = Some(pending.signature.to_string());
                }
                Pending::FailedOnChain => {
                    warn!("Earlier sell {} of position {} failed on-chain", pending.signature, id);
                    set_pending_sell(&state, &id, None).await;
                    record_sell_failure(&state, &id, &position, true).await;
                    continue;
                }
                Pending::InFlight => {
                    state.write().await.wait_for_pending(&id, Utc::now());
                    continue;
                }
                Pending::Expired => {
                    // It cost nothing, and is counted now, once.
                    info!("Earlier sell {} of position {} expired unseen", pending.signature, id);
                    set_pending_sell(&state, &id, None).await;
                    record_sell_failure(&state, &id, &position, false).await;
                    continue;
                }
                Pending::Unknown => {
                    record_sell_failure(&state, &id, &position, false).await;
                    continue;
                }
            }
        }

        // 2. What the wallet holds now, read from the chain: a sell that
        // landed late, a buy recorded from its estimate, or any change from
        // outside shows here. The read sets the amount only.
        let holding = read_holding(
            &rpc_client, &keypair.pubkey(), &position.base_mint, &position.quote_token_program,
        ).await;
        if let Holding::Held(held) = holding {
            state.write().await.record_holding(&id, held);
        }
        // As it is now, with what the settling and the read recorded.
        if let Some(p) = state.read().await.positions.get(&id) {
            position = p.clone();
        }

        let elapsed_secs = (Utc::now() - position.bought_at).num_seconds().max(0) as u64;
        let forced_reason =
            forced_exit_reason(elapsed_secs, sell_timeout_secs, current_sol_reserves, exit_pool_sol_lamports);

        // 3. What to do, decided in one place (plan_sell).
        let plan = plan_sell(
            &position, holding, forced_reason.clone(),
            current_sol_reserves, current_token_reserves, slippage_bps, sell_multiplier,
        );
        match &plan {
            Plan::Hold => {
                state.write().await.hold(&id);
                continue;
            }
            Plan::Retry(why) => {
                error!("Position {} not sold now: {}", id, why);
                record_sell_failure(&state, &id, &position, false).await;
                continue;
            }
            Plan::CloseSoldOut => {
                close_position(&state, &rpc_client, &send_rpc_client, &keypair, &id, &position, Close::Sold(last_sell_sig))
                    .await;
                continue;
            }
            Plan::Burn { .. } | Plan::Sell { .. } => {}
        }

        let fee_idx = rand::thread_rng().gen_range(0..FEE_RECIPIENT_COUNT);

        let pool_account = match rpc_client
            .get_account_with_commitment(&pool_address, CommitmentConfig::confirmed())
            .await
        {
            Ok(resp) => match resp.value {
                Some(a) => a,
                None => {
                    error!("Pool {} for sell not found", pool_address);
                    record_sell_failure(&state, &id, &position, false).await;
                    continue;
                }
            },
            Err(e) => {
                error!("Fetch pool for sell failed: {:?}", e);
                record_sell_failure(&state, &id, &position, false).await;
                continue;
            }
        };

        let pool_data = match deserialize_pool_lenient(&pool_account.data) {
            Ok(p) => p,
            Err(e) => {
                error!("Deserialize pool for sell failed: {:?}", e);
                record_sell_failure(&state, &id, &position, false).await;
                continue;
            }
        };

        let min_quote_out = match plan {
            Plan::Sell { min_out } => min_out,
            // Not worth a sell: burn + close the ATA instead. Tokens are
            // destroyed only when the plan, made again on reserves read at
            // confirmed just now rather than on what the stream passed in,
            // still says so.
            Plan::Burn { .. } => {
                let (sol_vault, token_vault) = position.side.vaults(&pool_data);
                let fresh = match (
                    fetch_token_balance_with_retry(&rpc_client, &sol_vault).await,
                    fetch_token_balance_with_retry(&rpc_client, &token_vault).await,
                ) {
                    // The low-liquidity exit is judged on the fresh SOL
                    // reserve too, not on the stream's.
                    (Ok(sol), Ok(tokens)) => Some(plan_sell(
                        &position,
                        holding,
                        forced_exit_reason(elapsed_secs, sell_timeout_secs, sol, exit_pool_sol_lamports),
                        sol,
                        tokens,
                        slippage_bps,
                        sell_multiplier,
                    )),
                    _ => None,
                };
                match fresh {
                    Some(Plan::Burn { reason }) => {
                        close_position(&state, &rpc_client, &send_rpc_client, &keypair, &id, &position, Close::Burn(reason))
                            .await;
                    }
                    Some(Plan::Hold) => {
                        // Worth holding on fresh reserves.
                        state.write().await.hold(&id);
                    }
                    Some(_) => {
                        // Decided otherwise on fresh reserves: the next check.
                        if let Some(p) = state.write().await.positions.get_mut(&id) {
                            p.status = PositionStatus::Active;
                        }
                    }
                    None => {
                        error!("Pool {} reserves could not be read again before a burn", pool_address);
                        record_sell_failure(&state, &id, &position, false).await;
                    }
                }
                continue;
            }
            Plan::Hold | Plan::Retry(_) | Plan::CloseSoldOut => continue,
        };

        let market = Market {
            pool: pool_address,
            data: pool_data,
            side: position.side,
            token_program: position.quote_token_program,
        };
        let sell_ix = match market.sell_ix(keypair.pubkey(), position.base_amount, min_quote_out, fee_idx) {
            Ok(ix) => ix,
            Err(e) => {
                error!("Build sell ix failed: {:?}", e);
                record_sell_failure(&state, &id, &position, false).await;
                continue;
            }
        };

        let (bh, last_valid_block_height) = match rpc_client
            .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())
            .await
        {
            Ok(v) => v,
            Err(e) => {
                error!("Blockhash for sell failed: {:?}", e);
                record_sell_failure(&state, &id, &position, false).await;
                continue;
            }
        };

        // The WSOL account the sell pays into, made when there is none, and
        // closed after it so that the SOL and the rent come back.
        let user = keypair.pubkey();
        let tx = Transaction::new_signed_with_payer(
            &[
                pumpswap::create_ata_if_needed(&user, &pumpswap::WSOL_MINT, &pumpswap::TOKEN_PROGRAM),
                sell_ix,
                amm::unwrap_sol(&user),
            ],
            Some(&user),
            &[keypair.as_ref()],
            bh,
        );

        // 4. The sell is recorded before it is sent: whatever the send
        // returns, nothing new is signed until this one is settled.
        let pending = PendingSell {
            signature: tx.signatures[0],
            last_valid_block_height,
            min_out: min_quote_out,
        };
        let sig_str = pending.signature.to_string();
        set_pending_sell(&state, &id, Some(pending.clone())).await;

        match send_rpc_client.send_transaction_with_config(&tx, send_config()).await {
            Ok(_) => {
                info!("Sell tx sent for position {}: sig={}", id, sig_str);

                match confirm_transaction(&rpc_client, &pending.signature, 30).await {
                    Ok(true) => {
                        info!("Sell tx confirmed for position {}: sig={}", id, sig_str);
                        record_sell_proceeds(&state, &rpc_client, &id, &position, &pending).await;
                        // 5. What is left decides what comes next.
                        match read_holding(
                            &rpc_client, &keypair.pubkey(), &position.base_mint, &position.quote_token_program,
                        ).await {
                            Holding::Held(0) => {
                                close_position(
                                    &state, &rpc_client, &send_rpc_client, &keypair, &id, &position,
                                    Close::Sold(Some(sig_str)),
                                ).await;
                            }
                            holding => {
                                // Some left, or not readable now: the next
                                // check reads it again and drains it.
                                info!("Position {} after the sell: {:?}; draining", id, holding);
                                let mut s = state.write().await;
                                if let Holding::Held(left) = holding {
                                    s.record_holding(&id, left);
                                }
                                if let Some(p) = s.positions.get_mut(&id) {
                                    p.status = PositionStatus::Active;
                                }
                            }
                        }
                    }
                    Ok(false) => {
                        warn!("Sell tx failed on-chain for position {}: sig={}", id, sig_str);
                        set_pending_sell(&state, &id, None).await;
                        // Landed and failed: this one paid its fee.
                        record_sell_failure(&state, &id, &position, true).await;
                        report_sell_error(
                            &state,
                            &position,
                            Some(sig_str.clone()),
                            format!("Sell tx failed on-chain: {}", sig_str),
                            i18n::sell_failed_onchain(&position.pool.to_string(), &sig_str),
                        )
                        .await;
                    }
                    Err(timeout_msg) => {
                        // Still pending: the next check settles it before
                        // signing anything new, and counts it then.
                        warn!("{}", timeout_msg);
                        let mut s = state.write().await;
                        s.wait_for_pending(&id, Utc::now());
                        notify(s.webhook_url.clone(), i18n::sell_tx_unknown(&position.pool.to_string(), &sig_str));
                    }
                }
            }
            Err(e) => {
                // Refused by its simulation: it never went out, at no cost,
                // and is counted now. Any other error can follow a
                // transaction that did go out: it stays pending, and the next
                // check settles it and counts it then.
                let err_msg = format!("Sell tx send failed for position {}: {:?}", id, e);
                error!("{}", err_msg);
                if refused_by_preflight(&e) {
                    set_pending_sell(&state, &id, None).await;
                    record_sell_failure(&state, &id, &position, false).await;
                } else {
                    state.write().await.wait_for_pending(&id, Utc::now());
                }
                let discord = i18n::sell_send_failed(&position.pool.to_string(), &err_msg);
                report_sell_error(&state, &position, None, err_msg, discord).await;
            }
        }
    }
}

/// What became of a transaction sent before.
#[derive(Debug)]
enum Pending {
    /// Confirmed, and it went through.
    Landed,
    /// Confirmed, and it failed: it paid its fee.
    FailedOnChain,
    /// Not confirmed yet, and it can still land.
    InFlight,
    /// Never seen, and its blockhash is past: it cannot land any more.
    Expired,
    /// The RPC could not say.
    Unknown,
}

/// What became of a transaction sent before. The block height is read
/// before the status: one that lands in its last valid block between the
/// two reads is then seen as landed, never taken for expired.
async fn resolve_pending(rpc_client: &RpcClient, signature: &Signature, last_valid_block_height: u64) -> Pending {
    let height = match rpc_client
        .get_block_height_with_commitment(CommitmentConfig::confirmed())
        .await
    {
        Ok(h) => h,
        Err(e) => {
            warn!("getBlockHeight error: {:?}", e);
            return Pending::Unknown;
        }
    };
    let status = match rpc_client
        .get_signature_statuses_with_history(&[*signature])
        .await
    {
        Ok(resp) => resp.value.into_iter().next().flatten(),
        Err(e) => {
            warn!("getSignatureStatuses error for {}: {:?}", signature, e);
            return Pending::Unknown;
        }
    };
    if let Some(status) = status {
        if status.satisfies_commitment(CommitmentConfig::confirmed()) {
            return if status.err.is_none() { Pending::Landed } else { Pending::FailedOnChain };
        }
        return Pending::InFlight;
    }
    pending_after_unseen(height, last_valid_block_height)
}

/// How long a buy is watched, at most, before the wallet decides.
const SETTLE_BUY_LIMIT_SECS: u64 = 180;

/// What became of a buy: watched until it is confirmed or its blockhash is
/// past, so that a buy landing late is tracked, not left. The pool's slot is
/// held meanwhile. Unknown when the RPC could not say in time.
async fn settle_buy(rpc_client: &RpcClient, signature: &Signature, last_valid_block_height: u64) -> Pending {
    let started = std::time::Instant::now();
    loop {
        sleep(Duration::from_millis(500)).await;
        match resolve_pending(rpc_client, signature, last_valid_block_height).await {
            Pending::InFlight | Pending::Unknown if started.elapsed() < Duration::from_secs(SETTLE_BUY_LIMIT_SECS) => {}
            Pending::InFlight => return Pending::Unknown,
            settled => return settled,
        }
    }
}

/// A sell never seen can still land while the chain has not passed its
/// blockhash's last valid block height.
fn pending_after_unseen(block_height: u64, last_valid_block_height: u64) -> Pending {
    if block_height > last_valid_block_height {
        Pending::Expired
    } else {
        Pending::InFlight
    }
}

/// Whether a send error is the RPC refusing the transaction on its
/// simulation: then it never went out.
fn refused_by_preflight(e: &solana_rpc_client_api::client_error::Error) -> bool {
    use solana_rpc_client_api::client_error::ErrorKind;
    use solana_rpc_client_api::request::{RpcError, RpcResponseErrorData};
    matches!(
        e.kind(),
        ErrorKind::RpcError(RpcError::RpcResponseError {
            data: RpcResponseErrorData::SendTransactionPreflightFailure(_),
            ..
        })
    )
}

async fn set_pending_sell(state: &Arc<RwLock<AppState>>, id: &str, pending: Option<PendingSell>) {
    if let Some(p) = state.write().await.positions.get_mut(id) {
        p.pending_sell = pending;
    }
}

/// A sell that went through: what it brought in is added to the position's
/// proceeds, and whatever is left is drained next.
async fn record_sell_proceeds(
    state: &Arc<RwLock<AppState>>,
    rpc_client: &RpcClient,
    id: &str,
    position: &Position,
    pending: &PendingSell,
) {
    // Fetch actual SOL received (lamport delta for payer account[0]); an
    // exact-out sell brings in its minimum out when that cannot be read.
    let actual_lamports = match fetch_actual_sol_change(rpc_client, &pending.signature).await {
        Some(delta) if delta > 0 => delta as u64,
        _ => pending.min_out,
    };
    let mut s = state.write().await;
    if let Some(p) = s.positions.get_mut(id) {
        p.total_sell_lamports += actual_lamports;
        p.pending_sell = None;
        p.draining = true;
    }
    s.sell_succeeded(id);
    s.record(TradeLog::sell(
        position.pool,
        position.base_mint,
        actual_lamports as f64 / 1e9,
        position.base_amount,
        pending.signature.to_string(),
    ));
}

/// Records a sell that went wrong against its position, and tells Discord
/// when a webhook is set.
async fn report_sell_error(
    state: &Arc<RwLock<AppState>>,
    position: &Position,
    signature: Option<String>,
    error: String,
    discord: String,
) {
    let mut s = state.write().await;
    s.push_log(TradeLog::error(position.pool, position.base_mint, 0.0, position.base_amount, signature, error));
    notify(s.webhook_url.clone(), discord);
}

/// How a position ends.
enum Close {
    /// Everything was sold; the last sell's signature, when there was one.
    Sold(Option<String>),
    /// What is left is burned, for this reason.
    Burn(String),
}

/// Ends a position: burns what is left and closes its token account, which
/// brings the rent back, then reports the trade. A close that does not go
/// through leaves the position open and watched (closing), and it is tried
/// again after a wait like a failed sell: the rent comes back once a close
/// lands.
async fn close_position(
    state: &Arc<RwLock<AppState>>,
    rpc_client: &RpcClient,
    send_rpc_client: &RpcClient,
    keypair: &solana_sdk::signer::keypair::Keypair,
    id: &str,
    position: &Position,
    how: Close,
) {
    if let Close::Burn(reason) = &how {
        info!("Position {} retreat burn: {} — closing ATA", id, reason);
    }
    // After a full sell nothing is burned; a burn burns the amount it was
    // decided for, read just before.
    let burn = match &how {
        Close::Sold(_) => 0,
        Close::Burn(_) => position.base_amount,
    };
    let burn_sig = match burn_and_close_ata(
        rpc_client, send_rpc_client, keypair,
        &position.base_mint, &position.quote_token_program,
        burn, position.close_sent,
    ).await {
        CloseOutcome::Closed(sig) => sig,
        CloseOutcome::Failed { paid, sent } => {
            warn!("Position {}: closing its token account did not go through; tried again after a wait", id);
            // Looked at again on every check (closing), but not drained: a
            // position that never had a sell land keeps its take-profit.
            if let Some(p) = state.write().await.positions.get_mut(id) {
                p.closing = true;
                p.close_sent |= sent;
            }
            record_sell_failure(state, id, position, paid).await;
            return;
        }
    };
    // The account is closed: what follows reports a trade that is over.
    let close_ok = true;

    let (total_sell, webhook_url) = {
        let mut s = state.write().await;
        let ts = s.positions.get(id).map(|p| p.total_sell_lamports).unwrap_or(0);
        if let Some(p) = s.positions.get_mut(id) {
            p.status = PositionStatus::Closed;
        }
        if let Close::Burn(reason) = &how {
            s.record(TradeLog::note(
                position.pool,
                position.base_mint,
                position.base_amount,
                format!("Retreat burn: {reason} | ATA closed"),
            ));
        }
        (ts, s.webhook_url.clone())
    };

    let buy_sol = position.buy_price_lamports as f64 / 1e9;
    let sell_sol = total_sell as f64 / 1e9;
    let profit_sol = sell_sol - buy_sol;
    let profit_pct = if buy_sol > 0.0 { (profit_sol / buy_sol) * 100.0 } else { 0.0 };
    let profit_sign = if profit_sol >= 0.0 { "+" } else { "" };
    let emoji = if profit_sol >= 0.0 { "🟢" } else { "🔴" };

    let discord_msg = match &how {
        Close::Burn(reason) => i18n::retreat_burn(
            &position.pool.to_string(),
            &position.base_mint.to_string(),
            reason,
            emoji,
            profit_sign,
            profit_sol,
            profit_pct,
            buy_sol,
            sell_sol,
            close_ok,
            burn_sig.as_deref(),
        ),
        Close::Sold(last_sig) => {
            info!(
                "Position {} CLOSED: buy={:.6} SOL, total_sell={:.6} SOL, profit={}{:.6} SOL ({}{:.1}%)",
                id, buy_sol, sell_sol, profit_sign, profit_sol, profit_sign, profit_pct
            );
            i18n::trade_complete(
                emoji,
                &position.pool.to_string(),
                &position.base_mint.to_string(),
                profit_sign,
                profit_sol,
                profit_pct,
                buy_sol,
                sell_sol,
                last_sig.as_deref().or(burn_sig.as_deref()).unwrap_or("-"),
                close_ok,
            )
        }
    };
    notify(webhook_url, discord_msg);
    maybe_auto_stop_after_cycle(state).await;
}

async fn fetch_pool_account_with_retry(
    rpc_client: &RpcClient,
    pool_address: Pubkey,
) -> anyhow::Result<solana_sdk::account::Account> {
    let mut last_error = None;
    let commitment = CommitmentConfig::confirmed();

    for attempt in 0..POOL_FETCH_RETRIES {
        match rpc_client
            .get_account_with_commitment(&pool_address, commitment)
            .await
        {
            Ok(response) => {
                if let Some(account) = response.value {
                    if attempt > 0 {
                        info!(
                            "Pool account {} available after {} retries (~{} ms)",
                            pool_address,
                            attempt,
                            attempt as u64 * POOL_FETCH_RETRY_DELAY_MS,
                        );
                    }
                    return Ok(account);
                }
                // RPC returned null value — not yet visible at confirmed.
                last_error = Some(anyhow::anyhow!("AccountNotFound at confirmed: {}", pool_address));
            }
            Err(error) => {
                let is_not_found = format!("{error:?}").contains("AccountNotFound");
                last_error = Some(anyhow::anyhow!(error));
                if !is_not_found {
                    break; // Non-retryable error
                }
            }
        }
        if attempt + 1 < POOL_FETCH_RETRIES {
            sleep(Duration::from_millis(POOL_FETCH_RETRY_DELAY_MS)).await;
        }
    }

    Err(last_error.expect("retry loop must record last error"))
}

async fn push_error_log(
    state: &Arc<RwLock<AppState>>,
    pool: Pubkey,
    base_mint: Pubkey,
    amount_lamports: u64,
    error_msg: String,
) {
    push_error_log_with_webhook(state, &None, pool, base_mint, amount_lamports, error_msg).await;
}

async fn push_error_log_with_webhook(
    state: &Arc<RwLock<AppState>>,
    webhook_url: &Option<String>,
    pool: Pubkey,
    base_mint: Pubkey,
    amount_lamports: u64,
    error_msg: String,
) {
    error!("{}", error_msg);
    let discord = i18n::error_notify(&pool.to_string(), &base_mint.to_string(), &error_msg);
    let mut s = state.write().await;
    s.push_log(TradeLog::error(pool, base_mint, amount_lamports as f64 / 1e9, 0, None, error_msg));
    // The webhook given, else the one the state knows.
    notify(webhook_url.clone().or_else(|| s.webhook_url.clone()), discord);
}

/// Fetch token account balance with retries at confirmed commitment.
async fn fetch_token_balance_with_retry(
    rpc_client: &RpcClient,
    token_account: &Pubkey,
) -> anyhow::Result<u64> {
    let mut last_error = None;
    let commitment = CommitmentConfig::confirmed();
    for attempt in 0..POOL_FETCH_RETRIES {
        match rpc_client
            .get_token_account_balance_with_commitment(token_account, commitment)
            .await
        {
            Ok(response) => return Ok(response.value.amount.parse::<u64>().unwrap_or(0)),
            Err(e) => {
                let msg = format!("{e:?}");
                let is_not_found = msg.contains("could not find account") || msg.contains("AccountNotFound");
                last_error = Some(anyhow::anyhow!(e));
                if !is_not_found {
                    break;
                }
            }
        }
        if attempt + 1 < POOL_FETCH_RETRIES {
            sleep(Duration::from_millis(POOL_FETCH_RETRY_DELAY_MS)).await;
        }
    }
    Err(last_error.expect("retry loop must record last error"))
}

/// What a burn-and-close did.
enum CloseOutcome {
    /// The account is gone, by this transaction (its signature) or before.
    Closed(Option<String>),
    /// Not done; `paid` when it landed and failed, `sent` when it may have
    /// gone out.
    Failed { paid: bool, sent: bool },
}

/// What a close does with the account it finds (`None`: the RPC cannot
/// find it).
#[derive(Debug, PartialEq)]
enum CloseStart {
    /// It holds exactly what was decided: burn that, and close.
    Proceed,
    /// Gone, and a close of ours was sent before: it landed.
    AlreadyClosed,
    /// Not now: decided again on the next check.
    NotNow(&'static str),
}

fn close_start(found: Option<u64>, burn: u64, close_sent: bool) -> CloseStart {
    match found {
        // An RPC behind by a slot or two cannot find an account a buy just
        // made: gone counts only after a close of ours.
        None if close_sent => CloseStart::AlreadyClosed,
        None => CloseStart::NotNow("not found, and no close of ours was sent"),
        Some(held) if held == burn => CloseStart::Proceed,
        Some(_) => CloseStart::NotNow("it holds other than what was decided"),
    }
}

/// Burns exactly `burn` tokens (0 after a full sell) and closes the token
/// account, which brings the rent back.
async fn burn_and_close_ata(
    rpc_client: &RpcClient,
    send_rpc_client: &RpcClient,
    keypair: &solana_sdk::signer::keypair::Keypair,
    mint: &Pubkey,
    token_program: &Pubkey,
    burn: u64,
    close_sent: bool,
) -> CloseOutcome {
    let user = keypair.pubkey();
    let ata = amm::ata(&user, mint, token_program);

    // Check current balance
    let balance = match rpc_client
        .get_token_account_balance_with_commitment(&ata, CommitmentConfig::confirmed())
        .await
    {
        Ok(resp) => match resp.value.amount.parse::<u64>() {
            Ok(b) => Some(b),
            Err(_) => return CloseOutcome::Failed { paid: false, sent: false },
        },
        Err(e) if is_account_not_found(&e) => None,
        Err(e) => {
            // Not readable now: not taken for closed, and nothing is burned.
            warn!("ATA {} balance could not be read: {:?}", ata, e);
            return CloseOutcome::Failed { paid: false, sent: false };
        }
    };
    match close_start(balance, burn, close_sent) {
        CloseStart::Proceed => {}
        CloseStart::AlreadyClosed => {
            info!("ATA {} not found after our close: closed", ata);
            return CloseOutcome::Closed(None);
        }
        CloseStart::NotNow(why) => {
            warn!("ATA {} not closed now: {} ({:?} held, {} to burn)", ata, why, balance, burn);
            return CloseOutcome::Failed { paid: false, sent: false };
        }
    }

    // What was decided is burned, if anything, then the account is closed.
    let mut instructions = Vec::new();
    if burn > 0 {
        instructions.push(amm::burn(&user, mint, token_program, burn));
    }
    instructions.push(amm::close_account(&user, mint, token_program));

    let bh = match rpc_client.get_latest_blockhash().await {
        Ok(bh) => bh,
        Err(e) => {
            error!("Blockhash failed for ATA close: {:?}", e);
            return CloseOutcome::Failed { paid: false, sent: false };
        }
    };

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&keypair.pubkey()),
        &[keypair],
        bh,
    );

    match send_rpc_client.send_transaction_with_config(&tx, send_config()).await {
        Ok(sig) => {
            let sig_str = sig.to_string();
            info!("Burn+Close ATA tx sent for {}: sig={}", ata, sig_str);
            match confirm_transaction(rpc_client, &sig, 30).await {
                Ok(true) => {
                    info!("ATA {} closed successfully, rent recovered", ata);
                    CloseOutcome::Closed(Some(sig_str))
                }
                Ok(false) => {
                    // It landed and failed: it closed nothing.
                    warn!("Burn+Close ATA tx failed on-chain: {}", sig_str);
                    CloseOutcome::Failed { paid: true, sent: false }
                }
                // It may land yet: the next try reads the account first, and
                // finds it gone if it did.
                Err(e) => {
                    warn!("Burn+Close ATA tx confirmation timeout: {}", e);
                    CloseOutcome::Failed { paid: false, sent: true }
                }
            }
        }
        Err(e) => {
            error!("Failed to send burn+close ATA tx for {}: {:?}", ata, e);
            CloseOutcome::Failed { paid: false, sent: !refused_by_preflight(&e) }
        }
    }
}

/// What the wallet's token account holds, as far as the RPC can say.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Holding {
    Held(u64),
    /// The RPC cannot find the account: closed, or the RPC is behind.
    Gone,
    /// The RPC could not say.
    Unknown,
}

async fn read_holding(rpc_client: &RpcClient, wallet: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Holding {
    let ata = amm::ata(wallet, mint, token_program);
    match rpc_client
        .get_token_account_balance_with_commitment(&ata, CommitmentConfig::confirmed())
        .await
    {
        Ok(resp) => resp.value.amount.parse::<u64>().map_or(Holding::Unknown, Holding::Held),
        Err(e) if is_account_not_found(&e) => Holding::Gone,
        Err(_) => Holding::Unknown,
    }
}

/// Why a position is forced out whatever its price, if it is: held past
/// the timeout, or the pool's SOL at or below the exit threshold.
fn forced_exit_reason(
    elapsed_secs: u64,
    sell_timeout_secs: u64,
    sol_reserves: u64,
    exit_pool_sol_lamports: u64,
) -> Option<String> {
    let timed_out = sell_timeout_secs > 0 && elapsed_secs >= sell_timeout_secs;
    let low_liquidity = exit_pool_sol_lamports > 0 && sol_reserves <= exit_pool_sol_lamports;
    let sol = sol_reserves as f64 / 1e9;
    match (timed_out, low_liquidity) {
        (true, true) => Some(format!("timeout {}s + low liquidity {:.6} SOL", elapsed_secs, sol)),
        (true, false) => Some(format!("timeout {}s", elapsed_secs)),
        (false, true) => Some(format!("low liquidity {:.6} SOL", sol)),
        (false, false) => None,
    }
}

/// Whether a position is claimed on every check, whatever its price: a
/// sell to settle, the rest of a partial sell, an amount not read yet, or a
/// close to retry. plan_sell decides what it does after the read.
fn claimed_on_every_check(p: &Position) -> bool {
    p.pending_sell.is_some() || p.draining || !p.amount_known || p.closing
}

/// What a claimed position does now.
#[derive(Debug, PartialEq)]
enum Plan {
    /// Sell what is held, for at least this.
    Sell { min_out: u64 },
    /// Burn what is held and close the account: a sell is not worth its fee.
    Burn { reason: String },
    /// Nothing is held any more: close the account.
    CloseSoldOut,
    /// Not now, and nothing failed.
    Hold,
    /// Cannot be decided now: a failure that cost nothing.
    Retry(&'static str),
}

/// What a claimed position does, from what the wallet holds and the pool's
/// reserves. A take-profit is judged here, on what is held now; a position
/// is sold whatever the price only when it drains (a sell of it landed) or
/// is forced out (timeout, liquidity collapse).
fn plan_sell(
    p: &Position,
    holding: Holding,
    forced: Option<String>,
    sol_reserves: u64,
    token_reserves: u64,
    slippage_bps: u64,
    sell_multiplier: f64,
) -> Plan {
    let held = match holding {
        Holding::Held(0) => return Plan::CloseSoldOut,
        Holding::Held(n) => n,
        // Gone counts only after a close of ours: an RPC behind cannot find
        // an account a buy just made.
        Holding::Gone if p.close_sent => return Plan::CloseSoldOut,
        Holding::Gone => return Plan::Retry("its token account is not found, and no close of ours was sent"),
        Holding::Unknown => return Plan::Retry("its token balance could not be read"),
    };
    let expected = match pumpswap::base_out_for_exact_quote_in(
        sol_reserves, token_reserves, held, pumpswap::DEFAULT_FEE_BPS,
    ) {
        Ok(v) => v,
        // A pool emptied of either side has nothing to sell into.
        Err(pumpswap::SwapError::ZeroLiquidity) => 0,
        Err(_) => return Plan::Retry("the AMM math failed"),
    };
    let min_out = pumpswap::with_slippage_min(expected, slippage_bps).unwrap_or(0);
    if !p.draining
        && forced.is_none()
        && !take_profit_reached(expected, slippage_bps, p.buy_price_lamports, sell_multiplier, p.sell_failures)
    {
        return Plan::Hold;
    }
    if !worth_selling(min_out) {
        return Plan::Burn {
            reason: forced
                .unwrap_or_else(|| format!("a sell would bring in {} lamports, no more than its fee", min_out)),
        };
    }
    Plan::Sell { min_out }
}

/// Whether an RPC error says the account does not exist.
fn is_account_not_found(e: &solana_rpc_client_api::client_error::Error) -> bool {
    let msg = format!("{e:?}");
    msg.contains("could not find account") || msg.contains("AccountNotFound")
}

/// A sell (or close) that did not go through: tried again after a wait
/// that grows. `paid` is one that landed and failed, paying its fee. After
/// MAX_SELL_FAILURES of those, or MAX_SELL_ATTEMPTS failures of any kind,
/// in a row, the position is given up, buying pauses until trading is
/// started again (so that a token that cannot be sold is not bought again
/// and again), and in single-shot mode the cycle ends.
async fn record_sell_failure(state: &Arc<RwLock<AppState>>, id: &str, position: &Position, paid: bool) {
    let (gave_up, failed_on_chain, tries) = {
        let mut s = state.write().await;
        let gave_up = s.sell_failed(id, Utc::now(), paid);
        if gave_up {
            s.sell_only = true;
        }
        let (failed_on_chain, tries) =
            s.positions.get(id).map_or((0, 0), |p| (p.sell_failures, p.sell_attempts));
        (gave_up, failed_on_chain, tries)
    };
    if gave_up {
        push_error_log(
            state,
            position.pool,
            position.base_mint,
            0,
            format!(
                "Gave up selling position {} after {} failed tries, {} of them failed on-chain; \
                 its tokens stay in the wallet. Buying is paused until trading is started again \
                 (POST /api/trade/start).",
                id, tries, failed_on_chain
            ),
        )
        .await;
        maybe_auto_stop_after_cycle(state).await;
    }
}

/// Lenient Pool deserialization that tolerates trailing bytes.
/// PumpSwap may add new fields; we only need the known prefix.
pub fn deserialize_pool_lenient(data: &[u8]) -> Result<Pool, std::io::Error> {
    amm::decode_pool(data)
}

/// In single-shot mode (`config.auto_loop == false`), set `running = false`
/// once a buy/sell cycle has fully wound down (no active or selling positions).
/// Has no effect when `auto_loop` is true or when the bot was already stopped.
async fn maybe_auto_stop_after_cycle(state: &Arc<RwLock<AppState>>) {
    let msg = i18n::auto_loop_disabled_stopped();
    let webhook_url = {
        let mut s = state.write().await;
        if !s.running || s.config.auto_loop {
            return;
        }
        if s.active_position_count() != 0 {
            return;
        }
        s.running = false;
        s.push_notification(
            solana_sdk::pubkey::Pubkey::default(),
            solana_sdk::pubkey::Pubkey::default(),
            msg.clone(),
        );
        info!("AUTO_LOOP=false → trading stopped after one buy/sell cycle");
        s.webhook_url.clone()
    };
    notify(webhook_url, msg);
}

/// Restore positions from wallet token holdings on startup.
///
/// Scans both Token and Token-2022 accounts for non-zero balances,
/// finds the corresponding PumpSwap pool via `getProgramAccounts`,
/// and creates Active positions with sell monitors.
pub async fn restore_positions_from_wallet(
    state: Arc<RwLock<AppState>>,
    rpc_client: Arc<RpcClient>,
    send_rpc_client: Arc<RpcClient>,
) {
    let wallet_pubkey = {
        let s = state.read().await;
        match &s.wallet {
            Some(kp) => kp.pubkey(),
            None => {
                warn!("No wallet loaded, skipping position restore");
                return;
            }
        }
    };

    info!("Restoring positions from wallet {} ...", wallet_pubkey);

    let token_programs = [pumpswap::TOKEN_PROGRAM, pumpswap::TOKEN_2022_PROGRAM];

    let mut restored = 0u32;

    for token_program in &token_programs {
        let accounts = match rpc_client
            .get_token_accounts_by_owner(
                &wallet_pubkey,
                solana_rpc_client_api::request::TokenAccountsFilter::ProgramId(*token_program),
            )
            .await
        {
            Ok(a) => a,
            Err(e) => {
                warn!("Failed to fetch token accounts for {:?}: {:?}", token_program, e);
                continue;
            }
        };

        for keyed in &accounts {
            // Parse the account data to get mint + amount
            let data = match &keyed.account.data {
                solana_account_decoder::UiAccountData::Json(parsed) => parsed,
                _ => continue,
            };
            let info = match data.parsed.get("info") {
                Some(v) => v,
                None => continue,
            };
            let mint_str = match info.get("mint").and_then(|v| v.as_str()) {
                Some(m) => m,
                None => continue,
            };
            // WSOL is the bot's own change, not a position.
            if mint_str == pumpswap::WSOL_MINT.to_string() {
                continue;
            }
            let amount_str = match info
                .get("tokenAmount")
                .and_then(|v| v.get("amount"))
                .and_then(|v| v.as_str())
            {
                Some(a) => a,
                None => continue,
            };
            let amount: u64 = match amount_str.parse() {
                Ok(a) if a > 0 => a,
                _ => continue,
            };

            let token_mint = match Pubkey::try_from(mint_str) {
                Ok(p) => p,
                Err(_) => continue,
            };

            info!("Found token {} amount={} — searching for PumpSwap pool...", mint_str, amount);

            // Find the token's PumpSwap pools, WSOL on either side: base_mint
            // is at offset 43 (discriminator 8, bump 1, index 2, creator 32),
            // quote_mint at 75.
            let wsol_mint = pumpswap::WSOL_MINT;
            let pump_amm = pumpswap::PUMP_AMM_PROGRAM_ID;

            use solana_rpc_client_api::filter::{Memcmp, RpcFilterType};
            use solana_rpc_client_api::config::RpcProgramAccountsConfig;
            use solana_account_decoder::UiAccountEncoding;

            let mut pool_accounts = Vec::new();
            for (base, quote) in [(wsol_mint, token_mint), (token_mint, wsol_mint)] {
                let filters = vec![
                    RpcFilterType::Memcmp(Memcmp::new_raw_bytes(0, amm::POOL_DISCRIMINATOR.to_vec())),
                    RpcFilterType::Memcmp(Memcmp::new_raw_bytes(43, base.to_bytes().to_vec())),
                    RpcFilterType::Memcmp(Memcmp::new_raw_bytes(75, quote.to_bytes().to_vec())),
                ];
                let config = RpcProgramAccountsConfig {
                    filters: Some(filters),
                    account_config: solana_rpc_client_api::config::RpcAccountInfoConfig {
                        encoding: Some(UiAccountEncoding::Base64),
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                // The accounts as bytes, which is how the pools are read; the
                // replacement hands them over decoded for display.
                #[allow(deprecated)]
                let found = rpc_client.get_program_accounts_with_config(&pump_amm, config).await;
                match found {
                    Ok(found) => pool_accounts.extend(found),
                    Err(e) => warn!("getProgramAccounts failed for mint {}: {:?}", mint_str, e),
                }
            }

            if pool_accounts.is_empty() {
                warn!("No WSOL/{} PumpSwap pool found: not taken up", mint_str);
                continue;
            } else {
                // The deepest WSOL/token pool: forced exits and the burn
                // decision read its reserves.
                let mut deepest: Option<(Pubkey, Vec<u8>, u64)> = None;
                for (address, account) in &pool_accounts {
                    let Ok(pool) = deserialize_pool_lenient(&account.data) else { continue };
                    let Some(side) = Side::of(&pool) else { continue };
                    if amm::not_tradable(&pool, Some(&account.data)).is_some() {
                        continue;
                    }
                    let Ok(sol) = fetch_token_balance_with_retry(&rpc_client, &side.vaults(&pool).0).await else {
                        continue;
                    };
                    if deepest.as_ref().is_none_or(|(_, _, best)| sol > *best) {
                        deepest = Some((*address, account.data.clone(), sol));
                    }
                }
                let Some((pool_address, pool_data, _)) = deepest else {
                    warn!("No readable WSOL/{} pool: not taken up", mint_str);
                    continue;
                };
                if let Err(e) = restore_single_position(
                    &state, &rpc_client, &send_rpc_client,
                    pool_address, &pool_data, token_mint, amount, *token_program,
                ).await {
                    warn!("Failed to restore position for mint {} (quote): {:?}", mint_str, e);
                } else {
                    restored += 1;
                }
            }
        }
    }

    info!("Position restore complete: {} positions restored", restored);
}

#[allow(clippy::too_many_arguments)]
async fn restore_single_position(
    state: &Arc<RwLock<AppState>>,
    rpc_client: &Arc<RpcClient>,
    send_rpc_client: &Arc<RpcClient>,
    pool_address: Pubkey,
    pool_data_raw: &[u8],
    token_mint: Pubkey,
    token_amount: u64,
    quote_token_program: Pubkey,
) -> Result<(), String> {
    let pool_data = deserialize_pool_lenient(pool_data_raw)
        .map_err(|e| format!("Pool deserialize: {:?}", e))?;

    // A token that its holders can be stopped from selling would hold a
    // slot with sells that never go through: it is not taken up.
    let mint_account = rpc_client
        .get_account(&token_mint)
        .await
        .map_err(|e| format!("Fetch mint: {:?}", e))?;
    if let Some(why) = mint_blocks_selling(&mint_account.data, &mint_account.owner) {
        return Err(format!("not taken up: {}", why));
    }

    let Some(side) = Side::of(&pool_data) else {
        return Err(format!("pool {} is not a WSOL/token pool", pool_address));
    };
    let (sol_vault, token_vault) = side.vaults(&pool_data);
    let token_reserves = fetch_token_balance_with_retry(rpc_client, &token_vault)
        .await
        .map_err(|e| format!("Fetch token reserves: {:?}", e))?;
    let sol_reserves = fetch_token_balance_with_retry(rpc_client, &sol_vault)
        .await
        .map_err(|e| format!("Fetch SOL reserves: {:?}", e))?;

    // The original buy price is not known: what the tokens would sell for
    // now is the baseline. The position then takes profit from here, or is
    // sold at the timeout, but only once trading is started: restoring
    // alone sells nothing.
    let current_value = side
        .sol_for_tokens(sol_reserves, token_reserves, token_amount)
        .unwrap_or(0)
        .max(1);

    // Its value now as the baseline, in place of the buy price.
    let position = Position {
        restored: true,
        ..Position::opened(pool_address, token_mint, current_value, token_amount, quote_token_program, side)
    };

    info!(
        "Restored position: pool={} mint={} amount={} est_value={} lamports",
        pool_address, token_mint, token_amount, current_value
    );

    let sell_multiplier = {
        let mut s = state.write().await;
        s.positions.insert(position.id.clone(), position);
        s.push_notification(
            pool_address,
            token_mint,
            i18n::position_restored(token_amount, current_value),
        );
        s.config.sell_multiplier
    };

    spawn_sell_monitor(
        state.clone(),
        rpc_client.clone(),
        send_rpc_client.clone(),
        pool_address,
        sell_multiplier,
    );

    Ok(())
}

#[cfg(test)]
mod auto_loop_tests {
    use super::*;
    use crate::state::{AppState, Position, PositionStatus};
    use chrono::Utc;
    use solana_sdk::pubkey::Pubkey;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn make_state(auto_loop: bool, running: bool) -> Arc<RwLock<AppState>> {
        let mut s = AppState::new(None);
        s.config.auto_loop = auto_loop;
        s.running = running;
        Arc::new(RwLock::new(s))
    }

    fn insert_active_position(s: &mut AppState) {
        let id = "test-pos".to_string();
        s.positions.insert(
            id.clone(),
            Position {
                id,
                ..Position::opened(Pubkey::new_unique(), Pubkey::new_unique(), 100_000, 1, Pubkey::default(), Side::SolBase)
            },
        );
    }

    #[test]
    fn a_take_profit_ends_the_trade_up_for_every_setting_allowed() {
        // A whole trade, with the library's AMM math: the buy (exact in);
        // the sells that landed and failed before, each a fee; the
        // take-profit sell, exact out, which brings in its minimum out and
        // spends only the tokens that takes; the tail it leaves, sold only
        // when that sell is worth its fee; and the close.
        let buy = 100_000u64;
        let fee = pumpswap::DEFAULT_FEE_BPS;
        for multiplier in [1.0, 1.1, 2.0] {
            for slippage_bps in [0u64, 500, 2_000, 5_000] {
                for failed in 0..MAX_SELL_FAILURES {
                    let (mut sol, mut tokens) = (1_000_000_000u64, 1_000_000_000_000u64);
                    let held = pumpswap::quote_out_for_exact_base_in(sol, tokens, buy, fee).expect("buy");
                    sol += buy;
                    tokens -= held;
                    // Others buy until the take-profit check passes.
                    let value = loop {
                        let value = pumpswap::base_out_for_exact_quote_in(sol, tokens, held, fee).expect("value");
                        if take_profit_reached(value, slippage_bps, buy, multiplier, failed) {
                            break value;
                        }
                        sol += sol / 100;
                        tokens -= tokens / 101;
                    };
                    let out = pumpswap::with_slippage_min(value, slippage_bps).expect("min out");
                    let spent = pumpswap::quote_in_for_exact_base_out(sol, tokens, out, fee).expect("spent");
                    assert!(spent <= held, "the sell spends no more than is held");
                    let (sol, tokens, tail) = (sol - out, tokens + spent, held - spent);
                    let mut proceeds = out as i64;
                    let mut txs = 3 + i64::from(failed);
                    if tail > 0 {
                        let tail_value = pumpswap::base_out_for_exact_quote_in(sol, tokens, tail, fee).unwrap_or(0);
                        let tail_out = pumpswap::with_slippage_min(tail_value, slippage_bps).unwrap_or(0);
                        if worth_selling(tail_out) {
                            proceeds += tail_out as i64;
                            txs += 1;
                        }
                    }
                    let net = proceeds - buy as i64 - txs * TX_FEE_LAMPORTS as i64;
                    let floor = ((multiplier - 1.0) * buy as f64) as i64;
                    assert!(
                        net >= floor,
                        "x{multiplier} slippage {slippage_bps} failed {failed}: net {net} < {floor}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn a_close_that_does_not_go_through_keeps_the_position_watched() {
        let state = make_state(true, true);
        insert_active_position(&mut *state.write().await);
        let pool = state.read().await.positions["test-pos"].pool;
        let position = state.write().await.claim_for_sell("test-pos", Utc::now()).expect("claimed");
        // No RPC answers: the balance cannot be read, so nothing is burned
        // and the account is not taken for closed.
        let rpc = RpcClient::new("http://127.0.0.1:9".to_string());
        let keypair = solana_sdk::signer::keypair::Keypair::new();
        close_position(&state, &rpc, &rpc, &keypair, "test-pos", &position, Close::Sold(None)).await;
        let s = state.read().await;
        let p = &s.positions["test-pos"];
        assert_eq!(p.status, PositionStatus::Active);
        assert!(p.closing, "the next check looks at it again");
        assert!(!p.draining, "but no sell of it landed: it is not drained");
        assert!(p.next_sell_at.is_some(), "after a wait");
        assert!(s.pool_has_open_position(&pool), "and its monitor keeps running");
        // Tokens turn up worth less than the target: held, not sold at
        // market.
        let (sol, tokens) = (1_000_000_000_000u64, 1_000_000_000u64);
        assert_eq!(plan_sell(p, Holding::Held(50), None, sol, tokens, 500, 1.1), Plan::Hold);
    }

    fn plan_position() -> Position {
        let mut s = AppState::new(None);
        insert_active_position(&mut s);
        s.positions["test-pos"].clone()
    }

    #[test]
    fn a_position_is_sold_below_its_target_only_when_draining_or_forced() {
        // At these reserves 1_000_000 tokens are worth 1_000_000_000
        // lamports, far above the target, and 4 tokens about 3_800 after
        // fees: below the target, and below a sell's fee.
        let (sol, tokens, slip, mult) = (1_000_000_000_000u64, 1_000_000_000u64, 500, 1.1);
        let mut p = plan_position();
        p.base_amount = 1_000_000;
        assert!(matches!(plan_sell(&p, Holding::Held(1_000_000), None, sol, tokens, slip, mult), Plan::Sell { .. }));
        // A read lower than recorded, with no sell landed: judged on what is
        // held, and held.
        assert_eq!(plan_sell(&p, Holding::Held(4), None, sol, tokens, slip, mult), Plan::Hold);
        // Draining or forced: sold, or burned when not worth a fee.
        p.draining = true;
        assert!(matches!(plan_sell(&p, Holding::Held(4), None, sol, tokens, slip, mult), Plan::Burn { .. }));
        assert!(matches!(plan_sell(&p, Holding::Held(1_000_000), None, sol, tokens, slip, mult), Plan::Sell { .. }));
        p.draining = false;
        let forced = Some("timeout 300s".to_string());
        assert_eq!(
            plan_sell(&p, Holding::Held(4), forced.clone(), sol, tokens, slip, mult),
            Plan::Burn { reason: "timeout 300s".to_string() }
        );
        // An emptied pool: worth nothing, held unless draining or forced.
        assert_eq!(plan_sell(&p, Holding::Held(1_000_000), None, 0, tokens, slip, mult), Plan::Hold);
        assert!(matches!(plan_sell(&p, Holding::Held(1_000_000), forced, 0, tokens, slip, mult), Plan::Burn { .. }));
    }

    #[test]
    fn a_forced_exit_is_judged_on_the_reserves_given() {
        let (timeout, exit) = (300, 1_000_000);
        assert_eq!(forced_exit_reason(10, timeout, 5_000_000, exit), None);
        assert!(forced_exit_reason(300, timeout, 5_000_000, exit).expect("timeout").starts_with("timeout"));
        assert!(forced_exit_reason(10, timeout, 1_000_000, exit).expect("low").starts_with("low liquidity"));
        // A pool back above the threshold on a fresh read is not forced out.
        assert_eq!(forced_exit_reason(10, timeout, 1_000_001, exit), None);
        // Zero turns either rule off.
        assert_eq!(forced_exit_reason(10_000, 0, 0, 0), None);
    }

    #[test]
    fn a_position_with_a_close_to_retry_is_claimed_on_every_check() {
        let mut p = plan_position();
        assert!(!claimed_on_every_check(&p));
        p.closing = true;
        assert!(claimed_on_every_check(&p));
        p.closing = false;
        p.amount_known = false;
        assert!(claimed_on_every_check(&p));
    }

    #[test]
    fn a_position_is_closed_on_what_the_chain_says_and_never_on_a_guess() {
        let (sol, tokens, slip, mult) = (1_000_000_000_000u64, 1_000_000_000u64, 500, 1.1);
        let mut p = plan_position();
        assert_eq!(plan_sell(&p, Holding::Held(0), None, sol, tokens, slip, mult), Plan::CloseSoldOut);
        assert!(matches!(plan_sell(&p, Holding::Unknown, None, sol, tokens, slip, mult), Plan::Retry(_)));
        // Not found: a lagging RPC, unless a close of ours went out.
        assert!(matches!(plan_sell(&p, Holding::Gone, None, sol, tokens, slip, mult), Plan::Retry(_)));
        p.close_sent = true;
        assert_eq!(plan_sell(&p, Holding::Gone, None, sol, tokens, slip, mult), Plan::CloseSoldOut);
    }

    #[test]
    fn a_close_burns_only_what_was_decided_and_trusts_gone_only_after_its_own() {
        assert_eq!(close_start(Some(0), 0, false), CloseStart::Proceed);
        assert_eq!(close_start(Some(700), 700, false), CloseStart::Proceed);
        // A sell decided on an empty account, or a burn decided on another
        // amount, burns nothing: decided again.
        assert!(matches!(close_start(Some(700), 0, false), CloseStart::NotNow(_)));
        assert!(matches!(close_start(Some(700), 300, true), CloseStart::NotNow(_)));
        // Not found: a lagging RPC, unless a close of ours went out.
        assert!(matches!(close_start(None, 0, false), CloseStart::NotNow(_)));
        assert_eq!(close_start(None, 0, true), CloseStart::AlreadyClosed);
    }

    #[test]
    fn a_sell_never_seen_is_waited_for_until_its_blockhash_is_past() {
        assert!(matches!(pending_after_unseen(100, 150), Pending::InFlight));
        assert!(matches!(pending_after_unseen(150, 150), Pending::InFlight));
        assert!(matches!(pending_after_unseen(151, 150), Pending::Expired));
    }

    #[tokio::test]
    async fn giving_up_on_a_position_pauses_buying_and_ends_the_cycle() {
        let state = make_state(false, true);
        insert_active_position(&mut *state.write().await);
        let position = state.read().await.positions["test-pos"].clone();
        for _ in 0..MAX_SELL_FAILURES {
            record_sell_failure(&state, "test-pos", &position, true).await;
        }
        {
            let s = state.read().await;
            assert_eq!(s.positions["test-pos"].status, PositionStatus::Failed);
            assert!(s.sell_only, "a give-up must pause buying");
            assert!(!s.running, "AUTO_LOOP=false: the cycle ends");
        }
        // Running again without POST /api/trade/start, which is what lifts
        // the pause: still nothing is bought.
        state.write().await.running = true;
        let rpc = Arc::new(RpcClient::new("http://127.0.0.1:9".to_string()));
        handle_new_pool(hand_made_pool(), sighting(), state.clone(), rpc.clone(), rpc).await;
        assert!(state.read().await.seen_pools.is_empty());
    }

    #[test]
    fn a_sell_that_brings_in_less_than_its_fee_is_not_sent() {
        assert!(!worth_selling(0));
        assert!(!worth_selling(TX_FEE_LAMPORTS));
        assert!(worth_selling(TX_FEE_LAMPORTS + 1));
    }

    /// A mint's account data: 82 bytes, initialized, with a freeze authority
    /// or not, and Token-2022 extensions of the given types.
    fn mint_data(freeze: bool, extensions: &[u16]) -> Vec<u8> {
        let mut d = vec![0u8; 82];
        d[45] = 1;
        if freeze {
            d[46] = 1;
        }
        if !extensions.is_empty() {
            d.resize(165, 0);
            d.push(1); // AccountType::Mint
            for ty in extensions {
                d.extend_from_slice(&ty.to_le_bytes());
                d.extend_from_slice(&4u16.to_le_bytes());
                d.extend_from_slice(&[0; 4]);
            }
        }
        d
    }

    #[test]
    fn a_token_whose_holders_can_be_stopped_from_selling_is_not_bought() {
        let (spl, t22) = (pumpswap::TOKEN_PROGRAM, pumpswap::TOKEN_2022_PROGRAM);
        assert_eq!(mint_blocks_selling(&mint_data(false, &[]), &spl), None);
        assert_eq!(mint_blocks_selling(&mint_data(false, &[]), &t22), None);
        assert_eq!(mint_blocks_selling(&mint_data(false, &[18, 19]), &t22), None);
        assert!(mint_blocks_selling(&mint_data(true, &[]), &spl).is_some());
        assert!(mint_blocks_selling(&mint_data(true, &[18, 19]), &t22).is_some());
        // TransferFeeConfig, DefaultAccountState, NonTransferable,
        // PermanentDelegate, TransferHook, Pausable.
        for ty in [1u16, 6, 9, 12, 14, 26] {
            assert!(mint_blocks_selling(&mint_data(false, &[18, ty]), &t22).is_some(), "{ty}");
        }
        // Extensions on a legacy mint, a length running past the end, not a
        // token program, too short.
        assert!(mint_blocks_selling(&mint_data(false, &[18]), &spl).is_some());
        let mut cut = mint_data(false, &[18]);
        cut.truncate(cut.len() - 2);
        assert!(mint_blocks_selling(&cut, &t22).is_some());
        assert!(mint_blocks_selling(&mint_data(false, &[]), &Pubkey::new_unique()).is_some());
        assert!(mint_blocks_selling(&[0u8; 40], &spl).is_some());
    }

    #[test]
    fn every_transaction_but_a_graduation_buy_is_simulated_first() {
        let cfg = send_config();
        assert!(!cfg.skip_preflight);
        assert_eq!(cfg.preflight_commitment, Some(CommitmentLevel::Processed));
        assert!(buy_now_config().skip_preflight);
    }

    /// A WSOL/token pool made by hand, as its create_pool reads.
    fn hand_made_pool() -> NewPool {
        NewPool {
            pool: Pubkey::new_unique(),
            data: Pool {
                pool_bump: 0,
                index: 0,
                creator: Pubkey::new_unique(),
                base_mint: pumpswap::WSOL_MINT,
                quote_mint: Pubkey::new_unique(),
                lp_mint: Pubkey::new_unique(),
                pool_base_token_account: Pubkey::new_unique(),
                pool_quote_token_account: Pubkey::new_unique(),
                lp_supply: 0,
                is_mayhem_mode: false,
                coin_creator: Pubkey::default(),
            },
            base_token_program: pumpswap::TOKEN_PROGRAM,
            quote_token_program: pumpswap::TOKEN_PROGRAM,
            base_reserves: 10_000_000_000,
            quote_reserves: 1_000_000_000_000,
            graduated: false,
            flagged: false,
        }
    }

    fn sighting() -> Sighting {
        Sighting { slot: 1, seen: std::time::Instant::now(), via: crate::timing::Via::Geyser }
    }

    #[test]
    fn a_priority_fee_sets_the_limit_and_price_and_is_counted_in_the_cost() {
        assert!(compute_budget(0, 200_000).is_empty());
        let ixs = compute_budget(50_000, 200_000);
        assert_eq!(ixs[0].data, [vec![2], 200_000u32.to_le_bytes().to_vec()].concat());
        assert_eq!(ixs[1].data, [vec![3], 50_000u64.to_le_bytes().to_vec()].concat());
        assert!(ixs.iter().all(|ix| ix.program_id == COMPUTE_BUDGET_PROGRAM && ix.accounts.is_empty()));

        let mut config = crate::state::TradeConfig::default();
        assert_eq!(config.priority_fee_lamports(), 0);
        config.priority_fee_micro_lamports = 50_000;
        // 50,000 micro-lamports on each of 200,000 units: 10,000 lamports.
        assert_eq!(config.priority_fee_lamports(), 10_000);
        config.compute_unit_limit = 1;
        assert_eq!(config.priority_fee_lamports(), 1, "rounded up");
        config.priority_fee_micro_lamports = u64::MAX;
        config.compute_unit_limit = 1_400_000;
        assert!(config.validate().is_err(), "a fee above the buy is refused");
        config.priority_fee_micro_lamports = 0;
        config.compute_unit_limit = 0;
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn a_pool_made_by_hand_is_not_bought_when_graduated_only() {
        let state = make_state(true, true);
        state.write().await.config.graduated_only = true;
        let rpc = Arc::new(RpcClient::new("http://127.0.0.1:9".to_string()));
        handle_new_pool(hand_made_pool(), sighting(), state.clone(), rpc.clone(), rpc).await;
        assert!(state.read().await.seen_pools.is_empty());
    }

    #[tokio::test]
    async fn nothing_is_bought_in_sell_only_mode() {
        let state = make_state(true, true);
        state.write().await.sell_only = true;
        // No RPC is reached: the pool is turned away before anything is fetched.
        let rpc = Arc::new(RpcClient::new("http://127.0.0.1:9".to_string()));
        handle_new_pool(hand_made_pool(), sighting(), state.clone(), rpc.clone(), rpc).await;
        assert!(state.read().await.seen_pools.is_empty(), "sell_only must not take a slot");
    }

    #[tokio::test]
    async fn stops_when_auto_loop_off_and_no_positions() {
        let state = make_state(false, true);
        maybe_auto_stop_after_cycle(&state).await;
        assert!(!state.read().await.running, "should auto-stop");
    }

    #[tokio::test]
    async fn keeps_running_when_auto_loop_on() {
        let state = make_state(true, true);
        maybe_auto_stop_after_cycle(&state).await;
        assert!(state.read().await.running, "auto_loop=true must keep running");
    }

    #[tokio::test]
    async fn keeps_running_when_active_position_remains() {
        let state = make_state(false, true);
        {
            let mut s = state.write().await;
            insert_active_position(&mut s);
        }
        maybe_auto_stop_after_cycle(&state).await;
        assert!(
            state.read().await.running,
            "must wait for all positions to close"
        );
    }

    #[tokio::test]
    async fn noop_when_already_stopped() {
        let state = make_state(false, false);
        maybe_auto_stop_after_cycle(&state).await;
        assert!(!state.read().await.running);
    }
}
