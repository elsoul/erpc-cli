use chrono::{DateTime, Utc};
use log::warn;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::Keypair;
use solana_signature::Signature;
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::Arc;

pub const PUMPSWAP_AMM: &str = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA";
pub const TRADE_LOG_CAP: usize = 10_000;
/// Pools remembered as already considered; past this the memory starts over.
pub const SEEN_POOLS_CAP: usize = 50_000;
/// Failed sells in a row before a position is given up.
pub const MAX_SELL_FAILURES: u32 = 5;
/// Failed sells in a row of any kind before a position is given up: with
/// the waits between them, about a quarter of an hour of trying.
pub const MAX_SELL_ATTEMPTS: u32 = 20;
/// The longest wait before trying a failed sell again.
pub const MAX_SELL_RETRY_SECS: i64 = 60;
/// The wait before looking again at a sell that can still land.
pub const PENDING_SELL_RECHECK_SECS: i64 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeConfig {
    pub buy_amount_lamports: u64,
    pub sell_multiplier: f64,
    pub slippage_bps: u64,
    pub max_positions: usize,
    /// Minimum pool SOL liquidity (in lamports) to trigger a buy.
    /// Pools with less WSOL reserves are skipped.
    pub min_pool_sol_lamports: u64,
    /// Force exit after this many seconds from buy, even if profit target is not hit.
    pub sell_timeout_secs: u64,
    /// If pool WSOL reserves fall to or below this threshold, retreat immediately.
    pub exit_pool_sol_lamports: u64,
    /// When true, keep buying new pools after each buy/sell cycle.
    /// When false (default), auto-stop after one full cycle completes
    /// (buy → sell → ATA close, with no remaining active positions).
    #[serde(default)]
    pub auto_loop: bool,
    /// No pool is bought for this many seconds after the bot starts, while
    /// it learns which creators open pool after pool.
    #[serde(default = "default_warmup_secs")]
    pub warmup_secs: u64,
    /// A creator opening more than `creator_max_pools` pools within this
    /// many seconds is banned.
    #[serde(default = "default_creator_window_secs")]
    pub creator_window_secs: u64,
    /// See `creator_window_secs`.
    #[serde(default = "default_creator_max_pools")]
    pub creator_max_pools: usize,
    /// Creators banned from the start, by address.
    #[serde(default)]
    pub banned_creators: Vec<String>,
}

fn default_warmup_secs() -> u64 {
    300
}

fn default_creator_window_secs() -> u64 {
    600
}

fn default_creator_max_pools() -> usize {
    2
}

impl Default for TradeConfig {
    fn default() -> Self {
        Self {
            buy_amount_lamports: 100_000, // 0.0001 SOL
            sell_multiplier: 1.1,
            slippage_bps: 500, // 5% — reasonable for small positions
            max_positions: 1,
            min_pool_sol_lamports: 1_000_000_000, // 1 SOL
            sell_timeout_secs: 300,         // 5 min timeout before retreat
            exit_pool_sol_lamports: 1_000_000, // 0.001 SOL => treat as liquidity collapse
            auto_loop: false,
            warmup_secs: default_warmup_secs(),
            creator_window_secs: default_creator_window_secs(),
            creator_max_pools: default_creator_max_pools(),
            banned_creators: Vec::new(),
        }
    }
}

impl TradeConfig {
    /// Why this configuration would trade badly, if it would.
    pub fn validate(&self) -> Result<(), String> {
        if self.buy_amount_lamports == 0 {
            return Err("buy_amount_lamports must be above 0".to_string());
        }
        if !self.sell_multiplier.is_finite() || self.sell_multiplier < 1.0 {
            return Err("sell_multiplier must be 1.0 or more".to_string());
        }
        if self.slippage_bps > 5_000 {
            return Err("slippage_bps must be 5000 (50%) or less".to_string());
        }
        if self.max_positions == 0 {
            return Err("max_positions must be 1 or more".to_string());
        }
        if self.creator_max_pools == 0 {
            return Err("creator_max_pools must be 1 or more".to_string());
        }
        if let Some(bad) = self
            .banned_creators
            .iter()
            .find(|c| c.parse::<Pubkey>().is_err())
        {
            return Err(format!("banned_creators: {bad} is not an address"));
        }
        if self.min_pool_sol_lamports <= self.exit_pool_sol_lamports {
            return Err(
                "min_pool_sol_lamports must be above exit_pool_sol_lamports, or a pool is sold as soon as it is bought"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PositionStatus {
    Active,
    Selling,
    Sold,
    /// ATA burned + closed, rent recovered. Terminal state.
    Closed,
    Failed,
}

/// A sell that was signed and may have gone out, not settled yet.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingSell {
    pub signature: Signature,
    /// After this block height it can no longer land.
    pub last_valid_block_height: u64,
    /// What it brings in when it lands: the sell is exact-out.
    pub min_out: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Position {
    pub id: String,
    #[serde(serialize_with = "pubkey_str")]
    pub pool: Pubkey,
    #[serde(serialize_with = "pubkey_str")]
    pub base_mint: Pubkey,
    pub buy_price_lamports: u64,
    pub base_amount: u64,
    pub bought_at: DateTime<Utc>,
    pub status: PositionStatus,
    /// Cumulative SOL received across all partial sells (lamports).
    pub total_sell_lamports: u64,
    /// Token program that owns the graduated (quote) mint.
    /// TOKEN_PROGRAM for legacy SPL tokens, TOKEN_2022 for Token Extensions.
    #[serde(serialize_with = "pubkey_str")]
    pub quote_token_program: Pubkey,
    /// Sells in a row that landed and failed, each paying its fee; after
    /// MAX_SELL_FAILURES the position is given up (Failed) instead of paying
    /// for failing sells for ever.
    pub sell_failures: u32,
    /// Failed sells in a row of any kind, those that cost nothing included
    /// (an RPC error, a refused simulation); they set the wait, and after
    /// MAX_SELL_ATTEMPTS the position is given up too.
    pub sell_attempts: u32,
    /// A sell of it landed: the rest is sold, or burned, whatever the price.
    /// Set only when a sell's proceeds are recorded.
    pub draining: bool,
    /// A close of its token account was decided and did not go through: it
    /// is looked at on every check, with the same rules for selling as any
    /// other position, until it is closed or the close no longer applies.
    pub closing: bool,
    /// A sell that may have gone out: settled before another is signed.
    #[serde(skip)]
    pub pending_sell: Option<PendingSell>,
    /// A close of its token account was sent and may have landed: only then
    /// is an account the RPC cannot find taken for closed.
    pub close_sent: bool,
    /// `base_amount` was read from the chain. A buy whose amount could not
    /// be read is recorded from its estimate, and read before any decision.
    pub amount_known: bool,
    /// After a failed sell, none is tried again before this.
    pub next_sell_at: Option<DateTime<Utc>>,
    /// Found in the wallet at start rather than bought by this run: it is
    /// sold only while trading runs.
    pub restored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TradeAction {
    Buy,
    Sell,
    Error,
    Notification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeLog {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: TradeAction,
    #[serde(serialize_with = "pubkey_str", deserialize_with = "pubkey_from_str")]
    pub pool: Pubkey,
    #[serde(serialize_with = "pubkey_str", deserialize_with = "pubkey_from_str")]
    pub base_mint: Pubkey,
    pub amount_sol: f64,
    pub amount_tokens: u64,
    pub tx_signature: Option<String>,
    pub error: Option<String>,
    /// Human-readable message for notification events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub struct AppState {
    pub config: TradeConfig,
    pub running: bool,
    /// Whether gRPC streaming is active.
    pub grpc_streaming: bool,
    /// The trading key, shared and never copied (see `wallet`).
    pub wallet: Option<Arc<Keypair>>,
    /// Positions keyed by UUID string for safe concurrent access.
    pub positions: HashMap<String, Position>,
    pub trade_logs: VecDeque<TradeLog>,
    pub watch_address: Pubkey,
    /// Discord webhook URL for notifications (from env).
    pub webhook_url: Option<String>,
    /// Optional Redis client for persistent trade log storage.
    pub redis_client: Option<redis::Client>,
    /// Started with `?mode=sell_only`, or a position was given up: positions
    /// are sold, nothing is bought, until trading is started again.
    pub sell_only: bool,
    /// Pools a buy is under way for, with their token; they count against
    /// max_positions, and a token is bought through one pool at a time.
    pub pending_buys: HashMap<Pubkey, Pubkey>,
    /// Pools already considered, so that no pool is bought twice.
    pub seen_pools: HashSet<Pubkey>,
    /// Creators to stay away from (see `creators`).
    pub creators: crate::creators::CreatorWatch,
    /// When the bot started watching: no buys during `warmup_secs`.
    pub started: std::time::Instant,
}

impl AppState {
    pub fn new(webhook_url: Option<String>) -> Self {
        Self {
            config: TradeConfig::default(),
            running: false,
            grpc_streaming: true,
            wallet: None,
            positions: HashMap::new(),
            trade_logs: VecDeque::new(),
            watch_address: Pubkey::from_str(PUMPSWAP_AMM).expect("valid pubkey"),
            webhook_url,
            redis_client: None,
            sell_only: false,
            pending_buys: HashMap::new(),
            seen_pools: HashSet::new(),
            creators: crate::creators::CreatorWatch::default(),
            started: std::time::Instant::now(),
        }
    }

    /// Takes a slot for buying `pool` of `mint`, or says why there is none:
    /// the pool was considered before, this token is being bought through
    /// another pool or may still be held from a position not closed (one
    /// token account serves them all), or max_positions are open or being
    /// bought.
    pub fn reserve_buy(&mut self, pool: Pubkey, mint: Pubkey) -> Result<(), &'static str> {
        if self.seen_pools.contains(&pool) {
            return Err("considered already");
        }
        if self
            .positions
            .values()
            .any(|p| p.base_mint == mint && p.status != PositionStatus::Closed)
        {
            return Err("a position in this token is not closed");
        }
        if self.pending_buys.values().any(|m| *m == mint) {
            return Err("this token is being bought through another pool");
        }
        if self.active_position_count() + self.pending_buys.len() >= self.config.max_positions {
            return Err("max positions open or being bought");
        }
        if self.seen_pools.len() >= SEEN_POOLS_CAP {
            self.seen_pools.clear();
        }
        self.seen_pools.insert(pool);
        self.pending_buys.insert(pool, mint);
        Ok(())
    }

    /// Gives back the slot `reserve_buy` took.
    pub fn release_buy(&mut self, pool: &Pubkey) {
        self.pending_buys.remove(pool);
    }

    /// Whether the position may be sold at `now`: Active, past any wait
    /// after a failure, and, when restored, only while trading runs.
    pub fn may_sell(&self, p: &Position, now: DateTime<Utc>) -> bool {
        p.status == PositionStatus::Active
            && p.next_sell_at.is_none_or(|at| now >= at)
            && (!p.restored || self.running)
    }

    /// Moves the position from Active to Selling and returns it, in one
    /// step, so that only one task sells it; none when it may not be sold.
    pub fn claim_for_sell(&mut self, id: &str, now: DateTime<Utc>) -> Option<Position> {
        let may = self.positions.get(id).is_some_and(|p| self.may_sell(p, now));
        if !may {
            return None;
        }
        let p = self.positions.get_mut(id)?;
        p.status = PositionStatus::Selling;
        Some(p.clone())
    }

    /// Whether a position on `pool` is still open, one being sold included.
    /// Its monitor runs while one is, so that a retry, a forced exit or the
    /// rest of a partial sell never waits on someone else's swap.
    pub fn pool_has_open_position(&self, pool: &Pubkey) -> bool {
        self.positions.values().any(|p| {
            p.pool == *pool && matches!(p.status, PositionStatus::Active | PositionStatus::Selling)
        })
    }

    /// Records a failed sell: Active again after a wait that doubles each
    /// time, up to MAX_SELL_RETRY_SECS. `paid` is a sell that landed and
    /// failed. The position is given up (Failed) after MAX_SELL_FAILURES of
    /// those in a row, or MAX_SELL_ATTEMPTS failures of any kind, so that a
    /// sell that can never go through does not hold its slot for ever.
    /// True when it was given up.
    pub fn sell_failed(&mut self, id: &str, now: DateTime<Utc>, paid: bool) -> bool {
        let Some(p) = self.positions.get_mut(id) else {
            return false;
        };
        p.sell_attempts += 1;
        if paid {
            p.sell_failures += 1;
        }
        if p.sell_failures >= MAX_SELL_FAILURES || p.sell_attempts >= MAX_SELL_ATTEMPTS {
            p.status = PositionStatus::Failed;
            return true;
        }
        let wait = (1i64 << p.sell_attempts.min(6)).min(MAX_SELL_RETRY_SECS);
        p.next_sell_at = Some(now + chrono::Duration::seconds(wait));
        p.status = PositionStatus::Active;
        false
    }

    /// A sell that can still land: looked at again shortly, without
    /// counting as a failure and without signing another.
    pub fn wait_for_pending(&mut self, id: &str, now: DateTime<Utc>) {
        if let Some(p) = self.positions.get_mut(id) {
            p.next_sell_at = Some(now + chrono::Duration::seconds(PENDING_SELL_RECHECK_SECS));
            p.status = PositionStatus::Active;
        }
    }

    /// What the wallet holds of the position's token, read from the chain.
    /// It changes the amount only: a position drains after a sell of it
    /// landed, never because a read came back lower.
    pub fn record_holding(&mut self, id: &str, held: u64) {
        if let Some(p) = self.positions.get_mut(id) {
            p.base_amount = held;
            p.amount_known = true;
        }
    }

    /// Back to Active with nothing done: its tokens are worth holding, so a
    /// close decided before no longer applies.
    pub fn hold(&mut self, id: &str) {
        if let Some(p) = self.positions.get_mut(id) {
            p.status = PositionStatus::Active;
            p.closing = false;
        }
    }

    /// A sell went through: the failures before it no longer count.
    pub fn sell_succeeded(&mut self, id: &str) {
        if let Some(p) = self.positions.get_mut(id) {
            p.sell_failures = 0;
            p.sell_attempts = 0;
            p.next_sell_at = None;
        }
    }

    pub fn push_log(&mut self, log: TradeLog) {
        if self.trade_logs.len() >= TRADE_LOG_CAP {
            self.trade_logs.pop_front();
        }
        self.trade_logs.push_back(log);
    }

    /// Push a notification event into the trade log.
    pub fn push_notification(&mut self, pool: Pubkey, base_mint: Pubkey, message: String) {
        let log = TradeLog {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            action: TradeAction::Notification,
            pool,
            base_mint,
            amount_sol: 0.0,
            amount_tokens: 0,
            tx_signature: None,
            error: None,
            message: Some(message),
        };
        self.push_log(log);
    }

    pub fn active_position_count(&self) -> usize {
        self.positions
            .values()
            .filter(|p| p.status == PositionStatus::Active || p.status == PositionStatus::Selling)
            .count()
    }
}

fn pubkey_str<S: serde::Serializer>(pubkey: &Pubkey, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&pubkey.to_string())
}

fn pubkey_from_str<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Pubkey, D::Error> {
    let s = String::deserialize(deserializer)?;
    Pubkey::from_str(&s).map_err(serde::de::Error::custom)
}

/// Persist a trade log entry to Redis (fire-and-forget).
/// Stores the JSON under `trade:logs:{id}`, and adds the id to sorted sets
/// `trade:logs:timeline` and `trade:logs:pool:{pool}` scored by unix-millis.
pub fn persist_trade_log_to_redis(client: &redis::Client, log: &TradeLog) {
    let client = client.clone();
    let log_id = log.id.clone();
    let pool_key = format!("trade:logs:pool:{}", log.pool);
    let score = log.timestamp.timestamp_millis() as f64;
    let json = match serde_json::to_string(log) {
        Ok(j) => j,
        Err(e) => {
            warn!("Failed to serialize TradeLog for Redis: {:?}", e);
            return;
        }
    };
    tokio::spawn(async move {
        let result: Result<(), redis::RedisError> = async {
            let mut con = client.get_multiplexed_async_connection().await?;
            redis::pipe()
                .atomic()
                .cmd("SET")
                .arg(format!("trade:logs:{}", &log_id))
                .arg(&json)
                .ignore()
                .cmd("ZADD")
                .arg("trade:logs:timeline")
                .arg(score)
                .arg(&log_id)
                .ignore()
                .cmd("ZADD")
                .arg(&pool_key)
                .arg(score)
                .arg(&log_id)
                .ignore()
                .query_async::<()>(&mut con)
                .await?;
            Ok(())
        }
        .await;
        if let Err(e) = result {
            warn!("Redis write failed for trade log {}: {:?}", log_id, e);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(id: &str, pool: Pubkey) -> Position {
        Position {
            id: id.to_string(),
            pool,
            base_mint: Pubkey::new_unique(),
            buy_price_lamports: 100_000,
            base_amount: 1_000,
            bought_at: Utc::now(),
            status: PositionStatus::Active,
            total_sell_lamports: 0,
            quote_token_program: Pubkey::default(),
            sell_failures: 0,
            sell_attempts: 0,
            draining: false,
            pending_sell: None,
            close_sent: false,
            amount_known: true,
            closing: false,
            next_sell_at: None,
            restored: false,
        }
    }

    #[test]
    fn a_pool_is_bought_once_and_buys_under_way_count_as_positions() {
        let mut s = AppState::new(None);
        s.config.max_positions = 1;
        let (a, b) = (Pubkey::new_unique(), Pubkey::new_unique());
        assert!(s.reserve_buy(a, Pubkey::new_unique()).is_ok());
        // The buy of a is still under way: it fills the one slot.
        assert!(s.reserve_buy(b, Pubkey::new_unique()).is_err());
        s.release_buy(&a);
        // a was considered: not again, even with the slot free.
        assert!(s.reserve_buy(a, Pubkey::new_unique()).is_err());
        assert!(s.reserve_buy(b, Pubkey::new_unique()).is_ok());
    }

    #[test]
    fn a_token_still_held_is_not_bought_again_through_another_pool() {
        let mut s = AppState::new(None);
        s.config.max_positions = 5;
        let mut p = position("p", Pubkey::new_unique());
        let mint = p.base_mint;
        // Given up: its tokens are still in the wallet.
        p.status = PositionStatus::Failed;
        s.positions.insert("p".into(), p);
        assert!(s.reserve_buy(Pubkey::new_unique(), mint).is_err());
        s.positions.get_mut("p").expect("p").status = PositionStatus::Closed;
        assert!(s.reserve_buy(Pubkey::new_unique(), mint).is_ok());
    }

    #[test]
    fn a_token_is_bought_through_one_pool_at_a_time() {
        let mut s = AppState::new(None);
        s.config.max_positions = 2;
        let mint = Pubkey::new_unique();
        let (a, b) = (Pubkey::new_unique(), Pubkey::new_unique());
        assert!(s.reserve_buy(a, mint).is_ok());
        // Two pools of one token would share one token account.
        assert!(s.reserve_buy(b, mint).is_err());
        assert!(s.reserve_buy(b, Pubkey::new_unique()).is_ok());
    }

    #[test]
    fn a_lower_balance_read_does_not_make_a_position_drain() {
        let mut s = AppState::new(None);
        let mut p = position("p", Pubkey::new_unique());
        p.amount_known = false;
        s.positions.insert("p".into(), p);
        s.record_holding("p", 400);
        let p = &s.positions["p"];
        assert_eq!((p.base_amount, p.amount_known, p.draining), (400, true, false));
    }

    #[test]
    fn holding_a_position_drops_a_close_that_no_longer_applies() {
        let mut s = AppState::new(None);
        let mut p = position("p", Pubkey::new_unique());
        p.closing = true;
        s.positions.insert("p".into(), p);
        assert!(s.claim_for_sell("p", Utc::now()).is_some());
        s.hold("p");
        let p = &s.positions["p"];
        assert_eq!((p.status.clone(), p.closing), (PositionStatus::Active, false));
    }

    #[test]
    fn only_one_task_claims_a_position_for_selling() {
        let mut s = AppState::new(None);
        s.positions.insert("p".into(), position("p", Pubkey::new_unique()));
        let now = Utc::now();
        assert!(s.claim_for_sell("p", now).is_some());
        assert!(s.claim_for_sell("p", now).is_none());
        assert_eq!(s.positions["p"].status, PositionStatus::Selling);
    }

    #[test]
    fn the_monitor_keeps_watching_a_position_being_sold() {
        let mut s = AppState::new(None);
        let pool = Pubkey::new_unique();
        s.positions.insert("p".into(), position("p", pool));
        // Claimed by a sell another task runs: still open, and when that
        // sell fails the monitor is there to retry it after the wait.
        assert!(s.claim_for_sell("p", Utc::now()).is_some());
        assert!(s.pool_has_open_position(&pool));
        s.sell_failed("p", Utc::now(), true);
        assert!(s.pool_has_open_position(&pool));
        for done in [PositionStatus::Sold, PositionStatus::Closed, PositionStatus::Failed] {
            s.positions.get_mut("p").expect("p").status = done;
            assert!(!s.pool_has_open_position(&pool));
        }
    }

    #[test]
    fn a_sell_that_landed_and_failed_waits_longer_each_time_then_is_given_up() {
        let mut s = AppState::new(None);
        s.positions.insert("p".into(), position("p", Pubkey::new_unique()));
        let now = Utc::now();
        let later = now + chrono::Duration::hours(1);
        let mut waits = Vec::new();
        for _ in 1..MAX_SELL_FAILURES {
            assert!(s.claim_for_sell("p", later).is_some());
            assert!(!s.sell_failed("p", now, true));
            let p = &s.positions["p"];
            assert_eq!(p.status, PositionStatus::Active);
            // Not before the wait is over.
            assert!(!s.may_sell(p, now));
            waits.push((p.next_sell_at.expect("a wait") - now).num_seconds());
        }
        assert!(waits.windows(2).all(|w| w[0] < w[1]), "{waits:?}");
        assert!(s.claim_for_sell("p", later).is_some());
        assert!(s.sell_failed("p", now, true));
        assert_eq!(s.positions["p"].status, PositionStatus::Failed);
    }

    #[test]
    fn failures_that_cost_nothing_are_retried_longer_but_not_for_ever() {
        let mut s = AppState::new(None);
        s.positions.insert("p".into(), position("p", Pubkey::new_unique()));
        let now = Utc::now();
        let later = now + chrono::Duration::hours(1);
        // More free failures than paid ones are allowed...
        for _ in 1..MAX_SELL_ATTEMPTS {
            assert!(s.claim_for_sell("p", later).is_some());
            assert!(!s.sell_failed("p", now, false));
        }
        let p = &s.positions["p"];
        assert_eq!(p.status, PositionStatus::Active);
        // ...with the wait at its cap...
        assert_eq!((p.next_sell_at.expect("a wait") - now).num_seconds(), MAX_SELL_RETRY_SECS);
        // ...and a sell that goes through clears the count.
        s.sell_succeeded("p");
        let p = &s.positions["p"];
        assert_eq!((p.sell_failures, p.sell_attempts, p.next_sell_at), (0, 0, None));
        // Without one, the last allowed failure gives it up.
        for _ in 1..MAX_SELL_ATTEMPTS {
            assert!(s.claim_for_sell("p", later).is_some());
            assert!(!s.sell_failed("p", now, false));
        }
        assert!(s.claim_for_sell("p", later).is_some());
        assert!(s.sell_failed("p", now, false));
        assert_eq!(s.positions["p"].status, PositionStatus::Failed);
    }

    #[test]
    fn a_sell_that_can_still_land_is_waited_for_without_counting() {
        let mut s = AppState::new(None);
        s.positions.insert("p".into(), position("p", Pubkey::new_unique()));
        let now = Utc::now();
        assert!(s.claim_for_sell("p", now).is_some());
        s.wait_for_pending("p", now);
        let p = &s.positions["p"];
        assert_eq!(p.status, PositionStatus::Active);
        assert_eq!((p.sell_failures, p.sell_attempts), (0, 0));
        assert!(!s.may_sell(p, now));
        assert!(s.may_sell(p, now + chrono::Duration::seconds(PENDING_SELL_RECHECK_SECS)));
    }

    #[test]
    fn a_restored_position_is_sold_only_while_trading_runs() {
        let mut s = AppState::new(None);
        let mut p = position("p", Pubkey::new_unique());
        p.restored = true;
        s.positions.insert("p".into(), p);
        assert!(s.claim_for_sell("p", Utc::now()).is_none());
        s.running = true;
        assert!(s.claim_for_sell("p", Utc::now()).is_some());
    }

    #[test]
    fn a_configuration_that_trades_badly_is_refused() {
        assert!(TradeConfig::default().validate().is_ok());
        assert!(TradeConfig { slippage_bps: 5_000, ..TradeConfig::default() }.validate().is_ok());
        let bad = [
            TradeConfig { buy_amount_lamports: 0, ..TradeConfig::default() },
            TradeConfig { sell_multiplier: 0.9, ..TradeConfig::default() },
            TradeConfig { sell_multiplier: f64::NAN, ..TradeConfig::default() },
            TradeConfig { slippage_bps: 5_001, ..TradeConfig::default() },
            TradeConfig { max_positions: 0, ..TradeConfig::default() },
            TradeConfig {
                min_pool_sol_lamports: 100_000,
                exit_pool_sol_lamports: 1_000_000,
                ..TradeConfig::default()
            },
        ];
        for config in bad {
            assert!(config.validate().is_err(), "{config:?}");
        }
    }
}
