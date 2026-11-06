//! Pool creators not to buy from.
//!
//! Some creators open pool after pool to draw bots in, then pull the
//! liquidity seconds after a buy. Two signs give them away, and either bans
//! the creator for as long as the bot runs (and, with Redis, across
//! restarts):
//!
//! - **Too many pools:** more than `creator_max_pools` in
//!   `creator_window_secs`.
//! - **Liquidity pulled:** a PumpSwap `withdraw` from a pool by the wallet
//!   that created it, or by anyone from a pool this bot saw created.
//!
//! `banned_creators` in the config bans creators from the start, and
//! `POST /api/bans/trace` bans the wallets banned creators were funded from
//! (see `trace`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use solana_sdk::pubkey::Pubkey;

/// The Anchor discriminator of PumpSwap's `withdraw`
/// (`sha256("global:withdraw")[..8]`).
pub const WITHDRAW_DISCRIMINATOR: [u8; 8] = [183, 18, 70, 156, 148, 109, 161, 34];

/// The Redis hash that keeps banned creators and why.
pub const REDIS_KEY: &str = "pumpfun:banned_creators";

/// The pool and the wallet of a PumpSwap `withdraw`, if `data` is one.
/// Its accounts start with the pool, then the user.
pub fn withdraw_of(data: &[u8], accounts: &[Pubkey]) -> Option<(Pubkey, Pubkey)> {
    if data.get(..8)? != WITHDRAW_DISCRIMINATOR {
        return None;
    }
    Some((*accounts.first()?, *accounts.get(1)?))
}

/// Who created which pool lately, and who is banned.
#[derive(Debug, Default)]
pub struct CreatorWatch {
    /// When each creator opened a pool, within the window.
    created: HashMap<Pubkey, VecDeque<Instant>>,
    /// Banned creators and why.
    banned: HashMap<Pubkey, String>,
    /// The creator of each pool seen created, to blame a withdraw on.
    pool_creator: HashMap<Pubkey, Pubkey>,
    /// Banned creators whose funding was traced already.
    traced: HashSet<Pubkey>,
}

/// What a new pool means.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The creator is fine: the pool may be bought.
    Fine,
    /// The creator was banned before.
    Banned(String),
    /// The creator is banned now, for this reason.
    NewlyBanned(String),
}

impl CreatorWatch {
    /// Bans `creator` for `reason`; whether it is new.
    pub fn ban(&mut self, creator: Pubkey, reason: &str) -> bool {
        if self.banned.contains_key(&creator) {
            return false;
        }
        self.banned.insert(creator, reason.to_owned());
        true
    }

    /// Notes `pool` created by `creator` at `now`, and says whether it may be
    /// bought: not when the creator is banned, or has now opened more than
    /// `max_pools` within `window`. A pool seen before (in the Shreds stream,
    /// then in Geyser) counts once.
    pub fn on_create(
        &mut self,
        pool: Pubkey,
        creator: Pubkey,
        now: Instant,
        window: Duration,
        max_pools: usize,
    ) -> Verdict {
        let seen_before = self.pool_creator.insert(pool, creator).is_some();
        if let Some(reason) = self.banned.get(&creator) {
            return Verdict::Banned(reason.clone());
        }
        if seen_before {
            return Verdict::Fine;
        }
        let times = self.created.entry(creator).or_default();
        times.push_back(now);
        while times
            .front()
            .is_some_and(|t| now.duration_since(*t) > window)
        {
            times.pop_front();
        }
        if times.len() > max_pools {
            let reason = format!(
                "opened {} pools in {} s",
                times.len(),
                window.as_secs()
            );
            self.ban(creator, &reason);
            return Verdict::NewlyBanned(reason);
        }
        Verdict::Fine
    }

    /// Notes a `withdraw` from `pool` by `user`, and bans the pool's creator
    /// (or the user, when the pool was not seen created). The creator newly
    /// banned, if any.
    pub fn on_withdraw(&mut self, pool: Pubkey, user: Pubkey) -> Option<Pubkey> {
        let creator = self.pool_creator.get(&pool).copied().unwrap_or(user);
        let reason = format!("pulled liquidity from pool {pool}");
        self.ban(creator, &reason).then_some(creator)
    }

    /// Banned creators whose funding has not been traced, in address order.
    pub fn untraced(&self) -> Vec<Pubkey> {
        let mut out: Vec<Pubkey> = self.banned.keys().filter(|c| !self.traced.contains(c)).copied().collect();
        out.sort();
        out
    }

    pub fn mark_traced(&mut self, creator: Pubkey) {
        self.traced.insert(creator);
    }

    /// Whether `creator` is banned.
    #[cfg(test)]
    pub fn is_banned(&self, creator: &Pubkey) -> bool {
        self.banned.contains_key(creator)
    }

    /// The banned creators and why, for the status API.
    pub fn banned(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .banned
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        out.sort();
        out
    }

    /// Forgets creators and pools last seen longer ago than `window`, so
    /// that a bot running for days holds only what still matters. Bans stay.
    pub fn prune(&mut self, now: Instant, window: Duration) {
        self.created.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) <= window);
            !times.is_empty()
        });
        if self.pool_creator.len() > 100_000 {
            self.pool_creator.clear();
        }
    }
}

/// Saves a ban to Redis, when there is one, without waiting.
pub fn persist_ban(client: Option<&redis::Client>, creator: Pubkey, reason: String) {
    let Some(client) = client.cloned() else {
        return;
    };
    tokio::spawn(async move {
        let result: Result<(), redis::RedisError> = async {
            let mut con = client.get_multiplexed_async_connection().await?;
            redis::cmd("HSET")
                .arg(REDIS_KEY)
                .arg(creator.to_string())
                .arg(reason)
                .query_async(&mut con)
                .await
        }
        .await;
        if let Err(e) = result {
            log::warn!("Could not save the ban of {creator} to Redis: {e:?}");
        }
    });
}

/// The bans saved in Redis, read at start.
pub async fn load_bans(client: &redis::Client) -> Vec<(Pubkey, String)> {
    let result: Result<Vec<(String, String)>, redis::RedisError> = async {
        let mut con = client.get_multiplexed_async_connection().await?;
        redis::cmd("HGETALL").arg(REDIS_KEY).query_async(&mut con).await
    }
    .await;
    match result {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|(k, v)| k.parse().ok().map(|p| (p, v)))
            .collect(),
        Err(e) => {
            log::warn!("Could not read banned creators from Redis: {e:?}");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Pubkey {
        Pubkey::new_from_array([n; 32])
    }

    #[test]
    fn a_creator_opening_too_many_pools_is_banned_from_the_next_one() {
        let mut w = CreatorWatch::default();
        let t0 = Instant::now();
        let window = Duration::from_secs(600);
        assert_eq!(w.on_create(key(1), key(9), t0, window, 2), Verdict::Fine);
        assert_eq!(
            w.on_create(key(2), key(9), t0 + Duration::from_secs(60), window, 2),
            Verdict::Fine
        );
        assert!(matches!(
            w.on_create(key(3), key(9), t0 + Duration::from_secs(120), window, 2),
            Verdict::NewlyBanned(_)
        ));
        assert!(matches!(
            w.on_create(key(4), key(9), t0 + Duration::from_secs(3600), window, 2),
            Verdict::Banned(_)
        ));
    }

    #[test]
    fn a_pool_seen_in_shreds_then_geyser_counts_once() {
        let mut w = CreatorWatch::default();
        let t0 = Instant::now();
        let window = Duration::from_secs(600);
        for _ in 0..3 {
            assert_eq!(w.on_create(key(1), key(9), t0, window, 1), Verdict::Fine);
        }
        assert!(matches!(w.on_create(key(2), key(9), t0, window, 1), Verdict::NewlyBanned(_)));
    }

    #[test]
    fn a_traced_creator_is_not_traced_again() {
        let mut w = CreatorWatch::default();
        w.ban(key(2), "x");
        w.ban(key(1), "x");
        assert_eq!(w.untraced(), vec![key(1), key(2)]);
        w.mark_traced(key(1));
        assert_eq!(w.untraced(), vec![key(2)]);
    }

    #[test]
    fn pools_outside_the_window_do_not_count() {
        let mut w = CreatorWatch::default();
        let t0 = Instant::now();
        let window = Duration::from_secs(600);
        for i in 0..5u8 {
            let at = t0 + Duration::from_secs(u64::from(i) * 700);
            assert_eq!(w.on_create(key(i), key(9), at, window, 2), Verdict::Fine);
        }
    }

    #[test]
    fn pulling_liquidity_bans_the_pools_creator() {
        let mut w = CreatorWatch::default();
        let window = Duration::from_secs(600);
        w.on_create(key(1), key(9), Instant::now(), window, 2);
        assert_eq!(w.on_withdraw(key(1), key(9)), Some(key(9)));
        assert!(w.is_banned(&key(9)));
        assert_eq!(w.on_withdraw(key(1), key(9)), None, "banned once");
        // A pool not seen created: the withdrawing wallet is banned.
        assert_eq!(w.on_withdraw(key(2), key(8)), Some(key(8)));
    }

    #[test]
    fn a_withdraw_is_read_from_its_discriminator_pool_and_user() {
        let mut data = WITHDRAW_DISCRIMINATOR.to_vec();
        data.extend_from_slice(&[0; 24]);
        let accounts = [key(1), key(9), key(3)];
        assert_eq!(withdraw_of(&data, &accounts), Some((key(1), key(9))));
        assert_eq!(withdraw_of(&[0; 32], &accounts), None);
        assert_eq!(withdraw_of(&data, &accounts[..1]), None);
    }
}
