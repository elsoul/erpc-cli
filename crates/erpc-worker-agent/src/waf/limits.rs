// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the proxy remembers about each client address: how many
//! connections it holds, how many requests it may still make, how often it
//! was blocked, and until when it is banned.
//!
//! All of it is in memory and none of it grows without limit: at most
//! [`TRACKED`] addresses are remembered, and the one seen longest ago is
//! forgotten for a new one. Time is a number of milliseconds handed in, so
//! that the tests need no clock.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};

use erpc_worker::waf::{Ban, Rate, WafConfig};

/// Milliseconds since the proxy started.
pub(super) type Millis = u64;

/// How many addresses are remembered at once. Well above the connections
/// the proxy holds, so an address with a connection is never the one
/// forgotten.
pub(super) const TRACKED: usize = 8192;

/// One request, in the bucket's unit: a thousandth of a request.
const REQUEST: u64 = 1000;

/// The address a client is counted under.
///
/// An IPv4 address that arrived over an IPv6 socket (`::ffff:a.b.c.d`) is
/// that IPv4 address. An IPv6 address is its `/64`: a network hands a
/// host that many addresses, and a rule each of them could step round
/// would be no rule.
pub(super) fn key(peer: IpAddr) -> IpAddr {
    match peer.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & !u128::from(u64::MAX))),
    }
}

/// Why a connection is not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// Its address is banned.
    Banned,
    /// Its address holds as many as it may.
    TooMany,
}

/// What is remembered about one address.
#[derive(Debug)]
struct Entry {
    /// When it was last heard from.
    seen: Millis,
    /// Open connections.
    connections: u32,
    /// What is left of its rate, in thousandths of a request.
    tokens: u64,
    /// When `tokens` was last brought up to date.
    refilled: Millis,
    /// When it was blocked, within the ban's window: at most `ban.after`.
    violations: VecDeque<Millis>,
    /// Until when it is banned.
    banned_until: Option<Millis>,
}

/// Every address the proxy remembers.
#[derive(Debug)]
pub(super) struct Limits {
    rate: Option<Rate>,
    ban: Option<Ban>,
    per_address: Option<u32>,
    capacity: usize,
    entries: HashMap<IpAddr, Entry>,
    /// The same addresses by when each was last heard from, oldest first.
    by_age: BTreeSet<(Millis, IpAddr)>,
}

impl Limits {
    pub(super) fn new(config: &WafConfig, capacity: usize) -> Self {
        Self {
            rate: config.rate,
            ban: config.ban,
            per_address: config.max_connections_per_address,
            capacity: capacity.max(1),
            entries: HashMap::new(),
            by_age: BTreeSet::new(),
        }
    }

    /// How many connections are open, from every address together.
    #[cfg(test)]
    pub(super) fn connections(&self) -> u32 {
        self.entries.values().map(|e| e.connections).sum()
    }

    /// How many addresses are remembered.
    #[cfg(test)]
    fn len(&self) -> usize {
        debug_assert_eq!(self.entries.len(), self.by_age.len());
        self.entries.len()
    }

    /// What is remembered about `key`, heard from now. A new address takes
    /// the place of the one heard from longest ago that has no connection;
    /// `None` when every one remembered has, which the capacity rules out.
    fn touch(&mut self, key: IpAddr, now: Millis) -> Option<&mut Entry> {
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= self.capacity {
                let oldest = self
                    .by_age
                    .iter()
                    .find(|(_, k)| self.entries.get(k).is_none_or(|e| e.connections == 0))
                    .copied()?;
                self.by_age.remove(&oldest);
                self.entries.remove(&oldest.1);
            }
            let full = self
                .rate
                .map_or(0, |r| u64::from(r.burst).saturating_mul(REQUEST));
            self.entries.insert(
                key,
                Entry {
                    seen: now,
                    connections: 0,
                    tokens: full,
                    refilled: now,
                    violations: VecDeque::new(),
                    banned_until: None,
                },
            );
            self.by_age.insert((now, key));
        }
        let entry = self.entries.get_mut(&key)?;
        if entry.seen != now {
            self.by_age.remove(&(entry.seen, key));
            entry.seen = now;
            self.by_age.insert((now, key));
        }
        Some(entry)
    }

    /// Takes a connection from `key`, or says why not. One taken is given
    /// back with [`Self::disconnect`].
    pub(super) fn connect(&mut self, key: IpAddr, now: Millis) -> Result<(), Refused> {
        let most = self.per_address;
        // An address that cannot be remembered cannot be counted either.
        let entry = self.touch(key, now).ok_or(Refused::TooMany)?;
        if entry.banned_until.is_some_and(|until| now < until) {
            return Err(Refused::Banned);
        }
        if most.is_some_and(|most| entry.connections >= most) {
            return Err(Refused::TooMany);
        }
        entry.connections = entry.connections.saturating_add(1);
        Ok(())
    }

    /// Gives back a connection [`Self::connect`] took.
    pub(super) fn disconnect(&mut self, key: IpAddr) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.connections = entry.connections.saturating_sub(1);
        }
    }

    /// Whether `key` is banned now.
    pub(super) fn is_banned(&self, key: IpAddr, now: Millis) -> bool {
        self.entries
            .get(&key)
            .and_then(|e| e.banned_until)
            .is_some_and(|until| now < until)
    }

    /// Takes one request from `key`'s rate, or says in how many seconds
    /// there will be one to take.
    pub(super) fn take(&mut self, key: IpAddr, now: Millis) -> Result<(), u64> {
        let Some(rate) = self.rate else {
            return Ok(());
        };
        let per_second = u64::from(rate.per_second.max(1));
        let full = u64::from(rate.burst).saturating_mul(REQUEST);
        let Some(entry) = self.touch(key, now) else {
            return Err(1);
        };
        // A thousandth of a request for each millisecond at one a second.
        let gained = now
            .saturating_sub(entry.refilled)
            .saturating_mul(per_second);
        entry.tokens = entry.tokens.saturating_add(gained).min(full);
        entry.refilled = entry.refilled.max(now);
        if entry.tokens >= REQUEST {
            entry.tokens -= REQUEST;
            return Ok(());
        }
        let millis = (REQUEST - entry.tokens).div_ceil(per_second);
        Err(millis.div_ceil(1000).max(1))
    }

    /// Counts a blocked request against `key`. True when that bans it: it
    /// was blocked `ban.after` times within `ban.window_secs`.
    pub(super) fn violation(&mut self, key: IpAddr, now: Millis) -> bool {
        let Some(ban) = self.ban else {
            return false;
        };
        let window = u64::from(ban.window_secs).saturating_mul(1000);
        let after = usize::try_from(ban.after).unwrap_or(usize::MAX).max(1);
        let Some(entry) = self.touch(key, now) else {
            return false;
        };
        while entry
            .violations
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= window)
        {
            entry.violations.pop_front();
        }
        entry.violations.push_back(now);
        if entry.violations.len() < after {
            return false;
        }
        entry.violations.clear();
        entry.banned_until = Some(now.saturating_add(u64::from(ban.for_secs).saturating_mul(1000)));
        true
    }

    /// How many addresses are banned now.
    pub(super) fn banned_now(&self, now: Millis) -> u64 {
        let banned = self
            .entries
            .values()
            .filter(|e| e.banned_until.is_some_and(|until| now < until))
            .count();
        u64::try_from(banned).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use erpc_worker::waf::{Ban, Rate, WafConfig};

    use super::{Limits, Refused, TRACKED, key};

    fn config() -> WafConfig {
        WafConfig::default_for(
            "bot-prod",
            "127.0.0.1:8080".parse().expect("listen"),
            "127.0.0.1:3000".parse().expect("upstream"),
        )
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    /// The `n`th of many distinct IPv4 addresses.
    fn nth(n: u32) -> IpAddr {
        IpAddr::V4((0x0b00_0000 + n).into())
    }

    #[test]
    fn a_client_is_counted_under_its_ipv4_address_or_its_ipv6_network() {
        assert_eq!(key(ip("198.51.100.7")), ip("198.51.100.7"));
        // The same client over an IPv6 socket.
        assert_eq!(key(ip("::ffff:198.51.100.7")), ip("198.51.100.7"));
        assert_eq!(key(ip("::ffff:c633:6407")), ip("198.51.100.7"));
        // Every address of one /64 is one client.
        assert_eq!(key(ip("2001:db8:1:2:3:4:5:6")), ip("2001:db8:1:2::"));
        assert_eq!(
            key(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")),
            ip("2001:db8:1:2::")
        );
        assert_ne!(key(ip("2001:db8:1:3::1")), key(ip("2001:db8:1:2::1")));
        assert_eq!(key(ip("::1")), ip("::"));
    }

    #[test]
    fn the_bucket_lets_the_burst_through_and_then_the_rate() {
        let mut config = config();
        config.rate = Some(Rate {
            per_second: 2,
            burst: 5,
        });
        let mut limits = Limits::new(&config, TRACKED);
        let (a, b) = (ip("198.51.100.7"), ip("198.51.100.8"));
        for _ in 0..5 {
            assert_eq!(limits.take(a, 0), Ok(()));
        }
        // Empty: the next is in half a second, said as a whole second.
        assert_eq!(limits.take(a, 0), Err(1));
        assert_eq!(limits.take(a, 499), Err(1));
        // Another address has its own.
        assert_eq!(limits.take(b, 499), Ok(()));
        assert_eq!(limits.take(a, 500), Ok(()));
        assert_eq!(limits.take(a, 500), Err(1));
        // Two a second from then on, and no more for having waited less.
        assert_eq!(limits.take(a, 1500), Ok(()));
        assert_eq!(limits.take(a, 1500), Ok(()));
        assert_eq!(limits.take(a, 1500), Err(1));
        // A long wait fills it to the burst and no further.
        for _ in 0..5 {
            assert_eq!(limits.take(a, 3_600_000), Ok(()));
        }
        assert_eq!(limits.take(a, 3_600_000), Err(1));
        // A clock that steps back gives nothing, then or after.
        assert_eq!(limits.take(a, 0), Err(1));
        assert_eq!(limits.take(a, 3_600_000), Err(1));
    }

    #[test]
    fn a_slow_rate_says_how_long_to_wait_and_no_rate_never_refuses() {
        let mut config = config();
        config.rate = Some(Rate {
            per_second: 1,
            burst: 1,
        });
        let mut limits = Limits::new(&config, TRACKED);
        let a = ip("198.51.100.7");
        assert_eq!(limits.take(a, 0), Ok(()));
        assert_eq!(limits.take(a, 1), Err(1));
        assert_eq!(limits.take(a, 999), Err(1));
        assert_eq!(limits.take(a, 1000), Ok(()));
        config.rate = None;
        let mut limits = Limits::new(&config, TRACKED);
        for _ in 0..10_000 {
            assert_eq!(limits.take(a, 0), Ok(()));
        }
    }

    #[test]
    fn an_address_is_banned_after_enough_blocks_in_the_window_and_then_let_back() {
        let mut config = config();
        config.ban = Some(Ban {
            after: 3,
            window_secs: 60,
            for_secs: 600,
        });
        let mut limits = Limits::new(&config, TRACKED);
        let (a, b) = (ip("198.51.100.7"), ip("198.51.100.8"));
        // Two in the window, and a third after the first has left it.
        assert!(!limits.violation(a, 0));
        assert!(!limits.violation(a, 30_000));
        assert!(!limits.violation(a, 60_000));
        assert!(!limits.is_banned(a, 60_000));
        assert_eq!(limits.connect(a, 60_000), Ok(()));
        limits.disconnect(a);
        // The third within sixty seconds of the second bans it.
        assert!(limits.violation(a, 89_999));
        assert!(limits.is_banned(a, 89_999));
        assert_eq!(limits.connect(a, 90_000), Err(Refused::Banned));
        assert_eq!(limits.banned_now(90_000), 1);
        // Only that address.
        assert_eq!(limits.connect(b, 90_000), Ok(()));
        assert!(!limits.is_banned(b, 90_000));
        // To the millisecond, for as long as the config says.
        assert_eq!(limits.connect(a, 689_998), Err(Refused::Banned));
        assert!(!limits.is_banned(a, 689_999));
        assert_eq!(limits.connect(a, 689_999), Ok(()));
        assert_eq!(limits.banned_now(689_999), 0);
        // And it starts from nothing: two more blocks are not a ban.
        assert!(!limits.violation(a, 690_000));
        assert!(!limits.violation(a, 690_001));
        assert!(limits.violation(a, 690_002));
        // Without a ban in the config nothing is counted.
        config.ban = None;
        let mut limits = Limits::new(&config, TRACKED);
        for at in 0..1000 {
            assert!(!limits.violation(a, at));
        }
        assert_eq!(limits.connect(a, 1000), Ok(()));
    }

    #[test]
    fn an_address_holds_only_so_many_connections() {
        let mut config = config();
        config.max_connections_per_address = Some(2);
        let mut limits = Limits::new(&config, TRACKED);
        let (a, b) = (ip("198.51.100.7"), ip("2001:db8::1"));
        assert_eq!(limits.connect(a, 0), Ok(()));
        assert_eq!(limits.connect(a, 0), Ok(()));
        assert_eq!(limits.connect(a, 0), Err(Refused::TooMany));
        assert_eq!(limits.connect(b, 0), Ok(()));
        limits.disconnect(a);
        assert_eq!(limits.connect(a, 1), Ok(()));
        assert_eq!(limits.connect(a, 1), Err(Refused::TooMany));
        // Giving back more than was taken does not go below none.
        for _ in 0..5 {
            limits.disconnect(b);
        }
        assert_eq!(limits.connect(b, 2), Ok(()));
        assert_eq!(limits.connect(b, 2), Ok(()));
        assert_eq!(limits.connect(b, 2), Err(Refused::TooMany));
        config.max_connections_per_address = None;
        let mut limits = Limits::new(&config, TRACKED);
        for _ in 0..5000 {
            assert_eq!(limits.connect(a, 0), Ok(()));
        }
    }

    #[test]
    fn no_more_addresses_are_remembered_than_the_table_holds() {
        let mut limits = Limits::new(&config(), 4);
        for n in 0..4 {
            assert_eq!(limits.take(nth(n), u64::from(n)), Ok(()));
        }
        assert_eq!(limits.len(), 4);
        // A fifth takes the place of the one heard from longest ago.
        assert_eq!(limits.take(nth(4), 10), Ok(()));
        assert_eq!(limits.len(), 4);
        assert!(!limits.entries.contains_key(&nth(0)));
        assert!(limits.entries.contains_key(&nth(1)));
        // Hearing from one again makes it the newest.
        assert_eq!(limits.take(nth(1), 11), Ok(()));
        assert_eq!(limits.take(nth(5), 12), Ok(()));
        assert!(limits.entries.contains_key(&nth(1)));
        assert!(!limits.entries.contains_key(&nth(2)));
        // However many addresses knock, the table stays its size.
        for n in 100..100_000 {
            let _ = limits.take(nth(n), 13);
            limits.violation(nth(n), 13);
        }
        assert_eq!(limits.len(), 4);
    }

    #[test]
    fn an_address_with_a_connection_is_not_the_one_forgotten() {
        let mut limits = Limits::new(&config(), 3);
        assert_eq!(limits.connect(nth(0), 0), Ok(()));
        assert_eq!(limits.take(nth(1), 1), Ok(()));
        assert_eq!(limits.take(nth(2), 2), Ok(()));
        // The oldest has a connection: the next oldest goes.
        assert_eq!(limits.take(nth(3), 3), Ok(()));
        assert!(limits.entries.contains_key(&nth(0)));
        assert!(!limits.entries.contains_key(&nth(1)));
        // Its count is still right when the connection ends.
        limits.disconnect(nth(0));
        assert_eq!(limits.entries.get(&nth(0)).expect("kept").connections, 0);
        // With every address holding a connection there is no room, and
        // one more is refused rather than left uncounted.
        let mut limits = Limits::new(&config(), 2);
        assert_eq!(limits.connect(nth(0), 0), Ok(()));
        assert_eq!(limits.connect(nth(1), 0), Ok(()));
        assert_eq!(limits.connect(nth(2), 0), Err(Refused::TooMany));
        assert_eq!(limits.take(nth(2), 0), Err(1));
        assert!(!limits.violation(nth(2), 0));
        assert_eq!(limits.len(), 2);
    }

    #[test]
    fn a_banned_address_that_keeps_knocking_stays_banned_while_others_come_and_go() {
        let mut config = config();
        config.ban = Some(Ban {
            after: 1,
            window_secs: 60,
            for_secs: 600,
        });
        let mut limits = Limits::new(&config, 4);
        let bad = nth(0);
        assert!(limits.violation(bad, 0));
        for n in 1..1000 {
            let now = u64::from(n);
            // It knocks, and is refused, between every two newcomers.
            assert_eq!(limits.connect(bad, now), Err(Refused::Banned));
            assert_eq!(limits.take(nth(n), now), Ok(()));
        }
        assert_eq!(limits.connect(bad, 1000), Err(Refused::Banned));
        assert_eq!(limits.banned_now(1000), 1);
        assert_eq!(limits.len(), 4);
    }
}
