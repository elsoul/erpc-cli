//! How early the bot sees a graduation, and how late its buys land.
//!
//! A pump.fun migration is seen up to three times: in the Shreds stream,
//! before it has run anywhere; in the Geyser stream at processed, once the
//! node that serves it has run it; and when its slot is confirmed. The
//! times between them, how far into its slot it was first seen, and how
//! many slots after the pool's own each buy landed, are what tell whether a
//! buy can land in the pool's slot. They judge; they never delay a send.

use serde::Serialize;
use solana_signature::Signature;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Samples kept per measure.
const SAMPLES: usize = 1_000;
/// Buys kept for the report.
const BUYS: usize = 50;
/// A migration or slot not finished with by then is forgotten.
const FORGET_AFTER: Duration = Duration::from_secs(120);

/// Where a pool was first seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    Shreds,
    Geyser,
}

/// When and where a pool was seen, to time its buy from.
#[derive(Debug, Clone, Copy)]
pub struct Sighting {
    pub slot: u64,
    pub seen: Instant,
    pub via: Via,
}

#[derive(Debug, Default)]
struct Samples(VecDeque<u64>);

impl Samples {
    fn push(&mut self, v: u64) {
        if self.0.len() == SAMPLES {
            self.0.pop_front();
        }
        self.0.push_back(v);
    }

    fn summary(&self) -> Summary {
        let mut sorted: Vec<u64> = self.0.iter().copied().collect();
        sorted.sort_unstable();
        let at = |q: usize| sorted.get((sorted.len() * q / 100).min(sorted.len().saturating_sub(1))).copied();
        Summary { count: sorted.len(), p50: at(50), p90: at(90), min: sorted.first().copied(), max: sorted.last().copied() }
    }
}

/// A measure over its last samples (up to 1000).
#[derive(Debug, Clone, Serialize, PartialEq, utoipa::ToSchema)]
pub struct Summary {
    pub count: usize,
    pub p50: Option<u64>,
    pub p90: Option<u64>,
    pub min: Option<u64>,
    pub max: Option<u64>,
}

#[derive(Debug)]
struct Track {
    slot: u64,
    shred: Option<Instant>,
    processed: Option<Instant>,
    since: Instant,
}

/// One buy, as the report shows it.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct BuyTiming {
    pub pool: String,
    pub via: Via,
    /// The slot the pool was seen in.
    pub pool_slot: u64,
    /// From first sight to the buy going out.
    pub detect_to_send_ms: u64,
    /// The slot the buy landed in, if it did.
    pub landed_slot: Option<u64>,
    /// `landed_slot - pool_slot`: 0 is the pool's own slot.
    pub slots_late: Option<u64>,
}

/// What `GET /api/timing` returns. Times in milliseconds.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct TimingReport {
    /// A migration in the Shreds stream to the same one in Geyser at processed.
    pub shred_to_processed_ms: Summary,
    /// A migration in the Shreds stream to its slot confirmed.
    pub shred_to_confirmed_ms: Summary,
    /// A migration in Geyser at processed to its slot confirmed.
    pub processed_to_confirmed_ms: Summary,
    /// How far into its slot a migration was first seen: from the slot's
    /// first shred at the Geyser node. A slot lasts about 400 ms.
    pub shred_offset_in_slot_ms: Summary,
    pub processed_offset_in_slot_ms: Summary,
    pub detect_to_send_ms: Summary,
    /// Slots between a pool's and its buy's: 0 is the same slot.
    pub slots_late: Summary,
    pub buys: Vec<BuyTiming>,
}

#[derive(Debug, Default)]
pub struct Timing {
    tracks: HashMap<Signature, Track>,
    slot_started: HashMap<u64, Instant>,
    shred_to_processed: Samples,
    shred_to_confirmed: Samples,
    processed_to_confirmed: Samples,
    shred_offset: Samples,
    processed_offset: Samples,
    detect_to_send: Samples,
    slots_late: Samples,
    buys: VecDeque<BuyTiming>,
}

fn ms(from: Instant, to: Instant) -> u64 {
    to.saturating_duration_since(from).as_millis() as u64
}

impl Timing {
    /// A migration seen in the Shreds stream.
    pub fn on_shred(&mut self, sig: Signature, slot: u64, now: Instant) {
        if let Some(start) = self.slot_started.get(&slot) {
            self.shred_offset.push(ms(*start, now));
        }
        self.tracks.entry(sig).or_insert(Track { slot, shred: None, processed: None, since: now }).shred.get_or_insert(now);
    }

    /// Whether a transaction is one being timed: the cheap check every
    /// Geyser transaction goes through.
    pub fn tracks(&self, sig: &Signature) -> bool {
        self.tracks.contains_key(sig)
    }

    /// A migration seen in Geyser at processed. Ones the Shreds stream
    /// missed are timed from here on.
    pub fn on_processed(&mut self, sig: Signature, slot: u64, now: Instant) {
        let track = self.tracks.entry(sig).or_insert(Track { slot, shred: None, processed: None, since: now });
        if track.processed.is_some() {
            return;
        }
        track.processed = Some(now);
        if let Some(shred) = track.shred {
            self.shred_to_processed.push(ms(shred, now));
        }
        if let Some(start) = self.slot_started.get(&slot) {
            self.processed_offset.push(ms(*start, now));
        }
    }

    /// The Geyser node got the first shred of `slot`.
    pub fn on_slot_started(&mut self, slot: u64, now: Instant) {
        self.slot_started.entry(slot).or_insert(now);
    }

    /// `slot` is confirmed: every migration in it is timed, and forgotten.
    pub fn on_slot_confirmed(&mut self, slot: u64, now: Instant) {
        let (shred_to_confirmed, processed_to_confirmed) = (&mut self.shred_to_confirmed, &mut self.processed_to_confirmed);
        self.tracks.retain(|_, t| {
            if t.slot != slot {
                return true;
            }
            if let Some(shred) = t.shred {
                shred_to_confirmed.push(ms(shred, now));
            }
            if let Some(processed) = t.processed {
                processed_to_confirmed.push(ms(processed, now));
            }
            false
        });
        self.forget(now);
    }

    /// `slot` will never be confirmed: what was seen in it is dropped.
    pub fn on_slot_dead(&mut self, slot: u64) {
        self.tracks.retain(|_, t| t.slot != slot);
        self.slot_started.remove(&slot);
    }

    fn forget(&mut self, now: Instant) {
        self.tracks.retain(|_, t| now.saturating_duration_since(t.since) < FORGET_AFTER);
        self.slot_started.retain(|_, at| now.saturating_duration_since(*at) < FORGET_AFTER);
    }

    /// A buy went out.
    pub fn on_buy_sent(&mut self, pool: String, sighting: &Sighting, now: Instant) {
        let detect_to_send_ms = ms(sighting.seen, now);
        self.detect_to_send.push(detect_to_send_ms);
        if self.buys.len() == BUYS {
            self.buys.pop_front();
        }
        self.buys.push_back(BuyTiming {
            pool,
            via: sighting.via,
            pool_slot: sighting.slot,
            detect_to_send_ms,
            landed_slot: None,
            slots_late: None,
        });
    }

    /// The buy of `pool` landed in `slot`.
    pub fn on_buy_landed(&mut self, pool: &str, slot: u64) {
        if let Some(buy) = self.buys.iter_mut().rev().find(|b| b.pool == pool && b.landed_slot.is_none()) {
            let late = slot.saturating_sub(buy.pool_slot);
            buy.landed_slot = Some(slot);
            buy.slots_late = Some(late);
            self.slots_late.push(late);
        }
    }

    pub fn report(&self) -> TimingReport {
        TimingReport {
            shred_to_processed_ms: self.shred_to_processed.summary(),
            shred_to_confirmed_ms: self.shred_to_confirmed.summary(),
            processed_to_confirmed_ms: self.processed_to_confirmed.summary(),
            shred_offset_in_slot_ms: self.shred_offset.summary(),
            processed_offset_in_slot_ms: self.processed_offset.summary(),
            detect_to_send_ms: self.detect_to_send.summary(),
            slots_late: self.slots_late.summary(),
            buys: self.buys.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_migration_is_timed_from_shreds_to_processed_to_confirmed() {
        let mut t = Timing::default();
        let t0 = Instant::now();
        let sig = Signature::from([7; 64]);
        t.on_slot_started(10, t0);
        t.on_shred(sig, 10, t0 + Duration::from_millis(120));
        assert!(t.tracks(&sig));
        t.on_processed(sig, 10, t0 + Duration::from_millis(170));
        // Seen twice at processed: timed once.
        t.on_processed(sig, 10, t0 + Duration::from_millis(900));
        t.on_slot_confirmed(10, t0 + Duration::from_millis(1_120));
        assert!(!t.tracks(&sig));
        let r = t.report();
        assert_eq!(r.shred_offset_in_slot_ms.p50, Some(120));
        assert_eq!(r.shred_to_processed_ms.p50, Some(50));
        assert_eq!(r.shred_to_processed_ms.count, 1);
        assert_eq!(r.processed_offset_in_slot_ms.count, 1);
        assert_eq!(r.shred_to_confirmed_ms.p50, Some(1_000));
        assert_eq!(r.processed_to_confirmed_ms.p50, Some(950));
    }

    #[test]
    fn a_buy_is_timed_from_sight_to_send_and_counted_in_slots_late() {
        let mut t = Timing::default();
        let t0 = Instant::now();
        let seen = Sighting { slot: 100, seen: t0, via: Via::Shreds };
        t.on_buy_sent("P".into(), &seen, t0 + Duration::from_millis(30));
        t.on_buy_landed("P", 100);
        let r = t.report();
        assert_eq!(r.detect_to_send_ms.p50, Some(30));
        assert_eq!(r.slots_late.p50, Some(0));
        assert_eq!(r.buys[0].slots_late, Some(0));
    }

    #[test]
    fn what_a_dead_slot_held_is_dropped() {
        let mut t = Timing::default();
        let sig = Signature::from([1; 64]);
        t.on_shred(sig, 5, Instant::now());
        t.on_slot_dead(5);
        assert!(!t.tracks(&sig));
    }

    #[test]
    fn percentiles_over_samples() {
        let mut s = Samples::default();
        for v in 1..=100 {
            s.push(v);
        }
        let sum = s.summary();
        assert_eq!((sum.count, sum.p50, sum.p90, sum.min, sum.max), (100, Some(51), Some(91), Some(1), Some(100)));
        assert_eq!(Samples::default().summary().p50, None);
    }
}
