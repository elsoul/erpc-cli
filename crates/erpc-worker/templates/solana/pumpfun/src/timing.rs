//! How early the bot sees a graduation, and how late its buys land.
//!
//! A pump.fun migration is seen up to four times: in the raw shreds ERPC
//! forwards over UDP and in the Shreds stream, both before it has run
//! anywhere; in the Geyser stream at processed, once the node that serves
//! it has run it; and when its slot is confirmed. The times between them,
//! how far into its slot it was first seen, and how many slots after the
//! pool's own each buy landed, are what tell whether a buy can land in the
//! pool's slot. They judge; they never delay a send.

use serde::Serialize;
use solana_signature::Signature;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
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
    /// The raw shreds ERPC forwards over UDP (`SHREDS_UDP_BIND`); a build
    /// without the `udp` feature never sees one.
    #[cfg_attr(not(feature = "udp"), allow(dead_code))]
    Udp,
    Geyser,
}

impl Via {
    /// The source, as a log line names it.
    pub fn source(self) -> &'static str {
        match self {
            Via::Shreds => "the Shreds stream",
            Via::Udp => "the UDP shreds",
            Via::Geyser => "Geyser",
        }
    }
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
    udp: Option<Instant>,
    processed: Option<Instant>,
    since: Instant,
}

impl Track {
    fn new(slot: u64, since: Instant) -> Self {
        Track { slot, shred: None, udp: None, processed: None, since }
    }
}

/// The settings a buy was made under, or those in force now: which
/// configuration it is (`rev`: 0 when the bot starts, one more each time
/// `PUT /api/config` changes the configuration, whatever setting changed),
/// and the settings that decide how a buy goes out. Buys of one `rev` were
/// made under one configuration, so what is read of buys after a change is
/// read of the buys whose `rev` is the one in force.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct Settings {
    pub rev: u64,
    pub buy_on_shreds: bool,
    pub priority_fee_micro_lamports: u64,
    pub compute_unit_limit: u32,
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
    /// It landed and failed on chain: before its pool existed, past its
    /// slippage, and the like. It paid its fee and bought nothing, so it is
    /// not in the `slots_late` summary.
    pub failed: bool,
    /// The settings it was made under, read with those it was sent with.
    pub settings: Settings,
}

/// What `GET /api/timing` returns. Times in milliseconds.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct TimingReport {
    /// A migration in the Shreds stream to the same one in Geyser at processed.
    pub shred_to_processed_ms: Summary,
    /// A migration in the Shreds stream to its slot confirmed.
    pub shred_to_confirmed_ms: Summary,
    /// A migration in the UDP shreds to the same one in Geyser at processed.
    pub udp_to_processed_ms: Summary,
    /// A migration in the UDP shreds to its slot confirmed.
    pub udp_to_confirmed_ms: Summary,
    /// A migration in Geyser at processed to its slot confirmed.
    pub processed_to_confirmed_ms: Summary,
    /// A migration seen in both: how much sooner the UDP shreds showed it
    /// than the Shreds stream did...
    pub udp_before_shreds_ms: Summary,
    /// ...or, when the Shreds stream was first, by how much.
    pub shreds_before_udp_ms: Summary,
    /// How far into its slot a migration was first seen: from the slot's
    /// first shred at the Geyser node. A slot lasts about 400 ms.
    pub shred_offset_in_slot_ms: Summary,
    pub udp_offset_in_slot_ms: Summary,
    pub processed_offset_in_slot_ms: Summary,
    pub detect_to_send_ms: Summary,
    /// Slots between a pool's and its buy's: 0 is the same slot.
    pub slots_late: Summary,
    pub buys: Vec<BuyTiming>,
    /// The UDP shreds: whether they arrive, and what came of them.
    pub udp: UdpReport,
    /// The settings in force now: a buy whose `settings.rev` is another
    /// was made under settings changed since.
    pub settings: Settings,
}

/// Why a datagram was dropped before anything of it was kept.
#[cfg_attr(not(feature = "udp"), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub enum Dropped {
    /// Longer than a packet, too short to name a slot, or no shred.
    Malformed,
    /// For a slot too far from the one Geyser is at, or before Geyser
    /// reported any.
    OutsideWindow,
    /// For a slot whose leader the RPC's schedule has not named yet.
    NoLeader,
    /// Not signed by its slot's leader.
    BadSignature,
}

/// What came in over UDP, counted without a lock: a datagram arrives
/// thousands of times a second, and the timing lock is for migrations.
#[derive(Debug, Default)]
pub struct UdpCounters {
    bound: OnceLock<SocketAddr>,
    datagrams: AtomicU64,
    batches: AtomicU64,
    migrations: AtomicU64,
    /// By `Dropped`, in its order.
    dropped: [AtomicU64; 4],
    resets: AtomicU64,
    migrations_dropped: AtomicU64,
}

// Without the `udp` feature nothing counts: the report shows zeros.
#[cfg_attr(not(feature = "udp"), allow(dead_code))]
impl UdpCounters {
    /// The socket is bound to `addr`.
    pub fn bound(&self, addr: SocketAddr) {
        let _ = self.bound.set(addr);
    }

    /// A datagram arrived.
    pub fn datagram(&self) {
        self.datagrams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn datagrams(&self) -> u64 {
        self.datagrams.load(Ordering::Relaxed)
    }

    /// A batch of shreds was decoded.
    pub fn batch(&self) {
        self.batches.fetch_add(1, Ordering::Relaxed);
    }

    /// A migration was found in one.
    pub fn migration(&self) {
        self.migrations.fetch_add(1, Ordering::Relaxed);
    }

    /// A datagram was dropped, for `why`.
    pub fn dropped(&self, why: Dropped) {
        self.dropped[why as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The shreds kept went over their limit, and were all dropped.
    pub fn reset(&self) {
        self.resets.fetch_add(1, Ordering::Relaxed);
    }

    /// A migration these shreds showed was not followed up: as many as the
    /// bot follows at once were being followed.
    pub fn migration_dropped(&self) {
        self.migrations_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn report(&self) -> UdpReport {
        let dropped = |why: Dropped| self.dropped[why as usize].load(Ordering::Relaxed);
        UdpReport {
            bound: self.bound.get().map(ToString::to_string),
            datagrams: self.datagrams(),
            batches: self.batches.load(Ordering::Relaxed),
            migrations: self.migrations.load(Ordering::Relaxed),
            dropped: UdpDropped {
                malformed: dropped(Dropped::Malformed),
                outside_window: dropped(Dropped::OutsideWindow),
                no_leader: dropped(Dropped::NoLeader),
                bad_signature: dropped(Dropped::BadSignature),
            },
            resets: self.resets.load(Ordering::Relaxed),
            migrations_dropped: self.migrations_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Datagrams dropped before anything of them was kept, by why. A datagram
/// is whatever reached the port, so these count what was sent to it by
/// others than the leader as much as what went wrong on the way.
#[derive(Debug, Clone, Default, Serialize, PartialEq, utoipa::ToSchema)]
pub struct UdpDropped {
    /// Longer than a packet, too short to name a slot, or no shred.
    pub malformed: u64,
    /// For a slot more than 32 before or 64 after the last one Geyser
    /// reported, or before Geyser reported any.
    pub outside_window: u64,
    /// For a slot whose leader the RPC's leader schedule has not named:
    /// above 0 and rising, the schedule cannot be read.
    pub no_leader: u64,
    /// Not signed by the leader of its slot.
    pub bad_signature: u64,
}

/// The UDP shreds (`SHREDS_UDP_BIND`), as the report shows them.
#[derive(Debug, Clone, Default, Serialize, PartialEq, utoipa::ToSchema)]
pub struct UdpReport {
    /// The address they arrive on, once the socket is bound; none without
    /// `SHREDS_UDP_BIND`.
    pub bound: Option<String>,
    /// Datagrams received, one shred each: above 0, the shreds arrive at all.
    pub datagrams: u64,
    /// Batches of shreds decoded: entry batches and block markers.
    pub batches: u64,
    /// pump.fun migrations found in them.
    pub migrations: u64,
    /// Datagrams dropped before anything of them was kept.
    pub dropped: UdpDropped,
    /// Times the shreds kept while their batches were incomplete went over
    /// their limit (4096 FEC sets, 128 MiB) and were all dropped.
    pub resets: u64,
    /// Migrations these shreds showed first that were not followed up,
    /// because eight were being followed already; Geyser still shows them.
    pub migrations_dropped: u64,
}

#[derive(Debug, Default)]
pub struct Timing {
    tracks: HashMap<Signature, Track>,
    slot_started: HashMap<u64, Instant>,
    shred_to_processed: Samples,
    shred_to_confirmed: Samples,
    udp_to_processed: Samples,
    udp_to_confirmed: Samples,
    processed_to_confirmed: Samples,
    udp_before_shreds: Samples,
    shreds_before_udp: Samples,
    shred_offset: Samples,
    udp_offset: Samples,
    processed_offset: Samples,
    detect_to_send: Samples,
    slots_late: Samples,
    buys: VecDeque<BuyTiming>,
    /// Shared with the UDP receiver, which counts without this lock.
    udp: Arc<UdpCounters>,
}

fn ms(from: Instant, to: Instant) -> u64 {
    to.saturating_duration_since(from).as_millis() as u64
}

impl Timing {
    /// A migration seen before it ran, in the Shreds stream or the UDP
    /// shreds. Seen twice from one source, it is timed once; seen from both,
    /// the later arrival says which was first and by how much. A Geyser
    /// sighting is `on_processed`. Returns whether this is the first time
    /// any source showed the migration before it ran: the caller buys from
    /// that sighting and not from the ones after it.
    pub fn on_sighting(&mut self, sig: Signature, slot: u64, now: Instant, via: Via) -> bool {
        if via == Via::Geyser {
            self.on_processed(sig, slot, now);
            return false;
        }
        let start = self.slot_started.get(&slot).copied();
        let track = self.tracks.entry(sig).or_insert_with(|| Track::new(slot, now));
        let first = track.shred.is_none() && track.udp.is_none();
        let (seen, other, offset) = match via {
            Via::Udp => (&mut track.udp, track.shred, &mut self.udp_offset),
            _ => (&mut track.shred, track.udp, &mut self.shred_offset),
        };
        if seen.is_some() {
            return false;
        }
        *seen = Some(now);
        if let Some(start) = start {
            offset.push(ms(start, now));
        }
        if let Some(other) = other {
            let (udp, shred) = if via == Via::Udp { (now, other) } else { (other, now) };
            if udp <= shred {
                self.udp_before_shreds.push(ms(udp, shred));
            } else {
                self.shreds_before_udp.push(ms(shred, udp));
            }
        }
        first
    }

    /// Whether a transaction is one being timed: the cheap check every
    /// Geyser transaction goes through.
    pub fn tracks(&self, sig: &Signature) -> bool {
        self.tracks.contains_key(sig)
    }

    /// A migration seen in Geyser at processed. Ones no shreds showed
    /// first are timed from here on.
    pub fn on_processed(&mut self, sig: Signature, slot: u64, now: Instant) {
        let track = self.tracks.entry(sig).or_insert_with(|| Track::new(slot, now));
        if track.processed.is_some() {
            return;
        }
        track.processed = Some(now);
        if let Some(shred) = track.shred {
            self.shred_to_processed.push(ms(shred, now));
        }
        if let Some(udp) = track.udp {
            self.udp_to_processed.push(ms(udp, now));
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
        let (shred_to_confirmed, udp_to_confirmed, processed_to_confirmed) =
            (&mut self.shred_to_confirmed, &mut self.udp_to_confirmed, &mut self.processed_to_confirmed);
        self.tracks.retain(|_, t| {
            if t.slot != slot {
                return true;
            }
            if let Some(shred) = t.shred {
                shred_to_confirmed.push(ms(shred, now));
            }
            if let Some(udp) = t.udp {
                udp_to_confirmed.push(ms(udp, now));
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

    /// A buy went out, made under `settings`.
    pub fn on_buy_sent(&mut self, pool: String, sighting: &Sighting, settings: Settings, now: Instant) {
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
            failed: false,
            settings,
        });
    }

    /// The buy of `pool` landed in `slot`; `failed` when it failed on
    /// chain there, which leaves it out of the `slots_late` summary.
    pub fn on_buy_landed(&mut self, pool: &str, slot: u64, failed: bool) {
        if let Some(buy) = self.buys.iter_mut().rev().find(|b| b.pool == pool && b.landed_slot.is_none()) {
            let late = slot.saturating_sub(buy.pool_slot);
            buy.landed_slot = Some(slot);
            buy.slots_late = Some(late);
            buy.failed = failed;
            if !failed {
                self.slots_late.push(late);
            }
        }
    }

    /// The UDP receiver's counters, to bump without this lock.
    pub fn udp_counters(&self) -> Arc<UdpCounters> {
        self.udp.clone()
    }

    /// The report, with `settings`, those in force now.
    pub fn report(&self, settings: Settings) -> TimingReport {
        TimingReport {
            shred_to_processed_ms: self.shred_to_processed.summary(),
            shred_to_confirmed_ms: self.shred_to_confirmed.summary(),
            udp_to_processed_ms: self.udp_to_processed.summary(),
            udp_to_confirmed_ms: self.udp_to_confirmed.summary(),
            processed_to_confirmed_ms: self.processed_to_confirmed.summary(),
            udp_before_shreds_ms: self.udp_before_shreds.summary(),
            shreds_before_udp_ms: self.shreds_before_udp.summary(),
            shred_offset_in_slot_ms: self.shred_offset.summary(),
            udp_offset_in_slot_ms: self.udp_offset.summary(),
            processed_offset_in_slot_ms: self.processed_offset.summary(),
            detect_to_send_ms: self.detect_to_send.summary(),
            slots_late: self.slots_late.summary(),
            buys: self.buys.iter().cloned().collect(),
            udp: self.udp.report(),
            settings,
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
        t.on_sighting(sig, 10, t0 + Duration::from_millis(120), Via::Shreds);
        assert!(t.tracks(&sig));
        t.on_processed(sig, 10, t0 + Duration::from_millis(170));
        // Seen twice at processed: timed once.
        t.on_processed(sig, 10, t0 + Duration::from_millis(900));
        t.on_slot_confirmed(10, t0 + Duration::from_millis(1_120));
        assert!(!t.tracks(&sig));
        let r = t.report(Settings::default());
        assert_eq!(r.shred_offset_in_slot_ms.p50, Some(120));
        assert_eq!(r.shred_to_processed_ms.p50, Some(50));
        assert_eq!(r.shred_to_processed_ms.count, 1);
        assert_eq!(r.processed_offset_in_slot_ms.count, 1);
        assert_eq!(r.shred_to_confirmed_ms.p50, Some(1_000));
        assert_eq!(r.processed_to_confirmed_ms.p50, Some(950));
        // Nothing came over UDP.
        assert_eq!(r.udp_to_processed_ms.count, 0);
        assert_eq!((r.udp_to_confirmed_ms.count, r.udp_offset_in_slot_ms.count), (0, 0));
        assert_eq!((r.udp_before_shreds_ms.count, r.shreds_before_udp_ms.count), (0, 0));
    }

    #[test]
    fn a_migration_seen_over_udp_first_is_timed_against_the_shreds_stream() {
        let mut t = Timing::default();
        let t0 = Instant::now();
        let sig = Signature::from([8; 64]);
        t.on_slot_started(20, t0);
        t.on_sighting(sig, 20, t0 + Duration::from_millis(100), Via::Udp);
        t.on_sighting(sig, 20, t0 + Duration::from_millis(130), Via::Shreds);
        // Seen again over UDP: timed once.
        t.on_sighting(sig, 20, t0 + Duration::from_millis(140), Via::Udp);
        t.on_processed(sig, 20, t0 + Duration::from_millis(170));
        t.on_slot_confirmed(20, t0 + Duration::from_millis(1_100));
        let r = t.report(Settings::default());
        assert_eq!(r.udp_offset_in_slot_ms.p50, Some(100));
        assert_eq!(r.shred_offset_in_slot_ms.p50, Some(130));
        assert_eq!((r.udp_before_shreds_ms.p50, r.udp_before_shreds_ms.count), (Some(30), 1));
        assert_eq!(r.shreds_before_udp_ms.count, 0);
        assert_eq!(r.udp_to_processed_ms.p50, Some(70));
        assert_eq!(r.shred_to_processed_ms.p50, Some(40));
        assert_eq!(r.udp_to_confirmed_ms.p50, Some(1_000));
        assert_eq!(r.shred_to_confirmed_ms.p50, Some(970));
    }

    #[test]
    fn a_migration_the_shreds_stream_shows_first_is_timed_the_other_way() {
        let mut t = Timing::default();
        let t0 = Instant::now();
        let sig = Signature::from([9; 64]);
        t.on_sighting(sig, 30, t0, Via::Shreds);
        t.on_sighting(sig, 30, t0 + Duration::from_millis(25), Via::Udp);
        let r = t.report(Settings::default());
        assert_eq!((r.shreds_before_udp_ms.p50, r.shreds_before_udp_ms.count), (Some(25), 1));
        assert_eq!(r.udp_before_shreds_ms.count, 0);
        // No slot start known, nothing processed: no offset and no other measure yet.
        assert_eq!((r.udp_offset_in_slot_ms.count, r.udp_to_processed_ms.count), (0, 0));
    }

    #[test]
    fn a_geyser_sighting_is_a_processed_one() {
        let mut t = Timing::default();
        let t0 = Instant::now();
        let sig = Signature::from([10; 64]);
        assert!(t.on_sighting(sig, 40, t0, Via::Udp));
        assert!(!t.on_sighting(sig, 40, t0 + Duration::from_millis(50), Via::Geyser));
        assert_eq!(t.report(Settings::default()).udp_to_processed_ms.p50, Some(50));
    }

    #[test]
    fn only_the_first_sighting_of_a_migration_is_the_one_to_buy_from() {
        let mut t = Timing::default();
        let t0 = Instant::now();
        // UDP first, then the Shreds stream, then UDP again.
        let sig = Signature::from([11; 64]);
        assert!(t.on_sighting(sig, 50, t0, Via::Udp));
        assert!(!t.on_sighting(sig, 50, t0 + Duration::from_millis(20), Via::Shreds));
        assert!(!t.on_sighting(sig, 50, t0 + Duration::from_millis(30), Via::Udp));
        // The Shreds stream first, then UDP, then the stream again.
        let sig = Signature::from([12; 64]);
        assert!(t.on_sighting(sig, 50, t0, Via::Shreds));
        assert!(!t.on_sighting(sig, 50, t0 + Duration::from_millis(20), Via::Udp));
        assert!(!t.on_sighting(sig, 50, t0 + Duration::from_millis(30), Via::Shreds));
        // One Geyser saw first is still bought from the first sighting before it ran;
        // `reserve_buy` keeps the pool from being bought twice, as before.
        let sig = Signature::from([13; 64]);
        t.on_processed(sig, 50, t0);
        assert!(t.on_sighting(sig, 50, t0 + Duration::from_millis(5), Via::Shreds));
        assert_eq!(t.report(Settings::default()).shreds_before_udp_ms.count, 1);
        assert_eq!(t.report(Settings::default()).udp_before_shreds_ms.count, 1);
    }

    #[test]
    fn the_udp_counters_are_in_the_report() {
        let t = Timing::default();
        let counters = t.udp_counters();
        assert_eq!(t.report(Settings::default()).udp, UdpReport::default());
        counters.bound("0.0.0.0:10001".parse().unwrap());
        counters.datagram();
        counters.datagram();
        counters.batch();
        counters.migration();
        let udp = t.report(Settings::default()).udp;
        assert_eq!(udp.bound.as_deref(), Some("0.0.0.0:10001"));
        assert_eq!((udp.datagrams, udp.batches, udp.migrations), (2, 1, 1));
        // What was dropped, by why, and what was let go.
        for why in [Dropped::Malformed, Dropped::OutsideWindow, Dropped::OutsideWindow, Dropped::BadSignature] {
            counters.dropped(why);
        }
        counters.dropped(Dropped::NoLeader);
        counters.reset();
        counters.migration_dropped();
        let udp = t.report(Settings::default()).udp;
        assert_eq!(udp.dropped, UdpDropped { malformed: 1, outside_window: 2, no_leader: 1, bad_signature: 1 });
        assert_eq!((udp.resets, udp.migrations_dropped), (1, 1));
        let json = serde_json::to_value(&udp).unwrap();
        assert_eq!(json["dropped"]["outside_window"], 2);
        assert_eq!(json["migrations_dropped"], 1);
        assert_eq!(serde_json::to_value(Via::Udp).unwrap(), "udp");
    }

    #[test]
    fn a_buy_is_timed_from_sight_to_send_and_counted_in_slots_late() {
        let mut t = Timing::default();
        let t0 = Instant::now();
        let seen = Sighting { slot: 100, seen: t0, via: Via::Shreds };
        t.on_buy_sent("P".into(), &seen, Settings::default(), t0 + Duration::from_millis(30));
        t.on_buy_landed("P", 100, false);
        let r = t.report(Settings::default());
        assert_eq!(r.detect_to_send_ms.p50, Some(30));
        assert_eq!(r.slots_late.p50, Some(0));
        assert_eq!(r.buys[0].slots_late, Some(0));
        assert!(!r.buys[0].failed);
    }

    #[test]
    fn a_buy_that_landed_and_failed_says_so_and_is_not_counted_in_slots_late() {
        // A buy from the stream can land in its pool's slot before the pool
        // exists, and fail there: it paid its fee and bought nothing.
        let mut t = Timing::default();
        let t0 = Instant::now();
        let seen = Sighting { slot: 100, seen: t0, via: Via::Shreds };
        t.on_buy_sent("P".into(), &seen, Settings::default(), t0 + Duration::from_millis(30));
        t.on_buy_landed("P", 100, true);
        t.on_buy_sent("Q".into(), &seen, Settings::default(), t0 + Duration::from_millis(40));
        t.on_buy_landed("Q", 102, false);
        let r = t.report(Settings::default());
        assert!(r.buys[0].failed && !r.buys[1].failed);
        assert_eq!(r.buys[0].slots_late, Some(0));
        assert_eq!((r.slots_late.count, r.slots_late.p50), (1, Some(2)));
        let json = serde_json::to_value(&r.buys[0]).unwrap();
        assert_eq!(json["failed"], true);
    }

    #[test]
    fn a_buy_is_stamped_with_the_settings_it_was_made_under() {
        let mut t = Timing::default();
        let t0 = Instant::now();
        let seen = Sighting { slot: 100, seen: t0, via: Via::Shreds };
        let before = Settings { rev: 0, buy_on_shreds: true, priority_fee_micro_lamports: 10_000, compute_unit_limit: 200_000 };
        let now = Settings { rev: 1, priority_fee_micro_lamports: 20_000, ..before };
        t.on_buy_sent("P".into(), &seen, before, t0);
        t.on_buy_sent("Q".into(), &seen, now, t0);
        let r = t.report(now);
        assert_eq!((r.buys[0].settings, r.buys[1].settings, r.settings), (before, now, now));
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["buys"][0]["settings"]["rev"], 0);
        assert_eq!(json["buys"][1]["settings"]["priority_fee_micro_lamports"], 20_000);
        assert_eq!(json["settings"]["rev"], 1);
    }

    /// `GET /api/timing` has the shape of `timing_example.json`, field for
    /// field, so a field renamed here and not in the example fails this
    /// test.
    #[test]
    fn the_report_has_the_shape_of_its_example() {
        let sum = |count, p50, p90, min, max| Summary { count, p50, p90, min, max };
        let measured = |count, p50, p90, min, max| sum(count, Some(p50), Some(p90), Some(min), Some(max));
        let settings = |rev, priority_fee_micro_lamports| Settings {
            rev,
            buy_on_shreds: true,
            priority_fee_micro_lamports,
            compute_unit_limit: 200_000,
        };
        let buy = |pool: &str, via, pool_slot, detect_to_send_ms, landed_slot: Option<u64>, failed, settings| BuyTiming {
            pool: pool.to_owned(),
            via,
            pool_slot,
            detect_to_send_ms,
            landed_slot,
            slots_late: landed_slot.map(|s| s - pool_slot),
            failed,
            settings,
        };
        let report = TimingReport {
            shred_to_processed_ms: measured(42, 18, 44, 3, 97),
            shred_to_confirmed_ms: measured(42, 960, 1310, 610, 2200),
            udp_to_processed_ms: measured(40, 31, 60, 9, 120),
            udp_to_confirmed_ms: measured(40, 975, 1330, 620, 2210),
            processed_to_confirmed_ms: measured(45, 940, 1280, 590, 2150),
            udp_before_shreds_ms: measured(38, 12, 25, 0, 61),
            shreds_before_udp_ms: sum(0, None, None, None, None),
            shred_offset_in_slot_ms: measured(42, 210, 350, 20, 398),
            udp_offset_in_slot_ms: measured(40, 198, 340, 12, 390),
            processed_offset_in_slot_ms: measured(45, 231, 371, 40, 420),
            detect_to_send_ms: measured(4, 41, 58, 29, 58),
            slots_late: measured(2, 1, 1, 0, 1),
            buys: vec![
                buy("PoolA", Via::Udp, 301, 37, Some(301), false, settings(1, 10_000)),
                buy("PoolB", Via::Shreds, 310, 41, Some(311), false, settings(1, 10_000)),
                buy("PoolC", Via::Geyser, 322, 58, None, false, settings(1, 10_000)),
                buy("PoolD", Via::Shreds, 330, 29, Some(330), true, settings(2, 20_000)),
            ],
            udp: UdpReport {
                bound: Some("0.0.0.0:10001".to_owned()),
                datagrams: 918_234,
                batches: 40_112,
                migrations: 40,
                dropped: UdpDropped { malformed: 3, outside_window: 12, no_leader: 0, bad_signature: 1 },
                resets: 0,
                migrations_dropped: 0,
            },
            settings: settings(2, 20_000),
        };
        let example: serde_json::Value = serde_json::from_str(include_str!("timing_example.json")).unwrap();
        assert_eq!(serde_json::to_value(&report).unwrap(), example);
    }

    #[test]
    fn what_a_dead_slot_held_is_dropped() {
        let mut t = Timing::default();
        let sig = Signature::from([1; 64]);
        t.on_sighting(sig, 5, Instant::now(), Via::Udp);
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
