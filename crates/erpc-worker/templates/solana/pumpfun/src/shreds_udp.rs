//! Raw shreds over UDP (`SHREDS_UDP_BIND`): ERPC UDP Forwarding sends the
//! leader's shreds, as a node of ERPC's in one region receives them, to one
//! public address and port of this server, with nothing in between: no
//! stream to subscribe to, and no node that has to run them first. Each
//! datagram carries one shred. The SDK keeps the shreds of a slot by FEC
//! set and hands a batch over once its data shreds are all here; the coding
//! shreds come in with them, but this SDK recovers nothing from them, so a
//! batch with a shred lost on the way is left out (the Shreds stream and
//! Geyser still see what it carried). Each batch is deshredded into
//! entries, as the Shreds stream sends them, and every pump.fun migration
//! in them goes down that stream's path (`shreds::on_migration`), seen
//! `Via::Udp` and timed against it.
//!
//! A datagram is whatever reached the port: UDP has no sender to trust, and
//! the firewall's list of ERPC's addresses stops only those who cannot
//! forge one. So nothing of a datagram is kept until it has passed, in this
//! order:
//!
//! 1. It is no longer than a packet, and names a slot.
//! 2. Its slot is near the last one Geyser reported (`SLOTS_BEHIND` before
//!    it to `SLOTS_AHEAD` after). Until Geyser reports one, nothing passes.
//! 3. It parses as a shred.
//! 4. The leader of its slot, as the RPC's leader schedule names it, signed
//!    it. The signature is over the merkle root of the shred's FEC set,
//!    which the shred's own bytes and proof lead to, so it covers the
//!    slot, the index, the shred version and the data. A slot whose leader
//!    is not known yet passes nothing.
//!
//! What passes is the leader's own, and is handed to the SDK. What the SDK
//! then holds (batches waiting for their last shred) is counted here, and
//! dropped whole when it goes over `KEPT`: a leader can still sign more
//! shreds than a slot should have.

use crate::shreds;
use crate::state::AppState;
use crate::timing::{Dropped, Sighting, UdpCounters, Via};
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use log::{info, warn};
use solana_stream_sdk::shred::{layout, Shred};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_stream_sdk::shreds_udp::{
    decode_udp_datagram, deshred_shreds_to_entries, insert_shred, DeshredPolicy, FecKey, ShredInsertOutcome,
    ShredReadyBatch, ShredsUdpConfig, ShredsUdpState, UdpDatagram, UdpShredReceiver,
};
use solana_stream_sdk::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// A shred fills one packet at most (1228 bytes, 1232 with a repair nonce).
const MAX_DATAGRAM: usize = 1232;
/// How far before the last slot Geyser reported a shred may be: Geyser
/// names a slot once its first shred is in, so the shreds of the slots just
/// before it are still on their way.
const SLOTS_BEHIND: u64 = 32;
/// How far after it: about 25 seconds, for a Geyser stream that lags. The
/// two together stay under the 128 slots the SDK keeps behind the newest
/// shred it took in, so no shred that passes can make it drop a batch that
/// is still inside the window.
const SLOTS_AHEAD: u64 = 64;
const _: () = assert!(SLOTS_BEHIND + SLOTS_AHEAD < 128);
/// The FEC sets and bytes the SDK may hold at once. A set is 32 data and 32
/// coding shreds, about 116 KB as counted here (a data shred twice), and a
/// set that lost a shred is held for 128 slots: with one set in fifty
/// incomplete that is some hundred sets. These limits are far above that
/// and far below what the server has; over either, all of it is dropped and
/// counted.
const KEPT: Limits = Limits { sets: 4_096, bytes: 128 * 1024 * 1024 };
/// The FEC sets whose signature is remembered: every one in the window, at
/// some hundred a slot, with room to spare.
const SIGNED_SETS: usize = 65_536;
/// The slots of leader schedule read at once, and how many must be left
/// past the window before more are read: one request every nine minutes.
const LEADERS_AT_ONCE: u64 = 2_000;
const LEADERS_LEFT: u64 = 500;
/// How often the schedule is looked at.
const LEADERS_LOOK: Duration = Duration::from_secs(1);

/// Receives on `bind` for as long as the bot runs. A socket that cannot be
/// bound, or fails, is bound again after a pause, which grows while nothing
/// comes in. `geyser_slot` is the last slot the Geyser stream reported.
pub async fn run(
    bind: SocketAddr,
    state: Arc<RwLock<AppState>>,
    geyser_slot: Arc<AtomicU64>,
    rpc: Arc<RpcClient>,
    send_rpc: Arc<RpcClient>,
) {
    let counters = state.read().await.timing.lock().expect("timing lock").udp_counters();
    let leaders = Arc::new(Leaders::default());
    tokio::spawn(keep_leaders(leaders.clone(), geyser_slot.clone(), rpc.clone()));
    let mut backoff = ExponentialBackoff { max_elapsed_time: None, ..ExponentialBackoff::default() };
    loop {
        let before = counters.datagrams();
        let decoder = Decoder::new(bind, geyser_slot.clone(), leaders.clone(), counters.clone());
        if let Err(e) = receive(bind, decoder, &state, &rpc, &send_rpc).await {
            warn!("UDP shreds on {bind} failed: {e:#}");
        }
        if counters.datagrams() > before {
            backoff.reset();
        }
        tokio::time::sleep(backoff.next_backoff().unwrap_or(Duration::from_secs(1))).await;
    }
}

/// One bound socket: every datagram goes through the decoder, and every
/// migration in a decoded batch down the Shreds path, until the socket fails.
async fn receive(
    bind: SocketAddr,
    mut decoder: Decoder,
    state: &Arc<RwLock<AppState>>,
    rpc: &Arc<RpcClient>,
    send_rpc: &Arc<RpcClient>,
) -> anyhow::Result<()> {
    let mut receiver = UdpShredReceiver::bind(bind.to_string(), None).await?;
    let bound = receiver.local_addr()?;
    let counters = decoder.counters.clone();
    counters.bound(bound);
    info!("UDP shreds: receiving on {bound}");
    loop {
        let datagram = receiver.recv_raw().await?;
        counters.datagram();
        let Some((slot, entries)) = decoder.take_in(&datagram).await else { continue };
        counters.batch();
        for tx in entries.iter().flat_map(|e| &e.transactions) {
            if let Some(found) = shreds::migration_in(tx) {
                counters.migration();
                let sighting = Sighting { slot, seen: datagram.received_at, via: Via::Udp };
                shreds::on_migration(found, tx, sighting, state, rpc, send_rpc).await;
            }
        }
    }
}

/// The slots a shred may be for, around the last slot Geyser reported;
/// none before it reports one.
fn window(geyser_slot: u64) -> Option<RangeInclusive<u64>> {
    (geyser_slot != 0).then(|| geyser_slot.saturating_sub(SLOTS_BEHIND)..=geyser_slot.saturating_add(SLOTS_AHEAD))
}

/// The leader of each slot around the present, as the RPC's leader schedule
/// names them: the key the shreds of a slot must be signed by.
#[derive(Default)]
struct Leaders(std::sync::RwLock<Schedule>);

/// Leaders by slot, from `first` on.
#[derive(Default)]
struct Schedule {
    first: u64,
    keys: Vec<[u8; 32]>,
}

impl Leaders {
    fn of(&self, slot: u64) -> Option<[u8; 32]> {
        let schedule = self.0.read().expect("leaders lock");
        let at = usize::try_from(slot.checked_sub(schedule.first)?).ok()?;
        schedule.keys.get(at).copied()
    }

    /// Whether the schedule reaches from the oldest slot a shred may be for
    /// now to well past the newest.
    fn covers(&self, geyser_slot: u64) -> bool {
        let schedule = self.0.read().expect("leaders lock");
        let end = schedule.first.saturating_add(schedule.keys.len() as u64);
        schedule.first <= geyser_slot.saturating_sub(SLOTS_BEHIND)
            && end > geyser_slot.saturating_add(SLOTS_AHEAD + LEADERS_LEFT)
    }

    fn set(&self, first: u64, keys: Vec<[u8; 32]>) {
        *self.0.write().expect("leaders lock") = Schedule { first, keys };
    }
}

/// Reads the leaders of the slots from the window's start on.
async fn read_leaders(rpc: &RpcClient, leaders: &Leaders, geyser_slot: u64) -> anyhow::Result<()> {
    let first = geyser_slot.saturating_sub(SLOTS_BEHIND);
    let keys = rpc.get_slot_leaders(first, LEADERS_AT_ONCE).await?;
    anyhow::ensure!(!keys.is_empty(), "the RPC names no leader from slot {first} on");
    info!("UDP shreds: the leaders of {} slots from {first} on are known", keys.len());
    leaders.set(first, keys.iter().map(|k| k.to_bytes()).collect());
    Ok(())
}

/// Keeps the leader schedule around the slot Geyser is at, for as long as
/// the bot runs. While it cannot be read no shred of the slots it lacks
/// passes, which is said, with a pause that grows.
async fn keep_leaders(leaders: Arc<Leaders>, geyser_slot: Arc<AtomicU64>, rpc: Arc<RpcClient>) {
    let mut backoff = ExponentialBackoff { max_elapsed_time: None, ..ExponentialBackoff::default() };
    loop {
        let slot = geyser_slot.load(Ordering::Relaxed);
        let mut pause = LEADERS_LOOK;
        if slot != 0 && !leaders.covers(slot) {
            if let Err(e) = read_leaders(&rpc, &leaders, slot).await {
                warn!("UDP shreds: the leader schedule could not be read ({e:#}); shreds of slots it lacks are dropped");
            }
            // Read, and still short (an RPC that names fewer leaders than
            // asked for): tried again later, not every second.
            if leaders.covers(slot) {
                backoff.reset();
            } else {
                pause = backoff.next_backoff().unwrap_or(LEADERS_LOOK);
            }
        }
        tokio::time::sleep(pause).await;
    }
}

/// The FEC sets a leader's signature was checked for. Every shred of a set
/// carries the same signature, over the same merkle root, so one check
/// serves the set: a later shred of it passes when its own bytes and proof
/// lead to that root under that signature.
#[derive(Default)]
struct Signed(BTreeMap<(u64, u32), ([u8; 32], solana_signature::Signature)>);

impl Signed {
    /// Whether `leader` signed `shred`. `oldest` is the window's first
    /// slot: what was remembered of slots before it is let go.
    fn by(&mut self, shred: &Shred, leader: [u8; 32], oldest: u64) -> bool {
        let Ok(root) = shred.merkle_root() else { return false };
        let (set, root) = ((shred.slot(), shred.fec_set_index()), root.to_bytes());
        if self.0.get(&set).is_some_and(|(r, s)| *r == root && s == shred.signature()) {
            return true;
        }
        if !shred.verify(&leader.into()) {
            return false;
        }
        while self.0.first_key_value().is_some_and(|((slot, _), _)| *slot < oldest) {
            self.0.pop_first();
        }
        if self.0.len() >= SIGNED_SETS {
            self.0.clear();
        }
        self.0.insert(set, (root, *shred.signature()));
        true
    }
}

/// The most the SDK may hold.
#[derive(Clone, Copy)]
struct Limits {
    sets: usize,
    bytes: usize,
}

/// What the SDK holds of batches not complete yet, as counted here: its
/// buffers are its own, and it keeps no count of them. Counted when a shred
/// goes in and when a batch is done with, and let go as the SDK lets go:
/// what is more than 128 slots behind the shred it takes in. The SDK keeps
/// one shred of each index, data or coding, in a FEC set, so a shred seen
/// again is not counted again: a replayed genuine shred, which the SDK
/// takes and drops, cannot push the count over its limit and have real
/// batches dropped with it.
#[derive(Default)]
struct Kept {
    by_slot: BTreeMap<u64, HashMap<(u16, u32), KeptSet>>,
    sets: usize,
    bytes: usize,
}

/// One FEC set's shreds as [`Kept`] counts them: their bytes, and which
/// (index, data or not) are in.
#[derive(Default)]
struct KeptSet {
    bytes: usize,
    shreds: HashSet<(u32, bool)>,
}

impl Kept {
    /// Counts `bytes` for `shred`, its (index, data or not), in the FEC set
    /// `key`; nothing when the set has it already.
    fn add(&mut self, key: FecKey, shred: (u32, bool), bytes: usize) {
        while let Some(entry) = self.by_slot.first_entry() {
            if entry.key().saturating_add(128) >= key.slot {
                break;
            }
            let gone = entry.remove();
            self.sets -= gone.len();
            self.bytes -= gone.values().map(|set| set.bytes).sum::<usize>();
        }
        let set = self.by_slot.entry(key.slot).or_default().entry((key.version, key.fec_set)).or_insert_with(|| {
            self.sets += 1;
            KeptSet::default()
        });
        if set.shreds.insert(shred) {
            set.bytes += bytes;
            self.bytes += bytes;
        }
    }

    fn done(&mut self, key: &FecKey) {
        let Some(sets) = self.by_slot.get_mut(&key.slot) else { return };
        if let Some(set) = sets.remove(&(key.version, key.fec_set)) {
            self.sets -= 1;
            self.bytes -= set.bytes;
        }
        if sets.is_empty() {
            self.by_slot.remove(&key.slot);
        }
    }

    fn over(&self, limits: Limits) -> bool {
        self.sets > limits.sets || self.bytes > limits.bytes
    }
}

/// The SDK's receiver, set to decode and nothing more (none of its logging,
/// and no latency monitor, which would poll an RPC for block times), behind
/// the checks a datagram has to pass first.
struct Decoder {
    cfg: ShredsUdpConfig,
    sdk: ShredsUdpState,
    policy: DeshredPolicy,
    geyser_slot: Arc<AtomicU64>,
    leaders: Arc<Leaders>,
    signed: Signed,
    kept: Kept,
    limits: Limits,
    counters: Arc<UdpCounters>,
}

impl Decoder {
    fn new(bind: SocketAddr, geyser_slot: Arc<AtomicU64>, leaders: Arc<Leaders>, counters: Arc<UdpCounters>) -> Self {
        let cfg = ShredsUdpConfig {
            bind_addr: bind.to_string(),
            log_raw: false,
            log_shreds: false,
            log_entries: false,
            log_deshred_attempts: false,
            log_deshred_errors: false,
            log_watch_hits: false,
            log_deferred: false,
            enable_latency_monitor: false,
            // The SDK's own window is set to the same slots as `window`,
            // from the slot Geyser is at, each time a shred is handed over.
            slot_window_max_future: SLOTS_BEHIND + SLOTS_AHEAD,
            ..ShredsUdpConfig::defaults()
        };
        let sdk = ShredsUdpState::new(&cfg);
        Decoder {
            cfg,
            sdk,
            policy: DeshredPolicy { require_code_match: false },
            geyser_slot,
            leaders,
            signed: Signed::default(),
            kept: Kept::default(),
            limits: KEPT,
            counters,
        }
    }

    /// Takes one datagram in: the entries of the batch it completed, with
    /// their slot, when it did. A datagram that does not pass is counted by
    /// why and leaves nothing behind. It is not logged: whoever can send
    /// one can send a million, and the SDK's own warnings about a datagram
    /// of the wrong size are never reached, since one is dropped here first.
    async fn take_in(&mut self, datagram: &UdpDatagram) -> Option<(u64, Vec<Entry>)> {
        let shred = match self.passes(&datagram.payload) {
            Ok(shred) => shred,
            Err(why) => {
                self.counters.dropped(why);
                return None;
            }
        };
        // The leader's own: the SDK's checks of a shred's shape are next,
        // and a shred they refuse is the leader's mistake, not a flood.
        let Some(decoded) = decode_udp_datagram(datagram, &self.sdk, &self.cfg).await else {
            self.counters.dropped(Dropped::Malformed);
            return None;
        };
        // A data shred is kept by FEC set and by slot. The SDK shares one
        // buffer between the two, so counting it twice over-counts, which
        // errs on the side of dropping sooner.
        let bytes = decoded.canonical_payload_len() * if shred.is_data() { 2 } else { 1 };
        match insert_shred(decoded, datagram, &self.sdk, &self.cfg, &self.policy).await {
            ShredInsertOutcome::Ready(ready) => self.finish(ready).await,
            ShredInsertOutcome::Buffered { key, .. } | ShredInsertOutcome::Deferred { key, .. } => {
                self.kept.add(key, (shred.index(), shred.is_data()), bytes);
                if self.kept.over(self.limits) {
                    self.sdk = ShredsUdpState::new(&self.cfg);
                    self.kept = Kept::default();
                    self.counters.reset();
                }
                None
            }
            ShredInsertOutcome::Skipped => None,
        }
    }

    /// The shred in `payload`, when it passes every check the module's
    /// first lines list; else why it does not. The cheap checks come first:
    /// a datagram outside the window costs a comparison, and only one
    /// inside it costs a signature check.
    fn passes(&mut self, payload: &[u8]) -> Result<Shred, Dropped> {
        let slot = (payload.len() <= MAX_DATAGRAM).then(|| layout::get_slot(payload)).flatten();
        let slot = slot.ok_or(Dropped::Malformed)?;
        let window = window(self.geyser_slot.load(Ordering::Relaxed)).filter(|w| w.contains(&slot));
        let window = window.ok_or(Dropped::OutsideWindow)?;
        let shred = Shred::new_from_serialized_shred(payload.to_vec()).map_err(|_| Dropped::Malformed)?;
        let leader = self.leaders.of(slot).ok_or(Dropped::NoLeader)?;
        if !self.signed.by(&shred, leader, *window.start()) {
            return Err(Dropped::BadSignature);
        }
        self.cfg.slot_window_root = Some(*window.start());
        Ok(shred)
    }

    /// A batch whose data shreds are all here: its entries. The batch's FEC
    /// sets are then done with, so a shred of theirs seen again is skipped;
    /// a batch that does not deshred is dropped, as the SDK drops one.
    async fn finish(&mut self, ready: ShredReadyBatch) -> Option<(u64, Vec<Entry>)> {
        let entries = deshred_shreds_to_entries(&ready.shreds);
        let fec_sets: BTreeSet<u32> = ready.shreds.iter().map(|s| s.fec_set_index()).collect();
        for fec_set in fec_sets {
            let key = FecKey { slot: ready.key.slot, version: ready.key.version, fec_set };
            self.sdk.remove_batch(&key).await;
            self.kept.done(&key);
            match &entries {
                Ok(_) => self.sdk.mark_completed(key).await,
                Err(_) => self.sdk.mark_suppressed(key).await,
            }
        }
        match entries {
            Ok(entries) => Some((ready.key.slot, entries)),
            Err(e) => {
                warn!("UDP shreds: a batch of slot {} did not deshred: {e}", ready.key.slot);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::hash::hashv;
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signer::keypair::Keypair;
    use solana_sdk::signer::Signer;
    use std::time::Instant;

    /// The slot Geyser is at in these tests, and the one the shreds are for.
    const NOW: u64 = 1_000;

    /// The domain prefixes of the Merkle tree over a FEC set, as Agave's
    /// `merkle_tree.rs` has them; the SDK reads the tree with the same
    /// bytes and does not export them.
    const MERKLE_LEAF: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
    const MERKLE_NODE: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

    /// Entries holding a migration, shredded for `slot` into one FEC set of
    /// 32 data and 32 coding shreds, the layout the SDK reads Agave's in,
    /// and signed by `leader`: the data shreds from shred `index` on (the
    /// last of them ends the slot), and the entries that went in. The
    /// coding shreds are not made: made-up leaves stand for them in the
    /// tree, and they stay out, as they may on the way. Each data shred is
    /// read back with the SDK's own decoder, which is tested against
    /// Agave's: one it refuses fails the test that made it.
    fn shredded(leader: &Keypair, slot: u64, index: u32) -> (Vec<Shred>, Vec<Entry>) {
        use solana_stream_sdk::shred::{
            ShredVariant, CODING_SHREDS_PER_FEC_BLOCK, DATA_SHREDS_PER_FEC_BLOCK, DATA_SHRED_PAYLOAD_SIZE,
            FLAG_LAST_SHRED_IN_SLOT, PROOF_ENTRIES_FOR_32_32_BATCH, SIZE_OF_DATA_SHRED_HEADERS,
            SIZE_OF_MERKLE_PROOF_ENTRY, SIZE_OF_MERKLE_ROOT, SIZE_OF_SIGNATURE,
        };
        const ENTRY: usize = SIZE_OF_MERKLE_PROOF_ENTRY;
        let bytes = shreds::tests::entry_with_a_migration(Pubkey::new_from_array([42; 32]));
        let entries = solana_stream_sdk::decode_entries(&bytes).unwrap();
        let proof_size = PROOF_ENTRIES_FOR_32_32_BATCH;
        // A data shred: headers, entry bytes, the chained merkle root (left
        // zero: no batch came before), and the proof.
        let proof_offset = DATA_SHRED_PAYLOAD_SIZE - usize::from(proof_size) * ENTRY;
        let capacity = proof_offset - SIZE_OF_MERKLE_ROOT - SIZE_OF_DATA_SHRED_HEADERS;
        let chunks: Vec<&[u8]> = bytes.chunks(capacity).collect();
        assert!(chunks.len() <= DATA_SHREDS_PER_FEC_BLOCK, "the entries fit one FEC set");
        let mut payloads: Vec<Vec<u8>> = (0..DATA_SHREDS_PER_FEC_BLOCK)
            .map(|i| {
                let data = chunks.get(i).copied().unwrap_or_default();
                let size = u16::try_from(SIZE_OF_DATA_SHRED_HEADERS + data.len()).unwrap();
                let last = i + 1 == DATA_SHREDS_PER_FEC_BLOCK;
                let mut p = vec![0u8; DATA_SHRED_PAYLOAD_SIZE];
                p[64] = u8::from(ShredVariant::MerkleData { proof_size, resigned: false });
                p[65..73].copy_from_slice(&slot.to_le_bytes());
                p[73..77].copy_from_slice(&(index + u32::try_from(i).unwrap()).to_le_bytes());
                p[77..79].copy_from_slice(&1u16.to_le_bytes()); // the shred version
                p[79..83].copy_from_slice(&index.to_le_bytes()); // the FEC set's first shred
                p[83..85].copy_from_slice(&1u16.to_le_bytes()); // the parent: the slot before
                p[85] = if last { FLAG_LAST_SHRED_IN_SLOT } else { 0 };
                p[86..88].copy_from_slice(&size.to_le_bytes());
                p[SIZE_OF_DATA_SHRED_HEADERS..usize::from(size)].copy_from_slice(data);
                p
            })
            .collect();
        // The tree: a leaf a shred, over its bytes from the signature to the
        // proof, data shreds first; a node over the first 20 bytes of each
        // of two children.
        let coding = (0..CODING_SHREDS_PER_FEC_BLOCK).map(|i| hashv(&[MERKLE_LEAF, &i.to_le_bytes()]));
        let mut levels = vec![payloads
            .iter()
            .map(|p| hashv(&[MERKLE_LEAF, &p[SIZE_OF_SIGNATURE..proof_offset]]))
            .chain(coding)
            .map(|hash| hash.to_bytes())
            .collect::<Vec<[u8; 32]>>()];
        while levels.last().unwrap().len() > 1 {
            let level = levels.last().unwrap().chunks(2).map(|two| hashv(&[MERKLE_NODE, &two[0][..ENTRY], &two[1][..ENTRY]]));
            levels.push(level.map(|hash| hash.to_bytes()).collect());
        }
        assert_eq!(levels.len() - 1, usize::from(proof_size));
        let signature = leader.sign_message(&levels.last().unwrap()[0]);
        for (i, p) in payloads.iter_mut().enumerate() {
            p[..SIZE_OF_SIGNATURE].copy_from_slice(signature.as_ref());
            for (depth, level) in levels[..levels.len() - 1].iter().enumerate() {
                let at = proof_offset + depth * ENTRY;
                p[at..at + ENTRY].copy_from_slice(&level[(i >> depth) ^ 1][..ENTRY]);
            }
        }
        let shreds = payloads.into_iter().map(|p| Shred::new_from_serialized_shred(p).expect("the SDK reads it")).collect();
        (shreds, entries)
    }

    /// A decoder with Geyser at `NOW` and `leader` the leader of every slot
    /// from the window's start on, and its counters.
    fn decoder(leader: &Keypair) -> (Decoder, Arc<UdpCounters>) {
        let leaders = Arc::new(Leaders::default());
        leaders.set(NOW - SLOTS_BEHIND, vec![leader.pubkey().to_bytes(); 1_000]);
        let counters = Arc::new(UdpCounters::default());
        let bind = "127.0.0.1:0".parse().unwrap();
        (Decoder::new(bind, Arc::new(AtomicU64::new(NOW)), leaders, counters.clone()), counters)
    }

    fn datagram(payload: Vec<u8>) -> UdpDatagram {
        UdpDatagram { payload, received_at: Instant::now(), from: "203.0.113.9:10001".parse().unwrap() }
    }

    fn sent(shred: &Shred) -> UdpDatagram {
        datagram(shred.payload().as_ref().to_vec())
    }

    /// `shred`'s bytes with another slot and shred version in its header,
    /// and nothing else changed.
    fn forged(shred: &Shred, slot: u64, version: u16) -> UdpDatagram {
        let mut payload = shred.payload().as_ref().to_vec();
        payload[65..73].copy_from_slice(&slot.to_le_bytes());
        payload[77..79].copy_from_slice(&version.to_le_bytes());
        datagram(payload)
    }

    /// What this process holds in memory now, where the system says.
    fn resident_bytes() -> Option<usize> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        Some(statm.split_whitespace().nth(1)?.parse::<usize>().ok()? * 4096)
    }

    /// The path short of the socket: entries holding a migration, shredded
    /// and signed as a leader's are, one data shred per datagram, decoded,
    /// and the migration found.
    #[tokio::test]
    async fn a_migration_in_the_datagrams_is_found() {
        let leader = Keypair::new();
        let (shreds, entries) = shredded(&leader, NOW, 0);
        assert!(!shreds.is_empty());
        let (mut decoder, counters) = decoder(&leader);
        let mut decoded = Vec::new();
        for shred in &shreds {
            decoded.extend(decoder.take_in(&sent(shred)).await);
        }
        // One batch, in the shredder's slot, holding the entries as they went in.
        assert_eq!(decoded.len(), 1);
        let (slot, got) = &decoded[0];
        assert_eq!(*slot, NOW);
        assert_eq!(got, &entries);
        let found = got.iter().flat_map(|e| &e.transactions).filter(|tx| shreds::migration_in(tx).is_some()).count();
        assert_eq!(found, 1);
        // The batch is done with: a shred of it seen again yields nothing,
        // and nothing of it is kept.
        assert!(decoder.take_in(&sent(&shreds[0])).await.is_none());
        assert_eq!((decoder.kept.sets, decoder.kept.bytes), (0, 0));
        assert_eq!(counters.report().dropped, Default::default());
    }

    /// Tens of thousands of datagrams that differ from a real shred only in
    /// slot and shred version, all within the 128 slots the SDK keeps at
    /// once. Before, each was kept as a batch of its own: 80,000 of them
    /// held some 300 MB and took most of a minute to take in. Most are for
    /// slots just past the window, which costs a comparison each; some
    /// hundreds are for slots inside it, which costs a signature check each.
    #[tokio::test]
    async fn forged_datagrams_are_dropped_and_leave_nothing_behind() {
        let leader = Keypair::new();
        let (shreds, _) = shredded(&leader, NOW, 0);
        let (mut decoder, counters) = decoder(&leader);
        let before = resident_bytes();
        for i in 0..78_000u64 {
            let slot = NOW + SLOTS_AHEAD + 1 + i % 60;
            assert!(decoder.take_in(&forged(&shreds[0], slot, (i / 60) as u16)).await.is_none());
        }
        for i in 0..640u64 {
            let slot = NOW + 1 + i % SLOTS_AHEAD;
            assert!(decoder.take_in(&forged(&shreds[0], slot, (i / SLOTS_AHEAD) as u16)).await.is_none());
        }
        // Nothing is kept, here or by the SDK, which was handed nothing.
        assert_eq!((decoder.kept.sets, decoder.kept.bytes), (0, 0));
        assert!(decoder.signed.0.is_empty());
        let dropped = counters.report().dropped;
        // The signature does not cover the header the forged ones came with.
        assert_eq!((dropped.outside_window, dropped.bad_signature), (78_000, 640));
        assert_eq!((dropped.malformed, dropped.no_leader), (0, 0));
        if let (Some(before), Some(after)) = (before, resident_bytes()) {
            let grew = after.saturating_sub(before) / (1024 * 1024);
            assert!(grew < 64, "the process grew by {grew} MiB");
        }
        // The real shreds still decode after it.
        let mut decoded = Vec::new();
        for shred in &shreds {
            decoded.extend(decoder.take_in(&sent(shred)).await);
        }
        assert_eq!(decoded.len(), 1);
    }

    /// One forged shred of a slot far in the future, arriving before a real
    /// batch's last shred. Before, the SDK took it for the newest slot and
    /// dropped everything more than 128 slots behind it: the real batch.
    #[tokio::test]
    async fn a_real_batch_still_decodes_after_a_forged_far_future_shred() {
        let leader = Keypair::new();
        let (shreds, entries) = shredded(&leader, NOW, 0);
        let (last, rest) = shreds.split_last().unwrap();
        assert!(!rest.is_empty(), "the batch has more than one shred");
        let (mut decoder, counters) = decoder(&leader);
        for shred in rest {
            assert!(decoder.take_in(&sent(shred)).await.is_none());
        }
        let mut far = forged(last, u64::MAX - 1, 1);
        far.payload[..64].copy_from_slice(&[7; 64]);
        assert!(decoder.take_in(&far).await.is_none());
        assert_eq!(counters.report().dropped.outside_window, 1);
        // The same, as close as a forged shred can come: the window's last slot.
        assert!(decoder.take_in(&forged(last, NOW + SLOTS_AHEAD, 1)).await.is_none());
        assert_eq!(counters.report().dropped.bad_signature, 1);
        let (slot, got) = decoder.take_in(&sent(last)).await.expect("the batch decodes");
        assert_eq!((slot, got), (NOW, entries));
    }

    #[tokio::test]
    async fn only_the_slots_leader_signs_its_shreds() {
        let (leader, stranger) = (Keypair::new(), Keypair::new());
        let (mut decoder, counters) = decoder(&leader);
        // Shreds as good as the leader's, signed by someone else.
        let (theirs, _) = shredded(&stranger, NOW, 0);
        for shred in &theirs {
            assert!(decoder.take_in(&sent(shred)).await.is_none());
        }
        assert_eq!(counters.report().dropped.bad_signature, theirs.len() as u64);
        // A slot the schedule does not reach: no leader to check against.
        decoder.leaders.set(NOW + 1, vec![leader.pubkey().to_bytes(); 10]);
        let (ours, _) = shredded(&leader, NOW, 0);
        assert!(decoder.take_in(&sent(&ours[0])).await.is_none());
        assert_eq!(counters.report().dropped.no_leader, 1);
        // Nothing of either was kept.
        assert_eq!((decoder.kept.sets, decoder.kept.bytes), (0, 0));
        // With the leader known, the same shreds decode.
        decoder.leaders.set(NOW, vec![leader.pubkey().to_bytes(); 10]);
        let mut decoded = Vec::new();
        for shred in &ours {
            decoded.extend(decoder.take_in(&sent(shred)).await);
        }
        assert_eq!(decoded.len(), 1);
        // One signature check served the set: its root is remembered.
        assert_eq!(decoder.signed.0.len(), 1);
    }

    /// One signature check serves a FEC set only for the shreds it signed:
    /// a shred of a checked set with a byte changed leads to another root,
    /// is checked again, and is dropped; the shred as signed still passes.
    #[tokio::test]
    async fn a_changed_shred_of_a_checked_set_is_checked_again() {
        let leader = Keypair::new();
        let (shreds, _) = shredded(&leader, NOW, 0);
        let (mut decoder, counters) = decoder(&leader);
        assert!(decoder.take_in(&sent(&shreds[0])).await.is_none());
        assert_eq!(decoder.signed.0.len(), 1);
        let mut changed = shreds[1].payload().as_ref().to_vec();
        changed[200] ^= 1;
        assert!(decoder.take_in(&datagram(changed)).await.is_none());
        assert_eq!(counters.report().dropped.bad_signature, 1);
        assert!(decoder.take_in(&sent(&shreds[1])).await.is_none());
        assert_eq!(counters.report().dropped.bad_signature, 1);
        assert_eq!(decoder.kept.sets, 1);
    }

    #[tokio::test]
    async fn the_window_follows_the_slot_geyser_is_at() {
        assert_eq!(window(0), None);
        assert_eq!(window(NOW), Some(NOW - SLOTS_BEHIND..=NOW + SLOTS_AHEAD));
        let leader = Keypair::new();
        let (mut decoder, counters) = decoder(&leader);
        decoder.leaders.set(0, vec![leader.pubkey().to_bytes(); 3_000]);
        let taken = |outcome: Option<(u64, Vec<Entry>)>| outcome.map(|(slot, _)| slot);
        // The window's two ends pass, and are kept or decoded.
        for slot in [NOW - SLOTS_BEHIND, NOW + SLOTS_AHEAD] {
            let (shreds, _) = shredded(&leader, slot, 0);
            let mut decoded = Vec::new();
            for shred in &shreds {
                decoded.extend(taken(decoder.take_in(&sent(shred)).await));
            }
            assert_eq!(decoded, [slot]);
        }
        // One slot past either end does not, though the leader signed it.
        for slot in [NOW - SLOTS_BEHIND - 1, NOW + SLOTS_AHEAD + 1] {
            let (shreds, _) = shredded(&leader, slot, 0);
            assert!(decoder.take_in(&sent(&shreds[0])).await.is_none());
        }
        assert_eq!(counters.report().dropped.outside_window, 2);
        // Geyser moves on, and the window with it.
        decoder.geyser_slot.store(NOW + 1, Ordering::Relaxed);
        let (shreds, _) = shredded(&leader, NOW + SLOTS_AHEAD + 1, 0);
        assert!(shreds.len() > 1);
        assert!(decoder.take_in(&sent(&shreds[0])).await.is_none());
        assert_eq!(counters.report().dropped.outside_window, 2);
        assert_eq!(decoder.kept.sets, 1);
        // Before Geyser reports a slot, nothing passes.
        decoder.geyser_slot.store(0, Ordering::Relaxed);
        assert!(decoder.take_in(&sent(&shreds[1])).await.is_none());
        assert_eq!(counters.report().dropped.outside_window, 3);
    }

    #[tokio::test]
    async fn a_datagram_that_is_no_shred_is_dropped() {
        let leader = Keypair::new();
        let (shreds, _) = shredded(&leader, NOW, 0);
        let (mut decoder, counters) = decoder(&leader);
        let real = shreds[0].payload().as_ref().to_vec();
        let mut long = real.clone();
        long.resize(MAX_DATAGRAM + 1, 0);
        // Too short to name a slot, longer than a packet, and bytes that
        // name a slot in the window and are no shred.
        let mut junk = vec![0xff; 200];
        junk[65..73].copy_from_slice(&NOW.to_le_bytes());
        for payload in [Vec::new(), vec![0; 72], long, junk] {
            assert!(decoder.take_in(&datagram(payload)).await.is_none());
        }
        assert_eq!(counters.report().dropped.malformed, 4);
        assert_eq!((decoder.kept.sets, decoder.kept.bytes), (0, 0));
    }

    /// What the leader signed is still kept only up to a limit: batches
    /// that never complete are dropped whole when there are too many, and
    /// the receiver goes on.
    #[tokio::test]
    async fn what_is_kept_is_dropped_whole_when_it_goes_over_its_limit() {
        let leader = Keypair::new();
        let (mut decoder, counters) = decoder(&leader);
        decoder.limits = Limits { sets: 8, bytes: usize::MAX };
        // One shred each of nine batches that never get their rest.
        for n in 0..9u64 {
            let (shreds, _) = shredded(&leader, NOW + n, 0);
            assert!(shreds.len() > 1);
            assert!(decoder.take_in(&sent(&shreds[0])).await.is_none());
            let kept = if n < 8 { n as usize + 1 } else { 0 };
            assert_eq!(decoder.kept.sets, kept, "after batch {n}");
        }
        assert_eq!(counters.report().resets, 1);
        assert_eq!(decoder.kept.bytes, 0);
        // The same by bytes: a data shred is counted twice, as it is kept.
        let (shreds, entries) = shredded(&leader, NOW + 20, 0);
        let one = shreds[0].payload().len() * 2;
        decoder.limits = Limits { sets: usize::MAX, bytes: one * 2 };
        for shred in &shreds[..2] {
            assert!(decoder.take_in(&sent(shred)).await.is_none());
        }
        assert_eq!((decoder.kept.sets, decoder.kept.bytes), (1, one * 2));
        let (other, _) = shredded(&leader, NOW + 21, 0);
        assert!(decoder.take_in(&sent(&other[0])).await.is_none());
        assert_eq!((decoder.kept.sets, decoder.kept.bytes, counters.report().resets), (0, 0, 2));
        // After a reset a whole batch decodes as before.
        decoder.limits = KEPT;
        let mut decoded = Vec::new();
        for shred in &shreds {
            decoded.extend(decoder.take_in(&sent(shred)).await);
        }
        assert_eq!(decoded, [(NOW + 20, entries)]);
        assert_eq!((decoder.kept.sets, decoder.kept.bytes), (0, 0));
    }

    /// A genuine shred sent again, as anyone who can spoof an ERPC source
    /// can: the SDK takes it and drops it, and it counts nothing here, so
    /// no number of replays forces a reset that would drop real batches.
    #[tokio::test]
    async fn a_replayed_genuine_shred_counts_nothing_and_drops_no_batch() {
        let leader = Keypair::new();
        let (shreds, entries) = shredded(&leader, NOW, 0);
        assert!(shreds.len() > 2);
        let (mut decoder, counters) = decoder(&leader);
        // A hundred shreds' worth, as the gate's reproduction scaled it.
        decoder.limits = Limits { sets: usize::MAX, bytes: shreds[0].payload().len() * 2 * 100 };
        let last = shreds.len() - 1;
        for shred in &shreds[..last] {
            assert!(decoder.take_in(&sent(shred)).await.is_none());
        }
        let before = decoder.kept.bytes;
        for _ in 0..1_000 {
            assert!(decoder.take_in(&sent(&shreds[0])).await.is_none());
        }
        assert_eq!(decoder.kept.bytes, before);
        assert_eq!(counters.report().resets, 0);
        // The batch's last shred still completes it.
        assert_eq!(decoder.take_in(&sent(&shreds[last])).await, Some((NOW, entries)));
        assert_eq!((decoder.kept.sets, decoder.kept.bytes), (0, 0));
    }

    #[test]
    fn what_is_kept_is_let_go_as_the_sdk_lets_go() {
        let key = |slot, fec_set| FecKey { slot, version: 1, fec_set };
        let mut kept = Kept::default();
        kept.add(key(100, 0), (0, true), 1_000);
        kept.add(key(100, 0), (1, true), 500);
        kept.add(key(100, 32), (32, true), 1_000);
        kept.add(key(228, 0), (0, true), 1_000);
        assert_eq!((kept.sets, kept.bytes), (3, 3_500));
        // A shred the set has already counts nothing: the SDK keeps one.
        kept.add(key(100, 0), (1, true), 500);
        assert_eq!((kept.sets, kept.bytes), (3, 3_500));
        // The coding shred of the same index is another shred.
        kept.add(key(100, 0), (1, false), 500);
        assert_eq!((kept.sets, kept.bytes), (3, 4_000));
        // 128 slots behind is still held; one more is not.
        kept.add(key(229, 0), (0, true), 1_000);
        assert_eq!((kept.sets, kept.bytes), (2, 2_000));
        // A batch done with is no longer counted, and one never counted changes nothing.
        kept.done(&key(228, 0));
        kept.done(&key(228, 0));
        kept.done(&key(500, 0));
        assert_eq!((kept.sets, kept.bytes), (1, 1_000));
        assert!(kept.over(Limits { sets: 0, bytes: usize::MAX }));
        assert!(kept.over(Limits { sets: usize::MAX, bytes: 999 }));
        assert!(!kept.over(Limits { sets: 1, bytes: 1_000 }));
    }

    /// A JSON-RPC server on loopback that answers `getSlotLeaders` with
    /// `leaders`, once per connection, and says what it was asked.
    fn leader_rpc(leaders: Vec<Pubkey>) -> (String, std::sync::mpsc::Receiver<serde_json::Value>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let (asked, was_asked) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let result: Vec<String> = leaders.iter().map(ToString::to_string).collect();
                let reply = serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }).to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = asked.send(request);
            }
        });
        (url, was_asked)
    }

    #[tokio::test]
    async fn the_leader_schedule_is_read_from_the_windows_start_on() {
        let (first, second) = (Pubkey::new_from_array([1; 32]), Pubkey::new_from_array([2; 32]));
        let (url, asked) = leader_rpc(vec![first, second]);
        let leaders = Leaders::default();
        assert_eq!(leaders.of(NOW), None);
        read_leaders(&RpcClient::new(url), &leaders, NOW).await.unwrap();
        let request = asked.recv().unwrap();
        assert_eq!(request["method"], "getSlotLeaders");
        assert_eq!(request["params"], serde_json::json!([NOW - SLOTS_BEHIND, LEADERS_AT_ONCE]));
        // The first key is the leader of the first slot asked for.
        assert_eq!(leaders.of(NOW - SLOTS_BEHIND), Some([1; 32]));
        assert_eq!(leaders.of(NOW - SLOTS_BEHIND + 1), Some([2; 32]));
        assert_eq!(leaders.of(NOW - SLOTS_BEHIND + 2), None);
        assert_eq!(leaders.of(NOW - SLOTS_BEHIND - 1), None);
        // Two slots do not reach past the window: more are wanted.
        assert!(!leaders.covers(NOW));
        leaders.set(NOW - SLOTS_BEHIND, vec![[1; 32]; LEADERS_AT_ONCE as usize]);
        assert!(leaders.covers(NOW));
        // Until Geyser has moved on far enough that too few are left.
        let last_covered = NOW - SLOTS_BEHIND + LEADERS_AT_ONCE - 1 - SLOTS_AHEAD - LEADERS_LEFT;
        assert!(leaders.covers(last_covered));
        assert!(!leaders.covers(last_covered + 1));
        // An RPC that names none is an error, and the schedule stays.
        let (url, _asked) = leader_rpc(Vec::new());
        assert!(read_leaders(&RpcClient::new(url), &leaders, NOW).await.is_err());
        assert!(leaders.covers(NOW));
    }
}
