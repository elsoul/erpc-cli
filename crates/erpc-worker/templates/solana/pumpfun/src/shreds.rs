//! The Shreds stream (`SHREDS_ENDPOINT`): transactions as the leader sends
//! them out, before any node has run them.
//!
//! Every pump.fun migration in it is timed (see `timing`), and, with
//! `buy_on_shreds`, its pool is bought from it: the accounts the migration
//! reads are fetched at processed, in one round trip, while it has not run
//! yet, and the pool it will create is made from them. A buy sent then can
//! land in the pool's own slot, and can also land before the pool exists,
//! and fail. The Geyser path still sees every pool; a pool bought from the
//! Shreds stream is not bought again (`reserve_buy`).

use crate::amm::{Migration, Read, PUMP_PROGRAM};
use crate::state::AppState;
use crate::timing::{Sighting, Via};
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use log::{info, warn};
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_signature::Signature;
use solana_stream_sdk::shredstream_proto::shredstream_proxy_client::ShredstreamProxyClient;
use solana_stream_sdk::{decode_entries, ShredstreamClient, VersionedTransaction};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tonic::transport::{ClientTlsConfig, Endpoint};

/// Where an address lookup table's addresses start.
const LOOKUP_TABLE_META_SIZE: usize = 56;
/// A batch of entries can be larger than tonic's 4 MB default.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// Address lookup tables by address, as last read. A table only grows, so
/// one read stays right for the indexes it had; a table read before it
/// grew is read again when a transaction uses an index past its end.
#[derive(Default)]
pub struct Luts(Mutex<HashMap<Pubkey, Arc<Vec<Pubkey>>>>);

impl Luts {
    fn get(&self, table: &Pubkey) -> Option<Arc<Vec<Pubkey>>> {
        self.0.lock().expect("luts lock").get(table).cloned()
    }

    pub fn knows(&self, table: &Pubkey) -> bool {
        self.0.lock().expect("luts lock").contains_key(table)
    }

    /// Reads `tables` from the RPC, in one request.
    pub async fn fetch(&self, rpc: &RpcClient, tables: &[Pubkey]) {
        if tables.is_empty() {
            return;
        }
        match rpc.get_multiple_accounts(tables).await {
            Ok(accounts) => {
                let mut known = self.0.lock().expect("luts lock");
                for (table, account) in tables.iter().zip(accounts) {
                    if let Some(addresses) = account.and_then(|a| lookup_table_addresses(&a.data)) {
                        known.insert(*table, Arc::new(addresses));
                    }
                }
            }
            Err(e) => warn!("Could not read address lookup tables: {e}"),
        }
    }
}

fn lookup_table_addresses(data: &[u8]) -> Option<Vec<Pubkey>> {
    let addresses = data.get(LOOKUP_TABLE_META_SIZE..)?;
    Some(addresses.as_chunks::<32>().0.iter().map(|k| Pubkey::new_from_array(*k)).collect())
}

fn key(k: &impl AsRef<[u8]>) -> Pubkey {
    Pubkey::new_from_array(k.as_ref().try_into().expect("32 bytes"))
}

/// A migration found in a transaction: its signature, and its
/// instruction's account indexes and data.
struct Found {
    signature: Signature,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

/// The `migrate_v2` in a transaction, if there is one. A program is always
/// among the message's own keys, so nothing has to be looked up to find it.
fn migration_in(tx: &VersionedTransaction) -> Option<Found> {
    let keys = tx.message.static_account_keys();
    let ix = tx.message.instructions().iter().find(|ix| {
        keys.get(ix.program_id_index as usize).is_some_and(|p| key(p) == PUMP_PROGRAM)
            && ix.data.starts_with(&crate::amm::MIGRATE_V2_DISCRIMINATOR)
            && ix.accounts.len() == 29
    })?;
    let signature = Signature::from(<[u8; 64]>::try_from(tx.signatures.first()?.as_ref()).ok()?);
    Some(Found { signature, accounts: ix.accounts.clone(), data: ix.data.clone() })
}

/// A transaction's keys in the order its instructions index them: its own,
/// then each table's writable ones, then each table's read-only ones. The
/// tables not known, or known too short, when some are missing.
fn resolve(tx: &VersionedTransaction, luts: &Luts) -> Result<Vec<Pubkey>, Vec<Pubkey>> {
    let mut keys: Vec<Pubkey> = tx.message.static_account_keys().iter().map(key).collect();
    let Some(lookups) = tx.message.address_table_lookups() else {
        return Ok(keys);
    };
    let mut missing = Vec::new();
    let mut readonly = Vec::new();
    for lookup in lookups {
        let table = key(&lookup.account_key);
        let addresses = luts.get(&table);
        let pick = |indexes: &[u8], out: &mut Vec<Pubkey>| -> bool {
            indexes.iter().all(|i| match addresses.as_ref().and_then(|a| a.get(*i as usize)) {
                Some(k) => {
                    out.push(*k);
                    true
                }
                None => false,
            })
        };
        let found = pick(&lookup.writable_indexes, &mut keys) & pick(&lookup.readonly_indexes, &mut readonly);
        if !found {
            missing.push(table);
        }
    }
    if !missing.is_empty() {
        return Err(missing);
    }
    keys.extend(readonly);
    Ok(keys)
}

/// Watches the Shreds stream for as long as the bot runs, reconnecting
/// with a growing pause when it drops.
pub async fn run(endpoint: String, state: Arc<RwLock<AppState>>, rpc: Arc<RpcClient>, send_rpc: Arc<RpcClient>) {
    let mut backoff = ExponentialBackoff { max_elapsed_time: None, ..ExponentialBackoff::default() };
    loop {
        match stream(&endpoint, &state, &rpc, &send_rpc).await {
            Ok(true) => {
                info!("Shreds stream ended, reconnecting");
                backoff.reset();
            }
            Ok(false) => info!("Shreds stream ended before any entry, reconnecting"),
            Err(e) => warn!("Shreds stream failed: {e:#}"),
        }
        tokio::time::sleep(backoff.next_backoff().unwrap_or(Duration::from_secs(1))).await;
    }
}

/// One connection: whether any entry came through it.
async fn stream(
    endpoint: &str,
    state: &Arc<RwLock<AppState>>,
    rpc: &Arc<RpcClient>,
    send_rpc: &Arc<RpcClient>,
) -> anyhow::Result<bool> {
    let mut channel = Endpoint::from_shared(endpoint.to_owned())?;
    if endpoint.starts_with("https://") {
        channel = channel.tls_config(ClientTlsConfig::new().with_native_roots())?;
    }
    let mut client = ShredstreamProxyClient::new(channel.connect().await?).max_decoding_message_size(MAX_MESSAGE);
    let mut entries = client
        .subscribe_entries(ShredstreamClient::create_empty_entries_request())
        .await?
        .into_inner();
    info!("Shreds stream connected");
    let mut any = false;
    while let Some(message) = entries.message().await? {
        any = true;
        let seen = Instant::now();
        let Ok(decoded) = decode_entries(&message.entries) else { continue };
        for tx in decoded.iter().flat_map(|e| &e.transactions) {
            if let Some(found) = migration_in(tx) {
                on_migration(found, tx, message.slot, seen, state, rpc, send_rpc).await;
            }
        }
    }
    Ok(any)
}

async fn on_migration(
    found: Found,
    tx: &VersionedTransaction,
    slot: u64,
    seen: Instant,
    state: &Arc<RwLock<AppState>>,
    rpc: &Arc<RpcClient>,
    send_rpc: &Arc<RpcClient>,
) {
    let (timing, luts, buy) = {
        let s = state.read().await;
        (s.timing.clone(), s.luts.clone(), s.config.buy_on_shreds && s.grpc_streaming && s.running)
    };
    timing.lock().expect("timing lock").on_shred(found.signature, slot, seen);
    if !buy {
        return;
    }
    let tx = tx.clone();
    let (state, rpc, send_rpc) = (state.clone(), rpc.clone(), send_rpc.clone());
    tokio::spawn(async move {
        let keys = match resolve(&tx, &luts) {
            Ok(keys) => keys,
            Err(missing) => {
                // Read once; the next migration through these tables finds them.
                luts.fetch(&rpc, &missing).await;
                match resolve(&tx, &luts) {
                    Ok(keys) => keys,
                    Err(_) => return warn!("Migration {}: its lookup tables could not be read", found.signature),
                }
            }
        };
        let accounts: Vec<Pubkey> = found.accounts.iter().filter_map(|i| keys.get(*i as usize).copied()).collect();
        let Some(migration) = Migration::parse(&found.data, &accounts) else {
            // Not run yet, so not believed: a migrate_v2 laid out otherwise,
            // or naming an account that is not the mint's own.
            return info!(
                "Migration {}: laid out otherwise than this bot reads, or with accounts that are not its mint's own; left to Geyser",
                found.signature
            );
        };
        let read = rpc
            .get_multiple_accounts_with_commitment(&migration.to_read(), CommitmentConfig::processed())
            .await
            .map(|r| r.value);
        let new_pool = match read.as_deref() {
            Ok([Some(curve), Some(token_account), Some(global)]) => {
                fn read(a: &solana_sdk::account::Account) -> Read<'_> {
                    Read { owner: &a.owner, data: &a.data }
                }
                migration.new_pool(read(curve), read(token_account), read(global))
            }
            Ok(_) => Err("its accounts could not be read"),
            Err(e) => {
                warn!("Migration {}: {e}", found.signature);
                Err("its accounts could not be read")
            }
        };
        match new_pool {
            Ok(new_pool) => {
                let sighting = Sighting { slot, seen, via: Via::Shreds };
                crate::handlers::processor::on_create_pool(new_pool, sighting, &state, &rpc, &send_rpc).await;
            }
            Err(why) => info!("Pool {} not bought from the Shreds stream: {why}", migration.pool()),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lookup_table_reads_its_addresses_after_its_header() {
        let mut data = vec![0u8; LOOKUP_TABLE_META_SIZE];
        data.extend_from_slice(&[1; 32]);
        data.extend_from_slice(&[2; 32]);
        let got = lookup_table_addresses(&data).unwrap();
        assert_eq!(got, vec![Pubkey::new_from_array([1; 32]), Pubkey::new_from_array([2; 32])]);
    }

    /// One entry holding one v0 transaction, as the ledger lays it out: a
    /// `migrate_v2` whose accounts are the message's own keys 0..=4 then
    /// the lookup table's, writable 0..14 and read-only 14..24.
    fn entry_with_a_migration(table: Pubkey) -> Vec<u8> {
        let mut msg = vec![0x80, 1, 0, 1, 5];
        for i in 0..5u8 {
            let k = if i == 4 { PUMP_PROGRAM } else { Pubkey::new_from_array([100 + i; 32]) };
            msg.extend_from_slice(k.as_ref());
        }
        msg.extend_from_slice(&[9; 32]); // blockhash
        msg.extend_from_slice(&[1, 4, 29]); // one instruction, program 4, 29 accounts
        msg.extend((0..4u8).chain(5..30));
        msg.push(8);
        msg.extend_from_slice(&crate::amm::MIGRATE_V2_DISCRIMINATOR);
        msg.push(1); // one lookup
        msg.extend_from_slice(table.as_ref());
        msg.push(14);
        msg.extend(0..14u8);
        msg.push(11);
        msg.extend(14..25u8);
        let mut out = 1u64.to_le_bytes().to_vec(); // entries
        out.extend_from_slice(&1u64.to_le_bytes()); // num_hashes
        out.extend_from_slice(&[7; 32]); // hash
        out.extend_from_slice(&1u64.to_le_bytes()); // transactions
        out.push(1); // signatures
        out.extend_from_slice(&[3; 64]);
        out.extend(msg);
        out
    }

    #[test]
    fn a_migration_in_the_stream_is_found_and_its_keys_resolved() {
        let table = Pubkey::new_from_array([42; 32]);
        let entries = decode_entries(&entry_with_a_migration(table)).unwrap();
        let tx = &entries[0].transactions[0];
        let found = migration_in(tx).unwrap();
        assert_eq!(found.signature, Signature::from([3; 64]));
        assert_eq!(found.accounts.len(), 29);

        let luts = Luts::default();
        assert_eq!(resolve(tx, &luts), Err(vec![table]));
        let addresses: Vec<Pubkey> = (0..25u8).map(|i| Pubkey::new_from_array([200 + i; 32])).collect();
        // Read before it grew: still missing.
        luts.0.lock().unwrap().insert(table, Arc::new(addresses[..20].to_vec()));
        assert_eq!(resolve(tx, &luts), Err(vec![table]));
        luts.0.lock().unwrap().insert(table, Arc::new(addresses.clone()));
        let keys = resolve(tx, &luts).unwrap();
        // Own keys, then the writable ones, then the read-only ones.
        assert_eq!(keys.len(), 5 + 25);
        assert_eq!(keys[4], PUMP_PROGRAM);
        assert_eq!(keys[5], addresses[0]);
        assert_eq!(keys[5 + 14], addresses[14]);
        assert_eq!(keys[29], addresses[24]);
    }
}
