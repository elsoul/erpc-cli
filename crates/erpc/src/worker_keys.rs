// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker key` and `erpc worker secret`: an app's trading key and
//! its secret settings, kept in 1Password, the keychain or erpc's
//! encrypted keystore (see [`crate::worker_secrets`]) and named in
//! `erpc.toml` by reference.
//!
//! A key is made in memory, or read from a key file the operator already
//! has, and goes straight to the store. A secret is read from standard
//! input when it is piped in, or asked for without echo; or, with a flag,
//! it is made here (`--generate`) or is the signed-in account's RPC API
//! key (`--from-account`), and then nothing is read or asked. Neither a
//! key nor a secret is ever printed or logged by erpc, and the only file
//! erpc writes one to is its keystore entry, sealed.

use std::io::{IsTerminal as _, Read as _};
use std::path::Path;

use erpc_chain_solana::identity::Keypair;
use erpc_worker::edit;
use erpc_worker::manifest::{self, Manifest, SecretRef};
use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::{Outcome, Said};
use crate::error::{CliError, Code};
use crate::ui::Report;
use crate::worker::{Dir, load};
use crate::worker_secrets::{self, Store, StoreFlag};
use crate::worker_vps::{AccountKey, Tried};

/// The biggest secret or key file read.
const MAX_SECRET: u64 = 64 * 1024;

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

/// Reads `path`'s manifest text again, applies `change`, and saves it.
fn rewrite(
    path: &Path,
    change: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(), CliError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        failed(t!(
            "worker_keys.read_failed",
            path = path.display(),
            error = e
        ))
    })?;
    let changed = change(&text).map_err(failed)?;
    edit::save(path, &changed).map_err(failed)
}

/// A warning when the app's servers are in 1Password and the store is the
/// keychain or the keystore, which only this machine has.
fn portability(m: &Manifest, store: &Store) -> Report {
    let report = Report::new();
    if !m.env.values().any(|e| e.inventory.is_some()) {
        return report;
    }
    match store {
        Store::Keychain => report.warning(t!("worker_keys.portability")),
        Store::Keystore { .. } => report.warning(t!("worker_keys.portability_keystore")),
        Store::OnePassword { .. } => report,
    }
}

/// What to heed about a trading key kept in `store`: in the keystore, its
/// file is the only copy there is.
fn key_cautions(m: &Manifest, store: &Store) -> Report {
    let report = match store {
        Store::Keystore { .. } => Report::new().warning(t!(
            "worker_keys.kept.keystore_backup",
            path = crate::worker_keystore::place_here()
        )),
        Store::OnePassword { .. } | Store::Keychain => Report::new(),
    };
    report.extend(portability(m, store))
}

/// `erpc worker key new`: a new key, made in memory and kept only in the store.
///
/// An app that has a wallet already keeps it: nothing is made, and that is
/// said as the state the command leaves, not as a failure (exit 0).
pub(crate) fn new(json: bool, dir: &Dir, store: Option<StoreFlag>, vault: Option<&str>) -> Outcome {
    let kept = Keypair::generate()
        .map_err(|e| failed(e.to_string()))
        .and_then(|keypair| keep(dir, store, vault, &keypair));
    match kept {
        Ok(Keeping::Kept(kept)) => kept.report(json, "made", None),
        Ok(Keeping::Already(already)) => already.report(json, dir),
        Err(e) => e.into(),
    }
}

/// `erpc worker key import`: a key file the operator has, moved into the store.
pub(crate) fn import(
    json: bool,
    dir: &Dir,
    file: &Path,
    store: Option<StoreFlag>,
    vault: Option<&str>,
    wipe: bool,
) -> Outcome {
    let kept = match read_key_file(file).and_then(|keypair| keep(dir, store, vault, &keypair)) {
        Ok(Keeping::Kept(kept)) => kept,
        // A key file brought to an app that has a wallet is not taken in:
        // what was asked is not done.
        Ok(Keeping::Already(already)) => return already.refusal(dir).into(),
        Err(e) => return e.into(),
    };
    let wipe = wipe
        || (!json
            && crate::session::has_terminal()
            && crate::node_common::confirm(&t!(
                "worker_keys.import.wipe_question",
                file = file.display()
            ))
            .unwrap_or(false));
    let wiped = wipe.then(|| wipe_file(file));
    let note = wipe_note(file, wiped.as_ref());
    kept.report(
        json,
        "imported",
        Some((
            note,
            json!({ "key_file": file, "wiped": matches!(wiped, Some(Ok(()))) }),
        )),
    )
}

/// What became of import's key file.
fn wipe_note(file: &Path, wiped: Option<&Result<(), String>>) -> Report {
    match wiped {
        Some(Ok(())) => {
            Report::new().marked("🧹", t!("worker_keys.import.wiped", file = file.display()))
        }
        Some(Err(e)) => Report::new().warning(t!(
            "worker_keys.import.wipe_failed",
            file = file.display(),
            error = e
        )),
        None => Report::new().info(t!("worker_keys.import.left_on_disk", file = file.display())),
    }
}

/// What keeping a key came to.
enum Keeping {
    Kept(Kept),
    /// The app has a wallet already; nothing was kept.
    Already(Already),
}

/// A key now kept, and named in erpc.toml.
struct Kept {
    app: String,
    pubkey: String,
    source: SecretRef,
    store: Store,
    warning: Report,
}

/// The wallet an app has already.
struct Already {
    app: String,
    pubkey: Option<String>,
    source: SecretRef,
}

impl Already {
    fn pubkey(&self) -> String {
        self.pubkey
            .clone()
            .unwrap_or_else(|| t!("worker_keys.already.no_pubkey"))
    }

    fn hints(dir: &Dir) -> [String; 2] {
        let scope = dir.scope();
        [
            t!("worker_keys.already.show_hint", dir_scope = scope),
            t!("worker_keys.already.replace_hint"),
        ]
    }

    /// `key new`: the wallet there is, as the state the command leaves.
    fn report(&self, json: bool, dir: &Dir) -> Outcome {
        if json {
            crate::print_json(&json!({
                "pubkey": self.pubkey,
                "source": self.source,
                "already": true,
            }));
            return Outcome::Done(String::new());
        }
        let [show, replace] = Self::hints(dir);
        Outcome::Done(
            Report::new()
                .marked("🔑", t!("worker_keys.already.title", app = self.app))
                .fields([
                    (t!("worker_keys.field.pubkey"), self.pubkey()),
                    (t!("worker_keys.field.kept_at"), self.source.to_string()),
                ])
                .hint(show)
                .hint(replace)
                .text(),
        )
    }

    /// `key import`: the key file was not taken in.
    fn refusal(&self, dir: &Dir) -> CliError {
        let scope = dir.scope();
        failed(t!(
            "worker_keys.already.refused",
            app = self.app,
            pubkey = self.pubkey(),
            source = self.source
        ))
        .hint(t!("worker_keys.already.refused_hint", dir_scope = scope))
        .mark("🔑")
    }
}

impl Kept {
    /// What to tell the operator, with `extra` for import's key file.
    fn report(self, json: bool, verb: &str, extra: Option<(Report, serde_json::Value)>) -> Outcome {
        if json {
            let mut body = json!({
                "pubkey": self.pubkey,
                "source": self.source,
                "store": self.store.describe(),
                "already": false,
            });
            if let (Some((_, more)), Some(obj)) = (&extra, body.as_object_mut())
                && let Some(more) = more.as_object()
            {
                obj.extend(more.clone());
            }
            crate::print_json(&body);
            return Outcome::Done(String::new());
        }
        let (app, pubkey) = (&self.app, &self.pubkey);
        let title = if verb == "imported" {
            t!("worker_keys.kept.imported", app, pubkey)
        } else {
            t!("worker_keys.kept.made", app, pubkey)
        };
        let mut report = Report::new()
            .done(title)
            .info(t!(
                "worker_keys.kept.where",
                store = self.store.describe(),
                source = self.source
            ))
            .marked("🔥", t!("worker_keys.kept.hot_wallet"))
            .extend(self.warning);
        if let Some((note, _)) = extra {
            report = report.extend(note);
        }
        Outcome::Done(report.text())
    }
}

fn read_key_file(file: &Path) -> Result<Keypair, CliError> {
    let size = std::fs::metadata(file)
        .map_err(|e| {
            failed(t!(
                "worker_keys.read_failed",
                path = file.display(),
                error = e
            ))
        })?
        .len();
    if size > MAX_SECRET {
        return Err(failed(t!(
            "worker_keys.key_file.not_one",
            path = file.display()
        )));
    }
    let mut text = Zeroizing::new(String::new());
    std::fs::File::open(file)
        .and_then(|mut f| f.read_to_string(&mut text))
        .map_err(|e| {
            failed(t!(
                "worker_keys.read_failed",
                path = file.display(),
                error = e
            ))
        })?;
    Keypair::parse_json(&text).map_err(|e| {
        failed(t!(
            "worker_keys.key_file.unreadable",
            path = file.display(),
            error = e
        ))
    })
}

/// Overwrites the file with zeros, syncs it, and removes it. On an SSD or a
/// copy-on-write file system the old blocks may survive; the store is the
/// key's home from now on.
fn wipe_file(file: &Path) -> Result<(), String> {
    use std::io::Write as _;
    let len = std::fs::metadata(file).map_err(|e| e.to_string())?.len();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(file)
        .map_err(|e| e.to_string())?;
    let zeros = vec![0_u8; usize::try_from(len).unwrap_or(0)];
    f.write_all(&zeros)
        .and_then(|()| f.sync_all())
        .map_err(|e| e.to_string())?;
    drop(f);
    std::fs::remove_file(file).map_err(|e| e.to_string())
}

/// Keeps `keypair` in the store and names it in erpc.toml's `[wallet]`.
fn keep(
    dir: &Dir,
    store: Option<StoreFlag>,
    vault: Option<&str>,
    keypair: &Keypair,
) -> Result<Keeping, CliError> {
    let (path, m) = load(dir)?;
    if let Some(wallet) = m.wallet {
        return Ok(Keeping::Already(Already {
            app: m.name,
            pubkey: wallet.pubkey,
            source: wallet.source,
        }));
    }
    let store = worker_secrets::choose(store, vault).map_err(failed)?;
    let pubkey = keypair.pubkey();
    let source = worker_secrets::put_key(&store, &m.name, keypair).map_err(failed)?;
    rewrite(&path, |text| edit::set_wallet(text, &source, &pubkey))
        .map_err(|e| e.hint(t!("worker_keys.kept.by_hand", source, pubkey)))?;
    Ok(Keeping::Kept(Kept {
        warning: key_cautions(&m, &store),
        app: m.name,
        pubkey,
        source,
        store,
    }))
}

/// `erpc worker key show`: the public key and where the key is kept.
pub(crate) fn show(json: bool, dir: &Dir) -> Outcome {
    let (_, m) = match load(dir) {
        Ok(found) => found,
        Err(e) => return e.into(),
    };
    let Some(wallet) = m.wallet else {
        return failed(t!("worker_keys.show.no_wallet", app = m.name))
            .hint(t!("worker_keys.show.new_hint", dir_scope = dir.scope()))
            .mark("🔑")
            .into();
    };
    // A key in the keystore is a file on the machine that kept it: where,
    // and whether this is that machine. Asks for no passphrase.
    let in_keystore = match &wallet.source {
        SecretRef::Keystore { service, account } => {
            let found = crate::worker_keystore::file_of(service, account)
                .and_then(|file| Ok((file, crate::worker_keystore::has(service, account)?)));
            match found {
                Ok(found) => Some(found),
                Err(e) => return failed(e).into(),
            }
        }
        SecretRef::OnePassword(_) | SecretRef::Keychain { .. } => None,
    };
    if json {
        let mut body = json!({ "pubkey": wallet.pubkey, "source": wallet.source });
        if let Some((file, here)) = &in_keystore {
            body["keystore"] = json!({ "file": file, "here": here });
        }
        crate::print_json(&body);
        return Outcome::Done(String::new());
    }
    let mut report = Report::new()
        .marked(
            "🔑",
            format!(
                "{}  {}",
                m.name,
                wallet
                    .pubkey
                    .unwrap_or_else(|| t!("worker_keys.show.no_pubkey"))
            ),
        )
        .detail(t!("worker_keys.show.kept_at", source = wallet.source));
    match in_keystore.map(|(file, here)| (crate::ui::tidy(&file), here)) {
        Some((file, true)) => report = report.detail(t!("worker_keys.show.keystore_file", file)),
        Some((file, false)) => {
            report = report.warning(t!("worker_keys.show.keystore_missing", file));
        }
        None => {}
    }
    Outcome::Done(report.text())
}

/// `erpc worker key balance`: the key's SOL, from the app's own RPC
/// setting, or `--rpc`.
pub(crate) async fn balance(json: bool, dir: &Dir, rpc_flag: Option<&str>) -> Outcome {
    let (_, m) = match load(dir) {
        Ok(found) => found,
        Err(e) => return e.into(),
    };
    let Some(pubkey) = m.wallet.as_ref().and_then(|w| w.pubkey.clone()) else {
        return failed(t!("worker_keys.balance.no_pubkey", app = m.name)).into();
    };
    let url = match rpc_url(&m, rpc_flag) {
        Ok(url) => url,
        Err(e) => return e.into(),
    };
    let answer = rpc(&url, "getBalance", json!([pubkey]))
        .await
        .and_then(|v| {
            v["result"]["value"]
                .as_u64()
                .ok_or_else(|| t!("worker_keys.balance.no_balance", status = 200))
        });
    let lamports = match answer {
        Ok(lamports) => lamports,
        Err(e) => {
            return CliError::new(Code::Network, t!("worker_keys.balance.failed", error = e))
                .into();
        }
    };
    #[allow(
        clippy::cast_precision_loss,
        reason = "a balance shown, not computed with"
    )]
    let sol = lamports as f64 / 1e9;
    if json {
        crate::print_json(&json!({ "pubkey": pubkey, "lamports": lamports, "sol": sol }));
        return Outcome::Done(String::new());
    }
    Outcome::Done(
        Report::new()
            .marked("💰", format!("{pubkey}  {sol:.9} SOL"))
            .text(),
    )
}

/// Why a JSON-RPC call gave no result. The two are told apart because
/// they say different things about a request that changes something: a
/// node that refused it did not do it, and anything else may have.
#[derive(Debug)]
enum RpcFailure {
    /// The RPC node refused the request itself ([`PREFLIGHT_REFUSALS`]).
    Refused(String),
    /// No answer that settles it: a timeout, a connection that dropped, a
    /// body that is not JSON, or a JSON-RPC error that is not a node's
    /// refusal (a gateway's, a proxy's).
    NoAnswer(String),
}

impl RpcFailure {
    fn into_message(self) -> String {
        match self {
            Self::Refused(m) | Self::NoAnswer(m) => m,
        }
    }
}

/// One JSON-RPC call to `url`, the whole answer back.
async fn rpc_call(
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, RpcFailure> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let response = reqwest::Client::new()
        .post(url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| RpcFailure::NoAnswer(e.without_url().to_string()))?;
    let status = response.status();
    let value: serde_json::Value = response.json().await.map_err(|e| {
        RpcFailure::NoAnswer(t!(
            "worker_keys.balance.not_json_rpc",
            status,
            error = e.without_url()
        ))
    })?;
    if let Some(error) = value.get("error").filter(|e| !e.is_null()) {
        let message = error["message"].as_str().unwrap_or("").to_owned();
        let message = if message.is_empty() {
            error.to_string()
        } else {
            message
        };
        return Err(match error["code"].as_i64() {
            Some(code) if PREFLIGHT_REFUSALS.contains(&code) => RpcFailure::Refused(message),
            // Any other error may come from something between here and the
            // validator, after the transaction went on: a gateway's
            // timeout, a proxy's. It says nothing about the transaction.
            _ => RpcFailure::NoAnswer(message),
        });
    }
    Ok(value)
}

/// The JSON-RPC errors an RPC node answers with when its own check of the
/// transaction refused it before sending it on. -32002: the preflight
/// simulation failed (a blockhash it does not know, too little SOL, a
/// signature that does not verify). -32003 is the code agave defines for a
/// signature that does not verify; its current `sendTransaction` reports
/// that as -32002 instead, and the code is kept for nodes that use it.
/// Only these say nothing was sent.
const PREFLIGHT_REFUSALS: [i64; 2] = [-32_002, -32_003];

/// As [`rpc_call`], for a read: why it failed is only something to show.
async fn rpc(
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    rpc_call(url, method, params)
        .await
        .map_err(RpcFailure::into_message)
}

/// The lamports of one SOL.
const LAMPORTS_PER_SOL: f64 = 1e9;

/// Lamports as SOL, for a person to read.
#[allow(
    clippy::cast_precision_loss,
    reason = "an amount shown, not computed with"
)]
fn in_sol(lamports: u64) -> String {
    format!("{:.9}", lamports as f64 / LAMPORTS_PER_SOL)
}

/// How a sent transfer is waited for: how often the RPC is asked, and for
/// how long before the signature is handed over to be checked by hand. A
/// blockhash lasts 150 blocks, about a minute, so the wait outlasts it and
/// most transfers end as landed or as expired, not as unknown.
#[derive(Debug, Clone, Copy)]
struct Pace {
    every: std::time::Duration,
    at_most: std::time::Duration,
}

const PACE: Pace = Pace {
    every: std::time::Duration::from_millis(1500),
    at_most: std::time::Duration::from_secs(120),
};

/// Where a signed transfer handed to the RPC ended.
#[derive(Debug, PartialEq, Eq)]
enum Delivery {
    /// On the chain, confirmed.
    Confirmed,
    /// On the chain, and failed there, with the chain's reason.
    Failed(String),
    /// The RPC node refused the send before sending it on: nothing went.
    Refused(String),
    /// Its blockhash is past and the chain has no trace of it: it did not
    /// land and no longer can.
    Expired,
    /// Not seen landing, and not known to be unable to.
    Unknown,
}

/// What the chain says of `signature`, when it says anything.
async fn landed(url: &str, signature: &str) -> Option<Delivery> {
    let status = rpc(url, "getSignatureStatuses", json!([[signature]]))
        .await
        .ok()?;
    let row = &status["result"]["value"][0];
    if row.is_null() {
        return None;
    }
    if !row["err"].is_null() {
        return Some(Delivery::Failed(row["err"].to_string()));
    }
    matches!(
        row["confirmationStatus"].as_str(),
        Some("confirmed" | "finalized")
    )
    .then_some(Delivery::Confirmed)
}

/// Sends the signed transfer `tx` and follows it to its end.
///
/// `signature` is the transfer's own, taken from `tx` and not from the
/// RPC's answer, so there is something to follow whatever the RPC answers.
/// Only an RPC node's own refusal ([`PREFLIGHT_REFUSALS`]) means nothing was
/// sent. A send that
/// got no answer may have gone out, and saying it had not would have the
/// person send again, under a new blockhash and so as a second transfer:
/// that send is followed like any other, until it lands or until
/// `last_valid_block_height` is past and it no longer can.
async fn deliver(
    url: &str,
    tx: &[u8],
    signature: &str,
    last_valid_block_height: Option<u64>,
    pace: Pace,
) -> Delivery {
    use base64::Engine as _;
    let sent = rpc_call(
        url,
        "sendTransaction",
        json!([
            base64::engine::general_purpose::STANDARD.encode(tx),
            { "encoding": "base64", "preflightCommitment": "confirmed" }
        ]),
    )
    .await;
    match sent {
        Err(RpcFailure::Refused(error)) => return Delivery::Refused(error),
        Err(RpcFailure::NoAnswer(error)) => {
            crate::interrupt::say(&t!("worker_keys.send.may_have_gone", signature, error));
        }
        Ok(_) => {}
    }
    let started = std::time::Instant::now();
    while started.elapsed() < pace.at_most {
        tokio::time::sleep(pace.every).await;
        if let Some(end) = landed(url, signature).await {
            return end;
        }
        let Some(last_valid) = last_valid_block_height else {
            continue;
        };
        let height = rpc(
            url,
            "getBlockHeight",
            json!([{ "commitment": "confirmed" }]),
        )
        .await
        .ok()
        .and_then(|v| v["result"].as_u64());
        if height.is_some_and(|height| height > last_valid) {
            // The last block it could be in is confirmed: one more look,
            // for a transfer that landed between the two questions.
            return landed(url, signature).await.unwrap_or(Delivery::Expired);
        }
    }
    Delivery::Unknown
}

/// A Solana legacy transaction message that moves `lamports` from `from` to
/// `to` through the System program: one signer, the destination writable,
/// the program read-only.
fn transfer_message(
    from: &[u8; 32],
    to: &[u8; 32],
    blockhash: &[u8; 32],
    lamports: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(3 + 1 + 96 + 32 + 1 + 1 + 1 + 2 + 1 + 12);
    // Header: one required signature, no read-only signed, one read-only unsigned.
    m.extend_from_slice(&[1, 0, 1]);
    m.push(3);
    m.extend_from_slice(from);
    m.extend_from_slice(to);
    m.extend_from_slice(&[0_u8; 32]);
    m.extend_from_slice(blockhash);
    m.push(1);
    m.push(2);
    m.extend_from_slice(&[2, 0, 1]);
    m.push(12);
    m.extend_from_slice(&2_u32.to_le_bytes());
    m.extend_from_slice(&lamports.to_le_bytes());
    m
}

/// `erpc worker key send`: SOL out of the trading wallet, to one address,
/// after the person's yes. The key is read here behind the same gate as a
/// run (erpc ai may not), the transfer is signed in memory and sent through
/// the app's own RPC, and the signature is shown.
#[allow(clippy::too_many_lines, reason = "one transfer, read top to bottom")]
pub(crate) async fn send(
    json: bool,
    dir: &Dir,
    to: &str,
    sol: Option<f64>,
    all: bool,
    rpc_flag: Option<&str>,
) -> Outcome {
    use base64::Engine as _;
    let run = async || -> Result<Outcome, CliError> {
        let (_, m) = load(dir)?;
        let Some(wallet) = m.wallet.as_ref() else {
            return Err(failed(t!("worker_keys.balance.no_pubkey", app = m.name)));
        };
        let Some(to_bytes) = erpc_chain_solana::identity::pubkey_bytes(to) else {
            return Err(CliError::new(
                Code::Usage,
                t!("worker_keys.send.bad_pubkey", to),
            ));
        };
        if sol.is_none() != all {
            return Err(CliError::new(
                Code::Usage,
                t!("worker_keys.send.amount_needed"),
            ));
        }
        let url = rpc_url(&m, rpc_flag)?;
        // The key, behind the gate, before anything is read from the chain.
        let keypair =
            worker_secrets::read_key(&wallet.source, wallet.pubkey.as_deref()).map_err(failed)?;
        let from = keypair.pubkey();
        if from == to {
            return Err(CliError::new(Code::Usage, t!("worker_keys.send.same_key")));
        }
        let from_bytes = erpc_chain_solana::identity::pubkey_bytes(&from)
            .ok_or_else(|| failed(t!("worker_keys.send.bad_pubkey", to = from.as_str())))?;
        let network =
            |e: String| CliError::new(Code::Network, t!("worker_keys.send.rpc_failed", error = e));
        let balance = rpc(&url, "getBalance", json!([from]))
            .await
            .map_err(network)?["result"]["value"]
            .as_u64()
            .ok_or_else(|| network(t!("worker_keys.balance.no_balance", status = 200)))?;
        let latest = rpc(
            &url,
            "getLatestBlockhash",
            json!([{ "commitment": "confirmed" }]),
        )
        .await
        .map_err(network)?;
        let blockhash = latest["result"]["value"]["blockhash"]
            .as_str()
            .and_then(erpc_chain_solana::identity::pubkey_bytes)
            .ok_or_else(|| network(t!("worker_keys.send.no_blockhash")))?;
        // The last block the transfer can land in: past it, a transfer the
        // chain has no trace of is known not to have been made.
        let last_valid_block_height = latest["result"]["value"]["lastValidBlockHeight"].as_u64();
        // The fee for this message shape, asked of the RPC; 5000 lamports
        // when it does not say.
        let probe = transfer_message(&from_bytes, &to_bytes, &blockhash, 1);
        let fee = rpc(
            &url,
            "getFeeForMessage",
            json!([base64::engine::general_purpose::STANDARD.encode(&probe), { "commitment": "confirmed" }]),
        )
        .await
        .ok()
        .and_then(|v| v["result"]["value"].as_u64())
        .unwrap_or(5_000);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "an amount typed by the person"
        )]
        let lamports = match sol {
            Some(sol) if sol > 0.0 => (sol * LAMPORTS_PER_SOL).round() as u64,
            Some(_) => {
                return Err(CliError::new(
                    Code::Usage,
                    t!("worker_keys.send.amount_needed"),
                ));
            }
            None => balance.saturating_sub(fee),
        };
        if lamports == 0 || lamports.saturating_add(fee) > balance {
            return Err(failed(t!(
                "worker_keys.send.too_much",
                balance = in_sol(balance),
                amount = in_sol(lamports),
                fee = in_sol(fee)
            )));
        }
        let left = balance - lamports - fee;
        // The address the SOL goes to, as decoded, not as typed.
        let to = erpc_chain_solana::identity::base58(&to_bytes);
        crate::interrupt::say(&t!(
            "worker_keys.send.ask",
            amount = in_sol(lamports),
            from,
            to,
            fee = in_sol(fee),
            left = in_sol(left)
        ));
        // Always asked: a transfer has no -y, so with nobody at a terminal
        // it is refused in its own words, without the hint to pass one.
        if !crate::session::has_terminal() {
            return Err(CliError::new(
                Code::NeedsTerminal,
                t!("worker_keys.send.needs_terminal"),
            ));
        }
        crate::node_common::go_ahead(false, &t!("worker_keys.send.refused"))?;
        let message = transfer_message(&from_bytes, &to_bytes, &blockhash, lamports);
        let signature = keypair.sign(&message);
        let mut tx = Vec::with_capacity(1 + 64 + message.len());
        tx.push(1);
        tx.extend_from_slice(&signature);
        tx.extend_from_slice(&message);
        // The transfer's name is its own signature, known before it is sent.
        let sig = erpc_chain_solana::identity::base58(&signature);
        let confirmed = match deliver(&url, &tx, &sig, last_valid_block_height, PACE).await {
            Delivery::Confirmed => true,
            Delivery::Unknown => false,
            Delivery::Refused(error) => {
                return Err(failed(t!(
                    "worker_keys.send.failed",
                    signature = sig,
                    error
                )));
            }
            Delivery::Failed(error) => {
                return Err(failed(t!(
                    "worker_keys.send.failed_on_chain",
                    signature = sig,
                    error
                )));
            }
            Delivery::Expired => {
                return Err(failed(t!("worker_keys.send.expired", signature = sig)));
            }
        };
        if json {
            crate::print_json(
                &json!({ "from": from, "to": to, "lamports": lamports, "fee": fee, "signature": sig, "confirmed": confirmed }),
            );
            return Ok(Outcome::Done(String::new()));
        }
        let text = if confirmed {
            t!("worker_keys.send.confirmed", signature = sig)
        } else {
            t!(
                "worker_keys.send.not_confirmed",
                signature = sig,
                secs = PACE.at_most.as_secs()
            )
        };
        Ok(Outcome::Done(Report::new().marked("💸", text).text()))
    };
    run().await.unwrap_or_else(Into::into)
}

/// The app's read RPC: `--rpc`, `SOLANA_RPC_ENDPOINT`, or the ERPC edge RPC
/// with `ERPC_API_KEY`, as the template builds it.
fn rpc_url(m: &Manifest, flag: Option<&str>) -> Result<Zeroizing<String>, CliError> {
    let setting = |name: &str| -> Result<Option<Zeroizing<String>>, CliError> {
        if let Some(v) = m.vars.get(name) {
            return Ok(Some(Zeroizing::new(v.clone())));
        }
        m.secrets
            .get(name)
            .map(|r| worker_secrets::read(r).map_err(failed))
            .transpose()
    };
    let url = match flag {
        Some(url) => Zeroizing::new(url.to_owned()),
        None => match setting("SOLANA_RPC_ENDPOINT")? {
            Some(url) => url,
            None => match setting("ERPC_API_KEY")? {
                Some(key) => Zeroizing::new(format!(
                    "{}?api-key={}",
                    erpc_core::endpoints::SHARED_RPC_URL,
                    key.as_str()
                )),
                None => {
                    return Err(
                        failed(t!("worker_keys.rpc.none")).hint(t!("worker_keys.rpc.none_hint"))
                    );
                }
            },
        },
    };
    erpc_core::endpoints::ensure_user_supplied_url(&url)
        .map_err(|e| CliError::new(Code::Usage, t!("worker_keys.rpc.unusable", error = e)))?;
    Ok(url)
}

/// Reads a secret from standard input when it is piped in, else asks for
/// it without echo.
pub(crate) fn read_secret(name: &str) -> Result<Zeroizing<String>, CliError> {
    let stdin = std::io::stdin();
    let mut value = Zeroizing::new(String::new());
    if stdin.is_terminal() {
        let typed = dialoguer::Password::new()
            .with_prompt(t!("worker_keys.secret.prompt", name))
            .interact_on(&dialoguer::console::Term::stderr())
            .map_err(|e| failed(t!("worker_keys.secret.ask_failed", error = e)))?;
        value = Zeroizing::new(typed);
    } else {
        stdin
            .lock()
            .take(MAX_SECRET + 1)
            .read_to_string(&mut value)
            .map_err(|e| failed(t!("worker_keys.secret.stdin_failed", error = e)))?;
        if value.len() as u64 > MAX_SECRET {
            return Err(failed(t!("worker_keys.secret.too_long")));
        }
        // What `echo` and a heredoc add.
        if value.ends_with('\n') {
            value.pop();
            if value.ends_with('\r') {
                value.pop();
            }
        }
    }
    if value.is_empty() {
        return Err(CliError::new(
            Code::Usage,
            t!("worker_keys.secret.empty", name),
        ));
    }
    Ok(value)
}

/// Where the value `erpc worker secret put` keeps comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value {
    /// Typed without echo, or piped in on standard input.
    Typed,
    /// `--generate`: made here, for a token of the app's own that nobody
    /// has to know (the bot's `API_TOKEN`).
    Generated,
    /// `--from-account`: the signed-in account's RPC API key, read from
    /// the account once the rest of the command is known to hold.
    Account,
}

/// Where the value `secret put` kept came from, for what it says after:
/// [`Value`], and of a value read from the account, which of its keys it
/// is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Came {
    Typed,
    Generated,
    Account(AccountKey),
}

impl Came {
    /// As `--json` names it, under `from`.
    const fn word(self) -> &'static str {
        match self {
            Self::Typed => "typed",
            Self::Generated => "generated",
            Self::Account(_) => "account",
        }
    }

    /// As `--json` names which of the account's keys it is, under
    /// `account_key`: `primary` or `other`, and null for a value that is
    /// not the account's.
    const fn account_key(self) -> Option<&'static str> {
        match self {
            Self::Account(which) => Some(which.word()),
            Self::Typed | Self::Generated => None,
        }
    }
}

/// What `secret put` takes from outside itself, each asked for only once
/// the command has got that far: the store a new secret goes in on this
/// machine, a value from the person, and the signed-in account's key. The
/// real one is [`Outside`]; a test brings its own, which answers from a
/// script and keeps what it was asked.
trait Sources {
    /// The store a new secret goes in, from `--store` and `--vault`.
    fn store(&self, flag: Option<StoreFlag>, vault: Option<&str>) -> Result<Store, String>;

    /// The value of `name`, typed without echo or piped in on standard
    /// input.
    fn typed(&self, name: &str) -> Result<Zeroizing<String>, CliError>;

    /// The signed-in account's API keys for the shared RPC, tried from
    /// this machine.
    async fn account(&self) -> Result<Tried, CliError>;
}

/// This machine, the person at it and the signed-in account.
struct Outside;

impl Sources for Outside {
    fn store(&self, flag: Option<StoreFlag>, vault: Option<&str>) -> Result<Store, String> {
        worker_secrets::choose(flag, vault)
    }

    fn typed(&self, name: &str) -> Result<Zeroizing<String>, CliError> {
        read_secret(name)
    }

    async fn account(&self) -> Result<Tried, CliError> {
        crate::worker_vps::account_keys_tried().await
    }
}

/// How many random bytes a generated secret is made of: 64 hexadecimal
/// characters.
const GENERATED_BYTES: usize = 32;

/// A new random secret, as hexadecimal.
fn generate() -> Result<Zeroizing<String>, CliError> {
    use core::fmt::Write as _;
    let mut bytes = Zeroizing::new([0_u8; GENERATED_BYTES]);
    aws_lc_rs::rand::fill(bytes.as_mut()).map_err(|_| failed(t!("worker_keys.put.no_random")))?;
    let mut text = Zeroizing::new(String::with_capacity(GENERATED_BYTES * 2));
    for byte in bytes.iter() {
        let _ = write!(text, "{byte:02x}");
    }
    Ok(text)
}

/// What `secret put` kept, for what it says after. The value is not in
/// it: it is never shown, so a value nobody typed is said to be what it
/// is.
struct PutSecret {
    name: String,
    reference: SecretRef,
    /// What the name was set to before this, with `--replace`.
    old: Option<SecretRef>,
    came: Came,
    store: Store,
    /// What to heed about where it is kept.
    cautions: Report,
}

impl PutSecret {
    /// What `--json` prints.
    fn body(&self) -> serde_json::Value {
        json!({
            "name": self.name,
            "source": self.reference,
            "replaced": self.old,
            "from": self.came.word(),
            "account_key": self.came.account_key(),
        })
    }

    /// What a person is told.
    fn text(self) -> String {
        let mut report = Report::new().done(t!(
            "worker_keys.put.done",
            name = self.name,
            source = self.reference,
            store = self.store.describe()
        ));
        report = match self.came {
            Came::Generated => report.info(t!("worker_keys.put.generated")),
            Came::Account(AccountKey::Primary) => report.info(t!("worker_keys.put.from_account")),
            Came::Account(AccountKey::Other) => {
                report.info(t!("worker_keys.put.from_account_other"))
            }
            Came::Typed => report,
        };
        // A keychain or keystore entry under the same account was overwritten
        // in place.
        if let Some(old) = self.old.filter(|o| *o != self.reference) {
            report = report.info(t!("worker_keys.put.old_kept", old));
        }
        report.extend(self.cautions).text()
    }

    /// What the command says: the JSON under `--json`, the text otherwise.
    fn said(self, json: bool) -> Said {
        if json {
            Said::Json(self.body())
        } else {
            Said::Text(self.text())
        }
    }
}

/// `erpc worker secret put`: keeps a value and names it in `[secrets]`.
pub(crate) async fn put(
    json: bool,
    dir: &Dir,
    name: &str,
    store: Option<StoreFlag>,
    vault: Option<&str>,
    replace: bool,
    value: Value,
) -> Outcome {
    match put_from(&Outside, dir, name, (store, vault), replace, value).await {
        Ok(kept) => kept.said(json).done(),
        Err(e) => e.into(),
    }
}

/// The command that keeps `name` by hand, typed or piped in, for the app
/// at `dir`: what a hint names when `--from-account` kept nothing. It
/// carries `--replace` when the command had it: without, following the
/// hint would be refused for a name that is set already.
fn by_hand(name: &str, replace: bool, dir: &Dir) -> String {
    let (replace, dir_scope) = (if replace { " --replace" } else { "" }, dir.scope());
    format!("erpc worker secret put {name}{replace}{dir_scope}")
}

/// [`put`], taking from `from` what it does not have itself.
///
/// Everything that can refuse the command comes before its value: the
/// name, the app's `erpc.toml`, a name set already without `--replace`,
/// the store, and the keystore's passphrase. Only then is the value
/// typed, made, or read from the account, so a command that is going to
/// be refused costs nobody a value, and asks nothing of user-api or the
/// RPC.
///
/// Of the account's keys, only one the shared RPC accepted is kept. The
/// value is seen by nobody, so a key that then fails on the server would
/// be found out only there: nothing is kept when every key was refused,
/// and nothing when none was accepted and the RPC could not be asked
/// about one, which the same command run again settles.
async fn put_from(
    from: &impl Sources,
    dir: &Dir,
    name: &str,
    (store, vault): (Option<StoreFlag>, Option<&str>),
    replace: bool,
    value: Value,
) -> Result<PutSecret, CliError> {
    manifest::check_setting_name(name)
        .map_err(|e| CliError::new(Code::Usage, format!("{name}: {e}")))?;
    let (path, m) = load(dir)?;
    if m.vars.contains_key(name) {
        return Err(failed(t!("worker_keys.put.in_vars", name)));
    }
    let old = m.secrets.get(name).cloned();
    if let Some(source) = old.as_ref().filter(|_| !replace) {
        return Err(failed(t!("worker_keys.put.already", name, source))
            .hint(t!("worker_keys.put.replace_hint"))
            .mark("🔑"));
    }
    let store = from.store(store, vault).map_err(failed)?;
    // A name the store cannot keep is said before anything is typed.
    worker_secrets::may_keep(&store, &m.name, name).map_err(|e| CliError::new(Code::Usage, e))?;
    // A keystore is opened, or made, before the value is typed: a
    // passphrase that does not open it must not cost the value.
    worker_secrets::ready(&store).map_err(failed)?;
    let (secret, came) = match value {
        Value::Typed => (from.typed(name)?, Came::Typed),
        Value::Generated => (generate()?, Came::Generated),
        Value::Account => match from.account().await? {
            Tried::Usable {
                key,
                accepted: true,
                which,
            } => (key, Came::Account(which)),
            // Not kept: the RPC accepted no key, and of this one it said
            // nothing. Run again, the command asks again.
            Tried::Usable {
                accepted: false, ..
            } => {
                let command = by_hand(name, replace, dir);
                return Err(failed(t!("worker_keys.put.account_unasked"))
                    .hint(t!("worker_keys.put.account_unasked_hint", command)));
            }
            // Not kept either. The key may still be a good one for the
            // server (one limited to its address), so the hint is how to
            // keep that one by hand.
            Tried::Refused { tried, .. } => {
                let command = by_hand(name, replace, dir);
                return Err(crate::worker_vps::keys_refused(tried)
                    .hint(t!("worker_keys.put.account_refused_hint", command)));
            }
        },
    };
    let reference = worker_secrets::put(&store, &m.name, name, &secret).map_err(failed)?;
    drop(secret);
    rewrite(&path, |text| edit::set_secret(text, name, &reference))
        .map_err(|e| e.hint(t!("worker_keys.put.by_hand", source = reference, name)))?;
    Ok(PutSecret {
        name: name.to_owned(),
        cautions: portability(&m, &store),
        reference,
        old,
        came,
        store,
    })
}

/// `erpc worker secret list`: every secret by name and reference, and the
/// required settings not set.
pub(crate) fn list(json: bool, dir: &Dir) -> Outcome {
    let (_, m) = match load(dir) {
        Ok(found) => found,
        Err(e) => return e.into(),
    };
    if json {
        crate::print_json(&json!({ "secrets": m.secrets, "missing": m.missing() }));
        return Outcome::Done(String::new());
    }
    // A set of settings reads "A or B".
    let missing: Vec<String> = m.missing().iter().map(ToString::to_string).collect();
    let scope = dir.scope();
    let mut lines: Vec<String> = m
        .secrets
        .iter()
        .map(|(name, r)| format!("{name}  {r}"))
        .collect();
    if lines.is_empty() {
        lines.push(t!("worker_keys.list.none", dir_scope = scope));
    }
    for name in &missing {
        lines.push(t!("worker_keys.list.missing_plain", name));
    }
    let mut report = Report::new();
    if m.secrets.is_empty() {
        report = report.info(t!("worker_keys.list.none", dir_scope = scope));
    } else {
        report = report
            .marked("🔐", t!("worker_keys.list.title", app = m.name))
            .fields(
                m.secrets
                    .iter()
                    .map(|(name, r)| (name.clone(), r.to_string())),
            );
    }
    for name in missing {
        report = report.warning(t!("worker_keys.list.missing", name));
    }
    Outcome::Done(report.or_plain(lines.join("\n")))
}

/// `erpc worker secret rm`: removes a secret's reference. A value kept in
/// 1Password or the keychain stays there, which erpc does not delete from;
/// one kept in the keystore is deleted with it, unless another setting of
/// the app names the same entry.
pub(crate) fn remove(json: bool, dir: &Dir, name: &str) -> Outcome {
    use crate::worker_secrets::Fate;
    let (path, m) = match load(dir) {
        Ok(found) => found,
        Err(e) => return e.into(),
    };
    let Some(reference) = m.secrets.get(name).cloned() else {
        return failed(t!("worker_keys.rm.not_there", name)).into();
    };
    // erpc.toml first: a value deleted and still named would be worse than
    // one named no longer and still kept.
    if let Err(e) = rewrite(&path, |text| {
        edit::remove_secret(text, name).map(|(t, _)| t)
    }) {
        return e.into();
    }
    let fate = worker_secrets::forget(&m, name, &reference);
    if json {
        let still_kept = !matches!(fate, Fate::Deleted | Fate::Absent);
        crate::print_json(&json!({
            "name": name,
            "removed": true,
            "still_kept_at": still_kept.then_some(&reference),
            "deleted": fate == Fate::Deleted,
        }));
        return Outcome::Done(String::new());
    }
    let done = Report::new().done(t!("worker_keys.rm.done", name));
    let source = &reference;
    Outcome::Done(match fate {
        Fate::Kept => done
            .info(t!("worker_keys.rm.still_kept", source))
            .or_plain(t!("worker_keys.rm.plain", name, source)),
        Fate::Deleted => done.info(t!("worker_keys.rm.deleted", source)).text(),
        Fate::Absent => done.info(t!("worker_keys.rm.absent", source)).text(),
        Fate::Shared(other) => done.info(t!("worker_keys.rm.shared", source, other)).text(),
        Fate::Key => done.info(t!("worker_keys.rm.is_key", source)).text(),
        Fate::NotDeleted(error) => done
            .warning(t!("worker_keys.rm.not_deleted", source, error))
            .text(),
    })
}

#[cfg(test)]
mod tests {

    /// A made-up 1Password vault id, of the shape a real one has.
    const OP_VAULT: &str = "abcdefghijklmnopqrstuvwxyz";
    use erpc_auth::store::keystore::Kind;
    use erpc_chain_solana::identity::Keypair;

    use serde_json::json;
    use zeroize::Zeroizing;

    use super::{read_key_file, wipe_file};
    use crate::error::CliError;
    use crate::worker_secrets;
    use crate::worker_vps::fake::Scripted;

    /// An app directory with `manifest` as its erpc.toml.
    fn app(tag: &str, manifest: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("erpc-w-plain-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("dir");
        std::fs::write(root.join("erpc.toml"), manifest).expect("toml");
        root
    }

    fn dir_of(root: &std::path::Path) -> crate::worker::Dir {
        crate::worker::Dir::at(root)
    }

    fn done(outcome: crate::commands::Outcome) -> String {
        match outcome {
            crate::commands::Outcome::Done(text) => text,
            other => panic!("not done: {:?}", other.error()),
        }
    }

    /// The key the scripted account gives, and the shared RPC takes.
    const ACCOUNT_KEY: &str = "the-accounts-rpc-key";

    /// What a test gives `secret put` in place of this machine, the person
    /// at it and the account: the store, what the person types, and an
    /// account whose user-api and RPC answer from a script. It keeps what
    /// it was asked.
    struct Given {
        store: Result<super::Store, String>,
        types: Option<&'static str>,
        account: Scripted,
        stores: std::cell::RefCell<Vec<(Option<super::StoreFlag>, Option<String>)>>,
        typed: std::cell::RefCell<Vec<String>>,
    }

    /// What a [`Given`] was asked: how many times for the store, the names
    /// the person was asked to type a value for, how many times user-api
    /// was read, and the keys the shared RPC was asked about.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct Asked {
        stores: usize,
        typed: Vec<String>,
        account_reads: usize,
        keys_tried: Vec<String>,
    }

    impl Given {
        /// The thread's keystore, a person who types nothing, and an
        /// account with one key, which the shared RPC takes.
        fn keystore() -> Self {
            Self {
                store: Ok(super::Store::Keystore { by_default: false }),
                types: None,
                account: Scripted::account(&json!({ "apiKey": ACCOUNT_KEY })),
                stores: std::cell::RefCell::new(Vec::new()),
                typed: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn asked(&self) -> Asked {
            Asked {
                stores: self.stores.borrow().len(),
                typed: self.typed.borrow().clone(),
                account_reads: self.account.reads.get(),
                keys_tried: self.account.asked(),
            }
        }
    }

    impl super::Sources for Given {
        fn store(
            &self,
            flag: Option<super::StoreFlag>,
            vault: Option<&str>,
        ) -> Result<super::Store, String> {
            self.stores
                .borrow_mut()
                .push((flag, vault.map(ToOwned::to_owned)));
            self.store.clone()
        }

        fn typed(&self, name: &str) -> Result<Zeroizing<String>, CliError> {
            self.typed.borrow_mut().push(name.to_owned());
            self.types
                .map(|value| Zeroizing::new(value.to_owned()))
                .ok_or_else(|| super::failed("the test has nobody typing"))
        }

        fn account(&self) -> impl Future<Output = Result<super::Tried, CliError>> {
            crate::worker_vps::keys_tried(&self.account)
        }
    }

    /// What is kept under `reference`, read back from the store.
    fn kept_at(reference: &erpc_worker::manifest::SecretRef) -> Zeroizing<String> {
        worker_secrets::read(reference).expect("read back")
    }

    const PUT_KEPT_IN_KEYSTORE: &str = "kept in the encrypted keystore on this machine";

    /// What is said of a value that is the account's primary key, and of
    /// one that is another of its keys.
    const FROM_THE_PRIMARY_KEY: &str = "Its value is the signed-in account's primary RPC API key, \
                                        read from the account and shown to nobody.";
    const FROM_ANOTHER_KEY: &str = "Its value is one of the signed-in account's other RPC API \
                                    keys, not its primary one, read from the account and shown \
                                    to nobody.";

    /// `erpc worker secret put ERPC_API_KEY --from-account` for the app at
    /// `root`, with `--replace` or without.
    async fn put_account(
        given: &Given,
        root: &std::path::Path,
        replace: bool,
    ) -> Result<super::PutSecret, CliError> {
        super::put_from(
            given,
            &dir_of(root),
            "ERPC_API_KEY",
            (None, None),
            replace,
            super::Value::Account,
        )
        .await
    }

    /// The same, where the command is to keep nothing: its error.
    async fn not_kept(given: &Given, root: &std::path::Path, replace: bool) -> CliError {
        match put_account(given, root, replace).await {
            Ok(kept) => panic!("kept at {}", kept.reference),
            Err(e) => e,
        }
    }

    /// An account with `keys`, the first its primary one, of which the
    /// shared RPC makes `verdicts`: it takes a key that none is given for.
    fn account_of(keys: &[&str], verdicts: &[(&'static str, crate::worker_vps::Verdict)]) -> Given {
        let mut account = Scripted::account(&json!({ "apiKey": keys[0], "activeApiKeys": keys }));
        for (key, verdict) in verdicts {
            account = account.with(key, *verdict);
        }
        Given {
            account,
            ..Given::keystore()
        }
    }

    #[tokio::test]
    async fn a_generated_secret_is_64_hex_characters_shown_to_nobody_and_new_each_time() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _keystore = set_up(&desk);
        let root = app("put-generated", "name = \"bot\"\nchain = \"solana\"\n");
        let given = Given::keystore();
        let put = async |replace| {
            super::put_from(
                &given,
                &dir_of(&root),
                "API_TOKEN",
                (Some(super::StoreFlag::Keystore), None),
                replace,
                super::Value::Generated,
            )
            .await
            .expect("kept")
        };
        let first = put(false).await;
        let source = "keystore:erpc-worker/bot.API_TOKEN";
        assert_eq!(first.reference.to_string(), source);
        let value = kept_at(&first.reference);
        // 32 random bytes, as lowercase hexadecimal.
        assert_eq!(value.len(), 64, "64 characters");
        assert!(
            value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "lowercase hexadecimal"
        );
        let mut shown = vec![first.body().to_string()];
        assert_eq!(
            first.body(),
            json!({
                "name": "API_TOKEN", "source": source, "replaced": null,
                "from": "generated", "account_key": null,
            })
        );
        let said = first.text();
        assert_eq!(
            said,
            format!(
                "API_TOKEN ← {source}, {PUT_KEPT_IN_KEYSTORE}\nIts value was made here: 64 random \
                 hexadecimal characters, shown to nobody."
            )
        );
        shown.push(said);
        assert!(
            std::fs::read_to_string(root.join("erpc.toml"))
                .expect("toml")
                .contains(&format!("API_TOKEN = \"{source}\"")),
        );
        // Made again in its place: another value, of the same shape.
        let second = put(true).await;
        let again = kept_at(&second.reference);
        assert_eq!(again.len(), 64);
        assert_ne!(again.as_str(), value.as_str(), "a new value each time");
        assert_eq!(
            second.body(),
            json!({
                "name": "API_TOKEN", "source": source, "replaced": source,
                "from": "generated", "account_key": null,
            })
        );
        shown.push(second.body().to_string());
        shown.push(second.text());
        // Neither value is in anything the command says.
        for said in &shown {
            assert!(!said.contains(value.as_str()), "{said}");
            assert!(!said.contains(again.as_str()), "{said}");
        }
        // The store was chosen from the flags, and nothing else was asked:
        // nobody typed, and neither user-api nor the RPC was reached.
        assert_eq!(
            *given.stores.borrow(),
            vec![(Some(super::StoreFlag::Keystore), None); 2]
        );
        assert_eq!(
            given.asked(),
            Asked {
                stores: 2,
                ..Asked::default()
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_secret_from_the_account_is_the_key_the_account_gives_shown_to_nobody() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        use crate::worker_vps::Verdict;
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _keystore = set_up(&desk);
        let root = app("put-account", "name = \"bot\"\nchain = \"solana\"\n");
        // An account whose primary key has run out, and whose second works.
        let given = Given {
            account: Scripted::account(&json!({
                "apiKey": "a-key-that-ended",
                "activeApiKeys": ["a-key-that-ended", ACCOUNT_KEY],
            }))
            .with("a-key-that-ended", Verdict::Refused),
            ..Given::keystore()
        };
        let Ok(kept) = put_account(&given, &root, false).await else {
            panic!("not kept");
        };
        let source = "keystore:erpc-worker/bot.ERPC_API_KEY";
        // Exactly the key the account gave, and the one the RPC takes:
        // not the account's primary one, which is said.
        assert_eq!(kept_at(&kept.reference).as_str(), ACCOUNT_KEY);
        let body = kept.body();
        assert_eq!(
            body,
            json!({
                "name": "ERPC_API_KEY", "source": source, "replaced": null,
                "from": "account", "account_key": "other",
            })
        );
        let said = kept.text();
        assert_eq!(
            said,
            format!("ERPC_API_KEY ← {source}, {PUT_KEPT_IN_KEYSTORE}\n{FROM_ANOTHER_KEY}")
        );
        for said in [said, body.to_string()] {
            assert!(!said.contains(ACCOUNT_KEY), "{said}");
            assert!(!said.contains("a-key-that-ended"), "{said}");
        }
        // The account was read once, and nobody was asked to type.
        assert_eq!(
            given.asked(),
            Asked {
                stores: 1,
                typed: Vec::new(),
                account_reads: 1,
                keys_tried: vec!["a-key-that-ended".to_owned(), ACCOUNT_KEY.to_owned()],
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `--from-account` keeps a key the shared RPC accepted, and says which
    /// of the account's keys it is, in the text and as `account_key`.
    #[tokio::test]
    async fn a_key_kept_from_the_account_is_said_to_be_the_primary_one_or_another() {
        use crate::i18n::speaking;
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        use crate::worker_vps::Verdict;
        use erpc_core::i18n::Lang;
        use futures_util::FutureExt as _;
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _keystore = set_up(&desk);
        let root = app("put-account-which", "name = \"bot\"\nchain = \"solana\"\n");
        let source = "keystore:erpc-worker/bot.ERPC_API_KEY";
        // The primary key accepted: kept, and no other is asked about.
        let primary = || account_of(&[ACCOUNT_KEY, "another-key"], &[]);
        // The primary key not to be asked about, and the second accepted:
        // the second is kept, though the first was not refused.
        let away = "not-to-be-asked-about";
        let other = || account_of(&[away, ACCOUNT_KEY], &[(away, Verdict::Unknown)]);
        for (given, which, sentence, tried) in [
            (
                primary(),
                "primary",
                FROM_THE_PRIMARY_KEY,
                vec![ACCOUNT_KEY],
            ),
            (other(), "other", FROM_ANOTHER_KEY, vec![away, ACCOUNT_KEY]),
        ] {
            // Each in place of what the round before kept (--replace).
            let Ok(kept) = put_account(&given, &root, true).await else {
                panic!("{which}: not kept");
            };
            assert_eq!(kept_at(&kept.reference).as_str(), ACCOUNT_KEY, "{which}");
            let body = kept.body();
            assert_eq!(body["from"], "account", "{which}");
            assert_eq!(body["account_key"], which);
            let said = kept.text();
            assert_eq!(
                said,
                format!("ERPC_API_KEY ← {source}, {PUT_KEPT_IN_KEYSTORE}\n{sentence}")
            );
            for said in [said, body.to_string()] {
                for key in [ACCOUNT_KEY, "another-key", away] {
                    assert!(!said.contains(key), "{said}");
                }
            }
            assert_eq!(given.asked().keys_tried, tried, "{which}");
        }
        // Said in the language of the run, and the two apart.
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let said = |given: Given| {
                speaking(lang, || {
                    let put = put_account(&given, &root, true).now_or_never();
                    let Some(Ok(kept)) = put else {
                        panic!("{lang:?}: not kept");
                    };
                    kept.text()
                })
            };
            let (of_primary, of_other) = (said(primary()), said(other()));
            assert_ne!(of_primary, of_other, "{lang:?}");
            for (said, english) in [
                (&of_primary, FROM_THE_PRIMARY_KEY),
                (&of_other, FROM_ANOTHER_KEY),
            ] {
                assert_ne!(said.lines().last(), Some(english), "{lang:?}");
                assert!(!said.contains('{'), "{said}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// No key accepted, and one the shared RPC could not be asked about:
    /// `--from-account` keeps nothing, and says to run it again.
    #[tokio::test]
    async fn an_account_the_shared_rpc_could_not_be_asked_about_keeps_nothing() {
        use crate::error::Code;
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        use crate::worker_vps::Verdict;
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        let manifest = "name = \"bot\"\nchain = \"solana\"\n";
        let root = app("put-account-unasked", manifest);
        let scope = dir_of(&root).scope();
        let unasked = format!(
            "error: the shared RPC could not be asked about the account's API keys just now (it \
             took none, and for one at least it gave no answer, or one that says nothing of the \
             key), so nothing was kept\nhint: run the same command again in a while; or keep the \
             key you mean by hand with `erpc worker secret put ERPC_API_KEY{scope}`, typed unseen \
             or piped in"
        );
        // An account alone with its primary key; and one whose primary
        // key is refused beside another that could not be asked about.
        let (only, ended, second) = ("the-only-key", "a-key-that-ended", "the-second-key");
        for (keys, verdicts) in [
            (vec![only], vec![(only, Verdict::Unknown)]),
            (
                vec![ended, second],
                vec![(ended, Verdict::Refused), (second, Verdict::Unknown)],
            ),
        ] {
            let given = account_of(&keys, &verdicts);
            let e = not_kept(&given, &root, false).await;
            assert_eq!(e.text(), unasked);
            assert_eq!(e.code, Code::Failed);
            // No key is in what is said, and none was kept: no entry, and
            // erpc.toml as it was.
            let said = format!("{} {}", e.text(), e.json());
            for key in &keys {
                assert!(!said.contains(key), "{said}");
            }
            assert!(
                !keystore
                    .entry_path("erpc-worker", "bot.ERPC_API_KEY")
                    .expect("named")
                    .exists()
            );
            assert_eq!(
                std::fs::read_to_string(root.join("erpc.toml")).expect("toml"),
                manifest
            );
            // Every key was asked about, once, before it gave up.
            assert_eq!(given.asked().account_reads, 1);
            assert_eq!(given.asked().keys_tried, keys);
        }
        // The command the hint names is one erpc takes.
        let words = format!("erpc worker secret put ERPC_API_KEY{scope}");
        assert!(
            <crate::Cli as clap::Parser>::try_parse_from(words.split_whitespace()).is_ok(),
            "{words}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `--from-account --replace` that keeps nothing leaves what was kept
    /// before as it was, and the command its hint names carries
    /// `--replace`: without, following the hint would be refused.
    #[tokio::test]
    async fn from_account_replace_that_keeps_nothing_leaves_the_old_value_and_hints_at_replace() {
        use crate::i18n::speaking;
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        use crate::worker_vps::Verdict;
        use erpc_core::i18n::Lang;
        use futures_util::FutureExt as _;
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        let store = super::Store::Keystore { by_default: false };
        let before = Zeroizing::new("the-key-kept-before".to_owned());
        let reference = worker_secrets::put(&store, "bot", "ERPC_API_KEY", &before).expect("kept");
        let manifest = format!(
            "name = \"bot\"\nchain = \"solana\"\n[secrets]\nERPC_API_KEY = \"{reference}\"\n"
        );
        let root = app("put-account-replace", &manifest);
        let file = keystore
            .entry_path("erpc-worker", "bot.ERPC_API_KEY")
            .expect("named");
        let sealed = std::fs::read(&file).expect("the entry");
        let command = format!(
            "erpc worker secret put ERPC_API_KEY --replace{}",
            dir_of(&root).scope()
        );
        let key = "the-accounts-key";
        for (verdict, message) in [
            (Verdict::Refused, "the shared RPC takes none of the account"),
            (Verdict::Unknown, "the shared RPC could not be asked about"),
        ] {
            let given = || account_of(&[key], &[(key, verdict)]);
            let e = not_kept(&given(), &root, true).await;
            assert!(e.message.starts_with(message), "{}", e.message);
            let hint = e.hint.clone().expect("a hint");
            assert!(hint.contains(&format!("`{command}`")), "{hint}");
            // The value kept before is as it was, and so is erpc.toml.
            assert_eq!(std::fs::read(&file).expect("the entry"), sealed);
            assert_eq!(kept_at(&reference).as_str(), before.as_str());
            assert_eq!(
                std::fs::read_to_string(root.join("erpc.toml")).expect("toml"),
                manifest
            );
            let said = format!("{} {}", e.text(), e.json());
            assert!(!said.contains(key), "{said}");
            assert!(!said.contains(before.as_str()), "{said}");
            // Said in the language of the run, with the same command.
            for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
                let there = speaking(lang, || not_kept(&given(), &root, true).now_or_never())
                    .expect("the doubles answer at once");
                assert_ne!(there.message, e.message, "{lang:?}");
                assert_ne!(there.hint, e.hint, "{lang:?}");
                let said = there.text();
                assert!(said.contains(&format!("`{command}`")), "{said}");
                assert!(!said.contains('{'), "{said}");
            }
        }
        // The command the hint names is one erpc takes.
        assert!(
            <crate::Cli as clap::Parser>::try_parse_from(command.split_whitespace()).is_ok(),
            "{command}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every key of the account refused from this machine: `--from-account`
    /// keeps nothing, and says how the key is kept by hand.
    #[tokio::test]
    async fn an_account_whose_keys_this_machine_is_refused_with_keeps_nothing_and_names_the_way_out()
     {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        use crate::worker_vps::Verdict;
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        let manifest = "name = \"bot\"\nchain = \"solana\"\n";
        let root = app("put-account-refused", manifest);
        let given = Given {
            account: Scripted::account(&json!({
                "apiKey": "for-the-server-only",
                "activeApiKeys": ["a-key-that-ended", "for-the-server-only"],
            }))
            .with("for-the-server-only", Verdict::Refused)
            .with("a-key-that-ended", Verdict::Refused),
            ..Given::keystore()
        };
        let e = super::put_from(
            &given,
            &dir_of(&root),
            "ERPC_API_KEY",
            (None, None),
            false,
            super::Value::Account,
        )
        .await
        .err()
        .expect("refused");
        let scope = dir_of(&root).scope();
        assert_eq!(
            e.text(),
            format!(
                "error: the shared RPC takes none of the account's API keys from this machine (2 \
                 tried)\nhint: the keys were tried from this machine, where a key limited to \
                 other addresses (the server's, say) is refused though it works from those: \
                 keep such a key by hand with `erpc worker secret put ERPC_API_KEY{scope}`, typed \
                 unseen or piped in; a key can also have an end date, and the account's RPC plan \
                 can have ended, which the ERPC dashboard shows"
            )
        );
        // The command the hint names is one erpc takes.
        let words = format!("erpc worker secret put ERPC_API_KEY{scope}");
        assert!(
            <crate::Cli as clap::Parser>::try_parse_from(words.split_whitespace()).is_ok(),
            "{words}"
        );
        // Neither key is in what is said, and neither was kept: no entry,
        // and erpc.toml as it was.
        let said = format!("{} {}", e.text(), e.json());
        for key in ["for-the-server-only", "a-key-that-ended"] {
            assert!(!said.contains(key), "{said}");
        }
        assert!(
            !keystore
                .entry_path("erpc-worker", "bot.ERPC_API_KEY")
                .expect("named")
                .exists()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("erpc.toml")).expect("toml"),
            manifest
        );
        assert_eq!(given.asked().account_reads, 1);
        assert_eq!(
            given.asked().keys_tried,
            ["for-the-server-only", "a-key-that-ended"]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_typed_secret_is_what_the_person_gave_asked_for_once() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _keystore = set_up(&desk);
        let root = app("put-typed", "name = \"bot\"\nchain = \"solana\"\n");
        let given = Given {
            types: Some("typed-by-the-person"),
            ..Given::keystore()
        };
        let kept = super::put_from(
            &given,
            &dir_of(&root),
            "X_TOKEN",
            (None, None),
            false,
            super::Value::Typed,
        )
        .await
        .expect("kept");
        let source = "keystore:erpc-worker/bot.X_TOKEN";
        assert_eq!(kept_at(&kept.reference).as_str(), "typed-by-the-person");
        let body = kept.body();
        assert_eq!(
            body,
            json!({
                "name": "X_TOKEN", "source": source, "replaced": null,
                "from": "typed", "account_key": null,
            })
        );
        // Nothing is said of where a typed value came from.
        let said = kept.text();
        assert_eq!(said, format!("X_TOKEN ← {source}, {PUT_KEPT_IN_KEYSTORE}"));
        for said in [said, body.to_string()] {
            assert!(!said.contains("typed-by-the-person"), "{said}");
        }
        assert_eq!(
            given.asked(),
            Asked {
                stores: 1,
                typed: vec!["X_TOKEN".to_owned()],
                ..Asked::default()
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_name_set_already_is_refused_before_a_value_is_typed_made_or_read() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        let store = super::Store::Keystore { by_default: false };
        let first = Zeroizing::new("the-value-kept-first".to_owned());
        let reference = worker_secrets::put(&store, "bot", "API_TOKEN", &first).expect("kept");
        let manifest =
            format!("name = \"bot\"\nchain = \"solana\"\n[secrets]\nAPI_TOKEN = \"{reference}\"\n");
        let root = app("put-already", &manifest);
        let file = keystore
            .entry_path("erpc-worker", "bot.API_TOKEN")
            .expect("named");
        let sealed = std::fs::read(&file).expect("the entry");
        for value in [
            super::Value::Typed,
            super::Value::Generated,
            super::Value::Account,
        ] {
            let given = Given {
                types: Some("another-value"),
                ..Given::keystore()
            };
            let e = super::put_from(
                &given,
                &dir_of(&root),
                "API_TOKEN",
                (None, None),
                false,
                value,
            )
            .await
            .err()
            .expect("refused");
            assert_eq!(
                e.text(),
                format!(
                    "error: API_TOKEN is set already ({reference})\nhint: pass --replace to keep \
                     a new value in its place"
                ),
                "{value:?}"
            );
            // Refused before the store is chosen, a value typed or made,
            // or anything asked of the account: what was kept is as it was.
            assert_eq!(given.asked(), Asked::default(), "{value:?}");
            assert_eq!(std::fs::read(&file).expect("the entry"), sealed);
            assert_eq!(kept_at(&reference).as_str(), first.as_str());
            assert_eq!(
                std::fs::read_to_string(root.join("erpc.toml")).expect("toml"),
                manifest
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// What `secret put` says is chosen by `--json`: the JSON with it, the
    /// text without.
    #[test]
    fn secret_put_says_json_under_json_and_text_otherwise() {
        use crate::commands::{Outcome, Said};
        use erpc_worker::manifest::SecretRef;
        crate::ui::force_drawn(false);
        let kept = || super::PutSecret {
            name: "X_TOKEN".to_owned(),
            reference: SecretRef::parse("keychain:erpc-worker/bot.X_TOKEN").expect("a reference"),
            old: None,
            came: super::Came::Generated,
            store: super::Store::Keychain,
            cautions: crate::ui::Report::new(),
        };
        let (body, text) = (kept().body(), kept().text());
        assert_eq!(body["from"], "generated");
        assert!(
            text.starts_with("X_TOKEN ← keychain:erpc-worker/bot.X_TOKEN, kept in "),
            "{text}"
        );
        assert_eq!(kept().said(true), Said::Json(body));
        assert_eq!(kept().said(false), Said::Text(text.clone()));
        // Text is handed on, to be printed where every outcome is.
        let Outcome::Done(handed_on) = Said::Text(text.clone()).done() else {
            panic!("not done");
        };
        assert_eq!(handed_on, text);
    }

    /// The store opens before a value is asked for: a keystore that does
    /// not open costs nobody a value they typed.
    #[tokio::test]
    async fn a_value_is_not_asked_for_before_the_store_opens() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        let manifest = "name = \"bot\"\nchain = \"solana\"\n";
        let root = app("put-locked", manifest);
        let put = async |given: &Given, value| {
            super::put_from(given, &dir_of(&root), "X_TOKEN", (None, None), false, value).await
        };
        let typing = || Given {
            types: Some("typed-by-the-person"),
            ..Given::keystore()
        };
        // A keystore that is there (it holds another app's secret), locked,
        // with nobody at a terminal to open it.
        let store = super::Store::Keystore { by_default: false };
        let other = Zeroizing::new("kept-before".to_owned());
        worker_secrets::put(&store, "other-app", "X_TOKEN", &other).expect("kept");
        desk.lock();
        desk.terminal.set(false);
        for value in [super::Value::Typed, super::Value::Generated] {
            let given = typing();
            let Err(e) = put(&given, value).await else {
                panic!("{value:?}: kept");
            };
            assert!(
                e.message.contains("`erpc worker secret unlock`"),
                "{value:?}: {}",
                e.message
            );
            // The store was chosen, and nobody was asked for a value.
            let chosen = Asked {
                stores: 1,
                ..Asked::default()
            };
            assert_eq!(given.asked(), chosen, "{value:?}");
            assert!(
                !keystore
                    .entry_path("erpc-worker", "bot.X_TOKEN")
                    .expect("named")
                    .exists()
            );
            assert_eq!(
                std::fs::read_to_string(root.join("erpc.toml")).expect("toml"),
                manifest
            );
        }
        // Once it opens, the value is asked for, and kept.
        desk.terminal.set(true);
        desk.will_type(&[PASSPHRASE]);
        let given = typing();
        let Ok(kept) = put(&given, super::Value::Typed).await else {
            panic!("not kept");
        };
        assert_eq!(kept_at(&kept.reference).as_str(), "typed-by-the-person");
        assert_eq!(given.asked().typed, ["X_TOKEN"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A generated value is random over its whole length: of sixteen made,
    /// no position holds the same character in all.
    ///
    /// A position holds one of 16 characters, so sixteen values that are
    /// random agree at a given position once in 16^15 runs, and at any of
    /// the 64 positions less often than once in 10^16 runs.
    #[test]
    fn a_generated_value_is_random_at_every_position() {
        let values: Vec<_> = (0..16)
            .map(|_| super::generate().expect("random"))
            .collect();
        for value in &values {
            assert_eq!(value.len(), 64);
        }
        for at in 0..64 {
            let first = values[0].as_bytes()[at];
            assert!(
                values.iter().any(|value| value.as_bytes()[at] != first),
                "position {at} holds the same character in all sixteen"
            );
        }
    }

    /// `--from-account` asks user-api for the account's keys and the
    /// shared RPC about them, one request a key. None of it is sent for a
    /// command that is going to be refused.
    #[tokio::test]
    async fn the_account_is_read_only_once_nothing_else_can_refuse_the_command() {
        use crate::error::Code;
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _keystore = set_up(&desk);
        let store = super::Store::Keystore { by_default: false };
        let kept = Zeroizing::new("kept-before".to_owned());
        let set = worker_secrets::put(&store, "bot", "SET_ALREADY", &kept).expect("kept");
        let root = app(
            "put-order",
            &format!(
                "name = \"bot\"\nchain = \"solana\"\n[vars]\nIN_VARS = \"plain\"\n\
                 [secrets]\nSET_ALREADY = \"{set}\"\n"
            ),
        );
        let put = async |given: &Given, dir: &std::path::Path, name: &str| {
            super::put_from(
                given,
                &dir_of(dir),
                name,
                (None, None),
                false,
                super::Value::Account,
            )
            .await
        };
        let refused = async |given: &Given, dir: &std::path::Path, name: &str| {
            let e = put(given, dir, name).await.err().expect("refused");
            // Not one request, to user-api or to the RPC.
            let asked = given.asked();
            assert_eq!(asked.account_reads, 0, "{name}: {}", e.text());
            assert!(asked.keys_tried.is_empty(), "{name}: {}", e.text());
            e
        };
        // A name that cannot be a setting's.
        let e = refused(&Given::keystore(), &root, "lower-case").await;
        assert_eq!(e.code, Code::Usage);
        assert!(e.message.starts_with("lower-case: "), "{}", e.message);
        // No erpc.toml where --dir says.
        let nowhere = root.join("no-app").join("erpc.toml");
        let e = refused(&Given::keystore(), &nowhere, "ERPC_API_KEY").await;
        assert!(e.message.contains("erpc.toml"), "{}", e.message);
        // A name [vars] has, and one set already, without --replace.
        let e = refused(&Given::keystore(), &root, "IN_VARS").await;
        assert!(
            e.message.starts_with("IN_VARS is in [vars]"),
            "{}",
            e.message
        );
        let e = refused(&Given::keystore(), &root, "SET_ALREADY").await;
        assert!(
            e.message.starts_with("SET_ALREADY is set already"),
            "{}",
            e.message
        );
        // A store that cannot be used as asked.
        let no_store = Given {
            store: Err("--vault is for --store 1password".to_owned()),
            ..Given::keystore()
        };
        let e = refused(&no_store, &root, "ERPC_API_KEY").await;
        assert_eq!(e.message, "--vault is for --store 1password");
        // A name the store cannot keep: it would be the trading key's entry.
        let e = refused(&Given::keystore(), &root, "WALLET").await;
        assert_eq!(e.code, Code::Usage);
        // The keystore locked, with nobody at a terminal to open it.
        desk.lock();
        desk.terminal.set(false);
        let e = refused(&Given::keystore(), &root, "ERPC_API_KEY").await;
        assert!(
            e.message.contains("`erpc worker secret unlock`"),
            "{}",
            e.message
        );
        // With all of that in order, the account is read, once.
        desk.terminal.set(true);
        desk.will_type(&[PASSPHRASE]);
        let given = Given::keystore();
        let put = put(&given, &root, "ERPC_API_KEY").await.expect("kept");
        assert_eq!(kept_at(&put.reference).as_str(), ACCOUNT_KEY);
        assert_eq!(
            given.asked(),
            Asked {
                stores: 1,
                typed: Vec::new(),
                account_reads: 1,
                keys_tried: vec![ACCOUNT_KEY.to_owned()],
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn off_a_terminal_secret_list_and_rm_read_as_they_always_have() {
        crate::ui::force_drawn(false);
        let root = app(
            "secrets",
            "name = \"bot\"\nchain = \"solana\"\n[run]\nrequires = [\"API_TOKEN\"]\n\
             [secrets]\nX_TOKEN = \"keychain:svc/acct\"\n",
        );
        assert_eq!(
            done(super::list(false, &dir_of(&root))),
            "X_TOKEN  keychain:svc/acct\nmissing: API_TOKEN (run.requires)"
        );
        assert_eq!(
            done(super::remove(false, &dir_of(&root), "X_TOKEN")),
            "X_TOKEN is no longer in erpc.toml. Its value is still kept at keychain:svc/acct; delete \
             it there if nothing else uses it."
        );
        let scope = dir_of(&root).scope();
        assert_eq!(
            done(super::list(false, &dir_of(&root))),
            format!(
                "No secrets yet; `erpc worker secret put <NAME>{scope}` keeps one.\n\
                 missing: API_TOKEN (run.requires)"
            )
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn off_a_terminal_a_kept_key_reads_as_it_always_has() {
        crate::ui::force_drawn(false);
        let kept = super::Kept {
            app: "bot".into(),
            pubkey: "PK".into(),
            source: erpc_worker::manifest::SecretRef::parse("keychain:svc/acct").expect("ref"),
            store: super::Store::Keychain,
            warning: super::Report::new(),
        };
        let store = super::Store::Keychain.describe();
        let again = super::Kept {
            app: kept.app.clone(),
            pubkey: kept.pubkey.clone(),
            source: kept.source.clone(),
            store: super::Store::Keychain,
            warning: super::Report::new(),
        };
        assert_eq!(
            done(kept.report(false, "made", None)),
            format!(
                "Trading key made for bot: PK\nKept in {store} as keychain:svc/acct; erpc.toml's \
                 [wallet] names it.\nFund only what the bot needs: it is a hot wallet."
            )
        );
        // At a terminal, the same result is drawn.
        crate::ui::force_drawn(true);
        let drawn = done(again.report(false, "made", None));
        let drawn = console::strip_ansi_codes(&drawn);
        assert!(
            drawn.starts_with("✅ Trading key made for bot: PK\n"),
            "{drawn}"
        );
        assert!(drawn.contains("🔥 Fund only what the bot needs"), "{drawn}");
        crate::ui::force_drawn(false);
    }

    #[test]
    fn a_key_kept_in_the_keystore_says_what_to_back_up() {
        use crate::worker_keystore::fake::{FakeDesk, set_up};
        crate::ui::force_drawn(false);
        let desk = FakeDesk::nobody();
        let (_home, keystore) = set_up(&desk);
        let m = erpc_worker::manifest::Manifest::parse(&format!(
            "name = \"bot\"\nchain = \"solana\"\n\
             [env.prod]\ninventory = {{ vault = \"{OP_VAULT}\" }}\n"
        ))
        .expect("manifest");
        let store = super::Store::Keystore { by_default: true };
        let kept = super::Kept {
            app: "bot".into(),
            pubkey: "PK".into(),
            source: erpc_worker::manifest::SecretRef::parse("keystore:erpc-worker/bot.wallet")
                .expect("ref"),
            warning: super::key_cautions(&m, &store),
            store,
        };
        let place = crate::ui::tidy(keystore.dir());
        assert_eq!(
            done(kept.report(false, "made", None)),
            format!(
                "Trading key made for bot: PK\nKept in the encrypted keystore on this machine as \
                 keystore:erpc-worker/bot.wallet; erpc.toml's [wallet] names it.\nFund only what \
                 the bot needs: it is a hot wallet.\nwarning: This key's only copy is its \
                 encrypted file in {place}. Back that directory up and keep its passphrase: \
                 without both, the wallet is gone.\nwarning: this app's servers are kept in \
                 1Password, and the keystore is only on this machine: another machine will not \
                 be able to start it. Pass --store 1password to keep it where they are."
            )
        );
        // A key kept elsewhere has no such file to back up.
        assert_eq!(
            super::key_cautions(&m, &super::Store::Keychain).text(),
            format!("warning: {}", t!("worker_keys.portability"))
        );
        let plain = erpc_worker::manifest::Manifest::parse("name = \"bot\"\nchain = \"solana\"\n")
            .expect("manifest");
        assert_eq!(
            super::key_cautions(&plain, &super::Store::Keychain).text(),
            ""
        );
        assert_eq!(
            super::portability(&plain, &super::Store::Keystore { by_default: false }).text(),
            ""
        );
    }

    #[test]
    fn key_show_names_the_keystore_file_and_says_when_it_is_not_here() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        let root = app(
            "show-keystore",
            "name = \"bot\"\nchain = \"solana\"\n[wallet]\n\
             source = \"keystore:erpc-worker/bot.wallet\"\n\
             pubkey = \"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"\n",
        );
        let file = crate::ui::tidy(
            &keystore
                .entry_path("erpc-worker", "bot.wallet")
                .expect("named"),
        );
        // As on a machine that did not keep the key: said, and nothing is
        // asked for.
        assert_eq!(
            done(super::show(false, &dir_of(&root))),
            format!(
                "bot  7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\n  kept at \
                 keystore:erpc-worker/bot.wallet\nwarning: this machine's keystore has no such \
                 entry ({file}): the key was kept on another machine, and this one cannot start \
                 the app with it"
            )
        );
        assert_eq!(desk.asked(), 0);
        crate::worker_keystore::write("erpc-worker", "bot.wallet", Kind::Key, "the key", false)
            .expect("kept");
        desk.lock();
        // Here, locked: shown without the passphrase.
        assert_eq!(
            done(super::show(false, &dir_of(&root))),
            format!(
                "bot  7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\n  kept at \
                 keystore:erpc-worker/bot.wallet\n  its keystore file is {file}"
            )
        );
        assert_eq!(desk.asked(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn secret_rm_deletes_a_keystore_entry_and_leaves_the_key() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        for (account, kind, value) in [
            ("bot.X_TOKEN", Kind::Secret, "tok-1"),
            ("bot.wallet", Kind::Key, "the key"),
            ("bot.SHARED", Kind::Secret, "tok-2"),
        ] {
            crate::worker_keystore::write("erpc-worker", account, kind, value, true).expect("kept");
        }
        let root = app(
            "rm-keystore",
            "name = \"bot\"\nchain = \"solana\"\n[secrets]\n\
             X_TOKEN = \"keystore:erpc-worker/bot.X_TOKEN\"\n\
             A_TOKEN = \"keystore:erpc-worker/bot.SHARED\"\n\
             B_TOKEN = \"keystore:erpc-worker/bot.SHARED\"\n\
             [wallet]\nsource = \"keystore:erpc-worker/bot.wallet\"\n",
        );
        let file = |account: &str| keystore.entry_path("erpc-worker", account).expect("named");
        // Locked, and with nobody at a terminal: removing asks for nothing.
        desk.lock();
        desk.terminal.set(false);
        assert_eq!(
            done(super::remove(false, &dir_of(&root), "X_TOKEN")),
            "X_TOKEN is no longer in erpc.toml.\nIts value was deleted from the keystore \
             (keystore:erpc-worker/bot.X_TOKEN)."
        );
        assert!(!file("bot.X_TOKEN").exists());
        // An entry another setting names stays until the last one goes.
        assert_eq!(
            done(super::remove(false, &dir_of(&root), "A_TOKEN")),
            "A_TOKEN is no longer in erpc.toml.\nIts value stays in the keystore under \
             keystore:erpc-worker/bot.SHARED: secrets.B_TOKEN names it too."
        );
        assert!(file("bot.SHARED").is_file());
        assert!(done(super::remove(false, &dir_of(&root), "B_TOKEN")).contains("was deleted from"));
        assert!(!file("bot.SHARED").exists());
        let left = std::fs::read_to_string(root.join("erpc.toml")).expect("toml");
        assert!(!left.contains("TOKEN"), "{left}");
        assert!(
            left.contains("source = \"keystore:erpc-worker/bot.wallet\""),
            "{left}"
        );
        assert!(file("bot.wallet").is_file());
        assert_eq!(desk.asked(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The erpc.toml of a second directory, with no `[wallet]`, that names
    /// the app's key under `[secrets]`: every command that reads the file
    /// refuses it, so the key is neither handed over as a setting nor
    /// removed as one.
    #[tokio::test]
    async fn a_setting_cannot_name_or_take_the_place_of_the_trading_key() {
        use crate::worker_keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        let store = super::Store::Keystore { by_default: true };
        let key = Keypair::generate().expect("random");
        let source = worker_secrets::put_key(&store, "bot", &key).expect("kept");
        let file = keystore
            .entry_path("erpc-worker", "bot.wallet")
            .expect("named");
        let sealed = std::fs::read(&file).expect("the key's entry");
        let unchanged = || {
            assert_eq!(std::fs::read(&file).expect("the key's entry"), sealed);
        };
        for (tag, line) in [
            ("copy", "KEY_COPY = \"keystore:erpc-worker/bot.wallet\""),
            ("upper", "WALLET = \"keystore:erpc-worker/bot.WALLET\""),
        ] {
            let text = format!("name = \"bot\"\nchain = \"solana\"\n[secrets]\n{line}\n");
            let root = app(&format!("key-as-setting-{tag}"), &text);
            let name = line.split(' ').next().expect("a name");
            // However the value would come: typed, made here, or read
            // from the account. Nothing is asked for any of them.
            let given = Given::keystore();
            let put = async |value| {
                super::put_from(&given, &dir_of(&root), name, (None, None), true, value)
                    .await
                    .err()
            };
            for refusal in [
                super::remove(false, &dir_of(&root), name).error(),
                super::list(false, &dir_of(&root)).error(),
                put(super::Value::Typed).await,
                put(super::Value::Generated).await,
                put(super::Value::Account).await,
            ] {
                let e = refusal.expect("refused").text();
                assert!(
                    e.contains(&format!("secrets.{name}: keystore:erpc-worker/bot.")),
                    "{e}"
                );
                assert!(e.contains("is an entry filed as a trading key"), "{e}");
                assert!(e.contains("named under [wallet]"), "{e}");
            }
            assert_eq!(given.asked(), Asked::default());
            assert_eq!(
                std::fs::read_to_string(root.join("erpc.toml")).expect("toml"),
                text
            );
            unchanged();
            let _ = std::fs::remove_dir_all(&root);
        }
        // Nothing was asked of the keystore for any of it, and the key
        // is still the one that was kept.
        assert_eq!(desk.asked(), 2);
        assert_eq!(source.to_string(), "keystore:erpc-worker/bot.wallet");
    }

    #[test]
    fn key_new_on_an_app_with_a_wallet_says_so_and_succeeds() {
        crate::ui::force_drawn(false);
        let already = super::Already {
            app: "bot".into(),
            pubkey: Some("PK".into()),
            source: erpc_worker::manifest::SecretRef::parse("keychain:svc/acct").expect("ref"),
        };
        let root = std::path::Path::new("/srv/apps/bot");
        // Done, not a failure: the command exits 0.
        let text = done(already.report(false, &dir_of(root)));
        assert_eq!(
            text,
            format!(
                "bot already has a wallet; nothing was made\n  pubkey   PK\n  kept at  \
                 keychain:svc/acct\nhint: `erpc worker key show --dir {}` shows it\n\
                 hint: to replace it, remove [wallet] from erpc.toml first",
                root.display()
            )
        );
    }

    #[test]
    fn key_new_through_the_command_keeps_an_existing_wallet_untouched() {
        crate::ui::force_drawn(false);
        // An app with a wallet: `key new` returns before a store is chosen
        // or written, leaves erpc.toml as it is, and succeeds.
        let manifest = "name = \"bot\"\nchain = \"solana\"\n[wallet]\n\
                        source = \"keychain:svc/acct\"\npubkey = \"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"\n";
        let root = app("already", manifest);
        let text = done(super::new(false, &dir_of(&root), None, None));
        assert!(
            text.starts_with("bot already has a wallet; nothing was made\n"),
            "{text}"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("erpc.toml")).expect("toml"),
            manifest
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn off_a_terminal_import_reads_as_it_always_has() {
        crate::ui::force_drawn(false);
        let file = std::path::Path::new("/tmp/k.json");
        assert_eq!(
            super::wipe_note(file, Some(&Ok(()))).text(),
            "Wiped /tmp/k.json."
        );
        assert_eq!(
            super::wipe_note(file, Some(&Err("busy".into()))).text(),
            "warning: could not wipe /tmp/k.json: busy"
        );
        assert_eq!(
            super::wipe_note(file, None).text(),
            "/tmp/k.json is still on disk. Delete it once you have checked the key in the store \
             (`--wipe` does it for you)."
        );
        let already = super::Already {
            app: "bot".into(),
            pubkey: Some("PK".into()),
            source: erpc_worker::manifest::SecretRef::parse("keychain:svc/acct").expect("ref"),
        };
        let root = std::path::Path::new("/srv/apps/bot");
        let e = already.refusal(&dir_of(root));
        assert_eq!(
            e.text(),
            format!(
                "error: bot has a wallet already (PK in keychain:svc/acct); nothing was made\n\
             hint: `erpc worker key show --dir {}` shows it; remove [wallet] from erpc.toml first \
             to replace it",
                root.display()
            )
        );
    }

    #[test]
    fn a_key_file_is_read_checked_and_wiped() {
        let dir = std::env::temp_dir().join(format!("erpc-w-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("throwaway.json");
        let made = erpc_chain_solana::identity::Keypair::generate().expect("random");
        std::fs::write(&file, made.to_json().as_bytes()).expect("write");
        assert_eq!(read_key_file(&file).expect("read").pubkey(), made.pubkey());
        wipe_file(&file).expect("wipe");
        assert!(!file.exists());
        std::fs::write(&file, "[1,2,3]").expect("write");
        assert!(read_key_file(&file).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_kept_key_is_said_in_the_chosen_language() {
        use erpc_core::i18n::Lang;
        let say = || t!("worker_keys.kept.made", app = "bot", pubkey = "PK");
        let english = say();
        for lang in [Lang::Ja, Lang::Ru] {
            let said = crate::i18n::speaking(lang, say);
            assert_ne!(said, english);
            assert!(!said.contains('{'), "{said}");
            assert!(said.contains("bot") && said.contains("PK"), "{said}");
        }
    }
}

#[cfg(test)]
mod send_tests {
    use super::{Delivery, Pace, deliver, transfer_message};
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::sync::{Arc, Mutex};

    const QUICK: Pace = Pace {
        every: std::time::Duration::from_millis(5),
        at_most: std::time::Duration::from_millis(400),
    };

    /// A JSON-RPC server on loopback for one test. `answer` gets each
    /// request's method and gives the `result` to answer with as JSON text,
    /// `Err` text for a JSON-RPC error, or `None` to drop the connection
    /// with no answer, as a timeout or a broken connection leaves it.
    /// Returns its URL and the methods asked, in order.
    fn rpc_server(
        answer: impl Fn(&str, usize) -> Option<Result<String, String>> + Send + 'static,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = asked.clone();
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
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                if reader.read_exact(&mut body).is_err() {
                    continue;
                }
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let method = request["method"].as_str().unwrap().to_owned();
                let nth = {
                    let mut seen = seen.lock().unwrap();
                    seen.push(method.clone());
                    seen.iter().filter(|m| **m == method).count()
                };
                let body = match answer(&method, nth) {
                    None => continue,
                    Some(Ok(result)) => format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#),
                    // A message that starts with `gateway:` comes with the
                    // code a proxy uses; any other with a node's refusal.
                    Some(Err(message)) => format!(
                        r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":{},"message":"{message}"}}}}"#,
                        if message.starts_with("gateway:") {
                            -32_603
                        } else {
                            -32_002
                        }
                    ),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (format!("http://127.0.0.1:{port}"), asked)
    }

    const CONFIRMED: &str = r#"{"value":[{"err":null,"confirmationStatus":"confirmed"}]}"#;
    const NO_TRACE: &str = r#"{"value":[null]}"#;

    /// The case that sent SOL twice: the RPC forwards the transfer and the
    /// answer never arrives. It is not called unsent; it is followed by its
    /// own signature and found on the chain.
    #[tokio::test]
    async fn a_send_that_got_no_answer_is_followed_and_found_landed() {
        let (url, asked) = rpc_server(|method, nth| match method {
            "sendTransaction" => None,
            "getSignatureStatuses" if nth < 3 => Some(Ok(NO_TRACE.to_owned())),
            "getSignatureStatuses" => Some(Ok(CONFIRMED.to_owned())),
            _ => Some(Ok("10".to_owned())),
        });
        let end = deliver(&url, &[1, 2, 3], "SiG", Some(100), QUICK).await;
        assert_eq!(end, Delivery::Confirmed);
        let asked = asked.lock().unwrap();
        // Sent once: nothing here signs or sends a second time.
        assert_eq!(asked.iter().filter(|m| *m == "sendTransaction").count(), 1);
    }

    /// The same silence, and the chain never shows the transfer: only once
    /// its blockhash is past is it said not to have been made.
    #[tokio::test]
    async fn a_send_that_got_no_answer_is_unsent_only_once_its_blockhash_is_past() {
        let (url, asked) = rpc_server(|method, nth| match method {
            "getSignatureStatuses" => Some(Ok(NO_TRACE.to_owned())),
            // Two looks inside the blockhash's life, then past it.
            "getBlockHeight" => Some(Ok(if nth < 3 { "100" } else { "101" }.to_owned())),
            // The send gets no answer.
            _ => None,
        });
        let end = deliver(&url, &[1, 2, 3], "SiG", Some(100), QUICK).await;
        assert_eq!(end, Delivery::Expired);
        let asked = asked.lock().unwrap();
        assert_eq!(asked.iter().filter(|m| *m == "getBlockHeight").count(), 3);
        // The last word is the chain's: asked once more after the height.
        assert_eq!(
            asked.last().map(String::as_str),
            Some("getSignatureStatuses")
        );
    }

    /// Past the blockhash, a transfer that landed in its last block is
    /// still found, by the look taken after the height.
    #[tokio::test]
    async fn a_transfer_that_landed_in_its_last_block_is_not_called_expired() {
        let (url, _) = rpc_server(|method, nth| match method {
            "getSignatureStatuses" if nth < 2 => Some(Ok(NO_TRACE.to_owned())),
            "getSignatureStatuses" => Some(Ok(CONFIRMED.to_owned())),
            "getBlockHeight" => Some(Ok("101".to_owned())),
            // The send gets no answer.
            _ => None,
        });
        let end = deliver(&url, &[1, 2, 3], "SiG", Some(100), QUICK).await;
        assert_eq!(end, Delivery::Confirmed);
    }

    /// With an RPC that says nothing at all, nothing is known: neither
    /// landed nor unsent.
    #[tokio::test]
    async fn an_rpc_that_stays_silent_leaves_the_transfer_unknown() {
        let (url, _) = rpc_server(|_, _| None);
        let end = deliver(&url, &[1, 2, 3], "SiG", Some(100), QUICK).await;
        assert_eq!(end, Delivery::Unknown);
    }

    /// An error from something between here and the node, a gateway that
    /// gave up waiting, says nothing of the transfer: it is followed by its
    /// signature like a send that got no answer, and found landed.
    #[tokio::test]
    async fn a_send_answered_with_a_gateways_error_is_followed_and_found_landed() {
        let (url, asked) = rpc_server(|method, nth| match method {
            "sendTransaction" => Some(Err("gateway: upstream timed out".to_owned())),
            "getSignatureStatuses" if nth < 2 => Some(Ok(NO_TRACE.to_owned())),
            "getSignatureStatuses" => Some(Ok(CONFIRMED.to_owned())),
            _ => Some(Ok("10".to_owned())),
        });
        let end = deliver(&url, &[1, 2, 3], "SiG", Some(100), QUICK).await;
        assert_eq!(end, Delivery::Confirmed);
        let asked = asked.lock().unwrap();
        assert_eq!(asked.iter().filter(|m| *m == "sendTransaction").count(), 1);
    }

    /// The node's own refusal of the transaction is the one case where
    /// nothing went out, and it is not waited on.
    #[tokio::test]
    async fn a_send_the_rpc_refused_sent_nothing() {
        let (url, asked) = rpc_server(|method, _| match method {
            "sendTransaction" => Some(Err("Blockhash not found".to_owned())),
            _ => Some(Ok(CONFIRMED.to_owned())),
        });
        let end = deliver(&url, &[1, 2, 3], "SiG", Some(100), QUICK).await;
        assert_eq!(end, Delivery::Refused("Blockhash not found".to_owned()));
        assert_eq!(*asked.lock().unwrap(), ["sendTransaction"]);
    }

    /// A transfer that landed and failed is the chain's refusal, with its
    /// reason, whatever the RPC answered to the send.
    #[tokio::test]
    async fn a_transfer_that_failed_on_the_chain_says_why() {
        let (url, _) = rpc_server(|method, _| {
            match method {
            "sendTransaction" => Some(Ok(r#""an-answer-that-is-not-read""#.to_owned())),
            "getSignatureStatuses" => Some(Ok(
                r#"{"value":[{"err":{"InstructionError":[0,"Custom"]},"confirmationStatus":"processed"}]}"#.to_owned(),
            )),
            _ => None,
        }
        });
        let end = deliver(&url, &[1, 2, 3], "SiG", Some(100), QUICK).await;
        assert_eq!(
            end,
            Delivery::Failed(r#"{"InstructionError":[0,"Custom"]}"#.to_owned())
        );
    }

    #[test]
    fn a_transfer_message_is_laid_out_as_the_system_program_reads_it() {
        let from = [1_u8; 32];
        let to = [2_u8; 32];
        let blockhash = [3_u8; 32];
        let m = transfer_message(&from, &to, &blockhash, 1_500_000_000);
        assert_eq!(m.len(), 150);
        // One signer, one read-only unsigned account (the program); three keys.
        assert_eq!(&m[..4], &[1, 0, 1, 3]);
        assert_eq!(&m[4..36], &from);
        assert_eq!(&m[36..68], &to);
        assert_eq!(&m[68..100], &[0_u8; 32]);
        assert_eq!(&m[100..132], &blockhash);
        // One instruction: program index 2, accounts 0 and 1, 12 bytes of data.
        assert_eq!(&m[132..138], &[1, 2, 2, 0, 1, 12]);
        assert_eq!(&m[138..142], &2_u32.to_le_bytes());
        assert_eq!(&m[142..150], &1_500_000_000_u64.to_le_bytes());
    }
}
