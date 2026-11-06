// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker key` and `erpc worker secret`: an app's trading key and
//! its secret settings, kept in 1Password or the keychain (see
//! [`crate::worker_secrets`]) and named in `erpc.toml` by reference.
//!
//! A key is made in memory, or read from a key file the operator already
//! has, and goes straight to the store. A secret is read from standard
//! input when it is piped in, or asked for without echo. Neither is ever
//! printed, logged or written to a file by erpc.

use std::io::{IsTerminal as _, Read as _};
use std::path::Path;

use erpc_chain_solana::identity::Keypair;
use erpc_worker::edit;
use erpc_worker::manifest::{self, Manifest, SecretRef};
use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::ui::Report;
use crate::worker::{Dir, load};
use crate::worker_secrets::{self, Store, StoreFlag};

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
/// keychain, which only this machine has.
fn portability(m: &Manifest, store: &Store) -> Report {
    let report = Report::new();
    if matches!(store, Store::Keychain) && m.env.values().any(|e| e.inventory.is_some()) {
        report.warning(t!("worker_keys.portability"))
    } else {
        report
    }
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
        warning: portability(&m, &store),
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
    if json {
        crate::print_json(&json!({ "pubkey": wallet.pubkey, "source": wallet.source }));
        return Outcome::Done(String::new());
    }
    Outcome::Done(
        Report::new()
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
            .detail(t!("worker_keys.show.kept_at", source = wallet.source))
            .text(),
    )
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

/// `erpc worker secret put`: keeps a value and names it in `[secrets]`.
pub(crate) fn put(
    json: bool,
    dir: &Dir,
    name: &str,
    store: Option<StoreFlag>,
    vault: Option<&str>,
    replace: bool,
) -> Outcome {
    if let Err(e) = manifest::check_setting_name(name) {
        return CliError::new(Code::Usage, format!("{name}: {e}")).into();
    }
    let (path, m) = match load(dir) {
        Ok(found) => found,
        Err(e) => return e.into(),
    };
    if m.vars.contains_key(name) {
        return failed(t!("worker_keys.put.in_vars", name)).into();
    }
    let old = m.secrets.get(name).cloned();
    if old.is_some() && !replace {
        return failed(t!(
            "worker_keys.put.already",
            name,
            source = old.as_ref().map(ToString::to_string).unwrap_or_default()
        ))
        .hint(t!("worker_keys.put.replace_hint"))
        .mark("🔑")
        .into();
    }
    let store = match worker_secrets::choose(store, vault) {
        Ok(store) => store,
        Err(e) => return failed(e).into(),
    };
    let value = match read_secret(name) {
        Ok(v) => v,
        Err(e) => return e.into(),
    };
    let reference = match worker_secrets::put(&store, &m.name, name, &value) {
        Ok(r) => r,
        Err(e) => return failed(e).into(),
    };
    drop(value);
    if let Err(e) = rewrite(&path, |text| edit::set_secret(text, name, &reference)) {
        return e
            .hint(t!("worker_keys.put.by_hand", source = reference, name))
            .into();
    }
    if json {
        crate::print_json(&json!({ "name": name, "source": reference, "replaced": old }));
        return Outcome::Done(String::new());
    }
    let mut report = Report::new().done(t!(
        "worker_keys.put.done",
        name,
        source = reference,
        store = store.describe()
    ));
    // A keychain entry under the same account was overwritten in place.
    if let Some(old) = old.filter(|o| *o != reference) {
        report = report.info(t!("worker_keys.put.old_kept", old));
    }
    Outcome::Done(report.extend(portability(&m, &store)).text())
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

/// `erpc worker secret rm`: removes a secret's reference. The value stays
/// where it is kept; erpc does not delete from 1Password or the keychain.
pub(crate) fn remove(json: bool, dir: &Dir, name: &str) -> Outcome {
    let (path, m) = match load(dir) {
        Ok(found) => found,
        Err(e) => return e.into(),
    };
    let Some(reference) = m.secrets.get(name).cloned() else {
        return failed(t!("worker_keys.rm.not_there", name)).into();
    };
    if let Err(e) = rewrite(&path, |text| {
        edit::remove_secret(text, name).map(|(t, _)| t)
    }) {
        return e.into();
    }
    if json {
        crate::print_json(&json!({ "name": name, "removed": true, "still_kept_at": reference }));
        return Outcome::Done(String::new());
    }
    Outcome::Done(
        Report::new()
            .done(t!("worker_keys.rm.done", name))
            .info(t!("worker_keys.rm.still_kept", source = reference))
            .or_plain(t!("worker_keys.rm.plain", name, source = reference)),
    )
}

#[cfg(test)]
mod tests {
    use super::{read_key_file, wipe_file};

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
