// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc worker seal`: this machine's sealing key in the ERPC account.
//!
//! An app's secrets kept in the account are to be sealed on the machine
//! that sets them to the public keys of the machines that may open them,
//! and the account is to keep only what is sealed. Each machine has one
//! sealing key per ERPC account: its private half is kept here, in
//! 1Password, the keychain or erpc's keystore (marked as a sealing key in
//! each, which is read as nothing else), and its public half is registered
//! in the account, where it waits until the person approves it on the ERPC
//! dashboard by its fingerprint.
//!
//! This machine's record of its key (`worker_seal.json` beside the config,
//! private to the user, per account) holds where the private half is kept,
//! never the key itself, with its public half, fingerprint and the
//! account's id of it. It is written as soon as the key is kept, before the
//! key is registered, and the store is chosen and the key kept under the
//! record's lock, so a run that stops part way goes on with the same key,
//! and two runs at once make one.
//!
//! What the account answers of a key is checked against what this machine
//! computes from its own, and is checked to be in its form, before any of
//! it is recorded or printed: a key answered with other bytes, or another
//! fingerprint, is not taken.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use erpc_api::worker::seal::{RegisteredKey, SealKey, SealKeyStatus};
use erpc_api::worker::{Code as AccountCode, WorkerError, Written};
use erpc_worker::manifest::SecretRef;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::account::commands::Outcome;
use crate::cli::error::{CliError, Code};
use crate::worker::account as kept;
use crate::worker::seal::{SecretKey, fingerprint, public_key_text};
use crate::worker::secrets::{self, Store, StoreFlag};

fn failed(message: String) -> CliError {
    CliError::new(Code::Failed, message)
}

/// The record's file, beside the config.
const FILE: &str = "worker_seal.json";

/// The largest account number a seal's associated data takes.
const USER_ID_MAX: u64 = 2_147_483_647;

/// This machine's record of its sealing key in one ERPC account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Record {
    /// Where the private half is kept: a reference, never the key.
    pub(crate) kept: String,
    /// The public half, as the account takes it.
    pub(crate) public_key: String,
    /// Its fingerprint, as this machine computes it.
    pub(crate) fingerprint: String,
    /// The account's id of the key, once it is registered.
    #[serde(default)]
    pub(crate) seal_key_id: Option<String>,
    /// The account's own number, which a seal's associated data names.
    #[serde(default)]
    pub(crate) user_id: Option<u64>,
}

/// The records, by account.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Records {
    #[serde(default)]
    accounts: BTreeMap<String, Record>,
    /// The other machines' keys a person here trusted, by account.
    #[serde(default)]
    trusted: BTreeMap<String, Vec<Trusted>>,
}

/// Another machine's sealing key a person trusted here, by its fingerprint
/// ([`trust_with`]): its id and its bytes, as this machine read them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Trusted {
    /// The account's id of the key.
    pub(crate) id: String,
    /// Its public key, as the account gave it when it was trusted.
    pub(crate) public_key: String,
    /// Its fingerprint, computed here from those bytes.
    pub(crate) fingerprint: String,
    /// The label its machine gave it, as text.
    #[serde(default)]
    pub(crate) label: Option<String>,
}

/// The keys trusted here in the account `tag` stands for.
pub(crate) fn trusted(path: &Path, tag: &str) -> Result<Vec<Trusted>, String> {
    Ok(load(path)?.trusted.remove(tag).unwrap_or_default())
}

/// Changes the keys trusted here for `tag` with `change`, under the lock.
fn change_trusted<T>(
    path: &Path,
    tag: &str,
    change: impl FnOnce(&mut Vec<Trusted>) -> Result<T, String>,
) -> Result<T, String> {
    erpc_core::private_file::locked(path, || {
        let mut records = load(path)?;
        let list = records.trusted.entry(tag.to_owned()).or_default();
        let done = change(list)?;
        if list.is_empty() {
            records.trusted.remove(tag);
        }
        let text = serde_json::to_vec_pretty(&records).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)?;
        Ok(done)
    })
}

/// Where this machine keeps its records of its sealing keys.
pub(crate) fn records_path() -> Result<PathBuf, String> {
    crate::account::session::beside_config(FILE)
}

fn load(path: &Path) -> Result<Records, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            t!(
                "worker_seal_keys.unreadable",
                path = path.display(),
                error = e
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Records::default()),
        Err(e) => Err(t!(
            "worker_seal_keys.unreadable",
            path = path.display(),
            error = e
        )),
    }
}

/// This machine's record of its key in the account `tag` stands for.
pub(crate) fn recorded(path: &Path, tag: &str) -> Result<Option<Record>, String> {
    Ok(load(path)?.accounts.remove(tag))
}

/// Writes `record` for `tag`, with the lock held by the caller.
fn write_held(path: &Path, tag: &str, record: &Record) -> Result<(), String> {
    let mut records = load(path)?;
    records.accounts.insert(tag.to_owned(), record.clone());
    let text = serde_json::to_vec_pretty(&records).map_err(|e| e.to_string())?;
    erpc_core::private_file::write(path, &text)
}

/// Writes `record` for `tag`, read and written under the lock so that two
/// commands writing at once keep both.
fn write(path: &Path, tag: &str, record: &Record) -> Result<(), String> {
    erpc_core::private_file::locked(path, || write_held(path, tag, record))
}

/// Whether `path` records a sealing key kept in the 1Password item
/// `reference` names, whatever its field: 1Password reads a reference
/// without regard to case.
fn item_recorded_at(path: &Path, reference: &SecretRef) -> bool {
    let SecretRef::OnePassword(asked) = reference else {
        return false;
    };
    load(path).is_ok_and(|records| {
        records.accounts.values().any(|a| {
            matches!(SecretRef::parse(&a.kept), Ok(SecretRef::OnePassword(kept))
                if kept.vault().eq_ignore_ascii_case(asked.vault())
                    && kept.item().eq_ignore_ascii_case(asked.item()))
        })
    })
}

/// Whether `reference` names the 1Password item this machine recorded a
/// sealing key in, by any field: a second guard beside the field's own
/// name, which [`SecretRef::is_seal_entry`] refuses wherever it is.
#[cfg(not(test))]
pub(crate) fn holds_a_seal_key(reference: &SecretRef) -> bool {
    records_path().is_ok_and(|path| item_recorded_at(&path, reference))
}

/// In tests, never this machine's real records.
#[cfg(test)]
pub(crate) fn holds_a_seal_key(_: &SecretRef) -> bool {
    false
}

/// What `erpc worker seal` asks of the ERPC account.
#[allow(
    async_fn_in_trait,
    reason = "the CLI's own seam, used within this crate with no Send bound needed"
)]
pub(crate) trait SealAccount {
    /// The account's sealing keys, revoked ones included.
    async fn seal_keys(&self) -> Result<Vec<SealKey>, WorkerError>;
    /// Registers `public_key`, or finds it registered already.
    async fn register(&self, public_key: &str) -> Result<Written<RegisteredKey>, WorkerError>;
    /// Revokes the key `id`, for good.
    async fn revoke(&self, id: &str) -> Result<RegisteredKey, WorkerError>;
}

impl SealAccount for kept::Signed {
    async fn seal_keys(&self) -> Result<Vec<SealKey>, WorkerError> {
        Self::seal_keys(self).await
    }

    async fn register(&self, public_key: &str) -> Result<Written<RegisteredKey>, WorkerError> {
        self.register_seal_key(public_key).await
    }

    async fn revoke(&self, id: &str) -> Result<RegisteredKey, WorkerError> {
        self.revoke_seal_key(id).await
    }
}

/// The 1Password vault a reference names, when it names one: a key kept
/// there is held by every machine that reads the vault.
fn vault_of(reference: &str) -> Option<String> {
    match SecretRef::parse(reference) {
        Ok(SecretRef::OnePassword(r)) => Some(r.vault().to_owned()),
        _ => None,
    }
}

/// Where a sealing key is kept and read from.
pub(crate) trait Keeper {
    /// Readies the store a new key goes in: chosen, and a keystore's
    /// passphrase asked for.
    fn ready(&mut self) -> Result<(), String>;
    /// A key kept already for `tag` in that store, with its reference.
    fn there(&self, tag: &str) -> Result<Option<(String, Zeroizing<String>)>, String>;
    /// Keeps `key` for `tag`, and returns its reference.
    fn keep(&self, tag: &str, key: &str) -> Result<String, String>;
    /// The key kept at `reference`.
    fn read(&self, reference: &str) -> Result<Zeroizing<String>, String>;
    /// The 1Password vault the new key is kept in, which every machine that
    /// reads the vault can read too.
    fn shared(&self) -> Option<String>;
    /// Whether a store was asked for (`--store`, `--vault`).
    fn asked(&self) -> bool;
}

/// The stores `erpc worker secret` keeps values in, chosen as it chooses.
pub(crate) struct Stores {
    flag: Option<StoreFlag>,
    vault: Option<String>,
    store: Option<Store>,
}

impl Stores {
    pub(crate) const fn new(flag: Option<StoreFlag>, vault: Option<String>) -> Self {
        Self {
            flag,
            vault,
            store: None,
        }
    }

    fn store(&self) -> Result<&Store, String> {
        self.store
            .as_ref()
            .ok_or_else(|| "the store is chosen first".to_owned())
    }
}

impl Keeper for Stores {
    fn ready(&mut self) -> Result<(), String> {
        let store = secrets::choose(self.flag, self.vault.as_deref())?;
        secrets::ready(&store)?;
        self.store = Some(store);
        Ok(())
    }

    fn there(&self, tag: &str) -> Result<Option<(String, Zeroizing<String>)>, String> {
        Ok(secrets::seal_key_there(self.store()?, tag)?
            .map(|(reference, key)| (reference.to_string(), key)))
    }

    fn keep(&self, tag: &str, key: &str) -> Result<String, String> {
        secrets::put_seal_key(self.store()?, tag, key).map(|r| r.to_string())
    }

    fn read(&self, reference: &str) -> Result<Zeroizing<String>, String> {
        let reference = SecretRef::parse(reference)?;
        secrets::read_seal_key(&reference)
    }

    fn shared(&self) -> Option<String> {
        match &self.store {
            Some(Store::OnePassword { vault }) => Some(vault.clone()),
            _ => None,
        }
    }

    fn asked(&self) -> bool {
        self.flag.is_some() || self.vault.is_some()
    }
}

/// The account's failure `e`, with its exit status.
fn account_error(e: &WorkerError) -> CliError {
    match e {
        WorkerError::Api(erpc_api::ApiError::Unauthorized) | WorkerError::Session(_) => {
            CliError::new(Code::NotSignedIn, e.to_string()).hint(t!("worker_vps.login_hint"))
        }
        WorkerError::Api(_) => CliError::new(Code::Network, e.to_string()),
        _ => failed(e.to_string()),
    }
}

/// The public half and fingerprint of the key kept as `text`.
fn halves(text: &str) -> Result<(String, String), String> {
    let key = SecretKey::from_text(text).map_err(|e| e.to_string())?;
    let public = key.public().map_err(|e| e.to_string())?;
    Ok((public_key_text(&public), fingerprint(&public)))
}

/// Whether `id` is in the form the account gives its ids in.
fn is_public_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// Whether `print` is a fingerprint in its form: `SHA256:` and 43
/// characters of unpadded standard base64.
fn is_fingerprint(print: &str) -> bool {
    print.strip_prefix("SHA256:").is_some_and(|b64| {
        b64.len() == 43
            && b64
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    })
}

/// Whether the account's `key` is this machine's: the same fingerprint,
/// and the same bytes unless it is revoked (a revoked key's are not said).
fn is_ours(key: &SealKey, record: &Record) -> bool {
    key.fingerprint == record.fingerprint
        && match &key.public_key {
            Some(k) => *k == record.public_key,
            None => key.status == SealKeyStatus::Revoked,
        }
}

/// This machine's key for the account `tag` stands for: as recorded and
/// read back, or, with none recorded, taken up again from its store or
/// made and kept, and recorded, under the record's lock. Says in `notes`
/// what the person should know.
fn this_machines(
    keeper: &mut impl Keeper,
    path: &Path,
    tag: &str,
    notes: &mut Vec<String>,
) -> Result<(Record, Option<String>), CliError> {
    if let Some(record) = recorded(path, tag).map_err(failed)? {
        let kept = keeper.read(&record.kept).map_err(failed)?;
        let (public_key, print) = halves(&kept).map_err(failed)?;
        if public_key != record.public_key || print != record.fingerprint {
            return Err(
                failed(t!("worker_seal_keys.kept_differs", reference = record.kept)).hint(t!(
                    "worker_seal_keys.kept_differs_hint",
                    path = path.display()
                )),
            );
        }
        if keeper.asked() {
            notes.push(t!(
                "worker_seal_keys.store_ignored",
                reference = record.kept
            ));
        }
        let shared = vault_of(&record.kept);
        if let Some(vault) = &shared {
            notes.push(t!("worker_seal_keys.shared_vault", vault));
        }
        return Ok((record, shared));
    }
    erpc_core::private_file::locked(path, || {
        // Another run may have kept and recorded one meanwhile.
        if let Some(record) = recorded(path, tag)? {
            let shared = vault_of(&record.kept);
            return Ok((record, shared));
        }
        keeper.ready()?;
        let (reference, text) = if let Some(found) = keeper.there(tag)? {
            found
        } else {
            let key = SecretKey::generate().map_err(|e| e.to_string())?;
            let text = key.to_text();
            (keeper.keep(tag, &text)?, text)
        };
        let (public_key, fingerprint) = halves(&text)?;
        let record = Record {
            kept: reference,
            public_key,
            fingerprint,
            seal_key_id: None,
            user_id: None,
        };
        write_held(path, tag, &record)?;
        Ok((record, keeper.shared()))
    })
    .map_err(failed)
    .inspect(|(_, shared)| {
        if let Some(vault) = shared {
            notes.push(t!("worker_seal_keys.shared_vault", vault));
        }
    })
}

/// Registers `record`'s key in the account, and records the account's id
/// of it, once the answer is checked to be this machine's key and in its
/// form. Whether this register made it.
async fn register(
    api: &impl SealAccount,
    path: &Path,
    tag: &str,
    mut record: Record,
) -> Result<(Record, SealKey, bool), CliError> {
    let answered = api
        .register(&record.public_key)
        .await
        .map_err(|e| match &e {
            WorkerError::Refused(r) if r.code == Some(AccountCode::LimitExceeded) => {
                failed(t!("worker_seal_keys.too_many")).hint(t!("worker_seal_keys.too_many_hint"))
            }
            _ => account_error(&e),
        })?;
    let key = answered.record.key;
    let user_id = answered.record.user_id;
    if !is_ours(&key, &record) {
        return Err(failed(t!(
            "worker_seal_keys.answer_differs",
            fingerprint = record.fingerprint
        )));
    }
    if !is_public_id(&key.id) || !(1..=USER_ID_MAX).contains(&user_id) {
        return Err(failed(t!("worker_seal_keys.answer_unreadable")));
    }
    record.seal_key_id = Some(key.id.clone());
    record.user_id = Some(user_id);
    write(path, tag, &record).map_err(failed)?;
    Ok((record, key, answered.created))
}

/// What a key's status calls for, in a line.
fn status_said(status: &SealKeyStatus) -> String {
    match status {
        SealKeyStatus::Pending => t!("worker_seal_keys.pending"),
        SealKeyStatus::Approved => t!("worker_seal_keys.approved"),
        SealKeyStatus::Revoked => t!("worker_seal_keys.revoked"),
        other => t!(
            "worker_seal_keys.other_status",
            status = kept::shown(other.as_str())
        ),
    }
}

/// `erpc worker seal show`, through `api` and `keeper`: this machine's
/// key, kept and registered first when it is not yet, and what the account
/// says of it.
pub(crate) async fn show_with(
    api: &impl SealAccount,
    keeper: &mut impl Keeper,
    path: &Path,
    tag: &str,
) -> Result<(Value, String), CliError> {
    let mut notes = Vec::new();
    let (record, shared) = this_machines(keeper, path, tag, &mut notes)?;
    let (record, key, now) = match record.seal_key_id.clone() {
        None => register(api, path, tag, record).await?,
        Some(id) => {
            let keys = api.seal_keys().await.map_err(|e| account_error(&e))?;
            let Some(key) = keys.into_iter().find(|k| k.id == id) else {
                return Err(failed(t!("worker_seal_keys.not_listed", id)).hint(t!(
                    "worker_seal_keys.not_listed_hint",
                    path = path.display()
                )));
            };
            if !is_ours(&key, &record) {
                return Err(failed(t!(
                    "worker_seal_keys.answer_differs",
                    fingerprint = record.fingerprint
                )));
            }
            (record, key, false)
        }
    };
    let id = key.id.as_str();
    let mut text = vec![
        t!(
            "worker_seal_keys.this_machine",
            fingerprint = record.fingerprint
        ),
        t!(
            "worker_seal_keys.as_listed",
            id,
            status = status_said(&key.status)
        ),
        t!("worker_seal_keys.kept_at", reference = record.kept),
    ];
    if now {
        text.push(t!("worker_seal_keys.registered_now"));
    }
    for note in notes {
        text.push(format!("note: {note}"));
    }
    match key.status {
        SealKeyStatus::Pending => text.push(format!(
            "hint: {}",
            t!(
                "worker_seal_keys.approve_hint",
                fingerprint = record.fingerprint
            )
        )),
        SealKeyStatus::Revoked => {
            text.push(format!("warning: {}", t!("worker_seal_keys.revoked_note")));
        }
        _ => {}
    }
    let answer = json!({
        "fingerprint": record.fingerprint,
        "public_key": record.public_key,
        "id": key.id,
        "status": kept::shown(key.status.as_str()),
        "kept": record.kept,
        "registered_now": now,
        "shared_vault": shared,
    });
    Ok((answer, text.join("\n")))
}

/// How a key of the account's list is marked.
struct Marked {
    /// What the row says after it.
    marks: String,
    /// It may be this machine's own key ([`may_be_this_machines`]).
    this: bool,
    /// It is listed under this machine's id with other bytes.
    other_bytes: bool,
    /// It is trusted here: by its bytes, or, revoked with none, by its id
    /// or fingerprint.
    trusts: bool,
}

/// How `k` is marked, by this machine's record `ours` and the keys
/// `trusted_here` (`by_bytes` whether its bytes are among them). This
/// machine's id listed with other bytes is not its key: said so, never
/// marked as this machine's. A key listed as revoked gives no bytes: it is
/// matched to what is trusted here by its id or fingerprint.
fn marked(k: &SealKey, ours: Option<&Record>, trusted_here: &[Trusted], by_bytes: bool) -> Marked {
    let other_bytes = ours.is_some_and(|r| {
        r.seal_key_id.as_deref() == Some(k.id.as_str())
            && computed(k).is_some_and(|(pk, _)| pk != r.public_key)
    });
    let this = !other_bytes && may_be_this_machines(k, ours);
    let revoked_here = k.status == SealKeyStatus::Revoked
        && k.public_key.is_none()
        && trusted_here
            .iter()
            .any(|t| t.id == k.id || t.fingerprint == k.fingerprint);
    let marks = if other_bytes {
        t!("worker_seal_keys.row_this_id_other_bytes")
    } else if this {
        t!("worker_seal_keys.row_this")
    } else if by_bytes {
        t!("worker_seal_keys.row_trusted")
    } else if revoked_here {
        t!("worker_seal_keys.row_revoked_trusted")
    } else {
        String::new()
    };
    Marked {
        marks,
        this,
        other_bytes,
        trusts: by_bytes || revoked_here,
    }
}

/// `erpc worker seal list`, through `api`: the account's sealing keys, this
/// machine's marked. What the account says is printed as text.
pub(crate) async fn list_with(
    api: &impl SealAccount,
    ours: Option<&Record>,
    trusted_here: &[Trusted],
) -> Result<(Value, String), CliError> {
    let keys = api.seal_keys().await.map_err(|e| account_error(&e))?;
    // Trust is of a key's bytes, under whatever id the account lists them.
    let trusted = |k: &SealKey| {
        computed(k).is_some_and(|(pk, _)| trusted_here.iter().any(|t| t.public_key == pk))
    };
    // Trusted here, and no longer listed by the account under any id.
    let unlisted: Vec<&Trusted> = trusted_here
        .iter()
        .filter(|t| {
            !keys.iter().any(|k| {
                computed(k).is_some_and(|(pk, _)| pk == t.public_key)
                    || (k.status == SealKeyStatus::Revoked
                        && k.public_key.is_none()
                        && (t.id == k.id || t.fingerprint == k.fingerprint))
            })
        })
        .collect();
    if keys.is_empty() && unlisted.is_empty() {
        return Ok((json!([]), t!("worker_seal_keys.none")));
    }
    let mut text = vec![t!("worker_seal_keys.list_title")];
    let mut answer = Vec::new();
    for k in &keys {
        let label = k.label.as_deref().map(kept::shown);
        let id = kept::shown(&k.id);
        let listed = if is_fingerprint(&k.fingerprint) {
            k.fingerprint.clone()
        } else {
            kept::shown(&k.fingerprint)
        };
        // The fingerprint shown is the one this machine computes from the
        // key's bytes; one the account lists otherwise is said beside it.
        let (print, differs) = match computed(k) {
            Some((_, print)) => {
                let differs = print != k.fingerprint;
                (print, differs)
            }
            None => (listed.clone(), false),
        };
        let Marked {
            mut marks,
            this,
            other_bytes,
            trusts,
        } = marked(k, ours, trusted_here, trusted(k));
        if differs {
            marks.push_str(&t!("worker_seal_keys.row_listed_otherwise", listed));
        }
        text.push(t!(
            "worker_seal_keys.row",
            fingerprint = print,
            id,
            status = status_said(&k.status),
            label = label.as_deref().unwrap_or("-"),
            this = marks
        ));
        answer.push(json!({
            "id": id,
            "fingerprint": print,
            "listed_fingerprint": listed,
            "label": label,
            "status": kept::shown(k.status.as_str()),
            "created_at": k.created_at.as_deref().map(kept::shown),
            "approved_at": k.approved_at.as_deref().map(kept::shown),
            "revoked_at": k.revoked_at.as_deref().map(kept::shown),
            "listed": true,
            "this_machine": this,
            "this_machines_id_other_bytes": other_bytes,
            "trusted_here": trusts,
        }));
    }
    for t in unlisted {
        let label = t.label.as_deref().map(kept::shown);
        text.push(t!(
            "worker_seal_keys.row_unlisted",
            fingerprint = t.fingerprint,
            id = kept::shown(&t.id),
            label = label.as_deref().unwrap_or("-")
        ));
        answer.push(json!({
            "id": kept::shown(&t.id),
            "fingerprint": t.fingerprint,
            "listed_fingerprint": null,
            "label": label,
            "status": null,
            "created_at": null,
            "approved_at": null,
            "revoked_at": null,
            "listed": false,
            "this_machine": false,
            "trusted_here": true,
        }));
    }
    Ok((Value::Array(answer), text.join("\n")))
}

/// `input` as a fingerprint in its form, `SHA256:` and 43 characters; the
/// prefix may be left out, and space around it is not counted, as the
/// dashboard takes one.
fn fingerprint_given(input: &str) -> Option<String> {
    let input = input.trim();
    let print = if input.starts_with("SHA256:") {
        input.to_owned()
    } else {
        format!("SHA256:{input}")
    };
    is_fingerprint(&print).then_some(print)
}

/// The public key and the fingerprint this machine computes of the
/// account's `key`, from its bytes: none for a revoked key, whose bytes the
/// account no longer says, or bytes not in their form.
fn computed(key: &SealKey) -> Option<(String, String)> {
    let text = key.public_key.as_deref()?;
    let bytes = crate::worker::seal::public_key(text).ok()?;
    Some((public_key_text(&bytes), fingerprint(&bytes)))
}

/// Whether `key` may be this machine's own, by `record`, for what is said
/// of it, never for what is trusted: its id is the one recorded, or its
/// bytes are this machine's (a key registered by a run whose answer was
/// lost has no id recorded), or, revoked with no bytes, its fingerprint is.
fn may_be_this_machines(key: &SealKey, record: Option<&Record>) -> bool {
    record.is_some_and(|r| {
        r.seal_key_id.as_deref() == Some(key.id.as_str())
            || computed(key).is_some_and(|(pk, _)| pk == r.public_key)
            || (key.public_key.is_none() && key.fingerprint == r.fingerprint)
    })
}

/// Whether the account lists the id of `key` more than once in `keys`: a
/// listing this machine cannot act on by that id.
fn id_listed_twice(keys: &[SealKey], key: &SealKey) -> bool {
    keys.iter().filter(|k| k.id == key.id).count() > 1
}

/// The account's key whose bytes have the fingerprint `print`, as this
/// machine computes it, with its public key: what the account says the
/// fingerprint is does not count. Refused: a key the account lists as
/// revoked, or in a state that is neither waiting nor approved, whatever
/// bytes it still gives; two keys with those bytes; an id not in its form
/// or listed twice; a key whose bytes have that fingerprint but that the
/// account lists with another; and a key listed with that fingerprint but
/// other bytes.
fn by_print<'k>(keys: &'k [SealKey], print: &str) -> Result<(&'k SealKey, String), CliError> {
    let found: Vec<(&SealKey, String)> = keys
        .iter()
        .filter_map(|k| {
            computed(k)
                .filter(|(_, p)| p == print)
                .map(|(pk, _)| (k, pk))
        })
        .collect();
    match found.as_slice() {
        [(key, _)] if key.status == SealKeyStatus::Revoked => Err(failed(t!(
            "worker_seal_keys.trust_revoked",
            fingerprint = print
        ))),
        [(key, _)] if !matches!(key.status, SealKeyStatus::Pending | SealKeyStatus::Approved) => {
            Err(failed(t!(
                "worker_seal_keys.trust_not_usable",
                fingerprint = print,
                status = status_said(&key.status)
            )))
        }
        [(key, _)] if !is_public_id(&key.id) => {
            Err(failed(t!("worker_seal_keys.answer_unreadable")))
        }
        [(key, _)] if id_listed_twice(keys, key) => Err(failed(t!(
            "worker_seal_keys.id_twice",
            id = kept::shown(&key.id)
        ))),
        // What the dashboard shows must be what is trusted, and no other
        // row may claim the fingerprint for other bytes.
        [(key, public_key)]
            if key.fingerprint != print
                || keys.iter().any(|k| {
                    k.fingerprint == print
                        && computed(k).map(|(pk, _)| pk).as_ref() != Some(public_key)
                }) =>
        {
            Err(failed(t!(
                "worker_seal_keys.listing_differs",
                fingerprint = print
            )))
        }
        [(key, public_key)] => Ok((key, public_key.clone())),
        [] => match keys.iter().find(|k| k.fingerprint == print) {
            Some(k) if k.status == SealKeyStatus::Revoked => Err(failed(t!(
                "worker_seal_keys.trust_revoked",
                fingerprint = print
            ))),
            Some(_) => Err(failed(t!(
                "worker_seal_keys.listing_differs",
                fingerprint = print
            ))),
            None => Err(
                failed(t!("worker_seal_keys.no_such_key", fingerprint = print))
                    .hint(t!("worker_seal_keys.no_such_key_hint")),
            ),
        },
        _ => Err(failed(t!(
            "worker_seal_keys.two_with_print",
            fingerprint = print
        ))),
    }
}

/// Who asks for a change of what is trusted or revoked.
#[derive(Debug, Clone)]
pub(crate) struct Asking {
    /// `--yes`, where a command takes it.
    pub(crate) yes: bool,
    /// `--json`: nobody is asked.
    pub(crate) json: bool,
    /// A terminal to ask at.
    pub(crate) terminal: bool,
    /// What the secret gate says of this process: a person, not an AI tool.
    pub(crate) person: Result<(), String>,
}

/// Refuses trust with nobody there to give it: under `--json`, with no
/// terminal, or past a secret gate that does not take this process for a
/// person. Asked before anything is reached.
fn may_trust(asking: &Asking) -> Result<(), CliError> {
    if asking.json || !asking.terminal {
        return Err(CliError::new(
            Code::NeedsTerminal,
            t!("worker_seal_keys.trust_needs_person"),
        )
        .hint(t!("worker_seal_keys.trust_needs_person_hint")));
    }
    if let Err(why) = &asking.person {
        return Err(failed(why.clone()));
    }
    Ok(())
}

/// What trusting `public_key` (id `id`) would do to `here`, the keys
/// trusted on this machine: nothing, for bytes trusted already under any
/// id; a refusal, for an id trusted with other bytes; else add it.
enum Trusting {
    Already,
    Differs(String),
    New,
}

fn trusting(here: &[Trusted], id: &str, public_key: &str) -> Trusting {
    if here.iter().any(|t| t.public_key == public_key) {
        return Trusting::Already;
    }
    match here.iter().find(|t| t.id == id) {
        Some(t) => Trusting::Differs(t.fingerprint.clone()),
        None => Trusting::New,
    }
}

/// `erpc worker seal trust <FINGERPRINT>`, through `api`: another
/// machine's key, found in the account by the fingerprint this machine
/// computes from the key's bytes, trusted here after a yes at a terminal.
/// Never with `--yes`, never under `--json`, never by an AI tool, and never
/// from what the account says of the key's approval. What is trusted is
/// the key's bytes: decided again under the record's lock when it is
/// written.
pub(crate) async fn trust_with(
    api: &impl SealAccount,
    path: &Path,
    tag: &str,
    input: &str,
    asking: &Asking,
    confirm: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<(Value, String), CliError> {
    let Some(print) = fingerprint_given(input) else {
        return Err(CliError::new(
            Code::Usage,
            t!(
                "worker_seal_keys.not_a_fingerprint",
                given = kept::shown(input)
            ),
        ));
    };
    may_trust(asking)?;
    let keys = api.seal_keys().await.map_err(|e| account_error(&e))?;
    let (key, public_key) = by_print(&keys, &print)?;
    let label = key.label.as_deref().map(kept::shown);
    let said = |already: bool, own: bool| {
        json!({
            "trusted": true,
            "id": key.id,
            "fingerprint": print,
            "label": label,
            "status": kept::shown(key.status.as_str()),
            "already": already,
            "this_machine": own,
        })
    };
    let ours = recorded(path, tag).map_err(failed)?;
    if ours.as_ref().is_some_and(|r| r.public_key == public_key) {
        return Ok((
            said(true, true),
            t!("worker_seal_keys.trust_own", fingerprint = print),
        ));
    }
    // This machine's own id with other bytes is no key to trust.
    if ours.is_some_and(|r| r.seal_key_id.as_deref() == Some(key.id.as_str())) {
        return Err(failed(t!(
            "worker_seal_keys.answer_differs",
            fingerprint = print
        )));
    }
    let differs = |was: String| {
        failed(t!(
            "worker_seal_keys.trusted_differs",
            id = key.id,
            fingerprint = was
        ))
    };
    match trusting(&trusted(path, tag).map_err(failed)?, &key.id, &public_key) {
        Trusting::Already => {
            return Ok((
                said(true, false),
                t!("worker_seal_keys.trusted_already", fingerprint = print),
            ));
        }
        Trusting::Differs(was) => return Err(differs(was)),
        Trusting::New => {}
    }
    let question = t!(
        "worker_seal_keys.trust_question",
        fingerprint = print,
        id = key.id,
        label = label.as_deref().unwrap_or("-"),
        status = status_said(&key.status)
    );
    if !confirm(&question).map_err(failed)? {
        return Err(CliError::new(
            Code::Declined,
            t!("worker_seal_keys.not_trusted"),
        ));
    }
    let entry = Trusted {
        id: key.id.clone(),
        public_key: public_key.clone(),
        fingerprint: print.clone(),
        label: label.clone(),
    };
    // Decided again under the lock: another run may have trusted these
    // bytes, or this id with other bytes, while the person was asked.
    let outcome = change_trusted(path, tag, |list| {
        let outcome = trusting(list, &entry.id, &entry.public_key);
        if matches!(outcome, Trusting::New) {
            list.push(entry);
        }
        Ok(outcome)
    })
    .map_err(failed)?;
    match outcome {
        Trusting::Already => Ok((
            said(true, false),
            t!("worker_seal_keys.trusted_already", fingerprint = print),
        )),
        Trusting::Differs(was) => Err(differs(was)),
        Trusting::New => Ok((
            said(false, false),
            t!("worker_seal_keys.trusted_now", fingerprint = print),
        )),
    }
}

/// Whether `input` names the key with `id` and fingerprint `print`: its id,
/// or its fingerprint (the prefix may be left out).
fn names(input: &str, id: &str, print: &str) -> bool {
    let input = input.trim();
    input == id || fingerprint_given(input).is_some_and(|p| p == print)
}

/// Drops from `list` every key that is any of `gone` by id, fingerprint or
/// bytes: one key the account listed under two ids goes with either.
fn drop_all(list: &mut Vec<Trusted>, gone: &[(String, Option<String>, String)]) {
    list.retain(|t| {
        !gone.iter().any(|(id, public_key, print)| {
            t.id == *id
                || t.fingerprint == *print
                || public_key.as_deref() == Some(t.public_key.as_str())
        })
    });
}

/// `erpc worker seal untrust <KEY>`: another machine's key is no longer
/// trusted here, by its fingerprint or id, under any id it is trusted by.
/// Only this machine's record changes.
pub(crate) fn untrust_with(
    path: &Path,
    tag: &str,
    input: &str,
) -> Result<(Value, String), CliError> {
    let here = trusted(path, tag).map_err(failed)?;
    let gone: Vec<(String, Option<String>, String)> = here
        .iter()
        .filter(|t| names(input, &t.id, &t.fingerprint))
        .map(|t| {
            (
                t.id.clone(),
                Some(t.public_key.clone()),
                t.fingerprint.clone(),
            )
        })
        .collect();
    let Some((_, _, print)) = gone.first().cloned() else {
        return Err(failed(t!(
            "worker_seal_keys.not_trusted_here",
            key = kept::shown(input)
        ))
        .hint(t!("worker_seal_keys.not_trusted_here_hint")));
    };
    change_trusted(path, tag, |list| {
        drop_all(list, &gone);
        Ok(())
    })
    .map_err(failed)?;
    Ok((
        json!({ "untrusted": true, "fingerprint": print }),
        t!("worker_seal_keys.untrusted", fingerprint = print),
    ))
}

/// The one key of `keys` that `input` names, by id or by fingerprint
/// (`print_of` gives a key's), with its id in its form.
fn named_key<'k>(
    keys: &'k [SealKey],
    input: &str,
    print_of: impl Fn(&SealKey) -> String,
) -> Result<&'k SealKey, CliError> {
    let found: Vec<&SealKey> = keys
        .iter()
        .filter(|k| names(input, &k.id, &print_of(k)))
        .collect();
    match found.as_slice() {
        [one] if !is_public_id(&one.id) => Err(failed(t!("worker_seal_keys.answer_unreadable"))),
        [one] if id_listed_twice(keys, one) => Err(failed(t!(
            "worker_seal_keys.id_twice",
            id = kept::shown(&one.id)
        ))),
        [one] => Ok(one),
        [] => Err(failed(t!(
            "worker_seal_keys.no_such_key_named",
            key = kept::shown(input)
        ))
        .hint(t!("worker_seal_keys.no_such_key_hint"))),
        _ => Err(failed(t!(
            "worker_seal_keys.two_named",
            key = kept::shown(input)
        ))),
    }
}

/// `erpc worker seal revoke <KEY>`, through `api`: a key of the account,
/// by its id or fingerprint, revoked there for good after a yes (`--yes`,
/// or at a terminal); what was sealed to it goes with it. No longer trusted
/// here either, under any id, once the account says it is revoked.
pub(crate) async fn revoke_with(
    api: &impl SealAccount,
    path: &Path,
    tag: &str,
    input: &str,
    asking: &Asking,
    confirm: impl FnOnce(&str) -> Result<bool, String>,
) -> Result<(Value, String), CliError> {
    let keys = api.seal_keys().await.map_err(|e| account_error(&e))?;
    let print_of = |k: &SealKey| computed(k).map_or_else(|| k.fingerprint.clone(), |(_, p)| p);
    let key = named_key(&keys, input, print_of)?;
    let print = print_of(key);
    let print = if is_fingerprint(&print) {
        print
    } else {
        kept::shown(&print)
    };
    let gone = vec![(
        key.id.clone(),
        computed(key).map(|(pk, _)| pk),
        print.clone(),
    )];
    let forget_here = || {
        change_trusted(path, tag, |list| {
            drop_all(list, &gone);
            Ok(())
        })
        .map_err(failed)
    };
    let own = may_be_this_machines(key, recorded(path, tag).map_err(failed)?.as_ref());
    if key.status == SealKeyStatus::Revoked {
        forget_here()?;
        return Ok((
            json!({ "revoked": true, "id": key.id, "fingerprint": print, "already": true, "this_machine": own }),
            t!("worker_seal_keys.revoked_already", fingerprint = print),
        ));
    }
    let label = key.label.as_deref().map(kept::shown);
    let mut question = t!(
        "worker_seal_keys.revoke_question",
        fingerprint = print,
        id = key.id,
        label = label.as_deref().unwrap_or("-")
    );
    if own {
        question = format!("{question} {}", t!("worker_seal_keys.revoke_own_note"));
    }
    if asking.yes {
        if own && !asking.json {
            crate::node::common::Say { quiet: false }.line(&format!(
                "warning: {}",
                t!("worker_seal_keys.revoke_own_note")
            ));
        }
    } else {
        if asking.json || !asking.terminal {
            return Err(CliError::new(
                Code::NeedsTerminal,
                t!("worker_seal_keys.revoke_needs_yes", fingerprint = print),
            )
            .hint(t!("worker_seal_keys.revoke_needs_yes_hint")));
        }
        if !confirm(&question).map_err(failed)? {
            return Err(CliError::new(
                Code::Declined,
                t!("worker_seal_keys.not_revoked"),
            ));
        }
    }
    let answered = api.revoke(&key.id).await.map_err(|e| {
        let said = account_error(&e);
        if answer_lost(&e) {
            said.hint(t!("worker_seal_keys.revoke_lost_hint"))
        } else {
            said
        }
    })?;
    if answered.key.id != key.id || answered.key.status != SealKeyStatus::Revoked {
        return Err(failed(t!(
            "worker_seal_keys.revoke_unconfirmed",
            fingerprint = print
        ))
        .hint(t!("worker_seal_keys.revoke_unconfirmed_hint")));
    }
    forget_here()?;
    let mut text = vec![t!("worker_seal_keys.revoked_now", fingerprint = print)];
    if own {
        text.push(format!("warning: {}", t!("worker_seal_keys.revoked_note")));
    }
    Ok((
        json!({ "revoked": true, "id": key.id, "fingerprint": print, "already": false, "this_machine": own }),
        text.join("\n"),
    ))
}

/// Whether `e` may follow a request the account carried out: its answer
/// lost on the way, unreadable, or a failure on the account's side. A
/// request refused as such, or never sent, is not.
fn answer_lost(e: &WorkerError) -> bool {
    match e {
        WorkerError::Refused(r) => r.status >= 500,
        WorkerError::Api(erpc_api::ApiError::Status(status)) => *status >= 500,
        WorkerError::Api(erpc_api::ApiError::Http(_) | erpc_api::ApiError::Malformed(_)) => true,
        _ => false,
    }
}

/// Signed in, with what this machine files the account's records under.
async fn signed() -> Result<(kept::Signed, String), CliError> {
    let signed = kept::Signed::open().await?;
    let uid = kept::Account::uid(&signed).await?;
    Ok((signed, kept::uid_tag(&uid)))
}

/// `erpc worker seal show`.
pub(crate) async fn show(json: bool, flag: Option<StoreFlag>, vault: Option<String>) -> Outcome {
    let run = async {
        let (signed, tag) = signed().await?;
        let path = records_path().map_err(failed)?;
        show_with(&signed, &mut Stores::new(flag, vault), &path, &tag).await
    };
    match run.await {
        Ok((answer, text)) => crate::worker::remote::done(json, &answer, text),
        Err(e) => e.into(),
    }
}

/// `erpc worker seal list`.
pub(crate) async fn list(json: bool) -> Outcome {
    let run = async {
        let (signed, tag) = signed().await?;
        let path = records_path().map_err(failed)?;
        let ours = recorded(&path, &tag).map_err(failed)?;
        let here = trusted(&path, &tag).map_err(failed)?;
        list_with(&signed, ours.as_ref(), &here).await
    };
    match run.await {
        Ok((answer, text)) => crate::worker::remote::done(json, &answer, text),
        Err(e) => e.into(),
    }
}

/// Who is asking, on this machine.
fn asking_here(json: bool, yes: bool) -> Asking {
    Asking {
        yes,
        json,
        terminal: crate::account::session::has_terminal(),
        person: secrets::gate(secrets::context()),
    }
}

/// `erpc worker seal trust`.
pub(crate) async fn trust(json: bool, fingerprint: &str) -> Outcome {
    let run = async {
        let asking = asking_here(json, false);
        // Nobody to give it: refused before anything is reached.
        may_trust(&asking)?;
        let (signed, tag) = signed().await?;
        let path = records_path().map_err(failed)?;
        trust_with(
            &signed,
            &path,
            &tag,
            fingerprint,
            &asking,
            crate::node::common::confirm,
        )
        .await
    };
    match run.await {
        Ok((answer, text)) => crate::worker::remote::done(json, &answer, text),
        Err(e) => e.into(),
    }
}

/// `erpc worker seal untrust`.
pub(crate) async fn untrust(json: bool, key: &str) -> Outcome {
    let run = async {
        let (_, tag) = signed().await?;
        let path = records_path().map_err(failed)?;
        untrust_with(&path, &tag, key)
    };
    match run.await {
        Ok((answer, text)) => crate::worker::remote::done(json, &answer, text),
        Err(e) => e.into(),
    }
}

/// `erpc worker seal revoke`.
pub(crate) async fn revoke(json: bool, key: &str, yes: bool) -> Outcome {
    let run = async {
        let asking = asking_here(json, yes);
        let (signed, tag) = signed().await?;
        let path = records_path().map_err(failed)?;
        revoke_with(
            &signed,
            &path,
            &tag,
            key,
            &asking,
            crate::node::common::confirm,
        )
        .await
    };
    match run.await {
        Ok((answer, text)) => crate::worker::remote::done(json, &answer, text),
        Err(e) => e.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use erpc_api::worker::Refusal;

    use super::*;

    /// The account, in memory: its keys, and how it answers a register.
    #[derive(Default)]
    struct Fake {
        keys: RefCell<Vec<SealKey>>,
        /// A refusal the next register answers.
        refuse: RefCell<Option<WorkerError>>,
        /// Answer a register with another key's bytes.
        swap: bool,
        /// Answer a register with this id, or this account number.
        id: Option<String>,
        user_id: Option<u64>,
        registered: RefCell<u32>,
        /// What a revoke answers instead of the key it revoked.
        revoke_answer: RefCell<Option<RegisteredKey>>,
        /// Revoke, and lose the answer on the way.
        revoke_lost: RefCell<bool>,
    }

    fn key(id: &str, public_key: Option<&str>, fingerprint: &str, status: &str) -> SealKey {
        serde_json::from_value(json!({
            "id": id, "publicKey": public_key, "fingerprint": fingerprint,
            "label": null, "status": status
        }))
        .expect("a key")
    }

    fn registered(k: &SealKey, user_id: u64) -> RegisteredKey {
        serde_json::from_value(json!({
            "id": k.id, "publicKey": k.public_key, "fingerprint": k.fingerprint,
            "status": k.status.as_str(), "userId": user_id
        }))
        .expect("registered")
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the stand-in answers at once"
    )]
    impl SealAccount for Fake {
        async fn seal_keys(&self) -> Result<Vec<SealKey>, WorkerError> {
            Ok(self.keys.borrow().clone())
        }

        async fn register(&self, public_key: &str) -> Result<Written<RegisteredKey>, WorkerError> {
            *self.registered.borrow_mut() += 1;
            if let Some(e) = self.refuse.borrow_mut().take() {
                return Err(e);
            }
            let user_id = self.user_id.unwrap_or(100_001);
            let mut keys = self.keys.borrow_mut();
            let bytes = crate::worker::seal::public_key(public_key).expect("a public key");
            if let Some(k) = keys.iter().find(|k| k.fingerprint == fingerprint(&bytes)) {
                return Ok(Written::new(false, registered(k, user_id)));
            }
            let (said, print) = if self.swap {
                let other = SecretKey::derive(b"another machine").expect("a key");
                let other = other.public().expect("public");
                (public_key_text(&other), fingerprint(&other))
            } else {
                (public_key.to_owned(), fingerprint(&bytes))
            };
            let id = self.id.clone().unwrap_or_else(|| {
                format!("3f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b{:02}", keys.len() + 13)
            });
            let k = key(&id, Some(&said), &print, "pending");
            keys.push(k.clone());
            Ok(Written::new(true, registered(&k, user_id)))
        }

        async fn revoke(&self, id: &str) -> Result<RegisteredKey, WorkerError> {
            if let Some(answer) = self.revoke_answer.borrow_mut().take() {
                return Ok(answer);
            }
            if *self.revoke_lost.borrow() {
                return Err(WorkerError::Api(erpc_api::ApiError::Malformed(
                    "cut off".to_owned(),
                )));
            }
            let mut keys = self.keys.borrow_mut();
            let k = keys.iter_mut().find(|k| k.id == id).ok_or_else(|| {
                WorkerError::Refused(Refusal {
                    status: 404,
                    code: Some(AccountCode::from("seal_key_not_found")),
                    message: None,
                    data: Value::Null,
                })
            })?;
            k.status = SealKeyStatus::Revoked;
            k.public_key = None;
            Ok(registered(k, 100_001))
        }
    }

    /// A store, in memory.
    #[derive(Default)]
    struct Memory {
        kept: RefCell<BTreeMap<String, String>>,
        readied: u32,
        asked: bool,
    }

    impl Keeper for Memory {
        fn ready(&mut self) -> Result<(), String> {
            self.readied += 1;
            Ok(())
        }

        fn there(&self, tag: &str) -> Result<Option<(String, Zeroizing<String>)>, String> {
            let reference = format!("keystore:erpc-worker-seal/{tag}.seal");
            Ok(self
                .kept
                .borrow()
                .get(&reference)
                .map(|k| (reference.clone(), Zeroizing::new(k.clone()))))
        }

        fn keep(&self, tag: &str, key: &str) -> Result<String, String> {
            let reference = format!("keystore:erpc-worker-seal/{tag}.seal");
            self.kept
                .borrow_mut()
                .insert(reference.clone(), key.to_owned());
            Ok(reference)
        }

        fn read(&self, reference: &str) -> Result<Zeroizing<String>, String> {
            self.kept
                .borrow()
                .get(reference)
                .map(|k| Zeroizing::new(k.clone()))
                .ok_or_else(|| format!("nothing kept at {reference}"))
        }

        fn shared(&self) -> Option<String> {
            None
        }

        fn asked(&self) -> bool {
            self.asked
        }
    }

    const TAG: &str = "0123456789abcdef";
    /// Made-up 1Password ids, built so no bare one is in the source.
    const VAULT: &str = concat!("abcdefghijklm", "nopqrstuvwxyz");
    const ITEM: &str = concat!("abcdefghijklm", "nopqrstuvwxy0");
    const ITEM_ELSE: &str = concat!("abcdefghijklm", "nopqrstuvwxy1");

    fn path_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join(FILE)
    }

    #[tokio::test]
    async fn a_first_show_makes_keeps_records_and_registers_the_key_and_a_second_reads_it() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let mut store = Memory::default();
        let (answer, text) = show_with(&api, &mut store, &path, TAG)
            .await
            .expect("shown");
        assert_eq!(answer["registered_now"], true);
        assert_eq!(answer["status"], "pending");
        assert_eq!(answer["shared_vault"], Value::Null);
        let fp = answer["fingerprint"]
            .as_str()
            .expect("a fingerprint")
            .to_owned();
        assert!(is_fingerprint(&fp), "{fp}");
        assert!(text.contains(&fp) && text.contains("dashboard"), "{text}");
        // The record names where the key is, and never the key.
        let record = recorded(&path, TAG).expect("readable").expect("recorded");
        let kept = store.kept.borrow().values().next().cloned().expect("kept");
        assert!(
            !std::fs::read_to_string(&path)
                .expect("read")
                .contains(&kept)
        );
        assert!(record.seal_key_id.as_deref().is_some_and(is_public_id));
        assert_eq!(record.user_id, Some(100_001));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("there")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Again: read back and listed, nothing made or registered; a store
        // asked for is said to be set aside.
        store.asked = true;
        let (again, text) = show_with(&api, &mut store, &path, TAG)
            .await
            .expect("shown");
        assert_eq!(again["registered_now"], false);
        assert_eq!(again["fingerprint"], fp.as_str());
        assert!(text.contains("note:"), "{text}");
        assert_eq!(*api.registered.borrow(), 1);
        assert_eq!(store.readied, 1);
        assert_eq!(store.kept.borrow().len(), 1);
    }

    #[tokio::test]
    async fn a_register_that_stopped_goes_on_with_the_same_key() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        *api.refuse.borrow_mut() = Some(WorkerError::Api(erpc_api::ApiError::Unauthorized));
        let mut store = Memory::default();
        let e = show_with(&api, &mut store, &path, TAG)
            .await
            .expect_err("stopped");
        assert_eq!(e.code, Code::NotSignedIn);
        let before = recorded(&path, TAG).expect("readable").expect("recorded");
        assert_eq!(before.seal_key_id, None);
        show_with(&api, &mut store, &path, TAG)
            .await
            .expect("shown");
        let after = recorded(&path, TAG).expect("readable").expect("recorded");
        assert_eq!(after.public_key, before.public_key);
        assert_eq!(store.kept.borrow().len(), 1);
        // A key kept with no record of it (the record lost) is taken up
        // again, not made twice, and found registered already.
        std::fs::remove_file(&path).expect("removed");
        let (answer, _) = show_with(&api, &mut store, &path, TAG)
            .await
            .expect("shown");
        assert_eq!(answer["public_key"], before.public_key.as_str());
        assert_eq!(answer["registered_now"], false);
        assert_eq!(store.kept.borrow().len(), 1);
    }

    #[tokio::test]
    async fn an_answer_with_another_key_or_out_of_its_form_is_not_taken() {
        for api in [
            Fake {
                swap: true,
                ..Fake::default()
            },
            Fake {
                id: Some("300003\u{1b}[2K".to_owned()),
                ..Fake::default()
            },
            Fake {
                user_id: Some(0),
                ..Fake::default()
            },
            Fake {
                user_id: Some(USER_ID_MAX + 1),
                ..Fake::default()
            },
        ] {
            let dir = tempfile::tempdir().expect("a directory");
            let path = path_in(&dir);
            let e = show_with(&api, &mut Memory::default(), &path, TAG)
                .await
                .expect_err("refused");
            assert!(!e.message.contains('\u{1b}'), "{}", e.message);
            let record = recorded(&path, TAG).expect("readable").expect("recorded");
            assert_eq!(record.seal_key_id, None);
            assert_eq!(record.user_id, None);
        }
    }

    #[tokio::test]
    async fn a_key_revoked_already_is_said_as_revoked() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let mut store = Memory::default();
        // Kept here, its record lost, and revoked in the account meanwhile.
        let made = SecretKey::derive(b"this machine").expect("a key");
        let public = made.public().expect("public");
        store.keep(TAG, &made.to_text()).expect("kept");
        let api = Fake::default();
        api.keys.borrow_mut().push(key(
            "3f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b99",
            None,
            &fingerprint(&public),
            "revoked",
        ));
        let (answer, text) = show_with(&api, &mut store, &path, TAG)
            .await
            .expect("shown");
        assert_eq!(answer["status"], "revoked");
        assert!(
            text.contains("warning:") && text.contains("revoked"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn eight_keys_waiting_is_said_with_the_way_out() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        *api.refuse.borrow_mut() = Some(WorkerError::Refused(Refusal {
            status: 422,
            code: Some(AccountCode::from("limit_exceeded")),
            message: None,
            data: Value::Null,
        }));
        let e = show_with(&api, &mut Memory::default(), &path, TAG)
            .await
            .expect_err("refused");
        assert!(e.hint.unwrap_or_default().contains("dashboard"));
    }

    #[tokio::test]
    async fn a_kept_key_that_is_not_the_one_recorded_is_refused() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let mut store = Memory::default();
        show_with(&api, &mut store, &path, TAG)
            .await
            .expect("shown");
        let other = SecretKey::derive(b"another machine")
            .expect("a key")
            .to_text();
        for value in store.kept.borrow_mut().values_mut() {
            value.clone_from(&other);
        }
        let e = show_with(&api, &mut store, &path, TAG)
            .await
            .expect_err("refused");
        assert!(e.message.contains("not the key"), "{}", e.message);
    }

    #[tokio::test]
    async fn the_list_marks_this_machines_key_and_shows_what_the_account_says_as_text() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        show_with(&api, &mut Memory::default(), &path, TAG)
            .await
            .expect("shown");
        let mut other = key(
            "3f1c2b9e\u{1b}[2K",
            None,
            "SHA256:\nThis machine's sealing key: SHA256:x",
            "approved",
        );
        other.label = Some("laptop\u{1b}[31m".to_owned());
        api.keys.borrow_mut().push(other);
        let ours = recorded(&path, TAG).expect("readable");
        let (answer, text) = list_with(&api, ours.as_ref(), &[]).await.expect("listed");
        assert_eq!(answer[0]["this_machine"], true);
        assert_eq!(answer[1]["this_machine"], false);
        assert!(!text.contains('\u{1b}'), "{text}");
        assert_eq!(text.lines().count(), 3, "{text}");
        let (_, empty) = list_with(&Fake::default(), None, &[])
            .await
            .expect("listed");
        assert!(empty.contains("no sealing key"), "{empty}");
    }

    #[test]
    fn a_1password_item_recorded_here_holds_a_seal_key_by_any_field_in_any_case() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let (vault, item) = (VAULT, ITEM);
        let named = |field: &str| {
            SecretRef::parse(&format!("op://{vault}/{item}/{field}")).expect("a reference")
        };
        assert!(!item_recorded_at(&path, &named("erpc-worker-seal")));
        let record = Record {
            kept: named("erpc-worker-seal").to_string(),
            public_key: String::new(),
            fingerprint: String::new(),
            seal_key_id: None,
            user_id: None,
        };
        write(&path, TAG, &record).expect("written");
        for field in ["erpc-worker-seal", "ERPC-WORKER-SEAL", "credential"] {
            assert!(item_recorded_at(&path, &named(field)), "{field}");
        }
        let elsewhere =
            SecretRef::parse(&format!("op://{vault}/{ITEM_ELSE}/x")).expect("a reference");
        assert!(!item_recorded_at(&path, &elsewhere));
    }

    #[test]
    fn a_sealing_key_kept_in_the_keystore_is_found_again_and_read_as_nothing_else() {
        use crate::worker::keystore::fake::{FakeDesk, PASSPHRASE, set_up};
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, _store) = set_up(&desk);
        let store = Store::Keystore { by_default: false };
        assert!(
            secrets::seal_key_there(&store, TAG)
                .expect("asked")
                .is_none()
        );
        let made = SecretKey::derive(b"this machine").expect("a key").to_text();
        let reference = secrets::put_seal_key(&store, TAG, &made).expect("kept");
        assert_eq!(
            reference.to_string(),
            format!("keystore:erpc-worker-seal/{TAG}.seal")
        );
        let (again, read) = secrets::seal_key_there(&store, TAG)
            .expect("asked")
            .expect("there");
        assert_eq!(again, reference);
        assert_eq!(read.as_str(), made.as_str());
        // Nothing kept there is written over.
        assert!(secrets::put_seal_key(&store, TAG, &made).is_err());
        // Not a setting, and not a trading key.
        assert!(secrets::read(&reference).is_err());
        assert!(secrets::read_key(&reference, None).is_err());
        // And nothing that is not a sealing key's place is read as one.
        let setting = SecretRef::parse("keystore:erpc-worker/bot.API_TOKEN").expect("a ref");
        assert!(secrets::read_seal_key(&setting).is_err());
        for sealed in [
            format!("op://{VAULT}/{ITEM}/ERPC-Worker-Seal"),
            format!("keychain:seal.erpc-worker-seal/{TAG}"),
        ] {
            let r = SecretRef::parse(&sealed).expect("a reference");
            let e = secrets::read(&r).expect_err("refused");
            assert!(e.contains("sealing key"), "{sealed}: {e}");
        }
    }

    /// Another machine's key in the account: its id, public key and
    /// fingerprint.
    fn another(api: &Fake, label: &str) -> (String, String, String) {
        let other = SecretKey::derive(label.as_bytes()).expect("a key");
        let public = other.public().expect("public");
        let id = format!(
            "4a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c{:02}",
            api.keys.borrow().len() + 10
        );
        let mut k = key(
            &id,
            Some(&public_key_text(&public)),
            &fingerprint(&public),
            "approved",
        );
        k.label = Some(label.to_owned());
        api.keys.borrow_mut().push(k);
        (id, public_key_text(&public), fingerprint(&public))
    }

    fn at_a_terminal() -> Asking {
        Asking {
            yes: false,
            json: false,
            terminal: true,
            person: Ok(()),
        }
    }

    fn refuse(_: &str) -> Result<bool, String> {
        panic!("nobody is asked")
    }

    #[tokio::test]
    async fn a_key_is_trusted_by_its_fingerprint_at_a_terminal_only_after_a_yes() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (id, public_key, print) = another(&api, "laptop");
        // Not under --json, not with no terminal, not past a refusing gate.
        for asking in [
            Asking {
                json: true,
                ..at_a_terminal()
            },
            Asking {
                terminal: false,
                ..at_a_terminal()
            },
            Asking {
                person: Err("an AI tool".to_owned()),
                ..at_a_terminal()
            },
        ] {
            assert!(
                trust_with(&api, &path, TAG, &print, &asking, refuse)
                    .await
                    .is_err()
            );
        }
        // A no: nothing trusted.
        let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(false))
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        assert!(trusted(&path, TAG).expect("readable").is_empty());
        // A yes, with the fingerprint given without its prefix: trusted,
        // with the bytes as read here.
        let bare = print.trim_start_matches("SHA256:");
        let (answer, _) = trust_with(
            &api,
            &path,
            TAG,
            &format!(" {bare} "),
            &at_a_terminal(),
            |q| {
                assert!(q.contains("laptop") && q.contains(&id), "{q}");
                Ok(true)
            },
        )
        .await
        .expect("trusted");
        assert_eq!(answer["already"], false);
        let here = trusted(&path, TAG).expect("readable");
        assert_eq!(here.len(), 1);
        assert_eq!(here[0].public_key, public_key);
        // Again: trusted already, nobody asked.
        let (again, _) = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
            .await
            .expect("trusted");
        assert_eq!(again["already"], true);
        // The list marks it.
        let (listed, _) = list_with(&api, None, &here).await.expect("listed");
        assert_eq!(listed[0]["trusted_here"], true);
    }

    #[tokio::test]
    async fn a_key_is_found_by_the_fingerprint_computed_here_not_the_one_the_account_says() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (_, _, print) = another(&api, "laptop");
        // Another row claims that fingerprint for other bytes: the listing
        // is not to be trusted, and nothing is, nobody asked.
        let (_, _, other) = another(&api, "desktop");
        api.keys.borrow_mut()[1].fingerprint = print.clone();
        let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
            .await
            .expect_err("refused");
        assert!(e.message.contains("differ"), "{}", e.message);
        assert!(trusted(&path, TAG).expect("readable").is_empty());
        // That row gone, the key with those bytes is found and trusted.
        api.keys.borrow_mut().pop();
        let (answer, _) = trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
            .await
            .expect("trusted");
        assert_eq!(answer["label"], "laptop");
        assert_ne!(other, print);
        // Not a fingerprint, or none in the account: said so.
        let e = trust_with(&api, &path, TAG, "laptop", &at_a_terminal(), refuse)
            .await
            .expect_err("refused");
        assert_eq!(e.code, Code::Usage);
        let missing = format!("SHA256:{}", "A".repeat(43));
        assert!(
            trust_with(&api, &path, TAG, &missing, &at_a_terminal(), refuse)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn this_machines_own_key_needs_no_trust_and_a_revoked_one_is_not_trusted() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (shown, _) = show_with(&api, &mut Memory::default(), &path, TAG)
            .await
            .expect("shown");
        let own = shown["fingerprint"]
            .as_str()
            .expect("a fingerprint")
            .to_owned();
        let (answer, _) = trust_with(&api, &path, TAG, &own, &at_a_terminal(), refuse)
            .await
            .expect("its own");
        assert_eq!(answer["this_machine"], true);
        assert!(trusted(&path, TAG).expect("readable").is_empty());
        let (id, _, print) = another(&api, "laptop");
        api.revoke(&id).await.expect("revoked");
        let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
            .await
            .expect_err("refused");
        assert!(e.message.contains("revoked"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_key_is_untrusted_here_by_its_fingerprint_or_id() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (id, _, print) = another(&api, "laptop");
        trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
            .await
            .expect("trusted");
        untrust_with(&path, TAG, &id).expect("untrusted");
        assert!(trusted(&path, TAG).expect("readable").is_empty());
        assert!(untrust_with(&path, TAG, &print).is_err());
    }

    #[tokio::test]
    async fn a_key_is_revoked_after_a_yes_and_is_no_longer_trusted_here() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (id, _, print) = another(&api, "laptop");
        trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
            .await
            .expect("trusted");
        // Nobody to ask and no --yes: refused, nothing sent.
        let e = revoke_with(
            &api,
            &path,
            TAG,
            &id,
            &Asking {
                terminal: false,
                ..at_a_terminal()
            },
            refuse,
        )
        .await
        .expect_err("refused");
        assert_eq!(e.code, Code::NeedsTerminal);
        assert_eq!(api.keys.borrow()[0].status, SealKeyStatus::Approved);
        // A no at a terminal: nothing sent.
        let e = revoke_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(false))
            .await
            .expect_err("declined");
        assert_eq!(e.code, Code::Declined);
        // A yes: revoked in the account, and no longer trusted here.
        let (answer, _) = revoke_with(&api, &path, TAG, &print, &at_a_terminal(), |q| {
            assert!(q.contains("laptop"), "{q}");
            Ok(true)
        })
        .await
        .expect("revoked");
        assert_eq!(answer["revoked"], true);
        assert_eq!(api.keys.borrow()[0].status, SealKeyStatus::Revoked);
        assert!(trusted(&path, TAG).expect("readable").is_empty());
        // Again: revoked already, said so, nobody asked.
        let (again, _) = revoke_with(&api, &path, TAG, &id, &at_a_terminal(), refuse)
            .await
            .expect("revoked");
        assert_eq!(again["already"], true);
    }

    #[tokio::test]
    async fn revoking_this_machines_own_key_says_what_it_takes_away() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (shown, _) = show_with(&api, &mut Memory::default(), &path, TAG)
            .await
            .expect("shown");
        let own = shown["fingerprint"]
            .as_str()
            .expect("a fingerprint")
            .to_owned();
        let (answer, text) = revoke_with(
            &api,
            &path,
            TAG,
            &own,
            &Asking {
                yes: true,
                terminal: false,
                ..at_a_terminal()
            },
            refuse,
        )
        .await
        .expect("revoked");
        assert_eq!(answer["this_machine"], true);
        assert!(text.contains("warning:"), "{text}");
    }

    #[test]
    fn a_1password_reference_names_its_vault_as_shared() {
        assert_eq!(
            vault_of(&format!("op://{VAULT}/{ITEM}/erpc-worker-seal")).as_deref(),
            Some(VAULT)
        );
        assert_eq!(
            vault_of("keystore:erpc-worker-seal/0123456789abcdef.seal"),
            None
        );
    }

    /// A key of another machine in the account, listed as `status`, with
    /// its bytes.
    fn listed(api: &Fake, seed: &str, id: &str, status: &str) -> (String, String) {
        let other = SecretKey::derive(seed.as_bytes()).expect("a key");
        let public = other.public().expect("public");
        let k = key(
            id,
            Some(&public_key_text(&public)),
            &fingerprint(&public),
            status,
        );
        api.keys.borrow_mut().push(k);
        (public_key_text(&public), fingerprint(&public))
    }

    const ID_X: &str = "5b2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c01";
    const ID_Y: &str = "5b2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c02";

    #[tokio::test]
    async fn a_key_listed_as_revoked_or_not_usable_is_not_trusted_whatever_bytes_it_gives() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        for status in ["revoked", "suspended"] {
            let api = Fake::default();
            let (_, print) = listed(&api, "laptop", ID_X, status);
            let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
                .await
                .expect_err("refused");
            assert!(!e.message.is_empty());
            assert!(trusted(&path, TAG).expect("readable").is_empty());
        }
    }

    #[tokio::test]
    async fn trust_is_of_the_bytes_under_any_id_and_untrust_drops_them_under_every_id() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (_, print) = listed(&api, "laptop", ID_X, "approved");
        trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
            .await
            .expect("trusted");
        // The account now lists the same bytes under another id.
        api.keys.borrow_mut()[0].id = ID_Y.to_owned();
        let (again, _) = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
            .await
            .expect("trusted already");
        assert_eq!(again["already"], true);
        let here = trusted(&path, TAG).expect("readable");
        let (listed_now, _) = list_with(&api, None, &here).await.expect("listed");
        assert_eq!(listed_now[0]["trusted_here"], true);
        untrust_with(&path, TAG, &print).expect("untrusted");
        let here = trusted(&path, TAG).expect("readable");
        assert!(here.is_empty(), "{here:?}");
        let (listed_now, _) = list_with(&api, None, &here).await.expect("listed");
        assert_eq!(listed_now[0]["trusted_here"], false);
    }

    #[tokio::test]
    async fn an_id_trusted_with_other_bytes_is_refused_even_when_another_run_wrote_it_meanwhile() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (_, print) = listed(&api, "laptop", ID_X, "approved");
        // While the person is asked, another run trusts the same id with
        // other bytes: decided again under the lock, and refused.
        let other = SecretKey::derive(b"desktop")
            .expect("a key")
            .public()
            .expect("public");
        let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| {
            change_trusted(&path, TAG, |list| {
                list.push(Trusted {
                    id: ID_X.to_owned(),
                    public_key: public_key_text(&other),
                    fingerprint: fingerprint(&other),
                    label: None,
                });
                Ok(())
            })?;
            Ok(true)
        })
        .await
        .expect_err("refused");
        assert!(e.message.contains("other bytes"), "{}", e.message);
        assert_eq!(trusted(&path, TAG).expect("readable").len(), 1);
        // And the account listing that id with other bytes than trusted
        // takes the mark off.
        let here = trusted(&path, TAG).expect("readable");
        let (listed_now, _) = list_with(&api, None, &here).await.expect("listed");
        assert_eq!(listed_now[0]["trusted_here"], false);
        let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
            .await
            .expect_err("refused");
        assert!(e.message.contains("other bytes"), "{}", e.message);
    }

    #[tokio::test]
    async fn this_machines_id_with_other_bytes_is_not_trusted_as_its_own_but_warned_of() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        show_with(&api, &mut Memory::default(), &path, TAG)
            .await
            .expect("shown");
        let own_id = api.keys.borrow()[0].id.clone();
        // The account lists another machine's bytes under this machine's id.
        let other = SecretKey::derive(b"desktop")
            .expect("a key")
            .public()
            .expect("public");
        {
            let mut keys = api.keys.borrow_mut();
            keys[0].public_key = Some(public_key_text(&other));
            keys[0].fingerprint = fingerprint(&other);
        }
        let print = fingerprint(&other);
        let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
            .await
            .expect_err("refused");
        assert!(e.message.contains("not this machine's"), "{}", e.message);
        let (answer, _) = revoke_with(
            &api,
            &path,
            TAG,
            &own_id,
            &Asking {
                yes: true,
                ..at_a_terminal()
            },
            refuse,
        )
        .await
        .expect("revoked");
        // Revoking it is warned of as this machine's: what is said errs
        // toward the warning, what is trusted does not.
        assert_eq!(answer["this_machine"], true);
    }

    #[tokio::test]
    async fn two_keys_with_one_fingerprint_an_id_out_of_form_and_terminal_control_are_refused_or_escaped()
     {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        // Two rows, the same bytes.
        let api = Fake::default();
        let (_, print) = listed(&api, "laptop", ID_X, "approved");
        listed(&api, "laptop", ID_Y, "approved");
        let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
            .await
            .expect_err("refused");
        assert!(e.message.contains("more than one"), "{}", e.message);
        assert!(
            revoke_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
                .await
                .is_err()
        );
        // An id holding terminal control.
        let api = Fake::default();
        let (_, print) = listed(&api, "laptop", "5b2b3c4d\u{1b}[2K", "approved");
        let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
            .await
            .expect_err("refused");
        assert!(!e.message.contains('\u{1b}'), "{}", e.message);
        // A label holding terminal control is shown as text in both
        // questions.
        let api = Fake::default();
        listed(&api, "laptop", ID_X, "approved");
        api.keys.borrow_mut()[0].label = Some("lap\u{1b}[31mtop\u{202e}".to_owned());
        let print = api.keys.borrow()[0].fingerprint.clone();
        trust_with(&api, &path, TAG, &print, &at_a_terminal(), |q| {
            assert!(!q.contains('\u{1b}') && !q.contains('\u{202e}'), "{q}");
            Ok(false)
        })
        .await
        .expect_err("declined");
        revoke_with(&api, &path, TAG, &print, &at_a_terminal(), |q| {
            assert!(!q.contains('\u{1b}') && !q.contains('\u{202e}'), "{q}");
            Ok(false)
        })
        .await
        .expect_err("declined");
    }

    #[tokio::test]
    async fn a_revoke_the_account_does_not_confirm_leaves_the_key_trusted_and_says_so() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        for wrong in ["another id", "not revoked"] {
            let api = Fake::default();
            let (_, print) = listed(&api, "laptop", ID_X, "approved");
            trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
                .await
                .ok();
            let mut answer = registered(&api.keys.borrow()[0], 100_001);
            if wrong == "another id" {
                // Revoked, as the account would answer it, but another key.
                answer.key.id = ID_Y.to_owned();
                answer.key.status = SealKeyStatus::Revoked;
                answer.key.public_key = None;
            }
            *api.revoke_answer.borrow_mut() = Some(answer);
            let e = revoke_with(
                &api,
                &path,
                TAG,
                &print,
                &Asking {
                    yes: true,
                    ..at_a_terminal()
                },
                refuse,
            )
            .await
            .expect_err("not confirmed");
            assert!(e.message.contains("may have"), "{wrong}: {}", e.message);
            assert!(e.hint.unwrap_or_default().contains("seal list"));
            assert_eq!(trusted(&path, TAG).expect("readable").len(), 1, "{wrong}");
        }
    }

    #[tokio::test]
    async fn a_key_kept_in_1password_is_said_as_shared_on_every_run() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let made = SecretKey::derive(b"this machine").expect("a key");
        let (public_key, print) = halves(&made.to_text()).expect("halves");
        let reference = format!("op://{VAULT}/{ITEM}/erpc-worker-seal");
        let mut store = Memory::default();
        store
            .kept
            .borrow_mut()
            .insert(reference.clone(), made.to_text().to_string());
        write(
            &path,
            TAG,
            &Record {
                kept: reference,
                public_key,
                fingerprint: print,
                seal_key_id: None,
                user_id: None,
            },
        )
        .expect("recorded");
        let api = Fake::default();
        for _ in 0..2 {
            let (answer, text) = show_with(&api, &mut store, &path, TAG)
                .await
                .expect("shown");
            assert_eq!(answer["shared_vault"], VAULT);
            assert!(text.contains("note:") && text.contains(VAULT), "{text}");
        }
    }

    #[tokio::test]
    async fn a_key_the_account_lists_with_a_fingerprint_its_bytes_do_not_have_is_not_trusted() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let elsewhere = SecretKey::derive(b"desktop")
            .expect("a key")
            .public()
            .expect("public");
        let listed_print = fingerprint(&elsewhere);
        for status in ["approved", "pending"] {
            let api = Fake::default();
            let (_, print) = listed(&api, "laptop", ID_X, status);
            api.keys.borrow_mut()[0]
                .fingerprint
                .clone_from(&listed_print);
            // By the fingerprint its bytes have, and by the one listed:
            // refused either way, nobody asked, nothing recorded.
            for typed in [&print, &listed_print] {
                let e = trust_with(&api, &path, TAG, typed, &at_a_terminal(), refuse)
                    .await
                    .expect_err("refused");
                assert!(e.message.contains("differ"), "{status}: {}", e.message);
                assert!(trusted(&path, TAG).expect("readable").is_empty());
            }
            // The list shows the fingerprint of its bytes, and what the
            // account lists beside it.
            let (answer, text) = list_with(&api, None, &[]).await.expect("listed");
            assert_eq!(answer[0]["fingerprint"], print.as_str());
            assert_eq!(answer[0]["listed_fingerprint"], listed_print.as_str());
            assert!(
                text.contains(&print) && text.contains(&format!("lists it as {listed_print}")),
                "{text}"
            );
        }
    }

    #[tokio::test]
    async fn a_revoke_drops_trust_under_every_id_the_bytes_were_trusted_by() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let yes = Asking {
            yes: true,
            ..at_a_terminal()
        };
        // Trusted under one id; the account lists the bytes under another.
        for by_print in [false, true] {
            let api = Fake::default();
            let (_, print) = listed(&api, "laptop", ID_X, "approved");
            trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
                .await
                .expect("trusted");
            api.keys.borrow_mut()[0].id = ID_Y.to_owned();
            let named = if by_print {
                print.clone()
            } else {
                ID_Y.to_owned()
            };
            revoke_with(&api, &path, TAG, &named, &yes, refuse)
                .await
                .expect("revoked");
            let here = trusted(&path, TAG).expect("readable");
            assert!(here.is_empty(), "{by_print}: {here:?}");
        }
        // Listed as revoked already: dropped here too, the account not asked.
        let api = Fake::default();
        let (_, print) = listed(&api, "laptop", ID_X, "approved");
        trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
            .await
            .expect("trusted");
        {
            let mut keys = api.keys.borrow_mut();
            keys[0].status = SealKeyStatus::Revoked;
            keys[0].public_key = None;
        }
        let (answer, _) = revoke_with(&api, &path, TAG, ID_X, &yes, refuse)
            .await
            .expect("revoked already");
        assert_eq!(answer["already"], true);
        assert!(trusted(&path, TAG).expect("readable").is_empty());
    }

    #[tokio::test]
    async fn a_key_registered_by_a_run_whose_answer_was_lost_is_warned_of_as_this_machines() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        show_with(&api, &mut Memory::default(), &path, TAG)
            .await
            .expect("shown");
        // The record without the account's id, as a run whose answer was
        // lost leaves it.
        let mut record = recorded(&path, TAG).expect("readable").expect("a record");
        record.seal_key_id = None;
        write(&path, TAG, &record).expect("written");
        let id = api.keys.borrow()[0].id.clone();
        let (listed_now, text) = list_with(&api, Some(&record), &[]).await.expect("listed");
        assert_eq!(listed_now[0]["this_machine"], true, "{text}");
        // Trust stays strict: these bytes are this machine's own, never
        // trusted as another's.
        let (own, _) = trust_with(
            &api,
            &path,
            TAG,
            &record.fingerprint,
            &at_a_terminal(),
            refuse,
        )
        .await
        .expect("its own");
        assert_eq!(own["this_machine"], true);
        assert!(trusted(&path, TAG).expect("readable").is_empty());
        let (answer, _) = revoke_with(
            &api,
            &path,
            TAG,
            &id,
            &Asking {
                yes: true,
                ..at_a_terminal()
            },
            refuse,
        )
        .await
        .expect("revoked");
        assert_eq!(answer["this_machine"], true);
    }

    #[tokio::test]
    async fn a_key_trusted_here_the_account_no_longer_lists_is_shown_and_an_id_listed_twice_refused()
     {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (_, print) = listed(&api, "laptop", ID_X, "approved");
        trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
            .await
            .expect("trusted");
        api.keys.borrow_mut().clear();
        let here = trusted(&path, TAG).expect("readable");
        let (answer, text) = list_with(&api, None, &here).await.expect("listed");
        assert_eq!(answer[0]["listed"], false);
        assert_eq!(answer[0]["trusted_here"], true);
        assert!(
            text.contains(&print) && text.contains("no longer listed"),
            "{text}"
        );
        // Untrusting by an id it is not trusted under says how to.
        let e = untrust_with(&path, TAG, ID_Y).expect_err("not trusted");
        assert!(e.hint.unwrap_or_default().contains("fingerprint"));
        // One id listed twice, with other bytes: neither trusted nor revoked.
        let api = Fake::default();
        let (_, print) = listed(&api, "tablet", ID_Y, "approved");
        listed(&api, "phone", ID_Y, "approved");
        let e = trust_with(&api, &path, TAG, &print, &at_a_terminal(), refuse)
            .await
            .expect_err("refused");
        assert!(e.message.contains("more than one key"), "{}", e.message);
        let e = revoke_with(
            &api,
            &path,
            TAG,
            &print,
            &Asking {
                yes: true,
                ..at_a_terminal()
            },
            refuse,
        )
        .await
        .expect_err("refused");
        assert!(e.message.contains("more than one key"), "{}", e.message);
        assert_eq!(trusted(&path, TAG).expect("readable").len(), 1);
    }

    #[tokio::test]
    async fn a_revoke_whose_answer_is_lost_says_it_may_have_been_revoked() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (_, print) = listed(&api, "laptop", ID_X, "approved");
        *api.revoke_lost.borrow_mut() = true;
        let e = revoke_with(
            &api,
            &path,
            TAG,
            &print,
            &Asking {
                yes: true,
                ..at_a_terminal()
            },
            refuse,
        )
        .await
        .expect_err("lost");
        assert!(e.hint.unwrap_or_default().contains("may have been revoked"));
    }

    #[tokio::test]
    async fn a_key_listed_revoked_already_under_another_id_is_dropped_by_fingerprint_or_that_id() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let yes = Asking {
            yes: true,
            ..at_a_terminal()
        };
        for by_print in [true, false] {
            let api = Fake::default();
            let (_, print) = listed(&api, "laptop", ID_X, "approved");
            trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
                .await
                .expect("trusted");
            // Listed revoked, with no bytes, under another id.
            {
                let mut keys = api.keys.borrow_mut();
                keys[0].id = ID_Y.to_owned();
                keys[0].status = SealKeyStatus::Revoked;
                keys[0].public_key = None;
            }
            // The list says it is revoked and still trusted here.
            let here = trusted(&path, TAG).expect("readable");
            let (rows, text) = list_with(&api, None, &here).await.expect("listed");
            assert_eq!(rows.as_array().map(Vec::len), Some(1), "{text}");
            assert_eq!(rows[0]["trusted_here"], true, "{text}");
            assert!(text.contains("revoked, still trusted here"), "{text}");
            let named = if by_print {
                print.clone()
            } else {
                ID_Y.to_owned()
            };
            revoke_with(&api, &path, TAG, &named, &yes, refuse)
                .await
                .expect("revoked already");
            let here = trusted(&path, TAG).expect("readable");
            assert!(here.is_empty(), "{by_print}: {here:?}");
        }
        // The trusted id, listed with other bytes, revoked by that id:
        // dropped by the id alone.
        let api = Fake::default();
        let (_, print) = listed(&api, "laptop", ID_X, "approved");
        trust_with(&api, &path, TAG, &print, &at_a_terminal(), |_| Ok(true))
            .await
            .expect("trusted");
        let other = SecretKey::derive(b"desktop")
            .expect("a key")
            .public()
            .expect("public");
        {
            let mut keys = api.keys.borrow_mut();
            keys[0].public_key = Some(public_key_text(&other));
            keys[0].fingerprint = fingerprint(&other);
        }
        revoke_with(&api, &path, TAG, ID_X, &yes, refuse)
            .await
            .expect("revoked");
        assert!(trusted(&path, TAG).expect("readable").is_empty());
    }

    #[tokio::test]
    async fn a_revoke_by_an_id_holding_terminal_control_is_refused() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        let (_, print) = listed(&api, "laptop", "5b2b3c4d\u{1b}[2K", "approved");
        let e = revoke_with(
            &api,
            &path,
            TAG,
            &print,
            &Asking {
                yes: true,
                ..at_a_terminal()
            },
            refuse,
        )
        .await
        .expect_err("refused");
        assert!(!e.message.contains('\u{1b}'), "{}", e.message);
        assert_eq!(api.keys.borrow()[0].status, SealKeyStatus::Approved);
    }

    #[tokio::test]
    async fn the_list_marks_this_machines_key_by_id_bytes_or_revoked_fingerprint_but_not_other_bytes()
     {
        let dir = tempfile::tempdir().expect("a directory");
        let path = path_in(&dir);
        let api = Fake::default();
        show_with(&api, &mut Memory::default(), &path, TAG)
            .await
            .expect("shown");
        let record = recorded(&path, TAG).expect("readable").expect("a record");
        // Revoked, with no bytes and no id recorded: by its fingerprint.
        let mut no_id = record.clone();
        no_id.seal_key_id = None;
        {
            let mut keys = api.keys.borrow_mut();
            keys[0].status = SealKeyStatus::Revoked;
            keys[0].public_key = None;
        }
        let (rows, text) = list_with(&api, Some(&no_id), &[]).await.expect("listed");
        assert_eq!(rows[0]["this_machine"], true, "{text}");
        // This machine's id with another machine's bytes: not its key.
        let other = SecretKey::derive(b"desktop")
            .expect("a key")
            .public()
            .expect("public");
        {
            let mut keys = api.keys.borrow_mut();
            keys[0].status = SealKeyStatus::Approved;
            keys[0].public_key = Some(public_key_text(&other));
            keys[0].fingerprint = fingerprint(&other);
        }
        let (rows, text) = list_with(&api, Some(&record), &[]).await.expect("listed");
        assert_eq!(rows[0]["this_machine"], false, "{text}");
        assert_eq!(rows[0]["this_machines_id_other_bytes"], true, "{text}");
        assert!(text.contains("not this machine's key"), "{text}");
    }
}
