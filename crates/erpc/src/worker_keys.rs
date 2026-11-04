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
pub(crate) async fn balance(json: bool, dir: &Dir, rpc: Option<&str>) -> Outcome {
    let (_, m) = match load(dir) {
        Ok(found) => found,
        Err(e) => return e.into(),
    };
    let Some(pubkey) = m.wallet.as_ref().and_then(|w| w.pubkey.clone()) else {
        return failed(t!("worker_keys.balance.no_pubkey", app = m.name)).into();
    };
    let url = match rpc_url(&m, rpc) {
        Ok(url) => url,
        Err(e) => return e.into(),
    };
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [pubkey] });
    let answer = async {
        let response = reqwest::Client::new()
            .post(url.as_str())
            .json(&body)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        let status = response.status();
        let value: serde_json::Value = response.json().await.map_err(|e| {
            t!(
                "worker_keys.balance.not_json_rpc",
                status,
                error = e.without_url()
            )
        })?;
        value["result"]["value"]
            .as_u64()
            .ok_or_else(|| t!("worker_keys.balance.no_balance", status))
    }
    .await;
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
    let missing = m.missing();
    if json {
        crate::print_json(&json!({ "secrets": m.secrets, "missing": missing }));
        return Outcome::Done(String::new());
    }
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
