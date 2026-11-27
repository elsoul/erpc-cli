// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Where `erpc worker` keeps an app's secrets and its trading key: in
//! 1Password, in the OS keychain, or in erpc's encrypted keystore on this
//! machine, and nowhere else.
//!
//! A value goes in on `op`'s standard input, the keychain's own call or
//! the keystore's sealed file, never on a command line, and comes back
//! into a buffer that is wiped when dropped. `erpc.toml` gets only the
//! reference.
//!
//! - **1Password:** one item per value, an `API_CREDENTIAL` tagged `erpc`
//!   and `erpc/worker/<app>`. A secret's field is `credential`. The trading
//!   key's item has the layout SLV and the validator commands use: a
//!   concealed `keypair` (the 64-byte array as `solana-keygen` writes it)
//!   and a `pubkey`.
//! - **Keychain:** service `erpc-worker`, account `<app>.<NAME>`, or
//!   `<app>.wallet` for the key, holding the same text.
//! - **Keystore:** the same service and account, as an entry of the
//!   keystore ([`crate::worker::keystore`]): a file sealed under a key that
//!   only the keystore's passphrase opens. It is where a value goes on a
//!   machine with neither 1Password nor a keychain that outlasts a reboot.
//!
//! The trading key is read only past the secret gate, as a person's wallet
//! that erpc ai may not ask for: from a terminal, not from an AI tool, not
//! with a 1Password service account. That is [`read_key`], the one way
//! `[wallet].source` is read, in every store. A keystore that is unlocked
//! does not stand in for the person, and the read of a secret ([`read`])
//! does not stand in for the key's:
//!
//! - **In the keystore** each entry is sealed as a key or as a secret
//!   ([`Kind`]). One written by [`put_key`] opens through [`read_key`]
//!   alone; [`read`] is refused by the entry itself, whatever names it.
//! - **In the keychain** nothing marks an entry, so it is the name that
//!   says: an account that ends in `.wallet` is a key's, and [`read`]
//!   refuses it, under any spelling a keychain that files an entry by one
//!   name (Windows) takes for the same.
//! - **In erpc.toml** a `[secrets]` line may name neither the entry
//!   `[wallet]` names nor an account ending in `.wallet`
//!   ([`erpc_worker::manifest`]).
//!
//! What erpc cannot tell is a key that nothing marks: a 1Password item,
//! which a reference names by its id, or a keychain entry under an account
//! of another name. An erpc.toml with no `[wallet]` that names one under
//! `[secrets]` has it read as the secret it is said to be.
//!
//! A setting cannot take a key's entry either. `<app>.WALLET` is the file
//! of `<app>.wallet` wherever case is ignored, so a setting of that name,
//! in any case, is not kept in the keychain or the keystore ([`put`]), and
//! is not removed from one ([`forget`]).
//!
//! A machine's sealing key ([`put_seal_key`]) is a third kind, and is
//! marked in every store: in the keystore its entry is sealed as one; in
//! the keychain and the keystore it is filed under the service
//! `erpc-worker-seal`; in 1Password it is the field `erpc-worker-seal` of
//! an item tagged for the ERPC account. [`read`] refuses each, in any case
//! and under any spelling of the same entry, and [`read_seal_key`] reads
//! nothing else.

use erpc_auth::store::StoreKind;
use erpc_auth::store::keychain::item;
use erpc_auth::store::keystore::Kind;
use erpc_auth::store::one_password::OpRunner;
use erpc_chain_solana::identity::Keypair;
use erpc_secret::gate::{Context, Decision, Operation, Profile, evaluate};
use erpc_worker::manifest::{SEAL_SERVICE, SecretRef, is_key_account};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// The keychain service every worker secret is under.
const SERVICE: &str = "erpc-worker";

/// Where a new secret goes, as `--store` names it.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreFlag {
    /// 1Password, through the desktop app or a service account.
    #[value(name = "1password", alias = "op")]
    OnePassword,
    /// The operating system keychain.
    Keychain,
    /// erpc's keystore: an encrypted file on this machine.
    Keystore,
}

impl StoreFlag {
    /// The name `--store` takes.
    const fn name(self) -> &'static str {
        match self {
            Self::OnePassword => "1password",
            Self::Keychain => "keychain",
            Self::Keystore => "keystore",
        }
    }
}

/// Where a new secret goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Store {
    /// A 1Password vault, by id.
    OnePassword {
        /// The vault's id.
        vault: String,
    },
    /// The OS keychain.
    Keychain,
    /// erpc's keystore on this machine.
    Keystore {
        /// Whether it was not asked for: nothing else here could keep the
        /// value. Said when the keystore is first made.
        by_default: bool,
    },
}

impl Store {
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::OnePassword { vault } => format!("1Password (vault {vault})"),
            Self::Keychain => "the OS keychain".to_owned(),
            Self::Keystore { .. } => "the encrypted keystore on this machine".to_owned(),
        }
    }
}

fn is_vault_id(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// What [`choose`] decides from: what was asked for, and what this machine
/// has. Apart from the reading of them, so the decision is tested for
/// machines of every kind on one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Facts<'a> {
    /// `--store`.
    pub(crate) flag: Option<StoreFlag>,
    /// `--vault`.
    pub(crate) vault: Option<&'a str>,
    /// Whether `erpc login` keeps the session in 1Password.
    pub(crate) session_in_op: bool,
    /// The vault the session is in.
    pub(crate) session_vault: Option<&'a str>,
    /// Whether this machine's keychain keeps a value past a reboot: macOS,
    /// Windows, and Linux with a Secret Service. Asked only when the
    /// answer decides something.
    pub(crate) durable_keychain: fn() -> bool,
}

/// The store a new secret goes in.
///
/// - `--store` names it. `--store keychain` on a machine whose keychain
///   forgets at a reboot is refused, with the ways out: what was asked
///   for is not swapped for something else.
/// - Without it: 1Password when `erpc login` keeps the session there or
///   `--vault` is given; else the keychain when it lasts; else the
///   keystore, where there used to be a refusal.
///
/// A 1Password vault is `--vault`, else the one the session is in.
pub(crate) fn decide(facts: &Facts<'_>) -> Result<Store, String> {
    let flag = match facts.flag {
        Some(flag) => flag,
        None if facts.session_in_op || facts.vault.is_some() => StoreFlag::OnePassword,
        None if (facts.durable_keychain)() => StoreFlag::Keychain,
        None => return Ok(Store::Keystore { by_default: true }),
    };
    if flag != StoreFlag::OnePassword && facts.vault.is_some() {
        return Err(t!("worker_secrets.vault_without_op", store = flag.name()));
    }
    match flag {
        StoreFlag::OnePassword => {
            let vault = facts
                .vault
                .or(facts.session_vault)
                .ok_or_else(|| t!("worker_secrets.no_vault"))?;
            if !is_vault_id(vault) {
                return Err(t!("worker_secrets.not_vault_id", vault));
            }
            Ok(Store::OnePassword {
                vault: vault.to_owned(),
            })
        }
        // A key has to outlive a reboot: on Linux only a Secret Service
        // keeps it, and a headless box, WSL or an SSH login has none. Said
        // here, with the ways out, rather than by the keychain crate later.
        StoreFlag::Keychain if !(facts.durable_keychain)() => {
            Err(t!("worker_secrets.no_durable_keychain"))
        }
        StoreFlag::Keychain => Ok(Store::Keychain),
        StoreFlag::Keystore => Ok(Store::Keystore { by_default: false }),
    }
}

/// Whether this machine's keychain keeps a value past a reboot.
fn durable_keychain() -> bool {
    #[cfg(target_os = "linux")]
    {
        erpc_auth::store::keychain::secret_service_answers()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// The store a new secret goes in on this machine: [`decide`], from
/// `--store`, `--vault`, where `erpc login` keeps the session, and whether
/// the keychain here lasts.
pub(crate) fn choose(flag: Option<StoreFlag>, vault: Option<&str>) -> Result<Store, String> {
    let config = crate::account::session::config_path()
        .and_then(|p| crate::account::config::load(&p))
        .unwrap_or_default();
    decide(&Facts {
        flag,
        vault,
        session_in_op: matches!(
            config.credential_store,
            Some(StoreKind::OnePasswordDesktop | StoreKind::OnePasswordServiceAccount)
        ),
        session_vault: config.credential_vault.as_deref(),
        durable_keychain,
    })
}

/// Opens `store` before a value is typed for it: a keystore's passphrase
/// is asked for, or chosen, first, so a mistyped one does not cost the
/// value. The other stores ask for nothing here.
pub(crate) fn ready(store: &Store) -> Result<(), String> {
    match store {
        Store::Keystore { by_default } => crate::worker::keystore::open_now(if *by_default {
            crate::worker::keystore::Make::ByDefault
        } else {
            crate::worker::keystore::Make::Asked
        }),
        Store::OnePassword { .. } | Store::Keychain => Ok(()),
    }
}

/// Checks what `m` keeps in this machine's keystore before anything slow
/// or paid for: that each entry it names is here and was kept as what it
/// is named as (a key under `[wallet]`, a secret under `[secrets]`), and
/// that the keystore opens, asking for the passphrase now and not at the
/// end of a build. An app that names nothing in the keystore asks for
/// nothing.
pub(crate) fn ready_for(m: &erpc_worker::manifest::Manifest) -> Result<(), String> {
    if kept_for(m)? {
        crate::worker::keystore::open_now(crate::worker::keystore::Make::No)?;
    }
    Ok(())
}

/// The first half of [`ready_for`], for a deploy that reads neither the
/// key nor a secret (`--prepare`): that each entry `m` names in the
/// keystore is here and was kept as what it is named as. The keystore is
/// not opened, so nothing is asked and a locked keystore is no obstacle:
/// the deploy that hands the key over opens it. Whether `m` names any.
pub(crate) fn kept_for(m: &erpc_worker::manifest::Manifest) -> Result<bool, String> {
    let mut any = false;
    let named = m
        .secrets
        .values()
        .map(|reference| (reference, Kind::Secret))
        .chain(m.wallet.iter().map(|w| (&w.source, Kind::Key)));
    for (reference, kind) in named {
        if let SecretRef::Keystore { service, account } = reference {
            if !crate::worker::keystore::kept_as(service, account, kind)? {
                return Err(t!("worker_secrets.nothing_kept", reference));
            }
            any = true;
        }
    }
    Ok(any)
}

/// Runs `op`, and returns its standard output when it succeeds. A spinner
/// turns while it waits on the 1Password app.
fn op(args: &[&str], stdin: Option<&str>, doing: &str) -> Result<Zeroizing<String>, String> {
    op_in(&crate::node::common::op_runner()?, args, stdin, doing)
}

/// [`op`] through `runner`.
fn op_in(
    runner: &impl OpRunner,
    args: &[&str],
    stdin: Option<&str>,
    doing: &str,
) -> Result<Zeroizing<String>, String> {
    let spinner = crate::node::common::op_waiting(doing);
    let out = runner.run(args, stdin).map_err(|e| e.to_string());
    if let Some(spinner) = spinner {
        spinner.done();
    }
    let out = out?;
    if out.success {
        Ok(Zeroizing::new(out.stdout))
    } else {
        let no_reason = t!("worker_secrets.no_reason");
        Err(t!(
            "worker_secrets.op_failed",
            doing,
            why = crate::node::common::op_why(&out.stderr, &no_reason)
        ))
    }
}

/// Makes a 1Password item from `head` (its title, category and tags) and
/// `fields`, the JSON of its fields with the secret already in it, and
/// returns its id.
fn create_item(vault: &str, head: &Value, fields: &str, doing: &str) -> Result<String, String> {
    create_item_in(
        &crate::node::common::op_runner()?,
        vault,
        head,
        fields,
        doing,
    )
}

/// What `op item create` answers, read for its id only: the answer may
/// carry the secret, which no other copy is made of.
#[derive(serde::Deserialize)]
struct Created {
    id: Option<String>,
}

/// [`create_item`] through `runner`.
fn create_item_in(
    runner: &impl OpRunner,
    vault: &str,
    head: &Value,
    fields: &str,
    doing: &str,
) -> Result<String, String> {
    // Built around the fields rather than through a serializer, so the one
    // copy of the secret in the template is the one that is wiped.
    let mut template = Zeroizing::new(String::new());
    template.push_str(head.to_string().trim_end_matches('}'));
    template.push_str(",\"fields\":");
    template.push_str(fields);
    template.push('}');
    let created = op_in(
        runner,
        &["item", "create", "-", "--vault", vault, "--format", "json"],
        Some(&template),
        doing,
    )?;
    let created: Created =
        serde_json::from_str(&created).map_err(|_| t!("worker_secrets.answer_not_json"))?;
    created.id.ok_or_else(|| t!("worker_secrets.no_id"))
}

fn head(app: &str, what: &str) -> Value {
    json!({
        "title": format!("erpc worker {app} {what}"),
        "category": "API_CREDENTIAL",
        "tags": ["erpc", format!("erpc/worker/{app}")],
    })
}

fn reference(raw: &str) -> Result<SecretRef, String> {
    SecretRef::parse(raw).map_err(|e| t!("worker_secrets.no_reference", error = e))
}

/// Whether `store` may keep a setting of app `app` called `name`. Asked
/// before the value is, so a refusal does not cost it.
///
/// The keychain and the keystore file a setting as `<app>.<NAME>` and the
/// trading key as `<app>.wallet`. A setting called `WALLET`, in any case,
/// would be the key's entry wherever names are compared without case (the
/// default file systems of macOS and Windows, a keychain that folds case),
/// and keeping it would write over the key. 1Password files by item id.
pub(crate) fn may_keep(store: &Store, app: &str, name: &str) -> Result<(), String> {
    match store {
        Store::Keychain | Store::Keystore { .. } if is_key_account(&format!("{app}.{name}")) => {
            Err(t!("worker_secrets.name_is_wallet", name, app))
        }
        Store::OnePassword { .. } | Store::Keychain | Store::Keystore { .. } => Ok(()),
    }
}

/// Keeps `secret` as app `app`'s `name`, and returns its reference, after
/// reading it back.
pub(crate) fn put(
    store: &Store,
    app: &str,
    name: &str,
    secret: &Zeroizing<String>,
) -> Result<SecretRef, String> {
    may_keep(store, app, name)?;
    let made = match store {
        Store::OnePassword { vault } => {
            let value =
                Zeroizing::new(serde_json::to_string(secret.as_str()).map_err(|e| e.to_string())?);
            let mut fields = Zeroizing::new(String::from(
                "[{\"id\":\"credential\",\"label\":\"credential\",\"type\":\"CONCEALED\",\"value\":",
            ));
            fields.push_str(&value);
            fields.push_str("}]");
            let id = create_item(
                vault,
                &head(app, name),
                &fields,
                &t!("worker_secrets.doing.keep_secret"),
            )?;
            reference(&format!("op://{vault}/{id}/credential"))?
        }
        Store::Keychain => {
            let account = format!("{app}.{name}");
            item::write(SERVICE, &account, secret)?;
            reference(&format!("keychain:{SERVICE}/{account}"))?
        }
        Store::Keystore { by_default } => {
            let account = format!("{app}.{name}");
            crate::worker::keystore::write(SERVICE, &account, Kind::Secret, secret, *by_default)?;
            reference(&format!("keystore:{SERVICE}/{account}"))?
        }
    };
    if read(&made)?.as_str() != secret.as_str() {
        return Err(t!("worker_secrets.not_read_back", reference = made));
    }
    Ok(made)
}

/// Keeps `keypair` as app `app`'s trading key, and returns its reference,
/// after reading it back.
pub(crate) fn put_key(store: &Store, app: &str, keypair: &Keypair) -> Result<SecretRef, String> {
    let pubkey = keypair.pubkey();
    let made = match store {
        Store::OnePassword { vault } => {
            let mut fields = Zeroizing::new(String::from(
                "[{\"id\":\"keypair\",\"label\":\"keypair\",\"type\":\"CONCEALED\",\"value\":\"",
            ));
            fields.push_str(&keypair.to_json());
            fields.push_str("\"},");
            fields.push_str(
                &json!({ "id": "pubkey", "label": "pubkey", "type": "STRING", "value": pubkey })
                    .to_string(),
            );
            fields.push(']');
            let id = create_item(
                vault,
                &head(app, "wallet"),
                &fields,
                &t!("worker_secrets.doing.keep_key"),
            )?;
            reference(&format!("op://{vault}/{id}/keypair"))?
        }
        Store::Keychain => {
            let account = format!("{app}.wallet");
            if item::read(SERVICE, &account)?.is_some() {
                return Err(t!(
                    "worker_secrets.key_exists",
                    app,
                    service = SERVICE,
                    account
                ));
            }
            item::write(SERVICE, &account, &keypair.to_json())?;
            reference(&format!("keychain:{SERVICE}/{account}"))?
        }
        Store::Keystore { by_default } => {
            let account = format!("{app}.wallet");
            // A key that is there may be a funded wallet's only copy: it
            // is never written over, and said before anything is asked.
            if crate::worker::keystore::has(SERVICE, &account)? {
                return Err(t!(
                    "worker_secrets.keystore_key_exists",
                    app,
                    reference = format!("keystore:{SERVICE}/{account}"),
                    file =
                        crate::cli::ui::tidy(&crate::worker::keystore::file_of(SERVICE, &account)?)
                ));
            }
            crate::worker::keystore::write(
                SERVICE,
                &account,
                Kind::Key,
                &keypair.to_json(),
                *by_default,
            )?;
            reference(&format!("keystore:{SERVICE}/{account}"))?
        }
    };
    // Read as the key it is, and not past the gate: this is what was
    // written a moment ago, from a key this process holds already.
    let back = Keypair::parse_json(&read_as(&made, Kind::Key)?).map_err(|e| e.to_string())?;
    if back.pubkey() != pubkey {
        return Err(t!("worker_secrets.key_not_read_back", reference = made));
    }
    Ok(made)
}

/// The entry this machine's sealing key for the ERPC account `tag` stands
/// for is kept in, in the keychain and the keystore.
pub(crate) fn seal_account(tag: &str) -> String {
    format!("{tag}.seal")
}

/// The 1Password tag this machine's sealing key items carry, per account.
fn seal_tag(tag: &str) -> String {
    format!("erpc/worker/seal/{tag}")
}

/// The one item of `listed`, the JSON `op item list` answers, that carries
/// the tag `tag` itself: some `op` versions list items whose tag only
/// begins with it. None when no item does; two are refused, not chosen
/// between.
fn one_tagged(listed: &str, tag: &str) -> Result<Option<String>, String> {
    let items: Vec<Value> =
        serde_json::from_str(listed).map_err(|_| t!("worker_secrets.answer_not_json"))?;
    // An item listed with no tags cannot be told apart: refused, not
    // passed over, so a second key is never made beside one.
    if items.iter().any(|i| !i["tags"].is_array()) {
        return Err(t!("worker_secrets.seal_untagged"));
    }
    let tagged: Vec<&Value> = items
        .iter()
        .filter(|i| {
            i["tags"]
                .as_array()
                .is_some_and(|tags| tags.iter().any(|t| t.as_str() == Some(tag)))
        })
        .collect();
    // A tagged item with no id in its form is one this machine cannot
    // read: refused, so a second key is never made beside it.
    let ids: Vec<&str> = tagged.iter().filter_map(|i| i["id"].as_str()).collect();
    if ids.len() != tagged.len() {
        return Err(t!("worker_secrets.answer_not_json"));
    }
    match ids.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some((*id).to_owned())),
        _ => Err(t!("worker_secrets.seal_twice", tag)),
    }
}

/// Whether the item `got`, as `op item get` answers it, keeps the field id
/// `field`: a reference to the sealing key names that id, and what refuses
/// such a reference as a setting reads it.
fn keeps_field_id(got: &str, field: &str) -> bool {
    // Read for the fields' ids only: the answer may carry the concealed
    // value, which no other copy is made of.
    #[derive(serde::Deserialize)]
    struct Item {
        fields: Vec<Field>,
    }
    #[derive(serde::Deserialize)]
    struct Field {
        id: Option<String>,
    }
    serde_json::from_str::<Item>(got)
        .is_ok_and(|item| item.fields.iter().any(|f| f.id.as_deref() == Some(field)))
}

/// Refuses the 1Password item `id` in `vault` unless it keeps the field
/// id [`SEAL_SERVICE`] ([`keeps_field_id`]).
fn field_kept(runner: &impl OpRunner, vault: &str, id: &str) -> Result<(), String> {
    let got = op_in(
        runner,
        &["item", "get", id, "--vault", vault, "--format", "json"],
        None,
        &t!("worker_secrets.doing.check_seal"),
    )?;
    if keeps_field_id(&got, SEAL_SERVICE) {
        Ok(())
    } else {
        Err(t!(
            "worker_secrets.seal_field_moved",
            reference = format!("op://{vault}/{id}"),
            field = SEAL_SERVICE
        ))
    }
}

/// The sealing key kept for `tag` in `store`, with its reference, when one
/// is there: a key kept before this machine's record of it was written,
/// taken up again rather than made twice. In 1Password, found by the item's
/// tag for the account; two such items are refused, not chosen between.
pub(crate) fn seal_key_there(
    store: &Store,
    tag: &str,
) -> Result<Option<(SecretRef, Zeroizing<String>)>, String> {
    let account = seal_account(tag);
    let raw = match store {
        Store::OnePassword { vault } => {
            match seal_item_there(&crate::node::common::op_runner()?, vault, tag)? {
                None => return Ok(None),
                Some(raw) => raw,
            }
        }
        Store::Keychain => {
            if item::read(SEAL_SERVICE, &account)?.is_none() {
                return Ok(None);
            }
            format!("keychain:{SEAL_SERVICE}/{account}")
        }
        Store::Keystore { .. } => {
            if !crate::worker::keystore::has(SEAL_SERVICE, &account)? {
                return Ok(None);
            }
            format!("keystore:{SEAL_SERVICE}/{account}")
        }
    };
    let made = reference(&raw)?;
    let key = read_seal_key(&made)?;
    Ok(Some((made, key)))
}

/// The reference to the sealing key kept for `tag` in the 1Password vault
/// `vault`, through `runner`, when an item tagged for the account is there:
/// two such items are refused, and so is one that does not keep the field
/// id [`SEAL_SERVICE`], so one refused when it was made is not taken up
/// later either.
fn seal_item_there(
    runner: &impl OpRunner,
    vault: &str,
    tag: &str,
) -> Result<Option<String>, String> {
    let listed = op_in(
        runner,
        &[
            "item",
            "list",
            "--vault",
            vault,
            "--tags",
            &seal_tag(tag),
            "--format",
            "json",
        ],
        None,
        &t!("worker_secrets.doing.find_seal"),
    )?;
    let Some(id) = one_tagged(&listed, &seal_tag(tag))? else {
        return Ok(None);
    };
    field_kept(runner, vault, &id)?;
    Ok(Some(format!("op://{vault}/{id}/{SEAL_SERVICE}")))
}

/// Keeps `key` in a new item of the 1Password vault `vault`, through
/// `runner`, tagged for the account `tag` stands for, in the field
/// [`SEAL_SERVICE`]; refused when the item made does not keep that field
/// id. Returns the reference.
fn put_seal_item(
    runner: &impl OpRunner,
    vault: &str,
    tag: &str,
    key: &str,
) -> Result<String, String> {
    let mut fields = Zeroizing::new(format!(
        "[{{\"id\":\"{SEAL_SERVICE}\",\"label\":\"{SEAL_SERVICE}\",\"type\":\"CONCEALED\",\"value\":\""
    ));
    fields.push_str(key);
    fields.push_str("\"}]");
    let head = json!({
        "title": format!("erpc worker sealing key {tag}"),
        "category": "API_CREDENTIAL",
        "tags": ["erpc", "erpc/worker/seal", seal_tag(tag)],
    });
    let id = create_item_in(
        runner,
        vault,
        &head,
        &fields,
        &t!("worker_secrets.doing.keep_seal"),
    )?;
    // The field is named by the id erpc gave it: an item that does not keep
    // that id could be read as a setting by another.
    field_kept(runner, vault, &id)?;
    Ok(format!("op://{vault}/{id}/{SEAL_SERVICE}"))
}

/// Keeps `key`, this machine's sealing key for the ERPC account `tag`
/// stands for (its 32 bytes as unpadded base64url), in `store`, and returns
/// its reference after reading it back. In the keystore it is filed as a
/// sealing key, which opens as nothing else; in 1Password, in the field
/// [`SEAL_SERVICE`] of an item tagged for the account. Nothing kept there
/// already is written over: [`seal_key_there`] is asked first.
pub(crate) fn put_seal_key(store: &Store, tag: &str, key: &str) -> Result<SecretRef, String> {
    let account = seal_account(tag);
    let made = match store {
        Store::OnePassword { vault } => reference(&put_seal_item(
            &crate::node::common::op_runner()?,
            vault,
            tag,
            key,
        )?)?,
        Store::Keychain => {
            if item::read(SEAL_SERVICE, &account)?.is_some() {
                return Err(t!(
                    "worker_secrets.seal_exists",
                    reference = format!("keychain:{SEAL_SERVICE}/{account}")
                ));
            }
            item::write(SEAL_SERVICE, &account, key)?;
            reference(&format!("keychain:{SEAL_SERVICE}/{account}"))?
        }
        Store::Keystore { by_default } => {
            if crate::worker::keystore::has(SEAL_SERVICE, &account)? {
                return Err(t!(
                    "worker_secrets.seal_exists",
                    reference = format!("keystore:{SEAL_SERVICE}/{account}")
                ));
            }
            crate::worker::keystore::write(SEAL_SERVICE, &account, Kind::Seal, key, *by_default)?;
            reference(&format!("keystore:{SEAL_SERVICE}/{account}"))?
        }
    };
    if *read_seal_key(&made)? != *key {
        return Err(t!("worker_secrets.seal_not_read_back", reference = made));
    }
    Ok(made)
}

/// This machine's sealing key, as kept at `reference`, which must be a
/// place a sealing key is kept ([`SecretRef::is_seal_entry`]): no other
/// reference is read as one. In the keystore it is read as a sealing key,
/// so an entry of another kind is not taken for one.
pub(crate) fn read_seal_key(reference: &SecretRef) -> Result<Zeroizing<String>, String> {
    if !reference.is_seal_entry() {
        return Err(t!("worker_secrets.not_a_seal_place", reference));
    }
    read_as(reference, Kind::Seal)
}

/// The secret a reference points at: a `[secrets]` setting, or a URL
/// `bench` was given by reference. Never a trading key: an entry filed as
/// one (an account ending in `.wallet`) is refused by its name, and a
/// keystore entry written as one by what is sealed in it. A key is read
/// by [`read_key`].
pub(crate) fn read(reference: &SecretRef) -> Result<Zeroizing<String>, String> {
    if reference.is_key_entry() {
        return Err(t!("worker_secrets.key_not_a_setting", reference));
    }
    // A machine's sealing key: filed under its own service, or, in
    // 1Password, the item this machine recorded it in.
    if reference.is_seal_entry() || crate::worker::seal_keys::holds_a_seal_key(reference) {
        return Err(t!("worker_secrets.seal_not_a_setting", reference));
    }
    read_as(reference, Kind::Secret)
}

/// The value a reference points at, read as a `kind`. The keystore holds
/// the kind of each entry and opens it as no other; 1Password and the
/// keychain do not know one.
fn read_as(reference: &SecretRef, kind: Kind) -> Result<Zeroizing<String>, String> {
    match reference {
        SecretRef::OnePassword(r) => op(
            &["read", "--no-newline", &r.to_string()],
            None,
            &t!("worker_secrets.doing.read", reference = r),
        ),
        SecretRef::Keychain { service, account } => item::read(service, account)?
            .ok_or_else(|| t!("worker_secrets.nothing_kept", reference)),
        SecretRef::Keystore { service, account } => {
            crate::worker::keystore::read(service, account, kind)?
                .ok_or_else(|| t!("worker_secrets.nothing_kept", reference))
        }
    }
}

/// What became of a value whose reference left erpc.toml.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fate {
    /// It stays where it is kept: erpc deletes nothing from 1Password or
    /// the keychain.
    Kept,
    /// Its keystore entry was removed.
    Deleted,
    /// This machine's keystore had no such entry.
    Absent,
    /// It stays in the keystore: this setting of the app names it too.
    Shared(String),
    /// It stays in the keystore: it is a trading key's entry.
    Key,
    /// It stays where it is: it is a machine's sealing key.
    Seal,
    /// Its keystore entry could not be removed, for this reason.
    NotDeleted(String),
}

/// Removes the value `reference` names once `m`'s `[secrets]` no longer
/// has `name`, when it is a keystore entry nothing else in `m` names. A
/// trading key's entry is never removed by erpc, whatever names it: the
/// wallet's own, and any entry filed as one, `<app>.wallet` in any case
/// (`<app>.WALLET` is the same file where case is ignored).
pub(crate) fn forget(
    m: &erpc_worker::manifest::Manifest,
    name: &str,
    reference: &SecretRef,
) -> Fate {
    let SecretRef::Keystore { service, account } = reference else {
        return Fate::Kept;
    };
    if m.wallet.as_ref().is_some_and(|w| w.source == *reference) {
        return Fate::Shared("wallet.source".to_owned());
    }
    if is_key_account(account) {
        return Fate::Key;
    }
    if reference.is_seal_entry() {
        return Fate::Seal;
    }
    if let Some((other, _)) = m
        .secrets
        .iter()
        .find(|(other, r)| other.as_str() != name && *r == reference)
    {
        return Fate::Shared(format!("secrets.{other}"));
    }
    match crate::worker::keystore::remove(service, account) {
        Ok(true) => Fate::Deleted,
        Ok(false) => Fate::Absent,
        Err(e) => Fate::NotDeleted(e),
    }
}

/// Where this process runs, as the secret gate reads it.
pub(crate) fn context() -> Context {
    Context::from_env(
        crate::account::session::has_terminal(),
        false,
        std::env::vars(),
    )
}

/// Whether the secret gate lets a process in `context` read a trading key:
/// a person's wallet that erpc ai may not ask for. Where the key is kept
/// is no part of the question.
pub(crate) fn gate(context: Context) -> Result<(), String> {
    match evaluate(
        Profile::HumanWallet { allow_ai: false },
        Operation::Resolve,
        &context,
    ) {
        Decision::Allow(_) => Ok(()),
        Decision::Deny(why) => Err(t!("worker_secrets.gate_denied", why)),
    }
}

/// Whether the secret gate lets this process read a trading key. Asked
/// before anything slow, so a refusal does not come at the end of a build.
pub(crate) fn may_read_key() -> Result<(), String> {
    gate(context())
}

/// The trading key a reference points at, checked against `pubkey` when
/// erpc.toml states one. Asks the secret gate first.
pub(crate) fn read_key(reference: &SecretRef, pubkey: Option<&str>) -> Result<Keypair, String> {
    read_key_in(context(), reference, pubkey)
}

/// [`read_key`], for a process in `context`. The gate is asked before the
/// store is: a keystore that is unlocked hands the key to nobody the gate
/// refuses. In the keystore the entry is read as a key, so one written as
/// a secret is not taken for one.
fn read_key_in(
    context: Context,
    reference: &SecretRef,
    pubkey: Option<&str>,
) -> Result<Keypair, String> {
    gate(context)?;
    let keypair =
        Keypair::parse_json(&read_as(reference, Kind::Key)?).map_err(|e| e.to_string())?;
    if let Some(expected) = pubkey
        && keypair.pubkey() != expected
    {
        return Err(t!(
            "worker_secrets.key_mismatch",
            reference,
            pubkey = keypair.pubkey(),
            expected
        ));
    }
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use erpc_auth::store::keystore::Kind;
    use erpc_chain_solana::identity::Keypair;
    use erpc_secret::gate::Context;
    use erpc_worker::manifest::{Manifest, SecretRef};
    use zeroize::Zeroizing;

    use super::{Facts, Fate, Store, StoreFlag, decide, is_vault_id};
    use crate::worker::keystore::fake::{FakeDesk, PASSPHRASE, set_up};

    const VAULT: &str = "abcdefghijklmnopqrstuvwxyz";
    const OTHER_VAULT: &str = "zyxwvutsrqponmlkjihgfedcba";
    const ITEM: &str = concat!("abcdefghijklm", "nopqrstuvwxy0");

    #[test]
    fn a_vault_is_named_by_its_id() {
        // In two halves: the hygiene gate reads a 26-character lowercase
        // token beside the word vault as a real identifier.
        assert!(is_vault_id(concat!("abcdefghijklm", "nopqrstuvwxyz")));
        assert!(!is_vault_id("Private"));
        assert!(!is_vault_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }

    /// A machine with no 1Password session; its keychain lasts or not.
    fn machine(durable: bool) -> Facts<'static> {
        Facts {
            flag: None,
            vault: None,
            session_in_op: false,
            session_vault: None,
            durable_keychain: if durable { || true } else { || false },
        }
    }

    #[test]
    fn without_1password_or_a_lasting_keychain_the_keystore_is_chosen() {
        // Linux with no Secret Service: a server, WSL, an SSH login. What
        // used to be a refusal.
        assert_eq!(
            decide(&machine(false)),
            Ok(Store::Keystore { by_default: true })
        );
        // The keychain, where it lasts: macOS, Windows, a Linux desktop.
        assert_eq!(decide(&machine(true)), Ok(Store::Keychain));
        // 1Password, when the session is kept there, whatever the keychain.
        for durable in [false, true] {
            let facts = Facts {
                session_in_op: true,
                session_vault: Some(VAULT),
                ..machine(durable)
            };
            assert_eq!(
                decide(&facts),
                Ok(Store::OnePassword {
                    vault: VAULT.to_owned()
                })
            );
            // And when `--vault` is given without it.
            let facts = Facts {
                vault: Some(OTHER_VAULT),
                ..machine(durable)
            };
            assert_eq!(
                decide(&facts),
                Ok(Store::OnePassword {
                    vault: OTHER_VAULT.to_owned()
                })
            );
        }
    }

    #[test]
    fn store_names_the_store_on_any_machine() {
        for durable in [false, true] {
            for session_in_op in [false, true] {
                let facts = Facts {
                    session_in_op,
                    session_vault: session_in_op.then_some(VAULT),
                    ..machine(durable)
                };
                // Asked for by name, it is not the fallback.
                assert_eq!(
                    decide(&Facts {
                        flag: Some(StoreFlag::Keystore),
                        ..facts
                    }),
                    Ok(Store::Keystore { by_default: false })
                );
                assert_eq!(
                    decide(&Facts {
                        flag: Some(StoreFlag::OnePassword),
                        vault: Some(OTHER_VAULT),
                        ..facts
                    }),
                    Ok(Store::OnePassword {
                        vault: OTHER_VAULT.to_owned()
                    })
                );
                let keychain = decide(&Facts {
                    flag: Some(StoreFlag::Keychain),
                    ..facts
                });
                if durable {
                    assert_eq!(keychain, Ok(Store::Keychain));
                } else {
                    // Asked for and unable to keep it: refused with the
                    // ways out, not swapped for the keystore unasked.
                    let e = keychain.expect_err("refused");
                    assert!(e.contains("cannot keep this past a reboot"), "{e}");
                    assert!(e.contains("--store keystore"), "{e}");
                    assert!(e.contains("1Password"), "{e}");
                }
            }
        }
    }

    #[test]
    fn a_vault_goes_with_1password_only() {
        for flag in [StoreFlag::Keychain, StoreFlag::Keystore] {
            let e = decide(&Facts {
                flag: Some(flag),
                vault: Some(VAULT),
                ..machine(true)
            })
            .expect_err("refused");
            assert!(e.contains("--vault is for 1Password"), "{e}");
            assert!(e.ends_with(flag.name()), "{e}");
        }
        // 1Password asked for, and no vault to be had; a vault by name.
        let e = decide(&Facts {
            flag: Some(StoreFlag::OnePassword),
            ..machine(true)
        })
        .expect_err("refused");
        assert!(e.contains("--vault <vault-id>"), "{e}");
        let e = decide(&Facts {
            vault: Some("Private"),
            ..machine(false)
        })
        .expect_err("refused");
        assert!(e.contains("is not a vault id"), "{e}");
    }

    #[test]
    fn whether_the_keychain_lasts_is_asked_only_when_it_decides() {
        // Asking opens a D-Bus session on Linux: not for a store that was
        // named, nor when 1Password is where the value goes.
        let never: fn() -> bool = || panic!("asked");
        for facts in [
            Facts {
                flag: Some(StoreFlag::Keystore),
                ..machine(true)
            },
            Facts {
                flag: Some(StoreFlag::OnePassword),
                vault: Some(VAULT),
                ..machine(true)
            },
            Facts {
                session_in_op: true,
                session_vault: Some(VAULT),
                ..machine(true)
            },
        ] {
            assert!(
                decide(&Facts {
                    durable_keychain: never,
                    ..facts
                })
                .is_ok()
            );
        }
    }

    fn manifest(text: &str) -> Manifest {
        Manifest::parse(text).expect("a manifest")
    }

    /// A person at a terminal, as the secret gate reads it.
    fn at_a_desk() -> Context {
        Context {
            has_tty: true,
            ..Context::empty()
        }
    }

    #[test]
    fn a_secret_kept_in_the_keystore_reads_back_through_its_reference() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (home, _store) = set_up(&desk);
        let store = Store::Keystore { by_default: true };
        let secret = Zeroizing::new("tok-7f3a9c1e5b2d-plain".to_owned());
        let made = super::put(&store, "bot", "API_TOKEN", &secret).expect("kept");
        assert_eq!(made.to_string(), "keystore:erpc-worker/bot.API_TOKEN");
        assert_eq!(super::read(&made).expect("reads").as_str(), secret.as_str());
        // A new value under the same name takes the old one's place.
        let newer = Zeroizing::new("tok-newer".to_owned());
        assert_eq!(
            super::put(&store, "bot", "API_TOKEN", &newer).expect("kept"),
            made
        );
        assert_eq!(super::read(&made).expect("reads").as_str(), "tok-newer");
        // Nothing under the erpc home holds either value in the clear.
        let mut seen = 0;
        let mut dirs = vec![home.path().to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("list").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                seen += 1;
                let text =
                    String::from_utf8_lossy(&std::fs::read(&path).expect("read")).into_owned();
                assert!(!text.contains("tok-"), "{} holds the value", path.display());
            }
        }
        assert!(seen >= 2, "master.json and the entry");
        // A reference to what is not there says so, and asks nothing.
        let asked = desk.asked();
        let missing = SecretRef::parse("keystore:erpc-worker/bot.OTHER").expect("ref");
        let e = super::read(&missing).expect_err("nothing there");
        assert_eq!(
            e,
            "nothing is kept under keystore:erpc-worker/bot.OTHER on this machine"
        );
        assert_eq!(desk.asked(), asked);
    }

    #[test]
    fn a_trading_key_kept_in_the_keystore_is_never_written_over() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (home, _store) = set_up(&desk);
        let store = Store::Keystore { by_default: false };
        let first = Keypair::generate().expect("random");
        let made = super::put_key(&store, "bot", &first).expect("kept");
        assert_eq!(made.to_string(), "keystore:erpc-worker/bot.wallet");
        // The key's own text is nowhere under the erpc home.
        let file = home
            .path()
            .join("keystore/entries/erpc-worker/bot.wallet.json");
        let on_disk = std::fs::read_to_string(&file).expect("the entry");
        assert!(!on_disk.contains(first.to_json().as_str()));
        assert!(!on_disk.contains(&first.pubkey()));
        // A second key for the same app is refused, locked or not, and the
        // first is still what the reference reads.
        for locked in [false, true] {
            if locked {
                desk.lock();
            }
            let asked = desk.asked();
            let second = Keypair::generate().expect("random");
            let e = super::put_key(&store, "bot", &second).expect_err("refused");
            assert!(
                e.contains("the keystore already holds a key for bot"),
                "{e}"
            );
            assert!(e.contains("bot.wallet.json"), "{e}");
            assert!(e.contains("nothing was replaced"), "{e}");
            assert_eq!(desk.asked(), asked, "refused before anything was asked");
        }
        desk.will_type(&[PASSPHRASE]);
        let back = super::read_key_in(at_a_desk(), &made, None).expect("reads");
        assert_eq!(back.pubkey(), first.pubkey());
    }

    #[test]
    fn an_unlocked_keystore_does_not_stand_in_for_the_person() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _kept = set_up(&desk);
        let key = Keypair::generate().expect("random");
        let store = Store::Keystore { by_default: true };
        let made = super::put_key(&store, "bot", &key).expect("kept");
        let secret = Zeroizing::new("tok-1".to_owned());
        let token = super::put(&store, "bot", "API_TOKEN", &secret).expect("kept");
        assert!(desk.is_unlocked());
        let at_a_desk = at_a_desk();
        // The key is read by a person at a terminal, as before.
        let back = super::read_key_in(at_a_desk, &made, Some(&key.pubkey())).expect("read");
        assert_eq!(back.pubkey(), key.pubkey());
        // And by nobody else, unlocked or not: no terminal, an AI tool, the
        // AI console, a service account.
        for (context, why) in [
            (Context::empty(), "no terminal is attached"),
            (
                Context {
                    ai_tool_path: true,
                    ..at_a_desk
                },
                "not marked for AI use",
            ),
            (
                Context {
                    ai_console: true,
                    ..at_a_desk
                },
                "an AI path may not resolve this key",
            ),
            (
                Context {
                    service_account: true,
                    ..at_a_desk
                },
                "a service account may not reach this key",
            ),
        ] {
            let e = super::read_key_in(context, &made, Some(&key.pubkey())).expect_err("refused");
            assert!(
                e.starts_with("erpc will not read the trading key here"),
                "{e}"
            );
            assert!(e.contains(why), "{e}");
        }
        // A secret is not the key: unlocked, it is read with no terminal.
        desk.terminal.set(false);
        assert_eq!(super::read(&token).expect("reads").as_str(), "tok-1");
        // The read of a secret does not reach the key that way: it has no
        // gate, so it is refused the key's entry by its name.
        let e = super::read(&made).expect_err("refused");
        assert_eq!(
            e,
            "keystore:erpc-worker/bot.wallet is an entry filed as a trading key: erpc reads it \
             only as the key [wallet] names, for a person at a terminal, and never as a setting \
             or a URL"
        );
        // The key read is still checked against erpc.toml's.
        let e = super::read_key_in(
            at_a_desk,
            &made,
            Some("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"),
        )
        .expect_err("mismatch");
        assert!(e.contains("wallet.pubkey is 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"));
    }

    /// The name is one guard and the seal is the other: a key's entry
    /// under a name of its owner's choosing is still a key's, and a secret
    /// is not taken for one.
    #[test]
    fn a_keystore_entry_is_read_only_as_the_kind_it_was_kept_as() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _kept = set_up(&desk);
        let store = Store::Keystore { by_default: true };
        let key = Keypair::generate().expect("random");
        // A key kept as one, by hand, under an account that does not say
        // so; and a secret.
        crate::worker::keystore::write("erpc-worker", "bot.hand", Kind::Key, &key.to_json(), true)
            .expect("kept");
        let hand = SecretRef::parse("keystore:erpc-worker/bot.hand").expect("ref");
        let secret = Zeroizing::new(key.to_json().as_str().to_owned());
        let token = super::put(&store, "bot", "API_TOKEN", &secret).expect("kept");
        assert!(desk.is_unlocked());
        // As a `[secrets]` line would have it read, unlocked and with
        // nobody at a terminal: refused by what is sealed in the entry.
        desk.terminal.set(false);
        let e = super::read(&hand).expect_err("refused");
        assert!(
            e.starts_with("erpc-worker/bot.hand is kept as a trading key"),
            "{e}"
        );
        // As `[wallet]` has it read: past the gate, and then it opens.
        let e = super::read_key_in(Context::empty(), &hand, None).expect_err("refused");
        assert!(e.contains("no terminal is attached"), "{e}");
        let back = super::read_key_in(at_a_desk(), &hand, Some(&key.pubkey())).expect("read");
        assert_eq!(back.pubkey(), key.pubkey());
        // A secret is never read as a key, though it holds one's text.
        let e = super::read_key_in(at_a_desk(), &token, None).expect_err("refused");
        assert!(
            e.starts_with("erpc-worker/bot.API_TOKEN is kept as a secret"),
            "{e}"
        );
        assert_eq!(
            super::read(&token).expect("reads").as_str(),
            secret.as_str()
        );
    }

    /// Runs on every system. Where file names ignore case (the defaults
    /// of macOS and Windows) `bot.WALLET.json` is the key's own file, and
    /// a write under that name would replace the key, a removal delete it.
    #[test]
    fn a_setting_called_wallet_neither_replaces_nor_removes_the_trading_key() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        let store = Store::Keystore { by_default: true };
        let key = Keypair::generate().expect("random");
        let made = super::put_key(&store, "bot", &key).expect("kept");
        let file = keystore
            .entry_path("erpc-worker", "bot.wallet")
            .expect("named");
        let sealed = std::fs::read(&file).expect("the key's entry");
        let entries = || {
            let dir = file.parent().expect("a directory");
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .expect("list")
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        // The key's file is as it was written, alone, and opens with the
        // key that was kept.
        let still_the_key = || {
            assert_eq!(std::fs::read(&file).expect("the key's entry"), sealed);
            assert_eq!(entries(), ["bot.wallet.json"]);
            let back = super::read_key_in(at_a_desk(), &made, Some(&key.pubkey())).expect("read");
            assert_eq!(back.to_json().as_str(), key.to_json().as_str());
        };
        still_the_key();
        let value = Zeroizing::new("tok-1".to_owned());
        let alone = manifest("name = \"bot\"\nchain = \"solana\"\n");
        let asked = desk.asked();
        for name in ["WALLET", "Wallet", "wallet"] {
            // Kept in neither store that files by name.
            for store in [
                Store::Keystore { by_default: true },
                Store::Keystore { by_default: false },
                Store::Keychain,
            ] {
                let e = super::put(&store, "bot", name, &value).expect_err("refused");
                assert!(
                    e.starts_with(&format!(
                        "a setting called {name} is not kept in the keychain or the keystore: \
                         its entry, bot.{name}, is the trading key's (bot.wallet)"
                    )),
                    "{e}"
                );
                assert_eq!(super::may_keep(&store, "bot", name), Err(e));
            }
            still_the_key();
            // And not removed from the keystore.
            let reference =
                SecretRef::parse(&format!("keystore:erpc-worker/bot.{name}")).expect("ref");
            assert_eq!(super::forget(&alone, name, &reference), Fate::Key);
            still_the_key();
        }
        // The keystore refuses the other spelling on its own account,
        // whoever asks.
        for kind in [Kind::Secret, Kind::Key] {
            let e =
                crate::worker::keystore::write("erpc-worker", "bot.WALLET", kind, "tok-1", true)
                    .expect_err("refused");
            assert!(
                e.starts_with("erpc-worker/bot.WALLET cannot be told apart from"),
                "{e}"
            );
        }
        let e = crate::worker::keystore::remove("erpc-worker", "bot.WALLET").expect_err("refused");
        assert!(e.contains("Nothing was read, written or removed"), "{e}");
        still_the_key();
        assert_eq!(desk.asked(), asked, "nothing was asked for");
        // 1Password files an item by its id, so the name is free there;
        // and a name that only has the word in it is a setting as any.
        let op = Store::OnePassword {
            vault: VAULT.to_owned(),
        };
        assert_eq!(super::may_keep(&op, "bot", "WALLET"), Ok(()));
        let label = super::put(&store, "bot", "WALLET_LABEL", &value).expect("kept");
        assert_eq!(label.to_string(), "keystore:erpc-worker/bot.WALLET_LABEL");
        assert_eq!(super::forget(&alone, "WALLET_LABEL", &label), Fate::Deleted);
        still_the_key();
    }

    #[test]
    fn what_an_app_keeps_in_the_keystore_is_checked_before_anything_slow() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _kept = set_up(&desk);
        let store = Store::Keystore { by_default: true };
        let secret = Zeroizing::new("tok-1".to_owned());
        super::put(&store, "bot", "API_TOKEN", &secret).expect("kept");
        let app = "name = \"bot\"\nchain = \"solana\"\n[secrets]\n\
                   API_TOKEN = \"keystore:erpc-worker/bot.API_TOKEN\"\n";
        let asked = desk.asked();
        // Unlocked and all there: nothing asked.
        super::ready_for(&manifest(app)).expect("ready");
        assert_eq!(desk.asked(), asked);
        // Locked: the passphrase is asked for now.
        desk.lock();
        desk.will_type(&[PASSPHRASE]);
        super::ready_for(&manifest(app)).expect("ready");
        assert_eq!(desk.asked(), asked + 1);
        // Locked with nobody at a terminal: refused now, naming the way out.
        desk.lock();
        desk.terminal.set(false);
        let e = super::ready_for(&manifest(app)).expect_err("locked");
        assert!(e.contains("`erpc worker secret unlock`"), "{e}");
        // A deploy that reads no key and no secret (--prepare) looks for
        // the entries and does not open the keystore: locked, with nobody
        // at a terminal, it goes on, and nothing is asked.
        let before = desk.asked();
        assert_eq!(super::kept_for(&manifest(app)), Ok(true));
        assert_eq!(desk.asked(), before);
        // An entry this machine does not have, as on a second machine:
        // said by its reference, before a passphrase is asked for.
        desk.terminal.set(true);
        let elsewhere = format!(
            "{app}[wallet]\nsource = \"keystore:erpc-worker/bot.wallet\"\n\
             pubkey = \"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"\n"
        );
        let asked = desk.asked();
        let e = super::ready_for(&manifest(&elsewhere)).expect_err("not here");
        assert_eq!(
            e,
            "nothing is kept under keystore:erpc-worker/bot.wallet on this machine"
        );
        assert_eq!(desk.asked(), asked);
        // An entry kept as the other kind than it is named as: a secret
        // under [wallet], a key under [secrets]. Said now, locked or not,
        // and not when the key is read, after the server is bought.
        desk.will_type(&[PASSPHRASE]);
        crate::worker::keystore::write("erpc-worker", "bot.hand", Kind::Key, "the key", true)
            .expect("kept");
        desk.lock();
        let asked = desk.asked();
        let head = "name = \"bot\"\nchain = \"solana\"\n";
        for (rest, said) in [
            (
                "[wallet]\nsource = \"keystore:erpc-worker/bot.API_TOKEN\"\n",
                "erpc-worker/bot.API_TOKEN is kept as a secret, and is read as nothing else",
            ),
            (
                "[secrets]\nHAND = \"keystore:erpc-worker/bot.hand\"\n",
                "erpc-worker/bot.hand is kept as a trading key",
            ),
        ] {
            let e = super::ready_for(&manifest(&format!("{head}{rest}"))).expect_err("refused");
            assert!(e.starts_with(said), "{e}");
        }
        assert_eq!(desk.asked(), asked);
        // The same key under [wallet] is what it is named as.
        desk.will_type(&[PASSPHRASE]);
        let hand = format!("{head}[wallet]\nsource = \"keystore:erpc-worker/bot.hand\"\n");
        super::ready_for(&manifest(&hand)).expect("ready");
        assert_eq!(desk.asked(), asked + 1);
        // An app that keeps nothing in the keystore reaches no keystore.
        let desk = FakeDesk::nobody();
        let (_home, store) = set_up(&desk);
        let plain = format!(
            "name = \"bot\"\nchain = \"solana\"\n[secrets]\n\
             API_TOKEN = \"op://{VAULT}/{OTHER_VAULT}/credential\"\n\
             X_TOKEN = \"keychain:erpc-worker/bot.X_TOKEN\"\n"
        );
        super::ready_for(&manifest(&plain)).expect("nothing to check");
        assert!(!store.dir().exists());
    }

    #[test]
    fn a_removed_secret_leaves_the_keystore_unless_something_else_names_it() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, keystore) = set_up(&desk);
        let store = Store::Keystore { by_default: true };
        let secret = Zeroizing::new("tok-1".to_owned());
        let made = super::put(&store, "bot", "API_TOKEN", &secret).expect("kept");
        let file = keystore
            .entry_path("erpc-worker", "bot.API_TOKEN")
            .expect("named");
        let head = "name = \"bot\"\nchain = \"solana\"\n";
        // Another setting names the same entry: it stays.
        let shared = manifest(&format!(
            "{head}[secrets]\nOTHER = \"keystore:erpc-worker/bot.API_TOKEN\"\n"
        ));
        assert_eq!(
            super::forget(&shared, "API_TOKEN", &made),
            Fate::Shared("secrets.OTHER".to_owned())
        );
        assert!(file.is_file());
        // The wallet names it: it stays.
        let wallet = manifest(&format!(
            "{head}[wallet]\nsource = \"keystore:erpc-worker/bot.API_TOKEN\"\n"
        ));
        assert_eq!(
            super::forget(&wallet, "API_TOKEN", &made),
            Fate::Shared("wallet.source".to_owned())
        );
        assert!(file.is_file());
        // A trading key's entry, kept while the keystore is still unlocked.
        let key = super::put_key(&store, "bot", &Keypair::generate().expect("random"));
        let key = key.expect("kept");
        // Nothing else does: the file goes, locked or not, and a second
        // removal finds nothing.
        desk.lock();
        desk.terminal.set(false);
        let alone = manifest(head);
        assert_eq!(super::forget(&alone, "API_TOKEN", &made), Fate::Deleted);
        assert!(!file.exists());
        assert_eq!(super::forget(&alone, "API_TOKEN", &made), Fate::Absent);
        // A trading key's entry stays, even with no [wallet] left to name it.
        assert_eq!(super::forget(&alone, "KEY_COPY", &key), Fate::Key);
        assert!(
            keystore
                .entry_path("erpc-worker", "bot.wallet")
                .expect("named")
                .is_file()
        );
        // What is kept in 1Password or the keychain is not erpc's to delete.
        for raw in [
            format!("op://{VAULT}/{OTHER_VAULT}/credential"),
            "keychain:erpc-worker/bot.API_TOKEN".to_owned(),
        ] {
            let reference = SecretRef::parse(&raw).expect("ref");
            assert_eq!(super::forget(&alone, "API_TOKEN", &reference), Fate::Kept);
        }
    }

    #[test]
    fn a_mismatched_key_is_told_in_the_operators_language() {
        use erpc_core::i18n::Lang;
        let said = || {
            t!(
                "worker_secrets.key_mismatch",
                reference = "keychain:erpc-worker/bot.wallet",
                pubkey = "PK1",
                expected = "PK2"
            )
        };
        let english = said();
        assert!(english.contains("wallet.pubkey is PK2"), "{english}");
        for lang in [Lang::Ja, Lang::Ru] {
            let text = crate::cli::i18n::speaking(lang, said);
            assert_ne!(text, english);
            assert!(!text.contains('{'), "{text}");
        }
    }

    #[test]
    fn a_1password_listing_is_read_by_the_tag_itself() {
        let tag = "erpc/worker/seal/0123456789abcdef";
        assert_eq!(super::one_tagged("[]", tag), Ok(None));
        let one = r#"[{"id":"aaa","tags":["erpc","erpc/worker/seal/0123456789abcdef"]}]"#;
        assert_eq!(super::one_tagged(one, tag), Ok(Some("aaa".to_owned())));
        // A longer tag that begins with it is another account's.
        let longer = r#"[{"id":"bbb","tags":["erpc/worker/seal/0123456789abcdef0"]}]"#;
        assert_eq!(super::one_tagged(longer, tag), Ok(None));
        let two = r#"[{"id":"aaa","tags":["erpc/worker/seal/0123456789abcdef"]},
                      {"id":"ccc","tags":["erpc/worker/seal/0123456789abcdef"]}]"#;
        assert!(super::one_tagged(two, tag).is_err());
        assert!(super::one_tagged("not json", tag).is_err());
        // An item listed with no tags cannot be told apart: refused.
        let untagged = r#"[{"id":"ddd"}]"#;
        assert!(super::one_tagged(untagged, tag).is_err());
        // A tagged item with no id is not passed over: refused.
        let no_id = r#"[{"tags":["erpc/worker/seal/0123456789abcdef"]}]"#;
        assert!(super::one_tagged(no_id, tag).is_err());
    }

    #[test]
    fn a_1password_item_keeps_the_field_id_erpc_gave_or_is_refused() {
        let kept =
            r#"{"id":"aaa","fields":[{"id":"erpc-worker-seal","label":"erpc-worker-seal"}]}"#;
        assert!(super::keeps_field_id(kept, "erpc-worker-seal"));
        let moved = r#"{"id":"aaa","fields":[{"id":"x7f2","label":"erpc-worker-seal"}]}"#;
        assert!(!super::keeps_field_id(moved, "erpc-worker-seal"));
        assert!(!super::keeps_field_id("not json", "erpc-worker-seal"));
    }

    #[test]
    fn a_sealing_key_is_not_read_as_a_trading_key_by_its_kind_at_a_desk() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, _store) = set_up(&desk);
        let store = Store::Keystore { by_default: false };
        let key = "A".repeat(43);
        let made = super::put_seal_key(&store, "0123456789abcdef", &key).expect("kept");
        // Past the gate (a person at a terminal), the kind refuses it.
        let e = super::read_key_in(at_a_desk(), &made, None).expect_err("refused");
        assert!(e.contains("sealing key"), "{e}");
        // And a secret's removal leaves it where it is.
        let m = manifest("name = \"bot\"\nchain = \"solana\"\n");
        assert_eq!(super::forget(&m, "X", &made), Fate::Seal);
    }

    /// A 1Password vault in memory that answers `op item list`, `create`
    /// and `get` with what a test sets, and logs what it was asked.
    struct SealOp {
        listed: &'static str,
        got: &'static str,
        log: std::cell::RefCell<Vec<String>>,
    }

    impl erpc_auth::store::one_password::OpRunner for SealOp {
        fn run(
            &self,
            args: &[&str],
            _stdin: Option<&str>,
        ) -> Result<erpc_auth::store::one_password::OpOutput, erpc_auth::store::StoreError>
        {
            self.log.borrow_mut().push(args[..2].join(" "));
            let stdout = match args {
                ["item", "list", ..] => self.listed.to_owned(),
                ["item", "create", ..] => format!("{{\"id\":\"{ITEM}\"}}"),
                ["item", "get", ..] => self.got.to_owned(),
                _ => String::new(),
            };
            Ok(erpc_auth::store::one_password::OpOutput {
                success: true,
                stdout,
                stderr: String::new(),
            })
        }
    }

    const KEPT_ID: &str = r#"{"fields":[{"id":"erpc-worker-seal","label":"erpc-worker-seal"}]}"#;
    const ID_LOST: &str = r#"{"fields":[{"id":"x3fk2a","label":"erpc-worker-seal"}]}"#;

    #[test]
    fn a_sealing_key_item_that_does_not_keep_its_field_id_is_refused_when_made_and_found() {
        const TAG: &str = "0123456789abcdef";
        let listed: &'static str = Box::leak(
            format!(
                r#"[{{"id":"{ITEM}","tags":["erpc","erpc/worker/seal","{}"]}}]"#,
                super::seal_tag(TAG)
            )
            .into_boxed_str(),
        );
        // Made, and the item keeps the id: its reference.
        let op = SealOp {
            listed: "[]",
            got: KEPT_ID,
            log: std::cell::RefCell::default(),
        };
        let made = super::put_seal_item(&op, VAULT, TAG, "k").expect("kept");
        assert_eq!(made, format!("op://{VAULT}/{ITEM}/erpc-worker-seal"));
        assert_eq!(*op.log.borrow(), ["item create", "item get"]);
        // Made, and the item lost the id: refused.
        let op = SealOp {
            listed: "[]",
            got: ID_LOST,
            log: std::cell::RefCell::default(),
        };
        let e = super::put_seal_item(&op, VAULT, TAG, "k").expect_err("refused");
        assert!(e.contains("erpc-worker-seal"), "{e}");
        // Found, keeping the id: taken up.
        let op = SealOp {
            listed,
            got: KEPT_ID,
            log: std::cell::RefCell::default(),
        };
        assert_eq!(
            super::seal_item_there(&op, VAULT, TAG)
                .expect("found")
                .as_deref(),
            Some(format!("op://{VAULT}/{ITEM}/erpc-worker-seal").as_str())
        );
        // Found, not keeping it: refused, not taken up.
        let op = SealOp {
            listed,
            got: ID_LOST,
            log: std::cell::RefCell::default(),
        };
        assert!(super::seal_item_there(&op, VAULT, TAG).is_err());
        // None there: nothing asked of an item.
        let op = SealOp {
            listed: "[]",
            got: KEPT_ID,
            log: std::cell::RefCell::default(),
        };
        assert_eq!(super::seal_item_there(&op, VAULT, TAG).expect("read"), None);
        assert_eq!(*op.log.borrow(), ["item list"]);
    }
}
