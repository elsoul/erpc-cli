// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Where `erpc worker` keeps an app's secrets and its trading key: in
//! 1Password, or in the OS keychain, and nowhere else.
//!
//! A value goes in on `op`'s standard input or the keychain's own call,
//! never on a command line, and comes back into a buffer that is wiped
//! when dropped. `erpc.toml` gets only the reference.
//!
//! - **1Password:** one item per value, an `API_CREDENTIAL` tagged `erpc`
//!   and `erpc/worker/<app>`. A secret's field is `credential`. The trading
//!   key's item has the layout SLV and the validator commands use: a
//!   concealed `keypair` (the 64-byte array as `solana-keygen` writes it)
//!   and a `pubkey`.
//! - **Keychain:** service `erpc-worker`, account `<app>.<NAME>`, or
//!   `<app>.wallet` for the key, holding the same text.
//!
//! The trading key is read only past the secret gate, as a person's wallet
//! that erpc ai may not ask for: from a terminal, not from an AI tool, not
//! with a 1Password service account.

use erpc_auth::store::StoreKind;
use erpc_auth::store::keychain::item;
use erpc_auth::store::one_password::OpRunner as _;
use erpc_chain_solana::identity::Keypair;
use erpc_secret::gate::{Context, Decision, Operation, Profile, evaluate};
use erpc_worker::manifest::SecretRef;
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
}

impl Store {
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::OnePassword { vault } => format!("1Password (vault {vault})"),
            Self::Keychain => "the OS keychain".to_owned(),
        }
    }
}

fn is_vault_id(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The store a new secret goes in: `--store`, else 1Password when
/// `erpc login` keeps the session there, else the keychain. A 1Password
/// vault is `--vault`, else the one the session is in.
pub(crate) fn choose(flag: Option<StoreFlag>, vault: Option<&str>) -> Result<Store, String> {
    let config = crate::session::config_path()
        .and_then(|p| crate::config::load(&p))
        .unwrap_or_default();
    let session_in_op = matches!(
        config.credential_store,
        Some(StoreKind::OnePasswordDesktop | StoreKind::OnePasswordServiceAccount)
    );
    let one_password = match flag {
        Some(StoreFlag::OnePassword) => true,
        Some(StoreFlag::Keychain) => false,
        None => session_in_op || vault.is_some(),
    };
    if !one_password {
        if vault.is_some() {
            return Err(t!("worker_secrets.vault_without_op"));
        }
        // A key has to outlive a reboot: on Linux only a Secret Service
        // keeps it, and a headless box, WSL or an SSH login has none. Said
        // here, with the ways out, rather than by the keychain crate later.
        #[cfg(target_os = "linux")]
        {
            if !erpc_auth::store::keychain::secret_service_answers() {
                return Err(t!("worker_secrets.no_durable_keychain"));
            }
        }
        return Ok(Store::Keychain);
    }
    let vault = vault
        .map(ToOwned::to_owned)
        .or(config.credential_vault)
        .ok_or_else(|| t!("worker_secrets.no_vault"))?;
    if !is_vault_id(&vault) {
        return Err(t!("worker_secrets.not_vault_id", vault));
    }
    Ok(Store::OnePassword { vault })
}

/// Runs `op`, and returns its standard output when it succeeds. A spinner
/// turns while it waits on the 1Password app.
fn op(args: &[&str], stdin: Option<&str>, doing: &str) -> Result<Zeroizing<String>, String> {
    let runner = crate::node_common::op_runner()?;
    let spinner = crate::node_common::op_waiting(doing);
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
            why = crate::node_common::op_why(&out.stderr, &no_reason)
        ))
    }
}

/// Makes a 1Password item from `head` (its title, category and tags) and
/// `fields`, the JSON of its fields with the secret already in it, and
/// returns its id.
fn create_item(vault: &str, head: &Value, fields: &str, doing: &str) -> Result<String, String> {
    // Built around the fields rather than through a serializer, so the one
    // copy of the secret in the template is the one that is wiped.
    let mut template = Zeroizing::new(String::new());
    template.push_str(head.to_string().trim_end_matches('}'));
    template.push_str(",\"fields\":");
    template.push_str(fields);
    template.push('}');
    let created = op(
        &["item", "create", "-", "--vault", vault, "--format", "json"],
        Some(&template),
        doing,
    )?;
    let created: Value =
        serde_json::from_str(&created).map_err(|_| t!("worker_secrets.answer_not_json"))?;
    created["id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| t!("worker_secrets.no_id"))
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

/// Keeps `secret` as app `app`'s `name`, and returns its reference, after
/// reading it back.
pub(crate) fn put(
    store: &Store,
    app: &str,
    name: &str,
    secret: &Zeroizing<String>,
) -> Result<SecretRef, String> {
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
    };
    let back = Keypair::parse_json(&read(&made)?).map_err(|e| e.to_string())?;
    if back.pubkey() != pubkey {
        return Err(t!("worker_secrets.key_not_read_back", reference = made));
    }
    Ok(made)
}

/// The value a reference points at.
pub(crate) fn read(reference: &SecretRef) -> Result<Zeroizing<String>, String> {
    match reference {
        SecretRef::OnePassword(r) => op(
            &["read", "--no-newline", &r.to_string()],
            None,
            &t!("worker_secrets.doing.read", reference = r),
        ),
        SecretRef::Keychain { service, account } => item::read(service, account)?
            .ok_or_else(|| t!("worker_secrets.nothing_kept", reference)),
    }
}

/// Whether the secret gate lets this process read a trading key: a
/// person's wallet that erpc ai may not ask for. Asked before anything
/// slow, so a refusal does not come at the end of a build.
pub(crate) fn may_read_key() -> Result<(), String> {
    let context = Context::from_env(crate::session::has_terminal(), false, std::env::vars());
    match evaluate(
        Profile::HumanWallet { allow_ai: false },
        Operation::Resolve,
        &context,
    ) {
        Decision::Allow(_) => Ok(()),
        Decision::Deny(why) => Err(t!("worker_secrets.gate_denied", why)),
    }
}

/// The trading key a reference points at, checked against `pubkey` when
/// erpc.toml states one. Asks the secret gate first.
pub(crate) fn read_key(reference: &SecretRef, pubkey: Option<&str>) -> Result<Keypair, String> {
    may_read_key()?;
    let keypair = Keypair::parse_json(&read(reference)?).map_err(|e| e.to_string())?;
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
    use super::is_vault_id;

    #[test]
    fn a_vault_is_named_by_its_id() {
        // In two halves: the hygiene gate reads a 26-character lowercase
        // token beside the word vault as a real identifier.
        assert!(is_vault_id(concat!("abcdefghijklm", "nopqrstuvwxyz")));
        assert!(!is_vault_id("Private"));
        assert!(!is_vault_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
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
            let text = crate::i18n::speaking(lang, said);
            assert_ne!(text, english);
            assert!(!text.contains('{'), "{text}");
        }
    }
}
