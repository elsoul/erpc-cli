// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The wallet `erpc ai` pays ERPC Credit top-ups from, as the config names
//! it: the private key's 1Password reference, its address, and whether the
//! assistant may ask to use it at all. And `erpc wallet`, which makes one.
//!
//! The key is read only after the person said yes to a quote, and only if
//! the secret gate allows it for a person's wallet reached through an AI
//! tool: the wallet marked for AI use, a terminal attached, no 1Password
//! service account. It is read into memory, checked against the configured
//! address, used for one signature and dropped.
//!
//! A new wallet's key is made in memory and goes to 1Password on standard
//! input, as a node key does; it is never written to disk or a command
//! line, and the assistant only ever sees the address.

use erpc_ai::confirm::{CreditWallet, FoundWallet};
use erpc_auth::store::one_password::OpRunner;
use erpc_secret::{Context, Decision, Operation, Profile, evaluate};
use erpc_wallet::evm::{Address, EvmKey};
use serde_json::{Value, json};
use zeroize::{Zeroize as _, Zeroizing};

use crate::commands::Outcome;

/// The title of the 1Password item a new wallet is kept in.
const ITEM_TITLE: &str = "ERPC credit wallet (Base)";

fn setting(key: &str) -> Option<String> {
    let path = crate::session::config_path().ok()?;
    crate::config::get(&path, key).ok().flatten()
}

/// The wallet as the config names it now: read on every use, so a wallet
/// made during a conversation is the one its next top-up uses.
pub(crate) struct ConfigWallet;

/// The gate's answer for this wallet, here.
fn gate(allow_ai: bool, has_tty: bool) -> Result<(), String> {
    let context = Context {
        ai_tool_path: true,
        ..Context::from_env(has_tty, false, std::env::vars())
    };
    match evaluate(
        Profile::HumanWallet { allow_ai },
        Operation::Resolve,
        &context,
    ) {
        Decision::Allow(_) => Ok(()),
        Decision::Deny(why) => Err(format!(
            "erpc will not read the wallet key here: {why}{}",
            if allow_ai {
                ""
            } else {
                " (the user allows erpc ai to pay from it with `erpc config set credit_wallet_ai on`)"
            }
        )),
    }
}

impl CreditWallet for ConfigWallet {
    fn address(&self) -> Result<Address, String> {
        if setting("credit_wallet").is_none() {
            // Half set up: a new wallet is refused (`existing`), so the
            // way on is to name the key this address has.
            return Err(match setting("credit_wallet_address") {
                Some(address) => format!(
                    "the wallet {address} is set up without its key: point the config at the \
                     key's 1Password item with `erpc config set credit_wallet \
                     op://<vault>/<item>/<field>`"
                ),
                None => NO_WALLET.to_owned(),
            });
        }
        let text = setting("credit_wallet_address").ok_or(
            "the wallet's address is not set: `erpc config set credit_wallet_address 0x…`",
        )?;
        Address::parse(&text).map_err(|e| e.to_string())
    }

    fn key(&self) -> Result<EvmKey, String> {
        use std::io::IsTerminal as _;
        let reference = setting("credit_wallet").ok_or(NO_WALLET)?;
        let allow_ai = setting("credit_wallet_ai").as_deref() == Some("on");
        gate(allow_ai, std::io::stdin().is_terminal())?;
        let runner = crate::node_common::op_runner()?;
        let mut out = runner
            .run(&["read", "--no-newline", &reference], None)
            .map_err(|e| format!("1Password did not give the wallet key: {e}"))?;
        let key = if out.success {
            EvmKey::from_hex(&out.stdout).map_err(|e| e.to_string())
        } else {
            Err("1Password did not give the wallet key (is `credit_wallet` right, and 1Password unlocked?)".to_owned())
        };
        out.stdout.zeroize();
        let key = key?;
        let configured = self.address()?;
        if key.address() != configured {
            return Err(format!(
                "the key in 1Password is for {}, not the configured wallet {configured}; nothing was signed",
                key.address()
            ));
        }
        Ok(key)
    }

    fn vault(&self) -> Option<String> {
        setting("credential_vault")
    }

    fn existing(&self) -> Option<String> {
        existing()
    }

    fn find(
        &self,
    ) -> core::pin::Pin<Box<dyn Future<Output = Result<Option<FoundWallet>, String>> + '_>> {
        Box::pin(off_thread(|| find(&crate::node_common::op_runner()?)))
    }

    fn adopt<'a>(
        &'a self,
        found: &'a FoundWallet,
        allow_ai: bool,
    ) -> core::pin::Pin<Box<dyn Future<Output = Result<Address, String>> + 'a>> {
        let found = found.clone();
        Box::pin(off_thread(move || adopt(&found, allow_ai)))
    }

    fn create<'a>(
        &'a self,
        vault: &'a str,
        allow_ai: bool,
    ) -> core::pin::Pin<Box<dyn Future<Output = Result<Address, String>> + 'a>> {
        let vault = vault.to_owned();
        Box::pin(off_thread(move || create(&vault, allow_ai)))
    }
}

/// Runs 1Password work, which may wait for an unlock, off the async
/// thread, so the console keeps drawing.
async fn off_thread<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| format!("the 1Password work stopped: {e}"))?
}

/// The tag every wallet erpc makes carries, in whichever vault: how the
/// one wallet is found again, on this machine or another.
const WALLET_TAG: &str = "erpc-credit-wallet";

/// The wallet erpc made before, if there is one: the oldest item tagged
/// [`WALLET_TAG`] in any vault the person can read. Only its address is
/// read, never its key.
pub(crate) fn find<R: OpRunner>(runner: &R) -> Result<Option<FoundWallet>, String> {
    let listed = run(
        runner,
        &["item", "list", "--tags", WALLET_TAG, "--format", "json"],
        None,
        "look for an ERPC wallet",
    )?;
    let listed: Vec<Value> =
        serde_json::from_str(&listed).map_err(|_| "1Password's listing was unreadable")?;
    let mut items: Vec<&Value> = listed
        .iter()
        .filter(|i| i["id"].as_str().is_some() && i["vault"]["id"].as_str().is_some())
        .collect();
    // The first one made is the default: the one funds were most likely
    // sent to, and the one every later setup lands on again.
    items.sort_by_key(|i| i["created_at"].as_str().unwrap_or_default().to_owned());
    let Some(item) = items.first() else {
        return Ok(None);
    };
    let (id, vault) = (
        item["id"].as_str().unwrap_or_default(),
        item["vault"]["id"].as_str().unwrap_or_default(),
    );
    let plain = |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric());
    if !plain(id) || !plain(vault) {
        return Err("1Password listed a wallet item with an unusable id".to_owned());
    }
    let field = run(
        runner,
        &[
            "item",
            "get",
            id,
            "--vault",
            vault,
            "--fields",
            "label=address",
            "--format",
            "json",
        ],
        None,
        "read the wallet's address",
    )?;
    let field: Value =
        serde_json::from_str(&field).map_err(|_| "1Password's address field was unreadable")?;
    let address = Address::parse(field["value"].as_str().unwrap_or_default()).map_err(|e| {
        format!("the ERPC wallet item {id} has no usable address ({e}); fix or remove it")
    })?;
    Ok(Some(FoundWallet {
        address,
        reference: format!("op://{vault}/{id}/private_key"),
        vault: item["vault"]["name"].as_str().unwrap_or(vault).to_owned(),
        others: items.len() - 1,
    }))
}

/// Points the config at `found`, the wallet erpc made before.
pub(crate) fn adopt(found: &FoundWallet, allow_ai: bool) -> Result<Address, String> {
    if let Some(why) = existing() {
        return Err(why);
    }
    point_config(&found.reference, found.address, allow_ai)?;
    Ok(found.address)
}

fn point_config(reference: &str, address: Address, allow_ai: bool) -> Result<(), String> {
    let path = crate::session::config_path()?;
    crate::config::set(&path, "credit_wallet", reference)?;
    crate::config::set(&path, "credit_wallet_address", &address.to_string())?;
    crate::config::set(
        &path,
        "credit_wallet_ai",
        if allow_ai { "on" } else { "off" },
    )
}

const NO_WALLET: &str = "no wallet is set up for top-ups; `create_credit_wallet` (or `erpc wallet create`) makes one in 1Password";

/// Why no new wallet may be made, if one is set up. Either setting means a
/// wallet was set up, perhaps half way: its key may hold funds, so it is
/// never pointed away from.
fn existing() -> Option<String> {
    if let Some(existing) = setting("credit_wallet_address") {
        return Some(format!(
            "a wallet is set up already ({existing}); erpc does not replace one"
        ));
    }
    setting("credit_wallet").map(|_| {
        "a wallet's key is set up already (credit_wallet) but not its address; erpc does not \
         replace one. Set its address with `erpc config set credit_wallet_address 0x…`"
            .to_owned()
    })
}

/// Makes a new wallet in `vault`, stores its key there, and points the
/// config at it. Refuses when a wallet is configured already, when one erpc
/// made is in 1Password already (it is the one to use: [`adopt`]), when the
/// vault holds an item of the same title, or under a service account.
pub(crate) fn create(vault: &str, allow_ai: bool) -> Result<Address, String> {
    if let Some(why) = existing() {
        return Err(why);
    }
    if std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_some() {
        return Err(
            "a person's wallet is not made through a 1Password service account; sign in to 1Password as yourself"
                .to_owned(),
        );
    }
    // An id or a name; never one that reads as an option to `op`.
    if vault.is_empty()
        || vault.starts_with('-')
        || !vault
            .chars()
            .all(|c| c.is_alphanumeric() || " -_".contains(c))
    {
        return Err("the vault is its 1Password id or its name".to_owned());
    }
    let runner = crate::node_common::op_runner()?;
    // One wallet per person: a second would split their EURC.
    if let Some(found) = find(&runner)? {
        return Err(format!(
            "an ERPC wallet is in 1Password already ({}, vault {}); erpc sets that one up \
             rather than make another",
            found.address, found.vault
        ));
    }
    let (reference, address) = store(&runner, vault)?;
    point_config(&reference, address, allow_ai)?;
    Ok(address)
}

fn run<R: OpRunner>(
    runner: &R,
    args: &[&str],
    stdin: Option<&str>,
    what: &str,
) -> Result<String, String> {
    let out = runner
        .run(args, stdin)
        .map_err(|e| format!("1Password could not {what}: {e}"))?;
    if out.success {
        Ok(out.stdout)
    } else {
        Err(format!("1Password could not {what}"))
    }
}

/// The id of `vault`, named by its id or its name: the reference the
/// config keeps names vaults by id only, so this is settled before
/// anything is stored.
fn vault_id<R: OpRunner>(runner: &R, vault: &str) -> Result<String, String> {
    let got = run(
        runner,
        &["vault", "get", vault, "--format", "json"],
        None,
        &format!("find the vault {vault:?}"),
    )?;
    let got: Value =
        serde_json::from_str(&got).map_err(|_| "1Password's vault details were unreadable")?;
    let id = got["id"].as_str().unwrap_or_default();
    if id.len() == 26
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        Ok(id.to_owned())
    } else {
        Err(format!(
            "1Password gave no usable id for the vault {vault:?}"
        ))
    }
}

/// Makes the key, stores it in `vault` (an id or a name) as a new item,
/// and reads it back; returns the item's reference and the address.
fn store<R: OpRunner>(runner: &R, vault: &str) -> Result<(String, Address), String> {
    let vault = vault_id(runner, vault)?;
    let vault = vault.as_str();
    let listed = run(
        runner,
        &["item", "list", "--vault", vault, "--format", "json"],
        None,
        "list the vault",
    )?;
    let listed: Vec<Value> =
        serde_json::from_str(&listed).map_err(|_| "1Password's listing was unreadable")?;
    if let Some(item) = listed.iter().find(|i| i["title"] == ITEM_TITLE) {
        let id = item["id"].as_str().unwrap_or_default();
        return Err(format!(
            "the vault already has an item \"{ITEM_TITLE}\" (op://{vault}/{id}/private_key), \
             perhaps from an earlier try. To use it: `erpc config set credit_wallet \
             op://{vault}/{id}/private_key` and `erpc config set credit_wallet_address` with its \
             address field. Or remove it from 1Password first, if it holds no funds"
        ));
    }
    let key = EvmKey::generate().map_err(|e| e.to_string())?;
    let address = key.address();
    let secret = key.secret_hex();
    // Built around the secret rather than through a serializer, so the one
    // copy of the template is the one that is wiped. Hex needs no escaping.
    let mut template = Zeroizing::new(String::new());
    let head =
        json!({ "title": ITEM_TITLE, "category": "API_CREDENTIAL", "tags": ["erpc", WALLET_TAG] })
            .to_string();
    template.push_str(head.trim_end_matches('}'));
    template.push_str(",\"fields\":[{\"id\":\"private_key\",\"label\":\"private_key\",\"type\":\"CONCEALED\",\"value\":\"");
    template.push_str(&secret);
    template.push_str("\"},");
    template.push_str(
        &json!({ "id": "address", "label": "address", "type": "STRING", "value": address.to_string() })
            .to_string(),
    );
    template.push_str("]}");
    drop(secret);
    let created = run(
        runner,
        &["item", "create", "-", "--vault", vault, "--format", "json"],
        Some(&template),
        "store the wallet",
    )?;
    drop(template);
    let created: Value =
        serde_json::from_str(&created).map_err(|_| "1Password's new item was unreadable")?;
    let id = created["id"]
        .as_str()
        .ok_or("1Password's new item has no id")?;
    let reference = format!("op://{vault}/{id}/private_key");
    // Read the key back before the config points at it. The item stays
    // either way: it is named, so a failure here is not a dead end.
    let kept = format!(
        "the item stays in 1Password as {reference} (address {address}); the config was not \
         changed. Check the item, then point the config at it with `erpc config set \
         credit_wallet {reference}` and `erpc config set credit_wallet_address {address}`"
    );
    let mut back = run(
        runner,
        &["read", "--no-newline", &reference],
        None,
        "read the wallet back",
    )
    .map_err(|e| format!("{e}; {kept}"))?;
    let same = EvmKey::from_hex(&back).map(|k| k.address() == address);
    back.zeroize();
    if same != Ok(true) {
        return Err(format!(
            "the key 1Password gave back is not the one stored; {kept}"
        ));
    }
    Ok((reference, address))
}

/// `erpc wallet create`: sets up the one wallet. The configured one stays;
/// else the one erpc made before, found in 1Password, is used; only when
/// there is none is a new one made, in `vault`.
pub(crate) fn create_command(json_out: bool, vault: Option<&str>, allow_ai: bool) -> Outcome {
    let said = |address: Address, how: &str, text: String| {
        if json_out {
            crate::print_json(
                &json!({ "address": address.to_string(), "wallet": how, "ai": allow_ai }),
            );
            Outcome::Done(String::new())
        } else {
            Outcome::Done(text)
        }
    };
    let ai_line = if allow_ai {
        "may ask to pay from it; every payment still asks you"
    } else {
        "may not use it (`erpc config set credit_wallet_ai on` allows it)"
    };
    if let (Some(_), Some(address)) = (setting("credit_wallet"), setting("credit_wallet_address"))
        && let Ok(address) = Address::parse(&address)
    {
        return said(
            address,
            "configured",
            format!("The credit wallet is set up already.\n  address  {address}"),
        );
    }
    if let Some(why) = existing() {
        return Outcome::Failed(why);
    }
    let found = match crate::node_common::op_runner().and_then(|runner| find(&runner)) {
        Ok(found) => found,
        Err(e) => return Outcome::Failed(e),
    };
    if let Some(found) = found {
        return match adopt(&found, allow_ai) {
            Ok(address) => said(
                address,
                "found",
                format!(
                    "Using the ERPC wallet already in 1Password (vault {}).\n  address  {address}\n  erpc ai  {ai_line}{}",
                    found.vault,
                    if found.others > 0 {
                        format!(
                            "\n  note     {} more ERPC wallet item(s) are in 1Password; this is the first one made",
                            found.others
                        )
                    } else {
                        String::new()
                    }
                ),
            ),
            Err(e) => Outcome::Failed(e),
        };
    }
    let Some(vault) = vault
        .map(ToOwned::to_owned)
        .or_else(|| setting("credential_vault"))
    else {
        return Outcome::Usage(
            "no ERPC wallet is in 1Password yet; say which vault to make it in: --vault <id or name> (a personal one, such as Private)".to_owned(),
        );
    };
    match create(&vault, allow_ai) {
        Ok(address) => said(
            address,
            "made",
            format!(
                "A new Base wallet is in 1Password (vault {vault}, item \"{ITEM_TITLE}\").\n  address  {address}\n  erpc ai  {ai_line}\nSend EURC on Base to that address; buying credit needs no ETH (ERPC pays the gas)."
            ),
        ),
        Err(e) => Outcome::Failed(e),
    }
}

/// `erpc wallet show`.
pub(crate) fn show_command(json_out: bool) -> Outcome {
    let address = setting("credit_wallet_address");
    let ai = setting("credit_wallet_ai").as_deref() == Some("on");
    if json_out {
        crate::print_json(
            &json!({ "address": address, "ai": ai, "configured": setting("credit_wallet").is_some() }),
        );
        return Outcome::Done(String::new());
    }
    match address {
        Some(address) => Outcome::Done(format!(
            "credit wallet  {address} (Base)\nerpc ai        {}",
            if ai {
                "may ask to pay from it"
            } else {
                "may not use it"
            }
        )),
        None => Outcome::Done(
            "No credit wallet is set up: `erpc wallet create` makes one in 1Password.".to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{find, gate, store};
    use erpc_auth::store::StoreError;
    use erpc_auth::store::one_password::{OpOutput, OpRunner};
    use std::cell::RefCell;

    /// A vault in memory: lists, creates and reads one item.
    struct FakeOp {
        stored: RefCell<Option<String>>,
        seen_secret_in_args: RefCell<bool>,
    }

    impl OpRunner for FakeOp {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<OpOutput, StoreError> {
            let ok = |stdout: String| {
                Ok(OpOutput {
                    success: true,
                    stdout,
                    stderr: String::new(),
                })
            };
            if args.iter().any(|a| a.len() == 66 && a.starts_with("0x")) {
                *self.seen_secret_in_args.borrow_mut() = true;
            }
            match args {
                ["vault", "get", "Private", ..] => {
                    ok(r#"{"id":"vaultvaultvaultvaultvaultx","name":"Private"}"#.to_owned())
                }
                // The id in two halves: the hygiene gate reads a 26-character
                // lowercase token beside the word vault as a real identifier.
                ["item", "list", "--vault", v, ..]
                    if *v == concat!("vaultvaultvault", "vaultvaultx") =>
                {
                    ok("[]".to_owned())
                }
                [
                    "item",
                    "create",
                    "-",
                    "--vault",
                    "vaultvaultvaultvaultvaultx",
                    ..,
                ] => {
                    let v: serde_json::Value =
                        serde_json::from_str(stdin.unwrap_or_default()).expect("template");
                    *self.stored.borrow_mut() =
                        v["fields"][0]["value"].as_str().map(ToOwned::to_owned);
                    ok(r#"{"id":"abcdefghijklmnopqrstuvwxyz"}"#.to_owned())
                }
                ["read", "--no-newline", reference] => {
                    assert_eq!(
                        *reference,
                        "op://vaultvaultvaultvaultvaultx/abcdefghijklmnopqrstuvwxyz/private_key"
                    );
                    ok(self.stored.borrow().clone().unwrap_or_default())
                }
                _ => panic!("unexpected op call {args:?}"),
            }
        }
    }

    #[test]
    fn a_new_wallet_goes_to_1password_on_stdin_and_reads_back() {
        let op = FakeOp {
            stored: RefCell::new(None),
            seen_secret_in_args: RefCell::new(false),
        };
        let (reference, address) = store(&op, "Private").expect("stored by the vault's name");
        assert!(reference.ends_with("/private_key"));
        let key =
            erpc_wallet::evm::EvmKey::from_hex(op.stored.borrow().as_deref().unwrap_or_default())
                .expect("key");
        assert_eq!(key.address(), address);
        assert!(
            !*op.seen_secret_in_args.borrow(),
            "the key never goes on a command line"
        );
    }

    /// 1Password holding the wallet items `listed`, each with an address.
    struct Listed(&'static str);

    impl OpRunner for Listed {
        fn run(&self, args: &[&str], _: Option<&str>) -> Result<OpOutput, StoreError> {
            let stdout = match args {
                ["item", "list", "--tags", "erpc-credit-wallet", ..] => self.0.to_owned(),
                [
                    "item",
                    "get",
                    "oldoldoldoldoldoldoldoldol",
                    "--vault",
                    "vaultaaaaaaaaaaaaaaaaaaaaa",
                    "--fields",
                    "label=address",
                    ..,
                ] => r#"{"value":"0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"}"#.to_owned(),
                _ => panic!("unexpected op call {args:?}"),
            };
            Ok(OpOutput {
                success: true,
                stdout,
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn the_wallet_made_first_is_the_one_found_and_its_key_is_not_read() {
        let op = Listed(
            // The vault ids in two halves: the hygiene gate reads a
            // 26-character lowercase token beside the word vault as a real
            // identifier.
            concat!(
                r#"[{"id":"newnewnewnewnewnewnewnewne","vault":{"id":"vaultbbbbbbbbbbb"#,
                r#"bbbbbbbbbb","name":"Work"},"created_at":"2026-10-20T00:00:00Z"},"#,
                r#"{"id":"oldoldoldoldoldoldoldoldol","vault":{"id":"vaultaaaaaaaaaaa"#,
                r#"aaaaaaaaaa","name":"Private"},"created_at":"2026-09-01T00:00:00Z"}]"#
            ),
        );
        let found = find(&op).expect("searched").expect("found");
        assert_eq!(
            found.reference,
            "op://vaultaaaaaaaaaaaaaaaaaaaaa/oldoldoldoldoldoldoldoldol/private_key"
        );
        assert_eq!(found.vault, "Private");
        assert_eq!(found.others, 1);
        assert_eq!(
            found.address.to_string().to_lowercase(),
            "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"
        );
        assert!(find(&Listed("[]")).expect("searched").is_none());
    }

    #[test]
    fn the_gate_needs_the_wallet_marked_for_ai_and_a_terminal() {
        // Run without a service account in the environment, as a person does.
        if std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_some() {
            return;
        }
        assert!(gate(true, true).is_ok());
        assert!(
            gate(false, true)
                .unwrap_err()
                .contains("credit_wallet_ai on")
        );
        assert!(gate(true, false).is_err());
    }
}
