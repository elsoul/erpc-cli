// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The tools that change the account: starting an hourly product paid from
//! ERPC Credit, and ending one. Each asks the person first through
//! [`Confirm`], with the price and the balance as user-api gives them, and
//! sends nothing without a yes. The read that goes with them, the hourly
//! catalogue, is here too.

use erpc_api::{account, hourly};
use erpc_auth::AuthClient;
use secrecy::SecretString;
use serde_json::{Map, Value, json};

use crate::confirm::{Confirm, Confirmation};
use crate::i18n::{t, tn};
use crate::tools::{pick, read};

/// Euros from cents, as a person reads them: `€0.14`.
fn euros(cents: f64) -> String {
    format!("€{:.2}", cents / 100.0)
}

/// A product's name, by its id; `None` when user-api does not say.
async fn product_name(client: &AuthClient, token: &SecretString, id: &str) -> Option<String> {
    let product = account::read_query(client, token, account::PRODUCT_URL, &[("productId", id)])
        .await
        .ok()?;
    product
        .get("message")
        .unwrap_or(&product)
        .get("name")
        .and_then(Value::as_str)
        .map(|n| n.trim().to_owned())
}

/// The catalogue's entry for `family`.
fn catalog_family<'a>(catalog: &'a Value, family: &str) -> Option<&'a Value> {
    catalog
        .get("families")
        .and_then(Value::as_array)?
        .iter()
        .find(|f| f.get("family").and_then(Value::as_str) == Some(family))
}

fn plans(entry: &Value) -> &[Value] {
    entry
        .get("plans")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// `hourly_catalog`: what can be started hourly, with its price per hour
/// and the fields each family's start takes. With a family, its products'
/// names too.
pub(crate) async fn hourly_catalog(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
) -> Result<Value, String> {
    let catalog = read(client, token, hourly::CATALOG_URL).await?;
    let only = input.get("family").and_then(Value::as_str);
    if let Some(name) = only
        && hourly::find(name).is_none()
    {
        return Err(format!("there is no hourly family {name}"));
    }
    let mut families = Vec::new();
    for entry in catalog
        .get("families")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = entry.get("family").and_then(Value::as_str) else {
            continue;
        };
        if only.is_some_and(|o| o != name) {
            continue;
        }
        let Some(family) = hourly::find(name) else {
            // A family this version does not know how to start.
            continue;
        };
        let mut out_plans = Vec::new();
        for plan in plans(entry) {
            let mut p = pick(plan, &["productId", "tier"]);
            if let Some(cents) = plan.get("hourlyCents").and_then(Value::as_f64) {
                p["eurPerHour"] = json!(cents / 100.0);
            }
            if only.is_some()
                && let Some(id) = plan.get("productId").and_then(Value::as_str)
            {
                p["name"] = json!(product_name(client, token, id).await);
            }
            out_plans.push(p);
        }
        families.push(json!({
            "family": name,
            "requiredFields": family.required,
            "optionalFields": family.optional,
            "plans": out_plans,
        }));
    }
    Ok(json!({ "families": families }))
}

/// The balance and what is drawing on it now, from the credit snapshot.
struct Credit {
    balance_cents: f64,
    burn_cents_per_hour: f64,
    hourly: Vec<Value>,
}

async fn credit(client: &AuthClient, token: &SecretString) -> Result<Credit, String> {
    let snapshot = read(client, token, account::CREDIT_SNAPSHOT_URL).await?;
    let m = snapshot.get("message").unwrap_or(&Value::Null);
    let number = |v: Option<&Value>| v.and_then(Value::as_f64).unwrap_or(0.0);
    Ok(Credit {
        balance_cents: number(m.get("balance").and_then(|b| b.get("balanceCents"))),
        burn_cents_per_hour: number(m.get("burnRateCentsPerHour")),
        hourly: m
            .get("hourlyResources")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    })
}

/// A random idempotency key: one per confirmed start.
fn idempotency_key() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| format!("no randomness for the purchase key: {e}"))?;
    Ok(bytes.iter().fold(String::with_capacity(32), |mut out, b| {
        use core::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    }))
}

const NO_ONE_TO_ASK: &str = "this changes what the account pays for, and only the person at the \
     terminal can say yes to that; erpc ai without a terminal (-m in a script, --json) cannot. \
     Tell the user to ask in `erpc ai` at a terminal";

/// What user-api answered, for the model: whether it worked and its words,
/// without Stripe's ids.
fn outcome(reply: &hourly::Reply, done: &str) -> Value {
    let body = &reply.body;
    let mut out = pick(
        body,
        &[
            "success",
            "message",
            "code",
            "provisioningPending",
            "registerWarning",
        ],
    );
    if let Some(fields) = body.as_object() {
        for (key, value) in fields {
            if key.ends_with("Id") && !key.starts_with("stripe") && !key.contains("Subscription") {
                out[key] = value.clone();
            }
        }
    }
    out["httpStatus"] = json!(reply.status);
    out["done"] = json!(
        (200..300).contains(&reply.status)
            && body.get("success").and_then(Value::as_bool) != Some(false)
    );
    out["what"] = json!(done);
    out
}

/// `start_hourly_product`: starts one, after the person says yes.
///
/// # Errors
///
/// A message saying what user-api or the person refused, for the caller to show.
pub async fn start_hourly_product(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
    confirm: Option<&dyn Confirm>,
) -> Result<Value, String> {
    let name = input
        .get("family")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let family = hourly::find(name).ok_or_else(|| format!("there is no hourly family {name:?}"))?;
    let empty = Map::new();
    let fields = input
        .get("fields")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let body = family.start_body(fields)?;
    let confirm = confirm.ok_or(NO_ONE_TO_ASK)?;

    // The price is the catalogue's, never the model's.
    let catalog = read(client, token, hourly::CATALOG_URL).await?;
    let entry = catalog_family(&catalog, family.name)
        .ok_or_else(|| format!("{} is not offered hourly now", family.name))?;
    let product_id = fields.get("productId").and_then(Value::as_str);
    let plan = match product_id {
        Some(id) => plans(entry)
            .iter()
            .find(|p| p.get("productId").and_then(Value::as_str) == Some(id))
            .ok_or_else(|| {
                format!(
                    "{id} is not a {} product open for sale; see hourly_catalog",
                    family.name
                )
            })?,
        None => match plans(entry) {
            [only] => only,
            _ => return Err(format!("{} needs productId", family.name)),
        },
    };
    let hourly_cents = plan
        .get("hourlyCents")
        .and_then(Value::as_f64)
        .ok_or("the catalogue gives no price for it")?;
    let id = plan
        .get("productId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let product = product_name(client, token, id)
        .await
        .unwrap_or_else(|| id.to_owned());
    let credit = credit(client, token).await?;
    let burn_after = credit.burn_cents_per_hour + hourly_cents;
    let hours = if burn_after > 0.0 {
        credit.balance_cents / burn_after
    } else {
        0.0
    };

    let mut lines = vec![
        (t!("confirm.label.product"), product.clone()),
        (
            t!("confirm.label.price"),
            t!(
                "confirm.start.price",
                hourly = euros(hourly_cents),
                daily = euros(hourly_cents * 24.0)
            ),
        ),
    ];
    for (key, value) in fields {
        if key != "productId" {
            let shown = value
                .as_str()
                .map_or_else(|| value.to_string(), ToOwned::to_owned);
            lines.push((t!("confirm.label.setting"), format!("{key} = {shown}")));
        }
    }
    lines.push((t!("confirm.label.credit"), euros(credit.balance_cents)));
    lines.push((
        t!("confirm.label.lasts"),
        t!(
            "confirm.start.lasts",
            hours = format!("{hours:.0}"),
            rate = euros(burn_after)
        ),
    ));
    let ask = Confirmation {
        title: t!("confirm.start.title", product),
        lines,
    };
    if !confirm.confirm(&ask).await {
        return Err("the user said no; nothing was started".to_owned());
    }
    let key = idempotency_key()?;
    let reply = hourly::start(client, token, family, &body, &key)
        .await
        .map_err(|e| format!("the start was not sent: {e}"))?;
    let mut out = outcome(&reply, &format!("start {product}"));
    if family.name == "vps" && out["done"] == json!(true) && out.get("userVpsId").is_some() {
        out["next"] = json!(
            "Tell the user it was started and that you are waiting for it to be ready, then \
             call wait_until_ready with family vps and this userVpsId."
        );
    }
    Ok(out)
}

/// `end_hourly_product`: ends one of the account's hourly products, after
/// the person says yes.
///
/// # Errors
///
/// A message saying what user-api or the person refused, for the caller to show.
pub async fn end_hourly_product(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
    confirm: Option<&dyn Confirm>,
) -> Result<Value, String> {
    let product_type = input
        .get("productType")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let user_product_id = input
        .get("userProductId")
        .and_then(Value::as_i64)
        .ok_or("userProductId is the number credit_balance gives for the product")?;
    let family = hourly::for_product_type(product_type)
        .ok_or_else(|| format!("erpc cannot end a product of type {product_type:?}"))?;
    let confirm = confirm.ok_or(NO_ONE_TO_ASK)?;

    // The product as the account has it now, not as the model remembers it.
    let credit = credit(client, token).await?;
    let row = credit
        .hourly
        .iter()
        .find(|r| {
            r.get("productType").and_then(Value::as_str) == Some(product_type)
                && r.get("userProductId").and_then(Value::as_i64) == Some(user_product_id)
        })
        .ok_or_else(|| format!("the account has no hourly {product_type} {user_product_id}"))?;
    if row.get("endHourlyEligible").and_then(Value::as_bool) == Some(false) {
        let why = row
            .get("endHourlyBlockedReason")
            .and_then(Value::as_str)
            .unwrap_or("not endable now");
        return Err(format!("it cannot be ended now: {why}"));
    }
    let product = row
        .get("productName")
        .and_then(Value::as_str)
        .unwrap_or(product_type)
        .to_owned();
    let cents = row
        .get("hourlyCents")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let ask = Confirmation {
        title: t!("confirm.end.title", product),
        lines: vec![
            (
                t!("confirm.label.product"),
                format!("{product} ({product_type} {user_product_id})"),
            ),
            (
                t!("confirm.label.price_now"),
                t!("confirm.end.price", hourly = euros(cents)),
            ),
        ],
    };
    if !confirm.confirm(&ask).await {
        return Err("the user said no; nothing was ended".to_owned());
    }
    let reply = hourly::end(client, token, family, &json!(user_product_id))
        .await
        .map_err(|e| format!("the end was not sent: {e}"))?;
    Ok(outcome(&reply, &format!("end {product}")))
}

/// A random version 4 UUID, for a session's client request id.
fn uuid_v4() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| format!("no randomness for the request id: {e}"))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = erpc_wallet::evm::hex(&b);
    let h = &h[2..];
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The transfer a ready session asks to be signed, refused unless it is
/// EURC on Base with the domain erpc knows.
fn transfer_of(
    session: &Value,
) -> Result<(erpc_wallet::eurc::TransferAuthorization, u128), String> {
    use erpc_wallet::eurc::{self, TransferAuthorization, parse_bytes32, parse_decimal};
    use erpc_wallet::evm::Address;
    let s = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or_default().to_owned();
    let typed = session
        .get("typedData")
        .ok_or("the session has no transfer to sign")?;
    let domain = typed.get("domain").unwrap_or(&Value::Null);
    let contract = s(domain.get("verifyingContract")).to_lowercase();
    if s(domain.get("name")) != eurc::DOMAIN_NAME
        || s(domain.get("version")) != eurc::DOMAIN_VERSION
        || domain.get("chainId").and_then(Value::as_u64) != Some(eurc::CHAIN_ID)
        || contract != eurc::EURC_CONTRACT
        || s(typed.get("primaryType")) != "TransferWithAuthorization"
    {
        return Err(
            "the session asks for something other than a EURC transfer on Base; nothing was signed"
                .to_owned(),
        );
    }
    let m = typed.get("message").unwrap_or(&Value::Null);
    let err = |e: erpc_wallet::evm::WalletError| e.to_string();
    let transfer = TransferAuthorization {
        from: Address::parse(&s(m.get("from"))).map_err(err)?,
        to: Address::parse(&s(m.get("to"))).map_err(err)?,
        value: parse_decimal(&s(m.get("value"))).map_err(err)?,
        valid_after: u64::try_from(parse_decimal(&s(m.get("validAfter"))).map_err(err)?)
            .map_err(|_| "validAfter is out of range")?,
        valid_before: u64::try_from(parse_decimal(&s(m.get("validBefore"))).map_err(err)?)
            .map_err(|_| "validBefore is out of range")?,
        nonce: parse_bytes32(&s(m.get("nonce"))).map_err(err)?,
    };
    let quoted = parse_decimal(&s(session
        .get("quote")
        .and_then(|q| q.get("totalEurcAtomic"))))
    .map_err(err)?;
    Ok((transfer, quoted))
}

/// `create_credit_wallet`: sets up the one wallet top-ups pay from. The
/// configured one stays; else the one erpc made before is found in
/// 1Password and used; only when there is none is a new one made, its key
/// going only to 1Password. Each step that sets one up asks the person
/// first; the model gets the address.
pub(crate) async fn create_credit_wallet(
    input: &Value,
    confirm: Option<&dyn Confirm>,
    wallet: Option<&dyn crate::confirm::CreditWallet>,
) -> Result<Value, String> {
    let wallet = wallet.ok_or("this erpc cannot make a wallet")?;
    if let Ok(address) = wallet.address() {
        return Ok(json!({
            "done": true,
            "already": true,
            "address": address.to_string(),
            "network": "Base",
            "note": "This is the user's wallet for buying credit; erpc keeps one, never more.",
        }));
    }
    if let Some(why) = wallet.existing() {
        return Err(why);
    }
    let confirm = confirm.ok_or(NO_ONE_TO_ASK)?;
    let allow_ai = input
        .get("allowAi")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let ai_line = if allow_ai {
        t!("confirm.wallet.ai_may_pay")
    } else {
        t!("confirm.wallet.ai_may_not")
    };
    if let Some(found) = wallet.find().await? {
        let ask = Confirmation {
            title: t!("confirm.wallet.found_title"),
            lines: vec![
                (t!("confirm.label.address"), found.address.to_string()),
                (
                    t!("confirm.label.vault"),
                    t!("confirm.wallet.vault", vault = found.vault),
                ),
                ("erpc ai".to_owned(), ai_line),
                (t!("confirm.label.why"), t!("confirm.wallet.one_wallet")),
            ],
        };
        if !confirm.confirm(&ask).await {
            return Err("the user said no; nothing was set up".to_owned());
        }
        let address = wallet.adopt(&found, allow_ai).await?;
        return Ok(json!({
            "done": true,
            "found": true,
            "address": address.to_string(),
            "network": "Base",
            "otherWalletItems": found.others,
            "next": "send EURC on Base to this address if it holds too little; buying credit needs no ETH (ERPC pays the gas)",
            "erpcAiMayPay": allow_ai,
        }));
    }
    let vault = input
        .get("vault")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| wallet.vault())
        .ok_or("no ERPC wallet is in 1Password yet; ask the user which 1Password vault to make it in (its id or name; a personal one, such as Private)")?;
    let ask = Confirmation {
        title: t!("confirm.wallet.new_title"),
        lines: vec![
            (t!("confirm.label.key"), t!("confirm.wallet.key")),
            (t!("confirm.label.vault"), t!("confirm.wallet.vault", vault)),
            ("erpc ai".to_owned(), ai_line),
        ],
    };
    if !confirm.confirm(&ask).await {
        return Err("the user said no; no wallet was made".to_owned());
    }
    let address = wallet.create(&vault, allow_ai).await?;
    Ok(json!({
        "done": true,
        "address": address.to_string(),
        "network": "Base",
        "next": "send EURC on Base to this address; buying credit needs no ETH (ERPC pays the gas)",
        "erpcAiMayPay": allow_ai,
    }))
}

/// What the person is asked before a top-up is signed.
fn top_up_question(
    credits: u32,
    session: &Value,
    quoted: u128,
    payer: &erpc_wallet::evm::Address,
    to: &erpc_wallet::evm::Address,
) -> Confirmation {
    let q = session.get("quote").unwrap_or(&Value::Null);
    let text = |k: &str| q.get(k).and_then(Value::as_str).unwrap_or("?").to_owned();
    Confirmation {
        title: tn!("confirm.top_up.title", credits, total = text("totalEurc")),
        lines: vec![
            (
                t!("confirm.label.credits"),
                format!("{credits} (€{:.2})", f64::from(credits) / 100.0),
            ),
            (
                t!("confirm.label.subtotal"),
                format!("{} EURC", text("subtotalEurc")),
            ),
            (
                t!("confirm.label.vat"),
                t!(
                    "confirm.top_up.vat",
                    amount = text("vatAmountEurc"),
                    rate = text("vatRate")
                ),
            ),
            (
                t!("confirm.label.total"),
                format!("{} EURC", erpc_wallet::eurc::format_eurc(quoted)),
            ),
            (t!("confirm.label.from"), payer.to_string()),
            (t!("confirm.label.to"), t!("confirm.top_up.to", to)),
            (t!("confirm.label.network"), t!("confirm.top_up.network")),
            (t!("confirm.label.valid_until"), text("quoteExpiresAt")),
        ],
    }
}

/// Follows a submitted session for about a minute, until it is granted or
/// settled otherwise.
async fn follow(
    client: &AuthClient,
    token: &SecretString,
    id: &str,
    submitted: erpc_api::gasless::Reply,
) -> erpc_api::gasless::Reply {
    let mut last = submitted;
    // The relay and the grant take a little while: follow it for a minute.
    for _ in 0..20 {
        let state = last
            .body
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if matches!(state, "granted" | "stuck" | "expired" | "cancelled")
            || !(200..300).contains(&last.status)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        match erpc_api::gasless::status(client, token, id).await {
            Ok(reply) => last = reply,
            Err(_) => break,
        }
    }
    last
}

/// `top_up_credit`: buys ERPC Credit with EURC on Base from the configured
/// wallet, after the person says yes to the quote.
pub(crate) async fn top_up_credit(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
    confirm: Option<&dyn Confirm>,
    wallet: Option<&dyn crate::confirm::CreditWallet>,
) -> Result<Value, String> {
    use erpc_api::gasless;
    let credits = input
        .get("amountCredits")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| (1..=10_000).contains(n))
        .ok_or("amountCredits is a whole number from 1 to 10,000 (1 Credit = €0.01)")?;
    let wallet = wallet.ok_or("this erpc has no wallet support")?;
    let confirm = confirm.ok_or(NO_ONE_TO_ASK)?;
    let payer = wallet.address()?;

    let request_id = uuid_v4()?;
    let prepared = gasless::prepare(
        client,
        token,
        &request_id,
        credits,
        &payer.to_string().to_lowercase(),
    )
    .await
    .map_err(|e| format!("the top-up was not prepared: {e}"))?;
    let session = prepared.body;
    let state = session
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !(200..300).contains(&prepared.status) || state != "ready" {
        let mut out = pick(&session, &["code", "message", "state"]);
        out["httpStatus"] = json!(prepared.status);
        out["done"] = json!(false);
        return Ok(out);
    }
    let id = session
        .get("sessionId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let cancel = || async {
        let _ = gasless::cancel(client, token, &id).await;
    };
    let (transfer, quoted) = match transfer_of(&session) {
        Ok(t) => t,
        Err(e) => {
            cancel().await;
            return Err(e);
        }
    };
    if let Err(e) = transfer.check(&payer, quoted, now_unix()) {
        cancel().await;
        return Err(format!("{e}; nothing was signed"));
    }
    let ask = top_up_question(credits, &session, quoted, &payer, &transfer.to);
    if !confirm.confirm(&ask).await {
        cancel().await;
        return Err("the user said no; nothing was signed or paid".to_owned());
    }
    let signature = {
        let key = match wallet.key() {
            Ok(key) => key,
            Err(e) => {
                cancel().await;
                return Err(e);
            }
        };
        match transfer.sign(&key, quoted, now_unix()) {
            Ok(sig) => erpc_wallet::evm::hex(&sig),
            Err(e) => {
                cancel().await;
                return Err(format!("{e}; nothing was signed"));
            }
        }
    };
    let submitted = gasless::submit(client, token, &id, &signature)
        .await
        .map_err(|e| format!("the signed transfer was not sent: {e}"))?;
    let last = follow(client, token, &id, submitted).await;
    let mut out = pick(&last.body, &["state", "code", "message", "transaction"]);
    out["httpStatus"] = json!(last.status);
    out["done"] = json!(last.body.get("state").and_then(Value::as_str) == Some("granted"));
    out["sessionId"] = json!(id);
    out["what"] = json!(format!("buy {credits} credits"));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{euros, outcome};
    use erpc_api::hourly::Reply;
    use serde_json::json;

    #[tokio::test]
    async fn nothing_is_started_or_ended_without_someone_to_ask() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let token = secrecy::SecretString::from("not-sent");
        let start =
            json!({ "family": "vps", "fields": { "productId": "prod_x", "region": "tokyo" } });
        let refused = super::start_hourly_product(&client, &token, &start, None).await;
        assert_eq!(refused, Err(super::NO_ONE_TO_ASK.to_owned()));
        let end = json!({ "productType": "vps", "userProductId": 7 });
        let refused = super::end_hourly_product(&client, &token, &end, None).await;
        assert_eq!(refused, Err(super::NO_ONE_TO_ASK.to_owned()));
        // A wrong family or a field the route does not take is refused first.
        let bad = json!({ "family": "vps", "fields": { "productId": "prod_x", "region": "tokyo", "price": 0 } });
        assert!(
            super::start_hourly_product(&client, &token, &bad, None)
                .await
                .unwrap_err()
                .contains("does not take price")
        );
    }

    #[tokio::test]
    async fn a_top_up_without_a_wallet_or_a_person_sends_nothing() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let token = secrecy::SecretString::from("not-sent");
        let ask = json!({ "amountCredits": 500 });
        let refused = super::top_up_credit(&client, &token, &ask, None, None).await;
        assert!(refused.unwrap_err().contains("no wallet support"));
        for bad in [
            json!({}),
            json!({ "amountCredits": 0 }),
            json!({ "amountCredits": 10_001 }),
        ] {
            let refused = super::top_up_credit(&client, &token, &bad, None, None).await;
            assert!(refused.unwrap_err().contains("1 to 10,000"), "{bad}");
        }
    }

    /// A wallet that is set up already, and makes none.
    struct SetUp;

    impl crate::confirm::CreditWallet for SetUp {
        fn address(&self) -> Result<erpc_wallet::evm::Address, String> {
            erpc_wallet::evm::Address::parse("0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826")
                .map_err(|e| e.to_string())
        }
        fn key(&self) -> Result<erpc_wallet::evm::EvmKey, String> {
            Err("not in tests".to_owned())
        }
        fn vault(&self) -> Option<String> {
            None
        }
        fn create<'a>(
            &'a self,
            _: &'a str,
            _: bool,
        ) -> core::pin::Pin<Box<dyn Future<Output = Result<erpc_wallet::evm::Address, String>> + 'a>>
        {
            panic!("a wallet that exists is never replaced")
        }
    }

    /// No wallet configured here; one erpc made before is in 1Password.
    struct InOnePassword(std::cell::Cell<bool>);

    impl crate::confirm::CreditWallet for InOnePassword {
        fn address(&self) -> Result<erpc_wallet::evm::Address, String> {
            Err("none here".to_owned())
        }
        fn existing(&self) -> Option<String> {
            None
        }
        fn key(&self) -> Result<erpc_wallet::evm::EvmKey, String> {
            Err("not in tests".to_owned())
        }
        fn vault(&self) -> Option<String> {
            None
        }
        fn find(
            &self,
        ) -> core::pin::Pin<
            Box<dyn Future<Output = Result<Option<crate::confirm::FoundWallet>, String>> + '_>,
        > {
            Box::pin(async {
                Ok(Some(crate::confirm::FoundWallet {
                    address: SetUp.address()?,
                    reference: "op://v/i/private_key".to_owned(),
                    vault: "Private".to_owned(),
                    others: 0,
                }))
            })
        }
        fn adopt<'a>(
            &'a self,
            found: &'a crate::confirm::FoundWallet,
            _: bool,
        ) -> core::pin::Pin<Box<dyn Future<Output = Result<erpc_wallet::evm::Address, String>> + 'a>>
        {
            self.0.set(true);
            Box::pin(async move { Ok(found.address) })
        }
        fn create<'a>(
            &'a self,
            _: &'a str,
            _: bool,
        ) -> core::pin::Pin<Box<dyn Future<Output = Result<erpc_wallet::evm::Address, String>> + 'a>>
        {
            panic!("a wallet in 1Password is used, not a second one made")
        }
    }

    struct Yes;

    impl crate::confirm::Confirm for Yes {
        fn confirm<'a>(
            &'a self,
            _: &'a crate::confirm::Confirmation,
        ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
            Box::pin(async { true })
        }
    }

    #[tokio::test]
    async fn the_wallet_in_1password_is_used_rather_than_a_second_made() {
        let wallet = InOnePassword(std::cell::Cell::new(false));
        let out = super::create_credit_wallet(&json!({}), Some(&Yes), Some(&wallet))
            .await
            .expect("set up");
        assert_eq!(out["found"], json!(true));
        assert!(wallet.0.get(), "adopted");
        let configured = super::create_credit_wallet(&json!({}), None, Some(&SetUp))
            .await
            .expect("the configured one");
        assert_eq!(configured["already"], json!(true));
    }

    #[tokio::test]
    async fn an_existing_wallet_is_kept_and_none_is_made_without_a_person() {
        // SetUp's create panics: the configured wallet is answered with.
        let kept = super::create_credit_wallet(&json!({}), None, Some(&SetUp)).await;
        assert_eq!(kept.expect("kept")["already"], json!(true));
        let none = super::create_credit_wallet(&json!({}), None, None).await;
        assert!(none.is_err());
    }

    #[test]
    fn a_top_up_asks_in_the_language_of_the_run() {
        use erpc_core::i18n::Lang;
        let session = json!({ "quote": {
            "totalEurc": "5.05", "subtotalEurc": "5.00", "vatAmountEurc": "0.05",
            "vatRate": "1%", "quoteExpiresAt": "2026-11-02T10:00:00Z",
        }});
        let payer = erpc_wallet::evm::Address::parse("0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826")
            .expect("an address");
        let to = erpc_wallet::evm::Address::parse(erpc_wallet::eurc::TREASURY).expect("treasury");
        let ask = |lang, credits| {
            crate::i18n::speaking(lang, || {
                super::top_up_question(credits, &session, 5_050_000, &payer, &to).text()
            })
        };
        let english = ask(Lang::En, 500);
        assert!(
            english.starts_with("Buy 500 ERPC Credits for 5.05 EURC from your wallet?"),
            "{english}"
        );
        assert!(ask(Lang::En, 1).starts_with("Buy 1 ERPC Credit for"));
        let chinese = ask(Lang::Zh, 500);
        assert!(
            chinese.starts_with("从你的钱包支付 5.05 EURC，购买 500 ERPC 积分？"),
            "{chinese}"
        );
        assert!(chinese.contains("增值税") && chinese.contains("0.05 EURC（税率 1%）"));
        let russian = ask(Lang::Ru, 500);
        assert!(
            russian.starts_with("Купить 500 кредитов ERPC за 5.05 EURC"),
            "{russian}"
        );
        assert!(ask(Lang::Ru, 3).starts_with("Купить 3 кредита ERPC"));
        assert!(ask(Lang::Ru, 21).starts_with("Купить 21 кредит ERPC"));
        assert!(russian.contains("Итого") && russian.contains(&payer.to_string()));
        // The money and both ends are in every language, as they are.
        for text in [&english, &chinese, &russian] {
            assert!(text.contains("5.05 EURC") && text.contains("2026-11-02T10:00:00Z"));
        }
    }

    #[test]
    fn a_session_that_is_not_eurc_on_base_is_not_signed() {
        let ready = |contract: &str| {
            json!({
                "quote": { "totalEurcAtomic": "5050000" },
                "typedData": {
                    "domain": { "name": "EURC", "version": "2", "chainId": 8453, "verifyingContract": contract },
                    "primaryType": "TransferWithAuthorization",
                    "message": {
                        "from": "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826",
                        "to": erpc_wallet::eurc::TREASURY,
                        "value": "5050000", "validAfter": "0", "validBefore": "1792900000",
                        "nonce": format!("0x{}", "11".repeat(32)),
                    },
                },
            })
        };
        let (transfer, quoted) =
            super::transfer_of(&ready(erpc_wallet::eurc::EURC_CONTRACT)).expect("eurc");
        assert_eq!((transfer.value, quoted), (5_050_000, 5_050_000));
        assert!(super::transfer_of(&ready("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")).is_err());
    }

    #[test]
    fn money_reads_as_euros() {
        assert_eq!(euros(14.0), "€0.14");
        assert_eq!(euros(729.0 * 24.0), "€174.96");
    }

    #[test]
    fn an_outcome_keeps_the_product_ids_and_drops_stripes() {
        let reply = Reply {
            status: 200,
            body: json!({
                "success": true, "userVpsId": 7, "stripeSubscriptionId": "sub_x",
                "stripeSubscriptionItemId": "si_x", "provisioningPending": true
            }),
        };
        let out = outcome(&reply, "start VPS");
        assert_eq!(out["done"], json!(true));
        assert_eq!(out["userVpsId"], json!(7));
        assert!(out.get("stripeSubscriptionId").is_none());
        assert!(out.get("stripeSubscriptionItemId").is_none());
        let refused = Reply {
            status: 400,
            body: json!({ "success": false, "message": "no stock", "code": "OUT_OF_STOCK" }),
        };
        let out = outcome(&refused, "start VPS");
        assert_eq!(out["done"], json!(false));
        assert_eq!(out["code"], json!("OUT_OF_STOCK"));
    }
}
