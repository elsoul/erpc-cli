// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the assistant may look up, read from user-api: the signed-in
//! account's credits, subscriptions, usage and services, and what ERPC
//! offers -- servers and their stock by region, plan prices, how each region
//! is answering ([`crate::services`]) -- and the text of a skill. The tools
//! that change the account (starting and ending an hourly product) are in
//! [`crate::actions`]; each asks the person first, whatever a skill or the
//! model says.
//!
//! Each tool passes on the fields it names and nothing else. The replies
//! hold more than the model needs, and some of it -- Stripe objects, ids --
//! is not the model's business; a field user-api adds later stays out
//! until a tool names it.

use erpc_api::{ApiError, account, ai};
use erpc_auth::AuthClient;
use erpc_core::i18n::Lang;
use secrecy::SecretString;
use serde_json::{Map, Value, json};

/// The tools, as the Messages API takes them.
#[must_use]
pub fn definitions() -> Vec<Value> {
    TOOLS
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": input_schema(tool.name),
            })
        })
        .collect()
}

/// What a tool takes: nothing, for most.
fn input_schema(name: &str) -> Value {
    let kind = json!({
        "type": "string",
        "enum": account::Server::ALL.map(account::Server::name),
    });
    let (properties, required) = match name {
        "server_catalog" => (
            json!({
                "kind": kind,
                "bare_metal_type": {
                    "type": "string",
                    "enum": account::BARE_METAL_TYPES,
                    "description": "Bare metal only. APP: apps, bots, testnet validators. MV: Solana mainnet validators. RPC: Solana RPC nodes. UT: 48 cores and more. LG: large. all: every one.",
                },
            }),
            json!(["kind"]),
        ),
        "server_stock" => (
            json!({
                "kind": kind,
                "region": { "type": "string", "enum": crate::services::REGIONS },
            }),
            json!(["kind"]),
        ),
        "plan_prices" => (
            json!({ "family": { "type": "string", "enum": crate::services::PLAN_FAMILIES } }),
            json!(["family"]),
        ),
        "service_health" => (
            json!({ "service": { "type": "string", "enum": ["rpc", "grpc", "shreds"] } }),
            json!(["service"]),
        ),
        "hourly_catalog" => (
            json!({ "family": { "type": "string", "enum": hourly_family_names() } }),
            json!([]),
        ),
        "start_hourly_product" => (
            json!({
                "family": { "type": "string", "enum": hourly_family_names() },
                "fields": {
                    "type": "object",
                    "description": "The start's fields, as hourly_catalog lists them for the family: productId from the catalogue, and region, ip and the rest as the user chose them.",
                },
            }),
            json!(["family", "fields"]),
        ),
        "end_hourly_product" => (
            json!({
                "productType": { "type": "string", "description": "hourlyResources[].productType from credit_balance." },
                "userProductId": { "type": "integer", "description": "hourlyResources[].userProductId from credit_balance." },
            }),
            json!(["productType", "userProductId"]),
        ),
        "create_credit_wallet" => (
            json!({
                "vault": { "type": "string", "description": "The 1Password vault id to keep it in, if the user named one; otherwise the one erpc login uses." },
                "allowAi": { "type": "boolean", "description": "Whether erpc ai may ask to pay from it (each payment still asks). Default true." },
            }),
            json!([]),
        ),
        "top_up_credit" => (
            json!({ "amountCredits": { "type": "integer", "minimum": 1, "maximum": 10000, "description": "Credits to buy; 1 Credit = €0.01, VAT is added." } }),
            json!(["amountCredits"]),
        ),
        "secure_vps" => (
            json!({ "userVpsId": { "type": "integer", "description": "userVpsId from my_services or the start's result." } }),
            json!(["userVpsId"]),
        ),
        "restrict_ssh" => (
            json!({
                "userVpsId": { "type": "integer" },
                "extraAddresses": { "type": "array", "items": { "type": "string" }, "description": "Other IP addresses the user named to allow too; theirs is added by erpc." },
                "open": { "type": "boolean", "description": "true takes the allow list away instead." },
            }),
            json!(["userVpsId"]),
        ),
        "wait_until_ready" => (
            json!({
                "family": { "type": "string", "enum": ["vps"] },
                "userVpsId": { "type": "integer", "description": "userVpsId from the start's result." },
            }),
            json!(["family", "userVpsId"]),
        ),
        "ask_choice" => crate::ask::input_schema(),
        "run_command" => crate::commands::input_schema(),
        "remember" | "forget" => crate::memory::input_schema(name),
        "read_skill" => {
            let names: Vec<&str> = erpc_skills::all().iter().map(|s| s.name).collect();
            (
                json!({ "name": { "type": "string", "enum": names } }),
                json!(["name"]),
            )
        }
        _ => (json!({}), json!([])),
    };
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn hourly_family_names() -> Vec<&'static str> {
    erpc_api::hourly::FAMILIES.iter().map(|f| f.name).collect()
}

/// One tool.
struct Tool {
    name: &'static str,
    description: &'static str,
}

/// The money note every description ends with.
macro_rules! credits {
    () => {
        " Amounts named ...Cents are ERPC Credits: 1 Credit is 1 euro cent (EUR 1 = 100 Credits)."
    };
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "run_command",
        description: "Runs a command on the user's own computer, where erpc runs (not on a \
                      server), and returns its exit code and output. Use it to look for \
                      yourself instead of asking the user to run something and paste the \
                      output. Give argv, the program and each argument as its own item, with \
                      no shell; or shell, a script for sh -c (cmd /C on Windows), when pipes, \
                      &&, redirection or globs are really needed. A script always asks, \
                      unless the user allowed that exact script or every command. \
                      Commands that only look run at once: uname, hostname, whoami, id, \
                      uptime, nproc, arch, free, df, du, lscpu, lsblk, ls, pwd, which, date, \
                      sysctl (reading), sw_vers, vm_stat, lsb_release, timedatectl, \
                      hostnamectl, ip (show, list, get), ss, systemctl (status, is-active, \
                      is-enabled, is-failed, list-units, list-unit-files, list-timers), \
                      journalctl (not -f), docker (ps, images, version, info, logs without \
                      -f, stats --no-stream), solana reads (balance, epoch-info, validators, \
                      ...) against its configured RPC or -u m, t or d, cat of \
                      /etc/os-release and /proc/cpuinfo, meminfo or loadavg, curl -q \
                      ifconfig.me or curl -q api.ipify.org (-q first), and --version of \
                      git, docker, solana, agave-validator and jq. Options outside the usual \
                      reading ones make a command ask. Anything else is shown to the person word for word and runs only \
                      on their yes; they may allow that exact command, or every command \
                      (scripts too), for the rest of the session. Standard input is empty, so nothing interactive works \
                      (sudo asking for a password, editors); a command is stopped after 30 \
                      seconds, or 5 minutes once agreed. Never use it to print secrets: key \
                      files, .env files, env, shell history.",
    },
    Tool {
        name: "remember",
        description: "Saves one short fact about the user for later conversations: their hosts \
                      and node names, chains and networks, plans, preferences, decisions. Save \
                      what will still matter next time, not one-off details; save it when you \
                      learn it or the user asks you to remember. Never save secrets (passwords, \
                      keys, tokens, seed phrases); they are refused.",
    },
    Tool {
        name: "forget",
        description: "Drops a remembered fact, by its number: when the user asks you to forget \
                      it, or it is no longer true.",
    },
    Tool {
        name: "secure_vps",
        description: "Logs in to the user's running VPS for them, once, with the password ERPC \
                      set (erpc reads it; you never see it), puts the user's own SSH key in \
                      place and turns password logins off for good, after the person says yes. \
                      Use it right after a VPS is ready, or when the user asks how to log in. \
                      Never give or ask for a password.",
    },
    Tool {
        name: "restrict_ssh",
        description: "Allows SSH to a VPS made key-only by secure_vps from the user's own \
                      address only (erpc reads it from the connection; extraAddresses adds \
                      others they name), after the person says yes; undone by itself if erpc \
                      cannot get back in. open: true takes it away. Recommend it after \
                      secure_vps; call it only when the user agrees or asks.",
    },
    Tool {
        name: "wait_until_ready",
        description: "Waits, up to five minutes, for a VPS just started to be running, reading \
                      its state every 15 seconds; the result says whether it is ready (with its \
                      IP and login user) or what went wrong. Call it right after \
                      start_hourly_product starts a VPS with provisioningPending, having told \
                      the user in a sentence that you are waiting. The password is never given.",
    },
    Tool {
        name: "ask_choice",
        description: "Asks the person a question they answer by picking from options (up and \
                      down, then Enter; several with Space when multiSelect), instead of typing. \
                      Use it whenever you need the user to choose or decide: a plan, a region, \
                      an amount, which of several, whether to go on. The result is the labels \
                      picked; carry on from them. Do not also ask in text. A tool that changes \
                      the account asks its own yes or no, so do not ask for a go-ahead before \
                      calling one.",
    },
    Tool {
        name: "read_skill",
        description: "The text of one of the skills listed in the system prompt: what erpc and \
                      ERPC offer on that subject and how to answer about it. Read the one that \
                      fits before answering about a chain, a node, ERPC's services or signing in.",
    },
    Tool {
        name: "credit_balance",
        description: concat!(
            "The signed-in account's ERPC Credit balance, what is drawing on it (hourly resources, \
             monthly plans paid in Credits), the burn rate, how many hours it lasts \
             (timeToZeroHours), the alert level, and the forecast of upcoming charges.",
            credits!()
        ),
    },
    Tool {
        name: "credit_history",
        description: concat!(
            "Credits added and spent by the signed-in account, by month, for the last three months.",
            credits!()
        ),
    },
    Tool {
        name: "card_subscriptions",
        description: "The signed-in account's subscriptions paid by card (Stripe): status, price, \
                      interval and renewal. Plans paid in ERPC Credits are in credit_balance, not here.",
    },
    Tool {
        name: "open_dashboard",
        description: "Opens the ERPC dashboard's home in the user's browser and returns its \
                      address. Monthly and yearly card subscriptions are bought there: the user \
                      picks the product, monthly or yearly, and pays by card, and the \
                      subscription starts when the payment is done; erpc cannot buy one itself. \
                      Call it when the user wants a monthly or yearly plan or a payment link for \
                      one. When opened is false, give the user the url to open.",
    },
    Tool {
        name: "rpc_usage",
        description: "The signed-in account's ERPC RPC usage this month (UTC), across all its API \
                      keys: total calls and RPC credits, and the methods that used the most RPC \
                      credits, by chain. RPC credits are the units the RPC plan's allowance is \
                      counted in; they are not ERPC Credits and not money, so never convert them \
                      to euros. A method's credits can differ from count times creditCost, which \
                      is today's rate.",
    },
    Tool {
        name: "ai_usage",
        description: "The signed-in account's ERPC AI plan: the plan, tokens left and the allowance, \
                      bonus and token packs, when the allowance resets, and whether AI use is \
                      suspended.",
    },
    Tool {
        name: "my_services",
        description: "Every service the signed-in account runs, by kind: VPS, bare metal, Unlimited \
                      RPC, dedicated RPC, shared and dedicated Geyser gRPC, shared and dedicated \
                      shreds, Epic Shreds Direct. Product, plan, region, status and dates; for a \
                      shared gRPC or shreds slot, any penalty. No IPs, passwords or keys: those are \
                      in the dashboard.",
    },
    Tool {
        name: "server_catalog",
        description: "The servers ERPC rents, of one kind, with monthly prices in euros and specs \
                      (CPU, RAM, disk, network). vps: shared EPYC VPS. super_vps: 5.7 GHz cores. \
                      premium_vps: 5.7 GHz Ryzen on the network of the Solana shreds sources. \
                      bare_metal: dedicated machines, by bare_metal_type (MV for Solana mainnet \
                      validators, RPC for Solana RPC nodes).",
    },
    Tool {
        name: "server_stock",
        description: "Servers of one kind free to rent now, counted by region and spec. Use it \
                      before recommending a region or a machine: a product with none in stock in \
                      a region cannot be had there now.",
    },
    Tool {
        name: "plan_prices",
        description: "Names and prices of the plans of one family, in euros per month and per \
                      year: erpc_plan (shared RPC), unlimited_rpc, dedicated_rpc, grpc (shared \
                      Geyser gRPC), dedicated_grpc, shreds, bundle, storage, slv_ai_plan, and the \
                      server families vps and bare_metal.",
    },
    Tool {
        name: "service_health",
        description: "How each region has answered rpc, grpc or shreds probes over the last 30 \
                      days: success rate, average latency, and its status now. For choosing a \
                      region, or when the user asks whether a service is up.",
    },
    Tool {
        name: "hourly_catalog",
        description: concat!(
            "What can be started hourly from ERPC Credit, by family, with each product's price              per hour in euros and the fields its start takes. Given a family, its products'              names too. Read it before proposing a start.",
            credits!()
        ),
    },
    Tool {
        name: "start_hourly_product",
        description: "Starts an hourly product for the signed-in account, paid from ERPC Credit \
                      until it is ended. erpc shows the person the product, its price per hour \
                      and how long the credit lasts, and starts it only if they say yes; the \
                      result says whether user-api started it or why not (no card \
                      authorisation, not enough credit, no stock). Call it only when the user \
                      asked for this product; say what it costs first.",
    },
    Tool {
        name: "end_hourly_product",
        description: "Ends one of the signed-in account's hourly products (from credit_balance's \
                      hourlyResources): it stops and stops being charged, and cannot be undone. \
                      erpc shows the person which product and asks; only a yes ends it. Call it \
                      only when the user asked to end this product.",
    },
    Tool {
        name: "top_up_credit",
        description: "Buys ERPC Credit with EURC on Base from the wallet the user set up for \
                      top-ups (ERPC pays the gas). erpc asks user-api for a quote (VAT added), \
                      shows the person the credits, the EURC total, their wallet and ERPC's \
                      treasury, and signs and sends only on their yes; the result says whether \
                      the credit was granted. A result with state `unknown` means the signed \
                      transfer may have been taken: never call this again for the same \
                      purchase until my_account shows the balance or the person has checked. \
                      Call it only when the user asked to buy credit, with the amount they \
                      named.",
    },
    Tool {
        name: "create_credit_wallet",
        description: "Sets up the user's one Base wallet for buying ERPC Credit in EURC: the \
                      one configured stays; else the ERPC wallet already in 1Password (made \
                      before, on any machine) is used; only when there is none is a new one \
                      made, its key kept only in 1Password. Each step asks the person first; \
                      the result is the address to send EURC to. Call it whenever the user \
                      wants to buy credit in EURC and no wallet is set up; never ask for or \
                      handle a private key.",
    },
];

/// The label of a tool erpc does not know.
pub(crate) const UNKNOWN_LABEL: &str = "tools.unknown";

/// The tools' names.
#[cfg(test)]
pub(crate) fn names() -> impl Iterator<Item = &'static str> {
    TOOLS.iter().map(|t| t.name)
}

/// What the console shows while `name` runs, in `lang`: `tools.<name>` in
/// the catalog.
#[must_use]
pub fn label(name: &str, lang: Lang) -> String {
    let key = if TOOLS.iter().any(|t| t.name == name) {
        format!("tools.{name}")
    } else {
        UNKNOWN_LABEL.to_owned()
    };
    crate::i18n::CATALOG.text(lang, &key, &[])
}

/// What the session lends the tools: someone to ask, the wallet, the
/// servers, the memory. Each is absent where the front end has none.
#[derive(Clone, Copy, Default)]
pub struct Helpers<'a> {
    /// Asks the person before anything changes.
    pub confirm: Option<&'a dyn crate::confirm::Confirm>,
    /// Pays credit top-ups.
    pub wallet: Option<&'a dyn crate::confirm::CreditWallet>,
    /// Logs in to the user's servers.
    pub servers: Option<&'a dyn crate::servers::Servers>,
    /// What is remembered between conversations.
    pub memory: Option<&'a crate::memory::Memory>,
    /// Runs commands on the user's computer.
    pub shell: Option<&'a dyn crate::commands::Shell>,
    /// The commands the person allowed until the console ends.
    pub allowed: Option<&'a crate::commands::Allowed>,
    /// Opens pages in the person's browser.
    pub browser: Option<&'a dyn crate::dashboard::Browser>,
}

/// The most RPC methods passed on: the reply lists every one.
const RPC_METHODS: usize = 15;

/// Runs a tool and returns what the model is given: JSON text, or why it
/// could not be read.
///
/// # Errors
///
/// Returns a sentence for the model when the tool is unknown or user-api
/// does not answer.
pub async fn run(
    name: &str,
    input: &Value,
    client: &AuthClient,
    token: &SecretString,
    helpers: Helpers<'_>,
) -> Result<String, String> {
    use crate::{actions, services};
    let Helpers {
        confirm,
        wallet,
        servers,
        memory,
        shell,
        allowed,
        browser,
    } = helpers;
    let value = match name {
        "hourly_catalog" => actions::hourly_catalog(client, token, input).await?,
        "start_hourly_product" => {
            actions::start_hourly_product(client, token, input, confirm).await?
        }
        "end_hourly_product" => actions::end_hourly_product(client, token, input, confirm).await?,
        "top_up_credit" => actions::top_up_credit(client, token, input, confirm, wallet).await?,
        "create_credit_wallet" => actions::create_credit_wallet(input, confirm, wallet).await?,
        "ask_choice" => crate::ask::ask_choice(input, confirm).await?,
        "run_command" => crate::commands::run_command(input, confirm, shell, allowed).await?,
        "remember" => crate::memory::remember(memory, input, unix_now())?,
        "forget" => crate::memory::forget(memory, input)?,
        "wait_until_ready" => crate::ready::wait_until_ready(client, token, input).await?,
        "secure_vps" => crate::servers::secure_vps(client, token, input, confirm, servers).await?,
        "restrict_ssh" => {
            crate::servers::restrict_ssh(client, token, input, confirm, servers).await?
        }
        "read_skill" => return read_skill(input),
        "my_services" => services::my_services(client, token).await?,
        "open_dashboard" => crate::dashboard::open_dashboard(browser),
        "server_catalog" => services::server_catalog(client, token, input).await?,
        "server_stock" => services::server_stock(client, token, input).await?,
        "plan_prices" => services::plan_prices(client, token, input).await?,
        "service_health" => services::service_health(client, token, input).await?,
        "credit_balance" => {
            credit_balance(&read(client, token, account::CREDIT_SNAPSHOT_URL).await?)
        }
        "credit_history" => {
            credit_history(&read(client, token, account::CREDIT_SUMMARY_URL).await?)
        }
        "card_subscriptions" => {
            card_subscriptions(&read(client, token, account::SUBSCRIPTIONS_URL).await?)
        }
        "rpc_usage" => rpc_usage(&read(client, token, account::RPC_USAGE_URL).await?),
        "ai_usage" => ai_usage(&read(client, token, ai::USAGE_URL).await?),
        other => return Err(format!("there is no tool named {other}")),
    };
    serde_json::to_string(&value).map_err(|e| e.to_string())
}

/// A skill's text, by the name in `input`.
fn read_skill(input: &Value) -> Result<String, String> {
    let name = input
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    erpc_skills::get(name)
        .map(|skill| skill.body.to_owned())
        .ok_or_else(|| format!("there is no skill named {name:?}"))
}

/// Reads a reply, with the error as the model should read it.
pub(crate) async fn read(
    client: &AuthClient,
    token: &SecretString,
    url: &str,
) -> Result<Value, String> {
    account::read(client, token, url)
        .await
        .map_err(|e| match e {
            ApiError::Unauthorized => {
                "the session was refused; the user should run `erpc login`".to_owned()
            }
            other => format!("user-api did not answer: {other}"),
        })
}

/// The named fields of an object, in that order; the rest is left out.
pub(crate) fn pick(value: &Value, fields: &[&str]) -> Value {
    let mut out = Map::new();
    for field in fields {
        if let Some(v) = value.get(*field) {
            out.insert((*field).to_owned(), v.clone());
        }
    }
    Value::Object(out)
}

/// `pick` over each element of an array field.
fn pick_each(value: &Value, field: &str, fields: &[&str]) -> Value {
    Value::Array(
        value
            .get(field)
            .and_then(Value::as_array)
            .map(|items| items.iter().map(|item| pick(item, fields)).collect())
            .unwrap_or_default(),
    )
}

fn credit_balance(reply: &Value) -> Value {
    let m = reply.get("message").unwrap_or(&Value::Null);
    let mut out = pick(
        m,
        &[
            "alertLevel",
            "burnRateCentsPerHour",
            "timeToZeroHours",
            "quoteTimestamp",
        ],
    );
    out["balance"] = pick(
        m.get("balance").unwrap_or(&Value::Null),
        &[
            "balanceCents",
            "lifetimePurchasedCents",
            "lifetimeConsumedCents",
            "balanceUpdatedAtIso",
        ],
    );
    out["hourlyResources"] = pick_each(
        m,
        "hourlyResources",
        &[
            "productType",
            "userProductId",
            "productName",
            "status",
            "hourlyCents",
            "suspendedAtIso",
            "scheduledCancelAtIso",
            "endHourlyEligible",
            "endHourlyBlockedReason",
            "isBundleChild",
        ],
    );
    let monthly: Vec<Value> = m
        .get("creditMonthlyResources")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let mut entry = pick(
                        item,
                        &[
                            "productType",
                            "productName",
                            "status",
                            "monthlyCents",
                            "tier",
                        ],
                    );
                    entry["funding"] = pick(
                        item.get("funding").unwrap_or(&Value::Null),
                        &[
                            "state",
                            "nextDebitAtIso",
                            "requiredCents",
                            "shortfallCents",
                            "suspendedAtIso",
                        ],
                    );
                    entry
                })
                .collect()
        })
        .unwrap_or_default();
    out["creditMonthlyResources"] = Value::Array(monthly);
    let forecast = m.get("balanceForecast").unwrap_or(&Value::Null);
    let mut summary = pick(
        forecast,
        &[
            "state",
            "horizonEndIso",
            "horizonHourlyChargesCents",
            "horizonCreditMonthlyChargesCents",
            "horizonShortfallCents",
            "horizonTopUpCents",
        ],
    );
    summary["firstShortfall"] = forecast.get("firstShortfall").map_or(Value::Null, |s| {
        pick(s, &["source", "productType", "atIso", "shortfallCents"])
    });
    out["balanceForecast"] = summary;
    out
}

fn credit_history(reply: &Value) -> Value {
    pick(reply, &["bucket", "createdAtFrom", "createdAtTo", "data"])
}

fn card_subscriptions(reply: &Value) -> Value {
    let subscriptions: Vec<Value> = reply
        .get("message")
        .and_then(Value::as_array)
        .map(|subs| {
            subs.iter()
                .map(|sub| {
                    let mut out = pick(
                        sub,
                        &[
                            "status",
                            "cancel_at_period_end",
                            "cancel_at",
                            "current_period_end",
                            "trial_end",
                            "currency",
                        ],
                    );
                    let items: Vec<Value> = sub
                        .pointer("/items/data")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .map(|item| {
                                    let mut entry = pick(item, &["quantity", "current_period_end"]);
                                    let price = item.get("price").unwrap_or(&Value::Null);
                                    entry["price"] = pick(
                                        price,
                                        &["nickname", "lookup_key", "unit_amount", "currency"],
                                    );
                                    entry["price"]["interval"] = price
                                        .pointer("/recurring/interval")
                                        .cloned()
                                        .unwrap_or(Value::Null);
                                    entry
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    out["items"] = Value::Array(items);
                    out
                })
                .collect()
        })
        .unwrap_or_default();
    json!({ "subscriptions": subscriptions, "unit_amount": "in the currency's smallest unit (cents)" })
}

fn rpc_usage(reply: &Value) -> Value {
    let m = reply.get("message").unwrap_or(&Value::Null);
    let mut out = pick(m, &["yearMonth", "totalCount", "totalCredits"]);
    let methods = m.get("methods").and_then(Value::as_array);
    out["methodCount"] = json!(methods.map_or(0, Vec::len));
    out["topMethods"] = Value::Array(
        methods
            .map(|all| all.iter().take(RPC_METHODS).cloned().collect())
            .unwrap_or_default(),
    );
    out
}

fn ai_usage(reply: &Value) -> Value {
    pick(
        reply.get("message").unwrap_or(&Value::Null),
        &[
            "ai_plan",
            "remaining_tokens",
            "max_tokens",
            "consumed_tokens",
            "bonus",
            "pack_balance",
            "sub_quota",
            "sub_used",
            "next_reset_at",
            "suspended",
            "auto_buy_enabled",
        ],
    )
}

/// Now, in Unix seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use erpc_core::i18n::Lang;
    use serde_json::json;

    #[test]
    fn every_tool_is_defined_once_with_an_empty_input() {
        let defs = super::definitions();
        let mut names: Vec<&str> = defs.iter().filter_map(|d| d["name"].as_str()).collect();
        assert_eq!(names.len(), super::TOOLS.len());
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), super::TOOLS.len(), "names are unique");
        for def in &defs {
            assert_eq!(def["input_schema"]["type"], "object");
            assert!(
                def.get("type").is_none(),
                "a custom tool, never a server tool"
            );
        }
        assert_eq!(
            super::label("credit_balance", Lang::Ja),
            "クレジット残高を確認しています"
        );
        assert_eq!(super::label("credit_balance", Lang::Zh), "正在查看积分余额");
        assert_eq!(
            super::label("credit_balance", Lang::Ru),
            "Смотрю баланс кредитов"
        );
        assert_eq!(super::label("no_such_tool", Lang::En), "Looking it up");
    }

    #[test]
    fn a_skill_is_read_by_a_name_it_lists() {
        let defs = super::definitions();
        let def = defs
            .iter()
            .find(|d| d["name"] == "read_skill")
            .expect("defined");
        let names = def["input_schema"]["properties"]["name"]["enum"]
            .as_array()
            .expect("names");
        assert_eq!(names.len(), erpc_skills::all().len());
        let text = super::read_skill(&json!({ "name": "solana-validator-mainnet" }));
        assert!(text.is_ok_and(|t| t.starts_with("# ")));
        assert!(super::read_skill(&json!({ "name": "../base" })).is_err());
        assert!(super::read_skill(&json!({})).is_err());
    }

    #[test]
    fn only_the_named_fields_of_the_balance_reach_the_model() {
        let reply = json!({ "success": true, "message": {
            "balance": { "balanceCents": 1234, "stripeCustomerId": "cus_secret" },
            "hourlyResources": [{ "productName": "VPS", "hourlyCents": 5, "priceId": "price_x", "subscriptionItemId": "si_x" }],
            "creditMonthlyResources": [],
            "balanceForecast": { "state": "ok", "upcomingCharges": [{ "x": 1 }] },
            "alertLevel": "none",
            "meterPushFailures24h": 0,
        }});
        let out = super::credit_balance(&reply);
        let text = out.to_string();
        assert_eq!(out["balance"]["balanceCents"], 1234);
        assert_eq!(out["hourlyResources"][0]["productName"], "VPS");
        for hidden in [
            "cus_secret",
            "price_x",
            "si_x",
            "upcomingCharges",
            "meterPushFailures24h",
        ] {
            assert!(!text.contains(hidden), "{hidden} in {text}");
        }
    }

    #[test]
    fn a_subscription_passes_on_its_terms_and_nothing_from_stripe_besides() {
        let reply = json!({ "success": true, "message": [{
            "id": "sub_1", "customer": "cus_1", "status": "active",
            "metadata": { "password": "hunter2" },
            "default_payment_method": { "card": { "last4": "4242" } },
            "items": { "data": [{ "id": "si_1", "quantity": 1, "price": {
                "id": "price_1", "nickname": "ERPC Pro", "unit_amount": 4900, "currency": "eur",
                "recurring": { "interval": "month" } } }] },
        }]});
        let out = super::card_subscriptions(&reply);
        let text = out.to_string();
        let item = &out["subscriptions"][0]["items"][0];
        assert_eq!(item["price"]["nickname"], "ERPC Pro");
        assert_eq!(item["price"]["interval"], "month");
        for hidden in ["hunter2", "4242", "cus_1", "sub_1", "si_1", "price_1"] {
            assert!(!text.contains(hidden), "{hidden} in {text}");
        }
    }

    #[test]
    fn rpc_usage_keeps_the_top_methods_and_says_how_many_there_were() {
        let methods: Vec<_> = (0..40)
            .map(|n| json!({ "method": format!("m{n}"), "credits": 40 - n }))
            .collect();
        let reply = json!({ "message": { "yearMonth": "2026-10", "totalCount": 9, "totalCredits": 8, "methods": methods }});
        let out = super::rpc_usage(&reply);
        assert_eq!(out["methodCount"], 40);
        assert_eq!(
            out["topMethods"].as_array().map(Vec::len),
            Some(super::RPC_METHODS)
        );
        assert_eq!(out["topMethods"][0]["method"], "m0");
    }
}
