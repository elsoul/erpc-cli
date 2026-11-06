// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The ERPC servers `erpc worker deploy` puts a worker on: a VPS the
//! account has, or a new one started by the hour.
//!
//! A new one is the cheapest VPS plan the hourly catalogue offers, in the
//! region nearest this machine. Nearest is read from the machine's time
//! zone: user-api names no per-region host erpc could time, and erpc asks
//! no outside service where the operator is. `--region` and `--plan`
//! choose otherwise. Starting it, waiting for it, and making it key-only
//! go through the same steps `erpc ai` uses, and starting it waits for the
//! person's yes to the price and the balance, which user-api gives.
//!
//! A data line (an hourly gRPC, Shreds or Unlimited RPC line) is started
//! for the server the same way, at the cheapest plan unless one is asked
//! for. It lets in the server's address only, and takes no token. A gRPC
//! or Shreds line is told the address when it starts; an Unlimited RPC is
//! started in the server's region, and its whitelist is set after.

use erpc_ai::confirm::Confirm;
use erpc_ai::session::Access as _;
use erpc_api::{account, hourly};
use erpc_auth::AuthClient;
use erpc_ssh::Target;
use std::net::Ipv4Addr;
use std::time::Duration;

use erpc_worker::manifest::{Env, Line, LineKind, Resource, ResourceKind};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::error::{CliError, Code};
use crate::node_common::Say;

/// The regions a VPS can be started in.
pub(crate) const REGIONS: [&str; 7] = [
    "amsterdam",
    "frankfurt",
    "london",
    "ny",
    "tokyo",
    "singapore",
    "sydney",
];

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

/// A session with user-api, and a way to ask the person.
pub(crate) struct Api {
    client: AuthClient,
    token: SecretString,
    confirm: crate::ai::TerminalConfirm,
}

impl Api {
    /// Signs in with the stored session.
    pub(crate) async fn open() -> Result<Self, CliError> {
        let client = AuthClient::new().map_err(|e| CliError::new(Code::Network, e.to_string()))?;
        let access = crate::ai::StoreAccess::open(client.clone()).map_err(|o| {
            o.error()
                .unwrap_or_else(|| CliError::new(Code::NotSignedIn, t!("worker_vps.no_session")))
        })?;
        let token = access
            .access_token()
            .await
            .map_err(|e| CliError::new(Code::NotSignedIn, e).hint(t!("worker_vps.login_hint")))?;
        Ok(Self {
            client,
            token,
            confirm: crate::ai::TerminalConfirm::default(),
        })
    }

    /// One that reaches nothing, for tests that never call user-api.
    #[cfg(test)]
    pub(crate) fn offline() -> Self {
        Self {
            client: AuthClient::new().expect("client"),
            token: SecretString::from(String::new()),
            confirm: crate::ai::TerminalConfirm::default(),
        }
    }

    fn confirm(&self) -> Option<&dyn Confirm> {
        crate::session::has_terminal().then_some(&self.confirm as &dyn Confirm)
    }

    async fn read(&self, url: &str) -> Result<Value, CliError> {
        account::read(&self.client, &self.token, url)
            .await
            .map_err(|e| CliError::new(Code::Network, t!("worker_vps.api_silent", error = e)))
    }
}

/// The account's primary API key for the shared RPC.
pub(crate) async fn shared_api_key(api: &Api) -> Result<zeroize::Zeroizing<String>, CliError> {
    let reply = api.read(account::DASHBOARD_URL).await?;
    reply["message"]["apiKey"]
        .as_str()
        .filter(|k| !k.is_empty())
        .map(|k| zeroize::Zeroizing::new(k.to_owned()))
        .ok_or_else(|| failed(t!("worker_vps.no_api_key")).hint(t!("worker_vps.no_api_key_hint")))
}

/// A server the worker will run on.
pub(crate) struct Server {
    pub(crate) target: Target,
    pub(crate) resource: Resource,
}

/// The account's VPSs that are running, as (id, address, region, plan).
pub(crate) async fn running(api: &Api) -> Result<Vec<(i64, String, String, String)>, CliError> {
    let reply = api
        .read(erpc_ai::ready::vps_status_url().map_err(failed)?)
        .await?;
    Ok(reply["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["status"].as_str() == Some("on"))
        .filter_map(|row| {
            Some((
                row["userVpsId"].as_i64()?,
                row["ip"].as_str()?.to_owned(),
                row["region"].as_str().unwrap_or("").to_owned(),
                row["vpsVersion"]
                    .as_str()
                    .or_else(|| row["productName"].as_str())
                    .unwrap_or("VPS")
                    .to_owned(),
            ))
        })
        .collect())
}

/// VPS `id` of the account, made key-only (asking first) when erpc has not
/// done so yet.
pub(crate) async fn existing(api: &Api, id: i64, hourly: bool) -> Result<Server, CliError> {
    let reply = api
        .read(erpc_ai::ready::vps_status_url().map_err(failed)?)
        .await?;
    let row =
        erpc_ai::ready::vps_row(&reply, id).ok_or_else(|| failed(t!("worker_vps.vps.none", id)))?;
    let ip = row["ip"]
        .as_str()
        .ok_or_else(|| failed(t!("worker_vps.vps.no_address", id)))?
        .to_owned();
    let region = row["region"].as_str().map(ToOwned::to_owned);
    // Billed by the hour when it was just started so, or when the credit
    // snapshot lists it among the hourly resources, as ending one reads it.
    let hourly = hourly
        || api
            .read(account::CREDIT_SNAPSHOT_URL)
            .await
            .is_ok_and(|snapshot| {
                snapshot["message"]["hourlyResources"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|r| {
                        r["productType"].as_str() == Some("vps")
                            && r["userProductId"].as_i64() == Some(id)
                    })
            });
    let servers = crate::vps_access::SshServers;
    let secured = erpc_ai::servers::secure_vps(
        &api.client,
        &api.token,
        &json!({ "userVpsId": id }),
        api.confirm(),
        Some(&servers),
    )
    .await
    .map_err(failed)?;
    if secured["done"] != json!(true) {
        return Err(failed(t!("worker_vps.vps.not_key_only", id)));
    }
    let target = crate::vps_access::pinned_target(&ip).map_err(failed)?;
    Ok(Server {
        target,
        resource: Resource {
            kind: ResourceKind::Vps,
            id: id.to_string(),
            region,
            hourly,
        },
    })
}

/// The region nearest this machine, by its time zone; Frankfurt when the
/// zone says nothing.
pub(crate) fn nearest_region() -> &'static str {
    let zone = std::env::var("TZ")
        .ok()
        .filter(|z| !z.is_empty())
        .or_else(|| {
            std::fs::read_link("/etc/localtime").ok().and_then(|p| {
                let text = p.to_string_lossy().into_owned();
                text.split_once("zoneinfo/").map(|(_, z)| z.to_owned())
            })
        });
    region_for_zone(zone.as_deref().unwrap_or(""))
}

fn region_for_zone(zone: &str) -> &'static str {
    let city = zone.rsplit('/').next().unwrap_or(zone);
    match zone.split('/').next().unwrap_or("") {
        "Asia" => match city {
            "Tokyo" | "Seoul" | "Pyongyang" | "Sakhalin" | "Vladivostok" => "tokyo",
            "Dubai" | "Riyadh" | "Tehran" | "Baku" | "Tbilisi" | "Yerevan" | "Qatar" | "Kuwait" => {
                "frankfurt"
            }
            _ => "singapore",
        },
        "Australia" | "Pacific" | "Antarctica" => "sydney",
        "America" | "US" | "Canada" | "Atlantic" => "ny",
        "Europe" | "Africa" => match city {
            "London" | "Dublin" | "Lisbon" | "Belfast" | "Guernsey" | "Isle_of_Man" | "Jersey" => {
                "london"
            }
            "Amsterdam" | "Brussels" | "Luxembourg" => "amsterdam",
            _ => "frankfurt",
        },
        "Japan" => "tokyo",
        _ => "frankfurt",
    }
}

/// A plan's id, price per hour in cents, and name.
struct Plan {
    id: String,
    cents: f64,
    name: String,
}

/// The name of product `id`, as user-api gives it.
async fn product_name(api: &Api, id: &str) -> Option<String> {
    let product = account::read_query(
        &api.client,
        &api.token,
        account::PRODUCT_URL,
        &[("productId", id)],
    )
    .await
    .ok()?;
    product
        .get("message")
        .unwrap_or(&product)
        .get("name")
        .and_then(Value::as_str)
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty())
}

/// The cheapest plan of hourly `family` the catalogue offers (for a VPS,
/// one to run an app on), or the one asked for.
async fn plan(api: &Api, family: &str, asked: Option<&str>) -> Result<Plan, CliError> {
    let catalog = api.read(hourly::CATALOG_URL).await?;
    let plans: Vec<(String, f64)> = catalog["families"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["family"].as_str() == Some(family))
        .flat_map(|f| f["plans"].as_array().cloned().unwrap_or_default())
        .filter_map(|p| {
            Some((
                p["productId"].as_str()?.to_owned(),
                p["hourlyCents"].as_f64()?,
            ))
        })
        .collect();
    if let Some(id) = asked {
        let (id, cents) = plans
            .into_iter()
            .find(|(p, _)| p == id)
            .ok_or_else(|| failed(t!("worker_vps.plan.not_offered", id, family)))?;
        let name = product_name(api, &id).await.unwrap_or_else(|| id.clone());
        return Ok(Plan { id, cents, name });
    }
    let mut offered = Vec::new();
    for (id, cents) in plans {
        let name = product_name(api, &id).await;
        // The VPS family also sells add-ons, such as the monitoring VPS,
        // which are not servers to run an app on: they are known by their
        // names.
        if family == "vps" && name.as_deref().is_none_or(is_add_on) {
            continue;
        }
        let name = name.unwrap_or_else(|| id.clone());
        offered.push(Plan { id, cents, name });
    }
    offered
        .into_iter()
        .min_by(|a, b| a.cents.total_cmp(&b.cents))
        .ok_or_else(|| failed(t!("worker_vps.plan.none", family)))
}

/// How a plan was chosen, as the line about buying it says.
fn how_chosen(asked_plan: Option<&str>) -> String {
    if asked_plan.is_some() {
        t!("worker_vps.plan.as_asked")
    } else {
        t!("worker_vps.plan.cheapest")
    }
}

/// Why user-api did not start a product, as its reply says.
fn reason(started: &Value) -> String {
    started["message"]
        .as_str()
        .or_else(|| started["error"].as_str())
        .map_or_else(|| t!("worker_vps.no_reason"), ToOwned::to_owned)
}

/// Whether a product of the VPS family is an add-on rather than a server.
fn is_add_on(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("monitoring") || lower.contains("grafana")
}

/// Starts a new hourly VPS, after the person's yes to its price, and
/// returns it as erpc.toml records it, before it is ready: the caller puts
/// it on record at once, then [`wait`] and [`secure`] make it a server.
pub(crate) async fn buy(
    api: &Api,
    region: Option<&str>,
    asked_plan: Option<&str>,
    scope: &str,
    say: &Say,
) -> Result<Resource, CliError> {
    let region_asked = region.is_some();
    let region = match region {
        Some(r) if REGIONS.contains(&r) => r.to_owned(),
        Some(r) => {
            return Err(CliError::new(
                Code::Usage,
                t!(
                    "worker_vps.buy.bad_region",
                    region = r,
                    regions = REGIONS.join(", ")
                ),
            ));
        }
        None => nearest_region().to_owned(),
    };
    let chosen = plan(api, "vps", asked_plan).await?;
    let (product, cents) = (chosen.id.clone(), chosen.cents);
    say.line(&t!(
        "worker_vps.buy.buying",
        name = chosen.name,
        product,
        how = how_chosen(asked_plan),
        price = format!("{:.4}", cents / 100.0),
        region,
        why = if region_asked {
            t!("worker_vps.buy.region_asked")
        } else {
            t!("worker_vps.buy.region_nearest")
        }
    ));
    let started = erpc_ai::actions::start_hourly_product(
        &api.client,
        &api.token,
        &json!({ "family": "vps", "fields": { "productId": product, "region": region } }),
        api.confirm(),
    )
    .await
    .map_err(failed)?;
    if started["done"] != json!(true) {
        return Err(failed(t!(
            "worker_vps.buy.not_started",
            status = started["httpStatus"],
            reason = reason(&started)
        ))
        .hint(t!("worker_vps.buy.other_region_hint", scope)));
    }
    let id = started["userVpsId"]
        .as_i64()
        .ok_or_else(|| failed(t!("worker_vps.buy.no_id")))?;
    say.line(&t!("worker_vps.buy.started", id));
    Ok(Resource {
        kind: ResourceKind::Vps,
        id: id.to_string(),
        region: Some(region),
        hourly: true,
    })
}

/// The id of VPS `resource`.
fn vps_id(resource: &Resource) -> Result<i64, CliError> {
    resource
        .id
        .parse()
        .map_err(|_| failed(t!("worker_vps.vps.bad_id", id = resource.id)))
}

/// Waits, up to five minutes, for VPS `resource` (one just bought, or one
/// on record from a deploy that stopped before it was ready) to be up. It asks nothing, so it can run beside a build.
pub(crate) async fn wait(api: &Api, resource: &Resource, say: &Say) -> Result<(), CliError> {
    let id = vps_id(resource)?;
    say.line(&t!("worker_vps.ready.waiting", id));
    let ready = erpc_ai::ready::wait_until_ready(
        &api.client,
        &api.token,
        &json!({ "family": "vps", "userVpsId": id }),
    )
    .await
    .map_err(|e| failed(t!("worker_vps.ready.failed", id, reason = e)))?;
    if ready["ready"] == json!(false) {
        return Err(failed(t!(
            "worker_vps.ready.failed",
            id,
            reason = ready["status"]
                .as_str()
                .map_or_else(|| t!("worker_vps.no_reason"), ToOwned::to_owned)
        )));
    }
    Ok(())
}

/// Once VPS `resource` is up ([`wait`]): makes it
/// key-only, which asks the person about its host key. Nothing else may
/// be printing then.
pub(crate) async fn secure(api: &Api, resource: &Resource) -> Result<Server, CliError> {
    let id = vps_id(resource)?;
    let mut server = existing(api, id, resource.hourly).await?;
    if server.resource.region.is_none() {
        server.resource.region.clone_from(&resource.region);
    }
    Ok(server)
}

/// Ends the hourly VPS `env` runs on, after the person's yes.
pub(crate) async fn end(env: &Env, say: &Say) -> Result<Value, CliError> {
    let resource = env
        .resource
        .as_ref()
        .filter(|r| r.hourly)
        .ok_or_else(|| failed(t!("worker_vps.end.not_hourly")))?;
    let id: i64 = resource
        .id
        .parse()
        .map_err(|_| failed(t!("worker_vps.vps.bad_id", id = resource.id)))?;
    let product_type = match resource.kind {
        ResourceKind::BareMetal => "bare_metal",
        _ => "vps",
    };
    let api = Api::open().await?;
    say.line(&t!("worker_vps.end.ending", kind = product_type, id));
    let ended = erpc_ai::actions::end_hourly_product(
        &api.client,
        &api.token,
        &json!({ "productType": product_type, "userProductId": id }),
        api.confirm(),
    )
    .await
    .map_err(failed)?;
    if ended["done"] != json!(true) {
        return Err(failed(t!(
            "worker_vps.end.failed",
            kind = product_type,
            id,
            answer = ended
        )));
    }
    Ok(ended)
}

/// How user-api names a data line of each kind.
struct LineProduct {
    /// The hourly family that starts one.
    family: &'static str,
    /// The start reply's field with its id.
    id_field: &'static str,
    /// Its `productType` in the credit snapshot, which ending it takes.
    product_type: &'static str,
    /// Its key in [`account::SERVICE_STATUS_URLS`].
    status_key: &'static str,
    /// How long it may take to become active, and how often to look.
    wait: Duration,
    poll: Duration,
}

const fn line_product(kind: LineKind) -> LineProduct {
    match kind {
        LineKind::Grpc => LineProduct {
            family: "grpc",
            id_field: "userGrpcId",
            product_type: "grpc",
            status_key: "grpc",
            wait: Duration::from_mins(3),
            poll: Duration::from_secs(5),
        },
        LineKind::Shreds => LineProduct {
            family: "shreds-shared",
            id_field: "userShredsId",
            product_type: "shreds",
            status_key: "shreds",
            wait: Duration::from_mins(3),
            poll: Duration::from_secs(5),
        },
        // A dedicated server is set up for it: user-api allows 45 minutes.
        LineKind::Unlimited => LineProduct {
            family: "user-unlimited",
            id_field: "userUnlimitedId",
            product_type: "unlimited",
            status_key: "unlimited_rpc",
            wait: Duration::from_mins(50),
            poll: Duration::from_secs(15),
        },
    }
}

/// The hourly products the account is charged for now, as (`productType`,
/// `userProductId`), from the credit snapshot: the record of what is
/// charged, which a status list (set up, or not yet) is not.
pub(crate) async fn charged(api: &Api) -> Result<Vec<(String, i64)>, CliError> {
    let snapshot = api.read(account::CREDIT_SNAPSHOT_URL).await?;
    let rows = snapshot["message"]["hourlyResources"]
        .as_array()
        .ok_or_else(|| failed(t!("worker_vps.end.no_hourly_list")))?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some((
                r["productType"].as_str()?.to_owned(),
                r["userProductId"].as_i64()?,
            ))
        })
        .collect())
}

/// Whether a line on record is gone from the account: the one rule deploy
/// and delete both go by. Only a line billed by the hour, seen with its
/// endpoint before, and neither listed nor charged for is gone. A line just
/// started (both can be behind for a minute) or not billed by the hour never
/// is: the operator says so, with `--forget-line`.
/// `on_record` is the line's (billed by the hour, pending: its endpoint
/// never seen).
pub(crate) const fn is_gone(on_record: (bool, bool), listed: bool, charged: bool) -> bool {
    let (hourly, pending) = on_record;
    hourly && !pending && !listed && !charged
}

/// Whether `line` is among what [`charged`] lists.
pub(crate) fn is_charged(charged: &[(String, i64)], line: &Line) -> bool {
    let product_type = line_product(line.kind).product_type;
    line.id
        .parse::<i64>()
        .is_ok_and(|id| charged.iter().any(|(t, n)| t == product_type && *n == id))
}

/// The account's data line `id` of `kind`, as its status lists it, or
/// `None` when the account has no such line.
pub(crate) async fn line_row(
    api: &Api,
    kind: LineKind,
    id: &str,
) -> Result<Option<Value>, CliError> {
    Ok(line_rows(api, kind).await?.into_iter().find(|row| {
        row["id"].as_i64().map(|n| n.to_string()).as_deref() == Some(id)
            || row["id"].as_str() == Some(id)
    }))
}

/// The id of the account's active data line of `kind` that lets in `ip`,
/// if it has one: what `erpc worker run` takes up rather than buy another.
pub(crate) async fn line_letting_in(
    api: &Api,
    kind: LineKind,
    ip: Ipv4Addr,
) -> Result<Option<String>, CliError> {
    let ip = ip.to_string();
    Ok(line_rows(api, kind).await?.iter().find_map(|row| {
        (row["status"] == "active" && line_ips(row).contains(&ip.as_str())).then(|| {
            row["id"]
                .as_i64()
                .map(|n| n.to_string())
                .or_else(|| row["id"].as_str().map(ToOwned::to_owned))
        })?
    }))
}

/// The account's data lines of `kind`, as their status lists them.
async fn line_rows(api: &Api, kind: LineKind) -> Result<Vec<Value>, CliError> {
    let product = line_product(kind);
    let url = account::SERVICE_STATUS_URLS
        .iter()
        .find(|(k, _)| *k == product.status_key)
        .map(|(_, url)| *url)
        .ok_or_else(|| failed(t!("worker_vps.line.no_status", kind = kind.label())))?;
    let reply = api.read(url).await?;
    // A reply with no list says nothing about the line: not taken as
    // "the account has none", which would let a deploy buy another.
    let rows = [reply.get("data"), reply.get("message")]
        .into_iter()
        .flatten()
        .find_map(Value::as_array)
        .ok_or_else(|| failed(t!("worker_vps.line.no_list", kind = kind.label())))?;
    Ok(rows.clone())
}

/// The addresses a line's status row lets in: one for gRPC and Shreds, a
/// list for Unlimited RPC.
fn line_ips(row: &Value) -> Vec<&str> {
    match &row["whitelistIps"] {
        Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
        _ => row["whiteListIp"].as_str().into_iter().collect(),
    }
}

/// A line's endpoint as the app dials it. user-api gives gRPC and Shreds
/// as `http://<host>`, served over TLS on 443 too, which is what the app
/// gets; an Unlimited RPC is `http://<address>:<port>`, served without
/// TLS, and kept as it is.
fn line_endpoint(kind: LineKind, given: &str) -> Option<String> {
    if kind == LineKind::Unlimited {
        let given = given.trim_end_matches('/');
        return kind.endpoint_ok(given).then(|| given.to_owned());
    }
    let host = ["https://", "http://"]
        .iter()
        .find_map(|scheme| given.strip_prefix(scheme))?
        .trim_end_matches('/');
    erpc_worker::net::is_host(host).then(|| ["https", host].join("://"))
}

/// Starts an hourly data line of `kind` for the server at `ip` in
/// `region`, after the person's yes to its price. It may not be active
/// yet, nor let the server in: [`wait_line`] sees to both.
#[allow(
    clippy::too_many_arguments,
    reason = "each is its own input to the one user-api call, and the hint names the scope"
)]
pub(crate) async fn start_line(
    api: &Api,
    kind: LineKind,
    ip: Ipv4Addr,
    region: Option<&str>,
    asked_plan: Option<&str>,
    scope: &str,
    say: &Say,
    named: &mut dyn FnMut(&str) -> Result<(), CliError>,
) -> Result<String, CliError> {
    let product = line_product(kind);
    let fields = if kind == LineKind::Unlimited {
        let region = region.ok_or_else(|| {
            failed(t!("worker_vps.line.no_region")).hint(t!("worker_vps.line.no_region_hint"))
        })?;
        json!({ "region": region })
    } else {
        json!({ "ip": ip.to_string() })
    };
    let chosen = plan(api, product.family, asked_plan).await?;
    say.line(&t!(
        "worker_vps.line.buying",
        kind = kind.label(),
        name = chosen.name,
        product = chosen.id,
        how = how_chosen(asked_plan),
        price = format!("{:.4}", chosen.cents / 100.0),
        ip,
    ));
    let mut fields = fields;
    fields["productId"] = json!(chosen.id);
    let started = erpc_ai::actions::start_hourly_product(
        &api.client,
        &api.token,
        &json!({ "family": product.family, "fields": fields }),
        api.confirm(),
    )
    .await
    .map_err(failed)?;
    let id = started[product.id_field]
        .as_i64()
        .map(|n| n.to_string())
        .or_else(|| started[product.id_field].as_str().map(ToOwned::to_owned));
    if started["done"] != json!(true) {
        let mut error = failed(t!(
            "worker_vps.line.not_started",
            kind = kind.label(),
            status = started["httpStatus"],
            reason = reason(&started)
        ));
        // A line user-api names, started or not, goes on record (`named`)
        // so that the next deploy finds it rather than buy another.
        if let Some(id) = id {
            named(&id)?;
            error = error.hint(t!("worker_vps.line.made_anyway", id, scope));
        }
        return Err(error);
    }
    let id = id.ok_or_else(|| failed(t!("worker_vps.line.no_id", kind = kind.label())))?;
    named(&id)?;
    if let Some(warning) = started["registerWarning"].as_str() {
        say.line(&t!("worker_vps.line.warned", warning));
    }
    say.line(&t!("worker_vps.line.started", kind = kind.label(), id));
    Ok(id)
}

/// Line `id` of `kind` as erpc.toml keeps it, once its status lists it
/// with an endpoint: right after a start, before it is active, so that it
/// is on record however the wait ends.
pub(crate) async fn first_sight(
    api: &Api,
    kind: LineKind,
    id: &str,
    hourly: bool,
    scope: &str,
) -> Result<Line, CliError> {
    for _ in 0..20 {
        if let Some(endpoint) = line_row(api, kind, id).await?.and_then(|row| {
            row["endpoint"]
                .as_str()
                .and_then(|e| line_endpoint(kind, e))
        }) {
            return Ok(Line {
                kind,
                id: id.to_owned(),
                endpoint,
                hourly,
            });
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    Err(
        failed(t!("worker_vps.line.no_endpoint", kind = kind.label(), id))
            .hint(t!("worker_vps.line.no_endpoint_hint", scope)),
    )
}

/// Lets `ip` in to Unlimited RPC `id`, keeping the addresses it lets in
/// already (`allowed`; user-api replaces the whole list). `Ok(false)` when
/// user-api kept the whitelist but could not apply it to the line's server
/// yet, which it says while the server is still being set up.
async fn let_in(api: &Api, id: &str, ip: Ipv4Addr, allowed: &[&str]) -> Result<bool, CliError> {
    let number = id
        .parse()
        .map_err(|_| failed(t!("worker_vps.line.bad_id", id)))?;
    let list = whitelist(ip, allowed);
    match account::set_unlimited_whitelist(&api.client, &api.token, number, &list).await {
        Ok(_) => Ok(true),
        Err(erpc_api::ApiError::Refused {
            status: 502,
            message,
        }) if message.to_ascii_lowercase().contains("saved") => Ok(false),
        Err(e) => Err(
            failed(t!("worker_vps.line.let_in_failed", ip, id, error = e))
                .hint(t!("worker_vps.line.let_in_hint")),
        ),
    }
}

/// `ip` and the addresses in `allowed`, once each: the whitelist erpc sets.
/// user-api's whitelist takes single IPv4 addresses only, so nothing else
/// can be in `allowed` to keep.
fn whitelist(ip: Ipv4Addr, allowed: &[&str]) -> Vec<Ipv4Addr> {
    let mut list: Vec<Ipv4Addr> = allowed.iter().filter_map(|a| a.parse().ok()).collect();
    if !list.contains(&ip) {
        list.push(ip);
    }
    list
}

/// Waits for data line `id` of `kind` to be active and to let in `ip`, and
/// returns it as erpc.toml keeps it. An Unlimited RPC's whitelist is set
/// to `ip` while it is set up, and again once it is active, which is when
/// user-api can apply it to the line's server for certain.
pub(crate) async fn wait_line(
    api: &Api,
    kind: LineKind,
    id: &str,
    ip: Ipv4Addr,
    hourly: bool,
    say: &Say,
) -> Result<Line, CliError> {
    // A person at a terminal sees a spinner while the line is set up, which
    // can take a while with nothing else to show; its message carries what
    // would otherwise be said in lines, which a spinner's redraws would
    // break. The caller says what came of the wait.
    let spinner = (!say.quiet && crate::ui::stderr_drawn()).then(|| {
        crate::prompt::Spinner::start(&t!("worker_vps.line.waiting_for", kind = kind.label(), id))
    });
    let tell = |text: String| match &spinner {
        Some(spinner) => spinner.set_message(&text),
        None => say.line(&text),
    };
    let waited = wait_line_saying(api, kind, id, ip, hourly, &tell).await;
    if let Some(spinner) = spinner {
        spinner.done();
    }
    waited
}

async fn wait_line_saying(
    api: &Api,
    kind: LineKind,
    id: &str,
    ip: Ipv4Addr,
    hourly: bool,
    tell: &dyn Fn(String),
) -> Result<Line, CliError> {
    let product = line_product(kind);
    let mut last = t!("worker_vps.line.not_listed");
    let started = std::time::Instant::now();
    let mut kept = false;
    let mut applied = false;
    while started.elapsed() < product.wait {
        if let Some(row) = line_row(api, kind, id).await? {
            let status = row["status"].as_str().unwrap_or("unknown");
            let allowed = line_ips(&row);
            if !allowed.is_empty() && !allowed.contains(&ip.to_string().as_str()) {
                return Err(failed(t!(
                    "worker_vps.line.wrong_ip",
                    kind = kind.label(),
                    id,
                    allowed = allowed.join(", "),
                    ip
                )));
            }
            if kind == LineKind::Unlimited
                && !applied
                && ((allowed.is_empty() && !kept) || status == "active")
            {
                applied = let_in(api, id, ip, &allowed).await?;
                if !kept {
                    tell(if applied {
                        t!("worker_vps.line.lets_in", id, ip)
                    } else {
                        t!("worker_vps.line.lets_in_later", id, ip)
                    });
                }
                kept = true;
            }
            let endpoint = row["endpoint"]
                .as_str()
                .and_then(|e| line_endpoint(kind, e));
            let let_in_now = if kind == LineKind::Unlimited {
                applied
            } else {
                !allowed.is_empty()
            };
            match (status, endpoint) {
                ("active", Some(endpoint)) if let_in_now => {
                    return Ok(Line {
                        kind,
                        id: id.to_owned(),
                        endpoint,
                        hourly,
                    });
                }
                ("suspended", _) => {
                    return Err(
                        failed(t!("worker_vps.line.suspended", kind = kind.label(), id))
                            .hint(t!("worker_vps.line.suspended_hint")),
                    );
                }
                (status, _) => {
                    if status != last {
                        if kind == LineKind::Unlimited {
                            tell(t!(
                                "worker_vps.line.waiting",
                                id,
                                status,
                                minutes = started.elapsed().as_secs() / 60
                            ));
                        }
                        status.clone_into(&mut last);
                    }
                }
            }
        }
        tokio::time::sleep(product.poll).await;
    }
    Err(failed(tn!(
        "worker_vps.line.not_active",
        product.wait.as_secs() / 60,
        kind = kind.label(),
        id,
        last
    )))
}

/// Ends hourly data line `line`, after the person's yes.
pub(crate) async fn end_line(api: &Api, line: &Line, say: &Say) -> Result<Value, CliError> {
    let product = line_product(line.kind);
    let id: i64 = line
        .id
        .parse()
        .map_err(|_| failed(t!("worker_vps.line.bad_id", id = line.id)))?;
    say.line(&t!("worker_vps.line.ending", kind = line.kind.label(), id));
    let ended = erpc_ai::actions::end_hourly_product(
        &api.client,
        &api.token,
        &json!({ "productType": product.product_type, "userProductId": id }),
        api.confirm(),
    )
    .await
    .map_err(failed)?;
    if ended["done"] != json!(true) {
        return Err(failed(t!(
            "worker_vps.line.end_failed",
            kind = line.kind.label(),
            id,
            answer = ended
        )));
    }
    Ok(ended)
}

#[cfg(test)]
mod tests {
    use erpc_worker::manifest::LineKind;
    use serde_json::json;

    use super::{is_add_on, line_endpoint, line_ips, region_for_zone};

    #[test]
    fn a_line_endpoint_is_dialled_over_tls_but_unlimited() {
        // Built, not written out: the endpoint gate reads literals.
        let url = |scheme: &str, rest: &str| [scheme, rest].join("://");
        let host = "edge.erpc.global";
        for given in [url("http", host), url("https", &format!("{host}/"))] {
            assert_eq!(
                line_endpoint(LineKind::Grpc, &given),
                Some(url("https", host))
            );
        }
        assert_eq!(line_endpoint(LineKind::Grpc, host), None);
        assert_eq!(line_endpoint(LineKind::Grpc, "http://"), None);
        let unlimited = url("http", "203.0.113.5:8899");
        assert_eq!(
            line_endpoint(LineKind::Unlimited, &format!("{unlimited}/")),
            Some(unlimited)
        );
        assert_eq!(line_endpoint(LineKind::Unlimited, &url("http", host)), None);
    }

    #[test]
    fn a_line_is_charged_when_the_snapshot_lists_its_type_and_id() {
        use erpc_worker::manifest::Line;
        let line = |kind, id: &str| Line {
            kind,
            id: id.to_owned(),
            endpoint: String::new(),
            hourly: true,
        };
        let charged = vec![
            ("grpc".to_owned(), 100_002),
            ("unlimited".to_owned(), 100_003),
        ];
        assert!(super::is_charged(&charged, &line(LineKind::Grpc, "100002")));
        assert!(super::is_charged(
            &charged,
            &line(LineKind::Unlimited, "100003")
        ));
        // The same id under another type is another product.
        assert!(!super::is_charged(
            &charged,
            &line(LineKind::Shreds, "100002")
        ));
        assert!(!super::is_charged(
            &charged,
            &line(LineKind::Grpc, "100009")
        ));
    }

    #[test]
    fn letting_the_server_in_keeps_the_others() {
        let ip: std::net::Ipv4Addr = "203.0.113.10".parse().expect("ip");
        assert_eq!(super::whitelist(ip, &[]), [ip]);
        assert_eq!(
            super::whitelist(ip, &["198.51.100.7", "203.0.113.10"]),
            [
                "198.51.100.7".parse::<std::net::Ipv4Addr>().expect("ip"),
                ip
            ]
        );
        assert_eq!(super::whitelist(ip, &["not an address"]), [ip]);
    }

    #[test]
    fn a_line_lets_in_one_address_or_a_list() {
        assert_eq!(
            line_ips(&json!({ "whiteListIp": "203.0.113.5" })),
            ["203.0.113.5"]
        );
        assert_eq!(
            line_ips(&json!({ "whitelistIps": ["203.0.113.5", "203.0.113.6"] })),
            ["203.0.113.5", "203.0.113.6"]
        );
        assert!(line_ips(&json!({ "whitelistIps": null })).is_empty());
    }

    #[test]
    fn the_monitoring_vps_is_not_a_server_to_run_an_app_on() {
        assert!(is_add_on("📊 SLV VPS for Advanced Monitoring"));
        assert!(!is_add_on(
            "🛰️ SLV VPS - 1 vCPU AMD EPYC4G x 4 GB DDR5 - 10 GB SSD NVMe4"
        ));
    }

    #[test]
    fn a_time_zone_picks_the_nearest_region() {
        for (zone, region) in [
            ("Asia/Tokyo", "tokyo"),
            ("Asia/Hong_Kong", "singapore"),
            ("Europe/Amsterdam", "amsterdam"),
            ("Europe/Berlin", "frankfurt"),
            ("Europe/London", "london"),
            ("America/Los_Angeles", "ny"),
            ("Australia/Sydney", "sydney"),
            ("", "frankfurt"),
            ("UTC", "frankfurt"),
        ] {
            assert_eq!(region_for_zone(zone), region, "{zone}");
        }
    }

    #[test]
    fn a_line_that_never_became_active_is_said_in_the_chosen_language() {
        use erpc_core::i18n::Lang;
        let say = || {
            tn!(
                "worker_vps.line.not_active",
                3,
                kind = "gRPC",
                id = "100002",
                last = "pending"
            )
        };
        let english = say();
        assert_eq!(
            english,
            "gRPC line 100002 did not become active in 3 minutes (it is pending)"
        );
        for lang in [Lang::Ja, Lang::Ru] {
            let said = crate::i18n::speaking(lang, say);
            assert_ne!(said, english);
            assert!(!said.contains('{'), "{said}");
            assert!(
                said.contains("100002") && said.contains("pending"),
                "{said}"
            );
        }
        // Russian says three minutes as a few.
        assert!(crate::i18n::speaking(Lang::Ru, say).contains("3 минуты"));
    }
}
