// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The tools about what ERPC sells and what the account runs: the server
//! catalogue, the servers in stock by region, plan prices, the account's
//! own services, and how each region has been answering.
//!
//! As everywhere in [`crate::tools`], each passes on only the fields it
//! names. The service replies hold root passwords, IP whitelists,
//! endpoints with keys in them and Stripe ids; none of those is named.
//! The addresses that are named: a VPS's own (`ip`, where the person logs
//! in), and a UDP Forwarding line's `destination` (the user's server and
//! port it sends to) and `sourceIp`/`sourceIps` (ERPC's addresses it sends
//! from, which that server's firewall has to let in).

use erpc_api::ApiError;
use erpc_api::account::{self, Server};
use erpc_auth::AuthClient;
use secrecy::SecretString;
use serde_json::{Map, Value, json};

use crate::tools::{pick, read};

/// The regions a stock search may be narrowed to.
pub const REGIONS: &[&str] = &[
    "amsterdam",
    "frankfurt",
    "london",
    "dublin",
    "stockholm",
    "ny",
    "chicago",
    "saltlakecity",
    "losangeles",
    "tokyo",
    "singapore",
    "hongkong",
    "sydney",
];

/// The most pages of stock read: enough for every server in stock today,
/// and a bound if that grows.
const STOCK_PAGES: usize = 10;

/// The most products named in one answer about plan prices; each name is
/// one more request.
const PLAN_NAMES: usize = 12;

/// The longest spec text passed on for a product.
const SPEC_CHARS: usize = 500;

/// The string `field` of the tool's input.
fn arg<'a>(input: &'a Value, field: &str) -> Option<&'a str> {
    input.get(field).and_then(Value::as_str)
}

/// The server kind the input names.
fn server(input: &Value) -> Result<Server, String> {
    let kind = arg(input, "kind").unwrap_or_default();
    Server::parse(kind).ok_or_else(|| {
        format!("kind must be one of vps, super_vps, premium_vps, bare_metal, not {kind:?}")
    })
}

/// `text`, cut to `max` characters.
fn cut(text: &str, max: usize) -> String {
    let mut out: String = text.chars().take(max).collect();
    if text.chars().count() > max {
        out.push('…');
    }
    out
}

/// The catalogue of one kind of server: names, monthly prices, specs.
pub(crate) async fn server_catalog(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
) -> Result<Value, String> {
    let kind = server(input)?;
    let mut url = kind.catalog_url().to_owned();
    if kind == Server::BareMetal {
        let category = arg(input, "bare_metal_type").unwrap_or("all");
        if !account::BARE_METAL_TYPES.contains(&category) {
            return Err(format!(
                "bare_metal_type must be one of {}",
                account::BARE_METAL_TYPES.join(", ")
            ));
        }
        url = format!("{url}/{category}");
    }
    let reply = read(client, token, &url).await?;
    let products: Vec<Value> = reply
        .get("message")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    json!({
                        "name": item.get("product").and_then(Value::as_str).unwrap_or_default().trim(),
                        "monthlyEur": item.get("price"),
                        "spec": cut(item.get("description").and_then(Value::as_str).unwrap_or_default(), SPEC_CHARS),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({
        "kind": kind.name(),
        "prices": "euros per month; paid a year at once, 12 x monthly x 0.7",
        "products": products,
    }))
}

/// The servers of one kind free to be rented now, counted by region and
/// spec.
pub(crate) async fn server_stock(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
) -> Result<Value, String> {
    let kind = server(input)?;
    let region = arg(input, "region");
    if let Some(region) = region
        && !REGIONS.contains(&region)
    {
        return Err(format!("region must be one of {}", REGIONS.join(", ")));
    }
    let fields: &[&str] = if kind == Server::BareMetal {
        &["region", "productId", "cpu", "ram", "disk", "network"]
    } else {
        &["region", "cpu", "ram", "disk", "vpsVersion"]
    };
    // Each spec once, in the order first seen, with how many there are.
    let mut groups: Vec<(Value, u64)> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut complete = false;
    let mut total = None;
    for _ in 0..STOCK_PAGES {
        let mut query: Vec<(&str, &str)> = Vec::new();
        if let Some(region) = region {
            query.push(("region", region));
        }
        if kind == Server::BareMetal {
            query.push(("limit", "100"));
        }
        if let Some(cursor) = cursor.as_deref() {
            query.push(("cursor", cursor));
        }
        let reply = account::read_query(client, token, kind.stock_url(), &query)
            .await
            .map_err(|e| format!("user-api did not answer: {e}"))?;
        total = total.or_else(|| reply.get("totalCount").and_then(Value::as_u64));
        for row in reply
            .get("message")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut group = pick(row, fields);
            // VPS memory comes in megabytes, as a string.
            if let Some(mb) = row
                .get("ram")
                .and_then(Value::as_str)
                .and_then(|r| r.parse::<u64>().ok())
                .filter(|_| kind != Server::BareMetal)
            {
                group["ram"] = json!(format!("{} GB", mb / 1024));
            }
            if let Some((_, n)) = groups.iter_mut().find(|(g, _)| *g == group) {
                *n += 1;
            } else {
                groups.push((group, 1));
            }
        }
        cursor = reply.get("nextCursor").and_then(|c| match c {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        });
        let more = reply.get("hasMore").and_then(Value::as_bool) == Some(true);
        if !more || cursor.is_none() {
            complete = true;
            break;
        }
    }
    let mut groups = with_product_names(client, token, groups).await;
    groups.sort_by_key(|g| g["region"].to_string());
    let mut out = json!({
        "kind": kind.name(),
        "region": region,
        "inStock": groups,
        "complete": complete,
    });
    if let Some(total) = total {
        out["totalAvailable"] = json!(total);
    }
    Ok(out)
}

/// Stock groups with their counts, each bare metal one with its product's
/// name in place of its id.
///
/// Bare metal stock names its product by id only: the name is looked up,
/// once per product, so the model does not have to guess it from the spec.
/// The id itself is not passed on.
async fn with_product_names(
    client: &AuthClient,
    token: &SecretString,
    groups: Vec<(Value, u64)>,
) -> Vec<Value> {
    let mut names: Vec<(String, Value)> = Vec::new();
    for (group, _) in &groups {
        if let Some(id) = group.get("productId").and_then(Value::as_str)
            && !names.iter().any(|(known, _)| known == id)
        {
            let name =
                account::read_query(client, token, account::PRODUCT_URL, &[("productId", id)])
                    .await
                    .ok()
                    .and_then(|p| p.get("message").unwrap_or(&p).get("name").cloned())
                    .unwrap_or(Value::Null);
            names.push((id.to_owned(), name));
        }
    }
    groups
        .into_iter()
        .map(|(mut group, n)| {
            if let Some(Value::String(id)) =
                group.as_object_mut().and_then(|g| g.remove("productId"))
            {
                group["product"] = names
                    .iter()
                    .find(|(known, _)| *known == id)
                    .map_or(Value::Null, |(_, name)| name.clone());
            }
            group["available"] = json!(n);
            group
        })
        .collect()
}

/// The plan families whose prices `plan_prices` gives.
pub const PLAN_FAMILIES: &[&str] = &[
    "erpc_plan",
    "unlimited_rpc",
    "dedicated_rpc",
    "grpc",
    "dedicated_grpc",
    "shreds",
    "bundle",
    "storage",
    "slv_ai_plan",
    "vps",
    "bare_metal",
];

/// The prices of one family of plans, with their names.
pub(crate) async fn plan_prices(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
) -> Result<Value, String> {
    let family = arg(input, "family").unwrap_or_default();
    if !PLAN_FAMILIES.contains(&family) {
        return Err(format!(
            "family must be one of {}",
            PLAN_FAMILIES.join(", ")
        ));
    }
    let catalog = read(client, token, account::PLAN_CATALOG_URL).await?;
    let plans: Vec<&Value> = catalog
        .get("plans")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get("productFamily").and_then(Value::as_str) == Some(family))
        .collect();
    let mut out = Vec::new();
    for plan in plans.iter().take(PLAN_NAMES) {
        let euros = |field: &str| {
            plan.get(field)
                .and_then(Value::as_f64)
                .map(|cents| cents / 100.0)
        };
        let mut entry = json!({
            "monthlyEur": euros("monthlyPeriodCents"),
            "annualEur": euros("annualPeriodCents"),
        });
        if let Some(id) = plan.get("productId").and_then(Value::as_str) {
            // A name not found is left out, not a reason to give no prices.
            if let Ok(product) =
                account::read_query(client, token, account::PRODUCT_URL, &[("productId", id)]).await
            {
                let product = product.get("message").unwrap_or(&product);
                entry["name"] = product.get("name").cloned().unwrap_or(Value::Null);
                entry["description"] = json!(cut(
                    product
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    SPEC_CHARS
                ));
            }
        }
        out.push(entry);
    }
    Ok(json!({
        "family": family,
        "plans": out,
        "more": plans.len().saturating_sub(PLAN_NAMES),
    }))
}

/// The fields passed on for each kind of service the account runs. An
/// endpoint is passed on only when [`public_endpoint`] allows it.
const SERVICE_FIELDS: &[(&str, &[&str])] = &[
    (
        "vps",
        &[
            // What wait_until_ready, secure_vps and restrict_ssh take, and
            // where the person reaches it: the address and login user. The
            // password never.
            "userVpsId",
            "ip",
            "username",
            "product",
            "price",
            "status",
            "region",
            "startedAt",
            "nextPaymentDue",
            "trialEnd",
        ],
    ),
    (
        "bare_metal",
        &[
            "productName",
            "tags",
            "status",
            "region",
            "cpu",
            "ram",
            "disk",
            "network",
            "startDate",
            "nextPaymentDate",
            "isCanceled",
        ],
    ),
    ("unlimited_rpc", &["productName", "region", "status"]),
    (
        "dedicated_rpc",
        &["productName", "plan", "region", "status", "createdAt"],
    ),
    (
        "grpc",
        &["grpcPlan", "region", "status", "distance", "createdAt"],
    ),
    (
        "dedicated_grpc",
        &[
            "productName",
            "plan",
            "version",
            "region",
            "status",
            "createdAt",
        ],
    ),
    (
        "shreds",
        &["shredsPlan", "region", "status", "distance", "createdAt"],
    ),
    (
        "dedicated_shreds",
        &[
            "name",
            "serverType",
            "blockEngineRegion",
            "status",
            "billingCycle",
            "hourlyCents",
            "assigned",
            "assignedRegion",
        ],
    ),
    (
        "epic_shreds_direct",
        &["status", "billingCycle", "hourlyCents", "createdAt"],
    ),
    ("udp_forwarding", UDP_FIELDS),
    ("udp_forwarding_premium", UDP_FIELDS),
];

/// What is passed on of a UDP Forwarding line: its id (which pointing it
/// takes), where it sends to and the addresses it sends from, and its
/// state. Its Stripe ids and the node's bookkeeping stay out.
const UDP_FIELDS: &[&str] = &[
    "id",
    "productName",
    "status",
    "billingCycle",
    "region",
    "destination",
    "sourceIp",
    "sourceIps",
    "lastError",
    "activatedAt",
    "createdAt",
    "suspendedAt",
    "cancelledAt",
];

/// The kind a UDP Forwarding product's lines are listed under:
/// `udp_forwarding`, `udp_forwarding_premium`.
fn udp_kind(family: &erpc_api::udp::Family) -> String {
    family.family.replace('-', "_")
}

/// `endpoint`, when it is an ERPC host with nothing after the path that
/// could be a key: no query, no fragment, no user. A dedicated service's
/// endpoint is a bare IP and an Unlimited one can carry its key; neither
/// is passed on.
fn public_endpoint(endpoint: &str) -> Option<&str> {
    let rest = ["https://", "wss://", "http://", "ws://"]
        .iter()
        .find_map(|scheme| endpoint.strip_prefix(scheme))?;
    if rest.contains(['?', '#', '@']) {
        return None;
    }
    let host = rest.split(['/', ':']).next()?;
    (host.ends_with(".erpc.global") && !host.starts_with('.')).then_some(endpoint)
}

/// One kind's rows, with the fields it names.
fn service_rows(kind: &str, reply: &Value) -> Vec<Value> {
    let fields = SERVICE_FIELDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or(&[][..], |(_, f)| *f);
    let rows = [reply.get("data"), reply.get("message")]
        .into_iter()
        .flatten()
        .find_map(Value::as_array);
    rows.into_iter()
        .flatten()
        .map(|row| {
            let mut out = pick(row, fields);
            if let Some(endpoint) = row
                .get("endpoint")
                .and_then(Value::as_str)
                .and_then(public_endpoint)
            {
                out["endpoint"] = json!(endpoint);
            }
            if let Some(penalty) = row.get("penalty").filter(|p| !p.is_null()) {
                out["penalty"] = pick(
                    penalty,
                    &["paused", "code", "reason", "stage", "endsAt", "faqUrl"],
                );
            }
            out
        })
        .collect()
}

/// Every service the account runs, by kind. The UDP Forwarding lines come
/// from their products' own lists, whose refusal is user-api's word on the
/// route (it may not open them to erpc's sign-in) and is passed on as such
/// in `refused`, never as a session to sign in again.
pub(crate) async fn my_services(
    client: &AuthClient,
    token: &SecretString,
) -> Result<Value, String> {
    let reads = account::SERVICE_STATUS_URLS
        .iter()
        .map(|(kind, url)| async move { (*kind, read(client, token, url).await) });
    let udp_reads = erpc_api::udp::FAMILIES.iter().map(|family| async move {
        let reply = account::read_udp_forwarding(client, token, family.my_url).await;
        (family, reply)
    });
    let (replies, udp_replies) = futures_util::future::join(
        futures_util::future::join_all(reads),
        futures_util::future::join_all(udp_reads),
    )
    .await;
    let mut services = Map::new();
    let mut unreadable: Vec<String> = Vec::new();
    for (kind, reply) in replies {
        match reply {
            Ok(reply) => {
                let rows = service_rows(kind, &reply);
                if !rows.is_empty() {
                    services.insert(kind.to_owned(), Value::Array(rows));
                }
            }
            Err(_) => unreadable.push(kind.to_owned()),
        }
    }
    if services.is_empty() && unreadable.len() == account::SERVICE_STATUS_URLS.len() {
        return Err("user-api did not answer for any service".to_owned());
    }
    let refused = udp_services(udp_replies, &mut services, &mut unreadable);
    Ok(json!({
        "services": services,
        "none": services.is_empty(),
        "unreadable": unreadable,
        "refused": refused,
    }))
}

/// The UDP Forwarding lines in `replies`, one product's each, into
/// `services`; a list user-api would not give into what is returned, in
/// its words, and one that got no answer into `unreadable`.
fn udp_services(
    replies: Vec<(&erpc_api::udp::Family, Result<Value, ApiError>)>,
    services: &mut Map<String, Value>,
    unreadable: &mut Vec<String>,
) -> Map<String, Value> {
    let mut refused = Map::new();
    for (family, reply) in replies {
        let kind = udp_kind(family);
        match reply {
            Ok(reply) => {
                let rows = service_rows(&kind, &reply);
                if !rows.is_empty() {
                    services.insert(kind, Value::Array(rows));
                }
            }
            Err(e @ (ApiError::Refused { .. } | ApiError::Status(_))) => {
                refused.insert(kind, json!(e.to_string()));
            }
            Err(_) => unreadable.push(kind),
        }
    }
    refused
}

/// How each region has answered `service` over the last 30 days.
pub(crate) async fn service_health(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
) -> Result<Value, String> {
    let service = arg(input, "service").unwrap_or_default();
    if !["rpc", "grpc", "shreds"].contains(&service) {
        return Err("service must be one of rpc, grpc, shreds".to_owned());
    }
    let reply = account::read_query(
        client,
        token,
        account::HEALTH_URL,
        &[("service", service), ("window", "30d")],
    )
    .await
    .map_err(|e| format!("user-api did not answer: {e}"))?;
    let m = reply.get("message").unwrap_or(&Value::Null);
    let regions: Vec<Value> = m
        .get("regions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|region| {
            let buckets = region
                .get("buckets")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let (mut probes, mut ok, mut latency, mut timed) = (0.0, 0.0, 0.0, 0.0);
            for b in &buckets {
                let n = b.get("probeCount").and_then(Value::as_f64).unwrap_or(0.0);
                probes += n;
                ok += n * b.get("successRate").and_then(Value::as_f64).unwrap_or(0.0);
                if let Some(ms) = b.get("avgLatencyMs").and_then(Value::as_f64) {
                    latency += n * ms;
                    timed += n;
                }
            }
            let mut out = pick(region, &["region", "currentStatus"]);
            out["successRate"] = if probes > 0.0 {
                json!((ok / probes * 10_000.0).round() / 10_000.0)
            } else {
                Value::Null
            };
            out["avgLatencyMs"] = if timed > 0.0 {
                json!((latency / timed).round())
            } else {
                Value::Null
            };
            out
        })
        .collect();
    Ok(json!({
        "service": service,
        "window": "30d",
        "generatedAt": m.get("generatedAt"),
        "regions": regions,
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    /// What `my_services` makes of each UDP Forwarding list: a line with
    /// what pointing it takes and nothing of Stripe's; a refusal in
    /// user-api's words, never as a session to sign in again; silence as
    /// a list it could not read.
    #[test]
    fn udp_forwarding_lines_are_listed_by_product_and_a_refusal_is_user_apis_word() {
        use erpc_api::ApiError;
        use erpc_api::udp::FAMILIES;
        let standard = json!({ "success": true, "data": [{
            "id": 42, "productKey": "one_hop_direct", "productName": "UDP Forwarding Standard",
            "status": "active", "billingCycle": "hourly", "region": "tokyo",
            "destination": "203.0.113.10:10001", "sourceIp": "198.51.100.20",
            "priceId": "price_x", "subscriptionItemId": "si_x", "revision": 3,
        }] });
        let refusal = erpc_api::account::udp_forwarding_reply(
            403,
            r#"{"message":"this route is not open to erpc-cli","code":"ROUTE_NOT_ALLOWED"}"#,
        )
        .expect_err("refused");
        let mut services = serde_json::Map::new();
        let mut unreadable = vec!["grpc".to_owned()];
        let refused = super::udp_services(
            vec![(&FAMILIES[0], Ok(standard)), (&FAMILIES[1], Err(refusal))],
            &mut services,
            &mut unreadable,
        );
        let line = &services["udp_forwarding"][0];
        assert_eq!(line["id"], json!(42));
        assert_eq!(line["destination"], json!("203.0.113.10:10001"));
        assert_eq!(line["sourceIp"], json!("198.51.100.20"));
        for stripe in ["priceId", "subscriptionItemId", "revision", "productKey"] {
            assert!(line.get(stripe).is_none(), "{stripe}");
        }
        let said = refused["udp_forwarding_premium"].as_str().expect("words");
        assert!(
            said.contains("not open to erpc-cli") && !said.contains("erpc login"),
            "{said}"
        );
        assert_eq!(unreadable, ["grpc"]);
        // An empty list is no service; no answer is a list not read.
        let mut services = serde_json::Map::new();
        let none = super::udp_services(
            vec![
                (&FAMILIES[0], Ok(json!({ "data": [] }))),
                (
                    &FAMILIES[1],
                    Err(ApiError::Malformed("not JSON".to_owned())),
                ),
            ],
            &mut services,
            &mut unreadable,
        );
        assert!(services.is_empty() && none.is_empty());
        assert_eq!(unreadable, ["grpc", "udp_forwarding_premium"]);
    }

    #[test]
    fn only_an_erpc_host_with_nothing_after_the_path_is_passed_on() {
        // Built, not written out: the endpoint gate reads literals, and
        // most of these are the kind it is there to refuse.
        let url = |scheme: &str, rest: &str| format!("{scheme}://{rest}");
        for endpoint in [
            url("https", "edge.erpc.global"),
            url("http", "edge.erpc.global:10000"),
            url("wss", "edge.erpc.global/ws"),
        ] {
            assert_eq!(super::public_endpoint(&endpoint), Some(endpoint.as_str()));
        }
        for endpoint in [
            url("https", "edge.erpc.global?api-key=k"),
            url("http", "203.0.113.5:7211"),
            url("https", "user:pw@edge.erpc.global"),
            url("https", "edge.erpc.global.evil.example/x"),
            url("https", "edge.erpc.global#k"),
            "edge.erpc.global".to_owned(),
            url("https", ".erpc.global"),
        ] {
            assert_eq!(super::public_endpoint(&endpoint), None, "{endpoint}");
        }
    }

    #[test]
    fn a_server_passes_on_its_terms_and_address_and_never_its_password() {
        let reply = json!({ "success": true, "data": [{
            "userVpsId": 7, "subscriptionItemId": "si_1", "priceId": "price_1",
            "product": "EPYC VPS+", "price": 78, "status": "on", "region": "tokyo",
            "ip": "203.0.113.9", "username": "solv", "password": "hunter2",
        }]});
        let rows = super::service_rows("vps", &reply);
        let text = serde_json::to_string(&rows).expect("json");
        assert_eq!(rows[0]["product"], "EPYC VPS+");
        assert_eq!(rows[0]["region"], "tokyo");
        assert_eq!(rows[0]["userVpsId"], 7, "the id the server tools take");
        assert_eq!(rows[0]["ip"], "203.0.113.9", "the person asks where it is");
        assert_eq!(rows[0]["username"], "solv");
        for hidden in ["hunter2", "si_1", "price_1"] {
            assert!(!text.contains(hidden), "{hidden} in {text}");
        }
    }

    #[test]
    fn an_unlimited_endpoint_with_its_key_is_left_out() {
        let reply = json!({ "data": [{
            "productName": "UserUnlimited Pro", "status": "active", "region": "frankfurt",
            "endpoint": "https://edge.erpc.global?api-key=secret", "whitelistIps": ["198.51.100.1"],
        }]});
        let rows = super::service_rows("unlimited_rpc", &reply);
        let text = serde_json::to_string(&rows).expect("json");
        assert!(
            !text.contains("secret") && !text.contains("198.51.100.1"),
            "{text}"
        );
        assert_eq!(rows[0]["productName"], "UserUnlimited Pro");
    }

    #[test]
    fn every_service_kind_has_its_fields() {
        for (kind, _) in erpc_api::account::SERVICE_STATUS_URLS {
            assert!(
                super::SERVICE_FIELDS.iter().any(|(k, _)| k == kind),
                "{kind}"
            );
        }
    }
}
