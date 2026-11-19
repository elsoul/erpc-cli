// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The account's own figures, read from user-api -- credits,
//! subscriptions, usage, the services it runs -- and what it could order:
//! the server catalogue and the stock of servers by region. Reads, but for
//! the two settings a data line takes ([`set_unlimited_whitelist`],
//! [`set_udp_destination`]); nothing here calls an endpoint that does
//! something as it reads (the `/list` catalogues open a Stripe checkout
//! session each time, so the public lists are read instead).
//!
//! Each call returns the reply as JSON, for the caller to take what it
//! needs from: the assistant's tools pick the fields they pass on, so a
//! field user-api adds later is not passed on by accident.

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde_json::Value;

use crate::ApiError;

/// Credit balance, what is drawing on it, and how long it lasts.
pub const CREDIT_SNAPSHOT_URL: &str = "https://user-api.erpc.global/v3/user/credit-snapshot";

/// How long user-api may answer [`CREDIT_SNAPSHOT_URL`] from its cache
/// (it says 60 seconds): a product started or ended within this can be
/// missing from it, or still in it.
pub const CREDIT_SNAPSHOT_CACHE: core::time::Duration = core::time::Duration::from_secs(60);

/// Credits added and spent, by month, for the last three months.
pub const CREDIT_SUMMARY_URL: &str = "https://user-api.erpc.global/v3/billing/credit/summary";

/// The subscriptions paid by card: active, trialing and past due.
pub const SUBSCRIPTIONS_URL: &str = "https://user-api.erpc.global/v3/billing/my-subscriptions";

/// RPC calls and credits this month, by method.
pub const RPC_USAGE_URL: &str = "https://user-api.erpc.global/v3/erpc/usage";

/// The prices of every plan paid by subscription, by product family, in
/// cents per month and per year. No names: see [`PRODUCT_URL`].
pub const PLAN_CATALOG_URL: &str =
    "https://user-api.erpc.global/v3/billing/credit-recurring/catalog";

/// One product's name and description, by `productId`.
pub const PRODUCT_URL: &str = "https://user-api.erpc.global/v3/billing/get-product-by-product-id";

/// Probe results by region over the last 30 days, for `service`.
pub const HEALTH_URL: &str = "https://user-api.erpc.global/v3/system/health";

/// The account's dashboard, with its API keys for the shared RPC: the
/// primary one (`message.apiKey`) and every active one
/// (`message.activeApiKeys`).
pub const DASHBOARD_URL: &str = "https://user-api.erpc.global/v3/user/dashboard";

/// The addresses an Unlimited RPC lets in: the whole list, replaced.
pub const UNLIMITED_WHITELIST_URL: &str =
    "https://user-api.erpc.global/v3/user-unlimited/whitelist";

/// The account's UDP Forwarding Standard lines (`data[]`), each with the
/// address it sends from (`sourceIp`, null until a node is allocated).
pub const UDP_FORWARDING_MY_URL: &str = "https://user-api.erpc.global/v3/udp-forwarding/my";

/// The account's UDP Forwarding Premium lines (`data[]`), each with the
/// addresses it sends from (`sourceIps`). An empty list for an account
/// with none.
pub const UDP_FORWARDING_PREMIUM_MY_URL: &str =
    "https://user-api.erpc.global/v3/udp-forwarding-premium/my";

/// Where a UDP Forwarding Standard line sends, and from which region: see
/// [`set_udp_destination`].
pub const UDP_FORWARDING_DESTINATION_URL: &str =
    "https://user-api.erpc.global/v3/udp-forwarding/destination";

/// The same for a Premium line.
pub const UDP_FORWARDING_PREMIUM_DESTINATION_URL: &str =
    "https://user-api.erpc.global/v3/udp-forwarding-premium/destination";

/// A kind of server ERPC rents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    /// The standard VPS.
    Vps,
    /// Super VPS: high-clock cores.
    SuperVps,
    /// Premium VPS: Ryzen, on the network of the Solana shreds sources.
    PremiumVps,
    /// Bare metal.
    BareMetal,
}

impl Server {
    /// Every kind.
    pub const ALL: [Self; 4] = [Self::Vps, Self::SuperVps, Self::PremiumVps, Self::BareMetal];

    /// The name tools use for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vps => "vps",
            Self::SuperVps => "super_vps",
            Self::PremiumVps => "premium_vps",
            Self::BareMetal => "bare_metal",
        }
    }

    /// The kind named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// The public catalogue: products, monthly prices in euros, specs.
    /// Bare metal takes its category after it (`/APP`, `/MV`, ...).
    #[must_use]
    pub const fn catalog_url(self) -> &'static str {
        match self {
            Self::Vps => "https://user-api.erpc.global/v3/vps/list/public",
            Self::SuperVps => "https://user-api.erpc.global/v3/super-vps/list/public",
            Self::PremiumVps => "https://user-api.erpc.global/v3/premium-vps/list/public",
            Self::BareMetal => "https://user-api.erpc.global/v3/baremetal/list/public",
        }
    }

    /// The servers free to be rented now.
    #[must_use]
    pub const fn stock_url(self) -> &'static str {
        match self {
            Self::Vps => "https://user-api.erpc.global/v3/vps/search-available-vps",
            Self::SuperVps => "https://user-api.erpc.global/v3/super-vps/search-available-vps",
            Self::PremiumVps => "https://user-api.erpc.global/v3/premium-vps/search-available-vps",
            Self::BareMetal => {
                "https://user-api.erpc.global/v3/baremetal/search-available-baremetal"
            }
        }
    }
}

/// The bare metal categories the catalogue is filed under.
pub const BARE_METAL_TYPES: &[&str] = &["APP", "MV", "RPC", "UT", "LG", "all"];

/// The status of each kind of service the account may run, by the name
/// tools use for it. Each reply lists the account's own.
pub const SERVICE_STATUS_URLS: &[(&str, &str)] = &[
    ("vps", "https://user-api.erpc.global/v3/vps/status"),
    (
        "bare_metal",
        "https://user-api.erpc.global/v3/baremetal/status",
    ),
    (
        "unlimited_rpc",
        "https://user-api.erpc.global/v3/user-unlimited/status",
    ),
    (
        "dedicated_rpc",
        "https://user-api.erpc.global/v3/rpc-index/status",
    ),
    ("grpc", "https://user-api.erpc.global/v3/grpc/status"),
    (
        "dedicated_grpc",
        "https://user-api.erpc.global/v3/geyser-grpc/status",
    ),
    (
        "shreds",
        "https://user-api.erpc.global/v3/shreds-shared/status",
    ),
    (
        "dedicated_shreds",
        "https://user-api.erpc.global/v3/shreds-dedicated/status",
    ),
    (
        "epic_shreds_direct",
        "https://user-api.erpc.global/v3/epic-shreds-direct/my",
    ),
];

/// Every URL this module reads, for the tests that check where a session
/// token may go.
pub const URLS: &[&str] = &[
    CREDIT_SNAPSHOT_URL,
    CREDIT_SUMMARY_URL,
    SUBSCRIPTIONS_URL,
    RPC_USAGE_URL,
    PLAN_CATALOG_URL,
    PRODUCT_URL,
    HEALTH_URL,
    DASHBOARD_URL,
    UNLIMITED_WHITELIST_URL,
    UDP_FORWARDING_MY_URL,
    UDP_FORWARDING_PREMIUM_MY_URL,
    UDP_FORWARDING_DESTINATION_URL,
    UDP_FORWARDING_PREMIUM_DESTINATION_URL,
];

/// Reads one of the URLs above as the signed-in account.
///
/// # Errors
///
/// Returns [`ApiError::Unauthorized`] for a refused session,
/// [`ApiError::Status`] for any other refusal, and [`ApiError::Malformed`]
/// when the reply is not JSON or says it did not succeed.
pub async fn read(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
) -> Result<Value, ApiError> {
    let (status, body) = client
        .get_with_token(Audience::AuthApi, url, access_token)
        .await?;
    read_reply(status, &body)
}

/// What a reply to [`read`] is taken for, by its status and body.
///
/// # Errors
///
/// As [`read`].
pub fn read_reply(status: u16, body: &str) -> Result<Value, ApiError> {
    match status {
        200 => parse(body),
        401 | 403 => Err(ApiError::Unauthorized),
        other => Err(ApiError::Status(other)),
    }
}

/// Reads a UDP Forwarding `my` list ([`UDP_FORWARDING_MY_URL`],
/// [`UDP_FORWARDING_PREMIUM_MY_URL`]) as the signed-in account.
///
/// # Errors
///
/// As [`udp_forwarding_reply`].
pub async fn read_udp_forwarding(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
) -> Result<Value, ApiError> {
    let (status, body) = client
        .get_with_token(Audience::AuthApi, url, access_token)
        .await?;
    udp_forwarding_reply(status, &body)
}

/// What a reply of a UDP Forwarding route (a `my` list, a destination) is
/// taken for. A 403 here is not a refused session: user-api answers one for
/// a route it does not open to the client that signed in, and signing in
/// again changes nothing. It is passed on with user-api's own words, as
/// every other refusal is.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] for a 401, [`ApiError::Refused`] with
/// user-api's reason and code for any other refusal
/// (`UDP_FORWARDING_REGION_UNAVAILABLE`, `INVALID_DESTINATION`,
/// `UDP_FORWARDING_PREMIUM_APPLY_IN_PROGRESS`, ...), [`ApiError::Status`]
/// for one that gives no reason, and [`ApiError::Malformed`] when the reply
/// is not JSON or says it did not succeed.
pub fn udp_forwarding_reply(status: u16, body: &str) -> Result<Value, ApiError> {
    match status {
        200 => parse(body),
        401 => Err(ApiError::Unauthorized),
        status => Err(match refused(status, body) {
            ApiError::Refused { message, .. } if message.is_empty() => ApiError::Status(status),
            refusal => refusal,
        }),
    }
}

/// Makes `addresses` the whole list Unlimited RPC `id` lets in. Its
/// endpoint takes no key: nothing reaches it until this is set.
///
/// # Errors
///
/// As [`read`], and [`ApiError::Refused`] with user-api's reason.
pub async fn set_unlimited_whitelist(
    client: &AuthClient,
    access_token: &SecretString,
    id: i64,
    addresses: &[std::net::Ipv4Addr],
) -> Result<Value, ApiError> {
    let body = serde_json::json!({
        "userUnlimitedId": id,
        "whitelistIps": addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
    });
    let (status, text) = client
        .patch_with_token(
            Audience::AuthApi,
            UNLIMITED_WHITELIST_URL,
            access_token,
            body.to_string().into_bytes(),
        )
        .await?;
    match status {
        200 => parse(&text),
        401 | 403 => Err(ApiError::Unauthorized),
        status => Err(refused(status, &text)),
    }
}

/// Points UDP Forwarding line `subscription_id` at `destination` (the
/// server's `<public IPv4>:<port>`), sending from `region`. `url` is
/// [`UDP_FORWARDING_DESTINATION_URL`] for a Standard line and
/// [`UDP_FORWARDING_PREMIUM_DESTINATION_URL`] for a Premium one. Another
/// region moves the line to a node there, which changes the address it
/// sends from.
///
/// # Errors
///
/// As [`udp_forwarding_reply`].
pub async fn set_udp_destination(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
    subscription_id: i64,
    region: &str,
    destination: &str,
) -> Result<Value, ApiError> {
    let body = udp_destination(subscription_id, region, destination);
    let (status, text) = client
        .put_with_token(
            Audience::AuthApi,
            url,
            access_token,
            body.to_string().into_bytes(),
        )
        .await?;
    udp_forwarding_reply(status, &text)
}

/// The JSON [`set_udp_destination`] sends.
#[must_use]
pub fn udp_destination(subscription_id: i64, region: &str, destination: &str) -> Value {
    serde_json::json!({
        "subscriptionId": subscription_id,
        "region": region,
        "destination": destination,
    })
}

/// [`ApiError::Refused`] from the body of a refusal: user-api's `message`
/// (or `error`), with its `code` after it when there is one, cut to one
/// printable line.
fn refused(status: u16, text: &str) -> ApiError {
    let body: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let line = |key: &str, at_most: usize| -> Option<String> {
        let text = body.get(key).and_then(Value::as_str)?;
        let line: String = text
            .chars()
            .filter(|c| !c.is_control())
            .take(at_most)
            .collect();
        (!line.is_empty()).then_some(line)
    };
    let message = line("message", 300).or_else(|| line("error", 300));
    let message = match (message, line("code", 64)) {
        (Some(message), Some(code)) => format!("{message} ({code})"),
        (Some(message), None) | (None, Some(message)) => message,
        (None, None) => String::new(),
    };
    ApiError::Refused { status, message }
}

/// Reads `url` with a query. Each value is letters, digits, `-` and `_`
/// only, so nothing a value holds can change the path or add a parameter;
/// a value that is not is refused before anything is sent.
///
/// # Errors
///
/// As [`read`], and [`ApiError::Malformed`] for a value that is refused.
pub async fn read_query(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
    query: &[(&str, &str)],
) -> Result<Value, ApiError> {
    read(client, access_token, &with_query(url, query)?).await
}

/// [`PRODUCT_URL`] for the product `id`, as [`read`] takes it.
///
/// # Errors
///
/// [`ApiError::Malformed`] for an id that is not a plain value.
pub fn product_url(id: &str) -> Result<String, ApiError> {
    with_query(PRODUCT_URL, &[("productId", id)])
}

/// `url` with `query` after it.
fn with_query(url: &str, query: &[(&str, &str)]) -> Result<String, ApiError> {
    let mut out = url.to_owned();
    for (n, (name, value)) in query.iter().enumerate() {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ApiError::Malformed(format!("{name} is not a plain value")));
        }
        out.push(if n == 0 { '?' } else { '&' });
        out.push_str(name);
        out.push('=');
        out.push_str(value);
    }
    Ok(out)
}

/// The reply, when it is JSON and does not say it failed.
fn parse(body: &str) -> Result<Value, ApiError> {
    let value: Value =
        serde_json::from_str(body).map_err(|e| ApiError::Malformed(e.to_string()))?;
    if value.get("success").and_then(Value::as_bool) == Some(false) {
        return Err(ApiError::Malformed(
            "user-api said the request did not succeed".to_owned(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{URLS, parse};

    #[test]
    fn every_url_is_a_place_the_session_may_go() {
        let servers = super::Server::ALL
            .into_iter()
            .flat_map(|kind| [kind.catalog_url(), kind.stock_url()]);
        let statuses = super::SERVICE_STATUS_URLS.iter().map(|(_, url)| *url);
        for url in URLS.iter().copied().chain(servers).chain(statuses) {
            assert!(
                erpc_auth::allowlist::ensure_token_destination(
                    erpc_auth::credential::Audience::AuthApi,
                    url
                )
                .is_ok(),
                "{url}"
            );
            assert!(
                erpc_core::endpoints::ensure_service_url(url).is_ok(),
                "{url}"
            );
        }
    }

    #[test]
    fn a_query_value_cannot_reach_past_its_parameter() {
        assert_eq!(
            super::with_query(
                "https://user-api.erpc.global/p",
                &[("region", "tokyo"), ("limit", "100")]
            )
            .ok(),
            Some("https://user-api.erpc.global/p?region=tokyo&limit=100".to_owned())
        );
        for bad in ["a&b=c", "../x", "a b", "a#b", "", "東京"] {
            assert!(
                super::with_query("https://user-api.erpc.global/p", &[("region", bad)]).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn every_server_kind_round_trips_through_its_name() {
        for kind in super::Server::ALL {
            assert_eq!(super::Server::parse(kind.name()), Some(kind));
        }
        assert_eq!(super::Server::parse("gpu"), None);
    }

    #[test]
    fn a_reply_that_failed_or_is_not_json_is_an_error() {
        assert!(parse(r#"{"success":true,"message":{"balance":1}}"#).is_ok());
        assert!(parse(r#"{"success":false,"message":"no"}"#).is_err());
        assert!(parse("<html>").is_err());
    }

    #[test]
    fn a_destination_is_sent_with_the_fields_user_api_names() {
        assert_eq!(
            super::udp_destination(7, "tokyo", "203.0.113.5:10001"),
            serde_json::json!({
                "subscriptionId": 7,
                "region": "tokyo",
                "destination": "203.0.113.5:10001",
            })
        );
    }

    #[test]
    fn a_403_on_a_udp_forwarding_route_is_user_apis_refusal_not_a_refused_session() {
        use super::ApiError;
        // A route user-api does not open to this client: its words, and no
        // word about signing in again.
        let closed = super::udp_forwarding_reply(
            403,
            r#"{"success":false,"message":"this route is not open to erpc-cli","code":"ROUTE_NOT_ALLOWED"}"#,
        )
        .expect_err("refused");
        assert!(
            matches!(&closed, ApiError::Refused { status: 403, message }
                if message == "this route is not open to erpc-cli (ROUTE_NOT_ALLOWED)"),
            "{closed:?}"
        );
        assert!(!closed.to_string().contains("erpc login"), "{closed}");
        // With nothing said, the status alone.
        assert!(matches!(
            super::udp_forwarding_reply(403, "Forbidden"),
            Err(ApiError::Status(403))
        ));
        // A 401 is still the session's, and a 200 the reply.
        assert!(matches!(
            super::udp_forwarding_reply(401, "{}"),
            Err(ApiError::Unauthorized)
        ));
        assert_eq!(
            super::udp_forwarding_reply(200, r#"{"success":true,"data":[]}"#).expect("a list")["data"],
            serde_json::json!([])
        );
        // Every other read keeps taking a 403 for a refused session.
        assert!(matches!(
            super::read_reply(403, "{}"),
            Err(ApiError::Unauthorized)
        ));
        assert!(matches!(
            super::read_reply(500, "{}"),
            Err(ApiError::Status(500))
        ));
    }

    #[test]
    fn a_refusal_carries_user_apis_message_and_its_code() {
        let shown = |text: &str| match super::refused(409, text) {
            super::ApiError::Refused { status, message } => (status, message),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            shown(
                r#"{"success":false,"message":"the region changed","code":"UDP_FORWARDING_REGION_CHANGED"}"#
            ),
            (
                409,
                "the region changed (UDP_FORWARDING_REGION_CHANGED)".to_owned()
            )
        );
        assert_eq!(shown(r#"{"message":"no such line"}"#).1, "no such line");
        assert_eq!(shown(r#"{"error":"nope"}"#).1, "nope");
        assert_eq!(shown(r#"{"code":"REGION_DOWN"}"#).1, "REGION_DOWN");
        assert_eq!(shown("<html>").1, "");
        // One printable line, whatever the body held.
        assert_eq!(
            shown(r#"{"message":"a\u001b[2Jb\nc","code":"X\u0007"}"#).1,
            "a[2Jbc (X)"
        );
    }
}
