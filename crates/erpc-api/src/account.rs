// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The account's own figures, read from user-api -- credits,
//! subscriptions, usage, the services it runs -- and what it could order:
//! the server catalogue and the stock of servers by region. Read only;
//! nothing here changes the account, and nothing here calls an endpoint that
//! does something as it reads (the `/list` catalogues open a Stripe checkout
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
    match status {
        200 => parse(&body),
        401 | 403 => Err(ApiError::Unauthorized),
        other => Err(ApiError::Status(other)),
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
        status => {
            let message = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| {
                    v.get("message")
                        .or_else(|| v.get("error"))
                        .and_then(Value::as_str)
                        .map(|m| m.chars().filter(|c| !c.is_control()).take(300).collect())
                })
                .unwrap_or_default();
            Err(ApiError::Refused { status, message })
        }
    }
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
}
