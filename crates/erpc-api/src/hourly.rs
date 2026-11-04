// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Hourly products, paid from ERPC Credit: the catalogue of what can be
//! started and its price per hour, and starting and ending one.
//!
//! Each family is one start route and the end route that stops what it
//! starts. The routes and the fields each takes are fixed here, so a call
//! can only reach a route this table names and only carry the fields that
//! route reads: what the values are is user-api's to check.

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde_json::{Map, Value};

use crate::ApiError;

/// The hourly catalogue: per family, its routes and each plan's price per
/// hour.
pub const CATALOG_URL: &str = "https://user-api.erpc.global/v3/billing/hourly-catalog";

const BASE: &str = "https://user-api.erpc.global";

/// One family of hourly products.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Family {
    /// The name the catalogue uses.
    pub name: &'static str,
    /// The route that starts one.
    pub start_path: &'static str,
    /// The route that ends one.
    pub end_path: &'static str,
    /// The fields the start route requires.
    pub required: &'static [&'static str],
    /// The fields it also takes.
    pub optional: &'static [&'static str],
    /// The field the end route names the product by.
    pub end_id: &'static str,
    /// Whether the start route takes an `idempotency-key`.
    pub idempotent: bool,
}

const fn family(
    name: &'static str,
    start_path: &'static str,
    end_path: &'static str,
    required: &'static [&'static str],
    optional: &'static [&'static str],
    end_id: &'static str,
    idempotent: bool,
) -> Family {
    Family {
        name,
        start_path,
        end_path,
        required,
        optional,
        end_id,
        idempotent,
    }
}

/// Every family, as user-api's routes define them.
pub const FAMILIES: &[Family] = &[
    family(
        "erpc",
        "/v3/erpc/start-hourly",
        "/v3/erpc/end-hourly",
        &["productId"],
        &[],
        "userErpcPlanHourlyId",
        true,
    ),
    family(
        "ai",
        "/v3/ai/start-hourly",
        "/v3/ai/end-hourly",
        &["productId"],
        &[],
        "userSlvAiPlanHourlyId",
        true,
    ),
    family(
        "vps",
        "/v3/vps/start-hourly",
        "/v3/vps/end-hourly",
        &["productId", "region"],
        &[],
        "userVpsId",
        true,
    ),
    family(
        "baremetal",
        "/v3/baremetal/start-hourly",
        "/v3/baremetal/end-hourly",
        &["productId", "region"],
        &[],
        "userBareMetalId",
        true,
    ),
    family(
        "grpc",
        "/v3/grpc/start-hourly",
        "/v3/grpc/end-hourly",
        &["productId", "ip"],
        &[],
        "userGrpcId",
        true,
    ),
    family(
        "grpc-bundle",
        "/v3/grpc/start-hourly-bundle",
        "/v3/grpc/end-hourly",
        &["productId"],
        &[],
        "userGrpcId",
        false,
    ),
    family(
        "geyser-grpc",
        "/v3/geyser-grpc/start-hourly",
        "/v3/geyser-grpc/end-hourly",
        &["productId", "region"],
        &["identityPubkey", "validatorType"],
        "geyserGrpcId",
        true,
    ),
    family(
        "shreds-shared",
        "/v3/shreds-shared/start-hourly",
        "/v3/shreds-shared/end-hourly",
        &["productId", "ip"],
        &[],
        "userShredsId",
        true,
    ),
    family(
        "shreds-bundle",
        "/v3/shreds-shared/start-hourly-bundle",
        "/v3/shreds-shared/end-hourly",
        &["productId"],
        &[],
        "userShredsId",
        false,
    ),
    family(
        "direct-shreds",
        "/v3/direct-shreds/start-hourly",
        "/v3/direct-shreds/end-hourly",
        &["productId", "region", "serverType"],
        &["blockEngineRegion", "whitelistIps", "destPorts"],
        "directShredsId",
        true,
    ),
    family(
        "epic-shreds-direct",
        "/v3/epic-shreds-direct/start-hourly",
        "/v3/epic-shreds-direct/end-hourly",
        &["destination"],
        &[],
        "userEpicShredsDirectId",
        true,
    ),
    family(
        "user-unlimited",
        "/v3/user-unlimited/start-hourly",
        "/v3/user-unlimited/end-hourly",
        &["productId", "region"],
        &[],
        "userUnlimitedId",
        true,
    ),
    family(
        "rpc-index",
        "/v3/rpc-index/start-hourly",
        "/v3/rpc-index/end-hourly",
        &["productId", "region"],
        &["identityPubkey", "validatorType"],
        "rpcIndexId",
        true,
    ),
    family(
        "bundle",
        "/v3/bundle/start-hourly",
        "/v3/bundle/end-hourly",
        &["productId", "region"],
        &[
            "grpcPlan",
            "shredsPlan",
            "grpcWhitelistIp",
            "shredsWhitelistIp",
        ],
        "userBundleId",
        false,
    ),
    family(
        "stream-bundle",
        "/v3/bundle/start-hourly-stream",
        "/v3/bundle/end-hourly",
        &["productId", "region"],
        &[
            "grpcPlan",
            "shredsPlan",
            "dedicatedServerType",
            "grpcWhitelistIp",
            "shredsWhitelistIp",
            "dedicatedBlockEngineRegion",
            "dedicatedWhitelistIps",
            "dedicatedDestPorts",
        ],
        "userBundleId",
        false,
    ),
    family(
        "udp-forwarding",
        "/v3/udp-forwarding/start-hourly",
        "/v3/udp-forwarding/end-hourly",
        &["subscriptionId"],
        &[],
        "subscriptionId",
        true,
    ),
];

/// The family whose end route stops a product of the credit snapshot's
/// `productType` (`hourlyResources[].productType`).
#[must_use]
pub fn for_product_type(product_type: &str) -> Option<&'static Family> {
    let name = match product_type {
        "vps" => "vps",
        "bare_metal" => "baremetal",
        "grpc" => "grpc",
        "shreds" => "shreds-shared",
        "unlimited" => "user-unlimited",
        "direct_shreds" => "direct-shreds",
        "geyser_grpc" => "geyser-grpc",
        "rpc_index" => "rpc-index",
        "bundle" => "bundle",
        "epic_shreds_direct" => "epic-shreds-direct",
        "erpc_plan" => "erpc",
        "slv_ai_plan" => "ai",
        "one_hop_direct" => "udp-forwarding",
        _ => return None,
    };
    find(name)
}

/// The family named `name`.
#[must_use]
pub fn find(name: &str) -> Option<&'static Family> {
    FAMILIES.iter().find(|f| f.name == name)
}

impl Family {
    /// The start body from `fields`: the required ones present, nothing
    /// the route does not take.
    ///
    /// # Errors
    ///
    /// Says which field is missing or not this route's.
    pub fn start_body(&self, fields: &Map<String, Value>) -> Result<Value, String> {
        for key in fields.keys() {
            if !self.required.contains(&key.as_str()) && !self.optional.contains(&key.as_str()) {
                return Err(format!(
                    "{} does not take {key}; it takes {}",
                    self.name,
                    self.required
                        .iter()
                        .chain(self.optional)
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        for key in self.required {
            if fields.get(*key).is_none_or(Value::is_null) {
                return Err(format!("{} needs {key}", self.name));
            }
        }
        Ok(Value::Object(fields.clone()))
    }
}

/// What user-api answered a start or an end: the status and the reply.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// The reply, or `null` when it was not JSON.
    pub body: Value,
}

async fn post(
    client: &AuthClient,
    access_token: &SecretString,
    path: &str,
    body: &Value,
    idempotency_key: Option<&str>,
) -> Result<Reply, ApiError> {
    let url = format!("{BASE}{path}");
    let bytes = serde_json::to_vec(body).map_err(|e| ApiError::Malformed(e.to_string()))?;
    let (status, text) = client
        .post_with_token(
            Audience::AuthApi,
            &url,
            access_token,
            bytes,
            idempotency_key,
        )
        .await?;
    if status == 401 {
        return Err(ApiError::Unauthorized);
    }
    Ok(Reply {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
    })
}

/// Starts a product of `family` with `body` (from [`Family::start_body`]).
/// `idempotency_key` is made once per confirmed start and sent again on a
/// retry of it.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] for a refused session, or the transport's
/// error. A refusal user-api answers (no credit, no stock, no card
/// authorisation) is a [`Reply`] with its status.
pub async fn start(
    client: &AuthClient,
    access_token: &SecretString,
    family: &Family,
    body: &Value,
    idempotency_key: &str,
) -> Result<Reply, ApiError> {
    let key = family.idempotent.then_some(idempotency_key);
    post(client, access_token, family.start_path, body, key).await
}

/// Ends the product of `family` user-api knows as `id`.
///
/// # Errors
///
/// As [`start`].
pub async fn end(
    client: &AuthClient,
    access_token: &SecretString,
    family: &Family,
    id: &Value,
) -> Result<Reply, ApiError> {
    let mut body = Map::new();
    body.insert(family.end_id.to_owned(), id.clone());
    post(
        client,
        access_token,
        family.end_path,
        &Value::Object(body),
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{FAMILIES, find};
    use serde_json::json;

    #[test]
    fn every_route_is_user_apis_and_every_family_is_found_by_name() {
        for f in FAMILIES {
            assert!(
                f.start_path.starts_with("/v3/") && f.start_path.contains("/start-hourly"),
                "{}",
                f.name
            );
            assert!(
                f.end_path.starts_with("/v3/") && f.end_path.ends_with("/end-hourly"),
                "{}",
                f.name
            );
            assert_eq!(find(f.name), Some(f));
        }
        assert_eq!(find("nope"), None);
        assert_eq!(
            super::for_product_type("bare_metal").map(|f| f.name),
            Some("baremetal")
        );
        assert_eq!(super::for_product_type("storage"), None);
    }

    #[test]
    fn a_start_body_has_the_required_fields_and_nothing_else() {
        let vps = find("vps").expect("vps");
        let ok = json!({ "productId": "prod_x", "region": "frankfurt" });
        assert_eq!(
            vps.start_body(ok.as_object().expect("object")),
            Ok(ok.clone())
        );
        let missing = json!({ "productId": "prod_x" });
        assert!(
            vps.start_body(missing.as_object().expect("object"))
                .is_err()
        );
        let extra = json!({ "productId": "prod_x", "region": "frankfurt", "price": 0 });
        assert!(vps.start_body(extra.as_object().expect("object")).is_err());
    }
}
