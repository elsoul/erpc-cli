// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! ERPC UDP Forwarding: the leader's raw shreds, sent over UDP from a node
//! in a region to an address and port of the customer's own. It comes as
//! two products, Standard and Premium, each its own hourly family with its
//! own list of the account's lines and its own route that points one. A
//! line is one product or the other by the list it is in.
//!
//! `erpc worker deploy --udp` and `erpc ai`'s `point_udp_line` both go by
//! this table: the routes are in [`crate::account`] and [`crate::hourly`].

use serde_json::Value;

use crate::account;

/// One of the two UDP Forwarding products, as user-api sells and lists it.
#[derive(Debug, PartialEq, Eq)]
pub struct Family {
    /// The hourly family that starts one.
    pub family: &'static str,
    /// What the operator reads.
    pub name: &'static str,
    /// Its `productKey` in a `my` list, and its `productType` in the
    /// credit snapshot, which ending it takes.
    pub product_type: &'static str,
    /// Where the account's lines of it are listed.
    pub my_url: &'static str,
    /// Where one is pointed at a server.
    pub destination_url: &'static str,
    /// The regions it sends from.
    pub regions: &'static [&'static str],
    /// Whether a line is charged from its start, pointed or not (Standard),
    /// or only once it is pointed and active (Premium).
    pub charged_from_start: bool,
}

/// Standard first: the cheaper one, and the one every account is sold.
/// The catalogue says which are on sale to the account; nothing is started
/// from this table alone.
pub const FAMILIES: [Family; 2] = [
    Family {
        family: "udp-forwarding",
        name: "UDP Forwarding Standard",
        product_type: "one_hop_direct",
        my_url: account::UDP_FORWARDING_MY_URL,
        destination_url: account::UDP_FORWARDING_DESTINATION_URL,
        regions: &[
            "amsterdam",
            "frankfurt",
            "london",
            "ny",
            "tokyo",
            "singapore",
        ],
        charged_from_start: true,
    },
    Family {
        family: "udp-forwarding-premium",
        name: "UDP Forwarding Premium",
        product_type: "udp_forwarding_premium",
        my_url: account::UDP_FORWARDING_PREMIUM_MY_URL,
        destination_url: account::UDP_FORWARDING_PREMIUM_DESTINATION_URL,
        regions: &[
            "amsterdam",
            "frankfurt",
            "london",
            "ny",
            "tokyo",
            "singapore",
            "dublin",
        ],
        charged_from_start: false,
    },
];

/// How both families are named together, where a plan is not found.
pub const FAMILY_NAMES: &str = "udp-forwarding or udp-forwarding-premium";

/// Every region either product sends from, each once, Standard's first.
#[must_use]
pub fn regions() -> Vec<&'static str> {
    let mut all: Vec<&'static str> = Vec::new();
    for region in FAMILIES.iter().flat_map(|f| f.regions.iter().copied()) {
        if !all.contains(&region) {
            all.push(region);
        }
    }
    all
}

/// The product whose `productKey` (in a `my` list) or `productType` (in
/// the credit snapshot) is `key`.
#[must_use]
pub fn for_product_type(key: &str) -> Option<&'static Family> {
    FAMILIES.iter().find(|f| f.product_type == key)
}

/// Which product a `my` row is, by its `productKey`.
#[must_use]
pub fn family_of(row: &Value) -> Option<&'static Family> {
    for_product_type(row["productKey"].as_str()?)
}

/// Whether `row` is line `id`'s: user-api gives an id as a number or a
/// string, by route.
#[must_use]
pub fn is_row_of(row: &Value, id: &str) -> bool {
    row["id"].as_i64().map(|n| n.to_string()).as_deref() == Some(id)
        || row["id"].as_str() == Some(id)
}

/// Whether `ip` can be where a UDP Forwarding line sends: a public IPv4
/// address, as user-api takes one. Not unspecified or `0.0.0.0/8`,
/// loopback, private, shared (`100.64.0.0/10`, which carrier NAT and
/// Tailscale use), link-local, multicast, broadcast, nor one of the other
/// special-purpose ranges: IETF protocol assignments (`192.0.0.0/24`), the
/// three documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
/// `203.0.113.0/24`), 6to4 relay anycast (`192.88.99.0/24`), benchmarking
/// (`198.18.0.0/15`) and the reserved `240.0.0.0/4`. user-api refuses
/// those (`INVALID_DESTINATION`), and a Standard line is charged from its
/// start, so `deploy --udp` and `erpc ai` refuse them before anything is
/// started. user-api can still refuse an address that passes, for reasons
/// of its own that no check here can know; its code then says why.
#[must_use]
pub fn is_public_destination(ip: std::net::Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    let special = SPECIAL_PURPOSE
        .iter()
        .any(|&(net, len)| bits >> (32 - len) == u32::from_be_bytes(net) >> (32 - len));
    !(special || ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_multicast())
}

/// The ranges [`is_public_destination`] refuses beside loopback, private,
/// link-local and multicast, as network and prefix length. `240.0.0.0/4`
/// holds the broadcast address.
const SPECIAL_PURPOSE: [([u8; 4], u32); 9] = [
    ([0, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 88, 99, 0], 24),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([240, 0, 0, 0], 4),
];

/// Whether a refusal to point a line may pass when it is tried again: a
/// region's (`REGION_DOWN`, or a code ending in `REGION_UNAVAILABLE`), a
/// conflict, a change too soon or a request timed out (409, 429, 408),
/// user-api failing or not
/// answering (a 5xx, no reply, one it cannot read), or a session to sign in
/// again. Any other refusal of the request (`INVALID_DESTINATION`, a route
/// closed to the sign-in, a 4xx with no reason) comes back the same.
#[must_use]
pub fn pointing_may_pass_later(error: &crate::ApiError) -> bool {
    use crate::ApiError;
    let busy = |status: u16| status >= 500 || matches!(status, 408 | 409 | 429);
    match error {
        ApiError::Refused { status, message } => {
            busy(*status)
                || message.contains("REGION_DOWN")
                || message.contains("REGION_UNAVAILABLE")
        }
        ApiError::Status(status) => busy(*status),
        ApiError::Http(_) | ApiError::Malformed(_) | ApiError::Unauthorized => true,
        _ => false,
    }
}

/// The rows of a `my` reply (`data[]`); `None` when it has no list, which
/// says nothing about the account's lines.
#[must_use]
pub fn rows(reply: &Value) -> Option<&[Value]> {
    reply["data"].as_array().map(Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        FAMILIES, family_of, for_product_type, is_public_destination, is_row_of,
        pointing_may_pass_later, regions, rows,
    };

    #[test]
    fn each_product_is_found_by_its_key_and_lists_its_own_regions() {
        assert_eq!(
            for_product_type("one_hop_direct").map(|f| f.family),
            Some("udp-forwarding")
        );
        assert_eq!(
            family_of(&json!({ "productKey": "udp_forwarding_premium" })).map(|f| f.name),
            Some("UDP Forwarding Premium")
        );
        assert!(family_of(&json!({ "productKey": "grpc" })).is_none());
        assert!(family_of(&json!({})).is_none());
        // Dublin is Premium's alone; every region once.
        assert!(!FAMILIES[0].regions.contains(&"dublin"));
        assert_eq!(regions().len(), 7);
        assert_eq!(regions().last(), Some(&"dublin"));
        // Standard is charged from its start, Premium once it is pointed.
        assert!(FAMILIES[0].charged_from_start && !FAMILIES[1].charged_from_start);
        // Both families are ones erpc knows how to start and end.
        for f in &FAMILIES {
            assert!(crate::hourly::find(f.family).is_some(), "{}", f.family);
            assert_eq!(
                crate::hourly::for_product_type(f.product_type).map(|h| h.name),
                Some(f.family)
            );
            assert!(crate::account::URLS.contains(&f.my_url));
            assert!(crate::account::URLS.contains(&f.destination_url));
        }
    }

    #[test]
    fn only_a_public_ipv4_address_is_a_destination() {
        // The documentation ranges are refused like the rest, so well-known
        // public resolvers stand for a public address here.
        for public in [
            "8.8.8.8",
            "1.1.1.1",
            "100.128.0.1",
            "172.32.0.1",
            "198.20.0.1",
        ] {
            assert!(
                is_public_destination(public.parse().expect("ip")),
                "{public}"
            );
        }
        for not in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.2",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.10",
            "192.88.99.1",
            "198.18.0.1",
            "198.19.255.254",
            "240.0.0.1",
        ] {
            assert!(!is_public_destination(not.parse().expect("ip")), "{not}");
        }
    }

    #[test]
    fn a_pointing_refused_for_good_is_told_from_one_that_may_pass() {
        use crate::ApiError;
        let refused = |status, message: &str| ApiError::Refused {
            status,
            message: message.to_owned(),
        };
        for later in [
            refused(503, "UDP_FORWARDING_REGION_UNAVAILABLE: busy"),
            refused(400, "REGION_DOWN: frankfurt"),
            refused(400, "UDP_FORWARDING_PREMIUM_REGION_UNAVAILABLE: dublin"),
            ApiError::Status(408),
            ApiError::Malformed("not JSON".to_owned()),
            ApiError::Http(erpc_auth::HttpError::Transport {
                host: "user-api",
                reason: "timed out".to_owned(),
            }),
            refused(409, "UDP_FORWARDING_CONFLICT: a change is under way"),
            refused(429, "too soon"),
            refused(502, "upstream"),
            ApiError::Status(500),
            ApiError::Unauthorized,
        ] {
            assert!(pointing_may_pass_later(&later), "{later}");
        }
        for never in [
            refused(400, "INVALID_DESTINATION: not a public address"),
            refused(403, "ROUTE_NOT_ALLOWED: not for this sign-in"),
            ApiError::Status(400),
            ApiError::Status(403),
            ApiError::Status(404),
        ] {
            assert!(!pointing_may_pass_later(&never), "{never}");
        }
    }

    #[test]
    fn a_row_is_found_by_its_id_as_a_number_or_a_string() {
        assert!(is_row_of(&json!({ "id": 42 }), "42"));
        assert!(is_row_of(&json!({ "id": "42" }), "42"));
        assert!(!is_row_of(&json!({ "id": 43 }), "42"));
        assert!(!is_row_of(&json!({}), "42"));
        assert_eq!(rows(&json!({ "data": [] })).map(<[_]>::len), Some(0));
        assert!(rows(&json!({ "message": [] })).is_none());
    }
}
