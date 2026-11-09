// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Source-qualified core-cell roles and operator-supplied static peer topology.

use std::net::Ipv4Addr;

/// A separate dedicated host in the documented core-cell topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Consensus node; administrative admission remains external.
    Consensus,
    /// Proxy node connecting its CN and another core-cell PN.
    Proxy,
}
impl Kind {
    /// Parse the native node-kind selector.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "cn" => Some(Self::Consensus),
            "pn" => Some(Self::Proxy),
            _ => None,
        }
    }
    /// Native role name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Consensus => "cn",
            Self::Proxy => "pn",
        }
    }
    /// Executable present in the same reviewed official image.
    #[must_use]
    pub const fn executable(self) -> &'static str {
        match self {
            Self::Consensus => "kcn",
            Self::Proxy => "kpn",
        }
    }
    /// Recommended logical CPU count (CN16 cores/32 threads; PN8/16).
    #[must_use]
    pub const fn threads(self) -> u32 {
        match self {
            Self::Consensus => 32,
            Self::Proxy => 16,
        }
    }
    /// Minimum reported memory after allowing operating-system overhead.
    #[must_use]
    pub const fn memory_kib(self) -> u64 {
        match self {
            Self::Consensus => 120_000_000,
            Self::Proxy => 60_000_000,
        }
    }
}

/// A validated public peer identity and explicit numeric IPv4 endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Uncompressed secp256k1 public identity, without the SEC1 prefix.
    pub identity: String,
    /// Explicit route supplied by the approved core-cell operator.
    pub address: Ipv4Addr,
    /// Native P2P port.
    pub port: u16,
    /// Declared CN/PN connection kind.
    pub kind: Kind,
}
impl Peer {
    /// Accept the documented KNI static-peer shape, without credentials/DNS.
    ///
    /// # Errors
    /// Rejects malformed public keys, ambiguous endpoints, other node kinds and
    /// unspecified/loopback/multicast/broadcast addresses. Private core-cell
    /// subnets are permitted because these are explicit P2P routes, not egress
    /// credential destinations.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value.len() > 256 {
            return Err("Kaia static peer exceeds its bound");
        }
        let (identity, endpoint) = value
            .strip_prefix("kni://")
            .and_then(|v| v.split_once('@'))
            .ok_or("expected a role-qualified Kaia KNI peer")?;
        if identity.len() != 128
            || !identity
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return Err("invalid Kaia peer public identity");
        }
        let mut point = [0u8; 65];
        point[0] = 4;
        for (index, pair) in identity.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let digit = |v: u8| if v <= b'9' { v - b'0' } else { v - b'a' + 10 };
            point[index + 1] = digit(pair[0]) * 16 + digit(pair[1]);
        }
        k256::PublicKey::from_sec1_bytes(&point)
            .map_err(|_| "Kaia peer public identity is not on the native curve")?;
        let (endpoint, query) = endpoint
            .split_once('?')
            .ok_or("Kaia peer kind is required")?;
        let kind = query
            .strip_prefix("discport=0&ntype=")
            .and_then(Kind::parse)
            .ok_or("expected discport=0 and an explicit CN/PN peer kind")?;
        let (address, port) = endpoint
            .split_once(':')
            .ok_or("Kaia static peer requires its IPv4 port")?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| "Kaia core-cell peers require numeric IPv4 addresses")?;
        let port: u16 = port.parse().map_err(|_| "invalid Kaia peer port")?;
        if port == 0
            || address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address.is_broadcast()
            || address.is_link_local()
            || address.octets()[0] == 0
            || address.octets()[0] >= 240
        {
            return Err("unsupported Kaia peer endpoint");
        }
        Ok(Self {
            identity: identity.into(),
            address,
            port,
            kind,
        })
    }
    /// Canonical native static-node record.
    #[must_use]
    pub fn uri(&self) -> String {
        format!(
            "kni://{}@{}:{}?discport=0&ntype={}",
            self.identity,
            self.address,
            self.port,
            self.kind.name()
        )
    }
}

/// Require the documented CN and PN links without inventing peers or admission.
/// # Errors
/// Refuses incomplete topology, duplicate identities/routes and self-peering.
pub fn peers(values: &[String], own_identity: Option<&str>) -> Result<Vec<Peer>, &'static str> {
    if !(2..=64).contains(&values.len()) {
        return Err("Kaia core cells require between two and 64 approved static peers");
    }
    let parsed = values
        .iter()
        .map(|v| Peer::parse(v))
        .collect::<Result<Vec<_>, _>>()?;
    let mut identities = std::collections::BTreeSet::new();
    let mut routes = std::collections::BTreeSet::new();
    for peer in &parsed {
        if own_identity == Some(peer.identity.as_str())
            || !identities.insert(peer.identity.as_str())
            || !routes.insert((peer.address, peer.port))
        {
            return Err("Kaia static peers cannot repeat an identity, route or this node");
        }
    }
    if !parsed.iter().any(|v| v.kind == Kind::Consensus)
        || !parsed.iter().any(|v| v.kind == Kind::Proxy)
    {
        return Err("the supported core-cell topology requires both a CN and a PN peer");
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    fn peer(seed: &[u8], address: &str, kind: &str) -> String {
        let scalar = Sha256::digest(seed);
        let key = k256::ecdsa::SigningKey::from_slice(&scalar).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let mut public = String::new();
        for byte in &point.as_bytes()[1..] {
            write!(&mut public, "{byte:02x}").unwrap();
        }
        format!("kni://{public}@{address}?discport=0&ntype={kind}")
    }

    #[test]
    fn read_only_staking_getter_selectors_match_the_pinned_solidity_storage_api() {
        use sha3::Keccak256;
        for (name, expected) in [
            ("gcId()", [0x6d, 0x27, 0x14, 0xdb]),
            ("nodeId()", [0x13, 0x9d, 0x7f, 0xed]),
        ] {
            assert_eq!(&Keccak256::digest(name.as_bytes())[..4], &expected);
        }
    }

    #[test]
    fn explicit_private_routes_require_both_peer_roles_and_unique_identities() {
        let cn = peer(b"public CN fixture", "10.1.2.3:32323", "cn");
        let pn = peer(b"public PN fixture", "10.1.2.4:32323", "pn");
        let topology = peers(&[cn.clone(), pn.clone()], None).unwrap();
        assert_eq!(topology[0].uri(), cn);
        assert_eq!(topology[1].kind, Kind::Proxy);
        assert!(peers(std::slice::from_ref(&cn), None).is_err());
        assert!(peers(&[cn.clone(), cn.clone()], None).is_err());
        assert!(peers(&[cn.clone(), pn], Some(&topology[0].identity)).is_err());
        let repeated_route = peer(b"public second fixture", "10.1.2.3:32323", "pn");
        assert!(peers(&[cn, repeated_route], None).is_err());
    }

    #[test]
    fn malformed_or_ambiguous_peer_routes_cannot_reach_native_configuration() {
        for route in [
            "0.0.0.1:32323",
            "127.0.0.1:32323",
            "169.254.1.1:32323",
            "224.1.1.1:32323",
            "240.1.1.1:32323",
            "255.255.255.255:32323",
            "10.1.2.3:0",
            "10.1.2.3:65536",
            "localhost:32323",
            "[::1]:32323",
        ] {
            assert!(Peer::parse(&peer(b"public route fixture", route, "cn")).is_err());
        }
        let good = peer(b"public route fixture", "10.1.2.3:32323", "cn");
        for bad in [
            good.replace("ntype=cn", "ntype=en"),
            good.replace("discport=0", "discport=32323"),
            format!("{good}&unexpected=value"),
            good.replace("kni://", "enode://"),
        ] {
            assert!(Peer::parse(&bad).is_err());
        }
        assert!(
            Peer::parse(&format!(
                "kni://{}@10.1.2.3:32323?discport=0&ntype=cn",
                "0".repeat(128)
            ))
            .is_err()
        );
    }
}
