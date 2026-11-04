// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The kinds of Arc RPC node erpc runs, and the onboarding peers a
//! provider node is given.
//!
//! - **full**: follows the chain through the public relays and keeps the
//!   last 237,600 blocks of history (`--full`).
//! - **archive**: follows the same way and keeps everything.
//! - **provider**: an RPC provider (relay) node Arc has onboarded. It peers
//!   with Arc's sentries instead of following the relays, keeps what full
//!   keeps, and serves only the public namespaces.

use std::net::Ipv4Addr;

/// What kind of Arc RPC node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcType {
    /// Follows the relays; pruned to the `--full` preset.
    Full,
    /// Follows the relays; keeps every block's history and state.
    Archive,
    /// Peers with Arc's sentries; pruned to the `--full` preset.
    Provider,
}

impl RpcType {
    /// Every kind, as the flag takes them.
    pub const NAMES: [&'static str; 3] = ["full", "archive", "provider"];

    /// The kind `name` names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "full" => Some(Self::Full),
            "archive" => Some(Self::Archive),
            "provider" => Some(Self::Provider),
            _ => None,
        }
    }

    /// The name the flag and the inventory use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Archive => "archive",
            Self::Provider => "provider",
        }
    }

    /// The `arc-snapshots --el-profile` that matches how the node prunes.
    #[must_use]
    pub fn el_profile(self) -> &'static str {
        match self {
            Self::Full | Self::Provider => "full",
            Self::Archive => "archive",
        }
    }

    /// Whether `debug` and `trace` may be served: never on a provider node,
    /// whose onboarding rules forbid them.
    #[must_use]
    pub fn allows_debug_api(self) -> bool {
        self != Self::Provider
    }
}

/// Checks an execution-layer peer from onboarding:
/// `enode://<128 hex>@<IPv4>:<port>`.
///
/// # Errors
/// What is wrong with it.
pub fn check_enode(enode: &str) -> Result<(), String> {
    let bad = || format!("{enode:?} is not an enode URL: enode://<128 hex digits>@<IPv4>:<port>");
    let rest = enode.strip_prefix("enode://").ok_or_else(bad)?;
    let (id, at) = rest.split_once('@').ok_or_else(bad)?;
    let (host, port) = at.split_once(':').ok_or_else(bad)?;
    let id_ok = id.len() == 128 && id.bytes().all(|b| b.is_ascii_hexdigit());
    let port_ok = port.parse::<u16>().is_ok_and(|p| p > 0);
    if id_ok && host.parse::<Ipv4Addr>().is_ok() && port_ok {
        Ok(())
    } else {
        Err(bad())
    }
}

/// The address of a consensus-layer peer from onboarding,
/// `/ip4/<IPv4>/tcp/<port>/p2p/<peer id>`, for the firewall to admit.
///
/// # Errors
/// What is wrong with it.
pub fn sentry_address(multiaddr: &str) -> Result<Ipv4Addr, String> {
    let bad =
        || format!("{multiaddr:?} is not a sentry multiaddr: /ip4/<IPv4>/tcp/<port>/p2p/<peer id>");
    let parts: Vec<&str> = multiaddr.split('/').collect();
    match parts.as_slice() {
        ["", "ip4", ip, "tcp", port, "p2p", id]
            if port.parse::<u16>().is_ok_and(|p| p > 0)
                && !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            ip.parse().map_err(|_| bad())
        }
        _ => Err(bad()),
    }
}

#[cfg(test)]
mod tests {
    use super::{RpcType, check_enode, sentry_address};

    #[test]
    fn every_kind_reads_back_by_its_name() {
        for name in RpcType::NAMES {
            assert_eq!(RpcType::parse(name).map(RpcType::as_str), Some(name));
        }
        assert_eq!(RpcType::parse("Full"), None);
        assert_eq!(RpcType::Archive.el_profile(), "archive");
        assert_eq!(RpcType::Provider.el_profile(), "full");
        assert!(!RpcType::Provider.allows_debug_api());
        assert!(RpcType::Archive.allows_debug_api());
    }

    #[test]
    fn an_enode_needs_its_id_an_ipv4_address_and_a_port() {
        let id = "ab".repeat(64);
        assert!(check_enode(&format!("enode://{id}@192.0.2.7:30303")).is_ok());
        for bad in [
            format!("enode://{id}@192.0.2.7"),
            format!("enode://{id}@sentry.example:30303"),
            format!("enode://{}@192.0.2.7:30303", "ab".repeat(63)),
            format!("enode://{id}@192.0.2.7:0"),
            format!("{id}@192.0.2.7:30303"),
            format!("enode://{id}@192.0.2.7:30303 --http.api=all"),
        ] {
            assert!(check_enode(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_sentry_multiaddr_gives_the_address_to_admit() {
        assert_eq!(
            sentry_address("/ip4/192.0.2.8/tcp/27000/p2p/12D3KooWabc"),
            Ok("192.0.2.8".parse().expect("ip"))
        );
        for bad in [
            "/dns4/sentry.example/tcp/27000/p2p/12D3KooWabc",
            "/ip4/192.0.2.8/tcp/27000",
            "/ip4/192.0.2.8/udp/27000/p2p/12D3KooWabc",
            "/ip4/192.0.2.8/tcp/27000/p2p/12D3 Koo",
            "/ip4/999.0.2.8/tcp/27000/p2p/12D3KooWabc",
        ] {
            assert!(sentry_address(bad).is_err(), "{bad}");
        }
    }
}
