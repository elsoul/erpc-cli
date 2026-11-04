// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Addresses as `erpc.toml` writes them: a firewall entry is one address or
//! one network, IPv4 or IPv6, and a host is an address or a DNS name.

use core::fmt;
use core::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// One firewall entry: `198.51.100.7`, `198.51.100.0/24`, `2001:db8::/32`.
/// A bare address is the network of that one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    address: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses an address with an optional `/prefix`.
    ///
    /// Host bits under the prefix must be zero (`10.0.0.1/24` is refused),
    /// because a list that says one thing and allows another is how a
    /// firewall ends up wider than its owner thinks.
    ///
    /// # Errors
    ///
    /// A message saying what is wrong with `raw`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let (address, prefix) = match raw.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (raw, None),
        };
        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("`{raw}` is not an IPv4 or IPv6 address"))?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("`{raw}` has a prefix that is not 0 to {max}"))?,
        };
        if prefix == 0 {
            return Err(format!(
                "`{raw}` allows every address; list the addresses that need access instead"
            ));
        }
        let cidr = Self { address, prefix };
        if cidr.network() != address {
            return Err(format!(
                "`{raw}` has host bits set under its prefix; did you mean {}/{prefix}?",
                cidr.network()
            ));
        }
        Ok(cidr)
    }

    /// The address part.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// The prefix length.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is inside this network.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    fn network(&self) -> IpAddr {
        match self.address {
            IpAddr::V4(a) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V4((u32::from(a) & mask).into())
            }
            IpAddr::V6(a) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V6((u128::from(a) & mask).into())
            }
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

impl Serialize for Cidr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Whether `host` is usable as a server address: an IP address, or a DNS
/// name of letters, digits, hyphens and dots. Anything else -- a user part,
/// a port, a path, an option for ssh -- is refused here rather than passed on.
#[must_use]
pub fn is_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::{Cidr, is_host};

    #[test]
    fn a_bare_address_is_its_own_network() {
        let one = Cidr::parse("198.51.100.7").expect("valid");
        assert_eq!(one.to_string(), "198.51.100.7/32");
        assert!(one.contains("198.51.100.7".parse().expect("ip")));
        assert!(!one.contains("198.51.100.8".parse().expect("ip")));
        assert_eq!(
            Cidr::parse("2001:db8::1").expect("valid").to_string(),
            "2001:db8::1/128"
        );
    }

    #[test]
    fn a_network_contains_its_addresses_only() {
        let net = Cidr::parse("10.1.0.0/16").expect("valid");
        assert!(net.contains("10.1.255.3".parse().expect("ip")));
        assert!(!net.contains("10.2.0.1".parse().expect("ip")));
        assert!(!net.contains("::1".parse().expect("ip")));
    }

    #[test]
    fn wide_or_ambiguous_entries_are_refused() {
        for bad in [
            "0.0.0.0/0",
            "::/0",
            "10.0.0.1/24",
            "10.0.0.0/33",
            "10.0.0.0/x",
            "example.com",
            "",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hosts_are_addresses_or_dns_names() {
        for good in ["203.0.113.10", "2001:db8::10", "node-1.example.com"] {
            assert!(is_host(good), "{good}");
        }
        for bad in [
            "root@203.0.113.10",
            "203.0.113.10:22",
            "-oProxyCommand=x",
            "a..b",
            "a b",
            "",
        ] {
            assert!(!is_host(bad), "{bad}");
        }
    }
}
