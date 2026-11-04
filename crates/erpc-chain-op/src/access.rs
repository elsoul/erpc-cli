// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Canonical network literals for nftables and independent application ACLs.
use std::net::IpAddr;

/// Parse exact IPv4/IPv6 addresses or networks, without echoing rejected inputs.
/// # Errors
/// Malformed input, host bits and forbidden world-wide prefixes fail closed.
pub fn list(values: &[String], allow_open: bool) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let (address, bits) = value
            .split_once('/')
            .map_or((value, None), |(a, b)| (a, Some(b)));
        let ip: IpAddr = address
            .parse()
            .map_err(|_| "access rule is not a numeric address or CIDR")?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let bits: u8 = bits.map_or(Ok(max), |bits| {
            bits.parse().map_err(|_| "invalid access prefix")
        })?;
        if bits > max || (bits == 0 && !allow_open) {
            return Err("access prefix is outside the permitted range".into());
        }
        let number = match ip {
            IpAddr::V4(ip) => u128::from(u32::from(ip)),
            IpAddr::V6(ip) => u128::from(ip),
        };
        let host_bits = max - bits;
        let mask = if host_bits == 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        if number & mask != 0 {
            return Err("access CIDR has host bits set".into());
        }
        let canonical = if bits == max {
            ip.to_string()
        } else {
            format!("{ip}/{bits}")
        };
        if !result.contains(&canonical) {
            result.push(canonical);
        }
    }
    Ok(result)
}

/// Require an explicit public IPv4 address for the supported peer advertisement.
/// # Errors
/// Hostnames, private/loopback/documentation addresses and IPv6 are not inferred.
pub fn advertise(value: &str) -> Result<String, String> {
    let ip: std::net::Ipv4Addr = value
        .parse()
        .map_err(|_| "peer advertisement requires a public numeric IPv4 address")?;
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        || (ip.octets()[0] == 198 && (18..=19).contains(&ip.octets()[1]))
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240
    {
        return Err("peer advertisement requires a public numeric IPv4 address".into());
    }
    Ok(ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::{advertise, list};
    #[test]
    fn cidrs_cannot_inject_templates_or_silently_widen_their_networks() {
        for value in [
            "1.2.3.4; accept",
            "10.0.0.1/24",
            "2001:db8::1/64",
            "1.2.3.4/33",
            "::/129",
            "https://github.com",
        ] {
            assert!(list(&[value.into()], true).is_err());
        }
        assert_eq!(
            list(&["2001:db8::/32".into(), "2001:db8::1/128".into()], false).expect("valid CIDRs"),
            ["2001:db8::/32", "2001:db8::1"]
        );
        assert!(list(&["::/0".into()], false).is_err());
        assert!(list(&["0.0.0.0/0".into()], false).is_err());
        assert!(list(&["::/0".into()], true).is_ok());
    }
    #[test]
    fn peer_advertisement_never_resolves_a_name_or_uses_private_space() {
        for value in [
            "localhost",
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "2001:db8::1",
            "224.0.0.1",
            "100.64.0.1",
            "198.18.0.1",
        ] {
            assert!(advertise(value).is_err());
        }
        assert_eq!(advertise("8.8.8.8").expect("public fixture"), "8.8.8.8");
    }
}
