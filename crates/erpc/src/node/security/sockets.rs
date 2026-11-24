// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The kernel's socket tables: every listening TCP socket and every bound,
//! unconnected UDP socket of the current network namespace.

use std::io::{BufRead as _, BufReader, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use erpc_api::security_check::{Bind, Proto};

/// A socket as the table states it, before its program is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Socket {
    pub(super) proto: Proto,
    pub(super) port: NonZeroU16,
    pub(super) bind: Bind,
    pub(super) uid: u32,
    pub(super) inode: u64,
}

#[derive(Clone, Copy)]
pub(super) enum Family {
    V4,
    V6,
}

// Bounds resource use; a larger table is reported as partly read.
const TABLE_LIMIT: u64 = 16 * 1024 * 1024;

const TCP_LISTEN: u8 = 0x0a;
const UDP_UNCONNECTED: u8 = 0x07;

/// The sockets of one table, or `None` when the table cannot be read
/// completely.
pub(super) fn read_table(table: impl Read, proto: Proto, family: Family) -> Option<Vec<Socket>> {
    let mut reader = BufReader::new(table.take(TABLE_LIMIT + 1));
    let mut line = String::new();
    let mut read = reader.read_line(&mut line).ok()?;
    if read as u64 > TABLE_LIMIT || !line.ends_with('\n') || !header(&line) {
        return None;
    }
    let mut sockets = Vec::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).ok()?;
        if bytes == 0 {
            return Some(sockets);
        }
        read += bytes;
        if read as u64 > TABLE_LIMIT || !line.ends_with('\n') {
            return None;
        }
        if let Row::Listening(socket) = row(&line, proto, family)? {
            sockets.push(socket);
        }
    }
}

fn header(line: &str) -> bool {
    let mut columns = line.split_ascii_whitespace();
    columns.next() == Some("sl")
        && columns.next() == Some("local_address")
        && matches!(columns.next(), Some("rem_address" | "remote_address"))
        && [
            "st", "tx_queue", "rx_queue", "tr", "tm->when", "retrnsmt", "uid", "timeout", "inode",
        ]
        .iter()
        .all(|expected| columns.next() == Some(expected))
}

/// What a readable row holds.
enum Row {
    Listening(Socket),
    Other,
}

/// One row, or `None` for a row that cannot be read.
fn row(line: &str, proto: Proto, family: Family) -> Option<Row> {
    let mut fields = line.split_ascii_whitespace();
    let _slot = fields.next()?.strip_suffix(':')?.parse::<u32>().ok()?;
    let (address, port) = fields.next()?.split_once(':')?;
    let bind = bind(address, family)?;
    let port = u16::try_from(hex(port, 4)?).ok()?;
    let (remote, remote_port) = fields.next()?.split_once(':')?;
    let state = u8::try_from(hex(fields.next()?, 2)?).ok()?;
    let _queues = fields.next()?;
    let _timer = fields.next()?;
    let _retransmits = fields.next()?;
    let uid = fields.next()?.parse::<u32>().ok()?;
    let _timeout = fields.next()?;
    let inode = fields.next()?.parse::<u64>().ok()?;
    let unconnected = remote.bytes().all(|b| b == b'0') && remote_port == "0000";
    let listening = match proto {
        Proto::Tcp => state == TCP_LISTEN,
        Proto::Udp => state == UDP_UNCONNECTED && unconnected,
    };
    let Some(port) = NonZeroU16::new(port).filter(|_| listening) else {
        return Some(Row::Other);
    };
    Some(Row::Listening(Socket {
        proto,
        port,
        bind,
        uid,
        inode,
    }))
}

fn hex(s: &str, width: usize) -> Option<u32> {
    (s.len() == width && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(s, 16).ok())
        .flatten()
}

fn bind(address: &str, family: Family) -> Option<Bind> {
    match family {
        Family::V4 => Some(classify_v4(Ipv4Addr::from(hex(address, 8)?.to_ne_bytes()))),
        Family::V6 => {
            if address.len() != 32 || !address.is_ascii() {
                return None;
            }
            // Linux prints IPv6 addresses as four native-endian words.
            let mut octets = [0; 16];
            for (index, word) in octets.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let start = index * 8;
                word.copy_from_slice(&hex(&address[start..start + 8], 8)?.to_ne_bytes());
            }
            Some(classify_v6(Ipv6Addr::from(octets)))
        }
    }
}

pub(super) fn classify_v4(address: Ipv4Addr) -> Bind {
    let [a, b, ..] = address.octets();
    if address.is_unspecified() {
        Bind::Wildcard
    } else if address.is_loopback() {
        Bind::Loopback
    } else if address.is_link_local() {
        Bind::LinkLocal
    } else if address.is_private() || (a == 100 && (64..128).contains(&b)) {
        Bind::Private
    } else {
        Bind::Public
    }
}

pub(super) fn classify_v6(address: Ipv6Addr) -> Bind {
    if let Some(v4) = address.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let first = address.segments()[0];
    if address.is_unspecified() {
        Bind::Wildcard
    } else if address.is_loopback() {
        Bind::Loopback
    } else if first & 0xffc0 == 0xfe80 {
        Bind::LinkLocal
    } else if first & 0xfe00 == 0xfc00 {
        Bind::Private
    } else {
        Bind::Public
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use erpc_api::security_check::{Bind, Proto};

    use super::{Family, read_table};

    pub(in crate::node::security) const TCP4: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    pub(in crate::node::security) const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    pub(in crate::node::security) const UDP4: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";

    pub(in crate::node::security) fn v4(address: Ipv4Addr) -> String {
        format!("{:08X}", u32::from_ne_bytes(address.octets()))
    }

    pub(in crate::node::security) fn v6(address: Ipv6Addr) -> String {
        use std::fmt::Write as _;
        let mut words = String::new();
        for &[a, b, c, d] in address.octets().as_chunks::<4>().0 {
            let _ = write!(words, "{:08X}", u32::from_ne_bytes([a, b, c, d]));
        }
        words
    }

    pub(in crate::node::security) fn row(
        address: &str,
        port: u16,
        state: u8,
        uid: u32,
        inode: u64,
    ) -> String {
        let zero = "0".repeat(address.len());
        format!(
            "   0: {address}:{port:04X} {zero}:0000 {state:02X} 00000000:00000000 00:00000000 00000000 {uid:>5} 0 {inode} 1 0000000000000000 100 0 0 10 0\n"
        )
    }

    fn binds(table: &str, proto: Proto, family: Family) -> Option<Vec<(u16, Bind, u32, u64)>> {
        read_table(table.as_bytes(), proto, family).map(|sockets| {
            sockets
                .into_iter()
                .map(|s| (s.port.get(), s.bind, s.uid, s.inode))
                .collect()
        })
    }

    #[test]
    fn listening_tcp_sockets_on_any_port_are_classified_by_address() {
        let table = format!(
            "{TCP4}{}{}{}{}{}{}",
            row(&v4(Ipv4Addr::UNSPECIFIED), 18899, 0x0a, 1001, 11),
            row(&v4(Ipv4Addr::new(127, 0, 0, 53)), 53, 0x0a, 0, 12),
            row(&v4(Ipv4Addr::new(10, 1, 2, 3)), 9100, 0x0a, 110, 13),
            row(&v4(Ipv4Addr::new(100, 100, 1, 1)), 9101, 0x0a, 110, 14),
            row(&v4(Ipv4Addr::new(203, 0, 113, 7)), 443, 0x0a, 0, 15),
            row(&v4(Ipv4Addr::UNSPECIFIED), 22, 0x01, 0, 16),
        );
        assert_eq!(
            binds(&table, Proto::Tcp, Family::V4),
            Some(vec![
                (18899, Bind::Wildcard, 1001, 11),
                (53, Bind::Loopback, 0, 12),
                (9100, Bind::Private, 110, 13),
                (9101, Bind::Private, 110, 14),
                (443, Bind::Public, 0, 15),
            ])
        );
        let table6 = format!(
            "{TCP6}{}{}{}{}{}",
            row(&v6(Ipv6Addr::UNSPECIFIED), 8899, 0x0a, 0, 21),
            row(&v6(Ipv6Addr::LOCALHOST), 8900, 0x0a, 0, 22),
            row(&v6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 8901, 0x0a, 0, 23),
            row(
                &v6("fe80::1".parse().unwrap_or(Ipv6Addr::LOCALHOST)),
                8902,
                0x0a,
                0,
                24
            ),
            row(
                &v6("fd00::1".parse().unwrap_or(Ipv6Addr::LOCALHOST)),
                8903,
                0x0a,
                0,
                25
            ),
        );
        assert_eq!(
            binds(&table6, Proto::Tcp, Family::V6),
            Some(vec![
                (8899, Bind::Wildcard, 0, 21),
                (8900, Bind::Loopback, 0, 22),
                (8901, Bind::Loopback, 0, 23),
                (8902, Bind::LinkLocal, 0, 24),
                (8903, Bind::Private, 0, 25),
            ])
        );
    }

    #[test]
    fn udp_counts_only_bound_unconnected_sockets() {
        let connected = format!(
            "   1: {}:1F41 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0 0 32 2 0000000000000000 0 0 0 0\n",
            v4(Ipv4Addr::UNSPECIFIED)
        );
        let table = format!(
            "{UDP4}{}{connected}",
            row(&v4(Ipv4Addr::UNSPECIFIED), 8001, 0x07, 1001, 31),
        );
        assert_eq!(
            binds(&table, Proto::Udp, Family::V4),
            Some(vec![(8001, Bind::Wildcard, 1001, 31)])
        );
    }

    #[test]
    fn a_table_that_cannot_be_read_completely_is_none() {
        let good = row(&v4(Ipv4Addr::UNSPECIFIED), 22, 0x0a, 0, 1);
        for bad in [
            String::new(),
            "bad header\n".to_owned(),
            format!("{TCP4}{}", good.trim_end()),
            format!("{TCP4}   0: truncated\n"),
            format!("{TCP4}{}", good.replace(" 1 1 ", " x 1 ")),
        ] {
            assert_eq!(binds(&bad, Proto::Tcp, Family::V4), None, "{bad:?}");
        }
        let repeats = usize::try_from(super::TABLE_LIMIT).unwrap_or(usize::MAX) / good.len() + 1;
        let oversized = format!("{TCP4}{}", good.repeat(repeats));
        assert_eq!(binds(&oversized, Proto::Tcp, Family::V4), None);
    }
}
