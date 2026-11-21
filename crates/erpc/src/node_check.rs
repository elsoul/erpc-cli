// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! One local, read-only check of listeners on the conventional Solana RPC port.

use std::io::IsTerminal as _;

use erpc_ai::session::Access as _;
use erpc_api::node_check::{Finding, Observation, SOLANA_RPC_BIND};
use erpc_auth::AuthClient;

use crate::commands::Outcome;

pub(crate) const SUPPORTED: bool = cfg!(target_os = "linux");

pub(crate) async fn menu(json: bool) -> Outcome {
    if !SUPPORTED {
        return Outcome::Failed(t!("node_check.unsupported"));
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Outcome::NeedsTerminal(t!("node_check.terminal_required"));
    }
    let selection = cliclack::select(t!("node_check.scope"))
        .item(true, t!("node_check.run"), "")
        .item(false, t!("node_check.cancel"), "")
        .initial_value(false)
        .interact();
    match selection {
        Ok(true) => match check().await {
            Ok(finding) if json => crate::commands::Said::Json(
                serde_json::json!({ "check": SOLANA_RPC_BIND, "finding": finding }),
            )
            .done(),
            Ok(finding) => Outcome::Done(report(finding)),
            Err(outcome) => outcome,
        },
        Ok(false) => Outcome::Done(String::new()),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Outcome::Done(String::new()),
        Err(_) => Outcome::Failed(t!("node_check.menu_failed")),
    }
}

pub(crate) async fn check() -> Result<Finding, Outcome> {
    if !SUPPORTED {
        return Err(Outcome::Failed(t!("node_check.unsupported")));
    }
    let observation = observe().await;
    let failed = || Outcome::Failed(t!("node_check.request_failed"));
    let sign_in = || Outcome::NoSession(t!("node_check.sign_in"));
    let client = AuthClient::new().map_err(|_| failed())?;
    let access = crate::ai::StoreAccess::open(client.clone()).map_err(|_| sign_in())?;
    let token = access.access_token().await.map_err(|_| sign_in())?;
    erpc_api::node_check::check(&client, &token, observation)
        .await
        .map_err(|err| match err {
            erpc_api::ApiError::Unauthorized => sign_in(),
            _ => failed(),
        })
}

pub(crate) fn report(finding: Finding) -> String {
    let summary = match finding {
        Finding::ReviewBinding => t!("node_check.review_binding"),
        Finding::LoopbackBinding => t!("node_check.loopback_binding"),
        Finding::NoListener => t!("node_check.no_listener"),
        Finding::Inconclusive => t!("node_check.inconclusive"),
    };
    format!("{summary}\n{}", t!("node_check.limits"))
}

#[cfg(target_os = "linux")]
async fn observe() -> Observation {
    // The operator's current network namespace only. Neither path can be
    // supplied by the command line, the server or chat.
    tokio::task::spawn_blocking(|| {
        use std::fs::File;
        classify(
            File::open("/proc/net/tcp").ok(),
            File::open("/proc/net/tcp6").ok(),
        )
    })
    .await
    .unwrap_or(Observation::Unknown)
}

#[cfg(not(target_os = "linux"))]
fn observe() -> std::future::Ready<Observation> {
    std::future::ready(Observation::Unknown)
}

#[cfg(any(target_os = "linux", test))]
fn classify(ipv4: Option<impl std::io::Read>, ipv6: Option<impl std::io::Read>) -> Observation {
    match (
        ipv4.and_then(|table| read_table(table, Family::V4)),
        ipv6.and_then(|table| read_table(table, Family::V6)),
    ) {
        (None, _) | (_, None) => Observation::Unknown,
        (Some(a), Some(b)) => a.max(b).into(),
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TableBinding {
    None,
    Loopback,
    NonLoopback,
}

#[cfg(any(target_os = "linux", test))]
impl From<TableBinding> for Observation {
    fn from(binding: TableBinding) -> Self {
        match binding {
            TableBinding::None => Self::NotListening,
            TableBinding::Loopback => Self::LoopbackOnly,
            TableBinding::NonLoopback => Self::NonLoopback,
        }
    }
}

// The byte cap bounds resource use and treats oversized tables as incomplete.
#[cfg(any(target_os = "linux", test))]
const TABLE_LIMIT: u64 = 8 * 1024 * 1024;

#[cfg(any(target_os = "linux", test))]
fn read_table(table: impl std::io::Read, family: Family) -> Option<TableBinding> {
    use std::io::{BufRead as _, BufReader};

    let mut reader = BufReader::new(table.take(TABLE_LIMIT + 1));
    let mut line = String::new();
    let mut read = reader.read_line(&mut line).ok()?;
    let mut header = line.split_ascii_whitespace();
    if read as u64 > TABLE_LIMIT
        || !line.ends_with('\n')
        || header.next()? != "sl"
        || header.next()? != "local_address"
        || !matches!(header.next()?, "rem_address" | "remote_address")
        || header.ne([
            "st", "tx_queue", "rx_queue", "tr", "tm->when", "retrnsmt", "uid", "timeout", "inode",
        ])
    {
        return None;
    }
    let mut binding = TableBinding::None;
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).ok()?;
        if bytes == 0 {
            return Some(binding);
        }
        read += bytes;
        if read as u64 > TABLE_LIMIT || !line.ends_with('\n') {
            return None;
        }
        binding = binding.max(read_row(&line, family)?);
    }
}

#[cfg(any(target_os = "linux", test))]
fn read_row(line: &str, family: Family) -> Option<TableBinding> {
    const RPC_PORT: u16 = 8899;
    const TCP_LISTEN: u8 = 0x0a;

    let mut fields = line.split_ascii_whitespace();
    let _slot = fields.next()?.strip_suffix(':')?.parse::<u32>().ok()?;
    let (address, port) = fields.next()?.split_once(':')?;
    let loopback = is_loopback(address, family)?;
    let port = u16::try_from(hex(port, 4)?).ok()?;
    let _remote = fields.next()?;
    let state = u8::try_from(hex(fields.next()?, 2)?).ok()?;
    // Require the rest of the columns common to the kernel's row types,
    // through inode. A partial row cannot decide whether a listener exists.
    let _inode = fields.nth(4)?.parse::<u64>().ok()?;
    if port != RPC_PORT || state != TCP_LISTEN {
        return Some(TableBinding::None);
    }
    Some(if loopback {
        TableBinding::Loopback
    } else {
        TableBinding::NonLoopback
    })
}

#[cfg(any(target_os = "linux", test))]
fn hex(s: &str, width: usize) -> Option<u32> {
    (s.len() == width && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(s, 16).ok())
        .flatten()
}

#[cfg(any(target_os = "linux", test))]
fn is_loopback(address: &str, family: Family) -> Option<bool> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    match family {
        Family::V4 => Some(Ipv4Addr::from(hex(address, 8)?.to_ne_bytes()).is_loopback()),
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
            let address = Ipv6Addr::from(octets);
            Some(
                address.is_loopback()
                    || address.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{Observation, TABLE_LIMIT, classify};

    // Match the field layout emitted by Linux, including the two spellings
    // for the remote column. These fixtures never inspect the host.
    const TCP4: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    fn ipv4(address: Ipv4Addr) -> String {
        format!("{:08X}", u32::from_ne_bytes(address.octets()))
    }

    fn ipv6(address: Ipv6Addr) -> String {
        let mut words = String::new();
        for &[a, b, c, d] in address.octets().as_chunks::<4>().0 {
            use std::fmt::Write as _;
            let _ = write!(words, "{:08X}", u32::from_ne_bytes([a, b, c, d]));
        }
        words
    }

    fn row(address: &str, port: u16, state: u8) -> String {
        let zero = "0".repeat(address.len());
        format!(
            "   0: {address}:{port:04X} {zero}:0000 {state:02X} 00000000:00000000 00:00000000 00000000   102 0 23061 1 0000000000000000 100 0 0 10 0\n"
        )
    }

    fn both(a: &str, b: &str) -> Observation {
        classify(Some(a.as_bytes()), Some(b.as_bytes()))
    }

    #[test]
    fn listener_scope_uses_ipv4_ipv6_and_mapped_loopback() {
        let local4 = format!(
            "{TCP4}{}",
            row(&ipv4(Ipv4Addr::new(127, 6, 5, 4)), 8899, 10)
        );
        let local6 = format!("{TCP6}{}", row(&ipv6(Ipv6Addr::LOCALHOST), 8899, 10));
        let mapped = format!(
            "{TCP6}{}",
            row(&ipv6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 8899, 10)
        );
        assert_eq!(both(&local4, TCP6), Observation::LoopbackOnly);
        assert_eq!(both(TCP4, &local6), Observation::LoopbackOnly);
        assert_eq!(both(&local4, &mapped), Observation::LoopbackOnly);

        let wide4 = format!("{TCP4}{}", row(&ipv4(Ipv4Addr::UNSPECIFIED), 8899, 10));
        let wide6 = format!("{TCP6}{}", row(&ipv6(Ipv6Addr::UNSPECIFIED), 8899, 10));
        let specific = format!(
            "{TCP6}{}",
            row(
                &ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                8899,
                10
            )
        );
        assert_eq!(both(&wide4, &local6), Observation::NonLoopback);
        assert_eq!(both(&local4, &wide6), Observation::NonLoopback);
        assert_eq!(both(TCP4, &specific), Observation::NonLoopback);
    }

    #[test]
    fn other_ports_and_states_are_not_a_match() {
        let address = ipv4(Ipv4Addr::UNSPECIFIED);
        let table = format!(
            "{TCP4}{}{}",
            row(&address, 8900, 10),
            row(&address, 8899, 1)
        );
        assert_eq!(both(&table, TCP6), Observation::NotListening);
        assert_eq!(both(TCP4, TCP6), Observation::NotListening);
    }

    #[test]
    fn incomplete_tables_are_inconclusive_even_with_a_known_binding() {
        let mut ipv4_table = format!("{TCP4}{}", row(&ipv4(Ipv4Addr::UNSPECIFIED), 8899, 10));
        assert_eq!(
            classify(Some(ipv4_table.as_bytes()), None::<&[u8]>),
            Observation::Unknown
        );
        for bad in [
            "",
            "bad header\n",
            "sl local_address remote_address st\n",
            &format!("{TCP6}0: truncated\n"),
        ] {
            assert_eq!(both(&ipv4_table, bad), Observation::Unknown);
        }
        ipv4_table.pop();
        assert_eq!(both(&ipv4_table, TCP6), Observation::Unknown);
        let address = ipv4(Ipv4Addr::UNSPECIFIED);
        let record = row(&address, 8899, 10);
        let repeats = usize::try_from(TABLE_LIMIT).expect("table limit fits") / record.len() + 1;
        let records = record.as_bytes().repeat(repeats);
        let oversized = TCP4.as_bytes().chain(records.as_slice());
        assert_eq!(
            classify(Some(oversized), Some(TCP6.as_bytes())),
            Observation::Unknown
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "run only in an isolated Linux network namespace with port 8899 free"]
    async fn node_check_observes_kernel_listener_tables() {
        use std::net::{SocketAddr, TcpListener};

        assert_eq!(super::observe().await, Observation::NotListening);
        for (address, observation) in [
            (
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8899)),
                Observation::LoopbackOnly,
            ),
            (
                SocketAddr::from((Ipv6Addr::LOCALHOST, 8899)),
                Observation::LoopbackOnly,
            ),
            (
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8899)),
                Observation::NonLoopback,
            ),
            (
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 8899)),
                Observation::NonLoopback,
            ),
        ] {
            let listener = TcpListener::bind(address);
            assert!(listener.is_ok(), "could not bind test listener {address}");
            assert_eq!(super::observe().await, observation);
        }
        assert_eq!(super::observe().await, Observation::NotListening);
    }

    #[test]
    fn reports_are_fixed_and_make_scope_visible() {
        use erpc_api::node_check::Finding;
        for (finding, phrase) in [
            (Finding::ReviewBinding, "Review binding"),
            (Finding::LoopbackBinding, "Loopback binding"),
            (Finding::NoListener, "No listener observed"),
            (Finding::Inconclusive, "Inconclusive"),
        ] {
            let report = super::report(finding);
            assert!(report.starts_with(phrase));
            assert!(report.contains("current Linux network namespace"));
            assert!(report.contains("network reachability"));
        }
    }
}
