// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Jito's regions: the table erpc carries, how near each is to a node, and
//! whether a host's endpoints are still the table's.
//!
//! Jito publishes its regions only as a table on a docs page, and a table
//! copied into code goes stale: SLV's had a London shred receiver the docs no
//! longer listed. So the table is data (`regions/jito.json`) with the page and
//! the date it was read from. A scheduled job reads the page and reports any
//! difference ([`drift`]), the node measures the regions itself, and a host's
//! stored endpoints are checked against the table before a deploy uses them
//! ([`stale`]).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use erpc_chain::inventory::Jito;
use erpc_ssh::{PING_PREFIX, PingTargets, RemoteCommand, Session, SshError};
use serde::Deserialize;

/// The table, as carried.
const TABLE_JSON: &str = include_str!("../regions/jito.json");

/// A region of one network.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Region {
    /// `ny`, `dallas` and so on; `global` for the network-wide endpoint.
    pub key: String,
    /// As the docs name it.
    pub name: String,
    /// The block engine.
    pub block_engine_url: String,
    /// Where the client forwards shreds, `ip:port`.
    #[serde(default)]
    pub shred_receiver_address: Option<String>,
    /// The region's NTP server.
    #[serde(default)]
    pub ntp_server: Option<String>,
    /// The relayer, which the docs do not list.
    #[serde(default)]
    pub relayer_url: Option<String>,
    /// The BAM endpoint, which the docs do not list.
    #[serde(default)]
    pub bam_url: Option<String>,
}

/// The whole table.
#[derive(Debug, Clone, Deserialize)]
pub struct Table {
    /// The page it was read from.
    pub source: String,
    /// When, `YYYY-MM-DD`.
    pub read: String,
    /// Each network's regions.
    pub networks: BTreeMap<String, Vec<Region>>,
}

/// The table erpc carries.
///
/// # Panics
///
/// Only if `regions/jito.json` does not parse, which a test rules out.
#[must_use]
pub fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    #[allow(clippy::expect_used)]
    TABLE.get_or_init(|| serde_json::from_str(TABLE_JSON).expect("regions/jito.json parses"))
}

/// The regions of `network`, the global endpoint first.
#[must_use]
pub fn regions(network: &str) -> &'static [Region] {
    table().networks.get(network).map_or(&[], Vec::as_slice)
}

/// A region by its key.
#[must_use]
pub fn region(network: &str, key: &str) -> Option<&'static Region> {
    regions(network).iter().find(|r| r.key == key)
}

/// A row of the docs' table: the columns the docs give.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocsRow {
    /// The region's key, from the block engine's host name.
    pub key: String,
    /// The block engine.
    pub block_engine_url: String,
    /// `-` in the docs becomes `None`.
    pub shred_receiver_address: Option<String>,
    /// As above.
    pub ntp_server: Option<String>,
}

/// Reads the region table out of the docs page: the first table with a
/// "Block Engine URL" column. A row naming `Mainnet` or `Testnet` starts that
/// network's section, and is its global endpoint.
#[must_use]
pub fn parse_docs(html: &str) -> BTreeMap<String, Vec<DocsRow>> {
    let mut out: BTreeMap<String, Vec<DocsRow>> = BTreeMap::new();
    let Some(table) = tables(html)
        .into_iter()
        .find(|t| t.contains("Block Engine URL"))
    else {
        return out;
    };
    let mut network: Option<String> = None;
    for row in tags(table, "tr") {
        let cells: Vec<String> = tags(row, "td").into_iter().map(text).collect();
        let [location, engine, shred, ntp] = cells.as_slice() else {
            continue;
        };
        for name in ["Mainnet", "Testnet"] {
            if location.contains(name) {
                network = Some(name.to_ascii_lowercase());
            }
        }
        let Some(network) = network.clone() else {
            continue;
        };
        let Some(host) = engine.strip_prefix("https://") else {
            continue;
        };
        let first = host.split('.').next().unwrap_or_default();
        let key = if first == network {
            "global".to_owned()
        } else {
            first.to_owned()
        };
        let present = |v: &String| (v != "-" && !v.is_empty()).then(|| v.clone());
        out.entry(network).or_default().push(DocsRow {
            key,
            block_engine_url: engine.clone(),
            shred_receiver_address: present(shred),
            ntp_server: present(ntp),
        });
    }
    out
}

fn tables(html: &str) -> Vec<&str> {
    tags(html, "table")
}

/// The contents of each `<tag …>…</tag>` in `html`, not nested.
fn tags<'a>(html: &'a str, tag: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{tag}"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start..];
        let Some(body_start) = after.find('>') else {
            break;
        };
        let Some(end) = after.find(&close) else { break };
        if body_start < end {
            out.push(&after[body_start + 1..end]);
        }
        rest = &after[end + close.len()..];
    }
    out
}

/// The text of an HTML fragment: tags dropped, the few entities a table
/// uses decoded, whitespace trimmed.
fn text(fragment: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in fragment.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .trim()
        .to_owned()
}

/// What differs between the table erpc carries and the docs: one line per
/// difference, empty when they agree on every column the docs give.
#[must_use]
pub fn drift(carried: &Table, docs: &BTreeMap<String, Vec<DocsRow>>) -> Vec<String> {
    let mut out = Vec::new();
    for (network, rows) in docs {
        let ours = carried.networks.get(network).map_or(&[][..], Vec::as_slice);
        for row in rows {
            match ours.iter().find(|r| r.key == row.key) {
                None => out.push(format!(
                    "{network}: the docs list {} ({}), erpc does not",
                    row.key, row.block_engine_url
                )),
                Some(r) => {
                    let mut check = |field: &str, ours: Option<&String>, docs: Option<&String>| {
                        if ours != docs {
                            out.push(format!(
                                "{network} {}: {field} is {docs:?} in the docs, {ours:?} in erpc",
                                row.key
                            ));
                        }
                    };
                    check(
                        "block_engine_url",
                        Some(&r.block_engine_url),
                        Some(&row.block_engine_url),
                    );
                    check(
                        "shred_receiver_address",
                        r.shred_receiver_address.as_ref(),
                        row.shred_receiver_address.as_ref(),
                    );
                    check("ntp_server", r.ntp_server.as_ref(), row.ntp_server.as_ref());
                }
            }
        }
        for r in ours {
            if !rows.iter().any(|row| row.key == r.key) {
                out.push(format!(
                    "{network}: erpc lists {}, the docs no longer do",
                    r.key
                ));
            }
        }
    }
    out
}

/// Why the regions could not be measured.
#[derive(Debug, thiserror::Error)]
pub enum MeasureError {
    /// The table gives nothing pingable for the network.
    #[error("no Jito regions to measure: {0}")]
    Targets(String),
    /// The node could not be reached or the command failed.
    #[error(transparent)]
    Ssh(#[from] SshError),
}

/// How near a region is to a node.
#[derive(Debug, Clone, PartialEq)]
pub struct Latency {
    /// The region's key.
    pub key: String,
    /// The best of three round trips, in milliseconds; `None` when nothing
    /// came back.
    pub ms: Option<f64>,
}

/// Pings every regional block engine of `network` from the node, three times
/// each, and returns the best round trip of each. The global endpoint is
/// not measured: it is not a place.
///
/// # Errors
///
/// Returns [`MeasureError`] when the network has no regions or the command
/// cannot be run on the node.
pub fn measure(session: &Session, network: &str) -> Result<Vec<Latency>, MeasureError> {
    let hosts: Vec<(&str, &str)> = regions(network)
        .iter()
        .filter(|r| r.key != "global")
        .filter_map(|r| {
            Some((
                r.key.as_str(),
                r.block_engine_url
                    .strip_prefix("https://")?
                    .split('/')
                    .next()?,
            ))
        })
        .collect();
    let names: Vec<&str> = hosts.iter().map(|(_, h)| *h).collect();
    let targets = PingTargets::new(&names).map_err(|e| MeasureError::Targets(e.to_string()))?;
    let out = session.run(&RemoteCommand::Ping(targets), None)?;
    let printed = String::from_utf8_lossy(&out.stdout).into_owned();
    Ok(hosts
        .iter()
        .map(|(key, host)| Latency {
            key: (*key).to_owned(),
            ms: printed
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{PING_PREFIX} {host} ")))
                .and_then(best_round_trip),
        })
        .collect())
}

/// The minimum of `ping`'s summary: `rtt min/avg/max/mdev = 1.2/…` on Linux,
/// `round-trip min/avg/max/stddev = 1.2/…` elsewhere.
fn best_round_trip(summary: &str) -> Option<f64> {
    let (_, numbers) = summary.split_once(" = ")?;
    numbers.split('/').next()?.trim().parse().ok()
}

/// The nearest region that answered.
#[must_use]
pub fn nearest(latencies: &[Latency]) -> Option<&Latency> {
    latencies.iter().filter(|l| l.ms.is_some()).min_by(|a, b| {
        a.ms.partial_cmp(&b.ms)
            .unwrap_or(core::cmp::Ordering::Equal)
    })
}

/// A host's Jito fields for region `key` of `network`, from the table, with
/// the measurement and the table's date.
#[must_use]
pub fn jito_for(
    network: &str,
    key: &str,
    latency_ms: Option<f64>,
    measured_at: &str,
) -> Option<Jito> {
    let r = region(network, key)?;
    Some(Jito {
        region: r.key.clone(),
        block_engine_url: r.block_engine_url.clone(),
        relayer_url: r.relayer_url.clone().unwrap_or_default(),
        shred_receiver_address: r.shred_receiver_address.clone().unwrap_or_default(),
        latency_ms: latency_ms.map_or(String::new(), |ms| format!("{ms:.1}")),
        measured_at: measured_at.to_owned(),
        table_date: table().read.clone(),
    })
}

/// How a host's stored endpoints differ from the table: one line per field,
/// empty when they match.
#[must_use]
pub fn stale(network: &str, stored: &Jito) -> Vec<String> {
    let Some(current) = jito_for(network, &stored.region, None, "") else {
        return vec![format!(
            "region {:?} is no longer in the {network} table",
            stored.region
        )];
    };
    let mut out = Vec::new();
    for (field, was, now) in [
        (
            "block_engine_url",
            &stored.block_engine_url,
            &current.block_engine_url,
        ),
        ("relayer_url", &stored.relayer_url, &current.relayer_url),
        (
            "shred_receiver_address",
            &stored.shred_receiver_address,
            &current.shred_receiver_address,
        ),
    ] {
        if was != now {
            out.push(format!("{field}: {was} → {now}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::Jito;

    use super::{
        Latency, best_round_trip, drift, jito_for, nearest, parse_docs, region, regions, stale,
        table,
    };

    const DOCS: &str = include_str!("../regions/testdata/docs-table.html");

    #[test]
    fn the_carried_table_parses_and_has_both_networks() {
        let t = table();
        assert_eq!(t.read, "2026-10-23");
        assert_eq!(
            regions("testnet")
                .iter()
                .map(|r| r.key.as_str())
                .collect::<Vec<_>>(),
            ["global", "dallas", "ny"]
        );
        assert!(regions("mainnet").len() >= 8);
        assert!(
            region("testnet", "ny")
                .and_then(|r| r.relayer_url.as_ref())
                .is_some()
        );
    }

    #[test]
    fn the_docs_table_reads_into_networks_and_regions() {
        let docs = parse_docs(DOCS);
        let testnet = &docs["testnet"];
        assert_eq!(
            testnet.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(),
            ["global", "dallas", "ny"]
        );
        assert_eq!(
            testnet[2].shred_receiver_address.as_deref(),
            Some("64.130.35.224:1002")
        );
        assert_eq!(testnet[0].shred_receiver_address, None);
        assert!(docs["mainnet"].iter().any(|r| r.key == "london"));
    }

    #[test]
    fn the_carried_table_agrees_with_the_docs_it_was_read_from() {
        let changes = drift(table(), &parse_docs(DOCS));
        assert!(changes.is_empty(), "{changes:#?}");
    }

    #[test]
    fn a_change_in_the_docs_is_reported() {
        let mut docs = parse_docs(DOCS);
        docs.get_mut("testnet").expect("testnet")[2].shred_receiver_address =
            Some("192.0.2.1:1002".to_owned());
        let changes = drift(table(), &docs);
        assert_eq!(changes.len(), 1, "{changes:#?}");
        assert!(
            changes[0].contains("ny") && changes[0].contains("192.0.2.1"),
            "{changes:#?}"
        );
    }

    #[test]
    fn ping_summaries_read_on_linux_and_bsd() {
        assert_eq!(
            best_round_trip("rtt min/avg/max/mdev = 75.123/75.3/75.5/0.2 ms"),
            Some(75.123)
        );
        assert_eq!(
            best_round_trip("round-trip min/avg/max/stddev = 1.5/2/3/0.1 ms"),
            Some(1.5)
        );
        assert_eq!(
            best_round_trip("3 packets transmitted, 0 received, 100% packet loss, time 2003ms"),
            None
        );
    }

    #[test]
    fn the_nearest_region_is_the_fastest_that_answered() {
        let l = |key: &str, ms: Option<f64>| Latency {
            key: key.to_owned(),
            ms,
        };
        let all = [
            l("dallas", Some(110.0)),
            l("ny", Some(75.0)),
            l("slc", None),
        ];
        assert_eq!(nearest(&all).map(|l| l.key.as_str()), Some("ny"));
        assert_eq!(nearest(&[l("x", None)]), None);
    }

    #[test]
    fn a_host_from_an_older_table_is_reported_stale() {
        let current = jito_for("testnet", "ny", Some(75.0), "2026-10-23T00:00:00Z").expect("ny");
        assert!(stale("testnet", &current).is_empty());
        let old = Jito {
            shred_receiver_address: "142.91.127.175:1002".to_owned(),
            ..current.clone()
        };
        let changes = stale("testnet", &old);
        assert_eq!(changes.len(), 1, "{changes:?}");
        let gone = Jito {
            region: "slc".to_owned(),
            ..current
        };
        assert!(stale("testnet", &gone)[0].contains("no longer"));
    }
}
