// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Closed, bounded reports from the fixed node-local collector.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

const MAX_ROWS: usize = 128;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Coverage {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum Service {
    Container,
    Dns,
    ErpcWorker,
    Mysql,
    Postgresql,
    Redis,
    Solana,
    Ssh,
    TimeSync,
    Unclassified,
    Unknown,
    Valkey,
    Web,
}

impl Service {
    pub(super) fn label(self) -> String {
        match self {
            Self::Container => t!("node_check.category_container"),
            Self::Dns => "DNS".into(),
            Self::ErpcWorker => "ERPC Worker".into(),
            Self::Mysql => "MySQL / MariaDB".into(),
            Self::Postgresql => "PostgreSQL".into(),
            Self::Redis => "Redis".into(),
            Self::Solana => "Solana".into(),
            Self::Ssh => "SSH".into(),
            Self::TimeSync => t!("node_check.category_time"),
            Self::Unclassified => t!("node_check.category_unclassified"),
            Self::Unknown => t!("node_check.unknown"),
            Self::Valkey => "Valkey".into(),
            Self::Web => t!("node_check.category_web"),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Port {
    pub(super) port: u16,
    pub(super) services: Vec<Service>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PortGroups {
    pub(super) coverage: Coverage,
    pub(super) wildcard: Vec<Port>,
    pub(super) interface: Vec<Port>,
    pub(super) loopback: Vec<Port>,
}

impl PortGroups {
    fn groups(&self) -> [&[Port]; 3] {
        [&self.wildcard, &self.interface, &self.loopback]
    }

    fn count(&self) -> usize {
        self.groups().into_iter().map(<[Port]>::len).sum()
    }

    fn valid(&self) -> bool {
        (self.coverage != Coverage::Unknown || self.count() == 0)
            && self.groups().iter().all(|group| {
                group.windows(2).all(|pair| pair[0].port < pair[1].port)
                    && group.iter().all(|port| {
                        port.port != 0
                            && !port.services.is_empty()
                            && port.services.len() <= 13
                            && port.services.windows(2).all(|pair| pair[0] < pair[1])
                    })
            })
    }

    fn fact(&self, truncated: bool) -> &'static str {
        if !self.wildcard.is_empty() || !self.interface.is_empty() {
            "non_loopback_observed"
        } else if truncated || self.coverage != Coverage::Complete {
            "unknown"
        } else if self.loopback.is_empty() {
            "none_observed"
        } else {
            "loopback_only"
        }
    }

    fn describe(&self, text: &mut String, protocol: &str) {
        let coverage = match self.coverage {
            Coverage::Complete => t!("node_check.coverage_complete"),
            Coverage::Partial => t!("node_check.coverage_partial"),
            Coverage::Unknown => t!("node_check.unknown"),
        };
        let _ = writeln!(text, "{protocol} ({coverage})");
        for (scope, ports) in [
            (t!("node_check.bind_wildcard"), &self.wildcard),
            (t!("node_check.bind_interface"), &self.interface),
            (t!("node_check.bind_loopback"), &self.loopback),
        ] {
            if ports.is_empty() {
                continue;
            }
            let labels = ports
                .iter()
                .map(|entry| {
                    let services = entry
                        .services
                        .iter()
                        .map(|service| service.label())
                        .collect::<Vec<_>>();
                    format!("{} ({})", entry.port, services.join(" / "))
                })
                .collect::<Vec<_>>();
            let _ = writeln!(text, "  {scope} · {}", labels.join(", "));
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ports {
    pub(super) tcp: PortGroups,
    pub(super) udp: PortGroups,
    pub(super) truncated: bool,
}

impl Ports {
    pub(super) fn valid(&self) -> bool {
        self.tcp.count() + self.udp.count() <= MAX_ROWS && self.tcp.valid() && self.udp.valid()
    }

    pub(super) fn facts(&self) -> (&'static str, &'static str) {
        (self.tcp.fact(self.truncated), self.udp.fact(self.truncated))
    }

    pub(super) fn category_facts(&self) -> (&'static str, &'static str) {
        let protocols = [&self.tcp, &self.udp];
        let services = protocols
            .iter()
            .flat_map(|protocol| protocol.groups())
            .flatten()
            .flat_map(|port| &port.services);
        let incomplete = self.truncated
            || protocols
                .iter()
                .any(|protocol| protocol.coverage != Coverage::Complete)
            || services.clone().any(|service| *service == Service::Unknown);
        let contains_redis_family = |ports: &[Port]| {
            ports.iter().any(|port| {
                port.services
                    .iter()
                    .any(|service| matches!(service, Service::Redis | Service::Valkey))
            })
        };
        let redis = if protocols.iter().any(|protocol| {
            contains_redis_family(&protocol.interface) || contains_redis_family(&protocol.wildcard)
        }) {
            "non_loopback_observed"
        } else if incomplete {
            "unknown"
        } else if protocols
            .iter()
            .any(|protocol| contains_redis_family(&protocol.loopback))
        {
            "loopback_only"
        } else {
            "none_observed"
        };
        let daemon = if services
            .clone()
            .any(|service| *service == Service::Unclassified)
        {
            "unclassified_observed"
        } else if incomplete {
            "unknown"
        } else {
            "none_in_observed"
        };
        (redis, daemon)
    }

    pub(super) fn describe(&self, text: &mut String) {
        self.tcp.describe(text, "TCP");
        self.udp.describe(text, "UDP");
        if self.truncated {
            let _ = writeln!(text, "{}", t!("node_check.remote_truncated"));
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Switch {
    Enabled,
    Disabled,
    Unknown,
}

impl Switch {
    pub(super) fn billing_fact(self) -> Self {
        // The on-disk default evaluation can surface a concern, but it
        // cannot establish that the running daemon disabled a method.
        match self {
            Self::Enabled => Self::Enabled,
            Self::Disabled | Self::Unknown => Self::Unknown,
        }
    }

    fn label(self) -> String {
        match self {
            Self::Enabled => t!("node_check.setting_enabled"),
            Self::Disabled => t!("node_check.setting_disabled"),
            Self::Unknown => t!("node_check.unknown"),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ssh {
    source: SshSource,
    pub(super) password: Switch,
    pub(super) keyboard_interactive: Switch,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SshSource {
    DefaultConfigForConnection,
}

impl Ssh {
    pub(super) fn describe(&self, text: &mut String) {
        let _ = writeln!(text, "{}", t!("node_check.ssh_config_scope"));
        let _ = writeln!(
            text,
            "{} · {}",
            t!("node_check.ssh_password"),
            self.password.label()
        );
        let _ = writeln!(
            text,
            "{} · {}",
            t!("node_check.ssh_keyboard_interactive"),
            self.keyboard_interactive.label()
        );
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum FirewallEvidence {
    NoInputFilterHook,
    InputFilterHook,
    ConfiguredDropOrRejectRule,
    InputDefaultDrop,
    Unknown,
}

impl FirewallEvidence {
    fn label(self) -> String {
        match self {
            Self::NoInputFilterHook => t!("node_check.firewall_no_hook"),
            Self::InputFilterHook => t!("node_check.firewall_hook"),
            Self::ConfiguredDropOrRejectRule => t!("node_check.firewall_rule"),
            Self::InputDefaultDrop => t!("node_check.firewall_default_drop"),
            Self::Unknown => t!("node_check.unknown"),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Firewall {
    pub(super) ipv4: FirewallEvidence,
    pub(super) ipv6: FirewallEvidence,
    pub(super) truncated: bool,
}

impl Firewall {
    pub(super) fn describe(&self, text: &mut String) {
        let _ = writeln!(text, "nftables IPv4 · {}", self.ipv4.label());
        let _ = writeln!(text, "nftables IPv6 · {}", self.ipv6.label());
        if self.truncated {
            let _ = writeln!(text, "{}", t!("node_check.remote_truncated"));
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Jail {
    SshdJailObserved,
    SshdJailNotListed,
    Unknown,
}

impl Jail {
    pub(super) fn describe(self, text: &mut String) {
        let label = match self {
            Self::SshdJailObserved => t!("node_check.jail_observed"),
            Self::SshdJailNotListed => t!("node_check.jail_missing"),
            Self::Unknown => t!("node_check.unknown"),
        };
        let _ = writeln!(text, "fail2ban sshd · {label}");
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum MetadataCoverage {
    Observed,
    Partial,
    Unknown,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModeCounts {
    pub(super) owner_only: u16,
    pub(super) group_or_other_access: u16,
    pub(super) unknown: u16,
}

impl ModeCounts {
    pub(super) fn total(&self) -> u32 {
        u32::from(self.owner_only) + u32::from(self.group_or_other_access) + u32::from(self.unknown)
    }

    fn fact(&self, complete: bool) -> &'static str {
        if self.group_or_other_access > 0 {
            "broad_mode_observed"
        } else if !complete || self.unknown > 0 {
            "unknown"
        } else if self.owner_only > 0 {
            "owner_only_modes_observed"
        } else {
            "none_observed"
        }
    }

    fn describe(&self, text: &mut String, label: &str) {
        let values = t!(
            "node_check.mode_counts",
            owner = self.owner_only,
            broad = self.group_or_other_access,
            unknown = self.unknown
        );
        let _ = writeln!(text, "{label} · {values}");
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DistinctCredentialSources {
    as_is: Option<u16>,
    encrypted: Option<u16>,
}

impl DistinctCredentialSources {
    fn valid(&self, observed: bool) -> bool {
        match (self.as_is, self.encrypted) {
            (Some(as_is), Some(encrypted)) => observed && as_is <= 64 && encrypted <= 64,
            (None, None) => !observed,
            _ => false,
        }
    }

    fn describe(&self, text: &mut String) {
        let label = |count: Option<u16>| {
            count.map_or_else(|| t!("node_check.unknown"), |count| count.to_string())
        };
        let _ = writeln!(
            text,
            "{}",
            t!(
                "node_check.credential_declarations",
                as_is = label(self.as_is),
                encrypted = label(self.encrypted)
            )
        );
        if self.as_is.is_some_and(|count| count > 0) {
            let _ = writeln!(text, "{}", t!("node_check.credential_as_is_scope"));
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Metadata {
    pub(super) coverage: MetadataCoverage,
    units_with_evidence: u16,
    pub(super) truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    environment_files: Option<ModeCounts>,
    service_env: ModeCounts,
    pub(super) credential_sources: ModeCounts,
    #[serde(
        default,
        alias = "credential_declarations",
        skip_serializing_if = "Option::is_none"
    )]
    distinct_credential_sources: Option<DistinctCredentialSources>,
    /// Which service refers to which of the files counted above: for the
    /// operator's screen only, never serialized again, so neither `--json`
    /// nor the report request carries it.
    #[serde(default, skip_serializing)]
    pub(super) files: Vec<ServiceFile>,
    /// How many such references `files` leaves out.
    #[serde(default, skip_serializing)]
    pub(super) files_more: u16,
}

/// How many service files the collector lists.
pub(super) const FILES_SHOWN: usize = 8;
/// The longest path of one, in characters of its encoding.
pub(super) const FILE_PATH_LIMIT: usize = 1024;
/// All their paths together, each counted with 3 more for its quotes and
/// comma.
pub(super) const FILES_BUDGET: usize = 1536;

/// What refers to a file: a service's `EnvironmentFile`, or its
/// `LoadCredential` or `LoadCredentialEncrypted` source.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum FileSource {
    EnvironmentFile,
    Credential,
}

/// What the collector found at the path without following it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum FileType {
    File,
    Directory,
    /// A symbolic link, socket or the like: no mode is judged.
    Other,
}

/// One service's reference to a file, as the collector found it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServiceFile {
    pub(super) source: FileSource,
    /// The systemd unit, one the collector reads: of its fixed list or an
    /// ERPC unit.
    pub(super) unit: String,
    /// Encoded as the key search encodes its places.
    pub(super) path: String,
    /// `None` when the collector judged no mode: a path it does not look
    /// at (a pattern) or one it could not read.
    #[serde(rename = "type")]
    pub(super) kind: Option<FileType>,
    /// The permission bits of a file or directory.
    pub(super) mode: Option<u16>,
}

/// The collector's fixed list of units (`FIXED_UNITS`).
pub(super) const COLLECTOR_UNITS: [&str; 11] = [
    "ssh.service",
    "sshd.service",
    "redis-server.service",
    "valkey-server.service",
    "postgresql.service",
    "mariadb.service",
    "nginx.service",
    "apache2.service",
    "caddy.service",
    "docker.service",
    "fail2ban.service",
];

/// The units the collector reads: its fixed list, or
/// `erpc-(worker|waf|backup)-<1 to 64 of a-z, 0-9 and ->.service`.
fn collector_unit(unit: &str) -> bool {
    if COLLECTOR_UNITS.contains(&unit) {
        return true;
    }
    ["erpc-worker-", "erpc-waf-", "erpc-backup-"]
        .into_iter()
        .filter_map(|prefix| unit.strip_prefix(prefix))
        .filter_map(|rest| rest.strip_suffix(".service"))
        .any(|name| {
            (1..=64).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl ServiceFile {
    /// Who can read it, as the collector's counts judge a path: `None` when
    /// they count it unknown.
    pub(super) fn broad(&self) -> Option<bool> {
        match (self.kind, self.mode) {
            (Some(FileType::File | FileType::Directory), Some(mode)) => Some(mode & 0o077 != 0),
            _ => None,
        }
    }

    fn valid(&self) -> bool {
        let typed = match (self.kind, self.mode) {
            (Some(FileType::File | FileType::Directory), Some(mode)) => mode <= 0o7777,
            (Some(FileType::Other) | None, None) => true,
            _ => false,
        };
        typed
            && collector_unit(&self.unit)
            && self.path.len() <= FILE_PATH_LIMIT
            && super::posture_keys::decode(&self.path).is_some()
    }
}

impl Metadata {
    /// The counts of the services' `EnvironmentFile` references (the named
    /// `.env` files alone, from a collector that counted no more).
    pub(super) fn environment_files(&self) -> &ModeCounts {
        self.environment_files.as_ref().unwrap_or(&self.service_env)
    }

    pub(super) fn has_environment_reference(&self) -> bool {
        self.environment_files().total() > 0 || self.service_env.total() > 0
    }

    /// Whether the listed files keep to their bounds and agree with the
    /// counts: no more paths of a kind, judged a way, than were counted so.
    /// A collector that ran out of room (`truncated`) counted only some.
    fn files_valid(&self) -> bool {
        let spent: usize = self.files.iter().map(|file| file.path.len() + 3).sum();
        let bounded = self.files.len() <= FILES_SHOWN
            && spent <= FILES_BUDGET
            && self.files.iter().all(ServiceFile::valid)
            && (self.coverage != MetadataCoverage::Unknown
                || (self.files.is_empty() && self.files_more == 0));
        bounded
            && (self.truncated
                || [
                    (FileSource::EnvironmentFile, self.environment_files()),
                    (FileSource::Credential, &self.credential_sources),
                ]
                .into_iter()
                .all(|(source, counts)| {
                    let mut paths: Vec<(&str, Option<bool>)> = self
                        .files
                        .iter()
                        .filter(|file| file.source == source)
                        .map(|file| (file.path.as_str(), file.broad()))
                        .collect();
                    paths.sort_unstable();
                    paths.dedup();
                    let judged = |broad| paths.iter().filter(|(_, b)| *b == broad).count();
                    judged(Some(false)) <= usize::from(counts.owner_only)
                        && judged(Some(true)) <= usize::from(counts.group_or_other_access)
                        && judged(None) <= usize::from(counts.unknown)
                }))
    }

    pub(super) fn valid(&self) -> bool {
        self.files_valid()
            && self.units_with_evidence <= 16
            && self
                .distinct_credential_sources
                .as_ref()
                .is_none_or(|declarations| {
                    declarations.valid(self.coverage != MetadataCoverage::Unknown)
                })
            && self.environment_files.as_ref().is_none_or(|files| {
                files.total() <= 64 && (self.truncated || self.service_env.total() <= files.total())
            })
            && self.service_env.total() <= 64
            && self.credential_sources.total() <= 64
            && match self.coverage {
                MetadataCoverage::Observed | MetadataCoverage::Partial => {
                    self.units_with_evidence > 0
                }
                MetadataCoverage::Unknown => {
                    self.units_with_evidence == 0
                        && self.service_env.total() == 0
                        && self.credential_sources.total() == 0
                        && self
                            .environment_files
                            .as_ref()
                            .is_none_or(|files| files.total() == 0)
                }
            }
    }

    pub(super) fn facts(&self) -> (&'static str, &'static str) {
        let complete = self.coverage == MetadataCoverage::Observed && !self.truncated;
        let environment = self.environment_files();
        (
            // Known owner-only counts describe the observed references. An
            // unreadable mode still prevents a mode classification.
            environment.fact(complete || environment.owner_only > 0),
            self.credential_sources.fact(complete),
        )
    }

    pub(super) fn describe(&self, text: &mut String) {
        if self.coverage == MetadataCoverage::Unknown {
            let _ = writeln!(
                text,
                "{} · {}",
                t!("node_check.file_modes"),
                t!("node_check.unknown")
            );
        } else {
            if self.coverage == MetadataCoverage::Partial {
                let _ = writeln!(text, "{}", t!("node_check.metadata_partial"));
            }
            if let Some(environment_files) = &self.environment_files {
                environment_files.describe(text, &t!("node_check.environment_files"));
            }
            self.service_env
                .describe(text, &t!("node_check.service_env"));
            if self.has_environment_reference() {
                let _ = writeln!(text, "{}", t!("node_check.environment_reference_review"));
            }
            self.credential_sources
                .describe(text, &t!("node_check.credential_sources"));
        }
        if let Some(declarations) = &self.distinct_credential_sources {
            declarations.describe(text);
        }
        if self.truncated {
            let _ = writeln!(text, "{}", t!("node_check.remote_truncated"));
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UpdateStatus {
    Available,
    NoneInCachedCandidates,
    Unknown,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Updates {
    pub(super) status: UpdateStatus,
    pub(super) packages: Option<u16>,
}

impl Updates {
    pub(super) fn valid(&self) -> bool {
        match self.status {
            UpdateStatus::Available => self.packages.is_some_and(|count| count > 0),
            UpdateStatus::NoneInCachedCandidates => self.packages == Some(0),
            UpdateStatus::Unknown => self.packages.is_none(),
        }
    }

    pub(super) fn describe(&self, text: &mut String) {
        let count = self.packages.unwrap_or_default();
        let label = match self.status {
            UpdateStatus::Available => t!("node_check.update_available", count = count),
            UpdateStatus::NoneInCachedCandidates => t!("node_check.update_none_cached"),
            UpdateStatus::Unknown => t!("node_check.unknown"),
        };
        let _ = writeln!(text, "{} · {label}", t!("node_check.update_status"));
    }
}
