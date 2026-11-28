// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The Security Check's report as a person reads it: a line of counts,
//! then what needs a look, what is fine and what could not be checked,
//! and the charge.
//!
//! The evidence alone decides the group a result is in. Private keys and
//! secrets found in plain text head the first group, since they can lose
//! funds at once; the findings a completed report ranked follow in their
//! order, and what they leave out after them in a fixed order. Nothing
//! here is sent anywhere: the services' files and the keys' places are
//! shown on this screen only.

use console::Style;

use super::billing::{self, FindingId, ReportFailure};
use super::posture_details::{
    Coverage, FileSource, FileType, Firewall, FirewallEvidence, Jail, Metadata, MetadataCoverage,
    Port, PortGroups, Ports, Service, ServiceFile, Ssh, Switch, UpdateStatus, Updates,
};
use super::posture_keys::{self, Access, Finding, Keys};
use super::{EligibleServer, Nftables, Posture};

/// How the report is drawn: marks before the groups' headings at a
/// terminal a person reads, and colours when that terminal takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Look {
    pub(super) marks: bool,
    pub(super) color: bool,
    /// The columns words are wrapped to.
    pub(super) width: usize,
}

impl Look {
    /// Plain lines of at most 80 columns (but for a command or a path):
    /// off a terminal, or at a terminal erpc does not draw on.
    pub(super) const PLAIN: Self = Self {
        marks: false,
        color: false,
        width: 80,
    };

    /// As standard output takes it: marks at a terminal a person reads
    /// (not `TERM=dumb`), colours there unless `NO_COLOR` says otherwise,
    /// and words wrapped to its width, from 40 to 100 columns.
    pub(super) fn here() -> Self {
        if !crate::cli::ui::stdout_drawn() {
            return Self::PLAIN;
        }
        let (_, columns) = console::Term::stdout().size();
        Self {
            marks: true,
            color: crate::cli::ui::help_coloured(false),
            width: usize::from(columns).clamp(40, 100),
        }
    }

    fn style(self, style: Style) -> Style {
        style.force_styling(self.color)
    }
}

/// What a result that needs a look is about, in the order such results
/// are listed when no ranked finding speaks to them. The key search's
/// findings come first whatever is ranked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Topic {
    Keys,
    EnvFiles,
    Credentials,
    Redis,
    Listeners,
    SshAuth,
    Firewall,
    Jail,
    Updates,
    Unclassified,
    /// A ranked finding the evidence here says nothing about.
    Ranked(FindingId),
}

impl Topic {
    /// Where results about this come when no ranked finding names them.
    const fn order(self) -> u8 {
        match self {
            Self::Keys => 0,
            Self::EnvFiles => 1,
            Self::Credentials => 2,
            Self::Redis => 3,
            Self::Listeners => 4,
            Self::SshAuth => 5,
            Self::Firewall => 6,
            Self::Jail => 7,
            Self::Updates => 8,
            Self::Unclassified => 9,
            Self::Ranked(_) => 10,
        }
    }

    /// The topics a ranked finding is about. Asking to verify what is
    /// unknown is about the "could not check" group as a whole.
    const fn of(id: FindingId) -> &'static [Self] {
        match id {
            FindingId::ReviewListenerBindings => &[Self::Listeners],
            FindingId::ReviewSshAuthentication => &[Self::SshAuth],
            FindingId::ReviewInputFilter => &[Self::Firewall],
            FindingId::ReviewSshJail => &[Self::Jail],
            FindingId::ReviewFilePermissions => &[Self::EnvFiles, Self::Credentials],
            FindingId::ReviewAvailableUpdates => &[Self::Updates],
            FindingId::VerifyUnobservedPosture => &[],
            FindingId::ReviewEnvFileUse => &[Self::EnvFiles],
            FindingId::ReviewRedisBinding => &[Self::Redis],
            FindingId::IdentifyUnclassifiedListener => &[Self::Unclassified],
        }
    }

    fn named_by(self, id: FindingId) -> bool {
        match self {
            Self::Ranked(ranked) => ranked == id,
            topic => Self::of(id).contains(&topic),
        }
    }
}

/// What to do: a command to run, or words when no command fits.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Todo {
    Run(String),
    Words(String),
}

/// A line under a result: words, wrapped to the width like the result's
/// own, or something shown exactly as it is (a path), never wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Words(String),
    Exact(String),
}

impl From<String> for Line {
    fn from(text: String) -> Self {
        Self::Words(text)
    }
}

impl std::ops::Deref for Line {
    type Target = str;

    fn deref(&self) -> &str {
        match self {
            Self::Words(text) | Self::Exact(text) => text,
        }
    }
}

impl PartialEq<&str> for Line {
    fn eq(&self, other: &&str) -> bool {
        &**self == *other
    }
}

impl PartialEq<String> for Line {
    fn eq(&self, other: &String) -> bool {
        **self == **other
    }
}

/// A result that needs a look: what it means, where (and what else bears
/// on it), and what to do.
#[derive(Debug)]
struct Item {
    topic: Topic,
    text: String,
    lines: Vec<Line>,
    todo: Vec<Todo>,
}

/// A result that could not be checked: what and why, the topics it leaves
/// open, and what would let it be checked.
#[derive(Debug)]
struct Open {
    topics: &'static [Topic],
    text: String,
    todo: Todo,
}

#[derive(Debug, Default)]
struct View {
    look: Vec<Item>,
    fine: Vec<String>,
    open: Vec<Open>,
}

impl View {
    /// The three groups, from the evidence, with the first in the order of
    /// `ranked`.
    fn of(posture: &Posture, ranked: &[FindingId]) -> Self {
        let mut view = Self::default();
        // Whether both families drop by default, and whether either could
        // be read at all: what the line under open ports may say.
        let families = posture
            .firewall
            .as_ref()
            .filter(|firewall| !firewall.truncated)
            .map(|firewall| [firewall.ipv4, firewall.ipv6]);
        let both_drop = families == Some([FirewallEvidence::InputDefaultDrop; 2]);
        let firewall_read =
            families.is_some_and(|families| !families.contains(&FirewallEvidence::Unknown));
        view.firewall(posture.firewall.as_ref(), &posture.nftables);
        view.jail(posture.fail2ban);
        view.ssh(posture.ssh.as_ref());
        match &posture.ports {
            Some(ports) => view.ports(ports, both_drop, firewall_read),
            None => view.rpc_port(posture.listeners, both_drop, firewall_read),
        }
        view.metadata(posture.metadata.as_ref());
        view.updates(posture.updates.as_ref());
        view.keys(posture.keys.as_ref());
        view.rank(ranked);
        view
    }

    fn need(&mut self, topic: Topic, text: String, lines: Vec<Line>, todo: Vec<Todo>) {
        self.look.push(Item {
            topic,
            text,
            lines,
            todo,
        });
    }

    fn unknown(&mut self, topics: &'static [Topic], text: String, todo: Todo) {
        self.open.push(Open { topics, text, todo });
    }

    /// Puts what needs a look in order: the key search's findings first
    /// (ERPC never sees them, and a key in plain text can lose funds at
    /// once), then the order of `ranked`, then the rest in the fixed order.
    /// A ranked finding that no result here speaks to is listed in its own
    /// words, so nothing the report ranked is left out.
    fn rank(&mut self, ranked: &[FindingId]) {
        for &id in ranked {
            let topics = Topic::of(id);
            let spoken = if topics.is_empty() {
                !self.open.is_empty()
            } else {
                self.look.iter().any(|item| topics.contains(&item.topic))
                    || self
                        .open
                        .iter()
                        .any(|open| open.topics.iter().any(|topic| topics.contains(topic)))
            };
            if !spoken && !self.look.iter().any(|item| item.topic == Topic::Ranked(id)) {
                self.need(
                    Topic::Ranked(id),
                    sentence(&id.label()),
                    Vec::new(),
                    Vec::new(),
                );
            }
        }
        self.look.sort_by_key(|item| {
            (
                item.topic != Topic::Keys,
                ranked
                    .iter()
                    .position(|id| item.topic.named_by(*id))
                    .unwrap_or(usize::MAX),
                item.topic.order(),
            )
        });
    }

    fn firewall(&mut self, firewall: Option<&Firewall>, nftables: &Nftables) {
        const OPEN: &[Topic] = &[Topic::Firewall];
        let rules = || Todo::Run("sudo nft list ruleset".to_owned());
        let Some(firewall) = firewall else {
            match nftables {
                Nftables::NoTablesObserved => self.need(
                    Topic::Firewall,
                    t!("node_check.view_firewall_no_tables"),
                    Vec::new(),
                    vec![Todo::Words(t!("node_check.view_firewall_set_up"))],
                ),
                Nftables::TablesPresent | Nftables::NotObserved => {
                    self.unknown(OPEN, t!("node_check.view_firewall_absent"), rules());
                }
            }
            return;
        };
        // A section that ran out of room judges nothing.
        let judged = |evidence| {
            if firewall.truncated {
                FirewallEvidence::Unknown
            } else {
                evidence
            }
        };
        let (ipv4, ipv6) = (judged(firewall.ipv4), judged(firewall.ipv6));
        // One line for both families when they agree.
        let mut said = Vec::new();
        for evidence in [ipv4, ipv6] {
            if said.contains(&evidence) {
                continue;
            }
            said.push(evidence);
            let families = match (ipv4 == evidence, ipv6 == evidence) {
                (true, true) => "IPv4/IPv6",
                (true, false) => "IPv4",
                (false, _) => "IPv6",
            };
            match evidence {
                FirewallEvidence::InputDefaultDrop => self
                    .fine
                    .push(t!("node_check.view_firewall_drops", families = families)),
                FirewallEvidence::NoInputFilterHook => self.need(
                    Topic::Firewall,
                    t!("node_check.view_firewall_none", families = families),
                    Vec::new(),
                    vec![Todo::Words(t!("node_check.view_firewall_set_up"))],
                ),
                FirewallEvidence::InputFilterHook => self.need(
                    Topic::Firewall,
                    t!("node_check.view_firewall_accepts", families = families),
                    Vec::new(),
                    vec![rules()],
                ),
                FirewallEvidence::ConfiguredDropOrRejectRule => self.need(
                    Topic::Firewall,
                    t!("node_check.view_firewall_rules_only", families = families),
                    Vec::new(),
                    vec![rules()],
                ),
                FirewallEvidence::Unknown => self.unknown(
                    OPEN,
                    t!("node_check.view_firewall_unknown", families = families),
                    rules(),
                ),
            }
        }
    }

    fn jail(&mut self, jail: Option<Jail>) {
        const OPEN: &[Topic] = &[Topic::Jail];
        let status = || Todo::Run("sudo fail2ban-client status sshd".to_owned());
        match jail {
            Some(Jail::SshdJailObserved) => self.fine.push(t!("node_check.view_jail_ok")),
            Some(Jail::SshdJailNotListed) => self.need(
                Topic::Jail,
                t!("node_check.view_jail_missing"),
                Vec::new(),
                vec![Todo::Words(t!("node_check.view_jail_fix"))],
            ),
            Some(Jail::Unknown) => {
                self.unknown(OPEN, t!("node_check.view_jail_unknown"), status());
            }
            None => self.unknown(OPEN, t!("node_check.view_jail_absent"), status()),
        }
    }

    fn ssh(&mut self, ssh: Option<&Ssh>) {
        const OPEN: &[Topic] = &[Topic::SshAuth];
        let dump = || {
            Todo::Run(
                "sudo sshd -T | grep -Ei '^(password|kbdinteractive)authentication'".to_owned(),
            )
        };
        let Some(ssh) = ssh else {
            self.unknown(OPEN, t!("node_check.view_ssh_absent"), dump());
            return;
        };
        let state = |switch| match switch {
            Switch::Enabled => 2,
            Switch::Unknown => 1,
            Switch::Disabled => 0,
        };
        let (password, keyboard) = (state(ssh.password), state(ssh.keyboard_interactive));
        let text = match (password == 2, keyboard == 2) {
            (true, true) => Some(t!("node_check.view_ssh_both")),
            (true, false) => Some(t!("node_check.view_ssh_password")),
            (false, true) => Some(t!("node_check.view_ssh_keyboard")),
            (false, false) => None,
        };
        if let Some(text) = text {
            self.need(
                Topic::SshAuth,
                text,
                Vec::new(),
                vec![Todo::Words(t!("node_check.view_ssh_fix"))],
            );
        } else if password == 1 || keyboard == 1 {
            self.unknown(OPEN, t!("node_check.view_ssh_unread"), dump());
        } else {
            // On disk, for this login's connection: the running server and
            // other logins may differ.
            self.unknown(
                OPEN,
                t!("node_check.view_ssh_configured_off"),
                Todo::Words(t!("node_check.view_ssh_try")),
            );
        }
    }

    fn ports(&mut self, ports: &Ports, both_drop: bool, firewall_read: bool) {
        const OPEN: &[Topic] = &[Topic::Listeners, Topic::Redis, Topic::Unclassified];
        const UNSEEN: &[Topic] = &[Topic::Redis, Topic::Unclassified];
        let sockets = || Todo::Run("sudo ss -tulpn".to_owned());
        let rows = Rows::of(ports);
        if !rows.all.is_empty() || !rows.interface.is_empty() {
            let count = rows.all.len() + rows.interface.len();
            let (text, lines) = match (rows.all.as_slice(), rows.interface.as_slice()) {
                ([one], []) => (
                    t!("node_check.view_listening_all_one", port = one.label()),
                    Vec::new(),
                ),
                ([], [one]) => (
                    t!(
                        "node_check.view_listening_interface_one",
                        port = one.label()
                    ),
                    Vec::new(),
                ),
                (all, interface) => (tn!("node_check.view_listening_many", count), {
                    let mut lines = Vec::new();
                    if !all.is_empty() {
                        lines.push(t!("node_check.view_listening_all", ports = listed(all)));
                    }
                    if !interface.is_empty() {
                        lines.push(t!(
                            "node_check.view_listening_interface",
                            ports = listed(interface)
                        ));
                    }
                    lines
                }),
            };
            let mut lines: Vec<Line> = lines.into_iter().map(Line::from).collect();
            lines.push(filtered(both_drop, firewall_read).into());
            self.need(
                Topic::Listeners,
                text,
                lines,
                vec![Todo::Run("sudo nft list ruleset".to_owned())],
            );
        }
        let redis: Vec<&Row> = rows
            .all
            .iter()
            .chain(&rows.interface)
            .filter(|row| {
                row.port
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::Redis | Service::Valkey))
            })
            .collect();
        if !redis.is_empty() {
            self.need(
                Topic::Redis,
                t!("node_check.view_redis"),
                vec![listed_refs(&redis).into()],
                vec![Todo::Words(t!("node_check.view_redis_fix"))],
            );
        }
        let strangers = rows.with(Service::Unclassified);
        if !strangers.is_empty() {
            self.need(
                Topic::Unclassified,
                t!("node_check.view_unclassified"),
                vec![listed_refs(&strangers).into()],
                vec![sockets()],
            );
        }
        if !rows.loopback.is_empty() {
            self.fine.push(t!(
                "node_check.view_inside_only",
                ports = listed(&rows.loopback)
            ));
        }
        let read = [&ports.tcp, &ports.udp].map(|group| group.coverage);
        if read.contains(&Coverage::Unknown) {
            self.unknown(OPEN, t!("node_check.view_ports_unread"), sockets());
        } else if ports.truncated || read.contains(&Coverage::Partial) {
            self.unknown(OPEN, t!("node_check.view_ports_partial"), sockets());
        } else if rows.is_empty() {
            self.fine.push(t!("node_check.view_no_ports"));
        }
        let unseen = rows.with(Service::Unknown);
        if !unseen.is_empty() {
            self.unknown(
                UNSEEN,
                t!(
                    "node_check.view_programs_unseen",
                    ports = listed_refs(&unseen)
                ),
                sockets(),
            );
        }
    }

    /// The older report's TCP 8899 result, when the collector listed no
    /// ports.
    fn rpc_port(
        &mut self,
        listeners: erpc_api::node_check::Finding,
        both_drop: bool,
        firewall_read: bool,
    ) {
        use erpc_api::node_check::Finding as Rpc;

        self.unknown(
            &[Topic::Listeners, Topic::Redis, Topic::Unclassified],
            t!("node_check.view_ports_absent"),
            Todo::Run("sudo ss -tulpn".to_owned()),
        );
        match listeners {
            Rpc::ReviewBinding => self.need(
                Topic::Listeners,
                t!("node_check.view_rpc_open"),
                vec![filtered(both_drop, firewall_read).into()],
                vec![Todo::Run("sudo nft list ruleset".to_owned())],
            ),
            Rpc::LoopbackBinding => self.fine.push(t!("node_check.view_rpc_inside")),
            Rpc::NoListener | Rpc::Inconclusive => {}
        }
    }

    fn metadata(&mut self, metadata: Option<&Metadata>) {
        const OPEN: &[Topic] = &[Topic::EnvFiles, Topic::Credentials];
        let services = || Todo::Words(t!("node_check.view_services_fix"));
        let Some(metadata) = metadata else {
            self.unknown(OPEN, t!("node_check.view_services_absent"), services());
            return;
        };
        match metadata.coverage {
            MetadataCoverage::Unknown => {
                self.unknown(OPEN, t!("node_check.view_services_unread"), services());
                return;
            }
            MetadataCoverage::Partial => {
                self.unknown(OPEN, t!("node_check.view_services_partial"), services());
            }
            MetadataCoverage::Observed if metadata.truncated => {
                self.unknown(OPEN, t!("node_check.view_services_partial"), services());
            }
            MetadataCoverage::Observed => {}
        }
        self.service_files(metadata);
        let environment = metadata.environment_files();
        let credentials = &metadata.credential_sources;
        let ls = || Todo::Words(t!("node_check.view_ls_fix"));
        if environment.unknown > 0 {
            self.unknown(
                &[Topic::EnvFiles],
                tn!("node_check.view_env_modes_unknown", environment.unknown),
                ls(),
            );
        }
        if credentials.unknown > 0 {
            self.unknown(
                &[Topic::Credentials],
                tn!("node_check.view_credentials_unknown", credentials.unknown),
                ls(),
            );
        }
        if credentials.owner_only > 0 && credentials.group_or_other_access == 0 {
            self.fine.push(t!("node_check.view_credentials_owner"));
        }
        let complete = metadata.coverage == MetadataCoverage::Observed && !metadata.truncated;
        if complete && environment.total() == 0 && credentials.total() == 0 {
            self.fine.push(t!("node_check.view_services_none"));
        }
    }

    /// The services' files whose mode opens them to others, and the
    /// environment files they load at all: each with its lines.
    fn service_files(&mut self, metadata: &Metadata) {
        let environment = metadata.environment_files();
        let credentials = &metadata.credential_sources;
        let files = |source| -> Vec<&ServiceFile> {
            let mut files: Vec<&ServiceFile> = metadata
                .files
                .iter()
                .filter(|file| file.source == source)
                .collect();
            files.sort_by_key(|file| match file.broad() {
                Some(true) => 0,
                None => 1,
                Some(false) => 2,
            });
            files
        };
        let env_files = files(FileSource::EnvironmentFile);
        if environment.group_or_other_access > 0 {
            let broad = environment.group_or_other_access;
            let text = if readable(&env_files, broad) {
                tn!("node_check.view_env_readable", broad)
            } else {
                tn!("node_check.view_env_open", broad)
            };
            let todo = vec![
                chmod(&env_files, broad),
                Todo::Words(t!("node_check.view_env_fix")),
            ];
            self.need(Topic::EnvFiles, text, file_lines(&env_files), todo);
        } else if environment.total() > 0 {
            self.need(
                Topic::EnvFiles,
                tn!("node_check.view_env_in_use", environment.total()),
                file_lines(&env_files),
                vec![Todo::Words(t!("node_check.view_env_fix"))],
            );
        }
        let credential_files = files(FileSource::Credential);
        if credentials.group_or_other_access > 0 {
            let broad = credentials.group_or_other_access;
            let text = if readable(&credential_files, broad) {
                tn!("node_check.view_credentials_readable", broad)
            } else {
                tn!("node_check.view_credentials_open", broad)
            };
            self.need(
                Topic::Credentials,
                text,
                file_lines(&credential_files),
                vec![chmod(&credential_files, broad)],
            );
        }
        if metadata.files_more > 0
            && let Some(last) = self
                .look
                .iter_mut()
                .rev()
                .find(|item| matches!(item.topic, Topic::EnvFiles | Topic::Credentials))
        {
            last.lines
                .push(tn!("node_check.view_files_more", metadata.files_more).into());
        }
    }

    fn updates(&mut self, updates: Option<&Updates>) {
        const OPEN: &[Topic] = &[Topic::Updates];
        let list = || Todo::Run("sudo apt update && apt list --upgradable".to_owned());
        let Some(updates) = updates else {
            self.unknown(OPEN, t!("node_check.view_updates_absent"), list());
            return;
        };
        match updates.status {
            UpdateStatus::Available => self.need(
                Topic::Updates,
                tn!(
                    "node_check.view_updates",
                    updates.packages.unwrap_or_default()
                ),
                Vec::new(),
                vec![Todo::Run("sudo apt update && sudo apt upgrade".to_owned())],
            ),
            UpdateStatus::NoneInCachedCandidates => {
                self.fine.push(t!("node_check.view_updates_none"));
            }
            UpdateStatus::Unknown => {
                self.unknown(OPEN, t!("node_check.view_updates_unknown"), list());
            }
        }
    }

    fn keys(&mut self, keys: Option<&Keys>) {
        const OPEN: &[Topic] = &[Topic::Keys];
        let again = || Todo::Words(t!("node_check.view_keys_fix"));
        let Some(keys) = keys else {
            self.unknown(OPEN, t!("node_check.view_keys_absent"), again());
            return;
        };
        for finding in Finding::ALL {
            let groups: Vec<_> = keys
                .groups
                .iter()
                .filter(|group| group.finding() == Some(finding))
                .collect();
            if groups.is_empty() {
                continue;
            }
            let (text, fix) = finding.words();
            let mut lines = Vec::new();
            for group in groups {
                let who = readable_by(group.access);
                lines.extend(
                    group.places.iter().map(|place| {
                        Line::Exact(format!("{} ({who})", posture_keys::shown(place)))
                    }),
                );
                if group.more > 0 {
                    lines.push(t!("node_check.key_more", count = group.more).into());
                }
            }
            self.need(
                Topic::Keys,
                sentence(&text),
                lines,
                vec![Todo::Words(sentence(&fix))],
            );
        }
        if keys
            .groups
            .iter()
            .any(|group| group.access == Access::World)
        {
            self.need(
                Topic::Keys,
                sentence(&t!("node_check.finding_key_world_readable")),
                vec![
                    t!(
                        "node_check.view_world_above",
                        who = readable_by(Access::World)
                    )
                    .into(),
                ],
                vec![Todo::Words(sentence(&t!(
                    "node_check.fix_key_world_readable"
                )))],
            );
        }
        if keys.groups.iter().any(|group| group.finding().is_none()) {
            self.fine.push(t!("node_check.view_identity_owner"));
        }
        match keys.coverage {
            posture_keys::Coverage::Complete => {
                if keys.groups.is_empty() {
                    self.fine.push(t!("node_check.view_keys_none"));
                }
            }
            posture_keys::Coverage::Partial => {
                if keys.groups.is_empty() {
                    self.fine.push(t!("node_check.view_keys_none_readable"));
                }
                self.unknown(OPEN, t!("node_check.view_keys_partial"), again());
            }
            posture_keys::Coverage::Unreadable => {
                self.unknown(OPEN, t!("node_check.view_keys_unreadable"), again());
            }
        }
    }
}

/// The context line under ports that listen beyond the server: what the
/// firewall was seen to do, never whether anyone can reach them.
fn filtered(both_drop: bool, firewall_read: bool) -> String {
    if both_drop {
        t!("node_check.view_firewall_filters")
    } else if firewall_read {
        t!("node_check.view_firewall_lets_in")
    } else {
        t!("node_check.view_firewall_unread")
    }
}

/// Who can read a key's file, as the key search judged it.
fn readable_by(access: Access) -> String {
    match access {
        Access::OwnerOnly => t!("node_check.view_readable_owner"),
        Access::Group => t!("node_check.view_readable_group"),
        Access::World => t!("node_check.view_readable_world"),
    }
}

/// A sentence used as a line of its own: without its closing full stop.
fn sentence(text: &str) -> String {
    text.trim_end_matches(['.', '。']).to_owned()
}

/// A listening port and the services seen on it.
struct Row<'a> {
    protocol: &'static str,
    port: &'a Port,
}

impl Row<'_> {
    /// `TCP 22`, with the services seen on it when they are known:
    /// `TCP 6379 (Redis)`. A port is never named by a service it was not
    /// seen to have.
    fn label(&self) -> String {
        format!("{} {}", self.protocol, self.short())
    }

    /// [`Self::label`] without the protocol.
    fn short(&self) -> String {
        let known: Vec<String> = self
            .port
            .services
            .iter()
            .filter(|service| **service != Service::Unknown)
            .map(|service| service.label())
            .collect();
        if known.is_empty() {
            self.port.port.to_string()
        } else {
            format!("{} ({})", self.port.port, known.join(" / "))
        }
    }
}

/// The listening ports by where they listen.
struct Rows<'a> {
    all: Vec<Row<'a>>,
    interface: Vec<Row<'a>>,
    loopback: Vec<Row<'a>>,
}

impl<'a> Rows<'a> {
    fn of(ports: &'a Ports) -> Self {
        let rows = |pick: fn(&'a PortGroups) -> &'a Vec<Port>| -> Vec<Row<'a>> {
            [("TCP", &ports.tcp), ("UDP", &ports.udp)]
                .into_iter()
                .flat_map(move |(protocol, group)| {
                    pick(group).iter().map(move |port| Row { protocol, port })
                })
                .collect()
        };
        Self {
            all: rows(|group| &group.wildcard),
            interface: rows(|group| &group.interface),
            loopback: rows(|group| &group.loopback),
        }
    }

    fn is_empty(&self) -> bool {
        self.all.is_empty() && self.interface.is_empty() && self.loopback.is_empty()
    }

    /// The ports, wherever they listen, that `service` was seen on.
    fn with(&self, service: Service) -> Vec<&Row<'a>> {
        self.all
            .iter()
            .chain(&self.interface)
            .chain(&self.loopback)
            .filter(|row| row.port.services.contains(&service))
            .collect()
    }
}

/// How many ports a line names before "and N more".
const PORTS_SHOWN: usize = 12;

fn listed(rows: &[Row<'_>]) -> String {
    listed_refs(&rows.iter().collect::<Vec<_>>())
}

/// The ports by protocol, each once: `TCP 22, 53, 3000 / UDP 53`, then
/// "and N more" past [`PORTS_SHOWN`].
fn listed_refs(rows: &[&Row<'_>]) -> String {
    let mut rows = rows.to_vec();
    rows.sort_by_key(|row| (row.protocol, row.port.port));
    rows.dedup_by_key(|row| (row.protocol, row.port.port));
    let shown = &rows[..rows.len().min(PORTS_SHOWN)];
    let mut text = ["TCP", "UDP"]
        .into_iter()
        .filter_map(|protocol| {
            let ports: Vec<String> = shown
                .iter()
                .filter(|row| row.protocol == protocol)
                .map(|row| row.short())
                .collect();
            (!ports.is_empty()).then(|| format!("{protocol} {}", ports.join(", ")))
        })
        .collect::<Vec<_>>()
        .join(" / ");
    if rows.len() > shown.len() {
        text.push_str(", ");
        text.push_str(&t!("node_check.key_more", count = rows.len() - shown.len()));
    }
    text
}

/// A service's file as a line: `example.service → /etc/example.env (0644)`.
fn file_lines(files: &[&ServiceFile]) -> Vec<Line> {
    files
        .iter()
        .map(|file| {
            let mode = match (file.kind, file.mode) {
                (Some(FileType::File | FileType::Directory), Some(mode)) => format!("{mode:04o}"),
                (Some(FileType::Other), _) => t!("node_check.view_file_other"),
                (Some(FileType::File | FileType::Directory) | None, _) => {
                    t!("node_check.view_file_unknown")
                }
            };
            Line::Exact(format!(
                "{} → {} ({mode})",
                file.unit,
                posture_keys::shown(&file.path)
            ))
        })
        .collect()
}

/// Whether a path pastes into a shell as it is: only letters, digits and
/// `/._-+,:@=` (so no space, quote, `$`, glob or control character).
fn shell_plain(path: &str) -> bool {
    posture_keys::decode(path).is_some_and(|bytes| {
        bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+,:@=".contains(b))
    })
}

/// The paths of the files whose mode opens them to others, each once.
fn open_paths<'a>(files: &[&'a ServiceFile]) -> Vec<&'a str> {
    let mut paths: Vec<&str> = files
        .iter()
        .filter(|file| file.broad() == Some(true))
        .map(|file| file.path.as_str())
        .collect();
    paths.sort_unstable();
    paths.dedup();
    paths
}

/// Whether the mode of every file counted as open to others (all `broad`
/// of them listed) lets its group or others read it: what "can read" may
/// say. Otherwise their modes only give others some access.
fn readable(files: &[&ServiceFile], broad: u16) -> bool {
    open_paths(files).len() == usize::from(broad)
        && files
            .iter()
            .filter(|file| file.broad() == Some(true))
            .all(|file| file.mode.is_some_and(|mode| mode & 0o044 != 0))
}

/// What to do about the files others can read: `sudo chmod 600` and their
/// paths when every one of them is listed, is a regular file and pastes
/// into a shell as it is; words otherwise (a directory needs its search
/// bit, and a path that is not plain is no command to paste).
fn chmod(files: &[&ServiceFile], broad: u16) -> Todo {
    let paths = open_paths(files);
    let commandable = paths.len() == usize::from(broad)
        && files
            .iter()
            .filter(|file| file.broad() == Some(true))
            .all(|file| file.kind == Some(FileType::File) && shell_plain(&file.path));
    if commandable {
        Todo::Run(format!("sudo chmod 600 {}", paths.join(" ")))
    } else {
        Todo::Words(t!("node_check.view_chmod_words"))
    }
}

/// `n` with its digits grouped as the language writes them: `2,408`, and
/// `2 408` (a no-break space) in Russian.
fn grouped(n: u32) -> String {
    let separator = match crate::cli::i18n::lang() {
        erpc_core::i18n::Lang::Ru => '\u{a0}',
        erpc_core::i18n::Lang::En | erpc_core::i18n::Lang::Ja | erpc_core::i18n::Lang::Zh => ',',
    };
    let digits = n.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(separator);
        }
        out.push(digit);
    }
    out
}

/// The report for `server`: its title, the counts, the three groups and
/// the charge (or why there is none), drawn as `look` says. `evidence`,
/// when given, follows under its own heading.
pub(super) fn render(
    server: &EligibleServer,
    posture: &Posture,
    model: &Result<billing::Receipt, ReportFailure>,
    request: &str,
    look: Look,
    evidence: Option<&str>,
) -> String {
    let ranked = model.as_ref().map_or(&[][..], billing::Receipt::findings);
    let view = View::of(posture, ranked);
    let bold = look.style(Style::new().bold());
    let mut out = Vec::new();
    let name = match server.region {
        Some(region) => format!("{} ({region})", server.rental.canonical_id()),
        None => server.rental.canonical_id(),
    };
    out.push(
        bold.apply_to(t!("node_check.view_title", server = name))
            .to_string(),
    );
    out.push(String::new());
    out.push(format!(
        "  {}",
        [
            tn!("node_check.view_count_look", view.look.len()),
            tn!("node_check.view_count_fine", view.fine.len()),
            tn!("node_check.view_count_unknown", view.open.len()),
        ]
        .join(" · ")
    ));
    if !view.look.is_empty() {
        out.push(String::new());
        out.push(look.heading("⚠", t!("node_check.view_look"), Style::new().yellow()));
        for (index, item) in view.look.iter().enumerate() {
            look.item(&mut out, index + 1, item);
        }
    }
    if !view.fine.is_empty() {
        out.push(String::new());
        out.push(look.heading("✓", t!("node_check.view_fine"), Style::new().green()));
        for line in packed(&view.fine, look.width.saturating_sub(2)) {
            out.extend(hanging(&line, "  ", "    ", look.width));
        }
    }
    if !view.open.is_empty() {
        out.push(String::new());
        out.push(look.heading("?", t!("node_check.view_unknown"), Style::new().cyan()));
        for open in &view.open {
            out.extend(hanging(&open.text, "  ", "    ", look.width));
            out.extend(look.todo(&open.todo, "    "));
        }
    }
    out.push(String::new());
    let footer = match model {
        Ok(receipt) => tn!(
            "node_check.view_charged",
            receipt.charged(),
            charged = grouped(receipt.charged()),
            maximum = grouped(billing::MAXIMUM)
        ),
        Err(failure) => failure.message(request),
    };
    for line in footer.lines() {
        out.extend(hanging(line, "", "", look.width));
    }
    if let Some(evidence) = evidence {
        out.push(String::new());
        out.push(bold.apply_to(t!("node_check.view_details")).to_string());
        out.push(evidence.to_owned());
    }
    out.join("\n")
}

impl Look {
    /// A group's heading: its mark first when marks are drawn.
    fn heading(self, mark: &str, text: String, style: Style) -> String {
        let text = if self.marks {
            format!("{mark} {text}")
        } else {
            text
        };
        self.style(style.bold()).apply_to(text).to_string()
    }

    /// A numbered result, its lines and what to do, each lined up with the
    /// result's words.
    fn item(self, out: &mut Vec<String>, number: usize, item: &Item) {
        let number = format!("{number}.");
        let under = " ".repeat(3 + number.len());
        let bold = self.style(Style::new().bold());
        // The number takes as many columns as the indent under it.
        let mut text = hanging(&item.text, &under, &under, self.width);
        if let Some(first) = text.first_mut() {
            *first = format!("  {} {}", bold.apply_to(&number), &first[under.len()..]);
        }
        out.extend(text);
        for line in &item.lines {
            match line {
                Line::Words(words) => out.extend(hanging(words, &under, &under, self.width)),
                Line::Exact(exact) => out.push(format!("{under}{exact}")),
            }
        }
        for step in &item.todo {
            out.extend(self.todo(step, &under));
        }
    }

    /// What to do, after `→` at `indent`: a command whole, on one line
    /// whatever its length, so that it pastes as it is; words wrapped.
    fn todo(self, todo: &Todo, indent: &str) -> Vec<String> {
        let arrow = self.style(Style::new().dim()).apply_to("→");
        match todo {
            Todo::Run(command) => vec![format!(
                "{indent}{arrow} {}",
                self.style(crate::cli::ui::blue()).apply_to(command)
            )],
            Todo::Words(words) => {
                let first = format!("{indent}→ ");
                let rest = format!("{indent}  ");
                hanging(words, &first, &rest, self.width)
                    .into_iter()
                    .enumerate()
                    .map(|(index, line)| {
                        if index == 0 {
                            format!("{indent}{arrow} {}", &line[first.len()..])
                        } else {
                            line
                        }
                    })
                    .collect()
            }
        }
    }
}

fn columns(text: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(text)
}

/// Whether `c` takes two columns, as East Asian letters do: a line may
/// break before or after one without a space.
fn wide(c: char) -> bool {
    unicode_width::UnicodeWidthChar::width(c) == Some(2)
}

/// `text` in lines that fit `width` columns: `first` before the first,
/// `rest` before each after it. Lines break at a space, or between wide
/// characters, never before closing punctuation, a prolonged sound mark or
/// a small kana, nor after opening punctuation; a word longer than a line
/// stays whole.
fn hanging(text: &str, first: &str, rest: &str, width: usize) -> Vec<String> {
    const CLOSING: &str =
        "、。，．：；）」』】・ー！？ぁぃぅぇぉっゃゅょゎァィゥェォッャュョヮヵヶ";
    const OPENING: &str = "（「『【";
    // Pieces that stay together, each with whether a space came before it.
    let mut pieces: Vec<(String, bool)> = Vec::new();
    let mut piece = String::new();
    let mut spaced = false;
    let mut before: Option<char> = None;
    for c in text.chars() {
        if c == ' ' {
            if !piece.is_empty() {
                pieces.push((std::mem::take(&mut piece), spaced));
            }
            spaced = true;
            before = None;
            continue;
        }
        if let Some(previous) = before
            && (wide(previous) || wide(c))
            && !CLOSING.contains(c)
            && !OPENING.contains(previous)
        {
            pieces.push((std::mem::take(&mut piece), spaced));
            spaced = false;
        }
        piece.push(c);
        before = Some(c);
    }
    if !piece.is_empty() {
        pieces.push((piece, spaced));
    }
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for (piece, spaced) in pieces {
        let prefix = if lines.is_empty() { first } else { rest };
        let gap = usize::from(spaced && !line.is_empty());
        if !line.is_empty() && columns(prefix) + columns(&line) + gap + columns(&piece) > width {
            lines.push(format!("{prefix}{line}"));
            line = piece;
        } else {
            if gap == 1 {
                line.push(' ');
            }
            line.push_str(&piece);
        }
    }
    let prefix = if lines.is_empty() { first } else { rest };
    lines.push(format!("{prefix}{line}"));
    lines
}

/// The fine results, as many on a line as fit in `width` columns.
fn packed(entries: &[String], width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for entry in entries {
        match lines.last_mut() {
            Some(line) if columns(line) + 3 + columns(entry) <= width => {
                line.push_str(" · ");
                line.push_str(entry);
            }
            _ => lines.push(entry.clone()),
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use erpc_core::i18n::Lang;
    use serde_json::{Value, json};

    use super::super::billing::{FindingId, Receipt, ReportFailure};
    use super::super::tests::{sample_server, sample_wire};
    use super::super::{Posture, decode_posture};
    use super::{Look, Todo, Topic, View, render};

    fn posture(wire: &Value) -> Posture {
        decode_posture(wire.to_string().as_bytes()).expect("valid posture")
    }

    /// The charge for the sample: 512 + 3 × 448 + 12 × 46.
    fn receipt(findings: &[&str]) -> Receipt {
        serde_json::from_value(json!({"status": "completed", "model": "fixture-model-a",
            "findings": findings, "billing": {"meterVersion": "posture1", "chargedCredits": 2408,
                "baseCredits": 512, "inputTokens": 448, "outputTokens": 46}}))
        .expect("receipt")
    }

    fn sample_findings() -> Receipt {
        receipt(&[
            "review_listener_bindings",
            "review_file_permissions",
            "review_env_file_use",
            "verify_unobserved_posture",
        ])
    }

    fn no_charge() -> ReportFailure {
        ReportFailure::from_response(
            409,
            r#"{"error":"posture_report_no_actionable_candidates"}"#,
        )
    }

    fn shown(
        lang: Lang,
        wire: &Value,
        model: &Result<Receipt, ReportFailure>,
        look: Look,
    ) -> String {
        crate::cli::i18n::speaking(lang, || {
            render(
                &sample_server(),
                &posture(wire),
                model,
                "fixture-request",
                look,
                None,
            )
        })
    }

    fn ids(names: &[&str]) -> Vec<FindingId> {
        names
            .iter()
            .map(|name| serde_json::from_value(json!(name)).expect("finding id"))
            .collect()
    }

    fn view(wire: &Value, ranked: &[&str]) -> View {
        View::of(&posture(wire), &ids(ranked))
    }

    fn texts(view: &View) -> (Vec<&str>, Vec<&str>, Vec<&str>) {
        (
            view.look.iter().map(|item| item.text.as_str()).collect(),
            view.fine.iter().map(String::as_str).collect(),
            view.open.iter().map(|open| open.text.as_str()).collect(),
        )
    }

    /// A server with nothing to look at: loopback DNS, both firewalls
    /// dropping by default, the jail, no service files, no updates and a
    /// complete key search with nothing found. SSH's settings turn
    /// passwords off, which stays something not checked.
    fn clean() -> Value {
        let none = json!({"owner_only": 0, "group_or_other_access": 0, "unknown": 0});
        json!({
            "listeners": "no_listener", "nftables": "tables_present",
            "ports": {
                "tcp": {"coverage": "complete", "wildcard": [], "interface": [],
                    "loopback": [{"port": 53, "services": ["dns"]}]},
                "udp": {"coverage": "complete", "wildcard": [], "interface": [], "loopback": []},
                "truncated": false,
            },
            "ssh": {"source": "default_config_for_connection", "password": "disabled",
                "keyboard_interactive": "disabled"},
            "firewall": {"ipv4": "input_default_drop", "ipv6": "input_default_drop",
                "truncated": false},
            "fail2ban": "sshd_jail_observed",
            "metadata": {"coverage": "observed", "units_with_evidence": 1, "truncated": false,
                "environment_files": none, "service_env": none, "credential_sources": none,
                "distinct_credential_sources": {"as_is": 0, "encrypted": 0},
                "files": [], "files_more": 0},
            "updates": {"status": "none_in_cached_candidates", "packages": 0},
            "keys": {"coverage": "complete", "groups": []},
        })
    }

    #[test]
    #[ignore = "a tool, not a test: prints the sample report"]
    fn print_the_sample() {
        let model = Ok(sample_findings());
        for lang in [Lang::En, Lang::Ja, Lang::Zh, Lang::Ru] {
            println!(
                "{}\n-----",
                shown(lang, &sample_wire(), &model, Look::PLAIN)
            );
        }
        for wire in variants().iter().skip(1) {
            println!(
                "{}\n-----",
                shown(Lang::En, wire, &Err(no_charge()), Look::PLAIN)
            );
        }
        // As this terminal takes it.
        println!("{}", shown(Lang::Ja, &sample_wire(), &model, Look::here()));
    }

    #[test]
    fn a_clean_server_has_nothing_to_look_at() {
        let clean = view(&clean(), &[]);
        let (look, fine, open) = texts(&clean);
        assert!(look.is_empty(), "{look:?}");
        assert_eq!(
            fine,
            [
                "Firewall drops incoming by default (IPv4/IPv6)",
                "fail2ban watches SSH",
                "Inside the server only: TCP 53 (DNS)",
                "The services the check reads load no environment or credential files",
                "No security updates in the package list",
                "No plain-text keys or seed phrases",
            ]
        );
        // Turned off on disk for this login is not proof the running
        // server refuses passwords.
        assert_eq!(
            open,
            [
                "SSH password login: the SSH server's settings turn it off for this login; the \
              running server and other logins were not checked"
            ]
        );
    }

    /// `wire` with each JSON pointer set to its value.
    fn with(mut wire: Value, edits: &[(&str, Value)]) -> Value {
        for (pointer, value) in edits {
            *wire.pointer_mut(pointer).expect(pointer) = value.clone();
        }
        wire
    }

    fn port(port: u16, services: &[&str]) -> Value {
        json!({"port": port, "services": services})
    }

    fn topics(view: &View) -> Vec<Topic> {
        view.look.iter().map(|item| item.topic).collect()
    }

    #[test]
    fn the_ranked_findings_order_what_needs_a_look_and_the_rest_follows() {
        let sample = sample_wire();
        let ranked = [
            "review_listener_bindings",
            "review_file_permissions",
            "review_env_file_use",
            "verify_unobserved_posture",
        ];
        assert_eq!(
            topics(&view(&sample, &ranked)),
            [Topic::Listeners, Topic::EnvFiles]
        );
        assert_eq!(
            topics(&view(
                &sample,
                &["review_env_file_use", "review_listener_bindings"]
            )),
            [Topic::EnvFiles, Topic::Listeners]
        );
        // No ranking (nothing charged): the fixed order.
        assert_eq!(
            topics(&view(&sample, &[])),
            [Topic::EnvFiles, Topic::Listeners]
        );
        // The key search's findings never reach ERPC, and a key in plain
        // text can lose funds at once: first, above what ERPC ranked.
        let keys = json!({"coverage": "complete", "groups": [{"kind": "mnemonic",
            "role": "unknown", "location": "opt", "access": "owner_only", "count": 1,
            "places": ["/opt/bot/seed.txt"], "more": 0}]});
        let with_keys = with(sample, &[("/keys", keys)]);
        assert_eq!(
            topics(&view(&with_keys, &ranked)),
            [Topic::Keys, Topic::Listeners, Topic::EnvFiles]
        );
        assert_eq!(
            topics(&view(&with_keys, &[])),
            [Topic::Keys, Topic::EnvFiles, Topic::Listeners]
        );
        // On screen too: item 1 is the seed phrase, whatever ERPC ranked first.
        let text = shown(Lang::En, &with_keys, &Ok(receipt(&ranked)), Look::PLAIN);
        assert!(
            text.contains("\n  1. A seed phrase is stored in plain text"),
            "{text}"
        );
    }

    /// Every finding of the key search heads the list, in its own order,
    /// above a ranked finding shown in its own words too.
    #[test]
    fn the_key_search_findings_head_what_needs_a_look() {
        let busy = busy();
        let ranked = [
            "review_ssh_jail",
            "identify_unclassified_listener",
            "review_input_filter",
            "verify_unobserved_posture",
        ];
        let order = topics(&view(&busy, &ranked));
        let keys = order
            .iter()
            .take_while(|topic| **topic == Topic::Keys)
            .count();
        assert_eq!(keys, 8, "{order:?}");
        assert!(!order[keys..].contains(&Topic::Keys), "{order:?}");
        assert_eq!(
            order[keys..keys + 3],
            [Topic::Jail, Topic::Unclassified, Topic::Firewall]
        );
        let clean_keys = with(clean(), &[("/keys", busy["keys"].clone())]);
        let order = topics(&view(&clean_keys, &["review_ssh_jail"]));
        assert_eq!(order.first(), Some(&Topic::Keys));
        assert_eq!(
            order.last(),
            Some(&Topic::Ranked(ids(&["review_ssh_jail"])[0]))
        );
    }

    #[test]
    fn a_ranked_finding_the_evidence_does_not_speak_to_is_shown_in_its_words() {
        let jail = view(&clean(), &["review_ssh_jail"]);
        assert_eq!(
            texts(&jail).0,
            ["Check that fail2ban is enforcing its sshd jail"]
        );
        // Evidence that could not be checked speaks to it: nothing added.
        let unknown = with(clean(), &[("/fail2ban", json!("unknown"))]);
        assert!(view(&unknown, &["review_ssh_jail"]).look.is_empty());
        // Verifying the unknown is the "could not check" group, when there
        // is one.
        assert!(
            view(&clean(), &["verify_unobserved_posture"])
                .look
                .is_empty()
        );
        let nothing_unknown = with(clean(), &[("/ssh/password", json!("enabled"))]);
        let verify = view(
            &nothing_unknown,
            &["verify_unobserved_posture", "review_ssh_authentication"],
        );
        assert!(verify.open.is_empty());
        assert_eq!(
            texts(&verify).0,
            [
                "Verify the unknown results with the appropriate read permissions",
                "SSH's settings allow logging in with a password, which can be guessed",
            ]
        );
        // Listed once however often it is ranked.
        assert_eq!(
            view(&clean(), &["review_ssh_jail", "review_ssh_jail"])
                .look
                .len(),
            1
        );
    }

    #[test]
    fn open_ports_name_their_service_only_when_it_was_seen() {
        let open = |wildcard: Value, interface: Value| {
            view(
                &with(
                    clean(),
                    &[
                        ("/ports/tcp/wildcard", wildcard),
                        ("/ports/tcp/interface", interface),
                    ],
                ),
                &[],
            )
        };
        let unseen = open(json!([port(22, &["unknown"])]), json!([]));
        assert_eq!(
            texts(&unseen).0,
            ["TCP 22 listens on all of the server's addresses, not only inside it"]
        );
        assert_eq!(
            unseen.look[0].lines,
            [
                "By default the firewall drops incoming connections it does not allow: check that \
              it lets in only what you expect"
            ]
        );
        assert_eq!(
            unseen.look[0].todo,
            [Todo::Run("sudo nft list ruleset".into())]
        );
        assert_eq!(
            texts(&open(json!([port(22, &["ssh"])]), json!([]))).0,
            ["TCP 22 (SSH) listens on all of the server's addresses, not only inside it"]
        );
        assert_eq!(
            texts(&open(json!([]), json!([port(9000, &["web"])]))).0,
            [
                "TCP 9000 (web service) listens on one of the server's network addresses, not only \
              inside it"
            ]
        );
        let many = open(
            json!([port(22, &["ssh"]), port(8899, &["solana"])]),
            json!([port(9000, &["web"])]),
        );
        assert_eq!(
            texts(&many).0,
            ["3 ports listen on the server's network addresses, not only inside it"]
        );
        assert_eq!(
            many.look[0].lines[..2],
            [
                "On all addresses: TCP 22 (SSH), 8899 (Solana)".to_owned(),
                "On a specific address: TCP 9000 (web service)".to_owned(),
            ]
        );
        let listed: Vec<Value> = (1..=14).map(|n| port(n, &["web"])).collect();
        let crowded = open(json!(listed), json!([]));
        assert!(
            crowded.look[0].lines[0].ends_with("12 (web service), and 2 more"),
            "{:?}",
            crowded.look[0].lines
        );
    }

    #[test]
    fn the_line_under_open_ports_says_only_what_the_firewall_was_seen_to_do() {
        let line = |edits: &[(&str, Value)]| {
            let mut all = vec![("/ports/tcp/wildcard", json!([port(22, &["ssh"])]))];
            all.extend(edits.iter().cloned());
            view(&with(clean(), &all), &[]).look[0].lines[0].clone()
        };
        assert!(line(&[]).starts_with("By default the firewall drops"));
        for edits in [
            vec![("/firewall/ipv6", json!("no_input_filter_hook"))],
            vec![("/firewall/ipv4", json!("configured_drop_or_reject_rule"))],
        ] {
            assert!(
                line(&edits).starts_with("The firewall does not drop every"),
                "{edits:?}"
            );
        }
        for edits in [
            vec![("/firewall/truncated", json!(true))],
            vec![("/firewall/ipv6", json!("unknown"))],
        ] {
            assert!(
                line(&edits).starts_with("The firewall's rules could not be read"),
                "{edits:?}"
            );
        }
        let no_section = with(
            clean(),
            &[("/ports/tcp/wildcard", json!([port(22, &["ssh"])]))],
        );
        let mut no_section = no_section;
        no_section
            .as_object_mut()
            .expect("object")
            .remove("firewall");
        assert!(
            view(&no_section, &[]).look[0].lines[0]
                .starts_with("The firewall's rules could not be read")
        );
    }

    #[test]
    fn listening_ports_fall_into_their_groups() {
        let ports =
            |edits: &[(&str, Value)]| texts(&view(&with(clean(), edits), &[])).clone_owned();
        let redis = ports(&[("/ports/tcp/wildcard", json!([port(6379, &["redis"])]))]);
        assert!(
            redis.0.contains(
                &"Redis or Valkey listens on the server's network addresses, not only inside it"
                    .to_owned()
            )
        );
        let inside = ports(&[("/ports/tcp/loopback", json!([port(6379, &["valkey"])]))]);
        assert!(inside.0.is_empty(), "{inside:?}");
        assert!(
            inside
                .1
                .contains(&"Inside the server only: TCP 6379 (Valkey)".to_owned())
        );
        let stranger = ports(&[(
            "/ports/udp/loopback",
            json!([port(4000, &["unclassified"])]),
        )]);
        assert_eq!(
            stranger.0,
            ["Programs erpc does not recognize are listening: check that each is one you set up"]
        );
        let unseen = ports(&[
            ("/ports/tcp/wildcard", json!([port(22, &["unknown"])])),
            (
                "/ports/udp/loopback",
                json!([port(53, &["dns", "unknown"])]),
            ),
        ]);
        assert!(unseen.2.contains(&"Which programs listen on TCP 22 / UDP 53 (DNS): this SSH login could not see them".to_owned()), "{unseen:?}");
        let partial = "Some listening ports: the list of sockets was read only in part, or had \
                       more ports than the check lists";
        assert!(
            ports(&[("/ports/udp/coverage", json!("partial"))])
                .2
                .contains(&partial.to_owned())
        );
        assert!(
            ports(&[("/ports/truncated", json!(true))])
                .2
                .contains(&partial.to_owned())
        );
        let unread = ports(&[
            ("/ports/tcp/coverage", json!("unknown")),
            ("/ports/tcp/loopback", json!([])),
        ]);
        assert!(
            unread
                .2
                .contains(&"Listening ports: the list of sockets could not be read".to_owned())
        );
        assert!(!unread.2.contains(&partial.to_owned()));
        let none = ports(&[("/ports/tcp/loopback", json!([]))]);
        assert!(none.1.contains(&"No listening ports".to_owned()));
        // The older report without ports: TCP 8899 alone, and the ports unread.
        for (listeners, look, fine) in [
            (
                "review_binding",
                Some("TCP 8899 listens on the server's network addresses, not only inside it"),
                None,
            ),
            (
                "loopback_binding",
                None,
                Some("TCP 8899 listens only inside the server"),
            ),
            ("no_listener", None, None),
            ("inconclusive", None, None),
        ] {
            let mut wire = with(clean(), &[("/listeners", json!(listeners))]);
            wire.as_object_mut().expect("object").remove("ports");
            let (l, f, o) = texts(&view(&wire, &[])).clone_owned();
            assert_eq!(l.first().map(String::as_str), look, "{listeners}");
            assert_eq!(
                f.iter().any(|t| Some(t.as_str()) == fine),
                fine.is_some(),
                "{listeners}"
            );
            assert!(o.contains(&"Listening ports: the check did not read them".to_owned()));
        }
    }

    trait Owned {
        fn clone_owned(&self) -> (Vec<String>, Vec<String>, Vec<String>);
    }

    impl Owned for (Vec<&str>, Vec<&str>, Vec<&str>) {
        fn clone_owned(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
            let own = |v: &Vec<&str>| v.iter().map(|t| (*t).to_owned()).collect();
            (own(&self.0), own(&self.1), own(&self.2))
        }
    }

    #[test]
    fn each_firewall_result_has_its_group_and_families() {
        let firewall = |ipv4: &str, ipv6: &str, truncated: bool| {
            let wire = with(
                clean(),
                &[(
                    "/firewall",
                    json!({"ipv4": ipv4, "ipv6": ipv6, "truncated": truncated}),
                )],
            );
            texts(&view(&wire, &[])).clone_owned()
        };
        let both = firewall("input_default_drop", "input_default_drop", false);
        assert_eq!(both.1[0], "Firewall drops incoming by default (IPv4/IPv6)");
        let split = firewall("input_default_drop", "no_input_filter_hook", false);
        assert_eq!(split.1[0], "Firewall drops incoming by default (IPv4)");
        assert_eq!(
            split.0,
            ["No nftables filter for incoming connections was found (IPv6)"]
        );
        assert_eq!(
            firewall("input_filter_hook", "input_filter_hook", false).0,
            ["The firewall (IPv4/IPv6) was not seen to drop anything coming in"]
        );
        assert_eq!(
            firewall(
                "configured_drop_or_reject_rule",
                "input_default_drop",
                false
            )
            .0,
            [
                "The firewall (IPv4) does not drop incoming connections by default: only its rules \
              drop some"
            ]
        );
        let unknown = firewall("unknown", "input_default_drop", false);
        assert!(unknown.0.is_empty());
        assert!(
            unknown.2[0].starts_with("The firewall (IPv4): its rules could not be read"),
            "{unknown:?}"
        );
        // A section that ran out of room judges nothing.
        let truncated = firewall("input_default_drop", "input_default_drop", true);
        assert!(!truncated.1.iter().any(|t| t.starts_with("Firewall")));
        assert!(
            truncated.2[0].starts_with("The firewall (IPv4/IPv6): its rules could not be read")
        );
        for (nftables, look) in [
            ("no_tables_observed", true),
            ("tables_present", false),
            ("not_observed", false),
        ] {
            let mut wire = with(clean(), &[("/nftables", json!(nftables))]);
            wire.as_object_mut().expect("object").remove("firewall");
            let (l, _, o) = texts(&view(&wire, &[])).clone_owned();
            assert_eq!(
                l.contains(&"No nftables firewall was found on the server".to_owned()),
                look
            );
            assert_eq!(
                o.contains(&"The firewall: the check did not read its rules".to_owned()),
                !look
            );
        }
    }

    #[test]
    fn ssh_passwords_need_a_look_only_when_its_settings_allow_them() {
        let ssh = |password: &str, keyboard: &str| {
            let wire = with(
                clean(),
                &[
                    ("/ssh/password", json!(password)),
                    ("/ssh/keyboard_interactive", json!(keyboard)),
                ],
            );
            texts(&view(&wire, &[])).clone_owned()
        };
        let password = "SSH's settings allow logging in with a password, which can be guessed";
        assert_eq!(ssh("enabled", "disabled").0, [password]);
        assert_eq!(
            ssh("enabled", "unknown"),
            (
                vec![password.to_owned()],
                ssh("enabled", "disabled").1,
                Vec::new()
            )
        );
        assert!(
            ssh("disabled", "enabled").0[0]
                .starts_with("SSH's settings allow keyboard-interactive login")
        );
        assert!(ssh("enabled", "enabled").0[0].starts_with(
            "SSH's settings allow logging in with a password or keyboard-interactive"
        ));
        for (password, keyboard) in [
            ("unknown", "disabled"),
            ("disabled", "unknown"),
            ("unknown", "unknown"),
        ] {
            let (look, _, open) = ssh(password, keyboard);
            assert!(look.is_empty());
            assert_eq!(
                open,
                [
                    "SSH password login: this SSH login could not read the SSH server's settings, or they did not say"
                ]
            );
        }
        let (look, fine, open) = ssh("disabled", "disabled");
        assert!(look.is_empty() && !fine.iter().any(|t| t.contains("SSH password")));
        assert!(open[0].contains("turn it off for this login"));
        let mut absent = clean();
        absent.as_object_mut().expect("object").remove("ssh");
        assert_eq!(
            texts(&view(&absent, &[])).2,
            ["SSH password login: the check did not read SSH's settings"]
        );
    }

    #[test]
    fn fail2ban_and_updates_fall_into_their_groups() {
        let of = |edits: &[(&str, Value)]| texts(&view(&with(clean(), edits), &[])).clone_owned();
        assert!(of(&[]).1.contains(&"fail2ban watches SSH".to_owned()));
        assert_eq!(
            of(&[("/fail2ban", json!("sshd_jail_not_listed"))]).0,
            ["fail2ban runs without its SSH jail, so it does not block repeated failed SSH logins"]
        );
        assert!(of(&[("/fail2ban", json!("unknown"))]).2.contains(
            &"fail2ban: it did not answer this SSH login, or is not installed".to_owned()
        ));
        assert_eq!(
            of(&[("/updates", json!({"status": "available", "packages": 3}))]).0,
            ["3 packages have security updates waiting"]
        );
        assert_eq!(
            of(&[("/updates", json!({"status": "available", "packages": 1}))]).0,
            ["1 package has a security update waiting"]
        );
        assert!(
            of(&[("/updates", json!({"status": "unknown", "packages": null}))])
                .2
                .contains(
                    &"Security updates: the server's package list could not be read".to_owned()
                )
        );
        let mut absent = clean();
        for section in ["fail2ban", "updates"] {
            absent.as_object_mut().expect("object").remove(section);
        }
        let open = texts(&view(&absent, &[])).clone_owned().2;
        assert!(open.contains(&"fail2ban: the check did not ask it".to_owned()));
        assert!(
            open.contains(&"Security updates: the check did not read the package list".to_owned())
        );
    }

    fn counts(owner: u16, broad: u16, unknown: u16) -> Value {
        json!({"owner_only": owner, "group_or_other_access": broad, "unknown": unknown})
    }

    fn file(source: &str, path: &str, kind: Option<&str>, mode: Option<u16>) -> Value {
        json!({"source": source, "unit": "erpc-worker-example.service", "path": path,
            "type": kind, "mode": mode})
    }

    fn services(env: Value, credentials: Value, files: Value) -> View {
        let wire = with(
            clean(),
            &[
                ("/metadata/environment_files", env),
                ("/metadata/credential_sources", credentials),
                ("/metadata/files", files),
            ],
        );
        view(&wire, &[])
    }

    #[test]
    fn a_service_file_others_can_open_names_its_unit_path_and_mode() {
        let env = |path: &str, kind: &str, mode: u16| {
            file("environment_file", path, Some(kind), Some(mode))
        };
        let readable = services(
            counts(0, 1, 0),
            counts(0, 0, 0),
            json!([env("/etc/example.env", "file", 0o644)]),
        );
        let item = &readable.look[0];
        assert_eq!(
            item.text,
            "The mode of a service's environment file lets other accounts on the server read it"
        );
        assert_eq!(
            item.lines,
            ["erpc-worker-example.service → /etc/example.env (0644)"]
        );
        assert_eq!(
            item.todo[0],
            Todo::Run("sudo chmod 600 /etc/example.env".into())
        );
        assert!(matches!(&item.todo[1], Todo::Words(words) if words.starts_with("Load secrets")));
        // Write or execute bits alone are access, not reading.
        let written = services(
            counts(0, 1, 0),
            counts(0, 0, 0),
            json!([env("/etc/example.env", "file", 0o620)]),
        );
        assert!(
            written.look[0]
                .text
                .contains("gives other accounts on the server access to it")
        );
        // No command for a directory, a path that is not plain or files not all listed.
        let words =
            Todo::Words("Make each one readable by its owner only (chmod 600 for a file)".into());
        for (broad, files) in [
            (1, json!([env("/etc/example.d", "directory", 0o755)])),
            (1, json!([env("/etc/my app.env", "file", 0o644)])),
            (1, json!([env("/etc/a$b.env", "file", 0o644)])),
            (2, json!([env("/etc/example.env", "file", 0o644)])),
        ] {
            let view = services(counts(0, broad, 0), counts(0, 0, 0), files.clone());
            assert_eq!(view.look[0].todo[0], words, "{files}");
        }
        assert!(
            services(
                counts(0, 2, 0),
                counts(0, 0, 0),
                json!([env("/etc/a.env", "file", 0o644)])
            )
            .look[0]
                .text
                .contains("The modes of 2 of the services' environment files give")
        );
        let credential = services(
            counts(0, 0, 0),
            counts(0, 1, 0),
            json!([file(
                "credential",
                "/etc/example/token",
                Some("file"),
                Some(0o640)
            )]),
        );
        assert_eq!(
            credential.look[0].text,
            "The mode of a service's credential file lets other accounts on the server read it"
        );
        assert_eq!(
            credential.look[0].todo,
            [Todo::Run("sudo chmod 600 /etc/example/token".into())]
        );
    }

    #[test]
    fn service_files_fall_into_their_groups() {
        let in_use = services(
            counts(1, 0, 0),
            counts(0, 0, 0),
            json!([file(
                "environment_file",
                "/etc/example.env",
                Some("file"),
                Some(0o600)
            )]),
        );
        assert_eq!(
            texts(&in_use).0,
            ["A service loads an environment file: keep secrets out of it"]
        );
        assert_eq!(
            in_use.look[0].lines,
            ["erpc-worker-example.service → /etc/example.env (0600)"]
        );
        let unknown = services(
            counts(0, 0, 2),
            counts(0, 0, 1),
            json!([
                file("environment_file", "/etc/a.env", Some("other"), None),
                file("environment_file", "/etc/b.env", None, None),
            ]),
        );
        assert_eq!(
            unknown.look[0].lines,
            [
                "erpc-worker-example.service → /etc/a.env (not a file or directory)",
                "erpc-worker-example.service → /etc/b.env (mode not read)"
            ]
        );
        let open = texts(&unknown).clone_owned().2;
        assert!(
            open.contains(
                &"Who can read 2 of the services' environment files: the check could not tell"
                    .to_owned()
            )
        );
        assert!(
            open.iter()
                .any(|t| t.starts_with("Who can read one of the services' credential sources"))
        );
        let owner = services(counts(0, 0, 0), counts(2, 0, 0), json!([]));
        assert!(
            texts(&owner)
                .1
                .contains(&"The services' credential files are readable by their owners only")
        );
        assert!(
            !texts(&owner)
                .1
                .iter()
                .any(|t| t.starts_with("The services the check reads"))
        );
        let more = with(
            clean(),
            &[
                ("/metadata/environment_files", counts(0, 1, 0)),
                ("/metadata/files_more", json!(3)),
            ],
        );
        assert_eq!(
            view(&more, &[]).look[0].lines,
            ["3 more of the services' files are not listed"]
        );
    }

    #[test]
    fn service_settings_not_read_are_listed_as_not_checked() {
        let of = |edits: &[(&str, Value)]| texts(&view(&with(clean(), edits), &[])).clone_owned();
        let partial = "Some services' settings: not all could be read with this SSH login, or there \
                       were more than the check reads";
        for edits in [
            vec![("/metadata/coverage", json!("partial"))],
            vec![("/metadata/truncated", json!(true))],
        ] {
            let (_, fine, open) = of(&edits);
            assert!(open.contains(&partial.to_owned()), "{edits:?}");
            assert!(
                !fine
                    .iter()
                    .any(|t| t.starts_with("The services the check reads"))
            );
        }
        let unread = of(&[
            ("/metadata/coverage", json!("unknown")),
            ("/metadata/units_with_evidence", json!(0)),
            (
                "/metadata/distinct_credential_sources",
                json!({"as_is": null, "encrypted": null}),
            ),
        ]);
        assert!(
            unread
                .2
                .iter()
                .any(|t| t.ends_with("no service's settings could be read with this SSH login"))
        );
        let mut absent = clean();
        absent.as_object_mut().expect("object").remove("metadata");
        assert!(
            texts(&view(&absent, &[]))
                .2
                .iter()
                .any(|t| t.ends_with("the check did not read them"))
        );
    }

    fn key_group(kind: &str, role: &str, access: &str, places: &[&str], more: u32) -> Value {
        let location = if kind == "history_secret" {
            "shell_history"
        } else {
            "home"
        };
        json!({"kind": kind, "role": role, "location": location, "access": access,
            "count": u32::try_from(places.len()).expect("few") + more, "places": places, "more": more})
    }

    #[test]
    fn keys_found_in_plain_text_name_their_places_and_what_to_do() {
        let keys = json!({"coverage": "partial", "groups": [
            key_group("solana_keypair", "validator_identity", "owner_only", &["/home/sol/id.json"], 0),
            key_group("solana_keypair", "unknown", "world", &["/home/a/%1B[2Jk.json"], 2),
            key_group("history_secret", "unknown", "owner_only", &["/root/.bash_history"], 0),
        ]});
        let found = view(&with(clean(), &[("/keys", keys)]), &[]);
        let (look, fine, open) = texts(&found).clone_owned();
        assert_eq!(
            look,
            [
                "A wallet private key is stored in plain text on this server",
                "A private key or secret was typed on the command line and is kept in a shell history file",
                "A private key or secret on this server can be read by every account",
            ]
        );
        assert_eq!(
            found.look[0].lines,
            [
                "/home/a/\\u{1b}[2Jk.json (readable by every account)",
                "and 2 more"
            ]
        );
        assert_eq!(
            found.look[1].lines,
            ["/root/.bash_history (readable by its owner only)"]
        );
        assert_eq!(
            found.look[2].lines,
            ["Each place above marked “readable by every account”"]
        );
        assert!(
            matches!(&found.look[0].todo[..], [Todo::Words(w)] if w.starts_with("Move the key off the server"))
        );
        assert!(
            fine.contains(
                &"The validator identity keypair is readable by its owner only".to_owned()
            )
        );
        assert!(!fine.iter().any(|t| t.starts_with("No plain-text")));
        assert!(
            open.iter()
                .any(|t| t.starts_with("Plain-text keys: some files"))
        );
        let search = |coverage: &str| {
            let wire = with(
                clean(),
                &[("/keys", json!({"coverage": coverage, "groups": []}))],
            );
            texts(&view(&wire, &[])).clone_owned()
        };
        assert!(
            search("complete")
                .1
                .contains(&"No plain-text keys or seed phrases".to_owned())
        );
        let partial = search("partial");
        assert!(
            partial
                .1
                .contains(&"No plain-text keys or seed phrases where readable".to_owned())
        );
        assert!(
            partial
                .2
                .iter()
                .any(|t| t.starts_with("Plain-text keys: some files"))
        );
        let unreadable = search("unreadable");
        assert!(!unreadable.1.iter().any(|t| t.starts_with("No plain-text")));
        assert!(
            unreadable
                .2
                .iter()
                .any(|t| t.starts_with("Plain-text keys: nothing could be read"))
        );
        let mut absent = clean();
        absent.as_object_mut().expect("object").remove("keys");
        assert!(
            texts(&view(&absent, &[]))
                .2
                .contains(&"Plain-text keys: the check did not search for them")
        );
    }

    const SAMPLE_EN: &[&str] = &[
        "ERPC Security Check — vps:100001 (frankfurt)",
        "",
        "  2 to look at · 5 fine · 4 could not be checked",
        "",
        "Needs a look",
        "  1. TCP 22 listens on all of the server's addresses, not only inside it",
        "     By default the firewall drops incoming connections it does not allow: check",
        "     that it lets in only what you expect",
        "     → sudo nft list ruleset",
        "  2. The mode of a service's environment file lets other accounts on the server",
        "     read it",
        "     erpc-worker-example.service → /etc/example.env (0644)",
        "     → sudo chmod 600 /etc/example.env",
        "     → Load secrets from a password manager or keychain when the app starts, not",
        "       from an environment file",
        "",
        "Fine",
        "  Firewall drops incoming by default (IPv4/IPv6) · fail2ban watches SSH",
        "  Inside the server only: TCP 53, 3000 / UDP 53",
        "  No security updates in the package list",
        "  No plain-text keys or seed phrases where readable",
        "",
        "Could not check",
        "  SSH password login: this SSH login could not read the SSH server's settings,",
        "    or they did not say",
        "    → sudo sshd -T | grep -Ei '^(password|kbdinteractive)authentication'",
        "  Which programs listen on TCP 22, 53, 3000 / UDP 53: this SSH login could not",
        "    see them",
        "    → sudo ss -tulpn",
        "  Some services' settings: not all could be read with this SSH login, or there",
        "    were more than the check reads",
        "    → Look at a service's settings with sudo systemctl cat and the service's",
        "      name",
        "  Plain-text keys: some files, directories or processes could not be read with",
        "    this SSH login, or the search reached its limit",
        "    → Run the check again with an SSH login that can read them",
        "",
        "Charged 2,408 ERPC AI tokens (limit 28,160)",
    ];

    const SAMPLE_JA: &[&str] = &[
        "ERPC Security Check — vps:100001 (frankfurt)",
        "",
        "  要確認 2 件 · 問題なし 5 件 · 確認できず 4 件",
        "",
        "要確認",
        "  1. TCP 22 がサーバー内だけでなく、すべてのアドレスで待ち受けています",
        "     ファイアウォールは許可していない着信を既定で遮断します。許可先が想定どおり",
        "     か確認してください",
        "     → sudo nft list ruleset",
        "  2. サービスの環境ファイル 1 件は、権限によりほかのアカウントも読めます",
        "     erpc-worker-example.service → /etc/example.env (0644)",
        "     → sudo chmod 600 /etc/example.env",
        "     → 秘密の情報は環境ファイルからではなく、アプリの起動時にパスワードマネー",
        "       ジャーやキーチェーンから読み込んでください",
        "",
        "問題なし",
        "  ファイアウォール（IPv4/IPv6）は着信を既定で遮断 · fail2ban が SSH を監視中",
        "  サーバー内のみ：TCP 53, 3000 / UDP 53",
        "  未適用のセキュリティ更新なし（パッケージ一覧）",
        "  平文の秘密鍵・シードフレーズなし（読めた範囲）",
        "",
        "確認できず",
        "  SSH のパスワードログイン：この SSH ログインでは SSH サーバーの設定を読み取れな",
        "    かったか、設定に記載がありませんでした",
        "    → sudo sshd -T | grep -Ei '^(password|kbdinteractive)authentication'",
        "  TCP 22, 53, 3000 / UDP 53 で待ち受けているプログラム：この SSH ログインからは",
        "    見えませんでした",
        "    → sudo ss -tulpn",
        "  一部のサービスの設定：この SSH ログインですべては読み取れなかったか、点検で読",
        "    む数を超えていました",
        "    → サービスの設定は sudo systemctl cat にサービス名を付けて確認してください",
        "  平文の鍵：この SSH ログインでは読めないファイル、ディレクトリ、プロセスがあっ",
        "    たか、検索が上限に達しました",
        "    → それらを読める SSH ログインで、点検をもう一度実行してください",
        "",
        "料金 2,408 ERPC AI トークン（上限 28,160）",
    ];

    /// The owner's sample, as a person reads it in English and Japanese,
    /// off a terminal: no marks, no colours.
    #[test]
    fn the_sample_reads_as_agreed_in_english_and_japanese() {
        let model = Ok(sample_findings());
        for (lang, expected) in [(Lang::En, SAMPLE_EN), (Lang::Ja, SAMPLE_JA)] {
            let text = shown(lang, &sample_wire(), &model, Look::PLAIN);
            assert_eq!(text.lines().collect::<Vec<_>>(), expected, "{text}");
        }
    }

    #[test]
    fn marks_and_colours_are_drawn_only_where_asked() {
        let model = Ok(sample_findings());
        let plain = shown(Lang::En, &sample_wire(), &model, Look::PLAIN);
        let marked = shown(
            Lang::En,
            &sample_wire(),
            &model,
            Look {
                marks: true,
                color: false,
                ..Look::PLAIN
            },
        );
        let coloured = shown(
            Lang::En,
            &sample_wire(),
            &model,
            Look {
                marks: true,
                color: true,
                ..Look::PLAIN
            },
        );
        for text in [&plain, &marked] {
            assert!(!text.contains('\u{1b}'), "{text}");
        }
        assert!(coloured.contains("\u{1b}[33m"), "{coloured:?}");
        assert!(coloured.contains("\u{1b}[1m"), "{coloured:?}");
        assert_eq!(console::strip_ansi_codes(&coloured), marked);
        for (mark, heading) in [
            ("⚠", "Needs a look"),
            ("✓", "Fine"),
            ("?", "Could not check"),
        ] {
            assert!(
                marked
                    .lines()
                    .any(|line| line == format!("{mark} {heading}")),
                "{marked}"
            );
            assert!(plain.lines().any(|line| line == heading), "{plain}");
        }
        let unmarked = marked
            .replace("⚠ Needs a look", "Needs a look")
            .replace("✓ Fine", "Fine")
            .replace("? Could not check", "Could not check");
        assert_eq!(unmarked, plain);
        // Off a terminal (or with TERM=dumb, which the same test of standard
        // output decides) nothing is drawn.
        crate::cli::ui::force_drawn(false);
        assert_eq!(Look::here(), Look::PLAIN);
        crate::cli::ui::force_drawn(true);
        assert!(Look::here().marks);
    }

    #[test]
    fn the_charge_is_one_line_and_a_report_without_one_says_why() {
        let last = |lang, model: &Result<Receipt, ReportFailure>| {
            let text = shown(lang, &clean(), model, Look::PLAIN);
            text.rsplit("\n\n").next().expect("footer").to_owned()
        };
        let charged = Ok(sample_findings());
        assert_eq!(
            last(Lang::En, &charged),
            "Charged 2,408 ERPC AI tokens (limit 28,160)"
        );
        assert_eq!(
            last(Lang::Ru, &charged),
            "Списано 2\u{a0}408 токенов ERPC AI (лимит 28\u{a0}160)"
        );
        let one: Receipt = serde_json::from_value(json!({"status": "completed", "model": "m",
            "findings": [], "billing": {"meterVersion": "posture1", "chargedCredits": 1,
                "baseCredits": 512, "inputTokens": 1, "outputTokens": 1}}))
        .expect("receipt");
        assert_eq!(
            last(Lang::En, &Ok(one)),
            "Charged 1 ERPC AI token (limit 28,160)"
        );
        assert_eq!(
            last(Lang::En, &Err(no_charge())),
            "Showing the local report. No AI tokens were charged.\n\
             HTTP 409 (posture_report_no_actionable_candidates)"
        );
        let unconfirmed =
            ReportFailure::from_response(503, r#"{"error":"posture_report_unavailable"}"#);
        assert_eq!(
            last(Lang::En, &Err(unconfirmed)),
            "Settlement could not be verified for request fixture-request. Check usage before\n\
             submitting a new report.\nHTTP 503 (posture_report_unavailable)"
        );
    }

    fn kg(kind: &str, role: &str, location: &str, access: &str, places: &[&str]) -> Value {
        json!({"kind": kind, "role": role, "location": location, "access": access,
            "count": places.len() + 1, "places": places, "more": 1})
    }

    /// A server with something of every kind to look at.
    fn busy() -> Value {
        let files = json!([
            file(
                "environment_file",
                "/etc/a.d",
                Some("directory"),
                Some(0o755)
            ),
            file(
                "environment_file",
                "/etc/b c.env",
                Some("file"),
                Some(0o644)
            ),
            file("environment_file", "/etc/c.env", Some("other"), None),
            file("credential", "/etc/token", Some("file"), Some(0o640)),
        ]);
        let keys = json!({"coverage": "partial", "groups": [
            kg("solana_keypair", "validator_identity", "home", "owner_only", &["/home/sol/id.json"]),
            kg("solana_keypair", "validator_identity", "home", "group", &["/home/sol/v.json"]),
            kg("solana_keypair", "unknown", "tmp", "world", &["/tmp/k.json"]),
            kg("evm_private_key", "unknown", "opt", "owner_only", &["/opt/key"]),
            kg("mnemonic", "unknown", "opt", "owner_only", &["/opt/seed.txt"]),
            kg("unencrypted_keystore", "unknown", "srv", "owner_only", &["/srv/ks.json"]),
            kg("env_secret", "unknown", "etc", "group", &["/etc/app.env"]),
            kg("process_env_secret", "unknown", "process_env", "owner_only", &["/proc/7/environ"]),
            kg("history_secret", "unknown", "shell_history", "owner_only", &["/root/.bash_history"]),
        ]});
        with(
            clean(),
            &[
                (
                    "/ports/tcp/wildcard",
                    json!([port(22, &["ssh"]), port(6379, &["redis"])]),
                ),
                (
                    "/ports/tcp/interface",
                    json!([port(9000, &["unclassified"])]),
                ),
                ("/ports/tcp/loopback", json!([port(53, &["unknown"])])),
                ("/ports/udp/coverage", json!("partial")),
                ("/firewall/ipv4", json!("no_input_filter_hook")),
                ("/firewall/ipv6", json!("configured_drop_or_reject_rule")),
                ("/ssh/password", json!("enabled")),
                ("/ssh/keyboard_interactive", json!("enabled")),
                ("/fail2ban", json!("sshd_jail_not_listed")),
                ("/metadata/coverage", json!("partial")),
                ("/metadata/environment_files", counts(0, 2, 1)),
                ("/metadata/credential_sources", counts(0, 1, 1)),
                ("/metadata/files", files),
                ("/metadata/files_more", json!(2)),
                ("/updates", json!({"status": "available", "packages": 4})),
                ("/keys", keys),
            ],
        )
    }

    /// Every result there is, across a few servers: what the sweep of the
    /// languages renders.
    fn variants() -> Vec<Value> {
        let unread = with(
            clean(),
            &[
                ("/ports/tcp/coverage", json!("unknown")),
                ("/ports/tcp/loopback", json!([])),
                (
                    "/firewall",
                    json!({"ipv4": "input_filter_hook", "ipv6": "unknown", "truncated": false}),
                ),
                ("/ssh/password", json!("unknown")),
                ("/fail2ban", json!("unknown")),
                (
                    "/metadata",
                    json!({"coverage": "unknown", "units_with_evidence": 0, "truncated": false,
                "environment_files": counts(0, 0, 0), "service_env": counts(0, 0, 0),
                "credential_sources": counts(0, 0, 0)}),
                ),
                ("/updates", json!({"status": "unknown", "packages": null})),
                ("/keys", json!({"coverage": "unreadable", "groups": []})),
            ],
        );
        let mut absent = with(
            clean(),
            &[
                ("/listeners", json!("review_binding")),
                ("/nftables", json!("no_tables_observed")),
            ],
        );
        let mut loopback = with(
            clean(),
            &[
                ("/listeners", json!("loopback_binding")),
                ("/metadata/environment_files", counts(1, 0, 0)),
                ("/metadata/credential_sources", counts(1, 0, 0)),
                ("/ports/tcp/interface", json!([port(8080, &["web"])])),
                ("/ports/tcp/loopback", json!([])),
            ],
        );
        for (wire, sections) in [
            (
                &mut absent,
                &[
                    "ports", "firewall", "ssh", "fail2ban", "metadata", "updates", "keys",
                ][..],
            ),
            (&mut loopback, &["ports", "firewall"][..]),
        ] {
            for section in sections {
                wire.as_object_mut().expect("object").remove(*section);
            }
        }
        vec![sample_wire(), clean(), busy(), unread, absent, loopback]
    }

    /// Every result in every language: its words found, every placeholder
    /// filled, and the counts those of the lists drawn.
    #[test]
    fn every_language_says_every_result_and_counts_what_it_lists() {
        let every_finding = [
            "review_listener_bindings",
            "review_ssh_authentication",
            "review_input_filter",
            "review_ssh_jail",
            "review_file_permissions",
            "review_available_updates",
            "verify_unobserved_posture",
            "review_env_file_use",
            "review_redis_binding",
            "identify_unclassified_listener",
        ];
        let models = [Ok(receipt(&every_finding)), Err(no_charge())];
        for wire in variants() {
            for model in &models {
                let ranked = model.as_ref().map_or(Vec::new(), |r| r.findings().to_vec());
                let view = View::of(&posture(&wire), &ranked);
                for lang in [Lang::En, Lang::Ja, Lang::Zh, Lang::Ru] {
                    let text = shown(lang, &wire, model, Look::PLAIN);
                    for unfilled in ['{', '}'] {
                        assert!(!text.contains(unfilled), "{lang:?}: {text}");
                    }
                    assert!(!text.contains("node_check."), "{lang:?}: {text}");
                    let numbered = text.lines().filter(|l| {
                        l.strip_prefix("  ")
                            .and_then(|l| l.split_once(". "))
                            .is_some_and(|(n, _)| n.parse::<usize>().is_ok())
                    });
                    assert_eq!(numbered.count(), view.look.len(), "{text}");
                    let open = text.split("\n\n").find(|block| {
                        block.lines().count() > 1
                            && block.lines().skip(1).all(|l| l.starts_with("  "))
                            && block.contains("\n    →")
                    });
                    assert_eq!(
                        open.map_or(0, |b| b.matches("\n    →").count()),
                        view.open.len(),
                        "{text}"
                    );
                    let counts = text.lines().nth(2).expect("counts");
                    let numbers: Vec<usize> = counts
                        .split(|c: char| !c.is_ascii_digit())
                        .filter_map(|n| n.parse().ok())
                        .collect();
                    assert_eq!(
                        numbers,
                        [view.look.len(), view.fine.len(), view.open.len()],
                        "{counts}"
                    );
                }
            }
        }
    }

    /// `--details` prints the evidence after the report, under its heading,
    /// and changes nothing above it.
    #[test]
    fn the_details_follow_the_report_unchanged() {
        let model = Ok(sample_findings());
        let report = shown(Lang::En, &sample_wire(), &model, Look::PLAIN);
        let detailed = crate::cli::i18n::speaking(Lang::En, || {
            render(
                &sample_server(),
                &posture(&sample_wire()),
                &model,
                "fixture-request",
                Look::PLAIN,
                Some("evidence\\nlines"),
            )
        });
        assert_eq!(detailed, format!("{report}\n\nDetails\nevidence\\nlines"));
    }

    /// Words wrap to the width with their indent, at spaces or between
    /// wide characters, never inside a word or before a small kana or a
    /// closing mark; a command or a path is never wrapped.
    #[test]
    fn words_wrap_to_the_width_and_commands_and_paths_never_do() {
        use super::{Item, hanging};

        let lines = hanging("one two three four five", "  ", "    ", 14);
        assert_eq!(lines, ["  one two", "    three four", "    five"]);
        assert!(lines.iter().all(|line| super::columns(line) <= 14));
        // A word longer than a line stays whole.
        assert_eq!(
            hanging("abcdefghijklmnop q", "", "", 8),
            ["abcdefghijklmnop", "q"]
        );
        assert_eq!(
            hanging("あいうえおかきくけこ", "", "", 10),
            ["あいうえお", "かきくけこ"]
        );
        // Not before a small kana, a prolonged sound mark or a comma.
        assert_eq!(
            hanging("ああああジャー", "", "", 10),
            ["ああああ", "ジャー"]
        );
        assert_eq!(hanging("ああああ、いい", "", "", 8), ["あああ", "あ、いい"]);
        // ASCII inside Japanese stays whole.
        assert_eq!(
            hanging("ああ sudo ls い", "", "", 9),
            ["ああ sudo", "ls い"]
        );
        let look = Look {
            width: 30,
            ..Look::PLAIN
        };
        let item = Item {
            topic: Topic::EnvFiles,
            text: "a sentence long enough to need a second line".into(),
            lines: vec![
                super::Line::Exact("unit.service → /a/path/longer/than/the/width (0644)".into()),
                "words that also wrap under the item".to_owned().into(),
            ],
            todo: vec![
                Todo::Run("sudo chmod 600 /a/path/longer/than/the/width".into()),
                Todo::Words("words to do that wrap after the arrow".into()),
            ],
        };
        let mut out = Vec::new();
        look.item(&mut out, 1, &item);
        assert_eq!(
            out,
            [
                "  1. a sentence long enough to",
                "     need a second line",
                "     unit.service → /a/path/longer/than/the/width (0644)",
                "     words that also wrap",
                "     under the item",
                "     → sudo chmod 600 /a/path/longer/than/the/width",
                "     → words to do that wrap",
                "       after the arrow",
            ]
        );
    }

    /// The fixed order, whole: what needs a look when nothing is ranked.
    #[test]
    fn what_was_not_ranked_follows_the_documented_order() {
        let busy = view(&busy(), &[]);
        let mut order = topics(&busy);
        order.dedup();
        assert_eq!(
            order,
            [
                Topic::Keys,
                Topic::EnvFiles,
                Topic::Credentials,
                Topic::Redis,
                Topic::Listeners,
                Topic::SshAuth,
                Topic::Firewall,
                Topic::Jail,
                Topic::Updates,
                Topic::Unclassified,
            ]
        );
    }

    /// No line of the report is wider than its width, in any language, but
    /// a command or a path, which pastes whole.
    #[test]
    fn only_commands_and_paths_go_past_the_width() {
        let models = [Ok(sample_findings()), Err(no_charge())];
        for (wire, lang) in variants().into_iter().flat_map(|wire| {
            [Lang::En, Lang::Ja, Lang::Zh, Lang::Ru].map(|lang| (wire.clone(), lang))
        }) {
            let view = crate::cli::i18n::speaking(lang, || View::of(&posture(&wire), &[]));
            let mut whole: Vec<String> = view
                .look
                .iter()
                .flat_map(|item| {
                    item.lines
                        .iter()
                        .filter(|line| matches!(line, super::Line::Exact(_)))
                        .map(|line| line.to_string())
                        .chain(item.todo.iter().filter_map(|todo| match todo {
                            Todo::Run(command) => Some(command.clone()),
                            Todo::Words(_) => None,
                        }))
                })
                .collect();
            whole.extend(view.open.iter().filter_map(|open| match &open.todo {
                Todo::Run(command) => Some(command.clone()),
                Todo::Words(_) => None,
            }));
            for model in &models {
                for line in shown(lang, &wire, model, Look::PLAIN).lines() {
                    if super::columns(line) > Look::PLAIN.width {
                        let bare = line.trim_start().trim_start_matches("→ ");
                        assert!(whole.iter().any(|w| w == bare), "{lang:?}: {line}");
                    }
                }
            }
        }
    }
}
