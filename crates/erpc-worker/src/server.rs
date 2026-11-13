// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What `erpc worker` and `erpc-worker-agent` agree on about a server: where
//! a worker's files are, its systemd unit, the launch file each release
//! carries, and what the agent's socket speaks.
//!
//! A worker is `<app>-<env>` ([`is_unit_id`]). On its server:
//!
//! ```text
//! /opt/erpc/workers/<id>/              root, 0755
//!   releases/<release-id>/             one per deploy (release::is_id)
//!     <bin>  release.json  launch.json  <run.files…>
//!   current  -> releases/<release-id>  what runs
//!   previous -> releases/<release-id>  what `rollback` goes back to
//!   .lock                              held by every change
//! /run/erpc-worker-<id>/agent.sock     the agent's socket, root only
//! /var/lib/erpc-worker-<id>/           the agent's state, and the app's
//! /etc/erpc/worker-waf/<id>.json       the WAF's config, when it has one
//! /etc/erpc/worker-waf/<id>.applying   while a deploy changes the WAF's files
//! /run/erpc-waf-<id>/stats.json      what the WAF has done
//! ```
//!
//! Two programs share the work, so that the one holding the key cannot
//! change what it runs:
//!
//! - `erpc-worker-agent supervise`, the unit's process, an unprivileged
//!   dynamic user. It holds the trading key and the secrets in memory,
//!   starts the app from `current` with the key on its standard input,
//!   restarts it when it ends, and probes its health. A reboot or a restart
//!   of the agent loses the key: the worker is *locked* until erpc unlocks
//!   it again.
//! - `erpc-worker-agent ctl`, run by erpc as root over SSH. It checks a
//!   release against its digests, moves `current` and `previous`, waits for
//!   the agent to report the new release healthy, and moves them back when
//!   it does not. It forwards everything else to the agent.
//!
//! A worker whose app is reached from outside has a third, in a unit of
//! its own ([`waf_unit`]): `erpc-worker-agent waf`, the HTTP proxy that
//! faces the network ([`crate::waf`]). It shares nothing with the two
//! above.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::manifest::is_slug;

/// Where every worker's files are.
pub const BASE: &str = "/opt/erpc/workers";
/// Where the agent binary is installed.
pub const AGENT_PATH: &str = "/usr/local/lib/erpc/erpc-worker-agent";
/// The launch file's name in a release.
pub const LAUNCH_FILE: &str = "launch.json";
/// The launch file's format.
pub const LAUNCH_FORMAT: u32 = 1;

/// Whether `id` names a worker: `<app>-<env>`, an app name and an
/// environment name joined, safe in a unit name and a path.
#[must_use]
pub fn is_unit_id(id: &str) -> bool {
    is_slug(id, 49)
}

/// Where needrestart reads the configuration erpc gives it.
pub const NEEDRESTART_CONF: &str = "/etc/needrestart/conf.d/50-erpc-worker.conf";

/// What [`NEEDRESTART_CONF`] holds. Debian's and Ubuntu's needrestart
/// restarts services after a package run (a deploy that installs a local
/// service, an unattended security update) when the file a process runs
/// from was replaced or a library it loaded was upgraded. A worker's agent
/// holds the trading key and the secrets in memory only, so a restarted
/// agent comes back locked, and its app stays down until the key is handed
/// over again.
///
/// This tells needrestart not to restart a worker unit: in its automatic
/// mode it defers every unit the pattern matches, and where it asks at a
/// terminal its answer for them defaults to no. It is about needrestart
/// alone: systemd still restarts an agent that failed or was killed
/// ([`unit`]), and that one comes back locked too.
#[must_use]
pub fn needrestart_conf() -> String {
    [
        "# Written by erpc worker. Its units hold a key in memory that a restart\n",
        "# forgets, so needrestart is told not to restart them after a package\n",
        "# run.\n",
        "$nrconf{override_rc}{qr(^erpc-worker-)} = 0;\n",
    ]
    .concat()
}

/// The worker's systemd unit name.
#[must_use]
pub fn unit_name(id: &str) -> String {
    format!("erpc-worker-{id}.service")
}

/// The worker's directory.
#[must_use]
pub fn worker_dir(id: &str) -> PathBuf {
    PathBuf::from(BASE).join(id)
}

/// The agent's socket.
#[must_use]
pub fn socket_path(id: &str) -> PathBuf {
    PathBuf::from(format!("/run/erpc-worker-{id}/agent.sock"))
}

/// The agent's state directory.
#[must_use]
pub fn state_dir(id: &str) -> PathBuf {
    PathBuf::from(format!("/var/lib/erpc-worker-{id}"))
}

/// The file in a worker's state directory (`state_dir`) where its agent
/// records whether it is asked to keep the app running: `1` or `0`, and a
/// newline. The agent writes it and reads it back when it starts; root's
/// `ctl` reads a neighbour's to know whether that worker holds its port.
/// Both name it through here, so that the two cannot come to name two
/// files.
#[must_use]
pub fn wanted_file(state_dir: &Path) -> PathBuf {
    state_dir.join("wanted")
}

/// The worker's systemd unit.
///
/// The agent runs as a dynamic user with the system read-only. It may not
/// gain privileges, dump core, swap, or write anywhere but its state
/// directory. `Restart=on-failure` brings back the agent, and only the
/// agent: the app is the agent's to restart, because only the agent has
/// the key. The agent comes back locked, as after a reboot.
/// `KillMode=control-group` takes the app down with the agent, so no app
/// outlives the process that was supervising it.
///
/// # Panics
///
/// Never for an id [`is_unit_id`] accepts; the caller checks it.
#[must_use]
pub fn unit(id: &str) -> String {
    assert!(is_unit_id(id), "not a worker id: {id:?}");
    format!(
        "\
# Written by erpc worker deploy. Changes here are replaced on the next deploy.
[Unit]
Description=erpc worker {id}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={AGENT_PATH} supervise --id {id}
DynamicUser=yes
RuntimeDirectory=erpc-worker-{id}
RuntimeDirectoryMode=0700
StateDirectory=erpc-worker-{id}
StateDirectoryMode=0700
WorkingDirectory=/var/lib/erpc-worker-{id}
Restart=on-failure
RestartSec=5
KillMode=control-group
TimeoutStopSec=30
UMask=0077
LimitCORE=0
LimitMEMLOCK=64M
MemorySwapMax=0
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=yes
SystemCallArchitectures=native
ReadOnlyPaths={BASE}/{id}

[Install]
WantedBy=multi-user.target
"
    )
}

/// Where each worker's WAF config is kept: `<id>.json`, a
/// [`crate::waf::WafConfig`]. Root's to write and anyone's to read, since
/// the proxy that reads it runs as a user of its own and it holds no
/// secret. Beside it, `<id>.applying` for as long as the agent's
/// `waf-apply` is changing the config or the unit and has not restarted
/// the proxy from them.
pub const WAF_DIR: &str = "/etc/erpc/worker-waf";

/// The systemd unit name of a worker's WAF. Not `erpc-worker-…`, as the
/// backup's is not: a worker called `waf-<x>` has `erpc-worker-waf-<x>` as
/// its own unit and runtime directory.
#[must_use]
pub fn waf_unit_name(id: &str) -> String {
    format!("erpc-waf-{id}.service")
}

/// A worker's WAF config.
#[must_use]
pub fn waf_config_path(id: &str) -> String {
    // A server's path, written whole: see `backup_env_path`.
    format!("{WAF_DIR}/{id}.json")
}

/// Where a worker's WAF writes its [`crate::waf::WafStats`]: in its own
/// runtime directory, which is gone when it stops.
#[must_use]
pub fn waf_stats_path(id: &str) -> String {
    format!("/run/erpc-waf-{id}/stats.json")
}

/// The systemd unit of a worker's WAF: `erpc-worker-agent waf`, the HTTP
/// proxy in front of the app.
///
/// It is a unit, a process and a dynamic user of its own, so the program
/// that faces the network shares nothing with the one that holds the key:
/// not an address space, not a user, not a directory. It is as confined as
/// the worker's unit and has less: no capability (so it listens on port
/// 1024 or above), no state directory, and the system read-only but for
/// its runtime directory, which holds the stats file and is readable by
/// every user, the file being counts. It starts after the worker's unit
/// and asks for it, but does not stop with it: with the app down the proxy
/// answers 502. `Restart=on-failure` brings it back if it ends badly; what
/// it held in memory (the banned addresses, the counts) starts again from
/// nothing. A config it refuses (exit 2) is not tried again: the next
/// deploy writes another. The descriptor limit is twice the connections
/// it holds at once and to spare: each has a client's socket and the
/// app's.
///
/// Two limits are its own, since it is the one unit that faces the
/// network:
///
/// - `MemoryMax=1G`. At the largest config a connection holds at most
///   some 400 KiB: a head read ahead (`max_header_bytes`, 64 KiB), what
///   hyper has read and has queued to write towards the client (72 KiB
///   each, and one piece of the app's answer more, 64 KiB) and towards
///   the app (64 KiB each), and the piece of a body in hand. 1024
///   connections are 400 MiB of that. The addresses it remembers add at
///   most 66 MiB (8192 of them, each with the times it was blocked, at
///   most `ban.after`, 1000), and the log queue 1 MiB. That is under 470
///   MiB, so the limit is more than twice it; past the limit the kernel
///   ends the proxy and systemd starts it anew, instead of the proxy
///   taking the memory the app and the agent run in.
/// - `SystemCallFilter=@system-service`: the system calls a service
///   makes, and no others (none that load a kernel module, change the
///   clock, mount, reboot or trace another process). The proxy reads a
///   file, listens, connects to loopback and writes a file.
///
/// needrestart is told nothing about it ([`needrestart_conf`] names the
/// worker's units only, and this one's name is not one of them): what a
/// restart after a package run costs here is the bans and the counts, not
/// a key, and the proxy serves again by itself once it is back.
///
/// # Panics
///
/// Never for an id [`is_unit_id`] accepts; the caller checks it.
#[must_use]
pub fn waf_unit(id: &str) -> String {
    assert!(is_unit_id(id), "not a worker id: {id:?}");
    format!(
        "\
# Written by erpc worker deploy. Changes here are replaced on the next deploy.
[Unit]
Description=erpc worker {id}, WAF
After=network-online.target erpc-worker-{id}.service
Wants=network-online.target erpc-worker-{id}.service

[Service]
Type=simple
ExecStart={AGENT_PATH} waf --config {WAF_DIR}/{id}.json
DynamicUser=yes
RuntimeDirectory=erpc-waf-{id}
RuntimeDirectoryMode=0755
Restart=on-failure
RestartSec=2
RestartPreventExitStatus=2
KillMode=control-group
TimeoutStopSec=20
UMask=0022
LimitCORE=0
LimitNOFILE=4096
MemoryMax=1G
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
"
    )
}

/// Where the pinned restic is installed on a server, root's.
pub const RESTIC_PATH: &str = "/usr/local/lib/erpc/restic";
/// The repository a worker backs up to: ERPC Global Storage's restic
/// backend, in the account's default region.
pub const BACKUP_REPOSITORY: &str = "rest:https://user-api.erpc.global/v3/storage/restic";
/// Where each worker's backup credentials are kept, root only.
pub const BACKUP_DIR: &str = "/etc/erpc/backup";
/// The variables a worker's backup credentials hold, and nothing else.
pub const BACKUP_KEYS: [&str; 5] = [
    "RESTIC_REPOSITORY",
    "RESTIC_REST_USERNAME",
    "RESTIC_REST_PASSWORD",
    "RESTIC_PASSWORD",
    "RESTIC_HOST",
];

/// The backup's service.
#[must_use]
pub fn backup_service_name(id: &str) -> String {
    format!("erpc-backup-{id}.service")
}

/// The backup's timer.
#[must_use]
pub fn backup_timer_name(id: &str) -> String {
    format!("erpc-backup-{id}.timer")
}

/// The worker's backup credentials.
#[must_use]
pub fn backup_env_path(id: &str) -> PathBuf {
    // A server's path, written whole: `join` would put a backslash in it
    // where erpc runs on Windows.
    PathBuf::from(format!("{BACKUP_DIR}/{id}.env"))
}

/// The name a worker's snapshots and restic key carry: its id, and `tag`,
/// eight hex digits that tell its server apart, since two apps or two
/// servers can have workers of the same id in one account.
#[must_use]
pub fn backup_host(id: &str, tag: &str) -> String {
    format!("erpc-worker-{id}-{tag}")
}

/// Whether `name` is a [`backup_host`] of worker `id`.
#[must_use]
pub fn is_backup_host(id: &str, name: &str) -> bool {
    name.strip_prefix("erpc-worker-")
        .and_then(|rest| rest.strip_prefix(id))
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|tag| {
            tag.len() == 8 && tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// What a worker's backup holds: its state, where systemd keeps it for a
/// dynamic user. `/var/lib/erpc-worker-<id>` is a link to it, and restic
/// given the link would keep the link alone.
#[must_use]
pub fn backup_source(id: &str) -> PathBuf {
    PathBuf::from(format!("/var/lib/private/erpc-worker-{id}"))
}

/// `HH:MM`, 24-hour, as hour and minute.
#[must_use]
pub fn time_of_day(text: &str) -> Option<(u8, u8)> {
    let (h, m) = text.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let h: u8 = h.parse().ok()?;
    let m: u8 = m.parse().ok()?;
    (h < 24 && m < 60).then_some((h, m))
}

/// Whether `text` is worker `id`'s backup credentials as erpc writes
/// them: each of [`BACKUP_KEYS`] once, as `KEY=value`, the repository
/// [`BACKUP_REPOSITORY`], the host a [`backup_host`] of `id`, and every
/// value plain enough that systemd reads it back unchanged. Nothing else:
/// the file becomes the environment of a program run as root.
#[must_use]
pub fn backup_env_ok(id: &str, text: &str) -> bool {
    // `lines` would take a CR off; the file keeps it, and systemd with it.
    if text.contains('\r') {
        return false;
    }
    let mut seen = [false; BACKUP_KEYS.len()];
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let Some(i) = BACKUP_KEYS.iter().position(|k| *k == key) else {
            return false;
        };
        let plain = !value.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.:/".contains(&b));
        if seen[i]
            || !plain
            || (i == 0 && value != BACKUP_REPOSITORY)
            || (i == 4 && !is_backup_host(id, value))
        {
            return false;
        }
        seen[i] = true;
    }
    seen.iter().all(|s| *s)
}

/// The backup's service: restic, run as root with the credentials file,
/// backing up the worker's state at the lowest CPU and I/O priority. Root
/// for one reason, to read the dynamic user's state; it may write only
/// its cache. Exit 3 is restic's "some files could not be read".
///
/// # Panics
///
/// Never for an id [`is_unit_id`] accepts; the caller checks it.
#[must_use]
pub fn backup_service(id: &str) -> String {
    assert!(is_unit_id(id), "not a worker id: {id:?}");
    let source = backup_source(id);
    let env = backup_env_path(id);
    let source = source.display();
    let env = env.display();
    format!(
        "\
# Written by erpc worker backup. `erpc worker backup off` removes it.
[Unit]
Description=erpc backup of worker {id}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile={env}
Environment=RESTIC_CACHE_DIR=/var/cache/erpc-backup-{id}
CacheDirectory=erpc-backup-{id}
CacheDirectoryMode=0700
ExecStart={RESTIC_PATH} backup --host ${{RESTIC_HOST}} --tag erpc-worker --tag {id} {source}
SuccessExitStatus=3
Nice=19
CPUSchedulingPolicy=batch
IOSchedulingClass=idle
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
SystemCallArchitectures=native
"
    )
}

/// The backup's timer: every day at `at`, within half an hour after, and a
/// run missed while the server was off as soon as it is back.
///
/// # Panics
///
/// Never for an id [`is_unit_id`] accepts and an hour and minute
/// [`time_of_day`] gives; the caller checks them.
#[must_use]
pub fn backup_timer(id: &str, (hour, minute): (u8, u8)) -> String {
    assert!(is_unit_id(id), "not a worker id: {id:?}");
    assert!(hour < 24 && minute < 60, "not a time of day");
    format!(
        "\
# Written by erpc worker backup. `erpc worker backup off` removes it.
[Unit]
Description=erpc backup of worker {id}, daily

[Timer]
OnCalendar=*-*-* {hour:02}:{minute:02}:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
"
    )
}

/// Where the worker firewall's files are on a server.
pub const FIREWALL_DIR: &str = "/etc/erpc/worker-firewall";
/// How long an applied firewall waits for erpc to get in again before it
/// is taken back.
pub const FIREWALL_ROLLBACK_SECONDS: u32 = 120;

/// The most new connections a second [`NewConnections::per_second`] allows.
pub const MAX_NEW_CONNECTIONS_PER_SECOND: u32 = 10_000;
/// The largest [`NewConnections::burst`].
pub const MAX_NEW_CONNECTIONS_BURST: u32 = 100_000;

/// A limit on the new TCP connections one client address may open to an
/// opening, kept by the firewall itself: a connection over it is dropped
/// before any program on the server sees it. An address is an IPv4
/// address, or an IPv6 `/64`. The firewall counts an address for a minute
/// from the new connection that put it in its set, and afresh after that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewConnections {
    /// New connections a second, sustained: 1 to
    /// [`MAX_NEW_CONNECTIONS_PER_SECOND`].
    pub per_second: u32,
    /// New connections at once before the rate applies: 1 to
    /// [`MAX_NEW_CONNECTIONS_BURST`].
    pub burst: u32,
}

impl NewConnections {
    /// The limit a WAF's opening has when `erpc.toml` says no other.
    pub const DEFAULT: Self = Self {
        per_second: 50,
        burst: 100,
    };

    /// What is wrong with its numbers, each named by its field; nothing
    /// when both are within their bounds. Checked by `erpc.toml`'s reader
    /// and again by the agent before either number reaches a table.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        [
            (
                "per_second",
                self.per_second,
                MAX_NEW_CONNECTIONS_PER_SECOND,
            ),
            ("burst", self.burst, MAX_NEW_CONNECTIONS_BURST),
        ]
        .into_iter()
        .filter(|(_, value, most)| !(1..=*most).contains(value))
        .map(|(field, value, most)| format!("{field} is {value}; it is 1 to {most}"))
        .collect()
    }
}

/// One worker's opening in its server's firewall: its port, to the
/// addresses and networks its `firewall.app_allow` lists. Kept on the
/// server per worker, as `FIREWALL_DIR/workers/<id>.json`, so the workers
/// on one server share one table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    /// The port opened: the app's, or its WAF's when it has one.
    pub port: u16,
    /// Who may reach it. `0.0.0.0/0` or `::/0` is everyone of that family.
    pub allow: Vec<crate::net::Cidr>,
    /// How many new connections one address may open to it; absent for no
    /// limit, which is also how an opening without one is written, so that
    /// it reads as it did before there was a limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<NewConnections>,
}

impl Opening {
    /// `m`'s opening in `env`: the WAF's port when the app has a WAF, with
    /// the limit `[waf]` gives new connections, else the app's own port.
    /// To the addresses `firewall.app_allow` lists; none when it lists
    /// nobody, or the app has no port.
    #[must_use]
    pub fn for_app(m: &crate::manifest::Manifest, env: &crate::manifest::Env) -> Option<Self> {
        if env.firewall.app_allow.is_empty() {
            return None;
        }
        let (port, limit) = match &m.waf {
            Some(waf) => (waf.port, waf.new_connections()),
            None => (m.run.port?, None),
        };
        Some(Self {
            port,
            allow: env.firewall.app_allow.clone(),
            limit,
        })
    }
}

/// What `erpc-worker-agent ctl firewall-apply` is handed on stdin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRequest {
    /// The SSH port, which stays open (who may reach it is the SSH allow
    /// list's business).
    pub ssh_port: u16,
    /// This worker's opening, or none to close it.
    pub opening: Option<Opening>,
}

/// The longest set name every kernel that runs nftables takes: 31 bytes.
/// (Linux 4.14 and later take 255; the name is kept to what all take.)
const SET_NAME_MAX: usize = 31;

/// The names of the two sets worker `id`'s limit counts addresses in, IPv4
/// and IPv6: `flood4_<id>` and `flood6_<id>` with the id's hyphens as
/// underscores, which no two ids share. An id too long for
/// [`SET_NAME_MAX`] is named by its first 14 characters, `__`, and a hash
/// of all of it; no name made the first way has `__`, since an id has no
/// `--`.
fn flood_sets(id: &str) -> (String, String) {
    let plain = id.replace('-', "_");
    let name = match plain.get(..14) {
        Some(start) if "flood4_".len() + plain.len() > SET_NAME_MAX => {
            // FNV-1a, 32 bits: eight hex digits that tell two long ids
            // with the same start apart.
            let hash = id.bytes().fold(0x811c_9dc5_u32, |hash, byte| {
                (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
            });
            format!("{start}__{hash:08x}")
        }
        _ => plain,
    };
    (format!("flood4_{name}"), format!("flood6_{name}"))
}

/// The server's worker firewall: every inbound connection is dropped
/// except loopback, replies to what the server started, ICMP (path MTU and
/// neighbour discovery need it), DHCP replies, SSH, and each worker's port
/// from the addresses it names. Loading it replaces the table loaded
/// before. Built from checked numbers and addresses only.
///
/// An opening with a [`NewConnections`] limit has two sets, one per
/// address family, in which the firewall counts each address's new
/// connections to the port, and two rules before its accepts that drop a
/// new connection from an address over the limit. They come after the
/// rule that accepts what is established, so a connection already made is
/// never counted or dropped. An opening without a limit adds neither, and
/// the table is then the text it was before there were limits.
///
/// A set holds 65536 addresses. While it is full an address that is not
/// in it cannot be added: its rule then does not match, and its new
/// connection goes on to the accepts. So the limit stops applying to new
/// addresses for as long as the set is full, and holds again as addresses
/// leave it, each a minute after it was added.
///
/// Where an opening lets in everyone of a family (`0.0.0.0/0`, `::/0`),
/// its accept names the family and no addresses.
#[must_use]
pub fn firewall_table(ssh_port: u16, openings: &BTreeMap<String, Opening>) -> String {
    use std::fmt::Write as _;
    let mut sets = String::new();
    let mut rules = String::new();
    for (id, opening) in openings {
        let port = opening.port;
        let _ = writeln!(rules, "    # worker {id}");
        if let Some(NewConnections { per_second, burst }) = opening.limit {
            let (four, six) = flood_sets(id);
            for (set, kind) in [(&four, "ipv4_addr"), (&six, "ipv6_addr")] {
                let _ = writeln!(
                    sets,
                    "  set {set} {{ type {kind}; flags dynamic; timeout 1m; size 65536; }}"
                );
            }
            // An IPv6 client has a /64 to itself: counted as one address.
            for (set, address) in [
                (&four, "ip saddr"),
                (&six, "ip6 saddr & ffff:ffff:ffff:ffff::"),
            ] {
                let _ = writeln!(
                    rules,
                    "    tcp dport {port} ct state new add @{set} {{ {address} limit rate over \
                     {per_second}/second burst {burst} packets }} drop"
                );
            }
        }
        for (family, protocol, v4) in [("ip", "ipv4", true), ("ip6", "ipv6", false)] {
            let of_family = || opening.allow.iter().filter(|c| c.address().is_ipv4() == v4);
            if of_family().any(crate::net::Cidr::is_everyone) {
                let _ = writeln!(rules, "    tcp dport {port} meta nfproto {protocol} accept");
                continue;
            }
            let set: Vec<String> = of_family().map(ToString::to_string).collect();
            if !set.is_empty() {
                let _ = writeln!(
                    rules,
                    "    tcp dport {port} {family} saddr {{ {} }} accept",
                    set.join(", ")
                );
            }
        }
    }
    format!(
        "table inet erpc_worker\n\
         delete table inet erpc_worker\n\
         table inet erpc_worker {{\n\
         {sets}  \
           chain input {{\n    \
             type filter hook input priority filter; policy drop;\n    \
             iif \"lo\" accept\n    \
             ct state established,related accept\n    \
             ct state invalid drop\n    \
             meta l4proto icmp accept\n    \
             meta l4proto ipv6-icmp accept\n    \
             udp sport 67 udp dport 68 accept\n    \
             udp sport 547 udp dport 546 accept\n    \
             tcp dport {ssh_port} accept\n\
         {rules}  \
           }}\n\
         }}\n"
    )
}

/// `[run.health]`, as a release carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    /// A loopback URL that answers 2xx once the app is ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<String>,
    /// How long a start has to become healthy, in seconds.
    pub timeout_secs: u32,
}

/// `launch.json`: how the agent starts this release. Written by `deploy`
/// from `erpc.toml`; holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    /// [`LAUNCH_FORMAT`].
    pub format: u32,
    /// The binary's name in the release directory.
    pub bin: String,
    /// Arguments after it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Plain settings.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
    /// The secret settings the app needs, by name; their values come with
    /// [`Request::Unlock`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    /// The public key of the trading key the app needs, when it needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    /// How a start is judged healthy.
    pub health: Health,
    /// How many releases the server keeps, the live one included.
    pub keep_releases: u8,
}

impl Launch {
    /// The launch file for `m`'s releases in `env`: its settings without
    /// their secret values, with the endpoints of `env`'s data lines over
    /// them, the names of its secrets, and its wallet's public key.
    ///
    /// # Errors
    ///
    /// A message when the app has a wallet without a public key: the app
    /// checks the key it is handed against it (`ERPC_WORKER_PUBKEY`), as
    /// erpc does when it reads the key.
    pub fn for_app(
        m: &crate::manifest::Manifest,
        env: &crate::manifest::Env,
    ) -> Result<Self, String> {
        let pubkey = match &m.wallet {
            Some(wallet) => Some(wallet.pubkey.clone().ok_or(
                "wallet.pubkey is not set in erpc.toml; the app checks the key it is handed \
                 against it, so a deploy needs it",
            )?),
            None => None,
        };
        let health = m.run.health.as_ref();
        let mut vars = m.vars.clone();
        for (name, url) in m.services.vars() {
            vars.entry(name.to_owned())
                .or_insert_with(|| url.to_owned());
        }
        for (name, endpoint) in env.line_vars() {
            vars.insert(name.to_owned(), endpoint.to_owned());
        }
        Ok(Self {
            format: LAUNCH_FORMAT,
            bin: m.bin().to_owned(),
            args: m.run.args.clone(),
            vars,
            secrets: m.secrets.keys().cloned().collect(),
            pubkey,
            health: Health {
                http: health.and_then(|h| h.http.clone()),
                timeout_secs: health.map_or(30, |h| h.timeout_secs),
            },
            keep_releases: m.deploy.keep_releases,
        })
    }

    /// Parses `launch.json`, refusing another format.
    ///
    /// # Errors
    ///
    /// A message when the text is not a launch file this agent reads.
    pub fn parse(text: &str) -> Result<Self, String> {
        let launch: Self =
            serde_json::from_str(text).map_err(|e| format!("{LAUNCH_FILE} is not valid: {e}"))?;
        if launch.format != LAUNCH_FORMAT {
            return Err(format!(
                "{LAUNCH_FILE} is format {}, and this agent reads {LAUNCH_FORMAT}",
                launch.format
            ));
        }
        if !crate::release::is_inside(&launch.bin) || launch.bin.contains('/') {
            return Err(format!(
                "{LAUNCH_FILE}'s binary `{}` is not a file name",
                launch.bin
            ));
        }
        Ok(launch)
    }
}

/// What erpc asks the agent, one JSON object per line on its socket.
///
/// Never answered with a secret: no request returns the key or a secret
/// value, so a process that reaches the socket can stop the app at worst.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    /// How the worker is.
    Status {},
    /// The key and the secrets, held in memory from now on. Replaces any
    /// held already.
    Unlock {
        /// Secret settings by name.
        #[serde(default)]
        secrets: BTreeMap<String, zeroize::Zeroizing<String>>,
        /// The trading key, as the 64 numbers `solana-keygen` writes.
        #[serde(default)]
        key: Option<zeroize::Zeroizing<Vec<u8>>>,
    },
    /// Forgets the key and the secrets, and stops the app.
    Lock {},
    /// Runs the app from `current`, and keeps it running.
    Start {},
    /// Stops the app, and keeps it stopped.
    Stop {},
    /// Stops the app and starts it again from `current`.
    Restart {},
}

/// The agent's answer about the worker.
///
/// The agent that runs is asked for this by the `ctl` of the agent that is
/// installed, and after an upgrade those are two versions until a deploy
/// restarts the agent: its setup waits for this answer first. So an older
/// agent's answer must stay readable: a field added here is optional
/// (`#[serde(default)]`), and none is renamed or removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// `locked`, `stopped`, `starting`, `running` or `waiting` (to restart
    /// after the app ended).
    pub state: String,
    /// Whether the app is up and answering its health check.
    pub healthy: bool,
    /// Whether it should be running.
    pub wanted: bool,
    /// Whether a key is held.
    pub key_held: bool,
    /// The secrets held, by name.
    pub secrets_held: Vec<String>,
    /// The release the app was started from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// The app's process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Seconds since the app started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_secs: Option<u64>,
    /// How many times the app was started again after ending.
    pub restarts: u32,
    /// How the app last ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_exit: Option<String>,
    /// Why it cannot run, when it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The agent's answer to a request. As with [`Status`], an older agent's
/// answer must stay readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    /// Whether the request was done.
    pub ok: bool,
    /// Why not, when not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The worker after the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

/// The parts of a health URL: the loopback address it names, its
/// authority as written and its path. `erpc.toml` allows only
/// `http://127.0.0.1:<port>/…`, `http://localhost:<port>/…` and
/// `http://[::1]:<port>/…` for a health check.
fn loopback(url: &str) -> Option<(std::net::SocketAddr, &str, &str)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| rest.split_at(i));
    let (host, port) = authority.rsplit_once(':')?;
    let host = match host {
        "localhost" => "127.0.0.1",
        other => other.trim_start_matches('[').trim_end_matches(']'),
    };
    let ip = host.parse::<std::net::IpAddr>().ok()?;
    if !ip.is_loopback() {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    Some((std::net::SocketAddr::new(ip, port), authority, path))
}

/// The loopback address a health URL is probed at, when it names one.
#[must_use]
pub fn health_address(url: &str) -> Option<std::net::SocketAddr> {
    loopback(url).map(|(address, _, _)| address)
}

/// Whether something already listens where `url` is probed. Asked before
/// an app is started: an answer then comes from another program, and the
/// health check would take that program's answer for the app's.
#[must_use]
pub fn listened_on(url: &str) -> Option<u16> {
    let address = health_address(url)?;
    TcpStream::connect_timeout(&address, Duration::from_millis(300))
        .ok()
        .map(|_| address.port())
}

/// What a start that was refused says when the app's port is not free:
/// `by` is the other worker on the server that listens there, when it is
/// one. [`taken_port`] reads the port back, for a hint in the reader's
/// language.
#[must_use]
pub fn port_taken(port: u16, by: Option<&str>) -> String {
    match by {
        Some(worker) => {
            format!("port {port} is taken: {worker} on this server listens there")
        }
        None => format!("port {port} is taken: another program on this server listens there"),
    }
}

/// The port a refusal worded by [`port_taken`] names.
#[must_use]
pub fn taken_port(refusal: &str) -> Option<u16> {
    let (port, _) = refusal.strip_prefix("port ")?.split_once(" is taken: ")?;
    port.parse().ok()
}

/// Whether a loopback URL answers 2xx. This speaks just enough HTTP for
/// the health checks `erpc.toml` allows.
#[must_use]
pub fn probe(url: &str) -> bool {
    let Some((address, authority, path)) = loopback(url) else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(500)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let request = format!("GET {path} HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0_u8; 32];
    let Ok(n) = stream.read(&mut head) else {
        return false;
    };
    let line = String::from_utf8_lossy(&head[..n]);
    line.split_whitespace()
        .nth(1)
        .is_some_and(|code| code.starts_with('2') && code.len() == 3)
}

#[cfg(test)]
mod tests {
    use super::{BACKUP_REPOSITORY, RESTIC_PATH};

    #[test]
    fn needrestart_is_told_to_leave_every_worker_unit_alone() {
        let conf = super::needrestart_conf();
        // One Perl statement that adds to the hash needrestart.conf sets,
        // with a pattern every worker unit's name starts with. The worker
        // firewall's units start with it too (`erpc-worker-firewall.service`,
        // and the `erpc-worker-firewall-rollback` timer and service): each
        // runs a command and ends, so there is no process for needrestart
        // to restart. A backup's units do not start with it, and neither
        // does the WAF's: it holds no key, and may be restarted.
        let rule = conf
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("a statement");
        assert_eq!(rule, "$nrconf{override_rc}{qr(^erpc-worker-)} = 0;");
        assert!(super::unit_name("bot-prod").starts_with("erpc-worker-"));
        assert!(!super::backup_service_name("bot-prod").starts_with("erpc-worker-"));
        assert!(!super::backup_timer_name("bot-prod").starts_with("erpc-worker-"));
        assert!(!super::waf_unit_name("bot-prod").starts_with("erpc-worker-"));
        assert!(
            super::NEEDRESTART_CONF.starts_with("/etc/needrestart/conf.d/")
                && std::path::Path::new(super::NEEDRESTART_CONF)
                    .extension()
                    .is_some_and(|ext| ext == "conf"),
            "needrestart reads conf.d/*.conf only"
        );
    }

    #[test]
    fn a_taken_port_is_read_back_from_its_refusal() {
        use super::{port_taken, taken_port};
        assert_eq!(taken_port(&port_taken(3000, None)), Some(3000));
        assert_eq!(
            taken_port(&port_taken(8080, Some("api-default"))),
            Some(8080)
        );
        assert!(port_taken(8080, Some("api-default")).contains("api-default"));
        for other in [
            "locked: no value for API_TOKEN",
            "port is taken",
            "port x is taken: y",
        ] {
            assert_eq!(taken_port(other), None, "{other}");
        }
    }

    #[test]
    fn only_a_listener_makes_a_health_port_taken() {
        use super::{health_address, listened_on};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let url = format!("http://127.0.0.1:{port}/healthz");
        assert_eq!(health_address(&url).map(|a| a.port()), Some(port));
        assert_eq!(listened_on(&url), Some(port));
        drop(listener);
        assert_eq!(listened_on(&url), None, "nothing listens there now");
        // Only a loopback URL is a health URL, so nothing else is asked.
        let elsewhere = ["http:", "//192.0.2.1:80/"].concat();
        assert_eq!(health_address(&elsewhere), None);
        assert_eq!(listened_on("https://127.0.0.1:1/"), None);
    }

    #[test]
    fn a_backup_credentials_file_holds_the_five_variables_only() {
        let good = format!(
            "RESTIC_REPOSITORY={BACKUP_REPOSITORY}\nRESTIC_REST_USERNAME=erpcsk_TESTONLY\n\
             RESTIC_REST_PASSWORD=abc-DEF_123\nRESTIC_PASSWORD=0123abcd\n\
             RESTIC_HOST=erpc-worker-bot-default-0a1b2c3d\n"
        );
        assert!(super::backup_env_ok("bot-default", &good));
        assert!(!super::backup_env_ok("bot-prod", &good));
        for bad in [
            good.replace("RESTIC_PASSWORD=0123abcd", "RESTIC_PASSWORD=a b"),
            good.replace("RESTIC_PASSWORD=0123abcd", "RESTIC_PASSWORD=$(id)"),
            good.replace("RESTIC_PASSWORD=0123abcd\n", ""),
            format!("{good}LD_PRELOAD=/tmp/x\n"),
            format!("{good}RESTIC_PASSWORD=again\n"),
            good.replace(
                BACKUP_REPOSITORY,
                &BACKUP_REPOSITORY.replace("user-api", "other"),
            ),
            good.replace("RESTIC_REST_PASSWORD=abc-DEF_123", "RESTIC_REST_PASSWORD="),
            good.replace('\n', "\r\n"),
            good.replace("-0a1b2c3d", "-0A1B2C3D"),
            good.replace("-0a1b2c3d", "-0a1b2c"),
            good.replace("-0a1b2c3d", ""),
            good.replace("RESTIC_HOST=erpc-worker-bot-default-0a1b2c3d\n", ""),
        ] {
            assert!(!super::backup_env_ok("bot-default", &bad), "{bad}");
        }
    }

    #[test]
    fn the_backup_units_back_up_the_state_where_it_really_is() {
        let service = super::backup_service("bot-default");
        assert!(service.contains(&format!(
            "ExecStart={RESTIC_PATH} backup --host ${{RESTIC_HOST}} --tag erpc-worker \
             --tag bot-default /var/lib/private/erpc-worker-bot-default\n"
        )));
        assert!(service.contains("EnvironmentFile=/etc/erpc/backup/bot-default.env\n"));
        assert!(service.contains("IOSchedulingClass=idle\n"));
        let timer = super::backup_timer("bot-default", (3, 5));
        assert!(timer.contains("OnCalendar=*-*-* 03:05:00\n"));
        assert!(timer.contains("Persistent=true\n"));
        assert!(super::is_backup_host(
            "bot-default",
            &super::backup_host("bot-default", "0a1b2c3d")
        ));
        for bad in [
            "erpc-worker-bot-default",
            "erpc-worker-bot-0a1b2c3d",
            "erpc-worker-bot-default-0a1b2c3d-x",
        ] {
            assert!(!super::is_backup_host("bot-default", bad), "{bad}");
        }
        assert_eq!(super::time_of_day("03:05"), Some((3, 5)));
        for bad in ["3:05", "24:00", "03:60", "0305", "aa:bb", "03:05 "] {
            assert_eq!(super::time_of_day(bad), None, "{bad}");
        }
    }

    use std::io::{Read as _, Write as _};

    use super::{Launch, Request, is_unit_id, probe, unit};

    /// A deploy's setup waits for the status of the agent that runs, with
    /// the `ctl` of the agent it has just installed: an older agent's
    /// answer has to parse, or no deploy reaches the restart that replaces
    /// it. These are the answers as an agent has sent them since the
    /// first; a field added to [`super::Status`] or [`super::Reply`] must
    /// leave them readable.
    #[test]
    fn an_older_agents_answer_stays_readable() {
        use super::Reply;
        let locked = r#"{"ok":true,"status":{"state":"locked","healthy":false,"wanted":true,"key_held":false,"secrets_held":[],"restarts":0}}"#;
        let reply: Reply = serde_json::from_str(locked).expect("an older agent, locked");
        let status = reply.status.expect("status");
        assert_eq!((status.state.as_str(), status.key_held), ("locked", false));
        assert_eq!(
            (status.release, status.pid, status.reason),
            (None, None, None)
        );
        let running = r#"{"ok":true,"status":{"state":"running","healthy":true,"wanted":true,"key_held":true,"secrets_held":["API_TOKEN"],"release":"20261029T121314Z-1a2b3c4d","pid":4242,"up_secs":90,"restarts":1,"last_exit":"exit status: 1"}}"#;
        let reply: Reply = serde_json::from_str(running).expect("an older agent, running");
        let status = reply.status.expect("status");
        assert!(status.healthy && status.key_held);
        assert_eq!(status.secrets_held, ["API_TOKEN"]);
        // A refusal carries no status.
        let refused: Reply =
            serde_json::from_str(r#"{"ok":false,"error":"locked"}"#).expect("a refusal");
        assert_eq!((refused.ok, refused.status), (false, None));
        // The other way round too: a newer agent's answer, with a field
        // this version does not know, is read by an older `ctl`.
        let newer = locked.replace(r#""restarts":0"#, r#""restarts":0,"since":"2026-11-11""#);
        assert!(serde_json::from_str::<Reply>(&newer).is_ok());
    }

    #[test]
    fn a_unit_is_written_for_a_worker_id_only() {
        assert!(is_unit_id("pump-sniper-default"));
        assert!(!is_unit_id("../etc"));
        assert!(!is_unit_id("Bot"));
        let text = unit("bot-prod");
        assert!(
            text.contains(
                "ExecStart=/usr/local/lib/erpc/erpc-worker-agent supervise --id bot-prod"
            )
        );
        for line in [
            "DynamicUser=yes",
            "LimitCORE=0",
            "MemorySwapMax=0",
            "NoNewPrivileges=yes",
            "KillMode=control-group",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}");
        }
    }

    #[test]
    fn the_waf_is_a_unit_of_its_own_with_nothing_of_the_workers() {
        use super::{WAF_DIR, waf_config_path, waf_stats_path, waf_unit, waf_unit_name};
        assert_eq!(waf_unit_name("bot-prod"), "erpc-waf-bot-prod.service");
        assert_eq!(
            waf_config_path("bot-prod"),
            "/etc/erpc/worker-waf/bot-prod.json"
        );
        assert!(waf_config_path("bot-prod").starts_with(WAF_DIR));
        assert_eq!(
            waf_stats_path("bot-prod"),
            "/run/erpc-waf-bot-prod/stats.json"
        );
        let text = waf_unit("bot-prod");
        for line in [
            "ExecStart=/usr/local/lib/erpc/erpc-worker-agent waf --config \
             /etc/erpc/worker-waf/bot-prod.json",
            "After=network-online.target erpc-worker-bot-prod.service",
            "Wants=network-online.target erpc-worker-bot-prod.service",
            "DynamicUser=yes",
            "RuntimeDirectory=erpc-waf-bot-prod",
            "RuntimeDirectoryMode=0755",
            "Restart=on-failure",
            "RestartPreventExitStatus=2",
            "TimeoutStopSec=20",
            "LimitNOFILE=4096",
            "LimitCORE=0",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "ProtectSystem=strict",
            "KillMode=control-group",
            // Its own, as the unit that faces the network: a ceiling on
            // its memory, the system calls of a service and no others, in
            // the machine's own architecture, and sockets of the three
            // families it uses.
            "MemoryMax=1G",
            "SystemCallFilter=@system-service",
            "SystemCallArchitectures=native",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}");
            assert_eq!(text.matches(line).count(), 1, "{line} is there once");
        }
        // Every directive is in [Service], where systemd reads it.
        let service: Vec<&str> = text
            .lines()
            .skip_while(|l| *l != "[Service]")
            .take_while(|l| *l != "[Install]")
            .collect();
        for line in ["MemoryMax=1G", "SystemCallFilter=@system-service"] {
            assert!(service.contains(&line), "{line} is not in [Service]");
        }
        // The stats file is where the unit's runtime directory is.
        assert!(waf_stats_path("bot-prod").starts_with("/run/erpc-waf-bot-prod/"));
        // A worker called `waf-<x>` and the WAF of worker `<x>` are two
        // units and two runtime directories.
        assert_ne!(waf_unit_name("bot-prod"), super::unit_name("waf-bot-prod"));
        assert!(
            !waf_stats_path("bot-prod").starts_with(
                super::socket_path("waf-bot-prod")
                    .parent()
                    .expect("its directory")
                    .to_str()
                    .expect("a plain path")
            )
        );
        // Every confinement of the worker's unit is on this one too, but
        // for what it has no use for: locked memory and no swap are for a
        // key, and netlink for nothing the proxy does.
        let worker = unit("bot-prod");
        let hardening = worker.lines().skip_while(|l| *l != "LimitCORE=0");
        for line in hardening.take_while(|l| !l.is_empty()) {
            let dropped = line.starts_with("LimitMEMLOCK=")
                || line.starts_with("MemorySwapMax=")
                || line.starts_with("ReadOnlyPaths=");
            if line.starts_with("RestrictAddressFamilies=") {
                assert!(
                    text.lines()
                        .any(|l| l == "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6")
                );
            } else {
                assert_eq!(text.lines().any(|l| l == line), !dropped, "{line}");
            }
        }
        // It has no state to keep, and nothing of the worker's to reach.
        for absent in ["StateDirectory", "supervise", "agent.sock", "/opt/erpc"] {
            assert!(!text.contains(absent), "{absent}");
        }
    }

    #[test]
    fn the_firewall_drops_what_it_does_not_name() {
        use super::{Opening, firewall_table};
        use crate::net::Cidr;
        let mut openings = std::collections::BTreeMap::new();
        openings.insert(
            "bot-default".to_owned(),
            Opening {
                port: 3000,
                allow: vec![
                    Cidr::parse("198.51.100.7").expect("v4"),
                    Cidr::parse("203.0.113.0/24").expect("net"),
                    Cidr::parse("2001:db8::1").expect("v6"),
                ],
                limit: None,
            },
        );
        let table = firewall_table(22, &openings);
        for line in [
            "type filter hook input priority filter; policy drop;",
            "tcp dport 22 accept",
            "tcp dport 3000 ip saddr { 198.51.100.7/32, 203.0.113.0/24 } accept",
            "tcp dport 3000 ip6 saddr { 2001:db8::1/128 } accept",
        ] {
            assert!(
                table.lines().any(|l| l.trim() == line),
                "missing {line} in:\n{table}"
            );
        }
        assert!(!firewall_table(22, &std::collections::BTreeMap::new()).contains("3000"));
    }

    /// The table an opening without a limit makes: what it was before an
    /// opening could have one, byte for byte.
    const PLAIN_TABLE: &str = "\
table inet erpc_worker
delete table inet erpc_worker
table inet erpc_worker {
  chain input {
    type filter hook input priority filter; policy drop;
    iif \"lo\" accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto icmp accept
    meta l4proto ipv6-icmp accept
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
    tcp dport 22 accept
    # worker api-prod
    tcp dport 8080 ip6 saddr { 2001:db8::/32 } accept
    # worker bot-default
    tcp dport 3000 ip saddr { 198.51.100.7/32, 203.0.113.0/24 } accept
    tcp dport 3000 ip6 saddr { 2001:db8::1/128 } accept
  }
}
";

    /// The same two workers, the first now behind a WAF on 8080 with the
    /// default limit on new connections.
    const LIMITED_TABLE: &str = "\
table inet erpc_worker
delete table inet erpc_worker
table inet erpc_worker {
  set flood4_api_prod { type ipv4_addr; flags dynamic; timeout 1m; size 65536; }
  set flood6_api_prod { type ipv6_addr; flags dynamic; timeout 1m; size 65536; }
  chain input {
    type filter hook input priority filter; policy drop;
    iif \"lo\" accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto icmp accept
    meta l4proto ipv6-icmp accept
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
    tcp dport 22 accept
    # worker api-prod
    tcp dport 8080 ct state new add @flood4_api_prod { ip saddr limit rate over 50/second burst 100 packets } drop
    tcp dport 8080 ct state new add @flood6_api_prod { ip6 saddr & ffff:ffff:ffff:ffff:: limit rate over 50/second burst 100 packets } drop
    tcp dport 8080 ip6 saddr { 2001:db8::/32 } accept
    # worker bot-default
    tcp dport 3000 ip saddr { 198.51.100.7/32, 203.0.113.0/24 } accept
    tcp dport 3000 ip6 saddr { 2001:db8::1/128 } accept
  }
}
";

    fn two_openings() -> std::collections::BTreeMap<String, super::Opening> {
        use super::Opening;
        use crate::net::Cidr;
        let mut openings = std::collections::BTreeMap::new();
        openings.insert(
            "api-prod".to_owned(),
            Opening {
                port: 8080,
                allow: vec![Cidr::parse("2001:db8::/32").expect("v6")],
                limit: None,
            },
        );
        openings.insert(
            "bot-default".to_owned(),
            Opening {
                port: 3000,
                allow: vec![
                    Cidr::parse("198.51.100.7").expect("v4"),
                    Cidr::parse("203.0.113.0/24").expect("net"),
                    Cidr::parse("2001:db8::1").expect("v6"),
                ],
                limit: None,
            },
        );
        openings
    }

    #[test]
    fn behind_a_waf_it_is_the_wafs_port_that_is_opened() {
        use super::{NewConnections, Opening};
        use crate::manifest::Manifest;
        let manifest = |waf: &str, allow: &str| {
            Manifest::parse(&format!(
                "name = \"bot\"\nchain = \"solana\"\n[run]\nport = 3000\n{waf}\
                 [env.prod]\nhost = \"203.0.113.10\"\n\
                 [env.prod.firewall]\napp_allow = [{allow}]\n"
            ))
            .expect("valid")
        };
        let opening = |m: &Manifest| Opening::for_app(m, &m.env["prod"]);
        // The app's own port, and no limit, as before.
        let direct = opening(&manifest("", "\"198.51.100.0/24\"")).expect("an opening");
        assert_eq!((direct.port, direct.limit), (3000, None));
        // Behind a WAF: its port, never the app's, with the firewall's limit.
        let behind = manifest("[waf]\nport = 8080\n", "\"0.0.0.0/0\"");
        let waf = opening(&behind).expect("an opening");
        assert_eq!((waf.port, waf.limit), (8080, Some(NewConnections::DEFAULT)));
        assert_eq!(waf.allow, behind.env["prod"].firewall.app_allow);
        let unlimited = manifest("[waf]\nport = 8080\nnew_connections = false\n", "\"::/0\"");
        let waf = opening(&unlimited).expect("an opening");
        assert_eq!((waf.port, waf.limit), (8080, None));
        // Nobody listed: nothing is opened, WAF or not.
        assert_eq!(opening(&manifest("[waf]\nport = 8080\n", "")), None);
        assert_eq!(opening(&manifest("", "")), None);
    }

    #[test]
    fn an_opening_without_a_limit_makes_the_table_it_always_made() {
        use super::{Opening, firewall_table};
        let openings = two_openings();
        assert_eq!(firewall_table(22, &openings), PLAIN_TABLE);
        // And is kept on the server as it always was: no `limit` key, so an
        // agent from before reads it.
        let kept = serde_json::to_string(&openings["api-prod"]).expect("json");
        assert_eq!(kept, r#"{"port":8080,"allow":["2001:db8::/32"]}"#);
        let read: Opening = serde_json::from_str(&kept).expect("read");
        assert_eq!(read.limit, None);
    }

    #[test]
    fn a_limit_on_new_connections_comes_before_the_openings_accepts() {
        use super::{NewConnections, firewall_table};
        let mut openings = two_openings();
        openings.get_mut("api-prod").expect("there").limit = Some(NewConnections::DEFAULT);
        assert_eq!(
            NewConnections::DEFAULT,
            NewConnections {
                per_second: 50,
                burst: 100
            }
        );
        assert_eq!(firewall_table(22, &openings), LIMITED_TABLE);
        // The limit's own numbers, and only its worker's rules, change.
        openings.get_mut("api-prod").expect("there").limit = Some(NewConnections {
            per_second: 5,
            burst: 7,
        });
        let table = firewall_table(22, &openings);
        assert_eq!(
            table,
            LIMITED_TABLE.replace("50/second burst 100 packets", "5/second burst 7 packets")
        );
        let kept = serde_json::to_string(&openings["api-prod"]).expect("json");
        assert_eq!(
            kept,
            r#"{"port":8080,"allow":["2001:db8::/32"],"limit":{"per_second":5,"burst":7}}"#
        );
    }

    #[test]
    fn a_limit_is_within_its_bounds_or_said_not_to_be() {
        use super::{MAX_NEW_CONNECTIONS_BURST, MAX_NEW_CONNECTIONS_PER_SECOND, NewConnections};
        let limit = |per_second, burst| NewConnections { per_second, burst };
        assert!(NewConnections::DEFAULT.problems().is_empty());
        assert!(limit(1, 1).problems().is_empty());
        assert!(
            limit(MAX_NEW_CONNECTIONS_PER_SECOND, MAX_NEW_CONNECTIONS_BURST)
                .problems()
                .is_empty()
        );
        assert_eq!(
            limit(0, 0).problems(),
            [
                "per_second is 0; it is 1 to 10000",
                "burst is 0; it is 1 to 100000"
            ]
        );
        assert_eq!(limit(10_001, 1).problems().len(), 1);
        assert_eq!(limit(1, 100_001).problems().len(), 1);
    }

    #[test]
    fn a_set_is_named_after_its_worker_within_what_nftables_takes() {
        use super::flood_sets;
        assert_eq!(
            flood_sets("bot-default"),
            (
                "flood4_bot_default".to_owned(),
                "flood6_bot_default".to_owned()
            )
        );
        // 24 characters is the longest id named as it is.
        let longest = "abcdefghij-klmnopqrst-12";
        assert_eq!(longest.len(), 24);
        assert_eq!(flood_sets(longest).0, "flood4_abcdefghij_klmnopqrst_12");
        // A longer one is its start and a hash of all of it, so two that
        // start alike differ, and neither is another worker's plain name.
        let (a, b) = (
            "pump-sniper-with-a-long-name-default",
            "pump-sniper-with-a-long-name-staging",
        );
        let (four, six) = flood_sets(a);
        assert_eq!(four, "flood4_pump_sniper_wi__0a31d5bd");
        assert_eq!(six, "flood6_pump_sniper_wi__0a31d5bd");
        assert_ne!(flood_sets(a), flood_sets(b));
        // The longest id there is, and every name in between.
        let id = format!("a{}", "-b".repeat(24));
        assert!(super::is_unit_id(&id) && id.len() == 49);
        for len in 1..=id.len() {
            let Some(id) = id.get(..len).filter(|id| super::is_unit_id(id)) else {
                continue;
            };
            for name in [flood_sets(id).0, flood_sets(id).1] {
                assert!(name.len() <= 31, "{name}");
                assert!(
                    name.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                    "{name}"
                );
                assert_eq!(name.contains("__"), id.len() > 24, "{name}");
            }
        }
    }

    #[test]
    fn everyone_is_let_in_by_family_without_a_set() {
        use super::{NewConnections, Opening, firewall_table};
        use crate::net::Cidr;
        let open_to = |allow: &[&str]| {
            let mut openings = std::collections::BTreeMap::new();
            openings.insert(
                "api-prod".to_owned(),
                Opening {
                    port: 8080,
                    allow: allow
                        .iter()
                        .map(|a| Cidr::parse_any(a).expect("cidr"))
                        .collect(),
                    limit: Some(NewConnections::DEFAULT),
                },
            );
            // What follows the limit's two rules: the opening's accepts.
            firewall_table(22, &openings)
                .lines()
                .skip_while(|l| !l.contains("add @flood6_api_prod {"))
                .skip(1)
                .take_while(|l| l.trim() != "}")
                .map(|l| l.trim().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            open_to(&["0.0.0.0/0", "::/0"]),
            [
                "tcp dport 8080 meta nfproto ipv4 accept",
                "tcp dport 8080 meta nfproto ipv6 accept"
            ]
        );
        // One family to everyone, the other to those it names; an address
        // beside "everyone" of its family adds nothing.
        assert_eq!(
            open_to(&["0.0.0.0/0", "198.51.100.7", "2001:db8::1"]),
            [
                "tcp dport 8080 meta nfproto ipv4 accept",
                "tcp dport 8080 ip6 saddr { 2001:db8::1/128 } accept"
            ]
        );
        assert_eq!(
            open_to(&["0.0.0.0/0"]),
            ["tcp dport 8080 meta nfproto ipv4 accept"]
        );
    }

    #[test]
    fn a_launch_file_of_another_format_is_refused() {
        let text = r#"{"format":1,"bin":"bot","health":{"timeout_secs":30},"keep_releases":5}"#;
        assert_eq!(Launch::parse(text).expect("valid").bin, "bot");
        assert!(Launch::parse(&text.replace("\"format\":1", "\"format\":2")).is_err());
        assert!(Launch::parse(&text.replace("\"bin\"", "\"binary\"")).is_err());
    }

    #[test]
    fn requests_are_one_object_each_and_unknown_ones_are_refused() {
        let r: Request = serde_json::from_str(r#"{"op":"unlock","secrets":{"A":"b"},"key":[1,2]}"#)
            .expect("unlock");
        assert!(
            matches!(r, Request::Unlock { ref secrets, ref key } if secrets.len() == 1 && key.as_ref().is_some_and(|k| k.len() == 2))
        );
        assert!(serde_json::from_str::<Request>(r#"{"op":"status"}"#).is_ok());
        assert!(serde_json::from_str::<Request>(r#"{"op":"dump-key"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"status","x":1}"#).is_err());
    }

    #[test]
    fn a_loopback_health_url_is_probed_and_another_is_not() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            for answer in ["HTTP/1.1 200 OK\r\n\r\nok", "HTTP/1.1 503 Busy\r\n\r\n"] {
                let (mut s, _) = listener.accept().expect("accept");
                let mut buf = [0_u8; 256];
                let _ = s.read(&mut buf);
                let _ = s.write_all(answer.as_bytes());
            }
        });
        let url = format!("http://127.0.0.1:{port}/healthz");
        assert!(probe(&url));
        assert!(!probe(&url));
        server.join().expect("server");
        assert!(!probe("http://127.0.0.1:1/healthz"));
        assert!(!probe("https://127.0.0.1:1/"));
    }
}
