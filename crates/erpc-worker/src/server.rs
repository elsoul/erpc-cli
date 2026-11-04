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

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
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

/// One worker's opening in its server's firewall: its port, to the
/// addresses and networks its `firewall.app_allow` lists. Kept on the
/// server per worker, as `FIREWALL_DIR/workers/<id>.json`, so the workers
/// on one server share one table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    /// The app's port.
    pub port: u16,
    /// Who may reach it.
    pub allow: Vec<crate::net::Cidr>,
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

/// The server's worker firewall: every inbound connection is dropped
/// except loopback, replies to what the server started, ICMP (path MTU and
/// neighbour discovery need it), DHCP replies, SSH, and each worker's port
/// from the addresses it names. Loading it replaces the table loaded
/// before. Built from checked numbers and addresses only.
#[must_use]
pub fn firewall_table(ssh_port: u16, openings: &BTreeMap<String, Opening>) -> String {
    use std::fmt::Write as _;
    let mut rules = String::new();
    for (id, opening) in openings {
        let _ = writeln!(rules, "    # worker {id}");
        for (family, v4) in [("ip", true), ("ip6", false)] {
            let set: Vec<String> = opening
                .allow
                .iter()
                .filter(|c| c.address().is_ipv4() == v4)
                .map(ToString::to_string)
                .collect();
            if !set.is_empty() {
                let _ = writeln!(
                    rules,
                    "    tcp dport {} {family} saddr {{ {} }} accept",
                    opening.port,
                    set.join(", ")
                );
            }
        }
    }
    format!(
        "table inet erpc_worker\n\
         delete table inet erpc_worker\n\
         table inet erpc_worker {{\n  \
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

/// The agent's answer to a request.
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

/// Whether a loopback URL answers 2xx. `erpc.toml` allows only
/// `http://127.0.0.1:<port>/…`, `http://localhost:<port>/…` and
/// `http://[::1]:<port>/…` for a health check, so this speaks just enough
/// HTTP for that.
#[must_use]
pub fn probe(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| rest.split_at(i));
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    let host = match host {
        "localhost" => "127.0.0.1",
        other => other.trim_start_matches('[').trim_end_matches(']'),
    };
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    if !ip.is_loopback() {
        return false;
    }
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    let address = std::net::SocketAddr::new(ip, port);
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
