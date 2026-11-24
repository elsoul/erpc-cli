// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which program holds which socket: each process's executable name and the
//! socket inodes among its open files.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use erpc_api::security_check::App;

/// The processes read, and the sockets each one holds.
#[derive(Debug, Default)]
pub(super) struct Scan {
    /// Socket inode to the process that holds it.
    pub(super) holders: HashMap<u64, u32>,
    /// Process to its program.
    pub(super) apps: HashMap<u32, App>,
    /// Whether every process was listed, so a program missing from
    /// `apps` is not running.
    pub(super) listed: bool,
    /// Whether, in addition, every process's open files could be read.
    pub(super) complete: bool,
}

/// What a scan may spend before it stops and reports itself partial. A
/// validator holds many open files; the check must not slow it down.
#[derive(Clone, Copy)]
pub(super) struct Budget {
    pub(super) entries: usize,
    pub(super) time: Duration,
}

impl Budget {
    pub(super) const DEFAULT: Self = Self {
        entries: 4_000_000,
        time: Duration::from_secs(20),
    };
}

/// Reads every process under `proc`.
pub(super) fn scan(proc: &Path, budget: Budget) -> Scan {
    let started = Instant::now();
    let Ok(entries) = std::fs::read_dir(proc) else {
        return Scan::default();
    };
    let mut scan = Scan {
        complete: true,
        ..Scan::default()
    };
    let mut seen = 0usize;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if started.elapsed() > budget.time {
            scan.complete = false;
            return scan;
        }
        let dir = entry.path();
        let app = app_of(&dir);
        scan.apps.insert(pid, app);
        let fds = match std::fs::read_dir(dir.join("fd")) {
            Ok(fds) => fds,
            // The process ended between the two reads.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                scan.complete = false;
                continue;
            }
        };
        for fd in fds.flatten() {
            seen += 1;
            if seen > budget.entries || started.elapsed() > budget.time {
                scan.complete = false;
                return scan;
            }
            if let Some(inode) = std::fs::read_link(fd.path())
                .ok()
                .as_deref()
                .and_then(Path::to_str)
                .and_then(socket_inode)
            {
                // A socket systemd or a supervisor also holds belongs to the
                // program that serves it, when that one is known.
                let holder = scan.holders.entry(inode).or_insert(pid);
                let named =
                    |app: Option<&App>| !matches!(app, None | Some(App::Other | App::Unknown));
                if !named(scan.apps.get(holder)) && named(Some(&app)) {
                    *holder = pid;
                }
            }
        }
    }
    scan.listed = true;
    scan
}

fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The program of the process at `dir`: its executable's name, or the
/// kernel's short name for it when the executable cannot be read.
fn app_of(dir: &Path) -> App {
    let exe = std::fs::read_link(dir.join("exe")).ok().and_then(|path| {
        let name = path.file_name()?.to_str()?.to_owned();
        Some(name.strip_suffix(" (deleted)").unwrap_or(&name).to_owned())
    });
    let name = exe.or_else(|| {
        std::fs::read_to_string(dir.join("comm"))
            .ok()
            .map(|comm| comm.trim_end_matches('\n').to_owned())
    });
    name.map_or(App::Unknown, |name| app_for(&name))
}

const PROGRAMS: &[(&str, App)] = &[
    ("agave-validator", App::AgaveValidator),
    ("solana-validator", App::SolanaValidator),
    ("fdctl", App::Firedancer),
    ("fddev", App::Firedancer),
    ("firedancer", App::Firedancer),
    ("jito-relayer", App::JitoRelayer),
    ("jito-transaction-relayer", App::JitoRelayer),
    ("jito-shredstream-proxy", App::JitoShredstream),
    ("geth", App::Geth),
    ("bsc", App::BscGeth),
    ("reth", App::Reth),
    ("op-reth", App::Reth),
    ("erigon", App::Erigon),
    ("nethermind", App::Nethermind),
    ("Nethermind.Runner", App::Nethermind),
    ("besu", App::Besu),
    ("op-node", App::OpNode),
    ("lighthouse", App::Lighthouse),
    ("beacon-chain", App::Prysm),
    ("teku", App::Teku),
    ("nimbus_beacon_node", App::Nimbus),
    ("lodestar", App::Lodestar),
    ("bitcoind", App::Bitcoind),
    ("avalanchego", App::Avalanchego),
    ("sui-node", App::SuiNode),
    ("aptos-node", App::AptosNode),
    ("neard", App::Neard),
    ("hl-node", App::HlNode),
    ("hl-visor", App::HlNode),
    ("erpc-worker-agent", App::ErpcWorker),
    ("sshd", App::Sshd),
    ("docker-proxy", App::DockerProxy),
    ("dockerd", App::Dockerd),
    ("containerd", App::Containerd),
    ("nginx", App::Nginx),
    ("caddy", App::Caddy),
    ("haproxy", App::Haproxy),
    ("envoy", App::Envoy),
    ("redis-server", App::Redis),
    ("postgres", App::Postgres),
    ("postmaster", App::Postgres),
    ("mysqld", App::Mysql),
    ("mariadbd", App::Mysql),
    ("mongod", App::Mongod),
    ("node", App::Node),
    ("nodejs", App::Node),
    ("bun", App::Node),
    ("deno", App::Node),
    ("java", App::Java),
    ("grafana", App::Grafana),
    ("grafana-server", App::Grafana),
    ("prometheus", App::Prometheus),
    ("node_exporter", App::NodeExporter),
];

// The kernel keeps the first 15 bytes of a program's name.
const COMM_LEN: usize = 15;

/// The program named `name`, matching a name the kernel cut short.
pub(super) fn app_for(name: &str) -> App {
    let known = PROGRAMS.iter().find(|(program, _)| {
        *program == name
            || (name.len() == COMM_LEN && program.len() > COMM_LEN && program.starts_with(name))
    });
    if let Some(&(_, app)) = known {
        return app;
    }
    if name.starts_with("python") {
        App::Python
    } else if name.starts_with("containerd-shim") {
        App::Containerd
    } else if name.starts_with("monad") {
        App::Monad
    } else {
        App::Other
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    use erpc_api::security_check::App;

    use super::{Budget, app_for, scan};

    fn process(proc: &std::path::Path, pid: u32, exe: Option<&str>, comm: &str, sockets: &[u64]) {
        let dir = proc.join(pid.to_string());
        std::fs::create_dir_all(dir.join("fd")).unwrap_or_else(|e| panic!("{e}"));
        if let Some(exe) = exe {
            symlink(exe, dir.join("exe")).unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(dir.join("comm"), format!("{comm}\n")).unwrap_or_else(|e| panic!("{e}"));
        for (fd, inode) in sockets.iter().enumerate() {
            symlink(
                format!("socket:[{inode}]"),
                dir.join("fd").join(fd.to_string()),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        }
        symlink("/dev/null", dir.join("fd").join("99")).unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn sockets_are_traced_to_their_program() {
        let proc = crate::node::security::fixture("procs");
        process(
            &proc,
            10,
            Some("/opt/agave/bin/agave-validator (deleted)"),
            "agave-validato",
            &[100, 101],
        );
        process(&proc, 20, None, "docker-proxy", &[200]);
        process(&proc, 30, None, "python3.12", &[]);
        process(&proc, 1, None, "systemd", &[300]);
        process(&proc, 40, None, "sshd", &[300]);
        std::fs::create_dir_all(proc.join("self")).unwrap_or_else(|e| panic!("{e}"));
        let found = scan(&proc, Budget::DEFAULT);
        assert!(found.listed && found.complete);
        assert_eq!(found.holders.get(&100), Some(&10));
        assert_eq!(found.holders.get(&101), Some(&10));
        assert_eq!(found.holders.get(&200), Some(&20));
        assert_eq!(found.apps.get(&10), Some(&App::AgaveValidator));
        assert_eq!(found.apps.get(&20), Some(&App::DockerProxy));
        assert_eq!(found.apps.get(&30), Some(&App::Python));
        assert_eq!(found.holders.get(&300), Some(&40));

        let cut = scan(
            &proc,
            Budget {
                entries: 3,
                time: Duration::from_secs(20),
            },
        );
        assert!(!cut.listed && !cut.complete);
        let _ = std::fs::remove_dir_all(&proc);
    }

    #[test]
    fn short_kernel_names_match_the_long_program_names() {
        assert_eq!(app_for("solana-validato"), App::SolanaValidator);
        assert_eq!(app_for("jito-shredstrea"), App::JitoShredstream);
        assert_eq!(app_for("agave-validator"), App::AgaveValidator);
        assert_eq!(app_for("solana-valid"), App::Other);
        assert_eq!(app_for("monad-bft"), App::Monad);
        assert_eq!(app_for("my-trading-bot"), App::Other);
    }
}
