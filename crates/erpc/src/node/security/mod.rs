// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the server security check reads on the server it runs on.
//!
//! Every reader takes the filesystem root it reads under, `/` in a real run,
//! so the tests can give it a fixture; nothing a person or a server supplies
//! can choose it. Reading only: no file is written, no program is started,
//! and nothing read verbatim (a path, a command line, a file's contents)
//! goes into the inventory.

// The readers run on Linux only; their tests run everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod firewall;
mod keys;
pub(crate) mod menu;
mod procs;
mod report;
mod secrets;
mod sockets;
mod solana;
mod ssh;
mod system;

use std::path::{Path, PathBuf};

use erpc_api::security_check::{
    App, Coverage, Inventory, Listener, Listeners, Owner, Proto, SolanaApp, SolanaNodes, Tristate,
};

pub(crate) use keys::Places;

/// The filesystem the check reads: `/` on a server.
pub(crate) struct Host {
    root: PathBuf,
    budget: procs::Budget,
    key_budget: procs::Budget,
}

impl Host {
    /// The filesystem of the machine this runs on.
    #[cfg(target_os = "linux")]
    pub(crate) fn this_machine() -> Self {
        Self {
            root: PathBuf::from("/"),
            budget: procs::Budget::DEFAULT,
            key_budget: keys::BUDGET,
        }
    }

    fn proc(&self) -> PathBuf {
        self.root.join("proc")
    }
}

/// The inventory of the machine under `host`, and where the keys it counts
/// were found, which stays on this machine.
pub(crate) fn collect(host: &Host) -> (Inventory, Places) {
    let scan = procs::scan(&host.proc(), host.budget);
    let (solana, identities) = solana_nodes(host, &scan);
    let (keys, places) = keys::search(&host.root, host.key_budget, &scan, &identities);
    let inventory = Inventory {
        privileged: system::privileged(&host.proc()),
        os: system::os(&host.root),
        listeners: listeners(host, &scan),
        solana,
        ssh: ssh::read(&host.root),
        firewall: firewall::read(&host.root),
        packages: system::packages(&host.root),
        keys,
    };
    (inventory, places)
}

fn listeners(host: &Host, scan: &procs::Scan) -> Listeners {
    use sockets::Family;

    let net = host.proc().join("net");
    let mut sockets = Vec::new();
    let mut read = 0;
    let mut partial = !scan.complete;
    let mut no_ipv6 = 0;
    for (file, proto, family) in [
        ("tcp", Proto::Tcp, Family::V4),
        ("tcp6", Proto::Tcp, Family::V6),
        ("udp", Proto::Udp, Family::V4),
        ("udp6", Proto::Udp, Family::V6),
    ] {
        match std::fs::File::open(net.join(file)) {
            Ok(table) => match sockets::read_table(table, proto, family) {
                Some(found) => {
                    read += 1;
                    sockets.extend(found);
                }
                None => partial = true,
            },
            // A kernel without IPv6 has no IPv6 sockets to list.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && matches!(family, Family::V6) => {
                no_ipv6 += 1;
            }
            Err(_) => partial = true,
        }
    }
    if read == 0 {
        return Listeners::unreadable();
    }
    partial |= read + no_ipv6 < 4;
    let mut items: Vec<Listener> = sockets
        .into_iter()
        .map(|socket| {
            let app = scan
                .holders
                .get(&socket.inode)
                .and_then(|pid| scan.apps.get(pid))
                .copied()
                .unwrap_or(App::Unknown);
            Listener {
                proto: socket.proto,
                port: socket.port,
                bind: socket.bind,
                app,
                owner: owner(socket.uid),
                docker: app == App::DockerProxy,
            }
        })
        .collect();
    items.sort_by_key(|l| (l.proto, l.port, l.bind, l.app));
    items.dedup();
    Listeners::new(
        if partial {
            Coverage::Partial
        } else {
            Coverage::Complete
        },
        items,
    )
}

// Debian and Ubuntu give people's accounts ids from 1000; the overflow id
// belongs to no one.
fn owner(uid: u32) -> Owner {
    match uid {
        0 => Owner::Root,
        1000..65534 => Owner::User,
        _ => Owner::Service,
    }
}

const CMDLINE_LIMIT: u64 = 256 * 1024;

/// The validators running, and the identity files they were given.
fn solana_nodes(host: &Host, scan: &procs::Scan) -> (SolanaNodes, keys::Identities) {
    let mut pids: Vec<(u32, SolanaApp)> = scan
        .apps
        .iter()
        .filter_map(|(&pid, &app)| {
            Some((
                pid,
                match app {
                    App::AgaveValidator => SolanaApp::AgaveValidator,
                    App::SolanaValidator => SolanaApp::SolanaValidator,
                    App::Firedancer => SolanaApp::Firedancer,
                    _ => return None,
                },
            ))
        })
        .collect();
    if pids.is_empty() {
        let nodes = SolanaNodes::new(
            if scan.listed {
                Coverage::Absent
            } else {
                Coverage::Partial
            },
            Vec::new(),
        );
        return (nodes, keys::Identities::default());
    }
    pids.sort_unstable();
    let mut partial = !scan.listed;
    let mut nodes = Vec::new();
    let mut identities = keys::Identities::default();
    for (pid, app) in pids {
        // Firedancer reads its settings from a file this check does not
        // parse; the listeners still show what it opened.
        if app == SolanaApp::Firedancer {
            partial = true;
            identities.undetermined = true;
            continue;
        }
        let dir = host.proc().join(pid.to_string());
        let Some(cmdline) = read_bytes(&dir.join("cmdline"), CMDLINE_LIMIT) else {
            partial = true;
            identities.undetermined = true;
            continue;
        };
        let args = solana::arguments(&cmdline);
        let cwd = std::fs::read_link(dir.join("cwd")).ok();
        let node = solana::node(app, &args, |path| {
            let (on_disk, file) = identity_file(&host.root, cwd.as_deref(), path);
            identities.given.extend(file.map(|file| keys::Given {
                process: dir.clone(),
                file,
            }));
            on_disk
        });
        identities.undetermined |= node.identity_on_disk == Tristate::Unknown;
        nodes.push(node);
    }
    let nodes = SolanaNodes::new(
        if partial {
            Coverage::Partial
        } else {
            Coverage::Complete
        },
        nodes,
    );
    (nodes, identities)
}

fn read_bytes(path: &Path, limit: u64) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(limit)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

/// Whether the identity keypair at `path`, as the validator was given it,
/// is a file, and that file under the root when it is. A relative path is
/// the validator's working directory's.
fn identity_file(root: &Path, cwd: Option<&Path>, path: &str) -> (Tristate, Option<PathBuf>) {
    let path = Path::new(path);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match cwd {
            Some(cwd) => cwd.join(path),
            None => return (Tristate::Unknown, None),
        }
    };
    let inside = absolute.strip_prefix("/").unwrap_or(&absolute);
    let file = root.join(inside);
    match std::fs::metadata(&file) {
        Ok(meta) if meta.is_file() => (Tristate::Yes, Some(file)),
        Ok(_) => (Tristate::No, None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Tristate::No, None),
        Err(_) => (Tristate::Unknown, None),
    }
}

#[cfg(test)]
pub(super) fn fixture(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("erpc-security-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    if let Err(e) = std::fs::create_dir_all(&root) {
        panic!("{e}");
    }
    root
}

#[cfg(all(test, unix))]
mod tests {
    use std::net::Ipv4Addr;
    use std::os::unix::fs::symlink;

    use erpc_api::security_check::{
        App, Bind, Coverage, Inventory, KeyKind, KeyRole, Owner, Proto, Tristate,
    };

    use super::sockets::tests::{TCP4, TCP6, UDP4, row, v4};
    use super::{Host, collect, procs};

    fn host(root: &std::path::Path) -> Host {
        Host {
            root: root.to_path_buf(),
            budget: procs::Budget::DEFAULT,
            key_budget: super::keys::BUDGET,
        }
    }

    /// The request that would start a check of this inventory, as text.
    fn request(inventory: &Inventory) -> String {
        let server =
            serde_json::from_value(serde_json::json!("vps:1")).unwrap_or_else(|e| panic!("{e}"));
        let body = erpc_api::security_check::request_body(&server, inventory)
            .unwrap_or_else(|e| panic!("{e}"));
        String::from_utf8(body).unwrap_or_default()
    }

    fn write(path: &std::path::Path, text: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(path, text).unwrap_or_else(|e| panic!("{e}"));
    }

    /// A validator host: RPC on 18899 with the full API, gossip on UDP 8001,
    /// a Docker-published 2375 and a loopback database, traced as root.
    fn validator_host(root: &std::path::Path) {
        let proc = root.join("proc");
        write(
            &proc.join("net/tcp"),
            &format!(
                "{TCP4}{}{}{}",
                row(&v4(Ipv4Addr::UNSPECIFIED), 18899, 0x0a, 1001, 501),
                row(&v4(Ipv4Addr::UNSPECIFIED), 2375, 0x0a, 0, 502),
                row(&v4(Ipv4Addr::LOCALHOST), 5432, 0x0a, 0, 503),
            ),
        );
        write(&proc.join("net/tcp6"), TCP6);
        write(
            &proc.join("net/udp"),
            &format!(
                "{UDP4}{}",
                row(&v4(Ipv4Addr::UNSPECIFIED), 8001, 0x07, 1001, 504)
            ),
        );
        let validator = proc.join("41");
        write(&validator.join("comm"), "agave-validator\n");
        write(
            &validator.join("cmdline"),
            &[
                "/opt/agave/bin/agave-validator",
                "--identity",
                "keys/validator-keypair.json",
                "--rpc-port",
                "18899",
                "--full-rpc-api",
                "",
            ]
            .join("\0"),
        );
        symlink("/home/sol", validator.join("cwd")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir_all(validator.join("fd")).unwrap_or_else(|e| panic!("{e}"));
        symlink("socket:[501]", validator.join("fd/10")).unwrap_or_else(|e| panic!("{e}"));
        symlink("socket:[504]", validator.join("fd/11")).unwrap_or_else(|e| panic!("{e}"));
        let proxy = proc.join("77");
        write(&proxy.join("comm"), "docker-proxy\n");
        std::fs::create_dir_all(proxy.join("fd")).unwrap_or_else(|e| panic!("{e}"));
        symlink("socket:[502]", proxy.join("fd/3")).unwrap_or_else(|e| panic!("{e}"));
        write(&proc.join("self/status"), "Uid:\t0\t0\t0\t0\n");
        write(&root.join("home/sol/keys/validator-keypair.json"), "[]");
    }

    #[test]
    fn a_validator_host_is_described_without_its_paths() {
        let root = super::fixture("collect");
        validator_host(&root);
        let (inventory, _) = collect(&host(&root));
        assert!(inventory.privileged);
        assert_eq!(inventory.listeners.coverage(), Coverage::Complete);
        let listeners: Vec<_> = inventory
            .listeners
            .items()
            .iter()
            .map(|l| (l.proto, l.port.get(), l.bind, l.app, l.owner, l.docker))
            .collect();
        assert_eq!(
            listeners,
            [
                (
                    Proto::Tcp,
                    2375,
                    Bind::Wildcard,
                    App::DockerProxy,
                    Owner::Root,
                    true
                ),
                (
                    Proto::Tcp,
                    5432,
                    Bind::Loopback,
                    App::Unknown,
                    Owner::Root,
                    false
                ),
                (
                    Proto::Tcp,
                    18899,
                    Bind::Wildcard,
                    App::AgaveValidator,
                    Owner::User,
                    false
                ),
                (
                    Proto::Udp,
                    8001,
                    Bind::Wildcard,
                    App::AgaveValidator,
                    Owner::User,
                    false
                ),
            ]
        );
        assert_eq!(inventory.solana.coverage(), Coverage::Complete);
        let node = &inventory.solana.items()[0];
        assert_eq!(node.rpc_port.map(std::num::NonZeroU16::get), Some(18899));
        assert_eq!(node.rpc_bind, Some(Bind::Wildcard));
        assert!(node.full_rpc_api);
        assert_eq!(node.identity_on_disk, Tristate::Yes);

        let text = request(&inventory);
        for local in ["/home/sol", "validator-keypair", "/opt/agave", "keys/"] {
            assert!(!text.contains(local), "{local} reached the request");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "reads this machine's own tables; run by hand on a Linux host"]
    fn this_machine_can_be_read() {
        let (inventory, _) = collect(&Host::this_machine());
        assert_ne!(inventory.listeners.coverage(), Coverage::Unreadable);
        assert_ne!(inventory.os.coverage, Coverage::Unreadable);
        let body = erpc_api::security_check::request_body(
            &serde_json::from_value(serde_json::json!("vps:1")).unwrap_or_else(|e| panic!("{e}")),
            &inventory,
        );
        assert!(body.is_ok());
    }

    #[test]
    fn missing_tables_and_hidden_processes_make_the_view_partial() {
        let root = super::fixture("partial");
        let host = host(&root);
        let (empty, _) = collect(&host);
        assert_eq!(empty.listeners.coverage(), Coverage::Unreadable);
        assert_eq!(empty.keys.coverage(), Coverage::Unreadable);
        assert!(!empty.privileged);

        write(&root.join("proc/net/tcp"), TCP4);
        write(&root.join("proc/net/udp"), UDP4);
        let hidden = root.join("proc/90");
        write(&hidden.join("comm"), "sshd\n");
        write(&hidden.join("fd"), "not a directory");
        let (partial, _) = collect(&host);
        assert_eq!(partial.listeners.coverage(), Coverage::Partial);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_host_full_of_keys_sends_none_of_their_bytes_or_paths() {
        let keys = super::keys::tests::key_host("no-key-leaves");
        let (inventory, places) = collect(&host(&keys.root));
        let groups = inventory.keys.items();
        assert_eq!(groups.len(), 11);
        // The validator in the fixture's /proc was given this identity.
        assert_eq!(
            (groups[0].kind, groups[0].role),
            (KeyKind::SolanaKeypair, KeyRole::ValidatorIdentity)
        );
        assert!(places.of(0).is_some_and(|shown| !shown.paths.is_empty()));

        let text = request(&inventory);
        for secret in &keys.secrets {
            assert!(
                !text.contains(secret.as_str()),
                "a secret reached the request"
            );
        }
        let root = keys.root.to_string_lossy();
        for local in [
            root.as_ref(),
            "/home/",
            "/root/",
            "/proc/",
            "/srv/",
            "/etc/",
            "/opt/",
            "/tmp/",
            "/var/",
            "validator-keypair",
            "deployer",
            "seed.txt",
            "keystore.json",
            ".env",
            ".bash_history",
            "fish_history",
            "_data",
        ] {
            assert!(!text.contains(local), "{local} reached the request");
        }
        assert!(!format!("{inventory:?}").contains(root.as_ref()));
        let _ = std::fs::remove_dir_all(&keys.root);
    }

    #[test]
    fn a_validator_whose_identity_cannot_be_told_leaves_the_keys_partial() {
        let root = super::fixture("firedancer");
        write(&root.join("etc/hostname"), "node\n");
        write(&root.join("proc/50/comm"), "fdctl\n");
        let (inventory, _) = collect(&host(&root));
        assert_eq!(inventory.keys.coverage(), Coverage::Partial);
        let _ = std::fs::remove_dir_all(&root);
    }
}
