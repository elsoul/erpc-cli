// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Reaching a node's host: the operator's login, the SSH target built from
//! a stored node and that login, the warning when SSH would be admitted
//! from one address alone, and the allow lists a host's firewall takes.
//!
//! Every chain logs in the same way, so this is the one place it is
//! written: a chain says where its node listens ([`Endpoint`]) and passes
//! the operator's [`Login`].

use std::net::Ipv4Addr;
use std::path::PathBuf;

use clap::ArgMatches;
use erpc_ssh::{HostKey, Identity, Target};

use crate::node::common::agent_socket;

/// What a node command says when no key to log in with was given.
pub(crate) const NO_SSH_KEY: &str = "pass --ssh-key <path to the .pub of the key that logs in>";

/// How to log in: the operator's key in its agent.
#[derive(Debug, Clone, Default)]
pub(crate) struct Login {
    /// The `.pub` file of the key that logs in.
    pub(crate) ssh_key: Option<PathBuf>,
    /// The agent's socket.
    pub(crate) ssh_agent: Option<PathBuf>,
}

impl Login {
    /// The login a command's `--ssh-key` and `--ssh-agent` flags give,
    /// where it has them.
    pub(crate) fn from_args(args: &ArgMatches) -> Self {
        let path = |id| args.try_get_one::<PathBuf>(id).ok().flatten().cloned();
        Self {
            ssh_key: path("ssh-key"),
            ssh_agent: path("ssh-agent"),
        }
    }
}

/// Where a node's SSH listens, as its stored record has it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Endpoint<'a> {
    /// Its address.
    pub(crate) address: &'a str,
    /// Its SSH port.
    pub(crate) port: u16,
    /// The user to log in as.
    pub(crate) user: &'a str,
    /// Its pinned host key, as stored.
    pub(crate) host_key: &'a str,
}

/// The target that logs in to `endpoint` with the operator's key, through
/// its agent, and accepts only the pinned host key.
pub(crate) fn target(endpoint: Endpoint<'_>, login: &Login) -> Result<Target, String> {
    // The missing flag is what to fix first, before the stored key is read.
    login.ssh_key.as_ref().ok_or(NO_SSH_KEY)?;
    let host_key = HostKey::parse(endpoint.host_key).map_err(|e| e.to_string())?;
    checked_target(
        endpoint.address,
        endpoint.port,
        endpoint.user,
        host_key,
        login,
    )
}

/// As [`target`], with the host key already in hand. This pins whatever key
/// it is given and checks nothing about it: which key to trust is the
/// caller's to settle (a stored pin it read, or a key the operator accepted
/// by `--fingerprint` or at a prompt) before calling this.
pub(crate) fn checked_target(
    address: &str,
    port: u16,
    user: &str,
    host_key: HostKey,
    login: &Login,
) -> Result<Target, String> {
    let public_key = login.ssh_key.clone().ok_or(NO_SSH_KEY)?;
    Ok(Target {
        host: address.to_owned(),
        port,
        user: user.to_owned(),
        host_key,
        identity: Identity::Agent {
            socket: agent_socket(login.ssh_agent.as_deref())?,
            public_key,
        },
    })
}

/// A warning when SSH would be admitted from erpc's present address,
/// `controller`, alone: if that address changes, nothing can reach the node
/// but its console.
pub(crate) fn lockout_warning(management: &[String], controller: &str) -> Option<String> {
    management.is_empty().then(|| {
        format!(
            "warning    SSH will be admitted only from {controller}, the address erpc connects \
             from now. If it changes, only the provider's console reaches the node: add a \
             stable range with --management-allow"
        )
    })
}

/// Checks an allow list: IPv4 addresses or CIDRs, without duplicates.
/// `open_ok` allows `0.0.0.0/0`, everyone.
pub(crate) fn allow_list(
    what: &str,
    items: &[String],
    open_ok: bool,
) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (addr, prefix) = match item.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (item, None),
        };
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|_| format!("{what}: {item:?} is not an IPv4 address or CIDR"))?;
        let canonical = match prefix {
            None => ip.to_string(),
            Some(p) => {
                let bits: u8 = p
                    .parse()
                    .ok()
                    .filter(|b| *b <= 32)
                    .ok_or_else(|| format!("{what}: {item:?} has no prefix length 0–32"))?;
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                if u32::from(ip) & !mask != 0 {
                    return Err(format!(
                        "{what}: {item} has host bits set; the network is {}/{bits}",
                        Ipv4Addr::from(u32::from(ip) & mask)
                    ));
                }
                if bits == 0 && !open_ok {
                    return Err(format!("{what}: 0.0.0.0/0 would admit everyone"));
                }
                if bits == 32 {
                    ip.to_string()
                } else {
                    format!("{ip}/{bits}")
                }
            }
        };
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use clap::{Arg, Command};
    use erpc_ssh::{HostKey, Identity};

    use super::{Endpoint, Login, NO_SSH_KEY, allow_list, checked_target, lockout_warning, target};

    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/";

    fn endpoint(host_key: &str) -> Endpoint<'_> {
        Endpoint {
            address: "192.0.2.10",
            port: 2222,
            user: "ubuntu",
            host_key,
        }
    }

    fn login(key: Option<&str>) -> Login {
        Login {
            ssh_key: key.map(PathBuf::from),
            ssh_agent: Some(PathBuf::from("/run/agent.sock")),
        }
    }

    #[test]
    fn a_target_is_the_stored_endpoint_and_the_operators_key_in_its_agent() {
        let t = target(endpoint(HOST_KEY), &login(Some("/home/op/.ssh/id.pub"))).expect("target");
        assert_eq!(
            (t.host.as_str(), t.port, t.user.as_str()),
            ("192.0.2.10", 2222, "ubuntu")
        );
        let Identity::Agent { socket, public_key } = t.identity else {
            panic!("not the agent: {:?}", t.identity);
        };
        assert_eq!(t.host_key, HostKey::parse(HOST_KEY).expect("key"));
        assert_eq!(socket, Path::new("/run/agent.sock"));
        assert_eq!(public_key, Path::new("/home/op/.ssh/id.pub"));
    }

    #[test]
    fn no_key_is_asked_for_before_anything_else_is_looked_at() {
        // The host key is not even read: the missing flag is what to fix.
        let e = target(endpoint("not a key"), &login(None)).expect_err("no key");
        assert_eq!(e, NO_SSH_KEY);
    }

    #[test]
    fn a_host_key_that_does_not_parse_is_refused() {
        assert!(target(endpoint("ssh-ed25519 AAAA"), &login(Some("/k.pub"))).is_err());
    }

    #[test]
    fn a_target_given_its_host_key_pins_that_key() {
        let given = HostKey::parse(HOST_KEY).expect("key");
        let t = checked_target(
            "192.0.2.10",
            22,
            "ubuntu",
            given.clone(),
            &login(Some("/k.pub")),
        )
        .expect("target");
        assert_eq!(
            (t.host.as_str(), t.port, t.user.as_str()),
            ("192.0.2.10", 22, "ubuntu")
        );
        assert_eq!(t.host_key, given);
        // Without --ssh-key there is no target, whatever agent is named.
        let e =
            checked_target("192.0.2.10", 22, "ubuntu", given, &login(None)).expect_err("no key");
        assert_eq!(e, NO_SSH_KEY);
    }

    #[test]
    fn a_login_is_read_from_the_flags_a_command_has() {
        let command = || {
            Command::new("x")
                .arg(
                    Arg::new("ssh-key")
                        .long("ssh-key")
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("ssh-agent")
                        .long("ssh-agent")
                        .value_parser(clap::value_parser!(PathBuf)),
                )
        };
        let both = Login::from_args(&command().get_matches_from([
            "x",
            "--ssh-key",
            "/k.pub",
            "--ssh-agent",
            "/a.sock",
        ]));
        assert_eq!(both.ssh_key.as_deref(), Some(Path::new("/k.pub")));
        assert_eq!(both.ssh_agent.as_deref(), Some(Path::new("/a.sock")));
        let none = Login::from_args(&command().get_matches_from(["x"]));
        assert!(none.ssh_key.is_none() && none.ssh_agent.is_none());
        // A command without the flags at all has no login, not an error.
        let bare = Login::from_args(&Command::new("x").get_matches_from(["x"]));
        assert!(bare.ssh_key.is_none() && bare.ssh_agent.is_none());
    }

    #[test]
    fn the_lockout_warning_names_the_address_and_only_when_nothing_else_is_admitted() {
        let warning = lockout_warning(&[], "203.0.113.7").expect("warned");
        assert!(warning.contains("only from 203.0.113.7,"), "{warning}");
        assert!(warning.contains("--management-allow"), "{warning}");
        assert_eq!(
            lockout_warning(&["198.51.100.0/24".to_owned()], "203.0.113.7"),
            None
        );
    }

    #[test]
    fn allow_lists_are_canonical_and_refuse_what_is_not_a_network() {
        let items: Vec<String> = ["198.51.100.0/24", "203.0.113.5", "203.0.113.5/32", " "]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            allow_list("rpc", &items, false).expect("ok"),
            ["198.51.100.0/24", "203.0.113.5"]
        );
        for bad in ["198.51.100.1/24", "300.1.1.1", "10.0.0.0/33", "::1", "x"] {
            assert!(allow_list("rpc", &[bad.to_owned()], true).is_err(), "{bad}");
        }
        assert!(allow_list("ssh", &["0.0.0.0/0".to_owned()], false).is_err());
        assert_eq!(
            allow_list("rpc", &["0.0.0.0/0".to_owned()], true).expect("open"),
            ["0.0.0.0/0"]
        );
    }
}
