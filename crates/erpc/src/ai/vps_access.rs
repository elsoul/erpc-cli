// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Logging in to the user's ERPC VPS for `erpc ai` ([`erpc_ai::servers`]),
//! and to a server kept in the ERPC account for `erpc worker deploy`
//! ([`crate::worker::first_login`]). A machine's pin is known by its host
//! key, and carries the account's id of the server beside any VPS id.
//!
//! The first login uses the password ERPC set, once, to put the user's key
//! in place; then a key login must work before password logins are turned
//! off, and a password login must then be refused before it counts as done.
//! The host key seen at that first login is pinned in `vps_hosts.json`
//! beside the config, as `known_hosts` pins it for OpenSSH, and every later
//! connection checks it. The pin is written as soon as the key gets in,
//! so a step that fails after it is taken up again from the key: the
//! password may already be refused by then.
//!
//! The key that logs in is the user's own: `ssh_key` in the config (its
//! `.pub`), else `~/.ssh/id_ed25519.pub`. Its private half is used from
//! the agent that holds it (1Password's, then `SSH_AUTH_SOCK`'s), else
//! from the file beside it.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::worker::first_login::{Fut as LoginFut, Logins, NotReady};
use erpc_ai::servers::{Prepared, Secured, Servers};
use erpc_ssh::first_login::{self, PasswordLogin};
use erpc_ssh::vps::AllowList;
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The SSH port of an ERPC VPS.
const PORT: u16 = 22;

/// A VPS erpc logged in to with the user's key, by its address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pin {
    host_key: String,
    user: String,
    port: u16,
    /// The VPS it is: an ended VPS's address goes to the next one. 0 for
    /// a server kept in the ERPC account, which `account_server` names.
    #[serde(default)]
    vps_id: i64,
    /// The ERPC account's id of the server, for one kept in the account:
    /// the account names its servers by ids of its own, never by product
    /// number. One machine reached both ways keeps both ids on one pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_server: Option<String>,
    /// Whether password logins were turned off and checked refused. Until
    /// then the key gets in but the work is unfinished, and the next
    /// `secure` takes it up from the key.
    #[serde(default)]
    key_only: bool,
}

fn pins_path() -> Result<PathBuf, String> {
    crate::account::session::beside_config("vps_hosts.json")
}

/// The pins; none when there is no file yet. A file that cannot be read
/// is an error, never an empty list: writing one pin over it would lose
/// every other.
fn load_pins(path: &Path) -> Result<BTreeMap<String, Pin>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            format!(
                "{} is unreadable ({e}); fix it or move it away, then ask again",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!("could not read {}: {e}", path.display())),
    }
}

/// Adds `pin` for `ip`, written whole to a new file and moved over the old.
fn save_pin(path: &Path, ip: &str, pin: Pin) -> Result<(), String> {
    // Read and written under the lock: two consoles securing two servers
    // at once keep both pins.
    erpc_core::private_file::locked(path, || {
        let mut pins = load_pins(path)?;
        pins.insert(ip.to_owned(), pin);
        let text = serde_json::to_vec_pretty(&pins).map_err(|e| e.to_string())?;
        erpc_core::private_file::write(path, &text)
    })
}

/// The `.pub` of the key erpc logs in with: the `ssh_key` setting in the
/// config at `config`, else `~/.ssh/id_ed25519.pub` under `home`; none when
/// that file is not there. A key set but not there is never passed over for
/// the default. `erpc worker`, `erpc ai` and the Security Check all use it.
fn public_key(config: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
    config
        .and_then(|path| crate::account::config::get(path, "ssh_key").ok().flatten())
        .map(PathBuf::from)
        .or_else(|| home.map(|h| h.join(".ssh/id_ed25519.pub")))
        .filter(|p| p.is_file())
}

/// This machine's config and home, for [`public_key`].
fn key_places() -> (Option<PathBuf>, Option<PathBuf>) {
    (
        crate::account::session::config_path().ok(),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

/// The user's key: its `.pub` and how its private half is reached.
pub(crate) fn login_key() -> Result<(PathBuf, Identity), String> {
    let (config, home) = key_places();
    let public = public_key(config.as_deref(), home.as_deref()).ok_or(
        "no SSH key to log in with: make one (ssh-keygen -t ed25519) or point erpc at yours \
         with `erpc config set ssh_key /path/to/key.pub`",
    )?;
    let line = crate::node::common::public_key_line(&public)?;
    // An agent counts only when it holds this key: 1Password's runs for
    // many people whose key is a plain file.
    let agents = home
        .iter()
        .flat_map(|h| {
            [
                h.join("Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"),
                h.join(".1password/agent.sock"),
            ]
        })
        .chain(std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from))
        .filter(|p| p.exists());
    let private = public.with_extension("");
    let identity =
        if let Some(socket) = agents.into_iter().find(|s| erpc_ssh::agent_holds(s, &line)) {
            Identity::Agent {
                socket,
                public_key: public.clone(),
            }
        } else if public.extension().is_some_and(|e| e == "pub") && private.is_file() {
            Identity::File(private)
        } else {
            return Err(format!(
                "the private half of {} is in no agent and not beside it",
                public.display()
            ));
        };
    Ok((public, identity))
}

/// `key=value` lines' value for `key`.
fn value(stdout: &[u8], key: &str) -> Option<String> {
    String::from_utf8_lossy(stdout).lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|v| v.trim().to_owned())
    })
}

fn target(ip: &str, pin: &Pin, identity: &Identity) -> Result<Target, String> {
    Ok(Target {
        host: ip.to_owned(),
        port: pin.port,
        user: pin.user.clone(),
        host_key: HostKey::parse(&pin.host_key).map_err(|e| e.to_string())?,
        identity: identity.clone(),
    })
}

/// The pinned SSH target of a VPS erpc made key-only, for `erpc worker
/// deploy`: its login user, port and host key, with the user's key.
pub(crate) fn pinned_target(ip: &str) -> Result<Target, String> {
    let pin = load_pins(&pins_path()?)?
        .remove(ip)
        .filter(|p| p.key_only)
        .ok_or_else(|| format!("erpc has not made {ip} key-only yet"))?;
    let (_, identity) = login_key()?;
    target(ip, &pin, &identity)
}

/// How the Security Check logs in to a server, but for its address and
/// the key that logs in: the host key it checks, and the login and port.
#[cfg(feature = "security-check-pilot")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostLogin {
    pub(crate) host_key: HostKey,
    pub(crate) user: String,
    pub(crate) port: u16,
}

#[cfg(feature = "security-check-pilot")]
impl HostLogin {
    /// The target at `host`, logging in with `identity`.
    pub(crate) fn target(self, host: String, identity: Identity) -> Target {
        Target {
            host,
            port: self.port,
            user: self.user,
            host_key: self.host_key,
            identity,
        }
    }
}

/// The login erpc pinned for VPS `id` at `ip` once it made it key-only, read
/// from this machine's pins: never a pin of the address alone.
#[cfg(feature = "security-check-pilot")]
pub(crate) fn security_pin(ip: &str, id: u64) -> Option<HostLogin> {
    security_pin_at(&pins_path().ok()?, ip, id)
}

/// [`security_pin`], from the pins at `path`.
#[cfg(feature = "security-check-pilot")]
pub(crate) fn security_pin_at(path: &Path, ip: &str, id: u64) -> Option<HostLogin> {
    let pin = load_pins(path)
        .ok()?
        .remove(ip)
        .filter(|pin| pin.key_only && u64::try_from(pin.vps_id).ok() == Some(id))?;
    Some(HostLogin {
        host_key: HostKey::parse(&pin.host_key).ok()?,
        user: pin.user,
        port: pin.port,
    })
}

/// The key the Security Check logs in with: [`login_key`]'s `.pub` (the
/// `ssh_key` setting, else `~/.ssh/id_ed25519.pub`), with its private half
/// in the `SSH_AUTH_SOCK` agent or beside it.
#[cfg(feature = "security-check-pilot")]
pub(crate) fn security_identity() -> Option<Identity> {
    let (config, home) = key_places();
    security_identity_from(
        config.as_deref(),
        home.as_deref(),
        std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from),
    )
}

/// [`security_identity`], from the config at `config`, the home `home` and
/// the agent at `agent`. The `.pub` must be an absolute path to one public
/// key line.
#[cfg(feature = "security-check-pilot")]
pub(crate) fn security_identity_from(
    config: Option<&Path>,
    home: Option<&Path>,
    agent: Option<PathBuf>,
) -> Option<Identity> {
    let public = public_key(config, home)?;
    if !public.is_absolute() || public.extension()?.to_str()? != "pub" {
        return None;
    }
    let line = crate::node::common::public_key_line(&public).ok()?;
    if let Some(socket) = agent
        && socket.is_absolute()
        && erpc_ssh::agent_holds(&socket, &line)
    {
        return Some(Identity::Agent {
            socket,
            public_key: public,
        });
    }
    Some(Identity::File(public.with_extension("")))
}

/// A key session to a VPS erpc pinned.
fn session(ip: &str, identity: &Identity) -> Result<Session, String> {
    let pin = load_pins(&pins_path()?)?
        .remove(ip)
        .ok_or_else(|| format!("erpc has not logged in to {ip}; secure it first"))?;
    Session::open(&target(ip, &pin, identity)?).map_err(|e| e.to_string())
}

/// A key session that has logged in, and the address the server saw it
/// come from. Opening a session only checks its settings; running a
/// command is what proves the key gets in.
fn key_login(
    ip: &str,
    pin: &Pin,
    identity: &Identity,
) -> Result<(Session, Option<String>), String> {
    let session = Session::open(&target(ip, pin, identity)?).map_err(|e| e.to_string())?;
    let out = session
        .run(&RemoteCommand::VpsController, None)
        .map_err(|e| e.to_string())?;
    let controller = value(&out.stdout, "controller").filter(|c| !c.is_empty());
    Ok((session, controller))
}

const KEY_GONE: &str = "erpc's key no longer gets in, and password logins are already off; \
     check the key erpc uses (`erpc config get ssh_key`) and your SSH agent";

/// The first login, step by step; blocking. Taken up from the key when
/// an earlier attempt on the same VPS got that far.
/// `password` is ERPC's login password, or why there is none: taken up
/// from the key, the work needs it only for a `sudo` that asks.
/// Why the key just added does not get in, and what to do.
fn key_does_not_get_in(e: &impl std::fmt::Display, public: &Path) -> String {
    format!(
        "your key was added but does not get in ({e}); password logins are still on. \
         Check that your SSH agent or the key file beside {} can be used: a key in \
         1Password signs only while 1Password is unlocked and the request it shows is \
         allowed. Running the same command again carries on from here",
        public.display()
    )
}

fn secure(
    prepared: &Prepared,
    account_server: Option<&str>,
    password: Result<&str, &str>,
) -> Result<Secured, String> {
    let path = pins_path()?;
    let (public, identity) = login_key()?;
    let host_key = HostKey::parse(&prepared.host_key).map_err(|e| e.to_string())?;
    // Made only when a password is to be sent: work taken up over the key
    // needs none.
    let by_password = || {
        PasswordLogin::open(
            &prepared.ip,
            PORT,
            &prepared.user,
            &host_key,
            &crate::account::session::state_dir()?,
        )
        .map_err(|e| e.to_string())
    };
    let old = load_pins(&path)?.get(&prepared.ip).cloned();
    let mut pin = pin_for(prepared, account_server, old.as_ref());
    let resumed = old
        .as_ref()
        .is_some_and(|old| same_machine(old, &pin.host_key) && old.user == pin.user);
    // Password logins are off only when the earlier attempt finished.
    let was_key_only = resumed && old.as_ref().is_some_and(|old| old.key_only);
    // Taken up from the key only while the key still gets in: the key
    // erpc logs in with may have changed since.
    let earlier = if resumed {
        key_login(&prepared.ip, &pin, &identity).ok()
    } else {
        None
    };
    let (by_key, controller) = if let Some(found) = earlier {
        found
    } else {
        let key_line = crate::node::common::public_key_line(&public)?;
        // Taken up, the key was the way in: that it fails is the news, not
        // a password that is no longer needed.
        let password = password.map_err(|why| {
            if was_key_only {
                KEY_GONE.to_owned()
            } else {
                why.to_owned()
            }
        })?;
        by_password()?
            .run(
                &RemoteCommand::VpsAuthorizeKey,
                password,
                Some(format!("{key_line}\n").as_bytes()),
            )
            .map_err(|e| match (first_login::refused(&e), resumed) {
                (true, false) => {
                    "the server refused ERPC's password; nothing was changed".to_owned()
                }
                (true, true) => KEY_GONE.to_owned(),
                (false, _) => format!("the first login failed: {e}"),
            })?;
        // The key must get in before passwords are turned off.
        key_login(&prepared.ip, &pin, &identity).map_err(|e| key_does_not_get_in(&e, &public))?
    };
    // The key gets in: it is the way back in from here, so it is pinned
    // before anything else changes.
    save_pin(&path, &prepared.ip, pin.clone())?;
    let sudo_password = password.unwrap_or_default();
    let mut stdin = Zeroizing::new(Vec::with_capacity(sudo_password.len() + 1));
    stdin.extend_from_slice(sudo_password.as_bytes());
    stdin.push(b'\n');
    let hardened = by_key
        .run(&RemoteCommand::VpsHarden, Some(&stdin))
        .map_err(|e| {
            format!(
                "your key gets in, but turning password logins off failed: {e}. What sshd \
                 refused is taken back on the server; if the connection broke part way, asking \
                 again takes it up from here"
            )
        })?;
    for key in ["password_authentication", "kbd_interactive_authentication"] {
        let now = value(&hardened.stdout, key).unwrap_or_default();
        if now != "no" {
            return Err(format!(
                "sshd still reports {key} {now:?} after the change; it is not key-only"
            ));
        }
    }
    // With no password left to try (ERPC removed it), what sshd reports
    // above is the check.
    if let Ok(password) = password {
        match by_password()?.run(&RemoteCommand::Uname, password, None) {
            Err(e) if first_login::refused(&e) => {}
            Ok(_) => return Err("a password login still got in after the change".to_owned()),
            Err(e) => {
                return Err(format!(
                    "could not check that passwords are refused: {e}; asking again checks once \
                     more"
                ));
            }
        }
    }
    pin.key_only = true;
    save_pin(&path, &prepared.ip, pin)?;
    Ok(Secured {
        controller,
        sudo_needed_password: value(&hardened.stdout, "sudo_was").as_deref() == Some("password"),
    })
}

/// Applies the allow list, then keeps it from a fresh connection; blocking.
fn allow(ip: &str, addresses: Vec<IpAddr>) -> Result<(), String> {
    let list = AllowList::new(addresses, PORT)?;
    let (_, identity) = login_key()?;
    session(ip, &identity)?
        .run(&RemoteCommand::VpsAllowSsh(list), None)
        .map_err(|e| {
            // The table may have been loaded before the connection went:
            // the rollback it armed undoes it either way.
            format!(
                "applying the allow list did not finish ({e}). It may be in force for now; if so, \
                 the server puts the previous one back by itself within {} s. Wait that long \
                 before asking again",
                erpc_ssh::vps::ROLLBACK_SECONDS
            )
        })?;
    // A new connection getting through is the proof it lets the user in;
    // without it the server puts the old table back by itself.
    let kept = session(ip, &identity)?
        .run(&RemoteCommand::VpsConfirmAllow, None)
        .map_err(|e| {
            format!(
                "erpc could not get back in through the new allow list ({e}); the server puts \
                 the previous one back within {} s",
                erpc_ssh::vps::ROLLBACK_SECONDS
            )
        })?;
    match value(&kept.stdout, "firewall").as_deref() {
        Some("confirmed") => Ok(()),
        Some("rolled_back") => Err(format!(
            "erpc got back in only after the {} s safety window, so the server had already put \
             the previous allow list back; nothing changed. Ask again to retry",
            erpc_ssh::vps::ROLLBACK_SECONDS
        )),
        other => Err(format!("the allow list was not kept ({other:?})")),
    }
}

/// Runs `work` off the async thread, so the console keeps drawing.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| format!("the SSH work stopped: {e}"))?
}

/// The SSH side of `erpc ai`'s server tools.
pub(crate) struct SshServers;

type Fut<'a, T> = core::pin::Pin<Box<dyn core::future::Future<Output = Result<T, String>> + 'a>>;

impl Servers for SshServers {
    fn secured(&self, vps_id: i64, ip: &str) -> bool {
        pins_path().is_ok_and(|path| {
            load_pins(&path)
                .ok()
                .and_then(|pins| pins.get(ip).cloned())
                .is_some_and(|pin| pin.key_only && pin.vps_id == vps_id)
        })
    }

    fn prepare<'a>(&'a self, vps_id: i64, ip: &'a str, user: &'a str) -> Fut<'a, Prepared> {
        let (ip, user) = (ip.to_owned(), user.to_owned());
        Box::pin(blocking(move || {
            let (public, _) = login_key()?;
            let line = crate::node::common::public_key_line(&public)?;
            let kind = line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            let offered = erpc_ssh::keyscan(&ip, PORT).map_err(|e| e.to_string())?;
            // An earlier attempt on this VPS pinned its host key: a different
            // one now is a reason to stop, never to send the password to it.
            // A pin from before VPS ids were kept (0) could be this VPS's,
            // so it is held to its key too.
            let pins = load_pins(&pins_path()?)?;
            let earlier = vps_pin(&pins, &ip, vps_id);
            if let Some(old) = earlier
                && old.host_key != offered.to_openssh()
            {
                let was = HostKey::parse(&old.host_key)
                    .map_or_else(|_| old.host_key.clone(), |k| k.fingerprint());
                return Err(format!(
                    "{ip} now offers host key {} where erpc pinned {was} at its earlier login. \
                     Someone may be in between; nothing was sent. If the VPS was rebuilt, remove \
                     its entry from {} and ask again",
                    offered.fingerprint(),
                    pins_path()?.display()
                ));
            }
            let resumable = resumable(&pins, &ip, &offered.to_openssh(), Some(&user));
            Ok(Prepared {
                resumable,
                vps_id,
                fingerprint: offered.fingerprint(),
                host_key: offered.to_openssh(),
                login_key: format!("{} ({kind})", public.display()),
                ip,
                user,
            })
        }))
    }

    fn secure<'a>(
        &'a self,
        prepared: &'a Prepared,
        password: Result<&'a SecretString, &'a str>,
    ) -> Fut<'a, Secured> {
        let prepared = prepared.clone();
        let password = password
            .map(|p| Zeroizing::new(p.expose_secret().to_owned()))
            .map_err(ToOwned::to_owned);
        Box::pin(blocking(move || {
            secure(
                &prepared,
                None,
                password
                    .as_ref()
                    .map(|p| p.as_str())
                    .map_err(String::as_str),
            )
        }))
    }

    fn controller<'a>(&'a self, ip: &'a str) -> Fut<'a, String> {
        let ip = ip.to_owned();
        Box::pin(blocking(move || {
            let (_, identity) = login_key()?;
            let out = session(&ip, &identity)?
                .run(&RemoteCommand::VpsController, None)
                .map_err(|e| e.to_string())?;
            value(&out.stdout, "controller")
                .filter(|c| !c.is_empty())
                .ok_or_else(|| "the server did not say where erpc connects from".to_owned())
        }))
    }

    fn allow_ssh<'a>(&'a self, ip: &'a str, addresses: Vec<IpAddr>) -> Fut<'a, ()> {
        let ip = ip.to_owned();
        Box::pin(blocking(move || allow(&ip, addresses)))
    }

    fn rollback_seconds(&self) -> u32 {
        erpc_ssh::vps::ROLLBACK_SECONDS
    }

    fn open_ssh<'a>(&'a self, ip: &'a str) -> Fut<'a, ()> {
        let ip = ip.to_owned();
        Box::pin(blocking(move || {
            let (_, identity) = login_key()?;
            session(&ip, &identity)?
                .run(&RemoteCommand::VpsOpenSsh, None)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }))
    }
}

/// The pin VPS `vps_id`'s host key at `ip` is held to: its own, or one
/// with no VPS id (written before VPS ids were kept, or for a server kept
/// in the ERPC account), which may be its: the address alone cannot tell.
/// Another VPS's pin is not: an ended VPS's address goes to the next one.
fn vps_pin<'a>(pins: &'a BTreeMap<String, Pin>, ip: &str, vps_id: i64) -> Option<&'a Pin> {
    pins.get(ip)
        .filter(|pin| pin.vps_id == vps_id || pin.vps_id == 0)
}

/// The pin `secure` writes for `prepared`, as `account_server` when it is a
/// server kept in the ERPC account, keeping what `old`, the same machine's
/// pin, knew of it the other way.
fn pin_for(prepared: &Prepared, account_server: Option<&str>, old: Option<&Pin>) -> Pin {
    merged(
        Pin {
            host_key: prepared.host_key.clone(),
            user: prepared.user.clone(),
            port: PORT,
            vps_id: prepared.vps_id,
            account_server: account_server.map(ToOwned::to_owned),
            key_only: false,
        },
        old,
    )
}

/// The pin of the server the ERPC account names `server`, at `ip`: never
/// one written only for a VPS, nor one written before VPS ids were kept.
#[cfg(test)]
fn account_pin<'a>(pins: &'a BTreeMap<String, Pin>, ip: &str, server: &str) -> Option<&'a Pin> {
    pins.get(ip)
        .filter(|pin| pin.account_server.as_deref() == Some(server))
}

/// Whether `old`, pinned at an address, is the machine that offers
/// `host_key` there now: a host key is the machine's own, and an address
/// handed to another machine comes with another. One machine may be
/// reached two ways, as an ERPC VPS (`erpc ai`) and as a server kept in the
/// ERPC account (`erpc worker deploy`), and its one pin serves both.
fn same_machine(old: &Pin, host_key: &str) -> bool {
    old.host_key == host_key
}

/// `pin`, with what `old`, the same machine's pin, knew of it the other
/// way: its VPS id, or the account's id of it. Neither way's pin drops the
/// other's.
fn merged(mut pin: Pin, old: Option<&Pin>) -> Pin {
    if let Some(old) = old.filter(|old| same_machine(old, &pin.host_key)) {
        if pin.vps_id == 0 {
            pin.vps_id = old.vps_id;
        }
        if pin.account_server.is_none() {
            pin.account_server.clone_from(&old.account_server);
        }
    }
    pin
}

/// Whether the first login of the machine offering `host_key` at `ip` can
/// be taken up from the key, as `user` when it is known: an earlier
/// attempt on that machine pinned it, whichever way it was reached.
fn resumable(pins: &BTreeMap<String, Pin>, ip: &str, host_key: &str, user: Option<&str>) -> bool {
    pins.get(ip)
        .is_some_and(|old| same_machine(old, host_key) && user.is_none_or(|u| old.user == u))
}

/// The host key and login name pinned for the machine offering `host_key`
/// at `ip`, when erpc made it key-only, whichever way it was reached.
fn key_only_at(pins: &BTreeMap<String, Pin>, ip: &str, host_key: &str) -> Option<(String, String)> {
    pins.get(ip)
        .filter(|pin| pin.key_only && same_machine(pin, host_key))
        .map(|pin| (pin.host_key.clone(), pin.user.clone()))
}

/// Why the first login of the server the account names `server` stops
/// before anything is sent: a pin at `ip` holds another host key than
/// `offered`, whichever way it was written. Only a pin of another server
/// the account names is no reason: the account's record says that server
/// is not this one, so the address was handed on. Whether it was is never
/// read from the key offered.
fn pinned_otherwise(
    pins: &BTreeMap<String, Pin>,
    ip: &str,
    server: &str,
    offered: &HostKey,
    path: &Path,
) -> Option<String> {
    let old = pins.get(ip).filter(|old| {
        !same_machine(old, &offered.to_openssh())
            && old.account_server.as_deref().is_none_or(|s| s == server)
    })?;
    let was =
        HostKey::parse(&old.host_key).map_or_else(|_| old.host_key.clone(), |k| k.fingerprint());
    Some(format!(
        "{ip} now offers host key {} where erpc pinned {was} at its earlier login. Someone may \
         be in between; nothing was sent. If the server at that address was rebuilt or handed \
         on, remove its entry from {} and run the deploy again",
        offered.fingerprint(),
        path.display()
    ))
}

/// The SSH side of the first login to a server kept in the ERPC account,
/// for `erpc worker deploy` ([`crate::worker::first_login`]): the same
/// login as a VPS's. Its pin is known by the machine's host key, and carries
/// the account's id of the server beside any VPS id.
pub(crate) struct AccountLogins;

/// [`AccountLogins::prepare`], blocking. SSH that does not answer yet is
/// [`NotReady::Yet`]; no key of the person's, a pin that cannot be read or
/// a host key other than the one pinned is [`NotReady::Stop`].
fn account_prepare(server: &str, ip: &str) -> Result<Prepared, NotReady> {
    let (public, _) = login_key().map_err(NotReady::Stop)?;
    let line = crate::node::common::public_key_line(&public).map_err(NotReady::Stop)?;
    let kind = line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    // No host key yet is SSH not answering yet; anything else (no
    // ssh-keyscan here, an address it does not take) is not waited for.
    let offered = erpc_ssh::keyscan(ip, PORT).map_err(|e| match e {
        erpc_ssh::SshError::NoHostKey(_) => NotReady::Yet(e.to_string()),
        other => NotReady::Stop(other.to_string()),
    })?;
    let path = pins_path().map_err(NotReady::Stop)?;
    account_prepared(
        &path,
        (server, ip),
        &offered,
        format!("{} ({kind})", public.display()),
    )
}

/// What [`account_prepare`] gives once it has the host key `offered` and
/// erpc's key (`login_key`, as the question names it): the pins at `path`
/// read, and the first login refused while one holds another host key
/// ([`account_decide`]). The login name is not known yet: it is left empty.
fn account_prepared(
    path: &Path,
    (server, ip): (&str, &str),
    offered: &HostKey,
    login_key: String,
) -> Result<Prepared, NotReady> {
    let pins = load_pins(path).map_err(NotReady::Stop)?;
    Ok(Prepared {
        resumable: account_decide(&pins, ip, server, offered, path)?,
        vps_id: 0,
        fingerprint: offered.fingerprint(),
        host_key: offered.to_openssh(),
        login_key,
        ip: ip.to_owned(),
        user: String::new(),
    })
}

/// Whether the first login of the server the account names `server`, at
/// `ip` offering `offered`, may go on, and whether it can be taken up from
/// the key; never while a pin at `ip` holds another host key
/// ([`pinned_otherwise`]).
fn account_decide(
    pins: &BTreeMap<String, Pin>,
    ip: &str,
    server: &str,
    offered: &HostKey,
    path: &Path,
) -> Result<bool, NotReady> {
    if let Some(why) = pinned_otherwise(pins, ip, server, offered, path) {
        return Err(NotReady::Stop(why));
    }
    Ok(resumable(pins, ip, &offered.to_openssh(), None))
}

/// The host key and login name pinned in the pins at `path` for the
/// machine offering `host_key` at `ip`, when erpc made it key-only.
fn done_at(path: &Path, ip: &str, host_key: &str) -> Option<(String, String)> {
    key_only_at(&load_pins(path).ok()?, ip, host_key)
}

impl Logins for AccountLogins {
    fn prepare<'a>(
        &'a self,
        server: &'a str,
        ip: &'a str,
    ) -> LoginFut<'a, Result<Prepared, NotReady>> {
        let (server, ip) = (server.to_owned(), ip.to_owned());
        Box::pin(async move {
            tokio::task::spawn_blocking(move || account_prepare(&server, &ip))
                .await
                .unwrap_or_else(|e| Err(NotReady::Stop(e.to_string())))
        })
    }

    fn done(&self, ip: &str, host_key: &str) -> Option<(String, String)> {
        done_at(&pins_path().ok()?, ip, host_key)
    }

    fn secure<'a>(
        &'a self,
        prepared: &'a Prepared,
        server: &'a str,
        password: Result<&'a SecretString, &'a str>,
    ) -> LoginFut<'a, Result<Secured, String>> {
        let (prepared, server) = (prepared.clone(), server.to_owned());
        let password = password
            .map(|p| Zeroizing::new(p.expose_secret().to_owned()))
            .map_err(ToOwned::to_owned);
        Box::pin(blocking(move || {
            secure(
                &prepared,
                Some(&server),
                password
                    .as_ref()
                    .map(|p| p.as_str())
                    .map_err(String::as_str),
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use erpc_ssh::HostKey;

    use erpc_ai::servers::Prepared;

    use super::{
        NotReady, Pin, account_decide, account_pin, key_only_at, load_pins, merged, pin_for,
        pinned_otherwise, resumable, save_pin, value, vps_pin,
    };

    #[test]
    fn a_pin_is_kept_beside_the_others_and_read_back() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("vps_hosts.json");
        let pin = |user: &str| Pin {
            host_key: "ssh-ed25519 AAAA".to_owned(),
            user: user.to_owned(),
            port: 22,
            vps_id: 570_059,
            account_server: None,
            key_only: true,
        };
        save_pin(&path, "203.0.113.1", pin("ubuntu")).expect("saved");
        save_pin(&path, "203.0.113.2", pin("solv")).expect("saved");
        let pins = load_pins(&path).expect("read");
        assert_eq!(pins.len(), 2);
        assert_eq!(pins["203.0.113.2"].user, "solv");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn an_unreadable_pin_file_is_never_written_over() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("vps_hosts.json");
        std::fs::write(&path, "{ not json").expect("written");
        let pin = Pin {
            host_key: "ssh-ed25519 AAAA".to_owned(),
            user: "ubuntu".to_owned(),
            port: 22,
            vps_id: 1,
            account_server: None,
            key_only: true,
        };
        assert!(save_pin(&path, "203.0.113.1", pin).is_err());
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "{ not json");
    }

    #[test]
    fn a_servers_pin_is_found_only_by_what_it_is() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("vps_hosts.json");
        let server = "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60";
        let pin = |vps_id: i64, account_server: Option<&str>| Pin {
            host_key: "ssh-ed25519 AAAA".to_owned(),
            user: "ubuntu".to_owned(),
            port: 22,
            vps_id,
            account_server: account_server.map(ToOwned::to_owned),
            key_only: true,
        };
        save_pin(&path, "203.0.113.1", pin(0, Some(server))).expect("saved");
        save_pin(&path, "203.0.113.2", pin(570_059, None)).expect("saved");
        save_pin(&path, "203.0.113.3", pin(0, None)).expect("saved");
        // A VPS's pin is written as before, with no account id.
        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(text.matches("accountServer").count(), 1, "{text}");
        let pins = load_pins(&path).expect("read");
        // The account's server: found by its id only.
        assert!(account_pin(&pins, "203.0.113.1", server).is_some());
        assert!(
            account_pin(&pins, "203.0.113.1", "1a2b3c4d-0000-4000-8000-000000000000").is_none()
        );
        assert!(account_pin(&pins, "203.0.113.2", server).is_none());
        assert!(account_pin(&pins, "203.0.113.3", server).is_none());
        // The VPS path holds its key to its own pin and to one with no VPS
        // id (from before VPS ids, or the account's), never to another
        // VPS's.
        assert!(vps_pin(&pins, "203.0.113.1", 570_059).is_some());
        assert!(vps_pin(&pins, "203.0.113.2", 570_059).is_some());
        assert!(vps_pin(&pins, "203.0.113.2", 1).is_none());
        assert!(vps_pin(&pins, "203.0.113.3", 570_059).is_some());
    }

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const OTHER_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUFbvp9NNSqiS0AfqlG4aRt4PZ125MdCaIRGfMurzG/";
    const SERVER: &str = "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60";
    const IP: &str = "203.0.113.1";

    fn pin(host_key: &str, vps_id: i64, account_server: Option<&str>, key_only: bool) -> Pin {
        Pin {
            host_key: host_key.to_owned(),
            user: "ubuntu".to_owned(),
            port: 22,
            vps_id,
            account_server: account_server.map(ToOwned::to_owned),
            key_only,
        }
    }

    fn at(p: Pin) -> BTreeMap<String, Pin> {
        BTreeMap::from([(IP.to_owned(), p)])
    }

    #[test]
    fn one_machine_reached_both_ways_keeps_one_pin_that_serves_both() {
        // Reached as a VPS first, stopped once the key got in: the account's
        // first login of the same machine takes it up from the key.
        let vps = pin(KEY, 570_059, None, false);
        assert!(resumable(&at(vps.clone()), IP, KEY, None));
        assert!(resumable(&at(vps.clone()), IP, KEY, Some("ubuntu")));
        assert!(!resumable(&at(vps.clone()), IP, KEY, Some("root")));
        assert!(!resumable(&at(vps.clone()), IP, OTHER_KEY, None));
        // Its pin then keeps the VPS id, so the VPS path still finds it.
        let both = merged(pin(KEY, 0, Some(SERVER), true), Some(&vps));
        assert_eq!(
            (both.vps_id, both.account_server.as_deref()),
            (570_059, Some(SERVER))
        );
        assert!(vps_pin(&at(both.clone()), IP, 570_059).is_some());
        assert!(account_pin(&at(both), IP, SERVER).is_some());
        // Reached through the account first: the VPS path's pin keeps the
        // account's id, and the VPS path takes it up from the key.
        let account = pin(KEY, 0, Some(SERVER), true);
        assert!(resumable(&at(account.clone()), IP, KEY, Some("ubuntu")));
        assert_eq!(
            key_only_at(&at(account.clone()), IP, KEY),
            Some((KEY.to_owned(), "ubuntu".to_owned()))
        );
        let both = merged(pin(KEY, 570_059, None, true), Some(&account));
        assert_eq!(
            (both.vps_id, both.account_server.as_deref()),
            (570_059, Some(SERVER))
        );
        // Another machine at the address (another host key): nothing merged
        // or taken up.
        let other = merged(pin(OTHER_KEY, 0, Some(SERVER), false), Some(&vps));
        assert_eq!(
            (other.vps_id, other.account_server.as_deref()),
            (0, Some(SERVER))
        );
        assert_eq!(key_only_at(&at(account), IP, OTHER_KEY), None);
        // Done only once password logins were turned off.
        assert_eq!(
            key_only_at(&at(pin(KEY, 0, Some(SERVER), false)), IP, KEY),
            None
        );
        assert_eq!(
            key_only_at(&at(pin(KEY, 1, None, true)), IP, KEY),
            Some((KEY.to_owned(), "ubuntu".to_owned()))
        );
    }

    #[test]
    fn another_host_key_than_any_pin_at_the_address_holds_stops_the_first_login() {
        let path = std::path::Path::new("vps_hosts.json");
        let offered = HostKey::parse(OTHER_KEY).expect("a key");
        let same = HostKey::parse(KEY).expect("a key");
        let other_server = "1a2b3c4d-0000-4000-8000-000000000000";
        // Held to its key: this server's pin, a VPS's pin, a pin from
        // before VPS ids. Stopped, naming both keys, before anything.
        for held in [
            pin(KEY, 0, Some(SERVER), false),
            pin(KEY, 570_059, None, true),
            pin(KEY, 0, None, false),
            pin(KEY, 570_059, Some(SERVER), true),
        ] {
            let why =
                pinned_otherwise(&at(held.clone()), IP, SERVER, &offered, path).expect("stopped");
            assert!(
                why.contains(&offered.fingerprint()) && why.contains(&same.fingerprint()),
                "{why}"
            );
            assert!(matches!(
                account_decide(&at(held), IP, SERVER, &offered, path),
                Err(NotReady::Stop(_))
            ));
        }
        // Only another server the account names: the account says the
        // address was handed on.
        assert_eq!(
            pinned_otherwise(
                &at(pin(KEY, 0, Some(other_server), true)),
                IP,
                SERVER,
                &offered,
                path
            ),
            None
        );
        assert_eq!(
            account_decide(
                &at(pin(KEY, 0, Some(other_server), true)),
                IP,
                SERVER,
                &offered,
                path
            ),
            Ok(false)
        );
        // The same key: goes on, taken up from the key whichever way it was
        // pinned.
        for same_machine in [
            pin(KEY, 0, Some(SERVER), false),
            pin(KEY, 570_059, None, false),
        ] {
            assert_eq!(
                account_decide(&at(same_machine), IP, SERVER, &same, path),
                Ok(true)
            );
        }
        assert_eq!(
            account_decide(&BTreeMap::new(), IP, SERVER, &same, path),
            Ok(false)
        );
    }

    #[test]
    fn the_account_side_reads_the_pins_file_and_stops_on_another_key_there() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("vps_hosts.json");
        let offered = HostKey::parse(OTHER_KEY).expect("a key");
        let prepared = |path: &std::path::Path| {
            super::account_prepared(
                path,
                (SERVER, IP),
                &offered,
                "key.pub (ssh-ed25519)".to_owned(),
            )
        };
        // No pins yet: goes on, nothing to take up, the offered key.
        let first = prepared(&path).expect("goes on");
        assert!(!first.resumable);
        assert_eq!(
            (
                first.host_key.as_str(),
                first.ip.as_str(),
                first.user.as_str(),
                first.vps_id
            ),
            (offered.to_openssh().as_str(), IP, "", 0)
        );
        assert_eq!(first.fingerprint, offered.fingerprint());
        assert_eq!(first.login_key, "key.pub (ssh-ed25519)");
        // A VPS's pin of another key at the address: stopped.
        save_pin(&path, IP, pin(KEY, 570_059, None, true)).expect("saved");
        assert!(matches!(prepared(&path), Err(NotReady::Stop(_))));
        // The same machine's pin: taken up from the key.
        save_pin(&path, IP, pin(OTHER_KEY, 570_059, None, false)).expect("saved");
        assert!(prepared(&path).expect("goes on").resumable);
        // A pins file that cannot be read: stopped, never written over.
        std::fs::write(&path, "{ not json").expect("written");
        assert!(matches!(prepared(&path), Err(NotReady::Stop(_))));
    }

    #[test]
    fn the_pin_a_login_writes_carries_both_ids_and_done_reads_the_file() {
        let prepared = |vps_id: i64| Prepared {
            resumable: false,
            vps_id,
            ip: IP.to_owned(),
            user: "ubuntu".to_owned(),
            host_key: KEY.to_owned(),
            fingerprint: String::new(),
            login_key: String::new(),
        };
        // The account's login over a VPS's pin of the same machine.
        let vps = pin(KEY, 570_059, None, true);
        let written = pin_for(&prepared(0), Some(SERVER), Some(&vps));
        assert_eq!(
            (
                written.vps_id,
                written.account_server.as_deref(),
                written.key_only
            ),
            (570_059, Some(SERVER), false)
        );
        // The VPS's login over the account's pin.
        let account = pin(KEY, 0, Some(SERVER), true);
        let written = pin_for(&prepared(570_059), None, Some(&account));
        assert_eq!(
            (written.vps_id, written.account_server.as_deref()),
            (570_059, Some(SERVER))
        );
        // Done is read from the file at the path given.
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("vps_hosts.json");
        assert_eq!(super::done_at(&path, IP, KEY), None);
        save_pin(&path, IP, pin(KEY, 0, Some(SERVER), true)).expect("saved");
        assert_eq!(
            super::done_at(&path, IP, KEY),
            Some((KEY.to_owned(), "ubuntu".to_owned()))
        );
        assert_eq!(super::done_at(&path, IP, OTHER_KEY), None);
    }

    /// The key erpc logs in with is the `.pub` the `ssh_key` setting
    /// names; with no setting, `~/.ssh/id_ed25519.pub`. A setting whose
    /// file is gone is never passed over for the default.
    #[test]
    fn the_key_is_the_ssh_key_setting_else_the_default_under_home() {
        let dir = tempfile::tempdir().expect("dir");
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).expect("ssh dir");
        let default = home.join(".ssh/id_ed25519.pub");
        // No config file: no setting.
        let config = dir.path().join("config.toml");
        assert_eq!(super::public_key(Some(&config), Some(&home)), None);
        std::fs::write(&default, format!("{KEY}\n")).expect("default key");
        assert_eq!(
            super::public_key(Some(&config), Some(&home)),
            Some(default.clone())
        );
        assert_eq!(super::public_key(None, Some(&home)), Some(default));
        let other = dir.path().join("other.pub");
        std::fs::write(&other, format!("{OTHER_KEY}\n")).expect("other key");
        crate::account::config::set(&config, "ssh_key", other.to_str().expect("a path"))
            .expect("set");
        assert_eq!(
            super::public_key(Some(&config), Some(&home)),
            Some(other.clone())
        );
        std::fs::remove_file(&other).expect("removed");
        assert_eq!(super::public_key(Some(&config), Some(&home)), None);
        assert_eq!(super::public_key(None, None), None);
    }

    /// The Security Check logs in with that key too: the default when
    /// `ssh_key` is unset, its private half beside it with no agent. It
    /// still takes only one public key line in a `.pub` file.
    #[cfg(feature = "security-check-pilot")]
    #[test]
    fn the_security_check_logs_in_with_the_default_key_when_ssh_key_is_unset() {
        use erpc_ssh::Identity;

        use super::security_identity_from as identity;

        let dir = tempfile::tempdir().expect("dir");
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).expect("ssh dir");
        let config = dir.path().join("config.toml");
        assert_eq!(identity(Some(&config), Some(&home), None), None);
        std::fs::write(home.join(".ssh/id_ed25519.pub"), format!("{KEY} fixture\n"))
            .expect("default key");
        assert_eq!(
            identity(Some(&config), Some(&home), None),
            Some(Identity::File(home.join(".ssh/id_ed25519")))
        );
        // Set: that key, and not the default.
        let other = dir.path().join("other.pub");
        std::fs::write(&other, format!("{OTHER_KEY}\n")).expect("other key");
        crate::account::config::set(&config, "ssh_key", other.to_str().expect("a path"))
            .expect("set");
        assert_eq!(
            identity(Some(&config), Some(&home), None),
            Some(Identity::File(dir.path().join("other")))
        );
        // Set to a file that is not one public key line, or not a .pub.
        std::fs::write(&other, format!("{KEY}\n{OTHER_KEY}\n")).expect("two keys");
        assert_eq!(identity(Some(&config), Some(&home), None), None);
        let bare = dir.path().join("bare");
        std::fs::write(&bare, format!("{KEY}\n")).expect("no extension");
        crate::account::config::set(&config, "ssh_key", bare.to_str().expect("a path"))
            .expect("set");
        assert_eq!(identity(Some(&config), Some(&home), None), None);
    }

    /// The Security Check takes only that VPS's pin, once erpc made it
    /// key-only: never an unfinished one, another VPS's, one with no VPS
    /// id, or one whose host key does not parse.
    #[cfg(feature = "security-check-pilot")]
    #[test]
    fn the_security_check_takes_only_this_vps_key_only_pin() {
        use super::security_pin_at;

        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("vps_hosts.json");
        for (ip, held) in [
            ("203.0.113.1", pin(KEY, 9, None, true)),
            ("203.0.113.2", pin(KEY, 9, None, false)),
            ("203.0.113.3", pin(KEY, 0, Some(SERVER), true)),
            ("203.0.113.4", pin("ssh-ed25519 AAAA", 9, None, true)),
        ] {
            save_pin(&path, ip, held).expect("saved");
        }
        let login = security_pin_at(&path, "203.0.113.1", 9).expect("pinned");
        assert_eq!(
            (login.host_key.to_openssh(), login.user.as_str(), login.port),
            (KEY.to_owned(), "ubuntu", 22)
        );
        for (ip, id) in [
            ("203.0.113.1", 10),
            ("203.0.113.2", 9),
            ("203.0.113.3", 9),
            ("203.0.113.4", 9),
            ("203.0.113.9", 9),
        ] {
            assert!(security_pin_at(&path, ip, id).is_none(), "{ip} {id}");
        }
    }

    #[test]
    fn a_pin_from_before_vps_ids_counts_as_unfinished() {
        let old: Pin =
            serde_json::from_str(r#"{"hostKey":"ssh-ed25519 AAAA","user":"ubuntu","port":22}"#)
                .expect("read");
        assert!(!old.key_only);
        assert_eq!(old.vps_id, 0);
    }

    #[test]
    fn values_are_read_from_their_lines() {
        let out = b"key=installed\ncontroller=203.0.113.9\n";
        assert_eq!(value(out, "controller").as_deref(), Some("203.0.113.9"));
        assert_eq!(value(out, "key").as_deref(), Some("installed"));
        assert_eq!(value(out, "sudo"), None);
    }
}
