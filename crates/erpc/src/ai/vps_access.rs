// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Logging in to the user's ERPC VPS for `erpc ai` ([`erpc_ai::servers`]).
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
    /// The VPS it is: an ended VPS's address goes to the next one.
    #[serde(default)]
    vps_id: i64,
    /// Whether password logins were turned off and checked refused. Until
    /// then the key gets in but the work is unfinished, and the next
    /// `secure` takes it up from the key.
    #[serde(default)]
    key_only: bool,
}

fn pins_path() -> Result<PathBuf, String> {
    crate::session::beside_config("vps_hosts.json")
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

/// The user's key: its `.pub` and how its private half is reached.
pub(crate) fn login_key() -> Result<(PathBuf, Identity), String> {
    let configured = crate::session::config_path()
        .ok()
        .and_then(|path| crate::config::get(&path, "ssh_key").ok().flatten())
        .map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let public = configured
        .or_else(|| home.as_ref().map(|h| h.join(".ssh/id_ed25519.pub")))
        .filter(|p| p.is_file())
        .ok_or(
            "no SSH key to log in with: make one (ssh-keygen -t ed25519) or point erpc at yours \
             with `erpc config set ssh_key /path/to/key.pub`",
        )?;
    let line = crate::node_common::public_key_line(&public)?;
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

fn secure(prepared: &Prepared, password: Result<&str, &str>) -> Result<Secured, String> {
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
            &crate::session::state_dir()?,
        )
        .map_err(|e| e.to_string())
    };
    let mut pin = Pin {
        host_key: prepared.host_key.clone(),
        user: prepared.user.clone(),
        port: PORT,
        vps_id: prepared.vps_id,
        key_only: false,
    };
    let resumed = load_pins(&path)?.get(&prepared.ip).is_some_and(|old| {
        old.vps_id == pin.vps_id && old.host_key == pin.host_key && old.user == pin.user
    });
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
        let key_line = crate::node_common::public_key_line(&public)?;
        // Taken up, the key was the way in: that it fails is the news, not
        // a password that is no longer needed.
        let password = password.map_err(|why| {
            if resumed {
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
            let line = crate::node_common::public_key_line(&public)?;
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
            let earlier = pins
                .get(&ip)
                .filter(|pin| pin.vps_id == vps_id || pin.vps_id == 0);
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
            let resumable = earlier.is_some_and(|old| old.vps_id == vps_id && old.user == user);
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

#[cfg(test)]
mod tests {
    use super::{Pin, load_pins, save_pin, value};

    #[test]
    fn a_pin_is_kept_beside_the_others_and_read_back() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("vps_hosts.json");
        let pin = |user: &str| Pin {
            host_key: "ssh-ed25519 AAAA".to_owned(),
            user: user.to_owned(),
            port: 22,
            vps_id: 570_059,
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
            key_only: true,
        };
        assert!(save_pin(&path, "203.0.113.1", pin).is_err());
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "{ not json");
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
