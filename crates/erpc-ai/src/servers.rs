// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Logging in to the user's ERPC VPS for them.
//!
//! A VPS comes with a password login. The first time, erpc logs in with it
//! once, puts the user's own SSH key in place, checks the key gets in, and
//! turns password logins off for good; from then on only the key gets in.
//! The password comes from user-api and goes from there to the server, on
//! standard input: the model never sees it, and is never given it. Then,
//! when the user asks, SSH can be allowed from their address only.
//!
//! The SSH work is the front end's ([`Servers`]); what is asked and what is
//! said is here. Each step that changes the server asks the person first.

use core::future::Future;
use core::pin::Pin;
use std::net::IpAddr;

use erpc_auth::AuthClient;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::confirm::{Confirm, Confirmation};
use crate::i18n::t;
use crate::tools::read;

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + 'a>>;

/// A server erpc is about to log in to for the first time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The VPS it is, as user-api numbers it.
    pub vps_id: i64,
    /// Its address.
    pub ip: String,
    /// The login user.
    pub user: String,
    /// The host key it offers, as OpenSSH writes it; pinned from now on.
    pub host_key: String,
    /// That key's fingerprint, for the person.
    pub fingerprint: String,
    /// The user's key erpc logs in with: where it is and its fingerprint.
    pub login_key: String,
    /// Whether an earlier attempt got as far as pinning it, so the work
    /// may be taken up over the key, with no password.
    pub resumable: bool,
}

/// What the first login did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secured {
    /// The address the server saw erpc come from: the user's.
    pub controller: Option<String>,
    /// Whether `sudo` asked for the password, so the login user was given
    /// `sudo` without one.
    pub sudo_needed_password: bool,
}

/// Reaching the user's servers over SSH.
pub trait Servers {
    /// Whether erpc has already made VPS `vps_id`, at `ip`, key-only. An
    /// address alone is not enough: an ended VPS's address goes to the
    /// next one.
    fn secured(&self, vps_id: i64, ip: &str) -> bool;

    /// The host key `ip` offers and the key erpc would log in with.
    fn prepare<'a>(&'a self, vps_id: i64, ip: &'a str, user: &'a str) -> Fut<'a, Prepared>;

    /// The first login: the key put in place, then password logins off.
    /// `password` is ERPC's login password, or why there is none: work an
    /// earlier attempt left part done is taken up with the key, and needs
    /// it only if `sudo` asks.
    fn secure<'a>(
        &'a self,
        prepared: &'a Prepared,
        password: Result<&'a SecretString, &'a str>,
    ) -> Fut<'a, Secured>;

    /// The address `ip` sees erpc come from.
    fn controller<'a>(&'a self, ip: &'a str) -> Fut<'a, String>;

    /// Allows SSH to `ip` from `addresses` only, kept only once a fresh
    /// connection gets through.
    fn allow_ssh<'a>(&'a self, ip: &'a str, addresses: Vec<IpAddr>) -> Fut<'a, ()>;

    /// Takes that allow list away.
    fn open_ssh<'a>(&'a self, ip: &'a str) -> Fut<'a, ()>;

    /// How long an applied allow list waits for a fresh connection before
    /// it is undone.
    fn rollback_seconds(&self) -> u32;
}

const NO_SERVERS: &str = "this erpc cannot log in to servers";
const NO_ONE_TO_ASK: &str = "this changes a server, and only the person at the terminal can say \
     yes to that; tell the user to ask in `erpc ai` at a terminal";

/// One of the account's VPSs, as `/v3/vps/status` gives it.
struct Vps {
    id: i64,
    ip: String,
    user: String,
    password: Option<SecretString>,
    password_status: String,
}

async fn vps(client: &AuthClient, token: &SecretString, input: &Value) -> Result<Vps, String> {
    let id = input
        .get("userVpsId")
        .and_then(Value::as_i64)
        .ok_or("userVpsId is needed: my_services or the start's result gives it")?;
    let reply = read(client, token, crate::ready::vps_status_url()?).await?;
    let row =
        crate::ready::vps_row(&reply, id).ok_or_else(|| format!("the account has no VPS {id}"))?;
    let text = |field: &str| {
        row.get(field)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
    };
    if text("status").as_deref() != Some("on") {
        return Err(format!(
            "VPS {id} is not running yet ({}); wait_until_ready first",
            text("status").unwrap_or_default()
        ));
    }
    Ok(Vps {
        id,
        ip: text("ip").ok_or("user-api gives no address for it yet")?,
        user: text("username").unwrap_or_else(|| "ubuntu".to_owned()),
        password: text("password").map(SecretString::from),
        password_status: text("passwordStatus").unwrap_or_default(),
    })
}

/// `secure_vps`: logs in once with the password, puts the user's key in
/// place and turns password logins off.
///
/// # Errors
///
/// A message saying what user-api or the person refused, for the caller to show.
pub async fn secure_vps(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
    confirm: Option<&dyn Confirm>,
    servers: Option<&dyn Servers>,
) -> Result<Value, String> {
    let servers = servers.ok_or(NO_SERVERS)?;
    let confirm = confirm.ok_or(NO_ONE_TO_ASK)?;
    let vps = vps(client, token, input).await?;
    if servers.secured(vps.id, &vps.ip) {
        return Ok(json!({
            "done": true,
            "already": true,
            "ssh": format!("ssh {}@{}", vps.user, vps.ip),
            "note": "erpc made it key-only before; password logins are off.",
        }));
    }
    // Missing is not yet a refusal: an attempt that got as far as the key
    // goes on without it.
    let password = vps
        .password
        .as_ref()
        .ok_or_else(|| match vps.password_status.as_str() {
            "deleted" => {
                "ERPC has already removed this VPS's login password, so erpc cannot make the \
                      first login; ERPC support can help"
                    .to_owned()
            }
            "pending" => {
                "the login password is not handed over yet; try again in a minute".to_owned()
            }
            _ => "user-api gives no login password for it".to_owned(),
        });
    let prepared = servers.prepare(vps.id, &vps.ip, &vps.user).await?;
    // With no password and nothing to take up, a yes could do nothing.
    if !prepared.resumable
        && let Err(why) = password
    {
        return Err(why);
    }
    let ask = Confirmation {
        title: t!("confirm.secure.title", ip = vps.ip),
        lines: vec![
            (
                t!("confirm.label.server"),
                format!("{}@{}", vps.user, vps.ip),
            ),
            (t!("confirm.label.host_key"), prepared.fingerprint.clone()),
            (t!("confirm.label.your_key"), prepared.login_key.clone()),
            (t!("confirm.label.changes"), t!("confirm.secure.changes")),
        ],
    };
    if !confirm.confirm(&ask).await {
        return Err("the user said no; nothing was changed".to_owned());
    }
    let secured = servers
        .secure(
            &prepared,
            password.as_ref().copied().map_err(String::as_str),
        )
        .await?;
    Ok(json!({
        "done": true,
        "ssh": format!("ssh {}@{}", vps.user, vps.ip),
        "passwordLogin": "off",
        "hostKey": prepared.fingerprint,
        "yourAddress": secured.controller,
        "sudoWithoutPassword": secured.sudo_needed_password,
        "next": "Tell the user it is key-only now and how to log in. Then recommend allowing SSH \
                 from their address only (yourAddress) for more safety, with ask_choice; call \
                 restrict_ssh only if they agree.",
    }))
}

/// `restrict_ssh`: allows SSH from the user's address (and any others they
/// name) only, or takes that away.
///
/// # Errors
///
/// A message saying what user-api or the person refused, for the caller to show.
pub async fn restrict_ssh(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
    confirm: Option<&dyn Confirm>,
    servers: Option<&dyn Servers>,
) -> Result<Value, String> {
    let servers = servers.ok_or(NO_SERVERS)?;
    let confirm = confirm.ok_or(NO_ONE_TO_ASK)?;
    let vps = vps(client, token, input).await?;
    if !servers.secured(vps.id, &vps.ip) {
        return Err("make it key-only first (secure_vps); erpc has not logged in to it".to_owned());
    }
    if input.get("open").and_then(Value::as_bool) == Some(true) {
        let ask = Confirmation {
            title: t!("confirm.ssh_open.title", ip = vps.ip),
            lines: vec![(t!("confirm.label.server"), vps.ip.clone())],
        };
        if !confirm.confirm(&ask).await {
            return Err("the user said no; nothing was changed".to_owned());
        }
        servers.open_ssh(&vps.ip).await?;
        return Ok(json!({ "done": true, "ssh": "open to every address (key only)" }));
    }
    let mut addresses = Vec::new();
    for extra in input
        .get("extraAddresses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let text = extra.as_str().unwrap_or_default();
        addresses.push(
            text.parse::<IpAddr>()
                .map_err(|_| format!("{text:?} is not an IP address"))?,
        );
    }
    let own = servers.controller(&vps.ip).await?;
    let own_ip: IpAddr = own
        .parse()
        .map_err(|_| format!("the server saw erpc come from {own:?}, not an address"))?;
    addresses.insert(0, own_ip);
    let shown: Vec<String> = addresses.iter().map(ToString::to_string).collect();
    let ask = Confirmation {
        title: t!("confirm.ssh_only.title", ip = vps.ip),
        lines: vec![
            (t!("confirm.label.server"), vps.ip.clone()),
            (t!("confirm.label.allowed"), shown.join(", ")),
            (t!("confirm.label.yours_now"), own.clone()),
            (
                t!("confirm.label.safety"),
                t!(
                    "confirm.ssh_only.safety",
                    seconds = servers.rollback_seconds()
                ),
            ),
            (t!("confirm.label.note"), t!("confirm.ssh_only.note")),
        ],
    };
    if !confirm.confirm(&ask).await {
        return Err("the user said no; nothing was changed".to_owned());
    }
    servers.allow_ssh(&vps.ip, addresses).await?;
    Ok(json!({
        "done": true,
        "allowed": shown,
        "note": "SSH now gets in from these addresses only; other ports are as they were. If \
                 the user's address changes (home or mobile networks often do), they cannot log \
                 in until it is allowed again: from an allowed address, or with ERPC support.",
    }))
}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::pin::Pin;
    use std::net::IpAddr;

    use secrecy::SecretString;

    use super::{Fut, Prepared, Secured, Servers};
    use crate::confirm::{Confirm, Confirmation};

    struct No;

    impl Confirm for No {
        fn confirm<'a>(&'a self, _: &'a Confirmation) -> Pin<Box<dyn Future<Output = bool> + 'a>> {
            Box::pin(async { false })
        }
    }

    struct Unreachable;

    impl Servers for Unreachable {
        fn secured(&self, _: i64, _: &str) -> bool {
            false
        }
        fn prepare<'a>(&'a self, _: i64, _: &'a str, _: &'a str) -> Fut<'a, Prepared> {
            Box::pin(async { Err("unreachable".to_owned()) })
        }
        fn secure<'a>(
            &'a self,
            _: &'a Prepared,
            _: Result<&'a SecretString, &'a str>,
        ) -> Fut<'a, Secured> {
            unreachable!("nothing logs in without a yes")
        }
        fn controller<'a>(&'a self, _: &'a str) -> Fut<'a, String> {
            Box::pin(async { Err("unreachable".to_owned()) })
        }
        fn allow_ssh<'a>(&'a self, _: &'a str, _: Vec<IpAddr>) -> Fut<'a, ()> {
            unreachable!("nothing is applied without a yes")
        }
        fn open_ssh<'a>(&'a self, _: &'a str) -> Fut<'a, ()> {
            unreachable!("nothing is applied without a yes")
        }
        fn rollback_seconds(&self) -> u32 {
            120
        }
    }

    #[tokio::test]
    async fn nothing_reaches_a_server_without_a_person_or_the_ability() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let token = SecretString::from("t".to_owned());
        let input = serde_json::json!({ "userVpsId": 1 });
        for (confirm, servers, why) in [
            (Some(&No as &dyn Confirm), None, super::NO_SERVERS),
            (
                None,
                Some(&Unreachable as &dyn Servers),
                super::NO_ONE_TO_ASK,
            ),
        ] {
            assert_eq!(
                super::secure_vps(&client, &token, &input, confirm, servers).await,
                Err(why.to_owned())
            );
            assert_eq!(
                super::restrict_ssh(&client, &token, &input, confirm, servers).await,
                Err(why.to_owned())
            );
        }
    }
}
