// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Waiting for what was just started to be ready to use: a VPS can be
//! logged in to a few minutes after its start. erpc reads its state until
//! it is running, and says so; a VPS that is not running after five
//! minutes, or that stops on the way, has gone wrong, and that is said
//! too. The password is never passed on.

use std::time::Duration;

use erpc_api::account;
use erpc_auth::AuthClient;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::tools::read;

/// The longest wait: a VPS takes a few minutes.
const WAIT: Duration = Duration::from_secs(300);
/// How often its state is read.
const EVERY: Duration = Duration::from_secs(15);
/// How many reads in a row may fail before the wait gives up: one that
/// fails now and then is user-api busy, not the VPS going wrong.
const FAILED_READS: u32 = 3;
/// How many reads in a row must find it stopped before that is the
/// answer: a VPS booting can pass through a state such as `off` on its way.
const WRONG_READS: u32 = 3;
/// How long a VPS just started may be missing from the list: user-api can
/// take a moment to list it.
const UNLISTED: Duration = Duration::from_secs(60);

/// Where a VPS is on the way to being used.
#[derive(Debug, PartialEq, Eq)]
enum State {
    /// Running: it can be logged in to.
    Ready {
        ip: Option<String>,
        username: Option<String>,
    },
    /// Still being set up, with user-api's word for it.
    Waiting(String),
    /// Stopped, suspended or in maintenance: it will not get ready by
    /// waiting.
    Wrong(String),
    /// Not among the account's VPSs.
    Missing,
}

/// Where the account's VPSs and their state are read.
///
/// # Errors
///
/// Never in this build: the address is a constant.
pub fn vps_status_url() -> Result<&'static str, String> {
    account::SERVICE_STATUS_URLS
        .iter()
        .find(|(kind, _)| *kind == "vps")
        .map(|(_, url)| *url)
        .ok_or_else(|| "no VPS status address".to_owned())
}

/// VPS `id`'s row in a `/v3/vps/status` reply.
pub fn vps_row(reply: &Value, id: i64) -> Option<&Value> {
    reply
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|row| row.get("userVpsId").and_then(Value::as_i64) == Some(id))
}

/// The state of VPS `id` in a `/v3/vps/status` reply.
fn vps_state(reply: &Value, id: i64) -> State {
    let Some(row) = vps_row(reply, id) else {
        return State::Missing;
    };
    let text = |field: &str| {
        row.get(field)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    let status = text("status").unwrap_or_default();
    match status.as_str() {
        "on" => State::Ready {
            ip: text("ip"),
            username: text("username"),
        },
        "pending" | "provisioning" | "vacant" | "" => State::Waiting(status),
        _ => State::Wrong(status),
    }
}

/// `wait_until_ready`: reads the VPS's state until it is running, it goes
/// wrong, or five minutes pass.
///
/// # Errors
///
/// A family erpc cannot watch, a missing id, or user-api not answering.
pub async fn wait_until_ready(
    client: &AuthClient,
    token: &SecretString,
    input: &Value,
) -> Result<Value, String> {
    if input.get("family").and_then(Value::as_str) != Some("vps") {
        return Err("erpc can only wait for a VPS so far; for anything else, \
                    check my_services in a few minutes"
            .to_owned());
    }
    let id = input
        .get("userVpsId")
        .and_then(Value::as_i64)
        .ok_or("userVpsId is needed: the start's result gives it")?;
    let url = vps_status_url()?;
    let started = tokio::time::Instant::now();
    let mut failed = 0;
    let mut wrong = 0;
    loop {
        let waited = started.elapsed().as_secs();
        let reply = match read(client, token, url).await {
            Ok(reply) => {
                failed = 0;
                reply
            }
            Err(e) => {
                failed += 1;
                if failed >= FAILED_READS || started.elapsed() + EVERY > WAIT {
                    return Err(format!(
                        "could not read the VPS's state ({e}); it may still be starting: check \
                         my_services in a few minutes"
                    ));
                }
                tokio::time::sleep(EVERY).await;
                continue;
            }
        };
        let state = vps_state(&reply, id);
        if !matches!(state, State::Wrong(_)) {
            wrong = 0;
        }
        let last = match state {
            State::Ready { ip, username } => {
                return Ok(json!({
                    "ready": true,
                    "status": "on",
                    "ip": ip,
                    "username": username,
                    "waitedSeconds": waited,
                    "next": "It is running. Tell the user, then log in for them with \
                             secure_vps (it asks the person first), which puts their key in \
                             place and turns password logins off. Never give a password.",
                }));
            }
            State::Wrong(status) if wrong + 1 < WRONG_READS => {
                wrong += 1;
                status
            }
            State::Wrong(status) => {
                return Ok(json!({
                    "ready": false,
                    "status": status,
                    "waitedSeconds": waited,
                    "note": "It stopped on the way to running: something went wrong. Tell the \
                             user, and that ERPC support can look into it; do not start \
                             another one on your own.",
                }));
            }
            State::Missing if started.elapsed() + EVERY > UNLISTED => {
                return Err(format!("the account has no VPS {id}; check my_services"));
            }
            State::Missing => "not listed yet".to_owned(),
            State::Waiting(status) => status,
        };
        if started.elapsed() + EVERY > WAIT {
            return Ok(json!({
                "ready": false,
                "status": last,
                "waitedSeconds": started.elapsed().as_secs(),
                "note": "Not running after five minutes, which it should be by now: \
                         something went wrong. Tell the user, and that ERPC support can look \
                         into it; do not start another one on your own.",
            }));
        }
        tokio::time::sleep(EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{State, vps_state};

    fn reply(status: &str) -> serde_json::Value {
        json!({ "data": [
            { "userVpsId": 1, "status": "on", "ip": "203.0.113.1" },
            { "userVpsId": 570_059, "status": status, "ip": "203.0.113.10", "username": "ubuntu", "password": "secret" },
        ] })
    }

    #[test]
    fn the_vps_asked_about_is_read_and_its_password_is_not() {
        assert_eq!(
            vps_state(&reply("on"), 570_059),
            State::Ready {
                ip: Some("203.0.113.10".to_owned()),
                username: Some("ubuntu".to_owned()),
            }
        );
        assert_eq!(
            vps_state(&reply("provisioning"), 570_059),
            State::Waiting("provisioning".to_owned())
        );
        assert_eq!(
            vps_state(&reply("suspended"), 570_059),
            State::Wrong("suspended".to_owned())
        );
        assert_eq!(vps_state(&reply("on"), 7), State::Missing);
    }
}
