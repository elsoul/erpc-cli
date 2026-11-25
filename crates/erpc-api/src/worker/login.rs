// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The first login of a server in an environment: its login name, and its
//! password while the account still hands it over.
//!
//! `erpc worker deploy` reads it once the account says the server is
//! ready, for the one login that puts the person's key on the server and
//! turns password logins off.
//!
//! Each read takes one of the writes the account allows (counted with a
//! deploy's writes), and each read within that limit is a line in its
//! audit history, so it is read once for that login, not polled.
//!
//! The password is never printed: [`fmt::Debug`] redacts it, and a reply
//! whose password is not text is read as having none, never as an error
//! that could quote it.
//!
//! [`fmt::Debug`]: core::fmt::Debug

use core::fmt;

use erpc_auth::AuthClient;
use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::money::path_id;
use super::{WorkerError, env_url, get, reply, token};

open_enum! {
    /// Whether the account hands the server's password over.
    PasswordStatus {
        /// It does: the password is in the reply.
        Visible = "visible",
        /// A password is set but not handed over yet.
        Pending = "pending",
        /// No longer: the account removed it, as it does a day after a
        /// password is handed over.
        Deleted = "deleted",
        /// The server has no password on record.
        None = "none",
    }
}

/// The first login of a server, as the account gives it.
#[derive(Clone)]
#[non_exhaustive]
pub struct FirstLogin {
    /// The login name: the account's text as sent, not checked here. A
    /// caller checks it with [`FirstLogin::login_name`] before it is used
    /// or printed.
    pub username: String,
    /// Whether the account hands the password over.
    pub password_status: PasswordStatus,
    /// When the account removes the password (ISO 8601, UTC), when it says;
    /// the account's text as sent. `None` when it sets no deadline: a
    /// server taken in from before the account kept deadlines may show a
    /// password with none, which is then not necessarily removed a day
    /// later.
    pub password_expires_at: Option<String>,
    /// The password, only while the status is [`PasswordStatus::Visible`]
    /// and the account sent one that is not empty.
    password: Option<SecretString>,
}

impl FirstLogin {
    /// The password, while the account hands it over: the status is
    /// [`PasswordStatus::Visible`] and it is text that is not empty. An
    /// empty one is none.
    #[must_use]
    pub const fn password(&self) -> Option<&SecretString> {
        self.password.as_ref()
    }

    /// The login name, when it is one SSH may be given: 1 to 32
    /// characters, a lowercase letter or `_` first, then lowercase letters,
    /// digits, `_` and `-`. `None` for anything else, which is not used.
    #[must_use]
    pub fn login_name(&self) -> Option<&str> {
        let name = self.username.as_str();
        let mut chars = name.chars();
        let first = chars.next()?;
        let ok = name.len() <= 32
            && (first.is_ascii_lowercase() || first == '_')
            && chars
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'));
        ok.then_some(name)
    }
}

impl fmt::Debug for FirstLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirstLogin")
            .field("username", &self.username)
            .field("password_status", &self.password_status)
            .field("password_expires_at", &self.password_expires_at)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl<'de> Deserialize<'de> for FirstLogin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            username: String,
            password_status: PasswordStatus,
            #[serde(default)]
            password_expires_at: Option<String>,
            // Read as any value, so that one of the wrong type is none
            // rather than an error that could quote it.
            #[serde(default)]
            password: Value,
        }
        let wire = Wire::deserialize(deserializer)?;
        let password = match (&wire.password_status, wire.password) {
            (PasswordStatus::Visible, Value::String(p)) if !p.is_empty() => {
                Some(SecretString::from(p))
            }
            _ => None,
        };
        Ok(Self {
            username: wire.username,
            password_status: wire.password_status,
            password_expires_at: wire.password_expires_at,
            password,
        })
    }
}

/// The URL of the first login of server `server` (its id in the
/// environment's record) of environment `env` of `app`.
fn first_login_url(app: &str, env: &str, server: &str) -> Result<String, WorkerError> {
    Ok(format!(
        "{}/servers/{}/credential",
        env_url(app, env)?,
        path_id(server)?
    ))
}

/// The first login of server `server` of environment `env` of `app`: its
/// login name and, while the account hands it over, its password. Read
/// once, for that login (each read takes one of the writes the account
/// allows, and each within that limit is a line in its audit history).
///
/// # Errors
///
/// [`super::Code::WorkerNotFound`], [`super::Code::EnvNotFound`] or
/// [`super::Code::ServerNotFound`] when there is no such app, environment
/// or server; [`super::Code::CredentialUnavailable`] when the server has no
/// login to read ([`super::Refusal::reason`]); [`super::Code::RateLimited`]
/// when too many writes were sent ([`super::Refusal::retry_after`]);
/// [`WorkerError::Id`] for an id that is not one the account gives, before
/// anything is sent; and [`WorkerError`] otherwise.
pub async fn first_login(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    env: &str,
    server: &str,
) -> Result<FirstLogin, WorkerError> {
    let url = first_login_url(app, env, server)?;
    let (status, text) = get(client, access_token, &url).await?;
    reply::<FirstLogin>(status, &text).map(|w| w.record)
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;
    use serde_json::json;

    use super::*;
    use crate::worker::{Code, Refusal};

    const SERVER_ID: &str = "0b8e7c52-91d4-4f6a-8e23-7d1a5c9b3e60";
    const PASSWORD: &str = "made-up-password-100001";

    fn read(data: &Value) -> FirstLogin {
        let text = json!({ "success": true, "message": "ok", "data": data }).to_string();
        reply::<FirstLogin>(200, &text).expect("reads").record
    }

    #[test]
    fn the_url_is_under_the_environment_and_a_bad_id_or_name_makes_none() {
        assert_eq!(
            first_login_url("bot", "prod", SERVER_ID).expect("a url"),
            format!(
                "https://user-api.erpc.global/v3/worker/apps/bot/envs/prod/servers/{SERVER_ID}/credential"
            )
        );
        for bad in ["", "../x", "0B8E7C52-91D4-4F6A-8E23-7D1A5C9B3E60", "100001"] {
            assert!(
                matches!(first_login_url("bot", "prod", bad), Err(WorkerError::Id)),
                "{bad:?}"
            );
        }
        assert!(first_login_url("bot", "Prod", SERVER_ID).is_err());
    }

    #[test]
    fn the_password_is_read_only_while_it_is_handed_over_and_not_empty() {
        let visible = read(&json!({
            "username": "ubuntu", "password": PASSWORD,
            "passwordStatus": "visible", "passwordExpiresAt": "2026-11-26T08:00:00.000Z"
        }));
        assert_eq!(visible.username, "ubuntu");
        assert_eq!(visible.password_status, PasswordStatus::Visible);
        assert_eq!(
            visible.password_expires_at.as_deref(),
            Some("2026-11-26T08:00:00.000Z")
        );
        assert_eq!(
            visible.password().map(|p| p.expose_secret().to_owned()),
            Some(PASSWORD.to_owned())
        );
        // An empty password is none.
        let blank = read(&json!({
            "username": "ubuntu", "password": "",
            "passwordStatus": "visible", "passwordExpiresAt": null
        }));
        assert!(blank.password().is_none());
        assert_eq!(blank.password_expires_at, None);
        // Not handed over: none, whatever is sent beside the status.
        for (status, known) in [
            ("pending", Some(PasswordStatus::Pending)),
            ("deleted", Some(PasswordStatus::Deleted)),
            ("none", Some(PasswordStatus::None)),
            ("later", None),
        ] {
            let login = read(&json!({
                "username": "ubuntu", "password": PASSWORD,
                "passwordStatus": status, "passwordExpiresAt": null
            }));
            assert!(login.password().is_none(), "{status}");
            assert_eq!(login.password_status.as_str(), status);
            if let Some(known) = known {
                assert_eq!(login.password_status, known, "{status}");
            }
        }
        assert_eq!(
            read(&json!({ "username": "ubuntu", "password": null, "passwordStatus": "deleted" }))
                .password_status,
            PasswordStatus::Deleted
        );
    }

    #[test]
    fn a_password_that_is_not_text_is_none_and_never_quoted() {
        for odd in [
            json!(100_001),
            json!({ "value": PASSWORD }),
            json!([PASSWORD]),
            json!(null),
        ] {
            let login = read(&json!({
                "username": "ubuntu", "password": odd, "passwordStatus": "visible"
            }));
            assert!(login.password().is_none(), "{odd}");
        }
        // No password member at all: none.
        let missing = read(&json!({ "username": "ubuntu", "passwordStatus": "visible" }));
        assert!(missing.password().is_none());
        // A reply that cannot be read is said without the password.
        let text = json!({ "success": true, "data": {
            "username": 100_001, "password": PASSWORD, "passwordStatus": "visible"
        }})
        .to_string();
        let e = reply::<FirstLogin>(200, &text).expect_err("not read");
        assert!(!e.to_string().contains(PASSWORD), "{e}");
    }

    #[test]
    fn debug_never_shows_the_password() {
        let login = read(&json!({
            "username": "ubuntu", "password": PASSWORD, "passwordStatus": "visible"
        }));
        let shown = format!("{login:?}");
        assert!(!shown.contains(PASSWORD), "{shown}");
        assert!(
            shown.contains("[redacted]") && shown.contains("ubuntu"),
            "{shown}"
        );
    }

    #[test]
    fn a_login_name_is_used_only_in_the_shape_ssh_takes() {
        let named = |username: &str| {
            read(&json!({ "username": username, "passwordStatus": "none" }))
                .login_name()
                .map(ToOwned::to_owned)
        };
        for good in [
            "ubuntu",
            "root",
            "_svc",
            "erpc-1",
            "erpc_1",
            &"a".repeat(32),
        ] {
            assert_eq!(named(good).as_deref(), Some(good), "{good:?}");
        }
        for bad in [
            "",
            "Ubuntu",
            "1ubuntu",
            "-oProxyCommand",
            "-ubuntu",
            "-lroot",
            "u$(id)",
            "$ubuntu",
            "ub\u{fc}ntu",
            "ubuntu@host",
            "uBuntu",
            "ub.untu",
            "ub untu",
            "ubuntu\n",
            &"a".repeat(33),
        ] {
            assert_eq!(named(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn refusals_are_the_accounts_with_their_reason_and_wait() {
        let refusal =
            |status: u16, body: &Value| match reply::<FirstLogin>(status, &body.to_string()) {
                Err(WorkerError::Refused(r)) => r,
                other => panic!("not a refusal: {other:?}"),
            };
        let gone: Refusal = refusal(
            409,
            &json!({ "success": false, "code": "credential_unavailable",
                "message": "no login", "data": { "reason": "server_gone" } }),
        );
        assert_eq!(gone.code, Some(Code::CredentialUnavailable));
        assert_eq!(gone.reason().as_deref(), Some("server_gone"));
        let missing = refusal(
            404,
            &json!({ "success": false, "code": "server_not_found", "message": "no server" }),
        );
        assert_eq!(missing.code, Some(Code::ServerNotFound));
        let busy = refusal(
            429,
            &json!({ "success": false, "code": "rate_limited", "message": "slow down",
                "data": { "retryAfter": 6 } }),
        );
        assert_eq!(busy.code, Some(Code::RateLimited));
        assert_eq!(busy.retry_after(), Some(6));
    }
}
