// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! An app's secrets kept sealed in the ERPC account, and the sealing keys
//! they are sealed to.
//!
//! A value is sealed on the machine that sets it, to the public keys of the
//! machines that may open it, and only the sealed form reaches the
//! account, which cannot open it: what is sent and read here is ciphertext
//! (`enc`, `ct`) and its record. Sealing and opening are not this module's;
//! it carries their result. Neither ciphertext nor a value is ever printed:
//! [`fmt::Debug`] redacts them, and the account never puts them in a
//! refusal.
//!
//! A secret has a version, and every put and delete is a compare-and-swap
//! on it, as an app's record is on its revision. Versions only grow, across
//! deletes: a name deleted at version `n` is made again expecting `n`, and
//! sealed for `n + 1`.
//!
//! [`fmt::Debug`]: core::fmt::Debug

use core::fmt;

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use serde_json::Value;

use super::money::path_id;
use super::{Refusal, SecretSummary, WorkerError, Written, app_url, get, post, put, reply, token};
use crate::ApiError;

/// The sealing keys of the account.
pub const SEAL_KEYS_URL: &str = "https://user-api.erpc.global/v3/worker/seal-keys";

open_enum! {
    /// Where a sealing key is in its life.
    SealKeyStatus {
        /// Registered by a machine, not yet approved in the dashboard.
        Pending = "pending",
        /// Approved: the dashboard seals to it.
        Approved = "approved",
        /// Revoked, for good: nothing is sealed to it, and what was is gone.
        Revoked = "revoked",
    }
}

open_enum! {
    /// How a secret was sealed.
    SealMode {
        /// By the dashboard, with no sender.
        Base = "base",
        /// By a machine's erpc, with that machine's key as the sender.
        Auth = "auth",
    }
}

open_enum! {
    /// Where a secret was set from.
    SetVia {
        /// The dashboard.
        Browser = "browser",
        /// erpc on a machine.
        ErpcCli = "erpc-cli",
    }
}

/// A sealing key of the account.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SealKey {
    /// Its id.
    pub id: String,
    /// Its public key: 32 bytes as unpadded base64url. `None` once revoked.
    #[serde(default)]
    pub public_key: Option<String>,
    /// `SHA256:` and the key's SHA-256 in unpadded base64, as the account
    /// computed it. A caller computes its own from the key's bytes and
    /// compares.
    pub fingerprint: String,
    /// The name the machine gave itself when it registered the key: the
    /// account's text, escaped before it is printed.
    #[serde(default)]
    pub label: Option<String>,
    /// Where it is in its life.
    pub status: SealKeyStatus,
    /// The address it was registered from.
    #[serde(default)]
    pub registered_ip: Option<String>,
    /// When it was registered.
    #[serde(default)]
    pub created_at: Option<String>,
    /// When it was approved.
    #[serde(default)]
    pub approved_at: Option<String>,
    /// When it was revoked.
    #[serde(default)]
    pub revoked_at: Option<String>,
}

/// A key registered, or found registered already, with the account it is
/// in: the account's own number, which a seal's associated data names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RegisteredKey {
    /// The key.
    #[serde(flatten)]
    pub key: SealKey,
    /// The account's number.
    pub user_id: u64,
}

/// An approved key a secret may be sealed to, as an app's secrets list it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ApprovedKey {
    /// Its id.
    pub id: String,
    /// Its public key.
    pub public_key: String,
    /// Its fingerprint, as the account computed it.
    pub fingerprint: String,
    /// The name the machine gave itself.
    #[serde(default)]
    pub label: Option<String>,
}

/// An app's secrets: their records, and the approved keys.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Secrets {
    /// The keys the account holds approved.
    #[serde(default)]
    pub approved_keys: Vec<ApprovedKey>,
    /// The secrets: names and versions, never values.
    #[serde(default)]
    pub secrets: Vec<SecretSummary>,
}

/// One value sealed to one key: the encapsulated key and the ciphertext,
/// both unpadded base64url. Never printed.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Seal {
    #[serde(rename = "sealKeyId")]
    key_id: String,
    enc: String,
    ct: String,
}

impl Seal {
    /// The value sealed to key `seal_key_id`.
    #[must_use]
    pub fn new(seal_key_id: impl Into<String>, enc: String, ct: String) -> Self {
        Self {
            key_id: seal_key_id.into(),
            enc,
            ct,
        }
    }
}

impl fmt::Debug for Seal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Seal")
            .field("key_id", &self.key_id)
            .field("enc", &"<redacted>")
            .field("ct", &"<redacted>")
            .finish()
    }
}

open_enum! {
    /// Why a secret is put.
    Purpose {
        /// A new value.
        Put = "put",
        /// The same value, sealed again to the keys trusted now.
        Reseal = "reseal",
    }
}

/// The body that puts a secret: its seals, one per key, from this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PutSecret {
    /// The version the secret is at, 0 for a name never set, or the
    /// version it was deleted at; the seals are for one more.
    pub expected_version: u64,
    /// The value sealed to each key, at most 8.
    pub seals: Vec<Seal>,
    /// This machine's key, the sender of every seal.
    pub sender_seal_key_id: String,
    /// Why.
    pub purpose: Purpose,
}

impl PutSecret {
    /// A put of `seals` from `sender_seal_key_id`, expecting the secret at
    /// `expected_version`.
    #[must_use]
    pub fn new(
        expected_version: u64,
        seals: Vec<Seal>,
        sender_seal_key_id: impl Into<String>,
        purpose: Purpose,
    ) -> Self {
        Self {
            expected_version,
            seals,
            sender_seal_key_id: sender_seal_key_id.into(),
            purpose,
        }
    }
}

/// One secret sealed to the key read for: its record and its seal. Never
/// printed whole: [`fmt::Debug`] redacts the seal.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SealedSecret {
    /// The setting's name.
    pub name: String,
    /// The version it was sealed for.
    pub version: u64,
    /// How it was sealed.
    pub seal_mode: SealMode,
    /// The sending machine's key, when sealed by a machine.
    #[serde(default)]
    pub sender_seal_key_id: Option<String>,
    /// Where it was set from.
    pub set_via: SetVia,
    /// When it last changed.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// The encapsulated key: unpadded base64url.
    pub enc: String,
    /// The ciphertext: unpadded base64url.
    pub ct: String,
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSecret")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("seal_mode", &self.seal_mode)
            .field("sender_seal_key_id", &self.sender_seal_key_id)
            .field("set_via", &self.set_via)
            .field("updated_at", &self.updated_at)
            .field("enc", &"<redacted>")
            .field("ct", &"<redacted>")
            .finish()
    }
}

/// An app's secrets sealed to one key: what a deploy opens.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Seals {
    /// The key they are sealed to.
    pub seal_key_id: String,
    /// The account's number.
    pub user_id: u64,
    /// The app's id, which the seals' associated data names.
    pub worker_id: String,
    /// The app.
    pub app: String,
    /// The secrets sealed to the key.
    #[serde(default)]
    pub secrets: Vec<SealedSecret>,
    /// The secrets with no seal to this key.
    #[serde(default)]
    pub missing: Vec<String>,
}

impl Refusal {
    /// The version the secret is at, on [`super::Code::RevisionConflict`]
    /// for a secret: for a name deleted, the version it was deleted at.
    #[must_use]
    pub fn current_version(&self) -> Option<u64> {
        self.data.get("currentVersion").and_then(Value::as_u64)
    }

    /// The keys that could not be used, on [`super::Code::SealKeyUnusable`].
    /// Each is kept only when it has the form of an id: safe to print.
    #[must_use]
    pub fn seal_key_ids(&self) -> Vec<String> {
        self.data
            .get("sealKeyIds")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .filter(|id| path_id(id).is_ok())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The URL of an app's secrets.
fn secrets_url(app: &str) -> Result<String, WorkerError> {
    Ok(format!("{}/secrets", app_url(app)?))
}

/// The URL that deletes secret `name` of `app` at `expected_version`.
fn delete_secret_url(app: &str, name: &str, expected_version: u64) -> Result<String, WorkerError> {
    Ok(format!(
        "{}?expectedVersion={expected_version}",
        secret_url(app, name)?
    ))
}

/// The URL of an app's seals to the key `seal_key_id`.
fn seals_url(app: &str, seal_key_id: &str) -> Result<String, WorkerError> {
    Ok(format!(
        "{}/seals?sealKeyId={}",
        app_url(app)?,
        path_id(seal_key_id)?
    ))
}

/// The URL that revokes the key `id`.
fn revoke_url(id: &str) -> Result<String, WorkerError> {
    Ok(format!("{SEAL_KEYS_URL}/{}/revoke", path_id(id)?))
}

/// The body that registers a public key, with the name the machine gives
/// itself.
fn register_body(public_key: &str, label: Option<&str>) -> Value {
    serde_json::json!({ "publicKey": public_key, "label": label })
}

/// The URL of secret `name` of `app`, once `name` can name one: a capital
/// letter or `_`, then capital letters, digits and `_`, up to 128
/// characters. Which names the account keeps for itself is checked where
/// the secret is declared; only what may go into a path is checked here.
fn secret_url(app: &str, name: &str) -> Result<String, WorkerError> {
    let b = name.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 128
        && matches!(b[0], b'A'..=b'Z' | b'_')
        && b.iter()
            .all(|c| matches!(c, b'A'..=b'Z' | b'0'..=b'9' | b'_'));
    if !ok {
        return Err(WorkerError::Name {
            what: "secret",
            name: name.to_owned(),
            rule: "up to 128 characters: a capital letter or `_`, then capital letters, digits \
                   and `_`",
        });
    }
    Ok(format!("{}/secrets/{name}", app_url(app)?))
}

/// The app's secrets, by name and version, and the keys approved to seal
/// to.
///
/// # Errors
///
/// [`super::Code::WorkerNotFound`] when there is no such app, and
/// [`WorkerError`] otherwise.
pub async fn list_secrets(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
) -> Result<Secrets, WorkerError> {
    let (status, text) = get(client, access_token, &secrets_url(app)?).await?;
    reply(status, &text).map(|w| w.record)
}

/// Puts the secret `name` of `app`: its value sealed to each key.
///
/// # Errors
///
/// [`super::Code::RevisionConflict`] with [`super::Refusal::current_version`]
/// when the secret is not at the version expected: seal again for one
/// more than that, the same ciphertext cannot be sent again.
/// [`super::Code::SealKeyUnusable`] when a key is revoked or not the
/// account's, [`super::Code::LimitExceeded`] at 64 secrets, and
/// [`WorkerError`] otherwise.
pub async fn put_secret(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    name: &str,
    body: &PutSecret,
) -> Result<Written<SecretSummary>, WorkerError> {
    let (status, text) = put(client, access_token, &secret_url(app, name)?, body).await?;
    reply(status, &text)
}

/// Deletes the secret `name` of `app` at `expected_version`, its seals with
/// it. Its version stays the account's: the name made again is sealed for
/// one more.
///
/// # Errors
///
/// [`super::Code::SecretNotFound`] when it is not there,
/// [`super::Code::RevisionConflict`] when it moved, and [`WorkerError`]
/// otherwise.
pub async fn delete_secret(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    name: &str,
    expected_version: u64,
) -> Result<super::Deleted, WorkerError> {
    let url = delete_secret_url(app, name, expected_version)?;
    let (status, text) = client
        .delete_with_token(Audience::AuthApi, &url, access_token, None)
        .await
        .map_err(ApiError::from)?;
    reply(status, &text).map(|w| w.record)
}

/// The app's secrets sealed to the key `seal_key_id`, this machine's.
///
/// # Errors
///
/// [`super::Code::SealKeyNotFound`] when the key is not the account's or is
/// revoked, and [`WorkerError`] otherwise.
pub async fn read_seals(
    client: &AuthClient,
    access_token: &SecretString,
    app: &str,
    seal_key_id: &str,
) -> Result<Seals, WorkerError> {
    let (status, text) = get(client, access_token, &seals_url(app, seal_key_id)?).await?;
    reply(status, &text).map(|w| w.record)
}

/// The account's sealing keys, revoked ones included.
///
/// # Errors
///
/// [`WorkerError`] when the request fails or is refused.
pub async fn list_seal_keys(
    client: &AuthClient,
    access_token: &SecretString,
) -> Result<Vec<SealKey>, WorkerError> {
    let (status, text) = get(client, access_token, SEAL_KEYS_URL).await?;
    reply(status, &text).map(|w| w.record)
}

/// Registers this machine's public key, pending until it is approved in the
/// dashboard. A key registered already is answered as it is, revoked or
/// not.
///
/// # Errors
///
/// [`super::Code::LimitExceeded`] at 8 pending keys,
/// [`super::Code::InvalidRequest`] for a key not of the form, and
/// [`WorkerError`] otherwise.
pub async fn register_seal_key(
    client: &AuthClient,
    access_token: &SecretString,
    public_key: &str,
    label: Option<&str>,
) -> Result<Written<RegisteredKey>, WorkerError> {
    let body = register_body(public_key, label);
    let (status, text) = post(client, access_token, SEAL_KEYS_URL, &body).await?;
    reply(status, &text)
}

/// Revokes the key `id`, for good: what was sealed to it is deleted.
///
/// # Errors
///
/// [`super::Code::SealKeyNotFound`] when it is not the account's, and
/// [`WorkerError`] otherwise.
pub async fn revoke_seal_key(
    client: &AuthClient,
    access_token: &SecretString,
    id: &str,
) -> Result<RegisteredKey, WorkerError> {
    let (status, text) = post(
        client,
        access_token,
        &revoke_url(id)?,
        &Value::Object(serde_json::Map::new()),
    )
    .await?;
    reply(status, &text).map(|w| w.record)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::worker::Code;

    const KEY_ID: &str = "e2d95b18-7a4c-4f03-b6e9-51c8a2d7f0b4";
    const APP: &str = "https://user-api.erpc.global/v3/worker/apps/pump-sniper";

    /// Text of the shape of a seal, assembled at run time: no literal here
    /// looks like key material.
    fn b64url(len: usize) -> String {
        "AbC-_9".chars().cycle().take(len).collect()
    }

    #[test]
    fn the_urls_are_the_accounts_and_check_what_goes_into_them() {
        assert_eq!(
            secrets_url("pump-sniper").expect("a url"),
            format!("{APP}/secrets")
        );
        assert_eq!(
            secret_url("pump-sniper", "API_TOKEN").expect("a url"),
            format!("{APP}/secrets/API_TOKEN")
        );
        assert_eq!(
            delete_secret_url("pump-sniper", "_X1", 3).expect("a url"),
            format!("{APP}/secrets/_X1?expectedVersion=3")
        );
        assert_eq!(
            seals_url("pump-sniper", KEY_ID).expect("a url"),
            format!("{APP}/seals?sealKeyId={KEY_ID}")
        );
        assert_eq!(
            revoke_url(KEY_ID).expect("a url"),
            format!("{SEAL_KEYS_URL}/{KEY_ID}/revoke")
        );
        for url in [
            SEAL_KEYS_URL.to_owned(),
            secrets_url("pump-sniper").expect("a url"),
        ] {
            assert!(erpc_core::endpoints::ensure_service_url(&url).is_ok());
        }
        for bad in ["", "api_token", "1TOKEN", "A-B", "A/../B", &"A".repeat(129)] {
            assert!(
                matches!(
                    secret_url("pump-sniper", bad),
                    Err(WorkerError::Name { .. })
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            seals_url("pump-sniper", "300003"),
            Err(WorkerError::Id)
        ));
        assert!(matches!(revoke_url("../x"), Err(WorkerError::Id)));
    }

    #[test]
    fn a_put_carries_the_seals_and_the_sender_and_never_prints_them() {
        let enc = b64url(43);
        let ct = b64url(40);
        let body = PutSecret::new(
            2,
            vec![Seal::new(KEY_ID, enc.clone(), ct.clone())],
            KEY_ID,
            Purpose::Put,
        );
        assert_eq!(
            serde_json::to_value(&body).expect("encodes"),
            json!({
                "expectedVersion": 2,
                "seals": [{ "sealKeyId": KEY_ID, "enc": enc, "ct": ct }],
                "senderSealKeyId": KEY_ID,
                "purpose": "put"
            })
        );
        let shown = format!("{body:?}");
        assert!(!shown.contains(&enc) && !shown.contains(&ct), "{shown}");
        assert_eq!(
            serde_json::to_value(Purpose::Reseal).expect("encodes"),
            json!("reseal")
        );
        assert_eq!(
            register_body(&enc, Some("deploy-laptop")),
            json!({ "publicKey": enc, "label": "deploy-laptop" })
        );
        assert_eq!(
            register_body(&enc, None),
            json!({ "publicKey": enc, "label": null })
        );
    }

    #[test]
    fn the_seals_of_a_key_are_read_and_never_printed() {
        let enc = b64url(43);
        let ct = b64url(30);
        let (status, text) = (
            200,
            json!({ "success": true, "message": "ok", "data": {
                "sealKeyId": KEY_ID, "userId": 100_001, "workerId": "6f1c2b9e-4d3a-4e8b-9a71-2c5d8e0f4b13",
                "app": "pump-sniper",
                "secrets": [{ "name": "API_TOKEN", "version": 2, "sealMode": "auth",
                              "senderSealKeyId": KEY_ID, "setVia": "erpc-cli",
                              "updatedAt": "2026-10-29T15:40:37.000Z", "enc": enc, "ct": ct }],
                "missing": ["OTHER_NAME"]
            } })
            .to_string(),
        );
        let seals: Seals = reply(status, &text).map(|w| w.record).expect("reads");
        assert_eq!(seals.user_id, 100_001);
        assert_eq!(seals.missing, ["OTHER_NAME"]);
        let secret = &seals.secrets[0];
        assert_eq!(
            (secret.seal_mode.clone(), secret.set_via.clone()),
            (SealMode::Auth, SetVia::ErpcCli)
        );
        assert_eq!(secret.enc, enc);
        let shown = format!("{seals:?}");
        assert!(!shown.contains(&enc) && !shown.contains(&ct), "{shown}");
    }

    #[test]
    fn keys_and_secrets_are_read_with_their_state() {
        let public = b64url(43);
        let (status, text) = (
            201,
            json!({ "success": true, "message": "ok", "data": {
                "id": KEY_ID, "publicKey": public, "fingerprint": "SHA256:x", "label": null,
                "status": "pending", "registeredIp": "198.51.100.7",
                "createdAt": "2026-10-29T15:40:37.000Z", "approvedAt": null, "revokedAt": null,
                "userId": 100_001
            } })
            .to_string(),
        );
        let w: Written<RegisteredKey> = reply(status, &text).expect("reads");
        assert!(w.created);
        assert_eq!(w.record.user_id, 100_001);
        assert_eq!(w.record.key.status, SealKeyStatus::Pending);
        assert_eq!(w.record.key.public_key.as_deref(), Some(public.as_str()));
        let revoked: SealKey = serde_json::from_value(json!({
            "id": KEY_ID, "publicKey": null, "fingerprint": "SHA256:x", "label": "old",
            "status": "revoked", "registeredIp": null, "createdAt": "2026-10-29T15:40:37.000Z",
            "approvedAt": null, "revokedAt": "2026-10-30T15:40:37.000Z"
        }))
        .expect("reads");
        assert_eq!(
            (revoked.status, revoked.public_key),
            (SealKeyStatus::Revoked, None)
        );
        let secrets: Secrets = serde_json::from_value(json!({
            "approvedKeys": [{ "id": KEY_ID, "publicKey": public, "fingerprint": "SHA256:x", "label": null }],
            "secrets": [{ "name": "API_TOKEN", "version": 2, "setVia": "browser", "sealMode": "base",
                          "senderSealKeyId": null, "sealedKeyIds": [KEY_ID], "missingKeyIds": [],
                          "updatedAt": "2026-10-29T15:40:37.000Z" }]
        }))
        .expect("reads");
        assert_eq!(secrets.approved_keys[0].id, KEY_ID);
        assert_eq!(secrets.secrets[0].sealed_key_ids, [KEY_ID]);
    }

    #[test]
    fn a_refused_put_says_the_version_and_the_keys_it_could_not_use() {
        let conflict = match reply::<Value>(
            409,
            &json!({ "success": false, "code": "revision_conflict", "message": "no",
                     "data": { "currentVersion": 5 } })
            .to_string(),
        ) {
            Err(WorkerError::Refused(r)) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(conflict.code, Some(Code::RevisionConflict));
        assert_eq!(conflict.current_version(), Some(5));
        let unusable = match reply::<Value>(
            409,
            &json!({ "success": false, "code": "seal_key_unusable", "message": "no",
                     "data": { "sealKeyIds": [KEY_ID, "not\u{1b}an-id"] } })
            .to_string(),
        ) {
            Err(WorkerError::Refused(r)) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(unusable.seal_key_ids(), [KEY_ID]);
    }
}
