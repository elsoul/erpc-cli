// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! ERPC Global Storage: usage and the plan, the files kept, the storage
//! access keys restic signs in with, and buying or changing the plan with
//! ERPC Credit.
//!
//! Every route is a constant under [`BASE`] and goes through
//! [`AuthClient`], so the destination allowlist covers it. The session is
//! the one `erpc login` holds; user-api treats it as a signed-in session,
//! which is what the access-key routes require.
//!
//! user-api meters every storage route against a monthly budget of write
//! and read operations per 5 GB unit. A spent budget, a sync asked for too
//! soon and a missing plan come back as their own [`StorageError`]
//! variants, so the command can say what to do rather than show a status.

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ApiError;

/// Where every storage route lives.
pub const BASE: &str = "https://user-api.erpc.global/v3/storage";

/// Capacity, files and this month's operation budgets.
pub const USAGE_URL: &str = "https://user-api.erpc.global/v3/storage/usage";

/// The storage plan held, if any.
pub const SUBSCRIPTION_URL: &str = "https://user-api.erpc.global/v3/storage/subscription";

/// The files, a page at a time.
pub const LIST_URL: &str = "https://user-api.erpc.global/v3/storage/list";

/// Deletes one file.
pub const DELETE_URL: &str = "https://user-api.erpc.global/v3/storage/delete";

/// Recounts the usage from what is actually stored.
pub const SYNC_URL: &str = "https://user-api.erpc.global/v3/storage/sync";

/// Storage access keys: list and create here, revoke under it by id.
pub const ACCESS_KEYS_URL: &str = "https://user-api.erpc.global/v3/storage/access-keys";

/// Starts a plan paid from ERPC Credit.
pub const START_PLAN_URL: &str = "https://user-api.erpc.global/v3/storage/start-credit-recurring";

/// Ends a plan paid from ERPC Credit.
pub const END_PLAN_URL: &str = "https://user-api.erpc.global/v3/storage/end-credit-recurring";

/// Changes the capacity of the plan held.
pub const UPGRADE_PLAN_URL: &str = "https://user-api.erpc.global/v3/storage/upgrade-plan";

/// Starts an upload that is sent a part at a time.
pub const MULTIPART_CREATE_URL: &str = "https://user-api.erpc.global/v3/storage/multipart/create";

/// Sends one part of an upload.
pub const MULTIPART_PART_URL: &str =
    "https://user-api.erpc.global/v3/storage/multipart/upload-part";

/// Puts the parts of an upload together into the file.
pub const MULTIPART_COMPLETE_URL: &str =
    "https://user-api.erpc.global/v3/storage/multipart/complete";

/// Streams a file back, honouring `Range`.
pub const DOWNLOAD_URL: &str = "https://user-api.erpc.global/v3/storage/download";

/// How long one part, or one download, may take: long, because a part is
/// tens of megabytes and a download can be gigabytes on a slow link.
pub const TRANSFER_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(3600);

/// The regions user-api keeps files in.
pub const REGIONS: [&str; 5] = ["eu", "asia", "us-east", "us-west", "oc"];

/// Gigabytes in one unit, the step a plan is bought in.
pub const GB_PER_UNIT: u64 = 5;

/// What a storage request can come back with, besides the reply.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The request failed, or user-api refused it for a reason of its own.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// This month's write or read operations are used up.
    #[error(
        "this month's {budget} operations are used up ({used} of {limit}); they reset at {resets_at}"
    )]
    BudgetExhausted {
        /// `write` or `read`.
        budget: String,
        /// Operations used this month.
        used: u64,
        /// Operations the plan allows a month.
        limit: u64,
        /// When the budget starts again, as user-api wrote it.
        resets_at: String,
    },
    /// `sync` was run less than ten minutes ago.
    #[error(
        "usage was recounted a moment ago; it can be recounted again in {retry_after_seconds} s"
    )]
    SyncThrottled {
        /// Seconds until it may be asked again.
        retry_after_seconds: u64,
    },
    /// There is no storage plan, or its capacity is 0.
    #[error("{0}")]
    NoPlan(String),
    /// Starting or changing the plan needs more ERPC Credit than there is.
    #[error("{0}")]
    InsufficientCredit(String),
    /// A plan is already held; change it rather than buy another.
    #[error("{0}")]
    PlanExists(String),
    /// The account has not done the one-time card authentication that
    /// buying and using storage need.
    #[error("{0}")]
    PaymentAuthRequired(String),
}

/// Capacity, files and operation budgets, as `GET /usage` returns them.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Usage {
    /// Bytes stored.
    #[serde(default)]
    pub used_bytes: u64,
    /// Files stored.
    #[serde(default)]
    pub file_count: u64,
    /// Bytes the plan allows; 0 without a plan.
    #[serde(default)]
    pub storage_limit_bytes: u64,
    /// The default region; empty without a plan.
    #[serde(default)]
    pub region: String,
    /// Bytes and files per region.
    #[serde(default)]
    pub region_usage: std::collections::BTreeMap<String, RegionUsage>,
    /// This month's operation budgets. Absent from a user-api that does
    /// not meter yet.
    #[serde(default)]
    pub operation_budget: Option<OperationBudget>,
}

/// One region's share.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RegionUsage {
    /// Bytes stored there.
    #[serde(default)]
    pub used_bytes: u64,
    /// Files stored there.
    #[serde(default)]
    pub file_count: u64,
}

/// The month's write and read budgets.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct OperationBudget {
    /// The month they count, as user-api names it.
    #[serde(default)]
    pub period: String,
    /// When they start again.
    #[serde(default)]
    pub resets_at: String,
    /// The 5 GB units they are for.
    #[serde(default)]
    pub units: u64,
    /// Writes: uploads, deletes, listings.
    #[serde(default)]
    pub write: Budget,
    /// Reads: downloads and checks.
    #[serde(default)]
    pub read: Budget,
}

/// Used and allowed, for one kind of operation.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[non_exhaustive]
pub struct Budget {
    /// Used this month.
    #[serde(default)]
    pub used: u64,
    /// Allowed a month.
    #[serde(default)]
    pub limit: u64,
}

/// One page of files.
#[derive(Debug, Clone, Default, Deserialize)]
#[non_exhaustive]
pub struct ListPage {
    /// The files on this page.
    #[serde(default)]
    pub files: Vec<StoredFile>,
    /// Where the next page starts, when there is one.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Whether there are more pages.
    #[serde(default)]
    pub truncated: bool,
}

/// A stored file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct StoredFile {
    /// Its path in the account's storage.
    #[serde(default)]
    pub path: String,
    /// Its size in bytes.
    #[serde(default)]
    pub size: u64,
    /// When it was last written.
    #[serde(default)]
    pub last_modified: String,
    /// The region it is kept in.
    #[serde(default)]
    pub region: Option<String>,
}

/// A storage access key as listed: never with its secret.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AccessKey {
    /// The number user-api revokes it by.
    #[serde(default)]
    pub id: u64,
    /// The id restic signs in with (`erpcsk_…`).
    #[serde(default)]
    pub access_key_id: String,
    /// `read_write`, `append_only` or `read_only`.
    #[serde(default)]
    pub permission: String,
    /// The label it was made with.
    #[serde(default)]
    pub label: Option<String>,
    /// When it was made.
    #[serde(default)]
    pub created_at: String,
    /// When it was last used, if user-api says.
    #[serde(default)]
    pub last_used_at: Option<String>,
}

/// A key just made, with the secret user-api shows this once only.
#[derive(Debug)]
#[non_exhaustive]
pub struct NewAccessKey {
    /// The key as it will be listed.
    pub key: AccessKey,
    /// Its secret.
    pub secret: SecretString,
}

/// What a storage access key may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Everything, deleting included. For pruning.
    ReadWrite,
    /// Add, and read; delete only lock files. For scheduled backups.
    AppendOnly,
    /// Read only. For restoring.
    ReadOnly,
}

impl Permission {
    /// The name user-api uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "read_write",
            Self::AppendOnly => "append_only",
            Self::ReadOnly => "read_only",
        }
    }
}

/// How often a plan is paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cadence {
    /// Every month.
    Monthly,
    /// Once a year.
    Annual,
}

impl Cadence {
    /// The name user-api uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Monthly => "monthly",
            Self::Annual => "annual",
        }
    }
}

/// An upload under way: where its parts go.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Upload {
    /// The upload's id.
    pub upload_id: String,
    /// The object it becomes.
    pub key: String,
    /// The region it goes to.
    pub region: String,
}

/// A part user-api has stored.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Part {
    /// Its number, from 1.
    pub part_number: u32,
    /// Its tag, which completing the upload names it by.
    pub etag: String,
}

/// Starts an upload of `file_size` bytes to `path`. user-api refuses one
/// that would not fit.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn upload_start(
    client: &AuthClient,
    access_token: &SecretString,
    path: &str,
    file_size: u64,
    region: Option<&str>,
    content_type: Option<&str>,
) -> Result<Upload, StorageError> {
    let mut body = json!({ "path": path, "fileSize": file_size });
    if let Some(region) = region {
        body["region"] = json!(region);
    }
    if let Some(content_type) = content_type {
        body["contentType"] = json!(content_type);
    }
    let value = post(client, access_token, MULTIPART_CREATE_URL, &body, None).await?;
    serde_json::from_value(value).map_err(|e| ApiError::Malformed(e.to_string()).into())
}

/// Sends part `part_number` of `upload`.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn upload_part(
    client: &AuthClient,
    access_token: &SecretString,
    upload: &Upload,
    part_number: u32,
    bytes: Vec<u8>,
) -> Result<Part, StorageError> {
    let number = part_number.to_string();
    let url = with_query(
        MULTIPART_PART_URL,
        &[
            ("uploadId", Some(&upload.upload_id)),
            ("key", Some(&upload.key)),
            ("partNumber", Some(&number)),
            ("region", Some(&upload.region)),
        ],
    )?;
    let (status, text) = client
        .post_bytes_with_token(
            Audience::AuthApi,
            &url,
            access_token,
            bytes,
            TRANSFER_TIMEOUT,
        )
        .await
        .map_err(ApiError::from)?;
    let value = classify(status, &text)?;
    serde_json::from_value(value).map_err(|e| ApiError::Malformed(e.to_string()).into())
}

/// Puts `parts` together into the file.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn upload_finish(
    client: &AuthClient,
    access_token: &SecretString,
    upload: &Upload,
    parts: &[Part],
) -> Result<(), StorageError> {
    let body = json!({
        "uploadId": upload.upload_id,
        "key": upload.key,
        "region": upload.region,
        "parts": parts.iter().map(|p| json!({ "partNumber": p.part_number, "etag": p.etag })).collect::<Vec<_>>(),
    });
    post(client, access_token, MULTIPART_COMPLETE_URL, &body, None)
        .await
        .map(drop)
}

/// Opens the file at `path` for reading, from byte `from` on when given.
/// The caller reads the body; a refusal has been turned into its error.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused, and
/// [`ApiError::Malformed`] when a range was asked for and the whole file
/// came back.
pub async fn download(
    client: &AuthClient,
    access_token: &SecretString,
    path: &str,
    region: Option<&str>,
    from: Option<u64>,
) -> Result<erpc_auth::client::Streamed, StorageError> {
    let url = with_query(DOWNLOAD_URL, &[("path", Some(path)), ("region", region)])?;
    let streamed = client
        .get_streaming(
            Audience::AuthApi,
            &url,
            access_token,
            from,
            TRANSFER_TIMEOUT,
        )
        .await
        .map_err(ApiError::from)?;
    match streamed.status {
        200 if from.is_none_or(|f| f == 0) => Ok(streamed),
        206 if from.is_some() => Ok(streamed),
        200 | 206 => Err(ApiError::Malformed(
            "the download did not start where it was asked to".to_owned(),
        )
        .into()),
        status => {
            let text = streamed.text().await;
            classify(status, &text)?;
            Err(ApiError::Status(status).into())
        }
    }
}

/// Reads the usage.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn usage(
    client: &AuthClient,
    access_token: &SecretString,
) -> Result<Usage, StorageError> {
    let value = get(client, access_token, USAGE_URL).await?;
    serde_json::from_value(value).map_err(|e| ApiError::Malformed(e.to_string()).into())
}

/// Reads the plan held, as user-api returns it.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn subscription(
    client: &AuthClient,
    access_token: &SecretString,
) -> Result<Value, StorageError> {
    get(client, access_token, SUBSCRIPTION_URL).await
}

/// Reads one page of files under `prefix`, starting at `cursor`.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn list(
    client: &AuthClient,
    access_token: &SecretString,
    prefix: Option<&str>,
    region: Option<&str>,
    limit: Option<u32>,
    cursor: Option<&str>,
) -> Result<ListPage, StorageError> {
    let limit = limit.map(|l| l.to_string());
    let url = with_query(
        LIST_URL,
        &[
            ("prefix", prefix),
            ("region", region),
            ("limit", limit.as_deref()),
            ("cursor", cursor),
        ],
    )?;
    let value = get(client, access_token, &url).await?;
    serde_json::from_value(value).map_err(|e| ApiError::Malformed(e.to_string()).into())
}

/// Deletes the file at `path`.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn delete(
    client: &AuthClient,
    access_token: &SecretString,
    path: &str,
    region: Option<&str>,
) -> Result<(), StorageError> {
    let mut body = json!({ "path": path });
    if let Some(region) = region {
        body["region"] = json!(region);
    }
    let (status, text) = client
        .delete_with_token(
            Audience::AuthApi,
            DELETE_URL,
            access_token,
            Some(encode(&body)?),
        )
        .await
        .map_err(ApiError::from)?;
    classify(status, &text).map(drop)
}

/// Recounts the usage from what is stored, in `region` or all of them.
///
/// # Errors
///
/// [`StorageError::SyncThrottled`] within ten minutes of the last one, and
/// [`StorageError`] when the request fails or is refused.
pub async fn sync(
    client: &AuthClient,
    access_token: &SecretString,
    region: Option<&str>,
) -> Result<Value, StorageError> {
    let body = region.map_or_else(|| json!({}), |r| json!({ "region": r }));
    post(client, access_token, SYNC_URL, &body, None).await
}

/// Lists the active storage access keys.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn access_keys(
    client: &AuthClient,
    access_token: &SecretString,
) -> Result<Vec<AccessKey>, StorageError> {
    let value = get(client, access_token, ACCESS_KEYS_URL).await?;
    let list = value.get("data").cloned().unwrap_or(value);
    serde_json::from_value(list).map_err(|e| ApiError::Malformed(e.to_string()).into())
}

/// Makes a storage access key.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused, and
/// [`ApiError::Malformed`] when the reply has no secret.
pub async fn create_access_key(
    client: &AuthClient,
    access_token: &SecretString,
    label: Option<&str>,
    permission: Permission,
) -> Result<NewAccessKey, StorageError> {
    let mut body = json!({ "permission": permission.as_str() });
    if let Some(label) = label {
        body["label"] = json!(label);
    }
    let value = post(client, access_token, ACCESS_KEYS_URL, &body, None).await?;
    parse_new_key(value)
}

/// Revokes the storage access key `id`. Revoking one already revoked is
/// not an error.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn revoke_access_key(
    client: &AuthClient,
    access_token: &SecretString,
    id: u64,
) -> Result<(), StorageError> {
    let url = format!("{ACCESS_KEYS_URL}/{id}");
    let (status, text) = client
        .delete_with_token(Audience::AuthApi, &url, access_token, None)
        .await
        .map_err(ApiError::from)?;
    classify(status, &text).map(drop)
}

/// Starts a plan of `units` × 5 GB, paid from ERPC Credit: the first
/// period is debited at once, the next ones when they fall due.
///
/// user-api takes no idempotency key here. A second start while the first
/// is under way, or once a plan is held, is refused with 409, so sending
/// it again does not buy twice.
///
/// # Errors
///
/// [`StorageError::InsufficientCredit`], [`StorageError::PlanExists`], and
/// [`StorageError`] when the request fails or is refused otherwise.
pub async fn start_plan(
    client: &AuthClient,
    access_token: &SecretString,
    units: u32,
    cadence: Cadence,
    region: Option<&str>,
) -> Result<Value, StorageError> {
    let mut body = json!({ "units": units, "cadence": cadence.as_str() });
    if let Some(region) = region {
        body["region"] = json!(region);
    }
    post(client, access_token, START_PLAN_URL, &body, None).await
}

/// Ends the plan paid from ERPC Credit with `user_product_id`.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn end_plan(
    client: &AuthClient,
    access_token: &SecretString,
    user_product_id: u64,
) -> Result<Value, StorageError> {
    let body = json!({ "userProductId": user_product_id });
    post(client, access_token, END_PLAN_URL, &body, None).await
}

/// Changes the plan held to `units` × 5 GB. Only a plan paid by card can
/// be resized; one paid from ERPC Credit answers 409.
///
/// # Errors
///
/// [`StorageError`] when the request fails or is refused.
pub async fn upgrade_plan(
    client: &AuthClient,
    access_token: &SecretString,
    units: u32,
) -> Result<Value, StorageError> {
    let body = json!({ "quantity": units });
    post(client, access_token, UPGRADE_PLAN_URL, &body, None).await
}

async fn get(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
) -> Result<Value, StorageError> {
    let (status, text) = client
        .get_with_token(Audience::AuthApi, url, access_token)
        .await
        .map_err(ApiError::from)?;
    classify(status, &text)
}

async fn post(
    client: &AuthClient,
    access_token: &SecretString,
    url: &str,
    body: &Value,
    idempotency_key: Option<&str>,
) -> Result<Value, StorageError> {
    let (status, text) = client
        .post_with_token(
            Audience::AuthApi,
            url,
            access_token,
            encode(body)?,
            idempotency_key,
        )
        .await
        .map_err(ApiError::from)?;
    classify(status, &text)
}

fn encode(body: &Value) -> Result<Vec<u8>, StorageError> {
    serde_json::to_vec(body).map_err(|e| ApiError::Malformed(e.to_string()).into())
}

/// `url` with each present value of `query` after it, percent-encoded, so a
/// path with spaces, `&` or `#` stays one value.
fn with_query(url: &str, query: &[(&str, Option<&str>)]) -> Result<String, StorageError> {
    let mut parsed = reqwest::Url::parse(url).map_err(|e| ApiError::Malformed(e.to_string()))?;
    {
        let mut pairs = parsed.query_pairs_mut();
        for (name, value) in query {
            if let Some(value) = value {
                pairs.append_pair(name, value);
            }
        }
    }
    let mut out = String::from(parsed);
    if out.ends_with('?') {
        out.pop();
    }
    Ok(out)
}

/// Turns a reply into its body, or the error it stands for.
fn classify(status: u16, text: &str) -> Result<Value, StorageError> {
    let body: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        return Ok(body);
    }
    let code = body.get("code").and_then(Value::as_str).unwrap_or_default();
    let message = message_of(&body);
    match (status, code) {
        (401, _) => Err(ApiError::Unauthorized.into()),
        (429, "storage_operation_budget_exhausted") => Err(StorageError::BudgetExhausted {
            budget: string_of(&body, "budget"),
            used: number_of(&body, "used"),
            limit: number_of(&body, "limit"),
            resets_at: string_of(&body, "resetsAt"),
        }),
        (429, "storage_sync_throttled") => Err(StorageError::SyncThrottled {
            retry_after_seconds: number_of(&body, "retryAfterSeconds"),
        }),
        (400, "PAYMENT_AUTH_REQUIRED") => Err(StorageError::PaymentAuthRequired(
            message.unwrap_or_else(|| "the one-time card authentication is not done".to_owned()),
        )),
        (400, _)
            if message
                .as_deref()
                .is_some_and(|m| m.contains("card authentication")) =>
        {
            Err(StorageError::PaymentAuthRequired(
                message.unwrap_or_default(),
            ))
        }
        (402, _) => Err(StorageError::InsufficientCredit(message.unwrap_or_else(
            || "there is not enough ERPC Credit for this plan".to_owned(),
        ))),
        (409, "STORAGE_SUBSCRIPTION_EXISTS") => {
            Err(StorageError::PlanExists(message.unwrap_or_else(|| {
                "this account already has a storage plan".to_owned()
            })))
        }
        (403, _)
            if message
                .as_deref()
                .is_some_and(|m| m.to_ascii_lowercase().contains("subscription")) =>
        {
            Err(StorageError::NoPlan(message.unwrap_or_default()))
        }
        (status, _) => Err(match message {
            Some(message) => ApiError::Refused { status, message },
            None => ApiError::Status(status),
        }
        .into()),
    }
}

/// The server's message, cut to one printable line.
fn message_of(body: &Value) -> Option<String> {
    let text = body
        .get("message")
        .or_else(|| body.get("error"))
        .and_then(Value::as_str)?;
    let line: String = text
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(300)
        .collect();
    (!line.is_empty()).then_some(line)
}

fn string_of(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn number_of(body: &Value, key: &str) -> u64 {
    body.get(key).and_then(Value::as_u64).unwrap_or_default()
}

fn parse_new_key(value: Value) -> Result<NewAccessKey, StorageError> {
    let object = value.get("data").cloned().unwrap_or(value);
    let secret = object
        .get("secret")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| SecretString::from(s.to_owned()))
        .ok_or_else(|| ApiError::Malformed("the new key came back without its secret".into()))?;
    let mut shown = object;
    if let Some(map) = shown.as_object_mut() {
        map.remove("secret");
        map.remove("resticUrl");
    }
    let key: AccessKey =
        serde_json::from_value(shown).map_err(|e| ApiError::Malformed(e.to_string()))?;
    if key.access_key_id.is_empty() {
        return Err(ApiError::Malformed("the new key came back without its id".into()).into());
    }
    Ok(NewAccessKey { key, secret })
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::*;

    const URLS: [&str; 13] = [
        MULTIPART_CREATE_URL,
        MULTIPART_PART_URL,
        MULTIPART_COMPLETE_URL,
        DOWNLOAD_URL,
        USAGE_URL,
        SUBSCRIPTION_URL,
        LIST_URL,
        DELETE_URL,
        SYNC_URL,
        ACCESS_KEYS_URL,
        START_PLAN_URL,
        END_PLAN_URL,
        UPGRADE_PLAN_URL,
    ];

    #[test]
    fn every_route_is_a_declared_host_the_session_may_go_to() {
        for url in URLS {
            assert!(url.starts_with(BASE), "{url}");
            assert!(
                erpc_core::endpoints::ensure_service_url(url).is_ok(),
                "{url}"
            );
            assert!(
                erpc_auth::allowlist::ensure_token_destination(Audience::AuthApi, url).is_ok(),
                "{url}"
            );
        }
    }

    #[test]
    fn a_path_in_the_query_stays_one_value() {
        let url = with_query(
            LIST_URL,
            &[
                ("prefix", Some("a b/&c#d")),
                ("region", None),
                ("limit", Some("5")),
            ],
        )
        .expect("builds");
        assert_eq!(url, format!("{LIST_URL}?prefix=a+b%2F%26c%23d&limit=5"));
        assert_eq!(
            with_query(LIST_URL, &[("prefix", None)]).expect("builds"),
            LIST_URL
        );
    }

    #[test]
    fn a_spent_budget_says_which_and_when_it_resets() {
        let body = r#"{"success":false,"code":"storage_operation_budget_exhausted","budget":"write","used":20000,"limit":20000,"resetsAt":"2026-11-01T00:00:00.000Z","message":"x"}"#;
        match classify(429, body) {
            Err(StorageError::BudgetExhausted {
                budget,
                used,
                limit,
                resets_at,
            }) => {
                assert_eq!(budget, "write");
                assert_eq!((used, limit), (20_000, 20_000));
                assert_eq!(resets_at, "2026-11-01T00:00:00.000Z");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_sync_asked_too_soon_says_how_long_to_wait() {
        let body = r#"{"success":false,"code":"storage_sync_throttled","retryAfterSeconds":412}"#;
        assert!(matches!(
            classify(429, body),
            Err(StorageError::SyncThrottled {
                retry_after_seconds: 412
            })
        ));
    }

    #[test]
    fn refusals_keep_their_meaning() {
        assert!(matches!(
            classify(401, "{}"),
            Err(StorageError::Api(ApiError::Unauthorized))
        ));
        assert!(matches!(
            classify(402, r#"{"message":"Insufficient credit"}"#),
            Err(StorageError::InsufficientCredit(m)) if m == "Insufficient credit"
        ));
        assert!(matches!(
            classify(
                409,
                r#"{"code":"STORAGE_SUBSCRIPTION_EXISTS","message":"held"}"#
            ),
            Err(StorageError::PlanExists(_))
        ));
        assert!(matches!(
            classify(403, r#"{"message":"No active storage subscription"}"#),
            Err(StorageError::NoPlan(_))
        ));
        assert!(matches!(
            classify(
                400,
                r#"{"success":false,"code":"PAYMENT_AUTH_REQUIRED","message":"Complete the card authentication"}"#
            ),
            Err(StorageError::PaymentAuthRequired(_))
        ));
        assert!(matches!(
            classify(
                400,
                r#"{"success":false,"message":"Complete the €5 card authentication before using EURC payments."}"#
            ),
            Err(StorageError::PaymentAuthRequired(_))
        ));
        assert!(matches!(
            classify(500, "<html>"),
            Err(StorageError::Api(ApiError::Status(500)))
        ));
    }

    #[test]
    fn a_server_message_is_one_printable_line() {
        let body = json!({ "message": "bad\u{1b}[2J thing\nsecond line" });
        assert_eq!(message_of(&body).as_deref(), Some("bad[2J thing"));
    }

    #[test]
    fn usage_reads_with_and_without_budgets() {
        let usage: Usage = serde_json::from_str(
            r#"{"usedBytes":10,"fileCount":2,"egressBytes":0,"storageLimitBytes":5368709120,"region":"eu",
                "monthlyAccessCount":3,"monthlyAccessLimit":20000,"regionUsage":{"eu":{"usedBytes":10,"fileCount":2}},
                "operationBudget":{"period":"2026-10","resetsAt":"2026-11-01T00:00:00.000Z","units":1,
                  "write":{"used":3,"limit":20000},"read":{"used":0,"limit":200000}}}"#,
        )
        .expect("parses");
        let budget = usage.operation_budget.expect("present");
        assert_eq!(
            (budget.units, budget.write.limit, budget.read.limit),
            (1, 20_000, 200_000)
        );
        assert_eq!(usage.region_usage["eu"].file_count, 2);
        let empty: Usage = serde_json::from_str(r#"{"usedBytes":0,"region":""}"#).expect("parses");
        assert!(empty.operation_budget.is_none());
    }

    #[test]
    fn a_new_key_keeps_its_secret_apart() {
        let key = parse_new_key(json!({
            "id": 7, "accessKeyId": "erpcsk_TESTONLY", "secret": "s3cr3t",
            "permission": "append_only", "label": "host", "createdAt": "2026-10-29T00:00:00Z",
            "resticUrl": "rest:<the url with the secret in it>"
        }))
        .expect("parses");
        assert_eq!(key.key.id, 7);
        assert_eq!(key.key.permission, "append_only");
        assert_eq!(key.secret.expose_secret(), "s3cr3t");
        assert!(!format!("{:?}", key.key).contains("s3cr3t"));
        assert!(parse_new_key(json!({ "id": 1, "accessKeyId": "erpcsk_x" })).is_err());
    }
}
