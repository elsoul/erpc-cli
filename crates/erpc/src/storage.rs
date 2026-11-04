// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc storage` (`erpc st`): ERPC Global Storage from the terminal.
//!
//! The usage and the plan, the files kept, the storage access keys restic
//! signs in with, and buying a plan from ERPC Credit. Everything goes
//! through [`erpc_api::storage`] with the session `erpc login` holds.
//!
//! What comes back from the server is printed through [`clean`], so a file
//! name cannot carry a terminal escape sequence onto the screen.

use clap::Subcommand;
use erpc_api::storage::{self as api, Cadence, Permission, StorageError};
use erpc_auth::credential::CredKey;
use erpc_auth::{AuthClient, session as auth_session};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::session;

/// What `erpc storage` does.
#[derive(Subcommand)]
pub enum Action {
    /// Capacity, files, and this month's write and read operations.
    Usage,
    /// The storage plan this account holds.
    Plan,
    /// Upload a file, encrypted unless --no-encrypt.
    #[command(visible_alias = "upload")]
    Put {
        /// The file to upload.
        file: std::path::PathBuf,
        /// Its path in storage (default: the file's name).
        remote: Option<String>,
        /// The region it goes to (default: the plan's region).
        #[arg(long, value_parser = api::REGIONS)]
        region: Option<String>,
        /// Upload it as it is, readable by anyone who obtains the stored
        /// object.
        #[arg(long)]
        no_encrypt: bool,
    },
    /// Download a file, decrypting it if it was encrypted.
    #[command(visible_alias = "download", visible_alias = "dl")]
    Get {
        /// The file's path in storage, as `erpc storage ls` shows it.
        remote: String,
        /// Where to write it (default: the file's name, here).
        local: Option<std::path::PathBuf>,
        /// The region it is in (default: the plan's region).
        #[arg(long, value_parser = api::REGIONS)]
        region: Option<String>,
        /// Replace the local file if it exists.
        #[arg(long)]
        force: bool,
        /// Take a file that is not encrypted by erpc, as it is: one uploaded
        /// with --no-encrypt. Without it such a file is refused, since it
        /// may have been put in place of an encrypted one.
        #[arg(long)]
        plain: bool,
    },
    /// The key files are encrypted with.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// List stored files.
    #[command(visible_alias = "ls")]
    List {
        /// Only files whose path starts with this.
        prefix: Option<String>,
        /// Only this region (default: the plan's region).
        #[arg(long, value_parser = api::REGIONS, conflicts_with = "all_regions")]
        region: Option<String>,
        /// Every region. Costs five write operations instead of one.
        #[arg(long)]
        all_regions: bool,
        /// Stop after this many files.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Delete a stored file.
    #[command(visible_alias = "rm")]
    Delete {
        /// The file's path, as `erpc storage ls` shows it.
        path: String,
        /// The region it is in (default: the plan's region).
        #[arg(long, value_parser = api::REGIONS)]
        region: Option<String>,
        /// Delete without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Recount the usage from what is actually stored (once per 10 minutes).
    Sync {
        /// Only this region.
        #[arg(long, value_parser = api::REGIONS)]
        region: Option<String>,
    },
    /// Storage access keys, which restic signs in with.
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Buy a storage plan, paid from ERPC Credit.
    Buy {
        /// Capacity in GB: 5, 10, 15, … up to 5000.
        gb: u64,
        /// Pay a year at once instead of every month.
        #[arg(long)]
        annual: bool,
        /// The region files go to by default.
        #[arg(long, value_parser = api::REGIONS)]
        region: Option<String>,
        /// Buy without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Change the plan's capacity. Only a plan paid by card can be resized.
    #[command(visible_alias = "upgrade")]
    Resize {
        /// The new capacity in GB: 5, 10, 15, … up to 5000.
        gb: u64,
        /// Resize without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// What `erpc storage key` does.
#[derive(Subcommand)]
pub enum KeyAction {
    /// Which key this machine has, and where it is kept.
    Show,
    /// Print the key, to keep a copy away from this machine.
    Export {
        /// Print it. Required: anyone who sees it can read every encrypted
        /// file.
        #[arg(long)]
        show: bool,
    },
    /// Keep a key read from standard input: the one exported elsewhere.
    Import,
}

/// What `erpc storage keys` does.
#[derive(Subcommand)]
pub enum KeysAction {
    /// The active keys, without their secrets.
    List,
    /// Make a key. Its secret is shown this one time only.
    Create {
        /// A name to tell it by, such as the host it is for.
        #[arg(long)]
        label: Option<String>,
        /// What it may do.
        #[arg(long, value_enum, default_value_t = KeyPermission::AppendOnly)]
        permission: KeyPermission,
        /// Print the secret. Required: a secret on the screen can end up in
        /// scrollback or a recording, so it is shown only when asked for.
        #[arg(long)]
        show: bool,
    },
    /// Revoke a key, by the number `erpc storage keys list` shows.
    Revoke {
        /// The key's number.
        id: u64,
        /// Revoke without asking.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// What a key may do, as the command line names it.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum KeyPermission {
    /// Add and read, never delete history: for scheduled backups.
    AppendOnly,
    /// Read only: for restoring.
    ReadOnly,
    /// Everything, deleting included: for pruning.
    ReadWrite,
}

impl From<KeyPermission> for Permission {
    fn from(p: KeyPermission) -> Self {
        match p {
            KeyPermission::AppendOnly => Self::AppendOnly,
            KeyPermission::ReadOnly => Self::ReadOnly,
            KeyPermission::ReadWrite => Self::ReadWrite,
        }
    }
}

/// The most units user-api sells in one plan.
const MAX_UNITS: u64 = 1000;

/// Runs `erpc storage`.
#[allow(clippy::too_many_lines)] // one arm per command
pub async fn run(json: bool, action: Action) -> Outcome {
    if let Action::Key { action } = action {
        return key(json, &action);
    }
    let client = match AuthClient::new() {
        Ok(client) => client,
        Err(e) => return crate::error::classify(&e).into(),
    };
    let token = match access_token(&client).await {
        Ok(token) => token,
        Err(outcome) => return outcome,
    };
    let result = match action {
        Action::Usage => usage(&client, &token, json).await,
        Action::Plan => plan(&client, &token, json).await,
        Action::Put {
            file,
            remote,
            region,
            no_encrypt,
        } => {
            put(
                &client,
                &token,
                json,
                &file,
                remote.as_deref(),
                region.as_deref(),
                !no_encrypt,
            )
            .await
        }
        Action::Get {
            remote,
            local,
            region,
            force,
            plain,
        } => {
            get(
                &client,
                &token,
                json,
                &remote,
                local.as_deref(),
                region.as_deref(),
                GetFlags { force, plain },
            )
            .await
        }
        Action::Key { .. } => unreachable!("handled before signing in"),
        Action::List {
            prefix,
            region,
            all_regions,
            limit,
        } => {
            let region = match (region, all_regions) {
                (Some(region), _) => Some(region),
                (None, true) => None,
                (None, false) => plan_region(&client, &token).await,
            };
            list(
                &client,
                &token,
                json,
                prefix.as_deref(),
                region.as_deref(),
                limit,
            )
            .await
        }
        Action::Delete { path, region, yes } => {
            delete(&client, &token, json, &path, region.as_deref(), yes).await
        }
        Action::Sync { region } => sync(&client, &token, json, region.as_deref()).await,
        Action::Keys { action } => match action {
            KeysAction::List => keys_list(&client, &token, json).await,
            KeysAction::Create {
                label,
                permission,
                show,
            } => {
                keys_create(
                    &client,
                    &token,
                    json,
                    label.as_deref(),
                    permission.into(),
                    show,
                )
                .await
            }
            KeysAction::Revoke { id, yes } => keys_revoke(&client, &token, json, id, yes).await,
        },
        Action::Resize { gb, yes } => resize(&client, &token, json, gb, yes).await,
        Action::Buy {
            gb,
            annual,
            region,
            yes,
        } => buy(&client, &token, json, gb, annual, region.as_deref(), yes).await,
    };
    result.unwrap_or_else(Outcome::from)
}

/// The current access token from the store `erpc login` chose.
pub(crate) async fn access_token(client: &AuthClient) -> Result<SecretString, Outcome> {
    let path = session::config_path().map_err(Outcome::Failed)?;
    let config = crate::config::load(&path).map_err(Outcome::Failed)?;
    let selection = session::plan_store(None, config.credential_store);
    let store = crate::store_for(selection.kind, config.credential_vault.as_deref())
        .map_err(|e| Outcome::from(crate::error::classify(&e)))?;
    let key = CredKey::new(session::LOGIN_AUDIENCE, session::local_account());
    let state_dir = session::state_dir().map_err(Outcome::Failed)?;
    match auth_session::current_session(client, &store, &key, &state_dir, crate::commands::now())
        .await
    {
        Ok(credential) => Ok(credential.access_token),
        Err(erpc_auth::SessionError::NoSession) => {
            Err(CliError::new(Code::NotSignedIn, "not signed in").into())
        }
        Err(erpc_auth::SessionError::Expired) => Err(CliError::new(
            Code::NotSignedIn,
            "the session has expired or was signed out elsewhere",
        )
        .into()),
        Err(e) => Err(crate::error::classify(&e).into()),
    }
}

/// A storage refusal as the operator should read it, with what to do next.
pub(crate) fn refused(e: StorageError) -> CliError {
    match e {
        StorageError::Api(erpc_api::ApiError::Unauthorized) => {
            CliError::new(Code::NotSignedIn, "the session was refused")
        }
        StorageError::Api(erpc_api::ApiError::Http(e)) => crate::error::classify(&e),
        StorageError::NoPlan(_) => CliError::new(Code::Failed, "this account has no storage plan")
            .hint("buy one with `erpc storage buy 5`"),
        StorageError::BudgetExhausted { .. } => CliError::new(Code::Failed, e.to_string())
            .hint("`erpc storage usage` shows the budgets; a larger plan has larger ones"),
        StorageError::PaymentAuthRequired(_) => CliError::new(
            Code::Failed,
            "the one-time €5 card authentication is not done on this account",
        )
        .hint("do it once at https://dashboard.erpc.global, then run this again"),
        StorageError::InsufficientCredit(message) => CliError::new(Code::Failed, clean(&message))
            .hint("add ERPC Credit, for example with `erpc ai`, then run this again"),
        StorageError::PlanExists(_) => {
            CliError::new(Code::Failed, "this account already has a storage plan")
                .hint("`erpc storage plan` shows it")
        }
        other => CliError::new(Code::Failed, clean(&other.to_string())),
    }
}

impl From<StorageError> for Outcome {
    fn from(e: StorageError) -> Self {
        refused(e).into()
    }
}

async fn usage(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
) -> Result<Outcome, StorageError> {
    let usage = api::usage(client, token).await?;
    if json {
        crate::print_json(&json!({
            "usedBytes": usage.used_bytes,
            "fileCount": usage.file_count,
            "limitBytes": usage.storage_limit_bytes,
            "region": usage.region,
            "regions": usage.region_usage.iter().map(|(name, r)| {
                json!({ "region": name, "usedBytes": r.used_bytes, "fileCount": r.file_count })
            }).collect::<Vec<_>>(),
            "operationBudget": usage.operation_budget.as_ref().map(|b| json!({
                "period": b.period,
                "resetsAt": b.resets_at,
                "units": b.units,
                "write": { "used": b.write.used, "limit": b.write.limit },
                "read": { "used": b.read.used, "limit": b.read.limit },
            })),
        }));
        return Ok(Outcome::Done(String::new()));
    }
    if usage.storage_limit_bytes == 0 && usage.used_bytes == 0 {
        return Ok(Outcome::Done(
            "No storage plan on this account.\n  Buy one with `erpc storage buy 5` (5 GB, paid from ERPC Credit)."
                .to_owned(),
        ));
    }
    let mut out = Vec::new();
    out.push(format!(
        "Used        {} of {} ({}), {} file{}",
        bytes(usage.used_bytes),
        bytes(usage.storage_limit_bytes),
        percent(usage.used_bytes, usage.storage_limit_bytes),
        usage.file_count,
        if usage.file_count == 1 { "" } else { "s" }
    ));
    if usage.storage_limit_bytes == 0 {
        out.push(
            "            Capacity is 0: files can be read and downloaded, not written.".to_owned(),
        );
    }
    if !usage.region.is_empty() {
        out.push(format!("Region      {}", clean(&usage.region)));
    }
    if let Some(budget) = &usage.operation_budget {
        out.push(format!(
            "Writes      {} of {} this month",
            thousands(budget.write.used),
            thousands(budget.write.limit)
        ));
        out.push(format!(
            "Reads       {} of {} this month",
            thousands(budget.read.used),
            thousands(budget.read.limit)
        ));
        out.push(format!(
            "            both reset at {}",
            clean(&budget.resets_at)
        ));
    }
    if usage.region_usage.len() > 1 {
        out.push("By region".to_owned());
        for (name, r) in &usage.region_usage {
            out.push(format!(
                "  {:<9} {:>10}  {} files",
                clean(name),
                bytes(r.used_bytes),
                r.file_count
            ));
        }
    }
    Ok(Outcome::Done(out.join("\n")))
}

async fn plan(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
) -> Result<Outcome, StorageError> {
    let reply = api::subscription(client, token).await?;
    let held = reply.get("subscription").filter(|s| !s.is_null());
    if json {
        crate::print_json(&json!({
            "plan": held.cloned(),
            "heldCount": reply.get("heldCount").cloned().unwrap_or(Value::Null),
        }));
        return Ok(Outcome::Done(String::new()));
    }
    let Some(plan) = held else {
        return Ok(Outcome::Done(
            "No storage plan on this account.\n  Buy one with `erpc storage buy 5` (5 GB, paid from ERPC Credit)."
                .to_owned(),
        ));
    };
    let text = |key: &str| plan.get(key).and_then(Value::as_str).map(clean);
    let mut out = Vec::new();
    if let Some(gb) = plan.get("capacityGB").and_then(Value::as_u64) {
        out.push(format!("Capacity    {gb} GB"));
    }
    if let Some(status) = text("status") {
        out.push(format!("Status      {status}"));
    }
    let paid_by = match text("billing").as_deref() {
        Some("credit") => "ERPC Credit".to_owned(),
        Some("card") => "card".to_owned(),
        Some(other) => other.to_owned(),
        None => String::new(),
    };
    let cadence = text("cadence").unwrap_or_default();
    let price = plan
        .get("unitAmountCents")
        .and_then(Value::as_f64)
        .zip(plan.get("quantityUnits").and_then(Value::as_f64))
        .map(|(cents, units)| format!("€{:.2} ", cents * units / 100.0))
        .unwrap_or_default();
    out.push(format!("Paid        {price}{cadence}, by {paid_by}"));
    if let Some(end) = text("currentPeriodEnd") {
        out.push(format!("Renews      {end}"));
    }
    out.push(String::new());
    out.push(
        "To end the plan, use https://dashboard.erpc.global. It ends at once: files can be read but not added, and they may be deleted 30 days after a notice."
            .to_owned(),
    );
    Ok(Outcome::Done(out.join("\n")))
}

async fn list(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
    prefix: Option<&str>,
    region: Option<&str>,
    limit: Option<u32>,
) -> Result<Outcome, StorageError> {
    let mut files = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page_size = limit.map(|l| {
            l.saturating_sub(u32::try_from(files.len()).unwrap_or(u32::MAX))
                .clamp(1, 1000)
        });
        let page = api::list(client, token, prefix, region, page_size, cursor.as_deref()).await?;
        files.extend(page.files);
        let full = limit.is_some_and(|l| files.len() >= l as usize);
        match page.cursor {
            Some(next) if page.truncated && !full => cursor = Some(next),
            _ => break,
        }
    }
    if let Some(l) = limit {
        files.truncate(l as usize);
    }
    if json {
        crate::print_json(&json!({
            "files": files.iter().map(|f| json!({
                "path": f.path,
                "size": f.size,
                "lastModified": f.last_modified,
                "region": f.region,
            })).collect::<Vec<_>>(),
        }));
        return Ok(Outcome::Done(String::new()));
    }
    if files.is_empty() {
        return Ok(Outcome::Done("No files.".to_owned()));
    }
    let width = files
        .iter()
        .map(|f| clean(&f.path).chars().count())
        .max()
        .unwrap_or(4)
        .max(4);
    let mut out = vec![format!(
        "{:<width$}  {:>10}  {:<7}  MODIFIED",
        "PATH", "SIZE", "REGION"
    )];
    for f in &files {
        out.push(format!(
            "{:<width$}  {:>10}  {:<7}  {}",
            clean(&f.path),
            bytes(f.size),
            clean(f.region.as_deref().unwrap_or("")),
            clean(&f.last_modified)
        ));
    }
    Ok(Outcome::Done(out.join("\n")))
}

async fn delete(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
    path: &str,
    region: Option<&str>,
    yes: bool,
) -> Result<Outcome, StorageError> {
    if !yes {
        crate::interrupt::say(&format!(
            "Delete {} from storage. This cannot be undone.",
            clean(path)
        ));
    }
    if let Err(e) = crate::node_common::go_ahead(yes, "nothing was deleted") {
        return Ok(e.into());
    }
    api::delete(client, token, path, region).await?;
    if json {
        crate::print_json(&json!({ "deleted": path }));
        return Ok(Outcome::Done(String::new()));
    }
    Ok(Outcome::Done(format!("Deleted {}", clean(path))))
}

async fn sync(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
    region: Option<&str>,
) -> Result<Outcome, StorageError> {
    let reply = api::sync(client, token, region).await?;
    if json {
        crate::print_json(&reply);
        return Ok(Outcome::Done(String::new()));
    }
    let n = |key: &str| reply.get(key).and_then(Value::as_u64).unwrap_or_default();
    let corrected = reply
        .get("corrected")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(Outcome::Done(format!(
        "Stored      {} in {} files\nCounted     {} in {} files before\n{}",
        bytes(n("r2UsedBytes")),
        n("r2FileCount"),
        bytes(n("dbUsedBytes")),
        n("dbFileCount"),
        if corrected {
            "The count was corrected."
        } else {
            "The count was already right."
        }
    )))
}

async fn keys_list(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
) -> Result<Outcome, StorageError> {
    let keys = api::access_keys(client, token).await?;
    if json {
        crate::print_json(&json!({
            "keys": keys.iter().map(|k| json!({
                "id": k.id,
                "accessKeyId": k.access_key_id,
                "permission": k.permission,
                "label": k.label,
                "createdAt": k.created_at,
            })).collect::<Vec<_>>(),
        }));
        return Ok(Outcome::Done(String::new()));
    }
    if keys.is_empty() {
        return Ok(Outcome::Done("No storage access keys.".to_owned()));
    }
    let mut out = vec![format!(
        "{:>4}  {:<23}  {:<11}  {:<20}  CREATED",
        "ID", "ACCESS KEY", "PERMISSION", "LABEL"
    )];
    for k in &keys {
        out.push(format!(
            "{:>4}  {:<23}  {:<11}  {:<20}  {}",
            k.id,
            clean(&k.access_key_id),
            clean(&k.permission),
            clean(k.label.as_deref().unwrap_or("")),
            clean(&k.created_at)
        ));
    }
    Ok(Outcome::Done(out.join("\n")))
}

async fn keys_create(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
    label: Option<&str>,
    permission: Permission,
    show: bool,
) -> Result<Outcome, StorageError> {
    if !show {
        return Ok(CliError::new(
            Code::Usage,
            "a new key's secret is shown once, and only with --show",
        )
        .hint("`erpc backup init` makes and keeps the keys a backup needs; pass --show to make one by hand")
        .into());
    }
    if let Some(label) = label
        && (label.is_empty() || label.chars().count() > 64)
    {
        return Ok(CliError::new(Code::Usage, "a label is 1 to 64 characters").into());
    }
    let made = api::create_access_key(client, token, label, permission).await?;
    if json {
        crate::print_json(&json!({
            "id": made.key.id,
            "accessKeyId": made.key.access_key_id,
            "secret": made.secret.expose_secret(),
            "permission": made.key.permission,
            "label": made.key.label,
        }));
        return Ok(Outcome::Done(String::new()));
    }
    Ok(Outcome::Done(format!(
        "Key {}  ({}, id {})\nSecret      {}\n\nThe secret is shown this once. Keep it somewhere safe; it cannot be read again.\nrestic signs in with RESTIC_REST_USERNAME={} and RESTIC_REST_PASSWORD=<the secret>.",
        clean(&made.key.access_key_id),
        clean(&made.key.permission),
        made.key.id,
        made.secret.expose_secret(),
        clean(&made.key.access_key_id),
    )))
}

async fn keys_revoke(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
    id: u64,
    yes: bool,
) -> Result<Outcome, StorageError> {
    if !yes {
        crate::interrupt::say(&format!(
            "Revoke storage access key {id}. Anything signing in with it stops working."
        ));
    }
    if let Err(e) = crate::node_common::go_ahead(yes, "the key was not revoked") {
        return Ok(e.into());
    }
    api::revoke_access_key(client, token, id).await?;
    if json {
        crate::print_json(&json!({ "revoked": id }));
        return Ok(Outcome::Done(String::new()));
    }
    Ok(Outcome::Done(format!("Revoked storage access key {id}")))
}

/// The bytes in one uploaded part: user-api passes a part through in one
/// request, and every part but the last must be the same size.
const PART: usize = 32 * 1024 * 1024;

/// How many times a part, or a download, is tried before giving up.
const ATTEMPTS: u32 = 4;

/// The plan's region, which listing and transfers use unless told
/// otherwise: asking about one region costs one operation, about all of
/// them five. `None` when it cannot be read; user-api then picks.
async fn plan_region(client: &AuthClient, token: &SecretString) -> Option<String> {
    api::usage(client, token)
        .await
        .ok()
        .map(|u| u.region)
        .filter(|r| !r.is_empty())
}

/// Whether a failure is worth trying again: the network, or the server
/// having trouble, never a refusal.
fn transient(e: &StorageError) -> bool {
    match e {
        StorageError::Api(erpc_api::ApiError::Http(_)) => true,
        StorageError::Api(
            erpc_api::ApiError::Status(s) | erpc_api::ApiError::Refused { status: s, .. },
        ) => *s >= 500,
        _ => false,
    }
}

async fn pause(attempt: u32) {
    tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt))).await;
}

/// A line on stderr while a transfer runs, when someone is watching.
fn progress(done: u64, total: u64, verb: &str) {
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        crate::interrupt::say(&format!("  {verb} {} of {}", bytes(done), bytes(total)));
    }
}

#[allow(clippy::too_many_lines)] // one transfer, start to finish, read in order
async fn put(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
    file: &std::path::Path,
    remote: Option<&str>,
    region: Option<&str>,
    encrypt: bool,
) -> Result<Outcome, StorageError> {
    use std::io::Read as _;
    let usage_err = |m: String| Ok(CliError::new(Code::Usage, m).into());
    let meta = match std::fs::metadata(file) {
        Ok(meta) if meta.is_file() => meta,
        Ok(_) => return usage_err(format!("{} is not a file", file.display())),
        Err(e) => return usage_err(format!("cannot read {}: {e}", file.display())),
    };
    let remote = match remote {
        Some(r) => r.to_owned(),
        None => match file.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_owned(),
            None => {
                return usage_err(
                    "name the file's path in storage: erpc storage put <file> <path>".to_owned(),
                );
            }
        },
    };
    if remote.is_empty() || remote.chars().count() > 1000 || remote.chars().any(char::is_control) {
        return usage_err("a path in storage is 1 to 1000 printable characters".to_owned());
    }
    let plain_len = meta.len();
    let (size, key_note) = if encrypt {
        let (key, kind, made) = match crate::storage_key::load_or_create() {
            Ok(k) => k,
            Err(e) => {
                return Ok(CliError::new(Code::Failed, format!("no storage key: {e}"))
                    .hint("or upload it unencrypted with --no-encrypt")
                    .into());
            }
        };
        let note = made.then(|| {
            format!(
                "A new storage encryption key was made and kept in {}.\n  Without it the encrypted files cannot be read: keep a copy with `erpc storage key export --show`.",
                crate::storage_key::place(kind)
            )
        });
        (
            crate::storage_crypt::sealed_len(plain_len),
            Some((key, note)),
        )
    } else {
        if plain_len == 0 {
            return usage_err("an empty file is not uploaded".to_owned());
        }
        (plain_len, None)
    };
    let opened = match std::fs::File::open(file) {
        Ok(f) => f,
        Err(e) => return usage_err(format!("cannot read {}: {e}", file.display())),
    };
    let mut source: Box<dyn std::io::Read> = match &key_note {
        Some((key, _)) => match crate::storage_crypt::Sealer::new(opened, key) {
            Ok(sealer) => Box::new(sealer),
            Err(e) => return Ok(CliError::new(Code::Failed, e.to_string()).into()),
        },
        None => Box::new(opened),
    };
    if let Some((_, Some(note))) = &key_note {
        crate::interrupt::say(note);
    }
    let region = match region {
        Some(r) => Some(r.to_owned()),
        None => plan_region(client, token).await,
    };
    let upload = api::upload_start(
        client,
        token,
        &remote,
        size,
        region.as_deref(),
        Some(if encrypt {
            "application/octet-stream"
        } else {
            content_type(&remote)
        }),
    )
    .await?;
    let mut parts = Vec::new();
    let mut sent: u64 = 0;
    let mut number: u32 = 0;
    while sent < size {
        let want = usize::try_from((size - sent).min(PART as u64)).unwrap_or(PART);
        let mut chunk = vec![0u8; want];
        let mut filled = 0;
        while filled < want {
            match source.read(&mut chunk[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    return Ok(CliError::new(
                        Code::Failed,
                        format!("reading {}: {e}", file.display()),
                    )
                    .into());
                }
            }
        }
        if filled != want {
            return Ok(CliError::new(
                Code::Failed,
                format!(
                    "{} changed while it was being uploaded; nothing was stored",
                    file.display()
                ),
            )
            .into());
        }
        number += 1;
        let mut attempt = 0;
        let part = loop {
            match api::upload_part(client, token, &upload, number, chunk.clone()).await {
                Ok(part) => break part,
                Err(e) if transient(&e) && attempt + 1 < ATTEMPTS => {
                    attempt += 1;
                    pause(attempt).await;
                }
                Err(e) => return Err(e),
            }
        };
        parts.push(part);
        sent += want as u64;
        progress(sent, size, "sent");
    }
    // Anything still to read means the file grew while it was read.
    if source.read(&mut [0u8; 1]).map_or(true, |n| n > 0) {
        return Ok(CliError::new(
            Code::Failed,
            format!(
                "{} changed while it was being uploaded; nothing was stored",
                file.display()
            ),
        )
        .into());
    }
    api::upload_finish(client, token, &upload, &parts).await?;
    if json {
        crate::print_json(&json!({
            "path": remote,
            "region": upload.region,
            "bytes": plain_len,
            "storedBytes": size,
            "encrypted": encrypt,
        }));
        return Ok(Outcome::Done(String::new()));
    }
    Ok(Outcome::Done(format!(
        "Uploaded {} to {} ({}, {}{})",
        file.display(),
        clean(&remote),
        clean(&upload.region),
        bytes(plain_len),
        if encrypt {
            ", encrypted"
        } else {
            ", not encrypted"
        }
    )))
}

/// A Content-Type for an unencrypted file, from its name.
fn content_type(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "json" => "application/json",
        "txt" | "log" => "text/plain",
        "gz" | "tgz" => "application/gzip",
        "zst" => "application/zstd",
        "tar" => "application/x-tar",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// How `get` treats what is there.
#[derive(Clone, Copy)]
struct GetFlags {
    /// Replace a local file.
    force: bool,
    /// Take a file erpc did not encrypt.
    plain: bool,
}

/// Why a file that is not erpc's encrypted format is refused.
const NOT_SEALED: &str = "the file is not encrypted by erpc: it was uploaded with --no-encrypt, \
     or something else was put in its place; pass --plain to download it as it is";

/// Where a download is written as it arrives: straight to the file, or
/// through the decryption.
enum Sink<'k> {
    /// Not yet known: the first bytes decide. The key, or why there is
    /// none; and whether a file erpc did not encrypt is taken.
    Undecided(
        Vec<u8>,
        Result<&'k crate::storage_crypt::MasterKey, &'k str>,
        bool,
        tempfile::NamedTempFile,
    ),
    Plain(tempfile::NamedTempFile),
    Sealed(crate::storage_crypt::Opener<'k, tempfile::NamedTempFile>),
}

impl Sink<'_> {
    fn write(self, data: &[u8]) -> Result<Self, String> {
        match self {
            Self::Undecided(mut head, key, plain, file) => {
                head.extend_from_slice(data);
                if head.len() < crate::storage_crypt::MAGIC.len() {
                    return Ok(Self::Undecided(head, key, plain, file));
                }
                let next = if crate::storage_crypt::is_sealed(&head) {
                    Self::Sealed(crate::storage_crypt::Opener::new(file, key?))
                } else if plain {
                    Self::Plain(file)
                } else {
                    return Err(NOT_SEALED.to_owned());
                };
                next.write_now(&head)
            }
            other => other.write_now(data),
        }
    }

    fn write_now(mut self, data: &[u8]) -> Result<Self, String> {
        use std::io::Write as _;
        match &mut self {
            Self::Plain(file) => file.write_all(data).map_err(|e| e.to_string())?,
            Self::Sealed(opener) => opener.write_all(data).map_err(|e| e.to_string())?,
            Self::Undecided(..) => unreachable!("decided before writing"),
        }
        Ok(self)
    }

    /// The finished file, and whether it was decrypted.
    fn finish(self) -> Result<(tempfile::NamedTempFile, bool), String> {
        use std::io::Write as _;
        match self {
            Self::Undecided(head, _, plain, mut file) => {
                if !plain {
                    return Err(NOT_SEALED.to_owned());
                }
                file.write_all(&head).map_err(|e| e.to_string())?;
                Ok((file, false))
            }
            Self::Plain(file) => Ok((file, false)),
            Self::Sealed(opener) => Ok((opener.finish().map_err(|e| e.to_string())?, true)),
        }
    }
}

#[allow(clippy::too_many_lines)] // one transfer, start to finish, read in order
async fn get(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
    remote: &str,
    local: Option<&std::path::Path>,
    region: Option<&str>,
    flags: GetFlags,
) -> Result<Outcome, StorageError> {
    let force = flags.force;
    let target = match local {
        Some(path) => path.to_owned(),
        None => match remote
            .rsplit('/')
            .next()
            .filter(|n| !n.is_empty() && *n != "." && *n != "..")
        {
            Some(name) => std::path::PathBuf::from(name),
            None => {
                return Ok(CliError::new(
                    Code::Usage,
                    "say where to write it: erpc storage get <path> <file>",
                )
                .into());
            }
        },
    };
    if target.exists() && !force {
        return Ok(
            CliError::new(Code::Failed, format!("{} exists already", target.display()))
                .hint("pass --force to replace it, or name another file")
                .into(),
        );
    }
    let dir = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_owned(),
        _ => std::path::PathBuf::from("."),
    };
    // Written to a temporary file beside the target -- 0600, removed if
    // anything fails -- and renamed into place only when complete and, if
    // encrypted, verified to the last chunk.
    let temp = match tempfile::NamedTempFile::new_in(&dir) {
        Ok(t) => t,
        Err(e) => {
            return Ok(CliError::new(
                Code::Failed,
                format!("cannot write in {}: {e}", dir.display()),
            )
            .into());
        }
    };
    let key = match crate::storage_key::load() {
        Ok((Some(key), _)) => Ok(key),
        Ok((None, _)) => Err(
            "the file is encrypted and this machine has no storage key; \
             `erpc storage key import` the one it was encrypted with"
                .to_owned(),
        ),
        Err(e) => Err(format!(
            "the file is encrypted, and the storage key could not be read: {e}"
        )),
    };
    let region = match region {
        Some(r) => Some(r.to_owned()),
        None => plan_region(client, token).await,
    };
    let mut sink = Sink::Undecided(
        Vec::new(),
        key.as_ref().map_err(String::as_str),
        flags.plain,
        temp,
    );
    let mut received: u64 = 0;
    let mut total: Option<u64> = None;
    let mut attempt = 0;
    loop {
        let from = (received > 0).then_some(received);
        let mut stream = match api::download(client, token, remote, region.as_deref(), from).await {
            Ok(s) => s,
            Err(e) if transient(&e) && attempt + 1 < ATTEMPTS => {
                attempt += 1;
                pause(attempt).await;
                continue;
            }
            Err(e) => return Err(e),
        };
        if total.is_none() {
            total = stream.content_length();
        }
        let broke = loop {
            match stream.next_chunk().await {
                Ok(Some(data)) => {
                    received += data.len() as u64;
                    sink = match sink.write(&data) {
                        Ok(s) => s,
                        Err(e) => {
                            return Ok(CliError::new(
                                Code::Failed,
                                format!("{}: {e}", clean(remote)),
                            )
                            .into());
                        }
                    };
                    if let Some(t) = total
                        && received % (8 * 1024 * 1024) < data.len() as u64
                    {
                        progress(received, t, "received");
                    }
                }
                Ok(None) => break false,
                Err(_) => break true,
            }
        };
        if !broke {
            break;
        }
        attempt += 1;
        if attempt >= ATTEMPTS {
            return Ok(CliError::new(
                Code::Network,
                format!("the download of {} kept breaking off", clean(remote)),
            )
            .into());
        }
        pause(attempt).await;
    }
    if let Some(t) = total
        && received != t
    {
        return Ok(CliError::new(
            Code::Network,
            format!("{} came back incomplete", clean(remote)),
        )
        .into());
    }
    let (temp, decrypted) = match sink.finish() {
        Ok(done) => done,
        Err(e) => return Ok(CliError::new(Code::Failed, format!("{}: {e}", clean(remote))).into()),
    };
    if let Err(e) = temp.as_file().sync_all() {
        return Ok(CliError::new(
            Code::Failed,
            format!("could not write {}: {e}", target.display()),
        )
        .into());
    }
    let kept = if force {
        temp.persist(&target).map(drop)
    } else {
        temp.persist_noclobber(&target).map(drop)
    };
    if let Err(e) = kept {
        return Ok(CliError::new(
            Code::Failed,
            format!("could not write {}: {}", target.display(), e.error),
        )
        .into());
    }
    let size = std::fs::metadata(&target)
        .map(|m| m.len())
        .unwrap_or_default();
    if json {
        crate::print_json(&json!({
            "path": remote,
            "file": target.display().to_string(),
            "bytes": size,
            "decrypted": decrypted,
        }));
        return Ok(Outcome::Done(String::new()));
    }
    Ok(Outcome::Done(format!(
        "Downloaded {} to {} ({}{})",
        clean(remote),
        target.display(),
        bytes(size),
        if decrypted { ", decrypted" } else { "" }
    )))
}

/// `erpc storage key`: no session needed, only the store.
fn key(json: bool, action: &KeyAction) -> Outcome {
    match action {
        KeyAction::Show => match crate::storage_key::load() {
            Ok((Some(key), kind)) => {
                if json {
                    crate::print_json(
                        &json!({ "keyId": key.id_hex(), "keptIn": crate::storage_key::place(kind) }),
                    );
                    return Outcome::Done(String::new());
                }
                Outcome::Done(format!(
                    "Storage key {}\n  kept in {}",
                    key.id_hex(),
                    crate::storage_key::place(kind)
                ))
            }
            Ok((None, kind)) => {
                if json {
                    crate::print_json(
                        &json!({ "keyId": null, "keptIn": crate::storage_key::place(kind) }),
                    );
                    return Outcome::Done(String::new());
                }
                Outcome::Done(
                    "No storage key yet. The first `erpc storage put` makes one; `erpc storage key import` keeps one made elsewhere."
                        .to_owned(),
                )
            }
            Err(e) => Outcome::Failed(e),
        },
        KeyAction::Export { show } => {
            if !*show {
                return CliError::new(Code::Usage, "the key is printed only with --show")
                    .hint("anyone who sees it can read every file it encrypted; write it down or keep it in a password manager")
                    .into();
            }
            match crate::storage_key::load() {
                Ok((Some(key), _)) => {
                    let hex = key.to_hex();
                    if json {
                        crate::print_json(&json!({ "keyId": key.id_hex(), "key": hex.as_str() }));
                        return Outcome::Done(String::new());
                    }
                    Outcome::Done(format!(
                        "{}\n\nStorage key {}. Keep this somewhere safe and away from this machine;\n`erpc storage key import` takes it back on another one.",
                        hex.as_str(),
                        key.id_hex()
                    ))
                }
                Ok((None, _)) => {
                    Outcome::Failed("there is no storage key to export yet".to_owned())
                }
                Err(e) => Outcome::Failed(e),
            }
        }
        KeyAction::Import => {
            let mut line = zeroize::Zeroizing::new(String::new());
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                crate::interrupt::say("Paste the storage key (64 hex digits) and press Enter:");
            }
            if let Err(e) = std::io::stdin().read_line(&mut line) {
                return Outcome::Failed(format!("could not read the key: {e}"));
            }
            let key = match crate::storage_crypt::MasterKey::from_hex(&line) {
                Ok(k) => k,
                Err(e) => return CliError::new(Code::Usage, e).into(),
            };
            drop(line);
            match crate::storage_key::import(&key) {
                Ok(kind) => {
                    if json {
                        crate::print_json(
                            &json!({ "keyId": key.id_hex(), "keptIn": crate::storage_key::place(kind) }),
                        );
                        return Outcome::Done(String::new());
                    }
                    Outcome::Done(format!(
                        "Storage key {} is kept in {}.",
                        key.id_hex(),
                        crate::storage_key::place(kind)
                    ))
                }
                Err(e) => Outcome::Failed(e),
            }
        }
    }
}

async fn resize(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
    gb: u64,
    yes: bool,
) -> Result<Outcome, StorageError> {
    let units = match units_for(gb) {
        Ok(units) => u32::try_from(units).unwrap_or(u32::MAX),
        Err(e) => return Ok(CliError::new(Code::Usage, e).into()),
    };
    let reply = api::subscription(client, token).await?;
    let Some(plan) = reply.get("subscription").filter(|s| !s.is_null()) else {
        return Ok(
            CliError::new(Code::Failed, "this account has no storage plan")
                .hint("buy one with `erpc storage buy 5`")
                .into(),
        );
    };
    if plan.get("billing").and_then(Value::as_str) != Some("card") {
        return Ok(CliError::new(
            Code::Failed,
            "a plan paid from ERPC Credit cannot be resized; only a plan paid by card can",
        )
        .into());
    }
    let now_gb = plan.get("capacityGB").and_then(Value::as_u64).unwrap_or(0);
    if now_gb == gb {
        return Ok(Outcome::Done(format!("The plan is {gb} GB already.")));
    }
    let monthly = plan
        .get("unitAmountCents")
        .and_then(Value::as_f64)
        .map(|cents| format!(" (€{:.2} a period)", cents * f64::from(units) / 100.0))
        .unwrap_or_default();
    if !yes {
        crate::interrupt::say(&if gb > now_gb {
            format!(
                "Resize the plan from {now_gb} GB to {gb} GB{monthly}. The card is charged the prorated difference now."
            )
        } else {
            format!(
                "Resize the plan from {now_gb} GB to {gb} GB{monthly}, from the next invoice. The current period is not credited."
            )
        });
    }
    if let Err(e) = crate::node_common::go_ahead(yes, "the plan was not changed") {
        return Ok(e.into());
    }
    let done = api::upgrade_plan(client, token, units).await?;
    let message = done.get("message").cloned().unwrap_or(Value::Null);
    if json {
        crate::print_json(&message);
        return Ok(Outcome::Done(String::new()));
    }
    let note = message
        .get("note")
        .and_then(Value::as_str)
        .map(clean)
        .unwrap_or_default();
    Ok(Outcome::Done(format!(
        "The plan is now {gb} GB{}. {note}",
        if message.get("capacityApplied").and_then(Value::as_bool) == Some(false) {
            " from the next invoice"
        } else {
            ""
        }
    )))
}

/// The units `gb` buys, or why it cannot be bought.
fn units_for(gb: u64) -> Result<u64, String> {
    if gb == 0 || !gb.is_multiple_of(api::GB_PER_UNIT) {
        return Err(format!(
            "storage is sold in steps of {} GB: 5, 10, 15, …",
            api::GB_PER_UNIT
        ));
    }
    let units = gb / api::GB_PER_UNIT;
    if units > MAX_UNITS {
        return Err(format!(
            "one plan holds at most {} GB",
            MAX_UNITS * api::GB_PER_UNIT
        ));
    }
    Ok(units)
}

/// The price of one unit for `cadence`, in cents, from user-api's
/// catalogue: never a number written into this binary, so the quote is the
/// price that is charged.
async fn unit_price_cents(
    client: &AuthClient,
    token: &SecretString,
    cadence: Cadence,
) -> Result<u64, StorageError> {
    let catalog =
        erpc_api::account::read(client, token, erpc_api::account::PLAN_CATALOG_URL).await?;
    let field = match cadence {
        Cadence::Monthly => "monthlyPeriodCents",
        Cadence::Annual => "annualPeriodCents",
    };
    catalog
        .get("plans")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|p| p.get("productFamily").and_then(Value::as_str) == Some("storage"))
        .and_then(|p| p.get(field))
        .and_then(Value::as_u64)
        .filter(|cents| *cents > 0)
        .ok_or_else(|| {
            erpc_api::ApiError::Malformed("the plan catalogue has no storage price".to_owned())
                .into()
        })
}

async fn buy(
    client: &AuthClient,
    token: &SecretString,
    json: bool,
    gb: u64,
    annual: bool,
    region: Option<&str>,
    yes: bool,
) -> Result<Outcome, StorageError> {
    let units = match units_for(gb) {
        Ok(units) => units,
        Err(why) => return Ok(CliError::new(Code::Usage, why).into()),
    };
    let held = api::subscription(client, token).await?;
    if held.get("subscription").is_some_and(|s| !s.is_null()) {
        return Err(StorageError::PlanExists(String::new()));
    }
    let cadence = if annual {
        Cadence::Annual
    } else {
        Cadence::Monthly
    };
    let total = unit_price_cents(client, token, cadence).await? * units;
    let period = if annual { "year" } else { "month" };
    let quote = format!(
        "Buy {gb} GB of ERPC Global Storage ({units} unit{}), region {}.\n  €{} now from ERPC Credit, then €{} every {period} until it is ended.",
        if units == 1 { "" } else { "s" },
        region.unwrap_or("chosen by ERPC"),
        euros(total),
        euros(total),
    );
    if !json || !yes {
        crate::interrupt::say(&quote);
    }
    if let Err(e) = crate::node_common::go_ahead(yes, "nothing was bought") {
        return Ok(e.into());
    }
    let units = u32::try_from(units).unwrap_or(1);
    let reply = api::start_plan(client, token, units, cadence, region).await?;
    if json {
        crate::print_json(&json!({
            "bought": { "gb": gb, "units": units, "cadence": cadence.as_str(), "chargedCents": total },
            "userProductId": reply.get("userProductId").cloned().unwrap_or(Value::Null),
            "limitBytes": reply.get("storageLimitBytes").cloned().unwrap_or(Value::Null),
        }));
        return Ok(Outcome::Done(String::new()));
    }
    let mut out = format!("Bought {gb} GB. `erpc storage usage` shows it.");
    for key in ["firstDebitWarning", "assignWarning"] {
        if let Some(warning) = reply.get(key).and_then(Value::as_str) {
            out.push_str("\nwarning: ");
            out.push_str(&clean(warning));
        }
    }
    Ok(Outcome::Done(out))
}

/// Text from the server made safe for a terminal: control characters and
/// the characters that reorder text become `?`.
pub(crate) fn clean(text: &str) -> String {
    text.chars()
        .map(|c| {
            let reorders = matches!(
                c,
                '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            );
            if c.is_control() || reorders { '?' } else { c }
        })
        .collect()
}

/// A size for people: B, KB, MB, GB, TB, in steps of 1024, as user-api
/// sizes its plans.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    #[allow(clippy::cast_precision_loss)]
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

fn percent(used: u64, limit: u64) -> String {
    if limit == 0 {
        return "no capacity".to_owned();
    }
    #[allow(clippy::cast_precision_loss)]
    let share = used as f64 * 100.0 / limit as f64;
    format!("{share:.1}%")
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn euros(cents: u64) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> tempfile::NamedTempFile {
        tempfile::NamedTempFile::new().expect("temp")
    }

    #[test]
    fn a_file_erpc_did_not_encrypt_is_refused_unless_plain() {
        // Refused as soon as the first bytes show it, and when the whole
        // file is shorter than the header.
        let refused = Sink::Undecided(Vec::new(), Err("no key"), false, temp());
        assert_eq!(
            refused.write(b"plain text").err().as_deref(),
            Some(NOT_SEALED)
        );
        let short = Sink::Undecided(Vec::new(), Err("no key"), false, temp())
            .write(b"abc")
            .expect("too short to tell");
        assert_eq!(short.finish().err().as_deref(), Some(NOT_SEALED));
        // Taken as it is with --plain.
        let taken = Sink::Undecided(Vec::new(), Err("no key"), true, temp())
            .write(b"plain text")
            .expect("plain");
        assert!(matches!(taken, Sink::Plain(_)));
        let (_, decrypted) = Sink::Undecided(Vec::new(), Err("no key"), true, temp())
            .write(b"ab")
            .expect("short")
            .finish()
            .expect("plain");
        assert!(!decrypted);
    }

    #[test]
    fn an_encrypted_file_says_why_there_is_no_key() {
        let key = crate::storage_crypt::MasterKey::new([3; 32]);
        let mut sealed = Vec::new();
        std::io::Read::read_to_end(
            &mut crate::storage_crypt::Sealer::new(&b"secret"[..], &key).expect("sealer"),
            &mut sealed,
        )
        .expect("seals");
        let why = "the storage key could not be read: 1Password is locked";
        let sink = Sink::Undecided(Vec::new(), Err(why), false, temp());
        assert_eq!(sink.write(&sealed).err().as_deref(), Some(why));
        let opened = Sink::Undecided(Vec::new(), Ok(&key), false, temp())
            .write(&sealed)
            .expect("opens");
        let (_, decrypted) = opened.finish().expect("finishes");
        assert!(decrypted);
    }

    /// Bytes in the gigabyte user-api sizes plans in.
    const GB: u64 = 1_073_741_824;

    #[test]
    fn plans_are_bought_in_five_gb_steps() {
        assert_eq!(units_for(5), Ok(1));
        assert_eq!(units_for(100), Ok(20));
        assert_eq!(units_for(5000), Ok(1000));
        assert!(units_for(0).is_err());
        assert!(units_for(7).is_err());
        assert!(units_for(5005).is_err());
    }

    #[test]
    fn sizes_and_counts_read_well() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(5 * GB), "5.00 GB");
        assert_eq!(bytes(1536), "1.50 KB");
        assert_eq!(thousands(200_000), "200,000");
        assert_eq!(thousands(999), "999");
        assert_eq!(euros(840), "8.40");
        assert_eq!(euros(100), "1.00");
        assert_eq!(percent(1, 0), "no capacity");
    }

    #[test]
    fn server_text_cannot_drive_the_terminal() {
        assert_eq!(clean("a\u{1b}[2Jb"), "a?[2Jb");
        assert_eq!(clean("x\u{202e}y"), "x?y");
        assert_eq!(clean("backups/2026-10-29.tar"), "backups/2026-10-29.tar");
    }
}
