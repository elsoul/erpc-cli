// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Local subscription definitions. A separate foreground runner delivers events.

use std::collections::BTreeMap;
use std::path::Path;

use clap::{Args, Subcommand, ValueEnum};
use erpc_core::private_file;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::commands::Outcome;
use crate::rpc_call::{Network, operator_url, output};

#[derive(Subcommand)]
pub(crate) enum Action {
    /// Save an enabled subscription locally. Start delivery with webhook run ID.
    Create(Create),
    /// List saved subscriptions.
    List,
    /// Show a subscription (callback credentials are omitted).
    Show { id: u64 },
    /// Count locally enabled subscriptions.
    EnabledCount,
    /// Disable delivery. An existing runner exits.
    Pause(Change),
    /// Enable a saved subscription for a new runner.
    Activate(Change),
    /// Remove a saved subscription.
    Delete(Change),
    /// Subscribe and POST notifications until interrupted, paused or disconnected.
    Run {
        id: u64,
        /// Operator-supplied WebSocket RPC URL. Defaults to the shared account endpoint.
        #[arg(long)]
        endpoint_url: Option<String>,
        /// Stop after the first successful delivery.
        #[arg(long)]
        once: bool,
    },
}

#[derive(Args)]
pub(crate) struct Change {
    id: u64,
    /// Confirm this change non-interactively.
    #[arg(short, long)]
    yes: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Template {
    /// Transaction logs mentioning a Solana account.
    SolanaWallet,
    /// EVM log events emitted by a contract.
    EvmContractEvents,
}

#[derive(Args)]
pub(crate) struct Create {
    /// Human-readable subscription name.
    #[arg(long)]
    name: String,
    #[arg(long, value_enum)]
    network: Network,
    /// HTTP callback, HTTPS or loopback HTTP.
    #[arg(long)]
    url: String,
    /// WebSocket RPC method, e.g. logsSubscribe or `eth_subscribe`.
    #[arg(
        long,
        required_unless_present = "template",
        conflicts_with = "template"
    )]
    method: Option<String>,
    /// JSON array of arguments for --method.
    #[arg(long, requires = "method")]
    params: Option<String>,
    /// Subscribe to wallet or contract activity using a built-in filter.
    #[arg(long, value_enum, requires = "address")]
    template: Option<Template>,
    /// Wallet or contract address for the chosen template.
    #[arg(long, visible_alias = "wallet", requires = "template")]
    address: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Hook {
    pub(crate) name: String,
    pub(crate) network: Network,
    pub(crate) url: String,
    pub(crate) method: String,
    pub(crate) params: Value,
    pub(crate) enabled: bool,
    // A pause fences the old runner even if another process immediately reactivates.
    #[serde(default)]
    pub(crate) generation: u64,
}

impl Hook {
    fn summary(&self, id: u64) -> Value {
        json!({"id":id,"name":self.name,"network":self.network,"method":self.method,"params":self.params,"enabled":self.enabled,
            "callback_host":operator_url(&self.url,false).ok().and_then(|u|u.host_str().map(str::to_string))})
    }
}

#[derive(Default, Deserialize, Serialize)]
pub(crate) struct Registry {
    last_id: u64,
    pub(crate) hooks: BTreeMap<u64, Hook>,
}

impl Registry {
    pub(crate) fn read(path: &Path) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(data) => serde_json::from_slice(&data)
                .map_err(|_| "cannot parse local webhook registry".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("cannot read webhook registry: {e}")),
        }
    }

    fn change(
        path: &Path,
        edit: impl FnOnce(&mut Self) -> Result<Value, String>,
    ) -> Result<Value, String> {
        private_file::locked(path, || {
            let mut registry = Self::read(path)?;
            let result = edit(&mut registry)?;
            private_file::write(
                path,
                &serde_json::to_vec(&registry).map_err(|e| e.to_string())?,
            )?;
            Ok(result)
        })
    }
}

fn subscription(args: &Create) -> Result<(String, Value), Outcome> {
    if let Some(template) = args.template {
        let address = args.address.as_deref().unwrap_or_default();
        return match (template, args.network) {
            (Template::SolanaWallet, Network::SolanaMainnet)
                if erpc_chain_solana::identity::pubkey_bytes(address).is_some() =>
            {
                Ok((
                    "logsSubscribe".into(),
                    json!([{"mentions":[address]},{"commitment":"confirmed"}]),
                ))
            }
            (Template::EvmContractEvents, Network::EthereumMainnet)
                if erpc_wallet::evm::Address::parse(address).is_ok() =>
            {
                Ok(("eth_subscribe".into(), json!(["logs",{"address":address}])))
            }
            _ => Err(Outcome::Usage(
                "the template requires a matching network and a valid address on that network"
                    .into(),
            )),
        };
    }
    let method = args
        .method
        .as_deref()
        .ok_or_else(|| Outcome::Usage("choose --method or --template".into()))?;
    let params: Value = serde_json::from_str(args.params.as_deref().unwrap_or("[]"))
        .map_err(|_| Outcome::Usage("invalid subscription params JSON".into()))?;
    if !params.is_array() {
        return Err(Outcome::Usage(
            "subscription params must be a JSON array".into(),
        ));
    }
    let valid = match args.network {
        Network::EthereumMainnet => method == "eth_subscribe" && params[0].is_string(),
        Network::SolanaMainnet => method.ends_with("Subscribe") && method.len() > "Subscribe".len(),
    };
    if !valid {
        return Err(Outcome::Usage("use a Solana *Subscribe method, or eth_subscribe with a subscription type in params[0]".into()));
    }
    Ok((method.to_owned(), params))
}

fn create(args: Create, path: &Path) -> Result<Value, Outcome> {
    operator_url(&args.url, false).map_err(Outcome::Usage)?;
    if args.name.trim().is_empty() {
        return Err(Outcome::Usage("name is empty".into()));
    }
    let (method, params) = subscription(&args)?;
    Registry::change(path, |r| {
        let id = r
            .last_id
            .checked_add(1)
            .ok_or("webhook id space exhausted")?;
        let hook = Hook {
            name: args.name,
            network: args.network,
            url: args.url,
            method,
            params,
            enabled: true,
            generation: 0,
        };
        let summary = hook.summary(id);
        r.last_id = id;
        r.hooks.insert(id, hook);
        Ok(summary)
    })
    .map_err(Outcome::Failed)
}

fn change(path: &Path, change: &Change, verb: &str) -> Result<Value, Outcome> {
    if !change.yes {
        if !crate::session::has_terminal() {
            return Err(Outcome::NeedsTerminal(
                "use --yes to confirm the webhook change".into(),
            ));
        }
        if !dialoguer::Confirm::new()
            .with_prompt(format!("{verb} webhook {}?", change.id))
            .default(false)
            .interact()
            .map_err(|_| Outcome::Failed("cannot read confirmation".into()))?
        {
            return Err(Outcome::Failed("webhook change cancelled".into()));
        }
    }
    Registry::change(path, |r| {
        let hook = r.hooks.get_mut(&change.id).ok_or("unknown webhook id")?;
        if verb == "delete" {
            r.hooks.remove(&change.id);
            Ok(json!({"id":change.id,"deleted":true}))
        } else {
            if verb == "pause" && hook.enabled {
                hook.generation = hook
                    .generation
                    .checked_add(1)
                    .ok_or("webhook generation exhausted")?;
            }
            hook.enabled = verb == "activate";
            Ok(hook.summary(change.id))
        }
    })
    .map_err(Outcome::Failed)
}

pub(crate) async fn run(action: Action, json: bool) -> Outcome {
    let path = match crate::session::state_dir() {
        Ok(dir) => dir.join("webhooks.json"),
        Err(e) => return Outcome::Failed(e),
    };
    let result = match action {
        Action::Create(args) => create(args, &path),
        Action::Pause(c) => change(&path, &c, "pause"),
        Action::Activate(c) => change(&path, &c, "activate"),
        Action::Delete(c) => change(&path, &c, "delete"),
        Action::Run {
            id,
            endpoint_url,
            once,
        } => crate::webhook_delivery::run(&path, id, endpoint_url.as_deref(), once).await,
        read => Registry::read(&path)
            .map_err(Outcome::Failed)
            .and_then(|r| match read {
                Action::List => Ok(Value::Array(
                    r.hooks.iter().map(|(&id, h)| h.summary(id)).collect(),
                )),
                Action::Show { id } => r
                    .hooks
                    .get(&id)
                    .map(|h| h.summary(id))
                    .ok_or_else(|| Outcome::Usage("unknown webhook id".into())),
                Action::EnabledCount => {
                    Ok(json!({"enabled":r.hooks.values().filter(|h|h.enabled).count()}))
                }
                _ => unreachable!(),
            }),
    };
    match result {
        Ok(v) => output(&v, json),
        Err(e) => e,
    }
}
