use crate::api::build_router;
use crate::handlers::processor::process_updates;
use crate::runtime::runner::run_geyser_stream;
use crate::runtime::settings::{for_log, redact, Settings};
use crate::runtime::subscription::build_subscribe_request;
use crate::state::AppState;
use crate::utils::config::Config;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_stream_sdk::GeyserSubscribeUpdate;
use std::sync::atomic::AtomicU64;
use std::{fs, net::SocketAddr, sync::Arc};
use tokio::sync::{mpsc, RwLock};

mod amm;
mod api;
mod creators;
mod engine;
mod handlers;
mod i18n;
mod runtime;
mod shreds;
mod state;
mod timing;
mod trace;
mod utils;
mod wallet;
mod webhook;

const UPDATE_CHANNEL_CAPACITY: usize = 10_000;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Before anything that could hold the key is in memory.
    wallet::harden_process();
    // Every line, the libraries' included, without the credentials in it.
    env_logger::Builder::from_default_env()
        .format(|buf, record| {
            use std::io::Write as _;
            writeln!(
                buf,
                "[{} {:<5} {}] {}",
                buf.timestamp(),
                record.level(),
                record.target(),
                redact(&record.args().to_string())
            )
        })
        .init();
    i18n::init_from_env();

    let settings = Settings::from_env()?;
    let config_content = fs::read_to_string(&settings.config_path)?;
    let config: Config = serde_jsonc::from_str(&config_content)?;
    let request = build_subscribe_request(&config);

    // The trading key, from the pipe erpc handed over; none means watch-only.
    let keypair = wallet::from_erpc()?;
    let rpc_client = Arc::new(RpcClient::new(settings.rpc_endpoint.clone()));
    let send_rpc_client = Arc::new(RpcClient::new(settings.send_rpc_endpoint.clone()));
    log::info!("RPC read: {}", for_log(&settings.rpc_endpoint));
    log::info!("RPC send: {}", for_log(&settings.send_rpc_endpoint));

    // Optional Redis client
    let redis_client = std::env::var("REDIS_URL").ok().and_then(|url| {
        match redis::Client::open(url.as_str()) {
            Ok(client) => {
                log::info!("Redis client initialized: {}", for_log(&url));
                Some(client)
            }
            Err(e) => {
                log::warn!(
                    "Failed to create Redis client ({}): {:?} — continuing without Redis",
                    for_log(&url),
                    e
                );
                None
            }
        }
    });

    // Shared state
    let app_state = Arc::new(RwLock::new({
        let mut s = AppState::new(settings.webhook_url.clone());
        s.wallet = keypair;
        s.redis_client = redis_client;
        s.config.auto_loop = settings.auto_loop;
        s
    }));
    // Creators banned before: saved in Redis, or listed in the config.
    {
        let mut s = app_state.write().await;
        if s.take_up_saved().await {
            // Trading was on when the last process ended: it is on again,
            // as a reboot or a crash restart should not leave the bot idle.
            let sell_only = s.sell_only;
            log::info!("Trading resumed as before the restart (sell_only = {sell_only})");
            let msg = i18n::trading_resumed(sell_only);
            s.push_notification(
                solana_sdk::pubkey::Pubkey::default(),
                solana_sdk::pubkey::Pubkey::default(),
                msg.clone(),
            );
            webhook::notify(s.webhook_url.clone(), msg);
        }
        log::info!(
            "Creators banned: {}; no buys for the first {} s",
            s.creators.banned().len(),
            s.config.warmup_secs
        );
    }
    log::info!("AUTO_LOOP = {}", settings.auto_loop);

    // Geyser infrastructure
    let tracked_slot = Arc::new(AtomicU64::new(0));
    let (updates_tx, updates_rx) = mpsc::channel::<GeyserSubscribeUpdate>(UPDATE_CHANNEL_CAPACITY);

    // Restore positions from wallet holdings on startup
    {
        let state = app_state.clone();
        let rpc = rpc_client.clone();
        let send_rpc = send_rpc_client.clone();
        engine::restore_positions_from_wallet(state, rpc, send_rpc).await;
    }

    let processor_handle = {
        let state = app_state.clone();
        let rpc = rpc_client.clone();
        let send_rpc = send_rpc_client.clone();
        tokio::spawn(async move {
            process_updates(updates_rx, state, rpc, send_rpc).await;
        })
    };

    let geyser_handle = {
        let tracked_slot = tracked_slot.clone();
        let updates_tx = updates_tx.clone();
        tokio::spawn(run_geyser_stream(
            settings.grpc_endpoint.clone(),
            settings.x_token.clone(),
            request,
            tracked_slot,
            updates_tx,
        ))
    };

    // The Shreds stream, when there is one: migrations seen before they run.
    let shreds_handle = {
        let endpoint = settings.shreds_endpoint.clone();
        let state = app_state.clone();
        let rpc = rpc_client.clone();
        let send_rpc = send_rpc_client.clone();
        tokio::spawn(async move {
            match endpoint {
                Some(endpoint) => {
                    log::info!("Shreds: {}", for_log(&endpoint));
                    shreds::run(endpoint, state, rpc, send_rpc).await
                }
                None => {
                    log::info!("Shreds: none (SHREDS_ENDPOINT is not set); pools are seen in Geyser only");
                    futures::future::pending().await
                }
            }
        })
    };

    // Axum API server
    let api_handle = {
        let state = app_state.clone();
        let rpc = rpc_client.clone();
        let addr = SocketAddr::new(settings.api_bind, settings.api_port);
        let api_token = settings.api_token.clone();
        tokio::spawn(async move {
            let router = build_router(state, rpc, api_token);
            log::info!("API server listening on {} (docs at /docs)", addr);
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            axum::serve(listener, router).await.unwrap();
        })
    };

    // The Geyser runner returns only on an error that reconnecting cannot fix;
    // exit with it (status 1) instead of idling without a stream.
    tokio::select! {
        result = geyser_handle => result?,
        result = processor_handle => result.map_err(anyhow::Error::from),
        result = shreds_handle => result.map_err(anyhow::Error::from),
        result = api_handle => result.map_err(anyhow::Error::from),
    }
}
