//! A small HTTP API: the starting point of an erpc worker app.
//!
//! `erpc worker run` builds and runs it on this machine, and `erpc worker
//! deploy` on a server, as a native binary under a hardened systemd unit.
//! Its settings come from `erpc.toml`: `[vars]` as they are written, and
//! `[secrets]` read from 1Password, the keychain or erpc's keystore when the
//! app starts.
//! Both reach it as environment variables; there is no `.env` file.

use axum::{extract::Path, routing::get, Json, Router};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};

/// What `GET /` and `GET /hello/{name}` answer.
#[derive(Debug, Serialize, PartialEq)]
struct Hello {
    message: String,
    app: &'static str,
    version: &'static str,
}

/// A setting, or `default` when it is not set.
fn setting(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

/// The greeting for `name`, with the word `GREETING` sets in `[vars]`.
fn hello(greeting: &str, name: &str) -> Hello {
    Hello {
        message: format!("{greeting}, {name}!"),
        app: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
    }
}

async fn root() -> Json<Hello> {
    Json(hello(&setting("GREETING", "Hello"), "World"))
}

async fn named(Path(name): Path<String>) -> Json<Hello> {
    Json(hello(&setting("GREETING", "Hello"), &name))
}

/// Where the API listens: `bind` is an IPv4 or IPv6 address (`0.0.0.0`,
/// `::`), `port` a port number.
fn listen_address(bind: &str, port: &str) -> Result<SocketAddr, String> {
    let ip: IpAddr = bind
        .parse()
        .map_err(|e| format!("API_BIND is not an address ({bind}): {e}"))?;
    let port: u16 = port
        .parse()
        .map_err(|e| format!("API_PORT is not a port ({port}): {e}"))?;
    Ok(SocketAddr::new(ip, port))
}

/// `erpc worker deploy` waits for this to answer before it calls a release
/// healthy (`run.health` in `erpc.toml`).
async fn healthz() -> &'static str {
    "ok"
}

/// The API's routes. Add yours here.
fn routes() -> Router {
    Router::new()
        .route("/", get(root))
        .route("/hello/{name}", get(named))
        .route("/healthz", get(healthz))
}

/// Ends when the app is asked to stop: Ctrl-C here, SIGTERM on a server
/// (`erpc worker stop`, a deploy, a restart).
async fn stop_asked() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut asked) => {
                asked.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Loopback unless `API_BIND` says otherwise: on a server the API is
    // reached with `erpc worker api /`, and opened wider only together
    // with `erpc worker firewall allow --to app <ADDRESS>`.
    let address = listen_address(
        &setting("API_BIND", "127.0.0.1"),
        &setting("API_PORT", "3000"),
    )?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|e| format!("could not listen on {address}: {e}"))?;
    println!("{} is listening on {address}", env!("CARGO_PKG_NAME"));
    axum::serve(listener, routes())
        .with_graceful_shutdown(stop_asked())
        .await?;
    println!("{} stopped", env!("CARGO_PKG_NAME"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_greeting_names_who_it_greets() {
        let world = hello("Hello", "World");
        assert_eq!(world.message, "Hello, World!");
        assert_eq!(world.app, env!("CARGO_PKG_NAME"));
        assert_eq!(hello("Konnichiwa", "erpc").message, "Konnichiwa, erpc!");
    }

    #[test]
    fn a_setting_that_is_not_set_is_its_default() {
        assert_eq!(setting("A_SETTING_NOBODY_SETS", "fallback"), "fallback");
    }

    #[test]
    fn the_api_listens_on_an_ipv4_or_ipv6_address() {
        assert_eq!(
            listen_address("127.0.0.1", "3000").map(|a| a.to_string()),
            Ok("127.0.0.1:3000".to_owned())
        );
        assert_eq!(
            listen_address("::", "8080").map(|a| a.to_string()),
            Ok("[::]:8080".to_owned())
        );
        assert!(listen_address("localhost", "3000").is_err());
        assert!(listen_address("127.0.0.1", "http").is_err());
    }

    #[tokio::test]
    async fn a_name_in_the_path_is_greeted() {
        let Json(answer) = named(Path("erpc".to_owned())).await;
        assert!(answer.message.ends_with(", erpc!"), "{}", answer.message);
        assert_eq!(healthz().await, "ok");
    }
}
