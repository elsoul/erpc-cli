use anyhow::Context;
use std::env;
use std::net::IpAddr;

use crate::utils::fallback::{DEFAULT_API_PORT, DEFAULT_CONFIG_PATH};

const DEFAULT_ERPC_BASE: &str = "https://edge.erpc.global";

#[derive(Clone)]
pub struct Settings {
    pub config_path: String,
    pub grpc_endpoint: String,
    pub x_token: Option<String>,
    /// The Shreds stream (optional): `erpc worker deploy --shreds` sets it.
    pub shreds_endpoint: Option<String>,
    pub rpc_endpoint: String,
    /// Separate RPC endpoint for sending transactions (optional).
    /// Falls back to `rpc_endpoint` when not set.
    pub send_rpc_endpoint: String,
    pub api_port: u16,
    /// The address the API listens on. Loopback unless `API_BIND` says
    /// otherwise; the server's firewall decides who reaches it then.
    pub api_bind: IpAddr,
    /// Optional Discord webhook URL for notifications.
    pub webhook_url: Option<String>,
    /// The bearer token every API request must carry. Required: the API can
    /// start and stop trading, and a page open in a browser on the same
    /// machine can send requests to a port on localhost.
    pub api_token: String,
    /// When true, keep auto-trading new pools after each buy/sell cycle.
    /// When false (default), stop after one complete cycle.
    pub auto_loop: bool,
}

impl Settings {
    /// Reads the settings from the environment, which `erpc worker` fills
    /// from `erpc.toml`'s `[vars]` and `[secrets]`.
    pub fn from_env() -> anyhow::Result<Self> {
        let config_path =
            env::var("CONFIG_PATH").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
        let grpc_endpoint = env::var("GRPC_ENDPOINT").context("GRPC_ENDPOINT is missing")?;
        let x_token = env::var("X_TOKEN").ok();
        let shreds_endpoint = env::var("SHREDS_ENDPOINT").ok().filter(|e| !e.is_empty());

        // Build RPC endpoint: prefer explicit SOLANA_RPC_ENDPOINT, then ERPC_API_KEY.
        // There is no public fallback: a rate-limited RPC loses trades.
        let rpc_endpoint = if let Ok(explicit) = env::var("SOLANA_RPC_ENDPOINT") {
            explicit
        } else if let Ok(api_key) = env::var("ERPC_API_KEY") {
            format!("{}?api-key={}", DEFAULT_ERPC_BASE, api_key)
        } else {
            anyhow::bail!("no RPC: set SOLANA_RPC_ENDPOINT, or ERPC_API_KEY to use the ERPC edge RPC");
        };

        let api_port = env::var("API_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(DEFAULT_API_PORT);
        // Separate endpoint for sending transactions (optional).
        let send_rpc_endpoint = if let Ok(explicit) = env::var("SOLANA_SEND_RPC_ENDPOINT") {
            explicit
        } else if let Ok(api_key) = env::var("ERPC_SEND_API_KEY") {
            format!("{}?api-key={}", DEFAULT_ERPC_BASE, api_key)
        } else {
            rpc_endpoint.clone()
        };

        let api_bind = match env::var("API_BIND") {
            Ok(raw) => raw
                .parse::<IpAddr>()
                .with_context(|| format!("API_BIND={raw:?} is not an IP address"))?,
            Err(_) => IpAddr::from([127, 0, 0, 1]),
        };
        let webhook_url = env::var("WEBHOOK_URL").ok().filter(|u| !u.is_empty());
        let api_token = env::var("API_TOKEN")
            .ok()
            .filter(|t| t.len() >= 16)
            .context("API_TOKEN is missing or shorter than 16 characters; every API request must carry it")?;
        let auto_loop = match parse_bool_env("AUTO_LOOP") {
            Some(v) => v,
            None => {
                if let Ok(raw) = env::var("AUTO_LOOP") {
                    log::warn!(
                        "AUTO_LOOP={:?} not recognized as bool — defaulting to false",
                        raw
                    );
                }
                false
            }
        };

        Ok(Self {
            config_path,
            grpc_endpoint,
            x_token,
            shreds_endpoint,
            rpc_endpoint,
            send_rpc_endpoint,
            api_port,
            api_bind,
            webhook_url,
            api_token,
            auto_loop,
        })
    }
}

/// A URL as it may appear in a log: without its query (where an RPC API key
/// rides) and without a user or password. Logs end up in the server's
/// journal, which is not where a credential belongs.
pub fn for_log(url: &str) -> String {
    let without_query = url.split(['?', '#']).next().unwrap_or_default();
    match without_query.split_once("://") {
        Some((scheme, rest)) => {
            let host_and_path = rest.rsplit_once('@').map_or(rest, |(_, after)| after);
            let redacted = without_query.len() != url.len() || host_and_path.len() != rest.len();
            format!(
                "{scheme}://{host_and_path}{}",
                if redacted { " (credentials hidden)" } else { "" }
            )
        }
        None => "(not a URL)".to_owned(),
    }
}

/// A log line with every credential it carries hidden: the values of
/// `api-key=`, `api_key=`, `apikey=` and `token=` query parameters, and the
/// user and password of a URL. Library errors print whole URLs -- the RPC
/// client's do -- so every line the app logs goes through this, not only
/// the lines this app writes.
pub fn redact(line: &str) -> String {
    // Same byte offsets as `line`: ASCII lowercasing keeps every byte's place.
    let lower = line.to_ascii_lowercase();
    let ends_value = |c: char| matches!(c, '&' | '"' | '\'' | ')' | '#') || c.is_whitespace();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    'outer: while i < line.len() {
        for key in ["api-key=", "api_key=", "apikey=", "token="] {
            if lower[i..].starts_with(key) {
                out.push_str(&line[i..i + key.len()]);
                out.push_str("***");
                i += key.len();
                i += line[i..].find(ends_value).unwrap_or(line.len() - i);
                continue 'outer;
            }
        }
        if line[i..].starts_with("://") {
            out.push_str("://");
            i += 3;
            let authority = line[i..]
                .find(|c: char| c == '/' || ends_value(c))
                .unwrap_or(line.len() - i);
            if let Some(at) = line[i..i + authority].rfind('@') {
                out.push_str("***@");
                i += at + 1;
            }
            continue;
        }
        let c = line[i..].chars().next().unwrap_or_default();
        out.push(c);
        i += c.len_utf8();
    }
    out
}

fn parse_bool_env(key: &str) -> Option<bool> {
    let v = env::var(key).ok()?;
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" | "" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::for_log;

    #[test]
    fn a_logged_url_keeps_no_credential() {
        // As the read RPC is built from ERPC_API_KEY.
        assert_eq!(
            for_log("https://edge.erpc.global?api-key=SECRET"),
            "https://edge.erpc.global (credentials hidden)"
        );
        assert_eq!(
            for_log("redis://:SECRET@127.0.0.1:6379/0"),
            "redis://127.0.0.1:6379/0 (credentials hidden)"
        );
        assert_eq!(for_log("redis://127.0.0.1:6379"), "redis://127.0.0.1:6379");
        assert!(!for_log("SECRET").contains("SECRET"));
    }

    #[test]
    fn a_log_line_keeps_no_credential() {
        use super::redact;
        // As the RPC client's errors print the URL they failed on.
        let line = r#"Failed: Error { url: "https://edge.erpc.global/?api-key=SECRET", kind: Connect }"#;
        let redacted = redact(line);
        assert!(!redacted.contains("SECRET"), "{redacted}");
        assert!(redacted.contains(r#"?api-key=***""#), "{redacted}");
        let redacted = redact("redis://:SECRET@127.0.0.1:6379/0 and ?a=1&TOKEN=SECRET&b=2");
        assert!(!redacted.contains("SECRET"), "{redacted}");
        assert!(redacted.contains("&b=2"), "{redacted}");
        assert_eq!(redact("plain text, ünïcode"), "plain text, ünïcode");
    }
}
