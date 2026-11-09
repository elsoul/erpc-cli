// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The concealed L1 credential schema. Validation never opens a connection.
//!
//! Remote DNS/IP and chain identity checks live in the carried proxy. This
//! schema is exclusively for operator-selected L1 upstreams, never ERPC login,
//! account or payment endpoints. The original concealed JSON travels on stdin
//! to systemd credential encryption; no URL belongs in public node inventory.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::{collections::BTreeMap, net::IpAddr};

/// Context-free credential validation failure; no provider text is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid concealed L1 upstream configuration")]
pub struct InvalidCredential;

/// Validated original JSON, still concealed and deliberately without Debug.
pub struct Credential(SecretString);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Schema {
    execution: Endpoint,
    beacon: Endpoint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    url: SecretString,
    #[serde(default)]
    headers: BTreeMap<String, SecretString>,
    #[serde(default)]
    allow_loopback: bool,
}

impl Endpoint {
    fn validate(&self) -> Result<(), InvalidCredential> {
        let raw = self.url.expose_secret();
        if raw.len() > 8192 || !printable(raw) || raw.contains('\\') {
            return Err(InvalidCredential);
        }
        let parsed = reqwest::Url::parse(raw).map_err(|_| InvalidCredential)?;
        let host = parsed.host_str().ok_or(InvalidCredential)?;
        let host = host.trim_matches(['[', ']']).trim_end_matches('.');
        if !matches!(parsed.scheme(), "https" | "http")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || host == "erpc.global"
            || host.ends_with(".erpc.global")
            || parsed.port() == Some(0)
            || raw
                .split('/')
                .nth(2)
                .is_some_and(|authority| authority.contains('@'))
        {
            return Err(InvalidCredential);
        }
        if self.allow_loopback {
            if !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
                return Err(InvalidCredential);
            }
        } else if parsed.scheme() != "https" {
            return Err(InvalidCredential);
        }
        if self.headers.len() > 2 {
            return Err(InvalidCredential);
        }
        let mut names = std::collections::BTreeSet::new();
        for (key, value) in &self.headers {
            let name = key.to_ascii_lowercase();
            if !matches!(name.as_str(), "authorization" | "x-api-key")
                || !names.insert(name)
                || !printable(value.expose_secret())
                || value.expose_secret().len() > 8192
            {
                return Err(InvalidCredential);
            }
        }
        Ok(())
    }
}

fn printable(value: &str) -> bool {
    value.bytes().all(|b| (32..127).contains(&b))
}

impl Credential {
    /// Validate the two endpoints while keeping provider secrets concealed.
    ///
    /// # Errors
    /// Rejects oversized, malformed or unexpected JSON, unsafe URL schemes,
    /// userinfo, fragments, invalid authentication
    /// headers, ERPC service hosts, and non-numeric loopback exceptions.
    pub fn parse(raw: SecretString) -> Result<Self, InvalidCredential> {
        if raw.expose_secret().len() > 65_536 {
            return Err(InvalidCredential);
        }
        let schema: Schema =
            serde_json::from_str(raw.expose_secret()).map_err(|_| InvalidCredential)?;
        schema.execution.validate()?;
        schema.beacon.validate()?;
        Ok(Self(raw))
    }

    /// Borrow only for secret-store/SSH stdin transport, never logs or argv.
    #[must_use]
    pub const fn secret(&self) -> &SecretString {
        &self.0
    }
}

/// A concealed execution-only parent-chain transport for clients such as Heimdall.
/// It deliberately grants no beacon route or transaction-submission authority.
pub struct ExecutionCredential(SecretString);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionSchema {
    execution: Endpoint,
}

impl ExecutionCredential {
    /// Validate the single explicitly selected parent execution endpoint.
    /// # Errors
    /// Applies the same URL/header/loopback policy as the two-endpoint profile,
    /// and rejects beacon fields or any additional destination.
    pub fn parse(raw: SecretString) -> Result<Self, InvalidCredential> {
        if raw.expose_secret().len() > 65_536 {
            return Err(InvalidCredential);
        }
        let schema: ExecutionSchema =
            serde_json::from_str(raw.expose_secret()).map_err(|_| InvalidCredential)?;
        schema.execution.validate()?;
        Ok(Self(raw))
    }

    /// Borrow only for private credential transport, never logs or arguments.
    #[must_use]
    pub const fn secret(&self) -> &SecretString {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Credential, InvalidCredential};
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::json;

    fn config(url: &str, loopback: bool) -> SecretString {
        let endpoint = json!({"url":url,"allow_loopback":loopback});
        json!({"execution":endpoint,"beacon":endpoint})
            .to_string()
            .into()
    }

    #[test]
    fn only_explicit_numeric_loopback_may_use_plaintext() {
        assert!(Credential::parse(config("https://github.com", false)).is_ok());
        assert!(Credential::parse(config("http://127.0.0.1:8545", true)).is_ok());
        assert!(Credential::parse(config("http://[::1]:5052", true)).is_ok());
        for (url, loopback) in [
            ("http://127.0.0.1", false),
            (concat!("http:", "//github.com"), false),
            ("http://localhost", true),
            ("https://github.com", true),
            ("https://github.com:0", false),
            ("https://edge.erpc.global", false),
            ("https://edge.erpc.global.", false),
            ("https://user:unit-test-placeholder@github.com", false),
            ("https://@github.com", false),
            ("https://github.com/#unit-test-placeholder", false),
        ] {
            assert!(Credential::parse(config(url, loopback)).is_err());
        }
    }

    #[test]
    fn no_arbitrary_request_headers_or_extra_destinations() {
        for extra in [
            json!({"Host":"github.com"}),
            json!({"Authorization":"a\r\nb"}),
            json!({"Authorization":"a","authorization":"b"}),
        ] {
            let endpoint = json!({"url":"https://github.com", "headers":extra});
            let raw = json!({"execution":endpoint,"beacon":endpoint}).to_string();
            assert!(Credential::parse(raw.into()).is_err());
        }
        let raw = r#"{"execution":{"url":"https://github.com"},"beacon":{"url":"https://github.com"},"extra":"unit-test-placeholder"}"#;
        assert!(Credential::parse(raw.into()).is_err());
        assert_eq!(
            InvalidCredential.to_string(),
            "invalid concealed L1 upstream configuration"
        );
    }

    #[test]
    fn execution_only_profile_preserves_shared_policy_without_weakening_two_endpoint_schema() {
        use super::ExecutionCredential;
        let raw = json!({"execution":{"url":"https://github.com","headers":{"Authorization":"unit-test-provider-placeholder"}}}).to_string();
        assert!(Credential::parse(raw.clone().into()).is_err());
        assert_eq!(
            ExecutionCredential::parse(raw.clone().into())
                .unwrap_or_else(|_| panic!("valid execution-only credential"))
                .secret()
                .expose_secret(),
            &raw
        );
        assert!(ExecutionCredential::parse(config("https://github.com", false)).is_err());
        for endpoint in [
            json!({"url":"https://edge.erpc.global"}),
            json!({"url":"http://127.0.0.1"}),
            json!({"url":"https://github.com","headers":{"Host":"github.com"}}),
        ] {
            assert!(
                ExecutionCredential::parse(json!({"execution":endpoint}).to_string().into())
                    .is_err()
            );
        }
    }

    #[test]
    fn transport_keeps_the_original_json_concealed() {
        let raw = config("https://github.com/path?unit-test-placeholder", false);
        let expected = raw.expose_secret().to_owned();
        let credential = Credential::parse(raw).unwrap_or_else(|_| panic!("valid schema"));
        assert_eq!(credential.secret().expose_secret(), &expected);
    }
}
