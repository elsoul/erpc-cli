// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A completed readiness observation is a report; transport failures are errors.
use crate::commands::Outcome;
use serde_json::Value;

pub(crate) fn status(
    result: Result<Value, String>,
    readiness: &str,
    json_out: bool,
    output: &mut dyn FnMut(&str),
) -> Outcome {
    match result {
        Ok(value) => {
            let ready = value.pointer(readiness) == Some(&Value::Bool(true));
            let report = if json_out {
                value.to_string()
            } else {
                serde_json::to_string_pretty(&value).unwrap_or_default()
            };
            output(&report);
            if ready {
                Outcome::Done(String::new())
            } else {
                Outcome::Problems(String::new())
            }
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Code;
    use serde_json::json;
    use std::process::ExitCode;
    type Adapter = fn(Result<Value, String>, bool, &mut dyn FnMut(&str)) -> Outcome;
    fn adapters() -> [(&'static str, &'static str, Adapter); 12] {
        [
            (
                "Bitcoin",
                "/readiness/ready",
                crate::bitcoin_rpc::report_status,
            ),
            (
                "OP/Base/Soneium",
                "/readiness/ready",
                crate::rollup_ops::report_status,
            ),
            (
                "Arbitrum/Robinhood RPC",
                "/ready",
                crate::nitro_rpc::report_status,
            ),
            ("Solana RPC", "/rpc_ready", |r, j, o| {
                crate::solana_native::report_status(true, r, j, o)
            }),
            ("Solana validator", "/validator_ready", |r, j, o| {
                crate::solana_native::report_status(false, r, j, o)
            }),
            ("bsc RPC/validator", "/ready", crate::bsc_rpc::report_status),
            (
                "near RPC/validator",
                "/ready",
                crate::near_rpc::report_status,
            ),
            (
                "hyperliquid AQA",
                "/publisher_service_ready",
                crate::hyperliquid_aqa::report_status,
            ),
            ("kaia EN/CN", "/ready", crate::kaia_rpc::report_status),
            (
                "polygon fullnode/validator",
                "/ready",
                crate::polygon_rpc::report_status,
            ),
            (
                "arbitrum validator",
                "/validator_ready",
                crate::arbitrum_validator::report_status,
            ),
            (
                "robinhood-validator",
                "/validator_ready",
                crate::robinhood_validator::report_status,
            ),
        ]
    }
    #[test]
    fn actual_status_adapters_return_one_report_and_exit_five_for_observed_problems() {
        for (name, field, adapter) in adapters() {
            for json_out in [false, true] {
                for ready in [json!(true), json!(false), Value::Null, json!("true")] {
                    let opposite = ready != true;
                    let mut value = json!({"ready":opposite,"readiness":{"ready":opposite},
                        "rpc_ready":opposite,"validator_ready":opposite,"publisher_service_ready":opposite,"observer_ready":true,
                        "height":123,"detail":"inert observation"});
                    *value.pointer_mut(field).unwrap() = ready.clone();
                    let mut lines = Vec::new();
                    let outcome = adapter(Ok(value.clone()), json_out, &mut |line| {
                        lines.push(line.to_owned());
                    });
                    let expected = if ready == true { 0 } else { 5 };
                    assert_eq!(crate::finish(outcome), ExitCode::from(expected), "{name}");
                    assert_eq!(lines.len(), 1, "{name}");
                    assert_eq!(serde_json::from_str::<Value>(&lines[0]).unwrap(), value);
                    if json_out {
                        assert_eq!(lines[0].lines().count(), 1);
                    }
                }
            }
        }
    }
    #[test]
    fn failed_observation_has_no_report_and_preserves_the_single_error_contract() {
        for (name, _, adapter) in adapters() {
            let mut lines = Vec::new();
            let outcome = adapter(Err("inert provider failure".into()), true, &mut |line| {
                lines.push(line.to_owned());
            });
            assert!(lines.is_empty(), "{name}");
            let error = outcome.error().unwrap();
            assert_eq!(error.code, Code::Failed);
            assert_eq!(error.code.exit(), 1);
            assert_eq!(error.json()["error"]["code"], "failed");
        }
    }
}
