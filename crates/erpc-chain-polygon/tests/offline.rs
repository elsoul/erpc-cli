// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Offline transport, release publication and independent TOML configuration checks.
use std::{path::Path, process::Command};
fn python(script: &str) -> Command {
    let mut command = Command::new(if cfg!(windows) { "python" } else { "python3" });
    command.arg(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(script),
    );
    command
}
// These fixtures load the scripts a managed host runs, which import POSIX-only
// modules; the two configuration tests below stay on every platform.
#[cfg(unix)]
#[test]
fn bounded_artifacts_and_parent_transport_failures() {
    for script in [
        "artifacts.py",
        "admission.py",
        "checkpoint.py",
        "signer.py",
        "signatures.py",
        "parent.py",
        "broker.py",
        "broker_docker.py",
        "broker_storage.py",
        "broker_runtime.py",
        "gateway.py",
        "native_peer.py",
        "native_authority.py",
        "local_tls.py",
        "launch.py",
        "validator_runtime.py",
        "validator_activation.py",
        "karwar.py",
        "volume.py",
        "state.py",
        "identity.py",
        "observe.py",
        "control.py",
        "host.py",
        "host_resources.py",
        "installer.py",
        "accounts_test.py",
    ] {
        assert!(
            python(script)
                .status()
                .expect("Python 3 is required")
                .success()
        );
    }
}
#[test]
fn generated_configuration_is_valid_toml_and_preserves_protocol_metadata() {
    let output = python("configure.py")
        .output()
        .expect("Python 3 is required");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("fixture JSON");
    assert_eq!(rows.len(), 2);
    for row in rows {
        let profile =
            erpc_chain_polygon::network::Network::get(row["network"].as_str().unwrap()).unwrap();
        assert_eq!(
            profile.digest().unwrap(),
            row["profile_digest"].as_str().unwrap()
        );
        let bor: toml::Value = toml::from_str(row["bor"].as_str().unwrap()).expect("Bor TOML");
        let consensus: toml::Value =
            toml::from_str(row["consensus"].as_str().unwrap()).expect("consensus TOML");
        let app: toml::Value =
            toml::from_str(row["app"].as_str().unwrap()).expect("application TOML");
        assert_eq!(bor["chain"].as_str(), row["network"].as_str());
        assert_eq!(bor["jsonrpc"]["http"]["host"].as_str(), Some("::"));
        assert_eq!(bor["jsonrpc"]["ws"]["host"].as_str(), Some("::"));
        assert_eq!(consensus["p2p"]["laddr"].as_str(), Some("tcp://[::]:26656"));
        assert_eq!(bor["protocol-marker"]["height"].as_integer(), Some(12345));
        assert_eq!(bor["miner"]["mine"].as_bool(), Some(false));
        assert_eq!(bor["accounts"]["disable-bor-wallet"].as_bool(), Some(true));
        let client: toml::Value =
            toml::from_str(row["client"].as_str().unwrap()).expect("client TOML");
        assert_eq!(client["keyring-backend"].as_str(), Some("memory"));
        assert_eq!(client["node"].as_str(), Some("tcp://127.0.0.1:26657"));
        assert_eq!(bor["heimdall"]["timeout"].as_str(), Some("30s"));
        assert_eq!(bor["state.scheme"].as_str(), Some("path"));
        assert_eq!(bor["db.engine"].as_str(), Some("pebble"));
        assert_eq!(
            consensus["p2p"]["seeds"].as_str(),
            Some("fixture-network-seed")
        );
        assert_eq!(
            consensus["p2p"]["external_address"].as_str(),
            Some("192.0.2.1:26656")
        );
        assert_eq!(consensus["rpc"]["unsafe"].as_bool(), Some(false));
        assert_eq!(app["pruning"].as_str(), Some("default"));
        assert_eq!(
            app["custom"]["eth_rpc_url"].as_str(),
            Some("http://127.0.0.1:9545")
        );
        assert_eq!(app["api"]["address"].as_str(), Some("tcp://127.0.0.1:1317"));
        assert!(!row.to_string().contains("fixture-unsafe-upstream"));
    }
}

#[test]
fn validator_configuration_separates_observer_and_hot_signer_and_limits_peers() {
    let output = python("validator_config.py")
        .output()
        .expect("Python 3 is required");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("fixture rows");
    assert_eq!(rows.len(), 4);
    for row in rows {
        let active = row["phase"] == "active";
        let bor: toml::Value = toml::from_str(row["bor"].as_str().unwrap()).expect("Bor TOML");
        let consensus: toml::Value =
            toml::from_str(row["consensus"].as_str().unwrap()).expect("CometBFT TOML");
        let app: toml::Value =
            toml::from_str(row["app"].as_str().unwrap()).expect("application TOML");
        assert_eq!(bor["miner"]["mine"].as_bool(), Some(active));
        assert_eq!(bor["accounts"]["disable-bor-wallet"].as_bool(), Some(true));
        assert_eq!(
            bor["accounts"]["allow-insecure-unlock"].as_bool(),
            Some(false)
        );
        assert_eq!(
            bor["accounts"]["unlock"].as_array().unwrap().len(),
            usize::from(active)
        );
        validator_private_transports(&bor, &consensus, &app);
        assert_eq!(bor["p2p"]["nodiscover"].as_bool(), Some(true));
        assert_eq!(bor["p2p"]["discovery"]["dns"].as_array().unwrap().len(), 0);
        assert_eq!(
            bor["p2p"]["discovery"]["static-nodes"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            bor["p2p"]["netrestrict"].as_str(),
            Some("192.0.2.2/32,2001:db8::3/128")
        );
        assert_eq!(consensus["p2p"]["seeds"].as_str(), Some(""));
        assert_eq!(consensus["p2p"]["pex"].as_bool(), Some(false));
        assert_eq!(
            consensus["priv_validator_state_file"].as_str(),
            Some(if active {
                "data/priv_validator_state.json"
            } else {
                "data/priv_validator_observer_state.json"
            })
        );
        assert_eq!(
            consensus["priv_validator_key_file"].as_str(),
            Some("config/priv_validator_key.json")
        );
        assert_eq!(
            bor["keystore"].as_str(),
            Some("/run/erpc-polygon-validator/bor-keystore")
        );
        assert_eq!(app["custom"]["amqp_url"].as_str(), Some(""));
        assert_eq!(
            app["custom"]["main_chain_gas_fee_cap"].as_str(),
            Some("500000000000")
        );
        assert_eq!(
            app["custom"]["main_chain_gas_tip_cap"].as_str(),
            Some("10000000000")
        );
        assert_eq!(bor["protocol-marker"]["height"].as_integer(), Some(12345));
        assert_eq!(
            consensus["consensus"]["timeout_propose"].as_str(),
            Some("1s")
        );
        assert_eq!(app["pruning"].as_str(), Some("default"));
        assert!(!row.to_string().contains("inert-old"));
    }
}

fn validator_private_transports(bor: &toml::Value, consensus: &toml::Value, app: &toml::Value) {
    assert_eq!(bor["jsonrpc"]["http"]["host"].as_str(), Some("127.0.0.1"));
    assert_eq!(bor["jsonrpc"]["http"]["enabled"].as_bool(), Some(false));
    assert_eq!(bor["jsonrpc"]["ws"]["enabled"].as_bool(), Some(false));
    assert_eq!(bor["jsonrpc"]["ipcdisable"].as_bool(), Some(false));
    assert_eq!(
        bor["jsonrpc"]["ipcpath"].as_str(),
        Some("/run/polygon-bor/native.rpc")
    );
    assert_eq!(
        bor["heimdall"]["url"].as_str(),
        Some("https://127.0.0.12:1317")
    );
    assert_eq!(
        app["custom"]["eth_rpc_url"].as_str(),
        Some("https://127.0.0.10:9545")
    );
    assert_eq!(
        app["custom"]["bor_rpc_url"].as_str(),
        Some("https://127.0.0.11:8545")
    );
    assert_eq!(
        app["custom"]["comet_bft_rpc_url"].as_str(),
        Some("https://127.0.0.13:26657")
    );
    assert_eq!(
        app["api"]["address"].as_str(),
        Some("unix:///run/polygon-heimdall/native.rest")
    );
    assert_eq!(
        consensus["rpc"]["tls_key_file"].as_str(),
        Some("/run/credentials/polygon-heimdall.service/comet-private-key")
    );

    assert_eq!(bor["jsonrpc"]["ws"]["host"].as_str(), Some("127.0.0.1"));
}
