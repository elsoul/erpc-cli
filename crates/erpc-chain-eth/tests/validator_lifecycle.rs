// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Runs the remote helper against fake systemd/Lighthouse/RPC and temporary files.
#[cfg(unix)]
#[test]
fn custody_failure_and_recovery_paths() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let result = std::process::Command::new("python3")
        .arg(root.join("tests/validator_control.py"))
        .arg(root.join("templates/validator/control.py"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("Python 3 for offline control-helper tests");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn upstream_public_deposits_verify_and_tampered_data_does_not() {
    // Public-only deposit vectors from Lighthouse v8.3.2; no mnemonic/keystore copied.
    // https://github.com/sigp/lighthouse/tree/a376defa30470923556d91bdeb15a802e297f31f/validator_manager/test_vectors/vectors
    for (network, fixture) in [
        ("hoodi", include_str!("deposit-hoodi.json")),
        ("mainnet", include_str!("deposit-mainnet.json")),
    ] {
        let net = erpc_chain_eth::validator::network(network).expect("network");
        let value: serde_json::Value = serde_json::from_str(fixture).expect("public fixture");
        let key = format!("0x{}", value[0]["pubkey"].as_str().expect("public key"));
        let withdrawal = format!(
            "0x{}",
            &value[0]["withdrawal_credentials"]
                .as_str()
                .expect("withdrawal")[24..]
        );
        assert!(erpc_chain_eth::deposit::review(&value, net, &key, &withdrawal).is_ok());
        for field in [
            "signature",
            "deposit_message_root",
            "deposit_data_root",
            "withdrawal_credentials",
            "pubkey",
            "fork_version",
        ] {
            let mut bad = value.clone();
            let text = bad[0][field].as_str().expect("hex");
            let replacement = format!(
                "{}{}",
                if text.starts_with('0') { "1" } else { "0" },
                &text[1..]
            );
            bad[0][field] = serde_json::json!(replacement);
            assert!(
                erpc_chain_eth::deposit::review(&bad, net, &key, &withdrawal).is_err(),
                "{field}"
            );
        }
        let mut duplicate = value.clone();
        duplicate
            .as_array_mut()
            .expect("array")
            .push(value[0].clone());
        assert!(erpc_chain_eth::deposit::review(&duplicate, net, &key, &withdrawal).is_err());
        let other = erpc_chain_eth::validator::network(if network == "hoodi" {
            "mainnet"
        } else {
            "hoodi"
        })
        .expect("network");
        assert!(erpc_chain_eth::deposit::review(&value, other, &key, &withdrawal).is_err());
    }
}
