// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Execute original-authority failure fixtures without native host operations.

#[cfg(unix)]
#[test]
fn original_authority_failure_paths_use_inert_host_effects() {
    for name in [
        "accounts",
        "layout",
        "state",
        "runtime",
        "migration",
        "process",
        "jwt",
        "entrypoints",
        "capacity",
        "artifacts",
        "namespace",
        "play",
        "source_floor",
        "volume",
        "validator_custody",
        "validator_transport",
        "validator_native",
        "validator_tls",
        "validator_runtime",
        "validator_keys",
        "validator_health",
        "validator_control",
        "validator_migration",
        "validator_units",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(format!("authority_{name}.py"));
        let output = std::process::Command::new("python3")
            .arg("-B")
            .arg(path)
            .output()
            .expect("inert Python fixture");
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn publisher_and_ssh_select_the_same_complete_profile() {
    let program = "import ast,json,pathlib,sys; tree=ast.parse(pathlib.Path(sys.argv[1]).read_text()); print(json.dumps(next(ast.literal_eval(x.value) for x in tree.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='RPC_FILES' for t in x.targets))))";
    let output = std::process::Command::new("python3")
        .args(["-I", "-c", program])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/authority/eth_namespace.py"
        ))
        .output()
        .unwrap();
    assert!(output.status.success());
    let profile: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(profile, erpc_chain_eth::authority::PROFILE);
}

#[cfg(unix)]
#[test]
fn validator_publisher_profile_matches_the_typed_controller_profile() {
    let program = "import json,pathlib,sys; sys.path.insert(0,sys.argv[1]); import eth_namespace as n; print(json.dumps(n.VALIDATOR_FILES))";
    let output = std::process::Command::new("python3")
        .args(["-I", "-B", "-c", program])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/authority"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let profile: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(profile, erpc_chain_eth::authority::VALIDATOR_PROFILE);
    for name in profile {
        assert!(erpc_chain_eth::file(&format!("authority/{name}")).is_some());
    }
}
