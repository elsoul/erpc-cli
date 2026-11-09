// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Execute inert failure fixtures without node, compiler, key or device execution.
#[cfg(unix)]
#[test]
fn controller_and_installed_publisher_select_the_same_complete_helper_revision() {
    let result = std::process::Command::new("python3")
        .args(["-B", "-c", "import pathlib,sys; root=pathlib.Path(sys.argv[1]); sys.path.insert(0,str(root)); import native_helpers as h; values={p.name:p.read_bytes() for p in root.iterdir() if p.is_file()}; print(h.revision(values))"])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/node"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        erpc_chain_solana_native::helper_revision().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn compiler_archive_and_publication_failures_are_exercised() {
    for name in [
        "toolchain_files.py",
        "build_inputs.py",
        "state_failures.py",
        "build_jobs.py",
        "entrypoints.py",
        "publication.py",
        "processes.py",
        "runtime_process.py",
        "runtime_observer.py",
        "runtime_control.py",
        "custody.py",
        "host.py",
        "host_layout.py",
        "tuning.py",
        "helpers.py",
        "deployment.py",
        "source_floor.py",
        "source_upgrade.py",
        "migration_copy.py",
        "migration_fence.py",
        "migration_privileges.py",
        "migration_retire.py",
        "migration_transfer.py",
        "migration_state.py",
        "migration_promote.py",
        "migration_settings.py",
        "migration_key.py",
        "migration_custody.py",
        "migration_cutover.py",
        "migration_guard.py",
        "migration_status.py",
        "migration_bls.py",
        "migration_process.py",
        "firewall.py",
        "gateway_account.py",
        "gateway.py",
        "gateway_package.py",
        "validator.py",
        "proof.py",
        "proof_recovery.py",
        "activation.py",
        "gateway_observer.py",
        "gateway_cutover.py",
        "mounts.py",
        "accounts.py",
    ] {
        let result = std::process::Command::new("python3")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(name),
            )
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("inert Python fixture");
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn carried_loader_authenticates_before_interpreting_its_controller() {
    let result = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/entrypoints.py"))
        .arg("--carried")
        .arg(erpc_chain_solana_native::carried_loader())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("inert carried entrypoint fixture");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
