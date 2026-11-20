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

/// One test per Python fixture, named after its file: the fixtures run in
/// parallel, and each one that fails is reported, not only the first. The
/// modules that use it are `cfg(test)`, so their shared `fixture` helper may
/// `expect` as a test does.
#[cfg(unix)]
macro_rules! fixtures {
    ($($fixture:ident),* $(,)?) => {
        $(
            #[test]
            fn $fixture() {
                fixture(concat!(stringify!($fixture), ".py"));
            }
        )*
    };
}

#[cfg(unix)]
#[cfg(test)]
mod compiler_archive_and_publication_failures_are_exercised {
    fn fixture(name: &str) {
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

    fixtures! {
        toolchain_files,
        build_inputs,
        state_failures,
        build_jobs,
        entrypoints,
        publication,
        processes,
        runtime_process,
        runtime_observer,
        runtime_control,
        custody,
        host,
        host_layout,
        tuning,
        helpers,
        deployment,
        source_floor,
        source_upgrade,
        migration_copy,
        migration_fence,
        migration_privileges,
        migration_retire,
        migration_transfer,
        migration_state,
        migration_promote,
        migration_settings,
        migration_key,
        migration_custody,
        migration_cutover,
        migration_guard,
        migration_status,
        migration_bls,
        migration_process,
        firewall,
        gateway_account,
        gateway,
        gateway_package,
        validator,
        proof,
        proof_recovery,
        activation,
        gateway_observer,
        gateway_cutover,
        mounts,
        accounts,
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
