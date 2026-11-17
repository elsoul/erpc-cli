// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Inert publication/ownership tests; native clients are never executed.

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
mod artifact_and_state_failure_paths {
    fn fixture(script: &str) {
        let output = std::process::Command::new("python3")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(script),
            )
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("inert Python fixture");
        assert!(
            output.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fixtures! {
        artifact_test,
        state_failures,
        gateway_test,
        public_test,
        process_test,
        render_retention_test,
        setup_test,
        accounts_test,
        phases_test,
        entrypoints_test,
        host_test,
        validator_custody,
        validator_volume,
        validator_public,
        validator_modes,
        aqa_artifact,
        aqa_public,
        aqa_custody,
        aqa_runtime,
        aqa_entrypoints,
        aqa_accounts,
        aqa_process,
        aqa_host,
    }
}
