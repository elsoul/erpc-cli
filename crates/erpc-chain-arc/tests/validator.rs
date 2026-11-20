// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Isolated validator host models; no native node, key generation or NSS mutation.

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
mod validator_original_authority_failure_cases {
    fn fixture(script: &str) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(script);
        let output = std::process::Command::new("python3")
            .arg("-B")
            .arg(path)
            .output()
            .expect("Python is required for validator authority regressions");
        assert!(
            output.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fixtures! {
        validator_accounts,
        validator_custody,
        validator_admission,
        validator_state,
        validator_units,
        validator_ipc,
        validator_remote,
        validator_process,
        validator_control,
        validator_namespace,
        validator_storage,
        validator_loaded,
        validator_revocation,
    }
}
