// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Inert controller/ABI fixtures. No device, blockchain client or real key is executed.

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
mod native_failure_paths_preserve_ownership_identity_and_cancellation {
    fn fixture(name: &str) {
        let result = std::process::Command::new("python3")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(name),
            )
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("offline Python harness");
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    fixtures! {
        device_identity,
        state_failures,
        host_failures,
        registration_observer,
        accounts_test,
        namespace_test,
        entrypoints_test,
        account_authority,
        data_layout,
        incomplete_data_recovery,
    }
}

#[test]
fn embedded_runtime_contains_no_generated_bytecode_or_secret_files() {
    for path in erpc_chain_monad::files() {
        let extension = std::path::Path::new(path)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();
        assert!(
            !path.contains("__pycache__")
                && !["pyc", "cred"]
                    .iter()
                    .any(|kind| extension.eq_ignore_ascii_case(kind)),
            "{path}"
        );
    }
}
