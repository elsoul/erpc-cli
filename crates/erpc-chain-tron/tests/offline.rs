// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Offline native API adapter and custody-boundary regression checks.

/// One test per Python fixture, named after its file: the fixtures run in
/// parallel, and each one that fails is reported, not only the first. The
/// modules that use it are `cfg(test)`, so their shared `fixture` helper may
/// `expect` as a test does.
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

#[cfg(test)]
mod custody_and_native_adapter_failures {
    fn fixture(script: &str) {
        let result = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(script),
            )
            .status()
            .expect("Python 3 and a JDK are required for offline TRON adapter checks");
        assert!(result.success());
    }

    fixtures! {
        offline,
        control_paths,
        authority,
        transport,
        trust,
    }
}
