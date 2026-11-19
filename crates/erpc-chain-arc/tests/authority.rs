// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! POSIX host-model regressions; these do not provision a host or run Arc.

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
mod original_authority_filesystem_and_release_failure_cases {
    fn fixture(script: &str) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(script);
        let output = std::process::Command::new("python3")
            .arg("-B")
            .arg(path)
            .output()
            .expect("Python is required for host failure-path verification");
        assert!(
            output.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fixtures! {
        authority_primitives,
        authority_release,
        authority_prepare,
        authority_lifecycle,
        authority_migration,
        authority_recovery,
        authority_process,
        authority_observer,
        authority_firewall,
        authority_volume,
    }
}
