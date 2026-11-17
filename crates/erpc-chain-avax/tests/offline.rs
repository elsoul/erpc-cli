// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Execute identity custody failure tests using inert fixture data.

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
mod identity_custody_failure_paths_execute_without_a_node {
    fn fixture(name: &str) {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(name);
        let result = std::process::Command::new("python3")
            .arg("-B")
            .arg(script)
            .output()
            .expect("Python 3");
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    fixtures! {
        offline,
        authority,
        observe,
        gateway,
        gateway_startup,
        firewall_integration,
        install_cache,
    }
}
