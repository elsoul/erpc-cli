// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-core`: shared config, inventory, output and error types for the erpc CLI.
//!
//! Phase 0 provides [`version`] and [`endpoints`]. Config (`~/.erpc`),
//! inventory, output formatting, guards and redaction land in Phase 1.

#![forbid(unsafe_code)]

pub mod endpoints;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-core";

/// Version and build information for the running binary.
pub mod version {
    use std::fmt;

    use serde::Serialize;

    /// Static build information embedded at compile time.
    ///
    /// `git_commit` and `build_time` are read from `ERPC_GIT_COMMIT` and
    /// `ERPC_BUILD_TIME` if the build environment sets them. **Nothing sets
    /// them today**, so every build reports `unknown`; stamping them in the
    /// release workflow has to keep the two independent builds byte-identical
    /// (see the rebuild comparison in `release-publish.yml`), which means
    /// deriving the timestamp from `SOURCE_DATE_EPOCH` rather than the clock.
    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    pub struct VersionInfo {
        /// Semantic version from `Cargo.toml`.
        pub version: &'static str,
        /// Full git commit hash of the build, when known.
        pub git_commit: &'static str,
        /// RFC 3339 build timestamp, when known.
        pub build_time: &'static str,
        /// Rust target triple the binary was compiled for.
        pub target: &'static str,
    }

    impl VersionInfo {
        /// Information about the currently running binary.
        #[must_use]
        pub fn current() -> Self {
            Self {
                version: env!("CARGO_PKG_VERSION"),
                git_commit: option_env!("ERPC_GIT_COMMIT").unwrap_or("unknown"),
                build_time: option_env!("ERPC_BUILD_TIME").unwrap_or("unknown"),
                target: target_triple(),
            }
        }
    }

    impl fmt::Display for VersionInfo {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "erpc {}", self.version)?;
            writeln!(f, "commit: {}", self.git_commit)?;
            writeln!(f, "built:  {}", self.build_time)?;
            write!(f, "target: {}", self.target)
        }
    }

    /// Target triple from compile-time cfg values.
    ///
    /// Covers the five release targets. A Linux build is only reported as
    /// `musl` when it really is one: a `cargo install` against glibc must not
    /// claim to be a release artifact in the output `SECURITY.md` asks
    /// reporters to paste. Anything else reports `unknown`.
    #[must_use]
    pub fn target_triple() -> &'static str {
        if cfg!(all(
            target_arch = "x86_64",
            target_os = "linux",
            target_env = "musl"
        )) {
            "x86_64-unknown-linux-musl"
        } else if cfg!(all(
            target_arch = "aarch64",
            target_os = "linux",
            target_env = "musl"
        )) {
            "aarch64-unknown-linux-musl"
        } else if cfg!(all(
            target_arch = "x86_64",
            target_os = "linux",
            target_env = "gnu"
        )) {
            "x86_64-unknown-linux-gnu"
        } else if cfg!(all(
            target_arch = "aarch64",
            target_os = "linux",
            target_env = "gnu"
        )) {
            "aarch64-unknown-linux-gnu"
        } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
            "x86_64-apple-darwin"
        } else if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
            "aarch64-apple-darwin"
        } else if cfg!(all(
            target_arch = "x86_64",
            target_os = "windows",
            target_env = "msvc"
        )) {
            "x86_64-pc-windows-msvc"
        } else if cfg!(all(
            target_arch = "x86_64",
            target_os = "windows",
            target_env = "gnu"
        )) {
            "x86_64-pc-windows-gnu"
        } else {
            "unknown"
        }
    }

    #[cfg(test)]
    mod tests {
        use super::VersionInfo;

        #[test]
        fn version_matches_cargo() {
            let v = VersionInfo::current();
            assert_eq!(v.version, env!("CARGO_PKG_VERSION"));
            assert!(!v.target.is_empty());
        }

        /// A build must not claim to be a release artifact it is not: the
        /// triple goes into the output `SECURITY.md` asks reporters to paste,
        /// and `musl` there would send a maintainer looking at the wrong build.
        #[test]
        fn target_triple_matches_the_compiled_environment() {
            let t = super::target_triple();
            if cfg!(target_os = "linux") {
                if cfg!(target_env = "musl") {
                    assert!(t.ends_with("-linux-musl"), "{t}");
                } else if cfg!(target_env = "gnu") {
                    assert!(t.ends_with("-linux-gnu"), "{t}");
                }
            } else if cfg!(target_os = "macos") {
                assert!(t.ends_with("-apple-darwin"), "{t}");
            } else if cfg!(all(target_os = "windows", target_env = "gnu")) {
                assert!(t.ends_with("-windows-gnu"), "{t}");
            } else if cfg!(all(target_os = "windows", target_env = "msvc")) {
                assert!(t.ends_with("-windows-msvc"), "{t}");
            }
            if cfg!(target_arch = "aarch64") {
                assert!(t.starts_with("aarch64-") || t == "unknown", "{t}");
            }
        }

        #[test]
        fn json_has_expected_keys() {
            let v = VersionInfo::current();
            let json = serde_json::to_value(&v).expect("serialize");
            for key in ["version", "git_commit", "build_time", "target"] {
                assert!(json.get(key).is_some(), "missing {key}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
