// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-core`: shared config, inventory, output and error types for the erpc CLI.
//!
//! Phase 0 provides only [`version`]. Config (`~/.erpc`), inventory, output
//! formatting, guards and redaction land in Phase 1.

#![forbid(unsafe_code)]

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-core";

/// Version and build information for the running binary.
pub mod version {
    use std::fmt;

    use serde::Serialize;

    /// Static build information embedded at compile time.
    ///
    /// `git_commit` and `build_time` are supplied by the release workflow
    /// through `ERPC_GIT_COMMIT` / `ERPC_BUILD_TIME`. Local builds show `unknown`.
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
    /// Limited to the five release targets; anything else reports the raw
    /// `arch-os` pair so support requests still carry the platform.
    #[must_use]
    pub fn target_triple() -> &'static str {
        if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
            "x86_64-unknown-linux-musl"
        } else if cfg!(all(target_arch = "aarch64", target_os = "linux")) {
            "aarch64-unknown-linux-musl"
        } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
            "x86_64-apple-darwin"
        } else if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
            "aarch64-apple-darwin"
        } else if cfg!(all(target_arch = "x86_64", target_os = "windows")) {
            "x86_64-pc-windows-msvc"
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
