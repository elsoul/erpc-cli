// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Reviewed network, source and immutable image identities.

/// Reviewed first-party release and network identities. Only linux/amd64 is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    /// Protocol string chain ID.
    pub name: &'static str,
    /// Release tag; Testnet deliberately uses its qualified prerelease.
    pub version: &'static str,
    /// Source revision resolved from the official release.
    pub commit: &'static str,
    /// Immutable platform-specific official OCI image, not a mutable network tag.
    pub image: &'static str,
    /// Hash reported by the network's read-only status API, independently of artifact SHA256.
    pub genesis_hash: &'static str,
    /// Initial block height from official genesis.
    pub genesis_height: u64,
    /// SHA256 of the fetched genesis bytes (XZ for Testnet).
    pub genesis_sha256: &'static str,
    /// SHA256 of the reviewed official RPC configuration before strict overrides.
    pub config_sha256: &'static str,
}

/// Resolve only the reviewed public networks.
#[must_use]
pub fn get(name: &str) -> Option<Network> {
    match name {
        "mainnet" => Some(Network {
            name: "mainnet",
            version: "2.14.0",
            commit: "bc4e9e8cfb03d9e82f027883055624e18576993e",
            image: "nearprotocol/nearcore@sha256:6c4f7a681b8920f0d9ec5256bac6aac00f657afd9de6c5a73b72e178f0c30082",
            genesis_hash: "EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H",
            genesis_height: 9_820_210,
            genesis_sha256: "501446da246048d0378979bea8e9f21a3a8f5ecd5fd1a6e2a709ace1ab6883a3",
            config_sha256: "274f8e66714d6d45830d90853fba0e4ea75309d96b3b0680bfc8f968e8106337",
        }),
        "testnet" => Some(Network {
            name: "testnet",
            version: "2.14.0-rc.6",
            commit: "d37c9e9ed3412dfab319e2e56bde24fd38e62ef1",
            image: "nearprotocol/nearcore@sha256:873963dceb8d14d94d35995cf51f1b98d2e6e8c85b031b69ace0664e9ce737ca",
            genesis_hash: "FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b",
            genesis_height: 42_376_888,
            genesis_sha256: "8a9d7a103b23d18879a73448fbb79bde547064c481e8f5d9db011478a671f48d",
            config_sha256: "a1c93a945b1827e952a4793e99d2b8c138f9f43865761c97254435d1f5027cef",
        }),
        _ => None,
    }
}

impl Network {
    /// Refuse platform guesses; upstream currently publishes only this native architecture.
    /// # Errors
    /// Returns an unsupported-platform error before pulling or mutating a host.
    pub fn platform(self, architecture: &str) -> Result<(), String> {
        if architecture == "x86_64" {
            Ok(())
        } else {
            Err("the reviewed NEAR image is linux/amd64 only".into())
        }
    }
    /// Verify actual binary output before installing a release target.
    /// # Errors
    /// Rejects another release, source revision or malformed output.
    pub fn verify_version(self, output: &str) -> Result<(), String> {
        if !output.starts_with("neard ")
            || !output.contains(&format!("(release {})", self.version))
            || !output.contains(&format!("(commit {})", self.commit))
        {
            return Err("NEAR binary release/source identity differs from the reviewed pin".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_network_tag_or_version_string_alone_cannot_authorize_a_binary() {
        let main = get("mainnet").unwrap();
        let test = get("testnet").unwrap();
        let output = format!(
            "neard (release {}) (build tag) (commit {}) (rustc 1.93.0)",
            main.version, main.commit
        );
        assert!(main.verify_version(&output).is_ok());
        assert!(test.verify_version(&output).is_err());
        assert!(
            main.verify_version(&output.replace(main.commit, &"0".repeat(40)))
                .is_err()
        );
        assert!(main.platform("aarch64").is_err());
        assert!(get("localnet").is_none());
    }
}
