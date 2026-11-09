// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Reviewed network-qualified releases, Testnet requalified 2026-11-04; Mainnet sourced 2026-10-26 from `MystenLabs`.
//! GitHub asset SHA-256 metadata is the binary trust anchor, not a GPG claim.

use serde::Serialize;

/// A deployment network with immutable artifact identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Network {
    /// CLI network name.
    pub name: &'static str,
    /// Genesis checkpoint short identifier.
    pub chain_id: &'static str,
    /// Network-qualified release tag.
    pub version: &'static str,
    /// Source revision resolved from that tag.
    pub commit: &'static str,
    /// Downloaded genesis blob SHA-256 (not the checkpoint digest).
    pub genesis_sha256: &'static str,
    /// Linux `x86_64` archive SHA-256.
    pub amd64_sha256: &'static str,
    /// Linux aarch64 archive SHA-256.
    pub arm64_sha256: &'static str,
}

/// Immutable genesis repository revision, checked for both networks.
pub const GENESIS_COMMIT: &str = "5a1fc5b1e91c9caa31f95a930848f65dfc5129f4";

/// Supported production networks. Devnet resets require a new deployment contract.
#[must_use]
pub fn get(name: &str) -> Option<Network> {
    match name {
        "mainnet" => Some(Network {
            name: "mainnet",
            chain_id: "35834a8a",
            version: "mainnet-v1.82.3",
            commit: "bf4073918ed33cfa0b09c500658fa116a774bcfd",
            genesis_sha256: "b57abe29e52ea89b68df6d08224c234f6e2cb1fa357203b12ba50dd4776f9038",
            amd64_sha256: "d616d63d90309926cf7f544633c8dd4132f762fdbba555a35c4842cfa4129379",
            arm64_sha256: "1946a62d579b1c1fe8725d4c5c22b3d75ee0312a97ccc726e54dec8f966bc0e6",
        }),
        "testnet" => Some(Network {
            name: "testnet",
            chain_id: "4c78adac",
            version: "testnet-v1.83.1",
            commit: "0e0ede4cbf48c6d7654b613f62fdca71542ace03",
            genesis_sha256: "df78eb5e525294d29c9f710a0d80c3b8e5c9f6e2e6485098584f0695d80de2aa",
            amd64_sha256: "1a59344f7e17c3f694c2f17f4a23c29e55293d5d5eb294d0dcafff304b188347",
            arm64_sha256: "c58f07c692f7b00a21b0177fff22589ccc89e90eb7a7d629295d16104fbc95b5",
        }),
        _ => None,
    }
}

/// Qualified original releases, including the previous testnet source for explicit history.
#[must_use]
pub fn historical(name: &str, version: &str) -> Option<Network> {
    let mut profile = get(name)?;
    if profile.version == version {
        return Some(profile);
    }
    if name == "testnet" && version == "testnet-v1.82.2" {
        profile.version = "testnet-v1.82.2";
        profile.commit = "e10772f4fafef31c46f598835fe66648caf6e005";
        profile.amd64_sha256 = "201427d5121422e878aa27dd6f66642af2b512a9b37b24ce4b3901c29d4b2750";
        profile.arm64_sha256 = "56b30fc29db8ffff4552f0f68c2f6e2037c1605c6ebffbe3e0091d8222950ee1";
        return Some(profile);
    }
    None
}

impl Network {
    /// Immutable genesis download URL.
    #[must_use]
    pub fn genesis_url(self) -> String {
        format!(
            "https://github.com/MystenLabs/sui-genesis/raw/{GENESIS_COMMIT}/{}/genesis.blob",
            self.name
        )
    }

    /// Release URL and digest for a supported `uname -m` result.
    ///
    /// # Errors
    /// Refuses architectures without an explicitly reviewed artifact.
    pub fn archive(self, architecture: &str) -> Result<(String, &'static str), String> {
        let digest = match architecture {
            "x86_64" => self.amd64_sha256,
            "aarch64" => self.arm64_sha256,
            _ => return Err("Sui releases support Linux x86_64 or aarch64".to_owned()),
        };
        Ok((
            format!(
                "https://github.com/MystenLabs/sui/releases/download/{}/sui-{}-ubuntu-{architecture}.tgz",
                self.version, self.version
            ),
            digest,
        ))
    }

    /// Refuse a saved inventory pin that would select another network or arbitrary download.
    ///
    /// # Errors
    /// Returns a message for stale or mismatched pins; updates require a reviewed CLI release.
    pub fn validate_pin(
        self,
        version: &str,
        commit: &str,
        digest: &str,
        arch: &str,
    ) -> Result<(), String> {
        if version != self.version || commit != self.commit || digest != self.archive(arch)?.1 {
            return Err("stored Sui pin differs from this CLI's reviewed network release; use update to adopt the reviewed pin".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::get;
    #[test]
    fn cross_network_and_modified_artifacts_are_refused() {
        let main = get("mainnet").expect("network");
        let test = get("testnet").expect("network");
        assert!(
            main.validate_pin(test.version, test.commit, test.amd64_sha256, "x86_64")
                .is_err()
        );
        assert!(
            main.validate_pin(main.version, main.commit, test.amd64_sha256, "x86_64")
                .is_err()
        );
        assert!(main.archive("armv7").is_err());
        assert!(get("devnet").is_none());
        for net in [main, test] {
            assert!(erpc_core::endpoints::ensure_service_url(&net.genesis_url()).is_ok());
            for arch in ["x86_64", "aarch64"] {
                assert!(
                    erpc_core::endpoints::ensure_service_url(
                        &net.archive(arch).expect("archive").0
                    )
                    .is_ok()
                );
            }
        }
    }
}
