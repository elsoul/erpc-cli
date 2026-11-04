// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Network-qualified official release metadata checked on 2026-10-26.
use serde::Serialize;

/// An immutable public network and its independently signed client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Network {
    /// CLI network name.
    pub name: &'static str,
    /// Official repository for this network.
    pub repository: &'static str,
    /// Exact release tag.
    pub tag: &'static str,
    /// Resolved source commit.
    pub commit: &'static str,
    /// Native `Version.getVersion()`, which differs from its stale `VERSION_NAME` banner.
    pub version: &'static str,
    /// Full genesis block identifier, independently observed from the public API.
    pub genesis: &'static str,
    /// Source filename for the complete network configuration.
    pub config_name: &'static str,
    /// Complete configuration content SHA-256.
    pub config_sha256: &'static str,
    /// Official primary GPG key fingerprint.
    pub primary_fingerprint: &'static str,
    /// Exact signing fingerprint, including Mainnet's signing subkey.
    pub signing_fingerprint: &'static str,
}

/// Selected architecture-specific release artifacts and Java runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Artifact {
    /// Immutable release URL.
    pub url: String,
    /// JAR content digest from the official release API.
    pub sha256: &'static str,
    /// Detached signature URL.
    pub signature_url: String,
    /// Detached signature content digest from the official release API.
    pub signature_sha256: &'static str,
    /// Ubuntu JDK package; its security updates remain distribution-managed.
    pub java_package: &'static str,
    /// Exact architecture/version-specific launcher path, never PATH-selected.
    pub java: &'static str,
    /// Compiler for the tiny native-keystore inspection adapter.
    pub javac: &'static str,
    /// JVM major version required by this architecture upstream.
    pub java_major: u8,
    /// Database engine: upstream forces `RocksDB` on ARM64.
    pub database: &'static str,
}

/// Supported public node networks; Shasta rejects third-party node participation.
#[must_use]
pub fn get(name: &str) -> Option<Network> {
    match name {
        "mainnet" => Some(Network {
            name: "mainnet",
            repository: "tronprotocol/java-tron",
            tag: "GreatVoyage-v4.8.2.4",
            commit: "4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9",
            version: "4.8.2.4",
            genesis: "00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc",
            config_name: "config.conf",
            config_sha256: "fb51f5ee508cefb4e0d4b0c1868029e385a997ee9b7468875c9d781d77b0ea2a",
            primary_fingerprint: "07B23298AEA4E006BD9A42DE785FB96D2C7C3CA5",
            signing_fingerprint: "1254F859D2B1BD9F66E7107DF859BCB44A28290B",
        }),
        "nile" => Some(Network {
            name: "nile",
            repository: "tron-nile-testnet/nile-testnet",
            tag: "GreatVoyage-Nile-v4.8.2.4-PQ1-build1",
            commit: "bc7752b638d9aa4da413c78645dcff1a1aa8e40a",
            version: "4.8.2.4.PQ1_build1",
            genesis: "0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc",
            config_name: "config-nile.conf",
            config_sha256: "296455a150477bc0f80a4125a57809cafcd843c271f1d7973ee051576a827b84",
            primary_fingerprint: "BBA2FC19D5F0B54AB1EE072BCA92A5501765E1EC",
            signing_fingerprint: "BBA2FC19D5F0B54AB1EE072BCA92A5501765E1EC",
        }),
        _ => None,
    }
}

impl Network {
    /// Complete network configuration, independently pinned before local overrides.
    #[must_use]
    pub fn config_url(self) -> String {
        format!(
            "https://github.com/{}/raw/{}/framework/src/main/resources/{}",
            self.repository, self.commit, self.config_name
        )
    }

    /// Select reviewed JAR, signature and platform requirements together.
    /// # Errors
    /// Refuses architectures without published, independently reviewed artifacts.
    pub fn artifact(self, architecture: &str) -> Result<Artifact, String> {
        let (suffix, java_package, java, java_major, database) = match architecture {
            "x86_64" => (
                "x64",
                "openjdk-8-jdk-headless",
                "/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java",
                8,
                "LEVELDB",
            ),
            "aarch64" => (
                "aarch64",
                "openjdk-17-jdk-headless",
                "/usr/lib/jvm/java-17-openjdk-arm64/bin/java",
                17,
                "ROCKSDB",
            ),
            _ => return Err("TRON supports reviewed Linux x86_64/aarch64 profiles".into()),
        };
        let (jar, sha256, signature_sha256) = match (self.name, suffix) {
            ("mainnet", "x64") => (
                "FullNode-x64.jar",
                "709423e8d14ccba391daeef7aa78bb5f41a1b69559cc867346beacbd6aae39c9",
                "3039807a83f4dc80bc38d859a602786b56e41217b7cfe2ffbd73f0d57cf15192",
            ),
            ("mainnet", "aarch64") => (
                "FullNode-aarch64.jar",
                "a185d0ddff6e3cebd69ac46b7f6c6fa8051c7d4c2e9fe8c55be0867bd06a21d4",
                "5c250f209ecc4baf38f68e7ef3f4ee4e5b21266e376046b11c3ff56de7ba459a",
            ),
            ("nile", "x64") => (
                "FullNode-Nile-x64-4.8.2.4-pq1-build1.jar",
                "b62fb08e647b1336749a2da1bfa37447377e26c80fd85540fabea5b2de23dc41",
                "48b3c937dd871cb4e88e3f8afaac58d95da71c4ec7abbf925b08ed394d95e9d8",
            ),
            ("nile", "aarch64") => (
                "FullNode-Nile-aarch64-4.8.2.4-pq1-build1.jar",
                "53d23346e2f59f57ce956f843834d051685b9a0a1f08c69d9841daac1006f416",
                "176e0fd61206045c3508fd65ab0d6d3566230cc520ded3ecc5058e714c58052e",
            ),
            _ => return Err("unknown TRON artifact".into()),
        };
        let url = format!(
            "https://github.com/{}/releases/download/{}/{jar}",
            self.repository, self.tag
        );
        Ok(Artifact {
            signature_url: format!("{url}.sig"),
            url,
            sha256,
            signature_sha256,
            java_package,
            java,
            javac: if java_major == 8 {
                "/usr/lib/jvm/java-8-openjdk-amd64/bin/javac"
            } else {
                "/usr/lib/jvm/java-17-openjdk-arm64/bin/javac"
            },
            java_major,
            database,
        })
    }

    /// Verify saved inventory never selects a different client or network.
    /// # Errors
    /// Rejects modified/stale pins; upgrading requires this CLI's reviewed release.
    pub fn validate(
        self,
        architecture: &str,
        tag: &str,
        commit: &str,
        digest: &str,
    ) -> Result<(), String> {
        if tag != self.tag || commit != self.commit || digest != self.artifact(architecture)?.sha256
        {
            return Err(
                "stored TRON release differs from the reviewed network pin; use update".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_and_architecture_select_distinct_artifacts_and_runtime() {
        let main = get("mainnet").unwrap();
        let nile = get("nile").unwrap();
        assert!(get("shasta").is_none());
        assert_ne!(main.genesis, nile.genesis);
        assert_ne!(main.signing_fingerprint, nile.signing_fingerprint);
        for network in [main, nile] {
            let x64 = network.artifact("x86_64").unwrap();
            let arm = network.artifact("aarch64").unwrap();
            assert_ne!(x64.sha256, arm.sha256);
            assert_eq!(x64.java_major, 8);
            assert_eq!(arm.java_major, 17);
            assert_eq!(arm.database, "ROCKSDB");
            assert!(
                network
                    .validate("x86_64", network.tag, network.commit, x64.sha256)
                    .is_ok()
            );
            assert!(
                network
                    .validate("aarch64", network.tag, network.commit, x64.sha256)
                    .is_err()
            );
        }
        assert!(
            nile.validate(
                "x86_64",
                main.tag,
                main.commit,
                main.artifact("x86_64").unwrap().sha256
            )
            .is_err()
        );
    }
}
