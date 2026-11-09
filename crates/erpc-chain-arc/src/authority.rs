// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Closed immutable helper profile for original Arc host operations.

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

/// Native ABI and archive layout qualified for this original-authority profile.
pub const VERSION: &str = "v0.8.1";

/// Refuse executable sources outside the reviewed carried release catalog.
///
/// # Errors
/// Refuses any tag, commit or platform archive substitution.
pub fn qualify_source(
    version: &str,
    commit: &str,
    archive: &str,
    platform: crate::releases::Platform,
) -> Result<(), String> {
    let allowed = crate::releases::snapshot()
        .releases
        .into_iter()
        .any(|release| {
            release.tag == VERSION
                && version == VERSION
                && release.commit == commit
                && release.digest(platform) == Some(archive)
                && !release.prerelease
        });
    if !allowed {
        return Err("Arc native source is not in the carried execution catalog; original history is retained".into());
    }
    Ok(())
}

/// Installed namespace. Each complete release is addressed by its contents.
pub const NAMESPACE: &str = "/usr/local/lib/erpc/arc";
/// Public protocol identifier, also checked by the carried controller.
pub const SCHEMA: &str = "erpc-arc-original-authority-v1";

/// Every module consumed by the actual isolated controller, in digest order.
#[must_use]
pub fn profile() -> Vec<&'static str> {
    crate::files()
        .into_iter()
        .filter_map(|path| path.strip_prefix("authority/"))
        .filter(|path| {
            (std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext == "py")
                || *path == "networks.json")
                && !path.contains('/')
        })
        .collect()
}

/// Canonical non-weak Ed25519 public identity, without handling a private seed.
#[must_use]
pub fn public_identity(value: &str) -> bool {
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(value) else {
        return false;
    };
    let Ok(bytes): Result<[u8; 32], _> = raw.try_into() else {
        return false;
    };
    base64::engine::general_purpose::STANDARD.encode(bytes) == value
        && ed25519_dalek::VerifyingKey::from_bytes(&bytes).is_ok_and(|key| !key.is_weak())
}

/// Digest used by the installed current-pointer verifier.
///
/// # Errors
/// Refuses an incomplete or unexpectedly large helper profile.
pub fn helper_hash() -> Result<String, String> {
    let names = profile();
    if names.len() > 16 || !names.contains(&"control.py") {
        return Err("invalid Arc authority helper profile".into());
    }
    let mut hash = Sha256::new();
    for name in names {
        hash.update(
            crate::file(&format!("authority/{name}"))
                .ok_or("missing carried Arc authority module")?,
        );
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Isolated carried entrypoint; its sole argument is the sealed run's script.
/// The shared trust function is byte-identical to the common verifier.
///
/// # Errors
/// Refuses a build without the canonical trust source.
pub fn carried_loader() -> Result<String, String> {
    let trust = std::str::from_utf8(
        crate::file("authority/arc_trust.py").ok_or("missing Arc trust bootstrap")?,
    )
    .map_err(|_| "Arc trust bootstrap is not UTF-8")?;
    Ok(format!(
        "{trust}\nimport os,runpy,sys\nscript=os.path.abspath(sys.argv[1])\ntrusted_imports(os.path.dirname(script))\nsys.argv=[script]\nrunpy.run_path(script,run_name='__main__')\n"
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn executable_catalog_is_exact_and_agrees_with_the_native_helper() {
        use crate::releases::{Platform, snapshot};
        let known = snapshot()
            .releases
            .into_iter()
            .find(|release| release.tag == super::VERSION)
            .unwrap();
        let source = std::str::from_utf8(crate::file("authority/arc_release.py").unwrap()).unwrap();
        assert!(source.contains(&known.commit));
        for platform in [Platform::X86_64, Platform::Aarch64] {
            let archive = known.digest(platform).unwrap();
            assert!(source.contains(archive));
            super::qualify_source(&known.tag, &known.commit, archive, platform).unwrap();
            assert!(super::qualify_source("v0.8.2", &known.commit, archive, platform).is_err());
            assert!(super::qualify_source(&known.tag, &"a".repeat(40), archive, platform).is_err());
            assert!(
                super::qualify_source(&known.tag, &known.commit, &"b".repeat(64), platform)
                    .is_err()
            );
        }
    }

    #[test]
    fn complete_profile_uses_the_same_flat_digest_order_as_the_installed_loader() {
        let names = super::profile();
        assert!(names.contains(&"control.py"));
        assert!(names.contains(&"arc_custody.py"));
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        let digest = super::helper_hash().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(super::carried_loader().unwrap().contains("trusted_imports"));
    }
}
