// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Source-built Agave profiles, separate from the carried legacy solv templates.
#![forbid(unsafe_code)]
pub mod contract;
pub mod migration;
pub mod migration_request;

use include_dir::{Dir, include_dir};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// Content identity used by the installed native helper publisher.
/// # Errors
/// Refuses a malformed compiled node-resource path or missing resource.
pub fn helper_revision() -> Result<String, String> {
    let mut hash = Sha256::new();
    for path in files().into_iter().filter(|path| path.starts_with("node/")) {
        let name = path
            .strip_prefix("node/")
            .ok_or("invalid native helper path")?;
        if name.contains('/') {
            return Err("nested native helper resources are unsupported".into());
        }
        hash.update(name.as_bytes());
        hash.update([0]);
        hash.update(Sha256::digest(
            file(path).ok_or("native helper resource missing")?,
        ));
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Compiled native deployment inputs; no operational key material.
pub static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// External loader for the carried, sealed Ansible bundle. Its path is a
/// separate argument; installed code is checked before Python interprets it.
#[must_use]
pub fn carried_loader() -> String {
    format!(
        "{}\nimport runpy, sys\nfrom pathlib import Path\npath=Path(sys.argv[1])\nif not path.is_absolute() or path.name != 'native_runtime_control.py': raise ValueError('invalid native controller path')\ntrusted_imports(path.parent)\nsys.argv=sys.argv[1:]\nrunpy.run_path(str(path), run_name='__main__')",
        include_str!("../templates/node/native_trust.py")
    )
}
/// A fixed official compiler component.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    /// Exact dated official artifact URL.
    pub url: String,
    /// Digest qualified from the official version manifest.
    pub sha256: String,
    /// Exact size verified from the official archive stream.
    pub size: u64,
    /// Independent download-size ceiling.
    pub maximum_bytes: u64,
}
/// Native source and compiler qualification for one network.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Official fixed gossip rendezvous addresses; only native nodes contact them.
    pub entrypoints: Vec<String>,
    /// Official bootstrap identities used with only-known-rpc.
    pub known_validators: Vec<String>,
    /// Canonical chain genesis identity.
    pub genesis: String,
    /// Upstream source release.
    pub version: String,
    /// Resolved immutable source commit.
    pub commit: String,
    /// Digest of the exact source Cargo.lock.
    pub cargo_lock_sha256: String,
    /// Compiler version from this source's rust-toolchain.toml.
    pub rust: String,
    /// Date from the official Rust version manifest.
    pub rust_date: String,
    /// Digest of that manifest.
    pub rust_manifest_sha256: String,
    /// Qualified compiler, cargo and standard library artifacts.
    pub components: BTreeMap<String, Component>,
}
/// Build inputs selected by a reviewed CLI release.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Catalog schema, currently one.
    pub schema: u8,
    /// Official source repository; no operator override.
    pub repository: String,
    /// Network-qualified source/compiler pairs.
    pub networks: BTreeMap<String, Profile>,
    /// Only these fully pinned upstream git dependencies are accepted.
    pub git_sources: Vec<String>,
    /// Arguments to the upstream production/developer separating install script.
    pub build_options: Vec<String>,
    /// Required native production executables to publish.
    pub publish_binaries: Vec<String>,
}
/// Read compiled qualification metadata.
/// # Errors
/// A malformed compiled catalog is refused.
pub fn catalog() -> Result<Catalog, String> {
    let bytes = TEMPLATES
        .get_file("node/catalog.json")
        .ok_or("compiled native catalog is missing")?
        .contents();
    let catalog: Catalog =
        serde_json::from_slice(bytes).map_err(|_| "invalid compiled native catalog")?;
    if catalog.schema != 1 {
        return Err("unsupported native catalog schema".into());
    }
    Ok(catalog)
}
/// Read one immutable deployment resource.
#[must_use]
pub fn file(path: &str) -> Option<&'static [u8]> {
    TEMPLATES.get_file(path).map(include_dir::File::contents)
}
/// Enumerate resources to seal into a remote run bundle.
#[must_use]
pub fn files() -> Vec<&'static str> {
    fn walk(dir: &'static Dir<'static>, out: &mut Vec<&'static str>) {
        for file in dir.files() {
            if let Some(path) = file.path().to_str() {
                out.push(path);
            }
        }
        for child in dir.dirs() {
            walk(child, out);
        }
    }
    let mut result = Vec::new();
    walk(&TEMPLATES, &mut result);
    result.sort_unstable();
    result
}
