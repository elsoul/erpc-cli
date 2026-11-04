// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Embeds the erpc worker agents (static musl, for `x86_64` and `aarch64`
//! Linux) that `erpc worker deploy` installs on a server, so the agent a
//! release ships is the one its signature covers.
//!
//! `ERPC_WORKER_AGENTS_DIR` names a directory holding
//! `erpc-worker-agent-x86_64-linux` and `erpc-worker-agent-aarch64-linux`
//! (`scripts/build-worker-agents.sh` makes it). Without it the build embeds
//! nothing and `deploy` looks for an agent beside erpc or in
//! `ERPC_WORKER_AGENT`. A release sets `ERPC_REQUIRE_WORKER_AGENTS=1`, so it
//! cannot ship without them.

use std::path::{Path, PathBuf};

const MACHINES: [&str; 2] = ["x86_64", "aarch64"];

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-env-changed=ERPC_WORKER_AGENTS_DIR");
    println!("cargo:rerun-if-env-changed=ERPC_REQUIRE_WORKER_AGENTS");
    // The catalogs are embedded by include_dir, which rustc does not track.
    println!("cargo:rerun-if-changed=locales");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("cargo did not set OUT_DIR")?);
    let dir = std::env::var_os("ERPC_WORKER_AGENTS_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    let required = std::env::var("ERPC_REQUIRE_WORKER_AGENTS").is_ok_and(|v| v == "1");
    for machine in MACHINES {
        let name = format!("erpc-worker-agent-{machine}-linux");
        let bytes = dir.as_deref().map_or_else(Vec::new, |dir| read(dir, &name));
        if required && bytes.is_empty() {
            return Err(format!(
                "ERPC_REQUIRE_WORKER_AGENTS=1 and {name} is not in ERPC_WORKER_AGENTS_DIR; \
                 run scripts/build-worker-agents.sh"
            ));
        }
        std::fs::write(out.join(&name), &bytes)
            .map_err(|e| format!("could not write {name} to OUT_DIR: {e}"))?;
    }
    Ok(())
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    let path = dir.join(name);
    println!("cargo:rerun-if-changed={}", path.display());
    std::fs::read(&path).unwrap_or_default()
}
