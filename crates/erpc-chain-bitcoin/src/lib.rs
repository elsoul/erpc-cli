// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin Core network, storage and authenticated-release contracts.
//!
//! The metadata client authenticates manifests with both carried public keys.
//! Deployment templates repeat authentication and hash the archive before use;
//! the host controller enforces persistent ownership and private RPC settings.

#![forbid(unsafe_code)]

pub mod download;
pub mod network;
pub mod release;
pub mod status;
pub mod storage;

/// Component name.
pub const CRATE_NAME: &str = "erpc-chain-bitcoin";

/// Carried deployment tasks, helper and release verification keys.
pub static TEMPLATES: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");

/// Fixed isolated host controller used by carried recovery and normal SSH calls.
pub const CONTROLLER: &str = concat!(
    include_str!("../templates/node/original.py"),
    "\n",
    include_str!("../templates/node/migration.py"),
    "\n",
    include_str!("../templates/node/processes.py"),
    "\n",
    include_str!("../templates/node/control.py")
);

/// Fixed unit with an external descriptor-authenticating isolated guard.
/// # Errors
/// Root and out-of-range service identities are refused.
pub fn unit(uid: u32, gid: u32) -> Result<String, String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let source = include_str!("../templates/node/entrypoint.py");
    if uid == 0 || gid == 0 || uid >= (1 << 31) || gid >= (1 << 31) {
        return Err("invalid original Bitcoin numeric service account".into());
    }
    let hex = source
        .as_bytes()
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect::<String>();
    let guard = format!("/usr/bin/python3 -I -c \"exec(bytes.fromhex('{hex}'))\"");
    Ok(include_str!("../templates/node/erpc-bitcoin.service")
        .replace("@BITCOIN_GUARD@", &guard)
        .replace("@BITCOIN_UID@", &uid.to_string())
        .replace("@BITCOIN_GID@", &gid.to_string()))
}
