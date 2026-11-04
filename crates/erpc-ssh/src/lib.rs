// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-ssh`: Hardened OpenSSH executor with host pinning for the erpc CLI.
//!
//! - **Host key:** a connection accepts only the node's pinned `ssh-ed25519`
//!   key, which lives in the host's 1Password item and is written to a
//!   `known_hosts` that exists for the run alone.
//! - **Configuration:** it is generated for the connection, and `ssh -G`
//!   confirms before anything connects that OpenSSH would use it as written:
//!   no proxy, no forwarding, no agent unless named, no password prompts.
//! - **Commands:** the commands a node may be sent are a fixed set with checked
//!   arguments. Secrets go in on standard input, never on a command line.

#![forbid(unsafe_code)]

pub mod arc;
pub mod avax;
pub mod bitcoin;
pub mod command;
pub mod config;
pub mod eth;
pub mod eth_validator;
pub mod exec;
pub mod firewall;
pub mod first_login;
pub mod hostkey;
mod nitro;
pub mod rollup;
pub mod solana_rpc;
pub mod sui;
pub mod tron;
pub mod vps;
pub mod worker;

pub use command::{
    FREE_DISKS_SCRIPT, KeyFilePath, PING_PREFIX, PingTargets, RESULT_MARKER, RemoteCommand,
    RemotePath, RunId, RunStart,
};
pub use config::{Identity, Target};
pub use exec::{Output, Session, SshError, Stream, agent_holds, keyscan};
pub use hostkey::HostKey;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-ssh";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
