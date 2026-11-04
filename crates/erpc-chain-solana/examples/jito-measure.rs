// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Measures Jito's regions from a real node, for checking the measurement by
//! hand:
//!
//! ```text
//! ERPC_PROBE_HOST_KEY='ssh-ed25519 AAAA…' \
//!   cargo run -p erpc-chain-solana --example jito-measure -- \
//!   <host> <user> <agent-socket> <public-key> <network>
//! ```

// A tool run by hand at a terminal: printing is its output.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;

use erpc_chain_solana::regions::{jito_for, measure, nearest};
use erpc_ssh::{HostKey, Identity, Session, Target};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [host, user, socket, public_key, network] = args.as_slice() else {
        eprintln!("usage: jito-measure <host> <user> <agent-socket> <public-key> <network>");
        std::process::exit(2);
    };
    if let Err(e) = run(host, user, socket, public_key, network) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(
    host: &str,
    user: &str,
    socket: &str,
    public_key: &str,
    network: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let host_key = HostKey::parse(&std::env::var("ERPC_PROBE_HOST_KEY").unwrap_or_default())?;
    let session = Session::open(&Target {
        host: host.to_owned(),
        port: 22,
        user: user.to_owned(),
        host_key,
        identity: Identity::Agent {
            socket: PathBuf::from(socket),
            public_key: PathBuf::from(public_key),
        },
    })?;
    let latencies = measure(&session, network)?;
    for l in &latencies {
        match l.ms {
            Some(ms) => println!("{:>12}  {ms:>8.2} ms", l.key),
            None => println!("{:>12}  no reply", l.key),
        }
    }
    let Some(best) = nearest(&latencies) else {
        return Err("no region answered".into());
    };
    println!("nearest: {}", best.key);
    println!("{:#?}", jito_for(network, &best.key, best.ms, "now"));
    Ok(())
}
