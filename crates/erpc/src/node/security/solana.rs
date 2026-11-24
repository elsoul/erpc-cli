// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A Solana validator's RPC settings, from its command line. The command
//! line and the paths in it stay on the server; only the settings' values
//! are reported.

use std::net::IpAddr;
use std::num::NonZeroU16;

use erpc_api::security_check::{Bind, SolanaApp, SolanaNode, Tristate};

/// The settings in `args`, the validator's arguments after its program.
/// `identity` says whether the identity keypair named there is a file.
pub(super) fn node(
    app: SolanaApp,
    args: &[String],
    identity: impl Fn(&str) -> Tristate,
) -> SolanaNode {
    let mut rpc_port = None;
    let mut rpc_bind_address = None;
    let mut bind_address = None;
    let mut identity_path = None;
    let mut full_rpc_api = false;
    let mut private_rpc = false;
    let mut rpc_tx_history = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value.to_owned())),
            _ => (arg.as_str(), None),
        };
        let mut value = || inline.clone().or_else(|| args.next().cloned());
        match flag {
            "--rpc-port" => rpc_port = value().and_then(|v| v.parse::<NonZeroU16>().ok()),
            "--rpc-bind-address" => rpc_bind_address = value(),
            "--bind-address" => bind_address = value(),
            "--identity" | "-i" => identity_path = value(),
            "--full-rpc-api" => full_rpc_api = true,
            "--private-rpc" => private_rpc = true,
            "--enable-rpc-transaction-history" => rpc_tx_history = true,
            _ => {}
        }
    }
    // The validator binds RPC to --rpc-bind-address, else to loopback for a
    // private RPC, else to --bind-address, which defaults to every address.
    let rpc_bind = rpc_port.map(|_| match (&rpc_bind_address, private_rpc) {
        (Some(address), _) => classify(address),
        (None, true) => Bind::Loopback,
        (None, false) => bind_address.as_deref().map_or(Bind::Wildcard, classify),
    });
    SolanaNode {
        app,
        rpc_port,
        rpc_bind,
        full_rpc_api,
        private_rpc,
        rpc_tx_history,
        identity_on_disk: identity_path.as_deref().map_or(Tristate::Unknown, identity),
        withdrawer_on_disk: Tristate::Unknown,
    }
}

/// An address as written on a command line. A name rather than an address
/// is taken as public, the side that asks for a look.
fn classify(address: &str) -> Bind {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => super::sockets::classify_v4(v4),
        Ok(IpAddr::V6(v6)) => super::sockets::classify_v6(v6),
        Err(_) => Bind::Public,
    }
}

/// A process's arguments from `/proc/<pid>/cmdline`, after the program.
pub(super) fn arguments(cmdline: &[u8]) -> Vec<String> {
    cmdline
        .split(|&b| b == 0)
        .skip(1)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use erpc_api::security_check::{Bind, SolanaApp, Tristate};

    use super::{arguments, node};

    fn run(cmdline: &str) -> erpc_api::security_check::SolanaNode {
        let args = arguments(cmdline.replace(' ', "\0").as_bytes());
        node(SolanaApp::AgaveValidator, &args, |path| {
            if path == "/home/sol/validator-keypair.json" {
                Tristate::Yes
            } else {
                Tristate::No
            }
        })
    }

    #[test]
    fn rpc_settings_follow_the_validators_own_defaults() {
        let public = run(
            "agave-validator --identity /home/sol/validator-keypair.json --rpc-port 8899 --full-rpc-api --enable-rpc-transaction-history",
        );
        assert_eq!(public.rpc_port.map(std::num::NonZeroU16::get), Some(8899));
        assert_eq!(public.rpc_bind, Some(Bind::Wildcard));
        assert!(public.full_rpc_api && public.rpc_tx_history && !public.private_rpc);
        assert_eq!(public.identity_on_disk, Tristate::Yes);

        let private = run("agave-validator --rpc-port=18899 --private-rpc -i /run/keys/id.json");
        assert_eq!(private.rpc_bind, Some(Bind::Loopback));
        assert_eq!(private.identity_on_disk, Tristate::No);

        let explicit =
            run("agave-validator --rpc-port 8899 --private-rpc --rpc-bind-address 0.0.0.0");
        assert_eq!(explicit.rpc_bind, Some(Bind::Wildcard));

        let bound = run("agave-validator --rpc-port 8899 --bind-address 10.0.0.5");
        assert_eq!(bound.rpc_bind, Some(Bind::Private));

        let named = run("agave-validator --rpc-port 8899 --rpc-bind-address rpc.example.invalid");
        assert_eq!(named.rpc_bind, Some(Bind::Public));

        let none = run("agave-validator --no-voting");
        assert_eq!((none.rpc_port, none.rpc_bind), (None, None));
        assert_eq!(none.identity_on_disk, Tristate::Unknown);
    }
}
