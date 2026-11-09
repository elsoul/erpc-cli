// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Sui RPC lifecycle and compatible `node` alias.
use crate::commands::Outcome;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) const REGISTRATION: Verb = Verb {
    name: "registration",
    about: "Prepare external registration, validate key binding or observe membership",
    read_only: true,
};

pub(crate) fn args(mut command: Command, verb: &Verb, validator: bool) -> Command {
    if verb.name != "list" && verb.name != "plan" {
        command = command
            .arg(
                Arg::new("ssh-key")
                    .long("ssh-key")
                    .value_parser(value_parser!(std::path::PathBuf))
                    .help("Public SSH key file; signing stays in the agent"),
            )
            .arg(
                Arg::new("ssh-agent")
                    .long("ssh-agent")
                    .value_parser(value_parser!(std::path::PathBuf)),
            );
    }
    if !verb.read_only {
        command = command.arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue),
        );
    }
    if verb.name == "init" {
        for (name, help) in [
            ("host", "Dedicated Ubuntu host, with mounted data storage"),
            ("fingerprint", "Expected SSH host key fingerprint"),
            ("vault", "1Password vault ID"),
        ] {
            command = command.arg(Arg::new(name).long(name).help(help));
        }
        command = command
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(
                Arg::new("port")
                    .long("port")
                    .default_value("22")
                    .value_parser(value_parser!(u16)),
            );
    }
    if verb.name == "init" {
        command = command.arg(Arg::new("migrate-account").long("migrate-account").action(ArgAction::SetTrue).help("Explicitly verify and retain this existing host original numeric account; stop old units, retain keys/data and require redeployment before start"));
    }
    if validator && verb.name == "init" {
        command = validator_init_args(command);
    }
    if verb.name == "registration" {
        command = command.arg(
            Arg::new("action")
                .long("action")
                .required(true)
                .value_parser(["prepare", "validate", "status"]),
        );
    }
    if ["init", "update-config"].contains(&verb.name) {
        for (name, help) in [
            (
                "rpc-allow",
                "Trusted gRPC clients or TLS gateways; unrestricted public access refused",
            ),
            ("management-allow", "Additional SSH ranges"),
            ("monitoring-allow", "Trusted metrics scrapers"),
        ] {
            if validator && name == "rpc-allow" {
                continue;
            }
            command = command.arg(
                Arg::new(name)
                    .long(name)
                    .help(help)
                    .value_delimiter(',')
                    .action(ArgAction::Append),
            );
        }
    }
    if matches!(verb.name, "deploy" | "update") {
        command = command.arg(Arg::new("recover-bootstrap").long("recover-bootstrap").action(ArgAction::SetTrue).help("Stop incomplete bootstrap, retain its database in quarantine and perform a fresh verified restore; requires extra free space"));
    }
    if validator && verb.name == "deploy" {
        command = command.arg(Arg::new("restore-keys").long("restore-keys").conflicts_with("recover-bootstrap").action(ArgAction::SetTrue).help("Stop this established validator and restore the original three keys from its saved references; retain old ciphertext, refuse changed metadata"));
    }
    if verb.name == "update" {
        command = command.arg(source_history_arg());
    }
    if verb.name == "logs" {
        command = command
            .arg(
                Arg::new("lines")
                    .long("lines")
                    .default_value("100")
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                Arg::new("follow")
                    .long("follow")
                    .short('f')
                    .action(ArgAction::SetTrue),
            );
    }
    command.about(about(verb))
}

fn source_history_arg() -> Arg {
    Arg::new("migrate-source-history").long("migrate-source-history").conflicts_with("recover-bootstrap")
        .value_parser(value_parser!(std::path::PathBuf))
        .help("Stop and migrate independently recorded original highest-opened source; migration only, no update or startup")
}

fn about(verb: &Verb) -> &'static str {
    match verb.name {
        "init" => "Reserve a Sui node host and prepare Ubuntu without formatting disks",
        "deploy" => "Install verified network pins and schedule verified snapshot bootstrap",
        "update" => "Adopt this CLI's reviewed Sui release, without unsafe database rollback",
        "destroy" => "Remove services; retain data, encrypted identity, host contract and firewall",
        "status" => "Check gRPC, network identity and advancing checkpoint execution",
        "plan" => "Show the stored deployment contract without contacting the host",
        _ => verb.about,
    }
}

fn validator_init_args(mut command: Command) -> Command {
    command = command.arg(Arg::new("validator-info").long("validator-info").value_parser(value_parser!(std::path::PathBuf)).help("Public official GenesisValidatorInfo in JSON; owner keys must not be included"))
            .arg(Arg::new("keys-unhosted").long("keys-unhosted").action(ArgAction::SetTrue).help("Confirm these keys have never been hosted; existing signer migration is refused"));
    for name in ["protocol-key", "network-key", "worker-key"] {
        command = command.arg(
            Arg::new(name)
                .long(name)
                .help("1Password field reference containing the original base64 key file"),
        );
    }
    command
}

pub(crate) fn run(
    verb: &Verb,
    sub: &ArgMatches,
    network: Option<&str>,
    name: Option<&str>,
    json: bool,
    validator: bool,
) -> Outcome {
    let Some(network) = network else {
        return Outcome::Usage("Sui commands require --network mainnet or testnet".to_owned());
    };
    let one = |id| sub.try_get_one::<String>(id).ok().flatten().cloned();
    let many = |id| {
        sub.try_get_many::<String>(id)
            .ok()
            .flatten()
            .map(|xs| xs.cloned().collect())
    };
    let args = crate::sui_node::Args {
        validator,
        source_history: sub
            .try_get_one::<std::path::PathBuf>("migrate-source-history")
            .ok()
            .flatten()
            .cloned(),
        migrate_account: sub
            .try_get_one::<bool>("migrate-account")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(false),
        restore_keys: sub
            .try_get_one::<bool>("restore-keys")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(false),
        validator_info: sub
            .try_get_one::<std::path::PathBuf>("validator-info")
            .ok()
            .flatten()
            .cloned(),
        keys_unhosted: sub
            .try_get_one::<bool>("keys-unhosted")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(false),
        key_references: [one("protocol-key"), one("network-key"), one("worker-key")],
        registration_action: one("action"),
        network: network.to_owned(),
        name: name.unwrap_or_default().to_owned(),
        host: one("host"),
        user: one("user").unwrap_or_else(|| "ubuntu".to_owned()),
        port: sub
            .try_get_one::<u16>("port")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(22),
        fingerprint: one("fingerprint"),
        vault: one("vault"),
        login: crate::eth_rpc::Login {
            ssh_key: sub
                .try_get_one::<std::path::PathBuf>("ssh-key")
                .ok()
                .flatten()
                .cloned(),
            ssh_agent: sub
                .try_get_one::<std::path::PathBuf>("ssh-agent")
                .ok()
                .flatten()
                .cloned(),
        },
        yes: sub
            .try_get_one::<bool>("yes")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(false),
        rpc_allow: many("rpc-allow"),
        management_allow: many("management-allow"),
        monitoring_allow: many("monitoring-allow"),
        lines: sub
            .try_get_one::<u32>("lines")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(100),
        recover_bootstrap: sub
            .try_get_one::<bool>("recover-bootstrap")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(false),
        follow: sub
            .try_get_one::<bool>("follow")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(false),
    };
    crate::sui_node::run(verb.name, &args, json)
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role};
    #[test]
    fn node_alias_and_rpc_have_identical_lifecycle_flags() {
        for role in [Role::Rpc, Role::Node] {
            let tree = crate::tree::command(role, Chain::Sui);
            for verb in [
                "init",
                "deploy",
                "list",
                "status",
                "logs",
                "start",
                "stop",
                "restart",
                "update",
                "update-config",
                "plan",
                "destroy",
            ] {
                assert!(
                    tree.clone()
                        .try_get_matches_from(["erpc", verb, "-n", "testnet", "--name", "sui1"])
                        .is_ok(),
                    "{verb}"
                );
            }
            assert!(
                tree.clone()
                    .try_get_matches_from(["erpc", "init", "-n", "devnet"])
                    .is_err()
            );
            assert!(
                tree.try_get_matches_from(["erpc", "destroy", "--purge-data"])
                    .is_err()
            );
        }
    }
    #[test]
    fn validator_registration_and_restore_keep_owner_signing_external() {
        let tree = crate::tree::command(Role::Validator, Chain::Sui);
        for action in ["prepare", "validate", "status"] {
            assert!(
                tree.clone()
                    .try_get_matches_from([
                        "erpc",
                        "registration",
                        "-n",
                        "testnet",
                        "--name",
                        "v1",
                        "--action",
                        action
                    ])
                    .is_ok()
            );
        }
        assert!(
            tree.clone()
                .try_get_matches_from(["erpc", "deploy", "-n", "testnet", "--restore-keys"])
                .is_ok()
        );
        assert!(
            tree.clone()
                .try_get_matches_from([
                    "erpc",
                    "registration",
                    "-n",
                    "testnet",
                    "--action",
                    "submit"
                ])
                .is_err()
        );
        assert!(
            tree.try_get_matches_from(["erpc", "init", "-n", "testnet", "--account-key", "owner"])
                .is_err()
        );
        let fullnode = crate::tree::command(Role::Rpc, Chain::Sui);
        assert!(
            fullnode
                .try_get_matches_from(["erpc", "deploy", "-n", "testnet", "--restore-keys"])
                .is_err()
        );
    }
}
