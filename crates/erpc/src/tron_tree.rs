// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! TRON query nodes and elected SRs, with external owner signing.
use crate::commands::Outcome;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) const REGISTRATION: Verb = Verb {
    name: "registration",
    about: "Prepare external SR registration, validate custody or observe election",
    read_only: true,
};

fn identity_args(mut command: Command) -> Command {
    for (name, help) in [
        (
            "owner-address",
            "Public candidate account; its owner wallet stays external",
        ),
        (
            "witness-address",
            "Dedicated Witness-only signing address, distinct from Owner/Active keys",
        ),
        (
            "candidate-url",
            "Public HTTPS URL for external candidate registration",
        ),
        (
            "keystore-ref",
            "1Password field reference containing the original native encrypted V3 keystore",
        ),
        (
            "password-ref",
            "1Password field reference containing its exact password",
        ),
    ] {
        command = command.arg(Arg::new(name).long(name).help(help));
    }
    command.arg(
        Arg::new("keys-unhosted")
            .long("keys-unhosted")
            .action(ArgAction::SetTrue)
            .help("Confirm this signer has never been hosted; live producer migration is refused"),
    )
}

pub(crate) fn args(mut command: Command, verb: &Verb, validator: bool) -> Command {
    if !["list", "plan"].contains(&verb.name) {
        command = command
            .arg(
                Arg::new("ssh-key")
                    .long("ssh-key")
                    .value_parser(value_parser!(std::path::PathBuf))
                    .help("Login public key; signing stays in the SSH agent"),
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
        for name in ["host", "fingerprint", "vault"] {
            command = command.arg(Arg::new(name).long(name));
        }
        command = command
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(
                Arg::new("port")
                    .long("port")
                    .default_value("22")
                    .value_parser(value_parser!(u16)),
            );
        if validator {
            command = identity_args(command);
        }
    }
    if ["init", "update-config"].contains(&verb.name) {
        for (name, help) in [
            (
                "rpc-allow",
                "Trusted API clients/TLS gateways; unrestricted public access refused",
            ),
            ("management-allow", "Additional trusted SSH ranges"),
            ("monitoring-allow", "Trusted private Prometheus scrapers"),
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
    if validator && verb.name == "deploy" {
        command=command.arg(Arg::new("restore-keys").long("restore-keys").action(ArgAction::SetTrue).help("Restore original credentials on this fenced host using its existing receipt; retain old ciphertext"));
    }
    if verb.name == "registration" {
        command = command.arg(
            Arg::new("action")
                .long("action")
                .required(true)
                .value_parser(["prepare", "validate", "status"]),
        );
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
    command.about(match verb.name {
        "init"=>"Reserve a TRON host and prepare Ubuntu/JDK without formatting disks",
        "deploy"=>"Authenticate network pins and start the original node identity under confirmed filtering",
        "update"=>"Adopt this CLI's reviewed network release without automatic database downgrade",
        "destroy"=>"Stop/remove the service, retaining original keys, ownership, data and filtering",
        "status"=>"Observe progressing correct-network blocks and separate election/permission state",
        _=>verb.about,
    })
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
        return Outcome::Usage("TRON commands require --network mainnet or nile".into());
    };
    let one = |id| sub.try_get_one::<String>(id).ok().flatten().cloned();
    let flag = |id| {
        sub.try_get_one::<bool>(id)
            .ok()
            .flatten()
            .copied()
            .unwrap_or(false)
    };
    let many = |id| {
        sub.try_get_many::<String>(id)
            .ok()
            .flatten()
            .map(|v| v.cloned().collect())
    };
    let args = crate::tron_node::Args {
        validator,
        network: network.into(),
        name: name.unwrap_or_default().into(),
        host: one("host"),
        user: one("user").unwrap_or_else(|| "ubuntu".into()),
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
        yes: flag("yes"),
        rpc_allow: many("rpc-allow"),
        management_allow: many("management-allow"),
        monitoring_allow: many("monitoring-allow"),
        owner: one("owner-address"),
        signer: one("witness-address"),
        candidate_url: one("candidate-url"),
        references: [one("keystore-ref"), one("password-ref")],
        keys_unhosted: flag("keys-unhosted"),
        restore_keys: flag("restore-keys"),
        registration: one("action"),
        lines: sub
            .try_get_one::<u32>("lines")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(100),
        follow: flag("follow"),
    };
    crate::tron_node::run(verb.name, &args, json)
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role};
    #[test]
    fn roles_expose_lifecycle_without_owner_signing_or_closed_shasta() {
        for role in [Role::Rpc, Role::Validator] {
            let tree = crate::tree::command(role, Chain::Tron);
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
                        .try_get_matches_from(["erpc", verb, "-n", "nile", "--name", "tron1"])
                        .is_ok(),
                    "{verb}"
                );
            }
            assert!(
                tree.clone()
                    .try_get_matches_from(["erpc", "init", "-n", "shasta"])
                    .is_err()
            );
            assert!(
                tree.clone()
                    .try_get_matches_from(["erpc", "init", "--owner-key", "secret"])
                    .is_err()
            );
            if role == Role::Validator {
                for action in ["prepare", "validate", "status"] {
                    assert!(
                        tree.clone()
                            .try_get_matches_from([
                                "erpc",
                                "registration",
                                "-n",
                                "nile",
                                "--action",
                                action
                            ])
                            .is_ok()
                    );
                }
                assert!(
                    tree.try_get_matches_from(["erpc", "registration", "--action", "submit"])
                        .is_err()
                );
            } else {
                assert!(
                    tree.try_get_matches_from(["erpc", "deploy", "--restore-keys"])
                        .is_err()
                );
            }
        }
    }
}
