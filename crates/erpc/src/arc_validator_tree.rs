// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated preparation lifecycle; production signer activation stays explicit and unavailable.
use clap::{Arg, ArgAction, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) const EXTRA: &[Verb] = &[
    Verb {
        name: "prepare-registration",
        about: "Prepare the official public governance call for external signing",
        read_only: true,
    },
    Verb {
        name: "validate-registration",
        about: "Compare a public governance intent with original inputs and live admission",
        read_only: true,
    },
    Verb {
        name: "remote-public-key",
        about: "Verify the external signer PublicKey over original server-CA TLS; never sign",
        read_only: true,
    },
    Verb {
        name: "reset-bootstrap",
        about: "Stop and quarantine only the explicit incomplete initial snapshot",
        read_only: false,
    },
    Verb {
        name: "restore-peer-key",
        about: "Stop and rewrap only this host's original local P2P key",
        read_only: false,
    },
    Verb {
        name: "activate",
        about: "Explain the unresolved production signing-history prerequisite; no activation",
        read_only: false,
    },
];

pub(crate) fn args(mut command: Command, verb: &Verb) -> Command {
    command = connection_args(command, verb);
    if verb.name == "init" {
        command = command
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16)))
            .arg(Arg::new("fingerprint").long("fingerprint"))
            .arg(Arg::new("vault").long("vault"))
            .arg(Arg::new("controller").long("controller").help("Original externally held EVM governance controller; no private key"))
            .arg(Arg::new("consensus-public-key").long("consensus-public-key").help("Original externally held Ed25519 signer public key, canonical base64"))
            .arg(Arg::new("remote-signer-profile").long("remote-signer-profile").value_parser(value_parser!(std::path::PathBuf)).help("Public JSON endpoint, CA digest, image digest and PCR0/1/2/4 qualification"))
            .arg(Arg::new("signer-ca").long("signer-ca").value_parser(value_parser!(std::path::PathBuf)).help("Exact public server CA PEM; required on initial or resumed init"));
    }
    if ["init", "update"].contains(&verb.name) {
        command = command.arg(
            Arg::new("version")
                .long("version")
                .help("Source-qualified Arc release; retained data never downgrades"),
        );
    }
    if ["init", "update-config"].contains(&verb.name) {
        command = command.arg(Arg::new("fee-recipient").long("fee-recipient"))
            .arg(Arg::new("admission-approved").long("admission-approved").action(ArgAction::SetTrue)
                 .help("Record institutional approval; does not prove on-chain admission or enable signing"));
        for field in [
            "execution-peer",
            "sentry-peer",
            "management-allow",
            "monitoring-allow",
        ] {
            command = command.arg(
                Arg::new(field)
                    .long(field)
                    .action(ArgAction::Append)
                    .value_delimiter(','),
            );
        }
    }
    if verb.name == "logs" {
        command = log_args(command);
    }
    if verb.name == "reset-bootstrap" {
        command = command.arg(
            Arg::new("original-intent")
                .long("original-intent")
                .help("Exact original interrupted bootstrap's 128-bit intent"),
        );
    }
    if ["prepare-registration", "validate-registration"].contains(&verb.name) {
        command = command
            .arg(Arg::new("step").long("step").value_parser([
                "register",
                "configure-controller",
                "activate",
                "voting-power",
                "remove",
            ]))
            .arg(
                Arg::new("from")
                    .long("from")
                    .help("Public external governance signer address"),
            )
            .arg(
                Arg::new("registration-id")
                    .long("registration-id")
                    .value_parser(value_parser!(u64)),
            )
            .arg(
                Arg::new("voting-power-limit")
                    .long("voting-power-limit")
                    .value_parser(value_parser!(u64)),
            )
            .arg(
                Arg::new("voting-power")
                    .long("voting-power")
                    .value_parser(value_parser!(u64)),
            );
        if verb.name == "validate-registration" {
            command = command.arg(
                Arg::new("registration-file")
                    .long("registration-file")
                    .value_parser(value_parser!(std::path::PathBuf)),
            );
        }
    }
    command
}

fn log_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("layer")
                .long("layer")
                .default_value("both")
                .value_parser(["execution", "consensus", "both"]),
        )
        .arg(
            Arg::new("lines")
                .long("lines")
                .default_value("100")
                .value_parser(value_parser!(u32).range(1..=10000)),
        )
        .arg(
            Arg::new("follow")
                .long("follow")
                .short('f')
                .action(ArgAction::SetTrue),
        )
}

fn connection_args(mut command: Command, verb: &Verb) -> Command {
    if verb.name != "list" {
        for name in ["ssh-key", "ssh-agent"] {
            command = command.arg(
                Arg::new(name)
                    .long(name)
                    .value_parser(value_parser!(std::path::PathBuf)),
            );
        }
    }
    if !verb.read_only {
        command = command.arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue),
        );
    }
    command
}
