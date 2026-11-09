// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Polygon RPC/sentry options; admission and financial keys are separate roles.
use clap::{Arg, ArgAction, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) const REGISTRATION: Verb = Verb {
    name: "registration",
    about: "Prepare external owner registration data or observe current validator admission",
    read_only: true,
};

pub(crate) fn args(mut command: Command, verb: &Verb, validator: bool) -> Command {
    if !["list", "plan"].contains(&verb.name) {
        command = command
            .arg(
                Arg::new("ssh-key")
                    .long("ssh-key")
                    .value_parser(value_parser!(std::path::PathBuf)),
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
    if ["init", "update-config"].contains(&verb.name) {
        for name in ["rpc-allow", "management-allow", "monitoring-allow"] {
            command = command.arg(
                Arg::new(name)
                    .long(name)
                    .action(ArgAction::Append)
                    .value_delimiter(',')
                    .help("Trusted IPv4/IPv6 CIDRs; an unrestricted /0 is refused"),
            );
        }
        command = command
            .arg(
                Arg::new("advertise-ip")
                    .long("advertise-ip")
                    .help("Public numeric P2P address"),
            )
            .arg(Arg::new("l1-execution").long("l1-execution").help(
                "Identifier-only op reference to a concealed execution-only parent configuration",
            ));
    }
    if ["deploy", "update", "update-config"].contains(&verb.name) {
        command=command.arg(Arg::new("restore-keys").long("restore-keys").action(ArgAction::SetTrue)
            .help("Restore only original host-bound encrypted keys from the retained local backup; never reset consensus history"));
    }
    if validator && ["init", "update-config"].contains(&verb.name) {
        command = command.arg(Arg::new("sentry").long("sentry").action(ArgAction::Append)
            .help("Original public IP,BOR_NODE_ID,HEIMDALL_NODE_ID; one to eight admitted sentries"));
        if verb.name == "init" {
            command =
                command.arg(Arg::new("stake-owner").long("stake-owner").help(
                    "Separate external staking owner address; no owner private key is imported",
                ));
        }
    }
    if validator && ["deploy", "update", "update-config", "plan"].contains(&verb.name) {
        command = command.arg(Arg::new("activate-validator").long("activate-validator")
            .action(ArgAction::SetTrue).help("Explicitly transition the healthy original observer after external admission; native checkpoints then use the dedicated hot signer"));
    }
    if verb.name == "registration" {
        return command.arg(
            Arg::new("action")
                .long("action")
                .required(true)
                .value_parser(["prepare", "validate", "status"]),
        );
    }
    match verb.name{
        "init"=>command.about(if validator { "Reserve the original encrypted dedicated signer and observing Polygon validator host; registration/funding stay external" } else { "Reserve a dedicated Polygon RPC/sentry host; no validator registration or funding account" })
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16)))
            .arg(Arg::new("fingerprint").long("fingerprint"))
            .arg(Arg::new("vault").long("vault")),
        "deploy"=>command.about("Authenticate and deploy the reviewed Bor/Heimdall pair; sync Heimdall before Bor"),
        "update"=>command.about("Upgrade to this CLI's reviewed pair without downgrading either database"),
        "update-config"=>command.about("Reapply the owned pair and rotate the selected parent credential while stopped"),
        "plan"=>command.arg(Arg::new("change").long("change").default_value("deploy").value_parser(["deploy","update","update-config"])),
        "logs"=>command.arg(Arg::new("component").long("component").default_value("all").value_parser(if validator { vec!["bor","heimdall","parent","broker","all"] } else { vec!["bor","heimdall","parent","all"] }))
            .arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32)))
            .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "destroy"=>command.about("Fence, stop and disable the owned pair; retain original identities and both databases"),
        _=>command,
    }
}
