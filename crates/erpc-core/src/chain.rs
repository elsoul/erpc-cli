// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which chain and network a node command runs against.
//!
//! The chain is resolved from, in order: `--chain`, `ERPC_CHAIN`, and
//! `default_chain` in the configuration. With none of those, a caller at a
//! terminal asks, and anything else is a usage error.
//!
//! Mainnet is never inferred for a command that changes anything: such a
//! command needs both `--chain` and `--network mainnet` on its own command
//! line. [`guard_mainnet`] is that rule.

use core::fmt;

/// A chain namespace understood by the CLI.
///
/// Recognition does not imply that every deployment backend is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    /// Solana.
    Solana,
    /// Ethereum.
    Eth,
    /// Avalanche.
    Avax,
    /// Sui.
    Sui,
    /// Arc, Circle's chain.
    Arc,
    /// Bitcoin.
    Bitcoin,
    /// Base.
    Base,
    /// Arbitrum.
    Arbitrum,
    /// Polygon proof of stake.
    Polygon,
    /// BNB Smart Chain.
    Bsc,
    /// OP Mainnet.
    Optimism,
    /// Kaia.
    Kaia,
    /// Soneium.
    Soneium,
    /// Monad.
    Monad,
    /// Hyperliquid.
    Hyperliquid,
    /// Robinhood Chain.
    Robinhood,
    /// NEAR.
    Near,
    /// TRON.
    Tron,
}

impl Chain {
    /// Every chain, in the order they are offered.
    pub const ALL: [Self; 18] = [
        Self::Solana,
        Self::Eth,
        Self::Avax,
        Self::Sui,
        Self::Arc,
        Self::Bitcoin,
        Self::Base,
        Self::Arbitrum,
        Self::Polygon,
        Self::Bsc,
        Self::Optimism,
        Self::Kaia,
        Self::Soneium,
        Self::Monad,
        Self::Hyperliquid,
        Self::Robinhood,
        Self::Near,
        Self::Tron,
    ];

    /// Parses a chain name or its short form.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "solana" | "sol" => Some(Self::Solana),
            "eth" | "ethereum" => Some(Self::Eth),
            "avax" | "avalanche" => Some(Self::Avax),
            "sui" => Some(Self::Sui),
            "arc" => Some(Self::Arc),
            "bitcoin" => Some(Self::Bitcoin),
            "base" => Some(Self::Base),
            "arbitrum" => Some(Self::Arbitrum),
            "polygon" => Some(Self::Polygon),
            "bsc" => Some(Self::Bsc),
            "optimism" => Some(Self::Optimism),
            "kaia" => Some(Self::Kaia),
            "soneium" => Some(Self::Soneium),
            "monad" => Some(Self::Monad),
            "hyperliquid" => Some(Self::Hyperliquid),
            "robinhood" => Some(Self::Robinhood),
            "near" => Some(Self::Near),
            "tron" => Some(Self::Tron),
            _ => None,
        }
    }

    /// The canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Solana => "solana",
            Self::Eth => "eth",
            Self::Avax => "avax",
            Self::Sui => "sui",
            Self::Arc => "arc",
            Self::Bitcoin => "bitcoin",
            Self::Base => "base",
            Self::Arbitrum => "arbitrum",
            Self::Polygon => "polygon",
            Self::Bsc => "bsc",
            Self::Optimism => "optimism",
            Self::Kaia => "kaia",
            Self::Soneium => "soneium",
            Self::Monad => "monad",
            Self::Hyperliquid => "hyperliquid",
            Self::Robinhood => "robinhood",
            Self::Near => "near",
            Self::Tron => "tron",
        }
    }

    /// Command roles available for this namespace, including planned backends.
    /// Unsupported deployment verbs must still return an explicit failure.
    #[must_use]
    pub const fn roles(self) -> &'static [Role] {
        match self {
            Self::Solana | Self::Eth => &[Role::Validator, Role::Rpc],
            Self::Avax => &[Role::Rpc, Role::Validator, Role::Node],
            Self::Sui => &[Role::Rpc, Role::Node, Role::Validator],
            Self::Bitcoin | Self::Base | Self::Optimism | Self::Soneium => &[Role::Rpc],
            Self::Arc
            | Self::Arbitrum
            | Self::Polygon
            | Self::Bsc
            | Self::Kaia
            | Self::Monad
            | Self::Hyperliquid
            | Self::Robinhood
            | Self::Near
            | Self::Tron => &[Role::Rpc, Role::Validator],
        }
    }

    /// The networks this chain has.
    #[must_use]
    pub const fn networks(self) -> &'static [&'static str] {
        match self {
            Self::Solana => &["mainnet", "testnet", "devnet"],
            Self::Eth => &["mainnet", "sepolia", "hoodi"],
            Self::Avax => &["mainnet", "fuji"],
            Self::Sui
            | Self::Arc
            | Self::Monad
            | Self::Hyperliquid
            | Self::Robinhood
            | Self::Near => &["mainnet", "testnet"],
            Self::Bitcoin => &["mainnet", "testnet4", "signet", "regtest"],
            Self::Base | Self::Optimism => &["mainnet", "sepolia"],
            Self::Arbitrum => &["mainnet", "nova", "sepolia"],
            Self::Polygon => &["mainnet", "amoy"],
            Self::Bsc => &["mainnet", "chapel"],
            Self::Kaia => &["mainnet", "kairos"],
            Self::Soneium => &["mainnet", "minato"],
            Self::Tron => &["mainnet", "nile"],
        }
    }
    /// Every canonical name, for help and errors without a separate stale list.
    #[must_use]
    pub fn names() -> String {
        Self::ALL
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Whether this network uses real assets and needs an explicit chain flag.
    /// Nova is another production network in the Arbitrum family.
    #[must_use]
    pub fn is_production_network(self, network: &str) -> bool {
        network == "mainnet" || (self == Self::Arbitrum && network == "nova")
    }

    /// Why the protocol has no standalone validator role in this command family.
    /// Permissioned validators are not classified as absent.
    #[must_use]
    pub const fn validator_na_reason(self) -> Option<&'static str> {
        match self {
            Self::Bitcoin => Some("Bitcoin uses proof-of-work mining, not a validator role"),
            Self::Base | Self::Optimism | Self::Soneium => Some(
                "this rollup has no independent PoS validator role; sequencer and dispute operations are separate",
            ),
            _ => None,
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a node does on its chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// A validator: `erpc validator`, `erpc v`.
    Validator,
    /// An RPC node: `erpc rpc`, `erpc r`.
    Rpc,
    /// A node on a chain without separate roles: `erpc node`, `erpc n`.
    Node,
}

impl Role {
    /// The subcommand name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::Rpc => "rpc",
            Self::Node => "node",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A verb every role has, and whether it only reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verb {
    /// The subcommand name.
    pub name: &'static str,
    /// One line for `--help`.
    pub about: &'static str,
    /// Whether it changes nothing. Anything not marked is treated as a
    /// change, so a new verb is guarded until someone says otherwise.
    pub read_only: bool,
}

/// The verbs common to every chain and role.
pub const COMMON_VERBS: &[Verb] = &[
    Verb {
        name: "init",
        about: "Record the node in the 1Password inventory and prepare the server",
        read_only: false,
    },
    Verb {
        name: "deploy",
        about: "Install the base system and the client, and start in safe mode",
        read_only: false,
    },
    Verb {
        name: "list",
        about: "List the hosts in the inventory",
        read_only: true,
    },
    Verb {
        name: "status",
        about: "Show the state of a host",
        read_only: true,
    },
    Verb {
        name: "logs",
        about: "Show a host's logs",
        read_only: true,
    },
    Verb {
        name: "start",
        about: "Start the service",
        read_only: false,
    },
    Verb {
        name: "stop",
        about: "Stop the service",
        read_only: false,
    },
    Verb {
        name: "restart",
        about: "Restart the service",
        read_only: false,
    },
    Verb {
        name: "update",
        about: "Update the client, with a guarded restart",
        read_only: false,
    },
    Verb {
        name: "update-config",
        about: "Regenerate the start script and configuration",
        read_only: false,
    },
    Verb {
        name: "plan",
        about: "Show what a change would do, without doing it",
        read_only: true,
    },
    Verb {
        name: "destroy",
        about: "Stop the service and retire the node (keys are untouched)",
        read_only: false,
    },
];

/// Where the chain came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `--chain` on the command line.
    Flag,
    /// The `ERPC_CHAIN` environment variable.
    Env,
    /// `default_chain` in the configuration.
    Config,
    /// The operator picked it when asked.
    Prompt,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Flag => "--chain",
            Self::Env => "ERPC_CHAIN",
            Self::Config => "default_chain in config.toml",
            Self::Prompt => "chosen when asked",
        })
    }
}

/// Resolves the chain from the flag, the environment and the
/// configuration, in that order. `Ok(None)` when none of them names one.
///
/// # Errors
///
/// Returns a message naming the source when a value is not a chain.
pub fn resolve(
    flag: Option<&str>,
    env: Option<&str>,
    config: Option<&str>,
) -> Result<Option<(Chain, Source)>, String> {
    for (value, source) in [
        (flag, Source::Flag),
        (env, Source::Env),
        (config, Source::Config),
    ] {
        let Some(value) = value.filter(|v| !v.is_empty()) else {
            continue;
        };
        return Chain::parse(value)
            .map(|chain| Some((chain, source)))
            .ok_or_else(|| {
                format!(
                    "{value} ({source}) is not a chain erpc knows: {}",
                    Chain::names()
                )
            });
    }
    Ok(None)
}

/// Refuses a change on mainnet unless the command line itself named both
/// the chain and the network.
///
/// # Errors
///
/// Returns the message to show, for exit code 2.
pub fn guard_mainnet(
    verb: &Verb,
    chain: Chain,
    chain_source: Source,
    network: Option<&str>,
) -> Result<(), String> {
    if verb.read_only || !network.is_some_and(|n| chain.is_production_network(n)) {
        return Ok(());
    }
    if chain_source == Source::Flag {
        return Ok(());
    }
    Err(format!(
        "`{}` changes a production node, so the chain has to be on the command line: add \
         `--chain {chain}`. The chain came from {chain_source}, which is not accepted for production networks",
        verb.name
    ))
}

#[cfg(test)]
mod tests {
    use super::{COMMON_VERBS, Chain, Role, Source, Verb, guard_mainnet, resolve};

    fn verb(name: &str) -> &'static Verb {
        COMMON_VERBS
            .iter()
            .find(|v| v.name == name)
            .expect("a verb")
    }

    #[test]
    fn the_flag_wins_then_the_environment_then_the_configuration() {
        assert_eq!(
            resolve(Some("eth"), Some("sui"), Some("solana")),
            Ok(Some((Chain::Eth, Source::Flag)))
        );
        assert_eq!(
            resolve(None, Some("sui"), Some("solana")),
            Ok(Some((Chain::Sui, Source::Env)))
        );
        assert_eq!(
            resolve(None, Some(""), Some("sol")),
            Ok(Some((Chain::Solana, Source::Config)))
        );
        assert_eq!(resolve(None, None, None), Ok(None));
    }

    #[test]
    fn a_value_that_is_not_a_chain_is_an_error_naming_where_it_came_from() {
        let err = resolve(None, Some("doge"), Some("solana")).expect_err("not a chain");
        assert!(err.contains("ERPC_CHAIN"), "{err}");
    }

    #[test]
    fn sdk_names_and_existing_aliases_resolve_without_changing_inventory_names() {
        let names = [
            "solana",
            "ethereum",
            "avalanche",
            "bitcoin",
            "base",
            "arbitrum",
            "polygon",
            "bsc",
            "optimism",
            "kaia",
            "soneium",
            "monad",
            "hyperliquid",
            "arc",
            "robinhood",
            "near",
            "tron",
            "sui",
        ];
        let resolved: std::collections::HashSet<_> = names
            .iter()
            .map(|name| Chain::parse(name).expect(name))
            .collect();
        assert_eq!(resolved.len(), 18);
        assert_eq!(resolved, Chain::ALL.into_iter().collect());
        for (alias, canonical) in [
            ("SOL", "solana"),
            ("ETHEREUM", "eth"),
            ("AVALANCHE", "avax"),
        ] {
            assert_eq!(Chain::parse(alias).expect(alias).as_str(), canonical);
        }
        for name in names {
            let chain = Chain::parse(name).expect(name);
            assert_eq!(
                resolve(None, Some(name), None),
                Ok(Some((chain, Source::Env)))
            );
            assert_eq!(
                resolve(None, None, Some(name)),
                Ok(Some((chain, Source::Config)))
            );
        }
    }

    #[test]
    fn validator_na_does_not_misclassify_permissioned_or_assertion_validators() {
        for chain in [Chain::Bitcoin, Chain::Base, Chain::Optimism, Chain::Soneium] {
            assert!(chain.validator_na_reason().is_some());
            assert!(!chain.roles().contains(&Role::Validator));
        }
        for chain in [
            Chain::Polygon,
            Chain::Kaia,
            Chain::Robinhood,
            Chain::Arbitrum,
        ] {
            assert!(chain.validator_na_reason().is_none());
            assert!(chain.roles().contains(&Role::Validator));
        }
        assert!(Chain::Arc.validator_na_reason().is_none());
        assert!(Chain::Arc.roles().contains(&Role::Validator));
    }

    #[test]
    fn nova_is_production_even_though_it_is_not_named_mainnet() {
        for source in [Source::Env, Source::Config, Source::Prompt] {
            assert!(guard_mainnet(verb("deploy"), Chain::Arbitrum, source, Some("nova")).is_err());
        }
        assert!(guard_mainnet(verb("deploy"), Chain::Arbitrum, Source::Flag, Some("nova")).is_ok());
        assert!(
            guard_mainnet(
                verb("status"),
                Chain::Arbitrum,
                Source::Config,
                Some("nova")
            )
            .is_ok()
        );
        assert!(
            guard_mainnet(
                verb("deploy"),
                Chain::Arbitrum,
                Source::Config,
                Some("sepolia")
            )
            .is_ok()
        );
        for chain in Chain::ALL {
            assert!(guard_mainnet(verb("update"), chain, Source::Config, Some("mainnet")).is_err());
        }
    }

    #[test]
    fn solana_has_validators_and_rpc_nodes_arc_rpc_nodes_and_the_rest_nodes() {
        assert_eq!(Chain::Solana.roles(), &[Role::Validator, Role::Rpc]);
        assert_eq!(Chain::Arc.roles(), &[Role::Rpc, Role::Validator]);
        assert_eq!(Chain::parse("ARC"), Some(Chain::Arc));
        assert_eq!(Chain::Arc.networks(), &["mainnet", "testnet"]);
        assert_eq!(Chain::Eth.roles(), &[Role::Validator, Role::Rpc]);
        assert_eq!(
            Chain::Sui.roles(),
            &[Role::Rpc, Role::Node, Role::Validator]
        );
        assert_eq!(
            Chain::Avax.roles(),
            &[Role::Rpc, Role::Validator, Role::Node]
        );
    }

    #[test]
    fn a_mainnet_change_needs_the_chain_on_the_command_line() {
        for source in [Source::Env, Source::Config, Source::Prompt] {
            assert!(guard_mainnet(verb("deploy"), Chain::Solana, source, Some("mainnet")).is_err());
        }
        assert!(
            guard_mainnet(verb("deploy"), Chain::Solana, Source::Flag, Some("mainnet")).is_ok()
        );
    }

    #[test]
    fn reading_or_testnet_is_not_guarded() {
        assert!(
            guard_mainnet(
                verb("status"),
                Chain::Solana,
                Source::Config,
                Some("mainnet")
            )
            .is_ok()
        );
        assert!(
            guard_mainnet(
                verb("deploy"),
                Chain::Solana,
                Source::Config,
                Some("testnet")
            )
            .is_ok()
        );
    }
}
