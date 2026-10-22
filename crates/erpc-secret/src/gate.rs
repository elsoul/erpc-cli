// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The gate that decides whether a secret may be resolved at all.
//!
//! This is the frozen interface named in the design: both the validator-key
//! work and the agent-wallet work are profiles of the same gate rather than
//! two mechanisms, so that neither can later redefine what "allowed" means
//! for the other.
//!
//! Three rules hold everywhere in this module:
//!
//! * The gate is evaluated **before** any secret is read, never after.
//! * A combination the table does not describe is denied. There is no
//!   fall-through to "allow".
//! * A [`Decision::Allow`] carries the confirmation the caller still owes
//!   the operator. Allowing is not the same as needing nothing.
//!
//! What this module does **not** do: it does not read secrets, prompt, talk
//! to `op`, or enforce a wallet's spending policy. It answers one question
//! about one request, and the caller is responsible for honouring the
//! answer.

use core::fmt;

/// Which chain network a key belongs to.
///
/// Mainnet is separated because every mainnet row of the table is stricter:
/// a service account may never reach a mainnet key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Real funds and real stake.
    Mainnet,
    /// A test network.
    Testnet,
    /// A development network.
    Devnet,
}

impl Network {
    /// Whether this network carries real value.
    #[must_use]
    pub fn is_mainnet(self) -> bool {
        matches!(self, Self::Mainnet)
    }
}

/// What a secret is for. One variant per row of the design's gate table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// A validator's identity key.
    ValidatorIdentity {
        /// The network the validator runs on.
        network: Network,
    },
    /// A wallet a person owns and signs with.
    HumanWallet {
        /// Whether an AI tool path may ask for this wallet at all.
        ///
        /// Even when true, signing still needs the operator at a terminal;
        /// this flag decides whether the request may be made, not whether
        /// it may skip confirmation.
        allow_ai: bool,
    },
    /// A low-value wallet an agent may spend from without asking.
    ///
    /// The protection here is not a prompt. It is that the wallet lives in
    /// its own vault, holds little, and carries a spending policy enforced
    /// elsewhere. This gate only decides that the request is in scope.
    AgentWallet,
    /// A session token for one of the ERPC APIs.
    SessionToken,
    /// Key material that is copied onto a node and lives there.
    NodeResident {
        /// The network the node serves.
        network: Network,
    },
}

/// What the caller wants to do with the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Assemble a request without reading the secret.
    ///
    /// An AI tool may do this for a human wallet: it can draft a payment,
    /// it cannot sign one.
    Prepare,
    /// Read the secret, or sign with it.
    Resolve,
}

/// Where the process asking for a secret is running.
///
/// A plain record of independent facts, one field per condition the design's
/// table reads. Clippy would rather see fewer booleans, but the value of
/// this type is that a reader can set it beside that table and check them
/// off one by one; folding them into flags or a state enum would hide the
/// correspondence that makes the gate reviewable.
#[allow(
    clippy::struct_excessive_bools,
    reason = "one field per condition in the design's gate table, kept legible on purpose"
)]
///
/// Set from the environment by [`Context::from_env`], or built by hand in a
/// test. Every field is a fact about the process, never a preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    /// A terminal is attached, so a person can be asked.
    pub has_tty: bool,
    /// The process is inside an SSH session.
    pub in_ssh_session: bool,
    /// The process is running on a node rather than an operator's machine.
    pub on_node: bool,
    /// The process is the AI console child, not the `erpc ai` parent.
    pub ai_console: bool,
    /// The request arrived through an AI tool call.
    pub ai_tool_path: bool,
    /// A 1Password service account token is in the environment.
    pub service_account: bool,
    /// A 1Password Connect or session variable is in the environment.
    pub op_env_session: bool,
    /// 1Password desktop (biometric) unlock is available.
    pub biometric_unlock: bool,
}

impl Context {
    /// A context with nothing available: no terminal, no desktop app.
    ///
    /// The deny-by-default starting point for tests and for callers that
    /// set only the fields they know.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            has_tty: false,
            in_ssh_session: false,
            on_node: false,
            ai_console: false,
            ai_tool_path: false,
            service_account: false,
            op_env_session: false,
            // Absent means available: 1Password desktop unlock is only
            // off when something says so. `from_env` overwrites this.
            biometric_unlock: true,
        }
    }

    /// Reads the context from environment variables and the given terminal
    /// and node facts.
    ///
    /// The terminal and node checks are passed in rather than probed here
    /// so that this stays testable and free of I/O.
    #[must_use]
    pub fn from_env<I>(has_tty: bool, on_node: bool, vars: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        // Takes the whole environment rather than a lookup function,
        // because one of the things to detect is a PREFIX. `op signin`
        // exports `OP_SESSION_<account>`, never a bare `OP_SESSION`, so a
        // by-name lookup for "OP_SESSION" never fired and the mainnet row
        // that refuses a 1Password session environment did not refuse the
        // environment it was written for.
        let mut ctx = Self {
            has_tty,
            on_node,
            ..Self::empty()
        };
        for (name, value) in vars {
            if value.is_empty() {
                continue;
            }
            match name.as_str() {
                "SSH_CONNECTION" | "SSH_TTY" => ctx.in_ssh_session = true,
                "ERPC_EXECUTION_CONTEXT" => {
                    ctx.ai_console = value == "ai-console";
                    ctx.ai_tool_path = value == "ai-tool";
                }
                "OP_SERVICE_ACCOUNT_TOKEN" => ctx.service_account = true,
                "OP_CONNECT_HOST" | "OP_CONNECT_TOKEN" => ctx.op_env_session = true,
                "OP_BIOMETRIC_UNLOCK_ENABLED" => {
                    ctx.biometric_unlock = !value.eq_ignore_ascii_case("false");
                }
                other if other.starts_with("OP_SESSION_") || other == "OP_SESSION" => {
                    ctx.op_env_session = true;
                }
                _ => {}
            }
        }
        ctx
    }
}

/// What the caller must still obtain from the operator before proceeding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Confirmation {
    /// Nothing. The request stands on the profile's own limits.
    None,
    /// A yes/no at the controlling terminal.
    Tty,
    /// A typed phrase at the controlling terminal.
    ///
    /// Used where a mistaken yes is expensive and unrecoverable.
    TtyPhrase,
}

/// Why a request was refused.
///
/// Each variant names the fact that caused it, so an error message can tell
/// the operator what to change rather than that something was "not allowed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Denial {
    /// No terminal, and this profile needs a person.
    NoTerminal,
    /// The AI console child process may not resolve this.
    FromAiConsole,
    /// An AI tool path may not resolve this wallet.
    AiNotPermittedForWallet,
    /// A service account may not reach this profile.
    ServiceAccount,
    /// A 1Password Connect or session variable is set, which this profile
    /// does not accept.
    OpEnvSession,
    /// The request came from inside an SSH session.
    SshSession,
    /// The process is running on a node.
    OnNode,
    /// 1Password desktop unlock is required and is switched off.
    BiometricUnlockRequired,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NoTerminal => "no terminal is attached, and this key needs a person present",
            Self::FromAiConsole => "the AI console may not resolve this key",
            Self::AiNotPermittedForWallet => {
                "this wallet is not marked for AI use; run the command yourself"
            }
            Self::ServiceAccount => "a service account may not reach this key",
            Self::OpEnvSession => {
                "a 1Password Connect or session variable is set in this \
                                   environment, which this key does not accept"
            }
            Self::SshSession => "this key may not be resolved from inside an SSH session",
            Self::OnNode => "this key may not be resolved on a node",
            Self::BiometricUnlockRequired => {
                "this key needs 1Password desktop unlock, which is switched off"
            }
        };
        f.write_str(text)
    }
}

/// The gate's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed once the given confirmation is obtained.
    Allow(Confirmation),
    /// The request is refused, for this reason.
    Deny(Denial),
}

impl Decision {
    /// Whether the request may proceed.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow(_))
    }
}

/// Decides whether `profile` may be used for `operation` in `context`.
///
/// This is the whole of the design's gate table. Reading it top to bottom
/// is meant to be the same as reading that table row by row.
#[must_use]
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature is frozen and Context is expected to gain non-Copy fields"
)]
pub fn evaluate(profile: Profile, operation: Operation, context: &Context) -> Decision {
    match profile {
        Profile::SessionToken => Decision::Allow(Confirmation::None),
        Profile::AgentWallet => agent_wallet(context),
        Profile::HumanWallet { allow_ai } => human_wallet(allow_ai, operation, context),
        Profile::ValidatorIdentity { network } => validator_identity(network, context),
        Profile::NodeResident { network } => node_resident(network, context),
    }
}

/// An agent wallet is reachable from anywhere, including headless and AI.
///
/// Its limit is the balance and the policy attached to it, not the caller's
/// surroundings, so there is nothing here to refuse.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature is frozen and Context is expected to gain non-Copy fields"
)]
fn agent_wallet(_context: &Context) -> Decision {
    Decision::Allow(Confirmation::None)
}

/// A person's wallet always needs that person at a terminal to sign.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature is frozen and Context is expected to gain non-Copy fields"
)]
fn human_wallet(allow_ai: bool, operation: Operation, context: &Context) -> Decision {
    if context.service_account {
        return Decision::Deny(Denial::ServiceAccount);
    }
    // `allow_ai` decides whether an AI tool path may ask at all, so it is
    // checked before the shortcut below rather than after it. Asking and
    // being told no is the whole protection for a wallet not marked for
    // AI use; letting the request through as far as "prepare" and
    // refusing only the signature is a different, weaker rule than the
    // one this flag is documented to be.
    if context.ai_tool_path && !allow_ai {
        return Decision::Deny(Denial::AiNotPermittedForWallet);
    }
    // Drafting a payment reveals nothing, so the AI console may do it. The
    // signature is the step that needs the operator.
    if operation == Operation::Prepare {
        return Decision::Allow(Confirmation::None);
    }
    if context.ai_console {
        return Decision::Deny(Denial::FromAiConsole);
    }
    if !context.has_tty {
        return Decision::Deny(Denial::NoTerminal);
    }
    Decision::Allow(Confirmation::Tty)
}

/// A validator identity. Mainnet is the strictest row in the table.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature is frozen and Context is expected to gain non-Copy fields"
)]
fn validator_identity(network: Network, context: &Context) -> Decision {
    if context.ai_console {
        return Decision::Deny(Denial::FromAiConsole);
    }
    if context.on_node {
        return Decision::Deny(Denial::OnNode);
    }

    if network.is_mainnet() {
        if context.service_account {
            return Decision::Deny(Denial::ServiceAccount);
        }
        if context.op_env_session {
            return Decision::Deny(Denial::OpEnvSession);
        }
        if !context.biometric_unlock {
            return Decision::Deny(Denial::BiometricUnlockRequired);
        }
        if context.in_ssh_session {
            return Decision::Deny(Denial::SshSession);
        }
        if !context.has_tty {
            return Decision::Deny(Denial::NoTerminal);
        }
        return Decision::Allow(Confirmation::TtyPhrase);
    }

    // Testnet and devnet: a service account is how CI reaches these, so it
    // is allowed and needs no terminal.
    if context.service_account {
        return Decision::Allow(Confirmation::None);
    }
    if context.in_ssh_session {
        return Decision::Deny(Denial::SshSession);
    }
    if !context.has_tty {
        return Decision::Deny(Denial::NoTerminal);
    }
    Decision::Allow(Confirmation::Tty)
}

/// Key material destined to live on a node. Only read when it is placed.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature is frozen and Context is expected to gain non-Copy fields"
)]
fn node_resident(network: Network, context: &Context) -> Decision {
    if context.ai_console {
        return Decision::Deny(Denial::FromAiConsole);
    }
    if context.service_account && network.is_mainnet() {
        return Decision::Deny(Denial::ServiceAccount);
    }
    if !context.has_tty {
        return Decision::Deny(Denial::NoTerminal);
    }
    Decision::Allow(Confirmation::Tty)
}

#[cfg(test)]
mod tests {
    use super::{Confirmation, Context, Decision, Denial, Network, Operation, Profile, evaluate};

    /// An operator sitting at their own machine with 1Password unlocked.
    fn at_a_desk() -> Context {
        Context {
            has_tty: true,
            biometric_unlock: true,
            ..Context::empty()
        }
    }

    /// Continuous integration: a service account, no person, no terminal.
    fn in_ci() -> Context {
        Context {
            service_account: true,
            ..Context::empty()
        }
    }

    #[test]
    fn a_session_token_is_reachable_from_anywhere() {
        for ctx in [Context::empty(), at_a_desk(), in_ci()] {
            assert_eq!(
                evaluate(Profile::SessionToken, Operation::Resolve, &ctx),
                Decision::Allow(Confirmation::None)
            );
        }
    }

    #[test]
    fn a_mainnet_validator_key_needs_a_typed_phrase() {
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &at_a_desk()
            ),
            Decision::Allow(Confirmation::TtyPhrase)
        );
    }

    #[test]
    fn a_mainnet_validator_key_refuses_a_service_account() {
        let ctx = Context {
            service_account: true,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::ServiceAccount)
        );
    }

    #[test]
    fn a_mainnet_validator_key_refuses_an_op_connect_environment() {
        let ctx = Context {
            op_env_session: true,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::OpEnvSession)
        );
    }

    #[test]
    fn a_mainnet_validator_key_refuses_an_ssh_session() {
        let ctx = Context {
            in_ssh_session: true,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::SshSession)
        );
    }

    #[test]
    fn a_mainnet_validator_key_refuses_a_node() {
        let ctx = Context {
            on_node: true,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::OnNode)
        );
    }

    #[test]
    fn a_mainnet_validator_key_refuses_a_switched_off_desktop_unlock() {
        let ctx = Context {
            biometric_unlock: false,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::BiometricUnlockRequired)
        );
    }

    #[test]
    fn a_testnet_validator_key_is_reachable_from_ci() {
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Testnet
                },
                Operation::Resolve,
                &in_ci()
            ),
            Decision::Allow(Confirmation::None)
        );
    }

    #[test]
    fn a_mainnet_validator_key_is_not_reachable_from_ci() {
        // The difference between these two tests is the whole reason the
        // network is part of the profile.
        assert!(
            !evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &in_ci()
            )
            .is_allowed()
        );
    }

    #[test]
    fn a_testnet_validator_key_still_needs_a_terminal_without_a_service_account() {
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Testnet
                },
                Operation::Resolve,
                &Context::empty()
            ),
            Decision::Deny(Denial::NoTerminal)
        );
    }

    #[test]
    fn a_human_wallet_may_be_prepared_by_the_ai_console_but_not_signed() {
        let ctx = Context {
            ai_console: true,
            ..at_a_desk()
        };
        let wallet = Profile::HumanWallet { allow_ai: true };
        assert_eq!(
            evaluate(wallet, Operation::Prepare, &ctx),
            Decision::Allow(Confirmation::None)
        );
        assert_eq!(
            evaluate(wallet, Operation::Resolve, &ctx),
            Decision::Deny(Denial::FromAiConsole)
        );
    }

    #[test]
    fn an_ai_tool_may_sign_with_a_wallet_marked_for_it() {
        let ctx = Context {
            ai_tool_path: true,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::HumanWallet { allow_ai: true },
                Operation::Resolve,
                &ctx
            ),
            Decision::Allow(Confirmation::Tty)
        );
    }

    #[test]
    fn an_ai_tool_may_not_sign_with_a_wallet_not_marked_for_it() {
        let ctx = Context {
            ai_tool_path: true,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::HumanWallet { allow_ai: false },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::AiNotPermittedForWallet)
        );
    }

    #[test]
    fn a_human_wallet_refuses_a_service_account_however_it_is_asked() {
        for allow_ai in [false, true] {
            for operation in [Operation::Prepare, Operation::Resolve] {
                assert_eq!(
                    evaluate(Profile::HumanWallet { allow_ai }, operation, &in_ci()),
                    Decision::Deny(Denial::ServiceAccount)
                );
            }
        }
    }

    #[test]
    fn an_agent_wallet_needs_neither_a_terminal_nor_a_person() {
        assert_eq!(
            evaluate(Profile::AgentWallet, Operation::Resolve, &Context::empty()),
            Decision::Allow(Confirmation::None)
        );
        assert_eq!(
            evaluate(Profile::AgentWallet, Operation::Resolve, &in_ci()),
            Decision::Allow(Confirmation::None)
        );
    }

    #[test]
    fn node_resident_material_refuses_a_service_account_on_mainnet_only() {
        assert_eq!(
            evaluate(
                Profile::NodeResident {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &Context {
                    service_account: true,
                    ..at_a_desk()
                }
            ),
            Decision::Deny(Denial::ServiceAccount)
        );
        assert_eq!(
            evaluate(
                Profile::NodeResident {
                    network: Network::Testnet
                },
                Operation::Resolve,
                &Context {
                    service_account: true,
                    ..at_a_desk()
                }
            ),
            Decision::Allow(Confirmation::Tty)
        );
    }

    #[test]
    fn the_ai_console_may_not_resolve_a_validator_identity() {
        // Both networks. Without this the AI console child process could
        // reach a mainnet staked identity key.
        for network in [Network::Mainnet, Network::Testnet] {
            let ctx = Context {
                ai_console: true,
                ..at_a_desk()
            };
            assert_eq!(
                evaluate(
                    Profile::ValidatorIdentity { network },
                    Operation::Resolve,
                    &ctx
                ),
                Decision::Deny(Denial::FromAiConsole),
                "{network:?}"
            );
        }
    }

    #[test]
    fn the_ai_console_may_not_resolve_node_resident_material() {
        let ctx = Context {
            ai_console: true,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::NodeResident {
                    network: Network::Testnet
                },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::FromAiConsole)
        );
    }

    #[test]
    fn a_mainnet_validator_key_needs_a_terminal_even_with_everything_else_in_place() {
        // Everything the mainnet row asks for except a person: desktop
        // unlock on, not SSH, not on a node, no service account.
        let ctx = Context {
            has_tty: false,
            biometric_unlock: true,
            ..Context::empty()
        };
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::NoTerminal)
        );
    }

    #[test]
    fn a_testnet_validator_key_refuses_an_ssh_session_without_a_service_account() {
        let ctx = Context {
            in_ssh_session: true,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Testnet
                },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::SshSession)
        );
    }

    #[test]
    fn every_profile_but_the_session_token_refuses_an_empty_context() {
        // The deny-by-default property: with nothing available, only the
        // two profiles whose rows say so get through.
        let nothing = Context::empty();
        for profile in [
            Profile::ValidatorIdentity {
                network: Network::Mainnet,
            },
            Profile::ValidatorIdentity {
                network: Network::Testnet,
            },
            Profile::HumanWallet { allow_ai: false },
            Profile::HumanWallet { allow_ai: true },
            Profile::NodeResident {
                network: Network::Mainnet,
            },
        ] {
            assert!(
                !evaluate(profile, Operation::Resolve, &nothing).is_allowed(),
                "{profile:?} should not resolve with nothing available"
            );
        }
    }

    /// Turns pairs into the iterator `from_env` wants.
    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn from_env_reads_the_facts_it_is_given() {
        let ctx = Context::from_env(
            true,
            false,
            env(&[
                ("ERPC_EXECUTION_CONTEXT", "ai-console"),
                ("SSH_CONNECTION", "10.0.0.1 1 10.0.0.2 22"),
                ("OP_SERVICE_ACCOUNT_TOKEN", "ops_token"),
            ]),
        );
        assert!(ctx.has_tty);
        assert!(ctx.ai_console);
        assert!(ctx.in_ssh_session);
        assert!(ctx.service_account);
        assert!(!ctx.op_env_session);
        // Absent means available: desktop unlock is only off when
        // something says it is.
        assert!(ctx.biometric_unlock);
    }

    #[test]
    fn from_env_treats_an_empty_variable_as_absent() {
        let ctx = Context::from_env(false, false, env(&[("OP_SERVICE_ACCOUNT_TOKEN", "")]));
        assert!(!ctx.service_account);
    }

    #[test]
    fn from_env_reads_the_desktop_unlock_switch() {
        let off = Context::from_env(
            true,
            false,
            env(&[("OP_BIOMETRIC_UNLOCK_ENABLED", "false")]),
        );
        assert!(!off.biometric_unlock);
    }

    #[test]
    fn a_real_1password_session_variable_is_detected() {
        // `op signin` exports OP_SESSION_<account>, never a bare
        // OP_SESSION. Looking up the bare name found nothing, so the
        // mainnet row that refuses a 1Password session environment did
        // not refuse the one it was written for.
        let ctx = Context::from_env(
            true,
            false,
            env(&[("OP_SESSION_mycompany", "eyJzZXNzaW9u")]),
        );
        assert!(ctx.op_env_session, "OP_SESSION_<account> is a session");
        assert_eq!(
            evaluate(
                Profile::ValidatorIdentity {
                    network: Network::Mainnet
                },
                Operation::Resolve,
                &ctx
            ),
            Decision::Deny(Denial::OpEnvSession)
        );
    }

    #[test]
    fn op_connect_variables_are_detected_too() {
        for name in ["OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_SESSION"] {
            let ctx = Context::from_env(true, false, env(&[(name, "x")]));
            assert!(ctx.op_env_session, "{name}");
        }
    }

    #[test]
    fn an_unmarked_wallet_refuses_an_ai_tool_path_before_it_can_even_prepare() {
        // `allow_ai` is documented as deciding whether the request may be
        // made at all. Allowing Prepare first made it decide only whether
        // the signature could be skipped, which is a weaker rule.
        let ctx = Context {
            ai_tool_path: true,
            ..at_a_desk()
        };
        for operation in [Operation::Prepare, Operation::Resolve] {
            assert_eq!(
                evaluate(Profile::HumanWallet { allow_ai: false }, operation, &ctx),
                Decision::Deny(Denial::AiNotPermittedForWallet),
                "{operation:?}"
            );
        }
    }

    #[test]
    fn a_marked_wallet_may_still_be_prepared_by_an_ai_tool_path() {
        let ctx = Context {
            ai_tool_path: true,
            ..at_a_desk()
        };
        assert_eq!(
            evaluate(
                Profile::HumanWallet { allow_ai: true },
                Operation::Prepare,
                &ctx
            ),
            Decision::Allow(Confirmation::None)
        );
    }
}
