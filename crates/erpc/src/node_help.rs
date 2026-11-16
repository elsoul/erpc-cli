// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What `erpc validator`, `erpc rpc` and `erpc node` show for help.
//!
//! Before a chain is chosen there is no clap tree to ask: the overview is
//! drawn here, in the styles clap's help is drawn in, and in the
//! operator's language. A chain's own tree is clap's, with its headings
//! translated and a line after it on where a command's options are; the
//! commands' own words stay English, since a catalog key is a command's
//! path and the same path says different things on different chains.

use core::fmt::Write as _;

use clap::Command;
use clap::builder::StyledStr;
use clap::builder::styling::Style;
use erpc_core::chain::{COMMON_VERBS, Chain, Role};
use unicode_width::UnicodeWidthStr as _;

use crate::cli::{i18n, ui};

/// The chains that have `role`, in the order they are offered.
pub(crate) fn chains_of(role: Role) -> Vec<Chain> {
    Chain::ALL
        .into_iter()
        .filter(|c| c.roles().contains(&role))
        .collect()
}

/// The names of the chains that have `role`, for a `--chain` help line.
pub(crate) fn names_of(role: Role) -> String {
    chains_of(role)
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Help for standard output: in colour when [`ui::help_coloured`] says so
/// and it is not for a script (`json`), wrapped to the terminal as
/// Japanese and Chinese need, without the blank line clap ends with.
pub(crate) fn shown(help: &StyledStr, json: bool) -> String {
    let text = if json {
        help.to_string()
    } else {
        ui::help_text(help)
    };
    let width = console::Term::stdout()
        .size_checked()
        .map_or(100, |(_, cols)| usize::from(cols));
    i18n::wrap(text.trim_end(), width)
}

/// `role`'s tree on `chain` as its help shows it: clap's headings in the
/// operator's language, and after the help, where a command's options are.
pub(crate) fn tree(role: Role, chain: Chain) -> Command {
    let command = crate::tree::command(role, chain);
    let next = t!("node_help.chain.next", role, chain);
    let after = match command.get_after_help() {
        Some(said) => format!("{said}\n\n{next}"),
        None => next,
    };
    i18n::localized(command.after_help(after), i18n::lang())
}

/// The overview of `role` before a chain is chosen: what it is for, how a
/// chain is chosen, the chains and their networks, the commands every
/// chain has and examples, plain for a script (`json`). What a request for
/// help asked about (`asked`) gets a line on where it is.
pub(crate) fn overview(role: Role, asked: Option<&Asked>, json: bool) -> String {
    shown(&overview_styled(role, &chains_of(role), asked), json)
}

/// The command a request for help named, with no chain chosen, and on
/// which chains of the role it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Asked {
    /// On every chain: what it takes depends on the chain.
    Everywhere(String),
    /// Only on these chains.
    On(String, Vec<Chain>),
    /// On none: no such command.
    Nowhere(String),
}

impl Asked {
    /// Where `word` is a command of `role`.
    pub(crate) fn of(role: Role, word: &str) -> Self {
        let all = chains_of(role);
        let on: Vec<Chain> = all
            .iter()
            .copied()
            .filter(|c| {
                crate::tree::command(role, *c)
                    .find_subcommand(word)
                    .is_some()
            })
            .collect();
        let word = word.to_owned();
        if on.is_empty() {
            Self::Nowhere(word)
        } else if on.len() == all.len() {
            Self::Everywhere(word)
        } else {
            Self::On(word, on)
        }
    }

    /// The line the overview ends with.
    fn said(&self, role: Role) -> String {
        match self {
            Self::Everywhere(verb) => t!("node_help.verb_help.depends", verb, role),
            Self::On(verb, on) => {
                let chains = on.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", ");
                let chain = on.first().copied().unwrap_or(Chain::Solana);
                t!("node_help.verb_help.only", verb, chains, role, chain)
            }
            Self::Nowhere(word) => t!("node_help.verb_help.none", word, role),
        }
    }
}

/// One line of a list: drawn as clap draws a command or a flag (`lit`),
/// with what is plain before it (`lead`) and after it (`plain`, a
/// placeholder), then what it is.
struct Row {
    lead: &'static str,
    lit: String,
    plain: String,
    about: String,
}

impl Row {
    fn new(lit: impl Into<String>, about: impl Into<String>) -> Self {
        Self {
            lead: "",
            lit: lit.into(),
            plain: String::new(),
            about: about.into(),
        }
    }

    fn with(mut self, plain: &str) -> Self {
        plain.clone_into(&mut self.plain);
        self
    }

    /// A flag with no short form, under one with (`-n, --network`).
    const fn long_only(mut self) -> Self {
        self.lead = "    ";
        self
    }

    fn width(&self) -> usize {
        self.lead.width() + self.lit.width() + self.plain.width()
    }
}

/// Writes help in the styles of clap's own.
struct Pen {
    out: StyledStr,
    header: Style,
    literal: Style,
    note: Style,
}

impl Pen {
    fn new() -> Self {
        let styles = ui::help_styles();
        Self {
            out: StyledStr::new(),
            header: *styles.get_header(),
            literal: *styles.get_literal(),
            note: *styles.get_context(),
        }
    }

    fn text(&mut self, text: &str) {
        let _ = writeln!(self.out, "{text}");
    }

    fn blank(&mut self) {
        let _ = writeln!(self.out);
    }

    /// A heading; `word` is a catalog's, without the colon clap adds.
    fn heading(&mut self, word: &str) {
        let h = self.header;
        let _ = writeln!(self.out, "{h}{word}:{h:#}");
    }

    /// The usage lines, the first after `Usage:` and the rest under it.
    fn usage(&mut self, lines: &[(String, &str)]) {
        let (h, l) = (self.header, self.literal);
        let word = t!("clap.usage");
        let under = " ".repeat(word.width() + 1);
        for (i, (lit, plain)) in lines.iter().enumerate() {
            if i == 0 {
                let _ = writeln!(self.out, "{h}{word}{h:#} {l}{lit}{l:#}{plain}");
            } else {
                let _ = writeln!(self.out, "{under}{l}{lit}{l:#}{plain}");
            }
        }
    }

    /// A list, its descriptions in one column, as clap aligns a section.
    fn rows(&mut self, rows: &[Row]) {
        let l = self.literal;
        let column = rows.iter().map(Row::width).max().unwrap_or(0) + 2;
        for row in rows {
            let pad = " ".repeat(column - row.width());
            let _ = writeln!(
                self.out,
                "  {}{l}{}{l:#}{}{pad}{}",
                row.lead, row.lit, row.plain, row.about
            );
        }
    }

    /// A command under a remark, drawn as clap draws a command.
    fn command(&mut self, command: &str) {
        let l = self.literal;
        let _ = writeln!(self.out, "    {l}{command}{l:#}");
    }

    /// A remark under a list, drawn as clap draws its notes.
    fn note(&mut self, text: &str) {
        let n = self.note;
        let _ = writeln!(self.out, "  {n}{text}{n:#}");
    }
}

fn overview_styled(role: Role, chains: &[Chain], asked: Option<&Asked>) -> StyledStr {
    let mut pen = Pen::new();
    pen.text(&match role {
        Role::Validator => t!("node_help.about.validator"),
        Role::Rpc => t!("node_help.about.rpc"),
        Role::Node => t!("node_help.about.node"),
    });
    pen.blank();
    let mut usage = vec![(
        format!("erpc {role} --chain"),
        " <chain> <COMMAND> [OPTIONS]",
    )];
    if role == Role::Rpc {
        usage.push(("erpc rpc call".to_owned(), " <METHOD> [PARAMS]"));
    }
    pen.usage(&usage);
    pen.blank();
    if role == Role::Rpc {
        pen.heading(&t!("node_help.heading.without_chain"));
        pen.rows(&[
            Row::new("call", t!("node_help.rpc.call")).with(" <METHOD> [PARAMS]"),
            Row::new("list-networks", t!("node_help.rpc.list_networks")),
        ]);
        pen.blank();
    }
    pen.heading(&t!("node_help.heading.chains"));
    let networks: Vec<Row> = chains
        .iter()
        .map(|c| Row::new(c.as_str(), c.networks().join(", ")))
        .collect();
    pen.rows(&networks);
    pen.blank();
    if role == Role::Validator {
        pen.heading(&t!("node_help.heading.no_validator"));
        pen.rows(&no_validator_rows());
        pen.note(&t!("node_help.no_validator.rpc"));
        pen.blank();
    }
    pen.heading(&t!("node_help.heading.commands"));
    let verbs: Vec<Row> = COMMON_VERBS
        .iter()
        .map(|v| {
            Row::new(
                v.name,
                verb_about(v.name).unwrap_or_else(|| v.about.to_owned()),
            )
        })
        .collect();
    pen.rows(&verbs);
    pen.note(&t!("node_help.commands.more"));
    pen.command(&format!("erpc {role} --chain <chain> --help"));
    pen.blank();
    pen.heading(&t!("clap.options"));
    pen.rows(&[
        Row::new("--chain", t!("node_help.option.chain"))
            .with(" <chain>")
            .long_only(),
        Row::new("-n, --network", t!("node_help.option.network")).with(" <network>"),
        Row::new("--name", t!("node_help.option.name"))
            .with(" <name>")
            .long_only(),
        Row::new("-h, --help", t!("clap.help")),
    ]);
    pen.blank();
    pen.heading(&t!("node_help.heading.examples"));
    pen.rows(&examples(
        role,
        chains.first().copied().unwrap_or(Chain::Solana),
    ));
    if let Some(asked) = asked {
        pen.blank();
        pen.text(&asked.said(role));
    }
    pen.out
}

/// The chains with no validator, grouped by why.
fn no_validator_rows() -> Vec<Row> {
    let mut rows: Vec<(Vec<&str>, String)> = Vec::new();
    for chain in Chain::ALL {
        let Some(why) = no_validator(chain) else {
            continue;
        };
        match rows.iter_mut().find(|(_, said)| *said == why) {
            Some((names, _)) => names.push(chain.as_str()),
            None => rows.push((vec![chain.as_str()], why)),
        }
    }
    rows.into_iter()
        .map(|(names, why)| Row::new(names.join(", "), why))
        .collect()
}

/// Why `chain` has no validator, in the operator's language: the reason
/// [`Chain::validator_na_reason`] gives, said short when it is one erpc
/// has words for, else as it is.
fn no_validator(chain: Chain) -> Option<String> {
    let reason = chain.validator_na_reason()?;
    Some(if reason.contains("proof-of-work") {
        t!("node_help.no_validator.mining")
    } else if reason.contains("rollup") {
        t!("node_help.no_validator.rollup")
    } else {
        reason.to_owned()
    })
}

/// What one of [`COMMON_VERBS`] does, in the operator's language; the
/// English is the verb's own `about`, which a test holds.
fn verb_about(name: &str) -> Option<String> {
    Some(match name {
        "init" => t!("node_help.verb.init"),
        "deploy" => t!("node_help.verb.deploy"),
        "list" => t!("node_help.verb.list"),
        "status" => t!("node_help.verb.status"),
        "logs" => t!("node_help.verb.logs"),
        "start" => t!("node_help.verb.start"),
        "stop" => t!("node_help.verb.stop"),
        "restart" => t!("node_help.verb.restart"),
        "update" => t!("node_help.verb.update"),
        "update-config" => t!("node_help.verb.update_config"),
        "plan" => t!("node_help.verb.plan"),
        "destroy" => t!("node_help.verb.destroy"),
        _ => return None,
    })
}

/// Examples that run as they say on a machine with nothing set up: a
/// `list` only where it needs neither a network nor a vault (solana's).
fn examples(role: Role, chain: Chain) -> Vec<Row> {
    let mut rows = vec![Row::new(
        format!("erpc {role} --chain {chain} --help"),
        t!("node_help.example.help", chain),
    )];
    if chain == Chain::Solana {
        rows.push(Row::new(
            format!("erpc {role} --chain {chain} list"),
            t!("node_help.example.list", chain),
        ));
    }
    rows.push(Row::new(
        format!("erpc config set default_chain {chain}"),
        t!("node_help.example.default", role),
    ));
    if role == Role::Rpc {
        rows.push(Row::new(
            "erpc rpc call getSlot",
            t!("node_help.example.call"),
        ));
    }
    rows
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{COMMON_VERBS, Chain, Role};
    use erpc_core::i18n::Lang;

    use super::{Asked, chains_of, examples, overview_styled, verb_about};
    use crate::cli::i18n::speaking;

    fn plain(role: Role) -> String {
        overview_styled(role, &chains_of(role), None).to_string()
    }

    #[test]
    fn the_overview_has_the_usage_each_chain_with_its_networks_and_every_common_verb() {
        for role in [Role::Validator, Role::Rpc, Role::Node] {
            let text = plain(role);
            assert!(
                text.contains(&format!(
                    "Usage: erpc {role} --chain <chain> <COMMAND> [OPTIONS]"
                )),
                "{text}"
            );
            for chain in chains_of(role) {
                let row = format!("{chain}  ");
                let networks = chain.networks().join(", ");
                assert!(
                    text.lines()
                        .any(|l| l.trim_start().starts_with(&row) && l.ends_with(&networks)),
                    "{role} {chain}: {text}"
                );
            }
            for verb in COMMON_VERBS {
                assert!(
                    text.lines()
                        .any(|l| l.trim_start().starts_with(&format!("{}  ", verb.name))
                            && l.ends_with(verb.about)),
                    "{role} {}: {text}",
                    verb.name
                );
            }
            assert!(
                text.contains(&format!(
                    "erpc {role} --chain {} --help",
                    chains_of(role)[0]
                )),
                "{text}"
            );
            // Where a chain's own commands are, on a line of its own.
            let own = format!("erpc {role} --chain <chain> --help");
            assert!(text.lines().any(|l| l.trim() == own), "{text}");
        }
    }

    #[test]
    fn only_rpc_lists_what_needs_no_chain_and_only_validator_what_has_no_validator() {
        let rpc = plain(Role::Rpc);
        assert!(rpc.contains("Usage: erpc rpc --chain"), "{rpc}");
        assert!(rpc.contains("erpc rpc call <METHOD> [PARAMS]"), "{rpc}");
        assert!(rpc.contains("list-networks"), "{rpc}");
        assert!(!rpc.contains("No validator"), "{rpc}");
        let validator = plain(Role::Validator);
        assert!(!validator.contains("list-networks"), "{validator}");
        assert!(validator.contains("No validator:"), "{validator}");
        // Each chain without a validator is said, grouped by why.
        let rows: Vec<&str> = validator
            .lines()
            .skip_while(|l| !l.starts_with("No validator:"))
            .skip(1)
            .take_while(|l| !l.trim().is_empty())
            .collect();
        for chain in Chain::ALL {
            let said = rows
                .iter()
                .any(|l| l.split([' ', ',']).any(|w| w == chain.as_str()));
            assert_eq!(
                said,
                chain.validator_na_reason().is_some(),
                "{chain}: {rows:?}"
            );
        }
        assert!(validator.contains("  bitcoin  "), "{validator}");
        assert!(
            validator.contains("  base, optimism, soneium  "),
            "{validator}"
        );
    }

    /// The English of each common verb is its own `about`: the overview
    /// says what `--chain <CHAIN> --help` says, in every language.
    #[test]
    fn the_common_verbs_read_as_their_own_about_in_english() {
        speaking(Lang::En, || {
            for verb in COMMON_VERBS {
                assert_eq!(
                    verb_about(verb.name).as_deref(),
                    Some(verb.about),
                    "{}",
                    verb.name
                );
            }
        });
    }

    /// The English of `call` and `list-networks` is their own about.
    #[test]
    fn what_needs_no_chain_reads_as_its_own_about_in_english() {
        let cli = <crate::Cli as clap::CommandFactory>::command();
        let rpc = cli.find_subcommand("rpc").expect("erpc rpc");
        let about = |name: &str| {
            rpc.find_subcommand(name)
                .and_then(clap::Command::get_about)
                .map(ToString::to_string)
        };
        speaking(Lang::En, || {
            assert_eq!(about("call"), Some(t!("node_help.rpc.call")));
            assert_eq!(
                about("list-networks"),
                Some(t!("node_help.rpc.list_networks"))
            );
        });
    }

    #[test]
    fn the_overview_speaks_the_operators_language() {
        let text = speaking(Lang::Ja, || plain(Role::Validator));
        assert!(text.contains("使い方: erpc validator --chain"), "{text}");
        assert!(text.contains("オプション:"), "{text}");
        assert!(!text.contains("Record the node"), "{text}");
    }

    /// A command asked about is said where it is: on every chain, on some
    /// (named, with one to try), or on none.
    #[test]
    fn a_command_asked_about_is_told_on_which_chains_it_is() {
        let v = Role::Validator;
        assert_eq!(Asked::of(v, "deploy"), Asked::Everywhere("deploy".into()));
        assert_eq!(
            Asked::of(v, "keys"),
            Asked::On("keys".into(), vec![Chain::Solana])
        );
        assert_eq!(Asked::of(v, "bogus"), Asked::Nowhere("bogus".into()));
        assert_eq!(Asked::of(Role::Rpc, "keys"), Asked::Nowhere("keys".into()));
        let last = |asked: &Asked| {
            overview_styled(v, &chains_of(v), Some(asked))
                .to_string()
                .trim_end()
                .rsplit('\n')
                .next()
                .unwrap_or_default()
                .to_owned()
        };
        speaking(Lang::En, || {
            assert_eq!(
                last(&Asked::of(v, "deploy")),
                "What deploy takes depends on the chain: erpc validator --chain <chain> deploy --help"
            );
            assert_eq!(
                last(&Asked::of(v, "keys")),
                "keys is on solana only: erpc validator --chain solana keys --help"
            );
            assert_eq!(
                last(&Asked::of(v, "bogus")),
                "`bogus` is no command of erpc validator on any chain"
            );
        });
    }

    /// A `list` example only where it runs with nothing set up: solana's,
    /// which needs neither a network nor a vault (`tests/output.rs` runs it).
    #[test]
    fn a_list_example_is_given_only_for_solana() {
        let lists = |role: Role, chain: Chain| {
            examples(role, chain)
                .iter()
                .filter(|r| r.lit.ends_with(" list"))
                .count()
        };
        assert_eq!(lists(Role::Validator, Chain::Solana), 1);
        assert_eq!(lists(Role::Rpc, Chain::Solana), 1);
        assert_eq!(lists(Role::Node, Chain::Avax), 0);
        assert_eq!(chains_of(Role::Node)[0], Chain::Avax);
    }
}
