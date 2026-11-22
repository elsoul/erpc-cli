// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The skills against the command line: every `erpc …` command a skill
//! names, and every `--flag`, must be one this binary has. A skill is read
//! by a model that runs what it says, so a command that was renamed or
//! removed has to fail the build, not the operator.
//!
//! What is checked: the code spans and fenced lines of every skill and of
//! the assistant's base prompt. A span that starts with `erpc` is walked
//! down the command tree, the node trees chosen by `--chain` the way the
//! binary chooses them; a span that is only a flag must be a flag of some
//! erpc command. Placeholders (`<name>`, `…`) and alternatives (`a|b`) are
//! understood; other programs' commands (`slv …`, `nft …`) are not checked.

use clap::{Arg, Command};
use erpc_core::chain::{Chain, Role};

/// Every code span in `text`, inline and fenced, with line breaks inside a
/// span turned into spaces.
pub(crate) fn spans(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    let mut prose = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            out.push(line.trim().to_owned());
        } else {
            prose.push_str(line);
            prose.push('\n');
        }
    }
    let mut parts = prose.split('`');
    parts.next();
    while let Some(inside) = parts.next() {
        out.push(inside.split_whitespace().collect::<Vec<_>>().join(" "));
        parts.next();
    }
    out
}

/// The node tree `role` has for the chain a span names, or every chain's
/// when it names none.
fn node_trees(role: Role, tokens: &[&str]) -> Vec<Command> {
    let named = tokens
        .windows(2)
        .find(|w| w[0] == "--chain")
        .and_then(|w| Chain::parse(w[1]));
    let chains: Vec<Chain> = match (named, role) {
        (Some(chain), _) => vec![chain],
        (None, Role::Validator) => vec![Chain::Solana],
        (None, _) => Chain::ALL
            .into_iter()
            .filter(|c| c.roles().contains(&role))
            .collect(),
    };
    chains
        .into_iter()
        .map(|chain| built(crate::tree::command(role, chain)))
        .collect()
}

/// `command` with its defaults filled in (how many values each flag takes),
/// as clap does before it parses.
fn built(mut command: Command) -> Command {
    command.build();
    command
}

fn root() -> Command {
    built(<crate::Cli as clap::CommandFactory>::command())
}

fn find_arg<'a>(path: &[&'a Command], flag: &str) -> Option<&'a Arg> {
    path.iter().rev().find_map(|c| {
        c.get_arguments().find(|a| {
            if let Some(long) = flag.strip_prefix("--") {
                a.get_long() == Some(long)
                    || a.get_all_aliases().is_some_and(|al| al.contains(&long))
            } else {
                flag.strip_prefix('-')
                    .and_then(|s| s.chars().next())
                    .is_some_and(|ch| flag.len() == 2 && a.get_short() == Some(ch))
            }
        })
    })
}

fn sub<'a>(command: &'a Command, name: &str) -> Option<&'a Command> {
    command
        .get_subcommands()
        .find(|s| s.get_name() == name || s.get_all_aliases().any(|a| a == name))
}

/// A word that stands for something: `<verb>`, `[--x]`, `…`.
fn placeholder(token: &str) -> bool {
    token.starts_with('<') || token.contains('…') || token == "..." || token.starts_with('$')
}

/// Walks `tokens` (after `erpc` and the role) down `tree`.
fn walk(tree: &Command, tokens: &[&str]) -> Result<(), String> {
    let mut path: Vec<&Command> = vec![tree];
    let mut i = 0;
    while i < tokens.len() {
        let raw =
            tokens[i].trim_matches(|c| matches!(c, '[' | ']' | '(' | ')' | ',' | ';' | ':' | '.'));
        i += 1;
        if raw.is_empty() || placeholder(raw) {
            continue;
        }
        if raw.starts_with('-') && raw.len() > 1 {
            let flag = raw.split('=').next().unwrap_or(raw);
            let here = path.last().copied().unwrap_or(tree);
            // Before the verb is chosen (`erpc r --chain arc <verb> --x`),
            // a flag of any verb will do.
            let arg = find_arg(&path, flag)
                .or_else(|| here.get_subcommands().find_map(|s| find_arg(&[s], flag)));
            let Some(arg) = arg else {
                return Err(format!("no flag {flag} here"));
            };
            let takes = arg.get_num_args().is_some_and(|n| n.min_values() > 0);
            if takes && !raw.contains('=') {
                i += 1;
            }
            continue;
        }
        let here = path.last().copied().unwrap_or(tree);
        if here.has_subcommands() {
            let names: Vec<&str> = raw.split('|').collect();
            let found: Vec<&Command> = names.iter().filter_map(|n| sub(here, n)).collect();
            if found.len() != names.len() {
                return Err(format!("no command {raw} under `{}`", here.get_name()));
            }
            path.push(found[0]);
        }
        // Anything else is an argument's value.
    }
    Ok(())
}

/// Every long and short flag of every command, for a span that is only a
/// flag.
fn every_flag() -> Vec<String> {
    fn collect(c: &Command, out: &mut Vec<String>) {
        for a in c.get_arguments() {
            if let Some(l) = a.get_long() {
                out.push(format!("--{l}"));
            }
        }
        for s in c.get_subcommands() {
            collect(s, out);
        }
    }
    let mut out = Vec::new();
    collect(&root(), &mut out);
    for chain in Chain::ALL {
        for role in chain.roles() {
            collect(&crate::tree::command(*role, chain), &mut out);
        }
    }
    out
}

/// What is wrong with one span, if it is an erpc command or flag.
fn check(span: &str, flags: &[String]) -> Result<(), String> {
    let tokens: Vec<&str> = span.split_whitespace().collect();
    match tokens.as_slice() {
        ["erpc", rest @ ..] => {
            // Global flags come first: `erpc --json r …`.
            let mut rest = rest;
            while let [first, tail @ ..] = rest {
                if first.starts_with("--") {
                    if !flags.iter().any(|f| f == first) {
                        return Err(format!("no flag {first}"));
                    }
                    rest = tail;
                } else {
                    break;
                }
            }
            let role = match rest.first().copied() {
                Some("v" | "validator") => Some(Role::Validator),
                Some("r" | "rpc") => Some(Role::Rpc),
                Some("n" | "node") => Some(Role::Node),
                _ => None,
            };
            if let Some(role) = role {
                let trees = node_trees(role, rest);
                let errors: Vec<String> = trees
                    .iter()
                    .filter_map(|t| walk(t, &rest[1..]).err())
                    .collect();
                // One chain that has it is enough when the span names none.
                if errors.len() == trees.len() {
                    return Err(errors.join("; "));
                }
                Ok(())
            } else {
                walk(&root(), rest)
            }
        }
        [first, ..] if first.starts_with("--") => {
            let flag = first.split('=').next().unwrap_or(first);
            if flags.iter().any(|f| f == flag) {
                Ok(())
            } else {
                Err(format!("no flag {flag}"))
            }
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{check, every_flag, spans};

    #[test]
    fn every_command_and_flag_a_skill_names_exists() {
        let flags = every_flag();
        let mut wrong = Vec::new();
        let texts = erpc_skills::all()
            .into_iter()
            .map(|s| (s.name, s.body))
            .chain([("base prompt", erpc_ai::prompt::BASE)]);
        for (name, body) in texts {
            for span in spans(body) {
                if let Err(e) = check(&span, &flags) {
                    wrong.push(format!("{name}: `{span}`: {e}"));
                }
            }
        }
        assert!(
            wrong.is_empty(),
            "skills name what erpc does not have:\n{}",
            wrong.join("\n")
        );
    }

    #[test]
    fn the_check_catches_a_wrong_command_and_flag() {
        let flags = every_flag();
        for good in [
            "erpc r --chain arc -n testnet --name arc1 init --host <ip> --type archive",
            "erpc r --chain arc -n testnet --name arc1 <verb> --ssh-key ~/.ssh/k.pub --ssh-agent <socket> …",
            "erpc --json r --chain arc list",
            "erpc v init -n testnet --client jito",
            "erpc r --chain arc start|stop|restart --layer execution",
            "erpc login --store keychain",
            "--yes",
            "--fingerprint SHA256:…",
        ] {
            assert_eq!(check(good, &flags), Ok(()), "{good}");
        }
        for bad in [
            "erpc r --chain arc reboot",
            "erpc r --chain arc deploy --fast",
            "erpc r --chain arc start|reboot",
            "erpc v init --not-a-flag",
            "erpc logins",
            "--never-heard-of",
        ] {
            assert!(check(bad, &flags).is_err(), "{bad}");
        }
    }

    #[test]
    fn spans_join_lines_and_read_fences() {
        let text = "a `erpc r\n  --chain arc` b\n```sh\nerpc whoami\n```\n";
        assert_eq!(spans(text), vec!["erpc whoami", "erpc r --chain arc"]);
    }
}
