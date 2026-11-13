// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which of erpc's own command lines build or deploy.
//!
//! `erpc ai` runs commands for the person and stops one after a few
//! minutes. A deploy takes longer: a worker's builds the app and waits for
//! a new server and its lines, a node's fetches a snapshot. So the
//! assistant's shell gives such a command a longer limit
//! ([`erpc_ai::commands::DEPLOY_LIMIT`]).
//!
//! Whether a line is one is not guessed from its words. It is read by the
//! parsers erpc itself runs it with, so a verb under another name, an
//! option before the verb, a host that is called `deploy` and what follows
//! `--` are all read as erpc reads them. A line erpc's parser refuses is
//! not a deploy: it ends at once.

use core::time::Duration;
use std::path::Path;

use erpc_ai::commands::{LocalShell, Ran, Shell};
use erpc_core::chain::Role;

/// Whether `command`, the program then its arguments, is erpc building or
/// deploying: `erpc worker deploy`, `erpc worker build`, `erpc worker run
/// --check` (which builds and ends once the app is healthy; a plain run
/// goes on until it is stopped), and a node's `deploy`.
pub(crate) fn builds_or_deploys(command: &[String]) -> bool {
    let is_erpc = command
        .first()
        .and_then(|program| Path::new(program).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "erpc" || name.eq_ignore_ascii_case("erpc.exe"));
    if !is_erpc {
        return false;
    }
    let Ok(read) = <crate::Cli as clap::Parser>::try_parse_from(command) else {
        return false;
    };
    match read.command {
        Some(crate::Command::Worker { action }) => match *action {
            crate::worker::Action::Deploy { .. } | crate::worker::Action::Build { .. } => true,
            crate::worker::Action::Run { check, .. } => check,
            _ => false,
        },
        Some(crate::Command::Validator { args }) => crate::tree::deploys(Role::Validator, &args),
        Some(crate::Command::Rpc { action: None, args }) => crate::tree::deploys(Role::Rpc, &args),
        Some(crate::Command::Node { args }) => crate::tree::deploys(Role::Node, &args),
        _ => false,
    }
}

/// The shell `erpc ai` runs commands in: this machine's, which knows which
/// of erpc's own commands build or deploy.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ErpcShell(LocalShell);

/// The shell the assistant's session is given.
pub(crate) fn assistants_shell() -> Box<dyn Shell> {
    Box::new(ErpcShell::default())
}

impl Shell for ErpcShell {
    fn folder(&self) -> String {
        self.0.folder()
    }

    fn run<'a>(
        &'a self,
        command: &'a [String],
        limit: Duration,
    ) -> core::pin::Pin<Box<dyn Future<Output = Result<Ran, String>> + 'a>> {
        self.0.run(command, limit)
    }

    fn runs_long(&self, command: &[String]) -> bool {
        builds_or_deploys(command)
    }
}

#[cfg(test)]
mod tests {
    use erpc_ai::commands::Shell as _;

    use super::{ErpcShell, builds_or_deploys};

    fn line(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn a_workers_deploy_build_and_checked_run_are_long_and_nothing_else_of_it_is() {
        for words in [
            &["erpc", "worker", "deploy"][..],
            &["erpc", "worker", "deploy", "bot", "--new-vps", "--yes"],
            &["erpc", "w", "deploy", "--env", "prod"],
            &["erpc", "--json", "worker", "build"],
            &["erpc", "--lang", "ja", "w", "build", "--dir", "apps/bot"],
            &["erpc", "worker", "run", "--check"],
            &["erpc", "w", "run", "--check", "--dir", "bot"],
            &["/home/me/.erpc/bin/erpc", "worker", "deploy"],
            &["ERPC.EXE", "worker", "deploy"],
        ] {
            assert!(builds_or_deploys(&line(words)), "{words:?}");
        }
        for words in [
            // A run goes on until it is stopped.
            &["erpc", "worker", "run"][..],
            // After `--` the word is not erpc's option.
            &["erpc", "worker", "run", "--", "--check"],
            // The word as a value, an app's name or another verb's.
            &["erpc", "worker", "run", "--dir", "deploy"],
            &["erpc", "worker", "status", "deploy"],
            &["erpc", "worker", "logs", "-f", "--env", "deploy"],
            &["erpc", "worker", "status", "--env", "deploy"],
            &["erpc", "ai", "-m", "deploy"],
            // What erpc's parser refuses ends at once.
            &["erpc", "deploy"],
            &["erpc", "storage", "deploy"],
            &["erpc", "worker", "deploy", "--no-such-option"],
            // Help is a look.
            &["erpc", "worker", "deploy", "--help"],
            &["erpc", "worker", "--help", "deploy"],
            // Not erpc.
            &["cargo", "worker", "deploy"],
            &["./deploy", "erpc", "worker", "deploy"],
            &["kubectl", "rollout", "deploy"],
        ] {
            assert!(!builds_or_deploys(&line(words)), "{words:?}");
        }
        assert!(!builds_or_deploys(&[]));
    }

    #[test]
    fn a_nodes_deploy_is_long_as_the_skills_and_the_readme_write_it() {
        for words in [
            // The chain, the network and the host before the verb.
            &[
                "erpc", "r", "--chain", "arc", "-n", "testnet", "--name", "arc1", "deploy",
            ][..],
            &[
                "erpc",
                "rpc",
                "--chain=arc",
                "--network",
                "testnet",
                "deploy",
            ],
            &[
                "erpc", "v", "--chain", "solana", "-n", "testnet", "--name", "v1", "deploy",
            ],
            &[
                "erpc",
                "validator",
                "deploy",
                "--chain",
                "solana",
                "-n",
                "testnet",
            ],
            &["erpc", "node", "--chain", "sui", "-n", "testnet", "deploy"],
            &["erpc", "n", "--chain", "avax", "-n", "fuji", "deploy"],
        ] {
            assert!(builds_or_deploys(&line(words)), "{words:?}");
        }
        for words in [
            // A host or a network that is called deploy is not the verb.
            &[
                "erpc", "v", "--chain", "solana", "--name", "deploy", "status",
            ][..],
            &["erpc", "r", "--chain", "arc", "--name", "deploy", "restart"],
            // Another verb, and one the role does not have.
            &["erpc", "v", "--chain", "solana", "-n", "testnet", "status"],
            &["erpc", "v", "--chain", "solana", "status", "deploy"],
            &["erpc", "r", "--chain", "arc", "aqa", "deploy"],
            // A chain erpc does not know.
            &["erpc", "v", "--chain", "nosuchchain", "deploy"],
            // erpc's own RPC call, whose method is called deploy.
            &["erpc", "rpc", "call", "deploy"],
        ] {
            assert!(!builds_or_deploys(&line(words)), "{words:?}");
        }
    }

    #[test]
    fn the_assistants_shell_answers_with_erpcs_own_reading() {
        // The shell the session is given, not one made for the test: a
        // plain shell there would give no command the long limit.
        let shell = super::assistants_shell();
        assert!(shell.runs_long(&line(&["erpc", "worker", "deploy"])));
        assert!(!shell.runs_long(&line(&["erpc", "worker", "status"])));
        assert!(!shell.runs_long(&line(&["sleep", "600"])));
        assert!(ErpcShell::default().runs_long(&line(&["erpc", "worker", "build"])));
    }

    /// Each role's name reads its own role's tree. The three arms of
    /// `builds_or_deploys` mirror erpc's dispatch by hand; this holds each
    /// to the role it names, on every chain and under both of its names.
    #[test]
    fn each_roles_name_is_read_with_that_roles_tree_on_every_chain() {
        use erpc_core::chain::{Chain, Role};
        let mut long = 0;
        for (role, names) in [
            (Role::Validator, ["validator", "v"]),
            (Role::Rpc, ["rpc", "r"]),
            (Role::Node, ["node", "n"]),
        ] {
            for chain in Chain::ALL {
                for verb in ["deploy", "status"] {
                    let rest = line(&["--chain", chain.as_str(), "--name", "h1", verb]);
                    let wanted = crate::tree::deploys(role, &rest);
                    for name in names {
                        let mut full = line(&["erpc", name]);
                        full.extend(rest.iter().cloned());
                        assert_eq!(builds_or_deploys(&full), wanted, "{full:?}");
                    }
                    long += usize::from(wanted);
                }
            }
        }
        // Not vacuous, and not every role has every chain: a line read with
        // another role's tree would change some answer.
        assert!(long >= 18, "{long} deploys");
        let only_validator = Chain::ALL.into_iter().any(|chain| {
            let rest = line(&["--chain", chain.as_str(), "--name", "h1", "deploy"]);
            crate::tree::deploys(Role::Validator, &rest) != crate::tree::deploys(Role::Rpc, &rest)
        });
        assert!(only_validator, "some chain has a deploy for one role only");
    }

    /// The lines the README and the guides write, word for word: a chain
    /// under another of its names, the network and host before or after
    /// the verb, a verb under another.
    #[test]
    fn the_documents_own_deploy_lines_are_long() {
        for words in [
            &[
                "erpc",
                "rpc",
                "--chain",
                "ethereum",
                "-n",
                "mainnet",
                "--name",
                "eth1",
                "deploy",
                "--ssh-key",
                "id_ed25519.pub",
            ][..],
            &[
                "erpc",
                "r",
                "--chain",
                "bitcoin",
                "deploy",
                "-n",
                "signet",
                "--name",
                "btc-a",
                "--ssh-key",
                "operator.pub",
            ],
            &[
                "erpc",
                "v",
                "--chain",
                "hyperliquid",
                "--network",
                "testnet",
                "aqa",
                "deploy",
                "--name",
                "aqa-test",
                "--ssh-key",
                "operator.pub",
                "--vault",
                "vault",
            ],
        ] {
            assert!(builds_or_deploys(&line(words)), "{words:?}");
        }
        // The same lines' neighbours in those documents are not.
        for words in [
            &[
                "erpc",
                "rpc",
                "--chain",
                "ethereum",
                "-n",
                "mainnet",
                "--name",
                "eth1",
                "status",
                "--ssh-key",
                "id_ed25519.pub",
            ][..],
            &[
                "erpc",
                "r",
                "--chain",
                "bitcoin",
                "status",
                "-n",
                "signet",
                "--name",
                "btc-a",
                "--ssh-key",
                "operator.pub",
            ],
        ] {
            assert!(!builds_or_deploys(&line(words)), "{words:?}");
        }
    }

    /// What is in `dir`, by name.
    fn listed(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|entry| entry.expect("an entry").path())
            .collect();
        entries.sort();
        entries
    }

    /// Every file in `dir` and the directories under it that `wanted`
    /// picks, but for what is under a directory called `plans`.
    fn files(
        dir: &std::path::Path,
        wanted: &dyn Fn(&std::path::Path) -> bool,
        found: &mut Vec<std::path::PathBuf>,
    ) {
        for entry in listed(dir) {
            if entry.is_dir() {
                if entry.file_name().is_some_and(|name| name != "plans") {
                    files(&entry, wanted, found);
                }
            } else if wanted(&entry) {
                found.push(entry);
            }
        }
    }

    /// The documents that write erpc's command lines for a person or the
    /// assistant to run, as the files of this repository are now: the
    /// README, SECURITY.md, every Markdown file under `docs/`, every
    /// skill, the assistant's base prompt and the READMEs that go out
    /// with a crate's templates (a worker app's, a chain's operations
    /// guide). Each with its path from the repository's root. Not the
    /// dated plans under `docs/plans`, which record what was planned on
    /// their day, nor the catalogs, whose lines are filled in when erpc
    /// prints them.
    fn documents() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut paths = vec![
            root.join("README.md"),
            root.join("SECURITY.md"),
            root.join("crates/erpc-ai/skills/base.md"),
        ];
        let markdown = |path: &std::path::Path| path.extension().is_some_and(|e| e == "md");
        files(&root.join("docs"), &markdown, &mut paths);
        let skills = listed(&root.join("crates/erpc-skills/skills")).into_iter();
        paths.extend(skills.map(|skill| skill.join("SKILL.md")));
        let readme = |path: &std::path::Path| path.file_name().is_some_and(|n| n == "README.md");
        for krate in listed(&root.join("crates")) {
            let templates = krate.join("templates");
            if templates.is_dir() {
                files(&templates, &readme, &mut paths);
            }
        }
        paths
            .into_iter()
            .map(|path| {
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                let name = path.strip_prefix(&root).expect("under the root");
                (name.display().to_string(), text)
            })
            .collect()
    }

    /// A plain value of the kind a placeholder's name says (`<ID>`,
    /// `<vault id>`, `$HOST`), so that erpc's parser reads the line a
    /// document writes as it reads the line a person types from it.
    fn value_for(name: &str) -> String {
        let name = name.to_ascii_lowercase();
        let has = |part: &str| name.contains(part);
        if has("vault") {
            // Of the shape a 1Password vault id has.
            ('a'..='z').collect()
        } else if has("ip") || has("address") || has("host") || has("server") {
            "203.0.113.7".to_owned()
        } else if has("port") {
            "8080".to_owned()
        } else if has("id") {
            "100001".to_owned()
        } else {
            "x".to_owned()
        }
    }

    /// `span` with every `<placeholder>` given its plain value.
    fn filled(span: &str) -> String {
        let (mut out, mut rest) = (String::new(), span);
        while let Some((before, after)) = rest.split_once('<') {
            let Some((name, after)) = after.split_once('>') else {
                break;
            };
            out.push_str(before);
            out.push_str(&value_for(name));
            rest = after;
        }
        out + rest
    }

    /// `span` as the argv a shell would hand erpc, when it is an erpc
    /// command line: up to a comment, a pipe or the next command of a
    /// list, with a usage line's brackets and quotes taken off, the first
    /// of `a|b` alternatives, and placeholders given plain values.
    fn argv_of(span: &str) -> Option<Vec<String>> {
        let plain = filled(span);
        let mut words = plain.split_whitespace().peekable();
        if words.peek() == Some(&"$") {
            words.next();
        }
        if words.next() != Some("erpc") {
            return None;
        }
        let mut argv = line(&["erpc"]);
        for word in words {
            if word.starts_with('#') || matches!(word, "|" | "||" | "&&" | ";" | ">" | "\\") {
                break;
            }
            let word =
                word.trim_matches(|c| matches!(c, '[' | ']' | '(' | ')' | ',' | ';' | '\'' | '"'));
            let word = word.split('|').next().unwrap_or(word);
            if matches!(word, "" | "…" | "...") {
                continue;
            }
            argv.push(match word.strip_prefix('$') {
                Some(variable) => value_for(variable),
                None => word.replace('…', "x"),
            });
        }
        Some(argv)
    }

    /// Every erpc command line `text` writes, in a code span or a fenced
    /// block; a fenced line that ends in a backslash goes on in the next.
    fn lines_of(text: &str) -> Vec<Vec<String>> {
        let joined = text.replace("\r\n", "\n").replace("\\\n", " ");
        crate::skill_check::spans(&joined)
            .iter()
            .filter_map(|span| argv_of(span))
            .collect()
    }

    /// Whether a line is one the long limit is for, told from its words
    /// alone and by no parser: `erpc worker deploy`, `erpc worker build`,
    /// `erpc worker run` with `--check`, and a node's line (`erpc
    /// validator`, `erpc rpc`, `erpc node`, under either name) with the
    /// verb `deploy`. erpc's own options may come before the command, and
    /// a line that asks for help is not one.
    fn written_as_long(argv: &[String]) -> bool {
        let mut words = argv.iter().skip(1).map(String::as_str);
        let command = loop {
            match words.next() {
                Some("--lang") => {
                    words.next();
                }
                Some(option) if option.starts_with("--") => {}
                other => break other,
            }
        };
        let rest: Vec<&str> = words.take_while(|word| *word != "--").collect();
        if rest.iter().any(|word| matches!(*word, "--help" | "-h")) {
            return false;
        }
        match command {
            Some("worker" | "w") => match rest.first() {
                Some(&("deploy" | "build")) => true,
                Some(&"run") => rest.contains(&"--check"),
                _ => false,
            },
            Some("validator" | "v" | "rpc" | "r" | "node" | "n") => rest.contains(&"deploy"),
            _ => false,
        }
    }

    /// The assistant's shell, as the session is given it, except that it
    /// runs nothing: it keeps the limit each command was handed.
    struct Timed {
        shell: Box<dyn erpc_ai::commands::Shell>,
        limits: core::cell::RefCell<Vec<core::time::Duration>>,
    }

    impl erpc_ai::commands::Shell for Timed {
        fn folder(&self) -> String {
            self.shell.folder()
        }

        fn run<'a>(
            &'a self,
            _command: &'a [String],
            limit: core::time::Duration,
        ) -> core::pin::Pin<Box<dyn Future<Output = Result<erpc_ai::commands::Ran, String>> + 'a>>
        {
            self.limits.borrow_mut().push(limit);
            Box::pin(async { Ok(erpc_ai::commands::Ran::default()) })
        }

        fn runs_long(&self, command: &[String]) -> bool {
            self.shell.runs_long(command)
        }
    }

    /// A person who says yes to every command they are asked about.
    struct Yes;

    impl erpc_ai::confirm::Confirm for Yes {
        fn confirm<'a>(
            &'a self,
            _ask: &'a erpc_ai::confirm::Confirmation,
        ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
            Box::pin(async { true })
        }
    }

    /// The limit the assistant's `run_command` hands the shell for `argv`,
    /// through the tool itself, with the shell the session is given.
    async fn limit_of(argv: &[String]) -> core::time::Duration {
        let timed = Timed {
            shell: super::assistants_shell(),
            limits: core::cell::RefCell::default(),
        };
        let helpers = erpc_ai::tools::Helpers {
            confirm: Some(&Yes),
            shell: Some(&timed),
            ..erpc_ai::tools::Helpers::default()
        };
        let client = erpc_auth::AuthClient::new().expect("a client");
        let token = secrecy::SecretString::from(String::new());
        let input = serde_json::json!({ "argv": argv });
        erpc_ai::tools::run("run_command", &input, &client, &token, helpers)
            .await
            .unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        let limits = timed.limits.borrow();
        assert_eq!(limits.len(), 1, "{argv:?} is run once");
        limits[0]
    }

    /// Every erpc line of every document, once, with the document that
    /// writes it first.
    fn every_line() -> Vec<(String, Vec<String>)> {
        let mut seen = std::collections::BTreeSet::new();
        let mut lines = Vec::new();
        for (path, text) in documents() {
            for argv in lines_of(&text) {
                if seen.insert(argv.clone()) {
                    lines.push((path.clone(), argv));
                }
            }
        }
        lines
    }

    /// The hand-copied lines above hold three of the documents' lines.
    /// This reads the documents themselves: every erpc line they write is
    /// run through the assistant's tool, and is handed the long limit when
    /// its words say it builds or deploys, and the limit every other
    /// command has when they do not. A line the documents write for a
    /// deploy that erpc's parser reads otherwise, or refuses, fails here.
    #[tokio::test]
    async fn every_erpc_line_the_documents_write_is_handed_its_limit() {
        use core::time::Duration;
        use erpc_ai::commands::DEPLOY_LIMIT;
        let lines = every_line();
        let mut long = Vec::new();
        let mut short = Vec::new();
        for (path, argv) in &lines {
            let wanted = written_as_long(argv);
            assert_eq!(builds_or_deploys(argv), wanted, "{path}: {argv:?}");
            let limit = limit_of(argv).await;
            if wanted {
                assert_eq!(limit, DEPLOY_LIMIT, "{path}: {argv:?}");
                long.push(argv.join(" "));
            } else {
                // Five minutes, or the thirty seconds of a line that only
                // looks and so runs without a yes.
                let look = erpc_ai::commands::only_looks(argv);
                let short_limit = Duration::from_secs(if look { 30 } else { 300 });
                assert_eq!(limit, short_limit, "{path}: {argv:?}");
                short.push(argv.join(" "));
            }
        }
        println!("{} lines: {} long", lines.len(), long.len());
        // Not vacuous: the documents write hundreds of lines, and each
        // kind the long limit is for is among them, with the flags a
        // deploy with nobody at a terminal is given.
        assert!(lines.len() >= 300 && long.len() >= 40, "{}", lines.len());
        let among = |lines: &[String], starts: &str, has: &str| {
            lines
                .iter()
                .any(|line| line.starts_with(starts) && line.split(' ').any(|word| word == has))
        };
        for (starts, has) in [
            ("erpc worker deploy", "--prepare"),
            ("erpc worker deploy", "--yes"),
            ("erpc worker deploy", "--new-vps"),
            ("erpc worker deploy", "--vps"),
            ("erpc worker deploy", "--unlimited"),
            ("erpc worker deploy", "--forget-line"),
            ("erpc worker build", "build"),
            ("erpc worker run", "--check"),
            ("erpc rpc", "deploy"),
            ("erpc r ", "deploy"),
            ("erpc v ", "deploy"),
        ] {
            assert!(among(&long, starts, has), "no long `{starts} … {has}`");
        }
        // And what stays short is there to be held short.
        for (starts, has) in [
            ("erpc worker import", "import"),
            ("erpc worker run", "run"),
            ("erpc worker secret put", "put"),
            ("erpc worker firewall", "allow"),
            ("erpc worker bench", "bench"),
            ("erpc worker logs", "logs"),
            ("erpc worker start", "start"),
        ] {
            assert!(among(&short, starts, has), "no short `{starts} … {has}`");
        }
    }
}
