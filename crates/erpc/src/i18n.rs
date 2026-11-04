// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What erpc says, in the language the operator reads.
//!
//! The words live in `crates/erpc/locales/<code>/<area>.toml` (see the
//! README there); [`t!`] and [`tn!`] say one in the language of the run,
//! which [`choose`] settles before the command line is read. `--json`
//! output, what goes to a server or a file, and the machine-read
//! `warning:` / `hint:` / `Next:` marks stay as they are in every language.
//!
//! `--help` is translated from the same catalogs: `cli_<command>.toml`
//! holds a command's help keyed by its path, `"worker deploy"` for the
//! command and `"worker deploy --host"` or `"worker deploy <name>"` for
//! its arguments. The English there is the doc comment as clap reads it,
//! which a test holds it to, so changing the comment asks for the
//! translations to change too.

use std::sync::LazyLock;

use clap::Command;
use erpc_core::i18n::{Catalog, Lang};
use include_dir::{Dir, include_dir};

static LOCALES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/locales");

/// Every message of this crate, in every language.
pub(crate) static CATALOG: LazyLock<Catalog> =
    LazyLock::new(|| Catalog::parse(files(&LOCALES)).unwrap_or_default());

fn files(dir: &'static Dir<'static>) -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    for entry in dir.entries() {
        if let Some(d) = entry.as_dir() {
            out.extend(files(d));
        } else if let Some((path, text)) = entry
            .as_file()
            .and_then(|f| Some((f.path().to_str()?, f.contents_utf8()?)))
        {
            out.push((path, text));
        }
    }
    out
}

/// The language a message is said in: the run's, or in a test English
/// unless [`speaking`] says otherwise, whatever the machine's locale.
pub(crate) fn lang() -> Lang {
    #[cfg(test)]
    {
        SPEAKING.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        erpc_core::i18n::current()
    }
}

#[cfg(test)]
thread_local! {
    static SPEAKING: std::cell::Cell<Lang> = const { std::cell::Cell::new(Lang::En) };
}

/// In a test: runs `f` with this thread's messages in `lang`.
#[cfg(test)]
pub(crate) fn speaking<T>(lang: Lang, f: impl FnOnce() -> T) -> T {
    let before = SPEAKING.with(|s| s.replace(lang));
    let out = f();
    SPEAKING.with(|s| s.set(before));
    out
}

/// A message in the language of this run: `t!("worker.deploy.done",
/// name, host = vps.ip)`, an argument by itself standing for `name = name`.
macro_rules! t {
    ($key:literal $(, $name:ident $(= $value:expr)?)* $(,)?) => {
        $crate::i18n::CATALOG.text(
            $crate::i18n::lang(),
            $key,
            &[$((stringify!($name), &$crate::i18n::arg!($name $(= $value)?) as &dyn ::std::fmt::Display)),*],
        )
    };
}

/// A message whose words follow the count `n`, which it can show as `{n}`:
/// `tn!("worker.vps.found", servers.len(), region)`.
macro_rules! tn {
    ($key:literal, $n:expr $(, $name:ident $(= $value:expr)?)* $(,)?) => {
        $crate::i18n::CATALOG.plural(
            $crate::i18n::lang(),
            $key,
            u64::try_from($n).unwrap_or(u64::MAX),
            &[$((stringify!($name), &$crate::i18n::arg!($name $(= $value)?) as &dyn ::std::fmt::Display)),*],
        )
    };
}

macro_rules! arg {
    ($name:ident) => {
        $name
    };
    ($name:ident = $value:expr) => {
        $value
    };
}

pub(crate) use arg;

/// Settles the language of this run from `--lang`, `ERPC_LANG`, the
/// `locale` setting and the system's locale, in that order. Runs before
/// clap reads the command line, so it finds `--lang` itself. A `--json`
/// run is for a program and speaks English, errors included.
pub(crate) fn choose() -> Lang {
    if crate::json_mode() {
        erpc_core::i18n::set_current(Lang::En);
        return Lang::En;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = args.iter().enumerate().find_map(|(i, a)| {
        a.strip_prefix("--lang=")
            .map(str::to_owned)
            .or_else(|| (a == "--lang").then(|| args.get(i + 1).cloned()).flatten())
    });
    let configured = crate::session::config_path()
        .ok()
        .and_then(|p| crate::config::get(&p, "locale").ok().flatten());
    let lang = erpc_core::i18n::resolve(flag.as_deref(), configured.as_deref(), |name| {
        std::env::var(name).ok()
    });
    erpc_core::i18n::set_current(lang);
    lang
}

/// `command` with its help in `lang`: about, arguments, headings and
/// clap's own words. Help a catalog has no words for stays English.
pub(crate) fn localized(mut command: Command, lang: Lang) -> Command {
    if lang == Lang::En {
        return command;
    }
    if wraps_itself(lang) {
        // clap wraps only at spaces; [`print_help`] wraps CJK text instead.
        command = command.term_width(0);
    }
    command.build();
    let words = Words::new(lang);
    words.apply(&mut command, &[]);
    command
}

/// Whether help in `lang` is wrapped by [`wrap`] rather than by clap,
/// which breaks lines only at spaces and so not inside Japanese or Chinese.
pub(crate) const fn wraps_itself(lang: Lang) -> bool {
    matches!(lang, Lang::Ja | Lang::Zh)
}

/// Prints the help clap rendered for `error` (`--help`, or a command
/// without its subcommand) wrapped to the terminal, and exits as clap
/// would.
pub(crate) fn print_help(error: &clap::Error) -> ! {
    use std::io::Write as _;
    let (term, drawn) = if error.use_stderr() {
        (console::Term::stderr(), crate::ui::stderr_drawn())
    } else {
        (console::Term::stdout(), crate::ui::stdout_drawn())
    };
    let coloured = drawn && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let rendered = error.render();
    let text = if coloured {
        rendered.ansi().to_string()
    } else {
        rendered.to_string()
    };
    let width = term
        .size_checked()
        .map_or(100, |(_, cols)| usize::from(cols));
    let wrapped = wrap(&text, width);
    let _ = if error.use_stderr() {
        std::io::stderr().lock().write_all(wrapped.as_bytes())
    } else {
        std::io::stdout().lock().write_all(wrapped.as_bytes())
    };
    std::process::exit(error.exit_code())
}

/// Clap's help with every line wider than `width` wrapped: a description
/// continues under where it began, CJK text breaks between any two
/// characters except before closing or after opening punctuation, Latin
/// words and `code` stay whole. Colour escapes take no room.
pub(crate) fn wrap(help: &str, width: usize) -> String {
    let mut out = String::with_capacity(help.len());
    for (i, line) in help.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        wrap_line(line, width, &mut out);
    }
    out
}

/// A piece of a line that is not broken: its text with any escapes, and
/// how wide it shows.
struct Atom<'a> {
    text: &'a str,
    width: usize,
    space: bool,
}

fn wrap_line(line: &str, width: usize, out: &mut String) {
    let glyphs = glyphs(line);
    let total: usize = glyphs.iter().map(|g| g.2).sum();
    if total <= width || width < 20 {
        out.push_str(line);
        return;
    }
    // Where the description starts: after the leading spaces, the first
    // gap of two spaces past some text; else the leading spaces.
    let lead = glyphs.iter().take_while(|g| g.1 == ' ').count();
    let mut start = lead;
    let mut seen_text = false;
    let mut k = lead;
    while k < glyphs.len() {
        if glyphs[k].1 == ' ' && glyphs.get(k + 1).is_some_and(|g| g.1 == ' ') && seen_text {
            let mut j = k;
            while glyphs.get(j).is_some_and(|g| g.1 == ' ') {
                j += 1;
            }
            start = j;
            break;
        }
        seen_text |= glyphs[k].1 != ' ';
        k += 1;
    }
    let col: usize = glyphs[..start].iter().map(|g| g.2).sum();
    let head_end = glyphs.get(start).map_or(line.len(), |g| g.0);
    let (head, body) = line.split_at(head_end);
    // A description that would start too far right goes on the next line,
    // as clap puts it.
    let indent = if col > width * 2 / 3 {
        out.push_str(head.trim_end());
        out.push('\n');
        out.push_str(&" ".repeat(lead + 10));
        lead + 10
    } else {
        out.push_str(head);
        col
    };
    let room = width.saturating_sub(indent).max(10);
    let mut used = 0;
    for atom in atoms(body) {
        if atom.space {
            if used > 0 && used + atom.width <= room {
                out.push_str(atom.text);
                used += atom.width;
            } else if used > 0 {
                // A break: the space goes, its colour does not.
                out.push_str(&escapes_of(atom.text));
                out.push('\n');
                out.push_str(&" ".repeat(indent));
                used = 0;
            }
            continue;
        }
        if used > 0 && used + atom.width > room {
            while out.ends_with(' ') {
                out.pop();
            }
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            used = 0;
        }
        out.push_str(atom.text);
        used += atom.width;
    }
}

/// Each visible character of `line`: its byte offset (escapes before it
/// included), the character and its width.
fn glyphs(line: &str) -> Vec<(usize, char, usize)> {
    use unicode_width::UnicodeWidthChar as _;
    let mut out = Vec::new();
    let mut chars = line.char_indices().peekable();
    let mut pending: Option<usize> = None;
    while let Some((at, c)) = chars.next() {
        if c == '\x1b' {
            pending.get_or_insert(at);
            for (_, e) in chars.by_ref() {
                if e.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push((pending.take().unwrap_or(at), c, c.width().unwrap_or(0)));
    }
    out
}

fn escapes_of(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for c in text.chars() {
        if c == '\x1b' {
            inside = true;
        }
        if inside {
            out.push(c);
            if c.is_ascii_alphabetic() {
                inside = false;
            }
        }
    }
    out
}

/// Whether a line may break before `c`.
fn closes(c: char) -> bool {
    "、。，．,.）)」』】〕〉》！？!?：:；;ー・…％%".contains(c)
}

/// Whether a line may break after `c`.
fn opens(c: char) -> bool {
    "（(「『【〔〈《".contains(c)
}

fn wide(c: char) -> bool {
    use unicode_width::UnicodeWidthChar as _;
    c.width() == Some(2)
}

/// `text` cut where a line may break.
fn atoms(text: &str) -> Vec<Atom<'_>> {
    let glyphs = glyphs(text);
    let mut out: Vec<Atom<'_>> = Vec::new();
    let mut i = 0;
    while i < glyphs.len() {
        let begin = glyphs[i].0;
        let c = glyphs[i].1;
        let mut j = i + 1;
        let space = c == ' ';
        if space {
            while glyphs.get(j).is_some_and(|g| g.1 == ' ') {
                j += 1;
            }
        } else if wide(c) && !opens(c) {
            // One CJK character, with the closing marks after it.
            while glyphs.get(j).is_some_and(|g| closes(g.1)) {
                j += 1;
            }
        } else {
            // A word: up to a space or a CJK character, keeping opening
            // marks with what follows and closing marks with what precedes.
            while let Some(g) = glyphs.get(j) {
                let prev = glyphs[j - 1].1;
                if g.1 == ' ' || (wide(g.1) && !closes(g.1) && !opens(prev)) {
                    break;
                }
                j += 1;
            }
        }
        let end = glyphs.get(j).map_or(text.len(), |g| g.0);
        let width = glyphs[i..j].iter().map(|g| g.2).sum();
        out.push(Atom {
            text: &text[begin..end],
            width,
            space,
        });
        i = j;
    }
    out
}

/// clap's words, and the catalog lookups for a command's help.
struct Words {
    lang: Lang,
    usage: String,
    options: String,
    arguments: String,
    commands: String,
    help: String,
    version: String,
    help_command: String,
}

impl Words {
    fn new(lang: Lang) -> Self {
        let word = |key: &str| CATALOG.text(lang, key, &[]);
        Self {
            lang,
            usage: word("clap.usage"),
            options: word("clap.options"),
            arguments: word("clap.arguments"),
            commands: word("clap.commands"),
            help: word("clap.help"),
            version: word("clap.version"),
            help_command: word("clap.help_command"),
        }
    }

    /// The translation of `key` in the help catalog of the top command
    /// `path` is under, or of the shared `cli` catalog.
    fn lookup(&self, path: &[&str], key: &str) -> Option<String> {
        path.first()
            .and_then(|top| CATALOG.get(self.lang, &format!("cli_{top}.{key}"), &[]))
            .or_else(|| CATALOG.get(self.lang, &format!("cli.{key}"), &[]))
    }

    fn apply(&self, command: &mut Command, path: &[&str]) {
        let name = path.join(" ");
        let at = |suffix: &str| {
            if name.is_empty() {
                suffix.trim_start().to_owned()
            } else {
                format!("{name}{suffix}")
            }
        };
        let header = command.get_styles().get_header();
        let template = format!(
            "{{before-help}}{{about-with-newline}}\n{header}{}{header:#} {{usage}}\n\n{{all-args}}{{after-help}}",
            self.usage
        );
        let mut c = std::mem::take(command)
            .help_template(template)
            .subcommand_help_heading(self.commands.clone());
        let about_key = if name.is_empty() {
            "erpc".to_owned()
        } else {
            name.clone()
        };
        if let Some(about) = self.lookup(path, &about_key) {
            c = c.about(about);
        }
        if let Some(long) = self.lookup(path, &format!("{about_key} @long")) {
            c = c.long_about(long);
        }
        let ids: Vec<(String, Option<String>, bool, bool)> = c
            .get_arguments()
            .map(|a| {
                (
                    a.get_id().to_string(),
                    a.get_long().map(str::to_owned),
                    a.is_positional(),
                    a.get_help_heading().is_some(),
                )
            })
            .collect();
        for (id, long, positional, headed) in ids {
            let arg_key = long
                .as_ref()
                .map_or_else(|| format!("<{id}>"), |l| format!("--{l}"));
            let translated = match id.as_str() {
                "help" => Some(self.help.clone()),
                "version" => Some(self.version.clone()),
                _ => self
                    .lookup(path, &at(&format!(" {arg_key}")))
                    .or_else(|| self.lookup(&[], &arg_key)),
            };
            let long_help = self.lookup(path, &at(&format!(" {arg_key} @long")));
            let heading = (!headed).then(|| {
                if positional {
                    self.arguments.clone()
                } else {
                    self.options.clone()
                }
            });
            c = c.mut_arg(id, |mut a| {
                if let Some(help) = translated {
                    a = a.help(help);
                }
                if let Some(long) = long_help {
                    a = a.long_help(long);
                }
                if let Some(heading) = heading {
                    a = a.help_heading(heading);
                }
                a
            });
        }
        for sub in c.get_subcommands_mut() {
            let sub_name = sub.get_name().to_owned();
            if sub_name == "help" {
                let taken = std::mem::take(sub);
                *sub = taken.about(self.help_command.clone());
                continue;
            }
            let mut deeper: Vec<&str> = path.to_vec();
            deeper.push(&sub_name);
            self.apply(sub, &deeper);
        }
        *command = c;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_core::i18n::unfilled;

    /// The top commands whose help is translated. One joins the list when
    /// its `cli_<name>.toml` is written in every language.
    const TRANSLATED: &[&str] = &["worker", "ai", "resume", "memory"];

    #[test]
    fn the_catalogs_read_and_every_language_says_everything() {
        let catalog = Catalog::parse(files(&LOCALES)).expect("the catalogs read");
        let problems = catalog.problems();
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    /// Every `t!`/`tn!` key in the source is in the English catalog, and
    /// every English key is said somewhere, so neither side drifts.
    #[test]
    fn the_source_and_the_catalogs_name_the_same_keys() {
        let mut used = std::collections::BTreeSet::new();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        collect_keys(&src, &mut used);
        let missing: Vec<&String> = used.iter().filter(|k| !CATALOG.has(k)).collect();
        assert!(missing.is_empty(), "used but not in en/: {missing:?}");
        let unused: Vec<&str> = CATALOG
            .keys()
            .filter(|k| !k.starts_with("cli") && !k.starts_with("clap.") && !used.contains(*k))
            .collect();
        assert!(unused.is_empty(), "in en/ but never used: {unused:?}");
    }

    fn collect_keys(dir: &std::path::Path, out: &mut std::collections::BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_keys(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                for marker in ["t!(", "tn!("] {
                    for (at, _) in text.match_indices(marker) {
                        let line = text[..at].rsplit('\n').next().unwrap_or_default();
                        if line.trim_start().starts_with("//") {
                            continue;
                        }
                        let before = text[..at].chars().next_back();
                        if before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '"') {
                            continue;
                        }
                        // rustfmt moves a long key to the next line.
                        let Some(rest) = text[at + marker.len()..].trim_start().strip_prefix('"')
                        else {
                            continue;
                        };
                        if let Some(end) = rest.find('"') {
                            out.insert(rest[..end].to_owned());
                        }
                    }
                }
            }
        }
    }

    /// The English help in `cli_*.toml` is clap's own, and a translated
    /// command has help for itself and each of its arguments in every
    /// language.
    #[test]
    fn translated_help_matches_the_commands() {
        let mut problems = Vec::new();
        let root = <crate::Cli as clap::CommandFactory>::command();
        for top in TRANSLATED {
            let command = root
                .find_subcommand(top)
                .expect("a translated command exists");
            check_help(command, &[top], &mut problems);
        }
        for key in CATALOG.keys().filter(|k| k.starts_with("cli_")) {
            if !TRANSLATED
                .iter()
                .any(|t| key.starts_with(&format!("cli_{t}.")))
            {
                problems.push(format!("{key}: its command is not in TRANSLATED"));
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    fn check_help(command: &Command, path: &[&str], problems: &mut Vec<String>) {
        let name = path.join(" ");
        let catalog = format!("cli_{}", path[0]);
        let mut expect = |key: String, english: Option<String>| {
            let full = format!("{catalog}.{key}");
            match (english, CATALOG.get(Lang::En, &full, &[])) {
                (Some(want), Some(got)) if want != got => {
                    problems.push(format!(
                        "{full}: English is {got:?}, the doc comment says {want:?}"
                    ));
                }
                (Some(_), None) => problems.push(format!("{full}: missing")),
                (None, Some(_)) => problems.push(format!("{full}: the command has no such help")),
                _ => {}
            }
        };
        expect(name.clone(), command.get_about().map(ToString::to_string));
        expect(
            format!("{name} @long"),
            command.get_long_about().map(ToString::to_string),
        );
        for arg in command.get_arguments() {
            let id = arg.get_id().as_str();
            if matches!(id, "help" | "version") || arg.is_global_set() {
                continue;
            }
            let key = arg
                .get_long()
                .map_or_else(|| format!("<{id}>"), |l| format!("--{l}"));
            expect(
                format!("{name} {key}"),
                arg.get_help().map(ToString::to_string),
            );
            expect(
                format!("{name} {key} @long"),
                arg.get_long_help().map(ToString::to_string),
            );
        }
        for sub in command.get_subcommands() {
            let mut deeper = path.to_vec();
            deeper.push(sub.get_name());
            check_help(sub, &deeper, problems);
        }
    }

    /// Prints the English `cli_<top>.toml` for a command, to start its
    /// catalogs from: `ERPC_HELP_DUMP=worker cargo test -p erpc
    /// dump_help -- --ignored --nocapture`.
    #[test]
    #[ignore = "a tool, not a test"]
    fn dump_help() {
        let top = std::env::var("ERPC_HELP_DUMP").expect("ERPC_HELP_DUMP names a command");
        let root = <crate::Cli as clap::CommandFactory>::command();
        let command = root.find_subcommand(&top).expect("the command exists");
        let mut out = String::new();
        dump(command, &[&top], &mut out);
        println!("{out}");
    }

    fn dump(command: &Command, path: &[&str], out: &mut String) {
        use std::fmt::Write as _;
        let name = path.join(" ");
        let mut line = |key: String, text: Option<String>| {
            if let Some(text) = text {
                let _ = writeln!(out, "{} = {}", toml_key(&key), toml_string(&text));
            }
        };
        line(name.clone(), command.get_about().map(ToString::to_string));
        line(
            format!("{name} @long"),
            command.get_long_about().map(ToString::to_string),
        );
        for arg in command.get_arguments() {
            let id = arg.get_id().as_str();
            if matches!(id, "help" | "version") || arg.is_global_set() {
                continue;
            }
            let key = arg
                .get_long()
                .map_or_else(|| format!("<{id}>"), |l| format!("--{l}"));
            line(
                format!("{name} {key}"),
                arg.get_help().map(ToString::to_string),
            );
            line(
                format!("{name} {key} @long"),
                arg.get_long_help().map(ToString::to_string),
            );
        }
        for sub in command.get_subcommands() {
            let mut deeper = path.to_vec();
            deeper.push(sub.get_name());
            dump(sub, &deeper, out);
        }
    }

    fn toml_key(key: &str) -> String {
        toml::Value::String(key.to_owned()).to_string()
    }

    fn toml_string(text: &str) -> String {
        if text.contains('\n') {
            format!(
                "\"\"\"\n{}\"\"\"",
                text.replace('\\', "\\\\").replace("\"\"\"", "\\\"\"\"")
            )
        } else {
            toml::Value::String(text.to_owned()).to_string()
        }
    }

    #[test]
    fn japanese_help_wraps_under_its_description() {
        let line = format!(
            "  --vault <VAULT>  {}",
            "鍵を保管する 1Password の保管庫（既定: セッションの保管庫）。`erpc login` が使うものと同じです。"
        );
        let wrapped = wrap(&line, 40);
        let lines: Vec<&str> = wrapped.lines().collect();
        assert!(lines.len() > 2, "{wrapped}");
        for l in &lines {
            assert!(console::measure_text_width(l) <= 40, "{l:?} in\n{wrapped}");
        }
        for l in &lines[1..] {
            assert!(
                l.starts_with(&" ".repeat(19)) && !l[19..].starts_with(' '),
                "{wrapped}"
            );
            assert!(!l.trim_start().starts_with(['、', '。', '）']), "{wrapped}");
        }
        assert!(
            wrapped.contains("`erpc login`") || wrapped.contains("`erpc\n"),
            "{wrapped}"
        );
        // What fits is left alone, colour and all.
        let short = "  \x1b[1m--json\x1b[0m  JSON を出力";
        assert_eq!(wrap(short, 40), short);
    }

    #[test]
    fn colour_takes_no_room_and_survives_a_break() {
        let line = "\x1b[1m使い方:\x1b[0m erpc worker deploy [OPTIONS] --env <ENV> --unlimited --vault <VAULT>";
        let wrapped = wrap(line, 40);
        assert!(wrapped.starts_with("\x1b[1m使い方:\x1b[0m"), "{wrapped:?}");
        for l in wrapped.lines() {
            assert!(console::measure_text_width(l) <= 40, "{l:?}");
        }
    }

    #[test]
    fn help_reads_in_the_chosen_language() {
        let command = localized(<crate::Cli as clap::CommandFactory>::command(), Lang::Ja);
        let help = command.clone().render_help().to_string();
        assert!(
            help.contains(&CATALOG.text(Lang::Ja, "clap.usage", &[])),
            "{help}"
        );
        assert!(
            help.contains(&CATALOG.text(Lang::Ja, "clap.commands", &[])),
            "{help}"
        );
        assert!(
            unfilled(&help)
                .iter()
                .all(|p| p.is_empty() || p.contains(' ')),
            "{help}"
        );
        // English is left as clap makes it.
        let mut english = localized(<crate::Cli as clap::CommandFactory>::command(), Lang::En);
        assert!(english.render_help().to_string().contains("Usage:"));
    }
}
