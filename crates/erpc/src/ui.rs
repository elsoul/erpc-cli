// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! How a command's result looks. At a terminal each line says what it is
//! with a mark in front (✅ done, ⚠️ to heed, 💡 a hint), details hang
//! under the line they belong to, and the commands to run next are listed
//! under 👉. Colours follow the terminal and `NO_COLOR`.
//!
//! Off a terminal (a pipe, a file, a script) the plain lines are written as
//! they always were, `warning:`, `hint:` and `Next:` included: they are what
//! logs and scripts read. `--json` does not come here at all.

use console::{Style, Term};

/// ERPC Blue, for what the eye should find first: help headings and the
/// commands to run next. The mark's blue ([`crate::tui::mark`]) starts at
/// `#2563EB`; this is a step lighter, so it reads on dark and light
/// backgrounds alike.
const ERPC_BLUE: [u8; 3] = [0x3B, 0x82, 0xF6];

/// ERPC Blue as this terminal takes it: RGB where `COLORTERM` says the
/// terminal has it, else the nearest of the 256 colours every terminal has.
fn blue_code() -> BlueCode {
    let [r, g, b] = ERPC_BLUE;
    if crate::tui::Look::detect().truecolor {
        BlueCode::Rgb(r, g, b)
    } else {
        BlueCode::Indexed(crate::tui::mark::nearest_256(r, g, b))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlueCode {
    Rgb(u8, u8, u8),
    Indexed(u8),
}

/// Text in ERPC Blue.
pub(crate) fn blue() -> Style {
    match blue_code() {
        BlueCode::Rgb(r, g, b) => Style::new().true_color(r, g, b),
        BlueCode::Indexed(n) => Style::new().color256(n),
    }
}

/// How clap draws help: the section headings and `Usage:` in ERPC Blue,
/// names of commands and flags bold, and the notes after a description
/// (`[env: …]`, `[possible values: …]`, `[alias: …]`) dimmed. In clap's
/// error messages `error:` and the values keep clap's own colours; their
/// `Usage:` line is blue too, as it takes the same style. Whether any of it
/// is drawn is decided where the help is printed: by clap for the help it
/// prints, and by [`help_coloured`] for help erpc prints itself.
pub(crate) fn help_styles() -> clap::builder::Styles {
    use clap::builder::styling::{Ansi256Color, Color, RgbColor, Style, Styles};
    let blue = match blue_code() {
        BlueCode::Rgb(r, g, b) => Color::Rgb(RgbColor(r, g, b)),
        BlueCode::Indexed(n) => Color::Ansi256(Ansi256Color(n)),
    };
    let heading = Style::new().fg_color(Some(blue)).bold();
    let note = Style::new().dimmed();
    Styles::styled()
        .header(heading)
        .usage(heading)
        .context(note)
        .context_value(note)
}

/// Help clap rendered, for standard output: drawn in its styles when
/// [`help_coloured`] says so, else plain.
pub(crate) fn help_text(help: &clap::builder::StyledStr) -> String {
    if help_coloured(false) {
        help.ansi().to_string()
    } else {
        help.to_string()
    }
}

/// Whether help erpc prints itself, rather than through clap, is drawn in
/// colour on standard error (`stderr`) or standard output: the help of a
/// role with no verb, and help that i18n wraps itself. The answer is
/// `console`'s, the one the colours of a [`Report`] follow: a terminal
/// that is not `dumb`, no `NO_COLOR` (`console` counts an empty one too)
/// and `CLICOLOR` not `0`, or `CLICOLOR_FORCE` set; on Windows, a console
/// that escape sequences can be turned on in. A `NO_COLOR` that is set and
/// not empty turns colour off even under `CLICOLOR_FORCE`, as it does for
/// the help clap prints.
pub(crate) fn help_coloured(stderr: bool) -> bool {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let enabled = if stderr {
        console::colors_enabled_stderr()
    } else {
        console::colors_enabled()
    };
    enabled && !no_color
}

/// Whether standard output is a terminal a person reads.
pub(crate) fn stdout_drawn() -> bool {
    drawn(&Term::stdout())
}

/// Whether standard error is a terminal a person reads.
pub(crate) fn stderr_drawn() -> bool {
    drawn(&Term::stderr())
}

fn drawn(term: &Term) -> bool {
    #[cfg(test)]
    if let Some(forced) = FORCED.with(std::cell::Cell::get) {
        return forced;
    }
    term.is_term() && std::env::var_os("TERM").is_none_or(|t| t != "dumb")
}

#[cfg(test)]
thread_local! {
    static FORCED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// In a test: whether this thread's output counts as drawn, whatever its
/// descriptors are (`cargo test` from a terminal leaves stdout a TTY).
#[cfg(test)]
pub(crate) fn force_drawn(drawn: bool) {
    FORCED.with(|f| f.set(Some(drawn)));
}

/// One line of a [`Report`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    /// What was done.
    Done(String),
    /// A line with a mark of its own (🔑, 👋), plain text off a terminal.
    Marked(&'static str, String),
    /// Something to know.
    Info(String),
    /// Something to heed.
    Warning(String),
    /// What to do about it.
    Hint(String),
    /// A detail under the line before.
    Detail(String),
    /// A name and its value, aligned with the others in a row of them.
    Field(String, String),
    /// The commands to run next.
    Next(Vec<String>),
}

/// A command's result, built line by line and rendered once, for a terminal
/// or as plain lines.
#[derive(Debug, Clone, Default)]
pub(crate) struct Report {
    lines: Vec<Line>,
}

impl Report {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// What was done: ✅ at a terminal.
    pub(crate) fn done(mut self, text: impl Into<String>) -> Self {
        self.lines.push(Line::Done(text.into()));
        self
    }

    /// A line with its own mark at a terminal, such as 🔑.
    pub(crate) fn marked(mut self, mark: &'static str, text: impl Into<String>) -> Self {
        self.lines.push(Line::Marked(mark, text.into()));
        self
    }

    /// Something to know: ℹ️ at a terminal.
    pub(crate) fn info(mut self, text: impl Into<String>) -> Self {
        self.lines.push(Line::Info(text.into()));
        self
    }

    /// Something to heed: ⚠️ at a terminal, `warning:` off one.
    pub(crate) fn warning(mut self, text: impl Into<String>) -> Self {
        self.lines.push(Line::Warning(text.into()));
        self
    }

    /// What to do about it: 💡 at a terminal, `hint:` off one.
    pub(crate) fn hint(mut self, text: impl Into<String>) -> Self {
        self.lines.push(Line::Hint(text.into()));
        self
    }

    /// A detail under the line before.
    pub(crate) fn detail(mut self, text: impl Into<String>) -> Self {
        self.lines.push(Line::Detail(text.into()));
        self
    }

    /// Names and values, aligned.
    pub(crate) fn fields<K: Into<String>, V: Into<String>>(
        mut self,
        fields: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        self.lines.extend(
            fields
                .into_iter()
                .map(|(k, v)| Line::Field(k.into(), v.into())),
        );
        self
    }

    /// The commands to run next: 👉 at a terminal, `Next:` off one.
    pub(crate) fn next(mut self, steps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let steps: Vec<String> = steps.into_iter().map(Into::into).collect();
        if !steps.is_empty() {
            self.lines.push(Line::Next(steps));
        }
        self
    }

    /// Lines of another report, in turn.
    pub(crate) fn extend(mut self, other: Self) -> Self {
        self.lines.extend(other.lines);
        self
    }

    /// The report for standard output: drawn when it is a terminal.
    pub(crate) fn text(&self) -> String {
        self.render(stdout_drawn())
    }

    /// This report, drawn, when standard output is a terminal; else
    /// `plain`, the lines the command has always printed.
    pub(crate) fn or_plain(&self, plain: String) -> String {
        if stdout_drawn() {
            self.render(true)
        } else {
            plain
        }
    }

    /// The report as a terminal shows it (`drawn`) or as plain lines.
    pub(crate) fn render(&self, drawn: bool) -> String {
        let width = self
            .lines
            .iter()
            .map(|l| match l {
                Line::Field(k, _) => unicode_width::UnicodeWidthStr::width(k.as_str()),
                _ => 0,
            })
            .max()
            .unwrap_or(0);
        let mut out: Vec<String> = Vec::new();
        for line in &self.lines {
            if drawn {
                draw(line, width, &mut out);
            } else {
                plain(line, width, &mut out);
            }
        }
        out.join("\n")
    }
}

/// How far a detail is indented at a terminal: past a mark and its space.
const UNDER: &str = "   ";

fn draw(line: &Line, width: usize, out: &mut Vec<String>) {
    let bold = Style::new().bold();
    let dim = Style::new().dim();
    match line {
        Line::Done(text) => out.push(format!("✅ {}", bold.apply_to(text))),
        Line::Marked(mark, text) => out.push(format!("{mark} {}", bold.apply_to(text))),
        Line::Info(text) => out.push(format!("ℹ️  {text}")),
        Line::Warning(text) => out.push(format!("⚠️  {}", Style::new().yellow().apply_to(text))),
        Line::Hint(text) => out.push(format!("{UNDER}💡 {}", dim.apply_to(text))),
        Line::Detail(text) => out.extend(text.lines().map(|l| format!("{UNDER}{l}"))),
        Line::Field(key, value) => {
            out.push(format!("{UNDER}{}  {value}", dim.apply_to(pad(key, width))));
        }
        Line::Next(steps) => {
            out.push(format!("👉 {}", bold.apply_to("Next")));
            let blue = blue();
            out.extend(
                steps
                    .iter()
                    .map(|s| format!("{UNDER}{} {}", dim.apply_to("$"), blue.apply_to(s))),
            );
        }
    }
}

fn plain(line: &Line, width: usize, out: &mut Vec<String>) {
    match line {
        Line::Done(text) | Line::Marked(_, text) | Line::Info(text) => out.push(text.clone()),
        Line::Warning(text) => out.push(format!("warning: {text}")),
        Line::Hint(text) => out.push(format!("hint: {text}")),
        Line::Detail(text) => out.extend(text.lines().map(|l| format!("  {l}"))),
        Line::Field(key, value) => out.push(format!("  {}  {value}", pad(key, width))),
        Line::Next(steps) => {
            out.push("Next:".to_owned());
            out.extend(steps.iter().map(|s| format!("  {s}")));
        }
    }
}

fn pad(text: &str, width: usize) -> String {
    let have = unicode_width::UnicodeWidthStr::width(text);
    format!("{text}{}", " ".repeat(width.saturating_sub(have)))
}

/// A command's plain result, drawn when standard output is a terminal:
/// `mark` before its first line, ⚠️ for `warning:` lines, 💡 for `hint:`
/// lines, 👉 for a `Next:` list, details under the line they belong to, and
/// ℹ️ for any other line. Off a terminal it is `text` as it is.
pub(crate) fn decorate(text: &str, mark: &str) -> String {
    if stdout_drawn() {
        decorated(text, mark)
    } else {
        text.to_owned()
    }
}

fn decorated(text: &str, mark: &str) -> String {
    let dim = Style::new().dim();
    let mut out = Vec::new();
    let mut in_next = false;
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            out.push(format!("{mark} {}", Style::new().bold().apply_to(line)));
            continue;
        }
        if let Some(step) = line.strip_prefix("  ").filter(|_| in_next) {
            out.push(format!(
                "{UNDER}{} {}",
                dim.apply_to("$"),
                blue().apply_to(step)
            ));
            continue;
        }
        in_next = line == "Next:";
        if in_next {
            out.push(format!("👉 {}", Style::new().bold().apply_to("Next")));
        } else if let Some(rest) = line.strip_prefix("warning: ") {
            out.push(format!("⚠️  {}", Style::new().yellow().apply_to(rest)));
        } else if let Some(rest) = line.strip_prefix("hint: ") {
            out.push(format!("{UNDER}💡 {}", dim.apply_to(rest)));
        } else if line.is_empty() {
            out.push(String::new());
        } else if let Some(rest) = line.strip_prefix("  ") {
            out.push(format!("{UNDER}{}", rest.trim_start()));
        } else {
            out.push(format!("ℹ️  {line}"));
        }
    }
    out.join("\n")
}

/// `path` as short as a person needs it: relative under the current
/// directory, `~/…` under the home directory, else as it is.
pub(crate) fn tidy(path: &std::path::Path) -> String {
    if let Ok(cwd) = std::env::current_dir()
        && let Ok(rel) = path.strip_prefix(&cwd)
        && !rel.as_os_str().is_empty()
    {
        return rel.display().to_string();
    }
    if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from)
        && let Ok(rel) = path.strip_prefix(&home)
    {
        return format!("~/{}", rel.display());
    }
    path.display().to_string()
}

/// The mark for a worker's state, as its agent names it.
pub(crate) fn state_mark(state: &str) -> &'static str {
    match state {
        "running" => "🟢",
        "starting" | "waiting" => "🟡",
        "locked" => "🔒",
        "stopped" => "⚪",
        _ => "❔",
    }
}

/// A step of work under way, on standard error: dimmed with a mark at a
/// terminal, the plain line off one.
pub(crate) fn step_line(text: &str, drawn: bool) -> String {
    if drawn {
        format!(
            "{} {}",
            blue().for_stderr().apply_to("›"),
            Style::new().dim().for_stderr().apply_to(text)
        )
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        Report::new()
            .done("Trading key made for hft-bot")
            .detail("EgxoQu")
            .fields([("vault", "abc"), ("reference", "op://abc/def/keypair")])
            .warning("fund only what the bot needs")
            .hint("`erpc worker key show` shows it")
            .next(["cd hft-bot", "erpc worker check"])
    }

    #[test]
    fn off_a_terminal_the_lines_are_plain() {
        let text = sample().render(false);
        assert_eq!(
            text,
            "Trading key made for hft-bot\n  EgxoQu\n  vault      abc\n  reference  op://abc/def/keypair\n\
             warning: fund only what the bot needs\nhint: `erpc worker key show` shows it\n\
             Next:\n  cd hft-bot\n  erpc worker check"
        );
        assert!(!text.contains('✅'));
    }

    #[test]
    fn at_a_terminal_each_line_says_what_it_is() {
        let text = console::strip_ansi_codes(&sample().render(true)).into_owned();
        assert!(
            text.starts_with("✅ Trading key made for hft-bot\n   EgxoQu\n"),
            "{text}"
        );
        assert!(text.contains("⚠️  fund only what the bot needs"), "{text}");
        assert!(
            text.contains("   💡 `erpc worker key show` shows it"),
            "{text}"
        );
        assert!(
            text.contains("👉 Next\n   $ cd hft-bot\n   $ erpc worker check"),
            "{text}"
        );
        assert!(
            !text.contains("warning:") && !text.contains("hint:"),
            "{text}"
        );
    }

    #[test]
    fn a_plain_result_is_drawn_line_by_line() {
        let text = "Deployed bot release r1\n  host 203.0.113.7\nwarning: not on record\n\
                    hint: run it again\nIt is an hourly VPS.\nNext:\n  erpc worker status\n\
                    done";
        assert_eq!(
            console::strip_ansi_codes(&decorated(text, "🚀")),
            "🚀 Deployed bot release r1\n   host 203.0.113.7\n⚠️  not on record\n   💡 run it again\n\
             ℹ️  It is an hourly VPS.\n👉 Next\n   $ erpc worker status\nℹ️  done"
        );
        assert_eq!(state_mark("running"), "🟢");
        assert_eq!(state_mark("locked"), "🔒");
    }

    #[test]
    fn a_step_is_marked_only_at_a_terminal() {
        assert_eq!(step_line("installing", false), "installing");
        assert_eq!(
            console::strip_ansi_codes(&step_line("installing", true)),
            "› installing"
        );
    }
}
