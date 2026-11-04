// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Asking the operator to pick one of a few options at a terminal: arrow
//! keys to move, Enter to choose, Esc to cancel. Drawn with cliclack, on
//! stderr, so that stdout stays the command's result; colours follow the
//! terminal and `NO_COLOR`.
//!
//! Callers ask only when a person is there to answer. A command run from a
//! script never waits on a question.

use std::io::ErrorKind;

/// Asks `question` with `options` listed below it, and returns the index
/// of the one chosen. The cursor starts on `default`, or on the first
/// option without one.
///
/// # Errors
///
/// Returns a message when the terminal cannot be used, or when the
/// operator presses Esc instead of choosing.
pub fn pick(question: &str, options: &[String], default: Option<usize>) -> Result<usize, String> {
    let options: Vec<(&str, &str)> = options.iter().map(|o| (o.as_str(), "")).collect();
    pick_described(question, &options, default)
}

/// As [`pick`], each option a label and a short description drawn beside
/// it, dimmed.
///
/// # Errors
///
/// As [`pick`].
pub fn pick_described(
    question: &str,
    options: &[(&str, &str)],
    default: Option<usize>,
) -> Result<usize, String> {
    let mut select = cliclack::select(question);
    for (i, (label, about)) in options.iter().enumerate() {
        select = select.item(i, label, about);
    }
    select
        .initial_value(default.unwrap_or(0))
        .interact()
        .map_err(|e| match e.kind() {
            ErrorKind::Interrupted => "nothing was chosen".to_owned(),
            _ => format!("could not ask: {e}"),
        })
}

// What follows draws an exchange at a terminal, in the picker's style:
// a heading, steps, a box, a closing line. Only ever drawn for a person at
// a terminal; a line that cannot be drawn has nothing to report.

/// The heading an exchange hangs from.
pub fn intro(title: &str) {
    let _ = cliclack::intro(console::style(format!(" {title} ")).on_cyan().black());
}

/// The closing line of an exchange that did what it set out to.
pub fn outro(message: &str) {
    let _ = cliclack::outro(message);
}

/// The closing line of an exchange that stopped short.
pub fn outro_cancel(message: &str) {
    let _ = cliclack::outro_cancel(message);
}

/// A line of information.
pub fn info(message: &str) {
    let _ = cliclack::log::info(message);
}

/// A line to heed.
pub fn warning(message: &str) {
    let _ = cliclack::log::warning(wrapped(message));
}

/// `text` broken at spaces to fit the terminal, past cliclack's gutter.
fn wrapped(text: &str) -> String {
    let width = usize::from(console::Term::stderr().size().1)
        .saturating_sub(4)
        .max(40);
    let mut out = String::new();
    let mut line = 0;
    for word in text.split(' ') {
        let w = console::measure_text_width(word);
        if line > 0 && line + 1 + w > width {
            out.push('\n');
            line = 0;
        } else if line > 0 {
            out.push(' ');
            line += 1;
        }
        out.push_str(word);
        line += w;
    }
    out
}

/// A titled box of lines, such as the commands to run next.
pub fn note(title: &str, body: &str) {
    let _ = cliclack::note(title, body);
}

/// A spinner for a step under way, stopped with what the step did.
pub struct Spinner(cliclack::ProgressBar);

impl Spinner {
    pub fn start(message: &str) -> Self {
        let spinner = cliclack::spinner();
        spinner.start(message);
        Self(spinner)
    }

    // The spinner is cleared and the line written as a log line: a stopped
    // spinner's line is padded to the width the terminal reports, which
    // pushes the gutter after it out of place where that is not the width
    // the text has.
    pub fn stop(self, message: &str) {
        self.0.clear();
        let _ = cliclack::log::step(message);
    }

    pub fn error(self, message: &str) {
        self.0.clear();
        let _ = cliclack::log::error(message);
    }
}
