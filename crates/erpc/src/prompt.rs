// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Asking the operator to pick one of a few options at a terminal: arrow
//! keys to move, Enter to choose.
//!
//! Callers ask only when a person is there to answer. A command run from a
//! script never waits on a question.

use dialoguer::Select;
use dialoguer::console::Term;

/// Asks `question` with `options` listed below it, and returns the index
/// of the one chosen. The cursor starts on `default`, or on the first
/// option without one.
///
/// Drawn on stderr, so that stdout stays the command's result.
///
/// # Errors
///
/// Returns a message when the terminal cannot be used, or when the
/// operator presses Esc or q instead of choosing.
pub fn pick(question: &str, options: &[String], default: Option<usize>) -> Result<usize, String> {
    Select::new()
        .with_prompt(question)
        .items(options)
        .default(default.unwrap_or(0))
        .report(true)
        .interact_on_opt(&Term::stderr())
        .map_err(|e| format!("could not ask: {e}"))?
        .ok_or_else(|| "nothing was chosen".to_owned())
}
