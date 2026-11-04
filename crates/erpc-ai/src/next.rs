// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Guessing what the user will say next.
//!
//! After an answer the front end may show, in the empty box, the message
//! the user is likely to send next, for them to take with Tab. The guess
//! comes from one small request to the small model, shown only the last
//! [`TURNS`] turns' words, never their tool calls or results. It is only
//! ever a suggestion: nothing is sent until the user sends it, and a tool
//! that changes the account still asks first.

use core::fmt::Write as _;

use erpc_api::ai::{ChatRequest, Effort};
use erpc_auth::AuthClient;
use secrecy::SecretString;
use serde_json::{Value, json};

/// The last turns the guess is made from.
const TURNS: usize = 2;
/// The most of one message the model is shown, from its end, in
/// characters: the end of an answer is where it asks or offers.
const MAX_PIECE: usize = 1500;
/// The longest guess shown, in characters; a longer one is not a message
/// someone types.
const MAX_GUESS: usize = 120;
/// What the model says when it has no guess, and how it says so in
/// Japanese when it forgets.
const NONE: [&str; 3] = ["NONE", "なし", "無し"];

/// What the model is told.
const INSTRUCTIONS: &str = "Below is the end of a conversation between a user and the ERPC \
     assistant in erpc, a command-line tool for ERPC's Solana RPC, nodes, servers and account. \
     Predict the message the user is most likely to send next, written as they would type it: \
     in the user's language, on one line, short (at most about 15 words). If the assistant asked \
     the user something or offered next steps, the likely reply to that. Never include \
     passwords, private keys, seed phrases, API keys or tokens. If there is no clear likely next \
     message, reply with exactly NONE. Reply with the message alone: no quotes, no \
     explanation.";

/// A guess to fetch, holding all it needs, so it runs apart from the
/// session and can be dropped at any time.
pub struct NextMessage {
    pub(crate) client: AuthClient,
    pub(crate) token: SecretString,
    pub(crate) model: &'static str,
    pub(crate) prompt: String,
}

impl NextMessage {
    /// The guess, or none when the model had none, refused, or failed.
    pub async fn fetch(self) -> Option<String> {
        let system = vec!["You predict the next message a user types.".to_owned()];
        let messages = vec![json!({ "role": "user", "content": self.prompt })];
        let request = ChatRequest {
            system: &system,
            messages: &messages,
            model: self.model,
            max_tokens: 100,
            effort: Effort::Low,
            thinking: false,
            tools: &[],
        };
        let mut quiet = |_: &str| {};
        let answer = erpc_api::ai::chat(&self.client, &self.token, &request, &mut quiet)
            .await
            .ok()?;
        if answer.stop_reason.as_deref() != Some("end_turn") {
            return None;
        }
        clean(&answer.text)
    }
}

/// What the model is asked, from `history`: the words of the last
/// [`TURNS`] turns. `None` when no turn has been answered.
#[must_use]
pub fn prompt(history: &[Value]) -> Option<String> {
    let starts: Vec<usize> = history
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            m.get("role").and_then(Value::as_str) == Some("user")
                && m.get("content").is_some_and(Value::is_string)
        })
        .map(|(i, _)| i)
        .collect();
    let from = *starts.get(starts.len().saturating_sub(TURNS))?;
    let mut out = String::new();
    for message in &history[from..] {
        let role = message.get("role").and_then(Value::as_str).unwrap_or("?");
        let text = match message.get("content") {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Array(blocks)) => blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(""),
            _ => continue,
        };
        let text = text.trim();
        if text.is_empty() || text.starts_with(crate::compact::SUMMARY_PREFIX) {
            continue;
        }
        let _ = write!(out, "{role}: {}\n\n", tail(text));
    }
    // The last word must be the assistant's, or there is nothing to reply
    // to yet.
    let last = history.last()?;
    if last.get("role").and_then(Value::as_str) != Some("assistant") || out.is_empty() {
        return None;
    }
    Some(format!(
        "{INSTRUCTIONS}\n\n<conversation>\n{out}</conversation>"
    ))
}

/// The end of `text`, at most [`MAX_PIECE`] characters.
fn tail(text: &str) -> String {
    let count = text.chars().count();
    if count > MAX_PIECE {
        let end: String = text.chars().skip(count - MAX_PIECE).collect();
        format!("…{end}")
    } else {
        text.to_owned()
    }
}

/// The guess as it is shown: its first line, without quotes or a speaker;
/// none when the model had none or wrote something no one types.
#[must_use]
pub fn clean(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    let line = line
        .strip_prefix("user:")
        .or_else(|| line.strip_prefix("User:"))
        .unwrap_or(line)
        .trim();
    let line = line
        .trim_matches(|c| matches!(c, '"' | '\'' | '「' | '」' | '“' | '”' | '`'))
        .trim();
    let bare = line.trim_end_matches(['.', '。']);
    // A command would run on Enter rather than be asked; text that hides
    // or reorders characters may send other than what was seen.
    if line.is_empty()
        || NONE.iter().any(|none| bare.eq_ignore_ascii_case(none))
        || line.starts_with('/')
        || line.chars().count() > MAX_GUESS
        || line.chars().any(|c| c.is_control() || hidden(c))
    {
        return None;
    }
    Some(line.to_owned())
}

/// Whether `c` takes no room, breaks the line, or reorders the text
/// around it.
const fn hidden(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{clean, prompt};

    #[test]
    fn a_guess_is_one_plain_line_or_none() {
        assert_eq!(
            clean("「Developer を止めて」\n"),
            Some("Developer を止めて".to_owned())
        );
        assert_eq!(clean("user: stop it\nbecause…"), Some("stop it".to_owned()));
        assert_eq!(clean("NONE"), None);
        assert_eq!(clean("none."), None);
        assert_eq!(clean("なし。"), None);
        assert_eq!(clean("/clear"), None, "a command would run on Enter");
        assert_eq!(clean("stop\u{202E}it"), None, "reorders the text");
        assert_eq!(clean("yes\u{200B}"), None, "hides a character");
        assert_eq!(clean("  \n"), None);
        assert_eq!(clean(&"x".repeat(200)), None);
    }

    #[test]
    fn the_prompt_has_the_last_turns_words_and_nothing_of_the_tools() {
        let history = vec![
            json!({ "role": "user", "content": "first question" }),
            json!({ "role": "assistant", "content": [{ "type": "text", "text": "first answer" }] }),
            json!({ "role": "user", "content": "balance?" }),
            json!({ "role": "assistant", "content": [
                { "type": "thinking", "thinking": "secret reasoning", "signature": "s" },
                { "type": "tool_use", "id": "t1", "name": "credit_balance", "input": {} },
            ] }),
            json!({ "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "t1", "content": "{\"balance\":886}" },
            ] }),
            json!({ "role": "assistant", "content": [{ "type": "text", "text": "€8.86. Buy more?" }] }),
            json!({ "role": "user", "content": "start the Developer plan" }),
            json!({ "role": "assistant", "content": [{ "type": "text", "text": "Started." }] }),
        ];
        let text = prompt(&history).expect("a prompt");
        assert!(!text.contains("first question"), "only the last two turns");
        assert!(text.contains("user: balance?"));
        assert!(text.contains("assistant: €8.86. Buy more?"));
        assert!(text.contains("assistant: Started."));
        assert!(!text.contains("secret reasoning"));
        assert!(!text.contains("credit_balance"));
        assert!(!text.contains("886}"));
    }

    #[test]
    fn no_prompt_before_an_answer() {
        assert!(prompt(&[]).is_none());
        assert!(prompt(&[json!({ "role": "user", "content": "hi" })]).is_none());
    }

    #[test]
    fn a_long_answer_is_shown_by_its_end() {
        let long = format!("{}Shall I stop it?", "x".repeat(5000));
        let history = vec![
            json!({ "role": "user", "content": "hi" }),
            json!({ "role": "assistant", "content": long }),
        ];
        let text = prompt(&history).expect("a prompt");
        assert!(text.contains("Shall I stop it?"));
        assert!(text.len() < 3000);
    }
}
