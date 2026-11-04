// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Keeping a long conversation short.
//!
//! Every turn sends the whole conversation, so a long one costs more with
//! each question and at last no longer fits. Past [`COMPACT_AT`] the older
//! turns are summarised by the small model, and the conversation goes on
//! from that summary and the last [`KEEP_TURNS`] turns word for word. The
//! turns summarised are not lost: the front end keeps them on disk.
//!
//! A conversation that is one long turn has no earlier turns to summarise,
//! and a summary can fail; either way the older tool results are cut short
//! in place ([`shrink`]), and a failed summary is not tried again until the
//! conversation has grown by [`RETRY_AFTER`].

use core::fmt::Write as _;

use serde_json::{Value, json};

/// The conversation's size, in bytes of JSON, past which it is compacted:
/// some 40,000 tokens.
pub const COMPACT_AT: usize = 160_000;
/// The last turns kept as they were.
pub const KEEP_TURNS: usize = 2;
/// How much a conversation grows, in bytes of JSON, before a summary that
/// failed is tried again.
pub const RETRY_AFTER: usize = COMPACT_AT / 4;
/// The last tool results [`shrink`] leaves whole.
const KEEP_RESULTS: usize = 4;
/// How the summary starts, so it reads as erpc's and not the user's.
pub const SUMMARY_PREFIX: &str =
    "[erpc: a summary of the conversation so far, made to keep it short]";
/// The most of one tool result or tool input the summariser is shown.
const MAX_PIECE: usize = 600;

/// What the summariser is told.
pub const INSTRUCTIONS: &str = "Summarise this conversation between a user and the ERPC \
     assistant in erpc, so the assistant can carry on from the summary alone. Keep what is still \
     useful: what the user wants and decided, names and ids (hosts, VPS ids, regions, products, \
     networks), figures that were looked up and when, what was started, ended, bought or \
     changed, and what is still open. Drop greetings and anything settled and no longer \
     relevant. Never include passwords, private keys, seed phrases, API keys or tokens. Write \
     in the user's language, as short bullet points, at most 300 words.";

/// The size of `history`, in bytes of JSON: counted as it is written out,
/// with nothing kept.
#[must_use]
pub fn size(history: &[Value]) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, history).map_or(0, |()| count.0)
}

/// Whether `history` is long enough to compact, and past `not_before`,
/// the size a failed attempt said to wait for.
#[must_use]
pub fn due(history: &[Value], not_before: usize) -> bool {
    size(history) > COMPACT_AT.max(not_before)
}

/// Cuts every tool result but the last [`KEEP_RESULTS`] down to its start,
/// in place. The tool calls and their pairing stay as they were. Whether
/// anything was cut.
pub fn shrink(history: &mut [Value]) -> bool {
    let mut results: Vec<&mut Value> = history
        .iter_mut()
        .filter_map(|m| m.get_mut("content").and_then(Value::as_array_mut))
        .flatten()
        .filter(|b| b.get("type").and_then(Value::as_str) == Some("tool_result"))
        .collect();
    let older = results.len().saturating_sub(KEEP_RESULTS);
    let mut cut = false;
    for block in results.iter_mut().take(older) {
        let text = match block.get("content") {
            Some(Value::String(text)) => text.clone(),
            Some(other) => other.to_string(),
            None => continue,
        };
        if text.chars().count() > MAX_PIECE * 2 {
            block["content"] = Value::String(format!(
                "{} [erpc: cut short to keep the conversation short]",
                short(&text)
            ));
            cut = true;
        }
    }
    cut
}

/// Where the turns kept start: the user's question [`KEEP_TURNS`] turns
/// from the end. `None` when there is nothing before it to summarise.
#[must_use]
pub fn cut(history: &[Value]) -> Option<usize> {
    let starts: Vec<usize> = history
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            m.get("role").and_then(Value::as_str) == Some("user")
                && m.get("content").is_some_and(Value::is_string)
        })
        .map(|(i, _)| i)
        .collect();
    let at = *starts.get(starts.len().checked_sub(KEEP_TURNS)?)?;
    (at > 0).then_some(at)
}

fn short(text: &str) -> String {
    if text.chars().count() > MAX_PIECE {
        let cut: String = text.chars().take(MAX_PIECE).collect();
        format!("{cut}…")
    } else {
        text.to_owned()
    }
}

/// The turns as text for the summariser: what was said, which tools ran
/// with what, and the start of what they returned. Thinking is left out.
#[must_use]
pub fn transcript(messages: &[Value]) -> String {
    let mut out = String::new();
    for message in messages {
        let role = message.get("role").and_then(Value::as_str).unwrap_or("?");
        match message.get("content") {
            Some(Value::String(text)) => {
                let _ = writeln!(out, "{role}: {text}\n");
            }
            Some(Value::Array(blocks)) => {
                for block in blocks {
                    match block.get("type").and_then(Value::as_str) {
                        Some("text") => {
                            let text = block.get("text").and_then(Value::as_str).unwrap_or("");
                            let _ = writeln!(out, "{role}: {text}\n");
                        }
                        Some("tool_use") => {
                            let name = block.get("name").and_then(Value::as_str).unwrap_or("?");
                            let input =
                                block.get("input").map(Value::to_string).unwrap_or_default();
                            let _ = writeln!(out, "(tool {name} {})\n", short(&input));
                        }
                        Some("tool_result") => {
                            let content = match block.get("content") {
                                Some(Value::String(text)) => text.clone(),
                                Some(other) => other.to_string(),
                                None => String::new(),
                            };
                            let _ = writeln!(out, "(result {})\n", short(&content));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// The conversation from here on: the summary, an acknowledgement so the
/// turns still alternate, then the turns kept.
#[must_use]
pub fn rebuilt(summary: &str, kept: &[Value]) -> Vec<Value> {
    let mut out = vec![
        json!({ "role": "user", "content": format!("{SUMMARY_PREFIX}\n{}", summary.trim()) }),
        json!({ "role": "assistant", "content": [{ "type": "text", "text": "Understood; I will carry on from this summary." }] }),
    ];
    out.extend_from_slice(kept);
    out
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{KEEP_TURNS, SUMMARY_PREFIX, cut, due, rebuilt, shrink, transcript};

    fn turn(question: &str, with_tool: bool) -> Vec<Value> {
        let mut out = vec![json!({ "role": "user", "content": question })];
        if with_tool {
            out.push(json!({ "role": "assistant", "content": [
                { "type": "thinking", "thinking": "secret reasoning", "signature": "s" },
                { "type": "tool_use", "id": "t1", "name": "credit_balance", "input": {} },
            ] }));
            out.push(json!({ "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "t1", "content": "{\"balance\":1207}" },
            ] }));
        }
        out.push(json!({ "role": "assistant", "content": [{ "type": "text", "text": format!("answer to {question}") }] }));
        out
    }

    #[test]
    fn the_last_turns_are_kept_whole_with_their_tool_calls() {
        let history: Vec<Value> = [
            turn("one", false),
            turn("two", true),
            turn("three", true),
            turn("four", false),
        ]
        .concat();
        let at = cut(&history).expect("something to summarise");
        assert_eq!(history[at]["content"], "three");
        let kept = &history[at..];
        let starts = kept.iter().filter(|m| m["content"].is_string()).count();
        assert_eq!(starts, KEEP_TURNS);
        let next = rebuilt("- the balance was €12.07", kept);
        assert!(
            next[0]["content"]
                .as_str()
                .is_some_and(|s| s.starts_with(SUMMARY_PREFIX))
        );
        for (i, message) in next.iter().enumerate() {
            let want = if i % 2 == 0 { "user" } else { "assistant" };
            assert_eq!(message["role"], want, "turns alternate at {i}");
        }
        assert!(
            cut(&turn("only", true)).is_none(),
            "nothing before the kept turns"
        );
    }

    #[test]
    fn the_transcript_has_what_was_said_and_done_but_no_thinking() {
        let text = transcript(&turn("balance?", true));
        assert!(text.contains("user: balance?"));
        assert!(text.contains("(tool credit_balance {})"));
        assert!(text.contains("(result {\"balance\":1207})"));
        assert!(!text.contains("secret reasoning"));
    }

    #[test]
    fn only_a_long_conversation_is_due() {
        assert!(!due(&turn("short", true), 0));
        let long = vec![json!({ "role": "user", "content": "x".repeat(super::COMPACT_AT) })];
        assert!(due(&long, 0));
        assert!(
            !due(&long, super::size(&long) + super::RETRY_AFTER),
            "not again until it grows"
        );
    }

    #[test]
    fn one_long_turn_has_its_older_tool_results_cut_short() {
        let big = "y".repeat(5000);
        let mut history = vec![json!({ "role": "user", "content": "do it all" })];
        for i in 0..6 {
            history.push(json!({ "role": "assistant", "content": [
                { "type": "tool_use", "id": format!("t{i}"), "name": "my_services", "input": {} },
            ] }));
            history.push(json!({ "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": format!("t{i}"), "content": big },
            ] }));
        }
        assert!(cut(&history).is_none(), "no earlier turn to summarise");
        assert!(shrink(&mut history));
        let lengths: Vec<usize> = history
            .iter()
            .filter_map(|m| m["content"].as_array())
            .flatten()
            .filter(|b| b["type"] == "tool_result")
            .map(|b| b["content"].as_str().map_or(0, str::len))
            .collect();
        assert!(lengths[..2].iter().all(|&n| n < 1000), "{lengths:?}");
        assert!(
            lengths[2..].iter().all(|&n| n == 5000),
            "the last four stay whole"
        );
        assert_eq!(
            history[2]["content"][0]["tool_use_id"], "t0",
            "pairing kept"
        );
        assert!(!shrink(&mut history), "nothing more to cut");
    }
}
