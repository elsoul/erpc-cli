// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Which model answers a turn, and how hard it thinks.
//!
//! Two rules pull against each other. A greeting answered by a model that
//! always thinks is slow for nothing, so the first small-talk turns of a
//! conversation go to the quick model. But the prompt cache belongs to one
//! model, and changing the effort mid-conversation throws the cached
//! history away, so once a conversation has reached the main model it
//! stays there, at one effort, for the rest of it.

use erpc_api::ai::{DEFAULT_MODEL, Effort, QUICK_MODEL};

/// What a turn is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnPolicy {
    /// The model.
    pub model: &'static str,
    /// Whether to think before answering.
    pub thinking: bool,
    /// How hard to think, when thinking.
    pub effort: Effort,
    /// The longest answer, thinking included, in tokens.
    pub max_tokens: u32,
}

/// The one effort a conversation on the main model runs at, set
/// explicitly so it does not move if the service's default does.
pub const CONVERSATION_EFFORT: Effort = Effort::Medium;

/// Greetings and thanks, in the languages the console is used in.
const SMALL_TALK: &[&str] = &[
    "hi",
    "hello",
    "hey",
    "hey there",
    "good morning",
    "good evening",
    "how are you",
    "thanks",
    "thank you",
    "bye",
    "goodbye",
    "こんにちは",
    "こんばんは",
    "おはよう",
    "おはようございます",
    "ありがとう",
    "ありがとうございます",
    "どうも",
    "元気ですか",
    "お疲れさま",
    "お疲れさまです",
    "やあ",
    "はじめまして",
    "你好",
    "您好",
    "谢谢",
    "谢谢你",
    "早上好",
    "晚上好",
    "再见",
    "привет",
    "здравствуйте",
    "спасибо",
    "добрый день",
    "доброе утро",
    "добрый вечер",
    "пока",
    "xin chào",
    "cảm ơn",
];

/// Words that mean a change to a node, where a mistake costs something.
const OPERATIONAL: &[&str] = &[
    "deploy",
    "migrat",
    "restart",
    "firewall",
    "nftables",
    "wireguard",
    "validator",
    "mainnet",
    "identity",
    "double vot",
    "デプロイ",
    "移行",
    "再起動",
    "ファイアウォール",
    "バリデータ",
    "鍵",
    "二重投票",
    "本番",
    "部署",
    "迁移",
    "重启",
    "防火墙",
    "验证",
    "密钥",
    "主网",
    "развер",
    "миграц",
    "перезапус",
    "файрвол",
    "валидатор",
    "ключ",
    "мейннет",
];

/// Short answers that continue the previous turn.
const CONTINUATION: &[&str] = &[
    "yes",
    "no",
    "ok",
    "okay",
    "continue",
    "go ahead",
    "はい",
    "いいえ",
    "続けて",
    "お願いします",
    "それで",
    "そのまま",
    "好的",
    "是的",
    "继续",
    "可以",
    "да",
    "нет",
    "ок",
    "продолжай",
    "давай",
];

/// Whether `text` answers the previous turn: "yes", "続けて", "2".
fn continues(text: &str) -> bool {
    let lower = text.trim().to_lowercase();
    lower.chars().count() <= 160
        && (CONTINUATION.iter().any(|w| lower.starts_with(w))
            || (!lower.is_empty() && lower.chars().all(|c| c.is_ascii_digit())))
}

/// Whether `text` is only a greeting or a thank-you.
#[must_use]
pub fn is_small_talk(text: &str) -> bool {
    let trimmed = text
        .trim()
        .trim_end_matches(|c: char| c.is_whitespace() || "!！?？.。,、…~〜👋😊🙏".contains(c))
        .to_lowercase();
    SMALL_TALK.contains(&trimmed.as_str())
}

/// Whether `text` is short enough that thinking about it is wasted: a word
/// or two that is not about an operation.
fn is_trivial(text: &str) -> bool {
    let lower = text.trim().to_lowercase();
    lower.chars().count() <= 12
        && !lower.contains('\n')
        && !OPERATIONAL.iter().any(|w| lower.contains(w))
}

/// The policy for a message. `settled` says the conversation has already
/// reached the main model.
#[must_use]
pub fn policy(text: &str, settled: bool) -> TurnPolicy {
    let quick = is_small_talk(text) || (is_trivial(text) && !continues(text));
    if quick && !settled {
        // The small model thinks too, at medium unless told otherwise, and
        // its thinking counts against the limit: low effort keeps a
        // greeting quick, and the limit leaves room for the thought.
        TurnPolicy {
            model: QUICK_MODEL,
            thinking: true,
            effort: Effort::Low,
            max_tokens: 4096,
        }
    } else {
        TurnPolicy {
            model: DEFAULT_MODEL,
            thinking: true,
            effort: CONVERSATION_EFFORT,
            max_tokens: 16_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CONVERSATION_EFFORT, is_small_talk, policy};
    use erpc_api::ai::{DEFAULT_MODEL, QUICK_MODEL};

    #[test]
    fn small_talk_before_the_conversation_settles_is_quick() {
        for text in [
            "こんにちは",
            "Hello!",
            "  ありがとうございます。 ",
            "thanks 🙏",
            "谢谢！",
            "Спасибо!",
            "yo",
            "test",
        ] {
            let p = policy(text, false);
            assert_eq!(p.model, QUICK_MODEL, "{text}");
            assert_eq!(p.effort, erpc_api::ai::Effort::Low, "{text}");
        }
        assert!(!is_small_talk("こんにちは、バリデータを立てたい"));
    }

    #[test]
    fn once_settled_everything_stays_on_one_model_at_one_effort() {
        for text in ["hi", "restart the validator", "はい", &"x".repeat(400)] {
            let p = policy(text, true);
            assert_eq!(p.model, DEFAULT_MODEL, "{text}");
            assert_eq!(p.effort, CONVERSATION_EFFORT, "{text}");
        }
    }

    #[test]
    fn real_questions_go_to_the_main_model() {
        for text in [
            "restart",
            "testnet にバリデータをデプロイしたい",
            "erpc login のやり方は？",
            "重启验证节点",
            "перезапусти",
            "继续",
            "да",
        ] {
            assert_eq!(policy(text, false).model, DEFAULT_MODEL, "{text}");
        }
    }
}
