// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Asking the person to pick: the model's question and options, shown as a
//! list the person moves through and picks from, one or several, instead of
//! a reply they have to type.

use serde_json::{Value, json};

use crate::confirm::{Answer, Confirm, Question};

/// The most options a question offers; more is a list to read, not pick.
const MAX_OPTIONS: usize = 8;
/// The longest question, label and line about a label, in characters.
const MAX_QUESTION: usize = 300;
const MAX_LABEL: usize = 80;
const MAX_DETAIL: usize = 160;
/// The most of an answer typed in one's own words passed on.
const MAX_SAID: usize = 500;

/// What the model is told when no one can pick: `erpc ai -m` in a script.
const NO_ONE_TO_ASK: &str = "no one can pick here (a script, or --json); ask in your reply \
                             instead, with the options as a short list";

/// What `ask_choice` takes: its properties and the required ones.
pub(crate) fn input_schema() -> (Value, Value) {
    (
        json!({
            "question": { "type": "string", "description": "What to ask, in the user's language, one short sentence." },
            "options": {
                "type": "array",
                "minItems": 2,
                "maxItems": 8,
                "items": {
                    "type": "object",
                    "properties": {
                        "label": { "type": "string", "description": "What the person picks: a few words." },
                        "description": { "type": "string", "description": "One short line about it: a price, what is free, what it means." },
                    },
                    "required": ["label"],
                    "additionalProperties": false,
                },
            },
            "multiSelect": { "type": "boolean", "description": "Whether several can be picked. Default false." },
        }),
        json!(["question", "options"]),
    )
}

/// The question in the tool's input, checked.
fn question(input: &Value) -> Result<Question, String> {
    let text = |value: &Value, max: usize, what: &str| -> Result<String, String> {
        let text = value.as_str().unwrap_or_default().trim();
        if text.is_empty() || text.chars().count() > max {
            return Err(format!("{what} must be 1 to {max} characters"));
        }
        Ok(text.to_owned())
    };
    let options = input
        .get("options")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if !(2..=MAX_OPTIONS).contains(&options.len()) {
        return Err(format!("give 2 to {MAX_OPTIONS} options"));
    }
    let options = options
        .iter()
        .map(|option| {
            let label = text(&option["label"], MAX_LABEL, "a label")?;
            // An empty one is none: models fill optional fields with "".
            let detail = match option.get("description") {
                None | Some(Value::Null) => None,
                Some(Value::String(blank)) if blank.trim().is_empty() => None,
                Some(detail) => Some(text(detail, MAX_DETAIL, "a description")?),
            };
            Ok((label, detail))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Question {
        question: text(&input["question"], MAX_QUESTION, "the question")?,
        options,
        multiple: input
            .get("multiSelect")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// Puts the question to the person and says what they picked.
///
/// # Errors
///
/// The input is not a question, or no one is there to pick.
pub(crate) async fn ask_choice(
    input: &Value,
    confirm: Option<&dyn Confirm>,
) -> Result<Value, String> {
    let question = question(input)?;
    let confirm = confirm.ok_or(NO_ONE_TO_ASK)?;
    Ok(match confirm.choose(&question).await {
        Answer::Picked(picked) => json!({
            "picked": picked
                .iter()
                .filter_map(|&i| question.options.get(i).map(|(label, _)| label.as_str()))
                .collect::<Vec<_>>(),
        }),
        Answer::Said(text) => json!({
            "picked": [],
            "answer": text.chars().take(MAX_SAID).collect::<String>(),
            "note": "None of the options fitted; this is the person's answer in their own words. \
                     Carry on with it.",
        }),
        Answer::OwnWords => json!({
            "picked": [],
            "note": "None of the options fitted; the person will answer in their own words. \
                     End your turn now without asking again, and wait for their message.",
        }),
    })
}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::pin::Pin;

    use serde_json::json;

    use super::ask_choice;
    use crate::confirm::{Answer, Confirm, Confirmation, Question};

    struct Picks(Answer);

    impl Confirm for Picks {
        fn confirm<'a>(&'a self, _: &'a Confirmation) -> Pin<Box<dyn Future<Output = bool> + 'a>> {
            Box::pin(async { false })
        }

        fn choose<'a>(&'a self, _: &'a Question) -> Pin<Box<dyn Future<Output = Answer> + 'a>> {
            let answer = self.0.clone();
            Box::pin(async move { answer })
        }
    }

    fn input() -> serde_json::Value {
        json!({
            "question": "Which region?",
            "options": [
                { "label": "tokyo", "description": "4 free" },
                { "label": "frankfurt" },
                { "label": "amsterdam" },
            ],
            "multiSelect": true,
        })
    }

    #[test]
    fn an_empty_description_is_none() {
        let mut input = input();
        input["options"][1]["description"] = json!("");
        let question = super::question(&input).expect("asked");
        assert_eq!(question.options[1], ("frankfurt".to_owned(), None));
    }

    #[tokio::test]
    async fn the_labels_picked_go_back_in_order() {
        let picks = Picks(Answer::Picked(vec![2, 0]));
        let answer = ask_choice(&input(), Some(&picks)).await.expect("asked");
        assert_eq!(answer["picked"], json!(["amsterdam", "tokyo"]));
    }

    #[tokio::test]
    async fn own_words_tell_the_model_to_wait() {
        let picks = Picks(Answer::OwnWords);
        let answer = ask_choice(&input(), Some(&picks)).await.expect("asked");
        assert_eq!(answer["picked"], json!([]));
        assert!(answer["note"].as_str().is_some_and(|n| n.contains("wait")));
    }

    #[tokio::test]
    async fn an_answer_typed_there_and_then_is_passed_on() {
        let picks = Picks(Answer::Said("tokyo".to_owned()));
        let answer = ask_choice(&input(), Some(&picks)).await.expect("asked");
        assert_eq!(answer["answer"], "tokyo");
        assert!(
            answer["note"]
                .as_str()
                .is_some_and(|n| n.contains("Carry on"))
        );
    }

    #[tokio::test]
    async fn a_bad_question_or_no_one_to_ask_is_refused() {
        let picks = Picks(Answer::Picked(vec![0]));
        for bad in [
            json!({ "question": "?", "options": [{ "label": "only" }] }),
            json!({ "question": "", "options": [{ "label": "a" }, { "label": "b" }] }),
            json!({ "question": "?", "options": [{ "label": "a" }, { "label": "" }] }),
        ] {
            assert!(ask_choice(&bad, Some(&picks)).await.is_err(), "{bad}");
        }
        assert_eq!(
            ask_choice(&input(), None).await,
            Err(super::NO_ONE_TO_ASK.to_owned())
        );
    }
}
