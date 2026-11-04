// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A question answered by picking: the options in place of the box to type
//! in, moved through with the arrows and picked with Enter, several marked
//! with Space where the question allows it.
//!
//! A yes or no that a tool asks before it changes the account is one too.
//! Its cursor starts on No, so an Enter meant for the box, pressed as the
//! question appears, stops rather than spends. Yes takes an arrow and
//! then Enter: no single key says it, and letters and digits being typed
//! for the box never move the cursor (`n` and Esc say no). And no key
//! counts for a moment after any question appears, so the rest of a line
//! being typed falls away.

use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use erpc_ai::confirm::{Allow, Answer, Question};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use tokio::sync::oneshot;

/// How long after a question appears its keys are ignored.
const SETTLE: Duration = Duration::from_millis(400);

/// Where the answer goes.
enum Reply {
    YesNo(oneshot::Sender<bool>),
    /// A yes or no with middle rows: yes, and not again until the console
    /// ends, for every command or for this one.
    Allow(oneshot::Sender<Allow>),
    Choice(oneshot::Sender<Answer>),
}

/// What a key decided.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Decided {
    /// These rows, in order. For a yes or no, row 0 is yes.
    Rows(Vec<usize>),
    /// The last row: none fitted, the person will type.
    OwnWords,
    /// No, to a yes or no.
    No,
}

/// What the answer was, for how it is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Said {
    Yes,
    Always,
    No,
    Picked,
    OwnWords,
}

/// A question on screen.
pub(super) struct Picker {
    /// Each row: a label and perhaps a line about it.
    rows: Vec<(String, Option<String>)>,
    multiple: bool,
    cursor: usize,
    marked: Vec<bool>,
    reply: Reply,
    shown: Instant,
}

impl Picker {
    /// A tool's yes or no, the cursor on no.
    pub(super) fn yes_no(reply: oneshot::Sender<bool>) -> Self {
        Self::stop_last(&[], Reply::YesNo(reply))
    }

    /// A command's yes or no, with middle rows that allow every command, or
    /// this one, until the console ends; the cursor on no. The row next to
    /// no is the narrower one.
    pub(super) fn allow(reply: oneshot::Sender<Allow>) -> Self {
        Self::stop_last(
            &[t!("tui.picker.every"), t!("tui.picker.always")],
            Reply::Allow(reply),
        )
    }

    /// Go ahead, the rows in `between`, then stop, where the cursor starts.
    fn stop_last(between: &[String], reply: Reply) -> Self {
        let rows: Vec<(String, Option<String>)> = core::iter::once(t!("tui.picker.yes"))
            .chain(between.iter().cloned())
            .chain(core::iter::once(t!("tui.picker.no")))
            .map(|label| (label, None))
            .collect();
        Self {
            cursor: rows.len() - 1,
            marked: vec![false; rows.len()],
            rows,
            multiple: false,
            reply,
            shown: Instant::now(),
        }
    }

    /// The model's question, with a last row for answering in one's own
    /// words.
    pub(super) fn choice(question: &Question, reply: oneshot::Sender<Answer>) -> Self {
        let mut rows = question.options.clone();
        rows.push((t!("tui.picker.own_words"), None));
        Self {
            marked: vec![false; rows.len()],
            rows,
            multiple: question.multiple,
            cursor: 0,
            reply: Reply::Choice(reply),
            shown: Instant::now(),
        }
    }

    fn yes_no_asked(&self) -> bool {
        matches!(self.reply, Reply::YesNo(_) | Reply::Allow(_))
    }

    /// The row for one's own words, which is never marked.
    fn own_words_row(&self) -> Option<usize> {
        (!self.yes_no_asked()).then(|| self.rows.len() - 1)
    }

    /// Moves, marks or decides for a key; `Some` when it decided. Keys
    /// in the first moment after the question appeared are ignored.
    pub(super) fn key(&mut self, code: KeyCode) -> Option<Decided> {
        if self.shown.elapsed() < SETTLE {
            return None;
        }
        self.press(code)
    }

    /// As if the question had been on screen for a while, for tests.
    #[cfg(test)]
    pub(super) fn settle(&mut self) {
        self.shown = Instant::now().checked_sub(SETTLE).unwrap_or(self.shown);
    }

    fn press(&mut self, code: KeyCode) -> Option<Decided> {
        let last = self.rows.len() - 1;
        let yes_no = self.yes_no_asked();
        match code {
            // A yes or no moves with the arrows alone: a letter or a digit
            // typed for the box must not carry the cursor to yes.
            KeyCode::Char('k' | 'j' | '1'..='9') | KeyCode::Tab | KeyCode::BackTab if yes_no => {
                None
            }
            // Nor does it wrap: Down from "Stop" stays there.
            KeyCode::Up if yes_no => {
                self.cursor = self.cursor.saturating_sub(1);
                None
            }
            KeyCode::Down if yes_no => {
                self.cursor = (self.cursor + 1).min(last);
                None
            }
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.cursor = if self.cursor == 0 {
                    last
                } else {
                    self.cursor - 1
                };
                None
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.cursor = if self.cursor == last {
                    0
                } else {
                    self.cursor + 1
                };
                None
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc if self.yes_no_asked() => Some(Decided::No),
            KeyCode::Esc => Some(Decided::OwnWords),
            KeyCode::Char(' ') if self.multiple && Some(self.cursor) != self.own_words_row() => {
                self.marked[self.cursor] ^= true;
                None
            }
            KeyCode::Char(c @ '1'..='9') => {
                let row = c as usize - '1' as usize;
                if row > last {
                    return None;
                }
                self.cursor = row;
                if self.multiple && Some(row) != self.own_words_row() {
                    self.marked[row] ^= true;
                    None
                } else {
                    Some(self.decided())
                }
            }
            KeyCode::Enter => Some(self.decided()),
            _ => None,
        }
    }

    /// What Enter on the current row decides.
    fn decided(&self) -> Decided {
        if self.yes_no_asked() {
            return if self.cursor + 1 == self.rows.len() {
                Decided::No
            } else {
                Decided::Rows(vec![self.cursor])
            };
        }
        if Some(self.cursor) == self.own_words_row() {
            return Decided::OwnWords;
        }
        let marked: Vec<usize> = (0..self.rows.len()).filter(|&i| self.marked[i]).collect();
        // Several allowed but none marked: the row the cursor is on.
        Decided::Rows(if marked.is_empty() {
            vec![self.cursor]
        } else {
            marked
        })
    }

    /// Sends the answer and says, for the conversation, what it was.
    pub(super) fn send(self, decided: Decided) -> (Said, String) {
        match self.reply {
            Reply::YesNo(reply) => {
                let yes = decided != Decided::No;
                let _ = reply.send(yes);
                if yes {
                    (Said::Yes, t!("tui.picker.said_yes"))
                } else {
                    (Said::No, t!("tui.picker.said_no"))
                }
            }
            Reply::Allow(reply) => {
                let allow = match decided {
                    Decided::No | Decided::OwnWords => Allow::No,
                    Decided::Rows(rows) if rows == [1] => Allow::Everything,
                    Decided::Rows(rows) if rows == [2] => Allow::Always,
                    Decided::Rows(_) => Allow::Once,
                };
                let _ = reply.send(allow);
                match allow {
                    Allow::Once => (Said::Yes, t!("tui.picker.said_yes")),
                    Allow::Always => (Said::Always, t!("tui.picker.said_always")),
                    // Not yet allowed: a second question makes sure.
                    Allow::Everything => (Said::Picked, t!("tui.picker.said_every")),
                    Allow::No => (Said::No, t!("tui.picker.said_no")),
                }
            }
            Reply::Choice(reply) => match decided {
                Decided::Rows(rows) => {
                    let labels: Vec<&str> = rows
                        .iter()
                        .filter_map(|&i| self.rows.get(i).map(|(label, _)| label.as_str()))
                        .collect();
                    let said = format!("→ {}", labels.join(", "));
                    let _ = reply.send(Answer::Picked(rows));
                    (Said::Picked, said)
                }
                Decided::OwnWords | Decided::No => {
                    let _ = reply.send(Answer::OwnWords);
                    (Said::OwnWords, t!("tui.picker.said_own_words"))
                }
            },
        }
    }

    /// How many rows it takes.
    pub(super) fn height(&self) -> usize {
        self.rows.len()
    }

    /// The rows as shown.
    pub(super) fn lines(&self) -> Vec<Line<'static>> {
        let own_words = self.own_words_row();
        self.rows
            .iter()
            .enumerate()
            .map(|(i, (label, detail))| {
                let here = i == self.cursor;
                let mut spans = vec![Span::styled(
                    if here { "› " } else { "  " },
                    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )];
                if self.multiple && Some(i) != own_words {
                    spans.push(Span::raw(if self.marked[i] { "[x] " } else { "[ ] " }));
                }
                spans.push(Span::styled(format!("{}. ", i + 1), dim()));
                spans.push(Span::styled(
                    label.clone(),
                    if here {
                        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                    } else {
                        Style::new()
                    },
                ));
                if let Some(detail) = detail {
                    spans.push(Span::styled(format!("  {detail}"), dim()));
                }
                Line::from(spans)
            })
            .collect()
    }

    /// The keys, for the line under it.
    pub(super) fn hint(&self) -> String {
        match (self.yes_no_asked(), self.multiple) {
            (true, _) => t!("tui.picker.hint_yes_no"),
            (false, false) => t!("tui.picker.hint_one"),
            (false, true) => t!("tui.picker.hint_several"),
        }
    }
}

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;
    use erpc_ai::confirm::{Answer, Question};

    use erpc_core::i18n::Lang;

    use super::{Decided, Picker};
    use crate::i18n::speaking;

    fn question(multiple: bool) -> Question {
        Question {
            question: "Which region?".to_owned(),
            options: vec![
                ("tokyo".to_owned(), Some("4 free".to_owned())),
                ("frankfurt".to_owned(), None),
                ("amsterdam".to_owned(), None),
            ],
            multiple,
        }
    }

    #[test]
    fn a_yes_or_no_starts_on_no_and_enter_there_stops() {
        let (reply, mut answer) = tokio::sync::oneshot::channel();
        let mut picker = Picker::yes_no(reply);
        let decided = picker.press(KeyCode::Enter).expect("decided");
        assert_eq!(decided, Decided::No);
        picker.send(decided);
        assert_eq!(answer.try_recv(), Ok(false));

        let (reply, mut answer) = tokio::sync::oneshot::channel();
        let mut picker = speaking(Lang::Ja, || Picker::yes_no(reply));
        assert_eq!(picker.press(KeyCode::Up), None);
        let decided = picker.press(KeyCode::Enter).expect("decided");
        assert_eq!(speaking(Lang::Ja, || picker.send(decided)).1, "はい。");
        assert_eq!(answer.try_recv(), Ok(true));
    }

    /// The rows, the hint and what is said back, as a person reads them.
    fn shown(picker: &Picker) -> Vec<String> {
        let mut out: Vec<String> = picker
            .lines()
            .iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        out.push(picker.hint());
        out
    }

    #[test]
    fn a_yes_or_no_is_asked_in_chinese_and_russian() {
        let ask = |lang| {
            speaking(lang, || {
                let (reply, _answer) = tokio::sync::oneshot::channel();
                let picker = Picker::yes_no(reply);
                let rows = shown(&picker);
                let said = picker.send(Decided::No).1;
                (rows, said)
            })
        };
        let (rows, said) = ask(Lang::Zh);
        assert_eq!(rows[..2], ["  1. 继续", "› 2. 停止"]);
        assert!(
            rows[2].contains("继续") && rows[2].contains("n/esc"),
            "{rows:?}"
        );
        assert_eq!(said, "否；未做任何更改。");
        let (rows, said) = ask(Lang::Ru);
        assert_eq!(rows[..2], ["  1. Продолжить", "› 2. Отмена"]);
        assert_eq!(said, "Нет; ничего не изменено.");
    }

    #[test]
    fn a_choice_offers_its_own_words_row_in_chinese_and_russian() {
        for (lang, own) in [
            (Lang::Zh, "都不是（自己输入回答）"),
            (Lang::Ru, "Ничего из этого (введу свой ответ)"),
        ] {
            let (rows, said) = speaking(lang, || {
                let (reply, _answer) = tokio::sync::oneshot::channel();
                let picker = Picker::choice(&question(true), reply);
                let rows = shown(&picker);
                (rows, picker.send(Decided::OwnWords).1)
            });
            assert_eq!(rows[3], format!("  4. {own}"));
            assert!(rows[0].contains("[ ] 1. tokyo  4 free"), "{rows:?}");
            assert!(!rows[4].contains("enter decide"), "{rows:?}");
            assert!(!said.is_empty() && said != "Type your answer below.");
        }
    }

    #[test]
    fn one_is_picked_with_the_arrows_or_its_number() {
        let (reply, mut answer) = tokio::sync::oneshot::channel();
        let mut picker = Picker::choice(&question(false), reply);
        assert_eq!(picker.press(KeyCode::Down), None);
        let decided = picker.press(KeyCode::Enter).expect("decided");
        assert_eq!(picker.send(decided).1, "→ frankfurt");
        assert_eq!(answer.try_recv(), Ok(Answer::Picked(vec![1])));

        let (reply, _answer) = tokio::sync::oneshot::channel();
        let mut picker = Picker::choice(&question(false), reply);
        assert_eq!(
            picker.press(KeyCode::Char('3')),
            Some(Decided::Rows(vec![2]))
        );
        assert_eq!(picker.press(KeyCode::Char('9')), None, "no such row");
    }

    #[test]
    fn several_are_marked_with_space_and_sent_with_enter() {
        let (reply, mut answer) = tokio::sync::oneshot::channel();
        let mut picker = Picker::choice(&question(true), reply);
        for code in [
            KeyCode::Char(' '),
            KeyCode::Down,
            KeyCode::Down,
            KeyCode::Char(' '),
            KeyCode::Char('2'),
            KeyCode::Char('2'),
        ] {
            assert_eq!(picker.press(code), None, "{code:?} only marks");
        }
        let decided = picker.press(KeyCode::Enter).expect("decided");
        assert_eq!(picker.send(decided).1, "→ tokyo, amsterdam");
        assert_eq!(answer.try_recv(), Ok(Answer::Picked(vec![0, 2])));
    }

    #[test]
    fn the_last_row_or_esc_leaves_it_to_typing() {
        let (reply, mut answer) = tokio::sync::oneshot::channel();
        let mut picker = Picker::choice(&question(true), reply);
        assert_eq!(picker.press(KeyCode::Up), None, "wraps to the last row");
        assert_eq!(picker.press(KeyCode::Char(' ')), None, "never marked");
        let decided = picker.press(KeyCode::Enter).expect("decided");
        assert_eq!(decided, Decided::OwnWords);
        picker.send(decided);
        assert_eq!(answer.try_recv(), Ok(Answer::OwnWords));

        let (reply, _answer) = tokio::sync::oneshot::channel();
        let mut picker = Picker::choice(&question(false), reply);
        assert_eq!(picker.press(KeyCode::Esc), Some(Decided::OwnWords));
    }

    #[test]
    fn a_command_can_be_allowed_until_the_console_ends() {
        use erpc_ai::confirm::Allow;
        for (pressed, expected) in [
            (&[KeyCode::Enter][..], Allow::No),
            (&[KeyCode::Up, KeyCode::Enter], Allow::Always),
            (
                &[KeyCode::Up, KeyCode::Up, KeyCode::Enter],
                Allow::Everything,
            ),
            (
                &[KeyCode::Up, KeyCode::Up, KeyCode::Up, KeyCode::Enter],
                Allow::Once,
            ),
            (
                &[
                    KeyCode::Up,
                    KeyCode::Up,
                    KeyCode::Up,
                    KeyCode::Up,
                    KeyCode::Enter,
                ],
                Allow::Once,
            ),
            (&[KeyCode::Up, KeyCode::Char('n')], Allow::No),
            (&[KeyCode::Up, KeyCode::Esc], Allow::No),
            (
                &[KeyCode::Char('2'), KeyCode::Char('y'), KeyCode::Enter],
                Allow::No,
            ),
        ] {
            let (reply, mut answer) = tokio::sync::oneshot::channel();
            let mut picker = Picker::allow(reply);
            assert_eq!(picker.height(), 4);
            let decided = pressed
                .iter()
                .find_map(|&code| picker.press(code))
                .expect("decided");
            picker.send(decided);
            assert_eq!(answer.try_recv(), Ok(expected), "{pressed:?}");
        }
    }

    #[test]
    fn typing_meant_for_the_box_never_says_yes() {
        let (reply, mut answer) = tokio::sync::oneshot::channel();
        let mut picker = Picker::yes_no(reply);
        for code in [
            KeyCode::Char('o'),
            KeyCode::Char('y'),
            KeyCode::Char('k'),
            KeyCode::Char('j'),
            KeyCode::Char('1'),
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Down,
            KeyCode::Down,
        ] {
            assert_eq!(picker.press(code), None, "{code:?} is ignored");
        }
        let decided = picker.press(KeyCode::Enter).expect("decided");
        assert_eq!(
            decided,
            Decided::No,
            "the cursor is still on Stop: Down does not wrap"
        );
        picker.send(decided);
        assert_eq!(answer.try_recv(), Ok(false));
    }

    #[test]
    fn keys_right_after_a_question_appears_are_ignored() {
        let (reply, _answer) = tokio::sync::oneshot::channel();
        let mut picker = Picker::yes_no(reply);
        assert_eq!(picker.key(KeyCode::Up), None);
        assert_eq!(picker.key(KeyCode::Enter), None);
    }
}
