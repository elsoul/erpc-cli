// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The console: the conversation above, a box to type in fixed below, and
//! the state of the answer being written between them.
//!
//! The session runs inside this loop rather than on a task of its own. A
//! turn is a future that owns the session while it runs and hands it back
//! when it ends, and the loop polls it alongside the keyboard. Its events
//! come through a channel, so drawing never waits on the network and the
//! box can be typed in while an answer is being written.

use std::collections::VecDeque;
use std::pin::Pin;
use std::time::{Duration, Instant};

use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event, EventStream, KeyCode, KeyEvent,
    KeyEventKind, KeyModifiers, KeyboardEnhancementFlags, PopKeyboardEnhancementFlags,
    PushKeyboardEnhancementFlags,
};
use erpc_ai::confirm::{Allow, Answer, Confirm, Confirmation, Question};
use erpc_ai::session::{Access, Session, SessionEvent, Turn};
use erpc_api::ai::Size;
use futures_util::StreamExt as _;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::{DefaultTerminal, Frame};
use tokio::sync::{mpsc, oneshot};
use unicode_width::UnicodeWidthChar as _;

use super::markdown::Markdown;
use super::picker::{Picker, Said};
use super::{Look, mark};
use crate::conversations::Record;

/// Who is signed in and where, for the top of the conversation.
pub struct Intro {
    /// The account, as it should be shown.
    pub account: String,
    /// Where the session is kept.
    pub store: String,
    /// The configured chain, if any.
    pub chain: Option<String>,
    /// The AI plan and what is left of it, when it could be read.
    pub plan: Option<String>,
}

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// The most rows the box grows to before it scrolls.
const MAX_INPUT_ROWS: usize = 6;
/// The commands.
const COMMANDS: [&str; 4] = ["/new", "/model", "/help", "/exit"];

/// What a command does, in the language of the run.
fn command_about(name: &str) -> String {
    match name {
        "/new" => t!("tui.commands.new"),
        "/model" => t!("tui.commands.model"),
        "/help" => t!("tui.commands.help"),
        _ => t!("tui.commands.exit"),
    }
}

/// What `/model` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeAsked {
    /// To be told the size in use: `/model` alone.
    Shown,
    /// To put the conversation on a size; none for `auto`.
    Put(Option<Size>),
}

/// What `/model` with `arg` after it asks for.
fn size_asked(arg: &str) -> Result<SizeAsked, String> {
    match arg.trim() {
        "" => Ok(SizeAsked::Shown),
        "auto" => Ok(SizeAsked::Put(None)),
        name => name
            .parse::<Size>()
            .map(|size| SizeAsked::Put(Some(size)))
            .map_err(|_| t!("tui.size.unknown", size = name)),
    }
}

/// What the console says when the conversation is put on `size`.
fn size_set(size: Option<Size>) -> String {
    match size {
        Some(Size::Xlarge) => t!("tui.size.xlarge"),
        Some(size) => t!("tui.size.set", size = size.name()),
        None => t!("tui.size.auto"),
    }
}

/// What the console does about `/model`.
#[derive(Debug)]
enum SizeReply {
    /// Put the waiting session on this size (none: `auto`), and say so.
    Put(Option<Size>),
    /// Change nothing, and say this.
    Say(Tone, String),
}

/// What the console does about `asked`: `sizes_refused` says the service
/// turned the sizes down, `waiting` that a session waits for the next
/// message (no turn is running), and `current` is the size in use.
fn size_reply(
    asked: SizeAsked,
    sizes_refused: bool,
    waiting: bool,
    current: Option<Size>,
) -> SizeReply {
    match asked {
        _ if sizes_refused => SizeReply::Say(Tone::Warn, t!("tui.size.unavailable")),
        SizeAsked::Shown => SizeReply::Say(Tone::Info, size_shown(current)),
        SizeAsked::Put(size) if waiting => SizeReply::Put(size),
        SizeAsked::Put(_) => SizeReply::Say(Tone::Warn, t!("tui.wait_first")),
    }
}

/// The size in use and the ones to pick from, for `/model` alone.
fn size_shown(size: Option<Size>) -> String {
    let current = size.map_or("auto", Size::name);
    format!(
        "{}\n{}",
        t!("tui.size.current", size = current),
        t!("tui.size.choices")
    )
}

/// The commands and the keys, for `/help`.
fn help() -> String {
    let mut lines: Vec<String> = COMMANDS
        .iter()
        .map(|name| format!("{name:<7} {}", command_about(name)))
        .collect();
    lines.push(String::new());
    lines.push(t!("tui.help.keys"));
    lines.join("\n")
}

type Running<A> = Pin<Box<dyn Future<Output = (Session<A>, Turn)>>>;
/// A guess at the next message being fetched, and the count of edits to the
/// box when it was asked for.
type Guessing = (u64, Pin<Box<dyn Future<Output = Option<String>>>>);

/// A tool asking the person, and where the answer goes.
enum Asking {
    YesNo(Confirmation, oneshot::Sender<bool>),
    /// A yes or no that can also allow the same until the console ends.
    Allow(Confirmation, oneshot::Sender<Allow>),
    Choice(Question, oneshot::Sender<Answer>),
}

/// Asks through the console: the question goes to the screen loop, which
/// shows it and sends back what the person picked.
struct ConsoleConfirm(mpsc::UnboundedSender<Asking>);

impl Confirm for ConsoleConfirm {
    fn confirm<'a>(&'a self, ask: &'a Confirmation) -> Pin<Box<dyn Future<Output = bool> + 'a>> {
        Box::pin(async move {
            let (reply, answer) = oneshot::channel();
            if self.0.send(Asking::YesNo(ask.clone(), reply)).is_err() {
                return false;
            }
            // The console gone, or the turn stopped, is a no.
            answer.await.unwrap_or(false)
        })
    }

    fn allow<'a>(&'a self, ask: &'a Confirmation) -> Pin<Box<dyn Future<Output = Allow> + 'a>> {
        Box::pin(async move {
            let (reply, answer) = oneshot::channel();
            if self.0.send(Asking::Allow(ask.clone(), reply)).is_err() {
                return Allow::No;
            }
            answer.await.unwrap_or(Allow::No)
        })
    }

    fn choose<'a>(&'a self, question: &'a Question) -> Pin<Box<dyn Future<Output = Answer> + 'a>> {
        Box::pin(async move {
            let (reply, answer) = oneshot::channel();
            if self
                .0
                .send(Asking::Choice(question.clone(), reply))
                .is_err()
            {
                return Answer::OwnWords;
            }
            answer.await.unwrap_or(Answer::OwnWords)
        })
    }
}

/// One thing in the conversation.
enum Entry {
    User(String),
    Answer {
        text: String,
        footer: Option<String>,
    },
    Note(Tone, String),
    /// What a tool asks before it changes the account: a title, then each
    /// label and value.
    Ask {
        title: String,
        rows: Vec<(String, String)>,
    },
}

#[derive(Debug, Clone, Copy)]
enum Tone {
    Info,
    Warn,
    Error,
    /// A question the model asks, to pick an answer to.
    Question,
    /// A yes.
    Done,
    /// What was picked.
    Picked,
}

/// The answer being written.
struct Busy {
    started: Instant,
    first_word: Option<Duration>,
    abort: Option<oneshot::Sender<()>>,
}

/// What a key asks the loop to do.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Send(String),
    Reset,
    /// `/model`: show the size, or put the conversation on one.
    Size(SizeAsked),
    Quit,
}

/// Runs the console until the operator leaves.
///
/// # Errors
///
/// Returns an error when the terminal cannot be read or drawn to.
pub async fn run<A: Access + 'static>(
    terminal: &mut DefaultTerminal,
    session: Session<A>,
    look: Look,
    intro: Intro,
    record: &mut Record,
) -> std::io::Result<()> {
    // Shift+Enter can only be told apart from Enter where the terminal
    // reports modifiers; where it does not, Alt+Enter and Ctrl+J still work.
    let enhanced = matches!(
        crossterm::terminal::supports_keyboard_enhancement(),
        Ok(true)
    );
    let mut out = std::io::stdout();
    if enhanced {
        crossterm::execute!(
            out,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )?;
    }
    crossterm::execute!(out, EnableBracketedPaste)?;
    let mut app = App::new(look, intro);
    app.size = session.size();
    if app.size.is_some() {
        app.note(Tone::Info, size_set(app.size));
    }
    let (history, _) = session.snapshot();
    if !history.is_empty() {
        let whole: Vec<serde_json::Value> =
            session.archived().iter().chain(history).cloned().collect();
        app.replay(&whole, record.id());
    }
    let (asks, asked) = mpsc::unbounded_channel();
    let session = session.with_confirm(Box::new(ConsoleConfirm(asks)));
    let result = run_loop(terminal, session, app, record, asked).await;
    let _ = crossterm::execute!(out, DisableBracketedPaste);
    if enhanced {
        let _ = crossterm::execute!(out, PopKeyboardEnhancementFlags);
    }
    result
}

async fn run_loop<A: Access + 'static>(
    terminal: &mut DefaultTerminal,
    session: Session<A>,
    mut app: App,
    record: &mut Record,
    mut asked: mpsc::UnboundedReceiver<Asking>,
) -> std::io::Result<()> {
    let mut idle = Some(session);
    let mut running: Option<Running<A>> = None;
    let mut guessing: Option<Guessing> = None;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(80));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        terminal.draw(|frame| app.render(frame))?;
        let mut actions = Vec::new();
        tokio::select! {
            _ = tick.tick(), if app.busy.is_some() => {}
            event = events.next() => match event {
                Some(Ok(event)) => actions.extend(app.on_event(&event)),
                Some(Err(e)) => return Err(e),
                None => return Ok(()),
            },
            Some(event) = rx.recv() => app.on_session(event),
            Some(asking) = asked.recv() => app.ask(asking),
            guess = async {
                match guessing.as_mut() {
                    Some((_, guess)) => guess.await,
                    None => core::future::pending().await,
                }
            },
                if guessing.is_some() =>
            {
                if let (Some((at, _)), Some(guess)) = (guessing.take(), guess) {
                    app.offer(guess, at);
                }
            }
            (session, turn) = async {
                match running.as_mut() {
                    Some(turn) => turn.await,
                    None => core::future::pending().await,
                }
            },
                if running.is_some() =>
            {
                running = None;
                while let Ok(event) = rx.try_recv() {
                    app.on_session(event);
                }
                app.busy = None;
                // A question the stopped turn left is no longer asked.
                app.picker = None;
                // Saved after every turn, so leaving loses nothing: one
                // stopped part way keeps the tool calls it made.
                let (history, settled) = session.snapshot();
                if !history.is_empty()
                    && let Err(e) = record.save(history, session.archived(), settled)
                {
                    app.note(Tone::Warn, e);
                }
                // A guess at what comes next, asked for apart from the
                // session so the box is never kept waiting for it; only
                // after an answer, with nothing typed or waiting to go.
                if turn == Turn::Answered
                    && app.queue.is_empty()
                    && app.input.is_empty()
                    && let Some(next) = session.next_message()
                {
                    guessing = Some((app.edits, Box::pin(next.fetch())));
                }
                idle = Some(session);
                if let Some(next) = app.queue.pop_front() {
                    actions.push(Action::Send(next));
                }
            }
        }
        // Typing makes a guess still on its way pointless.
        if guessing.as_ref().is_some_and(|(at, _)| *at != app.edits) {
            guessing = None;
        }
        for action in actions {
            if matches!(action, Action::Send(_) | Action::Reset) {
                guessing = None;
            }
            match action {
                Action::Quit => return Ok(()),
                Action::Reset => {
                    if let Some(session) = idle.as_mut() {
                        session.reset();
                        match Record::new() {
                            Ok(fresh) => *record = fresh,
                            Err(e) => app.note(Tone::Warn, e),
                        }
                        app.restart();
                    } else {
                        app.note(Tone::Warn, t!("tui.wait_first"));
                    }
                }
                Action::Size(asked) => app.on_size(idle.as_mut(), asked),
                Action::Send(text) => match idle.take() {
                    Some(session) => running = Some(app.start(session, text, tx.clone())),
                    None => app.queue.push_back(text),
                },
            }
        }
    }
}

struct App {
    /// The size the person put the conversation on; none when each turn's
    /// words decide it.
    size: Option<Size>,
    look: Look,
    intro: Intro,
    entries: Vec<Entry>,
    input: String,
    /// Where the cursor is in `input`, in bytes.
    cursor: usize,
    /// Messages sent while an answer was being written, in order.
    queue: VecDeque<String>,
    busy: Option<Busy>,
    /// The first row shown when scrolled back; `None` follows the end.
    top: Option<usize>,
    /// The last row the conversation can be scrolled to, from the last draw.
    max_top: usize,
    /// How far a page scrolls, from the last draw.
    page: usize,
    /// What was sent, for Up and Down.
    recall: Vec<String>,
    recall_at: Option<usize>,
    /// A question waiting for the person to pick, in place of the box.
    picker: Option<Picker>,
    /// The message the person is likely to send next, shown in the empty
    /// box for Tab to take.
    next: Option<String>,
    /// How many times the box's text has changed, so a guess asked for
    /// before the person typed is not shown after.
    edits: u64,
}

impl App {
    fn new(look: Look, intro: Intro) -> Self {
        Self {
            size: None,
            look,
            intro,
            entries: Vec::new(),
            input: String::new(),
            cursor: 0,
            queue: VecDeque::new(),
            busy: None,
            top: None,
            max_top: 0,
            page: 10,
            recall: Vec::new(),
            recall_at: None,
            picker: None,
            next: None,
            edits: 0,
        }
    }

    /// Answers `/model`: shows the size, or puts the waiting session on
    /// one. Once the service has turned the sizes down there is none to
    /// show or choose; while a turn runs, a change waits.
    fn on_size<A: Access>(&mut self, session: Option<&mut Session<A>>, asked: SizeAsked) {
        let refused = session
            .as_ref()
            .is_some_and(|session| session.sizes_refused());
        match (
            size_reply(asked, refused, session.is_some(), self.size),
            session,
        ) {
            (SizeReply::Put(size), Some(session)) => {
                session.set_size(size);
                self.size = size;
                self.note(Tone::Info, size_set(size));
            }
            (SizeReply::Say(tone, text), _) => self.note(tone, text),
            // `size_reply` puts only a waiting session on a size.
            (SizeReply::Put(_), None) => {}
        }
    }

    fn note(&mut self, tone: Tone, text: impl Into<String>) {
        self.entries.push(Entry::Note(tone, text.into()));
        self.top = None;
    }

    /// Shows what is asked and the options to pick from in place of the
    /// box.
    fn ask(&mut self, asking: Asking) {
        let picker = match asking {
            Asking::YesNo(ask, reply) => {
                self.show_ask(ask);
                Picker::yes_no(reply)
            }
            Asking::Allow(ask, reply) => {
                self.show_ask(ask);
                Picker::allow(reply)
            }
            Asking::Choice(question, reply) => {
                self.note(Tone::Question, question.question.clone());
                Picker::choice(&question, reply)
            }
        };
        self.picker = Some(picker);
    }

    /// What a tool asks, as an entry in the conversation.
    fn show_ask(&mut self, ask: Confirmation) {
        self.entries.push(Entry::Ask {
            title: ask.title,
            rows: ask.lines,
        });
        self.top = None;
    }

    /// A key while something is asked: it moves through the options, or
    /// picks and sends the answer.
    fn answer(&mut self, code: KeyCode) {
        let Some(picker) = self.picker.as_mut() else {
            return;
        };
        if let Some(decided) = picker.key(code)
            && let Some(picker) = self.picker.take()
        {
            let (said, text) = picker.send(decided);
            let tone = match said {
                Said::Yes | Said::Always => Tone::Done,
                Said::Picked => Tone::Picked,
                Said::No | Said::OwnWords => Tone::Info,
            };
            self.note(tone, text);
        }
    }

    /// Shows `guess` in the empty box, unless the box changed since it was
    /// asked for at `edits`, or an answer is being written.
    fn offer(&mut self, guess: String, edits: u64) {
        if edits == self.edits
            && self.input.is_empty()
            && self.busy.is_none()
            && self.picker.is_none()
        {
            self.next = Some(guess);
        }
    }

    fn restart(&mut self) {
        self.next = None;
        self.entries.clear();
        self.top = None;
        self.note(Tone::Info, t!("tui.restarted"));
    }

    /// Shows a saved conversation as it was: each question, and the text of
    /// each answer.
    fn replay(&mut self, history: &[serde_json::Value], id: &str) {
        use serde_json::Value;
        let mut skip_ack = false;
        for message in history {
            // The summary stands in for turns shown above it already, and
            // its acknowledgement says nothing.
            if std::mem::take(&mut skip_ack) {
                continue;
            }
            if message
                .get("content")
                .and_then(Value::as_str)
                .is_some_and(|t| t.starts_with(erpc_ai::compact::SUMMARY_PREFIX))
            {
                skip_ack = true;
                continue;
            }
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
            match message.get("role").and_then(Value::as_str) {
                Some("user") if !text.is_empty() => self.entries.push(Entry::User(text)),
                Some("assistant") => self.entries.push(Entry::Answer { text, footer: None }),
                _ => {}
            }
        }
        self.note(Tone::Info, t!("tui.continuing", id));
    }

    /// Starts a turn: the session goes into the future and comes back out
    /// when the turn ends.
    fn start<A: Access + 'static>(
        &mut self,
        mut session: Session<A>,
        text: String,
        tx: mpsc::UnboundedSender<SessionEvent>,
    ) -> Running<A> {
        self.entries.push(Entry::User(text.clone()));
        self.next = None;
        let (abort_tx, abort_rx) = oneshot::channel::<()>();
        self.busy = Some(Busy {
            started: Instant::now(),
            first_word: None,
            abort: Some(abort_tx),
        });
        self.top = None;
        Box::pin(async move {
            // A dropped sender is not a request to stop.
            let abort = async move {
                if abort_rx.await.is_err() {
                    core::future::pending::<()>().await;
                }
            };
            let turn = session
                .send(&text, abort, &mut |event| {
                    let _ = tx.send(event);
                })
                .await;
            (session, turn)
        })
    }

    /// Stops the answer being written, and drops what was queued behind it.
    fn stop(&mut self) -> bool {
        let Some(busy) = self.busy.as_mut() else {
            return false;
        };
        if let Some(abort) = busy.abort.take() {
            let _ = abort.send(());
        }
        self.queue.clear();
        true
    }

    fn on_session(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::TextDelta { text } => {
                if let Some(busy) = self.busy.as_mut() {
                    let started = busy.started;
                    busy.first_word.get_or_insert_with(|| started.elapsed());
                }
                if let Some(Entry::Answer { text: answer, .. }) = self.entries.last_mut() {
                    answer.push_str(&text);
                } else {
                    self.entries.push(Entry::Answer { text, footer: None });
                }
            }
            SessionEvent::Usage {
                input_tokens,
                cache_read_tokens,
                output_tokens,
            } => {
                let mut parts = Vec::new();
                if let Some(busy) = &self.busy {
                    if let Some(first) = busy.first_word {
                        let seconds = format!("{:.1}", first.as_secs_f64());
                        parts.push(t!("tui.footer.first_word", seconds));
                    }
                    let seconds = format!("{:.1}", busy.started.elapsed().as_secs_f64());
                    parts.push(t!("tui.footer.seconds", seconds));
                }
                // The size, when the person chose one: what the answer cost
                // depends on it.
                if let Some(size) = self.size {
                    parts.push(size.name().to_owned());
                }
                if let (Some(input), Some(output)) = (input_tokens, output_tokens) {
                    parts.push(t!("tui.footer.tokens", input, output));
                }
                if let Some(cached) = cache_read_tokens.filter(|c| *c > 0) {
                    parts.push(t!("tui.footer.cached", cached));
                }
                if let Some(Entry::Answer { footer, .. }) = self.entries.last_mut() {
                    *footer = Some(parts.join(" · "));
                }
            }
            SessionEvent::Refusal { explanation, .. } => {
                let text = match explanation {
                    Some(why) => t!("tui.declined_because", why),
                    None => t!("tui.declined"),
                };
                self.note(Tone::Warn, text);
            }
            SessionEvent::ToolUseStart { name, args, .. } => {
                let label = erpc_ai::tools::label(&name, crate::i18n::lang());
                match args.get("fact").and_then(serde_json::Value::as_str) {
                    Some(fact) if name == "remember" => {
                        self.note(Tone::Info, format!("{label}: {fact}"));
                    }
                    _ if name == "run_command" => {
                        let command = erpc_ai::commands::shown_input(&args).unwrap_or_default();
                        self.note(Tone::Info, format!("$ {command}"));
                    }
                    _ => self.note(Tone::Info, format!("{label}…")),
                }
            }
            SessionEvent::ToolResult {
                ok: false, content, ..
            } => self.note(Tone::Warn, content),
            // The link erpc built, when no browser opened, besides what the
            // model says of it.
            SessionEvent::ToolResult {
                ok: true, content, ..
            } => {
                if let Some(url) = erpc_ai::dashboard::unopened(&content) {
                    self.note(Tone::Info, t!("tui.open_dashboard", url));
                }
            }
            SessionEvent::Error { message } => self.note(Tone::Error, message),
            SessionEvent::SizeRefused { size } => {
                self.size = None;
                self.note(Tone::Warn, t!("tui.size.refused", size));
            }
            SessionEvent::Compacted { .. } => {
                self.note(Tone::Info, t!("tui.compacted"));
            }
            SessionEvent::Aborted { .. } => {
                self.note(Tone::Warn, t!("tui.stopped"));
            }
            _ => {}
        }
    }

    fn on_event(&mut self, event: &Event) -> Option<Action> {
        let before = self.input.clone();
        let action = self.on_input(event);
        // Any change to the box hides the guess, and outdates one on its
        // way.
        if self.input != before {
            self.edits += 1;
            self.next = None;
        }
        action
    }

    fn on_input(&mut self, event: &Event) -> Option<Action> {
        match event {
            // While a tool waits, only its answer is taken; Ctrl still works.
            Event::Key(key)
                if key.kind != KeyEventKind::Release
                    && self.picker.is_some()
                    && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.answer(key.code);
                None
            }
            Event::Key(key) if key.kind != KeyEventKind::Release => self.on_key(*key),
            Event::Paste(text) if self.picker.is_none() => {
                self.insert(&text.replace("\r\n", "\n").replace('\r', "\n"));
                None
            }
            _ => None,
        }
    }

    fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return self.on_control_key(key.code);
        }
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        match key.code {
            KeyCode::Char(c) => {
                self.insert(c.encode_utf8(&mut [0; 4]));
                None
            }
            KeyCode::Enter
                if key
                    .modifiers
                    .intersects(KeyModifiers::SHIFT | KeyModifiers::ALT) =>
            {
                self.insert("\n");
                None
            }
            KeyCode::Enter => self.submit(),
            KeyCode::Backspace => {
                if let Some(prev) = self.input[..self.cursor].chars().next_back() {
                    self.cursor -= prev.len_utf8();
                    self.input.remove(self.cursor);
                }
                None
            }
            KeyCode::Delete => {
                if self.cursor < self.input.len() {
                    self.input.remove(self.cursor);
                }
                None
            }
            KeyCode::Left => {
                if let Some(prev) = self.input[..self.cursor].chars().next_back() {
                    self.cursor -= prev.len_utf8();
                }
                None
            }
            KeyCode::Right => {
                if let Some(next) = self.input[self.cursor..].chars().next() {
                    self.cursor += next.len_utf8();
                }
                None
            }
            KeyCode::Home => {
                self.cursor = self.line_start();
                None
            }
            KeyCode::End => {
                self.cursor = self.line_end();
                None
            }
            KeyCode::Up if shift => {
                self.scroll_up(3);
                None
            }
            KeyCode::Down if shift => {
                self.scroll_down(3);
                None
            }
            KeyCode::Up if !self.input.contains('\n') => {
                let at = self.recall_at.unwrap_or(self.recall.len());
                if let Some(at) = at.checked_sub(1) {
                    self.recall_at = Some(at);
                    self.set_input(self.recall[at].clone());
                }
                None
            }
            KeyCode::Down if !self.input.contains('\n') => {
                if let Some(at) = self.recall_at {
                    if at + 1 < self.recall.len() {
                        self.recall_at = Some(at + 1);
                        self.set_input(self.recall[at + 1].clone());
                    } else {
                        self.recall_at = None;
                        self.set_input(String::new());
                    }
                }
                None
            }
            KeyCode::PageUp => {
                self.scroll_up(self.page);
                None
            }
            KeyCode::PageDown => {
                self.scroll_down(self.page);
                None
            }
            KeyCode::Esc => {
                self.stop();
                None
            }
            KeyCode::Tab => {
                self.complete();
                None
            }
            _ => None,
        }
    }

    /// Tab: the command being typed, or in the empty box the guess at the
    /// next message, for the person to edit or send.
    fn complete(&mut self) {
        if let Some((name, _)) = self.suggestions().first() {
            self.set_input((*name).to_owned());
        } else if self.input.is_empty()
            && let Some(next) = self.next.take()
        {
            self.set_input(next);
        }
    }

    /// Keys held with Ctrl, which edit the box like a shell line does.
    fn on_control_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Char('c') => {
                if self.stop() {
                    None
                } else if self.input.is_empty() {
                    Some(Action::Quit)
                } else {
                    self.set_input(String::new());
                    None
                }
            }
            KeyCode::Char('d') => {
                (self.input.is_empty() && self.busy.is_none()).then_some(Action::Quit)
            }
            KeyCode::Char('j') => {
                self.insert("\n");
                None
            }
            KeyCode::Char('a') => {
                self.cursor = self.line_start();
                None
            }
            KeyCode::Char('e') => {
                self.cursor = self.line_end();
                None
            }
            KeyCode::Char('u') => {
                let start = self.line_start();
                self.input.replace_range(start..self.cursor, "");
                self.cursor = start;
                None
            }
            KeyCode::Char('w') => {
                let before = &self.input[..self.cursor];
                let kept = before.trim_end().len();
                let start = before[..kept]
                    .rfind(char::is_whitespace)
                    .map_or(0, |i| i + 1);
                self.input.replace_range(start..self.cursor, "");
                self.cursor = start;
                None
            }
            _ => None,
        }
    }

    fn submit(&mut self) -> Option<Action> {
        let text = self.input.trim().to_owned();
        if text.is_empty() {
            return None;
        }
        self.set_input(String::new());
        self.recall.push(text.clone());
        self.recall_at = None;
        match text.as_str() {
            "/exit" | "/quit" => Some(Action::Quit),
            "/new" | "/clear" => Some(Action::Reset),
            "/help" => {
                let help = help();
                self.note(Tone::Info, help);
                None
            }
            // Before the arm below: `/model xlarge` has a space in it, and
            // would go to the assistant as a message.
            command if command == "/model" || command.starts_with("/model ") => {
                match size_asked(&command["/model".len()..]) {
                    Ok(asked) => Some(Action::Size(asked)),
                    Err(why) => {
                        self.note(Tone::Warn, why);
                        None
                    }
                }
            }
            command if command.starts_with('/') && !command.contains(char::is_whitespace) => {
                self.note(Tone::Warn, t!("tui.unknown_command", command));
                None
            }
            _ => Some(Action::Send(text)),
        }
    }

    fn set_input(&mut self, text: String) {
        self.cursor = text.len();
        self.input = text;
    }

    fn insert(&mut self, text: &str) {
        self.input.insert_str(self.cursor, text);
        self.cursor += text.len();
    }

    fn line_start(&self) -> usize {
        self.input[..self.cursor].rfind('\n').map_or(0, |i| i + 1)
    }

    fn line_end(&self) -> usize {
        self.input[self.cursor..]
            .find('\n')
            .map_or(self.input.len(), |i| self.cursor + i)
    }

    fn scroll_up(&mut self, rows: usize) {
        let from = self.top.unwrap_or(self.max_top);
        self.top = Some(from.saturating_sub(rows));
    }

    fn scroll_down(&mut self, rows: usize) {
        if let Some(top) = self.top {
            let top = top + rows;
            self.top = (top < self.max_top).then_some(top);
        }
    }

    /// The commands matching what has been typed, while a command is being
    /// typed.
    fn suggestions(&self) -> Vec<(&'static str, String)> {
        if !self.input.starts_with('/') || self.input.contains(char::is_whitespace) {
            return Vec::new();
        }
        COMMANDS
            .iter()
            .filter(|name| name.starts_with(self.input.as_str()))
            .map(|name| (*name, command_about(name)))
            .collect()
    }

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let suggestions = self.suggestions();
        let box_width = usize::from(area.width.saturating_sub(4)).max(4);
        let (rows, _) = input_rows(&self.input, self.cursor, box_width - 2);
        let input_height = match &self.picker {
            Some(picker) => picker.height(),
            None => rows.len().clamp(1, MAX_INPUT_ROWS),
        };
        let [body, hints_above, status, input, hints] = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(u16::try_from(suggestions.len()).unwrap_or(0)),
            Constraint::Length(1),
            Constraint::Length(u16::try_from(input_height).unwrap_or(1) + 2),
            Constraint::Length(1),
        ])
        .areas(area);

        self.render_conversation(frame, body);
        let suggestion_lines: Vec<Line> = suggestions
            .iter()
            .enumerate()
            .map(|(i, (name, what))| {
                let name_style = if i == 0 {
                    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                } else {
                    Style::new().fg(Color::Cyan)
                };
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("{name:<8}"), name_style),
                    Span::styled(what.clone(), dim()),
                ])
            })
            .collect();
        frame.render_widget(Paragraph::new(suggestion_lines), hints_above);
        frame.render_widget(Paragraph::new(self.status_line()), status);
        let hint = if let Some(picker) = &self.picker {
            let block = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(Color::Yellow));
            frame.render_widget(Paragraph::new(picker.lines()).block(block), input);
            picker.hint()
        } else {
            self.render_input(frame, input);
            t!("tui.hint")
        };
        frame.render_widget(Paragraph::new(Span::styled(hint, dim())), hints);

        if !self.look.color {
            for cell in &mut frame.buffer_mut().content {
                cell.fg = Color::Reset;
                cell.bg = Color::Reset;
            }
        }
    }

    fn render_conversation(&mut self, frame: &mut Frame, body: Rect) {
        let inner = Rect {
            x: body.x + 1,
            width: body.width.saturating_sub(2),
            ..body
        };
        let lines = self.conversation(usize::from(inner.width));
        let height = usize::from(inner.height);
        self.page = height.saturating_sub(2).max(1);
        self.max_top = lines.len().saturating_sub(height);
        let top = match self.top {
            Some(top) if top < self.max_top => top,
            _ => {
                self.top = None;
                self.max_top
            }
        };
        let shown: Vec<Line> = lines.into_iter().skip(top).take(height).collect();
        frame.render_widget(Paragraph::new(shown), inner);
    }

    fn status_line(&self) -> Line<'static> {
        let mut spans = vec![Span::raw(" ")];
        if let Some(busy) = &self.busy {
            let elapsed = busy.started.elapsed();
            #[allow(clippy::cast_possible_truncation)]
            let spin = SPINNER[(elapsed.as_millis() / 80) as usize % SPINNER.len()];
            let doing = if busy.abort.is_none() {
                t!("tui.status.stopping")
            } else if busy.first_word.is_some() {
                t!("tui.status.writing")
            } else {
                t!("tui.status.thinking")
            };
            spans.push(Span::styled(
                format!("{spin} "),
                Style::new().fg(Color::Cyan),
            ));
            spans.push(Span::raw(format!("{doing} {:.1}s", elapsed.as_secs_f64())));
            spans.push(Span::styled(
                if self.picker.is_some() {
                    t!("tui.status.waiting_for_pick")
                } else {
                    t!("tui.status.esc_to_stop")
                },
                dim(),
            ));
        }
        if !self.queue.is_empty() {
            let queued = tn!("tui.status.queued", self.queue.len());
            spans.push(Span::styled(queued, Style::new().fg(Color::Yellow)));
        }
        if self.top.is_some() {
            spans.push(Span::styled(t!("tui.status.scrolled_back"), dim()));
        }
        Line::from(spans)
    }

    fn render_input(&self, frame: &mut Frame, area: Rect) {
        let border = if self.busy.is_some() {
            Style::new().fg(Color::DarkGray)
        } else {
            Style::new().fg(Color::Cyan)
        };
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(border);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let width = usize::from(inner.width).saturating_sub(2).max(1);
        let (rows, (row, col)) = input_rows(&self.input, self.cursor, width);
        let visible = usize::from(inner.height).max(1);
        let skip = (row + 1).saturating_sub(visible);
        let prompt = Span::styled(
            "› ",
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        );
        let lines: Vec<Line> = if self.input.is_empty() {
            let mut line = vec![prompt];
            match self.guess() {
                Some(guess) => {
                    line.push(Span::styled(guess.to_owned(), dim()));
                    line.push(Span::styled(
                        t!("tui.placeholder.tab"),
                        dim().add_modifier(Modifier::ITALIC),
                    ));
                }
                None => line.push(Span::styled(self.placeholder(), dim())),
            }
            vec![Line::from(line)]
        } else {
            rows.iter()
                .enumerate()
                .skip(skip)
                .take(visible)
                .map(|(i, text)| {
                    let lead = if i == 0 {
                        prompt.clone()
                    } else {
                        Span::raw("  ")
                    };
                    Line::from(vec![lead, Span::raw(text.clone())])
                })
                .collect()
        };
        frame.render_widget(Paragraph::new(lines), inner);
        let x = inner.x + 2 + u16::try_from(col).unwrap_or(0);
        let y = inner.y + u16::try_from(row - skip).unwrap_or(0);
        frame.set_cursor_position(Position::new(x.min(inner.right()), y));
    }

    /// The guess at the next message, while it is shown in the box.
    fn guess(&self) -> Option<&str> {
        self.next
            .as_deref()
            .filter(|_| self.input.is_empty() && self.busy.is_none())
    }

    /// What the empty box says when there is no guess to show.
    fn placeholder(&self) -> String {
        if self.busy.is_some() {
            t!("tui.placeholder.busy")
        } else {
            t!("tui.placeholder.idle")
        }
    }

    /// The whole conversation, wrapped to `width`.
    fn conversation(&self, width: usize) -> Vec<Line<'static>> {
        let mut out = self.intro_lines(width);
        let content = width.saturating_sub(2).max(1);
        for entry in &self.entries {
            out.push(Line::default());
            match entry {
                Entry::User(text) => {
                    let style = Style::new().add_modifier(Modifier::BOLD);
                    for (i, para) in text.split('\n').enumerate() {
                        let lead = if i == 0 {
                            Span::styled(
                                "› ",
                                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                            )
                        } else {
                            Span::raw("  ")
                        };
                        push_wrapped(
                            &mut out,
                            &lead,
                            &[Span::styled(para.to_owned(), style)],
                            content,
                        );
                    }
                }
                Entry::Answer { text, footer } => {
                    let mut markdown = Markdown::default();
                    for (i, para) in text.trim_end().split('\n').enumerate() {
                        let lead = if i == 0 {
                            Span::styled("● ", Style::new().fg(Color::Cyan))
                        } else {
                            Span::raw("  ")
                        };
                        push_wrapped(&mut out, &lead, &markdown.line(para), content);
                    }
                    if let Some(footer) = footer {
                        out.push(Line::from(Span::styled(format!("  {footer}"), dim())));
                    }
                }
                Entry::Ask { title, rows } => ask_lines(&mut out, title, rows, content),
                Entry::Note(tone, text) => {
                    let style = match tone {
                        Tone::Info => dim(),
                        Tone::Warn => Style::new().fg(Color::Yellow),
                        Tone::Error => Style::new().fg(Color::Red),
                        Tone::Question => Style::new().add_modifier(Modifier::BOLD),
                        Tone::Done => Style::new().fg(Color::Green),
                        Tone::Picked => Style::new().fg(Color::Cyan),
                    };
                    for para in text.split('\n') {
                        push_wrapped(
                            &mut out,
                            &Span::raw("  "),
                            &[Span::styled(para.to_owned(), style)],
                            content,
                        );
                    }
                }
            }
        }
        out
    }

    /// The header: the ERPC mark, and beside it who is signed in and
    /// where; then what to try.
    fn intro_lines(&self, width: usize) -> Vec<Line<'static>> {
        use unicode_width::UnicodeWidthStr as _;
        let dim_text = |text: &str| Span::styled(text.to_owned(), dim());
        let labels = [
            t!("tui.intro.user"),
            t!("tui.intro.signed_in"),
            t!("tui.intro.chain"),
            t!("tui.intro.plan"),
        ];
        // The values line up after the longest label, and at column 10 at
        // least.
        let column = labels
            .iter()
            .map(|l| l.width() + 2)
            .max()
            .unwrap_or(0)
            .max(10);
        let [user, signed_in, chain_label, plan_label] = labels.map(|text| {
            let pad = column.saturating_sub(text.width());
            Span::styled(format!("{text}{}", " ".repeat(pad)), dim())
        });
        let chain = match &self.intro.chain {
            Some(chain) => vec![Span::raw(chain.clone())],
            None => vec![dim_text(&t!("tui.intro.chain_not_set"))],
        };
        let mut beside: Vec<Vec<Span<'static>>> = vec![
            vec![
                Span::styled("ERPC AI", Style::new().add_modifier(Modifier::BOLD)),
                dim_text(&format!(" v{}", env!("CARGO_PKG_VERSION"))),
            ],
            vec![
                user,
                Span::styled(
                    self.intro.account.clone(),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
            ],
            vec![signed_in, Span::raw(self.intro.store.clone())],
            [vec![chain_label], chain].concat(),
        ];
        if let Some(plan) = &self.intro.plan {
            beside.insert(2, vec![plan_label, Span::raw(plan.clone())]);
        }
        // The mark on the left with the text in its middle rows, or the
        // text alone where there is no mark.
        let mark = mark::rows(self.look);
        let rows: Vec<Vec<Span<'static>>> = if mark.is_empty() {
            beside.into_iter().collect()
        } else {
            // A blank row above and below, so the mark does not touch the
            // frame.
            let mark: Vec<Vec<Span<'static>>> = std::iter::once(Vec::new())
                .chain(mark.into_iter().map(|row| {
                    let mut row = row;
                    row.insert(0, Span::raw(" "));
                    row
                }))
                .chain(std::iter::once(Vec::new()))
                .collect();
            let first = (mark.len() - beside.len()).div_ceil(2);
            let mut beside = beside.into_iter();
            let mark_width = mark::WIDTH + 1;
            mark.into_iter()
                .enumerate()
                .map(|(i, mut row)| {
                    if i >= first
                        && let Some(text) = beside.next()
                    {
                        let drawn = Line::from(row.clone()).width();
                        row.push(Span::raw(" ".repeat(mark_width - drawn + 3)));
                        row.extend(text);
                    }
                    row
                })
                .collect()
        };
        let mut out = framed(rows, width);
        out.push(Line::default());
        out.push(Line::from(Span::styled(
            format!("  {}", t!("tui.intro.try")),
            dim(),
        )));
        let tries = [
            t!("tui.intro.try_validator"),
            t!("tui.intro.try_rpc"),
            t!("tui.intro.try_vps"),
        ];
        for text in tries {
            out.push(Line::from(vec![
                Span::styled("  › ", Style::new().fg(Color::Cyan)),
                Span::raw(text),
            ]));
        }
        out
    }
}

/// `rows` inside a rounded frame, or as they are where the frame does not
/// fit in `width`.
fn framed(rows: Vec<Vec<Span<'static>>>, width: usize) -> Vec<Line<'static>> {
    let inner = rows
        .iter()
        .map(|spans| Line::from(spans.clone()).width())
        .max()
        .unwrap_or(0);
    let border = Style::new().fg(Color::Cyan).add_modifier(Modifier::DIM);
    let mut out = Vec::new();
    if inner + 4 <= width {
        out.push(Line::from(Span::styled(
            format!("╭{}╮", "─".repeat(inner + 2)),
            border,
        )));
        for spans in rows {
            let pad = inner - Line::from(spans.clone()).width();
            let mut line = vec![Span::styled("│ ", border)];
            line.extend(spans);
            line.push(Span::raw(" ".repeat(pad)));
            line.push(Span::styled(" │", border));
            out.push(Line::from(line));
        }
        out.push(Line::from(Span::styled(
            format!("╰{}╯", "─".repeat(inner + 2)),
            border,
        )));
    } else {
        out.extend(rows.into_iter().map(Line::from));
    }
    out
}

/// A confirmation: a marked, bold title, then the labels dimmed and
/// lined up and the values plain, so the facts read apart from the words
/// around them.
fn ask_lines(out: &mut Vec<Line<'static>>, title: &str, rows: &[(String, String)], width: usize) {
    use unicode_width::UnicodeWidthStr as _;
    push_wrapped(
        out,
        &Span::styled(
            "◆ ",
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        &[Span::styled(
            title.to_owned(),
            Style::new().add_modifier(Modifier::BOLD),
        )],
        width,
    );
    let label_width = rows
        .iter()
        .map(|(label, _)| label.width())
        .max()
        .unwrap_or(0);
    for (label, value) in rows {
        let pad = " ".repeat(label_width - label.width());
        push_wrapped(
            out,
            &Span::raw("  "),
            &[
                Span::styled(format!("{label}{pad}  "), dim()),
                Span::raw(value.clone()),
            ],
            width,
        );
    }
}

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}

/// Adds `spans` to `out`, wrapped to `width`, the first row led by `lead`
/// and the rest indented to match.
fn push_wrapped(
    out: &mut Vec<Line<'static>>,
    lead: &Span<'static>,
    spans: &[Span<'_>],
    width: usize,
) {
    for (i, row) in wrap(spans, width).into_iter().enumerate() {
        let mut line = vec![if i == 0 {
            lead.clone()
        } else {
            Span::raw("  ")
        }];
        line.extend(row);
        out.push(Line::from(line));
    }
}

/// Wraps styled text to `width` columns. A row breaks at its last space,
/// as English and Russian wrap, or between two characters where either is
/// a wide (CJK) one, as Japanese and Chinese wrap, whichever comes later;
/// never before closing punctuation such as `。` or `）`, nor after an
/// opening one. A word longer than the row breaks anywhere.
fn wrap(spans: &[Span<'_>], width: usize) -> Vec<Vec<Span<'static>>> {
    let width = width.max(1);
    let mut rows: Vec<Vec<(char, Style)>> = Vec::new();
    let mut row: Vec<(char, Style)> = Vec::new();
    let mut row_width = 0;
    let cells = spans
        .iter()
        .flat_map(|span| span.content.chars().map(move |c| (c, span.style)));
    for (c, style) in cells {
        let w = c.width().unwrap_or(0);
        if row_width + w > width && !row.is_empty() {
            let last = row.last().map_or(' ', |(ch, _)| *ch);
            if c != ' ' && breaks_between(last, c) {
                rows.push(std::mem::take(&mut row));
            } else if let Some(at) = (1..row.len())
                .rev()
                .find(|&i| row[i].0 == ' ' || breaks_between(row[i - 1].0, row[i].0))
            {
                let rest = row.split_off(at);
                rows.push(std::mem::replace(&mut row, rest));
                // A space the row broke at is not carried over.
                if row.first().is_some_and(|(ch, _)| *ch == ' ') {
                    row.remove(0);
                }
            } else {
                rows.push(std::mem::take(&mut row));
            }
            row_width = row.iter().map(|(ch, _)| ch.width().unwrap_or(0)).sum();
            if row_width + w > width && !row.is_empty() {
                rows.push(std::mem::take(&mut row));
                row_width = 0;
            }
            if c == ' ' && row.is_empty() {
                continue;
            }
        }
        row.push((c, style));
        row_width += w;
    }
    rows.push(row);
    rows.into_iter()
        .map(|row| {
            let mut spans: Vec<Span<'static>> = Vec::new();
            for (c, style) in row {
                match spans.last_mut() {
                    Some(last) if last.style == style => last.content.to_mut().push(c),
                    _ => spans.push(Span::styled(c.to_string(), style)),
                }
            }
            spans
        })
        .collect()
}

/// Whether a row may end after `before` and the next start with `after`
/// with no space between them: beside a wide character, as CJK text does,
/// unless that would start a row with closing punctuation or end one with
/// opening punctuation.
fn breaks_between(before: char, after: char) -> bool {
    const NO_START: &str = "、。，．・：；？！）」』】〉》〕｝ー々〜…%％,.:;?!)]}";
    const NO_END: &str = "（「『【〈《〔｛([{";
    let wide = |c: char| c.width().unwrap_or(0) > 1;
    before != ' '
        && (wide(before) || wide(after))
        && !NO_START.contains(after)
        && !NO_END.contains(before)
}

/// The box's text as rows of at most `width` columns, and the row and
/// column of the cursor in them.
fn input_rows(input: &str, cursor: usize, width: usize) -> (Vec<String>, (usize, usize)) {
    let width = width.max(1);
    let mut rows = vec![String::new()];
    let mut col = 0;
    let mut at = None;
    for (i, c) in input.char_indices() {
        if i == cursor {
            at = Some((rows.len() - 1, col));
        }
        if c == '\n' {
            rows.push(String::new());
            col = 0;
            continue;
        }
        let w = c.width().unwrap_or(0);
        if col + w > width {
            rows.push(String::new());
            col = 0;
        }
        if let Some(row) = rows.last_mut() {
            row.push(c);
        }
        col += w;
    }
    let (row, col) = at.unwrap_or((rows.len() - 1, col));
    // A cursor at the end of a full row sits at the start of the next.
    if col >= width {
        if row + 1 == rows.len() {
            rows.push(String::new());
        }
        return (rows, (row + 1, 0));
    }
    (rows, (row, col))
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::text::{Line, Span};

    use super::{Action, App, Asking, Intro, input_rows, wrap};
    use crate::tui::Look;

    fn app() -> App {
        App::new(
            Look {
                color: true,
                truecolor: true,
                animate: true,
            },
            Intro {
                account: "alice@example.com".to_owned(),
                store: "keychain".to_owned(),
                chain: None,
                plan: Some("Developer · 3.2M tokens left".to_owned()),
            },
        )
    }

    fn key(app: &mut App, code: KeyCode, modifiers: KeyModifiers) -> Option<Action> {
        app.on_event(&crossterm::event::Event::Key(KeyEvent::new(
            code, modifiers,
        )))
    }

    fn typed(app: &mut App, text: &str) {
        for c in text.chars() {
            key(app, KeyCode::Char(c), KeyModifiers::NONE);
        }
    }

    #[test]
    fn a_question_takes_the_keys_and_nothing_is_typed_meanwhile() {
        let ask = erpc_ai::confirm::Confirmation {
            title: "Start VPS hourly?".to_owned(),
            lines: vec![],
        };
        for (pressed, expected) in [
            (&[KeyCode::Up, KeyCode::Enter][..], true),
            (&[KeyCode::Char('y'), KeyCode::Enter], false),
            (&[KeyCode::Esc], false),
            (&[KeyCode::Enter], false),
        ] {
            let mut app = app();
            let (reply, mut answer) = tokio::sync::oneshot::channel();
            app.ask(Asking::YesNo(ask.clone(), reply));
            typed(&mut app, "hello");
            assert!(
                app.input.is_empty(),
                "keys go to the question, not the input"
            );
            assert!(answer.try_recv().is_err(), "other keys do not answer");
            app.picker.as_mut().expect("asked").settle();
            for &code in pressed {
                key(&mut app, code, KeyModifiers::NONE);
            }
            assert_eq!(answer.try_recv(), Ok(expected));
            assert!(app.picker.is_none());
        }
    }

    #[test]
    fn a_confirmation_lines_up_its_labels_and_dims_only_them() {
        let mut out = Vec::new();
        super::ask_lines(
            &mut out,
            "VPS を開始しますか？",
            &[
                ("料金".to_owned(), "€0.07".to_owned()),
                ("クレジット残高".to_owned(), "€12.07".to_owned()),
            ],
            60,
        );
        let text: Vec<String> = out
            .iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert_eq!(
            text,
            [
                "◆ VPS を開始しますか？",
                "  料金            €0.07",
                "  クレジット残高  €12.07",
            ]
        );
        let value = out[1].spans.last().expect("value");
        assert_eq!(
            value.style,
            ratatui::style::Style::new(),
            "values are plain"
        );
    }

    #[test]
    fn a_pick_goes_back_and_is_shown_in_the_conversation() {
        let mut app = app();
        let (reply, mut answer) = tokio::sync::oneshot::channel();
        app.ask(Asking::Choice(
            erpc_ai::confirm::Question {
                question: "Which plan?".to_owned(),
                options: vec![("SLV VPS".to_owned(), None), ("VPS Plus".to_owned(), None)],
                multiple: false,
            },
            reply,
        ));
        app.picker.as_mut().expect("asked").settle();
        key(&mut app, KeyCode::Down, KeyModifiers::NONE);
        key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(
            answer.try_recv(),
            Ok(erpc_ai::confirm::Answer::Picked(vec![1]))
        );
        assert!(
            matches!(app.entries.last(), Some(super::Entry::Note(_, said)) if said == "→ VPS Plus")
        );
    }

    fn plain(rows: &[Vec<Span<'_>>]) -> Vec<String> {
        rows.iter()
            .map(|row| row.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn enter_sends_and_shift_enter_starts_a_new_line() {
        let mut app = app();
        typed(&mut app, "hello");
        key(&mut app, KeyCode::Enter, KeyModifiers::SHIFT);
        typed(&mut app, "there");
        assert_eq!(app.input, "hello\nthere");
        assert_eq!(
            key(&mut app, KeyCode::Enter, KeyModifiers::NONE),
            Some(Action::Send("hello\nthere".to_owned()))
        );
        assert!(app.input.is_empty());
    }

    #[test]
    fn commands_are_not_sent_to_the_model() {
        let mut app = app();
        typed(&mut app, "/new");
        assert_eq!(
            key(&mut app, KeyCode::Enter, KeyModifiers::NONE),
            Some(Action::Reset)
        );
        typed(&mut app, "/he");
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.input, "/help");
        assert_eq!(key(&mut app, KeyCode::Enter, KeyModifiers::NONE), None);
        typed(&mut app, "/nope");
        assert_eq!(key(&mut app, KeyCode::Enter, KeyModifiers::NONE), None);
    }

    #[test]
    fn model_picks_a_size_or_auto_and_never_reaches_the_assistant() {
        use super::SizeAsked;
        use erpc_api::ai::Size;
        let mut app = app();
        for (typed_text, asked) in [
            ("/model xlarge", SizeAsked::Put(Some(Size::Xlarge))),
            ("/model  Large ", SizeAsked::Put(Some(Size::Large))),
            ("/model erpc-ai-medium", SizeAsked::Put(Some(Size::Medium))),
            ("/model auto", SizeAsked::Put(None)),
            ("/model", SizeAsked::Shown),
        ] {
            typed(&mut app, typed_text);
            assert_eq!(
                key(&mut app, KeyCode::Enter, KeyModifiers::NONE),
                Some(Action::Size(asked)),
                "{typed_text}"
            );
        }
        // An unknown size is answered in the console.
        let notes = app.entries.len();
        typed(&mut app, "/model huge");
        assert_eq!(key(&mut app, KeyCode::Enter, KeyModifiers::NONE), None);
        assert_eq!(app.entries.len(), notes + 1);
        typed(&mut app, "/mo");
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.input, "/model");
    }

    #[test]
    fn model_is_answered_by_whether_sizes_are_offered_and_a_turn_is_running() {
        use super::{SizeAsked, SizeReply, size_reply};
        use erpc_api::ai::Size;
        let put = SizeAsked::Put(Some(Size::Xlarge));
        assert!(matches!(
            size_reply(put, false, true, None),
            SizeReply::Put(Some(Size::Xlarge))
        ));
        assert!(matches!(
            size_reply(SizeAsked::Put(None), false, true, Some(Size::Xlarge)),
            SizeReply::Put(None)
        ));
        let said = |reply: SizeReply| match reply {
            SizeReply::Say(_, text) => text,
            SizeReply::Put(size) => panic!("put on {size:?}"),
        };
        // While a turn runs, a change waits; showing the size does not.
        assert_eq!(
            said(size_reply(put, false, false, None)),
            t!("tui.wait_first")
        );
        assert!(
            said(size_reply(
                SizeAsked::Shown,
                false,
                false,
                Some(Size::Large)
            ))
            .contains("large")
        );
        // Once the sizes are turned down, every /model says so.
        for asked in [put, SizeAsked::Put(None), SizeAsked::Shown] {
            assert_eq!(
                said(size_reply(asked, true, true, None)),
                t!("tui.size.unavailable")
            );
        }
    }

    #[test]
    fn tab_takes_the_guess_and_enter_sends_it() {
        let mut app = app();
        assert_eq!(app.guess(), None, "no guess before one is offered");
        app.offer("stop the Developer plan".to_owned(), app.edits);
        assert_eq!(app.guess(), Some("stop the Developer plan"));
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.input, "stop the Developer plan");
        assert_eq!(app.guess(), None, "taken, it is no longer shown");
        typed(&mut app, " now");
        assert_eq!(
            key(&mut app, KeyCode::Enter, KeyModifiers::NONE),
            Some(Action::Send("stop the Developer plan now".to_owned()))
        );
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert!(app.input.is_empty(), "a guess is taken once");
    }

    #[test]
    fn typing_hides_the_guess_and_outdates_one_on_its_way() {
        let mut app = app();
        app.offer("yes".to_owned(), app.edits);
        typed(&mut app, "n");
        assert_eq!(app.guess(), None);
        key(&mut app, KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(app.guess(), None, "it does not come back");
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert!(app.input.is_empty(), "Tab has nothing to take");

        let asked_at = app.edits;
        typed(&mut app, "a");
        key(&mut app, KeyCode::Backspace, KeyModifiers::NONE);
        app.offer("late".to_owned(), asked_at);
        assert_eq!(app.guess(), None, "typed after it was asked for");

        typed(&mut app, "draft");
        app.offer("late".to_owned(), app.edits);
        assert_eq!(app.guess(), None, "not over typed text");
    }

    #[test]
    fn the_fixed_placeholder_stays_without_a_guess_or_while_busy() {
        let mut app = app();
        assert_eq!(
            app.placeholder(),
            "Ask anything about your nodes, account or erpc"
        );
        app.busy = Some(super::Busy {
            started: std::time::Instant::now(),
            first_word: None,
            abort: None,
        });
        app.offer("late".to_owned(), app.edits);
        assert_eq!(app.guess(), None, "not offered while an answer is written");
        app.busy = None;
        app.offer("next".to_owned(), app.edits);
        app.busy = Some(super::Busy {
            started: std::time::Instant::now(),
            first_word: None,
            abort: None,
        });
        assert_eq!(app.guess(), None, "hidden while an answer is written");
        assert!(app.placeholder().starts_with("Type the next message"));
    }

    #[test]
    fn tab_still_completes_a_command_over_a_guess() {
        let mut app = app();
        app.offer("next".to_owned(), app.edits);
        typed(&mut app, "/ne");
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.input, "/new");
    }

    #[test]
    fn ctrl_c_clears_the_box_then_leaves() {
        let mut app = app();
        typed(&mut app, "draft");
        assert_eq!(
            key(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL),
            None
        );
        assert!(app.input.is_empty());
        assert_eq!(
            key(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL),
            Some(Action::Quit)
        );
    }

    #[test]
    fn up_recalls_what_was_sent() {
        let mut app = app();
        typed(&mut app, "first");
        key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        typed(&mut app, "second");
        key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        key(&mut app, KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(app.input, "second");
        key(&mut app, KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(app.input, "first");
        key(&mut app, KeyCode::Down, KeyModifiers::NONE);
        key(&mut app, KeyCode::Down, KeyModifiers::NONE);
        assert!(app.input.is_empty());
    }

    #[test]
    fn editing_keeps_the_cursor_on_character_boundaries() {
        let mut app = app();
        typed(&mut app, "ノード");
        key(&mut app, KeyCode::Left, KeyModifiers::NONE);
        key(&mut app, KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(app.input, "ノド");
        key(&mut app, KeyCode::Char('w'), KeyModifiers::CONTROL);
        assert_eq!(app.input, "ド");
    }

    #[test]
    fn text_wraps_at_spaces_and_japanese_anywhere() {
        let spans = [Span::raw("run the testnet validator")];
        assert_eq!(
            plain(&wrap(&spans, 10)),
            ["run the", "testnet", "validator"]
        );
        let spans = [Span::raw("バリデータを立てる")];
        assert_eq!(plain(&wrap(&spans, 8)), ["バリデー", "タを立て", "る"]);
        // Between wide characters rather than back at an earlier space.
        let spans = [Span::raw("VPS を開始しますか")];
        assert_eq!(plain(&wrap(&spans, 10)), ["VPS を開始", "しますか"]);
        // Closing punctuation stays with what it closes.
        let spans = [Span::raw("会话太长了。请重试")];
        assert_eq!(plain(&wrap(&spans, 10)), ["会话太长", "了。请重试"]);
    }

    #[test]
    fn chinese_wraps_anywhere_and_russian_at_spaces() {
        let spans = [Span::raw("按小时启动服务器")];
        assert_eq!(plain(&wrap(&spans, 6)), ["按小时", "启动服", "务器"]);
        let spans = [Span::raw("启动 VPS Plus 吗")];
        assert_eq!(plain(&wrap(&spans, 10)), ["启动 VPS", "Plus 吗"]);
        let spans = [Span::raw("Запустить продукт с почасовой оплатой")];
        assert_eq!(
            plain(&wrap(&spans, 16)),
            ["Запустить", "продукт с", "почасовой", "оплатой"]
        );
        // A word longer than the row still breaks, inside the row.
        let spans = [Span::raw("перезапускается")];
        assert_eq!(plain(&wrap(&spans, 8)), ["перезапу", "скается"]);
        for row in wrap(&[Span::raw("Ничего из этого (введу свой ответ)")], 12)
        {
            assert!(Line::from(row).width() <= 12);
        }
    }

    #[test]
    fn the_console_speaks_chinese_and_russian() {
        use crate::i18n::speaking;
        use erpc_core::i18n::Lang;
        for (lang, user, ask_title) in [
            (Lang::Zh, "用户", "按小时启动 VPS？"),
            (Lang::Ru, "пользователь", "Запустить VPS?"),
        ] {
            speaking(lang, || {
                let mut app = app();
                let intro = app.intro_lines(100);
                let text: Vec<String> = intro
                    .iter()
                    .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
                    .collect();
                assert!(text.iter().any(|l| l.contains(user)), "{text:?}");
                // The frame closes on every row, wide characters and all.
                let widths: Vec<usize> = intro.iter().take(10).map(Line::width).collect();
                assert!(
                    widths.windows(2).all(|w| w[0] == w[1]),
                    "{widths:?} {text:?}"
                );
                let (reply, _answer) = tokio::sync::oneshot::channel();
                app.ask(Asking::YesNo(
                    erpc_ai::confirm::Confirmation {
                        title: ask_title.to_owned(),
                        lines: vec![],
                    },
                    reply,
                ));
                let hint = app.picker.as_ref().expect("asked").hint();
                assert!(!hint.contains("go ahead"), "{hint}");
                typed(&mut app, "x");
                assert!(super::help().contains("/new"));
                assert_ne!(super::command_about("/new"), "start a new conversation");
            });
        }
    }

    #[test]
    fn the_cursor_follows_wide_characters_and_new_lines() {
        assert_eq!(input_rows("ab", 2, 10).1, (0, 2));
        assert_eq!(input_rows("ノード", 3, 10).1, (0, 2));
        assert_eq!(input_rows("a\nb", 4, 10).1, (1, 1));
        let (rows, cursor) = input_rows("abcd", 4, 4);
        assert_eq!((rows.len(), cursor), (2, (1, 0)));
    }
}
