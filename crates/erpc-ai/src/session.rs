// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! One conversation with the ERPC assistant, as a stream of events.
//!
//! Every way of talking to the assistant -- the terminal console now, a
//! local WebSocket gateway and a browser UI next -- drives a [`Session`]
//! and renders the [`SessionEvent`]s it emits. Behaviour lives here once,
//! so the front ends cannot drift apart.
//!
//! The events, their names and their JSON shape follow the SLV gateway
//! protocol (version 1), so a client written for that protocol reads these
//! too. The list only grows: a client ignores a `type` it does not know.

use core::future::Future;

use erpc_api::ApiError;
use erpc_api::ai::{ChatRequest, Size};
use erpc_auth::AuthClient;
use secrecy::SecretString;
use serde::Serialize;
use serde_json::{Value, json};

use crate::i18n::t;

/// What a session tells its front end.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    /// More of the assistant's answer.
    TextDelta {
        /// The new text.
        text: String,
    },
    /// The assistant started a tool.
    ToolUseStart {
        /// The tool call's id.
        id: String,
        /// The tool's name.
        name: String,
        /// Its arguments.
        args: Value,
    },
    /// A line of a running tool's output.
    ToolStdout {
        /// The line.
        text: String,
    },
    /// A short progress label for a running tool.
    ToolProgress {
        /// The label.
        label: String,
    },
    /// A tool finished.
    ToolResult {
        /// The tool call's id.
        id: String,
        /// Whether it succeeded.
        ok: bool,
        /// What it returned.
        content: String,
    },
    /// The session started or stopped working.
    Status {
        /// `running` or `idle`.
        state: RunState,
        /// What it is doing, when there is something to say.
        #[serde(skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// Tokens used by the turn. An erpc addition to the protocol.
    Usage {
        /// Tokens read.
        #[serde(skip_serializing_if = "Option::is_none")]
        input_tokens: Option<u64>,
        /// Tokens read from the prompt cache.
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_read_tokens: Option<u64>,
        /// Tokens written.
        #[serde(skip_serializing_if = "Option::is_none")]
        output_tokens: Option<u64>,
    },
    /// The older turns were summarised to keep the conversation short. An
    /// erpc addition to the protocol.
    Compacted {
        /// How many messages the summary took the place of.
        messages: usize,
    },
    /// The turn finished.
    Complete,
    /// The service does not offer the size the person chose: the turn is
    /// asked again at its default. After it, the turns go back to the size
    /// each turn's words decide, or, when the service turned every size
    /// down, to its recommended model. An erpc addition to the protocol.
    SizeRefused {
        /// The size turned down: `xlarge`.
        size: String,
    },
    /// The model declined to answer. An erpc addition to the protocol.
    Refusal {
        /// The category, when the service gave one.
        #[serde(skip_serializing_if = "Option::is_none")]
        category: Option<String>,
        /// Why, when the service said.
        #[serde(skip_serializing_if = "Option::is_none")]
        explanation: Option<String>,
    },
    /// The turn was stopped before it finished.
    Aborted {
        /// Why, when there is something to say.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// The turn failed.
    Error {
        /// What went wrong, for a person.
        message: String,
    },
}

/// What a turn asks for next when the service does not offer the model it
/// asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retry {
    /// It asked for the size the person chose, other than large: large
    /// answers instead, and the person is told.
    Large(Size),
    /// The service does not know the sizes: its recommended model answers,
    /// and is asked for from then on.
    Recommended,
    /// It already asked for the recommended model: there is nothing else.
    Nothing,
}

/// The [`Retry`] after `asked` was turned down, with `chosen` the size the
/// person chose.
fn retry_after_refusal(chosen: Option<Size>, asked: &str) -> Retry {
    match chosen {
        Some(size) if size != Size::Large && asked == size.model() => Retry::Large(size),
        _ if asked == erpc_api::ai::FALLBACK_MODEL => Retry::Nothing,
        _ => Retry::Recommended,
    }
}

/// Whether a session is working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// Working on a turn.
    Running,
    /// Waiting for the next message.
    Idle,
}

/// Where a session gets a current access token, at the start of each turn.
pub trait Access {
    /// A token that is valid now, refreshed if need be.
    fn access_token(&self) -> impl Future<Output = Result<SecretString, String>>;
}

/// How a turn ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Turn {
    /// The assistant answered.
    Answered,
    /// The turn was stopped.
    Aborted,
    /// The turn failed; the event said why.
    Failed,
}

/// A conversation: its history, and how to reach the assistant.
pub struct Session<A: Access> {
    access: A,
    client: AuthClient,
    system: Vec<String>,
    history: Vec<Value>,
    /// Whether the conversation has reached the main model. From then on it
    /// stays there; see [`crate::policy`].
    settled: bool,
    /// Whether the service turned the model sizes down, so only its
    /// recommended model is asked for.
    sizes_refused: bool,
    /// The size the person put the conversation on; none, and each turn's
    /// words decide it ([`crate::policy`]).
    size: Option<Size>,
    /// Who says yes to a tool that changes the account; none, and such a
    /// tool refuses.
    confirm: Option<Box<dyn crate::confirm::Confirm>>,
    /// The wallet a credit top-up pays from; none, and a top-up refuses.
    wallet: Option<Box<dyn crate::confirm::CreditWallet>>,
    /// Reaching the user's servers; none, and the tools that log in refuse.
    servers: Option<Box<dyn crate::servers::Servers>>,
    /// Running commands on the user's computer; none, and `run_command`
    /// refuses.
    shell: Option<Box<dyn crate::commands::Shell>>,
    /// Opening pages in the person's browser; none, and `open_dashboard`
    /// only gives the address.
    browser: Option<Box<dyn crate::dashboard::Browser>>,
    /// The commands the person allowed until the console ends.
    allowed: crate::commands::Allowed,
    /// The messages compaction took out of the history, oldest first, for
    /// the front end to keep.
    archived: Vec<Value>,
    /// What is remembered between conversations; none, and nothing is.
    memory: Option<crate::memory::Memory>,
    /// After a summary failed: the size the history must pass before one
    /// is tried again.
    compact_not_before: usize,
    /// The access token the last turn was sent with, for the guess at the
    /// next message made after it.
    turn_token: Option<SecretString>,
}

impl<A: Access> Session<A> {
    /// A new, empty conversation. `system` is the system prompt, from
    /// [`crate::prompt::system`].
    pub const fn new(access: A, client: AuthClient, system: Vec<String>) -> Self {
        Self {
            access,
            client,
            system,
            history: Vec::new(),
            settled: false,
            sizes_refused: false,
            size: None,
            confirm: None,
            wallet: None,
            servers: None,
            shell: None,
            browser: None,
            allowed: crate::commands::Allowed::new(),
            archived: Vec::new(),
            memory: None,
            compact_not_before: 0,
            turn_token: None,
        }
    }

    /// The same session, paying credit top-ups from `wallet`.
    #[must_use]
    pub fn with_wallet(mut self, wallet: Box<dyn crate::confirm::CreditWallet>) -> Self {
        self.wallet = Some(wallet);
        self
    }

    /// The same session, remembering facts in `memory`.
    #[must_use]
    pub fn with_memory(mut self, memory: crate::memory::Memory) -> Self {
        self.memory = Some(memory);
        self
    }

    /// The same session, logging in to the user's servers through
    /// `servers`.
    #[must_use]
    pub fn with_servers(mut self, servers: Box<dyn crate::servers::Servers>) -> Self {
        self.servers = Some(servers);
        self
    }

    /// The same session, running commands through `shell`.
    #[must_use]
    pub fn with_shell(mut self, shell: Box<dyn crate::commands::Shell>) -> Self {
        self.shell = Some(shell);
        self
    }

    /// The same session, opening pages through `browser`.
    #[must_use]
    pub fn with_browser(mut self, browser: Box<dyn crate::dashboard::Browser>) -> Self {
        self.browser = Some(browser);
        self
    }

    /// The same session, asking `confirm` before a tool changes the account.
    #[must_use]
    pub fn with_confirm(mut self, confirm: Box<dyn crate::confirm::Confirm>) -> Self {
        self.confirm = Some(confirm);
        self
    }

    /// Puts every turn from the next one on `size`, or, with none, back on
    /// the size each turn's words decide. A change costs the next turn its
    /// prompt cache: the whole conversation is read again at the new size.
    /// It lasts until it is changed again, a new conversation included.
    pub const fn set_size(&mut self, size: Option<Size>) {
        self.size = size;
    }

    /// The size the person chose; none when each turn's words decide it.
    #[must_use]
    pub const fn size(&self) -> Option<Size> {
        self.size
    }

    /// Whether the service turned the model sizes down: from then on only
    /// its recommended model is asked for, and a size chosen is not.
    #[must_use]
    pub const fn sizes_refused(&self) -> bool {
        self.sizes_refused
    }

    /// The policy for a turn whose question is `text`: the size the person
    /// chose, or the one the words decide, and the service's recommended
    /// model once it has turned the sizes down.
    fn turn_policy(&self, text: &str) -> crate::policy::TurnPolicy {
        let mut policy = match self.size {
            Some(size) if !self.sizes_refused => crate::policy::chosen(size),
            _ => crate::policy::policy(text, self.settled || self.sizes_refused),
        };
        if self.sizes_refused {
            policy.model = erpc_api::ai::FALLBACK_MODEL;
        }
        policy
    }

    /// After the service turned down the model `policy` asked for, for the
    /// question `text`: moves the session and `policy` on to what is asked
    /// next. Returns whether to ask again, and the size the person chose
    /// that was turned down, to tell them.
    fn on_not_offered(
        &mut self,
        text: &str,
        policy: &mut crate::policy::TurnPolicy,
    ) -> (bool, Option<Size>) {
        match retry_after_refusal(self.size, policy.model) {
            Retry::Large(size) => {
                self.size = None;
                *policy = crate::policy::chosen(Size::Large);
                (true, Some(size))
            }
            Retry::Recommended => {
                // A size the person chose goes with the sizes, and they
                // are told.
                let chosen = self.size.take();
                self.sizes_refused = true;
                *policy = self.turn_policy(text);
                (true, chosen)
            }
            Retry::Nothing => (false, None),
        }
    }

    /// Forgets the conversation so far.
    pub fn reset(&mut self) {
        self.history.clear();
        self.archived.clear();
        self.settled = false;
        self.compact_not_before = 0;
        self.allowed.clear();
    }

    /// The messages summarised away so far, oldest first.
    #[must_use]
    pub fn archived(&self) -> &[Value] {
        &self.archived
    }

    /// Picks up the messages a saved conversation had summarised away.
    pub fn set_archived(&mut self, archived: Vec<Value>) {
        self.archived = archived;
    }

    /// The conversation as the model is sent it, and whether it has
    /// reached the main model: what [`Self::restore`] needs to pick it up
    /// again.
    #[must_use]
    pub fn snapshot(&self) -> (&[Value], bool) {
        (&self.history, self.settled)
    }

    /// Picks up a conversation saved from [`Self::snapshot`].
    ///
    /// # Errors
    ///
    /// Refuses a history that is not turns of a user then an assistant,
    /// ending with the assistant: the next message would be sent after it,
    /// and the model refuses anything else.
    pub fn restore(&mut self, history: Vec<Value>, settled: bool) -> Result<(), String> {
        let roles_alternate = history.iter().enumerate().all(|(i, message)| {
            let want = if i.is_multiple_of(2) {
                "user"
            } else {
                "assistant"
            };
            message.get("role").and_then(Value::as_str) == Some(want)
                && message.get("content").is_some()
        });
        if !roles_alternate || !history.len().is_multiple_of(2) {
            return Err(t!("session.not_continuable"));
        }
        self.history = history;
        self.settled = settled;
        self.allowed.clear();
        Ok(())
    }

    /// A guess at the user's next message, to fetch apart from the session:
    /// none before the first answer, or when no turn has had a token.
    #[must_use]
    pub fn next_message(&self) -> Option<crate::next::NextMessage> {
        Some(crate::next::NextMessage {
            client: self.client.clone(),
            token: self.turn_token.clone()?,
            model: if self.sizes_refused {
                erpc_api::ai::FALLBACK_MODEL
            } else {
                erpc_api::ai::QUICK_MODEL
            },
            prompt: crate::next::prompt(&self.history)?,
        })
    }

    /// How many messages the conversation holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.history.len()
    }

    /// Whether the conversation is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }

    /// Sends `text` and emits the answer as it arrives.
    ///
    /// `abort` stops the turn when it completes first. A turn that ends
    /// without an answer leaves the history when it called no tools, so a
    /// stopped question is not answered later as if it had been asked. One
    /// that did call tools keeps them, with a note that it stopped: a tool
    /// may have changed something (started a paid service, changed a
    /// server), and the next turn must know.
    pub async fn send(
        &mut self,
        text: &str,
        abort: impl Future<Output = ()>,
        emit: &mut dyn FnMut(SessionEvent),
    ) -> Turn {
        emit(SessionEvent::Status {
            state: RunState::Running,
            label: None,
        });
        tokio::pin!(abort);
        if crate::compact::due(&self.history, self.compact_not_before)
            && self.compact(&mut abort, emit).await.is_none()
        {
            emit(SessionEvent::Aborted { reason: None });
            emit(SessionEvent::Status {
                state: RunState::Idle,
                label: None,
            });
            return Turn::Aborted;
        }
        let before = self.history.len();
        self.history
            .push(json!({ "role": "user", "content": text }));
        let turn = self.run(text, abort, emit).await;
        if turn != Turn::Answered {
            self.close_unanswered(before, turn == Turn::Aborted);
        }
        emit(SessionEvent::Status {
            state: RunState::Idle,
            label: None,
        });
        turn
    }

    /// Leaves the history whole after a turn with no answer: without its
    /// question when no tool ran, otherwise with the tool calls up to their
    /// last results and a note that the turn stopped there.
    fn close_unanswered(&mut self, before: usize, stopped: bool) {
        // The last complete point: the question, or a message of results.
        // An assistant message after it may hold calls never answered.
        let end = (before + 1..self.history.len())
            .rev()
            .find(|&i| self.history[i].get("role").and_then(Value::as_str) == Some("user"))
            .map_or(before, |i| i + 1);
        if end <= before + 1 {
            self.history.truncate(before);
            return;
        }
        self.history.truncate(end);
        let why = if stopped {
            "the user stopped it"
        } else {
            "it failed"
        };
        self.history.push(json!({
            "role": "assistant",
            "content": format!(
                "(This turn ended before an answer: {why}. The tool calls above did run, as \
                 their results say. Do not carry on with it unless the user asks.)"
            ),
        }));
    }

    /// Asks the model, runs the tools it calls and hands back what they
    /// returned, until it answers. `text` is the user's question, which
    /// decides the model for the whole turn.
    async fn run(
        &mut self,
        text: &str,
        abort: impl Future<Output = ()>,
        emit: &mut dyn FnMut(SessionEvent),
    ) -> Turn {
        let mut policy = self.turn_policy(text);
        let tools = crate::tools::definitions();
        tokio::pin!(abort);
        for _ in 0..MAX_ROUNDS {
            let token = match self.access.access_token().await {
                Ok(token) => {
                    self.turn_token = Some(token.clone());
                    token
                }
                Err(message) => {
                    emit(SessionEvent::Error { message });
                    return Turn::Failed;
                }
            };
            let answer = match self
                .ask(text, &mut policy, &token, &tools, &mut abort, emit)
                .await
            {
                None => {
                    emit(SessionEvent::Aborted { reason: None });
                    return Turn::Aborted;
                }
                Some(Err(e)) => {
                    emit(SessionEvent::Error {
                        message: describe(&e),
                    });
                    return Turn::Failed;
                }
                Some(Ok(answer)) if answer.stop_reason.as_deref() == Some("refusal") => {
                    let refusal = answer.refusal.unwrap_or_default();
                    emit(SessionEvent::Refusal {
                        category: refusal.category,
                        explanation: refusal.explanation,
                    });
                    return Turn::Failed;
                }
                Some(Ok(answer)) => answer,
            };
            // The blocks as produced, thinking and its signature included:
            // the next request hands them back unchanged.
            let is_call = |b: &Value| b.get("type").and_then(Value::as_str) == Some("tool_use");
            let calling = answer.stop_reason.as_deref() == Some("tool_use");
            // A call in an answer that stopped for another reason (cut off
            // at its length) is never run, and a call left without its
            // result would make the API refuse the conversation from then
            // on: it is not kept.
            let content: Vec<Value> = answer
                .content
                .into_iter()
                .filter(|b| !b.is_null() && (calling || !is_call(b)))
                .collect();
            let calls: Vec<Value> = content.iter().filter(|b| is_call(b)).cloned().collect();
            let says_something = content.iter().any(|b| {
                b.get("type").and_then(Value::as_str) == Some("text")
                    && b.get("text")
                        .and_then(Value::as_str)
                        .is_some_and(|t| !t.trim().is_empty())
            });
            // The API refuses an empty message, so an empty answer is
            // recorded as saying so.
            let content = if !calls.is_empty() || says_something {
                Value::Array(content)
            } else if answer.text.trim().is_empty() {
                json!("(no answer)")
            } else {
                json!(answer.text)
            };
            self.history
                .push(json!({ "role": "assistant", "content": content }));
            emit(SessionEvent::Usage {
                input_tokens: answer.input_tokens,
                cache_read_tokens: answer.cache_read_tokens,
                output_tokens: answer.output_tokens,
            });
            if answer.stop_reason.as_deref() != Some("tool_use") || calls.is_empty() {
                if answer.stop_reason.as_deref() == Some("max_tokens") {
                    emit(SessionEvent::Error {
                        message: t!("session.cut_off"),
                    });
                }
                emit(SessionEvent::Complete);
                return Turn::Answered;
            }
            let (results, stopped) = self.call_tools(calls, &token, &mut abort, emit).await;
            self.history
                .push(json!({ "role": "user", "content": results }));
            if stopped {
                emit(SessionEvent::Aborted { reason: None });
                return Turn::Aborted;
            }
        }
        emit(SessionEvent::Error {
            message: t!("session.too_many_rounds", rounds = MAX_ROUNDS),
        });
        Turn::Failed
    }

    /// Summarises the turns before the last few and goes on from the
    /// summary. When there are none to summarise, or no summary can be
    /// had, the older tool results are cut short instead and a summary is
    /// not tried again until the history grows. `None` only when `abort`
    /// came first.
    async fn compact<F: Future<Output = ()>>(
        &mut self,
        abort: &mut core::pin::Pin<&mut F>,
        emit: &mut dyn FnMut(SessionEvent),
    ) -> Option<()> {
        let summarised = self.summarise(abort, emit).await?;
        // With no summary, or turns kept that are long by themselves: cut
        // them short, and wait for growth before summarising again.
        self.compact_not_before =
            if !summarised || crate::compact::size(&self.history) > crate::compact::COMPACT_AT {
                crate::compact::shrink(&mut self.history);
                crate::compact::size(&self.history) + crate::compact::RETRY_AFTER
            } else {
                0
            };
        Some(())
    }

    /// The summary step of [`Self::compact`]: whether it was done; `None`
    /// when `abort` came first.
    async fn summarise<F: Future<Output = ()>>(
        &mut self,
        abort: &mut core::pin::Pin<&mut F>,
        emit: &mut dyn FnMut(SessionEvent),
    ) -> Option<bool> {
        let Some(at) = crate::compact::cut(&self.history) else {
            return Some(false);
        };
        let Ok(token) = self.access.access_token().await else {
            return Some(false);
        };
        let system = vec!["You summarise conversations for the ERPC assistant.".to_owned()];
        let messages = vec![json!({
            "role": "user",
            "content": format!(
                "{}\n\n<conversation>\n{}</conversation>",
                crate::compact::INSTRUCTIONS,
                crate::compact::transcript(&self.history[..at])
            ),
        })];
        let request = ChatRequest {
            system: &system,
            messages: &messages,
            model: if self.sizes_refused {
                erpc_api::ai::FALLBACK_MODEL
            } else {
                erpc_api::ai::QUICK_MODEL
            },
            max_tokens: 1500,
            effort: erpc_api::ai::Effort::Low,
            thinking: false,
            tools: &[],
        };
        let mut quiet = |_: &str| {};
        let chat = erpc_api::ai::chat(&self.client, &token, &request, &mut quiet);
        tokio::pin!(chat);
        let result = tokio::select! {
            result = &mut chat => result,
            () = abort.as_mut() => return None,
        };
        let summary = match result {
            Ok(answer)
                if answer.stop_reason.as_deref() != Some("refusal")
                    && !answer.text.trim().is_empty() =>
            {
                answer.text
            }
            _ => return Some(false),
        };
        let kept = self.history.split_off(at);
        self.archived.append(&mut self.history);
        self.history = crate::compact::rebuilt(&summary, &kept);
        emit(SessionEvent::Compacted { messages: at });
        Some(true)
    }

    /// One request, streamed through `emit`; none when `abort` came first.
    async fn ask<F: Future<Output = ()>>(
        &mut self,
        text: &str,
        policy: &mut crate::policy::TurnPolicy,
        token: &SecretString,
        tools: &[Value],
        abort: &mut core::pin::Pin<&mut F>,
        emit: &mut dyn FnMut(SessionEvent),
    ) -> Option<Result<erpc_api::ai::Answer, ApiError>> {
        loop {
            // The request borrows the session and `emit` until it ends here.
            let result = {
                let mut on_text = |text: &str| {
                    emit(SessionEvent::TextDelta {
                        text: text.to_owned(),
                    });
                };
                let request = ChatRequest {
                    system: &self.system,
                    messages: &self.history,
                    model: policy.model,
                    max_tokens: policy.max_tokens,
                    effort: policy.effort,
                    thinking: policy.thinking,
                    tools,
                };
                let chat = erpc_api::ai::chat(&self.client, token, &request, &mut on_text);
                tokio::pin!(chat);
                tokio::select! {
                    result = &mut chat => Some(result),
                    () = abort.as_mut() => None,
                }
            };
            if matches!(result, Some(Err(ApiError::ModelNotAllowed(_)))) {
                let (again, turned_down) = self.on_not_offered(text, policy);
                if let Some(size) = turned_down {
                    emit(SessionEvent::SizeRefused {
                        size: size.name().to_owned(),
                    });
                }
                if again {
                    continue;
                }
            }
            self.settled |= policy.model != erpc_api::ai::QUICK_MODEL;
            return result;
        }
    }

    /// Runs the tools the model called, in order, and returns their
    /// results as `tool_result` blocks, one for each call, and whether
    /// `abort` came first. Calls not run then say so; a tool the person
    /// already said yes to is waited for, as what it sends cannot be called
    /// back (a start, a payment, a change to a server).
    async fn call_tools<F: Future<Output = ()>>(
        &self,
        calls: Vec<Value>,
        token: &SecretString,
        abort: &mut core::pin::Pin<&mut F>,
        emit: &mut dyn FnMut(SessionEvent),
    ) -> (Vec<Value>, bool) {
        let mut results = Vec::with_capacity(calls.len());
        let mut stopped = false;
        for call in calls {
            let field = |name: &str| {
                call.get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let (id, name) = (field("id"), field("name"));
            if stopped {
                results.push(json!({
                    "type": "tool_result",
                    "tool_use_id": id,
                    "content": "not run: the user stopped the turn",
                    "is_error": true,
                }));
                continue;
            }
            emit(SessionEvent::ToolUseStart {
                id: id.clone(),
                name: name.clone(),
                args: call.get("input").cloned().unwrap_or_else(|| json!({})),
            });
            let input = call.get("input").cloned().unwrap_or_else(|| json!({}));
            let said_yes = core::cell::Cell::new(false);
            let watched = self.confirm.as_deref().map(|inner| Watched {
                inner,
                said_yes: &said_yes,
            });
            let tool = crate::tools::run(
                &name,
                &input,
                &self.client,
                token,
                crate::tools::Helpers {
                    confirm: watched.as_ref().map(|w| w as &dyn crate::confirm::Confirm),
                    wallet: self.wallet.as_deref(),
                    servers: self.servers.as_deref(),
                    memory: self.memory.as_ref(),
                    shell: self.shell.as_deref(),
                    allowed: Some(&self.allowed),
                    browser: self.browser.as_deref(),
                },
            );
            tokio::pin!(tool);
            let finished = tokio::select! {
                result = &mut tool => Some(result),
                () = abort.as_mut() => None,
            };
            let result = if let Some(result) = finished {
                result
            } else {
                stopped = true;
                // A command is stopped as Ctrl-C would stop it in a
                // terminal: dropping it kills it.
                if said_yes.get() && name != "run_command" {
                    emit(SessionEvent::ToolProgress {
                        label: t!("session.finishing"),
                    });
                    tool.await
                } else {
                    Err("stopped by the user before it finished".to_owned())
                }
            };
            let ok = result.is_ok();
            let content = result.unwrap_or_else(|why| why);
            emit(SessionEvent::ToolResult {
                id: id.clone(),
                ok,
                content: content.clone(),
            });
            let mut block = json!({ "type": "tool_result", "tool_use_id": id, "content": content });
            if !ok {
                block["is_error"] = json!(true);
            }
            results.push(block);
        }
        (results, stopped)
    }
}

/// The person's [`crate::confirm::Confirm`], noting a yes: from then on the
/// tool is sending what was agreed, and a stopped turn waits for it.
struct Watched<'a> {
    inner: &'a dyn crate::confirm::Confirm,
    said_yes: &'a core::cell::Cell<bool>,
}

impl crate::confirm::Confirm for Watched<'_> {
    fn confirm<'a>(
        &'a self,
        ask: &'a crate::confirm::Confirmation,
    ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
        Box::pin(async move {
            let yes = self.inner.confirm(ask).await;
            if yes {
                self.said_yes.set(true);
            }
            yes
        })
    }

    fn allow<'a>(
        &'a self,
        ask: &'a crate::confirm::Confirmation,
    ) -> core::pin::Pin<Box<dyn Future<Output = crate::confirm::Allow> + 'a>> {
        Box::pin(async move {
            let allow = self.inner.allow(ask).await;
            if allow != crate::confirm::Allow::No {
                self.said_yes.set(true);
            }
            allow
        })
    }

    fn choose<'a>(
        &'a self,
        question: &'a crate::confirm::Question,
    ) -> core::pin::Pin<Box<dyn Future<Output = crate::confirm::Answer> + 'a>> {
        self.inner.choose(question)
    }
}

/// The most requests one turn makes: the answer, and the tool calls before
/// it. A model that keeps calling tools is stopped here rather than left to
/// spend the account's tokens.
const MAX_ROUNDS: usize = 24;

/// An API error as a person should read it: in ERPC's words, never in
/// those of a provider, a proxy or the network library.
fn describe(error: &ApiError) -> String {
    match error {
        ApiError::Unauthorized => t!("session.expired"),
        ApiError::Chat {
            trouble,
            status,
            reference,
        } => trouble.line(*status, reference.as_deref(), crate::i18n::lang()),
        ApiError::Http(_) => t!("session.unreachable"),
        ApiError::NoAccount => t!("session.no_account"),
        _ => erpc_api::ai::ChatTrouble::Failed
            .text(crate::i18n::lang())
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Access, RunState, Session, SessionEvent};
    use secrecy::SecretString;
    use serde_json::json;

    /// Never signs in: these tests do not reach the network.
    struct NoAccess;

    impl Access for NoAccess {
        fn access_token(&self) -> impl Future<Output = Result<SecretString, String>> {
            std::future::ready(Err("no access in tests".to_owned()))
        }
    }

    #[test]
    fn events_have_the_gateway_protocols_shape() {
        let cases = [
            (
                SessionEvent::TextDelta { text: "hi".into() },
                json!({ "type": "text_delta", "text": "hi" }),
            ),
            (
                SessionEvent::Status {
                    state: RunState::Running,
                    label: None,
                },
                json!({ "type": "status", "state": "running" }),
            ),
            (SessionEvent::Complete, json!({ "type": "complete" })),
            (
                SessionEvent::SizeRefused {
                    size: "xlarge".into(),
                },
                json!({ "type": "size_refused", "size": "xlarge" }),
            ),
            (
                SessionEvent::Aborted { reason: None },
                json!({ "type": "aborted" }),
            ),
            (
                SessionEvent::Error {
                    message: "x".into(),
                },
                json!({ "type": "error", "message": "x" }),
            ),
        ];
        for (event, expected) in cases {
            assert_eq!(serde_json::to_value(&event).expect("serialises"), expected);
        }
    }

    #[test]
    fn a_chosen_size_turned_down_steps_down_to_large_and_only_then_to_none() {
        use super::{Retry, retry_after_refusal};
        use erpc_api::ai::{FALLBACK_MODEL, Size};
        for size in [Size::Small, Size::Medium, Size::Xlarge] {
            assert_eq!(
                retry_after_refusal(Some(size), size.model()),
                Retry::Large(size)
            );
        }
        // Large is what a step down asks for: turned down too, the service
        // does not know the sizes.
        assert_eq!(
            retry_after_refusal(Some(Size::Large), Size::Large.model()),
            Retry::Recommended
        );
        assert_eq!(
            retry_after_refusal(None, Size::Large.model()),
            Retry::Recommended
        );
        assert_eq!(
            retry_after_refusal(Some(Size::Xlarge), Size::Large.model()),
            Retry::Recommended
        );
        assert_eq!(retry_after_refusal(None, FALLBACK_MODEL), Retry::Nothing);
        assert_eq!(
            retry_after_refusal(Some(Size::Xlarge), FALLBACK_MODEL),
            Retry::Nothing
        );
    }

    #[test]
    fn a_turn_asks_for_the_chosen_size_until_the_service_turns_the_sizes_down() {
        use erpc_api::ai::{FALLBACK_MODEL, QUICK_MODEL, Size};
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        assert_eq!(session.turn_policy("hi").model, QUICK_MODEL);
        session.set_size(Some(Size::Xlarge));
        assert_eq!(session.turn_policy("hi").model, Size::Xlarge.model());
        session.sizes_refused = true;
        assert_eq!(session.turn_policy("hi").model, FALLBACK_MODEL);
    }

    #[test]
    fn a_turned_down_size_steps_down_once_and_is_reported_once() {
        use erpc_api::ai::{FALLBACK_MODEL, Size};
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        session.set_size(Some(Size::Xlarge));
        let mut policy = session.turn_policy("deploy");
        // xlarge turned down: large next, xlarge reported, auto after.
        assert_eq!(
            session.on_not_offered("deploy", &mut policy),
            (true, Some(Size::Xlarge))
        );
        assert_eq!(policy.model, Size::Large.model());
        assert_eq!(session.size(), None);
        assert!(!session.sizes_refused());
        // large turned down too: the recommended model, nothing to report.
        assert_eq!(session.on_not_offered("deploy", &mut policy), (true, None));
        assert_eq!(policy.model, FALLBACK_MODEL);
        assert!(session.sizes_refused());
        // The recommended model turned down: nothing left to ask.
        assert_eq!(session.on_not_offered("deploy", &mut policy), (false, None));

        // A chosen large turned down: the sizes go, and large is reported.
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        session.set_size(Some(Size::Large));
        let mut policy = session.turn_policy("deploy");
        assert_eq!(
            session.on_not_offered("deploy", &mut policy),
            (true, Some(Size::Large))
        );
        assert_eq!(policy.model, FALLBACK_MODEL);
        assert_eq!(session.size(), None);
    }

    #[test]
    fn a_chosen_size_lasts_through_a_new_conversation() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        assert_eq!(session.size(), None);
        session.set_size(Some(erpc_api::ai::Size::Xlarge));
        session.reset();
        assert_eq!(session.size(), Some(erpc_api::ai::Size::Xlarge));
        session.set_size(None);
        assert_eq!(session.size(), None);
    }

    #[test]
    fn a_guess_at_the_next_message_needs_an_answer_and_a_token() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        session.turn_token = Some(SecretString::from("t"));
        assert!(session.next_message().is_none(), "nothing answered yet");
        session
            .restore(
                vec![
                    json!({ "role": "user", "content": "balance?" }),
                    json!({ "role": "assistant", "content": [{ "type": "text", "text": "€8.86" }] }),
                ],
                false,
            )
            .expect("restored");
        let next = session.next_message().expect("a guess to fetch");
        assert_eq!(next.model, erpc_api::ai::QUICK_MODEL);
        assert!(next.prompt.contains("assistant: €8.86"));
        // A chosen size is for the conversation's turns, not the guess.
        session.set_size(Some(erpc_api::ai::Size::Xlarge));
        assert_eq!(
            session.next_message().expect("a guess").model,
            erpc_api::ai::QUICK_MODEL
        );
        session.sizes_refused = true;
        assert_eq!(
            session.next_message().expect("a guess").model,
            erpc_api::ai::FALLBACK_MODEL
        );
        session.turn_token = None;
        assert!(session.next_message().is_none(), "no turn had a token");
    }

    #[tokio::test]
    async fn a_turn_that_fails_leaves_nothing_in_the_history() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        let mut events = Vec::new();
        let turn = session
            .send("hi", std::future::pending(), &mut |e| events.push(e))
            .await;
        assert_eq!(turn, super::Turn::Failed);
        assert!(session.is_empty(), "the question left with the turn");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::Error { .. }))
        );
    }

    #[test]
    fn a_saved_conversation_is_picked_up_only_in_a_shape_that_can_continue() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        let good = vec![
            json!({"role": "user", "content": "hi"}),
            json!({"role": "assistant", "content": [{"type": "text", "text": "hello"}]}),
        ];
        session.restore(good, true).expect("a whole turn");
        assert_eq!(session.snapshot().0.len(), 2);
        assert!(session.snapshot().1);
        let half = vec![json!({"role": "user", "content": "hi"})];
        assert!(session.restore(half, false).is_err());
        let swapped = vec![
            json!({"role": "assistant", "content": "x"}),
            json!({"role": "user", "content": "y"}),
        ];
        assert!(session.restore(swapped, false).is_err());
    }

    #[test]
    fn a_turn_that_ran_tools_keeps_them_when_it_ends_without_an_answer() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        let earlier = json!({"role": "assistant", "content": "earlier"});
        let question = json!({"role": "user", "content": "start a VPS"});
        let call = json!({"role": "assistant", "content": [
            {"type": "tool_use", "id": "a", "name": "start_hourly", "input": {}}
        ]});
        let results = json!({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "a", "content": "{\"started\":true}"}
        ]});
        let unanswered = json!({"role": "assistant", "content": [
            {"type": "tool_use", "id": "b", "name": "secure_vps", "input": {}}
        ]});
        session.history = vec![
            earlier.clone(),
            question.clone(),
            call.clone(),
            results.clone(),
            unanswered,
        ];
        session.close_unanswered(1, true);
        let history = &session.history;
        assert_eq!(history[..4], [earlier.clone(), question, call, results]);
        assert_eq!(history.len(), 5, "a note closes it: {history:?}");
        assert_eq!(history[4]["role"], "assistant");
        assert!(
            history[4]["content"]
                .as_str()
                .is_some_and(|t| t.contains("stopped"))
        );
        // No tool ran: the question goes.
        session.history = vec![earlier.clone(), json!({"role": "user", "content": "hi"})];
        session.close_unanswered(1, false);
        assert_eq!(session.history, [earlier]);
    }

    #[test]
    fn errors_are_told_in_the_language_of_the_run() {
        use erpc_api::ApiError;
        use erpc_core::i18n::Lang;

        let english = super::describe(&ApiError::Unauthorized);
        assert!(english.contains("`erpc login`"), "{english}");
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let said = crate::i18n::speaking(lang, || super::describe(&ApiError::Unauthorized));
            assert_ne!(said, english, "{lang:?}");
            assert!(said.contains("`erpc login`"), "{said}");
            let busy = crate::i18n::speaking(lang, || {
                super::describe(&ApiError::Chat {
                    trouble: erpc_api::ai::ChatTrouble::Busy,
                    status: 529,
                    reference: Some("ray-1".to_owned()),
                })
            });
            assert!(busy.contains("529") && busy.contains("ray-1"), "{busy}");
            assert!(!busy.contains("busy right now"), "{busy}");
        }
    }

    #[test]
    fn a_new_conversation_summarises_at_the_usual_size() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        session.compact_not_before = 1_000_000;
        session.reset();
        assert_eq!(session.compact_not_before, 0);
    }

    #[test]
    fn a_new_or_restored_conversation_takes_back_every_command() {
        let client = erpc_auth::AuthClient::new().expect("client");
        let mut session = Session::new(NoAccess, client, Vec::new());
        session.allowed.allow_everything();
        session.reset();
        assert!(
            !session.allowed.everything(),
            "/new and /clear take it back"
        );
        session.allowed.allow_everything();
        session.restore(Vec::new(), false).expect("restored");
        assert!(
            !session.allowed.everything(),
            "a conversation picked up starts asking"
        );
    }

    #[tokio::test]
    async fn a_yes_is_noted_so_a_stop_waits_for_what_was_agreed() {
        use crate::confirm::{Confirm, Confirmation};

        struct Says(bool);
        impl Confirm for Says {
            fn confirm<'a>(
                &'a self,
                _: &'a Confirmation,
            ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
                Box::pin(std::future::ready(self.0))
            }
        }
        let ask = Confirmation {
            title: String::new(),
            lines: Vec::new(),
        };
        for yes in [false, true] {
            let said_yes = core::cell::Cell::new(false);
            let watched = super::Watched {
                inner: &Says(yes),
                said_yes: &said_yes,
            };
            assert_eq!(watched.confirm(&ask).await, yes);
            assert_eq!(said_yes.get(), yes);
        }
    }
}
