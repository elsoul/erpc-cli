// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The ERPC AI chat: `POST /v3/ai/chat`, a messages request, read
//! as a server-sent event stream.

use erpc_auth::AuthClient;
use erpc_auth::credential::Audience;
use erpc_core::i18n::Lang;
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::ApiError;

/// The chat endpoint.
pub const CHAT_URL: &str = "https://user-api.erpc.global/v3/ai/chat";

/// The plan and what is left of it.
pub const USAGE_URL: &str = "https://user-api.erpc.global/v3/ai/usage";

/// The account's AI plan, as `GET /v3/ai/usage` reports it.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Usage {
    /// The plan's key: `free`, `freeAuth`, `developer`, `business`, `pro`,
    /// or one of those with `Hourly` after it.
    pub ai_plan: String,
    /// Tokens left to use.
    pub remaining_tokens: f64,
    /// The plan's allowance, bonus included.
    pub max_tokens: f64,
    /// Whether the account is suspended from AI use.
    #[serde(default)]
    pub suspended: bool,
}

/// Fetches the account's AI plan and remaining tokens.
///
/// # Errors
///
/// Returns [`ApiError`] when the request fails or the reply cannot be read.
pub async fn usage(client: &AuthClient, access_token: &SecretString) -> Result<Usage, ApiError> {
    let (status, body) = client
        .get_with_token(Audience::AuthApi, USAGE_URL, access_token)
        .await?;
    match status {
        200 => parse_usage(&body),
        401 | 403 => Err(ApiError::Unauthorized),
        other => Err(ApiError::Status(other)),
    }
}

/// Reads the plan out of `{"success": true, "message": {...}}`.
fn parse_usage(body: &str) -> Result<Usage, ApiError> {
    let value: Value =
        serde_json::from_str(body).map_err(|e| ApiError::Malformed(e.to_string()))?;
    let object = value.get("message").unwrap_or(&value);
    serde_json::from_value(object.clone()).map_err(|e| ApiError::Malformed(e.to_string()))
}

/// A model size. The service names its models by size and decides itself
/// which model each size is: this client asks for a size, never a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    /// The quickest.
    Small,
    /// Between small and large.
    Medium,
    /// The one ordinary turns use.
    Large,
    /// The most capable, which uses more of the plan per token.
    Xlarge,
}

impl Size {
    /// Every size, smallest first.
    pub const ALL: [Self; 4] = [Self::Small, Self::Medium, Self::Large, Self::Xlarge];

    /// The name a person types: `small`, `medium`, `large` or `xlarge`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Xlarge => "xlarge",
        }
    }

    /// What a request's `model` says for it.
    #[must_use]
    pub const fn model(self) -> &'static str {
        match self {
            Self::Small => "erpc-ai-small",
            Self::Medium => "erpc-ai-medium",
            Self::Large => "erpc-ai-large",
            Self::Xlarge => "erpc-ai-xlarge",
        }
    }
}

impl core::str::FromStr for Size {
    type Err = String;

    /// A size by its name, `xlarge`, or by its model, `erpc-ai-xlarge`,
    /// in any case.
    fn from_str(text: &str) -> Result<Self, String> {
        let text = text.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|size| text == size.name() || text == size.model())
            .ok_or_else(|| {
                let names: Vec<&str> = Self::ALL.iter().map(|size| size.name()).collect();
                format!("{text}: not one of {}", names.join(", "))
            })
    }
}

/// The large model, for ordinary turns.
pub const DEFAULT_MODEL: &str = Size::Large.model();

/// The small model, for small talk. The large model thinks before every
/// answer, which is wasted on a greeting; this one answers at once.
pub const QUICK_MODEL: &str = Size::Small.model();

/// No model at all, which every version of the service answers with its
/// recommended one. Asked for when a size is turned down; the request then
/// carries no `model` field.
pub const FALLBACK_MODEL: &str = "";

/// How hard the model works on a turn, as the chat endpoint names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effort {
    /// Quick replies: greetings, thanks, one-line facts.
    Low,
    /// Ordinary questions.
    Medium,
    /// Operations where a mistake costs something.
    High,
}

impl Effort {
    /// The API's name for it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// One request: what to send, and how hard to think about it.
#[derive(Debug, Clone)]
pub struct ChatRequest<'a> {
    /// The system prompt, as text blocks; the last one is marked for the
    /// prompt cache.
    pub system: &'a [String],
    /// The conversation, ending with the user's turn.
    pub messages: &'a [Value],
    /// The model.
    pub model: &'a str,
    /// The longest answer asked for, in tokens.
    pub max_tokens: u32,
    /// How hard to think.
    pub effort: Effort,
    /// Whether to think at all before answering. Off is the fastest reply.
    pub thinking: bool,
    /// Tools the model may call, as the chat endpoint takes them (`name`,
    /// `description`, `input_schema`). Empty sends none. The gateway takes
    /// only tools the caller runs: tools the service would run itself are
    /// refused.
    pub tools: &'a [Value],
}

/// The conversation with a cache breakpoint on its last message, so the
/// history up to it is read from the cache on the next turn instead of
/// processed again.
fn with_history_breakpoint(messages: &[Value]) -> Vec<Value> {
    let mut out = messages.to_vec();
    if let Some(last) = out.last_mut() {
        let content = last.get("content").cloned().unwrap_or(Value::Null);
        let mut blocks = match content {
            Value::String(text) => vec![json!({ "type": "text", "text": text })],
            Value::Array(blocks) => blocks,
            _ => return out,
        };
        if let Some(Value::Object(block)) = blocks.last_mut() {
            block.insert("cache_control".to_owned(), json!({ "type": "ephemeral" }));
        }
        last["content"] = Value::Array(blocks);
    }
    out
}

impl ChatRequest<'_> {
    /// The request body.
    #[must_use]
    pub fn body(&self) -> Value {
        let last = self.system.len().saturating_sub(1);
        let system: Vec<Value> = self
            .system
            .iter()
            .enumerate()
            .map(|(n, text)| {
                if n == last {
                    // Cached across turns: the prompt is the same each time,
                    // so after the first turn it is not read again.
                    json!({ "type": "text", "text": text, "cache_control": { "type": "ephemeral" } })
                } else {
                    json!({ "type": "text", "text": text })
                }
            })
            .collect();
        let mut body = json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "stream": true,
            "messages": with_history_breakpoint(self.messages),
        });
        if self.model.is_empty()
            && let Some(fields) = body.as_object_mut()
        {
            fields.remove("model");
        }
        if self.thinking {
            // Thought, but not shown: the console prints the answer only,
            // and a summary streamed first would only delay it.
            body["thinking"] = json!({ "type": "adaptive", "display": "omitted" });
            body["output_config"] = json!({ "effort": self.effort.as_str() });
        }
        if !self.tools.is_empty() {
            body["tools"] = Value::Array(self.tools.to_vec());
        }
        body
    }
}

/// One finished answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answer {
    /// The text of the answer.
    pub text: String,
    /// Every content block, as the model produced it: thinking (with its
    /// signature), text, tool calls with their input, and anything else.
    /// This, not `text`, goes back into the history -- models that think
    /// expect their thinking blocks returned unchanged on the next turn.
    pub content: Vec<Value>,
    /// Why it ended, as the stream said: `end_turn`, `max_tokens`,
    /// `refusal`, …
    pub stop_reason: Option<String>,
    /// Why the model declined, when `stop_reason` is `refusal`.
    pub refusal: Option<Refusal>,
    /// Tokens read and written, when the stream said.
    pub input_tokens: Option<u64>,
    /// Tokens read from the prompt cache.
    pub cache_read_tokens: Option<u64>,
    /// Tokens written.
    pub output_tokens: Option<u64>,
}

/// A refusal's details, as the stream gave them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refusal {
    /// The category, when there is one: `cyber`, `bio`, …
    pub category: Option<String>,
    /// A sentence for a person, when there is one.
    pub explanation: Option<String>,
}

/// Splits a server-sent event stream into `(event, data)` pairs as bytes
/// arrive.
///
/// Kept as bytes until an event is complete: a chunk can end inside a
/// character, and decoding each chunk on its own would turn the halves of
/// one into two replacement characters.
#[derive(Debug, Default)]
pub struct SseParser {
    pending: Vec<u8>,
}

impl SseParser {
    /// Feeds bytes in, and returns every event they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<(String, String)> {
        // A carriage return is only ever part of a line ending: the data
        // is JSON, which writes one inside a string as `\r`.
        self.pending
            .extend(bytes.iter().copied().filter(|&b| b != b'\r'));
        let mut events = Vec::new();
        while let Some(end) = self.pending.windows(2).position(|w| w == b"\n\n") {
            let raw: Vec<u8> = self.pending.drain(..end + 2).collect();
            let block = String::from_utf8_lossy(&raw[..end]);
            let mut event = String::from("message");
            let mut data = Vec::new();
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("event:") {
                    v.trim().clone_into(&mut event);
                } else if let Some(v) = line.strip_prefix("data:") {
                    data.push(v.strip_prefix(' ').unwrap_or(v).to_owned());
                }
            }
            if !data.is_empty() {
                events.push((event, data.join("\n")));
            }
        }
        events
    }
}

/// Applies one event to `answer`, calling `on_text` with any new text.
///
/// # Errors
///
/// Returns the `type` of an `error` event, or why the stream cannot be
/// read.
pub fn apply(
    answer: &mut Answer,
    event: &str,
    data: &str,
    on_text: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let Ok(value) = serde_json::from_str::<Value>(data) else {
        return Ok(());
    };
    let kind = value.get("type").and_then(Value::as_str).unwrap_or(event);
    let index = value
        .get("index")
        .and_then(Value::as_u64)
        .and_then(|i| usize::try_from(i).ok());
    match kind {
        "message_start" => {
            answer.input_tokens = value
                .pointer("/message/usage/input_tokens")
                .and_then(Value::as_u64);
            answer.cache_read_tokens = value
                .pointer("/message/usage/cache_read_input_tokens")
                .and_then(Value::as_u64);
        }
        "content_block_start" => {
            if let (Some(index), Some(block)) = (index, value.get("content_block")) {
                while answer.content.len() <= index {
                    answer.content.push(Value::Null);
                }
                answer.content[index] = block.clone();
            }
        }
        "content_block_delta" => {
            let block = index.and_then(|i| answer.content.get_mut(i));
            let delta = value.get("delta");
            match delta.and_then(|d| d.get("type")).and_then(Value::as_str) {
                Some("text_delta") => {
                    let text = delta
                        .and_then(|d| d.get("text"))
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if let Some(block) = block {
                        append(block, "text", text);
                    }
                    answer.text.push_str(text);
                    on_text(text);
                }
                // The rest add to a field of the block: the delta's field,
                // and the block's. A tool call's input arrives as pieces of
                // JSON text, kept aside until the block ends.
                kind => {
                    let fields = match kind {
                        Some("thinking_delta") => Some(("thinking", "thinking")),
                        Some("signature_delta") => Some(("signature", "signature")),
                        Some("input_json_delta") => Some(("partial_json", PARTIAL_INPUT)),
                        _ => None,
                    };
                    if let (Some(block), Some((from, to))) = (block, fields)
                        && let Some(text) = delta.and_then(|d| d.get(from)).and_then(Value::as_str)
                    {
                        append(block, to, text);
                    }
                }
            }
        }
        "content_block_stop" => {
            if let Some(Value::Object(block)) = index.and_then(|i| answer.content.get_mut(i))
                && let Some(Value::String(json)) = block.remove(PARTIAL_INPUT)
                && !json.is_empty()
            {
                let input = serde_json::from_str::<Value>(&json)
                    .map_err(|_| "a tool call's input was not JSON".to_owned())?;
                block.insert("input".to_owned(), input);
            }
        }
        "message_delta" => {
            answer.stop_reason = value
                .pointer("/delta/stop_reason")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            if answer.stop_reason.as_deref() == Some("refusal") {
                let detail = |field: &str| {
                    value
                        .pointer(&format!("/delta/stop_details/{field}"))
                        .and_then(Value::as_str)
                        .map(printable)
                };
                answer.refusal = Some(Refusal {
                    category: detail("category"),
                    explanation: detail("explanation"),
                });
            }
            answer.output_tokens = value
                .pointer("/usage/output_tokens")
                .and_then(Value::as_u64);
        }
        "error" => {
            // Its kind only: the message is the provider's, in its words.
            let kind = value
                .pointer("/error/type")
                .and_then(Value::as_str)
                .unwrap_or("error");
            return Err(printable(kind));
        }
        _ => {}
    }
    Ok(())
}

/// Where a tool call's input collects while it streams. Not a field of
/// the chat format: removed when the block ends.
const PARTIAL_INPUT: &str = "erpc_partial_input";

/// Appends `text` to the string field `field` of a content block.
fn append(block: &mut Value, field: &str, text: &str) {
    if let Some(object) = block.as_object_mut() {
        let current = object
            .entry(field)
            .or_insert_with(|| Value::String(String::new()));
        if let Value::String(s) = current {
            s.push_str(text);
        }
    }
}

/// A message from the server, cut to one printable line.
fn printable(text: &str) -> String {
    text.chars()
        .filter(|&c| !c.is_control() && !crate::reorders(c))
        .take(300)
        .collect()
}

/// Why ERPC AI could not answer, as a person can act on it.
///
/// Built from the refusal's status and kind, never from its words: a
/// provider's or a proxy's message is theirs, names them, and can say more
/// than a user should see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChatTrouble {
    /// ERPC's security check stopped the request before it was read.
    Blocked,
    /// The account's tokens do not cover the request.
    NoTokens,
    /// ERPC AI is paused for this account.
    Suspended,
    /// The conversation is too long to send.
    TooLong,
    /// ERPC AI is busy or briefly unavailable.
    Busy,
    /// The request was not accepted as it was sent.
    NotAccepted,
    /// Anything else.
    Failed,
}

impl ChatTrouble {
    /// What happened and what to do, in `lang`.
    #[must_use]
    pub const fn text(self, lang: Lang) -> &'static str {
        match lang {
            Lang::En => match self {
                Self::Blocked => {
                    "ERPC's security check stopped this request. If the conversation quotes commands, start a new one with /new and try again."
                }
                Self::NoTokens => {
                    "Your ERPC AI tokens do not cover this request. Add tokens in the ERPC dashboard, or wait for the next reset. A long conversation sends more with every message: /new starts a short one, which may still fit."
                }
                Self::Suspended => {
                    "ERPC AI is paused for this account. Please contact ERPC support."
                }
                Self::TooLong => {
                    "This conversation is too long to send. Start a new one with /new."
                }
                Self::Busy => "ERPC AI is busy right now. Please try again in a moment.",
                Self::NotAccepted => {
                    "ERPC AI could not process this request. Try again, or start a new conversation with /new."
                }
                Self::Failed => "ERPC AI ran into an error. Please try again.",
            },
            Lang::Ja => match self {
                Self::Blocked => {
                    "ERPC のセキュリティチェックでリクエストが止められました。会話にコマンドが含まれている場合は、/new で新しい会話を始めてお試しください。"
                }
                Self::NoTokens => {
                    "ERPC AI のトークンが足りません。ERPC のダッシュボードでトークンを追加するか、次のリセットをお待ちください。長い会話はメッセージごとに多く消費します。/new で新しい会話にすると、残りで足りることがあります。"
                }
                Self::Suspended => {
                    "このアカウントでは ERPC AI が一時停止されています。ERPC サポートにお問い合わせください。"
                }
                Self::TooLong => {
                    "会話が長くなりすぎて送れません。/new で新しい会話を始めてください。"
                }
                Self::Busy => "ERPC AI が混み合っています。少し待ってからもう一度お試しください。",
                Self::NotAccepted => {
                    "このリクエストは処理できませんでした。もう一度送るか、/new で新しい会話を始めてお試しください。"
                }
                Self::Failed => "ERPC AI でエラーが発生しました。もう一度お試しください。",
            },
            Lang::Zh => match self {
                Self::Blocked => {
                    "ERPC 的安全检查拦截了此请求。如果对话中引用了命令，请用 /new 开始新对话后重试。"
                }
                Self::NoTokens => {
                    "ERPC AI 的 Token 不足以完成此请求。请在 ERPC 控制台添加 Token，或等待下次重置。对话越长，每条消息消耗越多：用 /new 开始新对话，剩余的 Token 可能仍然够用。"
                }
                Self::Suspended => "此账户的 ERPC AI 已暂停。请联系 ERPC 支持。",
                Self::TooLong => "对话太长，无法发送。请用 /new 开始新对话。",
                Self::Busy => "ERPC AI 当前繁忙，请稍后重试。",
                Self::NotAccepted => "ERPC AI 无法处理此请求。请重试，或用 /new 开始新对话。",
                Self::Failed => "ERPC AI 出错了，请重试。",
            },
            Lang::Ru => match self {
                Self::Blocked => {
                    "Проверка безопасности ERPC остановила этот запрос. Если в разговоре цитируются команды, начните новый с /new и повторите."
                }
                Self::NoTokens => {
                    "Токенов ERPC AI не хватает на этот запрос. Добавьте токены в панели ERPC или дождитесь следующего сброса. Длинный разговор расходует больше на каждое сообщение: новый, начатый с /new, может уложиться в остаток."
                }
                Self::Suspended => {
                    "ERPC AI приостановлен для этой учётной записи. Обратитесь в поддержку ERPC."
                }
                Self::TooLong => {
                    "Разговор слишком длинный, чтобы его отправить. Начните новый с /new."
                }
                Self::Busy => "ERPC AI сейчас перегружен. Повторите чуть позже.",
                Self::NotAccepted => {
                    "ERPC AI не смог обработать этот запрос. Повторите или начните новый разговор с /new."
                }
                Self::Failed => "В ERPC AI произошла ошибка. Повторите попытку.",
            },
        }
    }

    /// The text with the status and the reference ERPC support asks for.
    #[must_use]
    pub fn line(self, status: u16, reference: Option<&str>, lang: Lang) -> String {
        let text = self.text(lang);
        match (lang, reference) {
            (Lang::En, Some(r)) => format!("{text} (error {status}, reference {r})"),
            (Lang::En, None) => format!("{text} (error {status})"),
            (Lang::Ja, Some(r)) => format!("{text}（エラー {status}・参照 ID {r}）"),
            (Lang::Ja, None) => format!("{text}（エラー {status}）"),
            (Lang::Zh, Some(r)) => format!("{text}（错误 {status}，参考 ID {r}）"),
            (Lang::Zh, None) => format!("{text}（错误 {status}）"),
            (Lang::Ru, Some(r)) => format!("{text} (ошибка {status}, номер обращения {r})"),
            (Lang::Ru, None) => format!("{text} (ошибка {status})"),
        }
    }

    /// From the status alone.
    const fn of_status(status: u16) -> Self {
        match status {
            413 => Self::TooLong,
            429 | 500..=599 => Self::Busy,
            400..=499 => Self::NotAccepted,
            _ => Self::Failed,
        }
    }

    /// From the `type` of an error in the chat format, which user-api
    /// passes on from the provider and which can end a stream.
    fn of_provider_kind(kind: &str) -> Option<Self> {
        match kind {
            "rate_limit_error" | "overloaded_error" | "api_error" | "timeout_error" => {
                Some(Self::Busy)
            }
            "request_too_large" => Some(Self::TooLong),
            _ => None,
        }
    }

    /// From one of user-api's own error codes.
    fn of_code(code: &str) -> Option<Self> {
        match code {
            "ai_token_limit_reached" => Some(Self::NoTokens),
            "ai_suspended" => Some(Self::Suspended),
            "request_too_large" => Some(Self::TooLong),
            _ => None,
        }
    }
}

/// What the firewall's block page says; the other error pages in front of
/// user-api (a 5xx from the origin, a rate limit) do not.
const BLOCK_PAGE_MARKS: [&str; 2] = ["Attention Required! | Cloudflare", "you have been blocked"];

/// The error for a refused chat request, from its status and body. `ray`
/// is the reply's `cf-ray` header, when it has one: it is on every reply on
/// this host, user-api's own included, and finds the request in the logs.
fn refusal(status: u16, text: &str, ray: Option<String>, model: &str) -> ApiError {
    let parsed = serde_json::from_str::<Value>(text).ok();
    let field = |pointer: &str| {
        parsed
            .as_ref()
            .and_then(|v| v.pointer(pointer))
            .and_then(Value::as_str)
    };
    if status == 400 && field("/error") == Some("model_not_allowed") {
        return ApiError::ModelNotAllowed(model.to_owned());
    }
    let trouble = if parsed.is_none() {
        let blocked = status == 403
            && ray.is_some()
            && text.trim_start().starts_with('<')
            && BLOCK_PAGE_MARKS.iter().any(|mark| text.contains(mark));
        if blocked {
            ChatTrouble::Blocked
        } else {
            ChatTrouble::of_status(status)
        }
    } else if matches!(status, 429 | 500..=599) {
        // Whatever it says, it is worth waiting for: "no allocation right
        // now" comes back as a 503 under the same code as "no tokens".
        ChatTrouble::Busy
    } else {
        // user-api's own refusals carry a code in `error`. One it passes on
        // from the provider is in the chat format's error shape,
        // `{"type":"error","error":{"type":…,"message":…}}`.
        field("/error")
            .and_then(ChatTrouble::of_code)
            .or_else(|| field("/error/type").and_then(ChatTrouble::of_provider_kind))
            .unwrap_or_else(|| ChatTrouble::of_status(status))
    };
    ApiError::Chat {
        trouble,
        status,
        reference: ray,
    }
}

/// Sends the conversation and streams the answer through `on_text`.
///
/// `request.messages` is the conversation so far, in the chat format,
/// ending with the user's turn.
///
/// # Errors
///
/// Returns [`ApiError::Unauthorized`] for a refused session,
/// [`ApiError::ModelNotAllowed`] for a model the service does not offer,
/// [`ApiError::Chat`] for any other refusal or an error inside the answer,
/// and [`ApiError::Malformed`] when the stream breaks.
pub async fn chat(
    client: &AuthClient,
    access_token: &SecretString,
    request: &ChatRequest<'_>,
    on_text: &mut dyn FnMut(&str),
) -> Result<Answer, ApiError> {
    let body =
        serde_json::to_vec(&request.body()).map_err(|e| ApiError::Malformed(e.to_string()))?;
    let mut reply = client
        .post_json_streaming(Audience::AuthApi, CHAT_URL, access_token, body)
        .await?;
    match reply.status {
        200 => {}
        401 => return Err(ApiError::Unauthorized),
        status => {
            let ray = reply.header("cf-ray").map(printable);
            let text = reply.text().await;
            return Err(refusal(status, &text, ray, request.model));
        }
    }
    let mut parser = SseParser::default();
    let mut answer = Answer::default();
    while let Some(chunk) = reply.next_chunk().await.map_err(ApiError::Malformed)? {
        for (event, data) in parser.push(&chunk) {
            apply(&mut answer, &event, &data, on_text).map_err(|kind| ApiError::Chat {
                trouble: ChatTrouble::of_provider_kind(&kind).unwrap_or(ChatTrouble::Failed),
                status: 200,
                reference: None,
            })?;
        }
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::{Answer, CHAT_URL, ChatRequest, ChatTrouble, Effort, SseParser, apply, refusal};
    use crate::ApiError;
    use erpc_core::i18n::Lang;

    /// The trouble, status and reference of a chat refusal; panics on any
    /// other error.
    fn chat(error: &ApiError) -> (ChatTrouble, u16, Option<&str>) {
        match error {
            ApiError::Chat {
                trouble,
                status,
                reference,
            } => (*trouble, *status, reference.as_deref()),
            other => panic!("not a chat refusal: {other:?}"),
        }
    }

    /// The head of the firewall's block page.
    const BLOCK_PAGE: &str = "<!DOCTYPE html>\n<html><head><title>Attention Required! | Cloudflare</title></head><body><h1>Sorry, you have been blocked</h1>";

    /// A made-up Ray ID in Cloudflare's format.
    const RAY: &str = "0000000000000000-AMS";

    #[test]
    fn the_firewalls_block_page_is_a_block_with_its_reference() {
        let error = refusal(403, BLOCK_PAGE, Some(RAY.to_owned()), "m");
        assert_eq!(chat(&error), (ChatTrouble::Blocked, 403, Some(RAY)));
    }

    #[test]
    fn other_pages_in_front_of_user_api_are_not_called_a_block() {
        let gateway = "<!DOCTYPE html>\n<html><head><title>erpc.global | 502: Bad gateway</title>";
        let ray = || Some(RAY.to_owned());
        assert_eq!(
            chat(&refusal(502, gateway, ray(), "m")).0,
            ChatTrouble::Busy
        );
        assert_eq!(
            chat(&refusal(429, gateway, ray(), "m")).0,
            ChatTrouble::Busy
        );
        assert_eq!(
            chat(&refusal(403, gateway, ray(), "m")).0,
            ChatTrouble::NotAccepted
        );
        assert_eq!(
            chat(&refusal(503, BLOCK_PAGE, ray(), "m")).0,
            ChatTrouble::Busy
        );
        assert_eq!(
            chat(&refusal(403, BLOCK_PAGE, None, "m")).0,
            ChatTrouble::NotAccepted
        );
    }

    #[test]
    fn user_apis_own_codes_say_what_to_do() {
        let body = |code: &str| {
            format!(
                r#"{{"error":"{code}","plan":"developer","remaining_tokens":0,"message":"Token balance exhausted"}}"#
            )
        };
        let of = |status, code: &str| chat(&refusal(status, &body(code), None, "m")).0;
        assert_eq!(of(403, "ai_token_limit_reached"), ChatTrouble::NoTokens);
        assert_eq!(of(403, "ai_suspended"), ChatTrouble::Suspended);
        assert_eq!(of(413, "request_too_large"), ChatTrouble::TooLong);
        // The same code at a 503 means no allocation right now.
        assert_eq!(of(503, "ai_token_limit_reached"), ChatTrouble::Busy);
        assert_eq!(of(403, "something_new"), ChatTrouble::NotAccepted);
    }

    #[test]
    fn a_refusal_passed_on_from_the_provider_is_classed_by_its_kind() {
        let body = |kind: &str| {
            format!(
                r#"{{"type":"error","error":{{"type":"{kind}","message":"Provider says no"}}}}"#
            )
        };
        let of = |status, kind: &str| chat(&refusal(status, &body(kind), None, "m")).0;
        assert_eq!(of(529, "overloaded_error"), ChatTrouble::Busy);
        assert_eq!(of(413, "request_too_large"), ChatTrouble::TooLong);
        assert_eq!(of(403, "permission_error"), ChatTrouble::NotAccepted);
        assert_eq!(of(400, "invalid_request_error"), ChatTrouble::NotAccepted);
    }

    #[test]
    fn no_refusal_repeats_what_the_server_said() {
        let bodies = [
            r#"{"type":"error","error":{"type":"permission_error","message":"Provider says no"}}"#,
            r#"{"error":"ai_suspended","message":"Provider says no"}"#,
            "Provider says no",
            BLOCK_PAGE,
        ];
        for body in bodies {
            for status in [400, 403, 429, 502] {
                let error = refusal(status, body, Some(RAY.to_owned()), "m");
                let (trouble, ..) = chat(&error);
                for lang in Lang::ALL {
                    let line = trouble.line(status, Some(RAY), lang);
                    for word in ["Provider", "Cloudflare", "Attention", "<"] {
                        assert!(!line.contains(word), "{line}");
                    }
                }
                assert!(!error.to_string().contains("Provider"), "{error}");
            }
        }
    }

    #[test]
    fn a_line_carries_the_status_and_the_reference() {
        let line = ChatTrouble::Busy.line(503, Some(RAY), Lang::Ja);
        assert!(line.starts_with("ERPC AI が混み合っています"), "{line}");
        assert!(line.contains("503") && line.contains(RAY), "{line}");
        let line = ChatTrouble::Busy.line(503, None, Lang::En);
        assert!(line.ends_with("(error 503)"), "{line}");
        for lang in [Lang::Zh, Lang::Ru] {
            let line = ChatTrouble::Busy.line(503, Some(RAY), lang);
            assert!(line.contains("503") && line.contains(RAY), "{line}");
            assert_ne!(line, ChatTrouble::Busy.line(503, Some(RAY), Lang::En));
        }
    }

    #[test]
    fn a_model_the_service_does_not_offer_is_named() {
        let error = refusal(
            400,
            r#"{"error":"model_not_allowed"}"#,
            None,
            "erpc-ai-xlarge",
        );
        assert!(
            matches!(&error, ApiError::ModelNotAllowed(m) if m == "erpc-ai-xlarge"),
            "{error:?}"
        );
    }

    #[test]
    fn an_empty_refusal_is_classed_by_its_status() {
        assert_eq!(
            chat(&refusal(403, "", None, "m")).0,
            ChatTrouble::NotAccepted
        );
        assert_eq!(chat(&refusal(500, "", None, "m")).0, ChatTrouble::Busy);
    }

    #[test]
    fn the_fallback_sends_no_model_at_all() {
        let request = super::ChatRequest {
            system: &["s".to_owned()],
            messages: &[serde_json::json!({"role": "user", "content": "hi"})],
            model: super::FALLBACK_MODEL,
            max_tokens: 16_000,
            effort: super::Effort::Medium,
            thinking: true,
            tools: &[],
        };
        assert!(request.body().get("model").is_none());
    }

    #[test]
    fn the_plan_is_read_from_the_usage_reply() {
        let body = r#"{"success":true,"message":{"ai_plan":"developer","bonus":0,"max_tokens":4200000,"remaining_tokens":3150000.5,"suspended":false,"next_reset_at":null}}"#;
        let usage = super::parse_usage(body).expect("parsed");
        assert_eq!(usage.ai_plan, "developer");
        assert!((usage.remaining_tokens - 3_150_000.5).abs() < f64::EPSILON);
        assert!(super::parse_usage("<html>").is_err());
    }

    #[test]
    fn the_usage_endpoint_is_a_destination_the_allowlist_permits() {
        assert!(
            erpc_auth::allowlist::ensure_token_destination(
                erpc_auth::credential::Audience::AuthApi,
                super::USAGE_URL
            )
            .is_ok()
        );
    }

    #[test]
    fn a_quick_turn_uses_the_quick_model_without_thinking_and_caches_the_prompt() {
        let system = ["base".to_owned(), "skills".to_owned()];
        let body = ChatRequest {
            system: &system,
            messages: &[],
            model: super::QUICK_MODEL,
            max_tokens: 512,
            effort: Effort::Low,
            thinking: false,
            tools: &[],
        }
        .body();
        assert_eq!(body["model"], "erpc-ai-small");
        assert!(body.get("thinking").is_none(), "no thinking for small talk");
        assert!(body.get("tools").is_none(), "no tools, no field");
        assert!(body["system"][0].get("cache_control").is_none());
        assert_eq!(body["system"][1]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn the_chat_endpoint_is_a_declared_host() {
        assert!(erpc_core::endpoints::ensure_service_url(CHAT_URL).is_ok());
    }

    #[test]
    fn events_are_found_across_chunk_boundaries() {
        let mut parser = SseParser::default();
        assert!(
            parser
                .push(b"event: content_block_delta\ndata: {\"a\":")
                .is_empty()
        );
        let events = parser.push(b"1}\n\nevent: ping\ndata: {}\n\n");
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            ("content_block_delta".to_owned(), "{\"a\":1}".to_owned())
        );
    }

    #[test]
    fn a_character_split_between_chunks_arrives_whole() {
        let event = "data: {\"t\":\"在庫\"}\n\n".as_bytes();
        // Split inside the three bytes of 在.
        let cut = event.iter().position(|&b| b == 0xE5).expect("在") + 1;
        let mut parser = SseParser::default();
        assert!(parser.push(&event[..cut]).is_empty());
        let events = parser.push(&event[cut..]);
        assert_eq!(
            events,
            [("message".to_owned(), "{\"t\":\"在庫\"}".to_owned())]
        );
    }

    #[test]
    fn a_stream_becomes_an_answer() {
        let stream = concat!(
            "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":12}}}\r\n\r\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"lo\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        );
        let mut parser = SseParser::default();
        let mut answer = Answer::default();
        let mut shown = String::new();
        for (event, data) in parser.push(stream.as_bytes()) {
            apply(&mut answer, &event, &data, &mut |t| shown.push_str(t)).expect("no error");
        }
        assert_eq!(answer.text, "Hello");
        assert_eq!(shown, "Hello");
        assert_eq!(answer.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(
            (answer.input_tokens, answer.output_tokens),
            (Some(12), Some(3))
        );
    }

    #[test]
    fn thinking_and_text_blocks_are_rebuilt_for_replay() {
        let stream = concat!(
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig-1\"}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
        );
        let mut parser = SseParser::default();
        let mut answer = Answer::default();
        for (event, data) in parser.push(stream.as_bytes()) {
            apply(&mut answer, &event, &data, &mut |_| {}).expect("no error");
        }
        assert_eq!(answer.content.len(), 2);
        assert_eq!(answer.content[0]["type"], "thinking");
        assert_eq!(answer.content[0]["signature"], "sig-1");
        assert_eq!(answer.content[1]["text"], "Hi");
    }

    #[test]
    fn tools_are_sent_when_there_are_some() {
        let tools = [serde_json::json!({
            "name": "lookup",
            "description": "d",
            "input_schema": { "type": "object" },
        })];
        let body = ChatRequest {
            system: &["s".to_owned()],
            messages: &[],
            model: super::DEFAULT_MODEL,
            max_tokens: 512,
            effort: Effort::Low,
            thinking: false,
            tools: &tools,
        }
        .body();
        assert_eq!(body["tools"][0]["name"], "lookup");
    }

    #[test]
    fn a_tool_call_is_rebuilt_with_its_input() {
        let stream = concat!(
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"lookup\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"query\\\": \\\"東\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"京\\\"}\"}}\n\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"ping\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n",
        );
        let mut parser = SseParser::default();
        let mut answer = Answer::default();
        for (event, data) in parser.push(stream.as_bytes()) {
            apply(&mut answer, &event, &data, &mut |_| {}).expect("no error");
        }
        assert_eq!(answer.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(
            answer.content[0],
            serde_json::json!({ "type": "tool_use", "id": "toolu_1", "name": "lookup", "input": { "query": "東京" } })
        );
        assert_eq!(answer.content[1]["input"], serde_json::json!({}));
    }

    #[test]
    fn a_tool_call_whose_input_is_not_json_is_an_error() {
        let mut answer = Answer::default();
        for data in [
            "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"n\",\"input\":{}}}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"a\"}}",
        ] {
            apply(&mut answer, "message", data, &mut |_| {}).expect("no error yet");
        }
        assert!(
            apply(
                &mut answer,
                "message",
                "{\"type\":\"content_block_stop\",\"index\":0}",
                &mut |_| {}
            )
            .is_err()
        );
    }

    #[test]
    fn a_refusal_carries_its_reason() {
        let mut answer = Answer::default();
        apply(
            &mut answer,
            "message_delta",
            "{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"refusal\",\"stop_details\":{\"type\":\"refusal\",\"category\":\"cyber\",\"explanation\":\"not this\"}}}",
            &mut |_| {},
        )
        .expect("no error");
        let refusal = answer.refusal.expect("a refusal");
        assert_eq!(refusal.category.as_deref(), Some("cyber"));
        assert_eq!(refusal.explanation.as_deref(), Some("not this"));
    }

    #[test]
    fn only_the_last_message_carries_the_history_breakpoint() {
        let messages = [
            serde_json::json!({ "role": "user", "content": "a" }),
            serde_json::json!({ "role": "assistant", "content": [{ "type": "text", "text": "b" }] }),
            serde_json::json!({ "role": "user", "content": "c" }),
        ];
        let out = super::with_history_breakpoint(&messages);
        assert_eq!(out[0]["content"], "a");
        assert!(out[1]["content"][0].get("cache_control").is_none());
        assert_eq!(out[2]["content"][0]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn an_error_event_is_an_error() {
        let mut answer = Answer::default();
        let err = apply(
            &mut answer,
            "error",
            "{\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}",
            &mut |_| {},
        );
        // Its kind, not the provider's words.
        assert_eq!(err, Err("overloaded_error".to_owned()));
    }
}
