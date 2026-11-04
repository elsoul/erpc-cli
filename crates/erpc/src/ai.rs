// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc ai`: the terminal front end of an [`erpc_ai::session::Session`].
//!
//! This file only renders events and reads lines. What a turn does lives in
//! the session, so the gateway and a browser UI behave the same way.

use std::fmt::Write as _;
use std::io::{IsTerminal as _, Read as _, Write as _};

use erpc_ai::session::{Access, Session, SessionEvent, Turn};
use erpc_auth::credential::CredKey;
use erpc_auth::{AuthClient, session as auth_session};
use secrecy::SecretString;

use crate::commands::Outcome;
use crate::session;

/// A current access token from the store `erpc login` chose.
///
/// Read from the store once and kept in memory until it is about to
/// expire. Reading the store every turn cost one or two `op` calls with
/// 1Password -- seconds each -- before every answer.
pub(crate) struct StoreAccess {
    client: AuthClient,
    store: std::sync::Arc<dyn erpc_auth::CredentialStore + Send + Sync>,
    key: CredKey,
    state_dir: std::path::PathBuf,
    cached: std::sync::Mutex<Option<erpc_auth::Credential>>,
}

impl StoreAccess {
    pub(crate) fn open(client: AuthClient) -> Result<Self, Outcome> {
        let path = session::config_path().map_err(Outcome::Failed)?;
        let config = crate::config::load(&path).map_err(Outcome::Failed)?;
        let selection = session::plan_store(None, config.credential_store);
        let store = crate::store_for(selection.kind, config.credential_vault.as_deref())
            .map_err(|e| Outcome::from(crate::error::classify(&e)))?;
        Ok(Self {
            client,
            store,
            key: CredKey::new(session::LOGIN_AUDIENCE, session::local_account()),
            state_dir: session::state_dir().map_err(Outcome::Failed)?,
            cached: std::sync::Mutex::new(None),
        })
    }
}

impl Access for StoreAccess {
    async fn access_token(&self) -> Result<SecretString, String> {
        let now = crate::commands::now();
        if let Ok(cached) = self.cached.lock()
            && let Some(credential) = cached.as_ref()
            && !credential.needs_refresh(now)
        {
            return Ok(credential.access_token.clone());
        }
        let credential = auth_session::current_session(
            &self.client,
            &self.store,
            &self.key,
            &self.state_dir,
            now,
        )
        .await
        .map_err(|e| e.to_string())?;
        let token = credential.access_token.clone();
        if let Ok(mut cached) = self.cached.lock() {
            *cached = Some(credential);
        }
        Ok(token)
    }
}

/// Which conversation the console opens on.
pub enum Start {
    /// A new one.
    Fresh,
    /// A saved one: this id, or one picked from a list.
    Resume(Option<String>),
    /// The one answered last; a new one when there is none.
    Latest,
}

/// Runs `erpc ai`, bare `erpc`, and `erpc resume`.
pub async fn run(json: bool, message: Option<String>, start: Start) -> Outcome {
    let client = match AuthClient::new() {
        Ok(client) => client,
        Err(e) => return crate::error::classify(&e).into(),
    };
    let access = match StoreAccess::open(client.clone()) {
        Ok(access) => access,
        Err(outcome) => return outcome,
    };
    let mut system = erpc_ai::prompt::system(&crate::command_reference());
    // What is remembered goes last, so the blocks before it stay cached
    // when it changes.
    if let Some(remembered) = crate::memory::store().ok().and_then(|m| m.prompt()) {
        system.push(remembered);
    }

    // A question on the command line, or piped in: one answer, then done.
    let one_shot = match message {
        Some(text) => Some(text),
        None if !std::io::stdin().is_terminal() => {
            let mut text = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut text) {
                return Outcome::Failed(t!("ai.question_unreadable", error = e));
            }
            Some(text)
        }
        None => None,
    };
    if let Some(text) = one_shot {
        let mut session = equipped(Session::new(access, client, system));
        // Asked at the terminal only when a person is there to answer: a
        // question piped in, or --json, has no one to say yes.
        // So is a browser opened: a question piped in, from a script, or
        // with --json, has no one to look at it.
        if !json && std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            session = session
                .with_confirm(Box::new(TerminalConfirm::default()))
                .with_browser(Box::new(LocalBrowser::default()));
        }
        // Continuing a conversation: the answer goes on from it, and is
        // saved to it.
        if matches!(start, Start::Resume(None)) {
            return Outcome::Usage(t!("ai.pick_needs_console"));
        }
        // `-c` with nothing saved yet starts the conversation the next
        // `-c` continues.
        let continuing = matches!(start, Start::Latest);
        let mut record = match saved_conversation(start) {
            Ok(None) if continuing => match crate::conversations::Record::new() {
                Ok(record) => Some(record),
                Err(e) => return Outcome::Failed(e),
            },
            Ok(None) => None,
            Ok(Some(saved)) => {
                if let Err(e) = session.restore(saved.messages.clone(), saved.settled) {
                    return Outcome::Failed(t!("ai.conversation_broken", id = saved.id, error = e));
                }
                session.set_archived(saved.archived.clone());
                match crate::conversations::Record::continuing(&saved) {
                    Ok(record) => Some(record),
                    Err(e) => return Outcome::Failed(e),
                }
            }
            Err(e) => return Outcome::Failed(e),
        };
        let outcome = once(&mut session, json, text.trim()).await;
        if let Some(record) = record.as_mut() {
            let (history, settled) = session.snapshot();
            if !history.is_empty()
                && let Err(e) = record.save(history, session.archived(), settled)
            {
                return Outcome::Failed(e);
            }
        }
        return outcome;
    }
    if json {
        return Outcome::Usage(t!("ai.json_needs_question"));
    }
    if !std::io::stdout().is_terminal() {
        return Outcome::Usage(t!("ai.needs_terminal"));
    }
    // Which conversation to continue is settled before the screen is taken.
    let saved = match start {
        Start::Resume(None) => match pick_conversation() {
            Ok(saved) => Some(saved),
            Err(outcome) => return outcome,
        },
        start => match saved_conversation(start) {
            Ok(saved) => saved,
            Err(e) => return Outcome::Failed(e),
        },
    };
    let look = crate::tui::Look::detect();
    let mut terminal = ratatui::init();
    // ratatui's panic hook restores the terminal and reports a failure to do
    // so with `eprintln!`, which panics once the terminal is gone. A panic in a
    // panic hook aborts before the hooks behind it run, so the park goes in
    // front again.
    crate::interrupt::park_first_on_panic();
    let outcome = console(&mut terminal, look, access, client, system, saved).await;
    // Not `ratatui::restore`, which reports its own failure with
    // `eprintln!`. Once the terminal has closed that panics, a release build
    // aborts, and a session rotation the splash started goes with it.
    let _ = ratatui::try_restore();
    outcome
}

/// The saved conversation `start` names: none for a new one, or when
/// there is no latest one yet. Not for picking one from a list.
fn saved_conversation(start: Start) -> Result<Option<crate::conversations::Saved>, String> {
    match start {
        Start::Fresh | Start::Resume(None) => Ok(None),
        Start::Resume(Some(id)) => crate::conversations::load(&id).map(Some),
        Start::Latest => crate::conversations::list()?
            .first()
            .map(|latest| crate::conversations::load(&latest.id))
            .transpose(),
    }
}

/// The session, paying credit top-ups from the configured wallet when
/// there is one, and logging in to the user's VPSs with their key.
fn equipped(session: Session<StoreAccess>) -> Session<StoreAccess> {
    let session = session
        .with_wallet(Box::new(crate::credit_wallet::ConfigWallet))
        .with_servers(Box::new(crate::vps_access::SshServers))
        .with_shell(Box::new(erpc_ai::commands::LocalShell));
    match crate::memory::store() {
        Ok(memory) => session.with_memory(memory),
        Err(_) => session,
    }
}

/// This computer's browser, where there is one to open: not over SSH, and
/// on Linux only with a display. Given only to a session someone is
/// watching at a terminal.
struct LocalBrowser {
    /// Reads the environment `browser::decide` judges, so a test can
    /// describe a machine without being on one.
    var: fn(&str) -> Option<std::ffi::OsString>,
}

impl Default for LocalBrowser {
    fn default() -> Self {
        Self {
            var: |name| std::env::var_os(name),
        }
    }
}

impl erpc_ai::dashboard::Browser for LocalBrowser {
    fn open(&self, url: &str) -> Result<(), String> {
        crate::browser::decide(false, self.var).map_err(|why| why.to_string())?;
        crate::browser::open(url)
    }
}

/// Asks on standard error and reads the answer from standard input, for
/// `erpc ai -m` at a terminal, in the language of the run.
#[derive(Default)]
pub(crate) struct TerminalConfirm {
    _private: (),
}

/// Whether a typed line says yes, in any language erpc speaks.
fn says_yes(line: &str) -> bool {
    matches!(
        line.trim().to_lowercase().as_str(),
        "y" | "yes" | "はい" | "是" | "是的" | "да" | "д"
    )
}

impl erpc_ai::confirm::Confirm for TerminalConfirm {
    fn confirm<'a>(
        &'a self,
        ask: &'a erpc_ai::confirm::Confirmation,
    ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
        // At a terminal the answer is picked, the cursor on stop; typed
        // only where the answer comes on a pipe.
        if crate::session::has_terminal() {
            let text = ask.text();
            let rows = [t!("tui.picker.yes"), t!("tui.picker.no")];
            return Box::pin(async move {
                tokio::task::spawn_blocking(move || {
                    eprintln!();
                    crate::prompt::pick(&text, &rows, Some(1)) == Ok(0)
                })
                .await
                .unwrap_or(false)
            });
        }
        let question = format!("\n{}\n{} ", ask.text(), t!("ai.go_ahead"));
        Box::pin(async move {
            let answer = tokio::task::spawn_blocking(move || {
                let mut err = std::io::stderr();
                let _ = err.write_all(question.as_bytes());
                let _ = err.flush();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).ok().map(|_| line)
            })
            .await
            .ok()
            .flatten();
            answer.is_some_and(|line| says_yes(&line))
        })
    }

    fn choose<'a>(
        &'a self,
        question: &'a erpc_ai::confirm::Question,
    ) -> core::pin::Pin<Box<dyn Future<Output = erpc_ai::confirm::Answer> + 'a>> {
        let mut text = format!("\n{}\n", question.question);
        for (i, (label, detail)) in question.options.iter().enumerate() {
            let _ = match detail {
                Some(detail) => writeln!(text, "  {}. {label}  {detail}", i + 1),
                None => writeln!(text, "  {}. {label}", i + 1),
            };
        }
        text.push_str(&if question.multiple {
            t!("ai.choose.several")
        } else {
            t!("ai.choose.one")
        });
        text.push(' ');
        let again = format!("{} ", t!("ai.choose.again"));
        let (count, multiple) = (question.options.len(), question.multiple);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let mut err = std::io::stderr();
                let _ = err.write_all(text.as_bytes());
                loop {
                    let _ = err.flush();
                    let mut line = String::new();
                    match std::io::stdin().read_line(&mut line) {
                        Ok(0) | Err(_) => return erpc_ai::confirm::Answer::OwnWords,
                        Ok(_) => {}
                    }
                    if let Some(answer) = picked(&line, count, multiple) {
                        return answer;
                    }
                    let _ = err.write_all(again.as_bytes());
                }
            })
            .await
            .unwrap_or(erpc_ai::confirm::Answer::OwnWords)
        })
    }
}

/// What a typed line answers: the options its numbers name, `1` being the
/// first, or else the line itself as the person's own words, numbers that
/// name no option included (an amount of their own, say). `None` when it
/// is empty, to ask again.
fn picked(line: &str, count: usize, multiple: bool) -> Option<erpc_ai::confirm::Answer> {
    use erpc_ai::confirm::Answer;
    let parts: Vec<&str> = line
        .split([',', ' ', '、'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }
    let numbers: Option<Vec<usize>> = parts.iter().map(|p| p.parse().ok()).collect();
    let own_words = || Some(Answer::Said(line.trim().to_owned()));
    let Some(numbers) = numbers else {
        return own_words();
    };
    let mut rows = Vec::new();
    for n in numbers {
        if !(1..=count).contains(&n) || rows.contains(&(n - 1)) {
            return own_words();
        }
        rows.push(n - 1);
    }
    if multiple || rows.len() == 1 {
        Some(Answer::Picked(rows))
    } else {
        own_words()
    }
}

/// The splash while signing in, then the console, on one full screen.
async fn console(
    terminal: &mut ratatui::DefaultTerminal,
    look: crate::tui::Look,
    access: StoreAccess,
    client: AuthClient,
    system: Vec<String>,
    saved: Option<crate::conversations::Saved>,
) -> Outcome {
    use crate::tui::splash::{self, Played, Words};

    let (tagline, connecting, signed_in) = (
        t!("ai.splash.tagline"),
        t!("ai.splash.connecting"),
        t!("ai.splash.signed_in"),
    );
    let words = Words {
        tagline: &tagline,
        connecting: &connecting,
        signed_in: &signed_in,
    };
    // Signing in and reading the account happen under the splash, so the
    // first answer does not wait for them.
    let played = splash::play(terminal, look, &words, async {
        let (user, usage) = connect(&access, &client).await?;
        let label = user.label_for_display();
        Ok(((label.clone(), usage), label))
    })
    .await;
    let (account, usage) = match played {
        Ok(Played::Ready(ready)) => ready,
        Ok(Played::Failed(e)) => return not_signed_in(&e),
        Ok(Played::Cancelled) => return Outcome::Done(String::new()),
        Err(e) => return Outcome::Failed(t!("ai.draw_failed", error = e)),
    };

    let config_path = session::config_path().ok();
    let config = config_path
        .as_deref()
        .and_then(|p| crate::config::load(p).ok())
        .unwrap_or_default();
    let intro = crate::tui::chat::Intro {
        account,
        store: store_name(session::plan_store(None, config.credential_store).kind),
        chain: config_path
            .as_deref()
            .and_then(|p| crate::config::get(p, "default_chain").ok().flatten()),
        plan: usage.as_ref().map(plan_line),
    };
    // The console is at a terminal, with someone to see a browser open.
    let mut session = equipped(Session::new(access, client, system))
        .with_browser(Box::new(LocalBrowser::default()));
    let record = match &saved {
        Some(saved) => {
            if let Err(e) = session.restore(saved.messages.clone(), saved.settled) {
                return Outcome::Failed(t!("ai.conversation_broken", id = saved.id, error = e));
            }
            session.set_archived(saved.archived.clone());
            crate::conversations::Record::continuing(saved)
        }
        None => crate::conversations::Record::new(),
    };
    let mut record = match record {
        Ok(record) => record,
        Err(e) => return Outcome::Failed(e),
    };
    match crate::tui::chat::run(terminal, session, look, intro, &mut record).await {
        Ok(()) if record.saved() => Outcome::Done(t!("ai.to_continue", id = record.id())),
        Ok(()) => Outcome::Done(String::new()),
        Err(e) => Outcome::Failed(t!("ai.console_stopped", error = e)),
    }
}

/// Where the session is kept, as a person would say it.
fn store_name(kind: erpc_auth::StoreKind) -> String {
    use erpc_auth::StoreKind;
    match kind {
        StoreKind::OnePasswordDesktop => "1Password".to_owned(),
        StoreKind::OnePasswordServiceAccount => t!("ai.store.service_account"),
        // erpc-auth names the keyring in English or Japanese.
        StoreKind::OsKeychain => {
            erpc_auth::store::keychain::describe(crate::i18n::lang()).to_owned()
        }
        StoreKind::File => t!("ai.store.file"),
    }
}

/// Lists saved conversations and asks which to continue.
fn pick_conversation() -> Result<crate::conversations::Saved, Outcome> {
    let all = crate::conversations::list().map_err(Outcome::Failed)?;
    if all.is_empty() {
        return Err(Outcome::Failed(t!("conversations.none_yet")));
    }
    let now = crate::commands::now();
    let options: Vec<String> = all
        .iter()
        .take(30)
        .map(|saved| {
            format!(
                "{} {}  {}",
                padded(&age(now - saved.updated), 9),
                saved.id,
                saved.title
            )
        })
        .collect();
    let chosen =
        crate::prompt::pick(&t!("conversations.which"), &options, None).map_err(Outcome::Failed)?;
    let summary = all
        .get(chosen)
        .ok_or_else(|| Outcome::Failed(t!("conversations.nothing_chosen")))?;
    crate::conversations::load(&summary.id).map_err(Outcome::Failed)
}

/// `text` padded with spaces to `columns`, a wide character taking two.
fn padded(text: &str, columns: usize) -> String {
    use unicode_width::UnicodeWidthStr as _;
    format!("{text}{}", " ".repeat(columns.saturating_sub(text.width())))
}

/// How long ago, roughly.
fn age(seconds: i64) -> String {
    match seconds.max(0) {
        s if s < 60 => t!("conversations.age.just_now"),
        s if s < 3600 => tn!("conversations.age.minutes", s / 60),
        s if s < 86_400 => tn!("conversations.age.hours", s / 3600),
        s => tn!("conversations.age.days", s / 86_400),
    }
}

/// Signs in and reads the account.
/// Signs in, and reads the account and its AI plan side by side. The plan
/// is only shown, so not being able to read it is not a failure.
async fn connect(
    access: &StoreAccess,
    client: &AuthClient,
) -> Result<(erpc_api::User, Option<erpc_api::ai::Usage>), String> {
    let token = access.access_token().await?;
    let (user, usage) = tokio::join!(
        erpc_api::get_user(client, &token),
        erpc_api::ai::usage(client, &token)
    );
    Ok((user.map_err(|e| e.to_string())?, usage.ok()))
}

/// The plan as a person would read it: its name, what is left, and
/// whether it is suspended.
fn plan_line(usage: &erpc_api::ai::Usage) -> String {
    let (base, hourly) = usage
        .ai_plan
        .strip_suffix("Hourly")
        .map_or((usage.ai_plan.as_str(), false), |base| (base, true));
    let name = match base {
        "free" | "freeAuth" => "Free",
        "developer" => "Developer",
        "business" => "Business",
        "pro" => "Pro",
        other => other,
    };
    let mut line = if hourly {
        t!("ai.plan.hourly", name)
    } else {
        name.to_owned()
    };
    let left = tokens(usage.remaining_tokens);
    let _ = write!(line, " · {}", t!("ai.plan.left", left));
    if usage.suspended {
        let _ = write!(line, " · {}", t!("ai.plan.suspended"));
    }
    line
}

/// A token count, short: 950, 12K, 3.2M.
fn tokens(count: f64) -> String {
    let count = count.max(0.0);
    if count >= 1_000_000.0 {
        format!("{:.1}M", count / 1_000_000.0)
    } else if count >= 1_000.0 {
        format!("{:.0}K", count / 1_000.0)
    } else {
        format!("{count:.0}")
    }
}

fn not_signed_in(reason: &str) -> Outcome {
    Outcome::NoSession(format!("{reason}\n\n  {}", t!("ai.sign_in_hint")))
}

async fn once(session: &mut Session<StoreAccess>, json: bool, text: &str) -> Outcome {
    if text.is_empty() {
        return Outcome::Usage(t!("ai.empty_question"));
    }
    let mut events = Vec::new();
    let mut failure = None;
    // Whether the answer so far ends a line, so a tool's line on stderr
    // starts on one of its own.
    let mut line_ended = true;
    let turn = session
        .send(text, crate::interrupt::ctrl_c(), &mut |event| {
            if json {
                events.push(event);
                return;
            }
            match event {
                SessionEvent::TextDelta { text } => {
                    print!("{text}");
                    let _ = std::io::stdout().flush();
                    line_ended = text.ends_with('\n');
                }
                // On stderr, so stdout carries the answer and nothing else.
                SessionEvent::ToolUseStart { name, args, .. } => {
                    if !line_ended {
                        println!();
                        line_ended = true;
                    }
                    match erpc_ai::commands::shown_input(&args).filter(|_| name == "run_command") {
                        Some(command) => eprintln!("$ {command}"),
                        None => eprintln!("{}…", erpc_ai::tools::label(&name, crate::i18n::lang())),
                    }
                }
                // The link erpc built, when no browser opened, besides
                // what the model says of it.
                SessionEvent::ToolResult {
                    ok: true, content, ..
                } => {
                    if let Some(url) = erpc_ai::dashboard::unopened(&content) {
                        eprintln!("{}", t!("ai.open_dashboard", url));
                    }
                }
                SessionEvent::Error { message } => failure = Some(message),
                SessionEvent::Refusal { explanation, .. } => {
                    failure = Some(match explanation {
                        Some(why) => t!("ai.declined_because", why),
                        None => t!("ai.declined"),
                    });
                }
                _ => {}
            }
        })
        .await;
    if json {
        crate::print_json(&serde_json::json!({ "events": events }));
    } else {
        println!();
    }
    match (turn, failure) {
        (Turn::Answered, None) => Outcome::Done(String::new()),
        (Turn::Aborted, _) => Outcome::Failed(t!("ai.stopped")),
        (_, failure) => Outcome::Failed(failure.unwrap_or_default()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use erpc_ai::session::Access as _;
    use erpc_auth::{AuthClient, CredKey, Credential, CredentialStore, StoreError, StoreKind};
    use secrecy::SecretString;

    use super::{StoreAccess, plan_line, tokens};
    use crate::session;
    use crate::tui::splash::{self, Played, Status};

    #[test]
    fn over_ssh_the_dashboard_is_not_opened_on_this_machine() {
        use erpc_ai::dashboard::Browser as _;
        // Were the check skipped, this would start the opener; it is made
        // before anything runs, so nothing does.
        let browser = super::LocalBrowser {
            var: |name| (name == "SSH_CONNECTION").then(|| "10.0.0.1 22 10.0.0.2 22".into()),
        };
        let refused = browser
            .open("https://dashboard.erpc.global/en/user")
            .expect_err("no browser over SSH");
        assert!(refused.contains("SSH"), "{refused}");
    }

    #[test]
    fn a_typed_answer_is_numbers_in_range_or_own_words() {
        use erpc_ai::confirm::Answer;
        assert_eq!(
            super::picked("2\n", 3, false),
            Some(Answer::Picked(vec![1]))
        );
        assert_eq!(
            super::picked("3, 1", 3, true),
            Some(Answer::Picked(vec![2, 0]))
        );
        assert_eq!(
            super::picked("1、2", 3, true),
            Some(Answer::Picked(vec![0, 1]))
        );
        assert_eq!(
            super::picked(" tokyo, please\n", 3, false),
            Some(Answer::Said("tokyo, please".to_owned())),
            "words are the person's own answer, not lost"
        );
        assert_eq!(
            super::picked(" \n", 3, true),
            None,
            "an empty line asks again"
        );
        for (line, multiple) in [("3000", false), ("4", true), ("1,2", false), ("1,1", true)] {
            assert_eq!(
                super::picked(line, 3, multiple),
                Some(Answer::Said(line.to_owned())),
                "{line:?} names no option, so it is the person's own answer"
            );
        }
    }

    fn usage(plan: &str, remaining: f64, suspended: bool) -> erpc_api::ai::Usage {
        erpc_api::ai::Usage {
            ai_plan: plan.to_owned(),
            remaining_tokens: remaining,
            max_tokens: 4_200_000.0,
            suspended,
        }
    }

    #[test]
    fn a_plan_reads_as_its_name_and_what_is_left() {
        use crate::i18n::speaking;
        use erpc_core::i18n::Lang;
        assert_eq!(
            plan_line(&usage("developer", 3_150_000.0, false)),
            "Developer · 3.1M tokens left"
        );
        assert_eq!(
            speaking(Lang::Ja, || plan_line(&usage("proHourly", 12_000.0, true))),
            "Pro（時間課金） · 残り 12K トークン · 利用停止中"
        );
        assert_eq!(
            plan_line(&usage("freeAuth", 950.0, false)),
            "Free · 950 tokens left"
        );
        assert_eq!(
            speaking(Lang::Zh, || plan_line(&usage("proHourly", 12_000.0, true))),
            "Pro（按小时计费） · 剩余 12K Token · 已暂停"
        );
        assert_eq!(
            speaking(Lang::Ru, || plan_line(&usage("proHourly", 12_000.0, true))),
            "Pro (почасовая оплата) · осталось токенов: 12K · приостановлен"
        );
    }

    #[test]
    fn ages_and_yeses_read_in_every_language() {
        use crate::i18n::speaking;
        use erpc_core::i18n::Lang;
        assert_eq!(super::age(30), "just now");
        assert_eq!(super::age(5 * 60), "5m ago");
        assert_eq!(speaking(Lang::Ja, || super::age(2 * 3600)), "2時間前");
        assert_eq!(speaking(Lang::Zh, || super::age(3 * 86_400)), "3 天前");
        assert_eq!(speaking(Lang::Ru, || super::age(21 * 60)), "21 мин назад");
        assert_eq!(super::padded("3 天前", 9), "3 天前   ");
        for yes in ["y", "Yes", "はい", "是", "Да"] {
            assert!(super::says_yes(&format!("{yes}\n")), "{yes}");
        }
        for no in ["", "n", "no", "нет", "否", "yes please"] {
            assert!(!super::says_yes(no), "{no}");
        }
    }

    #[test]
    fn token_counts_are_short() {
        assert_eq!(tokens(-5.0), "0");
        assert_eq!(tokens(42_000_000.0), "42.0M");
    }

    /// A store holding a current session that blocks its thread before it
    /// hands it over, the way `op` does while the 1Password app waits for
    /// approval. It notes when each read ran.
    #[derive(Default)]
    struct SlowStore {
        reads: Mutex<Vec<(Instant, Instant)>>,
    }

    impl CredentialStore for SlowStore {
        fn load(&self, _key: &CredKey) -> Result<Option<Credential>, StoreError> {
            let began = Instant::now();
            std::thread::sleep(Duration::from_millis(300));
            self.reads
                .lock()
                .expect("not poisoned")
                .push((began, Instant::now()));
            Ok(Some(Credential {
                access_token: SecretString::from("acc.SLOW.s"),
                refresh_token: SecretString::from("ref.SLOW.s"),
                expires_at: crate::commands::now() + 3600,
            }))
        }
        fn save(&self, _key: &CredKey, _cred: &Credential) -> Result<(), StoreError> {
            Ok(())
        }
        fn delete(&self, _key: &CredKey) -> Result<(), StoreError> {
            Ok(())
        }
        fn kind(&self) -> StoreKind {
            StoreKind::OnePasswordDesktop
        }
    }

    #[tokio::test]
    async fn the_splash_keeps_drawing_while_the_store_answers() {
        // With the session in 1Password, the splash drew one frame and
        // then nothing until `op` answered seconds later, by which time
        // the animation was over.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(SlowStore::default());
        let access = StoreAccess {
            client: AuthClient::new().expect("a client"),
            store: store.clone(),
            key: CredKey::new(session::LOGIN_AUDIENCE, "alice"),
            state_dir: dir.path().to_owned(),
            cached: Mutex::new(None),
        };

        let mut drawn = Vec::new();
        let played = splash::frames(
            false,
            async {
                access.access_token().await?;
                Ok(((), "alice".to_owned()))
            },
            futures_util::stream::pending(),
            |_, _, status| {
                drawn.push((Instant::now(), status == Status::Connecting));
                Ok(())
            },
        )
        .await
        .expect("drawn");
        assert!(matches!(played, Played::Ready(())));

        let reads = store.reads.lock().expect("not poisoned").clone();
        let [(began, ended)] = reads[..] else {
            panic!("one read, not {}", reads.len());
        };
        let meanwhile = drawn
            .iter()
            .filter(|&&(at, connecting)| connecting && began < at && at < ended)
            .count();
        // About 18 at 60 frames a second; none if the read held the thread.
        assert!(
            meanwhile >= 5,
            "{meanwhile} frames while the store answered"
        );

        // The session is kept, so the first turn does not ask the store again.
        access.access_token().await.expect("the kept token");
        assert_eq!(store.reads.lock().expect("not poisoned").len(), 1);
    }

    /// A tool call and its result, through the real gateway as the
    /// signed-in account: `/v3/ai/chat` takes `tools`, streams back a
    /// `tool_use`, and takes the `tool_result` that answers it.
    #[tokio::test]
    #[ignore = "talks to the ERPC AI gateway as the signed-in account, and uses its tokens"]
    async fn a_tool_call_makes_the_round_trip_through_the_gateway() {
        use erpc_api::ai::{self, ChatRequest, Effort};
        use serde_json::{Value, json};

        fn request<'a>(
            system: &'a [String],
            messages: &'a [Value],
            tools: &'a [Value],
        ) -> ChatRequest<'a> {
            ChatRequest {
                system,
                messages,
                model: ai::QUICK_MODEL,
                max_tokens: 512,
                effort: Effort::Low,
                thinking: false,
                tools,
            }
        }

        let client = AuthClient::new().expect("a client");
        let Ok(access) = StoreAccess::open(client.clone()) else {
            panic!("no store; run `erpc login` first");
        };
        let token = access.access_token().await.expect("signed in");
        let tools = [json!({
            "name": "credit_balance",
            "description": "The signed-in account's ERPC credit balance, in credits.",
            "input_schema": {
                "type": "object",
                "properties": { "currency": { "type": "string", "enum": ["credits"] } },
                "required": ["currency"],
                "additionalProperties": false,
            },
        })];
        let system = ["Answer from the tools. Call a tool when it can answer.".to_owned()];
        let mut messages =
            vec![json!({ "role": "user", "content": "How many credits do I have?" })];
        let first = ai::chat(
            &client,
            &token,
            &request(&system, &messages, &tools),
            &mut |_| {},
        )
        .await
        .expect("the first turn");
        assert_eq!(first.stop_reason.as_deref(), Some("tool_use"), "{first:?}");
        let call = first
            .content
            .iter()
            .find(|b| b["type"] == "tool_use")
            .expect("a tool_use block");
        assert_eq!(call["name"], "credit_balance");
        assert_eq!(call["input"], json!({ "currency": "credits" }));
        assert!(
            first
                .content
                .iter()
                .all(|b| b.get("erpc_partial_input").is_none()),
            "nothing of ours left in the blocks"
        );

        messages.push(json!({ "role": "assistant", "content": first.content.clone() }));
        messages.push(json!({ "role": "user", "content": [{
            "type": "tool_result",
            "tool_use_id": call["id"],
            "content": "73519 credits",
        }]}));
        let second = ai::chat(
            &client,
            &token,
            &request(&system, &messages, &tools),
            &mut |_| {},
        )
        .await
        .expect("the second turn");
        assert_eq!(
            second.stop_reason.as_deref(),
            Some("end_turn"),
            "{second:?}"
        );
        let digits: String = second.text.chars().filter(char::is_ascii_digit).collect();
        assert!(
            digits.contains("73519"),
            "the answer uses the result: {}",
            second.text
        );
    }
}
