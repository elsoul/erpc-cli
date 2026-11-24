// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! erpc's keystore on this machine: where it is, how it is opened, and
//! `erpc worker secret unlock` and `lock`.
//!
//! The files and their cryptography are
//! [`erpc_auth::store::keystore`]; what is here is what a person meets.
//!
//! - **Where:** `keystore/` beside `config.toml`, so `~/.erpc/keystore`
//!   unless `ERPC_HOME` says otherwise.
//! - **Opening it:** an entry is read or written with the keystore's master
//!   key. That is taken from the unlock the Linux kernel keyring keeps,
//!   when there is one; else the passphrase is asked for at a terminal,
//!   checked by unwrapping `master.json`, and the unlock is kept. With
//!   nobody at a terminal and nothing kept, the command fails and names
//!   `erpc worker secret unlock`. On other systems nothing is kept, and
//!   each command asks once.
//! - **First use:** with no `master.json`, a person at a terminal is told
//!   what the keystore is and chooses its passphrase, typed twice.
//!
//! The passphrase comes from the hidden prompt and nowhere else: never an
//! argument, never an environment variable, never standard input that is
//! not a terminal. The terminal's echo stays off from the first prompt
//! until the last attempt has been checked, so an attempt typed ahead while
//! one is checked is not shown ([`crate::echo`]).

use std::path::PathBuf;

#[cfg(not(test))]
use erpc_auth::store::keystore::unlock;
use erpc_auth::store::keystore::unlock::UnlockError;
use erpc_auth::store::keystore::{
    Keystore, KeystoreError, Kind, MAX_VALUE, MIN_PASSPHRASE_CHARS, Master,
};
use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::Outcome;
use crate::error::{CliError, Code};
use crate::ui::Report;

/// How many times a passphrase is asked for before the command gives up.
const TRIES: usize = 3;

/// Whether a keystore may be made here when there is none, and how it came
/// to be the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Make {
    /// Not at all: this is a read.
    No,
    /// Yes: `--store keystore` asked for it.
    Asked,
    /// Yes: nothing else on this machine could keep the value.
    ByDefault,
}

/// The terminal's echo held off, from a [`Desk`]: back on when this is
/// dropped.
pub(crate) struct Hush {
    _held: Box<dyn core::any::Any>,
}

impl Hush {
    /// A hush that lasts as long as `guard` does.
    pub(crate) fn holding(guard: impl core::any::Any) -> Self {
        Self {
            _held: Box::new(guard),
        }
    }
}

/// What opening the keystore needs from where erpc runs: a person to ask,
/// and a place to keep the unlock. The real one is [`Here`]; a test brings
/// its own.
pub(crate) trait Desk {
    /// Whether a person is at a terminal to be asked.
    fn terminal(&self) -> bool;
    /// Holds the terminal's echo off until what is returned is dropped:
    /// across every prompt of one question and the checking between them.
    fn hush(&self) -> Hush;
    /// Asks for a line that is not shown.
    fn ask(&self, prompt: &str) -> Result<Zeroizing<String>, String>;
    /// Says something to the person, on standard error: its first line,
    /// and the others under it.
    fn say(&self, text: &str);
    /// Whether an unlock can be kept on this system at all.
    fn keeps(&self) -> bool;
    /// The unlock kept for the keystore whose master key is `key_id`.
    fn kept(&self, key_id: &str) -> Option<Master>;
    /// Keeps the unlock.
    fn keep(&self, master: &Master) -> Result<(), UnlockError>;
    /// Drops every unlock erpc keeps for this user, of whichever keystore,
    /// and `here`'s, the keystore this command is at, even where the others
    /// cannot be listed. How many were dropped.
    fn forget_all(&self, here: Option<&str>) -> Result<usize, UnlockError>;
    /// How long the kernel keeps an unused keyring, in seconds.
    fn idle_secs(&self) -> Option<u64>;
}

/// The master key this process opened, for its later reads: a command
/// reads several entries, and where no unlock is kept it still asks once.
static HELD: std::sync::Mutex<Option<Master>> = std::sync::Mutex::new(None);

fn held(key_id: &str) -> Option<Master> {
    HELD.lock()
        .ok()?
        .as_ref()
        .filter(|master| master.id() == key_id)
        .cloned()
}

fn hold(master: &Master) {
    if let Ok(mut held) = HELD.lock() {
        *held = Some(master.clone());
    }
}

fn let_go() {
    if let Ok(mut held) = HELD.lock() {
        *held = None;
    }
}

/// This machine: its terminal, and the kernel keyring. A test brings its
/// own desk, and so never reaches the machine's.
#[cfg(not(test))]
struct Here;

#[cfg(not(test))]
impl Desk for Here {
    fn terminal(&self) -> bool {
        crate::session::has_terminal()
    }

    fn hush(&self) -> Hush {
        Hush::holding(crate::echo::off())
    }

    fn ask(&self, prompt: &str) -> Result<Zeroizing<String>, String> {
        dialoguer::Password::new()
            .with_prompt(prompt)
            .interact_on(&dialoguer::console::Term::stderr())
            .map(Zeroizing::new)
            .map_err(|e| t!("worker_keys.secret.ask_failed", error = e))
    }

    fn say(&self, text: &str) {
        let mut lines = text.lines();
        let report = lines
            .next()
            .map_or_else(Report::new, |first| Report::new().info(first));
        let report = lines.fold(report, Report::detail);
        crate::interrupt::say(&report.render(crate::ui::stderr_drawn()));
    }

    fn keeps(&self) -> bool {
        unlock::SUPPORTED
    }

    fn kept(&self, key_id: &str) -> Option<Master> {
        held(key_id).or_else(|| {
            let master = unlock::kept(key_id)?;
            hold(&master);
            Some(master)
        })
    }

    fn keep(&self, master: &Master) -> Result<(), UnlockError> {
        hold(master);
        unlock::keep(master)
    }

    fn forget_all(&self, here: Option<&str>) -> Result<usize, UnlockError> {
        let_go();
        unlock::forget_all(here)
    }

    fn idle_secs(&self) -> Option<u64> {
        unlock::idle_expiry_secs()
    }
}

/// Where this machine's keystore is.
#[cfg(not(test))]
fn dir() -> Result<PathBuf, String> {
    crate::session::beside_config("keystore")
}

#[cfg(test)]
thread_local! {
    static TESTING: std::cell::RefCell<Option<(Keystore, std::rc::Rc<dyn Desk>)>> =
        const { std::cell::RefCell::new(None) };
}

/// In a test: the keystore and the desk this thread's commands use. Without
/// one a test reaches no keystore at all, least of all the machine's own.
#[cfg(test)]
pub(crate) fn testing(store: Keystore, desk: std::rc::Rc<dyn Desk>) {
    TESTING.with(|t| *t.borrow_mut() = Some((store, desk)));
}

/// Runs `f` with this machine's keystore and its desk.
fn with<T>(f: impl FnOnce(&Keystore, &dyn Desk) -> Result<T, String>) -> Result<T, String> {
    #[cfg(test)]
    let out = TESTING.with(|t| match &*t.borrow() {
        Some((store, desk)) => f(store, desk.as_ref()),
        None => Err("this test set up no keystore".to_owned()),
    });
    #[cfg(not(test))]
    let out = f(&Keystore::at(dir()?), &Here);
    out
}

/// The keystore's directory, as a person reads it.
fn place(store: &Keystore) -> String {
    crate::ui::tidy(store.dir())
}

/// A keystore failure in the operator's language.
fn explain(store: &Keystore, error: &KeystoreError) -> String {
    match error {
        KeystoreError::Missing => t!("worker_keystore.none", path = place(store)),
        KeystoreError::Exists => t!("worker_keystore.exists"),
        KeystoreError::PassphraseTooShort => {
            t!("worker_keystore.too_short", min = MIN_PASSPHRASE_CHARS)
        }
        KeystoreError::WrongPassphrase => t!("worker_keystore.wrong"),
        KeystoreError::Unreadable { path, why } => t!("worker_keystore.unreadable", path, why),
        KeystoreError::Unsupported { path, what } => {
            t!("worker_keystore.unsupported", path, what)
        }
        KeystoreError::OtherMaster { name } => t!("worker_keystore.other_master", name),
        KeystoreError::Changed { name } => t!("worker_keystore.changed", name),
        KeystoreError::OtherKind {
            name,
            kept: Kind::Key,
        } => t!("worker_keystore.kept_as_key", name),
        KeystoreError::OtherKind {
            name,
            kept: Kind::Secret,
        } => t!("worker_keystore.kept_as_secret", name),
        KeystoreError::OtherSpelling { name, found } => {
            t!("worker_keystore.other_spelling", name, found)
        }
        KeystoreError::BadName => t!("worker_keystore.bad_name"),
        KeystoreError::TooLong => t!("worker_keystore.too_long", max = MAX_VALUE),
        // A file that could not be read or written, said with its path.
        other => other.to_string(),
    }
}

/// Why an unlock was not kept or dropped, in the operator's language.
fn why_not(error: &UnlockError) -> String {
    match error {
        UnlockError::NotHeld => t!("worker_keystore.why.not_held"),
        UnlockError::Kernel(reason) => t!("worker_keystore.why.kernel", reason),
        other => other.to_string(),
    }
}

/// `secs` as a person says it: whole days, else hours, else minutes.
fn span(secs: u64) -> String {
    const DAY: u64 = 24 * 60 * 60;
    if secs >= DAY && secs.is_multiple_of(DAY) {
        tn!("worker_keystore.days", secs / DAY)
    } else if secs >= 60 * 60 {
        tn!("worker_keystore.hours", secs / (60 * 60))
    } else {
        tn!("worker_keystore.minutes", (secs / 60).max(1))
    }
}

/// Until when an unlock kept now lasts.
fn until(desk: &dyn Desk) -> String {
    match desk.idle_secs() {
        Some(secs) => t!("worker_keystore.until_reboot_or_idle", idle = span(secs)),
        None => t!("worker_keystore.until_reboot"),
    }
}

/// Asks for the passphrase until it opens the keystore, [`TRIES`] times at
/// most.
fn ask_open(store: &Keystore, desk: &dyn Desk) -> Result<Master, String> {
    // One hold on the echo for all of it: checking a passphrase takes long
    // enough to type the next one in, and it is not shown. Every way out
    // of here drops it.
    let _hush = desk.hush();
    for attempt in 1..=TRIES {
        let passphrase = desk.ask(&t!("worker_keystore.prompt"))?;
        match store.open(&passphrase) {
            Ok(master) => return Ok(master),
            Err(KeystoreError::WrongPassphrase) if attempt < TRIES => {
                desk.say(&t!("worker_keystore.wrong_again"));
            }
            Err(e) => return Err(explain(store, &e)),
        }
    }
    Err(t!("worker_keystore.wrong"))
}

/// Keeps the unlock and says until when, or that it could not be kept: a
/// command that got its key goes on either way.
fn remember(desk: &dyn Desk, master: &Master) {
    match desk.keep(master) {
        Ok(()) => desk.say(&t!("worker_keystore.unlocked", until = until(desk))),
        // Nothing to keep it in here: each command asks, and that is all.
        Err(UnlockError::Unsupported) => {}
        Err(e) => desk.say(&t!("worker_keystore.not_kept", why = why_not(&e))),
    }
}

/// Makes the keystore: says what it is, and has its passphrase chosen.
fn create(store: &Keystore, desk: &dyn Desk, by_default: bool) -> Result<Master, String> {
    let path = place(store);
    if !desk.terminal() {
        return Err(t!("worker_keystore.first_needs_terminal", path));
    }
    desk.say(&if by_default {
        t!("worker_keystore.intro_by_default", path)
    } else {
        t!("worker_keystore.intro", path)
    });
    // Held until the keystore is made, as in `ask_open`.
    let hush = desk.hush();
    let first = desk.ask(&t!(
        "worker_keystore.new_prompt",
        min = MIN_PASSPHRASE_CHARS
    ))?;
    if first.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(t!("worker_keystore.too_short", min = MIN_PASSPHRASE_CHARS));
    }
    let again = desk.ask(&t!("worker_keystore.again_prompt"))?;
    if first.as_str() != again.as_str() {
        return Err(t!("worker_keystore.mismatch"));
    }
    let master = store.create(&first).map_err(|e| explain(store, &e))?;
    drop(hush);
    remember(desk, &master);
    Ok(master)
}

/// The keystore's master key: the unlock that is kept, else the passphrase
/// asked for at a terminal. With no keystore yet, one is made when `make`
/// allows it.
fn master(store: &Keystore, desk: &dyn Desk, make: Make) -> Result<Master, String> {
    let Some(key_id) = store.key_id().map_err(|e| explain(store, &e))? else {
        return match make {
            Make::No => Err(t!("worker_keystore.none", path = place(store))),
            Make::Asked => create(store, desk, false),
            Make::ByDefault => create(store, desk, true),
        };
    };
    if let Some(master) = desk.kept(&key_id) {
        return Ok(master);
    }
    if !desk.terminal() {
        return Err(if desk.keeps() {
            t!("worker_keystore.locked_no_terminal")
        } else {
            t!("worker_keystore.no_terminal_each_time")
        });
    }
    let master = ask_open(store, desk)?;
    remember(desk, &master);
    Ok(master)
}

/// This machine's keystore directory, as a person reads it.
pub(crate) fn place_here() -> String {
    with(|store, _| Ok(place(store))).unwrap_or_else(|_| "keystore".to_owned())
}

/// Whether the keystore has an entry under `service` and `account`. Asks
/// for nothing: the names are not hidden.
pub(crate) fn has(service: &str, account: &str) -> Result<bool, String> {
    with(|store, _| store.has(service, account).map_err(|e| explain(store, &e)))
}

/// Whether the keystore has an entry under `service` and `account` that
/// was kept as a `kind`; an entry kept as the other kind is an error, the
/// one a read of it would give. Asks for nothing: it is what the entry's
/// file says, which the seal holds it to when it is read. For finding the
/// wrong kind before anything slow.
pub(crate) fn kept_as(service: &str, account: &str, kind: Kind) -> Result<bool, String> {
    with(|store, _| {
        match store
            .kind(service, account)
            .map_err(|e| explain(store, &e))?
        {
            None => Ok(false),
            Some(kept) if kept == kind => Ok(true),
            Some(kept) => Err(explain(
                store,
                &KeystoreError::OtherKind {
                    name: format!("{service}/{account}"),
                    kept,
                },
            )),
        }
    })
}

/// The file the entry under `service` and `account` is, or would be, in.
pub(crate) fn file_of(service: &str, account: &str) -> Result<PathBuf, String> {
    with(|store, _| {
        store
            .entry_path(service, account)
            .map_err(|e| explain(store, &e))
    })
}

/// The value under `service` and `account`, read as a `kind`, or none
/// when this machine's keystore has no such entry (and then nothing is
/// asked). An entry kept as the other kind is refused: a trading key is
/// not read as a secret, nor a secret as a trading key.
pub(crate) fn read(
    service: &str,
    account: &str,
    kind: Kind,
) -> Result<Option<Zeroizing<String>>, String> {
    with(|store, desk| {
        if !store
            .has(service, account)
            .map_err(|e| explain(store, &e))?
        {
            return Ok(None);
        }
        let master = master(store, desk, Make::No)?;
        store
            .read(&master, service, account, kind)
            .map_err(|e| explain(store, &e))
    })
}

/// Opens the keystore now, making it when `make` allows: before a value is
/// typed that a wrong passphrase would lose, and before anything slow.
pub(crate) fn open_now(make: Make) -> Result<(), String> {
    with(|store, desk| master(store, desk, make).map(|_| ()))
}

/// Seals `value` under `service` and `account` as a `kind`, replacing
/// what was there. The first write on a machine makes the keystore.
pub(crate) fn write(
    service: &str,
    account: &str,
    kind: Kind,
    value: &str,
    by_default: bool,
) -> Result<(), String> {
    with(|store, desk| {
        // A name that cannot be kept, or that the keystore holds in
        // another spelling, is said before a passphrase is asked.
        store
            .has(service, account)
            .map_err(|e| explain(store, &e))?;
        let make = if by_default {
            Make::ByDefault
        } else {
            Make::Asked
        };
        let master = master(store, desk, make)?;
        store
            .write(&master, service, account, kind, value)
            .map_err(|e| explain(store, &e))
    })
}

/// Removes the entry under `service` and `account`; whether there was one.
pub(crate) fn remove(service: &str, account: &str) -> Result<bool, String> {
    with(|store, _| {
        store
            .delete(service, account)
            .map_err(|e| explain(store, &e))
    })
}

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

/// `erpc worker secret unlock`: asks for the passphrase and keeps the
/// unlock, so the commands after it do not ask.
pub(crate) fn unlock_command(json: bool) -> Outcome {
    with(|store, desk| Ok(unlock_at(json, store, desk))).unwrap_or_else(|e| failed(e).into())
}

fn unlock_at(json: bool, store: &Keystore, desk: &dyn Desk) -> Outcome {
    let key_id = match store.key_id() {
        Ok(Some(key_id)) => key_id,
        Ok(None) => {
            return failed(t!("worker_keystore.none", path = place(store)))
                .hint(t!("worker_keystore.none_hint"))
                .mark("🔐")
                .into();
        }
        Err(e) => return failed(explain(store, &e)).into(),
    };
    if !desk.keeps() {
        return failed(t!("worker_keystore.unlock.unsupported")).into();
    }
    let already = desk.kept(&key_id).is_some();
    if !already {
        if !desk.terminal() {
            return CliError::new(
                Code::NeedsTerminal,
                t!("worker_keystore.unlock.needs_terminal"),
            )
            .hint(t!("worker_keystore.unlock.needs_terminal_hint"))
            .into();
        }
        let master = match ask_open(store, desk) {
            Ok(master) => master,
            Err(e) => return failed(e).into(),
        };
        if let Err(e) = desk.keep(&master) {
            return failed(t!("worker_keystore.unlock.not_kept", why = why_not(&e))).into();
        }
    }
    if json {
        crate::print_json(&json!({
            "unlocked": true,
            "already": already,
            "keystore": store.dir(),
            "until": { "reboot": true, "idle_secs": desk.idle_secs() },
        }));
        return Outcome::Done(String::new());
    }
    let until = until(desk);
    let said = if already {
        t!("worker_keystore.unlock.already", until)
    } else {
        t!("worker_keystore.unlock.done", until)
    };
    Outcome::Done(
        Report::new()
            .marked("🔓", said)
            .hint(t!("worker_keystore.unlock.lock_hint"))
            .text(),
    )
}

/// `erpc worker secret lock`: drops the unlock, so the next command that
/// needs the keystore asks for the passphrase. Every unlock erpc keeps for
/// this user goes, not this keystore's alone: one kept for a keystore under
/// another `ERPC_HOME`, or for one whose `master.json` is gone or cannot be
/// read, has no other command to drop it.
pub(crate) fn lock_command(json: bool) -> Outcome {
    with(|store, desk| Ok(lock_at(json, store, desk))).unwrap_or_else(|e| failed(e).into())
}

fn lock_at(json: bool, store: &Keystore, desk: &dyn Desk) -> Outcome {
    // Which keystore is here decides what is said, not what is dropped.
    let here = store.key_id();
    let mine = here.as_ref().ok().and_then(|id| id.as_deref());
    let was = mine.is_some_and(|id| desk.kept(id).is_some());
    let dropped = if desk.keeps() {
        match desk.forget_all(mine) {
            Ok(dropped) => dropped,
            Err(e) => return failed(t!("worker_keystore.lock.failed", why = why_not(&e))).into(),
        }
    } else {
        0
    };
    let others = dropped.saturating_sub(usize::from(was));
    let said = match &here {
        // Nothing was dropped, and the keystore here cannot be read: that
        // is what there is to say.
        Err(e) if others == 0 => return failed(explain(store, e)).into(),
        Err(e) => Report::new().warning(explain(store, e)),
        Ok(None) => {
            Report::new().marked("🔒", t!("worker_keystore.lock.none", path = place(store)))
        }
        Ok(Some(_)) if !desk.keeps() => {
            Report::new().marked("🔒", t!("worker_keystore.lock.unsupported"))
        }
        Ok(Some(_)) if was => Report::new().marked("🔒", t!("worker_keystore.lock.done")),
        Ok(Some(_)) => Report::new().marked("🔒", t!("worker_keystore.lock.was_not")),
    };
    if json {
        crate::print_json(&json!({
            "locked": true,
            "was_unlocked": was,
            "dropped": dropped,
            "keystore": store.dir(),
        }));
        return Outcome::Done(String::new());
    }
    Outcome::Done(if others == 0 {
        said.text()
    } else {
        said.info(t!("worker_keystore.lock.others", count = others))
            .text()
    })
}

/// A desk for tests: what it is asked, what it answers, what it is told,
/// and an unlock kept in memory.
#[cfg(test)]
pub(crate) mod fake {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    use erpc_auth::store::keystore::unlock::UnlockError;
    use erpc_auth::store::keystore::{Keystore, Master};
    use zeroize::Zeroizing;

    /// The passphrase the test keystores are made with.
    pub(crate) const PASSPHRASE: &str = "correct horse battery";

    pub(crate) struct FakeDesk {
        pub(crate) terminal: Cell<bool>,
        pub(crate) keeps: Cell<bool>,
        /// What `keep` answers instead of keeping.
        pub(crate) refuses: RefCell<Option<UnlockError>>,
        pub(crate) answers: RefCell<VecDeque<String>>,
        pub(crate) asked: RefCell<Vec<String>>,
        pub(crate) said: RefCell<Vec<String>>,
        /// The unlocks kept: this keystore's, and any other's.
        pub(crate) unlocks: RefCell<Vec<Master>>,
        /// How many holds on the echo there are now: none, or one.
        pub(crate) hushed: Rc<Cell<usize>>,
        /// How many holds on the echo were taken.
        pub(crate) hushes: Cell<usize>,
        /// Whether the echo was held off each time something was said.
        pub(crate) said_hushed: RefCell<Vec<bool>>,
    }

    /// A hold on a [`FakeDesk`]'s echo.
    struct Quiet(Rc<Cell<usize>>);

    impl Drop for Quiet {
        fn drop(&mut self) {
            self.0.set(self.0.get() - 1);
        }
    }

    impl FakeDesk {
        /// A person at a terminal who will type `answers`, on a system
        /// that keeps an unlock.
        pub(crate) fn typing(answers: &[&str]) -> std::rc::Rc<Self> {
            std::rc::Rc::new(Self {
                terminal: Cell::new(true),
                keeps: Cell::new(true),
                refuses: RefCell::new(None),
                answers: RefCell::new(answers.iter().map(|a| (*a).to_owned()).collect()),
                asked: RefCell::new(Vec::new()),
                said: RefCell::new(Vec::new()),
                unlocks: RefCell::new(Vec::new()),
                hushed: Rc::new(Cell::new(0)),
                hushes: Cell::new(0),
                said_hushed: RefCell::new(Vec::new()),
            })
        }

        /// Nobody at a terminal.
        pub(crate) fn nobody() -> std::rc::Rc<Self> {
            let desk = Self::typing(&[]);
            desk.terminal.set(false);
            desk
        }

        pub(crate) fn will_type(&self, answers: &[&str]) {
            self.answers
                .borrow_mut()
                .extend(answers.iter().map(|a| (*a).to_owned()));
        }

        pub(crate) fn said(&self) -> String {
            self.said.borrow().join("\n")
        }

        pub(crate) fn asked(&self) -> usize {
            self.asked.borrow().len()
        }

        pub(crate) fn lock(&self) {
            self.unlocks.borrow_mut().clear();
        }

        pub(crate) fn is_unlocked(&self) -> bool {
            !self.unlocks.borrow().is_empty()
        }
    }

    impl super::Desk for FakeDesk {
        fn terminal(&self) -> bool {
            self.terminal.get()
        }

        fn hush(&self) -> super::Hush {
            assert_eq!(self.hushed.get(), 0, "one hold on the echo at a time");
            self.hushes.set(self.hushes.get() + 1);
            self.hushed.set(1);
            super::Hush::holding(Quiet(self.hushed.clone()))
        }

        fn ask(&self, prompt: &str) -> Result<Zeroizing<String>, String> {
            assert!(self.terminal.get(), "asked with nobody at a terminal");
            // Every line asked for here is a passphrase.
            assert_eq!(self.hushed.get(), 1, "asked with the echo on");
            self.asked.borrow_mut().push(prompt.to_owned());
            self.answers
                .borrow_mut()
                .pop_front()
                .map(Zeroizing::new)
                .ok_or_else(|| "asked more than the test answers".to_owned())
        }

        fn say(&self, text: &str) {
            self.said.borrow_mut().push(text.to_owned());
            self.said_hushed.borrow_mut().push(self.hushed.get() > 0);
        }

        fn keeps(&self) -> bool {
            self.keeps.get()
        }

        fn kept(&self, key_id: &str) -> Option<Master> {
            self.unlocks
                .borrow()
                .iter()
                .find(|m| m.id() == key_id)
                .cloned()
        }

        fn keep(&self, master: &Master) -> Result<(), UnlockError> {
            assert_eq!(self.hushed.get(), 0, "the echo is back on by now");
            if !self.keeps.get() {
                return Err(UnlockError::Unsupported);
            }
            if let Some(refusal) = self.refuses.borrow().clone() {
                return Err(refusal);
            }
            let mut unlocks = self.unlocks.borrow_mut();
            unlocks.retain(|m| m.id() != master.id());
            unlocks.push(master.clone());
            Ok(())
        }

        fn forget_all(&self, _here: Option<&str>) -> Result<usize, UnlockError> {
            if let Some(refusal) = self.refuses.borrow().clone() {
                return Err(refusal);
            }
            Ok(self.unlocks.borrow_mut().drain(..).count())
        }

        fn idle_secs(&self) -> Option<u64> {
            self.keeps.get().then_some(259_200)
        }
    }

    /// A keystore in a directory of its own, made with few iterations so
    /// the tests are quick. Not made yet: the first write makes it.
    pub(crate) fn store() -> (tempfile::TempDir, Keystore) {
        let home = tempfile::tempdir().expect("a directory");
        let store = Keystore::with_iterations(
            home.path().join("keystore"),
            core::num::NonZeroU32::new(1_000).expect("not zero"),
        );
        (home, store)
    }

    /// Sets this thread's commands up with a new keystore directory and
    /// `desk`; the directory lasts as long as what is returned.
    pub(crate) fn set_up(desk: &std::rc::Rc<FakeDesk>) -> (tempfile::TempDir, Keystore) {
        let (home, store) = store();
        super::testing(store.clone(), desk.clone());
        (home, store)
    }
}

#[cfg(test)]
mod tests {
    use erpc_auth::store::keystore::Kind;
    use erpc_auth::store::keystore::unlock::UnlockError;

    use super::fake::{FakeDesk, PASSPHRASE, set_up, store};
    use super::{Desk as _, Make, lock_at, master, unlock_at};
    use crate::commands::Outcome;
    use crate::error::Code;

    const SERVICE: &str = "erpc-worker";

    fn done(outcome: Outcome) -> String {
        match outcome {
            Outcome::Done(text) => text,
            other => panic!("not done: {:?}", other.error()),
        }
    }

    fn refused(outcome: Outcome) -> crate::error::CliError {
        outcome.error().expect("a failure")
    }

    #[test]
    fn what_this_process_opened_serves_its_later_reads_of_that_keystore_only() {
        let (_home, ours) = store();
        let (_other_home, theirs) = store();
        let master = ours.create(PASSPHRASE).expect("made");
        let other = theirs.create(PASSPHRASE).expect("made");
        assert!(super::held(&master.id()).is_none());
        super::hold(&master);
        assert_eq!(super::held(&master.id()).map(|m| m.id()), Some(master.id()));
        // Asked for by another keystore's key, it is not handed over.
        assert!(super::held(&other.id()).is_none());
        super::let_go();
        assert!(super::held(&master.id()).is_none());
    }

    #[test]
    fn the_first_write_makes_the_keystore_after_saying_what_it_is() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, store) = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        assert!(store.master_path().is_file());
        // Told what it is, what to back up, and the alternative, before
        // the passphrase was asked for twice.
        let said = desk.said();
        for needle in [
            "an encrypted file on this machine",
            "Back that directory up and remember the passphrase",
            "erpc login --store 1password-desktop",
            "no keychain that outlasts a reboot",
        ] {
            assert!(said.contains(needle), "{needle} in {said}");
        }
        assert_eq!(desk.asked(), 2);
        // The unlock is kept, and said to be, with until when.
        assert!(desk.is_unlocked());
        assert!(said.contains("3 days"), "{said}");
        assert!(said.contains("erpc worker secret lock"), "{said}");
        // Unlocked, the next read and write ask nothing.
        assert_eq!(
            super::read(SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .expect("there")
                .as_str(),
            "s3cret-value"
        );
        super::write(SERVICE, "bot.OTHER", Kind::Secret, "another", true).expect("kept");
        assert_eq!(desk.asked(), 2);
        // Asked for by name, the reason given is not the fallback's.
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _kept = set_up(&desk);
        super::write(
            SERVICE,
            "bot.API_TOKEN",
            Kind::Secret,
            "s3cret-value",
            false,
        )
        .expect("kept");
        assert!(
            !desk.said().contains("outlasts a reboot"),
            "{}",
            desk.said()
        );
        assert!(desk.said().contains("an encrypted file on this machine"));
    }

    #[test]
    fn a_new_passphrase_that_is_short_or_mistyped_makes_nothing() {
        let desk = FakeDesk::typing(&["too short"]);
        let (_home, store) = set_up(&desk);
        let e =
            super::write(SERVICE, "bot.wallet", Kind::Key, "the key", false).expect_err("refused");
        assert!(e.contains("12 characters or more"), "{e}");
        // Refused at once, not after typing it again.
        assert_eq!(desk.asked(), 1);
        desk.will_type(&[PASSPHRASE, "correct horse batterY"]);
        let e =
            super::write(SERVICE, "bot.wallet", Kind::Key, "the key", false).expect_err("refused");
        assert!(e.contains("the two passphrases differ"), "{e}");
        assert!(!store.dir().exists(), "nothing was made");
        assert!(!desk.is_unlocked());
        assert!(!super::has(SERVICE, "bot.wallet").expect("named"));
    }

    #[test]
    fn with_nobody_at_a_terminal_no_keystore_is_made() {
        let desk = FakeDesk::nobody();
        let (_home, store) = set_up(&desk);
        for by_default in [true, false] {
            let e = super::write(SERVICE, "bot.wallet", Kind::Key, "the key", by_default)
                .expect_err("refused");
            assert!(e.contains("chosen at a terminal"), "{e}");
        }
        let e = super::open_now(Make::ByDefault).expect_err("refused");
        assert!(e.contains("chosen at a terminal"), "{e}");
        assert!(!store.dir().exists());
        assert_eq!(desk.asked(), 0);
        // A read of what is not there asks nothing, and is not an error.
        assert!(
            super::read(SERVICE, "bot.wallet", Kind::Key)
                .expect("reads")
                .is_none()
        );
    }

    #[test]
    fn locked_with_nobody_at_a_terminal_names_secret_unlock() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _kept = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        desk.lock();
        desk.terminal.set(false);
        let e = super::read(SERVICE, "bot.API_TOKEN", Kind::Secret).expect_err("locked");
        assert!(e.contains("the keystore is locked"), "{e}");
        assert!(e.contains("`erpc worker secret unlock`"), "{e}");
        let e =
            super::write(SERVICE, "bot.OTHER", Kind::Secret, "another", true).expect_err("locked");
        assert!(e.contains("`erpc worker secret unlock`"), "{e}");
        let e = super::open_now(Make::No).expect_err("locked");
        assert!(e.contains("`erpc worker secret unlock`"), "{e}");
        assert_eq!(desk.asked(), 2, "nothing was asked of nobody");
        // On a system that keeps no unlock, unlocking first is no way out,
        // and is not named as one.
        desk.keeps.set(false);
        let e = super::read(SERVICE, "bot.API_TOKEN", Kind::Secret).expect_err("locked");
        assert!(!e.contains("secret unlock"), "{e}");
        assert!(e.contains("run this at a terminal"), "{e}");
    }

    #[test]
    fn unlocked_a_secret_is_read_with_nobody_at_a_terminal() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _kept = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        desk.terminal.set(false);
        assert!(desk.is_unlocked());
        assert_eq!(
            super::read(SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .expect("there")
                .as_str(),
            "s3cret-value"
        );
    }

    #[test]
    fn a_locked_keystore_asks_for_its_passphrase_three_times_at_most() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, store) = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        desk.lock();
        // Wrong, wrong, right: opened, and unlocked again.
        desk.will_type(&["wrong passphrase 1", "wrong passphrase 2", PASSPHRASE]);
        assert_eq!(
            super::read(SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .expect("there")
                .as_str(),
            "s3cret-value"
        );
        assert_eq!(desk.asked(), 5);
        assert!(desk.is_unlocked());
        assert!(desk.said().contains("does not open the keystore"));
        // Wrong three times: refused, nothing unlocked, and not asked a
        // fourth time.
        desk.lock();
        desk.will_type(&["wrong 1", "wrong 2", "wrong 3", PASSPHRASE]);
        let e = super::read(SERVICE, "bot.API_TOKEN", Kind::Secret).expect_err("refused");
        assert!(e.contains("does not open the keystore"), "{e}");
        assert_eq!(desk.asked(), 8);
        assert!(!desk.is_unlocked());
        // Neither the refusal nor what was said repeats what was typed.
        assert!(!e.contains("wrong 3"), "{e}");
        assert!(!desk.said().contains("wrong passphrase 1"));
        assert!(master(&store, desk.as_ref(), Make::No).is_ok());
    }

    #[test]
    fn where_no_unlock_is_kept_each_command_asks_and_says_nothing_of_one() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        desk.keeps.set(false);
        let _kept = set_up(&desk);
        super::write(
            SERVICE,
            "bot.API_TOKEN",
            Kind::Secret,
            "s3cret-value",
            false,
        )
        .expect("kept");
        assert!(!desk.is_unlocked());
        assert!(!desk.said().contains("unlocked"), "{}", desk.said());
        // The next command asks again.
        desk.will_type(&[PASSPHRASE]);
        assert!(
            super::read(SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .is_some()
        );
        assert_eq!(desk.asked(), 3);
    }

    #[test]
    fn an_unlock_that_cannot_be_kept_is_said_and_the_command_goes_on() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        *desk.refuses.borrow_mut() = Some(UnlockError::NotHeld);
        let _kept = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true)
            .expect("kept all the same");
        assert!(!desk.is_unlocked());
        let said = desk.said();
        assert!(said.contains("could not be kept"), "{said}");
        assert!(
            said.contains("holds none of your kernel keyrings"),
            "{said}"
        );
        assert!(said.contains("asks for the passphrase again"), "{said}");
        desk.will_type(&[PASSPHRASE]);
        assert!(
            super::read(SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .is_some()
        );
    }

    #[test]
    fn unlock_asks_keeps_and_says_until_when() {
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, store) = set_up(&desk);
        // No keystore yet: nothing to unlock, and none is made.
        let e = refused(unlock_at(false, &store, desk.as_ref()));
        assert_eq!(e.code, Code::Failed);
        assert!(
            e.text()
                .contains("there is no keystore on this machine yet")
        );
        assert!(!store.dir().exists());
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        // Unlocked by that write already: said, and nothing asked.
        let text = done(unlock_at(false, &store, desk.as_ref()));
        assert!(
            text.starts_with("The keystore is unlocked already"),
            "{text}"
        );
        assert_eq!(desk.asked(), 2);
        desk.lock();
        desk.will_type(&[PASSPHRASE]);
        let text = done(unlock_at(false, &store, desk.as_ref()));
        assert_eq!(
            text,
            "Keystore unlocked until this machine restarts, or until your kernel keyring has \
             gone 3 days unused.\nhint: `erpc worker secret lock` locks it again"
        );
        assert!(desk.is_unlocked());
        // A wrong passphrase, three times: nothing is unlocked.
        desk.lock();
        desk.will_type(&["wrong 1", "wrong 2", "wrong 3"]);
        let e = refused(unlock_at(false, &store, desk.as_ref()));
        assert!(
            e.text().contains("does not open the keystore"),
            "{}",
            e.text()
        );
        assert!(!desk.is_unlocked());
    }

    #[test]
    fn unlock_fails_where_it_cannot_ask_or_cannot_keep() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, store) = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        desk.lock();
        // Nobody at a terminal.
        desk.terminal.set(false);
        let e = refused(unlock_at(false, &store, desk.as_ref()));
        assert_eq!(e.code, Code::NeedsTerminal);
        assert_eq!(
            e.text(),
            "error: the keystore's passphrase is typed at a terminal, and nobody is at one\n\
             hint: run it in a terminal: the passphrase is not read from a pipe, an argument \
             or the environment"
        );
        assert_eq!(desk.asked(), 2);
        // The kernel keyring refuses: the passphrase was right, and the
        // command still failed, since nothing is unlocked.
        desk.terminal.set(true);
        *desk.refuses.borrow_mut() = Some(UnlockError::Kernel("QuotaExceeded".to_owned()));
        desk.will_type(&[PASSPHRASE]);
        let e = refused(unlock_at(false, &store, desk.as_ref()));
        assert_eq!(e.code, Code::Failed);
        assert!(
            e.text().contains("the unlock could not be kept"),
            "{}",
            e.text()
        );
        assert!(e.text().contains("QuotaExceeded"), "{}", e.text());
        assert!(!desk.is_unlocked());
        // A system with no kernel keyring: said before anything is asked.
        *desk.refuses.borrow_mut() = None;
        desk.keeps.set(false);
        let asked = desk.asked();
        let e = refused(unlock_at(false, &store, desk.as_ref()));
        assert!(e.text().contains("no kernel keyring"), "{}", e.text());
        assert_eq!(desk.asked(), asked);
    }

    #[test]
    fn lock_drops_the_unlock_and_the_next_read_asks() {
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, store) = set_up(&desk);
        // No keystore: nothing to lock, and not a failure.
        let text = done(lock_at(false, &store, desk.as_ref()));
        assert!(
            text.starts_with("There is no keystore on this machine"),
            "{text}"
        );
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        assert!(desk.is_unlocked());
        assert_eq!(
            done(lock_at(false, &store, desk.as_ref())),
            "Keystore locked: the next command that needs it asks for the passphrase."
        );
        assert!(!desk.is_unlocked());
        assert_eq!(
            done(lock_at(false, &store, desk.as_ref())),
            "The keystore was not unlocked."
        );
        // Locked: a read asks again, and with nobody to ask, fails.
        desk.will_type(&[PASSPHRASE]);
        assert!(
            super::read(SERVICE, "bot.API_TOKEN", Kind::Secret)
                .expect("reads")
                .is_some()
        );
        assert_eq!(desk.asked(), 3);
        // A keyring that cannot be reached is a failure: the unlock may
        // still be there.
        *desk.refuses.borrow_mut() = Some(UnlockError::NotHeld);
        let e = refused(lock_at(false, &store, desk.as_ref()));
        assert!(
            e.text().contains("could not drop the unlock"),
            "{}",
            e.text()
        );
        assert!(desk.is_unlocked());
        // Where nothing is ever kept, there is nothing to drop.
        *desk.refuses.borrow_mut() = None;
        desk.keeps.set(false);
        let text = done(lock_at(false, &store, desk.as_ref()));
        assert!(
            text.starts_with("Nothing is kept unlocked on this system"),
            "{text}"
        );
    }

    #[test]
    fn lock_drops_the_unlocks_of_other_keystores_too() {
        const OTHERS: &str = "Unlocks kept for other erpc keystores were dropped as well";
        crate::ui::force_drawn(false);
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, here) = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        // Two more unlocks: keystores under another ERPC_HOME, say, which
        // this command cannot name.
        let elsewhere: Vec<_> = (0..2)
            .map(|_| {
                let (home, other) = store();
                let master = other.create(PASSPHRASE).expect("made");
                desk.keep(&master).expect("kept");
                (home, master)
            })
            .collect();
        assert_eq!(desk.unlocks.borrow().len(), 3);
        assert_eq!(
            done(lock_at(false, &here, desk.as_ref())),
            format!(
                "Keystore locked: the next command that needs it asks for the passphrase.\n\
                 {OTHERS}: 2 (a keystore under another ERPC_HOME, or one whose files are gone)."
            )
        );
        assert!(!desk.is_unlocked());
        // This one locked already, another's unlock still kept.
        desk.keep(&elsewhere[0].1).expect("kept");
        let text = done(lock_at(false, &here, desk.as_ref()));
        assert!(
            text.starts_with(&format!("The keystore was not unlocked.\n{OTHERS}: 1 (")),
            "{text}"
        );
        assert!(!desk.is_unlocked());
        // A keystore whose master.json is gone: its unlock has no key id
        // left to be dropped by, and goes all the same.
        desk.will_type(&[PASSPHRASE]);
        master(&here, desk.as_ref(), Make::No).expect("unlocked");
        assert!(desk.is_unlocked());
        let kept = std::fs::read(here.master_path()).expect("master.json");
        std::fs::remove_file(here.master_path()).expect("removed");
        let text = done(lock_at(false, &here, desk.as_ref()));
        assert!(
            text.starts_with("There is no keystore on this machine"),
            "{text}"
        );
        assert!(text.contains(&format!("\n{OTHERS}: 1 (")), "{text}");
        assert!(!desk.is_unlocked());
        // One whose master.json cannot be read: what is kept is dropped,
        // and the file is said.
        std::fs::write(here.master_path(), b"not a keystore file").expect("written");
        desk.keep(&elsewhere[1].1).expect("kept");
        let text = done(lock_at(false, &here, desk.as_ref()));
        assert!(text.starts_with("warning: "), "{text}");
        assert!(
            text.contains("is not a keystore file erpc can read"),
            "{text}"
        );
        assert!(text.contains(&format!("\n{OTHERS}: 1 (")), "{text}");
        assert!(!desk.is_unlocked());
        // With nothing to drop, it is the failure it was.
        let e = refused(lock_at(false, &here, desk.as_ref()));
        assert!(
            e.text().contains("is not a keystore file erpc can read"),
            "{}",
            e.text()
        );
        // Back as it was, nothing else is said when only this one is kept.
        std::fs::write(here.master_path(), kept).expect("restored");
        desk.will_type(&[PASSPHRASE]);
        master(&here, desk.as_ref(), Make::No).expect("unlocked");
        assert_eq!(
            done(lock_at(false, &here, desk.as_ref())),
            "Keystore locked: the next command that needs it asks for the passphrase."
        );
    }

    #[test]
    fn the_echo_stays_off_from_the_first_prompt_until_the_last_attempt_is_checked() {
        // The desk itself refuses a prompt with the echo on, and an unlock
        // kept with it still off: every test that asks checks that much.
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, store) = set_up(&desk);
        let held = || (desk.hushes.get(), desk.hushed.get());
        // A new keystore: both prompts and the making of it under one hold.
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        assert_eq!(held(), (1, 0));
        // Wrong, wrong, right: one hold over the three prompts and the two
        // checks between them, where the next attempt is typed ahead.
        desk.lock();
        desk.will_type(&["wrong 1", "wrong 2", PASSPHRASE]);
        let before = desk.said_hushed.borrow().len();
        master(&store, desk.as_ref(), Make::No).expect("opens");
        assert_eq!(held(), (2, 0));
        // "It is asked for again", twice, with the echo off; then, with it
        // back on, that the keystore stays unlocked.
        assert_eq!(desk.said_hushed.borrow()[before..], [true, true, false]);
        // Every way out gives it back. Three wrong attempts.
        desk.lock();
        desk.will_type(&["wrong 1", "wrong 2", "wrong 3"]);
        master(&store, desk.as_ref(), Make::No).expect_err("refused");
        assert_eq!(held(), (3, 0));
        // A prompt that fails, after one that did not.
        desk.will_type(&["wrong 1"]);
        let e = master(&store, desk.as_ref(), Make::No).expect_err("no answer");
        assert_eq!(e, "asked more than the test answers");
        assert_eq!(held(), (4, 0));
        // `secret unlock` asks the same way.
        desk.answers.borrow_mut().clear();
        desk.will_type(&["wrong 1", PASSPHRASE]);
        let taken = desk.hushes.get();
        done(unlock_at(false, &store, desk.as_ref()));
        assert_eq!(held(), (taken + 1, 0));
        // A new passphrase that is too short, or typed two ways.
        for answers in [&["too short"][..], &[PASSPHRASE, "correct horse batterY"]] {
            let desk = FakeDesk::typing(answers);
            let _kept = set_up(&desk);
            super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "x", true).expect_err("refused");
            assert_eq!((desk.hushes.get(), desk.hushed.get()), (1, 0));
        }
        // Where nothing is asked, nothing is held.
        let desk = FakeDesk::nobody();
        let _kept = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "x", true).expect_err("nobody");
        assert_eq!(desk.hushes.get(), 0);
    }

    #[test]
    fn a_key_is_not_read_as_a_secret_nor_a_secret_as_a_key() {
        use erpc_core::i18n::Lang;
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, store) = set_up(&desk);
        super::write(SERVICE, "bot.hand", Kind::Key, "the key", true).expect("kept");
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "tok-1", true).expect("kept");
        // Unlocked, and with nobody at a terminal: what a script meets.
        desk.terminal.set(false);
        assert!(desk.is_unlocked());
        let as_secret = || super::read(SERVICE, "bot.hand", Kind::Secret).expect_err("refused");
        let as_key = || super::read(SERVICE, "bot.API_TOKEN", Kind::Key).expect_err("refused");
        // Asked with no read, the answer is the one a read gives.
        assert_eq!(
            super::kept_as(SERVICE, "bot.hand", Kind::Secret),
            Err(as_secret())
        );
        assert_eq!(
            super::kept_as(SERVICE, "bot.API_TOKEN", Kind::Key),
            Err(as_key())
        );
        assert_eq!(super::kept_as(SERVICE, "bot.hand", Kind::Key), Ok(true));
        assert_eq!(super::kept_as(SERVICE, "bot.OTHER", Kind::Key), Ok(false));
        assert_eq!(
            as_secret(),
            "erpc-worker/bot.hand is kept as a trading key: erpc reads it only as the key \
             [wallet] names, for a person at a terminal, and never as a secret"
        );
        assert_eq!(
            as_key(),
            "erpc-worker/bot.API_TOKEN is kept as a secret, and a trading key is not read from \
             it: [wallet] names an entry that was kept as a key"
        );
        // Each as what it is.
        for (account, kind, value) in [
            ("bot.hand", Kind::Key, "the key"),
            ("bot.API_TOKEN", Kind::Secret, "tok-1"),
        ] {
            assert_eq!(
                super::read(SERVICE, account, kind)
                    .expect("reads")
                    .expect("there")
                    .as_str(),
                value
            );
        }
        // A name the keystore holds in another spelling is one file with
        // it where case is ignored: not written, removed or read, and said
        // before anything is asked.
        desk.lock();
        let spelled =
            || super::write(SERVICE, "bot.HAND", Kind::Secret, "x", true).expect_err("refused");
        let file = store.entry_path(SERVICE, "bot.hand").expect("named");
        assert_eq!(
            spelled(),
            format!(
                "erpc-worker/bot.HAND cannot be told apart from {}, which the keystore holds: \
                 where a file system ignores case the two are one file. Nothing was read, \
                 written or removed",
                file.display()
            )
        );
        assert_eq!(super::remove(SERVICE, "bot.HAND").err(), Some(spelled()));
        assert_eq!(super::has(SERVICE, "bot.HAND").err(), Some(spelled()));
        assert_eq!(
            super::read(SERVICE, "bot.HAND", Kind::Secret).err(),
            Some(spelled())
        );
        assert!(file.is_file());
        // In the operator's language.
        desk.terminal.set(true);
        desk.will_type(&[PASSPHRASE]);
        master(&store, desk.as_ref(), Make::No).expect("unlocked");
        for said in [&as_secret as &dyn Fn() -> String, &as_key, &spelled] {
            let english = said();
            for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
                let text = crate::i18n::speaking(lang, said);
                assert_ne!(text, english, "{lang:?}");
                assert!(text.contains("erpc-worker/bot."), "{text}");
                assert!(!text.contains('{'), "{text}");
            }
        }
    }

    #[test]
    fn an_unlock_of_another_keystore_does_not_open_this_one() {
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let _kept = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        // The unlock a desk holds is another keystore's master key.
        let (_other_home, other) = store();
        let theirs = other.create(PASSPHRASE).expect("made");
        desk.lock();
        desk.keep(&theirs).expect("kept");
        desk.terminal.set(false);
        let e = super::read(SERVICE, "bot.API_TOKEN", Kind::Secret).expect_err("locked");
        assert!(e.contains("the keystore is locked"), "{e}");
    }

    #[test]
    fn a_damaged_keystore_is_said_in_the_operators_language() {
        use erpc_core::i18n::Lang;
        let desk = FakeDesk::typing(&[PASSPHRASE, PASSPHRASE]);
        let (_home, store) = set_up(&desk);
        super::write(SERVICE, "bot.API_TOKEN", Kind::Secret, "s3cret-value", true).expect("kept");
        let path = store.entry_path(SERVICE, "bot.API_TOKEN").expect("named");
        std::fs::copy(
            &path,
            store.entry_path(SERVICE, "bot.OTHER").expect("named"),
        )
        .expect("copy");
        let read = || super::read(SERVICE, "bot.OTHER", Kind::Secret).expect_err("refused");
        let english = read();
        assert!(
            english.contains("erpc-worker/bot.OTHER does not open"),
            "{english}"
        );
        for lang in [Lang::Ja, Lang::Zh, Lang::Ru] {
            let said = crate::i18n::speaking(lang, read);
            assert_ne!(said, english, "{lang:?}");
            assert!(said.contains("erpc-worker/bot.OTHER"), "{said}");
            assert!(!said.contains('{'), "{said}");
        }
        // The time an unlock lasts is counted in each language's own way.
        let spans = |lang| {
            crate::i18n::speaking(lang, || {
                [60, 3_600, 7_200, 86_400, 259_200, 432_000, 90_000]
                    .map(super::span)
                    .join(" | ")
            })
        };
        assert_eq!(
            spans(Lang::En),
            "1 minute | 1 hour | 2 hours | 1 day | 3 days | 5 days | 25 hours"
        );
        assert_eq!(
            spans(Lang::Ru),
            "1 минуту | 1 час | 2 часа | 1 день | 3 дня | 5 дней | 25 часов"
        );
    }
}
