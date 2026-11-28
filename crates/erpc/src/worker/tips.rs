// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A spinner, with the time taken and a short trading tip, while a long
//! step of an `erpc worker` command runs: the build (cargo's own lines go
//! to a log, so nothing else is said meanwhile), the wait for a new
//! server to be ready, and the wait for a server kept in the ERPC account
//! to be ready for its first login. Each printed its line and then little
//! else for minutes.
//!
//! At a terminal, and when not quiet (`--json` is), the step's line is the
//! spinner's, with the time since the first step under way began, and
//! below it one tip at a time in the run's language: the next one every
//! [`TIP_EVERY`], the first picked at random. When the step ends, on
//! success or failure, the spinner is taken down and the line is said as
//! it always was (once, for a wait that says it again each round:
//! [`Busy::again`]). Anywhere else (quiet, or where erpc does not draw)
//! the line is said as it always was: when the step starts, and again
//! each round.
//!
//! A deploy builds while a new server gets ready: one spinner shows every
//! step under way, and a line said meanwhile through [`Say`] is printed
//! above it ([`above`]), never into it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::cli::prompt::Spinner;
use crate::node::common::Say;

/// How long a tip is shown before the next one.
const TIP_EVERY: Duration = Duration::from_secs(8);

/// How often the spinner's time and tip are drawn again.
const TICK: Duration = Duration::from_millis(500);

/// How many tips there are: `[tips]` in `worker_tips.toml`.
const TIPS: usize = 30;

/// The tips, in the language of the run.
fn tips() -> [String; TIPS] {
    [
        t!("worker_tips.tips.t01"),
        t!("worker_tips.tips.t02"),
        t!("worker_tips.tips.t03"),
        t!("worker_tips.tips.t04"),
        t!("worker_tips.tips.t05"),
        t!("worker_tips.tips.t06"),
        t!("worker_tips.tips.t07"),
        t!("worker_tips.tips.t08"),
        t!("worker_tips.tips.t09"),
        t!("worker_tips.tips.t10"),
        t!("worker_tips.tips.t11"),
        t!("worker_tips.tips.t12"),
        t!("worker_tips.tips.t13"),
        t!("worker_tips.tips.t14"),
        t!("worker_tips.tips.t15"),
        t!("worker_tips.tips.t16"),
        t!("worker_tips.tips.t17"),
        t!("worker_tips.tips.t18"),
        t!("worker_tips.tips.t19"),
        t!("worker_tips.tips.t20"),
        t!("worker_tips.tips.t21"),
        t!("worker_tips.tips.t22"),
        t!("worker_tips.tips.t23"),
        t!("worker_tips.tips.t24"),
        t!("worker_tips.tips.t25"),
        t!("worker_tips.tips.t26"),
        t!("worker_tips.tips.t27"),
        t!("worker_tips.tips.t28"),
        t!("worker_tips.tips.t29"),
        t!("worker_tips.tips.t30"),
    ]
}

/// Whether a step is shown as a spinner: at a terminal (`drawn`), and
/// when not `quiet`.
const fn spins(quiet: bool, drawn: bool) -> bool {
    !quiet && drawn
}

/// Which of `count` tips is shown `elapsed` into a wait that started on
/// tip `first`: the next one every [`TIP_EVERY`], round to the first.
fn tip_at(first: usize, elapsed: Duration, count: usize) -> usize {
    let count = count.max(1);
    let turns = elapsed.as_secs() / TIP_EVERY.as_secs();
    let turns = usize::try_from(turns % u64::try_from(count).unwrap_or(1)).unwrap_or(0);
    (first % count + turns) % count
}

/// A tip picked at random of `count`, to start on.
fn first_tip(count: usize) -> usize {
    use std::hash::BuildHasher as _;
    let random = std::collections::hash_map::RandomState::new().hash_one(Instant::now());
    usize::try_from(random % u64::try_from(count.max(1)).unwrap_or(1)).unwrap_or(0)
}

/// `elapsed` as a clock: `0:07`, `12:30`, `1:02:03`.
fn clock(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// The lines the spinner shows: each step under way, the first with the
/// time taken, and last the tip.
fn lines(steps: &[String], elapsed: Duration, tip: &str) -> Vec<String> {
    let mut out: Vec<String> = steps.to_vec();
    if let Some(first) = out.first_mut() {
        first.push_str(" · ");
        first.push_str(&clock(elapsed));
    }
    out.push(tip.to_owned());
    out
}

/// The steps under way, and the spinner that shows them.
struct Board {
    next: u64,
    steps: Vec<(u64, String)>,
    session: Option<Session>,
}

/// From the first step under way to the last: the spinner, and what it
/// shows besides the steps.
struct Session {
    /// Up, but for the moment a line is printed above it.
    spinner: Option<Spinner>,
    since: Instant,
    first: usize,
    /// Each with its label, in the language of the run.
    tips: Vec<String>,
    stop: Arc<AtomicBool>,
    ticker: Option<JoinHandle<()>>,
    /// In a test: how many times a spinner was put up for it.
    #[cfg(test)]
    raised: u32,
}

impl Session {
    /// What the spinner shows of `steps` now, the tip dimmed.
    fn drawn(&self, steps: &[(u64, String)]) -> String {
        let elapsed = self.since.elapsed();
        let tip = self
            .tips
            .get(tip_at(self.first, elapsed, self.tips.len()))
            .map_or("", String::as_str);
        let steps: Vec<String> = steps.iter().map(|(_, line)| line.clone()).collect();
        let mut drawn = lines(&steps, elapsed, tip);
        if let Some(tip) = drawn.last_mut() {
            *tip = console::Style::new()
                .dim()
                .for_stderr()
                .apply_to(&*tip)
                .to_string();
        }
        // Under the spinner's message, past its mark.
        drawn.join("\n   ")
    }
}

static BOARD: Mutex<Board> = Mutex::new(Board {
    next: 0,
    steps: Vec::new(),
    session: None,
});

fn board() -> MutexGuard<'static, Board> {
    BOARD.lock().unwrap_or_else(PoisonError::into_inner)
}

/// In a test: how many spinners are up, and how many times a line was
/// printed with none on the board while one was still up, which the lock
/// is there to make never happen.
#[cfg(test)]
static LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static STRAY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A spinner put up, showing `drawn`. Only while the board is locked.
fn put_up(drawn: &str) -> Spinner {
    let spinner = Spinner::start(drawn.lines().next().unwrap_or_default());
    spinner.set_message(drawn);
    #[cfg(test)]
    LIVE.fetch_add(1, Ordering::SeqCst);
    spinner
}

/// `spinner` taken off the screen. Only while the board is locked, so that
/// no line is printed while it is still drawn and the board shows none.
fn take_down(spinner: Spinner) {
    spinner.done();
    #[cfg(test)]
    LIVE.fetch_sub(1, Ordering::SeqCst);
}

/// The spinner put up, or drawn again with the steps under way now.
fn raise(board: &mut Board) {
    let Board { steps, session, .. } = board;
    let Some(session) = session else {
        return;
    };
    let drawn = session.drawn(steps);
    if let Some(spinner) = &session.spinner {
        spinner.set_message(&drawn);
    } else {
        session.spinner = Some(put_up(&drawn));
        #[cfg(test)]
        {
            session.raised += 1;
        }
    }
}

/// Draws the spinner again every [`TICK`] until `stop`.
fn ticker(stop: Arc<AtomicBool>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        loop {
            std::thread::park_timeout(TICK);
            let mut board = board();
            if stop.load(Ordering::Acquire) {
                return;
            }
            raise(&mut board);
        }
    })
}

/// A long step under way, from [`busy`] until it is dropped.
pub(crate) struct Busy {
    /// On the board: shown by the spinner.
    id: Option<u64>,
}

/// Step `line` begins, as `say` says it: at a terminal and when not quiet,
/// as the spinner's line, said once the [`Busy`] is dropped; anywhere
/// else, said now.
pub(crate) fn busy(say: &Say, line: String) -> Busy {
    if !spins(say.quiet, crate::cli::ui::stderr_drawn()) {
        say.line(&line);
        return Busy { id: None };
    }
    // Read here: the language of the run is this thread's in a test.
    let label = |tip: &String| t!("worker_tips.tip", tip);
    let tips: Vec<String> = tips().iter().map(label).collect();
    let mut board = board();
    let id = board.next;
    board.next += 1;
    board.steps.push((id, line));
    if board.session.is_none() {
        let stop = Arc::new(AtomicBool::new(false));
        board.session = Some(Session {
            spinner: None,
            since: Instant::now(),
            first: first_tip(tips.len()),
            tips,
            stop: Arc::clone(&stop),
            ticker: Some(ticker(stop)),
            #[cfg(test)]
            raised: 0,
        });
    }
    raise(&mut board);
    Busy { id: Some(id) }
}

impl Busy {
    /// The step's line said again, as a wait says it each round: anywhere
    /// but at a spinner as a line, now; at one, as the spinner's line from
    /// now on.
    pub(crate) fn again(&self, say: &Say, line: String) {
        let Some(id) = self.id else {
            say.line(&line);
            return;
        };
        let mut board = board();
        if let Some(step) = board.steps.iter_mut().find(|(at, _)| *at == id) {
            step.1 = line;
        }
        raise(&mut board);
    }
}

impl Drop for Busy {
    /// The step is over: off the spinner, which is taken down when it was
    /// the last, and its line said.
    fn drop(&mut self) {
        let Some(id) = self.id else {
            return;
        };
        let (line, ended) = {
            let mut board = board();
            let line = board
                .steps
                .iter()
                .position(|(at, _)| *at == id)
                .map(|at| board.steps.remove(at).1);
            let mut ended = if board.steps.is_empty() {
                board.session.take()
            } else {
                raise(&mut board);
                None
            };
            // The last step: the spinner is off the screen before the lock
            // is let go, so a line said from another thread meanwhile is
            // never printed into it.
            if let Some(ended) = &mut ended {
                ended.stop.store(true, Ordering::Release);
                if let Some(spinner) = ended.spinner.take() {
                    take_down(spinner);
                }
            }
            (line, ended)
        };
        // Joined once the lock is let go, which the ticker takes to see
        // that it is to stop.
        if let Some(ticker) = ended.and_then(|mut ended| ended.ticker.take()) {
            ticker.thread().unpark();
            let _ = ticker.join();
        }
        if let Some(line) = line {
            Say { quiet: false }.line(&line);
        }
    }
}

/// Prints with `print` above the spinner while one is up, so that the
/// line is not drawn into it; as it is when none is.
pub(crate) fn above(print: impl FnOnce()) {
    let mut board = board();
    let Some(spinner) = board.session.as_mut().and_then(|s| s.spinner.take()) else {
        #[cfg(test)]
        if LIVE.load(Ordering::SeqCst) > 0 {
            STRAY.fetch_add(1, Ordering::SeqCst);
        }
        // Printed with the lock held, so that no spinner is put up while
        // the line is half out.
        print();
        return;
    };
    take_down(spinner);
    print();
    raise(&mut board);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use erpc_core::i18n::Lang;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{
        Busy, STRAY, TIP_EVERY, TIPS, above, board, busy, clock, first_tip, lines, spins, tip_at,
        tips,
    };
    use crate::cli::i18n::{CATALOG, speaking};
    use crate::node::common::{Say, heard};

    /// The tests that put a spinner up share the one board.
    static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn on_board(busy: &Busy) -> bool {
        let id = busy.id.expect("on the board");
        board().steps.iter().any(|(at, _)| *at == id)
    }

    #[test]
    fn a_step_spins_only_at_a_terminal_and_when_not_quiet() {
        assert!(spins(false, true));
        assert!(!spins(true, true));
        assert!(!spins(false, false));
        assert!(!spins(true, false));
    }

    /// Quiet (`--json`), or off a terminal: no spinner, and the line is
    /// said when the step starts, as it always was, and again each round.
    #[test]
    fn quiet_or_off_a_terminal_a_step_is_said_at_once_and_nothing_spins() {
        for (quiet, drawn) in [(true, true), (true, false), (false, false)] {
            crate::cli::ui::force_drawn(drawn);
            let _ = heard::take();
            let _ = heard::take_printed();
            let say = Say { quiet };
            let step = busy(&say, "building".to_owned());
            assert!(step.id.is_none(), "quiet {quiet}, drawn {drawn}");
            assert_eq!(heard::take(), ["building"]);
            step.again(&say, "still building".to_owned());
            assert_eq!(heard::take(), ["still building"]);
            drop(step);
            assert!(heard::take().is_empty(), "nothing more when it ends");
            let printed = heard::take_printed();
            if quiet {
                assert!(printed.is_empty(), "{printed:?}");
            } else {
                assert_eq!(printed, ["building", "still building"]);
            }
        }
    }

    /// At a terminal: the line is the spinner's while the step runs, and
    /// said once it ends; two steps at once share one spinner, which goes
    /// with the last.
    #[test]
    fn at_a_terminal_a_step_is_the_spinners_line_and_said_when_it_ends() {
        let _one = ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::cli::ui::force_drawn(true);
        let _ = heard::take_printed();
        let say = Say { quiet: false };
        // Which session is up, and how many times it put a spinner up.
        let session = || {
            board()
                .session
                .as_ref()
                .filter(|s| s.spinner.is_some())
                .map(|s| (Arc::as_ptr(&s.stop), s.raised))
        };
        let build = busy(&say, "building".to_owned());
        let first = session().expect("a spinner up").0;
        let wait = busy(&say, "waiting for server 1".to_owned());
        assert!(heard::take_printed().is_empty(), "said only once it ends");
        assert!(on_board(&build) && on_board(&wait));
        assert_eq!(session(), Some((first, 1)), "the second step joined it");
        wait.again(&say, "waiting for server 1, again".to_owned());
        assert!(heard::take_printed().is_empty(), "a round is not a line");
        // A line said meanwhile is printed with the spinner taken down,
        // and the spinner is put up again.
        above(|| {});
        assert_eq!(session(), Some((first, 2)));
        Say { quiet: false }.line("said meanwhile");
        assert_eq!(heard::take_printed(), ["said meanwhile"]);
        assert_eq!(session(), Some((first, 3)), "Say goes above it too");
        drop(build);
        assert_eq!(heard::take_printed(), ["building"]);
        assert!(board().session.is_some(), "one step still under way");
        drop(wait);
        assert_eq!(heard::take_printed(), ["waiting for server 1, again"]);
        assert!(board().session.is_none(), "the last step took it down");
        crate::cli::ui::force_drawn(false);
    }

    /// Lines said from another thread while steps begin and end are never
    /// printed while a spinner is still drawn that the board no longer
    /// shows, where they would be drawn into it and wiped with it.
    #[test]
    fn a_line_said_meanwhile_never_lands_in_a_spinner_going_down() {
        let _one = ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let strays = STRAY.load(Ordering::SeqCst);
        let done = Arc::new(AtomicBool::new(false));
        let saying = {
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    above(|| {});
                }
            })
        };
        crate::cli::ui::force_drawn(true);
        let say = Say { quiet: false };
        for _ in 0..300 {
            drop(busy(&say, "building".to_owned()));
        }
        done.store(true, Ordering::SeqCst);
        saying.join().expect("the other thread");
        crate::cli::ui::force_drawn(false);
        let _ = heard::take_printed();
        assert_eq!(STRAY.load(Ordering::SeqCst), strays);
    }

    /// One tip at a time, the next every eight seconds, round to the first.
    #[test]
    fn the_tips_turn_in_order_from_the_first() {
        assert_eq!(TIP_EVERY, Duration::from_secs(8), "as the docs say");
        let at = |secs: u64| tip_at(28, Duration::from_secs(secs), 30);
        assert_eq!(at(0), 28);
        assert_eq!(at(7), 28);
        assert_eq!(at(8), 29);
        assert_eq!(at(16), 0);
        assert_eq!(at(24), 1);
        assert_eq!(at(30 * 8), 28, "round to the first");
        assert_eq!(tip_at(0, Duration::from_secs(8), 1), 0);
        // The first is one of them, and not always the same one.
        let firsts: std::collections::BTreeSet<usize> = (0..200).map(|_| first_tip(TIPS)).collect();
        assert!(
            firsts.len() > 1 && firsts.iter().all(|i| *i < TIPS),
            "{firsts:?}"
        );
        assert_eq!(clock(Duration::from_secs(7)), "0:07");
        assert_eq!(clock(Duration::from_secs(750)), "12:30");
        assert_eq!(clock(Duration::from_secs(3723)), "1:02:03");
        assert_eq!(
            lines(
                &["building".to_owned(), "waiting".to_owned()],
                Duration::from_secs(65),
                "Tip: one"
            ),
            ["building · 1:05", "waiting", "Tip: one"]
        );
    }

    /// Whether `text` holds a link: a scheme, `www.`, or a host with a path
    /// (`erpc.global/en`).
    fn has_link(text: &str) -> bool {
        let lower = text.to_lowercase();
        if ["://", "www."].iter().any(|m| lower.contains(m)) {
            return true;
        }
        lower.match_indices('/').any(|(at, _)| {
            let host: Vec<char> = lower[..at]
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                .collect();
            let host: String = host.into_iter().rev().collect();
            host.rsplit_once('.').is_some_and(|(name, top)| {
                !name.is_empty() && top.len() > 1 && top.chars().all(|c| c.is_ascii_alphabetic())
            })
        })
    }

    #[test]
    fn a_link_is_found_with_a_scheme_or_without() {
        for link in [
            "See erpc.global/en/news. Then",
            "https://erpc.global",
            "HTTPS://ERPC.GLOBAL",
            "ftp://host",
            "at www.example then",
            "docs at example.com/path",
        ] {
            assert!(has_link(link), "{link}");
        }
        for plain in [
            "add history=true to your edge.erpc.global URL",
            "HTTP (no TLS work) or HTTPS",
            "ping/pong",
            "RPC/WebSocket",
            "TPU/QUIC",
            "about 0.1ms/hop",
            "Geyser gRPCではping/pongに応答し",
        ] {
            assert!(!has_link(plain), "{plain}");
        }
    }

    /// Every tip, in every language: there, said, distinct, and with no
    /// link in it.
    #[test]
    fn every_tip_is_said_in_every_language() {
        let keys = CATALOG
            .keys()
            .filter(|k| k.starts_with("worker_tips.tips."))
            .count();
        assert_eq!(keys, TIPS, "tips() names every tip in the catalog");
        for lang in Lang::ALL {
            let said = speaking(lang, tips);
            let distinct: std::collections::BTreeSet<&String> = said.iter().collect();
            assert_eq!(distinct.len(), TIPS, "{lang:?}");
            for tip in &said {
                assert!(
                    !tip.is_empty() && !tip.starts_with("worker_tips."),
                    "{lang:?}: {tip}"
                );
                assert!(!has_link(tip), "{lang:?}: {tip}");
            }
        }
        let tip = speaking(Lang::Ja, || t!("worker_tips.tip", tip = "x"));
        assert_eq!(tip, "ヒント：x");
    }
}
