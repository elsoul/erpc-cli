// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What erpc does when it is asked to stop: Ctrl-C, SIGTERM, or the
//! terminal closing.
//!
//! The default is to end the process wherever it is, and in one place that
//! signs the operator out. A session rotation spends the old refresh token
//! at the issuer before the store has the new one; ended in between, the
//! store keeps the spent token, the next refresh presents it, and the
//! issuer revokes the whole family.
//!
//! So erpc answers these signals itself, on a thread of its own, so that it
//! answers while the main thread is inside a blocking call. On Windows that
//! is Ctrl-C only. With no
//! rotation under way it does what the default did: it ends at once, by the
//! same signal, so that a shell or a script sees exactly what it saw before.
//! During a rotation it waits for the store. If the store has not taken the
//! new session within [`SAVE_GRACE`], or a second signal comes, it parks the
//! session where the next command files it into the store, and ends.
//!
//! Ctrl-C during a turn of `erpc ai -m` stops the turn instead: the turn
//! waits on [`ctrl_c`], and the signal goes to it.
//!
//! A panic is the other way the process ends mid-rotation: a release build
//! aborts on one. Before it does, the session the store has not taken yet is
//! parked too. A rotation still waiting for the issuer has nothing to park.
//!
//! Neither way out runs destructors, so both also wipe the Solana signer
//! files a command has on disk ([`erpc_chain_solana::cli::wipe_live`]),
//! stop a command the assistant is running, which would otherwise run on
//! with nobody reading it ([`erpc_ai::commands::stop_live`], on Unix), and
//! turn the terminal's echo back on where a passphrase prompt holds it off
//! ([`crate::echo::restore`]).

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use erpc_auth::session::Leaving;
use tokio::sync::Notify;

/// How long a rotation's save is waited for once erpc is asked to stop.
pub const SAVE_GRACE: Duration = Duration::from_secs(10);

/// Whether the thread is answering signals.
static INSTALLED: AtomicBool = AtomicBool::new(false);
/// How many waits on [`ctrl_c`] there are. While there is one, Ctrl-C goes
/// to them.
static CLAIMS: AtomicUsize = AtomicUsize::new(0);
static CTRL_C: Notify = Notify::const_new();

/// Whether a panic ends the process, as it does in a release build.
const PANICS_ABORT: bool = cfg!(panic = "abort");

/// Starts answering signals. Until it is called, and if it fails, they keep
/// their default action.
pub fn install() {
    install_with(SAVE_GRACE);
    park_on_panic(PANICS_ABORT);
}

/// Puts the park in front of the panic hooks installed since [`install`].
/// For one that can panic itself, as `ratatui::init`'s does once the
/// terminal is gone: a panic in a panic hook aborts before the hooks behind
/// it run.
pub fn park_first_on_panic() {
    park_on_panic(PANICS_ABORT);
}

/// Parks what the store has not taken yet before a panic ends the process,
/// when a panic does, then runs the hooks installed before.
fn park_on_panic(fatal: bool) {
    if !fatal {
        return;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        erpc_chain_solana::cli::wipe_live();
        erpc_ai::commands::stop_live();
        crate::echo::restore();
        let _ = Leaving::start().park();
        previous(info);
    }));
}

fn install_with(grace: Duration) {
    let (ready, started) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("erpc-signals".to_owned())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                let _ = ready.send(());
                return;
            };
            runtime.block_on(async move {
                let signals = Signals::listen();
                INSTALLED.store(signals.is_ok(), Ordering::SeqCst);
                let _ = ready.send(());
                if let Ok(signals) = signals {
                    answer(signals, grace).await;
                }
            });
        });
    // The handlers are in place once this returns, so a Ctrl-C that comes
    // early is not left to the default. If the thread could not start, the
    // sender is already gone and this returns at once.
    drop(spawned);
    let _ = started.recv();
}

/// Resolves on the next Ctrl-C, which then goes to this wait rather than
/// ending erpc. For a turn that Ctrl-C stops.
pub async fn ctrl_c() {
    if !INSTALLED.load(Ordering::SeqCst) {
        // Nothing answers signals: take Ctrl-C from the runtime, or never
        // stop rather than stop at once.
        if tokio::signal::ctrl_c().await.is_err() {
            core::future::pending::<()>().await;
        }
        return;
    }
    let mut notified = std::pin::pin!(CTRL_C.notified());
    // Waiting before the claim is counted, so a Ctrl-C that sees the claim
    // reaches this wait.
    notified.as_mut().enable();
    let _claim = Claim::new();
    notified.await;
}

/// Ctrl-C taken for a whole stretch of work, and kept: from [`Hold::new`]
/// on it goes to the hold, which remembers it, whether or not anything was
/// waiting for it when it came.
///
/// For work that must be followed by its own undoing, as hourly lines
/// bought for a run are ended when the run ends. A wait on [`ctrl_c`] made
/// only around the slow steps leaves the requests between them to the
/// default, and erpc then ends in the middle with the lines still charged.
///
/// It keeps one Ctrl-C. A second one, once the first has come, ends erpc
/// as it would without a hold.
pub struct Hold {
    wait: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
    came: bool,
}

impl Hold {
    /// Takes Ctrl-C from here on.
    pub fn new() -> Self {
        Self::of(ctrl_c())
    }

    /// A hold on whatever `wait` resolves on, in place of Ctrl-C.
    pub fn of(wait: impl Future<Output = ()> + Send + 'static) -> Self {
        let mut hold = Self {
            wait: Box::pin(wait),
            came: false,
        };
        // Polled once now: that is what counts the claim, so that Ctrl-C
        // goes to this hold before anything waits on it.
        let _ = hold.came();
        hold
    }

    /// Whether Ctrl-C has come since the hold began. Does not wait.
    pub fn came(&mut self) -> bool {
        if !self.came {
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            self.came = self.wait.as_mut().poll(&mut context).is_ready();
        }
        self.came
    }

    /// Resolves once Ctrl-C has come: at once when it already has.
    pub async fn wait(&mut self) {
        if !self.came {
            self.wait.as_mut().await;
            self.came = true;
        }
    }
}

impl Default for Hold {
    fn default() -> Self {
        Self::new()
    }
}

/// One wait on [`ctrl_c`], counted in [`CLAIMS`] for as long as it lives.
struct Claim;

impl Claim {
    fn new() -> Self {
        CLAIMS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        CLAIMS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Writes a line to stderr, or nothing if stderr is gone, as it is once the
/// terminal has closed. `eprintln!` would panic there, and a panic aborts.
pub fn say(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

async fn answer(mut signals: Signals, grace: Duration) {
    while let Some(asked) = signals.next().await {
        if asked == Asked::Interrupt && CLAIMS.load(Ordering::SeqCst) > 0 {
            CTRL_C.notify_waiters();
            continue;
        }
        leave(&mut signals, asked, grace).await;
    }
}

/// Ends the process as `asked` asked, once that loses no session.
async fn leave(signals: &mut Signals, asked: Asked, grace: Duration) {
    // From here no rotation starts.
    let leaving = Leaving::start();
    if leaving.rotating() {
        say(
            "erpc: saving the refreshed session before leaving (ask again to leave now; the next command saves it)",
        );
        let saved = tokio::select! {
            () = leaving.settled() => true,
            () = tokio::time::sleep(grace) => false,
            _ = signals.next() => false,
        };
        if !saved {
            // The store is taking too long, or the operator will not wait.
            // The new session goes where the next command files it into the
            // store, not nowhere. One still on its way back from the issuer
            // is waited for; the request has a timeout.
            leaving.answered().await;
            for parked in leaving.park() {
                match parked {
                    Ok(at) => say(&format!(
                        "erpc: the refreshed session is parked at {} until the next command saves it",
                        at.display()
                    )),
                    Err(e) => say(&format!("erpc: could not park the refreshed session: {e}")),
                }
            }
        }
    }
    // Ending by the signal runs no destructors: the signer files a command
    // has on disk go first, a command the assistant is running is stopped
    // rather than left to run on unread, and a terminal whose echo a
    // passphrase prompt holds off gets it back.
    erpc_chain_solana::cli::wipe_live();
    erpc_ai::commands::stop_live();
    crate::echo::restore();
    end(asked);
}

/// Ends the process by the signal that asked, with its default action, as
/// if erpc had never answered it. A script that runs erpc in a loop stops
/// on Ctrl-C only when erpc died of it; an exit status of 130 does not stop
/// it. If the signal cannot be raised again, signal-hook aborts instead.
#[cfg(unix)]
fn end(asked: Asked) -> ! {
    let _ = signal_hook::low_level::emulate_default_handler(asked.signal());
    // Not reached: signal-hook has ended the process either way.
    std::process::exit(128 + asked.signal());
}

/// Ends the process as Windows' own Ctrl-C handler does, with
/// `STATUS_CONTROL_C_EXIT`.
#[cfg(not(unix))]
fn end(_asked: Asked) -> ! {
    #[allow(clippy::cast_possible_wrap)]
    std::process::exit(0xC000_013A_u32 as i32);
}

/// A request to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
enum Asked {
    /// Ctrl-C.
    Interrupt,
    /// SIGTERM.
    Terminate,
    /// The terminal closed.
    HangUp,
}

impl Asked {
    #[cfg(unix)]
    const fn signal(self) -> i32 {
        use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
        match self {
            Self::Interrupt => SIGINT,
            Self::Terminate => SIGTERM,
            Self::HangUp => SIGHUP,
        }
    }
}

#[cfg(unix)]
struct Signals {
    interrupt: tokio::signal::unix::Signal,
    terminate: Option<tokio::signal::unix::Signal>,
    hangup: Option<tokio::signal::unix::Signal>,
}

#[cfg(unix)]
impl Signals {
    /// Takes the signals over. Ctrl-C first: if that fails nothing has
    /// changed, and if a later one fails it keeps its default.
    fn listen() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate()).ok(),
            hangup: signal(SignalKind::hangup()).ok(),
        })
    }

    async fn next(&mut self) -> Option<Asked> {
        tokio::select! {
            got = self.interrupt.recv() => got.map(|()| Asked::Interrupt),
            got = recv(self.terminate.as_mut()) => got.map(|()| Asked::Terminate),
            got = recv(self.hangup.as_mut()) => got.map(|()| Asked::HangUp),
        }
    }
}

#[cfg(unix)]
async fn recv(signal: Option<&mut tokio::signal::unix::Signal>) -> Option<()> {
    match signal {
        Some(signal) => signal.recv().await,
        None => core::future::pending().await,
    }
}

#[cfg(windows)]
struct Signals {
    ctrl_c: tokio::signal::windows::CtrlC,
}

#[cfg(windows)]
impl Signals {
    fn listen() -> std::io::Result<Self> {
        Ok(Self {
            ctrl_c: tokio::signal::windows::ctrl_c()?,
        })
    }

    async fn next(&mut self) -> Option<Asked> {
        self.ctrl_c.recv().await.map(|()| Asked::Interrupt)
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    //! Each case runs in a child: this test binary again, running only
    //! [`child`] with `ERPC_SIGNAL_CASE` set. A signal reaches the whole
    //! process and its handler stays for the process's life, so the cases
    //! cannot share the test runner's process.

    use std::io::{BufRead as _, BufReader};
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{Receiver, channel};
    use std::time::{Duration, Instant};

    use erpc_auth::session::Refresher;
    use erpc_auth::store::file::FileStore;
    use erpc_auth::{
        Audience, CredKey, Credential, CredentialStore, HttpError, StoreError, StoreKind,
        current_session,
    };
    use secrecy::{ExposeSecret as _, SecretString};
    use signal_hook::consts::{SIGABRT, SIGHUP, SIGINT, SIGKILL, SIGTERM};

    const CASE: &str = "ERPC_SIGNAL_CASE";
    const DIR: &str = "ERPC_SIGNAL_DIR";
    const GRACE_MS: &str = "ERPC_SIGNAL_GRACE_MS";
    const ISSUER_MS: &str = "ERPC_SIGNAL_ISSUER_MS";
    /// A time at which `session("OLD")` needs refreshing.
    const NOW: i64 = 2_000;

    /// In the child: whether the issuer has been asked, and whether a save
    /// has begun.
    static ASKED: AtomicBool = AtomicBool::new(false);
    static SAVING: AtomicBool = AtomicBool::new(false);

    fn session(tag: &str) -> Credential {
        Credential {
            access_token: SecretString::from(format!("acc.{tag}.s")),
            refresh_token: SecretString::from(format!("ref.{tag}.s")),
            expires_at: 1_000,
        }
    }

    fn key() -> CredKey {
        CredKey::new(crate::session::LOGIN_AUDIENCE, "alice")
    }

    fn store_at(dir: &Path) -> FileStore {
        FileStore::new(dir.join("credentials.toml"))
    }

    fn parked_at(dir: &Path) -> PathBuf {
        erpc_auth::session::parked_path(dir, crate::session::LOGIN_AUDIENCE)
    }

    fn env_ms(name: &str, otherwise: u64) -> Duration {
        Duration::from_millis(
            std::env::var(name)
                .ok()
                .and_then(|ms| ms.parse().ok())
                .unwrap_or(otherwise),
        )
    }

    /// Rotates any session into `session("NEW")`, `ERPC_SIGNAL_ISSUER_MS`
    /// after it is asked, and says so on stdout.
    #[derive(Clone)]
    struct SlowIssuer;

    impl Refresher for SlowIssuer {
        fn refresh(
            &self,
            _audience: Audience,
            _refresh_token: &SecretString,
            _now: i64,
        ) -> impl Future<Output = Result<Credential, HttpError>> + Send {
            ASKED.store(true, Ordering::SeqCst);
            println!("refreshing");
            let delay = env_ms(ISSUER_MS, 300);
            async move {
                tokio::time::sleep(delay).await;
                Ok(session("NEW"))
            }
        }
    }

    /// The file store, except that a save never comes back, the way a
    /// keyring save waits on an unlock prompt nobody answers.
    struct HangingStore(FileStore);

    impl CredentialStore for HangingStore {
        fn load(&self, key: &CredKey) -> Result<Option<Credential>, StoreError> {
            self.0.load(key)
        }
        fn save(&self, _key: &CredKey, _cred: &Credential) -> Result<(), StoreError> {
            SAVING.store(true, Ordering::SeqCst);
            println!("saving");
            std::thread::sleep(Duration::from_secs(3600));
            Ok(())
        }
        fn delete(&self, key: &CredKey) -> Result<(), StoreError> {
            self.0.delete(key)
        }
        fn kind(&self) -> StoreKind {
            StoreKind::OsKeychain
        }
    }

    async fn until(flag: &AtomicBool) {
        while !flag.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// The child's side. Without `ERPC_SIGNAL_CASE` it does nothing, which is
    /// how it runs among the other tests.
    #[test]
    fn child() {
        let Ok(case) = std::env::var(CASE) else {
            return;
        };
        let dir = PathBuf::from(std::env::var(DIR).expect("a directory"));
        super::install_with(env_ms(GRACE_MS, 10_000));
        if case == "after the command" {
            // The command has finished with a rotation still saving, and
            // `run_to_end` waits for it.
            let _ = crate::run_to_end(async move {
                rotate(Arc::new(HangingStore(store_at(&dir))), dir);
                until(&SAVING).await;
            });
            unreachable!("the save never comes back");
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(async move {
            match case.as_str() {
                "idle" => println!("ready"),
                "rotating" => rotate(Arc::new(store_at(&dir)), dir),
                "hanging" => rotate(Arc::new(HangingStore(store_at(&dir))), dir),
                "terminal gone" => {
                    // The console's way out once the terminal has closed: a
                    // draw fails, and the failure is reported to a stderr
                    // that is no longer there.
                    rotate(Arc::new(store_at(&dir)), dir);
                    until(&ASKED).await;
                    let _ = crate::finish(crate::commands::Outcome::Failed(
                        "could not draw to the terminal".to_owned(),
                    ));
                    crate::print_json(&serde_json::json!({ "status": "failed" }));
                }
                "panic behind a hook" => {
                    // As in the console: a hook installed after erpc's that
                    // panics itself, as ratatui's does once the terminal is
                    // gone, and erpc's put back in front of it.
                    super::park_on_panic(true);
                    std::panic::set_hook(Box::new(|_| panic!("could not restore the terminal")));
                    super::park_on_panic(true);
                    rotate(Arc::new(HangingStore(store_at(&dir))), dir);
                    until(&SAVING).await;
                    let _ = std::thread::spawn(|| panic!("a bug")).join();
                    unreachable!("a panic in a panic hook aborts");
                }
                "panic" => {
                    super::park_on_panic(true);
                    rotate(Arc::new(HangingStore(store_at(&dir))), dir);
                    until(&SAVING).await;
                    let _ = std::thread::spawn(|| panic!("a bug")).join();
                    println!("panicked");
                }
                "signer" => {
                    // A command with a signer file on disk, as `erpc v
                    // vote-account` has while the CLI runs.
                    let key = zeroize::Zeroizing::new("[1,2,3]".to_owned());
                    let pipes = erpc_chain_solana::cli::Pipes::new(&dir, &[&key]).expect("pipes");
                    println!("ready");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(pipes);
                }
                "command" => commanding(&dir, false).await,
                "command panic" => commanding(&dir, true).await,
                "echo" => echoing(&dir, false).await,
                "echo panic" => echoing(&dir, true).await,
                "signer panic" => {
                    super::park_on_panic(true);
                    let key = zeroize::Zeroizing::new("[1,2,3]".to_owned());
                    let pipes = erpc_chain_solana::cli::Pipes::new(&dir, &[&key]).expect("pipes");
                    let _ = std::thread::spawn(|| panic!("a bug")).join();
                    println!("panicked");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(pipes);
                }
                "turn" => {
                    tokio::spawn(async {
                        super::ctrl_c().await;
                        println!("turn stopped");
                    });
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    println!("ready");
                }
                "hold" => {
                    // A run that has bought a line and is in the middle of
                    // a request, with nothing waiting on Ctrl-C.
                    let mut hold = super::Hold::new();
                    println!("ready");
                    tokio::time::sleep(Duration::from_millis(600)).await;
                    println!("request done, ctrl-c came: {}", hold.came());
                    hold.wait().await;
                    println!("lines ended");
                }
                other => panic!("no case {other}"),
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
    }

    fn rotate(store: Arc<dyn CredentialStore + Send + Sync>, dir: PathBuf) {
        tokio::spawn(async move {
            let _ = current_session(&SlowIssuer, &store, &key(), &dir, NOW).await;
        });
    }

    /// How a child is set up.
    struct Setup<'a> {
        case: &'a str,
        dir: &'a Path,
        grace: Duration,
        issuer: Duration,
        /// Closes the reading end of the child's stderr at once, as a
        /// closed terminal would.
        stderr_gone: bool,
        /// The terminal on the child's standard input; without one it has
        /// nothing there.
        terminal: Option<&'a std::os::fd::OwnedFd>,
    }

    impl<'a> Setup<'a> {
        fn new(case: &'a str, dir: &'a Path) -> Self {
            Self {
                case,
                dir,
                grace: Duration::from_secs(10),
                issuer: Duration::from_millis(300),
                stderr_gone: false,
                terminal: None,
            }
        }
    }

    /// A child running one case, and its stdout and stderr as lines.
    struct Child {
        process: std::process::Child,
        lines: Receiver<String>,
    }

    impl Child {
        fn spawn(setup: &Setup<'_>) -> Self {
            let mut process = Command::new(std::env::current_exe().expect("this test binary"))
                .args(["--exact", "interrupt::tests::child", "--nocapture"])
                .env(CASE, setup.case)
                .env(DIR, setup.dir)
                .env(GRACE_MS, setup.grace.as_millis().to_string())
                .env(ISSUER_MS, setup.issuer.as_millis().to_string())
                .stdin(setup.terminal.map_or_else(Stdio::null, |terminal| {
                    Stdio::from(terminal.try_clone().expect("a handle on the terminal"))
                }))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("the child");
            let (send, lines) = channel();
            let stdout = process.stdout.take().expect("stdout");
            let stderr = process.stderr.take().expect("stderr");
            let mut outs: Vec<Box<dyn std::io::Read + Send>> = vec![Box::new(stdout)];
            if setup.stderr_gone {
                drop(stderr);
            } else {
                outs.push(Box::new(stderr));
            }
            for out in outs {
                let send = send.clone();
                std::thread::spawn(move || {
                    for line in BufReader::new(out).lines().map_while(Result::ok) {
                        let _ = send.send(line);
                    }
                });
            }
            Self { process, lines }
        }

        /// Waits for a line containing `wanted`.
        fn expect(&self, wanted: &str) {
            let until = Instant::now() + Duration::from_secs(10);
            while let Some(left) = until.checked_duration_since(Instant::now()) {
                match self.lines.recv_timeout(left) {
                    Ok(line) if line.contains(wanted) => return,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            panic!("the child never said {wanted:?}");
        }

        fn signal(&self, name: &str) {
            let sent = Command::new("kill")
                .args([format!("-{name}"), self.process.id().to_string()])
                .status()
                .expect("kill");
            assert!(sent.success(), "kill -{name}");
        }

        /// Waits for the child to end.
        fn ended(mut self) -> ExitStatus {
            let until = Instant::now() + Duration::from_secs(10);
            while Instant::now() < until {
                if let Some(status) = self.process.try_wait().expect("the child's status") {
                    return status;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = self.process.kill();
            panic!("the child did not end");
        }

        fn running_after(&mut self, wait: Duration) -> bool {
            std::thread::sleep(wait);
            self.process
                .try_wait()
                .expect("the child's status")
                .is_none()
        }
    }

    /// A state directory whose store holds `session("OLD")`.
    fn holding_old() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a temporary directory");
        store_at(dir.path())
            .save(&key(), &session("OLD"))
            .expect("save");
        dir
    }

    fn stored(dir: &Path) -> String {
        let held = store_at(dir).load(&key()).expect("readable").expect("held");
        held.refresh_token.expose_secret().to_owned()
    }

    /// The parked session the next command will file into the store.
    fn parked_over_old(dir: &Path) {
        let parked = erpc_auth::lock::read_parked(&parked_at(dir))
            .expect("readable")
            .expect("parked");
        assert_eq!(parked.credential.refresh_token.expose_secret(), "ref.NEW.s");
        assert!(parked.supersedes(Some(&session("OLD"))));
        assert_eq!(stored(dir), "ref.OLD.s", "the store never answered");
    }

    #[test]
    fn ctrl_c_with_nothing_under_way_ends_erpc_by_it_at_once() {
        // By the signal, not with status 130: a shell loop stops only on a
        // child that died of Ctrl-C.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let child = Child::spawn(&Setup::new("idle", dir.path()));
        child.expect("ready");
        let asked = Instant::now();
        child.signal("INT");
        assert_eq!(child.ended().signal(), Some(SIGINT));
        assert!(asked.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn ctrl_c_during_a_rotation_ends_erpc_once_it_is_saved() {
        let dir = holding_old();
        let child = Child::spawn(&Setup::new("rotating", dir.path()));
        child.expect("refreshing");
        child.signal("INT");
        assert_eq!(child.ended().signal(), Some(SIGINT));
        assert_eq!(stored(dir.path()), "ref.NEW.s");
        assert!(!parked_at(dir.path()).exists());
    }

    #[test]
    fn sigterm_during_a_rotation_ends_erpc_once_it_is_saved() {
        let dir = holding_old();
        let child = Child::spawn(&Setup::new("rotating", dir.path()));
        child.expect("refreshing");
        child.signal("TERM");
        assert_eq!(child.ended().signal(), Some(SIGTERM));
        assert_eq!(stored(dir.path()), "ref.NEW.s");
    }

    #[test]
    fn the_terminal_closing_during_a_rotation_ends_erpc_once_it_is_saved() {
        // A closed terminal sends SIGHUP, and every write to it fails. A
        // failed write used to panic, and a release build aborts on a panic.
        let dir = holding_old();
        let child = Child::spawn(&Setup {
            stderr_gone: true,
            ..Setup::new("terminal gone", dir.path())
        });
        child.expect("refreshing");
        child.signal("HUP");
        assert_eq!(child.ended().signal(), Some(SIGHUP));
        assert_eq!(stored(dir.path()), "ref.NEW.s");
    }

    #[test]
    fn a_second_ctrl_c_parks_a_save_that_does_not_come_back() {
        let dir = holding_old();
        let child = Child::spawn(&Setup {
            grace: Duration::from_secs(60),
            ..Setup::new("hanging", dir.path())
        });
        child.expect("saving");
        child.signal("INT");
        child.expect("saving the refreshed session before leaving");
        child.signal("INT");
        assert_eq!(child.ended().signal(), Some(SIGINT));
        parked_over_old(dir.path());
    }

    #[test]
    fn a_save_that_does_not_come_back_is_parked_after_the_grace() {
        let dir = holding_old();
        let child = Child::spawn(&Setup {
            grace: Duration::from_millis(300),
            ..Setup::new("hanging", dir.path())
        });
        child.expect("saving");
        child.signal("INT");
        assert_eq!(child.ended().signal(), Some(SIGINT));
        parked_over_old(dir.path());
    }

    #[test]
    fn a_refresh_still_out_is_waited_for_and_then_parked() {
        // Ctrl-C while the issuer has not answered: the grace runs out with
        // nothing to park yet. Leaving then would spend the old token with
        // the new one still on its way.
        let dir = holding_old();
        let child = Child::spawn(&Setup {
            grace: Duration::from_millis(100),
            issuer: Duration::from_millis(1_000),
            ..Setup::new("hanging", dir.path())
        });
        child.expect("refreshing");
        let asked = Instant::now();
        child.signal("INT");
        assert_eq!(child.ended().signal(), Some(SIGINT));
        assert!(
            asked.elapsed() >= Duration::from_millis(700),
            "{:?}",
            asked.elapsed()
        );
        parked_over_old(dir.path());
    }

    #[test]
    fn ctrl_c_while_erpc_waits_after_the_command_parks_the_session() {
        let dir = holding_old();
        let child = Child::spawn(&Setup {
            grace: Duration::from_secs(60),
            ..Setup::new("after the command", dir.path())
        });
        child.expect("erpc: saving the refreshed session before leaving");
        child.signal("INT");
        child.expect("ask again to leave now");
        child.signal("INT");
        assert_eq!(child.ended().signal(), Some(SIGINT));
        parked_over_old(dir.path());
    }

    #[test]
    fn a_panic_parks_what_the_store_has_not_taken() {
        // A release build aborts on a panic, and nothing after it runs.
        let dir = holding_old();
        let mut child = Child::spawn(&Setup::new("panic", dir.path()));
        child.expect("panicked");
        assert!(
            child.running_after(Duration::ZERO),
            "the rotation is still saving"
        );
        child.signal("KILL");
        assert_eq!(child.ended().signal(), Some(SIGKILL));
        parked_over_old(dir.path());
    }

    #[test]
    fn a_panic_parks_first_even_behind_a_hook_that_panics() {
        let dir = holding_old();
        let child = Child::spawn(&Setup::new("panic behind a hook", dir.path()));
        child.expect("saving");
        assert_eq!(child.ended().signal(), Some(SIGABRT));
        parked_over_old(dir.path());
    }

    fn signer_dirs(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .expect("the directory")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("signers-"))
            .count()
    }

    #[test]
    fn a_signal_wipes_the_signer_files_a_command_has_on_disk() {
        for (name, signal) in [("INT", SIGINT), ("TERM", SIGTERM), ("HUP", SIGHUP)] {
            let dir = tempfile::tempdir().expect("a temporary directory");
            let child = Child::spawn(&Setup::new("signer", dir.path()));
            child.expect("ready");
            assert_eq!(
                signer_dirs(dir.path()),
                1,
                "the file is there while it runs"
            );
            child.signal(name);
            assert_eq!(child.ended().signal(), Some(signal));
            assert_eq!(signer_dirs(dir.path()), 0, "wiped on {name}");
        }
    }

    #[test]
    fn a_panic_wipes_the_signer_files_before_it_aborts() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let child = Child::spawn(&Setup::new("signer panic", dir.path()));
        child.expect("panicked");
        assert_eq!(signer_dirs(dir.path()), 0);
        child.signal("KILL");
        let _ = child.ended();
    }

    /// A child's `command` cases: a command the assistant runs, as
    /// `run_command` starts one. It says which process it is, then runs on;
    /// with `panics`, a thread panics once it has started.
    async fn commanding(dir: &Path, panics: bool) {
        use erpc_ai::commands::Shell as _;
        if panics {
            super::park_on_panic(true);
        }
        let said = dir.join("pid");
        let script = format!("echo $$ > '{}'; exec sleep 30", said.display());
        let command = ["sh".to_owned(), "-c".to_owned(), script];
        let shell = erpc_ai::commands::LocalShell;
        let running = shell.run(&command, Duration::from_secs(60));
        tokio::pin!(running);
        let started = async {
            while !said.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if panics {
                let _ = std::thread::spawn(|| panic!("a bug")).join();
                println!("panicked");
            } else {
                println!("ready");
            }
            std::future::pending::<()>().await;
        };
        tokio::select! {
            _ = &mut running => {}
            () = started => {}
        }
    }

    /// Whether process `id` is still there.
    fn alive(id: &str) -> bool {
        Command::new("kill")
            .args(["-0", id])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    /// The process a `command` case's command said it is.
    fn command_of(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("pid"))
            .expect("the command's id")
            .trim()
            .to_owned()
    }

    /// Waits for process `id` to be gone, for a few seconds.
    fn gone(id: &str) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if !alive(id) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    #[test]
    fn a_signal_stops_the_command_the_assistant_is_running() {
        for (name, signal) in [("INT", SIGINT), ("TERM", SIGTERM), ("HUP", SIGHUP)] {
            let dir = tempfile::tempdir().expect("a temporary directory");
            let child = Child::spawn(&Setup::new("command", dir.path()));
            child.expect("ready");
            let command = command_of(dir.path());
            assert!(alive(&command), "the command runs while erpc does");
            child.signal(name);
            assert_eq!(child.ended().signal(), Some(signal));
            assert!(gone(&command), "stopped with erpc on {name}");
        }
    }

    #[test]
    fn a_panic_stops_the_command_before_it_aborts() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let child = Child::spawn(&Setup::new("command panic", dir.path()));
        child.expect("panicked");
        assert!(gone(&command_of(dir.path())));
        child.signal("KILL");
        let _ = child.ended();
    }

    /// A child's `echo` cases: a passphrase prompt that holds the echo of
    /// the terminal on standard input off, as the keystore's does while it
    /// asks. The hold is never dropped, as on a way out that runs no
    /// destructors. With `panics`, a thread panics once the test has seen
    /// the echo off and says so (the file `go`).
    async fn echoing(dir: &Path, panics: bool) {
        if panics {
            super::park_on_panic(true);
        }
        core::mem::forget(crate::echo::off());
        println!("ready");
        if panics {
            while !dir.join("go").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let _ = std::thread::spawn(|| panic!("a bug")).join();
            println!("panicked");
        }
    }

    /// A child with a pseudoterminal of the test's own on standard input,
    /// running `case`, once it holds the terminal's echo off; and the
    /// terminal, both ends, the second being the one the child reads.
    #[cfg(target_os = "linux")]
    fn holding_the_echo_off(
        case: &str,
        dir: &Path,
    ) -> (Child, std::fs::File, std::os::fd::OwnedFd) {
        use crate::echo::tests::{echoes, terminal};
        let (typed, read) = terminal();
        assert!(echoes(&read), "a new terminal shows what is typed");
        let child = Child::spawn(&Setup {
            terminal: Some(&read),
            ..Setup::new(case, dir)
        });
        child.expect("ready");
        assert!(!echoes(&read), "held off while the prompt has it");
        (child, typed, read)
    }

    /// The keystore's prompt holds the echo off across its questions, and
    /// a signal's way out drops no guard: `leave` puts the echo back, or
    /// the shell erpc was started from shows nothing that is typed after.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_signal_gives_back_the_echo_a_prompt_holds_off() {
        use crate::echo::tests::echoes;
        for (name, signal) in [("INT", SIGINT), ("TERM", SIGTERM), ("HUP", SIGHUP)] {
            let dir = tempfile::tempdir().expect("a temporary directory");
            let (child, _typed, read) = holding_the_echo_off("echo", dir.path());
            child.signal(name);
            assert_eq!(child.ended().signal(), Some(signal));
            assert!(echoes(&read), "the echo is back on {name}");
        }
    }

    /// A panic that aborts drops no guard either: the hook puts the echo
    /// back before the process ends.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_panic_gives_back_the_echo_before_it_aborts() {
        use crate::echo::tests::echoes;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (child, _typed, read) = holding_the_echo_off("echo panic", dir.path());
        std::fs::write(dir.path().join("go"), b"").expect("the go-ahead");
        child.expect("panicked");
        assert!(echoes(&read), "the hook put the echo back");
        child.signal("KILL");
        let _ = child.ended();
    }

    #[test]
    fn signer_files_left_by_a_killed_erpc_are_swept() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let child = Child::spawn(&Setup::new("signer", dir.path()));
        child.expect("ready");
        assert!(
            erpc_chain_solana::cli::leftovers(dir.path()).is_empty(),
            "a running erpc's files are its own"
        );
        // SIGKILL runs nothing at all.
        child.signal("KILL");
        let _ = child.ended();
        assert_eq!(signer_dirs(dir.path()), 1);
        assert_eq!(erpc_chain_solana::cli::sweep(dir.path()).len(), 1);
        assert_eq!(signer_dirs(dir.path()), 0);
    }

    /// What left an hourly line charged: Ctrl-C while a request was under
    /// way and nothing waited on it. Under a hold it does not end erpc, and
    /// it is still known once the request is done.
    #[test]
    fn ctrl_c_under_a_hold_is_kept_while_nothing_waits_for_it() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut child = Child::spawn(&Setup::new("hold", dir.path()));
        child.expect("ready");
        child.signal("INT");
        child.expect("request done, ctrl-c came: true");
        child.expect("lines ended");
        assert!(child.running_after(Duration::from_millis(300)));
        // The hold keeps one: the next ends erpc, by the signal.
        child.signal("INT");
        assert_eq!(child.ended().signal(), Some(SIGINT));
    }

    #[test]
    fn ctrl_c_during_a_turn_stops_the_turn_and_not_erpc() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut child = Child::spawn(&Setup::new("turn", dir.path()));
        child.expect("ready");
        child.signal("INT");
        child.expect("turn stopped");
        assert!(child.running_after(Duration::from_millis(300)));
        child.signal("KILL");
        assert_eq!(child.ended().signal(), Some(SIGKILL));
    }
}
