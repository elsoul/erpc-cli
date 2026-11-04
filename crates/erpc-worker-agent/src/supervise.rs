// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-worker-agent supervise`: the worker's unit process.
//!
//! It holds the trading key and the secrets in memory, and nowhere else:
//! the process is marked undumpable and its pages locked before anything
//! secret arrives, and every buffer that held a secret is wiped when it is
//! dropped. It starts the app from `current` with a cleared environment
//! (the release's settings, the secrets, nothing of its own) and the key
//! on the app's standard input, a pipe it writes the 64 bytes to and
//! closes. When the app ends it is started again after a pause that grows
//! with each quick failure. The app's health is probed the way `erpc
//! worker run --check` probes it.
//!
//! The socket takes one JSON request per connection from root only
//! ([`erpc_worker::server::Request`]) and answers with the worker's
//! status. Nothing it answers carries a secret.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use erpc_worker::server::{self, Launch, Reply, Request, Status};
use zeroize::Zeroizing;

/// The biggest request read: a key and a few secrets fit many times over.
const MAX_REQUEST: u64 = 1024 * 1024;
/// The pause before the first restart, and the longest one.
const FIRST_PAUSE: Duration = Duration::from_secs(1);
const LONGEST_PAUSE: Duration = Duration::from_secs(60);
/// How long the app must stay up for the pause to start over.
const STEADY: Duration = Duration::from_secs(300);
/// How long the app has to stop before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(10);
/// Without a health URL, how long a start must stay up to be healthy.
const SETTLE: Duration = Duration::from_secs(5);

type Asked = (Request, Sender<Reply>);

fn say(line: &str) {
    eprintln!("erpc-worker-agent: {line}");
}

/// Makes this process undumpable and locks its memory, before any secret
/// is in it. A failure to lock is said and survived: the unit forbids
/// swap as well.
fn harden() {
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        say(&format!("could not make the process undumpable: {e}"));
    }
    if let Err(e) =
        rustix::mm::mlockall(rustix::mm::MlockAllFlags::CURRENT | rustix::mm::MlockAllFlags::FUTURE)
    {
        say(&format!(
            "could not lock memory ({e}); the unit's MemorySwapMax=0 keeps it from swap"
        ));
    }
}

/// An app that is running.
struct Running {
    child: Child,
    release: String,
    started: Instant,
    health_url: Option<String>,
    healthy: bool,
    last_probe: Option<Instant>,
}

/// The worker.
struct Supervisor {
    dir: PathBuf,
    state_dir: PathBuf,
    secrets: BTreeMap<String, Zeroizing<String>>,
    key: Option<Zeroizing<[u8; 64]>>,
    wanted: bool,
    running: Option<Running>,
    restarts: u32,
    last_exit: Option<String>,
    next_start: Option<Instant>,
    pause: Duration,
    reason: Option<String>,
}

/// Runs the worker until SIGTERM or SIGINT.
pub(crate) fn run(dir: &Path, socket: &Path, state_dir: &Path) -> Result<(), String> {
    harden();
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, Arc::clone(&stop))
            .map_err(|e| format!("could not take signal {signal}: {e}"))?;
    }
    std::fs::create_dir_all(state_dir)
        .map_err(|e| format!("could not make {}: {e}", state_dir.display()))?;
    let listener = listen(socket)?;
    let (tx, rx) = channel::<Asked>();
    std::thread::spawn(move || accept(&listener, &tx));

    let mut worker = Supervisor {
        dir: dir.to_owned(),
        state_dir: state_dir.to_owned(),
        secrets: BTreeMap::new(),
        key: None,
        wanted: std::fs::read_to_string(state_dir.join("wanted")).is_ok_and(|w| w.trim() == "1"),
        running: None,
        restarts: 0,
        last_exit: None,
        next_start: None,
        pause: FIRST_PAUSE,
        reason: None,
    };
    say(&format!(
        "supervising {} (locked until erpc hands the key over; wanted: {})",
        dir.display(),
        worker.wanted
    ));
    while !stop.load(Ordering::Relaxed) {
        worker.serve(&rx);
        worker.tick();
    }
    say("stopping");
    worker.stop_app();
    let _ = std::fs::remove_file(socket);
    Ok(())
}

fn listen(socket: &Path) -> Result<UnixListener, String> {
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not make {}: {e}", parent.display()))?;
    }
    // Left by an agent that was killed; nothing listens on it.
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)
        .map_err(|e| format!("could not listen on {}: {e}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("could not restrict {}: {e}", socket.display()))?;
    Ok(listener)
}

/// Takes connections, one request each, and hands them to the supervisor.
fn accept(listener: &UnixListener, tx: &Sender<Asked>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = answer(stream, &tx);
        });
    }
}

fn answer(mut stream: UnixStream, tx: &Sender<Asked>) -> std::io::Result<()> {
    let reply = match request(&stream) {
        Ok(request) => {
            let (reply_tx, reply_rx) = channel();
            if tx.send((request, reply_tx)).is_err() {
                refused("the agent is stopping")
            } else {
                reply_rx
                    .recv_timeout(Duration::from_secs(60))
                    .unwrap_or_else(|_| refused("the agent did not answer"))
            }
        }
        Err(why) => refused(&why),
    };
    let mut line = serde_json::to_vec(&reply).unwrap_or_default();
    line.push(b'\n');
    stream.write_all(&line)
}

fn refused(why: &str) -> Reply {
    Reply {
        ok: false,
        error: Some(why.to_owned()),
        status: None,
    }
}

/// One request line, from root only. The bytes are wiped once parsed: an
/// unlock carries the key.
fn request(stream: &UnixStream) -> Result<Request, String> {
    let peer = rustix::net::sockopt::socket_peercred(stream)
        .map_err(|e| format!("could not tell who is asking: {e}"))?;
    if !peer.uid.is_root() {
        return Err("only root may ask the agent".to_owned());
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    #[allow(clippy::cast_possible_truncation, reason = "1 MiB")]
    let line = crate::wiped::read(&mut &*stream, MAX_REQUEST as usize, true)
        .map_err(|e| format!("could not read the request: {e}"))?
        .ok_or("the request is too long")?;
    serde_json::from_slice(&line).map_err(|e| format!("not a request: {e}"))
}

impl Supervisor {
    /// Answers what is asked, waiting a moment for it.
    fn serve(&mut self, rx: &Receiver<Asked>) {
        let Ok((request, reply)) = rx.recv_timeout(Duration::from_millis(200)) else {
            return;
        };
        let answer = match self.handle(request) {
            Ok(()) => Reply {
                ok: true,
                error: None,
                status: Some(self.status()),
            },
            Err(why) => Reply {
                ok: false,
                error: Some(why),
                status: Some(self.status()),
            },
        };
        let _ = reply.send(answer);
    }

    fn handle(&mut self, request: Request) -> Result<(), String> {
        match request {
            Request::Status {} => Ok(()),
            Request::Unlock { secrets, key } => {
                let key = match key {
                    Some(bytes) => {
                        let mut held = Zeroizing::new([0_u8; 64]);
                        if bytes.len() != held.len() {
                            return Err(format!("a key is 64 bytes, not {}", bytes.len()));
                        }
                        held.copy_from_slice(&bytes);
                        Some(held)
                    }
                    None => None,
                };
                self.secrets = secrets;
                self.key = key;
                self.reason = None;
                say(&format!(
                    "unlocked: key {}, {} secret(s)",
                    if self.key.is_some() {
                        "held"
                    } else {
                        "not given"
                    },
                    self.secrets.len()
                ));
                if self.wanted && self.running.is_none() {
                    self.next_start = None;
                }
                Ok(())
            }
            Request::Lock {} => {
                // A lock is a stop that also forgets. Without `want(false)`
                // the next tick started an app that needs no key or secret
                // straight back up, and so did the agent after a restart,
                // since the wanted state is persisted.
                self.want(false);
                self.stop_app();
                self.secrets.clear();
                self.key = None;
                say("locked: the key and the secrets are forgotten");
                Ok(())
            }
            Request::Start {} => {
                self.want(true);
                if self.running.is_none() {
                    self.pause = FIRST_PAUSE;
                    self.next_start = None;
                    self.start_app();
                }
                self.reason.clone().map_or(Ok(()), Err)
            }
            Request::Stop {} => {
                self.want(false);
                self.stop_app();
                Ok(())
            }
            Request::Restart {} => {
                self.want(true);
                self.stop_app();
                self.pause = FIRST_PAUSE;
                self.next_start = None;
                self.start_app();
                self.reason.clone().map_or(Ok(()), Err)
            }
        }
    }

    fn want(&mut self, wanted: bool) {
        self.wanted = wanted;
        let _ = std::fs::write(
            self.state_dir.join("wanted"),
            if wanted { "1\n" } else { "0\n" },
        );
    }

    /// Restarts an app that ended, and probes the one running.
    fn tick(&mut self) {
        if let Some(running) = &mut self.running {
            match running.child.try_wait() {
                Ok(Some(status)) => {
                    let up = running.started.elapsed();
                    say(&format!("the app ended after {}s: {status}", up.as_secs()));
                    self.last_exit = Some(status.to_string());
                    self.running = None;
                    self.pause = if up >= STEADY {
                        FIRST_PAUSE
                    } else {
                        (self.pause * 2).min(LONGEST_PAUSE)
                    };
                    if self.wanted {
                        self.next_start = Some(Instant::now() + self.pause);
                    }
                }
                Ok(None) => probe(running),
                Err(e) => say(&format!("could not ask after the app: {e}")),
            }
        }
        if self.running.is_none()
            && self.wanted
            && self.next_start.is_none_or(|at| Instant::now() >= at)
        {
            self.next_start = None;
            if self.start_app() {
                self.restarts += u32::from(self.last_exit.is_some());
            } else {
                // Retried when something changes: an unlock, a start, a
                // new release.
                self.next_start = Some(Instant::now() + LONGEST_PAUSE);
            }
        }
    }

    /// The release `current` points at, and its launch file.
    fn current(&self) -> Result<(String, PathBuf, Launch), String> {
        let link = self.dir.join("current");
        let release_dir = std::fs::canonicalize(&link)
            .map_err(|_| "there is no current release yet".to_owned())?;
        let release = release_dir
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| erpc_worker::release::is_id(n))
            .ok_or_else(|| format!("{} is not a release", release_dir.display()))?
            .to_owned();
        let text = std::fs::read_to_string(release_dir.join(server::LAUNCH_FILE))
            .map_err(|e| format!("could not read {}: {e}", server::LAUNCH_FILE))?;
        Ok((release, release_dir, Launch::parse(&text)?))
    }

    /// Why the app cannot start now, when it cannot.
    fn missing(&self, launch: &Launch) -> Option<String> {
        if launch.pubkey.is_some() && self.key.is_none() {
            return Some("locked: the trading key has not been handed over".to_owned());
        }
        let absent: Vec<&str> = launch
            .secrets
            .iter()
            .filter(|n| !self.secrets.contains_key(*n))
            .map(String::as_str)
            .collect();
        (!absent.is_empty()).then(|| format!("locked: no value for {}", absent.join(", ")))
    }

    /// Starts the app from `current`. Says why not, in `reason`, when it
    /// cannot.
    fn start_app(&mut self) -> bool {
        let (release, release_dir, launch) = match self.current() {
            Ok(found) => found,
            Err(why) => {
                self.reason = Some(why);
                return false;
            }
        };
        if let Some(why) = self.missing(&launch) {
            self.reason = Some(why);
            return false;
        }
        let mut command = Command::new(release_dir.join(&launch.bin));
        command
            .args(&launch.args)
            .current_dir(&release_dir)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &self.state_dir)
            .env("LANG", "C.UTF-8")
            .env("ERPC_WORKER_STATE_DIR", &self.state_dir)
            .envs(&launch.vars)
            .envs(self.secrets.iter().map(|(k, v)| (k, v.as_str())))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if let Some(pubkey) = &launch.pubkey {
            command
                .env("ERPC_WORKER_KEY_FD", "0")
                .env("ERPC_WORKER_PUBKEY", pubkey)
                .stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                self.reason = Some(format!("could not start {}: {e}", launch.bin));
                return false;
            }
        };
        if launch.pubkey.is_some() {
            let handed = match (child.stdin.take(), &self.key) {
                (Some(mut pipe), Some(key)) => pipe.write_all(&key[..]).is_ok(),
                _ => false,
            };
            if !handed {
                let _ = child.kill();
                let _ = child.wait();
                self.reason = Some("could not hand the key to the app".to_owned());
                return false;
            }
        }
        say(&format!("started {release} (pid {})", child.id()));
        self.reason = None;
        self.running = Some(Running {
            child,
            release,
            started: Instant::now(),
            health_url: launch.health.http,
            healthy: false,
            last_probe: None,
        });
        true
    }

    /// Asks the app to stop, and kills it when it does not.
    fn stop_app(&mut self) {
        let Some(mut running) = self.running.take() else {
            return;
        };
        let pid = rustix::process::Pid::from_raw(i32::try_from(running.child.id()).unwrap_or(0));
        if let Some(pid) = pid {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        }
        let asked = Instant::now();
        while asked.elapsed() < STOP_GRACE {
            if let Ok(Some(_)) = running.child.try_wait() {
                say(&format!("stopped {}", running.release));
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = running.child.kill();
        let _ = running.child.wait();
        say(&format!(
            "killed {}: it did not stop in {}s",
            running.release,
            STOP_GRACE.as_secs()
        ));
    }

    fn status(&self) -> Status {
        let locked = self
            .current()
            .ok()
            .and_then(|(_, _, launch)| self.missing(&launch));
        let state = match (&self.running, &locked) {
            (Some(r), _) if r.healthy => "running",
            (Some(_), _) => "starting",
            (None, Some(_)) => "locked",
            (None, None) if self.wanted && self.next_start.is_some() => "waiting",
            (None, None) => "stopped",
        };
        Status {
            state: state.to_owned(),
            healthy: self.running.as_ref().is_some_and(|r| r.healthy),
            wanted: self.wanted,
            key_held: self.key.is_some(),
            secrets_held: self.secrets.keys().cloned().collect(),
            release: self.running.as_ref().map(|r| r.release.clone()),
            pid: self.running.as_ref().map(|r| r.child.id()),
            up_secs: self.running.as_ref().map(|r| r.started.elapsed().as_secs()),
            restarts: self.restarts,
            last_exit: self.last_exit.clone(),
            reason: locked.or_else(|| self.reason.clone()),
        }
    }
}

/// Probes a running app: every second until it is healthy, then every five.
fn probe(running: &mut Running) {
    let every = if running.healthy {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(1)
    };
    if running.last_probe.is_some_and(|at| at.elapsed() < every) {
        return;
    }
    running.last_probe = Some(Instant::now());
    let healthy = match &running.health_url {
        Some(url) => server::probe(url),
        None => running.started.elapsed() >= SETTLE,
    };
    if healthy != running.healthy {
        say(&format!(
            "{} is {}",
            running.release,
            if healthy { "healthy" } else { "not healthy" }
        ));
    }
    running.healthy = healthy;
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;

    #[test]
    fn only_root_is_answered() {
        let (mut ours, theirs) = UnixStream::pair().expect("pair");
        writeln!(ours, r#"{{"op":"status"}}"#).expect("write");
        let asked = super::request(&theirs);
        // The peer is this test process: not root in CI, root when run as
        // root (in a container, say).
        if rustix::process::geteuid().is_root() {
            assert!(asked.is_ok(), "{asked:?}");
        } else {
            let refused = asked.expect_err("refused");
            assert!(refused.contains("only root"), "{refused}");
        }
    }
}
