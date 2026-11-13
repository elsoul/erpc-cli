// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A worker's WAF, as `ctl` sets it up (run as root).
//!
//! The WAF is `erpc-worker-agent waf`, in a unit of its own
//! ([`erpc_worker::server::waf_unit`]) that reads one file,
//! `/etc/erpc/worker-waf/<id>.json`. `waf-apply` is handed that file's
//! content: it writes the file and the unit when either differs from what
//! is there, has systemd run the proxy, and waits for it to listen. A
//! proxy that does not come up is said, with why, and what was there
//! before is put back. `waf-remove` takes all of it away, and `status`
//! and `firewall-show` say how it is.
//!
//! The proxy is the agent's own code, so the rules in force are the
//! config as the agent that runs as the proxy reads it. `status` says
//! whether that is the agent installed ([`Binary`]), and `waf-apply`
//! restarts a proxy that is not, or that cannot be told to be, whatever
//! the files say: an agent installed since the proxy started may read the
//! same file otherwise, and has the proxy's fixes.
//!
//! And the proxy reads its config once, when it starts, and runs under
//! the unit systemd had read then, so what is in force is the two files
//! as they were then. `status` says whether the proxy was started after
//! both last changed ([`Started`]), by times the proxy has no hand in:
//! when systemd started the unit's main process, and when the config and
//! the unit, each in a directory of root's, last changed. `waf-apply`
//! restarts a proxy that was not, or that cannot be told to have been,
//! though the files are already what it would write: an apply that ended
//! between writing one of them and restarting the proxy leaves just that.
//! And systemd is told to read the unit files again before it is asked to
//! start or restart the proxy, whichever apply wrote the unit.
//!
//! The two times do not tell everything such an apply can leave. systemd
//! starts a proxy again by itself when it fails, and then under the unit
//! it had read, not the one on disk: a start like that is dated after
//! both files. And nothing systemd says tells it apart for long: it reads
//! its units again at every `systemctl enable`, which each deploy runs for
//! the agent's unit before it comes to the WAF, and from then on the unit
//! it has is the one on disk, with the proxy still running under the one
//! from before. So an apply leaves a note beside the config before it
//! writes either file ([`Host::begin`]), and takes it away once systemd,
//! having read the unit files again, has been asked to start or restart
//! the proxy ([`Host::settled`]). While the note is there the proxy is not
//! taken to have been started from the files as they are, whatever its
//! start is dated, and the next apply restarts it.
//!
//! Where the files are, what systemd is asked and where a process's
//! binary is looked up is a [`Host`], so that the tests run the same
//! steps against a directory and a systemd that answers as they say.

use std::io::Read as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use erpc_worker::server;
use erpc_worker::waf::{MAX_STATS_BYTES, WafConfig, WafStats};
use serde_json::{Value, json};

use crate::backup::put;
use crate::waf::printable;

/// The largest config read from standard input: the proxy reads no larger.
const MAX_CONFIG: u64 = 1024 * 1024;
/// How many lines of the proxy's journal are said when it does not come up.
const JOURNAL_LINES: &str = "5";
/// How much of one of those lines is said, and of why a config or a stats
/// file does not read, in bytes.
const SAID: usize = 300;
/// How far a file's time may be behind the clock, in microseconds: the
/// kernel dates a change to a file by its last tick, and ticks are 10 ms
/// apart at the slowest a server's kernel is built with. systemd dates a
/// start by the clock itself. So a start is known to have come after a
/// change to a file only when it is dated a tick or more after it.
const TICK_MICROS: u64 = 10_000;

/// What systemd is asked about a unit.
pub(crate) trait Systemd {
    /// Runs `systemctl` with `args`.
    fn run(&self, args: &[&str]) -> Result<(), String>;
    /// What `systemctl is-active` says of `unit`: `active`, `activating`
    /// (starting, or waiting to be started again), `inactive`, `failed`.
    fn state(&self, unit: &str) -> String;
    /// The unit's main process; 0 when it has none.
    fn pid(&self, unit: &str) -> u32;
    /// When the unit's main process was started, as `systemctl show`
    /// prints it to the microsecond in UTC
    /// (`Thu 2026-11-12 04:40:01.123456 UTC`); nothing, or whatever else
    /// it printed, when it does not say so.
    fn started(&self, unit: &str) -> String;
    /// The last lines of the unit's journal, oldest first.
    fn journal(&self, unit: &str) -> Vec<String>;
}

/// The server's systemd.
struct Real;

/// What `program` printed with `args`, whatever its exit status: `systemctl
/// is-active` exits non-zero for every state but `active`, and says the
/// state all the same.
fn printed(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_default()
}

impl Systemd for Real {
    fn run(&self, args: &[&str]) -> Result<(), String> {
        crate::ctl::systemctl(args).map(|_| ())
    }

    fn state(&self, unit: &str) -> String {
        let said = printed("systemctl", &["is-active", unit]);
        match said.lines().next().map(str::trim) {
            Some(state) if !state.is_empty() => state.to_owned(),
            _ => "unknown".to_owned(),
        }
    }

    fn pid(&self, unit: &str) -> u32 {
        printed(
            "systemctl",
            &["show", unit, "--property", "MainPID", "--value"],
        )
        .parse()
        .unwrap_or(0)
    }

    fn started(&self, unit: &str) -> String {
        // A systemd that does not know `--timestamp` does not print the
        // time in this form: whatever it prints instead, or nothing, is
        // read as not saying.
        let args = [
            "show",
            unit,
            "--property",
            "ExecMainStartTimestamp",
            "--value",
            "--timestamp=us+utc",
        ];
        printed("systemctl", &args)
    }

    fn journal(&self, unit: &str) -> Vec<String> {
        let args = ["--no-pager", "-o", "cat", "-n", JOURNAL_LINES, "-u", unit];
        printed("journalctl", &args)
            .lines()
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty())
            .collect()
    }
}

/// A server, as far as a WAF is concerned.
pub(crate) struct Host<'a> {
    /// Its systemd.
    pub(crate) systemd: &'a dyn Systemd,
    /// Where unit files are.
    pub(crate) units: PathBuf,
    /// Where the WAF configs are ([`server::WAF_DIR`]).
    pub(crate) configs: PathBuf,
    /// Where the units' runtime directories are.
    pub(crate) runtime: PathBuf,
    /// Where the processes are (`/proc`): `<pid>/exe` is the file a
    /// process runs.
    pub(crate) proc: PathBuf,
    /// The agent installed, as a file ([`crate::ctl::INSTALLED`]).
    pub(crate) agent: PathBuf,
    /// How long a proxy has to come up.
    pub(crate) patience: Duration,
    /// How long between two looks at it.
    pub(crate) pause: Duration,
}

impl Host<'static> {
    /// The server this runs on.
    pub(crate) fn server() -> Self {
        Self {
            systemd: &Real,
            units: PathBuf::from("/etc/systemd/system"),
            configs: PathBuf::from(server::WAF_DIR),
            runtime: PathBuf::from("/run"),
            proc: PathBuf::from("/proc"),
            agent: PathBuf::from(crate::ctl::INSTALLED),
            patience: Duration::from_secs(10),
            pause: Duration::from_millis(300),
        }
    }
}

/// Which agent binary a proxy runs, against the one installed. The proxy
/// is a process of the binary that was installed when it started; an agent
/// installed since is another file, and its proxy code reaches the proxy
/// only with a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Binary {
    /// The agent installed: the rules in force are the config as this
    /// agent reads it.
    Installed,
    /// Another file: an agent from before the one installed.
    Other,
    /// It could not be told: the unit has no main process, or its binary
    /// could not be looked at.
    Unknown,
}

impl Binary {
    /// As `status` names it.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether a proxy was started after its files last changed: its config
/// and its unit, the later of the two. The proxy reads its config once,
/// when it starts, and runs under the unit systemd had read then: only
/// one started after the last change to either runs both as they are.
///
/// An apply that wrote one of the files and ended before it restarted the
/// proxy is told by the note it left ([`Host::unfinished`]), not by the
/// two times. What is left to the times alone is a file changed by
/// anything else: there, a clock set back between the proxy's start and
/// the change, or a restart by systemd itself before it had read a unit
/// changed that way, dates the start after a file the proxy does not run.
///
/// The names `status` gives them say "config", from when the config was
/// the one file looked at; they mean the config or the unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Started {
    /// After both files last changed, by a tick or more
    /// ([`TICK_MICROS`]), with no apply left unfinished: it was started
    /// with the files as they are.
    AfterConfig,
    /// Before one of the files last changed, or less than a tick after:
    /// it was started with a file from before, or may have been. Or an
    /// apply that wrote one of them ended before it restarted the proxy,
    /// whenever the proxy was started since.
    BeforeConfig,
    /// It could not be told: systemd did not say when the proxy was
    /// started, or the time of one of the files could not be read.
    Unknown,
}

impl Started {
    /// As `status` names it.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AfterConfig => "after_config",
            Self::BeforeConfig => "before_config",
            Self::Unknown => "unknown",
        }
    }
}

/// The microseconds since 1970 that `text` names, when it is a time as
/// `systemctl show --timestamp=us+utc` prints one: the day's name, the
/// date, the time to the microsecond, and `UTC`
/// (`Thu 2026-11-12 04:40:01.123456 UTC`). None for anything else: no
/// time (a unit never started), a time without microseconds or in another
/// zone, or other text.
fn micros(text: &str) -> Option<u64> {
    let number = |digits: &str, width: usize, most: u64| {
        (digits.len() == width && digits.bytes().all(|b| b.is_ascii_digit()))
            .then(|| digits.parse::<u64>().ok())
            .flatten()
            .filter(|n| *n <= most)
    };
    let mut words = text.split(' ');
    let (day, date, time, zone) = (words.next()?, words.next()?, words.next()?, words.next()?);
    let named = day.len() == 3 && day.bytes().all(|b| b.is_ascii_alphabetic());
    if !named || zone != "UTC" || words.next().is_some() {
        return None;
    }
    let mut date = date.split('-');
    let (year, month, day) = (date.next()?, date.next()?, date.next()?);
    let (clock, fraction) = time.split_once('.')?;
    let mut clock = clock.split(':');
    let (hour, minute, second) = (clock.next()?, clock.next()?, clock.next()?);
    if date.next().is_some() || clock.next().is_some() {
        return None;
    }
    let year = number(year, 4, 9999).filter(|y| *y >= 1970)?;
    let month = number(month, 2, 12).filter(|m| *m >= 1)?;
    let day = number(day, 2, 31).filter(|d| *d >= 1)?;
    // Howard Hinnant's days-from-civil, for the proleptic Gregorian
    // calendar: the year counted from March, in eras of 400 years.
    let year = year - u64::from(month <= 2);
    let (era, year_of_era) = (year / 400, year % 400);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = (era * 146_097 + day_of_era).checked_sub(719_468)?;
    let seconds =
        number(hour, 2, 23)? * 3600 + number(minute, 2, 59)? * 60 + number(second, 2, 59)?;
    Some((days * 86_400 + seconds) * 1_000_000 + number(fraction, 6, 999_999)?)
}

/// When the file at `path` last changed, content or anything else of it,
/// in microseconds since 1970 as the kernel dated it: none when it cannot
/// be looked at. Not the time it was last modified, which whoever writes a
/// file can set.
fn changed_at(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let seconds = u64::try_from(meta.ctime()).ok()?;
    let nanos = u64::try_from(meta.ctime_nsec()).ok()?;
    seconds.checked_mul(1_000_000)?.checked_add(nanos / 1000)
}

/// How long until the clock, at `now`, is a tick past a file's time,
/// `changed` (both in microseconds since 1970): what a start is to be
/// dated after the file by ([`TICK_MICROS`]). Never longer than a tick: a
/// file dated ahead of the clock is not waited out, and a proxy started
/// under it reads as started before it until the clock has passed it.
fn until_past(now: u64, changed: u64) -> Duration {
    let wait = changed.saturating_add(TICK_MICROS).saturating_sub(now);
    Duration::from_micros(wait.min(TICK_MICROS))
}

/// What `waf-apply` does with the proxy, once the files are as asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    /// It does not run: started.
    Start,
    /// It runs, and not with the files or the agent there are now, or
    /// that cannot be told: restarted, for this reason.
    Restart(&'static str),
    /// It runs the agent installed, and was started after its files last
    /// changed: left running.
    Leave,
}

/// What the note of an apply that has not finished says, for whoever
/// finds it on the server.
const UNFINISHED: &str = "erpc: a deploy was writing this worker's WAF config or its unit and has \
                          not restarted the WAF from them yet. The next deploy does, and removes \
                          this file.\n";

impl Host<'_> {
    /// Where the note of an apply of worker `id` that has not finished
    /// is: beside its config, in a directory of root's.
    fn unfinished_path(&self, id: &str) -> PathBuf {
        self.configs.join(format!("{id}.applying"))
    }

    /// Whether an apply set out to write one of worker `id`'s files and
    /// the proxy has not been started from them since: its note is there
    /// ([`Host::begin`]). Anything at that path counts.
    fn unfinished(&self, id: &str) -> bool {
        std::fs::symlink_metadata(self.unfinished_path(id)).is_ok()
    }

    /// Leaves the note that worker `id`'s files are being changed, before
    /// the first of them is written. An apply that ends from here on,
    /// before the proxy is restarted, is known by it.
    ///
    /// # Errors
    ///
    /// When the note cannot be written: nothing is written without it.
    fn begin(&self, id: &str) -> Result<(), String> {
        put(&self.unfinished_path(id), UNFINISHED, 0o644).map(|_| ())
    }

    /// Takes the note away: systemd has read the unit files again and has
    /// been asked to start or restart worker `id`'s proxy, so what runs
    /// now was started from the files as they are. A note that cannot be
    /// removed stays, and the next apply restarts the proxy once more.
    fn settled(&self, id: &str) {
        let _ = std::fs::remove_file(self.unfinished_path(id));
    }

    /// Writes worker `id`'s config and unit where they differ from what
    /// is there, the note first ([`Host::begin`]), and says of each
    /// whether it was written. Both are root's to write and anyone's to
    /// read: the proxy runs as a user of its own, and neither holds a
    /// secret.
    fn write(&self, id: &str, config: &str, unit: &str) -> Result<(bool, bool), String> {
        let (config_path, unit_path) = (self.config_path(id), self.unit_path(id));
        let differs =
            |path: &Path, text: &str| std::fs::read_to_string(path).ok().as_deref() != Some(text);
        if differs(&config_path, config) || differs(&unit_path, unit) {
            self.begin(id)?;
        }
        let config = put(&config_path, config, 0o644)?;
        Ok((config, put(&unit_path, unit, 0o644)?))
    }

    /// When worker `id`'s files last changed: the later of its config's
    /// time and its unit's ([`changed_at`]). None when either cannot be
    /// looked at.
    fn files_changed_at(&self, id: &str) -> Option<u64> {
        let config = changed_at(&self.config_path(id))?;
        let unit = changed_at(&self.unit_path(id))?;
        Some(config.max(unit))
    }

    /// Whether the main process of `unit` was started after worker `id`'s
    /// files last changed, its config and its unit, by systemd's time for
    /// the one and the kernel's for the others. Not while an apply that
    /// set out to write them is unfinished, whatever the times say: the
    /// proxy has not been restarted from them by an apply since
    /// ([`Host::unfinished`]).
    fn started(&self, unit: &str, id: &str) -> Started {
        if self.unfinished(id) {
            return Started::BeforeConfig;
        }
        let started = micros(&self.systemd.started(unit));
        match (started, self.files_changed_at(id)) {
            (Some(started), Some(changed)) if started >= changed + TICK_MICROS => {
                Started::AfterConfig
            }
            (Some(_), Some(_)) => Started::BeforeConfig,
            _ => Started::Unknown,
        }
    }

    /// Lets the clock get a tick past the time of worker `id`'s files,
    /// the later of the two, where it is not yet ([`until_past`]), so
    /// that a proxy started next is dated after both by enough to tell.
    fn past_the_files(&self, id: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|now| u64::try_from(now.as_micros()).ok());
        if let (Some(now), Some(changed)) = (now, self.files_changed_at(id)) {
            std::thread::sleep(until_past(now, changed));
        }
    }

    /// What `waf-apply` does with the proxy of `unit`, worker `id`'s:
    /// `changed` says whether this apply wrote one of its files.
    ///
    /// A proxy that runs is restarted for new files, and for a new agent:
    /// the one installed may read the same config otherwise than the one
    /// that runs as the proxy, and has its fixes. And for a config or a
    /// unit that changed after it started, though not by this apply: it
    /// runs the file from before. Where which agent runs, or when the
    /// proxy started, cannot be told, it is restarted too, so that what
    /// runs after this is the agent installed, with these files. A server
    /// where either can never be told has its proxy restarted by every
    /// deploy, which forgets its bans and its counts.
    fn next(&self, unit: &str, id: &str, changed: bool) -> Next {
        if self.state(unit) != "active" {
            return Next::Start;
        }
        if changed {
            return Next::Restart("changed");
        }
        match self.binary(unit) {
            Binary::Installed => match self.started(unit, id) {
                Started::AfterConfig => Next::Leave,
                Started::BeforeConfig => Next::Restart("older_than_config"),
                Started::Unknown => Next::Restart("unknown_start"),
            },
            Binary::Other => Next::Restart("other_binary"),
            Binary::Unknown => Next::Restart("unknown_binary"),
        }
    }

    /// Which agent binary the main process of `unit` runs
    /// ([`crate::ctl::runs_installed`]).
    fn binary(&self, unit: &str) -> Binary {
        let pid = self.systemd.pid(unit);
        match crate::ctl::runs_installed(&self.proc, pid, &self.agent) {
            Some(true) => Binary::Installed,
            Some(false) => Binary::Other,
            None => Binary::Unknown,
        }
    }

    /// What systemd calls `unit`, when it is one of systemd's words for a
    /// state (lower-case letters and hyphens); `unknown` otherwise. It is
    /// said to erpc, which shows it.
    fn state(&self, unit: &str) -> String {
        let state = self.systemd.state(unit);
        let word = !state.is_empty()
            && state.len() <= 32
            && state.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
        if word { state } else { "unknown".to_owned() }
    }

    fn unit_path(&self, id: &str) -> PathBuf {
        self.units.join(server::waf_unit_name(id))
    }

    fn config_path(&self, id: &str) -> PathBuf {
        self.configs.join(format!("{id}.json"))
    }

    /// Where worker `id`'s proxy writes its stats:
    /// [`server::waf_stats_path`], under this host's runtime directory.
    fn stats_path(&self, id: &str) -> PathBuf {
        let path = server::waf_stats_path(id);
        self.runtime
            .join(path.strip_prefix("/run/").unwrap_or(&path))
    }
}

/// The config `waf-apply` is handed on standard input.
pub(crate) fn config_on_stdin() -> Result<String, String> {
    let mut text = String::new();
    std::io::stdin()
        .lock()
        .take(MAX_CONFIG + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("could not read standard input: {e}"))?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIG {
        return Err("the WAF config on standard input is larger than one can be".to_owned());
    }
    Ok(text)
}

/// What a worker's WAF was before `waf-apply` changed it.
struct Before {
    config: Option<String>,
    unit: Option<String>,
}

/// `waf-apply`: worker `id`'s WAF made what `input` says, and listening.
///
/// `input` is a [`WafConfig`] as JSON. It is refused, before anything is
/// written, when it is not one the proxy takes ([`WafConfig::parse`], which
/// lets it forward to loopback only), or when the stats file it names is
/// not this worker's: a config for another worker, or one that would have
/// the proxy write somewhere else, is not installed under this id.
///
/// The config (root's, readable by all: the proxy runs as a user of its
/// own, and it holds no secret) and the unit are written when they differ
/// from what is there. The unit is enabled, and the proxy started when it
/// does not run; restarted when either file changed, when it does not
/// run the agent installed, or that cannot be told ([`Binary`]), and when
/// it was started before the config or the unit last changed, or that
/// cannot be told ([`Started`]); and left running otherwise
/// ([`Host::next`]). Then it is waited for ([`up`]).
///
/// Before the proxy is started or restarted, systemd is told to read the
/// unit files again (`daemon-reload`), whether or not this apply wrote
/// the unit: the unit on disk may be one an apply before this one wrote
/// and did not get to tell systemd of. A proxy left running is not
/// started from any unit, and no `daemon-reload` is asked for.
///
/// From before the first file is written until systemd has been asked to
/// start or restart the proxy, a note beside the config says that an
/// apply is under way ([`Host::begin`], [`Host::settled`]). An apply
/// that ends in between leaves it, and the proxy then counts as started
/// before its files last changed ([`Started::BeforeConfig`]) until an
/// apply restarts it: also when systemd started it again by itself
/// meanwhile, which dates its start after both files.
///
/// The answer is `ok`; `changed`, whether either file was written;
/// `proxy`, `started`, `restarted` or `running`; and, for a proxy that was
/// restarted, `restarted_because`: `changed`, `other_binary` (it ran an
/// agent from before the one installed), `unknown_binary` (which it ran
/// could not be told), `older_than_config` (it was started before its
/// config or its unit last changed, though this apply changed neither:
/// an apply before this one wrote the file and did not get to restart
/// the proxy) or `unknown_start` (when it was started could not be told).
/// When the proxy does not come up the answer says why, in systemd's word
/// for the unit and the last lines of its journal, and what was there
/// before is put back ([`put_back`]).
pub(crate) fn apply(host: &Host<'_>, id: &str, input: &str) -> Result<Value, String> {
    let config = WafConfig::parse(input.trim())?;
    let stats = server::waf_stats_path(id);
    if config.stats_path != stats {
        return Err(format!(
            "the WAF config names {} for its stats, and this worker's are {stats}",
            config.stats_path
        ));
    }
    let unit = server::waf_unit_name(id);
    let before = Before {
        config: std::fs::read_to_string(host.config_path(id)).ok(),
        unit: std::fs::read_to_string(host.unit_path(id)).ok(),
    };
    let applied = (|| -> Result<(bool, &'static str, Option<&'static str>), String> {
        std::fs::create_dir_all(&host.configs)
            .and_then(|()| {
                std::fs::set_permissions(&host.configs, std::fs::Permissions::from_mode(0o755))
            })
            .map_err(|e| format!("could not make {}: {e}", host.configs.display()))?;
        let text = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())? + "\n";
        // needrestart is told nothing about this unit: it holds no key,
        // only bans and counts a restart forgets, so a package run on the
        // server may restart it (the rule that keeps needrestart off is
        // for the worker's own unit, `server::needrestart_conf`).
        let (config_changed, unit_changed) = host.write(id, &text, &server::waf_unit(id))?;
        let changed = config_changed || unit_changed;
        let next = host.next(&unit, id, changed);
        // systemd reads the unit files again before it starts anything
        // from them, whichever apply wrote the unit: this one, or one
        // that ended before it got here, whose unit is the one on disk
        // and not the one systemd has.
        if next != Next::Leave {
            host.systemd.run(&["daemon-reload"])?;
        }
        host.systemd.run(&["enable", "--quiet", &unit])?;
        let (proxy, because) = match next {
            Next::Leave => ("running", None),
            Next::Start => {
                host.past_the_files(id);
                host.systemd.run(&["start", &unit])?;
                host.settled(id);
                ("started", None)
            }
            Next::Restart(because) => {
                host.past_the_files(id);
                host.systemd.run(&["restart", &unit])?;
                host.settled(id);
                ("restarted", Some(because))
            }
        };
        up(host, &unit, config.listen)?;
        Ok((changed, proxy, because))
    })();
    Ok(match applied {
        Ok((changed, proxy, because)) => json!({
            "ok": true,
            "changed": changed,
            "proxy": proxy,
            "restarted_because": because,
            "unit": unit,
            "listen": config.listen,
            "upstream": config.upstream,
        }),
        Err(why) => {
            let left = put_back(host, id, &before);
            json!({ "ok": false, "error": format!("{why}; {left}"), "unit": unit })
        }
    })
}

/// Where to knock to see whether a proxy that listens on `listen` does:
/// loopback when it listens on every address.
fn door(listen: SocketAddr) -> SocketAddr {
    match listen {
        SocketAddr::V4(a) if a.ip().is_unspecified() => (Ipv4Addr::LOCALHOST, a.port()).into(),
        SocketAddr::V6(a) if a.ip().is_unspecified() => (Ipv6Addr::LOCALHOST, a.port()).into(),
        other => other,
    }
}

/// Waits until the proxy is up: systemd calls its unit `active`, it has a
/// main process, and something accepts a connection on its port. All
/// three are seen twice, [`Host::pause`] apart, with the same main
/// process: a proxy that cannot listen (its port is another program's)
/// ends at once and systemd starts it again every two seconds, so for an
/// instant it is `active` while that other program accepts on the port;
/// it is never the same process twice.
///
/// # Errors
///
/// After [`Host::patience`]: what systemd calls the unit, and the last
/// lines of its journal, which is where the proxy says why it ended.
fn up(host: &Host<'_>, unit: &str, listen: SocketAddr) -> Result<(), String> {
    let door = door(listen);
    let since = Instant::now();
    let mut seen = None;
    loop {
        let state = host.state(unit);
        let pid = host.systemd.pid(unit);
        let accepts = TcpStream::connect_timeout(&door, Duration::from_millis(500)).is_ok();
        if state == "active" && pid != 0 && accepts {
            if seen == Some(pid) {
                return Ok(());
            }
            seen = Some(pid);
        } else {
            seen = None;
        }
        if since.elapsed() >= host.patience {
            // The journal is the proxy's to write: what is passed on of it
            // is printable ASCII, and no more than a few lines' worth.
            let journal: Vec<String> = host
                .systemd
                .journal(unit)
                .iter()
                .map(|line| printable(line, SAID))
                .collect();
            let said = if journal.is_empty() {
                format!("its journal says nothing (journalctl -u {unit})")
            } else {
                format!("its journal ends: {}", journal.join(" | "))
            };
            let port = if accepts {
                "something accepts on the port, and it is not a proxy that stays up"
            } else {
                "nothing accepts on the port"
            };
            return Err(format!(
                "the WAF did not come up on {listen} within {} s: {unit} is {state}, {port}; \
                 {said}",
                host.patience.as_secs()
            ));
        }
        std::thread::sleep(host.pause);
    }
}

/// Puts back what a worker's WAF was before an apply that failed, as far
/// as it can, and says what is there now. A WAF that was there has its
/// config and unit written back and is restarted with them, systemd
/// having been told to read the unit files again first, whichever of the
/// two was written back. Where there was none, what the apply wrote is
/// removed, so that systemd does not go on starting a proxy that cannot
/// run.
///
/// Writing the files back is a change to them like the apply's own, with
/// the same note left first ([`Host::write`]). It is taken away once
/// systemd has read the unit files and restarted the proxy, both: where
/// either failed the proxy may run the files of the apply that failed,
/// and the note stays for the next apply.
fn put_back(host: &Host<'_>, id: &str, before: &Before) -> String {
    let unit = server::waf_unit_name(id);
    let (Some(config), Some(unit_text)) = (&before.config, &before.unit) else {
        return match remove(host, id) {
            Ok(_) => "there was no WAF on this server before, and none is left".to_owned(),
            Err(e) => format!("what this left on the server could not be removed: {e}"),
        };
    };
    match host.write(id, config, unit_text) {
        Ok((false, false)) => "its config and unit are as they were".to_owned(),
        Ok(_) => {
            let read = host.systemd.run(&["daemon-reload"]);
            host.past_the_files(id);
            let restarted = host.systemd.run(&["restart", &unit]);
            if read.is_ok() && restarted.is_ok() {
                host.settled(id);
            }
            format!(
                "the config and the unit from before are back, and {unit} is {}",
                host.state(&unit)
            )
        }
        Err(e) => format!("what was there before could not be put back: {e}"),
    }
}

/// `waf-remove`: worker `id`'s WAF stopped and gone, its unit and its
/// config, and the note of an apply that did not finish; its runtime
/// directory, with the stats, goes when it stops. Not an error when
/// there is none.
pub(crate) fn remove(host: &Host<'_>, id: &str) -> Result<Value, String> {
    let unit = server::waf_unit_name(id);
    let (config_path, unit_path) = (host.config_path(id), host.unit_path(id));
    let mut removed = false;
    if unit_path.exists() {
        let _ = host.systemd.run(&["disable", "--now", "--quiet", &unit]);
        std::fs::remove_file(&unit_path)
            .map_err(|e| format!("could not remove {}: {e}", unit_path.display()))?;
        host.systemd.run(&["daemon-reload"])?;
        removed = true;
    }
    if config_path.exists() {
        std::fs::remove_file(&config_path)
            .map_err(|e| format!("could not remove {}: {e}", config_path.display()))?;
        removed = true;
    }
    // Nothing is left for the note to be about.
    host.settled(id);
    Ok(json!({ "ok": true, "removed": removed }))
}

/// The port worker `id`'s WAF listens on, by its config; none when it has
/// no WAF, or a config that does not read.
pub(crate) fn listen_port(host: &Host<'_>, id: &str) -> Option<u16> {
    let text = std::fs::read_to_string(host.config_path(id)).ok()?;
    Some(WafConfig::parse(&text).ok()?.listen.port())
}

/// What the proxy's stats file at `path` says: none when there is no
/// file (the proxy has not written one yet, or does not run), else the
/// stats, or why they are not shown.
///
/// This is read as root, and the file is in the proxy's runtime directory,
/// which the proxy can write to: the one program on the server that faces
/// the network. So, as `ctl` reads a worker's `wanted` file, it is opened
/// without following a link and without waiting (a FIFO would hold `ctl`
/// here, and `erpc worker status` with it), only a regular file is read,
/// and no more of it than [`MAX_STATS_BYTES`]. What is read is taken only
/// as stats ([`WafStats::parse`]): a time, and numbers under the names the
/// proxy counts by. Why it does not read is said without a word of what
/// was in it.
fn counted(path: &std::path::Path) -> Option<Result<WafStats, String>> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(file) => std::fs::File::from(file),
        Err(rustix::io::Errno::NOENT) => return None,
        Err(_) => return Some(Err("the WAF stats file could not be opened".to_owned())),
    };
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        return Some(Err("the WAF stats file is not a regular file".to_owned()));
    }
    let mut text = Vec::new();
    match file.take(MAX_STATS_BYTES + 1).read_to_end(&mut text) {
        Ok(read) if read as u64 <= MAX_STATS_BYTES => {}
        Ok(_) => {
            return Some(Err(format!(
                "the WAF stats file is larger than {MAX_STATS_BYTES} bytes, which no proxy writes"
            )));
        }
        Err(_) => return Some(Err("the WAF stats file could not be read".to_owned())),
    }
    let Ok(text) = String::from_utf8(text) else {
        return Some(Err("the WAF stats are not valid: not UTF-8".to_owned()));
    };
    // serde's own words for what is wrong can quote what it found, so
    // they are not passed on.
    let Ok(stats) = serde_json::from_str::<WafStats>(&text) else {
        return Some(Err("the WAF stats are not valid".to_owned()));
    };
    Some(stats.validate().map(|()| stats))
}

/// How worker `id`'s WAF is, for `status` and `firewall-show`: null when
/// it has none; else whether its unit is active, what its config has it
/// listen on and forward to, and what it has counted since it started,
/// when its stats file is there ([`counted`]).
///
/// `config` is the file `waf-apply` wrote, as the agent installed reads
/// and checks it here ([`WafConfig::parse`]). It is null when the file
/// does not read. Whether it is what the proxy runs is said by the two
/// that follow.
///
/// `started` says whether the proxy was started after its files last
/// changed, that file and its unit ([`Started`]): `after_config`,
/// `before_config` or `unknown`. Only with `after_config` was the proxy
/// started with the files as they are: `waf-apply` restarts the proxy
/// whenever it writes one of them, but an apply that ended between the
/// two, or anything else that changed a file, leaves a proxy that runs
/// the file from before. An apply that ended there is `before_config` by
/// the note it left, until an apply restarts the proxy, whenever the
/// proxy was started since.
///
/// `binary` says whether the proxy that runs is the agent installed
/// ([`Binary`]): `installed`, `other` or `unknown`. Only with `installed`
/// is `config` read as the proxy reads it: an earlier agent's proxy may
/// have read the same file otherwise (a key it did not know and this one
/// gives a default), and may lack what this one's proxy does.
///
/// erpc takes the rules in force for the ones `erpc.toml` makes only when
/// `config` is the config it makes, `started` is `after_config` and
/// `binary` is `installed`, and does not open the WAF's port wider
/// otherwise.
///
/// Every string in it is one erpc may show: systemd's word for the state,
/// addresses, a time, and why the config or the stats do not read as
/// printable ASCII of a bounded length.
pub(crate) fn status(host: &Host<'_>, id: &str) -> Value {
    let config = std::fs::read_to_string(host.config_path(id)).ok();
    if config.is_none() && !host.unit_path(id).exists() {
        return Value::Null;
    }
    let unit = server::waf_unit_name(id);
    let state = host.state(&unit);
    let binary = host.binary(&unit);
    let started = host.started(&unit, id);
    let config = config
        .ok_or_else(|| "it has a unit and no config".to_owned())
        .and_then(|text| WafConfig::parse(&text));
    let counted = counted(&host.stats_path(id));
    let read = config.as_ref().ok();
    let said = |why: &String| printable(why, SAID);
    json!({
        "unit": unit,
        "state": state,
        "active": state == "active",
        "listen": read.map(|c| c.listen),
        "port": read.map(|c| c.listen.port()),
        "upstream": read.map(|c| c.upstream),
        "config": read,
        "started": started.as_str(),
        "binary": binary.as_str(),
        "config_error": config.as_ref().err().map(said),
        "stats": counted.as_ref().and_then(|s| s.as_ref().ok()),
        "stats_error": counted.as_ref().and_then(|s| s.as_ref().err()).map(said),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use erpc_worker::server;
    use erpc_worker::waf::{Rate, WafConfig};

    use super::{Host, Systemd};

    const ID: &str = "bot-default";
    const UNIT: &str = "erpc-waf-bot-default.service";

    /// A systemd that does what it is told and says what the test has it
    /// say: a unit is `after_start` once it was started or restarted, and
    /// `inactive` once disabled.
    struct Fake {
        calls: RefCell<Vec<String>>,
        state: RefCell<String>,
        after_start: RefCell<String>,
        /// When the main process was started, as systemd says it: the
        /// time a start or a restart was asked for, unless `mute`.
        started: RefCell<String>,
        /// Whether it says nothing of when a unit was started, as a
        /// systemd that does not print that to the microsecond.
        mute: Cell<bool>,
        /// The main process; with `respawning`, another one each time it
        /// is asked for, as a proxy that systemd keeps starting has.
        pid: Cell<u32>,
        respawning: Cell<bool>,
        /// How many more things it is asked to do before whoever asks is
        /// ended there, as a killed `ctl` is: the last of them is not
        /// done, and nothing after it runs ([`killed`]).
        dies_in: Cell<Option<usize>>,
        /// What it refuses to do (`daemon-reload`, `restart`), with an
        /// error, as a `systemctl` that fails.
        refuses: Cell<Option<&'static str>>,
        journal: Vec<String>,
        /// Where the processes are and the agent installed, once a host
        /// was made of this ([`host`]): a unit started or restarted runs
        /// the agent installed then.
        runs: RefCell<Option<(PathBuf, PathBuf)>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                state: RefCell::new("inactive".to_owned()),
                after_start: RefCell::new("active".to_owned()),
                started: RefCell::new(String::new()),
                mute: Cell::new(false),
                pid: Cell::new(4242),
                respawning: Cell::new(false),
                dies_in: Cell::new(None),
                refuses: Cell::new(None),
                journal: vec![
                    "erpc-worker-agent: could not listen on 0.0.0.0:8080: Address already in use"
                        .to_owned(),
                ],
                runs: RefCell::new(None),
            }
        }

        /// The main process is made one of the agent installed now: its
        /// `exe` under the processes is that file, as it is for a process
        /// systemd has just started from it.
        fn exec(&self) {
            let Some((proc, agent)) = self.runs.borrow().clone() else {
                return;
            };
            let dir = proc.join(self.pid.get().to_string());
            std::fs::create_dir_all(&dir).expect("the process");
            let _ = std::fs::remove_file(dir.join("exe"));
            std::fs::hard_link(agent, dir.join("exe")).expect("its binary");
        }

        /// What was asked since the last time this was asked.
        fn asked(&self) -> Vec<String> {
            core::mem::take(&mut *self.calls.borrow_mut())
        }
    }

    impl Systemd for Fake {
        fn run(&self, args: &[&str]) -> Result<(), String> {
            self.calls.borrow_mut().push(args.join(" "));
            if let Some(left) = self.dies_in.get() {
                self.dies_in
                    .set(left.checked_sub(1).filter(|left| *left > 0));
                assert!(left > 1, "ctl was killed at `{}`", args.join(" "));
            }
            if self
                .refuses
                .get()
                .is_some_and(|verb| args.first() == Some(&verb))
            {
                return Err(format!("systemctl {} failed", args.join(" ")));
            }
            match args.first() {
                Some(&("start" | "restart")) => {
                    self.state.replace(self.after_start.borrow().clone());
                    self.started.replace(said(now()));
                    self.exec();
                }
                Some(&"disable") => {
                    self.state.replace("inactive".to_owned());
                }
                _ => {}
            }
            Ok(())
        }

        fn state(&self, _unit: &str) -> String {
            self.state.borrow().clone()
        }

        fn pid(&self, _unit: &str) -> u32 {
            if self.respawning.get() {
                self.pid.set(self.pid.get() + 1);
            }
            self.pid.get()
        }

        fn started(&self, _unit: &str) -> String {
            if self.mute.get() {
                String::new()
            } else {
                self.started.borrow().clone()
            }
        }

        fn journal(&self, _unit: &str) -> Vec<String> {
            self.journal.clone()
        }
    }

    /// The clock, in microseconds since 1970.
    fn now() -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after 1970");
        u64::try_from(now.as_micros()).expect("before the year 586524")
    }

    /// `micros` since 1970 as `systemctl show --timestamp=us+utc` prints a
    /// time: `Thu 2026-11-12 04:40:01.123456 UTC`.
    fn said(micros: u64) -> String {
        let (seconds, fraction) = (micros / 1_000_000, micros % 1_000_000);
        let (days, rest) = (seconds / 86_400, seconds % 86_400);
        // Howard Hinnant's civil-from-days.
        let z = days + 719_468;
        let (era, doe) = (z / 146_097, z % 146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + u64::from(month <= 2);
        // The first of January 1970 was a Thursday.
        let name = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]
            [usize::try_from(days % 7).expect("a day of the week")];
        format!(
            "{name} {year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{fraction:06} UTC",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60
        )
    }

    fn host<'a>(systemd: &'a Fake, root: &Path) -> Host<'a> {
        let units = root.join("systemd");
        std::fs::create_dir_all(&units).expect("units");
        let (proc, agent) = (root.join("proc"), root.join("agent"));
        if !agent.exists() {
            std::fs::write(&agent, b"the agent").expect("the agent");
        }
        systemd.runs.replace(Some((proc.clone(), agent.clone())));
        Host {
            systemd,
            units,
            configs: root.join("worker-waf"),
            runtime: root.join("run"),
            proc,
            agent,
            patience: Duration::from_millis(200),
            pause: Duration::from_millis(5),
        }
    }

    /// Installs another agent over the one there, as `install` does: a
    /// new file under the name, while what runs keeps the one from before.
    fn install_agent(host: &Host<'_>) {
        std::fs::remove_file(&host.agent).expect("remove");
        std::fs::write(&host.agent, b"a newer agent").expect("the agent");
    }

    /// A config for the worker, listening where `listener` does, as erpc
    /// sends it.
    fn config(listener: &TcpListener) -> WafConfig {
        config_at(listener.local_addr().expect("address").port())
    }

    /// A config for the worker, listening on `port`, as erpc sends it.
    fn config_at(port: u16) -> WafConfig {
        WafConfig::default_for(
            ID,
            format!("0.0.0.0:{port}").parse().expect("listen"),
            "127.0.0.1:3000".parse().expect("upstream"),
        )
    }

    /// A config that has the proxy listen on a port nothing accepts on,
    /// and the socket that keeps it so. The socket is bound to the port
    /// and never listens: a connection there is refused, and while the
    /// socket is kept the system gives the port to nobody else. A port
    /// only let go can be given to another test's listener the moment
    /// after, and would then accept.
    fn deaf() -> (rustix::fd::OwnedFd, WafConfig) {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, bind, getsockname, socket_with};
        let held = socket_with(
            AddressFamily::INET,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socket");
        let loopback = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
        bind(&held, &loopback).expect("bind");
        let address: std::net::SocketAddr = getsockname(&held)
            .expect("address")
            .try_into()
            .expect("an IP address");
        assert!(
            std::net::TcpStream::connect(address).is_err(),
            "a socket that does not listen accepts nothing"
        );
        (held, config_at(address.port()))
    }

    fn json(config: &WafConfig) -> String {
        serde_json::to_string(config).expect("json")
    }

    /// What systemd is asked, in order, by an apply that starts the proxy
    /// (`start`) or restarts it (`restart`): to read the unit files again,
    /// to enable the unit, and only then to start it.
    fn after_reload(verb: &str) -> [String; 3] {
        [
            "daemon-reload".to_owned(),
            format!("enable --quiet {UNIT}"),
            format!("{verb} {UNIT}"),
        ]
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).expect("there").permissions().mode() & 0o777
    }

    /// Every string in `value`, the names of its fields among them.
    fn strings(value: &serde_json::Value) -> Vec<String> {
        match value {
            serde_json::Value::String(text) => vec![text.clone()],
            serde_json::Value::Array(items) => items.iter().flat_map(strings).collect(),
            serde_json::Value::Object(fields) => fields
                .iter()
                .flat_map(|(name, value)| {
                    let mut all = strings(value);
                    all.push(name.clone());
                    all
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Whether every string in `value` is printable ASCII.
    fn plain(value: &serde_json::Value) -> bool {
        strings(value)
            .iter()
            .all(|text| text.bytes().all(|b| matches!(b, b' '..=b'~')))
    }

    /// Stats as the proxy writes them, with `since` and `requests` as given
    /// (`requests` as JSON: a number, or anything else).
    fn stats(since: &str, requests: &str) -> String {
        format!(
            r#"{{"format":1,"since":"{since}","requests":{requests},"forwarded":7,
            "blocked":{{"method":1,"path":0,"denied":1,"not_allowed":0,"probe":2,"rate":0,
            "body":0,"malformed":0,"banned":1,"connections":0,"upgrade":0,"body_timeout":0}},
            "banned_now":1,"upstream_errors":0}}"#
        )
    }

    const SINCE: &str = "2026-11-11T09:00:00Z";
    /// What a terminal would act on: a title change, a bell, a screen clear.
    const ESCAPES: &str = "\u{1b}]0;owned\u{7}\u{1b}[2J";
    /// The same, as JSON text spells it inside a string.
    const ESCAPES_JSON: &str = r"\u001b]0;owned\u0007\u001b[2J";

    #[test]
    fn the_verbs_are_the_words_erpc_sends() {
        use clap::Parser as _;
        for verb in ["waf-apply", "waf-remove"] {
            let line = ["erpc-worker-agent", "ctl", "--id", ID, verb];
            assert!(crate::Cli::try_parse_from(line).is_ok(), "{verb}");
        }
    }

    #[test]
    fn a_new_waf_is_written_enabled_started_and_waited_for() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);

        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["changed"], true, "{answer}");
        assert_eq!(answer["proxy"], "started", "{answer}");
        assert_eq!(systemd.asked(), after_reload("start"));
        // The config is what the proxy reads, where its unit says, and
        // both are root's to write and anyone's to read.
        let config_path = host.configs.join("bot-default.json");
        let written = std::fs::read_to_string(&config_path).expect("config");
        assert_eq!(WafConfig::parse(&written).expect("reads"), config);
        assert!(
            server::waf_config_path(ID).ends_with("/worker-waf/bot-default.json"),
            "the unit reads the file of this name"
        );
        let unit_path = host.units.join(UNIT);
        assert_eq!(
            std::fs::read_to_string(&unit_path).expect("unit"),
            server::waf_unit(ID)
        );
        assert_eq!((mode(&config_path), mode(&unit_path)), (0o644, 0o644));
        assert_eq!(mode(&host.configs), 0o755);
        // The proxy was started after both were written: it runs them.
        assert_eq!(super::status(&host, ID)["started"], "after_config");

        // The same again changes nothing and restarts nothing: systemd is
        // not told to read the unit files, nor to start anything.
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["changed"], false, "{answer}");
        assert_eq!(answer["proxy"], "running", "{answer}");
        assert_eq!(systemd.asked(), [format!("enable --quiet {UNIT}")]);

        // Unchanged, and found stopped: started, not called changed.
        systemd.state.replace("failed".to_owned());
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["changed"], false, "{answer}");
        assert_eq!(answer["proxy"], "started", "{answer}");
        assert_eq!(systemd.asked(), after_reload("start"));
    }

    #[test]
    fn a_changed_config_or_unit_restarts_the_proxy_once_systemd_has_read_the_units_again() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let mut config = config(&listener);
        super::apply(&host, ID, &json(&config)).expect("answers");
        systemd.asked();

        config.rate = Some(Rate {
            per_second: 5,
            burst: 9,
        });
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["changed"], true, "{answer}");
        assert_eq!(answer["proxy"], "restarted", "{answer}");
        assert_eq!(systemd.asked(), after_reload("restart"));
        let written = std::fs::read_to_string(host.configs.join("bot-default.json")).expect("it");
        assert_eq!(WafConfig::parse(&written).expect("reads").rate, config.rate);

        // A unit from an older erpc is replaced, and the proxy restarted
        // under the new one.
        std::fs::write(host.units.join(UNIT), "[Service]\nExecStart=/bin/true\n").expect("old");
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["changed"], true, "{answer}");
        assert_eq!(answer["restarted_because"], "changed", "{answer}");
        assert_eq!(systemd.asked(), after_reload("restart"));
        assert_eq!(
            std::fs::read_to_string(host.units.join(UNIT)).expect("unit"),
            server::waf_unit(ID)
        );
        assert_eq!(super::status(&host, ID)["started"], "after_config");
    }

    #[test]
    fn a_proxy_that_does_not_run_the_agent_installed_is_restarted_whatever_the_files_say() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        let config_path = host.configs.join("bot-default.json");
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["proxy"], "started", "{answer}");
        assert!(answer["restarted_because"].is_null(), "{answer}");
        let written = std::fs::read_to_string(&config_path).expect("config");
        systemd.asked();

        // It runs the agent installed: `status` says so, and the same
        // config again leaves it running.
        assert_eq!(super::status(&host, ID)["binary"], "installed");
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["proxy"], "running", "{answer}");
        assert!(answer["restarted_because"].is_null(), "{answer}");
        assert_eq!(systemd.asked(), [format!("enable --quiet {UNIT}")]);

        // A newer agent is installed. The proxy is a process of the one
        // from before: `status` says so, with the config as the file has
        // it, which is not what tells erpc the rules in force.
        install_agent(&host);
        let status = super::status(&host, ID);
        assert_eq!(status["binary"], "other", "{status}");
        assert_eq!(status["active"], true, "{status}");
        let reported: WafConfig =
            serde_json::from_value(status["config"].clone()).expect("the config");
        assert_eq!(reported, config);
        // The same config, the same unit: restarted all the same, and the
        // answer says why. Neither file is written.
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["changed"], false, "{answer}");
        assert_eq!(answer["proxy"], "restarted", "{answer}");
        assert_eq!(answer["restarted_because"], "other_binary", "{answer}");
        assert_eq!(systemd.asked(), after_reload("restart"));
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("config"),
            written
        );
        // What runs now is the agent installed, and is left running.
        assert_eq!(super::status(&host, ID)["binary"], "installed");
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["proxy"], "running", "{answer}");
        assert_eq!(systemd.asked(), [format!("enable --quiet {UNIT}")]);

        // Which binary it runs cannot be told (its process is not to be
        // looked at): not taken for the one installed, and restarted.
        std::fs::remove_dir_all(&host.proc).expect("no processes");
        assert_eq!(super::status(&host, ID)["binary"], "unknown");
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["proxy"], "restarted", "{answer}");
        assert_eq!(answer["restarted_because"], "unknown_binary", "{answer}");
        assert_eq!(systemd.asked(), after_reload("restart"));
        // So is a unit with no main process.
        systemd.pid.set(0);
        assert_eq!(super::status(&host, ID)["binary"], "unknown");

        // A changed config says that it is why, whichever agent runs.
        systemd.pid.set(4242);
        install_agent(&host);
        let mut tighter = config.clone();
        tighter.deny_paths = vec!["/admin/*".to_owned()];
        let answer = super::apply(&host, ID, &json(&tighter)).expect("answers");
        assert_eq!(answer["changed"], true, "{answer}");
        assert_eq!(answer["restarted_because"], "changed", "{answer}");
        assert_eq!(super::status(&host, ID)["binary"], "installed");

        // A proxy that does not run is started, and runs the one installed.
        install_agent(&host);
        systemd.state.replace("failed".to_owned());
        let answer = super::apply(&host, ID, &json(&tighter)).expect("answers");
        assert_eq!(answer["proxy"], "started", "{answer}");
        assert!(answer["restarted_because"].is_null(), "{answer}");
        assert_eq!(super::status(&host, ID)["binary"], "installed");
    }

    #[test]
    fn the_time_a_proxy_started_is_read_only_as_systemd_prints_it_to_the_microsecond() {
        use super::micros;
        // What `systemctl show --timestamp=us+utc` printed on a server,
        // beside the seconds it printed for the same unit with
        // `--timestamp=unix`.
        assert_eq!(
            micros("Wed 2026-11-04 06:50:40.946753 UTC"),
            Some(1_793_775_040_946_753)
        );
        assert_eq!(micros("Thu 1970-01-01 00:00:00.000000 UTC"), Some(0));
        assert_eq!(
            micros("Tue 2000-02-29 00:00:00.000000 UTC"),
            Some(951_782_400_000_000)
        );
        assert_eq!(
            micros("Thu 2026-12-31 23:59:59.999999 UTC"),
            Some(1_798_761_599_999_999)
        );
        // And back, by the test's own arithmetic: the ends of months and
        // years, a leap day, a moment ago.
        for at in [
            0,
            1,
            86_399_999_999,
            86_400_000_000,
            951_782_399_999_999,
            951_868_800_000_000,
            1_793_775_040_946_753,
            1_798_761_600_000_000,
            4_102_444_800_000_000,
            now(),
        ] {
            assert_eq!(micros(&said(at)), Some(at), "{}", said(at));
        }
        // Anything else is not a time it started at: no time (a unit that
        // never started), systemd's other forms, another zone, a number
        // out of its range, more or less than was asked for.
        for not_one in [
            "",
            "n/a",
            "0",
            "1793775040946753",
            "@1793775040",
            "Wed 2026-11-04 06:50:40 UTC",
            "Wed 2026-11-04 06:50:40.946753",
            "Wed 2026-11-04 15:50:40.946753 JST",
            "2026-11-04 06:50:40.946753 UTC",
            "Wed 2026-11-04 06:50:40.946753 UTC ",
            " Wed 2026-11-04 06:50:40.946753 UTC",
            "Wed 2026-11-04 06:50:40.946753 UTC and more",
            "Wed  2026-11-04 06:50:40.946753 UTC",
            "Wed 2026-11-04T06:50:40.946753 UTC",
            "Wed 2026-11-04 06:50:40.94675 UTC",
            "Wed 2026-11-04 06:50:40.9467531 UTC",
            "Wed 2026-11-04 06:50:40.+46753 UTC",
            "Wed 2026-13-04 06:50:40.946753 UTC",
            "Wed 2026-00-04 06:50:40.946753 UTC",
            "Wed 2026-11-00 06:50:40.946753 UTC",
            "Wed 2026-11-32 06:50:40.946753 UTC",
            "Wed 2026-11-04 24:50:40.946753 UTC",
            "Wed 2026-11-04 06:60:40.946753 UTC",
            "Wed 2026-11-04 06:50:60.946753 UTC",
            "Wed 1969-12-31 23:59:59.999999 UTC",
            "Wed 02026-11-04 06:50:40.946753 UTC",
            "Wed 2026-11-04-01 06:50:40.946753 UTC",
            "Wed 2026-11-04 06:50:40:00.946753 UTC",
            "W3d 2026-11-04 06:50:40.946753 UTC",
            "Wed\u{1b}[2J 2026-11-04 06:50:40.946753 UTC",
        ] {
            assert_eq!(micros(not_one), None, "{not_one:?}");
        }
    }

    /// The config as `waf-apply` writes it, written where it writes it and
    /// nothing more: the file changed on the server, by whatever is not
    /// an apply of this agent's, and the proxy not restarted. (An apply
    /// that ended there leaves its note as well: [`killed`].)
    fn write_only(host: &Host<'_>, config: &WafConfig) {
        let text = serde_json::to_string_pretty(config).expect("json") + "\n";
        let written = super::put(&host.configs.join("bot-default.json"), &text, 0o644);
        assert_eq!(written, Ok(true), "the file changed");
    }

    #[test]
    fn a_proxy_started_before_its_config_last_changed_is_restarted_though_the_file_is_as_asked() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        let config_path = host.configs.join("bot-default.json");
        super::apply(&host, ID, &json(&config)).expect("answers");
        systemd.asked();
        // Started after its config was written: `status` says so, and the
        // same config again leaves it running.
        assert_eq!(super::status(&host, ID)["started"], "after_config");
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["proxy"], "running", "{answer}");
        assert_eq!(systemd.asked(), [format!("enable --quiet {UNIT}")]);

        // A tighter config is written there and the proxy not restarted
        // (by an agent from before the note, or by hand). The file is
        // the tighter config; the proxy runs the one from before.
        // `status` reports the file and says the proxy was started
        // before it.
        let mut tighter = config.clone();
        tighter.deny_paths = vec!["/admin/*".to_owned()];
        write_only(&host, &tighter);
        let status = super::status(&host, ID);
        assert_eq!(status["started"], "before_config", "{status}");
        assert_eq!(status["binary"], "installed", "{status}");
        assert_eq!(status["active"], true, "{status}");
        let reported: WafConfig =
            serde_json::from_value(status["config"].clone()).expect("the config");
        assert_eq!(reported, tighter);
        // The next apply is handed what the file already holds, writes
        // nothing, and restarts the proxy all the same, saying why.
        let written = std::fs::read_to_string(&config_path).expect("config");
        let answer = super::apply(&host, ID, &json(&tighter)).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["changed"], false, "{answer}");
        assert_eq!(answer["proxy"], "restarted", "{answer}");
        assert_eq!(answer["restarted_because"], "older_than_config", "{answer}");
        assert_eq!(systemd.asked(), after_reload("restart"));
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("config"),
            written
        );
        // Now it runs the file, and is left running.
        assert_eq!(super::status(&host, ID)["started"], "after_config");
        let answer = super::apply(&host, ID, &json(&tighter)).expect("answers");
        assert_eq!(answer["proxy"], "running", "{answer}");
        assert!(answer["restarted_because"].is_null(), "{answer}");
        assert_eq!(systemd.asked(), [format!("enable --quiet {UNIT}")]);

        // A file changed with its date kept, as a copy that preserves
        // times makes it: the time it was modified is an hour ago, and it
        // changed after the proxy started all the same.
        write_only(&host, &config);
        let hour_ago = SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&config_path)
            .and_then(|file| file.set_modified(hour_ago))
            .expect("dated back");
        assert_eq!(super::status(&host, ID)["started"], "before_config");
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["restarted_because"], "older_than_config", "{answer}");

        // Where the proxy is also an agent from before the one installed,
        // that is the reason said: which agent runs is looked at first.
        write_only(&host, &tighter);
        install_agent(&host);
        systemd.asked();
        let answer = super::apply(&host, ID, &json(&tighter)).expect("answers");
        assert_eq!(answer["restarted_because"], "other_binary", "{answer}");
        assert_eq!(super::status(&host, ID)["started"], "after_config");
    }

    /// When the later of the worker's two files last changed.
    fn later(host: &Host<'_>) -> u64 {
        let config = super::changed_at(&host.configs.join("bot-default.json")).expect("a time");
        let unit = super::changed_at(&host.units.join(UNIT)).expect("a time");
        config.max(unit)
    }

    #[test]
    fn a_start_is_after_its_files_only_when_dated_a_tick_or_more_after_the_later_of_them() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let mut config = config(&listener);
        let (config_path, unit_path) =
            (host.configs.join("bot-default.json"), host.units.join(UNIT));
        let started = || super::micros(&systemd.started.borrow()).expect("a time");
        // An apply does not start a proxy, or restart one, sooner than a
        // tick after the time of the later of its files: both written,
        let between = Duration::from_millis(30);
        super::apply(&host, ID, &json(&config)).expect("answers");
        assert!(started() >= later(&host) + 10_000);
        // the config alone, the unit being the older,
        std::thread::sleep(between);
        config.deny_paths = vec!["/admin/*".to_owned()];
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["proxy"], "restarted", "{answer}");
        let config_at = super::changed_at(&config_path).expect("a time");
        assert_eq!(later(&host), config_at, "the config is the later");
        assert!(started() >= config_at + 10_000);
        // and the unit alone, the config being the older.
        std::thread::sleep(between);
        std::fs::write(&unit_path, "[Service]\nExecStart=/bin/true\n").expect("an older unit");
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["proxy"], "restarted", "{answer}");
        let unit_at = super::changed_at(&unit_path).expect("a time");
        assert_eq!(later(&host), unit_at, "the unit is the later");
        assert!(started() >= unit_at + 10_000);

        // It waits for what is left of the tick, and for nothing where
        // the file is older; never longer than a tick, though the file is
        // dated ahead of the clock.
        let wait = |now: u64| super::until_past(now, 1_000_000_000_000);
        let micros = Duration::from_micros;
        assert_eq!(wait(1_000_000_000_000), micros(10_000));
        assert_eq!(wait(1_000_000_004_000), micros(6_000));
        assert_eq!(wait(1_000_000_009_999), micros(1));
        assert_eq!(wait(1_000_000_010_000), Duration::ZERO);
        assert_eq!(wait(2_000_000_000_000), Duration::ZERO);
        assert_eq!(wait(999_999_999_999), micros(10_000));
        assert_eq!(wait(0), micros(10_000));
        assert_eq!(super::until_past(0, u64::MAX), micros(10_000));

        let started_at = |micros: u64| {
            systemd.started.replace(said(micros));
            super::status(&host, ID)["started"].clone()
        };
        // The unit is the later of the two here, by more than a tick. The
        // kernel dates a file by its last tick, up to 10 ms before the
        // clock systemd reads: a start dated less than that after the
        // later file may have come before its change.
        assert!(unit_at > config_at + 20_000, "{unit_at} after {config_at}");
        assert_eq!(started_at(unit_at + 3_600_000_000), "after_config");
        assert_eq!(started_at(unit_at + 10_000), "after_config");
        assert_eq!(started_at(unit_at + 9_999), "before_config");
        assert_eq!(started_at(unit_at), "before_config");
        assert_eq!(started_at(unit_at - 1), "before_config");
        // A tick after the config, and before the unit: before.
        assert_eq!(started_at(config_at + 10_000), "before_config");
        assert_eq!(started_at(config_at - 86_400_000_000), "before_config");

        // The other way round: the config is the later, by more than a
        // tick. A tick after the unit, and before the config, is before.
        std::thread::sleep(between);
        std::fs::write(&config_path, std::fs::read(&config_path).expect("config"))
            .expect("written again");
        let config_at = super::changed_at(&config_path).expect("a time");
        assert!(config_at > unit_at + 20_000, "{config_at} after {unit_at}");
        assert_eq!(started_at(unit_at + 10_000), "before_config");
        assert_eq!(started_at(config_at + 9_999), "before_config");
        assert_eq!(started_at(config_at + 10_000), "after_config");
    }

    /// The unit as `waf-apply` writes it, written where it writes it and
    /// nothing more: systemd is not told to read it, and the proxy is not
    /// restarted. What an apply of an agent from before the note left
    /// when it ended there; this agent's leaves its note too ([`killed`]).
    fn write_unit_only(host: &Host<'_>) {
        let written = super::put(&host.units.join(UNIT), &server::waf_unit(ID), 0o644);
        assert_eq!(written, Ok(true), "the unit changed");
    }

    /// Leaves the server as an older erpc had it: its unit on disk, and
    /// the proxy started under it, after both files.
    fn under_an_older_unit(host: &Host<'_>, systemd: &Fake) {
        std::fs::write(host.units.join(UNIT), "[Service]\nExecStart=/bin/true\n")
            .expect("an older unit");
        std::thread::sleep(Duration::from_millis(15));
        systemd.state.replace("active".to_owned());
        systemd.run(&["restart", UNIT]).expect("restarted");
        systemd.asked();
        assert_eq!(super::status(host, ID)["started"], "after_config");
    }

    #[test]
    fn a_proxy_started_before_its_unit_last_changed_is_restarted_once_systemd_has_read_the_unit() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        super::apply(&host, ID, &json(&config)).expect("answers");
        let (config_path, unit_path) =
            (host.configs.join("bot-default.json"), host.units.join(UNIT));
        let written = std::fs::read_to_string(&config_path).expect("config");
        let files = || {
            (
                std::fs::read_to_string(&config_path).expect("config"),
                std::fs::read_to_string(&unit_path).expect("unit"),
            )
        };
        let as_asked = (written, server::waf_unit(ID));

        // This erpc's unit is written over an older one and nothing more
        // is done: systemd has not read it, and the proxy runs under the
        // one from before. `status` says the proxy was started before its
        // files last changed.
        under_an_older_unit(&host, &systemd);
        write_unit_only(&host);
        let status = super::status(&host, ID);
        assert_eq!(status["started"], "before_config", "{status}");
        assert_eq!(status["binary"], "installed", "{status}");
        assert_eq!(status["active"], true, "{status}");
        // The next apply is handed the same config. Both files are what
        // it would write, and it writes nothing; it has systemd read the
        // unit files again, restarts the proxy, and says why.
        assert_eq!(files(), as_asked);
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["changed"], false, "{answer}");
        assert_eq!(answer["proxy"], "restarted", "{answer}");
        assert_eq!(answer["restarted_because"], "older_than_config", "{answer}");
        assert_eq!(systemd.asked(), after_reload("restart"));
        assert_eq!(files(), as_asked);
        // Now it runs under the unit on disk, and is left running: systemd
        // is asked to enable the unit, and nothing else.
        assert_eq!(super::status(&host, ID)["started"], "after_config");
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["proxy"], "running", "{answer}");
        assert!(answer["restarted_because"].is_null(), "{answer}");
        assert_eq!(systemd.asked(), [format!("enable --quiet {UNIT}")]);

        // The same where the proxy has stopped meanwhile: it is started,
        // and under the unit on disk, which systemd reads first.
        under_an_older_unit(&host, &systemd);
        write_unit_only(&host);
        systemd.state.replace("failed".to_owned());
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["changed"], false, "{answer}");
        assert_eq!(answer["proxy"], "started", "{answer}");
        assert_eq!(systemd.asked(), after_reload("start"));
        assert_eq!(super::status(&host, ID)["started"], "after_config");

        // And where the proxy is restarted for the agent it runs: under
        // the unit on disk too, though this apply did not write it.
        under_an_older_unit(&host, &systemd);
        write_unit_only(&host);
        install_agent(&host);
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["changed"], false, "{answer}");
        assert_eq!(answer["restarted_because"], "other_binary", "{answer}");
        assert_eq!(systemd.asked(), after_reload("restart"));
        assert_eq!(super::status(&host, ID)["started"], "after_config");
    }

    /// An apply of `config` that is ended, as a killed `ctl` is, at the
    /// `step`th thing it asks systemd to do: what it had done by then
    /// stays as it is, that step is not done, and nothing is put back.
    fn killed(host: &Host<'_>, systemd: &Fake, config: &WafConfig, step: usize) {
        systemd.dies_in.set(Some(step));
        let input = json(config);
        let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::apply(host, ID, &input)
        }));
        assert!(ended.is_err(), "the apply is ended at its step {step}");
        assert_eq!(systemd.dies_in.get(), None, "at that step");
        systemd.asked();
    }

    /// systemd starts the proxy again by itself, as it does when the
    /// proxy fails, under the unit it has read: nobody tells it to read
    /// the unit files. The start is dated now, a tick or more after both
    /// files.
    fn restarted_by_systemd(host: &Host<'_>, systemd: &Fake) {
        std::thread::sleep(Duration::from_millis(15));
        systemd.run(&["restart", UNIT]).expect("restarted");
        systemd.asked();
        let started = super::micros(&systemd.started.borrow()).expect("a time");
        assert!(started >= later(host) + 10_000, "dated after both files");
    }

    /// What the next apply does with a proxy an unfinished apply left,
    /// handed what the files already hold: it writes nothing, has systemd
    /// read the unit files, restarts the proxy and says why; the note is
    /// gone, and the proxy is left running from then on.
    fn the_next_apply_restarts_it(host: &Host<'_>, systemd: &Fake, config: &WafConfig) {
        let note = host.configs.join("bot-default.applying");
        let status = super::status(host, ID);
        assert_eq!(status["started"], "before_config", "{status}");
        assert_eq!(status["binary"], "installed", "{status}");
        assert!(note.exists(), "the note is there");
        let answer = super::apply(host, ID, &json(config)).expect("answers");
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["changed"], false, "{answer}");
        assert_eq!(answer["proxy"], "restarted", "{answer}");
        assert_eq!(answer["restarted_because"], "older_than_config", "{answer}");
        assert_eq!(systemd.asked(), after_reload("restart"));
        assert!(!note.exists(), "the note is gone");
        assert_eq!(super::status(host, ID)["started"], "after_config");
        let answer = super::apply(host, ID, &json(config)).expect("answers");
        assert_eq!(answer["proxy"], "running", "{answer}");
        assert_eq!(systemd.asked(), [format!("enable --quiet {UNIT}")]);
    }

    #[test]
    fn an_apply_that_ended_before_its_restart_is_known_whatever_started_the_proxy_since() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        super::apply(&host, ID, &json(&config)).expect("answers");
        let note = host.configs.join("bot-default.applying");
        // Wherever it ends once it has written: before systemd is told to
        // read the unit files, before the unit is enabled, before the
        // restart.
        for step in 1..=3 {
            // An older erpc's unit is the one systemd has read, and the
            // proxy runs under it. This erpc's apply writes its unit over
            // it, and is ended.
            under_an_older_unit(&host, &systemd);
            assert!(!note.exists(), "no apply is under way");
            killed(&host, &systemd, &config, step);
            assert_eq!(
                std::fs::read_to_string(host.units.join(UNIT)).expect("unit"),
                server::waf_unit(ID),
                "step {step}: the unit was written"
            );
            assert!(note.exists(), "step {step}: its note stays");
            assert_eq!(super::status(&host, ID)["started"], "before_config");
            // The proxy fails, and systemd starts it again under the unit
            // it had read: a start dated after both files, which the two
            // times alone take for one made from them.
            restarted_by_systemd(&host, &systemd);
            // Then a deploy comes. Before it gets to the WAF it enables
            // the agent's unit, at which systemd reads every unit file:
            // from here systemd has no unit but the one on disk, and the
            // proxy still runs under the one from before.
            systemd
                .run(&["enable", "--quiet", "erpc-worker-bot-default.service"])
                .expect("enabled");
            systemd.asked();
            the_next_apply_restarts_it(&host, &systemd, &config);
        }
    }

    #[test]
    fn an_apply_that_ended_after_writing_the_config_is_known_whatever_the_clock_says() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        super::apply(&host, ID, &json(&config)).expect("answers");
        // An apply of a tighter config writes it and is ended before it
        // restarts the proxy: the proxy runs the config from before.
        let mut tighter = config.clone();
        tighter.deny_paths = vec!["/admin/*".to_owned()];
        killed(&host, &systemd, &tighter, 1);
        let status = super::status(&host, ID);
        let reported: WafConfig =
            serde_json::from_value(status["config"].clone()).expect("the config");
        assert_eq!(reported, tighter, "the file is the tighter config");
        // The clock had been set back before that apply: the file is
        // dated an hour before the proxy's start, though it changed
        // after it. The times alone say the proxy was started after.
        systemd.started.replace(said(later(&host) + 3_600_000_000));
        the_next_apply_restarts_it(&host, &systemd, &tighter);

        // A first apply that ended once it had written, wherever: before
        // systemd read the unit files, before the unit was enabled, before
        // the start. Nothing runs, and the next apply starts the proxy.
        for step in 1..=3 {
            let other = tempfile::tempdir().expect("tmp");
            let systemd = Fake::new();
            let host = self::host(&systemd, other.path());
            let note = host.configs.join("bot-default.applying");
            killed(&host, &systemd, &config, step);
            assert!(note.exists(), "step {step}: its note stays");
            assert!(host.units.join(UNIT).exists(), "step {step}");
            let status = super::status(&host, ID);
            assert_eq!(status["active"], false, "{status}");
            assert_eq!(status["started"], "before_config", "{status}");
            let answer = super::apply(&host, ID, &json(&config)).expect("answers");
            assert_eq!(answer["changed"], false, "{answer}");
            assert_eq!(answer["proxy"], "started", "{answer}");
            assert_eq!(systemd.asked(), after_reload("start"));
            assert!(!note.exists(), "the note is gone");
            assert_eq!(super::status(&host, ID)["started"], "after_config");
        }
    }

    #[test]
    fn putting_back_what_was_there_is_a_change_that_leaves_its_note_until_the_restart() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let before = config(&listener);
        super::apply(&host, ID, &json(&before)).expect("answers");
        let config_path = host.configs.join("bot-default.json");
        let kept = std::fs::read_to_string(&config_path).expect("config");
        let note = host.configs.join("bot-default.applying");
        // A config that has the proxy listen where nothing answers: the
        // apply restarts the proxy with it, the proxy does not come up,
        // and the config from before is written back. The apply is ended
        // there, before systemd reads the unit files (the fourth thing
        // it is asked) or before the restart (the fifth). The proxy runs
        // the config that failed, under a file that is the one from
        // before.
        let (_held, moved) = deaf();
        for step in 4..=5 {
            killed(&host, &systemd, &moved, step);
            assert_eq!(std::fs::read_to_string(&config_path).expect("config"), kept);
            assert!(note.exists(), "step {step}: its note stays");
            restarted_by_systemd(&host, &systemd);
            the_next_apply_restarts_it(&host, &systemd, &before);
        }
        // The same where systemd fails at one of the two: the proxy may
        // still run the config that failed, and the note stays.
        for refused in ["daemon-reload", "restart"] {
            systemd.refuses.set(Some(refused));
            let answer = super::apply(&host, ID, &json(&moved)).expect("answers");
            assert_eq!(answer["ok"], false, "{refused}: {answer}");
            assert_eq!(std::fs::read_to_string(&config_path).expect("config"), kept);
            assert!(note.exists(), "{refused}: its note stays");
            systemd.refuses.set(None);
            systemd.asked();
            restarted_by_systemd(&host, &systemd);
            the_next_apply_restarts_it(&host, &systemd, &before);
        }
    }

    #[test]
    fn an_apply_that_cannot_leave_its_note_writes_nothing() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        super::apply(&host, ID, &json(&config)).expect("answers");
        systemd.asked();
        let config_path = host.configs.join("bot-default.json");
        let written = std::fs::read_to_string(&config_path).expect("config");
        // Where the note goes is a directory with something in it: no
        // file can be put there.
        let note = host.configs.join("bot-default.applying");
        std::fs::create_dir_all(note.join("kept")).expect("a directory");
        let mut tighter = config.clone();
        tighter.deny_paths = vec!["/admin/*".to_owned()];
        let answer = super::apply(&host, ID, &json(&tighter)).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");
        let why = answer["error"].as_str().expect("why");
        assert!(why.contains("bot-default.applying"), "{why}");
        assert!(
            why.contains("its config and unit are as they were"),
            "{why}"
        );
        // Neither file was written, and systemd was asked nothing.
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("config"),
            written
        );
        assert!(systemd.asked().is_empty(), "systemd was asked nothing");
        // Whatever is where the note goes counts as one: the proxy is not
        // taken to have been started from its files.
        assert_eq!(super::status(&host, ID)["started"], "before_config");
    }

    #[test]
    fn a_proxy_whose_start_cannot_be_told_is_not_taken_to_run_its_config_and_is_restarted() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        super::apply(&host, ID, &json(&config)).expect("answers");
        systemd.asked();
        // What systemd says is not a time to the microsecond in UTC: one
        // that does not know the form asked for prints nothing.
        for said in [
            "",
            "n/a",
            "Thu 2026-11-12 04:40:01 UTC",
            "Thu 2026-11-12 13:40:01.123456 JST",
            "\u{1b}]0;owned\u{7}",
        ] {
            systemd.started.replace(said.to_owned());
            let status = super::status(&host, ID);
            assert_eq!(status["started"], "unknown", "{said:?}");
            assert!(plain(&status), "{status}");
            let answer = super::apply(&host, ID, &json(&config)).expect("answers");
            assert_eq!(answer["changed"], false, "{said:?}: {answer}");
            assert_eq!(answer["proxy"], "restarted", "{said:?}: {answer}");
            assert_eq!(answer["restarted_because"], "unknown_start", "{said:?}");
            assert_eq!(systemd.asked(), after_reload("restart"), "{said:?}");
        }
        // A server whose systemd never says it: every apply restarts the
        // proxy, and `status` never takes it to run its config.
        systemd.mute.set(true);
        for _ in 0..3 {
            let answer = super::apply(&host, ID, &json(&config)).expect("answers");
            assert_eq!(answer["restarted_because"], "unknown_start", "{answer}");
            assert_eq!(systemd.asked(), after_reload("restart"));
            assert_eq!(super::status(&host, ID)["started"], "unknown");
        }
        // Nor is it told where the time of one of its files cannot be
        // read: a config with no unit, and a unit with no config.
        systemd.mute.set(false);
        let unit_path = host.units.join(UNIT);
        let unit = std::fs::read(&unit_path).expect("the unit");
        assert_eq!(super::status(&host, ID)["started"], "after_config");
        std::fs::remove_file(&unit_path).expect("removed");
        assert_eq!(super::status(&host, ID)["started"], "unknown");
        std::fs::write(&unit_path, unit).expect("back");
        std::fs::remove_file(host.configs.join("bot-default.json")).expect("removed");
        assert_eq!(super::status(&host, ID)["started"], "unknown");
    }

    #[test]
    fn a_proxy_restarted_for_its_binary_that_does_not_come_up_leaves_the_files_as_they_were() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        super::apply(&host, ID, &json(&config)).expect("answers");
        let config_path = host.configs.join("bot-default.json");
        let written = std::fs::read_to_string(&config_path).expect("config");
        install_agent(&host);
        systemd.asked();
        // The newer agent's proxy does not stay up.
        systemd.after_start.replace("activating".to_owned());
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");
        let why = answer["error"].as_str().expect("why");
        assert!(
            why.contains("its config and unit are as they were"),
            "{why}"
        );
        assert_eq!(systemd.asked(), after_reload("restart"));
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("config"),
            written
        );
        assert!(host.units.join(UNIT).exists());
    }

    #[test]
    fn a_config_that_is_not_this_workers_is_refused_before_anything_is_written() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let good = config(&listener);
        let elsewhere = WafConfig {
            stats_path: server::waf_stats_path("other-default"),
            ..good.clone()
        };
        let own_file = WafConfig {
            stats_path: "/etc/cron.d/stats".to_owned(),
            ..good.clone()
        };
        // Built, not written out: only loopback is an upstream.
        let abroad = json(&good).replace("127.0.0.1:3000", "198.51.100.7:3000");
        let unknown = json(&good).replace("\"block_probes\"", "\"tls\":true,\"block_probes\"");
        for (input, says) in [
            (
                json(&elsewhere),
                "this worker's are /run/erpc-waf-bot-default/stats.json",
            ),
            (json(&own_file), "this worker's are"),
            (abroad, "not a loopback address"),
            (unknown, "not valid"),
            ("{}".to_owned(), "not valid"),
            (String::new(), "not valid"),
        ] {
            let refused = super::apply(&host, ID, &input).expect_err(&input);
            assert!(refused.contains(says), "{input}: {refused}");
        }
        assert!(systemd.asked().is_empty(), "systemd was asked nothing");
        assert!(!host.configs.exists());
        assert!(!host.units.join(UNIT).exists());
    }

    #[test]
    fn a_first_proxy_that_does_not_come_up_says_why_and_leaves_no_waf() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        // Its port is another program's (the listener here): it ends at
        // once, and systemd waits to start it again.
        systemd.after_start.replace("activating".to_owned());

        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");
        let why = answer["error"].as_str().expect("why");
        for part in [
            &format!("the WAF did not come up on {} within ", config.listen),
            &format!("{UNIT} is activating"),
            "something accepts on the port, and it is not a proxy that stays up",
            "its journal ends: erpc-worker-agent: could not listen on 0.0.0.0:8080: Address \
             already in use",
            "there was no WAF on this server before, and none is left",
        ] {
            assert!(why.contains(part), "{part}\nin: {why}");
        }
        assert!(!host.configs.join("bot-default.json").exists());
        assert!(!host.units.join(UNIT).exists());
        let asked = systemd.asked();
        assert_eq!(
            asked[asked.len() - 2..],
            [
                format!("disable --now --quiet {UNIT}"),
                "daemon-reload".to_owned()
            ],
            "{asked:?}"
        );
    }

    #[test]
    fn a_proxy_systemd_keeps_starting_again_is_not_taken_for_one_that_is_up() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        // `active` each time it is looked at, and another process each
        // time: started over and over, while the listener here accepts.
        systemd.respawning.set(true);
        let answer = super::apply(&host, ID, &json(&config(&listener))).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");

        // Active and the same process, and nothing accepts on its port.
        let systemd = Fake::new();
        let host = self::host(&systemd, tmp.path());
        let (_held, config) = deaf();
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");
        let why = answer["error"].as_str().expect("why");
        assert!(why.contains("nothing accepts on the port"), "{why}");
        assert!(why.contains(&format!("{UNIT} is active")), "{why}");
    }

    #[test]
    fn a_changed_proxy_that_does_not_come_up_gets_its_config_from_before_back() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let before = config(&listener);
        super::apply(&host, ID, &json(&before)).expect("answers");
        let config_path = host.configs.join("bot-default.json");
        let kept = std::fs::read_to_string(&config_path).expect("config");
        systemd.asked();

        // The next config has it listen where nothing will answer.
        let (_held, moved) = deaf();
        let answer = super::apply(&host, ID, &json(&moved)).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");
        let why = answer["error"].as_str().expect("why");
        assert!(why.contains("nothing accepts on the port"), "{why}");
        assert!(
            why.contains(&format!(
                "the config and the unit from before are back, and {UNIT} is active"
            )),
            "{why}"
        );
        assert_eq!(std::fs::read_to_string(&config_path).expect("config"), kept);
        assert_eq!(
            systemd.asked(),
            [
                "daemon-reload".to_owned(),
                format!("enable --quiet {UNIT}"),
                format!("restart {UNIT}"),
                "daemon-reload".to_owned(),
                format!("restart {UNIT}")
            ],
            "restarted with the new config, then with the one from before, the unit files \
             read again before each"
        );
        // The proxy that runs now was started after the config from
        // before was written back: it is that config it runs.
        let status = super::status(&host, ID);
        assert_eq!(status["started"], "after_config", "{status}");
        let reported: WafConfig =
            serde_json::from_value(status["config"].clone()).expect("the config");
        assert_eq!(reported, before);

        // Nothing changed and it still does not run: left as it is.
        systemd.state.replace("failed".to_owned());
        systemd.after_start.replace("failed".to_owned());
        let answer = super::apply(&host, ID, &json(&before)).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");
        let why = answer["error"].as_str().expect("why");
        assert!(
            why.contains("its config and unit are as they were"),
            "{why}"
        );
        assert_eq!(std::fs::read_to_string(&config_path).expect("config"), kept);
    }

    #[test]
    fn removing_takes_the_unit_and_the_config_and_is_no_error_without_them() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let none = super::remove(&host, ID).expect("answers");
        assert_eq!(none["ok"], true, "{none}");
        assert_eq!(none["removed"], false, "{none}");
        assert!(systemd.asked().is_empty());

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        super::apply(&host, ID, &json(&config(&listener))).expect("answers");
        systemd.asked();
        assert_eq!(
            super::listen_port(&host, ID),
            Some(listener.local_addr().expect("address").port())
        );
        let gone = super::remove(&host, ID).expect("answers");
        assert_eq!(gone["ok"], true, "{gone}");
        assert_eq!(gone["removed"], true, "{gone}");
        assert_eq!(
            systemd.asked(),
            [
                format!("disable --now --quiet {UNIT}"),
                "daemon-reload".to_owned()
            ]
        );
        assert!(!host.configs.join("bot-default.json").exists());
        assert!(!host.units.join(UNIT).exists());
        assert_eq!(super::listen_port(&host, ID), None);
        assert_eq!(super::status(&host, ID), serde_json::Value::Null);

        // The note of an apply that did not finish goes with the rest.
        killed(&host, &systemd, &config(&listener), 1);
        let unfinished = host.configs.join("bot-default.applying");
        assert!(unfinished.exists() && host.units.join(UNIT).exists());
        let gone = super::remove(&host, ID).expect("answers");
        assert_eq!(gone["removed"], true, "{gone}");
        assert!(!unfinished.exists(), "the note is gone");
        assert_eq!(super::status(&host, ID), serde_json::Value::Null);
    }

    #[test]
    fn the_stats_are_read_only_as_a_small_regular_file_in_their_place() {
        use rustix::fs::{CWD, Mode, mkfifoat};
        let tmp = tempfile::tempdir().expect("tmp");
        let file = tmp.path().join("stats.json");
        // No file: the proxy has written none yet, and that is no error.
        assert_eq!(super::counted(&file), None);
        std::fs::write(&file, stats(SINCE, "12")).expect("stats");
        let read = super::counted(&file).expect("a file").expect("stats");
        assert_eq!((read.requests, read.since.as_str()), (12, SINCE));

        // What the proxy's user can put there instead. A link to stats
        // elsewhere, however well they read, is not followed.
        let elsewhere = tmp.path().join("elsewhere.json");
        std::fs::write(&elsewhere, stats(SINCE, "99")).expect("stats");
        std::fs::remove_file(&file).expect("removed");
        std::os::unix::fs::symlink(&elsewhere, &file).expect("link");
        assert_eq!(
            super::counted(&file),
            Some(Err("the WAF stats file could not be opened".to_owned()))
        );

        // A FIFO nobody writes to: an open or a read that waited would not
        // return.
        std::fs::remove_file(&file).expect("removed");
        mkfifoat(CWD, &file, Mode::RUSR | Mode::WUSR).expect("fifo");
        let (tx, rx) = std::sync::mpsc::channel();
        let fifo = file.clone();
        std::thread::spawn(move || {
            let said = super::counted(&fifo).and_then(Result::err);
            let _ = tx.send(said);
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).ok(),
            Some(Some("the WAF stats file is not a regular file".to_owned())),
            "a FIFO is not waited for"
        );

        std::fs::remove_file(&file).expect("removed");
        std::fs::create_dir(&file).expect("dir");
        assert_eq!(
            super::counted(&file),
            Some(Err("the WAF stats file is not a regular file".to_owned()))
        );
        std::fs::remove_dir(&file).expect("removed");

        // As much as is read, and one byte more, which no proxy writes:
        // the rest of a file of any size is never read.
        let most = usize::try_from(super::MAX_STATS_BYTES).expect("small");
        let good = stats(SINCE, "12");
        std::fs::write(&file, format!("{good}{}", " ".repeat(most - good.len()))).expect("stats");
        assert!(super::counted(&file).expect("a file").is_ok());
        std::fs::write(
            &file,
            format!("{good}{}", " ".repeat(most + 1 - good.len())),
        )
        .expect("stats");
        assert_eq!(
            super::counted(&file),
            Some(Err(
                "the WAF stats file is larger than 4096 bytes, which no proxy writes".to_owned()
            ))
        );
        let sparse = std::fs::File::create(&file).expect("create");
        sparse.set_len(512 * 1024 * 1024).expect("sparse");
        drop(sparse);
        assert!(super::counted(&file).expect("a file").is_err());

        std::fs::write(&file, [0xff_u8, 0xfe, b'{']).expect("stats");
        assert_eq!(
            super::counted(&file),
            Some(Err("the WAF stats are not valid: not UTF-8".to_owned()))
        );
    }

    #[test]
    fn nothing_in_the_stats_is_passed_on_but_a_time_and_counts_under_their_names() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        super::apply(&host, ID, &json(&config(&listener))).expect("answers");
        let file = host.stats_path(ID);
        std::fs::create_dir_all(file.parent().expect("its directory")).expect("run");
        let shown = |text: String| {
            std::fs::write(&file, text).expect("stats");
            super::status(&host, ID)
        };

        // A `since` that is not a time: nothing of the stats is shown, and
        // why says nothing of what was there.
        let status = shown(stats(ESCAPES_JSON, "12"));
        assert!(status["stats"].is_null(), "{status}");
        assert_eq!(
            status["stats_error"],
            "the WAF stats are not valid: `since` is not a time"
        );
        assert!(plain(&status), "{status}");
        // The same with the bytes themselves in the file.
        let status = shown(stats(ESCAPES, "12"));
        assert!(status["stats"].is_null() && plain(&status), "{status}");

        // A count that is not a number, and its text is not quoted back.
        let status = shown(stats(SINCE, &format!("\"{ESCAPES_JSON}\"")));
        assert!(status["stats"].is_null(), "{status}");
        assert_eq!(status["stats_error"], "the WAF stats are not valid");
        let status = shown(stats(SINCE, "-1"));
        assert_eq!(status["stats_error"], "the WAF stats are not valid");

        // A rule, or a field, the proxy does not count by is not passed
        // on, whatever it is called.
        let more = stats(SINCE, "12")
            .replace(
                "\"upgrade\":0",
                &format!("\"upgrade\":0,\"{ESCAPES_JSON}\":3,\"other\":\"x\""),
            )
            .replace(
                "\"banned_now\"",
                &format!("\"note\":\"{ESCAPES_JSON}\",\"banned_now\""),
            );
        let status = shown(more);
        assert_eq!(status["stats"]["requests"], 12, "{status}");
        assert!(plain(&status), "{status}");
        let rules: Vec<&String> = status["stats"]["blocked"]
            .as_object()
            .expect("the rules")
            .keys()
            .collect();
        assert_eq!(
            rules,
            [
                "banned",
                "body",
                "body_timeout",
                "connections",
                "denied",
                "malformed",
                "method",
                "not_allowed",
                "path",
                "probe",
                "rate",
                "upgrade"
            ]
        );
        assert!(status["stats"].get("note").is_none(), "{status}");
    }

    #[test]
    fn what_systemd_the_journal_and_the_config_say_is_passed_on_as_plain_text() {
        let tmp = tempfile::tempdir().expect("tmp");
        let mut systemd = Fake::new();
        // The proxy's journal is the proxy's to write.
        systemd.journal = vec![
            format!("could not listen{ESCAPES}"),
            format!("a long line {}", "x".repeat(1000)),
        ];
        let host = host(&systemd, tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        systemd.after_start.replace("activating".to_owned());
        let answer = super::apply(&host, ID, &json(&config)).expect("answers");
        assert_eq!(answer["ok"], false, "{answer}");
        assert!(plain(&answer), "{answer}");
        let why = answer["error"].as_str().expect("why");
        assert!(
            why.contains(
                "its journal ends: could not listen\\x1b]0;owned\\x07\\x1b[2J | a long line xxx"
            ),
            "{why}"
        );
        // 300 bytes of a line, and that it was cut.
        assert!(
            why.contains("x...; there was no WAF on this server before"),
            "{why}"
        );
        assert!(why.len() < 1200, "{} bytes", why.len());

        // A state that is not one of systemd's words is not said at all.
        systemd.after_start.replace("active".to_owned());
        super::apply(&host, ID, &json(&config)).expect("answers");
        systemd.state.replace(format!("active{ESCAPES}"));
        let status = super::status(&host, ID);
        assert_eq!(status["state"], "unknown", "{status}");
        assert_eq!(status["active"], false, "{status}");
        assert!(plain(&status), "{status}");

        // A config that does not read: why is said, bounded and plain,
        // whatever the file holds.
        std::fs::write(
            host.configs.join("bot-default.json"),
            format!("{{\"{ESCAPES_JSON}{}\":1}}", "k".repeat(2000)),
        )
        .expect("config");
        let status = super::status(&host, ID);
        let why = status["config_error"].as_str().expect("why");
        assert!(why.starts_with("the WAF config is not valid: "), "{why}");
        // 300 bytes of it, each written in four at most, and the mark of
        // the cut.
        assert!(why.len() <= 4 * 300 + 3 && why.ends_with("..."), "{why}");
        assert!(plain(&status), "{status}");
    }

    #[test]
    fn status_says_whether_it_runs_where_it_listens_and_what_it_counted() {
        let tmp = tempfile::tempdir().expect("tmp");
        let systemd = Fake::new();
        let host = host(&systemd, tmp.path());
        assert_eq!(super::status(&host, ID), serde_json::Value::Null);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = config(&listener);
        super::apply(&host, ID, &json(&config)).expect("answers");
        // Running, and nothing counted yet.
        let status = super::status(&host, ID);
        assert_eq!(status["active"], true, "{status}");
        assert_eq!(status["unit"], UNIT);
        assert_eq!(status["port"], config.listen.port());
        assert_eq!(status["listen"], config.listen.to_string());
        assert_eq!(status["upstream"], "127.0.0.1:3000");
        // The config, whole, as erpc reads it back, and that the proxy was
        // started after it was written.
        let in_force: WafConfig =
            serde_json::from_value(status["config"].clone()).expect("the config");
        assert_eq!(in_force, config);
        assert_eq!(status["started"], "after_config", "{status}");
        assert!(status["stats"].is_null() && status["stats_error"].is_null());

        // The stats are read where the proxy writes them.
        let file = host.stats_path(ID);
        assert_eq!(
            Host::server().stats_path(ID),
            Path::new(&server::waf_stats_path(ID))
        );
        std::fs::create_dir_all(file.parent().expect("its directory")).expect("run");
        std::fs::write(
            &file,
            r#"{"format":1,"since":"2026-11-11T09:00:00Z","requests":12,"forwarded":7,
            "blocked":{"method":1,"path":0,"denied":1,"not_allowed":0,"probe":2,"rate":0,
            "body":0,"malformed":0,"banned":1,"connections":0,"upgrade":0},"banned_now":1,
            "upstream_errors":0}"#,
        )
        .expect("stats");
        let status = super::status(&host, ID);
        assert_eq!(status["stats"]["requests"], 12, "{status}");
        assert_eq!(status["stats"]["blocked"]["probe"], 2, "{status}");
        assert_eq!(status["stats"]["banned_now"], 1, "{status}");
        assert_eq!(status["stats"]["since"], "2026-11-11T09:00:00Z");

        // Stats this version does not read are said, not shown.
        std::fs::write(&file, r#"{"format":2}"#).expect("stats");
        let status = super::status(&host, ID);
        assert!(status["stats"].is_null(), "{status}");
        assert!(
            status["stats_error"]
                .as_str()
                .is_some_and(|e| e.contains("not valid") || e.contains("format 2")),
            "{status}"
        );

        // A config written before `body_timeout_secs` was a key: it reads,
        // with the default, so the WAF's port is still known to the
        // firewall and the config is still reported.
        let before = json(&config).replace("\"body_timeout_secs\":30,", "");
        assert_ne!(before, json(&config));
        std::fs::write(host.configs.join("bot-default.json"), before).expect("config");
        assert_eq!(super::listen_port(&host, ID), Some(config.listen.port()));
        let status = super::status(&host, ID);
        assert_eq!(status["config"]["body_timeout_secs"], 30, "{status}");
        assert!(status["config_error"].is_null(), "{status}");

        // Stopped, and a config that no longer reads.
        systemd.state.replace("failed".to_owned());
        std::fs::write(host.configs.join("bot-default.json"), "{}").expect("config");
        let status = super::status(&host, ID);
        assert_eq!(status["active"], false, "{status}");
        assert_eq!(status["state"], "failed", "{status}");
        assert!(status["port"].is_null(), "{status}");
        assert!(status["config"].is_null(), "{status}");
        assert!(status["config_error"].as_str().is_some(), "{status}");
    }
}
