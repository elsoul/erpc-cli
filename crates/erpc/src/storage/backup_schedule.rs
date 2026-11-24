// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc backup schedule` and `erpc backup status`: `erpc backup run` on a
//! timer, and what the last run did.
//!
//! - Linux: a systemd service and timer in `/etc/systemd/system`, run as
//!   root, at the lowest CPU and I/O priority so a validator beside it is
//!   not slowed. A run missed while the machine was off runs when it is back
//!   (`Persistent=`). Its output goes to the journal.
//! - macOS: a launchd agent in `~/Library/LaunchAgents`, run as the person
//!   who scheduled it, writing to `~/.erpc/state/backup.log`.
//!
//! The unit files hold no secret: the run reads this machine's credentials
//! from `backup.env`, as it does by hand.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::commands::Outcome;
use crate::error::{CliError, Code};

/// How often a scheduled backup runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Every {
    /// Every day.
    Daily,
    /// Every Sunday.
    Weekly,
    /// No more scheduled backups.
    Off,
}

/// The name of the systemd units and the launchd job.
const UNIT: &str = "erpc-backup";
const LABEL: &str = "global.erpc.backup";
const SYSTEMD_DIR: &str = "/etc/systemd/system";

/// What a scheduled run does.
pub struct Plan {
    /// The erpc program the timer runs.
    pub program: PathBuf,
    /// When, as hour and minute.
    pub at: (u8, u8),
    /// Daily or weekly.
    pub every: Every,
    /// What to back up; empty means the default.
    pub paths: Vec<PathBuf>,
    /// What else to leave out.
    pub exclude: Vec<String>,
    /// Where erpc's state is: the home directory, and `ERPC_HOME` if set.
    pub home: PathBuf,
    /// `ERPC_HOME`, when it is set.
    pub erpc_home: Option<PathBuf>,
}

/// `HH:MM`, 24-hour.
///
/// # Errors
///
/// When it is not a time of day.
pub fn parse_at(text: &str) -> Result<(u8, u8), String> {
    let bad = || format!("--at {text:?} is not a time of day such as 03:00");
    let (h, m) = text.split_once(':').ok_or_else(bad)?;
    let h: u8 = h.parse().map_err(|_| bad())?;
    let m: u8 = m.parse().map_err(|_| bad())?;
    if h > 23 || m > 59 {
        return Err(bad());
    }
    Ok((h, m))
}

/// The arguments after the program: `backup run`, the excludes, the paths.
fn run_args(plan: &Plan) -> Vec<String> {
    let mut args = vec!["backup".to_owned(), "run".to_owned()];
    for e in &plan.exclude {
        args.push("--exclude".to_owned());
        args.push(e.clone());
    }
    if !plan.paths.is_empty() {
        args.push("--".to_owned());
        args.extend(plan.paths.iter().map(|p| p.display().to_string()));
    }
    args
}

/// One word of a systemd command line, quoted.
fn systemd_word(word: &str) -> String {
    let mut out = String::from("\"");
    for c in word.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The service and the timer, as systemd reads them.
#[must_use]
pub fn systemd_units(plan: &Plan) -> (String, String) {
    let mut exec = systemd_word(&plan.program.display().to_string());
    for a in run_args(plan) {
        exec.push(' ');
        exec.push_str(&systemd_word(&a));
    }
    let mut env = format!(
        "Environment={}\n",
        systemd_word(&format!("HOME={}", plan.home.display()))
    );
    if let Some(erpc_home) = &plan.erpc_home {
        let _ = writeln!(
            env,
            "Environment={}",
            systemd_word(&format!("ERPC_HOME={}", erpc_home.display()))
        );
    }
    let service = format!(
        "# Written by `erpc backup schedule`; `erpc backup schedule off` removes it.\n\
         [Unit]\n\
         Description=erpc backup\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         User=root\n\
         {env}\
         ExecStart={exec}\n\
         Nice=19\n\
         CPUSchedulingPolicy=batch\n\
         IOSchedulingClass=idle\n"
    );
    let calendar = match plan.every {
        Every::Weekly => format!("Sun *-*-* {:02}:{:02}:00", plan.at.0, plan.at.1),
        _ => format!("*-*-* {:02}:{:02}:00", plan.at.0, plan.at.1),
    };
    let timer = format!(
        "# Written by `erpc backup schedule`; `erpc backup schedule off` removes it.\n\
         [Unit]\n\
         Description=erpc backup, {}\n\
         \n\
         [Timer]\n\
         OnCalendar={calendar}\n\
         RandomizedDelaySec=30min\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n",
        if plan.every == Every::Weekly {
            "weekly"
        } else {
            "daily"
        }
    );
    (service, timer)
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The launchd job, as a property list.
#[must_use]
pub fn launchd_plist(plan: &Plan, log: &Path) -> String {
    let mut args = format!(
        "    <string>{}</string>\n",
        xml(&plan.program.display().to_string())
    );
    for a in run_args(plan) {
        let _ = writeln!(args, "    <string>{}</string>", xml(&a));
    }
    let weekday = if plan.every == Every::Weekly {
        "    <key>Weekday</key><integer>0</integer>\n"
    } else {
        ""
    };
    let mut env = format!(
        "    <key>HOME</key><string>{}</string>\n",
        xml(&plan.home.display().to_string())
    );
    if let Some(erpc_home) = &plan.erpc_home {
        let _ = writeln!(
            env,
            "    <key>ERPC_HOME</key><string>{}</string>",
            xml(&erpc_home.display().to_string())
        );
    }
    let log = xml(&log.display().to_string());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!-- Written by `erpc backup schedule`; `erpc backup schedule off` removes it. -->\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20 <key>Label</key><string>{LABEL}</string>\n\
         \x20 <key>ProgramArguments</key>\n\
         \x20 <array>\n{args}  </array>\n\
         \x20 <key>StartCalendarInterval</key>\n\
         \x20 <dict>\n\
         \x20   <key>Hour</key><integer>{}</integer>\n\
         \x20   <key>Minute</key><integer>{}</integer>\n\
         {weekday}  </dict>\n\
         \x20 <key>EnvironmentVariables</key>\n\
         \x20 <dict>\n{env}  </dict>\n\
         \x20 <key>StandardOutPath</key><string>{log}</string>\n\
         \x20 <key>StandardErrorPath</key><string>{log}</string>\n\
         \x20 <key>ProcessType</key><string>Background</string>\n\
         \x20 <key>LowPriorityIO</key><true/>\n\
         \x20 <key>Nice</key><integer>10</integer>\n\
         </dict>\n\
         </plist>\n",
        plan.at.0, plan.at.1
    )
}

/// Writes `text` to `path` through a temporary file beside it.
fn put(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write as _;
    let dir = path.parent().ok_or("no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("could not make {}: {e}", dir.display()))?;
    let mut file = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("could not write in {}: {e}", dir.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.as_file().sync_all())
        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("could not set the mode of {}: {e}", path.display()))?;
    }
    file.persist(path)
        .map_err(|e| format!("could not keep {}: {}", path.display(), e.error))?;
    Ok(())
}

/// Runs a system tool and says why it failed.
fn tool(program: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            crate::storage::clean(String::from_utf8_lossy(&out.stderr).trim())
        ))
    }
}

/// This process's user id.
fn uid() -> Result<String, String> {
    tool("/usr/bin/id", &["-u"])
}

fn launchd_path() -> Result<PathBuf, String> {
    let home = std::env::home_dir().ok_or("no home directory")?;
    Ok(home.join(format!("Library/LaunchAgents/{LABEL}.plist")))
}

fn log_path() -> Result<PathBuf, String> {
    Ok(crate::session::state_dir()?.join("backup.log"))
}

/// Installs, replaces or removes the schedule. Says what it did.
///
/// # Errors
///
/// When the platform has no scheduler erpc knows, the user may not install
/// one, or a file or tool fails.
pub fn apply(plan: &Plan) -> Result<String, CliError> {
    if cfg!(target_os = "linux") {
        apply_systemd(plan)
    } else if cfg!(target_os = "macos") {
        apply_launchd(plan)
    } else {
        Err(CliError::new(
            Code::Failed,
            "erpc backup schedule knows systemd and launchd only",
        ))
    }
}

/// Whether only root can change `program`: it and every directory above
/// it are root's and writable by no one else. The timer runs it as root
/// every day, so a program a user could replace would be that user's way
/// to root.
#[cfg(unix)]
fn root_only(program: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let mut at = Some(program);
    while let Some(path) = at {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{} can be changed by someone other than root",
                path.display()
            ));
        }
        at = path.parent();
    }
    Ok(())
}

/// What the timer runs or reads as root: erpc, and in erpc's directory the
/// pinned restic and this machine's credentials. A user who could change
/// any of them could choose what root runs, or with which credentials.
fn root_paths(plan: &Plan) -> Result<Vec<PathBuf>, String> {
    let config = crate::session::beside_config("")?;
    Ok(vec![
        plan.program.clone(),
        crate::restic::program_path()?,
        config.join("backup.env"),
    ])
}

#[cfg(not(unix))]
fn root_only(_program: &Path) -> Result<(), String> {
    Err("a root schedule needs a Unix system".to_owned())
}

fn apply_systemd(plan: &Plan) -> Result<String, CliError> {
    if uid()? != "0" {
        return Err(
            CliError::new(Code::Failed, "a backup schedule is set up as root")
                .hint("run `sudo erpc backup init`, then `sudo erpc backup schedule daily`"),
        );
    }
    if plan.every != Every::Off
        && let Err(e) =
            root_paths(plan).and_then(|paths| paths.iter().try_for_each(|p| root_only(p)))
    {
        return Err(CliError::new(
            Code::Failed,
            format!("the timer would run erpc as root, and {e}"),
        )
        .hint(
            "install erpc where only root can write, for example \
             `sudo install -m 0755 ~/.erpc/bin/erpc /usr/local/bin/erpc`, \
             then run `sudo /usr/local/bin/erpc backup schedule daily`",
        ));
    }
    let dir = Path::new(SYSTEMD_DIR);
    let service = dir.join(format!("{UNIT}.service"));
    let timer = dir.join(format!("{UNIT}.timer"));
    let systemctl = "/usr/bin/systemctl";
    if plan.every == Every::Off {
        let _ = tool(systemctl, &["disable", "--now", &format!("{UNIT}.timer")]);
        for path in [&timer, &service] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("could not remove {}: {e}", path.display()).into()),
            }
        }
        tool(systemctl, &["daemon-reload"])?;
        return Ok("Scheduled backups are off.".to_owned());
    }
    let (service_text, timer_text) = systemd_units(plan);
    put(&service, &service_text)?;
    put(&timer, &timer_text)?;
    tool(systemctl, &["daemon-reload"])?;
    tool(systemctl, &["enable", "--now", &format!("{UNIT}.timer")])?;
    Ok(format!(
        "Backups run {} at {:02}:{:02} (within 30 minutes after), as root.\n  timer   {}\n  log     journalctl -u {UNIT}.service",
        if plan.every == Every::Weekly {
            "every Sunday"
        } else {
            "every day"
        },
        plan.at.0,
        plan.at.1,
        timer.display()
    ))
}

fn apply_launchd(plan: &Plan) -> Result<String, CliError> {
    let path = launchd_path()?;
    let domain = format!("gui/{}", uid()?);
    let _ = tool("/bin/launchctl", &["bootout", &format!("{domain}/{LABEL}")]);
    if plan.every == Every::Off {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("could not remove {}: {e}", path.display()).into()),
        }
        return Ok("Scheduled backups are off.".to_owned());
    }
    let log = log_path()?;
    put(&path, &launchd_plist(plan, &log))?;
    let display = path.display().to_string();
    tool("/bin/launchctl", &["bootstrap", &domain, &display])?;
    Ok(format!(
        "Backups run {} at {:02}:{:02}, as you, while you are signed in.\n  job     {}\n  log     {}",
        if plan.every == Every::Weekly {
            "every Sunday"
        } else {
            "every day"
        },
        plan.at.0,
        plan.at.1,
        path.display(),
        log.display()
    ))
}

/// The schedule installed now, as the line it was written with.
fn installed() -> Option<String> {
    if cfg!(target_os = "linux") {
        let timer = std::fs::read_to_string(format!("{SYSTEMD_DIR}/{UNIT}.timer")).ok()?;
        timer
            .lines()
            .find_map(|l| l.strip_prefix("OnCalendar="))
            .map(|c| format!("systemd timer, OnCalendar={c}"))
    } else {
        let plist = std::fs::read_to_string(launchd_path().ok()?).ok()?;
        let number = |key: &str| {
            let at = plist.find(&format!("<key>{key}</key><integer>"))?;
            let rest = &plist[at + key.len() + 20..];
            rest.split('<').next().map(ToOwned::to_owned)
        };
        let (h, m) = (number("Hour")?, number("Minute")?);
        let h: u8 = h.parse().ok()?;
        let m: u8 = m.parse().ok()?;
        let when = if number("Weekday").is_some() {
            "every Sunday"
        } else {
            "every day"
        };
        Some(format!("launchd, {when} at {h:02}:{m:02}"))
    }
}

/// Where the last run's result is kept.
fn last_path() -> Result<PathBuf, String> {
    Ok(crate::session::state_dir()?.join("backup-last.json"))
}

/// Keeps what a run did, for `erpc backup status`. A failure to keep it is
/// not the backup's failure, so it is only said.
pub fn record(host: &str, code: i32) {
    let value = json!({ "host": host, "at": crate::commands::now(), "exit": code });
    if let Err(e) = last_path().and_then(|p| put(&p, &value.to_string())) {
        crate::interrupt::say(&format!("(the result of this run was not kept: {e})"));
    }
}

/// `YYYY-MM-DD HH:MM UTC` for Unix seconds.
fn utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let secs = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    )
}

/// `erpc backup status`.
#[must_use]
pub fn status(json: bool) -> Outcome {
    let schedule = installed();
    let last: Option<Value> = last_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str(&t).ok());
    if json {
        crate::print_json(&json!({ "schedule": schedule, "lastRun": last }));
        return Outcome::Done(String::new());
    }
    let mut out = format!(
        "Schedule   {}\n",
        schedule
            .as_deref()
            .unwrap_or("none (`erpc backup schedule daily`)")
    );
    match last {
        Some(last) => {
            let at = last["at"].as_i64().map_or_else(|| "?".to_owned(), utc);
            let outcome = match last["exit"].as_i64() {
                Some(0) => "succeeded".to_owned(),
                Some(3) => "succeeded, without some files it could not read".to_owned(),
                Some(code) => format!("failed (restic exit {code})"),
                None => "unknown".to_owned(),
            };
            let _ = write!(out, "Last run   {at}, {outcome}");
        }
        None => out.push_str("Last run   none on this machine yet"),
    }
    Outcome::Done(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(every: Every, paths: &[&str]) -> Plan {
        Plan {
            program: PathBuf::from("/usr/local/bin/erpc"),
            at: (3, 5),
            every,
            paths: paths.iter().map(PathBuf::from).collect(),
            exclude: vec!["/srv/cache/*".to_owned()],
            home: PathBuf::from("/root"),
            erpc_home: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_program_others_can_change_is_not_run_as_root() {
        let dir = tempfile::tempdir().expect("dir");
        let program = dir.path().join("erpc");
        std::fs::write(&program, b"x").expect("write");
        // A user's own file is not root's, whoever runs the test.
        let is_root = std::fs::metadata("/").is_ok_and(|_| {
            std::process::Command::new("/usr/bin/id")
                .arg("-u")
                .output()
                .is_ok_and(|o| o.stdout.starts_with(b"0"))
        });
        if !is_root {
            assert!(root_only(&program).is_err());
        }
        assert!(root_only(Path::new("/no/such/erpc")).is_err());
        // A state directory a user owns, under the root one erpc found.
        let state = dir.path().join(".erpc");
        std::fs::create_dir_all(state.join("bin")).expect("mkdir");
        std::fs::write(state.join("backup.env"), b"x").expect("write");
        if !is_root {
            assert!(root_only(&state.join("backup.env")).is_err());
        }
        let paths = root_paths(&plan(Every::Daily, &[])).expect("paths");
        assert_eq!(paths[0], PathBuf::from("/usr/local/bin/erpc"));
        assert!(paths[1].ends_with(format!("bin/restic-{}", crate::restic::VERSION)));
        assert!(paths[2].ends_with("backup.env"));
    }

    #[test]
    fn a_time_of_day_is_hours_and_minutes() {
        assert_eq!(parse_at("03:00"), Ok((3, 0)));
        assert_eq!(parse_at("23:59"), Ok((23, 59)));
        for bad in ["24:00", "3", "03:60", "x:y", ""] {
            assert!(parse_at(bad).is_err(), "{bad} was taken");
        }
    }

    #[test]
    fn the_timer_runs_at_the_hour_asked_and_catches_up() {
        let (service, timer) = systemd_units(&plan(Every::Daily, &[]));
        assert!(timer.contains("OnCalendar=*-*-* 03:05:00\n"));
        assert!(timer.contains("Persistent=true\n"));
        assert!(service.contains(
            "ExecStart=\"/usr/local/bin/erpc\" \"backup\" \"run\" \"--exclude\" \"/srv/cache/*\"\n"
        ));
        assert!(service.contains("IOSchedulingClass=idle\n"));
        assert!(service.contains("Environment=\"HOME=/root\"\n"));
        let (_, weekly) = systemd_units(&plan(Every::Weekly, &["/srv"]));
        assert!(weekly.contains("OnCalendar=Sun *-*-* 03:05:00\n"));
    }

    #[test]
    fn a_path_cannot_break_out_of_its_word() {
        let (service, _) =
            systemd_units(&plan(Every::Daily, &["/a\" ; rm -rf / \"", "/100%$HOME"]));
        assert!(service.contains("\"--\" \"/a\\\" ; rm -rf / \\\"\" \"/100%%$$HOME\""));
        let plist = launchd_plist(
            &plan(Every::Daily, &["/a</string><string>x"]),
            Path::new("/l"),
        );
        assert!(plist.contains("<string>/a&lt;/string&gt;&lt;string&gt;x</string>"));
    }

    #[test]
    fn the_launchd_job_runs_at_the_hour_asked() {
        let plist = launchd_plist(
            &plan(Every::Weekly, &["/home/operator/Documents"]),
            Path::new("/home/operator/.erpc/state/backup.log"),
        );
        assert!(plist.contains("<key>Hour</key><integer>3</integer>"));
        assert!(plist.contains("<key>Minute</key><integer>5</integer>"));
        assert!(plist.contains("<key>Weekday</key><integer>0</integer>"));
        assert!(
            plist.contains("<string>--</string>\n    <string>/home/operator/Documents</string>")
        );
        assert!(!plist.contains("http"), "a URL in the plist");
        let daily = launchd_plist(&plan(Every::Daily, &["/d"]), Path::new("/l"));
        assert!(!daily.contains("Weekday"));
    }

    #[test]
    fn unix_seconds_read_as_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_793_305_200), "2026-10-29 20:20 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
    }
}
