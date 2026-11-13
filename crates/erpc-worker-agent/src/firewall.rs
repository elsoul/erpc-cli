// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The server's worker firewall, as `ctl` changes it (run as root).
//!
//! One table for the server, `inet erpc_worker`, dropping every inbound
//! connection it does not name ([`erpc_worker::server::firewall_table`]).
//! It is made from one opening per worker, kept in
//! `/etc/erpc/worker-firewall/workers/<id>.json`, so the workers on a
//! server share it and each changes only its own part.
//!
//! A change that may lock erpc out goes in two steps, as the SSH allow list
//! does. `firewall-apply` loads the new table after keeping the one in
//! force, and arms a timer that loads the kept one again after
//! [`erpc_worker::server::FIREWALL_ROLLBACK_SECONDS`]. Only
//! `firewall-confirm`, run over a fresh connection -- which proves the new
//! table lets erpc in -- disarms it, keeps the new opening, and loads the
//! table at boot. A worker's removal only closes its port, so it is applied
//! at once.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use erpc_worker::server::{
    FIREWALL_DIR, FIREWALL_ROLLBACK_SECONDS, FirewallRequest, Opening, firewall_table,
};
use serde_json::{Value, json};

use crate::wafctl;

const ROLLBACK_UNIT: &str = "erpc-worker-firewall-rollback";
const BOOT_UNIT: &str = "erpc-worker-firewall.service";

/// Where `confirm` moves the pending change it takes.
const CONFIRMING: &str = "confirming.json";
/// Where the rollback moves the pending change it takes.
const ROLLED_BACK: &str = "rolled-back.json";

fn dir() -> PathBuf {
    PathBuf::from(FIREWALL_DIR)
}

/// What a firewall change runs on the server: `nft`, `systemctl` and
/// `systemd-run`.
pub(crate) trait Tools {
    /// Runs `program` with `args`: what it printed, or why it failed.
    fn run(&self, program: &str, args: &[&str]) -> Result<String, String>;
    /// Whether the rollback timer of a change not yet confirmed is waiting.
    fn armed(&self) -> Result<bool, String>;
}

/// The server's own.
struct Real;

impl Tools for Real {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, String> {
        run(program, args)
    }

    fn armed(&self) -> Result<bool, String> {
        armed()
    }
}

/// A server, as far as `firewall-apply` is concerned: where the firewall's
/// files are, what it runs, and where the workers' WAFs are, so that the
/// tests apply a change to a directory with tools that write down what
/// they were asked.
pub(crate) struct Host<'a> {
    /// What it runs.
    pub(crate) tools: &'a dyn Tools,
    /// Where the firewall's files are ([`FIREWALL_DIR`]).
    pub(crate) dir: PathBuf,
    /// The server's WAFs: the port a worker's listens on is the one port
    /// that may be opened to everyone.
    pub(crate) waf: wafctl::Host<'a>,
}

impl Host<'static> {
    /// The server this runs on.
    pub(crate) fn server() -> Self {
        Self {
            tools: &Real,
            dir: dir(),
            waf: wafctl::Host::server(),
        }
    }
}

/// What the rollback timer runs: take the pending change, and only then
/// put the previous table back.
fn rollback_command(d: &Path) -> String {
    let quoted = |name: &str| format!("'{}'", d.join(name).display());
    format!(
        "mv {} {} && /usr/sbin/nft -f {}",
        quoted("pending.json"),
        quoted(ROLLED_BACK),
        quoted("previous.nft")
    )
}

/// Holds the server's firewall lock while a firewall verb runs: two
/// workers deploying at once take turns.
fn lock(d: &Path) -> Result<std::fs::File, String> {
    std::fs::create_dir_all(d).map_err(|e| format!("could not make {}: {e}", d.display()))?;
    let file = std::fs::File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(d.join(".lock"))
        .map_err(|e| format!("could not open the firewall lock: {e}"))?;
    file.lock()
        .map_err(|e| format!("could not take the firewall lock: {e}"))?;
    Ok(file)
}

/// Whether the rollback timer of a change not yet confirmed is waiting.
/// It is gone once it has fired, and after a restart: either way the
/// change it guards is no longer in force.
fn armed() -> Result<bool, String> {
    let out = Command::new("systemctl")
        .args(["is-active", &format!("{ROLLBACK_UNIT}.timer")])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run systemctl: {e}"))?;
    timer_state(&String::from_utf8_lossy(&out.stdout))
}

/// What `systemctl is-active` printed, as armed or not. Anything else
/// (systemd not answering) is an error, never "not armed": taken for one,
/// it would let a change be kept or dropped while its timer still runs.
fn timer_state(stdout: &str) -> Result<bool, String> {
    match stdout.lines().next().map(str::trim) {
        Some("active" | "activating" | "reloading") => Ok(true),
        Some("inactive" | "failed" | "dead") => Ok(false),
        other => Err(format!(
            "could not tell whether the firewall's rollback timer is waiting (systemctl said {})",
            other.filter(|o| !o.is_empty()).unwrap_or("nothing")
        )),
    }
}

/// Moves a change that is no longer in force out of the way, as the
/// rollback itself does, rather than deleting it.
fn set_aside(d: &Path) {
    let _ = std::fs::rename(d.join("pending.json"), d.join(ROLLED_BACK));
}

/// Refuses while another change waits to be confirmed: its table and the
/// one it would go back to were made from the openings as they were.
fn refuse_while_waiting(
    d: &Path,
    armed: impl FnOnce() -> Result<bool, String>,
) -> Result<(), String> {
    if !d.join("pending.json").exists() {
        return Ok(());
    }
    if armed()? {
        return Err(format!(
            "another firewall change on this server is waiting to be confirmed; try again in \
             {FIREWALL_ROLLBACK_SECONDS} seconds"
        ));
    }
    set_aside(d);
    Ok(())
}

/// The pending change, taken for `confirm` by one rename, or `None` when
/// there is none to take: the rollback took it, or nothing was applied.
fn claim(d: &Path) -> Option<String> {
    std::fs::rename(d.join("pending.json"), d.join(CONFIRMING)).ok()?;
    std::fs::read_to_string(d.join(CONFIRMING)).ok()
}

fn rolled_back() -> Value {
    json!({ "ok": false, "firewall": "rolled_back",
        "error": "the change is not in force: the rollback put the previous firewall back, or \
                  the server restarted before it was confirmed" })
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, text)
        .and_then(|()| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)))
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("could not write {}: {e}", path.display())
        })
}

/// The openings kept in `d`, by worker; `candidate` in place of its
/// worker's.
fn openings(
    d: &Path,
    candidate: Option<(&str, Option<&Opening>)>,
) -> Result<BTreeMap<String, Opening>, String> {
    let mut all = BTreeMap::new();
    let workers = d.join("workers");
    if let Ok(entries) = std::fs::read_dir(&workers) {
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if !erpc_worker::server::is_unit_id(id) {
                continue;
            }
            let text = std::fs::read_to_string(entry.path())
                .map_err(|e| format!("could not read {name}: {e}"))?;
            let opening: Opening = serde_json::from_str(&text)
                .map_err(|e| format!("{name} is not an opening: {e}"))?;
            all.insert(id.to_owned(), opening);
        }
    }
    if let Some((id, opening)) = candidate {
        match opening {
            Some(o) => {
                all.insert(id.to_owned(), o.clone());
            }
            None => {
                all.remove(id);
            }
        }
    }
    Ok(all)
}

/// Checks `table` with `nft -c`, then loads it.
fn load(tools: &dyn Tools, table: &str, path: &Path) -> Result<(), String> {
    write(path, table)?;
    let path = path.to_string_lossy();
    tools.run("nft", &["-c", "-f", &path])?;
    tools.run("nft", &["-f", &path]).map(|_| ())
}

/// Why `opening` is not one a server takes, whatever is in force there,
/// when it is not: its port, how many addresses it names, its limit's
/// numbers.
fn refuse_shape(opening: &Opening, ssh_port: u16) -> Result<(), String> {
    let o = opening;
    if o.port == 0 || o.port == ssh_port || o.allow.is_empty() || o.allow.len() > 64 {
        return Err("an opening is a port other than SSH's, for 1 to 64 addresses".to_owned());
    }
    if let Some(problem) = o
        .limit
        .and_then(|limit| limit.problems().into_iter().next())
    {
        return Err(format!("the opening's limit on new connections: {problem}"));
    }
    Ok(())
}

/// The refusal for an opening that names "everyone" on a port that is not
/// the one the worker's WAF listens on (`waf_port`: none when the worker
/// has no WAF, or one whose config does not read): only a WAF's port may
/// be open to everyone. None for any other opening: an app's own port is
/// open to the addresses it names, as it always was.
fn refuse_everyone(opening: &Opening, waf_port: Option<u16>) -> Option<String> {
    let everyone = opening.allow.iter().find(|c| c.is_everyone())?;
    (waf_port != Some(opening.port)).then(|| {
        format!(
            "{everyone} is every address, and port {} is not the one this worker's WAF listens \
             on; only a WAF's port is opened to everyone",
            opening.port
        )
    })
}

/// Whether `opening` lets in nobody that `in_force`, the worker's opening
/// in force, does not: the same port, with the same limit on new
/// connections, to addresses that are each, as written, among the ones in
/// force. Applying it makes nothing wider than it is.
fn within(opening: &Opening, in_force: Option<&Opening>) -> bool {
    in_force.is_some_and(|now| {
        opening.port == now.port
            && opening.limit == now.limit
            && opening.allow.iter().all(|a| now.allow.contains(a))
    })
}

/// `firewall-apply`: this worker's opening (stdin) applied to the table,
/// under the rollback timer.
pub(crate) fn apply(id: &str) -> Result<Value, String> {
    let mut input = String::new();
    std::io::stdin()
        .lock()
        .take(64 * 1024)
        .read_to_string(&mut input)
        .map_err(|e| format!("could not read standard input: {e}"))?;
    apply_to(&Host::server(), id, &input)
}

/// [`apply`] on `host`, with the request `input`. The opening is checked
/// ([`refuse_shape`], [`refuse_everyone`]) before the lock is taken, a
/// file written or a tool run: whatever erpc sent, this is where
/// "everyone" is refused to a port that is not the one the worker's WAF
/// listens on.
///
/// With one exception, looked at once the lock is held: an opening that
/// lets in nobody the worker's opening in force does not ([`within`]) is
/// applied whatever the WAF's config reads as. It makes nothing wider,
/// and it is what erpc asks of a server whose WAF's config does not read
/// (an agent installed since does not take the file, say) while its port
/// is open to everyone: the opening in force, again, on the way to the
/// `waf-apply` that writes a config that reads. Refused, a deploy could
/// not get that far until the port had been closed.
fn apply_to(host: &Host<'_>, id: &str, input: &str) -> Result<Value, String> {
    let request: FirewallRequest =
        serde_json::from_str(input.trim()).map_err(|e| format!("not a firewall request: {e}"))?;
    if request.ssh_port == 0 {
        return Err("0 is not the SSH port".to_owned());
    }
    let (d, tools) = (&host.dir, host.tools);
    // The refusal of everyone on a port that is not known to be the
    // WAF's, kept for under the lock where the worker has an opening in
    // force that this one may be within. Without one it is refused here.
    let mut everyone = None;
    if let Some(o) = &request.opening {
        refuse_shape(o, request.ssh_port)?;
        if let Some(refused) = refuse_everyone(o, wafctl::listen_port(&host.waf, id)) {
            if !d.join("workers").join(format!("{id}.json")).exists() {
                return Err(refused);
            }
            everyone = Some(refused);
        }
    }
    let _lock = lock(d)?;
    std::fs::create_dir_all(d.join("workers"))
        .map_err(|e| format!("could not make {}: {e}", d.display()))?;
    // Another worker's change, not yet confirmed, has its own timer:
    // stopping it would keep a table nobody proved lets erpc in.
    refuse_while_waiting(d, || tools.armed())?;
    if let (Some(refused), Some(o)) = (everyone, &request.opening)
        && !within(o, openings(d, None)?.get(id))
    {
        return Err(refused);
    }
    let all = openings(d, Some((id, request.opening.as_ref())))?;
    let table = firewall_table(request.ssh_port, &all);
    let _ = tools.run("systemctl", &["stop", &format!("{ROLLBACK_UNIT}.timer")]);
    // What is in force now is what the timer goes back to.
    let previous = std::fs::read_to_string(d.join("applied.nft"))
        .unwrap_or_else(|_| "table inet erpc_worker\ndelete table inet erpc_worker\n".to_owned());
    write(&d.join("previous.nft"), &previous)?;
    let pending = serde_json::to_string(&json!({
        "id": id,
        "ssh_port": request.ssh_port,
        "opening": request.opening,
    }))
    .map_err(|e| e.to_string())?;
    write(&d.join("pending.json"), &pending)?;
    let _ = std::fs::remove_file(d.join(ROLLED_BACK));
    let _ = std::fs::remove_file(d.join(CONFIRMING));
    // The timer puts the previous table back only if it takes the pending
    // change first, by a rename `confirm` races for: one of them wins.
    let rollback = rollback_command(d);
    tools.run(
        "systemd-run",
        &[
            "--quiet",
            "--collect",
            &format!("--unit={ROLLBACK_UNIT}"),
            &format!("--on-active={FIREWALL_ROLLBACK_SECONDS}"),
            "/bin/sh",
            "-c",
            &rollback,
        ],
    )?;
    if let Err(e) = load(tools, &table, &d.join("pending.nft")) {
        let _ = tools.run("systemctl", &["stop", &format!("{ROLLBACK_UNIT}.timer")]);
        return Err(e);
    }
    Ok(json!({ "ok": true, "firewall": "applied", "rollback_seconds": FIREWALL_ROLLBACK_SECONDS }))
}

/// `firewall-confirm`: keeps what `firewall-apply` loaded, when its timer
/// has not run out.
pub(crate) fn confirm() -> Result<Value, String> {
    let d = dir();
    let _lock = lock(&d)?;
    // No timer means the change is not in force: the rollback ran, or the
    // server restarted and loaded the table kept before it. Checked before
    // the change is taken, so a timer that fires in between takes it
    // first, and confirm reports that.
    if !armed()? {
        set_aside(&d);
        return Ok(rolled_back());
    }
    let Some(pending) = claim(&d) else {
        return Ok(rolled_back());
    };
    // The change is this command's now: the timer, if it fires, finds
    // nothing to take and leaves the table alone.
    let _ = run("systemctl", &["stop", &format!("{ROLLBACK_UNIT}.timer")]);
    let pending: Value = serde_json::from_str(&pending).map_err(|e| e.to_string())?;
    let id = pending["id"].as_str().unwrap_or_default();
    if !erpc_worker::server::is_unit_id(id) {
        return Err("the pending change names no worker".to_owned());
    }
    let opening_path = d.join("workers").join(format!("{id}.json"));
    match pending.get("opening").filter(|o| !o.is_null()) {
        Some(opening) => write(&opening_path, &opening.to_string())?,
        None => {
            let _ = std::fs::remove_file(&opening_path);
        }
    }
    std::fs::rename(d.join("pending.nft"), d.join("applied.nft"))
        .map_err(|e| format!("could not keep the table: {e}"))?;
    let _ = std::fs::remove_file(d.join(CONFIRMING));
    boot_unit()?;
    Ok(json!({ "ok": true, "firewall": "confirmed" }))
}

/// Loads the kept table at boot, after nftables' own rules.
fn boot_unit() -> Result<(), String> {
    let unit = format!(
        "# Written by erpc worker. Loads the worker firewall at boot.\n\
         [Unit]\n\
         Description=erpc worker firewall\n\
         DefaultDependencies=no\n\
         After=nftables.service\n\
         Wants=network-pre.target\n\
         Before=network-pre.target shutdown.target\n\
         Conflicts=shutdown.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         ExecStart=/usr/sbin/nft -f {FIREWALL_DIR}/applied.nft\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    let path = PathBuf::from("/etc/systemd/system").join(BOOT_UNIT);
    if std::fs::read_to_string(&path).ok().as_deref() != Some(unit.as_str()) {
        write(&path, &unit)?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        run("systemctl", &["daemon-reload"])?;
    }
    run("systemctl", &["enable", "--quiet", BOOT_UNIT]).map(|_| ())
}

/// The firewall held for closing a worker's port: taken by `remove` before
/// it takes the worker down and kept until the port is closed, so no other
/// change can come in between, and a refusal leaves the worker as it was.
pub(crate) struct Held {
    // Held, not read: the lock lasts as long as this does.
    _lock: std::fs::File,
}

/// Takes the firewall for [`close`], refused while another worker's change
/// waits to be confirmed: that change has this worker's opening in both
/// its tables, so either its confirm or its rollback would open the port
/// again.
pub(crate) fn hold() -> Result<Held, String> {
    let d = dir();
    let file = lock(&d)?;
    refuse_while_waiting(&d, armed)?;
    Ok(Held { _lock: file })
}

/// Closes `id`'s port at once (it cannot lock anyone out), with the
/// firewall held. Nothing to do when the server has no worker firewall.
pub(crate) fn close(id: &str, _held: &Held) -> Result<Value, String> {
    let d = dir();
    let opening_path = d.join("workers").join(format!("{id}.json"));
    if !d.join("applied.nft").exists() {
        let _ = std::fs::remove_file(&opening_path);
        return Ok(json!("none"));
    }
    let ssh_port = std::fs::read_to_string(d.join("applied.nft"))
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("tcp dport ")
                    .and_then(|r| r.strip_suffix(" accept"))
                    .and_then(|p| p.parse::<u16>().ok())
            })
        })
        .unwrap_or(22);
    let all = openings(&d, Some((id, None)))?;
    load(&Real, &firewall_table(ssh_port, &all), &d.join("next.nft"))?;
    std::fs::rename(d.join("next.nft"), d.join("applied.nft"))
        .map_err(|e| format!("could not keep the table: {e}"))?;
    let _ = std::fs::remove_file(&opening_path);
    Ok(json!("closed"))
}

/// `firewall-show`: the table in force, and the openings.
pub(crate) fn show() -> Result<Value, String> {
    let table = run("nft", &["list", "table", "inet", "erpc_worker"]).ok();
    Ok(json!({
        "ok": true,
        "table": table,
        "openings": openings(&dir(), None)?,
        "pending": dir().join("pending.json").exists(),
    }))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::Path;
    use std::time::Duration;

    use erpc_worker::waf::WafConfig;

    use super::{Host, Tools};
    use crate::wafctl;

    /// Tools that run nothing and write down what they were asked to.
    #[derive(Default)]
    struct Recording {
        ran: RefCell<Vec<String>>,
    }

    impl Tools for Recording {
        fn run(&self, program: &str, args: &[&str]) -> Result<String, String> {
            self.ran
                .borrow_mut()
                .push(format!("{program} {}", args.join(" ")));
            Ok(String::new())
        }

        fn armed(&self) -> Result<bool, String> {
            Ok(false)
        }
    }

    /// A systemd nothing is asked of: an opening is checked against a
    /// WAF's config file, not against its unit.
    struct Unasked;

    impl wafctl::Systemd for Unasked {
        fn run(&self, _args: &[&str]) -> Result<(), String> {
            Err("not asked in this test".to_owned())
        }

        fn state(&self, _unit: &str) -> String {
            "inactive".to_owned()
        }

        fn pid(&self, _unit: &str) -> u32 {
            0
        }

        fn started(&self, _unit: &str) -> String {
            String::new()
        }

        fn journal(&self, _unit: &str) -> Vec<String> {
            Vec::new()
        }
    }

    fn host<'a>(tools: &'a Recording, root: &Path) -> Host<'a> {
        Host {
            tools,
            dir: root.join("worker-firewall"),
            waf: wafctl::Host {
                systemd: &Unasked,
                units: root.join("systemd"),
                configs: root.join("worker-waf"),
                runtime: root.join("run"),
                proc: root.join("proc"),
                agent: root.join("agent"),
                patience: Duration::ZERO,
                pause: Duration::ZERO,
            },
        }
    }

    /// Puts the config of a WAF for worker `id`, listening on `port`,
    /// where `waf-apply` writes it.
    fn waf_on(host: &Host<'_>, id: &str, port: u16) {
        let config = WafConfig::default_for(
            id,
            format!("0.0.0.0:{port}").parse().expect("listen"),
            "127.0.0.1:3000".parse().expect("upstream"),
        );
        std::fs::create_dir_all(&host.waf.configs).expect("configs");
        std::fs::write(
            host.waf.configs.join(format!("{id}.json")),
            serde_json::to_string(&config).expect("json"),
        )
        .expect("config");
    }

    #[test]
    fn everyone_is_applied_only_to_the_port_the_workers_own_waf_listens_on() {
        let tmp = tempfile::tempdir().expect("tmp");
        let tools = Recording::default();
        let host = host(&tools, tmp.path());
        let everyone = r#"{"ssh_port":22,"opening":{"port":8080,"allow":["0.0.0.0/0","::/0"],
            "limit":{"per_second":50,"burst":100}}}"#;
        let untouched = |host: &Host<'_>| {
            assert!(tools.ran.borrow().is_empty(), "{:?}", tools.ran.borrow());
            assert!(
                !host.dir.exists(),
                "nothing was written, nor the lock taken"
            );
        };

        // A worker with no WAF, whatever erpc sent: refused before a file
        // is written or a tool run.
        let refused = super::apply_to(&host, "bot-default", everyone).expect_err("no WAF");
        assert!(
            refused.contains("only a WAF's port is opened to everyone"),
            "{refused}"
        );
        untouched(&host);
        // Another worker's WAF on that port is not this worker's.
        waf_on(&host, "api-default", 8080);
        assert!(super::apply_to(&host, "bot-default", everyone).is_err());
        // Its own WAF, on another port.
        waf_on(&host, "bot-default", 9090);
        let refused = super::apply_to(&host, "bot-default", everyone).expect_err("another port");
        assert!(refused.contains("port 8080 is not the one"), "{refused}");
        // And every other check of an opening is made here too.
        for bad in [
            r#"{"ssh_port":22,"opening":{"port":22,"allow":["198.51.100.7"]}}"#,
            r#"{"ssh_port":22,"opening":{"port":8080,"allow":[]}}"#,
            r#"{"ssh_port":0,"opening":null}"#,
            "{}",
        ] {
            assert!(super::apply_to(&host, "bot-default", bad).is_err(), "{bad}");
        }
        untouched(&host);

        // Its own WAF on that port: applied, the rollback armed before the
        // table is checked and loaded.
        waf_on(&host, "bot-default", 8080);
        let answer = super::apply_to(&host, "bot-default", everyone).expect("applied");
        assert_eq!(answer["firewall"], "applied", "{answer}");
        let d = host.dir.display();
        assert_eq!(
            tools.ran.take(),
            [
                "systemctl stop erpc-worker-firewall-rollback.timer".to_owned(),
                format!(
                    "systemd-run --quiet --collect --unit=erpc-worker-firewall-rollback \
                     --on-active=120 /bin/sh -c mv '{d}/pending.json' '{d}/rolled-back.json' && \
                     /usr/sbin/nft -f '{d}/previous.nft'"
                ),
                format!("nft -c -f {d}/pending.nft"),
                format!("nft -f {d}/pending.nft"),
            ]
        );
        let table = std::fs::read_to_string(host.dir.join("pending.nft")).expect("the table");
        for line in [
            "    tcp dport 8080 meta nfproto ipv4 accept",
            "    tcp dport 8080 meta nfproto ipv6 accept",
            "    tcp dport 22 accept",
        ] {
            assert!(table.lines().any(|l| l == line), "{line} in\n{table}");
        }
        let pending: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(host.dir.join("pending.json")).expect("pending"),
        )
        .expect("json");
        assert_eq!(pending["id"], "bot-default");
        assert_eq!(pending["opening"]["port"], 8080);
        // Not kept yet: that is `firewall-confirm`'s, over a fresh
        // connection.
        assert!(!host.dir.join("workers/bot-default.json").exists());

        // Addresses, to a port with no WAF, as an app's own always were.
        let named = r#"{"ssh_port":22,"opening":{"port":3000,"allow":["198.51.100.7"]}}"#;
        std::fs::remove_file(host.dir.join("pending.json")).expect("removed");
        let answer = super::apply_to(&host, "bot-default", named).expect("applied");
        assert_eq!(answer["firewall"], "applied", "{answer}");
    }

    /// Keeps `opening` as worker `id`'s opening in force, where
    /// `firewall-confirm` keeps it.
    fn in_force(host: &Host<'_>, id: &str, opening: &str) {
        std::fs::create_dir_all(host.dir.join("workers")).expect("workers");
        std::fs::write(host.dir.join("workers").join(format!("{id}.json")), opening)
            .expect("the opening");
    }

    #[test]
    fn the_opening_in_force_is_applied_again_though_the_wafs_config_does_not_read() {
        let tmp = tempfile::tempdir().expect("tmp");
        let tools = Recording::default();
        let host = host(&tools, tmp.path());
        let request = |opening: &str| format!(r#"{{"ssh_port":22,"opening":{opening}}}"#);
        let everyone =
            r#"{"port":8080,"allow":["0.0.0.0/0","::/0"],"limit":{"per_second":50,"burst":100}}"#;
        // The worker's WAF listened on 8080 when its port was opened to
        // everyone, and that opening is in force. Its config no longer
        // reads: the agent installed does not take the file.
        waf_on(&host, "bot-default", 8080);
        in_force(&host, "bot-default", everyone);
        std::fs::write(host.waf.configs.join("bot-default.json"), "{}").expect("config");
        assert_eq!(wafctl::listen_port(&host.waf, "bot-default"), None);
        let applied = |opening: &str| {
            let answer = super::apply_to(&host, "bot-default", &request(opening));
            // Each on its own: not waiting on the one before.
            let _ = std::fs::remove_file(host.dir.join("pending.json"));
            tools.ran.take();
            answer.map(|answer| answer["firewall"] == "applied")
        };

        // The opening in force, again: nothing becomes wider. This is what
        // a deploy's firewall step asks before `waf-apply` can write a
        // config that reads.
        assert_eq!(applied(everyone), Ok(true));
        // The same addresses in another order, and fewer of them.
        assert_eq!(
            applied(
                r#"{"port":8080,"allow":["::/0","0.0.0.0/0"],"limit":{"per_second":50,"burst":100}}"#
            ),
            Ok(true)
        );
        assert_eq!(
            applied(r#"{"port":8080,"allow":["0.0.0.0/0"],"limit":{"per_second":50,"burst":100}}"#),
            Ok(true)
        );

        // Anything wider stays refused: an address more, another port, a
        // looser limit or none.
        for wider in [
            r#"{"port":8080,"allow":["0.0.0.0/0","::/0","198.51.100.7"],"limit":{"per_second":50,"burst":100}}"#,
            r#"{"port":9090,"allow":["0.0.0.0/0","::/0"],"limit":{"per_second":50,"burst":100}}"#,
            r#"{"port":8080,"allow":["0.0.0.0/0","::/0"],"limit":{"per_second":500,"burst":1000}}"#,
            r#"{"port":8080,"allow":["0.0.0.0/0","::/0"]}"#,
        ] {
            let refused = applied(wider).expect_err(wider);
            assert!(
                refused.contains("only a WAF's port is opened to everyone"),
                "{wider}: {refused}"
            );
        }
        // And everyone where the opening in force names addresses, or
        // where none is in force.
        in_force(
            &host,
            "bot-default",
            r#"{"port":8080,"allow":["198.51.100.7/32"],"limit":{"per_second":50,"burst":100}}"#,
        );
        assert!(applied(everyone).is_err());
        // Another worker's opening is not this one's. Where this worker
        // has one in force, it is its own that the request is held to,
        // under the lock: the very opening asked for, in force for
        // another worker, lets nothing through.
        in_force(&host, "api-default", everyone);
        let refused = applied(everyone).expect_err("another worker's");
        assert!(
            refused.contains("only a WAF's port is opened to everyone"),
            "{refused}"
        );
        // And where this worker has none, it is refused before the lock.
        std::fs::remove_file(host.dir.join("workers/bot-default.json")).expect("removed");
        assert!(applied(everyone).is_err());
    }

    #[test]
    fn an_opening_is_checked_before_it_reaches_the_table() {
        use erpc_worker::server::{NewConnections, Opening};
        let opening = |json: &str| serde_json::from_str::<Opening>(json).expect("an opening");
        // Every check of an opening, as `firewall-apply` makes them.
        let refuse_opening = |o: &Opening, ssh_port: u16, waf_port: Option<u16>| {
            super::refuse_shape(o, ssh_port)?;
            super::refuse_everyone(o, waf_port).map_or(Ok(()), Err)
        };
        let plain = r#"{"port":8080,"allow":["198.51.100.7/32"]}"#;
        assert_eq!(refuse_opening(&opening(plain), 22, None), Ok(()));
        let limited = Opening {
            limit: Some(NewConnections::DEFAULT),
            ..opening(plain)
        };
        assert_eq!(refuse_opening(&limited, 22, None), Ok(()));
        // Everyone, to the port the worker's WAF listens on and no other.
        let everyone = opening(r#"{"port":8080,"allow":["0.0.0.0/0","::/0"]}"#);
        assert_eq!(refuse_opening(&everyone, 22, Some(8080)), Ok(()));
        let refused = refuse_opening(&everyone, 22, Some(9090)).expect_err("another port");
        assert!(refused.contains("port 8080 is not the one"), "{refused}");
        for (bad, says) in [
            (
                r#"{"port":22,"allow":["198.51.100.7/32"]}"#,
                "other than SSH's",
            ),
            (
                r#"{"port":0,"allow":["198.51.100.7/32"]}"#,
                "other than SSH's",
            ),
            (r#"{"port":8080,"allow":[]}"#, "1 to 64 addresses"),
            (
                r#"{"port":8080,"allow":["198.51.100.7/32"],"limit":{"per_second":0,"burst":100}}"#,
                "per_second is 0",
            ),
            (
                r#"{"port":8080,"allow":["198.51.100.7/32"],"limit":{"per_second":50,"burst":100001}}"#,
                "burst is 100001",
            ),
            (r#"{"port":8080,"allow":["0.0.0.0/0"]}"#, "every address"),
            (
                r#"{"port":8080,"allow":["198.51.100.7/32","::/0"]}"#,
                "every address",
            ),
        ] {
            let refused = refuse_opening(&opening(bad), 22, None).expect_err(bad);
            assert!(refused.contains(says), "{bad}: {refused}");
        }
        // What is no wider than the opening in force: the same port and
        // limit, to addresses that are each among those in force.
        let within = |o: &str, now: &str| super::within(&opening(o), Some(&opening(now)));
        let two = r#"{"port":8080,"allow":["0.0.0.0/0","198.51.100.7/32"]}"#;
        assert!(within(two, two));
        assert!(within(r#"{"port":8080,"allow":["198.51.100.7/32"]}"#, two));
        assert!(!within(two, r#"{"port":8080,"allow":["0.0.0.0/0"]}"#));
        assert!(!within(r#"{"port":8081,"allow":["0.0.0.0/0"]}"#, two));
        // An address inside a network in force is not one of them as
        // written, and a limit that is not the one in force is not "the
        // same".
        assert!(!within(
            r#"{"port":8080,"allow":["198.51.100.7/32"]}"#,
            r#"{"port":8080,"allow":["198.51.100.0/24"]}"#
        ));
        assert!(!within(
            r#"{"port":8080,"allow":["0.0.0.0/0"],"limit":{"per_second":50,"burst":100}}"#,
            two
        ));
        assert!(!super::within(&opening(two), None));
    }

    #[test]
    fn confirm_and_the_rollback_cannot_both_take_the_change() {
        let tmp = tempfile::tempdir().expect("tmp");
        let d = tmp.path();
        std::fs::write(d.join("pending.json"), r#"{"id":"bot-default"}"#).expect("pending");
        assert!(super::claim(d).is_some(), "confirm takes it");
        assert!(super::claim(d).is_none(), "once");

        // The timer fired first: its command moved the change away, and
        // confirm reports the rollback.
        std::fs::write(d.join("pending.json"), r#"{"id":"bot-default"}"#).expect("pending");
        std::fs::remove_file(d.join(super::CONFIRMING)).expect("clear");
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(super::rollback_command(d).replace("&& /usr/sbin/nft -f", "&& test -n"))
            .status()
            .expect("sh");
        assert!(status.success());
        assert!(super::claim(d).is_none());
        assert_eq!(super::rolled_back()["firewall"], "rolled_back");
    }

    #[test]
    fn only_a_timer_systemd_calls_inactive_is_not_armed() {
        assert_eq!(super::timer_state("active\n"), Ok(true));
        assert_eq!(super::timer_state("inactive\n"), Ok(false));
        assert_eq!(super::timer_state("failed\n"), Ok(false));
        assert!(super::timer_state("").is_err());
        assert!(super::timer_state("Failed to connect to bus\n").is_err());
    }

    #[test]
    fn a_change_no_longer_in_force_is_set_aside_not_deleted() {
        let tmp = tempfile::tempdir().expect("tmp");
        std::fs::write(tmp.path().join("pending.json"), "{}").expect("pending");
        super::set_aside(tmp.path());
        assert!(!tmp.path().join("pending.json").exists());
        assert!(tmp.path().join(super::ROLLED_BACK).exists());
    }

    #[test]
    fn a_change_waiting_its_timer_refuses_another_and_a_stale_one_is_set_aside() {
        let tmp = tempfile::tempdir().expect("tmp");
        let d = tmp.path();
        assert!(
            super::refuse_while_waiting(d, || Ok(true)).is_ok(),
            "nothing waiting"
        );
        std::fs::write(d.join("pending.json"), "{}").expect("pending");
        let refused = super::refuse_while_waiting(d, || Ok(true)).expect_err("refused");
        assert!(refused.contains("waiting to be confirmed"), "{refused}");
        assert!(d.join("pending.json").exists(), "left as it was");
        // systemd not answering: an error, and nothing is touched.
        assert!(super::refuse_while_waiting(d, || Err("no bus".to_owned())).is_err());
        assert!(d.join("pending.json").exists());
        // Its timer gone: no longer in force, set aside.
        assert!(super::refuse_while_waiting(d, || Ok(false)).is_ok());
        assert!(!d.join("pending.json").exists());
        assert!(d.join(super::ROLLED_BACK).exists());
    }

    #[test]
    fn the_firewall_lock_is_taken_in_turn() {
        let tmp = tempfile::tempdir().expect("tmp");
        let first = super::lock(tmp.path()).expect("first");
        assert!(
            std::fs::File::open(tmp.path().join(".lock"))
                .expect("open")
                .try_lock()
                .is_err(),
            "held"
        );
        drop(first);
        assert!(super::lock(tmp.path()).is_ok(), "free again");
    }

    #[test]
    fn the_rollback_does_nothing_once_confirm_has_the_change() {
        let tmp = tempfile::tempdir().expect("tmp");
        let d = tmp.path();
        std::fs::write(d.join("pending.json"), "{}").expect("pending");
        assert!(super::claim(d).is_some());
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(super::rollback_command(d).replace("/usr/sbin/nft -f", "touch"))
            .status()
            .expect("sh");
        assert!(!status.success(), "mv finds nothing to take");
        assert!(
            !d.join("previous.nft").exists(),
            "and the table is not put back"
        );
    }
}
