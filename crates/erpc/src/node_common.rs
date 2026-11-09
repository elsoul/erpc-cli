// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the node commands of every chain share: progress lines, questions,
//! reaching a server (agent, operator key, pinned host key), the Ubuntu
//! check, the vault a network's inventory lives in, and following a run on
//! the node through dropped connections.

use crate::error::{CliError, Code};
use std::path::{Path, PathBuf};

use erpc_auth::store::one_password::{Mode, OpCli};
use erpc_chain::inventory::{Scope, Store};
use erpc_ssh::{HostKey, RemoteCommand, Session, Target};

/// How many times a dropped connection is reopened to follow a run.
pub(crate) const FOLLOW_ATTEMPTS: u32 = 5;

/// Progress, on stderr so that stdout stays the result.
pub(crate) struct Say {
    pub(crate) quiet: bool,
}

impl Say {
    /// A step of the work, marked at a terminal (see [`crate::ui::step_line`]).
    pub(crate) fn line(&self, text: &str) {
        if !self.quiet {
            eprintln!("{}", crate::ui::step_line(text, crate::ui::stderr_drawn()));
        }
    }
}

/// Why `op` failed, as a person reads it. The two answers a beginner meets
/// most, the desktop app not allowing the request in time and no account
/// signed in, are said in words with the way out; anything else is op's
/// own first line, as it came.
pub(crate) fn op_why(stderr: &str, no_reason: &str) -> String {
    let first = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or(no_reason);
    let lower = first.to_ascii_lowercase();
    if lower.contains("authorization timeout") || lower.contains("authorization prompt dismissed") {
        t!("worker_secrets.op_not_allowed")
    } else if lower.contains("not currently signed in")
        || lower.contains("not signed in")
        || lower.contains("no accounts configured")
        || lower.contains("account is not signed in")
    {
        t!("worker_secrets.op_not_signed_in")
    } else {
        first
            .chars()
            .filter(|c| !c.is_control())
            .take(300)
            .collect()
    }
}

/// A spinner while `op` waits on the 1Password app, which can take as long
/// as the person takes to allow it; none off a terminal.
pub(crate) fn op_waiting(doing: &str) -> Option<crate::prompt::Spinner> {
    crate::ui::stderr_drawn()
        .then(|| crate::prompt::Spinner::start(&t!("worker_secrets.op_waiting", doing)))
}

/// The `op` this machine has: a service account when its token is in the
/// environment, otherwise the desktop app.
pub(crate) fn op_runner() -> Result<OpCli, String> {
    // A service account token in the environment means a machine set up for
    // automation; otherwise the desktop app, which asks the operator.
    let mode = if std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_some() {
        Mode::ServiceAccount
    } else {
        Mode::Desktop
    };
    OpCli::from_env(mode, |name| std::env::var_os(name)).map_err(|e| e.to_string())
}

/// The agent socket: the flag, 1Password's agent where it lives, else
/// `SSH_AUTH_SOCK`.
pub(crate) fn agent_socket(flag: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = flag {
        return Ok(path.to_owned());
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for candidate in [
            home.join("Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"),
            home.join(".1password/agent.sock"),
        ] {
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    std::env::var_os("SSH_AUTH_SOCK")
        .map(PathBuf::from)
        .ok_or_else(|| "no SSH agent found: pass --ssh-agent <socket>".to_owned())
}

/// The one public key line in a `.pub` file.
pub(crate) fn public_key_line(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    match lines.as_slice() {
        [line]
            if line.starts_with("ssh-")
                || line.starts_with("ecdsa-")
                || line.starts_with("sk-") =>
        {
            Ok((*line).to_owned())
        }
        _ => Err(format!(
            "{} is not one OpenSSH public key line",
            path.display()
        )),
    }
}

/// The confirmed host key: the pinned one for a stored host (checked
/// against what the server offers), or a new one the operator confirms.
pub(crate) fn host_key(
    address: &str,
    port: u16,
    pinned: Option<&str>,
    expected: Option<&str>,
    say: &Say,
) -> Result<HostKey, String> {
    let offered = erpc_ssh::keyscan(address, port).map_err(|e| e.to_string())?;
    if let Some(pinned) = pinned.filter(|p| !p.is_empty()) {
        let pinned = HostKey::parse(pinned).map_err(|e| e.to_string())?;
        if pinned != offered {
            return Err(format!(
                "{address} now offers host key {}, not the pinned {}; nothing was changed. \
                 If the server was reinstalled, remove its host item and run init again",
                offered.fingerprint(),
                pinned.fingerprint()
            ));
        }
        return Ok(pinned);
    }
    let fingerprint = offered.fingerprint();
    if let Some(expected) = expected {
        if expected.trim() != fingerprint {
            return Err(format!(
                "{address} offers {fingerprint}, not the {expected} given; nothing was changed"
            ));
        }
        say.line(&format!("host key  {fingerprint} (matches --fingerprint)"));
        return Ok(offered);
    }
    if !crate::session::has_terminal() {
        return Err(format!(
            "{address} offers host key {fingerprint}. Check it against the server's console \
             (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) and pass --fingerprint {fingerprint}"
        ));
    }
    let question = format!(
        "{address} offers host key {fingerprint}. Is it the server's? \
         (on the server: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)"
    );
    if confirm(&question)? {
        Ok(offered)
    } else {
        Err("the host key was not confirmed; nothing was changed".to_owned())
    }
}

/// Asks a yes/no question on the terminal; no is the default.
pub(crate) fn confirm(question: &str) -> Result<bool, String> {
    // Picked from two rows, the cursor on No: this asks about host keys,
    // validators and money, where a stray key must not turn the answer
    // into a yes. An arrow only moves the cursor (a toggling prompt would
    // flip the answer), and Enter on No, or Esc, is no.
    let rows = [t!("tui.picker.yes"), t!("tui.picker.no")];
    match crate::prompt::pick(question, &rows, Some(1)) {
        Ok(i) => Ok(i == 0),
        Err(e) if e == "nothing was chosen" => Ok(false),
        Err(e) => Err(e),
    }
}

/// Says what will change and asks, unless `yes`. `refused` is what the
/// operator is told when the answer is no ([`Code::Declined`]) or nobody
/// can answer ([`Code::NeedsTerminal`]).
pub(crate) fn go_ahead(yes: bool, refused: &str) -> Result<(), CliError> {
    if yes {
        return Ok(());
    }
    if !crate::session::has_terminal() {
        return Err(
            CliError::new(Code::NeedsTerminal, t!("tui.picker.no_terminal", refused))
                .hint(t!("tui.picker.pass_yes")),
        );
    }
    if confirm(&t!("tui.picker.go_ahead"))? {
        Ok(())
    } else {
        Err(CliError::new(
            Code::Declined,
            t!("tui.picker.said_no_to", refused),
        ))
    }
}

/// Refuses a server that is not Ubuntu, which the plays are written for,
/// and returns its pretty name.
pub(crate) fn check_ubuntu(session: &Session) -> Result<String, String> {
    let out = session
        .run(&RemoteCommand::OsRelease, None)
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .map(|v| v.trim_matches('"').to_owned())
            .unwrap_or_default()
    };
    if field("ID") != "ubuntu" {
        return Err(format!(
            "the server runs {}, and erpc's plays are written for Ubuntu",
            field("PRETTY_NAME")
        ));
    }
    Ok(field("PRETTY_NAME"))
}

/// The vault for the network: the flag, else the one `keyless.toml` has.
/// `first` is the command that sets one up, for the message when neither
/// names one. Every chain's nodes on a network share its one vault, so a
/// flag naming another vault than the saved one is refused rather than
/// moving the network, and the other chains' nodes with it.
pub(crate) fn vault_for(network: &str, flag: Option<&str>, first: &str) -> Result<String, String> {
    vault_given(network, flag)?.ok_or_else(|| {
        format!(
            "no vault is set for {network}: run `{first}` first, \
             or pass --vault <vault id> (op vault list)"
        )
    })
}

/// [`vault_for`]'s vault, or none when neither the flag nor `keyless.toml`
/// names one, for a command that says what to do then in its own words.
pub(crate) fn vault_given(network: &str, flag: Option<&str>) -> Result<Option<String>, String> {
    let path = crate::keyless::path()?;
    let keyless = crate::keyless::load(&path)?;
    let vault = match (flag, keyless.networks.get(network)) {
        (Some(v), Some(saved)) if v != saved.vault_id => {
            return Err(format!(
                "{network} already keeps its nodes in vault {}; leave --vault out to use it. \
                 To move {network} to {v}, change it in {} first",
                saved.vault_id,
                path.display()
            ));
        }
        (Some(v), _) => v.to_owned(),
        (None, Some(saved)) => saved.vault_id.clone(),
        (None, None) => return Ok(None),
    };
    if !crate::keyless::is_vault_id(&vault) {
        return Err(format!(
            "{vault:?} is not a vault id; `op vault list` prints them"
        ));
    }
    Ok(Some(vault))
}

/// The inventory store of `chain` on `network` in `vault`, with erpc's
/// local lock.
pub(crate) fn store(
    runner: &OpCli,
    vault: &str,
    chain: &str,
    network: &str,
) -> Result<Store<OpCli>, String> {
    let scope = Scope {
        chain: chain.to_owned(),
        network: network.to_owned(),
    };
    let lock = crate::session::state_dir()?.join("inventory.lock");
    Ok(Store::new(runner.clone(), vault, scope, lock))
}

/// Records the network's vault in `keyless.toml`, once it has been used.
pub(crate) fn save_vault(network: &str, vault: &str) -> Result<(), String> {
    let path = crate::keyless::path()?;
    let mut keyless = crate::keyless::load(&path)?;
    keyless.networks.insert(
        network.to_owned(),
        crate::keyless::NetworkVault {
            vault_id: vault.to_owned(),
        },
    );
    crate::keyless::save(&path, &keyless)
}

/// Follows a run to its end, opening the connection again when it drops,
/// and printing each line of the log once. `again` says how to see the end
/// of a run that was lost.
pub(crate) fn follow(
    target: &Target,
    run: &erpc_ssh::RunId,
    again: &str,
    say: &Say,
) -> Result<erpc_ops::run::RunResult, String> {
    let mut seen = 0_usize;
    let mut last = String::new();
    for attempt in 1..=FOLLOW_ATTEMPTS {
        let session = match Session::open(target) {
            Ok(s) => s,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_secs(10));
                continue;
            }
        };
        // The node prints the log from its start each time: skip what was
        // shown before the connection dropped.
        let mut n = 0_usize;
        let followed = erpc_ops::run::follow(&session, run, &mut |line| {
            n += 1;
            if n > seen {
                say.line(&format!("  | {line}"));
            }
        });
        seen = seen.max(n);
        match followed {
            Ok(result) => return Ok(result),
            Err(e) => {
                last = e.to_string();
                say.line(&format!(
                    "           the connection dropped ({last}); following again ({attempt}/{FOLLOW_ATTEMPTS})"
                ));
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        }
    }
    Err(format!(
        "lost the run {} ({last}); it carries on on the node. {again}",
        run.as_str()
    ))
}

/// A disk that holds nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreeDisk {
    pub(crate) name: String,
    pub(crate) bytes: u64,
    /// It has a partition table of empty partitions, which is removed.
    pub(crate) wipe: bool,
    pub(crate) partitions: String,
}

/// Reads [`erpc_ssh::FREE_DISKS_SCRIPT`]'s lines: the free disks, largest
/// first, then by name, as `mount_disks.yml` orders them.
pub(crate) fn parse_free_disks(text: &str) -> Vec<FreeDisk> {
    let mut disks: Vec<FreeDisk> = text
        .lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            if f.next()? != "free" {
                return None;
            }
            let name = f.next()?.to_owned();
            let bytes = f.next()?.parse().ok()?;
            let (wipe, partitions) = match f.next()? {
                "clean" => (false, String::new()),
                "empty-partitions" => (true, f.next().unwrap_or_default().to_owned()),
                _ => return None,
            };
            Some(FreeDisk {
                name,
                bytes,
                wipe,
                partitions,
            })
        })
        .collect();
    disks.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    disks
}

pub(crate) fn free_disks(session: &Session) -> Result<Vec<FreeDisk>, String> {
    let out = session
        .run(&RemoteCommand::FreeDisks, None)
        .map_err(|e| e.to_string())?;
    Ok(parse_free_disks(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(test)]
mod op_why_tests {
    use super::op_why;

    #[test]
    fn the_two_answers_a_beginner_meets_are_said_in_words() {
        let timeout = op_why(
            "[ERROR] 2026/11/04 12:38:37 authorization timeout\n",
            "no reason",
        );
        assert!(timeout.contains("1Password app"), "{timeout}");
        assert!(!timeout.contains("[ERROR]"), "{timeout}");
        let out = op_why(
            "[ERROR] 2026/11/04 12:38:37 You are not currently signed in.\n",
            "no reason",
        );
        assert!(out.contains("op signin"), "{out}");
        // Anything else comes as op said it, first line only, no control characters.
        assert_eq!(
            op_why("\n  something else\x1b[0m\nmore\n", "no reason"),
            "something else[0m"
        );
        assert_eq!(op_why("", "no reason"), "no reason");
    }
}
