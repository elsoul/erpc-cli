// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The SSH server's effective settings, from `sshd_config` and the files it
//! includes. Like the server, the first value given for a setting wins.

use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use erpc_api::security_check::{Bounded, Coverage, RootLogin, Ssh, Tristate};

const FILE_LIMIT: u64 = 1024 * 1024;
const INCLUDE_DEPTH: usize = 8;

#[derive(Default)]
struct Settings {
    password_auth: Option<Tristate>,
    root_login: Option<RootLogin>,
    kbd_interactive: Option<Tristate>,
    ports: Vec<NonZeroU16>,
    partial: bool,
}

/// The settings of the server whose configuration is under `root`.
pub(super) fn read(root: &Path) -> Ssh {
    let main = root.join("etc/ssh/sshd_config");
    let mut settings = Settings::default();
    match read_file(&main) {
        Ok(text) => apply(root, &text, &mut settings, 0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ssh {
                coverage: Coverage::Absent,
                password_auth: Tristate::Unknown,
                root_login: RootLogin::Unknown,
                kbd_interactive: Tristate::Unknown,
                ports: Bounded::default(),
            };
        }
        Err(_) => {
            return Ssh {
                coverage: Coverage::Unreadable,
                password_auth: Tristate::Unknown,
                root_login: RootLogin::Unknown,
                kbd_interactive: Tristate::Unknown,
                ports: Bounded::default(),
            };
        }
    }
    let mut ports = settings.ports;
    if ports.is_empty() {
        ports.push(NonZeroU16::new(22).unwrap_or(NonZeroU16::MIN));
    }
    ports.dedup();
    let (ports, dropped) = Bounded::new(ports);
    Ssh {
        coverage: if settings.partial || dropped {
            Coverage::Partial
        } else {
            Coverage::Complete
        },
        // The server's own defaults for what no file sets.
        password_auth: settings.password_auth.unwrap_or(Tristate::Yes),
        root_login: settings.root_login.unwrap_or(RootLogin::ProhibitPassword),
        kbd_interactive: settings.kbd_interactive.unwrap_or(Tristate::Yes),
        ports,
    }
}

fn read_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(FILE_LIMIT)
        .read_to_string(&mut text)?;
    Ok(text)
}

fn apply(root: &Path, text: &str, settings: &mut Settings, depth: usize) {
    let mut conditional = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (keyword, value) = line
            .split_once(|c: char| c.is_ascii_whitespace() || c == '=')
            .map_or((line, ""), |(k, v)| {
                (
                    k,
                    v.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '=')
                        .trim(),
                )
            });
        let keyword = keyword.to_ascii_lowercase();
        if keyword == "match" {
            // What a Match block sets applies only to some connections; the
            // report says it could not settle those.
            conditional = !value.eq_ignore_ascii_case("all");
            settings.partial |= conditional;
            continue;
        }
        if conditional {
            continue;
        }
        match keyword.as_str() {
            "include" => include(root, value, settings, depth),
            "port" => match value.parse::<NonZeroU16>() {
                Ok(port) => settings.ports.push(port),
                Err(_) => settings.partial = true,
            },
            "passwordauthentication" => first(&mut settings.password_auth, yes_no(value)),
            "kbdinteractiveauthentication" | "challengeresponseauthentication" => {
                first(&mut settings.kbd_interactive, yes_no(value));
            }
            "permitrootlogin" => first(&mut settings.root_login, root_login(value)),
            _ => {}
        }
    }
}

fn first<T>(slot: &mut Option<T>, value: T) {
    if slot.is_none() {
        *slot = Some(value);
    }
}

fn yes_no(value: &str) -> Tristate {
    match value.to_ascii_lowercase().as_str() {
        "yes" => Tristate::Yes,
        "no" => Tristate::No,
        _ => Tristate::Unknown,
    }
}

fn root_login(value: &str) -> RootLogin {
    match value.to_ascii_lowercase().as_str() {
        "yes" => RootLogin::Yes,
        "prohibit-password" | "without-password" => RootLogin::ProhibitPassword,
        "forced-commands-only" => RootLogin::ForcedCommandsOnly,
        "no" => RootLogin::No,
        _ => RootLogin::Unknown,
    }
}

fn include(root: &Path, value: &str, settings: &mut Settings, depth: usize) {
    if depth >= INCLUDE_DEPTH {
        settings.partial = true;
        return;
    }
    for pattern in value.split_ascii_whitespace() {
        let pattern = pattern
            .strip_prefix('/')
            .map_or_else(|| Path::new("etc/ssh").join(pattern), PathBuf::from);
        let Some(files) = expand(root, &pattern) else {
            settings.partial = true;
            continue;
        };
        for file in files {
            match read_file(&file) {
                Ok(text) => apply(root, &text, settings, depth + 1),
                Err(_) => settings.partial = true,
            }
        }
    }
}

/// The files `pattern` names under `root`, in the order the server reads
/// them. Only the last part may hold a `*`; anything else is `None`.
fn expand(root: &Path, pattern: &Path) -> Option<Vec<PathBuf>> {
    let name = pattern.file_name()?.to_str()?;
    let parent = pattern.parent()?;
    if parent.to_str()?.contains(['*', '?', '[']) || name.contains(['?', '[']) {
        return None;
    }
    let Some((prefix, suffix)) = name.split_once('*') else {
        let file = root.join(pattern);
        return Some(if file.is_file() {
            vec![file]
        } else {
            Vec::new()
        });
    };
    if suffix.contains('*') {
        return None;
    }
    let dir = root.join(parent);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(_) => return None,
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| {
            e.file_name().to_str().is_some_and(|n| {
                n.len() >= prefix.len() + suffix.len()
                    && n.starts_with(prefix)
                    && n.ends_with(suffix)
            })
        })
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    Some(files)
}

#[cfg(all(test, unix))]
mod tests {
    use erpc_api::security_check::{Coverage, RootLogin, Tristate};

    use super::read;

    fn ports(ssh: &erpc_api::security_check::Ssh) -> Vec<u16> {
        ssh.ports.items().iter().map(|p| p.get()).collect()
    }

    #[test]
    fn included_files_come_first_where_they_are_included() {
        let root = crate::node::security::fixture("ssh");
        std::fs::create_dir_all(root.join("etc/ssh/sshd_config.d"))
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(
            root.join("etc/ssh/sshd_config"),
            "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nPort 22\nPort=2222\nPermitRootLogin yes\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(
            root.join("etc/ssh/sshd_config.d/50-cloud-init.conf"),
            "PasswordAuthentication yes\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(
            root.join("etc/ssh/sshd_config.d/60-hardening.conf"),
            "passwordauthentication no\nKbdInteractiveAuthentication no\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let ssh = read(&root);
        assert_eq!(ssh.coverage, Coverage::Complete);
        assert_eq!(ssh.password_auth, Tristate::Yes);
        assert_eq!(ssh.kbd_interactive, Tristate::No);
        assert_eq!(ssh.root_login, RootLogin::Yes);
        assert_eq!(ports(&ssh), [22, 2222]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn defaults_absence_and_conditional_blocks() {
        let root = crate::node::security::fixture("ssh-defaults");
        assert_eq!(read(&root).coverage, Coverage::Absent);

        std::fs::create_dir_all(root.join("etc/ssh")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(root.join("etc/ssh/sshd_config"), "# nothing set\n")
            .unwrap_or_else(|e| panic!("{e}"));
        let ssh = read(&root);
        assert_eq!(
            (
                ssh.coverage,
                ssh.password_auth,
                ssh.root_login,
                ssh.kbd_interactive
            ),
            (
                Coverage::Complete,
                Tristate::Yes,
                RootLogin::ProhibitPassword,
                Tristate::Yes
            )
        );
        assert_eq!(ports(&ssh), [22]);

        std::fs::write(
            root.join("etc/ssh/sshd_config"),
            "Match User deploy\n  PasswordAuthentication yes\nMatch all\nPasswordAuthentication no\nInclude /etc/ssh/missing/*.conf\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let ssh = read(&root);
        assert_eq!(
            (ssh.coverage, ssh.password_auth),
            (Coverage::Partial, Tristate::No)
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
