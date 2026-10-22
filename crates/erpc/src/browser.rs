// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Opening the approval page, and knowing when not to.
//!
//! Opening a browser is the right default on a laptop and the wrong thing
//! on a server: over SSH it either fails noisily or, worse, opens a page
//! on a machine nobody is looking at while the operator waits. So the
//! decision is made from the environment and is separated from the act,
//! which is what lets it be tested.

use std::ffi::OsString;
use std::process::{Command, Stdio};

use erpc_core::endpoints;

/// Why a browser was not opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoBrowser {
    /// The operator asked for the URL instead.
    Requested,
    /// The session is over SSH, so any window would open elsewhere.
    SshSession,
    /// There is no graphical session to open anything in.
    NoDisplay,
}

impl core::fmt::Display for NoBrowser {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Requested => "you asked for the code instead of a browser",
            Self::SshSession => {
                "this is an SSH session, so a browser here would open on the wrong machine"
            }
            Self::NoDisplay => "this machine has no graphical session",
        };
        f.write_str(text)
    }
}

/// Whether to open a browser, and if not, why not.
///
/// `var` reads the environment, so a test can describe a machine without
/// being on one.
pub fn decide<F>(requested_no_browser: bool, var: F) -> Result<(), NoBrowser>
where
    F: Fn(&str) -> Option<OsString>,
{
    let present = |name: &str| var(name).is_some_and(|v| !v.is_empty());
    if requested_no_browser {
        return Err(NoBrowser::Requested);
    }
    if present("SSH_CONNECTION") || present("SSH_TTY") {
        return Err(NoBrowser::SshSession);
    }
    // macOS and Windows always have a way to open a URL. On Linux there
    // has to be a session to open it in.
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        return Ok(());
    }
    if present("DISPLAY") || present("WAYLAND_DISPLAY") {
        return Ok(());
    }
    Err(NoBrowser::NoDisplay)
}

/// The variables a browser does not get from this process.
///
/// Every `OP_` variable: the service account token, a Connect token, and
/// the `OP_SESSION_*` a signed-in `op` exports. The browser inherits the
/// rest of the environment, because the openers need the display and the
/// session bus to find it; these it has no use for, and a browser started
/// with them holds a 1Password credential for as long as it runs.
fn withheld(names: impl Iterator<Item = std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    names
        .filter(|name| name.to_str().is_some_and(|n| n.starts_with("OP_")))
        .collect()
}

/// Opens `url` in the operator's browser.
///
/// Refuses a URL that is not on a host declared in `erpc-core`'s
/// endpoints, or that holds anything but the characters a verification
/// URL needs. The URL comes from the identity provider's reply, which is
/// the right source but still a remote one, and this is the last point
/// before it is handed to the operating system. On Windows that is
/// `cmd /C start`, which reads `&`, `|`, `^`, `%` and quotes as syntax and
/// which the standard library does not escape for; the character check is
/// what keeps the URL a single argument. `erpc-auth` already refuses such a
/// URL when the reply arrives; this repeats it where it matters most.
///
/// # Errors
///
/// Returns a message when the URL is not an allowed destination or the
/// opener could not be started.
pub fn open(url: &str) -> Result<(), String> {
    endpoints::ensure_service_url(url).map_err(|e| format!("refusing to open {url}: {e}"))?;
    if !url
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~:/?=".contains(&b))
    {
        return Err(format!(
            "refusing to open {url:?}: it holds characters a verification page does not need"
        ));
    }

    let (program, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("/usr/bin/open", &[])
    } else if cfg!(target_os = "windows") {
        ("cmd", &["/C", "start", ""])
    } else {
        ("xdg-open", &[])
    };

    let mut command = Command::new(program);
    for name in withheld(std::env::vars_os().map(|(name, _)| name)) {
        command.env_remove(name);
    }
    command
        .args(args)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not start {program}: {e}"))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{NoBrowser, decide, open, withheld};

    #[test]
    fn a_browser_does_not_inherit_a_1password_credential() {
        let names = [
            "OP_SERVICE_ACCOUNT_TOKEN",
            "OP_SESSION_my_account",
            "OP_CONNECT_TOKEN",
            "PATH",
            "DISPLAY",
            "DBUS_SESSION_BUS_ADDRESS",
        ]
        .map(OsString::from);
        let removed = withheld(names.into_iter());
        assert_eq!(
            removed,
            [
                "OP_SERVICE_ACCOUNT_TOKEN",
                "OP_SESSION_my_account",
                "OP_CONNECT_TOKEN"
            ]
            .map(OsString::from)
            .to_vec()
        );
    }

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(*v))
        }
    }

    #[test]
    fn asking_for_no_browser_is_honoured_before_anything_else() {
        assert_eq!(
            decide(true, env(&[("DISPLAY", ":0")])),
            Err(NoBrowser::Requested)
        );
    }

    #[test]
    fn an_ssh_session_never_opens_a_browser() {
        // Even with a DISPLAY set: that display is on the far machine, and
        // the operator is not looking at it.
        for pairs in [
            &[
                ("SSH_CONNECTION", "10.0.0.1 1 10.0.0.2 22"),
                ("DISPLAY", ":0"),
            ] as &[_; 2],
            &[("SSH_TTY", "/dev/pts/0"), ("DISPLAY", ":0")],
        ] {
            assert_eq!(decide(false, env(pairs)), Err(NoBrowser::SshSession));
        }
    }

    #[test]
    fn an_empty_variable_is_not_an_ssh_session() {
        let outcome = decide(false, env(&[("SSH_CONNECTION", ""), ("DISPLAY", ":0")]));
        assert_ne!(outcome, Err(NoBrowser::SshSession));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_needs_a_display() {
        assert_eq!(decide(false, env(&[])), Err(NoBrowser::NoDisplay));
        assert_eq!(decide(false, env(&[("DISPLAY", ":0")])), Ok(()));
        assert_eq!(
            decide(false, env(&[("WAYLAND_DISPLAY", "wayland-0")])),
            Ok(())
        );
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn macos_and_windows_always_have_an_opener() {
        assert_eq!(decide(false, env(&[])), Ok(()));
    }

    #[test]
    fn a_url_outside_the_allowlist_is_not_opened() {
        // The URL arrives from the identity provider. That is the right
        // source and still a remote one, and this is the last check before
        // it reaches the operating system.
        let evil = format!("{}evil.example.net/activate", "https://");
        let err = open(&evil).expect_err("an undeclared host is not opened");
        assert!(err.contains("refusing to open"), "{err}");
    }

    #[test]
    fn a_url_a_shell_would_read_as_syntax_is_not_opened() {
        // Refused before anything is started, so this test never
        // opens a browser on the machine running it.
        for url in [
            "https://auth-api.erpc.global/oauth/device?user_code=A&calc.exe",
            "https://auth-api.erpc.global/oauth/device?x=1|whoami",
            "https://auth-api.erpc.global/oauth/device?x=%PATH%",
            "https://auth-api.erpc.global/oauth/device?x=^\"y",
        ] {
            let err = open(url).expect_err("not opened");
            assert!(err.contains("refusing to open"), "{err}");
        }
    }

    #[test]
    fn every_reason_prints_something_an_operator_can_act_on() {
        for reason in [
            NoBrowser::Requested,
            NoBrowser::SshSession,
            NoBrowser::NoDisplay,
        ] {
            assert!(reason.to_string().len() > 20, "{reason:?}");
        }
    }
}
