// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The macOS keychain, reached through Apple's `/usr/bin/security`.
//!
//! The keychain trusts the program that created an item, by its code
//! signature. erpc built on the operator's machine has no lasting
//! signature -- each build is a new program to the keychain -- so going to
//! the keychain directly asked for the login password on every read and
//! every write, and again after every update. `security` is Apple's own
//! signed program: an item it creates trusts it, and erpc reaches the item
//! through it without asking, as other command-line tools do.
//!
//! The trade is the one those tools make: another program running as the
//! same user can read the item the same way, by running `security` itself.
//! The keychain still keeps the session encrypted at rest and away from
//! other users, which is what the file store cannot.
//!
//! The session never goes on a command line, where any process can see
//! it. Writes go through `security -i`, which reads its commands from
//! standard input, with the session hex-encoded so no quoting can break it.

use std::io::Write as _;
use std::process::{Command, Stdio};

/// Apple's keychain tool, by its full path so `PATH` cannot substitute it.
const SECURITY: &str = "/usr/bin/security";
/// What `security` exits with when there is no such item.
const NOT_FOUND: i32 = 44;

/// Reads an item's secret, or `None` when there is no item.
///
/// # Errors
///
/// Returns a message when `security` cannot be run or fails otherwise.
pub fn read(service: &str, account: &str) -> Result<Option<String>, String> {
    let output = Command::new(SECURITY)
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run {SECURITY}: {e}"))?;
    if output.status.code() == Some(NOT_FOUND) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(failure(&output.stderr));
    }
    let text =
        String::from_utf8(output.stdout).map_err(|_| "the keychain item is not text".to_owned())?;
    Ok(Some(text.trim_end_matches('\n').to_owned()))
}

/// Writes an item's secret, replacing the item if there is one.
///
/// The old item is removed and a new one made rather than updated in
/// place, so an item that an earlier erpc made -- trusting that build
/// alone -- is replaced by one that trusts `security`. The write is read
/// back to confirm it, because `security -i` reports success either way.
///
/// # Errors
///
/// Returns a message when the item could not be written.
pub fn write(service: &str, account: &str, secret: &str) -> Result<(), String> {
    run_script(service, account, secret, true)
}

/// Adds an item, never replacing one: when an item is there already,
/// `security` refuses to add another, and the read-back finds the one
/// that was there. For secrets that must not be lost to a second writer.
///
/// # Errors
///
/// Returns a message when the item could not be written, or another
/// secret is kept under the same name.
pub fn add(service: &str, account: &str, secret: &str) -> Result<(), String> {
    run_script(service, account, secret, false)
}

/// The commands `security -i` is given: an add, after a delete only when
/// the item is to be replaced.
fn script(service: &str, account: &str, secret: &str, replace: bool) -> String {
    let delete = if replace {
        format!("delete-generic-password -s \"{service}\" -a \"{account}\"\n")
    } else {
        String::new()
    };
    format!(
        "{delete}add-generic-password -s \"{service}\" -a \"{account}\" -T {SECURITY} -X {}\n",
        hex(secret.as_bytes())
    )
}

fn run_script(service: &str, account: &str, secret: &str, replace: bool) -> Result<(), String> {
    for name in [service, account] {
        if name.is_empty() || name.contains(['"', '\\', '\n', '\r']) {
            return Err(format!("{name:?} cannot name a keychain item"));
        }
    }
    let script = script(service, account, secret, replace);
    let mut child = Command::new(SECURITY)
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run {SECURITY}: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("could not talk to {SECURITY}: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("could not run {SECURITY}: {e}"))?;
    match read(service, account)? {
        Some(stored) if stored == secret => Ok(()),
        Some(_) if !replace => Err(format!(
            "the keychain holds another secret under {service} already; it was not replaced"
        )),
        _ => Err(failure(&output.stderr)),
    }
}

/// Removes an item; no item is not an error.
///
/// # Errors
///
/// Returns a message when `security` cannot be run or fails otherwise.
pub fn delete(service: &str, account: &str) -> Result<(), String> {
    let output = Command::new(SECURITY)
        .args(["delete-generic-password", "-s", service, "-a", account])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .map_err(|e| format!("could not run {SECURITY}: {e}"))?;
    if output.status.success() || output.status.code() == Some(NOT_FOUND) {
        Ok(())
    } else {
        Err(failure(&output.stderr))
    }
}

/// `security`'s complaint, one printable line. It never holds the secret:
/// the secret goes in on standard input and errors name only the item.
fn failure(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("security failed");
    line.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(200)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::{delete, hex, read, script, write};

    #[test]
    fn an_add_never_deletes_what_is_there() {
        let add = script("erpc-storage-key", "me", "secret", false);
        assert!(!add.contains("delete-generic-password"), "{add}");
        assert!(add.starts_with("add-generic-password "));
        assert!(
            !add.contains("secret"),
            "the secret went into the script as text"
        );
        let replace = script("erpc-storage-key", "me", "secret", true);
        assert!(replace.starts_with("delete-generic-password "));
    }

    #[test]
    fn the_secret_is_hex_encoded_for_the_script() {
        assert_eq!(hex(br#"{"a":"b c"}"#), "7b2261223a22622063227d");
    }

    #[test]
    fn a_name_that_would_break_the_script_is_refused() {
        for bad in ["a\"b", "a\\b", "a\nb", ""] {
            assert!(write("erpc-test", bad, "x").is_err(), "{bad:?}");
        }
    }

    /// Writes, reads back and removes a real item in the login keychain,
    /// under a service name of its own. Run by hand on a Mac.
    #[test]
    #[ignore = "touches the login keychain"]
    fn an_item_round_trips_through_security() {
        let service = "erpc-test-security-cli";
        let secret = r#"{"store_version":1,"access_token":"a b \"c\""}"#;
        write(service, "tester", secret).expect("written");
        assert_eq!(
            read(service, "tester").expect("read").as_deref(),
            Some(secret)
        );
        write(service, "tester", "second").expect("replaced");
        assert_eq!(
            read(service, "tester").expect("read").as_deref(),
            Some("second")
        );
        delete(service, "tester").expect("deleted");
        assert_eq!(read(service, "tester").expect("read"), None);
        delete(service, "tester").expect("deleting nothing is fine");
    }
}
