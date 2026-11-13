// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The terminal's echo, held off across a run of hidden prompts.
//!
//! A hidden prompt turns the echo off for the one line it reads and back
//! on after it. Between two prompts of one question the echo is therefore
//! on: while a keystore passphrase is checked, which takes PBKDF2 its
//! 600,000 rounds, and until it is asked for again. What is typed ahead in
//! that time is the next attempt at the passphrase, and the terminal shows
//! it.
//!
//! [`off`] turns the echo off and returns a guard that keeps it off until
//! the guard is dropped. A prompt inside finds the echo off and leaves it
//! off. When the guard goes the terminal is as it was, and what was typed
//! unseen and not read is discarded, so it does not reach the shell after
//! erpc either.
//!
//! erpc also ends by a signal or by a panic, and neither runs destructors
//! ([`crate::interrupt`]): both call [`restore`] before they end it.
//!
//! This is for Unix, where the terminal echoes what is typed whether or
//! not anything is reading. The Windows console shows a typed character
//! only when a line read takes it, and the hidden prompt reads its line key
//! by key, which shows nothing: there the guard holds nothing.

/// The echo held off: back as it was once this is dropped.
pub(crate) struct Off {
    /// Whether this is the hold that turned it off, and so turns it back.
    ours: bool,
}

impl Drop for Off {
    fn drop(&mut self) {
        if self.ours {
            restore();
        }
    }
}

/// Turns the echo of the terminal on standard input off until what is
/// returned is dropped. Where standard input is no terminal, or the echo
/// is held off already, nothing changes and the guard restores nothing.
#[cfg_attr(
    all(test, not(unix)),
    allow(
        dead_code,
        reason = "the desk that asks at the real terminal is not built into the tests, \
                  and the tests that hold the echo off are Unix's"
    )
)]
pub(crate) fn off() -> Off {
    #[cfg(unix)]
    return off_at(std::io::stdin());
    #[cfg(not(unix))]
    Off { ours: false }
}

/// [`off`], for the terminal `fd`.
#[cfg(unix)]
fn off_at(fd: impl std::os::fd::AsFd) -> Off {
    Off { ours: tty::off(fd) }
}

/// Puts the echo back where a hold turned it off, and discards what was
/// typed unseen and not read. With nothing held it does nothing. Also for
/// the ways out that drop no guard: a signal, a panic that aborts.
pub(crate) fn restore() {
    #[cfg(unix)]
    tty::restore();
}

#[cfg(unix)]
mod tty {
    use std::os::fd::{AsFd, OwnedFd};
    use std::sync::{Mutex, PoisonError};

    use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};

    /// The terminal whose echo is held off, and how it was set before.
    static HELD: Mutex<Option<(OwnedFd, Termios)>> = Mutex::new(None);

    /// Turns the echo of `fd` off; whether this call did. It did not when
    /// `fd` is no terminal, or when the echo is held off already.
    pub(super) fn off(fd: impl AsFd) -> bool {
        let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_some() {
            return false;
        }
        let Ok(before) = tcgetattr(&fd) else {
            return false;
        };
        // A handle of its own on the terminal, so the way back does not
        // depend on what the caller does with `fd`.
        let Ok(terminal) = fd.as_fd().try_clone_to_owned() else {
            return false;
        };
        let mut quiet = before.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        if tcsetattr(&terminal, OptionalActions::Now, &quiet).is_err() {
            return false;
        }
        *held = Some((terminal, before));
        true
    }

    pub(super) fn restore() {
        let held = HELD.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some((terminal, before)) = held {
            // `Flush` discards the input that was not read: an attempt
            // typed ahead and never asked for is not left for the shell.
            let _ = tcsetattr(&terminal, OptionalActions::Flush, &before);
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
pub(crate) mod tests {
    use std::io::Write as _;
    use std::os::fd::OwnedFd;
    use std::time::{Duration, Instant};

    use rustix::fs::{Mode, OFlags};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

    /// A terminal of the test's own: both ends of a new pseudoterminal,
    /// the side a person types into and the side a program reads.
    pub(crate) fn terminal() -> (std::fs::File, OwnedFd) {
        let typed = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("a pseudoterminal");
        grantpt(&typed).expect("granted");
        unlockpt(&typed).expect("unlocked");
        let name = ptsname(&typed, Vec::new()).expect("its name");
        let read = rustix::fs::open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY,
            Mode::empty(),
        )
        .expect("opens");
        (std::fs::File::from(typed), read)
    }

    /// Whether `terminal` shows what is typed.
    pub(crate) fn echoes(terminal: &OwnedFd) -> bool {
        tcgetattr(terminal)
            .expect("a terminal")
            .local_modes
            .contains(LocalModes::ECHO)
    }

    /// How many bytes `terminal` has for a reader, once it has any, or
    /// none after a second without.
    fn waiting(terminal: &OwnedFd) -> u64 {
        let until = Instant::now() + Duration::from_secs(1);
        loop {
            let ready = rustix::io::ioctl_fionread(terminal).expect("asked");
            if ready > 0 || Instant::now() > until {
                return ready;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// One test, since the hold is the process's.
    #[test]
    fn the_echo_is_off_while_held_and_back_on_every_way_out() {
        let (mut typed, read) = terminal();
        assert!(echoes(&read));
        // Held: off. A hold taken inside it changes nothing, and is not
        // the one that turns the echo back on.
        let held = super::off_at(&read);
        assert!(!echoes(&read));
        let inner = super::off_at(&read);
        assert!(!echoes(&read));
        drop(inner);
        assert!(!echoes(&read));
        // A hidden prompt inside the hold, as the prompt's own code reads
        // a line: it turns the echo off, reads, and puts back what it
        // found, which is off.
        let found = tcgetattr(&read).expect("a terminal");
        let mut hidden = found.clone();
        hidden.local_modes.remove(LocalModes::ECHO);
        tcsetattr(&read, OptionalActions::Flush, &hidden).expect("set");
        tcsetattr(&read, OptionalActions::Flush, &found).expect("set");
        assert!(!echoes(&read));
        // An attempt typed ahead while it is held, and never read.
        typed.write_all(b"typed ahead\n").expect("typed");
        assert_eq!(waiting(&read), 12);
        // Dropped: on again, and what was typed unseen is gone.
        drop(held);
        assert!(echoes(&read));
        assert_eq!(rustix::io::ioctl_fionread(&read).expect("asked"), 0);
        // The way out that drops nothing: a signal, a panic that aborts.
        let held = super::off_at(&read);
        assert!(!echoes(&read));
        super::restore();
        assert!(echoes(&read));
        // The guard left behind finds nothing more to put back, and with
        // nothing held, nothing is done.
        drop(held);
        super::restore();
        assert!(echoes(&read));
        // What is no terminal has no echo to hold.
        let file = tempfile::tempfile().expect("a file");
        drop(super::off_at(&file));
    }
}
