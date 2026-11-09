// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bounded secret-output capture. Neither stream is a diagnostic on failure.
use std::{
    io::{Read, Write as _},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Secret response bytes. Debug never displays their contents.
pub struct PrivateOutput(Zeroizing<Vec<u8>>);
impl std::fmt::Debug for PrivateOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateOutput([REDACTED])")
    }
}
impl PrivateOutput {
    /// Borrow the original response only for explicit validation or secret storage.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
fn read(mut stream: impl Read, maximum: usize) -> Result<Zeroizing<Vec<u8>>, ()> {
    let mut result = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    let mut exceeded = false;
    loop {
        let count = stream.read(&mut *buffer).map_err(|_| ())?;
        if count == 0 {
            return if exceeded { Err(()) } else { Ok(result) };
        }
        if result.len().saturating_add(count) > maximum {
            exceeded = true;
        } else if !exceeded {
            result.extend_from_slice(&buffer[..count]);
        }
        // Continue draining until exit/timeout without accumulating oversized data.
    }
}
pub(crate) fn run(
    command: &mut Command,
    input: &[u8],
    maximum: usize,
    timeout: Duration,
) -> Result<PrivateOutput, &'static str> {
    const FAILURE: &str = "protected private response could not be verified";
    if maximum == 0 || maximum > 65_536 || input.len() > 65_536 {
        return Err(FAILURE);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| FAILURE)?;
    let mut stdin = child.stdin.take().ok_or(FAILURE)?;
    let stdout = child.stdout.take().ok_or(FAILURE)?;
    let stderr = child.stderr.take().ok_or(FAILURE)?;
    let deadline = Instant::now() + timeout;
    // The writer has its own secret copy so a stalled peer cannot block the
    // caller before its timeout/reaping path. All three buffers wipe on drop.
    let input = Zeroizing::new(input.to_vec());
    let writer = thread::spawn(move || stdin.write_all(&input).map_err(|_| ()));
    let output = thread::spawn(move || read(stdout, maximum));
    let errors = thread::spawn(move || read(stderr, 65_536));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(());
            }
        }
    };
    let written = writer.join().map_err(|_| FAILURE)?;
    let stdout = output.join().map_err(|_| FAILURE)?.map_err(|()| FAILURE)?;
    let stderr = errors.join().map_err(|_| FAILURE)?.map_err(|()| FAILURE)?;
    if written.is_err()
        || status.is_err()
        || !status.map_err(|()| FAILURE)?.success()
        || !stderr.is_empty()
    {
        return Err(FAILURE);
    }
    Ok(PrivateOutput(stdout))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn capture_never_formats_private_streams_and_bounds_both_channels() {
        let mut good = Command::new("python3");
        good.args([
            "-I",
            "-c",
            "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())",
        ]);
        let result = run(
            &mut good,
            b"inert private response",
            64,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(result.expose(), b"inert private response");
        assert!(!format!("{result:?}").contains("inert private"));
        for script in [
            "import sys;print('inert private response',file=sys.stderr);sys.exit(1)",
            "print('x'*100000)",
            "import sys;sys.stderr.write('x'*100000)",
        ] {
            let mut command = Command::new("python3");
            command.args(["-I", "-c", script]);
            assert_eq!(
                run(&mut command, b"", 64, Duration::from_secs(5)).unwrap_err(),
                "protected private response could not be verified"
            );
        }
    }
    #[test]
    fn timeout_reaps_a_peer_that_never_consumes_private_stdin() {
        let mut command = Command::new("python3");
        command.args(["-I", "-c", "import time;time.sleep(10)"]);
        let started = Instant::now();
        assert!(
            run(
                &mut command,
                &vec![7; 65_536],
                64,
                Duration::from_millis(100)
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
