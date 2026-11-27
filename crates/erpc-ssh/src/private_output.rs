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
/// Sanitized capture failure. Output and diagnostics never appear in the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PrivateCaptureError {
    /// The capture was not configured within its allowed bounds.
    #[error("the collector capture limits are invalid")]
    InvalidLimits,
    /// The operating system could not start the local command.
    #[error("the local SSH command could not start")]
    Start,
    /// The capture subprocess or its pipes failed.
    #[error("the collector output could not be captured")]
    Io,
    /// The locally enforced operation deadline expired.
    #[error("the collector operation timed out")]
    Timeout,
    /// Either output stream exceeded its capture limit.
    #[error("the collector output exceeded the capture limit")]
    OutputLimit,
    /// OpenSSH reported a failed host-key verification.
    #[error("SSH host-key verification failed")]
    HostKey,
    /// OpenSSH reported that the selected agent declined the signature.
    #[error("the SSH agent refused the requested signature")]
    AgentDenied,
    /// OpenSSH reported that its public-key login was refused.
    #[error("SSH public-key authentication was denied")]
    AuthenticationDenied,
    /// OpenSSH reported a transport timeout.
    #[error("the SSH transport reported a timeout")]
    TransportTimeout,
    /// OpenSSH reported a network transport failure.
    #[error("the SSH transport could not establish or keep the connection")]
    TransportFailure,
    /// OpenSSH ended with its ambiguous transport/remote exit value.
    #[error("SSH exited with status 255 without a recognized reason")]
    SshExit,
    /// The subprocess exited with a nonzero or signal exit status.
    #[error("the collector exited with status {0}")]
    Exit(i32),
    /// A successful collector produced unexpected diagnostics.
    #[error("the collector emitted unexpected diagnostics")]
    UnexpectedStderr,
}

impl PrivateCaptureError {
    /// Stable diagnostic category without paths, keys, or raw peer output.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "capture_invalid_limits",
            Self::Start => "ssh_command_start",
            Self::Io => "capture_io",
            Self::Timeout => "capture_timeout",
            Self::OutputLimit => "capture_limit",
            Self::HostKey => "ssh_host_key",
            Self::AgentDenied => "ssh_agent_denied",
            Self::AuthenticationDenied => "ssh_authentication_denied",
            Self::TransportTimeout => "ssh_transport_timeout",
            Self::TransportFailure => "ssh_transport_failure",
            Self::SshExit => "ssh_exit_255",
            Self::Exit(_) => "collector_exit",
            Self::UnexpectedStderr => "collector_unexpected_diagnostics",
        }
    }
}

fn read(mut stream: impl Read, maximum: usize) -> Result<Zeroizing<Vec<u8>>, PrivateCaptureError> {
    let mut result = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    let mut exceeded = false;
    loop {
        let count = stream
            .read(&mut *buffer)
            .map_err(|_| PrivateCaptureError::Io)?;
        if count == 0 {
            return if exceeded {
                Err(PrivateCaptureError::OutputLimit)
            } else {
                Ok(result)
            };
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
    run_detailed(command, input, maximum, timeout)
        .map_err(|_| "protected private response could not be verified")
}

pub(crate) fn run_detailed(
    command: &mut Command,
    input: &[u8],
    maximum: usize,
    timeout: Duration,
) -> Result<PrivateOutput, PrivateCaptureError> {
    use PrivateCaptureError as Failure;

    if maximum == 0 || maximum > 65_536 || input.len() > 65_536 {
        return Err(Failure::InvalidLimits);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| Failure::Start)?;
    let mut stdin = child.stdin.take().ok_or(Failure::Io)?;
    let stdout = child.stdout.take().ok_or(Failure::Io)?;
    let stderr = child.stderr.take().ok_or(Failure::Io)?;
    let deadline = Instant::now() + timeout;
    // The writer has its own secret copy so a stalled peer cannot block the
    // caller before its timeout/reaping path. All three buffers wipe on drop.
    let input = Zeroizing::new(input.to_vec());
    let writer = thread::spawn(move || stdin.write_all(&input).map_err(|_| ()));
    let output = thread::spawn(move || read(stdout, maximum));
    let errors = thread::spawn(move || read(stderr, 65_536));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            waiting => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(if waiting.is_err() {
                    Failure::Io
                } else {
                    Failure::Timeout
                });
            }
        }
    };
    let written = writer.join().map_err(|_| Failure::Io)?;
    let stdout = output.join().map_err(|_| Failure::Io)??;
    let stderr = errors.join().map_err(|_| Failure::Io)??;
    if !status.success() {
        return Err(exit_failure(status.code(), &stderr));
    }
    if !stderr.is_empty() {
        return Err(Failure::UnexpectedStderr);
    }
    written.map_err(|()| Failure::Io)?;
    Ok(PrivateOutput(stdout))
}

fn exit_failure(status: Option<i32>, stderr: &[u8]) -> PrivateCaptureError {
    use PrivateCaptureError as Failure;

    let Some(255) = status else {
        return Failure::Exit(status.unwrap_or(-1));
    };
    let text = String::from_utf8_lossy(stderr);
    if text.contains("Host key verification failed")
        || text.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
    {
        Failure::HostKey
    } else if text.contains("agent refused operation") {
        Failure::AgentDenied
    } else if text.contains("Permission denied (publickey") {
        Failure::AuthenticationDenied
    } else if text.contains("Connection timed out")
        || text.contains("Operation timed out")
        || text.contains("Timeout, server ")
        || (text.contains("Connection to ") && text.contains("timed out"))
    {
        Failure::TransportTimeout
    } else if [
        "Connection refused",
        "Connection reset",
        "No route to host",
        "Network is unreachable",
        "Connection closed",
    ]
    .iter()
    .any(|marker| text.contains(marker))
    {
        Failure::TransportFailure
    } else {
        Failure::SshExit
    }
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
    fn detailed_capture_returns_closed_diagnostics_without_peer_text() {
        use PrivateCaptureError as Failure;
        for (source, expected) in [
            (
                "import sys;print('fixture secret',file=sys.stderr);sys.exit(23)",
                Failure::Exit(23),
            ),
            (
                "import sys;print('fixture secret',file=sys.stderr)",
                Failure::UnexpectedStderr,
            ),
            ("print('x'*8192)", Failure::OutputLimit),
            (
                "import sys;print('fixture agent refused operation',file=sys.stderr);sys.exit(255)",
                Failure::AgentDenied,
            ),
            (
                "import sys;print('fixture Permission denied (publickey).',file=sys.stderr);sys.exit(255)",
                Failure::AuthenticationDenied,
            ),
            (
                "import sys;print('fixture Connection timed out',file=sys.stderr);sys.exit(255)",
                Failure::TransportTimeout,
            ),
            (
                "import sys;print('fixture',file=sys.stderr);sys.exit(255)",
                Failure::SshExit,
            ),
        ] {
            let mut child = Command::new("python3");
            child.args(["-I", "-c", source]);
            let error = run_detailed(&mut child, &[], 64, Duration::from_secs(5)).unwrap_err();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains("fixture"));
        }
        let mut child = Command::new("python3");
        child.args(["-I", "-c", "import time;time.sleep(10)"]);
        assert_eq!(
            run_detailed(&mut child, &[], 64, Duration::from_millis(100)).unwrap_err(),
            Failure::Timeout
        );
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
