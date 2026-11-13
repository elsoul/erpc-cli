// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the proxy counts, and the stats file it writes from the counts
//! ([`erpc_worker::waf::WafStats`]). Counts only: nothing of a request is
//! kept.

use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use erpc_worker::waf::{Blocked, WAF_FORMAT, WafStats};

use super::rules::Reason;

/// The counts, since the proxy started.
#[derive(Debug, Default)]
pub(super) struct Counters {
    requests: AtomicU64,
    forwarded: AtomicU64,
    upstream_errors: AtomicU64,
    blocked: [AtomicU64; Reason::ALL.len()],
}

impl Counters {
    /// A request was received.
    pub(super) fn request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// The app answered one.
    pub(super) fn forwarded(&self) {
        self.forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// The app did not answer one.
    pub(super) fn upstream_error(&self) {
        self.upstream_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// A request, or a connection, was refused for `reason`.
    pub(super) fn block(&self, reason: Reason) {
        if let Some(count) = Reason::ALL
            .iter()
            .position(|r| *r == reason)
            .and_then(|at| self.blocked.get(at))
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn blocked(&self, reason: Reason) -> u64 {
        Reason::ALL
            .iter()
            .position(|r| *r == reason)
            .and_then(|at| self.blocked.get(at))
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }

    /// The counts now, as the stats file holds them.
    pub(super) fn snapshot(&self, since: &str, banned_now: u64) -> WafStats {
        WafStats {
            format: WAF_FORMAT,
            since: since.to_owned(),
            requests: self.requests.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            blocked: Blocked {
                method: self.blocked(Reason::Method),
                path: self.blocked(Reason::Path),
                denied: self.blocked(Reason::Denied),
                not_allowed: self.blocked(Reason::NotAllowed),
                probe: self.blocked(Reason::Probe),
                rate: self.blocked(Reason::Rate),
                body: self.blocked(Reason::Body),
                malformed: self.blocked(Reason::Malformed),
                banned: self.blocked(Reason::Banned),
                connections: self.blocked(Reason::Connections),
                upgrade: self.blocked(Reason::Upgrade),
                body_timeout: self.blocked(Reason::BodyTimeout),
            },
            banned_now,
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
        }
    }
}

/// Writes the stats file whole: beside it first, then in its place, so
/// that a reader sees the file before or the file after and never half of
/// one. Readable by every user; it holds counts.
pub(super) fn write(path: &Path, stats: &WafStats) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut text = serde_json::to_vec(stats)?;
    text.push(b'\n');
    let mut beside = path.as_os_str().to_owned();
    beside.push(".tmp");
    let beside = Path::new(&beside);
    let written = (|| {
        let mut file = std::fs::File::create(beside)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        file.write_all(&text)?;
        file.flush()?;
        std::fs::rename(beside, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(beside);
    }
    written
}

/// Seconds since the epoch as RFC 3339 UTC: `2026-11-11T09:00:00Z`.
pub(super) fn rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Howard Hinnant's days-to-civil, for the proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use erpc_worker::waf::WafStats;

    use super::{Counters, Reason, rfc3339, write};

    #[test]
    fn each_block_is_counted_under_its_own_name() {
        let counters = Counters::default();
        counters.request();
        counters.request();
        counters.request();
        counters.forwarded();
        counters.upstream_error();
        // One of the first, two of the second, and so on: none is counted
        // under another's name.
        for (n, reason) in Reason::ALL.iter().enumerate() {
            for _ in 0..=n {
                counters.block(*reason);
            }
        }
        let stats = counters.snapshot("2026-11-11T09:00:00Z", 4);
        let json = serde_json::to_value(&stats).expect("json");
        for (n, reason) in Reason::ALL.iter().enumerate() {
            assert_eq!(
                json["blocked"][reason.name()],
                u64::try_from(n + 1).expect("small"),
                "{}",
                reason.name()
            );
        }
        assert_eq!(
            json["blocked"].as_object().expect("an object").len(),
            Reason::ALL.len()
        );
        assert_eq!(json["format"], 1);
        assert_eq!(json["since"], "2026-11-11T09:00:00Z");
        assert_eq!(json["requests"], 3);
        assert_eq!(json["forwarded"], 1);
        assert_eq!(json["upstream_errors"], 1);
        assert_eq!(json["banned_now"], 4);
    }

    #[test]
    fn the_stats_file_is_replaced_whole_and_is_readable_by_others() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("stats.json");
        let counters = Counters::default();
        write(&path, &counters.snapshot("2026-11-11T09:00:00Z", 0)).expect("first");
        counters.request();
        counters.block(Reason::Probe);
        write(&path, &counters.snapshot("2026-11-11T09:00:00Z", 1)).expect("second");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.ends_with('\n'));
        let stats = WafStats::parse(&text).expect("the file is the shared type");
        assert_eq!(
            (stats.requests, stats.blocked.probe, stats.banned_now),
            (1, 1, 1)
        );
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        // Nothing is left beside it.
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .expect("dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(left, ["stats.json"]);
        // Where it cannot be written, that is said, and nothing is left.
        let missing = dir.path().join("absent").join("stats.json");
        assert!(write(&missing, &counters.snapshot("x", 0)).is_err());
    }

    #[test]
    fn a_time_is_written_as_rfc_3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_794_387_599), "2026-11-11T08:59:59Z");
        assert_eq!(rfc3339(1_794_387_600), "2026-11-11T09:00:00Z");
        assert_eq!(rfc3339(4_102_444_799), "2099-12-31T23:59:59Z");
    }
}
