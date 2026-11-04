// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin's fixed owned-host operations. No cookie or wallet material leaves the host.

/// Fixed controller entry point; ownership/network/retention request travels on stdin.
pub(crate) const CONTROL: &str = "sudo -n /usr/local/lib/erpc/bitcoin-control";

/// Bounded journal read, after the caller has verified the host contract.
pub(crate) fn logs(lines: u32, follow: bool) -> String {
    format!(
        "sudo -n journalctl --no-pager -o short-iso -u erpc-bitcoin -n {lines}{}",
        if follow { " -f" } else { "" }
    )
}
