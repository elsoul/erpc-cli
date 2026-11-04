// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed remote Nitro follower commands. Custody is accepted only on stdin.

/// The installed root-owned control helper; its request arrives on standard input.
pub(crate) const CONTROL: &str = "sudo -n /usr/local/lib/erpc/nitro-control";

/// Journal request, with no user-controlled unit name or signing material.
pub(crate) fn logs(robinhood: bool, lines: u32, follow: bool) -> String {
    let family = if robinhood { "robinhood" } else { "arbitrum" };
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} -u erpc-{family}-nitro -u erpc-{family}-upstreams{}",
        if follow { " -f" } else { "" }
    )
}

pub(crate) fn confirm(robinhood: bool, token: &crate::firewall::FirewallToken) -> String {
    let family = if robinhood { "robinhood" } else { "arbitrum" };
    format!(
        "sudo -n python3 /usr/local/lib/erpc/rpc-firewall.py {family} confirm {} {}",
        token.run.as_str(),
        token.bundle
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn control_has_no_secret_arguments() {
        assert_eq!(super::CONTROL, "sudo -n /usr/local/lib/erpc/nitro-control");
        assert!(!super::logs(false, 10, false).ends_with(" -f"));
        assert!(super::logs(true, 10, true).ends_with(" -f"));
    }
}
