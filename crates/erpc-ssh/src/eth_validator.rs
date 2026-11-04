// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed remote Ethereum validator commands. Custody is accepted only on stdin.

/// The installed root-owned control helper; its request arrives on standard input.
pub(crate) const CONTROL: &str = "sudo -n /usr/local/lib/erpc/eth-validator-control";

/// Journal request, with no user-controlled unit name or signing material.
pub(crate) fn logs(lines: u32, follow: bool) -> String {
    format!(
        "sudo -n journalctl --no-pager -o short-iso -n {lines} -u erpc-eth-validator -u erpc-eth-beacon -u erpc-eth-execution{}",
        if follow { " -f" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn control_has_no_secret_arguments() {
        assert_eq!(
            super::CONTROL,
            "sudo -n /usr/local/lib/erpc/eth-validator-control"
        );
        assert!(!super::logs(10, false).ends_with(" -f"));
        assert!(super::logs(10, true).ends_with(" -f"));
    }
}
