// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Immutable caller receipt for RPC firewall changes.

/// Caller-owned immutable operation token for firewall confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallToken {
    pub(crate) run: crate::RunId,
    pub(crate) bundle: String,
}
impl FirewallToken {
    /// Bind confirmation to the run and exact bundle submitted by this caller.
    /// # Errors
    /// Rejects malformed SHA-256, preventing shell interpolation of unchecked input.
    pub fn new(run: crate::RunId, bundle: &str) -> Result<Self, String> {
        if bundle.len() != 64
            || !bundle
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid firewall bundle digest".into());
        }
        Ok(Self {
            run,
            bundle: bundle.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn bundle_receipts_cannot_inject_shell_tokens() {
        let run = crate::RunId::new("r-20261026t120000-abc123").unwrap();
        for bad in [
            "",
            "abc; id",
            &"a".repeat(63),
            &"A".repeat(64),
            &format!("{};", "a".repeat(63)),
        ] {
            assert!(super::FirewallToken::new(run.clone(), bad).is_err());
        }
        assert!(super::FirewallToken::new(run, &"a".repeat(64)).is_ok());
    }
}
