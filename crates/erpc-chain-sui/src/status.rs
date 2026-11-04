// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Readiness is checkpoint execution plus gRPC availability and the correct genesis.
use serde::Serialize;

/// Observations collected from the node's own loopback interfaces.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    /// systemd active state.
    pub service: String,
    /// Chain identifier extracted from the uptime metric.
    pub chain_id: String,
    /// Latest downloaded checkpoint.
    pub synced: Option<u64>,
    /// Latest executed checkpoint.
    pub executed: Option<u64>,
    /// Latest executed checkpoint after a second observation.
    pub later_executed: Option<u64>,
    /// gRPC health probe returned a successful frame and grpc-status 0.
    pub grpc: bool,
    /// Seconds since the last executed checkpoint, absent for unknown/future timestamps.
    pub checkpoint_age_seconds: Option<u64>,
    /// Currently selected release directory.
    pub release: String,
}
impl Status {
    /// Parse the bounded remote probe result. Missing/malformed values stay unknown.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut s = Self::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k {
                "service" => v.clone_into(&mut s.service),
                "chain_id" => v.clone_into(&mut s.chain_id),
                "synced" => s.synced = v.parse().ok(),
                "executed" => s.executed = v.parse().ok(),
                "later_executed" => s.later_executed = v.parse().ok(),
                "grpc" => s.grpc = v == "ok",
                "checkpoint_age_seconds" => s.checkpoint_age_seconds = v.parse().ok(),
                "release" => v.clone_into(&mut s.release),
                _ => {}
            }
        }
        s
    }
    /// Conservatively admit RPC only for correct identity, advancing execution and bounded lag.
    #[must_use]
    pub fn ready(&self, chain: &str) -> bool {
        self.checkpoint_age_seconds.is_some_and(|age| age <= 60)
            && self.service == "active"
            && self.chain_id == chain
            && self.grpc
            && matches!((self.synced,self.executed,self.later_executed), (Some(s),Some(e),Some(l)) if l > e && s.saturating_sub(l) <= 20)
    }
}
#[cfg(test)]
mod tests {
    use super::Status;
    #[test]
    fn liveness_is_not_readiness() {
        let mut s = Status::parse(
            "service=active\nchain_id=4c78adac\nsynced=120\nexecuted=118\nlater_executed=119\ngrpc=ok\ncheckpoint_age_seconds=5\n",
        );
        assert!(s.ready("4c78adac"));
        assert!(!s.ready("35834a8a"));
        s.later_executed = s.executed;
        assert!(!s.ready("4c78adac"));
        s.later_executed = Some(119);
        s.grpc = false;
        assert!(!s.ready("4c78adac"));
        assert!(!Status::parse("service=active\nexecuted=oops").ready("4c78adac"));
    }
}
