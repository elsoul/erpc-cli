// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Rollup identity anchors from the clients' pinned upstream configurations.
use erpc_chain_rollup::profile::{Family, Profile};
use serde::Serialize;

/// An L2 block anchoring the selected rollup, distinct from L1 block zero.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Anchor {
    /// OP Mainnet starts at the Bedrock transition, not L2 block zero.
    pub number: u64,
    /// Required canonical hash at that block.
    pub hash: &'static str,
}

/// Anchor belonging to a profile already selected from the closed registry.
#[must_use]
pub fn anchor(profile: Profile) -> Option<Anchor> {
    Some(match (profile.family, profile.network) {
        (Family::Optimism, "mainnet") => Anchor {
            number: 105_235_063,
            hash: "0xdbf6a80fef073de06add9b0d14026d6e5a86c85f6d102c36d3d8e9cf89c2afd3",
        },
        (Family::Optimism, "sepolia") => Anchor {
            number: 0,
            hash: "0x102de6ffb001480cc9b8b548fd05c34cd4f46ae4aa91759393db90ea0409887d",
        },
        (Family::Base, "mainnet") => Anchor {
            number: 0,
            hash: "0xf712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd",
        },
        (Family::Base, "sepolia") => Anchor {
            number: 0,
            hash: "0x0dcc9e089e30b90ddfc55be9a37dd15bc551aeee999d2e2b51414c54eaf934e4",
        },
        (Family::Soneium, "mainnet") => Anchor {
            number: 0,
            hash: "0x295d22d269634c7d0055b33b887519362d0b31899e97109d1789a8a168de1b21",
        },
        (Family::Soneium, "minato") => Anchor {
            number: 0,
            hash: "0x7ec49d93fa8f47c00e98cc5965cd3903a8faa9238743d2eba0e0550ab4c45c43",
        },
        _ => return None,
    })
}
