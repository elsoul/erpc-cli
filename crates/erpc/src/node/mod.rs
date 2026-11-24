// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The node command tree and what the chains' node commands share: the
//! dispatch (`tree`), the commands that are implemented (`nodes`), common
//! helpers, reaching a node's host (`host`), reports, help, and the opt-in
//! local check.

#[cfg(feature = "node-check-pilot")]
pub(crate) mod check;
pub(crate) mod common;
pub(crate) mod help;
pub(crate) mod host;
pub(crate) mod nodes;
pub(crate) mod report;
#[cfg(feature = "security-check-pilot")]
pub(crate) mod security;
pub(crate) mod tree;
