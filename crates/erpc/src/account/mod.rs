// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The operator's account and this machine's part in it: logging in and
//! out, the session store, `erpc doctor`, the config and keyless files,
//! account secrets, and the wallet `erpc ai` pays credit top-ups from.

pub(crate) mod account_secret;
pub(crate) mod commands;
pub(crate) mod config;
pub(crate) mod credit_wallet;
pub(crate) mod doctor;
pub(crate) mod keyless;
pub(crate) mod session;
