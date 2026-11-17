// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The terminal around every command: messages and their languages,
//! errors and exit codes, prompts, the terminal's echo, interrupts,
//! opening a browser, and the full-screen interface.

#[macro_use]
pub(crate) mod i18n;
pub(crate) mod browser;
pub(crate) mod echo;
pub(crate) mod error;
pub(crate) mod interrupt;
pub(crate) mod long_commands;
pub(crate) mod prompt;
pub(crate) mod tui;
pub(crate) mod ui;
