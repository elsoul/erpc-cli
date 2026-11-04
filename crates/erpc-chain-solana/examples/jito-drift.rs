// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Compares the Jito region table erpc carries with the docs page, saved to a
//! file first, so the check itself makes no request:
//!
//! ```text
//! curl -fsSL "$(jq -r .source crates/erpc-chain-solana/regions/jito.json)" -o page.html
//! cargo run -p erpc-chain-solana --example jito-drift -- page.html
//! ```
//!
//! Exits 0 when they agree, 1 with one line per difference when they do not,
//! and 2 when the page has no region table at all.

// A tool run by CI and by hand: printing is its output.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use erpc_chain_solana::regions::{drift, parse_docs, table};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: jito-drift <saved docs page>");
        std::process::exit(2);
    };
    let html = match std::fs::read_to_string(&path) {
        Ok(html) => html,
        Err(e) => {
            eprintln!("error: {path}: {e}");
            std::process::exit(2);
        }
    };
    let docs = parse_docs(&html);
    if docs.is_empty() {
        eprintln!("error: no region table in {path}; the page has changed shape");
        std::process::exit(2);
    }
    let changes = drift(table(), &docs);
    if changes.is_empty() {
        println!("the Jito table (read {}) matches the docs", table().read);
        return;
    }
    for change in &changes {
        println!("{change}");
    }
    std::process::exit(1);
}
