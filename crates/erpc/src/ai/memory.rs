// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc memory`: what `erpc ai` remembers about the user between
//! conversations ([`erpc_ai::memory`]), to read and to delete.

use erpc_ai::memory::Memory;
use serde_json::json;

use crate::commands::Outcome;

/// The memory: `memory.json` beside the config.
pub(crate) fn store() -> Result<Memory, String> {
    crate::session::beside_config("memory.json").map(Memory::at)
}

/// `erpc memory list`.
pub(crate) fn list(json_out: bool) -> Outcome {
    let memory = match store() {
        Ok(memory) => memory,
        Err(e) => return Outcome::Failed(e),
    };
    let facts = match memory.facts() {
        Ok(facts) => facts,
        Err(e) => return Outcome::Failed(e),
    };
    if json_out {
        crate::print_json(&json!({
            "path": memory.path().display().to_string(),
            "facts": facts.iter().map(|f| json!({ "id": f.id, "text": f.text, "saved": f.saved })).collect::<Vec<_>>(),
        }));
        return Outcome::Done(String::new());
    }
    if facts.is_empty() {
        return Outcome::Done(t!("memory.empty"));
    }
    let mut lines: Vec<String> = facts
        .iter()
        .map(|f| format!("{:>4}  {}", f.id, f.text))
        .collect();
    lines.push(format!(
        "\n{}",
        t!("memory.kept_in", path = memory.path().display())
    ));
    Outcome::Done(lines.join("\n"))
}

/// `erpc memory forget <id>`.
pub(crate) fn forget(json_out: bool, id: u32) -> Outcome {
    let result = store().and_then(|memory| memory.forget(id));
    match result {
        Ok(found) if json_out => {
            crate::print_json(&json!({ "forgotten": found, "id": id }));
            Outcome::Done(String::new())
        }
        Ok(true) => Outcome::Done(t!("memory.forgot", id)),
        Ok(false) => Outcome::Usage(t!("memory.no_such", id)),
        Err(e) => Outcome::Failed(e),
    }
}

/// `erpc memory clear`.
pub(crate) fn clear(json_out: bool) -> Outcome {
    match store().and_then(|memory| memory.clear()) {
        Ok(()) if json_out => {
            crate::print_json(&json!({ "cleared": true }));
            Outcome::Done(String::new())
        }
        Ok(()) => Outcome::Done(t!("memory.cleared")),
        Err(e) => Outcome::Failed(e),
    }
}
