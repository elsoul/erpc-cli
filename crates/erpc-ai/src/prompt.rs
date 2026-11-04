// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the assistant is told before the conversation: who it is, how to
//! answer, what erpc can do, and which skills it can read.
//!
//! The skills themselves are in `erpc-skills`. Only their names and
//! descriptions are sent here; the model reads one with the `read_skill`
//! tool when a question needs it, so a skill for every chain costs a line
//! each until it is used. The prompt does not change between turns, so it
//! is read from the cache after the first one.

/// Who the assistant is and how it answers.
pub const BASE: &str = include_str!("../skills/base.md");

/// The system prompt: the base, the computer erpc runs on, then the
/// command reference, then the skills to choose from. The command reference is produced from the CLI
/// definition by the caller, so it lists exactly the commands this binary
/// has.
#[must_use]
pub fn system(command_reference: &str) -> Vec<String> {
    vec![
        BASE.to_owned(),
        format!(
            "{}\n\n# Command reference\n\n{command_reference}\n\n# Skills\n\nRead the skill \
             that fits with `read_skill` before answering about its subject.\n\n{}",
            computer(std::env::consts::OS, std::env::consts::ARCH),
            erpc_skills::index()
        ),
    ]
}

/// What the model is told about the computer `run_command` runs on, so it
/// picks that system's commands rather than guess. The same for every turn
/// of one binary, so the cache holds.
fn computer(os: &str, arch: &str) -> String {
    let (name, hint) = match os {
        "macos" => (
            "macOS",
            " Use macOS commands: vm_stat and sysctl hw.memsize vm.swapusage for memory, \
             sysctl -n hw.ncpu and machdep.cpu.brand_string for the CPU, sw_vers for the \
             version; there is no free, lscpu, ip, ss, systemctl, journalctl or /proc.",
        ),
        "linux" => ("Linux", ""),
        "windows" => (
            "Windows",
            " Most of the commands that run without asking are not there.",
        ),
        other => (other, ""),
    };
    format!(
        "# This computer\n\nerpc runs on {name} ({arch}), and `run_command` runs there, not on \
         the user's servers.{hint}"
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_prompt_says_which_system_commands_run_on() {
        let mac = super::computer("macos", "aarch64");
        assert!(
            mac.contains("macOS (aarch64)") && mac.contains("vm_stat"),
            "{mac}"
        );
        assert!(super::computer("linux", "x86_64").contains("Linux (x86_64)"));
        assert!(
            super::system("")
                .iter()
                .any(|block| block.contains("# This computer"))
        );
    }
}
