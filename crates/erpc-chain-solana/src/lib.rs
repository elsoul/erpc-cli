// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-chain-solana`: Solana validator and RPC node operations for the erpc CLI.
//!
//! The playbooks that set up and run a node are SLV's, at the version
//! `templates/PROVENANCE.md` names, and they are carried in the binary. A
//! deploy therefore runs exactly the files this version of erpc was built and
//! tested with: nothing is downloaded at the time of use, and no template
//! version can drift out of step with the binary.
//!
//! The node runs them itself (`ansible-playbook -c local`); erpc only sends
//! them. Which files are here is fixed by a test: everything the entry plays
//! reach, and nothing else.

#![forbid(unsafe_code)]

use include_dir::{Dir, include_dir};

pub mod cli;
pub mod crypt;
pub mod github;
pub mod identity;
pub mod regions;
pub mod rpc;
mod validator_json;
pub mod validator_observer;
pub mod validator_profile;
pub mod vars;
pub mod versions;
pub mod vote;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-chain-solana";

/// The template tree: `ansible/`, `jinja/`, `NOTICE` and `PROVENANCE.md`.
pub static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// The plays erpc starts a run with, relative to the template root.
pub mod plays {
    /// Short firewall preparation, confirmed before deployment starts.
    pub const MAINNET_RPC_FIREWALL: &str = "ansible/erpc-mainnet-rpc/firewall.yml";
    /// Makes the `solv` user every later play runs as.
    pub const CREATE_USER: &str = "ansible/erpc-testnet-validator/create_user.yml";
    /// Sets a testnet validator up and starts it, sync-only.
    pub const TESTNET_VALIDATOR_DEPLOY: &str = "ansible/erpc-testnet-validator/deploy.yml";
    /// Sets a mainnet validator up and starts it, sync-only.
    pub const MAINNET_VALIDATOR_DEPLOY: &str = "ansible/erpc-mainnet-validator/deploy.yml";
    /// Sets a mainnet RPC node up, starts it and applies its firewall.
    pub const MAINNET_RPC_DEPLOY: &str = "ansible/erpc-mainnet-rpc/deploy.yml";
    /// Builds an RPC node's newly pinned client and restarts it onto it.
    pub const MAINNET_RPC_UPDATE: &str = "ansible/erpc-mainnet-rpc/update.yml";
    /// Writes an RPC node's startup and firewall again from the inventory.
    pub const MAINNET_RPC_CONFIG: &str = "ansible/erpc-mainnet-rpc/config.yml";
    /// Stops an RPC node and removes its services and firewall.
    pub const MAINNET_RPC_DESTROY: &str = "ansible/erpc-mainnet-rpc/destroy.yml";
    /// Every play erpc starts a run with.
    pub const ALL: [&str; 8] = [
        CREATE_USER,
        TESTNET_VALIDATOR_DEPLOY,
        MAINNET_VALIDATOR_DEPLOY,
        MAINNET_RPC_FIREWALL,
        MAINNET_RPC_DEPLOY,
        MAINNET_RPC_UPDATE,
        MAINNET_RPC_CONFIG,
        MAINNET_RPC_DESTROY,
    ];
}

/// What erpc adds to the template tree to make a run's bundle. See
/// `docs/porting/ansible-controller-deps.md` for why each is needed.
pub mod bundle {
    /// The files the plays read from `{{ playbook_dir }}/../../vars/`, which
    /// SLV kept on the operator's machine.
    pub const VARS_FILES: [&str; 2] = ["vars/versions.yml", "vars/config.pwd.yml"];
    /// The host variables erpc sets beyond the inventory's own.
    pub const INJECTED_HOST_VARS: [&str; 1] = ["solv_authorized_key"];
    /// Where the disk rule the deploy plays check again is put in a bundle.
    pub const FREE_DISKS: &str = "files/free-disks.sh";
}

/// A file of the template tree, by its path from the root.
#[must_use]
pub fn file(path: &str) -> Option<&'static [u8]> {
    TEMPLATES.get_file(path).map(include_dir::File::contents)
}

/// Every file of the template tree, as paths from the root, sorted.
#[must_use]
pub fn files() -> Vec<&'static str> {
    let mut out = Vec::new();
    collect(&TEMPLATES, &mut out);
    out.sort_unstable();
    out
}

fn collect(dir: &'static Dir<'static>, out: &mut Vec<&'static str>) {
    for entry in dir.files() {
        if let Some(path) = entry.path().to_str() {
            out.push(path);
        }
    }
    for sub in dir.dirs() {
        collect(sub, out);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{file, files, plays};

    /// Files that describe the tree rather than take part in a run.
    const DOCUMENTS: [&str; 2] = ["NOTICE", "PROVENANCE.md"];

    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }

    /// `a/b/../c` → `a/c`.
    fn normalise(path: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                other => parts.push(other),
            }
        }
        parts.join("/")
    }

    fn has_extension(path: &str, extension: &str) -> bool {
        std::path::Path::new(path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case(extension))
    }

    fn dir_of(path: &str) -> &str {
        path.rsplit_once('/').map_or("", |(dir, _)| dir)
    }

    /// The value after `key` on a line, unquoted, unless it is templated.
    fn value_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        let (_, rest) = line.split_once(key)?;
        let value = rest.trim().trim_matches(['"', '\'']);
        (!value.is_empty() && !value.contains("{{")).then_some(value)
    }

    /// The Jinja templates a play names: `…/jinja/<dir>/<file>.j2`; SLV's
    /// operator-side copies `~/.slv/<dir>/<file>.j2`, which are copies of the
    /// same files; and list items `- <dir>/<file>.j2`, which a loop over
    /// `…/jinja/{{ item }}` checks for.
    fn templates_named(text: &str) -> Vec<String> {
        let mut out: Vec<String> = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("- "))
            .filter(|item| has_extension(item, "j2") && item.contains('/') && !item.contains(' '))
            .map(|item| format!("jinja/{item}"))
            .collect();
        for marker in ["jinja/", "~/.slv/"] {
            let mut rest = text;
            while let Some(at) = rest.find(marker) {
                let tail = &rest[at + marker.len()..];
                let end = tail
                    .find(|c: char| !(c.is_ascii_alphanumeric() || "._-/".contains(c)))
                    .unwrap_or(tail.len());
                let name = &tail[..end];
                if has_extension(name, "j2") {
                    out.push(format!("jinja/{name}"));
                }
                rest = tail;
            }
        }
        out
    }

    /// Everything the entry plays reach: imported and included plays and task
    /// files, and the templates they name.
    fn closure() -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut queue: Vec<String> = plays::ALL.iter().map(|p| (*p).to_owned()).collect();
        while let Some(path) = queue.pop() {
            if !seen.insert(path.clone()) || !has_extension(&path, "yml") {
                continue;
            }
            let bytes = file(&path).unwrap_or_else(|| panic!("{path} is reached but not embedded"));
            let text = std::str::from_utf8(bytes).expect("plays are UTF-8");
            for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
                for key in ["import_playbook:", "include_tasks:", "import_tasks:"] {
                    if let Some(target) = value_after(line, key) {
                        queue.push(normalise(&format!("{}/{target}", dir_of(&path))));
                    }
                }
                // A copy from the play's own `files/`, as Ansible finds it.
                if let Some(target) = value_after(line, "src: files/") {
                    queue.push(normalise(&format!("{}/files/{target}", dir_of(&path))));
                }
            }
            queue.extend(templates_named(text));
        }
        seen
    }

    #[test]
    fn the_embedded_files_are_exactly_what_the_entry_plays_reach() {
        let reached = closure();
        let embedded: BTreeSet<String> = files()
            .into_iter()
            .filter(|f| !DOCUMENTS.contains(f))
            .map(str::to_owned)
            .collect();
        let unused: Vec<_> = embedded.difference(&reached).collect();
        let missing: Vec<_> = reached.difference(&embedded).collect();
        assert!(unused.is_empty(), "embedded but never reached: {unused:?}");
        assert!(missing.is_empty(), "reached but not embedded: {missing:?}");
    }

    #[test]
    fn no_play_that_is_left_out_is_carried() {
        for path in files() {
            for word in [
                "copy_keys",
                "copy_rpc_keys",
                "doublezero",
                "richat_build",
                "install_richat",
            ] {
                assert!(!path.contains(word), "{path} should not be carried");
            }
        }
    }

    #[test]
    fn every_vendored_file_matches_the_digest_in_its_provenance() {
        use sha2::{Digest as _, Sha256};
        let provenance =
            std::str::from_utf8(file("PROVENANCE.md").expect("provenance")).expect("UTF-8");
        let hex = |bytes: &[u8]| {
            Sha256::digest(bytes)
                .iter()
                .fold(String::new(), |mut out, b| {
                    use core::fmt::Write as _;
                    let _ = write!(out, "{b:02x}");
                    out
                })
        };
        let mut checked = 0;
        for path in files() {
            if DOCUMENTS.contains(&path)
                || path.starts_with("ansible/erpc-")
                || path.starts_with("jinja/erpc-")
            {
                continue;
            }
            let row = provenance
                .lines()
                .find(|l| l.starts_with(&format!("| `{path}` |")))
                .unwrap_or_else(|| panic!("{path} has no row in PROVENANCE.md"));
            let digest = hex(file(path).expect("embedded"));
            assert!(
                row.contains(&digest),
                "{path} changed without its row: {row}"
            );
            checked += 1;
        }
        assert!(checked > 20, "only {checked} files checked");
    }

    #[test]
    fn no_play_erpc_wrote_runs_a_free_form_multi_line_shell() {
        // Ansible splits a free-form `shell: |` like key=value arguments, so
        // one apostrophe in it, even in a comment, fails the run; a task file
        // reached by include_tasks is not parsed by --syntax-check. SLV's
        // own plays are carried as they are and ran so in SLV.
        for path in files()
            .into_iter()
            .filter(|p| p.starts_with("ansible/erpc-") && has_extension(p, "yml"))
        {
            for (n, line) in play_text(path).lines().enumerate() {
                let t = line.trim_start();
                let free_form = [
                    "shell:",
                    "command:",
                    "ansible.builtin.shell:",
                    "ansible.builtin.command:",
                ]
                .iter()
                .any(|k| {
                    t.strip_prefix(k)
                        .is_some_and(|rest| matches!(rest.trim(), "|" | "|-" | ">" | ">-"))
                });
                assert!(
                    !free_form,
                    "{path}:{}: use `cmd: |` under the module",
                    n + 1
                );
            }
        }
    }

    fn play_text(path: &str) -> &'static str {
        std::str::from_utf8(file(path).expect("embedded")).expect("UTF-8")
    }

    fn carried_plays() -> Vec<&'static str> {
        files()
            .into_iter()
            .filter(|f| has_extension(f, "yml"))
            .collect()
    }

    /// The lines that read from the operator's machine, outside comments.
    fn controller_reads(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter(|l| {
                [
                    "~/.slv",
                    "lookup('env'",
                    "lookup('file'",
                    "lookup('ansible.builtin.file'",
                    "delegate_to",
                ]
                .iter()
                .any(|needle| l.contains(needle))
            })
            .collect()
    }

    #[test]
    fn no_play_reads_from_the_operators_machine() {
        // The one kept case: the bootstrap check stats and reads the carried
        // startup templates through localhost, which on the node is the node.
        const KEPT: &str = "ansible/cmn/tasks/validator_bootstrap.yml";
        for play in carried_plays() {
            let reads = controller_reads(play_text(play));
            if play == KEPT {
                assert_eq!(reads.len(), 3, "{play}: {reads:#?}");
                assert!(
                    reads
                        .iter()
                        .all(|l| !l.contains("~/.slv") && !l.contains("lookup('env'"))
                );
            } else {
                assert!(
                    reads.is_empty(),
                    "{play} still reads the controller: {reads:#?}"
                );
            }
        }
    }

    #[test]
    fn the_bundle_vars_files_are_exactly_the_ones_the_plays_read() {
        const MARKER: &str = "{{ playbook_dir }}/../../";
        let mut read = BTreeSet::new();
        for play in carried_plays() {
            let mut rest = play_text(play);
            while let Some(at) = rest.find(MARKER) {
                let tail = &rest[at + MARKER.len()..];
                let end = tail.find(['"', '\'', ' ', '\n']).unwrap_or(tail.len());
                if let Some(name) = tail[..end].strip_prefix("vars/") {
                    read.insert(format!("vars/{name}"));
                }
                rest = tail;
            }
        }
        let written: BTreeSet<String> = super::bundle::VARS_FILES
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(read, written);
    }

    #[test]
    fn the_injected_key_is_checked_before_it_is_used() {
        let play = play_text("ansible/cmn/create_user.yml");
        for var in super::bundle::INJECTED_HOST_VARS {
            let checked = play.find(&format!("{var} | default('', true) | string is match("));
            let used = play.find(&format!("line: \"{{{{ {var} }}}}\""));
            assert!(
                matches!((checked, used), (Some(c), Some(u)) if c < u),
                "{var}"
            );
        }
    }

    #[test]
    fn every_changed_file_is_explained_in_the_porting_table() {
        let table = include_str!("../../../docs/porting/ansible-controller-deps.md");
        let provenance = play_text("PROVENANCE.md");
        let changed: Vec<&str> = provenance
            .lines()
            .filter(|l| l.starts_with("| `") && !l.ends_with("| unchanged |"))
            .filter_map(|l| l.strip_prefix("| `")?.split('`').next())
            // The plays erpc wrote are explained in their own section.
            .filter(|path| !path.starts_with("ansible/erpc-") && !path.starts_with("jinja/erpc-"))
            .collect();
        assert!(changed.len() >= 8, "{changed:?}");
        for path in changed {
            let short = path.rsplit_once('/').map_or(path, |(_, name)| name);
            assert!(
                table.contains(short),
                "{path} is changed but not in the table"
            );
        }
    }

    #[test]
    fn the_entry_plays_sit_where_the_plays_expect_the_templates() {
        // The plays find the templates at {{ playbook_dir }}/../../jinja,
        // and playbook_dir is the directory of the entry play.
        for play in plays::ALL {
            let jinja = normalise(&format!("{}/../../jinja", dir_of(play)));
            assert_eq!(jinja, "jinja", "{play}");
        }
    }
}
