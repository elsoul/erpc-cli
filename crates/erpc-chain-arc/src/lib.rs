// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-chain-arc`: Arc RPC node operations for the erpc CLI.
//!
//! An Arc node is two processes on one host: the execution layer
//! (`arc-node-execution`, Reth based), which serves JSON-RPC, and the
//! consensus layer (`arc-node-consensus`), which follows the chain through
//! public relays and drives the execution layer over IPC. This crate holds
//! what erpc knows about them: the networks, the releases and how one is
//! pinned, the consensus key, and the plays a node runs to set itself up,
//! carried in the binary like the Solana ones.

#![forbid(unsafe_code)]

use include_dir::{Dir, include_dir};

pub mod key;
pub mod kind;
pub mod network;
pub mod releases;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-chain-arc";

/// The template tree: `ansible/` and `jinja/`.
pub static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// The plays erpc starts a run with, relative to the template root.
pub mod plays {
    /// Short firewall preparation, confirmed before deployment starts.
    pub const FIREWALL: &str = "ansible/arc-rpc/firewall.yml";
    /// Prepares the host: packages, the `arc` user, the data disk, kernel
    /// and journal settings.
    pub const INIT: &str = "ansible/arc-rpc/init.yml";
    /// Installs the pinned release, fetches snapshots, starts both layers
    /// and applies the firewall; again for `update-config`.
    pub const DEPLOY: &str = "ansible/arc-rpc/deploy.yml";
    /// Moves a running node to the pinned release, rolling back on failure.
    pub const UPDATE: &str = "ansible/arc-rpc/update.yml";
    /// Removes what deploy put on the host.
    pub const DESTROY: &str = "ansible/arc-rpc/destroy.yml";
}

/// What erpc adds to the template tree to make a run's bundle.
pub mod bundle {
    /// The free-disk rule `init.yml` checks again before it wipes a disk:
    /// the script erpc ran before asking the operator.
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
    use super::{file, files, plays};

    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }

    fn text(path: &str) -> String {
        String::from_utf8(file(path).expect(path).to_vec()).expect("UTF-8")
    }

    fn is_yaml(path: &str) -> bool {
        std::path::Path::new(path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("yml"))
    }

    /// Every play, task file and vars file as one text.
    fn all_yaml() -> String {
        files()
            .into_iter()
            .filter(|p| is_yaml(p))
            .map(text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn everything_the_plays_name_is_carried() {
        let yaml = all_yaml();
        for (i, _) in yaml.match_indices("tasks/") {
            let name: String = yaml[i..]
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '"')
                .collect();
            if is_yaml(&name) {
                let path = format!("ansible/arc-rpc/{name}");
                assert!(file(&path).is_some(), "{path} is named but not carried");
            }
        }
        let marker = "{{ arc_jinja }}/";
        for (i, _) in yaml.match_indices(marker) {
            let name: String = yaml[i + marker.len()..]
                .chars()
                .take_while(|c| *c != '"')
                .collect();
            if !name.starts_with("{{") {
                assert!(
                    file(&format!("jinja/{name}")).is_some(),
                    "{name} is named but not carried"
                );
            }
        }
        for play in [
            plays::INIT,
            plays::FIREWALL,
            plays::DEPLOY,
            plays::UPDATE,
            plays::DESTROY,
        ] {
            assert!(file(play).is_some(), "{play}");
        }
    }

    #[test]
    fn every_carried_file_is_named_by_a_play() {
        let yaml = all_yaml();
        for path in files() {
            let named = if let Some(template) = path.strip_prefix("jinja/") {
                let stem = template.trim_end_matches(".j2");
                yaml.contains(template) || yaml.contains(&format!("- {stem}\n"))
            } else if let Some(task) = path.strip_prefix("ansible/arc-rpc/tasks/") {
                yaml.contains(&format!("tasks/{task}"))
            } else {
                path.strip_prefix("ansible/arc-rpc/")
                    .is_some_and(|name| yaml.contains(&format!("import_playbook: {name}")))
                    || path == "README.md"
                    || path == "ansible/arc-rpc/vars.yml"
                    || [
                        plays::INIT,
                        plays::FIREWALL,
                        plays::DEPLOY,
                        plays::UPDATE,
                        plays::DESTROY,
                    ]
                    .contains(&path)
            };
            assert!(named, "{path} is carried but no play names it");
        }
    }

    #[test]
    fn no_shell_script_is_split_as_free_form_arguments() {
        // Ansible splits a free-form `shell: |` like `k=v` arguments, so an
        // apostrophe in a comment ("a run's table") fails the task at run
        // time, which --syntax-check does not reach. Scripts go in `cmd:`.
        for path in files().into_iter().filter(|p| is_yaml(p)) {
            for (n, line) in text(path).lines().enumerate() {
                let line = line.trim();
                let free_form = ["shell:", "command:"].iter().any(|m| {
                    line.split_once(m)
                        .is_some_and(|(_, rest)| rest.trim_start().starts_with(['|', '>']))
                });
                assert!(!free_form, "{path}:{}: {line}", n + 1);
            }
        }
    }

    #[test]
    fn the_only_urls_in_the_tree_are_the_nodes_own_loopback() {
        for path in files() {
            let body = text(path).replace("http://127.0.0.1", "");
            // The URLs a node fetches come in through the inventory: the
            // release archive and the relays.
            assert!(!body.contains("http://"), "{path}");
            assert!(!body.contains("https://"), "{path}");
        }
    }
}
