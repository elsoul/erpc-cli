// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-chain-eth`: Ethereum RPC node operations for the erpc CLI.
//!
//! An Ethereum RPC node is two processes on one host: Reth, the execution
//! layer, which serves JSON-RPC, and Lighthouse, the consensus layer, which
//! drives it over the engine API. This crate holds what erpc knows about
//! them: the networks, the kinds of node, the releases and how a pair is
//! pinned, the keys that sign the releases, and the plays a node runs to set
//! itself up, carried in the binary like the Solana and Arc ones.

#![forbid(unsafe_code)]

use include_dir::{Dir, include_dir};

pub mod authority;
pub mod deposit;
pub mod kind;
pub mod network;
pub mod releases;
pub mod validator;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-chain-eth";

/// The template tree: `ansible/`, `jinja/` and `gpg/`.
pub static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// The plays erpc starts a run with, relative to the template root.
pub mod plays {
    /// Short firewall preparation, confirmed before deployment starts.
    pub const FIREWALL: &str = "ansible/eth-rpc/firewall.yml";
    /// Prepares the host: checks, packages, users, the data disk, kernel and
    /// journal settings.
    pub const INIT: &str = "ansible/eth-rpc/init.yml";
    /// Installs the pinned pair, fetches Reth's snapshot, starts both layers
    /// and applies the firewall; again for `update-config`.
    pub const DEPLOY: &str = "ansible/eth-rpc/deploy.yml";
    /// Moves a running node to the pinned pair without lowering its database source floor.
    pub const UPDATE: &str = "ansible/eth-rpc/update.yml";
    /// Retires owned services while retaining original data and authority.
    pub const DESTROY: &str = "ansible/eth-rpc/destroy.yml";
    /// Bind independent original filesystem UUID evidence without deployment.
    pub const UPGRADE_VOLUME: &str = "ansible/eth-rpc/upgrade-volume.yml";
    /// Stop and archive one explicitly named interrupted original operation.
    pub const RECOVER: &str = "ansible/eth-rpc/recover.yml";
    /// Import original numeric authority from independently retained host records.
    pub const MIGRATE: &str = "ansible/eth-rpc/migrate.yml";
    /// Every play erpc starts a run with.
    pub const ALL: [&str; 8] = [
        INIT,
        FIREWALL,
        DEPLOY,
        UPDATE,
        DESTROY,
        RECOVER,
        MIGRATE,
        UPGRADE_VOLUME,
    ];
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
    use crate::releases::Client;

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
                let path = format!("ansible/eth-rpc/{name}");
                assert!(file(&path).is_some(), "{path} is named but not carried");
            }
        }
        let marker = "{{ eth_jinja }}/";
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
        for play in plays::ALL {
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
            } else if let Some(task) = path.strip_prefix("ansible/eth-rpc/tasks/") {
                yaml.contains(&format!("tasks/{task}"))
            } else if path.starts_with("gpg/") {
                Client::ALL
                    .iter()
                    .any(|c| path == format!("gpg/{}.asc", c.name()))
            } else if let Some(member) = path.strip_prefix("authority/") {
                (crate::authority::PROFILE.contains(&member)
                    && yaml.contains("../../authority/control.py"))
                    || (crate::authority::VALIDATOR_PROFILE.contains(&member)
                        && yaml.contains("../authority/eth_validator_control.py"))
            } else {
                path.strip_prefix("ansible/eth-rpc/")
                    .is_some_and(|name| yaml.contains(&format!("import_playbook: {name}")))
                    || path == "ansible/eth-rpc/vars.yml"
                    || plays::ALL.contains(&path)
                    || (path == "validator/install_release.yml"
                        && yaml.contains("ansible.builtin.include_tasks: install_release.yml"))
                    || [
                        "validator/control.py",
                        "validator/time_service.py",
                        "validator/deploy.yml",
                        "validator/migrate.yml",
                        "validator/execution.service.j2",
                        "validator/beacon.service.j2",
                        "validator/validator.service.j2",
                    ]
                    .contains(&path)
            };
            assert!(named, "{path} is carried but no play names it");
        }
    }

    #[test]
    fn no_play_runs_a_free_form_multi_line_shell() {
        // Ansible splits a free-form `shell: |` like key=value arguments, so
        // one apostrophe in it, even in a comment, fails the run; a task file
        // reached by include_tasks is not parsed by --syntax-check, so only
        // the run would show it. `cmd: |` is taken as it is.
        for path in files().into_iter().filter(|p| is_yaml(p)) {
            for (n, line) in text(path).lines().enumerate() {
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

    #[test]
    fn each_clients_signing_key_is_carried() {
        for client in Client::ALL {
            let key = text(&format!("gpg/{}.asc", client.name()));
            assert!(
                key.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
                "{client:?}"
            );
        }
    }
}
