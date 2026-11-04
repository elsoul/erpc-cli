// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Runs a small play on a real node through `erpc-ops`, for checking the
//! runner by hand:
//!
//! ```text
//! ERPC_PROBE_HOST_KEY='ssh-ed25519 AAAA…' \
//!   cargo run -p erpc-ops --example trial -- <host> <user> <agent-socket> <public-key>
//! ```
//!
//! The play checks that Ansible runs from the pinned venv, who it runs as,
//! that `become` works, and that the collections the plays need are there.

// A tool run by hand at a terminal: printing is its output.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;

use erpc_ops::bundle::Bundle;
use erpc_ssh::{HostKey, Identity, Session, Target};

const PLAY: &str = r#"- hosts: all
  gather_facts: yes
  tasks:
    - name: Where this runs
      ansible.builtin.debug:
        msg: "{{ inventory_hostname }}: {{ ansible_distribution }} {{ ansible_distribution_version }}, Ansible {{ ansible_version.full }} from {{ ansible_playbook_python }}"
    - name: The login user runs the play
      ansible.builtin.command: id -un
      register: who
      changed_when: false
    - name: become reaches root
      become: yes
      ansible.builtin.command: id -u
      register: root
      changed_when: false
    - name: The collections the plays use are installed
      ansible.builtin.command: "{{ ansible_playbook_python }} -c 'import ansible_collections.community.general, ansible_collections.ansible.posix'"
      changed_when: false
    - ansible.builtin.assert:
        that:
          - root.stdout == "0"
        success_msg: "ran as {{ who.stdout }}, become gives root, collections present"
"#;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [host, user, socket, public_key] = args.as_slice() else {
        eprintln!("usage: trial <host> <user> <agent-socket> <public-key>");
        std::process::exit(2);
    };
    if let Err(e) = run(host, user, socket, public_key) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(
    host: &str,
    user: &str,
    socket: &str,
    public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let host_key = HostKey::parse(&std::env::var("ERPC_PROBE_HOST_KEY").unwrap_or_default())?;
    let session = Session::open(&Target {
        host: host.to_owned(),
        port: 22,
        user: user.to_owned(),
        host_key,
        identity: Identity::Agent {
            socket: PathBuf::from(socket),
            public_key: PathBuf::from(public_key),
        },
    })?;
    let mut bundle = Bundle::new();
    bundle.add("ansible/erpc-trial/site.yml", PLAY)?;
    bundle.add(
        "inventory.yml",
        r#"{"all": {"hosts": {"erpc-trial": {"ansible_connection": "local"}}}}"#,
    )?;
    let built = bundle.finish()?;
    println!(
        "bundle {} bytes, sha256 {}",
        built.bytes.len(),
        built.sha256
    );
    let run = erpc_ops::run::start(&session, &built, "ansible/erpc-trial/site.yml")?;
    println!("started {}", run.as_str());
    let result = erpc_ops::run::follow(&session, &run, &mut |line| println!("  | {line}"))?;
    println!(
        "result: {} (exit {}) {}",
        result.status, result.exit_code, result.message
    );
    Ok(())
}
