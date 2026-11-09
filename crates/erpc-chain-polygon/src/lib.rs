// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Polygon `PoS` network pins and dual-client lifecycle templates.
pub mod network;

/// Managed-host playbooks and source-verified native configuration transforms.
pub static TEMPLATES: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");

/// Immutable helper profile order, shared with the root release-pointer loader.
pub const HELPER_FILES: &[&str] = &[
    "accounts.py",
    "admission.py",
    "artifacts.py",
    "broker.py",
    "broker_docker.py",
    "broker_runtime.py",
    "broker_storage.py",
    "checkpoint.py",
    "configure.py",
    "control.py",
    "gateway.py",
    "host.py",
    "host_resources.py",
    "identity.py",
    "install.py",
    "launch.py",
    "local_tls.py",
    "native_authority.py",
    "native_peer.py",
    "observe.py",
    "parent.py",
    "signer.py",
    "signatures.py",
    "state.py",
    "upstreams.py",
    "validator_activation.py",
    "validator_runtime.py",
    "volume.py",
];
