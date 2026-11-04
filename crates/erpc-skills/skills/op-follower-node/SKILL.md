---
name: op-follower-node
description: Operate Optimism, Base and Soneium follower RPC nodes with chain-specific reviewed clients, concealed L1 upstreams, immutable bootstrap pins and guarded recovery.
---
# OP-family follower nodes

<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

Use `erpc r --chain optimism|base|soneium`. Optimism and Base support mainnet
and sepolia; Soneium supports mainnet and minato. These are dedicated follower
hosts, without sequencer/challenger/staking activation. Base's client mode called
validator performs follower derivation and does not create a PoS validator.

Base uses native base-reth-node/base-consensus 1.5.1 with pinned SHA-256 and the
embedded upstream GPG public key. OP/Soneium use op-reth 2.6.1 + op-node 1.19.11
with per-platform official OCI digests. Soneium's exact operator endorsement is
not documented; source qualification and live acceptance are separate.

Init requires the pinned SSH host, operator public key, network vault, full/archive
history, explicit public peer IPv4 and an identifier-only 1Password reference to
one unique CONCEALED L1 execution/beacon JSON field. Never place provider values
in argv, bundles or public inventory. The encrypted systemd credential belongs to
a separate L1 proxy account; clients see only loopback services. Mainnet profiles
need Ethereum mainnet upstreams; test profiles need Sepolia, including catch-up blobs.

Bootstrap validates official pinned metadata before downloading on the target.
Base capacity follows the pinned full-history selection and official 20% formula;
never substitute the catalog's older full-size estimate. OP Mainnet requires its
pre-Bedrock snapshot. Full is not archive, and archive does not add legacy Geth
history or a proofs database. No disk is formatted or unowned data adopted.

RPC/WS, SSH and metrics have separate ACLs. RPC defaults to loopback, native APIs
and Engine stay local, and every long deployment requires a fresh operation-bound
firewall confirmation. All twelve lifecycle verbs act on immutable host/network/
history ownership. Updates reject downgrades and keep incomplete installs fenced.

Resume installation with deploy and bootstrap with start/deploy. Explicit
`deploy --reset-bootstrap` quarantines only incomplete bootstrap data; completed
databases always refuse. Retained consensus identity and credentials are not reset.
Destroy retires and disables services while retaining data and ownership. Missing
identity or changed protected files require explicit recovery, not automatic replacement.

Both peer identities and the Engine JWT are sealed once with an encrypted receipt;
initial publication can resume without new entropy. Established missing/changed
credentials refuse startup and updates. Native Base shutdown verifies process and
cgroup absence even when its units are missing; an orphan prevents data mutation.

A successful submission can still be syncing. Status checks network identity,
canonical safe/finalized heads and recent L1/L2 progress. Structured Reth syncing
responses require stage progress. Real-host bootstrap, provider compatibility,
reboot and load acceptance remain deferred until the complete implementation batch.
See `docs/op-follower-rpc.md` for exact resources, ports, pins and recovery boundaries.

## Official sources

- https://docs.optimism.io/node-operators/tutorials/node-from-docker
- https://docs.base.org/specifications/node-operators/run-a-node
- https://docs.base.org/specifications/node-operators/performance-tuning
- https://github.com/base/base/releases/tag/v1.5.1
- https://docs.soneium.org/docs/builders/sfa
