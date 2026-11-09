---
name: hyperliquid-node
description: Manage dedicated Hyperliquid RPC or consensus-validator hosts with original custody and a qualified supervisor.
---

# Hyperliquid node operations

<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

Use `erpc rpc --chain hyperliquid --network mainnet|testnet` and the standard
twelve lifecycle verbs. Initialize with a pinned SSH host fingerprint, an SSH
agent/public key, network inventory vault and explicit public peer IPv4 address.
The original host, service identities and peer advertisement remain immutable.

Run `plan` before selecting a supervisor update. ERPC pins and verifies hl-visor;
hl-node remains vendor managed. `status` reports owned process/socket freshness
and observed child hashes, not an approved child source commit. Readiness is
separate from successful service startup.

Public RPC ingress is closed until `--rpc-allow` is supplied. `update-config`
uses a fresh firewall confirmation. `stop` and `destroy` preserve data and
filtering; the latter disables owned services. `--recover-preparation` on
deploy/update/update-config abandons only incomplete preparation after owned
shutdown and preserves native files. Never invent a purge or key-regeneration
step to repair native synchronization.

This RPC profile does not import a funded validator key. Keep funding,
registration and financial signatures outside RPC operations. The official
[node instructions](https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/README.md)
describe the supervisor, native API limits and public outputs. Use the compiled
qualification and public operational guide for exact current settings.

## Dedicated consensus validator

Use the separate `erpc v --chain hyperliquid` inventory and its twelve verbs.
Initialize with distinct public cold/hot identities, an identifier-only concealed
native key reference, explicit `--max-hot-usdc` and `--keys-unhosted`. Never put
private key text in arguments. The cold key is never imported. Initial deploy
runs an unkeyed follower; `deploy --activate-validator` requires synchronized
original state and matching externally registered, initially jailed identities.
The activated native client signs consensus using the original encrypted hot
credential. Public RPC access remains closed on validator hosts.

`plan --step register|jail|unjail|deposit|delegate|undelegate|withdraw` emits public
unsigned native action data. Financial steps require explicit positive integer
`--amount-wei`; registration also needs a public name and description. Signing,
funding and submission remain external. Follow the official consensus-output
check before external unjail; planned shutdown should follow external self-jail
and departure from the active set. Emergency local stop stays available.

`update-config --restore-key` stops and restores only the exact original native
bytes from the concealed field; it does not restart or rekey. Missing native
private history is not automatically regenerated. Never duplicate the signer or
reuse it for a publisher agent. AQA is a separately approved host/profile and is
not deployed by this consensus lifecycle.

## Separate AQA publisher

Use `erpc v --chain hyperliquid --network mainnet|testnet aqa` and its twelve
verbs for an explicitly approved separate host and dedicated API/agent key.
Initialize with public cold/consensus/master addresses, an exact agent name,
a uniquely labelled CONCEALED original JSON key field and `--agent-exclusive`.
Never reuse the consensus key or infer which approving master the protocol needs.
The API agent has general trading authority, not a vote-only permission.

The pinned signed `publish_daemon` runs daily at 22:00 UTC. External named-agent
approval is verified before deployment and during operation, but generic approval
is not proof of vote eligibility. `accepted_vote` stays unknown until official
accepted-vote evidence is verified separately. `plan --step approve-agent` emits
public fields only; signing and submission remain external. `logs` forwards only
public lifecycle events, never native diagnostic/private-environment output.

`update-config --restore-key` restores only original custody and remains stopped.
`--recover-preparation` abandons an unfinished attempt before continuing the
explicitly requested deployment. Stop and retirement retain ciphertext and
filtering and attempt owned shutdown even when cancellation persistence fails;
a failed operation is not proof of durable reboot fencing. The exact credential
`.env` is read back before launch; stock dotenv then puts the key in the native
process's own environment. Do not claim it is absent from every environment.

## Official sources

- https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/README.md
- https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/nodes

- https://github.com/native-markets/aqa-publisher/blob/974ee88fbfda6a6d6fb298ae30348bb4e20bd517/README.md
