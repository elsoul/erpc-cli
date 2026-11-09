---
name: near-node
description: Operate network-qualified NEAR follower RPC nodes with erpc, including immutable ownership, native peer identity, verified genesis, guarded startup and retained-data recovery.
---

# NEAR RPC nodes

Use `erpc r --chain near` with explicit `mainnet` or `testnet`. The follower
tracks all shards and keeps five epochs; it does not activate a validator or
sign account/stake transactions. The separate `erpc v --chain near` role uses
original dedicated consensus keys and external staking-pool signing; see
`docs/near-validator.md`. See `docs/near-rpc.md` for the operating contract.

Initialize a dedicated Ubuntu 24.04+ x86-64 host using its pinned SSH identity and
network vault. Use the qualified network-specific version and OCI digest, never a
mutable image tag or arbitrary binary. Mainnet uses stable 2.13.4; Testnet uses its
qualified 2.14.0-rc.6 prerelease. Docker and actual binary source/version checks,
genesis/configuration hashes and documented CPU features precede activation.

RPC 3030 and metrics 3032 are loopback-only unless explicit trusted ranges are
selected. Peer TCP 24567 is admitted. The short firewall operation requires a
fresh SSH confirmation after artifacts have been prepared; its exact receipt and
the pending policy identity authorize startup. Do not bypass a pending fence.

The native initializer creates only a peer identity, with networking disabled and
no validator account argument. It is encrypted with the host systemd credential
key and retained with an immutable identity receipt. Missing established material
must be restored from its protected original backup; do not generate a substitute.
The encrypted credential alone cannot restore a different host's identity.

All twelve lifecycle verbs are available. Retry interrupted deployment at the
same stored target. Stop/retire remain available during interruption. Destroy
preserves data, keys and ownership. A same-owner deployment can resume retained
data; database downgrade and automatic history deletion are refused.

Status requires owned listeners, matching network/genesis and peer identity,
installed source/version, confirmed ingress, no validator key, a fresh block and
completed synchronization. A successful deploy can still be syncing. Live
bootstrap, reboot, RPC workload and recovery acceptance are deferred to the later
batch; do not describe offline tests as successful real-host deployment.

## Validator workflow

Reserve a dedicated host, factory-qualified pool account, external owner,
Ed25519 public key, concealed native key reference and explicit commission.
Initial deploy requires `--keys-unhosted` and refuses current/next-epoch identities
on fresh hosts. Keep financial/access keys external. Original key bytes travel
only through stdin into host-encrypted custody, never Ansible variables or argv.

Use registration prepare/validate/status to inspect pool code, owner/key/fee,
factory minimum, balances and current/next-epoch membership. Create-pool, stake,
unstake and withdraw require explicit integer amounts. Ping, pause and resume
prepare zero-deposit calls. Sign and submit with official external tooling only.
Stopping or retiring a node does not withdraw funds or exit an epoch immediately.
Original-key restoration is explicit and leaves startup fenced until a fresh
deploy. Do not replace missing keys or import a used identity onto another host.

## Official sources

- https://github.com/near/nearcore — pinned client source and release workflow.
- https://github.com/near/node-docs — hardware, initialization and epoch synchronization.
- https://docs.near.org/api/rpc/setup — public RPC protocol documentation.
