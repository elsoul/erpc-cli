<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# NEAR staking-pool validators

`erpc v --chain near` provides `init`, `deploy`, `list`, `status`, `logs`,
`start`, `stop`, `restart`, `update`, `update-config`, `plan`, and `destroy`.
`registration` prepares public call parameters, validates original custody,
observes pool/epoch state, or explicitly restores an original consensus key.
Account transaction signing and submission use external official tooling.

## Profile and release qualification

The validator uses the same network-qualified Mainnet 2.14.0 / Testnet
2.14.0-rc.6 source and image pins, verified genesis, direct native entrypoint,
all-shard tracking and five-epoch retention described in [NEAR RPC](near-rpc.md).
Use a dedicated Ubuntu 24.04+ x86-64 host with at least 16 logical cores,
64 GB RAM, and more than 4 TB local NVMe capacity: the initial free-space
floor is 4 TB on either network, retaining at least 100 GB operating headroom.
These are ERPC's conservative deployment floors for this all-shard profile,
based on the [producer hardware guidance][hardware], not benchmark results.
The smaller chunk-only profile is not selected.

RPC remains on loopback; explicit metrics ranges are supported. The managed
firewall admits peer TCP 24567 and approved management traffic. Initialization
preserves an existing supported clock daemon or installs systemd-timesyncd.
Startup requires a synchronized clock, original encrypted identities, verified
configuration and the caller's confirmed firewall receipt.

## Dedicated consensus custody

Create the native `validator_key.json` with official external tooling and keep
its exact original bytes in a concealed 1Password field. Reserve its public
account/key and an identifier-only `op://` reference. This dedicated Ed25519
key must never be an account transaction key, including an owner account's
restricted function-call key. The pool owner signs financial operations
externally. [Native key roles][keys], [onboarding][guide].

```sh
erpc v --chain near init -n testnet --name near-validator-a \
  --host <server> --ssh-key <operator.pub> --vault <network-vault> \
  --validator-account <pool-prefix>.pool.f863973.m0 \
  --owner-account <external-owner-account> \
  --staking-public-key <dedicated-ed25519-public-key> \
  --validator-key <concealed-native-key-reference> --commission-bps <explicit-fee>
erpc v --chain near deploy -n testnet --name near-validator-a \
  --ssh-key <operator.pub> --keys-unhosted
erpc v --chain near status -n testnet --name near-validator-a --ssh-key <operator.pub>
```

The first import requires `--keys-unhosted`, a matching prepared deployment
intent, no existing database and no current/next-epoch membership. This assertion
is an operator responsibility; public state cannot prove that another offline
host has no copy. ERPC refuses importing an already-active identity onto a fresh
host. There is no cross-host migration or key-rotation shortcut.

The CLI checks the native secret/public pair before sending it through SSH stdin.
The host independently derives the public key through OpenSSL's Ed25519 support.
Neither private key nor password is placed in process arguments, environment,
public inventory or Ansible variables. systemd credentials encrypt the original
bytes using the host key. Receipts bind owner/network/role, exact plaintext and
ciphertext digests. Runtime plaintext is restricted to root-owned `/run` files
readable by the dedicated node group and mounted read-only into the container.
Core dumps are disabled. These controls do not protect against a compromised
host root or consensus process that legitimately reads its signing key.

For same-host recovery, use `registration --action restore-key`. Only the exact
original key-file bytes and reserved identity are accepted. The controller
persists cancellation and startup fences before attempting shutdown; failure
leaves the node fenced. Encrypted previous generations are retained. A crash
between receipt and ciphertext publication resumes only the matching staged
ciphertext. After restoration, run a fresh `deploy`; restoration itself never
starts the signer. Preserve original 1Password material, the peer credential,
receipts, database and host systemd credential secret in protected backups.

## Pool creation and external financial operations

The official [near-cli-rs network configuration][cli] selects `poolv1.near`
on Mainnet and `pool.f863973.m0` on Testnet. ERPC uses that legacy staking-pool
profile. The pinned node guide also contains `pool.near` examples; that account
has a different deployed factory interface and is not interchangeable.

Read-only network observations on 2026-10-26 established factory code hash
`FjtxkkaKDKCW1F6HgsuYvnQ9GMxrzhnkQwCm52G9gYuA` on both selected factories.
Its embedded pool module has code hash
`J1arLz48fgXcGyCPVckFwLnewNH6j1uw79thsvwqGYTY`, also observed on deployed pools.
These are deployed-code identities, not a reproducible-build claim. The inspected
[factory][factory] and [pool][pool] source revision is
`1b0436c96379c63aee7d2429c6d5d24019031ab8`; its carried prebuilt pool module
differs, so ERPC does not claim that revision reproduces the deployed bytes.

After deployment, `registration --action prepare --step create-pool
--amount-yocto <explicit-integer>` emits the reserved owner/key/commission,
factory, receiver, method, gas and attached deposit. It observes the factory's
current minimum instead of treating an old example amount as sufficient.
The payload is public function-call parameters, not a serialized transaction;
the external wallet supplies access key, nonce, recent block hash and signature.
Use official tooling to inspect/simulate where supported, sign and submit it.

Other steps are `stake` (`deposit_and_stake`, explicit deposit), `ping`,
`pause`, `resume`, `unstake` and `withdraw`. Unstake/withdraw require an explicit
`--amount-yocto`; preparation checks the owner's observed pool balance and, for
withdrawal, epoch availability. No amount is defaulted and ERPC never submits.
External tooling must revalidate state immediately before signing; an observation
does not reserve funds or guarantee execution. Pausing the pool or stopping a
host does not instantly remove it from an epoch or withdraw delegators' funds.
`destroy` only retires the host and preserves keys/history.

`registration --action validate` checks original custody and live pool bindings;
`--action status` reads public state. Observations verify chain/genesis, freshness,
factory/pool code, owner access keys, staking public key and commission.
Account/contract views bind to one observed block; validator information uses
that block's explicit epoch ID, because native block-ID lookup supports only
the last block of a completed epoch. [RPC implementation][epoch-rpc].
An absent pool is allowed before external creation; unknown/mismatched state is
not treated as absence. Once created, the exact reviewed pool interface, empty
pool access-key list and reserved owner/key/fee are required.

`status` distinguishes synchronized node readiness from `producer_eligible`:
the latter additionally needs an existing unpaused pool and current-epoch
membership. Public membership and native identity do not prove that this host
has produced a particular block. Seat requirements are dynamic; no fixed deposit
is claimed to guarantee admission. [Validator guide][guide].

Offline tests cover ownership, dedicated key validation, interrupted publication,
restoration, stale intents, public-state mismatches, guarded startup and CLI
routing. Native node execution, actual 1Password/SSH custody transfer, complete
synchronization, restart/reboot, epoch admission, performance and real recovery
remain deferred to the later acceptance batch.

[hardware]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/validator/hardware-validator.md
[keys]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/intro/keys.md
[guide]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/validator/guide.md
[cli]: https://github.com/near/near-cli-rs/blob/7c0b2bf8cec6135fb31d12b9cd68fcc4b61894b1/src/config/mod.rs
[factory]: https://github.com/near/core-contracts/blob/1b0436c96379c63aee7d2429c6d5d24019031ab8/staking-pool-factory/src/lib.rs
[pool]: https://github.com/near/core-contracts/blob/1b0436c96379c63aee7d2429c6d5d24019031ab8/staking-pool/src/lib.rs
[epoch-rpc]: https://github.com/near/nearcore/blob/bc4e9e8cfb03d9e82f027883055624e18576993e/chain/client/src/view_client_actor.rs
