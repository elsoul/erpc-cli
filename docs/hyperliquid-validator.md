<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Hyperliquid validator lifecycle

`erpc v --chain hyperliquid` manages a dedicated validator host on `mainnet` or
`testnet`. The host first synchronizes as a non-validating follower. Explicit
activation switches the original host to `hl-visor run-validator` after external
registration. The [qualified official instructions](https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/README.md#running-a-validating-node)
describe the follower prerequisite, separate cold validator and hot consensus
wallets, initial jailing, and external jail/unjail operations.

The [RPC supervisor qualification](hyperliquid-rpc.md#qualified-supervisor)
applies to this profile too. ERPC verifies the pinned signed supervisor; its
child remains vendor managed. A stable child source mapping, reproducible child
build and independently verified native anti-double-signing history format are
not documented in the checked official instructions. Keep the original private
native state and never run the same signer on another machine.

The separately provisioned [AQA publisher](hyperliquid-aqa.md) has its own agent
key and nested `aqa` lifecycle; this validator profile does not install it.

## Accounts and custody

Choose a separate cold validator/funds-management account and dedicated hot
consensus signer. ERPC refuses identical addresses. It never imports the cold
private key, signs a financial action, broadcasts registration or transfers
funds. The native validator uses the hot key to sign consensus messages.

Before initialization, put the **original native JSON key object** in a dedicated
1Password field of type `CONCEALED`. The field label must be unique. Use the
identifier-only reference to this field; never paste the key into a CLI argument.
The official native format is a JSON object with a `key` string. ERPC accepts
only that field, derives the public SEC1 point/address, and preserves the exact
original bytes rather than rewriting the object. Keep this original concealed
field for explicit same-host recovery.

Both wallets need nonzero perps USDC according to the official instructions.
Choose `--max-hot-usdc` explicitly for the dedicated minimum-balance signer.
ERPC checks its perps-USDC fixed-point ceiling, absence of hot perps trading positions and open
orders before first custody and first validator activation. These checks do not
fund either wallet or guarantee future balances. They do not prove absence of spot, EVM or other-chain assets controlled by the same key; the operator must select a dedicated key. Once original custody exists,
a later unsolicited transfer does not revoke same-host restoration authority.

The projected secret enters ERPC's concealed memory and reaches the host only on
SSH stdin. It is absent from public inventory, playbook bundles, unit text and
process arguments. OpenSSL receives secret DER on stdin to verify the original
public point. Host-bound `systemd-creds` encryption is privately decrypted and
checked before its ciphertext/receipt is published. Explicit restoration retains
old ciphertext as a separate inode and accepts only the exact original native
bytes; it never rekeys or moves a signer to another host.

Only activated validator units load the encrypted credential. A protected first
`ExecCondition` checks original NSS ownership before systemd v255's credential
write phase; numeric original User/Group prevent a later name lookup from
redirecting the recipient. The pre-start guard then verifies the decrypted bytes. Outer loader failures also
exit 255, so systemd does not treat an authentication failure as a successful
condition skip. Start/activation reports success only after the original numeric
services are observed loaded, active and running with a positive main PID and
successful service result. Pending, skipped or failed partial startup is cancelled
and owned services are stopped; synchronization and admission remain separate.
The native key path is a read-only credential bind at
`~/hl/hyperliquid_data/node_config.json`; its persistent destination contains only
a root-owned nonsecret placeholder. The private-state directory's original
filesystem UUID, ext4/XFS type, filesystem root, inode and numeric account are
recorded before ownership handoff or placeholder publication. Device numbers
are compared only within the current observation, so reboot renumbering does
not change original authority. Missing or substituted established history
requires operator recovery; ERPC does not create replacement history automatically.
These controls do not prevent an administrator from reassigning the original
numeric UID after the precondition. [systemd v255 startup ordering](https://github.com/systemd/systemd/blob/v255/src/core/service.c#L2470)

## Initialize, synchronize and activate

Use a dedicated Ubuntu 24.04 x86-64 host with 32 available CPU cores, 128 GB RAM
and a 1 TB SSD, matching the official validator recommendation. ERPC requires at
least 980 GB formatted capacity and free space of
`max(200 GB, 900 GB - allocated bytes under home/hl)`. This is ERPC's initial-sync
and operating-headroom policy. Actual native filesystem/device and nested-mount
checks also run before startup and deployment.

```sh
erpc v --chain hyperliquid --network testnet init \
  --name hl-validator --host 192.0.2.10 --user ubuntu \
  --fingerprint '<verified SSH SHA256 fingerprint>' \
  --public-ip '<server public IPv4>' --ssh-key ./operator.pub \
  --vault '<network inventory vault>' \
  --validator-address '<external cold validator address>' \
  --hot-key-ref 'op://<vault-id>/<item-id>/consensus' \
  --max-hot-usdc '<explicit dedicated hot balance ceiling>' --keys-unhosted

erpc v --chain hyperliquid --network testnet deploy \
  --name hl-validator --ssh-key ./operator.pub --vault '<network inventory vault>'

erpc v --chain hyperliquid --network testnet status \
  --name hl-validator --ssh-key ./operator.pub --vault '<network inventory vault>' --json
```

The addresses and references above are placeholders. `--keys-unhosted` attests
that the original signer is not operating elsewhere. Initialization checks the
remote contract before inventory reservation and imports custody without starting
a node. Ordinary deploy starts the follower without loading the key. Validator
hosts have no public RPC allowlist; the gateway is stopped when consensus mode
is activated. Peer ports 4000–4010 are open as required by the official guide;
both TCP and UDP are an explicit ERPC policy because that source does not name
the transports. Management uses the observed host SSH port and current caller.

Prepare the external registration as described below, sign/submit it externally,
and wait for its matching cold/hot identities to appear as registered and jailed.
Then explicitly activate:

```sh
erpc v --chain hyperliquid --network testnet deploy --activate-validator \
  --name hl-validator --ssh-key ./operator.pub --vault '<network inventory vault>'
```

First activation requires a healthy synchronized owned follower, original encrypted
custody and matching public registration. The proof is durably tied to its exact
host/target/follower receipt before shutdown, so interrupted preparation can
resume without requiring the stopped follower to run again. A changed target
cannot reuse that proof. A fresh confirmed firewall receipt is still required
before any native startup. Successful service startup does not assert admission:
inspect `status`, native consensus logs and the external registration separately. During follower synchronization, `node_ready` can be true while validator `ready` remains false.
Follow the official consensus-output check before external unjail.

## Operations and external action plans

All twelve common verbs are available. `list` reads public inventory; `plan`
reads the profile; `logs` streams owned journals as compact JSON lines with
`--json`; `status` reports native and external registration observations separately.
`start`, `stop`, `restart`, `update`, `update-config` and `destroy` keep their
[owned lifecycle semantics](hyperliquid-rpc.md#operations). The original host,
network, cold/hot identities, reference and ceiling are immutable. A validator
cannot silently become a follower. Updates retain the vendor-managed child
policy and private history.

`plan --step` constructs unsigned native action data and subcommand arguments;
it does not execute the native signing command. Amounts are explicit positive
integer base units. Verify current admission/staking requirements externally.

| Step | Additional arguments | External signing authority |
|---|---|---|
| `register` | `--amount-wei`, `--validator-name`, `--description` | Original cold validator wallet |
| `deposit` | `--amount-wei` | External validator/funds wallet |
| `delegate`, `undelegate` | `--amount-wei` | External validator/funds wallet |
| `withdraw` | `--amount-wei` | External validator/funds wallet |
| `jail`, `unjail` | None | Original dedicated consensus signer |

For example, `erpc v --chain hyperliquid --network testnet plan --name
hl-validator --step register --amount-wei '<explicit amount>' --validator-name
'<public name>' --description '<public description>'` emits the public profile,
original signer/IP and unsigned registration data. Use the official external
signing workstation procedure. No private key is included in the plan.

Registration observations use the official `validatorSummaries` API bracketed by
fresh HyperCore clock observations. The exposed summary does not prove the
registered IP, so that field is explicitly reported as unavailable. Jailed
active-set entries are not reported as currently participating. An unavailable
public reference yields unknown registration and non-success readiness, even
when the local node is healthy. A planned shutdown should follow external self-jail
and departure from the active set; emergency owned stop remains available if
public APIs, custody or startup checks fail.

## Recovery

`update-config --restore-key` stops owned services and restores the exact original
concealed material; it does not restart. Unknown orphan ciphertext/staging on a
fresh host is refused. Import/restore failures preserve original native data and
referenced ciphertext candidates. `--recover-preparation` has the same explicit,
retaining semantics as the RPC profile and never deletes native private state.
Stop/destroy attempt owned shutdown even if cancellation storage fails, then
report failure without claiming durable reboot protection. Destroy retains
accounts, native data, ciphertext and ingress policy.


For an existing installation with the older device-number-only private-state
receipt, first stop the original validator and supply its **independently
recorded original filesystem UUID** from provisioning/backup evidence:

```sh
erpc v --chain hyperliquid stop -n testnet --name validator1 --ssh-key OPERATOR_PUBLIC_KEY
erpc v --chain hyperliquid update-config -n testnet --name validator1 \
  --ssh-key OPERATOR_PUBLIC_KEY --recover-private-filesystem ORIGINAL_FILESYSTEM_UUID
erpc v --chain hyperliquid deploy -n testnet --name validator1 --ssh-key OPERATOR_PUBLIC_KEY
```

This recovery uses the sealed carried controller, so it does not require the
old installed helper to understand the new operation. It requires durable stop,
original contract/custody/account and quiescent original UIDs. The supplied UUID
must match the identified native volume and the existing private directory must
retain its original inode, permissions and nonsecret placeholder. The exact old
receipt and its digest are durably retained before switching the identity format.
An interrupted publication retries only the same original UUID and receipt;
keys, native history, supervisor pins and activation mode remain unchanged.
The node stays stopped and recovery does not publish helpers or activate anything.
Use ordinary deploy afterward to install the qualified current controller under
its existing release rules. Do not combine this option with key restoration,
preparation recovery or policy changes.

Do not use the currently mounted UUID as a guess for the original one. Missing
independent evidence, original inode or history requires separately reviewed
recovery. Owned stop/destroy remain available when this startup receipt is
missing or outdated. The complete managed root must share one identified
writable ext4/XFS filesystem; nested mounts and subroot filesystem binds are
refused. ERPC uses explicit UUID/FSTYPE/FSROOT/MAJ:MIN columns from the PID1 mount
table, following [util-linux findmnt](https://github.com/util-linux/util-linux/blob/v2.39.3/misc-utils/findmnt.8.adoc).
Actual mounting/reboot and systemd namespace behavior remain host acceptance
checks; offline fixtures model their observations without mounting anything.

The official guide also recommends a separate-host AQA publisher with a dedicated
agent. This validator profile does not deploy that separate service or reuse its
consensus key for agent delegation. Its agent approval, custody and deployment
belong to the separate publisher profile. No automatic jailing rule for missing
AQA votes is asserted here.

Offline verification covers private stdin transport, original-key/receipt recovery,
publication failures, scope/account/device binding, external action parsing,
registration/funding observations and mode transitions. Real funding, NSS/device
changes, systemd credential setup, synchronization, consensus activation and
reboots require the later host acceptance run.
