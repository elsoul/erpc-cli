<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Hyperliquid AQA publisher

`erpc v --chain hyperliquid --network <mainnet|testnet> aqa` manages a **separate
publisher host with its own dedicated API/agent key**. It does not share the
consensus host, cold validator wallet, consensus signer or their encrypted
credentials. The [official publisher guide][publisher] recommends a separate
API wallet, and the [node guide][node] instructs active validators to run the
publisher. This profile uses `publish_daemon`, whose pinned source fetches on
startup and publishes daily at 22:00 UTC; ERPC does not execute `publish_once`.

An approved API agent has **general trading authority**, not an AQA-only scope.
The operator must choose a fresh dedicated key, an explicit approving master
and a separate host. Agent approval/revocation and financial actions stay in the
external wallet or official SDK. ERPC never signs or submits those actions.
The native publisher signs and submits its scheduled `validatorL1Stream` action.
[API wallet authority and pruning][agents]; [pinned signing code][signing].

## Qualification and remaining protocol uncertainty

The qualified release is **v1.2.0**, source commit
`974ee88fbfda6a6d6fb298ae30348bb4e20bd517`, published 2026-03-31. Only the Linux
x86-64 GNU archive is enabled. The catalog fixes archive size/hash, detached
signature, signer fingerprint, signature timestamp and extracted ELF hash. The
root helper verifies these before publication; an update cannot select arbitrary
URLs, older signature timestamps or changed bytes under the same version.
The source association is the publisher's release/tag association, not a claim
that ERPC reproduced the native build. [Release][release]; [public signing key][key].

| Qualified value | Pin |
|---|---|
| Archive SHA-256 | `56864ff5d7fd61cf8ca7be3b57ce007243ea56cb6c13a31a690a67d44f681f00` |
| Native ELF SHA-256 | `dd388f2bfee35da68883e6ad82e18cecaa6b5148cbfe188ff37211153df9bf1e` |
| Publisher GPG fingerprint | `0F2980DEE814C761B2016C2F3080B08C4722CF13` |
| Verified signature time | `1774922628` (2026-03-31 02:03:48 UTC) |

ERPC checks fresh network `exchangeStatus`, the explicit master's named
`extraAgents` entry, the agent's `userRole`, and the original cold/consensus pair
in `validatorSummaries`. A changed, removed, expired or reassigned approval is a
revocation; the observer fences startup and attempts owned shutdown. An API
`validUntil: null` is recorded as an unspecified expiry, not a permanent grant.
Inspection failure also stops the owned publisher; this conservative availability
policy is ERPC's choice. [Official SDK request definitions][sdk].

**Not documented in the checked primary sources:** which validator-associated
account must be the approving master, and how its generic agent approval maps to
protocol vote eligibility. ERPC therefore requires the operator's public
`--agent-master` input and reports `accepted_vote: null`. A running service and a
verified agent relationship do not establish that Hyperliquid accepted a vote.
No automatic jail/unjail consequence or vote-specific permission is claimed.
Before production acceptance, independently verify an accepted vote for this
exact agent/validator relationship using an official observable result. Do not
infer that result from successful process startup. [Checked publisher guide][publisher];
[checked native action][signing]; [checked node instructions][node].

## Host and original custody

ERPC qualifies Ubuntu 24.04, x86-64, systemd 255 and cgroup v2. Two CPUs, nominal
2 GiB RAM and at least 1 GiB free on each managed filesystem are **ERPC operating
policies**; an official AQA hardware minimum is not documented in the checked
[publisher guide][publisher]. AQA opens no application listener. Ingress permits
only loopback, established traffic, ICMP and the observed SSH port for the current
caller/additional management ranges. The native daemon contacts Hyperliquid and
its source-defined public FRED/New York Fed/OFR feeds. The endpoint declaration
is not a native-process egress sandbox. [Fixed feed source implementations][feeds].

Put the original single-key JSON object (`{"key":"<32-byte hexadecimal key>"}`)
in a uniquely labelled **CONCEALED** 1Password field. Use an identifier-only
`op://<vault-id>/<item-id>/<field-id-or-label>` reference. Do not place the key in
arguments or environment variables. `--agent-exclusive` attests that no other
signing process uses this fresh agent and that it has never been deregistered.
API-wallet pruning/reuse can invalidate nonce assumptions; an observed revoked
identity cannot be reapproved in place. Initialize a fresh publisher identity on
a separately provisioned host instead. [Official nonce guidance][agents].

The projected secret is validated locally, sent on SSH stdin and independently
checked against the original public key on the host. It is encrypted with the
host's `systemd-creds` key and privately read back before publication. Original
JSON bytes, public identity, encrypted bytes and their durable receipts are
bound together. Recovery accepts only the same original concealed bytes on the
same original host. Existing ciphertext is retained as a separate private inode.
No replacement key is generated and no cold/master key is imported.

The root-owned reservation fixes the original numeric service UID/GID before NSS
creation; unknown or changed accounts are not adopted. A protected first
`ExecCondition` checks this authority before systemd v255 writes credentials.
The unit binds numeric User/Group, and authentication failures exit 255 rather
than causing a successful condition skip. Later guards recheck original
ownership, exact configuration, approval, artifact and confirmed firewall.
Administrative reassignment of the original numeric UID after authentication is
outside this boundary. [systemd v255 startup ordering][systemd].

The native process receives one read-only credential named **`.env`**. Its exact
bytes are checked, then the launcher changes to that exact credential directory
and executes with a small clean environment. The stock dotenv library then
**populates the native process's own environment**. The guarantee is no private
key in ERPC's unit text, argv, inherited launcher environment or persistent
plaintext file; it is not a guarantee that the native process has no key in its
environment. The checked `.env` prevents the library's parent-directory search
from selecting another input. Native stdout/stderr are discarded, core dumps
are disabled and ERPC never forwards the native private environment or diagnostic
output. [Native dotenv initialization][daemon]; [dotenvy 0.15.7][dotenv].

## Initialize and explicitly deploy

The examples use placeholders and documentation IP addresses. Verify the SSH
fingerprint independently. Keep the consensus signer and cold/master wallets
outside this publisher's concealed field.

```sh
erpc v --chain hyperliquid --network testnet aqa init \
  --name aqa-test --host 192.0.2.46 --user ubuntu --port 22 \
  --fingerprint '<verified SSH SHA256 fingerprint>' --ssh-key ./operator.pub \
  --vault '<network inventory vault>' \
  --validator-address '<original cold validator address>' \
  --consensus-signer '<original consensus signer address>' \
  --agent-master '<explicit external approving master address>' \
  --agent-name erpc-aqa --agent-key-ref 'op://<vault-id>/<item-id>/agent' \
  --agent-exclusive

erpc --json v --chain hyperliquid --network testnet aqa plan \
  --name aqa-test --step approve-agent --vault '<network inventory vault>'
```

Initialization reserves the separate host and encrypted original custody without
starting the publisher. Complete the named approval externally. The plan contains
public action fields; the operator must supply a fresh nonce, signing domain and
signature externally. It is not a ready-to-broadcast transaction.

```sh
erpc v --chain hyperliquid --network testnet aqa deploy \
  --name aqa-test --ssh-key ./operator.pub --vault '<network inventory vault>'

erpc --json v --chain hyperliquid --network testnet aqa status \
  --name aqa-test --ssh-key ./operator.pub --vault '<network inventory vault>'
```

Deployment authorizes a new intent, quiesces the original identity, installs the
qualified artifact, applies the firewall, confirms it through a fresh SSH
connection and activates only under that exact run/bundle receipt. Every later
stage verifies its intent; an old queued operation cannot revive a stopped host.
Startup success requires the original native executable/PID generation in its
owned cgroup, not only a successful `systemctl start` exit. Service readiness is
separate from accepted vote evidence.

## All twelve operations and recovery

| Verb | Publisher behavior |
|---|---|
| `init` | Reserve original separate host, account and encrypted agent; no publishing |
| `deploy` | Explicitly prepare, confirm ingress and start the qualified daemon |
| `list` | Read the network's public publisher inventory |
| `status` | Observe original process/host/approval readiness; accepted vote remains unknown |
| `logs` | Bounded public lifecycle events only; `erpc --json v … aqa logs` emits compact NDJSON |
| `start` | Start the completed original profile after all current checks |
| `stop` | Persist cancellation and attempt owned shutdown; retain custody/configuration |
| `restart` | Explicit stop followed by the same guarded original start |
| `update --version <qualified>` | Select only a catalog-qualified release and preserve original identity |
| `update-config` | Apply management policy through fresh confirmation and deployment |
| `plan` | Public profile or external `--step approve-agent` / `revoke-agent` guidance |
| `destroy` | Retire and stop the publisher; retain original ciphertext, receipts and filtering |

`update-config --restore-key` is a **restore-only** operation: it stops the
publisher, reads the same concealed reference, restores only original custody and
leaves it stopped. It conflicts with management changes and unfinished-preparation
recovery. Use a separate guarded `start` after successful restoration.

If an incomplete preparation cannot continue, `deploy`, `update` or
`update-config --recover-preparation` first fences/drains the old attempt and
abandons only its unfinished target, preserving original identity/custody. The
same command then performs its explicitly requested new deployment. This is not
a key reset or a history/ownership adoption mechanism.

Stop/retirement still attempt exact owned process shutdown if persistence fails.
They report failure rather than claiming durable cancellation. With permanently
unwritable storage, reboot fencing cannot be guaranteed; repair storage and repeat
the operation before relying on reboot behavior. Foreign scope is never stopped.
Missing or changed units do not authorize a new writer: retained original
UID/cgroup/executable/argv/generation proofs govern orphan handling, and unknown
processes cause refusal. A sealed carried stop/retire path remains available when
the installed helper cannot be loaded.

The implementation has offline source, signature, parser, namespace, custody,
publication and failure-path coverage. Actual Linux systemd credential delivery,
native publisher startup, feed connectivity, 22:00 UTC publication and official
accepted-vote evidence still await acceptance on a real host.

[publisher]: https://github.com/native-markets/aqa-publisher/blob/974ee88fbfda6a6d6fb298ae30348bb4e20bd517/README.md
[release]: https://github.com/native-markets/aqa-publisher/releases/tag/v1.2.0
[key]: https://github.com/native-markets/aqa-publisher/blob/974ee88fbfda6a6d6fb298ae30348bb4e20bd517/pub_key.asc
[daemon]: https://github.com/native-markets/aqa-publisher/blob/974ee88fbfda6a6d6fb298ae30348bb4e20bd517/src/bin/publish_daemon.rs
[signing]: https://github.com/native-markets/aqa-publisher/blob/974ee88fbfda6a6d6fb298ae30348bb4e20bd517/src/chain/signing.rs
[feeds]: https://github.com/native-markets/aqa-publisher/tree/974ee88fbfda6a6d6fb298ae30348bb4e20bd517/src/sources
[node]: https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/README.md
[agents]: https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets
[sdk]: https://github.com/hyperliquid-dex/hyperliquid-python-sdk/blob/2fdb18f9517675ea03695a0962bd19eece9c83f0/hyperliquid/info.py
[dotenv]: https://docs.rs/dotenvy/0.15.7/src/dotenvy/lib.rs.html
[systemd]: https://github.com/systemd/systemd/blob/v255/src/core/service.c
