<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Robinhood admitted Defensive validator

ERPC provides a dedicated original-wallet Defensive profile for Robinhood
mainnet (child 4663, Ethereum parent 1) and testnet (child 46630, Sepolia parent
11155111). All twelve lifecycle verbs are connected. Admission remains an
external administrator decision. The default deployment is a non-signing
Watchtower; it is not reported as a ready active validator.

The [official node guide](https://docs.robinhood.com/chain/run-a-full-node/)
describes permissioned BoLD validators, a 1 WETH bond and Defensive operation.
Funding an address alone does not admit it. ERPC observes the fixed network's
Rollup allowlist or whitelist-disabled flag at a finalized parent block, checks
its Bridge, child ID, WETH and challenge-manager relationship, and refuses
paused or inconsistent protocol observations. This is not an attestation of the
current proxy implementation or administrator's authority.

## Qualified native profile

The validator catalog selects Nitro **3.12.2**, source commit
`5f02f3f03076343061f167e81b8e82ec5518064b`, published 2026-10-27. Public source and
OCI metadata were rechecked on 2026-11-04. This source-qualified choice is
separate from Robinhood's older guide example and the existing RPC follower's
3.12.1 catalog. It is not presented as a new chain endorsement. See the
[upstream release](https://github.com/OffchainLabs/nitro/releases/tag/v3.12.2).

The Linux amd64 full image is
`docker.io/offchainlabs/nitro-node@sha256:c908f324a08b7332d1fa031b83b071cfa2d9edd8a364c4344d7c34b665bf08e9`,
with configuration digest
`sha256:10de676fe40c8ff6046d9ad113db2e587877442c77df013559a342ea3a81757a`.
These are observed official registry byte identities, not an independent
reproducible-build or binary signature claim. The pinned Nitro BSL license and
additional use grant remain applicable.

ERPC explicitly enables the same-process authenticated validation server and
`self-auth` client in the full image. This is a source-supported configuration,
not a claim to use the upstream split `-validator` entrypoint. Persistent state
uses HashDB and chain-tip validation recordings; the pinned native code rejects
PathDB when block validation is required. See the
[pinned node configuration](https://github.com/OffchainLabs/nitro/blob/5f02f3f03076343061f167e81b8e82ec5518064b/arbnode/node.go)
and [native startup](https://github.com/OffchainLabs/nitro/blob/5f02f3f03076343061f167e81b8e82ec5518064b/cmd/nitro/nitro.go).

Each network has a separate fixed chain-info byte pin. Mainnet additionally
fetches its pinned custom genesis; testnet has no custom-genesis input. The
validator replays from genesis and does not adopt a follower snapshot or its
signing history. Providers must be able to serve the historical parent data
required for that replay. Files are linked by the official node guide and fixed
in the [sealed network scopes](../crates/erpc-chain-nitro/templates/robinhood-validator/scopes).
A new version requires an explicitly reviewed catalog change. `update --version`
refuses arbitrary versions and unknown prior native catalogs; no automatic
binary/database rollback or native-state recreation is provided.

## Exact automatic participation authority

After explicit activation, the dedicated hot EOA may sign and submit only
`newStakeOnNewAssertion` and `stakeOnNewAssertion` to the qualified Rollup.
Native Defensive reacts to rival assertions. It does not periodically create
MakeNodes assertions, confirm assertions, or initiate challenge edges in this
pinned implementation. The parent transport independently rejects those other
methods even if requested by a native client. The source boundaries are
[mode capabilities](https://github.com/OffchainLabs/nitro/blob/5f02f3f03076343061f167e81b8e82ec5518064b/bold/challenge/types/mode.go),
[rival assertion processing](https://github.com/OffchainLabs/nitro/blob/5f02f3f03076343061f167e81b8e82ec5518064b/bold/assertions/sync.go)
and [confirmation mode](https://github.com/OffchainLabs/nitro/blob/5f02f3f03076343061f167e81b8e82ec5518064b/bold/assertions/confirmation.go).

The transport checks canonical typed transaction encoding, the original sender,
parent chain ID, Rollup recipient, original withdrawal address, zero ETH value,
empty access list, live admission, bond and allowance. The profile caps each
assertion bond at 1 WETH, gas at 30 million and fee cap at 100 gwei, and refuses
a maximum transaction gas charge exceeding the observed dedicated ETH balance.
A live bond above 1 WETH requires new qualification. One bond is not a lifetime
spending or loss limit: the operator controls external wallet funding and must
monitor gas expenditure and possible bond loss. Native validation supplies the
execution decision; the transport does not independently recompute an alleged
bad assertion. These method limits govern the configured ERPC parent transport,
not an out-of-band key copy or a compromised native signer bypassing that
transport. A transaction already accepted by the parent chain cannot be revoked
by stopping the local service.

Administrator admission, ETH funding, WETH wrapping, ERC20 approval, stake
withdrawal and owner operations stay external. Native `auto-deposit`,
`auto-increase-allowance`, delegated staking, custom withdrawal address, smart
contract wallet and external signer configuration are disabled. ERPC does not
request a challenge-manager allowance for this Defensive profile. The
[pinned Rollup interface](https://github.com/OffchainLabs/nitro-contracts/blob/4341b132cfbdcc980ead03765ca5224ff6cb5d97/src/rollup/RollupUserLogic.sol)
and [BoLD configuration](https://github.com/OffchainLabs/nitro/blob/5f02f3f03076343061f167e81b8e82ec5518064b/staker/bold/bold_staker.go)
provide the ABI and native option boundaries.

## Prepare and activate

Use a dedicated Ubuntu 24.04 amd64 host with systemd 255, Python 3.12, sudo,
16 cores and 128 GB RAM. ERPC's conservative storage policy reserves 6 TB for
initial synchronization, crediting verified allocated original data on retries,
with at least 200 GB operating headroom. These are ERPC policy floors, not a
claim that Robinhood documents a fixed 6 TB minimum. Prepare local ext4/XFS NVMe
storage first; ERPC does not format disks. Only empty root-owned prepared
volumes and their verified empty `lost+found` can be adopted. Unknown data,
foreign accounts, nested/stacked mounts and another Nitro role/network are
refused.

Store the execution and beacon provider configuration in a concealed 1Password
field using the [shared provider schema](nitro-rpc.md#preparation-and-access). Both
endpoints must use authenticated public HTTPS. Provider values never enter
inventory, command arguments or Ansible task input. Use identifier-only
references. Replace the example public host name and SSH key path:

```sh
erpc v --chain robinhood init -n testnet --name rh-validator --host <public-host> --ssh-key <key.pub> --vault <vault> --l1-upstreams <op-reference>
erpc v --chain robinhood deploy -n testnet --name rh-validator --ssh-key <key.pub>
erpc v --chain robinhood prepare-registration -n testnet --name rh-validator --ssh-key <key.pub>
```

`init` reserves the original public wallet/address/creation intent, stores the
new dedicated key as a separate concealed item and verifies exact readback
before any host transfer. An ambiguous write or missing original item never
permits a replacement wallet to be generated on retry. Public list/plan reads
use projected fields; mainnet and testnet items, keys and host paths cannot
cross-adopt each other or Arbitrum One.

Arrange admission externally and fund/wrap/approve only the dedicated wallet.
`prepare-registration`, `validate-registration` and `registration-status` on
this validator host make fresh read-only observations and prepare unsigned
funding/wrap/Rollup approval data. Revalidate immediately before external action.
The existing [public administrator admission command](robinhood-admission.md)
remains available on an independently managed Robinhood RPC inventory host.
Neither observation path submits administrator transactions.

After the original Watchtower is synchronized and its WASM validation is healthy:

```sh
erpc v --chain robinhood deploy -n testnet --name rh-validator --ssh-key <key.pub> --activate-signer
erpc --json v --chain robinhood status -n testnet --name rh-validator --ssh-key <key.pub>
```

Use `-n mainnet` for the independently qualified mainnet profile. Activation
rechecks admission/funding and the original key, drains the original observer,
and durably records its database, node identity and validation history before
signing starts. An already staked arbitrary wallet cannot be adopted as a fresh
signer. `validator_ready` means the original active Defensive runtime and local
validation passed current checks; it does not mean a rival assertion has been
posted. `original_wallet_staked` reports that fact separately. A synchronized
Watchtower still returns a non-success active-validator status.

## Operations, retention and recovery

`list`, `plan`, `logs`, `start`, `stop`, `restart`, `update`, `update-config` and
`destroy` use the same explicit network and original inventory. `plan` displays
the fixed source/version and desired mode. JSON journal lines use stdout NDJSON.
`update` requires `--version 3.12.2`; it preserves active mode. There is no
`--strategy MakeNodes`, used-key import, history reset or purge-data option.

`stop` and `destroy` revoke the current generation and drain only original
processes. `destroy` retires while retaining the original wallet, data and
signing history. Missing or changed native services do not authorize signaling
foreign processes. Persistence failure remains an error even if emergency
shutdown succeeds; complete storage failure cannot guarantee reboot fencing.

`update-config --l1-upstreams <op-reference>` can replace an unavailable provider.
The carried recovery first stops and retains original history, then checks
current original accounts and volumes before private provider delivery. New
provider chain/Beacon/protocol checks precede ciphertext publication. Stale
private requests cannot overtake a subsequent stop. The local parent CA and
wallet are not replaced by a provider change.

`deploy --restore-custody` restores only the original active wallet from the
original 1Password item, after original stop/history qualification, then
continues normal guarded deployment. Missing original key-origin or history
receipts are refused. Before the first history receipt, an interrupted active
attempt can rebuild only the same non-signing observer and repeat validation;
it cannot demote an already activated signer.

Root-owned encrypted custody and original numeric account receipts are checked
before narrow runtime material is granted. The authenticated local parent
transport uses the original private CA; native process, account, container,
PID generation and loopback listeners are qualified. RPC/WS, authenticated
validation, metrics and credentialed parent listeners remain loopback-only;
ingress is SSH from the management ACL through the shared confirmed firewall.
An administrator reassigning an already authorized UID or copying keys outside
ERPC is outside these managed guarantees.

Offline evidence covers actual compiled bundles, strict units, carried Ansible
routing, public/secret scope separation, original volume/account/history
failures, provider and wallet recovery, cancellation, financial-method rejection
and parent observations. Real Linux/PID1/Docker behavior, native genesis replay,
provider historical-data availability, key delivery and funded participation
remain deferred acceptance work. No production readiness claim replaces that
later real-host test batch.
