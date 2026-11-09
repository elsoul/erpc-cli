<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Hyperliquid non-validator RPC

`erpc rpc --chain hyperliquid` manages a dedicated Ubuntu 24.04 x86-64
non-validator host on `mainnet` or `testnet`. The `r` alias selects the same
operations. It runs the official supervisor, an isolated HTTP gateway and public
output retention. This role does not import a validator or financial key.

The [official node instructions at the qualified commit](https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/README.md)
recommend 16 vCPUs, 128 GB RAM and a 500 GB SSD for non-validators. They document
the supervisor's automatic child signature verification and refusal to upgrade
when verification fails. ERPC pins and verifies the supervisor itself; the child
remains vendor managed. Its observed executable hash is an observation of running
bytes, not a reproducible build or a source-commit attestation. A stable native
release tag and matching child source commit are not documented by that source.

## Qualified supervisor

The public key is pinned to the [same instruction commit](https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/pub_key.asc).
ERPC verifies the artifact length, SHA-256, detached signature, original publisher
fingerprint and signature timestamp before publishing executable bytes. The
publisher fingerprint is `CF2C2EA3DC3E8F042A55FB6503254A9349F1820B`.

| Network | HyperEVM chain ID | Supervisor SHA-256 | Signature UTC |
|---|---:|---|---|
| mainnet | 999 | `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31` | 2026-09-09 09:29:14 |
| testnet | 998 | `9190ff844064ec879778f1441488d0384ae74c83fb30720296118638bf408b83` | 2026-09-08 10:33:47 |

These observations were qualified on 2026-10-27. The catalog carries network
specific official origins, exact bytes and signature digests. Artifact requests
do not follow redirects or ambient HTTP proxies. A changed supervisor requires
an explicitly selected `update` from a CLI carrying the new qualification.
Signature-time downgrades are refused. `update-config` does not silently select
another supervisor. Vendor child updates can occur independently of either verb.

## Initialize and deploy

Use an SSH agent and the corresponding public key file. Verify the initial host
fingerprint independently. The public IPv4 address is the operator's explicit
peer advertisement and becomes part of immutable host ownership.

```sh
erpc rpc --chain hyperliquid --network testnet init \
  --name hl-test --host 192.0.2.10 --user ubuntu \
  --fingerprint '<verified SSH SHA256 fingerprint>' \
  --public-ip '<server public IPv4>' --ssh-key ./operator.pub \
  --vault '<network inventory vault>' --rpc-allow 192.0.2.20/32

erpc rpc --chain hyperliquid --network testnet deploy \
  --name hl-test --ssh-key ./operator.pub --vault '<network inventory vault>'

erpc rpc --chain hyperliquid --network testnet status \
  --name hl-test --ssh-key ./operator.pub --vault '<network inventory vault>' --json
```

The example addresses are documentation placeholders. `--public-ip` requires a
public numeric IPv4 address; special-use addresses are refused. `--port` selects
the SSH transport port. Filtering uses the server port observed through SSH, so a
forwarded transport port does not become the host's firewall port.

Initialization checks the remote contract before reserving inventory, then
reserves original numeric service identities before creating their accounts.
Unknown existing accounts, runtime files, data or boot units are not adopted.
An interrupted initialization resumes only its original ownership. Deployment
prepares the pinned supervisor and fixed public configuration, applies a bounded
firewall candidate, confirms it over a fresh SSH connection and then starts the
services. Preparation and startup use a unique operation intent; stopping or
retiring revokes queued activation.

## Operations

| Verb | Effect |
|---|---|
| `init` | Reserve the dedicated host, original accounts and immutable ownership; no node startup |
| `deploy` | Prepare and start the selected supervisor with exact firewall confirmation |
| `list` | Read public network inventory |
| `status` | Check startup authority, owned sockets, network freshness and observed executable identity |
| `logs` | Read the owned services' journals; `--lines` is bounded and `--follow` streams |
| `start` | Start a completed installation after checking retained configuration, capacity and filtering |
| `stop` | Revoke activation and stop owned services/processes; preserve data and filtering |
| `restart` | Revoke and stop first, then validate the completed installation before starting |
| `update` | Explicitly select this CLI's qualified supervisor; retain the native data tree |
| `update-config` | Apply the requested public ingress policy and reconfirm filtering |
| `plan` | Show public ownership and qualification without changing the host |
| `destroy` | Retire and disable owned services, preserving original accounts, data and filtering |

Public JSON log events and completion records are compact lines on stdout.
Normal text remains suitable for interactive use. A not-ready status is a
non-success outcome, including absent listeners, wrong process ownership,
incomplete preparation or stale network observations.

## Network and storage policy

The gateway listens on port 8545 and is closed to external callers unless their
address appears in `--rpc-allow`. Management ingress accepts explicit
`--management-allow` ranges and the current SSH controller address. Ports 4001
and 4002 are open for gossip. ERPC allows both TCP and UDP there as its deployment
policy; the cited upstream instructions do not specify their transports.
The native port 3001 is not exposed publicly.

The gateway forwards a closed JSON-RPC method set and read-only local `/info`
requests to the fixed loopback native listener. It refuses filesystem snapshot
requests and administrative/signing APIs. Sending an already signed EVM
transaction remains an ordinary RPC operation. Native historical-series and
WebSocket support are limited as described by the official instructions; the
gateway does not provide an archive or WebSocket service.

The managed volume is `/var/lib/erpc-hyperliquid`; mounting that complete root is
supported. Nested data/bootstrap mounts and indirect native paths are refused.
Capacity is checked on an opened descriptor for the actual native filesystem.
ERPC requires at least 490 GB formatted total capacity. Required free space is
`max(100 GB, 450 GB - allocated bytes under home/hl)`; this is ERPC's initial-sync
and operating-headroom policy, not a guarantee about future network growth.

The native home and data belong to the original dedicated UID. The gateway uses
a different dedicated UID. Public configuration and helpers remain root-owned.
The supervisor has a read-only public verification keyring. The default output
mode is `recent-actions`, documented upstream to retain only the two latest
replica-command height files. An hourly retention job removes allowlisted public
outputs older than 48 hours and older periodic snapshots while keeping the latest
two numeric snapshots. Private native state and unknown paths are not retention
targets. This RPC profile is not a historical-data backup.

## Recovery and observation

Retry the same target after an acquisition or configuration failure. If a
preparation cannot be completed, `deploy`, `update` and `update-config` accept
`--recover-preparation`: owned shutdown is required, the old pending receipt is
archived, only its preparation marker is cleared, and every native data file is
retained. A fresh operation intent is required afterwards. This is not a database
purge or an automatic repair of native state.

Owned shutdown includes orphan processes under the original dedicated UID and
expected cgroup when a service unit is missing. Failed cancellation persistence
still attempts owned shutdown and returns an error. It does not claim durable
reboot prevention when storage refused the cancellation records.

Status binds both the native and gateway listeners to their kernel socket,
process generation, original numeric UID and service cgroup before attributing
loopback responses. It verifies the HyperEVM chain ID and freshness of HyperEVM
and HyperCore observations. The running supervisor must match the qualified
hash. The child hash, size and observation timestamp are reported separately;
child source mapping and a qualified public genesis artifact remain
`not documented` rather than inferred from a network name.

Offline tests cover command routing, artifact verification, namespace entrypoints,
original identity reservation, cancellation, recovery, public filtering and
retention. Real host synchronization, vendor-child compatibility, systemd
reboots and sustained-load acceptance require the separate host acceptance run.
