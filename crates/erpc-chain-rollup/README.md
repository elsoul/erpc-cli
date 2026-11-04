<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Ethereum L1 upstream transport and follower profiles

This crate provides concealed upstream configuration validation, a carried Python
proxy and chain-specific follower selectors. It does **not** register deployment
commands or install a service by itself. Consumers must provide host ownership,
credential provisioning, service lifecycle and their own chain acceptance checks.

`Credential::parse` accepts a `SecretString` containing one JSON object with
`execution` and `beacon` endpoints. Each endpoint has a `url`, optional `headers`
(only `Authorization` and `X-API-Key`), and optional boolean `allow_loopback`.
The result retains the original JSON as a concealed value. Store provider URLs
and headers only in a concealed secret-store field. Readable node inventory may
carry the secret reference, never the credential itself.

The carried `UPSTREAM_PROXY` reads only the `l1-upstreams` file beneath systemd's
`CREDENTIALS_DIRECTORY`. A consumer must provision it with
`LoadCredentialEncrypted=l1-upstreams:…`, under a dedicated unprivileged user and
with core dumps disabled. The only command-line argument is the expected L1
network, `mainnet` or `sepolia`. The consumer must protect its executable and
unit/configuration and ensure conflicting services cannot share its loopback
ports. The proxy binds execution on 127.0.0.1:18545 and beacon on 127.0.0.1:15052.
It starts listening only after execution chain ID/block-zero hash and beacon
genesis time/validators root/fork version match; it rechecks after 60 seconds.
A provider is still trusted to return truthful L1 data after those checks.

HTTPS uses normal certificate validation and the original hostname for TLS SNI.
Every connection validates all DNS answers and connects to the checked numeric
address without a second lookup. Private/link-local/transition IP destinations,
redirects and environment proxies are refused. Explicit numeric loopback may use
HTTP for an operator-owned local Ethereum pair. ERPC account/service hosts cannot
be selected through this separate upstream transport.

The execution listener accepts a bounded set of read-only JSON-RPC methods; it
cannot submit transactions or invoke engine/admin/debug methods. The beacon
listener accepts GET requests beneath beacon/config/node APIs, with indices
queries scoped to blob sidecars and versioned hashes scoped to blobs. Caller
headers, authorities and arbitrary paths are not forwarded. Provider HTTP/RPC
errors use fixed messages because diagnostics can contain credentials. JSON-RPC
error codes remain bounded signed integers so clients can detect unsupported
methods. HTTP 404 is preserved only for missing beacon blob/sidecar resources;
other HTTP failures become a generic 502. No provider error body or headers are
forwarded. Blob hash queries accept both repeated keys and comma-separated
hashes used by the Base client.
Successful provider results retain their data, so the provider remains trusted.
There are eight bounded workers per listener, request/response size limits and
socket timeouts. Consumers must account for bounded responses when selecting
provider limits and batching; this component makes no throughput guarantee.

## Source qualification

Read 2026-10-26. These selectors establish source compatibility, not a claim of
successful live deployment or endorsement of a release by a chain operator.

| Family/network | Execution selector | Consensus selector | L1 |
|---|---|---|---|
| Optimism/mainnet | optimism | op-mainnet | mainnet |
| Optimism/sepolia | optimism-sepolia | op-sepolia | sepolia |
| Base/mainnet | base | 8453 | mainnet |
| Base/sepolia | base-sepolia | 84532 | sepolia |
| Soneium/mainnet | soneium | soneium-mainnet | mainnet |
| Soneium/minato | soneium-minato-sepolia | soneium-minato-sepolia | sepolia |

- [op-reth v2.6.1 generated selectors](https://github.com/ethereum-optimism/optimism/blob/e16bffa18420c86dbab693097bc33117f74a5f7d/rust/op-reth/crates/chainspec/src/superchain/chain_spec_macro.rs) and [included Soneium configurations](https://github.com/ethereum-optimism/optimism/blob/e16bffa18420c86dbab693097bc33117f74a5f7d/rust/op-reth/crates/chainspec/src/superchain/chain_specs.rs).
- [op-node v1.19.11 names](https://github.com/ethereum-optimism/optimism/blob/43c071cbff8ad7512581561aa2d43c990544b650/op-node/chaincfg/chains.go) combine each registry name and parent network.
- [Registry chain identifiers and IDs](https://github.com/ethereum-optimism/superchain-registry/blob/08d6a44910d75e28a5ee1c7c047d3bdd0bbdbdd2/chainList.json), at the submodule commit selected by op-node v1.19.11.
- [Base beacon request/error handling](https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/crates/consensus/providers/src/beacon_client.rs) requires comma-separated blob hashes and distinguishes a missing slot from a retryable request.
- [Base v1.5.1 consensus selectors](https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/crates/consensus/cli/src/chain.rs) and [execution entrypoint](https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/etc/scripts/node/execution-entrypoint).
- [Ethereum execution genesis hashes](https://github.com/ethereum/go-ethereum/blob/d01e869d59696d915410b0b5bc374ae1a8b9418e/params/config.go), [mainnet beacon genesis](https://github.com/eth-clients/mainnet/blob/8cad4805e9cb5aa5e8e74d30e3f5029a7f133372/README.md), and [Sepolia beacon genesis](https://github.com/eth-clients/sepolia/blob/7b1b9d9549787b6bbf538f943304c4cf84f7e39e/metadata/README.md) provide the L1 identity constants.

Offline tests execute the actual proxy with mocked sockets/TLS/provider responses
and an ephemeral local HTTP fixture. They cover DNS rebinding, mixed-address
answers, TLS hostname binding, forbidden redirects, malformed requests, error
redaction, body limits and mismatched chain/genesis data. No real provider/node,
1Password credential or systemd service is used. Host credential provisioning and
real client compatibility remain acceptance work for the consuming backends.


Nitro 3.12.1 also needs two read-only historical lookups. Its
[`GetLogTransaction`](https://github.com/OffchainLabs/nitro/blob/70fa99a6e711f09eedd96a907290c3df0f3bcf7d/arbutil/transaction_data.go)
uses `TransactionInBlock` to recover sequencer batch calldata and verifies the
returned transaction hash against the log. The pinned
[geth client](https://github.com/OffchainLabs/go-ethereum/blob/5eee8f546e7602b7deeef7909f291bbebc77e233/ethclient/ethclient.go)
implements this with `eth_getTransactionByBlockHashAndIndex`; its full block reads
also request `eth_getUncleByBlockHashAndIndex` when historical L1 blocks contain
uncles. Both methods are allowed only on the execution listener. This does not
permit gas estimation, signing, transaction submission or wallet methods. Tests
send the actual block-hash/index parameter shape through the local HTTP listener
and prove that the beacon listener and write-method family reject it.
