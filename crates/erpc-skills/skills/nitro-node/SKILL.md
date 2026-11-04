---
name: nitro-node
description: Operate Arbitrum and Robinhood Nitro follower RPC nodes with erpc, including qualified image digests, private L1 credentials, network-specific genesis, and safe lifecycle recovery.
---

# Nitro follower nodes

Use `erpc r --chain arbitrum` with mainnet, nova or sepolia, and
`erpc r --chain robinhood` with mainnet or testnet. These are dedicated follower
hosts. Staking, assertion validation, sequencer and batch-poster signing are
separate roles and are not activated by this backend.

Initialize with a pinned SSH host, operator public key, network vault and
`--l1-upstreams` referencing one uniquely labeled CONCEALED 1Password field.
The JSON value contains execution and beacon endpoints, optional Authorization or
X-API-Key headers, and an explicit numeric-loopback exception when needed. Never
put provider URLs or credentials in command arguments or public inventory.

The shared L1 proxy verifies Ethereum execution and beacon genesis identities,
validates each DNS resolution, pins numeric connections with TLS hostname checking,
refuses redirects and forwards only approved read methods. Its dedicated account
and encrypted systemd credential keep provider secrets out of Nitro's container.
Only local RPC/WS/metrics are exposed; application gateways are separate.

Nitro 3.12.1 is source-qualified, with official image manifests pinned by digest.
Robinhood's software notice still recommends an older version; do not call the
newer upstream selection a Robinhood endorsement or a successful live deployment.
Mainnet requires its pinned custom genesis; testnet does not. PathDB provides
online pruning; full RPC is not archive RPC. One/Nova/Sepolia bootstrap from the
official checksummed full-path snapshots, according to the pinned Nitro resolver.

All twelve lifecycle verbs are available. Host ownership precedes every mutation;
initialization cannot repurpose another network's host or adopt an unowned named
container. Updates use the reviewed catalog, preserve data, refuse database
downgrades, and keep interrupted installations fenced. Resume with deploy at the
same stored target. Destroy retains ownership, encrypted credentials and data.

`status` combines service state, L2 chain ID, verified L1 identity, sync status and
recent blocks. A successful deploy can still be syncing. Real-host bootstrap,
RPC/WS, reboot and failure recovery remain deferred by user direction.
See `docs/nitro-rpc.md` for the full operational contract and acceptance checklist.

## Official sources

- https://docs.arbitrum.io/run-a-node/run-full-node — node operation and resources.
- https://github.com/OffchainLabs/nitro — exact release source and configuration behavior.
- https://docs.robinhood.com/chain/run-a-full-node/ — Robinhood network/genesis instructions.
- https://docs.robinhood.com/chain/notices-and-upgrades/ — chain-specific notices.
