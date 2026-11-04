---
name: bitcoin-node
description: Operate Bitcoin Core RPC nodes with erpc r --chain bitcoin, including signed releases, immutable full/pruned storage, private cookie RPC and index-aware health.
---


# Bitcoin Core nodes

`erpc r --chain bitcoin` owns a Core instance on mainnet, testnet4, default signet
or regtest. All twelve lifecycle verbs are implemented; real-host acceptance is
explicitly deferred. Bitcoin staking validators are N/A; this backend neither
mines nor enables wallets.

Use `init --host <server> --name <name> -n <network> --ssh-key <operator.pub>` to
reserve and prepare the host, then deploy. Ubuntu 24.04+, 4 GB RAM, two CPU cores,
Linux x86-64/ARM64 and provisioned storage are required. `full` defaults to retained
blocks plus txindex. Capacity is rechecked before prepare, deployment/resume and
start/reboot using remaining sync estimates and operating headroom. `--type pruned --prune-mib <MiB>` disables txindex. Retention
cannot change in place; never claim pruned data is a complete historical RPC.

Release pins require two carried Guix-builder signatures and the selected archive
hash, independently checked on the controller and target. The controller requires
GnuPG in a standard system location and uses a clean verifier environment. No
unverified download, cached latest-major inference or downgrade is permitted.

RPC and its cookie remain local to the host; wallet/REST are disabled, and daemon `-nosettings` prevents dynamic settings overrides. Prefer
running bitcoin-cli through SSH as the bitcoin service user. Do not suggest public
RPC exposure or imply that an SSH tunnel supplies cookie authentication. A separate
application TLS/authentication gateway is not provisioned by this backend.

`status` must distinguish process activity from correct genesis/network, completed
block download, txindex and current peers/tip. Regtest has different peer/time
expectations. `logs`, `start`, `stop`, `restart` and `update-config` operate only
after host ownership is checked. `update --version <stable>` preserves data and
never auto-rolls back database versions. Resume interrupted installs with deploy
at the stored target. Destroy retires/disables the owned service while retaining
data and ownership, and has no purge switch.

See `docs/bitcoin-rpc.md` for the operational contract and deferred live checklist.
## Official sources

For current client behavior, use official first-party sources:

- https://bitcoincore.org/en/download/ — release verification and downloads.
- https://github.com/bitcoin/bitcoin — client source, versioned configuration and RPC interfaces.
