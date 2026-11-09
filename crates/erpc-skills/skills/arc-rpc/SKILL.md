---
name: arc-rpc
description: Running an Arc RPC node (mainnet or testnet) with erpc r --chain arc -- its types (full, archive, provider), the server and disk it needs, how long and how big, init, deploy, status, logs, start/stop/restart, qualified updates, update-config, plan, destroy -- its firewall, and reading what went wrong.
---

# Arc RPC node

All twelve RPC verbs are connected on mainnet and testnet. The original-authority
profile has offline verification; its real-host acceptance remains deferred. A node is the execution layer (`arc-node-execution`, a Reth;
JSON-RPC on 8545 and WebSocket on 8546) and the consensus layer (`arc-node-consensus`),
joined over IPC sockets in /run/arc and run by systemd with the original numeric `arc` UID/GID.

## Types

`init --type` picks one, and it is fixed once stored (it decides what history the data holds):

- `full` (default): follows Arc's public relays, keeps the last 237,600 blocks; transactions go
  out through the relays.
- `archive`: follows the same way and keeps every block's history and state; the data only
  grows. Old state answers (`eth_getBalance` at an old block).
- `provider`: an RPC provider (relay) node Arc has onboarded: peers with Arc's sentries
  (`--trusted-peers <enode URLs>`, `--sentry-peers <multiaddrs>`, both from onboarding), opens
  30303 to everyone and 27000 to the sentries, and serves only `eth,net,web3,rpc`. Without
  onboarding there is nothing to peer with; suggest `full`.

`status` and deployment results distinguish applied changes from observed readiness.
`start` and `restart` include the applied action/layer separately; node readiness
still includes all service and synchronization problems, even for execution-only
startup. JSON `ready: null` means the public comparison is unavailable, not a proven local
failure or an accepted healthy deployment; it returns a non-success observation
outcome. Local checks require the full served commit, network genesis, non-syncing
response and a recent latest header. The 300-second age / 120-second future-clock
bounds are ERPC monitoring policy. `logs --json` produces one compact stdout JSON
record per native/diagnostic line and a compact completion or error record.
The host and reporting controls are tested offline; final live acceptance remains
required. See [original runtime](../../../../docs/arc-runtime.md) for exact guarantees.

Arc's validator role is permissioned. `erpc v --chain arc` has a dedicated
preparation lifecycle with separate local peer custody, public Remote signer
qualification and unsigned governance intents. Production signing remains held;
`activate` refuses until the Circle signing-history contract is qualified.
See [validator preparation](../../../../docs/arc-validator.md). Do not substitute
the RPC profile for an admitted validator or infer activation from membership.

`--debug-api` adds `debug` and `trace` (useful mostly on `archive`); refused on `provider`.
Keep `--rpc-allow` to your own proxies when it is on. `update-config --debug-api false` turns
it off, and `update-config` also replaces a provider's peers.

The history type stays bound to the original inventory item. `--forget` is refused;
do not unlink that item to adopt its consensus key as a new node. A separately named
fresh reservation has a new identity. See [Arc custody](../../../../docs/arc-custody.md)
for original-key reservation and recovery semantics.

## The server

Ubuntu 24.04 with systemd 255, 64 GB RAM and a passwordless sudo login. Prepare
an ext4/XFS UUID-addressed filesystem at `/var/lib/arc`; init does not format disks.
The root must be empty and root-owned, or contain only a verified empty root-owned
`lost+found`. Existing original volumes retain their inodes and recorded identity.
Nested/stacked mounts are refused. ERPC's initial capacity estimates are 1 TB for
full/provider or 2 TB for archive, less allocated original data, with at least
100 GB remaining. These estimates are not guarantees about upstream snapshots.

Only the carried v0.8.1 exact source/archive catalog can execute. Future releases
need an explicit catalog addition. Current version strings alone do not authorize
an existing host or a downgrade.

## Commands

What every chain's commands share -- the inventory in 1Password and where keys are kept, logging in through an
SSH agent with the verb's `--ssh-key`, the host key, `plan`, `--yes`, `--json`, repeating a verb
-- is in the skill `erpc-nodes`. For Arc: pass `--chain arc` every time, and a node is named by
`-n` and `--name`:

```sh
erpc r --chain arc -n testnet --name arc1 <verb> --ssh-key ~/.ssh/id_ed25519.pub …
```

The consensus key lives in 1Password with the node's item; deploy puts it on the node encrypted
with systemd-creds.

## The path

1. `init --host <ip> [--type full|archive|provider] --rpc-allow <proxy ips>
   --management-allow <stable ssh range> [--monitoring-allow <ips>] [--version vX.Y.Z]`: shows
   the server's host key to check against its console (or takes `--fingerprint SHA256:…`),
   checks the server, pins the carried qualified arc-node release with its commit and
   archive digest, reserves the public host and consensus identity, stores and verifies that
   original key in 1Password, then prepares the host. Retrying an ambiguous creation only
   recovers a matching original item; it never regenerates a key.
2. `deploy`: installs the pinned release, restores the snapshot for the type, puts the
   consensus key in place encrypted with systemd-creds, starts both layers, applies the
   firewall in a separate preparation confirmed through a fresh SSH connection. It
   fences/stops original writers and preserves the same key and active data on retry.
3. Operate:
   - `status`: both layers, the release that is actually serving, head and lag behind the
     public endpoint, data used and free, firewall and key. Exits 1 on a problem. Right after a
     start a lag of a few dozen blocks is normal; in steady state it is 0 or 1.
   - `logs [--layer execution|consensus|both] [--lines N] [-f]`.
   - `start|stop|restart [--layer execution|consensus]`: always in dependency order (the
     consensus layer needs the execution layer, so restarting execution restarts both).
   - `update [--version vX.Y.Z]`: installs beside the running release and restarts on it;
     the highest opened database source forbids downgrades and same-version substitution.
   - `update-config --rpc-allow … --management-allow … --monitoring-allow … --debug-api`:
     each list given replaces the stored one; ones not given stay. Opening monitoring also
     moves the metrics (9001, 29000) off loopback, so the layers restart once.
   - `plan --change deploy|update|update-config` (same flags): says what would change, changes
     nothing.
   - `destroy`: retires services while retaining filtering, original key, data and
     authority receipts. `deploy` resumes that same identity/history. Both
     `--purge-data` and `--forget` are refused.
   - `deploy --restore-custody`: fences/stops originals, restores only the same key,
     retains prior ciphertext, then continues deployment.
   - `deploy --reset-bootstrap`: quarantines an interrupted initial snapshot;
     never clears active or already-promoted history.
   - `init --migrate-authority` plus all four independent historical record flags:
     qualifies a supported previous managed host and leaves first migration retired.
     See the migration command and refusal boundaries in the original-runtime guide.

## The firewall

The table is `inet erpc_arc` (the rules and the two-minute rollback are in `erpc-nodes`): SSH from
`--management-allow` and erpc's own address, 8545 and 8546 from `--rpc-allow`, 9001 and 29000 from
`--monitoring-allow`; a provider node also opens 30303 to everyone and 27000 to its sentries.
After reboot, confirmed filtering and eligible original units can return. Stopped or
retired services retain their fences; a changed original account or helper prevents
startup before credential delivery.

## When something fails

- A failed `update` retains the source floor and original data. There is no automatic
  database rollback. Read `logs`, repair the cause and retry the qualified source.
- `start` that waits for "the execution layer made no IPC sockets": the execution layer did not
  come up; its `logs --layer execution` say why.
- A snapshot restore that stops: `logs` shows `arc-snapshots`; deploy again starts the fetch
  again (it is marked done only when it finishes).
- `status` problems name what is wrong: a layer inactive, the release serving not the pinned
  one, too far behind, less than 100 GB free, an unconfirmed firewall change.

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a node erpc runs, the release it
pinned is the one `init`, `update` and `status` show.

- https://github.com/circlefin/arc-node: the node's source; releases (tag, commit, archives)
  at https://github.com/circlefin/arc-node/releases
- https://docs.arc.io/arc/references/node-requirements: hardware and network; with
  https://docs.arc.io/arc/tutorials/run-an-arc-node and
  https://docs.arc.io/arc/tutorials/deploy-node-as-service (each page also as `.md`)
