---
name: solana-validator-testnet
description: Running a Solana testnet validator with erpc -- a new validator on the native backend (the server and the keys it needs, then erpc v init, deploy, status, registration and voting activation), a validator an earlier erpc recorded on the solv backend and the commands it keeps, and erpc v migration from one to the other.
---

# Solana validator, testnet

Testnet is where a validator is learnt and every change is tried first. How erpc runs one
depends on what the inventory holds under the validator's name:

- No server yet: a **native** node. erpc builds Agave on the server and runs it under accounts
  of its own. Every new validator is one; `--backend solv` cannot start a new node.
- A server that an earlier erpc set up with its `solv` user: the **solv** backend, which keeps
  the commands it was set up with ("A validator recorded as solv" below).

`erpc --json v list` gives each validator's `backend` (`null` for one registered without a host
yet: its init resumes it). Pass `--chain solana` and `-n testnet`
(`--network testnet`), or set `erpc config set default_chain solana` once. What every chain's
commands share (1Password, the SSH agent and `--ssh-key` after the verb, the host key, `--yes`,
`--json`) is in the skill `erpc-nodes`.

## A new validator: what must be ready

The server. `init` refuses one below this floor, which is lower than mainnet's only for memory:

- Ubuntu 24.04 and no other release, systemd 255, x86-64 with AVX2 and SHA-NI on every CPU.
- 24 threads or more and 120 GiB of memory or more, as the running kernel reports them (a 128 GB machine
  passes).
- Three separate ext4 or XFS filesystems, mounted and empty (an empty `lost+found` aside):
  `/mnt/erpc-solana-accounts` and `/mnt/erpc-solana-ledger` of 900 GB or more each,
  `/mnt/erpc-solana-snapshots` of 450 GB or more. erpc does not partition, format or mount
  disks; `init` is given each filesystem's UUID (its name under `/dev/disk/by-uuid`).
- No `solv` user and nothing under `/etc/erpc`: the server is for this node alone.
- A login with passwordless sudo (`--user`, `ubuntu` by default) whose key an SSH agent holds.

Before suggesting a server, compare its threads, memory and disks in `server_catalog` with this
floor, whatever the server type is called, and say plainly when it falls short. A VPS is not
enough.

The keys. erpc makes none on this path: the operator makes them and keeps them in 1Password
before `init`.

- The validator's identity: a Solana JSON keypair in a concealed field named `keypair`. Its
  reference is given by id, `--identity-reference op://<vault-id>/<item-id>/keypair` (the
  26-character ids, not names), with its public key, `--identity-public`.
- A second keypair, which the node runs under while it only syncs: `--sync-reference
  op://<vault-id>/<item-id>/<field>` (a concealed field too) and `--sync-public`.
- Public keys only for the vote account and the withdraw authority: `--vote-public` and
  `--withdraw-public`. erpc never takes their private keys.
- `--commission`, 0 to 100. erpc cannot change it afterwards.

The four keys must all differ.

## A new validator: the path

One name is the validator and its one server: lowercase letters, digits and `-`, a letter
first, 32 characters at most. `--vault` is needed only the first time on a network.

```sh
erpc v --chain solana -n testnet --name <name> init --host <address> \
  --ssh-key ~/.ssh/id_ed25519.pub --vault <vault id> --management-allow <your ranges> \
  --identity-reference op://<vault-id>/<item-id>/keypair --identity-public <key> \
  --sync-reference op://<vault-id>/<item-id>/keypair --sync-public <key> \
  --vote-public <key> --withdraw-public <key> --commission <percent> \
  --accounts-uuid <uuid> --ledger-uuid <uuid> --snapshots-uuid <uuid>
erpc v --chain solana -n testnet --name <name> deploy --ssh-key ~/.ssh/id_ed25519.pub
erpc v --chain solana -n testnet --name <name> status --ssh-key ~/.ssh/id_ed25519.pub
```

1. `init` asks first, then checks the platform and the three filesystems, records the validator
   and its server as two items in 1Password (references and public keys, no key), and prepares
   the server: build tools from apt, three accounts that cannot log in, a data directory on each
   filesystem, four kernel settings and the clock service. It starts no node. The same command
   again resumes it.
2. `deploy` builds Agave from source on the server (4.4.0 with this erpc; `plan` shows the
   target), under its builder account and on two CPU cores. The server stops a source fetch
   after 30 minutes and a compile after four hours; erpc waits and says so each minute. If the
   command is interrupted the build goes on: run the same command again, and read it with
   `logs --component build`. A failed build is dropped with `deploy --abandon-build` before
   another can start. Then deploy applies the firewall and confirms it over a new SSH
   connection, reads the sync keypair from 1Password and sends it over SSH to the server, which
   keeps it encrypted for that machine, and starts Agave with voting off. The identity keypair
   stays in 1Password. A second `deploy` builds again and restarts the node.
3. `status` prints a JSON report. `rpc_ready` is true when the node answers on the right
   network under the sync identity and the pinned version, is healthy, and has a finalized
   block at most 120 seconds old. `mode` is `sync` and `validator_ready` is false, so `status`
   exits 5 for a validator that only syncs, caught up or not: read `rpc_ready`. Exit 1 means
   erpc could not ask the node.

After `deploy` the SSH port answers only the address erpc connected from and the
`--management-allow` ranges, so give a stable range at `init` (or later with `update-config
--management-allow <ranges>`) and keep the provider's console at hand. Ports 8000 to 8032 are
open to peers; the node's RPC is on the server's loopback only. erpc's table covers only the SSH
port, 8000 to 8032 and the RPC ports (8899, 8900, 7211 and 7212, closed on a validator); every
other port is left to the server's own rules.

Voting. erpc signs nothing and sends no transaction. The vote account is created and its BLS
key registered with Solana's own tools, with the identity as voter and the withdraw authority
and commission given at `init`. `erpc v registration --name <name> --action
status|validate|prepare --bls <BLS public key> --commission <percent>` reads the chain:
`validate` succeeds only when the account matches, and `prepare --step
create-vote|register-bls|fund-identity` prints the step as public JSON (not a transaction) to
build and sign with those tools; `fund-identity`, a transfer to the identity, also takes
`--amount-lamports <n>`.
erpc refuses to activate until `status` shows `rpc_ready` true, the vote account matches, holds
at least its rent and has its BLS key registered, and the identity's balance is above zero.
Then `erpc v --chain solana -n testnet --name <name> plan --ssh-key ~/.ssh/id_ed25519.pub
--activate-validator --bls-public <key> --exclusive-identity` previews, without reading the vote
account or the balances, and `deploy` with the same flags moves the node from the sync identity
to the validator's and starts voting, without building again. `--exclusive-identity` is the
operator's statement that the identity runs nowhere else. From then on `validator_ready` needs
the vote account current, staked and voting within 128 slots.

Operating it: `logs --component node|firewall|build` (`--lines` up to 1000; there is no `-f`),
`stop`, `start`, `restart`, `update` (builds the release this erpc pins), `plan --change
deploy|update|update-config`, and `destroy`, which stops and retires the node and keeps its
data, its key on the server and the firewall; `deploy` brings it back.

What a native validator does not take: a client other than Agave (`--client
jito|allnodes-jito|firedancer` is refused), so no Jito region either; a choice of release (it is
the one this erpc pins); key making or import (`--identity`, `--vote-account` and `--authority`
are refused); `--spare`, `--host-name` and `--rpc-allow`. `erpc v keys` shows its public keys
and nothing more, and `erpc v vote-account` is refused: use `erpc v registration`.

## A validator recorded as solv

`erpc v init` (to resume, or `--spare` for another server), `deploy`, `status`, `keys` and
`vote-account` work as they did, with the client it was set up with and the keys erpc made or
imported in 1Password. Its `logs`, `start`, `stop`, `restart`, `update`, `update-config`, `plan`
and `destroy` only say they are not implemented; SLV (`slv v ...`) does those, so give the SLV
command if the user wants it now. The native flags above are refused for it.

`erpc v migration plan|inspect|execute|resume|status` moves a solv validator to the native
backend, copying its data to three filesystems provisioned for it. `plan` reads the inventory
only; it reports a validator whose client is not Agave as unsupported, and that validator stays
on solv. So does one on more than one host, or whose Agave was not built from 4.4.0-beta.1, the
only testnet origin this erpc accepts. Migration asks for records of the original server kept
from before (its passwd, group and machine-id files, and the Agave versions it has run);
`docs/solana-native.md` in erpc's repository has the procedure.

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a native node, `plan` shows the
release it would be built from and `status` the one it runs; `erpc --json v list` gives a solv
validator's `version`.

- https://github.com/anza-xyz/agave and https://docs.anza.xyz/operations/requirements: Agave and
  Anza's operator guide
- https://github.com/jito-foundation/jito-solana and https://docs.jito.wtf/: Jito
- https://github.com/allnodes/solana-jito: Allnodes' Jito fork
- https://github.com/firedancer-io/firedancer and https://docs.firedancer.io/guide/getting-started.html:
  Firedancer
