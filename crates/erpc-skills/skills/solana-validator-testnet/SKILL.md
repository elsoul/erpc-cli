---
name: solana-validator-testnet
description: Running a Solana testnet validator with erpc -- the server it needs, then erpc v init, deploy, keys, vote-account, list and status -- and what erpc does not do yet.
---

# Solana validator, testnet

Testnet is where a validator is learnt and every change is tried first. erpc runs the whole path
for it today, with any of the four clients (agave, jito, allnodes-jito, the full Firedancer).

## The server

Bare metal APP from ERPC (in stock in the region wanted: `server_stock`, kind `bare_metal`, type APP),
Ubuntu 22.04 or 24.04, reached by an SSH key (a file or the 1Password SSH agent). A VPS is not
enough. Testnet does not need mainnet's hardware, but the catalogue's APP specs are the floor.

## The path

1. `erpc v init`: the inventory, the identity key in 1Password, and the server's `solv` user.
2. `erpc v deploy`: the base system and the client, started in safe mode (not voting).
3. `erpc v keys`: the validator's keys; makes or imports the vote account key and withdraw
   authority.
4. `erpc v vote-account`: creates the vote account on chain and registers its BLS key. Deploy
   then writes the voting start script once the vote account checks out.
5. `erpc v list` and `erpc v status`: the hosts, and a host's state (caught up or not).

Pass `--network testnet` (`-n testnet`) and `--chain solana`, or set
`erpc config set default_chain solana` once.
What every chain's commands share (1Password, the SSH agent and `--ssh-key` after the verb, the
host key, `--yes`, `--json`, repeating a verb) is in the skill `erpc-nodes`.

## Not in erpc yet

`erpc v logs`, `start`, `stop`, `restart`, `update`, `update-config`, `plan` and `destroy` only
say they are not implemented; node tuning, XDP and switching the identity to a spare host are
not done either. The clients are all there: `erpc v init --client agave|jito|allnodes-jito|firedancer`
(`firedancer` is the full Firedancer). SLV (`slv v ...`) still does
those. Say so when asked, and give the SLV command if the user wants it now.

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a node erpc runs, the release it
pinned is the one `init`, `update` and `status` show.

- https://github.com/anza-xyz/agave and https://docs.anza.xyz/operations/requirements: Agave and
  Anza's operator guide
- https://github.com/jito-foundation/jito-solana and https://docs.jito.wtf/: Jito
- https://github.com/allnodes/solana-jito: Allnodes' Jito fork
- https://github.com/firedancer-io/firedancer and https://docs.firedancer.io/guide/getting-started.html:
  Firedancer
