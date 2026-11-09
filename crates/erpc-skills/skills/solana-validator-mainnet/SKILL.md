---
name: solana-validator-mainnet
description: Running a Solana mainnet validator -- the server erpc requires and the hardware worth having, a new validator on the native backend (Agave, keys the operator makes, sync first, explicit voting activation), a validator already recorded on the solv backend, BLS, node tuning (SMT, CPU boost, C-states, IRQ), rolling restarts and catch-up checks.
---

# Solana validator, mainnet

Real stake and real money: explain what each change does before suggesting it, and try it on
testnet first (skill `solana-validator-testnet`).

## What erpc does for mainnet today

Type `--chain solana` in every mainnet command. erpc refuses a mainnet change whose chain came
from `ERPC_CHAIN` or `default_chain`. What every chain's commands share (1Password, the SSH
agent, the host key, `--yes`, `--json`) is in the skill `erpc-nodes`. `erpc --json v list` gives
each validator's `backend` (`null` for one registered without a host yet: its init resumes it).

A new validator is a **native** node, set up as on testnet with `-n mainnet`: the same server
floor, the same keys made by the operator beforehand, the same `init`, `deploy` and `status`.
The skill `solana-validator-testnet` has the flags and what each step does. In short:

- It runs Agave, built from source on the server (4.4.0 with this erpc). No other client can be
  chosen, and erpc downloads no snapshot for it: Agave fetches one from the known validators
  this erpc pins.
- It starts sync-only: a separate sync keypair, voting off, the validator's identity still in
  1Password. `status` exits 5 with `validator_ready` false until voting is on; `rpc_ready` says
  whether it is caught up.
- Voting is switched on by `erpc v deploy -n mainnet --chain solana --name <name> --ssh-key
  <key.pub> --activate-validator --bls-public <key> --exclusive-identity`. erpc refuses it
  unless `status` shows `rpc_ready` true, the vote account exists with the identity, withdraw
  authority and commission given at `init`, holds at least its rent and has its BLS key
  registered with Solana's own tools, and the identity's balance is above zero (the
  `registration` command under "BLS key" below prints that transfer with `--step fund-identity
  --amount-lamports <n>` in place of `--step register-bls`). erpc signs nothing and sends no
  transaction. Preview it with `plan` and the same three flags; the preview does not read the
  vote account or the balances.
- `logs`, `stop`, `start`, `restart`, `update`, `update-config`, `plan` and `destroy` work. A
  `deploy` or `update` builds Agave again and then restarts the node on it: on a voting
  validator, say so before suggesting one.

A validator that an earlier erpc recorded with a server is on the **solv** backend and keeps its
commands: `erpc v init`, `deploy`, `status` and `keys`, sync-only under an unstaked identity
with the staked one kept in 1Password, the client it was set up with, and a snapshot from the
freshest and fastest of the ERPC mirrors and Avorio's public mirror (Firedancer fetches its
own). Voting on mainnet (vote account, BLS, putting the staked identity on), tuning and identity
switches are SLV's for it (`slv v ...`). `erpc v migration plan|inspect|execute|resume|status`
moves a qualified one to the native backend: one host running Agave built from 4.3.2, the only
mainnet origin this erpc accepts, with a startup configuration that `migration inspect` accepts.
Any other stays on solv.

## Hardware

erpc refuses a new validator's server below its floor. The rest is what is worth having, from
SLV's Solana guides.

| | erpc's floor | Worth having |
|---|---|---|
| OS | Ubuntu 24.04, systemd 255 | |
| CPU | 24 threads, AVX2 and SHA-NI | 2.8 GHz or more, AMD Gen3+ or Intel Ice Lake+; a high clock matters more than many cores |
| RAM | 300 GiB as the kernel reports it, so a 256 GB machine is refused | |
| Disk | three separate ext4 or XFS filesystems: accounts 900 GB, ledger 900 GB, snapshots 450 GB | NVMe, on separate drives |
| ERPC server | | bare metal MV (stock: `server_stock`, kind `bare_metal`, type MV) |

Compare with the specs in ERPC's catalogue (`server_catalog`) and say plainly when a server
falls short of the floor, whatever its type is called. A VPS is never enough.

## Clients

A new validator runs Agave; erpc sets up no new validator on another client. The others are what
a solv validator may have been set up with, and what SLV offers: `jito` (the usual choice on
mainnet, with MEV), `allnodes-jito` (Allnodes' Jito fork), and `firedancer`: the full Firedancer
(v26.10.2 or later, which runs Alpenglow), not Frankendancer, which ends with Alpenglow (SLV's
`firedancer-jito` and `firedancer-agave` are Frankendancer and SLV refuses them on mainnet). Jito
types take a block engine and shred receiver for their region; BAM is joined with a BAM URL
beside them, not instead of them. Firedancer needs many cores: its default layout gives each
tile its own.

## BLS key (SIMD-0387)

A voting validator registers the BLS public key of its authorized voter; without it the vote
account counts as unstaked once Alpenglow voting is active. For a native validator the voter is
the identity, and the key is the one `solana-keygen bls_pubkey` derives from the identity
keypair. erpc checks and prepares the registration but signs nothing: `erpc v --chain solana -n
mainnet --name <name> registration --action prepare --step register-bls --bls <key> --commission
<percent>` prints the step as public JSON for Solana's own tools, the same command with
`--action validate` and no `--step` checks the account afterwards, and activation takes the
registered key as `--bls-public`. For a solv validator it is SLV's,
idempotent and safe to re-run: `slv v register:bls -n mainnet -p <host>`.

## Node tuning

What a validator box is tuned with. SLV applies it once, before the first deploy, and reboots
once when a kernel or boot setting changed. erpc does none of it for a native node; its `init`
sets four kernel limits and no more.

- SMT (Hyper-Threading) off: `nosmt` on the kernel command line. Afterwards
  `cat /sys/devices/system/cpu/smt/active` is `0`. erpc's 24-thread floor counts the CPUs the
  running kernel has online, so with SMT off a native node needs 24 cores.
- CPU boost (AMD): kernel 6.14 or newer (Ubuntu HWE), `amd_pstate=active`, governor and energy
  preference `performance`, boost on, `processor.max_cstate=0` and idle states off. Set
  `scaling_max_freq` before `scaling_min_freq`, or the kernel clamps both.
- IRQ and NIC: each NIC queue pinned to its own CPU, RPS and XPS spread, ring sizes a power of
  two at or under the NIC's maximum (AF_XDP zero-copy needs it), transparent huge pages off.
- Check it: `slv check boost -t validator -n mainnet -p <pubkey>` (OK, WARN or NG), or by hand
  `uname -r`, `cat /sys/devices/system/cpu/amd_pstate/status` (`active`) and
  `grep 'cpu MHz' /proc/cpuinfo`: every core near the CPU's maximum, none stuck at its base
  clock. When the OS side is right and the clock is still capped, the BIOS is the limit
  (determinism slider Performance, CPPC and core boost on, global C-states off).

## Restarts and maintenance

- One host at a time, never several at once.
- After a restart or reboot a validator needs to catch up, often 20 to 30 minutes. Do not
  touch the next host, or switch traffic back, until it is caught up: `erpc v status` (for a
  native node, `rpc_ready` true), or `solana catchup` / SLV's monitor showing 0 slots behind. An
  open port is not caught up.
- A reboot can leave SSH refused for 3 to 5 minutes while the box starts; ping answering and
  SSH refused is usually that.
- To move the identity to another box without downtime, SLV's `slv v switch -n mainnet -f <from>
  -t <to>` hands the tower over; never run the same staked identity on two hosts.
- Before any of this on a staked validator, say what it will do and when it is safe to stop.

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a native node, `plan` shows the
release it would be built from and `status` the one it runs; `erpc --json v list` gives a solv
validator's `version`.

- https://github.com/anza-xyz/agave and https://docs.anza.xyz/operations/requirements: Agave, the
  reference validator, and Anza's operator guide
- https://github.com/jito-foundation/jito-solana and https://docs.jito.wtf/: Jito's client, block
  engines and relayers
- https://github.com/allnodes/solana-jito: Allnodes' Jito fork
- https://github.com/firedancer-io/firedancer and https://docs.firedancer.io/guide/getting-started.html:
  Firedancer
