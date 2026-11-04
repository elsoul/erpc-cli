---
name: solana-validator-mainnet
description: Running a Solana mainnet validator -- the hardware and ERPC server it needs, the clients (Jito, Allnodes-Jito, Agave, Firedancer), BLS, node tuning (SMT, CPU boost, C-states, IRQ), rolling restarts and catch-up checks, and what erpc does and does not do for mainnet yet.
---

# Solana validator, mainnet

Real stake and real money: explain what each change does before suggesting it, and try it on
testnet first (skill `solana-validator-testnet`).

## What erpc does for mainnet today

`erpc v init -n mainnet --chain solana --client <client>` and `erpc v deploy -n mainnet --chain
solana` bring a mainnet validator up sync-only: an unstaked identity, not voting, the staked
identity kept in 1Password. The snapshot comes from the freshest and fastest of the ERPC mirrors
and Avorio's public mirror (Firedancer fetches its own). `erpc v list` / `erpc v status` read the
hosts. Voting on mainnet (vote account, BLS, putting the staked identity on), tuning and identity
switches are still SLV's (`slv v ...`). Every mainnet change in erpc needs `--chain` on the
command line itself; `ERPC_CHAIN` and `default_chain` are refused for it. What every chain's commands
share (1Password, the SSH agent, the host key, `--yes`, `--json`) is in the skill `erpc-nodes`.

## Hardware

| | Needs |
|---|---|
| CPU | 2.8 GHz or more, AMD Gen3+ or Intel Ice Lake+; a high clock matters more than many cores |
| RAM | 256 GB or more |
| Disk | NVMe, with accounts, ledger and snapshots on separate drives |
| ERPC server | bare metal MV (stock: `server_stock`, kind `bare_metal`, type MV) |

Compare with the specs in ERPC's catalogue (`server_catalog`) and say plainly when a server falls short. A VPS
is never enough. Source: SLV's Solana guides.

## Clients

`jito` (the usual choice on mainnet, with MEV), `allnodes-jito` (Allnodes' Jito fork), `agave`,
and `firedancer`: the full Firedancer (v26.10.2 or later, which runs Alpenglow), not
Frankendancer, which ends with Alpenglow (SLV's `firedancer-jito` and `firedancer-agave` are
Frankendancer and SLV refuses them on mainnet). Jito types take a block engine and shred receiver
for their region; BAM is joined with a BAM URL beside them, not instead of them. Firedancer needs
many cores: its default layout gives each tile its own.

## BLS key (SIMD-0387)

A voting validator registers the BLS public key of its authorized voter; without it the vote
account counts as unstaked once Alpenglow voting is active. It is idempotent and safe to re-run:
`slv v register:bls -n mainnet -p <host>` (erpc's `erpc v vote-account` does it for testnet).

## Node tuning

What a validator box is tuned with. SLV applies it once, before the first deploy, and reboots
once when a kernel or boot setting changed:

- SMT (Hyper-Threading) off: `nosmt` on the kernel command line. Afterwards
  `cat /sys/devices/system/cpu/smt/active` is `0`.
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
  touch the next host, or switch traffic back, until it is caught up: `erpc v status`, or
  `solana catchup` / SLV's monitor showing 0 slots behind. An open port is not caught up.
- A reboot can leave SSH refused for 3 to 5 minutes while the box starts; ping answering and
  SSH refused is usually that.
- To move the identity to another box without downtime, SLV's `slv v switch -n mainnet -f <from>
  -t <to>` hands the tower over; never run the same staked identity on two hosts.
- Before any of this on a staked validator, say what it will do and when it is safe to stop.

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a node erpc runs, the release it
pinned is the one `init`, `update` and `status` show.

- https://github.com/anza-xyz/agave and https://docs.anza.xyz/operations/requirements: Agave, the
  reference validator, and Anza's operator guide
- https://github.com/jito-foundation/jito-solana and https://docs.jito.wtf/: Jito's client, block
  engines and relayers
- https://github.com/allnodes/solana-jito: Allnodes' Jito fork
- https://github.com/firedancer-io/firedancer and https://docs.firedancer.io/guide/getting-started.html:
  Firedancer
