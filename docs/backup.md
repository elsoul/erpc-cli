<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# `erpc backup`

`erpc backup` backs a machine up to ERPC Global Storage with
restic. restic encrypts everything on the machine
before it is sent, and ERPC never holds a password that opens the backups.
A storage plan is needed (`erpc storage buy 5`).

```bash
erpc backup init
```

```bash
erpc backup run
```

## The commands

| Command | What it does |
|---|---|
| `init` | Installs restic, makes the access keys and the repository, and gives this machine its own restic key. Running it again changes nothing that works |
| `run [paths]` | Backs up. On Linux, with no paths, `/` less pseudo-filesystems, mounts and volatile paths. Elsewhere, name the paths. `--exclude` leaves more out; `--dry-run` sends nothing |
| `snapshots` | This machine's snapshots; `--all-hosts` for every machine's |
| `restore <id\|latest>` | Restores into a new directory, `./erpc-restore-<id>` unless `--target` names another. `--in-place` writes over this machine, after asking. `--from-host` restores another machine's snapshot. `--path /etc` restores one directory of it: into the target as its contents, or with `--in-place` back into `/etc` |
| `check` | Checks the repository and reads back 5% of the data (`--read-data`) |
| `prune` | Forgets one machine's snapshots beyond 7 daily, 4 weekly and 6 monthly, after asking, and frees their space |
| `schedule daily\|weekly\|off [paths]` | Runs `run` on a timer, at `--at` (default 03:00). Linux: a systemd timer, as root, at the lowest CPU and I/O priority; a run missed while the machine was off runs when it is back. macOS: a launchd agent, as you, while you are signed in |
| `status` | The schedule, and when the last run was and how it ended |
| `password --show` | Prints the repository's master password, to keep a copy elsewhere |

**Do not restore an Ethereum validator's signer from a backup.** Its slashing
history stops at the snapshot, so a key that signed after it can be slashed. Move a
signer with `erpc v --chain eth migrate`; [the validator guide](ethereum-validator.md)
covers a lost one.

## Who holds what

- **The account**, in the store `erpc login` chose (1Password, the macOS
  keychain, or a 0600 file under `~/.erpc`):
  - the repository's master password;
  - a `read_write` storage access key.

  Only `init` and `prune` use them.
- **Each machine**, in `~/.erpc/backup.env`, mode 0600:
  - an `append_only` storage access key;
  - the password of the machine's own restic key.

  `run`, `snapshots`, `restore` and `check` use only these. With an
  `append_only` key, ERPC refuses every delete except restic's lock files.
  Its restic key can be removed without touching the others.

**What the append-only key protects, and when.** A machine that holds only
`backup.env` can add snapshots but cannot remove any. But `erpc backup init`
keeps the account's secrets above in the store of the machine it runs on,
and the `erpc login` session stays there too, which can make a new
`read_write` key at any time. So on the machine where `init` ran, whoever
takes it over can delete the backups. The protection holds only on a
machine that keeps neither the erpc session nor the account's backup
secrets.

Every restic key opens the same repository, so:
- a machine can read the snapshots of the others;
- a machine can add a snapshot under another machine's name, since the
  name is only a label. `restore latest` takes the newest snapshot with this
  machine's name. Before an in-place restore, it shows the snapshot's id
  and time; compare them with `erpc backup snapshots` when in doubt.

**Losing the master password and every machine's `backup.env` loses the
backups.** Keep a copy of `erpc backup password --show` away from the
machines.

## What a backup leaves out

A backup leaves out the files below, and a restore does not write them,
including a restore of one directory with `--path`. The home directories are
`/root`, `/home/*`, `/Users/*` and `/var/root`.
- **Under a home directory, at any depth:** files named `*keypair*.json`
  or `*identity*.json`.
- **At fixed places in a home directory:**
  - `.config/solana/id.json`;
  - `.ssh/id_*` (the SSH private keys, and their `.pub` files with them);
  - `.slv/keys`, `.slv/wallet-rescue`, `.slv/api.yml`,
    `.slv/gateway/gateway.json`, `.slv/backup.env`, `.slv/restic-password`;
  - erpc's session (`.erpc/state/credentials.toml`), `.erpc/storage-key`,
    `.erpc/backup.env`, `.erpc/backup-password`,
    `.erpc/backup-admin-key`, `.erpc/keyless.toml`.
- **System files:** the SSH host keys (`/etc/ssh/ssh_host_*_key`),
  `/etc/shadow`, `/etc/gshadow`, `/etc/wireguard`, `/etc/ssl/private`,
  `/etc/nginx/ssl`, `/etc/doublezero/keys`.

Key material under another name or at another place is backed up like any
other file, encrypted by restic. Leave it out with `--exclude`.

An `--exclude` that starts with `!` is refused, since restic reads such a
pattern as one that takes files back in.

A restore also leaves this machine's own disks, network and SSH host
identity alone, unless `--include-system` is given: `/etc/fstab`, `/boot`,
`/etc/netplan`, `/etc/machine-id` and the SSH host keys.

## restic

- erpc installs restic 0.19.1 under `~/.erpc/bin`, downloaded from restic's
  GitHub releases.
- Both the archive and the program inside it are checked against SHA-256
  digests compiled into erpc. The archive's digests are restic's own
  `SHA256SUMS`, which is signed by restic's release key.
- restic gets the access key and the password from its environment, never
  from its command line or a URL. Apart from those, its environment is
  cleared.

## Scheduling

- **Linux:** `sudo erpc backup init`, then `sudo erpc backup schedule daily`.
  The service and the timer go in `/etc/systemd/system`, named
  `erpc-backup`. The run's output is in `journalctl -u erpc-backup.service`.
- **macOS:** `erpc backup schedule daily ~/Documents`. The job is
  `~/Library/LaunchAgents/global.erpc.backup.plist`, and its output goes to
  `~/.erpc/state/backup.log`. macOS may refuse a background job access to
  folders such as Documents until erpc is given Full Disk Access in System
  Settings; the run then ends with files left out, and `status` says so.
- **Credentials:** the unit files hold none. The run reads this machine's
  credentials from `backup.env`, as it does by hand.

## Limits

- **Regions.** Backups go to the account's default region.
- **One machine at a time.** `erpc backup` runs on the machine it backs up.
  A worker's server is set up from the operator's machine instead, with
  `erpc worker backup on` (`docs/worker.md`), and holds only its own
  append-only key and restic key; it can still read every machine's
  snapshots, as any machine here can.
