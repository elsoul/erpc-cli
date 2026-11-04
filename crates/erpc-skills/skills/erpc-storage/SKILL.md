---
name: erpc-storage
description: ERPC Global Storage and backups with erpc -- the plan and its price (erpc storage buy, resize, plan, usage), files up and down encrypted by default (put, get, ls, rm), the storage encryption key and its copy, access keys, and erpc backup (restic) -- init, run, snapshots, restore, check, prune, schedule, status, and what to do when something is refused.
---

# Storage and backups

`erpc storage` (alias `erpc st`) and `erpc backup` need `erpc login` first.

## The plan

- One unit is 5 GB. A plan is 5 GB steps up to 5000 GB, monthly or yearly.
- `erpc storage buy <GB>` buys one, paid from ERPC Credit, after showing the price it reads from
  ERPC. Quote that price, never one from memory.
  - `--annual` pays a year at once.
  - `--region eu|asia|us-east|us-west|oc` sets where files go by default.
  - `--yes` skips the question; use it only when the person asked to buy.
  - Paid from ERPC Credit: monthly or yearly, debited at purchase and at each renewal, never
    hourly.
- `erpc storage plan` shows the plan, its price and when it renews.
- `erpc storage resize <GB>` changes a plan paid by card. A larger plan is charged the prorated
  difference now; a smaller one applies from the next invoice. A plan paid from ERPC Credit
  cannot be resized.
- Ending a plan is done in the dashboard, not in erpc. It ends at once: files can still be read
  but not added, and they may be deleted 30 days after a notice.
- `erpc storage usage` shows capacity, files, and the month's operations. Each unit allows
  20,000 writes and 200,000 reads a month; both reset at the start of the UTC month.
- `erpc storage sync` recounts usage; once per 10 minutes.

## Files

- `erpc storage put <file> [remote]` uploads, encrypted on this machine first.
  - `--no-encrypt` uploads it as it is; only when the person asks.
  - Large files go up in 32 MiB parts, each retried.
- `erpc storage get <remote> [local]` downloads and decrypts.
  - It refuses to overwrite a file unless `--force`.
  - It refuses a file erpc did not encrypt, unless `--plain`: one uploaded with `--no-encrypt`,
    or one put in place of an encrypted file.
  - A broken download resumes where it stopped.
- `erpc storage ls [prefix]` lists files; `--all-regions`, `--limit`.
- `erpc storage rm <path>` deletes after asking; `--yes` for scripts.

## The encryption key

- One key per account, made by the first encrypted `put`.
- It is kept in the store `erpc login` chose: 1Password, the macOS keychain, or
  `~/.erpc/storage-key`.
- **Losing it loses every encrypted file, and ERPC cannot recover it.** After the first `put`,
  tell the person to keep a copy with `erpc storage key export --show`, away from the machine.
- `erpc storage key show` prints only its id.
- `erpc storage key import` takes a copy back on another machine. It refuses to replace a
  different key.
- Never print the key unless the person asks for it.

## Access keys

- `erpc storage keys list`, `keys create --permission read_write|append_only|read_only --show`,
  `keys revoke <id>`.
- `erpc backup init` makes the keys a backup needs; making them by hand is rarely needed.

## Backups

- `erpc backup init` sets up this machine: restic (a pinned version, checked), the repository,
  and this machine's own key. Running it again is safe.
  - A repository `slv backup` made: `erpc backup init --password-file ~/.slv/restic-password`.
- `erpc backup run [paths]` backs up.
  - On Linux with no paths, it backs up `/` less system, volatile and mounted paths.
  - On macOS, name the paths.
  - Left out: files named `*keypair*.json` or `*identity*.json` at any depth under a home
    directory, `.config/solana/id.json`, `.ssh/id_*`, the slv and erpc sign-ins and
    secrets, and system key files. Key material elsewhere is backed up; `--exclude` leaves it
    out.
  - `--exclude <glob>` leaves more out; `--dry-run` sends nothing.
- `erpc backup snapshots` lists this machine's snapshots; `--all-hosts` lists every machine's.
- `erpc backup restore <id|latest>` restores into a new directory, `./erpc-restore-<id>`.
  - `--target <dir>` names another directory.
  - `--in-place` writes over this machine, after asking.
  - `--from-host <name>` restores another machine's snapshot.
  - `--path /etc` restores one directory of it: into the target, or with `--in-place` back into
    `/etc`, never into `/`.
- `erpc backup check` reads back 5% of the data.
- `erpc backup prune` forgets snapshots beyond 7 daily, 4 weekly and 6 monthly, after asking.
- `erpc backup schedule daily|weekly|off [paths] --at 03:00` runs backups on a timer.
  - Linux: a systemd timer, as root (`sudo`).
  - macOS: a launchd job.
- `erpc backup status` shows the schedule and the last run.
- **The repository password:** `erpc backup password --show` prints it. Tell the person to keep a
  copy away from the machine: without it and every machine's `~/.erpc/backup.env`, the backups
  cannot be read.
- Backups go to the account's default region only.
- **The append-only protection:** a machine that holds only `~/.erpc/backup.env` cannot delete
  snapshots. The machine where `erpc backup init` ran also holds the erpc session and the
  account's admin key, so whoever takes it over can. Say so when setting up a server.

## When something is refused

- **"budget" (429):** the month's writes or reads are spent. `erpc storage usage` says when they
  reset; a larger plan has larger budgets.
- **"no storage plan":** buy one with `erpc storage buy 5`.
- **"card authentication":** the one-time card check is done once in the dashboard.
- **Not enough ERPC Credit:** add credit, then buy again.
- **"a different storage key":** this machine has another key than the files were encrypted
  with. Import the right one with `erpc storage key import`.
- **"the repository is locked":** another backup is running; wait for it.
