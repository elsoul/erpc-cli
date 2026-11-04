---
name: erpc-account
description: Signing in to ERPC with erpc (login, logout, whoami, doctor, config), where the session is kept (keychain, 1Password, file) on macOS and Linux, and the common sign-in problems.
---

# Account and session

- `erpc signup` opens the ERPC dashboard's sign-up page. Accounts are created there; erpc never
  sees a password.
- `erpc login` signs in with the OAuth device flow: a browser opens an approval page and shows a
  code. At a terminal it first asks where to keep the session: the OS keychain (default) or
  1Password (desktop app), then which 1Password vault. `--store keychain|1password|file` and
  `--vault <ID>` choose without asking. The choice is saved in `~/.erpc/config.toml`
  (`credential_store`, `credential_vault`) and the other commands use it.
- Moving to another store at `erpc login` signs out of the session kept in the previous one.
- `erpc whoami` shows the account. It refreshes the session when it is about to expire.
- `erpc logout` revokes the session at the issuer and removes it locally. It reports whether
  the revocation was confirmed, not confirmed, or there was nothing to revoke.
- `erpc doctor` shows which store is in use and why, the 1Password vault if any, and any secret
  left on disk (the file store, a parked session after a save that failed or that erpc could
  not wait for, or a temporary file from an interrupted write). It exits non-zero when something needs attention.
- `erpc config get [key]`, `erpc config set <key> <value>`, `erpc config path`,
  `erpc config init`. Keys: `credential_store`, `credential_vault`, `default_chain`, `locale`.
  Only public settings belong there, never secrets.
- On Linux the keychain is the Secret Service when one runs (a desktop session), and otherwise
  the kernel keyring: nothing on disk, kept across logins until a reboot or a few days unused,
  then `erpc login` again. A shell started without a login of its own (`su` without `-`,
  `sudo -E`) cannot use the kernel keyring; log in as yourself.
- Without the 1Password app (a Linux server over SSH), sign in to 1Password with
  `op account add` once and `eval $(op signin)` per shell; erpc uses that session. It expires
  after 30 minutes unused, and `eval $(op signin)` renews it. For node work that runs unattended,
  a 1Password service account (`OP_SERVICE_ACCOUNT_TOKEN` in the environment, for a vault it may
  read) works instead. Node commands do not check the network for one, so keep mainnet keys in a
  vault it cannot read. Reading an `erpc worker` trading key to run, start or deploy refuses one, and so does the credit
  wallet.
- On macOS erpc reaches the keychain through Apple's `security` tool, so an update does not make
  it ask again. A session saved by an older erpc may ask once; "Always Allow" ends that, and the
  next save makes the item `security`'s own.
- A 1Password vault that other people or automation can read lets them use the session. Pick a
  personal vault (for example "Employee" or "Private").

Common problems:
- "not signed in" → `erpc login`.
- "the session has expired or was signed out elsewhere" → `erpc login`.
- "no 1Password vault is chosen" → `erpc login` and pick a vault, or `--vault <ID>`.
