<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Node operation execution

Each deployment uploads its configuration and scripts to a new run ID.
Uploads create root-owned mode0755 namespace ancestors explicitly, independent
of the caller's restrictive umask. Existing real root-owned mode0700 ancestors
can be made traversable; foreign, writable or symlink ancestors are refused.
Only the private run leaf belongs to the SSH login until sealing. Uploads use
new regular inodes and never truncate a destination link or special file.
A run's files are bounded (64 MiB each) and lie in its one directory, and every
other upload outside `/opt/erpc/uploads` is held to the same rules. A worker's
files are staged under `/opt/erpc/uploads` in two shapes only: the agent or
restic as one file in `agent/` or `restic/`, and a release in
`<worker>/<release>/`, which may hold nested files. These are streamed without
a bound. The directory holding the agent or restic, the release directory and
every directory inside it are the login's own; `/opt/erpc/uploads` and each
`<worker>` directory stay root's. Any other path under `/opt/erpc/uploads` is
refused before anything is read or created.
Before starting systemd, the CLI sends an isolated preparation program over SSH
stdin. It checks the SHA-256 of the archive and both runner scripts, rejects
symlink ancestors, hardlinked uploads, prior output files and unsafe archive
members, and replaces the uploaded inodes with root-owned copies. The archive,
extracted bundle and firewall receipts retain their existing run paths. An
already opened writable upload descriptor cannot modify the published copy.

Root is the only writer. A Linux POSIX ACL grants the SSH login UID read access
and directory traversal, without granting its primary group access to password
hashes in the bundle. The filesystem containing `/opt/erpc` must support POSIX
ACLs; preparation fails if the kernel does not retain the requested ACL. Logs
are created as protected regular files before systemd opens them, and results
are published with an atomic replacement rather than truncating a destination.
Following a run after an SSH disconnect uses the same log and result paths.
The login user remains the runner's identity and must already have the required
passwordless sudo access. The global host lock still surrounds Ansible and all
node mutations.

Python helpers use the absolute distribution interpreter with `-I`, including
root service guards, rollback timers, SSH commands and deployment helpers.
This suppresses the user site, `PYTHON*` startup environment and automatic
working/script directory imports. It matters for systemd's `+` commands:
privilege elevation does not make a node user's HOME a trusted Python site.
Helpers needing sibling modules embed the canonical `trusted_imports` function
from `erpc-ssh/src/python-trust.py`. It checks every traversed ancestor before normalizing `..`, refuses symlink
traversal, and validates root-owned, non-writable module/cache files before
appending the directory after the standard-library search paths. It rejects
links and special files and disables new helper bytecode writes. A real,
root-owned cache directory without effective-UID traversal permission can be
skipped: Python cannot read its entries and uses checked source instead.
Denied listing alone is insufficient; readable caches remain fully checked.
This preserves OP's root bootstrap to unprivileged extractor transition even
when an older helper left a private mode0700 cache. The tests check each embedded
copy against the canonical source.

Ansible 2.18.19 treats an interpreter configuration containing spaces as one
executable name. Instead, each sealed run carries its own immutable shell shim
that executes `/usr/bin/python3 -I`. The runner supplies that path through
`ANSIBLE_PYTHON_INTERPRETER`; invoking the bundle without the managed runner
fails closed. The controller and pip also run in isolated mode. Ansible's
private temporary directory is outside the sealed bundle and removed on exit.

Updating the CLI protects new SSH invocations and new deployment runs. Existing
installed service units and helpers must be redeployed with the updated CLI to
receive their isolated startup commands. The legacy TRON SSH adapter validates
its installed helper directory and executes through an inline isolated loader,
so a controller predating the sibling bootstrap can still perform status/stop.
For versioned helper installations, `erpc_ssh::python::release_command` accepts
only an explicitly requested root-owned `current` pointer to
`releases/<sha256>`. It validates all real target ancestors and module files,
checks a complete caller-declared file profile against the directory digest,
and executes that resolved immutable revision. Generic sibling imports still
reject symlinks. Both APIs preserve standard input for credentials.
No node process, real credential or privileged host operation is exercised by
the offline tests. Root ownership is modeled where necessary; startup-hook
suppression is tested with real unprivileged Python processes. The Linux ACL
round-trip test uses a temporary file owned by the test user.

Primary implementation references:

- [CPython isolated startup options](https://github.com/python/cpython/blob/v3.12.12/Doc/using/cmdline.rst)
- [CPython user-site initialization](https://github.com/python/cpython/blob/v3.12.12/Lib/site.py)
- [systemd 255 execution environment and privilege handling](https://github.com/systemd/systemd/blob/v255/src/core/exec-invoke.c)
- [Ansible 2.18.19 interpreter selection](https://github.com/ansible/ansible/blob/v2.18.19/lib/ansible/executor/module_common.py)
- [Linux POSIX ACL xattr format](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/posix_acl_xattr.h)

Offline checks:

```sh
cargo test -p erpc-ops -p erpc-ssh
# Use the Python from a venv installed with node/requirements.txt --require-hashes:
python -I crates/erpc-ops/tests/ansible_isolation.py
```
