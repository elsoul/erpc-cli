#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Stage sealed Engine and peer credentials for the container UID on host tmpfs."""
import os
from pathlib import Path
import pwd
import sys


# BEGIN ERPC TRUSTED IMPORTS
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Embedded verbatim in helpers that need sibling modules. Startup uses -I;
# only this checked directory is added, after the standard-library paths.
def trusted_imports(directory):
    import os
    import stat
    import sys
    path = os.fspath(directory)
    if not os.path.isabs(path):
        raise ValueError('helper directory must be an absolute path')
    current = os.path.sep
    for part in path.split(os.path.sep)[1:]:
        if part in ('', '.'):
            continue
        if part == '..':
            # The component being left was already checked as a real root-only
            # directory. Never normalize away an unchecked symlink ancestor.
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('helper ancestors must be real root-owned directories')
    path = current
    if path == os.path.sep:
        raise ValueError('the filesystem root is not a helper directory')
    # Do not create root0700 bytecode caches before an unprivileged helper
    # imports the same module. Existing readable caches remain fully checked.
    sys.dont_write_bytecode = True
    pending = [path]
    while pending:
        for child in os.scandir(pending.pop()):
            info = child.stat(follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('helper modules must be writable only by root')
            if stat.S_ISDIR(info.st_mode):
                if (child.name == '__pycache__'
                        and not os.access(child.path, os.X_OK, effective_ids=True)):
                    # No traversal means Python cannot read any cached module
                    # here and must use the checked source. Denied listing alone
                    # (e.g. mode0711) is not sufficient for this exception.
                    continue
                pending.append(child.path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('helper modules cannot be links or special files')
    if path not in sys.path:
        sys.path.append(path)
# END ERPC TRUSTED IMPORTS

if __name__ == '__main__':
    trusted_imports('/usr/local/lib/erpc')
import rollup_control as c


def stage(family, role):
    c.require(os.geteuid() == 0 and family in {'optimism', 'soneium'} and role in {'execution', 'consensus'}, 'invalid runtime credential request')
    state = c.read_state()
    c.require(state['contract']['family'] == family, 'runtime credential ownership mismatch')
    c.guard(state, role)
    c.require(c.run(['findmnt', '-n', '-o', 'FSTYPE', '-T', '/run']).strip() == b'tmpfs', 'runtime credentials require tmpfs')
    directory = Path('/run') / ('erpc-' + family + '-' + role)
    c.require(directory.is_dir() and not directory.is_symlink() and directory.stat().st_uid == 0, 'unsafe runtime directory')
    user = pwd.getpwnam('erpc-' + family)
    for source, filename in [('engine-jwt', 'engine-jwt'), (role + '-peer', 'peer-key')]:
        value = c.runtime_identity(state, source)
        target = directory / filename
        c.atomic(target, value, 0o400)
        os.chown(target, user.pw_uid, user.pw_gid)



if __name__ == '__main__':
    try:
        c.require(len(sys.argv) == 3, 'invalid runtime credential invocation')
        stage(*sys.argv[1:])
    except Exception:
        print('Follower runtime credentials unavailable', file=sys.stderr)
        sys.exit(1)
