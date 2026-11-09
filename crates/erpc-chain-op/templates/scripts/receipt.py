#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Seal only this operation's protected public configuration; no secret files."""
import hashlib
import json
from pathlib import Path
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


def record(request):
    state = c.read_state()
    c.check(state, request['contract'])
    c.require(state['phase'] == 'installing' and state['target'] == request['pair'], 'installation lost target ownership')
    conf, _, _ = c.paths(state['contract'])
    files = [conf / name for name in ('network.json', 'nginx.conf')]
    files += [c.LIB / name for name in ('rollup_control.py', 'rollup_status.py', 'rollup_upstreams.py',
                                       'rollup_bootstrap.py', 'rollup_runtime_jwt.py', 'rollup_container.py')]
    files += [Path('/etc/systemd/system') / (name + '.service') for name in c.units(state['contract']).values()]
    if state['contract']['family'] != 'base':
        files.append(conf / 'docker/config.json')
    if (conf / 'base-manifest.json').exists():
        files.append(conf / 'base-manifest.json')
    # The initial downloader regenerates reth.toml. The bootstrap completion
    # transaction seals it before ready; existing databases must retain it.
    if state.get('bootstrap_done'):
        files.append(conf / 'reth.toml')
    hashes = {}
    for path in files:
        c.root_file(path)
        hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt = {'contract': state['contract'], 'pair': state['target'], 'files': hashes}
    c.atomic(conf / 'installation.json', json.dumps(receipt, sort_keys=True).encode(), 0o644)


if __name__ == '__main__':
    try:
        record(json.loads(sys.stdin.buffer.read(1024 * 1024)))
    except Exception:
        print('Protected follower installation could not be recorded', file=sys.stderr)
        sys.exit(1)
