#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Cleanly stop only a container bearing this host's exact immutable owner labels."""
import json
import os
import re
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


def prepare(family, role):
    c.require(os.geteuid() == 0 and family in {'optimism', 'soneium'} and role in {'execution', 'consensus'}, 'invalid container ownership request')
    state = c.read_state()
    c.require(state['contract']['family'] == family, 'container family differs from owner')
    c.guard(state, role)
    stop_owned(state, role)


def stop_owned(state, role):
    family = state['contract']['family']
    c.require(family in {'optimism', 'soneium'} and role in {'execution', 'consensus'}, 'invalid container role')
    conf, _, _ = c.paths(state['contract'])
    docker = ['docker', '--config', str(conf / 'docker')]
    name = 'erpc-' + family + '-' + role
    raw = c.run(docker + ['container', 'inspect', name], allowed=(0, 1))
    c.require(raw.strip(), 'container daemon did not return an inspection result')
    values = json.loads(raw)
    if not values:
        return
    c.require(isinstance(values, list) and len(values) == 1, 'ambiguous owned container')
    value = values[0]
    c.require(value.get('Name') == '/' + name, 'wrong container selected')
    labels = value.get('Config', {}).get('Labels', {})
    for field in ('owner', 'family', 'network', 'history'):
        c.require(labels.get('erpc.' + field) == state['contract'][field], 'unowned or cross-network container exists')
    identity = value.get('Id')
    c.require(isinstance(identity, str) and re.fullmatch('[a-f0-9]{64}', identity), 'invalid owned container identifier')
    # A lost Docker CLI must not leave an orphan operating the database while a
    # replacement is started. Shutdown remains graceful and bounded.
    if value.get('State', {}).get('Running'):
        c.run(docker + ['container', 'stop', '--time', '600', identity], timeout=660)
    after = c.run(docker + ['container', 'inspect', identity], allowed=(0, 1))
    c.require(after.strip(), 'container shutdown could not be verified')
    remaining = json.loads(after)
    if remaining:
        c.require(len(remaining) == 1 and remaining[0].get('Id') == identity and remaining[0].get('State', {}).get('Running') is False, 'owned container is still running')
        c.run(docker + ['container', 'rm', identity])
    final = c.run(docker + ['container', 'inspect', name], allowed=(0, 1))
    c.require(final.strip() and json.loads(final) == [], 'a replacement container appeared during shutdown')


if __name__ == '__main__':
    try:
        c.require(len(sys.argv) == 3, 'invalid container invocation')
        prepare(*sys.argv[1:])
    except Exception:
        print('Owned container preparation refused', file=sys.stderr)
        sys.exit(1)
