#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Stage sealed Engine and peer credentials for the container UID on host tmpfs."""
import os
from pathlib import Path
import pwd
import sys

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
