#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Validator UUID/inode storage, derived from reviewed Arc follower storage.

Dedicated EL/CL identities own different private layers; only quiesced original
writers permit directory creation/handoff. No persistent kernel device number.
"""
import os
import pathlib
import stat
from arc_files import require, strict_json

DATA_HOME = '/var/lib/erpc-arc-validator'
LAYERS = ('execution', 'consensus')


def identity(info):
    # st_dev is a current kernel observation, not a persistent volume identity.
    # Every saved inode below is scoped by the original filesystem UUID/type.
    return {'inode': info.st_ino}


def receipt(record):
    require(isinstance(record, dict) and set(record) in ({'inode'}, {'inode', 'device'}) and
            type(record.get('inode')) is int and record['inode'] > 0,
            'invalid original Arc directory receipt')
    if 'device' in record:
        require(type(record['device']) is int and record['device'] >= 0,
                'invalid legacy Arc directory observation')
    # Accept the old receipt's original inode, never replace it with today's inode.
    return {'inode': record['inode']}


def same(info, record, current_device):
    return info.st_dev == current_device and identity(info) == receipt(record)


def observation(first, second):
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def volume(record):
    require(isinstance(record, dict) and set(record) in (
                {'uuid', 'fstype'}, {'uuid', 'fstype', 'device'}) and
            record.get('fstype') in ('ext4', 'xfs') and isinstance(record.get('uuid'), str) and
            4 <= len(record['uuid']) <= 128, 'invalid original Arc filesystem receipt')
    if 'device' in record:
        require(type(record['device']) is int and record['device'] >= 0,
                'invalid legacy Arc filesystem observation')
    return {key: record[key] for key in ('uuid', 'fstype')}


def empty_volume(c, path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == c.owner and not info.st_mode & 0o022,
                'unowned Arc volume ownership or permissions are unsafe')
        entries = os.listdir(fd)
        require(not entries or entries == ['lost+found'], 'unowned Arc volume contains data')
        if entries:
            recovery = os.open('lost+found', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                found = os.fstat(recovery)
                require(found.st_uid == c.owner and not found.st_mode & 0o022 and
                        not os.listdir(recovery), 'unowned Arc recovery directory contains data or is unsafe')
                require(found.st_dev == info.st_dev and observation(
                            os.stat('lost+found', dir_fd=fd, follow_symlinks=False), found),
                        'Arc recovery directory changed')
            finally:
                os.close(recovery)
        require(observation(path.lstat(), info), 'Arc volume changed while checked')
        return identity(info)
    finally:
        os.close(fd)


def filesystem(c):
    home = c.path(DATA_HOME)
    probe = home if home.exists() else home.parent
    before = probe.lstat()
    require(stat.S_ISDIR(before.st_mode), 'Arc filesystem probe is not a real directory')
    result = c.command('/usr/bin/findmnt', '--json', '--output', 'TARGET,SOURCE,FSTYPE,UUID,FSROOT,OPTIONS',
                       '--target', str(probe))
    rows = strict_json(result.stdout).get('filesystems')
    require(isinstance(rows, list) and len(rows) == 1, 'Arc filesystem identity is ambiguous')
    row = rows[0]
    require(row.get('fstype') in ('ext4', 'xfs') and isinstance(row.get('uuid'), str)
            and 4 <= len(row['uuid']) <= 128 and row.get('fsroot') == '/' and 'rw' in row.get('options', '').split(','),
            'Arc requires a writable UUID-addressed ext4 or XFS filesystem')
    mounts = strict_json(c.command('/usr/bin/findmnt', '--json', '--list', '--output', 'TARGET').stdout)
    targets = mounts.get('filesystems')
    require(isinstance(targets, list) and len(targets) <= 100000, 'Arc mount inventory is unavailable')
    matching = 0
    for mount in targets:
        target = mount.get('target')
        require(isinstance(target, str) and target.startswith('/'), 'invalid Arc mount target')
        target = pathlib.Path(target)
        require(home not in target.parents, 'nested mounts beneath the Arc data root are refused')
        if target == home:
            matching += 1
    require(matching <= 1, 'stacked mounts at the Arc data root are refused')
    require(observation(before, probe.lstat()), 'Arc filesystem changed during observation')
    return {'uuid': row['uuid'], 'fstype': row['fstype']}


def fresh(c):
    c.protected('/var/lib', directory=True)
    home = c.protected(DATA_HOME, missing=True, directory=True)
    layout = None if not home.exists() else empty_volume(c, home)
    return {'home': layout, 'filesystem': filesystem(c)}


def prepare(c, state):
    observed = state.get('storage')
    require(isinstance(observed, dict), 'original Arc volume reservation is missing')
    require(filesystem(c) == volume(observed['filesystem']), 'original Arc filesystem changed')
    home = c.protected(DATA_HOME, missing=True, directory=True)
    if observed.get('home') is None:
        if not home.exists():
            c.mkdir(DATA_HOME, mode=0o755)
        # No native process can run before this first original-root receipt exists.
        observed['home'] = empty_volume(c, home)
        c.save(state)
    if observed.get('prepared') is not True:
        require(empty_volume(c, home) == receipt(observed['home']), 'initial Arc volume was replaced')
        named = home.lstat()
        fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(same(os.fstat(fd), observed['home'], named.st_dev) and
                    observation(os.fstat(fd), home.lstat()), 'initial Arc volume changed')
            os.fchmod(fd, 0o755)
            os.fsync(fd)
        finally:
            os.close(fd)
        c.sync(home)
        observed['prepared'] = True
        c.save(state)
    info = home.lstat()
    require(same(info, observed['home'], info.st_dev) and stat.S_ISDIR(info.st_mode)
            and info.st_uid == c.owner and not info.st_mode & 0o022
            and info.st_mode & 0o005 == 0o005,
            'original Arc root inode/ownership/traversal changed')
    # Sync even a visible receipt from an interrupted previous publication.
    c.save(state)
    c.sync(home)
    return observed


def verify(c, state):
    record = state.get('storage')
    require(isinstance(record, dict) and isinstance(record.get('home'), dict),
            'original Arc data root is not prepared')
    home = c.protected(DATA_HOME, directory=True)
    before = home.lstat()
    require(same(before, record['home'], before.st_dev) and filesystem(c) == volume(record['filesystem']) and
            observation(before, home.lstat()), 'original Arc storage identity changed')
    require(home.stat().st_mode & 0o005 == 0o005, 'Arc root is not traversable by the original identity')
    return home


def private_directory(c, state, name, record=None, create=False):
    uid = gid = state['accounts']['consensus' if name == 'consensus' else 'execution']
    if create:
        c.assert_all_quiescent(state)
    home = verify(c, state)
    current_home = home.lstat()
    path = home / name
    require(name in ('bootstrap', 'execution', 'consensus'), 'unknown Arc private directory')
    if not path.exists() and create:
        path.mkdir(mode=0o700)
        c.sync(home)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if record is None:
            require(create, 'original Arc directory receipt is missing')
            require(info.st_uid == c.owner and not info.st_mode & 0o022 and not os.listdir(fd),
                    'receipt-free Arc directory cannot be adopted')
            record = identity(info)
            state.setdefault('directory_intents', {})[name] = record
            c.save(state)
        require(same(info, record, current_home.st_dev) and observation(info, path.lstat()) and
                observation(current_home, home.lstat()), 'original Arc private directory changed')
        if create:
            require((info.st_uid == c.owner and not info.st_mode & 0o022) or
                    (info.st_uid == uid and info.st_gid == gid
                     and stat.S_IMODE(info.st_mode) == 0o700),
                    'initial Arc private directory ownership was changed')
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o700)
            os.fsync(fd)
        info = os.fstat(fd)
        require(info.st_uid == uid and info.st_gid == gid and
                stat.S_IMODE(info.st_mode) == 0o700 and same(info, record, current_home.st_dev) and
                observation(info, path.lstat()) and observation(current_home, home.lstat()),
                'original Arc private directory ownership changed')
    finally:
        os.close(fd)
    c.sync(home)
    return record


def capacity(c, state):
    home = verify(c, state)
    free = os.statvfs(home)
    available = free.f_bavail * free.f_frsize
    # ERPC initial operating estimate, not an upstream archive-size guarantee.
    minimum = 1000_000_000_000
    allocated = 0
    for name in ('execution', 'consensus', 'bootstrap'):
        path = home / name
        record = state.get('directories', {}).get(name) or state.get('directory_intents', {}).get(name)
        if record is not None and path.exists():
            private_directory(c, state, name, record)
            result = c.command('/usr/bin/du', '-sx', '--block-size=1', str(path))
            words = result.stdout.decode('ascii').split()
            require(words and words[0].isdecimal(), 'Arc allocation observation is unavailable')
            allocated += int(words[0])
    need = max(100_000_000_000, minimum - allocated)
    require(available >= need, 'original Arc filesystem lacks bootstrap or operating headroom')
    return {'free_bytes': available, 'required_bytes': need}
