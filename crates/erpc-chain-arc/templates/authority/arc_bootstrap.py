#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Separate first restore from active Arc history; retain interrupted original paths."""
import os
import stat
from arc_files import digest, encoded, require
import arc_storage as storage


def prepare(c, state):
    require(not state.get('bootstrap_complete') and not state.get('native_started'),
            'active original Arc history cannot be bootstrapped again')
    record = state.get('directories', {}).get('bootstrap') or state.get('directory_intents', {}).get('bootstrap')
    record = storage.private_directory(c, state, 'bootstrap', record, create=True)
    state.setdefault('directories', {})['bootstrap'] = record
    c.save(state)
    return record


def sync_tree(c, state, root):
    """Native snapshot data remains private, regular, single-link and on the original device."""
    original = root.stat()
    stack = [root]
    directories = []
    while stack:
        path = stack.pop()
        info = path.lstat()
        require(info.st_dev == original.st_dev and info.st_uid == state['service_uid'] and
                info.st_gid == state['service_gid'] and not info.st_mode & 0o022,
                'Arc restored data ownership, mode or filesystem changed')
        if stat.S_ISDIR(info.st_mode):
            directories.append(path)
            stack.extend(path.iterdir())
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    'Arc restored history contains links or special files')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                opened = os.fstat(fd)
                require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                        'Arc restored history changed while synchronized')
                os.fsync(fd)
            finally:
                os.close(fd)
    for path in reversed(directories):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    c.sync(root.parent)


def completed(c, state):
    require(state.get('phase') == 'bootstrap' and not state.get('retired') and
            state.get('bootstrap_generation') == state.get('generation'),
            'cancelled or replaced Arc bootstrap cannot publish completion')
    stage = c.path(storage.DATA_HOME) / 'bootstrap'
    record = state['directories']['bootstrap']
    storage.private_directory(c, state, 'bootstrap', record)
    require(set(os.listdir(stage)) == {'execution', 'consensus'}, 'Arc bootstrap contains incomplete or unknown staging')
    expected = {'execution': 'db/mdbx.dat', 'consensus': 'store.db'}
    layers = {}
    current_stage = stage.lstat()
    for name in storage.LAYERS:
        path = stage / name
        before = path.lstat()
        require(stat.S_ISDIR(before.st_mode) and before.st_dev == current_stage.st_dev,
                'Arc bootstrap layer is absent or on another filesystem')
        for relative in (expected[name], '.snapshot-url'):
            item = path / relative
            info = item.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size > 0,
                    'Arc native bootstrap marker or database is incomplete')
        sync_tree(c, state, path)
        require(storage.observation(before, path.lstat()) and
                storage.observation(current_stage, stage.lstat()), 'Arc bootstrap changed during completion')
        layers[name] = storage.identity(before)
    state['bootstrap_pair'] = layers
    state['phase'] = 'bootstrap-complete'
    c.save(state)
    return {'bootstrap': 'qualified'}


def promote(c, state):
    require(state.get('phase') in ('bootstrap-complete', 'promoting') and not state.get('retired') and
            state.get('bootstrap_generation') == state.get('generation'),
            'cancelled Arc bootstrap cannot replace native data')
    home = storage.verify(c, state)
    current_home = home.lstat()
    require(set(state.get('bootstrap_pair', {})) == set(storage.LAYERS),
            'original Arc bootstrap pair is incomplete')
    state['promotion_started'] = True
    state['phase'] = 'promoting'
    c.save(state)
    for name in storage.LAYERS:
        source, target = home / 'bootstrap' / name, home / name
        record = state['bootstrap_pair'][name]
        if target.exists() or target.is_symlink():
            require(not source.exists() and not target.is_symlink() and storage.same(target.lstat(), record, current_home.st_dev),
                    'Arc original destination differs from the qualified bootstrap pair')
        else:
            require(not source.is_symlink() and storage.same(source.lstat(), record, current_home.st_dev),
                    'Arc qualified bootstrap source changed')
            os.rename(source, target)
            c.sync(source.parent)
            c.sync(target.parent)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(storage.same(os.fstat(fd), record, current_home.st_dev) and
                    storage.observation(os.fstat(fd), target.lstat()) and
                    storage.observation(current_home, home.lstat()), 'Arc promoted original directory changed')
            os.fchmod(fd, 0o700)
            os.fsync(fd)
        finally:
            os.close(fd)
        state.setdefault('directories', {})[name] = record
        c.save(state)
    state['bootstrap_complete'] = True
    state['phase'] = 'installed'
    c.save(state)
    return {'bootstrap': 'original-pair-promoted'}


def reset(c, state, original_intent):
    require(state.get('bootstrap_intent') == original_intent and not state.get('native_started') and
            not state.get('bootstrap_complete') and not state.get('promotion_started'),
            'only the explicit interrupted initial Arc bootstrap may be quarantined')
    home = storage.verify(c, state)
    current_home = home.lstat()
    old = state.get('directories', {}).get('bootstrap') or state.get('directory_intents', {}).get('bootstrap')
    if old is None:
        retained_receipt = state.get('retained_bootstrap')
        require(isinstance(retained_receipt, dict), 'original Arc retained bootstrap receipt is missing')
        old = retained_receipt.get('root')
    require(isinstance(old, dict), 'original Arc bootstrap root receipt is unavailable')
    original = home / 'bootstrap'
    name = 'bootstrap-retained-' + digest(encoded({'intent': original_intent, 'root': old}))
    retained = home / name
    state['stopped'] = ['execution', 'consensus']
    state['generation'] += 1
    state.pop('intent', None)
    state['phase'] = 'resetting-bootstrap'
    state['retained_bootstrap'] = {'name': name, 'root': old}
    c.save(state)
    if retained.exists():
        require(not original.exists() and not retained.is_symlink() and storage.same(retained.lstat(), old, current_home.st_dev),
                'original Arc retained bootstrap path changed')
    else:
        require(not original.is_symlink() and storage.same(original.lstat(), old, current_home.st_dev), 'Arc bootstrap root changed')
        os.rename(original, retained)
        c.sync(home)
    require(storage.same(retained.lstat(), old, current_home.st_dev) and
            storage.observation(current_home, home.lstat()), 'Arc retained bootstrap changed during quarantine')
    state.get('directories', {}).pop('bootstrap', None)
    state.get('directory_intents', {}).pop('bootstrap', None)
    state.pop('bootstrap_pair', None)
    state['phase'] = 'prepared'
    c.save(state)
    return {'reset': 'quarantined', 'retained': name, 'started': False}
