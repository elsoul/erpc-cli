# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Durable retirement of one previously qualified Solv service.

The caller authenticates original account/source/loaded policy and a separate
management login before entry. This transaction retains the original unit and
installs a persistent mask before stopping it. It never restores the old runtime.
Copy authorization additionally requires the caller's original-account privilege
revocation and whole-account process reconciliation; a masked unit alone is not
proof that old writers cannot return.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
from native_files import atomic, encoded, json_value, read, require, root_directory, sync_directory, sync_file

ROOT_UID = 0
UNIT = Path('/etc/systemd/system/solv.service')
STORE = Path('/var/lib/erpc-solana-migration/retirement')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def original(value):
    require(isinstance(value, dict) and set(value) == {
        'intent', 'source_sha256', 'machine_id_sha256', 'uid', 'gid', 'unit_sha256',
        'commands_sha256', 'execution_policy_sha256'}, 'invalid original retirement binding')
    require(isinstance(value['intent'], str) and re.fullmatch('[a-f0-9]{32}', value['intent']),
            'invalid retirement intent')
    require(all(isinstance(value[name], str) and re.fullmatch('[a-f0-9]{64}', value[name])
                for name in ('source_sha256', 'machine_id_sha256', 'unit_sha256',
                             'commands_sha256', 'execution_policy_sha256')),
            'original retirement evidence is incomplete')
    require(all(type(value[name]) is int and 0 < value[name] < 2**31 for name in ('uid', 'gid')),
            'invalid original retirement identity')
    return value


class Fence:
    def __init__(self, binding, authenticate, run, reconcile):
        self.binding = original(binding)
        # authenticate verifies the historical account, management login and
        # loaded policy. Once masked, it must allow only the recorded definition
        # already loaded in PID1 or a fully masked/dead service; never new code.
        self.authenticate, self.run, self.reconcile = authenticate, run, reconcile

    def saved(self):
        path = STORE / 'retirement.json'
        value = json_value(read(path, owner=ROOT_UID))
        require(isinstance(value, dict) and set(value) == {'schema', 'binding', 'phase'}
                and value['schema'] == 1 and encoded(value['binding']) == encoded(self.binding)
                and value['phase'] in ('reserved', 'masked', 'retired'),
                'retirement belongs to another original host or operation')
        sync_file(path, ROOT_UID); sync_directory(STORE)
        return value

    def put(self, phase):
        atomic(STORE / 'retirement.json', encoded({'schema': 1, 'binding': self.binding, 'phase': phase}))

    def unit(self):
        info = UNIT.lstat()
        require(info.st_uid == ROOT_UID, 'legacy service authority changed')
        if stat.S_ISLNK(info.st_mode):
            require(os.readlink(UNIT) == '/dev/null', 'legacy service points to an unknown target')
            return 'masked'
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022,
                'legacy service is not the original protected file')
        require(sha(read(UNIT, 65536, ROOT_UID)) == self.binding['unit_sha256'],
                'legacy service bytes differ from original retirement evidence')
        return 'original'

    def backup(self):
        path = STORE / 'original.service'
        require(sha(read(path, 65536, ROOT_UID)) == self.binding['unit_sha256'],
                'retained original service definition changed')
        sync_file(path, ROOT_UID); sync_directory(STORE)

    def mask(self):
        self.backup()
        if self.unit() == 'original':
            pending = STORE / 'mask-intent.json'
            expected = {'binding': self.binding, 'unit': str(UNIT), 'target': '/dev/null'}
            if pending.exists(): require(json_value(read(pending, owner=ROOT_UID)) == expected, 'mask intent changed')
            else: atomic(pending, encoded(expected))
            sync_file(pending, ROOT_UID); sync_directory(STORE)
            # The sibling link is on the unit filesystem so publication is an
            # atomic rename even when the receipt store uses another volume.
            temporary = UNIT.with_name('.erpc-solv-mask-' + self.binding['intent'])
            if temporary.exists() or temporary.is_symlink():
                info = temporary.lstat()
                require(stat.S_ISLNK(info.st_mode) and info.st_uid == ROOT_UID
                        and os.readlink(temporary) == '/dev/null', 'mask staging path is not original')
            else:
                os.symlink('/dev/null', temporary)
            sync_directory(UNIT.parent)
            require(self.unit() == 'original', 'legacy service changed before masking')
            os.replace(temporary, UNIT)
        require(self.unit() == 'masked', 'original legacy service is not masked')
        sync_directory(UNIT.parent)
        self.put('masked')

    def retire_locked(self):
        root_directory(UNIT.parent)
        self.authenticate(self.binding)
        journal = STORE / 'retirement.json'
        if not journal.exists():
            require(self.unit() == 'original', 'unrecorded legacy service mask cannot be adopted')
            paths = list(STORE.iterdir())
            require(len(paths) <= 256, 'migration receipt store exceeds its bound')
            for path in paths:
                require(path.name == 'original.service' or re.fullmatch(r'\.erpc-[a-f0-9]{32}', path.name),
                        'unowned migration receipt store cannot be adopted')
                # A killed atomic writer can leave an unpublished private file.
                # Retain it as inert bytes, never recover authorization from it.
                read(path, 65536, ROOT_UID)
            path = STORE / 'original.service'
            if path.exists(): self.backup()
            else: atomic(path, read(UNIT, 65536, ROOT_UID))
            self.backup()
            self.put('reserved')
        self.saved(); self.backup()
        error = None
        try:
            self.mask()
        except Exception as failure:
            # A visible mask or restrictive receipt can outlive its fsync error.
            # Still attempt only authenticated original shutdown; no copy result.
            error = failure
        try:
            self.authenticate(self.binding)
            self.run(['stop', 'solv.service'])
            self.run(['daemon-reload'])
            self.run(['disable', 'solv.service'])
            require(self.unit() == 'masked', 'legacy boot fence was removed')
            self.authenticate(self.binding)
            self.reconcile(self.binding)
        except Exception as failure:
            if error is None: error = failure
        if error is not None:
            raise error
        # Re-sync both filesystems before exposing a successful retirement.
        self.saved(); self.backup(); sync_directory(UNIT.parent)
        self.put('retired')
        self.saved()
        return {'legacy_retired': True, 'original_unit_retained': True,
                'copy_authorized': False, 'runtime_started': False}

    def retire(self):
        # Outer controller additionally holds the original host-operation lock.
        root_directory(STORE, create=True, mode=0o700)
        require(STORE.lstat().st_mode & 0o7777 == 0o700, 'migration receipt store is not private')
        descriptor = os.open(STORE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self.retire_locked()
        finally: os.close(descriptor)
