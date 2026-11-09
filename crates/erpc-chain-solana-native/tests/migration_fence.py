# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Retirement journal/mask faults on real files; PID1/NSS effects are inert."""
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_migration_fence as migration


class Retirement(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.units = self.root / 'units'; self.units.mkdir()
        self.store = self.root / 'receipt'; self.store.mkdir(mode=0o700)
        self.unit = self.units / 'solv.service'
        self.raw = b'[Service]\nUser=solv\nExecStart=/inert-original-no-execution\n'
        self.unit.write_bytes(self.raw); self.unit.chmod(0o644)
        self.binding = {'intent': 'a'*32, 'source_sha256': 'b'*64, 'machine_id_sha256': 'c'*64,
                        'uid': 1001, 'gid': 1101, 'unit_sha256': hashlib.sha256(self.raw).hexdigest(),
                        'commands_sha256': 'd'*64, 'execution_policy_sha256': 'e'*64}
        self.calls = []; self.foreign = False; self.remaining_writer = False
        def trusted(path, create=False, mode=0o755):
            self.assertTrue(path == self.root or self.root in path.parents)
            if create: path.mkdir(exist_ok=True, mode=mode)
            info = path.lstat()
            migration.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                              and not info.st_mode & 0o022, 'untrusted model root')
        for name, value in [('UNIT', self.unit), ('STORE', self.store), ('ROOT_UID', os.getuid()),
                            ('root_directory', trusted)]:
            item = patch.object(migration, name, value); item.start(); self.addCleanup(item.stop)
        self.fence = migration.Fence(self.binding, self.authenticate, self.service_command, self.reconcile)

    def authenticate(self, expected):
        self.assertEqual(expected, self.binding)
        migration.require(not self.foreign, 'inert changed loaded policy or original management identity')
        self.fence.unit()

    def service_command(self, args):
        self.assertIn(args, [['stop', 'solv.service'], ['daemon-reload'], ['disable', 'solv.service']])
        self.calls.append(args)
        if args[0] == 'stop':
            self.assertEqual((self.store/'original.service').read_bytes(), self.raw)

    def reconcile(self, expected):
        migration.require(not self.remaining_writer, 'inert original privilege or writer remains')

    def test_original_definition_retained_and_mask_persists_without_start_or_copy_authorization(self):
        result = self.fence.retire()
        self.assertEqual(result, {'legacy_retired': True, 'original_unit_retained': True,
                                  'copy_authorized': False, 'runtime_started': False})
        self.assertTrue(self.unit.is_symlink()); self.assertEqual(os.readlink(self.unit), '/dev/null')
        self.assertEqual((self.store/'original.service').read_bytes(), self.raw)
        self.assertEqual(self.fence.saved()['phase'], 'retired')
        self.assertEqual(self.fence.retire(), result)
        self.assertEqual([row[0] for row in self.calls], ['stop', 'daemon-reload', 'disable']*2)

    def test_unqualified_loaded_policy_or_unrecorded_mask_never_stops_any_service(self):
        self.foreign = True
        with self.assertRaises(ValueError): self.fence.retire()
        self.assertEqual(self.calls, []); self.assertEqual(self.unit.read_bytes(), self.raw)
        self.foreign = False; self.unit.unlink(); self.unit.symlink_to('/dev/null')
        with self.assertRaises(ValueError): self.fence.retire()
        self.assertEqual(self.calls, []); self.assertFalse((self.store/'retirement.json').exists())

    def test_retired_receipt_never_recreates_replaced_unit_or_forgotten_original_bytes(self):
        self.fence.retire(); self.calls.clear()
        self.unit.unlink(); self.unit.write_bytes(b'foreign unit must survive')
        with self.assertRaises(ValueError): self.fence.retire()
        self.assertEqual(self.calls, []); self.assertEqual(self.unit.read_bytes(), b'foreign unit must survive')
        self.unit.unlink(); self.unit.symlink_to('/dev/null')
        (self.store/'original.service').write_bytes(b'foreign retained definition')
        with self.assertRaises(ValueError): self.fence.retire()
        self.assertEqual(self.calls, [])

    def test_remaining_writers_or_privileges_prevent_retirement_success_but_keep_mask(self):
        self.remaining_writer = True
        with self.assertRaises(ValueError): self.fence.retire()
        self.assertEqual(self.fence.saved()['phase'], 'masked')
        self.assertEqual(os.readlink(self.unit), '/dev/null')
        self.remaining_writer = False
        self.assertTrue(self.fence.retire()['legacy_retired'])

    def test_persistent_mask_directory_sync_failure_still_attempts_original_shutdown(self):
        real = os.fsync; inode = self.units.stat().st_ino
        def fail(fd):
            if os.fstat(fd).st_ino == inode and self.unit.is_symlink():
                raise OSError('inert persistent mask durability failure')
            real(fd)
        with patch.object(os, 'fsync', fail):
            for _ in range(3):
                with self.assertRaises(OSError): self.fence.retire()
                self.assertEqual(os.readlink(self.unit), '/dev/null')
                self.assertEqual((self.store/'original.service').read_bytes(), self.raw)
        self.assertEqual(sum(row[0] == 'stop' for row in self.calls), 3)
        self.assertTrue(self.fence.retire()['legacy_retired'])

    def test_foreign_mask_staging_and_competing_controller_are_not_replaced(self):
        temporary = self.unit.with_name('.erpc-solv-mask-' + self.binding['intent'])
        temporary.write_bytes(b'retain unrelated staging bytes')
        with self.assertRaises(ValueError): self.fence.retire()
        self.assertEqual(temporary.read_bytes(), b'retain unrelated staging bytes')
        self.assertEqual(self.unit.read_bytes(), self.raw)
        temporary.unlink(); self.calls.clear()
        descriptor = os.open(self.store, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            with self.assertRaises(BlockingIOError): self.fence.retire()
        finally: os.close(descriptor)
        self.assertEqual(self.calls, [])

    def test_killed_writer_unpublished_bytes_remain_inert_and_do_not_prevent_original_retry(self):
        pending = self.store / ('.erpc-' + 'f'*32)
        pending.write_bytes(b'incomplete untrusted JSON must never become a receipt')
        pending.chmod(0o600)
        self.assertTrue(self.fence.retire()['legacy_retired'])
        self.assertEqual(pending.read_bytes(), b'incomplete untrusted JSON must never become a receipt')

    def test_each_real_fsync_interruption_can_resume_with_the_same_original_unit(self):
        # Enumerate actual durable barriers, then fail each exactly once. Tests
        # retain visible rename effects, as a lost reply does, rather than mock
        # the transaction result or assume writes happen all-or-nothing.
        count = []; real = os.fsync
        def record(fd): count.append(True); return real(fd)
        with patch.object(os, 'fsync', record): self.fence.retire()
        for position in range(len(count)):
            with self.subTest(barrier=position):
                f = Retirement('runTest'); f.setUp()
                try:
                    calls = []
                    def fail(fd):
                        index = len(calls); calls.append(True)
                        if index == position: raise OSError('inert interruption')
                        return real(fd)
                    with patch.object(os, 'fsync', fail), self.assertRaises(OSError): f.fence.retire()
                    result = f.fence.retire()
                    self.assertTrue(result['legacy_retired'])
                    self.assertEqual((f.store/'original.service').read_bytes(), f.raw)
                    self.assertEqual(os.readlink(f.unit), '/dev/null')
                    self.assertFalse(result['copy_authorized'])
                finally: f.doCleanups()
        print(str(len(count))+' actual retirement fsync interruption points passed')


if __name__ == '__main__': unittest.main()
