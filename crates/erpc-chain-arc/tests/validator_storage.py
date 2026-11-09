#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real inert snapshot paths/rename/fsync with dedicated UID/GID observations modeled.

There are no native archives, node processes, mounts or account mutations. File
contents, inode identity, modes, symlinks and directory barriers are real. The
fixture projects virtual native ownership rather than invoking privileged chown.
"""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
TEMPLATES = Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_bootstrap as bootstrap
import av_storage as storage
from av_files import Files, ROOT
from arc_files import Refused


class Storage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.context = Files(Path(self.temp.name), owner=os.getuid())
        self.context.mkdir(ROOT)
        self.context.mkdir('/var/lib', 0o755)
        self.context.mkdir(storage.DATA_HOME, 0o755)
        self.home = self.context.path(storage.DATA_HOME)
        self.uid = {'execution': 991, 'consensus': 992, 'engine': 993, 'established': True}
        self.ownership = {}
        self.devices = {}
        self.actual_stat, self.actual_lstat, self.actual_fstat = os.stat, os.lstat, os.fstat
        self.actual_chown_calls = []
        def mapped(info):
            key = (info.st_dev, info.st_ino)
            owner = self.ownership.get(key)
            device = self.devices.get(key)
            if owner is None and device is None:
                return info
            fields = list(info)
            if owner is not None: fields[4], fields[5] = owner
            if device is not None: fields[2] = device
            return os.stat_result(fields)
        def chown(descriptor, uid, gid):
            info = self.actual_fstat(descriptor)
            self.ownership[(info.st_dev, info.st_ino)] = (uid, gid)
            self.actual_chown_calls.append((info.st_ino, uid, gid))
        self.enterContext(mock.patch.object(os, 'stat', side_effect=lambda *a, **k: mapped(self.actual_stat(*a, **k))))
        self.enterContext(mock.patch.object(os, 'lstat', side_effect=lambda *a, **k: mapped(self.actual_lstat(*a, **k))))
        self.enterContext(mock.patch.object(os, 'fstat', side_effect=lambda *a, **k: mapped(self.actual_fstat(*a, **k))))
        # pathlib3.9 caches OS accessors; project both entry paths explicitly.
        self.enterContext(mock.patch.object(Path, 'stat', lambda path, *a, **k: mapped(self.actual_stat(path, *a, **k))))
        self.enterContext(mock.patch.object(Path, 'lstat', lambda path, *a, **k: mapped(self.actual_lstat(path, *a, **k))))
        self.enterContext(mock.patch.object(os, 'fchown', side_effect=chown))
        self.uuid = 'original-ext4-volume'
        self.mounts = [str(self.home)]
        self.context.command = self.command
        self.context.assert_all_quiescent = mock.Mock()
        self.context.assert_bootstrap_finished = mock.Mock()
        self.context.assert_cancelled = mock.Mock()
        self.state = {'accounts': self.uid, 'phase': 'reserved', 'signer_used': False,
                      'storage': storage.fresh(self.context), 'contract': {'owner': 'a' * 26}}
        storage.prepare(self.context, self.state)

    # unittest.enterContext was added after the oldest supported host Python.
    def enterContext(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def command(self, *args, **_kwargs):
        if args[0] == '/usr/bin/findmnt':
            rows = ([{'target': str(self.home), 'fstype': 'ext4', 'uuid': self.uuid,
                      'fsroot': '/', 'options': 'rw'}] if '--target' in args else
                    [{'target': name} for name in self.mounts])
            return SimpleNamespace(stdout=json.dumps({'filesystems': rows}).encode())
        if args[0] == '/usr/bin/du':
            return SimpleNamespace(stdout=b'1024 inert\n')
        raise AssertionError(args)

    def mark(self, path, role):
        info = self.actual_lstat(path)
        self.ownership[(info.st_dev, info.st_ino)] = (self.uid[role], self.uid[role])

    def snapshot(self):
        bootstrap.prepare(self.context, self.state)
        stage = self.home / 'bootstrap'
        for name in ('execution', 'consensus'):
            root = stage / name
            root.mkdir()
            if name == 'execution':
                (root / 'db').mkdir()
                (root / 'db/mdbx.dat').write_bytes(b'inert original EL data')
            else:
                (root / 'store.db').write_bytes(b'inert original CL data')
            (root / '.snapshot-url').write_text('inert-original-native-completion')
            for path in [root, *root.rglob('*')]:
                path.chmod(0o700 if path.is_dir() else 0o600)
                self.mark(path, 'execution')
        self.state.update({'phase': 'bootstrap', 'generation': '1' * 32,
                           'bootstrap_generation': '1' * 32, 'bootstrap_intent': '1' * 32})
        self.context.save(self.state)
        bootstrap.completed(self.context, self.state)
        return stage

    def test_original_pair_is_promoted_to_separate_private_native_owners(self):
        self.snapshot()
        original = copy.deepcopy(self.state['bootstrap_pair'])
        bootstrap.promote(self.context, self.state)
        for name, expected in (('execution', b'inert original EL data'), ('consensus', b'inert original CL data')):
            path = self.home / name
            self.assertEqual(path.stat().st_ino, original[name]['inode'])
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (self.uid[name], self.uid[name]))
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            data = path / ('db/mdbx.dat' if name == 'execution' else 'store.db')
            self.assertEqual(data.read_bytes(), expected)
        self.assertTrue(self.state['bootstrap_complete'])

    def test_visible_promotion_retries_source_barrier_before_handoff_or_success(self):
        stage = self.snapshot()
        original = self.context.sync
        def fail(directory):
            if Path(directory) == stage and (self.home / 'execution').exists():
                raise OSError('inert persistent source-directory sync failure')
            return original(directory)
        with mock.patch.object(self.context, 'sync', side_effect=fail):
            for _ in range(2):
                with self.assertRaises(OSError):
                    bootstrap.promote(self.context, self.state)
                self.assertFalse(self.state.get('bootstrap_complete'))
                self.assertTrue((stage / 'consensus/store.db').exists())
        bootstrap.promote(self.context, self.state)
        self.assertTrue(self.state['bootstrap_complete'])

    def test_visible_quarantine_never_clears_original_receipts_without_directory_barrier(self):
        bootstrap.prepare(self.context, self.state)
        self.state['bootstrap_intent'] = '2' * 32
        self.context.save(self.state)
        original = self.context.sync
        def fail(directory):
            if Path(directory) == self.home and list(self.home.glob('bootstrap-retained-*')):
                raise OSError('inert persistent quarantine barrier')
            return original(directory)
        with mock.patch.object(self.context, 'sync', side_effect=fail):
            for _ in range(2):
                with self.assertRaises(OSError):
                    bootstrap.reset(self.context, self.state, '2' * 32)
                self.assertIn('bootstrap', self.state['directories'])
        result = bootstrap.reset(self.context, self.state, '2' * 32)
        self.assertFalse(result['started'])
        self.assertTrue((self.home / result['retained']).is_dir())
        self.assertNotIn('bootstrap', self.state['directories'])

    def test_hostile_snapshot_link_never_changes_external_target_or_owners(self):
        stage = self.snapshot()
        outside = self.context.root / 'outside'
        outside.write_bytes(b'inert external data')
        outside.chmod(0o644)
        (stage / 'consensus/foreign').symlink_to(outside)
        before = (outside.stat().st_ino, outside.stat().st_mode, outside.read_bytes())
        with self.assertRaises(Refused):
            bootstrap.promote(self.context, self.state)
        self.assertEqual((outside.stat().st_ino, outside.stat().st_mode, outside.read_bytes()), before)
        self.assertFalse(self.state.get('bootstrap_complete'))

    def test_original_writer_reappearance_refuses_before_snapshot_mutation(self):
        stage = self.snapshot()
        before = stage.stat().st_ino
        self.context.assert_all_quiescent.side_effect = Refused('inert surviving original writer')
        with self.assertRaises(Refused):
            bootstrap.promote(self.context, self.state)
        self.assertEqual(stage.stat().st_ino, before)
        self.assertFalse((self.home / 'execution').exists())

    def test_uuid_and_nested_mount_drift_refuse_even_with_same_kernel_device(self):
        self.uuid = 'foreign-volume'
        with self.assertRaises(Refused): storage.verify(self.context, self.state)
        self.uuid = 'original-ext4-volume'
        self.mounts.append(str(self.home / 'execution/db'))
        with self.assertRaises(Refused): storage.verify(self.context, self.state)

    def test_same_original_volume_and_inodes_survive_kernel_device_renumbering(self):
        self.snapshot()
        for path in [self.home, *self.home.rglob('*')]:
            info = self.actual_lstat(path)
            self.devices[(info.st_dev, info.st_ino)] = info.st_dev + 7
        storage.verify(self.context, self.state)
        bootstrap.promote(self.context, self.state)
        self.assertTrue(self.state['bootstrap_complete'])

    def test_used_signer_never_accepts_bootstrap_or_quarantine(self):
        bootstrap.prepare(self.context, self.state)
        self.state.update({'bootstrap_intent': '3' * 32, 'signer_used': True})
        for action in (lambda: bootstrap.prepare(self.context, self.state),
                       lambda: bootstrap.reset(self.context, self.state, '3' * 32)):
            with self.assertRaises(Refused): action()
        self.assertTrue((self.home / 'bootstrap').is_dir())


if __name__ == '__main__':
    unittest.main()
