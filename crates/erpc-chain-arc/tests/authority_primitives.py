#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual filesystem fault fixtures; no NSS, mount, service or operational keys."""
import base64
import copy
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'templates/authority'
sys.path.insert(0, str(SOURCE))
import arc_files as files
import arc_storage as storage
import arc_custody as custody


class Fixture(files.Files):
    def __init__(self, root):
        super().__init__(root, owner=os.getuid())
        self.mkdir('/etc/erpc/arc/authority')
        self.mkdir('/var/lib')
        self.machine = {'uuid': 'inert-original-volume', 'fstype': 'ext4', 'device': root.stat().st_dev}
        self.mutations = []
        self.public = base64.b64encode(bytes([1]) * 32).decode()

    def command(self, *args, check=True, input=None):
        if args[0] == '/usr/bin/findmnt':
            data = {'filesystems': [{'target': str(self.root), **self.machine, 'options': 'rw'}]}
            if '--list' in args:
                data = {'filesystems': [{'target': str(self.root)}]}
            return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b'')
        if args[0] == '/usr/bin/systemd-creds':
            if args[1] == 'encrypt':
                self.mutations.append('encrypt')
                return subprocess.CompletedProcess(args, 0, b'inert-sealed-capsule:' + input, b'')
            return subprocess.CompletedProcess(args, 0, input.removeprefix(b'inert-sealed-capsule:'), b'')
        raise AssertionError(args)


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.c = Fixture(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_protected_tree_refuses_writable_ancestor_and_single_file_links(self):
        self.c.write('/etc/erpc/arc/authority/value.json', {'public': True})
        path = self.c.path('/etc/erpc/arc/authority/value.json')
        os.link(path, path.with_name('hardlink'))
        with self.assertRaises(files.Refused):
            self.c.json('/etc/erpc/arc/authority/value.json')
        path.with_name('hardlink').unlink()
        path.parent.chmod(0o777)
        with self.assertRaises(files.Refused):
            self.c.write('/etc/erpc/arc/authority/value.json', {})
        path.parent.chmod(0o700)
        path.unlink()
        path.symlink_to('/dev/null')
        with self.assertRaises(files.Refused):
            self.c.write('/etc/erpc/arc/authority/value.json', {})

    def test_prepared_root_retains_empty_recovery_directory_and_refuses_drift(self):
        home = self.c.path(storage.DATA_HOME)
        home.mkdir(mode=0o700)
        recovery = home / 'lost+found'
        recovery.mkdir(mode=0o700)
        before = recovery.stat().st_ino
        state = {'storage': storage.fresh(self.c)}
        self.c.save(state)
        storage.prepare(self.c, state)
        self.assertEqual(recovery.stat().st_ino, before)
        self.assertEqual(home.stat().st_mode & 0o777, 0o755)
        self.assertEqual(storage.verify(self.c, state), home)
        home.chmod(0o700)
        with self.assertRaises(files.Refused):
            storage.prepare(self.c, state)
        self.assertEqual(home.stat().st_mode & 0o777, 0o700)

    def test_original_root_inode_and_mount_receipt_not_current_name(self):
        state = {'storage': storage.fresh(self.c)}
        self.c.save(state)
        storage.prepare(self.c, state)
        home = self.c.path(storage.DATA_HOME)
        home.rename(home.with_name('original'))
        home.mkdir(mode=0o755)
        with self.assertRaises(files.Refused):
            storage.verify(self.c, state)
        home.rmdir()
        home.with_name('original').rename(home)
        self.c.machine['uuid'] = 'different-volume'
        with self.assertRaises(files.Refused):
            storage.verify(self.c, state)

    def test_unknown_or_nonempty_recovery_content_is_not_fresh(self):
        home = self.c.path(storage.DATA_HOME)
        home.mkdir(mode=0o755)
        item = home / 'unknown'
        item.write_text('inert')
        with self.assertRaises(files.Refused):
            storage.fresh(self.c)
        item.unlink()
        recovery = home / 'lost+found'
        recovery.mkdir()
        (recovery / 'recovered').write_text('inert')
        with self.assertRaises(files.Refused):
            storage.fresh(self.c)
        self.assertTrue((recovery / 'recovered').exists())

    def test_all_nested_mounts_are_refused_including_same_device_bind(self):
        home = self.c.path(storage.DATA_HOME)
        home.mkdir(mode=0o755)
        original = self.c.command
        for target in (str(home / 'execution/db'), str(home / 'consensus/store.db')):
            def command(*args, **kwargs):
                if '--list' in args:
                    return subprocess.CompletedProcess(args, 0, json.dumps({'filesystems':
                        [{'target': str(self.root)}, {'target': target}]}).encode(), b'')
                return original(*args, **kwargs)
            with patch.object(self.c, 'command', command), self.assertRaises(files.Refused):
                storage.fresh(self.c)

    def test_persistent_receipt_directory_sync_failure_cannot_publish_credential(self):
        # Public, inert envelope: public() is a deterministic boundary stub here.
        state = {'contract': {'public_key': self.c.public}}
        self.c.save(state)
        raw = b'inert-public-format-fixture'
        real_fsync = os.fsync
        owner_file = self.c.path('/etc/erpc/arc/authority/owner.json')
        root_id = self.c.ROOT.stat().st_ino
        def fsync(fd):
            if os.fstat(fd).st_ino == root_id and 'credential' in json.loads(owner_file.read_text()):
                raise OSError('inert directory durability fault')
            real_fsync(fd)
        with patch.object(custody, 'public', return_value=self.c.public):
            # Stage an already verified ciphertext, as a prior successful staging write.
            self.c.write_bytes(custody.PENDING, b'inert-sealed-capsule:' + raw)
            for _ in range(3):
                with patch.object(os, 'fsync', fsync), self.assertRaises(OSError):
                    custody.import_original(self.c, state, raw)
                state = self.c.json('/etc/erpc/arc/authority/owner.json')
                self.assertFalse(self.c.path(custody.CREDENTIAL).exists())
                self.assertTrue(self.c.path(custody.PENDING).exists())
            result = custody.import_original(self.c, state, raw)
            self.assertEqual(result['public_key'], self.c.public)
            original = self.c.read(custody.CREDENTIAL)
            self.c.path(custody.CREDENTIAL).unlink()
            custody.materialize(self.c, state)
            self.assertEqual(self.c.read(custody.CREDENTIAL), original)
            self.assertEqual(self.c.mutations, [])
            self.assertEqual(owner_file.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
