#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real source/staging files; no node, mount, operational identity or key tool."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_migration_copy as copy


class Fixture:
    def __init__(self, root, sparse=False):
        self.root = root
        self.paths = [root / name for name in ('original', 'payload', 'scratch', 'receipts')]
        for path in self.paths: path.mkdir(mode=0o700)
        self.source, self.payload, self.scratch, self.journal = self.paths
        (self.source / 'ledger').mkdir(mode=0o700)
        (self.source / 'ledger' / 'tower.bin').write_bytes(b'inert original signed history bytes')
        (self.source / 'empty').write_bytes(b'')
        if sparse:
            with (self.source / 'accounts.bin').open('wb') as stream:
                stream.write(b'inert-account-data')
                stream.seek(4 * copy.CHUNK + 7); stream.write(b'last')
        else: (self.source / 'accounts.bin').write_bytes(b'inert account data' * 257)
        os.link(self.source / 'accounts.bin', self.source / 'account-link.bin')
        self.uid, self.gid = os.getuid() or 1, os.getgid() or 1
        if os.getuid() == 0:
            for path in [self.source, *self.source.rglob('*')]: os.chown(path, self.uid, self.gid)
        self.binding = {'intent': 'a'*32, 'source_uuid': '10000000-0000-0000-0000-000000000001',
                        'target_uuid': '10000000-0000-0000-0000-000000000002',
                        'source_inode': self.source.stat().st_ino, 'source_uid': self.uid, 'source_gid': self.gid,
                        'payload_inode': self.payload.stat().st_ino, 'scratch_inode': self.scratch.stat().st_ino,
                        'history_sha256': 'b'*64}
        self.allowed = True; self.gates = 0

    def gate(self):
        self.gates += 1
        copy.require(self.allowed, 'original migration cancelled')

    def worker(self, **changes):
        return copy.Copy(*self.paths, dict(self.binding, **changes), self.gate)

    def snapshot(self):
        return {str(p.relative_to(self.source)): (p.read_bytes(), copy.fingerprint(p.stat()))
                for p in self.source.rglob('*') if p.is_file()}


@contextlib.contextmanager
def fixture(sparse=False):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve(); value = Fixture(root, sparse)
        # Only the shared temporary ancestors model production protected paths.
        # Source/payload/receipt files and their device/inode/link/IO remain real.
        ancestors = {(p.stat().st_dev, p.stat().st_ino) for p in root.parents}
        original = os.fstat
        def metadata(fd):
            info = original(fd)
            if stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) in ancestors:
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                fields['st_mode'] &= ~0o022
                return SimpleNamespace(**fields)
            return info
        with patch.object(copy, 'ROOT_UID', os.getuid()), patch.object(os, 'fstat', side_effect=metadata):
            yield value


class MigrationCopy(unittest.TestCase):
    def test_copy_retains_original_history_and_does_not_write_zero_regions(self):
        with fixture(sparse=True) as f:
            before = f.snapshot(); worker = f.worker(); writes = []; real = os.write
            def written(fd, data):
                amount = real(fd, data); writes.append(amount); return amount
            with patch.object(os, 'write', side_effect=written): first = worker.run()
            second = worker.run()
            self.assertEqual(first, second); self.assertEqual(before, f.snapshot())
            self.assertTrue(first['source_retained']); self.assertFalse(first['runtime_started'])
            self.assertGreater(f.gates, 20); self.assertFalse(list(f.scratch.iterdir()))
            for relative, (raw, _) in before.items():
                target = f.payload / relative
                self.assertEqual(target.read_bytes(), raw)
                self.assertEqual(target.stat().st_mode & 0o7777, 0o600)
                self.assertEqual(target.stat().st_nlink, 1)
                self.assertNotEqual(target.stat().st_ino, (f.source / relative).stat().st_ino)
            # Allocation reporting differs by filesystem, including for the
            # original sparse fixture. Verify actual writes skip zero regions;
            # qualified Linux ext4/XFS allocation remains a real-host check.
            self.assertLess(sum(writes), first['bytes'])

    def test_write_failure_and_cancellation_reuse_only_original_staging(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel), fixture() as f:
                before = f.snapshot(); real = os.write; calls = []
                def write(fd, data):
                    count = real(fd, data); calls.append(count)
                    if cancel: f.allowed = False
                    else: raise OSError('inert failed copy write reply')
                    return count
                with patch.object(os, 'write', side_effect=write), self.assertRaises((OSError, ValueError)):
                    f.worker().run()
                self.assertTrue(calls); self.assertEqual(before, f.snapshot())
                f.allowed = True; f.worker().run()
                self.assertEqual(before, f.snapshot())
                self.assertEqual((f.payload/'accounts.bin').read_bytes(), (f.source/'accounts.bin').read_bytes())

    def test_lost_no_replace_publication_reply_preserves_both_original_links_for_retry(self):
        with fixture() as f:
            before = f.snapshot(); real = os.link
            def lost(*args, **kwargs):
                real(*args, **kwargs); raise OSError('inert lost hardlink publication reply')
            with patch.object(os, 'link', side_effect=lost), self.assertRaises(OSError): f.worker().run()
            self.assertEqual(before, f.snapshot()); self.assertTrue(list(f.scratch.iterdir()))
            f.worker().run(); self.assertFalse(list(f.scratch.iterdir()))
            self.assertEqual(before, f.snapshot())

    def test_unknown_staging_links_and_source_changes_are_not_replaced(self):
        with fixture() as f:
            (f.payload/'unowned').write_bytes(b'keep foreign data')
            with self.assertRaisesRegex(ValueError, 'adopt'): f.worker().run()
            self.assertEqual((f.payload/'unowned').read_bytes(), b'keep foreign data')
        with fixture() as f:
            (f.source/'indirect').symlink_to(f.root/'outside')
            with self.assertRaises((ValueError, OSError)): f.worker().run()
            self.assertTrue((f.source/'indirect').is_symlink())
        with fixture() as f:
            f.worker().run(); old = (f.payload/'ledger/tower.bin').read_bytes()
            (f.source/'ledger/tower.bin').write_bytes(b'changed original history')
            with self.assertRaisesRegex(ValueError, 'receipt changed'): f.worker().run()
            self.assertEqual((f.payload/'ledger/tower.bin').read_bytes(), old)
        with fixture() as f:
            f.worker().run(); (f.payload/'accounts.bin').write_bytes(b'foreign changed copy')
            with self.assertRaises(ValueError): f.worker().run()
            self.assertEqual((f.payload/'accounts.bin').read_bytes(), b'foreign changed copy')

    def test_binding_and_private_directory_authority_are_not_adopted(self):
        with fixture() as f:
            f.worker().run()
            for key, value in [('history_sha256','f'*64), ('intent','f'*32), ('payload_inode',1), ('source_uid',True)]:
                with self.subTest(key=key), self.assertRaises(ValueError): f.worker(**{key:value}).run()
            f.payload.chmod(0o755)
            with self.assertRaises(ValueError): f.worker().run()
        with fixture() as f:
            with self.assertRaisesRegex(ValueError, 'overlap'):
                copy.Copy(f.source, f.source/'nested', f.scratch, f.journal, f.binding, f.gate)

    def test_directory_lock_prevents_overlapping_copy_workers(self):
        with fixture() as f:
            original = f.gate; inside = False; rejected = []
            def gate():
                nonlocal inside
                original()
                if (f.journal/'owner.json').exists() and not inside:
                    inside = True
                    try:
                        with self.assertRaises(BlockingIOError): f.worker().run()
                        rejected.append(True)
                    finally: inside = False
            worker = f.worker(); worker.gate = gate
            worker.run(); self.assertTrue(rejected)

    def test_every_actual_fsync_failure_resumes_with_original_data_unchanged(self):
        real = os.fsync; calls = []
        with fixture() as f:
            def counted(fd): calls.append(fd); return real(fd)
            with patch.object(os, 'fsync', side_effect=counted): f.worker().run()
        for failure in range(1, len(calls)+1):
            with self.subTest(fsync=failure), fixture() as f:
                before = f.snapshot(); count = 0
                def broken(fd):
                    nonlocal count
                    count += 1
                    if count >= failure: raise OSError('inert persistent copy fsync failure')
                    return real(fd)
                with patch.object(os, 'fsync', side_effect=broken), self.assertRaises(OSError): f.worker().run()
                self.assertEqual(before, f.snapshot())
                f.worker().run(); self.assertEqual(before, f.snapshot())
                self.assertEqual((f.payload/'ledger/tower.bin').read_bytes(), (f.source/'ledger/tower.bin').read_bytes())
        print(str(len(calls)) + ' actual copy fsync failure points recovered')


if __name__ == '__main__': unittest.main()
