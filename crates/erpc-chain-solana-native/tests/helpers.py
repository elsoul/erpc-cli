#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Helper publication on real temporary files with modeled root ownership."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_helpers as helpers
import native_files as files


class Helpers(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(tmp.name); source = self.root / 'source'; source.mkdir()
        for name in helpers.FILES: (source / name).write_bytes(b'# inert public helper ' + name.encode())
        patch.object(helpers, 'SOURCE', source).start(); patch.object(helpers, 'RELEASES', self.root / 'releases').start()
        patch.object(helpers, 'read', lambda p, n: files.read(p, n, os.getuid())).start()
        patch.object(helpers, 'sync_file', lambda p: files.sync_file(p, os.getuid())).start()
        def directory(path, create=False):
            if create: path.mkdir(parents=True, mode=0o755, exist_ok=True)
            if path.is_symlink() or not path.is_dir() or path.stat().st_mode & 0o022:
                raise ValueError('unsafe fixture directory')
        patch.object(helpers, 'root_directory', directory).start()

    def test_publication_is_complete_immutable_and_idempotent(self):
        value = helpers.publish(); original = helpers.verify(value)
        inode = (original / 'catalog.json').stat().st_ino
        self.assertEqual(helpers.publish(), value)
        self.assertEqual((original / 'catalog.json').stat().st_ino, inode)
        self.assertEqual(helpers.contents(original), helpers.contents(helpers.SOURCE))
        (helpers.SOURCE / 'catalog.json').write_bytes(b'inert updated public catalog')
        second = helpers.publish(); self.assertNotEqual(second, value)
        self.assertEqual(helpers.verify(value), original)
        self.assertEqual((original / 'catalog.json').stat().st_mode & 0o777, 0o444)

    def test_missing_extra_linked_and_changed_helpers_refuse(self):
        value = helpers.publish(); final = helpers.verify(value)
        extra = final / 'unknown.py'; extra.write_bytes(b'inert')
        with self.assertRaises(ValueError): helpers.verify(value)
        extra.unlink(); path = final / 'catalog.json'; path.chmod(0o644); path.write_bytes(b'changed')
        with self.assertRaises(ValueError): helpers.verify(value)
        path.unlink(); path.symlink_to(helpers.SOURCE / 'catalog.json')
        with self.assertRaises(OSError): helpers.verify(value)
        path.unlink()
        with self.assertRaises(ValueError): helpers.verify(value)

    def test_visible_final_after_failed_directory_sync_requires_resync_on_retry(self):
        original = helpers.sync_directory
        def fail(path):
            if path == helpers.RELEASES: raise OSError('inert publication durability failure')
            original(path)
        with patch.object(helpers, 'sync_directory', fail), self.assertRaises(OSError): helpers.publish()
        self.assertEqual(len(list(helpers.RELEASES.iterdir())), 1)
        with patch.object(helpers, 'sync_directory', fail), self.assertRaises(OSError): helpers.publish()
        value = helpers.publish(); helpers.verify(value)

    def test_unknown_release_and_staging_symlinks_are_not_followed_or_deleted(self):
        helpers.RELEASES.mkdir(); link = helpers.RELEASES / ('.pending-' + 'a'*32); link.symlink_to(helpers.SOURCE)
        with self.assertRaises(ValueError): helpers.publish()
        self.assertTrue(link.is_symlink()); link.unlink()
        foreign = helpers.RELEASES / 'foreign'; foreign.mkdir()
        with self.assertRaises(ValueError): helpers.publish()
        self.assertTrue(foreign.is_dir())


if __name__ == '__main__': unittest.main()
