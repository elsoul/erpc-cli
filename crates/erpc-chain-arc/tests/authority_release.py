#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert native archives and actual durable source-floor failures."""
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'templates/authority'))
from arc_files import Files, Refused, digest
import arc_release as release


class Images(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.calls = []
        self.bad_version = False
        self.c = Files(self.root, self.command, os.getuid())
        self.c.mkdir('/etc/erpc/arc/authority')
        self.c.mkdir('/opt/arc/downloads')
        self.target = {'version': 'v0.8.1', 'commit': 'a' * 40, 'archive_sha256': 'b' * 64,
                       'platform': 'x86_64-unknown-linux-gnu'}

    def tearDown(self):
        self.tmp.cleanup()

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b'wrong' if self.bad_version else b'v0.8.1 aaaaaaaa', b'')

    def archive(self, names=release.BINARIES, link=False):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w:gz') as archive:
            for name in names:
                raw = b'inert public release image ' + name.encode()
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                if link:
                    member.type, member.linkname = tarfile.SYMTYPE, '/outside'
                archive.addfile(member, io.BytesIO(raw))
        raw = payload.getvalue()
        self.target['archive_sha256'] = digest(raw)
        self.addCleanup(patch.stopall)
        patch.object(release, 'QUALIFIED_COMMIT', self.target['commit']).start()
        patch.dict(release.QUALIFIED_ARCHIVES, {self.target['platform']: self.target['archive_sha256']}).start()
        name = '/opt/arc/downloads/' + release.identifier(self.target) + '.tar.gz'
        self.c.write_bytes(name, raw, 0o644)
        return name

    def test_public_catalog_refuses_unqualified_source_without_executing_any_image(self):
        original = {'version':release.QUALIFIED_VERSION, 'commit':release.QUALIFIED_COMMIT,
                    'archive_sha256':release.QUALIFIED_ARCHIVES['x86_64-unknown-linux-gnu'],
                    'platform':'x86_64-unknown-linux-gnu'}
        self.assertEqual(release.executable(original), original)
        for field,value in [('version','v0.8.2'),('commit','a'*40),('archive_sha256','b'*64)]:
            with self.subTest(field=field),self.assertRaises(Refused):
                release.install(self.c,{**original,field:value},'/untrusted')
        self.assertEqual(self.calls,[])

    def test_flat_original_archive_and_version_checks_run_on_every_retry(self):
        name = self.archive()
        first = release.install(self.c, self.target, name)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(release.install(self.c, self.target, name), first)
        self.assertEqual(len(self.calls), 6)
        self.bad_version = True
        with self.assertRaises(Refused):
            release.install(self.c, self.target, name)
        self.assertEqual(len(self.calls), 7)

    def test_visible_release_rename_retries_repeat_durability_before_native_execution(self):
        archive=self.archive();real=os.fsync
        releases=self.c.path('/opt/arc/releases');self.c.mkdir('/opt/arc/releases')
        identity=releases.stat().st_ino
        def fail(fd):
            if os.fstat(fd).st_ino==identity and self.c.path(release.directory(self.target)).exists():
                raise OSError('inert release parent sync fault')
            real(fd)
        with patch.object(os,'fsync',fail):
            for _ in range(3):
                with self.assertRaises(OSError):release.install(self.c,self.target,archive)
                self.assertEqual(self.calls,[])
        release.install(self.c,self.target,archive)
        self.assertEqual(len(self.calls),3)

    def test_link_duplicate_unknown_or_traversal_members_never_execute(self):
        for names, link in [(release.BINARIES, True), (('arc-node-execution',) * 3, False),
                            (('arc-node-execution', 'arc-node-consensus', '../outside'), False),
                            (release.BINARIES + ('extra',), False)]:
            with self.subTest(names=names, link=link):
                name = self.archive(names, link)
                with self.assertRaises(Refused):
                    release.install(self.c, self.target, name)
        self.assertEqual(self.calls, [])

    def test_same_version_different_source_and_lower_version_refused(self):
        state = {}
        release.floor(self.c, state, self.target, opening=True)
        for key, value in [('version', 'v0.8.0'), ('commit', 'c' * 40),
                           ('archive_sha256', 'd' * 64), ('platform', 'aarch64-unknown-linux-gnu')]:
            with self.subTest(key=key), self.assertRaises(Refused):
                release.floor(self.c, state, {**self.target, key: value}, opening=True)
        self.assertEqual(self.c.json('/etc/erpc/arc/authority/owner.json')['source_floor'], self.target)

    def test_visible_newer_floor_remains_restrictive_after_sync_failure(self):
        state = {}
        release.floor(self.c, state, self.target, opening=True)
        newer = {**self.target, 'version': 'v0.8.2', 'commit': 'c' * 40}
        real = os.fsync
        directory = self.c.ROOT.stat().st_ino
        def fail(fd):
            if os.fstat(fd).st_ino == directory:
                raise OSError('inert source-floor directory fault')
            real(fd)
        with patch.object(os, 'fsync', fail), self.assertRaises(OSError):
            release.floor(self.c, state, newer, opening=True)
        saved = self.c.json('/etc/erpc/arc/authority/owner.json')
        self.assertEqual(saved['source_floor'], newer)
        with self.assertRaises(Refused):
            release.floor(self.c, saved, self.target, opening=True)
        release.floor(self.c, saved, newer, opening=True)
        self.assertEqual(self.c.json('/etc/erpc/arc/authority/owner.json')['source_floor'], newer)


if __name__ == '__main__':
    unittest.main()
