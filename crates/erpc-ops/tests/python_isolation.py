#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline startup/ownership tests. No sudo, nodes, real keys or network calls."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import struct
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('run_files', ROOT / 'crates/erpc-ops/node/run-files.py')
files = importlib.util.module_from_spec(spec)
spec.loader.exec_module(files)
spec = importlib.util.spec_from_file_location('upload', ROOT / 'crates/erpc-ssh/src/upload.py')
upload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upload)
TRUST = (ROOT / 'crates/erpc-ssh/src/python-trust.py').read_text()
trust_module = {}
exec(compile(TRUST, '<trusted imports>', 'exec'), trust_module)
exec(compile((ROOT / 'crates/erpc-ssh/src/python-release.py').read_text(), '<trusted release>', 'exec'), trust_module)


def archive(extra=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as tar:
        for name, value in dict({'ansible.cfg': b'config', 'requirements.txt': b'pins', 'inventory.yml': b'inventory', 'scripts/check.py': b'print(42)'}, **(extra or {})).items():
            info = tarfile.TarInfo(name)
            info.size = len(value)
            tar.addfile(info, io.BytesIO(value))
    return out.getvalue()


class Seal(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = '/opt/erpc/runs/r-20261026t000000-abcdef'
        self.directory = self.root / self.run.lstrip('/')
        self.directory.mkdir(parents=True)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.controller = files.Files(self.root, self.uid)
        for path in (self.directory, *self.directory.parents):
            path.chmod(0o750)
            if path == self.root:
                break
        self.payload = archive()
        for name, data in [('bundle.tar.gz', self.payload), ('node-run.sh', b'runner'), ('run-files.py', b'helper')]:
            (self.directory / name).write_bytes(data)
            (self.directory / name).chmod(0o640)

    def seal(self):
        self.controller.seal(self.run, hashlib.sha256(self.payload).hexdigest(), self.uid, self.gid,
                             hashlib.sha256(b'runner').hexdigest(), hashlib.sha256(b'helper').hexdigest())

    def test_seal_preserves_receipt_follow_and_safe_result_reads(self):
        self.seal()
        self.assertEqual((self.directory / 'bundle/scripts/check.py').read_bytes(), b'print(42)')
        self.assertEqual((self.directory / 'bundle.tar.gz').read_bytes(), self.payload)
        receipt = json.loads((self.directory / 'sealed.json').read_text())
        self.assertEqual(receipt['bundle'], hashlib.sha256(self.payload).hexdigest())
        for path in [self.directory, *self.directory.rglob('*')]:
            mode = path.stat().st_mode
            self.assertFalse(mode & 0o022)
            self.assertTrue(mode & stat.S_IRUSR)
            if path.is_dir():
                self.assertTrue(mode & stat.S_IXUSR)
        # The follower can read the stable log and atomic JSON after disconnection.
        with (self.directory / 'log').open('ab') as stream:
            stream.write(b'public progress\n')
        self.controller.result(self.run, dict(status='ok', exit_code=0))
        self.assertEqual(json.loads((self.directory / 'result.json').read_text())['status'], 'ok')
        self.assertEqual((self.directory / 'log').read_bytes(), b'public progress\n')
        self.assertFalse((self.directory / 'result.json').stat().st_mode & 0o022)
        with self.assertRaises(ValueError):
            self.seal()

    def test_acl_grants_only_named_login_read_access(self):
        target = self.directory / 'node-run.sh'
        with target.open('rb') as stream:
            encoded = {}
            def set_acl(fd, name, value): encoded[name] = value
            def get_acl(fd, name): return encoded[name]
            with mock.patch.object(os, 'setxattr', set_acl, create=True), mock.patch.object(os, 'getxattr', get_acl, create=True):
                self.controller.access(stream.fileno(), self.uid + 1)
            raw = encoded['system.posix_acl_access']
            self.assertEqual(struct.unpack('<I', raw[:4]), (2,))
            self.assertEqual(list(struct.iter_unpack('<HHI', raw[4:])),
                [(1, 6, 0xffffffff), (2, 4, self.uid + 1), (4, 0, 0xffffffff),
                 (16, 4, 0xffffffff), (32, 0, 0xffffffff)])
            if sys.platform.startswith('linux'):
                # Actual kernel round-trip as this unprivileged file owner.
                self.controller.access(stream.fileno(), self.uid + 1)
                self.assertEqual(os.getxattr(stream.fileno(), 'system.posix_acl_access'), raw)

    def test_preopened_upload_descriptor_cannot_change_published_code(self):
        with (self.directory / 'node-run.sh').open('r+b') as old:
            self.seal()
            old.write(b'edited')
        self.assertEqual((self.directory / 'node-run.sh').read_bytes(), b'runner')

    def test_preexisting_log_result_fifo_and_links_refused_before_publication(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'untouched')
        for kind in ('symlink', 'hardlink', 'fifo', 'regular'):
            for name in ('log', 'result.json', 'result.json.tmp'):
                with self.subTest(kind=kind, name=name):
                    path = self.directory / name
                    if kind == 'symlink': path.symlink_to(outside)
                    elif kind == 'hardlink': os.link(outside, path)
                    elif kind == 'fifo': os.mkfifo(path)
                    else: path.write_bytes(b'old output')
                    with self.assertRaises(ValueError): self.seal()
                    path.unlink()
                    self.assertEqual(outside.read_bytes(), b'untouched')
                    self.assertFalse((self.directory / 'bundle').exists())

    def test_upload_hardlinks_symlinks_and_digest_changes_fail_closed(self):
        target = self.directory / 'node-run.sh'
        outside = self.root / 'outside'
        outside.write_bytes(b'runner')
        for kind in ('hardlink', 'symlink', 'changed'):
            with self.subTest(kind=kind):
                target.unlink()
                if kind == 'hardlink': os.link(outside, target)
                elif kind == 'symlink': target.symlink_to(outside)
                else: target.write_bytes(b'changed')
                with self.assertRaises((ValueError, OSError)): self.seal()
                self.assertFalse((self.directory / 'bundle').exists())
        self.assertEqual(outside.read_bytes(), b'runner')

    def test_ancestor_symlink_and_writable_directory_refused(self):
        original = self.directory.parent
        moved = original.with_name('saved')
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError): self.seal()
        original.unlink()
        moved.rename(original)
        original.chmod(0o770)
        with self.assertRaises(ValueError): self.seal()

    def test_archive_traversal_and_unexpected_prior_state_refused(self):
        self.payload = archive({'../escape': b'bad'})
        (self.directory / 'bundle.tar.gz').write_bytes(self.payload)
        with self.assertRaises(ValueError): self.seal()
        self.assertFalse((self.directory.parent / 'escape').exists())

    def test_result_replaces_inode_without_following_destination_link(self):
        self.seal()
        outside = self.root / 'outside'
        outside.write_bytes(b'untouched')
        # Model a malicious privileged mutation after seal; even that must not
        # cause O_TRUNC through an existing result destination.
        (self.directory / 'result.json').symlink_to(outside)
        self.controller.result(self.run, dict(status='failed'))
        self.assertEqual(outside.read_bytes(), b'untouched')
        self.assertFalse((self.directory / 'result.json').is_symlink())


class FreshNamespace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'opt').mkdir()
        (self.root / 'opt').chmod(0o755)
        self.login, self.group = 12345, 12345
        self.owners, self.acls = {}, {}
        original_fstat, original_stat = os.fstat, os.stat
        def key(info): return (info.st_dev, info.st_ino)
        def mapped(info):
            value = list(info)
            value[4], value[5] = self.owners.get(key(info), (0, 0))
            return os.stat_result(value)
        def held(fd):
            # Owners and ACLs are emulated per inode. Keep each recorded inode
            # allocated until the test ends: a file created after a recorded
            # one is removed may get its number and would inherit its record.
            copy = os.dup(fd)
            self.addCleanup(os.close, copy)
            return key(original_fstat(copy))
        self.held = held
        def chown(fd, uid, gid): self.owners[held(fd)] = (uid, gid)
        def set_acl(fd, name, data): self.acls[(held(fd), name)] = data
        def get_acl(fd, name): return self.acls[(key(original_fstat(fd)), name)]
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(os, 'fstat', side_effect=lambda fd: mapped(original_fstat(fd))).start()
        mock.patch.object(os, 'stat', side_effect=lambda *a, **kw: mapped(original_stat(*a, **kw))).start()
        mock.patch.object(os, 'fchown', side_effect=chown).start()
        mock.patch.object(os, 'setxattr', side_effect=set_acl, create=True).start()
        mock.patch.object(os, 'getxattr', side_effect=get_acl, create=True).start()
        self.uploader = upload.Upload(self.root)
        self.sealer = files.Files(self.root)
        self.run = '/opt/erpc/runs/r-20261026t000000-abcdef'
        self.payload = archive()

    def own(self, path, uid, gid):
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try: self.owners[self.held(fd)] = (uid, gid)
        finally: os.close(fd)

    def publish(self, name, data):
        previous = os.umask(0o077)
        try: self.uploader.write(self.run + '/' + name, self.login, self.group, io.BytesIO(data))
        finally: os.umask(previous)

    def can_read(self, path, directory=False):
        info = os.stat(path)
        required = 5 if directory else 4
        if info.st_uid == self.login:
            return (stat.S_IMODE(info.st_mode) >> 6) & required == required
        acl = self.acls.get(((info.st_dev, info.st_ino), 'system.posix_acl_access'))
        if acl:
            entries = list(struct.iter_unpack('<HHI', acl[4:]))
            mask = next(perm for tag, perm, _ in entries if tag == 16)
            grant = next((perm for tag, perm, uid in entries if tag == 2 and uid == self.login), 0)
            return grant & mask & required == required
        return stat.S_IMODE(info.st_mode) & required == required

    def test_empty_namespace_upload_seal_and_follow_under_umask077(self):
        for name, data in [('node-run.sh', b'runner'), ('run-files.py', b'helper'), ('bundle.tar.gz', self.payload)]:
            self.publish(name, data)
        directory = self.root / self.run.lstrip('/')
        for name in ('opt', 'opt/erpc', 'opt/erpc/runs'):
            ancestor = self.root / name
            self.assertEqual(os.stat(ancestor).st_uid, 0)
            self.assertEqual(stat.S_IMODE(os.stat(ancestor).st_mode), 0o755)
            self.assertTrue(self.can_read(ancestor, directory=True))
        self.assertEqual(os.stat(directory).st_uid, self.login)
        self.assertEqual(stat.S_IMODE(os.stat(directory).st_mode), 0o700)
        for path in directory.iterdir():
            self.assertEqual(os.stat(path).st_uid, self.login)
            self.assertTrue(self.can_read(path))
        self.sealer.seal(self.run, hashlib.sha256(self.payload).hexdigest(), self.login, self.group,
                         hashlib.sha256(b'runner').hexdigest(), hashlib.sha256(b'helper').hexdigest())
        self.assertEqual(os.stat(directory).st_uid, 0)
        self.assertTrue(self.can_read(directory, directory=True))
        self.assertTrue(self.can_read(directory / 'log'))
        self.assertTrue(self.can_read(directory / 'python-isolated', directory=True))
        self.sealer.result(self.run, {'status': 'ok'})
        self.assertTrue(self.can_read(directory / 'result.json'))
        self.assertEqual(json.loads((directory / 'result.json').read_text()), {'status': 'ok'})
        with self.assertRaises(ValueError): self.publish('node-run.sh', b'must not unseal')

    def test_existing_root0700_ancestors_are_repaired_without_adoption(self):
        erpc = self.root / 'opt/erpc'
        erpc.mkdir(mode=0o700)
        self.publish('node-run.sh', b'runner')
        self.assertEqual(stat.S_IMODE(erpc.stat().st_mode), 0o755)
        self.assertTrue(self.can_read(erpc, directory=True))

    def test_foreign_writable_and_symlink_ancestors_are_refused(self):
        erpc = self.root / 'opt/erpc'
        erpc.mkdir(mode=0o755)
        self.own(erpc, 99999, 99999)
        with self.assertRaises(ValueError): self.publish('node-run.sh', b'runner')
        self.own(erpc, 0, 0)
        erpc.chmod(0o777)
        with self.assertRaises(ValueError): self.publish('node-run.sh', b'runner')
        erpc.chmod(0o755)
        erpc.rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        erpc.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError): self.publish('node-run.sh', b'runner')
        self.assertFalse(any(outside.iterdir()))

    def test_upload_refuses_links_and_special_destinations(self):
        self.publish('node-run.sh', b'runner')
        target = self.root / self.run.lstrip('/') / 'node-run.sh'
        outside = self.root / 'outside'
        outside.write_bytes(b'untouched')
        for kind in ('symlink', 'hardlink', 'fifo'):
            target.unlink()
            if kind == 'symlink': target.symlink_to(outside)
            elif kind == 'hardlink': os.link(outside, target)
            else: os.mkfifo(target)
            with self.assertRaises(ValueError): self.publish('node-run.sh', b'new')
            self.assertEqual(outside.read_bytes(), b'untouched')

    # A worker's release, staged for the agent as `erpc worker deploy` uploads it.
    RELEASE = '/opt/erpc/uploads/bot-default/20261029T121314Z-1a2b3c4d'

    def stage(self, name, data=b'x', login=None, release=None):
        self.upload_to((release or self.RELEASE) + '/' + name, io.BytesIO(data), login)

    def upload_to(self, path, source, login=None):
        login = self.login if login is None else login
        previous = os.umask(0o077)
        try: self.uploader.write(path, login, login, source)
        finally: os.umask(previous)

    def tree(self):
        # Every path under the root, with its type and mode, owner and content.
        state = {}
        for path in [self.root, *self.root.rglob('*')]:
            info = os.stat(path, follow_symlinks=False)
            content = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
            state[path] = (info.st_mode, info.st_uid, info.st_gid, content)
        return state

    def test_worker_release_takes_nested_files_inside_its_login_owned_directory(self):
        # The order of worker_deploy: the binary, release.json, launch.json, then run.files.
        names = ('bot', 'release.json', 'launch.json', 'config.jsonc', 'config/settings.json',
                 'data/deep/table.bin', 'data/top.json')
        for name in names: self.stage(name, name.encode())
        release = self.root / self.RELEASE.lstrip('/')
        for ancestor in (release.parent, release.parent.parent, release.parent.parent.parent):
            self.assertEqual(os.stat(ancestor).st_uid, 0)
            self.assertEqual(stat.S_IMODE(os.stat(ancestor).st_mode), 0o755)
        for path in [release, *release.rglob('*')]:
            self.assertEqual(os.stat(path).st_uid, self.login, path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o700 if path.is_dir() else 0o600, path)
        for name in names: self.assertEqual((release / name).read_bytes(), name.encode())

    def test_worker_release_is_the_logins_whatever_order_its_files_arrive_in(self):
        self.stage('config/settings.json')
        self.stage('bot')
        release = self.root / self.RELEASE.lstrip('/')
        self.assertEqual(os.stat(release).st_uid, self.login)
        self.assertEqual(stat.S_IMODE(os.stat(release).st_mode), 0o700)

    def test_worker_release_may_ship_the_names_a_sealed_run_reserves(self):
        for name in ('bundle', 'release.json', 'result.json', 'sealed.json', 'config.jsonc'):
            self.stage(name)
        # The same as root, whose directories never change hands.
        other = self.RELEASE.replace('bot-default', 'root-default')
        for name in ('bundle', 'release.json', 'bundle2/x.json', 'result.json', 'config.jsonc'):
            self.stage(name, login=0, release=other)

    def test_only_a_run_is_bounded_and_a_worker_release_is_streamed(self):
        size = 1025 + 2 * 1024 * 1024
        with mock.patch.object(upload, 'LIMIT', 1024):
            self.stage('bot', bytes(size))
            self.publish('bundle.tar.gz', bytes(1024))
            with self.assertRaises(ValueError): self.publish('node-run.sh', bytes(1025))
        self.assertEqual((self.root / self.RELEASE.lstrip('/') / 'bot').stat().st_size, size)
        self.assertFalse((self.root / self.run.lstrip('/') / 'node-run.sh').exists())

    def test_worker_namespace_stays_roots_and_refuses_foreign_writable_and_symlink_directories(self):
        self.stage('bot')
        release = self.root / self.RELEASE.lstrip('/')
        with self.assertRaises(ValueError): self.stage('config/settings.json', login=54321)
        nested = release / 'config'
        nested.mkdir()
        nested.chmod(0o770)
        with self.assertRaises(ValueError): self.stage('config/settings.json')
        nested.rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        nested.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError): self.stage('config/settings.json')
        self.assertFalse(any(outside.iterdir()))
        nested.unlink()
        # A populated directory of root's inside the release is never handed over.
        nested.mkdir(mode=0o700)
        (nested / 'kept').write_bytes(b'roots')
        with self.assertRaises(ValueError): self.stage('config/settings.json')
        # The worker's own directory is namespace, as /opt/erpc/uploads is: no
        # upload hands it to a login, and a release under one a login owns
        # is refused.
        self.own(release.parent, self.login, self.login)
        with self.assertRaises(ValueError): self.stage('later.json')

    def test_uploads_takes_the_agent_restic_and_releases_and_no_other_shape(self):
        refused = ('/opt/erpc/uploads/x', '/opt/erpc/uploads/agent', '/opt/erpc/uploads/bot-default/bot',
                   '/opt/erpc/uploads/agent/sub/erpc-worker-agent',
                   '/opt/erpc/uploads/restic/20261029T121314Z-1a2b3c4d/restic')
        # Refused before the input is read or anything is created.
        for path in refused:
            source = io.BytesIO(b'x')
            with self.assertRaises(ValueError): self.upload_to(path, source)
            self.assertEqual(source.tell(), 0, path)
        self.assertFalse((self.root / 'opt/erpc').exists())
        # As `erpc worker deploy` stages the agent, and `erpc worker backup on` restic.
        for path in ('/opt/erpc/uploads/agent/erpc-worker-agent', '/opt/erpc/uploads/restic/restic'):
            self.upload_to(path, io.BytesIO(b'binary'))
            staged = self.root / path.lstrip('/')
            self.assertEqual(staged.read_bytes(), b'binary')
            for item, mode in ((staged, 0o600), (staged.parent, 0o700)):
                self.assertEqual((os.stat(item).st_uid, stat.S_IMODE(os.stat(item).st_mode)), (self.login, mode))
        uploads = self.root / 'opt/erpc/uploads'
        self.assertEqual((os.stat(uploads).st_uid, stat.S_IMODE(os.stat(uploads).st_mode)), (0, 0o755))
        before = self.tree()
        for path in refused:
            with self.assertRaises(ValueError): self.upload_to(path, io.BytesIO(b'x'))
        self.assertEqual(self.tree(), before)

    def test_a_run_takes_no_nested_upload_and_stays_sealed_for_a_root_login(self):
        self.publish('node-run.sh', b'runner')
        with self.assertRaises(ValueError):
            self.uploader.write(self.run + '/sub/file', self.login, self.group, io.BytesIO(b'x'))
        self.assertFalse((self.root / self.run.lstrip('/') / 'sub').exists())
        run = '/opt/erpc/runs/r-20261026t000000-fedcba'
        for name, data in [('node-run.sh', b'runner'), ('run-files.py', b'helper'), ('bundle.tar.gz', self.payload)]:
            self.uploader.write(run + '/' + name, 0, 0, io.BytesIO(data))
        self.sealer.seal(run, hashlib.sha256(self.payload).hexdigest(), 0, 0,
                         hashlib.sha256(b'runner').hexdigest(), hashlib.sha256(b'helper').hexdigest())
        with self.assertRaises(ValueError): self.uploader.write(run + '/node-run.sh', 0, 0, io.BytesIO(b'must not unseal'))
        # Nor does a deeper path open a sealed run or put a login's directory in it.
        self.publish('run-files.py', b'helper')
        self.publish('bundle.tar.gz', self.payload)
        self.sealer.seal(self.run, hashlib.sha256(self.payload).hexdigest(), self.login, self.group,
                         hashlib.sha256(b'runner').hexdigest(), hashlib.sha256(b'helper').hexdigest())
        sealed = self.root / self.run.lstrip('/')
        with self.assertRaises(ValueError):
            self.uploader.write(self.run + '/sub/file', self.login, self.group, io.BytesIO(b'x'))
        self.assertEqual(stat.S_IMODE(os.stat(sealed).st_mode), 0o700)
        self.assertFalse((sealed / 'sub').exists())

    def test_a_run_path_through_uploads_or_deeper_is_refused_and_leaves_a_sealed_run_alone(self):
        # Only /opt/erpc/uploads stages a worker's files: `uploads` lower
        # down a run's path makes it no less a run's.
        for name, data in [('node-run.sh', b'runner'), ('run-files.py', b'helper'), ('bundle.tar.gz', self.payload)]:
            self.publish(name, data)
        self.sealer.seal(self.run, hashlib.sha256(self.payload).hexdigest(), self.login, self.group,
                         hashlib.sha256(b'runner').hexdigest(), hashlib.sha256(b'helper').hexdigest())
        before = self.tree()
        for rest in ('uploads/x', 'uploads/bot-default/20261029T121314Z-1a2b3c4d/bot', 'sub/x',
                     'bundle/scripts/x', 'a/b/c/x'):
            for login in (self.login, 0):
                with self.subTest(rest=rest, login=login):
                    source = io.BytesIO(b'x')
                    with self.assertRaises(ValueError):
                        self.uploader.write(self.run + '/' + rest, login, login, source)
                    self.assertEqual(source.tell(), 0)
        self.assertEqual(self.tree(), before)

    def test_a_release_refuses_links_and_special_destinations(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'untouched')
        release = self.root / self.RELEASE.lstrip('/')
        for name in ('bot', 'config/settings.json'):
            self.stage(name, b'first')
            target = release / name
            for kind in ('symlink', 'hardlink', 'fifo'):
                with self.subTest(name=name, kind=kind):
                    target.unlink()
                    if kind == 'symlink': target.symlink_to(outside)
                    elif kind == 'hardlink': os.link(outside, target)
                    else: os.mkfifo(target)
                    planted = os.stat(target, follow_symlinks=False)
                    with self.assertRaises(ValueError): self.stage(name, b'new')
                    self.assertEqual(outside.read_bytes(), b'untouched')
                    left = os.stat(target, follow_symlinks=False)
                    self.assertEqual((left.st_ino, left.st_mode), (planted.st_ino, planted.st_mode))
        self.assertEqual(list(release.rglob('.upload-*')), [])


# upload.py's own main program, in a process of its own, against a temporary
# root: `/` opens as that root, root's ownership is modeled as FreshNamespace
# models it, and the destination already holds an earlier upload.
UPLOADER = r"""
import importlib.util, io, os, runpy, sys
from pathlib import Path
program, root, path = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
inject = sys.argv[4] if len(sys.argv) > 4 else ''
owners = {}
original_fstat, original_stat, original_open = os.fstat, os.stat, os.open
def key(info): return (info.st_dev, info.st_ino)
def mapped(info):
    value = list(info)
    value[4], value[5] = owners.get(key(info), (0, 0))
    return os.stat_result(value)
os.fstat = lambda fd: mapped(original_fstat(fd))
os.stat = lambda *a, **kw: mapped(original_stat(*a, **kw))
os.fchown = lambda fd, uid, gid: owners.__setitem__(key(original_fstat(fd)), (uid, gid))
os.open = lambda name, *a, **kw: original_open(root if name == Path('/') else name, *a, **kw)
os.geteuid = lambda: 0
os.umask(0o077)
spec = importlib.util.spec_from_file_location('upload', program)
upload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upload)
upload.Upload().write(path, 12345, 12345, io.BytesIO(b'old'))
# A test may have one more signal arrive at a chosen moment of the upload.
import signal
if inject == 'signal-at-cleanup':
    # A second signal, as the cleanup removes the temporary.
    unlink = os.unlink
    def unlink_after_a_signal(name, *a, **kw):
        if str(name).startswith('.upload-'):
            os.kill(os.getpid(), signal.SIGHUP)
        return unlink(name, *a, **kw)
    os.unlink = unlink_after_a_signal
elif inject == 'signal-at-open':
    # A signal as soon as the temporary exists.
    opened = os.open
    def open_then_signal(name, flags, *a, **kw):
        descriptor = opened(name, flags, *a, **kw)
        if str(name).startswith('.upload-') and flags & os.O_EXCL:
            os.kill(os.getpid(), signal.SIGTERM)
        return descriptor
    os.open = open_then_signal
sys.argv = [program, path, '12345', '12345']
runpy.run_path(program, run_name='__main__')
"""


class InterruptedUpload(unittest.TestCase):
    RELEASE = '/opt/erpc/uploads/bot-default/20261029T121314Z-1a2b3c4d'
    SENT = 3 * 1024 * 1024

    def streamed(self, release):
        # Whether the upload's temporary holds all that was sent so far.
        try:
            return any(path.name.startswith('.upload-') and path.stat().st_size == self.SENT
                       for path in release.iterdir())
        except FileNotFoundError:
            return False

    def interrupt(self, number, inject=''):
        # Streams part of a release file to the real uploader over a staged
        # b'old', then sends `number` (none: `inject` signals by itself).
        # Returns whether the stream got that far, what is left in the
        # release, the destination's bytes, the exit status and stderr.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'opt').mkdir()
            (root / 'opt').chmod(0o755)
            release = root / self.RELEASE.lstrip('/')
            argv = [sys.executable, '-I', '-B', '-c', UPLOADER, str(ROOT / 'crates/erpc-ssh/src/upload.py'),
                    str(root), self.RELEASE + '/bot', inject]
            uploader = subprocess.Popen(argv, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                # Standard input stays open: more is to come.
                with contextlib.suppress(BrokenPipeError):
                    uploader.stdin.write(bytes(self.SENT))
                    uploader.stdin.flush()
                deadline = time.monotonic() + 30
                while not self.streamed(release) and uploader.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                midway = self.streamed(release)
                if number is not None:
                    uploader.send_signal(number)
                uploader.wait(timeout=30)
            finally:
                uploader.kill()
                stderr = uploader.communicate()[1].decode()
            left = sorted(path.name for path in release.iterdir())
            return midway, left, (release / 'bot').read_bytes(), uploader.returncode, stderr

    def test_a_signal_mid_stream_removes_the_temporary_and_keeps_the_destination(self):
        for number in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number.name):
                midway, left, content, status, stderr = self.interrupt(number)
                self.assertTrue(midway, stderr)
                self.assertEqual(left, ['bot'], stderr)
                self.assertEqual(content, b'old')
                self.assertEqual(status, 128 + number, stderr)

    def test_a_second_signal_during_the_cleanup_does_not_stop_it(self):
        midway, left, content, status, stderr = self.interrupt(signal.SIGTERM, 'signal-at-cleanup')
        self.assertTrue(midway, stderr)
        self.assertEqual(left, ['bot'], stderr)
        self.assertEqual(content, b'old')
        self.assertEqual(status, 128 + signal.SIGTERM, stderr)

    def test_a_signal_as_the_temporary_is_created_still_removes_it(self):
        _, left, content, status, stderr = self.interrupt(None, 'signal-at-open')
        self.assertEqual(left, ['bot'], stderr)
        self.assertEqual(content, b'old')
        self.assertEqual(status, 128 + signal.SIGTERM, stderr)


class Startup(unittest.TestCase):
    def test_real_interpreter_ignores_usercustomize_pythonpath_and_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, poison, work = (root / name for name in ('home', 'poison', 'work'))
            for directory in (home, poison, work): directory.mkdir()
            env = dict(os.environ, HOME=str(home), PYTHONPATH=str(poison))
            env.pop('PYTHONHOME', None)
            site = subprocess.check_output([sys.executable, '-E', '-s', '-c', 'import site; print(site.getusersitepackages())'], env=env, text=True).strip()
            site = Path(site)
            self.assertTrue(str(site).startswith(str(home)))
            site.mkdir(parents=True)
            marker = root / 'injected'
            payload = 'open(' + repr(str(marker)) + ', "a").write("startup hook\\n")\n'
            (site / 'usercustomize.py').write_text(payload)
            (poison / 'sitecustomize.py').write_text(payload)
            (work / 'erpc_poison_module.py').write_text(payload)
            (root / 'erpc_poison_module.py').write_text(payload)
            # Positive control proves this environment executes harmless hooks.
            subprocess.run([sys.executable, '-c', 'pass'], env=env, cwd=work, check=True)
            self.assertTrue(marker.exists())
            marker.unlink()
            script = root / 'helper.py'
            script.write_text('import importlib.util, sys; assert sys.flags.isolated; assert importlib.util.find_spec("erpc_poison_module") is None; print("managed-helper")')
            for mode in ([str(script)], ['-c', script.read_text()], ['-']):
                completed = subprocess.run([sys.executable, '-I', *mode], input=script.read_text(), env=env,
                                           cwd=work, text=True, capture_output=True, check=True)
                self.assertEqual(completed.stdout.strip(), 'managed-helper')
                self.assertFalse(marker.exists())

    def test_real_nested_entrypoint_with_parent_segments_loads_its_checked_sibling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            play = root / 'run/bundle/ansible/chain'
            helper = root / 'run/bundle/jinja'
            play.mkdir(parents=True)
            helper.mkdir()
            (helper / 'offline_sibling.py').write_text('VALUE = 42\n')
            # Model only root metadata, because this test intentionally has no
            # sudo. The interpreter, ../ traversal and sibling import are real.
            model = """import os, stat
from pathlib import Path
original_lstat, original_scandir = os.lstat, os.scandir
def modeled(info):
    values = list(info)
    values[4] = 0
    values[0] &= ~0o022
    return os.stat_result(values)
def lstat(path): return modeled(original_lstat(path))
class Entry:
    def __init__(self, entry): self.entry, self.path, self.name = entry, entry.path, entry.name
    def stat(self, **kwargs): return modeled(self.entry.stat(**kwargs))
def scandir(path): return [Entry(entry) for entry in original_scandir(path)]
os.lstat, os.scandir = lstat, scandir
"""
            (helper / 'entry.py').write_text(model + TRUST + "\nassert '..' in Path(__file__).parts\ntrusted_imports(Path(__file__).absolute().parent)\nimport offline_sibling\nprint(offline_sibling.VALUE)\n")
            argv = [sys.executable, '-I', str(play / '../../jinja/entry.py')]
            self.assertIn('/../../', argv[-1])
            completed = subprocess.run(argv, capture_output=True, text=True, check=True)
            self.assertEqual(completed.stdout, '42\n')

    def test_trusted_import_snippets_remain_identical(self):
        count = 0
        for path in (ROOT / 'crates').glob('erpc-chain-*/templates/**/*.py'):
            source = path.read_text()
            if '# BEGIN ERPC TRUSTED IMPORTS\n' in source:
                embedded = source.split('# BEGIN ERPC TRUSTED IMPORTS\n', 1)[1].split('# END ERPC TRUSTED IMPORTS', 1)[0]
                self.assertEqual(embedded, TRUST, str(path))
                count += 1
        self.assertGreaterEqual(count, 7)

    def test_trusted_import_refuses_actual_unprivileged_script_tree(self):
        if os.getuid() == 0: self.skipTest('the non-root rejection case requires an unprivileged test process')
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError): trust_module['trusted_imports'](temporary)

    def test_trusted_import_root_metadata_model_and_symlinks(self):
        # No sudo: model only uid metadata; all path traversal and imported code
        # remain real harmless files owned by this test's unprivileged account.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            module = directory / 'erpc_fixture_sibling.py'
            module.write_text('VALUE = 42\n')
            (directory / 'json.py').write_text('raise AssertionError("sibling must not shadow stdlib")\n')
            module.chmod(0o644)
            original_lstat, original_scandir = os.lstat, os.scandir
            def root_stat(value):
                values = list(value)
                values[4] = 0
                return os.stat_result(values)
            def lstat(path): return root_stat(original_lstat(path))
            class Entry:
                def __init__(self, entry): self.entry, self.path, self.name = entry, entry.path, entry.name
                def stat(self, **kw): return root_stat(self.entry.stat(**kw))
            def scandir(path): return [Entry(entry) for entry in original_scandir(path)]
            try:
                with mock.patch.object(os, 'lstat', lstat), mock.patch.object(os, 'scandir', scandir):
                    # The temporary root's real ancestors may be world writable;
                    # model them protected, retaining actual leaf file types.
                    def protected(path):
                        info = lstat(path)
                        values = list(info)
                        values[0] &= ~0o022
                        return os.stat_result(values)
                    with mock.patch.object(os, 'lstat', protected):
                        nested = directory / 'nested'
                        nested.mkdir()
                        trust_module['trusted_imports'](str(nested / '..'))
                        self.assertIn(str(directory), sys.path)
                        hidden_link = directory / 'hidden-link'
                        hidden_link.symlink_to(nested, target_is_directory=True)
                        with self.assertRaises(ValueError):
                            trust_module['trusted_imports'](str(hidden_link / '..'))
                        hidden_link.unlink()
                        imported = importlib.import_module('erpc_fixture_sibling')
                        self.assertEqual(imported.VALUE, 42)
                        self.assertNotEqual(Path(importlib.util.find_spec('json').origin).parent, directory)
                        # Every readable helper entry remains checked before import.
                        (directory / 'linked.py').symlink_to(module)
                        with self.assertRaises(ValueError): trust_module['trusted_imports'](str(directory))
                        (directory / 'linked.py').unlink()
                        module.chmod(0o666)
                        with self.assertRaises(ValueError): trust_module['trusted_imports'](str(directory))
            finally:
                sys.path[:] = [value for value in sys.path if value != str(directory)]
                sys.modules.pop('erpc_fixture_sibling', None)


class PrivateCache(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.name = 'erpc_private_cache_fixture'
        self.source = self.root / (self.name + '.py')
        self.source.write_text('VALUE = 42\n')
        self.cache = self.root / '__pycache__'
        program = "import os,sys;sys.dont_write_bytecode=False;os.umask(0o077);sys.path.append(" + repr(str(self.root)) + ");import " + self.name
        subprocess.run([sys.executable, '-I', '-c', program], check=True)
        self.assertEqual(stat.S_IMODE(self.cache.stat().st_mode), 0o700)
        self.addCleanup(lambda: sys.modules.pop(self.name, None))
        self.addCleanup(lambda: sys.path.__setitem__(slice(None), [p for p in sys.path if p != str(self.root)]))
        self.denied_listing = False
        self.traversable = True
        self.foreign = None
        original_lstat, original_scandir, original_access = os.lstat, os.scandir, os.access
        def modeled(info, path):
            values = list(info)
            values[4] = 99999 if str(path) == self.foreign else 0
            if not str(path).startswith(str(self.root)): values[0] &= ~0o022
            return os.stat_result(values)
        def lstat(path): return modeled(original_lstat(path), path)
        class Entry:
            def __init__(self, entry): self.entry, self.path, self.name = entry, entry.path, entry.name
            def stat(self, **kw): return modeled(self.entry.stat(**kw), self.path)
        def scandir(path):
            if str(path) == str(self.cache) and self.denied_listing:
                raise PermissionError('modeled non-root cache enumeration')
            return [Entry(entry) for entry in original_scandir(path)]
        def access(path, mode, **kw):
            if str(path) == str(self.cache):
                self.assertEqual(mode, os.X_OK)
                self.assertTrue(kw.get('effective_ids'))
                return self.traversable
            return original_access(path, mode, **kw)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(os, 'lstat', lstat).start()
        mock.patch.object(os, 'scandir', scandir).start()
        mock.patch.object(os, 'access', access).start()

    def test_cold_import_private_cache_then_distinct_runtime_uses_source(self):
        # Real -I import above produced a mode0700 cache. Model the distinct
        # runtime UID's kernel denial, including actual importlib read attempts.
        self.denied_listing, self.traversable = True, False
        loader = importlib.machinery.SourceFileLoader
        original = loader.get_data
        read = []
        cache = str(self.cache) + os.path.sep
        def get_data(instance, path):
            read.append(path)
            if path.startswith(cache): raise PermissionError('modeled non-root cache read')
            return original(instance, path)
        with mock.patch.object(loader, 'get_data', get_data):
            trust_module['trusted_imports'](str(self.root))
            module = importlib.import_module(self.name)
        self.assertEqual(module.VALUE, 42)
        self.assertIn(str(self.source), read)
        # Some interpreters reject the inaccessible cache at stat time; any
        # attempted read above is denied, and checked source was executed.
        self.assertTrue(sys.dont_write_bytecode)

    def test_listing_denial_without_traversal_denial_is_not_trusted(self):
        self.cache.chmod(0o711)
        self.denied_listing, self.traversable = True, True
        with self.assertRaises(PermissionError): trust_module['trusted_imports'](str(self.root))

    def test_readable_foreign_or_writable_cache_is_rejected(self):
        self.cache.chmod(0o755)
        cached = self.cache / os.listdir(self.cache)[0]
        self.foreign = str(cached)
        with self.assertRaises(ValueError): trust_module['trusted_imports'](str(self.root))
        self.foreign = None
        cached.chmod(0o666)
        with self.assertRaises(ValueError): trust_module['trusted_imports'](str(self.root))

    def test_new_trusted_import_does_not_create_another_private_cache(self):
        # Existing cache is preserved; new modules compile directly from source.
        self.denied_listing, self.traversable = True, False
        name = 'erpc_new_source_fixture'
        (self.root / (name + '.py')).write_text('VALUE = 7\n')
        self.addCleanup(lambda: sys.modules.pop(name, None))
        before = set(os.listdir(self.cache))
        trust_module['trusted_imports'](str(self.root))
        self.assertEqual(importlib.import_module(name).VALUE, 7)
        self.assertEqual(set(os.listdir(self.cache)), before)


class ReleasePointer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.namespace = self.root / 'helpers'
        self.namespace.mkdir()
        self.profile = ['control.py', 'bootstrap.py', 'catalog.json']
        values = [b'import bootstrap\n', b'VALUE = 42\n', b'{}']
        self.digest = hashlib.sha256(b''.join(values)).hexdigest()
        self.release = self.namespace / 'releases' / self.digest
        self.release.mkdir(parents=True)
        for name, value in zip(self.profile, values):
            (self.release / name).write_bytes(value)
        self.pointer = self.namespace / 'current'
        self.pointer.symlink_to(self.release, target_is_directory=True)
        self.original_lstat, self.original_scandir = os.lstat, os.scandir
        def modeled(info):
            values = list(info)
            values[4] = 0
            return os.stat_result(values)
        def lstat(path):
            info = modeled(self.original_lstat(path))
            # Model protected host ancestors above the owned fixture only.
            if not str(path).startswith(str(self.root)):
                values = list(info)
                values[0] &= ~0o022
                info = os.stat_result(values)
            return info
        class Entry:
            def __init__(self, entry): self.entry, self.path, self.name = entry, entry.path, entry.name
            def stat(self, **kw): return modeled(self.entry.stat(**kw))
        def scandir(path): return [Entry(entry) for entry in self.original_scandir(path)]
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(os, 'lstat', lstat).start()
        mock.patch.object(os, 'scandir', scandir).start()
        self.addCleanup(lambda: sys.path.__setitem__(slice(None), [p for p in sys.path if not p.startswith(str(self.root))]))

    def selected(self):
        return trust_module['trusted_release'](str(self.namespace), [self.profile])

    def test_complete_absolute_and_relative_pointer_select_the_same_real_release(self):
        self.assertEqual(self.selected(), str(self.release))
        self.pointer.unlink()
        self.pointer.symlink_to('releases/' + self.digest, target_is_directory=True)
        self.assertEqual(self.selected(), str(self.release))
        self.assertIn(str(self.release), sys.path)
        self.assertNotIn(str(self.pointer), sys.path)

    def test_unknown_target_extra_member_changed_hash_and_incomplete_profiles_refused(self):
        self.pointer.unlink()
        self.pointer.symlink_to('../helpers/releases/' + self.digest, target_is_directory=True)
        with self.assertRaises(ValueError): self.selected()
        self.pointer.unlink()
        self.pointer.symlink_to(self.release, target_is_directory=True)
        (self.release / 'unexpected.py').write_text('pass')
        with self.assertRaises(ValueError): self.selected()
        (self.release / 'unexpected.py').unlink()
        original = (self.release / 'catalog.json').read_bytes()
        (self.release / 'catalog.json').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.selected()
        (self.release / 'catalog.json').write_bytes(original)
        (self.release / 'bootstrap.py').unlink()
        with self.assertRaises(ValueError): self.selected()

    def test_target_ancestor_symlink_writable_module_and_nonroot_pointer_refused(self):
        file = self.release / 'bootstrap.py'
        file.chmod(0o666)
        with self.assertRaises(ValueError): self.selected()
        file.chmod(0o644)
        actual = self.release.with_name('saved')
        self.release.rename(actual)
        self.release.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ValueError): self.selected()
        self.release.unlink()
        actual.rename(self.release)
        original = os.lstat
        def foreign(path):
            info = original(path)
            if str(path) == str(self.pointer):
                values = list(info)
                values[4] = 12345
                return os.stat_result(values)
            return info
        with mock.patch.object(os, 'lstat', foreign):
            with self.assertRaises(ValueError): self.selected()

    def test_selected_release_does_not_follow_later_current_replacement(self):
        selected = self.selected()
        self.pointer.unlink()
        self.pointer.symlink_to('releases/' + 'b' * 64, target_is_directory=True)
        self.assertEqual((Path(selected) / 'bootstrap.py').read_bytes(), b'VALUE = 42\n')
        with self.assertRaises(FileNotFoundError): self.selected()


if __name__ == '__main__':
    unittest.main()
