#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Seal an authorized upload before systemd opens logs or root executes its code."""
import contextlib
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile

LIMIT = 64 * 1024 * 1024
INTERPRETER = b'''#!/bin/sh
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
unset PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP
export PYTHONNOUSERSITE=1
exec /usr/bin/python3 -I "$@"
'''


class Files:
    def __init__(self, root=Path('/'), owner=0):
        self.root, self.owner = root, owner

    @contextlib.contextmanager
    def directory(self, run, upload_owner=None):
        if not re.fullmatch(r'/opt/erpc/runs/r-[a-z0-9-]+', run):
            raise ValueError('invalid run directory')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in Path(run).parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                expected = (self.owner, upload_owner) if part == Path(run).name else (self.owner,)
                if info.st_uid not in expected or info.st_mode & 0o022:
                    raise ValueError('untrusted run ancestor')
            yield fd
        finally:
            os.close(fd)

    def read(self, fd, name, owners):
        file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in owners or info.st_mode & 0o022:
                raise ValueError('upload must be a protected single-link regular file')
            data = stream.read(LIMIT + 1)
            if len(data) > LIMIT:
                raise ValueError('run file exceeds the bounded upload size')
            return data

    def access(self, fd, login, directory=False, executable=False):
        # Linux POSIX ACL v2: owner rw[x], named login r[x], group/other none.
        # The mode's group bits represent the ACL mask, not group membership.
        os.fchmod(fd, 0o700 if directory or executable else 0o600)
        if directory and sys.platform.startswith('linux'):
            try:
                os.removexattr(fd, 'system.posix_acl_default')
            except OSError as error:
                if error.errno != errno.ENODATA:
                    raise
        if login == self.owner:
            return
        read = 5 if directory or executable else 4
        entries = [(1, 7 if directory or executable else 6, 0xffffffff), (2, read, login),
                   (4, 0, 0xffffffff), (16, read, 0xffffffff), (32, 0, 0xffffffff)]
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in entries)
        os.setxattr(fd, 'system.posix_acl_access', acl)
        if os.getxattr(fd, 'system.posix_acl_access') != acl:
            raise ValueError('run filesystem did not preserve the private login ACL')

    def write(self, fd, name, data, group, login=None, executable=False):
        # The directory is already sealed. Never truncate a caller-chosen inode.
        temporary = '.erpc-' + name + '.new'
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(out, 'wb') as stream:
                os.fchown(stream.fileno(), self.owner, group)
                self.access(stream.fileno(), self.owner if login is None else login, executable=executable)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=fd)

    def seal(self, run, expected, login, group, runner_hash, helper_hash):
        if not re.fullmatch('[a-f0-9]{64}', expected):
            raise ValueError('invalid bundle digest')
        with self.directory(run, login) as fd:
            # New run only: never adopt logs, FIFOs, links, results or extracted code.
            if set(os.listdir(fd)) != {'bundle.tar.gz', 'node-run.sh', 'run-files.py'}:
                raise ValueError('run contains unexpected prior state')
            sources = {name: self.read(fd, name, (self.owner, login)) for name in os.listdir(fd)}
            if hashlib.sha256(sources['bundle.tar.gz']).hexdigest() != expected:
                raise ValueError('bundle differs from its submitted digest')
            for name, digest in [('node-run.sh', runner_hash), ('run-files.py', helper_hash)]:
                if hashlib.sha256(sources[name]).hexdigest() != digest:
                    raise ValueError('runner differs from its submitted digest')
            members = {}
            size = 0
            with tarfile.open(fileobj=io.BytesIO(sources['bundle.tar.gz']), mode='r:gz') as archive:
                for entry in archive:
                    parts = entry.name.split('/')
                    if not entry.isfile() or entry.name in members or any(not re.fullmatch(r'[A-Za-z0-9_.-]+', p) or p in ('.', '..') for p in parts):
                        raise ValueError('bundle contains a non-regular or unsafe member')
                    size += entry.size
                    if size > LIMIT or len(members) >= 10000:
                        raise ValueError('expanded bundle exceeds its limit')
                    members[entry.name] = archive.extractfile(entry).read()
            if any('/'.join(name.split('/')[:index]) in members
                   for name in members for index in range(1, len(name.split('/')))):
                raise ValueError('bundle file/directory collision')
            if not {'ansible.cfg', 'requirements.txt', 'inventory.yml'} <= members.keys():
                raise ValueError('bundle lacks the required run inputs')
            # Seal the directory before publication. Replacing upload inodes also
            # invalidates any previously opened writable descriptor to those files.
            os.fchown(fd, self.owner, group)
            self.access(fd, login, directory=True)
            for name, data in sources.items():
                self.write(fd, name, data, group, login)
            os.mkdir('bundle', 0o700, dir_fd=fd)
            bundle = os.open('bundle', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                os.fchown(bundle, self.owner, group)
                self.access(bundle, login, directory=True)
                for name, data in members.items():
                    parent = os.dup(bundle)
                    try:
                        for part in name.split('/')[:-1]:
                            try:
                                os.mkdir(part, 0o700, dir_fd=parent)
                            except FileExistsError:
                                pass
                            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                            os.close(parent)
                            parent = child
                            os.fchown(parent, self.owner, group)
                            self.access(parent, login, directory=True)
                        self.write(parent, name.split('/')[-1], data, group, login)
                    finally:
                        os.close(parent)
            finally:
                os.close(bundle)
            self.write(fd, 'log', b'', group, login)
            self.write(fd, 'python-isolated', INTERPRETER, group, login, executable=True)
            self.write(fd, 'sealed.json', json.dumps({'bundle': expected, 'group': group, 'login': login}).encode(), group, login)

    def result(self, run, value):
        with self.directory(run) as fd:
            receipt = json.loads(self.read(fd, 'sealed.json', (self.owner,)))
            self.write(fd, 'result.json', json.dumps(value).encode() + b'\n', receipt['group'], receipt['login'])


def main():
    if os.geteuid() != 0 or not sys.flags.isolated:
        raise ValueError('run sealing requires root and isolated Python')
    files = Files()
    if sys.argv[1] == 'seal' and len(sys.argv) == 8:
        files.seal(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6], sys.argv[7])
    elif sys.argv[1] == 'result' and len(sys.argv) == 9:
        status, code, started, finished, play, message = sys.argv[3:]
        files.result(sys.argv[2], dict(status=status, exit_code=int(code), started_at=started,
                                      finished_at=finished, play=play, message=message))
    else:
        raise ValueError('invalid run file operation')


if __name__ == '__main__':
    main()
