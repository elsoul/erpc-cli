#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Descriptor-checked public authority and encrypted custody storage for Arc."""
import hashlib
import json
import os
import pathlib
import stat
import subprocess


class Refused(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate Arc state field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite Arc value')))


class Files:
    Refused = Refused
    require = staticmethod(require)

    def __init__(self, root=pathlib.Path('/'), run=subprocess.run, owner=0):
        self.root, self.run, self.owner = pathlib.Path(root), run, owner
        self.ROOT = self.path('/etc/erpc/arc/authority')
        self.TRUST_ANCHOR = self.root
        self.image_cache = {}

    def path(self, name):
        require(isinstance(name, str) and name.startswith('/') and
                all(p not in ('', '.', '..') for p in name.split('/')[1:]), 'invalid Arc path')
        return self.root / name.lstrip('/')

    def protected(self, name, missing=False, directory=False):
        target = self.path(name)
        current = self.root
        anchor = current.lstat()
        require(stat.S_ISDIR(anchor.st_mode) and anchor.st_uid == self.owner and
                not anchor.st_mode & 0o022, 'unsafe Arc trust anchor')
        for index, part in enumerate(target.relative_to(self.root).parts):
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                if missing:
                    return target
                raise Refused('required Arc path is absent') from None
            require(info.st_uid == self.owner and not info.st_mode & 0o022,
                    'Arc authority path is not exclusively root owned')
            if current != target or directory:
                require(stat.S_ISDIR(info.st_mode), 'Arc ancestor is not a real directory')
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                        'Arc authority file is not a single-link regular file')
        return target

    def sync(self, directory):
        directory = pathlib.Path(directory)
        require(directory == self.root or self.root in directory.parents, 'sync outside Arc trust anchor')
        while True:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                named = directory.lstat()
                require((info.st_dev, info.st_ino) == (named.st_dev, named.st_ino),
                        'Arc directory changed during synchronization')
                os.fsync(fd)
            finally:
                os.close(fd)
            if directory == self.root:
                return
            directory = directory.parent

    def mkdir(self, name, mode=0o700):
        target = self.protected(name, missing=True, directory=True)
        relative = target.relative_to(self.root).parts
        current = self.root
        for part in relative:
            current = current / part
            virtual = '/' + str(current.relative_to(self.root))
            if not current.exists():
                current.mkdir(mode=mode if current == target else 0o755)
                self.sync(current.parent)
            self.protected(virtual, directory=True)
        return target

    def read(self, name, limit=1048576, resync=False, private=False):
        target = self.protected(name)
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and info.st_nlink == 1
                    and not info.st_mode & (0o077 if private else 0o022) and info.st_size <= limit,
                    'Arc authority content is unsafe or exceeds its bound')
            raw = stream.read(limit + 1)
            named = target.lstat()
            require(len(raw) == info.st_size and
                    (named.st_dev, named.st_ino) == (info.st_dev, info.st_ino),
                    'Arc authority changed while read')
            if resync:
                os.fsync(stream.fileno())
        if resync:
            self.sync(target.parent)
        return raw

    def json(self, name, **kwargs):
        return strict_json(self.read(name, **kwargs))

    def write(self, name, value, mode=0o600):
        self.write_bytes(name, encoded(value), mode)

    def write_bytes(self, name, raw, mode=0o600):
        require(isinstance(raw, bytes) and len(raw) <= 1048576, 'Arc receipt exceeds its bound')
        target = self.protected(name, missing=True)
        pending = self.protected(name + '.pending', missing=True)
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, mode)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and info.st_nlink == 1
                    and not info.st_mode & 0o022, 'unsafe Arc pending receipt')
            os.fchmod(fd, mode)
            os.ftruncate(fd, 0)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                require(written > 0, 'Arc receipt write made no progress')
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self.protected(name, missing=True)
        self.protected(name + '.pending')
        os.replace(pending, target)
        self.sync(target.parent)

    def remove(self, name):
        target = self.protected(name, missing=True)
        if target.exists():
            target.unlink()
            self.sync(target.parent)

    def save(self, state):
        self.write('/etc/erpc/arc/authority/owner.json', state)

    def command(self, *args, check=True, input=None):
        return self.run(list(args), check=check, input=input, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=330, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
