# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bounded no-follow reads and durable, explicit-mode publication."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat


class Refused(ValueError):
    """A fixed public diagnostic without native or credential output."""


def require(condition, message):
    if not condition:
        raise Refused(message)


def json_value(data):
    def pairs(entries):
        result = {}
        for key, value in entries:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused('invalid JSON number')))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_file(path, owner=0):
    """Re-establish durability of an existing protected regular file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == owner and not info.st_mode & 0o022,
                'untrusted managed file during synchronization')
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    """Caller first validates a root-only parent; old open descriptors are replaced."""
    temporary = path.parent / ('.erpc-' + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def read(path, maximum=1048576, owner=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == owner and not info.st_mode & 0o022, 'untrusted managed file')
        data = stream.read(maximum + 1)
        require(len(data) <= maximum, 'managed file exceeds its bound')
        return data


def digest_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum,
                'invalid bounded artifact')
        count, digest = 0, hashlib.sha256()
        for chunk in iter(lambda: stream.read(1048576), b''):
            count += len(chunk)
            require(count <= maximum, 'artifact grew beyond its bound')
            digest.update(chunk)
        require(count == info.st_size and os.fstat(stream.fileno()).st_mtime_ns == info.st_mtime_ns,
                'artifact changed while hashing')
        return digest.hexdigest()


def root_directory(path, create=False, mode=0o755):
    require(path.is_absolute(), 'managed directory must be absolute')
    for parent in [*reversed(path.parents), path]:
        try:
            info = parent.lstat()
        except FileNotFoundError:
            require(create, 'managed directory is missing')
            parent.mkdir(mode=0o700)
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            sync_directory(parent.parent)
            info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'managed ancestors must be real root-owned directories')
