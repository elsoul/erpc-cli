# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Protected, bounded and durable native-validator state publication."""
import json
import os
from pathlib import Path
import secrets
import stat

ROOT_UID = 0
TRUST_ANCHOR = Path('/')


def require(value, message):
    if not value: raise ValueError(message)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def directory(path, create=False, mode=0o700):
    require(path.is_absolute() and os.path.normpath(path) == str(path), 'invalid protected directory path')
    current = TRUST_ANCHOR
    for part in (None, *path.relative_to(TRUST_ANCHOR).parts):
        if part is not None: current = current / part
        try: info = current.lstat()
        except FileNotFoundError:
            require(create, 'protected validator directory is missing')
            current.mkdir(mode=0o700)
            descriptor = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fchmod(descriptor, mode); os.fsync(descriptor)
            finally: os.close(descriptor)
            sync_directory(current.parent); info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and not info.st_mode & 0o022,
                'validator ancestors must be real root-owned directories')


def read(path, maximum=1048576, mode=None):
    directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size <= maximum,
                'unsafe validator state or helper file')
        require(mode is None or info.st_mode & 0o7777 == mode, 'validator state mode differs')
        value = source.read(maximum + 1)
        require(len(value) <= maximum, 'validator state exceeds its bound')
        return value


def synchronize(path):
    directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1
                and not info.st_mode & 0o022, 'unsafe validator state synchronization')
        os.fsync(descriptor)
    finally: os.close(descriptor)
    sync_directory(path.parent)


def write(path, value, mode=0o600, group=None):
    directory(path.parent)
    if path.exists() or path.is_symlink(): read(path)
    temporary = path.parent / ('.pending-' + secrets.token_hex(16))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as target:
            target.write(value); target.flush()
            if group is not None:
                require(type(group) is int and 0 < group < 2**31, 'invalid numeric publication group')
                os.fchown(target.fileno(), ROOT_UID, group)
            os.fchmod(target.fileno(), mode); os.fsync(target.fileno())
        os.replace(temporary, path); sync_directory(path.parent)
    finally: temporary.unlink(missing_ok=True)


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True, allow_nan=False).encode()


def decode(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'duplicate validator state field'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'invalid validator state number'))
