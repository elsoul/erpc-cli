#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed paths, bounded data and durable publication for the Monad host controller."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

ROOT = Path('/var/lib/erpc-monad')
CONFIG = Path('/etc/erpc/monad')
HELPERS = Path('/usr/local/lib/erpc/monad')
RELEASES = Path('/opt/erpc/monad')
RUN = Path('/run/erpc-monad')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


class Refused(ValueError):
    """A fixed, non-secret operator-facing reason."""


def require(condition, message):
    if not condition:
        raise Refused(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def unique_json(data):
    def pairs(values):
        out = {}
        for key, value in values:
            require(key not in out, 'duplicate JSON field')
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON number')))


def read(path, limit=1048576, owner=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid == owner and s.st_nlink==1 and not s.st_mode & 0o022,
                'untrusted managed file')
        data = stream.read(limit + 1)
        require(len(data) <= limit, 'managed file exceeds limit')
        return data


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    """The containing root-owned directory must have been verified before use."""
    temporary = path.parent / ('.erpc-' + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            # The controller uses umask077. Apply the reviewed final mode to
            # this exact descriptor before publishing public configs or secrets.
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def publish(path, value):
    atomic(path, json_bytes(value))


def remove(path):
    if path.exists():
        path.unlink()
        fsync_dir(path.parent)


def owned_directory(path, create=False):
    """Never traverse a node-writable directory while running as root."""
    for parent in [*reversed(path.parents), path]:
        if not parent.exists():
            require(create, 'managed directory is missing')
            parent.mkdir(mode=0o700)
            fsync_dir(parent.parent)
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'unsafe managed directory')


def execute(args, *, input_data=None, timeout=120, check=True, env=None):
    require(args and str(args[0]).startswith('/'), 'absolute executable required')
    result = subprocess.run([str(arg) for arg in args], input=input_data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, env=ENV if env is None else env,
                            check=False, close_fds=True)
    require(not check or result.returncode == 0, 'native operation failed; output withheld')
    return result


def token(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{32}', value), 'invalid operation intent')
    return value


def public_key(value, kind):
    length = 66 if kind == 'secp' else 96
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value)
            and (kind != 'secp' or value[:2] in ('02', '03')) and int(value, 16),
            'invalid expected public identity')
    return value


def address(value):
    require(isinstance(value, str) and re.fullmatch('0x[a-f0-9]{40}', value), 'invalid reward/auth address')
    return value


def data_dir_fd(path, uid):
    """Anchor each component; a node-owned parent cannot redirect a root write."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            s = os.fstat(fd)
            require(s.st_uid in (0, uid) and not s.st_mode & 0o022, 'untrusted data path component')
        return os.dup(fd)
    finally:
        os.close(fd)


def seed_data(path, data, uid, gid):
    """Publish one exact cached bootstrap file; retries accept only its bytes."""
    parent = data_dir_fd(path.parent, uid)
    temporary = '.erpc-' + secrets.token_hex(16)
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            fd = None
        if fd is not None:
            with os.fdopen(fd, 'rb') as stream:
                s = os.fstat(stream.fileno())
                require(stat.S_ISREG(s.st_mode) and s.st_uid in (0, uid)
                        and stream.read(len(data) + 1) == data,
                        'existing bootstrap file differs from the retained initialization receipt')
            return
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), uid, gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)
