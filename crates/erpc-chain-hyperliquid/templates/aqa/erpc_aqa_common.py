#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed paths, bounded data and durable publication for the separate AQA publisher controller."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

ROOT = Path('/var/lib/erpc-hyperliquid-aqa')
CONFIG = Path('/etc/hyperliquid-aqa')
HELPERS = Path('/usr/local/lib/erpc/hyperliquid-aqa')
RELEASES = Path('/opt/erpc/hyperliquid-aqa')
RUN = Path('/run/erpc-hyperliquid-aqa')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
UNIT = 'erpc-hyperliquid-aqa.service'
RUNTIME_FILES = ('catalog.json', 'control.py', 'erpc_aqa_common.py', 'erpc_aqa_state.py',
                 'erpc_aqa_accounts.py', 'erpc_aqa_host.py', 'erpc_aqa_artifact.py', 'erpc_aqa_custody.py',
                 'erpc_aqa_public.py', 'erpc_aqa_process.py', 'erpc_aqa_units.py', 'erpc_aqa_trust.py')


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
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == owner and not s.st_mode & 0o022,
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


def owned_directory(path, create=False, mode=0o700):
    """Never traverse a node-writable directory while running as root."""
    for parent in [*reversed(path.parents), path]:
        if not parent.exists():
            require(create, 'managed directory is missing')
            parent.mkdir(mode=0o700)
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchmod(descriptor, mode)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
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
