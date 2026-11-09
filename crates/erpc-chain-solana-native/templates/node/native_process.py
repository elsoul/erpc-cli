# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated-UID quiescence includes orphan processes outside a service cgroup."""
import os
from pathlib import Path
from native_files import require

PROC = Path('/proc')


def bounded(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        result = stream.read(maximum + 1)
    require(len(result) <= maximum, 'process metadata exceeds its bound')
    return result


def generation(directory):
    raw = bounded(directory / 'stat', 16384)
    before, separator, fields = raw.rpartition(b') ')
    require(separator and before.split(b' (', 1)[0] == directory.name.encode(), 'invalid process identity')
    tail = fields.split()
    require(len(tail) >= 20 and tail[19].isdigit(), 'invalid process generation')
    return int(tail[19])


def assert_quiescent(uid):
    """Caller holds the root launch lock and first rejects queued/running units."""
    require(type(uid) is int and uid > 0, 'quiescence requires an isolated non-root UID')
    seen = 0
    for directory in PROC.iterdir():
        if not directory.name.isdecimal():
            continue
        seen += 1
        require(seen <= 1_000_000 and not directory.is_symlink(), 'untrusted process namespace')
        try:
            first = generation(directory)
            status = bounded(directory / 'status', 65536)
            lines = [line for line in status.splitlines() if line.startswith(b'Uid:')]
            require(len(lines) == 1, 'ambiguous process UID metadata')
            ids = lines[0].split()[1:]
            require(len(ids) == 4 and all(value.isdigit() for value in ids), 'invalid process UID metadata')
            require(generation(directory) == first, 'process changed while checking quiescence')
            require(uid not in [int(value) for value in ids], 'dedicated account still has a process; refuse publication or startup')
        except FileNotFoundError:
            # An exiting process has no writable descriptor left. A replacement
            # with a different generation is refused above, never assumed idle.
            continue
