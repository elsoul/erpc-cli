#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Unprivileged retention matching the official recent-progress condition."""
import os
from pathlib import Path
import stat
import time

ROOT = Path('/var/lib/erpc-monad/data')


def files(directory):
    if directory.is_symlink():
        raise ValueError('redirected retention directory')
    for parent, dirs, names in os.walk(directory, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(parent) / name).is_symlink()]
        for name in names:
            path = Path(parent) / name
            if stat.S_ISREG(path.lstat().st_mode):
                yield path


def cleanup(now):
    if not any(now - path.stat().st_mtime < 1200 for path in files(ROOT / 'ledger')):
        return
    for directory, prefix, minutes in [('forkpoint', 'forkpoint.toml.', 300),
                                        ('forkpoint', 'forkpoint.rlp.', 300),
                                        ('validators', 'validators.toml.', 43200),
                                        ('ledger/headers', '', 600), ('ledger/bodies', '', 600)]:
        for path in files(ROOT / directory):
            if path.name.startswith(prefix) and now - path.stat().st_mtime > minutes * 60:
                path.unlink()


if __name__ == '__main__':
    cleanup(time.time())
