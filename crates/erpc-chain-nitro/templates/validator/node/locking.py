# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Root-only kernel locks with checked descriptor identity and bounded waits."""
from contextlib import contextmanager
import scope
import fcntl
import os
from pathlib import Path
import stat
import time
import storage
from storage import directory, require, sync_directory

CONTROL = Path('/run/erpc-'+scope.NAMESPACE+'-operation.lock')


@contextmanager
def locked(path, timeout=240):
    directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor); actual = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == storage.ROOT_UID and info.st_nlink == 1
                and info.st_mode & 0o7777 == 0o600 and (info.st_dev, info.st_ino) == (actual.st_dev, actual.st_ino),
                'validator operation lock is not an original protected root file')
        deadline = time.monotonic()+timeout
        while True:
            try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                require(time.monotonic() < deadline, 'another original validator operation is still running')
                time.sleep(0.05)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)
