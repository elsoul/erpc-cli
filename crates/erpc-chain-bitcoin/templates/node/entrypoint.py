# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Standalone descriptor loader copied from reviewed common firewall PR48.

def trusted_main(path):
    import os
    import stat
    import sys
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise ValueError('invalid standalone helper path')
    parts = path.split('/')[1:]
    if not parts or any(part in ('', '.', '..') for part in parts):
        raise ValueError('invalid standalone helper component')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    source = None
    try:
        for part in [None, *parts[:-1]]:
            if part is not None:
                next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                os.close(directory)
                directory = next_directory
            info = os.fstat(directory)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('standalone helper ancestors must be protected real root directories')
        source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or before.st_nlink != 1 or not 0 < before.st_size <= 1048576):
            raise ValueError('standalone helper must be a protected single-link root file')
        raw = bytearray()
        while len(raw) <= 1048576:
            chunk = os.read(source, min(65536, 1048577 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(source)
        if (len(raw) != before.st_size or len(raw) > 1048576
                or any(getattr(before, name) != getattr(after, name) for name in
                       ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
            raise ValueError('standalone helper changed while it was read')
    finally:
        if source is not None:
            os.close(source)
        os.close(directory)
    sys.argv[0] = path
    exec(compile(bytes(raw), path, 'exec'), {'__name__':'__main__', '__file__':path,
         '__package__':None, '__spec__':None, '__cached__':None})

trusted_main('/usr/local/lib/erpc/bitcoin-control')
