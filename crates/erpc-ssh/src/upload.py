# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Create a traversable root namespace and publish one private authorized upload."""
import contextlib
import os
from pathlib import Path
import re
import signal
import stat
import sys
import uuid

LIMIT = 64 * 1024 * 1024


class Upload:
    def __init__(self, root=Path('/'), owner=0):
        self.root, self.owner = root, owner

    def write(self, path, login, group, source):
        if any(type(value) is not int or not 0 <= value < 0xffffffff for value in (login, group)):
            raise ValueError('invalid upload login identity')
        if not path.startswith('/opt/erpc/'):
            raise ValueError('upload is outside the managed namespace')
        parts = path.split('/')[1:]
        if len(parts) < 4 or any(not re.fullmatch('[A-Za-z0-9_.-]+', p) or p in ('.', '..') for p in parts):
            raise ValueError('invalid upload path')
        # A worker's files are staged under /opt/erpc/uploads in two shapes
        # only: the agent or restic as one file in agent/ or restic/, and a
        # release in <worker>/<release>/, nested as it ships. Both are streamed
        # without a bound; any other shape there is refused before anything
        # is read or created. A path outside /opt/erpc/uploads is held to a
        # run's rules: a root helper seals a run reading each file whole, so
        # it stays bounded and flat.
        worker = parts[2] == 'uploads'
        if worker and parts[3] in ('agent', 'restic'):
            shaped = len(parts) == 5
        elif worker:
            shaped = len(parts) > 5
        else:
            shaped = len(parts) <= 5
        if not shaped:
            raise ValueError('invalid upload path')
        data = b'' if worker else source.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError('upload exceeds the bounded run size')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for index, part in enumerate(parts[:-1]):
                leaf = index == len(parts) - 2
                # Never create a system ancestor outside /opt/erpc. /opt must
                # already be a real root-owned directory on the managed host.
                if index > 0:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                if info.st_mode & 0o022:
                    raise ValueError('writable upload ancestor is refused')
                # /opt/erpc/uploads/<worker>/<release> and every directory in it
                # is private to the login, exactly as a leaf is.
                if leaf or worker and index > 3:
                    if info.st_uid not in (self.owner, login):
                        raise ValueError('upload directory belongs to another login')
                    # A sealed root-owned leaf must never be handed back. Only
                    # a new empty root-created leaf may become login-private.
                    entries = set(os.listdir(fd))
                    if (info.st_uid == self.owner and login != self.owner and entries
                            or not worker and entries & {'sealed.json', 'bundle', 'result.json'}):
                        raise ValueError('root-owned upload directory is already sealed or populated')
                    os.fchown(fd, login, group)
                    os.fchmod(fd, 0o700)
                else:
                    if info.st_uid != self.owner:
                        raise ValueError('upload namespace is not owned by root')
                    if index > 0:
                        # Explicit modes avoid sudo's union with caller umask077.
                        os.fchmod(fd, 0o755)
            name = parts[-1]
            try:
                existing = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and (not stat.S_ISREG(existing.st_mode)
                    or existing.st_uid != login or existing.st_mode & 0o077 or existing.st_nlink != 1):
                raise ValueError('existing upload destination is unsafe')
            temporary = '.upload-' + uuid.uuid4().hex
            # Created inside the try: a signal that arrives as soon as the
            # temporary exists still reaches the cleanup below.
            try:
                output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                with os.fdopen(output, 'wb') as stream:
                    stream.write(data)
                    if worker:
                        for chunk in iter(lambda: source.read(1024 * 1024), b''):
                            stream.write(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
                    os.fchown(stream.fileno(), login, group)
                    os.fchmod(stream.fileno(), 0o600)
                os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=fd)
        finally:
            os.close(fd)


if __name__ == '__main__':
    if os.geteuid() != 0 or not sys.flags.isolated or len(sys.argv) != 4:
        raise ValueError('upload requires root, isolated Python and a checked destination')
    # SIGTERM or SIGHUP raises where the upload is, so that write() removes
    # its temporary as on any failure; the exit status is the one a shell
    # reports for a command that the signal ended.
    # A second signal is ignored, so that it cannot stop that cleanup.
    def interrupted(number, frame):
        for each in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(each, signal.SIG_IGN)
        raise SystemExit(128 + number)
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)
    Upload().write(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.stdin.buffer)
