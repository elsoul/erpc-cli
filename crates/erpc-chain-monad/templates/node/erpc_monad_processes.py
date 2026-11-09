# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Quiescence includes native processes whose systemd units have disappeared."""
import os
from pathlib import Path
import signal
import time
from erpc_monad_common import digest, execute, require

UNITS = ('erpc-monad-rpc.service', 'erpc-monad-bft.service',
         'erpc-monad-execution.service', 'erpc-monad-gateway.service',
         'erpc-monad-cleanup.timer', 'erpc-monad-cleanup.service', 'erpc-monad-memory.service')


def identity(proc):
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    return fields[19]  # /proc/pid/stat field 22, after the parenthesized comm.


def inspect(pid, uid, approved, proc_root=Path('/proc')):
    proc = proc_root / str(pid)
    try:
        first = identity(proc)
        status = (proc / 'status').read_text()
        ids = next(line.split()[1:] for line in status.splitlines() if line.startswith('Uid:'))
        if str(uid) not in ids:
            return None
        require(ids == [str(uid)] * 4, 'service process has mixed user authority')
        executable = proc / 'exe'
        target = os.readlink(executable)
        if target.endswith(' (deleted)'):
            target = target[:-10]
        require(target in approved, 'unrecognized process runs under the dedicated Monad user')
        # Hash the kernel executable handle, not a pathname which could point at
        # a replacement after an upgrade. Root-owned approved paths are immutable.
        with executable.open('rb') as stream:
            import hashlib
            h = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(block)
        require(h.hexdigest() == approved[target] and identity(proc) == first,
                'native executable or process identity changed')
        return first
    except (FileNotFoundError, ProcessLookupError):
        if not proc.exists():
            return None
        try:
            phase = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            return None
        require(phase in ('Z', 'X'), 'cannot establish an existing process executable')
        return None


def owned(uid, approved):
    result = {}
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            value = inspect(int(path.name), uid, approved)
            if value is not None:
                result[int(path.name)] = value
    return result


def stop(uid, approved):
    failures=[]
    for unit in UNITS:
        try:
            result = execute(['/usr/bin/systemctl', 'stop', unit], check=False, timeout=180)
            if result.returncode:
                loaded = execute(['/usr/bin/systemctl', 'show', '--property=LoadState', '--value', unit], check=False)
                require(loaded.stdout.strip() == b'not-found', 'systemd could not stop a managed service')
        except Exception:failures.append(unit)
    # A failed unit stop must not suppress the independent original-UID scan
    # and pidfd shutdown of already-qualified native writers.
    remaining = owned(uid, approved)
    handles = []
    try:
        for pid, start in remaining.items():
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            handles.append(fd)
            require(inspect(pid, uid, approved) == start, 'native process changed before shutdown')
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        deadline = time.monotonic() + 120
        while owned(uid, approved):
            require(time.monotonic() < deadline, 'native writer did not exit; data and startup fence preserved')
            time.sleep(0.2)
    finally:
        for fd in handles:
            os.close(fd)
    require(not owned(uid, approved), 'native writer remains active')

    require(not failures,'owned writers were drained but one or more unit stops failed')


def quiescent(uid, approved):
    require(not owned(uid, approved), 'stop all owned native processes before changing data or identity')


def start_safe(uid, approved, current_directory, gateway=False, proc_root=Path('/proc')):
    """Existing native services are idempotent; detached writers must be stopped first."""
    units = {'monad': 'erpc-monad-execution.service', 'monad-node': 'erpc-monad-bft.service',
             'monad-rpc': 'erpc-monad-rpc.service'}
    if gateway:
        units = {'nginx': 'erpc-monad-gateway.service'}
    for pid, start in owned(uid, approved).items():
        proc = proc_root / str(pid)
        try:
            name = os.readlink(proc / 'exe')
            require(not name.endswith(' (deleted)'), 'deleted native executable still runs; stop before startup')
            executable = Path(name)
            require(executable.name in units and executable == current_directory / ('sbin' if gateway else 'bin') / executable.name,
                    'an older or detached native writer must be explicitly stopped before startup')
            group = '0::/system.slice/' + units[executable.name]
            require(group in (proc / 'cgroup').read_text().splitlines() and identity(proc) == start,
                    'native writer is outside its owned systemd service; stop before startup')
        except (FileNotFoundError, ProcessLookupError):
            require(not proc.exists(), 'existing native writer became uninspectable before startup')
            continue
