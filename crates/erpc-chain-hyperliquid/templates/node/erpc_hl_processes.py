# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated UID and kernel cgroup ownership; rolling-child hashes are observations."""
import hashlib
import os
from pathlib import Path
import select
import signal
import time
from erpc_hl_common import CONFIG, HELPERS, execute, require

UNITS = ('erpc-hyperliquid-node.service', 'erpc-hyperliquid-rpc.service',
         'erpc-hyperliquid-retention.service', 'erpc-hyperliquid-retention.timer')
CGROUPS = frozenset('/system.slice/' + name for name in UNITS if name.endswith('.service'))
PROC = Path('/proc')


def identity(pid, uid, proc=PROC):
    entry = proc / str(pid)
    try:
        fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
        if fields[0] == 'Z':
            return None
        values = next(line.split()[1:] for line in (entry / 'status').read_text().splitlines()
                      if line.startswith('Uid:'))
        require(len(values) == 4 and all(value.isdigit() and int(value) == uid for value in values),
                'managed process changed its dedicated identity')
        groups = (entry / 'cgroup').read_text().splitlines()
        require(any(line.startswith('0::') and line[3:] in CGROUPS for line in groups),
                'dedicated process is outside an owned service cgroup; inspect before proceeding')
        require(fields[19].isdigit(), 'managed process start time is unavailable')
        return fields[19]
    except (FileNotFoundError, ProcessLookupError):
        require(not entry.exists(), 'cannot establish whether a disappearing process remains alive')
        return None


def owned(uid, proc=PROC):
    require(type(uid) is int and 100 <= uid < 2**31, 'invalid dedicated process identity')
    result = {}
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            # Check every kernel UID field, including saved/filesystem identity,
            # before classifying a process as unrelated to the dedicated user.
            values = next(line.split()[1:] for line in (entry / 'status').read_text().splitlines()
                          if line.startswith('Uid:'))
            if str(uid) not in values:
                continue
        except (FileNotFoundError, ProcessLookupError):
            require(not entry.exists(), 'process ownership disappeared during inspection')
            continue
        start = identity(int(entry.name), uid, proc)
        if start is not None:
            result[int(entry.name)] = start
    return result


def quiescent(uids):
    for uid in uids:
        require(not owned(uid), 'owned native or gateway process is still running')


def stop(uids):
    for uid in uids:
        owned(uid)  # Establish scope before touching any fixed service unit.
    failed = False
    # Stop scheduling before the workers; missing unit files do not hide live
    # processes that remain in their original kernel service cgroup.
    for unit in reversed(UNITS):
        try:
            result = execute(['/usr/bin/systemctl', 'show', '--property=LoadState', '--value', unit], check=False)
            state = result.stdout.strip()
            require(state in (b'loaded', b'masked', b'not-found'), 'cannot establish managed service state')
            if state != b'not-found':
                execute(['/usr/bin/systemctl', 'stop', unit], timeout=1860)
        except Exception:
            failed = True
    for uid in uids:
        for pid, start in owned(uid).items():
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                require(identity(pid, uid) == start, 'owned process identity changed before shutdown')
                signal.pidfd_send_signal(fd, signal.SIGTERM)
                ready, _, _ = select.select([fd], [], [], 1800)
                require(ready, 'owned process did not stop gracefully; data remains preserved')
            finally:
                os.close(fd)
    quiescent(uids)
    require(not failed, 'service shutdown failed; owned process drain was still attempted')


def observed_images(uid, proc=PROC):
    result = []
    for pid, start in owned(uid, proc).items():
        handle = proc / str(pid) / 'exe'
        executable = os.readlink(handle)
        name = Path(executable.removesuffix(' (deleted)')).name
        if name not in ('hl-node', 'hl-visor'):
            continue  # Native supervisor subprocesses such as curl/GPG are not client versions.
        digest = hashlib.sha256()
        size = 0
        # This is the kernel's live executable handle, not a writable pathname.
        with handle.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                size += len(block)
                require(size <= 2_000_000_000, 'native executable observation exceeded bounds')
                digest.update(block)
        require(identity(pid, uid, proc) == start, 'native executable changed during observation')
        result.append({'name': name, 'pid': pid, 'sha256': digest.hexdigest(), 'bytes': size,
                       'source_commit': None, 'observed_at': int(time.time()),
                       'identity_kind': 'observed running bytes, not an approved child release'})
    return result


def listener(uid, port, proc=PROC, gateway=False):
    """Bind loopback observations to kernel socket inodes of the owned native child."""
    sockets = set()
    for name in ('tcp', 'tcp6'):
        table = proc / 'net' / name
        with table.open('r') as stream:
            data = stream.read(8_388_609)
        require(len(data) <= 8_388_608, 'kernel TCP observation exceeded its bound')
        for row in data.splitlines()[1:]:
            fields = row.split()
            require(len(fields) >= 10, 'malformed kernel TCP observation')
            address, number = fields[1].rsplit(':', 1)
            if fields[3] != '0A' or int(number, 16) != port:
                continue
            require(address in ('00000000', '0100007F', '0' * 32,
                                '00000000000000000000000001000000'),
                    'native API listener is not available through the fixed local endpoint')
            require(fields[9].isdigit(), 'native API socket identity is unavailable')
            sockets.add(fields[9])
    require(sockets, 'native API has no listening kernel socket')
    proofs = []
    for pid, start in owned(uid, proc).items():
        entry = proc / str(pid)
        name = Path(os.readlink(entry / 'exe').removesuffix(' (deleted)')).name
        if not gateway and name != 'hl-node':
            continue
        executable = (entry / 'exe').stat()
        if gateway:
            interpreter = Path('/usr/bin/python3').stat()
            if (executable.st_dev, executable.st_ino) != (interpreter.st_dev, interpreter.st_ino):
                continue
            with (entry / 'cmdline').open('rb') as stream:
                command = stream.read(65537)
            expected = [b'/usr/bin/python3', b'-I', os.fsencode(HELPERS / 'current/erpc_hl_gateway.py'),
                        os.fsencode(CONFIG / 'gateway.json'), b'']
            require(command.split(b'\0') == expected, 'gateway process does not execute the fixed reviewed helper')
        group = '/system.slice/erpc-hyperliquid-' + ('rpc' if gateway else 'node') + '.service'
        require('0::' + group in (entry / 'cgroup').read_text().splitlines(),
                'API listener belongs to a different owned service')
        held = set()
        for descriptor in (entry / 'fd').iterdir():
            try:
                link = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            if link.startswith('socket:[') and link.endswith(']'):
                number = link[8:-1]
                if number in sockets:
                    held.add(number)
        require(identity(pid, uid, proc) == start, 'native process changed during listener verification')
        if held:
            proofs.append((pid, start, executable.st_dev, executable.st_ino, tuple(sorted(held))))
    require(proofs and set().union(*(set(item[4]) for item in proofs)) == sockets,
            'native API listener does not belong exclusively to the owned hl-node')
    return sorted(proofs)
