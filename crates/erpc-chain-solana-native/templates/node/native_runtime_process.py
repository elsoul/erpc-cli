# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Kernel evidence for a fixed, unprivileged native runtime and its RPC sockets.

The root caller authenticates the published executable, original account and
unit before using this observer. No RPC answer establishes process ownership.
Only kernel proc links are followed; no environment or credential is read.
"""
import os
from pathlib import Path
import re
import stat
from native_files import require
import native_process as proc

CGROUP = '/system.slice/erpc-solana.service'
RPC_PORTS = (8899, 8900)


def fields(raw):
    result = {}
    selected = {b'Uid', b'Gid', b'Groups', b'NoNewPrivs', b'CapInh', b'CapPrm', b'CapEff', b'CapBnd', b'CapAmb'}
    for line in raw.splitlines():
        name, separator, value = line.partition(b':')
        if name not in selected:
            continue  # Kernel task names can contain arbitrary non-ASCII bytes.
        name = name.decode('ascii')
        require(separator and name not in result, 'ambiguous native process metadata')
        result[name] = value.strip().decode('ascii')
    return result


def integers(value, count=None):
    values = value.split()
    require((count is None or len(values) == count) and all(v.isdecimal() for v in values),
            'invalid native process account metadata')
    return tuple(map(int, values))


def identity(pid, uid, gid, binary, argv):
    require(type(pid) is int and pid > 0 and type(uid) is int and type(gid) is int
            and uid > 0 and gid > 0, 'invalid native process authority')
    require(isinstance(binary, Path) and binary.is_absolute() and isinstance(argv, list)
            and argv and argv[0] == str(binary)
            and all(isinstance(v, str) and '\x00' not in v for v in argv),
            'invalid expected native invocation')
    directory = proc.PROC / str(pid)
    require(not directory.is_symlink(), 'indirect native process directory')
    start = proc.generation(directory)
    metadata = fields(proc.bounded(directory / 'status', 65536))
    require(integers(metadata.get('Uid', ''), 4) == (uid,) * 4
            and integers(metadata.get('Gid', ''), 4) == (gid,) * 4
            and set(integers(metadata.get('Groups', ''))) <= {gid},
            'native process inherited another account or group')
    require(metadata.get('NoNewPrivs') == '1', 'native process privilege restriction differs')
    for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
        value = metadata.get(name, '')
        require(re.fullmatch('[a-fA-F0-9]{1,16}', value) and int(value, 16) == 0,
                'native process retained capabilities')
    group = proc.bounded(directory / 'cgroup', 16384)
    require(group == ('0::' + CGROUP + '\n').encode(), 'native process is outside its fixed cgroup')
    command = proc.bounded(directory / 'cmdline', 65536)
    require(command == b'\x00'.join(value.encode() for value in argv) + b'\x00',
            'native process invocation differs from its approved runtime')
    expected = binary.lstat()
    # /proc/PID/exe is a kernel link to the actual opened executable. A copied
    # pathname or an exec into another inode cannot satisfy this comparison.
    executed = (directory / 'exe').stat()
    require(stat.S_ISREG(expected.st_mode) and expected.st_nlink == 1
            and not expected.st_mode & 0o222
            and (executed.st_dev, executed.st_ino) == (expected.st_dev, expected.st_ino),
            'native executable inode differs from the verified publication')
    require(proc.generation(directory) == start, 'native process changed during inspection')
    return (pid, start, expected.st_dev, expected.st_ino)


def exclusive(uid, expected_pid):
    """The node account runs exactly one process; threads are not proc children."""
    found = set()
    seen = 0
    for directory in proc.PROC.iterdir():
        if not directory.name.isdecimal():
            continue
        seen += 1
        require(seen <= 1_000_000 and not directory.is_symlink(), 'untrusted process namespace')
        try:
            first = proc.generation(directory)
            metadata = fields(proc.bounded(directory / 'status', 65536))
            values = integers(metadata.get('Uid', ''), 4)
            require(proc.generation(directory) == first, 'process changed during account inspection')
            if uid in values:
                found.add(int(directory.name))
        except FileNotFoundError:
            continue
    require(found == {expected_pid}, 'native account has a missing, additional or orphan process')


def socket_inodes(directory):
    result = set()
    descriptors = directory / 'fd'
    require(not descriptors.is_symlink(), 'indirect native descriptor directory')
    count = 0
    for path in descriptors.iterdir():
        count += 1
        require(count <= 1_000_000 and path.name.isdecimal(), 'invalid native descriptor namespace')
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
        if match:
            result.add(int(match[1]))
    return result


def listeners(directory):
    result = {port: [] for port in RPC_PORTS}
    for name, loopback, width in (('tcp', '0100007F', 8), ('tcp6', '', 32)):
        raw = proc.bounded(directory / 'net' / name, 4 * 1024 * 1024)
        lines = raw.decode('ascii').splitlines()
        require(lines and 'local_address' in lines[0], 'invalid kernel TCP table')
        for line in lines[1:]:
            parts = line.split()
            require(len(parts) >= 10, 'invalid kernel TCP record')
            address, separator, port = parts[1].partition(':')
            require(separator and re.fullmatch('[A-Fa-f0-9]{' + str(width) + '}', address)
                    and re.fullmatch('[A-Fa-f0-9]{4}', port), 'invalid kernel TCP address')
            number = int(port, 16)
            if number not in result or parts[3] != '0A':
                continue
            require(address == loopback and parts[7].isdecimal() and parts[9].isdecimal(),
                    'native RPC listener is not exclusively IPv4 loopback')
            result[number].append((int(parts[7]), int(parts[9])))
    return result


def prove(pid, uid, gid, binary, argv):
    before = identity(pid, uid, gid, binary, argv)
    exclusive(uid, pid)
    directory = proc.PROC / str(pid)
    native_net = (directory / 'ns/net').stat()
    observer_net = (proc.PROC / 'self/ns/net').stat()
    require((native_net.st_dev, native_net.st_ino) == (observer_net.st_dev, observer_net.st_ino),
            'native RPC belongs to a different network namespace')
    owned = socket_inodes(directory)
    ports = listeners(directory)
    require(all(len(records) == 1 and records[0][0] == uid and records[0][1] in owned
                for records in ports.values()), 'native process does not exclusively own RPC listeners')
    require(identity(pid, uid, gid, binary, argv) == before,
            'native process changed during listener inspection')
    exclusive(uid, pid)
    return before
